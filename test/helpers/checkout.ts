// A throwaway copy of this checkout, for tests that run entry points as
// programs.
//
// An entry point finds its repository from its cwd (src/main.ts, the CLI) or
// from its own file (scripts/eval.ts). Spawned from the real checkout, a
// regression — or a falsify mutant — that makes one open <repo>/.env would
// read the operator's real keys before any assertion could object. Spawned
// from here, it opens the TRAP below: mode 0644 and a name no config declares,
// so the loader refuses it loudly and nothing is read.
//
// The copy is taken when the test file loads, so a falsify run that has just
// mutated src/ is exercised as mutated. node_modules is linked, not copied.
//
// runEntry/spawnEntry are the only way a test runs an entry point: they set
// the cwd to the copy themselves and refuse one passed in, so no edit to a
// call site can point a run back at the real checkout. hygiene.test.ts holds
// every test to them.

import './guard.js'

import { spawn, spawnSync, type ChildProcessByStdio, type SpawnOptions, type SpawnSyncOptionsWithStringEncoding, type SpawnSyncReturns } from 'node:child_process'
import { appendFileSync, chmodSync, cpSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import type { Readable } from 'node:stream'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '')

const COPIED_DIRS = ['src', 'scripts', 'config', 'agents', 'souls'] as const
// .npmrc too, so anything that does reach npm keeps its cache in the copy's
// .aos/, deleted with it, never in ~/.npm (the operator's footprint rule).
const COPIED_FILES = ['package.json', 'tsconfig.json', '.gitignore', '.npmrc'] as const

/** What the trap holds: refused for its mode before its content is ever parsed. */
export const TRAP_DOTENV = 'NODE_OPTIONS=--require=/nonexistent/aos-dotenv-trap.js\n'

/**
 * The programs an operator runs: each of the first four may open <repo>/.env
 * given --dotenv, and the installer inspects and appends to it through the one
 * writer, so each runs here, against the trap.
 */
export const ENTRY_POINTS = ['src/main.ts', 'src/cli/index.ts', 'scripts/eval.ts', 'scripts/capture-pmmcp.ts', 'scripts/install.ts'] as const
export type EntryPoint = (typeof ENTRY_POINTS)[number]

export interface ShadowCheckout {
  readonly root: string
  dispose(): void
}

function noCwd(opts: object): void {
  if ('cwd' in opts) throw new Error('an entry point runs from the shadow checkout only; drop the cwd option')
}

/** Run an entry point to completion from the copy: `node --import tsx <entry> ...args`, cwd = the copy. */
export function runEntry(
  checkout: ShadowCheckout,
  entry: EntryPoint,
  args: readonly string[],
  opts: Omit<SpawnSyncOptionsWithStringEncoding, 'cwd' | 'encoding'> = {},
): SpawnSyncReturns<string> {
  noCwd(opts)
  return spawnSync(process.execPath, ['--import', 'tsx', entry, ...args], { ...opts, cwd: checkout.root, encoding: 'utf8' })
}

/**
 * What is typed at the terminal, in order: each step waits for its cue in
 * what the command wrote there since the last step's (or for a file to
 * exist), then, `delayMs` later, types `send`. A file step is how a test
 * types at a moment the screen does not show (a probe that has started).
 */
export type PtyStep =
  | { readonly cue: string; readonly send: string; readonly delayMs?: number }
  | { readonly file: string; readonly send: string; readonly delayMs?: number }

/**
 * Gives a child a terminal: python3's pty module (no Node dependency has
 * one). It forks the command on a new pseudo-terminal, its stdin, stdout and
 * stderr; copies what the command writes there to its own stdout; types each
 * step's keys (PtyStep) and nothing else; and exits with the command's
 * status. The terminal's own line discipline turns a typed Ctrl-C (\x03)
 * into SIGINT for its foreground process group, as a real one does.
 */
const PTY_WRAPPER = [
  'import json, os, pty, select, sys, time',
  'steps = json.loads(sys.argv[1])',
  'pid, fd = pty.fork()',
  'if pid == 0:',
  '    os.execv(sys.argv[2], sys.argv[2:])',
  "out = b''",
  'at = 0',
  'i = 0',
  'while True:',
  '    if i < len(steps):',
  '        step = steps[i]',
  '        hit = False',
  "        if 'cue' in step:",
  "            k = out.find(step['cue'].encode(), at)",
  '            if k >= 0:',
  '                hit = True',
  "                at = k + len(step['cue'].encode())",
  '        else:',
  "            hit = os.path.exists(step['file'])",
  '        if hit:',
  "            time.sleep(step.get('delayMs', 0) / 1000)",
  "            os.write(fd, step['send'].encode())",
  '            i += 1',
  '            continue',
  '    ready, _, _ = select.select([fd], [], [], 0.05)',
  '    if not ready:',
  '        continue',
  '    try:',
  '        chunk = os.read(fd, 4096)',
  '    except OSError:',
  '        break',
  '    if not chunk:',
  '        break',
  '    out += chunk',
  '_, status = os.waitpid(pid, 0)',
  'sys.stdout.buffer.write(out)',
  'sys.stdout.flush()',
  'sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))',
  '',
].join('\n')

/** Whether a terminal can be given to an entry point here (spawnEntry's `eofAfter`): python3 with its pty module. */
export function terminalAvailable(): boolean {
  return spawnSync('python3', ['-I', '-c', 'import os, pty'], { encoding: 'utf8' }).status === 0
}

/**
 * Start an entry point from the copy, stdin closed, stdout and stderr piped.
 * With `eofAfter` or `typed`, it runs at a terminal instead (PTY_WRAPPER):
 * its stdin and stdout are one, the end of the input is typed once its output
 * holds `eofAfter`'s text (or `typed`'s steps are typed), and what it wrote
 * there (stderr included, lines ending \r\n) comes on stdout when it has
 * exited.
 */
export function spawnEntry(
  checkout: ShadowCheckout,
  entry: EntryPoint,
  args: readonly string[],
  opts: Omit<SpawnOptions, 'cwd' | 'stdio'> & { readonly eofAfter?: string; readonly typed?: readonly PtyStep[] } = {},
): ChildProcessByStdio<null, Readable, Readable> {
  noCwd(opts)
  const { eofAfter, typed, ...options } = opts
  const node = [process.execPath, '--import', 'tsx', entry, ...args]
  const steps: readonly PtyStep[] | undefined = typed ?? (eofAfter === undefined ? undefined : [{ cue: eofAfter, send: '\x04' }])
  if (steps !== undefined) return spawn('python3', ['-I', '-c', PTY_WRAPPER, JSON.stringify(steps), ...node], { ...options, cwd: checkout.root, stdio: ['ignore', 'pipe', 'pipe'] })
  return spawn(process.execPath, node.slice(1), { ...options, cwd: checkout.root, stdio: ['ignore', 'pipe', 'pipe'] })
}

export function shadowCheckout(): ShadowCheckout {
  const root = mkdtempSync(join(tmpdir(), 'aos-checkout-'))
  for (const dir of COPIED_DIRS) cpSync(join(REPO, dir), join(root, dir), { recursive: true })
  for (const file of COPIED_FILES) cpSync(join(REPO, file), join(root, file))
  // A cache in a fresh copy has no update-check stamp, so anything that did
  // reach npm would ask the registry on every run.
  appendFileSync(join(root, '.npmrc'), '\nupdate-notifier=false\n')
  symlinkSync(join(REPO, 'node_modules'), join(root, 'node_modules'))
  const trap = join(root, '.env')
  writeFileSync(trap, TRAP_DOTENV, { mode: 0o644 })
  chmodSync(trap, 0o644)
  return { root, dispose: () => rmSync(root, { recursive: true, force: true }) }
}
