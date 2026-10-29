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

/** Start an entry point from the copy, stdin closed, stdout and stderr piped. */
export function spawnEntry(
  checkout: ShadowCheckout,
  entry: EntryPoint,
  args: readonly string[],
  opts: Omit<SpawnOptions, 'cwd' | 'stdio'> = {},
): ChildProcessByStdio<null, Readable, Readable> {
  noCwd(opts)
  return spawn(process.execPath, ['--import', 'tsx', entry, ...args], { ...opts, cwd: checkout.root, stdio: ['ignore', 'pipe', 'pipe'] })
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
