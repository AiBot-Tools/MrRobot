// The installer's process runner: the one place npm run aos-install starts a
// program.
//
// CONTRACT
//
//   Who calls it: the installer's probes and steps (scripts/install.ts and
//   scripts/install/*). In scripts/, node:child_process is imported only here
//   and by the mutation runner (hygiene.test.ts), so every program the
//   installer runs goes through the rules below.
//
//   What a child gets:
//     - An environment built from an allowlist, never the installer's own:
//       HOME, USER, LOGNAME, TMPDIR, LANG, LC_ALL, TERM and SHELL as the
//       installer has them, PATH fixed to ~/.local/bin, Homebrew's and the
//       system's directories, then ~/.docker/bin and ~/.cargo/bin (Docker
//       Desktop's per-user CLI and the older uv installer, found only when
//       nothing before them has the program), and SSH_AUTH_SOCK for git
//       alone. So no DOCKER_* (a DOCKER_CONFIG export points docker at a
//       Colima VM, which holds no pmmcp-qdrant), no PMMCP_* (pmmcp's
//       load_config refuses to start under a name it does not know,
//       PMMCP_CONFIG_PATH included), no AOS_* and no credential name ever
//       reaches a child.
//     - stdin from /dev/null, or one `sha256:<64 lowercase hex>` line: a
//       digest is the only thing the installer ever hands a child.
//     - stdout and stderr in two files, <step>.out and <step>.err, created
//       0600 with O_EXCL under <repo>/.aos/install/<UTC stamp>/ (0700; the
//       logs are written only while .gitignore ignores /.aos/ and .aos is
//       spelled .aos on disk, and never through a link). Never one merged
//       capture: the stop script writes its --jobs warnings to stderr before
//       stdout's first line, so a merge would put a warning where the count
//       belongs. Never a pipe: if the installer died, a child writing to a
//       pipe nobody reads would end on SIGPIPE, and a stop script ended
//       mid-stop leaves pmmcp half stopped. These logs are written in a dry
//       run too: they are the one thing a dry run writes.
//     - Exactly cwd, env, stdio and detached from Node's spawn: no timeout,
//       no kill signal, no shell (spawnWith).
//
//   What it refuses, before anything is created or spawned: a command, cwd,
//   argument, environment value or stdin that holds a value registered with
//   SecretMask or a credential shape redactString knows; stdin that is not one
//   digest; a relative cwd, or a command that is neither absolute nor a bare
//   program name; and, once a child's output held a registered value, every
//   further run (below).
//
//   The stop and start scripts (stop-pmmcp-server.sh, start-pmmcp-server.sh),
//   recognised by name in any case (APFS runs Stop-PMMCP-Server.sh as the same
//   file) and through a link: run only as the command itself, by absolute
//   path; any other run whose command or arguments name either is refused, so
//   a shell or `env` in front cannot take them around these rules. That
//   includes read-only commands that only mention one (`git show
//   HEAD:stop-pmmcp-server.sh`, `pgrep -f start-pmmcp-server.sh`): A4 and A6
//   learn what they need from the facts' feature flags, whole-tree git
//   commands and the pid active.json records. Their arguments come from an
//   allowlist: the stop gets none, `--jobs` alone, or `--quiet` and
//   `--wait-timeout N` with N at least 300 (the script's own default), so
//   never --force or -f (CLAUDE.md) nor a wait that ends at once; the start
//   gets none or `--check` (never --force, nor --tail or --only: a start that
//   follows its logs never exits, and nothing here would end it).
//
//   A step in its own session: the stop and start scripts always, and any
//   other step the caller marks ownSession (a step inside the stopped window,
//   L2 to L4, which a Ctrl-C at the installer's terminal must not interrupt
//   mid-change). It runs detached, in a session and process group of its own,
//   so a Ctrl-C or a hangup at the installer's terminal never reaches it; with
//   no timeout, and never signalled by this module, whatever happens. A stop
//   killed part way leaves services half stopped and the drain lock behind.
//   While one runs, <repo>/.aos/install/active.json records {step, pid,
//   started, out, err}; it is created with O_EXCL before the spawn and
//   removed when the child exits, so a re-run after the installer died finds
//   the window still open. A second one is refused while the record exists:
//   only the caller, having seen the recorded child gone, clears it
//   (clearActive). A record that cannot be removed after the exit is reported
//   in the result (activeError), never thrown from the exit.
//
//   What it reads and shows: machine output from the .out file only
//   (readOut, readJobs); the .err file is shown, never parsed. Either is shown
//   through tail(), which strips terminal control sequences and then applies
//   redactString.
//
//   After a child exits, both files are scanned for every value registered
//   with SecretMask. A hit empties that file, fails the step with a defect
//   that names the file and never the value, and halts the runner: nothing
//   more is run, a read-only probe or the start script included, so the
//   installer stops before its next live step (A6's end report then names the
//   manual start and the checks it could not make). While any value is
//   registered, a file that cannot be scanned counts as a hit.
//
//   A read-only probe may be given timeoutMs, after which it is sent SIGKILL
//   and reported timedOut; one the kill does not end (a process in
//   uninterruptible sleep) is reported unreaped (exited false) after a grace
//   period. Only a probe: a step that writes (rotate, qdrant, auth init, git)
//   must be left to finish or fail on its own, and a step in its own session
//   refuses a timeout outright.

import { spawn as nodeSpawn, type SpawnOptions } from 'node:child_process'
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { basename, isAbsolute, join, resolve } from 'node:path'
import type { Writable } from 'node:stream'
import { z } from 'zod'

import { assertAosEntry, gitignoresAos } from '../../src/config.js'
import { ConfigError, KernelError } from '../../src/errors.js'
import { SecretMask, redactString } from '../../src/events/redact.js'

/** The names a child is given from the installer's environment, when set and not empty. */
export const PASSED_NAMES: readonly string[] = ['HOME', 'USER', 'LOGNAME', 'TMPDIR', 'LANG', 'LC_ALL', 'TERM', 'SHELL']

/** Given to git alone: a clone over SSH needs the operator's agent, and nothing else does. */
export const GIT_ONLY_NAMES: readonly string[] = ['SSH_AUTH_SOCK']

/** After ~/.local/bin (uv): Homebrew on Apple silicon, then on Intel, then the system's. */
const SYSTEM_PATH: readonly string[] = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']

/**
 * Last, so they only supply what nothing earlier has: Docker Desktop's
 * per-user CLI (docker, docker-credential-desktop) and the older uv
 * installer's directory. Unverified on the operator's Mac (plan §7).
 */
const HOME_FALLBACK_PATH: readonly (readonly string[])[] = [
  ['.docker', 'bin'],
  ['.cargo', 'bin'],
]

/** The child's PATH, whatever the installer's own holds. */
export function childPath(home: string): string {
  return [join(home, '.local', 'bin'), ...SYSTEM_PATH, ...HOME_FALLBACK_PATH.map((p) => join(home, ...p))].join(':')
}

/** The one thing stdin may carry: pmmcp's digest_of form. */
export const DIGEST_LINE = /^sha256:[0-9a-f]{64}$/

/** The scripts that stop and start pmmcp, by file name. */
export const STOP_SCRIPT = 'stop-pmmcp-server.sh'
export const START_SCRIPT = 'start-pmmcp-server.sh'
const SERVICE_SCRIPTS: readonly string[] = [STOP_SCRIPT, START_SCRIPT]

/** The shortest job wait the stop may be given: its own default. A shorter one ends the wait early, as --force does. */
export const MIN_WAIT_TIMEOUT_S = 300

/** A step's name: its files are <step>.out and <step>.err. */
const STEP_NAME = /^[a-z0-9][a-z0-9._-]{0,47}$/

/** A program looked up on the child's PATH. */
const BARE_PROGRAM = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/

/** The longest timeout a probe may be given: a day is no longer a probe. */
const MAX_TIMEOUT_MS = 24 * 60 * 60 * 1000

/** How long a probe sent SIGKILL at its deadline is waited for before it is reported unreaped. */
export const KILL_GRACE_MS = 5000

/** Machine output larger than this is not what any interface the installer reads prints. */
export const MAX_MACHINE_OUTPUT = 1024 * 1024

/** How much of a file tail() reads from its end. */
const TAIL_BYTES = 64 * 1024

/** How much the leak scan reads at a time, and how much of the last read it keeps, so a value across two reads is still whole in one window. */
export const SCAN_CHUNK = 1024 * 1024
const SCAN_OVERLAP = 64 * 1024

export type RunErrorCode =
  | 'AOS_INSTALL_RUN_REFUSED'
  | 'AOS_INSTALL_RUN_BUSY'
  | 'AOS_INSTALL_RUN_SPAWN'
  | 'AOS_INSTALL_RUN_LEAK'
  | 'AOS_INSTALL_RUN_HALTED'
  | 'AOS_INSTALL_RUN_OUTPUT'

/** What went wrong, by code; the message names steps, paths and names, never a value. */
export class InstallRunError extends KernelError {
  readonly step: string | undefined
  /** For a leak: how the child ended. Its output is gone. */
  readonly result: RunResult | undefined

  constructor(code: RunErrorCode, message: string, step?: string, result?: RunResult) {
    super(code, message)
    this.step = step
    this.result = result
  }
}

export interface RunSpec {
  /** The step's name: its output goes to <step>.out and <step>.err (a repeated name gets -2, -3, ...). */
  readonly step: string
  /** An absolute path, or a bare program name looked up on the child's PATH. */
  readonly command: string
  readonly args: readonly string[]
  /** An absolute directory. */
  readonly cwd: string
  /** One `sha256:<64 lowercase hex>` digest, sent as one line on stdin; without it stdin is /dev/null. */
  readonly digest?: string
  /** A read-only probe only: SIGKILL after this many milliseconds. */
  readonly timeoutMs?: number
  /**
   * Run in a session of its own, recorded in active.json, with no timeout:
   * for a step inside the stopped window. The stop and start scripts always
   * run so, whatever this says.
   */
  readonly ownSession?: boolean
}

/** What spawn is handed: no timeout and no kill signal, by construction. */
export interface ChildOptions {
  readonly cwd: string
  readonly env: Readonly<Record<string, string>>
  /** stdin ('ignore' is /dev/null), then the .out and .err descriptors. */
  readonly stdio: readonly ['ignore' | 'pipe', number, number]
  readonly detached: boolean
}

/** The part of a ChildProcess the runner uses. */
export interface ChildLike {
  readonly pid?: number | undefined
  readonly stdin: Writable | null
  kill(signal: NodeJS.Signals): boolean
  once(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown
  once(event: 'error', listener: (error: Error) => void): unknown
}

export type SpawnFn = (command: string, args: readonly string[], options: ChildOptions) => ChildLike

/** Node's spawn, as spawnWith calls it. */
export type NodeSpawnFn = (command: string, args: readonly string[], options: SpawnOptions) => ChildLike

/**
 * A SpawnFn over Node's spawn (or a stand-in for it): the options it hands
 * on are exactly cwd, env, stdio and detached, so no timeout, kill signal or
 * shell can be added on the way.
 */
export function spawnWith(impl: NodeSpawnFn): SpawnFn {
  return (command, args, o) => impl(command, [...args], { cwd: o.cwd, env: { ...o.env }, stdio: [o.stdio[0], o.stdio[1], o.stdio[2]], detached: o.detached })
}

const realSpawn: SpawnFn = spawnWith(nodeSpawn)

export interface RunResult {
  readonly step: string
  readonly pid: number | undefined
  readonly out: string
  readonly err: string
  readonly started: Date
  readonly elapsedMs: number
  readonly code: number | null
  readonly signal: NodeJS.Signals | null
  readonly timedOut: boolean
  /**
   * False only for a probe that was sent SIGKILL at its deadline and had not
   * exited a grace period later: it may still run and write to its files,
   * and code and signal are null.
   */
  readonly exited: boolean
  /** The stdin pipe's error code, when the digest could not be delivered. */
  readonly stdinError: string | undefined
  /** An error the child emitted after it was spawned: only a failed kill can be one. */
  readonly childError: string | undefined
  /** For a step in its own session: why active.json could not be removed after the exit. The record stays, and a re-run waits on it. */
  readonly activeError: string | undefined
}

export interface Started {
  readonly step: string
  readonly pid: number | undefined
  readonly out: string
  readonly err: string
  readonly started: Date
  /** For a step in its own session: why active.json could not be filled in. It then reads as unreadable, which keeps a re-run waiting. */
  readonly activeError: string | undefined
  readonly done: Promise<RunResult>
}

export interface RunnerOptions {
  /** The repository root: the logs go under <repoRoot>/.aos/install. */
  readonly repoRoot: string
  /** The installer's environment, which the child's is picked from (default: process.env). */
  readonly env?: Readonly<Record<string, string | undefined>>
  readonly spawn?: SpawnFn
  readonly now?: () => Date
}

const refused = (message: string, step?: string): InstallRunError => new InstallRunError('AOS_INSTALL_RUN_REFUSED', message, step)

/** An error by its errno or Node code, else its class: never its message, which may quote what it was handed. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

/**
 * The environment a child runs with: the allowlisted names the installer has,
 * PATH fixed, and SSH_AUTH_SOCK only when the program is git.
 */
export function childEnv(parent: Readonly<Record<string, string | undefined>>, command: string): Record<string, string> {
  const home = parent['HOME']
  if (home === undefined || !isAbsolute(home) || home.includes(':')) {
    throw refused('HOME is not set to an absolute path without a colon, so no PATH can be built for a child')
  }
  const env: Record<string, string> = {}
  const names = basename(command) === 'git' ? [...PASSED_NAMES, ...GIT_ONLY_NAMES] : PASSED_NAMES
  for (const name of names) {
    const value = parent[name]
    if (value !== undefined && value !== '') env[name] = value
  }
  env['PATH'] = childPath(home)
  return env
}

/** True when a string holds a registered secret or a credential shape. */
const holdsCredential = (s: string): boolean => redactString(s) !== s

/** The service script a file name is, in any case. */
const scriptNamed = (name: string): string | undefined => {
  const lower = name.toLowerCase()
  return SERVICE_SCRIPTS.find((s) => s === lower)
}

/** The basename of what a path resolves to, when it resolves. */
function resolvedName(path: string): string | undefined {
  try {
    return basename(realpathSync(path))
  } catch {
    return undefined
  }
}

/** The stop or start script `command` runs, by its own name in any case or by what a link resolves to; else undefined. */
function serviceScript(command: string): string | undefined {
  const named = scriptNamed(basename(command))
  if (named !== undefined || !isAbsolute(command)) return named
  const resolved = resolvedName(command)
  return resolved === undefined ? undefined : scriptNamed(resolved)
}

/** True when an argument names a service script: as text in any case, or as a path (from cwd) that resolves to one. */
function namesScript(arg: string, cwd: string): boolean {
  const lower = arg.toLowerCase()
  if (SERVICE_SCRIPTS.some((s) => lower.includes(s))) return true
  if (arg === '') return false
  const resolved = resolvedName(resolve(cwd, arg))
  return resolved !== undefined && scriptNamed(resolved) !== undefined
}

/** The arguments the stop or start script may be given here (the contract); anything else is refused. */
function scriptArgsAllowed(script: string, args: readonly string[]): boolean {
  if (script === START_SCRIPT) return args.length === 0 || (args.length === 1 && args[0] === '--check')
  if (args.length === 1 && args[0] === '--jobs') return true
  let quiet = false
  let wait = false
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]
    if (arg === '--quiet' && !quiet) {
      quiet = true
    } else if (arg === '--wait-timeout' && !wait) {
      // Whole seconds as the script reads them: no sign, no leading 0, no more digits than bash arithmetic holds.
      const n = args[i + 1]
      if (n === undefined || !/^[1-9][0-9]{0,8}$/.test(n) || Number(n) < MIN_WAIT_TIMEOUT_S) return false
      wait = true
      i += 1
    } else {
      return false
    }
  }
  return true
}

/** What checkSpec found: the service script the spec runs, if any, and whether it runs in its own session. */
interface Checked {
  readonly script: string | undefined
  readonly ownSession: boolean
}

/** Check a spec without touching anything. */
function checkSpec(spec: RunSpec, env: Readonly<Record<string, string>>): Checked {
  const { step } = spec
  if (!STEP_NAME.test(step)) throw refused(`a step is named [a-z0-9][a-z0-9._-]*, at most 48 characters; got ${JSON.stringify(redactString(step))}`)
  if (!isAbsolute(spec.cwd)) throw refused(`${step}: the working directory must be absolute`, step)
  if (!isAbsolute(spec.command) && !BARE_PROGRAM.test(spec.command)) {
    throw refused(`${step}: the command must be an absolute path or a bare program name`, step)
  }
  // Every byte that leaves for the child, before anything is created.
  const where: [string, string][] = [
    ['the command', spec.command],
    ['the working directory', spec.cwd],
    ...spec.args.map((a, i): [string, string] => [`argument ${String(i + 1)}`, a]),
    ...Object.entries(env).map(([k, v]): [string, string] => [`the environment's ${k}`, v]),
  ]
  if (spec.digest !== undefined) where.push(['stdin', spec.digest])
  for (const [what, text] of where) {
    if (holdsCredential(text)) throw refused(`${step}: ${what} holds a registered secret or a credential shape; nothing was run`, step)
  }
  if (spec.digest !== undefined && !DIGEST_LINE.test(spec.digest)) {
    throw refused(`${step}: stdin carries one sha256:<64 lowercase hex> digest or nothing; nothing was run`, step)
  }
  const script = serviceScript(spec.command)
  if (script === undefined) {
    if (spec.args.some((a) => namesScript(a, spec.cwd)) || SERVICE_SCRIPTS.some((s) => spec.command.toLowerCase().includes(s))) {
      throw refused(`${step}: the stop and start scripts run only as the command itself, by absolute path; nothing was run`, step)
    }
    const ownSession = spec.ownSession === true
    if (spec.timeoutMs !== undefined) {
      if (ownSession) throw refused(`${step}: a step in its own session is given no timeout; nothing was run`, step)
      if (!Number.isInteger(spec.timeoutMs) || spec.timeoutMs <= 0 || spec.timeoutMs > MAX_TIMEOUT_MS) {
        throw refused(`${step}: timeoutMs must be a whole number of milliseconds from 1 to a day`, step)
      }
    }
    return { script: undefined, ownSession }
  }
  if (!isAbsolute(spec.command)) throw refused(`${step}: ${script} runs only by absolute path; nothing was run`, step)
  if (!scriptArgsAllowed(script, spec.args)) {
    const allowed = script === START_SCRIPT ? 'no argument or --check' : `no argument, --jobs alone, or --quiet and --wait-timeout N (N at least ${String(MIN_WAIT_TIMEOUT_S)})`
    throw refused(`${step}: ${script} is run here only with ${allowed}; nothing was run`, step)
  }
  if (spec.timeoutMs !== undefined) throw refused(`${step}: ${script} is given no timeout; nothing was run`, step)
  if (spec.digest !== undefined) throw refused(`${step}: ${script} takes no stdin; nothing was run`, step)
  return { script, ownSession: true }
}

/** The UTC stamp a run's folder is named by: 20261029T054506Z. */
export function stampOf(at: Date): string {
  return at.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')
}

/** <repoRoot>/.aos/install: the runs' folders and active.json. */
export function installDir(repoRoot: string): string {
  return join(repoRoot, '.aos', 'install')
}

export function activePath(repoRoot: string): string {
  return join(installDir(repoRoot), 'active.json')
}

const euid = (): number | undefined => process.geteuid?.()

/**
 * Make a directory 0700. False when it was there already. umask only clears
 * bits, and one of 0700 would leave none, hence the chmod.
 */
function makeDirectory(path: string): boolean {
  try {
    mkdirSync(path, { mode: 0o700 })
  } catch (e) {
    if (errnoOf(e) === 'EEXIST') return false
    throw refused(`cannot make ${path} (${errnoOf(e)})`)
  }
  chmodSync(path, 0o700)
  return true
}

/** A directory the logs may go beneath: one, not a link, this account's, and no one else's to write in. */
function checkDirectory(path: string): void {
  const st = lstatSync(path)
  if (st.isSymbolicLink() || !st.isDirectory()) throw refused(`${path} is not a directory (a link is not one): the installer writes its logs only beneath a real one`)
  const me = euid()
  if (me !== undefined && st.uid !== me) throw refused(`${path} belongs to uid ${String(st.uid)}, not this account`)
  if ((st.mode & 0o022) !== 0) throw refused(`${path} is writable by group or others: chmod go-w ${path}, then re-run`)
}

/** Create a log file: 0600, exclusive, never through a link, appended to by the child. */
function createLog(path: string): number {
  let fd: number
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_APPEND, 0o600)
  } catch (e) {
    throw refused(`cannot create ${path} (${errnoOf(e)}); nothing was run`)
  }
  try {
    fchmodSync(fd, 0o600)
    if ((fstatSync(fd).mode & 0o777) !== 0o600) throw refused(`${path} does not keep mode 0600 on this filesystem`)
  } catch (e) {
    closeSync(fd)
    throw e
  }
  return fd
}

/** readSync's shape, as readAt calls it. */
export type ReadFn = (fd: number, buffer: Buffer, offset: number, length: number, position: number) => number

/**
 * Up to `length` bytes of a file from `position`, over as many reads as it
 * takes: a short read is read on from, and only the end of the file returns
 * fewer, so the buffer never carries bytes nothing was read into.
 */
export function readAt(fd: number, length: number, position: number, read: ReadFn = readSync): Buffer {
  const buf = Buffer.alloc(length)
  let got = 0
  while (got < length) {
    const n = read(fd, buf, got, length - got, position + got)
    if (n <= 0) break
    got += n
  }
  return buf.subarray(0, got)
}

const ActiveRecord = z.object({
  step: z.string(),
  pid: z.number().int().positive(),
  started: z.string(),
  out: z.string(),
  err: z.string(),
})
export type ActiveRecord = z.infer<typeof ActiveRecord>

export type Active =
  | { readonly state: 'none' }
  | { readonly state: 'recorded'; readonly record: ActiveRecord }
  /** A record that cannot be read: one being written when the installer died counts, and is no proof the child is gone. */
  | { readonly state: 'unreadable'; readonly reason: string }

/** What active.json says: a step in its own session that this installer started may still run. */
export function readActive(repoRoot: string): Active {
  const path = activePath(repoRoot)
  let text: string
  try {
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
      const size = fstatSync(fd).size
      if (size > 4096) return { state: 'unreadable', reason: `${path} is ${String(size)} bytes` }
      text = readAt(fd, size, 0).toString('utf8')
    } finally {
      closeSync(fd)
    }
  } catch (e) {
    if (errnoOf(e) === 'ENOENT') return { state: 'none' }
    return { state: 'unreadable', reason: `${path} cannot be read (${errnoOf(e)})` }
  }
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    return { state: 'unreadable', reason: `${path} is not JSON` }
  }
  const parsed = ActiveRecord.safeParse(json)
  if (!parsed.success) return { state: 'unreadable', reason: `${path} is not a record of a running step` }
  return { state: 'recorded', record: parsed.data }
}

/** Remove active.json, once the caller has seen the child it records gone. */
export function clearActive(repoRoot: string): void {
  try {
    unlinkSync(activePath(repoRoot))
  } catch (e) {
    if (errnoOf(e) !== 'ENOENT') throw refused(`cannot remove ${activePath(repoRoot)} (${errnoOf(e)})`)
  }
}

/** True when the file holds a value registered with SecretMask; a file that cannot be read counts. */
function holdsRegistered(path: string): boolean {
  if (SecretMask.size === 0) return false
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch {
    return true
  }
  try {
    let carry = Buffer.alloc(0)
    const chunk = Buffer.alloc(SCAN_CHUNK)
    for (;;) {
      const n = readSync(fd, chunk, 0, SCAN_CHUNK, null)
      if (n === 0) return false
      const window = Buffer.concat([carry, chunk.subarray(0, n)])
      const text = window.toString('utf8')
      if (SecretMask.apply(text) !== text) return true
      carry = window.subarray(Math.max(0, window.length - SCAN_OVERLAP))
    }
  } catch {
    return true
  } finally {
    closeSync(fd)
  }
}

/** Empty a log file that held a registered value. */
function empty(path: string): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_NOFOLLOW)
  try {
    ftruncateSync(fd, 0)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/** Terminal control: CSI and other escape sequences, then every C0 and C1 control but tab. */
const CONTROL = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|[\x00-\x08\x0a-\x1f\x7f-\x9f]/g

/** One line of child output as it may be shown: no terminal control, scrubbed. */
export function shownLine(line: string): string {
  return redactString(line.replace(CONTROL, ''))
}

/** The last `lines` lines of a log file, as they may be shown. A file that is not there shows nothing. */
export function tail(path: string, lines = 20): string[] {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch (e) {
    if (errnoOf(e) === 'ENOENT') return []
    throw new InstallRunError('AOS_INSTALL_RUN_OUTPUT', `cannot read ${path} (${errnoOf(e)})`)
  }
  try {
    const size = fstatSync(fd).size
    const from = Math.max(0, size - TAIL_BYTES)
    const all = readAt(fd, size - from, from).toString('utf8').split('\n')
    // Read from the middle of a line: drop its end, and the empty piece after a final newline.
    if (from > 0) all.shift()
    if (all.at(-1) === '') all.pop()
    return all.slice(-lines).map(shownLine)
  } finally {
    closeSync(fd)
  }
}

/** A child's stdout, for parsing: whole, valid UTF-8, and at most `maxBytes`. */
export function readOut(result: Pick<RunResult, 'step' | 'out'>, maxBytes = MAX_MACHINE_OUTPUT): string {
  const fail = (why: string): InstallRunError => new InstallRunError('AOS_INSTALL_RUN_OUTPUT', `${result.step}: stdout ${why}`, result.step)
  let fd: number
  try {
    fd = openSync(result.out, constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch (e) {
    throw fail(`cannot be read (${errnoOf(e)})`)
  }
  try {
    const size = fstatSync(fd).size
    if (size > maxBytes) throw fail(`is ${String(size)} bytes, over the ${String(maxBytes)} machine output may be`)
    const buf = readAt(fd, size, 0)
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(buf)
    } catch {
      throw fail('is not valid UTF-8')
    }
  } finally {
    closeSync(fd)
  }
}

export type Jobs =
  | { readonly running: number; readonly display: readonly string[] }
  | { readonly running: 'unknown' }

/** The longest job listing shown. */
const MAX_JOB_LINES = 50

/**
 * `stop-pmmcp-server.sh --jobs`, as its contract has it: stdout's first line
 * alone, `running jobs: N` with exit 0 or `running jobs: unknown` with exit 1.
 * Anything else, a line on stderr included however much it looks like a
 * count, is no answer (undefined). The job lines after the first are display
 * text, returned as they may be shown, never parsed.
 */
export function readJobs(result: RunResult): Jobs | undefined {
  const text = readOut(result)
  const lines = text.split('\n')
  const first = /^running jobs: (0|[1-9][0-9]{0,8}|unknown)$/.exec(lines[0] ?? '')
  if (first === null || result.signal !== null || !result.exited) return undefined
  if (first[1] === 'unknown') return result.code === 1 ? { running: 'unknown' } : undefined
  if (result.code !== 0) return undefined
  const display = lines.slice(1).filter((l) => l.trim() !== '').slice(0, MAX_JOB_LINES).map(shownLine)
  return { running: Number(first[1]), display }
}

/**
 * Runs the installer's children by the rules in the contract. One per
 * installer run: its first child makes <repo>/.aos/install/<UTC stamp>/.
 */
export class Runner {
  readonly repoRoot: string
  readonly #env: Readonly<Record<string, string | undefined>>
  readonly #spawn: SpawnFn
  readonly #now: () => Date
  #dir: string | undefined
  readonly #steps = new Set<string>()
  #halted: string | undefined

  constructor(options: RunnerOptions) {
    if (!isAbsolute(options.repoRoot)) throw refused('the repository root must be an absolute path')
    this.repoRoot = options.repoRoot
    this.#env = options.env ?? process.env
    this.#spawn = options.spawn ?? realSpawn
    this.#now = options.now ?? ((): Date => new Date())
  }

  /** This run's log folder, once a child has made it. */
  get dir(): string | undefined {
    return this.#dir
  }

  /** Why nothing more is run, once a child's output held a registered value. */
  get halted(): string | undefined {
    return this.#halted
  }

  /** Run a child to its exit. */
  run(spec: RunSpec): Promise<RunResult> {
    return this.start(spec).done
  }

  /** Start a child; `done` settles when it exits. Every refusal is thrown here, before anything exists. */
  start(spec: RunSpec): Started {
    if (this.#halted !== undefined) {
      throw new InstallRunError('AOS_INSTALL_RUN_HALTED', `${spec.step}: not run: ${this.#halted}`, spec.step)
    }
    const env = childEnv(this.#env, spec.command)
    const { script, ownSession } = checkSpec(spec, env)
    if (ownSession) {
      const active = readActive(this.repoRoot)
      if (active.state !== 'none') throw this.#busy(spec.step, active)
    }

    const dir = this.#logDir()
    const step = this.#uniqueStep(spec.step)
    const out = join(dir, `${step}.out`)
    const err = join(dir, `${step}.err`)
    const outFd = createLog(out)
    let errFd: number
    try {
      errFd = createLog(err)
    } catch (e) {
      closeSync(outFd)
      throw e
    }
    const started = this.#now()

    let child: ChildLike
    let claim: number | undefined
    try {
      if (ownSession) claim = this.#claim(spec.step)
      child = this.#spawn(spec.command, spec.args, {
        cwd: spec.cwd,
        env,
        stdio: [spec.digest === undefined ? 'ignore' : 'pipe', outFd, errFd],
        detached: ownSession,
      })
    } catch (e) {
      const left = claim === undefined ? undefined : this.#release(claim)
      if (e instanceof InstallRunError && left === undefined) throw e
      throw new InstallRunError('AOS_INSTALL_RUN_SPAWN', `${step}: ${spec.command} could not be started (${errnoOf(e)})${left === undefined ? '' : `; ${left}`}`, step)
    } finally {
      // The child holds its own copies.
      closeSync(outFd)
      closeSync(errFd)
    }
    const pid = child.pid
    let activeError: string | undefined
    if (claim !== undefined) {
      // No pid: the spawn failed, and its 'error' comes next, so nothing here may throw past the listeners below.
      activeError = pid === undefined ? this.#release(claim) : this.#record(claim, { step, pid, started: started.toISOString(), out, err })
    }

    let stdinError: string | undefined
    if (spec.digest !== undefined) {
      if (child.stdin === null) stdinError = 'no stdin'
      else {
        // A child that ends without reading its stdin closes the pipe; its exit code says what it made of that.
        child.stdin.on('error', (e: Error) => {
          stdinError = errnoOf(e)
        })
        child.stdin.end(`${spec.digest}\n`)
      }
    }

    const done = new Promise<RunResult>((resolveRun, reject) => {
      let settled = false
      let timedOut = false
      let childError: string | undefined
      let timer: NodeJS.Timeout | undefined
      let grace: NodeJS.Timeout | undefined
      const stopTimers = (): void => {
        if (timer !== undefined) clearTimeout(timer)
        if (grace !== undefined) clearTimeout(grace)
      }
      const finish = (code: number | null, signal: NodeJS.Signals | null, exited: boolean): void => {
        if (settled) return
        settled = true
        stopTimers()
        const cleared = ownSession && exited ? this.#clearOwn(pid) : undefined
        const result: RunResult = {
          step,
          pid,
          out,
          err,
          started,
          elapsedMs: this.#now().getTime() - started.getTime(),
          code,
          signal,
          timedOut,
          exited,
          stdinError,
          childError,
          activeError: cleared,
        }
        const leaked = [out, err].filter(holdsRegistered)
        if (leaked.length === 0) {
          resolveRun(result)
          return
        }
        const emptied: string[] = []
        for (const path of leaked) {
          try {
            empty(path)
            emptied.push(path)
          } catch (e) {
            emptied.push(`${path} (could not be emptied: ${errnoOf(e)}; delete it)`)
          }
        }
        this.#halted = `a registered secret value reached ${step}'s output, a defect; the file was emptied: ${emptied.join(', ')}`
        reject(new InstallRunError('AOS_INSTALL_RUN_LEAK', `${step}: ${this.#halted}. Nothing more is run.`, step, result))
      }
      if (spec.timeoutMs !== undefined && !ownSession) {
        const { timeoutMs } = spec
        timer = setTimeout(() => {
          timedOut = true
          child.kill('SIGKILL')
          // A process in uninterruptible sleep dies only when its syscall returns: report it rather than wait on it for ever.
          grace = setTimeout(() => finish(null, null, false), KILL_GRACE_MS)
        }, timeoutMs)
      }
      child.once('error', (e) => {
        // Spawned: the only error left is a failed kill. It is reported with the exit, which still comes and decides.
        if (pid !== undefined) {
          childError = errnoOf(e)
          return
        }
        if (settled) return
        settled = true
        stopTimers()
        reject(new InstallRunError('AOS_INSTALL_RUN_SPAWN', `${step}: ${spec.command} could not be started (${errnoOf(e)})`, step))
      })
      child.once('exit', (code, signal) => {
        finish(code, signal, true)
      })
    })
    return { step, pid, out, err, started, activeError, done }
  }

  #busy(step: string, active: Active): InstallRunError {
    const what =
      active.state === 'recorded'
        ? `${active.record.step} (pid ${String(active.record.pid)}, since ${active.record.started}, output in ${active.record.out} and ${active.record.err})`
        : active.state === 'unreadable'
          ? `a step whose record cannot be read (${active.reason})`
          : 'a step whose record was there a moment ago'
    return new InstallRunError(
      'AOS_INSTALL_RUN_BUSY',
      `${step}: not run: ${activePath(this.repoRoot)} says an earlier step in its own session (a stop, a start, or a step inside the stopped window) may still be running: ${what}. ` +
        'Wait for it to end; nothing is stopped or started meanwhile.',
      step,
    )
  }

  /** The run's log folder, made on first use, under a .aos git ignores. */
  #logDir(): string {
    if (this.#dir !== undefined) return this.#dir
    if (!gitignoresAos(this.repoRoot)) {
      throw refused('.gitignore does not ignore /.aos/, where the installer keeps its logs: add the line /.aos/, then re-run')
    }
    try {
      assertAosEntry(this.repoRoot)
    } catch (e) {
      throw e instanceof ConfigError ? refused(e.message) : e
    }
    for (const dir of [join(this.repoRoot, '.aos'), installDir(this.repoRoot)]) {
      makeDirectory(dir)
      checkDirectory(dir)
    }
    const stamp = stampOf(this.#now())
    for (let n = 1; n <= 100; n += 1) {
      const dir = join(installDir(this.repoRoot), n === 1 ? stamp : `${stamp}-${String(n)}`)
      if (!makeDirectory(dir)) continue
      checkDirectory(dir)
      this.#dir = dir
      return dir
    }
    throw refused(`${installDir(this.repoRoot)} already holds 100 runs stamped ${stamp}`)
  }

  #uniqueStep(step: string): string {
    let name = step
    for (let n = 2; this.#steps.has(name); n += 1) name = `${step}-${String(n)}`
    this.#steps.add(name)
    return name
  }

  /** Claim active.json before the spawn, exclusively: a second claim fails while the first stands. */
  #claim(step: string): number {
    try {
      const fd = openSync(activePath(this.repoRoot), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
      fchmodSync(fd, 0o600)
      return fd
    } catch (e) {
      if (errnoOf(e) === 'EEXIST') throw this.#busy(step, readActive(this.repoRoot))
      throw refused(`${step}: cannot create ${activePath(this.repoRoot)} (${errnoOf(e)}); nothing was run`, step)
    }
  }

  /**
   * Fill the claim once the pid is known. The child runs by now, so a write
   * that fails is returned rather than thrown: it leaves the record
   * unreadable, which a re-run reads as a window that may be open.
   */
  #record(fd: number, record: ActiveRecord): string | undefined {
    try {
      writeSync(fd, `${JSON.stringify(record)}\n`)
      fsyncSync(fd)
      return undefined
    } catch (e) {
      return `${activePath(this.repoRoot)} could not be filled in (${errnoOf(e)})`
    } finally {
      closeSync(fd)
    }
  }

  /** Give a claim back: no child was started. Returns why the record stays, rather than throwing over the error that brought it here. */
  #release(fd: number): string | undefined {
    closeSync(fd)
    return this.#removeRecord()
  }

  /**
   * Remove active.json when it records this child, which has exited. Called
   * from the child's exit, so an error is returned, never thrown: thrown
   * there it would escape as an uncaught exception, and the step's leak scan
   * would never run.
   */
  #clearOwn(pid: number | undefined): string | undefined {
    const active = readActive(this.repoRoot)
    if (active.state === 'recorded' && active.record.pid !== pid) return undefined
    return this.#removeRecord()
  }

  #removeRecord(): string | undefined {
    try {
      clearActive(this.repoRoot)
      return undefined
    } catch (e) {
      return `${e instanceof Error ? e.message : 'active.json could not be removed'}: remove it once nothing it names runs`
    }
  }
}
