// A typed force-quit of the one pmmcp service the stop is waiting on.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), and only
//   from its SIGINT handler, when scripts/install/signals.ts decides
//   `force-quit`: a Ctrl-C while L1's stop-pmmcp-server.sh runs inside the
//   stopped window. Nothing else in scripts/ or src/install imports it, and it
//   is the one installer module (scripts/install.ts, scripts/install/,
//   src/install) that sends a process a signal (process.kill with a signal
//   other than 0), once, to one pid. Outside the installer only the mutation
//   runner, scripts/falsify/runner.ts, sends one: to the process group of a
//   test run it started itself, never to anything of pmmcp's.
//   test/hygiene.test.ts holds all of it, and refuses there any other
//   reference to process.kill or to a member of process that reaches a
//   signal beneath it (`_kill`, any other `_` member, `binding`, `dlopen`),
//   any alias of process or globalThis, and node:process loaded any way but
//   a static import it follows (a re-export, import(), require(),
//   createRequire, getBuiltinModule). It is a tripwire for natural code: a
//   module name built from parts, and what eval, new Function or vm run, are
//   beyond any static scan, and a reviewer reads those by eye. It is the one
//   exception CLAUDE.md "Never" makes to its rule that pmmcp is stopped only
//   by stop-pmmcp-server.sh without --force and that nothing sends the stop a
//   signal: "no SIGKILL to a pmmcp service but the one the operator types
//   `force-quit` for while the stop waits on it" (the operator's approval of
//   2026-11-04, docs/DECISIONS.md D35). The stop itself is never signalled,
//   only the service its drain waits on, and only once the operator has
//   typed force-quit for it.
//
//   Why: inside the window the installer holds every signal and the stop
//   runs in a session of its own (A3), while the stop's drain waits on a
//   service with no upper bound and offers only Ctrl+C, which cannot reach
//   it. A hung service would leave the operator no way out from the
//   installer.
//
//   In order (offerForceQuit):
//     The target: the stop's current drain target (scripts/install/drain.ts),
//       its stdout read once more first. None (the stop is counting jobs,
//       stopping Qdrant with docker stop -t 60, or between services): one
//       line says so, nothing is force-quit, and the stop goes on.
//     Its identity, by ps through the runner (its rules; ps's two files
//       emptied once read, since they hold other processes' command lines):
//       `ps -o lstart= -p <pid>`, its start time, kept as ps prints it (macOS
//       prints it in the locale's form, so it is compared, never parsed),
//       `ps -ww -o pid=,uid=,pgid=,args= -p <pid>,<installer>,<stop>`, and its
//       start time once more after that row: the two readings must be equal,
//       so the row is the same process's as the start time (a pid given to
//       another process between the two calls is caught by the second). It
//       must be alive; this account's uid; and pmmcp's by one of the stop
//       script's own rules. Either its command line holds
//       Persistent-Memory-MCP or a word that is the install's folder or
//       starts with it (as typed or resolved; ASCII case folded on macOS:
//       _is_pmmcp_process), or, while the stop drains one of pmmcp's Ollama
//       instances (its label `<role> (port <n>)` or `<role> port-scan (port
//       <n>)`, the role one of PMMCP_OLLAMA_ROLES: PMMCP-TextQuery,
//       PMMCP-CodeQuery, PMMCP-TextIndex, PMMCP-CodeIndex), it is exactly two
//       words, the first that role's name or PMMCP-Ollama (case exact on
//       every system, no path before it) and the second `serve` (the forms
//       _is_pmmcp_ollama vouches for with no PID file for that role: how
//       pmmcp's MCP server and its embedding health monitor start them).
//       Under any other label no Ollama form is taken. Refused, with why and
//       the way out (check it with ps in another terminal and end it there):
//       exactly `ollama serve`, which only a PID file of the start script
//       vouches for (the installer reads none, and Ollama.app's and
//       Homebrew's servers look the same once their path is dropped); an
//       ollama in any case, or a PMMCP- name, run by a path (Ollama.app's
//       /Applications/Ollama.app/Contents/Resources/ollama, Homebrew's
//       <prefix>/bin/ollama); a word after `serve`, or another verb; an
//       ollama in another case, or a PMMCP- name that is none of those five;
//       another role's name, or any of the five while the stop drains a
//       service that is no Ollama instance (the pid was given to another
//       process since the stop's line). And it must not be pid 1, the
//       installer's pid or a process in its
//       group, nor the stop script's pid or a process in its group (the
//       runner starts the stop in a session, so a group, of its own).
//       Anything else, or a ps that gives no answer (one the terminal's
//       Ctrl-C ended is asked again, up to PS_TRIES times), is said in one
//       line, and nothing is force-quit.
//     The question, through the terminal the gate asks with: `pmmcp's stop
//       is waiting on <label> (PID <n>: <command line, control characters
//       stripped, cut to CMD_SHOWN>) for <s>s. Type force-quit to SIGKILL
//       that one process (the stop then goes on); anything else keeps
//       waiting:`. Only force-quit (trimmed, as the gate reads every typed
//       word) acts. Any other line, the input ending, and a second Ctrl-C
//       (which answers the open question, signals.ts) keep waiting, and so
//       does the offer's withdrawal (`cancelled`: a second Ctrl-C before the
//       question, or the stop's end).
//     Just before the kill, again: the offer was not withdrawn, the stop
//       still runs (`running`) and still waits on that pid and label, and ps
//       shows the same start time (both readings), uid and command line and
//       none of the excluded pids or groups. So a pid given to another process
//       since the question was asked is never signalled. Then process.kill(pid,
//       'SIGKILL'), once (sigkill); ESRCH (it exited meanwhile) or EPERM is
//       said, and is no kill.
//     The record: a line in the run folder's force-quit.log (0600, appended,
//       never through a link), and the outcome `killed` with what the end
//       report says (drain.ts forceQuitLine); the stop then sees the pid gone
//       and goes on, and the installer goes on to the start and its checks.
//
//   <s> is the time since the installer first read the stop's "Sent SIGTERM"
//   line for it (the entry point reads the stop's stdout every second), in
//   whole seconds.

import { closeSync, constants, fchmodSync, fstatSync, openSync, realpathSync, writeSync } from 'node:fs'
import { join } from 'node:path'

import type { Answer } from '../../src/install/gate.js'
import { forceQuitLine, type DrainTarget, type ForceQuitRecord } from './drain.js'
import { InstallRunError, readOut, shownLine, type RunResult, type Runner } from './run.js'

/** The one word that SIGKILLs the target. */
export const FORCE_QUIT_WORD = 'force-quit'

/** The most of a command line the question shows. */
export const CMD_SHOWN = 120

/** How many times a ps the terminal's Ctrl-C ended is asked. */
export const PS_TRIES = 3

/** The file in the run's log folder each force-quit is recorded in. */
export const FORCE_QUIT_LOG = 'force-quit.log'

/** The name the stop script's ownership rule looks for in a command line. */
export const PROJECT_NAME = 'Persistent-Memory-MCP'

/**
 * pmmcp's four Ollama roles, as the stop names the instance it drains (the
 * first word of its label) and as pmmcp's MCP server names the instance's
 * argv[0] when it starts one as `<role> serve` (src/ollama_manager.py's
 * ensure_ollama_running).
 */
export const PMMCP_OLLAMA_ROLES: readonly string[] = ['PMMCP-TextQuery', 'PMMCP-CodeQuery', 'PMMCP-TextIndex', 'PMMCP-CodeIndex']

/** The name pmmcp's embedding health monitor relaunches an instance of any role under (`PMMCP-Ollama serve`, _launch_ollama's default). */
export const PMMCP_OLLAMA_RELAUNCHED = 'PMMCP-Ollama'

/**
 * pmmcp's named Ollama instances, as the first word of their command lines:
 * the four roles and the health monitor's name. The stop script's
 * _is_pmmcp_ollama takes `<role> serve` and `PMMCP-Ollama serve` with no PID
 * file while it drains that role; `ollama serve` only with one.
 */
export const PMMCP_OLLAMA_NAMES: readonly string[] = [...PMMCP_OLLAMA_ROLES, PMMCP_OLLAMA_RELAUNCHED]

const PS_MS = 15_000

/** What the stop's own drain says it waits for, as a process: what ps shows of it, and of the installer and the stop. */
export interface PsRow {
  readonly pid: number
  readonly uid: number
  readonly pgid: number
  readonly args: string
}

export interface Snapshot {
  /** ps lstart, as printed. */
  readonly start: string
  /** ps lstart again, read after the row: unless it equals `start`, the row may be another process's. */
  readonly startAfter: string
  readonly target: PsRow
  /** The installer's process group; undefined when ps did not list the installer. */
  readonly installerPgid: number | undefined
  /** The stop script's process group; undefined when ps did not list it (it has exited). */
  readonly stopPgid: number | undefined
}

/** Who may not be signalled, and whose a target must be. */
export interface Guard {
  /** This account's uid: the target's must be it. */
  readonly uid: number | undefined
  readonly installerPid: number
  readonly stopPid: number
  /** The install's folder, as typed and as resolved. */
  readonly dirs: readonly string[]
  /** macOS: command lines and folders compared without regard to ASCII case. */
  readonly darwin: boolean
}

/** ASCII letters lowercased on macOS, as the stop script's _fold_case does; as it is elsewhere. */
const fold = (s: string, darwin: boolean): string => (darwin ? s.replace(/[A-Z]+/g, (c) => c.toLowerCase()) : s)

/**
 * Whether a command line is pmmcp's by the stop script's rule
 * (_is_pmmcp_process): it holds Persistent-Memory-MCP, or a word that is one
 * of `dirs` or starts with it and a slash.
 */
export function pmmcpCommand(args: string, dirs: readonly string[], darwin: boolean): boolean {
  const a = fold(args.trim(), darwin)
  if (a.includes(fold(PROJECT_NAME, darwin))) return true
  const words = ` ${a} `
  return dirs.some((dir) => {
    const d = fold(dir, darwin)
    return d !== '' && (words.includes(` ${d}/`) || words.includes(` ${d} `))
  })
}

/** A command line's words as the stop script's `read -r` splits a ps row: at spaces and tabs (bash's default IFS within a line), those at either end dropped. */
const wordsOf = (args: string): string[] => args.split(/[ \t]+/).filter((w) => w !== '')

/**
 * The Ollama role a drain's label names, as the stop's two graceful_kill
 * calls for an instance write it: `<role> (port <n>)` (from its PID file) or
 * `<role> port-scan (port <n>)` (from its port), the role one of
 * PMMCP_OLLAMA_ROLES as written; undefined for any other label (a Worker, the
 * MCP Server, ...).
 */
export function ollamaRole(label: string): string | undefined {
  const m = /^(\S+) (?:port-scan )?\(port [0-9]{1,5}\)$/.exec(label)
  const role = m?.[1]
  return role !== undefined && PMMCP_OLLAMA_ROLES.includes(role) ? role : undefined
}

/**
 * Whether a command line is the Ollama instance the stop drains under
 * `label`, by the stop script's rule (_is_pmmcp_ollama "$pid" "$_ol_name",
 * the forms it takes with no PID file): the label names a role (ollamaRole),
 * and the command line is exactly two words, the first that role's name or
 * PMMCP-Ollama as written (no path before it, case exact on every system:
 * the stop folds no case here) and the second `serve`. Under any other label,
 * no command line is.
 */
export function pmmcpOllama(args: string, label: string): boolean {
  const role = ollamaRole(label)
  const [name, verb, ...rest] = wordsOf(args)
  return role !== undefined && (name === role || name === PMMCP_OLLAMA_RELAUNCHED) && verb === 'serve' && rest.length === 0
}

/**
 * Why a command line shaped like an Ollama server's (its first word ollama in
 * any case, or a PMMCP- name in any case, by a path or not) is not one the
 * installer force-quits while the stop drains `label`, with the way out;
 * undefined for any other command line, and for one pmmcpOllama takes. The
 * shape is matched without case so that an `Ollama serve` is told the way
 * out too; what is taken is pmmcpOllama's, case exact.
 */
export function ollamaRefusal(args: string, pid: number, label: string): string | undefined {
  const [first = '', verb, ...rest] = wordsOf(args)
  const base = first.slice(first.lastIndexOf('/') + 1)
  const ollama = base.toLowerCase() === 'ollama'
  if (!ollama && !/^pmmcp-/i.test(base)) return undefined
  const role = ollamaRole(label)
  const names = `${PMMCP_OLLAMA_NAMES.join(', ')}, case as written`
  let why: string
  if (base !== first) why = `it is run by a path (\`${shownCommand(first)}\`), as Ollama.app's and Homebrew's servers are and pmmcp's own Ollama instances never are`
  else if (ollama && base !== 'ollama') why = `\`${shownCommand(first)}\` is neither \`ollama\` nor one of pmmcp's named Ollama instances (${names})`
  else if (!ollama && !PMMCP_OLLAMA_NAMES.includes(base)) why = `\`${shownCommand(first)}\` is none of pmmcp's named Ollama instances (${names})`
  else if (verb !== 'serve') why = `its command line is not \`${first} serve\``
  else if (rest.length > 0) why = `its command line has a word after \`${first} serve\``
  else if (ollama) {
    why = "it is `ollama serve`, which only a PID file of pmmcp's start script vouches for (the installer reads none), and which Ollama.app's or Homebrew's server also is once its path is dropped"
  } else if (role === undefined) {
    why = `its command line is \`${first} serve\`, one of pmmcp's Ollama instances, but the stop is draining ${shownLine(label)}, which is none (the pid may have been given to another process since the stop's line)`
  } else if (base !== role && base !== PMMCP_OLLAMA_RELAUNCHED) {
    why = `its command line is \`${first} serve\`, but the stop is draining ${role}, and takes only \`${role} serve\` or \`${PMMCP_OLLAMA_RELAUNCHED} serve\` for it (the pid may have been given to another process since the stop's line)`
  } else return undefined
  return `${why} (to end it, check it with \`ps -ww -o pid,uid,lstart,args -p ${String(pid)}\` in another terminal, and end it there if it is pmmcp's)`
}

/**
 * Why the drain's target, as `snap` shows its pid, may not be SIGKILLed;
 * undefined when it may. Its label decides whether an Ollama form is
 * pmmcp's (pmmcpOllama). With `kept` (the snapshot the question was asked
 * on), it must also be that same process: the same start time, uid and
 * command line.
 */
export function targetRefusal(drain: Pick<DrainTarget, 'pid' | 'label'>, snap: Snapshot, guard: Guard, kept?: Snapshot): string | undefined {
  const pid = drain.pid
  if (pid <= 1) return `it is pid ${String(pid)}`
  if (pid === guard.installerPid) return "it is the installer's own process"
  if (pid === guard.stopPid) return 'it is the stop script itself'
  const t = snap.target
  if (t.pid !== pid) return `ps answered for pid ${String(t.pid)}`
  if (guard.uid === undefined || t.uid !== guard.uid) return `it is not this account's (uid ${String(t.uid)})`
  if (snap.installerPgid === undefined) return "the installer's own process group cannot be read"
  if (t.pgid === snap.installerPgid) return "it is in the installer's own process group"
  if (snap.stopPgid === undefined) return 'the stop script is no longer running'
  if (t.pgid === guard.stopPid || t.pgid === snap.stopPgid) return "it is in the stop script's own process group"
  if (!pmmcpCommand(t.args, guard.dirs, guard.darwin) && !pmmcpOllama(t.args, drain.label)) {
    return ollamaRefusal(t.args, pid, drain.label) ?? `its command line names neither ${PROJECT_NAME} nor ${guard.dirs[0] ?? 'the install'}, and is no named Ollama instance of pmmcp's (\`PMMCP-TextQuery serve\` and the like)`
  }
  if (snap.startAfter !== snap.start) return 'its start time changed while ps read it (the pid was given to another process)'
  if (kept !== undefined) {
    if (snap.start !== kept.start) return 'it is no longer the process you were asked about (its start time changed: the pid was given to another process)'
    if (t.uid !== kept.target.uid || t.args !== kept.target.args) return 'it is no longer the process you were asked about (its owner or command line changed)'
  }
  return undefined
}

/** A command line as the question shows it: control characters stripped, scrubbed, cut. */
export function shownCommand(args: string): string {
  const shown = shownLine(args).trim()
  return shown.length <= CMD_SHOWN ? shown : `${shown.slice(0, CMD_SHOWN - 3)}...`
}

/** The question, for a target ps confirmed. */
export function forceQuitQuestion(target: Pick<DrainTarget, 'pid' | 'label'>, args: string, seconds: number): string {
  return (
    `pmmcp's stop is waiting on ${shownLine(target.label)} (PID ${String(target.pid)}: ${shownCommand(args)}) for ${String(seconds)}s. ` +
    `Type ${FORCE_QUIT_WORD} to SIGKILL that one process (the stop then goes on); anything else keeps waiting:`
  )
}

/** Said when the stop waits on no service's drain. */
export const NO_TARGET =
  "Ctrl-C: pmmcp's stop is not waiting on a service's drain right now (it may be counting jobs, stopping Qdrant with docker stop -t 60, or between services): nothing to force-quit; the stop goes on."

export interface ForceQuitOptions {
  /** The runner every ps goes through. */
  readonly runner: Pick<Runner, 'run' | 'discard'>
  /** Where ps runs: the repository root. */
  readonly cwd: string
  /** The stop script's pid: its process group too (the runner starts it in a session of its own). */
  readonly stopPid: number
  /** What the stop waits on now, its stdout read afresh. */
  readonly target: () => DrainTarget | undefined
  /** L1's stop still runs. */
  readonly running: () => boolean
  /** The install's folder, as discovery found it (it is resolved here too). */
  readonly dir: string
  /** The terminal's question. */
  readonly ask: (question: string) => Promise<Answer>
  readonly print: (line: string) => void
  /** The run's log folder, for force-quit.log; undefined when none was made. */
  readonly logDir: string | undefined
  /** Aborted when the offer is withdrawn: a second Ctrl-C before the question, or the stop's end. */
  readonly cancelled?: AbortSignal
  /** This account's uid (default process.getuid()). */
  readonly uid?: number
  /** The uid force-quit.log must be owned by: the installer's effective uid, which creates it (default process.geteuid()). */
  readonly euid?: number
  /** The installer's pid (default process.pid). */
  readonly installerPid?: number
  /** Default: process.platform is darwin. */
  readonly darwin?: boolean
  /** Milliseconds (default Date.now). */
  readonly now?: () => number
}

export type ForceQuitOutcome =
  | { readonly kind: 'no-target' }
  | { readonly kind: 'refused'; readonly why: string }
  | { readonly kind: 'kept-waiting' }
  | { readonly kind: 'killed'; readonly record: ForceQuitRecord }

/** How a kill went: sent, or why not (an errno). */
export type Kill = { readonly sent: true } | { readonly sent: false; readonly why: string }

/** An error by its errno or Node code, else its class: never its message. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

/** The one signal the installer sends: SIGKILL, to the one pid the operator typed force-quit for. */
function sigkill(pid: number): Kill {
  try {
    process.kill(pid, 'SIGKILL')
    return { sent: true }
  } catch (e) {
    return { sent: false, why: errnoOf(e) }
  }
}

type PsAnswer = { readonly ok: true; readonly out: string; readonly code: number | null } | { readonly ok: false; readonly why: string }

/** One ps through the runner, its files emptied once read; one the terminal's Ctrl-C ended (it is the installer's own child) is asked again. */
async function ps(o: ForceQuitOptions, step: string, args: readonly string[]): Promise<PsAnswer> {
  for (let i = 0; i < PS_TRIES; i += 1) {
    let result: RunResult
    try {
      result = await o.runner.run({ step, command: 'ps', args, cwd: o.cwd, timeoutMs: PS_MS })
    } catch (e) {
      if (e instanceof InstallRunError) return { ok: false, why: e.message }
      throw e
    }
    let out: string | undefined
    try {
      out = readOut(result)
    } catch {
      out = undefined
    }
    const left = o.runner.discard(result)
    if (left !== undefined) o.print(left)
    if (result.exited && (result.signal === 'SIGINT' || result.signal === 'SIGHUP' || result.code === 130 || result.code === 129)) continue
    if (!result.exited || result.timedOut || result.signal !== null) return { ok: false, why: `ps ${result.timedOut ? 'gave no answer in time' : `ended by ${String(result.signal)}`}` }
    if (out === undefined) return { ok: false, why: "ps's output could not be read" }
    return { ok: true, out, code: result.code }
  }
  return { ok: false, why: `ps was interrupted ${String(PS_TRIES)} times` }
}

const ROW = /^\s*([0-9]{1,10})\s+([0-9]{1,10})\s+([0-9]{1,10})(?:\s+(.*))?$/

/** `pid`'s start time (ps lstart, as printed); 'gone' when it no longer runs. */
async function startOf(o: ForceQuitOptions, pid: number): Promise<string | 'gone' | { readonly why: string }> {
  const lstart = await ps(o, 'force-quit-lstart', ['-o', 'lstart=', '-p', String(pid)])
  if (!lstart.ok) return { why: lstart.why }
  const start = (lstart.out.split('\n')[0] ?? '').trim()
  if (lstart.code === 1 && lstart.out.trim() === '') return 'gone'
  if (lstart.code !== 0 || start === '') return { why: `ps -o lstart= exited ${String(lstart.code)}` }
  return start
}

/**
 * What ps shows of `pid` now, with the installer's and the stop's groups;
 * 'gone' when it no longer runs. Its start time is read before the row and
 * again after it (targetRefusal holds the two equal): ps cannot print lstart
 * and the row in one call that parses in every locale.
 */
async function snapshot(o: ForceQuitOptions, pid: number, guard: Guard): Promise<Snapshot | 'gone' | { readonly why: string }> {
  const start = await startOf(o, pid)
  if (typeof start !== 'string' || start === 'gone') return start
  const pids = [...new Set([pid, guard.installerPid, guard.stopPid])].map(String).join(',')
  const listed = await ps(o, 'force-quit-ps', ['-ww', '-o', 'pid=,uid=,pgid=,args=', '-p', pids])
  if (!listed.ok) return { why: listed.why }
  if (listed.code !== 0 && listed.code !== 1) return { why: `ps -o pid=,uid=,pgid=,args= exited ${String(listed.code)}` }
  const rows = new Map<number, PsRow>()
  for (const line of listed.out.split('\n')) {
    const m = ROW.exec(line)
    if (m === null) continue
    const row = { pid: Number(m[1]), uid: Number(m[2]), pgid: Number(m[3]), args: (m[4] ?? '').trim() }
    if (!rows.has(row.pid)) rows.set(row.pid, row)
  }
  const target = rows.get(pid)
  if (target === undefined) return 'gone'
  const startAfter = await startOf(o, pid)
  if (typeof startAfter !== 'string' || startAfter === 'gone') return startAfter
  return { start, startAfter, target, installerPgid: rows.get(guard.installerPid)?.pgid, stopPgid: rows.get(guard.stopPid)?.pgid }
}

/** The install's folder as typed and as resolved, as the stop script compares both. */
function dirsOf(dir: string): string[] {
  const dirs = [dir]
  try {
    const real = realpathSync(dir)
    if (real !== dir) dirs.push(real)
  } catch {
    // Not there to resolve: as typed only.
  }
  return dirs
}

/** Append one record to the run folder's force-quit.log: 0600, `me`'s regular file (its creator's), never through a link. Why not, or undefined. */
function logRecord(dir: string | undefined, me: number | undefined, text: string): string | undefined {
  if (dir === undefined) return 'no log folder was made for this run'
  const path = join(dir, FORCE_QUIT_LOG)
  let fd: number
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600)
  } catch (e) {
    return `${path} could not be opened (${errnoOf(e)})`
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || (me !== undefined && st.uid !== me) || st.nlink !== 1) return `${path} is not this account's regular file`
    fchmodSync(fd, 0o600)
    writeSync(fd, text)
    return undefined
  } catch (e) {
    return `${path} could not be written (${errnoOf(e)})`
  } finally {
    closeSync(fd)
  }
}

/** Offer the force-quit of what L1's stop waits on, and carry it out at the typed word. See the contract above. */
export function offerForceQuit(o: ForceQuitOptions): Promise<ForceQuitOutcome> {
  return offerForceQuitWith(o, sigkill)
}

/** offerForceQuit with the kill handed in: for its tests, which see whom it would signal; the installer calls offerForceQuit. */
export async function offerForceQuitWith(o: ForceQuitOptions, kill: (pid: number) => Kill): Promise<ForceQuitOutcome> {
  const now = o.now ?? Date.now
  const guard: Guard = {
    uid: o.uid ?? process.getuid?.(),
    installerPid: o.installerPid ?? process.pid,
    stopPid: o.stopPid,
    dirs: dirsOf(o.dir),
    darwin: o.darwin ?? process.platform === 'darwin',
  }
  const withdrawn = (): boolean => o.cancelled?.aborted === true || !o.running()
  const target = o.target()
  if (target === undefined) {
    o.print(NO_TARGET)
    return { kind: 'no-target' }
  }
  const named = `${shownLine(target.label)} (PID ${String(target.pid)})`
  const notSignalled = (why: string): ForceQuitOutcome => {
    o.print(`pmmcp's stop is waiting on ${named}, but ${why}: nothing is force-quit, and the stop goes on`)
    return { kind: 'refused', why }
  }
  const keptWaiting = (why: string): ForceQuitOutcome => {
    o.print(`${why}: nothing was signalled${o.running() ? `, and the stop goes on waiting on ${named}` : ''}`)
    return { kind: 'kept-waiting' }
  }
  const withdrawal = (): string => (o.running() ? 'the force-quit was withdrawn (Ctrl-C again)' : 'the stop has finished meanwhile')

  const first = await snapshot(o, target.pid, guard)
  if (first === 'gone') return notSignalled('it has exited')
  if ('why' in first) return notSignalled(`whether it may be signalled cannot be checked (${first.why})`)
  const refused = targetRefusal(target, first, guard)
  if (refused !== undefined) return notSignalled(refused)
  if (withdrawn()) return keptWaiting(withdrawal())

  const asked = forceQuitQuestion(target, first.target.args, Math.max(0, Math.floor((now() - target.seenAt) / 1000)))
  const answer = await o.ask(asked)
  if (withdrawn()) return keptWaiting(withdrawal())
  if (answer.kind !== 'line') return keptWaiting(answer.kind === 'eof' ? 'the input ended at the question' : 'Ctrl-C at the question')
  if (answer.text.trim() !== FORCE_QUIT_WORD) return keptWaiting(`that is not \`${FORCE_QUIT_WORD}\``)

  // Once more, just before the kill: the same drain, and the same process.
  const still = o.target()
  if (still === undefined || still.pid !== target.pid || still.label !== target.label) return keptWaiting(`the stop is no longer waiting on ${named}`)
  const again = await snapshot(o, target.pid, guard)
  if (again === 'gone') return keptWaiting(`${named} has exited meanwhile`)
  if ('why' in again) return notSignalled(`whether it may be signalled cannot be checked again (${again.why})`)
  const changed = targetRefusal(target, again, guard, first)
  if (changed !== undefined) return notSignalled(changed)
  if (withdrawn()) return keptWaiting(withdrawal())

  const sent = kill(target.pid)
  if (!sent.sent) return sent.why === 'ESRCH' ? keptWaiting(`${named} has exited meanwhile`) : notSignalled(`SIGKILL could not be sent (${sent.why})`)
  const record: ForceQuitRecord = { label: target.label, pid: target.pid, seconds: Math.max(0, Math.floor((now() - target.seenAt) / 1000)) }
  o.print(`SIGKILL sent to ${named} at your typed ${FORCE_QUIT_WORD}: the stop sees it gone and goes on`)
  const logged = logRecord(
    o.logDir,
    o.euid ?? process.geteuid?.(),
    [`${new Date(now()).toISOString()} ${forceQuitLine(record)}`, `  command line: ${shownLine(again.target.args)}`, `  started (ps lstart): ${shownLine(again.start)}`, ''].join('\n'),
  )
  if (logged !== undefined) o.print(`the force-quit is not recorded in the run's log folder: ${logged}`)
  return { kind: 'killed', record }
}
