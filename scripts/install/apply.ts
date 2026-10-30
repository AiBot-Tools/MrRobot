// The installer's apply step: it carries out what the operator chose at the
// gate (plan §5 S5 to S7) and says how it went (S8).
//
// CONTRACT
//
//   Who calls it: the installer (scripts/install.ts) through the gate
//   (src/install/gate.ts): Applier.apply is the gate's GateIO.apply and
//   Applier.countJobs its jobs check; Applier.report is the end report the
//   installer prints once the gate is done. It is handed the plan the
//   planner made (src/install/plan.ts), discovery's result
//   (scripts/install/discover.ts) and the A3 runner, and every program it
//   starts goes through that runner (scripts/install/run.ts): an allowlisted
//   environment with no DOCKER_*, PMMCP_*, AOS_* or credential name, stdin
//   from /dev/null or one digest, output in 0600 files under
//   .aos/install/<stamp>/. It writes no file itself: <repo>/.env only through
//   the one writer (src/secrets/dotenv-append.ts), pmmcp's files only through
//   pmmcp's own scripts. It holds no credential value: the tokens it mints go
//   straight into the writer, which registers them with SecretMask before it
//   writes them, and what pmmcp is given is the digest the writer returns, on
//   stdin. It never imports the loader (src/secrets/dotenv.ts) and never
//   reads .env itself. It reads pmmcp's logs in-process (server.log,
//   launchd.err.log, the checkout's <child>_stderr.log a refusal names) as
//   regular files only, never through a link, non-blocking, from their end
//   and to a cap, and shows each line scrubbed.
//
//   S5, the non-live phase, in plan order, stopping at the first failure
//   before anything live: the .env append (appendCredentials with the plan's
//   generate map and the staged token's digest asked for; a DotenvWriteError
//   whose `written` is false changed nothing, exit 2; true, exit 1); the
//   aos-kernel digest piped to `rotate_http_auth_token.py aos-kernel --create
//   --digest-stdin` and then to `http_auth check --expect aos-kernel`, which
//   alone decides whether the digest is on file (rotate's 0 must be
//   confirmed by it; its 1 and 2 wrote nothing; its 4 and 130 are re-checked,
//   whatever its stderr says it did); the kept prekey's cleanup.
//
//   S6, the jobs check (countJobs): `stop-pmmcp-server.sh --jobs`, read from
//   stdout's first line alone (readJobs), after an earlier run's stale
//   active.json record is cleared (only the one discovery found stale); a
//   Ctrl-C the installer reports through `interrupt` while it runs answers
//   `interrupt` (the count itself, read-only, runs on in its own session).
//
//   S7, the live window, in plan order. The installer is told when the
//   window opens and closes (`window`), so it traps SIGINT inside it; every
//   step there runs in a session of its own (the stop and start scripts by
//   the runner's rule, the fast-forward, the Qdrant cutover and auth init
//   marked ownSession), with no timeout, and nothing here ever signals one.
//   A read-only probe (lsof, ps, docker, pgrep, git, the facts, a check) is
//   the installer's own child, in its process group, so the terminal's
//   Ctrl-C or hangup reaches it even while the installer traps it: inside
//   the window a probe that ended by SIGINT or SIGHUP (or exit 130 or 129)
//   is run again, up to INTERRUPT_RERUNS times, rather than read as a
//   finding. A question asked
//   from inside the window ("start pmmcp again?", "start the old
//   revision?") is asked with the window closed, so a Ctrl-C there answers
//   it as no; a yes opens it again for the start.
//     Every handed step id (and, for an update, the head and origin/main
//     discovery found) is checked before the window opens: a malformed
//     caller is refused with nothing stopped.
//     L1 the graceful stop, never --force, never re-run, then checked:
//        nothing listens on 8766, 8765 or 8767, pmmcp-qdrant does not run,
//        no PID file under ~/.persistent-memory-mcp/pids names a live
//        process. A stop that exits 0 with any of that still true, exits 1 or
//        130 (whatever the checks say: the stop script removes a PID file
//        even for a daemon it failed to stop, so its exit is the one sign),
//        or cannot be checked, makes no further change: the state is shown,
//        the operator is asked "start pmmcp again to restore service?
//        [Y/n]", and the run ends (exit 4). Once the stop ran, whether the
//        running server loaded the staged token is not known until the
//        start's checks show a new server.
//     L2 the fast-forward (`git merge --ff-only <origin/main as found>`),
//        only while HEAD is still the head discovery found and the tree is
//        still clean with uv.lock and pyproject.toml unchanged; then the
//        facts and `http_auth check`, with the new code, before anything
//        else. The check refuses the file only by its exit 1 with an
//        `invalid:` line on stderr (shown: it names the line of the token to
//        rename). That prefix is the one thing read from a .err file, against
//        the runner's rule that the .err file is shown, never parsed:
//        pmmcp's interface puts the refusal there and nothing on stdout
//        (docs/installer_interfaces.md, `check`'s exit 1); any other
//        end (a timeout, exit 2, a signal, a refused run) is no verdict, and
//        the check is run once more before that is believed. A refusal, no
//        verdict, or facts that cannot be read stop the run before any start
//        (pmmcp left stopped, exit 4), with the reason and the ways on
//        printed, and "start the old revision (<head>) now? [y/N]" asked: a
//        yes runs `git reset --keep <head>` in its own session and goes
//        straight to L5 (L3 and L4 are not reached), the one way back the
//        installer takes, and only when asked.
//     L3 the Qdrant cutover (`enable --dry-run`, then `enable`): its 1, 2 or
//        130 left Qdrant as it was, and the run goes on to the start; its 3
//        (or an end by a signal) stops the run without starting pmmcp, with
//        the script's own instructions shown (exit 4).
//     L4 `auth init` (or `--only dashboard` / `--only curator`), each file
//        only where the facts show pmmcp takes it safely (the facts re-read
//        after L2 when it ran, and the curator on 127.0.0.1:8767 or
//        disabled); the curator secret never while any scripts/monitor_tui.py
//        runs (or whether one runs cannot be told). Then `auth status --json`
//        says what L4 left.
//     L5 the start, then its checks: /health 200; an MCP server on 8766 of
//        this account whose pid is not the one discovery found and that
//        started (ps etime, a lower bound) after http_auth.yaml last changed
//        (an lsof that fails is a check that could not be made, never "no
//        server listens", and leaves whether the digest loaded not known);
//        pmmcp-qdrant running; the worker and scraper PID files naming live
//        processes; after L3, `status --json` verdict `enforced` (any other
//        names the rollback); after L4 left a usable dashboard token,
//        auth_required and a 401 for an unauthenticated /api/fingerprint;
//        after L4 left a usable curator secret with the curator enabled, a
//        401 from :8767/api/curator/status. A probe that gets no answer
//        shows the last "refused to start" lines of server.log, the stderr
//        file each names (only this checkout's own two), and any "pmmcp:
//        refusing to start:" line of launchd.err.log, each log read only
//        from where it ended when the start began (the whole file when it
//        was rotated since): launchd.err.log only grows, and server.log is
//        rotated only by an MCP server that starts, so an older run's lines
//        are never shown as this start's. Any check failed: exit 4, with the
//        rollback commands of what this window did.
//     L6 whether "first request with token" for aos-kernel is in server.log
//        since the start (read from the same mark: the whole file when the
//        new server rotated it at its start, as pmmcp's setup_logging does,
//        and only what came after the mark when it was not): found, or
//        inconclusive (never a failure). No MCP initialize is sent: that
//        would need the token's value, which no installer module holds (A2),
//        so the line comes from the kernel's own next request: from a
//        restarted npm run dev when the next steps ask that restart
//        (something it reads changed), else from the running daemon, whose
//        hub reconnects to the restarted pmmcp within its 240 s heartbeat.
//        Plan S7 L6 reads so since A6 fix round 3 (plan §9, option (a)), and
//        so does the planner's title for the step.
//   A fresh install runs its whole sequence the same way: the .env append,
//   the clone, setup.sh --non-interactive in its own session (stdin
//   /dev/null), the facts of the new checkout (its features, and each
//   service on its port and a loopback host), the stop, `qdrant_api_key.py
//   init`, the digest staged, both in their own session, the start and its
//   checks, L6.
//
//   After a leak (a registered value reached a child's output: the runner
//   halts and runs nothing more, a probe or the start included), the phase
//   ends at once; the report names the step and the files (never a value)
//   and, once the stop (or a fresh install's setup) had begun and until the
//   start's checks had all passed, that pmmcp may be stopped, the manual
//   start, and the checks not made. Exit 4 in that stretch; 1 before it,
//   and 1 after it (pmmcp is up as its checks showed: what failed is the
//   read that leaked, and the state is as reported).
//
//   The end report (S8) has a line for every plan step: done, failed or
//   skipped as it went, a step a phase was handed but did not reach
//   skipped with why ("not reached: the stop did not stop pmmcp"), and a
//   step no phase was handed skipped. Then .env (what was appended, its
//   mode, and an ACL when ls -le shows one or cannot tell; after a write
//   that failed part way, never "not written": that it may have changed, the
//   names this run was appending, and `ls -l .env` and `git check-ignore -v
//   .env` to run before npm run dev restarts), the bearer, the Qdrant verdict
//   (after the kept prekey's cleanup, no longer "kept"), the dashboard, the
//   backups, a leak, what is left to do by hand, and the next steps: the
//   restart of npm run dev only when something it reads changed (.env gained
//   a line, or the restarted pmmcp loaded an aos-kernel digest the server
//   before it had not: staged this run, or on file but loaded by no server
//   that discovery could show started after http_auth.yaml last changed; a
//   cutover, a dashboard token or an update on a system whose server had
//   the digest loaded asks none), and the
//   steps about pmmcp only for a pmmcp this run touched (not with --aos-only,
//   nor with --no-install and none installed).
//
//   Exit codes (Applied): 0 done; 1 a step failed and the state is as
//   reported (a non-live step; a live item that changed nothing, or a leak
//   in a read, once pmmcp was started and every check of the start passed:
//   plan §9 records this reading, which the operator may still turn to 4,
//   one line in Applier.apply); 2 refused before any change; 4 a live step
//   failed and pmmcp is not in its intended state (stopped, or started
//   without every check passing).

import { randomBytes } from 'node:crypto'
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, realpathSync, statSync } from 'node:fs'
import { basename, dirname, isAbsolute, join } from 'node:path'
import { z } from 'zod'

import type { KernelConfig } from '../../src/config.js'
import { ConfigError, KernelError } from '../../src/errors.js'
import { PmmcpDocumentError, featuresOf, parseFacts, parseQdrantStatus, type Facts, type QdrantStatus } from '../../src/install/facts.js'
import type { Answer, Applied, JobsAnswer, Phase } from '../../src/install/gate.js'
import { PMMCP_CLIENT, generatorsFor, shellWord, type AuthFile, type Plan, type Step, type StepId } from '../../src/install/plan.js'
import type { ProvidersFile } from '../../src/models/registry.js'
import {
  DotenvWriteError,
  appendCredentials,
  credentialNames,
  inspectCredentials,
  mintedCredentialNames,
  type AppendResult,
  type InspectOptions,
} from '../../src/secrets/dotenv-append.js'
import { CURATOR_ADDRESS, LOOPBACK_HOSTS, PMMCP_FOLDER, PMMCP_PORTS, loopbackGet, parseEtime, startedAfter, type Absent, type Found, type HttpGet } from './discover.js'
import {
  InstallRunError,
  START_SCRIPT,
  STOP_SCRIPT,
  clearActive,
  readActive,
  readAt,
  readJobs,
  readOut,
  shownLine,
  tail,
  type ActiveRecord,
  type RunResult,
  type RunSpec,
  type Runner,
} from './run.js'

/** Where a fresh install is cloned from: what discovery accepts as the origin. */
export const CLONE_URL = 'https://github.com/AiBot-Tools/persistent-memory-mcp.git'

/** How long each kind of probe may take; a step that writes gets no timeout. */
const QUICK_MS = 15_000
const DOCKER_MS = 30_000
const PYTHON_MS = 60_000
const HTTP_MS = 3_000

/** After the start script returns, how many times an endpoint that does not answer yet is asked again, and how long apart. */
export const PROBE_TRIES = 10
export const PROBE_WAIT_MS = 3_000

/**
 * Inside the window, how many times a probe the terminal's Ctrl-C or hangup
 * ended (SIGINT or SIGHUP, or exit 130 or 129) is run again before its end
 * is read as it is: the probe shares the installer's process group, which
 * the terminal signals as a whole, the installer traps both there, and the
 * window goes on. No terminal sends SIGTERM, so a probe it ended is read as
 * it is.
 */
export const INTERRUPT_RERUNS = 3

/** The terminal's signal that ended a probe, in words; undefined for any other end. */
function endedBy(result: Pick<RunResult, 'signal' | 'code'>): string | undefined {
  if (result.signal === 'SIGINT' || result.code === 130) return 'Ctrl-C'
  if (result.signal === 'SIGHUP' || result.code === 129) return 'SIGHUP (the terminal closed)'
  return undefined
}

/** How much of a pmmcp log is read from its end. */
const LOG_TAIL_BYTES = 256 * 1024
/** The most of server.log L6 reads after the start's mark. */
const SERVER_LOG_BYTES = 1024 * 1024
/** The most of a PID file read. */
const PID_FILE_CAP = 64

/** The container the start script runs Qdrant as. */
const QDRANT_CONTAINER = 'pmmcp-qdrant'

/** The step ids each phase carries out: a step of any other id is a caller's defect, refused before anything runs. */
const PHASE_STEPS: Readonly<Record<Phase, ReadonlySet<StepId>>> = {
  'non-live': new Set<StepId>(['env', 'stage-digest', 'qdrant-cleanup']),
  live: new Set<StepId>(['stop', 'update', 'qdrant-enable', 'auth-init', 'start', 'bearer-check']),
  'fresh-install': new Set<StepId>(['env', 'clone', 'setup', 'stop', 'qdrant-init', 'stage-digest', 'start', 'bearer-check']),
}

/** The PID files whose processes the start must leave alive. */
const WORKER_PID_FILES: readonly (readonly [string, string])[] = [
  ['worker.pid', 'the worker'],
  ['scraper_worker.pid', 'the scraper worker'],
]

export type ItemState = 'done' | 'skipped' | 'failed' | 'inconclusive'

/** One line of the end report: an item, and what came of it. */
export interface Item {
  readonly what: string
  readonly state: ItemState
  readonly detail: string
}

export interface ApplyOptions {
  /** The AOS repository root: .env is <repoRoot>/.env, and the runner logs under it. */
  readonly repoRoot: string
  /** The operator's HOME (injected in tests): pmmcp's ~/.persistent-memory-mcp is under it. */
  readonly home: string
  /** The A3 runner every child goes through: the one discovery used. */
  readonly runner: Runner
  readonly config: KernelConfig
  readonly providers: ProvidersFile
  /** The plan the gate walks. */
  readonly plan: Plan
  /** Discovery's result: found for an install, absent for a fresh one; undefined for --aos-only. */
  readonly discovery: Found | Absent | undefined
  /** Show one line (scrubbed here first). */
  readonly print: (line: string) => void
  /** Ask one question (the failed stop's "start pmmcp again?"). */
  readonly ask: (question: string) => Promise<Answer>
  /** The operator's uid: whose a listener on 8766 must be. Default process.getuid(). */
  readonly uid?: number
  /** Passed to the writer as they are (tests stand a temp .env's owner and a non-root euid in). */
  readonly inspect?: Pick<InspectOptions, 'uid' | 'euid'>
  /** The GET every HTTP probe makes (default discovery's loopbackGet). */
  readonly http?: HttpGet
  readonly now?: () => Date
  /** The pause between probes after the start (default a timer). */
  readonly sleep?: (ms: number) => Promise<void>
  /** What makes each generated token (default 32 random bytes as hex): handed to the writer, never kept. */
  readonly mint?: () => string
  /** Told when the stopped window opens (true) and when it closes (false): the installer traps SIGINT inside it. */
  readonly window?: (open: boolean) => void
  /** Aborted when the operator presses Ctrl-C outside the window: ends the jobs count's wait. */
  readonly interrupt?: AbortSignal
}

/** What the applier refuses to do: a defect in its caller, never a finding about pmmcp. */
export class ApplyError extends KernelError {
  constructor(message: string) {
    super('AOS_INSTALL_APPLY', message)
  }
}

/** Ends a phase early with its exit code; the items already say why, and `why` is what every step not reached is skipped for. */
class End {
  readonly exitCode: 1 | 2 | 4
  readonly why: string
  constructor(exitCode: 1 | 2 | 4, why: string) {
    this.exitCode = exitCode
    this.why = why
  }
}

type Ran = { readonly ok: true; readonly result: RunResult } | { readonly ok: false; readonly why: string; readonly result?: RunResult }

type Listening = { readonly state: 'none' } | { readonly state: 'listening'; readonly pids: readonly { readonly pid: number; readonly uid: number | undefined }[] } | { readonly state: 'unknown'; readonly why: string }

type ContainerState = 'running' | 'stopped' | 'absent' | 'unknown'

const FileState = z.enum(['absent', 'present', 'unusable'])

/** `python -m src.dashboard.auth status --json`, as pmmcp ships it (docs/installer_interfaces.md); loose, like every pmmcp document. */
const AuthStatus = z
  .object({
    auth: z.literal(1),
    dashboard_token: z.object({ state: FileState }).loose(),
    curator_secret: z.object({ state: FileState }).loose(),
  })
  .loose()
type AuthStatus = z.output<typeof AuthStatus>

/** An error by its errno or Node code, else its class: never its message. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

/** `cd <dir> && <command>`, for a line the operator pastes. */
const within = (dir: string, command: string): string => `cd ${shellWord(dir)} && ${command}`

const list = (names: readonly string[]): string => (names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names.at(-1) ?? ''}`)

const seconds = (ms: number): string => `${String(Math.round(ms / 1000))} s`

/** The address a probe dials for a configured host. */
const dial = (host: string): string => (host === '::1' ? '::1' : '127.0.0.1')

/** Where a log file ended at some moment: the file (dev, ino) and its size then. */
export interface LogMark {
  readonly dev: number
  readonly ino: number
  readonly size: number
}

/** A log file's mark now; null when it is not there or is not a regular file (then anything in it later was written since). */
export function logMark(path: string): LogMark | null {
  try {
    const st = lstatSync(path)
    return st.isFile() ? { dev: st.dev, ino: st.ino, size: st.size } : null
  } catch {
    return null
  }
}

/**
 * The last lines of a log file of pmmcp's, read in-process: a regular file
 * and never a link (lstat), opened non-blocking without following one, the
 * same file once open, at most `bytes` from its end, and, given a mark, only
 * what was written after it (the whole file, to the cap, when it is another
 * file or shorter than the mark: rotated or truncated since). Raw lines, for
 * the caller to match and then show scrubbed; [] for a file that is not
 * there or is not a regular file.
 */
export function logTail(path: string, bytes: number, since?: LogMark | null): string[] {
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(path)
  } catch {
    return []
  }
  if (st.isSymbolicLink() || !st.isFile()) return []
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch {
    return []
  }
  try {
    const opened = fstatSync(fd)
    if (!opened.isFile() || opened.ino !== st.ino || opened.dev !== st.dev) return []
    const same = since !== undefined && since !== null && since.dev === opened.dev && since.ino === opened.ino && since.size <= opened.size
    const start = same ? since.size : 0
    const from = Math.max(start, opened.size - bytes)
    const lines = readAt(fd, opened.size - from, from).toString('utf8').split('\n')
    // Read from the middle of a line: drop its end, and the empty piece after a final newline.
    if (from > start) lines.shift()
    if (lines.at(-1) === '') lines.pop()
    return lines
  } catch {
    return []
  } finally {
    closeSync(fd)
  }
}

/** A JSON log line's `event` (pmmcp's server.log is structlog's JSON), else the line itself. */
function eventOf(line: string): string {
  try {
    const v: unknown = JSON.parse(line)
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      const event = (v as Record<string, unknown>)['event']
      if (typeof event === 'string') return event
    }
  } catch {
    // Not JSON: the line as it is.
  }
  return line
}

/** One field of a JSON object body, or undefined. */
function jsonField(body: string, key: string): unknown {
  try {
    const v: unknown = JSON.parse(body)
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>)[key] : undefined
  } catch {
    return undefined
  }
}

/** A folder's spellings that pmmcp may print: as given, and with its links resolved. */
function spellings(dir: string): string[] {
  const out = [dir]
  try {
    const real = realpathSync(dir)
    if (real !== dir) out.push(real)
  } catch {
    // Not there: as given only.
  }
  return out
}

/**
 * The pids of every running scripts/monitor_tui.py, of any checkout: an
 * older TUI reads ~/.persistent-memory-mcp/curator_secret, the same file
 * whichever checkout it runs from, and sends it raw to whatever answers on
 * 8767 (plan P9), and pgrep cannot tell a TUI started by a relative path
 * from another checkout's. Undefined when pgrep cannot say. A read-only
 * probe through the runner; pgrep prints pids only, never a command line.
 */
export async function tuiPids(runner: Runner, cwd: string): Promise<readonly number[] | undefined> {
  let result: RunResult
  try {
    result = await runner.run(tuiProbe(cwd))
  } catch (e) {
    if (e instanceof InstallRunError && (e.code === 'AOS_INSTALL_RUN_LEAK' || e.code === 'AOS_INSTALL_RUN_HALTED')) throw e
    return undefined
  }
  return tuiPidsOf(result)
}

/** The read-only pgrep tuiPids runs; it names no stop or start script. */
const tuiProbe = (cwd: string): RunSpec => ({ step: 'pgrep-tui', command: 'pgrep', args: ['-f', 'scripts/monitor_tui\\.py'], cwd, timeoutMs: QUICK_MS })

/** What that pgrep said: its pids, [] for none, undefined when it cannot say. */
function tuiPidsOf(result: RunResult): readonly number[] | undefined {
  if (result.timedOut || !result.exited || result.signal !== null) return undefined
  let out: string
  try {
    out = readOut(result)
  } catch {
    return undefined
  }
  if (result.code === 1 && out.trim() === '') return []
  if (result.code !== 0) return undefined
  const pids = out.split('\n').filter((l) => l.trim() !== '')
  if (!pids.every((p) => /^\s*\d+\s*$/.test(p))) return undefined
  return pids.map((p) => Number(p.trim()))
}

/** Carries out the gate's phases and keeps what the end report says. See the contract above. */
export class Applier {
  readonly #o: ApplyOptions
  readonly #http: HttpGet
  readonly #now: () => Date
  readonly #sleep: (ms: number) => Promise<void>
  readonly #mint: () => string
  readonly #uid: number | undefined
  readonly #items: Item[] = []
  /** The plan steps a phase was handed: the rest are reported skipped. */
  readonly #handed = new Set<Step>()
  /** Whether anything was changed in this run: a later refusal is then exit 1, not 2. */
  #written = false
  /** The handed steps whose turn came: a phase that ends early reports the rest skipped, with why. */
  readonly #reached = new Set<Step>()
  #env: AppendResult | undefined
  /** The writer's failure, when the append failed: `written` true means .env may have been changed all the same (never "not written"). */
  #envFailed: { readonly written: boolean; readonly message: string } | undefined
  /** .env's mode and ACL as the end report shows them, once looked at (whenever the file exists). */
  #dotenvMode: { readonly path: string; readonly mode: number; readonly acl: boolean | undefined } | undefined
  #dotenvChecked = false
  /** Where server.log ended when the start began: L5's refusals and L6 read only what came after. Undefined until the start. */
  #serverLogMark: LogMark | null | undefined
  /** Where launchd.err.log ended when the start began: it only grows, so its older refusals are not this start's. */
  #launchdErrMark: LogMark | null | undefined
  /** The staged token's digest, from the writer: never its value. */
  #digest: string | undefined
  #digestOnFile: boolean | undefined
  #loaded: boolean | undefined
  /**
   * Whether the server discovery found had loaded http_auth.yaml as it was then (it started after the file last changed); undefined
   * when that cannot be told. A digest not on file then can only be loaded now by being staged this run, which #digestStaged says.
   */
  readonly #loadedBefore: boolean | undefined
  /** Set once this run put the digest on file (check --expect matches after the rotate). */
  #digestStaged = false
  readonly #backups: string[] = []
  #facts: Facts | undefined
  /** The facts L2 re-read from the updated tree. */
  #updatedFacts: Facts | undefined
  #updated = false
  #qdrant: QdrantStatus | undefined
  /** L3's enable (or a fresh install's init) made the key: L5 then wants verdict enforced. */
  #keyed = false
  /** What L4 chose and auth status said afterwards. */
  readonly #chosen = new Set<AuthFile>()
  #auth: AuthStatus | undefined
  /** Set once the stop (or a fresh install's setup) began: from then on pmmcp may be stopped. */
  #liveBegun = false
  /** Set once the start ran. */
  #started = false
  /** Set once every check of the start passed: pmmcp is up as checked, and a leak after it no longer leaves it maybe stopped. */
  #upChecked = false
  #windowOpen = false
  #staleCleared = false
  #leak: { readonly step: string | undefined; readonly what: string; readonly live: boolean } | undefined
  /** How to undo each change this run made by hand: printed when a later step fails, and in the report then. */
  readonly #undo: string[] = []
  /** What is left for the operator to do by hand: always in the report. */
  readonly #todo: string[] = []

  constructor(options: ApplyOptions) {
    if (!isAbsolute(options.repoRoot) || !isAbsolute(options.home)) throw new ApplyError('the repository root and HOME must be absolute paths')
    this.#o = options
    this.#http = options.http ?? loopbackGet
    this.#now = options.now ?? ((): Date => new Date())
    this.#sleep = options.sleep ?? ((ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms)))
    this.#mint = options.mint ?? ((): string => randomBytes(32).toString('hex'))
    this.#uid = options.uid ?? process.getuid?.()
    const d = options.discovery
    this.#facts = d?.kind === 'found' ? d.facts : undefined
    this.#qdrant = d?.kind === 'found' ? d.qdrant : undefined
    if (d?.kind === 'found') {
      if (d.bearer.state === 'matches') this.#digestOnFile = true
      const server = d.server
      if (server?.startedAfter !== undefined && d.httpAuthModified !== undefined) this.#loaded = server.startedAfter.getTime() > d.httpAuthModified.getTime()
    }
    // Before anything runs: a restart this run makes changes what the daemon reads only if the digest was not loaded already.
    this.#loadedBefore = this.#loaded
  }

  /** What has been done, skipped, failed or left inconclusive, in order. */
  get items(): readonly Item[] {
    return [...this.#items]
  }

  /** Why nothing more runs, when a registered value reached a child's output. */
  get leak(): { readonly step: string | undefined; readonly what: string; readonly live: boolean } | undefined {
    return this.#leak
  }

  // ── the gate's two calls ──

  /** Carry out one phase's steps in order (GateIO.apply). */
  async apply(phase: Phase, steps: readonly Step[]): Promise<Applied> {
    // A step this phase does not carry out is the caller's defect: refused before anything runs, never halfway through a window.
    const known = PHASE_STEPS[phase]
    const stray = steps.find((s) => !known.has(s.id))
    if (stray !== undefined) throw new ApplyError(`${stray.id} is not a step of the ${phase} phase`)
    for (const step of steps) this.#handed.add(step)
    let exitCode: 0 | 1 | 2 | 4 = 0
    const worst = (code: 1 | 2 | 4): void => {
      if (code > exitCode) exitCode = code
    }
    const mark = this.#items.length
    let notReached = 'the phase ended before it'
    try {
      if (this.#leak !== undefined || this.#o.runner.halted !== undefined) {
        notReached = `nothing more is run: ${this.#leak?.what ?? this.#o.runner.halted ?? ''}`
        worst((this.#leak?.live ?? (this.#liveBegun && !this.#upChecked)) ? 4 : 1)
      } else if (phase === 'non-live') await this.#nonLive(steps)
      else if (phase === 'live') await this.#live(steps)
      else await this.#fresh(steps)
    } catch (e) {
      if (e instanceof End) {
        worst(e.exitCode)
        notReached = e.why
      } else if (e instanceof InstallRunError && (e.code === 'AOS_INSTALL_RUN_LEAK' || e.code === 'AOS_INSTALL_RUN_HALTED')) {
        worst(this.#leaked(e))
        notReached = 'nothing more is run after the defect named above'
      } else throw e
    } finally {
      this.#closeWindow()
    }
    // Every step handed on gets its line: the ones whose turn never came, with why.
    for (const step of steps) {
      if (this.#reached.has(step)) continue
      this.#reached.add(step)
      this.#item(step.short, 'skipped', `not reached: ${notReached}`)
    }
    // An existing .env is looked at once a run, whether or not this run wrote it (S8: its mode and any ACL).
    if (this.#o.runner.halted === undefined) await this.#checkDotenv(this.#o.plan.dotenv.path)
    // A live item that failed without stopping the phase (it changed nothing) still makes this phase's exit 1.
    if (this.#items.slice(mark).some((i) => i.state === 'failed')) worst(1)
    if (exitCode === 0) return { ok: true }
    return { ok: false, exitCode }
  }

  /**
   * The jobs check between the two confirmations (GateIO.countJobs):
   * `stop-pmmcp-server.sh --jobs`, stdout's first line alone. An earlier
   * run's record discovery found stale is cleared first, since the runner
   * refuses the stop script while active.json holds one.
   */
  async countJobs(): Promise<JobsAnswer> {
    const found = this.#found()
    const gate = this.#o.plan.jobsGate
    if (!gate.available) return { state: 'failed', why: gate.why, stderr: [] }
    const cleared = this.#clearStale()
    if (cleared !== undefined) return { state: 'failed', why: cleared, stderr: [] }
    const dir = found.install.dir
    let started: ReturnType<Runner['start']>
    try {
      started = this.#o.runner.start({ step: 'stop-jobs', command: join(dir, STOP_SCRIPT), args: ['--jobs'], cwd: dir })
    } catch (e) {
      if (e instanceof InstallRunError) {
        if (e.code === 'AOS_INSTALL_RUN_HALTED') this.#leaked(e)
        return { state: 'failed', why: e.message, stderr: [] }
      }
      throw e
    }
    this.#activeProblem(started.activeError)
    const signal = this.#o.interrupt
    let onAbort: (() => void) | undefined
    const interrupted = new Promise<'interrupt'>((resolve) => {
      if (signal === undefined) return
      if (signal.aborted) {
        resolve('interrupt')
        return
      }
      onAbort = (): void => resolve('interrupt')
      signal.addEventListener('abort', onAbort, { once: true })
    })
    // The count runs on in its own session after a Ctrl-C; its end, or its leak, is no longer anyone's to await.
    const done = started.done.then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    )
    let first: Awaited<typeof done> | 'interrupt'
    try {
      first = await Promise.race([done, interrupted])
    } finally {
      // The gate counts every 10 s while jobs run: each count's listener goes with it.
      if (onAbort !== undefined) signal?.removeEventListener('abort', onAbort)
    }
    if (first === 'interrupt') return { state: 'interrupt' }
    if ('error' in first) {
      const e = first.error
      if (e instanceof InstallRunError) {
        if (e.code === 'AOS_INSTALL_RUN_LEAK' || e.code === 'AOS_INSTALL_RUN_HALTED') this.#leaked(e)
        return { state: 'failed', why: e.message, stderr: [] }
      }
      throw e
    }
    const { result } = first
    this.#activeProblem(result.activeError)
    const stderr = this.#tailOf(result.err, 5)
    let jobs: ReturnType<typeof readJobs>
    try {
      jobs = readJobs(result)
    } catch (e) {
      if (e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_OUTPUT') return { state: 'failed', why: e.message, stderr }
      throw e
    }
    if (jobs === undefined) return { state: 'failed', why: `${STOP_SCRIPT} --jobs gave no count (exit ${String(result.code)})`, stderr }
    if (jobs.running === 'unknown') return { state: 'unknown', stderr }
    return { state: 'counted', running: jobs.running, display: jobs.display }
  }

  // ── S5 ──

  async #nonLive(steps: readonly Step[]): Promise<void> {
    for (const step of steps) {
      this.#reached.add(step)
      if (step.id === 'env') await this.#append(step)
      else if (step.id === 'stage-digest') {
        if (!(await this.#stage(step, false))) throw new End(1, `the ${PMMCP_CLIENT} digest is not on file`)
      } else if (step.id === 'qdrant-cleanup') await this.#cleanup(step)
      else throw new ApplyError(`${step.id} is not a non-live step`)
    }
    if (steps.some((s) => s.id !== 'env')) await this.#refreshFacts()
  }

  /** The .env append, through the one writer; then the file's mode, and whether ls shows an ACL on it. */
  async #append(step: Step): Promise<void> {
    const { config, providers, plan, repoRoot } = this.#o
    const staged = plan.staged
    let result: AppendResult
    try {
      result = appendCredentials({
        repoRoot,
        accepted: credentialNames(config, providers),
        generate: generatorsFor(plan, this.#mint),
        generatable: mintedCredentialNames(config),
        providers,
        digests: staged === undefined ? [] : [staged.name],
        ...this.#ids(),
      })
    } catch (e) {
      if (e instanceof DotenvWriteError) {
        this.#envFailed = { written: e.written, message: e.message }
        this.#item(step.short, 'failed', e.message)
        this.#print(`failed: ${e.message}`)
        if (e.written) {
          // The writer stopped after it began writing: the file may hold the new names, or be left empty, and may no longer be one the loader reads.
          this.#written = true
          this.#print(`  ${this.#dotenvCheck()}`)
        }
        throw new End(e.written || this.#written ? 1 : 2, '.env was not written as planned')
      }
      throw e
    }
    this.#env = result
    if (result.created || result.appended.length > 0) this.#written = true
    const digest = staged === undefined ? undefined : result.digests.find((d) => d.name === staged.name)?.digest
    if (digest !== undefined) this.#digest = digest
    const appended = result.appended.map((n) => `${n.name} (line ${String(n.line)})`)
    const detail =
      appended.length === 0
        ? `nothing appended to ${result.path}: ${list(result.present.map((n) => `${n.name} (line ${String(n.line)})`))} already set`
        : `${result.created ? `created ${result.path} at 0600 with` : `appended to ${result.path}:`} ${list(appended)}`
    this.#item(step.short, 'done', detail)
    this.#print(`.env: ${detail}`)
    for (const b of result.blank) this.#print(`  ${b.name} is on line ${String(b.line)} with no value: fill it in or delete the line`)
    // Looked at again here: this run may have created it.
    this.#dotenvChecked = false
    await this.#checkDotenv(result.path)
  }

  /**
   * What to check once the writer failed after it began writing: the names
   * this run was appending (never a value), and the two commands that show
   * whether the loader will still read the file.
   */
  #dotenvCheck(): string {
    const names = this.#o.plan.generate
    return (
      `.env may now hold ${names.length === 0 ? 'what this run was appending' : list([...names])} (the names this run was appending), or be left empty if this run created it: ` +
      `check it in ${this.#o.repoRoot} with ls -l .env (-rw------- and yours) and git check-ignore -v .env (it must name the .gitignore line that ignores .env), ` +
      'and fix what they show before you restart npm run dev'
    )
  }

  /** .env's mode, and whether ls shows an ACL on it, for the end report: once, whenever the file exists, written by this run or not. */
  async #checkDotenv(path: string): Promise<void> {
    if (this.#dotenvChecked) return
    let mode: number
    try {
      mode = statSync(path).mode & 0o7777
    } catch {
      // Not there (yet): nothing to show.
      return
    }
    this.#dotenvChecked = true
    this.#dotenvMode = { path, mode, acl: await this.#aclOf(path) }
  }

  /**
   * Whether .env carries an ACL, from `ls -lde` (macOS: -e lists the ACL's
   * entries, numbered, under the line): true when it lists one or the mode
   * shows `+`, false for a plain mode and no entry, undefined when it cannot
   * be told (ls failed, or the mode shows `@`, which macOS prints in place of
   * `+` when the file has extended attributes as well).
   */
  async #aclOf(path: string): Promise<boolean | undefined> {
    const ran = await this.#exec({ step: 'ls-dotenv', command: 'ls', args: ['-lde', path], cwd: this.#o.repoRoot, timeoutMs: QUICK_MS })
    if (!ran.ok || ran.result.code !== 0) return undefined
    const lines = (this.#out(ran.result) ?? '').split('\n')
    const mode = (lines[0] ?? '').split(/\s/)[0] ?? ''
    if (lines.slice(1).some((l) => /^\s*\d+:\s/.test(l))) return true
    if (/^[-a-z][-rwxsStT]{9}\+$/.test(mode)) return true
    if (/^[-a-z][-rwxsStT]{9}\.?$/.test(mode)) return false
    return undefined
  }

  /**
   * The aos-kernel digest: piped to the rotate script, then to check
   * --expect, which alone decides whether it is on file. True when it is.
   * Inside a fresh install's window the rotate runs in its own session.
   */
  async #stage(step: Step, inWindow: boolean): Promise<boolean> {
    const staged = this.#o.plan.staged
    const dir = this.#dir()
    if (staged === undefined) throw new ApplyError('a stage-digest step with no staged token in the plan')
    let digest = this.#digest
    if (digest === undefined) {
      try {
        const inspected = inspectCredentials({
          repoRoot: this.#o.repoRoot,
          accepted: credentialNames(this.#o.config, this.#o.providers),
          names: [],
          digests: [staged.name],
          ...this.#ids(),
        })
        digest = inspected.digests.find((d) => d.name === staged.name)?.digest
      } catch (e) {
        if (e instanceof ConfigError) {
          this.#item(step.short, 'failed', e.message)
          this.#print(`failed: ${e.message}`)
          if (!this.#written && !inWindow) throw new End(2, '.env could not be read for the digest')
          return false
        }
        throw e
      }
    }
    if (digest === undefined) {
      this.#item(step.short, 'failed', `${staged.name} holds no value in .env, so there is no digest to stage`)
      return false
    }
    this.#digest = digest
    const before = this.#backupNames()
    const rotate = await this.#exec(
      {
        step: 'rotate',
        command: this.#python(dir),
        args: ['scripts/rotate_http_auth_token.py', staged.client, '--create', '--digest-stdin'],
        cwd: dir,
        digest,
        ...(inWindow ? { ownSession: true } : {}),
      },
      'rotate_http_auth_token.py --digest-stdin',
    )
    for (const name of this.#backupNames()) if (!before.has(name)) this.#backups.push(name)
    if (!rotate.ok && rotate.result === undefined) {
      this.#item(step.short, 'failed', `${rotate.why}; nothing was written in http_auth.yaml`)
      return false
    }
    const code = rotate.result?.code ?? null
    if (code === 1 || code === 2) {
      this.#item(
        step.short,
        'failed',
        `the rotate script exited ${String(code)}: nothing was written in http_auth.yaml${code === 1 ? ' (its message, above, names any folder it made and could not remove)' : ''}`,
      )
      return false
    }
    // 0 must be confirmed; 4 (written, then stopped), 130 (committed or put back, by its stderr) and anything else are decided here alone.
    const check = await this.#expect(dir, digest)
    const on = check === 'matches'
    this.#digestOnFile = on
    if (on) {
      this.#written = true
      this.#digestStaged = true
      this.#loaded = false
      this.#item(
        step.short,
        'done',
        code === 0
          ? `${PMMCP_CLIENT}: matches (check --expect)`
          : `the rotate script ${rotate.ok ? `exited ${String(code)}` : rotate.why}, and check --expect says ${PMMCP_CLIENT}: matches, so the digest is on file`,
      )
      return true
    }
    this.#item(
      step.short,
      'failed',
      `the rotate script ${rotate.ok ? `exited ${String(code)}` : rotate.why}, and check --expect ${typeof check === 'string' ? `says ${PMMCP_CLIENT}: ${check}` : `gave no verdict (${check.why})`}: the digest is not on file`,
    )
    return false
  }

  /** `http_auth check --expect aos-kernel` with the digest on stdin: the verdict, or why there is none. */
  async #expect(dir: string, digest: string): Promise<'matches' | 'differs' | 'absent' | { readonly why: string }> {
    const ran = await this.#exec(
      { step: 'http-auth-expect', command: this.#python(dir), args: ['-B', '-m', 'src.transport.http_auth', 'check', '--expect', PMMCP_CLIENT], cwd: dir, digest, timeoutMs: PYTHON_MS },
      'http_auth check --expect',
    )
    if (!ran.ok) return { why: ran.why }
    const line = ((this.#out(ran.result) ?? '').split('\n')[0] ?? '').trim()
    const said = new RegExp(`^${PMMCP_CLIENT}: (matches|differs|absent)$`).exec(line)?.[1]
    if (said === 'matches' && ran.result.code === 0) return 'matches'
    if ((said === 'differs' || said === 'absent') && ran.result.code === 3) return said
    return { why: `exit ${String(ran.result.code)} without a verdict` }
  }

  /** The http_auth.yaml backups beside the file the rotate script writes (the one its links lead to). */
  #backupNames(): Set<string> {
    const auth = join(this.#pmmcpHome(), 'http_auth.yaml')
    let target = auth
    try {
      target = realpathSync(auth)
    } catch {
      // No file yet: its backups would sit beside it.
    }
    const out = new Set<string>()
    try {
      for (const name of readdirSync(dirname(target))) if (name.startsWith(`${basename(target)}.bak-`)) out.add(join(dirname(target), name))
    } catch {
      // No folder: no backups.
    }
    return out
  }

  async #cleanup(step: Step): Promise<void> {
    const dir = this.#dir()
    const ran = await this.#exec({ step: 'qdrant-cleanup', command: this.#python(dir), args: ['scripts/qdrant_api_key.py', 'cleanup'], cwd: dir }, 'qdrant_api_key.py cleanup')
    if (ran.ok && ran.result.code === 0) {
      this.#written = true
      // Discovery's status said the prekey was kept: its exit 0 says it is gone, so the report no longer says "kept" beside "removed".
      if (this.#qdrant !== undefined) this.#qdrant = { ...this.#qdrant, prekey_kept: false }
      this.#item(step.short, 'done', 'pmmcp-qdrant-prekey removed (its volumes stay)')
      return
    }
    this.#item(step.short, 'failed', ran.ok ? `qdrant_api_key.py cleanup exited ${String(ran.result.code)}: see its message above` : ran.why)
    throw new End(1, 'the kept prekey was not removed')
  }

  // ── S7 ──

  async #live(steps: readonly Step[]): Promise<void> {
    const found = this.#found()
    const dir = found.install.dir
    const stop = steps.find((s) => s.id === 'stop')
    const start = steps.find((s) => s.id === 'start')
    if (stop === undefined || start === undefined) throw new ApplyError('a live window needs its stop and its start')
    // Checked before anything stops: an update with nothing to fast-forward from or to is the caller's defect, not a window left open.
    if (steps.some((s) => s.id === 'update') && (found.git.head === undefined || found.git.originMain === undefined)) {
      throw new ApplyError('an update step for a checkout with no head or origin/main')
    }
    this.#reached.add(stop)
    const cleared = this.#clearStale()
    if (cleared !== undefined) {
      this.#item(stop.short, 'failed', cleared)
      throw new End(1, "an earlier run's active.json record could not be cleared, so nothing was stopped")
    }
    this.#openWindow()
    await this.#stopStep(stop, dir)
    /** Set when L2 put the old revision back: L3 and L4 are then not reached. */
    let passed: string | undefined
    for (const step of steps) {
      if (step.id === 'stop' || step.id === 'start' || step.id === 'bearer-check') continue
      if (step.id !== 'update' && step.id !== 'qdrant-enable' && step.id !== 'auth-init') throw new ApplyError(`${step.id} is not a step of the live window`)
      this.#reached.add(step)
      if (passed !== undefined) this.#item(step.short, 'skipped', `not reached: ${passed}`)
      else if (step.id === 'update') passed = await this.#update(step, found)
      else if (step.id === 'qdrant-enable') await this.#qdrantEnable(step, dir)
      else await this.#authInit(step, found)
    }
    this.#reached.add(start)
    await this.#startStep(start, dir, found.server?.pid)
    this.#closeWindow()
    const bearer = steps.find((s) => s.id === 'bearer-check')
    if (bearer !== undefined) {
      this.#reached.add(bearer)
      this.#bearerCheck(bearer)
    }
    await this.#refreshFacts()
  }

  /** L1: the graceful stop, and the check that it stopped. A stop that did not stop ends the run, offering the start. */
  async #stopStep(step: Step, dir: string): Promise<void> {
    this.#liveBegun = true
    const ran = await this.#exec({ step: 'stop', command: join(dir, STOP_SCRIPT), args: [], cwd: dir }, `L1 ${STOP_SCRIPT}`)
    if (!ran.ok && ran.result === undefined) {
      this.#item(step.short, 'failed', `${ran.why}: nothing was stopped`)
      throw new End(1, 'the stop did not run, so nothing was stopped')
    }
    const code = ran.result?.code ?? null
    if (code === 2) {
      this.#item(step.short, 'failed', `${STOP_SCRIPT} refused its arguments (exit 2): nothing was stopped`)
      throw new End(1, 'the stop refused its arguments, so nothing was stopped')
    }
    // The stop ran: the server discovery found may be gone, so what it loaded says nothing of what runs from here; only a new server the start's checks find sets it again.
    this.#loaded = undefined
    const state = await this.#stoppedState(dir)
    if (ran.ok && code === 0 && state.ok) {
      this.#item(step.short, 'done', `exit 0; ${state.lines.join('; ')}`)
      return
    }
    const how = !ran.ok ? ran.why : code === 0 ? 'it exited 0, but pmmcp is not stopped' : code === 130 ? 'it was interrupted (exit 130)' : `a service FAILED TO STOP (exit ${String(code)})`
    this.#item(step.short, 'failed', `${how}; ${state.lines.join('; ')}`)
    this.#print(`the stop did not stop pmmcp (${how}), so nothing more is changed:`)
    for (const line of state.lines) this.#print(`  ${line}`)
    await this.#offerStart(dir)
    throw new End(4, 'the stop did not stop pmmcp')
  }

  /** What is left running after a stop: listeners, the Qdrant container, live PID files. */
  async #stoppedState(dir: string): Promise<{ readonly ok: boolean; readonly lines: readonly string[] }> {
    const lines: string[] = []
    let ok = true
    const ports = this.#ports(this.#factsNow())
    for (const port of [ports.server, ports.dashboard, ports.curator]) {
      const l = await this.#listening(port)
      if (l.state === 'none') continue
      ok = false
      lines.push(l.state === 'unknown' ? `what listens on ${String(port)} cannot be checked (${l.why})` : `${String(port)} is still listened on (pid ${l.pids.map((p) => String(p.pid)).join(', ')})`)
    }
    const qdrant = await this.#containerState()
    if (qdrant === 'running' || qdrant === 'unknown') {
      ok = false
      lines.push(qdrant === 'running' ? `${QDRANT_CONTAINER} is still running` : `whether ${QDRANT_CONTAINER} runs cannot be checked`)
    }
    const pids = await this.#livePidFiles()
    for (const p of pids.alive) {
      ok = false
      lines.push(`${p.file} names pid ${String(p.pid)}, which still runs`)
    }
    for (const u of pids.unknown) {
      ok = false
      lines.push(u)
    }
    if (ok) lines.push(`nothing listens on ${list([ports.server, ports.dashboard, ports.curator].map(String))}, ${QDRANT_CONTAINER} does not run, and no PID file names a live process`)
    return { ok, lines }
  }

  /**
   * After a stop that did not stop: "start pmmcp again to restore service?
   * [Y/n]", asked with the window closed (nothing of it runs meanwhile), so
   * a Ctrl-C there is a no as EOF is; a yes opens it again for the start.
   */
  async #offerStart(dir: string): Promise<void> {
    const manual = within(dir, './start-pmmcp-server.sh')
    this.#closeWindow()
    const answer = await this.#o.ask(shownLine('start pmmcp again to restore service? [Y/n]'))
    const yes = answer.kind === 'line' && !/^(?:n|no)$/i.test(answer.text.trim())
    if (!yes) {
      this.#item('start pmmcp again', 'skipped', `not asked to: start it with ${manual}`)
      this.#print(`pmmcp is left as the stop left it: start it with ${manual}`)
      this.#todo.push(`start pmmcp: ${manual}`)
      return
    }
    this.#openWindow()
    const ran = await this.#exec({ step: 'start-again', command: join(dir, START_SCRIPT), args: [], cwd: dir }, START_SCRIPT)
    this.#started = true
    const health = await this.#health(this.#factsNow())
    if (ran.ok && ran.result.code === 0 && health === 200) {
      this.#item('start pmmcp again', 'done', '/health answers 200; none of the chosen changes was made')
      return
    }
    this.#item('start pmmcp again', 'failed', `${ran.ok ? `exit ${String(ran.result.code)}` : ran.why}; /health ${health === 0 ? 'gave no answer' : `answered ${String(health)}`}`)
    this.#todo.push(`start pmmcp: ${manual}`)
  }

  /**
   * L2: the fast-forward, re-checked first, then the facts and http_auth
   * check with the new code. Undefined to go on; once the old revision was
   * put back on the operator's word, why the rest of the chosen changes is
   * not reached (the start comes next).
   */
  async #update(step: Step, found: Found): Promise<string | undefined> {
    const dir = found.install.dir
    const { head, originMain } = found.git
    if (head === undefined || originMain === undefined) throw new ApplyError('an update step for a checkout with no head or origin/main')
    const now = await this.#gitHead(dir)
    if (now !== head) {
      this.#item(step.short, 'failed', `HEAD is ${now === undefined ? 'not readable' : now.slice(0, 7)}, not ${head.slice(0, 7)} as discovery found it: not updated`)
      return undefined
    }
    const st = await this.#exec({ step: 'git-status', command: 'git', args: ['--no-optional-locks', 'status', '--porcelain'], cwd: dir, timeoutMs: QUICK_MS })
    const clean = st.ok && st.result.code === 0 && (this.#out(st.result) ?? 'x').trim() === ''
    const lock = await this.#exec({ step: 'git-lock-diff', command: 'git', args: ['--no-optional-locks', 'diff', '--quiet', 'HEAD', originMain, '--', 'uv.lock', 'pyproject.toml'], cwd: dir, timeoutMs: QUICK_MS })
    const lockSame = lock.ok && lock.result.code === 0
    if (!clean || !lockSame) {
      this.#item(step.short, 'failed', `${!clean ? 'the working tree is no longer clean' : 'uv.lock or pyproject.toml differ at origin/main'}: not updated (update it by hand with pmmcp stopped)`)
      return undefined
    }
    const merge = await this.#exec({ step: 'git-merge', command: 'git', args: ['merge', '--ff-only', originMain], cwd: dir, ownSession: true }, 'L2 git merge --ff-only')
    const after = await this.#gitHead(dir)
    const back = `git -C ${shellWord(dir)} reset --keep ${head}`
    if (after === head) {
      this.#item(step.short, 'failed', `git merge --ff-only ${merge.ok ? `exited ${String(merge.result.code)}` : merge.why}; HEAD is still ${head.slice(0, 7)}: not updated`)
      return undefined
    }
    if (after !== originMain) {
      this.#item(step.short, 'failed', `after git merge --ff-only HEAD is ${after === undefined ? 'not readable' : after.slice(0, 7)}, neither ${head.slice(0, 7)} nor ${originMain.slice(0, 7)}: pmmcp is not started`)
      this.#stopBeforeStart([`put the checkout back (with pmmcp stopped): ${back}`], 'the fast-forward left HEAD neither where it was nor at origin/main')
    }
    this.#updated = true
    this.#written = true
    this.#item(step.short, 'done', `HEAD is ${originMain.slice(0, 7)}`)
    const undo = `to run the old code again: stop pmmcp, ${back}, then start it`
    this.#undo.push(undo)

    // With the new code, before anything else: the facts, then http_auth check (its token-name rule is newer than the gate).
    const asIs = within(dir, './start-pmmcp-server.sh')
    const again = within(dir, `${back} && ./start-pmmcp-server.sh`)
    const facts = await this.#readFacts(dir, 'facts-updated')
    if ('why' in facts) {
      this.#item("the updated pmmcp's facts", 'failed', facts.why)
      this.#print(`the updated pmmcp's facts cannot be had (${facts.why}), so what it takes safely is not known, and it is not started on it:`)
      return this.#oldRevision(found, undo, [`start the old revision: ${again}`], "the updated pmmcp's facts cannot be read")
    }
    this.#updatedFacts = facts.facts
    this.#facts = facts.facts
    const check = await this.#checkUpdated(dir)
    if (check.state === 'loads') {
      this.#item('http_auth check with the updated code', 'done', 'http_auth.yaml loads')
      return undefined
    }
    if (check.state === 'refused') {
      this.#item('http_auth check with the updated code', 'failed', `exit 1: ${check.lines.join(' ')}`)
      this.#print('the updated pmmcp refuses ~/.persistent-memory-mcp/http_auth.yaml, so its MCP server would not start on it:')
      for (const line of check.lines) this.#print(`  ${line}`)
      return this.#oldRevision(
        found,
        undo,
        [
          `rename the token on the line it names (a name the updated server refuses, given by its line, never quoted) in ~/.persistent-memory-mcp/http_auth.yaml, then start it as it is: ${asIs}`,
          `or start the old revision: ${again}`,
        ],
        'the updated pmmcp refuses http_auth.yaml',
      )
    }
    this.#item('http_auth check with the updated code', 'failed', `no verdict, twice: ${check.why}`)
    this.#print(`http_auth check with the updated code gave no verdict, twice (${check.why}), so whether the updated pmmcp takes ~/.persistent-memory-mcp/http_auth.yaml is not known:`)
    return this.#oldRevision(
      found,
      undo,
      [
        `check it by hand (${within(dir, '.venv/bin/python -m src.transport.http_auth check')}); once it exits 0, start it as it is: ${asIs}`,
        `or start the old revision: ${again}`,
      ],
      'whether the updated pmmcp takes http_auth.yaml is not known',
    )
  }

  /**
   * `http_auth check` with the updated code: it loads the file (exit 0), it
   * refuses it (exit 1 with an `invalid:` line on stderr, which names the
   * fault: the lines are returned to show), or there is no verdict (a
   * timeout, another exit, a signal, a run refused), which is asked once
   * more before it is believed.
   */
  async #checkUpdated(dir: string): Promise<{ readonly state: 'loads' } | { readonly state: 'refused'; readonly lines: readonly string[] } | { readonly state: 'none'; readonly why: string }> {
    const whys: string[] = []
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const check = await this.#exec(
        { step: 'http-auth-check-updated', command: this.#python(dir), args: ['-B', '-m', 'src.transport.http_auth', 'check'], cwd: dir, timeoutMs: PYTHON_MS },
        'http_auth check (the updated code)',
      )
      if (check.ok && check.result.code === 0) return { state: 'loads' }
      const err = check.result === undefined ? [] : this.#tailOf(check.result.err, 5)
      if (check.ok && check.result.code === 1 && err.some((l) => l.startsWith('invalid:'))) return { state: 'refused', lines: err }
      whys.push(check.ok ? `exit ${String(check.result.code)}${err.length > 0 ? ` (${err.join(' ')})` : ''}` : check.why)
      if (attempt === 1) this.#print('http_auth check gave no verdict: asking it once more')
    }
    return { state: 'none', why: whys.join('; then ') }
  }

  /**
   * The updated code is not started on as it is: "start the old revision
   * (<head>) now? [y/N]", asked with the window closed. A yes puts the head
   * discovery found back (`git reset --keep`, in its own session) and
   * returns why the rest of the chosen changes is not reached: the start
   * comes next, on the old code. Anything else, or a reset that does not
   * bring that head back, ends the run before the start with the ways on
   * printed (exit 4).
   */
  async #oldRevision(found: Found, undo: string, ways: readonly string[], why: string): Promise<string> {
    const dir = found.install.dir
    const head = found.git.head
    if (head === undefined) throw new ApplyError('an update step for a checkout with no head')
    this.#closeWindow()
    const answer = await this.#o.ask(shownLine(`start the old revision (${head.slice(0, 7)}) now? [y/N]`))
    const yes = answer.kind === 'line' && /^(?:y|yes)$/i.test(answer.text.trim())
    if (!yes) this.#stopBeforeStart(ways, why)
    this.#openWindow()
    const reset = await this.#exec({ step: 'git-reset-keep', command: 'git', args: ['reset', '--keep', head], cwd: dir, ownSession: true }, `git reset --keep ${head.slice(0, 7)}`)
    const now = await this.#gitHead(dir)
    if (now !== head) {
      this.#item('the old revision put back', 'failed', `git reset --keep ${reset.ok ? `exited ${String(reset.result.code)}` : reset.why}; HEAD is ${now === undefined ? 'not readable' : now.slice(0, 7)}`)
      this.#stopBeforeStart(ways, `${why}, and the old revision could not be put back`)
    }
    this.#updated = false
    this.#updatedFacts = undefined
    this.#facts = found.facts
    const at = this.#undo.indexOf(undo)
    if (at >= 0) this.#undo.splice(at, 1)
    this.#item('the old revision put back', 'done', `HEAD is ${head.slice(0, 7)} again (git reset --keep), as discovery found it`)
    return `${why}, so the old revision was put back and started instead`
  }

  async #gitHead(dir: string): Promise<string | undefined> {
    const ran = await this.#exec({ step: 'git-head', command: 'git', args: ['--no-optional-locks', 'rev-parse', '--verify', '-q', 'HEAD'], cwd: dir, timeoutMs: QUICK_MS })
    const out = ran.ok && ran.result.code === 0 ? (this.#out(ran.result) ?? '').trim() : ''
    return /^[0-9a-f]{40,64}$/.test(out) ? out : undefined
  }

  /** End the window before the start: pmmcp stays stopped, and the ways on are printed (never taken). */
  #stopBeforeStart(ways: readonly string[], why: string): never {
    this.#print(`pmmcp is stopped and was not started. ${ways.length > 1 ? 'Either' : 'To go on'}:`)
    for (const way of ways) {
      this.#print(`  ${way}`)
      this.#todo.push(way)
    }
    throw new End(4, `${why}, so pmmcp was not started`)
  }

  /** L3: the Qdrant cutover. Its 3 (or an end by a signal) stops the run before the start. */
  async #qdrantEnable(step: Step, dir: string): Promise<void> {
    const script = 'scripts/qdrant_api_key.py'
    const dry = await this.#exec({ step: 'qdrant-enable-dry-run', command: this.#python(dir), args: [script, 'enable', '--dry-run'], cwd: dir, ownSession: true }, 'L3 qdrant_api_key.py enable --dry-run')
    if (!dry.ok || dry.result.code !== 0) {
      this.#item(step.short, 'failed', `enable --dry-run ${dry.ok ? `exited ${String(dry.result.code)}` : dry.why}: not enabled, Qdrant is as it was`)
      return
    }
    const ran = await this.#exec({ step: 'qdrant-enable', command: this.#python(dir), args: [script, 'enable'], cwd: dir, ownSession: true }, 'L3 qdrant_api_key.py enable')
    if (ran.ok && ran.result.code === 0) {
      this.#keyed = true
      this.#written = true
      // Discovery's verdict was the keyless container's: only a status --json read after the start says what holds now.
      this.#qdrant = undefined
      this.#item(step.short, 'done', 'a new pmmcp-qdrant with the key; the old one kept, stopped, as pmmcp-qdrant-prekey')
      this.#undo.push(`to undo the Qdrant cutover: ${this.#qdrantRollback(dir)}`)
      return
    }
    const code = ran.result?.code ?? null
    if (code === 3 || (ran.result !== undefined && !ran.ok)) {
      // Failed and could not put everything back: its own words say what to do.
      this.#item(step.short, 'failed', `qdrant_api_key.py enable ${code === 3 ? 'exited 3: it failed and could not put everything back' : ran.ok ? '' : ran.why}`)
      this.#print("the Qdrant cutover failed and could not put everything back; pmmcp is not started. The script's instructions:")
      const out = ran.result === undefined ? [] : [...this.#tailOf(ran.result.out, 30), ...this.#tailOf(ran.result.err, 30)]
      for (const line of out) this.#print(`  ${line}`)
      this.#todo.push(`follow qdrant_api_key.py's instructions above, then ${within(dir, './start-pmmcp-server.sh')}`)
      throw new End(4, 'the Qdrant cutover failed and could not put everything back, so pmmcp was not started')
    }
    this.#item(
      step.short,
      'failed',
      `qdrant_api_key.py enable ${ran.ok ? `exited ${String(code)}` : ran.why}: ${code === 130 ? 'interrupted, and the old pmmcp-qdrant is in place, without a key' : 'refused or failed with everything as it was'}`,
    )
  }

  /** A fresh install's key file, made before the first start. */
  async #qdrantInit(step: Step, dir: string): Promise<void> {
    const ran = await this.#exec({ step: 'qdrant-init', command: this.#python(dir), args: ['scripts/qdrant_api_key.py', 'init'], cwd: dir, ownSession: true }, 'qdrant_api_key.py init')
    if (ran.ok && ran.result.code === 0) {
      this.#keyed = true
      this.#qdrant = undefined
      this.#item(step.short, 'done', '~/.persistent-memory-mcp/qdrant_api_key is there: the start creates pmmcp-qdrant with it')
      return
    }
    this.#item(step.short, 'failed', `qdrant_api_key.py init ${ran.ok ? `exited ${String(ran.result.code)}` : ran.why}: see its message above`)
  }

  /** L4: auth init for the files the facts show pmmcp takes safely, the curator secret never beside a running TUI. */
  async #authInit(step: Step, found: Found): Promise<void> {
    const dir = found.install.dir
    if (step.afterUpdate && !this.#updated) {
      this.#item(step.short, 'skipped', 'the update did not run, so nothing is created that only the updated pmmcp takes safely')
      return
    }
    const facts = this.#updatedFacts ?? found.facts
    if (facts === undefined) {
      this.#item(step.short, 'skipped', "pmmcp's facts cannot be read, so it cannot be told what pmmcp takes safely")
      return
    }
    const f = featuresOf(facts)
    const wanted = step.creates ?? []
    const skip = (file: AuthFile, why: string): void => this.#item(`the ${file === 'dashboard_token' ? 'dashboard token' : 'curator secret'}`, 'skipped', why)
    const dashSafe = f.dashboard_auth && f.stop_listener_check
    let dash = false
    if (wanted.includes('dashboard_token')) {
      if (!dashSafe) skip('dashboard_token', `pmmcp${this.#updated ? ', updated,' : ''} still lacks the dashboard token or the stop script's dashboard listener check`)
      else if (facts.dashboard_token.state !== 'absent') skip('dashboard_token', `~/.persistent-memory-mcp/dashboard_token is ${facts.dashboard_token.state} already`)
      else dash = true
    }
    let cur = false
    if (wanted.includes('curator_secret')) {
      const curator = facts.config.curator
      const bindOk = !curator.enabled || (curator.host === CURATOR_ADDRESS.host && curator.port === CURATOR_ADDRESS.port)
      if (!dashSafe || !f.curator_secret || !f.curator_proof) skip('curator_secret', `pmmcp${this.#updated ? ', updated,' : ''} still lacks the curator secret or the curator proof`)
      else if (!bindOk) {
        skip('curator_secret', `config.curator is ${curator.host}:${String(curator.port)}, and with a secret the curator serves only ${CURATOR_ADDRESS.host}:${String(CURATOR_ADDRESS.port)}: set curator.host and curator.port to that, then re-run`)
      } else if (facts.curator_secret.state !== 'absent') skip('curator_secret', `~/.persistent-memory-mcp/curator_secret is ${facts.curator_secret.state} already`)
      else {
        const tui = await this.#exec(tuiProbe(dir))
        const tuis = tui.result === undefined ? undefined : tuiPidsOf(tui.result)
        if (tuis === undefined) skip('curator_secret', 'whether a scripts/monitor_tui.py runs cannot be told (pgrep), and an older one would send the secret to whatever answers on 8767: not created; re-run')
        else if (tuis.length > 0) {
          skip(
            'curator_secret',
            `scripts/monitor_tui.py runs (${tuis.length === 1 ? 'pid' : 'pids'} ${list(tuis.map(String))}), and one started from older code sends the curator its raw secret once the file exists: quit it, then re-run`,
          )
        } else cur = true
      }
    }
    if (!dash && !cur) return
    const args = dash && cur ? [] : dash ? ['--only', 'dashboard'] : ['--only', 'curator']
    const ran = await this.#exec({ step: 'auth-init', command: this.#python(dir), args: ['-m', 'src.dashboard.auth', 'init', ...args], cwd: dir, ownSession: true }, `L4 auth init${args.length > 0 ? ` ${args.join(' ')}` : ''}`)
    if (dash) this.#chosen.add('dashboard_token')
    if (cur) this.#chosen.add('curator_secret')
    this.#written = true
    const status = await this.#authStatus(dir)
    if (status !== undefined) this.#auth = status
    for (const file of [...(dash ? (['dashboard_token'] as const) : []), ...(cur ? (['curator_secret'] as const) : [])]) {
      const state = status?.[file].state
      const name = `the ${file === 'dashboard_token' ? 'dashboard token' : 'curator secret'}`
      if (state === 'present') {
        this.#item(name, 'done', `~/.persistent-memory-mcp/${file} is there (0600, made by pmmcp's CLI)`)
        this.#undo.push(`to undo ${name}: stop pmmcp, remove ~/.persistent-memory-mcp/${file}, then start it`)
      } else {
        this.#item(name, 'failed', `auth init ${ran.ok ? `exited ${String(ran.result.code)}` : ran.why}, and auth status says ${state ?? 'nothing it can read'}`)
      }
    }
  }

  async #authStatus(dir: string): Promise<AuthStatus | undefined> {
    const ran = await this.#exec({ step: 'auth-status', command: this.#python(dir), args: ['-B', '-m', 'src.dashboard.auth', 'status', '--json'], cwd: dir, timeoutMs: PYTHON_MS })
    if (!ran.ok || (ran.result.code !== 0 && ran.result.code !== 1)) return undefined
    try {
      const parsed = AuthStatus.safeParse(JSON.parse(this.#out(ran.result) ?? ''))
      return parsed.success ? parsed.data : undefined
    } catch {
      return undefined
    }
  }

  /** L5: the start and its checks. Any check failed ends the run (exit 4) with the rollback commands. */
  async #startStep(step: Step, dir: string, oldPid: number | undefined): Promise<void> {
    this.#serverLogMark = logMark(this.#serverLog())
    this.#launchdErrMark = logMark(this.#launchdErrLog())
    const ran = await this.#exec({ step: 'start', command: join(dir, START_SCRIPT), args: [], cwd: dir }, `L5 ${START_SCRIPT}`)
    this.#started = ran.result !== undefined
    const facts = this.#factsNow()
    const ports = this.#ports(facts)
    const failed: string[] = []
    const passed: string[] = []
    let silent = false
    if (!ran.ok || ran.result.code !== 0) failed.push(`${START_SCRIPT} ${ran.ok ? `exited ${String(ran.result.code)}` : ran.why}`)

    const health = await this.#health(facts)
    if (health === 200) passed.push('/health 200')
    else {
      failed.push(`/health ${health === 0 ? 'gave no answer' : `answered ${String(health)}`}`)
      if (health === 0) silent = true
    }

    const mcp = await this.#mcpProcess(ports.server)
    const modified = this.#httpAuthModified()
    if (mcp.state === 'unknown') {
      // lsof could not say: neither that a server runs nor that none does, so whether one loaded the digest stays not known.
      failed.push(`whether an MCP server of this account listens on ${String(ports.server)} could not be checked (lsof failed: ${mcp.why})`)
    } else if (mcp.state === 'none') {
      // No server runs to have loaded it.
      this.#loaded = false
      failed.push(`no MCP server of this account listens on ${String(ports.server)}`)
    } else {
      const changed = oldPid === undefined || mcp.pid !== oldPid
      const after = mcp.startedAfter !== undefined && (modified === undefined || mcp.startedAfter.getTime() > modified.getTime())
      if (modified !== undefined) this.#loaded = changed && after
      if (!changed) failed.push(`the MCP server is still pid ${String(mcp.pid)}, the one that ran before the stop`)
      else if (mcp.startedAfter === undefined) failed.push(`when the MCP server (pid ${String(mcp.pid)}) started cannot be read (ps etime)`)
      else if (!after) failed.push(`the MCP server (pid ${String(mcp.pid)}) cannot be shown to have started after http_auth.yaml last changed`)
      else passed.push(`a new MCP server (pid ${String(mcp.pid)})${modified === undefined ? '' : ', started after http_auth.yaml last changed'}`)
    }

    const qdrant = await this.#containerState()
    if (qdrant === 'running') passed.push(`${QDRANT_CONTAINER} running`)
    else failed.push(qdrant === 'unknown' ? `whether ${QDRANT_CONTAINER} runs cannot be checked` : `${QDRANT_CONTAINER} is ${qdrant === 'absent' ? 'not there' : 'not running'}`)

    for (const [file, what] of WORKER_PID_FILES) {
      const alive = await this.#pidFileAlive(file)
      if (alive === true) passed.push(`${what} alive`)
      else failed.push(alive === false ? `${what} is not running (~/.persistent-memory-mcp/pids/${file} names no live process)` : `whether ${what} runs cannot be told (~/.persistent-memory-mcp/pids/${file})`)
    }

    if (this.#keyed) {
      const status = await this.#qdrantStatus(dir)
      if (status === undefined) failed.push(`Qdrant's status --json cannot be had, so whether it enforces the key is not known; to undo the cutover: ${this.#qdrantRollback(dir)}`)
      else {
        this.#qdrant = status
        if (status.verdict === 'enforced') passed.push('Qdrant verdict enforced')
        else failed.push(`Qdrant's verdict is ${status.verdict}, not enforced; to undo the cutover: ${this.#qdrantRollback(dir)}`)
      }
    }

    const dashboard = facts?.config.dashboard ?? { host: '127.0.0.1', port: PMMCP_PORTS.dashboard, enabled: true }
    if (this.#chosen.has('dashboard_token') && this.#auth?.dashboard_token.state === 'present') {
      const target = { host: dial(dashboard.host), port: dashboard.port }
      const st = await this.#answering({ ...target, path: '/api/auth/status' })
      if (st.status === 0) {
        silent = true
        failed.push(`the dashboard on ${String(dashboard.port)} gives no answer`)
      } else if (jsonField(st.body, 'auth_required') !== true) failed.push(`the dashboard's /api/auth/status does not say auth_required (HTTP ${String(st.status)})`)
      else {
        const fp = await this.#http({ ...target, path: '/api/fingerprint' }, HTTP_MS)
        if (fp.status === 401) passed.push('the dashboard requires its token (401 without it)')
        else failed.push(`the dashboard's /api/fingerprint answered ${fp.status === 0 ? 'nothing' : String(fp.status)} without a token, not 401`)
      }
    }
    const curator = facts?.config.curator ?? { host: '127.0.0.1', port: PMMCP_PORTS.curator, enabled: true }
    if (this.#chosen.has('curator_secret') && this.#auth?.curator_secret.state === 'present' && curator.enabled) {
      const cs = await this.#answering({ host: dial(curator.host), port: curator.port, path: '/api/curator/status' })
      if (cs.status === 401) passed.push('the curator requires a proof (401 without one)')
      else if (cs.status === 0) {
        silent = true
        failed.push(`the curator on ${String(curator.port)} gives no answer`)
      } else failed.push(`the curator's /api/curator/status answered ${String(cs.status)} without a proof, not 401`)
    }

    if (failed.length === 0) {
      this.#upChecked = true
      this.#item(step.short, 'done', passed.join('; '))
      return
    }
    this.#item(step.short, 'failed', failed.join('; '))
    this.#print('the start, or a check after it, failed:')
    for (const f of failed) this.#print(`  - ${f}`)
    if (silent) {
      this.#print('what pmmcp logged about a service that did not come up:')
      for (const line of this.#refusals(dir)) this.#print(`  ${line}`)
    }
    if (ran.result !== undefined) this.#print('pmmcp may be partly up (the start script re-enabled launchd). Once what failed is fixed, start it again:')
    else this.#print('the start did not run: pmmcp is stopped, and launchd stays disabled until the start script runs. Once what failed is fixed, start it:')
    this.#print(`  ${within(dir, './start-pmmcp-server.sh')}`)
    this.#todo.push(`once what failed is fixed: ${within(dir, './start-pmmcp-server.sh')}`)
    if (this.#undo.length > 0) {
      this.#print('or go back on what this window changed:')
      for (const way of this.#undo) this.#print(`  ${way}`)
    }
    throw new End(4, 'the start, or a check after it, failed')
  }

  /** GET an endpoint until something answers, a few times after the start script returns. */
  async #answering(target: { readonly host: string; readonly port: number; readonly path: string }): Promise<{ readonly status: number; readonly body: string }> {
    let answer = await this.#http(target, HTTP_MS)
    for (let i = 1; i < PROBE_TRIES && answer.status === 0; i += 1) {
      await this.#sleep(PROBE_WAIT_MS)
      answer = await this.#http(target, HTTP_MS)
    }
    return answer
  }

  /** /health on the MCP port, asked again until it answers 200 or the tries run out. */
  async #health(facts: Facts | undefined): Promise<number> {
    const server = facts?.config.server ?? { host: '127.0.0.1', port: PMMCP_PORTS.server }
    const target = { host: dial(server.host), port: server.port, path: '/health' }
    let status = (await this.#http(target, HTTP_MS)).status
    for (let i = 1; i < PROBE_TRIES && status !== 200; i += 1) {
      await this.#sleep(PROBE_WAIT_MS)
      status = (await this.#http(target, HTTP_MS)).status
    }
    return status
  }

  /**
   * The MCP server this account runs on the port, and the earliest it can
   * have started; none when nothing of this account listens there, unknown
   * when lsof could not say.
   */
  async #mcpProcess(
    port: number,
  ): Promise<{ readonly state: 'found'; readonly pid: number; readonly startedAfter: Date | undefined } | { readonly state: 'none' } | { readonly state: 'unknown'; readonly why: string }> {
    const l = await this.#listening(port)
    if (l.state === 'unknown') return { state: 'unknown', why: l.why }
    if (l.state === 'none') return { state: 'none' }
    const mine = l.pids.find((p) => p.uid !== undefined && p.uid === this.#uid)
    if (mine === undefined) return { state: 'none' }
    const before = this.#now()
    const ran = await this.#exec({ step: `ps-etime-${String(mine.pid)}`, command: 'ps', args: ['-o', 'etime=', '-p', String(mine.pid)], cwd: this.#o.repoRoot, timeoutMs: QUICK_MS })
    const elapsed = ran.ok && ran.result.code === 0 ? parseEtime((this.#out(ran.result) ?? '').split('\n')[0] ?? '') : undefined
    return { state: 'found', pid: mine.pid, startedAfter: elapsed === undefined ? undefined : startedAfter(before, elapsed) }
  }

  #httpAuthModified(): Date | undefined {
    try {
      return statSync(join(this.#pmmcpHome(), 'http_auth.yaml')).mtime
    } catch {
      return undefined
    }
  }

  async #qdrantStatus(dir: string): Promise<QdrantStatus | undefined> {
    const ran = await this.#exec({ step: 'qdrant-status', command: this.#python(dir), args: ['-B', 'scripts/qdrant_api_key.py', 'status', '--json'], cwd: dir, timeoutMs: PYTHON_MS })
    if (!ran.ok || ran.result.code !== 0) return undefined
    try {
      return parseQdrantStatus(this.#out(ran.result) ?? '')
    } catch (e) {
      if (e instanceof PmmcpDocumentError) return undefined
      throw e
    }
  }

  #qdrantRollback(dir: string): string {
    return `${within(dir, './stop-pmmcp-server.sh')}, then .venv/bin/python scripts/qdrant_api_key.py rollback, then ./start-pmmcp-server.sh`
  }

  /**
   * What pmmcp logged about a service that did not come up: the last
   * "refused to start" lines of server.log, the last lines of each stderr
   * file they name (only this checkout's dashboard_stderr.log and
   * curator_stderr.log), and any "pmmcp: refusing to start:" line of
   * launchd.err.log. Each log only from where it ended when the start began
   * (launchd.err.log is append-only across runs, and server.log is rotated
   * only by an MCP server that got as far as its logging): an older run's
   * refusal is not this start's. Each line scrubbed.
   */
  #refusals(dir: string): string[] {
    const out: string[] = []
    const refused = logTail(this.#serverLog(), LOG_TAIL_BYTES, this.#serverLogMark).filter((l) => l.includes('refused to start')).slice(-3)
    for (const line of refused) out.push(`server.log: ${shownLine(eventOf(line))}`)
    const allowed = new Map<string, string>()
    for (const d of spellings(dir)) for (const name of ['dashboard_stderr.log', 'curator_stderr.log']) allowed.set(join(d, 'logs', name), name)
    const named = new Set<string>()
    // pmmcp names the file absolutely, "(see <path>) — restarting": the path may hold spaces (a checkout under ~/My Projects), so it runs to the ")" before the dash or the end.
    for (const line of refused) for (const m of eventOf(line).matchAll(/\(see (\S.*?_stderr\.log)\)(?= —|\s*$)/g)) if (m[1] !== undefined) named.add(m[1])
    for (const path of named) {
      const name = allowed.get(path)
      if (name === undefined) {
        out.push(`server.log names ${shownLine(path)}, which is not this checkout's: not read`)
        continue
      }
      for (const line of logTail(path, LOG_TAIL_BYTES).slice(-5)) out.push(`${name}: ${shownLine(line)}`)
    }
    for (const line of logTail(this.#launchdErrLog(), LOG_TAIL_BYTES, this.#launchdErrMark).filter((l) => l.includes('pmmcp: refusing to start:')).slice(-2)) {
      out.push(`launchd.err.log: ${shownLine(line)}`)
    }
    if (out.length === 0) out.push('no "refused to start" line in ~/.persistent-memory-mcp/logs/server.log, and no "pmmcp: refusing to start:" line in launchd.err.log, since the start')
    return out
  }

  /**
   * L6: whether the kernel's bearer reached pmmcp since the start: server.log
   * from the start's mark. pmmcp's setup_logging rolls server.log over to
   * server.log.1 whenever an MCP server starts, so after a start that got
   * that far the file is the new server's alone (read whole: another file
   * than the mark's); the mark guards the case where the server did not
   * restart its log, where an earlier run's line would still be there.
   * Inconclusive, never failed, when the line is not there.
   */
  #bearerCheck(step: Step): void {
    const lines = logTail(this.#serverLog(), SERVER_LOG_BYTES, this.#serverLogMark)
    const seen = lines.some((line) => {
      if (!line.includes('first request with token')) return false
      try {
        const v: unknown = JSON.parse(line)
        if (v !== null && typeof v === 'object' && !Array.isArray(v)) return (v as Record<string, unknown>)['token'] === PMMCP_CLIENT
      } catch {
        // Not JSON: by the name as a word.
      }
      return new RegExp(`(?:^|[^a-z0-9._-])${PMMCP_CLIENT}(?:$|[^a-z0-9._-])`).test(line)
    })
    if (seen) {
      this.#item(step.short, 'done', `server.log has "first request with token" for ${PMMCP_CLIENT} since the start`)
      return
    }
    // A restart only when the next steps ask one (the running daemon does not hold what changed); else its hub reconnects by itself.
    const then = this.#daemonRestartNeeded()
      ? 'restart npm run dev, as the next steps say'
      : "the AOS daemon's next request makes the line (its hub reconnects to the restarted pmmcp within its 240 s heartbeat; if npm run dev is not running, start it)"
    this.#item(
      step.short,
      'inconclusive',
      `no "first request with token" for ${PMMCP_CLIENT} in server.log since the start (the installer holds no token to send one): ${then}, then ` +
        `grep "first request with token" ~/.persistent-memory-mcp/logs/server.log`,
    )
  }

  /**
   * Whether something the daemon reads changed in this run: .env gained a
   * line, or the restarted pmmcp loaded an aos-kernel digest that the server
   * before it had not (staged this run, or on file but not loaded, or not
   * known to be loaded). A cutover, a dashboard token or an update on a
   * system whose server had the digest already changes nothing it reads.
   */
  #daemonRestartNeeded(): boolean {
    const env = this.#env
    const envChanged = env !== undefined && (env.created || env.appended.length > 0)
    const loadedNow = this.#started && this.#digestOnFile === true && this.#loaded === true
    return envChanged || (loadedNow && (this.#digestStaged || this.#loadedBefore !== true))
  }

  // ── a fresh install ──

  async #fresh(steps: readonly Step[]): Promise<void> {
    const d = this.#o.discovery
    const at = this.#o.plan.pmmcpDir
    if (d?.kind !== 'absent' || at === undefined) throw new ApplyError('a fresh install needs discovery to have found no pmmcp')
    for (const step of steps) {
      this.#reached.add(step)
      switch (step.id) {
        case 'env':
          await this.#append(step)
          break
        case 'clone':
          await this.#clone(step, at)
          break
        case 'setup':
          await this.#setup(step, at)
          break
        case 'stop':
          this.#clearStale()
          await this.#stopStep(step, at)
          break
        case 'qdrant-init':
          await this.#qdrantInit(step, at)
          break
        case 'stage-digest':
          await this.#stage(step, true)
          break
        case 'start':
          await this.#startStep(step, at, undefined)
          this.#closeWindow()
          break
        case 'bearer-check':
          this.#bearerCheck(step)
          break
        default:
          throw new ApplyError(`${step.id} is not a step of a fresh install`)
      }
    }
    await this.#refreshFacts()
  }

  async #clone(step: Step, at: string): Promise<void> {
    let there = true
    try {
      lstatSync(at)
    } catch {
      there = false
    }
    if (there) {
      this.#item(step.short, 'failed', `${at} exists already: nothing was cloned. Re-run, and the installer finds it`)
      throw new End(this.#written ? 1 : 2, `${at} exists already, so nothing was installed`)
    }
    const ran = await this.#exec({ step: 'git-clone', command: 'git', args: ['clone', CLONE_URL, at], cwd: this.#o.home }, 'git clone')
    if (!ran.ok || ran.result.code !== 0) {
      this.#item(step.short, 'failed', `git clone ${ran.ok ? `exited ${String(ran.result.code)}` : ran.why}: see its message above`)
      throw new End(1, 'the clone failed')
    }
    this.#written = true
    this.#item(step.short, 'done', `${CLONE_URL} cloned to ${at}`)
  }

  /** setup.sh in its own session (it loads the launchd service), then the new checkout's facts. */
  async #setup(step: Step, at: string): Promise<void> {
    const cleared = this.#clearStale()
    if (cleared !== undefined) {
      this.#item(step.short, 'failed', cleared)
      throw new End(1, "an earlier run's active.json record could not be cleared, so setup did not run")
    }
    this.#liveBegun = true
    this.#openWindow()
    const ran = await this.#exec({ step: 'setup', command: join(at, 'setup.sh'), args: ['--non-interactive'], cwd: at, ownSession: true }, 'setup.sh --non-interactive')
    if (!ran.ok || ran.result.code !== 0) {
      this.#item(step.short, 'failed', `setup.sh ${ran.ok ? `exited ${String(ran.result.code)}` : ran.why}: see its message above`)
      this.#todo.push(`finish the setup by hand: ${within(at, './setup.sh')}, then re-run the installer`)
      throw new End(4, 'setup.sh failed')
    }
    this.#item(step.short, 'done', 'exit 0')
    const facts = await this.#readFacts(at, 'facts')
    const problems: string[] = []
    if ('why' in facts) problems.push(facts.why)
    else {
      this.#facts = facts.facts
      const f = featuresOf(facts.facts)
      const lacking = (['stop_jobs_flag', 'rotate_digest_stdin', 'check_expect', 'qdrant_init'] as const).filter((x) => !f[x])
      if (lacking.length > 0) problems.push(`the new checkout lacks ${list([...lacking])}`)
      // As discovery holds a found install (plan Q15): each service on its own port, on a loopback host, never 0.0.0.0 or a LAN address.
      for (const svc of ['server', 'dashboard', 'curator'] as const) {
        const { host, port } = facts.facts.config[svc]
        if (port !== PMMCP_PORTS[svc] || !LOOPBACK_HOSTS.has(host)) {
          problems.push(`config.${svc} is ${host}:${String(port)}: the installer needs ${svc}.host on loopback (127.0.0.1) and ${svc}.port ${String(PMMCP_PORTS[svc])}`)
        }
      }
    }
    if (problems.length > 0) {
      this.#item("the new checkout's facts", 'failed', problems.join('; '))
      this.#todo.push(`fix what is named, then stop what setup started (${within(at, './stop-pmmcp-server.sh')}) and re-run the installer`)
      throw new End(4, "the new checkout's facts are not what the installer needs")
    }
  }

  // ── probes ──

  /**
   * Run one child through the runner; a step (with a label) prints its
   * elapsed time and the tail of its logs. Inside the window, a probe the
   * terminal's Ctrl-C or hangup ended is run again (INTERRUPT_RERUNS at
   * most): only a probe is given a timeout here, and only a probe is the
   * installer's own child, so a spec with timeoutMs is one; a step in its own
   * session never sees the Ctrl-C, and a step that writes is never run twice.
   */
  async #exec(spec: RunSpec, label?: string): Promise<Ran> {
    for (let rerun = 0; ; rerun += 1) {
      let result: RunResult
      try {
        result = await this.#o.runner.run(spec)
      } catch (e) {
        if (e instanceof InstallRunError && e.code !== 'AOS_INSTALL_RUN_LEAK' && e.code !== 'AOS_INSTALL_RUN_HALTED') {
          if (label !== undefined) this.#print(`${label}: not run: ${e.message}`)
          return { ok: false, why: e.message }
        }
        throw e
      }
      this.#activeProblem(result.activeError)
      if (label !== undefined) {
        const how = !result.exited ? 'gave no answer' : result.signal !== null ? `ended by ${result.signal}` : `exit ${String(result.code)}`
        this.#print(`${label}: ${how} after ${seconds(result.elapsedMs)}`)
        for (const line of this.#tailOf(result.out, 5)) this.#print(`  | ${line}`)
        for (const line of this.#tailOf(result.err, 5)) this.#print(`  ! ${line}`)
      }
      const by = result.exited ? endedBy(result) : undefined
      if (by !== undefined && this.#windowOpen && spec.timeoutMs !== undefined && spec.ownSession !== true && rerun < INTERRUPT_RERUNS) {
        this.#print(`${spec.step}: ended by ${by}, which does not end the window: asked again`)
        continue
      }
      if (result.timedOut || !result.exited) return { ok: false, why: `${spec.step}: ${spec.command} gave no answer within ${seconds(spec.timeoutMs ?? 0)}`, result }
      if (result.signal !== null) return { ok: false, why: `${spec.step}: ${spec.command} ended by ${result.signal}`, result }
      return { ok: true, result }
    }
  }

  #out(result: RunResult): string | undefined {
    try {
      return readOut(result)
    } catch (e) {
      if (e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_OUTPUT') return undefined
      throw e
    }
  }

  #tailOf(path: string, lines: number): string[] {
    try {
      return tail(path, lines)
    } catch {
      return []
    }
  }

  /** What listens on a loopback port: lsof's p and u fields only. */
  async #listening(port: number): Promise<Listening> {
    const ran = await this.#exec({ step: `lsof-${String(port)}`, command: 'lsof', args: ['-nP', `-iTCP:${String(port)}`, '-sTCP:LISTEN', '-Fpu'], cwd: this.#o.repoRoot, timeoutMs: QUICK_MS })
    if (!ran.ok) return { state: 'unknown', why: ran.why }
    const out = this.#out(ran.result) ?? ''
    if (ran.result.code === 1 && out.trim() === '') return { state: 'none' }
    if (ran.result.code !== 0) return { state: 'unknown', why: `lsof exited ${String(ran.result.code)}` }
    const pids: { pid: number; uid: number | undefined }[] = []
    for (const line of out.split('\n')) {
      if (/^p\d+$/.test(line)) {
        const pid = Number(line.slice(1))
        if (!pids.some((p) => p.pid === pid)) pids.push({ pid, uid: undefined })
      } else if (/^u\d+$/.test(line)) {
        const last = pids.at(-1)
        if (last !== undefined) last.uid = Number(line.slice(1))
      }
    }
    return pids.length === 0 ? { state: 'none' } : { state: 'listening', pids }
  }

  /** pmmcp-qdrant in the runner's docker engine (no DOCKER_* reaches it), from docker ps's names and states. */
  async #containerState(): Promise<ContainerState> {
    const ran = await this.#exec({
      step: 'docker-ps-qdrant',
      command: 'docker',
      args: ['ps', '--all', '--filter', `name=${QDRANT_CONTAINER}`, '--format', '{{.Names}} {{.State}}'],
      cwd: this.#o.repoRoot,
      timeoutMs: DOCKER_MS,
    })
    if (!ran.ok || ran.result.code !== 0) return 'unknown'
    const out = this.#out(ran.result)
    if (out === undefined) return 'unknown'
    for (const line of out.split('\n')) {
      const [name, state] = line.trim().split(/\s+/)
      if (name === QDRANT_CONTAINER) return state === 'running' ? 'running' : 'stopped'
    }
    return 'absent'
  }

  /** The PID files under ~/.persistent-memory-mcp/pids that name a live process, and those that cannot be told. */
  async #livePidFiles(): Promise<{ readonly alive: readonly { readonly file: string; readonly pid: number }[]; readonly unknown: readonly string[] }> {
    const folder = join(this.#pmmcpHome(), 'pids')
    let names: string[]
    try {
      names = readdirSync(folder).filter((n) => n.endsWith('.pid')).sort()
    } catch (e) {
      return errnoOf(e) === 'ENOENT' ? { alive: [], unknown: [] } : { alive: [], unknown: [`~/.persistent-memory-mcp/pids cannot be read (${errnoOf(e)})`] }
    }
    const alive: { file: string; pid: number }[] = []
    const unknown: string[] = []
    for (const name of names) {
      const pid = this.#pidIn(join(folder, name))
      if (pid === undefined) continue
      const live = await this.#pidAlive(pid)
      if (live === true) alive.push({ file: `pids/${name}`, pid })
      else if (live === undefined) unknown.push(`whether pid ${String(pid)} (pids/${name}) runs cannot be told`)
    }
    return { alive, unknown }
  }

  /** Whether the process a PID file names runs: undefined when the file or ps cannot say. */
  async #pidFileAlive(name: string): Promise<boolean | undefined> {
    const pid = this.#pidIn(join(this.#pmmcpHome(), 'pids', name))
    if (pid === undefined) return false
    return this.#pidAlive(pid)
  }

  /** The pid a PID file holds, read as a regular file only, to a cap; undefined for none. */
  #pidIn(path: string): number | undefined {
    const lines = logTail(path, PID_FILE_CAP)
    const m = /^\s*(\d{1,9})\s*$/.exec(lines.join('\n'))
    const pid = m === null ? undefined : Number(m[1])
    return pid === undefined || pid <= 1 ? undefined : pid
  }

  async #pidAlive(pid: number): Promise<boolean | undefined> {
    const ran = await this.#exec({ step: `ps-pid-${String(pid)}`, command: 'ps', args: ['-o', 'pid=', '-p', String(pid)], cwd: this.#o.repoRoot, timeoutMs: QUICK_MS })
    if (!ran.ok) return undefined
    const out = (this.#out(ran.result) ?? '').trim()
    if (ran.result.code === 0 && out === String(pid)) return true
    if (ran.result.code === 1 && out === '') return false
    return undefined
  }

  async #readFacts(dir: string, stepName: string): Promise<{ readonly facts: Facts } | { readonly why: string }> {
    const ran = await this.#exec({ step: stepName, command: this.#python(dir), args: ['scripts/pmmcp_facts.py', '--json'], cwd: dir, timeoutMs: PYTHON_MS })
    if (!ran.ok) return { why: `the facts cannot be had: ${ran.why}` }
    if (ran.result.code !== 0) {
      const err = this.#tailOf(ran.result.err, 1)
      return { why: `the facts exited ${String(ran.result.code)}${err.length > 0 ? `: ${err.join(' ')}` : ''}` }
    }
    try {
      return { facts: parseFacts(this.#out(ran.result) ?? '') }
    } catch (e) {
      if (e instanceof PmmcpDocumentError) return { why: e.message }
      throw e
    }
  }

  /** The facts once a phase changed pmmcp, for the end report's bearer line; the last ones kept when they cannot be had. */
  async #refreshFacts(): Promise<void> {
    const dir = this.#o.plan.pmmcpDir
    if (dir === undefined || this.#o.runner.halted !== undefined || this.#o.discovery === undefined) return
    if (this.#o.discovery.kind === 'absent' && this.#facts === undefined) return
    const facts = await this.#readFacts(dir, 'facts-after')
    if ('facts' in facts) this.#facts = facts.facts
  }

  // ── small helpers ──

  #found(): Found {
    const d = this.#o.discovery
    if (d?.kind !== 'found') throw new ApplyError('a live window needs an install discovery found')
    return d
  }

  #dir(): string {
    const dir = this.#o.plan.pmmcpDir
    if (dir === undefined) throw new ApplyError('the plan names no pmmcp folder')
    return dir
  }

  #python(dir: string): string {
    return join(dir, '.venv', 'bin', 'python')
  }

  #pmmcpHome(): string {
    return join(this.#o.home, '.persistent-memory-mcp')
  }

  #serverLog(): string {
    return join(this.#pmmcpHome(), 'logs', 'server.log')
  }

  #launchdErrLog(): string {
    return join(this.#pmmcpHome(), 'logs', 'launchd.err.log')
  }

  /** The facts that describe the checkout now: L2's re-read ones once it ran. */
  #factsNow(): Facts | undefined {
    return this.#updatedFacts ?? this.#facts
  }

  #ports(facts: Facts | undefined): { readonly server: number; readonly dashboard: number; readonly curator: number } {
    return {
      server: facts?.config.server.port ?? PMMCP_PORTS.server,
      dashboard: facts?.config.dashboard.port ?? PMMCP_PORTS.dashboard,
      curator: facts?.config.curator.port ?? PMMCP_PORTS.curator,
    }
  }

  #ids(): Pick<InspectOptions, 'uid' | 'euid'> {
    const ids = this.#o.inspect
    return { ...(ids?.uid === undefined ? {} : { uid: ids.uid }), ...(ids?.euid === undefined ? {} : { euid: ids.euid }) }
  }

  /**
   * Clear the active.json record discovery found stale (its pid no longer
   * runs it), once, and only while active.json still holds that record:
   * another is no one's to clear here. Returns why it could not be cleared.
   */
  #clearStale(): string | undefined {
    if (this.#staleCleared) return undefined
    const d = this.#o.discovery
    const stale: ActiveRecord | undefined = d === undefined ? undefined : d.staleActive
    this.#staleCleared = true
    if (stale === undefined) return undefined
    const now = readActive(this.#o.repoRoot)
    if (now.state !== 'recorded' || now.record.pid !== stale.pid || now.record.started !== stale.started || now.record.step !== stale.step) return undefined
    try {
      clearActive(this.#o.repoRoot)
      this.#print(`cleared an earlier run's .aos/install/active.json record of ${shownLine(stale.step)} (pid ${String(stale.pid)}), which no longer runs`)
      return undefined
    } catch (e) {
      return `${e instanceof Error ? e.message : 'active.json could not be removed'}: remove it once nothing it names runs, then re-run`
    }
  }

  /**
   * A record the runner could not remove (or fill in) after a step in its
   * own session: a re-run reads it as a window that may still be open, so
   * the operator is told to remove it once nothing it names runs.
   */
  #activeProblem(problem: string | undefined): void {
    if (problem === undefined || this.#todo.includes(problem)) return
    this.#print(problem)
    this.#todo.push(problem)
  }

  #openWindow(): void {
    if (this.#windowOpen) return
    this.#windowOpen = true
    this.#o.window?.(true)
  }

  #closeWindow(): void {
    if (!this.#windowOpen) return
    this.#windowOpen = false
    this.#o.window?.(false)
  }

  #leaked(e: InstallRunError): 1 | 4 {
    if (this.#leak === undefined) {
      const what = this.#o.runner.halted ?? e.message
      // From the stop until the start's checks all passed, pmmcp may be stopped; after them it is up as checked, and nothing of the window is left unchecked.
      this.#leak = { step: e.step, what, live: this.#liveBegun && !this.#upChecked }
      this.#item(`${e.step ?? 'a step'}'s output`, 'failed', what)
      this.#print(`stopped: ${what}. Nothing more is run.`)
      if (this.#leak.live) {
        const dir = this.#o.plan.pmmcpDir
        if (dir !== undefined) this.#todo.push(`pmmcp may be stopped: start it with ${within(dir, './start-pmmcp-server.sh')}`)
      }
    }
    return this.#leak.live ? 4 : 1
  }

  #item(what: string, state: ItemState, detail: string): void {
    this.#items.push({ what: shownLine(what), state, detail: shownLine(detail) })
  }

  #print(line: string): void {
    this.#o.print(shownLine(line))
  }

  // ── S8 ──

  /** The end report (S8): every item, .env, pmmcp's bearer, Qdrant, the dashboard, the backups, a leak, the next steps. Never a value. */
  report(): string[] {
    const out: string[] = ['end report:']
    const plan = this.#o.plan
    const dir = plan.pmmcpDir
    for (const item of this.#items) out.push(`  ${item.state.padEnd(12)} ${item.what}${item.detail === '' ? '' : `: ${item.detail}`}`)
    for (const step of plan.steps) if (!this.#handed.has(step)) out.push(`  ${'skipped'.padEnd(12)} ${shownLine(step.short)}`)

    const env = this.#env
    const failed = this.#envFailed
    const mode = this.#dotenvMode
    const modeText = mode === undefined ? '' : `; mode ${mode.mode.toString(8).padStart(4, '0')}`
    if (env !== undefined) {
      const appended = env.appended.map((n) => `${n.name} (line ${String(n.line)})`)
      out.push(`.env  ${env.path}: ${appended.length === 0 ? 'nothing appended' : `${env.created ? 'created with' : 'appended'} ${list(appended)}`}${modeText}`)
    } else if (failed?.written === true) {
      // Never "not written": the writer said it may have changed the file before it failed.
      out.push(`.env  ${mode?.path ?? plan.dotenv.path}: may have been changed by this run before the writer failed (${shownLine(failed.message)})${modeText}`)
      out.push(`  ${shownLine(this.#dotenvCheck())}`)
    } else out.push(`.env  ${mode?.path ?? plan.dotenv.path}: not written by this run${modeText}`)
    if (mode?.acl === true) out.push('  it carries an ACL, which the loader does not read: run chmod -N .env in the repository root')
    else if (mode !== undefined && mode.acl === undefined) {
      out.push('  whether it carries an ACL cannot be told (ls -le .env lists one as numbered lines under it): if it does, run chmod -N .env in the repository root')
    }

    const facts = this.#facts
    if (dir !== undefined && plan.kind !== 'aos-only' && plan.kind !== 'not-installed') {
      if (facts !== undefined) {
        const a = facts.http_auth
        out.push(`pmmcp bearer: http_auth.yaml ${a.state}${a.mode === null ? '' : `, mode ${a.mode}`}, tokens [${a.tokens.map((t) => shownLine(t)).join(', ')}]`)
      }
      const yes = (b: boolean | undefined): string => (b === undefined ? 'not known' : b ? 'yes' : 'no')
      if (plan.staged !== undefined || this.#digestOnFile !== undefined) {
        out.push(`  ${PMMCP_CLIENT} digest matches .env: ${yes(this.#digestOnFile)}; loaded by the running server: ${yes(this.#digestOnFile === true ? this.#loaded : undefined)}`)
      }
      const q = this.#qdrant
      if (q !== undefined) {
        out.push(`qdrant: verdict ${q.verdict}`)
        if (q.prekey_kept) out.push(`  pmmcp-qdrant-prekey kept; remove it later with ${within(dir, '.venv/bin/python scripts/qdrant_api_key.py cleanup')}`)
      } else if (this.#keyed) {
        // The key was made this run, and no status --json was read since: the verdict from before the key no longer holds.
        out.push(`qdrant: verdict not known (no status --json was read after the key was made): ${within(dir, '.venv/bin/python scripts/qdrant_api_key.py status')}`)
      }
      const dash = this.#auth?.dashboard_token.state ?? facts?.dashboard_token.state
      if (dash === 'present') out.push(`dashboard: open it with ${within(dir, '.venv/bin/python -m src.dashboard.auth open')}`)
    }
    if (this.#backups.length > 0) out.push(`backups made: ${this.#backups.join(', ')}`)

    const leak = this.#leak
    if (leak !== undefined) {
      out.push(`stopped by a defect: ${leak.what}`)
      if (leak.live && dir !== undefined) {
        out.push(
          `  not checked: what listens on ${list([PMMCP_PORTS.server, PMMCP_PORTS.dashboard, PMMCP_PORTS.curator].map(String))}, whether ${QDRANT_CONTAINER} runs, ` +
            'the PID files under ~/.persistent-memory-mcp/pids, and /health',
        )
      }
    }
    if (this.#todo.length > 0) {
      out.push('to do by hand:')
      for (const t of this.#todo) out.push(`  ${t}`)
    }
    if (this.#undo.length > 0 && this.#items.some((i) => i.state === 'failed')) {
      out.push('to go back on what this run changed:')
      for (const u of this.#undo) out.push(`  ${u}`)
    }

    out.push('next steps:')
    // Only when something the daemon reads changed (#daemonRestartNeeded).
    if (failed?.written === true) out.push('  check .env as above before you restart npm run dev: the loader refuses a .env that git does not ignore or that others can read')
    else if (this.#daemonRestartNeeded()) out.push('  restart npm run dev (it reads .env when it starts), and check that its credentials line names the tokens and that the hub is ok')
    if (plan.dotenv.lines.some((l) => l.name === 'ANTHROPIC_API_KEY' && l.state !== 'present')) out.push('  add ANTHROPIC_API_KEY to .env yourself: the installer never writes it')
    // The virtualenv's own module, not `uv run`, which may sync (and prune) the virtualenv on the way.
    if (plan.kind === 'fresh-install') out.push(`  for scraping pages that need JavaScript: ${within(dir ?? `~/Github/${PMMCP_FOLDER}`, '.venv/bin/python -m playwright install chromium')}`)
    const shared = this.#o.discovery?.kind === 'found' || this.#o.discovery?.kind === 'absent' ? this.#o.discovery.kernel.ollamaShared : []
    if (shared.length > 0) out.push(`  ${list(shared.map((s) => `${s.ref} (${String(s.port)})`))} shares one of pmmcp's Ollama ports 11434-11437, which pmmcp's stop stops: move it to a port of its own`)
    // Of a pmmcp this run touched: none with --aos-only, and none is installed with --no-install.
    if (plan.kind !== 'aos-only' && plan.kind !== 'not-installed') {
      out.push("  pmmcp's bearer gate stays in warn mode: switching it to enforce is your later step")
      out.push('  re-running setup.sh or deploy-multi-session-config.sh rewrites ~/.persistent-memory-mcp/config.yaml')
    }
    return out
  }
}
