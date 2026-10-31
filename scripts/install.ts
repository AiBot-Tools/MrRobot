// The installer's entry point: `npm run aos-install`.
//
// CONTRACT
//
//   What it is: the program that walks plan §5 screen by screen, and nothing
//   more. Every decision is made elsewhere: what .env holds by the one writer's
//   inspection (src/secrets/dotenv-append.ts), what pmmcp is and how it runs by
//   discovery (scripts/install/discover.ts), what would change by the pure
//   planner and what the operator must answer and type by the gate
//   (src/install/plan.ts, src/install/gate.ts), and how each step is carried
//   out and checked by the applier (scripts/install/apply.ts). Every program it
//   starts goes through the A3 runner (scripts/install/run.ts): no DOCKER_*,
//   PMMCP_*, AOS_* or credential name in a child's environment, stdin from
//   /dev/null or one digest, output in 0600 files under
//   .aos/install/<UTC stamp>/. It holds no credential value: it never opens
//   .env itself and never imports the loader (src/secrets/dotenv.ts); the
//   tokens it mints go from the applier straight into the writer, and pmmcp is
//   given the digest the writer returns.
//
//   In order:
//     npm's traces (scripts/install/preflight.ts, npmTookFlags): a flag given
//       before `--` is npm's, not the installer's (`npm run aos-install
//       --dry-run` runs a real run with npm_config_dry_run set): usage on
//       stderr, exit 2, nothing looked at.
//     Flags (--dry-run, --aos-only, --pmmcp-dir PATH, --no-install, --help).
//       Anything else, a repeat, or --aos-only beside a pmmcp flag: usage on
//       stderr, exit 2, nothing looked at. There is no --yes and no --force.
//     S1, the preflight (scripts/install/preflight.ts), read-only and
//       in-process (no child is started): not root, HOME, the checkout's
//       root as the current directory, no falsify hold, Node's engines,
//       node_modules, .gitignore, the shell's DOCKER_* and PMMCP_* exports
//       by name, and, unless --aos-only, the programs pmmcp and its scripts
//       call on the PATH a child gets. Any refusal: every one is printed
//       with its fix, exit 2.
//     The lock (scripts/install/lock.ts), <repo>/.aos/install.lock: one
//       installer at a time. A stale one (its pid gone, the machine booted
//       since, or the pid given to a process that started after it) is
//       taken over and said so; a live one, or anything else at that path,
//       refuses (exit 2) and names its removal. It is removed at exit,
//       whatever ends the run but a kill.
//     S2, the .env screen: inspectCredentials over every accepted name (the
//       credentials map's first), and again over the map's names alone for
//       `writable` and `fits` (its `fits` counts every missing name it is
//       given). A refusal of the writer's (the trap .env's mode, a placeholder,
//       an undeclared name, ...) changes nothing: exit 2.
//     S3, discovery, unless --aos-only: a stop (exit 2), a probe the runner's
//       rules refused for the machine's state (InstallRunError.machine: a
//       file on the child's PATH that is pmmcp's stop or start script by
//       link or identity, a link to a program never run there, the log
//       folder's mode: exit 2, the runner's message naming the file and the
//       fix; any other refusal of the runner's is the installer's defect,
//       exit 1), or the screen of what was found (or not) and discovery's
//       notes, which the gate prints after S2's (plan §5's order); for a
//       found install the pids of every running scripts/monitor_tui.py,
//       handed to the planner as pgrep gave them (the warning lists them,
//       or says whether one runs cannot be told when pgrep gave no answer,
//       never that none runs, and the applier checks again before a curator
//       secret is made), the same refusals and stops ending the run there.
//     S4 on: the plan (planInstall) walked by the gate (runGate) with the
//       applier as its apply and jobs count, and, once a phase was applied or
//       failed, the applier's recheck (the facts and Qdrant's status read
//       again when the window opened, with a signal held meanwhile) and its
//       end report (S8).
//
//   A dry run (--dry-run) stops after the gate printed the plan, every step as
//   would-do and every question and typed word it would ask. What it writes:
//   .aos and .aos/install when missing (0700), the runner's logs of its
//   read-only probes under .aos/install/<stamp>/ (active.json while a --jobs
//   count runs, removed at its exit), <stamp>/installer.out only when its own
//   stdout or stderr went away during the run (Output.keep, at the end), and
//   the lock while it runs. Nothing else, in the checkout or in HOME.
//
//   Signals (scripts/install/signals.ts): SIGINT, SIGHUP and SIGTERM. The
//   same one again within 100 ms is one delivered twice (npm forwards the
//   terminal's Ctrl-C) and does nothing. At a prompt or the jobs wait it is
//   that prompt's answer (the gate and the applier read it as a no or an
//   abort). Inside the stopped window (the applier's `window`, from L1's
//   start to L5's end) it is trapped: the installer says the window is
//   finishing and goes on, and says so again at the end; the steps there run
//   in sessions of their own (A3), so neither a Ctrl-C nor a closed terminal
//   reaches them. Once the window has opened, and until the end report is
//   printed, it is held outside the window too: the run's last checks and
//   its report (what was done, whether pmmcp is left stopped, what is left
//   to do) come first, and the run ends with the gate's code. While pmmcp's
//   jobs are counted it ends the count (the gate then ends the run, 130).
//   Anywhere else, before the window ever opened, it ends the run at once,
//   with 130, 129 or 143 (nothing is half done then that a re-run does not
//   pick up from the state on disk).
//
//   Output (scripts/install/output.ts): a write error on stdout or stderr
//   (EPIPE from a `| tee` the same Ctrl-C ended, EIO from a closed terminal)
//   never ends the run: the stream is read as lost, stdout's lines go to
//   stderr while that works, nothing more is asked (a question no one sees
//   is answered as the input ending), and at the end what the installer said
//   goes to installer.out in the run's log folder, the end report and any
//   manual start with it. A line typed ahead of a question is not its answer
//   (scripts/install/terminal.ts).
//
//   The last line, once the flags were taken: `aos-install: exit N: <how
//   this run ended>`, the installer's own code and what it was for this run
//   (scripts/install/ending.ts: the gate's outcome, a refusal, a stop, a
//   signal or a defect, and "the end report above" only when one was
//   printed). npm 10 re-raises a SIGINT it forwarded, so `npm run
//   aos-install` may end with 130 after a Ctrl-C inside the window although
//   the installer finished; this line is the run's word, and `node --import
//   tsx scripts/install.ts` (from the root) exits with the installer's own
//   code.
//
//   Exit codes (plan §5): 0 done, nothing to do, a dry run, or declined; 1 a step
//   failed and the state is as reported (also a leak, or an installer defect,
//   before the window opened); 2 refused before any change; 3 changes are
//   needed but stdin is not a terminal; 4 a live step failed and pmmcp is not
//   in its intended state (also a defect once the window had opened); 130
//   interrupted before the window opened (129 and 143 for SIGHUP and
//   SIGTERM), and the input ending or any of those signals at a prompt,
//   which answers it, or during the jobs count, which it ends (130 whichever
//   it was: the last line says "interrupted", not which).

import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { ConfigError } from '../src/errors.js'
import { runGate, type GateIO, type GateOutcome, type JobsAnswer } from '../src/install/gate.js'
import { credentialsMap, exportedNames, planInstall, shellWord } from '../src/install/plan.js'
import { parseProviders, type ProvidersFile } from '../src/models/registry.js'
import { DotenvWriteError, credentialNames, inspectCredentials, mintedCredentialNames, type InspectResult } from '../src/secrets/dotenv-append.js'
import { Applier, tuiPids } from './install/apply.js'
import { DiscoverError, PLIST_LABEL, discover, type Absent, type Found } from './install/discover.js'
import { defectEnding, exitLine, outcomeEnding, refusedEnding, signalEnded, signalEnding, stoppedEnding, type Ending } from './install/ending.js'
import { startWithPs, takeLock } from './install/lock.js'
import { Output } from './install/output.js'
import { npmTookFlags, preflight } from './install/preflight.js'
import { InstallRunError, Runner, shownLine } from './install/run.js'
import { HANDLED_SIGNALS, defectExit, handleSignal, signalWords, windowChanged, type HandledSignal } from './install/signals.js'
import { Terminal } from './install/terminal.js'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const USAGE = [
  'usage: npm run aos-install [-- <flags>]',
  '',
  'Finds pmmcp (or installs it at ~/Github/Persistent-Memory-MCP when there is none), appends the tokens',
  '.env lacks, gives pmmcp only the aos-kernel digest, and changes a running pmmcp only after a warning',
  'and two typed confirmations, through a graceful stop-pmmcp-server.sh.',
  '',
  '  --dry-run          discover and plan only: nothing is changed, stopped or started',
  '  --aos-only         .env only: pmmcp is never touched',
  '  --pmmcp-dir PATH   use this pmmcp install (still validated)',
  '  --no-install       never offer the clone and setup.sh',
  '  --help             this text',
  '',
  'The flags go after --, as in npm run aos-install -- --dry-run: npm takes one given before -- as its own.',
  'There is no --yes and no --force. Exit codes: 0 done or nothing to do; 1 a step failed; 2 refused',
  'before any change; 3 changes are needed but stdin is not a terminal; 4 a live step failed and pmmcp',
  'is not in its intended state; 130 interrupted before the stopped window (129, 143 by SIGHUP, SIGTERM; 130 for',
  'any of them at a question or during the jobs count). Once the window opened, a signal waits for the end report.',
  'Its last line, aos-install: exit N, is its own code: after a Ctrl-C npm may report 130 for a run it finished.',
].join('\n')

interface Flags {
  readonly dryRun: boolean
  readonly aosOnly: boolean
  readonly noInstall: boolean
  readonly pmmcpDir: string | undefined
  readonly help: boolean
}

/** The flags, or why they are refused (usage, exit 2). Each may be given once. */
function parseFlags(argv: readonly string[], cwd: string): Flags | { readonly error: string } {
  const seen = new Set<string>()
  let pmmcpDir: string | undefined
  const once = (name: string): string | undefined => {
    if (seen.has(name)) return `${name} may be given once`
    seen.add(name)
    return undefined
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? ''
    if (arg === '--dry-run' || arg === '--aos-only' || arg === '--no-install' || arg === '--help' || arg === '-h') {
      const twice = once(arg === '-h' ? '--help' : arg)
      if (twice !== undefined) return { error: twice }
      continue
    }
    let value: string | undefined
    if (arg === '--pmmcp-dir') {
      value = argv[i + 1]
      i += 1
    } else if (arg.startsWith('--pmmcp-dir=')) {
      value = arg.slice('--pmmcp-dir='.length)
    } else {
      return { error: `unknown argument ${JSON.stringify(shownLine(arg).slice(0, 80))}` }
    }
    const twice = once('--pmmcp-dir')
    if (twice !== undefined) return { error: twice }
    if (value === undefined || value === '' || value.startsWith('-')) return { error: '--pmmcp-dir needs a path' }
    pmmcpDir = resolve(cwd, value)
  }
  if (seen.has('--aos-only') && (seen.has('--pmmcp-dir') || seen.has('--no-install'))) {
    return { error: '--aos-only touches no pmmcp, so it takes neither --pmmcp-dir nor --no-install' }
  }
  return { dryRun: seen.has('--dry-run'), aosOnly: seen.has('--aos-only'), noInstall: seen.has('--no-install'), pmmcpDir, help: seen.has('--help') }
}

// ── output ──────────────────────────────────────────────────────────────────

const list = (names: readonly string[]): string => (names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names.at(-1) ?? ''}`)

// ── S3: what discovery found ────────────────────────────────────────────────

const SOURCE_LABEL: Readonly<Record<Found['install']['source'], string>> = {
  'pmmcp-dir': '--pmmcp-dir',
  plist: `the ${PLIST_LABEL} plist's WorkingDirectory`,
  listener: 'the MCP server listening on 8766',
  default: 'the default place',
}

function kernelLine(kernel: Found['kernel'], config: KernelConfig): string {
  const url = kernel.urlMatches === true ? 'matches' : kernel.urlMatches === false ? `(${kernel.url}) does not match` : 'not compared (no facts)'
  const token = kernel.tokenEnv === undefined ? 'no pmmcp tokenEnv declared' : `pmmcp tokenEnv ${kernel.tokenEnv}`
  const daemon = kernel.daemonListening ? `AOS daemon listening on ${String(config.control.port)}` : 'AOS daemon not listening'
  return `kernel     kernel.yaml url ${url}; ${token}; ${daemon}`
}

/** S3 for an install that is there: names, states, commits and paths, never a value. Exported for its test. */
export function foundScreen(f: Found, config: KernelConfig): string[] {
  const out: string[] = []
  const facts = f.facts
  out.push(`pmmcp      ${f.install.dir} (${SOURCE_LABEL[f.install.source]}), origin AiBot-Tools/persistent-memory-mcp`)
  const g = f.git
  const tracked = g.trackedChanges
  const untracked = g.untracked ?? 0
  const tree = tracked === undefined ? 'tree not read' : tracked === 0 && untracked === 0 ? 'clean' : `${String(tracked)} tracked and ${String(untracked)} untracked changes`
  const branch = facts === undefined ? '' : ` ${facts.git.branch ?? '(detached)'}`
  const missing = f.missing.length === 0 ? '' : `; missing: ${list(f.missing.map((m) => `${m.label} (${m.commit})`))}`
  const update =
    g.fastForward && g.originMain !== undefined
      ? ` (update available: ${g.originMain.slice(0, 7)}, ${g.lockUnchanged === true ? 'lockfile unchanged' : g.lockUnchanged === false ? 'uv.lock or pyproject.toml changes' : 'lockfile not compared'})`
      : ''
  out.push(`code       ${g.head === undefined ? 'HEAD not read' : g.head.slice(0, 7)}${branch} ${tree}${missing}${update}`)
  const s = f.service
  const service =
    s.loaded === undefined
      ? `${PLIST_LABEL}: whether launchd has it loaded is not known`
      : s.loaded
        ? `${PLIST_LABEL} loaded${s.state === undefined ? '' : `, ${s.state}`}${s.pid === undefined ? '' : `, pid ${String(s.pid)}`}`
        : `${PLIST_LABEL} not loaded`
  const server = f.server === undefined ? 'no MCP server on its port' : `MCP server pid ${String(f.server.pid)}${f.server.startedAfter === undefined ? '' : `, started after ${f.server.startedAfter.toISOString()}`}`
  const left = f.leftStopped === undefined ? '' : `; the last installer run that stopped it ran no start after it (${f.leftStopped.folder})`
  out.push(`service    ${service}; ${server}${left}`)
  const e = f.endpoints
  const at = facts?.config
  const health = e.health === 0 ? 'no answer' : String(e.health)
  const dash = e.dashboard === undefined ? 'dashboard disabled' : `dashboard :${String(at?.dashboard.port ?? 8765)} auth required ${e.dashboard.authRequired === undefined ? 'unknown' : e.dashboard.authRequired ? 'yes' : 'no'}`
  const curator = at === undefined ? 'curator :8767' : at.curator.enabled ? `curator ${at.curator.host}:${String(at.curator.port)}` : 'curator disabled'
  const qdrant = e.qdrant.version !== undefined ? `v${e.qdrant.version}` : e.qdrant.status === 0 ? 'no answer' : `answers ${String(e.qdrant.status)}`
  out.push(`endpoints  MCP ${at === undefined ? '127.0.0.1:8766' : `${at.server.host}:${String(at.server.port)}`} /health ${health}; ${dash}; ${curator}; Qdrant :6333 ${qdrant}`)
  const b = f.bearer
  const check =
    b.state === 'not-checked'
      ? `not checked (${b.why})`
      : b.state === 'failed'
        ? `check failed (${b.why})`
        : b.state === 'matches'
          ? 'digest matches .env'
          : b.state === 'differs'
            ? 'digest differs from .env'
            : 'absent'
  const auth = facts === undefined ? '' : `http_auth.yaml ${facts.http_auth.state}${facts.http_auth.mode === null ? '' : `, mode ${facts.http_auth.mode}`}, tokens [${facts.http_auth.tokens.join(', ')}]; `
  out.push(`bearer     ${auth}aos-kernel ${check}`)
  const q = f.qdrant
  out.push(`qdrant     ${q === undefined ? 'status not read' : `key file ${q.key_file.state}; verdict ${q.verdict}${q.prekey_kept ? '; pmmcp-qdrant-prekey kept' : ''}`}`)
  out.push(
    `dashboard  ${facts === undefined ? 'not read (no facts)' : `token ${facts.dashboard_token.state}; curator secret ${facts.curator_secret.state}; config.yaml ${facts.config.dashboard.legacy_token_key ? 'has' : 'has no'} dashboard.token`}`,
  )
  const j = f.jobs
  out.push(`jobs       ${j.state === 'counted' ? (j.jobs.running === 'unknown' ? 'unknown' : `${String(j.jobs.running)} running`) : j.state === 'not-run' ? `not counted: ${j.why}` : `count failed: ${j.why}`}`)
  out.push(kernelLine(f.kernel, config))
  return out
}

function absentScreen(a: Absent, config: KernelConfig): string[] {
  return [`pmmcp      not found (looked at ${list(a.searched)}): a fresh install would clone it to ${a.at}`, kernelLine(a.kernel, config)]
}

// ── the run ─────────────────────────────────────────────────────────────────

function readYaml(path: string): unknown {
  return parseYaml(readFileSync(path, 'utf8'))
}

/** Whether the outcome followed a phase that ran (or failed): the end report is printed then, and only then. Exported for its test. */
export const ranAPhase = (outcome: GateOutcome): boolean =>
  outcome.kind === 'failed' || outcome.kind === 'done' || ((outcome.kind === 'declined' || outcome.kind === 'aborted') && outcome.applied.length > 0)

/**
 * The outcome once the applier's recheck before the report ran: a leak
 * there (`leaked`, the exit code it implies) ends a failed phase with that
 * code when it is the worse, as a leak inside the phase would have. recheck
 * reads only after a phase that ended inside the window, so a failed one;
 * any other outcome is left as it is. Exported for its test.
 */
export const afterRecheck = (outcome: GateOutcome, leaked: 1 | 4 | undefined): GateOutcome =>
  leaked !== undefined && outcome.kind === 'failed' && leaked > outcome.exitCode ? { ...outcome, exitCode: leaked } : outcome

/**
 * What a throw from discovery or the TUI check ends the run with: a probe
 * the runner's rules refused for the machine's state (InstallRunError.
 * machine: a file on the child's PATH, an argument's file or pmmcp's own
 * script that is the stop or start script by link or identity, a link to a
 * program never run here, the log folder's owner or mode: plan §5's failure
 * table) is a refusal before any change, exit 2, its message naming the
 * file and the fix; any other refusal of the runner's (a bad step name,
 * arguments off the allowlist, a timeout on a step in its own session) only
 * an installer defect makes, and stops it before any change, exit 1, said
 * as a defect; so do a leak or a halted runner (a registered value reached a
 * child's output) and discovery's own defect (exit 1, never 2: nothing of
 * the machine's was refused); anything else is undefined here, and main
 * throws it on (a defect of its own). Exported for its test.
 */
export function stoppedBy(e: unknown): { readonly line: string; readonly ending: Ending } | undefined {
  if (e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_REFUSED') {
    if (e.machine) return { line: `refused before any change: ${e.message}`, ending: refusedEnding() }
    return { line: `stopped by a defect (report it): the runner refused a probe the installer asked for: ${e.message}`, ending: stoppedEnding() }
  }
  if (e instanceof InstallRunError && (e.code === 'AOS_INSTALL_RUN_LEAK' || e.code === 'AOS_INSTALL_RUN_HALTED')) return { line: `stopped: ${e.message}`, ending: stoppedEnding() }
  if (e instanceof DiscoverError) return { line: `discovery failed (a defect, report it): ${e.message}`, ending: stoppedEnding() }
  return undefined
}

/** What main shares with the signal handlers and the end of the run. */
interface RunState {
  terminal: Terminal | undefined
  windowOpen: boolean
  windowOpened: boolean
  /** From the window's first opening until the end report is printed (signals.ts windowChanged). */
  reporting: boolean
  counting: boolean
  readonly interrupt: AbortController
  pmmcpDir: string | undefined
  /** The signal handled last, so the same one delivered twice is not read twice. */
  last: { readonly signal: HandledSignal; readonly at: number } | undefined
  /** The signals the window trapped. */
  readonly trapped: Set<HandledSignal>
  /** The signals held after the window until the end report. */
  readonly held: Set<HandledSignal>
  /** The run's log folder, once a child made it. */
  logs: () => string | undefined
  /** Once the flags were taken (not --help, not a usage error): the run ends with its exit line. */
  exitLine: boolean
}

/** A usage error or --help: no run, so no exit line. */
const noRun = (code: 0 | 2): Ending => ({ code, why: '' })

async function main(argv: readonly string[], state: RunState, out: Output): Promise<Ending> {
  const root = REPO_ROOT
  const say = (line: string): void => out.say(line)
  // A flag npm took before `--` never reached argv: whatever is left would run without it.
  const taken = npmTookFlags(process.env)
  if (taken.length > 0) {
    out.raw(
      'stderr',
      `${shownLine(`npm took ${list(taken)} as its own option${taken.length > 1 ? 's' : ''}, so the installer was not given ${taken.length > 1 ? 'them' : 'it'}: ` +
        "put the installer's flags after --, as in npm run aos-install -- --dry-run")}\n\n${USAGE}\n`,
    )
    return noRun(2)
  }
  const flags = parseFlags(argv, process.cwd())
  if ('error' in flags) {
    out.raw('stderr', `${shownLine(flags.error)}\n\n${USAGE}\n`)
    return noRun(2)
  }
  if (flags.help) {
    out.raw('stdout', `${USAGE}\n`)
    return noRun(0)
  }
  state.exitLine = true

  // S1
  const home = process.env['HOME']
  const pre = preflight({ aosOnly: flags.aosOnly, root, home, env: process.env })
  for (const line of pre.lines) say(line)
  if (pre.refusals.length > 0 || home === undefined) {
    say('refused before any change:')
    for (const r of pre.refusals) say(`  - ${r}`)
    return refusedEnding()
  }

  const runner = new Runner({ repoRoot: root })
  state.logs = () => runner.dir
  const lock = await takeLock({ root, print: say, startOf: startWithPs(runner, root) })
  if (typeof lock === 'string') {
    say(`refused before any change: ${lock}`)
    return refusedEnding()
  }
  process.once('exit', () => lock.release())

  let config: KernelConfig
  let providers: ProvidersFile
  try {
    config = parseKernelConfig(readYaml(join(root, 'config', 'kernel.yaml')), { repoRoot: root })
    providers = parseProviders(readYaml(join(root, 'config', 'providers.yaml')))
  } catch (e) {
    say(`refused before any change: the config cannot be read: ${e instanceof Error ? e.message : String(e)}`)
    return refusedEnding()
  }

  // S2: names, lines and states only; the writer's inspection reads .env without opening it for writing.
  const accepted = credentialNames(config, providers)
  const mapped = [...credentialsMap(config).keys()]
  const shown = [...mapped, ...[...accepted].filter((n) => !mapped.includes(n))]
  let screen: InspectResult
  let room: InspectResult
  // The tokens the installer mints are judged for a write an earlier run did not finish: one cut short is refused, never staged.
  const minted = mintedCredentialNames(config)
  try {
    screen = inspectCredentials({ repoRoot: root, accepted, names: shown, minted })
    room = inspectCredentials({ repoRoot: root, accepted, names: mapped, minted })
  } catch (e) {
    if (!(e instanceof DotenvWriteError) && !(e instanceof ConfigError)) throw e
    say(`refused before any change: ${e.message}`)
    return refusedEnding()
  }
  const exported = exportedNames(process.env, accepted)

  let discovery: Found | Absent | undefined
  // undefined when pgrep could not say: the warning then says so, never that none runs.
  let tui: readonly number[] | undefined = []
  // S3's screen: the gate prints it after S2's, as plan §5 orders them.
  const s3: string[] = []
  if (!flags.aosOnly) {
    // S3
    let found: Awaited<ReturnType<typeof discover>>
    try {
      found = await discover({ repoRoot: root, home, runner, config, providers, print: say, ...(flags.pmmcpDir === undefined ? {} : { pmmcpDir: flags.pmmcpDir }) })
    } catch (e) {
      const stopped = stoppedBy(e)
      if (stopped === undefined) throw e
      say(stopped.line)
      return stopped.ending
    }
    if (found.kind === 'stopped') {
      if (found.install !== undefined) say(`pmmcp      ${found.install.dir} (${SOURCE_LABEL[found.install.source]})`)
      say('refused before any change:')
      for (const stop of found.stops) say(`  - ${stop.message}`)
      return refusedEnding()
    }
    discovery = found
    const notes = [...found.notes]
    if (found.kind === 'found') {
      state.pmmcpDir = found.install.dir
      let pids: readonly number[] | undefined
      try {
        pids = await tuiPids(runner, found.install.dir)
      } catch (e) {
        // tuiPids throws a leak, a halt or the runner's refusal (of the machine's state, or a defect): any other failure of pgrep is no answer.
        const stopped = stoppedBy(e)
        if (stopped === undefined) throw e
        say(stopped.line)
        return stopped.ending
      }
      if (pids === undefined) notes.push('whether a scripts/monitor_tui.py runs cannot be told (pgrep gave no answer): the installer checks again before it makes a curator secret')
      tui = pids
    } else {
      state.pmmcpDir = found.at
    }
    s3.push(...(found.kind === 'found' ? foundScreen(found, config) : absentScreen(found, config)))
    if (notes.length > 0) s3.push('discovery notes:', ...notes.map((note) => `  - ${note}`))
  }

  // S4 on
  const plan = planInstall({
    config,
    providers,
    dotenv: screen,
    room,
    exported,
    pmmcp: discovery,
    tuiPids: tui,
    options: { aosOnly: flags.aosOnly, noInstall: flags.noInstall },
  })
  const terminal = new Terminal({
    input: process.stdin,
    output: process.stdout,
    interactive: process.stdin.isTTY === true,
    raw: process.stdin.isTTY === true && process.stdout.isTTY === true,
    outputWorks: () => out.stdoutWorks,
    print: say,
  })
  state.terminal = terminal
  const applier = new Applier({
    repoRoot: root,
    home,
    runner,
    config,
    providers,
    plan,
    discovery,
    print: say,
    ask: (question) => terminal.ask(question),
    window: (open) => windowChanged(state, open),
    interrupt: state.interrupt.signal,
  })
  const io: GateIO = {
    interactive: terminal.interactive,
    print: say,
    ask: (question) => terminal.ask(question),
    countJobs: async (): Promise<JobsAnswer> => {
      state.counting = true
      try {
        return await applier.countJobs()
      } finally {
        state.counting = false
      }
    },
    pause: (ms) => terminal.pause(ms),
    apply: (phase, steps) => applier.apply(phase, steps),
  }
  const outcome = await runGate(plan, io, { dryRun: flags.dryRun, discovery: s3, ...(runner.dir === undefined ? {} : { logs: runner.dir }) })
  const reported = ranAPhase(outcome)
  let ended = outcome
  if (reported) {
    // What the report says of pmmcp is read again first when the window opened (a signal is held until the report is out); a leak there is reported in it.
    ended = afterRecheck(outcome, await applier.recheck())
    for (const line of applier.report()) say(line)
  }
  // The report is out: what a held signal waited for is said.
  state.reporting = false
  return outcomeEnding(ended, reported)
}

/**
 * The end of every run: what the window trapped, said once more; once
 * output was lost, the transcript kept in the run's log folder; then exit
 * once what is queued on stdout and stderr is handed on (process.exit alone
 * can cut a pipe's last lines on macOS).
 */
function finish(out: Output, state: RunState, ending: Ending): void {
  if (finishing) return
  finishing = true
  const code = ending.code
  if (state.trapped.size > 0) {
    out.say(`${list([...state.trapped].map(signalWords))} came while pmmcp was stopped; the installer went on to the start and its checks, as reported above`)
  }
  if (state.held.size > 0) {
    out.say(`${list([...state.held].map(signalWords))} came after the stopped window; the installer finished its checks and printed the end report above first`)
  }
  if (state.exitLine) out.say(exitLine(ending))
  const kept = out.keep(state.logs(), code)
  if (kept !== undefined) out.warn(`the installer's output went away (${out.lost?.code ?? 'unknown'}) during the run; what it said is in ${kept}`)
  out.flush(() => process.exit(code))
}
let finishing = false

// Only when run as the entry point, so importing this module runs nothing.
// Compared as resolved paths rather than by suffix.
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  // First: an 'error' on stdout or stderr that nothing listens for would end the run there and then.
  const out = new Output(process.stdout, process.stderr)
  const state: RunState = {
    terminal: undefined,
    windowOpen: false,
    windowOpened: false,
    reporting: false,
    counting: false,
    interrupt: new AbortController(),
    pmmcpDir: undefined,
    last: undefined,
    trapped: new Set(),
    held: new Set(),
    logs: () => undefined,
    exitLine: false,
  }
  // A read error on stdin (EIO once the terminal is gone) ends the question it was read for (the terminal's), never the run.
  process.stdin.on('error', () => undefined)
  for (const signal of HANDLED_SIGNALS) {
    process.on(signal, () => {
      // The last line is printed (or being handed on): nothing is said after it.
      if (finishing) return
      handleSignal(state, signal, Date.now(), {
        promptOpen: () => state.terminal?.promptOpen === true,
        answer: () => state.terminal?.interrupt(),
        trapped: (s) => out.say(`${signalWords(s)} does not interrupt the stopped window: its steps run in sessions of their own. It is finishing; wait for the start and its checks.`),
        held: (s) =>
          out.say(`${signalWords(s)} does not end the run yet: the stopped window opened in this run, so the installer finishes its last checks and prints the end report (what was done, and what is left to do) first.`),
        abortCount: () => state.interrupt.abort(),
        exit: (code, s) => {
          // The same words as the last line's: the two match.
          out.say(signalEnded(s))
          finish(out, state, signalEnding(code, s))
        },
      })
    })
  }
  main(process.argv.slice(2), state, out)
    .then((ending) => finish(out, state, ending))
    .catch((e: unknown) => {
      out.warn(`npm run aos-install failed (a defect, report it): ${e instanceof Error ? e.message : String(e)}`)
      if (state.windowOpened && state.pmmcpDir !== undefined) {
        out.warn(`pmmcp may be stopped: start it with cd ${shellWord(state.pmmcpDir)} && ./start-pmmcp-server.sh`)
      }
      finish(out, state, defectEnding(defectExit(state.windowOpened)))
    })
}
