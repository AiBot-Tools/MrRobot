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
//     S3, discovery, unless --aos-only: a stop (exit 2), or the screen of what
//       was found (or not) and discovery's notes, which the gate prints after
//       S2's (plan §5's order); for a found install the pids of every running
//       scripts/monitor_tui.py (the planner lists them, and the applier
//       checks again before a curator secret is made).
//     S4 on: the plan (planInstall) walked by the gate (runGate) with the
//       applier as its apply and jobs count, and, once a phase was applied or
//       failed, the applier's end report (S8).
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
//   reaches them. While pmmcp's jobs are counted it ends the count (the gate
//   then ends the run, 130). Anywhere else it ends the run at once, with 130,
//   129 or 143 (outside the window nothing is half done that a re-run does
//   not pick up from the state on disk).
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
//   Exit codes (plan §5): 0 done, or nothing to do, or a dry run; 1 a step
//   failed and the state is as reported (also a leak, or an installer defect,
//   before the window opened); 2 refused before any change; 3 changes are
//   needed but stdin is not a terminal; 4 a live step failed and pmmcp is not
//   in its intended state (also a defect once the window had opened); 130
//   interrupted outside the window (129 and 143 for SIGHUP and SIGTERM).

import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { ConfigError } from '../src/errors.js'
import { runGate, type GateIO, type GateOutcome, type JobsAnswer } from '../src/install/gate.js'
import { credentialsMap, exportedNames, planInstall, shellWord } from '../src/install/plan.js'
import { parseProviders, type ProvidersFile } from '../src/models/registry.js'
import { DotenvWriteError, credentialNames, inspectCredentials, type InspectResult } from '../src/secrets/dotenv-append.js'
import { Applier, tuiPids } from './install/apply.js'
import { DiscoverError, PLIST_LABEL, discover, type Absent, type Found } from './install/discover.js'
import { startWithPs, takeLock } from './install/lock.js'
import { Output } from './install/output.js'
import { npmTookFlags, preflight } from './install/preflight.js'
import { InstallRunError, Runner, shownLine } from './install/run.js'
import { HANDLED_SIGNALS, defectExit, handleSignal, signalWords, type HandledSignal } from './install/signals.js'
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
  'is not in its intended state; 130 interrupted outside the stopped window (129, 143 by SIGHUP, SIGTERM).',
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

/** S3 for an install that is there: names, states, commits and paths, never a value. */
function foundScreen(f: Found, config: KernelConfig): string[] {
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
  const service = s.loaded ? `${PLIST_LABEL} loaded${s.state === undefined ? '' : `, ${s.state}`}${s.pid === undefined ? '' : `, pid ${String(s.pid)}`}` : `${PLIST_LABEL} not loaded`
  const server = f.server === undefined ? 'no MCP server on its port' : `MCP server pid ${String(f.server.pid)}${f.server.startedAfter === undefined ? '' : `, started after ${f.server.startedAfter.toISOString()}`}`
  out.push(`service    ${service}; ${server}`)
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

/** Whether the outcome followed a phase that ran (or failed): the end report is printed then. */
const ranAPhase = (outcome: GateOutcome): boolean =>
  outcome.kind === 'failed' || outcome.kind === 'done' || ((outcome.kind === 'declined' || outcome.kind === 'aborted') && outcome.applied.length > 0)

/** What main shares with the signal handlers and the end of the run. */
interface RunState {
  terminal: Terminal | undefined
  windowOpen: boolean
  windowOpened: boolean
  counting: boolean
  readonly interrupt: AbortController
  pmmcpDir: string | undefined
  /** The signal handled last, so the same one delivered twice is not read twice. */
  last: { readonly signal: HandledSignal; readonly at: number } | undefined
  /** The signals the window trapped. */
  readonly trapped: Set<HandledSignal>
  /** The run's log folder, once a child made it. */
  logs: () => string | undefined
}

async function main(argv: readonly string[], state: RunState, out: Output): Promise<number> {
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
    return 2
  }
  const flags = parseFlags(argv, process.cwd())
  if ('error' in flags) {
    out.raw('stderr', `${shownLine(flags.error)}\n\n${USAGE}\n`)
    return 2
  }
  if (flags.help) {
    out.raw('stdout', `${USAGE}\n`)
    return 0
  }

  // S1
  const home = process.env['HOME']
  const pre = preflight({ aosOnly: flags.aosOnly, root, home, env: process.env })
  for (const line of pre.lines) say(line)
  if (pre.refusals.length > 0 || home === undefined) {
    say('refused before any change:')
    for (const r of pre.refusals) say(`  - ${r}`)
    return 2
  }

  const runner = new Runner({ repoRoot: root })
  state.logs = () => runner.dir
  const lock = await takeLock({ root, print: say, startOf: startWithPs(runner, root) })
  if (typeof lock === 'string') {
    say(`refused before any change: ${lock}`)
    return 2
  }
  process.once('exit', () => lock.release())

  let config: KernelConfig
  let providers: ProvidersFile
  try {
    config = parseKernelConfig(readYaml(join(root, 'config', 'kernel.yaml')), { repoRoot: root })
    providers = parseProviders(readYaml(join(root, 'config', 'providers.yaml')))
  } catch (e) {
    say(`refused before any change: the config cannot be read: ${e instanceof Error ? e.message : String(e)}`)
    return 2
  }

  // S2: names, lines and states only; the writer's inspection reads .env without opening it for writing.
  const accepted = credentialNames(config, providers)
  const mapped = [...credentialsMap(config).keys()]
  const shown = [...mapped, ...[...accepted].filter((n) => !mapped.includes(n))]
  let screen: InspectResult
  let room: InspectResult
  try {
    screen = inspectCredentials({ repoRoot: root, accepted, names: shown })
    room = inspectCredentials({ repoRoot: root, accepted, names: mapped })
  } catch (e) {
    if (!(e instanceof DotenvWriteError) && !(e instanceof ConfigError)) throw e
    say(`refused before any change: ${e.message}`)
    return 2
  }
  const exported = exportedNames(process.env, accepted)

  let discovery: Found | Absent | undefined
  let tui: readonly number[] = []
  // S3's screen: the gate prints it after S2's, as plan §5 orders them.
  const s3: string[] = []
  if (!flags.aosOnly) {
    // S3
    let found: Awaited<ReturnType<typeof discover>>
    try {
      found = await discover({ repoRoot: root, home, runner, config, providers, ...(flags.pmmcpDir === undefined ? {} : { pmmcpDir: flags.pmmcpDir }) })
    } catch (e) {
      if (e instanceof InstallRunError && (e.code === 'AOS_INSTALL_RUN_LEAK' || e.code === 'AOS_INSTALL_RUN_HALTED')) {
        say(`stopped: ${e.message}`)
        return 1
      }
      if (e instanceof DiscoverError) {
        say(`discovery failed (a defect, report it): ${e.message}`)
        return 1
      }
      throw e
    }
    if (found.kind === 'stopped') {
      if (found.install !== undefined) say(`pmmcp      ${found.install.dir} (${SOURCE_LABEL[found.install.source]})`)
      say('refused before any change:')
      for (const stop of found.stops) say(`  - ${stop.message}`)
      return 2
    }
    discovery = found
    const notes = [...found.notes]
    if (found.kind === 'found') {
      state.pmmcpDir = found.install.dir
      let pids: readonly number[] | undefined
      try {
        pids = await tuiPids(runner, found.install.dir)
      } catch (e) {
        if (e instanceof InstallRunError) {
          say(`stopped: ${e.message}`)
          return 1
        }
        throw e
      }
      if (pids === undefined) notes.push('whether a scripts/monitor_tui.py runs cannot be told (pgrep gave no answer): the installer checks again before it makes a curator secret')
      tui = pids ?? []
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
    window: (open) => {
      state.windowOpen = open
      if (open) state.windowOpened = true
    },
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
  if (ranAPhase(outcome)) for (const line of applier.report()) say(line)
  return outcome.exitCode
}

/**
 * The end of every run: what the window trapped, said once more; once
 * output was lost, the transcript kept in the run's log folder; then exit
 * once what is queued on stdout and stderr is handed on (process.exit alone
 * can cut a pipe's last lines on macOS).
 */
function finish(out: Output, state: RunState, code: number): void {
  if (finishing) return
  finishing = true
  if (state.trapped.size > 0) {
    out.say(`${list([...state.trapped].map(signalWords))} came while pmmcp was stopped; the installer went on to the start and its checks, as reported above`)
  }
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
    counting: false,
    interrupt: new AbortController(),
    pmmcpDir: undefined,
    last: undefined,
    trapped: new Set(),
    logs: () => undefined,
  }
  // A read error on stdin (EIO once the terminal is gone) ends the question it was read for (the terminal's), never the run.
  process.stdin.on('error', () => undefined)
  for (const signal of HANDLED_SIGNALS) {
    process.on(signal, () => {
      handleSignal(state, signal, Date.now(), {
        promptOpen: () => state.terminal?.promptOpen === true,
        answer: () => state.terminal?.interrupt(),
        trapped: (s) => out.say(`${signalWords(s)} does not interrupt the stopped window: its steps run in sessions of their own. It is finishing; wait for the start and its checks.`),
        abortCount: () => state.interrupt.abort(),
        exit: (code, s) => {
          out.say(s === 'SIGINT' ? 'interrupted: nothing more is done' : `ended by ${s}: nothing more is done`)
          finish(out, state, code)
        },
      })
    })
  }
  main(process.argv.slice(2), state, out)
    .then((code) => finish(out, state, code))
    .catch((e: unknown) => {
      out.warn(`npm run aos-install failed (a defect, report it): ${e instanceof Error ? e.message : String(e)}`)
      if (state.windowOpened && state.pmmcpDir !== undefined) {
        out.warn(`pmmcp may be stopped: start it with cd ${shellWord(state.pmmcpDir)} && ./start-pmmcp-server.sh`)
      }
      finish(out, state, defectExit(state.windowOpened))
    })
}
