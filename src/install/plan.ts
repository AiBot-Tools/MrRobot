// The installer's planner: from what .env holds and what discovery found,
// the ordered steps `npm run aos-install` would take, each tagged by what it
// touches, and the questions it would ask before the live ones.
//
// CONTRACT
//
//   Who calls it: the installer (scripts/install.ts), after its preflight,
//   the .env screen and discovery (scripts/install/discover.ts), and then the
//   confirmation gate (src/install/gate.ts) with the plan it returns. Pure: no
//   I/O, no process, no clock, no randomness, nothing kept. The kernel, the
//   daemon, the CLI and eval never import src/install (hygiene.test.ts). It
//   never sees a credential value: .env reaches it as names, line numbers and
//   states (inspectCredentials' result), the shell as the names it exports
//   with a value that is not blank (exportedNames), pmmcp as discovery's
//   result, and a running scripts/monitor_tui.py of the checkout as its pids.
//   What it returns is names, paths, commands and reasons. Every path in a
//   command or a rollback is a shell word (shellWord), so a line the
//   operator pastes runs what it says under a folder whose name holds a
//   space or a quote.
//
//   The tags. `aos-file`: <repo>/.env, through the one writer
//   (src/secrets/dotenv-append.ts). `pmmcp-file`: a file under
//   ~/.persistent-memory-mcp that the running server loads only at its next
//   start (the aos-kernel digest in http_auth.yaml). `pmmcp-docker`: a
//   stopped container the running service does not use (the
//   pmmcp-qdrant-prekey a cutover kept, which qdrant_api_key.py cleanup
//   removes, never a volume); applied with the non-live steps. `live`: a
//   change to the running pmmcp, inside one stopped window (the graceful
//   stop, the fast-forward, the Qdrant cutover, the dashboard token and
//   curator secret, which pmmcp reads per request, the start and its
//   checks). `fresh-install`: the clone, setup.sh, the Qdrant key file and
//   the aos-kernel digest made before the first start, and the first stop and
//   start of a pmmcp that was not installed (plan Q24: the one typed
//   `install` covers them).
//
//   The credentials map (credentialsMap) is the config's alone:
//   control.tokenEnv, the control plane's bearer, and pmmcp's tokenEnv once
//   kernel.yaml declares one, mapped to pmmcp's client aos-kernel. K3 replaces
//   only that function. What the writer is asked to generate (Plan.generate,
//   generatorsFor) is the names of that map that hold no line in .env and that
//   the shell does not export, never inspectCredentials' `missing`, which
//   holds the provider keys too: those, ANTHROPIC_API_KEY first, are the
//   operator's to add, and a name of the map that is a provider's key is
//   refused. A name that holds a line is never generated again, so a present
//   token is never replaced: only its digest is staged.
//
//   What stops the plan (Plan.stops: refused before any change, exit 2): a
//   map name on a line with no value (the writer never appends a name that
//   holds a line); a map name the shell exports while .env lacks it (the
//   export would win at boot, so an appended line would go unused); pmmcp's
//   token set in .env while the shell exports it too (the kernel started
//   from that shell sends the export, not the value whose digest pmmcp is
//   given; the control token in that state is only noted, since nothing is
//   appended or staged for it: plan Q26); a .env the writer could not append
//   to or create, or that would outgrow 64 KiB; a pmmcp tokenEnv that is the
//   control plane's own or a provider's key; and an aos-kernel check
//   discovery could not make.
//
//   What is offered (Plan.offers, asked by the gate, default no), each only
//   from what the facts show: the Qdrant cutover, for an existing container
//   that asks for no key and with no pmmcp-qdrant-prekey kept; the kept
//   prekey's cleanup once Qdrant enforces the key (not live), and only in a
//   run that asks or does something else anyway: on its own it is a note
//   that gives its command, and the run has nothing to do; the dashboard
//   token and the curator secret, each only where pmmcp's code takes it
//   safely (the token with dashboard_auth and stop_listener_check, the
//   secret with curator_secret and curator_proof as well, and the curator on
//   127.0.0.1:8767 or disabled: older code hands either one to whatever
//   answers on its port once the service is down), and, where this code
//   does not take one, "if the updated pmmcp supports them" behind this
//   run's update (L4 then re-reads the facts); the fast-forward to the local
//   origin/main, only on a clean tree whose uv.lock and pyproject.toml it
//   leaves alone, and only when something else needs pmmcp changed or the
//   checkout lacks a feature; one restart when a digest is staged now, or
//   is on file but the running MCP server cannot be shown to have started
//   after http_auth.yaml last changed; and the start, when pmmcp is stopped
//   with launchd's service unloaded and discovery found that the last
//   installer run that stopped it ran no start after it (killed or crashed
//   inside the window, or a stop that did not stop and no start after it:
//   Found.leftStopped). Every live item opens the same window:
//   one graceful stop, the chosen changes, one start and its checks, so two
//   items still make one restart; when pmmcp's MCP server is not running,
//   the window still runs the stop (for whatever else of pmmcp runs) and
//   ends by starting pmmcp, which the plan says at S4, in the start step and
//   in the warning. Nothing live is offered unless the jobs check can run
//   (Plan.jobsGate): with features.stop_jobs_flag (an older stop script runs
//   a full stop on --jobs), without features.stop_listener_check only while
//   no dashboard token is present (that stop script hands it to whatever
//   listens on 8765), and only when discovery's own --jobs did not fail or
//   answer unknown. Enforce mode is never offered (the operator's later
//   step).
//
//   Plan.blocked holds the notes that say something the installer makes is
//   not in place and this run cannot make it (a digest not staged, a file
//   that is unusable, an item that needs pmmcp updated by hand first, an item
//   the jobs check keeps from being offered, a checkout with no facts, whose
//   Qdrant key, dashboard token and curator secret cannot be read at all):
//   with nothing to do, the gate says so rather than that everything is in
//   place.

import { dirname } from 'node:path'

import type { KernelConfig } from '../config.js'
import { KernelError } from '../errors.js'
import type { ProvidersFile } from '../models/registry.js'
import { FACTS_COMMIT, FEATURE_COMMITS, FEATURE_LABELS, type Facts, type FeatureName, type MissingFeature, type QdrantStatus } from './facts.js'

/** pmmcp's client name for the AOS kernel's bearer in http_auth.yaml. */
export const PMMCP_CLIENT = 'aos-kernel'

/** The folder an install has on disk, which the second confirmation types. */
export const PMMCP_FOLDER = 'Persistent-Memory-MCP'

/** The start offered for a pmmcp left stopped: said as the run folders show it, never what was done by hand since. */
export const START_QUESTION = 'Start pmmcp (stopped now; the last installer run that stopped it ran no start after it)? [y/N]'

/** What the gate says, in place of asking, for an offer the window of the changes accepted above already carries out. */
export function impliedAnswer(offer: Pick<Offer, 'id'>): string {
  return offer.id === 'start' ? 'yes, the window the changes above open ends by starting pmmcp' : 'yes, by the changes above, which restart pmmcp once'
}

/** The MCP server whose tokenEnv the credentials map gives a pmmcp client. */
const PMMCP_SERVER = 'pmmcp'

/** The provider key the created .env tells the operator to add: never generated, by name. */
const OPERATORS_KEY = 'ANTHROPIC_API_KEY'

/** How many characters each generated token has: 32 random bytes as hex (GENERATED_LENGTH in the writer). */
const TOKEN_HEX = 64

/** Where the curator must serve once a curator secret exists (pmmcp's CURATOR_ADDRESS). */
const CURATOR_HOST = '127.0.0.1'
const CURATOR_PORT = 8767

/** A caller that hands the planner less than it needs: a defect, never a finding. */
export class PlanError extends KernelError {
  constructor(message: string) {
    super('AOS_INSTALL_PLAN', message)
  }
}

/**
 * A word as a POSIX shell reads it back: bare when it holds nothing the
 * shell treats specially, else in single quotes with each ' as '\''.
 */
export function shellWord(word: string): string {
  return /^[\w@%+=:,./-]+$/.test(word) ? word : `'${word.replace(/'/g, "'\\''")}'`
}

/** A file of the checkout, as one shell word. */
const inDir = (dir: string, rel: string): string => shellWord(`${dir}/${rel}`)

/** The checkout's own Python, as one shell word. */
const python = (dir: string): string => inDir(dir, '.venv/bin/python')

/** `cd <dir> && <command>`, for a line the operator pastes. */
const within = (dir: string, command: string): string => `cd ${shellWord(dir)} && ${command}`

// ── the credentials map ───────────────────────────────────────────────────

/** A token the AOS mints itself, and the pmmcp client its digest is staged as. */
export interface Credential {
  readonly name: string
  /** The config field that names it. */
  readonly from: 'control.tokenEnv' | 'mcp.servers.pmmcp.tokenEnv'
  /** pmmcp's client for it (aos-kernel), whose digest is staged; undefined for the control plane's bearer. */
  readonly client: string | undefined
}

/**
 * The tokens the installer makes, from the config alone: control.tokenEnv,
 * and pmmcp's tokenEnv, once declared, as client aos-kernel. Never another
 * MCP server's tokenEnv (a credential its service issues), never a provider
 * key. When pmmcp's tokenEnv repeats control.tokenEnv the first entry stands
 * (the planner refuses that config).
 */
export function credentialsMap(config: Pick<KernelConfig, 'control' | 'mcp'>): ReadonlyMap<string, Credential> {
  const map = new Map<string, Credential>()
  map.set(config.control.tokenEnv, { name: config.control.tokenEnv, from: 'control.tokenEnv', client: undefined })
  const pmmcp = config.mcp.servers[PMMCP_SERVER]?.tokenEnv
  if (pmmcp !== undefined && !map.has(pmmcp)) map.set(pmmcp, { name: pmmcp, from: 'mcp.servers.pmmcp.tokenEnv', client: PMMCP_CLIENT })
  return map
}

/**
 * The map appendCredentials is handed as `generate`: the plan's `generate`
 * names, each made by `mint` (the installer's crypto.randomBytes(32) as hex),
 * and nothing else.
 */
export function generatorsFor(plan: Pick<Plan, 'generate'>, mint: () => string): ReadonlyMap<string, () => string> {
  return new Map(plan.generate.map((name) => [name, mint]))
}

/**
 * The names in `names` that `env` sets to something not blank, as the
 * loader's credentialEnv counts a shell export that wins at boot. Names only:
 * no value is kept or returned.
 */
export function exportedNames(env: Readonly<Record<string, string | undefined>>, names: Iterable<string>): ReadonlySet<string> {
  const out = new Set<string>()
  for (const name of names) {
    const value = env[name]
    if (value !== undefined && value.trim() !== '') out.add(name)
  }
  return out
}

// ── what the planner is handed ────────────────────────────────────────────

/** A name and the line it holds in .env (from 1), as the writer reports it. */
export interface NameLine {
  readonly name: string
  readonly line: number
}

/** .env as inspectCredentials describes it: names and lines, never values. */
export interface DotenvView {
  readonly path: string
  readonly found: boolean
  readonly present: readonly NameLine[]
  readonly blank: readonly NameLine[]
  readonly missing: readonly string[]
}

/** What the write would meet, from inspectCredentials over the credentials map's names alone (its `fits` counts every missing name it is given). */
export interface DotenvRoom {
  readonly writable: boolean
  readonly fits: boolean
}

/** Discovery's own `stop-pmmcp-server.sh --jobs` (scripts/install/discover.ts JobsState). */
export type FoundJobs =
  | { readonly state: 'counted'; readonly jobs: { readonly running: number; readonly display: readonly string[] } | { readonly running: 'unknown' } }
  | { readonly state: 'not-run'; readonly why: string }
  | { readonly state: 'failed'; readonly why: string; readonly stderr: readonly string[] }

/** AOS providers on one of pmmcp's Ollama ports, which pmmcp's stop script stops (discovery's KernelSide). */
export interface OllamaShared {
  readonly ollamaShared: readonly { readonly ref: string; readonly port: number }[]
}

/** Discovery's `found`, as far as the planner reads it (scripts/install/discover.ts Found passes as it is). */
export interface PmmcpFound {
  readonly kind: 'found'
  readonly install: { readonly dir: string }
  readonly facts: Facts | undefined
  readonly features: Readonly<Record<FeatureName, boolean>>
  readonly missing: readonly MissingFeature[]
  readonly git: {
    readonly head: string | undefined
    readonly originMain: string | undefined
    readonly fastForward: boolean
    readonly lockUnchanged: boolean | undefined
    readonly trackedChanges: number | undefined
    readonly untracked: number | undefined
  }
  readonly server: { readonly pid: number; readonly startedAfter: Date | undefined } | undefined
  /** pmmcp is stopped with launchd's service unloaded, and the last installer run that stopped it ran no start after it (its run folder): the start is offered. */
  readonly leftStopped: { readonly folder: string } | undefined
  readonly httpAuthModified: Date | undefined
  readonly qdrant: QdrantStatus | undefined
  readonly jobs: FoundJobs
  readonly bearer:
    | { readonly state: 'matches' | 'differs' | 'absent' }
    | { readonly state: 'not-checked'; readonly why: string }
    | { readonly state: 'failed'; readonly why: string; readonly stderr: readonly string[] }
  readonly kernel: OllamaShared
}

/** Discovery's `absent`: no pmmcp anywhere it looked (scripts/install/discover.ts Absent passes as it is). */
export interface PmmcpAbsent {
  readonly kind: 'absent'
  /** Where the installer would clone it. */
  readonly at: string
  readonly searched: readonly string[]
  readonly kernel: OllamaShared
}

export interface PlanOptions {
  /** --aos-only: .env only, pmmcp is never touched. */
  readonly aosOnly: boolean
  /** --no-install: never offer the clone and setup.sh. */
  readonly noInstall: boolean
}

export interface PlanInput {
  /** kernel.yaml as the installer loaded it: control.tokenEnv and mcp.servers. */
  readonly config: Pick<KernelConfig, 'control' | 'mcp'>
  /** providers.yaml as loaded: no entry's auth.envVar is ever generated. */
  readonly providers: Pick<ProvidersFile, 'entries'>
  /** inspectCredentials over every name the screen shows, the credentials map's included. */
  readonly dotenv: DotenvView
  /** writable and fits from inspectCredentials over the credentials map's names alone. */
  readonly room: DotenvRoom
  /** The names the installer's shell exports with a value that is not blank (exportedNames). */
  readonly exported: ReadonlySet<string>
  /** What discovery found; undefined only with --aos-only. */
  readonly pmmcp: PmmcpFound | PmmcpAbsent | undefined
  /**
   * The pids of every scripts/monitor_tui.py of the found checkout that runs
   * now (the installer's pgrep before it plans, which names no stop or start
   * script); [] when none runs, and for --aos-only or a fresh install. The
   * stop does not stop one, and the warning lists them.
   */
  readonly tuiPids: readonly number[]
  readonly options: PlanOptions
}

// ── what it returns ───────────────────────────────────────────────────────

export type StepTag = 'aos-file' | 'pmmcp-file' | 'pmmcp-docker' | 'live' | 'fresh-install'

/** How each tag is shown at S4. */
export const TAG_LABEL: Readonly<Record<StepTag, string>> = {
  'aos-file': '[AOS file]',
  'pmmcp-file': '[pmmcp file, loads at next restart]',
  'pmmcp-docker': "[pmmcp's Docker, not the running service]",
  live: '[LIVE]',
  'fresh-install': '[fresh install]',
}

export type StepId =
  | 'env'
  | 'stage-digest'
  | 'qdrant-cleanup'
  | 'clone'
  | 'setup'
  | 'qdrant-init'
  | 'stop'
  | 'update'
  | 'qdrant-enable'
  | 'auth-init'
  | 'start'
  | 'bearer-check'

export type OfferId = 'qdrant' | 'qdrant-cleanup' | 'auth' | 'update' | 'auth-after-update' | 'restart' | 'start'

/** A file pmmcp's auth CLI makes. */
export type AuthFile = 'dashboard_token' | 'curator_secret'

export interface Step {
  readonly id: StepId
  readonly tag: StepTag
  readonly title: string
  /** A few words for the second confirmation's one line. */
  readonly short: string
  /** What runs, as shown: programs and arguments as shell words, never a value (a digest goes on stdin). */
  readonly commands: readonly string[]
  /** How to undo it by hand, when that is more than doing nothing. */
  readonly rollback: string | undefined
  /** The S4 answer that brings it in; undefined for a step its phase always runs (the window's stop, start and checks run whenever the window opens). */
  readonly offer: OfferId | undefined
  /** Offered "if the updated pmmcp supports them": acts only after this run's update, by the re-read facts. */
  readonly afterUpdate: boolean
  /** The files an auth-init step creates: the warning asks for no TUI while the curator secret is made. */
  readonly creates?: readonly AuthFile[]
}

export interface Offer {
  readonly id: OfferId
  /** The question, ending in its default: [y/N]. */
  readonly question: string
  /** Already done by the window any other accepted item opens (the restart): asked only when nothing else that opens it was accepted. */
  readonly impliedByWindow: boolean
  /** An offer that acts only alongside this one: asked only once that one was accepted. */
  readonly requires: OfferId | undefined
  /** A yes opens the stopped window: every offer but the prekey's cleanup. */
  readonly live: boolean
}

export type JobsGate = { readonly available: true } | { readonly available: false; readonly why: string }

export type CredentialState = 'present' | 'blank' | 'missing'

/** One line of the S2 screen. */
export interface CredentialLine {
  readonly name: string
  readonly state: CredentialState
  readonly line: number | undefined
  readonly exported: boolean
  /** What the installer does with it, as shown. */
  readonly text: string
}

export type PlanKind = 'found' | 'fresh-install' | 'not-installed' | 'aos-only'

/** A token whose digest the installer stages, and where its value is. */
export interface Staged {
  readonly name: string
  readonly client: string
  /** 'append': the writer makes it in this run and returns the digest; 'file': inspectCredentials returns the digest of the line already there. */
  readonly from: 'append' | 'file'
}

export interface Plan {
  readonly kind: PlanKind
  /** Refusals, each with its fix: when any is here, nothing may run (exit 2). */
  readonly stops: readonly string[]
  readonly dotenv: { readonly path: string; readonly found: boolean; readonly lines: readonly CredentialLine[]; readonly exported: readonly string[] }
  /** The names appendCredentials generates: the credentials map's alone (generatorsFor). */
  readonly generate: readonly string[]
  /** The token whose digest is staged in pmmcp, if any: the name asked for in `digests`. */
  readonly staged: Staged | undefined
  /** In order: the non-live steps first, then the live window's (or, for a fresh install, its sequence). */
  readonly steps: readonly Step[]
  readonly offers: readonly Offer[]
  readonly jobsGate: JobsGate
  /** The pmmcp folder: the install found, or where a fresh one is cloned; undefined when pmmcp is not touched. */
  readonly pmmcpDir: string | undefined
  /** Whether pmmcp's MCP server runs now; undefined when no install was found. */
  readonly running: boolean | undefined
  /** The scripts/monitor_tui.py pids of the checkout, as handed in: the warning lists them. */
  readonly tuiPids: readonly number[]
  /** The fresh install's screen (S3b): what it does and writes, before the typed `install`. */
  readonly screen: readonly string[]
  readonly notes: readonly string[]
  /** The notes that say something the installer makes is not in place and this run cannot make it. */
  readonly blocked: readonly string[]
}

// ── the planner ───────────────────────────────────────────────────────────

/** Plan the run. See the contract above. */
export function planInstall(input: PlanInput): Plan {
  return new Planner(input).plan()
}

/** True when the plan has nothing to run, nothing to ask and nothing refused: the run exits 0 with no prompt. */
export function nothingToDo(plan: Plan): boolean {
  return plan.stops.length === 0 && plan.steps.length === 0 && plan.offers.length === 0
}

/** Whether a step changes nothing in the running pmmcp: the .env append, the digest staging and the kept prekey's cleanup. */
export const isNonLive = (step: Step): boolean => step.tag === 'aos-file' || step.tag === 'pmmcp-file' || step.tag === 'pmmcp-docker'

/** The offers that act, given the answers: one that requires another acts only with it. */
export function effective(plan: Plan, accepted: ReadonlySet<OfferId>): ReadonlySet<OfferId> {
  const out = new Set<OfferId>()
  for (const offer of plan.offers) {
    if (accepted.has(offer.id) && (offer.requires === undefined || accepted.has(offer.requires))) out.add(offer.id)
  }
  return out
}

/** Whether these answers open the stopped window: some offer that acts is live. */
export function opensWindow(plan: Plan, accepted: ReadonlySet<OfferId>): boolean {
  const acts = effective(plan, accepted)
  return plan.offers.some((o) => o.live && acts.has(o.id))
}

/**
 * The steps that run for these answers: every non-live step not offered, and
 * each offered one that was accepted; and, when a live item acts, the window:
 * its stop, the chosen items in plan order, its start and checks. A step
 * offered after the update acts only with it.
 */
export function select(plan: Plan, accepted: ReadonlySet<OfferId>): { readonly nonLive: readonly Step[]; readonly live: readonly Step[] } {
  if (plan.kind === 'fresh-install') throw new PlanError('a fresh install runs its whole sequence after the typed install; select is for the S4 answers')
  const acts = effective(plan, accepted)
  const nonLive = plan.steps.filter((s) => isNonLive(s) && (s.offer === undefined || acts.has(s.offer)))
  const live = opensWindow(plan, accepted) ? plan.steps.filter((s) => s.tag === 'live' && (s.offer === undefined || acts.has(s.offer))) : []
  return { nonLive, live }
}

const plural = (n: number, one: string, many = `${one}s`): string => `${String(n)} ${n === 1 ? one : many}`

const list = (names: readonly string[]): string => (names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names.at(-1) ?? ''}`)

const short7 = (sha: string): string => sha.slice(0, 7)

/** A feature with what it is and the commit that adds it. */
const lacking = (features: readonly FeatureName[]): string => list(features.map((f) => `${FEATURE_LABELS[f]} (${FEATURE_COMMITS[f]})`))

/** The stop's note when an AOS provider shares one of pmmcp's Ollama ports. */
const ollamaOverlap = (shared: OllamaShared['ollamaShared']): string =>
  `the stop also stops pmmcp's Ollama instances on 11434-11437, which ${list(shared.map((o) => `${o.ref} (${String(o.port)})`))} ${shared.length === 1 ? 'shares' : 'share'}`

class Planner {
  readonly #in: PlanInput
  readonly #stops: string[] = []
  readonly #notes: string[] = []
  readonly #blocked: string[] = []
  readonly #steps: Step[] = []
  readonly #offers: Offer[] = []
  readonly #lines: CredentialLine[] = []
  readonly #generate: string[] = []
  #staged: Staged | undefined
  #jobsGate: JobsGate = { available: true }
  #running: boolean | undefined
  #screen: string[] = []

  constructor(input: PlanInput) {
    this.#in = input
  }

  plan(): Plan {
    const { options, pmmcp } = this.#in
    this.#credentials()
    let kind: PlanKind
    let pmmcpDir: string | undefined
    if (options.aosOnly) {
      kind = 'aos-only'
      if (this.#staged === undefined) this.#notes.push('--aos-only: pmmcp is not touched')
      else {
        this.#block(
          this.#staged.from === 'append'
            ? `--aos-only: pmmcp is not touched, so the ${this.#staged.client} digest of the ${this.#staged.name} this run appends is not staged: run the installer without --aos-only to stage it`
            : // .env holds the token already: pmmcp may well hold its digest, which is neither checked nor staged here.
              `--aos-only: pmmcp is not touched, so whether it holds the ${this.#staged.client} digest of ${this.#staged.name} is not checked, nor is the digest staged: ` +
              'run the installer without --aos-only to check it, and to stage it if pmmcp lacks it',
        )
      }
      this.#staged = undefined
    } else if (pmmcp === undefined) {
      throw new PlanError('discovery found nothing and this is not --aos-only: hand the planner its result')
    } else if (pmmcp.kind === 'absent') {
      if (options.noInstall) {
        kind = 'not-installed'
        this.#block(
          `pmmcp is not installed (looked at ${list(pmmcp.searched)}), and --no-install offers no setup: install it, or give --pmmcp-dir, then re-run` +
            (this.#staged === undefined ? '' : `; the ${this.#staged.client} digest of ${this.#staged.name} is staged once it is installed`),
        )
        this.#staged = undefined
      } else {
        kind = 'fresh-install'
        pmmcpDir = pmmcp.at
        this.#fresh(pmmcp)
      }
    } else {
      kind = 'found'
      pmmcpDir = pmmcp.install.dir
      this.#found(pmmcp)
    }
    const exported = this.#lines.filter((l) => l.exported).map((l) => l.name)
    return {
      kind,
      stops: [...this.#stops],
      dotenv: { path: this.#in.dotenv.path, found: this.#in.dotenv.found, lines: [...this.#lines], exported },
      generate: [...this.#generate],
      staged: this.#staged,
      steps: [...this.#steps],
      offers: [...this.#offers],
      jobsGate: this.#jobsGate,
      pmmcpDir,
      running: this.#running,
      tuiPids: [...this.#in.tuiPids],
      screen: [...this.#screen],
      notes: [...this.#notes],
      blocked: [...this.#blocked],
    }
  }

  /** A note that something the installer makes is not in place, and this run cannot make it. */
  #block(note: string): void {
    this.#notes.push(note)
    this.#blocked.push(note)
  }

  // ── S2: the AOS credentials ──

  #stateOf(name: string): { readonly state: CredentialState; readonly line: number | undefined } | undefined {
    const { dotenv } = this.#in
    const present = dotenv.present.find((n) => n.name === name)
    if (present !== undefined) return { state: 'present', line: present.line }
    const blank = dotenv.blank.find((n) => n.name === name)
    if (blank !== undefined) return { state: 'blank', line: blank.line }
    if (dotenv.missing.includes(name)) return { state: 'missing', line: undefined }
    return undefined
  }

  #credentials(): void {
    const { config, providers, dotenv, exported, room } = this.#in
    const map = credentialsMap(config)
    const pmmcpEnv = config.mcp.servers[PMMCP_SERVER]?.tokenEnv
    if (pmmcpEnv !== undefined && pmmcpEnv === config.control.tokenEnv) {
      this.#stops.push(
        `kernel.yaml's mcp.servers.pmmcp.tokenEnv is ${pmmcpEnv}, the control plane's own bearer: pmmcp's client ${PMMCP_CLIENT} needs a token of its own. Name another (AOS_PMMCP_TOKEN), then re-run`,
      )
    }
    const providerKeys = new Set<string>([OPERATORS_KEY])
    for (const entry of Object.values(providers.entries)) if (entry.auth.envVar !== undefined) providerKeys.add(entry.auth.envVar)

    for (const cred of map.values()) {
      const { name } = cred
      const at = this.#stateOf(name)
      if (at === undefined) throw new PlanError(`the .env inspection does not describe ${name}: ask inspectCredentials for every name of the credentials map`)
      const isExported = exported.has(name)
      if (providerKeys.has(name)) {
        this.#line(name, at, isExported, 'refused: a provider key is yours to add')
        this.#stops.push(`kernel.yaml's ${cred.from} is ${name}, a provider's key, which the installer never generates: name a token of the AOS's own there, then re-run`)
        continue
      }
      if (at.state === 'blank') {
        this.#line(name, at, isExported, `blank (line ${String(at.line)}) -> not set; fill it in or delete the line`)
        this.#stops.push(
          `${dotenv.path} line ${String(at.line)}: ${name} has no value, so it is not set, and the installer never appends a name that holds a line (the file would hold it twice): ` +
            'put the value there or delete the line, then re-run',
        )
        continue
      }
      if (at.state === 'missing') {
        if (isExported) {
          this.#line(name, at, isExported, 'missing, and exported by this shell -> not appended; unset it and re-run')
          this.#stops.push(
            `${name} is exported by this shell and holds no line in .env: the installer never appends a name the shell exports, since a non-blank export wins at boot and the line would go unused. ` +
              `Unset it (unset ${name}) and re-run`,
          )
          continue
        }
        this.#line(name, at, isExported, `missing  -> will be generated (${String(TOKEN_HEX)} hex)`)
        this.#generate.push(name)
        if (cred.client !== undefined) this.#staged = { name, client: cred.client, from: 'append' }
        continue
      }
      // Present: never generated again, so never replaced.
      if (isExported && cred.client !== undefined) {
        this.#line(name, at, isExported, `present (line ${String(at.line)}), and exported by this shell -> unset it and re-run`)
        this.#stops.push(
          `${name} is set in .env (line ${String(at.line)}) and exported by this shell: the kernel started from this shell would send the export, not the value whose digest pmmcp is given. ` +
            `Unset it (unset ${name}) and re-run`,
        )
        continue
      }
      this.#line(name, at, isExported, `present (line ${String(at.line)})`)
      // The control token: nothing is appended or staged for it, so the export is only noted (plan Q26).
      if (isExported) this.#notes.push(`${name} is exported by this shell as well as set in .env (line ${String(at.line)}): a daemon started from this shell uses the export`)
      if (cred.client !== undefined) this.#staged = { name, client: cred.client, from: 'file' }
    }

    // The rest of the screen: the provider keys, which are the operator's.
    const shown = new Set(map.keys())
    for (const name of [...dotenv.present.map((n) => n.name), ...dotenv.blank.map((n) => n.name), ...dotenv.missing]) {
      if (shown.has(name)) continue
      shown.add(name)
      const at = this.#stateOf(name)
      if (at === undefined) continue
      const isExported = exported.has(name)
      if (at.state === 'present') this.#line(name, at, isExported, `present (line ${String(at.line)})`)
      else if (at.state === 'blank') this.#line(name, at, isExported, `blank (line ${String(at.line)}) -> fill it in yourself; the installer never writes it`)
      else this.#line(name, at, isExported, 'missing  -> add it yourself; the installer never writes it')
    }

    if (this.#generate.length > 0) {
      const names = list(this.#generate)
      if (!room.writable) {
        this.#stops.push(
          dotenv.found
            ? `${dotenv.path} is not writable by its owner, and ${names} must be appended to it: chmod 600 ${shellWord(dotenv.path)}, then re-run`
            : `${dotenv.path} cannot be created: you cannot write ${dirname(dotenv.path)}. Make the repository root yours and writable, then re-run`,
        )
      }
      if (!room.fits) {
        this.#stops.push(`${dotenv.path} would be over 64 KiB with ${names} appended, and the loader refuses a larger one: remove lines you no longer need, then re-run`)
      }
      this.#steps.push({
        id: 'env',
        tag: 'aos-file',
        title: dotenv.found
          ? `append ${names} to ${dotenv.path} (each ${String(TOKEN_HEX)} hex, generated; no line there changes)`
          : `create ${dotenv.path} at 0600 with ${names} (each ${String(TOKEN_HEX)} hex, generated)`,
        short: `${names} appended to .env`,
        commands: ['the .env writer (src/secrets/dotenv-append.ts): create at 0600 if missing, append only'],
        rollback: undefined,
        offer: undefined,
        afterUpdate: false,
      })
    }
  }

  #line(name: string, at: { readonly state: CredentialState; readonly line: number | undefined }, exported: boolean, text: string): void {
    this.#lines.push({ name, state: at.state, line: at.line, exported, text })
  }

  // ── S3/S4: an install that is there ──

  #found(found: PmmcpFound): void {
    const { features: f } = found
    const dir = found.install.dir
    const running = found.server !== undefined
    this.#running = running
    this.#jobsGate = jobsGateOf(found)
    if (found.facts === undefined) {
      // Discovery reads no Qdrant status, and #auth no file state, without the facts: none of them is known to be in place.
      this.#block(
        `pmmcp lacks the facts (scripts/pmmcp_facts.py --json, ${FACTS_COMMIT} or later), so whether the Qdrant key, the dashboard token and the curator secret are in place ` +
          `cannot be read, and its stop script cannot count jobs: fetch (${within(dir, 'git fetch')}), update it by hand with pmmcp stopped, then re-run`,
      )
    }

    const token = this.#stage(found)
    if (token.onFile && !running) {
      this.#notes.push(`pmmcp is not running: it loads the ${PMMCP_CLIENT} digest when it next starts (${within(dir, './start-pmmcp-server.sh')})`)
    }
    const server = found.server
    const loaded =
      !token.now &&
      server !== undefined &&
      server.startedAfter !== undefined &&
      found.httpAuthModified !== undefined &&
      server.startedAfter.getTime() > found.httpAuthModified.getTime()
    const restart = token.onFile && running && !loaded
    if (restart && !token.now && server !== undefined) this.#notes.push(notLoaded(server, found.httpAuthModified))

    // Not live: offered whatever the jobs check can do, but only beside something else (below).
    const cleanup = this.#cleanup(found)

    const qdrant = this.#qdrant(found)
    const auth = this.#auth(found)
    const anyItem = qdrant !== undefined || auth.now !== undefined || restart
    const update = this.#update(found, anyItem || auth.later !== undefined)

    const offered: { offer: Offer; step: Step | undefined }[] = []
    if (qdrant !== undefined) offered.push(qdrant)
    if (auth.now !== undefined) offered.push(auth.now)
    if (update !== undefined) offered.push(update)
    if (update !== undefined && auth.later !== undefined) offered.push(auth.later)
    if (restart) {
      offered.push({
        offer: { id: 'restart', question: `Restart pmmcp to load the staged ${PMMCP_CLIENT} token? [y/N]`, impliedByWindow: true, requires: undefined, live: true },
        step: undefined,
      })
    }
    // The last installer run that stopped pmmcp ran no start after it (killed or crashed inside the window, or a stop that did not stop and no
    // start after it), and pmmcp is stopped now: the start, behind the same window and confirmations as any live item; beside another, that
    // window's own start is it. Said as the folders show it: what was run by hand since is not known here.
    if (!running && found.leftStopped !== undefined) {
      this.#notes.push(
        `the last installer run that stopped pmmcp (its logs: ${found.leftStopped.folder}) ran no start after it, and pmmcp is stopped now: no MCP server listens on ` +
          `its port, and launchd has its service unloaded until a start (${within(dir, './start-pmmcp-server.sh')})`,
      )
      offered.push({ offer: { id: 'start', question: START_QUESTION, impliedByWindow: true, requires: undefined, live: true }, step: undefined })
    }
    // The kept prekey's cleanup is asked only in a run that asks or does something else anyway: on its own it is a note with its
    // command, and a re-run after a cutover has nothing to do (plan A10). The cutover can be rolled back only while the prekey is kept.
    if (cleanup !== undefined) {
      if (this.#steps.length > 0 || (offered.length > 0 && this.#jobsGate.available)) {
        this.#offers.push(cleanup.offer)
        this.#steps.push(cleanup.step)
      } else {
        this.#notes.push(
          'pmmcp-qdrant-prekey, the keyless Qdrant the cutover kept stopped, is still there: once you no longer want to roll the cutover back, ' +
            `remove it with ${within(dir, '.venv/bin/python scripts/qdrant_api_key.py cleanup')} (its volumes stay)`,
        )
      }
    }
    if (offered.length === 0) return

    const gate = this.#jobsGate
    if (!gate.available) {
      for (const { offer } of offered) this.#block(`not offered: ${offer.question.replace(/ \[y\/N\]$/, '')}: ${gate.why}`)
      return
    }
    for (const { offer } of offered) this.#offers.push(offer)
    if (!running) {
      this.#notes.push(
        "pmmcp's MCP server is not running now: a live item below still runs the stop, for whatever else of pmmcp runs, and ends by starting pmmcp, which is then left running",
      )
    }
    const items = (id: StepId): Step[] => offered.flatMap((o) => (o.step?.id === id ? [o.step] : []))
    this.#steps.push(
      {
        id: 'stop',
        tag: 'live',
        title: 'stop pmmcp gracefully: stop-pmmcp-server.sh, never --force, never interrupted (its job wait is up to 300 s)',
        short: 'the graceful stop (stop-pmmcp-server.sh)',
        commands: [inDir(dir, 'stop-pmmcp-server.sh')],
        rollback: within(dir, './start-pmmcp-server.sh'),
        offer: undefined,
        afterUpdate: false,
      },
      ...items('update'),
      ...items('qdrant-enable'),
      ...items('auth-init'),
      {
        id: 'start',
        tag: 'live',
        title:
          `start pmmcp${running ? '' : ' (its MCP server is not running now: this starts pmmcp and leaves it running)'}: start-pmmcp-server.sh, then /health 200, ` +
          'a new MCP pid that started after http_auth.yaml changed, Qdrant running, the worker and the scraper alive',
        short: `the start (start-pmmcp-server.sh) and its checks${running ? '' : ', which leave pmmcp running (it is not running now)'}`,
        commands: [inDir(dir, 'start-pmmcp-server.sh')],
        rollback: undefined,
        offer: undefined,
        afterUpdate: false,
      },
    )
    if (token.onFile) this.#steps.push(bearerCheck())
    if (f.stop_jobs_flag && found.kernel.ollamaShared.length > 0) this.#notes.push(ollamaOverlap(found.kernel.ollamaShared))
  }

  /** The aos-kernel digest: on file once the non-live steps ran, and whether this run stages it. */
  #stage(found: PmmcpFound): { readonly onFile: boolean; readonly now: boolean } {
    const token = this.#staged
    if (token === undefined) return { onFile: false, now: false }
    const b = found.bearer
    if (b.state === 'failed') {
      this.#staged = undefined
      this.#stops.push(
        `pmmcp's http_auth check --expect ${token.client} could not say whether its digest is on file: ${b.why}${b.stderr.length > 0 ? ` (${b.stderr.join(' ')})` : ''}. Fix what it names, then re-run`,
      )
      return { onFile: false, now: false }
    }
    if (token.from === 'file' && b.state === 'matches') {
      this.#staged = undefined
      return { onFile: true, now: false }
    }
    const missing = (['rotate_digest_stdin', 'check_expect'] as const).filter((x) => !found.features[x])
    if (missing.length > 0) {
      this.#staged = undefined
      this.#block(`the ${token.client} digest of ${token.name} is not staged: pmmcp lacks ${lacking(missing)}. Update pmmcp first, then re-run`)
      return { onFile: false, now: false }
    }
    this.#steps.push(stageStep(found.install.dir, token, 'pmmcp-file'))
    return { onFile: true, now: true }
  }

  /** The kept pmmcp-qdrant-prekey once Qdrant enforces the key: its removal, offered default no, which the running service does not notice. */
  #cleanup(found: PmmcpFound): { offer: Offer; step: Step } | undefined {
    const q = found.qdrant
    if (q?.verdict !== 'enforced' || !q.prekey_kept) return undefined
    if (!found.features.qdrant_key_script) {
      this.#notes.push(`pmmcp-qdrant-prekey is kept from the cutover, and pmmcp lacks ${lacking(['qdrant_key_script'])}, which removes it: update pmmcp first`)
      return undefined
    }
    return {
      offer: {
        id: 'qdrant-cleanup',
        question: 'Remove the kept pmmcp-qdrant-prekey now (qdrant_api_key.py cleanup: its volumes stay, and the cutover can no longer be rolled back)? [y/N]',
        impliedByWindow: false,
        requires: undefined,
        live: false,
      },
      step: {
        id: 'qdrant-cleanup',
        tag: 'pmmcp-docker',
        title:
          'remove pmmcp-qdrant-prekey, the stopped keyless Qdrant the cutover kept (qdrant_api_key.py cleanup refuses unless pmmcp-qdrant runs with the key, and never removes a volume); ' +
          'the running pmmcp is not touched',
        short: 'the kept pmmcp-qdrant-prekey removed',
        commands: [`${python(found.install.dir)} scripts/qdrant_api_key.py cleanup`],
        rollback: undefined,
        offer: 'qdrant-cleanup',
        afterUpdate: false,
      },
    }
  }

  #qdrant(found: PmmcpFound): { offer: Offer; step: Step } | undefined {
    const q = found.qdrant
    const dir = found.install.dir
    const status = within(dir, '.venv/bin/python scripts/qdrant_api_key.py status')
    if (q === undefined) {
      if (found.facts !== undefined && !found.features.qdrant_status_json) {
        this.#block(`whether Qdrant asks for a key cannot be read: pmmcp lacks ${lacking(['qdrant_status_json'])}. Update pmmcp first`)
      }
      return undefined
    }
    // Enforced: done; a kept prekey is #cleanup's.
    if (q.verdict === 'enforced') return undefined
    if (q.prekey_kept) {
      this.#block(
        `pmmcp-qdrant-prekey is kept from an earlier cutover, and Qdrant's verdict is ${q.verdict}, so the cutover is not offered again: ` +
          `check with ${status}, then rollback or cleanup by hand`,
      )
      return undefined
    }
    if (q.container.state === 'absent') {
      // The start script creates pmmcp-qdrant, with the key when the file is there first; init only makes the file (and keeps one that is there).
      const start = within(dir, './start-pmmcp-server.sh')
      const init = within(dir, '.venv/bin/python scripts/qdrant_api_key.py init')
      const kf = q.key_file
      this.#block(
        kf.state === 'present'
          ? `pmmcp-qdrant does not exist, and ~/.persistent-memory-mcp/qdrant_api_key is there: the next start creates it with the key (${start})`
          : kf.state === 'absent'
            ? `pmmcp-qdrant does not exist, and ~/.persistent-memory-mcp/qdrant_api_key is not there: run init first (${init}), and the next start creates it with the key (${start})`
            : `pmmcp-qdrant does not exist, and ~/.persistent-memory-mcp/qdrant_api_key is unusable (${kf.reason ?? 'no reason given'}): fix or remove it, run init (${init}), and the next start creates it with the key (${start})`,
      )
      return undefined
    }
    // key_set is null only for a container that is absent (above); read a null anywhere else as unknown, never as keyless.
    if (q.container.key_set === null) {
      this.#block(`whether pmmcp-qdrant has a key could not be read, and its verdict is ${q.verdict}: see ${status}`)
      return undefined
    }
    if (q.container.key_set !== false) {
      this.#block(`pmmcp-qdrant has a key, but its verdict is ${q.verdict}: see ${status}`)
      return undefined
    }
    if (q.key_file.state === 'unusable') {
      this.#block(`~/.persistent-memory-mcp/qdrant_api_key is unusable (${q.key_file.reason ?? 'no reason given'}): fix or remove it, and the cutover is offered on a re-run`)
      return undefined
    }
    if (!found.features.qdrant_key_script) {
      this.#block(`Qdrant asks for no key, and pmmcp lacks ${lacking(['qdrant_key_script'])}: update pmmcp first`)
      return undefined
    }
    return {
      offer: { id: 'qdrant', question: 'Enable the Qdrant API key now (live cutover)? [y/N]', impliedByWindow: false, requires: undefined, live: true },
      step: {
        id: 'qdrant-enable',
        tag: 'live',
        title: 'Qdrant API key cutover: a new pmmcp-qdrant from the same image with the key and every port on 127.0.0.1, each collection checked; the old one kept, stopped, as pmmcp-qdrant-prekey',
        short: 'the Qdrant key cutover',
        commands: [`${python(dir)} scripts/qdrant_api_key.py enable --dry-run`, `${python(dir)} scripts/qdrant_api_key.py enable`],
        rollback: within(dir, '.venv/bin/python scripts/qdrant_api_key.py rollback'),
        offer: 'qdrant',
        afterUpdate: false,
      },
    }
  }

  /**
   * The dashboard token and the curator secret: offered now where the facts
   * show pmmcp takes each safely, or, where they do not, "if the updated
   * pmmcp supports them", which only this run's update may bring.
   */
  #auth(found: PmmcpFound): { now: { offer: Offer; step: Step } | undefined; later: { offer: Offer; step: Step } | undefined } {
    const none = { now: undefined, later: undefined }
    const facts = found.facts
    if (facts === undefined) return none
    const f = found.features
    const dir = found.install.dir
    const dash = facts.dashboard_token.state
    const cur = facts.curator_secret.state
    const status = within(dir, '.venv/bin/python -m src.dashboard.auth status')
    if (dash === 'unusable') this.#block(`~/.persistent-memory-mcp/dashboard_token is unusable: ${status} names the rule it breaks; fix or remove it`)
    if (cur === 'unusable') this.#block(`~/.persistent-memory-mcp/curator_secret is unusable: ${status} names the rule it breaks; fix or remove it`)

    const dashNeeds: readonly FeatureName[] = ['dashboard_auth', 'stop_listener_check']
    const curNeeds: readonly FeatureName[] = [...dashNeeds, 'curator_secret', 'curator_proof']
    const dashOk = dashNeeds.every((x) => f[x])
    const curFlags = curNeeds.every((x) => f[x])
    const curator = facts.config.curator
    const bindOk = !curator.enabled || (curator.host === CURATOR_HOST && curator.port === CURATOR_PORT)
    const makeDash = dash === 'absent' && dashOk
    const makeCur = cur === 'absent' && curFlags && bindOk
    if (cur === 'absent' && !bindOk) {
      this.#block(
        `no curator secret is offered: config.curator is ${curator.host}:${String(curator.port)}, and with a secret the curator serves only ${CURATOR_HOST}:${String(CURATOR_PORT)}. ` +
          `Set curator.host to ${CURATOR_HOST} and curator.port to ${String(CURATOR_PORT)}, then re-run`,
      )
    }
    // config.yaml's dashboard.token counts only while no token file has been seen (pmmcp's access_control.md):
    // the file replaces it, and the installer never edits config.yaml, so removing the key is the operator's.
    const legacy = facts.config.dashboard.legacy_token_key
    const config = facts.config.source ?? '~/.persistent-memory-mcp/config.yaml'
    if (legacy) {
      this.#notes.push(
        dash === 'present'
          ? `${config} still holds the legacy dashboard.token, which ~/.persistent-memory-mcp/dashboard_token overrides (a client that sends it gets 401): remove dashboard.token from it`
          : `${config} holds the legacy dashboard.token: once ~/.persistent-memory-mcp/dashboard_token exists it replaces that token (a client that sends it gets 401), so remove dashboard.token from it then`,
      )
    }

    const filesOf = (files: { dash: boolean; cur: boolean }): AuthFile[] => [...(files.dash ? (['dashboard_token'] as const) : []), ...(files.cur ? (['curator_secret'] as const) : [])]
    const step = (offerWords: string, files: { dash: boolean; cur: boolean }, afterUpdate: boolean): Step => {
      const only = files.dash && files.cur ? '' : files.dash ? ' --only dashboard' : ' --only curator'
      const creates = filesOf(files)
      return {
        id: 'auth-init',
        tag: 'live',
        title:
          `create ${offerWords} (${creates.length === 1 ? '0600 file' : '0600 files'} under ~/.persistent-memory-mcp, made by pmmcp's own CLI; ` +
          `pmmcp reads ${creates.length === 1 ? 'it' : 'them'} per request, and the installer never sees ${creates.length === 1 ? 'it' : 'them'})` +
          (afterUpdate ? ', only where the updated pmmcp takes each safely' : '') +
          (files.dash && legacy ? "; the dashboard token file replaces config.yaml's legacy dashboard.token, so a client that sends that token gets 401 once the file exists" : ''),
        short: afterUpdate ? `${offerWords}, where the updated pmmcp supports them` : offerWords,
        commands: [`${python(dir)} -m src.dashboard.auth init${only}`],
        rollback: `with pmmcp stopped, remove ${list(creates.map((x) => `~/.persistent-memory-mcp/${x}`))}, then start it`,
        offer: afterUpdate ? 'auth-after-update' : 'auth',
        afterUpdate,
        creates,
      }
    }
    const words = (files: { dash: boolean; cur: boolean }): string =>
      files.dash && files.cur ? 'the dashboard token and curator secret' : files.dash ? 'the dashboard token' : 'the curator secret'

    let now: { offer: Offer; step: Step } | undefined
    if (makeDash || makeCur) {
      const files = { dash: makeDash, cur: makeCur }
      const w = words(files)
      now = { offer: { id: 'auth', question: `Create ${w} (live)? [y/N]`, impliedByWindow: false, requires: undefined, live: true }, step: step(w, files, false) }
    }

    // What is wanted but not taken safely by this code: only an update brings it.
    const laterDash = dash === 'absent' && !dashOk
    const laterCur = cur === 'absent' && !curFlags && bindOk
    if (!laterDash && !laterCur) return { now, later: undefined }
    const needs = laterCur ? curNeeds : dashNeeds
    const absentFlags = needs.filter((x) => !f[x])
    const files = { dash: laterDash, cur: laterCur }
    const w = words(files)
    this.#block(`${w}: update pmmcp first: its code lacks ${lacking(absentFlags)}`)
    return {
      now,
      later: {
        offer: { id: 'auth-after-update', question: `Create ${w} if the updated pmmcp supports them (live)? [y/N]`, impliedByWindow: false, requires: 'update', live: true },
        step: step(w, files, true),
      },
    }
  }

  #update(found: PmmcpFound, wanted: boolean): { offer: Offer; step: Step } | undefined {
    const g = found.git
    // No head, no way back before the start: not offered.
    if (!g.fastForward || g.originMain === undefined || g.head === undefined) return undefined
    const to = short7(g.originMain)
    const dir = found.install.dir
    const why =
      g.lockUnchanged === false
        ? "it changes uv.lock or pyproject.toml, so pmmcp's virtualenv needs uv sync by hand"
        : g.lockUnchanged !== true
          ? 'whether it changes uv.lock or pyproject.toml could not be told'
          : g.trackedChanges !== 0
            ? `the working tree has ${g.trackedChanges === undefined ? 'changes git could not count' : plural(g.trackedChanges, 'tracked change')}`
            : g.untracked !== 0
              ? `the working tree has ${g.untracked === undefined ? 'files git could not count' : plural(g.untracked, 'untracked file')}`
              : undefined
    if (why !== undefined) {
      const note = `pmmcp can be updated to ${to} (origin/main as last fetched), but not by the installer: ${why}. Update it by hand with pmmcp stopped, then re-run`
      // Blocked when the update would have been offered: something needs it, or the checkout lacks a feature.
      if (wanted || found.missing.length > 0) this.#block(note)
      else this.#notes.push(note)
      return undefined
    }
    if (!wanted && found.missing.length === 0) {
      this.#notes.push(`pmmcp can be updated to ${to} (origin/main as last fetched); nothing else needs pmmcp changed, so the installer does not stop it for that: update it by hand with pmmcp stopped`)
      return undefined
    }
    return {
      offer: { id: 'update', question: `Update pmmcp to ${to} (fast-forward, inside the stopped window)? [y/N]`, impliedByWindow: false, requires: undefined, live: true },
      step: {
        id: 'update',
        tag: 'live',
        title: `update pmmcp to ${to} (a fast-forward to origin/main as last fetched; no fetch), then its facts and http_auth check again with the new code, before the start`,
        short: `the fast-forward to ${to}`,
        commands: [
          `git -C ${shellWord(dir)} merge --ff-only ${g.originMain}`,
          `${python(dir)} scripts/pmmcp_facts.py --json`,
          `${python(dir)} -B -m src.transport.http_auth check`,
        ],
        rollback: `before the start: git -C ${shellWord(dir)} reset --keep ${g.head}`,
        offer: 'update',
        afterUpdate: false,
      },
    }
  }

  // ── S3b: no pmmcp ──

  #fresh(absent: PmmcpAbsent): void {
    const at = absent.at
    this.#jobsGate = { available: true }
    this.#screen = [
      `pmmcp is not installed (looked at ${list(absent.searched)}).`,
      `What will happen: clone github.com/AiBot-Tools/persistent-memory-mcp to ${at} (that capitalisation); ./setup.sh --non-interactive </dev/null; ` +
        'a master passphrase created silently in the macOS Keychain (service persistent-memory-mcp, user master_key); then a stop and a full start.',
      "What the stop signals: whatever listens on 8765, 8767 or 8766, whoever's process it is (it signals a port's listener without a command-line check, " +
        'and SIGKILLs it if the stop is interrupted), ' +
        "and the four Ollama instances on 11434-11437, including whatever answers on 11434 once the start script's PID file for it exists, " +
        "which setup's launchd load can write: your own Ollama there included.",
      'Written outside both program folders: ~/.persistent-memory-mcp, ~/.ollama/models, ~/.gemini/config/plugins/pmmcp-plugin, ~/Library/LaunchAgents/com.aibot.pmmcp.plist, ' +
        "uv and Python under ~/.local, uv's cache ~/.cache/uv (setup's uv sync and its CPU torch install fill it: several GB), " +
        "the macOS Keychain item (service persistent-memory-mcp, user master_key), and Docker Desktop's volume pmmcp-qdrant-data.",
      '~/.gemini/config/skills/pmmcp-skill will be deleted (rm -rf, under -y), if it exists.',
      'An existing ~/.persistent-memory-mcp/config.yaml will be backed up and replaced.',
      "It takes about 10-30 min and several GB of disk (both estimates; setup.sh's ~7.5 GB is unreliable).",
    ]
    const fresh = (id: StepId, title: string, short: string, commands: readonly string[]): Step => ({
      id,
      tag: 'fresh-install',
      title,
      short,
      commands,
      rollback: undefined,
      offer: undefined,
      afterUpdate: false,
    })
    // The key file and the digest are made while nothing runs, just before the first full start, so
    // the start script creates pmmcp-qdrant with the key and the MCP server loads the digest.
    this.#steps.push(
      fresh('clone', `clone pmmcp to ${at}`, `the clone to ${at}`, [`git clone https://github.com/AiBot-Tools/persistent-memory-mcp.git ${shellWord(at)}`]),
      fresh('setup', "run pmmcp's setup: its virtualenv, models, launchd plist and config", 'setup.sh', [within(at, './setup.sh --non-interactive </dev/null')]),
      fresh('stop', 'stop whatever setup started: stop-pmmcp-server.sh, never --force', 'the stop', [inDir(at, 'stop-pmmcp-server.sh')]),
      fresh('qdrant-init', "create Qdrant's key file before the first start, so the start script creates pmmcp-qdrant with the key", 'the Qdrant key file', [
        `${python(at)} scripts/qdrant_api_key.py init`,
      ]),
    )
    const token = this.#staged
    if (token !== undefined) this.#steps.push(stageStep(at, token, 'fresh-install'))
    this.#steps.push(
      fresh('start', 'the full start: start-pmmcp-server.sh, then /health 200, Qdrant running, the worker and the scraper alive', 'the start and its checks', [inDir(at, 'start-pmmcp-server.sh')]),
    )
    if (token !== undefined) this.#steps.push({ ...bearerCheck(), tag: 'fresh-install' })
    if (absent.kernel.ollamaShared.length > 0) this.#notes.push(ollamaOverlap(absent.kernel.ollamaShared))
    this.#notes.push('the dashboard token and the curator secret are offered by a re-run once pmmcp runs')
  }
}

/** Why the running server may not have the digest on file: the restart's note. */
function notLoaded(server: { readonly pid: number; readonly startedAfter: Date | undefined }, modified: Date | undefined): string {
  const pid = `the running MCP server (pid ${String(server.pid)})`
  const why =
    modified === undefined
      ? `http_auth.yaml's last change could not be read, so ${pid} may not have loaded it`
      : server.startedAfter === undefined
        ? `${pid} cannot be shown to have started after http_auth.yaml last changed (ps gave no start), so it may not have loaded it`
        : `${pid} started before http_auth.yaml last changed, as far as ps can tell, so it may not have loaded it`
  return `the ${PMMCP_CLIENT} digest is on file, but ${why}`
}

/** The jobs check the gate runs between the two confirmations, and when it cannot be run. */
function jobsGateOf(found: PmmcpFound): JobsGate {
  if (!found.features.stop_jobs_flag) {
    return {
      available: false,
      why: `the stop script cannot count jobs (it lacks ${lacking(['stop_jobs_flag'])}, and an older one runs a full stop on --jobs), so the installer stops nothing: update pmmcp by hand first, with pmmcp stopped, then re-run`,
    }
  }
  if (!found.features.stop_listener_check && found.facts?.dashboard_token.state === 'present') {
    return {
      available: false,
      why:
        "this stop script sends the dashboard token to whatever listens on 8765 without checking that it is this checkout's dashboard, in --jobs and in a full stop's drain alike, " +
        `so the installer stops nothing while a dashboard token exists: update pmmcp by hand first (${FEATURE_COMMITS.stop_listener_check} or later), then re-run`,
    }
  }
  // Discovery's own count: one that failed, or said unknown, fails again at S6 after every answer; not-run (a stale active.json) is counted after it is cleared.
  const jobs = found.jobs
  if (jobs.state === 'failed' || (jobs.state === 'counted' && jobs.jobs.running === 'unknown')) {
    const what = jobs.state === 'failed' ? `failed in discovery (${jobs.why})` : 'could not count the running jobs in discovery (running jobs: unknown)'
    const stderr = jobs.state === 'failed' && jobs.stderr.length > 0 ? `: ${jobs.stderr.join(' ')}` : ''
    return { available: false, why: `stop-pmmcp-server.sh --jobs ${what}${stderr}, so the installer stops nothing: fix what it names, then re-run` }
  }
  return { available: true }
}

function stageStep(dir: string, token: Staged, tag: 'pmmcp-file' | 'fresh-install'): Step {
  return {
    id: 'stage-digest',
    tag,
    title:
      `stage the ${token.client} digest of ${token.name} in ~/.persistent-memory-mcp/http_auth.yaml ` +
      `(of ${token.from === 'append' ? 'the token appended above' : "the token .env holds"}; the digest alone, on stdin), then check it is on file`,
    short: `the ${token.client} digest staged`,
    commands: [
      `${python(dir)} scripts/rotate_http_auth_token.py ${token.client} --create --digest-stdin`,
      `${python(dir)} -B -m src.transport.http_auth check --expect ${token.client}`,
    ],
    rollback: 'the rotate script keeps http_auth.yaml.bak-<stamp> beside it: put that back while pmmcp is stopped',
    offer: undefined,
    afterUpdate: false,
  }
}

function bearerCheck(): Step {
  return {
    id: 'bearer-check',
    tag: 'live',
    // No MCP initialize: the installer holds no token's value (A2) to send one; the kernel's own next request makes the line (plan S7 L6, §9 option (a)).
    title: `"first request with token" for ${PMMCP_CLIENT} in ~/.persistent-memory-mcp/logs/server.log since the start (not found: inconclusive, not a failure; the AOS daemon's next request makes the line)`,
    short: `the ${PMMCP_CLIENT} bearer check`,
    commands: [],
    rollback: undefined,
    offer: undefined,
    afterUpdate: false,
  }
}

// ── what the operator is shown ────────────────────────────────────────────

/** The plan as S2-S4 show it: .env by name and line, pmmcp, the numbered steps with their tags, the notes. Never a value. */
export function describe(plan: Plan): string[] {
  return [...describeDotenv(plan), ...describePlan(plan)]
}

/** S2: .env by name, line and state, and the names the shell exports. */
export function describeDotenv(plan: Plan): string[] {
  const out: string[] = []
  const { dotenv } = plan
  out.push(`.env  ${dotenv.path}  ${dotenv.found ? 'present' : 'absent (created at 0600 when something is appended)'}`)
  for (const line of dotenv.lines) out.push(`  ${line.name.padEnd(20)} ${line.text}`)
  out.push(`  ${'shell exports'.padEnd(20)} ${dotenv.exported.length === 0 ? 'none of these' : dotenv.exported.join(', ')}`)
  return out
}

/** S3b and S4: pmmcp as the plan takes it, the numbered steps with their tags, the notes. */
export function describePlan(plan: Plan): string[] {
  const out: string[] = []
  if (plan.kind === 'found') out.push(`pmmcp  ${plan.pmmcpDir ?? ''}`)
  else if (plan.kind === 'aos-only') out.push('pmmcp  not touched (--aos-only)')
  else if (plan.kind === 'not-installed') out.push('pmmcp  not installed (--no-install)')
  else out.push(`pmmcp  not installed: a fresh install at ${plan.pmmcpDir ?? ''}`, ...plan.screen.map((s) => `  ${s}`))
  if (plan.steps.length > 0) {
    out.push('plan:')
    plan.steps.forEach((step, i) => out.push(`  ${String(i + 1)}. ${stepLine(plan, step)}`))
  }
  if (plan.notes.length > 0) {
    out.push('notes:')
    for (const note of plan.notes) out.push(`  - ${note}`)
  }
  return out
}

function stepLine(plan: Plan, step: Step): string {
  let when = ''
  if (step.tag === 'live' && step.offer === undefined) when = ' (whenever a live item is chosen)'
  else if (step.offer !== undefined) {
    const offer = plan.offers.find((o) => o.id === step.offer)
    when = offer === undefined ? '' : ` (if you answer yes to "${offer.question.replace(/ \[y\/N\]$/, '')}")`
  }
  return `${TAG_LABEL[step.tag]} ${step.title}${when}`
}

/** A dry run's lines: every step marked would-do, every question it would ask. */
export function wouldDo(plan: Plan): string[] {
  const out = plan.steps.map((step, i) => `would ${String(i + 1)}. ${stepLine(plan, step)}`)
  for (const offer of plan.offers) out.push(`would ask: ${offer.question}`)
  return out
}

/** The numbers `steps` have in describe(), for the question that applies them: "step 2", "steps 1-2", "steps 1 and 3". */
export function nonLiveNumbers(plan: Plan, steps: readonly Step[]): string {
  const numbers = steps.map((s) => plan.steps.indexOf(s) + 1).filter((n) => n > 0)
  const first = numbers[0]
  if (first === undefined) return ''
  if (numbers.length === 1) return `step ${String(first)}`
  const last = numbers.at(-1) ?? first
  return numbers.every((n, i) => n === first + i) ? `steps ${String(first)}-${String(last)}` : `steps ${list(numbers.map(String))}`
}

/** S6: what the window stops and for how long, what it does not stop, and each live item with its rollback. */
export function warning(plan: Plan, live: readonly Step[]): string[] {
  const dir = plan.pmmcpDir ?? '<pmmcp>'
  const pids = plan.tuiPids
  const tui = pids.length === 0 ? 'none runs now' : `${pids.length === 1 ? 'pid' : 'pids'} ${list(pids.map(String))} ${pids.length === 1 ? 'runs' : 'run'} now`
  const out = [
    'WARNING: these changes stop pmmcp, and every program that uses it waits until it is back.',
    'What stops: the MCP server (Antigravity and the AOS lose their memory meanwhile), the dashboard, the curator, the worker, the scraper, the backup daemon, Qdrant, ' +
      "and the four Ollama instances on 11434-11437, including whatever answers on 11434 when the start script's PID file for it exists; " +
      "also whatever listens on 8765, 8767 or the MCP port, whoever's process it is (the stop signals a port's listener without a command-line check, " +
      'so a VM port forwarder of yours there is stopped too, and SIGKILLed if the stop is interrupted).',
    `What does not stop: a scripts/monitor_tui.py of ${dir} (${tui}).`,
    'Downtime: the job wait up to 300 s, graceful stops with no upper bound, then a start of up to about 6 min. launchd keeps pmmcp disabled until the start.',
  ]
  if (plan.running === false) {
    out.push(
      "pmmcp's MCP server is not running now: the stop still stops whatever else of pmmcp runs, and the window ends by starting pmmcp, which is then left running. " +
        'To leave it stopped, type anything but the words asked for below.',
    )
  }
  if (live.some((s) => s.creates?.includes('curator_secret') === true)) {
    out.push(
      `Quit any scripts/monitor_tui.py of ${dir} first (${tui}), and start none until this run ends: a TUI started from older code sends the curator its raw secret once the file exists. ` +
        'The installer checks again before it creates it.',
    )
  }
  out.push('The live items, and how each is undone:')
  for (const step of live) out.push(`  - ${step.title}${step.rollback === undefined ? '' : `; rollback: ${step.rollback}`}`)
  out.push('Do not close this terminal. Ctrl-C will not interrupt a graceful stop.')
  return out
}

/** S6b: the exact sequence, in one line. */
export function sequence(live: readonly Step[]): string {
  return `Now: ${live.map((s) => s.short).join(', then ')}.`
}
