// The installer's discovery: where pmmcp is installed, what its code can do,
// how it runs now, and whether the kernel's config agrees with it.
//
// CONTRACT
//
//   Who calls it: the installer (scripts/install.ts), after its preflight and
//   the .env screen, before it plans anything. Read-only: every program it
//   starts goes through the A3 runner (scripts/install/run.ts), so a child
//   gets the runner's allowlisted environment (no DOCKER_*, PMMCP_*, AOS_*
//   or credential name), stdin from /dev/null or one digest, and output in
//   0600 files under .aos/install/<stamp>/, the one thing it writes. It
//   writes no file itself, holds no credential value and never opens .env
//   itself: the one digest it hands a child comes from inspectCredentials
//   (src/secrets/dotenv-append.ts), which reads .env without opening it for
//   writing and returns the digest, never the value. No child prints the git
//   remote (an https one can carry a token, and the runner's leak scan knows
//   only registered values): the origin is read in-process and held only
//   without user or password. The probes whose output may hold another
//   process's command line or launchd's copy of the service's environment (ps
//   on a pid, launchctl print) have their two files emptied by the runner
//   once read (Runner.discard), and a foreign process is named by its
//   program alone. In-process reads of the checkout's files (pyproject.toml,
//   .git/config, a worktree's .git file) take regular files only, never
//   through a link, opened non-blocking and read to a cap, so a FIFO or a link
//   to a device cannot hang it.
//
//   Finding the install, in order: an explicit --pmmcp-dir; the
//   WorkingDirectory of ~/Library/LaunchAgents/com.aibot.pmmcp.plist, which
//   must exist and run <that folder>/.venv/bin/pmmcp (ProgramArguments[1]);
//   the folder of the MCP server listening on 8766 (lsof, then ps); then
//   ~/Github/Persistent-Memory-MCP. Every source that names a folder counts
//   (the default one only when it is an install, unless it is the only one),
//   so two different folders stop discovery: the stop script SIGKILLs, on a
//   Ctrl-C, whatever has Persistent-Memory-MCP in its command line, and
//   launchd runs one of them. No folder at all is `absent`: the installer
//   asks, or offers the clone (S3b).
//
//   A folder is an install only when it is named exactly
//   Persistent-Memory-MCP on disk (the stop script matches command lines by
//   that name, and the operator's second confirmation types it; APFS keeps a
//   lowercase clone under a lowercase name whatever case a path is typed in),
//   its pyproject.toml names the project persistent-memory-mcp,
//   .venv/bin/pmmcp exists, and the [remote "origin"] url in its git config
//   (.git/config, or the common config a worktree's .git file leads to; as
//   written there, with no include or insteadOf applied) is
//   github.com/AiBot-Tools/persistent-memory-mcp over https (port 443
//   allowed) or ssh (github.com, or ssh.github.com).
//
//   What stops discovery (kind 'stopped', each Stop with its code and a
//   message that names the field, the path or the fix, never a value): a
//   step an earlier run started in its own session that active.json still
//   records while its pid still runs that step (ps; a record that cannot be
//   read, or a pid ps cannot be asked about, counts as running); a legacy
//   com.aibot-tools.pmmcp* plist; a com.aibot.pmmcp plist whose
//   WorkingDirectory is gone; two candidate installs; a folder that is not an
//   install; something other than this account's pmmcp MCP server on 8766;
//   facts that cannot be had or do not fit `facts: 1` (src/install/facts.ts);
//   facts about another folder or origin, or that saw PMMCP_* names; a pmmcp
//   port other than 8766/8765/8767 or a host that is not loopback;
//   http_auth.yaml invalid, or present with a second hard link (the rotate
//   script refuses to replace it); a curator secret present, offered by these
//   facts, or offered once an available fast-forward is applied (S4 asks "if
//   the updated pmmcp supports them", and the bind is read from config.yaml,
//   which the update does not change), while config.curator is not exactly
//   127.0.0.1:8767 with the curator enabled; kernel.yaml's pmmcp url naming
//   another host or port; docker, in the runner's environment, not answering
//   as desktop-linux; a Qdrant status that cannot be had; and, when the
//   digest is wanted, a .env the writer's inspection refuses (its message
//   names the path, names and lines only). Probes after the first facts stop
//   are not run, but for the git state the curator check reads.
//
//   What is only reported: the features the checkout lacks, each with the
//   commit that adds it; an active.json record whose pid no longer runs it
//   (staleActive: the caller clears it before a window of its own, and
//   --jobs is not run meanwhile, which the runner would refuse); the launchd
//   service and the MCP server's pid and the earliest it can have started
//   (ps etime, which no locale changes, so `ps -o lstart=` is never parsed);
//   /health, the RFC 9728 document (enforce shows as
//   bearer_methods_supported ["header"]), the dashboard's /api/auth/status
//   (its 503 body included) and Qdrant's version, all on loopback through
//   node:http with an agent of its own (no proxy, no keep-alive) and no
//   credential (the first /health a running server is asked starts its
//   background services early, which is harmless and the one thing a probe
//   changes there); Qdrant's status document; `stop-pmmcp-server.sh --jobs`,
//   run only when the facts show features.stop_jobs_flag (an older stop script
//   ignores the option and runs a full stop) and, unless they show
//   stop_listener_check, only while dashboard_token is not present (that
//   stop script hands a usable token to whatever listens on 8765), read from
//   stdout's first line alone; `http_auth check --expect aos-kernel` with the
//   digest of pmmcp's tokenEnv on stdin, run only when the kernel declares
//   that tokenEnv, .env holds it and the facts show check_expect; the local
//   origin/main (no fetch); an AOS provider on one of pmmcp's Ollama ports
//   11434-11437; and whether the AOS daemon listens on control.port. Only the
//   facts' flags say what a checkout's scripts can do: no probe names the stop
//   or start script but --jobs (the runner refuses it, A3). pmmcp's Python
//   runs with -B where its own code does not keep from writing __pycache__
//   (qdrant status, http_auth check), so a dry run writes nothing in the
//   checkout.
//
//   What it throws: the runner's leak and halt (a registered value reached a
//   child's output: nothing more may run, and the caller reports it), and a
//   refusal, which is a defect here. A program that cannot be started or
//   does not answer in time is a probe that failed, and says so.

import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, realpathSync, statSync } from 'node:fs'
import http from 'node:http'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'

import type { KernelConfig } from '../../src/config.js'
import { ConfigError, KernelError } from '../../src/errors.js'
import { redactString } from '../../src/events/redact.js'
import {
  FACTS_MISSING,
  FEATURE_NAMES,
  PmmcpDocumentError,
  featuresOf,
  missingFeatures,
  parseFacts,
  parseQdrantStatus,
  type Facts,
  type FeatureName,
  type MissingFeature,
  type QdrantStatus,
} from '../../src/install/facts.js'
import type { ProvidersFile } from '../../src/models/registry.js'
import { credentialNames, inspectCredentials, type InspectOptions } from '../../src/secrets/dotenv-append.js'
import {
  InstallRunError,
  STOP_SCRIPT,
  readActive,
  readAt,
  readJobs,
  readOut,
  shownLine,
  tail,
  type ActiveRecord,
  type Jobs,
  type RunResult,
  type RunSpec,
  type Runner,
} from './run.js'

/** The folder name an install must have on disk. */
export const PMMCP_FOLDER = 'Persistent-Memory-MCP'

/** Where the installer clones pmmcp when there is none: ~/Github/Persistent-Memory-MCP. */
export function defaultInstallDir(home: string): string {
  return join(home, 'Github', PMMCP_FOLDER)
}

/** The launchd label of pmmcp's one service. */
export const PLIST_LABEL = 'com.aibot.pmmcp'

/** The old multi-service supervisor's plists (scripts/supervisor.py), which a current install never has. */
const LEGACY_PLIST = /^com\.aibot-tools\.pmmcp.*\.plist$/i

/** pyproject.toml's [project] name. */
export const PROJECT_NAME = 'persistent-memory-mcp'

/** The origin an install must have: github.com/<this>, compared without case. */
export const ORIGIN_REPO = 'aibot-tools/persistent-memory-mcp'

/** pmmcp's client name for the AOS kernel's bearer in http_auth.yaml. */
export const PMMCP_CLIENT = 'aos-kernel'

/** The ports pmmcp's stop script stops by (stop_by_port) and its callers call: any other is refused. */
export const PMMCP_PORTS = { server: 8766, dashboard: 8765, curator: 8767 } as const

/** Where the curator serves once a curator secret exists, and nowhere else (pmmcp's CURATOR_ADDRESS). */
export const CURATOR_ADDRESS = { host: '127.0.0.1', port: 8767 } as const

export const QDRANT_PORT = 6333

/** pmmcp's four Ollama instances, which its stop script stops. */
export const PMMCP_OLLAMA_PORTS: readonly number[] = [11434, 11435, 11436, 11437]

/** The docker context pmmcp's Qdrant lives in. */
export const DOCKER_CONTEXT = 'desktop-linux'

/** The hosts a pmmcp service may be configured on. */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '::1'])

/** How long each kind of probe may take. */
const QUICK_MS = 15_000
const DOCKER_MS = 30_000
const PYTHON_MS = 60_000
const HTTP_MS = 3_000

/** How long after its active.json record a recorded child may have started: the record is made just before the spawn. */
const SPAWN_SLACK_MS = 10_000

export type StopCode =
  | 'active-step'
  | 'legacy-plist'
  | 'plist'
  | 'two-installs'
  | 'not-an-install'
  | 'folder-name'
  | 'listener'
  | 'probe'
  | 'facts'
  | 'facts-schema'
  | 'facts-mismatch'
  | 'port'
  | 'host'
  | 'http-auth-invalid'
  | 'http-auth-links'
  | 'curator-bind'
  | 'kernel-url'
  | 'docker'
  | 'qdrant-status'
  | 'dotenv'

/** Why discovery stops: matched by code, shown by message (names, paths and fixes, never a value). */
export interface Stop {
  readonly code: StopCode
  readonly message: string
}

export type Source = 'pmmcp-dir' | 'plist' | 'listener' | 'default'

const SOURCE_LABEL: Readonly<Record<Source, string>> = {
  'pmmcp-dir': '--pmmcp-dir',
  plist: `the ${PLIST_LABEL} plist's WorkingDirectory`,
  listener: `the MCP server listening on ${String(PMMCP_PORTS.server)}`,
  default: 'the default place',
}

export interface Install {
  readonly dir: string
  readonly source: Source
}

/** A GET on loopback. */
export interface HttpTarget {
  /** 127.0.0.1 or ::1: loopbackGet refuses any other. */
  readonly host: string
  readonly port: number
  readonly path: string
}

/** What answered: status 0 when nothing did (refused, reset, timed out), with `error` saying which. */
export interface HttpAnswer {
  readonly status: number
  readonly body: string
  readonly error?: string
}

export type HttpGet = (target: HttpTarget, timeoutMs: number) => Promise<HttpAnswer>

/** The largest body a probe reads; a larger one is no answer any of these endpoints gives. */
export const HTTP_BODY_CAP = 64 * 1024

/** What discovery refuses to do: a defect in the caller, never a finding about pmmcp. */
export class DiscoverError extends KernelError {
  constructor(message: string) {
    super('AOS_INSTALL_DISCOVER', message)
  }
}

/** http.request's shape, as loopbackGetWith calls it: a test stands one in to see what it is handed. */
export type RequestFn = (options: http.RequestOptions, callback: (res: http.IncomingMessage) => void) => http.ClientRequest

/**
 * A GET of a loopback URL over `request` (http.request) with an agent of its
 * own: no proxy from the environment (where Node honours one, from 24 on with
 * NODE_USE_ENV_PROXY, it rides the global agent, never a new one), no
 * keep-alive, no credential, no redirect followed. Nothing that answers is an
 * error: status 0 and `error`.
 */
export function loopbackGetWith(request: RequestFn): HttpGet {
  return (target, timeoutMs) => loopbackRequest(request, target, timeoutMs)
}

/** loopbackGetWith(http.request): the GET every HTTP probe makes. */
export const loopbackGet: HttpGet = loopbackGetWith((options, callback) => http.request(options, callback))

function loopbackRequest(request: RequestFn, target: HttpTarget, timeoutMs: number): Promise<HttpAnswer> {
  if (target.host !== '127.0.0.1' && target.host !== '::1') {
    return Promise.reject(new DiscoverError(`a probe asks loopback only (127.0.0.1 or ::1), not ${JSON.stringify(redactString(target.host))}`))
  }
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65_535 || !target.path.startsWith('/')) {
    return Promise.reject(new DiscoverError(`a probe needs a port from 1 to 65535 and a path from /`))
  }
  const agent = new http.Agent({ keepAlive: false, maxSockets: 1 })
  return new Promise<HttpAnswer>((resolveAnswer) => {
    let settled = false
    const finish = (answer: HttpAnswer): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      agent.destroy()
      resolveAnswer(answer)
    }
    const hostHeader = `${target.host === '::1' ? '[::1]' : target.host}:${String(target.port)}`
    const req = request(
      { host: target.host, port: target.port, path: target.path, method: 'GET', agent, headers: { host: hostHeader, accept: 'application/json', connection: 'close' } },
      (res) => {
        const chunks: Buffer[] = []
        let size = 0
        res.on('data', (chunk: Buffer) => {
          size += chunk.length
          if (size > HTTP_BODY_CAP) {
            finish({ status: res.statusCode ?? 0, body: '', error: 'too large' })
            res.destroy()
          } else {
            chunks.push(chunk)
          }
        })
        res.on('end', () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
        res.on('error', (e: Error) => finish({ status: 0, body: '', error: errnoOf(e) }))
        res.on('close', () => finish({ status: 0, body: '', error: 'closed' }))
      },
    )
    const timer = setTimeout(() => {
      finish({ status: 0, body: '', error: 'timeout' })
      req.destroy()
    }, timeoutMs)
    req.on('error', (e: Error) => finish({ status: 0, body: '', error: errnoOf(e) }))
    req.end()
  })
}

/** An error by its errno or Node code, else its class: never its message. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

export interface DiscoverOptions {
  /** The AOS repository root: kernel.yaml's home, and where the runner logs. */
  readonly repoRoot: string
  /** The operator's HOME (injected in tests). */
  readonly home: string
  /** The A3 runner every child goes through. */
  readonly runner: Runner
  /** kernel.yaml and providers.yaml, as the installer loaded them. */
  readonly config: KernelConfig
  readonly providers: ProvidersFile
  /** --pmmcp-dir: this install, still validated. Absolute. */
  readonly pmmcpDir?: string
  /** The operator's uid: launchctl's gui/<uid>, and whose a listener must be. Default process.getuid(). */
  readonly uid?: number
  /** Passed to inspectCredentials as they are (tests stand a temp .env's owner and a non-root euid in). */
  readonly inspect?: Pick<InspectOptions, 'uid' | 'euid'>
  /** The GET every HTTP probe makes (default loopbackGet). */
  readonly http?: HttpGet
  /** The clock a process's start is reckoned from (ps etime) and a recorded step is checked against (default the system's). */
  readonly now?: () => Date
}

export interface ServiceState {
  /** launchctl print found the service in gui/<uid>. */
  readonly loaded: boolean
  readonly state: string | undefined
  readonly pid: number | undefined
}

/** The process listening on the MCP port. */
export interface ServerProcess {
  readonly pid: number
  /**
   * The process started after this instant (the clock before ps, less its
   * etime and one second: a lower bound, never late); undefined when ps
   * cannot say. A6's "started after http_auth.yaml's mtime" compares this.
   */
  readonly startedAfter: Date | undefined
}

export interface Endpoints {
  /** GET /health on the MCP port: the status, 0 when nothing answered. */
  readonly health: number
  /** The RFC 9728 document: 'enforce' when it lists bearer_methods_supported ["header"]; off and warn look the same from outside. */
  readonly bearer: 'enforce' | 'off-or-warn' | 'unknown'
  /** GET :8765/api/auth/status; undefined when the dashboard is disabled. */
  readonly dashboard: { readonly status: number; readonly authRequired: boolean | undefined; readonly source: string | undefined } | undefined
  /** GET :6333/: the status, and the version when it answered with one. */
  readonly qdrant: { readonly status: number; readonly version: string | undefined }
}

export type JobsState =
  | { readonly state: 'counted'; readonly jobs: Jobs }
  | { readonly state: 'not-run'; readonly why: string }
  | { readonly state: 'failed'; readonly why: string; readonly stderr: readonly string[] }

export type BearerCheck =
  | { readonly state: 'matches' | 'differs' | 'absent' }
  | { readonly state: 'not-checked'; readonly why: string }
  | { readonly state: 'failed'; readonly why: string; readonly stderr: readonly string[] }

export interface GitState {
  readonly head: string | undefined
  /** refs/remotes/origin/main as the checkout has it (no fetch); undefined without one. */
  readonly originMain: string | undefined
  /** origin/main is ahead of HEAD and HEAD is its ancestor: a fast-forward would update. */
  readonly fastForward: boolean
  /** uv.lock and pyproject.toml are the same at HEAD and origin/main; undefined when not compared. */
  readonly lockUnchanged: boolean | undefined
  /** `git status --porcelain`: tracked changes, and untracked files. */
  readonly trackedChanges: number | undefined
  readonly untracked: number | undefined
}

export interface KernelSide {
  readonly url: string
  /** The url names pmmcp's host and port; undefined when there are no facts to compare with. */
  readonly urlMatches: boolean | undefined
  /** mcp.servers.pmmcp.tokenEnv, when declared. */
  readonly tokenEnv: string | undefined
  /** AOS providers on one of pmmcp's Ollama ports, which pmmcp's stop script stops. */
  readonly ollamaShared: readonly { readonly ref: string; readonly port: number }[]
  /** Something answers on 127.0.0.1:<control.port>. */
  readonly daemonListening: boolean
}

export interface Found {
  readonly kind: 'found'
  readonly install: Install
  /** An earlier run's active.json record whose pid no longer runs that step: the caller clears it (clearActive) before a window of its own. */
  readonly staleActive: ActiveRecord | undefined
  /** Undefined for a checkout older than the facts (c8bae1e): then every feature reads false. */
  readonly facts: Facts | undefined
  readonly features: Readonly<Record<FeatureName, boolean>>
  /** What the checkout lacks, each with the commit that adds it; the facts themselves first when there are none. */
  readonly missing: readonly MissingFeature[]
  readonly git: GitState
  readonly service: ServiceState
  readonly server: ServerProcess | undefined
  /** ~/.persistent-memory-mcp/http_auth.yaml's mtime, when there is one: the server loads it only at its start. */
  readonly httpAuthModified: Date | undefined
  readonly endpoints: Endpoints
  readonly qdrant: QdrantStatus | undefined
  readonly jobs: JobsState
  readonly bearer: BearerCheck
  readonly kernel: KernelSide
  readonly notes: readonly string[]
}

export interface Absent {
  readonly kind: 'absent'
  /** Where the installer would clone it. */
  readonly at: string
  /** As in Found. */
  readonly staleActive: ActiveRecord | undefined
  /** Where discovery looked. */
  readonly searched: readonly string[]
  readonly kernel: KernelSide
  readonly notes: readonly string[]
}

export interface Stopped {
  readonly kind: 'stopped'
  readonly stops: readonly Stop[]
  readonly install: Install | undefined
  readonly facts: Facts | undefined
}

export type Discovery = Found | Absent | Stopped

/** Find and probe pmmcp, read-only. See the contract above. */
export function discover(options: DiscoverOptions): Promise<Discovery> {
  return new Discoverer(options).run()
}

// ── small readers ────────────────────────────────────────────────────────────

/** The remote URL without user or password: an https remote can carry a token. */
export function withoutUserinfo(url: string): string {
  const scheme = url.indexOf('://')
  if (scheme >= 0) {
    const rest = url.slice(scheme + 3)
    const slash = rest.indexOf('/')
    const authority = slash < 0 ? rest : rest.slice(0, slash)
    return url.slice(0, scheme + 3) + authority.slice(authority.lastIndexOf('@') + 1) + (slash < 0 ? '' : rest.slice(slash))
  }
  const colon = url.indexOf(':')
  if (colon < 0) return url
  const host = url.slice(0, colon)
  return host.slice(host.lastIndexOf('@') + 1) + url.slice(colon)
}

/**
 * `owner/repo` of a GitHub remote, lower case; undefined for anything else.
 * The forms git and GitHub's docs give: https to github.com (port 443 may be
 * written), ssh:// to github.com (any port) or to ssh.github.com (port 22 or
 * 443), and scp-like to either host.
 */
export function githubRepo(url: string): string | undefined {
  const m =
    /^(?:https:\/\/(?:[^@/]*@)?github\.com(?::443)?\/|ssh:\/\/(?:[^@/]*@)?(?:github\.com(?::\d+)?|ssh\.github\.com(?::(?:22|443))?)\/|(?:[^@/:]+@)?(?:ssh\.)?github\.com:)([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i.exec(
      url.trim(),
    )
  return m === null ? undefined : `${m[1] ?? ''}/${m[2] ?? ''}`.toLowerCase()
}

/** The origin forms githubRepo takes, for a message that refuses one. */
export const ORIGIN_FORMS =
  'https://github.com/AiBot-Tools/persistent-memory-mcp(.git) (:443 may be written), git@github.com:AiBot-Tools/persistent-memory-mcp(.git), ' +
  'or ssh://git@github.com/… (ssh.github.com on 22 or 443 too), as written in the git config: no url.<base>.insteadOf or include.path is applied'

/** pyproject.toml's [project] name, read line by line (a name line, as setup tools write it). */
export function projectName(text: string): string | undefined {
  let inProject = false
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.startsWith('[')) {
      inProject = /^\[\s*project\s*\]\s*(?:#.*)?$/.test(line)
      continue
    }
    if (!inProject) continue
    const m = /^name\s*=\s*(?:"([^"]*)"|'([^']*)')\s*(?:#.*)?$/.exec(line)
    if (m !== null) return m[1] ?? m[2]
  }
  return undefined
}

/** The pmmcp folder a server's command line runs: an argument <dir>/.venv/bin/pmmcp. */
export function serverDirOf(args: string): string | undefined {
  for (const arg of args.split(' ')) {
    if (isAbsolute(arg) && arg.endsWith('/.venv/bin/pmmcp')) return dirname(dirname(dirname(arg)))
  }
  return undefined
}

/**
 * `ps -o etime=`, `[[dd-]hh:]mm:ss`, in seconds; undefined for anything else.
 * Read rather than `lstart`, which macOS's ps prints in the locale's own
 * date form (LANG and LC_ALL reach every child).
 */
export function parseEtime(text: string): number | undefined {
  const m = /^(?:(?:(\d{1,6})-)?(\d{1,2}):)?(\d{1,2}):(\d{2})$/.exec(text.trim())
  if (m === null) return undefined
  const [days, hours, minutes, seconds] = [m[1], m[2], m[3], m[4]].map((x) => Number(x ?? '0'))
  if (days === undefined || hours === undefined || minutes === undefined || seconds === undefined) return undefined
  if (seconds > 59 || minutes > 59 || (m[1] !== undefined && hours > 23)) return undefined
  return ((days * 24 + hours) * 60 + minutes) * 60 + seconds
}

/**
 * The earliest a process can have started, from a clock read before ps ran
 * and the etime ps printed: etime counts whole seconds, so the start lies
 * after `before` less etime and one more second. A lower bound, so "started
 * after a file's mtime" is never claimed early.
 */
export function startedAfter(before: Date, etimeSeconds: number): Date {
  return new Date(before.getTime() - (etimeSeconds + 1) * 1000)
}

/** The program a command line runs, by name alone: what may be shown of a process not pmmcp's. */
export function programOf(args: string): string {
  const first = args.trim().split(/\s+/)[0] ?? ''
  return shown(basename(first), 60) || 'an unnamed program'
}

/** The url kernel.yaml should name for pmmcp's MCP endpoint. */
export function mcpUrl(host: string, port: number): string {
  return `http://${host.includes(':') ? `[${host}]` : host}:${String(port)}/mcp`
}

/** The address a probe dials for a configured host. */
const dial = (host: string): string => (host === '::1' ? '::1' : '127.0.0.1')

/** A line of child output or a path as it may be shown, cut to a width. */
const shown = (s: string, width = 200): string => {
  const line = shownLine(s)
  return line.length > width ? `${line.slice(0, width)}…` : line
}

/** The name a folder is stored under on disk, by inode among its parent's entries (APFS keeps the typed case in a path). */
function storedName(dir: string): string | undefined {
  let real: string
  let ino: number
  let dev: number
  try {
    real = realpathSync(dir)
    const st = statSync(real)
    ino = st.ino
    dev = st.dev
  } catch {
    return undefined
  }
  const parent = dirname(real)
  try {
    for (const entry of readdirSync(parent)) {
      try {
        const st = lstatSync(join(parent, entry))
        if (st.ino === ino && st.dev === dev) return entry
      } catch {
        // An entry that went meanwhile is not the folder.
      }
    }
  } catch {
    return basename(real)
  }
  return basename(real)
}

/** A folder's identity: device and inode once it resolves, else its spelling. */
function identity(dir: string): string {
  try {
    const st = statSync(realpathSync(dir))
    return `${String(st.dev)}:${String(st.ino)}`
  } catch {
    return `path:${dir}`
  }
}

const isDirectory = (p: string): boolean => {
  try {
    return statSync(p).isDirectory()
  } catch {
    return false
  }
}

const isFile = (p: string): boolean => {
  try {
    return statSync(p).isFile()
  } catch {
    return false
  }
}

/** The most of pyproject.toml read: a project file is a few KiB. */
export const PYPROJECT_CAP = 256 * 1024

/** The most of a git config read, and of a worktree's .git or commondir file. */
const GIT_CONFIG_CAP = 1024 * 1024
const GIT_POINTER_CAP = 4096

type Read = { readonly text: string } | { readonly problem: string }

/**
 * A small file of the checkout, read in-process: a regular file and never a
 * link (lstat), opened non-blocking without following one, the same file once
 * open (fstat), at most `cap` bytes, as UTF-8. So a FIFO, a link to a device,
 * or a file larger than any such file is refused, and nothing can hang or
 * grow without end.
 */
export function readRegular(path: string, cap: number): Read {
  let st: ReturnType<typeof lstatSync>
  try {
    st = lstatSync(path)
  } catch (e) {
    return { problem: `cannot be read (${errnoOf(e)})` }
  }
  if (st.isSymbolicLink()) return { problem: 'is a link, which is not read' }
  if (!st.isFile()) return { problem: 'is not a regular file' }
  if (st.size > cap) return { problem: `is larger than ${String(cap)} bytes` }
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (e) {
    return { problem: `cannot be read (${errnoOf(e)})` }
  }
  try {
    const opened = fstatSync(fd)
    if (!opened.isFile() || opened.ino !== st.ino || opened.dev !== st.dev) return { problem: 'was replaced while it was read' }
    const buf = readAt(fd, cap + 1, 0)
    if (buf.length > cap) return { problem: `is larger than ${String(cap)} bytes` }
    try {
      return { text: new TextDecoder('utf-8', { fatal: true }).decode(buf) }
    } catch {
      return { problem: 'is not UTF-8' }
    }
  } catch (e) {
    return { problem: `cannot be read (${errnoOf(e)})` }
  } finally {
    closeSync(fd)
  }
}

/**
 * The git config file of the repository at `dir`: <dir>/.git/config, or, when
 * .git is a file (a worktree, a submodule), the config of the folder its
 * `gitdir:` line leads to, by way of that folder's commondir when it has one.
 */
function gitConfigOf(dir: string): { readonly path: string } | { readonly problem: string } {
  const dotgit = join(dir, '.git')
  let st: ReturnType<typeof statSync>
  try {
    st = statSync(dotgit)
  } catch (e) {
    return { problem: errnoOf(e) === 'ENOENT' ? 'has no .git: it is not a git clone' : `has a .git that cannot be read (${errnoOf(e)})` }
  }
  if (st.isDirectory()) return { path: join(dotgit, 'config') }
  if (!st.isFile()) return { problem: 'has a .git that is neither a folder nor a file' }
  const pointer = readRegular(dotgit, GIT_POINTER_CAP)
  if ('problem' in pointer) return { problem: `has a .git file that ${pointer.problem}` }
  const gitdir = /^gitdir: *(.+?)\s*$/m.exec(pointer.text)?.[1]
  if (gitdir === undefined) return { problem: 'has a .git file with no gitdir: line' }
  const at = resolve(dir, gitdir)
  const commondir = join(at, 'commondir')
  let common = at
  try {
    lstatSync(commondir)
    const read = readRegular(commondir, GIT_POINTER_CAP)
    if ('problem' in read) return { problem: `has a worktree whose commondir ${read.problem}` }
    common = resolve(at, read.text.trim())
  } catch {
    // No commondir: a submodule's own git folder, whose config is its own.
  }
  return { path: join(common, 'config') }
}

/** A git config that git itself would refuse: the line it breaks on. */
export class GitConfigError extends KernelError {
  readonly line: number
  constructor(line: number) {
    super('AOS_INSTALL_GIT_CONFIG', `bad config line ${String(line)}`)
    this.line = line
  }
}

/**
 * remote.origin.url in a git config file's text, as `git config --get` reads
 * it from that file: the last value, or undefined. Parsed the way git's
 * config.c does: section names and keys in any case, a quoted subsection as
 * written (`[remote "origin"]`), the deprecated `[remote.origin]` in any case,
 * values trimmed outside quotes, `"` quoting, the escapes \\ \" \n \t \b, a
 * backslash at a line's end joining the next line, # and ; comments, CRLF
 * line ends, a leading UTF-8 BOM. Neither include.path nor insteadOf is
 * applied: the origin is the one written here.
 *
 * @throws {GitConfigError} for a file git would refuse.
 */
export function originUrlIn(text: string): string | undefined {
  const src = text.startsWith('\ufeff') ? text.slice(1) : text
  let i = 0
  /** The line of the last character read: a line end counts on its own line. */
  let line = 1
  let ended = false

  /** The next character, CRLF read as LF (as git's get_next_char); undefined at the end. */
  function next(): string | undefined {
    if (i >= src.length) return undefined
    if (ended) {
      line += 1
      ended = false
    }
    let c = src[i] ?? ''
    i += 1
    if (c === '\r' && src[i] === '\n') {
      c = '\n'
      i += 1
    }
    if (c === '\n') ended = true
    return c
  }
  function peek(): string | undefined {
    const c = src[i]
    return c === '\r' && src[i + 1] === '\n' ? '\n' : c
  }
  function fail(): never {
    throw new GitConfigError(line)
  }

  /** After `[`: `name]`, `name "sub"]` (sub as written), or `name.sub]` (all lower case). */
  function readSection(): string {
    let name = ''
    for (;;) {
      const c = next()
      if (c === undefined || c === '\n') fail()
      if (c === ']') return name === '' ? fail() : name
      if (isConfigSpace(c)) {
        while (isConfigSpace(peek())) next()
        if (next() !== '"') fail()
        let sub = ''
        for (;;) {
          const d = next()
          if (d === undefined || d === '\n') fail()
          if (d === '"') break
          if (d === '\\') {
            const e = next()
            if (e === undefined || e === '\n') fail()
            sub += e
          } else {
            sub += d
          }
        }
        if (next() !== ']') fail()
        return `${name}.${sub}`
      }
      if (!isKeyChar(c) && c !== '.') fail()
      name += c.toLowerCase()
    }
  }

  /** After `=`: to the line's end, as git's parse_value reads it. */
  function readValue(): string {
    let value = ''
    let quote = false
    let comment = false
    let trimAt: number | undefined
    for (;;) {
      const c = next()
      if (c === undefined || c === '\n') {
        if (quote) fail()
        return trimAt === undefined ? value : value.slice(0, trimAt)
      }
      if (comment) continue
      if (isConfigSpace(c) && !quote) {
        if (trimAt === undefined) trimAt = value.length
        if (value.length > 0) value += c
        continue
      }
      if (!quote && (c === '#' || c === ';')) {
        comment = true
        continue
      }
      trimAt = undefined
      if (c === '\\') {
        const e = next()
        if (e === '\n') continue
        if (e === 't') value += '\t'
        else if (e === 'b') value += '\b'
        else if (e === 'n') value += '\n'
        else if (e === '\\' || e === '"') value += e
        else fail()
        continue
      }
      if (c === '"') {
        quote = !quote
        continue
      }
      value += c
    }
  }

  let section: string | undefined
  let url: string | undefined
  let comment = false
  for (;;) {
    const c = next()
    if (c === undefined) return url
    if (c === '\n') {
      comment = false
      continue
    }
    if (comment || isConfigSpace(c)) continue
    if (c === '#' || c === ';') {
      comment = true
      continue
    }
    if (c === '[') {
      section = readSection()
      continue
    }
    if (!/^[A-Za-z]$/.test(c)) fail()
    let key = c.toLowerCase()
    while (isKeyChar(peek())) key += (next() ?? '').toLowerCase()
    while (isConfigSpace(peek())) next()
    const after = peek()
    let value: string | undefined
    if (after === '=') {
      next()
      value = readValue()
    } else if (after !== undefined && after !== '\n') {
      fail()
    }
    if (section === 'remote.origin' && key === 'url') url = value ?? fail()
  }
}

/** Whitespace as git's isspace has it, but the line end, which the parser reads as its own. */
const isConfigSpace = (c: string | undefined): boolean => c === ' ' || c === '\t' || c === '\v' || c === '\f' || c === '\r'

/** A character of a key or a section name, as git's iskeychar. */
const isKeyChar = (c: string | undefined): boolean => c !== undefined && /^[A-Za-z0-9-]$/.test(c)

/** Why `dir` is not a pmmcp install by its files (pyproject and .venv/bin/pmmcp), or undefined. */
function filesProblem(dir: string): string | undefined {
  if (!isDirectory(dir)) return `${dir} does not exist or is not a folder`
  const pyproject = join(dir, 'pyproject.toml')
  const read = readRegular(pyproject, PYPROJECT_CAP)
  if ('problem' in read) return `${dir} has no pyproject.toml it can read: ${pyproject} ${read.problem}`
  const text = read.text
  const name = projectName(text)
  if (name !== PROJECT_NAME) return `${pyproject} names the project ${name === undefined ? 'nothing' : JSON.stringify(shown(name, 60))}, not ${PROJECT_NAME}`
  if (!isFile(join(dir, '.venv', 'bin', 'pmmcp'))) return `${dir} has no .venv/bin/pmmcp: its setup has not run (./setup.sh), or its virtualenv is gone`
  return undefined
}

// ── the probe ────────────────────────────────────────────────────────────────

type Ran = { readonly ok: true; readonly result: RunResult } | { readonly ok: false; readonly why: string; readonly result?: RunResult }

class Halt {
  readonly stops: readonly Stop[]
  constructor(stops: readonly Stop[]) {
    this.stops = stops
  }
}

/** A stop, its message as it may be shown: no terminal control, scrubbed. */
const stopOf = (code: StopCode, message: string): Stop => ({ code, message: shownLine(message) })

const stop = (code: StopCode, message: string): Halt => new Halt([stopOf(code, message)])

class Discoverer {
  readonly #o: DiscoverOptions
  readonly #http: HttpGet
  readonly #uid: number | undefined
  readonly #now: () => Date
  readonly #notes: string[] = []
  #install: Install | undefined
  #facts: Facts | undefined
  /** The MCP server found on 8766 while locating, if any. */
  #serverPids: readonly number[] = []

  constructor(options: DiscoverOptions) {
    if (!isAbsolute(options.repoRoot) || !isAbsolute(options.home)) throw new DiscoverError('the repository root and HOME must be absolute paths')
    if (options.pmmcpDir !== undefined && !isAbsolute(options.pmmcpDir)) throw new DiscoverError('--pmmcp-dir must be an absolute path')
    this.#o = options
    this.#http = options.http ?? loopbackGet
    this.#uid = options.uid ?? process.getuid?.()
    this.#now = options.now ?? ((): Date => new Date())
  }

  async run(): Promise<Discovery> {
    try {
      return await this.#discover()
    } catch (e) {
      if (e instanceof Halt) return { kind: 'stopped', stops: e.stops, install: this.#install, facts: this.#facts }
      throw e
    }
  }

  async #discover(): Promise<Discovery> {
    const { home } = this.#o
    const staleActive = await this.#activeStep()

    const agents = join(home, 'Library', 'LaunchAgents')
    const legacy = this.#legacyPlists(agents)
    if (legacy.length > 0) {
      throw stop(
        'legacy-plist',
        `the old supervisor's launchd plist${legacy.length > 1 ? 's are' : ' is'} still installed: ${legacy.map((p) => shown(p)).join(', ')}. ` +
          `It runs pmmcp's services beside ${PLIST_LABEL}: unload and remove ${legacy.length > 1 ? 'them' : 'it'} (launchctl bootout gui/<uid> <plist>), then re-run`,
      )
    }

    const candidates = await this.#candidates(agents)
    if (candidates.length === 0) {
      // A fresh install serves pmmcp's defaults, so kernel.yaml must name those.
      const url = this.#pmmcpUrl()
      const fresh = mcpUrl('127.0.0.1', PMMCP_PORTS.server)
      if (!sameUrl(url, fresh)) {
        throw stop('kernel-url', `kernel.yaml's mcp.servers.pmmcp.url is ${shown(url)}, but a fresh pmmcp serves ${fresh}: set the url to that, then re-run`)
      }
      await this.#docker()
      const kernel = await this.#kernel({ host: '127.0.0.1', port: PMMCP_PORTS.server })
      return {
        kind: 'absent',
        at: defaultInstallDir(home),
        staleActive,
        searched: [join(agents, `${PLIST_LABEL}.plist`), `the listener on 127.0.0.1:${String(PMMCP_PORTS.server)}`, defaultInstallDir(home)],
        kernel,
        notes: this.#notes.map((n) => shownLine(n)),
      }
    }
    const install = candidates[0]
    if (install === undefined) throw new DiscoverError('no candidate')
    this.#validate(install)
    this.#install = install

    const facts = await this.#readFacts(install.dir)
    this.#facts = facts
    // Before the facts' stops: the curator check asks whether a fast-forward is there to be applied.
    const git = await this.#git(install.dir, facts)
    if (facts !== undefined) this.#checkFacts(install, facts, git)

    const features: Record<FeatureName, boolean> =
      facts === undefined ? (Object.fromEntries(FEATURE_NAMES.map((f) => [f, false])) as Record<FeatureName, boolean>) : { ...featuresOf(facts) }
    const missing: readonly MissingFeature[] =
      facts === undefined ? [FACTS_MISSING] : missingFeatures(facts)
    for (const m of missing) this.#notes.push(`pmmcp lacks ${m.label}: update it to ${m.commit} or later`)

    await this.#docker()
    const qdrant = features.qdrant_status_json ? await this.#qdrantStatus(install.dir) : undefined
    const kernel = await this.#kernel(facts?.config.server)
    const service = await this.#service()
    const server = await this.#server()
    const httpAuthModified = this.#httpAuthModified()
    const endpoints = await this.#endpoints(facts)
    const jobs = await this.#jobs(install.dir, features, facts, staleActive)
    const bearer = await this.#bearer(install.dir, features)

    return {
      kind: 'found',
      install,
      staleActive,
      facts,
      features,
      missing,
      git,
      service,
      server,
      httpAuthModified,
      endpoints,
      qdrant,
      jobs,
      bearer,
      kernel,
      notes: this.#notes.map((n) => shownLine(n)),
    }
  }

  // ── a step an earlier run left in its own session ──

  /**
   * What active.json says, decided by the recorded pid (plan A6): a record
   * that cannot be read, a pid ps cannot be asked about, or one that still
   * runs a process started when the record was made stops discovery; a pid
   * that runs nothing, or a process started later (the pid was reused), means
   * the recorded child is gone, and the record is returned for the caller to
   * clear before a window of its own.
   */
  async #activeStep(): Promise<ActiveRecord | undefined> {
    const active = readActive(this.#o.repoRoot)
    if (active.state === 'none') return undefined
    if (active.state === 'unreadable') {
      throw stop(
        'active-step',
        `an earlier installer run left .aos/install/active.json, and its record cannot be read (${active.reason}), so a step it started in its own session may still be stopping or starting pmmcp. ` +
          'Wait for it to end; remove active.json only once nothing it names runs, then re-run',
      )
    }
    const { record } = active
    const what = `${shown(record.step, 48)} (pid ${String(record.pid)}, since ${shown(record.started, 40)})`
    const running = await this.#recordedPid(record)
    if (running === undefined) return this.#stale(record, what)
    const readOnly = /^stop-jobs(?:-\d+)?$/.test(record.step)
    throw stop(
      'active-step',
      `an earlier installer run started ${what} in its own session, and .aos/install/active.json still records it while that pid runs ${running}: ` +
        (readOnly
          ? "it only counts pmmcp's jobs and changes nothing. Wait for it to end, then re-run"
          : `it may still be stopping, starting or changing pmmcp. Wait for it to end (its output: ${shown(record.out)}, ${shown(record.err)}), then re-run`),
    )
  }

  /**
   * What the recorded pid runs, by name, while it may still be the recorded
   * child; undefined once it is not: ps finds no such pid, or the process
   * there started a while after the record was made (a reused pid; the child
   * started just after it). A record with no start to tell it by, or a pid ps
   * cannot be asked about, may still be the child.
   */
  async #recordedPid(record: ActiveRecord): Promise<string | undefined> {
    const recorded = Date.parse(record.started)
    if (Number.isNaN(recorded)) return 'something the record gives no start to tell it by'
    const before = this.#now()
    const ran = await this.#quick(`ps-active-${String(record.pid)}`, 'ps', ['-ww', '-o', 'etime=,command=', '-p', String(record.pid)])
    const after = this.#now()
    if (!ran.ok) return `a process ps cannot be asked about (${ran.why})`
    const out = this.#out(ran.result)
    this.#discard(ran.result)
    if (out === undefined) return 'a process ps does not describe'
    if (ran.result.code === 1 && out.trim() === '') return undefined
    const m = /^\s*(\S+)\s+(.*)$/.exec(out.split('\n')[0] ?? '')
    const elapsed = m === null ? undefined : parseEtime(m[1] ?? '')
    if (ran.result.code !== 0 || m === null || elapsed === undefined) return `a process ps does not describe (exit ${String(ran.result.code)})`
    const earliest = before.getTime() - (elapsed + 1) * 1000
    const latest = after.getTime() - elapsed * 1000
    if (earliest > recorded + SPAWN_SLACK_MS || latest < recorded - 1000) return undefined
    const args = m[2] ?? ''
    return /(?:^|\/)((?:stop|start)-pmmcp-server\.sh)(?:\s|$)/i.exec(args)?.[1] ?? programOf(args)
  }

  #stale(record: ActiveRecord, what: string): ActiveRecord {
    this.#notes.push(
      `.aos/install/active.json still records ${what} from an earlier installer run, but that pid no longer runs it: ` +
        'the record is cleared before this run starts a step of its own, and --jobs is not counted until then',
    )
    return record
  }

  // ── running a child ──

  /** Run one child through the runner: a program that cannot start or does not answer is a failed probe; a leak or a halt is thrown. */
  async #run(spec: RunSpec): Promise<Ran> {
    let result: RunResult
    try {
      result = await this.#o.runner.run(spec)
    } catch (e) {
      if (e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_SPAWN') return { ok: false, why: e.message }
      throw e
    }
    if (result.timedOut || !result.exited) {
      return { ok: false, why: `${spec.step}: ${spec.command} gave no answer within ${String(Math.round((spec.timeoutMs ?? 0) / 1000))} s`, result }
    }
    if (result.signal !== null) return { ok: false, why: `${spec.step}: ${spec.command} ended by ${result.signal}`, result }
    return { ok: true, result }
  }

  /** stdout for parsing, or undefined when it is not machine output (too large, not UTF-8). */
  #out(result: RunResult): string | undefined {
    try {
      return readOut(result)
    } catch (e) {
      if (e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_OUTPUT') return undefined
      throw e
    }
  }

  /** The last lines of a child's stderr, as they may be shown. */
  #stderr(result: RunResult | undefined, lines = 3): string[] {
    if (result === undefined) return []
    try {
      return tail(result.err, lines)
    } catch {
      return []
    }
  }

  #quick(step: string, command: string, args: readonly string[], cwd = this.#o.repoRoot, timeoutMs = QUICK_MS): Promise<Ran> {
    return this.#run({ step, command, args, cwd, timeoutMs })
  }

  /** Have the runner empty a probe's files once read: they may hold another process's command line or environment. */
  #discard(result: RunResult): void {
    const left = this.#o.runner.discard(result)
    if (left !== undefined) this.#notes.push(`${result.step}'s output may hold another process's command line, and it ${left}`)
  }

  // ── finding the install ──

  #legacyPlists(agents: string): string[] {
    let entries: string[]
    try {
      entries = readdirSync(agents)
    } catch {
      return []
    }
    return entries.filter((e) => LEGACY_PLIST.test(e)).sort().map((e) => join(agents, e))
  }

  async #candidates(agents: string): Promise<Install[]> {
    const found: Install[] = []
    if (this.#o.pmmcpDir !== undefined) found.push({ dir: this.#o.pmmcpDir, source: 'pmmcp-dir' })

    const plist = join(agents, `${PLIST_LABEL}.plist`)
    let plistThere = false
    try {
      lstatSync(plist)
      plistThere = true
    } catch {
      plistThere = false
    }
    if (plistThere) {
      const working = await this.#plutil(plist, 'WorkingDirectory')
      if (!isAbsolute(working)) throw stop('plist', `${plist}'s WorkingDirectory is not an absolute path: reinstall the service from the install's folder (./setup.sh), then re-run`)
      if (!isDirectory(working)) {
        const domain = this.#uid === undefined ? 'gui/$(id -u)' : `gui/${String(this.#uid)}`
        throw stop(
          'plist',
          `${shown(plist)} is left from an install that is gone: its WorkingDirectory ${shown(working)} does not exist or is not a folder. ` +
            `Unload and remove it (launchctl bootout ${domain}/${PLIST_LABEL}, then rm ${shown(plist)}), or reinstall it with ./setup.sh from the clone you use, then re-run`,
        )
      }
      const program = await this.#plutil(plist, 'ProgramArguments.1')
      const expected = join(working, '.venv', 'bin', 'pmmcp')
      if (program !== expected) {
        throw stop(
          'two-installs',
          `${shown(plist)} names two installs: its WorkingDirectory is ${shown(working)}, but it runs ${shown(program)}, not ${shown(expected)}. ` +
            'Reinstall the service from the install you use (./setup.sh there), then re-run',
        )
      }
      found.push({ dir: working, source: 'plist' })
    }

    const listener = await this.#listener()
    if (listener !== undefined) found.push({ dir: listener, source: 'listener' })

    const fallback = defaultInstallDir(this.#o.home)
    if (isDirectory(fallback) && (found.length === 0 || filesProblem(fallback) === undefined)) found.push({ dir: fallback, source: 'default' })

    const distinct = new Map<string, Install[]>()
    for (const c of found) {
      const key = identity(c.dir)
      distinct.set(key, [...(distinct.get(key) ?? []), c])
    }
    if (distinct.size > 1) {
      const named = [...distinct.values()].map((cs) => `${shown(cs[0]?.dir ?? '')} (${cs.map((c) => SOURCE_LABEL[c.source]).join(', ')})`)
      throw stop(
        'two-installs',
        `two candidate pmmcp installs: ${named.join('; ')}. The stop script stops processes by the folder name in their command line, so the installer works only with one: ` +
          'remove or rename the one you do not use (or reinstall the service from the one you do), then re-run',
      )
    }
    return found
  }

  /** One key of the plist, by plutil. */
  async #plutil(plist: string, key: string): Promise<string> {
    const ran = await this.#quick(`plutil-${key.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`, 'plutil', ['-extract', key, 'raw', '-o', '-', plist])
    if (!ran.ok) throw stop('probe', `${plist} cannot be read: ${ran.why}`)
    const out = this.#out(ran.result)
    if (ran.result.code !== 0 || out === undefined) {
      const err = this.#stderr(ran.result, 1)
      throw stop('plist', `${plist} holds no ${key} that plutil can read${err.length > 0 ? ` (${err.join(' ')})` : ''}: reinstall the service from the install's folder (./setup.sh), then re-run`)
    }
    return out.replace(/\n$/, '')
  }

  /** The folder of the pmmcp MCP server listening on 8766, undefined when nothing listens; anything else there stops discovery. */
  async #listener(): Promise<string | undefined> {
    const port = PMMCP_PORTS.server
    const ran = await this.#quick(`lsof-${String(port)}`, 'lsof', ['-nP', `-iTCP:${String(port)}`, '-sTCP:LISTEN', '-Fpu'])
    if (!ran.ok) throw stop('probe', `what listens on ${String(port)} cannot be checked: ${ran.why}`)
    const out = this.#out(ran.result) ?? ''
    if (ran.result.code === 1 && out.trim() === '') return undefined
    if (ran.result.code !== 0) throw stop('probe', `what listens on ${String(port)} cannot be checked: lsof exited ${String(ran.result.code)}`)
    // -F output: a "p<pid>" line starts each process, "u<uid>" is its user.
    const listeners: { pid: number; uid: number | undefined }[] = []
    for (const line of out.split('\n')) {
      if (/^p\d+$/.test(line)) {
        const pid = Number(line.slice(1))
        // One process listening on IPv4 and IPv6 is listed once per process set; a repeat is the same one.
        if (!listeners.some((l) => l.pid === pid)) listeners.push({ pid, uid: undefined })
      } else if (/^u\d+$/.test(line)) {
        const last = listeners.at(-1)
        if (last !== undefined) last.uid = Number(line.slice(1))
      }
    }
    if (listeners.length === 0) return undefined
    const dirs = new Set<string>()
    for (const { pid, uid } of listeners) {
      if (uid === undefined || uid !== this.#uid) throw stop('listener', `${String(port)} is held by pid ${String(pid)}, which is not this account's: pmmcp cannot serve there. Stop that process, then re-run`)
      const ps = await this.#quick(`ps-${String(pid)}`, 'ps', ['-ww', '-o', 'uid=,args=', '-p', String(pid)])
      const line = ps.ok ? (this.#out(ps.result) ?? '').split('\n')[0] ?? '' : ''
      // Another process's command line may carry anything: once read, the log keeps none of it.
      if (ps.ok) this.#discard(ps.result)
      const m = /^\s*(\d+)\s+(.+)$/.exec(line)
      if (m === null) throw stop('probe', `what pid ${String(pid)} on ${String(port)} runs cannot be read${ps.ok ? '' : `: ${ps.why}`}`)
      const dir = serverDirOf(m[2] ?? '')
      if (Number(m[1]) !== this.#uid || dir === undefined) {
        throw stop('listener', `${String(port)} is held by pid ${String(pid)}, which is not a pmmcp MCP server of this account (it runs ${programOf(m[2] ?? '')}): stop that process, then re-run`)
      }
      dirs.add(dir)
    }
    if (dirs.size > 1) throw stop('two-installs', `${String(port)} is held by MCP servers of two installs: ${[...dirs].map((d) => shown(d)).join(', ')}. Stop the one you do not use, then re-run`)
    this.#serverPids = listeners.map((l) => l.pid)
    return [...dirs][0]
  }

  /** Is the chosen folder an install, named as the stop script expects, from AiBot-Tools' repository? */
  #validate(install: Install): void {
    const { dir } = install
    const how = SOURCE_LABEL[install.source]
    if (!isDirectory(dir)) throw stop('not-an-install', `${shown(dir)} (${how}) does not exist or is not a folder: install pmmcp, or give --pmmcp-dir, then re-run`)
    const name = storedName(dir)
    if (name !== PMMCP_FOLDER) {
      throw stop(
        'folder-name',
        `${shown(dir)} (${how}) is stored as ${JSON.stringify(shown(name ?? basename(dir), 80))}, not ${PMMCP_FOLDER}: the stop script finds pmmcp's processes by that name in their command line, ` +
          `and the second confirmation types it. Move the clone to a folder named ${PMMCP_FOLDER} (and reinstall its service there), then re-run`,
      )
    }
    const problem = filesProblem(dir)
    if (problem !== undefined) throw stop('not-an-install', `${shown(dir)} (${how}) is not a pmmcp install: ${problem}`)
    const origin = this.#origin(dir)
    if ('problem' in origin) throw stop('not-an-install', `${shown(dir)} (${how}) is not a pmmcp install: it ${origin.problem}`)
    if (githubRepo(origin.url) !== ORIGIN_REPO) {
      throw stop(
        'not-an-install',
        `${shown(dir)} (${how}) is not a pmmcp install: its git origin is ${origin.url === '' ? 'not set' : shown(origin.url)}, not github.com/AiBot-Tools/persistent-memory-mcp. ` +
          `The forms read: ${ORIGIN_FORMS}`,
      )
    }
  }

  /**
   * The checkout's origin, read in-process and held only without user or
   * password: `git config --get remote.origin.url` through the runner would
   * write a token an https remote carries into its log, which no scan knows.
   */
  #origin(dir: string): { readonly url: string } | { readonly problem: string } {
    const config = gitConfigOf(dir)
    if ('problem' in config) return config
    const read = readRegular(config.path, GIT_CONFIG_CAP)
    if ('problem' in read) return { problem: `has a git config (${shown(config.path)}) that ${read.problem}` }
    try {
      const url = originUrlIn(read.text)
      return { url: url === undefined ? '' : withoutUserinfo(url.trim()) }
    } catch (e) {
      if (e instanceof GitConfigError) return { problem: `has a git config (${shown(config.path)}) that git would refuse: ${e.message}` }
      throw e
    }
  }

  // ── the facts ──

  async #readFacts(dir: string): Promise<Facts | undefined> {
    if (!isFile(join(dir, 'scripts', 'pmmcp_facts.py'))) return undefined
    const ran = await this.#run({ step: 'facts', command: join(dir, '.venv', 'bin', 'python'), args: ['scripts/pmmcp_facts.py', '--json'], cwd: dir, timeoutMs: PYTHON_MS })
    if (!ran.ok) throw stop('facts', `pmmcp's facts cannot be had: ${ran.why}`)
    const err = this.#stderr(ran.result, 1)
    if (ran.result.code !== 0) {
      throw stop('facts', `pmmcp's facts exited ${String(ran.result.code)}${err.length > 0 ? `: ${err.join(' ')}` : ''}. Fix what it names (in ${shown(dir)}), then re-run`)
    }
    const out = this.#out(ran.result)
    if (out === undefined) throw stop('facts', "pmmcp's facts printed something that is not machine output (too large, or not UTF-8)")
    try {
      return parseFacts(out)
    } catch (e) {
      if (e instanceof PmmcpDocumentError) throw stop('facts-schema', `${e.message}. This installer reads facts: 1 as pmmcp ships it; update one or the other`)
      throw e
    }
  }

  /** Everything about the facts that stops discovery, all at once. */
  #checkFacts(install: Install, facts: Facts, git: GitState): void {
    const stops: Stop[] = []
    const add = (code: StopCode, message: string): void => {
      stops.push(stopOf(code, message))
    }
    if (identity(facts.dir) !== identity(install.dir)) add('facts-mismatch', `pmmcp's facts describe ${shown(facts.dir)}, not ${shown(install.dir)}`)
    if (facts.git.origin !== null && githubRepo(facts.git.origin) !== ORIGIN_REPO) {
      add('facts-mismatch', `pmmcp's facts give the origin ${shown(withoutUserinfo(facts.git.origin))}, not github.com/AiBot-Tools/persistent-memory-mcp. The forms read: ${ORIGIN_FORMS}`)
    }
    if (facts.env_overrides.length > 0) {
      add('facts-mismatch', `pmmcp's facts saw ${facts.env_overrides.map((n) => shown(n, 64)).join(', ')} in their environment, which the installer never passes: a defect, report it`)
    }
    if (facts.launchd.exists && facts.launchd.working_directory !== null && identity(facts.launchd.working_directory) !== identity(install.dir)) {
      add('two-installs', `the ${PLIST_LABEL} plist runs ${shown(facts.launchd.working_directory)}, not ${shown(install.dir)}: reinstall the service from the install you use, then re-run`)
    }
    const where = facts.config.source === null ? "pmmcp's built-in defaults" : shown(facts.config.source)
    for (const svc of ['server', 'dashboard', 'curator'] as const) {
      const { host, port } = facts.config[svc]
      if (port !== PMMCP_PORTS[svc]) {
        add('port', `config.${svc}.port is ${String(port)} (${where}); the stop script stops pmmcp on ${String(PMMCP_PORTS[svc])}, so the installer works only there: set ${svc}.port to ${String(PMMCP_PORTS[svc])}, then re-run`)
      }
      if (!LOOPBACK_HOSTS.has(host)) {
        add('host', `config.${svc}.host is ${JSON.stringify(shown(host, 64))} (${where}), which is not loopback: set ${svc}.host to 127.0.0.1, then re-run`)
      }
    }
    const auth = facts.http_auth
    if (auth.state === 'invalid') {
      add('http-auth-invalid', `~/.persistent-memory-mcp/http_auth.yaml is invalid, and pmmcp will not start on it: ${shown(auth.reason ?? 'no reason given')}. Fix it, then re-run`)
    }
    const links = auth.links === undefined ? this.#httpAuthLinks() : auth.links
    if (auth.state === 'present' && links !== null && links !== undefined && links > 1) {
      add(
        'http-auth-links',
        `~/.persistent-memory-mcp/http_auth.yaml has ${String(links)} hard links, and the rotate script refuses to replace it (its other links would keep the old digests): ` +
          'make it a single file first (copy it to a new file in the same folder and move that over it), then re-run',
      )
    }
    const curator = facts.config.curator
    const f = featuresOf(facts)
    const secret = facts.curator_secret.state
    const offered = secret === 'absent' && f.curator_secret && f.curator_proof && f.dashboard_auth && f.stop_listener_check
    // S4 offers it after an update too ("if the updated pmmcp supports them"), and the bind is config.yaml's, which the update leaves as it is.
    const offeredLater = secret === 'absent' && !offered && git.fastForward
    if (curator.enabled && (secret !== 'absent' || offered || offeredLater) && (curator.host !== CURATOR_ADDRESS.host || curator.port !== CURATOR_ADDRESS.port)) {
      const why =
        secret === 'present'
          ? 'present'
          : secret === 'unusable'
            ? 'present (unusable)'
            : offered
              ? 'offered'
              : `offered once pmmcp is updated to origin/main (${(git.originMain ?? '').slice(0, 7)})`
      add(
        'curator-bind',
        `config.curator is ${JSON.stringify(shown(curator.host, 64))}:${String(curator.port)} (${where}), and with a curator secret ${why} ` +
          `the curator serves only ${CURATOR_ADDRESS.host}:${String(CURATOR_ADDRESS.port)}, the address the dashboard and the TUI call, and refuses to start on any other (localhost and ::1 included): ` +
          `set curator.host to ${CURATOR_ADDRESS.host} and curator.port to ${String(CURATOR_ADDRESS.port)}, then re-run`,
      )
    }
    const server = facts.config.server
    const url = this.#pmmcpUrl()
    if (!sameUrl(url, mcpUrl(server.host, server.port))) {
      add('kernel-url', `kernel.yaml's mcp.servers.pmmcp.url is ${shown(url)}, but pmmcp serves ${mcpUrl(server.host, server.port)} (config.server, ${where}): set the url to that, then re-run`)
    }
    if (stops.length > 0) throw new Halt(stops)
  }

  /** The hard-link count of the file http_auth.yaml leads to, for facts older than e6516d5, which do not say. */
  #httpAuthLinks(): number | null {
    try {
      const st = statSync(join(this.#o.home, '.persistent-memory-mcp', 'http_auth.yaml'))
      return st.isFile() ? st.nlink : null
    } catch {
      return null
    }
  }

  #httpAuthModified(): Date | undefined {
    try {
      return statSync(join(this.#o.home, '.persistent-memory-mcp', 'http_auth.yaml')).mtime
    } catch {
      return undefined
    }
  }

  #pmmcpUrl(): string {
    const server = this.#o.config.mcp.servers['pmmcp']
    if (server === undefined) throw new DiscoverError('kernel.yaml declares no pmmcp server')
    return server.url
  }

  // ── probes ──

  async #docker(): Promise<string> {
    const fix = `pmmcp's Qdrant runs in Docker Desktop: in a shell without DOCKER_CONFIG, DOCKER_HOST or DOCKER_CONTEXT, start Docker Desktop and run docker context use ${DOCKER_CONTEXT}, then re-run`
    const ctx = await this.#quick('docker-context', 'docker', ['context', 'show'], this.#o.repoRoot, DOCKER_MS)
    if (!ctx.ok) throw stop('docker', `docker cannot be asked which engine it uses: ${ctx.why}. ${fix}`)
    const context = ctx.result.code === 0 ? ((this.#out(ctx.result) ?? '').split('\n')[0] ?? '').trim() : ''
    if (context !== DOCKER_CONTEXT) {
      throw stop('docker', `docker, without the installer's DOCKER_* names, uses ${context === '' ? 'no context it can name' : JSON.stringify(shown(context, 64))}, not ${DOCKER_CONTEXT}. ${fix}`)
    }
    const info = await this.#quick('docker-info', 'docker', ['info', '--format', '{{.ServerVersion}}'], this.#o.repoRoot, DOCKER_MS)
    if (!info.ok || info.result.code !== 0) {
      throw stop('docker', `docker's ${DOCKER_CONTEXT} engine does not answer${info.ok ? ` (docker info exited ${String(info.result.code)})` : `: ${info.why}`}. ${fix}`)
    }
    return context
  }

  async #qdrantStatus(dir: string): Promise<QdrantStatus> {
    const ran = await this.#run({ step: 'qdrant-status', command: join(dir, '.venv', 'bin', 'python'), args: ['-B', 'scripts/qdrant_api_key.py', 'status', '--json'], cwd: dir, timeoutMs: PYTHON_MS })
    if (!ran.ok) throw stop('qdrant-status', `Qdrant's status cannot be had: ${ran.why}`)
    const err = this.#stderr(ran.result, 1)
    if (ran.result.code !== 0) throw stop('qdrant-status', `Qdrant's status exited ${String(ran.result.code)}${err.length > 0 ? `: ${err.join(' ')}` : ''}`)
    const out = this.#out(ran.result)
    if (out === undefined) throw stop('qdrant-status', "Qdrant's status printed something that is not machine output")
    let status: QdrantStatus
    try {
      status = parseQdrantStatus(out)
    } catch (e) {
      if (e instanceof PmmcpDocumentError) throw stop('qdrant-status', e.message)
      throw e
    }
    if (status.docker_context !== DOCKER_CONTEXT) {
      throw stop('docker', `Qdrant's status asked the docker engine ${JSON.stringify(shown(status.docker_context, 80))}, not ${DOCKER_CONTEXT}: the installer passes no DOCKER_* name, so this is a defect, report it`)
    }
    return status
  }

  /** The kernel's side, against the host and port pmmcp serves (undefined: not known, no facts). */
  async #kernel(server: { readonly host: string; readonly port: number } | undefined): Promise<KernelSide> {
    const url = this.#pmmcpUrl()
    const tokenEnv = this.#o.config.mcp.servers['pmmcp']?.tokenEnv
    const ollamaShared: { ref: string; port: number }[] = []
    for (const [ref, entry] of Object.entries(this.#o.providers.entries)) {
      let u: URL
      try {
        u = new URL(entry.baseUrl)
      } catch {
        continue
      }
      const host = u.hostname.replace(/^\[|\]$/g, '')
      const port = Number(u.port === '' ? (u.protocol === 'https:' ? 443 : 80) : u.port)
      if ((host === 'localhost' || host === '::1' || /^127\.\d+\.\d+\.\d+$/.test(host)) && PMMCP_OLLAMA_PORTS.includes(port)) {
        ollamaShared.push({ ref, port })
        this.#notes.push(`AOS provider ${ref} is on 127.0.0.1:${String(port)}, one of pmmcp's Ollama instances (11434-11437): shared, and pmmcp's stop stops it`)
      }
    }
    const control = this.#o.config.control.port
    const daemon = control === 0 ? { status: 0, body: '' } : await this.#http({ host: '127.0.0.1', port: control, path: '/' }, HTTP_MS)
    const daemonListening = daemon.status !== 0
    if (daemonListening) this.#notes.push(`the AOS daemon listens on ${String(control)}: restart it after this run`)
    return { url, urlMatches: server === undefined ? undefined : sameUrl(url, mcpUrl(server.host, server.port)), tokenEnv, ollamaShared, daemonListening }
  }

  async #service(): Promise<ServiceState> {
    if (this.#uid === undefined) return { loaded: false, state: undefined, pid: undefined }
    const ran = await this.#quick('launchctl-print', 'launchctl', ['print', `gui/${String(this.#uid)}/${PLIST_LABEL}`])
    if (!ran.ok) {
      this.#notes.push(`launchd cannot be asked about ${PLIST_LABEL}: ${ran.why}`)
      return { loaded: false, state: undefined, pid: undefined }
    }
    const out = this.#out(ran.result) ?? ''
    // launchd's copy of the service's environment is in there: once read, the log keeps none of it.
    this.#discard(ran.result)
    if (ran.result.code !== 0) return { loaded: false, state: undefined, pid: undefined }
    const state = /^\tstate = (\S+)$/m.exec(out)?.[1]
    const pid = /^\tpid = (\d+)$/m.exec(out)?.[1]
    return { loaded: true, state, pid: pid === undefined ? undefined : Number(pid) }
  }

  async #server(): Promise<ServerProcess | undefined> {
    const pid = this.#serverPids[0]
    if (pid === undefined) return undefined
    // etime, not lstart: macOS's ps prints lstart in the locale's date form, and LANG and LC_ALL reach the child.
    const before = this.#now()
    const ran = await this.#quick(`ps-etime-${String(pid)}`, 'ps', ['-o', 'etime=', '-p', String(pid)])
    const elapsed = ran.ok && ran.result.code === 0 ? parseEtime((this.#out(ran.result) ?? '').split('\n')[0] ?? '') : undefined
    return { pid, startedAfter: elapsed === undefined ? undefined : startedAfter(before, elapsed) }
  }

  async #endpoints(facts: Facts | undefined): Promise<Endpoints> {
    const server = facts?.config.server ?? { host: '127.0.0.1', port: PMMCP_PORTS.server }
    const health = await this.#http({ host: dial(server.host), port: server.port, path: '/health' }, HTTP_MS)
    const meta = await this.#http({ host: dial(server.host), port: server.port, path: '/.well-known/oauth-protected-resource' }, HTTP_MS)
    let bearer: Endpoints['bearer'] = 'unknown'
    if (meta.status === 200) {
      const methods = jsonField(meta.body, 'bearer_methods_supported')
      if (Array.isArray(methods)) bearer = methods.includes('header') ? 'enforce' : 'off-or-warn'
    }
    const served = facts?.http_auth.mode
    if (bearer === 'enforce' && served !== 'enforce') this.#notes.push('the running MCP server enforces its bearer, but http_auth.yaml says otherwise: it changes at the next restart')
    if (bearer === 'off-or-warn' && served === 'enforce') this.#notes.push('http_auth.yaml says enforce, but the running MCP server does not: it loads the file at its next restart')

    let dashboard: Endpoints['dashboard']
    const dash = facts?.config.dashboard ?? { host: '127.0.0.1', port: PMMCP_PORTS.dashboard, enabled: true }
    if (dash.enabled) {
      const a = await this.#http({ host: dial(dash.host), port: dash.port, path: '/api/auth/status' }, HTTP_MS)
      const required = a.status === 200 || a.status === 503 ? jsonField(a.body, 'auth_required') : undefined
      const source = a.status === 200 || a.status === 503 ? jsonField(a.body, 'source') : undefined
      dashboard = {
        status: a.status,
        authRequired: typeof required === 'boolean' ? required : undefined,
        source: typeof source === 'string' && /^(?:file|config|none)$/.test(source) ? source : undefined,
      }
    }

    const q = await this.#http({ host: '127.0.0.1', port: QDRANT_PORT, path: '/' }, HTTP_MS)
    const version = q.status === 200 ? jsonField(q.body, 'version') : undefined
    return {
      health: health.status,
      bearer,
      dashboard,
      qdrant: { status: q.status, version: typeof version === 'string' && /^[0-9A-Za-z.+-]{1,40}$/.test(version) ? version : undefined },
    }
  }

  async #git(dir: string, facts: Facts | undefined): Promise<GitState> {
    let head = facts?.git.head ?? undefined
    if (head === undefined) {
      const ran = await this.#quick('git-head', 'git', ['--no-optional-locks', 'rev-parse', '--verify', '-q', 'HEAD'], dir)
      const out = ran.ok && ran.result.code === 0 ? (this.#out(ran.result) ?? '').trim() : ''
      head = /^[0-9a-f]{40,64}$/.test(out) ? out : undefined
    }
    const ref = await this.#quick('git-origin-main', 'git', ['--no-optional-locks', 'rev-parse', '--verify', '-q', 'refs/remotes/origin/main^{commit}'], dir)
    const refOut = ref.ok && ref.result.code === 0 ? (this.#out(ref.result) ?? '').trim() : ''
    const originMain = /^[0-9a-f]{40,64}$/.test(refOut) ? refOut : undefined
    let fastForward = false
    let lockUnchanged: boolean | undefined
    if (head !== undefined && originMain !== undefined && head !== originMain) {
      const anc = await this.#quick('git-is-ancestor', 'git', ['--no-optional-locks', 'merge-base', '--is-ancestor', 'HEAD', originMain], dir)
      fastForward = anc.ok && anc.result.code === 0
      const diff = await this.#quick('git-lock-diff', 'git', ['--no-optional-locks', 'diff', '--quiet', 'HEAD', originMain, '--', 'uv.lock', 'pyproject.toml'], dir)
      lockUnchanged = diff.ok && diff.result.code === 0 ? true : diff.ok && diff.result.code === 1 ? false : undefined
    }
    const st = await this.#quick('git-status', 'git', ['--no-optional-locks', 'status', '--porcelain'], dir)
    let trackedChanges: number | undefined
    let untracked: number | undefined
    const stOut = st.ok && st.result.code === 0 ? this.#out(st.result) : undefined
    if (stOut !== undefined) {
      const lines = stOut.split('\n').filter((l) => l !== '')
      untracked = lines.filter((l) => l.startsWith('?? ')).length
      trackedChanges = lines.length - untracked
    }
    return { head, originMain, fastForward, lockUnchanged, trackedChanges, untracked }
  }

  async #jobs(dir: string, features: Readonly<Record<FeatureName, boolean>>, facts: Facts | undefined, staleActive: ActiveRecord | undefined): Promise<JobsState> {
    if (!features.stop_jobs_flag) {
      return { state: 'not-run', why: 'the stop script cannot count jobs (an older one runs a full stop on --jobs); update pmmcp first' }
    }
    // From 540bc6b to fa67d43 --jobs sends a usable dashboard token to whatever listens on 8765, pmmcp's
    // dashboard or not; the facts say it checks first only from e6516d5 (0e8e4cc's code, unflagged, counts as unchecked).
    if (!features.stop_listener_check && facts?.dashboard_token.state === 'present') {
      return {
        state: 'not-run',
        why: "this stop script sends the dashboard token to whatever listens on 8765 without checking it is this checkout's dashboard, so --jobs is not run while a dashboard token exists; update pmmcp first",
      }
    }
    if (staleActive !== undefined) {
      return { state: 'not-run', why: "not counted while .aos/install/active.json holds an earlier run's record, which the runner honours; it is cleared before this run's own window" }
    }
    const ran = await this.#run({ step: 'stop-jobs', command: join(dir, STOP_SCRIPT), args: ['--jobs'], cwd: dir })
    if (!ran.ok) return { state: 'failed', why: ran.why, stderr: this.#stderr(ran.result) }
    let jobs: Jobs | undefined
    try {
      jobs = readJobs(ran.result)
    } catch (e) {
      if (!(e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_OUTPUT')) throw e
      jobs = undefined
    }
    if (jobs === undefined) return { state: 'failed', why: `${STOP_SCRIPT} --jobs gave no count (exit ${String(ran.result.code)})`, stderr: this.#stderr(ran.result) }
    return { state: 'counted', jobs }
  }

  async #bearer(dir: string, features: Readonly<Record<FeatureName, boolean>>): Promise<BearerCheck> {
    const tokenEnv = this.#o.config.mcp.servers['pmmcp']?.tokenEnv
    if (tokenEnv === undefined) return { state: 'not-checked', why: 'kernel.yaml declares no tokenEnv for pmmcp, so there is no aos-kernel token yet' }
    let digest: string | undefined
    try {
      const inspected = inspectCredentials({
        repoRoot: this.#o.repoRoot,
        accepted: credentialNames(this.#o.config, this.#o.providers),
        names: [],
        digests: [tokenEnv],
        ...(this.#o.inspect?.uid === undefined ? {} : { uid: this.#o.inspect.uid }),
        ...(this.#o.inspect?.euid === undefined ? {} : { euid: this.#o.inspect.euid }),
      })
      digest = inspected.digests.find((d) => d.name === tokenEnv)?.digest
    } catch (e) {
      // The writer's refusals name the path, names and line numbers only.
      if (e instanceof ConfigError) throw stop('dotenv', e.message)
      throw e
    }
    if (digest === undefined) return { state: 'not-checked', why: `${tokenEnv} holds no value in .env yet` }
    if (!features.check_expect) return { state: 'not-checked', why: 'pmmcp has no http_auth check --expect; update it first' }
    const ran = await this.#run({
      step: 'http-auth-check',
      command: join(dir, '.venv', 'bin', 'python'),
      args: ['-B', '-m', 'src.transport.http_auth', 'check', '--expect', PMMCP_CLIENT],
      cwd: dir,
      digest,
      timeoutMs: PYTHON_MS,
    })
    if (!ran.ok) return { state: 'failed', why: ran.why, stderr: this.#stderr(ran.result) }
    const line = ((this.#out(ran.result) ?? '').split('\n')[0] ?? '').trim()
    const m = new RegExp(`^${PMMCP_CLIENT}: (matches|differs|absent)$`).exec(line)
    const said = m?.[1]
    if (said === 'matches' && ran.result.code === 0) return { state: 'matches' }
    if ((said === 'differs' || said === 'absent') && ran.result.code === 3) return { state: said }
    return { state: 'failed', why: `http_auth check --expect ${PMMCP_CLIENT} exited ${String(ran.result.code)} without a verdict`, stderr: this.#stderr(ran.result) }
  }
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

/** Two URLs that name the same endpoint, by WHATWG's normal form. */
function sameUrl(a: string, b: string): boolean {
  try {
    return new URL(a).href === new URL(b).href
  } catch {
    return false
  }
}
