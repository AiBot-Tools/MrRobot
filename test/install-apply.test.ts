// The installer's apply step (scripts/install/apply.ts): the non-live steps,
// the jobs check, the stopped window and its checks, a fresh install, and
// the end report.
//
// Every repository and HOME here is a mkdtemp directory. Every child goes
// through the real A3 runner to a fake spawn that answers as pmmcp's
// scripts, git, lsof, ps, docker and pgrep would, from one machine's state
// (what listens where, which pids are alive, which files pmmcp holds), and
// never one of them runs. Every HTTP probe is a fake loopback GET over that
// state. The plans come from the real planner, over the real .env writer's
// inspection of the scratch repository, and the .env the steps write is
// written by the real writer there.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { appendFileSync, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync, writeSync } from 'node:fs'
import { tmpdir as osTmpdir } from 'node:os'
import { join, sep } from 'node:path'
import { PassThrough } from 'node:stream'
import test, { type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { Applier, CLONE_URL, INTERRUPT_RERUNS, PROBE_TRIES, logMark, logTail, type ApplyOptions, type Item } from '../scripts/install/apply.js'
import type { Absent, Found, HttpAnswer, HttpGet, HttpTarget } from '../scripts/install/discover.js'
import { Runner, START_SCRIPT, STOP_SCRIPT, activePath, readActive, type Active, type ActiveRecord, type ChildOptions, type RunSpec, type SpawnFn } from '../scripts/install/run.js'
import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { FEATURE_NAMES, featuresOf, missingFeatures, parseFacts, parseQdrantStatus } from '../src/install/facts.js'
import { runGate, type Answer, type GateIO, type JobsAnswer } from '../src/install/gate.js'
import { credentialsMap, planInstall, select, type OfferId, type Plan, type Step } from '../src/install/plan.js'
import { parseProviders, type ProvidersFile } from '../src/models/registry.js'
import { appendCredentials, credentialNames, inspectCredentials, mintedCredentialNames, type InspectResult } from '../src/secrets/dotenv-append.js'
import { tmpdir } from './helpers/tmpdir.js'

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '')
const NOW = new Date('2026-10-29T10:00:00.000Z')
/** The operator's uid on the Mac: the writer refuses root, and the suite may run as root. */
const OP_UID = 501
const OLD_PID = 812
const NEW_PID = 913
const WORKER_PID = 921
const SCRAPER_PID = 922
const HEAD = 'e6516d5'.padEnd(40, '0')
const ORIGIN_MAIN = '53ea308'.padEnd(40, '0')
const ORIGIN = 'https://github.com/AiBot-Tools/persistent-memory-mcp.git'
/** http_auth.yaml as it was before this run: an hour before NOW, after the old server started. */
const AUTH_BEFORE = new Date(NOW.getTime() - 60 * 60 * 1000)
const OLD_STARTED_AFTER = new Date(NOW.getTime() - 2 * 60 * 60 * 1000)

const raw = (p: string): unknown => parseYaml(readFileSync(join(REPO_ROOT, p), 'utf8'))
const PROVIDERS: ProvidersFile = parseProviders(raw('config/providers.yaml'))

/** kernel.yaml with pmmcp's bearer declared as AOS_PMMCP_TOKEN (A8). */
function declaring(): KernelConfig {
  const doc = structuredClone(raw('config/kernel.yaml')) as { mcp: { servers: Record<string, Record<string, unknown>> } }
  const pmmcp = doc.mcp.servers['pmmcp']
  assert.ok(pmmcp !== undefined)
  pmmcp['tokenEnv'] = 'AOS_PMMCP_TOKEN'
  return parseKernelConfig(doc, { repoRoot: REPO_ROOT })
}
const DECLARED = declaring()

type Doc = Record<string, unknown>

/** Set or delete a dotted path in a JSON document. */
function edit(doc: Doc, path: string, value?: unknown): Doc {
  const parts = path.split('.')
  let at: Doc = doc
  for (const p of parts.slice(0, -1)) at = at[p] as Doc
  const last = parts.at(-1) ?? ''
  if (value === undefined) delete at[last]
  else at[last] = value
  return doc
}

/** The facts as e6516d5 prints them, with no dashboard token or curator secret yet. */
function factsDoc(dir: string, home: string): Doc {
  return {
    facts: 1,
    dir,
    git: { head: HEAD, branch: 'main', dirty: false, origin: ORIGIN },
    features: Object.fromEntries(FEATURE_NAMES.map((f) => [f, true])),
    config: {
      source: join(home, '.persistent-memory-mcp', 'config.yaml'),
      server: { host: '127.0.0.1', port: 8766, enabled: true },
      dashboard: { host: '127.0.0.1', port: 8765, enabled: true, legacy_token_key: false },
      curator: { host: '127.0.0.1', port: 8767, enabled: true },
    },
    env_overrides: [],
    http_auth: { state: 'present', mode: 'warn', tokens: ['antigravity'], reason: null, links: 1 },
    qdrant_key_file: { state: 'absent' },
    dashboard_token: { state: 'absent' },
    curator_secret: { state: 'absent' },
    launchd: { plist: join(home, 'Library', 'LaunchAgents', 'com.aibot.pmmcp.plist'), exists: true, working_directory: dir, legacy_plists: [] },
  }
}

/** Qdrant once the key is enforced on 127.0.0.1. */
function enforced(): Doc {
  return {
    docker_context: 'desktop-linux',
    key_file: { state: 'present', reason: null },
    container: {
      state: 'running',
      key_set: true,
      image12: '0123456789ab',
      published: [{ host_ip: '127.0.0.1', host_port: 6333, container_port: '6333/tcp' }],
      publish_all_ports: false,
      reachable_beyond_loopback: [],
    },
    prekey_kept: false,
    collections: { without_key: 401, with_key: 200 },
    verdict: 'enforced',
  }
}

/** A keyless Qdrant, as before the cutover. */
function keyless(): Doc {
  const doc = enforced()
  edit(doc, 'key_file', { state: 'absent', reason: null })
  edit(doc, 'container.key_set', false)
  edit(doc, 'collections', { without_key: 200, with_key: null })
  edit(doc, 'verdict', 'not_asked')
  return doc
}

interface Reply {
  readonly out?: string
  readonly err?: string
  readonly code?: number
  /** Ended by this signal (code null): a probe the terminal's Ctrl-C reached. */
  readonly signal?: NodeJS.Signals
  /** The exit waits for this: a child still running while the test acts. */
  readonly hold?: Promise<void>
}

interface Call {
  readonly key: string
  readonly command: string
  readonly args: readonly string[]
  readonly options: ChildOptions
  stdin: string
  /** active.json as the child's exit found it. */
  active: Active | undefined
  readonly child: FakeChild
}

class FakeChild extends EventEmitter {
  readonly pid: number | undefined
  readonly stdin: PassThrough | null
  readonly kills: string[] = []
  constructor(pid: number | undefined, piped: boolean) {
    super()
    this.pid = pid
    this.stdin = piped ? new PassThrough() : null
  }
  kill(signal: NodeJS.Signals): boolean {
    this.kills.push(signal)
    return true
  }
}

/** The runner, recording every spec it is handed: what the applier asked for, timeouts and sessions included. */
class RecordingRunner extends Runner {
  readonly specs: RunSpec[] = []
  override start(spec: RunSpec): ReturnType<Runner['start']> {
    this.specs.push(spec)
    return super.start(spec)
  }
}

/** A reply for one command line; a function that answers undefined leaves that call to the machine. */
type Over = Reply | ((call: Call) => Reply | undefined)

/**
 * One machine: an AOS checkout, a HOME with pmmcp's folder, a pmmcp install,
 * and what runs there. Tests change the fields, build a plan, then apply it.
 */
class Machine {
  readonly t: TestContext
  readonly root: string
  readonly home: string
  readonly dir: string
  config: KernelConfig = DECLARED
  facts: Doc
  /** What the facts say once the checkout was fast-forwarded. */
  updatedFacts: Doc | undefined
  /** Qdrant's status as discovery read it, and as status --json says after the start. */
  qdrantBefore: Doc = enforced()
  qdrantAfter: Doc = enforced()
  head = HEAD
  originMain = HEAD
  /** Discovery's aos-kernel check; undefined: worked out from .env. */
  bearer: Found['bearer'] | undefined
  staleActive: ActiveRecord | undefined
  /** Discovery's leftStopped: the last installer run that stopped pmmcp ran no start after it. */
  leftStopped: Found['leftStopped']
  /** Discovery found the MCP server running on 8766 (false: pmmcp is stopped). */
  discoveredServer = true
  /** pmmcp is installed (false: a fresh install's machine). */
  installed = true

  // ── what runs ──
  running = true
  readonly etimes = new Map<number, string>([[OLD_PID, '02:00:00']])
  readonly alive = new Set<number>([OLD_PID, 700, 701])
  readonly listeners = new Map<number, number[]>([
    [8766, [OLD_PID]],
    [8765, [OLD_PID + 1]],
    [8767, [OLD_PID + 2]],
  ])
  qdrant: 'running' | 'exited' | 'absent' = 'running'
  readonly auth: { dashboard_token: string; curator_secret: string } = { dashboard_token: 'absent', curator_secret: 'absent' }
  tuis: number[] = []
  updated = false

  // ── how it behaves ──
  stopCode = 0
  /** The stop ends by this signal instead of an exit (code null). */
  stopSignal: NodeJS.Signals | undefined
  /** Ports the stop leaves listened on. */
  stopLeaves: number[] = []
  /** The stop leaves pmmcp-qdrant running. */
  stopLeavesQdrant = false
  /** The stop leaves the worker (pid 700) running, its PID file in place. */
  stopLeavesWorker = false
  /** The kernel's first request with its bearer reaches the started server: its line lands in server.log after the start. */
  kernelAfterStart = false
  /** Other lines the started server writes to server.log. */
  serverLogOnStart: string[] = []
  /** A new MCP server rolls server.log over to server.log.1 as it starts (pmmcp's setup_logging); false: a server.log no start rotated. */
  rotateServerLog = true
  /** Lines appended to launchd.err.log while the start runs. */
  launchdErrOnStart: string[] = []
  /** What the dashboard's /api/auth/status says auth_required is; undefined: whether a token file is present. */
  authRequired: boolean | undefined
  /** `ls -lde .env`'s mode field and the lines under it. */
  lsMode = '-rw-------'
  lsAcl: string[] = []
  startCode = 0
  /** The start leaves an MCP server listening on 8766. */
  startServer = true
  startPid = NEW_PID
  startEtime = '00:07'
  startQdrant = true
  startWorkers = true
  /** /health after the start. */
  health = 200
  dashboardUp = true
  curatorUp = true
  /** What :8767/api/curator/status answers without a proof once a curator secret exists. */
  curatorWithSecret = 401
  /** What /api/fingerprint answers without a token; undefined: 401 with a dashboard token file, else 200. */
  fingerprint: number | undefined
  /** A listener's uid as lsof prints it, by pid; the operator's when not named. */
  readonly listenerUids = new Map<number, number>()
  jobs: Reply = { out: 'running jobs: 0\n' }
  expect: Reply = { out: 'aos-kernel: matches\n', code: 0 }
  readonly over = new Map<string, Over>()

  // ── what was seen ──
  readonly calls: Call[] = []
  readonly gets: string[] = []
  readonly printed: string[] = []
  readonly asked: string[] = []
  /** Whether the window was open when each question was asked. */
  readonly askedInWindow: boolean[] = []
  readonly windows: boolean[] = []
  /** Every token the installer minted, in order: the control token first, then pmmcp's. */
  readonly minted: string[] = []
  answer: Answer = { kind: 'line', text: 'n' }
  readonly runner: RecordingRunner
  discovery: Found | Absent | undefined

  constructor(t: TestContext, options: { installed?: boolean; parent?: string } = {}) {
    this.t = t
    this.root = tmpdir(t)
    writeFileSync(join(this.root, '.gitignore'), '/.aos/\n/.env\n')
    this.home = tmpdir(t)
    this.dir = join(this.home, options.parent ?? 'Github', 'Persistent-Memory-MCP')
    this.facts = factsDoc(this.dir, this.home)
    this.installed = options.installed ?? true
    mkdirSync(join(this.pmmcpHome, 'pids'), { recursive: true })
    mkdirSync(join(this.pmmcpHome, 'logs'), { recursive: true })
    if (this.installed) {
      mkdirSync(join(this.dir, 'logs'), { recursive: true })
      writeFileSync(this.authFile, 'mode: warn\ntokens:\n  antigravity: "sha256:00"\n')
      utimesSync(this.authFile, AUTH_BEFORE, AUTH_BEFORE)
      this.writePid('mcp.pid', OLD_PID)
      this.writePid('worker.pid', 700)
      this.writePid('scraper_worker.pid', 701)
    } else {
      this.running = false
      this.listeners.clear()
      this.alive.clear()
      this.qdrant = 'absent'
    }
    this.runner = new RecordingRunner({ repoRoot: this.root, env: { HOME: this.home, USER: 'op', LANG: 'en_US.UTF-8' }, spawn: this.spawn, now: () => NOW })
  }

  get pmmcpHome(): string {
    return join(this.home, '.persistent-memory-mcp')
  }

  get authFile(): string {
    return join(this.pmmcpHome, 'http_auth.yaml')
  }

  get py(): string {
    return join(this.dir, '.venv', 'bin', 'python')
  }

  writePid(name: string, pid: number): void {
    writeFileSync(join(this.pmmcpHome, 'pids', name), `${String(pid)}\n`)
  }

  /** The .env writer's own ids for a scratch file: its owner is this process, the operator stands in as the euid. */
  get ids(): { uid: number; euid: number } {
    return { uid: process.getuid?.() ?? OP_UID, euid: OP_UID }
  }

  // ── the programs ──

  #stop(): Reply {
    // Every end but a refusal of its arguments has done its work: a stop that exits 1 or 130 may have stopped everything, and only its exit says it did not finish.
    if (this.stopCode !== 2) {
      for (const port of [...this.listeners.keys()]) if (!this.stopLeaves.includes(port)) this.listeners.delete(port)
      const left = new Set([...this.listeners.values()].flat())
      if (this.stopLeavesWorker) left.add(700)
      for (const pid of [...this.alive]) if (!left.has(pid)) this.alive.delete(pid)
      this.running = this.listeners.has(8766)
      if (this.qdrant === 'running' && !this.stopLeavesQdrant) this.qdrant = 'exited'
      for (const name of ['mcp.pid', ...(this.stopLeavesWorker ? [] : ['worker.pid']), 'scraper_worker.pid']) rmSync(join(this.pmmcpHome, 'pids', name), { force: true })
    }
    return { out: '╔══ pmmcp stop ══╗\nStopped: MCP server, dashboard, curator, worker, Qdrant\n', code: this.stopCode, ...(this.stopSignal === undefined ? {} : { signal: this.stopSignal }) }
  }

  #start(): Reply {
    this.running = true
    this.alive.add(this.startPid)
    this.etimes.set(this.startPid, this.startEtime)
    if (this.startServer) {
      this.listeners.set(8766, [this.startPid])
      const log = join(this.pmmcpHome, 'logs', 'server.log')
      if (this.rotateServerLog && existsSync(log) && statSync(log).size > 0) renameSync(log, `${log}.1`)
    }
    if (this.dashboardUp) this.listeners.set(8765, [this.startPid + 1])
    if (this.curatorUp) this.listeners.set(8767, [this.startPid + 2])
    if (this.startQdrant) this.qdrant = 'running'
    this.writePid('mcp.pid', this.startPid)
    if (this.startWorkers) {
      this.alive.add(WORKER_PID).add(SCRAPER_PID)
      this.writePid('worker.pid', WORKER_PID)
      this.writePid('scraper_worker.pid', SCRAPER_PID)
    }
    for (const line of this.serverLogOnStart) this.logServer(line)
    if (this.kernelAfterStart) this.logServer(firstRequest('aos-kernel'))
    for (const line of this.launchdErrOnStart) this.logLaunchdErr(line)
    return { out: 'OK: pmmcp services are running\n', code: this.startCode }
  }

  /** One line appended to ~/.persistent-memory-mcp/logs/server.log. */
  logServer(line: string): void {
    appendFileSync(join(this.pmmcpHome, 'logs', 'server.log'), `${line}\n`)
  }

  /** One line appended to ~/.persistent-memory-mcp/logs/launchd.err.log, which only grows. */
  logLaunchdErr(line: string): void {
    appendFileSync(join(this.pmmcpHome, 'logs', 'launchd.err.log'), `${line}\n`)
  }

  #rotate(): Reply {
    const stamp = '20261029T100000Z'
    if (existsSync(this.authFile)) writeFileSync(`${this.authFile}.bak-${stamp}`, readFileSync(this.authFile))
    writeFileSync(this.authFile, 'mode: warn\ntokens:\n  antigravity: "sha256:00"\n  aos-kernel: "sha256:11"\n')
    const at = new Date(NOW.getTime() - 30_000)
    utimesSync(this.authFile, at, at)
    return { out: `putting the digest from stdin on file for 'aos-kernel'\n  backup: ${this.authFile}.bak-${stamp}\n` }
  }

  #authInit(only: string | undefined): Reply {
    if (only !== 'curator' && this.auth.dashboard_token === 'absent') this.auth.dashboard_token = 'present'
    if (only !== 'dashboard' && this.auth.curator_secret === 'absent') this.auth.curator_secret = 'present'
    return { out: 'created\n' }
  }

  answerFor(call: Call): Reply {
    const over = this.over.get(call.key)
    const given = typeof over === 'function' ? over(call) : over
    if (given !== undefined) return given
    const py = this.py
    const pid = /^ps -o (etime|pid)= -p (\d+)$/.exec(call.key)
    if (pid !== null) {
      const n = Number(pid[2])
      if (pid[1] === 'etime') {
        const e = this.etimes.get(n)
        return e === undefined || !this.alive.has(n) ? { code: 1 } : { out: `${e}\n` }
      }
      return this.alive.has(n) ? { out: `  ${String(n)}\n` } : { code: 1 }
    }
    const lsof = /^lsof -nP -iTCP:(\d+) -sTCP:LISTEN -Fpu$/.exec(call.key)
    if (lsof !== null) {
      const pids = this.listeners.get(Number(lsof[1])) ?? []
      return pids.length === 0 ? { code: 1 } : { out: pids.map((p) => `p${String(p)}\nu${String(this.listenerUids.get(p) ?? OP_UID)}\nf7\n`).join('') }
    }
    switch (call.key) {
      case join(this.dir, STOP_SCRIPT):
        return this.#stop()
      case `${join(this.dir, STOP_SCRIPT)} --jobs`:
        return this.jobs
      case join(this.dir, START_SCRIPT):
        return this.#start()
      case `${py} scripts/pmmcp_facts.py --json`: {
        const doc = structuredClone(this.updated && this.updatedFacts !== undefined ? this.updatedFacts : this.facts)
        edit(doc, 'dashboard_token', { state: this.auth.dashboard_token })
        edit(doc, 'curator_secret', { state: this.auth.curator_secret })
        return { out: `${JSON.stringify(doc)}\n` }
      }
      case `${py} scripts/rotate_http_auth_token.py aos-kernel --create --digest-stdin`:
        return this.#rotate()
      case `${py} -B -m src.transport.http_auth check --expect aos-kernel`:
        return this.expect
      case `${py} -B -m src.transport.http_auth check`:
        return { out: `${this.authFile}: present; mode warn; tokens [antigravity]\n` }
      case `${py} scripts/qdrant_api_key.py enable --dry-run`:
        return { out: 'dry run: nothing changed\n' }
      case `${py} scripts/qdrant_api_key.py enable`:
        return { out: 'enabled\n' }
      case `${py} scripts/qdrant_api_key.py init`:
        return { out: 'created the key file\n' }
      case `${py} scripts/qdrant_api_key.py cleanup`:
        return { out: 'removed pmmcp-qdrant-prekey\n' }
      case `${py} -B scripts/qdrant_api_key.py status --json`:
        return { out: `${JSON.stringify(this.qdrantAfter)}\n` }
      case `${py} -m src.dashboard.auth init`:
        return this.#authInit(undefined)
      case `${py} -m src.dashboard.auth init --only dashboard`:
        return this.#authInit('dashboard')
      case `${py} -m src.dashboard.auth init --only curator`:
        return this.#authInit('curator')
      case `${py} -B -m src.dashboard.auth status --json`:
        // Exit 1 when a file is unusable, the document printed all the same (installer_interfaces.md).
        return {
          out: `${JSON.stringify({
            auth: 1,
            dashboard_token: { path: join(this.pmmcpHome, 'dashboard_token'), state: this.auth.dashboard_token, reason: this.auth.dashboard_token === 'unusable' ? 'mode 0644' : null },
            curator_secret: { path: join(this.pmmcpHome, 'curator_secret'), state: this.auth.curator_secret, reason: this.auth.curator_secret === 'unusable' ? 'mode 0644' : null },
          })}\n`,
          code: this.auth.dashboard_token === 'unusable' || this.auth.curator_secret === 'unusable' ? 1 : 0,
        }
      case `docker ps --all --filter name=pmmcp-qdrant --format {{.Names}} {{.State}}`:
        return { out: this.qdrant === 'absent' ? '' : `pmmcp-qdrant ${this.qdrant}\n` }
      case 'git --no-optional-locks rev-parse --verify -q HEAD':
        return { out: `${this.head}\n` }
      case 'git --no-optional-locks status --porcelain':
        return { out: '' }
      case `git --no-optional-locks diff --quiet HEAD ${this.originMain} -- uv.lock pyproject.toml`:
        return { code: 0 }
      case `git merge --ff-only ${this.originMain}`:
        this.head = this.originMain
        this.updated = true
        return { out: 'Fast-forward\n' }
      case `git reset --keep ${HEAD}`:
        this.head = HEAD
        this.updated = false
        return {}
      case 'pgrep -f scripts/monitor_tui\\.py':
        return this.tuis.length === 0 ? { code: 1 } : { out: this.tuis.map((p) => `${String(p)}\n`).join('') }
      case `ls -lde ${join(this.root, '.env')}`:
        return { out: [`${this.lsMode}  1 op  staff  210 Oct 29 10:00 ${join(this.root, '.env')}`, ...this.lsAcl, ''].join('\n') }
      case `git clone ${CLONE_URL} ${this.dir}`:
        mkdirSync(join(this.dir, 'logs'), { recursive: true })
        return { err: "Cloning into 'Persistent-Memory-MCP'...\n" }
      case `${join(this.dir, 'setup.sh')} --non-interactive`:
        // setup's launchd load starts the service.
        this.running = true
        this.listeners.set(8766, [OLD_PID])
        this.alive.add(OLD_PID)
        return { out: 'setup complete\n' }
      default:
        return { code: 127, err: `fake: no answer for ${call.key}\n` }
    }
  }

  readonly spawn: SpawnFn = (command, args, options) => {
    const child = new FakeChild(5000 + this.calls.length, options.stdio[0] === 'pipe')
    const call: Call = { key: [command, ...args].join(' '), command, args: [...args], options, stdin: '', active: undefined, child }
    this.calls.push(call)
    const reply = this.answerFor(call)
    if (reply.out !== undefined) writeSync(options.stdio[1], reply.out)
    if (reply.err !== undefined) writeSync(options.stdio[2], reply.err)
    const exit = (): void => {
      setImmediate(() => {
        const read: unknown = child.stdin?.read()
        call.stdin = read === null || read === undefined ? '' : String(read)
        call.active = readActive(this.root)
        if (reply.signal !== undefined) child.emit('exit', null, reply.signal)
        else child.emit('exit', reply.code ?? 0, null)
      })
    }
    if (reply.hold === undefined) exit()
    else void reply.hold.then(exit)
    return child
  }

  /** The GET every HTTP probe makes, over the machine's state. */
  readonly http: HttpGet = (target: HttpTarget): Promise<HttpAnswer> => {
    this.gets.push(`${String(target.port)}${target.path}`)
    const json = (status: number, body: unknown): HttpAnswer => ({ status, body: JSON.stringify(body) })
    const up = (port: number): boolean => (this.listeners.get(port) ?? []).length > 0
    let answer: HttpAnswer = { status: 0, body: '', error: 'ECONNREFUSED' }
    if (target.port === 8766 && up(8766) && target.path === '/health') answer = json(this.calls.some((c) => c.key === join(this.dir, START_SCRIPT)) ? this.health : 200, { status: 'ok' })
    if (target.port === 8765 && up(8765)) {
      const token = this.auth.dashboard_token === 'present'
      if (target.path === '/api/auth/status') answer = json(200, { auth_required: this.authRequired ?? token, source: token ? 'file' : 'none' })
      if (target.path === '/api/fingerprint') answer = json(this.fingerprint ?? (token ? 401 : 200), {})
    }
    if (target.port === 8767 && up(8767) && target.path === '/api/curator/status') answer = json(this.auth.curator_secret === 'present' ? this.curatorWithSecret : 200, {})
    return Promise.resolve(answer)
  }

  // ── discovery's result, the plan, the applier ──

  /** Discovery's result for this machine, as discover() would hand it on. */
  found(): Found {
    const facts = parseFacts(JSON.stringify(this.facts))
    // Read only when the test names no bearer state: a config that declares no AOS_PMMCP_TOKEN cannot ask the writer for it.
    const dotenvHasToken = (): boolean => existsSync(join(this.root, '.env')) && inspectIn(this, ['AOS_PMMCP_TOKEN'], ['AOS_PMMCP_TOKEN']).digests.length > 0
    return {
      kind: 'found',
      install: { dir: this.dir, source: 'plist' },
      staleActive: this.staleActive,
      facts,
      features: featuresOf(facts),
      missing: missingFeatures(facts),
      git: { head: HEAD, originMain: this.originMain, fastForward: this.originMain !== HEAD, lockUnchanged: this.originMain !== HEAD ? true : undefined, trackedChanges: 0, untracked: 0 },
      service: { loaded: true, state: 'running', pid: OLD_PID },
      server: this.discoveredServer ? { pid: OLD_PID, startedAfter: OLD_STARTED_AFTER } : undefined,
      leftStopped: this.leftStopped,
      httpAuthModified: statSync(this.authFile).mtime,
      endpoints: { health: 200, bearer: 'off-or-warn', dashboard: { status: 200, authRequired: false, source: 'none' }, qdrant: { status: 200, version: '1.13.4' } },
      qdrant: parseQdrantStatus(JSON.stringify(this.qdrantBefore)),
      jobs: { state: 'counted', jobs: { running: 0, display: [] } },
      bearer: this.bearer ?? (dotenvHasToken() ? { state: 'matches' } : { state: 'not-checked', why: 'AOS_PMMCP_TOKEN holds no value in .env yet' }),
      kernel: { url: 'http://127.0.0.1:8766/mcp', urlMatches: true, tokenEnv: 'AOS_PMMCP_TOKEN', ollamaShared: [], daemonListening: false },
      notes: [],
    }
  }

  absent(): Absent {
    return {
      kind: 'absent',
      at: this.dir,
      staleActive: undefined,
      searched: ['the plist', 'the listener on 127.0.0.1:8766', this.dir],
      kernel: { url: 'http://127.0.0.1:8766/mcp', urlMatches: true, tokenEnv: 'AOS_PMMCP_TOKEN', ollamaShared: [], daemonListening: false },
      notes: [],
    }
  }

  /** S2 and discovery as the installer would have them, then the planner. */
  plan(): Plan {
    this.discovery = this.installed ? this.found() : this.absent()
    const map = [...credentialsMap(this.config).keys()]
    const screen = inspectIn(this, [...map, 'ANTHROPIC_API_KEY'])
    const room = inspectIn(this, map)
    return planInstall({
      config: this.config,
      providers: PROVIDERS,
      dotenv: screen,
      room,
      exported: new Set(),
      pmmcp: this.discovery,
      tuiPids: [],
      options: { aosOnly: false, noInstall: false },
    })
  }

  applier(plan: Plan, extra: Partial<ApplyOptions> = {}): Applier {
    return new Applier({
      repoRoot: this.root,
      home: this.home,
      runner: this.runner,
      config: this.config,
      providers: PROVIDERS,
      plan,
      discovery: this.discovery,
      print: (line) => this.printed.push(line),
      ask: (question) => {
        this.asked.push(question)
        this.askedInWindow.push(this.windows.at(-1) === true)
        return Promise.resolve(this.answer)
      },
      uid: OP_UID,
      inspect: this.ids,
      http: this.http,
      now: () => NOW,
      sleep: () => Promise.resolve(),
      mint: () => {
        const v = randomBytes(32).toString('hex')
        this.minted.push(v)
        return v
      },
      window: (open) => this.windows.push(open),
      ...extra,
    })
  }

  /** .env written beforehand by the writer, as an earlier run would have left it: both tokens. */
  preEnv(): void {
    appendIn(this)
  }

  /** The calls whose command line matches, in order. */
  ran(pattern: RegExp): Call[] {
    return this.calls.filter((c) => pattern.test(c.key))
  }

  indexOf(pattern: RegExp): number {
    return this.calls.findIndex((c) => pattern.test(c.key))
  }

  text(): string {
    return this.printed.join('\n')
  }
}

/** The only way these tests write a .env themselves: every minted name, into a scratch directory under the OS temp dir, never this checkout. */
function appendIn(m: Machine): void {
  const real = realpathSync(m.root)
  assert.ok(real.startsWith(realpathSync(osTmpdir()) + sep), `${m.root} is not a scratch directory`)
  const checkout = realpathSync(REPO_ROOT)
  assert.ok(real !== checkout && !real.startsWith(checkout + sep), `${m.root} is this checkout`)
  appendCredentials({
    repoRoot: m.root,
    accepted: credentialNames(m.config, PROVIDERS),
    generate: new Map([...mintedCredentialNames(m.config)].map((n) => [n, (): string => randomBytes(32).toString('hex')])),
    generatable: mintedCredentialNames(m.config),
    providers: PROVIDERS,
    ...m.ids,
  })
}

/** The writer's inspection, held to scratch directories as appendIn is. */
function inspectIn(m: Machine, names: readonly string[], digests: readonly string[] = []): InspectResult {
  const real = realpathSync(m.root)
  assert.ok(real.startsWith(realpathSync(osTmpdir()) + sep), `${m.root} is not a scratch directory`)
  const checkout = realpathSync(REPO_ROOT)
  assert.ok(real !== checkout && !real.startsWith(checkout + sep), `${m.root} is this checkout`)
  return inspectCredentials({ repoRoot: m.root, accepted: credentialNames(m.config, PROVIDERS), names, digests, ...m.ids })
}

const sha256 = (value: string): string => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`

/** pmmcp's line for a client's first request with its bearer (src/transport/http_auth.py), as structlog writes it. */
const firstRequest = (token: string): string => JSON.stringify({ event: 'http auth: first request with token', token, mode: 'warn', level: 'info' })

/** A reply for the first call only; later calls are the machine's. */
function once(reply: Reply): (call: Call) => Reply | undefined {
  let used = false
  return () => {
    if (used) return undefined
    used = true
    return reply
  }
}

/** The end report's line for a step skipped as not reached, by a piece of its name. */
const notReached = (report: readonly string[], what: RegExp, why: RegExp): boolean => report.some((l) => /^ {2}skipped {5}/.test(l) && what.test(l) && /not reached: /.test(l) && why.test(l))

/** The steps a set of answers selects, the way the gate hands them on. */
function chosen(plan: Plan, offers: readonly OfferId[]): { nonLive: readonly Step[]; live: readonly Step[] } {
  return select(plan, new Set(offers))
}

const itemNamed = (items: readonly Item[], pattern: RegExp): Item => {
  const item = items.find((i) => pattern.test(i.what))
  if (item === undefined) assert.fail(`no item matches ${String(pattern)}: ${JSON.stringify(items)}`)
  return item
}

/** A plan whose only live item is the restart: .env holds both tokens, the digest is on file, and the server started before it was. */
function restartOnly(m: Machine): Plan {
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const plan = m.plan()
  assert.deepEqual(
    plan.offers.map((o) => o.id),
    ['restart'],
    JSON.stringify(plan.notes),
  )
  return plan
}

/** A plan whose live items are the update and the files that wait for it: dfcc99a's facts, origin/main one fast-forward ahead. */
function updating(m: Machine): Plan {
  m.preEnv()
  m.bearer = { state: 'matches' }
  edit(m.facts, 'features.curator_proof')
  edit(m.facts, 'features.stop_listener_check')
  m.originMain = ORIGIN_MAIN
  m.updatedFacts = factsDoc(m.dir, m.home)
  const plan = m.plan()
  assert.deepEqual(chosen(plan, ['update', 'auth-after-update']).live.map((s) => s.id), ['stop', 'update', 'auth-init', 'start', 'bearer-check'])
  return plan
}

/** A plan whose one live item is the Qdrant cutover: .env complete, the digest on file, both auth files there. */
function cutoverOnly(m: Machine): Plan {
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.qdrantBefore = keyless()
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const plan = m.plan()
  assert.deepEqual(chosen(plan, ['qdrant']).live.map((s) => s.id), ['stop', 'qdrant-enable', 'start', 'bearer-check'])
  return plan
}

/** The cutover alone, with whatever bearer state the machine already names: no restart is asked beside it. */
function cutoverOnlyWith(m: Machine): Plan {
  m.preEnv()
  m.qdrantBefore = keyless()
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const plan = m.plan()
  assert.deepEqual(plan.offers.map((o) => o.id), ['qdrant'], JSON.stringify(plan.notes))
  return plan
}

const THIRD = 'f00dfac'.padEnd(40, '0')

// ── S5: the non-live steps ───────────────────────────────────────────────

test('the non-live steps create .env through the writer, stage the digest it returns on stdin, and confirm it with check --expect; a .env that changed since the plan is refused with exit 2', async (t) => {
  const m = new Machine(t)
  const plan = m.plan()
  assert.deepEqual(plan.generate, ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN'])
  const { nonLive } = chosen(plan, [])
  assert.deepEqual(nonLive.map((s) => s.id), ['env', 'stage-digest'])
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', nonLive), { ok: true })

  const env = join(m.root, '.env')
  assert.equal(statSync(env).mode & 0o777, 0o600)
  const text = readFileSync(env, 'utf8')
  assert.match(text, /^AOS_CONTROL_TOKEN=[0-9a-f]{64}$/m)
  assert.match(text, /^AOS_PMMCP_TOKEN=[0-9a-f]{64}$/m)
  // pmmcp got the digest of the token .env now holds, on stdin, and nothing else.
  const pmmcpToken = m.minted[1] ?? ''
  const [rotate] = m.ran(/rotate_http_auth_token\.py aos-kernel --create --digest-stdin$/)
  assert.ok(rotate !== undefined)
  assert.equal(rotate.stdin, `${sha256(pmmcpToken)}\n`)
  assert.equal(rotate.options.stdio[0], 'pipe')
  const [expect] = m.ran(/check --expect aos-kernel$/)
  assert.ok(expect !== undefined && m.calls.indexOf(expect) > m.calls.indexOf(rotate), 'the digest was not checked after the rotate')
  assert.equal(expect.stdin, `${sha256(pmmcpToken)}\n`)
  assert.equal(itemNamed(applier.items, /digest staged/).state, 'done')
  // No value anywhere the installer shows or keeps.
  const shown = [...m.printed, ...applier.report(), ...m.calls.flatMap((c) => [c.key, ...Object.values(c.options.env)])].join('\n')
  for (const v of m.minted) assert.equal(shown.includes(v), false, 'a minted token was shown')

  // A .env made looser after the plan: the writer refuses, nothing changes, exit 2.
  const m2 = new Machine(t)
  const plan2 = m2.plan()
  writeFileSync(join(m2.root, '.env'), '# mine\n', { mode: 0o644 })
  const before = readFileSync(join(m2.root, '.env'))
  const refused = await m2.applier(plan2).apply('non-live', chosen(plan2, []).nonLive)
  assert.deepEqual(refused, { ok: false, exitCode: 2 })
  assert.deepEqual(readFileSync(join(m2.root, '.env')), before)
  assert.equal(m2.ran(/rotate_http_auth_token/).length, 0, 'a digest was staged after the .env was refused')
})

test('rotate exit 130 is re-checked with --expect, whichever way stderr says it ended', async (t) => {
  const cases = [
    { err: 'interrupted: every file this run wrote was put back\n', verdict: { out: 'aos-kernel: matches\n', code: 0 }, staged: true },
    { err: 'interrupted after the new digest was written: restart pmmcp to load it\n', verdict: { out: 'aos-kernel: absent\n', code: 3 }, staged: false },
    { err: 'stopped (OSError()) after the new digest was written: restart pmmcp to load it\n', verdict: { out: 'aos-kernel: matches\n', code: 0 }, staged: true, code: 4 },
    // Ended by a signal, with no word of what it did: the check decides that too.
    { err: '', verdict: { out: 'aos-kernel: matches\n', code: 0 }, staged: true, signal: 'SIGTERM' as const },
  ]
  for (const c of cases) {
    const m = new Machine(t)
    const plan = m.plan()
    m.over.set(`${m.py} scripts/rotate_http_auth_token.py aos-kernel --create --digest-stdin`, c.signal === undefined ? { err: c.err, code: c.code ?? 130 } : { signal: c.signal })
    m.expect = c.verdict
    const applier = m.applier(plan)
    const result = await applier.apply('non-live', chosen(plan, []).nonLive)
    // The check ran after the rotate in every case: its verdict, never the rotate's stderr, decides.
    assert.ok(m.indexOf(/check --expect aos-kernel$/) > m.indexOf(/rotate_http_auth_token/), c.err)
    const item = itemNamed(applier.items, /digest staged/)
    assert.equal(item.state, c.staged ? 'done' : 'failed', c.err)
    assert.deepEqual(result, c.staged ? { ok: true } : { ok: false, exitCode: 1 }, c.err)
  }
})

// ── S6: the jobs check ───────────────────────────────────────────────────

test("the jobs count reads stdout's first line alone, after clearing the stale record discovery found, and a Ctrl-C while it runs answers interrupt", async (t) => {
  const m = new Machine(t)
  const plan = restartOnly(m)
  // An earlier run's record whose pid no longer runs it: discovery hands it back as staleActive.
  const record: ActiveRecord = { step: 'stop', pid: 4321, started: '2026-10-28T09:00:00.000Z', out: '/x/stop.out', err: '/x/stop.err' }
  mkdirSync(join(m.root, '.aos', 'install'), { recursive: true, mode: 0o700 })
  writeFileSync(activePath(m.root), JSON.stringify(record), { mode: 0o600 })
  m.discovery = { ...(m.discovery as Found), staleActive: record }
  m.jobs = { err: 'running jobs: 9\n[WARN] the listener on 8765 is not this checkout\'s dashboard, so nothing was sent\n', out: 'running jobs: 2\n  j1  index  aos  40%\n  j2  scrape  web  10%\n' }
  const applier = m.applier(plan)
  const count = await applier.countJobs()
  assert.deepEqual(count, { state: 'counted', running: 2, display: ['  j1  index  aos  40%', '  j2  scrape  web  10%'] })
  const [jobs] = m.ran(/stop-pmmcp-server\.sh --jobs$/)
  assert.ok(jobs !== undefined)
  assert.equal(jobs.options.detached, true)
  assert.equal(readActive(m.root).state, 'none')

  // A count that says unknown carries its stderr; and one the operator interrupts answers interrupt, whatever the child does next.
  m.jobs = { err: 'registry.db: the config cannot be read\n', out: 'running jobs: unknown\n', code: 1 }
  const unknown = await applier.countJobs()
  assert.equal(unknown.state, 'unknown')
  assert.ok(unknown.state === 'unknown' && unknown.stderr.some((l) => l.includes('registry.db')))

  let release: () => void = () => undefined
  m.jobs = { out: 'running jobs: 0\n', hold: new Promise<void>((r) => (release = r)) }
  const interrupt = new AbortController()
  const pending = m.applier(plan, { interrupt: interrupt.signal }).countJobs()
  interrupt.abort()
  assert.deepEqual(await pending, { state: 'interrupt' } satisfies JobsAnswer)
  // The count runs on in its own session: an installer that leaves now leaves its record, marked read-only, which a re-run clears once its pid has ended.
  const left = readActive(m.root)
  assert.equal(left.state, 'recorded')
  assert.ok(left.state === 'recorded' && left.record.readOnly === true && /^stop-jobs/.test(left.record.step), JSON.stringify(left))
  release()
})

// ── S7: the window ───────────────────────────────────────────────────────

test('a stop that exits 0 with 8766 still listening ends the run before any further change and offers start', async (t) => {
  // 8766 left listening, and each other thing L1 checks: a stop that exits 0 with any of them is no stop.
  const leftovers: readonly { readonly name: string; readonly setup: (m: Machine) => void; readonly detail: RegExp }[] = [
    { name: '8766 still listened on', setup: (m) => (m.stopLeaves = [8766]), detail: /8766 is still listened on \(pid 812\)/ },
    { name: '8765 still listened on', setup: (m) => (m.stopLeaves = [8765]), detail: /8765 is still listened on \(pid 813\)/ },
    { name: '8767 still listened on', setup: (m) => (m.stopLeaves = [8767]), detail: /8767 is still listened on \(pid 814\)/ },
    { name: 'pmmcp-qdrant still running', setup: (m) => (m.stopLeavesQdrant = true), detail: /pmmcp-qdrant is still running/ },
    { name: 'a worker.pid naming a live process', setup: (m) => (m.stopLeavesWorker = true), detail: /pids\/worker\.pid names pid 700, which still runs/ },
    {
      name: 'a worker.pid whose process ps cannot tell about',
      setup: (m) => {
        m.stopLeavesWorker = true
        m.over.set('ps -o pid= -p 700', { code: 2, err: 'ps: cannot read the process table\n' })
      },
      detail: /whether pid 700 \(pids\/worker\.pid\) runs cannot be told/,
    },
    {
      name: 'lsof that cannot say what listens',
      setup: (m) => m.over.set('lsof -nP -iTCP:8765 -sTCP:LISTEN -Fpu', { code: 2, err: 'lsof: unsupported option\n' }),
      detail: /what listens on 8765 cannot be checked \(lsof exited 2\)/,
    },
    {
      // Docker that cannot be asked is no proof Qdrant stopped.
      name: 'docker that cannot be asked',
      setup: (m) => m.over.set('docker ps --all --filter name=pmmcp-qdrant --format {{.Names}} {{.State}}', { code: 1, err: 'Cannot connect to the Docker daemon\n' }),
      detail: /whether pmmcp-qdrant runs cannot be checked/,
    },
  ]
  // A Ctrl-C at the question is a no, as EOF is.
  const answers = [{ kind: 'line', text: '' }, { kind: 'line', text: 'n' }, { kind: 'eof' }, { kind: 'interrupt' }] as const
  for (const leftover of leftovers) {
    // Every answer for 8766; one for the rest.
    for (const answer of leftover === leftovers[0] ? answers : answers.slice(1, 2)) {
      const label = `${leftover.name}, ${JSON.stringify(answer)}`
      const m = new Machine(t)
      m.qdrantBefore = keyless()
      const plan = m.plan()
      const { nonLive, live } = chosen(plan, ['qdrant', 'auth', 'restart'])
      assert.deepEqual(live.map((s) => s.id), ['stop', 'qdrant-enable', 'auth-init', 'start', 'bearer-check'])
      leftover.setup(m)
      m.answer = answer
      const applier = m.applier(plan)
      assert.deepEqual(await applier.apply('non-live', nonLive), { ok: true })
      const result = await applier.apply('live', live)
      assert.deepEqual(result, { ok: false, exitCode: 4 }, label)
      assert.equal(itemNamed(applier.items, /graceful stop/).state, 'failed', label)
      assert.match(itemNamed(applier.items, /graceful stop/).detail, leftover.detail, label)
      // Nothing of the window ran: no cutover, no auth init.
      assert.equal(m.ran(/qdrant_api_key\.py enable|src\.dashboard\.auth init/).length, 0, label)
      // Asked with the window closed: a Ctrl-C there is a no, never trapped as the window's.
      assert.deepEqual(m.asked, ['start pmmcp again to restore service? [Y/n]'], label)
      assert.deepEqual(m.askedInWindow, [false], label)
      const starts = m.ran(new RegExp(`${START_SCRIPT}$`))
      if (answer.kind === 'line' && answer.text === '') {
        // The default is yes: only the start runs, bare, in a window opened again for it.
        assert.equal(starts.length, 1, label)
        assert.deepEqual(starts[0]?.args, [], label)
        assert.deepEqual(m.windows, [true, false, true, false], label)
      } else {
        assert.equal(starts.length, 0, `${label} started pmmcp`)
        assert.ok(applier.report().some((l) => l.includes(`./start-pmmcp-server.sh`)), label)
        assert.deepEqual(m.windows, [true, false], label)
      }
      // Every step of the window the stop kept from running has its line, and why.
      const report = applier.report()
      for (const what of [/the Qdrant key cutover/, /the dashboard token and curator secret/, /the start \(start-pmmcp-server\.sh\) and its checks/, /bearer check/]) {
        assert.ok(notReached(report, what, /the stop did not stop pmmcp/), `${label}: no skipped line for ${String(what)}:\n${report.join('\n')}`)
      }
      if (answer.kind === 'line' && answer.text === '') assert.equal(itemNamed(applier.items, /start pmmcp again/).state, 'done', label)
    }
  }

  // Started again, but /health does not answer 200: no service is restored, and the manual start is left to do.
  const sick = new Machine(t)
  const plan = restartOnly(sick)
  sick.stopLeaves = [8767]
  sick.health = 503
  sick.answer = { kind: 'line', text: 'y' }
  const applier = sick.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: false, exitCode: 4 })
  const again = itemNamed(applier.items, /start pmmcp again/)
  assert.equal(again.state, 'failed')
  assert.match(again.detail, /exit 0; \/health answered 503/)
  assert.ok(applier.report().some((l) => /^ {2}start pmmcp: cd .* && \.\/start-pmmcp-server\.sh$/.test(l)), applier.report().join('\n'))
})

test('stop is never re-run with --force and never interrupted on SIGINT', async (t) => {
  const m = new Machine(t)
  const plan = restartOnly(m)
  const { live } = chosen(plan, ['restart'])
  let release: () => void = () => undefined
  m.stopCode = 1
  m.stopLeaves = [8767]
  m.over.set(join(m.dir, STOP_SCRIPT), () => {
    const reply = { out: 'FAILED TO STOP: curator (8767)\n', code: 1, hold: new Promise<void>((r) => (release = r)) }
    m.listeners.delete(8766)
    m.listeners.delete(8765)
    m.running = false
    return reply
  })
  m.answer = { kind: 'line', text: 'n' }
  const interrupt = new AbortController()
  const applier = m.applier(plan, { interrupt: interrupt.signal })
  let settled = false
  const pending = applier.apply('live', live).then((r) => {
    settled = true
    return r
  })
  await new Promise((r) => setImmediate(r))
  // The operator's Ctrl-C arrives while the stop runs: the window was opened for the installer to trap it, and it changes nothing here.
  assert.deepEqual(m.windows, [true])
  interrupt.abort()
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r))
  assert.equal(settled, false, 'the window ended before the stop did')
  const [stop] = m.ran(new RegExp(`${STOP_SCRIPT}$`))
  assert.ok(stop !== undefined)
  assert.deepEqual(stop.child.kills, [], 'the stop was signalled')
  assert.equal(stop.options.detached, true)
  release()
  assert.deepEqual(await pending, { ok: false, exitCode: 4 })
  assert.deepEqual(m.windows, [true, false])
  // One stop, bare: never again, never with --force, and no timeout was asked for it.
  const stops = m.ran(/stop-pmmcp-server\.sh/)
  assert.deepEqual(stops.map((c) => c.args), [[]])
  assert.equal(m.calls.some((c) => c.args.some((a) => /^--force$|^-f$|kickstart/.test(a))), false)
  const spec = m.runner.specs.find((s) => s.command === join(m.dir, STOP_SCRIPT))
  assert.ok(spec !== undefined && spec.timeoutMs === undefined)
  assert.match(itemNamed(applier.items, /graceful stop/).detail, /FAILED TO STOP \(exit 1\)/)
})

test('a start that exits 0 without /health 200, Qdrant running and the worker and scraper alive is reported failed', async (t) => {
  const m = new Machine(t)
  const plan = restartOnly(m)
  m.health = 503
  m.startQdrant = false
  m.startWorkers = false
  const applier = m.applier(plan)
  const result = await applier.apply('live', chosen(plan, ['restart']).live)
  assert.deepEqual(result, { ok: false, exitCode: 4 })
  const start = itemNamed(applier.items, /the start/)
  assert.equal(start.state, 'failed')
  assert.match(start.detail, /\/health answered 503/)
  assert.match(start.detail, /pmmcp-qdrant is not running/)
  assert.match(start.detail, /the worker is not running/)
  assert.match(start.detail, /the scraper worker is not running/)
  // /health was asked again a few times before it was called failed.
  assert.equal(m.gets.filter((g) => g === '8766/health').length, PROBE_TRIES)
  assert.ok(m.text().includes('./start-pmmcp-server.sh'), 'no way on was printed')
  // The start ran: it re-enabled launchd, and may have brought part of pmmcp up.
  assert.ok(m.text().includes('pmmcp may be partly up (the start script re-enabled launchd)'), m.text())
  assert.ok(notReached(applier.report(), /bearer check/, /the start, or a check after it, failed/), applier.report().join('\n'))

  // And all of them in place: done.
  const ok = new Machine(t)
  const plan2 = restartOnly(ok)
  const applier2 = ok.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['restart']).live), { ok: true })
  assert.equal(itemNamed(applier2.items, /the start/).state, 'done')
})

test("the token counts as loaded only when the MCP pid changed and started after http_auth.yaml's mtime", async (t) => {
  /** A window for the cutover alone, on a server discovery found had loaded http_auth.yaml: it started after the file last changed. */
  const loadedCutover = (m: Machine): Plan => {
    const longAgo = new Date(NOW.getTime() - 3 * 60 * 60 * 1000)
    utimesSync(m.authFile, longAgo, longAgo)
    return cutoverOnly(m)
  }
  const cases: readonly { readonly name: string; readonly plan: (m: Machine) => Plan; readonly offers: readonly OfferId[]; readonly setup: (m: Machine) => void; readonly shown: 'yes' | 'no' | 'not known'; readonly exitCode: 0 | 4 }[] = [
    { name: 'a new pid, started after the file changed', plan: restartOnly, offers: ['restart'], setup: () => undefined, shown: 'yes', exitCode: 0 },
    {
      // As young as a new one would be: only its being the pid discovery found tells it from a restarted server.
      name: 'the same pid',
      plan: restartOnly,
      offers: ['restart'],
      setup: (m) => {
        m.startPid = OLD_PID
        m.startEtime = '00:07'
      },
      shown: 'no',
      exitCode: 4,
    },
    {
      name: 'a new pid that cannot be shown to have started after the file changed',
      plan: restartOnly,
      offers: ['restart'],
      // The file last changed after the earliest the new server can have started (ps etime is a lower bound).
      setup: (m) => utimesSync(m.authFile, NOW, NOW),
      shown: 'no',
      exitCode: 4,
    },
    { name: 'a new pid whose start ps cannot read', plan: restartOnly, offers: ['restart'], setup: (m) => m.over.set(`ps -o etime= -p ${String(NEW_PID)}`, { out: 'soon\n' }), shown: 'no', exitCode: 4 },
    // A server discovery found loaded is no proof for what runs after the stop.
    { name: 'loaded before the window, and the new server started after the file changed', plan: loadedCutover, offers: ['qdrant'], setup: () => undefined, shown: 'yes', exitCode: 0 },
    { name: 'loaded before the window, and the start leaves nothing on 8766', plan: loadedCutover, offers: ['qdrant'], setup: (m) => (m.startServer = false), shown: 'no', exitCode: 4 },
    {
      name: 'loaded before the window, the stop stopped the server but not the dashboard, and the start is declined',
      plan: loadedCutover,
      offers: ['qdrant'],
      setup: (m) => {
        m.stopLeaves = [8765]
        m.answer = { kind: 'line', text: 'n' }
      },
      shown: 'not known',
      exitCode: 4,
    },
  ]
  for (const c of cases) {
    const m = new Machine(t)
    const plan = c.plan(m)
    c.setup(m)
    const applier = m.applier(plan)
    const result = await applier.apply('live', chosen(plan, c.offers).live)
    const line = applier.report().find((l) => l.includes('loaded by the running server'))
    assert.ok(line !== undefined, c.name)
    assert.match(line, new RegExp(`aos-kernel digest matches \\.env: yes; loaded by the running server: ${c.shown}$`), c.name)
    assert.deepEqual(result, c.exitCode === 0 ? { ok: true } : { ok: false, exitCode: c.exitCode }, c.name)
  }
  // Why each start failed, where it did.
  const why = async (setup: (m: Machine) => void): Promise<string> => {
    const m = new Machine(t)
    const plan = restartOnly(m)
    setup(m)
    const applier = m.applier(plan)
    await applier.apply('live', chosen(plan, ['restart']).live)
    return itemNamed(applier.items, /the start/).detail
  }
  assert.match(await why((m) => (m.startPid = OLD_PID)), /the MCP server is still pid 812, the one that ran before the stop/)
  assert.match(await why((m) => utimesSync(m.authFile, NOW, NOW)), /cannot be shown to have started after http_auth\.yaml last changed/)
  assert.match(await why((m) => m.over.set(`ps -o etime= -p ${String(NEW_PID)}`, { out: 'soon\n' })), /when the MCP server \(pid 913\) started cannot be read \(ps etime\)/)
  // A listener on 8766 of another account is no MCP server of this one's, however young.
  assert.match(await why((m) => m.listenerUids.set(NEW_PID, OP_UID + 1)), /no MCP server of this account listens on 8766/)
})

test('after a cutover, any verdict but enforced is a failure that names rollback', async (t) => {
  for (const verdict of ['not_asked', 'inconsistent', 'not_running']) {
    const m = new Machine(t)
    m.preEnv()
    m.bearer = { state: 'matches' }
    m.qdrantBefore = keyless()
    m.auth.dashboard_token = 'present'
    m.auth.curator_secret = 'present'
    edit(m.facts, 'dashboard_token', { state: 'present' })
    edit(m.facts, 'curator_secret', { state: 'present' })
    const plan = m.plan()
    const { live } = chosen(plan, ['qdrant'])
    assert.deepEqual(live.map((s) => s.id), ['stop', 'qdrant-enable', 'start', 'bearer-check'])
    m.qdrantAfter = edit(enforced(), 'verdict', verdict)
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 }, verdict)
    assert.equal(itemNamed(applier.items, /Qdrant key cutover/).state, 'done', verdict)
    const start = itemNamed(applier.items, /the start/)
    assert.equal(start.state, 'failed', verdict)
    assert.match(start.detail, new RegExp(`verdict is ${verdict}, not enforced`), verdict)
    assert.match(start.detail, /qdrant_api_key\.py rollback/, verdict)
    // The way back is printed too, and the report keeps it.
    assert.ok(m.text().includes('qdrant_api_key.py rollback'), verdict)
    assert.ok(applier.report().some((l) => l.includes('qdrant_api_key.py rollback')), verdict)
  }
})

test("qdrant enable exit 3 stops the run without starting pmmcp and prints the script's instructions", async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.qdrantBefore = keyless()
  const plan = m.plan()
  const { live } = chosen(plan, ['qdrant', 'auth'])
  assert.deepEqual(live.map((s) => s.id), ['stop', 'qdrant-enable', 'auth-init', 'start', 'bearer-check'])
  m.over.set(`${m.py} scripts/qdrant_api_key.py enable`, {
    out: 'swapping pmmcp-qdrant\n',
    err: 'FAILED and could not put the old container back.\nTo put it back by hand: docker rm -f pmmcp-qdrant && docker rename pmmcp-qdrant-prekey pmmcp-qdrant\n',
    code: 3,
  })
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 })
  assert.equal(m.ran(new RegExp(`${START_SCRIPT}$`)).length, 0, 'pmmcp was started')
  assert.equal(m.ran(/src\.dashboard\.auth init/).length, 0, 'L4 ran after a failed cutover')
  assert.ok(m.printed.some((l) => l.includes('docker rename pmmcp-qdrant-prekey pmmcp-qdrant')), "the script's instructions were not printed")
  assert.equal(itemNamed(applier.items, /Qdrant key cutover/).state, 'failed')
  assert.deepEqual(m.windows, [true, false])
  const report = applier.report()
  for (const what of [/the dashboard token and curator secret/, /the start \(start-pmmcp-server\.sh\) and its checks/, /bearer check/]) {
    assert.ok(notReached(report, what, /the Qdrant cutover failed and could not put everything back/), `no skipped line for ${String(what)}:\n${report.join('\n')}`)
  }
})

test('a re-run after a failure picks up from the state on disk', async (t) => {
  // The first run: .env made, the digest staged, then a stop that FAILED TO STOP.
  const m = new Machine(t)
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const first = m.plan()
  assert.deepEqual(first.steps.map((s) => s.id), ['env', 'stage-digest', 'stop', 'start', 'bearer-check'])
  m.stopCode = 1
  m.stopLeaves = [8766, 8765, 8767]
  m.answer = { kind: 'line', text: 'n' }
  const one = m.applier(first)
  const io = (applier: Applier, answers: (q: string) => string): GateIO => ({
    interactive: true,
    print: (line) => m.printed.push(line),
    ask: (q) => {
      m.asked.push(q)
      return Promise.resolve({ kind: 'line', text: answers(q) })
    },
    countJobs: () => applier.countJobs(),
    pause: () => Promise.resolve('elapsed'),
    apply: (phase, steps) => applier.apply(phase, steps),
  })
  const yes = (q: string): string => (q.includes('`stop pmmcp`') ? 'stop pmmcp' : q.includes('`Persistent-Memory-MCP`') ? 'Persistent-Memory-MCP' : 'y')
  const outcome1 = await runGate(first, io(one, yes), { dryRun: false })
  assert.equal(outcome1.kind, 'failed')
  assert.equal(outcome1.exitCode, 4)
  const env = readFileSync(join(m.root, '.env'))
  const rotations = m.ran(/rotate_http_auth_token/).length
  assert.equal(rotations, 1)

  // The re-run: discovery reads what the first run left (both tokens in .env, the digest on file, the old server still running).
  m.stopCode = 0
  m.stopLeaves = []
  m.bearer = { state: 'matches' }
  const second = m.plan()
  assert.deepEqual(second.generate, [], 'a token present in .env is generated again')
  assert.equal(second.staged, undefined, 'a digest on file is staged again')
  assert.deepEqual(second.steps.map((s) => s.id), ['stop', 'start', 'bearer-check'])
  const two = m.applier(second)
  const outcome2 = await runGate(second, io(two, yes), { dryRun: false })
  assert.equal(outcome2.kind, 'done', JSON.stringify(two.items))
  assert.deepEqual(readFileSync(join(m.root, '.env')), env, 'the re-run changed .env')
  assert.equal(m.ran(/rotate_http_auth_token/).length, rotations, 'the re-run staged the digest again')
  assert.ok(two.report().some((l) => /loaded by the running server: yes/.test(l)))
})

test('after an L2 update, http_auth check runs with the new code before L5, and its exit 1 stops the run before any start, naming the token', async (t) => {
  /** pmmcp's refusal of a token-like name (src/transport/http_auth.py): given by its line, never quoted. */
  const refusal = (m: Machine): string =>
    `invalid: ${m.authFile}: token name on line 4 (a str of 36 characters, not shown) looks like a token, not a name; name the client instead, such as aos-kernel\n`
  const token = 'mac-0123456789abcdef0123456789abcdef'
  // The old revision is offered, default no, with the window closed: no, an empty line, EOF and Ctrl-C all put nothing back and start nothing.
  const answers: readonly Answer[] = [{ kind: 'line', text: 'n' }, { kind: 'line', text: '' }, { kind: 'eof' }, { kind: 'interrupt' }]
  for (const answer of answers) {
    const label = JSON.stringify(answer)
    const m = new Machine(t)
    m.preEnv()
    m.bearer = { state: 'matches' }
    // dfcc99a's facts: neither the curator proof nor the listener check, so the files wait for the update.
    edit(m.facts, 'features.curator_proof')
    edit(m.facts, 'features.stop_listener_check')
    m.originMain = ORIGIN_MAIN
    m.updatedFacts = factsDoc(m.dir, m.home)
    // The token-like name is in the file; pmmcp never repeats it.
    writeFileSync(m.authFile, `mode: warn\ntokens:\n  antigravity: "sha256:00"\n  ${token}: "sha256:22"\n`)
    utimesSync(m.authFile, AUTH_BEFORE, AUTH_BEFORE)
    m.answer = answer
    const plan = m.plan()
    const { live } = chosen(plan, ['update', 'auth-after-update'])
    assert.deepEqual(live.map((s) => s.id), ['stop', 'update', 'auth-init', 'start', 'bearer-check'])
    m.over.set(`${m.py} -B -m src.transport.http_auth check`, { err: refusal(m), code: 1 })
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 }, label)
    // In order: the fast-forward, the facts with the new code, then the check; no start, no auth init.
    const merge = m.indexOf(/^git merge --ff-only /)
    const facts = m.indexOf(/pmmcp_facts\.py --json$/)
    const check = m.indexOf(/src\.transport\.http_auth check$/)
    assert.ok(merge >= 0 && facts > merge && check > facts, `order: merge ${String(merge)}, facts ${String(facts)}, check ${String(check)}`)
    assert.equal(m.ran(new RegExp(`${START_SCRIPT}$`)).length, 0, `${label}: pmmcp was started on a file the new code refuses`)
    assert.equal(m.ran(/src\.dashboard\.auth init/).length, 0, label)
    // pmmcp's own line is shown, naming the line of the token to rename; the name itself appears nowhere.
    assert.ok(m.printed.some((l) => l.includes('token name on line 4 (a str of 36 characters, not shown) looks like a token, not a name')), `${label}: the refusal was not shown:\n${m.text()}`)
    assert.ok(m.printed.some((l) => l.includes('rename the token on the line it names')), label)
    assert.equal([...m.printed, ...applier.report()].some((l) => l.includes(token)), false, label)
    assert.ok(m.printed.some((l) => l.includes(`reset --keep ${HEAD}`) && l.includes('./start-pmmcp-server.sh')), 'the old revision was not offered')
    assert.equal(itemNamed(applier.items, /http_auth check with the updated code/).state, 'failed', label)
    assert.deepEqual(m.asked, [`start the old revision (${HEAD.slice(0, 7)}) now? [y/N]`], label)
    assert.deepEqual(m.askedInWindow, [false], label)
    assert.equal(m.ran(/^git reset /).length, 0, label)
    assert.deepEqual(m.windows, [true, false], label)
    const report = applier.report()
    for (const what of [/where the updated pmmcp supports them/, /the start \(start-pmmcp-server\.sh\) and its checks/, /bearer check/]) {
      assert.ok(notReached(report, what, /the updated pmmcp refuses http_auth\.yaml, so pmmcp was not started/), `${label}: no skipped line for ${String(what)}:\n${report.join('\n')}`)
    }
  }

  // A yes puts the head discovery found back, in its own session, and goes straight to the start on the old code.
  const y = new Machine(t)
  y.preEnv()
  y.bearer = { state: 'matches' }
  edit(y.facts, 'features.curator_proof')
  edit(y.facts, 'features.stop_listener_check')
  y.originMain = ORIGIN_MAIN
  // The updated code would serve on another port: once the old revision is back, its facts are the ones the start is checked by.
  y.updatedFacts = edit(factsDoc(y.dir, y.home), 'config.server.port', 8769)
  y.over.set(`${y.py} -B -m src.transport.http_auth check`, () => (y.updated ? { err: refusal(y), code: 1 } : undefined))
  y.answer = { kind: 'line', text: 'y' }
  const plan2 = y.plan()
  const applier2 = y.applier(plan2)
  // The old revision started and checked: the update is the one item that failed, and pmmcp runs (exit 1).
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['update', 'auth-after-update']).live), { ok: false, exitCode: 1 }, JSON.stringify(applier2.items))
  const [reset] = y.ran(/^git reset --keep /)
  assert.ok(reset !== undefined && reset.args.at(-1) === HEAD)
  const resetSpec = y.runner.specs.find((s) => s.command === 'git' && s.args[0] === 'reset')
  assert.ok(resetSpec?.ownSession === true && resetSpec.timeoutMs === undefined)
  assert.ok(y.indexOf(new RegExp(`${START_SCRIPT}$`)) > y.calls.indexOf(reset))
  assert.equal(y.ran(/src\.dashboard\.auth init/).length, 0)
  assert.equal(itemNamed(applier2.items, /the old revision put back/).state, 'done')
  assert.equal(itemNamed(applier2.items, /the start/).state, 'done')
  assert.deepEqual(y.windows, [true, false, true, false])
  assert.ok(notReached(applier2.report(), /where the updated pmmcp supports them/, /the old revision was put back and started instead/), applier2.report().join('\n'))
  // Back on the old code, there is nothing of the update to undo.
  assert.equal(applier2.report().some((l) => l.includes('to run the old code again')), false)

  // A yes whose reset does not bring that head back: nothing is started on a checkout no one chose.
  const stuck = new Machine(t)
  stuck.preEnv()
  stuck.bearer = { state: 'matches' }
  edit(stuck.facts, 'features.curator_proof')
  edit(stuck.facts, 'features.stop_listener_check')
  stuck.originMain = ORIGIN_MAIN
  stuck.updatedFacts = factsDoc(stuck.dir, stuck.home)
  stuck.over.set(`${stuck.py} -B -m src.transport.http_auth check`, { err: refusal(stuck), code: 1 })
  stuck.over.set(`git reset --keep ${HEAD}`, { err: 'error: Entry src/server.py would be overwritten by merge. Cannot merge.\n', code: 1 })
  stuck.answer = { kind: 'line', text: 'yes' }
  const plan3 = stuck.plan()
  const applier3 = stuck.applier(plan3)
  assert.deepEqual(await applier3.apply('live', chosen(plan3, ['update', 'auth-after-update']).live), { ok: false, exitCode: 4 })
  assert.equal(stuck.ran(new RegExp(`${START_SCRIPT}$`)).length, 0)
  assert.match(itemNamed(applier3.items, /the old revision put back/).detail, /git reset --keep exited 1; HEAD is 53ea308/)
  assert.ok(notReached(applier3.report(), /the start/, /the old revision could not be put back/), applier3.report().join('\n'))
})

test('8767 is expected to answer 401 only when L4 left a usable curator_secret and the facts show the curator enabled; with auth init --only dashboard it is not checked', async (t) => {
  // Both files made, the curator enabled: an unauthenticated status must get 401.
  for (const answer of [401, 200]) {
    const m = new Machine(t)
    m.preEnv()
    m.bearer = { state: 'matches' }
    m.curatorWithSecret = answer
    const plan = m.plan()
    const { live } = chosen(plan, ['auth'])
    assert.deepEqual(live.map((s) => s.id), ['stop', 'auth-init', 'start', 'bearer-check'])
    const applier = m.applier(plan)
    const result = await applier.apply('live', live)
    assert.ok(m.ran(/src\.dashboard\.auth init$/).length === 1)
    assert.ok(m.gets.includes('8767/api/curator/status'))
    assert.ok(m.gets.includes('8765/api/fingerprint'))
    assert.deepEqual(result, answer === 401 ? { ok: true } : { ok: false, exitCode: 4 }, String(answer))
    if (answer === 200) assert.match(itemNamed(applier.items, /the start/).detail, /curator_status|api\/curator\/status answered 200/)
  }

  // The curator secret there already: auth init --only dashboard, and 8767 is not asked, though it answers 200.
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.auth.curator_secret = 'present'
  edit(m.facts, 'curator_secret', { state: 'present' })
  m.curatorWithSecret = 200
  const plan = m.plan()
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['auth']).live), { ok: true }, JSON.stringify(applier.items))
  assert.equal(m.ran(/src\.dashboard\.auth init --only dashboard$/).length, 1)
  assert.equal(m.gets.some((g) => g.startsWith('8767')), false, '8767 was checked after --only dashboard')

  // auth init that leaves neither file usable: neither 8765 nor 8767 is expected to refuse, so neither is asked, and the items fail (pmmcp itself started: exit 1).
  const bad = new Machine(t)
  bad.preEnv()
  bad.bearer = { state: 'matches' }
  bad.over.set(`${bad.py} -m src.dashboard.auth init`, () => {
    bad.auth.dashboard_token = 'unusable'
    bad.auth.curator_secret = 'unusable'
    return { err: 'dashboard_token: unusable (mode 0644)\ncurator_secret: unusable (mode 0644)\n', code: 1 }
  })
  const planBad = bad.plan()
  const applierBad = bad.applier(planBad)
  assert.deepEqual(await applierBad.apply('live', chosen(planBad, ['auth']).live), { ok: false, exitCode: 1 }, JSON.stringify(applierBad.items))
  assert.equal(bad.gets.some((g) => g.startsWith('8767')), false, 'the curator was asked though no usable curator secret was left')
  assert.equal(bad.gets.some((g) => g.startsWith('8765')), false, 'the dashboard was asked though no usable dashboard token was left')
  for (const what of [/the dashboard token/, /the curator secret/]) {
    const item = itemNamed(applierBad.items, what)
    assert.equal(item.state, 'failed')
    assert.match(item.detail, /auth init exited 1, and auth status says unusable/)
  }
  assert.equal(itemNamed(applierBad.items, /the start/).state, 'done')

  // The curator disabled: nothing listens there, and nothing is asked.
  const off = new Machine(t)
  off.preEnv()
  off.bearer = { state: 'matches' }
  edit(off.facts, 'config.curator.enabled', false)
  off.curatorUp = false
  off.listeners.delete(8767)
  const plan3 = off.plan()
  const applier3 = off.applier(plan3)
  assert.deepEqual(await applier3.apply('live', chosen(plan3, ['auth']).live), { ok: true }, JSON.stringify(applier3.items))
  assert.equal(off.gets.some((g) => g.startsWith('8767')), false, 'a disabled curator was asked')
})

/** The line pmmcp's watchdog writes to server.log for a child that refused to start (src/dashboard/server_lifecycle.py), naming its stderr file. */
const refusedLine = (child: 'Dashboard' | 'Curator', path: string): string =>
  JSON.stringify({ event: `${child} subprocess refused to start: its secret file is unusable, or its bind is not the one its callers call (see ${path}) — restarting`, level: 'warning' })

test('an L5 probe with no answer prints the last "refused to start" lines of server.log and the stderr file they name', async (t) => {
  // A checkout under a folder whose name holds a space is read the same (--pmmcp-dir allows one).
  for (const parent of ['Github', 'My Projects']) {
    const m = new Machine(t, { parent })
    m.preEnv()
    m.bearer = { state: 'matches' }
    m.auth.curator_secret = 'present'
    edit(m.facts, 'curator_secret', { state: 'present' })
    m.dashboardUp = false
    const stderrLog = join(m.dir, 'logs', 'dashboard_stderr.log')
    // An earlier run's refusals: launchd.err.log only grows, and server.log was the old server's until the new one rolled it over.
    m.logServer(refusedLine('Dashboard', join(m.dir, 'logs', 'an-old-run_stderr.log')))
    m.logLaunchdErr('pmmcp: refusing to start: an old refusal of weeks ago')
    // What the new server logs as it starts.
    m.serverLogOnStart.push(JSON.stringify({ event: 'server started', level: 'info' }), refusedLine('Dashboard', '/tmp/elsewhere/logs/other_stderr.log'), refusedLine('Dashboard', stderrLog))
    writeFileSync(stderrLog, 'PMMCP Dashboard: not starting: ~/.persistent-memory-mcp/dashboard_token has group or other mode bits\n   chmod 600 it\n')
    const plan = m.plan()
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('live', chosen(plan, ['auth']).live), { ok: false, exitCode: 4 })
    const text = m.text()
    assert.match(text, /the dashboard on 8765 gives no answer/)
    assert.match(text, /what pmmcp logged about a service that did not come up:/)
    assert.match(text, /server\.log: Dashboard subprocess refused to start/)
    assert.match(text, /dashboard_stderr\.log: PMMCP Dashboard: not starting: ~\/\.persistent-memory-mcp\/dashboard_token has group or other mode bits/)
    // A stderr file outside this checkout's logs is named, never read.
    assert.match(text, /server\.log names \/tmp\/elsewhere\/logs\/other_stderr\.log, which is not this checkout's: not read/)
    assert.equal(text.includes('not read') && text.includes(`names ${stderrLog}`), false, `${parent}: this checkout's own stderr file was not read`)
    // Nothing from before the start is shown as this start's.
    assert.equal(text.includes('an-old-run_stderr.log'), false, `${parent}: server.log's older refusal was shown`)
    assert.equal(text.includes('an old refusal of weeks ago'), false, `${parent}: launchd.err.log's older refusal was shown`)
    // The dashboard was asked again before it was called silent.
    assert.equal(m.gets.filter((g) => g === '8765/api/auth/status').length, PROBE_TRIES)
  }

  // /health with no answer: the MCP server did not come up (it refused http_auth.yaml before its logging, so server.log is the old run's).
  const health = new Machine(t)
  const plan2 = restartOnly(health)
  health.startServer = false
  health.logServer(refusedLine('Curator', join(health.dir, 'logs', 'curator_stderr.log')))
  health.logLaunchdErr('pmmcp: refusing to start: an old refusal of weeks ago')
  health.launchdErrOnStart.push(
    `pmmcp: refusing to start: ${health.authFile}: token name on line 4 (a str of 36 characters, not shown) looks like a token, not a name; name the client instead, such as aos-kernel`,
  )
  const applier2 = health.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['restart']).live), { ok: false, exitCode: 4 })
  const text2 = health.text()
  assert.match(text2, /\/health gave no answer/)
  assert.match(text2, /what pmmcp logged about a service that did not come up:/)
  assert.match(text2, /launchd\.err\.log: pmmcp: refusing to start: .*token name on line 4 .*looks like a token, not a name/)
  assert.equal(text2.includes('an old refusal of weeks ago') || text2.includes('Curator subprocess refused'), false, text2)

  // The curator with no answer on 8767, once its secret was made.
  const curator = new Machine(t)
  curator.preEnv()
  curator.bearer = { state: 'matches' }
  curator.curatorUp = false
  const curatorLog = join(curator.dir, 'logs', 'curator_stderr.log')
  curator.serverLogOnStart.push(refusedLine('Curator', curatorLog))
  writeFileSync(curatorLog, 'PMMCP Curator: not starting: curator.host is 0.0.0.0; with a curator secret it serves only 127.0.0.1:8767\n')
  const plan3 = curator.plan()
  const applier3 = curator.applier(plan3)
  assert.deepEqual(await applier3.apply('live', chosen(plan3, ['auth']).live), { ok: false, exitCode: 4 })
  const text3 = curator.text()
  assert.match(text3, /the curator on 8767 gives no answer/)
  assert.match(text3, /what pmmcp logged about a service that did not come up:/)
  assert.match(text3, /server\.log: Curator subprocess refused to start/)
  assert.match(text3, /curator_stderr\.log: PMMCP Curator: not starting: curator\.host is 0\.0\.0\.0/)
})

test('the curator secret is not created while a monitor_tui.py of this checkout runs', async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.tuis = [4242]
  const plan = m.plan()
  const { live } = chosen(plan, ['auth'])
  const auth = live.find((s) => s.id === 'auth-init')
  assert.deepEqual(auth?.creates, ['dashboard_token', 'curator_secret'])
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', live), { ok: true }, JSON.stringify(applier.items))
  // The TUI check ran inside the window, before auth init, which then made the dashboard token alone.
  const pgrep = m.indexOf(/^pgrep -f scripts\/monitor_tui\\\.py$/)
  const init = m.indexOf(/src\.dashboard\.auth init/)
  assert.ok(pgrep > m.indexOf(new RegExp(`${STOP_SCRIPT}$`)) && init > pgrep)
  assert.equal(m.calls[init]?.key.endsWith('init --only dashboard'), true)
  assert.equal(m.auth.curator_secret, 'absent')
  const skipped = itemNamed(applier.items, /the curator secret/)
  assert.equal(skipped.state, 'skipped')
  assert.match(skipped.detail, /monitor_tui\.py runs \(pid 4242\).*quit it, then re-run/)
  assert.equal(m.gets.some((g) => g.startsWith('8767')), false)

  // And pgrep that cannot say is no proof none runs.
  const m2 = new Machine(t)
  m2.preEnv()
  m2.bearer = { state: 'matches' }
  m2.over.set('pgrep -f scripts/monitor_tui\\.py', { code: 3, err: 'pgrep: cannot allocate\n' })
  const plan2 = m2.plan()
  const applier2 = m2.applier(plan2)
  await applier2.apply('live', chosen(plan2, ['auth']).live)
  assert.equal(m2.auth.curator_secret, 'absent')
  assert.match(itemNamed(applier2.items, /the curator secret/).detail, /cannot be told/)
})

test('after a leak nothing more runs: the end report names the file, the manual start and the checks it could not make, exit 4 inside the window', async (t) => {
  const m = new Machine(t)
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const plan = m.plan()
  const { nonLive, live } = chosen(plan, ['restart'])
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', nonLive), { ok: true })
  // The stop echoes a token the writer minted (and registered) in this run: a defect.
  m.over.set(join(m.dir, STOP_SCRIPT), () => ({ out: `stopping with ${m.minted[1] ?? ''}\n` }))
  const before = m.calls.length
  assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 })
  assert.equal(m.calls.length, before + 1, 'something ran after the leak')
  const stopOut = join(m.runner.dir ?? '', 'stop.out')
  assert.equal(readFileSync(stopOut, 'utf8'), '', 'the file that held the value was not emptied')
  const report = applier.report().join('\n')
  assert.ok(report.includes(stopOut), 'the report does not name the file')
  assert.match(report, /pmmcp may be stopped: start it with cd .*Persistent-Memory-MCP && \.\/start-pmmcp-server\.sh/)
  assert.match(report, /not checked: what listens on 8766, 8765 and 8767, whether pmmcp-qdrant runs, the PID files under ~\/\.persistent-memory-mcp\/pids, and \/health/)
  for (const v of m.minted) assert.equal(report.includes(v) || m.text().includes(v), false)
  // Any further phase runs nothing either.
  assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 })
  assert.equal(m.calls.length, before + 1)

  // A leak in a read once the start's checks all passed: pmmcp is up as checked, so nothing says it may be stopped or names checks not made (exit 1).
  const late = new Machine(t)
  late.auth.dashboard_token = 'present'
  late.auth.curator_secret = 'present'
  edit(late.facts, 'dashboard_token', { state: 'present' })
  edit(late.facts, 'curator_secret', { state: 'present' })
  const plan3 = late.plan()
  const { nonLive: nonLive3, live: live3 } = chosen(plan3, ['restart'])
  const applier3 = late.applier(plan3)
  assert.deepEqual(await applier3.apply('non-live', nonLive3), { ok: true })
  late.over.set(`${late.py} scripts/pmmcp_facts.py --json`, () => (late.ran(new RegExp(`${START_SCRIPT}$`)).length > 0 ? { out: `{"echo": "${late.minted[1] ?? ''}"}\n` } : undefined))
  assert.deepEqual(await applier3.apply('live', live3), { ok: false, exitCode: 1 }, JSON.stringify(applier3.items))
  assert.equal(itemNamed(applier3.items, /the start/).state, 'done')
  const lateReport = applier3.report().join('\n')
  assert.match(lateReport, /stopped by a defect: .*facts-after(?:-\d+)?\.out/)
  assert.equal(/pmmcp may be stopped|not checked: /.test(lateReport), false, lateReport)
  for (const v of late.minted) assert.equal(lateReport.includes(v) || late.text().includes(v), false)
  // A later phase runs nothing, and pmmcp is still not said to be stopped.
  assert.deepEqual(await applier3.apply('live', live3), { ok: false, exitCode: 1 })

  // Before the window, a leak is exit 1, and says nothing of pmmcp being stopped.
  const early = new Machine(t)
  const plan2 = early.plan()
  early.over.set(`${early.py} scripts/rotate_http_auth_token.py aos-kernel --create --digest-stdin`, () => ({ err: `token ${early.minted[0] ?? ''}\n` }))
  const applier2 = early.applier(plan2)
  assert.deepEqual(await applier2.apply('non-live', chosen(plan2, []).nonLive), { ok: false, exitCode: 1 })
  assert.equal(applier2.report().some((l) => l.includes('pmmcp may be stopped')), false)
})

test('a step its phase does not carry out, or an update with no head or origin/main, is refused before anything runs', async (t) => {
  const m = new Machine(t)
  const plan = restartOnly(m)
  const { live } = chosen(plan, ['restart'])
  const [stop, ...rest] = live
  assert.ok(stop !== undefined)
  // A step of a fresh install handed to the live window: refused before the stop, the window never opened.
  const clone = plan.steps.find((s) => s.id === 'clone') ?? { ...stop, id: 'clone' as const }
  await assert.rejects(m.applier(plan).apply('live', [stop, clone, ...rest]), /clone is not a step of the live phase/)
  assert.equal(m.calls.length, 0)
  assert.deepEqual(m.windows, [])
  // The same for the other phases: nothing written, nothing cloned.
  const fresh = new Machine(t, { installed: false })
  const freshPlan = fresh.plan()
  await assert.rejects(fresh.applier(freshPlan).apply('fresh-install', [...freshPlan.steps, { ...stop, id: 'update' as const }]), /update is not a step of the fresh-install phase/)
  await assert.rejects(fresh.applier(freshPlan).apply('non-live', [...freshPlan.steps]), /is not a step of the non-live phase/)
  assert.equal(fresh.calls.length, 0)
  assert.equal(existsSync(join(fresh.root, '.env')), false)
  // An update with nothing to fast-forward to: refused before the stop.
  const u = new Machine(t)
  const planU = updating(u)
  const found = u.discovery as Found
  u.discovery = { ...found, git: { ...found.git, originMain: undefined } }
  await assert.rejects(u.applier(planU).apply('live', chosen(planU, ['update', 'auth-after-update']).live), /an update step for a checkout with no head or origin\/main/)
  assert.equal(u.calls.length, 0)
  assert.deepEqual(u.windows, [])
})

test('L2, L3 and L4 run in their own session, recorded in active.json, with no timeout', async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.qdrantBefore = keyless()
  edit(m.facts, 'features.curator_proof', false)
  m.originMain = ORIGIN_MAIN
  m.updatedFacts = factsDoc(m.dir, m.home)
  const plan = m.plan()
  const { live } = chosen(plan, ['qdrant', 'auth', 'update', 'auth-after-update'])
  assert.deepEqual(live.map((s) => s.id), ['stop', 'update', 'qdrant-enable', 'auth-init', 'auth-init', 'start', 'bearer-check'])
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', live), { ok: true }, JSON.stringify(applier.items))
  const inWindow = [/^git merge --ff-only /, /qdrant_api_key\.py enable --dry-run$/, /qdrant_api_key\.py enable$/, /src\.dashboard\.auth init --only dashboard$/, /src\.dashboard\.auth init --only curator$/]
  for (const pattern of inWindow) {
    const calls = m.ran(pattern)
    assert.equal(calls.length, 1, String(pattern))
    const call = calls[0]
    assert.ok(call !== undefined)
    assert.equal(call.options.detached, true, `${String(pattern)} was not detached`)
    assert.ok(call.active?.state === 'recorded', `${String(pattern)} was not recorded in active.json`)
    const spec = m.runner.specs.find((s) => [s.command, ...s.args].join(' ') === call.key)
    assert.ok(spec !== undefined && spec.ownSession === true && spec.timeoutMs === undefined, `${String(pattern)}: ${JSON.stringify(spec)}`)
  }
  // The stop and start too; and every record is gone once the window closed.
  for (const script of [STOP_SCRIPT, START_SCRIPT]) {
    const [call] = m.ran(new RegExp(`${script}$`))
    assert.ok(call?.options.detached === true && call.active?.state === 'recorded')
  }
  assert.equal(readActive(m.root).state, 'none')
  // A probe in the window is the installer's own child, not a session.
  const [probe] = m.ran(/^lsof /)
  assert.equal(probe?.options.detached, false)
  // Both files exist after the update brought what the curator secret needs.
  assert.deepEqual(m.auth, { dashboard_token: 'present', curator_secret: 'present' })
})

test('an active.json the runner could not remove after a step in its own session is reported, and no later step of the window runs past it', async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  const plan = m.plan()
  const { live } = chosen(plan, ['auth'])
  // auth init ends with its record turned into something unlink cannot remove (a folder), as a failing disk would leave it.
  const key = `${m.py} -m src.dashboard.auth init`
  m.over.set(key, () => {
    m.auth.dashboard_token = 'present'
    m.auth.curator_secret = 'present'
    const exit = new Promise<void>((resolve) => {
      setImmediate(() => {
        rmSync(activePath(m.root), { force: true })
        mkdirSync(activePath(m.root))
        resolve()
      })
    })
    return { out: 'created\n', hold: exit }
  })
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 })
  // The start is a step in its own session too: the runner refuses it while the record stands, so pmmcp is left stopped and said to be.
  assert.equal(m.ran(new RegExp(`${START_SCRIPT}$`)).length, 0)
  const report = applier.report().join('\n')
  assert.match(report, /active\.json \(EISDIR\): remove it once nothing it names runs/)
  assert.match(report, /once what failed is fixed: cd .* && \.\/start-pmmcp-server\.sh/)
  // The start's own line: the runner refused it, and that alone fails the start.
  assert.match(itemNamed(applier.items, /the start/).detail, /^start-pmmcp-server\.sh start: not run: .*active\.json says an earlier step in its own session .* may still be running/)
  // A start that never ran re-enabled nothing: pmmcp is stopped, and launchd disabled.
  assert.match(m.text(), /the start did not run: pmmcp is stopped, and launchd stays disabled until the start script runs/)
  assert.equal(m.text().includes('pmmcp may be partly up'), false, m.text())
})

test('a stop that refuses its arguments (exit 2) changes nothing more and asks nothing; one interrupted (exit 130) is no stop, and the start is offered', async (t) => {
  const refused = new Machine(t)
  const plan = restartOnly(refused)
  refused.stopCode = 2
  const applier = refused.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: false, exitCode: 1 })
  assert.match(itemNamed(applier.items, /graceful stop/).detail, /refused its arguments \(exit 2\): nothing was stopped/)
  assert.deepEqual(refused.asked, [])
  assert.equal(refused.ran(new RegExp(`${START_SCRIPT}$`)).length, 0)
  assert.ok(notReached(applier.report(), /the start/, /the stop refused its arguments/), applier.report().join('\n'))

  const interrupted = new Machine(t)
  const plan2 = restartOnly(interrupted)
  interrupted.stopCode = 130
  const applier2 = interrupted.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['restart']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier2.items, /graceful stop/).detail, /it was interrupted \(exit 130\)/)
  assert.deepEqual(interrupted.asked, ['start pmmcp again to restore service? [Y/n]'])
  // Ended as a Ctrl-C ends a probe, inside the window: a stop is never run again.
  assert.equal(interrupted.ran(new RegExp(`${STOP_SCRIPT}$`)).length, 1)
  assert.equal(interrupted.ran(new RegExp(`${START_SCRIPT}$`)).length, 0)
})

test('a stop that exits 1 or 130, or ends by a signal, is no stop even when every L1 check is clean: it runs once, nothing more is changed, and the start is offered', async (t) => {
  // The stop script removes a PID file even for a daemon it failed to stop: its exit is the one sign.
  const ends: readonly { readonly name: string; readonly setup: (m: Machine) => void; readonly detail: RegExp }[] = [
    { name: 'exit 1', setup: (m) => (m.stopCode = 1), detail: /^a service FAILED TO STOP \(exit 1\); nothing listens on 8766, 8765 and 8767, pmmcp-qdrant does not run, and no PID file names a live process$/ },
    { name: 'exit 130', setup: (m) => (m.stopCode = 130), detail: /^it was interrupted \(exit 130\); nothing listens on 8766/ },
    { name: 'SIGINT', setup: (m) => (m.stopSignal = 'SIGINT'), detail: /stop-pmmcp-server\.sh ended by SIGINT; nothing listens on 8766/ },
  ]
  for (const c of ends) {
    const m = new Machine(t)
    m.qdrantBefore = keyless()
    const plan = m.plan()
    const { nonLive, live } = chosen(plan, ['qdrant', 'auth', 'restart'])
    c.setup(m)
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('non-live', nonLive), { ok: true })
    assert.deepEqual(await applier.apply('live', live), { ok: false, exitCode: 4 }, c.name)
    const stop = itemNamed(applier.items, /graceful stop/)
    assert.equal(stop.state, 'failed', c.name)
    assert.match(stop.detail, c.detail, c.name)
    assert.equal(m.ran(new RegExp(`${STOP_SCRIPT}$`)).length, 1, `${c.name}: the stop was run again`)
    assert.equal(m.ran(/qdrant_api_key\.py enable|src\.dashboard\.auth init|start-pmmcp-server\.sh/).length, 0, `${c.name}: the window went on`)
    assert.deepEqual(m.asked, ['start pmmcp again to restore service? [Y/n]'], c.name)
  }
})

test('a step in its own session that ends as a Ctrl-C would inside the window is never run again: the cutover, auth init and the fast-forward', async (t) => {
  const cutover = new Machine(t)
  const plan = cutoverOnly(cutover)
  cutover.over.set(`${cutover.py} scripts/qdrant_api_key.py enable`, { signal: 'SIGINT' })
  const applier = cutover.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['qdrant']).live), { ok: false, exitCode: 4 })
  assert.equal(cutover.ran(/qdrant_api_key\.py enable$/).length, 1)
  // Ended by a signal, it may not have put everything back: as its exit 3, pmmcp is not started on it.
  assert.equal(cutover.ran(new RegExp(`${START_SCRIPT}$`)).length, 0)
  assert.ok(notReached(applier.report(), /the start/, /the Qdrant cutover failed and could not put everything back/), applier.report().join('\n'))

  const auth = new Machine(t)
  auth.preEnv()
  auth.bearer = { state: 'matches' }
  auth.over.set(`${auth.py} -m src.dashboard.auth init`, { signal: 'SIGINT' })
  const plan2 = auth.plan()
  const applier2 = auth.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['auth']).live), { ok: false, exitCode: 1 }, JSON.stringify(applier2.items))
  assert.equal(auth.ran(/src\.dashboard\.auth init$/).length, 1)
  assert.match(itemNamed(applier2.items, /the dashboard token/).detail, /auth init auth-init: .* ended by SIGINT, and auth status says absent/)

  const merge = new Machine(t)
  const plan3 = updating(merge)
  merge.over.set(`git merge --ff-only ${ORIGIN_MAIN}`, { code: 130, err: 'interrupted\n' })
  const applier3 = merge.applier(plan3)
  assert.deepEqual(await applier3.apply('live', chosen(plan3, ['update', 'auth-after-update']).live), { ok: false, exitCode: 1 }, JSON.stringify(applier3.items))
  assert.equal(merge.ran(/^git merge /).length, 1)
  assert.match(itemNamed(applier3.items, /the fast-forward/).detail, /git merge --ff-only exited 130; HEAD is still e6516d5: not updated/)
})

test("an earlier run's record is cleared only while active.json still holds the one discovery found stale", async (t) => {
  const stale: ActiveRecord = { step: 'stop', pid: 4321, started: '2026-10-28T09:00:00.000Z', out: '/x/stop.out', err: '/x/stop.err' }
  // A record by another pid, or by the same pid at another start or for another step, is another run's.
  for (const held of [stale, { ...stale, pid: 4322 }, { ...stale, started: '2026-10-28T09:00:05.000Z' }, { ...stale, step: 'start' }]) {
    const m = new Machine(t)
    const plan = restartOnly(m)
    mkdirSync(join(m.root, '.aos', 'install'), { recursive: true, mode: 0o700 })
    writeFileSync(activePath(m.root), JSON.stringify(held), { mode: 0o600 })
    m.discovery = { ...(m.discovery as Found), staleActive: stale }
    const applier = m.applier(plan)
    const result = await applier.apply('live', chosen(plan, ['restart']).live)
    if (held === stale) {
      // Discovery's own stale record: cleared, and the window runs.
      assert.deepEqual(result, { ok: true }, JSON.stringify(applier.items))
      assert.equal(m.ran(new RegExp(`${STOP_SCRIPT}$`)).length, 1)
      continue
    }
    // Another record: no one's to clear here, so it stands, and the runner refuses the stop while it does.
    assert.deepEqual(result, { ok: false, exitCode: 1 })
    assert.equal(m.ran(/stop-pmmcp-server\.sh/).length, 0)
    const now = readActive(m.root)
    assert.ok(now.state === 'recorded' && now.record.pid === held.pid && now.record.started === held.started && now.record.step === held.step, JSON.stringify(now))
    assert.match(itemNamed(applier.items, /graceful stop/).detail, /may still be running.*nothing was stopped/)
  }
})

test('L2 fast-forwards only from the head discovery found, on a clean tree; otherwise nothing is updated and the after-update files are not made', async (t) => {
  const cases: readonly { readonly name: string; readonly setup: (m: Machine) => void; readonly detail: RegExp }[] = [
    { name: 'HEAD moved since discovery', setup: (m) => (m.head = THIRD), detail: /HEAD is f00dfac, not e6516d5 as discovery found it: not updated/ },
    {
      name: 'a working tree no longer clean',
      setup: (m) => m.over.set('git --no-optional-locks status --porcelain', { out: ' M src/server.py\n' }),
      detail: /the working tree is no longer clean: not updated/,
    },
    {
      // uv sync is the operator's: a fast-forward that changes the lock or the project file would leave the venv behind the code.
      name: 'uv.lock or pyproject.toml changed at origin/main',
      setup: (m) => m.over.set(`git --no-optional-locks diff --quiet HEAD ${ORIGIN_MAIN} -- uv.lock pyproject.toml`, { code: 1 }),
      detail: /uv\.lock or pyproject\.toml differ at origin\/main: not updated \(update it by hand with pmmcp stopped\)/,
    },
  ]
  for (const c of cases) {
    const m = new Machine(t)
    const plan = updating(m)
    c.setup(m)
    const applier = m.applier(plan)
    // The update failed cleanly and pmmcp was started on the code it had: exit 1.
    assert.deepEqual(await applier.apply('live', chosen(plan, ['update', 'auth-after-update']).live), { ok: false, exitCode: 1 }, c.name)
    assert.equal(m.ran(/^git merge /).length, 0, c.name)
    assert.match(itemNamed(applier.items, /the fast-forward/).detail, c.detail, c.name)
    assert.match(itemNamed(applier.items, /where the updated pmmcp supports them/).detail, /the update did not run/, c.name)
    assert.equal(m.ran(/src\.dashboard\.auth init/).length, 0, c.name)
    assert.equal(itemNamed(applier.items, /the start/).state, 'done', c.name)
  }
})

test('after the fast-forward, facts that cannot be had or a HEAD at neither commit leave pmmcp stopped, before any start', async (t) => {
  const unreadable = new Machine(t)
  const plan = updating(unreadable)
  unreadable.over.set(`${unreadable.py} scripts/pmmcp_facts.py --json`, () => (unreadable.updated ? { err: 'failed: config.yaml cannot be read\n', code: 1 } : undefined))
  const applier = unreadable.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['update', 'auth-after-update']).live), { ok: false, exitCode: 4 })
  assert.equal(unreadable.ran(new RegExp(`${START_SCRIPT}$`)).length, 0, 'pmmcp was started on code whose facts cannot be read')
  assert.equal(unreadable.ran(/http_auth check$/).length, 0)
  assert.match(itemNamed(applier.items, /the updated pmmcp's facts/).detail, /the facts exited 1: failed: config\.yaml cannot be read/)
  assert.deepEqual(unreadable.asked, [`start the old revision (${HEAD.slice(0, 7)}) now? [y/N]`])
  assert.ok(notReached(applier.report(), /the start/, /the updated pmmcp's facts cannot be read, so pmmcp was not started/), applier.report().join('\n'))

  const elsewhere = new Machine(t)
  const plan2 = updating(elsewhere)
  elsewhere.over.set(`git merge --ff-only ${ORIGIN_MAIN}`, () => {
    elsewhere.head = THIRD
    elsewhere.updated = true
    return { out: 'Fast-forward\n' }
  })
  const applier2 = elsewhere.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['update', 'auth-after-update']).live), { ok: false, exitCode: 4 })
  assert.equal(elsewhere.ran(new RegExp(`${START_SCRIPT}$`)).length, 0, 'pmmcp was started on a HEAD no one chose')
  assert.match(itemNamed(applier2.items, /the fast-forward/).detail, /HEAD is f00dfac, neither e6516d5 nor 53ea308: pmmcp is not started/)
  assert.ok(elsewhere.printed.some((l) => l.includes(`put the checkout back (with pmmcp stopped): git -C`) && l.includes(`reset --keep ${HEAD}`)))
})

test('after an L2 update, a check that gives no verdict is asked once more, and only its exit 1 with an invalid: line is read as a refusal', async (t) => {
  const key = (m: Machine): string => `${m.py} -B -m src.transport.http_auth check`
  const noVerdicts: readonly { readonly name: string; readonly reply: Reply; readonly why: RegExp }[] = [
    { name: 'exit 2', reply: { err: 'usage: python -m src.transport.http_auth check [--expect NAME]\n', code: 2 }, why: /exit 2 \(usage: / },
    { name: 'exit 1 with no invalid: line', reply: { err: 'Traceback (most recent call last):\nImportError: cannot import name load_config\n', code: 1 }, why: /exit 1 \(Traceback/ },
    { name: 'a signal', reply: { signal: 'SIGTERM' }, why: /ended by SIGTERM/ },
  ]
  for (const c of noVerdicts) {
    const m = new Machine(t)
    const plan = updating(m)
    m.over.set(key(m), c.reply)
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('live', chosen(plan, ['update', 'auth-after-update']).live), { ok: false, exitCode: 4 }, c.name)
    assert.equal(m.ran(/src\.transport\.http_auth check$/).length, 2, `${c.name}: not asked once more`)
    assert.equal(m.ran(new RegExp(`${START_SCRIPT}$`)).length, 0, c.name)
    const item = itemNamed(applier.items, /http_auth check with the updated code/)
    assert.equal(item.state, 'failed', c.name)
    assert.match(item.detail, /^no verdict, twice: /, c.name)
    assert.match(item.detail, c.why, c.name)
    // No refusal is claimed, and no token is named to rename.
    assert.equal(m.printed.some((l) => /refuses|rename the token/.test(l)), false, `${c.name}:\n${m.text()}`)
    assert.ok(m.printed.some((l) => l.includes('gave no verdict, twice')), c.name)
    assert.ok(notReached(applier.report(), /the start/, /whether the updated pmmcp takes http_auth\.yaml is not known/), c.name)
  }

  // No verdict once, then the file loads: the window goes on.
  const m = new Machine(t)
  const plan = updating(m)
  m.over.set(key(m), once({ code: 2 }))
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['update', 'auth-after-update']).live), { ok: true }, JSON.stringify(applier.items))
  assert.equal(m.ran(/src\.transport\.http_auth check$/).length, 2)
  assert.equal(itemNamed(applier.items, /http_auth check with the updated code/).state, 'done')
})

test("inside the window a probe that Ctrl-C or a hangup ended is asked again and the window goes on; past INTERRUPT_RERUNS, and outside the window, its end is read as it is", async (t) => {
  // The terminal's Ctrl-C reaches the installer's own children: L1's lsof, L2's facts and check with the new code, L5's ps (exit 130).
  // So does its hangup (a closed terminal: SIGHUP, or exit 129), which the installer traps in the window too (A7).
  const m = new Machine(t)
  const plan = updating(m)
  m.over.set('lsof -nP -iTCP:8765 -sTCP:LISTEN -Fpu', once({ signal: 'SIGINT' }))
  m.over.set('lsof -nP -iTCP:8767 -sTCP:LISTEN -Fpu', once({ signal: 'SIGHUP' }))
  m.over.set('docker ps --all --filter name=pmmcp-qdrant --format {{.Names}} {{.State}}', once({ code: 129 }))
  m.over.set(`${m.py} -B -m src.transport.http_auth check`, once({ signal: 'SIGINT' }))
  // The applier's first facts are L2's, with the new code (discovery's were read before the window).
  m.over.set(`${m.py} scripts/pmmcp_facts.py --json`, once({ signal: 'SIGINT' }))
  m.over.set(`ps -o etime= -p ${String(NEW_PID)}`, once({ code: 130 }))
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['update', 'auth-after-update']).live), { ok: true }, JSON.stringify(applier.items))
  assert.equal(itemNamed(applier.items, /graceful stop/).state, 'done')
  assert.equal(itemNamed(applier.items, /http_auth check with the updated code/).state, 'done')
  assert.equal(itemNamed(applier.items, /the start/).state, 'done')
  assert.equal(m.ran(/^lsof -nP -iTCP:8765 /).length, 2)
  assert.equal(m.ran(/src\.transport\.http_auth check$/).length, 2)
  assert.equal(m.ran(new RegExp(`^ps -o etime= -p ${String(NEW_PID)}$`)).length, 2)
  assert.equal(m.printed.filter((l) => l.includes('ended by Ctrl-C, which does not end the window: asked again')).length, 4, m.text())
  assert.equal(m.ran(/^lsof -nP -iTCP:8767 /).length, 2)
  assert.equal(m.printed.filter((l) => l.includes('ended by SIGHUP (the terminal closed), which does not end the window: asked again')).length, 2, m.text())

  // A probe ended so every time is asked INTERRUPT_RERUNS more times, then read as it is: what listens there cannot be checked.
  const always = new Machine(t)
  const plan2 = restartOnly(always)
  always.over.set('lsof -nP -iTCP:8765 -sTCP:LISTEN -Fpu', { signal: 'SIGINT' })
  const applier2 = always.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['restart']).live), { ok: false, exitCode: 4 })
  assert.equal(always.ran(/^lsof -nP -iTCP:8765 /).length, 1 + INTERRUPT_RERUNS)
  assert.match(itemNamed(applier2.items, /graceful stop/).detail, /what listens on 8765 cannot be checked \(lsof-8765: lsof ended by SIGINT\)/)

  // Outside the window a Ctrl-C ends the installer (A7): a probe is never run again there.
  const outside = new Machine(t)
  const plan3 = outside.plan()
  outside.over.set(`ls -lde ${join(outside.root, '.env')}`, { signal: 'SIGINT' })
  const applier3 = outside.applier(plan3)
  assert.deepEqual(await applier3.apply('non-live', chosen(plan3, []).nonLive), { ok: true })
  assert.equal(outside.ran(/^ls -lde /).length, 1)
})

test("L3 runs enable only after its own dry run passed; a refused dry run, enable's exit 1 or its 130 leave Qdrant as it was, and the start goes on (exit 1)", async (t) => {
  const cases: readonly { readonly name: string; readonly key: string; readonly reply: Reply; readonly detail: RegExp }[] = [
    { name: 'dry run exit 1', key: 'enable --dry-run', reply: { err: 'refused: pmmcp-qdrant is running\n', code: 1 }, detail: /enable --dry-run exited 1: not enabled, Qdrant is as it was/ },
    { name: 'enable exit 1', key: 'enable', reply: { err: 'failed: the image could not be pulled; the old pmmcp-qdrant was put back\n', code: 1 }, detail: /enable exited 1: refused or failed with everything as it was/ },
    { name: 'enable exit 130', key: 'enable', reply: { err: 'interrupted: the old pmmcp-qdrant was put back\n', code: 130 }, detail: /enable exited 130: interrupted, and the old pmmcp-qdrant is in place, without a key/ },
  ]
  for (const c of cases) {
    const m = new Machine(t)
    const plan = cutoverOnly(m)
    m.over.set(`${m.py} scripts/qdrant_api_key.py ${c.key}`, c.reply)
    const applier = m.applier(plan)
    // A live item that failed with nothing changed, and pmmcp started and checked: exit 1 (plan §9 holds the question of 1 or 4).
    assert.deepEqual(await applier.apply('live', chosen(plan, ['qdrant']).live), { ok: false, exitCode: 1 }, c.name)
    const item = itemNamed(applier.items, /Qdrant key cutover/)
    assert.equal(item.state, 'failed', c.name)
    assert.match(item.detail, c.detail, c.name)
    // Each is run once: the cutover is a step in its own session, never run again, whatever its end.
    assert.equal(m.ran(/qdrant_api_key\.py enable --dry-run$/).length, 1, c.name)
    assert.equal(m.ran(/qdrant_api_key\.py enable$/).length, c.key === 'enable --dry-run' ? 0 : 1, `${c.name}: enable ran ${c.key === 'enable --dry-run' ? 'after its own dry run refused' : 'again'}`)
    assert.equal(itemNamed(applier.items, /the start/).state, 'done', c.name)
    // No key was set, so no verdict is asked for.
    assert.equal(m.ran(/status --json$/).length, 0, c.name)
    assert.deepEqual(m.windows, [true, false], c.name)
  }
})

test('after an update, L4 makes each file only where the updated facts show pmmcp takes it safely', async (t) => {
  // The curator bound off 127.0.0.1:8767: with a secret it would refuse every launch (exit 78), so only the dashboard token is made.
  const bind = new Machine(t)
  const plan = updating(bind)
  bind.updatedFacts = edit(factsDoc(bind.dir, bind.home), 'config.curator', { host: '127.0.0.1', port: 8768, enabled: true })
  const applier = bind.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['update', 'auth-after-update']).live), { ok: true }, JSON.stringify(applier.items))
  assert.deepEqual(bind.ran(/src\.dashboard\.auth init/).map((c) => c.args.slice(-2)), [['--only', 'dashboard']])
  assert.equal(bind.auth.curator_secret, 'absent')
  assert.match(itemNamed(applier.items, /the curator secret/).detail, /config\.curator is 127\.0\.0\.1:8768/)
  assert.equal(itemNamed(applier.items, /the dashboard token/).state, 'done')

  // An updated stop script still without the listener check would send the token to a squatter on 8765 (P7): neither file is made.
  const squat = new Machine(t)
  const plan2 = updating(squat)
  squat.updatedFacts = edit(factsDoc(squat.dir, squat.home), 'features.stop_listener_check', false)
  const applier2 = squat.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['update', 'auth-after-update']).live), { ok: true }, JSON.stringify(applier2.items))
  assert.equal(squat.ran(/src\.dashboard\.auth init/).length, 0)
  assert.deepEqual(squat.auth, { dashboard_token: 'absent', curator_secret: 'absent' })
  assert.match(itemNamed(applier2.items, /the dashboard token/).detail, /updated, still lacks the dashboard token or the stop script's dashboard listener check/)
  assert.equal(itemNamed(applier2.items, /the curator secret/).state, 'skipped')

  // An updated pmmcp that says it has the curator proof but not the curator secret itself: only the dashboard token.
  const noSecret = new Machine(t)
  const plan3 = updating(noSecret)
  noSecret.updatedFacts = edit(factsDoc(noSecret.dir, noSecret.home), 'features.curator_secret', false)
  const applier3 = noSecret.applier(plan3)
  assert.deepEqual(await applier3.apply('live', chosen(plan3, ['update', 'auth-after-update']).live), { ok: true }, JSON.stringify(applier3.items))
  assert.deepEqual(noSecret.ran(/src\.dashboard\.auth init/).map((c) => c.args.slice(-2)), [['--only', 'dashboard']])
  assert.equal(noSecret.auth.curator_secret, 'absent')
  assert.match(itemNamed(applier3.items, /the curator secret/).detail, /updated, still lacks the curator secret or the curator proof/)
})

test('each L5 check fails the start on its own: a start that exits 1, no status --json after a cutover, a dashboard that does not say auth_required', async (t) => {
  const exits = new Machine(t)
  const plan = restartOnly(exits)
  exits.startCode = 1
  const applier = exits.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier.items, /the start/).detail, /^start-pmmcp-server\.sh exited 1$/)

  const status = new Machine(t)
  const plan2 = cutoverOnly(status)
  status.over.set(`${status.py} -B scripts/qdrant_api_key.py status --json`, { err: 'failed: docker cannot be asked\n', code: 1 })
  const applier2 = status.applier(plan2)
  assert.deepEqual(await applier2.apply('live', chosen(plan2, ['qdrant']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier2.items, /the start/).detail, /status --json cannot be had, so whether it enforces the key is not known; to undo the cutover: .*qdrant_api_key\.py rollback/)
  // The report does not fall back on discovery's verdict of the keyless container.
  const statusReport = applier2.report().join('\n')
  assert.match(statusReport, /qdrant: verdict not known \(no status --json was read after the key was made\): cd .* && \.venv\/bin\/python scripts\/qdrant_api_key\.py status/)
  assert.equal(/qdrant: verdict not_asked/.test(statusReport), false, statusReport)

  const open = new Machine(t)
  open.preEnv()
  open.bearer = { state: 'matches' }
  open.authRequired = false
  const plan3 = open.plan()
  const applier3 = open.applier(plan3)
  assert.deepEqual(await applier3.apply('live', chosen(plan3, ['auth']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier3.items, /the start/).detail, /the dashboard's \/api\/auth\/status does not say auth_required \(HTTP 200\)/)
  assert.equal(open.gets.includes('8765/api/fingerprint'), false)

  // auth_required said, but /api/fingerprint served without the token: the dashboard does not require it.
  const served = new Machine(t)
  served.preEnv()
  served.bearer = { state: 'matches' }
  served.fingerprint = 200
  const plan4 = served.plan()
  const applier4 = served.applier(plan4)
  assert.deepEqual(await applier4.apply('live', chosen(plan4, ['auth']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier4.items, /the start/).detail, /the dashboard's \/api\/fingerprint answered 200 without a token, not 401/)
  assert.ok(served.gets.includes('8765/api/fingerprint'))

  // Docker that cannot be asked after the start is no proof Qdrant runs.
  const docker = new Machine(t)
  const plan5 = restartOnly(docker)
  docker.over.set('docker ps --all --filter name=pmmcp-qdrant --format {{.Names}} {{.State}}', () =>
    docker.ran(new RegExp(`${START_SCRIPT}$`)).length > 0 ? { code: 1, err: 'Cannot connect to the Docker daemon\n' } : undefined,
  )
  const applier5 = docker.applier(plan5)
  assert.deepEqual(await applier5.apply('live', chosen(plan5, ['restart']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier5.items, /the start/).detail, /whether pmmcp-qdrant runs cannot be checked/)
})

test('the bearer check is done only on an aos-kernel line written since the start, and is otherwise inconclusive, never failed', async (t) => {
  const cases: readonly { readonly name: string; readonly setup: (m: Machine) => void; readonly state: 'done' | 'inconclusive' }[] = [
    { name: 'the kernel reached the new server', setup: (m) => (m.kernelAfterStart = true), state: 'done' },
    { name: "only antigravity's line since the start", setup: (m) => m.serverLogOnStart.push(firstRequest('antigravity')), state: 'inconclusive' },
    { name: 'no line at all', setup: () => undefined, state: 'inconclusive' },
    // An earlier run's line: the new server rolled server.log over to server.log.1 as it started (pmmcp's setup_logging), so it is not read.
    { name: 'an aos-kernel line from before the start, rolled over by the new server', setup: (m) => m.logServer(firstRequest('aos-kernel')), state: 'inconclusive' },
    // And where nothing rolled it over, the start's mark keeps it from counting; a line written after the mark still does.
    {
      name: 'an aos-kernel line from before the start, in a server.log no start rolled over',
      setup: (m) => {
        m.rotateServerLog = false
        m.logServer(firstRequest('aos-kernel'))
      },
      state: 'inconclusive',
    },
    {
      name: 'the kernel reached the new server, in a server.log no start rolled over',
      setup: (m) => {
        m.rotateServerLog = false
        m.kernelAfterStart = true
      },
      state: 'done',
    },
    { name: 'a name that only holds aos-kernel', setup: (m) => m.serverLogOnStart.push(firstRequest('aos-kernel-old')), state: 'inconclusive' },
  ]
  // What the operator is told the step does: a look at server.log, never an initialize the installer has no token to send.
  const shownPlan = restartOnly(new Machine(t))
  const title = shownPlan.steps.find((s) => s.id === 'bearer-check')?.title ?? ''
  assert.equal(/initialize/i.test(title), false, title)
  assert.match(title, /"first request with token" for aos-kernel in ~\/\.persistent-memory-mcp\/logs\/server\.log since the start \(not found: inconclusive, not a failure; the AOS daemon's next request makes the line\)$/)
  assert.equal(/restart npm run dev/.test(title), false, title)
  for (const c of cases) {
    const m = new Machine(t)
    const plan = restartOnly(m)
    m.logServer(JSON.stringify({ event: 'server started', level: 'info' }))
    c.setup(m)
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: true }, c.name)
    const item = itemNamed(applier.items, /bearer check/)
    assert.equal(item.state, c.state, c.name)
    // This restart loaded the digest, so the next steps ask the daemon restarted, and the line comes from the restarted daemon.
    if (c.state === 'inconclusive') assert.match(item.detail, /since the start .*: restart npm run dev, as the next steps say, then grep "first request with token" /, c.name)
    assert.ok(applier.report().some((l) => l.startsWith(`  ${c.state.padEnd(12)} the aos-kernel bearer check`)), c.name)
  }
})

test('a digest re-staged without a restart is on file and not loaded by the running server', async (t) => {
  const m = new Machine(t)
  m.preEnv()
  // The running server started after http_auth.yaml last changed: it loaded what was there, an older aos-kernel digest.
  const longAgo = new Date(NOW.getTime() - 3 * 60 * 60 * 1000)
  utimesSync(m.authFile, longAgo, longAgo)
  m.bearer = { state: 'differs' }
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const plan = m.plan()
  const { nonLive } = chosen(plan, [])
  assert.deepEqual(nonLive.map((s) => s.id), ['stage-digest'])
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', nonLive), { ok: true })
  assert.ok(applier.report().some((l) => l.includes('aos-kernel digest matches .env: yes; loaded by the running server: no')), applier.report().join('\n'))
})

test('rotate exit 1 or 2 wrote nothing and is not checked; check --expect counts only its own "matches" with exit 0', async (t) => {
  for (const code of [1, 2]) {
    const m = new Machine(t)
    const plan = m.plan()
    m.over.set(`${m.py} scripts/rotate_http_auth_token.py aos-kernel --create --digest-stdin`, { err: 'refused\n', code })
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('non-live', chosen(plan, []).nonLive), { ok: false, exitCode: 1 }, String(code))
    assert.equal(m.ran(/check --expect/).length, 0, `exit ${String(code)} was checked as if something were written`)
    assert.match(itemNamed(applier.items, /digest staged/).detail, new RegExp(`exited ${String(code)}: nothing was written in http_auth\\.yaml`))
  }
  const m = new Machine(t)
  const plan = m.plan()
  m.expect = { out: 'aos-kernel: matches\n', code: 3 }
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', chosen(plan, []).nonLive), { ok: false, exitCode: 1 })
  assert.match(itemNamed(applier.items, /digest staged/).detail, /check --expect gave no verdict \(exit 3 without a verdict\): the digest is not on file/)
  // And "differs" or "absent" only with its exit 3: with another exit there is no verdict.
  for (const said of ['differs', 'absent']) {
    const other = new Machine(t)
    const plan2 = other.plan()
    other.expect = { out: `aos-kernel: ${said}\n`, code: 0 }
    const applier2 = other.applier(plan2)
    assert.deepEqual(await applier2.apply('non-live', chosen(plan2, []).nonLive), { ok: false, exitCode: 1 })
    assert.match(itemNamed(applier2.items, /digest staged/).detail, /check --expect gave no verdict \(exit 0 without a verdict\): the digest is not on file/, said)
  }
})

test('a .env the writer may have changed before it failed ends the run with exit 1, never 2', async (t) => {
  const m = new Machine(t)
  const plan = m.plan()
  // The .gitignore stops ignoring .env while the writer works: its read-back through the loader refuses the file it wrote.
  // Every value it minted is kept here, so that none can be found in what was shown.
  const minted: string[] = []
  const applier = m.applier(plan, {
    mint: () => {
      if (minted.length === 0) writeFileSync(join(m.root, '.gitignore'), '/.aos/\n')
      const v = randomBytes(32).toString('hex')
      minted.push(v)
      return v
    },
  })
  assert.deepEqual(await applier.apply('non-live', chosen(plan, []).nonLive), { ok: false, exitCode: 1 })
  assert.equal(itemNamed(applier.items, /appended to \.env/).state, 'failed')
  assert.equal(m.ran(/rotate_http_auth_token/).length, 0)

  // The report never says "not written": .env may hold the tokens now, and may no longer be git-ignored. It names what may have
  // changed (the names, never a value), the two checks to run, and holds back the restart of npm run dev until they pass.
  const report = applier.report()
  const text = report.join('\n')
  assert.equal(/not written by this run/.test(text), false, text)
  const envLine = report.find((l) => l.startsWith('.env  '))
  assert.match(envLine ?? '', /: may have been changed by this run before the writer failed \(.+\); mode 0600$/, text)
  assert.ok(
    report.includes(
      `  .env may now hold AOS_CONTROL_TOKEN and AOS_PMMCP_TOKEN (the names this run was appending), or be left empty if this run created it: ` +
        `check it in ${m.root} with ls -l .env (-rw------- and yours) and git check-ignore -v .env (it must name the .gitignore line that ignores .env), ` +
        'and fix what they show before you restart npm run dev',
    ),
    text,
  )
  assert.equal(/^ {2}restart npm run dev/m.test(text), false, text)
  assert.match(text, /^ {2}check \.env as above before you restart npm run dev/m)
  assert.ok(m.printed.some((l) => /^ {2}\.env may now hold AOS_CONTROL_TOKEN and AOS_PMMCP_TOKEN/.test(l)), m.text())
  // Both tokens were minted, and the file holds them (the writer wrote before its read-back refused): neither was shown.
  assert.equal(minted.length, 2)
  const written = readFileSync(join(m.root, '.env'), 'utf8')
  for (const v of minted) {
    assert.ok(written.includes(v), 'the writer did not write what was minted: this check would prove nothing')
    assert.equal(text.includes(v) || m.text().includes(v), false, 'a minted token was shown')
  }

  // A refusal (written false) changed nothing: "not written", and no check to run.
  const m2 = new Machine(t)
  const plan2 = m2.plan()
  writeFileSync(join(m2.root, '.env'), '# mine\n', { mode: 0o644 })
  const refused = m2.applier(plan2)
  assert.deepEqual(await refused.apply('non-live', chosen(plan2, []).nonLive), { ok: false, exitCode: 2 })
  const text2 = refused.report().join('\n')
  assert.match(text2, /: not written by this run; mode 0644/)
  assert.equal(/may have been changed|git check-ignore|restart npm run dev/.test(text2), false, text2)
})

test("the kept prekey's cleanup failing stops the run before anything live (exit 1)", async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.qdrantBefore = edit(enforced(), 'prekey_kept', true)
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  const plan = m.plan()
  const { nonLive } = chosen(plan, ['qdrant-cleanup'])
  assert.deepEqual(nonLive.map((s) => s.id), ['qdrant-cleanup'])
  m.over.set(`${m.py} scripts/qdrant_api_key.py cleanup`, { err: 'refused: pmmcp-qdrant does not run with the key\n', code: 1 })
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', nonLive), { ok: false, exitCode: 1 })
  assert.match(itemNamed(applier.items, /prekey removed/).detail, /cleanup exited 1/)
})

// ── a fresh install ──────────────────────────────────────────────────────

test('a fresh install clones, runs setup in its own session, makes the key file and stages the digest before the first start, then checks the start', async (t) => {
  const m = new Machine(t, { installed: false })
  m.facts = factsDoc(m.dir, m.home)
  edit(m.facts, 'http_auth', { state: 'absent', mode: null, tokens: [], reason: 'no http_auth.yaml', links: null })
  const plan = m.plan()
  assert.equal(plan.kind, 'fresh-install')
  assert.deepEqual(plan.steps.map((s) => s.id), ['env', 'clone', 'setup', 'stop', 'qdrant-init', 'stage-digest', 'start', 'bearer-check'])
  m.kernelAfterStart = true
  const applier = m.applier(plan)
  const result = await applier.apply('fresh-install', plan.steps)
  assert.deepEqual(result, { ok: true }, JSON.stringify(applier.items))
  const order = [/^git clone /, /setup\.sh --non-interactive$/, /pmmcp_facts\.py --json$/, new RegExp(`${STOP_SCRIPT}$`), /qdrant_api_key\.py init$/, /rotate_http_auth_token\.py/, /check --expect/, new RegExp(`${START_SCRIPT}$`)]
  const at = order.map((p) => m.indexOf(p))
  assert.ok(at.every((n, i) => n >= 0 && (i === 0 || n > (at[i - 1] ?? -1))), `order ${JSON.stringify(at)}`)
  const [clone] = m.ran(/^git clone /)
  assert.deepEqual(clone?.args, ['clone', CLONE_URL, m.dir])
  const [setup] = m.ran(/setup\.sh/)
  assert.equal(setup?.options.detached, true)
  assert.equal(setup?.options.stdio[0], 'ignore')
  assert.equal(setup?.active?.state, 'recorded')
  // Inside the window, the key file and the digest are made in their own session too.
  for (const pattern of [/qdrant_api_key\.py init$/, /rotate_http_auth_token\.py aos-kernel --create --digest-stdin$/]) {
    const [call] = m.ran(pattern)
    assert.ok(call?.options.detached === true && call.active?.state === 'recorded', String(pattern))
    const spec = m.runner.specs.find((s) => [s.command, ...s.args].join(' ') === call.key)
    assert.ok(spec?.ownSession === true && spec.timeoutMs === undefined, String(pattern))
  }
  assert.equal(itemNamed(applier.items, /bearer check/).state, 'done')
  // The window opened at setup (which loads launchd) and closed after the start's checks.
  assert.deepEqual(m.windows, [true, false])
  const report = applier.report().join('\n')
  assert.match(report, /playwright install chromium/)
  assert.match(report, /qdrant: verdict enforced/)
})

test('a fresh install stops at the step that fails: an existing clone target, setup, a new checkout lacking a feature or bound off loopback; a key file that was not made is reported failed', async (t) => {
  const fresh = (setup: (m: Machine) => void): { m: Machine; plan: Plan } => {
    const m = new Machine(t, { installed: false })
    m.facts = factsDoc(m.dir, m.home)
    edit(m.facts, 'http_auth', { state: 'absent', mode: null, tokens: [], reason: 'no http_auth.yaml', links: null })
    const plan = m.plan()
    setup(m)
    return { m, plan }
  }
  const stops: readonly { readonly name: string; readonly setup: (m: Machine) => void; readonly exitCode: 1 | 4; readonly item: RegExp; readonly detail: RegExp; readonly why: RegExp }[] = [
    {
      name: 'the clone target exists',
      setup: (m) => mkdirSync(m.dir, { recursive: true }),
      // .env was created first, so something was written: 1, not 2.
      exitCode: 1,
      item: /the clone to /,
      detail: /exists already: nothing was cloned/,
      why: /exists already, so nothing was installed/,
    },
    { name: 'setup fails', setup: (m) => m.over.set(`${join(m.dir, 'setup.sh')} --non-interactive`, { err: 'setup: uv not found\n', code: 1 }), exitCode: 4, item: /^setup\.sh$/, detail: /setup\.sh exited 1/, why: /setup\.sh failed/ },
    {
      name: 'the new checkout lacks qdrant_init',
      setup: (m) => edit(m.facts, 'features.qdrant_init', false),
      exitCode: 4,
      item: /the new checkout's facts/,
      detail: /the new checkout lacks qdrant_init/,
      why: /the new checkout's facts are not what the installer needs/,
    },
    { name: 'the new checkout lacks stop_jobs_flag', setup: (m) => edit(m.facts, 'features.stop_jobs_flag', false), exitCode: 4, item: /the new checkout's facts/, detail: /lacks stop_jobs_flag/, why: /not what the installer needs/ },
    // The digest goes to pmmcp only on stdin, and is confirmed only by check --expect.
    { name: 'the new checkout lacks rotate_digest_stdin', setup: (m) => edit(m.facts, 'features.rotate_digest_stdin', false), exitCode: 4, item: /the new checkout's facts/, detail: /lacks rotate_digest_stdin/, why: /not what the installer needs/ },
    { name: 'the new checkout lacks check_expect', setup: (m) => edit(m.facts, 'features.check_expect', false), exitCode: 4, item: /the new checkout's facts/, detail: /lacks check_expect/, why: /not what the installer needs/ },
    {
      name: 'the MCP server on another port',
      setup: (m) => edit(m.facts, 'config.server.port', 8768),
      exitCode: 4,
      item: /the new checkout's facts/,
      detail: /config\.server is 127\.0\.0\.1:8768: the installer needs server\.host on loopback \(127\.0\.0\.1\) and server\.port 8766/,
      why: /not what the installer needs/,
    },
    {
      name: 'the dashboard bound to every interface',
      setup: (m) => edit(m.facts, 'config.dashboard.host', '0.0.0.0'),
      exitCode: 4,
      item: /the new checkout's facts/,
      detail: /config\.dashboard is 0\.0\.0\.0:8765: the installer needs dashboard\.host on loopback/,
      why: /not what the installer needs/,
    },
  ]
  for (const c of stops) {
    const { m, plan } = fresh(c.setup)
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('fresh-install', plan.steps), { ok: false, exitCode: c.exitCode }, c.name)
    const item = itemNamed(applier.items, c.item)
    assert.equal(item.state, 'failed', c.name)
    assert.match(item.detail, c.detail, c.name)
    // Nothing after it ran: no stop, no start.
    assert.equal(m.ran(/stop-pmmcp-server\.sh|start-pmmcp-server\.sh/).length, 0, c.name)
    if (c.name === 'the clone target exists') assert.equal(m.ran(/^git clone /).length, 0)
    assert.ok(notReached(applier.report(), /the start and its checks/, c.why), `${c.name}:\n${applier.report().join('\n')}`)
  }

  // An earlier run's record discovery found stale is cleared before setup, which runs in its own session and is refused while a record stands.
  {
    const { m, plan } = fresh(() => undefined)
    const stale: ActiveRecord = { step: 'setup', pid: 4321, started: '2026-10-28T09:00:00.000Z', out: '/x/setup.out', err: '/x/setup.err' }
    mkdirSync(join(m.root, '.aos', 'install'), { recursive: true, mode: 0o700 })
    writeFileSync(activePath(m.root), JSON.stringify(stale), { mode: 0o600 })
    m.discovery = { ...(m.discovery as Absent), staleActive: stale }
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('fresh-install', plan.steps), { ok: true }, JSON.stringify(applier.items))
    assert.equal(m.ran(/setup\.sh --non-interactive$/).length, 1)
    assert.ok(m.printed.some((l) => l.includes("cleared an earlier run's .aos/install/active.json record of setup (pid 4321)")), m.text())
  }

  // A key file init could not make: failed, never done, and the start goes on without a key (exit 1).
  const { m, plan } = fresh((x) => x.over.set(`${x.py} scripts/qdrant_api_key.py init`, { err: 'use enable: this docker engine has pmmcp-qdrant\n', code: 1 }))
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('fresh-install', plan.steps), { ok: false, exitCode: 1 }, JSON.stringify(applier.items))
  assert.match(itemNamed(applier.items, /the Qdrant key file/).detail, /init exited 1/)
  assert.equal(itemNamed(applier.items, /the Qdrant key file/).state, 'failed')
  assert.equal(itemNamed(applier.items, /the start and its checks/).state, 'done')
  assert.equal(m.ran(/status --json$/).length, 0, 'a verdict was asked for a key that was never made')
})

// ── S8 ───────────────────────────────────────────────────────────────────

test('a whole window ends in a report of every item, the .env lines and mode, the digest and its load, the Qdrant verdict, the dashboard, the backups and the next steps, and never a value', async (t) => {
  const m = new Machine(t)
  m.qdrantBefore = keyless()
  edit(m.qdrantAfter, 'prekey_kept', true)
  const plan = m.plan()
  const { nonLive, live } = chosen(plan, ['qdrant', 'auth', 'restart'])
  m.kernelAfterStart = true
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', nonLive), { ok: true })
  assert.deepEqual(await applier.countJobs(), { state: 'counted', running: 0, display: [] })
  assert.deepEqual(await applier.apply('live', live), { ok: true }, JSON.stringify(applier.items))
  const report = applier.report()
  const text = report.join('\n')
  for (const what of [/graceful stop/, /Qdrant key cutover/, /the dashboard token/, /the curator secret/, /the start/, /bearer check/, /appended to \.env/, /digest staged/]) {
    assert.ok(report.some((l) => /^ {2}done {9}/.test(l) && what.test(l)), `no done line for ${String(what)}:\n${text}`)
  }
  assert.match(text, new RegExp(`\\.env {2}${join(m.root, '.env').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: created with AOS_CONTROL_TOKEN \\(line 3\\) and AOS_PMMCP_TOKEN \\(line 4\\); mode 0600`))
  assert.match(text, /pmmcp bearer: http_auth\.yaml present, mode warn, tokens \[antigravity\]/)
  assert.match(text, /aos-kernel digest matches \.env: yes; loaded by the running server: yes/)
  assert.match(text, /qdrant: verdict enforced/)
  assert.match(text, /pmmcp-qdrant-prekey kept; remove it later with cd .* && \.venv\/bin\/python scripts\/qdrant_api_key\.py cleanup/)
  assert.match(text, /dashboard: open it with cd .* && \.venv\/bin\/python -m src\.dashboard\.auth open/)
  assert.match(text, /backups made: .*http_auth\.yaml\.bak-20261029T100000Z/)
  assert.match(text, /restart npm run dev/)
  assert.match(text, /add ANTHROPIC_API_KEY to \.env yourself/)
  assert.match(text, /enforce is your later step/)
  assert.match(text, /rewrites ~\/\.persistent-memory-mcp\/config\.yaml/)
  // A success leaves no undo list behind, and no value anywhere.
  assert.equal(/to go back on what this run changed/.test(text), false)
  for (const v of m.minted) assert.equal(text.includes(v) || m.text().includes(v), false)
  // Every step the gate handed on is reported; none as skipped.
  assert.equal(report.some((l) => /^ {2}skipped/.test(l)), false, text)
})

test('the end report shows an ACL on .env when ls -le lists one or prints +, says it cannot tell for @, and looks at an existing .env the run did not write', async (t) => {
  const cases: readonly { readonly name: string; readonly mode: string; readonly acl: readonly string[]; readonly shown: RegExp | undefined }[] = [
    { name: '+', mode: '-rw-------+', acl: [], shown: /it carries an ACL, which the loader does not read: run chmod -N \.env/ },
    // macOS ls prints @ in place of + when the file has extended attributes too; -e still lists the entries.
    { name: '@ with an entry', mode: '-rw-------@', acl: [' 0: group:everyone deny delete'], shown: /it carries an ACL, which the loader does not read: run chmod -N \.env/ },
    { name: '@ alone', mode: '-rw-------@', acl: [], shown: /whether it carries an ACL cannot be told .*chmod -N \.env/ },
    { name: 'none', mode: '-rw-------', acl: [], shown: undefined },
  ]
  for (const c of cases) {
    const m = new Machine(t)
    const plan = m.plan()
    m.lsMode = c.mode
    m.lsAcl = [...c.acl]
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('non-live', chosen(plan, []).nonLive), { ok: true }, c.name)
    const text = applier.report().join('\n')
    assert.match(text, /; mode 0600/, c.name)
    if (c.shown === undefined) assert.equal(/ACL/.test(text), false, `${c.name}:\n${text}`)
    else assert.match(text, c.shown, c.name)
  }

  // A .env this run never writes is looked at all the same, once.
  const m = new Machine(t)
  const plan = restartOnly(m)
  m.lsMode = '-rw-------+'
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: true }, JSON.stringify(applier.items))
  const text = applier.report().join('\n')
  assert.match(text, new RegExp(`\\.env {2}${join(m.root, '.env').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: not written by this run; mode 0600`))
  assert.match(text, /run chmod -N \.env/)
  assert.equal(m.ran(/^ls -lde /).length, 1)
})

/** The gate's IO over this machine and an applier: a yes to every y/N question and the word each typed confirmation asks for. */
function gateIO(m: Machine, applier: Applier): GateIO {
  return {
    interactive: true,
    print: (line) => m.printed.push(line),
    ask: (q) => {
      m.asked.push(q)
      const text = q.includes('`stop pmmcp`') ? 'stop pmmcp' : q.includes('`Persistent-Memory-MCP`') ? 'Persistent-Memory-MCP' : q.includes('`install`') ? 'install' : 'y'
      return Promise.resolve({ kind: 'line', text })
    },
    countJobs: () => applier.countJobs(),
    pause: () => Promise.resolve('elapsed'),
    apply: (phase, steps) => applier.apply(phase, steps),
  }
}

test('a non-live phase that fails ends the run there, through the gate: no warning, no typed confirmation, no jobs count, no stop, no window (exit 1)', async (t) => {
  const m = new Machine(t)
  m.qdrantBefore = keyless()
  const plan = m.plan()
  assert.ok(plan.offers.some((o) => o.live), JSON.stringify(plan.offers))
  // The rotate refuses its arguments: nothing was written in http_auth.yaml, and the digest is not on file.
  m.over.set(`${m.py} scripts/rotate_http_auth_token.py aos-kernel --create --digest-stdin`, { err: 'usage: rotate_http_auth_token.py\n', code: 2 })
  const applier = m.applier(plan)
  const outcome = await runGate(plan, gateIO(m, applier), { dryRun: false })
  assert.deepEqual(outcome, { kind: 'failed', phase: 'non-live', applied: [], exitCode: 1 })
  assert.equal(itemNamed(applier.items, /digest staged/).state, 'failed')
  assert.deepEqual(m.windows, [], 'the window opened after a failed non-live step')
  assert.deepEqual(m.ran(/stop-pmmcp-server\.sh|start-pmmcp-server\.sh/), [], 'the jobs count, the stop or the start ran')
  assert.equal(m.asked.some((q) => /`stop pmmcp`|`Persistent-Memory-MCP`/.test(q)), false, m.asked.join('\n'))
  assert.equal(m.printed.some((l) => l.startsWith('WARNING: ')), false)
  // The window's steps were never handed on: skipped, as the gate never reached them.
  assert.ok(applier.report().some((l) => /^ {2}skipped +the graceful stop/.test(l) && !l.includes('not reached')), applier.report().join('\n'))
})

test("after the kept prekey's cleanup the report says it was removed and never also kept; a cleanup alone asks for no npm run dev restart", async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  m.qdrantBefore = edit(enforced(), 'prekey_kept', true)
  const plan = m.plan()
  // Beside the restart the run asks anyway, the cleanup is asked too; on its own it would be a note (install-plan.test.ts).
  assert.deepEqual(plan.offers.map((o) => o.id), ['qdrant-cleanup', 'restart'])
  const KEPT = /pmmcp-qdrant-prekey kept; remove it later with cd .* && \.venv\/bin\/python scripts\/qdrant_api_key\.py cleanup/
  assert.match(m.applier(plan).report().join('\n'), KEPT, 'before the cleanup the report says it is kept')
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', chosen(plan, ['qdrant-cleanup']).nonLive), { ok: true })
  const text = applier.report().join('\n')
  assert.match(text, /^ {2}done {9}the kept pmmcp-qdrant-prekey removed: pmmcp-qdrant-prekey removed \(its volumes stay\)$/m)
  assert.match(text, /^qdrant: verdict enforced$/m)
  assert.equal(KEPT.test(text), false, text)
  // Nothing the daemon reads changed: .env and pmmcp's bearer are as they were.
  assert.equal(/restart npm run dev/.test(text), false, text)
})

test('npm run dev is asked to restart only when something it reads changed: .env gained a line, or a new pmmcp loaded the aos-kernel digest', async (t) => {
  const says = (report: readonly string[]): boolean => report.some((l) => l.startsWith('  restart npm run dev (it reads .env when it starts)'))
  // A stop that did not stop, and the start asked for after it: pmmcp is back as it was, and the daemon has nothing new to read.
  const noop = new Machine(t)
  const plan = restartOnly(noop)
  noop.stopLeaves = [8767]
  noop.answer = { kind: 'line', text: '' }
  const noopApplier = noop.applier(plan)
  assert.deepEqual(await noopApplier.apply('live', chosen(plan, ['restart']).live), { ok: false, exitCode: 4 })
  assert.equal(itemNamed(noopApplier.items, /start pmmcp again/).state, 'done')
  assert.equal(says(noopApplier.report()), false, noopApplier.report().join('\n'))
  // The restart that loaded the digest: the daemon's next request is the one that shows it.
  const restart = new Machine(t)
  const restartPlan = restartOnly(restart)
  const restarted = restart.applier(restartPlan)
  assert.deepEqual(await restarted.apply('live', chosen(restartPlan, ['restart']).live), { ok: true }, JSON.stringify(restarted.items))
  assert.ok(restarted.report().some((l) => /loaded by the running server: yes/.test(l)))
  assert.equal(says(restarted.report()), true, restarted.report().join('\n'))
  // .env appended: always.
  const appended = new Machine(t)
  const appendPlan = appended.plan()
  const writer = appended.applier(appendPlan)
  assert.deepEqual(await writer.apply('non-live', chosen(appendPlan, []).nonLive), { ok: true })
  assert.equal(says(writer.report()), true)
  // A configured system: .env holds both tokens, the digest matches, and the server discovery found started after http_auth.yaml
  // last changed, so it had loaded the digest already. A cutover restarts pmmcp, and the daemon has nothing new to read.
  const configured = new Machine(t)
  utimesSync(configured.authFile, new Date(OLD_STARTED_AFTER.getTime() - 60_000), new Date(OLD_STARTED_AFTER.getTime() - 60_000))
  const cutPlan = cutoverOnly(configured)
  assert.equal(cutPlan.offers.some((o) => o.id === 'restart'), false, 'the digest is loaded: no restart is offered')
  configured.qdrantAfter = enforced()
  const cut = configured.applier(cutPlan)
  assert.deepEqual(await cut.apply('live', chosen(cutPlan, ['qdrant']).live), { ok: true }, JSON.stringify(cut.items))
  assert.ok(cut.report().some((l) => /digest matches \.env: yes; loaded by the running server: yes/.test(l)), cut.report().join('\n'))
  assert.equal(says(cut.report()), false, cut.report().join('\n'))
  // Nor does the bearer check ask one: the running daemon's hub reconnects to the restarted pmmcp by itself and sends the bearer.
  const bearer = itemNamed(cut.items, /bearer check/)
  assert.equal(bearer.state, 'inconclusive')
  assert.match(
    bearer.detail,
    /: the AOS daemon's next request makes the line \(its hub reconnects to the restarted pmmcp within its 240 s heartbeat; if npm run dev is not running, start it\), then grep "first request with token" ~\/\.persistent-memory-mcp\/logs\/server\.log$/,
  )
  assert.equal(/restart npm run dev/.test(cut.report().join('\n')), false, cut.report().join('\n'))
  // The same cutover where the server before it had not loaded the digest: the restart loaded it, and the daemon's bearer now counts.
  const unloaded = new Machine(t)
  const unloadedPlan = cutoverOnly(unloaded)
  const loading = unloaded.applier(unloadedPlan)
  assert.deepEqual(await loading.apply('live', chosen(unloadedPlan, ['qdrant']).live), { ok: true }, JSON.stringify(loading.items))
  assert.equal(says(loading.report()), true, loading.report().join('\n'))
  // A server that had loaded http_auth.yaml, but without the digest: this run stages it, and the restart that loads it is new to
  // the daemon although .env gained nothing.
  const staging = new Machine(t)
  staging.preEnv()
  staging.bearer = { state: 'absent' }
  utimesSync(staging.authFile, new Date(OLD_STARTED_AFTER.getTime() - 60_000), new Date(OLD_STARTED_AFTER.getTime() - 60_000))
  const stagePlan = staging.plan()
  assert.deepEqual(chosen(stagePlan, ['restart']).nonLive.map((s) => s.id), ['stage-digest'])
  const stager = staging.applier(stagePlan)
  assert.deepEqual(await stager.apply('non-live', chosen(stagePlan, ['restart']).nonLive), { ok: true })
  assert.deepEqual(await stager.apply('live', chosen(stagePlan, ['restart']).live), { ok: true }, JSON.stringify(stager.items))
  assert.match(stager.report().join('\n'), /^\.env  .*: not written by this run/m)
  assert.equal(says(stager.report()), true, stager.report().join('\n'))
  // No aos-kernel token at all (kernel.yaml declares no tokenEnv for pmmcp): a cutover's new server loads http_auth.yaml, but no
  // digest of the daemon's is in it, so nothing the daemon reads changed.
  const bare = new Machine(t)
  const doc = structuredClone(raw('config/kernel.yaml')) as { mcp: { servers: Record<string, Record<string, unknown>> } }
  const pmmcp = doc.mcp.servers['pmmcp']
  assert.ok(pmmcp !== undefined)
  delete pmmcp['tokenEnv']
  bare.config = parseKernelConfig(doc, { repoRoot: REPO_ROOT })
  bare.bearer = { state: 'not-checked', why: 'kernel.yaml declares no tokenEnv for pmmcp' }
  const barePlan = cutoverOnlyWith(bare)
  assert.equal(barePlan.staged, undefined)
  const bareApplier = bare.applier(barePlan)
  assert.deepEqual(await bareApplier.apply('live', chosen(barePlan, ['qdrant']).live), { ok: true }, JSON.stringify(bareApplier.items))
  assert.equal(says(bareApplier.report()), false, bareApplier.report().join('\n'))
})

test('an lsof that fails after the start is reported as a check not made, never as "no MCP server listens", and leaves "loaded" not known', async (t) => {
  for (const failure of [{ code: 2, err: 'lsof: status error on /dev\n' }, { signal: 'SIGKILL' as const }]) {
    const m = new Machine(t)
    const plan = restartOnly(m)
    const started = (): boolean => m.calls.some((c) => c.key === join(m.dir, START_SCRIPT))
    m.over.set('lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', () => (started() ? failure : undefined))
    const applier = m.applier(plan)
    assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: false, exitCode: 4 }, JSON.stringify(failure))
    const start = itemNamed(applier.items, /the start/)
    assert.equal(start.state, 'failed')
    assert.match(start.detail, /whether an MCP server of this account listens on 8766 could not be checked \(lsof failed: (?:lsof exited 2|lsof-8766: lsof ended by SIGKILL)\)/, start.detail)
    assert.equal(/no MCP server of this account listens/.test(start.detail), false, start.detail)
    const text = applier.report().join('\n')
    assert.match(text, /aos-kernel digest matches \.env: yes; loaded by the running server: not known/, text)
  }
  // lsof that answers, with nothing of this account there: that is a finding, and the server loaded nothing.
  const none = new Machine(t)
  const plan = restartOnly(none)
  none.startServer = false
  const applier = none.applier(plan)
  assert.deepEqual(await applier.apply('live', chosen(plan, ['restart']).live), { ok: false, exitCode: 4 })
  assert.match(itemNamed(applier.items, /the start/).detail, /no MCP server of this account listens on 8766/)
  assert.match(applier.report().join('\n'), /loaded by the running server: no/)
})

test('with --no-install, the report gives no next step about a pmmcp that is not installed', async (t) => {
  const m = new Machine(t, { installed: false })
  m.discovery = m.absent()
  const map = [...credentialsMap(m.config).keys()]
  const plan = planInstall({
    config: m.config,
    providers: PROVIDERS,
    dotenv: inspectIn(m, [...map, 'ANTHROPIC_API_KEY']),
    room: inspectIn(m, map),
    exported: new Set(),
    pmmcp: m.discovery,
    tuiPids: [],
    options: { aosOnly: false, noInstall: true },
  })
  assert.equal(plan.kind, 'not-installed')
  const applier = m.applier(plan)
  assert.deepEqual(await applier.apply('non-live', chosen(plan, []).nonLive), { ok: true })
  const text = applier.report().join('\n')
  assert.match(text, /^ {2}restart npm run dev/m, 'the .env it wrote is something the daemon reads')
  assert.equal(/warn mode|setup\.sh|config\.yaml|pmmcp bearer|qdrant:/.test(text), false, text)
})

test('pmmcp stopped after the last installer run that stopped it ran no start is started by a window of its own: the stop (for whatever else runs), then the start and its checks', async (t) => {
  const m = new Machine(t)
  m.preEnv()
  m.bearer = { state: 'matches' }
  m.auth.dashboard_token = 'present'
  m.auth.curator_secret = 'present'
  edit(m.facts, 'dashboard_token', { state: 'present' })
  edit(m.facts, 'curator_secret', { state: 'present' })
  // As a run killed after L1 left it: nothing listens, no PID file names a live process, Qdrant stopped, launchd unloaded.
  m.listeners.clear()
  m.alive.clear()
  m.running = false
  m.qdrant = 'exited'
  for (const name of ['mcp.pid', 'worker.pid', 'scraper_worker.pid']) rmSync(join(m.pmmcpHome, 'pids', name), { force: true })
  m.discoveredServer = false
  m.leftStopped = { folder: join(m.root, '.aos', 'install', '20261029T090000Z') }
  const plan = m.plan()
  assert.deepEqual(plan.offers.map((o) => o.id), ['start'])
  const { nonLive, live } = chosen(plan, ['start'])
  assert.deepEqual([nonLive, live.map((s) => s.id)], [[], ['stop', 'start', 'bearer-check']])
  const applier = m.applier(plan)
  const outcome = await runGate(plan, gateIO(m, applier), { dryRun: false })
  assert.deepEqual(outcome, { kind: 'done', applied: ['live'], exitCode: 0 }, JSON.stringify(applier.items))
  assert.ok(m.asked.includes('Start pmmcp (stopped now; the last installer run that stopped it ran no start after it)? [y/N]'), m.asked.join('\n'))
  assert.ok(m.asked.some((q) => q.includes('`stop pmmcp`')) && m.asked.some((q) => q.includes('`Persistent-Memory-MCP`')), 'the start ran without both typed confirmations')
  assert.equal(itemNamed(applier.items, /graceful stop/).state, 'done')
  assert.match(itemNamed(applier.items, /the start/).detail, /^\/health 200; a new MCP server \(pid 913\), started after http_auth\.yaml last changed; pmmcp-qdrant running/)
  assert.deepEqual(m.windows, [true, false])
  assert.match(applier.report().join('\n'), /loaded by the running server: yes/)
})

test('logTail reads a regular file from its end, never through a link, and nothing else', (t) => {
  const dir = tmpdir(t)
  const file = join(dir, 'server.log')
  writeFileSync(file, `${'x'.repeat(100)}\nsecond\nthird\n`)
  assert.deepEqual(logTail(file, 1024), ['x'.repeat(100), 'second', 'third'])
  // From the middle of a line, that line's end is dropped.
  assert.deepEqual(logTail(file, 16), ['second', 'third'])
  assert.deepEqual(logTail(join(dir, 'missing.log'), 1024), [])
  assert.deepEqual(logTail(dir, 1024), [])
  const link = join(dir, 'link.log')
  symlinkSync(file, link)
  assert.deepEqual(logTail(link, 1024), [])

  // From a mark: only what was written after it; the whole file once it is another file or shorter than the mark.
  const mark = logMark(file)
  assert.ok(mark !== null)
  appendFileSync(file, 'fourth\nfifth\n')
  assert.deepEqual(logTail(file, 1024, mark), ['fourth', 'fifth'])
  assert.deepEqual(logTail(file, 8, mark), ['fifth'])
  assert.deepEqual(logTail(file, 1024, null), ['x'.repeat(100), 'second', 'third', 'fourth', 'fifth'])
  const rotated = join(dir, 'rotated.log')
  writeFileSync(rotated, 'new\n')
  assert.deepEqual(logTail(rotated, 1024, mark), ['new'])
  writeFileSync(file, 'cut\n')
  assert.deepEqual(logTail(file, 1024, mark), ['cut'])
  assert.equal(logMark(join(dir, 'missing.log')), null)
})
