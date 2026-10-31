// The installer's discovery (scripts/install/discover.ts) and pmmcp's machine
// documents as it reads them (src/install/facts.ts).
//
// Discovery is read-only, and these tests are about what it concludes from
// what pmmcp's interfaces print: where the install is, whether it is one,
// what its code can do, and which findings stop the installer before it
// plans anything. Every repository and HOME here is a mkdtemp directory;
// every child is a fake behind the A3 runner, answering as plutil, lsof, ps,
// git, launchctl, docker and pmmcp's scripts would, and never one of them;
// every HTTP endpoint is a node:http server on an ephemeral loopback port.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import fs, { chmodSync, closeSync, constants, existsSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync, writeSync } from 'node:fs'
import http, { createServer, type IncomingHttpHeaders } from 'node:http'
import { syncBuiltinESMExports } from 'node:module'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import test, { type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import {
  DOCKER_CONTEXT,
  DiscoverError,
  GitConfigError,
  HTTP_BODY_CAP,
  PMMCP_FOLDER,
  PYPROJECT_CAP,
  READ_ONLY_POLLS,
  READ_ONLY_POLL_MS,
  discover,
  earlierStop,
  githubRepo,
  loopbackGet,
  loopbackGetWith,
  originUrlIn,
  parseEtime,
  programOf,
  projectName,
  readRegular,
  serverDirOf,
  startedAfter,
  withoutUserinfo,
  type Discovery,
  type Found,
  type HttpGet,
  type RequestFn,
  type Stop,
  type Stopped,
} from '../scripts/install/discover.js'
import { Runner, STOP_SCRIPT, activePath, type ChildOptions, type SpawnFn } from '../scripts/install/run.js'
import { foundScreen } from '../scripts/install.js'
import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { FEATURE_COMMITS, FEATURE_NAMES, PmmcpDocumentError, featuresOf, keyedLoopbackOnly, missingFeatures, parseFacts, parseQdrantStatus } from '../src/install/facts.js'
import { parseProviders, type ProvidersFile } from '../src/models/registry.js'
import { bareName, bareStandIns, pythonStandIn, shWord } from './helpers/python-stand-in.js'
import { tmpdir } from './helpers/tmpdir.js'

const REPO = fileURLToPath(new URL('..', import.meta.url))
const NOW = new Date('2026-10-29T08:00:00.000Z')
/** The operator's uid on the Mac; the suite may run as root, which the .env writer's inspection refuses. */
const OP_UID = 501
const SERVER_PID = 812
const HEAD = 'e6516d5'.padEnd(40, '0')
const ORIGIN_MAIN = '53ea308'.padEnd(40, '0')
const ORIGIN = 'https://github.com/AiBot-Tools/persistent-memory-mcp.git'
/** What ps prints as the MCP server's etime: 1 h 45 min 57 s. */
const SERVER_ETIME = '01:45:57'
const SERVER_ETIME_S = 6357

const SHIPPED_KERNEL = parseYaml(readFileSync(join(REPO, 'config', 'kernel.yaml'), 'utf8')) as unknown
const SHIPPED_PROVIDERS: ProvidersFile = parseProviders(parseYaml(readFileSync(join(REPO, 'config', 'providers.yaml'), 'utf8')))

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

/** The facts as e6516d5 prints them for a healthy install. */
function factsDoc(dir: string, home: string, plist: boolean): Doc {
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
    launchd: {
      plist: join(home, 'Library', 'LaunchAgents', 'com.aibot.pmmcp.plist'),
      exists: plist,
      working_directory: plist ? dir : null,
      legacy_plists: [],
    },
  }
}

/** The facts as dfcc99a printed them: no curator_proof, no stop_listener_check, no http_auth.links. */
function dfcc99a(doc: Doc): Doc {
  edit(doc, 'features.curator_proof')
  edit(doc, 'features.stop_listener_check')
  edit(doc, 'http_auth.links')
  return doc
}

/** Qdrant's status for a keyless container on 127.0.0.1, as status --json prints it. */
function qdrantDoc(): Doc {
  return {
    docker_context: 'desktop-linux',
    key_file: { state: 'absent', reason: null },
    container: {
      state: 'running',
      key_set: false,
      image12: '0123456789ab',
      published: [{ host_ip: '127.0.0.1', host_port: 6333, container_port: '6333/tcp' }],
      publish_all_ports: false,
      reachable_beyond_loopback: [],
    },
    prekey_kept: false,
    collections: { without_key: 200, with_key: null },
    verdict: 'not_asked',
  }
}

interface Answer {
  readonly out?: string
  readonly err?: string
  readonly code?: number
  /** The spawn fails with this errno: the program is not there. */
  readonly spawnError?: string
}

interface Call {
  readonly command: string
  readonly args: readonly string[]
  readonly options: ChildOptions
  stdin: string
}

class FakeChild extends EventEmitter {
  readonly pid: number | undefined
  readonly stdin: PassThrough | null
  constructor(pid: number | undefined, piped: boolean) {
    super()
    this.pid = pid
    this.stdin = piped ? new PassThrough() : null
  }
  kill(): boolean {
    return true
  }
}

interface Served {
  readonly port: number
  readonly path: string
  readonly headers: IncomingHttpHeaders
}

/**
 * One machine as discovery sees it: an AOS checkout, a HOME, perhaps a pmmcp
 * install, and the answers its programs and ports give. Tests change the
 * fields, then call run().
 */
class World {
  readonly root: string
  readonly home: string
  /** The install folder the default answers describe. */
  dir: string
  /** The plist's WorkingDirectory, or no plist. */
  plistDir: string | undefined
  /** The plist's ProgramArguments[1], when it is not <plistDir>/.venv/bin/pmmcp. */
  plistProgram: string | undefined
  /** The folder of the MCP server listening on 8766, or nothing listens. */
  listenerDir: string | undefined
  listenerUid = OP_UID
  /** The [remote "origin"] url written into the install's .git/config at run(); undefined writes no remote. */
  origin: string | undefined = ORIGIN
  /** refs/remotes/origin/main as the checkout has it: HEAD itself means no update. */
  originMain = ORIGIN_MAIN
  /** The locale a shell on the Mac hands the installer, which the runner passes on. */
  lang = 'en_US.UTF-8'
  /** Whether run() writes the install's .git/config from `origin`; a test that lays out .git itself turns it off. */
  writeGit = true
  facts: Doc
  qdrant: Doc = qdrantDoc()
  dockerContext = DOCKER_CONTEXT
  dockerInfoCode = 0
  jobs: Answer = { out: 'running jobs: 0\n' }
  check: Answer = { out: 'aos-kernel: absent\n', code: 3 }
  enforce = false
  config: KernelConfig
  providers: ProvidersFile = SHIPPED_PROVIDERS
  readonly overrides = new Map<string, Answer>()
  readonly calls: Call[] = []
  readonly served: Served[] = []
  /** Logical port → the ephemeral port its fake server listens on. */
  readonly ports = new Map<number, number>()
  readonly handlers = new Map<number, (path: string) => { status: number; body: string }>()
  /** Every pause discovery asked for, in milliseconds. */
  readonly slept: number[] = []
  /** Called at each pause, after it is counted: a test changes the world while discovery waits. */
  onSleep: (() => void) | undefined
  /** What discovery said at once (its print), with the number of pauses taken before each line. */
  readonly said: { readonly line: string; readonly afterPauses: number }[] = []

  /** `under`: the install's folder, as path parts under HOME (default Github/Persistent-Memory-MCP). */
  constructor(t: TestContext, options: { under?: readonly string[]; install?: boolean; plist?: boolean; listener?: boolean } = {}) {
    this.root = tmpdir(t)
    writeFileSync(join(this.root, '.gitignore'), '/.aos/\n.env\n')
    this.home = tmpdir(t)
    // What the runner spawns for a bare name: the file it found on the child's PATH, whose first entry is ~/.local/bin.
    bareStandIns(this.home)
    this.dir = join(this.home, ...(options.under ?? ['Github', PMMCP_FOLDER]))
    if (options.install ?? true) makeInstall(this.dir)
    this.plistDir = options.plist === true ? this.dir : undefined
    this.listenerDir = options.listener === true ? this.dir : undefined
    this.facts = factsDoc(this.dir, this.home, options.plist === true)
    this.config = parseKernelConfig(structuredClone(SHIPPED_KERNEL), { repoRoot: this.root })
    this.handlers.set(8766, (path) => {
      if (path === '/health') return { status: 200, body: '{"status":"ok"}' }
      if (path === '/.well-known/oauth-protected-resource') {
        return { status: 200, body: JSON.stringify({ resource: 'http://127.0.0.1:8766/mcp', authorization_servers: [], bearer_methods_supported: this.enforce ? ['header'] : [], scopes_supported: [] }) }
      }
      return { status: 404, body: '' }
    })
    this.handlers.set(8765, (path) => (path === '/api/auth/status' ? { status: 200, body: '{"auth_required":false,"source":"none"}' } : { status: 404, body: '' }))
    this.handlers.set(6333, (path) => (path === '/' ? { status: 200, body: '{"title":"qdrant - vector search engine","version":"1.13.4"}' } : { status: 404, body: '' }))
    this.handlers.set(7777, () => ({ status: 404, body: 'not found' }))
  }

  get plist(): string {
    return join(this.home, 'Library', 'LaunchAgents', 'com.aibot.pmmcp.plist')
  }

  get python(): string {
    return join(this.dir, '.venv', 'bin', 'python')
  }

  /** The answer a program gives, from the world as it is now. */
  answer(call: Call): Answer {
    const key = [call.command, ...call.args].join(' ')
    const over = this.overrides.get(key)
    if (over !== undefined) return over
    const listener = this.listenerDir
    switch (key) {
      case `plutil -extract WorkingDirectory raw -o - ${this.plist}`:
        return this.plistDir === undefined ? { code: 1, err: 'Could not extract value\n' } : { out: `${this.plistDir}\n` }
      case `plutil -extract ProgramArguments.1 raw -o - ${this.plist}`:
        return this.plistDir === undefined ? { code: 1 } : { out: `${this.plistProgram ?? join(this.plistDir, '.venv', 'bin', 'pmmcp')}\n` }
      case 'lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu':
        return listener === undefined ? { code: 1 } : { out: `p${String(SERVER_PID)}\nu${String(this.listenerUid)}\nf7\n` }
      case `ps -ww -o uid=,args= -p ${String(SERVER_PID)}`:
        return listener === undefined ? { code: 1 } : { out: `  ${String(this.listenerUid)} ${listener}/.venv/bin/python ${listener}/.venv/bin/pmmcp\n` }
      case `ps -o lstart= -p ${String(SERVER_PID)}`:
        // In the locale the installer's shell has: never what discovery reads.
        return { out: this.lang.startsWith('de') ? 'Do 29 Okt 06:14:09 2026\n' : 'Thu Oct 29 06:14:09 2026\n' }
      case `ps -o etime= -p ${String(SERVER_PID)}`:
        return { out: `${SERVER_ETIME}\n` }
      case `${this.python} scripts/pmmcp_facts.py --json`:
        return { out: `${JSON.stringify(this.facts, null, 2)}\n` }
      case `${this.python} -B scripts/qdrant_api_key.py status --json`:
        return { out: `${JSON.stringify(this.qdrant)}\n` }
      case `${this.python} -B -m src.transport.http_auth check --expect aos-kernel`:
        return this.check
      case 'docker context show':
        return { out: `${this.dockerContext}\n` }
      case 'docker info --format {{.ServerVersion}}':
        return this.dockerInfoCode === 0 ? { out: '29.0.1\n' } : { code: this.dockerInfoCode, err: 'Cannot connect to the Docker daemon\n' }
      case `launchctl print gui/${String(OP_UID)}/com.aibot.pmmcp`:
        return this.plistDir === undefined
          ? { code: 113, err: 'Could not find service "com.aibot.pmmcp" in domain for user gui: 501\n' }
          : { out: `gui/501/com.aibot.pmmcp = {\n\tactive count = 1\n\tstate = running\n\tpid = ${String(SERVER_PID)}\n\tendpoints = {\n\t\tstate = active\n\t}\n}\n` }
      case 'git --no-optional-locks rev-parse --verify -q refs/remotes/origin/main^{commit}':
        return { out: `${this.originMain}\n` }
      case 'git --no-optional-locks rev-parse --verify -q HEAD':
        return { out: `${HEAD}\n` }
      case `git --no-optional-locks merge-base --is-ancestor HEAD ${this.originMain}`:
        return { code: 0 }
      case `git --no-optional-locks diff --quiet HEAD ${this.originMain} -- uv.lock pyproject.toml`:
        return { code: 0 }
      case 'git --no-optional-locks status --porcelain':
        return { out: '?? notes.txt\n' }
      case `${join(this.dir, STOP_SCRIPT)} --jobs`:
        return this.jobs
      default:
        return { code: 127, err: `fake: no answer for ${key}\n` }
    }
  }

  readonly spawn: SpawnFn = (command, args, options) => {
    // By the name the installer gave it: a bare name reaches spawn as its stand-in's path.
    const call: Call = { command: bareName(command, this.home), args: [...args], options, stdin: '' }
    this.calls.push(call)
    const a = this.answer(call)
    const child = new FakeChild(a.spawnError === undefined ? 4000 + this.calls.length : undefined, options.stdio[0] === 'pipe')
    if (a.spawnError !== undefined) {
      setImmediate(() => child.emit('error', Object.assign(new Error(`spawn ${command} ${a.spawnError ?? ''}`), { code: a.spawnError })))
      return child
    }
    if (a.out !== undefined) writeSync(options.stdio[1], a.out)
    if (a.err !== undefined) writeSync(options.stdio[2], a.err)
    setImmediate(() => {
      const read: unknown = child.stdin?.read()
      call.stdin = read === null || read === undefined ? '' : String(read)
      child.emit('exit', a.code ?? 0, null)
    })
    return child
  }

  /** Every logical port served by a node:http server on an ephemeral loopback port. */
  async serve(t: TestContext): Promise<void> {
    for (const [logical, handler] of this.handlers) {
      const server = createServer((req, res) => {
        this.served.push({ port: logical, path: req.url ?? '', headers: req.headers })
        const { status, body } = handler(req.url ?? '/')
        res.writeHead(status, { 'content-type': 'application/json', connection: 'close' })
        res.end(body)
      })
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
      this.ports.set(logical, (server.address() as AddressInfo).port)
      t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
    }
  }

  /** The GET discovery makes: the real loopbackGet, at the ephemeral port its logical one maps to. */
  readonly http: HttpGet = (target, timeoutMs) => {
    const port = this.ports.get(target.port)
    if (port === undefined) return Promise.resolve({ status: 0, body: '', error: 'ECONNREFUSED' })
    return loopbackGet({ ...target, port }, timeoutMs)
  }

  /** The runner's environment: what a shell on the Mac would hand the installer, DOCKER_* included. */
  env(): Record<string, string> {
    return {
      HOME: this.home,
      USER: 'op',
      LANG: this.lang,
      LC_ALL: this.lang,
      PATH: '/usr/bin:/bin',
      DOCKER_CONFIG: join(this.root, '.aos', 'docker'),
      DOCKER_HOST: 'unix:///Users/op/.colima/hostile/docker.sock',
      DOCKER_CONTEXT: 'colima-hostile',
      PMMCP_CONFIG_PATH: '/Users/op/elsewhere.yaml',
    }
  }

  /** What the HOME and the AOS checkout held just before the last run. */
  before: { readonly root: ReadonlyMap<string, string>; readonly home: ReadonlyMap<string, string> } | undefined

  async run(t: TestContext, extra: { pmmcpDir?: string } = {}): Promise<Discovery> {
    if (this.ports.size === 0) await this.serve(t)
    if (this.plistDir !== undefined) writePlist(this.plist, this.plistDir)
    // A .git file (a worktree's) is the test's own layout.
    if (this.writeGit && existsSync(join(this.dir, '.git')) && statSync(join(this.dir, '.git')).isDirectory()) writeGitConfig(this.dir, this.origin)
    this.before = { root: tree(this.root), home: tree(this.home) }
    const runner = new Runner({ repoRoot: this.root, env: this.env(), spawn: this.spawn, now: () => NOW })
    return discover({
      repoRoot: this.root,
      home: this.home,
      runner,
      config: this.config,
      providers: this.providers,
      uid: OP_UID,
      inspect: { euid: OP_UID },
      http: this.http,
      now: () => NOW,
      sleep: (ms) => {
        this.slept.push(ms)
        this.onSleep?.()
        return Promise.resolve()
      },
      print: (line) => this.said.push({ line, afterPauses: this.slept.length }),
      ...extra,
    })
  }

  /** Whether any child was handed the stop or start script, as its command or in an argument. */
  ranScript(): boolean {
    return this.calls.some((c) => [c.command, ...c.args].some((a) => /(?:stop|start)-pmmcp-server\.sh/i.test(a)))
  }

  ran(command: string, ...args: string[]): boolean {
    return this.calls.some((c) => c.command === command && args.every((a, i) => c.args[i] === a))
  }
}

/** Every path under `dir`, with its type, size and mode: enough to see that nothing was written. */
function tree(dir: string, out = new Map<string, string>(), rel = ''): Map<string, string> {
  for (const name of readdirSync(join(dir, rel))) {
    const path = rel === '' ? name : join(rel, name)
    const st = statSync(join(dir, path))
    out.set(path, `${st.isDirectory() ? 'd' : 'f'} ${String(st.size)} ${(st.mode & 0o7777).toString(8)} ${String(st.mtimeMs)}`)
    if (st.isDirectory()) tree(dir, out, path)
  }
  return out
}

/** What changed between two trees: added, removed or altered paths. */
function changes(before: ReadonlyMap<string, string>, after: ReadonlyMap<string, string>): string[] {
  const out: string[] = []
  for (const [p, v] of after) if (before.get(p) !== v) out.push(p)
  for (const p of before.keys()) if (!after.has(p)) out.push(`-${p}`)
  return out.sort()
}

/** A pmmcp checkout as setup.sh leaves it, as far as discovery looks. */
function makeInstall(dir: string, name = 'persistent-memory-mcp'): void {
  mkdirSync(join(dir, '.venv', 'bin'), { recursive: true })
  mkdirSync(join(dir, 'scripts'), { recursive: true })
  writeFileSync(join(dir, 'pyproject.toml'), `[build-system]\nrequires = ["hatchling"]\n\n[project]\nname = "${name}"\nversion = "3.0.0"\n\n[project.scripts]\npmmcp = "src.mcp_server:main"\n`)
  writeFileSync(join(dir, '.venv', 'bin', 'pmmcp'), '#!/usr/bin/env python3\n')
  chmodSync(join(dir, '.venv', 'bin', 'pmmcp'), 0o755)
  writeFileSync(join(dir, 'scripts', 'pmmcp_facts.py'), '# facts\n')
  writeGitConfig(dir, ORIGIN)
}

/** A clone's .git/config as git writes it, with this origin (or none). */
function writeGitConfig(dir: string, origin: string | undefined): void {
  mkdirSync(join(dir, '.git'), { recursive: true })
  const remote = origin === undefined ? '' : `[remote "origin"]\n\turl = ${origin}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`
  writeFileSync(join(dir, '.git', 'config'), `[core]\n\trepositoryformatversion = 0\n\tbare = false\n${remote}[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`)
}

/** A file's text, or '' for a folder or a file gone. */
function readFileSafe(path: string): string {
  try {
    return statSync(path).isFile() ? readFileSync(path, 'utf8') : ''
  } catch {
    return ''
  }
}

/**
 * A FIFO at `path`, made the way the installer runs any program: through the runner (no test but four
 * imports child_process), by a stand-in python whose body runs mkfifo, which is no program the installer runs.
 */
async function mkfifo(t: TestContext, path: string): Promise<void> {
  const root = tmpdir(t)
  writeFileSync(join(root, '.gitignore'), '/.aos/\n')
  const runner = new Runner({ repoRoot: root, env: { HOME: tmpdir(t) }, now: () => NOW })
  const made = await runner.run({ step: 'mkfifo', ...pythonStandIn(t, `exec mkfifo ${shWord(path)}`), timeoutMs: 10_000 })
  assert.equal(made.code, 0, `mkfifo ${path} failed`)
}

/**
 * A process that opens `fifo` for writing after `seconds` and writes a project file into it: what
 * releases a reader that blocked on it. release() holds the FIFO open for reading until it has.
 */
function fifoWriter(t: TestContext, fifo: string, seconds: number): { release: () => Promise<void> } {
  const root = tmpdir(t)
  writeFileSync(join(root, '.gitignore'), '/.aos/\n')
  // A stand-in python whose body writes: the runner runs no shell, nor anything else the installer does not run.
  const writer = pythonStandIn(t, `sleep ${String(seconds)}\nprintf '[project]\\nname = "late"\\n' > ${shWord(fifo)}`)
  const runner = new Runner({ repoRoot: root, env: { HOME: tmpdir(t) }, now: () => NOW })
  const started = runner.start({ step: 'fifo-writer', ...writer, timeoutMs: (seconds + 20) * 1000 })
  return {
    release: async () => {
      const fd = openSync(fifo, constants.O_RDONLY | constants.O_NONBLOCK)
      try {
        await started.done
      } finally {
        closeSync(fd)
      }
    },
  }
}

/** Every file of this run's logs, by name, with what it holds. */
function logs(root: string): Map<string, string> {
  const out = new Map<string, string>()
  const base = join(root, '.aos', 'install')
  if (!existsSync(base)) return out
  for (const run of readdirSync(base).filter((n) => statSync(join(base, n)).isDirectory())) {
    for (const file of readdirSync(join(base, run))) out.set(file, readFileSync(join(base, run, file), 'utf8'))
  }
  return out
}

function writePlist(path: string, dir: string): void {
  mkdirSync(join(path, '..'), { recursive: true })
  writeFileSync(
    path,
    `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>Label</key><string>com.aibot.pmmcp</string>` +
      `<key>ProgramArguments</key><array><string>${dir}/.venv/bin/python</string><string>${dir}/.venv/bin/pmmcp</string></array>` +
      `<key>WorkingDirectory</key><string>${dir}</string></dict></plist>\n`,
  )
}

function found(d: Discovery): Found {
  if (d.kind !== 'found') assert.fail(`expected an install, got ${d.kind}: ${d.kind === 'stopped' ? d.stops.map((s) => `${s.code}: ${s.message}`).join(' | ') : ''}`)
  return d
}

function stopped(d: Discovery): Stopped {
  if (d.kind !== 'stopped') assert.fail(`expected discovery to stop, got ${d.kind}`)
  return d
}

/** The one stop with this code; it must be there. */
function stopWith(d: Discovery, code: Stop['code']): Stop {
  const s = stopped(d).stops.find((x) => x.code === code)
  if (s === undefined) assert.fail(`no ${code} stop among ${JSON.stringify(stopped(d).stops)}`)
  return s
}

const withoutTokenEnv = (config: KernelConfig): KernelConfig => {
  const pmmcp = config.mcp.servers['pmmcp']
  assert.ok(pmmcp)
  const { tokenEnv: _declared, ...rest } = pmmcp
  return { ...config, mcp: { ...config.mcp, servers: { ...config.mcp.servers, pmmcp: rest } } }
}

const withUrl = (config: KernelConfig, url: string): KernelConfig => {
  const pmmcp = config.mcp.servers['pmmcp']
  assert.ok(pmmcp)
  return { ...config, mcp: { ...config.mcp, servers: { ...config.mcp.servers, pmmcp: { ...pmmcp, url } } } }
}

test('the install is found from the plist WorkingDirectory first, then the process on 8766, then ~/Github/Persistent-Memory-MCP', async (t) => {
  // The plist names a folder outside the default place, and the server on 8766 runs from it too.
  const a = new World(t, { under: ['src', PMMCP_FOLDER], plist: true, listener: true })
  const byPlist = found(await a.run(t))
  assert.deepEqual(byPlist.install, { dir: a.dir, source: 'plist' })
  assert.deepEqual(a.calls.slice(0, 2).map((c) => c.args.slice(0, 2)), [['-extract', 'WorkingDirectory'], ['-extract', 'ProgramArguments.1']])
  // What runs and how: the launchd service, the MCP server's pid and start, its endpoints.
  assert.deepEqual(byPlist.service, { loaded: true, state: 'running', pid: SERVER_PID })
  assert.equal(byPlist.server?.pid, SERVER_PID)
  // From etime, never lstart: the start is a lower bound, a second before what ps's whole seconds say.
  assert.equal(byPlist.server?.startedAfter?.getTime(), NOW.getTime() - (SERVER_ETIME_S + 1) * 1000)
  assert.equal(a.ran('ps', '-o', 'lstart='), false)
  assert.equal(byPlist.staleActive, undefined)
  assert.deepEqual(byPlist.endpoints, { health: 200, bearer: 'off-or-warn', dashboard: { status: 200, authRequired: false, source: 'none' }, qdrant: { status: 200, version: '1.13.4' } })
  assert.deepEqual(byPlist.git, { head: HEAD, originMain: ORIGIN_MAIN, fastForward: true, lockUnchanged: true, trackedChanges: 0, untracked: 1 })
  assert.equal(byPlist.qdrant?.verdict, 'not_asked')
  // Every child ran with the runner's environment, in which no DOCKER_* or PMMCP_* name survives.
  for (const c of a.calls) assert.deepEqual(Object.keys(c.options.env).filter((k) => /^(?:DOCKER|PMMCP)_/.test(k)), [], `${c.command} got a DOCKER_* or PMMCP_* name`)
  // The probes asked loopback only, with no credential.
  assert.ok(a.served.length >= 4)
  for (const s of a.served) assert.equal(s.headers.authorization, undefined)
  // Read-only: HOME is as it was, and in the checkout only the runner's logs are new, 0600 in 0700 folders.
  assert.ok(a.before)
  assert.deepEqual(changes(a.before.home, tree(a.home)), [])
  const written = changes(a.before.root, tree(a.root))
  assert.ok(written.length > 2)
  for (const p of written) {
    assert.match(p, /^\.aos(?:\/install(?:\/20261029T080000Z(?:\/[a-z0-9.-]+\.(?:out|err))?)?)?$/, p)
    const mode = statSync(join(a.root, p)).mode & 0o777
    assert.equal(mode, statSync(join(a.root, p)).isDirectory() ? 0o700 : 0o600, p)
  }

  // No plist: the server listening on 8766 names the folder.
  const b = new World(t, { under: ['work', PMMCP_FOLDER], listener: true })
  const byListener = found(await b.run(t))
  assert.deepEqual(byListener.install, { dir: b.dir, source: 'listener' })
  assert.equal(byListener.service.loaded, false)
  assert.equal(byListener.server?.pid, SERVER_PID)

  // Neither: the default place.
  const c = new World(t)
  // The running server enforces its bearer while the file says warn: the RFC 9728 document shows it.
  c.enforce = true
  const byDefault = found(await c.run(t))
  assert.deepEqual(byDefault.install, { dir: join(c.home, 'Github', PMMCP_FOLDER), source: 'default' })
  assert.equal(byDefault.server, undefined)
  assert.equal(byDefault.endpoints.bearer, 'enforce')
  assert.ok(byDefault.notes.some((n) => n.includes('enforces its bearer, but http_auth.yaml says otherwise')), byDefault.notes.join('\n'))

  // --pmmcp-dir names one directly, and is still validated.
  const d = new World(t, { under: ['elsewhere', PMMCP_FOLDER] })
  assert.deepEqual(found(await d.run(t, { pmmcpDir: d.dir })).install, { dir: d.dir, source: 'pmmcp-dir' })
  await assert.rejects(d.run(t, { pmmcpDir: 'relative/dir' }), DiscoverError)

  // Nowhere: absent, and nothing of pmmcp's was run.
  const e = new World(t, { install: false })
  const absent = await e.run(t)
  assert.equal(absent.kind, 'absent')
  assert.equal(absent.kind === 'absent' ? absent.at : '', join(e.home, 'Github', PMMCP_FOLDER))
  assert.equal(e.calls.some((x) => x.command.includes('.venv')), false)
  assert.equal(e.ranScript(), false)
})

test('the MCP server start is read from ps etime, never lstart, so a localized ps changes nothing', async (t) => {
  const w = new World(t, { plist: true, listener: true })
  w.lang = 'de_DE.UTF-8'
  const f = found(await w.run(t))
  assert.equal(f.server?.startedAfter?.getTime(), NOW.getTime() - (SERVER_ETIME_S + 1) * 1000)
  // The child had the operator's locale: the runner passes LANG and LC_ALL on.
  const ps = w.calls.find((c) => c.command === 'ps' && c.args.includes('etime='))
  assert.equal(ps?.options.env['LC_ALL'], 'de_DE.UTF-8')
  // ps cannot say: no start, rather than a wrong one.
  const silent = new World(t, { listener: true })
  silent.overrides.set(`ps -o etime= -p ${String(SERVER_PID)}`, { out: 'Do 29 Okt 06:14:09 2026\n' })
  assert.deepEqual(found(await silent.run(t)).server, { pid: SERVER_PID, startedAfter: undefined })

  for (const [text, seconds] of [
    ['00:05', 5],
    ['45:57', 2757],
    ['01:45:57', 6357],
    ['2-01:02:03', 2 * 86_400 + 3723],
    ['  123-00:00:00\n', 123 * 86_400],
  ] as const) {
    assert.equal(parseEtime(text), seconds, text)
  }
  for (const text of ['', '5', '1:5', '00:60', '61:00', '1-24:00:00', 'Thu Oct 29 06:14:09 2026', '-1:00', '01:02:03:04']) assert.equal(parseEtime(text), undefined, text)
  assert.equal(startedAfter(NOW, 10).getTime(), NOW.getTime() - 11_000)
})

test('the launchd service, the dashboard (its 503 included) and http_auth.yaml are reported as they are, and ps and launchctl output is not kept', async (t) => {
  const w = new World(t, { plist: true, listener: true })
  const dir = join(w.home, '.persistent-memory-mcp')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'http_auth.yaml'), 'mode: warn\ntokens: {}\n', { mode: 0o600 })
  const mtime = new Date('2026-10-28T21:03:04.000Z')
  utimesSync(join(dir, 'http_auth.yaml'), mtime, mtime)
  edit(w.facts, 'dashboard_token.state', 'unusable')
  w.handlers.set(8765, (path) =>
    path === '/api/auth/status' ? { status: 503, body: '{"auth_required": true, "source": "file", "error": "dashboard_token_unusable"}' } : { status: 503, body: '' },
  )
  const f = found(await w.run(t))
  assert.equal(f.httpAuthModified?.getTime(), mtime.getTime())
  assert.deepEqual(f.endpoints.dashboard, { status: 503, authRequired: true, source: 'file' })
  assert.deepEqual(f.service, { loaded: true, state: 'running', pid: SERVER_PID })
  // launchd's copy of the service's environment and the server's command line are read, then emptied.
  const kept = logs(w.root)
  assert.equal(kept.get('launchctl-print.out'), '')
  assert.equal(kept.get(`ps-${String(SERVER_PID)}.out`), '')
  // No file: no mtime; a body that is not the auth status document: nothing read from it.
  const none = new World(t)
  none.handlers.set(8765, () => ({ status: 401, body: '{"auth_required": false, "source": "none"}' }))
  const g = found(await none.run(t))
  assert.equal(g.httpAuthModified, undefined)
  assert.deepEqual(g.endpoints.dashboard, { status: 401, authRequired: undefined, source: undefined })
  // The dashboard disabled: not asked.
  const off = new World(t)
  edit(off.facts, 'config.dashboard.enabled', false)
  assert.equal(found(await off.run(t)).endpoints.dashboard, undefined)
  assert.equal(off.served.some((x) => x.port === 8765), false)
})

test('the git state comes from whole-tree commands: an update only when origin/main is ahead and HEAD its ancestor, and whether the lockfile changes', async (t) => {
  const w = new World(t)
  w.overrides.set(`git --no-optional-locks merge-base --is-ancestor HEAD ${ORIGIN_MAIN}`, { code: 1 })
  w.overrides.set(`git --no-optional-locks diff --quiet HEAD ${ORIGIN_MAIN} -- uv.lock pyproject.toml`, { code: 1 })
  w.overrides.set('git --no-optional-locks status --porcelain', { out: ' M src/config.py\n?? notes.txt\n?? b.txt\n' })
  assert.deepEqual(found(await w.run(t)).git, { head: HEAD, originMain: ORIGIN_MAIN, fastForward: false, lockUnchanged: false, trackedChanges: 1, untracked: 2 })
  // git that fails to answer is no answer, never "unchanged".
  const odd = new World(t)
  odd.overrides.set(`git --no-optional-locks diff --quiet HEAD ${ORIGIN_MAIN} -- uv.lock pyproject.toml`, { code: 128, err: 'fatal: bad revision\n' })
  odd.overrides.set(`git --no-optional-locks merge-base --is-ancestor HEAD ${ORIGIN_MAIN}`, { code: 128 })
  const o = found(await odd.run(t)).git
  assert.equal(o.lockUnchanged, undefined)
  assert.equal(o.fastForward, false)
  // At origin/main already: nothing to compare.
  const level = new World(t)
  level.originMain = HEAD
  assert.deepEqual(found(await level.run(t)).git, { head: HEAD, originMain: HEAD, fastForward: false, lockUnchanged: undefined, trackedChanges: 0, untracked: 1 })
  assert.equal(level.ran('git', '--no-optional-locks', 'merge-base'), false)
})

test('a folder is an install only with pyproject name persistent-memory-mcp and .venv/bin/pmmcp', async (t) => {
  const noProject = new World(t)
  const pyproject = join(noProject.dir, 'pyproject.toml')
  writeFileSync(pyproject, '[tool.ruff]\nline-length = 100\n')
  const a = stopWith(await noProject.run(t), 'not-an-install')
  assert.match(a.message, /pyproject\.toml names the project nothing, not persistent-memory-mcp/)

  const other = new World(t)
  makeInstall(other.dir, 'some-other-project')
  assert.match(stopWith(await other.run(t), 'not-an-install').message, /names the project "some-other-project", not persistent-memory-mcp/)

  const noVenv = new World(t)
  rmSync(join(noVenv.dir, '.venv', 'bin', 'pmmcp'))
  const b = stopWith(await noVenv.run(t), 'not-an-install')
  assert.match(b.message, /has no \.venv\/bin\/pmmcp: its setup has not run \(\.\/setup\.sh\)/)
  // Only the locating probes ran: nothing of the folder's own, not even git in it.
  assert.deepEqual(noVenv.calls.map((c) => c.command), ['lsof'])

  // And it must be AiBot-Tools' repository; a token in the remote's URL is never shown, nor written anywhere.
  const fork = new World(t, { listener: true })
  const token = `ghp_${randomBytes(18).toString('hex')}`
  fork.origin = `https://x-access-token:${token}@github.com/someone/persistent-memory-mcp.git`
  const c = stopWith(await fork.run(t), 'not-an-install')
  assert.match(c.message, /its git origin is https:\/\/github\.com\/someone\/persistent-memory-mcp\.git, not github\.com\/AiBot-Tools\/persistent-memory-mcp/)
  assert.equal(c.message.includes(token), false)
  assert.equal(fork.calls.some((x) => x.command.includes('.venv')), false, 'a fork had its python run')
  // The origin is read in-process: no child is asked for it, so none prints it into a log.
  assert.equal(fork.calls.some((x) => x.args.some((arg) => /remote\.origin|ls-remote|get-url/.test(arg))), false)
  const written = logs(fork.root)
  assert.ok(written.size > 0, 'the run wrote no logs at all')
  for (const [file, text] of written) assert.equal(text.includes(token), false, `${file} holds the token`)
  assert.ok(fork.before)
  for (const p of changes(fork.before.root, tree(fork.root))) assert.equal(readFileSafe(join(fork.root, p)).includes(token), false, p)
  // The same origin, AiBot-Tools' this time, is held only without its token.
  const tokened = new World(t)
  tokened.origin = `https://x-access-token:${token}@github.com/AiBot-Tools/persistent-memory-mcp.git`
  found(await tokened.run(t))
  for (const [file, text] of logs(tokened.root)) assert.equal(text.includes(token), false, `${file} holds the token`)
  // No origin at all, or a folder that is no clone.
  const bare = new World(t)
  bare.origin = undefined
  assert.match(stopWith(await bare.run(t), 'not-an-install').message, /its git origin is not set/)
  const unclone = new World(t)
  rmSync(join(unclone.dir, '.git'), { recursive: true })
  assert.match(stopWith(await unclone.run(t), 'not-an-install').message, /has no \.git: it is not a git clone/)

  // Each spelling of the real origin counts, case and .git aside, and the explicit ports GitHub documents.
  for (const url of [
    ORIGIN,
    'https://github.com/aibot-tools/Persistent-Memory-MCP',
    'git@github.com:AiBot-Tools/persistent-memory-mcp.git',
    'ssh://git@github.com/AiBot-Tools/persistent-memory-mcp.git',
    'https://github.com:443/AiBot-Tools/persistent-memory-mcp.git',
    'ssh://git@ssh.github.com:443/AiBot-Tools/persistent-memory-mcp.git',
    'ssh://git@ssh.github.com/AiBot-Tools/persistent-memory-mcp.git',
    'git@ssh.github.com:AiBot-Tools/persistent-memory-mcp.git',
    // As the facts print it: without the user.
    'github.com:AiBot-Tools/persistent-memory-mcp.git',
  ]) {
    assert.equal(githubRepo(url), 'aibot-tools/persistent-memory-mcp', url)
  }
  for (const url of [
    'https://gitlab.com/AiBot-Tools/persistent-memory-mcp.git',
    'https://github.com.evil.example/AiBot-Tools/persistent-memory-mcp',
    'https://github.com/AiBot-Tools/persistent-memory-mcp/tree/main',
    'https://github.com:8443/AiBot-Tools/persistent-memory-mcp.git',
    'ssh://git@ssh.github.com:2222/AiBot-Tools/persistent-memory-mcp.git',
    'https://ssh.github.com/AiBot-Tools/persistent-memory-mcp.git',
    'http://github.com/AiBot-Tools/persistent-memory-mcp.git',
  ]) {
    assert.notEqual(githubRepo(url), 'aibot-tools/persistent-memory-mcp', url)
  }
  // An insteadOf alias, a git:// remote or a mirror is refused, and the message says which forms are read.
  for (const url of ['gh:AiBot-Tools/persistent-memory-mcp', 'git://github.com/AiBot-Tools/persistent-memory-mcp.git']) {
    const alias = new World(t)
    alias.origin = url
    const m = stopWith(await alias.run(t), 'not-an-install').message
    assert.ok(m.includes(`its git origin is ${url}`), m)
    assert.match(m, /The forms read: https:\/\/github\.com\/AiBot-Tools\/persistent-memory-mcp\(\.git\) \(:443 may be written\)/)
    assert.match(m, /no url\.<base>\.insteadOf or include\.path is applied/)
  }
  const port = new World(t)
  port.origin = 'ssh://git@ssh.github.com:443/AiBot-Tools/persistent-memory-mcp.git'
  found(await port.run(t))
  assert.equal(projectName('[project]\nname = "persistent-memory-mcp" # the package\n'), 'persistent-memory-mcp')
  assert.equal(projectName("[tool.x]\nname = 'no'\n[project]\nname='persistent-memory-mcp'\n"), 'persistent-memory-mcp')
  assert.equal(projectName('[tool.poetry]\nname = "persistent-memory-mcp"\n'), undefined)

  const ok = new World(t)
  assert.equal(found(await ok.run(t)).install.source, 'default')
})

test("the checkout's own files are read only as regular files, never through a link, without blocking and to a cap", async (t) => {
  // A FIFO: an open that blocked would wait for a writer for ever. One turns up after 3 s, from a
  // process of its own, so a reader that blocked is seen to: it ends late, and with what was written.
  const fifo = new World(t)
  const pyproject = join(fifo.dir, 'pyproject.toml')
  rmSync(pyproject)
  await mkfifo(t, pyproject)
  const writer = fifoWriter(t, pyproject, 3)
  const began = Date.now()
  const a = stopWith(await fifo.run(t), 'not-an-install')
  assert.match(a.message, /pyproject\.toml is not a regular file/)
  // And swapped in between the lstat and the open (lstat saw a regular file): opened without blocking, refused at once.
  const regular = join(tmpdir(t), 'regular.toml')
  writeFileSync(regular, '[project]\nname = "persistent-memory-mcp"\n')
  const realLstat = fs.lstatSync
  const lstat = t.mock.method(fs, 'lstatSync', (path: string) => realLstat(path === pyproject ? regular : path))
  syncBuiltinESMExports()
  let raced: ReturnType<typeof readRegular>
  try {
    raced = readRegular(pyproject, PYPROJECT_CAP)
  } finally {
    lstat.mock.restore()
    syncBuiltinESMExports()
  }
  assert.ok(lstat.mock.callCount() >= 1, 'readRegular no longer calls lstatSync through node:fs, so this proves nothing')
  assert.deepEqual(raced, { problem: 'was replaced while it was read' })
  assert.ok(Date.now() - began < 2000, 'a read blocked on the FIFO until its writer came')
  await writer.release()

  // A link, even to a good project file, and a link to a device: not read.
  const linked = new World(t)
  const real = join(linked.home, 'pyproject.real.toml')
  writeFileSync(real, readFileSync(join(linked.dir, 'pyproject.toml')))
  rmSync(join(linked.dir, 'pyproject.toml'))
  symlinkSync(real, join(linked.dir, 'pyproject.toml'))
  assert.match(stopWith(await linked.run(t), 'not-an-install').message, /pyproject\.toml is a link, which is not read/)
  const zero = new World(t)
  rmSync(join(zero.dir, 'pyproject.toml'))
  symlinkSync('/dev/zero', join(zero.dir, 'pyproject.toml'))
  assert.match(stopWith(await zero.run(t), 'not-an-install').message, /pyproject\.toml is a link/)
  // Larger than any project file: refused before it is read; the cap itself is read.
  const big = new World(t)
  writeFileSync(join(big.dir, 'pyproject.toml'), `[project]\nname = "persistent-memory-mcp"\n#${'x'.repeat(PYPROJECT_CAP)}\n`)
  assert.match(stopWith(await big.run(t), 'not-an-install').message, new RegExp(`is larger than ${String(PYPROJECT_CAP)} bytes`))
  const capped = join(tmpdir(t), 'capped')
  writeFileSync(capped, 'abcd')
  assert.deepEqual(readRegular(capped, 4), { text: 'abcd' })
  assert.deepEqual(readRegular(capped, 3), { problem: 'is larger than 3 bytes' })
  writeFileSync(capped, Buffer.from([0x5b, 0xff, 0x5d]))
  assert.deepEqual(readRegular(capped, 10), { problem: 'is not UTF-8' })
  assert.match('problem' in readRegular('/dev/null', 10) ? 'refused' : 'read', /refused/)

  // The git config the same: a .git/config that is a link is not read, and the folder is no install.
  const gitLink = new World(t)
  gitLink.writeGit = false
  const elsewhere = join(gitLink.home, 'config.elsewhere')
  writeFileSync(elsewhere, `[remote "origin"]\n\turl = ${ORIGIN}\n`)
  rmSync(join(gitLink.dir, '.git', 'config'))
  symlinkSync(elsewhere, join(gitLink.dir, '.git', 'config'))
  assert.match(stopWith(await gitLink.run(t), 'not-an-install').message, /has a git config \(.*\.git\/config\) that is a link, which is not read/)
})

test('the origin is read from the git config as git reads it, a worktree followed to its common config', async (t) => {
  const url = (text: string): string | undefined => originUrlIn(text)
  assert.equal(url(`[remote "origin"]\n\turl = ${ORIGIN}\n`), ORIGIN)
  // Sections and keys in any case, the subsection as written; the deprecated form in any case.
  assert.equal(url(`[REMOTE "origin"]\n\tURL = ${ORIGIN}\n`), ORIGIN)
  assert.equal(url(`[remote "Origin"]\n\turl = ${ORIGIN}\n`), undefined)
  assert.equal(url(`[Remote.Origin]\nurl=${ORIGIN}\n`), ORIGIN)
  // The last value wins, as git config --get has it; another remote's url is not the origin's.
  assert.equal(url(`[remote "origin"]\nurl = https://example.com/a.git\n[remote "upstream"]\nurl = https://example.com/b.git\n[remote "origin"]\nurl = ${ORIGIN}\n`), ORIGIN)
  assert.equal(url('[remote "upstream"]\nurl = https://example.com/b.git\n'), undefined)
  // Quotes, escapes, comments, a joined line, CRLF, a BOM, and trailing blanks.
  assert.equal(url(`[remote "origin"]\n  url = "${ORIGIN}" ; the origin\r\n`), ORIGIN)
  assert.equal(url(`\ufeff# a clone\n[remote "origin"] url = https://github.com/AiBot-Tools/\\\npersistent-memory-mcp.git   # pinned\n`), ORIGIN)
  assert.equal(url('[remote "origin"]\nurl = "a \\"b\\" \\\\ c"\n'), 'a "b" \\ c')
  assert.equal(url('[remote "o\\"x"]\nurl = y\n[remote "origin"]\nfetch = +refs/heads/*:refs/remotes/origin/*\n'), undefined)
  // What git refuses, this refuses, with the line.
  for (const [text, line] of [
    ['[remote "origin"\nurl = x\n', 1],
    ['[core]\n\tbare = false\n[remote "origin"]\nurl = "unterminated\n', 4],
    ['[remote "origin"]\nurl = bad \\q escape\n', 2],
    ['[remote "origin"]\n9url = x\n', 2],
    ['[remote "origin"]\nurl\n', 2],
    ['[]\n', 1],
  ] as const) {
    assert.throws(() => url(text), (e: unknown) => e instanceof GitConfigError && e.line === line, JSON.stringify(text))
  }
  assert.equal(withoutUserinfo('https://x-access-token:ghp_x@github.com/AiBot-Tools/persistent-memory-mcp.git'), ORIGIN)
  assert.equal(withoutUserinfo('git@github.com:AiBot-Tools/persistent-memory-mcp.git'), 'github.com:AiBot-Tools/persistent-memory-mcp.git')

  // A worktree: .git is a file naming its git folder, whose commondir leads to the shared config.
  const w = new World(t)
  const main = join(w.home, 'main-clone', '.git')
  mkdirSync(join(main, 'worktrees', 'pmmcp'), { recursive: true })
  writeFileSync(join(main, 'config'), `[remote "origin"]\n\turl = ${ORIGIN}\n`)
  writeFileSync(join(main, 'worktrees', 'pmmcp', 'commondir'), '../..\n')
  rmSync(join(w.dir, '.git'), { recursive: true })
  writeFileSync(join(w.dir, '.git'), `gitdir: ${join(main, 'worktrees', 'pmmcp')}\n`)
  assert.equal(found(await w.run(t)).install.dir, w.dir)
  // The same worktree with a fork's config: refused.
  writeFileSync(join(main, 'config'), '[remote "origin"]\n\turl = https://github.com/someone/persistent-memory-mcp.git\n')
  const again = new World(t)
  rmSync(join(again.dir, '.git'), { recursive: true })
  writeFileSync(join(again.dir, '.git'), `gitdir: ${join(main, 'worktrees', 'pmmcp')}\n`)
  assert.match(stopWith(await again.run(t), 'not-an-install').message, /someone\/persistent-memory-mcp/)
  // A submodule's git folder has no commondir: its own config.
  const sub = new World(t)
  const modules = join(sub.home, 'super', '.git', 'modules', 'pmmcp')
  mkdirSync(modules, { recursive: true })
  writeFileSync(join(modules, 'config'), `[remote "origin"]\n\turl = git@github.com:AiBot-Tools/persistent-memory-mcp.git\n`)
  rmSync(join(sub.dir, '.git'), { recursive: true })
  writeFileSync(join(sub.dir, '.git'), 'gitdir: ../../super/.git/modules/pmmcp\n')
  // Relative to the checkout: <home>/Github/Persistent-Memory-MCP/../../super is <home>/super.
  found(await sub.run(t))
  const pointless = new World(t)
  rmSync(join(pointless.dir, '.git'), { recursive: true })
  writeFileSync(join(pointless.dir, '.git'), 'not a pointer\n')
  assert.match(stopWith(await pointless.run(t), 'not-an-install').message, /has a \.git file with no gitdir: line/)
  const broken = new World(t)
  broken.writeGit = false
  writeFileSync(join(broken.dir, '.git', 'config'), '[remote "origin"\n')
  assert.match(stopWith(await broken.run(t), 'not-an-install').message, /that git would refuse: bad config line 1/)
})

test('a legacy com.aibot-tools.pmmcp-* plist, two candidate installs, or a lowercase clone path stops discovery with the reason', async (t) => {
  const legacy = new World(t, { plist: true })
  const old = join(legacy.home, 'Library', 'LaunchAgents', 'com.aibot-tools.pmmcp-server.plist')
  mkdirSync(join(old, '..'), { recursive: true })
  writeFileSync(old, '<plist/>\n')
  const a = stopWith(await legacy.run(t), 'legacy-plist')
  assert.ok(a.message.includes(old), a.message)
  // The domain as the operator pastes it: this account's uid, never a literal <uid>.
  assert.match(a.message, /\(launchctl bootout gui\/501 <plist>, then rm <plist>\), then re-run$/)
  assert.equal(a.message.includes('<uid>'), false, a.message)
  assert.equal(legacy.calls.length, 0)
  // Any of the old supervisor's names, in any case (APFS opens it whatever the case).
  const worker = new World(t)
  const mixed = join(worker.home, 'Library', 'LaunchAgents', 'COM.AiBot-Tools.PMMCP-Worker.plist')
  mkdirSync(join(mixed, '..'), { recursive: true })
  writeFileSync(mixed, '<plist/>\n')
  assert.ok(stopWith(await worker.run(t), 'legacy-plist').message.includes(mixed))
  const unrelated = new World(t)
  mkdirSync(join(unrelated.home, 'Library', 'LaunchAgents'), { recursive: true })
  writeFileSync(join(unrelated.home, 'Library', 'LaunchAgents', 'com.aibot-tools.other.plist'), '<plist/>\n')
  found(await unrelated.run(t))

  // The plist runs one folder and the server on 8766 another.
  const split = new World(t, { plist: true })
  const other = join(split.home, 'old', PMMCP_FOLDER)
  makeInstall(other)
  split.listenerDir = other
  const b = stopWith(await split.run(t), 'two-installs')
  assert.ok(b.message.includes(split.dir) && b.message.includes(other), b.message)
  assert.match(b.message, /WorkingDirectory/)
  assert.match(b.message, /listening on 8766/)

  // The plist's WorkingDirectory and the program it runs disagree.
  const crossed = new World(t, { plist: true })
  crossed.plistProgram = join(crossed.home, 'old', PMMCP_FOLDER, '.venv', 'bin', 'pmmcp')
  const c = stopWith(await crossed.run(t), 'two-installs')
  assert.ok(c.message.includes(crossed.plistProgram), c.message)

  // The plist names one install, and the default place holds another.
  const stray = new World(t)
  const used = join(stray.home, 'src', PMMCP_FOLDER)
  makeInstall(used)
  stray.plistDir = used
  const d = stopWith(await stray.run(t), 'two-installs')
  assert.ok(d.message.includes(used) && d.message.includes(join(stray.home, 'Github', PMMCP_FOLDER)), d.message)
  // But a default folder that is no install (empty, or a clone cut short) is not a second candidate beside the plist's.
  for (const leave of ['empty', 'half']) {
    const beside = new World(t, { under: ['src', PMMCP_FOLDER], plist: true })
    const stub = join(beside.home, 'Github', PMMCP_FOLDER)
    mkdirSync(stub, { recursive: true })
    if (leave === 'half') writeFileSync(join(stub, 'pyproject.toml'), '[project]\nname = "persistent-memory-mcp"\n')
    assert.deepEqual(found(await beside.run(t)).install, { dir: beside.dir, source: 'plist' }, leave)
  }
  // Alone, an invalid default folder is the candidate, and is refused for what it lacks.
  const alone = new World(t, { install: false })
  mkdirSync(alone.dir, { recursive: true })
  assert.match(stopWith(await alone.run(t), 'not-an-install').message, /\(the default place\) is not a pmmcp install/)

  // A clone at a lowercase path: the stop script and the second confirmation know it by its name.
  const lower = new World(t, { under: ['Github', 'persistent-memory-mcp'], plist: true })
  const e = stopWith(await lower.run(t), 'folder-name')
  assert.ok(e.message.includes(lower.dir), e.message)
  assert.match(e.message, /stored as "persistent-memory-mcp", not Persistent-Memory-MCP/)
  assert.equal(lower.calls.some((x) => x.command.includes('.venv')), false)

  // Something other than this account's pmmcp on 8766 stops it too, named by its program alone.
  const squat = new World(t)
  squat.overrides.set('lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', { out: `p${String(SERVER_PID)}\nu${String(OP_UID)}\n` })
  const secret = `-oIdentityFile=/Users/op/.ssh/${randomBytes(8).toString('hex')}`
  squat.overrides.set(`ps -ww -o uid=,args= -p ${String(SERVER_PID)}`, { out: `${String(OP_UID)} /usr/bin/ssh -N -L 8766:127.0.0.1:8766 ${secret} vm\n` })
  const sq = stopWith(await squat.run(t), 'listener')
  assert.match(sq.message, /not a pmmcp MCP server of this account \(it runs ssh\)/)
  assert.equal(sq.message.includes('-L'), false, sq.message)
  // Its command line is not kept in the logs either, once read.
  assert.equal(logs(squat.root).get(`ps-${String(SERVER_PID)}.out`), '')
  for (const [file, text] of logs(squat.root)) assert.equal(text.includes(secret), false, file)
  const foreign = new World(t)
  foreign.listenerDir = foreign.dir
  foreign.listenerUid = 502
  assert.match(stopWith(await foreign.run(t), 'listener').message, /not this account's/)
  // lsof says this account's, but ps says another uid runs the pid: that is not this account's server.
  const swapped = new World(t, { listener: true })
  swapped.overrides.set(`ps -ww -o uid=,args= -p ${String(SERVER_PID)}`, { out: `  502 ${swapped.dir}/.venv/bin/python ${swapped.dir}/.venv/bin/pmmcp\n` })
  assert.match(stopWith(await swapped.run(t), 'listener').message, /held by pid 812, which is not a pmmcp MCP server of this account \(it runs python\)/)
  // Two MCP servers of this account on 8766, from two folders.
  const twice = new World(t, { listener: true })
  const second = join(twice.home, 'old', PMMCP_FOLDER)
  makeInstall(second)
  twice.overrides.set('lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', { out: `p${String(SERVER_PID)}\nu${String(OP_UID)}\np813\nu${String(OP_UID)}\n` })
  twice.overrides.set(`ps -ww -o uid=,args= -p 813`, { out: `  ${String(OP_UID)} ${second}/.venv/bin/python ${second}/.venv/bin/pmmcp\n` })
  const tw = stopWith(await twice.run(t), 'two-installs')
  assert.match(tw.message, /held by MCP servers of two installs/)
  assert.ok(tw.message.includes(second) && tw.message.includes(twice.dir), tw.message)
  // One server listed twice (IPv4 and IPv6) is one.
  const dual = new World(t, { listener: true })
  dual.overrides.set('lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', { out: `p${String(SERVER_PID)}\nu${String(OP_UID)}\nf7\np${String(SERVER_PID)}\nu${String(OP_UID)}\nf8\n` })
  assert.equal(found(await dual.run(t)).server?.pid, SERVER_PID)
})

test('a plist left from a clone that is gone stops discovery with its bootout, --pmmcp-dir or not', async (t) => {
  const gone = join('/nonexistent-aos-test', PMMCP_FOLDER)
  const w = new World(t, { install: false })
  w.plistDir = gone
  const s = stopWith(await w.run(t), 'plist')
  assert.ok(s.message.includes(w.plist) && s.message.includes(gone), s.message)
  assert.match(s.message, /launchctl bootout gui\/501\/com\.aibot\.pmmcp, then rm /)
  assert.match(s.message, /or reinstall it with \.\/setup\.sh from the clone you use/)
  // Given the clone the operator uses, the same stale plist is what is named, not two installs.
  const used = new World(t, { under: ['src', PMMCP_FOLDER] })
  used.plistDir = gone
  const u = await used.run(t, { pmmcpDir: used.dir })
  assert.match(stopWith(u, 'plist').message, /launchctl bootout/)
  assert.equal(stopped(u).stops.some((x) => x.code === 'two-installs'), false)
})

test('facts that fail the v1 schema stop discovery, naming the field', async (t) => {
  const w = new World(t)
  edit(w.facts, 'features.bearer_gate', 'yes')
  const s = stopWith(await w.run(t), 'facts-schema')
  assert.match(s.message, /features\.bearer_gate/)
  // Nothing was probed after the facts.
  assert.equal(w.ran('docker', 'context', 'show'), false)
  assert.equal(w.ranScript(), false)

  const base = (): Doc => factsDoc('/Users/op/Github/Persistent-Memory-MCP', '/Users/op', true)
  const fields = (doc: unknown): readonly string[] => {
    try {
      parseFacts(typeof doc === 'string' ? doc : JSON.stringify(doc))
    } catch (e) {
      assert.ok(e instanceof PmmcpDocumentError)
      return e.fields
    }
    return assert.fail('the document passed')
  }
  assert.deepEqual(fields(edit(base(), 'facts', 2)), ['facts'])
  assert.deepEqual(fields(edit(base(), 'http_auth')), ['http_auth'])
  assert.deepEqual(fields(edit(base(), 'config.server.port', '8766')), ['config.server.port'])
  assert.deepEqual(fields(edit(base(), 'config.server.enabled', false)), ['config.server.enabled'])
  assert.deepEqual(fields(edit(base(), 'http_auth.mode', 'strict')), ['http_auth.mode'])
  assert.deepEqual(fields(edit(base(), 'curator_secret.state', 'missing')), ['curator_secret.state'])
  assert.deepEqual(fields(edit(base(), 'features.stop_jobs_flag')), ['features.stop_jobs_flag'])
  assert.deepEqual(fields(edit(base(), 'features.curator_proof', 'yes')), ['features.curator_proof'])
  assert.deepEqual(fields('facts: 1\n'), ['(document)'])
  assert.deepEqual(fields([base()]), ['(document)'])

  // A facts run that fails says so with its stderr line, which names fields only.
  const failing = new World(t)
  failing.overrides.set(`${failing.python} scripts/pmmcp_facts.py --json`, { code: 1, err: 'facts: the config cannot be read: invalid settings: config_path (extra_forbidden)\n' })
  assert.match(stopWith(await failing.run(t), 'facts').message, /exited 1: facts: the config cannot be read: invalid settings: config_path \(extra_forbidden\)/)
})

test('a refusal of a pmmcp document names the field, never the value it held', async (t) => {
  const canary = `canary-${randomBytes(6).toString('hex')}`
  const number = 987_654_321
  const doc = factsDoc('/Users/op/Github/Persistent-Memory-MCP', '/Users/op', true)
  edit(doc, 'http_auth.mode', canary)
  edit(doc, 'config.server.host', number)
  edit(doc, 'curator_secret.state', `${canary}-state`)
  try {
    parseFacts(JSON.stringify(doc))
    assert.fail('the document passed')
  } catch (e) {
    assert.ok(e instanceof PmmcpDocumentError)
    assert.deepEqual([...e.fields].sort(), ['config.server.host', 'curator_secret.state', 'http_auth.mode'])
    assert.equal(e.message.includes(canary), false, e.message)
    assert.equal(e.message.includes(String(number)), false, e.message)
    assert.match(e.message, /http_auth\.mode: /)
  }
  const q = qdrantDoc()
  edit(q, 'verdict', canary)
  assert.throws(() => parseQdrantStatus(JSON.stringify(q)), (e: unknown) => e instanceof PmmcpDocumentError && !e.message.includes(canary) && e.fields.includes('verdict'))

  // Nor does the stop that carries it.
  const w = new World(t)
  edit(w.facts, 'http_auth.mode', canary)
  edit(w.facts, 'config.server.host', number)
  const s = stopWith(await w.run(t), 'facts-schema')
  assert.match(s.message, /http_auth\.mode/)
  assert.equal(s.message.includes(canary), false, s.message)
  assert.equal(s.message.includes(String(number)), false, s.message)
})

test('facts about another folder or origin, that saw PMMCP_* names, or whose plist runs elsewhere stop discovery', async (t) => {
  const elsewhere = '/Users/op/elsewhere/Persistent-Memory-MCP'
  const cases: readonly [string, (w: World) => void, Stop['code'], RegExp][] = [
    ['env_overrides', (w) => edit(w.facts, 'env_overrides', ['PMMCP_X']), 'facts-mismatch', /saw PMMCP_X in their environment, which the installer never passes/],
    ['dir', (w) => edit(w.facts, 'dir', elsewhere), 'facts-mismatch', /pmmcp's facts describe \/Users\/op\/elsewhere\/Persistent-Memory-MCP, not /],
    ['git.origin', (w) => edit(w.facts, 'git.origin', 'https://github.com/someone/persistent-memory-mcp.git'), 'facts-mismatch', /give the origin https:\/\/github\.com\/someone\/persistent-memory-mcp\.git, not /],
    [
      'launchd.working_directory',
      (w) => edit(w.facts, 'launchd', { plist: w.plist, exists: true, working_directory: elsewhere, legacy_plists: [] }),
      'two-installs',
      /the com\.aibot\.pmmcp plist runs \/Users\/op\/elsewhere\/Persistent-Memory-MCP, not /,
    ],
  ]
  for (const [what, change, code, message] of cases) {
    const w = new World(t)
    change(w)
    const d = stopped(await w.run(t))
    // That stop alone: each check stands on its own.
    assert.deepEqual(d.stops.map((x) => x.code), [code], what)
    assert.match(stopWith(d, code).message, message, what)
    assert.equal(w.ranScript(), false, what)
  }
  // The same facts with each of those as it should be go on: the plist the facts read is this install's, the origin the facts print has no user.
  const ok = new World(t)
  edit(ok.facts, 'git.origin', 'github.com:AiBot-Tools/persistent-memory-mcp.git')
  edit(ok.facts, 'launchd', { plist: ok.plist, exists: true, working_directory: ok.dir, legacy_plists: [] })
  found(await ok.run(t))
  const noPlist = new World(t)
  edit(noPlist.facts, 'launchd', { plist: noPlist.plist, exists: false, working_directory: elsewhere, legacy_plists: [] })
  found(await noPlist.run(t))
})

test('facts with keys v1 does not name pass the schema (it is additive)', async (t) => {
  const w = new World(t)
  edit(w.facts, 'future_section', { anything: [1, 2, 3] })
  edit(w.facts, 'features.some_later_flag', true)
  edit(w.facts, 'config.server.transport', 'streamable-http')
  edit(w.facts, 'http_auth.loaded_at', '2026-10-29T07:14:03Z')
  edit(w.facts, 'launchd.label', 'com.aibot.pmmcp')
  const f = found(await w.run(t))
  // Kept, not stripped: a later reader of the same document sees them.
  assert.deepEqual(f.facts?.['future_section'], { anything: [1, 2, 3] })
  assert.equal(f.facts?.features['some_later_flag'], true)
  // An unknown flag is not a feature the installer acts on.
  assert.deepEqual(Object.keys(f.features).sort(), [...FEATURE_NAMES].sort())
  assert.deepEqual(f.missing, [])
})

test('a dfcc99a facts document, with no curator_proof key, passes and reads as curator_proof false', async (t) => {
  const doc = dfcc99a(factsDoc('/Users/op/Github/Persistent-Memory-MCP', '/Users/op', true))
  const facts = parseFacts(JSON.stringify(doc))
  assert.equal(facts.features.curator_proof, undefined)
  assert.equal(featuresOf(facts).curator_proof, false)
  assert.equal(featuresOf(facts).stop_listener_check, false)
  assert.equal(featuresOf(facts).curator_secret, true)
  assert.deepEqual(missingFeatures(facts).map((m) => [m.feature, m.commit]), [
    ['curator_proof', 'e6516d5'],
    ['stop_listener_check', 'e6516d5'],
  ])

  const w = new World(t)
  dfcc99a(w.facts)
  const f = found(await w.run(t))
  assert.equal(f.features.curator_proof, false)
  assert.equal(f.features.stop_listener_check, false)
  assert.equal(f.facts?.http_auth.links, undefined)
})

test('a qdrant status --json document with verdict not_running passes, and only enforced counts as keyed', async (t) => {
  const absent = {
    docker_context: 'desktop-linux',
    key_file: { state: 'absent', reason: null },
    container: { state: 'absent', key_set: null, image12: null, published: [], publish_all_ports: null, reachable_beyond_loopback: [] },
    prekey_kept: false,
    collections: { without_key: null, with_key: null },
    verdict: 'not_running',
  }
  assert.equal(keyedLoopbackOnly(parseQdrantStatus(JSON.stringify(absent))), false)
  const stoppedDoc = { ...absent, container: { state: 'stopped', key_set: true, image12: '0123456789ab', published: [{ host_ip: '', host_port: null, container_port: '6333/tcp' }], publish_all_ports: false, reachable_beyond_loopback: ['*:?->6333/tcp'] } }
  assert.equal(keyedLoopbackOnly(parseQdrantStatus(JSON.stringify(stoppedDoc))), false)

  const enforced: Doc = { ...qdrantDoc(), key_file: { state: 'present', reason: null }, collections: { without_key: 401, with_key: 200 }, verdict: 'enforced' }
  edit(enforced, 'container.key_set', true)
  assert.equal(keyedLoopbackOnly(parseQdrantStatus(JSON.stringify(enforced))), true)
  // Bindings on 127.0.0.1 alone prove nothing: only the verdict does.
  assert.equal(keyedLoopbackOnly(parseQdrantStatus(JSON.stringify(qdrantDoc()))), false)
  const hostNetwork = { ...enforced, verdict: 'inconsistent', container: { ...(enforced.container as Doc), published: [], reachable_beyond_loopback: ['the host network (--network host)'] } }
  assert.equal(keyedLoopbackOnly(parseQdrantStatus(JSON.stringify(hostNetwork))), false)
  // Additive, and refused by field.
  assert.equal(parseQdrantStatus(JSON.stringify({ ...absent, later: true }))['later'], true)
  assert.throws(() => parseQdrantStatus(JSON.stringify({ ...absent, verdict: null })), (e: unknown) => e instanceof PmmcpDocumentError && e.fields.includes('verdict'))
  const bad = qdrantDoc()
  edit(bad, 'container.published', [{ host_ip: '127.0.0.1', host_port: '6333', container_port: '6333/tcp' }])
  assert.throws(() => parseQdrantStatus(JSON.stringify(bad)), (e: unknown) => e instanceof PmmcpDocumentError && e.fields.includes('container.published.0.host_port'))

  // Discovery reads it when the facts offer it, with -B (the script's own code does not keep it from writing __pycache__), and stops on a document that does not fit.
  const w = new World(t)
  w.qdrant = absent
  assert.equal(found(await w.run(t)).qdrant?.verdict, 'not_running')
  assert.ok(w.ran(w.python, '-B', 'scripts/qdrant_api_key.py', 'status', '--json'))
  const broken = new World(t)
  edit(broken.qdrant, 'verdict', 'fine')
  assert.match(stopWith(await broken.run(t), 'qdrant-status').message, /verdict/)
  const older = new World(t)
  edit(older.facts, 'features.qdrant_status_json', false)
  assert.equal(found(await older.run(t)).qdrant, undefined)
  assert.equal(older.ran(older.python, 'scripts/qdrant_api_key.py'), false)
})

test('http_auth present with links above 1 stops discovery, naming the single-file fix', async (t) => {
  const w = new World(t)
  edit(w.facts, 'http_auth.links', 2)
  const s = stopWith(await w.run(t), 'http-auth-links')
  assert.match(s.message, /has 2 hard links, and the rotate script refuses to replace it/)
  assert.match(s.message, /make it a single file first/)

  // Facts older than e6516d5 do not say: discovery counts the links itself.
  const old = new World(t)
  dfcc99a(old.facts)
  const dir = join(old.home, '.persistent-memory-mcp')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'http_auth.yaml'), 'mode: warn\ntokens: {}\n')
  linkSync(join(dir, 'http_auth.yaml'), join(dir, 'http_auth.yaml.bak'))
  assert.match(stopWith(await old.run(t), 'http-auth-links').message, /has 2 hard links/)

  // One link, or no file, goes on.
  const one = new World(t)
  assert.equal(found(await one.run(t)).facts?.http_auth.links, 1)
  const none = new World(t)
  edit(none.facts, 'http_auth', { state: 'absent', mode: 'off', tokens: [], reason: 'no http_auth.yaml', links: null })
  found(await none.run(t))
  // And an invalid file stops it with the facts' reason.
  const invalid = new World(t)
  edit(invalid.facts, 'http_auth', { state: 'invalid', mode: null, tokens: [], reason: 'tokens.mac-0123456789abcdef0123456789abcdef: the name looks like a token', links: 1 })
  assert.match(stopWith(await invalid.run(t), 'http-auth-invalid').message, /the name looks like a token/)
})

test('with a curator secret present or offered, curator.host other than 127.0.0.1 or curator.port other than 8767 stops discovery, naming curator.host', async (t) => {
  const present = new World(t)
  edit(present.facts, 'curator_secret.state', 'present')
  edit(present.facts, 'config.curator.host', 'localhost')
  const a = stopWith(await present.run(t), 'curator-bind')
  assert.match(a.message, /curator\.host/)
  assert.match(a.message, /"localhost":8767/)
  assert.match(a.message, /with a curator secret present/)

  // Absent, but the facts would have the installer offer it.
  const offered = new World(t)
  edit(offered.facts, 'config.curator.host', '::1')
  assert.match(stopWith(await offered.run(t), 'curator-bind').message, /with a curator secret offered/)

  // A port other than 8767 is named as well; an unusable file is there all the same, and said so.
  const port = new World(t)
  edit(port.facts, 'curator_secret.state', 'unusable')
  edit(port.facts, 'config.curator.port', 8768)
  const p = stopWith(await port.run(t), 'curator-bind')
  assert.match(p.message, /curator\.port to 8767/)
  assert.match(p.message, /with a curator secret present \(unusable\)/)

  // Not offered (dfcc99a: no curator_proof), not present, and no update to bring it: nothing to refuse.
  const older = new World(t)
  dfcc99a(older.facts)
  older.originMain = HEAD
  edit(older.facts, 'config.curator.host', 'localhost')
  assert.equal(found(await older.run(t)).git.fastForward, false)
  // But with a fast-forward there, S4 asks for it "if the updated pmmcp supports them", and L4 would make it on a bind the curator refuses.
  const behind = new World(t)
  dfcc99a(behind.facts)
  edit(behind.facts, 'config.curator.host', 'localhost')
  const b = stopWith(await behind.run(t), 'curator-bind')
  assert.match(b.message, /with a curator secret offered once pmmcp is updated to origin\/main \(53ea308\)/)
  assert.match(b.message, /set curator\.host to 127\.0\.0\.1/)
  assert.equal(behind.ranScript(), false)
  // Each flag the offer needs, missing alone, means no offer: curator_proof (dfcc99a, above), stop_listener_check, dashboard_auth, curator_secret.
  for (const flag of ['stop_listener_check', 'dashboard_auth', 'curator_secret']) {
    const lacking = new World(t)
    lacking.originMain = HEAD
    edit(lacking.facts, `features.${flag}`, false)
    edit(lacking.facts, 'config.curator.host', '::1')
    found(await lacking.run(t))
  }
  // The curator disabled: nothing listens on 8767, and nothing is checked there.
  const off = new World(t)
  edit(off.facts, 'curator_secret.state', 'present')
  edit(off.facts, 'config.curator', { host: 'localhost', port: 8767, enabled: false })
  found(await off.run(t))
  // Exactly 127.0.0.1:8767 goes on.
  const right = new World(t)
  edit(right.facts, 'curator_secret.state', 'present')
  found(await right.run(t))
})

test('--jobs is never run unless the facts show stop_jobs_flag', async (t) => {
  const without = new World(t)
  edit(without.facts, 'features.stop_jobs_flag', false)
  const a = found(await without.run(t))
  assert.equal(without.ranScript(), false)
  assert.deepEqual(a.jobs, { state: 'not-run', why: 'the stop script cannot count jobs (an older one runs a full stop on --jobs); update pmmcp first' })

  // No facts at all (before c8bae1e): no --jobs either.
  const ancient = new World(t)
  rmSync(join(ancient.dir, 'scripts', 'pmmcp_facts.py'))
  const b = found(await ancient.run(t))
  assert.equal(ancient.ranScript(), false)
  assert.equal(b.jobs.state, 'not-run')

  // With the flag: once, as the command itself, with --jobs alone, detached, stdin /dev/null, no timeout.
  const w = new World(t)
  w.jobs = { out: 'running jobs: 2\n  a1  scrape  my project  50%\n  b2  backfill  aos/ceo  10%\n', err: 'running jobs: 9\n[WARN] the listener on 8765 is not this checkout\'s dashboard, so nothing was sent\n' }
  const c = found(await w.run(t))
  const runs = w.calls.filter((x) => [x.command, ...x.args].some((s) => s.includes(STOP_SCRIPT)))
  assert.equal(runs.length, 1)
  assert.equal(runs[0]?.command, join(w.dir, STOP_SCRIPT))
  assert.deepEqual(runs[0]?.args, ['--jobs'])
  assert.equal(runs[0]?.options.detached, true)
  assert.equal(runs[0]?.options.stdio[0], 'ignore')
  // The count is stdout's first line; the warning on stderr that looks like one is not.
  assert.equal(c.jobs.state, 'counted')
  if (c.jobs.state === 'counted') {
    assert.equal(c.jobs.jobs.running, 2)
    assert.deepEqual('display' in c.jobs.jobs ? c.jobs.jobs.display : [], ['  a1  scrape  my project  50%', '  b2  backfill  aos/ceo  10%'])
  }
  // Its record in active.json is gone once it exited.
  assert.equal(existsSync(activePath(w.root)), false)

  // unknown is a count it could not make, and anything else is no answer.
  const unknown = new World(t)
  unknown.jobs = { out: 'running jobs: unknown\n', code: 1 }
  const d = found(await unknown.run(t))
  assert.deepEqual(d.jobs.state === 'counted' ? d.jobs.jobs : undefined, { running: 'unknown' })
  const garbled = new World(t)
  garbled.jobs = { out: 'Stopping pmmcp...\n', code: 0 }
  assert.equal(found(await garbled.run(t)).jobs.state, 'failed')

  // The pushed dfcc99a's stop script (and 540bc6b's, fa67d43's) sends a usable dashboard token to whatever
  // listens on 8765: without stop_listener_check, --jobs runs only while no token file is present.
  const squatted = new World(t)
  dfcc99a(squatted.facts)
  edit(squatted.facts, 'dashboard_token.state', 'present')
  const e = found(await squatted.run(t))
  assert.equal(squatted.ranScript(), false)
  assert.equal(e.jobs.state, 'not-run')
  assert.match(e.jobs.state === 'not-run' ? e.jobs.why : '', /sends the dashboard token to whatever listens on 8765 without checking .*update pmmcp first/)
  for (const state of ['absent', 'unusable']) {
    const noToken = new World(t)
    dfcc99a(noToken.facts)
    edit(noToken.facts, 'dashboard_token.state', state)
    assert.equal(found(await noToken.run(t)).jobs.state, 'counted', state)
    assert.equal(noToken.ranScript(), true, state)
  }
  // From e6516d5 the script sends it only to this checkout's own dashboard.
  const checked = new World(t)
  edit(checked.facts, 'dashboard_token.state', 'present')
  assert.equal(found(await checked.run(t)).jobs.state, 'counted')
})

/** An earlier run's record in active.json, as the runner writes it (readOnly: the jobs count's). */
function record(w: World, step: string, pid: number, started: Date | string, readOnly = false): void {
  mkdirSync(join(w.root, '.aos', 'install'), { recursive: true })
  writeFileSync(
    activePath(w.root),
    JSON.stringify({ step, pid, started: typeof started === 'string' ? started : started.toISOString(), out: '/x/stop.out', err: '/x/stop.err', ...(readOnly ? { readOnly: true } : {}) }),
  )
}

/** `ps -ww -o etime=,command= -p <pid>`'s key in World.overrides. */
const psActive = (pid: number): string => `ps -ww -o etime=,command= -p ${String(pid)}`

test('an active.json record stops discovery while its pid still runs the recorded step, and a dead one is handed back', async (t) => {
  // The stop an earlier run started 10 minutes ago still runs: wait.
  const busy = new World(t)
  record(busy, 'stop', 999_999, new Date(NOW.getTime() - 600_000))
  busy.overrides.set(psActive(999_999), { out: `   10:00 /bin/bash ${busy.dir}/stop-pmmcp-server.sh\n` })
  const a = stopWith(await busy.run(t), 'active-step')
  assert.match(a.message, /started stop \(pid 999999, since 2026-10-29T07:50:00\.000Z\) in its own session/)
  assert.match(a.message, /while that pid runs stop-pmmcp-server\.sh: it may still be stopping, starting or changing pmmcp/)
  // Only ps ran, naming no script, and its output is not kept.
  assert.deepEqual(busy.calls.map((c) => [c.command, ...c.args].join(' ')), [psActive(999_999)])
  assert.equal(logs(busy.root).get('ps-active-999999.out'), '')

  // A read-only --jobs an earlier run left running (a Ctrl-C during the count) is waited for, then said to change nothing: never a window.
  const counting = new World(t)
  record(counting, 'stop-jobs', 4321, new Date(NOW.getTime() - 5_000), true)
  counting.overrides.set(psActive(4321), { out: `   00:05 /bin/bash ${counting.dir}/stop-pmmcp-server.sh --jobs\n` })
  const b = stopWith(await counting.run(t), 'active-step')
  assert.match(b.message, /count of pmmcp's jobs, stop-jobs \(pid 4321, .*\), still runs stop-pmmcp-server\.sh after 15 s, .*it only counts and changes nothing/)
  assert.equal(b.message.includes('may still be stopping'), false)
  assert.deepEqual(counting.slept, Array.from({ length: READ_ONLY_POLLS }, () => READ_ONLY_POLL_MS))
  assert.ok(existsSync(activePath(counting.root)), 'a count that still runs lost its record')
  // The wait is said once, before its first pause: never a silent stop after the preflight and .env lines.
  assert.deepEqual(counting.said, [{ line: "waiting up to 15 s for an earlier run's count of pmmcp's jobs (pid 4321) to end", afterPauses: 0 }])
  // One that ends while discovery waits: its record is removed, and this run counts the jobs itself.
  const ending = new World(t)
  record(ending, 'stop-jobs', 4329, new Date(NOW.getTime() - 5_000), true)
  ending.overrides.set(psActive(4329), { out: `   00:05 /bin/bash ${ending.dir}/stop-pmmcp-server.sh --jobs\n` })
  ending.onSleep = (): void => {
    if (ending.slept.length === 2) ending.overrides.set(psActive(4329), { code: 1 })
  }
  const ended = found(await ending.run(t))
  assert.equal(ending.slept.length, 2)
  assert.equal(ended.staleActive, undefined)
  assert.equal(existsSync(activePath(ending.root)), false, "the ended count's record was kept")
  assert.equal(ended.jobs.state, 'counted')
  assert.ok(ended.notes.some((n) => /recorded an earlier run's count of pmmcp's jobs, stop-jobs \(pid 4329, .*\), which has ended: the record was removed/.test(n)), ended.notes.join('\n'))
  assert.deepEqual(ending.said.map((s) => s.afterPauses), [0])
  // Another record in active.json by the time the count has ended (written while this run waited): it is not this record, so it is
  // no one's to remove here, and it stands; discovery stops rather than read past it, and a re-run reads it afresh.
  const replaced = new World(t)
  record(replaced, 'stop-jobs', 4332, new Date(NOW.getTime() - 5_000), true)
  replaced.overrides.set(psActive(4332), { out: `   00:05 /bin/bash ${replaced.dir}/stop-pmmcp-server.sh --jobs\n` })
  replaced.onSleep = (): void => {
    if (replaced.slept.length !== 1) return
    replaced.overrides.set(psActive(4332), { code: 1 })
    record(replaced, 'stop', 4333, new Date(NOW.getTime() - 1_000))
  }
  assert.match(
    stopWith(await replaced.run(t), 'active-step').message,
    /active\.json changed while discovery waited for an earlier run's count of pmmcp's jobs, stop-jobs \(pid 4332, .*\), to end: it no longer holds that record, so nothing was removed\. Re-run/,
  )
  const standing = JSON.parse(readFileSync(activePath(replaced.root), 'utf8')) as { pid: number; step: string }
  assert.deepEqual([standing.pid, standing.step], [4333, 'stop'], 'a record that is not the one waited for was removed')
  assert.equal(replaced.ranScript(), false)
  // A record that cannot be read by the time the count has ended (written part way, or not the runner's shape): it may be a window's,
  // so it is neither removed nor read past, and discovery stops as for another record.
  const garbled = new World(t)
  record(garbled, 'stop-jobs', 4335, new Date(NOW.getTime() - 5_000), true)
  garbled.overrides.set(psActive(4335), { out: `   00:05 /bin/bash ${garbled.dir}/stop-pmmcp-server.sh --jobs\n` })
  garbled.onSleep = (): void => {
    if (garbled.slept.length !== 1) return
    garbled.overrides.set(psActive(4335), { code: 1 })
    writeFileSync(activePath(garbled.root), '{"step":"stop","pid":', { mode: 0o600 })
  }
  assert.match(
    stopWith(await garbled.run(t), 'active-step').message,
    /active\.json changed while discovery waited for an earlier run's count of pmmcp's jobs, stop-jobs \(pid 4335, .*\), to end: it no longer holds that record, so nothing was removed\. Re-run/,
  )
  assert.equal(readFileSync(activePath(garbled.root), 'utf8'), '{"step":"stop","pid":', 'an unreadable record was removed')
  assert.equal(garbled.ranScript(), false)
  // Gone meanwhile (its own run removed it): nothing to remove, and discovery goes on.
  const gone = new World(t)
  record(gone, 'stop-jobs', 4334, new Date(NOW.getTime() - 5_000), true)
  gone.overrides.set(psActive(4334), { out: `   00:05 /bin/bash ${gone.dir}/stop-pmmcp-server.sh --jobs\n` })
  gone.onSleep = (): void => {
    gone.overrides.set(psActive(4334), { code: 1 })
    rmSync(activePath(gone.root))
  }
  const went = found(await gone.run(t))
  assert.equal(went.staleActive, undefined)
  assert.equal(went.jobs.state, 'counted')
  assert.equal(went.notes.some((n) => n.includes('the record was removed')), false, went.notes.join('\n'))
  // The same name without the runner's read-only mark is any other step: it may be changing pmmcp, and nothing waits on it.
  const unmarked = new World(t)
  record(unmarked, 'stop-jobs', 4330, new Date(NOW.getTime() - 5_000))
  unmarked.overrides.set(psActive(4330), { out: `   00:05 /bin/bash ${unmarked.dir}/stop-pmmcp-server.sh\n` })
  assert.match(stopWith(await unmarked.run(t), 'active-step').message, /it may still be stopping, starting or changing pmmcp/)
  assert.deepEqual(unmarked.slept, [])
  // A step of the stopped window is named by its program, nothing more of its command line.
  const merging = new World(t)
  record(merging, 'git-merge', 4322, new Date(NOW.getTime() - 3_000))
  merging.overrides.set(psActive(4322), { out: '   00:03 /usr/bin/git merge --ff-only 53ea308\n' })
  const g = stopWith(await merging.run(t), 'active-step')
  assert.match(g.message, /while that pid runs git: it may still be stopping, starting or changing pmmcp/)
  assert.equal(g.message.includes('--ff-only'), false)

  // The pid runs nothing now (the installer died before the exit cleared the record): discovery goes on and hands the record back.
  const dead = new World(t)
  record(dead, 'stop', 4323, new Date(NOW.getTime() - 3_600_000))
  dead.overrides.set(psActive(4323), { code: 1 })
  const c = found(await dead.run(t))
  assert.equal(c.staleActive?.pid, 4323)
  assert.equal(c.staleActive?.step, 'stop')
  assert.ok(c.notes.some((n) => n.includes('that pid no longer runs it')), c.notes.join('\n'))
  // --jobs is not run meanwhile: the runner would refuse it while the record stands.
  assert.equal(dead.ranScript(), false)
  assert.equal(c.jobs.state, 'not-run')
  assert.ok(existsSync(activePath(dead.root)), 'discovery removed the record')
  // A read-only count whose pid has ended: removed at once, nothing waited for, and the jobs counted, a dry run's included.
  const deadCount = new World(t)
  record(deadCount, 'stop-jobs', 4331, new Date(NOW.getTime() - 3_600_000), true)
  deadCount.overrides.set(psActive(4331), { code: 1 })
  const dc = found(await deadCount.run(t))
  assert.equal(dc.staleActive, undefined)
  assert.deepEqual(deadCount.slept, [])
  assert.deepEqual(deadCount.said, [], 'a count that has ended is not waited for, so nothing is said')
  assert.equal(existsSync(activePath(deadCount.root)), false)
  assert.equal(dc.jobs.state, 'counted')
  assert.equal(dc.notes.some((n) => n.includes('that pid no longer runs it')), false, dc.notes.join('\n'))
  // A pid reused by a process that started long after the record: the recorded child is gone.
  const reused = new World(t)
  record(reused, 'stop', 4324, new Date(NOW.getTime() - 3_600_000))
  reused.overrides.set(psActive(4324), { out: '   00:42 /Applications/Safari.app/Contents/MacOS/Safari\n' })
  assert.equal(found(await reused.run(t)).staleActive?.pid, 4324)
  // As does a fresh install's discovery.
  const fresh = new World(t, { install: false })
  record(fresh, 'start', 4325, new Date(NOW.getTime() - 60_000))
  fresh.overrides.set(psActive(4325), { code: 1 })
  const f = await fresh.run(t)
  assert.equal(f.kind === 'absent' ? f.staleActive?.pid : undefined, 4325)

  // What cannot be told apart from the child still running stops: an unreadable record, a pid ps cannot be asked about, an answer it cannot read.
  const unreadable = new World(t)
  mkdirSync(join(unreadable.root, '.aos', 'install'), { recursive: true })
  writeFileSync(activePath(unreadable.root), '{"step": "stop", "pi')
  assert.match(stopWith(await unreadable.run(t), 'active-step').message, /its record cannot be read \(.*is not JSON\)/)
  assert.equal(unreadable.calls.length, 0)
  const noPs = new World(t)
  record(noPs, 'stop', 4326, NOW)
  noPs.overrides.set(psActive(4326), { spawnError: 'ENOENT' })
  assert.match(stopWith(await noPs.run(t), 'active-step').message, /a process ps cannot be asked about/)
  const odd = new World(t)
  record(odd, 'stop', 4327, NOW)
  odd.overrides.set(psActive(4327), { out: 'garbled\n' })
  assert.match(stopWith(await odd.run(t), 'active-step').message, /a process ps does not describe/)
  const undated = new World(t)
  // A start that is no ISO time fails the runner's record schema: the record is unreadable, shown by its reason alone.
  record(undated, 'stop', 4328, 'yesterday')
  const u = stopWith(await undated.run(t), 'active-step').message
  assert.match(u, /its record cannot be read \(.*is not a record of a running step\)/)
  assert.equal(u.includes('yesterday'), false)
  assert.equal(undated.calls.length, 0)
})

test('a port other than 8766/8765/8767 or a non-loopback host stops discovery', async (t) => {
  const w = new World(t)
  edit(w.facts, 'config.server.port', 8770)
  edit(w.facts, 'config.dashboard.host', '0.0.0.0')
  const d = stopped(await w.run(t))
  const port = stopWith(d, 'port')
  assert.match(port.message, /config\.server\.port is 8770/)
  assert.match(stopWith(d, 'host').message, /config\.dashboard\.host is "0\.0\.0\.0"/)
  // Nothing was probed, on loopback or anywhere.
  assert.equal(w.served.length, 0)
  assert.equal(w.ranScript(), false)

  for (const [path, value, code] of [
    ['config.dashboard.port', 8775, 'port'],
    ['config.curator.port', 9000, 'port'],
    ['config.server.host', '192.168.5.2', 'host'],
    ['config.curator.host', '0.0.0.0', 'host'],
  ] as const) {
    const x = new World(t)
    edit(x.facts, path, value)
    assert.ok(stopWith(await x.run(t), code).message.includes(path), path)
  }
  // localhost and ::1 are loopback (the kernel's url must then say so).
  const v6 = new World(t)
  edit(v6.facts, 'config.dashboard.host', '::1')
  found(await v6.run(t))
})

test("kernel.yaml's pmmcp url must name the discovered host and port", async (t) => {
  const w = new World(t)
  edit(w.facts, 'config.server.host', 'localhost')
  const s = stopWith(await w.run(t), 'kernel-url')
  assert.match(s.message, /mcp\.servers\.pmmcp\.url is http:\/\/127\.0\.0\.1:8766\/mcp, but pmmcp serves http:\/\/localhost:8766\/mcp/)

  const fixed = new World(t)
  edit(fixed.facts, 'config.server.host', 'localhost')
  fixed.config = withUrl(fixed.config, 'http://localhost:8766/mcp')
  const f = found(await fixed.run(t))
  assert.equal(f.kernel.urlMatches, true)
  assert.equal(f.kernel.url, 'http://localhost:8766/mcp')

  const path = new World(t)
  path.config = withUrl(path.config, 'http://127.0.0.1:8766/sse')
  stopWith(await path.run(t), 'kernel-url')

  // With nothing installed, a fresh pmmcp serves its defaults.
  const fresh = new World(t, { install: false })
  fresh.config = withUrl(fresh.config, 'http://127.0.0.1:8770/mcp')
  assert.match(stopWith(await fresh.run(t), 'kernel-url').message, /a fresh pmmcp serves http:\/\/127\.0\.0\.1:8766\/mcp/)
})

test("an AOS provider on 11434-11437 is reported as sharing pmmcp's Ollama", async (t) => {
  // The shipped providers put ollama/qwen3:8b on 11434, pmmcp's TextQuery instance.
  const w = new World(t)
  const f = found(await w.run(t))
  assert.deepEqual(f.kernel.ollamaShared, [{ ref: 'ollama/qwen3:8b', port: 11434 }])
  assert.ok(f.notes.some((n) => n.includes('ollama/qwen3:8b') && n.includes('11434-11437')), f.notes.join('\n'))

  const moved = (port: number): ProvidersFile => {
    const entry = SHIPPED_PROVIDERS.entries['ollama/qwen3:8b']
    assert.ok(entry)
    return { ...SHIPPED_PROVIDERS, entries: { ...SHIPPED_PROVIDERS.entries, 'ollama/qwen3:8b': { ...entry, baseUrl: `http://127.0.0.1:${String(port)}` } } }
  }
  const own = new World(t)
  own.providers = moved(11438)
  assert.deepEqual(found(await own.run(t)).kernel.ollamaShared, [])
  const last = new World(t)
  last.providers = moved(11437)
  assert.deepEqual(found(await last.run(t)).kernel.ollamaShared, [{ ref: 'ollama/qwen3:8b', port: 11437 }])
  // localhost, ::1 and any 127/8 address are the Mac's loopback as much as 127.0.0.1.
  const named = (url: string): ProvidersFile => {
    const entry = SHIPPED_PROVIDERS.entries['ollama/qwen3:8b']
    assert.ok(entry)
    return { ...SHIPPED_PROVIDERS, entries: { ...SHIPPED_PROVIDERS.entries, 'ollama/qwen3:8b': { ...entry, baseUrl: url } } }
  }
  for (const url of ['http://localhost:11434/v1', 'http://[::1]:11435/v1', 'http://127.0.0.2:11436']) {
    const w2 = new World(t)
    w2.providers = named(url)
    assert.equal(found(await w2.run(t)).kernel.ollamaShared.length, 1, url)
  }
  const remote = new World(t)
  remote.providers = named('http://192.168.5.2:11434/v1')
  assert.deepEqual(found(await remote.run(t)).kernel.ollamaShared, [])

  // And the daemon: something answers on control.port. The note says so, and asks no restart: the end report does, and only when
  // something the daemon reads changed (a re-run with nothing to do, or a dry run, changes nothing).
  assert.equal(f.kernel.daemonListening, true)
  assert.ok(f.notes.includes("the AOS daemon listens on 7777: it reads .env when it starts, and the end report's next steps say whether this run needs it restarted"), JSON.stringify(f.notes))
  assert.equal(f.notes.some((n) => /restart it after this run/.test(n)), false)
  const quiet = new World(t)
  quiet.handlers.delete(7777)
  assert.equal(found(await quiet.run(t)).kernel.daemonListening, false)
})

test('Docker must answer as desktop-linux in the scrubbed environment', async (t) => {
  const colima = new World(t)
  colima.dockerContext = 'colima-trusted'
  const a = stopWith(await colima.run(t), 'docker')
  assert.match(a.message, /uses "colima-trusted", not desktop-linux/)
  assert.match(a.message, /without DOCKER_CONFIG, DOCKER_HOST or DOCKER_CONTEXT/)
  // docker was asked without the installer's DOCKER_* names, though its shell exports all three.
  const docker = colima.calls.find((c) => c.command === 'docker')
  assert.ok(docker)
  assert.deepEqual(Object.keys(docker.options.env).filter((k) => k.startsWith('DOCKER_')), [])
  assert.ok(colima.env()['DOCKER_CONFIG'] !== undefined)

  const down = new World(t)
  down.dockerInfoCode = 1
  assert.match(stopWith(await down.run(t), 'docker').message, /does not answer \(docker info exited 1\)/)

  const missing = new World(t)
  missing.overrides.set('docker context show', { spawnError: 'ENOENT' })
  assert.match(stopWith(await missing.run(t), 'docker').message, /ENOENT/)

  // The Qdrant status names the engine it asked: it must be the same one.
  const elsewhere = new World(t)
  edit(elsewhere.qdrant, 'docker_context', 'DOCKER_HOST=unix:///Users/op/.colima/hostile/docker.sock')
  assert.match(stopWith(await elsewhere.run(t), 'docker').message, /not desktop-linux/)

  // A fresh install needs it as much.
  const fresh = new World(t, { install: false })
  fresh.dockerContext = 'default'
  stopWith(await fresh.run(t), 'docker')
})

test('a missing pmmcp feature is reported with the commit that adds it', async (t) => {
  const w = new World(t)
  edit(w.facts, 'features.stop_jobs_flag', false)
  edit(w.facts, 'features.stop_engine_guard', false)
  edit(w.facts, 'features.stop_listener_check')
  const f = found(await w.run(t))
  assert.deepEqual(f.missing.map((m) => [m.feature, m.commit]), [
    ['stop_jobs_flag', '540bc6b'],
    ['stop_engine_guard', '540bc6b'],
    ['stop_listener_check', 'e6516d5'],
  ])
  assert.ok(f.notes.includes('pmmcp lacks stop --jobs: update it to 540bc6b or later'), f.notes.join('\n'))
  // Every feature has its commit.
  for (const name of FEATURE_NAMES) assert.match(FEATURE_COMMITS[name], /^[0-9a-f]{7}$/)

  // No facts: the facts themselves are what is missing, and no feature counts.
  const ancient = new World(t)
  rmSync(join(ancient.dir, 'scripts', 'pmmcp_facts.py'))
  const g = found(await ancient.run(t))
  assert.deepEqual(g.missing.map((m) => [m.feature, m.commit]), [['facts', 'c8bae1e']])
  assert.equal(Object.values(g.features).every((v) => !v), true)
  assert.equal(g.facts, undefined)
  assert.equal(ancient.calls.some((c) => c.command === ancient.python), false)
  assert.equal(g.kernel.urlMatches, undefined)
  assert.equal(g.git.head, HEAD)
})

test('http_auth check --expect gets the aos-kernel digest from inspectCredentials on stdin, and runs only when kernel.yaml declares the tokenEnv, .env holds it and the facts show check_expect', async (t) => {
  const TOKEN = randomBytes(32).toString('hex')
  const DIGEST = `sha256:${createHash('sha256').update(TOKEN, 'utf8').digest('hex')}`
  const withEnv = (w: World, text: string): void => {
    writeFileSync(join(w.root, '.env'), text, { mode: 0o600 })
    chmodSync(join(w.root, '.env'), 0o600)
  }
  const checks = (w: World): Call[] => w.calls.filter((c) => c.args.includes('--expect'))

  // A kernel.yaml that declares no pmmcp tokenEnv: nothing to check, whatever .env holds.
  const undeclared = new World(t)
  undeclared.config = withoutTokenEnv(undeclared.config)
  withEnv(undeclared, `AOS_PMMCP_TOKEN=${TOKEN}\n`)
  const a = found(await undeclared.run(t))
  assert.equal(a.bearer.state, 'not-checked')
  assert.equal(checks(undeclared).length, 0)

  // As shipped, kernel.yaml declares it: checked. Every World below keeps the shipped declaration.
  const w = new World(t)
  assert.equal(w.config.mcp.servers['pmmcp']?.tokenEnv, 'AOS_PMMCP_TOKEN')
  withEnv(w, `AOS_CONTROL_TOKEN=${randomBytes(32).toString('hex')}\nAOS_PMMCP_TOKEN=${TOKEN}\n`)
  w.check = { out: 'aos-kernel: matches\n', code: 0 }
  const b = found(await w.run(t))
  assert.deepEqual(b.bearer, { state: 'matches' })
  const call = checks(w)[0]
  assert.ok(call)
  // -B: pmmcp's own code does not keep this one from writing __pycache__ into the checkout.
  assert.deepEqual(call.args, ['-B', '-m', 'src.transport.http_auth', 'check', '--expect', 'aos-kernel'])
  assert.equal(call.options.stdio[0], 'pipe')
  assert.equal(call.stdin, `${DIGEST}\n`)
  // The value itself went nowhere: not in an argument, the environment, stdin, or the runner's logs.
  for (const c of w.calls) {
    assert.equal([c.command, ...c.args, ...Object.values(c.options.env), c.stdin].some((s) => s.includes(TOKEN)), false, c.command)
  }
  const logs = join(w.root, '.aos', 'install')
  for (const run of readdirSync(logs).filter((n) => statSync(join(logs, n)).isDirectory())) {
    for (const file of readdirSync(join(logs, run))) assert.equal(readFileSync(join(logs, run, file), 'utf8').includes(TOKEN), false, file)
  }

  const differs = new World(t)
  withEnv(differs, `AOS_PMMCP_TOKEN=${TOKEN}\n`)
  differs.check = { out: 'aos-kernel: differs\n', code: 3 }
  assert.deepEqual(found(await differs.run(t)).bearer, { state: 'differs' })
  // A verdict counts only with its exit: matches with 0, differs or absent with 3.
  for (const answer of [{ out: 'aos-kernel: matches\n', code: 1 }, { out: 'aos-kernel: matches\n', code: 3 }, { out: 'aos-kernel: differs\n', code: 0 }, { out: 'aos-kernel: absent\n', code: 1 }, { out: '', code: 1, err: 'invalid: tokens.x\n' }]) {
    const mismatched = new World(t)
    withEnv(mismatched, `AOS_PMMCP_TOKEN=${TOKEN}\n`)
    mismatched.check = answer
    assert.equal(found(await mismatched.run(t)).bearer.state, 'failed', JSON.stringify(answer))
  }

  // Cut short by a write that did not finish (the last line, 7 hex characters, no newline): no digest of it is checked, and it is said why.
  const torn = new World(t)
  withEnv(torn, `AOS_CONTROL_TOKEN=${randomBytes(32).toString('hex')}\nAOS_PMMCP_TOKEN=${TOKEN.slice(0, 7)}`)
  assert.deepEqual(found(await torn.run(t)).bearer, {
    state: 'not-checked',
    why: '.env line 2: AOS_PMMCP_TOKEN looks cut short (a write that did not finish): delete that line and re-run',
  })
  assert.equal(checks(torn).length, 0)

  // No value yet (missing, or blank): not checked.
  const blank = new World(t)
  withEnv(blank, 'AOS_PMMCP_TOKEN=\n')
  const c = found(await blank.run(t))
  assert.deepEqual(c.bearer, { state: 'not-checked', why: 'AOS_PMMCP_TOKEN holds no value in .env yet' })
  assert.equal(checks(blank).length, 0)

  // An older pmmcp without check --expect: not run.
  const older = new World(t)
  withEnv(older, `AOS_PMMCP_TOKEN=${TOKEN}\n`)
  edit(older.facts, 'features.check_expect', false)
  assert.equal(found(await older.run(t)).bearer.state, 'not-checked')
  assert.equal(checks(older).length, 0)

  // A .env the writer refuses stops discovery with its reason, which names no value.
  const loose = new World(t)
  withEnv(loose, `AOS_PMMCP_TOKEN=${TOKEN}\n`)
  chmodSync(join(loose.root, '.env'), 0o644)
  const s = stopWith(await loose.run(t), 'dotenv')
  assert.equal(s.message.includes(TOKEN), false)
  assert.equal(checks(loose).length, 0)
})

test('the HTTP probes ask loopback only, through no proxy, with no credential', async (t) => {
  for (const host of ['localhost', '10.0.0.1', 'example.com', '127.0.0.1.nip.io', '[::1]']) {
    await assert.rejects(loopbackGet({ host, port: 8766, path: '/health' }, 1000), DiscoverError, host)
  }
  const seen: IncomingHttpHeaders[] = []
  let proxied = 0
  const proxy = createServer((_req, res) => {
    proxied += 1
    res.end()
  })
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => proxy.close(() => resolve())))
  const big = 'x'.repeat(HTTP_BODY_CAP + 1)
  const server = createServer((req, res) => {
    seen.push(req.headers)
    if (req.url === '/hang') return
    if (req.url === '/big') {
      res.end(big)
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{"status":"ok"}')
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => {
    server.closeAllConnections()
    return new Promise<void>((resolve) => server.close(() => resolve()))
  })
  const port = (server.address() as AddressInfo).port
  const saved = { HTTP_PROXY: process.env['HTTP_PROXY'], http_proxy: process.env['http_proxy'] }
  process.env['HTTP_PROXY'] = `http://127.0.0.1:${String((proxy.address() as AddressInfo).port)}`
  process.env['http_proxy'] = process.env['HTTP_PROXY']
  t.after(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  })
  assert.deepEqual(await loopbackGet({ host: '127.0.0.1', port, path: '/health' }, 2000), { status: 200, body: '{"status":"ok"}' })
  assert.equal(proxied, 0, 'the request went through the proxy')
  // Where Node honours an env proxy (24 on, NODE_USE_ENV_PROXY), it rides the global agent: each probe has an agent of its own.
  const handed: http.RequestOptions[] = []
  const spy: RequestFn = (options, callback) => {
    handed.push(options)
    return http.request(options, callback)
  }
  const spied = loopbackGetWith(spy)
  assert.deepEqual(await spied({ host: '127.0.0.1', port, path: '/health' }, 2000), { status: 200, body: '{"status":"ok"}' })
  await spied({ host: '127.0.0.1', port, path: '/health' }, 2000)
  assert.equal(handed.length, 2)
  for (const options of handed) {
    assert.ok(options.agent instanceof http.Agent, 'no agent of its own')
    assert.notEqual(options.agent, http.globalAgent)
    assert.equal(Reflect.get(options.agent, 'keepAlive'), false)
    assert.equal(options.agent.maxSockets, 1)
    assert.equal(options.method, 'GET')
    assert.equal(options.host, '127.0.0.1')
    assert.equal(JSON.stringify(options.headers ?? {}).toLowerCase().includes('authorization'), false)
  }
  assert.notEqual(handed[0]?.agent, handed[1]?.agent, 'two probes shared an agent')
  assert.equal(seen[0]?.authorization, undefined)
  assert.equal(seen[0]?.host, `127.0.0.1:${String(port)}`)
  assert.equal(seen[0]?.connection, 'close')
  // Nothing answering, an answer that never comes, and one too large are each no answer.
  const closed = createServer()
  await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve))
  const gone = (closed.address() as AddressInfo).port
  await new Promise<void>((resolve) => closed.close(() => resolve()))
  assert.deepEqual(await loopbackGet({ host: '127.0.0.1', port: gone, path: '/' }, 2000), { status: 0, body: '', error: 'ECONNREFUSED' })
  const started = Date.now()
  assert.deepEqual(await loopbackGet({ host: '127.0.0.1', port, path: '/hang' }, 200), { status: 0, body: '', error: 'timeout' })
  assert.ok(Date.now() - started < 2000)
  assert.equal((await loopbackGet({ host: '127.0.0.1', port, path: '/big' }, 2000)).error, 'too large')

  // A server command line names its folder only by <dir>/.venv/bin/pmmcp.
  assert.equal(serverDirOf('/Users/op/Github/Persistent-Memory-MCP/.venv/bin/python /Users/op/Github/Persistent-Memory-MCP/.venv/bin/pmmcp'), '/Users/op/Github/Persistent-Memory-MCP')
  assert.equal(serverDirOf('/usr/bin/python3 -m src.mcp_server'), undefined)
  assert.equal(serverDirOf('python .venv/bin/pmmcp'), undefined)
  // ps joins the arguments with spaces: a folder whose name holds one is read back from the suffix, never split.
  const spaced = '/Users/op/My Projects/Persistent-Memory-MCP'
  assert.equal(serverDirOf(`${spaced}/.venv/bin/python ${spaced}/.venv/bin/pmmcp`), spaced)
  assert.equal(serverDirOf(`/opt/homebrew/bin/python3.12 ${spaced}/.venv/bin/pmmcp --transport http`), spaced)
  assert.equal(serverDirOf(`${spaced}/.venv/bin/pmmcp`), spaced)
  // The suffix must end an argument; a start nearer to it is taken unless the caller's check accepts an earlier one.
  assert.equal(serverDirOf(`${spaced}/.venv/bin/pmmcp-helper`), undefined)
  const odd = '/Users/op/a /b/Persistent-Memory-MCP'
  assert.equal(serverDirOf(`${odd}/.venv/bin/pmmcp`), '/b/Persistent-Memory-MCP')
  assert.equal(serverDirOf(`${odd}/.venv/bin/pmmcp`, (d) => d === odd), odd)
})

test('a pmmcp under a folder whose name holds a space is found by its MCP server on 8766', async (t) => {
  const w = new World(t, { under: ['My Projects', PMMCP_FOLDER], listener: true })
  assert.ok(w.dir.includes(' '))
  const f = found(await w.run(t))
  assert.deepEqual(f.install, { dir: w.dir, source: 'listener' })
  assert.equal(f.server?.pid, SERVER_PID)
  // A folder name that ends in a space puts " /" in the command line: the nearest start reads as /b/Persistent-Memory-MCP, which holds
  // no .venv/bin/pmmcp, so the start whose folder does is taken.
  const odd = new World(t, { under: ['op ', 'b', PMMCP_FOLDER], listener: true })
  assert.ok(odd.dir.includes(' /b/'), odd.dir)
  assert.equal(existsSync(join('/b', PMMCP_FOLDER, '.venv', 'bin', 'pmmcp')), false, 'this machine has a /b install, which this case needs absent')
  assert.deepEqual(found(await odd.run(t)).install, { dir: odd.dir, source: 'listener' })
})

test('an earlier run that stopped pmmcp and did not start it again is found from its run folder, only while pmmcp is stopped and launchd answers that its service is not loaded', async (t) => {
  const runFolder = (w: World, name: string, ...logs: string[]): string => {
    const dir = join(w.root, '.aos', 'install', name)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    for (const log of logs) writeFileSync(join(dir, log), '')
    return dir
  }
  // Killed inside the window: the stop's log, and no start's.
  const killed = new World(t)
  const folder = runFolder(killed, '20261029T070000Z', 'stop-jobs.out', 'stop.out', 'stop.err', 'git-merge.out')
  // A dry run since, which ran no stop or start, does not hide it.
  runFolder(killed, '20261029T073000Z', 'facts.out', 'stop-jobs.out')
  const k = found(await killed.run(t))
  assert.deepEqual(k.leftStopped, { folder })
  assert.equal(k.server, undefined)
  assert.equal(k.service.loaded, false)

  // A later run that started it (L5, or the start offered after a stop that did not stop): nothing left stopped.
  for (const start of ['start.out', 'start-again.out']) {
    const restarted = new World(t)
    runFolder(restarted, '20261029T070000Z', 'stop.out')
    runFolder(restarted, '20261029T070000Z-2', 'stop.out', start)
    assert.equal(found(await restarted.run(t)).leftStopped, undefined, start)
  }
  // The run that started it was the earlier one: the later stop stands. (-10 sorts after -9.)
  const again = new World(t)
  runFolder(again, '20261029T070000Z-9', 'stop.out', 'start.out')
  const latest = runFolder(again, '20261029T070000Z-10', 'stop.out')
  assert.deepEqual(found(await again.run(t)).leftStopped, { folder: latest })
  // Runs at different stamps are read newest first, whatever order the folder lists them in: an old run killed after its stop,
  // then a later run that stopped and started pmmcp, is nothing left stopped; the reverse is the later run's stop.
  const startedSince = new World(t)
  runFolder(startedSince, '20261029T090000Z', 'stop.out', 'start.out')
  runFolder(startedSince, '20261028T070000Z', 'stop.out')
  assert.equal(found(await startedSince.run(t)).leftStopped, undefined, 'a later run started pmmcp')
  assert.equal(earlierStop(startedSince.root, undefined), undefined)
  const stoppedSince = new World(t)
  runFolder(stoppedSince, '20261028T070000Z', 'stop.out', 'start.out')
  const newer = runFolder(stoppedSince, '20261029T090000Z', 'stop.out')
  assert.deepEqual(found(await stoppedSince.run(t)).leftStopped, { folder: newer })
  // A -n run of an older second is older than a plain run of a later one.
  const seconds = new World(t)
  runFolder(seconds, '20261029T085959Z-3', 'stop.out')
  runFolder(seconds, '20261029T090000Z', 'stop.out', 'start.out')
  assert.equal(earlierStop(seconds.root, undefined), undefined)

  // pmmcp running, or a launchd that cannot be asked: not known to be left stopped.
  const running = new World(t, { listener: true })
  runFolder(running, '20261029T070000Z', 'stop.out')
  assert.equal(found(await running.run(t)).leftStopped, undefined)
  const loaded = new World(t, { plist: true })
  runFolder(loaded, '20261029T070000Z', 'stop.out')
  assert.equal(found(await loaded.run(t)).leftStopped, undefined, 'launchd has the service loaded')
  const deaf = new World(t)
  runFolder(deaf, '20261029T070000Z', 'stop.out')
  deaf.overrides.set(`launchctl print gui/${String(OP_UID)}/com.aibot.pmmcp`, { spawnError: 'ENOENT' })
  const d = found(await deaf.run(t))
  assert.equal(d.leftStopped, undefined)
  assert.equal(d.service.loaded, undefined)
  // launchctl failing otherwise (an unusable gui domain, say) did not answer "no such service": not known to be unloaded, and noted so.
  for (const code of [1, 5, 125]) {
    const failing = new World(t)
    runFolder(failing, '20261029T070000Z', 'stop.out')
    failing.overrides.set(`launchctl print gui/${String(OP_UID)}/com.aibot.pmmcp`, { code, err: 'Bad request.\nCould not print domain: Domain does not support specified action\n' })
    const f = found(await failing.run(t))
    assert.equal(f.leftStopped, undefined, String(code))
    assert.equal(f.service.loaded, undefined, String(code))
    assert.ok(
      f.notes.some((n) => n === `launchctl print gui/${String(OP_UID)}/com.aibot.pmmcp exited ${String(code)}, not 113 ("Could not find service"): whether launchd has pmmcp loaded is not known`),
      JSON.stringify(f.notes),
    )
  }

  // S3's screen says it as discovery found it: unloaded, with the run folder that shows the stop; or not known, with no claim either way.
  assert.ok(
    foundScreen(k, killed.config).includes(`service    com.aibot.pmmcp not loaded; no MCP server on its port; the last installer run that stopped it ran no start after it (${folder})`),
    foundScreen(k, killed.config).join('\n'),
  )
  assert.ok(foundScreen(d, deaf.config).includes('service    com.aibot.pmmcp: whether launchd has it loaded is not known; no MCP server on its port'), foundScreen(d, deaf.config).join('\n'))
  const loadedScreen = foundScreen(found(await new World(t, { plist: true, listener: true }).run(t)), killed.config)
  assert.ok(loadedScreen.some((l) => new RegExp(`^service {4}com\\.aibot\\.pmmcp loaded, running, pid ${String(SERVER_PID)}; MCP server pid ${String(SERVER_PID)}`).test(l)), loadedScreen.join('\n'))
  assert.equal(loadedScreen.some((l) => l.includes('ran no start')), false)

  // Read by folder and entry names alone: a link where a run folder would be, or a name not a run's, is passed over.
  const linked = new World(t)
  const elsewhere = tmpdir(t)
  writeFileSync(join(elsewhere, 'stop.out'), '')
  mkdirSync(join(linked.root, '.aos', 'install'), { recursive: true })
  symlinkSync(elsewhere, join(linked.root, '.aos', 'install', '20261029T070000Z'))
  runFolder(linked, 'notes', 'stop.out')
  assert.equal(earlierStop(linked.root, undefined), undefined)
  assert.equal(earlierStop(tmpdir(t), undefined), undefined, 'no .aos/install at all')
  // This run's own folder is never an earlier run.
  assert.equal(earlierStop(killed.root, folder)?.folder, undefined)
})
