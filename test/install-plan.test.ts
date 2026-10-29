// The installer's planner and confirmation gate (src/install/plan.ts,
// src/install/gate.ts).
//
// Both are pure: the planner turns .env's names and lines, the shell's
// exported names and discovery's result into tagged steps and questions, and
// the gate walks them through injected IO. So every test here hands them
// documents in pmmcp's shipped shapes (parsed by src/install/facts.ts) and a
// fake IO that records each question, jobs count, pause and apply in order,
// and every printed line among them; no program runs and nothing live
// exists. The two tests that hand the plan's `generate` map to the real .env
// writer do it in mkdtemp directories only, through appendIn and inspectIn,
// which refuse any other root.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { tmpdir as osTmpdir } from 'node:os'
import { join, sep } from 'node:path'
import test, { type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { PMMCP_CLIENT as DISCOVERY_CLIENT, PMMCP_FOLDER as DISCOVERY_FOLDER, type Absent, type Found } from '../scripts/install/discover.js'
import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { CENSOR, SecretMask } from '../src/events/redact.js'
import { FACTS_MISSING, FEATURE_COMMITS, FEATURE_NAMES, featuresOf, missingFeatures, parseFacts, parseQdrantStatus, type FeatureName } from '../src/install/facts.js'
import {
  FIRST_CONFIRMATION,
  INSTALL_CONFIRMATION,
  JOBS_POLL_MS,
  SECOND_CONFIRMATION,
  runGate,
  type Answer,
  type Applied,
  type GateIO,
  type GateOutcome,
  type JobsAnswer,
  type Pause,
  type Phase,
} from '../src/install/gate.js'
import {
  PMMCP_CLIENT,
  PMMCP_FOLDER,
  PlanError,
  credentialsMap,
  describe,
  exportedNames,
  generatorsFor,
  nonLiveNumbers,
  nothingToDo,
  planInstall,
  select,
  sequence,
  shellWord,
  warning,
  type DotenvView,
  type OfferId,
  type Plan,
  type PlanInput,
  type PmmcpAbsent,
  type PmmcpFound,
  type Step,
} from '../src/install/plan.js'
import { parseProviders, type ProvidersFile } from '../src/models/registry.js'
import { appendCredentials, credentialNames, inspectCredentials, mintedCredentialNames, type AppendResult, type InspectResult } from '../src/secrets/dotenv-append.js'
import { tmpdir } from './helpers/tmpdir.js'

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '')
const DIR = '/Users/op/Github/Persistent-Memory-MCP'
const HEAD = 'e6516d5'.padEnd(40, '0')
const ORIGIN_MAIN = '53ea308'.padEnd(40, '0')
const ORIGIN = 'https://github.com/AiBot-Tools/persistent-memory-mcp.git'
/** http_auth.yaml last changed at 09:00; a server started after 09:10 has loaded it. */
const MODIFIED = new Date('2026-10-29T09:00:00.000Z')
const STARTED_AFTER = new Date('2026-10-29T09:10:00.000Z')
const STARTED_BEFORE = new Date('2026-10-29T08:50:00.000Z')
/** The operator's uid on the Mac: the writer refuses root, and the suite may run as root. */
const OPERATOR_UID = 501

const raw = (p: string): unknown => parseYaml(readFileSync(join(REPO_ROOT, p), 'utf8'))
/** kernel.yaml as shipped: no pmmcp tokenEnv yet, so the credentials map holds the control token alone. */
const SHIPPED: KernelConfig = parseKernelConfig(raw('config/kernel.yaml'), { repoRoot: REPO_ROOT })
const PROVIDERS: ProvidersFile = parseProviders(raw('config/providers.yaml'))

/** kernel.yaml with pmmcp's bearer declared as `tokenEnv` (A8 ships AOS_PMMCP_TOKEN). */
function declaring(tokenEnv: string, extra: Record<string, unknown> = {}): KernelConfig {
  const doc = structuredClone(raw('config/kernel.yaml')) as { mcp: { servers: Record<string, Record<string, unknown>> } }
  const pmmcp = doc.mcp.servers['pmmcp']
  assert.ok(pmmcp !== undefined)
  pmmcp['tokenEnv'] = tokenEnv
  Object.assign(doc.mcp.servers, extra)
  return parseKernelConfig(doc, { repoRoot: REPO_ROOT })
}
const DECLARED = declaring('AOS_PMMCP_TOKEN')

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

const ALL_FEATURES = [
  'bearer_gate',
  'rotate_digest_stdin',
  'check_expect',
  'qdrant_key_script',
  'qdrant_init',
  'qdrant_status_json',
  'dashboard_auth',
  'curator_secret',
  'stop_jobs_flag',
  'stop_engine_guard',
  'curator_proof',
  'stop_listener_check',
] as const

/** The facts as e6516d5 prints them for an install with the dashboard token and curator secret in place. */
function factsDoc(): Doc {
  return {
    facts: 1,
    dir: DIR,
    git: { head: HEAD, branch: 'main', dirty: false, origin: ORIGIN },
    features: Object.fromEntries(ALL_FEATURES.map((f) => [f, true])),
    config: {
      source: '/Users/op/.persistent-memory-mcp/config.yaml',
      server: { host: '127.0.0.1', port: 8766, enabled: true },
      dashboard: { host: '127.0.0.1', port: 8765, enabled: true, legacy_token_key: false },
      curator: { host: '127.0.0.1', port: 8767, enabled: true },
    },
    env_overrides: [],
    http_auth: { state: 'present', mode: 'warn', tokens: ['aos-kernel', 'antigravity'], reason: null, links: 1 },
    qdrant_key_file: { state: 'present' },
    dashboard_token: { state: 'present' },
    curator_secret: { state: 'present' },
    launchd: { plist: '/Users/op/Library/LaunchAgents/com.aibot.pmmcp.plist', exists: true, working_directory: DIR, legacy_plists: [] },
  }
}

/** The facts as dfcc99a printed them: no curator_proof, no stop_listener_check, no http_auth.links. */
function dfcc99a(doc: Doc): Doc {
  edit(doc, 'features.curator_proof')
  edit(doc, 'features.stop_listener_check')
  edit(doc, 'http_auth.links')
  return doc
}

/** Qdrant's status once the key is enforced on 127.0.0.1. */
function qdrantDoc(): Doc {
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
function keyless(doc: Doc = qdrantDoc()): Doc {
  edit(doc, 'key_file', { state: 'absent', reason: null })
  edit(doc, 'container.key_set', false)
  edit(doc, 'collections', { without_key: 200, with_key: null })
  edit(doc, 'verdict', 'not_asked')
  return doc
}

interface FoundOver {
  readonly dir?: string
  /** null: no facts document (a checkout before c8bae1e), so every feature reads false, and discovery reads no Qdrant status and runs no --jobs. */
  readonly facts?: Doc | null
  /** null: no Qdrant status (the checkout cannot print one). */
  readonly qdrant?: Doc | null
  readonly bearer?: PmmcpFound['bearer']
  /** null: nothing listens on 8766. */
  readonly server?: PmmcpFound['server'] | null
  readonly httpAuthModified?: Date | undefined
  readonly git?: Partial<PmmcpFound['git']>
  readonly jobs?: PmmcpFound['jobs']
  readonly ollamaShared?: PmmcpFound['kernel']['ollamaShared']
}

/** Discovery's result for an install that is in place, as the planner reads it, with the fields a test changes. */
function found(over: FoundOver = {}): PmmcpFound {
  const facts = over.facts === null ? undefined : parseFacts(JSON.stringify(over.facts ?? factsDoc()))
  // As discovery reads a checkout with no facts: every feature false, the facts themselves missing, no Qdrant status, no --jobs.
  const q = over.qdrant === undefined ? (facts === undefined ? null : qdrantDoc()) : over.qdrant
  const noJobs = { state: 'not-run', why: 'the stop script cannot count jobs (an older one runs a full stop on --jobs); update pmmcp first' } as const
  return {
    kind: 'found',
    install: { dir: over.dir ?? DIR },
    facts,
    features: facts === undefined ? (Object.fromEntries(FEATURE_NAMES.map((f) => [f, false])) as Record<FeatureName, boolean>) : featuresOf(facts),
    missing: facts === undefined ? [FACTS_MISSING] : missingFeatures(facts),
    git: { head: HEAD, originMain: HEAD, fastForward: false, lockUnchanged: undefined, trackedChanges: 0, untracked: 0, ...over.git },
    server: over.server === null ? undefined : (over.server ?? { pid: 812, startedAfter: STARTED_AFTER }),
    httpAuthModified: 'httpAuthModified' in over ? over.httpAuthModified : MODIFIED,
    qdrant: q === null ? undefined : parseQdrantStatus(JSON.stringify(q)),
    jobs: over.jobs ?? (facts === undefined ? noJobs : { state: 'counted', jobs: { running: 0, display: [] } }),
    bearer: over.bearer ?? { state: 'not-checked', why: 'kernel.yaml declares no tokenEnv for pmmcp, so there is no aos-kernel token yet' },
    kernel: { ollamaShared: over.ollamaShared ?? [] },
  }
}

/** Discovery's result when no pmmcp is installed. */
const ABSENT: PmmcpAbsent = { kind: 'absent', at: DIR, searched: ['the plist', 'the listener on 127.0.0.1:8766', DIR], kernel: { ollamaShared: [] } }

/** A fast-forward discovery would apply: clean tree, uv.lock and pyproject.toml unchanged. */
const FAST_FORWARD: Partial<PmmcpFound['git']> = { originMain: ORIGIN_MAIN, fastForward: true, lockUnchanged: true, trackedChanges: 0, untracked: 0 }

/** .env as inspectCredentials describes it: each name present at a line, blank at a line, or missing. */
function dotenv(names: Readonly<Record<string, number | 'missing' | { blank: number }>>, found = true): DotenvView {
  const present: { name: string; line: number }[] = []
  const blank: { name: string; line: number }[] = []
  const missing: string[] = []
  for (const [name, at] of Object.entries(names)) {
    if (at === 'missing') missing.push(name)
    else if (typeof at === 'number') present.push({ name, line: at })
    else blank.push({ name, line: at.blank })
  }
  return { path: '/Users/op/MrRobot/.env', found, present, blank, missing }
}

/** A .env that holds every name of the shipped config and of A8's. */
const FULL = dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: 4, ANTHROPIC_API_KEY: 5 })

function input(over: Partial<PlanInput> = {}): PlanInput {
  return {
    config: SHIPPED,
    providers: PROVIDERS,
    dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, ANTHROPIC_API_KEY: 5 }),
    room: { writable: true, fits: true },
    exported: new Set(),
    pmmcp: found(),
    tuiPids: [],
    options: { aosOnly: false, noInstall: false },
    ...over,
  }
}

const ids = (steps: readonly Step[]): string[] => steps.map((s) => s.id)
const offerIds = (plan: Plan): string[] => plan.offers.map((o) => o.id)
const has = (lines: readonly string[], pattern: RegExp): boolean => lines.some((l) => pattern.test(l))

// ── the fake IO ──────────────────────────────────────────────────────────

/**
 * What a "yes" to everything types, as `yes` piped into the installer, or an
 * operator who means it, would: y to a y/N question, and the word each typed
 * confirmation asks for.
 */
function yesTo(question: string): string {
  if (question.includes(`\`${FIRST_CONFIRMATION}\``)) return FIRST_CONFIRMATION
  if (question.includes(`\`${SECOND_CONFIRMATION}\``)) return SECOND_CONFIRMATION
  if (question.includes(`\`${INSTALL_CONFIRMATION}\``)) return INSTALL_CONFIRMATION
  return 'y'
}

/** More counts than any test's jobs answers call for. */
const MAX_COUNTS = 20

interface FakeOptions {
  readonly interactive?: boolean
  /** Answers by the question's start; a question no rule matches gets yesTo's answer. */
  readonly answers?: readonly (readonly [RegExp, string | Answer])[]
  readonly jobs?: readonly JobsAnswer[]
  readonly pauses?: readonly Pause[]
  readonly apply?: (phase: Phase, steps: readonly Step[]) => Applied
}

/** Records, in order, every question, jobs count, pause and apply the gate makes (events), and those with every printed line (transcript). */
class FakeIO implements GateIO {
  readonly interactive: boolean
  readonly events: string[] = []
  readonly transcript: string[] = []
  readonly printed: string[] = []
  readonly asked: string[] = []
  readonly applied: { phase: Phase; steps: string[] }[] = []
  readonly #answers: readonly (readonly [RegExp, string | Answer])[]
  readonly #jobs: JobsAnswer[]
  readonly #pauses: Pause[]
  readonly #apply: (phase: Phase, steps: readonly Step[]) => Applied

  constructor(options: FakeOptions = {}) {
    this.interactive = options.interactive ?? true
    this.#answers = options.answers ?? []
    this.#jobs = [...(options.jobs ?? [{ state: 'counted', running: 0, display: [] }])]
    this.#pauses = [...(options.pauses ?? [])]
    this.#apply = options.apply ?? ((): Applied => ({ ok: true }))
  }

  print(line: string): void {
    this.printed.push(line)
    this.transcript.push(`print ${line}`)
  }

  #event(event: string): void {
    this.events.push(event)
    this.transcript.push(event)
  }

  ask(question: string): Promise<Answer> {
    this.asked.push(question)
    this.#event(`ask ${question}`)
    const rule = this.#answers.find(([pattern]) => pattern.test(question))
    const answer = rule === undefined ? yesTo(question) : rule[1]
    return Promise.resolve(typeof answer === 'string' ? { kind: 'line', text: answer } : answer)
  }

  countJobs(): Promise<JobsAnswer> {
    this.#event('jobs')
    // A gate that keeps counting after its answer should have ended the wait fails here, rather than spinning the test forever.
    assert.ok(this.events.filter((e) => e === 'jobs').length <= MAX_COUNTS, `the gate counted jobs more than ${String(MAX_COUNTS)} times`)
    const next = this.#jobs.length > 1 ? this.#jobs.shift() : this.#jobs[0]
    assert.ok(next !== undefined, 'the test gave no jobs answer')
    return Promise.resolve(next)
  }

  pause(ms: number): Promise<Pause> {
    this.#event(`pause ${String(ms)}`)
    return Promise.resolve(this.#pauses.shift() ?? 'elapsed')
  }

  apply(phase: Phase, steps: readonly Step[]): Promise<Applied> {
    this.#event(`apply ${phase}`)
    this.applied.push({ phase, steps: ids(steps) })
    return Promise.resolve(this.#apply(phase, steps))
  }
}

const gate = (plan: Plan, io: FakeIO, dryRun = false): Promise<GateOutcome> => runGate(plan, io, { dryRun, logs: '/Users/op/MrRobot/.aos/install/20261029T090000Z' })

/** The events from the gate's first typed confirmation on. */
const fromFirst = (io: FakeIO): string[] => io.events.slice(io.events.findIndex((e) => e.startsWith(`ask Type \`${FIRST_CONFIRMATION}\``)))

// ── the real writer, held to scratch directories ─────────────────────────

/** The only way these tests call the writer: `repo` must be a scratch directory under the OS temp dir, never this checkout. */
function appendIn(repo: string, generate: ReadonlyMap<string, () => string>, config: KernelConfig, digests: readonly string[]): AppendResult {
  const real = realpathSync(repo)
  assert.ok(real.startsWith(realpathSync(osTmpdir()) + sep), `${repo} is not a scratch directory`)
  const checkout = realpathSync(REPO_ROOT)
  assert.ok(real !== checkout && !real.startsWith(checkout + sep), `${repo} is this checkout`)
  return appendCredentials({
    repoRoot: repo,
    accepted: credentialNames(config, PROVIDERS),
    generate,
    generatable: mintedCredentialNames(config),
    providers: PROVIDERS,
    uid: process.getuid?.() ?? OPERATOR_UID,
    euid: OPERATOR_UID,
    digests,
  })
}

/** The writer's inspection, held to scratch directories as appendIn is. */
function inspectIn(repo: string, names: readonly string[], config: KernelConfig, digests: readonly string[] = []): InspectResult {
  const real = realpathSync(repo)
  assert.ok(real.startsWith(realpathSync(osTmpdir()) + sep), `${repo} is not a scratch directory`)
  const checkout = realpathSync(REPO_ROOT)
  assert.ok(real !== checkout && !real.startsWith(checkout + sep), `${repo} is this checkout`)
  return inspectCredentials({
    repoRoot: repo,
    accepted: credentialNames(config, PROVIDERS),
    names,
    uid: process.getuid?.() ?? OPERATOR_UID,
    euid: OPERATOR_UID,
    digests,
  })
}

/** A scratch repository whose .gitignore ignores .env, with no .env. */
function scratchRepo(t: TestContext): string {
  const repo = tmpdir(t)
  writeFileSync(join(repo, '.gitignore'), '/.env\n')
  return repo
}

/** The planner's input from the writer's own inspection of a scratch repository: S2's two calls. */
function inspected(repo: string, config: KernelConfig, pmmcp: PmmcpFound): PlanInput {
  const map = [...credentialsMap(config).keys()]
  const screen = inspectIn(repo, [...map, 'ANTHROPIC_API_KEY'], config)
  const room = inspectIn(repo, map, config)
  return input({ config, dotenv: screen, room, pmmcp })
}

const sha256 = (value: string): string => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`

// ── the tests ────────────────────────────────────────────────────────────

test("discovery's result and the writer's inspection are what the planner takes, by the names discovery uses", () => {
  // A compile-time check: scripts/install/discover.ts's Found and the
  // writer's InspectResult pass to the planner as they are.
  const fromDiscovery = (f: Found): PmmcpFound => f
  const fromWriter = (r: InspectResult): DotenvView => r
  const fromAbsent = (a: Absent): PmmcpAbsent => a
  assert.equal(typeof fromDiscovery, 'function')
  assert.equal(typeof fromAbsent, 'function')
  assert.equal(typeof fromWriter, 'function')
  assert.equal(PMMCP_CLIENT, DISCOVERY_CLIENT)
  assert.equal(PMMCP_FOLDER, DISCOVERY_FOLDER)
  assert.equal(SECOND_CONFIRMATION, DISCOVERY_FOLDER)
  assert.equal(FIRST_CONFIRMATION, 'stop pmmcp')
})

test('nothing to do on a configured system: an empty plan and no prompt', async () => {
  // As shipped (no pmmcp tokenEnv): the control token in .env, Qdrant
  // enforced, the dashboard token and curator secret present, no update.
  const shipped = planInstall(input())
  assert.deepEqual(shipped.stops, [])
  assert.deepEqual(shipped.steps, [])
  assert.deepEqual(shipped.offers, [])
  assert.deepEqual(shipped.generate, [])
  assert.equal(nothingToDo(shipped), true)

  // Once kernel.yaml declares the bearer: on file in pmmcp, and loaded by a server that started after.
  const declared = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ bearer: { state: 'matches' } }) }))
  assert.deepEqual([declared.stops, declared.steps, declared.offers, declared.generate], [[], [], [], []])
  assert.equal(declared.staged, undefined)

  for (const plan of [shipped, declared]) {
    for (const interactive of [true, false]) {
      const io = new FakeIO({ interactive })
      const outcome = await gate(plan, io)
      assert.deepEqual(outcome, { kind: 'nothing-to-do', exitCode: 0 })
      assert.deepEqual(io.events, [], 'nothing is asked, counted or applied')
      assert.ok(has(io.printed, /^nothing to do/), io.printed.join('\n'))
    }
  }

  // An update alone, with every feature there, is noted, not offered: still nothing to do.
  const update = planInstall(input({ pmmcp: found({ git: FAST_FORWARD }) }))
  assert.equal(nothingToDo(update), true)
  assert.ok(has(update.notes, /can be updated to 53ea308/), update.notes.join('\n'))
})

test('a missing AOS_PMMCP_TOKEN is generated and its digest staged; a present one is never replaced, only its digest staged', async (t) => {
  const repo = scratchRepo(t)
  // Nothing in .env yet; pmmcp has no aos-kernel digest, which discovery could not check without a value.
  const first = planInstall(inspected(repo, DECLARED, found({ bearer: { state: 'not-checked', why: 'AOS_PMMCP_TOKEN holds no value in .env yet' } })))
  assert.deepEqual(first.stops, [])
  assert.deepEqual(first.generate, ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN'])
  assert.deepEqual(first.staged, { name: 'AOS_PMMCP_TOKEN', client: 'aos-kernel', from: 'append' })
  const stage = first.steps.find((s) => s.id === 'stage-digest')
  assert.ok(stage !== undefined)
  assert.equal(stage.tag, 'pmmcp-file')
  assert.deepEqual(ids(first.steps.slice(0, 2)), ['env', 'stage-digest'], 'the append comes first: the digest is of what it appends')
  assert.ok(stage.commands.some((c) => c.endsWith('rotate_http_auth_token.py aos-kernel --create --digest-stdin')), stage.commands.join('\n'))
  assert.ok(stage.commands.some((c) => c.endsWith('check --expect aos-kernel')))
  assert.equal(stage.commands.some((c) => /sha256:|[0-9a-f]{64}/.test(c)), false, 'a digest goes on stdin, never in argv')

  // The writer, handed generatorsFor(plan), appends exactly those names and returns the digest to stage.
  const minted = new Map<string, string>()
  const mint = (): string => {
    const value = randomBytes(32).toString('hex')
    minted.set(String(minted.size), value)
    return value
  }
  const appended = appendIn(repo, generatorsFor(first, mint), DECLARED, [first.staged?.name ?? ''])
  assert.deepEqual(appended.appended.map((n) => n.name), ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN'])
  const pmmcpValue = minted.get('1') ?? ''
  assert.deepEqual(appended.digests, [{ name: 'AOS_PMMCP_TOKEN', digest: sha256(pmmcpValue) }])
  const bytes = readFileSync(join(repo, '.env'))

  // A re-run: the token is present, and pmmcp does not have its digest yet (absent), or holds another (differs).
  for (const state of ['absent', 'differs'] as const) {
    const again = planInstall(inspected(repo, DECLARED, found({ bearer: { state } })))
    assert.deepEqual(again.generate, [], 'a present token is never generated again')
    assert.deepEqual(again.staged, { name: 'AOS_PMMCP_TOKEN', client: 'aos-kernel', from: 'file' }, state)
    assert.equal(again.steps.some((s) => s.id === 'env'), false)
    assert.ok(again.steps.some((s) => s.id === 'stage-digest'), state)
    // The digest staged is the one of the line .env already holds.
    assert.deepEqual(inspectIn(repo, [], DECLARED, ['AOS_PMMCP_TOKEN']).digests, [{ name: 'AOS_PMMCP_TOKEN', digest: sha256(pmmcpValue) }])
    // And the writer, handed the re-run's map, changes no byte.
    assert.deepEqual(appendIn(repo, generatorsFor(again, mint), DECLARED, []).appended, [])
    assert.deepEqual(readFileSync(join(repo, '.env')), bytes)
  }

  // A token this run appends is staged whatever discovery said of pmmcp's file: its digest is of the value about to be made.
  const appending = planInstall(input({ config: DECLARED, dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 5 }), pmmcp: found({ bearer: { state: 'matches' } }) }))
  assert.deepEqual(appending.staged, { name: 'AOS_PMMCP_TOKEN', client: 'aos-kernel', from: 'append' })
  assert.deepEqual(ids(appending.steps.slice(0, 2)), ['env', 'stage-digest'])

  // Already on file and loaded: nothing is staged at all.
  const done = planInstall(inspected(repo, DECLARED, found({ bearer: { state: 'matches' } })))
  assert.equal(done.staged, undefined)
  assert.equal(nothingToDo(done), true)

  // A pmmcp without rotate --digest-stdin or check --expect: noted, with the commit that adds it, and not staged.
  const old = factsDoc()
  edit(old, 'features.rotate_digest_stdin', false)
  const behind = planInstall(inspected(repo, DECLARED, found({ facts: old, bearer: { state: 'absent' } })))
  assert.equal(behind.steps.some((s) => s.id === 'stage-digest'), false)
  assert.ok(has(behind.notes, new RegExp(`rotate --digest-stdin \\(${FEATURE_COMMITS.rotate_digest_stdin}\\)`)), behind.notes.join('\n'))
})

test("a name the installer's shell exports is never appended", async () => {
  // A blank export does not win at boot, so it does not count.
  const env = { AOS_CONTROL_TOKEN: 'f'.repeat(64), AOS_PMMCP_TOKEN: '  ', ANTHROPIC_API_KEY: 'k', UNRELATED: 'x' }
  assert.deepEqual([...exportedNames(env, ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY'])], ['AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY'])

  // Missing from .env and exported: not appended, and the run stops with "unset it and re-run".
  const missing = planInstall(
    input({
      config: DECLARED,
      dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }),
      exported: new Set(['AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY']),
      pmmcp: found({ bearer: { state: 'not-checked', why: 'no value yet' } }),
    }),
  )
  assert.deepEqual(missing.generate, ['AOS_PMMCP_TOKEN'])
  assert.ok(has(missing.stops, /^AOS_CONTROL_TOKEN is exported by this shell and holds no line in \.env.*unset AOS_CONTROL_TOKEN/), missing.stops.join('\n'))
  assert.equal(has(missing.stops, /ANTHROPIC_API_KEY/), false, "a provider key's export is the operator's business")
  assert.deepEqual(missing.dotenv.exported, ['AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY'])
  const io = new FakeIO()
  assert.deepEqual(await gate(missing, io), { kind: 'refused', exitCode: 2 })
  assert.deepEqual(io.events, [], 'a refused plan asks and applies nothing')

  // pmmcp's token set in .env and exported: no digest is staged, since the kernel would send the export.
  const present = planInstall(input({ config: DECLARED, dotenv: FULL, exported: new Set(['AOS_PMMCP_TOKEN']), pmmcp: found({ bearer: { state: 'absent' } }) }))
  assert.deepEqual(present.generate, [])
  assert.equal(present.staged, undefined)
  assert.equal(present.steps.some((s) => s.id === 'stage-digest'), false)
  assert.ok(has(present.stops, /^AOS_PMMCP_TOKEN is set in \.env \(line 4\) and exported by this shell/), present.stops.join('\n'))

  // The control token set and exported: nothing to append or stage for it, so only a note.
  const control = planInstall(input({ exported: new Set(['AOS_CONTROL_TOKEN']) }))
  assert.deepEqual([control.stops, control.generate], [[], []])
  assert.ok(has(control.notes, /AOS_CONTROL_TOKEN is exported by this shell as well as set in \.env \(line 3\)/))
})

test('a staged digest the running server has not loaded adds one restart', () => {
  const plan = (pmmcp: PmmcpFound): Plan => planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp }))

  // On file, but the server started before http_auth.yaml last changed, or cannot be shown to have started after.
  for (const server of [{ pid: 812, startedAfter: STARTED_BEFORE }, { pid: 812, startedAfter: undefined }]) {
    const p = plan(found({ bearer: { state: 'matches' }, server }))
    assert.deepEqual(offerIds(p), ['restart'])
    assert.equal(p.offers[0]?.question, 'Restart pmmcp to load the staged aos-kernel token? [y/N]')
    assert.deepEqual(ids(select(p, new Set<OfferId>(['restart'])).live), ['stop', 'start', 'bearer-check'])
  }
  // Loaded: nothing.
  assert.equal(nothingToDo(plan(found({ bearer: { state: 'matches' }, server: { pid: 812, startedAfter: STARTED_AFTER } }))), true)
  // To the second: started 1 s before the change has not loaded it, 1 s after has.
  for (const [offset, restart] of [[-1000, true], [1000, false]] as const) {
    const p = plan(found({ bearer: { state: 'matches' }, server: { pid: 812, startedAfter: new Date(MODIFIED.getTime() + offset) } }))
    assert.deepEqual(offerIds(p), restart ? ['restart'] : [], String(offset))
  }

  // Why, in each case: never that it has not loaded it, which ps's lower bound cannot show.
  const why = (server: PmmcpFound['server'] | null, modified: Date | undefined): Plan => plan(found({ bearer: { state: 'matches' }, server, httpAuthModified: modified }))
  for (const [p, note] of [
    [why({ pid: 812, startedAfter: STARTED_BEFORE }, MODIFIED), 'the running MCP server (pid 812) started before http_auth.yaml last changed, as far as ps can tell, so it may not have loaded it'],
    [why({ pid: 812, startedAfter: undefined }, MODIFIED), 'the running MCP server (pid 812) cannot be shown to have started after http_auth.yaml last changed (ps gave no start), so it may not have loaded it'],
    [why({ pid: 812, startedAfter: STARTED_AFTER }, undefined), "http_auth.yaml's last change could not be read, so the running MCP server (pid 812) may not have loaded it"],
    [why({ pid: 812, startedAfter: undefined }, undefined), "http_auth.yaml's last change could not be read, so the running MCP server (pid 812) may not have loaded it"],
  ] as const) {
    assert.deepEqual(offerIds(p), ['restart'], note)
    assert.ok(p.notes.includes(`the aos-kernel digest is on file, but ${note}`), p.notes.join('\n'))
    assert.equal(has(p.notes, /has not loaded/), false)
  }

  // Staged by this run, beside a Qdrant cutover and the auth files: one stop and one start for all of them.
  const facts = factsDoc()
  edit(facts, 'dashboard_token', { state: 'absent' })
  edit(facts, 'curator_secret', { state: 'absent' })
  const all = plan(found({ facts, qdrant: keyless(), bearer: { state: 'absent' } }))
  assert.deepEqual(offerIds(all), ['qdrant', 'auth', 'restart'])
  const { nonLive, live } = select(all, new Set<OfferId>(['qdrant', 'auth', 'restart']))
  assert.deepEqual(ids(nonLive), ['stage-digest'])
  assert.deepEqual(ids(live), ['stop', 'qdrant-enable', 'auth-init', 'start', 'bearer-check'])
  assert.deepEqual(ids(select(all, new Set<OfferId>(['qdrant'])).live), ['stop', 'qdrant-enable', 'start', 'bearer-check'], 'any item restarts pmmcp, so the token loads too')
  assert.deepEqual(select(all, new Set()).live, [], 'no live item, no window')

  // pmmcp not running: the digest is staged for its next start, and no restart is offered.
  const stopped = plan(found({ bearer: { state: 'absent' }, server: null }))
  assert.deepEqual(ids(stopped.steps), ['stage-digest'])
  assert.deepEqual(stopped.offers, [])
  assert.ok(has(stopped.notes, /^pmmcp is not running: it loads the aos-kernel digest when it next starts/))
})

test('every live step needs both typed confirmations in order, with the jobs check between them', async () => {
  const plan = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ qdrant: keyless(), bearer: { state: 'absent' } }) }))
  assert.deepEqual(offerIds(plan), ['qdrant', 'restart'])
  const io = new FakeIO()
  const outcome = await gate(plan, io)
  assert.deepEqual(outcome, { kind: 'done', applied: ['non-live', 'live'], exitCode: 0 })
  assert.deepEqual(io.events, [
    'ask Enable the Qdrant API key now (live cutover)? [y/N]',
    // The restart is not asked: the cutover's window restarts pmmcp anyway.
    'ask Apply the non-live step 1 now? [y/N]',
    'apply non-live',
    `ask Type \`${FIRST_CONFIRMATION}\` to continue`,
    'jobs',
    `ask Second confirmation: type the folder name \`${PMMCP_FOLDER}\` to stop it now`,
    'apply live',
  ])
  assert.deepEqual(io.applied, [
    { phase: 'non-live', steps: ['stage-digest'] },
    { phase: 'live', steps: ['stop', 'qdrant-enable', 'start', 'bearer-check'] },
  ])
  // The warning, each item's rollback and the "do not close" line come before the first confirmation;
  // the exact sequence after the jobs check and before the second.
  const at = (event: string): number => {
    const i = io.transcript.indexOf(event)
    assert.ok(i >= 0 && io.transcript.lastIndexOf(event) === i, `${event} is in the transcript once:\n${io.transcript.join('\n')}`)
    return i
  }
  // The restart is said, not asked: after the cutover's answer and before the non-live question.
  const implied = at('print Restart pmmcp to load the staged aos-kernel token?: yes, by the changes above, which restart pmmcp once')
  assert.ok(at('ask Enable the Qdrant API key now (live cutover)? [y/N]') < implied && implied < at('ask Apply the non-live step 1 now? [y/N]'), io.transcript.join('\n'))
  const warned = at('print WARNING: these changes stop pmmcp, and every program that uses it waits until it is back.')
  // What stops (every port's listener, whoever's, and the four Ollama instances), the downtime, and launchd until the start.
  const stops = at(
    'print What stops: the MCP server (Antigravity and the AOS lose their memory meanwhile), the dashboard, the curator, the worker, the scraper, the backup daemon, Qdrant, ' +
      "and the four Ollama instances on 11434-11437, including whatever answers on 11434 when the start script's PID file for it exists; " +
      "also whatever listens on 8765, 8767 or the MCP port, whoever's process it is (the stop signals a port's listener without a command-line check, " +
      'so a VM port forwarder of yours there is stopped too, and SIGKILLed if the stop is interrupted).',
  )
  const downtime = at('print Downtime: the job wait up to 300 s, graceful stops with no upper bound, then a start of up to about 6 min. launchd keeps pmmcp disabled until the start.')
  assert.ok(warned < stops && stops < downtime, io.transcript.join('\n'))
  const rollback = at(
    "print   - Qdrant API key cutover: a new pmmcp-qdrant from the same image with the key and every port on 127.0.0.1, each collection checked; the old one kept, stopped, as pmmcp-qdrant-prekey; " +
      'rollback: cd /Users/op/Github/Persistent-Memory-MCP && .venv/bin/python scripts/qdrant_api_key.py rollback',
  )
  const doNotClose = at('print Do not close this terminal. Ctrl-C will not interrupt a graceful stop.')
  const first = at(`ask Type \`${FIRST_CONFIRMATION}\` to continue`)
  const jobs = at('jobs')
  const now = at('print Now: the graceful stop (stop-pmmcp-server.sh), then the Qdrant key cutover, then the start (start-pmmcp-server.sh) and its checks, then the aos-kernel bearer check.')
  const second = at(`ask Second confirmation: type the folder name \`${PMMCP_FOLDER}\` to stop it now`)
  assert.ok(downtime < rollback && rollback < doNotClose && doNotClose < first, io.transcript.join('\n'))
  assert.ok(first < jobs && jobs < now && now < second && second < at('apply live'), io.transcript.join('\n'))
})

test('a wrong word, EOF or Ctrl-C at either confirmation aborts with nothing live done', async () => {
  const plan = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ qdrant: keyless(), bearer: { state: 'absent' } }) }))
  const FIRST = /^Type `stop pmmcp`/
  const SECOND = /^Second confirmation/
  const cases: readonly { at: RegExp; answer: string | Answer; outcome: Partial<GateOutcome> }[] = [
    { at: FIRST, answer: 'stop', outcome: { kind: 'declined', exitCode: 0 } },
    { at: FIRST, answer: 'Stop pmmcp', outcome: { kind: 'declined', exitCode: 0 } },
    { at: FIRST, answer: 'yes', outcome: { kind: 'declined', exitCode: 0 } },
    { at: FIRST, answer: '', outcome: { kind: 'declined', exitCode: 0 } },
    // The word inside other text is not the word: not as a suffix, nor as a prefix.
    { at: FIRST, answer: 'do not stop pmmcp', outcome: { kind: 'declined', exitCode: 0 } },
    { at: FIRST, answer: 'stop pmmcp now', outcome: { kind: 'declined', exitCode: 0 } },
    { at: FIRST, answer: { kind: 'eof' }, outcome: { kind: 'aborted', exitCode: 130 } },
    { at: FIRST, answer: { kind: 'interrupt' }, outcome: { kind: 'aborted', exitCode: 130 } },
    { at: SECOND, answer: 'persistent-memory-mcp', outcome: { kind: 'declined', exitCode: 0 } },
    { at: SECOND, answer: 'stop pmmcp', outcome: { kind: 'declined', exitCode: 0 } },
    { at: SECOND, answer: 'y', outcome: { kind: 'declined', exitCode: 0 } },
    { at: SECOND, answer: `not ${PMMCP_FOLDER}`, outcome: { kind: 'declined', exitCode: 0 } },
    { at: SECOND, answer: `${PMMCP_FOLDER}!`, outcome: { kind: 'declined', exitCode: 0 } },
    { at: SECOND, answer: { kind: 'eof' }, outcome: { kind: 'aborted', exitCode: 130 } },
    { at: SECOND, answer: { kind: 'interrupt' }, outcome: { kind: 'aborted', exitCode: 130 } },
  ]
  for (const c of cases) {
    const io = new FakeIO({ answers: [[c.at, c.answer]] })
    const outcome = await gate(plan, io)
    const label = `${String(c.at)} ${JSON.stringify(c.answer)}`
    assert.equal(outcome.kind, c.outcome.kind, label)
    assert.equal(outcome.exitCode, c.outcome.exitCode, label)
    assert.ok('applied' in outcome)
    assert.deepEqual(outcome.applied, ['non-live'], label)
    assert.equal(io.events.includes('apply live'), false, `${label}: nothing live is done`)
    assert.equal(io.events.at(-1)?.startsWith('ask '), true, `${label}: the run ends at the prompt`)
    if (c.at === SECOND) assert.ok(io.events.includes('jobs'), label)
    else assert.equal(io.events.includes('jobs'), false, `${label}: no count before the first confirmation`)
    if (outcome.kind === 'declined') assert.ok(has(io.printed, /nothing live was done \(the non-live steps above were applied\)/), io.printed.join('\n'))
  }
  // Spaces around the word are not a wrong word.
  const spaced = new FakeIO({ answers: [[FIRST, '  stop pmmcp '], [SECOND, ` ${PMMCP_FOLDER}  `]] })
  assert.equal((await gate(plan, spaced)).kind, 'done')

  // No to every live item: the non-live steps alone, and no confirmation is asked.
  const noLive = new FakeIO({ answers: [[/^Enable the Qdrant/, 'n'], [/^Restart/, 'n']] })
  assert.deepEqual(await gate(plan, noLive), { kind: 'done', applied: ['non-live'], exitCode: 0 })
  assert.equal(noLive.asked.some((q) => FIRST.test(q) || SECOND.test(q)), false)
  // A no (an empty line), or Ctrl-C, at the non-live steps: nothing at all.
  for (const [answer, outcome] of [
    ['', { kind: 'declined', at: 'non-live', applied: [], exitCode: 0 }],
    [{ kind: 'interrupt' }, { kind: 'aborted', at: 'non-live', by: 'interrupt', applied: [], exitCode: 130 }],
  ] as const) {
    const io = new FakeIO({ answers: [[/^Apply the non-live/, answer]] })
    assert.deepEqual(await gate(plan, io), outcome)
    assert.equal(io.events.some((e) => e.startsWith('apply')), false, JSON.stringify(answer))
  }
})

test('a non-TTY stdin never reaches a write: plan printed, exit 3', async () => {
  const facts = factsDoc()
  edit(facts, 'dashboard_token', { state: 'absent' })
  const plans = [
    planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ facts, qdrant: keyless(), bearer: { state: 'absent' } }) })),
    planInstall(input({ dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }) })),
    planInstall(input({ pmmcp: ABSENT })),
  ]
  for (const plan of plans) {
    // Whatever stdin would say: the gate never asks it.
    const io = new FakeIO({ interactive: false })
    const outcome = await gate(plan, io)
    assert.deepEqual(outcome, { kind: 'not-a-terminal', exitCode: 3 })
    assert.deepEqual(io.events, [], 'nothing is asked, counted or applied')
    for (const line of describe(plan)) assert.ok(io.printed.includes(line), `the plan is printed: ${line}`)
    assert.ok(has(io.printed, /^stdin is not a terminal: changes are needed/))
  }
})

test('dry run marks every step would-do and runs none', async () => {
  const facts = factsDoc()
  edit(facts, 'dashboard_token', { state: 'absent' })
  edit(facts, 'curator_secret', { state: 'absent' })
  edit(facts, 'features.qdrant_init', false)
  const plan = planInstall(
    input({
      config: DECLARED,
      dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }),
      pmmcp: found({ facts, qdrant: keyless(), git: FAST_FORWARD, bearer: { state: 'not-checked', why: 'no value yet' } }),
    }),
  )
  assert.deepEqual(ids(plan.steps), ['env', 'stage-digest', 'stop', 'update', 'qdrant-enable', 'auth-init', 'start', 'bearer-check'])
  assert.deepEqual(offerIds(plan), ['qdrant', 'auth', 'update', 'restart'])
  for (const interactive of [true, false]) {
    const io = new FakeIO({ interactive })
    assert.deepEqual(await gate(plan, io, true), { kind: 'dry-run', exitCode: 0 })
    assert.deepEqual(io.events, [], 'nothing is asked, counted or applied')
    plan.steps.forEach((step, i) => {
      assert.ok(has(io.printed, new RegExp(`^would ${String(i + 1)}\\. \\[[^\\]]+\\] ${step.title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`)), `step ${String(i + 1)} (${step.id}) is marked would-do`)
    })
    for (const offer of plan.offers) assert.ok(io.printed.includes(`would ask: ${offer.question}`), offer.question)
    assert.equal(io.printed.at(-2), 'would ask you to type `stop pmmcp` and then, after the jobs check, `Persistent-Memory-MCP`, before any live step')
    assert.equal(io.printed.at(-1), 'dry run: nothing was changed, nothing was stopped or started (probe output in /Users/op/MrRobot/.aos/install/20261029T090000Z)')
  }
  // Non-live steps alone (pmmcp not running, so no restart): no typed word would be asked.
  const stagedOnly = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ bearer: { state: 'absent' }, server: null }) }))
  assert.deepEqual([ids(stagedOnly.steps), stagedOnly.offers], [['stage-digest'], []])
  const quiet = new FakeIO()
  assert.deepEqual(await gate(stagedOnly, quiet, true), { kind: 'dry-run', exitCode: 0 })
  assert.equal(has(quiet.printed, /^would ask you to type/), false, quiet.printed.join('\n'))
  // The tags, as S4 shows them.
  const shown = describe(plan)
  assert.ok(has(shown, /^ {2}1\. \[AOS file\] append AOS_PMMCP_TOKEN to/), shown.join('\n'))
  assert.ok(has(shown, /^ {2}2\. \[pmmcp file, loads at next restart\] stage the aos-kernel digest/))
  assert.ok(has(shown, /^ {2}3\. \[LIVE\] stop pmmcp gracefully.*\(whenever a live item is chosen\)$/))
  assert.ok(has(shown, /^ {2}5\. \[LIVE\] Qdrant API key cutover.*\(if you answer yes to "Enable the Qdrant API key now \(live cutover\)\?"\)$/))
})

test('Qdrant cutover is offered only for an existing, keyless container with no prekey kept', async () => {
  const qdrantPlan = (q: Doc | null, facts: Doc = factsDoc()): Plan => planInstall(input({ pmmcp: found({ facts, qdrant: q }) }))

  for (const state of ['running', 'stopped'] as const) {
    const p = qdrantPlan(edit(keyless(), 'container.state', state))
    assert.deepEqual(offerIds(p), ['qdrant'], state)
    const step = p.steps.find((s) => s.id === 'qdrant-enable')
    assert.ok(step !== undefined)
    assert.equal(step.tag, 'live')
    assert.deepEqual(step.commands, [`${DIR}/.venv/bin/python scripts/qdrant_api_key.py enable --dry-run`, `${DIR}/.venv/bin/python scripts/qdrant_api_key.py enable`])
    assert.match(step.rollback ?? '', /qdrant_api_key\.py rollback/)
  }

  /** No pmmcp-qdrant at all, as status --json gives it: key_set null, nothing asked, the key file as `keyFile` says. */
  const noContainer = (keyFile: { state: string; reason: string | null }): Doc =>
    edit(edit(edit(edit(keyless(), 'container.state', 'absent'), 'container.key_set', null), 'verdict', 'not_running'), 'key_file', keyFile)
  const notOffered: readonly [string, Doc | null, RegExp][] = [
    ['enforced', qdrantDoc(), /^$/],
    // init only makes the key file (and keeps one that is there); the start script creates pmmcp-qdrant with it.
    [
      'no container, no key file',
      noContainer({ state: 'absent', reason: null }),
      /^pmmcp-qdrant does not exist, and ~\/\.persistent-memory-mcp\/qdrant_api_key is not there: run init first \(cd \/Users\/op\/Github\/Persistent-Memory-MCP && \.venv\/bin\/python scripts\/qdrant_api_key\.py init\), and the next start creates it with the key \(cd \/Users\/op\/Github\/Persistent-Memory-MCP && \.\/start-pmmcp-server\.sh\)$/,
    ],
    [
      'no container, the key file there',
      noContainer({ state: 'present', reason: null }),
      /^pmmcp-qdrant does not exist, and ~\/\.persistent-memory-mcp\/qdrant_api_key is there: the next start creates it with the key \(cd \/Users\/op\/Github\/Persistent-Memory-MCP && \.\/start-pmmcp-server\.sh\)$/,
    ],
    [
      'no container, the key file unusable',
      noContainer({ state: 'unusable', reason: 'mode 0644' }),
      /^pmmcp-qdrant does not exist, and ~\/\.persistent-memory-mcp\/qdrant_api_key is unusable \(mode 0644\): fix or remove it, run init \(cd .* init\), and the next start creates it with the key/,
    ],
    ['a prekey kept', edit(keyless(), 'prekey_kept', true), /^pmmcp-qdrant-prekey is kept from an earlier cutover/],
    // A kept prekey beside a stopped pmmcp-qdrant: nothing was asked (not_running), and the cutover is still not offered again.
    [
      'a prekey kept, Qdrant stopped',
      edit(edit(edit(keyless(), 'container.state', 'stopped'), 'verdict', 'not_running'), 'prekey_kept', true),
      /^pmmcp-qdrant-prekey is kept from an earlier cutover, and Qdrant's verdict is not_running, so the cutover is not offered again/,
    ],
    ['a key set but not enforced', edit(qdrantDoc(), 'verdict', 'inconsistent'), /^pmmcp-qdrant has a key, but its verdict is inconsistent/],
    ['a key state that cannot be read', edit(keyless(), 'container.key_set', null), /^whether pmmcp-qdrant has a key could not be read, and its verdict is not_asked/],
    ['an unusable key file', edit(keyless(), 'key_file', { state: 'unusable', reason: 'mode 0644' }), /qdrant_api_key is unusable \(mode 0644\)/],
  ]
  for (const [what, q, note] of notOffered) {
    const p = qdrantPlan(q)
    assert.deepEqual(p.offers, [], what)
    assert.equal(p.steps.some((s) => s.id === 'qdrant-enable'), false, what)
    if (note.source !== '^$') assert.ok(has(p.blocked, note), `${what}: ${p.blocked.join('\n')}`)
  }
  // Enforced, with the prekey still kept: its cleanup is offered, default no, and touches nothing that runs.
  const kept = qdrantPlan(edit(qdrantDoc(), 'prekey_kept', true))
  assert.deepEqual(offerIds(kept), ['qdrant-cleanup'])
  assert.deepEqual(kept.offers[0], {
    id: 'qdrant-cleanup',
    question: 'Remove the kept pmmcp-qdrant-prekey now (qdrant_api_key.py cleanup: its volumes stay, and the cutover can no longer be rolled back)? [y/N]',
    impliedByWindow: false,
    requires: undefined,
    live: false,
  })
  const cleanup = kept.steps.find((s) => s.id === 'qdrant-cleanup')
  assert.ok(cleanup !== undefined)
  assert.deepEqual(ids(kept.steps), ['qdrant-cleanup'], 'no window: nothing live')
  assert.deepEqual([kept.notes, kept.blocked], [[], []], 'offered, so nothing else is said of it')
  assert.equal(cleanup.tag, 'pmmcp-docker')
  assert.deepEqual(cleanup.commands, [`${DIR}/.venv/bin/python scripts/qdrant_api_key.py cleanup`])
  assert.equal(cleanup.rollback, undefined)
  assert.ok(has(describe(kept), /^ {2}1\. \[pmmcp's Docker, not the running service\] remove pmmcp-qdrant-prekey, .*\(if you answer yes to "Remove the kept pmmcp-qdrant-prekey now/))
  assert.deepEqual(select(kept, new Set<OfferId>(['qdrant-cleanup'])), { nonLive: [cleanup], live: [] })
  assert.deepEqual(select(kept, new Set()), { nonLive: [], live: [] })
  // A yes, then the non-live question; no typed confirmation, no jobs count.
  const yes = new FakeIO()
  assert.deepEqual(await gate(kept, yes), { kind: 'done', applied: ['non-live'], exitCode: 0 })
  assert.deepEqual(yes.events, [`ask ${kept.offers[0]?.question ?? ''}`, 'ask Apply the non-live step 1 now? [y/N]', 'apply non-live'])
  assert.deepEqual(yes.applied, [{ phase: 'non-live', steps: ['qdrant-cleanup'] }])
  const no = new FakeIO({ answers: [[/^Remove the kept/, 'n']] })
  assert.deepEqual(await gate(kept, no), { kind: 'declined', at: 'offer', applied: [], exitCode: 0 })
  assert.equal(no.events.some((e) => e.startsWith('apply')), false)
  // Not live, so offered when the jobs check cannot run; and it opens no window, so a restart beside it is still asked.
  const blind = factsDoc()
  edit(blind, 'features.stop_jobs_flag', false)
  assert.deepEqual(offerIds(qdrantPlan(edit(qdrantDoc(), 'prekey_kept', true), blind)), ['qdrant-cleanup'])
  const withRestart = planInstall(
    input({ config: DECLARED, dotenv: FULL, pmmcp: found({ qdrant: edit(qdrantDoc(), 'prekey_kept', true), bearer: { state: 'matches' }, server: { pid: 812, startedAfter: STARTED_BEFORE } }) }),
  )
  assert.deepEqual(offerIds(withRestart), ['qdrant-cleanup', 'restart'])
  const both = new FakeIO()
  assert.deepEqual(await gate(withRestart, both), { kind: 'done', applied: ['non-live', 'live'], exitCode: 0 })
  assert.ok(both.events.includes('ask Restart pmmcp to load the staged aos-kernel token? [y/N]'), both.events.join('\n'))
  assert.deepEqual(both.applied, [
    { phase: 'non-live', steps: ['qdrant-cleanup'] },
    { phase: 'live', steps: ['stop', 'start', 'bearer-check'] },
  ])
  // A checkout without the script that removes it: named, not offered.
  const noScript = factsDoc()
  edit(noScript, 'features.qdrant_key_script', false)
  const stuck = qdrantPlan(edit(qdrantDoc(), 'prekey_kept', true), noScript)
  assert.deepEqual(stuck.offers, [])
  assert.ok(has(stuck.notes, /^pmmcp-qdrant-prekey is kept from the cutover, and pmmcp lacks the Qdrant API key script \(0b6c7e2\), which removes it/), stuck.notes.join('\n'))
  // A keyless container on a checkout without the cutover script.
  const old = factsDoc()
  edit(old, 'features.qdrant_key_script', false)
  assert.deepEqual(qdrantPlan(keyless(), old).offers, [])
})

test('dashboard and curator secrets are offered only when pmmcp has the auth CLI', () => {
  const authPlan = (facts: Doc): Plan => planInstall(input({ pmmcp: found({ facts }) }))
  const absent = (doc: Doc, ...files: string[]): Doc => {
    for (const f of files) edit(doc, `${f}.state`, 'absent')
    return doc
  }

  const both = authPlan(absent(factsDoc(), 'dashboard_token', 'curator_secret'))
  assert.deepEqual(both.offers.map((o) => o.question), ['Create the dashboard token and curator secret (live)? [y/N]'])
  const step = both.steps.find((s) => s.id === 'auth-init')
  assert.deepEqual(step?.commands, [`${DIR}/.venv/bin/python -m src.dashboard.auth init`])
  assert.equal(step?.tag, 'live')
  assert.match(step?.title ?? '', /^create the dashboard token and curator secret \(0600 files under ~\/\.persistent-memory-mcp, made by pmmcp's own CLI; pmmcp reads them per request, and the installer never sees them\)$/)
  assert.equal(step?.rollback, 'with pmmcp stopped, remove ~/.persistent-memory-mcp/dashboard_token and ~/.persistent-memory-mcp/curator_secret, then start it')
  assert.deepEqual(step?.creates, ['dashboard_token', 'curator_secret'])

  const curatorOnly = authPlan(absent(factsDoc(), 'curator_secret'))
  assert.deepEqual(curatorOnly.offers.map((o) => o.question), ['Create the curator secret (live)? [y/N]'])
  const curatorStep = curatorOnly.steps.find((s) => s.id === 'auth-init')
  assert.deepEqual(curatorStep?.commands, [`${DIR}/.venv/bin/python -m src.dashboard.auth init --only curator`])
  assert.match(curatorStep?.title ?? '', /^create the curator secret \(0600 file under ~\/\.persistent-memory-mcp, made by pmmcp's own CLI; pmmcp reads it per request, and the installer never sees it\)$/)
  assert.equal(curatorStep?.rollback, 'with pmmcp stopped, remove ~/.persistent-memory-mcp/curator_secret, then start it')

  // Before 25d4a26 there is no auth CLI at all (nor anything added after it).
  const noCli = absent(factsDoc(), 'dashboard_token', 'curator_secret')
  for (const f of ['dashboard_auth', 'curator_secret', 'curator_proof', 'stop_listener_check']) edit(noCli, `features.${f}`, false)
  const none = authPlan(noCli)
  assert.deepEqual(none.offers, [])
  assert.equal(none.steps.some((s) => s.id === 'auth-init'), false)
  assert.ok(has(none.notes, new RegExp(`^the dashboard token and curator secret: update pmmcp first: its code lacks the dashboard token \\(${FEATURE_COMMITS.dashboard_auth}\\)`)), none.notes.join('\n'))

  // Each flag counts on its own: a document with curator_proof but not the curator_secret flag offers no curator secret.
  const noSecretFlag = absent(factsDoc(), 'curator_secret')
  edit(noSecretFlag, 'features.curator_secret', false)
  assert.deepEqual(authPlan(noSecretFlag).offers, [])
  assert.ok(has(authPlan(noSecretFlag).notes, /^the curator secret: update pmmcp first: its code lacks the curator secret \(25d4a26\)$/))

  // Both in place: nothing.
  assert.equal(nothingToDo(authPlan(factsDoc())), true)
})

test("a legacy dashboard.token in config.yaml: the step that makes the token file says the file replaces it, and a note says to remove it", async () => {
  // pmmcp's access_control.md: the file wins over config.yaml's dashboard.token, which counts only while no file has been seen.
  const legacy = (doc: Doc = factsDoc()): Doc => edit(doc, 'config.dashboard.legacy_token_key', true)
  const REPLACES = "; the dashboard token file replaces config.yaml's legacy dashboard.token, so a client that sends that token gets 401 once the file exists"
  const REMOVE_THEN =
    '/Users/op/.persistent-memory-mcp/config.yaml holds the legacy dashboard.token: once ~/.persistent-memory-mcp/dashboard_token exists it replaces that token ' +
    '(a client that sends it gets 401), so remove dashboard.token from it then'

  const dash = planInstall(input({ pmmcp: found({ facts: edit(legacy(), 'dashboard_token', { state: 'absent' }) }) }))
  assert.deepEqual(offerIds(dash), ['auth'])
  const step = dash.steps.find((s) => s.id === 'auth-init')
  assert.ok(step !== undefined)
  assert.ok(step.title.endsWith(REPLACES), step.title)
  assert.ok(dash.notes.includes(REMOVE_THEN), dash.notes.join('\n'))
  assert.equal(dash.blocked.includes(REMOVE_THEN), false, "removing it is the operator's, and nothing the installer makes")
  // The S6 warning lists it with the item, before the first confirmation.
  const io = new FakeIO()
  assert.equal((await gate(dash, io)).kind, 'done')
  const listed = io.transcript.findIndex((e) => e.startsWith('print   - create the dashboard token') && e.includes(REPLACES))
  assert.ok(listed >= 0 && listed < io.transcript.indexOf(`ask Type \`${FIRST_CONFIRMATION}\` to continue`), io.transcript.join('\n'))

  // Behind this run's update too.
  const later = dfcc99a(legacy())
  edit(later, 'dashboard_token', { state: 'absent' })
  const behind = planInstall(input({ pmmcp: found({ facts: later, git: FAST_FORWARD }) }))
  assert.deepEqual(offerIds(behind), ['update', 'auth-after-update'])
  assert.ok(behind.steps.find((s) => s.id === 'auth-init')?.title.endsWith(`, only where the updated pmmcp takes each safely${REPLACES}`), JSON.stringify(behind.steps))

  // The curator secret alone: its step says nothing of the dashboard token; the token file is there, so the note says remove it now.
  const cur = planInstall(input({ pmmcp: found({ facts: edit(legacy(), 'curator_secret', { state: 'absent' }) }) }))
  assert.equal(cur.steps.find((s) => s.id === 'auth-init')?.title.includes('legacy'), false)
  const REMOVE_NOW =
    '/Users/op/.persistent-memory-mcp/config.yaml still holds the legacy dashboard.token, which ~/.persistent-memory-mcp/dashboard_token overrides (a client that sends it gets 401): ' +
    'remove dashboard.token from it'
  assert.ok(cur.notes.includes(REMOVE_NOW), cur.notes.join('\n'))
  // Everything in place: still nothing to do, and in place, with the note above it.
  const done = planInstall(input({ pmmcp: found({ facts: legacy() }) }))
  assert.equal(nothingToDo(done), true)
  assert.deepEqual([done.notes, done.blocked], [[REMOVE_NOW], []])
  const quiet = new FakeIO()
  await gate(done, quiet)
  assert.deepEqual(quiet.printed.slice(-3), ['notes:', `  - ${REMOVE_NOW}`, 'nothing to do: everything the installer makes is in place'])

  // No legacy key: neither.
  const plain = planInstall(input({ pmmcp: found({ facts: edit(factsDoc(), 'dashboard_token', { state: 'absent' }) }) }))
  assert.equal(has(plain.notes, /legacy/), false)
  assert.equal(plain.steps.some((s) => s.title.includes('legacy')), false)
})

test('the curator secret is offered only when facts show curator_proof; without it neither file, "update pmmcp first", unless this run\'s update brings them', async () => {
  // dfcc99a: curator_secret and dashboard_auth, but neither curator_proof nor stop_listener_check.
  const old = (): Doc => {
    const doc = dfcc99a(factsDoc())
    edit(doc, 'dashboard_token', { state: 'absent' })
    edit(doc, 'curator_secret', { state: 'absent' })
    return doc
  }
  const stuck = planInstall(input({ pmmcp: found({ facts: old() }) }))
  assert.equal(stuck.steps.some((s) => s.id === 'auth-init'), false)
  assert.deepEqual(stuck.offers, [], 'no update to bring them, so nothing is offered')
  assert.ok(has(stuck.notes, /^the dashboard token and curator secret: update pmmcp first: its code lacks .*the curator proof/), stuck.notes.join('\n'))

  // With a fast-forward there: the update is offered, and the files only "if the updated pmmcp supports them", behind it.
  const later = planInstall(input({ pmmcp: found({ facts: old(), git: FAST_FORWARD }) }))
  assert.deepEqual(offerIds(later), ['update', 'auth-after-update'])
  const offer = later.offers[1]
  assert.equal(offer?.question, 'Create the dashboard token and curator secret if the updated pmmcp supports them (live)? [y/N]')
  assert.equal(offer?.requires, 'update')
  assert.deepEqual(select(later, new Set<OfferId>(['auth-after-update'])).live, [], 'without the update it does nothing')
  const live = select(later, new Set<OfferId>(['update', 'auth-after-update'])).live
  assert.deepEqual(ids(live), ['stop', 'update', 'auth-init', 'start'])
  assert.equal(live.find((s) => s.id === 'auth-init')?.afterUpdate, true)
  // Declining the update: the files are not asked about at all.
  const io = new FakeIO({ answers: [[/^Update pmmcp/, 'n']] })
  assert.equal((await gate(later, io)).kind, 'declined')
  assert.equal(io.asked.some((q) => q.includes('if the updated pmmcp supports them')), false)
  assert.equal(io.events.some((e) => e.startsWith('apply')), false)

  // A stop script that checks its listener, without the curator proof: the dashboard token alone.
  const half = old()
  edit(half, 'features.stop_listener_check', true)
  const dash = planInstall(input({ pmmcp: found({ facts: half }) }))
  assert.deepEqual(dash.offers.map((o) => o.question), ['Create the dashboard token (live)? [y/N]'])
  assert.deepEqual(dash.steps.find((s) => s.id === 'auth-init')?.commands, [`${DIR}/.venv/bin/python -m src.dashboard.auth init --only dashboard`])
  assert.ok(has(dash.notes, /^the curator secret: update pmmcp first: its code lacks the curator proof/), dash.notes.join('\n'))

  // e6516d5: both.
  const current = factsDoc()
  edit(current, 'dashboard_token', { state: 'absent' })
  edit(current, 'curator_secret', { state: 'absent' })
  assert.deepEqual(planInstall(input({ pmmcp: found({ facts: current }) })).offers.map((o) => o.question), ['Create the dashboard token and curator secret (live)? [y/N]'])
})

test('generate holds only the names the config maps to installer-made tokens: ANTHROPIC_API_KEY is never generated, whatever is missing', (t) => {
  assert.deepEqual([...credentialsMap(SHIPPED).values()], [{ name: 'AOS_CONTROL_TOKEN', from: 'control.tokenEnv', client: undefined }])
  // Another MCP server's bearer is a credential its service issues: never in the map.
  const withGithub = declaring('AOS_PMMCP_TOKEN', { github: { url: 'http://127.0.0.1:9999/mcp', tokenEnv: 'GITHUB_TOKEN' } })
  assert.deepEqual([...credentialsMap(withGithub).values()], [
    { name: 'AOS_CONTROL_TOKEN', from: 'control.tokenEnv', client: undefined },
    { name: 'AOS_PMMCP_TOKEN', from: 'mcp.servers.pmmcp.tokenEnv', client: 'aos-kernel' },
  ])

  // Everything is missing, provider keys and the other server's bearer included.
  const everything = dotenv({ AOS_CONTROL_TOKEN: 'missing', AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing', GITHUB_TOKEN: 'missing' }, false)
  const plan = planInstall(input({ config: withGithub, dotenv: everything, pmmcp: found({ bearer: { state: 'not-checked', why: 'no value yet' } }) }))
  assert.deepEqual(plan.generate, ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN'])
  assert.deepEqual([...generatorsFor(plan, () => 'x').keys()], ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN'])
  const screen = describe(plan)
  assert.ok(has(screen, /^ {2}ANTHROPIC_API_KEY +missing {2}-> add it yourself; the installer never writes it$/), screen.join('\n'))
  assert.ok(has(screen, /^ {2}GITHUB_TOKEN +missing {2}-> add it yourself/))
  assert.ok(has(screen, /^ {2}AOS_PMMCP_TOKEN +missing {2}-> will be generated \(64 hex\)$/))

  // The real writer, handed that map in a scratch repository, leaves the provider key missing.
  const repo = scratchRepo(t)
  const fresh = planInstall(inspected(repo, DECLARED, found({ bearer: { state: 'not-checked', why: 'no value yet' } })))
  appendIn(repo, generatorsFor(fresh, () => randomBytes(32).toString('hex')), DECLARED, [])
  const after = inspectIn(repo, ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY'], DECLARED)
  assert.deepEqual(after.present.map((n) => n.name), ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN'])
  assert.deepEqual(after.missing, ['ANTHROPIC_API_KEY'])

  // A config whose pmmcp tokenEnv is a provider key, or the control plane's own: refused, nothing generated for it.
  for (const [tokenEnv, refusal] of [
    ['ANTHROPIC_API_KEY', /^kernel\.yaml's mcp\.servers\.pmmcp\.tokenEnv is ANTHROPIC_API_KEY, a provider's key/],
    ['AOS_CONTROL_TOKEN', /^kernel\.yaml's mcp\.servers\.pmmcp\.tokenEnv is AOS_CONTROL_TOKEN, the control plane's own bearer/],
  ] as const) {
    const odd = planInstall(input({ config: declaring(tokenEnv), dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }) }))
    assert.ok(has(odd.stops, refusal), odd.stops.join('\n'))
    assert.deepEqual(odd.generate, ['AOS_CONTROL_TOKEN'], 'the control token alone: never the provider key')
  }
  // The screen says so on the refused name's own line, once.
  const refusedScreen = describe(planInstall(input({ config: declaring('ANTHROPIC_API_KEY'), dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, ANTHROPIC_API_KEY: 'missing' }) })))
  assert.deepEqual(
    refusedScreen.filter((l) => /^ {2}ANTHROPIC_API_KEY /.test(l)),
    ['  ANTHROPIC_API_KEY    refused: a provider key is yours to add'],
    refusedScreen.join('\n'),
  )
  // Any provider's key, from providers.yaml, not ANTHROPIC_API_KEY alone.
  const anthropic = PROVIDERS.entries['anthropic/claude-sonnet-5']
  assert.ok(anthropic !== undefined)
  const withOpenRouter: PlanInput['providers'] = { entries: { ...PROVIDERS.entries, 'openrouter/some-model': { ...anthropic, auth: { ...anthropic.auth, envVar: 'OPENROUTER_API_KEY' } } } }
  const openrouter = planInstall(
    input({ config: declaring('OPENROUTER_API_KEY'), providers: withOpenRouter, dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', OPENROUTER_API_KEY: 'missing', ANTHROPIC_API_KEY: 'missing' }) }),
  )
  assert.ok(has(openrouter.stops, /^kernel\.yaml's mcp\.servers\.pmmcp\.tokenEnv is OPENROUTER_API_KEY, a provider's key, which the installer never generates/), openrouter.stops.join('\n'))
  assert.deepEqual(openrouter.generate, ['AOS_CONTROL_TOKEN'])
  assert.equal(openrouter.staged, undefined)
})

test('a caller that hands the planner less than it needs gets a PlanError, never a plan; --aos-only stages nothing', () => {
  // The screen's inspection must describe every name of the credentials map: one it skipped is a defect, not a missing name.
  assert.throws(() => planInstall(input({ dotenv: dotenv({ ANTHROPIC_API_KEY: 5 }) })), (e: unknown) => e instanceof PlanError && /does not describe AOS_CONTROL_TOKEN/.test(e.message))
  assert.throws(
    () => planInstall(input({ config: DECLARED, dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, ANTHROPIC_API_KEY: 5 }) })),
    (e: unknown) => e instanceof PlanError && /does not describe AOS_PMMCP_TOKEN/.test(e.message),
  )
  // No discovery result is --aos-only only when the operator said so.
  assert.throws(() => planInstall(input({ pmmcp: undefined })), (e: unknown) => e instanceof PlanError && /discovery found nothing and this is not --aos-only/.test(e.message))

  // --aos-only: the token is appended or kept, and no digest is staged, from either source.
  const aosOnly = { aosOnly: true, noInstall: false } as const
  const appended = planInstall(input({ config: DECLARED, dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 5 }), pmmcp: undefined, options: aosOnly }))
  assert.equal(appended.kind, 'aos-only')
  assert.deepEqual(appended.generate, ['AOS_PMMCP_TOKEN'])
  assert.deepEqual(ids(appended.steps), ['env'])
  assert.equal(appended.staged, undefined)
  assert.ok(has(appended.blocked, /^--aos-only: pmmcp is not touched, so the aos-kernel digest of AOS_PMMCP_TOKEN is not staged/), appended.blocked.join('\n'))
  const kept = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: undefined, options: aosOnly }))
  assert.equal(kept.staged, undefined)
  assert.deepEqual(kept.steps, [])
})

test('the jobs gate prompts only when something runs: running jobs: 0 goes straight on', async () => {
  const plan = planInstall(input({ pmmcp: found({ qdrant: keyless() }) }))
  assert.deepEqual(offerIds(plan), ['qdrant'])
  const FIRST = `ask Type \`${FIRST_CONFIRMATION}\` to continue`
  const SECOND = `ask Second confirmation: type the folder name \`${PMMCP_FOLDER}\` to stop it now`

  // None running: no question, no pause.
  const idle = new FakeIO({ jobs: [{ state: 'counted', running: 0, display: [] }] })
  assert.equal((await gate(plan, idle)).kind, 'done')
  assert.deepEqual(fromFirst(idle), [FIRST, 'jobs', SECOND, 'apply live'])

  // Two, then one, then none: asked once (an empty line waits), counted every 10 s.
  const busy = new FakeIO({
    answers: [[/^Wait for them/, '']],
    jobs: [
      { state: 'counted', running: 2, display: ['  j1  scrape  aos/ceo  40%', '  j2  index  aos/shared  10%'] },
      { state: 'counted', running: 1, display: ['  j1  scrape  aos/ceo  90%'] },
      { state: 'counted', running: 0, display: [] },
    ],
  })
  assert.equal((await gate(plan, busy)).kind, 'done')
  // Every 10 s, as the plan says: never a busy loop while the operator waits.
  assert.equal(JOBS_POLL_MS, 10_000)
  assert.deepEqual(fromFirst(busy), [FIRST, 'jobs', 'ask Wait for them to finish? [Y/n]', 'pause 10000', 'jobs', 'pause 10000', 'jobs', SECOND, 'apply live'])
  assert.ok(busy.printed.includes('waiting: counted again every 10 s; type q to abort (nothing is stopped yet)'), busy.printed.join('\n'))
  // The job lines as the stop script gave them, with their own indent and no more.
  assert.ok(busy.printed.includes('2 pmmcp jobs are running:') && busy.printed.includes('  j2  index  aos/shared  10%'), busy.printed.join('\n'))
  assert.equal(has(busy.printed, /^ {3}/), false, busy.printed.join('\n'))

  // n: no wait; the second confirmation still stands between it and the stop.
  const now = new FakeIO({ answers: [[/^Wait for them/, 'n']], jobs: [{ state: 'counted', running: 1, display: [] }] })
  assert.equal((await gate(plan, now)).kind, 'done')
  assert.deepEqual(fromFirst(now), [FIRST, 'jobs', 'ask Wait for them to finish? [Y/n]', SECOND, 'apply live'])
  assert.ok(has(now.printed, /^not waiting: the stop waits up to 300 s for it, then stops anyway$/))

  // q, EOF or Ctrl-C while waiting, Ctrl-C during a count, an unknown count, or one that failed: nothing is stopped.
  // A pause's answer the gate ignored would count again and find none running: the run would go on to the second confirmation.
  const thenIdle: readonly JobsAnswer[] = [{ state: 'counted', running: 1, display: [] }, { state: 'counted', running: 0, display: [] }]
  const ends: readonly [string, FakeOptions, number, string][] = [
    ['q at the wait', { jobs: thenIdle, pauses: ['quit'] }, 0, 'quit'],
    ['Ctrl-C at the wait', { jobs: thenIdle, pauses: ['interrupt'] }, 130, 'interrupt'],
    ['EOF at the wait', { jobs: thenIdle, pauses: ['eof'] }, 130, 'eof'],
    ['EOF at the wait question', { jobs: thenIdle, answers: [[/^Wait for them/, { kind: 'eof' }]] }, 130, 'eof'],
    ['Ctrl-C during the count', { jobs: [{ state: 'interrupt' }] }, 130, 'interrupt'],
    ['Ctrl-C during a later count', { jobs: [{ state: 'counted', running: 1, display: [] }, { state: 'interrupt' }] }, 130, 'interrupt'],
    ['unknown', { jobs: [{ state: 'unknown', stderr: ["the listener on 8765 is not this checkout's dashboard, so nothing was sent"] }] }, 1, 'jobs'],
    ['failed', { jobs: [{ state: 'failed', why: 'stop-pmmcp-server.sh --jobs gave no count (exit 2)', stderr: ['registry.db: the config cannot be read'] }] }, 1, 'jobs'],
  ]
  for (const [what, options, exitCode, by] of ends) {
    const io = new FakeIO(options)
    const outcome = await gate(plan, io)
    assert.equal(outcome.kind, 'aborted', what)
    assert.equal(outcome.exitCode, exitCode, what)
    assert.ok(outcome.kind === 'aborted' && outcome.by === by && outcome.at === 'jobs', `${what}: ${JSON.stringify(outcome)}`)
    assert.equal(io.events.includes(SECOND), false, `${what}: no second confirmation`)
    assert.equal(io.events.includes('apply live'), false, `${what}: nothing is stopped`)
    // Its stderr is shown, whichever way the count gave none.
    if (what === 'unknown') assert.ok(io.printed.includes("  the listener on 8765 is not this checkout's dashboard, so nothing was sent"), io.printed.join('\n'))
    if (what === 'failed') {
      assert.ok(io.printed.includes('stop-pmmcp-server.sh --jobs gave no count (stop-pmmcp-server.sh --jobs gave no count (exit 2)), so nothing was stopped:'), io.printed.join('\n'))
      assert.ok(io.printed.includes('  registry.db: the config cannot be read'), io.printed.join('\n'))
    }
    if (what.startsWith('Ctrl-C during')) assert.equal(io.printed.at(-1), 'interrupted while counting the jobs: nothing was stopped', what)
  }

  // A stop script that cannot count jobs: nothing live is offered at all.
  const noJobs = factsDoc()
  edit(noJobs, 'features.stop_jobs_flag', false)
  const blind = planInstall(input({ pmmcp: found({ facts: noJobs, qdrant: keyless() }) }))
  assert.deepEqual(blind.offers, [])
  assert.deepEqual(blind.jobsGate.available, false)
  assert.ok(has(blind.notes, /^not offered: Enable the Qdrant API key now \(live cutover\)\?: the stop script cannot count jobs/), blind.notes.join('\n'))
  // Nor while a dashboard token is present and the stop script does not check its listener (540bc6b to 0e8e4cc).
  const sends = factsDoc()
  edit(sends, 'features.stop_listener_check')
  const unsafe = planInstall(input({ pmmcp: found({ facts: sends, qdrant: keyless() }) }))
  assert.deepEqual(unsafe.offers, [])
  assert.ok(has(unsafe.notes, /sends the dashboard token to whatever listens on 8765/))
  // Whether or not pmmcp's MCP server runs: that stop script hands the token to whatever listens on 8765 either way.
  const down = planInstall(input({ pmmcp: found({ facts: sends, qdrant: keyless(), server: null }) }))
  assert.deepEqual(down.offers, [])
  assert.equal(down.jobsGate.available, false)
  assert.ok(has(down.blocked, /^not offered: Enable the Qdrant API key now \(live cutover\)\?: this stop script sends the dashboard token to whatever listens on 8765/), down.blocked.join('\n'))
})

test('a fresh install asks one typed install, and any other answer changes nothing', async () => {
  const absent = ABSENT
  const plan = planInstall(input({ config: DECLARED, dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }), pmmcp: absent }))
  assert.equal(plan.kind, 'fresh-install')
  assert.deepEqual(ids(plan.steps), ['env', 'clone', 'setup', 'stop', 'qdrant-init', 'stage-digest', 'start', 'bearer-check'])
  assert.deepEqual(plan.steps.map((s) => s.tag), ['aos-file', ...Array<string>(7).fill('fresh-install')])
  assert.ok(has(plan.screen, /~\/\.gemini\/config\/skills\/pmmcp-skill will be deleted/))
  // The one typed install covers the stop, so S3b says what it signals, as S6 does for an install that is there.
  assert.ok(
    plan.screen.includes(
      "What the stop signals: whatever listens on 8765, 8767 or 8766, whoever's process it is (it signals a port's listener without a command-line check, " +
        'and SIGKILLs it if the stop is interrupted), ' +
        "and the four Ollama instances on 11434-11437, including whatever answers on 11434 once the start script's PID file for it exists, which setup's launchd load can write: " +
        'your own Ollama there included.',
    ),
    plan.screen.join('\n'),
  )
  assert.equal(has(plan.notes, /Ollama/), false, 'no provider shares a port: no overlap note')
  const OVERLAP = "the stop also stops pmmcp's Ollama instances on 11434-11437, which ollama/qwen3:8b (11434) shares"
  const shared = planInstall(input({ pmmcp: { ...absent, kernel: { ollamaShared: [{ ref: 'ollama/qwen3:8b', port: 11434 }] } } }))
  assert.ok(shared.notes.includes(OVERLAP), shared.notes.join('\n'))
  // An install that is there: noted once a window is planned, and not when nothing stops.
  const ollamaShared = [{ ref: 'ollama/qwen3:8b', port: 11434 }] as const
  const window = planInstall(input({ pmmcp: found({ qdrant: keyless(), ollamaShared }) }))
  assert.deepEqual(offerIds(window), ['qdrant'])
  assert.ok(window.notes.includes(OVERLAP), window.notes.join('\n'))
  assert.equal(planInstall(input({ pmmcp: found({ ollamaShared }) })).notes.includes(OVERLAP), false, 'nothing offered, nothing stops')
  const two = planInstall(input({ pmmcp: found({ qdrant: keyless(), ollamaShared: [...ollamaShared, { ref: 'ollama/llama3', port: 11435 }] }) }))
  assert.ok(two.notes.includes("the stop also stops pmmcp's Ollama instances on 11434-11437, which ollama/qwen3:8b (11434) and ollama/llama3 (11435) share"), two.notes.join('\n'))
  // A dry run names the word it would ask for.
  const dry = new FakeIO()
  assert.deepEqual(await gate(plan, dry, true), { kind: 'dry-run', exitCode: 0 })
  assert.ok(dry.printed.includes('would ask you to type `install` before anything is installed'), dry.printed.join('\n'))
  assert.equal(has(dry.printed, /`stop pmmcp`/), false)
  assert.ok(has(describe(plan), /^pmmcp {2}not installed: a fresh install at \/Users\/op\/Github\/Persistent-Memory-MCP$/))

  const yes = new FakeIO()
  assert.deepEqual(await gate(plan, yes), { kind: 'done', applied: ['fresh-install'], exitCode: 0 })
  assert.deepEqual(yes.events, ['ask Type `install` to begin', 'apply fresh-install'])
  assert.deepEqual(yes.applied[0]?.steps, ids(plan.steps))

  // Not the word inside other text either.
  for (const answer of ['yes', 'Install', 'y', '', 'reinstall', 'install it'] as const) {
    const io = new FakeIO({ answers: [[/^Type `install`/, answer]] })
    assert.deepEqual(await gate(plan, io), { kind: 'declined', at: 'install', applied: [], exitCode: 0 })
    assert.equal(io.events.some((e) => e.startsWith('apply')), false, answer)
  }
  // --no-install: .env only, and a note.
  const noInstall = planInstall(input({ pmmcp: absent, options: { aosOnly: false, noInstall: true }, dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }) }))
  assert.equal(noInstall.kind, 'not-installed')
  assert.deepEqual(ids(noInstall.steps), ['env'])
  assert.ok(has(noInstall.notes, /--no-install offers no setup/))
})

test('the update is offered only on a clean tree whose uv.lock and pyproject.toml it leaves alone, or when the checkout lacks a feature', () => {
  // Something needs pmmcp changed (a keyless Qdrant), so the update is wanted.
  const wanted = (git: Partial<PmmcpFound['git']>): Plan => planInstall(input({ pmmcp: found({ qdrant: keyless(), git: { ...FAST_FORWARD, ...git } }) }))
  const clean = wanted({})
  assert.deepEqual(offerIds(clean), ['qdrant', 'update'])
  assert.deepEqual(clean.blocked, [])
  const refused: readonly [Partial<PmmcpFound['git']>, string][] = [
    [{ lockUnchanged: false }, "it changes uv.lock or pyproject.toml, so pmmcp's virtualenv needs uv sync by hand"],
    [{ lockUnchanged: undefined }, 'whether it changes uv.lock or pyproject.toml could not be told'],
    [{ trackedChanges: 2 }, 'the working tree has 2 tracked changes'],
    [{ trackedChanges: undefined }, 'the working tree has changes git could not count'],
    [{ untracked: 1 }, 'the working tree has 1 untracked file'],
    [{ untracked: undefined }, 'the working tree has files git could not count'],
  ]
  for (const [git, why] of refused) {
    const p = wanted(git)
    const label = JSON.stringify(git, (_k, v: unknown) => (v === undefined ? 'undefined' : v))
    assert.deepEqual(offerIds(p), ['qdrant'], label)
    assert.equal(p.steps.some((s) => s.id === 'update'), false, label)
    const note = `pmmcp can be updated to 53ea308 (origin/main as last fetched), but not by the installer: ${why}. Update it by hand with pmmcp stopped, then re-run`
    assert.ok(p.notes.includes(note), `${label}: ${p.notes.join('\n')}`)
    assert.ok(p.blocked.includes(note), `${label}: wanted, so blocked`)
  }
  // No head to go back to before the start: not offered.
  assert.deepEqual(offerIds(wanted({ head: undefined })), ['qdrant'])

  // Nothing else wanted, but the checkout lacks a feature: the update alone opens the window.
  const behind = factsDoc()
  edit(behind, 'features.qdrant_init', false)
  const update = planInstall(input({ pmmcp: found({ facts: behind, git: FAST_FORWARD }) }))
  assert.deepEqual(offerIds(update), ['update'])
  assert.deepEqual(ids(select(update, new Set<OfferId>(['update'])).live), ['stop', 'update', 'start'])
  const step = update.steps.find((s) => s.id === 'update')
  assert.deepEqual(step?.commands, [
    `git -C ${DIR} merge --ff-only ${ORIGIN_MAIN}`,
    `${DIR}/.venv/bin/python scripts/pmmcp_facts.py --json`,
    `${DIR}/.venv/bin/python -B -m src.transport.http_auth check`,
  ])
  // The way back names the full head, which a short one may not stay unique for.
  assert.equal(step?.rollback, `before the start: git -C ${DIR} reset --keep ${HEAD}`)
  // That checkout on a dirty tree: blocked, since the update was needed.
  assert.ok(has(planInstall(input({ pmmcp: found({ facts: behind, git: { ...FAST_FORWARD, untracked: 3 } }) })).blocked, /but not by the installer: the working tree has 3 untracked files/))
  // Nothing wanted and nothing missing: a dirty tree is only noted, not blocked.
  const idle = planInstall(input({ pmmcp: found({ git: { ...FAST_FORWARD, trackedChanges: 1 } }) }))
  assert.equal(nothingToDo(idle), true)
  assert.deepEqual(idle.blocked, [])
  assert.ok(has(idle.notes, /but not by the installer: the working tree has 1 tracked change\./))
})

test('a blank token line, a .env that cannot take the append and a failed aos-kernel check each stop the plan; a pmmcp without check --expect stages nothing', async () => {
  // The map's name on a line with no value: never appended again, nothing staged, refused with nothing asked.
  const blank = planInstall(
    input({
      config: DECLARED,
      dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: { blank: 4 }, ANTHROPIC_API_KEY: 5 }),
      pmmcp: found({ bearer: { state: 'not-checked', why: 'AOS_PMMCP_TOKEN holds no value in .env yet' } }),
    }),
  )
  assert.deepEqual(blank.stops, [
    '/Users/op/MrRobot/.env line 4: AOS_PMMCP_TOKEN has no value, so it is not set, and the installer never appends a name that holds a line (the file would hold it twice): ' +
      'put the value there or delete the line, then re-run',
  ])
  assert.deepEqual(blank.generate, [])
  assert.equal(blank.staged, undefined)
  assert.deepEqual(ids(blank.steps), [])
  assert.ok(has(describe(blank), /^ {2}AOS_PMMCP_TOKEN +blank \(line 4\) -> not set; fill it in or delete the line$/))
  const io = new FakeIO()
  assert.deepEqual(await gate(blank, io), { kind: 'refused', exitCode: 2 })
  assert.deepEqual(io.events, [], 'nothing is asked, counted or applied')
  assert.ok(has(io.printed, /^ {2}- \/Users\/op\/MrRobot\/\.env line 4: AOS_PMMCP_TOKEN has no value/), io.printed.join('\n'))

  // A .env the writer cannot append to, or cannot create.
  for (const exists of [true, false]) {
    const p = planInstall(input({ dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }, exists), room: { writable: false, fits: true } }))
    assert.deepEqual(
      p.stops,
      [
        exists
          ? '/Users/op/MrRobot/.env is not writable by its owner, and AOS_CONTROL_TOKEN must be appended to it: chmod 600 /Users/op/MrRobot/.env, then re-run'
          : '/Users/op/MrRobot/.env cannot be created: you cannot write /Users/op/MrRobot. Make the repository root yours and writable, then re-run',
      ],
      String(exists),
    )
    assert.deepEqual((await gate(p, new FakeIO())).exitCode, 2)
  }
  // One that would outgrow 64 KiB.
  const big = planInstall(input({ dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', ANTHROPIC_API_KEY: 5 }), room: { writable: true, fits: false } }))
  assert.deepEqual(big.stops, ['/Users/op/MrRobot/.env would be over 64 KiB with AOS_CONTROL_TOKEN appended, and the loader refuses a larger one: remove lines you no longer need, then re-run'])
  // Nothing to append: the room is not asked about.
  assert.deepEqual(planInstall(input({ room: { writable: false, fits: false } })).stops, [])

  // Discovery could not tell whether pmmcp has the digest: refused, nothing staged.
  const failed = planInstall(
    input({
      config: DECLARED,
      dotenv: FULL,
      pmmcp: found({ bearer: { state: 'failed', why: 'http_auth check --expect aos-kernel exited 2 without a verdict', stderr: ['http_auth.yaml: line 3: not a mapping'] } }),
    }),
  )
  assert.deepEqual(failed.stops, [
    "pmmcp's http_auth check --expect aos-kernel could not say whether its digest is on file: http_auth check --expect aos-kernel exited 2 without a verdict (http_auth.yaml: line 3: not a mapping). Fix what it names, then re-run",
  ])
  assert.equal(failed.staged, undefined)
  assert.equal(failed.steps.some((s) => s.id === 'stage-digest'), false)

  // A checkout with rotate --digest-stdin but no check --expect: the digest is not staged, and the commit that adds it is named.
  const old = factsDoc()
  edit(old, 'features.check_expect', false)
  const noCheck = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ facts: old, bearer: { state: 'not-checked', why: 'pmmcp has no http_auth check --expect; update it first' } }) }))
  assert.equal(noCheck.steps.some((s) => s.id === 'stage-digest'), false)
  assert.equal(noCheck.staged, undefined)
  const note = 'the aos-kernel digest of AOS_PMMCP_TOKEN is not staged: pmmcp lacks http_auth check --expect (bf63dce). Update pmmcp first, then re-run'
  assert.ok(noCheck.notes.includes(note) && noCheck.blocked.includes(note), noCheck.notes.join('\n'))
})

test('the gate itself refuses a window whose jobs check cannot run: aborted after the first confirmation, nothing counted', async () => {
  // The planner never hands the gate such a plan; one rebuilt later (A6, A7) still cannot reach a stop script without --jobs.
  const plan = planInstall(input({ pmmcp: found({ qdrant: keyless() }) }))
  assert.deepEqual(offerIds(plan), ['qdrant'])
  const blind: Plan = { ...plan, jobsGate: { available: false, why: 'the stop script cannot count jobs' } }
  const io = new FakeIO()
  assert.deepEqual(await gate(blind, io), { kind: 'aborted', at: 'jobs', by: 'jobs', applied: [], exitCode: 1 })
  assert.deepEqual(fromFirst(io), [`ask Type \`${FIRST_CONFIRMATION}\` to continue`])
  assert.equal(io.events.includes('jobs'), false, 'no count')
  assert.equal(io.events.some((e) => e.startsWith('apply')), false)
  assert.ok(io.printed.includes("pmmcp's jobs cannot be counted: the stop script cannot count jobs. Nothing was stopped"), io.printed.join('\n'))
})

test('every line the gate prints or asks is stripped of terminal control and scrubbed', async (t) => {
  const value = `pmmcp-${randomBytes(16).toString('hex')}`
  assert.ok(SecretMask.register(value))
  t.after(() => SecretMask.clear())
  const plan = planInstall(input({ pmmcp: found({ qdrant: keyless() }) }))
  const CONTROL_BYTES = /[\x00-\x08\x0a-\x1f\x7f-\x9f]/
  const clean = (io: FakeIO): void => {
    for (const line of [...io.printed, ...io.asked]) {
      assert.equal(CONTROL_BYTES.test(line), false, JSON.stringify(line))
      assert.equal(line.includes(value), false, 'a registered value is never shown')
    }
  }
  // A job's display line with a screen clear, an 8-bit CSI and a bell, and the value; and one whose CR, LF, VT and FF
  // would overwrite or break what the operator sees ("\rrunning jobs: 0" over the line before it).
  const busy = new FakeIO({
    answers: [[/^Wait for them/, 'n']],
    jobs: [{ state: 'counted', running: 2, display: [`  j1\x1b[2J  scrape \x9b31m${value}\x07`, '  j2\r\nrunning jobs: 0\v\f  index'] }],
  })
  assert.equal((await gate(plan, busy)).kind, 'done')
  clean(busy)
  assert.ok(busy.printed.includes(`  j1  scrape 31m${CENSOR}`), busy.printed.join('\n'))
  assert.ok(busy.printed.includes('  j2running jobs: 0  index'), busy.printed.join('\n'))
  // An unknown count's stderr quoting the value, with a title-setting escape, and one with CR, LF, VT and FF.
  const unknown = new FakeIO({ jobs: [{ state: 'unknown', stderr: [`registry.db: \x1b]0;owned\x07 the config names ${value}`, '\rrunning jobs: 0\n\v\f(stale)'] }] })
  assert.equal((await gate(plan, unknown)).exitCode, 1)
  clean(unknown)
  assert.ok(has(unknown.printed, new RegExp(`^ {2}registry\\.db: .*the config names \\${CENSOR.replace(']', '\\]')}$`)), unknown.printed.join('\n'))
  assert.ok(unknown.printed.includes('  running jobs: 0(stale)'), unknown.printed.join('\n'))
  // A question passes the same way: one from a plan rebuilt later (A6, A7) whose offer carries control and the value.
  const rebuilt: Plan = { ...plan, offers: plan.offers.map((o) => ({ ...o, question: `Enable the Qdrant\r\x1b[2K API key ${value}\n now (live cutover)? [y/N]` })) }
  const asks = new FakeIO({ answers: [[/^Enable the Qdrant/, 'n']] })
  assert.equal((await gate(rebuilt, asks)).kind, 'declined')
  clean(asks)
  assert.deepEqual(asks.asked, [`Enable the Qdrant API key ${CENSOR} now (live cutover)? [y/N]`])
  // The plan's own lines (a stop's stderr from discovery) pass the same way.
  const refused = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ bearer: { state: 'failed', why: 'exit 2', stderr: [`\x1b[31m${value}\x1b[0m`] } }) }))
  const io = new FakeIO()
  assert.equal((await gate(refused, io)).exitCode, 2)
  clean(io)
})

test('only y or yes is yes at a y/N offer, and only n or no skips the wait', async () => {
  const plan = planInstall(input({ pmmcp: found({ qdrant: keyless() }) }))
  for (const answer of ['y', 'Y', 'yes', 'Yes', ' YES ']) {
    const io = new FakeIO({ answers: [[/^Enable the Qdrant/, answer]] })
    assert.deepEqual(await gate(plan, io), { kind: 'done', applied: ['live'], exitCode: 0 }, JSON.stringify(answer))
  }
  for (const answer of ['n', 'no', '', 'ok', 'q', 'yes please', 'yy', 'sure']) {
    const io = new FakeIO({ answers: [[/^Enable the Qdrant/, answer]] })
    assert.deepEqual(await gate(plan, io), { kind: 'declined', at: 'offer', applied: [], exitCode: 0 }, JSON.stringify(answer))
    assert.equal(io.events.some((e) => e.startsWith('apply') || e.startsWith('ask Type')), false, JSON.stringify(answer))
  }
  // The wait defaults to waiting: only n or no goes on without it.
  const busy = (answer: string): FakeIO =>
    new FakeIO({ answers: [[/^Wait for them/, answer]], jobs: [{ state: 'counted', running: 1, display: [] }, { state: 'counted', running: 0, display: [] }] })
  for (const answer of ['n', 'no', ' N ', 'NO']) {
    const io = busy(answer)
    assert.equal((await gate(plan, io)).kind, 'done', JSON.stringify(answer))
    assert.equal(io.events.some((e) => e.startsWith('pause')), false, JSON.stringify(answer))
    assert.ok(has(io.printed, /^not waiting: /), JSON.stringify(answer))
  }
  // q is not a no: at the question it waits (the default), and only during the wait does it abort.
  for (const answer of ['', 'y', 'yes', 'Y', 'ok', 'nope', 'wait', 'q', 'Q']) {
    const io = busy(answer)
    assert.equal((await gate(plan, io)).kind, 'done', JSON.stringify(answer))
    assert.deepEqual(fromFirst(io).slice(1, 5), ['jobs', 'ask Wait for them to finish? [Y/n]', 'pause 10000', 'jobs'], JSON.stringify(answer))
    assert.equal(has(io.printed, /^not waiting/), false, JSON.stringify(answer))
  }
})

test('the stop and start run their scripts bare: no command or rollback in any plan names --force, --restart, kickstart or enforce', () => {
  const all = factsDoc()
  edit(all, 'dashboard_token', { state: 'absent' })
  edit(all, 'curator_secret', { state: 'absent' })
  edit(all, 'features.qdrant_init', false)
  const later = dfcc99a(factsDoc())
  edit(later, 'dashboard_token', { state: 'absent' })
  edit(later, 'curator_secret', { state: 'absent' })
  const freshInput = input({ config: DECLARED, dotenv: dotenv({ AOS_CONTROL_TOKEN: 'missing', AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 'missing' }), pmmcp: ABSENT })
  const plans: readonly [string, Plan][] = [
    ['every live item', planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ facts: all, qdrant: keyless(), git: FAST_FORWARD, bearer: { state: 'absent' } }) }))],
    ['after the update', planInstall(input({ pmmcp: found({ facts: later, git: FAST_FORWARD }) }))],
    ['a restart', planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ bearer: { state: 'matches' }, server: { pid: 812, startedAfter: STARTED_BEFORE } }) }))],
    ['not running', planInstall(input({ pmmcp: found({ qdrant: keyless(), server: null }) }))],
    ['the prekey', planInstall(input({ pmmcp: found({ qdrant: edit(qdrantDoc(), 'prekey_kept', true) }) }))],
    ['a fresh install', planInstall(freshInput)],
  ]
  for (const [what, plan] of plans) {
    assert.ok(plan.steps.length > 0, what)
    for (const step of plan.steps) {
      for (const text of [...step.commands, step.rollback ?? '']) assert.equal(/--force|--restart|kickstart|enforce/.test(text), false, `${what}: ${step.id}: ${text}`)
    }
    if (what === 'the prekey') continue
    assert.deepEqual(plan.steps.find((s) => s.id === 'stop')?.commands, [`${DIR}/stop-pmmcp-server.sh`], what)
    assert.deepEqual(plan.steps.find((s) => s.id === 'start')?.commands, [`${DIR}/start-pmmcp-server.sh`], what)
  }
  const [first] = plans
  assert.ok(first !== undefined)
  assert.deepEqual(ids(first[1].steps), ['stage-digest', 'stop', 'update', 'qdrant-enable', 'auth-init', 'start', 'bearer-check'])
})

test('a curator off 127.0.0.1:8767 or an unusable file is offered nothing; the TUI warning stands exactly when the curator secret is made', async () => {
  // Enabled on localhost:8767: with a secret the curator would refuse to start (exit 78), so none is offered.
  const local = factsDoc()
  edit(local, 'config.curator', { host: 'localhost', port: 8767, enabled: true })
  edit(local, 'curator_secret', { state: 'absent' })
  const wrong = planInstall(input({ pmmcp: found({ facts: local }) }))
  assert.deepEqual(wrong.offers, [])
  const bind =
    'no curator secret is offered: config.curator is localhost:8767, and with a secret the curator serves only 127.0.0.1:8767. Set curator.host to 127.0.0.1 and curator.port to 8767, then re-run'
  assert.ok(wrong.notes.includes(bind) && wrong.blocked.includes(bind), wrong.notes.join('\n'))
  // On 127.0.0.1, but another port: the curator would refuse to start with a secret just the same.
  const otherPort = factsDoc()
  edit(otherPort, 'config.curator', { host: '127.0.0.1', port: 9999, enabled: true })
  edit(otherPort, 'curator_secret', { state: 'absent' })
  const port = planInstall(input({ pmmcp: found({ facts: otherPort }) }))
  assert.deepEqual(port.offers, [])
  assert.ok(has(port.blocked, /^no curator secret is offered: config\.curator is 127\.0\.0\.1:9999, and with a secret the curator serves only 127\.0\.0\.1:8767/), port.blocked.join('\n'))
  // Behind an update: the dashboard token is offered "if the updated pmmcp supports them", never the curator secret on that bind.
  const oldBind = dfcc99a(factsDoc())
  edit(oldBind, 'config.curator', { host: 'localhost', port: 8767, enabled: true })
  edit(oldBind, 'dashboard_token', { state: 'absent' })
  edit(oldBind, 'curator_secret', { state: 'absent' })
  const behind = planInstall(input({ pmmcp: found({ facts: oldBind, git: FAST_FORWARD }) }))
  assert.deepEqual(behind.offers.map((o) => o.question), ['Update pmmcp to 53ea308 (fast-forward, inside the stopped window)? [y/N]', 'Create the dashboard token if the updated pmmcp supports them (live)? [y/N]'])
  assert.deepEqual(behind.steps.find((s) => s.id === 'auth-init')?.creates, ['dashboard_token'])
  // Disabled: nothing listens there, so any bind takes a secret.
  const off = factsDoc()
  edit(off, 'config.curator', { host: '0.0.0.0', port: 9999, enabled: false })
  edit(off, 'curator_secret', { state: 'absent' })
  assert.deepEqual(planInstall(input({ pmmcp: found({ facts: off }) })).offers.map((o) => o.question), ['Create the curator secret (live)? [y/N]'])

  // An unusable file: init exits 1 on one, so nothing is offered for it, and the fix is named.
  for (const file of ['dashboard_token', 'curator_secret'] as const) {
    const bad = factsDoc()
    edit(bad, file, { state: 'unusable' })
    const p = planInstall(input({ pmmcp: found({ facts: bad }) }))
    assert.deepEqual(p.offers, [], file)
    const note = `~/.persistent-memory-mcp/${file} is unusable: cd ${DIR} && .venv/bin/python -m src.dashboard.auth status names the rule it breaks; fix or remove it`
    assert.ok(p.notes.includes(note) && p.blocked.includes(note), p.notes.join('\n'))
  }

  // The TUI: listed by pid, and asked to quit when (and only when) the curator secret is among the live items.
  const both = factsDoc()
  edit(both, 'dashboard_token', { state: 'absent' })
  edit(both, 'curator_secret', { state: 'absent' })
  const QUIT = /^Quit any scripts\/monitor_tui\.py of \/Users\/op\/Github\/Persistent-Memory-MCP first \(pid 4242 runs now\), and start none until this run ends: /
  const withTui = planInstall(input({ pmmcp: found({ facts: both, qdrant: keyless() }), tuiPids: [4242] }))
  assert.deepEqual(offerIds(withTui), ['qdrant', 'auth'])
  const authLive = select(withTui, new Set<OfferId>(['auth'])).live
  assert.ok(has(warning(withTui, authLive), QUIT), warning(withTui, authLive).join('\n'))
  assert.ok(warning(withTui, authLive).includes('What does not stop: a scripts/monitor_tui.py of /Users/op/Github/Persistent-Memory-MCP (pid 4242 runs now).'))
  assert.equal(has(warning(withTui, select(withTui, new Set<OfferId>(['qdrant'])).live), /^Quit any/), false, 'no curator secret, no TUI line')
  const dashOnly = factsDoc()
  edit(dashOnly, 'dashboard_token', { state: 'absent' })
  const dash = planInstall(input({ pmmcp: found({ facts: dashOnly }), tuiPids: [4242] }))
  assert.equal(has(warning(dash, select(dash, new Set<OfferId>(['auth'])).live), /^Quit any/), false, 'the dashboard token alone: no TUI line')
  // None running, or two.
  const none = planInstall(input({ pmmcp: found({ facts: both }) }))
  const noneWarning = warning(none, select(none, new Set<OfferId>(['auth'])).live)
  assert.ok(noneWarning.includes('What does not stop: a scripts/monitor_tui.py of /Users/op/Github/Persistent-Memory-MCP (none runs now).'), noneWarning.join('\n'))
  assert.ok(has(noneWarning, /^Quit any scripts\/monitor_tui\.py of \/Users\/op\/Github\/Persistent-Memory-MCP first \(none runs now\)/))
  const two = planInstall(input({ pmmcp: found({ facts: both }), tuiPids: [4242, 4250] }))
  assert.ok(warning(two, []).includes('What does not stop: a scripts/monitor_tui.py of /Users/op/Github/Persistent-Memory-MCP (pids 4242 and 4250 run now).'))
  // Through the gate: before the first confirmation.
  const io = new FakeIO({ answers: [[/^Enable the Qdrant/, 'n']] })
  assert.equal((await gate(withTui, io)).kind, 'done')
  const quit = io.transcript.findIndex((e) => QUIT.test(e.replace(/^print /, '')))
  const firstAsk = io.transcript.indexOf(`ask Type \`${FIRST_CONFIRMATION}\` to continue`)
  assert.ok(quit >= 0 && quit < firstAsk, io.transcript.join('\n'))
})

test('a window opened while pmmcp is not running says, at S4, in the sequence and in the warning, that it ends by starting pmmcp', async () => {
  const plan = planInstall(input({ pmmcp: found({ qdrant: keyless(), server: null }) }))
  assert.equal(plan.running, false)
  assert.deepEqual(offerIds(plan), ['qdrant'])
  assert.ok(
    plan.notes.includes("pmmcp's MCP server is not running now: a live item below still runs the stop, for whatever else of pmmcp runs, and ends by starting pmmcp, which is then left running"),
    plan.notes.join('\n'),
  )
  const live = select(plan, new Set<OfferId>(['qdrant'])).live
  assert.deepEqual(ids(live), ['stop', 'qdrant-enable', 'start'])
  assert.match(live.at(-1)?.title ?? '', /^start pmmcp \(its MCP server is not running now: this starts pmmcp and leaves it running\): start-pmmcp-server\.sh/)
  const NOT_RUNNING =
    "pmmcp's MCP server is not running now: the stop still stops whatever else of pmmcp runs, and the window ends by starting pmmcp, which is then left running. To leave it stopped, type anything but the words asked for below."
  const SEQUENCE = 'Now: the graceful stop (stop-pmmcp-server.sh), then the Qdrant key cutover, then the start (start-pmmcp-server.sh) and its checks, which leave pmmcp running (it is not running now).'
  assert.equal(sequence(live), SEQUENCE)
  const io = new FakeIO()
  assert.deepEqual(await gate(plan, io), { kind: 'done', applied: ['live'], exitCode: 0 })
  const shownAt = io.transcript.indexOf(`print ${NOT_RUNNING}`)
  assert.ok(shownAt >= 0 && shownAt < io.transcript.indexOf(`ask Type \`${FIRST_CONFIRMATION}\` to continue`), io.transcript.join('\n'))
  assert.ok(io.printed.includes(SEQUENCE))
  // Declined at the first word: nothing starts it.
  const no = new FakeIO({ answers: [[/^Type `stop pmmcp`/, 'no']] })
  assert.equal((await gate(plan, no)).kind, 'declined')
  assert.equal(no.events.some((e) => e.startsWith('apply')), false)

  // Running: none of it.
  const up = planInstall(input({ pmmcp: found({ qdrant: keyless() }) }))
  assert.equal(up.running, true)
  assert.equal(has(up.notes, /not running/), false)
  const upLive = select(up, new Set<OfferId>(['qdrant'])).live
  assert.equal(has(warning(up, upLive), /not running/), false)
  assert.equal(sequence(upLive), 'Now: the graceful stop (stop-pmmcp-server.sh), then the Qdrant key cutover, then the start (start-pmmcp-server.sh) and its checks.')
})

test('nothing to do says everything is in place only when the plan blocks nothing; a dry run of it ends with its closing line', async () => {
  const rotate = factsDoc()
  edit(rotate, 'features.rotate_digest_stdin', false)
  const check = factsDoc()
  edit(check, 'features.check_expect', false)
  const noJobs = factsDoc()
  edit(noJobs, 'features.stop_jobs_flag', false)
  const noProof = dfcc99a(factsDoc())
  edit(noProof, 'dashboard_token', { state: 'absent' })
  edit(noProof, 'curator_secret', { state: 'absent' })
  const cases: readonly [string, Plan, boolean][] = [
    ['configured', planInstall(input()), false],
    ['the digest loaded', planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ bearer: { state: 'matches' } }) })), false],
    ['an update with nothing to bring', planInstall(input({ pmmcp: found({ git: FAST_FORWARD }) })), false],
    ['no rotate --digest-stdin', planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ facts: rotate, bearer: { state: 'absent' } }) })), true],
    ['no check --expect', planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ facts: check, bearer: { state: 'not-checked', why: 'no --expect' } }) })), true],
    ['an unusable dashboard token', planInstall(input({ pmmcp: found({ facts: edit(factsDoc(), 'dashboard_token', { state: 'unusable' }) }) })), true],
    ['an unusable curator secret', planInstall(input({ pmmcp: found({ facts: edit(factsDoc(), 'curator_secret', { state: 'unusable' }) }) })), true],
    ['update pmmcp first', planInstall(input({ pmmcp: found({ facts: noProof }) })), true],
    ['the jobs check cannot run', planInstall(input({ pmmcp: found({ facts: noJobs, qdrant: keyless() }) })), true],
    ['--aos-only, with a digest to stage', planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: undefined, options: { aosOnly: true, noInstall: false } })), true],
    // A checkout before c8bae1e (the Mac's 0b6c7e2), origin/main never fetched: nothing can be read, so nothing is known to be in place.
    ['no facts, no fast-forward', planInstall(input({ pmmcp: found({ facts: null }) })), true],
    ['no facts, a fast-forward', planInstall(input({ pmmcp: found({ facts: null, git: FAST_FORWARD }) })), true],
  ]
  for (const [what, plan, blocked] of cases) {
    assert.equal(nothingToDo(plan), true, what)
    assert.equal(plan.blocked.length > 0, blocked, `${what}: ${plan.blocked.join('\n')}`)
    for (const b of plan.blocked) assert.ok(plan.notes.includes(b), `${what}: every blocked line is a note shown above`)
    const line = blocked ? 'nothing the installer can do now: see the notes above' : 'nothing to do: everything the installer makes is in place'
    const io = new FakeIO()
    assert.deepEqual(await gate(plan, io), { kind: 'nothing-to-do', exitCode: 0 }, what)
    assert.equal(io.printed.at(-1), line, what)
    assert.equal(io.printed.includes(blocked ? 'nothing to do: everything the installer makes is in place' : 'nothing the installer can do now: see the notes above'), false, what)
    const dry = new FakeIO()
    assert.deepEqual(await gate(plan, dry, true), { kind: 'nothing-to-do', exitCode: 0 }, what)
    assert.deepEqual(dry.printed.slice(-2), [line, 'dry run: nothing was changed, nothing was stopped or started (probe output in /Users/op/MrRobot/.aos/install/20261029T090000Z)'], what)
    assert.deepEqual(dry.events, [], what)
  }

  // What the no-facts plan says, whether or not a fast-forward is there to apply.
  const NO_FACTS =
    'pmmcp lacks the facts (scripts/pmmcp_facts.py --json, c8bae1e or later), so whether the Qdrant key, the dashboard token and the curator secret are in place cannot be read, ' +
    `and its stop script cannot count jobs: fetch (cd ${DIR} && git fetch), update it by hand with pmmcp stopped, then re-run`
  const bare = planInstall(input({ pmmcp: found({ facts: null }) }))
  assert.deepEqual(bare.blocked, [NO_FACTS])
  const ahead = planInstall(input({ pmmcp: found({ facts: null, git: FAST_FORWARD }) }))
  assert.deepEqual(ahead.offers, [])
  assert.ok(ahead.blocked.includes(NO_FACTS), ahead.blocked.join('\n'))
  assert.ok(has(ahead.blocked, /^not offered: Update pmmcp to 53ea308 \(fast-forward, inside the stopped window\)\?: the stop script cannot count jobs/), ahead.blocked.join('\n'))
})

test("a jobs count that failed or said unknown in discovery offers nothing live; a stale record's not-run does not", () => {
  const failures: readonly [PmmcpFound['jobs'], string][] = [
    [
      { state: 'failed', why: 'stop-pmmcp-server.sh --jobs gave no count (exit 2)', stderr: ['registry.db: the config cannot be read'] },
      'stop-pmmcp-server.sh --jobs failed in discovery (stop-pmmcp-server.sh --jobs gave no count (exit 2)): registry.db: the config cannot be read, so the installer stops nothing: fix what it names, then re-run',
    ],
    [{ state: 'counted', jobs: { running: 'unknown' } }, 'stop-pmmcp-server.sh --jobs could not count the running jobs in discovery (running jobs: unknown), so the installer stops nothing: fix what it names, then re-run'],
  ]
  for (const [jobs, why] of failures) {
    const p = planInstall(input({ pmmcp: found({ qdrant: keyless(), jobs }) }))
    assert.deepEqual(p.offers, [], why)
    assert.deepEqual(p.steps, [], why)
    assert.deepEqual(p.jobsGate, { available: false, why })
    assert.deepEqual(p.blocked, [`not offered: Enable the Qdrant API key now (live cutover)?: ${why}`])
  }
  // Not counted because an earlier run's record was stale: the record is cleared before the window, and the gate counts then.
  const stale = planInstall(input({ pmmcp: found({ qdrant: keyless(), jobs: { state: 'not-run', why: "not counted while .aos/install/active.json holds an earlier run's record" } }) }))
  assert.deepEqual(offerIds(stale), ['qdrant'])
  assert.deepEqual(stale.jobsGate, { available: true })
  // Jobs running at discovery: offered, and the gate counts again.
  assert.deepEqual(offerIds(planInstall(input({ pmmcp: found({ qdrant: keyless(), jobs: { state: 'counted', jobs: { running: 3, display: [] } } }) }))), ['qdrant'])
})

test('every path in a command or a rollback the operator may paste is one shell word', () => {
  assert.equal(shellWord(DIR), DIR)
  assert.equal(shellWord('/Users/op/Code Projects/Persistent-Memory-MCP'), "'/Users/op/Code Projects/Persistent-Memory-MCP'")
  assert.equal(shellWord("/Users/o'p/x"), "'/Users/o'\\''p/x'")
  assert.equal(shellWord('/a/$(rm -rf ~)/b'), "'/a/$(rm -rf ~)/b'")
  assert.equal(shellWord(''), "''")
  // A leading ~ would be the shell's home, not the folder named.
  assert.equal(shellWord('~/Github/Persistent-Memory-MCP'), "'~/Github/Persistent-Memory-MCP'")

  const SPACED = '/Users/op/Code Projects/Persistent-Memory-MCP'
  const Q = `'${SPACED}'`
  const facts = factsDoc()
  edit(facts, 'dir', SPACED)
  edit(facts, 'dashboard_token', { state: 'absent' })
  edit(facts, 'curator_secret', { state: 'absent' })
  const plan = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ dir: SPACED, facts, qdrant: keyless(), git: FAST_FORWARD, bearer: { state: 'absent' } }) }))
  const step = (id: string): Step => {
    const s = plan.steps.find((x) => x.id === id)
    assert.ok(s !== undefined, id)
    return s
  }
  assert.deepEqual(step('stop').commands, [`'${SPACED}/stop-pmmcp-server.sh'`])
  assert.equal(step('stop').rollback, `cd ${Q} && ./start-pmmcp-server.sh`)
  assert.deepEqual(step('start').commands, [`'${SPACED}/start-pmmcp-server.sh'`])
  assert.equal(step('qdrant-enable').rollback, `cd ${Q} && .venv/bin/python scripts/qdrant_api_key.py rollback`)
  assert.deepEqual(step('qdrant-enable').commands, [`'${SPACED}/.venv/bin/python' scripts/qdrant_api_key.py enable --dry-run`, `'${SPACED}/.venv/bin/python' scripts/qdrant_api_key.py enable`])
  assert.equal(step('update').commands[0], `git -C ${Q} merge --ff-only ${ORIGIN_MAIN}`)
  assert.equal(step('update').rollback, `before the start: git -C ${Q} reset --keep ${HEAD}`)
  assert.equal(step('auth-init').commands[0], `'${SPACED}/.venv/bin/python' -m src.dashboard.auth init`)
  assert.equal(step('stage-digest').commands[0], `'${SPACED}/.venv/bin/python' scripts/rotate_http_auth_token.py aos-kernel --create --digest-stdin`)
  // The notes' commands too.
  const stopped = planInstall(input({ config: DECLARED, dotenv: FULL, pmmcp: found({ dir: SPACED, facts: edit(factsDoc(), 'dir', SPACED), bearer: { state: 'absent' }, server: null }) }))
  assert.ok(stopped.notes.includes(`pmmcp is not running: it loads the aos-kernel digest when it next starts (cd ${Q} && ./start-pmmcp-server.sh)`), stopped.notes.join('\n'))
  const unusable = planInstall(input({ pmmcp: found({ dir: SPACED, facts: edit(edit(factsDoc(), 'dir', SPACED), 'dashboard_token', { state: 'unusable' }) }) }))
  assert.ok(has(unusable.notes, new RegExp(`^~/\\.persistent-memory-mcp/dashboard_token is unusable: cd '${SPACED}' && \\.venv`)), unusable.notes.join('\n'))
  // A .env under such a path.
  const env = { ...dotenv({ AOS_CONTROL_TOKEN: 'missing', ANTHROPIC_API_KEY: 5 }), path: "/Users/op/My Repo's/.env" }
  assert.ok(has(planInstall(input({ dotenv: env, room: { writable: false, fits: true } })).stops, /: chmod 600 '\/Users\/op\/My Repo'\\''s\/\.env', then re-run$/))
  // A fresh install there.
  const fresh = planInstall(input({ pmmcp: { ...ABSENT, at: SPACED } }))
  assert.deepEqual(
    fresh.steps.map((s) => s.commands[0]),
    [
      `git clone ${ORIGIN} ${Q}`,
      `cd ${Q} && ./setup.sh --non-interactive </dev/null`,
      `'${SPACED}/stop-pmmcp-server.sh'`,
      `'${SPACED}/.venv/bin/python' scripts/qdrant_api_key.py init`,
      `'${SPACED}/start-pmmcp-server.sh'`,
    ],
  )
})

test('the non-live question numbers the steps it applies, as describe() shows them', () => {
  const plan = planInstall(
    input({
      config: DECLARED,
      dotenv: dotenv({ AOS_CONTROL_TOKEN: 3, AOS_PMMCP_TOKEN: 'missing', ANTHROPIC_API_KEY: 5 }),
      pmmcp: found({ qdrant: edit(qdrantDoc(), 'prekey_kept', true), bearer: { state: 'not-checked', why: 'no value yet' }, server: null }),
    }),
  )
  assert.deepEqual(ids(plan.steps), ['env', 'stage-digest', 'qdrant-cleanup'])
  const [env, stage, cleanup] = plan.steps
  assert.ok(env !== undefined && stage !== undefined && cleanup !== undefined)
  assert.deepEqual(select(plan, new Set()).nonLive, [env, stage], 'the cleanup only on a yes')
  assert.equal(nonLiveNumbers(plan, [env, stage]), 'steps 1-2')
  assert.equal(nonLiveNumbers(plan, [env, stage, cleanup]), 'steps 1-3')
  assert.equal(nonLiveNumbers(plan, [env, cleanup]), 'steps 1 and 3')
  assert.equal(nonLiveNumbers(plan, [stage]), 'step 2')
  assert.equal(nonLiveNumbers(plan, []), '')
})
