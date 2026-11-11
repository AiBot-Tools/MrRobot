// Egress plan S3 — the sandbox.exec tool, no egress yet.
//
// sandbox.exec runs one command in one container of the caller's own sandbox
// domain: the pinned image by id, the run's workspace <mountRoot>/<runId>,
// no network and no channel, and a hard wallclock that is what is left of
// the run's budget, at most sandbox.defaults.wallclockMs. It is driven here
// through the real run loop, gate, engine and approvals, against the fake
// driver (test/helpers/fake-sandbox.ts), with the shipped tool-views.yaml.
//
// The runner is not wired into bootKernel or the loop until the egress plan's
// W1, so these tests hand the loop an agent view that routes sandbox.* refs to
// it, with the run's id, agent and budget, which is what W1's wiring must hand
// it too.
//
// The falsifiers:
//
//   Leave the result untainted and a run's second exec, whose command a
//   container's output may have steered, runs with no human (invariant 3).
//   Offer or run the tool for an orchestrator, a manifest with no sandbox:,
//   or one below tier 2, and a run that should hold no container holds one.
//   Give the container the operator's cap rather than what is left of the
//   run's budget, or the reverse, and a container outlives its run, or the
//   cap kernel.yaml names never reaches the driver.
//   Ask for a channel, or a workspace other than the run's own, and a
//   container reaches what no grant gave it.
//   Start a container without a sandbox.started row, or end one without its
//   sandbox.killed row, and the log does not say what ran. Record the end of
//   a container whose docker client died with no exit status without killing
//   it by name, and the log ends a container that may still run.
//   Run an exec whose arguments the approval preview cuts, or redacts, or
//   shows with a character a screen hides, and a human approves a command
//   they never read whole.
//   Wait without bound on a kill by name, and a daemon that never answers
//   holds the run forever with no end recorded.
//   Let a long stdout fill the result, and the failure on stderr is lost;
//   count a stream's share in raw bytes, and a stream of quotes pushes
//   tool.result past the store's limit; show the end of a stream the driver
//   capped, and the credential its cut split reaches the log unredacted.
//   Redact a stream whole rather than its window, and a MiB of BEGIN lines
//   with no END holds the daemon's event loop for seconds; show a window's
//   cut side, or a key block its cut splits, and a credential reaches the log.
//   Quote a key the model sent in a refusal, or bound a failure text by raw
//   bytes, and tool.result's append throws with tool.call written.

import './helpers/guard.js'

import { test, mock, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { getEventListeners } from 'node:events'
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { AgentRegistry } from '../src/agents/registry.js'
import { mintHumanActor } from '../src/control/actor.js'
import type { KernelConfig } from '../src/config.js'
import { ConfigError, PolicyDenied } from '../src/errors.js'
import { MAX_LOGGED_OUTPUT, PAYLOAD_TEXT_BUDGET } from '../src/events/bound.js'
import { canonicalize, sha256Hex } from '../src/events/canonical.js'
import { redactString, SecretMask, TOKEN_PATTERNS } from '../src/events/redact.js'
import type { EventStore } from '../src/events/store.js'
import type { AgentView } from '../src/mcp/hub.js'
import { parseToolViews, type ToolViewsFile } from '../src/mcp/tool-views.js'
import type { ModelCard } from '../src/models/registry.js'
import { OpenAiChatAdapter } from '../src/models/openai-chat.js'
import { Router } from '../src/models/router.js'
import { Approvals } from '../src/policy/approvals.js'
import { APPROVAL_PREVIEW_BYTES, hashArgs, PolicyEngine, type GateTicket } from '../src/policy/engine.js'
import { Quarantine } from '../src/policy/quarantine.js'
import { Budget } from '../src/runtime/budget.js'
import { Lanes } from '../src/runtime/lanes.js'
import { RunLoop, type RunAgent } from '../src/runtime/loop.js'
import {
  CAPTURE_EDGE_BYTES,
  DESCRIBE_RESERVE,
  DOCKER_CLI_FAILED,
  KILL_WAIT_MS,
  MAX_EXEC_ARGS,
  MAX_EXEC_ARG_BYTES,
  MAX_EXEC_BYTES,
  PEM_BEGIN,
  PEM_END,
  SANDBOX_SERVER,
  STREAM_WINDOW_BYTES,
  SandboxTools,
  endReason,
  sandboxToolProblem,
  type SandboxCallContext,
  type SandboxToolsOptions,
} from '../src/runtime/sandbox-tools.js'
import { DockerDriver, type ChildLike } from '../src/sandbox/docker.js'
import { CAPTURE_MAX_BYTES, CONTAINER_PREFIX, type SandboxDriver, type SandboxResult, type SandboxSpec } from '../src/sandbox/driver.js'
import { fakeProvider, http, FAKE_PRICING, type RecordedRequest, type ScriptEntry, type ScriptedResponse } from './helpers/fake-provider.js'
import { fakeSandbox, type FakeSandbox, type ScriptedExit } from './helpers/fake-sandbox.js'
import { freshProbe } from './helpers/probe.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const REF = 'anthropic/claude-sonnet-5'
const KEY = 'Yt7bN3mQ9wE5rT1uI6oP2aS8dF4gH0jK'
const IMAGE = `sha256:${'ab'.repeat(32)}`
const EXEC = 'sandbox.exec'

/** The tool-views file the daemon ships: sandbox.exec is agent, write, taints. */
const SHIPPED_VIEWS = parseToolViews(parseYaml(readFileSync(join(REPO_ROOT, 'config', 'tool-views.yaml'), 'utf8')))

const CARD: ModelCard = {
  dialect: 'openai-chat',
  baseUrl: 'https://model.test',
  path: '/v1/chat/completions',
  auth: { header: 'Authorization', scheme: 'Bearer', vaultId: 'k' },
  model: 'test-model',
  local: false,
  placeholder: false,
  pricing: {
    inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
    outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
    cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
    cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
    cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
    source: 'table',
  },
  limits: { contextTokens: 100_000, maxOutputTokens: 4_096 },
  caps: {
    toolChoice: 'auto',
    parallelToolCalls: null,
    strictSchema: null,
    sampling: 'none',
    streamUsage: null,
    preserveAssistantMessage: false,
  },
  orchestrator: false,
}

/** One Chat Completions turn. */
function turn(message: unknown, finish = 'tool_calls'): ScriptedResponse {
  return http(200, {
    id: 'chatcmpl-sandbox',
    object: 'chat.completion',
    created: 1_758_000_000,
    model: 'test-model',
    choices: [{ index: 0, message, finish_reason: finish }],
    usage: { prompt_tokens: 1_000, completion_tokens: 100, total_tokens: 1_100 },
  })
}

function exec(command: readonly string[], id = 'call_1'): ScriptedResponse {
  return turn({
    role: 'assistant',
    content: null,
    tool_calls: [{ id, type: 'function', function: { name: 'sandbox__exec', arguments: JSON.stringify({ command }) } }],
  })
}

const done = (text = 'all finished'): ScriptedResponse => turn({ role: 'assistant', content: text }, 'stop')

/** A manifest, with the parts these tests vary. */
function manifest(
  id: string,
  over: {
    role?: 'worker' | 'orchestrator'
    tier?: number
    sandbox?: 'trusted' | 'hostile' | 'none'
    kind?: 'standard' | 'template'
    allow?: readonly string[]
  } = {},
): string {
  const sandbox = over.sandbox ?? 'trusted'
  return [
    `id: ${id}`,
    'version: 1',
    `kind: ${over.kind ?? 'standard'}`,
    `role: ${over.role ?? 'worker'}`,
    'soul: worker.md',
    `tier: ${String(over.tier ?? 2)}`,
    'model:',
    `  primary: ${REF}`,
    'tools:',
    `  allow: [${(over.allow ?? [EXEC]).join(', ')}]`,
    ...(sandbox === 'none' ? [] : ['sandbox:', `  domain: ${sandbox}`]),
    'memory:',
    `  projectId: aos/agent/${id}`,
    '',
  ].join('\n')
}

function agentsDir(t: TestContext, files: Record<string, string>): string {
  const dir = join(tmpdir(t), 'agents')
  for (const [id, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, id), { recursive: true })
    writeFileSync(join(dir, id, 'agent.yaml'), yaml)
  }
  return dir
}

function registry(store: EventStore, views: ToolViewsFile = SHIPPED_VIEWS): AgentRegistry {
  return new AgentRegistry({
    providers: new Set([REF]),
    toolViews: views,
    store,
    budgets: { defaultRunMicroUsd: 2_000_000, defaultWallclockMs: 600_000, maxLlmCallsPerRun: 50, maxToolCallsPerRun: 100 },
    egressBindings: {},
  })
}

type SandboxConfig = Pick<KernelConfig['sandbox'], 'imageId' | 'domains' | 'defaults'>

/** kernel.yaml's sandbox block, with each domain's mountRoot made under the test's own directory. */
function sandboxConfig(t: TestContext, over: { wallclockMs?: number; imageId?: string | undefined } = {}): SandboxConfig {
  const root = tmpdir(t)
  const trusted = join(root, 'trusted')
  const hostile = join(root, 'hostile')
  mkdirSync(trusted)
  mkdirSync(hostile)
  return {
    ...('imageId' in over ? (over.imageId === undefined ? {} : { imageId: over.imageId }) : { imageId: IMAGE }),
    domains: {
      trusted: { dockerHost: 'unix:///nowhere/trusted.sock', network: 'aos-trusted', mountRoot: trusted },
      hostile: { dockerHost: 'unix:///nowhere/hostile.sock', network: 'aos-hostile', mountRoot: hostile },
    },
    defaults: { user: '65534:65534', pidsLimit: 256, memory: '2g', cpus: 2, wallclockMs: over.wallclockMs ?? 120_000 },
  }
}

/**
 * The agent view a loop is handed: sandbox.* refs to the runner, with the
 * run's id, agent and budget, and nothing else. What W1 wires.
 */
function sandboxView(tools: SandboxTools, contextOf: (runId: string) => SandboxCallContext): () => AgentView {
  return () => ({
    tools: tools.schemas(),
    call: (ticket, args) => {
      if (!tools.isSandboxRef(ticket.toolRef)) throw new Error(`test view: no tool ${ticket.toolRef}`)
      return tools.call(ticket, args, contextOf(ticket.runId))
    },
  })
}

interface Wired {
  readonly store: EventStore
  readonly loop: RunLoop
  readonly driver: FakeSandbox
  readonly approvals: Approvals
  readonly provider: ReturnType<typeof fakeProvider>
  readonly budget: Budget
  readonly sandbox: SandboxConfig
  readonly agents: AgentRegistry
  agent(id: string): RunAgent
  advance(ms: number): void
}

function wire(
  t: TestContext,
  options: {
    script: readonly ScriptEntry[]
    exits: readonly ScriptedExit[]
    files?: Record<string, string>
    views?: ToolViewsFile
    wallclockMs?: number
    budgetMs?: number
    approvalWaitMs?: number
  },
): Wired {
  const store = withStore(t)
  const views = options.views ?? SHIPPED_VIEWS
  const agents = registry(store, views)
  agents.load(agentsDir(t, options.files ?? { coder: manifest('coder') }))
  const driver = fakeSandbox({ imageId: IMAGE, script: options.exits })
  const sandbox = sandboxConfig(t, options.wallclockMs === undefined ? {} : { wallclockMs: options.wallclockMs })
  const tools = new SandboxTools({ store, views, driver, agents, sandbox })

  const provider = fakeProvider(options.script)
  const router = new Router({
    store,
    cards: new Map([[REF, CARD]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve(KEY),
    maxRetries: 0,
    adapters: { 'openai-chat': new OpenAiChatAdapter() },
    fetch: provider.fetch,
  })
  const approvals = new Approvals({ waitMs: options.approvalWaitMs ?? 300_000 })
  const engine = new PolicyEngine({ store, approvals })
  const quarantine = new Quarantine({ store })

  let clock = 5_000_000
  const budget = new Budget(
    { usdMax: 1_000_000, maxLlmCalls: 20, maxToolCalls: 20, wallclockMs: options.budgetMs ?? 600_000 },
    { now: () => clock },
  )
  const runAgent = (id: string): RunAgent => {
    const m = agents.get(id)?.manifest
    assert.ok(m, `no agent ${id}`)
    return {
      agentId: m.id,
      tier: m.tier,
      lane: 'subagent',
      model: m.model,
      toolAllow: m.tools.allow,
      system: 'you are a test agent',
      projectId: m.memory.projectId,
      role: m.role,
    }
  }
  // One run at a time in these tests: its agent is the one the run was started for.
  let runningAs = 'coder'
  const loop = new RunLoop({
    store,
    lanes: new Lanes({ main: 4, subagent: 8 }),
    router,
    engine,
    quarantine,
    views,
    agentView: sandboxView(tools, (runId) => ({ runId, agentId: runningAs, budget })),
    budgetFor: () => budget,
  })
  const start = loop.start.bind(loop)
  loop.start = (request) => {
    runningAs = request.agent.agentId
    return start(request)
  }
  return {
    store,
    loop,
    driver,
    approvals,
    provider,
    budget,
    sandbox,
    agents,
    agent: runAgent,
    advance(ms) {
      clock += ms
    },
  }
}

/** Event types from run.queued onward: registration rows precede it. */
function types(store: EventStore): string[] {
  const all = store.query().map((r) => r.type)
  return all.slice(all.indexOf('run.queued'))
}

function payloads(store: EventStore, type: string): Record<string, unknown>[] {
  return store.query({ type }).map((r) => JSON.parse(r.payload) as Record<string, unknown>)
}

/** The tool names a provider request offered the model. */
function offered(request: RecordedRequest | undefined): string[] {
  const body = request?.body as { tools?: { function: { name: string } }[] } | undefined
  return (body?.tools ?? []).map((tool) => tool.function.name)
}

/** The tool messages a provider request carried back to the model. */
function toolMessages(request: RecordedRequest | undefined): string[] {
  const body = request?.body as { messages?: { role: string; content: unknown }[] } | undefined
  return (body?.messages ?? []).filter((m) => m.role === 'tool').map((m) => String(m.content))
}

// ── the acceptance tests ────────────────────────────────────────────────────

test('exec runs one container, logs sandbox.started and sandbox.killed, and taints the run', async (t) => {
  const w = wire(t, {
    script: [exec(['node', '--version']), done()],
    exits: [{ stdout: 'v24.15.0\n', stderr: '', durationMs: 7 }],
  })

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent('coder'), prompt: 'which node?' })

  assert.equal(out.status, 'ok', String(out.reason))
  // The run is tainted by what the container printed.
  assert.equal(out.taint, 'tainted')

  // One container, on the manifest's domain, of the pinned image by id, in
  // the run's own workspace, with no channel: no -i, no egress.
  assert.equal(w.driver.specs.length, 1)
  const spec = w.driver.specs[0]!
  const workspace = join(w.sandbox.domains.trusted.mountRoot, 'run_1')
  assert.deepEqual(spec, {
    name: `${CONTAINER_PREFIX}run_1-1`,
    runId: 'run_1',
    agentId: 'coder',
    domain: 'trusted',
    image: IMAGE,
    command: ['node', '--version'],
    workspace,
    // The caps kernel.yaml names; the wallclock is defaults.wallclockMs,
    // below the run's 600 000 ms left.
    limits: { memoryMb: 2048, cpus: 2, pids: 256, wallclockMs: 120_000 },
  })
  assert.equal('channel' in spec, false, 'an exec asks for no channel')
  assert.equal(w.driver.channels.length, 0)
  // Made by the runner, as a directory only the operator reads.
  const made = lstatSync(workspace)
  assert.ok(made.isDirectory() && !made.isSymbolicLink())
  assert.equal(statSync(workspace).mode & 0o777, 0o700)

  // tool.call before the container, sandbox.started once it has started,
  // sandbox.killed once it has ended, tool.result after.
  assert.deepEqual(types(w.store), [
    'run.queued',
    'run.started',
    'llm.request',
    'llm.response',
    'tool.gate',
    'tool.call',
    'sandbox.started',
    'sandbox.killed',
    'tool.result',
    'llm.request',
    'llm.response',
    'run.finished',
  ])
  assert.deepEqual(payloads(w.store, 'sandbox.started'), [
    {
      schemaVersion: 1,
      sandboxId: `${CONTAINER_PREFIX}run_1-1`,
      driver: 'fake',
      domain: 'trusted',
      image: IMAGE,
      memoryMb: 2048,
      pids: 256,
      wallclockMs: 120_000,
    },
  ])
  assert.deepEqual(payloads(w.store, 'sandbox.killed'), [
    { schemaVersion: 1, sandboxId: `${CONTAINER_PREFIX}run_1-1`, reason: 'exited', exitCode: 0 },
  ])
  for (const type of ['sandbox.started', 'sandbox.killed', 'tool.call', 'tool.result']) {
    const [row] = w.store.query({ type })
    assert.equal(row?.runId, 'run_1', type)
    assert.equal(row?.agentId, 'coder', type)
  }
  // The gate allowed the first exec of a clean run: write risk, no taint yet.
  assert.deepEqual(
    payloads(w.store, 'tool.gate').map((g) => [g.decision, g.risk, g.taint]),
    [['allow', 'write', 'clean']],
  )

  // What the model read is what the log stores.
  const [result] = payloads(w.store, 'tool.result')
  assert.equal(result?.ok, true)
  assert.equal(
    String(result?.text),
    'aos-run-run_1-1 on the trusted domain, no network, exited 0 after 7 ms\n--- stdout (9 bytes) ---\nv24.15.0\n\n--- stderr (0 bytes) ---\n',
  )
  assert.equal(result?.truncated, false)
  // A container that exited with a status is not killed by name.
  assert.deepEqual(w.driver.kills, [])
  assert.deepEqual(toolMessages(w.provider.requests[1]), [String(result?.text)])
  // Offered to the worker whose manifest lists it, under its provider name.
  assert.deepEqual(offered(w.provider.requests[0]), ['sandbox__exec'])
})

test('a second exec on the tainted run waits for a human', async (t) => {
  for (const decision of ['approved', 'denied'] as const) {
    await t.test(decision, async (t) => {
      const w = wire(t, {
        script: [exec(['git', 'clone', 'x']), exec(['node', '--test'], 'call_2'), done()],
        exits: [{ stdout: 'cloned\n' }, { stdout: 'ok 1\n' }],
      })
      // At the moment the human is asked, only the first container has run.
      let specsWhenAsked: number | undefined
      w.store.subscribe((row) => {
        if (row.type !== 'approval.requested') return
        specsWhenAsked = w.driver.specs.length
        const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
        queueMicrotask(() => {
          w.approvals.resolve(id, mintHumanActor('conn-test'), decision)
        })
      })

      const out = await w.loop.start({ runId: 'run_2', agent: w.agent('coder'), prompt: 'clone and test' })

      assert.equal(out.status, 'ok', String(out.reason))
      assert.equal(out.taint, 'tainted')
      assert.equal(specsWhenAsked, 1, 'the second exec waited for the human with one container run')
      const gates = payloads(w.store, 'tool.gate')
      assert.deepEqual(gates.map((g) => [g.decision, g.taint]), [['allow', 'clean'], ['needs-human', 'tainted']])
      assert.match(String(gates[1]?.reason), /run run_2 is tainted and sandbox\.exec is a write tool/)
      const [asked] = payloads(w.store, 'approval.requested')
      assert.equal(asked?.toolRef, EXEC)
      assert.equal(asked?.risk, 'write')
      assert.equal(asked?.argsPreview, '{"command":["node","--test"]}')
      assert.equal(w.store.query({ type: 'run.parked' }).length, 1)
      assert.equal(w.store.query({ type: 'run.resumed' }).length, 1)

      if (decision === 'approved') {
        assert.deepEqual(w.driver.specs.map((s) => [s.name, s.workspace]), [
          [`${CONTAINER_PREFIX}run_2-1`, join(w.sandbox.domains.trusted.mountRoot, 'run_2')],
          [`${CONTAINER_PREFIX}run_2-2`, join(w.sandbox.domains.trusted.mountRoot, 'run_2')],
        ])
        assert.equal(w.store.query({ type: 'sandbox.started' }).length, 2)
        assert.equal(w.store.query({ type: 'sandbox.killed' }).length, 2)
      } else {
        // Denied: no second container, and the model is told.
        assert.equal(w.driver.specs.length, 1)
        assert.equal(w.store.query({ type: 'sandbox.started' }).length, 1)
        assert.deepEqual(toolMessages(w.provider.requests[2]).slice(1), ['[denied] a human denied this call'])
      }
    })
  }
})

test('a manifest without sandbox: or an orchestrator is never offered sandbox.exec', async (t) => {
  // Refused at load, the file named: no run of such a manifest lists the
  // tool, and the loop offers a run only what its manifest lists.
  const refused: readonly [string, Parameters<typeof manifest>[1], RegExp][] = [
    ['orchestrator', { role: 'orchestrator' }, /boss lists a sandbox tool, but it is role: orchestrator\. Sandbox tools are a worker's/],
    ['no sandbox: block', { sandbox: 'none' }, /boss lists a sandbox tool, but it declares no sandbox: block/],
    ['tier 1', { tier: 1 }, /boss lists a sandbox tool at tier 1, but sandbox tools need tier 2 or more/],
    ['an orchestrator with no sandbox: block', { role: 'orchestrator', sandbox: 'none' }, /it is role: orchestrator/],
  ]
  for (const [what, over, why] of refused) {
    const store = withStore(t)
    assert.throws(
      () => registry(store).load(agentsDir(t, { boss: manifest('boss', over) })),
      (e: unknown) => e instanceof ConfigError && /boss\/agent\.yaml: tools\.allow names sandbox\.exec: /.test(e.message) && why.test(e.message),
      what,
    )
    assert.equal(store.query({ type: 'agent.registered' }).length, 0, `${what}: a refused fleet left a registration`)
  }

  // Loaded without the tool, an orchestrator and an unsandboxed worker are
  // never offered it, though the agent view carries it.
  const w = wire(t, {
    script: [done(), done()],
    exits: [],
    files: {
      coder: manifest('coder'),
      boss: manifest('boss', { role: 'orchestrator', allow: [] }),
      reader: manifest('reader', { sandbox: 'none', tier: 1, allow: [] }),
    },
  })
  for (const [runId, id] of [['run_a', 'boss'], ['run_b', 'reader']] as const) {
    const out = await w.loop.start({ runId, agent: w.agent(id), prompt: 'anything' })
    assert.equal(out.status, 'ok', String(out.reason))
  }
  assert.deepEqual(w.provider.requests.map(offered), [[], []])
  assert.equal(w.driver.specs.length, 0)

  // A run whose agent claims the tool its manifest lacks (a forged RunAgent)
  // is refused at execution, before any row of the call or any container.
  const forged = wire(t, {
    script: [exec(['id'])],
    exits: [],
    files: { coder: manifest('coder'), boss: manifest('boss', { role: 'orchestrator', allow: [] }) },
  })
  const out = await forged.loop.start({
    runId: 'run_c',
    agent: { ...forged.agent('boss'), toolAllow: [EXEC] },
    prompt: 'run something',
  })
  assert.equal(out.status, 'error')
  assert.match(String(out.reason), /policy denied sandbox\.exec: boss lists a sandbox tool, but it is role: orchestrator/)
  assert.equal(forged.driver.specs.length, 0)
  assert.equal(forged.store.query({ type: 'tool.call' }).length, 0)
  assert.equal(forged.store.query({ type: 'sandbox.started' }).length, 0)
})

// ── the wallclock, the workspace and the domain ─────────────────────────────

test("a container's wallclock is what is left of the run's budget, at most sandbox.defaults.wallclockMs", async (t) => {
  // Below the cap: the run has 600 000 ms, and 590 000 have gone by the time
  // the model asks, so the container gets the 10 000 left, not the cap.
  const late = wire(t, {
    script: [
      () => {
        late.advance(590_000)
        return exec(['make'])
      },
      done(),
    ],
    exits: [{}],
    wallclockMs: 120_000,
  })
  await late.loop.start({ runId: 'run_l', agent: late.agent('coder'), prompt: 'build' })
  assert.equal(late.driver.specs[0]?.limits.wallclockMs, 10_000)
  assert.equal(payloads(late.store, 'sandbox.started')[0]?.wallclockMs, 10_000)

  // Above it: kernel.yaml's defaults.wallclockMs reaches the driver.
  const early = wire(t, { script: [exec(['make']), done()], exits: [{}], wallclockMs: 45_000 })
  await early.loop.start({ runId: 'run_e', agent: early.agent('coder'), prompt: 'build' })
  assert.equal(early.driver.specs[0]?.limits.wallclockMs, 45_000)
})

/** A ticket as the engine mints one, for a direct call of the runner. */
function ticketFor(runId: string, args: Record<string, unknown>, toolRef = EXEC): GateTicket {
  return { ticketId: 'tkt-1', runId, toolRef, argsHash: hashArgs(args), quarantine: false }
}

interface Direct {
  readonly store: EventStore
  readonly driver: FakeSandbox
  readonly tools: SandboxTools
  readonly sandbox: SandboxConfig
  readonly agents: AgentRegistry
}

function direct(
  t: TestContext,
  options: {
    exits?: readonly ScriptedExit[]
    files?: Record<string, string>
    views?: ToolViewsFile
    imageId?: string | undefined
    driverImageId?: string
  } = {},
): Direct {
  const store = withStore(t)
  const views = options.views ?? SHIPPED_VIEWS
  const agents = registry(store, views)
  agents.load(agentsDir(t, options.files ?? { coder: manifest('coder') }))
  const driver = fakeSandbox({ imageId: options.driverImageId ?? IMAGE, script: options.exits ?? [] })
  const sandbox = sandboxConfig(t, 'imageId' in options ? { imageId: options.imageId } : {})
  return { store, driver, tools: new SandboxTools({ store, views, driver, agents, sandbox }), sandbox, agents }
}

const context = (runId: string, over: Partial<SandboxCallContext> = {}): SandboxCallContext => ({
  runId,
  agentId: 'coder',
  budget: { remainingMs: () => 600_000 },
  ...over,
})

test('a hostile-domain worker runs on the hostile domain, in its mountRoot, with no channel', async (t) => {
  const d = direct(t, { exits: [{ exitCode: 3, stderr: 'boom\n' }], files: { coder: manifest('coder', { sandbox: 'hostile', tier: 3 }) } })
  const args = { command: ['sh', '-c', 'exit 3'] }
  const out = await d.tools.call(ticketFor('run_h', args), args, context('run_h'))
  assert.equal(out.ok, false)
  assert.equal(out.taints, true)
  assert.match(out.text, /on the hostile domain, no network, exited 3 after/)
  assert.match(out.text, /--- stderr \(5 bytes\) ---\nboom\n$/)
  const spec = d.driver.specs[0]
  assert.equal(spec?.domain, 'hostile')
  assert.equal(spec?.workspace, join(d.sandbox.domains.hostile.mountRoot, 'run_h'))
  assert.equal(spec !== undefined && 'channel' in spec, false)
  assert.deepEqual(payloads(d.store, 'sandbox.killed').map((p) => [p.reason, p.exitCode]), [['exited', 3]])
})

test('a run whose budget has elapsed starts no container, and a refusal before the container writes no sandbox row', async (t) => {
  const cases: readonly [string, (t: TestContext) => { d: Direct; args: Record<string, unknown>; ctx: SandboxCallContext }, RegExp][] = [
    [
      'wallclock elapsed',
      (t) => ({ d: direct(t), args: { command: ['true'] }, ctx: context('run_w', { budget: { remainingMs: () => 0 } }) }),
      /^\[refused\] the run's wallclock has elapsed; no container was started$/,
    ],
    [
      'no image pinned',
      (t) => ({ d: direct(t, { imageId: undefined }), args: { command: ['true'] }, ctx: context('run_i') }),
      /^\[refused\] sandbox\.imageId is not set in config\/kernel\.yaml/,
    ],
    [
      'arguments that are no argv',
      (t) => ({ d: direct(t), args: { command: 'rm -rf /' }, ctx: context('run_a') }),
      /^\[refused\] sandbox\.exec takes \{command: \[program, \.\.\.args\]\}: command: /,
    ],
    [
      'an empty program',
      (t) => ({ d: direct(t), args: { command: [''] }, ctx: context('run_p') }),
      /command\[0\], the program, may not be empty/,
    ],
    [
      'a key the tool does not take',
      (t) => ({ d: direct(t), args: { command: ['true'], network: 'host' }, ctx: context('run_k') }),
      /^\[refused\] sandbox\.exec takes \{command: \[program, \.\.\.args\]\}: \(arguments\): 1 key it does not take; it takes only command$/,
    ],
    [
      'a NUL in an argument',
      (t) => ({ d: direct(t), args: { command: ['echo', 'a\u0000b'] }, ctx: context('run_n') }),
      /an argument may not hold a NUL character/,
    ],
    [
      'a run already stopped',
      (t) => {
        const stopped = new AbortController()
        stopped.abort()
        return { d: direct(t), args: { command: ['true'] }, ctx: context('run_s', { signal: stopped.signal }) }
      },
      /^\[refused\] the run was stopped before the container started$/,
    ],
    [
      'a run id that is no directory name',
      (t) => ({ d: direct(t), args: { command: ['true'] }, ctx: context('../run') }),
      /^\[refused\] the run id is not one directory name/,
    ],
    [
      // Its containers' prefix, aos-run-run_1-, would be another run's too.
      'a run id with a -, which the kernel never mints',
      (t) => ({ d: direct(t), args: { command: ['true'] }, ctx: context('run_1-2') }),
      /^\[refused\] the run id is not one directory name and one container prefix/,
    ],
    [
      // A separator after the first character: <mountRoot>/run/../x is no
      // directory under the mountRoot.
      'a run id with a / after its first character',
      (t) => ({ d: direct(t), args: { command: ['true'] }, ctx: context('run/../x') }),
      /^\[refused\] the run id is not one directory name and one container prefix/,
    ],
    [
      'a run id with a . after its first character',
      (t) => ({ d: direct(t), args: { command: ['true'] }, ctx: context('run_1.2') }),
      /^\[refused\] the run id is not one directory name and one container prefix/,
    ],
    [
      'the driver refusing the spec',
      // The driver holds another image id than the kernel pins.
      (t) => ({ d: direct(t, { driverImageId: `sha256:${'cd'.repeat(32)}` }), args: { command: ['true'] }, ctx: context('run_r') }),
      /^\[refused\] docker args run image sha256:abab/,
    ],
  ]
  for (const [what, make, why] of cases) {
    await t.test(what, async (t) => {
      const { d, args, ctx } = make(t)
      const out = await d.tools.call(ticketFor(ctx.runId, args), args, ctx)
      assert.equal(out.ok, false, what)
      assert.match(out.text, why, what)
      // Still a call the log records, and still tainting.
      assert.equal(out.taints, true)
      assert.deepEqual(d.store.query().map((r) => r.type).filter((type) => type.startsWith('tool.') || type.startsWith('sandbox.')), ['tool.call', 'tool.result'])
      // The driver refused the one spec that reached it, and started nothing.
      assert.equal(d.driver.specs.length, what === 'the driver refusing the spec' ? 1 : 0, what)
    })
  }
})

test("the workspace is the run's own directory under the domain's mountRoot: made once, reused, never a link, never the mountRoot made", async (t) => {
  // Reused: a second exec of the run finds what the first left.
  const d = direct(t, { exits: [{}, {}] })
  const args = { command: ['true'] }
  await d.tools.call(ticketFor('run_x', args), args, context('run_x'))
  writeFileSync(join(d.sandbox.domains.trusted.mountRoot, 'run_x', 'left.txt'), 'kept')
  await d.tools.call(ticketFor('run_x', args), args, context('run_x'))
  assert.deepEqual(d.driver.specs.map((s) => s.workspace), [
    join(d.sandbox.domains.trusted.mountRoot, 'run_x'),
    join(d.sandbox.domains.trusted.mountRoot, 'run_x'),
  ])
  assert.equal(readFileSync(join(d.sandbox.domains.trusted.mountRoot, 'run_x', 'left.txt'), 'utf8'), 'kept')

  // A link where the workspace would be is refused, wherever it points: here
  // at another run's workspace, inside the same mountRoot.
  const linked = direct(t, { exits: [{}] })
  const root = linked.sandbox.domains.trusted.mountRoot
  mkdirSync(join(root, 'run_other'))
  symlinkSync(join(root, 'run_other'), join(root, 'run_y'))
  const refused = await linked.tools.call(ticketFor('run_y', args), args, context('run_y'))
  assert.match(refused.text, /^\[refused\] the workspace .*run_y is there and is no directory of its own$/)
  assert.equal(linked.driver.specs.length, 0)

  // A mountRoot that is not there is the VM's share missing: refused, and not made.
  const gone = direct(t, { exits: [{}] })
  const missing = join(tmpdir(t), 'no-such-root')
  const tools = new SandboxTools({
    store: gone.store,
    views: SHIPPED_VIEWS,
    driver: gone.driver,
    agents: gone.agents,
    sandbox: { ...gone.sandbox, domains: { ...gone.sandbox.domains, trusted: { ...gone.sandbox.domains.trusted, mountRoot: missing } } },
  })
  const absent = await tools.call(ticketFor('run_z', args), args, context('run_z'))
  assert.match(absent.text, /^\[refused\] the trusted domain's mountRoot .*no-such-root does not exist: it is the VM's share/)
  assert.throws(() => statSync(missing), /ENOENT/)
  assert.equal(gone.driver.specs.length, 0)
})

// ── how a container ends ────────────────────────────────────────────────────

/** Call exec on a run that hangs, and do `end` once its container has started. */
async function hung(
  t: TestContext,
  exit: ScriptedExit,
  end: (d: Direct, name: string, stop: AbortController) => void,
): Promise<{ d: Direct; out: Awaited<ReturnType<SandboxTools['call']>> }> {
  const d = direct(t, { exits: [exit] })
  const stop = new AbortController()
  d.store.subscribe((row) => {
    if (row.type !== 'sandbox.started') return
    const name = (JSON.parse(row.payload) as { sandboxId: string }).sandboxId
    queueMicrotask(() => {
      end(d, name, stop)
    })
  })
  const args = { command: ['sleep', 'infinity'] }
  const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k', { signal: stop.signal }))
  return { d, out }
}

test('a container ended by its wallclock, by the run being stopped, or outliving its wallclock is logged with that reason', async (t) => {
  const wallclock = await hung(t, { hangs: true }, (d, name) => {
    d.driver.simulateOverrun(name)
  })
  assert.equal(wallclock.out.ok, false)
  assert.match(wallclock.out.text, /was killed at its wallclock of 120000 ms \(exit 137\)/)
  assert.deepEqual(payloads(wallclock.d.store, 'sandbox.killed').map((p) => [p.reason, p.exitCode]), [['wallclock', 137]])

  // The run is stopped (the control plane's kill aborts its signal): the
  // container is killed by name, not left to its wallclock.
  const stopped = await hung(t, { hangs: true }, (_d, _name, stop) => {
    stop.abort()
  })
  assert.deepEqual(stopped.d.driver.kills, [`${CONTAINER_PREFIX}run_k-1`])
  assert.match(stopped.out.text, /was killed: the run was stopped \(exit 137\)/)
  assert.deepEqual(payloads(stopped.d.store, 'sandbox.killed').map((p) => [p.reason, p.exitCode]), [['requested', 137]])

  // The wallclock fired and its kill ended nothing; the container then
  // exited on its own. A wallclock end, which the model is told, and never ok.
  const outlived = await hung(t, { hangs: true, ignoresKill: true, exitCode: 0 }, (d, name) => {
    d.driver.simulateOverrun(name)
  })
  assert.equal(outlived.out.ok, false)
  assert.match(outlived.out.text, /outlived its wallclock of 120000 ms: the kill it was sent ended nothing, and it then exited on its own \(exit 0\)/)
  assert.deepEqual(payloads(outlived.d.store, 'sandbox.killed').map((p) => [p.reason, p.exitCode]), [['wallclock', 0]])

  // Every started row has its end, in order.
  for (const { d } of [wallclock, stopped, outlived]) {
    assert.deepEqual(
      d.store.query().map((r) => r.type).filter((type) => type.startsWith('sandbox.') || type.startsWith('tool.')),
      ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'],
    )
  }
})

test("sandbox.killed's reason reads the driver's verdict: killedBy, then overran, then a missing exit code, then exited", () => {
  const base: SandboxResult = { name: 'aos-run-x-1', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, durationMs: 1 }
  assert.equal(endReason(base), 'exited')
  assert.equal(endReason({ ...base, exitCode: 137 }), 'exited', "a 137 with no killedBy is the container's own")
  assert.equal(endReason({ ...base, exitCode: null, signal: 'SIGKILL' }), 'error')
  assert.equal(endReason({ ...base, overran: true }), 'wallclock')
  assert.equal(endReason({ ...base, exitCode: 137, signal: 'SIGKILL', killedBy: 'requested' }), 'requested')
  assert.equal(endReason({ ...base, exitCode: 137, signal: 'SIGKILL', killedBy: 'wallclock', overran: true }), 'wallclock')
})

// ── the runner's own refusals ───────────────────────────────────────────────

test('the runner refuses, before any row, a ticket for other arguments, another run or another tool, and an agent that may not hold the tool', async (t) => {
  const args = { command: ['true'] }
  const cases: readonly [string, (d: Direct) => Promise<unknown>, RegExp][] = [
    ['other arguments', (d) => d.tools.call(ticketFor('run_t', { command: ['false'] }), args, context('run_t')), /ticket argsHash does not match/],
    ['another run', (d) => d.tools.call(ticketFor('run_other', args), args, context('run_t')), /the ticket was issued for run run_other, and this call is run run_t's/],
    ['a kernel tool', (d) => d.tools.call(ticketFor('run_t', args, 'kernel.delegate'), args, context('run_t')), /not a sandbox tool/],
    ['a tool the views do not expose', (d) => d.tools.call(ticketFor('run_t', args, 'sandbox.publish'), args, context('run_t')), /exposure is kernel-only; agents may only call agent tools/],
    ['an agent the registry does not hold', (d) => d.tools.call(ticketFor('run_t', args), args, context('run_t', { agentId: 'ghost' })), /no agent ghost is registered/],
    ['an agent whose manifest lacks the tool', (d) => d.tools.call(ticketFor('run_t', args), args, context('run_t', { agentId: 'plain' })), /sandbox\.exec is not in agent plain's manifest \(default deny\)/],
    [
      'an archived agent',
      (d) => {
        d.agents.archive('coder', mintHumanActor('conn-1'))
        return d.tools.call(ticketFor('run_t', args), args, context('run_t'))
      },
      /agent coder is archived/,
    ],
  ]
  for (const [what, call, why] of cases) {
    const d = direct(t, { exits: [{}], files: { coder: manifest('coder'), plain: manifest('plain', { allow: [] }) } })
    await assert.rejects(call(d), (e: unknown) => e instanceof PolicyDenied && why.test(e.message), what)
    assert.deepEqual(
      d.store.query().map((r) => r.type).filter((type) => type.startsWith('tool.') || type.startsWith('sandbox.')),
      [],
      `${what}: a refused call left a row`,
    )
    assert.equal(d.driver.specs.length, 0, what)
  }
})

test('exec taints the run whatever tool-views.yaml says of its taint', async (t) => {
  // A views file that forgot taints: true. The runner marks its result
  // tainting regardless, and the loop reads that mark, so the second exec
  // still waits for a human.
  const views = parseToolViews({
    version: 1,
    servers: { sandbox: { default: 'kernel-only', tools: { exec: { exposure: 'agent', risk: 'write', taints: false } } } },
  })
  const w = wire(t, {
    views,
    script: [exec(['true']), exec(['true'], 'call_2'), done()],
    exits: [{}],
    approvalWaitMs: 1,
  })
  const out = await w.loop.start({ runId: 'run_v', agent: w.agent('coder'), prompt: 'twice' })
  assert.equal(out.taint, 'tainted')
  assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => g.decision), ['allow', 'needs-human'])
  // Nobody answered: the approval expired, and no second container ran.
  assert.equal(w.driver.specs.length, 1)
})

test('a tool-views file that withholds exec offers no sandbox tool, and the runner refuses it at execution', async (t) => {
  // Exposure is re-derived from the views at the offer and again at the call,
  // as the hub and the kernel's own tools do: a ticket buys nothing once the
  // file says kernel-only.
  const views = parseToolViews({
    version: 1,
    servers: { sandbox: { default: 'kernel-only', tools: { exec: { exposure: 'kernel-only', risk: 'write', taints: true } } } },
  })
  // The registry would refuse the manifest under such a file, so the agents
  // are loaded against the shipped one, and the runner reads these views.
  const d = direct(t, { exits: [{}] })
  const withheld = new SandboxTools({ store: d.store, views, driver: d.driver, agents: d.agents, sandbox: d.sandbox })
  assert.deepEqual(withheld.schemas(), [])
  const args = { command: ['true'] }
  await assert.rejects(
    withheld.call(ticketFor('run_q', args), args, context('run_q')),
    (e: unknown) => e instanceof PolicyDenied && /exposure is kernel-only; agents may only call agent tools/.test(e.message),
  )
  assert.equal(d.driver.specs.length, 0)
  assert.deepEqual(d.tools.schemas().map((s) => s.ref), [EXEC])
})

test('sandboxToolProblem admits a worker with a sandbox: block at tier 2 or 3, in either domain, and nothing else', () => {
  const base = { id: 'a', role: 'worker' as const, tier: 2, sandbox: { domain: 'trusted' as const } }
  assert.equal(sandboxToolProblem(base), undefined)
  assert.equal(sandboxToolProblem({ ...base, tier: 3, sandbox: { domain: 'hostile' } }), undefined)
  assert.match(String(sandboxToolProblem({ ...base, role: 'orchestrator' })), /role: orchestrator/)
  assert.match(String(sandboxToolProblem({ ...base, sandbox: undefined })), /declares no sandbox: block/)
  for (const tier of [1, 0, Number.NaN]) {
    assert.match(String(sandboxToolProblem({ ...base, tier })), /sandbox tools need tier 2 or more/, String(tier))
  }
  assert.equal(SANDBOX_SERVER, 'sandbox')
})

test('a spawned child that lowers its tier below 2 keeps no sandbox tool', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t, { 'coder-template': manifest('coder-template', { kind: 'template' }) }))
  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'coder-template', childId: 'low-1', tier: 1 }),
    /^ConfigError: spawn rejected: tools\.allow names sandbox\.exec: low-1 lists a sandbox tool at tier 1, but sandbox tools need tier 2 or more/,
  )
  assert.equal(reg.get('low-1'), undefined)
  // Dropping the tool, the child spawns at tier 1; keeping its tier, with it.
  assert.deepEqual(reg.spawnEphemeral({ templateId: 'coder-template', childId: 'ok-1', tier: 1, toolsAllow: [] }).manifest.tools.allow, [])
  assert.deepEqual(reg.spawnEphemeral({ templateId: 'coder-template', childId: 'ok-2' }).manifest.tools.allow, [EXEC])
})

// ── how a container with no exit status ends ────────────────────────────────

test('a docker client that ends with no exit status has its container killed by name before the log records its end', async (t) => {
  // A docker CLI killed by a signal it cannot catch (SIGKILL from outside,
  // the OOM killer on the Mac) is expected to leave its --rm container
  // running, with the driver's wallclock timer cleared at the CLI's exit
  // (docker.ts); a spawn that started nothing gives the same null exit.
  for (const exit of [{ exitCode: null, signal: 'SIGKILL' }, { exitCode: null }] as const) {
    const d = direct(t, { exits: [exit] })
    const name = `${CONTAINER_PREFIX}run_g-1`
    let killsWhenEnded: string[] | undefined
    d.store.subscribe((row) => {
      if (row.type === 'sandbox.killed') killsWhenEnded = [...d.driver.kills]
    })
    const args = { command: ['sleep', 'infinity'] }
    const out = await d.tools.call(ticketFor('run_g', args), args, context('run_g'))
    assert.deepEqual(killsWhenEnded, [name], 'the kill by name was sent before sandbox.killed was written')
    assert.deepEqual(d.driver.kills, [name])
    assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }])
    assert.equal(out.ok, false)
    assert.match(
      out.text,
      new RegExp(
        `^aos-run-run_g-1 on the trusted domain, no network, ended with no exit status \\(${'signal' in exit ? 'SIGKILL' : 'the docker client did not start'}\\) after 1 ms; ` +
          'a kill by name was sent to aos-run-run_g-1, as a docker client with no exit status may leave its container running\n',
      ),
    )
  }
})

test('a driver whose result rejects has its container killed by name, and its end recorded, before the call fails', async (t) => {
  const d = direct(t, { exits: [{}] })
  // The contract says a result never rejects (SandboxDriver.run); this one does.
  const lossy: SandboxDriver = {
    name: d.driver.name,
    probe: () => d.driver.probe(),
    run: (spec) => {
      const running = d.driver.run(spec)
      return { ...running, result: running.result.then(() => Promise.reject(new Error('the driver lost track'))) }
    },
    kill: (name) => d.driver.kill(name),
  }
  const tools = new SandboxTools({ store: d.store, views: SHIPPED_VIEWS, driver: lossy, agents: d.agents, sandbox: d.sandbox })
  const name = `${CONTAINER_PREFIX}run_j-1`
  let killsWhenEnded: string[] | undefined
  d.store.subscribe((row) => {
    if (row.type === 'sandbox.killed') killsWhenEnded = [...d.driver.kills]
  })
  const args = { command: ['true'] }
  const out = await tools.call(ticketFor('run_j', args), args, context('run_j'))
  assert.equal(out.ok, false)
  assert.equal(out.text, `[error] the driver lost ${name}: the driver lost track; a kill by name was sent to ${name}`)
  assert.deepEqual(killsWhenEnded, [name])
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }])
  assert.deepEqual(
    d.store.query().map((r) => r.type).filter((type) => type.startsWith('tool.') || type.startsWith('sandbox.')),
    ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'],
  )
})

test('a container the log cannot record is killed by name, and one a subscriber stops as it is recorded is killed too', { timeout: 10_000 }, async (t) => {
  // The sandbox.started append throws: the container is killed, not left to
  // its wallclock while the call waits on it, and the call fails readably.
  const unrecorded = direct(t, { exits: [{ hangs: true }] })
  const append = unrecorded.store.append.bind(unrecorded.store)
  unrecorded.store.append = ((event: Parameters<EventStore['append']>[0]) => {
    if (event.type === 'sandbox.started') throw new Error('the log refused the row')
    return append(event)
  }) as EventStore['append']
  const args = { command: ['sleep', 'infinity'] }
  const out = await unrecorded.tools.call(ticketFor('run_u', args), args, context('run_u'))
  assert.deepEqual(unrecorded.driver.kills, [`${CONTAINER_PREFIX}run_u-1`])
  assert.equal(out.ok, false)
  assert.equal(out.text, 'the log refused the row')
  assert.deepEqual(
    unrecorded.store.query().map((r) => r.type).filter((type) => type.startsWith('tool.') || type.startsWith('sandbox.')),
    ['tool.call', 'tool.result'],
  )

  // A store subscriber that stops the run synchronously, as sandbox.started
  // is written: the signal is aborted before the runner listens for it, so
  // only its check after listening sees the stop.
  const stopped = direct(t, { exits: [{ hangs: true }] })
  const stop = new AbortController()
  stopped.store.subscribe((row) => {
    if (row.type === 'sandbox.started') stop.abort()
  })
  const ended = await stopped.tools.call(ticketFor('run_v', args), args, context('run_v', { signal: stop.signal }))
  assert.deepEqual(stopped.driver.kills, [`${CONTAINER_PREFIX}run_v-1`])
  assert.match(ended.text, /was killed: the run was stopped \(exit 137\)/)
  assert.deepEqual(payloads(stopped.store, 'sandbox.killed').map((p) => [p.reason, p.exitCode]), [['requested', 137]])
})

// ── what a human approving an exec is shown ─────────────────────────────────

/** Arguments `{command: ['echo', <fill>]}` whose canonical JSON is exactly `bytes` long. */
function argsOfSize(bytes: number): { command: string[] } {
  const overhead = Buffer.byteLength(canonicalize({ command: ['echo', ''] }))
  const args = { command: ['echo', 'x'.repeat(bytes - overhead)] }
  assert.equal(Buffer.byteLength(canonicalize(args)), bytes)
  return args
}

test('an exec whose arguments the approval preview would cut is refused, whoever approved it', async (t) => {
  // At the preview's bound, a human sees all of it, and it runs; one byte
  // past, the preview cuts it, and it is refused before any container.
  const d = direct(t, { exits: [{}] })
  const fits = argsOfSize(APPROVAL_PREVIEW_BYTES)
  const ran = await d.tools.call(ticketFor('run_b', fits), fits, context('run_b'))
  assert.equal(ran.ok, true, ran.text)
  const over = argsOfSize(APPROVAL_PREVIEW_BYTES + 1)
  const refused = await d.tools.call(ticketFor('run_b', over), over, context('run_b'))
  assert.equal(refused.ok, false)
  assert.equal(
    refused.text,
    `[refused] sandbox.exec's arguments come to ${String(APPROVAL_PREVIEW_BYTES + 1)} bytes as a human approving the ` +
      `call is shown them (redacted canonical JSON), and approval.requested shows at most ${String(APPROVAL_PREVIEW_BYTES)}: ` +
      'a human could approve a command whose end they never saw. Keep each command within that, and write a longer ' +
      'script in steps.',
  )
  assert.equal(d.driver.specs.length, 1)

  // Through the loop: a tainted run's second exec is padded past the preview,
  // with its point at the end. The human is shown 500 bytes without it, and
  // approves; the ticket binds the whole, and the runner refuses it.
  const hidden = ['sh', '-c', `${'echo building; '.repeat(40)}rm -rf /workspace/src`]
  const w = wire(t, {
    script: [exec(['git', 'clone', 'x']), exec(hidden, 'call_2'), done()],
    exits: [{ stdout: 'cloned\n' }],
  })
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      w.approvals.resolve(id, mintHumanActor('conn-test'), 'approved')
    })
  })
  const out = await w.loop.start({ runId: 'run_p', agent: w.agent('coder'), prompt: 'clone and build' })
  assert.equal(out.status, 'ok', String(out.reason))
  const [asked] = payloads(w.store, 'approval.requested')
  assert.equal(Buffer.byteLength(String(asked?.argsPreview)), APPROVAL_PREVIEW_BYTES)
  assert.doesNotMatch(String(asked?.argsPreview), /rm -rf/, 'the human was never shown the tail')
  assert.equal(w.driver.specs.length, 1, 'the approved command with the unseen tail did not run')
  const results = payloads(w.store, 'tool.result')
  assert.equal(results.length, 2)
  assert.equal(results[1]?.ok, false)
  assert.match(String(results[1]?.text), /^\[refused\] sandbox\.exec's arguments come to 647 bytes as a human approving the call is shown them/)
})

// ── the argument bounds ─────────────────────────────────────────────────────

test('an exec past the argument bounds is refused by the bound it passes, before any spec', async (t) => {
  // Each bound is below the approval preview's own check, which runs after
  // it: these hold the arguments should that bound ever be widened.
  const cases: readonly [string, readonly string[], RegExp][] = [
    [`${String(MAX_EXEC_ARGS + 1)} arguments`, ['true', ...Array.from({ length: MAX_EXEC_ARGS }, () => 'x')], new RegExp(`command: Too big: expected array to have <=${String(MAX_EXEC_ARGS)} items`)],
    [`one argument of ${String(MAX_EXEC_ARG_BYTES + 1)} bytes`, ['echo', 'x'.repeat(MAX_EXEC_ARG_BYTES + 1)], new RegExp(`command\\.1: an argument is at most ${String(MAX_EXEC_ARG_BYTES)} bytes`)],
    [`17 arguments of 4000 bytes, past ${String(MAX_EXEC_BYTES)} in all`, Array.from({ length: 17 }, () => 'x'.repeat(4_000)), new RegExp(`command: the command is at most ${String(MAX_EXEC_BYTES)} bytes in all`)],
  ]
  for (const [what, command, why] of cases) {
    const d = direct(t, { exits: [{}] })
    const args = { command }
    const out = await d.tools.call(ticketFor('run_m', args), args, context('run_m'))
    assert.equal(out.ok, false, what)
    assert.match(out.text, /^\[refused\] sandbox\.exec takes \{command: \[program, \.\.\.args\]\}: /, what)
    assert.match(out.text, why, `${what}: ${out.text.slice(0, 300)}`)
    assert.equal(d.driver.specs.length, 0, what)
  }
})

test('a tool-views file that exposes a sandbox tool the kernel does not implement gets a refusal, not exec', async (t) => {
  const views = parseToolViews({
    version: 1,
    servers: {
      sandbox: {
        default: 'kernel-only',
        tools: {
          exec: { exposure: 'agent', risk: 'write', taints: true },
          other: { exposure: 'agent', risk: 'write', taints: true },
        },
      },
    },
  })
  // The manifest lists both, so nothing but the runner's own check stands
  // between sandbox.other and exec's body.
  const d = direct(t, { views, exits: [{}], files: { coder: manifest('coder', { allow: [EXEC, 'sandbox.other'] }) } })
  const args = { command: ['true'] }
  await assert.rejects(
    d.tools.call(ticketFor('run_o', args, 'sandbox.other'), args, context('run_o')),
    (e: unknown) => e instanceof PolicyDenied && /the kernel implements no sandbox tool other/.test(e.message),
  )
  assert.equal(d.driver.specs.length, 0)
  assert.deepEqual(d.store.query().map((r) => r.type).filter((type) => type.startsWith('tool.') || type.startsWith('sandbox.')), [])
  assert.deepEqual(d.tools.schemas().map((s) => s.ref), [EXEC], 'and it is never offered')
})

// ── what reaches the model of a long output ─────────────────────────────────

test("each stream keeps its own share of the result, and its end: a long stdout never pushes stderr out", async (t) => {
  // Long lines: the next llm.request carries this result inside the JSON
  // body it logs, and a text of many short lines would grow past the payload
  // limit there as each newline is escaped twice, which is the transport's to
  // bound, not this runner's.
  const stdout = `first line of the build\n${'compiling module; '.repeat(4_200)}\nlast line of stdout\n`
  assert.ok(Buffer.byteLength(stdout) > 70_000)
  const stderr = 'FAIL test/thing.test.ts: expected 1, got 2\n'
  const w = wire(t, { script: [exec(['make', 'test']), done()], exits: [{ exitCode: 2, stdout, stderr }] })
  const out = await w.loop.start({ runId: 'run_o', agent: w.agent('coder'), prompt: 'test' })
  assert.equal(out.status, 'ok', String(out.reason))

  const [result] = payloads(w.store, 'tool.result')
  const text = String(result?.text)
  // The exit status, then stdout said cut and its end kept, then all of stderr.
  assert.match(text, /^aos-run-run_o-1 on the trusted domain, no network, exited 2 after 1 ms\n/)
  const kept = text.slice(text.indexOf('\n--- stdout'))
  assert.match(kept, new RegExp(`^\\n--- stdout \\(${String(Buffer.byteLength(stdout))} bytes, cut to its last \\d+\\) ---\\n`))
  assert.ok(text.includes('last line of stdout\n'), 'the end of stdout is kept')
  assert.ok(!text.includes('first line of the build'), 'the start of stdout is what was cut')
  assert.ok(text.endsWith(`\n--- stderr (${String(Buffer.byteLength(stderr))} bytes) ---\n${stderr}`), text.slice(-300))
  assert.ok(Buffer.byteLength(text) <= PAYLOAD_TEXT_BUDGET)
  // Marked cut, with the size and digest of the whole it stands for.
  assert.equal(result?.truncated, true)
  assert.ok(Number(result?.bytes) > Buffer.byteLength(stdout))
  assert.match(String(result?.sha256), /^[0-9a-f]{64}$/)
  // And what the model read is what the log stores.
  assert.deepEqual(toolMessages(w.provider.requests[1]), [text])
})


// ── the real driver's whole-argv scans ──────────────────────────────────────

/** The real driver, with test functions for its two process seams. */
function realDriver(sandbox: SandboxConfig, root: string, processes: Pick<ConstructorParameters<typeof DockerDriver>[0], 'spawn' | 'execFile'>): DockerDriver {
  mkdirSync(join(root, 'repo'), { recursive: true })
  return new DockerDriver({
    ...processes,
    domains: sandbox.domains,
    defaults: { user: '65534:65534', pidsLimit: 256, memory: '2g', cpus: 2 },
    repoRoot: join(root, 'repo'),
    imageId: IMAGE,
    path: '/usr/bin:/bin',
    home: join(root, 'home'),
    dockerConfig: join(root, 'docker'),
  })
}

test("an exec of go test -v is refused in its own terms, before any workspace, as the real driver's whole-argv audit would refuse it", async (t) => {
  // The audit's FORBIDDEN_FLAGS and its --mount/-v count read the command
  // too (docker.ts wholeArgvRefusal), an over-refusal kept until the
  // operator decides whether they move before the image. The runner asks the
  // same scans first, and names the argument, not docker's argv.
  const d = direct(t, { exits: [{}] })
  const root = tmpdir(t)
  const spawned: (readonly string[])[] = []
  const real = realDriver(d.sandbox, root, {
    spawn: (_cmd, args) => {
      spawned.push(args)
      throw new Error('test: nothing is spawned here')
    },
    execFile: () => Promise.resolve({ stdout: '', stderr: '' }),
  })
  const tools = new SandboxTools({ store: d.store, views: SHIPPED_VIEWS, driver: real, agents: d.agents, sandbox: d.sandbox })
  const mount = 'docker args must carry exactly one --mount and no -v (found 1 and 1)'
  const respell = 'Spell it another way if the program has one (--verbose for -v), or leave it out.'
  const socket = 'Leave it out: no container reaches the docker daemon, so no command needs its socket.'
  const long = `${'x'.repeat(80)} /var/run/docker.sock`
  const cases: readonly [readonly string[], string, string, string][] = [
    [['go', 'test', '-v'], 'command[2], "-v",', mount, respell],
    [['pytest', '-v'], 'command[1], "-v",', mount, respell],
    [['node', '-v'], 'command[1], "-v",', mount, respell],
    [['grep', '-v', 'x'], 'command[1], "-v",', mount, respell],
    [['grep', '--volume', 'x'], 'command[1], "--volume",', mount, respell],
    [['ls', '--mount', 'x'], 'command[1], "--mount",', 'docker args must carry exactly one --mount and no -v (found 2 and 0)', respell],
    [['python', 'train.py', '--device', 'cpu'], 'command[2], "--device",', 'docker args contain --device, which invariant 9 forbids', respell],
    [['ls', '/var/run/docker.sock'], 'command[1], "/var/run/docker.sock",', 'docker args mention docker.sock: a container may never reach the daemon', socket],
    // A long argument is named by its place, not quoted.
    [['sh', '-c', long], 'command[2]', 'docker args mention docker.sock: a container may never reach the daemon', socket],
  ]
  const expected = (named: string, audit: string, advice: string): string =>
    `[refused] ${named} is refused wherever it stands in a command, for now: the sandbox's audit reads the command as ` +
    `part of the docker run's own arguments, and refuses it there (${audit}), until the operator decides whether ` +
    `that check stops at the image. ${advice}`
  for (const [command, named, audit, advice] of cases) {
    const args = { command }
    const fromReal = await tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.equal(fromReal.text, expected(named, audit, advice), command.join(' '))
    const fromFake = await d.tools.call(ticketFor('run_f', args), args, context('run_f'))
    assert.equal(fromFake.text, expected(named, audit, advice), command.join(' '))
  }
  assert.equal(spawned.length, 0, 'the real driver spawned nothing for a refused command')
  // Refused before the workspace is made, and before either driver is asked.
  assert.equal(existsSync(join(d.sandbox.domains.trusted.mountRoot, 'run_r')), false)
  assert.equal(existsSync(join(d.sandbox.domains.trusted.mountRoot, 'run_f')), false)
  assert.equal(d.driver.specs.length, 0)

  // Both drivers still refuse such a command themselves, in the audit's words,
  // and the fake spends no scripted exit on it.
  const workspace = join(d.sandbox.domains.trusted.mountRoot, 'run_d')
  mkdirSync(workspace)
  for (const [command, , audit] of cases) {
    const spec: SandboxSpec = {
      name: `${CONTAINER_PREFIX}run_d-1`,
      runId: 'run_d',
      agentId: 'coder',
      domain: 'trusted',
      image: IMAGE,
      command,
      workspace,
      limits: { memoryMb: 2048, cpus: 2, pids: 256, wallclockMs: 1_000 },
    }
    assert.throws(() => real.run(spec), (e: unknown) => e instanceof ConfigError && e.message === audit, command.join(' '))
    assert.throws(() => d.driver.run(spec), (e: unknown) => e instanceof ConfigError && e.message === audit, command.join(' '))
  }

  // A command the scans admit reaches the spawn, in the run's own workspace.
  const admitted = { command: ['go', 'test', './...'] }
  await tools.call(ticketFor('run_r', admitted), admitted, context('run_r'))
  assert.equal(spawned.length, 1)
  assert.deepEqual(spawned[0]?.slice(-4), [IMAGE, 'go', 'test', './...'])
  assert.ok(
    spawned[0]?.includes(`type=bind,source=${realpathSync(join(d.sandbox.domains.trusted.mountRoot, 'run_r'))},target=/workspace`),
    'mounted at its workspace',
  )
  const fromFake = await d.tools.call(ticketFor('run_f', admitted), admitted, context('run_f'))
  assert.equal(fromFake.ok, true, fromFake.text)
})

// ── what a human approving an exec is shown, as it runs ─────────────────────

const BEGIN_KEY = '-----BEGIN PRIVATE KEY-----'
const END_KEY = '-----END PRIVATE KEY-----'

/** The refusal of an exec whose preview redaction changed. */
function redactedRefusal(where: string): string {
  return (
    `[refused] ${where} a span the log redacts as a credential (a PEM private key block, a bearer token, a provider, ` +
    'GitHub, Slack or AWS key, a JWT, or a value the kernel holds as secret), so a human approving this call ' +
    'would be shown [REDACTED] in its place, and could approve a command they cannot read. A worker never holds ' +
    'a credential: keep anything of that shape out of the command, and make a test key inside the container ' +
    'rather than writing one into it.'
  )
}

test('an exec whose arguments the approval preview would redact is refused, whoever approved it, and the refusal echoes none of it', async (t) => {
  // Through the loop: a tainted run's second exec hides `rm -rf` between the
  // markers of a PEM block. The human is shown a short preview that is not
  // cut, with the middle redacted, and approves; the runner refuses it.
  const hidden = ['sh', '-c', `echo '${BEGIN_KEY}' >/dev/null; rm -rf /workspace/src; echo '${END_KEY}' >/dev/null; make test`]
  const w = wire(t, {
    script: [exec(['git', 'clone', 'x']), exec(hidden, 'call_2'), done()],
    exits: [{ stdout: 'cloned\n' }],
  })
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      w.approvals.resolve(id, mintHumanActor('conn-test'), 'approved')
    })
  })
  const out = await w.loop.start({ runId: 'run_k', agent: w.agent('coder'), prompt: 'clone and test' })
  assert.equal(out.status, 'ok', String(out.reason))
  const [asked] = payloads(w.store, 'approval.requested')
  assert.equal(asked?.argsPreview, `{"command":["sh","-c","echo '[REDACTED]' >/dev/null; make test"]}`, 'what the human was shown')
  assert.equal(payloads(w.store, 'approval.resolved')[0]?.decision, 'approved')
  assert.equal(w.driver.specs.length, 1, 'the approved command with the hidden span did not run')
  const results = payloads(w.store, 'tool.result')
  assert.equal(results.length, 2)
  assert.equal(results[1]?.ok, false)
  assert.equal(results[1]?.text, redactedRefusal('command[2] holds'))
  assert.deepEqual(toolMessages(w.provider.requests[2]).slice(1), [redactedRefusal('command[2] holds')])

  // Direct: a Bearer-shaped argument, a value the kernel holds as secret, and
  // a PEM block whose markers stand in two arguments, which no one argument's
  // redaction shows.
  const secret = 'opaque-vault-value-7731'
  assert.equal(SecretMask.register(secret), true)
  t.after(() => {
    SecretMask.clear()
  })
  const cases: readonly [string, readonly string[], string][] = [
    ['a Bearer token', ['curl', '-H', 'Authorization: Bearer abc.def-123', 'https://x.test'], 'command[2] holds'],
    ['a value the kernel holds as secret', ['echo', `key=${secret}`], 'command[1] holds'],
    ['a PEM block across two arguments', ['sh', '-c', `echo '${BEGIN_KEY}'`, `rm -rf /; echo '${END_KEY}'`], "sandbox.exec's arguments hold, across more than one of them,"],
  ]
  for (const [what, command, where] of cases) {
    const d = direct(t, { exits: [{}] })
    const args = { command }
    const refused = await d.tools.call(ticketFor('run_q', args), args, context('run_q'))
    assert.equal(refused.ok, false, what)
    assert.equal(refused.text, redactedRefusal(where), what)
    assert.equal(d.driver.specs.length, 0, what)
    assert.equal(existsSync(join(d.sandbox.domains.trusted.mountRoot, 'run_q')), false, `${what}: no workspace made`)
  }
})

test('an exec holding a character a screen hides or reorders by is refused, naming it; plain non-ASCII text runs', async (t) => {
  // Written as escapes, so this file shows no hidden or bidirectional text
  // itself, which is the hazard the test is about.
  const unseen: readonly [string, string][] = [
    ['\u202E', 'U+202E'], // right-to-left override
    ['\u2066', 'U+2066'], // left-to-right isolate
    ['\u200B', 'U+200B'], // zero-width space
    ['\uFEFF', 'U+FEFF'], // byte order mark
    ['\u00AD', 'U+00AD'], // soft hyphen
    ['\u0085', 'U+0085'], // a C1 control (next line)
    ['\u007F', 'U+007F'], // DEL
    ['\u2028', 'U+2028'], // line separator
    ['\u2029', 'U+2029'], // paragraph separator
    // Default-ignorable code points outside Cf. The Hangul fillers are
    // letters to JavaScript and Python, so `node -e` or `python -c` code can
    // name a variable the human approving it cannot see.
    ['\u3164', 'U+3164'], // Hangul filler
    ['\u115F', 'U+115F'], // Hangul choseong filler
    ['\u1160', 'U+1160'], // Hangul jungseong filler
    ['\uFFA0', 'U+FFA0'], // halfwidth Hangul filler
    ['\uFE0F', 'U+FE0F'], // variation selector 16
    ['\uFE00', 'U+FE00'], // variation selector 1
    ['\u{E0100}', 'U+E0100'], // variation selector 17
    ['\u034F', 'U+034F'], // combining grapheme joiner
    ['\u180B', 'U+180B'], // Mongolian free variation selector one
    ['\u17B4', 'U+17B4'], // Khmer vowel inherent aq
  ]
  for (const [ch, point] of unseen) {
    const d = direct(t, { exits: [{}] })
    const args = { command: ['git', 'commit', '-m', `fix the ${ch}build`] }
    const refused = await d.tools.call(ticketFor('run_u', args), args, context('run_u'))
    assert.equal(
      refused.text,
      `[refused] command[3] holds ${point}, a character a screen shows as nothing or uses to reorder the text around ` +
        'it (a format, bidi or C1 control, a filler or variation selector, or a line separator), so a human ' +
        'approving this call would not read the command as it runs. Write it as an escape the program decodes, or ' +
        'leave it out.',
      point,
    )
    assert.equal(d.driver.specs.length, 0, point)
  }
  // As a zero-width joiner is, an emoji written with VS16 is refused: a red
  // heart (U+2764 U+FE0F) names its selector.
  const heart = direct(t, { exits: [{}] })
  const hearts = { command: ['echo', 'I \u2764\uFE0F tests'] }
  const refused = await heart.tools.call(ticketFor('run_u', hearts), hearts, context('run_u'))
  assert.match(refused.text, /^\[refused\] command\[1\] holds U\+FE0F, /)
  assert.equal(heart.driver.specs.length, 0)
  // C0 controls are escaped in the preview (\n, \t, \u001b), so a human sees
  // them, and ordinary text in any script is shown as itself.
  const d = direct(t, { exits: [{}] })
  const args = { command: ['sh', '-c', 'printf "naïve café 日本語 😀\\n"\techo\u001b[0m done\nexit 0'] }
  const ran = await d.tools.call(ticketFor('run_u', args), args, context('run_u'))
  assert.equal(ran.ok, true, ran.text)
  assert.equal(d.driver.specs.length, 1)
})

/** Arguments `{command: ['echo', ...]}` of backslashes, whose canonical JSON is exactly `bytes` long. */
function backslashArgsOfSize(bytes: number): { command: string[] } {
  const command = ['echo']
  const size = (): number => Buffer.byteLength(canonicalize({ command }))
  while (size() < bytes) {
    const left = bytes - size()
    // A new argument takes 3 bytes (`,""`) and 2 for each backslash; an x
    // added to the last takes 1.
    if (left < 5) command[command.length - 1] += 'x'.repeat(left)
    else command.push('\\'.repeat(Math.min(2_000, Math.floor((left - 3) / 2))))
  }
  assert.equal(size(), bytes)
  return { command }
}

test("an exec at the preview's bound whose every byte JSON escapes is still asked of a human, and runs once approved", async (t) => {
  // approval.requested holds the preview, which is canonical JSON, inside its
  // own canonical JSON, so each backslash the preview shows as two takes four
  // there. A preview bound widened past about half the store's limit would
  // make this append throw and the run fail, rather than ask the human.
  const command = backslashArgsOfSize(APPROVAL_PREVIEW_BYTES).command
  const w = wire(t, {
    script: [exec(['git', 'clone', 'x']), exec(command, 'call_2'), done()],
    exits: [{ stdout: 'cloned\n' }, {}],
    // An approval whose approval.requested the store refused stays pending
    // in Approvals with its expiry armed: short, so such a run ends here as
    // the failure it is rather than holding the test open.
    approvalWaitMs: 2_000,
  })
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      w.approvals.resolve(id, mintHumanActor('conn-test'), 'approved')
    })
  })
  const out = await w.loop.start({ runId: 'run_b', agent: w.agent('coder'), prompt: 'twice' })
  assert.equal(out.status, 'ok', String(out.reason))
  const [asked] = w.store.query({ type: 'approval.requested' })
  assert.equal(Buffer.byteLength(String((JSON.parse(String(asked?.payload)) as { argsPreview: string }).argsPreview)), APPROVAL_PREVIEW_BYTES)
  assert.ok(Buffer.byteLength(String(asked?.payload)) <= MAX_LOGGED_OUTPUT)
  assert.deepEqual(w.driver.specs.map((s) => s.command.length), [3, command.length], 'the approved command ran')
})

// ── how a container that may run on is ended ────────────────────────────────

test('a docker client that exits 125, its own failure, has its container killed by name before the log records its end', async (t) => {
  // `docker run` exits 125 for its own error, a daemon connection lost
  // mid-run among them, after which its --rm container runs on in the VM
  // with the driver's wallclock timer cleared at the CLI's exit.
  const d = direct(t, { exits: [{ exitCode: DOCKER_CLI_FAILED, stderr: 'docker: error waiting for container: unexpected EOF\n' }] })
  const name = `${CONTAINER_PREFIX}run_c-1`
  let killsWhenEnded: string[] | undefined
  d.store.subscribe((row) => {
    if (row.type === 'sandbox.killed') killsWhenEnded = [...d.driver.kills]
  })
  const args = { command: ['make', 'test'] }
  const out = await d.tools.call(ticketFor('run_c', args), args, context('run_c'))
  assert.deepEqual(killsWhenEnded, [name], 'the kill by name was sent before sandbox.killed was written')
  // The container's own exit 125 looks the same, so the end says exited.
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'exited', exitCode: 125 }])
  assert.equal(out.ok, false)
  assert.match(
    out.text,
    new RegExp(
      `^${name} on the trusted domain, no network, exited 125 after 1 ms; a kill by name was sent to ${name}, as a ` +
        'docker client that exits 125, its own failure \\(a lost daemon connection among them\\), may leave its ' +
        'container running\n',
    ),
  )
  // Any other status is the container's own end, and sends no kill.
  for (const exitCode of [0, 1, 124, 126, 127, 137]) {
    const other = direct(t, { exits: [{ exitCode }] })
    await other.tools.call(ticketFor('run_o', args), args, context('run_o'))
    assert.deepEqual(other.driver.kills, [], String(exitCode))
  }
})

/** The fake driver, but every kill is recorded and then does `answer`. */
function withKill(base: FakeSandbox, answer: (name: string) => Promise<void>): SandboxDriver & { readonly kills: string[] } {
  const kills: string[] = []
  return {
    name: base.name,
    probe: () => base.probe(),
    run: (spec) => base.run(spec),
    kill: (name) => {
      kills.push(name)
      return answer(name)
    },
    kills,
  }
}

function toolsOver(d: Direct, driver: SandboxDriver, over: Partial<SandboxToolsOptions> = {}): SandboxTools {
  return new SandboxTools({ store: d.store, views: SHIPPED_VIEWS, driver, agents: d.agents, sandbox: d.sandbox, ...over })
}

/** sandbox.* and tool.* rows, in order. */
function callRows(store: EventStore): string[] {
  return store.query().map((r) => r.type).filter((type) => type.startsWith('tool.') || type.startsWith('sandbox.'))
}

test('a kill by name that no daemon answers holds the call for killWaitMs at most, and the end is still recorded', { timeout: 20_000 }, async (t) => {
  const never = (): Promise<void> => new Promise<void>(() => undefined)
  const cases: readonly [string, ScriptedExit, (base: FakeSandbox) => SandboxDriver & { readonly kills: string[] }][] = [
    ['no exit status', { exitCode: null, signal: 'SIGKILL' }, (base) => withKill(base, never)],
    ['exit 125', { exitCode: DOCKER_CLI_FAILED }, (base) => withKill(base, never)],
    [
      'a result that rejects',
      {},
      (base) => {
        const driver = withKill(base, never)
        return {
          ...driver,
          run: (spec) => {
            const running = base.run(spec)
            return { ...running, result: running.result.then(() => Promise.reject(new Error('the driver lost track'))) }
          },
        }
      },
    ],
  ]
  for (const [what, exit, make] of cases) {
    const d = direct(t, { exits: [exit] })
    const driver = make(d.driver)
    const tools = toolsOver(d, driver, { killWaitMs: 25 })
    const args = { command: ['sleep', 'infinity'] }
    const startedAt = Date.now()
    const out = await tools.call(ticketFor('run_n', args), args, context('run_n'))
    assert.ok(Date.now() - startedAt < 5_000, what)
    const name = `${CONTAINER_PREFIX}run_n-1`
    assert.deepEqual(driver.kills, [name], what)
    assert.ok(out.text.includes(`a kill by name was sent to ${name}, and no daemon answered within 25 ms`), `${what}: ${out.text}`)
    assert.deepEqual(callRows(d.store), ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'], what)
    assert.equal(payloads(d.store, 'sandbox.killed')[0]?.reason, what === 'exit 125' ? 'exited' : 'error', what)
  }

  // The real driver, as it was met: the docker CLI dies of SIGKILL, and the
  // driver, no longer holding the name, asks both domains to kill it; the
  // hostile VM's daemon accepts and never answers.
  const d = direct(t)
  const execs: string[] = []
  const real = realDriver(d.sandbox, tmpdir(t), {
    spawn: () => killedChild(),
    execFile: (_cmd, args, options) => {
      execs.push(`${options.env['DOCKER_HOST'] ?? '?'} ${args.join(' ')}`)
      return options.env['DOCKER_HOST'] === d.sandbox.domains.hostile.dockerHost ? new Promise(() => undefined) : Promise.resolve({ stdout: '', stderr: '' })
    },
  })
  const tools = toolsOver(d, real, { killWaitMs: 25 })
  const args = { command: ['make'] }
  const out = await tools.call(ticketFor('run_m', args), args, context('run_m'))
  const name = `${CONTAINER_PREFIX}run_m-1`
  assert.deepEqual(execs, [
    `${d.sandbox.domains.trusted.dockerHost} kill --signal=KILL ${name}`,
    `${d.sandbox.domains.hostile.dockerHost} kill --signal=KILL ${name}`,
  ])
  assert.match(out.text, new RegExp(`ended with no exit status \\(SIGKILL\\) after \\d+ ms; a kill by name was sent to ${name}, and no daemon answered within 25 ms, as a docker client with no exit status may leave its container running`))
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }])
})

/** A docker CLI child that is killed by SIGKILL just after it starts, as Node reports one. */
function killedChild(): ChildLike {
  const handlers: Record<string, ((...a: never[]) => void)[]> = {}
  const child: ChildLike = {
    stdin: null,
    stdout: { on: () => undefined },
    stderr: { on: () => undefined },
    on: ((event: string, cb: (...a: never[]) => void) => {
      ;(handlers[event] ??= []).push(cb)
      return child
    }) as ChildLike['on'],
  }
  setImmediate(() => {
    for (const event of ['exit', 'close']) {
      for (const cb of handlers[event] ?? []) (cb as (code: number | null, signal: string | null) => void)(null, 'SIGKILL')
    }
  })
  return child
}

test('unset, the kill wait is KILL_WAIT_MS', { timeout: 10_000 }, async (t) => {
  // The fake ends a hung run on a real setImmediate, so only the runner's own
  // timer is mocked here.
  mock.timers.enable({ apis: ['setTimeout'] })
  t.after(() => {
    mock.timers.reset()
  })
  const d = direct(t, { exits: [{ exitCode: null }] })
  const driver = withKill(d.driver, () => new Promise<void>(() => undefined))
  const tools = toolsOver(d, driver)
  const args = { command: ['true'] }
  let ended = false
  const call = tools.call(ticketFor('run_w', args), args, context('run_w')).then((out) => {
    ended = true
    return out
  })
  // Bounded by count, not time: this test's own timeout is a timer, and
  // timers are mocked here.
  for (let i = 0; i < 1_000 && driver.kills.length === 0; i++) await new Promise((resolve) => setImmediate(resolve))
  assert.equal(driver.kills.length, 1, 'the kill by name was sent')
  mock.timers.tick(KILL_WAIT_MS - 1)
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve))
  assert.equal(ended, false, 'still waiting one millisecond short of KILL_WAIT_MS')
  mock.timers.tick(1)
  const out = await call
  assert.ok(out.text.includes(`and no daemon answered within ${String(KILL_WAIT_MS)} ms`), out.text)
  assert.equal(KILL_WAIT_MS, 10_000)
})

test("a driver whose kill rejects, or throws as it is called, still has the container's end recorded, and is said to have refused", async (t) => {
  const answers: readonly [string, (base: FakeSandbox) => SandboxDriver & { readonly kills: string[] }][] = [
    ['rejects', (base) => withKill(base, () => Promise.reject(new Error('the daemon said no')))],
    [
      'throws',
      (base) =>
        withKill(base, () => {
          throw new Error('the daemon said no')
        }),
    ],
  ]
  for (const [what, make] of answers) {
    const d = direct(t, { exits: [{ exitCode: null }] })
    const driver = make(d.driver)
    const args = { command: ['true'] }
    const out = await toolsOver(d, driver).call(ticketFor('run_e', args), args, context('run_e'))
    const name = `${CONTAINER_PREFIX}run_e-1`
    assert.deepEqual(callRows(d.store), ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'], what)
    assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }], what)
    assert.ok(
      out.text.includes(
        `; a kill by name was sent to ${name}, and the driver refused it: the daemon said no, as a docker client with no exit status may leave its container running\n`,
      ),
      `${what}: ${out.text}`,
    )
  }
})

test("a run stopped after its exec has ended sends no kill, and an exec leaves no listener on the run's signal", async (t) => {
  const d = direct(t, { exits: [{}, {}, { exitCode: null }] })
  const stop = new AbortController()
  const args = { command: ['true'] }
  for (let i = 0; i < 3; i++) await d.tools.call(ticketFor('run_l', args), args, context('run_l', { signal: stop.signal }))
  assert.equal(getEventListeners(stop.signal, 'abort').length, 0)
  // The third ended with no exit status, and was killed by name then.
  assert.deepEqual(d.driver.kills, [`${CONTAINER_PREFIX}run_l-3`])
  stop.abort()
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(d.driver.kills, [`${CONTAINER_PREFIX}run_l-3`], 'no kill for a container that has ended')
})

test('a container the log cannot record fails the call only once it has ended', { timeout: 10_000 }, async (t) => {
  const d = direct(t, { exits: [{ hangs: true }] })
  let settled = false
  const driver: SandboxDriver = {
    name: d.driver.name,
    probe: () => d.driver.probe(),
    run: (spec) => {
      const running = d.driver.run(spec)
      void running.result.then(() => {
        settled = true
      })
      return running
    },
    kill: (name) => d.driver.kill(name),
  }
  const append = d.store.append.bind(d.store)
  d.store.append = ((event: Parameters<EventStore['append']>[0]) => {
    if (event.type === 'sandbox.started') throw new Error('the log refused the row')
    return append(event)
  }) as EventStore['append']
  const args = { command: ['sleep', 'infinity'] }
  const out = await toolsOver(d, driver).call(ticketFor('run_x', args), args, context('run_x'))
  assert.equal(out.text, 'the log refused the row')
  assert.equal(settled, true, "the container's result had settled when the call returned")
  assert.deepEqual(d.driver.kills, [`${CONTAINER_PREFIX}run_x-1`])
})

// ── what reaches the model of an output, by the bytes it takes in the log ───

/** The bytes a string takes in canonical JSON, its quotes aside. */
const payloadBytes = (text: string): number => Buffer.byteLength(JSON.stringify(text)) - 2

test('two streams share the result: a short one whole and the other the rest, and each its half when both are long', async (t) => {
  const head = 'aos-run-run_s-1 on the trusted domain, no network, exited 1 after 1 ms'
  const room = PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE - payloadBytes(head)
  const half = Math.floor(room / 2)
  // Long, and within STREAM_WINDOW_BYTES, so each is read whole.
  const long = 70_000
  assert.ok(long <= STREAM_WINDOW_BYTES)
  const cases: readonly [string, number, number, number, number][] = [
    // stdout, stderr, and the bytes each keeps.
    ['a long stdout', long, 100, room - 100, 100],
    ['a long stderr', 100, long, 100, room - 100],
    ['both long', long, long, half, room - half],
  ]
  for (const [what, outBytes, errBytes, outKept, errKept] of cases) {
    const d = direct(t, { exits: [{ exitCode: 1, stdout: 'o'.repeat(outBytes), stderr: 'e'.repeat(errBytes) }] })
    const args = { command: ['make'] }
    const out = await d.tools.call(ticketFor('run_s', args), args, context('run_s'))
    const part = (label: string, bytes: number, kept: number, ch: string): string =>
      `--- ${label} (${String(bytes)} bytes${kept === bytes ? '' : `, cut to its last ${String(kept)}`}) ---\n${ch.repeat(kept)}`
    assert.equal(out.text, `${head}\n${part('stdout', outBytes, outKept, 'o')}\n${part('stderr', errBytes, errKept, 'e')}`, what)
  }
})

test('a cut keeps whole characters, a pair of surrogates among them', async (t) => {
  // 60 KB, read whole, and 120 KB or 160 KB, read by its window.
  const cases: readonly [string, number][] = [['€', 20_000], ['€', 40_000], ['😀', 15_000], ['😀', 40_000]]
  for (const [ch, count] of cases) {
    for (let pad = 0; pad < 8; pad++) {
      const stdout = ch.repeat(count)
      const d = direct(t, { exits: [{ stdout, stderr: 'e'.repeat(pad) }] })
      const args = { command: ['cat', 'x'] }
      const out = await d.tools.call(ticketFor('run_c', args), args, context('run_c'))
      assert.equal(out.ok, true, out.text.slice(0, 200))
      const kept = /--- stdout \((?:\d+ bytes, cut to its last \d+|its end, redacted: \d+ bytes, of the \d+ bytes it printed)\) ---\n([\s\S]*)\n--- stderr/.exec(out.text)?.[1]
      assert.ok(kept !== undefined && kept.length > 0, `${ch} ${String(pad)}`)
      assert.ok(stdout.endsWith(kept), `${ch} ${String(pad)}: the kept text is the end of the stream`)
      assert.doesNotMatch(kept, /�|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u)
    }
  }
})

test('a stream of quotes and backslashes is shared out by the bytes it takes in the log, so its tool.result fits', async (t) => {
  // `cat package-lock.json`: by raw bytes, the result's JSON escapes would
  // push tool.result past the store's limit, and its append would throw with
  // the container already gone.
  const cases = [
    ['a lockfile', '    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://x.test/l.tgz"},\n'],
    ['backslashes and quotes', '"\\"\\\\\n'],
  ] as const
  for (const [what, line] of cases) {
    const stdout = line.repeat(Math.ceil(200_000 / line.length))
    const d = direct(t, { exits: [{ stdout }] })
    const args = { command: ['cat', 'package-lock.json'] }
    const out = await d.tools.call(ticketFor('run_j', args), args, context('run_j'))
    assert.equal(out.ok, true, what)
    const [row] = d.store.query({ type: 'tool.result' })
    assert.ok(row !== undefined && Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, what)
    const heading = /--- stdout \(its end, redacted: (\d+) bytes, of the (\d+) bytes it printed\) ---\n([\s\S]*)\n--- stderr/.exec(out.text)
    assert.ok(heading !== null, what)
    assert.equal(Number(heading[2]), Buffer.byteLength(stdout), what)
    assert.ok(stdout.endsWith(heading[3] ?? '!'), what)
  }
})

test("tool.result's bytes and digest are of the whole describe() stands for, each stream redacted once", async (t) => {
  const head = 'aos-run-run_d-1 on the trusted domain, no network, exited 1 after 1 ms'
  const cases: readonly [string, string, string][] = [
    ['a long stdout', `first\n${'y'.repeat(70_000)}\nlast\n`, 'boom\n'],
    // Each stream alone redacts nothing, and the joined whole would redact
    // across the stderr heading: the whole is hashed as describe() joined it.
    ['markers in two streams', `${'z'.repeat(70_000)}\n${BEGIN_KEY}\n`, `${END_KEY}\n`],
  ]
  for (const [what, stdout, stderr] of cases) {
    const d = direct(t, { exits: [{ exitCode: 1, stdout, stderr }] })
    const args = { command: ['make'] }
    await d.tools.call(ticketFor('run_d', args), args, context('run_d'))
    const whole =
      `${head}\n--- stdout (${String(Buffer.byteLength(stdout))} bytes) ---\n${stdout}\n` +
      `--- stderr (${String(Buffer.byteLength(stderr))} bytes) ---\n${stderr}`
    if (what === 'markers in two streams') assert.notEqual(redactString(whole), whole, 'the case is one a second redaction changes')
    const [result] = payloads(d.store, 'tool.result')
    assert.equal(result?.truncated, true, what)
    assert.equal(result?.sha256, sha256Hex(whole), what)
    assert.equal(result?.bytes, Buffer.byteLength(whole), what)
  }
})

/** `text` padded with `.` after `before` to exactly `bytes` UTF-8 bytes. */
function padTo(bytes: number, before: string, after: string): string {
  const fill = bytes - Buffer.byteLength(before) - Buffer.byteLength(after)
  assert.ok(fill >= 0)
  return `${before}${'.'.repeat(fill)}${after}`
}

/** `text` as a regular expression that matches it literally. */
const literal = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** The head of a result whose run the driver capped, for run `runId`'s first exec, exit 1. */
const cappedHead = (runId: string): string =>
  `aos-run-${runId}-1 on the trusted domain, no network, exited 1 after 1 ms\n` +
  `[output cut: a stream carried more than ${String(CAPTURE_MAX_BYTES)} bytes, and the driver kept only its first; ` +
  'such a stream is shown from its start]\n'

/** The heading of a stream read by its start, `shown` bytes of a capture of `printed`. */
const startHeading = (label: string, shown: number, printed = CAPTURE_MAX_BYTES): string =>
  `--- ${label} (its start, redacted: ${String(shown)} bytes, of the ${String(printed)} bytes its capture kept; the stream carried more) ---`

/** startHeading as a regular expression, for any count shown. */
const startHeadingRe = (label: string, printed = CAPTURE_MAX_BYTES): string =>
  literal(startHeading(label, 0, printed)).replace('redacted: 0 bytes', 'redacted: \\d+ bytes')

/** The lines of a build, plain text no credential pattern matches. */
const BUILD_LINES = Array.from({ length: 3_000 }, (_, i) => `line ${String(i)} of the build\n`).join('')

/** A key block redact.ts hides whole: some 4 KB that redaction shrinks to 10 bytes. */
const KEY_BLOCK = `${BEGIN_KEY}\n${'A'.repeat(4_000)}\n${END_KEY}\n`

/**
 * A credential the driver's cut splits: a key block with no END and a token
 * short of the length its pattern needs, which redaction misses both of.
 */
const SPLIT = `${BEGIN_KEY}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC${'S'.repeat(2_000)}\nghp_T0kenCutSh0rt`

test('a stream the driver capped is read by its start, and its capture is never shown up to the cut', async (t) => {
  assert.equal(redactString(SPLIT), SPLIT, 'the split credential is one redaction misses')
  // Mostly plain lines, the split credential at the driver's cut, far past
  // the window describe() reads: the start is shown, within its share.
  const big = direct(t, { exits: [{ exitCode: 1, stdout: padTo(CAPTURE_MAX_BYTES, `FIRST LINE\n${BUILD_LINES}`, SPLIT), stderr: 'FAIL\n', truncated: true }] })
  const args = { command: ['make'] }
  const out = await big.tools.call(ticketFor('run_t', args), args, context('run_t'))
  assert.match(
    out.text,
    new RegExp(`^${literal(cappedHead('run_t'))}${startHeadingRe('stdout')}\nFIRST LINE\nline 0 of the build\n`),
  )
  assert.ok(out.text.endsWith('\n--- stderr (5 bytes) ---\nFAIL\n'), 'the short stderr is whole')
  for (const piece of ['MIIEvQ', 'SSSS', 'ghp_']) assert.ok(!out.text.includes(piece), piece)

  // The driver cuts back to a character's start, up to three bytes short of
  // the cap: such a stream is one it capped all the same, read by its start,
  // and the credential at its end is never shown.
  for (const short of [1, 2, 3]) {
    const stdout = padTo(CAPTURE_MAX_BYTES - short, `FIRST LINE\n${BUILD_LINES}`, SPLIT)
    const d = direct(t, { exits: [{ exitCode: 1, stdout, stderr: 'FAIL\n', truncated: true }] })
    const cut = await d.tools.call(ticketFor('run_t', args), args, context('run_t'))
    const heading = startHeadingRe('stdout', CAPTURE_MAX_BYTES - short)
    assert.match(cut.text, new RegExp(`^${literal(cappedHead('run_t'))}${heading}\nFIRST LINE\n`), String(short))
    for (const piece of ['MIIEvQ', 'SSSS', 'ghp_']) assert.ok(!cut.text.includes(piece), `${String(short)}: ${piece}`)
  }
})

test("a capped stream's window is never shown at its own cut, where it may split a token, however much redaction shrank it", async (t) => {
  // Mostly key blocks, each redacted whole, then 20 KB of plain output, then
  // a token the window's cut, at STREAM_WINDOW_BYTES, leaves 10 bytes of. The
  // redacted window fits the share, so only its edge keeps the token out.
  const start = `FIRST LINE\n${BUILD_LINES.slice(0, 1_000)}`
  const at = STREAM_WINDOW_BYTES - 10
  const blocks = KEY_BLOCK.repeat(Math.floor((at - start.length - 20_000) / KEY_BLOCK.length))
  const token = `ghp_${'Q7xK'.repeat(9)}`
  assert.notEqual(redactString(token), token, 'the whole token is redacted')
  const stdout = padTo(CAPTURE_MAX_BYTES, `${padTo(at, `${start}${blocks}`, '')}${token}`, '')
  const window = stdout.slice(0, STREAM_WINDOW_BYTES)
  const read = redactString(window)
  assert.ok(read.endsWith(token.slice(0, 10)), 'the window ends in the token, unredacted')
  assert.ok(Buffer.byteLength(read) < PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE - 400, 'the redacted window fits the share')
  const d = direct(t, { exits: [{ exitCode: 1, stdout, truncated: true }] })
  const args = { command: ['make'] }
  const out = await d.tools.call(ticketFor('run_w', args), args, context('run_w'))
  const shown = read.slice(0, read.length - CAPTURE_EDGE_BYTES)
  assert.equal(out.text, `${cappedHead('run_w')}${startHeading('stdout', shown.length)}\n${shown}\n--- stderr (0 bytes) ---\n`)
  assert.ok(shown.includes(`${BUILD_LINES.slice(0, 1_000)}[REDACTED]\n[REDACTED]\n`), 'the redacted blocks are shown')
  assert.ok(!out.text.includes('ghp_'))
  // Nothing describe() read was cut from what it shows: the text is whole.
  assert.equal(payloads(d.store, 'tool.result')[0]?.truncated, false)
})

test('a private key block a window cut splits is never shown from its marker on, however far before the cut it begins', async (t) => {
  // A 24 KiB PGP block that begins 20 000 bytes before the window's cut, more
  // than CAPTURE_EDGE_BYTES, and ends past it, after mostly redacted key
  // blocks. The capture holds it whole, so a redaction of all of it would
  // hide it; the window's does not, as the cut parts its markers.
  const pgp = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${`lQdGBGZ${'x'.repeat(56)}\n`.repeat(384)}-----END PGP PRIVATE KEY BLOCK-----\n`
  assert.ok(Buffer.byteLength(pgp) > 24 * 1024)
  const start = `FIRST LINE\n${BUILD_LINES.slice(0, 1_000)}`
  const at = STREAM_WINDOW_BYTES - 20_000
  const blocks = KEY_BLOCK.repeat(Math.floor((at - start.length - 2_000) / KEY_BLOCK.length))
  const stdout = padTo(CAPTURE_MAX_BYTES, `${padTo(at, `${start}${blocks}`, '')}${pgp}`, '')
  assert.ok(!redactString(stdout).includes('lQdGBGZ'), 'a redaction of the whole capture hides the block')
  const read = redactString(stdout.slice(0, STREAM_WINDOW_BYTES))
  assert.ok(read.includes('lQdGBGZ'), "the window's redaction does not")
  const begin = read.indexOf('-----BEGIN PGP')
  assert.ok(begin !== -1 && begin < read.length - CAPTURE_EDGE_BYTES, 'the BEGIN lies before the edge')
  const d = direct(t, { exits: [{ exitCode: 1, stdout, truncated: true }] })
  const args = { command: ['gpg', '--export-secret-keys'] }
  const out = await d.tools.call(ticketFor('run_g', args), args, context('run_g'))
  const shown = read.slice(0, begin)
  assert.equal(out.text, `${cappedHead('run_g')}${startHeading('stdout', shown.length)}\n${shown}\n--- stderr (0 bytes) ---\n`)
  for (const piece of ['PGP PRIVATE KEY', 'lQdGBGZ']) assert.ok(!out.text.includes(piece), piece)
})

test('a stream longer than its window is read by its end, and never shown where the window starts, inside a token or a key block', async (t) => {
  const args = { command: ['make'] }
  // The window's start falls inside a token, which it keeps the last 20
  // bytes of. Plain output follows, then key blocks redaction shrinks, so
  // the window fits its share and only its edge keeps the token out.
  const token = `ghp_${'Q7xK'.repeat(9)}`
  const tail = `\n${'.'.repeat(17_000)}\n${KEY_BLOCK.repeat(12)}${BUILD_LINES.slice(0, 5_000)}LAST LINE\n`
  const windowStart = STREAM_WINDOW_BYTES - (Buffer.byteLength(tail) + 20)
  assert.ok(windowStart > 0)
  const stdout = `${BUILD_LINES}${'.'.repeat(100_000)} ${token}${padTo(windowStart, '', '')}${tail}`
  const window = stdout.slice(stdout.length - STREAM_WINDOW_BYTES)
  assert.ok(window.startsWith(token.slice(-20) + '.'), 'the window starts inside the token')
  const read = redactString(window)
  assert.ok(Buffer.byteLength(read) < PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE - 400, 'the redacted window fits the share')
  const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
  const out = await d.tools.call(ticketFor('run_e', args), args, context('run_e'))
  const shown = read.slice(CAPTURE_EDGE_BYTES)
  const head = 'aos-run-run_e-1 on the trusted domain, no network, exited 1 after 1 ms'
  assert.equal(
    out.text,
    `${head}\n--- stdout (its end, redacted: ${String(shown.length)} bytes, of the ${String(stdout.length)} bytes it printed) ---\n${shown}\n--- stderr (0 bytes) ---\n`,
  )
  assert.ok(out.text.endsWith('LAST LINE\n\n--- stderr (0 bytes) ---\n'))
  assert.ok(!out.text.includes('Q7xK'), 'no part of the token')

  // The window's start falls inside a 30 KB key block whose BEGIN lies
  // before it, and its END some 25 KB in: a redaction of all of the stream
  // hides the block, the window's does not, and nothing up to its END is
  // shown.
  const body = `MIIEvQIBADANBgkq${'Z'.repeat(47)}\n`.repeat(470)
  const after = `${'.'.repeat(20_000)}\n${KEY_BLOCK.repeat(7)}LAST LINE\n`
  const inside = STREAM_WINDOW_BYTES - Buffer.byteLength(`\n${END_KEY}\n${after}`)
  assert.ok(inside > CAPTURE_EDGE_BYTES && inside < body.length)
  const stderr = `${BUILD_LINES}${'.'.repeat(100_000)}\n${BEGIN_KEY}\n${body}\n${END_KEY}\n${after}`
  assert.ok(!redactString(stderr).includes('ZZZZ'), 'a redaction of the whole stream hides the block')
  const readErr = redactString(stderr.slice(stderr.length - STREAM_WINDOW_BYTES))
  assert.ok(readErr.slice(CAPTURE_EDGE_BYTES).includes('ZZZZ'), "the window's redaction does not, past its edge")
  const e = direct(t, { exits: [{ exitCode: 1, stderr }] })
  const err = await e.tools.call(ticketFor('run_e', args), args, context('run_e'))
  const shownErr = readErr.slice(readErr.indexOf(END_KEY) + END_KEY.length)
  assert.equal(
    err.text,
    `${head}\n--- stdout (0 bytes) ---\n\n--- stderr (its end, redacted: ${String(shownErr.length)} bytes, of the ${String(stderr.length)} bytes it printed) ---\n${shownErr}`,
  )
  for (const piece of ['MIIEvQ', 'ZZZZ', 'PRIVATE KEY']) assert.ok(!err.text.includes(piece), piece)
  assert.ok(err.text.endsWith('[REDACTED]\nLAST LINE\n'))
})

test('no redaction reads more than a window of a stream, so a MiB of BEGIN lines with no END costs milliseconds, not seconds', async (t) => {
  // redact.ts's PEM pattern takes time quadratic in a text of BEGIN lines no
  // END follows: some 11 s for each 1 MiB stream, with the daemon's event
  // loop blocked throughout, on an exec that needs no human.
  const lines = `${BEGIN_KEY}\n`.repeat(Math.ceil(CAPTURE_MAX_BYTES / (BEGIN_KEY.length + 1)))
  const stdout = lines.slice(0, CAPTURE_MAX_BYTES)
  const stderr = lines.slice(0, CAPTURE_MAX_BYTES - 100)
  const d = direct(t, { exits: [{ exitCode: 0, stdout, stderr, truncated: true }] })
  const args = { command: ['make', 'keys'] }
  const began = performance.now()
  const out = await d.tools.call(ticketFor('run_b', args), args, context('run_b'))
  const took = performance.now() - began
  assert.ok(took < 5_000, `the exec took ${String(Math.round(took))} ms`)
  assert.equal(out.ok, true)
  // stdout is read by its start, and shown up to its first BEGIN, which no
  // END in its window follows: nothing. stderr, not capped, by its end.
  assert.match(
    out.text,
    new RegExp(
      `\n${literal(startHeading('stdout', 0))}\n\n--- stderr \\(its end, redacted: \\d+ bytes, of the ${String(CAPTURE_MAX_BYTES - 100)} bytes it printed\\) ---\n`,
    ),
  )
  const [result] = payloads(d.store, 'tool.result')
  assert.equal(result?.truncated, true)
  const bytes = result?.bytes
  assert.ok(typeof bytes === 'number' && bytes <= 2 * STREAM_WINDOW_BYTES, `tool.result's bytes: ${String(bytes)}`)
})

test("the window cuts read redact.ts's PEM pattern's own markers", () => {
  const pem = TOKEN_PATTERNS.filter((re) => re.source.includes('PRIVATE KEY'))
  assert.equal(pem.length, 1)
  assert.equal(pem[0]?.source, `${PEM_BEGIN.source}[\\s\\S]*?${PEM_END.source}`)
  assert.equal(PEM_BEGIN.flags, '')
  assert.equal(PEM_END.flags, '')
})

test('a capped stream of quotes or backslashes is shown from its start by the bytes it takes in the log, so its tool.result fits', async (t) => {
  for (const ch of ['"', '\\']) {
    const d = direct(t, { exits: [{ stdout: ch.repeat(CAPTURE_MAX_BYTES), truncated: true }] })
    const args = { command: ['cat', 'quotes'] }
    const out = await d.tools.call(ticketFor('run_q', args), args, context('run_q'))
    assert.equal(out.ok, true, ch)
    assert.deepEqual(callRows(d.store), ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'], ch)
    const [row] = d.store.query({ type: 'tool.result' })
    assert.ok(row !== undefined && Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, ch)
    const shown = /--- stdout \(its start, redacted: (\d+) bytes, [^\n]*\n([\s\S]*)\n--- stderr/.exec(out.text)
    assert.ok(shown !== null && shown[2] !== undefined && shown[2].length > 20_000 && shown[2] === ch.repeat(shown[2].length), ch)
    assert.equal(Number(shown[1]), shown[2].length, ch)
  }
})

test("a stderr cut to its share, beside a stdout shown whole, marks tool.result cut, with the whole's bytes and digest", async (t) => {
  const stdout = 'ok\n'
  const stderr = `${'e'.repeat(70_000)}\nFAILED\n`
  const d = direct(t, { exits: [{ exitCode: 1, stdout, stderr }] })
  const args = { command: ['make'] }
  const out = await d.tools.call(ticketFor('run_v', args), args, context('run_v'))
  assert.match(out.text, /\n--- stderr \(70008 bytes, cut to its last \d+\) ---\ne+\nFAILED\n$/)
  const head = 'aos-run-run_v-1 on the trusted domain, no network, exited 1 after 1 ms'
  const whole = `${head}\n--- stdout (3 bytes) ---\n${stdout}\n--- stderr (70008 bytes) ---\n${stderr}`
  const [result] = payloads(d.store, 'tool.result')
  assert.equal(result?.truncated, true)
  assert.equal(result?.bytes, Buffer.byteLength(whole))
  assert.equal(result?.sha256, sha256Hex(whole))
})

test('a refusal never quotes a key the model sent, and a failure text past what tool.result holds is cut to fit', async (t) => {
  const refusal = (n: number): string =>
    `[refused] sandbox.exec takes {command: [program, ...args]}: (arguments): ${String(n)} ${n === 1 ? 'key' : 'keys'} ` +
    'it does not take; it takes only command'
  // A key of quotes takes twice its bytes in the log's JSON, one of controls
  // six times: zod's own text quotes each key, raw.
  const keys: readonly (readonly string[])[] = [['"'.repeat(40_000)], ['\u0001'.repeat(40_000)], ['network', 'privileged']]
  for (const named of keys) {
    const d = direct(t, { exits: [{}] })
    const args: Record<string, unknown> = { command: ['true'] }
    for (const key of named) args[key] = 1
    const out = await d.tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.equal(out.ok, false)
    assert.equal(out.text, refusal(named.length))
    assert.deepEqual(callRows(d.store), ['tool.call', 'tool.result'])
    for (const row of d.store.query()) assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT)
  }
  // A driver's refusal is the driver's text, and one of quotes would escape
  // past the store's limit: it is cut, by the bytes it takes in the log, and
  // tool.result gives the bytes and digest of the whole, redacted.
  for (const ch of ['"', '\u0001']) {
    const d = direct(t, { exits: [{}] })
    const message = `${ch.repeat(40_000)} ghp_${'Q7xK'.repeat(9)}`
    const refusing: SandboxDriver = {
      name: d.driver.name,
      probe: () => d.driver.probe(),
      run: () => {
        throw new ConfigError(message)
      },
      kill: (name) => d.driver.kill(name),
    }
    const tools = toolsOver(d, refusing)
    const args = { command: ['true'] }
    const out = await tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.equal(out.ok, false)
    assert.deepEqual(callRows(d.store), ['tool.call', 'tool.result'])
    const [row] = d.store.query({ type: 'tool.result' })
    assert.ok(row !== undefined && Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT)
    const whole = `[refused] ${ch.repeat(40_000)} [REDACTED]`
    const [result] = payloads(d.store, 'tool.result')
    assert.equal(result?.truncated, true)
    assert.equal(result?.bytes, Buffer.byteLength(whole))
    assert.equal(result?.sha256, sha256Hex(whole))
    assert.ok(whole.startsWith(out.text), 'the text is the start of the whole')
    assert.ok(payloadBytes(out.text) <= PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE)
  }
})
