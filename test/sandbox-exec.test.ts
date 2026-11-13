// Egress plan S3 — the sandbox.exec tool — and W1, its egress.
//
// sandbox.exec runs one command in one container of the caller's own sandbox
// domain: the pinned image by id, the run's workspace <mountRoot>/<runId>,
// no network, and a hard wallclock that is what is left of the run's budget,
// at most sandbox.defaults.wallclockMs. A trusted run whose manifest names
// egress is issued a grant before its container starts, and its container
// reaches the grant's hosts only through the kernel's egress engine, over the
// driver's channel (the end of this file, with test/helpers/fake-egress.ts
// playing the mux and the upstream host in process). It is driven here
// through the real run loop, gate, engine and approvals, against the fake
// driver (test/helpers/fake-sandbox.ts), with the shipped tool-views.yaml.
//
// The loop is handed the runner as bootKernel hands it (LoopOptions.
// sandboxTools, egress plan W1a), and an agent view with no tool of the hub's,
// so every sandbox.* call the loop makes reaches the runner, never the hub,
// with the run's id, its agent's id and its budget; test/kernel-boot.test.ts
// drives the daemon's own wiring.
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
//   Ask for a channel with no grant, or a workspace other than the run's
//   own, and a container reaches what no grant gave it. Issue a grant after
//   the spawn, put git-push or github-pulls in an exec's, give a hostile run
//   a channel, issue one while egress is degraded or one whose identifier the
//   log would censor, or dial before the decision row, and a container
//   reaches the network on terms the log does not hold.
//   Start a container without a sandbox.started row, or end one without its
//   sandbox.killed row, and the log does not say what ran. Record the end of
//   a container whose docker client died with no exit status without killing
//   it by name, and the log ends a container that may still run.
//   Run an exec whose arguments the approval preview cuts, or redacts, or
//   shows with a character a screen hides, and a human approves a command
//   they never read whole.
//   Wait without bound on a kill by name, or on the driver's result, and a
//   daemon that never answers holds the run forever with no end recorded.
//   Offer the tool to a run by its RunAgent's own tool list rather than its
//   manifest in the registry, or run a call the registry no longer admits,
//   and an agent that may not hold a container holds one; deny it with no
//   tool.result, and the log does not hold what the model was told.
//   Put an exec the runner refuses on its arguments to a human, and the
//   human approves a command that never runs, or one they never saw whole.
//   Bound the next llm.request's prompt by its raw bytes, and a result of
//   quoted lines escapes past the store's limit and ends the run in error.
//   Let a long stdout fill the result, and the failure on stderr is lost;
//   count a stream's share in raw bytes, and a stream of quotes pushes
//   tool.result past the store's limit; show the end of a stream the driver
//   capped, and the credential its cut split reaches the log unredacted.
//   Redact a stream whole rather than its window, and a MiB of BEGIN lines
//   with no END holds the daemon's event loop for seconds; show a window's
//   cut side, or a key block its cut splits, and a credential reaches the log;
//   read an end window from inside a token's match, and its redaction breaks a
//   BEGIN the stream's keeps, and that block's body reaches the log.
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
import { MAX_TIMER_MS, type KernelConfig } from '../src/config.js'
import { ConfigError, PolicyDenied } from '../src/errors.js'
import { MAX_LOGGED_OUTPUT, PAYLOAD_TEXT_BUDGET } from '../src/events/bound.js'
import { canonicalize, sha256Hex } from '../src/events/canonical.js'
import { projectRecovery } from '../src/events/projections.js'
import { redactString, SecretMask, TOKEN_PATTERNS } from '../src/events/redact.js'
import type { EventStore } from '../src/events/store.js'
import { PROXY_GRANT_MAX_REPOS } from '../src/events/types.js'
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
  AWS_KEY_ID,
  CAPTURE_EDGE_BYTES,
  EXEC_DESCRIPTION,
  EXEC_PROFILES,
  DESCRIBE_RESERVE,
  DOCKER_CLI_FAILED,
  DRIVER_TEXT_BYTES,
  EXIT_KILL_GRACE_MS,
  JWT_RUN_STARTS_MAX,
  KILL_WAIT_MS,
  MAX_EXEC_ARGS,
  MAX_EXEC_ARG_BYTES,
  MAX_EXEC_BYTES,
  PEM_BEGIN,
  PEM_END,
  RESULT_GRACE_MS,
  SANDBOX_SERVER,
  STREAM_WINDOW_BYTES,
  SandboxTools,
  MUX_ARGV,
  muxCommand,
  endReason,
  jwtRunStarts,
  pemEndHolds,
  sandboxToolProblem,
  tokenFreeStart,
  type SandboxCallContext,
  type SandboxEgress,
  type SandboxToolsOptions,
} from '../src/runtime/sandbox-tools.js'
import type { EgressHost } from '../src/egress/host.js'
import { acceptReady } from '../src/egress/ready.js'
import type { CredentialInjector } from '../src/egress/session.js'
import { readAllRows } from '../src/events/chain.js'
import { FakeMux, fakeUpstream, refusedReport, until, type FakeUpstream } from './helpers/fake-egress.js'
import { AppleContainerDriver } from '../src/sandbox/apple-container.js'
import { DockerDriver, type ChildLike } from '../src/sandbox/docker.js'
import { CAPTURE_MAX_BYTES, CONTAINER_PREFIX, type SandboxDomain, type SandboxDriver, type SandboxResult, type SandboxSpec } from '../src/sandbox/driver.js'
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
/** The home the fake driver's audit refuses, as the real driver refuses the operator's. */
const FAKE_HOME = '/Users/operator'

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
    /** egress: { allow, bind }, written only when given. */
    egress?: { readonly allow?: readonly string[]; readonly bind?: readonly string[] }
  } = {},
): string {
  const sandbox = over.sandbox ?? 'trusted'
  const egress = over.egress
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
    ...(egress === undefined ? [] : ['egress:', `  allow: [${(egress.allow ?? []).join(', ')}]`, `  bind: [${(egress.bind ?? []).join(', ')}]`]),
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

function registry(
  store: EventStore,
  views: ToolViewsFile = SHIPPED_VIEWS,
  egressBindings: Record<string, { readonly host: string; readonly repos: readonly string[] }> = {},
): AgentRegistry {
  return new AgentRegistry({
    providers: new Set([REF]),
    toolViews: views,
    store,
    budgets: { defaultRunMicroUsd: 2_000_000, defaultWallclockMs: 600_000, maxLlmCallsPerRun: 50, maxToolCallsPerRun: 100 },
    egressBindings: egressBindings as Record<string, { readonly host: EgressHost; readonly repos: readonly string[] }>,
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
 * The hub's agent view a loop is handed: no tool, and a call of any is a
 * test failure, so a sandbox call that reached the hub instead of the runner
 * fails the run that made it.
 */
function emptyHub(): AgentView {
  return {
    tools: [],
    call: (ticket) => Promise.reject(new Error(`test hub: ${ticket.toolRef} reached the hub`)),
  }
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
    /** What the runner reads agents from, in place of the registry itself. */
    sandboxAgents?: (registry: AgentRegistry) => SandboxToolsOptions['agents']
    /** The hub's agent view, in place of emptyHub. */
    hub?: AgentView
    /** Wire no sandbox runner into the loop, as a kernel built without one. */
    unwired?: true
    /** The runner's grace past a container's wallclock (SandboxToolsOptions.resultGraceMs). */
    resultGraceMs?: number
    /** kernel.yaml's sandbox.imageId, in place of IMAGE; undefined pins none. */
    imageId?: string | undefined
    /** The driver the runner is handed, in place of the fake (still `driver`, for its records). */
    driver?: (fake: FakeSandbox) => SandboxDriver
    /** The egress engine the runner is handed (SandboxToolsOptions.egress). */
    egress?: SandboxEgress
    /** The domains boot closed (SandboxToolsOptions.closedDomains): read at each ask, so a test may close one after the offer. */
    closedDomains?: Partial<Record<SandboxDomain, string>>
  },
): Wired {
  const store = withStore(t)
  const views = options.views ?? SHIPPED_VIEWS
  const agents = registry(store, views, options.egress?.bindings ?? {})
  agents.load(agentsDir(t, options.files ?? { coder: manifest('coder') }))
  const driver = fakeSandbox({ imageId: IMAGE, script: options.exits, home: FAKE_HOME })
  const sandbox = sandboxConfig(t, {
    ...(options.wallclockMs === undefined ? {} : { wallclockMs: options.wallclockMs }),
    ...('imageId' in options ? { imageId: options.imageId } : {}),
  })
  const tools = new SandboxTools({
    store,
    views,
    driver: options.driver?.(driver) ?? driver,
    agents: options.sandboxAgents?.(agents) ?? agents,
    sandbox,
    ...(options.resultGraceMs === undefined ? {} : { resultGraceMs: options.resultGraceMs }),
    ...(options.egress === undefined ? {} : { egress: options.egress }),
    ...(options.closedDomains === undefined ? {} : { closedDomains: options.closedDomains }),
  })

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
  const loop = new RunLoop({
    store,
    lanes: new Lanes({ main: 4, subagent: 8 }),
    router,
    engine,
    quarantine,
    views,
    agentView: options.hub === undefined ? emptyHub : () => options.hub as AgentView,
    budgetFor: () => budget,
    ...(options.unwired === true ? {} : { sandboxTools: tools }),
  })
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

/**
 * Deny every approval the loop files, and count them: a test that holds no
 * human must be asked of none, and one that is fails on the count rather
 * than wait out the approval's expiry.
 */
function denyEveryApproval(w: Wired): () => number {
  let asked = 0
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    asked += 1
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      w.approvals.resolve(id, mintHumanActor('conn-test'), 'denied')
    })
  })
  return () => asked
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
  // is not offered it, so a call the model makes of it anyway is one the
  // adapter rejects as not offered, before any gate, tool.call or container:
  // the two tests below take every such manifest in turn.
  const forged = wire(t, {
    script: [exec(['id']), done()],
    exits: [],
    files: { coder: manifest('coder'), boss: manifest('boss', { role: 'orchestrator', allow: [] }) },
  })
  const out = await forged.loop.start({
    runId: 'run_c',
    agent: { ...forged.agent('boss'), toolAllow: [EXEC] },
    prompt: 'run something',
  })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.deepEqual(offered(forged.provider.requests[0]), [])
  assert.deepEqual(toolMessages(forged.provider.requests[1]), ['[error] the model named a tool that was not offered on this call'])
  assert.equal(forged.driver.specs.length, 0)
  assert.deepEqual(callRows(forged.store), [])
})

/**
 * Manifests sandboxToolProblem refuses (or holderProblem: one that does not
 * list the tool, an agent the registry does not hold), loaded without the
 * tool, each with the refusal a call of it from a run of theirs is given.
 */
const UNFIT: readonly (readonly [string, string | undefined, RegExp])[] = [
  ['boss', manifest('boss', { role: 'orchestrator', allow: [] }), /^boss lists a sandbox tool, but it is role: orchestrator\./],
  ['reader', manifest('reader', { sandbox: 'none', tier: 1, allow: [] }), /^reader lists a sandbox tool, but it declares no sandbox: block/],
  ['bare', manifest('bare', { sandbox: 'none', allow: [] }), /^bare lists a sandbox tool, but it declares no sandbox: block/],
  ['low', manifest('low', { tier: 1, allow: [] }), /^low lists a sandbox tool at tier 1, but sandbox tools need tier 2 or more/],
  ['unlisted', manifest('unlisted', { allow: [] }), /^sandbox\.exec is not in agent unlisted's manifest \(default deny\)$/],
  ['ghost', undefined, /^no agent ghost is registered$/],
]

/** A RunAgent for `id` whose own tool list claims sandbox.exec, whatever its manifest says. */
function claiming(w: Wired, id: string): RunAgent {
  if (w.agents.get(id) === undefined) {
    return { ...w.agent('coder'), agentId: id, projectId: `aos/agent/${id}`, toolAllow: [EXEC] }
  }
  return { ...w.agent(id), toolAllow: [EXEC] }
}

function unfitFleet(): Record<string, string> {
  const files: Record<string, string> = { coder: manifest('coder') }
  for (const [id, yaml] of UNFIT) if (yaml !== undefined) files[id] = yaml
  return files
}

test('a RunAgent whose toolAllow lists sandbox.exec, for a manifest sandboxToolProblem refuses, is not offered it', async (t) => {
  // The registry refused each of these manifests with the tool at load, so
  // they are loaded without it; a RunAgent built for one that claims it
  // anyway (a forged or stale tool list) is offered nothing: the loop reads
  // the manifest from the registry by the agent's id, not the RunAgent.
  const w = wire(t, { script: [...UNFIT.map(() => done()), done(), done()], exits: [], files: unfitFleet() })
  for (const [id] of UNFIT) {
    const out = await w.loop.start({ runId: `run_${id}`, agent: claiming(w, id), prompt: 'anything' })
    assert.equal(out.status, 'ok', `${id}: ${String(out.reason)}`)
  }
  assert.deepEqual(w.provider.requests.map(offered), UNFIT.map(() => []))
  // The control: the worker the manifest admits, with the same tool list.
  const out = await w.loop.start({ runId: 'run_fit', agent: claiming(w, 'coder'), prompt: 'anything' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.deepEqual(offered(w.provider.requests[UNFIT.length]), ['sandbox__exec'])
  // And the other side of the intersection: the worker the manifest admits,
  // in a run whose own tool list omits the tool, is offered nothing. The
  // registry's admission narrows the run's list; it never adds to it.
  const bare = await w.loop.start({ runId: 'run_bare', agent: { ...w.agent('coder'), toolAllow: [] }, prompt: 'anything' })
  assert.equal(bare.status, 'ok', String(bare.reason))
  assert.deepEqual(offered(w.provider.requests[UNFIT.length + 1]), [])
  assert.equal(w.driver.specs.length, 0)

  // Nor is the worker the manifest admits, with the tool in its list, on a
  // kernel whose sandbox config lets no exec run (no image id pinned, or one
  // that is no id: configRefusal): the gate would deny every call, and a
  // model shown the tool would spend its model calls retrying it.
  for (const imageId of [undefined, 'aos-worker:test']) {
    const unpinned = wire(t, { script: [done()], exits: [], imageId })
    const out = await unpinned.loop.start({ runId: 'run_unpinned', agent: unpinned.agent('coder'), prompt: 'anything' })
    assert.equal(out.status, 'ok', String(out.reason))
    assert.deepEqual(offered(unpinned.provider.requests[0]), [], String(imageId))
  }
})

test('a RunAgent whose toolAllow lists sandbox.exec, for a manifest sandboxToolProblem refuses, is denied it at execution: by the gate before any human is asked, or with its tool.result row when the registry changes while one is', async (t) => {
  // An adapter refuses a call of a tool it did not offer, so the loop's
  // check at execution is met by a record that changes between the offer and
  // the call. Here the runner reads, at the offer, a record that may hold the
  // tool (the coder's manifest under the agent's id), and from the model's
  // answer on the registry as it is. The loop asks the runner, before the
  // gate, whether it may hold the tool, and the gate denies the call (its
  // rule 3c) with the runner's reason: nothing runs, no tool.call or
  // tool.result is written, and the model is told the denial.
  for (const [id, , why] of UNFIT) {
    let swapped = false
    const w = wire(t, {
      script: [
        () => {
          swapped = true
          return exec(['id'])
        },
        done(),
      ],
      exits: [],
      files: unfitFleet(),
      sandboxAgents: (agents) => ({
        get: (agentId) => {
          const fit = agents.get('coder')
          if (swapped || agentId !== id || fit === undefined) return agents.get(agentId)
          return { ...fit, manifest: { ...fit.manifest, id } }
        },
      }),
    })
    const out = await w.loop.start({ runId: `run_${id}`, agent: claiming(w, id), prompt: 'run something' })
    assert.deepEqual(offered(w.provider.requests[0]), ['sandbox__exec'], `${id}: offered as the record read then`)
    assert.equal(out.status, 'ok', `${id}: ${String(out.reason)}`)
    assert.equal(out.taint, 'clean', `${id}: a denied call taints nothing`)
    const gates = payloads(w.store, 'tool.gate')
    assert.deepEqual(gates.map((g) => g.decision), ['deny'], id)
    assert.match(String(gates[0]?.reason), why, id)
    assert.deepEqual(toolMessages(w.provider.requests[1]), [`[denied] ${String(gates[0]?.reason)}`], `${id}: the model is told the gate's reason`)
    assert.deepEqual(callRows(w.store), ['tool.gate'], `${id}: no tool.call or tool.result, as nothing was about to run`)
    assert.equal(w.driver.specs.length, 0, id)
    assert.equal(existsSync(join(w.sandbox.domains.trusted.mountRoot, `run_${id}`)), false, `${id}: no workspace`)
  }

  // A record that changes between the offer and the call on a tainted run,
  // where the gate would otherwise ask a human: the worker runs one exec, and
  // is archived before its second is called. No human is asked to approve a
  // call that would then be denied.
  {
    const w = wire(t, {
      script: [
        exec(['git', 'clone', 'x']),
        () => {
          w.agents.archive('coder', mintHumanActor('conn-test'))
          return exec(['make'], 'call_2')
        },
        done(),
      ],
      exits: [{ stdout: 'cloned\n' }],
    })
    const asked = denyEveryApproval(w)
    const out = await w.loop.start({ runId: 'run_a', agent: w.agent('coder'), prompt: 'clone and build' })
    assert.equal(out.status, 'ok', String(out.reason))
    assert.equal(asked(), 0, 'a human was asked to approve a call of an archived agent')
    assert.equal(w.store.query({ type: 'run.parked' }).length, 0)
    assert.deepEqual(
      payloads(w.store, 'tool.gate').map((g) => [g.decision, g.taint, g.reason]),
      [['allow', 'clean', 'sandbox.exec is allowed for coder'], ['deny', 'tainted', 'agent coder is archived']],
    )
    assert.deepEqual(toolMessages(w.provider.requests[2]).slice(1), ['[denied] agent coder is archived'])
    assert.equal(w.driver.specs.length, 1, 'the second exec did not run')
    assert.equal(w.store.query({ type: 'tool.result' }).length, 1)
  }

  // A record that changes between the gate's ruling and the execution, on a
  // clean run, where the gate allows the call with no human: denied with its
  // tool.result, and, as nothing ran, the run stays clean.
  {
    let ruled = false
    const w = wire(t, {
      script: [exec(['id']), done()],
      exits: [],
      sandboxAgents: (agents) => ({
        get: (agentId) => {
          const record = agents.get(agentId)
          return ruled && record !== undefined ? { ...record, status: 'archived' as const } : record
        },
      }),
    })
    w.store.subscribe((row) => {
      if (row.type === 'tool.gate') ruled = true
    })
    const out = await w.loop.start({ runId: 'run_c', agent: w.agent('coder'), prompt: 'run something' })
    assert.equal(out.status, 'ok', String(out.reason))
    assert.equal(out.taint, 'clean', 'a call denied after the gate tainted the run')
    assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => [g.decision, g.taint]), [['allow', 'clean']])
    assert.deepEqual(callRows(w.store), ['tool.gate', 'tool.result'])
    assert.deepEqual(payloads(w.store, 'tool.result').map((r) => [r.ok, r.text]), [[false, '[denied] agent coder is archived']])
    assert.deepEqual(toolMessages(w.provider.requests[1]), ['[denied] agent coder is archived'])
    assert.equal(w.driver.specs.length, 0)
  }

  // And a record that changes while a human is asked: the worker is offered
  // exec, runs one, and is archived while a human is asked to approve its
  // second; approved, the call is denied at execution, as the registry reads
  // then, and recorded as its tool.result. It is charged as a tool call, so
  // the run's count is the one recovery reads back from its tool.result rows.
  const w = wire(t, {
    script: [exec(['git', 'clone', 'x']), exec(['make'], 'call_2'), done()],
    exits: [{ stdout: 'cloned\n' }],
  })
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      w.agents.archive('coder', mintHumanActor('conn-test'))
      w.approvals.resolve(id, mintHumanActor('conn-test'), 'approved')
    })
  })
  const out = await w.loop.start({ runId: 'run_z', agent: w.agent('coder'), prompt: 'clone and build' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.equal(w.driver.specs.length, 1, 'the second exec did not run')
  assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => g.decision), ['allow', 'needs-human'])
  const results = payloads(w.store, 'tool.result')
  assert.equal(results.length, 2)
  const [, denied] = results
  assert.equal(denied?.text, '[denied] agent coder is archived')
  assert.equal(denied?.ok, false)
  assert.equal(denied?.truncated, false)
  assert.equal(denied?.toolRef, EXEC)
  assert.deepEqual(toolMessages(w.provider.requests[2]).slice(1), ['[denied] agent coder is archived'], 'the model is told what the log holds')
  assert.deepEqual(w.store.query({ type: 'tool.call' }).length, 1)
  const [finished] = payloads(w.store, 'run.finished')
  assert.equal(finished?.toolCalls, results.length, 'the denial is charged as a tool call')
  // What recovery would have counted had the run been orphaned before it
  // finished: every tool.result row, the denial's among them.
  const [orphan] = projectRecovery(w.store.query().filter((r) => r.type !== 'run.finished')).orphanRuns
  assert.equal(orphan?.toolCalls, finished?.toolCalls, 'recovery counts what the live run charged')
})

test('a kernel with no sandbox runner denies a sandbox call before the gate asks anyone, and never sends it to the hub', async (t) => {
  // A hub view that offers a sandbox.exec schema (config reserves the
  // server id, so only a test builds one) lets the adapter take the model's
  // call; the loop, with no runner wired, hands the gate the reason, and the
  // gate denies it (rule 3c) on a clean run, which it would otherwise allow,
  // and on a tainted one, which would otherwise wait for a human. Nothing
  // reaches the hub, and no tool.call or tool.result is written.
  for (const taint of ['clean', 'tainted'] as const) {
    const hubCalls: string[] = []
    const hub: AgentView = {
      tools: [{ ref: EXEC, description: 'a hub tool under the sandbox server id', inputSchema: { type: 'object' } }],
      call: (ticket) => {
        hubCalls.push(ticket.toolRef)
        return Promise.resolve({ ok: true, text: 'ran on the hub', bytes: 14, truncated: false, durationMs: 0 })
      },
    }
    const w = wire(t, { script: [exec(['id']), done()], exits: [], hub, unwired: true })
    const asked = denyEveryApproval(w)
    const out = await w.loop.start({ runId: `run_${taint}`, agent: w.agent('coder'), prompt: 'run something', taint })
    assert.equal(out.status, 'ok', `${taint}: ${String(out.reason)}`)
    assert.deepEqual(offered(w.provider.requests[0]), ['sandbox__exec'], `${taint}: the hub's schema is offered`)
    assert.deepEqual(hubCalls, [], `${taint}: the call reached the hub`)
    assert.equal(asked(), 0, `${taint}: a human was asked`)
    assert.deepEqual(
      payloads(w.store, 'tool.gate').map((g) => [g.decision, g.taint, g.reason]),
      [['deny', taint, 'no sandbox runner is wired into this kernel']],
      taint,
    )
    assert.deepEqual(toolMessages(w.provider.requests[1]), ['[denied] no sandbox runner is wired into this kernel'], taint)
    assert.deepEqual(callRows(w.store), ['tool.gate'], `${taint}: no tool.call or tool.result`)
    assert.equal(w.driver.specs.length, 0, taint)
  }
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
    /** The egress engine the runner is handed (SandboxToolsOptions.egress). */
    egress?: SandboxEgress
    /**
     * kernel.yaml's bindings as the registry reads them, in place of the
     * egress engine's: a record the registry would refuse at load, reaching
     * the runner as no boot builds one.
     */
    registryBindings?: SandboxEgress['bindings']
    /** What the runner reads agents from, in place of the registry itself. */
    sandboxAgents?: (registry: AgentRegistry) => SandboxToolsOptions['agents']
    /** How long a container may outlive its command's exit frame (SandboxToolsOptions.exitKillGraceMs). */
    exitKillGraceMs?: number
    /** The domains boot closed (SandboxToolsOptions.closedDomains). */
    closedDomains?: Partial<Record<SandboxDomain, string>>
  } = {},
): Direct {
  const store = withStore(t)
  const views = options.views ?? SHIPPED_VIEWS
  const agents = registry(store, views, options.registryBindings ?? options.egress?.bindings ?? {})
  agents.load(agentsDir(t, options.files ?? { coder: manifest('coder') }))
  const driver = fakeSandbox({ imageId: options.driverImageId ?? IMAGE, script: options.exits ?? [], home: FAKE_HOME })
  const sandbox = sandboxConfig(t, 'imageId' in options ? { imageId: options.imageId } : {})
  const tools = new SandboxTools({
    store,
    views,
    driver,
    agents: options.sandboxAgents?.(agents) ?? agents,
    sandbox,
    ...(options.egress === undefined ? {} : { egress: options.egress }),
    ...(options.exitKillGraceMs === undefined ? {} : { exitKillGraceMs: options.exitKillGraceMs }),
    ...(options.closedDomains === undefined ? {} : { closedDomains: options.closedDomains }),
  })
  return { store, driver, tools, sandbox, agents }
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

test('a domain boot closed runs no exec: never offered, denied before the gate asks anyone, refused at execution with no workspace, and the other domain runs as before', async (t) => {
  // SandboxToolsOptions.closedDomains: boot's canary on that domain showed a
  // container there may have a route out (src/runtime/canary.ts routed), so
  // every exec there is refused, egress or none.
  const reason = 'hostile: the boot canary (aos-run-canary-1-000000000000-hostile) found that a container on this domain may have a route'
  const refusal = `${reason}; no container was started`
  const files = { coder: manifest('coder'), boxer: manifest('boxer', { sandbox: 'hostile' }) }

  // The runner itself: the agent on the closed domain is refused, the other is not.
  const d = direct(t, { files, closedDomains: { hostile: reason }, exits: [{ stdout: 'v24\n' }] })
  assert.equal(d.tools.domainRefusal(EXEC, 'boxer'), refusal)
  assert.equal(d.tools.domainRefusal(EXEC, 'coder'), undefined)
  assert.equal(d.tools.domainRefusal('sandbox.other', 'boxer'), undefined)
  assert.equal(d.tools.domainRefusal(EXEC, 'nobody'), undefined, 'holderProblem says why an unknown agent is refused')
  const args = { command: ['node', '--version'] }
  const refused = await d.tools.call(ticketFor('run_c', args), args, context('run_c', { agentId: 'boxer' }))
  assert.deepEqual([refused.ok, refused.text, refused.taints], [false, `[refused] ${refusal}`, true])
  assert.equal(existsSync(join(d.sandbox.domains.hostile.mountRoot, 'run_c')), false, 'a workspace was made on a closed domain')
  assert.deepEqual(payloads(d.store, 'sandbox.started'), [])
  const ran = await d.tools.call(ticketFor('run_o', args), args, context('run_o'))
  assert.equal(ran.ok, true, ran.text)
  assert.deepEqual(d.driver.specs.map((spec) => spec.domain), ['trusted'])

  // Through the loop: a run on the closed domain is shown no sandbox tool.
  {
    const w = wire(t, { script: [done()], exits: [], files, closedDomains: { hostile: reason } })
    const out = await w.loop.start({ runId: 'run_l', agent: w.agent('boxer'), prompt: 'go' })
    assert.equal(out.status, 'ok', String(out.reason))
    assert.deepEqual(offered(w.provider.requests[0]), [])
  }
  // A domain closed after the offer: the call is denied before the gate
  // asks anyone, on a clean run or a tainted one, and nothing runs.
  for (const taint of ['clean', 'tainted'] as const) {
    const closed: Partial<Record<SandboxDomain, string>> = {}
    const w: Wired = wire(t, {
      script: [
        () => {
          closed.hostile = reason
          return exec(['node', '--version'])
        },
        done(),
      ],
      exits: [],
      files,
      closedDomains: closed,
    })
    const asked = denyEveryApproval(w)
    const out = await w.loop.start({ runId: `run_${taint}`, agent: w.agent('boxer'), prompt: 'go', taint })
    assert.equal(out.status, 'ok', `${taint}: ${String(out.reason)}`)
    assert.equal(asked(), 0, `${taint}: a human was asked`)
    assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => [g.decision, g.reason]), [['deny', refusal]], taint)
    assert.deepEqual(toolMessages(w.provider.requests[1]), [`[denied] ${refusal}`], taint)
    assert.deepEqual(callRows(w.store), ['tool.gate'], `${taint}: no tool.call or tool.result`)
    assert.equal(w.driver.specs.length, 0, taint)
  }
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

test("a run the loop is running, stopped through its RunRequest's signal mid-exec, has its container killed by name, sandbox.killed records requested, and the run ends killed", { timeout: 10_000 }, async (t) => {
  // Through RunLoop, as bootKernel's launch hands the loop the run's
  // signal (aos kill, a shutdown): the loop passes it to the runner, whose
  // kill by name ends the container, and the loop takes no further step.
  // Were the signal not passed, the hung container would be given up at its
  // wallclock and the grace (250 ms here), with no kill by name and
  // sandbox.killed recording error.
  const w = wire(t, { script: [exec(['sleep', 'infinity']), done()], exits: [{ hangs: true }], wallclockMs: 200, resultGraceMs: 50 })
  const stop = new AbortController()
  w.store.subscribe((row) => {
    if (row.type !== 'sandbox.started') return
    queueMicrotask(() => {
      stop.abort()
    })
  })
  const out = await w.loop.start({ runId: 'run_s', agent: w.agent('coder'), prompt: 'wait', signal: stop.signal })
  const name = `${CONTAINER_PREFIX}run_s-1`
  assert.deepEqual(w.driver.kills, [name], "the stop's kill by name")
  assert.deepEqual(w.driver.abandons, [], 'the container was given up rather than killed at the stop')
  assert.deepEqual(payloads(w.store, 'sandbox.killed').map((p) => [p.reason, p.exitCode]), [['requested', 137]])
  assert.deepEqual(callRows(w.store), ['tool.gate', 'tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'])
  assert.deepEqual([out.status, out.reason], ['killed', 'requested'])
  const [finished] = payloads(w.store, 'run.finished')
  assert.deepEqual([finished?.status, finished?.reason], ['killed', 'requested'])
  assert.equal(w.provider.requests.length, 1, 'the model was called again after the stop')
  assert.equal(getEventListeners(stop.signal, 'abort').length, 0, 'the exec left a listener on the run signal')
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
    abandon: (name) => d.driver.abandon(name),
    commandRefusal: (command) => d.driver.commandRefusal(command),
    everyRunRefusal: () => d.driver.everyRunRefusal(),
    sweepOrphans: (request) => d.driver.sweepOrphans(request),
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
  // with its point at the end. A human would be shown 500 bytes without it;
  // the gate denies it instead, before anyone is asked, and nothing runs.
  const hidden = ['sh', '-c', `${'echo building; '.repeat(40)}rm -rf /workspace/src`]
  const w = wire(t, {
    script: [exec(['git', 'clone', 'x']), exec(hidden, 'call_2'), done()],
    exits: [{ stdout: 'cloned\n' }],
  })
  const asked = denyEveryApproval(w)
  const out = await w.loop.start({ runId: 'run_p', agent: w.agent('coder'), prompt: 'clone and build' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.equal(asked(), 0, 'no human was asked')
  assert.equal(w.driver.specs.length, 1, 'the command with the unseen tail did not run')
  const gates = payloads(w.store, 'tool.gate')
  assert.deepEqual(gates.map((g) => [g.decision, g.taint]), [['allow', 'clean'], ['deny', 'tainted']])
  assert.match(String(gates[1]?.reason), /^sandbox\.exec's arguments come to 647 bytes as a human approving the call is shown them/)
  assert.equal(payloads(w.store, 'tool.result').length, 1)
  assert.deepEqual(toolMessages(w.provider.requests[2]).slice(1), [`[denied] ${String(gates[1]?.reason)}`])
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

test("an exec naming the operator's home, in either spelling, is refused in its own terms before any workspace, as the real driver's audit would refuse it", async (t) => {
  // The audit's home check reads the command too (docker.ts
  // commandAuditRefusal): an argument that is the home, or a path under it,
  // as given or resolved. The runner asks the driver the same check before
  // anything (SandboxDriver.commandRefusal), so the loop can deny the call
  // before a human is asked, and names the argument, not the home's resolved
  // spelling.
  const d = direct(t, { exits: [] })
  const root = tmpdir(t)
  const resolved = join(realpathSync(root), 'realhome')
  mkdirSync(resolved)
  symlinkSync(resolved, join(root, 'home'))
  const home = join(root, 'home')
  const spawned: (readonly string[])[] = []
  const real = realDriver(d.sandbox, root, {
    spawn: (_cmd, args) => {
      spawned.push(args)
      throw new Error('test: nothing is spawned here')
    },
    execFile: () => Promise.resolve({ stdout: '', stderr: '' }),
  })
  const tools = new SandboxTools({ store: d.store, views: SHIPPED_VIEWS, driver: real, agents: d.agents, sandbox: d.sandbox })
  const refusal = (named: string): string =>
    `${named} names the operator's home directory, or a path under it, which no container sees: the sandbox's ` +
    "audit refuses such an argument wherever it stands in the docker run's arguments, in either spelling of the " +
    "home. Name a path under /workspace, the run's own workspace, instead."
  const nameOf = (at: number, arg: string): string =>
    Buffer.byteLength(arg) <= 64 ? `command[${String(at)}], ${JSON.stringify(arg)},` : `command[${String(at)}]`
  const cases: readonly (readonly [readonly string[], number])[] = [
    [['cat', join(home, '.ssh', 'id_ed25519')], 1],
    [['ls', home], 1],
    [['cat', join(resolved, '.aws', 'credentials')], 1],
    [['cp', 'x', resolved], 2],
    [['ls', `type=bind,source=${home},target=/x`], 1],
  ]
  for (const [command, at] of cases) {
    const args = { command }
    const expected = refusal(nameOf(at, command[at] ?? ''))
    assert.equal(tools.argsRefusal(EXEC, args), expected, command.join(' '))
    const out = await tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.equal(out.text, `[refused] ${expected}`, command.join(' '))
    assert.ok(!out.text.includes(resolved) || command.some((arg) => arg.includes(resolved)), 'the resolved home is not told')
    // The real driver refuses the same command itself, in the audit's words.
    const workspace = join(d.sandbox.domains.trusted.mountRoot, 'run_d')
    mkdirSync(workspace, { recursive: true })
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
    assert.throws(
      () => real.run(spec),
      (e: unknown) => e instanceof ConfigError && /^docker args reference the home directory \(/.test(e.message),
      command.join(' '),
    )
    assert.equal(real.commandRefusal(command)?.startsWith('docker args reference the home directory ('), true)
  }
  assert.equal(spawned.length, 0, 'the real driver spawned nothing for a refused command')
  assert.equal(existsSync(join(d.sandbox.domains.trusted.mountRoot, 'run_r')), false, 'no workspace made')

  // A command that only mentions the home inside a longer argument is one
  // the audit admits, and so does the runner: it asks the driver, not a
  // check of its own.
  const inside = { command: ['sh', '-c', `cat ${home}/x`] }
  assert.equal(real.commandRefusal(inside.command), undefined)
  assert.equal(tools.argsRefusal(EXEC, inside), undefined)
  // And the fake refuses the home a test hands it, as the real driver does,
  // and none when it is handed none.
  assert.match(String(d.driver.commandRefusal(['ls', FAKE_HOME])), /^docker args reference the home directory \(\/Users\/operator\)$/)
  assert.equal(fakeSandbox({ imageId: IMAGE }).commandRefusal(['ls', FAKE_HOME]), undefined)
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
  // markers of a PEM block. A human would be shown a short preview that is
  // not cut, with the middle redacted; the gate denies it instead, before
  // anyone is asked, and the denial echoes none of it.
  const hidden = ['sh', '-c', `echo '${BEGIN_KEY}' >/dev/null; rm -rf /workspace/src; echo '${END_KEY}' >/dev/null; make test`]
  const w = wire(t, {
    script: [exec(['git', 'clone', 'x']), exec(hidden, 'call_2'), done()],
    exits: [{ stdout: 'cloned\n' }],
  })
  const asked = denyEveryApproval(w)
  const out = await w.loop.start({ runId: 'run_k', agent: w.agent('coder'), prompt: 'clone and test' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.equal(asked(), 0, 'no human was asked')
  assert.equal(w.driver.specs.length, 1, 'the command with the hidden span did not run')
  const denial = redactedRefusal('command[2] holds').replace(/^\[refused\] /, '')
  assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => [g.decision, g.reason]).slice(1), [['deny', denial]])
  assert.equal(payloads(w.store, 'tool.result').length, 1)
  assert.deepEqual(toolMessages(w.provider.requests[2]).slice(1), [`[denied] ${denial}`])

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

/** A model turn that calls sandbox.exec with `args` as they stand, whatever their shape. */
function execWith(args: Record<string, unknown>, id = 'call_1'): ScriptedResponse {
  return turn({
    role: 'assistant',
    content: null,
    tool_calls: [{ id, type: 'function', function: { name: 'sandbox__exec', arguments: JSON.stringify(args) } }],
  })
}

test('an exec whose arguments the runner refuses is refused before any approval is filed', async (t) => {
  // Every refusal the runner makes on the arguments alone
  // (SandboxTools.argsRefusal): the loop asks it before the gate, and the
  // gate denies the call (its rule 3c) rather than ask a human to approve a
  // command the runner would then refuse. On a tainted run's second exec,
  // which would otherwise wait for a human, no approval is filed and the run
  // is never parked; on a clean run's first, which the gate would otherwise
  // allow, no tool.call is written. Either way the denial is the runner's own
  // refusal, word for word, and nothing runs.
  const cases: readonly (readonly [string, Record<string, unknown>])[] = [
    ['one the approval preview would cut', argsOfSize(APPROVAL_PREVIEW_BYTES + 1)],
    ['one it would redact', { command: ['curl', '-H', 'Authorization: Bearer abc.def-123', 'https://x.test'] }],
    ['one holding a character a screen hides', { command: ['echo', 'left‮right'] }],
    ['one past an argument bound', { command: ['echo', 'x'.repeat(MAX_EXEC_ARG_BYTES + 1)] }],
    ['one with a key it does not take', { command: ['true'], env: { HOME: '/root' } }],
    ['one with no command', { cmd: 'true' }],
    ['one whose flag the driver audit refuses', { command: ['go', 'test', '-v'] }],
    ["one naming a path under the driver's home", { command: ['cat', `${FAKE_HOME}/.ssh/id_ed25519`] }],
    ["one naming the driver's home itself", { command: ['ls', '-la', FAKE_HOME] }],
  ]
  for (const [what, args] of cases) {
    // What the runner itself says of these arguments, when it is called.
    const d = direct(t, { exits: [] })
    const refused = await d.tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.ok(refused.text.startsWith('[refused] '), `${what}: ${refused.text.slice(0, 200)}`)
    const refusal = refused.text.slice('[refused] '.length)
    assert.equal(d.tools.argsRefusal(EXEC, args), refusal, `${what}: argsRefusal says what the runner refuses with`)

    const tainted = wire(t, { script: [exec(['git', 'clone', 'x']), execWith(args, 'call_2'), done()], exits: [{ stdout: 'cloned\n' }] })
    const asked = denyEveryApproval(tainted)
    const out = await tainted.loop.start({ runId: 'run_t', agent: tainted.agent('coder'), prompt: 'clone and go' })
    assert.equal(out.status, 'ok', `${what}: ${String(out.reason)}`)
    assert.equal(asked(), 0, `${what}: a human was asked`)
    assert.equal(tainted.store.query({ type: 'run.parked' }).length, 0, `${what}: the run was parked`)
    const gates = payloads(tainted.store, 'tool.gate')
    assert.deepEqual(gates.map((g) => [g.decision, g.taint, g.risk]), [['allow', 'clean', 'write'], ['deny', 'tainted', 'write']], what)
    assert.equal(gates[1]?.reason, refusal, what)
    assert.deepEqual(toolMessages(tainted.provider.requests[2]).slice(1), [`[denied] ${refusal}`], what)
    assert.equal(tainted.driver.specs.length, 1, `${what}: only the first exec ran`)
    assert.equal(tainted.store.query({ type: 'tool.call' }).length, 1, what)

    const clean = wire(t, { script: [execWith(args), done()], exits: [] })
    const first = await clean.loop.start({ runId: 'run_f', agent: clean.agent('coder'), prompt: 'go' })
    assert.equal(first.status, 'ok', `${what}: ${String(first.reason)}`)
    assert.deepEqual(payloads(clean.store, 'tool.gate').map((g) => [g.decision, g.reason]), [['deny', refusal]], what)
    assert.deepEqual(callRows(clean.store), ['tool.gate'], what)
    assert.equal(clean.driver.specs.length, 0, what)
    assert.equal(existsSync(join(clean.sandbox.domains.trusted.mountRoot, 'run_f')), false, `${what}: no workspace made`)
  }

  // Arguments the runner takes are put to a human on a tainted run as before,
  // and argsRefusal says nothing of a tool it reads no arguments for.
  const d = direct(t)
  assert.equal(d.tools.argsRefusal(EXEC, argsOfSize(APPROVAL_PREVIEW_BYTES)), undefined)
  assert.equal(d.tools.argsRefusal('sandbox.other', { anything: true }), undefined)
})

/**
 * Set the runner's sandbox config to pin `imageId` (none, for undefined): as
 * a kernel.yaml read anew would, which only a test does, since the kernel
 * reads it once at boot.
 */
function pinImage(sandbox: SandboxConfig, imageId: string | undefined): void {
  const mutable = sandbox as { imageId?: string }
  if (imageId === undefined) delete mutable.imageId
  else mutable.imageId = imageId
}

test('an exec on a kernel that pins no image id, or one that is no id, is refused before any approval is filed', async (t) => {
  // A refusal of every call, whatever its arguments (SandboxTools.
  // configRefusal): the loop offers no such kernel's run the tool (the test
  // below that it is not offered), and asks it again before the gate, which
  // denies a call of it (its rule 3c) on a run that starts tainted, where it
  // would otherwise ask a human, and on a clean one, where it would
  // otherwise allow it. A model's call reaches the gate only once offered,
  // so here the config pins an id at the offer and none at the call.
  const cases: readonly (readonly [string, string | undefined, RegExp])[] = [
    ['none pinned', undefined, /^sandbox\.imageId is not set in config\/kernel\.yaml, which ships none/],
    ['a tag', 'aos-worker:test', /^sandbox\.imageId "aos-worker:test" is no image id: it must be sha256:<64 lower-case hex>/],
  ]
  for (const [what, imageId, why] of cases) {
    // What the runner itself says, when it is called.
    const d = direct(t, { imageId })
    const refusal = d.tools.configRefusal(EXEC)
    assert.match(String(refusal), why, what)
    const args = { command: ['true'] }
    const refused = await d.tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.equal(refused.text, `[refused] ${String(refusal)}`, `${what}: configRefusal says what the runner refuses with`)

    for (const taint of ['tainted', 'clean'] as const) {
      const w: Wired = wire(t, {
        script: [
          () => {
            pinImage(w.sandbox, imageId)
            return exec(['true'])
          },
          done(),
        ],
        exits: [],
      })
      const asked = denyEveryApproval(w)
      const out = await w.loop.start({ runId: `run_${taint}`, agent: w.agent('coder'), prompt: 'go', taint })
      assert.equal(out.status, 'ok', `${what}, ${taint}: ${String(out.reason)}`)
      assert.equal(asked(), 0, `${what}, ${taint}: a human was asked`)
      assert.equal(w.store.query({ type: 'run.parked' }).length, 0, `${what}, ${taint}: the run was parked`)
      assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => [g.decision, g.taint, g.reason]), [['deny', taint, refusal]], `${what}, ${taint}`)
      assert.deepEqual(toolMessages(w.provider.requests[1]), [`[denied] ${String(refusal)}`], `${what}, ${taint}`)
      assert.deepEqual(callRows(w.store), ['tool.gate'], `${what}, ${taint}: no tool.call or tool.result`)
      assert.equal(w.driver.specs.length, 0, `${what}, ${taint}`)
    }

    // Arguments the runner refuses on their own too (a home in the
    // command): the gate's reason is the config's, the more fundamental, as
    // no call of the tool can run on this kernel whatever its arguments.
    const homeward = ['cat', `${FAKE_HOME}/.ssh/id_ed25519`]
    const argsWhy = d.tools.argsRefusal(EXEC, { command: homeward })
    assert.ok(argsWhy !== undefined && argsWhy !== refusal, `${what}: the runner refuses these arguments on their own`)
    const w: Wired = wire(t, {
      script: [
        () => {
          pinImage(w.sandbox, imageId)
          return exec(homeward)
        },
        done(),
      ],
      exits: [],
    })
    const asked = denyEveryApproval(w)
    const out = await w.loop.start({ runId: 'run_both', agent: w.agent('coder'), prompt: 'go', taint: 'tainted' })
    assert.equal(out.status, 'ok', `${what}: ${String(out.reason)}`)
    assert.equal(asked(), 0, `${what}: a human was asked`)
    assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => [g.decision, g.reason]), [['deny', refusal]], `${what}: the config's refusal first`)
    assert.equal(w.driver.specs.length, 0, what)
  }

  // A pinned id refuses nothing, and a ref the kernel implements none of is
  // not the config's to refuse.
  const d = direct(t)
  assert.equal(d.tools.configRefusal(EXEC), undefined)
  assert.equal(direct(t, { imageId: undefined }).tools.configRefusal('sandbox.other'), undefined)
})

/**
 * The fake driver until stub() is called, the apple-container stub after: as
 * a kernel.yaml read anew whose sandbox.driver names the stub would make it,
 * which only a test does, since the kernel builds its driver once at boot.
 */
function switching(base: FakeSandbox): SandboxDriver & { stub(): void } {
  const stub = new AppleContainerDriver()
  let now: SandboxDriver = base
  return {
    get name() {
      return now.name
    },
    probe: () => now.probe(),
    run: (spec) => now.run(spec),
    kill: (name) => now.kill(name),
    abandon: (name) => now.abandon(name),
    commandRefusal: (command) => now.commandRefusal(command),
    everyRunRefusal: () => now.everyRunRefusal(),
    sweepOrphans: (request) => now.sweepOrphans(request),
    stub: () => {
      now = stub
    },
  }
}

test('an exec on a kernel whose driver runs nothing, the apple-container stub, is never offered, and is refused before any approval is filed', async (t) => {
  // The stub's run() throws whatever it is handed: a fact of its code, read
  // before any approval (SandboxDriver.everyRunRefusal, SandboxTools.
  // configRefusal), not a probe's reading of a daemon. With an image id
  // pinned and a manifest that may hold the tool, no run is shown it, and a
  // call of it is denied by the gate (its rule 3c) on a run that starts
  // tainted, where it would otherwise ask a human, and on a clean one.
  const stub = new AppleContainerDriver()
  const why = stub.everyRunRefusal()
  assert.match(String(why), /^the apple-container driver is not implemented: macOS 15 has no `container` binary/)
  const probe = await stub.probe()
  assert.equal(probe.ok ? undefined : probe.why, why, "the probe's reason and the refusal are one")
  const neverSpawned = (): never => {
    throw new Error('the real driver spawned something')
  }
  assert.equal(realDriver(sandboxConfig(t), tmpdir(t), { spawn: neverSpawned, execFile: neverSpawned }).everyRunRefusal(), undefined)
  assert.equal(fakeSandbox({ imageId: IMAGE }).everyRunRefusal(), undefined)

  // What the runner itself says, when it is called: before any workspace.
  const d = direct(t)
  const tools = toolsOver(d, stub)
  assert.equal(tools.configRefusal(EXEC), why)
  assert.equal(tools.configRefusal('sandbox.other'), undefined)
  const args = { command: ['true'] }
  const refused = await tools.call(ticketFor('run_r', args), args, context('run_r'))
  assert.equal(refused.text, `[refused] ${String(why)}`)
  assert.deepEqual(callRows(d.store), ['tool.call', 'tool.result'])
  assert.equal(existsSync(join(d.sandbox.domains.trusted.mountRoot, 'run_r')), false, 'a workspace was made')

  // Not offered: the worker the manifest admits, with the tool in its list.
  const offeredNone = wire(t, { script: [done()], exits: [], driver: () => new AppleContainerDriver() })
  const out = await offeredNone.loop.start({ runId: 'run_o', agent: offeredNone.agent('coder'), prompt: 'anything' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.deepEqual(offered(offeredNone.provider.requests[0]), [])

  // Denied before the gate asks anyone. A model's call reaches the gate only
  // once offered, so the driver runs at the offer and is the stub at the call.
  for (const taint of ['tainted', 'clean'] as const) {
    let driver: ReturnType<typeof switching> | undefined
    const w = wire(t, {
      script: [
        () => {
          driver?.stub()
          return exec(['true'])
        },
        done(),
      ],
      exits: [],
      driver: (fake) => (driver = switching(fake)),
    })
    const asked = denyEveryApproval(w)
    const ran = await w.loop.start({ runId: `run_${taint}`, agent: w.agent('coder'), prompt: 'go', taint })
    assert.equal(ran.status, 'ok', `${taint}: ${String(ran.reason)}`)
    assert.deepEqual(offered(w.provider.requests[0]), ['sandbox__exec'], taint)
    assert.equal(asked(), 0, `${taint}: a human was asked`)
    assert.equal(w.store.query({ type: 'run.parked' }).length, 0, `${taint}: the run was parked`)
    assert.deepEqual(payloads(w.store, 'tool.gate').map((g) => [g.decision, g.taint, g.reason]), [['deny', taint, why]], taint)
    assert.deepEqual(toolMessages(w.provider.requests[1]), [`[denied] ${String(why)}`], taint)
    assert.deepEqual(callRows(w.store), ['tool.gate'], `${taint}: no tool.call or tool.result`)
    assert.equal(w.driver.specs.length, 0, taint)
  }

  // On a kernel that also pins no image id, the driver's refusal is the one
  // given: no image id would make a stub run.
  const unpinned = direct(t, { imageId: undefined })
  assert.equal(toolsOver(unpinned, stub).configRefusal(EXEC), why)
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
    abandon: (name) => base.abandon(name),
    commandRefusal: (command) => base.commandRefusal(command),
    everyRunRefusal: () => base.everyRunRefusal(),
    sweepOrphans: (request) => base.sweepOrphans(request),
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
    // Never asked: the child is gone before any wait on its result could end.
    kill: () => false,
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

/** A docker CLI child that runs until it is sent SIGKILL, and then ends as Node reports one killed by it. */
function hangingChild(signals: string[]): ChildLike {
  const handlers: Record<string, ((...a: never[]) => void)[]> = {}
  const child: ChildLike = {
    stdin: null,
    stdout: { on: () => undefined },
    stderr: { on: () => undefined },
    kill: (signal) => {
      signals.push(signal)
      setImmediate(() => {
        for (const event of ['exit', 'close']) {
          for (const cb of handlers[event] ?? []) (cb as (code: number | null, signal: string | null) => void)(null, signal)
        }
      })
      return true
    },
    on: ((event: string, cb: (...a: never[]) => void) => {
      ;(handlers[event] ??= []).push(cb)
      return child
    }) as ChildLike['on'],
  }
  return child
}

test('a driver whose result never settles is given up at its wallclock and a grace, its CLI ended and its container killed by name, and sandbox.killed records error', { timeout: 20_000 }, async (t) => {
  // The fake never ends a hung run on its own: one nothing kills is a driver
  // that never answers. The run has 60 ms left, so the container's wallclock
  // is 60 ms, and the runner waits 40 ms more before it gives it up.
  const d = direct(t, { exits: [{ hangs: true, stdout: 'half way\n' }] })
  const tools = toolsOver(d, d.driver, { resultGraceMs: 40, killWaitMs: 25 })
  const args = { command: ['sleep', 'infinity'] }
  const name = `${CONTAINER_PREFIX}run_g-1`
  // Should the runner wait with no bound, the run is stopped after 5 s, so
  // the call ends, the test fails on what it took, and nothing is left
  // waiting to hold the process open.
  const stuck = new AbortController()
  const guard = setTimeout(() => {
    stuck.abort()
  }, 5_000)
  guard.unref()
  const startedAt = Date.now()
  const out = await tools.call(ticketFor('run_g', args), args, context('run_g', { budget: { remainingMs: () => 60 }, signal: stuck.signal }))
  clearTimeout(guard)
  const took = Date.now() - startedAt
  assert.ok(took >= 95 && took < 5_000, `given up after ${String(took)} ms`)
  assert.deepEqual(d.driver.abandons, [name])
  assert.deepEqual(d.driver.kills, [], 'a give-up is not a requested kill')
  assert.equal(out.ok, false)
  assert.equal(out.taints, true)
  assert.equal(
    out.text,
    `[error] the driver never answered: ${name} had no result within 100 ms of its start (its wallclock of 60 ms and ` +
      `a grace of 40 ms), so the run gave it up; the driver was asked to end its docker client and kill ${name} by name`,
  )
  assert.deepEqual(callRows(d.store), ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'])
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }])
  // Nothing the container printed is read: the result was never given.
  assert.equal(out.text.includes('half way'), false)

  // The real driver, as it would be met: a daemon that accepts and never
  // answers holds the docker CLI and every kill by name. The driver's own
  // wallclock kill goes out at 60 ms and is never answered; at 100 ms the
  // runner gives the run up: the CLI is sent SIGKILL, the one process the
  // driver signals, and a second kill by name goes to the run's own domain,
  // which the runner waits 25 ms for.
  const r = direct(t)
  const signals: string[] = []
  const execs: string[] = []
  const real = realDriver(r.sandbox, tmpdir(t), {
    spawn: () => hangingChild(signals),
    execFile: (_cmd, cli, options) => {
      execs.push(`${options.env['DOCKER_HOST'] ?? '?'} ${cli.join(' ')}`)
      return new Promise(() => undefined)
    },
  })
  const given = await toolsOver(r, real, { resultGraceMs: 40, killWaitMs: 25 }).call(
    ticketFor('run_d', args),
    args,
    context('run_d', { budget: { remainingMs: () => 60 } }),
  )
  const realName = `${CONTAINER_PREFIX}run_d-1`
  assert.deepEqual(signals, ['SIGKILL'])
  const kill = `${r.sandbox.domains.trusted.dockerHost} kill --signal=KILL ${realName}`
  assert.deepEqual(execs, [kill, kill], 'the wallclock kill, then the give-up, each on the run\'s own domain only')
  assert.ok(
    given.text.endsWith(`the driver was asked to end its docker client and kill ${realName} by name, and no daemon answered within 25 ms`),
    given.text,
  )
  assert.deepEqual(payloads(r.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: realName, reason: 'error' }])

  // A result that settles within the bound is read, and nothing is given up.
  const quick = direct(t, { exits: [{ hangs: true }] })
  const stop = new AbortController()
  setTimeout(() => {
    stop.abort()
  }, 10)
  const stopped = await toolsOver(quick, quick.driver, { resultGraceMs: 40 }).call(
    ticketFor('run_s', args),
    args,
    context('run_s', { budget: { remainingMs: () => 60 }, signal: stop.signal }),
  )
  assert.match(stopped.text, /was killed: the run was stopped/)
  assert.deepEqual(quick.driver.abandons, [])
  assert.equal(payloads(quick.store, 'sandbox.killed')[0]?.reason, 'requested')
})

test('a run stopped while its driver never answers is given up at the stop and a grace, not at its wallclock, and sandbox.killed records error', { timeout: 10_000 }, async (t) => {
  // The stop's kill by name is sent to a daemon that accepts and never
  // answers, and ends nothing: the run's container has some 2 s of wallclock
  // left, and the stop at 10 ms gives the runner 40 ms more, not the rest of
  // that wallclock and the grace, before it gives it up.
  const d = direct(t, { exits: [{ hangs: true }] })
  const driver = withKill(d.driver, () => new Promise(() => undefined))
  const tools = toolsOver(d, driver, { resultGraceMs: 40, killWaitMs: 25 })
  const args = { command: ['sleep', 'infinity'] }
  const name = `${CONTAINER_PREFIX}run_k-1`
  const stop = new AbortController()
  setTimeout(() => {
    stop.abort()
  }, 10)
  // Should the wait hold on past the stop's grace, and past any bound, the
  // hung run is ended after 3 s as its docker CLI's end would end it, so the
  // call ends, the test fails on what it took, and nothing is left waiting to
  // hold the process open.
  const guard = setTimeout(() => {
    void d.driver.abandon(name)
  }, 3_000)
  guard.unref()
  const startedAt = Date.now()
  const out = await tools.call(ticketFor('run_k', args), args, context('run_k', { budget: { remainingMs: () => 2_000 }, signal: stop.signal }))
  clearTimeout(guard)
  const took = Date.now() - startedAt
  assert.ok(took >= 45 && took < 1_000, `given up after ${String(took)} ms`)
  assert.deepEqual(driver.kills, [name], "the stop's kill by name")
  assert.deepEqual(d.driver.abandons, [name])
  assert.equal(out.ok, false)
  assert.equal(
    out.text,
    `[error] the driver never answered: ${name} had no result within 40 ms of the run being stopped, which sent a ` +
      `kill by name to it, so the run gave it up; the driver was asked to end its docker client and kill ${name} by name`,
  )
  assert.deepEqual(callRows(d.store), ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'])
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }])
  assert.equal(getEventListeners(stop.signal, 'abort').length, 0, 'the wait left a listener on the run signal')

  // A stop with less of the bound left than the grace does not lengthen the
  // wait: the container's wallclock of 60 ms and the grace end it at 100 ms,
  // and a stop at 90 ms leaves that as it is.
  const late = direct(t, { exits: [{ hangs: true }] })
  const lateName = `${CONTAINER_PREFIX}run_m-1`
  const lateStop = new AbortController()
  setTimeout(() => {
    lateStop.abort()
  }, 90)
  const lateGuard = setTimeout(() => {
    void late.driver.abandon(lateName)
  }, 3_000)
  lateGuard.unref()
  const lateStartedAt = Date.now()
  const lateOut = await toolsOver(late, withKill(late.driver, () => new Promise(() => undefined)), { resultGraceMs: 40, killWaitMs: 25 }).call(
    ticketFor('run_m', args),
    args,
    context('run_m', { budget: { remainingMs: () => 60 }, signal: lateStop.signal }),
  )
  clearTimeout(lateGuard)
  assert.ok(Date.now() - lateStartedAt < 125, `given up after ${String(Date.now() - lateStartedAt)} ms, past the bound`)
  assert.match(lateOut.text, new RegExp(`^\\[error\\] the driver never answered: ${lateName} had no result within 100 ms of its start `))
  assert.deepEqual(late.driver.abandons, [lateName])
})

test("a container the log cannot record, whose kill ends nothing, is given up at its wallclock and a grace before the call fails", { timeout: 10_000 }, async (t) => {
  const d = direct(t, { exits: [{ hangs: true }] })
  // The kill by name reaches nothing, so the hung run never ends but by a give-up.
  const driver = withKill(d.driver, () => Promise.resolve())
  const append = d.store.append.bind(d.store)
  d.store.append = ((event: Parameters<EventStore['append']>[0]) => {
    if (event.type === 'sandbox.started') throw new Error('the log refused the row')
    return append(event)
  }) as EventStore['append']
  const args = { command: ['sleep', 'infinity'] }
  const startedAt = Date.now()
  const out = await toolsOver(d, driver, { resultGraceMs: 40 }).call(ticketFor('run_y', args), args, context('run_y', { budget: { remainingMs: () => 60 } }))
  assert.ok(Date.now() - startedAt >= 95, 'the call failed before the bound')
  assert.equal(out.text, 'the log refused the row')
  const name = `${CONTAINER_PREFIX}run_y-1`
  assert.deepEqual(driver.kills, [name])
  assert.deepEqual(d.driver.abandons, [name])
})

test('unset, the grace is RESULT_GRACE_MS, and the wait is held to a timer\'s limit', { timeout: 10_000 }, async (t) => {
  mock.timers.enable({ apis: ['setTimeout'] })
  t.after(() => {
    mock.timers.reset()
  })
  const d = direct(t, { exits: [{ hangs: true }] })
  const tools = toolsOver(d, d.driver)
  const args = { command: ['true'] }
  let ended = false
  const call = tools.call(ticketFor('run_w', args), args, context('run_w', { budget: { remainingMs: () => 1_000 } })).then((out) => {
    ended = true
    return out
  })
  // Bounded by count, not time: timers are mocked here.
  for (let i = 0; i < 1_000 && d.store.query({ type: 'sandbox.started' }).length === 0; i++) {
    await new Promise((resolve) => setImmediate(resolve))
  }
  assert.equal(d.store.query({ type: 'sandbox.started' }).length, 1, 'the container started')
  mock.timers.tick(1_000 + RESULT_GRACE_MS - 1)
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve))
  assert.equal(ended, false, 'still waiting one millisecond short of the wallclock and RESULT_GRACE_MS')
  assert.deepEqual(d.driver.abandons, [])
  mock.timers.tick(1)
  const out = await call
  assert.ok(out.text.includes(`(its wallclock of 1000 ms and a grace of ${String(RESULT_GRACE_MS)} ms)`), out.text)
  assert.equal(RESULT_GRACE_MS, 30_000)
  mock.timers.reset()

  // A container whose wallclock is a timer's limit is waited on for that
  // long, not past it: a delay over 2^31 - 1 ms fires at once, and the run
  // would be given up the moment it started.
  const long = direct(t, { exits: [{ hangs: true }] })
  const sandbox = { ...long.sandbox, defaults: { ...long.sandbox.defaults, wallclockMs: MAX_TIMER_MS } }
  const stop = new AbortController()
  const pending = toolsOver(long, long.driver, { sandbox }).call(
    ticketFor('run_x', args),
    args,
    context('run_x', { budget: { remainingMs: () => MAX_TIMER_MS }, signal: stop.signal }),
  )
  await new Promise((resolve) => setTimeout(resolve, 50))
  assert.deepEqual(long.driver.abandons, [], 'given up before its wallclock')
  assert.equal(payloads(long.store, 'sandbox.started')[0]?.wallclockMs, MAX_TIMER_MS)
  stop.abort()
  const stopped = await pending
  assert.match(stopped.text, /was killed: the run was stopped/)
  assert.deepEqual(long.driver.abandons, [])
})

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
    abandon: (name) => d.driver.abandon(name),
    commandRefusal: (command) => d.driver.commandRefusal(command),
    everyRunRefusal: () => d.driver.everyRunRefusal(),
    sweepOrphans: (request) => d.driver.sweepOrphans(request),
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

test('a tool result of many short quoted lines near the budget still gets its llm.request row, cut to fit', async (t) => {
  // The next llm.request carries the exec's result inside its prompt, the
  // provider's JSON body, which escapes every quote and newline once; the
  // log's canonical JSON escapes that prompt again, so a quote the result
  // shows as one byte takes four there. Bounded by its raw bytes, the prompt
  // made that append throw (some 67 KiB for the 64 KiB limit) and ended the
  // run in error; bounded by its canonical size it is cut to fit, and the
  // run goes on. What the provider is sent is not cut: only what the log
  // keeps of it is.
  const line = 'print("abcdefg")\n'
  assert.equal(Buffer.byteLength(line), 17)
  const stdout = line.repeat(Math.ceil((70 * 1_024) / line.length))
  const w = wire(t, { script: [exec(['cat', 'lines.py']), done()], exits: [{ stdout }] })
  const out = await w.loop.start({ runId: 'run_q', agent: w.agent('coder'), prompt: 'show me the file' })
  assert.equal(out.status, 'ok', String(out.reason))
  const requests = w.store.query({ type: 'llm.request' })
  assert.equal(requests.length, 2)
  for (const row of w.store.query()) assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, row.type)
  const [first, second] = requests.map((row) => JSON.parse(row.payload) as { prompt: string })
  const sent = JSON.stringify(w.provider.requests[1]?.body)
  // The second prompt is cut, to a start of what was sent; the first, short,
  // is whole.
  assert.ok(second !== undefined && second.prompt.length < sent.length, 'the second prompt was not cut')
  assert.ok(sent.startsWith(second.prompt), 'the second prompt is not a start of what was sent')
  assert.ok(Buffer.byteLength(second.prompt) > 16 * 1_024, 'cut to far less than fits')
  assert.equal(first?.prompt, JSON.stringify(w.provider.requests[0]?.body))
  // The model was still told the whole result, as tool.result holds it.
  const [result] = payloads(w.store, 'tool.result')
  assert.deepEqual(toolMessages(w.provider.requests[1]), [String(result?.text)])
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
  `--- ${label} (its start, redacted: ${String(shown)} bytes, of the ${String(printed)} bytes its capture kept; the stream may have carried more) ---`

/** startHeading as a regular expression, for any count shown. */
const startHeadingRe = (label: string, printed = CAPTURE_MAX_BYTES): string =>
  literal(startHeading(label, 0, printed)).replace('redacted: 0 bytes', 'redacted: \\d+ bytes')

/** What an exec shows of its stdout, read by its end: the text after its heading. */
const shownEnd = (text: string): string | undefined =>
  /\n--- stdout \(its end, redacted: \d+ bytes, of the \d+ bytes it printed\) ---\n([\s\S]*)\n--- stderr \(0 bytes\) ---\n$/.exec(text)?.[1]

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
  // Nothing was cut to fit, and the stream is still shown by its window, not
  // whole: tool.result is marked cut, with the bytes and digest of the text,
  // which is the window short of its cut side.
  const [result] = payloads(d.store, 'tool.result')
  assert.equal(result?.truncated, true)
  assert.equal(result?.bytes, Buffer.byteLength(out.text))
  assert.equal(result?.sha256, sha256Hex(out.text))
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
  // bytes of, then a run of dots, which a Bearer credential would take too:
  // it is read from the newline after them, the first character no token
  // holds. Plain output follows, then key blocks redaction shrinks, so the
  // window fits its share and is shown from its edge on.
  const token = `ghp_${'Q7xK'.repeat(9)}`
  const tail = `\n${'.'.repeat(17_000)}\n${KEY_BLOCK.repeat(12)}${BUILD_LINES.slice(0, 5_000)}LAST LINE\n`
  const windowStart = STREAM_WINDOW_BYTES - (Buffer.byteLength(tail) + 20)
  assert.ok(windowStart > 0)
  const stdout = `${BUILD_LINES}${'.'.repeat(100_000)} ${token}${padTo(windowStart, '', '')}${tail}`
  const window = stdout.slice(stdout.length - STREAM_WINDOW_BYTES)
  assert.ok(window.startsWith(token.slice(-20) + '.'), 'the window starts inside the token')
  const read = redactString(window.slice(window.indexOf('\n')))
  assert.equal(window.indexOf('\n'), 20 + windowStart, 'read from the newline after the dots')
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

test("no redaction reads more than a window of a stream, so a MiB of BEGIN lines with no END, the PEM pattern's slow shape, costs milliseconds, not seconds", async (t) => {
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

/**
 * The heading and line of a stream withheld for a run JWT_RUN_STARTS_MAX
 * refuses, `printed` bytes: of a stream the driver `capped`, what its capture
 * kept, which the stream may have printed more than.
 */
const withheldPart = (label: string, printed: number, capped = false): string =>
  (capped
    ? `--- ${label} (withheld: the ${String(printed)} bytes its capture kept; the stream may have carried more) ---\n`
    : `--- ${label} (withheld: ${String(printed)} bytes printed) ---\n`) +
  `[withheld: what would be read of this stream holds a run of letters, digits, - and _ in which redact.ts's JWT ` +
  `pattern starts at more than ${String(JWT_RUN_STARTS_MAX)} places, which redaction reads in time quadratic in ` +
  `the run's length, so none of it is redacted or shown; ` +
  (capped ? `its capture kept ${String(printed)} bytes]` : `the stream printed ${String(printed)} bytes]`)

test("the JWT starts counted in a run are the places redact.ts's JWT pattern starts, a run ended by anything it does not take", () => {
  // Each `ey` that \b admits, as the pattern's own regular expression reads
  // it, counted within each stretch of [A-Za-z0-9_-]: the reference this
  // one-pass count must agree with.
  const reference = (text: string): number => {
    let most = 0
    for (const run of text.split(/[^A-Za-z0-9_-]+/)) {
      let starts = 0
      for (let i = 0; i < run.length; i++) {
        const at = /\bey/y
        // The character before the run is none it takes, so \b reads the run
        // alone as it reads it in the text.
        at.lastIndex = i
        if (at.test(run)) starts += 1
      }
      most = Math.max(most, starts)
    }
    return most
  }
  const rows: readonly [string, number][] = [
    ['', 0],
    ['ey', 1],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWhlcmU', 1],
    ['-ey'.repeat(17), 17],
    // Upper case and digits are segment characters, and word characters to
    // \b: they neither end a run nor admit a start after them.
    ['-eyA'.repeat(17), 17],
    ['-ey7'.repeat(17), 17],
    ['Aey', 0],
    ['7ey', 0],
    ['aey-ey', 1],
    ['_ey-ey', 1],
    ['0ey', 0],
    ['-ey-ey.-ey-ey-ey', 3],
    ['-ey-ey -ey', 2],
    ['é-ey€ey', 1],
    ['\u0000ey ey', 1],
    ['-eY-Ey-ey', 1],
    ['-e-y', 0],
  ]
  for (const [text, starts] of rows) {
    assert.equal(jwtRunStarts(text), starts, JSON.stringify(text))
    assert.equal(reference(text), starts, `the reference agrees: ${JSON.stringify(text)}`)
  }
  // And over text no row was written for: every mix of the characters that
  // decide a start.
  const alphabet = ['e', 'y', '-', '.', 'a', 'A', '7', '_', ' ', 'é']
  let seed = 7
  for (let n = 0; n < 2_000; n++) {
    let text = ''
    for (let i = 0; i < 40; i++) {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648
      text += alphabet[seed % alphabet.length] ?? ''
    }
    assert.equal(jwtRunStarts(text), reference(text), JSON.stringify(text))
  }
})

test('a window of -ey runs is withheld, or not read at all when its cut leaves no character no token holds, and costs milliseconds', async (t) => {
  // redact.ts's JWT pattern starts at every -ey and scans the rest of the run
  // from each: some 2 s for one redaction of 74 KiB of them, the daemon's
  // event loop blocked throughout, and as much again on every later
  // redaction of the result while it stays in the model's context.
  const run = (bytes: number): string => '-ey'.repeat(Math.ceil(bytes / 3)).slice(0, bytes)
  // A long stream whose window starts inside a key block a later END
  // closes, and is read from that END (pemOpenAt): what follows it is held
  // to the bound as well.
  const body = `MIIEvQIBADANBgkq${'Z'.repeat(47)}\n`.repeat(1_500)
  assert.ok(body.length > 90_000)
  const inBlock = `${BUILD_LINES}${BEGIN_KEY}\n${body}${END_KEY}\n${run(60_000)}\nLAST\n`
  const windowAt = inBlock.length - STREAM_WINDOW_BYTES
  assert.ok(windowAt > inBlock.indexOf(BEGIN_KEY) && windowAt < inBlock.indexOf(END_KEY), 'the window starts inside the block')
  const cases: readonly [string, ScriptedExit, 'stdout' | 'stderr', number, boolean?][] = [
    ['read whole', { exitCode: 1, stdout: run(STREAM_WINDOW_BYTES - 2) }, 'stdout', STREAM_WINDOW_BYTES - 2],
    // -eyA, the second shape: an upper-case letter is a segment character,
    // and a word character to \b, so the run goes on and each -ey starts.
    ['a run of -eyA, read whole', { exitCode: 1, stdout: `FIRST\n${'-eyA'.repeat(18_000)}\nLAST\n` }, 'stdout', 0],
    // Its window's cut lands in the first run, which every token pattern's
    // characters make up: it is read from the newline after it, the first
    // character no token holds, and so holds all of the second.
    ['read by its end', { exitCode: 1, stderr: `${BUILD_LINES}${run(200_000)}\n${run(60_000)}\n` }, 'stderr', BUILD_LINES.length + 260_002],
    ['read by its end, from the END closing a block its window starts in', { exitCode: 1, stdout: inBlock }, 'stdout', inBlock.length],
    // Its count is what the capture kept: the stream printed at least that.
    ['capped, read by its start', { exitCode: 1, stdout: run(CAPTURE_MAX_BYTES), truncated: true }, 'stdout', CAPTURE_MAX_BYTES, true],
    // One run of exactly as many starts as a window may hold, and one more,
    // amid plain lines.
    ['one start too many', { exitCode: 1, stdout: `FIRST\n${'-ey'.repeat(JWT_RUN_STARTS_MAX + 1)}\nLAST\n` }, 'stdout', 0],
  ]
  for (const [what, exit, label, printed, capped = false] of cases) {
    const d = direct(t, { exits: [exit] })
    const args = { command: ['make'] }
    const began = performance.now()
    const out = await d.tools.call(ticketFor('run_y', args), args, context('run_y'))
    const took = performance.now() - began
    assert.ok(took < 1_000, `${what}: the exec took ${String(Math.round(took))} ms`)
    const bytes = printed === 0 ? Buffer.byteLength(exit.stdout ?? '') : printed
    assert.ok(out.text.includes(`\n${withheldPart(label, bytes, capped)}`), `${what}: ${out.text.slice(0, 600)}`)
    assert.ok(!out.text.includes('-ey'), `${what}: no part of the run is shown`)
    const [result] = payloads(d.store, 'tool.result')
    assert.equal(result?.truncated, true, what)
    assert.equal(result?.sha256, sha256Hex(out.text), what)
    for (const row of d.store.query()) assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, what)
  }
  // A run past the cut that reaches the stream's end holds no character no
  // token holds, so none of it is read: nothing is redacted, or shown.
  const toEnd = `${BUILD_LINES}${run(200_000)}`
  const e = direct(t, { exits: [{ exitCode: 1, stdout: toEnd }] })
  const ended = await e.tools.call(ticketFor('run_y', { command: ['make'] }), { command: ['make'] }, context('run_y'))
  assert.equal(shownEnd(ended.text), '', 'nothing of a run that reaches the end is shown')
  // As many starts as a window may hold is redacted and shown as printed.
  const most = `FIRST\n${'-ey'.repeat(JWT_RUN_STARTS_MAX)}\nLAST\n`
  const d = direct(t, { exits: [{ exitCode: 1, stdout: most }] })
  const args = { command: ['make'] }
  const out = await d.tools.call(ticketFor('run_y', args), args, context('run_y'))
  assert.ok(out.text.includes(`\n--- stdout (${String(most.length)} bytes) ---\n${most}`), out.text)
})

test("a long stream's window that starts inside an unterminated key block shows nothing up to the first END printed after it, even one the window's redaction paired with a later BEGIN", async (t) => {
  const args = { command: ['make'] }
  const head = 'aos-run-run_k-1 on the trusted domain, no network, exited 1 after 1 ms'
  const endPart = (shown: string, printed: number): string =>
    `--- stdout (its end, redacted: ${String(Buffer.byteLength(shown))} bytes, of the ${String(printed)} bytes it printed) ---\n${shown}`
  const body = `MIIEvQIBADANBgkq${'Z'.repeat(47)}\n`.repeat(1_500)
  assert.ok(body.length > 90_000)
  // A BEGIN with no END of its own, then a whole key block: a redaction of
  // the whole stream pairs the first BEGIN with the block's END and hides all
  // between; the window's pairs the block's own two markers, and holds no END
  // left over.
  const paired = `${BUILD_LINES}${BEGIN_KEY}\n${body}${KEY_BLOCK}LAST LINE\n`
  assert.equal(redactString(paired), `${BUILD_LINES}[REDACTED]\nLAST LINE\n`)
  const window = paired.slice(paired.length - STREAM_WINDOW_BYTES)
  assert.ok(!PEM_END.test(redactString(window)), "the window's redaction leaves no END")
  // Two ENDs after the BEGIN: the first closes it, the second closes nothing,
  // and what stands between them is shown.
  const twice = `${BUILD_LINES}${BEGIN_KEY}\n${body}${END_KEY}\nBETWEEN\n${END_KEY}\nAFTER\n`
  // No END at all: nothing of the window is shown.
  const open = `${BUILD_LINES}${BEGIN_KEY}\n${body}LAST LINE\n`
  const cases: readonly [string, string, string][] = [
    ['an END the window paired', paired, '\nLAST LINE\n'],
    ['two ENDs', twice, `\nBETWEEN\n${END_KEY}\nAFTER\n`],
    ['no END', open, ''],
  ]
  for (const [what, stdout, shown] of cases) {
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
    assert.equal(out.text, `${head}\n${endPart(shown, stdout.length)}\n--- stderr (0 bytes) ---\n`, what)
    for (const piece of ['MIIEvQ', 'ZZZZ']) assert.ok(!out.text.includes(piece), `${what}: ${piece}`)
  }
  // A window that starts outside any block, holding two ENDs with no BEGIN
  // before them past its edge: nothing up to the first is shown, and what
  // stands between the two is.
  const stray = `${BUILD_LINES}${'.'.repeat(100_000)}\n${'.'.repeat(STREAM_WINDOW_BYTES - 10_000)}\n${END_KEY}\nBETWEEN\n${END_KEY}\nAFTER\n`
  const d = direct(t, { exits: [{ exitCode: 1, stdout: stray }] })
  const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
  assert.equal(out.text, `${head}\n${endPart(`\nBETWEEN\n${END_KEY}\nAFTER\n`, stray.length)}\n--- stderr (0 bytes) ---\n`)
})

test("a long stream's window that starts inside a key block is read from the first END the token patterns leave whole, not one an AWS id, a Bearer or a token's run breaks", async (t) => {
  const args = { command: ['make'] }
  const head = 'aos-run-run_k-1 on the trusted domain, no network, exited 1 after 1 ms'
  const endPart = (shown: string, printed: number): string =>
    `--- stdout (its end, redacted: ${String(Buffer.byteLength(shown))} bytes, of the ${String(printed)} bytes it printed) ---\n${shown}`
  const body = `MIIEvQIBADANBgkq${'Z'.repeat(47)}\n`.repeat(1_500)
  const second = `SECONDBODY${'Q'.repeat(53)}\n`.repeat(10)
  // redact.ts runs its token patterns before its PEM pattern, so a token
  // that overlaps the first END leaves no END there: a redaction of the whole
  // stream pairs the BEGIN with the next END, and hides the SECONDBODY lines.
  const broken: readonly [string, string][] = [
    ['an AWS key id inside the END', '-----END AKIAABCDEFGHIJKLMNOP PRIVATE KEY-----'],
    ['a Bearer before the END', `Bearer\n${END_KEY}`],
    ["a JWT's last segment run into the END", `eyAAAAAAAAAA.eyBBBBBBBBBB.cc${END_KEY}`],
    ["an sk- key's run into the END", `sk-AAAAAAAA${END_KEY}`],
  ]
  for (const [what, end] of broken) {
    const stdout = `${BUILD_LINES}${BEGIN_KEY}\n${body}${end}\n${second}${END_KEY}\nLAST\n`
    const windowAt = stdout.length - STREAM_WINDOW_BYTES
    assert.ok(windowAt > stdout.indexOf(BEGIN_KEY) && windowAt < stdout.indexOf(end), `${what}: the window starts inside the block`)
    assert.ok(PEM_END.test(end), `${what}: the raw text holds an END there`)
    assert.equal(redactString(stdout), `${BUILD_LINES}[REDACTED]\nLAST\n`, `${what}: the stream's redaction hides up to the second END`)
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
    assert.equal(out.text, `${head}\n${endPart('\nLAST\n', stdout.length)}\n--- stderr (0 bytes) ---\n`, what)
    for (const piece of ['SECONDBODY', 'MIIEvQ', 'ZZZZ']) assert.ok(!out.text.includes(piece), `${what}: ${piece}`)
  }
  // A window that starts past such an END, inside the block it leaves open,
  // whose own redaction pairs the END that closes that block with a later
  // BEGIN, and holds no END left over: the stream's redaction hides all of
  // it up to that END, the later BEGIN among it.
  const late = `${BUILD_LINES}${BEGIN_KEY}\n${body.slice(0, 6_400)}${broken[0]?.[1] ?? ''}\n${'SECONDBODY\n'.repeat(9_000)}${KEY_BLOCK}LAST\n`
  const windowAt = late.length - STREAM_WINDOW_BYTES
  assert.ok(windowAt > late.indexOf('SECONDBODY') && windowAt < late.lastIndexOf(BEGIN_KEY), 'the window starts in the SECONDBODY lines')
  assert.equal(redactString(late), `${BUILD_LINES}[REDACTED]\nLAST\n`)
  assert.ok(!PEM_END.test(redactString(late.slice(windowAt))), "the window's redaction leaves no END")
  const d = direct(t, { exits: [{ exitCode: 1, stdout: late }] })
  const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
  assert.equal(out.text, `${head}\n${endPart('\nLAST\n', late.length)}\n--- stderr (0 bytes) ---\n`)
})

test("a long stream's window that starts inside a key block, however the stream's redaction pairs the markers before it, shows none of the block", async (t) => {
  const args = { command: ['make'] }
  const body = `MIIEvQIBADANBgkq${'Z'.repeat(47)}\n`.repeat(1_500)
  const secret = `SECONDBODY${'Q'.repeat(53)}\n`.repeat(1_200)
  // A BEGIN whose greedy marker holds an END: redact.ts reads the line as one
  // BEGIN when an END follows it, and pairs it with that END.
  const holdsEnd = '-----BEGIN Q PRIVATE KEY----- -----END Q PRIVATE KEY-----'
  // A BEGIN an AWS key id breaks, holding a BEGIN that reaches a PRIVATE
  // KEY----- past the outer one's 100 characters: redact.ts opens a block at
  // the inner BEGIN, whose marker runs on past the END inside it.
  const nested = `-----BEGIN AKIAABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY-----${'A'.repeat(50)} -----END Q PRIVATE KEY-----`
  // Each stream, and what is shown of it: from the END that ends the last
  // block that may hold the window's start, or nothing when no END the token
  // patterns surely leave whole does.
  const rows: readonly [string, string, string][] = [
    // An END that pemEndHolds refuses and redact.ts keeps closes the first
    // block; a single chain then closes on the END inside the next BEGIN.
    ['v1, a refused END, then a BEGIN holding an END', `${BUILD_LINES}${BEGIN_KEY}\nAAAA\nabc${END_KEY}\n${holdsEnd}\n${secret}${KEY_BLOCK}LAST\n`, '\nLAST\n'],
    // A key block after the END that ends them is shown as its own: hidden.
    ['v1, a key block after', `${BUILD_LINES}${BEGIN_KEY}\nAAAA\nabc${END_KEY}\n${holdsEnd}\n${secret}${KEY_BLOCK}MIDDLE\n${KEY_BLOCK}LAST\n`, '\nMIDDLE\n[REDACTED]\nLAST\n'],
    // The last END follows a Q, a token character, so none is surely whole.
    ['v2, the window starts in the first block, its END refused', `${BUILD_LINES}${BEGIN_KEY}\n${body}abc${END_KEY}\n${holdsEnd}\n${secret.slice(0, 38_000)}${END_KEY}\nLAST\n`, ''],
    ['v2, its last END on a line of its own', `${BUILD_LINES}${BEGIN_KEY}\n${body}abc${END_KEY}\n${holdsEnd}\n${secret.slice(0, 38_016)}${END_KEY}\nLAST\n`, '\nLAST\n'],
    ['v3, a BEGIN inside an END marker', `${BUILD_LINES}${BEGIN_KEY}\nAAAA\nabc${END_KEY}\n-----END -----BEGIN Q PRIVATE KEY-----\n${secret}${KEY_BLOCK}LAST\n`, '\nLAST\n'],
    ['v4, a BEGIN an AWS id breaks', `${BUILD_LINES}-----BEGIN AKIAABCDEFGHIJKLMNOP PRIVATE KEY-----\nAAAA\n${holdsEnd}\n${secret}${KEY_BLOCK}LAST\n`, '\nLAST\n'],
    ['v5, an END Bearer breaks, holding one it does not', `${BUILD_LINES}${BEGIN_KEY}\nAAAA\nBearer -----END -----END RSA PRIVATE KEY-----\n${holdsEnd}\n${secret}${KEY_BLOCK}LAST\n`, '\nLAST\n'],
    ['v6, a BEGIN inside a BEGIN an AWS id breaks', `${BUILD_LINES}${nested}\n${secret}${KEY_BLOCK}LAST\n`, '\nLAST\n'],
    // An END inside an END that Bearer breaks is one redact.ts keeps, and
    // closes the block: what follows it is shown.
    ['v7, an END inside an END Bearer breaks', `${BUILD_LINES}${BEGIN_KEY}\n${body}Bearer -----END -----END RSA PRIVATE KEY-----\nAFTER\nLAST\n`, '\nAFTER\nLAST\n'],
  ]
  for (const [what, stdout, expected] of rows) {
    const whole = redactString(stdout)
    assert.ok(!whole.includes('SECONDBODY'), `${what}: the stream's redaction hides every SECONDBODY line`)
    const windowAt = stdout.length - STREAM_WINDOW_BYTES
    assert.ok(windowAt > stdout.indexOf('SECONDBODY') || windowAt < stdout.indexOf(holdsEnd), `${what}: the window starts inside what is hidden`)
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
    const shown = shownEnd(out.text)
    assert.equal(shown, expected, what)
    assert.ok(whole.endsWith(expected), `${what}: what is shown is what the stream's redaction leaves`)
    for (const piece of ['SECONDBODY', 'MIIEvQ', 'ZZZZ']) assert.ok(!out.text.includes(piece), `${what}: ${piece}`)
  }
})

test("a long stream's window whose cut a token crosses, or follows a word character, is read from the first character at or past the cut that no token holds, and shows only an end of what the stream's redaction shows", async (t) => {
  const args = { command: ['make'] }
  const secret = `SECRETBODY${'Q'.repeat(53)}\n`.repeat(600)
  // A BEGIN inside the block's body, and the block's END after it: redact.ts
  // pairs the first BEGIN with that END and hides all between.
  const rest = `${secret}${BEGIN_KEY}\nBODY2\n${END_KEY}\n`
  // Each row: what stands just before the cut, and the opener the window
  // starts with. In the stream no token breaks the opener's BEGIN; read from
  // the cut, a token starts in the window that breaks it, so the window's
  // redaction pairs the later BEGIN with the END and leaves no END for pemCut
  // to cut to. A word character before the cut keeps a token from starting
  // at the window's first character in the stream (every token pattern is
  // \b-led). A token that crosses the cut, and runs a few bytes past it,
  // keeps one from starting inside its run in the stream: the token holds
  // those bytes, and its pattern's search goes on past it, where the
  // window's starts at the cut and finds a token of a pattern whose turn
  // comes no earlier, inside the run, that runs on past where the crossing
  // one ends: a Bearer credential reaches through white space after its
  // word, and a JWT through dots, which an sk- key, a Slack key or a JWT's
  // last segment does not take. Reading past the word characters the window
  // starts with closes only the first kind.
  const rows: readonly [string, string, string][] = [
    ['an sk- key after a word character', 'x', `sk-AAAAAAAA${BEGIN_KEY}\n`],
    ['a Bearer after a word character', 'x', `Bearer ${BEGIN_KEY}\n`],
    ['a JWT after a word character', 'x', 'eyAAAAAAAAAA.eyBBBBBBBBBB.-----BEGINX PRIVATE KEY-----\n'],
    ['a Bearer inside a Bearer credential, after a -', `Bearer ${'a'.repeat(20)}`, `aa-Bearer ${BEGIN_KEY}\n`],
    ['a Bearer inside a Bearer credential, after a .', `Bearer ${'a'.repeat(20)}`, `aa.Bearer ${BEGIN_KEY}\n`],
    ['a Bearer inside a Bearer credential, after a ~', `Bearer ${'a'.repeat(20)}`, `aa~Bearer ${BEGIN_KEY}\n`],
    ['a Bearer inside a Bearer credential, after a +', `Bearer ${'a'.repeat(20)}`, `aa+Bearer ${BEGIN_KEY}\n`],
    ['a Bearer inside a Bearer credential, after a /', `Bearer ${'a'.repeat(20)}`, `aa/Bearer ${BEGIN_KEY}\n`],
    ["a Bearer inside a Bearer's white space and credential", 'Bearer ', ` aa-Bearer ${BEGIN_KEY}\n`],
    ['a JWT inside an sk- key', 'sk-AAAAAAAA', 'AA-eyAAAAAAAAAA.eyBBBBBBBBBB.-----BEGINX PRIVATE KEY-----\n'],
    ['a JWT inside a Slack key', 'xoxb-AAAAAAAAAA', 'AA-eyAAAAAAAAAA.eyBBBBBBBBBB.-----BEGINX PRIVATE KEY-----\n'],
    ['a JWT inside an app-level Slack key', 'xapp-AAAAAAAAAA', 'AA-eyAAAAAAAAAA.eyBBBBBBBBBB.-----BEGINX PRIVATE KEY-----\n'],
    ["a JWT inside a JWT's last segment", 'eyAAAAAAAAAA.eyBBBBBBBBBB.CCCC', 'CCCCCC-eyDDDDDDDDDD.eyEEEEEEEEEE.-----BEGINX PRIVATE KEY-----\n'],
  ]
  for (const [what, before, opener] of rows) {
    const window = padTo(STREAM_WINDOW_BYTES, `${opener}${rest}`, 'LAST\n')
    const stdout = `${'.'.repeat(30_000)}\n${before}${window}`
    assert.equal(stdout.slice(stdout.length - STREAM_WINDOW_BYTES), window, `${what}: the window starts at the opener`)
    const whole = redactString(stdout)
    assert.ok(!whole.includes('SECRETBODY'), `${what}: the stream's redaction hides every SECRETBODY line`)
    // Read from the cut, the window shows key body past its edge, and holds
    // no END to cut to; read past the word characters it starts with, so
    // too, but for a word character before the cut.
    const shows = (read: string): boolean => !PEM_END.test(read) && read.slice(CAPTURE_EDGE_BYTES).includes('SECRETBODY')
    assert.ok(shows(redactString(window)), `${what}: read from the cut, the window shows key body`)
    assert.equal(shows(redactString(window.replace(/^\w+/, ''))), before !== 'x', `${what}: read past the word characters it starts with`)
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const out = await d.tools.call(ticketFor('run_w', args), args, context('run_w'))
    const shown = shownEnd(out.text)
    assert.ok(!out.text.includes('SECRETBODY'), `${what}: no SECRETBODY line is shown`)
    assert.ok(!JSON.stringify(payloads(d.store, 'tool.result')).includes('SECRETBODY'), `${what}: none is logged`)
    assert.ok(shown !== undefined && shown.endsWith('LAST\n'), `${what}: the end is shown`)
    assert.ok(whole.endsWith(shown), `${what}: what is shown is an end of what the stream's redaction shows`)
  }
  // Where the window is read from: the cut when the character before it is
  // one no token holds, or the character after it is, and else the first
  // such character past it. A space or a newline is none a token holds, but
  // for white space just after a Bearer, which its \s+ takes. Key blocks
  // shrink the window to fit its share, so it is shown from its edge on.
  const plain = (lead: string): string => padTo(STREAM_WINDOW_BYTES, `${lead}${'.'.repeat(CAPTURE_EDGE_BYTES - 1)}SHOWN\n`, `${KEY_BLOCK.repeat(3)}LAST\n`)
  const reads: readonly [string, string, string, boolean][] = [
    // What stands before the cut, the window's first character, and whether
    // it is read from the cut.
    ['a word character, then a space', 'x', ' ', true],
    ['a word character, then a newline', 'x', '\n', true],
    ['a space, then a word character', ' ', 'x', true],
    ['a newline, then a -', '\n', '-', true],
    ['a comma, then a word character', ',', 'x', true],
    ['a word character, then a -', 'x', '-', false],
    ['a word character, then a .', 'x', '.', false],
    // Bearer's \s+ takes the space after the cut, and its credential the
    // dots and SHOWN: the stream's redaction hides them.
    ['a Bearer, then a space', 'Bearer', ' ', false],
    ['a Bearer and a newline, then a space', 'Bearer\n', ' ', false],
  ]
  for (const [what, before, lead, fromCut] of reads) {
    const window = plain(lead)
    const stdout = `${BUILD_LINES}${before}${window}`
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const out = await d.tools.call(ticketFor('run_w', args), args, context('run_w'))
    const shown = shownEnd(out.text)
    // Read from past the cut, it is read from the newline after SHOWN.
    const from = fromCut ? window : window.slice(window.indexOf('\n', 1))
    assert.equal(shown, redactString(from).slice(CAPTURE_EDGE_BYTES), what)
    assert.equal(shown?.startsWith('SHOWN\n'), fromCut, what)
    assert.ok(redactString(stdout).endsWith(shown), `${what}: what is shown is an end of what the stream's redaction shows`)
  }
})

test("an end window is read from where no match of redact.ts's token patterns runs across, so they read the stream there as they read its two sides apart", () => {
  // tokenFreeStart's characters are read off these patterns: one added to
  // redact.ts, or changed, must be read again before this pin moves.
  assert.deepEqual(
    TOKEN_PATTERNS.filter((re) => !re.source.includes('PRIVATE KEY')).map((re) => `/${re.source}/${re.flags}`),
    [
      '/\\bBearer\\s+[A-Za-z0-9._~+/-]+=*/g',
      '/\\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}/g',
      '/\\bgh[pousr]_[A-Za-z0-9]{20,}/g',
      '/\\bgithub_pat_[A-Za-z0-9_]{20,}/g',
      '/\\bxox[abeprs]-[A-Za-z0-9-]{10,}/g',
      '/\\bxapp-[A-Za-z0-9-]{10,}/g',
      '/\\b(?:AKIA|ASIA)[A-Z2-7]{16}\\b/g',
      '/\\bey[A-Za-z0-9_-]{10,}\\.ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b/g',
    ],
  )
  // No PEM marker in any of these, so redactString is the token patterns'
  // pass alone. Split at the place tokenFreeStart gives, each side redacted
  // apart reads as the whole does; split at the cut itself, often not.
  const splitHolds = (text: string, at: number): boolean => redactString(text) === redactString(text.slice(0, at)) + redactString(text.slice(at))
  const rows: readonly [string, string, string, boolean][] = [
    // Before the cut, after it, and whether it is read from past the cut,
    // where a split at the cut does not hold.
    ['a Bearer credential, a Bearer inside it', `Bearer ${'a'.repeat(20)}`, 'aa-Bearer -----BEGIN x', true],
    ["a Bearer's white space", 'Bearer ', ' aa-Bearer xyz==', true],
    ["a Bearer's white space across a newline", 'Bearer\n', '  tok.en/x+y~z= more', true],
    ['a JWT inside an sk- key', 'sk-AAAAAAAA', 'AA-eyAAAAAAAAAA.eyBBBBBBBBBB.CCCCCCCCCCCC done', true],
    ["a JWT inside a JWT's last segment", 'eyAAAAAAAAAA.eyBBBBBBBBBB.CCCC', 'CCCCCC-eyDDDDDDDDDD.eyEEEEEEEEEE.FFFFFFFFFFFF ok', true],
    ['a word character, then an sk- key', 'x', 'sk-AAAAAAAAAAAA, then', true],
    // A character no token holds starts the window: it is read from the cut.
    ['an astral character first', 'abc', '😀sk-AAAAAAAAAAAA', false],
  ]
  for (const [what, before, after, past] of rows) {
    const text = `start ${before}${after}`
    const cut = text.length - after.length
    const at = tokenFreeStart(text, cut)
    assert.equal(at > cut, past, `${what}: read from past the cut`)
    assert.equal(splitHolds(text, cut), !past, `${what}: split at the cut`)
    assert.ok(splitHolds(text, at), `${what}: split where it is read from, at ${String(at - cut)}`)
  }
  // The cut itself, when the character before it, or the one at it, is one
  // no token holds; the stream's end when no such character follows.
  for (const [text, cut, at] of [
    ['abc def', 4, 4],
    ['abc def', 3, 3],
    ['abc,def', 5, 7],
    ['abc€def', 4, 4],
    ['Bearer  def', 7, 11],
    ['Bearer  def', 8, 11],
    ['Bearer x def', 8, 8],
    ['xBearer  def', 8, 12],
    ['ab😀cd', 2, 2],
    ['abcdef', 3, 6],
    ['', 0, 0],
  ] as const) {
    assert.equal(tokenFreeStart(text, cut), at, `${JSON.stringify(text)} at ${String(cut)}`)
  }
  // Over every mix of the pieces tokens are made of, at every cut: the place
  // it is read from lies at or past the cut, on a character's start, and the
  // split there holds.
  const pieces = ['Bearer', ' ', '\n', '\t', ' ', ' ', 'sk-', 'ant-', 'xoxb-', 'xapp-', 'ghp_', 'github_pat_', 'AKIA', 'ASIA', 'ey', 'eyAAAAAAAAAA.', 'ABCDEFGHIJKLMNOP', 'abcdefghij', '0123', '.', '-', '_', '=', '~', '+', '/', ',', ':', '"', 'é', '😀', '[', ']']
  let seed = 19
  let failsAtCut = 0
  for (let n = 0; n < 1_500; n++) {
    let text = ''
    for (let i = 0; i < 14; i++) {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648
      text += pieces[seed % pieces.length] ?? ''
    }
    for (let cut = 0; cut <= text.length; cut++) {
      const low = text.charCodeAt(cut)
      if (low >= 0xdc00 && low <= 0xdfff) continue
      const at = tokenFreeStart(text, cut)
      assert.ok(at >= cut && at <= text.length, JSON.stringify(text))
      const split = text.charCodeAt(at)
      assert.ok(!(split >= 0xdc00 && split <= 0xdfff), `split inside a character: ${JSON.stringify(text)} at ${String(at)}`)
      assert.ok(splitHolds(text, at), `${JSON.stringify(text)}, cut at ${String(cut)}, read from ${String(at)}`)
      if (!splitHolds(text, cut)) failsAtCut += 1
    }
  }
  assert.ok(failsAtCut > 1_000, `${String(failsAtCut)} cuts at which the split does not hold`)
})

test("over random streams of key blocks and markers that token patterns break, cut anywhere, just before a token's prefix, or inside a token that crosses the cut, an exec shows only an end of what the stream's redaction shows, and no line it hides", async (t) => {
  const pieces = [
    `${BEGIN_KEY}\n`,
    `${END_KEY}\n`,
    KEY_BLOCK,
    KEY_BLOCK,
    `abc${END_KEY}\n`,
    `Bearer ${END_KEY}\n`,
    `x.${END_KEY}\n`,
    '-----BEGIN Q PRIVATE KEY----- -----END Q PRIVATE KEY-----\n',
    '-----END -----BEGIN Q PRIVATE KEY-----\n',
    '-----BEGIN AKIAABCDEFGHIJKLMNOP PRIVATE KEY-----\n',
    '-----END AKIAABCDEFGHIJKLMNOP PRIVATE KEY-----\n',
    'Bearer -----END -----END RSA PRIVATE KEY-----\n',
    'sk-AAAAAAAA-----BEGIN PRIVATE KEY-----\n',
    `-----BEGIN AKIAABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY-----${'A'.repeat(50)} -----END Q PRIVATE KEY-----\n`,
  ]
  // Pieces led by a token's prefix whose run breaks the BEGIN after it, and
  // the characters a window's cut may follow just before one: a word
  // character, after which no token starts in the stream, or another.
  const openers = [
    'sk-AAAAAAAA-----BEGIN PRIVATE KEY-----\n',
    `Bearer ${BEGIN_KEY}\n`,
    'eyAAAAAAAAAA.eyBBBBBBBBBB.-----BEGINX PRIVATE KEY-----\n',
    'xoxb-AAAAAAAAAA-----BEGIN PRIVATE KEY-----\n',
    'xapp-AAAAAAAAAA-----BEGIN RSA PRIVATE KEY-----\n',
  ]
  const leads = ['x', '7', '_', 'Q', '-', '.', ' ', '\n']
  let seed = 3
  const rnd = (n: number): number => {
    seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648
    return seed % n
  }
  const args = { command: ['make'] }
  // Numbered sentinel lines between the pieces, each a line the stream's
  // redaction either hides or leaves whole.
  let sentinels = 0
  const piece = (from: readonly string[], lines = 1 + rnd(8)): string => {
    let text = from[rnd(from.length)] ?? ''
    for (let j = 0; j < lines; j++) text += `S${String(sentinels++).padStart(5, '0')}${'q'.repeat(1_500)}\n`
    return text
  }
  // How many sentinels the stream's redaction hides, each checked unshown,
  // and what is shown checked to be an end of what it shows.
  const hiddenIn = async (what: string, stdout: string): Promise<number> => {
    const whole = redactString(stdout)
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const out = await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
    const shown = shownEnd(out.text)
    assert.ok(shown !== undefined && whole.endsWith(shown), `${what}: what is shown is not an end of what the stream's redaction shows`)
    let hidden = 0
    for (let k = 0; k < sentinels; k++) {
      const tag = `S${String(k).padStart(5, '0')}`
      if (whole.includes(tag)) continue
      hidden += 1
      assert.ok(!out.text.includes(tag), `${what}: ${tag}, which the stream's redaction hides, is shown`)
    }
    return hidden
  }
  let cases = 0
  let hidden = 0
  for (let n = 0; n < 600; n++) {
    sentinels = 0
    let stdout = `${'f'.repeat(1_000)}\n`
    const count = 30 + rnd(40)
    for (let i = 0; i < count; i++) stdout += piece(pieces)
    stdout += 'LAST\n'
    if (Buffer.byteLength(stdout) <= STREAM_WINDOW_BYTES) continue
    cases += 1
    hidden += await hiddenIn(`case ${String(n)}`, stdout)
  }
  assert.ok(cases > 400 && hidden > 5_000, `${String(cases)} cases, ${String(hidden)} hidden sentinels`)
  // The window's cut placed: a lead, then the window, an opener first, as
  // much as 45 KB of lines after it, and a few pieces after those or as many
  // as fit, padded to exactly STREAM_WINDOW_BYTES. A token that starts at
  // the window's first character where the stream's starts none breaks the
  // opener's BEGIN, and the block it opens would be shown past the edge when
  // a later BEGIN takes its END and no END is left after.
  let placed = 0
  for (let n = 0; n < 300; n++) {
    sentinels = 0
    let before = `${'f'.repeat(1_000)}\n`
    const count = 5 + rnd(20)
    for (let i = 0; i < count; i++) before += piece(pieces)
    const lead = leads[rnd(leads.length)] ?? ''
    let window = piece(openers, 1 + rnd(30))
    for (let more = rnd(2) === 0 ? 1 + rnd(3) : Infinity; more > 0; more--) {
      const numbered = sentinels
      const next = piece(pieces)
      if (Buffer.byteLength(window + next) > STREAM_WINDOW_BYTES - 5) {
        sentinels = numbered
        break
      }
      window += next
    }
    window = padTo(STREAM_WINDOW_BYTES, window, 'LAST\n')
    const stdout = `${before}${lead}${window}`
    assert.equal(stdout.slice(stdout.length - STREAM_WINDOW_BYTES), window)
    placed += await hiddenIn(`placed case ${String(n)}, after ${JSON.stringify(lead)}`, stdout)
  }
  assert.ok(placed > 1, `${String(placed)} hidden sentinels in placed cases`)
  // The window's cut placed inside a token that crosses it, a few of its
  // bytes in the window: then a character the token may take, then an
  // opener. The crossing token holds those bytes, so the stream's patterns
  // start none inside them; a window read from its cut may start one there,
  // which runs on past where the crossing token ends and breaks the opener's
  // BEGIN.
  const crossing: readonly [string, string][] = [
    // The token's bytes before the cut, and after it.
    [`Bearer ${'a'.repeat(20)}`, 'aa'],
    ['Bearer ', ' aa'],
    ['Bearer\n', ' '],
    ['sk-AAAAAAAA', 'AA'],
    ['xoxb-AAAAAAAAAA', 'AA'],
    ['xapp-AAAAAAAAAA', 'AA'],
    ['eyAAAAAAAAAA.eyBBBBBBBBBB.CCCC', 'CCCCCC'],
    [`ghp_${'A'.repeat(20)}`, 'AA'],
  ]
  const joins = ['-', '.', '~', '+', '/', '_', '=', '', ' ', '\n']
  let crossed = 0
  for (let n = 0; n < 300; n++) {
    sentinels = 0
    let before = `${'f'.repeat(1_000)}\n`
    const count = 5 + rnd(20)
    for (let i = 0; i < count; i++) before += piece(pieces)
    const [head, rest] = crossing[rnd(crossing.length)] ?? ['', '']
    const join = joins[rnd(joins.length)] ?? ''
    let window = `${rest}${join}${piece(openers, 1 + rnd(30))}`
    for (let more = rnd(2) === 0 ? 1 + rnd(3) : Infinity; more > 0; more--) {
      const numbered = sentinels
      const next = piece(pieces)
      if (Buffer.byteLength(window + next) > STREAM_WINDOW_BYTES - 5) {
        sentinels = numbered
        break
      }
      window += next
    }
    window = padTo(STREAM_WINDOW_BYTES, window, 'LAST\n')
    const stdout = `${before}${head}${window}`
    assert.equal(stdout.slice(stdout.length - STREAM_WINDOW_BYTES), window)
    crossed += await hiddenIn(`crossed case ${String(n)}, ${JSON.stringify(head)} and ${JSON.stringify(rest + join)}`, stdout)
  }
  assert.ok(crossed > 1, `${String(crossed)} hidden sentinels in crossed cases`)
})

test("the walk of a long stream's markers is linear: a MiB of BEGINs, ENDs, or BEGINs holding ENDs costs milliseconds", async (t) => {
  const args = { command: ['make'] }
  const shapes: readonly [string, string][] = [
    ['BEGIN words', '-----BEGIN '.repeat(95_000)],
    ['END words', '-----END '.repeat(116_000)],
    ['BEGIN lines, no END', `${BEGIN_KEY}\n`.repeat(37_000)],
    ['BEGIN lines and refused ENDs', `${BEGIN_KEY}\nabc${END_KEY}\n`.repeat(18_000)],
    ['BEGIN holding END lines', '-----BEGIN Q PRIVATE KEY----- -----END Q PRIVATE KEY-----\n'.repeat(17_000)],
    ['long markers', `-----BEGIN ${'A '.repeat(45)}PRIVATE KEY-----\n`.repeat(8_800)],
    ['white space before ENDs', `${' '.repeat(60)}${END_KEY}`.repeat(12_000)],
  ]
  for (const [what, stdout] of shapes) {
    assert.ok(stdout.length > 900_000, what)
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const began = performance.now()
    await d.tools.call(ticketFor('run_k', args), args, context('run_k'))
    const took = performance.now() - began
    assert.ok(took < 2_000, `${what}: the exec took ${String(Math.round(took))} ms`)
  }
})

test('a stream of exactly STREAM_WINDOW_BYTES is read whole, and one byte more by its window', async (t) => {
  for (const bytes of [STREAM_WINDOW_BYTES, STREAM_WINDOW_BYTES + 1]) {
    // Lines, so a window cut inside one is read from its end, 62 bytes on:
    // a window of letters alone, which every token pattern's characters
    // make up, would be read from the stream's end, and show nothing.
    const stdout = `${'o'.repeat(63)}\n`.repeat(Math.ceil(bytes / 64)).slice(0, bytes)
    const d = direct(t, { exits: [{ exitCode: 1, stdout }] })
    const args = { command: ['make'] }
    const out = await d.tools.call(ticketFor('run_x', args), args, context('run_x'))
    const heading =
      bytes === STREAM_WINDOW_BYTES
        ? new RegExp(`\n--- stdout \\(${String(bytes)} bytes, cut to its last \\d+\\) ---\n`)
        : new RegExp(`\n--- stdout \\(its end, redacted: \\d+ bytes, of the ${String(bytes)} bytes it printed\\) ---\n`)
    assert.match(out.text, heading, String(bytes))
    // Read whole, the whole it stands for is the stream; by its window, the
    // window short of its edge.
    const whole = payloads(d.store, 'tool.result')[0]?.bytes
    const head = Buffer.byteLength(out.text.slice(0, out.text.indexOf('\n--- stdout')))
    if (bytes === STREAM_WINDOW_BYTES) assert.ok(typeof whole === 'number' && whole > head + bytes, String(whole))
    else assert.ok(typeof whole === 'number' && Math.abs(whole - (head + bytes - CAPTURE_EDGE_BYTES)) < 200, String(whole))
  }
})

test("a window's edge cut, shown when redaction shrinks the window to fit, lands on a whole character", async (t) => {
  for (const ch of ['€', '😀']) {
    for (let pad = 0; pad < 4; pad++) {
      // Read by its end: the window starts amid the characters, and the key
      // blocks after them shrink it, so its edge, 16 KiB in, is what is shown
      // first.
      const tail = `${ch.repeat(Math.ceil(30_000 / Buffer.byteLength(ch)))}${KEY_BLOCK.repeat(12)}LAST LINE\n`
      const stdout = `${'x'.repeat(100_000 + pad)}${tail}`
      const end = direct(t, { exits: [{ exitCode: 1, stdout }] })
      const args = { command: ['make'] }
      const out = await end.tools.call(ticketFor('run_u', args), args, context('run_u'))
      const shown = /--- stdout \(its end, redacted: \d+ bytes, of the \d+ bytes it printed\) ---\n([\s\S]*)\n--- stderr/.exec(out.text)?.[1]
      assert.ok(shown?.startsWith(ch) === true && shown.endsWith('[REDACTED]\nLAST LINE\n'), `${ch} ${String(pad)}: ${String(shown?.slice(0, 20))}`)
      assert.doesNotMatch(out.text, /�|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u, `${ch} ${String(pad)}`)
      assert.ok(Buffer.byteLength(shown) < STREAM_WINDOW_BYTES - CAPTURE_EDGE_BYTES - 40_000, 'the window was shrunk, and shown to its edge')

      // Capped, read by its start: key blocks first, then the characters past
      // the window's cut, so its edge, 16 KiB short of that cut, is what is
      // shown last.
      const start = `${'x'.repeat(pad)}${KEY_BLOCK.repeat(12)}FIRST LINE\n`
      const capped = padTo(CAPTURE_MAX_BYTES, `${start}${ch.repeat(Math.ceil(60_000 / Buffer.byteLength(ch)))}`, '')
      const head = direct(t, { exits: [{ exitCode: 1, stdout: capped, truncated: true }] })
      const cut = await head.tools.call(ticketFor('run_u', args), args, context('run_u'))
      const first = new RegExp(`${startHeadingRe('stdout')}\n([\\s\\S]*)\n--- stderr`).exec(cut.text)?.[1]
      assert.ok(first?.endsWith(ch) === true && first.includes('[REDACTED]\nFIRST LINE\n'), `${ch} ${String(pad)}: ${String(first?.slice(-20))}`)
      assert.doesNotMatch(cut.text, /�|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u, `${ch} ${String(pad)}`)
    }
  }
})

test('a driver whose kill refuses with a long text of quotes still gets its tool.result, the refusal cut to fit', async (t) => {
  const quotes = '"'.repeat(40_000)
  const cut = ` [cut: ${String(quotes.length)} bytes in all]`
  // A kill refused at length, and a signal no docker client reports, each
  // the driver's own text, in a head no share bounds.
  const cases: readonly [string, (base: FakeSandbox) => SandboxDriver][] = [
    ['a refusal', (base) => withKill(base, () => Promise.reject(new Error(quotes)))],
    [
      'a signal',
      (base) => ({
        name: base.name,
        probe: () => base.probe(),
        run: (spec) => {
          const running = base.run(spec)
          const result = running.result.then((r) => ({ ...r, signal: quotes as unknown as SandboxResult['signal'] }))
          return { ...running, result }
        },
        kill: (name) => base.kill(name),
        abandon: (name) => base.abandon(name),
        commandRefusal: (command) => base.commandRefusal(command),
        everyRunRefusal: () => base.everyRunRefusal(),
        sweepOrphans: (request) => base.sweepOrphans(request),
      }),
    ],
  ]
  for (const [what, make] of cases) {
    const d = direct(t, { exits: [{ exitCode: null }] })
    const args = { command: ['true'] }
    const out = await toolsOver(d, make(d.driver)).call(ticketFor('run_q', args), args, context('run_q'))
    assert.deepEqual(callRows(d.store), ['tool.call', 'sandbox.started', 'sandbox.killed', 'tool.result'], what)
    for (const row of d.store.query()) assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, what)
    const kept = '"'.repeat(DRIVER_TEXT_BYTES / 2)
    const said = what === 'a refusal' ? `and the driver refused it: ${kept}${cut}, as a docker client` : `ended with no exit status (${kept}${cut}) after`
    assert.ok(out.text.includes(said), `${what}: ${out.text.slice(0, 400)}`)
    assert.ok(!out.text.includes(`${kept}"`), `${what}: no more of it`)
  }

  // A channel run's docker client, ended by such a signal before its mux
  // sent the command's status: the same bound on the client's own text.
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true, exitCode: null }] })
  const make = cases[1]?.[1]
  assert.ok(make !== undefined)
  const args = { command: ['true'] }
  const call = toolsOver(d, make(d.driver), { egress: fx.egress }).call(ticketFor('run_q', args), args, context('run_q'))
  await until(() => d.driver.channels.length === 1, 'the channel')
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  d.driver.simulateExit(d.driver.channels[0]!.name)
  const out = await call
  for (const row of d.store.query()) assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, row.type)
  const kept = '"'.repeat(DRIVER_TEXT_BYTES / 2)
  assert.ok(out.text.includes(`the docker client ended with no exit status (${kept}${cut}) before the mux sent one`), out.text.slice(0, 900))
  assert.ok(!out.text.includes(`${kept}"`), 'no more of it')
})

test("a driver's text of exactly DRIVER_TEXT_BYTES payload bytes is shown whole, and one of a byte more is redacted, then cut and said to be", async (t) => {
  const refusing = (text: string) => (base: FakeSandbox): SandboxDriver => withKill(base, () => Promise.reject(new Error(text)))
  const signalling = (text: string) => (base: FakeSandbox): SandboxDriver => ({
    name: base.name,
    probe: () => base.probe(),
    run: (spec) => {
      const running = base.run(spec)
      const result = running.result.then((r) => ({ ...r, signal: text as unknown as SandboxResult['signal'] }))
      return { ...running, result }
    },
    kill: (name) => base.kill(name),
    abandon: (name) => base.abandon(name),
    commandRefusal: (command) => base.commandRefusal(command),
    everyRunRefusal: () => base.everyRunRefusal(),
    sweepOrphans: (request) => base.sweepOrphans(request),
  })
  // Counted in the bytes it takes in the log's JSON: 256 quotes are 512.
  const rows: readonly [string, string, string][] = [
    ['x at the bound', 'x'.repeat(DRIVER_TEXT_BYTES), 'x'.repeat(DRIVER_TEXT_BYTES)],
    ['x one past it', 'x'.repeat(DRIVER_TEXT_BYTES + 1), `${'x'.repeat(DRIVER_TEXT_BYTES)} [cut: ${String(DRIVER_TEXT_BYTES + 1)} bytes in all]`],
    ['quotes at the bound', '"'.repeat(DRIVER_TEXT_BYTES / 2), '"'.repeat(DRIVER_TEXT_BYTES / 2)],
    ['quotes one past it', '"'.repeat(DRIVER_TEXT_BYTES / 2 + 1), `${'"'.repeat(DRIVER_TEXT_BYTES / 2)} [cut: ${String(DRIVER_TEXT_BYTES / 2 + 1)} bytes in all]`],
    // Redacted, then cut: cut first, the bound would leave sk- and six
    // characters, too few for the pattern when boundOutput redacts again.
    ['a key across the bound', `${'x'.repeat(DRIVER_TEXT_BYTES - 10)} sk-${'A'.repeat(20)}`, `${'x'.repeat(DRIVER_TEXT_BYTES - 10)} [REDACTED [cut: ${String(DRIVER_TEXT_BYTES + 1)} bytes in all]`],
  ]
  for (const [what, text, shown] of rows) {
    for (const [how, make, said] of [
      ['a refusal', refusing(text), `and the driver refused it: ${shown}, as a docker client`],
      ['a signal', signalling(text), `ended with no exit status (${shown}) after`],
    ] as const) {
      const d = direct(t, { exits: [{ exitCode: null }] })
      const args = { command: ['true'] }
      const out = await toolsOver(d, make(d.driver)).call(ticketFor('run_q', args), args, context('run_q'))
      assert.ok(out.text.includes(said), `${what}, ${how}: ${out.text.slice(0, 900)}`)
      assert.equal(out.text.includes('[cut:'), shown.includes('[cut:'), `${what}, ${how}`)
      assert.ok(!out.text.includes('sk-'), `${what}, ${how}: part of a key is shown`)
    }
  }
})

test("the window cuts read redact.ts's PEM pattern's own markers", () => {
  const pem = TOKEN_PATTERNS.filter((re) => re.source.includes('PRIVATE KEY'))
  assert.equal(pem.length, 1)
  assert.equal(pem[0]?.source, `${PEM_BEGIN.source}[\\s\\S]*?${PEM_END.source}`)
  assert.equal(PEM_BEGIN.flags, '')
  assert.equal(PEM_END.flags, '')
})

test("an END is taken to close a block only when no token pattern can break it, as redact.ts's patterns read it in context", () => {
  // The one token pattern that can match inside a marker is redact.ts's own.
  assert.ok(TOKEN_PATTERNS.some((re) => re.source === AWS_KEY_ID.source), 'AWS_KEY_ID is a token pattern of redact.ts')
  assert.equal(AWS_KEY_ID.flags, '')
  const markers = [
    END_KEY,
    '-----END RSA PRIVATE KEY-----',
    '-----ENDXY PRIVATE KEY-----',
    '-----END PRIVATE KEY BLOCK-----',
    '-----END AKIAABCDEFGHIJKLMNOP PRIVATE KEY-----',
    '-----END-ASIA2345234523452345- PRIVATE KEY BLOCK-----',
  ]
  // Whether the END ending the text is one the PEM pattern still finds once
  // the token patterns have run over all of it.
  const survives = (text: string): boolean => new RegExp(`(?:${PEM_END.source})$`).test(redactString(text))
  const rows: readonly [string, string, boolean][] = [
    ['a line end before it', `abc==\n`, true],
    ['the stream starts with it', '', true],
    ['a Bearer with a value before the line end', 'Bearer x\n', true],
    ["a word ending in Bearer", 'xBearer\n', true],
    ['an = after a Bearer value', 'Bearer abc=', true],
    ['Bearer and a line end', 'Bearer\n', false],
    ['Bearer and white space', 'Bearer \t\u00a0', false],
    ['a token character', 'abc', false],
    ['a dot', 'x.', false],
  ]
  for (const [what, before, holds] of rows) {
    assert.equal(pemEndHolds(before + END_KEY, before.length, END_KEY), holds, what)
  }
  // Each character a Bearer credential takes that no other token's run
  // does, and two that others take too: Bearer's run reaches through it into
  // the END and breaks it, so it is never taken to hold.
  for (const ch of ['+', '~', '/', '_', '-']) {
    const text = `Bearer abc${ch}${END_KEY}`
    assert.equal(survives(text), false, `${ch}: redact.ts breaks it`)
    assert.equal(pemEndHolds(text, text.length - END_KEY.length, END_KEY), false, `${ch}: taken to hold`)
  }
  assert.equal(pemEndHolds(markers[4] ?? '', 0, markers[4] ?? ''), false, 'an AWS key id inside it')
  // Never taken to hold where redact.ts breaks it: over every mix of the
  // pieces a breaking token is made of, before every marker shape.
  const pieces = ['Bearer', ' ', '\n', '\t', '\u00a0', 'sk-', 'xoxb-', 'xapp-', 'ey', 'eyAAAAAAAAAA.eyBBBBBBBBBB.', 'ABCDEFGHIJ', 'abcdefghij', '.', '-', '_', '=', '~', '+', '/', ',', '7', 'AKIA', 'ghp_', 'github_pat_', ':', '"']
  let seed = 11
  const counted = { holds: 0, breaks: 0 }
  for (let n = 0; n < 4_000; n++) {
    let before = ''
    for (let i = 0; i < 6; i++) {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648
      before += pieces[seed % pieces.length] ?? ''
    }
    const marker = markers[n % markers.length] ?? END_KEY
    const text = before + marker
    if (pemEndHolds(text, before.length, marker)) {
      counted.holds += 1
      assert.ok(survives(text), `taken to hold, yet redact.ts breaks it: ${JSON.stringify(text)}`)
    } else if (!survives(text)) counted.breaks += 1
  }
  assert.ok(counted.holds > 200 && counted.breaks > 200, JSON.stringify(counted))
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
      abandon: (name) => d.driver.abandon(name),
      commandRefusal: (command) => d.driver.commandRefusal(command),
      everyRunRefusal: () => d.driver.everyRunRefusal(),
      sweepOrphans: (request) => d.driver.sweepOrphans(request),
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

// ── egress: grants, the channel and the session (egress plan W1) ────────────

/** kernel.yaml's shipped egress.limits. */
const EGRESS_LIMITS = Object.freeze({
  frameMaxBytes: 65_536,
  maxFlows: 16,
  maxHeaderBytes: 16_384,
  maxRequests: 2_000,
  maxBytes: 536_870_912,
  maxDenied: 20,
  idleMs: 60_000,
})

/** A binding value no credential pattern knows: only the kernel's care keeps it out of a row. */
const BINDING_VALUE = 'opaque-binding-value-7f3a9c2e1d5b'

/** One binding of every profile, on the fixture repository. */
const GITHUB = Object.freeze({ host: 'github.com', profiles: ['git-fetch', 'git-push', 'github-pulls'], repos: ['op/fixture'] })

/** A worker with egress: a credential-free registry and the github binding. */
const EGRESS_CODER = manifest('coder', { egress: { allow: ['registry.npmjs.org'], bind: ['github'] } })

interface EgressFixture {
  readonly egress: SandboxEgress
  readonly up: FakeUpstream
  /** The binding ids the injector was asked for, in order. */
  readonly injected: string[]
}

/**
 * The egress engine as boot builds it, over an in-process upstream, with the
 * kernel's own ready judge: ok and every binding resolved unless a test says
 * otherwise. The injector sets the binding's Bearer, as boot's sets the
 * broker's value.
 */
function egressOf(
  over: {
    state?: SandboxEgress['state']
    bindings?: SandboxEgress['bindings']
    resolved?: SandboxEgress['resolved']
    onStep?: (step: string) => void
  } = {},
): EgressFixture {
  const bindings = over.bindings ?? { github: GITHUB }
  const resolved = over.resolved ?? new Map(Object.keys(bindings).map((id) => [id, { bindingId: id, envVar: 'AOS_GITHUB_TOKEN' }]))
  const up = fakeUpstream(over.onStep)
  const injected: string[] = []
  const credential: CredentialInjector = (bindingId, set) => {
    injected.push(bindingId)
    set('Authorization', `Bearer ${BINDING_VALUE}`)
  }
  return {
    egress: { state: over.state ?? { state: 'ok' }, bindings, resolved, limits: EGRESS_LIMITS, upstream: up.upstream, credential, acceptReady },
    up,
    injected,
  }
}

const DEGRADED = { state: 'degraded', reason: 'egress.enabled is false in config/kernel.yaml, so no run is given a channel' } as const

test('exec with egress refuses with the egress reason when the state is not ok', async (t) => {
  const args = { command: ['git', 'clone', 'http://github.com/op/fixture.git'] }
  const allowOnly = manifest('coder', { egress: { allow: ['registry.npmjs.org'] } })
  // Three bindings on github.com, each git-fetch on 64 repositories: each
  // route within EgressGrant's bounds, 192 between them, and a
  // proxy.grant.issued row names at most PROXY_GRANT_MAX_REPOS (128). The
  // registry refuses such a manifest at load; one that reached the runner
  // anyway is refused at the offer and before the gate, by the row's bound,
  // never after a human approved it and its workspace was made.
  const wide = Object.fromEntries(
    [0, 1, 2].map((b) => [`gh-${String(b)}`, { host: 'github.com', profiles: ['git-fetch'], repos: Array.from({ length: 64 }, (_, i) => `op/b${String(b)}-r${String(i)}`) }]),
  )
  const narrow = Object.fromEntries(Object.keys(wide).map((id) => [id, { host: 'github.com', profiles: ['git-fetch'], repos: [`op/${id}`] }]))
  const cases: readonly {
    name: string
    egress: SandboxEgress | undefined
    files: string
    refusal: string
    registryBindings?: SandboxEgress['bindings']
  }[] = [
    {
      name: 'egress degraded',
      egress: egressOf({ state: DEGRADED }).egress,
      files: EGRESS_CODER,
      refusal: 'egress is degraded: egress.enabled is false in config/kernel.yaml, so no run is given a channel; no container was started',
    },
    {
      name: 'a binding that did not resolve',
      egress: egressOf({ resolved: new Map([['github', { bindingId: 'github', envVar: 'AOS_GITHUB_TOKEN', problem: 'AOS_GITHUB_TOKEN is not set (secrets.source: env)' }]]) }).egress,
      files: EGRESS_CODER,
      refusal: 'egress binding github (envVar AOS_GITHUB_TOKEN) did not resolve at boot: AOS_GITHUB_TOKEN is not set (secrets.source: env); no container was started',
    },
    {
      name: 'no egress engine wired',
      egress: undefined,
      files: allowOnly,
      refusal: 'coder has egress, and no egress engine is wired into this kernel, so its exec gets no channel; no container was started',
    },
    {
      name: 'a grant past the repositories one row records',
      egress: egressOf({ bindings: wide }).egress,
      registryBindings: narrow,
      files: manifest('coder', { egress: { bind: ['gh-0', 'gh-1', 'gh-2'] } }),
      refusal:
        "the grant coder's egress would be issued names 192 repositories across its bindings, and a proxy.grant.issued " +
        'row names at most 128, so it could not be recorded and is not issued; no container was started',
    },
  ]
  for (const c of cases) {
    const d = direct(t, {
      files: { coder: c.files },
      ...(c.egress === undefined ? {} : { egress: c.egress }),
      ...(c.registryBindings === undefined ? {} : { registryBindings: c.registryBindings }),
    })
    // Asked before the gate (with the run's id) and at the offer (without):
    // the same refusal, so no human is asked and no model is shown the tool.
    assert.equal(d.tools.egressRefusal(EXEC, 'coder', 'run_d'), c.refusal, c.name)
    assert.equal(d.tools.egressRefusal(EXEC, 'coder'), c.refusal, c.name)
    const out = await d.tools.call(ticketFor('run_d', args), args, context('run_d'))
    assert.equal(out.ok, false, c.name)
    assert.equal(out.text, `[refused] ${c.refusal}`, c.name)
    assert.equal(d.driver.specs.length, 0, `${c.name}: a container was started`)
    assert.deepEqual(payloads(d.store, 'proxy.grant.issued'), [], c.name)
    assert.deepEqual(payloads(d.store, 'sandbox.started'), [], c.name)
    assert.deepEqual(d.tools.liveGrants(), [], c.name)
    assert.equal(existsSync(join(d.sandbox.domains.trusted.mountRoot, 'run_d')), false, `${c.name}: a workspace was made`)
  }

  // The same kernel runs a manifest with no egress as it always did: no
  // channel, no grant, and its exec is offered.
  const plain = direct(t, { exits: [{ stdout: 'v24\n' }], egress: egressOf({ state: DEGRADED }).egress })
  assert.equal(plain.tools.egressRefusal(EXEC, 'coder', 'run_p'), undefined)
  const ran = await plain.tools.call(ticketFor('run_p', { command: ['node', '--version'] }), { command: ['node', '--version'] }, context('run_p'))
  assert.equal(ran.ok, true, ran.text)
  assert.equal('channel' in (plain.driver.specs[0] ?? {}), false)

  // Through the loop: a worker whose egress the kernel cannot serve is shown
  // no sandbox tool at all, so the model never spends a call on one.
  const w = wire(t, { script: [done()], exits: [], files: { coder: EGRESS_CODER }, egress: egressOf({ state: DEGRADED }).egress })
  const out = await w.loop.start({ runId: 'run_l', agent: w.agent('coder'), prompt: 'clone it' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.deepEqual(offered(w.provider.requests[0]), [])
})

test('grant issued before spawn, revoked on finish and on wallclock', async (t) => {
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }, { hangs: true }] })
  const order: string[] = []
  d.store.subscribe((row) => order.push(row.type))
  const run = d.driver.run.bind(d.driver)
  d.driver.run = (spec) => {
    order.push('spawn')
    return run(spec)
  }

  // Finished: the container's command exits 0, then the container.
  const args = { command: ['true'] }
  const first = d.tools.call(ticketFor('run_g', args), args, context('run_g'))
  await until(() => d.driver.channels.length === 1, 'the first channel')
  const [live] = d.tools.liveGrants()
  assert.ok(live !== undefined, 'no grant is live while its container runs')
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  mux.stdout('done\n')
  mux.exit(0)
  d.driver.simulateExit(d.driver.channels[0]!.name)
  const out = await first
  assert.equal(out.ok, true, out.text)
  assert.match(out.text, /^aos-run-run_g-1 on the trusted domain, no network but the kernel's egress engine \(grant grant_\d+_[0-9a-f]{12}: 0 request\(s\), 0 allowed, 0 denied\), exited 0 after \d+ ms\n/)
  assert.match(out.text, /--- stdout \(5 bytes\) ---\ndone\n/)
  const egressRows = order.filter((type) => /^(spawn|proxy\.grant\.|sandbox\.)/.test(type))
  assert.deepEqual(egressRows, ['proxy.grant.issued', 'spawn', 'sandbox.started', 'sandbox.killed', 'proxy.grant.revoked'])
  const [issued] = payloads(d.store, 'proxy.grant.issued')
  assert.deepEqual(issued, {
    schemaVersion: 1,
    grantId: live.grantId,
    purpose: 'exec',
    runId: 'run_g',
    agentId: 'coder',
    sandbox: 'aos-run-run_g-1',
    domain: 'trusted',
    allow: ['registry.npmjs.org'],
    routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }],
  })
  // The envelope's columns too, which W2's recovery reads.
  assert.deepEqual(
    d.store.query({ type: 'proxy.grant.issued' }).map((row) => [row.runId, row.agentId]),
    [['run_g', 'coder']],
  )
  assert.deepEqual(
    d.store.query({ type: 'proxy.grant.revoked' }).map((row) => [row.runId, row.agentId]),
    [['run_g', 'coder']],
  )
  const [revoked] = payloads(d.store, 'proxy.grant.revoked')
  assert.equal(revoked?.['grantId'], live.grantId)
  assert.equal(revoked?.['reason'], 'exited')
  assert.deepEqual(Object.keys((revoked?.['totals'] ?? {}) as object).sort(), ['allowed', 'denied', 'durationMs', 'failed', 'flows', 'receivedBytes', 'refused', 'requests', 'sentBytes'])
  assert.deepEqual(d.tools.liveGrants(), [], 'the grant outlived its container')
  // The spec asks for the channel, on the trusted domain.
  assert.deepEqual([d.driver.specs[0]?.channel, d.driver.specs[0]?.domain], [true, 'trusted'])
  // Ended by the container's own exit: no kill by name was needed.
  assert.deepEqual(d.driver.kills, [])

  // On its wallclock: the driver kills it by name, and the grant is revoked
  // with that verdict.
  const second = d.tools.call(ticketFor('run_g', args), args, context('run_g'))
  await until(() => d.driver.channels.length === 2, 'the second channel')
  const late = new FakeMux(d.driver.channels[1]!)
  await late.ready()
  d.driver.simulateOverrun(d.driver.channels[1]!.name)
  const timed = await second
  assert.equal(timed.ok, false)
  assert.match(timed.text, /was killed at its wallclock of \d+ ms/)
  assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['exited', 'wallclock'])
  assert.deepEqual(payloads(d.store, 'sandbox.killed').map((r) => r['reason']), ['exited', 'wallclock'])
  assert.deepEqual(d.tools.liveGrants(), [])
  // One grant per container: each revocation names the grant its container was issued.
  const grants = payloads(d.store, 'proxy.grant.issued').map((r) => r['grantId'])
  assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['grantId']), grants)
  assert.equal(new Set(grants).size, 2)
})

test("a channel run's container runs the worker image's mux around the command, and a run with no channel runs the command itself, in the docker run the real driver builds", async (t) => {
  // The image's entrypoint is empty and docker appends the spec's command
  // after the image, so a channel run whose command were the agent's argv
  // would run no mux: the session would read the command's own stdout as
  // frames, no ready report would come, and every egress exec would fail.
  // The fakes play the mux, so only the real driver's argv shows it.
  const fx = egressOf()
  const files = { coder: EGRESS_CODER, plain: manifest('plain'), boxer: manifest('boxer', { sandbox: 'hostile' }) }
  const d = direct(t, { files, egress: fx.egress })
  const spawned: (readonly string[])[] = []
  const real = realDriver(d.sandbox, tmpdir(t), {
    spawn: (_cmd, args) => {
      spawned.push(args)
      throw new Error('test: nothing is spawned here')
    },
    execFile: () => Promise.resolve({ stdout: '', stderr: '' }),
  })
  const tools = toolsOver(d, real, { egress: fx.egress })
  const command = ['git', 'fetch', '--depth', '1']
  const cases: readonly (readonly [string, boolean])[] = [
    ['coder', true],
    ['plain', false],
    ['boxer', false],
  ]
  for (const [agentId, channel] of cases) {
    spawned.length = 0
    const runId = `run_${agentId}`
    await tools.call(ticketFor(runId, { command }), { command }, context(runId, { agentId }))
    assert.equal(spawned.length, 1, agentId)
    const args = spawned[0] ?? []
    const image = args.indexOf(IMAGE)
    assert.ok(image > 0, `${agentId}: no image in ${JSON.stringify(args)}`)
    assert.deepEqual(args.slice(image + 1), channel ? [...MUX_ARGV, '--', ...command] : command, agentId)
    assert.deepEqual(args.slice(image + 1), channel ? [...muxCommand(command)] : command, agentId)
    assert.equal(args.slice(0, image).includes('-i'), channel, `${agentId}: -i`)
  }
})

test('an exec grant never includes git-push or github-pulls', async (t) => {
  assert.deepEqual([...EXEC_PROFILES], ['git-fetch'])
  // github holds every profile; api holds only github-pulls, so an exec
  // grant routes it not at all.
  const fx = egressOf({
    bindings: { github: GITHUB, api: { host: 'api.github.com', profiles: ['github-pulls'], repos: ['op/fixture'] } },
  })
  const d = direct(t, {
    files: { coder: manifest('coder', { egress: { bind: ['github', 'api'] } }) },
    egress: fx.egress,
    exits: [{ hangs: true }],
  })
  const args = { command: ['git', 'push'] }
  const call = d.tools.call(ticketFor('run_x', args), args, context('run_x'))
  await until(() => d.driver.channels.length === 1, 'the channel')
  const routes = d.tools.liveGrants()[0]?.grant.routes
  assert.deepEqual(routes, [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }])
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  // A push and a pull request from inside the container are denied, never sent.
  const pushed = await mux.request(
    'POST http://github.com/op/fixture.git/git-receive-pack HTTP/1.1\r\nHost: github.com\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\n\r\n0000',
  )
  assert.match(pushed, /^HTTP\/1\.1 403 /)
  const pr = '{"title":"x","head":"aos/run_x/fix","base":"main"}'
  const pulled = await mux.request(
    `POST http://api.github.com/repos/op/fixture/pulls HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\nContent-Length: ${String(pr.length)}\r\n\r\n${pr}`,
  )
  assert.match(pulled, /^HTTP\/1\.1 403 /)
  mux.exit(0)
  d.driver.simulateExit(d.driver.channels[0]!.name)
  await call
  assert.deepEqual(fx.up.steps, [], 'a write was resolved or dialled')
  assert.deepEqual(fx.injected, [], 'a credential was injected for a write')
  const [issued] = payloads(d.store, 'proxy.grant.issued')
  for (const route of (issued?.['routes'] ?? []) as { profiles: string[] }[]) {
    assert.equal(route.profiles.some((p) => p === 'git-push' || p === 'github-pulls'), false)
  }
  const decisions = payloads(d.store, 'proxy.decision')
  assert.ok(decisions.length >= 1)
  assert.ok(decisions.every((row) => row['verdict'] === 'deny'), JSON.stringify(decisions))
})

test('a hostile-domain run gets no channel and no grant', async (t) => {
  // The registry refuses egress on a hostile manifest at load; one that
  // reached the runner anyway (forged here) still runs as every hostile run
  // does: no channel, no grant, whatever its manifest says, and whether or
  // not egress is ok.
  for (const state of [{ state: 'ok' } as const, DEGRADED]) {
    const fx = egressOf({ state })
    const d = direct(t, {
      files: { coder: manifest('coder', { sandbox: 'hostile', tier: 3 }) },
      egress: fx.egress,
      exits: [{ stdout: 'ran\n' }],
      sandboxAgents: (r) => ({
        get: (id) => {
          const record = r.get(id)
          return record === undefined
            ? undefined
            : { ...record, manifest: { ...record.manifest, egress: { allow: ['registry.npmjs.org' as EgressHost], bind: ['github'] } } }
        },
      }),
    })
    assert.equal(d.tools.egressRefusal(EXEC, 'coder', 'run_h'), undefined, state.state)
    const args = { command: ['curl', 'http://registry.npmjs.org/'] }
    const out = await d.tools.call(ticketFor('run_h', args), args, context('run_h'))
    assert.equal(out.ok, true, out.text)
    assert.match(out.text, /on the hostile domain, no network, exited 0/)
    const spec = d.driver.specs[0]
    assert.equal(spec?.domain, 'hostile')
    assert.equal(spec !== undefined && 'channel' in spec, false, 'a hostile run asked for a channel')
    assert.equal(d.driver.channels.length, 0)
    assert.deepEqual(payloads(d.store, 'proxy.grant.issued'), [])
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked'), [])
    assert.deepEqual(d.tools.liveGrants(), [])
  }
})

test('a grant whose identifier the mask would change is not issued', async (t) => {
  // kernel.yaml and the registry refuse an identifier in a credential's
  // shape at load, but cannot see a value the broker registers with the mask
  // later. The issuer checks every identifier with redactString, names the
  // field by its place only, and issues nothing.
  t.after(() => SecretMask.clear())
  const cases: readonly { field: string; secret: string; bindings: SandboxEgress['bindings']; files: string; agent?: string }[] = [
    { field: 'repository routes\\[0\\]\\.repos\\[0\\]', secret: 'fixture-7f3a9c2e', bindings: { github: { ...GITHUB, repos: ['op/fixture-7f3a9c2e'] } }, files: EGRESS_CODER },
    { field: 'credential-free host allow\\[0\\]', secret: 'example-4d1b8e0a', bindings: { github: GITHUB }, files: manifest('coder', { egress: { allow: ['pkgs.example-4d1b8e0a.org'] } }) },
    { field: 'bound host routes\\[0\\]', secret: 'gitea-host-91c3', bindings: { gitea: { host: 'gitea-host-91c3.example.org', profiles: ['git-fetch'], repos: ['op/fixture'] } }, files: manifest('coder', { egress: { bind: ['gitea'] } }) },
    // The agent's own id, which the row names beside the run's: a host, a
    // binding and a repository that are all plain do not save it.
    { field: 'agent id', secret: 'mask7f3a9c2e', bindings: { github: GITHUB }, files: manifest('coder-mask7f3a9c2e', { egress: { allow: ['registry.npmjs.org'], bind: ['github'] } }), agent: 'coder-mask7f3a9c2e' },
    // A binding's id, which no host or repository of it repeats.
    { field: 'binding id routes\\[0\\]', secret: 'mask4d1b8e0a', bindings: { 'gh-mask4d1b8e0a': GITHUB }, files: manifest('coder', { egress: { bind: ['gh-mask4d1b8e0a'] } }) },
  ]
  for (const c of cases) {
    const agent = c.agent ?? 'coder'
    const fx = egressOf({ bindings: c.bindings })
    const d = direct(t, { files: { [agent]: c.files }, egress: fx.egress, exits: [{ hangs: true }] })
    assert.equal(d.tools.egressRefusal(EXEC, agent, 'run_m'), undefined, 'refused before the mask held the value')
    assert.ok(SecretMask.register(c.secret))
    const refusal = new RegExp(`^the grant's ${c.field} is in the shape of a credential, or holds a value the kernel holds as secret`)
    assert.match(d.tools.egressRefusal(EXEC, agent, 'run_m') ?? 'none', refusal, c.field)
    assert.match(d.tools.egressRefusal(EXEC, agent) ?? 'none', refusal, `${c.field}, at the offer`)
    const args = { command: ['git', 'fetch'] }
    const out = await d.tools.call(ticketFor('run_m', args), args, context('run_m', { agentId: agent }))
    assert.equal(out.ok, false)
    assert.match(out.text, new RegExp(`^\\[refused\\] the grant's ${c.field} is in the shape of a credential`))
    assert.equal(out.text.includes(c.secret), false, 'the refusal quoted the secret')
    assert.equal(d.driver.specs.length, 0, 'a container started')
    assert.deepEqual(payloads(d.store, 'proxy.grant.issued'), [])
    assert.deepEqual(d.tools.liveGrants(), [])
    SecretMask.clear()
  }
})

test("a forged record whose egress binds an id kernel.yaml does not hold is refused by name, never granted without it", async (t) => {
  // The registry refuses such a manifest at load (an unknown bind id); one
  // that reached the runner anyway is refused at the offer, before the gate
  // and at execution, not quietly issued a grant that leaves the binding out.
  const fx = egressOf()
  const d = direct(t, {
    files: { coder: EGRESS_CODER },
    egress: fx.egress,
    exits: [{ hangs: true }],
    sandboxAgents: (r) => ({
      get: (id) => {
        const record = r.get(id)
        return record === undefined
          ? undefined
          : { ...record, manifest: { ...record.manifest, egress: { allow: [...record.manifest.egress.allow], bind: ['github', 'gitlab'] } } }
      },
    }),
  })
  const refusal = "coder's egress.bind names 1 binding(s) kernel.yaml does not hold; no container was started"
  assert.equal(d.tools.egressRefusal(EXEC, 'coder'), refusal)
  assert.equal(d.tools.egressRefusal(EXEC, 'coder', 'run_f'), refusal)
  const args = { command: ['git', 'fetch'] }
  const out = await d.tools.call(ticketFor('run_f', args), args, context('run_f'))
  assert.deepEqual([out.ok, out.text], [false, `[refused] ${refusal}`])
  assert.equal(d.driver.specs.length, 0, 'a container started')
  assert.deepEqual(payloads(d.store, 'proxy.grant.issued'), [])
  assert.deepEqual(d.tools.liveGrants(), [])
})

test('a run the driver gives no channel, though its spec asked for one, is killed by name at once and its grant revoked unserved', { timeout: 10_000 }, async (t) => {
  // Node gives a child no pipes only for a spawn that started nothing, so a
  // driver that answers a channel spec with no channel is one to distrust:
  // the container it may have started would wait for a go nobody sends
  // until its wallclock, holding the run and its lane. It is killed by name
  // at once, and the grant, which served nothing, revoked as unserved.
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
  const base = d.driver
  const noChannel: SandboxDriver = {
    name: base.name,
    probe: () => base.probe(),
    run: (spec) => {
      const running = base.run(spec)
      return { name: running.name, result: running.result }
    },
    kill: (name) => base.kill(name),
    abandon: (name) => base.abandon(name),
    commandRefusal: (command) => base.commandRefusal(command),
    everyRunRefusal: () => base.everyRunRefusal(),
    sweepOrphans: (request) => base.sweepOrphans(request),
  }
  // A short wallclock and grace, so a runner that sent no kill gives the
  // container up in well under the test's timeout, by abandon, not by kill.
  const tools = toolsOver(d, noChannel, { egress: fx.egress, resultGraceMs: 100 })
  const args = { command: ['git', 'fetch'] }
  const out = await tools.call(ticketFor('run_c', args), args, context('run_c', { budget: { remainingMs: () => 300 } }))
  const name = d.driver.specs[0]?.name
  assert.equal(d.driver.specs[0]?.channel, true)
  assert.deepEqual(d.driver.kills, [name], 'the container was not killed by name')
  assert.deepEqual(d.driver.abandons, [], 'the container was given up at its wallclock, not killed at once')
  assert.deepEqual(payloads(d.store, 'sandbox.killed').map((r) => r['reason']), ['requested'])
  const issued = payloads(d.store, 'proxy.grant.issued')
  assert.equal(issued.length, 1)
  assert.deepEqual(payloads(d.store, 'proxy.grant.revoked'), [
    {
      schemaVersion: 1,
      grantId: issued[0]?.['grantId'],
      reason: 'error',
      detail: 'the driver gave the run no channel',
      totals: { flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 },
    },
  ])
  assert.deepEqual(
    d.store.query({ type: 'proxy.grant.revoked' }).map((row) => [row.runId, row.agentId]),
    [['run_c', 'coder']],
  )
  assert.equal(out.ok, false, out.text)
  // The head says the kernel killed it, and why: the run was never stopped.
  assert.match(
    out.text,
    new RegExp(
      `^${String(name)} on the trusted domain, no network, was killed by name by the kernel, which could not serve its ` +
        'egress grant \\(exit 137\\) after \\d+ ms\n\\[egress grant grant_\\S+ revoked unserved: the driver gave the run no channel\\]\n',
    ),
  )
  assert.doesNotMatch(out.text, /the run was stopped/)
  assert.deepEqual(tools.liveGrants(), [])
})

test("a trusted run's container reaches an allowed host over its channel through an injected dialer: every flow is a proxy.decision of that run before the dial, one credential injected, and the chain verifies", async (t) => {
  const order: string[] = []
  const fx = egressOf({ onStep: (step) => order.push(step) })
  const w = wire(t, {
    script: [exec(['git', 'clone', 'http://github.com/op/fixture.git']), done()],
    exits: [{ hangs: true }],
    files: { coder: EGRESS_CODER },
    egress: fx.egress,
  })
  w.store.subscribe((row) => {
    if (row.type !== 'proxy.decision') {
      order.push(row.type)
      return
    }
    const p = JSON.parse(row.payload) as { verdict: string; host?: string; stage: string }
    order.push(`decision ${p.stage} ${p.verdict} ${p.host ?? '-'}`)
  })
  const started = w.loop.start({ runId: 'run_e2e', agent: w.agent('coder'), prompt: 'clone the fixture' })
  await until(() => w.driver.channels.length === 1, 'the channel')
  const mux = new FakeMux(w.driver.channels[0]!)
  await mux.ready()
  const registry = await mux.request('GET http://registry.npmjs.org/react HTTP/1.1\r\nHost: registry.npmjs.org\r\nAuthorization: Bearer worker-own-token-9d8c7b6a\r\n\r\n')
  assert.match(registry, /^HTTP\/1\.1 200 /)
  assert.match(registry, /\r\nupstream-ok\r\n/)
  const fetched = await mux.request('GET http://github.com/op/fixture.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n\r\n')
  assert.match(fetched, /^HTTP\/1\.1 200 /)
  const loopback = await mux.request('GET http://192.168.5.2:8766/mcp HTTP/1.1\r\nHost: 192.168.5.2:8766\r\n\r\n')
  assert.match(loopback, /^HTTP\/1\.1 403 /)
  mux.stdout('cloned\n')
  mux.exit(0)
  w.driver.simulateExit(w.driver.channels[0]!.name)
  const out = await started
  assert.equal(out.status, 'ok', String(out.reason))
  assert.equal(out.taint, 'tainted')

  // Every flow is a proxy.decision of this run and of its grant, and each
  // allowed one is recorded before the upstream resolves or dials anything.
  const rows = w.store.query({ type: 'proxy.decision' })
  const [issued] = payloads(w.store, 'proxy.grant.issued')
  assert.ok(rows.length >= 3)
  for (const row of rows) {
    assert.equal(row.runId, 'run_e2e')
    assert.equal(row.agentId, 'coder')
    assert.equal((JSON.parse(row.payload) as { grantId: string }).grantId, issued?.['grantId'])
  }
  const steps = order.filter((step) => /^(decision|resolve4|dial)/.test(step))
  assert.deepEqual(steps, [
    'decision policy allow registry.npmjs.org',
    'resolve4 registry.npmjs.org',
    'dial 140.82.112.3',
    'decision policy allow github.com',
    'resolve4 github.com',
    'dial 140.82.112.3',
    'decision policy deny -',
  ])
  // The grant spans the container's life, and every decision is inside it.
  const lifecycle = order.filter((step) => /^(proxy\.grant\.|sandbox\.|decision)/.test(step))
  assert.equal(lifecycle[0], 'proxy.grant.issued')
  assert.equal(lifecycle.at(-1), 'proxy.grant.revoked')
  // Exactly one Authorization reached the bound host, the binding's; the
  // worker's own never left; the credential-free host got none.
  assert.deepEqual(fx.injected, ['github'])
  const auth = (seen: { rawHeaders: readonly string[] } | undefined): string[] => {
    const out: string[] = []
    for (let i = 0; i + 1 < (seen?.rawHeaders.length ?? 0); i += 2) if (seen?.rawHeaders[i]?.toLowerCase() === 'authorization') out.push(seen.rawHeaders[i + 1] ?? '')
    return out
  }
  assert.deepEqual(fx.up.seen.map((seen) => seen.url), ['/react', '/op/fixture.git/info/refs?service=git-upload-pack'])
  assert.deepEqual(auth(fx.up.seen[0]), [])
  assert.deepEqual(auth(fx.up.seen[1]), [`Bearer ${BINDING_VALUE}`])
  // The grant's totals and the result say what crossed the channel.
  const [revoked] = payloads(w.store, 'proxy.grant.revoked')
  assert.equal(revoked?.['reason'], 'exited')
  assert.deepEqual(
    ['requests', 'allowed', 'denied', 'flows'].map((key) => (revoked?.['totals'] as Record<string, number> | undefined)?.[key]),
    [3, 2, 1, 3],
  )
  const [result] = payloads(w.store, 'tool.result')
  assert.match(String(result?.['text']), /no network but the kernel's egress engine \(grant grant_\S+: 3 request\(s\), 2 allowed, 1 denied\), exited 0/)
  assert.match(String(result?.['text']), /--- stdout \(7 bytes\) ---\ncloned\n/)
  // No row holds the binding's value or the worker's own token.
  for (const row of readAllRows(w.store.db)) {
    assert.equal(row.payload.includes(BINDING_VALUE), false, row.type)
    assert.equal(row.payload.includes('worker-own-token-9d8c7b6a'), false, row.type)
  }
  assert.equal(w.store.verifyChain(w.store.readAnchor()).ok, true)
})

test("a grant is revoked on a violation and on the run's stop, and its container killed by name on its own domain", async (t) => {
  // A violation: the container writes bytes no frame reads. The session
  // revokes the grant on its own, and the runner kills the container by name
  // through the driver; nothing ends its stdin.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const args = { command: ['true'] }
    const call = d.tools.call(ticketFor('run_v', args), args, context('run_v'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.raw(Buffer.from([0, 0, 0, 0, 0x7f, 0, 0, 0, 1]))
    const out = await call
    assert.equal(out.ok, false)
    assert.deepEqual(d.driver.kills, [name], 'the container was not killed by name, once')
    assert.match(out.text, /was killed by name when its egress grant was revoked/)
    assert.match(out.text, /\n\[egress grant grant_\S+ revoked: violation: /)
    const [revoked] = payloads(d.store, 'proxy.grant.revoked')
    assert.equal(revoked?.['reason'], 'violation')
    assert.ok(revoked?.['totals'] !== undefined, 'a violation is revoked with its totals')
    assert.deepEqual(payloads(d.store, 'sandbox.killed').map((r) => r['reason']), ['requested'])
    assert.deepEqual(d.tools.liveGrants(), [])
  }
  // The run's stop: the runner's kill by name ends the container, and the
  // grant is revoked with the driver's verdict.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const stop = new AbortController()
    const args = { command: ['sleep', '600'] }
    const call = d.tools.call(ticketFor('run_s', args), args, context('run_s', { signal: stop.signal }))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    stop.abort()
    const out = await call
    assert.equal(out.ok, false)
    assert.match(out.text, /was killed: the run was stopped/)
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['requested'])
    assert.deepEqual(d.driver.kills, [d.driver.channels[0]!.name])
    assert.deepEqual(d.tools.liveGrants(), [])
  }
  // A container that exits with no exit frame from its mux: the command's
  // status is unknown, so the call is no success, whatever the mux exited.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const args = { command: ['true'] }
    const call = d.tools.call(ticketFor('run_n', args), args, context('run_n'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    d.driver.simulateExit(d.driver.channels[0]!.name)
    const out = await call
    assert.equal(out.ok, false)
    assert.match(out.text, /ended with no exit status from its command \(the mux exited 0 before it sent one\)/)
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['exited'])
  }
  // A container that sends its command's exit status, then breaks the
  // protocol (a frame cut inside its header) and exits on its own: a
  // violation, though the command exited 0, and the exec is no success.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const args = { command: ['true'] }
    const call = d.tools.call(ticketFor('run_x', args), args, context('run_x'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.exit(0)
    mux.raw(Buffer.from([0, 0, 0]))
    d.driver.simulateExit(d.driver.channels[0]!.name)
    const out = await call
    assert.equal(out.ok, false, out.text)
    assert.match(out.text, /, exited 0 after \d+ ms\n\[egress grant grant_\S+ revoked: violation: /)
    const [revoked] = payloads(d.store, 'proxy.grant.revoked')
    assert.equal(revoked?.['reason'], 'violation')
    assert.match(String(revoked?.['detail']), /truncated/)
    assert.deepEqual(d.driver.kills, [], 'a container that exited on its own was killed')
  }
  // A docker client that ends saying nothing of its container (125, its own
  // failure, or no exit status) after its stream was cut inside a frame: the
  // kernel kills the container by name, and the grant is revoked `error`,
  // the kernel's verdict, never a violation blamed on the container.
  for (const exit of [
    { exitCode: DOCKER_CLI_FAILED, stderr: 'docker: error waiting for container: unexpected EOF\n' },
    { exitCode: null, signal: 'SIGKILL' },
    { exitCode: null },
  ] as const) {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true, ...exit }] })
    const args = { command: ['true'] }
    const call = d.tools.call(ticketFor('run_c', args), args, context('run_c'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.raw(Buffer.from([0, 0, 0]))
    d.driver.simulateExit(name)
    const out = await call
    const what = String(exit.exitCode)
    assert.equal(out.ok, false, what)
    assert.deepEqual(d.driver.kills, [name], `${what}: the container was not killed by name`)
    const [revoked] = payloads(d.store, 'proxy.grant.revoked')
    assert.equal(revoked?.['reason'], 'error', what)
    assert.match(String(revoked?.['detail']), /^the kernel killed the container by name, as a docker client (that exits 125|with no exit status)/, what)
    const client =
      exit.exitCode === null
        ? `the docker client ended with no exit status \\(${'signal' in exit ? 'SIGKILL' : 'it did not start'}\\) before the mux sent one`
        : 'the docker client exited 125, its own failure, before the mux sent one'
    assert.match(out.text, new RegExp(`ended with no exit status from its command \\(${client}\\) after \\d+ ms; a kill by name was sent to ${name}`), what)
    assert.doesNotMatch(out.text, /the mux exited/, what)
    assert.match(out.text, /\n\[egress grant grant_\S+ revoked: error: the kernel killed the container by name/, what)
  }
  // A driver that refuses the spec: the grant served nothing, and is revoked
  // as an error with zero totals, in the row after its issue.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [], driverImageId: `sha256:${'cd'.repeat(32)}` })
    const args = { command: ['true'] }
    const out = await d.tools.call(ticketFor('run_r', args), args, context('run_r'))
    assert.match(out.text, /^\[refused\] /)
    const [revoked] = payloads(d.store, 'proxy.grant.revoked')
    assert.deepEqual(
      [revoked?.['reason'], revoked?.['detail'], (revoked?.['totals'] as Record<string, number> | undefined)?.['requests']],
      ['error', 'the driver refused the container before it started', 0],
    )
    assert.deepEqual(
      d.store.query({ type: 'proxy.grant.revoked' }).map((row) => [row.runId, row.agentId]),
      [['run_r', 'coder']],
    )
    assert.deepEqual(payloads(d.store, 'sandbox.started'), [])
    assert.deepEqual(d.tools.liveGrants(), [])
  }
})

test("a container whose ready report says its self-test reached what --network none keeps out is never sent go: killed by name, its grant revoked as a violation, and nothing served", { timeout: 10_000 }, async (t) => {
  // The kernel's judge (src/egress/ready.ts acceptReady) is its one check,
  // before the command runs, that the container's network is the --network
  // none the kernel asked for: a probe of 192.168.5.2:8766 that reached it,
  // or that timed out (a SYN that went somewhere), is refused. The run's
  // budget and a short grace bound the call well inside the test's timeout,
  // so a judge that accepts every report fails here within a second, not
  // after the default 120 s wallclock and its grace.
  for (const how of ['reached', 'timed out'] as const) {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const tools = toolsOver(d, d.driver, { egress: fx.egress, resultGraceMs: 100 })
    const args = { command: ['git', 'fetch'] }
    const call = tools.call(ticketFor('run_y', args), args, context('run_y', { budget: { remainingMs: () => 400 } }))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    mux.send({ type: 'ready', flow: 0, payload: refusedReport(how) })
    const out = await call
    assert.equal(out.ok, false, how)
    assert.equal(mux.kernelFrames.includes('go'), false, `${how}: the container was sent go, so its command ran`)
    assert.deepEqual(d.driver.kills, [name], `${how}: the container was not killed by name, once`)
    assert.match(out.text, /was killed by name when its egress grant was revoked/, how)
    const why =
      how === 'reached'
        ? 'the self-test reached 1 of what it must not (192.168.5.2:8766)'
        : "the self-test's probe of 192.168.5.2:8766 met ETIMEDOUT, which does not say there is no route"
    const [revoked] = payloads(d.store, 'proxy.grant.revoked')
    assert.equal(revoked?.['reason'], 'violation', how)
    assert.equal(revoked?.['detail'], `the mux's ready report was refused: ${why}`, how)
    const [result] = payloads(d.store, 'tool.result')
    assert.equal(result?.['ok'], false, how)
    assert.deepEqual(payloads(d.store, 'proxy.decision'), [], `${how}: a request was judged`)
    assert.equal(fx.up.seen.length, 0, `${how}: an upstream was sent a request`)
    assert.deepEqual(tools.liveGrants(), [], how)
  }
})

test('a grant the session revokes on its own leaves the grant table once its revocation is appended, while its container still runs', { timeout: 10_000 }, async (t) => {
  // A container that breaks the protocol, on a daemon that never answers
  // the kill by name: the container runs on until its wallclock and the
  // grace, and the call with it. The table (liveGrants) is every grant
  // issued whose revocation has not yet been attempted, so the revoked grant
  // is not in it then.
  const never = (): Promise<void> => new Promise<void>(() => undefined)
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
  const driver = withKill(d.driver, never)
  const tools = toolsOver(d, driver, { egress: fx.egress, killWaitMs: 25, resultGraceMs: 100 })
  const args = { command: ['true'] }
  let settled = false
  const call = tools.call(ticketFor('run_q', args), args, context('run_q', { budget: { remainingMs: () => 400 } }))
  void call.then(() => {
    settled = true
  })
  await until(() => d.driver.channels.length === 1, 'the channel')
  const name = d.driver.channels[0]!.name
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  assert.equal(tools.liveGrants().length, 1)
  mux.raw(Buffer.from([0, 0, 0, 0, 0x7f, 0, 0, 0, 1]))
  await until(() => payloads(d.store, 'proxy.grant.revoked').length === 1, "the session's revocation")
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(payloads(d.store, 'proxy.grant.revoked')[0]?.['reason'], 'violation')
  assert.deepEqual(driver.kills, [name], 'the session did not have the container killed by name')
  assert.equal(settled, false, 'the call ended before the container did')
  assert.equal(payloads(d.store, 'sandbox.killed').length, 0, 'the container was recorded ended')
  assert.deepEqual(tools.liveGrants(), [], 'a revoked grant is still listed live')
  // The call ends at the container's wallclock and the grace, by abandon.
  const out = await call
  assert.equal(out.ok, false)
  assert.deepEqual(d.driver.abandons, [name])
  assert.deepEqual(tools.liveGrants(), [])
  assert.equal(payloads(d.store, 'proxy.grant.revoked').length, 1, 'the grant was revoked twice')
})

test("a grant whose session's revocation the store refuses leaves the grant table all the same, and stays open in the log for the next boot to close", { timeout: 10_000 }, async (t) => {
  // The session ends whether or not its proxy.grant.revoked row was taken
  // (EgressSession.done: the revocation attempted). The table drops the
  // grant then, as it does a revoked one, so liveGrants lists no grant the
  // kernel no longer serves; the log, which holds no revocation, shows it
  // open, and projectRecovery hands it to the next boot (GRANT_RECOVERED_DETAIL).
  const never = (): Promise<void> => new Promise<void>(() => undefined)
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
  let refused = 0
  const append = d.store.append.bind(d.store)
  d.store.append = ((event: Parameters<EventStore['append']>[0]) => {
    if (event.type === 'proxy.grant.revoked') {
      refused += 1
      throw new Error('the log refused the row')
    }
    return append(event)
  }) as EventStore['append']
  const driver = withKill(d.driver, never)
  const tools = toolsOver(d, driver, { egress: fx.egress, killWaitMs: 25, resultGraceMs: 100 })
  const args = { command: ['true'] }
  let settled = false
  const call = tools.call(ticketFor('run_r', args), args, context('run_r', { budget: { remainingMs: () => 400 } }))
  void call.then(() => {
    settled = true
  })
  await until(() => d.driver.channels.length === 1, 'the channel')
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  const [live] = tools.liveGrants()
  assert.ok(live !== undefined, 'no grant was live while the channel was served')
  mux.raw(Buffer.from([0, 0, 0, 0, 0x7f, 0, 0, 0, 1]))
  await until(() => refused === 1, "the session's revocation")
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(settled, false, 'the call ended before the container did')
  assert.deepEqual(tools.liveGrants(), [], 'a grant the session no longer serves is still listed live')
  await call
  assert.deepEqual(tools.liveGrants(), [])
  assert.deepEqual(payloads(d.store, 'proxy.grant.revoked'), [], 'a revocation the store refused is in the log')
  const open = projectRecovery(readAllRows(d.store.db)).openGrants
  assert.deepEqual(open.map((g) => g.grantId), [live.grantId], 'the grant left open is not handed to the next boot')
})

test("sandbox.exec's description says a container reaches only what its manifest's egress grants, through the kernel, and nothing without it", (t) => {
  // One description for every run: a model whose manifest grants egress must
  // not be told its container has no network, nor one without egress that it
  // has some.
  const d = direct(t)
  const [schema] = d.tools.schemas()
  assert.equal(schema?.description, EXEC_DESCRIPTION)
  assert.match(EXEC_DESCRIPTION, /^Run one command in a fresh container of your sandbox\. The container has no network of its own: if your manifest grants egress, it reaches the hosts that grant names, and nothing else, through the kernel, over the HTTP_PROXY its image sets; otherwise it reaches nothing\. /)
  assert.doesNotMatch(EXEC_DESCRIPTION, /with no network\./)
  // How to reach a granted host, as the engine routes it: an http:// URL in
  // absolute form, which the kernel sends on over TLS; never an https:// URL
  // through the proxy, which is a CONNECT the engine denies, whatever it names.
  assert.match(EXEC_DESCRIPTION, /Name such a host with an http:\/\/ URL and no port \(http:\/\/<host>\/<path>\): the kernel makes the TLS connection to it itself\. /)
  assert.match(EXEC_DESCRIPTION, /An https:\/\/ URL sent through the proxy asks it for a tunnel \(CONNECT\), which is always refused; /)
  assert.doesNotMatch(EXEC_DESCRIPTION, /HTTPS_PROXY/)
})

test('a grant whose bindings name exactly PROXY_GRANT_MAX_REPOS repositories between them is issued, its row naming each one', async (t) => {
  // The row's bound, at the bound: two bindings of 64 each, 128 in all, is
  // a grant proxy.grant.issued records (the 192 row in 'exec with egress
  // refuses with the egress reason when the state is not ok' is one past).
  const wide = Object.fromEntries(
    [0, 1].map((b) => [`gh-${String(b)}`, { host: 'github.com', profiles: ['git-fetch'], repos: Array.from({ length: 64 }, (_, i) => `op/b${String(b)}-r${String(i)}`) }]),
  ) as SandboxEgress['bindings']
  assert.equal(PROXY_GRANT_MAX_REPOS, 128)
  const fx = egressOf({ bindings: wide })
  const d = direct(t, { files: { coder: manifest('coder', { egress: { bind: ['gh-0', 'gh-1'] } }) }, egress: fx.egress, registryBindings: wide, exits: [{ hangs: true }] })
  assert.equal(d.tools.egressRefusal(EXEC, 'coder'), undefined)
  assert.equal(d.tools.egressRefusal(EXEC, 'coder', 'run_m'), undefined)
  const args = { command: ['git', 'fetch', '--all'] }
  const call = d.tools.call(ticketFor('run_m', args), args, context('run_m'))
  await until(() => d.driver.channels.length === 1, 'the channel')
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  mux.exit(0)
  d.driver.simulateExit(d.driver.channels[0]!.name)
  const out = await call
  assert.equal(out.ok, true, out.text)
  const [issued] = payloads(d.store, 'proxy.grant.issued')
  const routes = (issued?.['routes'] ?? []) as { bindingId: string; repos: string[] }[]
  assert.deepEqual(routes.map((r) => [r.bindingId, r.repos.length]), [['gh-0', 64], ['gh-1', 64]])
  assert.equal(routes.reduce((n, r) => n + r.repos.length, 0), PROXY_GRANT_MAX_REPOS)
})

test('a container whose command exited while a flow stays open is killed by name and its grant revoked', { timeout: 10_000 }, async (t) => {
  // The mux sends the command's exit frame once the command and its group
  // are gone, and exits once its last flow retires; a descendant that left
  // the group (setsid) may hold a flow open, which no new open, no limit
  // short of idleMs or maxBytes, and no wallclock short of the container's
  // would end. Past the grace from the exit frame the kernel kills the
  // container by name, and the grant is revoked `requested`, saying why.
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }], exitKillGraceMs: 50 })
  const order: string[] = []
  d.store.subscribe((row) => order.push(row.type))
  const args = { command: ['sh', '-c', 'setsid curl http://registry.npmjs.org/ &'] }
  const call = d.tools.call(ticketFor('run_o', args), args, context('run_o'))
  await until(() => d.driver.channels.length === 1, 'the channel')
  const name = d.driver.channels[0]!.name
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  // A flow opened and never closed, its request never finished.
  mux.send({ type: 'open', flow: 1, payload: new Uint8Array(0) })
  mux.send({ type: 'data', flow: 1, payload: Buffer.from('GET http://registry.npmjs.org/ HTTP/1.1\r\nHost: regis', 'latin1') })
  mux.stdout('started\n')
  mux.exit(0)
  const out = await call
  assert.deepEqual(d.driver.kills, [name], 'the container was not killed by name, once')
  assert.equal(out.ok, false, out.text)
  assert.match(out.text, new RegExp(`^${name} on the trusted domain, no network but the kernel's egress engine \\(grant grant_\\S+: 0 request\\(s\\), 0 allowed, 0 denied\\), was killed by name, still running 50 ms after its command exited 0 \\(exit 137\\) after \\d+ ms\n`))
  assert.match(out.text, /\n\[egress grant grant_\S+ revoked: requested: the command exited, and its container was still running 50 ms later, so the kernel killed it by name\]\n/)
  assert.match(out.text, /--- stdout \(8 bytes\) ---\nstarted\n/)
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'requested', exitCode: 137 }])
  const [revoked] = payloads(d.store, 'proxy.grant.revoked')
  assert.deepEqual([revoked?.['reason'], revoked?.['detail']], [
    'requested',
    'the command exited, and its container was still running 50 ms later, so the kernel killed it by name',
  ])
  assert.deepEqual(order.filter((type) => /^(sandbox\.|proxy\.grant\.)/.test(type)), ['proxy.grant.issued', 'sandbox.started', 'sandbox.killed', 'proxy.grant.revoked'])
  assert.deepEqual(d.tools.liveGrants(), [])

  // A container that ends within the grace of its command's exit is not
  // killed: its own exit ends the grant, `exited`.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }], exitKillGraceMs: 50 })
    const call = d.tools.call(ticketFor('run_q', args), args, context('run_q'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.exit(0)
    d.driver.simulateExit(d.driver.channels[0]!.name)
    const out = await call
    assert.equal(out.ok, true, out.text)
    assert.deepEqual(d.driver.kills, [])
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['exited'])
    // Its grace timer was cleared with the result: nothing fires after it.
    await new Promise((resolve) => setTimeout(resolve, 80))
    assert.deepEqual(d.driver.kills, [])
  }

  // The grace's kill that ends nothing (it lands as the container exits on
  // its own, or reaches no daemon): the driver credits no kill, and the
  // grant is revoked with the container's own end, `exited`, as
  // sandbox.killed records it, never `requested` with a kill that ended
  // nothing.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true, ignoresKill: true }], exitKillGraceMs: 50 })
    const call = d.tools.call(ticketFor('run_i', args), args, context('run_i'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.send({ type: 'open', flow: 1, payload: new Uint8Array(0) })
    mux.exit(0)
    const out = await call
    assert.deepEqual(d.driver.kills, [name], 'the grace sent no kill')
    assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'exited', exitCode: 0 }])
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => [r['reason'], r['detail']]), [['exited', undefined]])
    assert.equal(out.text.includes('so the kernel killed it by name'), false, out.text)
    assert.deepEqual(d.tools.liveGrants(), [])
  }

  // A run stopped in the grace is killed by its stop, and says so: the
  // grace's own kill is not sent after the stop's.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }], exitKillGraceMs: 50 })
    const stop = new AbortController()
    const call = d.tools.call(ticketFor('run_s', args), args, context('run_s', { signal: stop.signal }))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.send({ type: 'open', flow: 1, payload: new Uint8Array(0) })
    mux.exit(0)
    stop.abort()
    const out = await call
    assert.match(out.text, /was killed: the run was stopped \(exit 137\)/)
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => [r['reason'], r['detail']]), [['requested', undefined]])
    await new Promise((resolve) => setTimeout(resolve, 80))
    assert.deepEqual(d.driver.kills, [d.driver.channels[0]!.name])
  }

  // Stopped in the grace, with a kill that never answers: the grace runs
  // out while the stop's kill is still unanswered, and sends no second kill,
  // the stop having sent its own; the result is the stop's give-up.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const driver = withKill(d.driver, () => new Promise<void>(() => undefined))
    const tools = toolsOver(d, driver, { egress: fx.egress, exitKillGraceMs: 30, resultGraceMs: 150, killWaitMs: 20 })
    const stop = new AbortController()
    const call = tools.call(ticketFor('run_n', args), args, context('run_n', { signal: stop.signal }))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.send({ type: 'open', flow: 1, payload: new Uint8Array(0) })
    mux.exit(0)
    await new Promise((resolve) => setImmediate(resolve))
    stop.abort()
    const out = await call
    assert.match(out.text, /^\[error\] the driver never answered: .* within 150 ms of the run being stopped/)
    assert.deepEqual(driver.kills, [name], 'the grace sent a kill after the stop had sent its own')
    assert.deepEqual(d.driver.abandons, [name])
    // The container given up, its grant is revoked with it, as an error.
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['error'])
    assert.deepEqual(tools.liveGrants(), [])
  }
})

test('unset, the grace past a command\'s exit frame is EXIT_KILL_GRACE_MS, longer than the mux takes to flush and exit', { timeout: 10_000 }, async (t) => {
  // The in-image mux, once its last flow has retired, flushes its stdout for
  // at most its FLUSH_TIMEOUT_MS (5 s) and exits: an honest container is
  // never killed for that.
  assert.equal(EXIT_KILL_GRACE_MS, 10_000)
  mock.timers.enable({ apis: ['setTimeout'] })
  t.after(() => {
    mock.timers.reset()
  })
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
  const args = { command: ['true'] }
  const call = d.tools.call(ticketFor('run_u', args), args, context('run_u'))
  await until(() => d.driver.channels.length === 1, 'the channel')
  const name = d.driver.channels[0]!.name
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  mux.send({ type: 'open', flow: 1, payload: new Uint8Array(0) })
  mux.exit(0)
  // Bounded by count, not time: timers are mocked here. The frames move on
  // setImmediate and the stream's own ticks.
  for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve))
  mock.timers.tick(EXIT_KILL_GRACE_MS - 1)
  for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(d.driver.kills, [], 'killed before the grace was out')
  mock.timers.tick(1)
  const out = await call
  assert.deepEqual(d.driver.kills, [name])
  assert.match(out.text, new RegExp(`was killed by name, still running ${String(EXIT_KILL_GRACE_MS)} ms after its command exited 0`))
})

test("an exec whose run id the mask would change is denied at the gate, before anything runs, though the offer showed the tool", async (t) => {
  // The offer is judged without a run (the agent's egress and boot's
  // verdict); the gate's check is handed the run's id, so a grant that could
  // not record its run is denied there, its tool.gate row giving the reason,
  // and no tool.call is written.
  t.after(() => SecretMask.clear())
  const fx = egressOf()
  const w = wire(t, { script: [exec(['git', 'fetch']), done()], exits: [], files: { coder: EGRESS_CODER }, egress: fx.egress })
  assert.ok(SecretMask.register('mask_k9x7q2'))
  const out = await w.loop.start({ runId: 'run_mask_k9x7q2', agent: w.agent('coder'), prompt: 'fetch' })
  assert.equal(out.status, 'ok', String(out.reason))
  assert.deepEqual(offered(w.provider.requests[0]), ['sandbox__exec'])
  const [gate] = payloads(w.store, 'tool.gate')
  assert.equal(gate?.['decision'], 'deny')
  assert.match(String(gate?.['reason']), /the grant's run id is in the shape of a credential, or holds a value the kernel holds as secret/)
  assert.deepEqual(payloads(w.store, 'tool.call'), [])
  assert.equal(w.driver.specs.length, 0)
  assert.deepEqual(payloads(w.store, 'proxy.grant.issued'), [])
})

// ── a channel run's end, its error paths, and what it shows (W1b review, round 4) ──

test("a channel run whose command exits non-zero fails with the command's status, though the mux exits 0", async (t) => {
  // The mux exits 0 (MUX_EXIT.ok) whatever its command's status: only the
  // exit frame says how the command ended, so a failed git fetch is never
  // shown to the model as a success.
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
  const args = { command: ['git', 'fetch'] }
  const call = d.tools.call(ticketFor('run_x', args), args, context('run_x'))
  await until(() => d.driver.channels.length === 1, 'the channel')
  const name = d.driver.channels[0]!.name
  const mux = new FakeMux(d.driver.channels[0]!)
  await mux.ready()
  mux.stderr('fatal: could not read from remote repository\n')
  mux.exit(128)
  d.driver.simulateExit(name)
  const out = await call
  assert.equal(out.ok, false, out.text)
  assert.match(
    out.text,
    new RegExp(`^${name} on the trusted domain, no network but the kernel's egress engine \\(grant grant_\\S+: 0 request\\(s\\), 0 allowed, 0 denied\\), exited 128 after \\d+ ms\n`),
  )
  assert.match(out.text, /--- stderr \(45 bytes\) ---\nfatal: could not read from remote repository\n/)
  // The docker client's own exit, the mux's 0, is what sandbox.killed records.
  assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'exited', exitCode: 0 }])
  assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['exited'])
  assert.deepEqual(d.driver.kills, [])
  assert.deepEqual(d.tools.liveGrants(), [])
})

test('every error path of a channel run revokes its grant, and leaves the grant table empty', { timeout: 10_000 }, async (t) => {
  const args = { command: ['git', 'fetch'] }
  // A driver whose result rejects, after its container ended.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const lossy: SandboxDriver = {
      name: d.driver.name,
      probe: () => d.driver.probe(),
      run: (spec) => {
        const running = d.driver.run(spec)
        return { ...running, result: running.result.then(() => Promise.reject(new Error('the driver lost track'))) }
      },
      kill: (name) => d.driver.kill(name),
      abandon: (name) => d.driver.abandon(name),
      commandRefusal: (command) => d.driver.commandRefusal(command),
      everyRunRefusal: () => d.driver.everyRunRefusal(),
      sweepOrphans: (request) => d.driver.sweepOrphans(request),
    }
    const tools = toolsOver(d, lossy, { egress: fx.egress })
    const call = tools.call(ticketFor('run_j', args), args, context('run_j'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.exit(0)
    d.driver.simulateExit(name)
    const out = await call
    assert.match(out.text, new RegExp(`^\\[error\\] the driver lost ${name}: the driver lost track`))
    assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }])
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['error'], 'a rejected result')
    assert.deepEqual(tools.liveGrants(), [], 'a rejected result')
  }
  // A store that refuses sandbox.started: the container is killed by name,
  // and the grant revoked once it has ended, before the call fails.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const append = d.store.append.bind(d.store)
    d.store.append = ((event: Parameters<EventStore['append']>[0]) => {
      if (event.type === 'sandbox.started') throw new Error('the log refused the row')
      return append(event)
    }) as EventStore['append']
    const out = await d.tools.call(ticketFor('run_u', args), args, context('run_u'))
    assert.equal(out.text, 'the log refused the row')
    assert.deepEqual(d.driver.kills, [`${CONTAINER_PREFIX}run_u-1`])
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => r['reason']), ['error'], 'an unrecorded start')
    assert.deepEqual(d.tools.liveGrants(), [], 'an unrecorded start')
  }
  // A session that would not start: the container is killed by name at
  // once, by the kernel, and the grant revoked unserved, saying why.
  {
    const fx = egressOf()
    const broken: SandboxEgress = { ...fx.egress, upstream: {} as unknown as SandboxEgress['upstream'] }
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: broken, exits: [{ hangs: true }] })
    const out = await d.tools.call(ticketFor('run_z', args), args, context('run_z'))
    const name = `${CONTAINER_PREFIX}run_z-1`
    assert.deepEqual(d.driver.kills, [name])
    const detail = 'the egress session would not start: egress session: upstream must be an Upstream'
    const [issued] = payloads(d.store, 'proxy.grant.issued')
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked'), [
      {
        schemaVersion: 1,
        grantId: issued?.['grantId'],
        reason: 'error',
        detail,
        totals: { flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 },
      },
    ])
    assert.deepEqual(d.tools.liveGrants(), [], 'a session that would not start')
    assert.equal(out.ok, false)
    assert.match(
      out.text,
      new RegExp(
        `^${name} on the trusted domain, no network, was killed by name by the kernel, which could not serve its egress ` +
          `grant \\(exit 137\\) after \\d+ ms\n\\[egress grant ${String(issued?.['grantId'])} revoked unserved: ${detail}\\]\n`,
      ),
    )
  }
  // The same, but the container exits on its own before the kernel's kill
  // by name lands. Nobody sent the mux a go, so its command never ran: the
  // docker client's exit, 0 or not, is the mux's, and says nothing of a
  // command. The run is not ok, and its head never says the command exited;
  // the docker client's stderr is said to be its own, not the command's.
  for (const exitCode of [0, 3]) {
    const fx = egressOf()
    const broken: SandboxEgress = { ...fx.egress, upstream: {} as unknown as SandboxEgress['upstream'] }
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: broken, exits: [{ exitCode, stderr: 'mux: no go\n' }] })
    const out = await d.tools.call(ticketFor('run_z', args), args, context('run_z'))
    const name = `${CONTAINER_PREFIX}run_z-1`
    const detail = 'the egress session would not start: egress session: upstream must be an Upstream'
    const [issued] = payloads(d.store, 'proxy.grant.issued')
    assert.deepEqual(payloads(d.store, 'sandbox.killed'), [{ schemaVersion: 1, sandboxId: name, reason: 'exited', exitCode }], String(exitCode))
    assert.deepEqual(payloads(d.store, 'proxy.grant.revoked').map((r) => [r['reason'], r['detail']]), [['error', detail]], String(exitCode))
    assert.deepEqual(d.tools.liveGrants(), [], String(exitCode))
    assert.equal(out.ok, false, `${String(exitCode)}: ${out.text}`)
    assert.doesNotMatch(out.text, /no network, exited \d/, String(exitCode))
    assert.match(
      out.text,
      new RegExp(
        `^${name} on the trusted domain, no network, ended with no exit status from its command \\(the mux exited ` +
          `${String(exitCode)} before it sent one\\) after \\d+ ms\n` +
          `\\[egress grant ${String(issued?.['grantId'])} revoked unserved: ${detail}\\]\n`,
      ),
      String(exitCode),
    )
    assert.match(out.text, /\n--- stderr \(\d+ bytes\) ---\n\[the docker client's stderr\]\nmux: no go\n$/, String(exitCode))
    const [result] = payloads(d.store, 'tool.result')
    assert.equal(result?.['ok'], false, String(exitCode))
  }
})

test("a forged record whose grant the egress engine would not read withholds the tool, refuses its exec, and grants nothing", async (t) => {
  // A record that reached the runner as no load builds one: its egress.allow
  // lists a host twice, which EgressGrant refuses. The refusal is the
  // runner's, at the offer, before the gate and at execution: never a
  // TypeError from reading a grant that did not parse, which would end the
  // run in error at its offer.
  const npm = 'registry.npmjs.org' as EgressHost
  const forged = (r: AgentRegistry): SandboxToolsOptions['agents'] => ({
    get: (id) => {
      const record = r.get(id)
      return record === undefined
        ? undefined
        : { ...record, manifest: { ...record.manifest, egress: { allow: [npm, npm], bind: [] } } }
    },
  })
  const refusal = "the grant coder's egress would be issued is not one the egress engine reads (1 issue(s)); no container was started"
  const fx = egressOf()
  const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }], sandboxAgents: forged })
  assert.equal(d.tools.egressRefusal(EXEC, 'coder'), refusal)
  assert.equal(d.tools.egressRefusal(EXEC, 'coder', 'run_f'), refusal)
  const args = { command: ['npm', 'ci'] }
  const out = await d.tools.call(ticketFor('run_f', args), args, context('run_f'))
  assert.deepEqual([out.ok, out.text], [false, `[refused] ${refusal}`])
  assert.equal(d.driver.specs.length, 0, 'a container started')
  assert.deepEqual(payloads(d.store, 'proxy.grant.issued'), [])
  assert.deepEqual(d.tools.liveGrants(), [])

  // Through the loop: the run is shown no sandbox tool, and ends ok.
  const w = wire(t, { script: [done()], exits: [], files: { coder: EGRESS_CODER }, egress: egressOf().egress, sandboxAgents: forged })
  const ran = await w.loop.start({ runId: 'run_l', agent: w.agent('coder'), prompt: 'install' })
  assert.equal(ran.status, 'ok', String(ran.reason))
  assert.deepEqual(offered(w.provider.requests[0]), [])
  assert.equal(w.driver.specs.length, 0)
})

test("a channel run's result is assembled from the session's capture of each stream, the docker client's stderr after the command's, each cut by its own capture", { timeout: 20_000 }, async (t) => {
  const args = { command: ['make'] }
  // The command's stdout frames overflow the session's capture: shown from
  // its start, said to be cut, and the result marked cut, though the docker
  // client's own capture (its stdout is the frame stream) was not.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true }] })
    const call = d.tools.call(ticketFor('run_o', args), args, context('run_o'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    const block = 'o'.repeat(32_768)
    for (let sent = 0; sent <= CAPTURE_MAX_BYTES; sent += block.length) mux.stdout(block)
    mux.exit(0)
    d.driver.simulateExit(name)
    const out = await call
    assert.match(out.text, /\n\[output cut: a stream carried more than \d+ bytes, and the driver kept only its first; such a stream is shown from its start\]\n/)
    assert.match(out.text, /\n--- stdout \(its start, redacted: \d+ bytes, of the \d+ bytes its capture kept; the stream may have carried more\) ---\no/)
    const [result] = payloads(d.store, 'tool.result')
    assert.equal(result?.['truncated'], true)
  }
  // The docker client writes stderr of its own (the mux's complaints): a
  // section of its own, after the command's stderr.
  {
    const fx = egressOf()
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true, stderr: 'mux: a worker left a flow open\n' }] })
    const call = d.tools.call(ticketFor('run_e', args), args, context('run_e'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.stderr('make: nothing to do\n')
    mux.exit(0)
    d.driver.simulateExit(name)
    const out = await call
    assert.equal(out.ok, true, out.text)
    assert.match(out.text, /--- stderr \(\d+ bytes\) ---\nmake: nothing to do\n\n\[the docker client's stderr\]\nmux: a worker left a flow open\n$/)
  }
  // The docker client's own capture was cut: stderr is marked cut, and read
  // by its start, whatever the session's capture of the command kept.
  {
    const fx = egressOf()
    const flood = 'm'.repeat(CAPTURE_MAX_BYTES)
    const d = direct(t, { files: { coder: EGRESS_CODER }, egress: fx.egress, exits: [{ hangs: true, stderr: flood, truncated: true }] })
    const call = d.tools.call(ticketFor('run_t', args), args, context('run_t'))
    await until(() => d.driver.channels.length === 1, 'the channel')
    const name = d.driver.channels[0]!.name
    const mux = new FakeMux(d.driver.channels[0]!)
    await mux.ready()
    mux.exit(0)
    d.driver.simulateExit(name)
    const out = await call
    assert.match(out.text, /\n\[output cut: a stream carried more than \d+ bytes/)
    assert.match(out.text, /\n--- stderr \(its start, redacted: \d+ bytes, of the \d+ bytes its capture kept; the stream may have carried more\) ---\n\n\[the docker client's stderr\]\nm/)
  }
})
