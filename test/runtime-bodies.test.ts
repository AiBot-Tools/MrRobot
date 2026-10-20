// The Phase 1 live runtime checks, run OFFLINE on every `npm test`.
//
// The bodies in helpers/runtime-bodies.ts are what test/live-runtime.test.ts
// runs against the operator's pmmcp and the real model. Here they run against the
// pmmcp double and a scripted provider, so every assertion a live run depends on
// has already been seen to pass — and, in the falsifier pass, seen to fail. A live
// test whose assertions have never executed is a test nobody knows is correct.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'
import { parse as parseYaml } from 'yaml'

import { parseManifest, type AgentManifest } from '../src/agents/manifest.js'
import { parseKernelConfig } from '../src/config.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { anthropicEndTurn, anthropicToolUse, fakeProvider, http, type RecordedRequest, type ScriptEntry } from './helpers/fake-provider.js'
import { bootCrashable, bootOn, fixture, REPO_ROOT, runThroughControl, TEST_TOKEN, withKernel } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'
import {
  evalHarnessAssumptions,
  goalTreeRoundTrip,
  objectiveFanOut,
  restartMidFanOut,
  LIVE_ORCHESTRATOR,
  LIVE_TEST_PROJECT,
  liveFleet,
  PLAN_REQUEST,
  planToTree,
  SCRIPTED_PLAN,
} from './helpers/runtime-bodies.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const REF = 'anthropic/claude-sonnet-5'
const VAULT_ID = 'anthropic-api-key'

function shippedGoals(): ReturnType<typeof parseKernelConfig>['goals'] {
  return parseKernelConfig(parseYaml(readFileSync(`${REPO_ROOT}/config/kernel.yaml`, 'utf8')), {
    repoRoot: REPO_ROOT,
  }).goals
}

test('goalTreeRoundTrip holds against the double', async (t) => {
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const hub = new McpHub({
    store,
    views: parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8'))),
  })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)

  await goalTreeRoundTrip({ hub, store, goals: shippedGoals(), projectId: LIVE_TEST_PROJECT, runId: 'run_offline' })

  // Everything it wrote is in the test namespace and nowhere else.
  assert.ok(mock.state.goals.size > 0)
  for (const goal of mock.state.goals.values()) assert.equal(goal.projectId, LIVE_TEST_PROJECT)
})

test('planToTree holds against the double, and nothing lands in aos/ceo', async (t) => {
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider([anthropicEndTurn({ text: SCRIPTED_PLAN, inputTokens: 1_500, outputTokens: 400 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-runtime' },
    fetch: provider.fetch,
    agentsDir: liveFleet(tmpdir(t), REF),
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })

  const { tasks } = await planToTree({
    dbPath: fx.dbPath,
    run: () => runThroughControl(kernel, PLAN_REQUEST, LIVE_ORCHESTRATOR),
    shutdown: () => kernel.shutdown(),
    projectId: LIVE_TEST_PROJECT,
  })
  assert.equal(tasks, 2)

  // The point of the fleet fixture: the operator's own tree is untouched.
  for (const goal of mock.state.goals.values()) {
    assert.notEqual(goal.projectId, 'aos/ceo', 'a runtime test wrote into the operator’s CEO namespace')
  }
  // And the prompt the live model will see is the one the double answered.
  assert.equal(provider.requests.length, 1)
  assert.match(JSON.stringify(provider.requests[0]?.body ?? ''), /append-only event log/)
})

test('planToTree fails with the parser’s reason when the model’s plan does not parse', async (t) => {
  // The failure path is the one a live run is most likely to take: a real model
  // adds a key the strict schema refuses. The message must say which, or the
  // operator is left guessing whether the model, the parser or the server failed.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const withExtraKey = SCRIPTED_PLAN.replace('"assumptions": []', '"assumptions": [],\n  "confidence": 0.9')
  const provider = fakeProvider([anthropicEndTurn({ text: withExtraKey, inputTokens: 1_500, outputTokens: 400 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-runtime' },
    fetch: provider.fetch,
    agentsDir: liveFleet(tmpdir(t), REF),
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })

  await assert.rejects(
    () =>
      planToTree({
        dbPath: fx.dbPath,
        run: () => runThroughControl(kernel, PLAN_REQUEST, LIVE_ORCHESTRATOR),
        shutdown: () => kernel.shutdown(),
        projectId: LIVE_TEST_PROJECT,
      }),
    (e: unknown) => {
      const message = String(e)
      assert.match(message, /no plan was adopted/)
      // Anchored on the parser's own segment. An earlier version matched
      // /confidence/ anywhere — and the message also echoes the model's text,
      // which contains "confidence", so it passed with the reason deleted.
      assert.match(
        message,
        /Parser: plan refused: [^.]*[Uu]nrecognized key[^.]*confidence/,
        'the parser’s reason is missing from the failure',
      )
      assert.match(message, /The model said:/)
      return true
    },
  )
  assert.equal(mock.state.goals.size, 0)
})

test('evalHarnessAssumptions holds against a scripted provider', async (t) => {
  const provider = fakeProvider([
    anthropicEndTurn({ text: 'The shared vault is the single point of compromise.', inputTokens: 900, outputTokens: 60 }),
  ])
  const { kernel, fx } = await withKernel(t, {
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-eval-runtime' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })
  const result = await evalHarnessAssumptions({
    port: kernel.port,
    token: TEST_TOKEN,
    dbPath: fx.dbPath,
    timeoutMs: 20_000,
  })
  assert.equal(result.caseId, 'ceo-inline-small-objective')
})

// ── negative runs ──────────────────────────────────────────────────────────
//
// The bodies ARE tests, and a test's assertion deleted from a passing path still
// passes. A falsifier pass found exactly that: removing the namespace check from
// planToTree, the id read-back from goalTreeRoundTrip and the calibration checks
// from evalHarnessAssumptions all survived, because the offline runs only ever
// took the happy path. Each body is therefore also run against the precise
// violation it exists to catch, and must refuse.

test('goalTreeRoundTrip refuses a server that does not know the goals it created', async (t) => {
  const mock = pmmcpMock({ forgetsGoals: true })
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const hub = new McpHub({
    store,
    views: parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8'))),
  })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)

  await assert.rejects(
    () => goalTreeRoundTrip({ hub, store, goals: shippedGoals(), projectId: LIVE_TEST_PROJECT, runId: 'run_neg' }),
    /is not in the tree the server returned/,
  )
})

test('planToTree refuses a tree written anywhere but the namespace it was told to expect', async (t) => {
  // The live protection against writing into the operator's CEO tree is THIS
  // assertion inside the body; on a live run nothing else checks it. So it is
  // run against a kernel that writes to the test namespace while the body is
  // told to expect another, and must say so.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider([anthropicEndTurn({ text: SCRIPTED_PLAN, inputTokens: 1_500, outputTokens: 400 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-runtime' },
    fetch: provider.fetch,
    agentsDir: liveFleet(tmpdir(t), REF),
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })

  await assert.rejects(
    () =>
      planToTree({
        dbPath: fx.dbPath,
        run: () => runThroughControl(kernel, PLAN_REQUEST, LIVE_ORCHESTRATOR),
        shutdown: () => kernel.shutdown(),
        projectId: 'aos/agent/somewhere-else',
      }),
    /somewhere other than the test namespace/,
  )
})

test('evalHarnessAssumptions refuses a run whose calibration checks could not pass', async (t) => {
  // A run that never got a model answer leaves `llm-events-paired` and
  // `cost-reconciles-with-log` n/a — not failed, and not passed. The body demands
  // PASS on both, because a live run that proved nothing about accounting must not
  // read as one that proved it right. Three 500s, one per attempt the router's
  // retry cap allows.
  const provider = fakeProvider([
    http(500, { error: { type: 'api_error', message: 'upstream down' } }),
    http(500, { error: { type: 'api_error', message: 'upstream down' } }),
    http(500, { error: { type: 'api_error', message: 'upstream down' } }),
  ])
  const { kernel, fx } = await withKernel(t, {
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-eval-runtime' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })
  await assert.rejects(
    () => evalHarnessAssumptions({ port: kernel.port, token: TEST_TOKEN, dbPath: fx.dbPath, timeoutMs: 20_000 }),
    /llm-events-paired|cost-reconciles-with-log/,
  )
})

test("the live fleet's orchestrator is the shipped CEO in every field but its id, model and memory, and loses its kernel tools only when asked to", (t) => {
  const read = (path: string): AgentManifest => parseManifest(parseYaml(readFileSync(path, 'utf8')), path)
  const shipped = read(`${REPO_ROOT}/agents/ceo/agent.yaml`)
  const other = 'openai/a-model'
  for (const delegation of [true, false]) {
    const live = read(join(liveFleet(tmpdir(t), other, { delegation }), LIVE_ORCHESTRATOR, 'agent.yaml'))
    assert.equal(live.id, LIVE_ORCHESTRATOR)
    assert.equal(live.model.primary, other)
    assert.equal(live.memory.projectId, LIVE_TEST_PROJECT)
    assert.deepEqual(live.tools.allow, delegation ? shipped.tools.allow : [], `delegation ${String(delegation)}`)
    // Everything else, field for field: role, soul, tier, egress, spawn, budget, version.
    const rest = (m: AgentManifest): unknown => ({ ...m, id: '', model: { ...m.model, primary: '' }, memory: {}, tools: { ...m.tools, allow: [] } })
    assert.deepEqual(rest(live), rest(shipped), `delegation ${String(delegation)}`)
  }
  // The shipped CEO's tools are the kernel's two, so "with delegation" means it can fan out.
  assert.deepEqual([...shipped.tools.allow].sort(), ['kernel.adopt_plan', 'kernel.delegate'])
})

// ── Phase 1 exit ───────────────────────────────────────────────────────────

const FAN_OUT_PLAN = {
  objective: { title: 'compare two event log stores', successCriteria: ['both written up and compared'] },
  milestones: [
    {
      id: 'm1',
      title: 'two independent write-ups',
      tasks: [
        { id: 't1', title: 'write up sqlite with triggers', template: 'researcher', acceptance: ['a findings note'], dependsOn: [] },
        { id: 't2', title: 'write up an append-only file with an index', template: 'writer', acceptance: ['a findings note'], dependsOn: [] },
      ],
    },
  ],
  assumptions: [],
  risks: [],
  questionsForOperator: [],
}

/** Child run ids the kernel handed back in tool results, in order. */
const childIdsIn = (request: RecordedRequest): string[] => [...new Set(JSON.stringify(request.body).match(/run_\d+_[a-z0-9]+/g) ?? [])]

/** The live-test fleet, delegating as shipped, against the double and a script. */
async function fanOutKernel(t: TestContext, script: readonly ScriptEntry[]): Promise<{ port: number; dbPath: string }> {
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-fanout' },
    fetch: fakeProvider(script).fetch,
    agentsDir: liveFleet(tmpdir(t), REF, { delegation: true }),
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })
  return { port: kernel.port, dbPath: fx.dbPath }
}

test('objectiveFanOut holds against the double: a tree in the test namespace, two children, a summary the log backs', async (t) => {
  // Fetch order is call order: the orchestrator, each child during its delegate
  // call, then the orchestrator's summary naming both children.
  const { port, dbPath } = await fanOutKernel(t, [
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: FAN_OUT_PLAN } }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'Write up SQLite with append-only triggers.' } }),
    anthropicEndTurn({ text: 'SQLite: triggers refuse UPDATE and DELETE.', inputTokens: 800, outputTokens: 80 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't2', brief: 'Write up an append-only file with an index.' } }),
    anthropicEndTurn({ text: 'Flat file: simple, but the index is a second thing to keep honest.', inputTokens: 900, outputTokens: 90 }),
    (request) => {
      const [first, second] = childIdsIn(request)
      return anthropicEndTurn({
        text: `Compared. t1 ran as ${String(first)} and t2 as ${String(second)}; both finished ok.`,
        inputTokens: 1_200,
        outputTokens: 60,
      })
    },
  ])
  const result = await objectiveFanOut({ port, token: TEST_TOKEN, dbPath, timeoutMs: 20_000 }, { agentId: LIVE_ORCHESTRATOR, projectId: LIVE_TEST_PROJECT })
  assert.equal(result.caseId, 'ceo-objective-fanout')
})

test('objectiveFanOut holds when both write-ups go to one worker: two tasks, not a repeat', async (t) => {
  // The shipped objective asks for two researched write-ups, so a plan giving
  // both to the researcher is the natural one and must not fail the exit.
  const sameWorker = JSON.parse(JSON.stringify(FAN_OUT_PLAN).replace('"template":"writer"', '"template":"researcher"')) as typeof FAN_OUT_PLAN
  const { port, dbPath } = await fanOutKernel(t, [
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: sameWorker } }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'Write up SQLite with triggers.' } }),
    anthropicEndTurn({ text: 'SQLite note.', inputTokens: 300, outputTokens: 30 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't2', brief: 'Write up the flat file.' } }),
    anthropicEndTurn({ text: 'Flat file note.', inputTokens: 300, outputTokens: 30 }),
    (request) => {
      const [first, second] = childIdsIn(request)
      return anthropicEndTurn({ text: `Compared: ${String(first)} and ${String(second)}.`, inputTokens: 400, outputTokens: 20 })
    },
  ])
  await objectiveFanOut({ port, token: TEST_TOKEN, dbPath, timeoutMs: 20_000 }, { agentId: LIVE_ORCHESTRATOR, projectId: LIVE_TEST_PROJECT })
})

test('objectiveFanOut refuses an orchestrator that answers alone, and one whose summary drops a child', async (t) => {
  const alone = await fanOutKernel(t, [anthropicEndTurn({ text: 'SQLite is better. Done.', inputTokens: 500, outputTokens: 20 })])
  await assert.rejects(
    () => objectiveFanOut({ port: alone.port, token: TEST_TOKEN, dbPath: alone.dbPath, timeoutMs: 20_000 }, { agentId: LIVE_ORCHESTRATOR, projectId: LIVE_TEST_PROJECT }),
    /child-runs/,
  )
  const dropped = await fanOutKernel(t, [
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: FAN_OUT_PLAN } }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'one' } }),
    anthropicEndTurn({ text: 'one', inputTokens: 100, outputTokens: 10 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't2', brief: 'two' } }),
    anthropicEndTurn({ text: 'two', inputTokens: 100, outputTokens: 10 }),
    (request) => anthropicEndTurn({ text: `Compared; see ${String(childIdsIn(request)[0])}.`, inputTokens: 100, outputTokens: 10 }),
  ])
  await assert.rejects(
    () => objectiveFanOut({ port: dropped.port, token: TEST_TOKEN, dbPath: dropped.dbPath, timeoutMs: 20_000 }, { agentId: LIVE_ORCHESTRATOR, projectId: LIVE_TEST_PROJECT }),
    /child-outcomes-accounted/,
  )
})

/**
 * A provider whose `hangAt`-th call never returns a body, as a model call the
 * crash interrupts: headers now, no end, so nothing is held open after the test.
 */
function hangingAt(script: readonly ScriptEntry[], hangAt: number): typeof globalThis.fetch {
  const scripted = fakeProvider(script)
  let calls = 0
  return (input, init) => {
    calls += 1
    if (calls >= hangAt) {
      return Promise.resolve(
        new Response(new ReadableStream<Uint8Array>({ start: () => undefined }), { status: 200, headers: { 'content-type': 'application/json' } }),
      )
    }
    return scripted.fetch(input, init)
  }
}

async function restartFixture(
  t: TestContext,
  script: readonly ScriptEntry[],
  hangAt: number,
  server: Parameters<typeof pmmcpMock>[0] = {},
): Promise<Parameters<typeof restartMidFanOut>[0]> {
  const mock = pmmcpMock(server)
  t.after(async () => {
    await mock.close()
  })
  const fx = fixture(t)
  writeProbeRecord(fx.dataDir, freshProbe(REF))
  const agentsDir = liveFleet(tmpdir(t), REF, { delegation: true })
  const env = { ANTHROPIC_API_KEY: 'offline-fixture-credential-restart' }
  return {
    dbPath: fx.dbPath,
    agentId: LIVE_ORCHESTRATOR,
    waitMs: 20_000,
    boot: () => bootCrashable(t, fx, { env, clientFactory: mock.connect, fetch: hangingAt(script, hangAt), agentsDir }),
    // The reboot calls no model: an empty script throws on any call.
    reboot: () => bootOn(t, fx, { env, clientFactory: mock.connect, fetch: fakeProvider([]).fetch, agentsDir }),
  }
}

test('restartMidFanOut holds against the double: the crash comes with a child in its first model call, and nothing is orphaned', async (t) => {
  // The orchestrator adopts and delegates t1; the child's first call (the third) hangs.
  const ctx = await restartFixture(
    t,
    [
      anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: FAN_OUT_PLAN }, inputTokens: 1_000, outputTokens: 50 }),
      anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'Write up SQLite with triggers.' }, inputTokens: 1_100, outputTokens: 40 }),
    ],
    3,
  )
  const { ceoRunId, inFlight } = await restartMidFanOut(ctx)
  assert.notEqual(ceoRunId, inFlight)
})

test('restartMidFanOut refuses an orchestrator that never put a child in flight', async (t) => {
  const ctx = await restartFixture(t, [anthropicEndTurn({ text: 'Answered alone.', inputTokens: 300, outputTokens: 10 })], 99)
  await assert.rejects(() => restartMidFanOut(ctx), /finished before any child was in a model call/)
})

test('restartMidFanOut holds when pmmcp answers late, as it does over HTTP: shutdown waits for the restart to block the orphan', async (t) => {
  // The in-memory double answers within the same turn, which hid a shutdown
  // that closed the hub under the recovery's move. Here every goal move answers
  // after 25 ms.
  const ctx = await restartFixture(
    t,
    [
      anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: FAN_OUT_PLAN }, inputTokens: 1_000, outputTokens: 50 }),
      anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'Write up SQLite with triggers.' }, inputTokens: 1_100, outputTokens: 40 }),
    ],
    3,
    { answerAfterMs: { update_goal: 25 } },
  )
  await restartMidFanOut(ctx)
})
