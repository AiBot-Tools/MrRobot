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
import test from 'node:test'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { anthropicEndTurn, fakeProvider, http } from './helpers/fake-provider.js'
import { REPO_ROOT, runThroughControl, TEST_TOKEN, withKernel } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'
import {
  evalHarnessAssumptions,
  goalTreeRoundTrip,
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
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-runtime' } })
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider([anthropicEndTurn({ text: SCRIPTED_PLAN, inputTokens: 1_500, outputTokens: 400 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
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
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-runtime' } })
  t.after(async () => {
    await mock.close()
  })
  const withExtraKey = SCRIPTED_PLAN.replace('"assumptions": []', '"assumptions": [],\n  "confidence": 0.9')
  const provider = fakeProvider([anthropicEndTurn({ text: withExtraKey, inputTokens: 1_500, outputTokens: 400 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
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
    envFallback: true,
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

test('goalTreeRoundTrip refuses a server that does not return the ids it created', async (t) => {
  const mock = pmmcpMock({ listGoalsReturnsNothing: true })
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
    /is not among the milestone's children/,
  )
})

test('planToTree refuses a tree written anywhere but the namespace it was told to expect', async (t) => {
  // The live protection against writing into the operator's CEO tree is THIS
  // assertion inside the body; on a live run nothing else checks it. So it is
  // run against a kernel that writes to the test namespace while the body is
  // told to expect another, and must say so.
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-runtime' } })
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider([anthropicEndTurn({ text: SCRIPTED_PLAN, inputTokens: 1_500, outputTokens: 400 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
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
    envFallback: true,
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
