// Delegation, end to end, through the real kernel.
//
// The Phase 1 exit criterion is "one objective → goal tree + ≥2 child runs +
// trustworthy summary". Everything here drives the shipped fleet (the CEO v2
// manifest with its two kernel tools, the researcher, the writer) against the pmmcp
// double and a scripted provider, and then asks the eval harness — which reads only
// the log — whether the run met that shape. The harness is the judge on purpose: a
// test that asserted success its own way could pass while the harness, the thing
// the operator will actually trust, disagreed.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test, { type TestContext } from 'node:test'

import { CEO_CHECKS } from '../src/eval/checks.js'
import { runCase } from '../src/eval/harness.js'
import { writeProbeRecord } from '../src/models/probe.js'
import {
  anthropicEndTurn,
  anthropicToolUse,
  fakeProvider,
  type RecordedRequest,
  type ScriptEntry,
} from './helpers/fake-provider.js'
import { rows, runThroughControl, TEST_TOKEN, withKernel } from './helpers/kernel.js'
import { pmmcpMock, type PmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'

const REF = 'anthropic/claude-sonnet-5'
const VAULT_ID = 'anthropic-api-key'
const CEO_PROJECT = 'aos/ceo'

const PLAN = {
  objective: { title: 'compare two append-only log stores', successCriteria: ['both compared in writing'] },
  milestones: [
    {
      id: 'm1',
      title: 'research then write',
      tasks: [
        {
          id: 't1',
          title: 'research sqlite with triggers',
          template: 'researcher',
          acceptance: ['a findings note with sources'],
          dependsOn: [],
        },
        {
          id: 't2',
          title: 'write the comparison',
          template: 'writer',
          acceptance: ['a comparison citing the findings'],
          dependsOn: ['t1'],
        },
      ],
    },
  ],
  assumptions: [],
  risks: [],
  questionsForOperator: [],
}

/** Child run ids the kernel handed back in tool results, in order. */
function childIdsIn(request: RecordedRequest): string[] {
  const text = JSON.stringify(request.body)
  return [...new Set(text.match(/run_\d+_[a-z0-9]+/g) ?? [])]
}

async function boot(
  t: TestContext,
  script: readonly ScriptEntry[],
): Promise<{ mock: PmmcpMock; kernel: Awaited<ReturnType<typeof withKernel>>['kernel']; dbPath: string; requests: RecordedRequest[] }> {
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-delegation' } })
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider(script)
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REF))
    },
  })
  return { mock, kernel, dbPath: fx.dbPath, requests: provider.requests }
}

const payloads = (dbPath: string, type: string): Record<string, unknown>[] =>
  rows(dbPath)
    .filter((r) => r.type === type)
    .map((r) => JSON.parse(r.payload) as Record<string, unknown>)

test('one objective → goal tree + two child runs + a summary the eval harness accepts', async (t) => {
  // Fetch order is the order the kernel makes calls: the CEO, then each child
  // DURING the CEO's delegate call, then the CEO again.
  const { mock, kernel, dbPath } = await boot(t, [
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: PLAN } }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'Research SQLite with append-only triggers; cite sources.' } }),
    anthropicEndTurn({ text: 'Findings: triggers refuse UPDATE/DELETE; WAL gives durability. Sources: sqlite.org.', inputTokens: 800, outputTokens: 80 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't2', brief: 'Write the comparison from the t1 findings.' } }),
    anthropicEndTurn({ text: 'Comparison: SQLite with triggers wins on auditability; the flat file wins on simplicity.', inputTokens: 900, outputTokens: 120 }),
    (request) => {
      const [first, second] = childIdsIn(request)
      return anthropicEndTurn({
        text: `Done. t1 ran as ${String(first)} (researcher) and t2 as ${String(second)} (writer); both finished ok.`,
        inputTokens: 1_200,
        outputTokens: 60,
      })
    },
  ])

  const result = await runCase(
    { port: kernel.port, token: TEST_TOKEN, dbPath, timeoutMs: 30_000 },
    {
      id: 'offline-delegation',
      title: 'the exit criterion shape, offline',
      agentId: 'ceo',
      input: 'Compare two append-only log stores. Plan it, then delegate.',
      expect: { status: ['ok'], minChildRuns: 2, maxCostMicroUsd: 2_000_000, irreversibleInventory: [] },
    },
    CEO_CHECKS,
  )
  const summary = result.checks.map((c) => `${c.verdict} ${c.id}: ${c.detail}`).join('\n')

  // THE assertion: the harness, reading only the log, finds nothing to fail —
  // including the four cheat-fixture checks that were n/a until delegation existed.
  assert.deepEqual(result.gatesFailed, [], summary)
  const verdict = new Map(result.checks.map((c) => [c.id, c.verdict]))
  for (const id of ['child-runs', 'child-goal-ancestry', 'no-duplicate-dispatch', 'child-outcomes-accounted', 'cost-reconciles-with-log', 'evidence-refs-resolve']) {
    assert.equal(verdict.get(id), 'pass', `${id} did not pass:\n${summary}`)
  }

  await kernel.shutdown()

  // The goal tree: one plan, written once (the final message did not trigger a
  // second adoption), four goals, all in aos/ceo.
  assert.equal(payloads(dbPath, 'plan.adopted').length, 1)
  const created = payloads(dbPath, 'goal.created')
  assert.equal(created.length, 4)
  for (const goal of created) assert.equal(goal['projectId'], CEO_PROJECT)

  // Two children, each on the worker its task named, each carrying its goal.
  const admitted = payloads(dbPath, 'delegation.admitted')
  assert.deepEqual(admitted.map((a) => `${String(a['taskId'])}:${String(a['agentId'])}`), ['t1:researcher', 't2:writer'])
  for (const a of admitted) {
    assert.equal(typeof a['goalId'], 'string')
    assert.ok((a['ceilingMicroUsd'] as number) > 0)
  }

  // Both task goals moved in the CEO's namespace — the tracker bug fixed last
  // commit is exactly what this depends on — and nothing was closed by the kernel.
  const taskGoals = admitted.map((a) => String(a['goalId']))
  for (const goalId of taskGoals) {
    assert.equal(mock.state.goals.get(goalId)?.status, 'review', `${goalId} did not reach review`)
    assert.equal(mock.state.goals.get(goalId)?.projectId, CEO_PROJECT)
  }
  assert.equal(
    [...mock.state.goals.values()].some((g) => g.status === 'done'),
    false,
    'the kernel closed a goal itself',
  )

  // Money: the parent paid for its children, and the log says so twice over.
  const results = payloads(dbPath, 'delegation.result')
  assert.equal(results.length, 2)
  const childCost = results.reduce((n, r) => n + (r['costMicroUsd'] as number), 0)
  assert.ok(childCost > 0)
  const ceoFinished = rows(dbPath).find(
    (r) => r.type === 'run.finished' && (JSON.parse(r.payload) as { runId: string }).runId === result.runId,
  )
  const ceoCost = (JSON.parse(ceoFinished?.payload ?? '{}') as { costMicroUsd: number }).costMicroUsd
  assert.ok(ceoCost > childCost, 'the parent’s cost does not include its own calls plus its children')
})

test('the kernel refuses what the plan does not allow, and says why', async (t) => {
  // One CEO run that tries every refusal in turn, then stops. Nothing it asks for
  // out of order may start a child.
  const { kernel, dbPath } = await boot(t, [
    // Before any plan.
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'go' } }),
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: PLAN } }),
    // A second plan in the same run.
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: PLAN } }),
    // A task that is not in the plan.
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't9', brief: 'go' } }),
    // t2 before its dependency.
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't2', brief: 'go' } }),
    anthropicEndTurn({ text: 'stopping', inputTokens: 100, outputTokens: 10 }),
  ])

  await runThroughControl(kernel, 'try everything out of order')
  await kernel.shutdown()

  const refused = payloads(dbPath, 'delegation.refused').map((r) => String(r['reason']))
  assert.equal(refused.length, 4, refused.join('\n'))
  assert.match(refused[0] ?? '', /no plan adopted in this run/)
  assert.match(refused[1] ?? '', /already adopted/)
  assert.match(refused[2] ?? '', /t9 is not a task in the adopted plan/)
  assert.match(refused[3] ?? '', /t2 depends on t1, which has not been delegated/)
  assert.equal(payloads(dbPath, 'delegation.admitted').length, 0, 'a refused delegation started a child')
  // The one adoption that was allowed wrote one tree.
  assert.equal(payloads(dbPath, 'plan.adopted').length, 1)
})

test('a task cannot be delegated twice in one run', async (t) => {
  const { kernel, dbPath } = await boot(t, [
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: PLAN } }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'research' } }),
    anthropicEndTurn({ text: 'findings', inputTokens: 100, outputTokens: 10 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'research again' } }),
    anthropicEndTurn({ text: 'stopping', inputTokens: 100, outputTokens: 10 }),
  ])
  // The race-safe waiter: a CEO run that dies fast can finish before the
  // run.start reply lands, and a listener keyed on the not-yet-known id would
  // wait forever.
  await runThroughControl(kernel, 'go')
  await kernel.shutdown()

  // Double dispatch is impossible, not merely scored: one child, one refusal.
  assert.equal(payloads(dbPath, 'delegation.admitted').length, 1)
  const refused = payloads(dbPath, 'delegation.refused').map((r) => String(r['reason']))
  assert.deepEqual(refused, ['t1 was already delegated in this run'])
})

test('the kernel enforces the ceiling it hands a child, not the child’s own cap', async (t) => {
  // Handing a child a ceiling proves nothing if the kernel then builds the
  // child's budget from its manifest alone. So the ceiling has to BITE here:
  // the CEO spends all but 50_000 µ$ of its 2_000_000 default before it
  // delegates, and the researcher's first turn costs 61_000 µ$ — far under its
  // own 500_000 cap, over the slice it was handed. Pricing is the shipped card
  // for this ref: 2 µ$ per input token, 10 per output token.
  const { kernel, dbPath } = await boot(t, [
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: PLAN }, inputTokens: 900_000, outputTokens: 100 }),
    anthropicToolUse({
      name: 'kernel__delegate',
      input: { taskId: 't1', brief: 'research' },
      inputTokens: 74_000,
      outputTokens: 100,
    }),
    // The child asks for a tool, so the loop takes another turn and must look
    // at the budget before it does. A child still under budget would make a
    // fourth provider call here; the script has none to give it.
    anthropicToolUse({ name: 'pmmcp__recall', input: { query: 'x' }, inputTokens: 30_000, outputTokens: 100 }),
  ])

  await runThroughControl(kernel, 'go')
  await kernel.shutdown()

  const [admitted] = payloads(dbPath, 'delegation.admitted')
  assert.equal(admitted?.['ceilingMicroUsd'], 50_000, 'the slice handed down is not what the parent had left')
  const childId = String(admitted?.['childRunId'])
  const childEnd = payloads(dbPath, 'run.finished').find((p) => p['runId'] === childId)
  assert.equal(childEnd?.['costMicroUsd'], 61_000)
  assert.equal(childEnd?.['status'], 'killed', `the child ran past its ceiling: ${JSON.stringify(childEnd)}`)
  assert.equal(childEnd?.['reason'], 'usdMax')
  // And what it spent was still charged upward.
  const [result] = payloads(dbPath, 'delegation.result')
  assert.equal(result?.['costMicroUsd'], 61_000)
})
