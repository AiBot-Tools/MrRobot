// A kernel restart in the middle of a delegation orphans nothing.
//
// The Phase 1 exit criterion, for the one shape where a run is waiting on
// another run. The crash here is real, not modelled: the shipped fleet runs a
// CEO that adopts a plan, delegates t1 to the researcher (which finishes), then
// delegates t2 to the writer — whose first model call never returns. The
// process dies at that moment, with the CEO blocked inside `kernel.delegate` and
// the writer blocked inside a provider call. A hand-written crash log could
// drift from what the kernel actually writes; this one cannot.
//
// What "orphans nothing" has to mean for delegation:
//   every run that started has a terminal row;
//   every admission has a result, filed after its child ends and before its
//     parent does — the order the live kernel writes them in;
//   the parent's bill is everything spent on its account, children included;
//   the in-flight child's task goal is blocked, not left in_progress;
//   nothing re-executes, and a second restart finds nothing to do.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test from 'node:test'

import { connectControl } from '../src/cli/client.js'
import { costReconciles } from '../src/eval/checks.js'
import { observe } from '../src/eval/observe.js'
import { EventStore } from '../src/events/store.js'
import { readAllRows, type EventRow } from '../src/events/chain.js'
import { isClean } from '../src/events/projections.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { anthropicEndTurn, anthropicToolUse, fakeProvider } from './helpers/fake-provider.js'
import { bootCrashable, bootOn, fixture, TEST_TOKEN } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'

const REF = 'anthropic/claude-sonnet-5'
const VAULT_ID = 'anthropic-api-key'

const PLAN = {
  objective: { title: 'compare two append-only log stores', successCriteria: ['both compared in writing'] },
  milestones: [
    {
      id: 'm1',
      title: 'research then write',
      tasks: [
        { id: 't1', title: 'research', template: 'researcher', acceptance: ['findings'], dependsOn: [] },
        { id: 't2', title: 'write', template: 'writer', acceptance: ['a comparison'], dependsOn: ['t1'] },
      ],
    },
  ],
  assumptions: [],
  risks: [],
  questionsForOperator: [],
}

/** Every row, read back read-only, with run ids — which `rows()` does not carry. */
function logOf(dbPath: string): EventRow[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return readAllRows(store.db)
  } finally {
    store.close()
  }
}

const body = (row: EventRow): Record<string, unknown> => JSON.parse(row.payload) as Record<string, unknown>
const settle = (): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, 250)
  })

test('a restart mid-delegation orphans nothing: runs, admissions, bill and goals all close', async (t) => {
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-restart' } })
  t.after(async () => {
    await mock.close()
  })
  const fx = fixture(t)
  writeProbeRecord(fx.dataDir, freshProbe(REF))
  const env = { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' }

  // Fetch order is the order the kernel makes calls; the fifth is the writer's
  // first turn, and it hangs. (The writer is offered no tools, so there is no
  // honest way to script it a costed turn that does not end its run; the
  // in-flight child's spend reaching the parent's bill is proven in
  // projections.test.ts. Here child 1's result carries real spend upward.)
  const scripted = fakeProvider([
    anthropicToolUse({ name: 'kernel__adopt_plan', input: { plan: PLAN }, inputTokens: 1_000, outputTokens: 50 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't1', brief: 'research' }, inputTokens: 1_100, outputTokens: 40 }),
    anthropicEndTurn({ text: 'findings: triggers refuse UPDATE', inputTokens: 700, outputTokens: 60 }),
    anthropicToolUse({ name: 'kernel__delegate', input: { taskId: 't2', brief: 'write it up' }, inputTokens: 1_300, outputTokens: 40 }),
  ])
  let calls = 0
  let reached: () => void = () => undefined
  const hung = new Promise<void>((resolve) => {
    reached = resolve
  })
  const fetch: typeof globalThis.fetch = (input, init) => {
    calls += 1
    if (calls === 5) {
      reached()
      // Headers now, a body that never ends. The call is as in-flight as a
      // stalled network read, and the SDK's own request timer — cleared once
      // headers arrive — does not hold the test process open for ten minutes
      // after the "crash", which a real crash would have ended with the process.
      return Promise.resolve(
        new Response(new ReadableStream<Uint8Array>({ start: () => undefined }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    }
    return scripted.fetch(input, init)
  }

  const { kernel: first, crash } = await bootCrashable(t, fx, { env, clientFactory: mock.connect, fetch })
  const client = await connectControl({ port: first.port, token: TEST_TOKEN, timeoutMs: 20_000 })
  const { runId: ceoRunId } = (await client.call('run.start', { agentId: 'ceo', input: 'go' })) as { runId: string }
  client.close()
  await hung
  // The writer's goal move to in_progress rides the tracker's queue; let it land
  // so the restart has a live status to clean up rather than a pending one.
  await settle()
  await crash()

  const beforeRestart = logOf(fx.dbPath)
  const admissions = beforeRestart.filter((r) => r.type === 'delegation.admitted').map(body)
  assert.equal(admissions.length, 2, 'the crash did not happen mid-delegation')
  assert.equal(beforeRestart.filter((r) => r.type === 'delegation.result').length, 1)
  const writerRunId = String(admissions[1]?.['childRunId'])
  const writerGoal = String(admissions[1]?.['goalId'])
  assert.equal(mock.state.goals.get(writerGoal)?.status, 'in_progress')

  // The restart. A provider with an empty script: any model call throws, and
  // the assertion below that no llm.request follows the second boot says so.
  const second = await bootOn(t, fx, { env, clientFactory: mock.connect, fetch: fakeProvider([]).fetch })
  await settle()
  const recovered = second.recovered
  await second.shutdown()

  assert.deepEqual(recovered.orphanRuns.map((r) => r.runId), [ceoRunId, writerRunId])
  assert.deepEqual(recovered.danglingDelegations.map((d) => d.childRunId), [writerRunId])

  const log = logOf(fx.dbPath)
  const reboot = log.filter((r) => r.type === 'kernel.booted')[1]?.seq ?? Infinity

  // 1. Every run that started reached exactly one terminal row.
  const startedIds = log.filter((r) => r.type === 'run.started').map((r) => String(body(r)['runId']))
  assert.equal(startedIds.length, 3)
  for (const id of startedIds) {
    const terminals = log.filter((r) => r.type === 'run.finished' && body(r)['runId'] === id)
    assert.equal(terminals.length, 1, `run ${id} has ${String(terminals.length)} terminal rows`)
  }

  // 2. Every admission has exactly one result, in causal order.
  for (const a of admissions) {
    const results = log.filter((r) => r.type === 'delegation.result' && body(r)['childRunId'] === a['childRunId'])
    assert.equal(results.length, 1, `admission of ${String(a['childRunId'])} has no single result`)
  }
  const seqOf = (type: string, key: string, value: string): number =>
    log.find((r) => r.type === type && body(r)[key] === value)?.seq ?? -1
  const writerEnd = seqOf('run.finished', 'runId', writerRunId)
  const writerResult = seqOf('delegation.result', 'childRunId', writerRunId)
  const ceoEnd = seqOf('run.finished', 'runId', ceoRunId)
  assert.ok(reboot < writerEnd && writerEnd < writerResult && writerResult < ceoEnd, 'recovery rows out of causal order')

  // 3. The recovered result says what the log supports: the writer died in its
  // first call, so it spent nothing yet, executed nothing, and is provably clean.
  const result = body(log.find((r) => r.seq === writerResult) as EventRow)
  assert.deepEqual(
    { status: result['status'], costMicroUsd: result['costMicroUsd'], taint: result['taint'] },
    { status: 'error', costMicroUsd: 0, taint: 'clean' },
  )

  // 4. The parent's bill is every micro-dollar spent on its account: its own
  // calls and both children's. At depth 1 that is every llm.response in the log.
  const total = log.filter((r) => r.type === 'llm.response').reduce((n, r) => n + Number(body(r)['costMicroUsd']), 0)
  const ownOnly = log
    .filter((r) => r.type === 'llm.response' && r.runId === ceoRunId)
    .reduce((n, r) => n + Number(body(r)['costMicroUsd']), 0)
  assert.ok(total > ownOnly, 'no child spent anything, so the bill check proves nothing')
  const ceoFinished = body(log.find((r) => r.seq === ceoEnd) as EventRow)
  assert.equal(ceoFinished['costMicroUsd'], total, 'the recovered parent bill omits a child')
  assert.match(String(ceoFinished['reason']), /orphaned by a kernel restart/)
  // And the eval harness, reading only the log, agrees the parent's numbers add up.
  const reconciled = costReconciles.run(
    observe({ runId: ceoRunId, agentId: 'ceo', rows: log.filter((r) => r.runId === ceoRunId), log, expect: {} }),
  )
  assert.equal(reconciled.verdict, 'pass', reconciled.detail)

  // 5. The in-flight child's task goal is blocked, not left in_progress.
  assert.equal(mock.state.goals.get(writerGoal)?.status, 'blocked')

  // 6. Nothing re-executed after the reboot.
  assert.equal(log.filter((r) => r.seq > reboot && r.type === 'llm.request').length, 0)

  // 7. A second restart finds nothing left to close.
  const third = await bootOn(t, fx, { env, clientFactory: mock.connect, fetch: fakeProvider([]).fetch })
  const again = third.recovered
  await third.shutdown()
  assert.equal(isClean(again), true, JSON.stringify(again))
})
