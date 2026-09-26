// P1.1 — crash recovery, projected from the log.
//
// The projection is a pure function of rows, which is the whole reason it can be
// trusted: "what was open" and "what we did about it" must be two steps, or the
// second restart cannot tell them apart and re-terminates work it already closed.
//
// The falsifiers:
//
//   Report nothing open and a restart silently abandons a run mid-flight, an
//   approval a human was deciding, and a hold nobody reviewed. Empty is the
//   dangerous answer here — it reads as "everything was handled".
//   Treat a terminal row as not closing its subject and every boot re-terminates,
//   filling the log with duplicate run.finished rows.
//   Count an orphan's cost as zero and the bill understates what was spent.
//   Let quarantine.abandoned not close a hold and recovery loops forever.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { readAllRows } from '../src/events/chain.js'
import { isClean, projectRecovery } from '../src/events/projections.js'
import { withStore } from './helpers/store.js'

const BOOT = { schemaVersion: 1 as const, version: '0.0.1', configHash: 'h', degraded: [] }

type Store = ReturnType<typeof withStore>

function started(store: Store, runId: string, agentId = 'ceo'): void {
  store.append({
    type: 'run.started',
    runId,
    agentId,
    payload: { schemaVersion: 1, runId, agentId, lane: 'main', tier: 2, taint: 'clean' },
  })
}

function finished(store: Store, runId: string, costMicroUsd = 0): void {
  store.append({
    type: 'run.finished',
    runId,
    payload: {
      schemaVersion: 1, runId, status: 'ok', costMicroUsd,
      llmCalls: 0, toolCalls: 0, durationMs: 1,
    },
  })
}

function spent(store: Store, runId: string, costMicroUsd: number): void {
  store.append({
    type: 'llm.response',
    runId,
    payload: {
      schemaVersion: 1, ref: 'anthropic/claude-sonnet-5', attempt: 1, content: 'x',
      finish: 'end_turn', inputTokens: 10, outputTokens: 2, costMicroUsd, durationMs: 5,
    },
  })
}

function requested(store: Store, runId: string, approvalId: string): void {
  store.append({
    type: 'approval.requested',
    runId,
    payload: {
      schemaVersion: 1, approvalId, toolRef: 'github.merge_pull_request',
      argsPreview: '{"pr":7}', risk: 'irreversible',
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
    },
  })
}

function held(store: Store, runId: string, holdId: string): void {
  store.append({
    type: 'quarantine.held',
    runId,
    payload: { schemaVersion: 1, holdId, toolRef: 'web.fetch', reason: 'untrusted page' },
  })
}

test('a clean log projects nothing', (t) => {
  const store = withStore(t)
  store.append({ type: 'kernel.booted', payload: BOOT })
  // A whole run, start to finish, plus a decided approval and a released hold.
  started(store, 'run-1')
  spent(store, 'run-1', 900)
  requested(store, 'run-1', 'apr_1')
  store.append({
    type: 'approval.resolved',
    runId: 'run-1',
    payload: { schemaVersion: 1, approvalId: 'apr_1', decision: 'approved', byConnectionId: 'c1' },
  })
  held(store, 'run-1', 'hold_1')
  store.append({
    type: 'quarantine.released',
    runId: 'run-1',
    payload: { schemaVersion: 1, holdId: 'hold_1', byConnectionId: 'c1' },
  })
  finished(store, 'run-1', 900)
  store.append({ type: 'kernel.shutdown', payload: { schemaVersion: 1, reason: 'requested', uptimeMs: 5 } })

  const recovery = projectRecovery(readAllRows(store.db))
  assert.equal(isClean(recovery), true, JSON.stringify(recovery))
  // An empty log too: recovery on a first boot must be quiet, not a special case.
  assert.equal(isClean(projectRecovery([])), true)
})

test('replays a crash log into orphan runs, unresolved approvals and unreleased holds', (t) => {
  const store = withStore(t)
  store.append({ type: 'kernel.booted', payload: BOOT })

  // run-done finished; run-open did not. Only the second is an orphan, so the
  // projection cannot be passing by simply listing every run it sees.
  started(store, 'run-done')
  spent(store, 'run-done', 100)
  finished(store, 'run-done', 100)

  started(store, 'run-open', 'ceo')
  spent(store, 'run-open', 4_200)
  spent(store, 'run-open', 800)
  store.append({
    type: 'tool.result',
    runId: 'run-open',
    payload: {
      schemaVersion: 1, ticketId: 't1', toolRef: 'web.fetch', ok: true,
      text: 'page', bytes: 4, truncated: false, durationMs: 10,
    },
  })
  requested(store, 'run-open', 'apr_open')
  held(store, 'run-open', 'hold_open')

  const recovery = projectRecovery(readAllRows(store.db))
  assert.equal(isClean(recovery), false)

  assert.deepEqual(recovery.orphanRuns.map((r) => r.runId), ['run-open'])
  const orphan = recovery.orphanRuns[0]
  assert.ok(orphan)
  assert.equal(orphan.agentId, 'ceo')
  // Counted from the log. Zero here would understate a real bill, and two
  // responses plus one tool result is what the log holds.
  assert.equal(orphan.costMicroUsd, 5_000)
  assert.equal(orphan.llmCalls, 2)
  assert.equal(orphan.toolCalls, 1)

  assert.deepEqual(recovery.unresolvedApprovals.map((a) => a.approvalId), ['apr_open'])
  assert.equal(recovery.unresolvedApprovals[0]?.runId, 'run-open')
  assert.equal(recovery.unresolvedApprovals[0]?.risk, 'irreversible')
  assert.equal(recovery.unresolvedApprovals[0]?.toolRef, 'github.merge_pull_request')

  assert.deepEqual(recovery.unreleasedHolds.map((h) => h.holdId), ['hold_open'])
  assert.equal(recovery.unreleasedHolds[0]?.runId, 'run-open')
  // The record carries no content, because the content was never in the log.
  assert.equal('output' in (recovery.unreleasedHolds[0] ?? {}), false)

  // Costs are attributed per run, not pooled: run-done's spend is not on the
  // orphan's tab.
  assert.equal(recovery.orphanRuns.some((r) => r.runId === 'run-done'), false)
})

test('a resolved approval and a released hold are not pending', (t) => {
  const store = withStore(t)
  started(store, 'run-1')

  // Every way a request can close, including the two a recovery writes.
  for (const [i, decision] of (['approved', 'denied', 'expired'] as const).entries()) {
    const id = `apr_${String(i)}`
    requested(store, 'run-1', id)
    store.append({
      type: 'approval.resolved',
      runId: 'run-1',
      payload: {
        schemaVersion: 1,
        approvalId: id,
        decision,
        ...(decision === 'expired' ? {} : { byConnectionId: 'c1' }),
      },
    })
  }
  // And both ways a hold can end.
  held(store, 'run-1', 'hold_released')
  store.append({
    type: 'quarantine.released',
    runId: 'run-1',
    payload: { schemaVersion: 1, holdId: 'hold_released', byConnectionId: 'c1' },
  })
  held(store, 'run-1', 'hold_abandoned')
  store.append({
    type: 'quarantine.abandoned',
    runId: 'run-1',
    payload: { schemaVersion: 1, holdId: 'hold_abandoned', reason: 'the kernel restarted' },
  })

  const recovery = projectRecovery(readAllRows(store.db))
  assert.deepEqual(recovery.unresolvedApprovals, [])
  assert.deepEqual(recovery.unreleasedHolds, [])
  // The run itself is still open — closing its children does not close it, and
  // conflating the two would leave a run dangling while looking tidy.
  assert.deepEqual(recovery.orphanRuns.map((r) => r.runId), ['run-1'])
})

test('a terminal row written by a previous recovery closes its subject, so recovery does not repeat', (t) => {
  const store = withStore(t)
  started(store, 'run-1')
  requested(store, 'run-1', 'apr_1')
  held(store, 'run-1', 'hold_1')
  assert.equal(isClean(projectRecovery(readAllRows(store.db))), false)

  // Exactly the rows bootKernel writes. If any of the three failed to close its
  // subject, every restart would append another set and the log would grow
  // without bound while looking busy.
  store.append({
    type: 'run.finished',
    runId: 'run-1',
    payload: {
      schemaVersion: 1, runId: 'run-1', status: 'error', reason: 'orphaned by a kernel restart',
      costMicroUsd: 0, llmCalls: 0, toolCalls: 0, durationMs: 0,
    },
  })
  store.append({
    type: 'approval.resolved',
    runId: 'run-1',
    payload: { schemaVersion: 1, approvalId: 'apr_1', decision: 'expired' },
  })
  store.append({
    type: 'quarantine.abandoned',
    runId: 'run-1',
    payload: { schemaVersion: 1, holdId: 'hold_1', reason: 'the kernel restarted' },
  })

  assert.equal(isClean(projectRecovery(readAllRows(store.db))), true)
})

test('the projection writes nothing and survives a log it cannot fully read', (t) => {
  // Pure. Called twice on the same rows it gives the same answer, and appends
  // none of its own — a projection that wrote would make its own output part of
  // its next input.
  const store = withStore(t)
  started(store, 'run-1')
  requested(store, 'run-1', 'apr_1')
  const rows = readAllRows(store.db)
  const before = store.query().length

  const a = projectRecovery(rows)
  const b = projectRecovery(rows)
  assert.deepEqual(a, b)
  assert.equal(store.query().length, before, 'the projection appended to the log')

  // A row whose payload will not parse still counts as a row: its seq advances
  // and its type is honoured. Boot has already refused a log whose bytes are
  // damaged, so this is about robustness, not about trusting the bytes.
  const damaged = [...rows, { ...rows[0]!, seq: 99, type: 'approval.resolved', payload: 'not json' }]
  const result = projectRecovery(damaged)
  // The unparseable resolution names no approvalId, so it closes nothing — it
  // must not be read as closing everything.
  assert.deepEqual(result.unresolvedApprovals.map((x) => x.approvalId), ['apr_1'])
})
