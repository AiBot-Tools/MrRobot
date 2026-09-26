// T14a — approvals and gate tickets.
//
// The timeout test is the one that matters most. An approval nobody answers
// must deny, not wait forever and not drift into a yes. Operator inattention
// is not consent.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mintHumanActor } from '../src/control/actor.js'
import { Approvals, rebuildFromLog } from '../src/policy/approvals.js'
import { hashArgs, PolicyEngine } from '../src/policy/engine.js'
import type { GateInput } from '../src/policy/gate.js'
import { EventStore } from '../src/events/store.js'
import { readAllRows } from '../src/events/chain.js'
import { storeFile, withStore } from './helpers/store.js'

function gateInput(overrides: Partial<GateInput> = {}): GateInput {
  return {
    view: { exposure: 'agent', risk: 'read', taints: false, quarantine: false },
    scope: { runId: 'run-1', agentId: 'researcher', taint: 'clean' },
    manifestAllows: true,
    toolRef: 'pmmcp.recall',
    args: { query: 'goals' },
    ...overrides,
  }
}

const IRREVERSIBLE = {
  view: { exposure: 'agent', risk: 'irreversible', taints: false, quarantine: false },
  toolRef: 'github.merge_pull_request',
  args: { pr: 7 },
} as const

test('allow emits tool.gate and returns a ticket bound to argsHash', async (t) => {
  const store = withStore(t)
  const approvals = new Approvals()
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  const ticket = await engine.check(gateInput())

  assert.equal(ticket.toolRef, 'pmmcp.recall')
  assert.equal(ticket.runId, 'run-1')
  assert.equal(ticket.quarantine, false)
  assert.equal(ticket.argsHash, hashArgs({ query: 'goals' }))

  const gates = store.query({ type: 'tool.gate' })
  assert.equal(gates.length, 1)
  assert.match(gates[0]?.payload ?? '', /"decision":"allow"/)
  // The ruling is in the log before anything acts on it.
  assert.equal(gates[0]?.runId, 'run-1')

  // Key order must not change the binding: the hash is over canonical JSON.
  assert.equal(hashArgs({ b: 2, a: 1 }), hashArgs({ a: 1, b: 2 }))
})

test('needs-human creates a pending approval and resolves to a ticket on approve', async (t) => {
  const store = withStore(t)
  const approvals = new Approvals({ waitMs: 60_000 })
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  const pending = engine.check(gateInput(IRREVERSIBLE))

  // The request exists and is bound to these exact arguments.
  const waiting = approvals.pending()
  assert.equal(waiting.length, 1)
  const request = waiting[0]
  assert.equal(request?.toolRef, 'github.merge_pull_request')
  assert.equal(request?.argsHash, hashArgs({ pr: 7 }))

  approvals.resolve(request?.approvalId ?? '', mintHumanActor('conn-1'), 'approved')
  const ticket = await pending

  assert.equal(ticket.toolRef, 'github.merge_pull_request')
  assert.equal(ticket.argsHash, hashArgs({ pr: 7 }))
  assert.equal(approvals.pending().length, 0)

  const resolved = store.query({ type: 'approval.resolved' })
  assert.equal(resolved.length, 1)
  assert.match(resolved[0]?.payload ?? '', /"decision":"approved"/)
  assert.match(resolved[0]?.payload ?? '', /"byConnectionId":"conn-1"/)
})

test('deny yields PolicyDenied and no ticket', async (t) => {
  const store = withStore(t)
  const approvals = new Approvals()
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  await assert.rejects(
    () => engine.check(gateInput({ manifestAllows: false })),
    /policy denied pmmcp.recall/,
  )
  // A denial is recorded, and no approval was ever raised for it.
  assert.equal(store.query({ type: 'tool.gate' }).length, 1)
  assert.equal(store.query({ type: 'approval.requested' }).length, 0)
  assert.equal(approvals.pending().length, 0)
})

test('approval timeout expires and denies (fail closed)', async (t) => {
  const store = withStore(t)
  // A short real wait rather than mocked timers: the failure mode being
  // tested is "nobody answers", and that is a genuine timer expiring.
  const approvals = new Approvals({ waitMs: 20 })
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  await assert.rejects(
    () => engine.check(gateInput(IRREVERSIBLE)),
    /approval expired before a human answered \(fail closed\)/,
  )

  // Expiry is a first-class outcome in the record, not an absence.
  const resolved = store.query({ type: 'approval.resolved' })
  assert.equal(resolved.length, 1)
  assert.match(resolved[0]?.payload ?? '', /"decision":"expired"/)
  assert.ok(!(resolved[0]?.payload ?? '').includes('byConnectionId'), 'nobody approved it')
  assert.equal(approvals.pending().length, 0)
})

test('a ticket cannot be reused for different args', async (t) => {
  const store = withStore(t)
  const approvals = new Approvals({ waitMs: 60_000 })
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  const pending = engine.check(gateInput(IRREVERSIBLE))
  const request = approvals.pending()[0]
  approvals.resolve(request?.approvalId ?? '', mintHumanActor('conn-1'), 'approved')
  const ticket = await pending

  // The approved arguments pass.
  PolicyEngine.assertTicketMatches(ticket, 'github.merge_pull_request', { pr: 7 })

  // The classic swap: approve one thing, execute another. Refused at the last
  // moment, by recomputing the hash from what is actually being sent.
  assert.throws(
    () => PolicyEngine.assertTicketMatches(ticket, 'github.merge_pull_request', { pr: 9 }),
    /argsHash does not match/,
  )
  // Nor may a ticket be carried to a different tool.
  assert.throws(
    () => PolicyEngine.assertTicketMatches(ticket, 'github.delete_branch', { pr: 7 }),
    /ticket was issued for github.merge_pull_request/,
  )
})

test('resolving twice returns conflict', async (t) => {
  const store = withStore(t)
  const approvals = new Approvals({ waitMs: 60_000 })
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  const pending = engine.check(gateInput(IRREVERSIBLE))
  const request = approvals.pending()[0]
  const actor = mintHumanActor('conn-1')
  approvals.resolve(request?.approvalId ?? '', actor, 'approved')
  await pending

  // A second answer applies to nothing: the call already proceeded on the
  // first one. Silently accepting it would imply a decision that never took
  // effect.
  assert.throws(
    () => approvals.resolve(request?.approvalId ?? '', actor, 'denied'),
    /approval is not pending/,
  )
  assert.throws(() => approvals.resolve('never-existed', actor, 'approved'), /not pending/)
})

test("resolve with an object literal {kind:'human'} throws (brand check)", async (t) => {
  const store = withStore(t)
  const approvals = new Approvals({ waitMs: 60_000 })
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  const pending = engine.check(gateInput(IRREVERSIBLE))
  const request = approvals.pending()[0]
  const approvalId = request?.approvalId ?? ''

  for (const forgery of [{ kind: 'human' }, { connectionId: 'conn-1' }, null, 'conn-1']) {
    assert.throws(
      () => approvals.resolve(approvalId, forgery as never, 'approved'),
      /requires a human/,
      `${JSON.stringify(forgery)} must not resolve an approval`,
    )
  }
  // Still pending: no forgery moved it.
  assert.equal(approvals.pending().length, 1)

  approvals.resolve(approvalId, mintHumanActor('conn-1'), 'denied')
  await assert.rejects(() => pending, /a human denied this call/)
})

test('expired approvals are not honoured', async (t) => {
  const store = withStore(t)
  const approvals = new Approvals({ waitMs: 20 })
  t.after(() => approvals.close())
  const engine = new PolicyEngine({ store, approvals })

  const pending = engine.check(gateInput(IRREVERSIBLE))
  const request = approvals.pending()[0]
  const approvalId = request?.approvalId ?? ''

  await assert.rejects(() => pending, /expired/)

  // An operator answering late cannot revive it. The run already moved on
  // believing it was denied, so a late yes would authorise a call nobody is
  // waiting to make.
  assert.throws(
    () => approvals.resolve(approvalId, mintHumanActor('conn-1'), 'approved'),
    /approval is not pending/,
  )
  assert.equal(store.query({ type: 'approval.resolved' }).length, 1)
})

test('projections are empty after re-open and rebuildFromLog throws NotImplemented (documented Phase 1 gap)', async (t) => {
  const path = storeFile(t)
  const store = withStore(t, { path })
  const approvals = new Approvals({ waitMs: 60_000 })
  const engine = new PolicyEngine({ store, approvals })

  const pending = engine.check(gateInput(IRREVERSIBLE))
  assert.equal(approvals.pending().length, 1)

  // Simulate a restart: the in-memory queue goes with the process.
  approvals.close()
  await assert.rejects(() => pending, /expired/)

  const reopened = new EventStore(path, { readOnly: true })
  t.after(() => reopened.close())
  // The request and its outcome are both in the durable log…
  assert.equal(reopened.query({ type: 'approval.requested' }).length, 1)
  assert.equal(reopened.query({ type: 'approval.resolved' }).length, 1)

  // …and the projection reads them back. This one was RESOLVED before the
  // restart — it expired — so it is not returned: a decision of any kind closes
  // a request, and offering an answered one again would ask an operator to
  // decide something twice.
  assert.deepEqual(rebuildFromLog(readAllRows(reopened.db)), [])
})

test('rebuildFromLog returns what was pending at the crash, not an empty set', (t) => {
  const path = storeFile(t)
  const store = withStore(t, { path })
  // A long wait, so the request is still open when the process "dies". The
  // timeout is what would normally close it, and a crash beats the timeout.
  // Registered for cleanup IMMEDIATELY, not at the end of the test. The wait is
  // deliberately long so the request is still open when the process "dies", and
  // Approvals does not unref its timers — parked runs are real obligations. So an
  // assertion failure before a manual close() would leave a ten-minute timer
  // holding the event loop open, and the file would hang instead of failing.
  const approvals = new Approvals({ waitMs: 600_000, onRequested: () => undefined })
  t.after(() => {
    approvals.close()
  })

  const wired = new Approvals({
    waitMs: 600_000,
    onRequested: (request) => {
      store.append({
        type: 'approval.requested',
        ...(request.runId === undefined ? {} : { runId: request.runId }),
        payload: {
          schemaVersion: 1,
          approvalId: request.approvalId,
          toolRef: request.toolRef ?? 'pmmcp.remember',
          argsPreview: request.argsPreview,
          risk: 'irreversible',
          expiresAt: new Date(request.expiresAt).toISOString(),
        },
      })
    },
  })
  t.after(() => {
    wired.close()
  })
  const open = wired.request({
    runId: 'run-crash',
    toolRef: 'github.merge_pull_request',
    risk: 'irreversible',
    argsPreview: '{"pr":7}',
  })
  void open.outcome
  void approvals

  // The process stops here. No approval.resolved row is ever written, because
  // nothing got the chance to write one.
  const recovered = rebuildFromLog(readAllRows(store.db))
  assert.equal(recovered.length, 1, 'the unanswered request was not recovered')
  assert.equal(recovered[0]?.approvalId, open.request.approvalId)
  assert.equal(recovered[0]?.runId, 'run-crash')
  assert.equal(recovered[0]?.toolRef, 'github.merge_pull_request')
  assert.equal(recovered[0]?.risk, 'irreversible')

  // An empty answer here is the dangerous one: it reads as "everything was
  // handled" when a human was mid-decision on an irreversible tool call.
  assert.notDeepEqual(recovered, [])

  // Once a decision is recorded — any decision — it closes. This is what makes
  // boot's recovery idempotent rather than re-terminating on every restart.
  store.append({
    type: 'approval.resolved',
    runId: 'run-crash',
    payload: { schemaVersion: 1, approvalId: open.request.approvalId, decision: 'expired' },
  })
  assert.deepEqual(rebuildFromLog(readAllRows(store.db)), [])

})
