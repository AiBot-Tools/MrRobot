// T05b — the frozen event catalog.
//
// The list below is duplicated from src/events/types.ts on purpose. A test
// that imported the list and compared it to itself would pass no matter what
// changed; this one fails the moment a type is added, removed or renamed
// without a deliberate edit here, which is what "frozen" means in practice.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { EVENT_TYPES, PAYLOAD_SCHEMAS, type EventType } from '../src/events/types.js'
import { withStore } from './helpers/store.js'

const FROZEN_36: readonly string[] = [
  'kernel.booted',
  'kernel.shutdown',
  'subsystem.state',
  'chain.anchored',
  'control.connected',
  'control.rejected',
  'hub.connected',
  'hub.degraded',
  'hub.tools.classified',
  'sandbox.degraded',
  'router.degraded',
  'secrets.degraded',
  'agent.registered',
  'agent.spawned',
  'agent.spawn.rejected',
  'agent.promotion.requested',
  'agent.promoted',
  'agent.archived',
  'run.queued',
  'run.started',
  'run.parked',
  'run.resumed',
  'run.finished',
  'llm.request',
  'llm.response',
  'tool.gate',
  'tool.call',
  'tool.result',
  'approval.requested',
  'approval.resolved',
  'quarantine.held',
  'quarantine.released',
  'sandbox.started',
  'sandbox.killed',
  'secret.accessed',
  'probe.recorded',
]

/**
 * One valid payload per type. These double as the catalog's documentation:
 * if a schema changes shape, the sample here has to change with it.
 */
const SAMPLES: Record<EventType, Record<string, unknown>> = {
  'kernel.booted': { schemaVersion: 1, version: '0.0.1', degraded: ['hub'] },
  'kernel.shutdown': { schemaVersion: 1, reason: 'signal', signal: 'SIGTERM', uptimeMs: 1000 },
  'subsystem.state': { schemaVersion: 1, subsystem: 'hub', state: 'degraded', reason: 'no pmmcp' },
  'chain.anchored': { schemaVersion: 1, seq: 7, hash: 'abc' },
  'control.connected': { schemaVersion: 1, connectionId: 'c1', origin: 'http://127.0.0.1:1420' },
  'control.rejected': { schemaVersion: 1, reason: 'query_token' },
  'hub.connected': { schemaVersion: 1, server: 'pmmcp', toolCount: 49 },
  'hub.degraded': { schemaVersion: 1, server: 'pmmcp', reason: 'connect refused' },
  'hub.tools.classified': {
    schemaVersion: 1,
    server: 'pmmcp',
    exposed: 12,
    kernelOnly: 35,
    disabled: 2,
    unclassified: ['new_tool'],
  },
  'sandbox.degraded': { schemaVersion: 1, driver: 'docker', reason: 'no daemon' },
  'router.degraded': { schemaVersion: 1, reason: 'no probed model' },
  'secrets.degraded': { schemaVersion: 1, reason: 'vault unreachable' },
  'agent.registered': { schemaVersion: 1, agentId: 'ceo', version: 1, kind: 'standard', role: 'orchestrator', tier: 0 },
  'agent.spawned': { schemaVersion: 1, agentId: 'scout-1', templateId: 'scout', tier: 1 },
  'agent.spawn.rejected': { schemaVersion: 1, templateId: 'scout', reason: 'tier exceeds template' },
  'agent.promotion.requested': { schemaVersion: 1, agentId: 'scout-1', requestedByRunId: 'r1', rationale: 'useful' },
  'agent.promoted': { schemaVersion: 1, agentId: 'scout-1', fromVersion: 1, toVersion: 2, byConnectionId: 'c1' },
  'agent.archived': { schemaVersion: 1, agentId: 'scout-1', version: 2, byConnectionId: 'c1' },
  'run.queued': { schemaVersion: 1, runId: 'r1', agentId: 'ceo', lane: 'ceo' },
  'run.started': { schemaVersion: 1, runId: 'r1', agentId: 'ceo', lane: 'ceo', tier: 0, taint: 'clean' },
  'run.parked': { schemaVersion: 1, runId: 'r1', reason: 'approval', approvalId: 'a1' },
  'run.resumed': { schemaVersion: 1, runId: 'r1', parkedMs: 4200 },
  'run.finished': {
    schemaVersion: 1,
    runId: 'r1',
    status: 'ok',
    costMicroUsd: 1234,
    llmCalls: 2,
    toolCalls: 3,
    durationMs: 900,
  },
  'llm.request': { schemaVersion: 1, ref: 'anthropic/claude-sonnet-5', attempt: 1, prompt: 'hello', tools: ['pmmcp__recall'] },
  'llm.response': {
    schemaVersion: 1,
    ref: 'anthropic/claude-sonnet-5',
    attempt: 1,
    content: 'hi',
    finish: 'end_turn',
    inputTokens: 10,
    outputTokens: 5,
    costMicroUsd: 77,
    durationMs: 800,
  },
  'tool.gate': { schemaVersion: 1, toolRef: 'pmmcp.recall', decision: 'allow', reason: 'exposed read', risk: 'read', taint: 'clean' },
  'tool.call': { schemaVersion: 1, ticketId: 't1', toolRef: 'pmmcp.recall', argsHash: 'deadbeef', quarantine: false },
  'tool.result': {
    schemaVersion: 1,
    ticketId: 't1',
    toolRef: 'pmmcp.recall',
    ok: true,
    text: 'result',
    bytes: 6,
    truncated: false,
    durationMs: 12,
  },
  'approval.requested': { schemaVersion: 1, approvalId: 'a1', toolRef: 'github.merge', argsPreview: 'pr 7', risk: 'irreversible', expiresAt: '2026-09-21T00:00:00.000Z' },
  'approval.resolved': { schemaVersion: 1, approvalId: 'a1', decision: 'approved', byConnectionId: 'c1' },
  'quarantine.held': { schemaVersion: 1, holdId: 'q1', toolRef: 'fs.write', reason: 'tainted run' },
  'quarantine.released': { schemaVersion: 1, holdId: 'q1', byConnectionId: 'c1' },
  'sandbox.started': {
    schemaVersion: 1,
    sandboxId: 's1',
    driver: 'docker',
    domain: 'trusted',
    image: 'aos-worker:0.0.1',
    memoryMb: 2048,
    pids: 256,
    wallclockMs: 600000,
  },
  'sandbox.killed': { schemaVersion: 1, sandboxId: 's1', reason: 'wallclock' },
  'secret.accessed': { schemaVersion: 1, id: 'anthropic-api-key', purpose: 'llm', source: 'vault' },
  'probe.recorded': { schemaVersion: 1, ref: 'anthropic/claude-sonnet-5', toolCalling: true, toolChoiceForced: null },
}

test('EVENT_TYPES equals the 36 frozen names by literal array equality', () => {
  assert.equal(EVENT_TYPES.length, 36)
  assert.deepEqual([...EVENT_TYPES], FROZEN_36)
  // No duplicates, and every name is dotted and lowercase.
  assert.equal(new Set(EVENT_TYPES).size, 36)
  for (const t of EVENT_TYPES) assert.match(t, /^[a-z]+(\.[a-z]+)+$/)
})

test('every type has a strict payload schema that rejects an unknown key', () => {
  assert.deepEqual(Object.keys(PAYLOAD_SCHEMAS).sort(), [...EVENT_TYPES].sort())
  for (const type of EVENT_TYPES) {
    const schema = PAYLOAD_SCHEMAS[type]
    const sample = SAMPLES[type]
    assert.ok(sample, `no sample payload for ${type}`)
    assert.equal(schema.safeParse(sample).success, true, `valid sample rejected for ${type}`)
    assert.equal(
      schema.safeParse({ ...sample, unexpected: 1 }).success,
      false,
      `${type} accepted an unknown key; the schema is not strict`,
    )
  }
})

test('every payload schema requires schemaVersion: 1', () => {
  for (const type of EVENT_TYPES) {
    const schema = PAYLOAD_SCHEMAS[type]
    const sample = SAMPLES[type]
    const { schemaVersion, ...withoutVersion } = sample as { schemaVersion: unknown }
    assert.equal(schemaVersion, 1)
    assert.equal(schema.safeParse(withoutVersion).success, false, `${type} accepted a missing schemaVersion`)
    assert.equal(schema.safeParse({ ...sample, schemaVersion: 2 }).success, false, `${type} accepted schemaVersion 2`)
  }
})

test('store.append rejects a type outside EVENT_TYPES', (t) => {
  const store = withStore(t)
  assert.throws(() => store.append({ type: 'kernel.exploded', payload: {} }), /unknown event type/)
  // A near-miss is still a miss: the catalog is a literal allow-list.
  assert.throws(() => store.append({ type: 'kernel.boot', payload: {} }), /unknown event type/)
  assert.equal(store.query().length, 0)

  // And every catalogued type round-trips through a real append.
  for (const type of EVENT_TYPES) {
    const row = store.append({ type, payload: SAMPLES[type] })
    assert.equal(row.type, type)
  }
  assert.equal(store.query().length, 36)
  assert.equal(store.verifyChain().ok, true)
})

test('an optional field passed as undefined hashes the same as an omitted one', (t) => {
  // Two callers describing the same event must produce the same bytes. Before
  // the store dropped undefined keys, the explicit form failed inside the
  // canonicalizer with a TypeError instead of appending at all.
  const store = withStore(t)
  const omitted = store.append({
    type: 'subsystem.state',
    payload: { schemaVersion: 1, subsystem: 'hub', state: 'degraded' },
  })
  const explicit = store.append({
    type: 'subsystem.state',
    payload: { schemaVersion: 1, subsystem: 'hub', state: 'degraded', reason: undefined },
  })
  assert.equal(explicit.payload, omitted.payload, 'the two forms must serialize identically')
  assert.ok(!omitted.payload.includes('reason'))
  assert.equal(store.verifyChain().ok, true)
})
