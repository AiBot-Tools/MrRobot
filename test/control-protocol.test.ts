// T28 — protocol v1, frozen.
//
// A shipped UI parses these shapes, so the tests are deliberately literal:
// deepEqual against a hand-written list rather than "contains" or "at least".
// A `contains` assertion passes while a name is added, which is exactly the
// change that must not happen quietly — the whole point of a freeze is that
// widening it fails a test rather than a user's app.
//
// Two rules are asserted by walking every schema rather than by reading them:
//
//   No frame carries a credential. Authentication is once, at the upgrade, in
//   a header (invariant 1). D10 records that a browser WebSocket cannot set
//   Authorization, so if Phase 3 cannot open the socket from Rust the
//   amendment is a connect ticket — and this walk forces that to be a VISIBLE
//   v2 bump instead of one more optional params field.
//
//   Money is integer micro-USD. A float dollar in a UI is a number two
//   implementations disagree about, and costMicroUsd is frozen into a hash
//   chain.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  AgentSummary,
  ApprovalItem,
  ApprovalsListResult,
  ChainVerifyResult,
  COMMAND_SCHEMAS,
  COMMANDS,
  CmdFrame,
  ERROR_CODES,
  EventEnvelope,
  HoldItem,
  ModelSummary,
  parseFrame,
  ProbeRecordResult,
  PROTOCOL_VERSION,
  RunDetail,
  RunSummary,
  StatusResult,
} from '../src/control/protocol.js'
import {
  agentSummaryView,
  approvalsListView,
  chainVerifyView,
  eventView,
  modelSummaryView,
  probeView,
  runDetailView,
  statusView,
  type RunState,
} from '../src/control/views.js'
import { freshProbe } from './helpers/probe.js'
import type { ModelCard } from '../src/models/registry.js'

// ── zod introspection ──────────────────────────────────────────────────────
//
// Verified against zod 4.6.5: `.shape` gives an object's keys, `.def.type`
// names the node, `.def.innerType` unwraps optional/nullable, `.def.element`
// an array, `.def.options` a union, and `z.number().int()` carries a check
// whose `def.format` is 'safeint' (a plain z.number() has none).

interface ZodNode {
  readonly def: {
    readonly type: string
    readonly innerType?: ZodNode
    readonly element?: ZodNode
    readonly options?: readonly ZodNode[]
    readonly checks?: readonly { readonly def?: { readonly format?: string } }[]
  }
  readonly shape?: Record<string, ZodNode>
}

const node = (schema: unknown): ZodNode => schema as ZodNode

function unwrap(n: ZodNode): ZodNode {
  let cur = n
  for (let i = 0; i < 16; i++) {
    const inner = cur.def.innerType
    if (inner === undefined) return cur
    cur = inner
  }
  return cur
}

function isInt(n: ZodNode): boolean {
  const u = unwrap(n)
  return (
    u.def.type === 'number' && (u.def.checks ?? []).some((c) => c.def?.format === 'safeint')
  )
}

/** Every (path, node) pair reachable in a schema. */
function walk(n: ZodNode, path: string[] = [], seen = new Set<ZodNode>()): [string[], ZodNode][] {
  if (seen.has(n)) return []
  seen.add(n)
  const out: [string[], ZodNode][] = [[path, n]]
  const u = unwrap(n)
  if (u !== n) out.push(...walk(u, path, seen))
  if (u.def.element !== undefined) out.push(...walk(u.def.element, [...path, '[]'], seen))
  for (const option of u.def.options ?? []) out.push(...walk(option, path, seen))
  for (const [key, child] of Object.entries(u.shape ?? {})) {
    out.push(...walk(child, [...path, key], seen))
  }
  return out
}

const keysOf = (schema: unknown): string[] => Object.keys(node(schema).shape ?? {}).sort()

const ALL_SCHEMAS: [string, unknown][] = [
  ...Object.entries(COMMAND_SCHEMAS).flatMap(
    ([cmd, s]): [string, unknown][] => [
      [`${cmd}.params`, s.params],
      [`${cmd}.result`, s.result],
    ],
  ),
  ['CmdFrame', CmdFrame],
]

// ── the frozen lists ───────────────────────────────────────────────────────

test('command list equals the 16 frozen names by literal array equality', () => {
  // Hand-written, in order. A `contains` check would pass while a 17th name
  // was added, which is the change a freeze exists to catch.
  assert.deepEqual([...COMMANDS], [
    'status.get',
    'agents.list',
    'agent.promote',
    'agent.archive',
    'run.start',
    'run.kill',
    'runs.list',
    'run.get',
    'approvals.list',
    'approval.approve',
    'approval.deny',
    'quarantine.release',
    'events.query',
    'chain.verify',
    'models.list',
    'model.probe',
  ])
  assert.equal(COMMANDS.length, 16)
  assert.equal(Object.keys(COMMAND_SCHEMAS).length, 16)
  // Exactly one command promotes an agent (invariant 6).
  assert.deepEqual(COMMANDS.filter((c) => /promote/.test(c)), ['agent.promote'])
})

test('error code list equals the frozen list by literal equality', () => {
  assert.deepEqual([...ERROR_CODES], [
    'bad_request',
    'unknown_command',
    'not_found',
    'conflict',
    'forbidden',
    'not_implemented',
    'degraded',
    'payload_too_large',
    'internal',
  ])
})

test('result schema key sets equal the frozen literal sets (RunSummary, RunDetail, ApprovalItem, HoldItem, ProbeRecord, ChainVerifyResult, StatusResult, AgentSummary, EventEnvelope)', () => {
  assert.deepEqual(keysOf(RunSummary), [
    'agentId', 'finishedAt', 'reason', 'runId', 'startedAt', 'status', 'taint',
  ])
  assert.deepEqual(keysOf(RunDetail), [
    'agentId', 'costMicroUsd', 'finishedAt', 'lastEventSeq', 'llmCalls', 'reason', 'runId',
    'startedAt', 'status', 'taint', 'toolCalls',
  ])
  assert.deepEqual(keysOf(ApprovalItem), [
    'agentId', 'approvalId', 'argsHash', 'expiresAt', 'kind', 'requestedAt', 'runId', 'toolRef',
  ])
  assert.deepEqual(keysOf(HoldItem), ['heldAt', 'holdId', 'runId', 'toolRef'])
  assert.deepEqual(keysOf(ProbeRecordResult), [
    'costMicroUsd', 'finishSeen', 'latencyMs', 'modelIdSeen', 'probedAt', 'reason', 'ref',
    'roundTrip', 'serverVersion', 'toolCalling', 'toolChoiceForced', 'ttlHours', 'usage',
  ])
  // The wire shape carries no schemaVersion: the file on disk may migrate
  // independently of the protocol.
  assert.equal(keysOf(ProbeRecordResult).includes('schemaVersion'), false)

  // A union: both arms, by their own key sets.
  const arms = (node(ChainVerifyResult).def.options ?? []).map((o) => keysOf(o))
  assert.deepEqual(arms, [['count', 'head', 'ok'], ['at', 'ok', 'reason']])

  assert.deepEqual(keysOf(StatusResult), [
    'chainHead', 'envFallback', 'kernel', 'lanes', 'state', 'subsystems',
  ])
  assert.deepEqual(keysOf(node(StatusResult).shape?.['subsystems']), [
    'control', 'egress', 'events', 'hub', 'router', 'sandbox', 'scheduler', 'secrets',
  ])
  assert.deepEqual(keysOf(AgentSummary), [
    'id', 'kind', 'modelPrimary', 'role', 'status', 'tier', 'version',
  ])
  assert.deepEqual(keysOf(EventEnvelope), [
    'agentId', 'hash', 'id', 'payload', 'prevHash', 'runId', 'seq', 'ts', 'type',
  ])
  assert.deepEqual(keysOf(ModelSummary), [
    'dialect', 'local', 'orchestrator', 'placeholder', 'probe', 'ref', 'routable',
  ])
})

// ── the two structural rules ───────────────────────────────────────────────

test('no command or params field is named token, auth or authorization (schema walk)', () => {
  const banned = /^(token|auth|authorization|access_token|bearer|apikey|api_key|secret|password|credential)s?$/i
  for (const [label, schema] of ALL_SCHEMAS) {
    for (const [path] of walk(node(schema))) {
      const key = path[path.length - 1]
      if (key === undefined) continue
      assert.equal(banned.test(key), false, `${label} exposes a credential field at ${path.join('.')}`)
    }
  }
  // And no command is named after one either.
  for (const cmd of COMMANDS) assert.equal(banned.test(cmd.replace('.', '')), false, cmd)
})

test('result schemas contain no float money field', () => {
  const money = /cost|usd|price/i
  let checked = 0
  for (const [label, schema] of ALL_SCHEMAS) {
    for (const [path, n] of walk(node(schema))) {
      const key = path[path.length - 1]
      if (key === undefined || !money.test(key)) continue
      checked++
      // Both halves: an integer, and a name that says what unit it is in. A
      // field called `cost` that happens to be an integer is still a unit
      // nobody declared.
      assert.ok(isInt(n), `${label}.${path.join('.')} is money but not an integer`)
      assert.ok(/MicroUsd$/.test(key), `${label}.${path.join('.')} does not end in MicroUsd`)
    }
  }
  assert.ok(checked >= 3, `expected to find money fields to check, found ${String(checked)}`)
})

test('event envelope type is a string, not an enum', () => {
  // The event catalog grows; growing it must not be a protocol bump. A UI that
  // meets an unknown type can still show its seq, timestamp and run.
  assert.equal(unwrap(node(EventEnvelope).shape?.['type'] as ZodNode).def.type, 'string')
  assert.equal(EventEnvelope.parse({
    seq: 1, id: 'e1', ts: '2026-01-01T00:00:00.000Z', type: 'a.type.invented.later',
    payload: {}, prevHash: 'p', hash: 'h',
  }).type, 'a.type.invented.later')
})

// ── frames ─────────────────────────────────────────────────────────────────

test('every command parses a valid example and rejects an unknown key', () => {
  const examples: Record<string, Record<string, unknown>> = {
    'status.get': {},
    'agents.list': { includeArchived: true },
    'agent.promote': { approvalId: 'apr_1' },
    'agent.archive': { agentId: 'researcher', reason: 'done' },
    'run.start': { agentId: 'ceo', input: 'go', goalId: 'g1', taint: 'clean' },
    'run.kill': { runId: 'run_1' },
    'runs.list': { status: 'running', limit: 10 },
    'run.get': { runId: 'run_1' },
    'approvals.list': {},
    'approval.approve': { approvalId: 'apr_1' },
    'approval.deny': { approvalId: 'apr_1', reason: 'no' },
    'quarantine.release': { holdId: 'hold_1' },
    'events.query': { afterSeq: 0, limit: 5, types: ['run.started'], runId: 'run_1', text: 'x' },
    'chain.verify': {},
    'models.list': {},
    'model.probe': { ref: 'anthropic/claude-sonnet-5' },
  }

  for (const cmd of COMMANDS) {
    const params = examples[cmd]
    assert.ok(params !== undefined, `no example for ${cmd}`)
    assert.doesNotThrow(() => COMMAND_SCHEMAS[cmd].params.parse(params), cmd)
    // Strict everywhere: a field nobody declared is a field nobody reviewed.
    assert.throws(() => COMMAND_SCHEMAS[cmd].params.parse({ ...params, extra: 1 }), cmd)
  }

  // The id prefixes are load-bearing: the CLI dispatches on them.
  assert.throws(() => COMMAND_SCHEMAS['approval.approve'].params.parse({ approvalId: 'hold_1' }))
  assert.throws(() => COMMAND_SCHEMAS['quarantine.release'].params.parse({ holdId: 'apr_1' }))
})

test('unknown cmd and wrong v are rejected', () => {
  const bad = parseFrame(JSON.stringify({ v: 1, id: 'i1', cmd: 'secrets.get', params: {} }), 1_000)
  assert.equal(bad.ok, false)
  assert.equal(bad.ok ? '' : bad.code, 'unknown_command')
  // The id comes back so a client can correlate the rejection.
  assert.equal(bad.ok ? '' : bad.id, 'i1')

  const wrongV = parseFrame(JSON.stringify({ v: 2, id: 'i2', cmd: 'status.get', params: {} }), 1_000)
  assert.equal(wrongV.ok, false)
  assert.equal(wrongV.ok ? '' : wrongV.code, 'bad_request')

  const ok = parseFrame(JSON.stringify({ v: PROTOCOL_VERSION, id: 'i3', cmd: 'status.get' }), 1_000)
  assert.equal(ok.ok, true)
  assert.deepEqual(ok.ok ? ok.frame.params : null, {})

  assert.equal(parseFrame('{not json', 1_000).ok, false)
})

test('frames over maxPayloadBytes are rejected payload_too_large by byte length before JSON.parse', () => {
  // Measured in BYTES. `String.length` undercounts multi-byte UTF-8, so a
  // 1 MB limit counted in characters admits up to 4 MB.
  const multibyte = 'é'.repeat(40) // 40 chars, 80 bytes
  assert.equal(Buffer.byteLength(multibyte, 'utf8'), 80)
  assert.equal(multibyte.length, 40)

  const under = parseFrame(multibyte, 100)
  // Rejected for being bad JSON, not for being too large: it fits.
  assert.equal(under.ok ? '' : under.code, 'bad_request')

  const over = parseFrame(multibyte, 60)
  assert.equal(over.ok, false)
  assert.equal(over.ok ? '' : over.code, 'payload_too_large')

  // The size check runs BEFORE the parse: a hostile frame does not get a full
  // JSON parse of whatever it sent before being turned away. An oversized
  // frame that IS valid JSON is still refused for its size.
  const bigValid = JSON.stringify({ v: 1, id: 'x', cmd: 'status.get', params: { pad: 'y'.repeat(500) } })
  const refused = parseFrame(bigValid, 100)
  assert.equal(refused.ok ? '' : refused.code, 'payload_too_large')
  assert.match(refused.ok ? '' : refused.message, /over the 100 byte limit/)

  // Bytes work too, not just strings.
  assert.equal(parseFrame(new TextEncoder().encode(bigValid), 100).ok, false)
})

// ── views round-trip through the schemas ───────────────────────────────────

const RUN: RunState = {
  runId: 'run_1',
  agentId: 'researcher',
  status: 'finished',
  taint: 'tainted',
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:01:00.000Z',
  reason: 'usdMax',
  llmCalls: 3,
  toolCalls: 2,
  costMicroUsd: 13_500,
  lastEventSeq: 42,
}

const CARD: ModelCard = {
  dialect: 'anthropic',
  baseUrl: 'https://api.anthropic.com',
  path: '/v1/messages',
  auth: { header: 'x-api-key', scheme: 'none', vaultId: 'anthropic-api-key', envVar: 'ANTHROPIC_API_KEY' },
  headers: { 'anthropic-version': '2023-06-01' },
  model: 'claude-sonnet-5',
  local: false,
  placeholder: false,
  pricing: { inMicroUsdPerMTok: 3_000_000, outMicroUsdPerMTok: 15_000_000, source: 'table' },
  caps: {
    toolChoice: 'auto', parallelToolCalls: true, strictSchema: null,
    sampling: 'none', streamUsage: null, preserveAssistantMessage: false,
  },
  orchestrator: true,
}

test("every command's result schema parses the corresponding view output", () => {
  const now = Date.now()

  assert.doesNotThrow(() => COMMAND_SCHEMAS['run.get'].result.parse(runDetailView(RUN)))
  assert.doesNotThrow(() => COMMAND_SCHEMAS['runs.list'].result.parse([runDetailView(RUN)].map((d) => ({
    runId: d.runId, agentId: d.agentId, status: d.status, taint: d.taint,
    startedAt: d.startedAt, finishedAt: d.finishedAt, reason: d.reason,
  }))))

  const approvals = approvalsListView(
    [
      { approvalId: 'apr_1', kind: 'tool', runId: 'run_1', toolRef: 'pmmcp.recall', argsHash: 'h', requestedAt: now, expiresAt: now + 1_000 },
      { approvalId: 'apr_2', kind: 'promotion', agentId: 'scout', requestedAt: now, expiresAt: now + 1_000 },
    ],
    [{ holdId: 'hold_1', runId: 'run_1', toolRef: 'pmmcp.recall', heldAt: now }],
  )
  assert.doesNotThrow(() => COMMAND_SCHEMAS['approvals.list'].result.parse(approvals))
  // A promotion carries an agent and no tool fields; a tool approval the
  // reverse. A UI that rendered an empty "tool" row for a promotion would
  // invite a human to approve the wrong thing.
  assert.deepEqual(Object.keys(approvals.approvals[1] ?? {}).sort(), [
    'agentId', 'approvalId', 'expiresAt', 'kind', 'requestedAt',
  ])

  const models = [modelSummaryView('anthropic/claude-sonnet-5', CARD, freshProbe('anthropic/claude-sonnet-5'), now)]
  assert.doesNotThrow(() => COMMAND_SCHEMAS['models.list'].result.parse(models))
  assert.equal(models[0]?.routable, true)

  assert.doesNotThrow(() =>
    COMMAND_SCHEMAS['chain.verify'].result.parse(chainVerifyView({ ok: true, count: 10, head: 'abc' }, 10)),
  )
  assert.doesNotThrow(() =>
    COMMAND_SCHEMAS['chain.verify'].result.parse(chainVerifyView({ ok: false, at: 7, reason: 'gap' }, 0)),
  )
  // An empty log has no head.
  assert.equal(chainVerifyView({ ok: true, count: 0, head: 'genesis' }, 0).ok, true)

  const status = statusView({
    bootedAt: '2026-01-01T00:00:00.000Z',
    subsystems: {
      events: { state: 'ok' },
      control: { state: 'ok' },
      hub: { state: 'degraded', reason: 'pmmcp unreachable' },
      secrets: { state: 'degraded', reason: 'no hub' },
      sandbox: { state: 'absent', reason: 'no docker' },
      router: { state: 'ok' },
      scheduler: { state: 'absent', reason: 'not implemented' },
      egress: { state: 'absent', reason: 'not implemented' },
    },
    chainHead: { seq: 10, hash: 'abc' },
    lanes: {
      lanes: { main: { active: 1, queued: 0, cap: 4 }, subagent: { active: 0, queued: 0, cap: 8 } },
      agents: [],
    },
    envFallback: false,
  })
  assert.doesNotThrow(() => COMMAND_SCHEMAS['status.get'].result.parse(status))
  // One degraded subsystem degrades the kernel: a status line that read
  // 'ready' with the vault unreachable would lie about the thing an operator
  // most needs to know.
  assert.equal(status.state, 'degraded')
  assert.deepEqual(status.lanes.map((l) => l.lane), ['main', 'subagent'])

  assert.doesNotThrow(() =>
    COMMAND_SCHEMAS['model.probe'].result.parse(probeView(freshProbe('anthropic/claude-sonnet-5'))),
  )
  assert.doesNotThrow(() =>
    COMMAND_SCHEMAS['events.query'].result.parse([
      eventView({
        seq: 1, id: 'e1', ts: '2026-01-01T00:00:00.000Z', type: 'run.started',
        runId: 'run_1', agentId: 'researcher', payload: '{"schemaVersion":1}', prevHash: 'p', hash: 'h',
      }),
    ]),
  )
})

test('agents view never includes auth or env names', () => {
  const summary = agentSummaryView({
    id: 'researcher', version: 2, kind: 'standard', role: 'research',
    tier: 1, status: 'active', modelPrimary: 'anthropic/claude-sonnet-5',
  })
  assert.doesNotThrow(() => COMMAND_SCHEMAS['agents.list'].result.parse([summary]))

  // A model summary is the closest a UI gets to a provider entry, and it
  // must not describe where the credential comes from — naming the env var is
  // half of finding it (invariant 2).
  const model = modelSummaryView('anthropic/claude-sonnet-5', CARD, undefined, Date.now())
  const serialised = JSON.stringify({ summary, model })
  for (const leak of ['ANTHROPIC_API_KEY', 'anthropic-api-key', 'x-api-key', 'vaultId', 'envVar', 'baseUrl', 'headers']) {
    assert.equal(serialised.includes(leak), false, `${leak} reached a view`)
  }
})

test('views serialise without functions or undefined', () => {
  const now = Date.now()
  const everything = [
    runDetailView(RUN),
    runDetailView({ ...RUN, startedAt: undefined, finishedAt: undefined, reason: undefined }),
    approvalsListView([{ approvalId: 'apr_1', kind: 'promotion', agentId: 'x', requestedAt: now, expiresAt: now }], []),
    modelSummaryView('r', CARD, undefined, now),
    probeView(freshProbe('r')),
    chainVerifyView({ ok: true, count: 1, head: 'h' }, 1),
    agentSummaryView({ id: 'a', version: 1, kind: 'ephemeral', role: 'r', tier: 0, status: 'archived', modelPrimary: 'm' }),
  ]

  for (const view of everything) {
    // An absent optional is OMITTED, never present-and-undefined: the two are
    // the same in TypeScript and different over the wire, and a strict schema
    // on the far side rejects the second.
    const walkValue = (v: unknown, path: string): void => {
      assert.notEqual(typeof v, 'function', `${path} is a function`)
      if (Array.isArray(v)) return v.forEach((item, i) => walkValue(item, `${path}[${String(i)}]`))
      if (v !== null && typeof v === 'object') {
        for (const [k, child] of Object.entries(v)) {
          assert.notEqual(child, undefined, `${path}.${k} is present and undefined`)
          walkValue(child, `${path}.${k}`)
        }
      }
    }
    walkValue(view, 'view')
    assert.deepEqual(JSON.parse(JSON.stringify(view)), view)
  }
})
