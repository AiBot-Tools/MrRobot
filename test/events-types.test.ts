// T05b — the frozen event catalog.
//
// The list below is duplicated from src/events/types.ts on purpose. A test
// that imported the list and compared it to itself would pass no matter what
// changed; this one fails the moment a type is added, removed or renamed
// without a deliberate edit here, which is what "frozen" means in practice.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { z } from 'zod'

import { ADDRESS_DENIALS } from '../src/egress/addr.js'
import { EgressHost, HOST_REFUSALS } from '../src/egress/host.js'
import { ALLOW_REASONS, BINDING_ID, DENY_REASONS } from '../src/egress/policy.js'
import { EGRESS_PROFILES, matchRoute, MAX_PATH, MAX_TARGET, RepoSlug, RUN_REF } from '../src/egress/routes.js'
import { SESSION_REFUSALS } from '../src/egress/session.js'
import { ERROR_CODE, UPSTREAM_REFUSALS, UPSTREAM_REFUSALS_AFTER_SEND } from '../src/egress/upstream.js'
import { MAX_LOGGED_OUTPUT, recordable } from '../src/events/bound.js'
import { canonicalize } from '../src/events/canonical.js'
import { CENSOR, DENY_KEYS, redactString, TOKEN_PATTERNS } from '../src/events/redact.js'
import {
  EGRESS_BINDING_ID,
  EGRESS_CENSOR,
  EGRESS_DETAIL_BYTES,
  EGRESS_ERROR_CODE,
  EGRESS_PATH_BYTES,
  EGRESS_REASON_BYTES,
  EGRESS_REF,
  EGRESS_REQUEST_TARGET_MAX_BYTES,
  EGRESS_TARGET_MAX_BYTES,
  EGRESS_TOKEN_PATTERNS,
  EGRESS_WHY_BYTES,
  EVENT_TYPES,
  PAYLOAD_SCHEMAS,
  PROXY_ADDRESS_DENIALS,
  PROXY_ALLOW_REASONS,
  PROXY_DENIES_BEFORE_HOST,
  PROXY_DENIES_BEFORE_PATH,
  PROXY_DENIES_BY_HOST_REFUSAL,
  PROXY_DENIES_ON_A_ROUTE,
  PROXY_DENY_REASONS,
  PROXY_GRANT_MAX_REPOS,
  PROXY_HOST_REFUSALS,
  PROXY_OVERFLOW_WHY,
  PROXY_PROFILES,
  PROXY_REFUSALS_AFTER_SEND,
  PROXY_UPSTREAM_REFUSALS,
  type EventType,
} from '../src/events/types.js'
import { withStore } from './helpers/store.js'

const FROZEN_50: readonly string[] = [
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
  'goals.degraded',
  'agent.registered',
  'agent.spawned',
  'agent.spawn.rejected',
  'agent.promotion.requested',
  'agent.promoted',
  'agent.archived',
  'run.scheduled',
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
  'quarantine.abandoned',
  'sandbox.started',
  'sandbox.killed',
  'secret.accessed',
  'probe.recorded',
  'plan.adopted',
  'goal.created',
  'goal.status',
  'goal.unconfirmed',
  'delegation.admitted',
  'delegation.result',
  'delegation.refused',
  'proxy.decision',
  'proxy.grant.issued',
  'proxy.grant.revoked',
  'egress.degraded',
]

/**
 * One valid payload per type. These double as the catalog's documentation:
 * if a schema changes shape, the sample here has to change with it.
 */
const SAMPLES: Record<EventType, Record<string, unknown>> = {
  'kernel.booted': { schemaVersion: 1, version: '0.0.1', configHash: 'h', degraded: ['hub'] },
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
  'run.scheduled': { schemaVersion: 1, agentId: 'ceo', schedule: '0 9 * * 1-5', minute: '2026-09-28T09:00' },
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
  'quarantine.abandoned': { schemaVersion: 1, holdId: 'q1', reason: 'the kernel restarted' },
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
  'goals.degraded': { schemaVersion: 1, reason: 'pmmcp declares no tool "create_goal"' },
  'plan.adopted': {
    schemaVersion: 1,
    runId: 'run_1',
    projectId: 'aos/ceo',
    objectiveGoalId: 'goal-1',
    title: 'compare two log storage options',
    milestones: 1,
    tasks: 2,
    questions: 0,
  },
  'goal.created': {
    schemaVersion: 1,
    projectId: 'aos/ceo',
    goalId: 'goal-2',
    kind: 'task',
    parentId: 'goal-1',
    title: 'write up sqlite',
    planTaskId: 't1',
  },
  'delegation.admitted': {
    schemaVersion: 1,
    parentRunId: 'run_1',
    childRunId: 'run_2',
    agentId: 'researcher',
    taskId: 't1',
    goalId: 'goal-3',
    ceilingMicroUsd: 500_000,
    ceilingWallclockMs: 300_000,
  },
  'delegation.result': {
    schemaVersion: 1,
    parentRunId: 'run_1',
    childRunId: 'run_2',
    status: 'ok',
    costMicroUsd: 4_200,
    taint: 'clean',
  },
  'delegation.refused': { schemaVersion: 1, parentRunId: 'run_1', taskId: 't2', reason: 't2 depends on t1' },
  'goal.status': {
    schemaVersion: 1,
    projectId: 'aos/ceo',
    goalId: 'goal-2',
    from: 'pending',
    to: 'in_progress',
    by: 'kernel',
    runId: 'run_2',
  },
  'goal.unconfirmed': {
    schemaVersion: 1,
    projectId: 'aos/ceo',
    tool: 'create_goal',
    goalId: 'goal_000000000002',
    reason: 'the text and structuredContent of create_goal disagree',
  },
  'proxy.decision': {
    schemaVersion: 1,
    grantId: 'grant_1',
    stage: 'policy',
    verdict: 'allow',
    reason: 'git-fetch',
    count: 1,
    method: 'GET',
    host: 'github.com',
    path: '/op/fixture.git/info/refs',
    pathBytes: 25,
    queryBytes: 24,
    service: 'git-upload-pack',
    bindingId: 'github',
    repo: 'op/fixture',
    why: 'git-fetch admits info/refs of a bound repository',
  },
  'proxy.grant.issued': {
    schemaVersion: 1,
    grantId: 'grant_1',
    purpose: 'exec',
    runId: 'run_1',
    agentId: 'coder',
    sandbox: 'aos-run-run_1-1',
    domain: 'trusted',
    allow: ['registry.npmjs.org'],
    routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }],
  },
  'proxy.grant.revoked': {
    schemaVersion: 1,
    grantId: 'grant_1',
    reason: 'exited',
    totals: { flows: 2, requests: 3, allowed: 2, denied: 1, refused: 0, failed: 0, sentBytes: 1_024, receivedBytes: 65_536, durationMs: 4_200 },
  },
  'egress.degraded': {
    schemaVersion: 1,
    check: 'config',
    reason: 'egress.enabled is false in config/kernel.yaml: set it to true once the worker image is pinned',
  },
}

test('EVENT_TYPES equals the 50 frozen names by literal array equality', () => {
  // The list is frozen by literal equality precisely so that growing it is a
  // deliberate act with a reason. The reasons, in order of arrival:
  //
  //   `quarantine.abandoned` — a restart must end a hold WITHOUT claiming a human
  //     released its content;
  //   `run.scheduled` — the scheduler must claim a minute durably BEFORE it tries
  //     to start a run;
  //   `goals.degraded` — the configured pmmcp goal tools can disagree with the
  //     live server, and `StatusResult.subsystems` is a strict object in the
  //     frozen protocol v1, so this cannot be a subsystem key without a bump;
  //   `plan.adopted`, `goal.created`, `goal.status` — the kernel writing a goal
  //     tree and moving it is a side effect on the operator's long-term memory,
  //     and every one of those writes has to be in the record;
  //   `delegation.admitted`, `.result`, `.refused` — a child run's spend and taint
  //     must be traceable to the parent that caused it, and a refusal to the reason
  //     the model was given;
  //   `goal.unconfirmed` — pmmcp can write a goal the kernel then refuses to
  //     confirm (contract P6), and that orphan belongs in the record, not only in
  //     a refusal reason (operator decision, 2026-10-19);
  //   `proxy.decision`, `proxy.grant.issued`, `.revoked`, `egress.degraded` —
  //     the Phase 2 exit asks that every network call a container makes be
  //     visible as a decision, attributed to the grant its channel holds, and
  //     a boot that cannot run egress must say which check failed (egress plan
  //     E4, accepted 2026-11-09).
  assert.equal(EVENT_TYPES.length, 50)
  assert.deepEqual([...EVENT_TYPES], FROZEN_50)
  // No duplicates, and every name is dotted and lowercase.
  assert.equal(new Set(EVENT_TYPES).size, 50)
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
  assert.equal(store.query().length, 50)
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

// ── the egress rows (egress plan E4) ───────────────────────────────────────
//
// The kernel appends these since W1. What is proven here is the
// boundary they will be written through: what a row may hold, what it may
// never hold, and that every row the schemas admit can be appended.

const EGRESS_TYPES = ['proxy.decision', 'proxy.grant.issued', 'proxy.grant.revoked', 'egress.degraded'] as const satisfies readonly EventType[]

const parses = (type: EventType, payload: unknown): boolean => PAYLOAD_SCHEMAS[type].safeParse(payload).success

/** A key a schema declares, at any depth: its name and where it sits. */
interface Declared {
  readonly key: string
  readonly at: string
}

/**
 * Every key a schema declares, at any depth. A schema kind the walk cannot see
 * into fails the test rather than hiding the keys beneath it.
 */
function declaredKeys(schema: z.ZodType, at: string): Declared[] {
  if (schema instanceof z.ZodObject) {
    return Object.entries(schema.shape as Record<string, z.ZodType>).flatMap(([key, inner]) => [
      { key, at: `${at}.${key}` },
      ...declaredKeys(inner, `${at}.${key}`),
    ])
  }
  if (schema instanceof z.ZodOptional) return declaredKeys(schema.unwrap() as z.ZodType, at)
  if (schema instanceof z.ZodArray) return declaredKeys(schema.element as z.ZodType, `${at}[]`)
  const leaf =
    schema instanceof z.ZodString ||
    schema instanceof z.ZodNumber ||
    schema instanceof z.ZodBoolean ||
    schema instanceof z.ZodEnum ||
    schema instanceof z.ZodLiteral
  assert.ok(leaf, `${at} is a schema kind this walk cannot see into`)
  return []
}

/** A key that would hold a credential or something computed from one. */
const CREDENTIAL_FUNCTION = /hash|digest|fingerprint|sha|hmac|value|header|auth|secret|token|cred|key|password|bearer|basic/i

test('no proxy.* or egress.* payload key matches DENY_KEYS, and none is named for a credential or a function of one', () => {
  // A key in DENY_KEYS has its value censored wholesale at the append, so the
  // row would record nothing; a key named for a credential or its digest is
  // the field the design forbids (a binding is named by bindingId alone).
  for (const type of EGRESS_TYPES) {
    const keys = declaredKeys(PAYLOAD_SCHEMAS[type], type)
    assert.ok(keys.length >= 5, `${type} declares only ${String(keys.length)} keys`)
    for (const { key, at } of keys) {
      assert.equal(DENY_KEYS.test(key), false, `${at} matches DENY_KEYS, so its value would be censored wholesale`)
      assert.equal(CREDENTIAL_FUNCTION.test(key), false, `${at} is named for a credential or a function of one`)
    }
  }
  // The walk descends: the nested keys are among those it judged.
  const grant = declaredKeys(PAYLOAD_SCHEMAS['proxy.grant.issued'], 'g').map((d) => d.at)
  assert.ok(grant.includes('g.routes[].bindingId') && grant.includes('g.routes[].repos'), grant.join(' '))
  const revoked = declaredKeys(PAYLOAD_SCHEMAS['proxy.grant.revoked'], 'r').map((d) => d.at)
  assert.ok(revoked.includes('r.totals.sentBytes') && revoked.includes('r.totals.failed'), revoked.join(' '))
  // And the guard bites: a key the design forbids is caught by name.
  for (const bad of ['authorization', 'token', 'credential', 'secret']) assert.equal(DENY_KEYS.test(bad), true, bad)
  for (const bad of ['credentialFingerprint', 'valueSha256', 'headerValue', 'tokenHash', 'headerBytes']) assert.equal(CREDENTIAL_FUNCTION.test(bad), true, bad)
})

/** A row's path with the lengths that go with it: the path's, and its query's with the `?`. */
const pathed = (path: string, queryBytes = 0): Record<string, unknown> => ({ path, pathBytes: path.length, queryBytes })

/** What recordable() keeps of a path past its budget: EGRESS_PATH_BYTES bytes, the cut mark's three among them. */
const CUT_PATH = recordable(`/${'p'.repeat(5_000)}`, EGRESS_PATH_BYTES)

const ALLOW_ROW = SAMPLES['proxy.decision']
/** A credential-free host's allow: no binding, no repository, no service. */
const FREE_ROW = {
  ...ALLOW_ROW,
  reason: 'allow-host',
  host: 'registry.npmjs.org',
  ...pathed('/zod/-/zod-4.6.7.tgz'),
  service: undefined,
  bindingId: undefined,
  repo: undefined,
  why: 'a credential-free host this grant allows, read-only',
}
/** A push's allow: the receive-pack POST, which takes no query. */
const PUSH_ROW = {
  ...ALLOW_ROW,
  reason: 'git-push',
  method: 'POST',
  ...pathed('/op/fixture.git/git-receive-pack'),
  service: undefined,
  why: "a push of this run's branches to a bound repository",
}
const DENY_ROW = {
  schemaVersion: 1,
  grantId: 'grant_1',
  stage: 'policy',
  verdict: 'deny',
  reason: 'not-a-host',
  count: 1,
  method: 'GET',
  hostRefusal: 'special-use',
  why: 'the target host is no egress host',
}
const UPSTREAM_ROW = {
  ...ALLOW_ROW,
  stage: 'upstream',
  verdict: 'deny',
  sent: false,
  refusal: 'denied-address',
  address: '192.168.5.2',
  denial: 'private',
  why: 'an answer is not a global unicast address',
}
/** A credentialed push the host stopped answering after it had the head and the pack: it left, and may have been applied. */
const SENT_PUSH_ROW = {
  ...PUSH_ROW,
  stage: 'upstream',
  verdict: 'allow',
  sent: true,
  refusal: 'idle-timeout',
  why: 'the connection carried no byte for the idle timeout',
}
const OVERFLOW_ROW = { schemaVersion: 1, grantId: 'grant_1', stage: 'policy', verdict: 'deny', reason: 'not-allowed', count: 412, overflow: true, why: PROXY_OVERFLOW_WHY }
const GRANT = SAMPLES['proxy.grant.issued']
const PUBLISH_GRANT = {
  ...GRANT,
  grantId: 'grant_2',
  purpose: 'publish',
  allow: [],
  routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-push', 'github-pulls'], repos: ['op/fixture'] }],
}
const CANARY_GRANT = { schemaVersion: 1, grantId: 'grant_canary', purpose: 'canary', sandbox: 'aos-run-canary-trusted', domain: 'trusted', allow: [], routes: [] }
const REVOKED = SAMPLES['proxy.grant.revoked']
const TOTALS = REVOKED['totals'] as Record<string, number>

/** One row of every shape the egress schemas admit, beyond the one SAMPLES holds. */
const EGRESS_VARIANTS: ReadonlyArray<readonly [EventType, Record<string, unknown>]> = [
  ['proxy.grant.issued', CANARY_GRANT],
  ['proxy.grant.issued', PUBLISH_GRANT],
  ['proxy.decision', FREE_ROW],
  ['proxy.decision', { ...FREE_ROW, ...pathed('/-/v1/search', '?text=zod&size=20'.length) }],
  ['proxy.decision', PUSH_ROW],
  ['proxy.decision', { ...PUSH_ROW, reason: 'github-pulls', ...pathed('/repos/op/fixture/pulls'), why: "a pull request from this run's branch, in a bound repository" }],
  ['proxy.decision', DENY_ROW],
  // A loopback probe, coalesced under its own reason and host refusal.
  ['proxy.decision', { ...DENY_ROW, hostRefusal: 'ip-literal', count: 12 }],
  ['proxy.decision', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', ...pathed('/') }],
  ['proxy.decision', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', count: 37 }],
  ['proxy.decision', OVERFLOW_ROW],
  // Past the second's bound, a loopback probe is still counted under its own host refusal.
  ['proxy.decision', { ...OVERFLOW_ROW, reason: 'not-a-host', hostRefusal: 'ip-literal', count: 1 }],
  ['proxy.decision', { ...OVERFLOW_ROW, reason: 'not-a-host', hostRefusal: 'special-use', count: 9 }],
  ['proxy.decision', { ...DENY_ROW, reason: 'use-route', method: 'CONNECT', hostRefusal: undefined }],
  // A CONNECT names where it was headed: pmmcp by its host refusal, a real host by name; past the bound, counted by its refusal.
  ['proxy.decision', { ...DENY_ROW, reason: 'use-route', method: 'CONNECT', hostRefusal: 'ip-literal' }],
  ['proxy.decision', { ...DENY_ROW, reason: 'use-route', method: 'CONNECT', hostRefusal: undefined, host: 'github.com', count: 3 }],
  ['proxy.decision', { ...OVERFLOW_ROW, reason: 'use-route', hostRefusal: 'ip-literal', count: 40 }],
  ['proxy.decision', { ...DENY_ROW, reason: 'second-host', method: 'GET', hostRefusal: 'special-use' }],
  // An exec grant's container asking for a push: denied, and the service it asked for named.
  [
    'proxy.decision',
    { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, host: 'github.com', bindingId: 'github', service: 'git-receive-pack', ...pathed('/op/fixture.git/info/refs', 25) },
  ],
  ['proxy.decision', UPSTREAM_ROW],
  ['proxy.decision', { ...UPSTREAM_ROW, denial: 'not-an-address', address: undefined }],
  ['proxy.decision', { ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined, denial: undefined, code: 'ECONNREFUSED' }],
  ['proxy.decision', { ...UPSTREAM_ROW, refusal: 'host-address', address: '2001:db8::1', denial: undefined }],
  ['proxy.decision', SENT_PUSH_ROW],
  ['proxy.decision', { ...SENT_PUSH_ROW, refusal: 'upstream-failed', code: 'ECONNRESET', why: 'the connection failed or closed before a response arrived' }],
  ['proxy.decision', { ...SENT_PUSH_ROW, verdict: 'deny', sent: false, why: 'the body never began, and the host had nothing of the request' }],
  ['proxy.grant.revoked', { ...REVOKED, reason: 'limit', limit: 'maxDenied' }],
  ['proxy.grant.revoked', { ...REVOKED, reason: 'violation', detail: 'a frame named flow 0' }],
  ['proxy.grant.revoked', { ...REVOKED, totals: { ...TOTALS, requests: 5, allowed: 4, denied: 1, refused: 1, failed: 1 } }],
  ['proxy.grant.revoked', { schemaVersion: 1, grantId: 'grant_1', reason: 'recovered' }],
  ['egress.degraded', { schemaVersion: 1, check: 'binding', bindingId: 'github', reason: 'AOS_GITHUB_TOKEN is not set: add it to .env' }],
  ['egress.degraded', { schemaVersion: 1, check: 'image', domain: 'hostile', reason: 'the worker image is not loaded on hostile: docker load it there' }],
  ['egress.degraded', { schemaVersion: 1, check: 'canary', domain: 'trusted', reason: 'the canary reached 192.168.5.2:8766: egress stays off' }],
  ['egress.degraded', { schemaVersion: 1, check: 'sandbox', reason: 'docker: no daemon on the trusted VM; run scripts/colima-up.sh trusted' }],
]

/** The payload as the store will write it: undefined keys dropped, as store.append drops them. */
const defined = (payload: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(payload).filter(([, v]) => v !== undefined))

/** Why a payload was refused, for a failing assertion's message. */
const why = (type: EventType, payload: unknown): string => {
  const parsed = PAYLOAD_SCHEMAS[type].safeParse(payload)
  return parsed.success ? 'accepted' : parsed.error.issues.map((i) => i.message).join('; ')
}

test('every sample appends and verifyChain passes, every egress shape among them, each stored exactly as given', (t) => {
  const store = withStore(t)
  const all: Array<readonly [EventType, Record<string, unknown>]> = [
    ...EVENT_TYPES.map((type) => [type, SAMPLES[type]] as const),
    ...EGRESS_VARIANTS,
  ]
  for (const [type, payload] of all) {
    assert.equal(parses(type, payload), true, `${type} ${JSON.stringify(payload)}: ${why(type, payload)}`)
    const row = store.append({ type, payload })
    // Nothing in an egress row is censored on the way in: no key is a
    // DENY_KEYS name and no sample holds a credential shape, so a stored
    // payload that differs means the redaction pass ate a field.
    assert.equal(row.payload, canonicalize(defined(payload)), `${type} was not stored as given`)
  }
  assert.equal(store.query().length, EVENT_TYPES.length + EGRESS_VARIANTS.length)
  assert.equal(store.verifyChain().ok, true)
})

/** A distinct EgressHost of exactly 253 characters, four labels at their longest. */
function longHost(i: number): string {
  const head = `h${String(i).padStart(3, '0')}`
  return [head + 'a'.repeat(63 - head.length), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.')
}
/** A distinct RepoSlug at its longest: a 39-character owner and a 100-character name. */
const longRepo = (i: number): string => `o${String(i).padStart(38, '0')}/${'n'.repeat(100)}`
/** A distinct binding id at its longest. */
const longBinding = (i: number): string => `b${String(i).padStart(2, '0')}${'x'.repeat(60)}`
const longRef = (c: string): string => c.repeat(64)

test('the largest row each proxy.* and egress.* schema admits appends inside MAX_LOGGED_OUTPUT, and one repository more is refused', (t) => {
  const store = withStore(t)
  const perRoute = PROXY_GRANT_MAX_REPOS / 16
  const grant = {
    schemaVersion: 1,
    grantId: longRef('g'),
    purpose: 'publish',
    runId: longRef('r'),
    agentId: longRef('a'),
    sandbox: `aos-run-${'s'.repeat(120)}`,
    domain: 'trusted',
    allow: Array.from({ length: 64 }, (_, i) => longHost(i)),
    routes: Array.from({ length: 16 }, (_, r) => ({
      bindingId: longBinding(r),
      host: longHost(100 + r),
      profiles: [...PROXY_PROFILES],
      repos: Array.from({ length: perRoute }, (_, i) => longRepo(r * perRoute + i)),
    })),
  }
  // Real names: the normaliser and the repository schema take them as they are.
  for (const host of [...grant.allow, ...grant.routes.map((r) => r.host)]) assert.equal(EgressHost.parse(host), host)
  for (const repo of grant.routes.flatMap((r) => r.repos)) assert.equal(RepoSlug.parse(repo), repo)

  const path = recordable(`/${'p'.repeat(10_000)}`, EGRESS_PATH_BYTES)
  const reason = recordable('w'.repeat(10_000), EGRESS_WHY_BYTES)
  // An info/refs path at the budget, uncut, so that a service rides it.
  const infoRefs = `/${'p'.repeat(EGRESS_PATH_BYTES - 1 - '/info/refs'.length)}/info/refs`
  assert.equal(infoRefs.length, EGRESS_PATH_BYTES)
  const answer = { address: '0000:0000:0000:0000:0000:ffff:255.255.255.255', denial: 'not-global-unicast', code: `E${'X'.repeat(63)}` }
  const upstream = { schemaVersion: 1, grantId: longRef('g'), stage: 'upstream', verdict: 'deny', refusal: 'denied-address', sent: false, count: 1, host: longHost(0), ...answer, why: reason }
  const largest: ReadonlyArray<readonly [EventType, Record<string, unknown>]> = [
    ['proxy.grant.issued', grant],
    // A deny names every field decide() may have read, each at its longest.
    [
      'proxy.decision',
      {
        schemaVersion: 1,
        grantId: longRef('g'),
        stage: 'policy',
        verdict: 'deny',
        reason: 'not-granted',
        count: 1,
        method: `M${'-'.repeat(23)}`,
        host: longHost(0),
        path: infoRefs,
        pathBytes: infoRefs.length,
        queryBytes: '?service=git-receive-pack'.length,
        service: 'git-receive-pack',
        bindingId: longBinding(0),
        why: reason,
      },
    ],
    // An upstream row of a credential-free host carries the longest path, and one of a bound route the binding and repository.
    ['proxy.decision', { ...upstream, reason: 'allow-host', method: 'HEAD', path, pathBytes: EGRESS_TARGET_MAX_BYTES, queryBytes: 0 }],
    [
      'proxy.decision',
      { ...upstream, reason: 'github-pulls', method: 'POST', ...pathed(`/repos/${longRepo(0)}/pulls`), bindingId: longBinding(0), repo: longRepo(0) },
    ],
    [
      'proxy.grant.revoked',
      {
        schemaVersion: 1,
        grantId: longRef('g'),
        reason: 'limit',
        limit: 'maxHeaderBytes',
        detail: recordable('d'.repeat(10_000), EGRESS_DETAIL_BYTES),
        totals: {
          ...Object.fromEntries(['flows', 'requests', 'allowed', 'refused', 'sentBytes', 'receivedBytes', 'durationMs'].map((k) => [k, Number.MAX_SAFE_INTEGER])),
          denied: 0,
          failed: 0,
        },
      },
    ],
    ['egress.degraded', { schemaVersion: 1, check: 'binding', bindingId: longBinding(0), reason: recordable('r'.repeat(10_000), EGRESS_REASON_BYTES) }],
  ]
  for (const [type, payload] of largest) {
    assert.equal(parses(type, payload), true, `${type}: ${why(type, payload)}`)
    const bytes = Buffer.byteLength(canonicalize(payload), 'utf8')
    assert.ok(bytes < MAX_LOGGED_OUTPUT, `${type} at its largest is ${String(bytes)} bytes`)
    store.append({ type, payload })
  }
  assert.equal(store.verifyChain().ok, true)

  // One repository past the row's bound is refused by the schema, with a
  // reason, rather than by the store's size check further down.
  const over = { ...grant, routes: grant.routes.map((r, i) => (i === 0 ? { ...r, repos: [...r.repos, longRepo(999)] } : r)) }
  assert.match(why('proxy.grant.issued', over), /at most 128 repositories/)
})

test('egress free text is bounded in UTF-8 bytes: it takes what recordable() makes of anything, credential shapes censored, and refuses raw text over its budget', (t) => {
  const store = withStore(t)
  // A credential shape, a lone surrogate (which the canonical form refuses) and
  // multi-byte text, far past every budget.
  const raw = `Bearer abcdefghijklmnop \ud800 ${'é'.repeat(300)} ${'x'.repeat(5_000)}`
  // A path is printable ASCII, as parseTarget admits one; a token in it is still a token.
  const rawPath = `/ghp_abcdefghijklmnopqrstuvwxyz0123456789/${'x'.repeat(5_000)}`
  const fields: ReadonlyArray<readonly [EventType, Record<string, unknown>, string, number, string]> = [
    ['proxy.decision', { ...FREE_ROW, pathBytes: rawPath.length }, 'path', EGRESS_PATH_BYTES, rawPath],
    ['proxy.decision', ALLOW_ROW, 'why', EGRESS_WHY_BYTES, raw],
    ['proxy.grant.revoked', { ...REVOKED, reason: 'violation', detail: 'x' }, 'detail', EGRESS_DETAIL_BYTES, raw],
    ['egress.degraded', SAMPLES['egress.degraded'], 'reason', EGRESS_REASON_BYTES, raw],
  ]
  for (const [type, base, field, budget, text] of fields) {
    const bounded = recordable(text, budget)
    assert.ok(Buffer.byteLength(bounded, 'utf8') <= budget)
    const row = store.append({ type, payload: defined({ ...base, [field]: bounded }) })
    assert.ok(row.payload.includes(CENSOR), `${type}.${field} kept the credential shape`)
    assert.equal(row.payload.includes('abcdefghijklmnop'), false)
    // Raw, the same text is refused: a writer must bound it first.
    assert.equal(parses(type, defined({ ...base, [field]: text })), false, `${type}.${field} took raw text over its budget`)
    assert.equal(parses(type, defined({ ...base, [field]: `${text.slice(0, 1)}${'x'.repeat(budget)}` })), false, `${type}.${field} took ${String(budget + 1)} characters`)
  }

  // Bytes, not UTF-16 units: a budget's worth of characters that take two
  // bytes each is twice the budget, refused raw, and recordable() makes it fit.
  for (const [type, base, field, budget] of fields.slice(1)) {
    const wide = 'é'.repeat(budget)
    assert.equal(wide.length, budget)
    assert.equal(parses(type, { ...base, [field]: wide }), false, `${type}.${field} took ${String(budget)} characters of ${String(2 * budget)} bytes`)
    assert.equal(parses(type, { ...base, [field]: 'é'.repeat(budget / 2) }), true, `${type}.${field} refused exactly its budget in bytes`)
    const bounded = recordable(wide, budget)
    assert.equal(parses(type, { ...base, [field]: bounded }), true, `${type}.${field} refused what recordable() made of it`)
    store.append({ type, payload: { ...base, [field]: bounded } })
  }
  // A path's one character that is not ASCII is recordable()'s mark of a cut,
  // three bytes long: a path that ends in it is held to the budget in bytes.
  const cut = recordable(`/${'p'.repeat(5_000)}`, EGRESS_PATH_BYTES)
  assert.ok(cut.endsWith('…') && Buffer.byteLength(cut, 'utf8') === EGRESS_PATH_BYTES)
  assert.equal(parses('proxy.decision', { ...FREE_ROW, path: cut, pathBytes: 5_001 }), true)
  const overByMark = `/${'p'.repeat(EGRESS_PATH_BYTES - 2)}…`
  assert.equal(overByMark.length, EGRESS_PATH_BYTES)
  assert.equal(parses('proxy.decision', { ...FREE_ROW, path: overByMark, pathBytes: 5_001 }), false, `a path of ${String(EGRESS_PATH_BYTES)} characters and ${String(EGRESS_PATH_BYTES + 2)} bytes was taken`)
  assert.equal(store.verifyChain().ok, true)
})

test("proxy.decision stores no query string but git's service= value, and how much each request carried as numbers alone", () => {
  for (const path of [
    '/op/fixture.git/info/refs?service=git-upload-pack',
    '/download?access_token=abc',
    '/x?',
    '/x#fragment',
    'op/fixture.git/info/refs',
    'https://github.com/op/fixture.git/info/refs',
    '',
  ]) {
    // On a credential-free host too, where no service ties the path to info/refs: the path's own shape refuses a query.
    for (const row of [ALLOW_ROW, FREE_ROW]) assert.equal(parses('proxy.decision', { ...row, path }), false, `path ${JSON.stringify(path)} was stored`)
    // With lengths that agree with it, so that nothing but the path's own shape is left to refuse it, on an allow and a deny.
    if (!path.startsWith('/')) continue
    for (const row of [FREE_ROW, { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com' }]) {
      assert.equal(parses('proxy.decision', defined({ ...row, ...pathed(path) })), false, `path ${JSON.stringify(path)} was stored with its own length`)
    }
  }
  for (const service of ['git-upload-pack', 'git-receive-pack']) {
    const row = { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, host: 'github.com', service, ...pathed('/op/fixture.git/info/refs', `?service=${service}`.length) }
    assert.equal(parses('proxy.decision', defined(row)), true, `${service}: ${why('proxy.decision', defined(row))}`)
  }
  for (const service of ['service=git-upload-pack', 'git-upload-pack&access_token=abc', 'git-upload-archive', 'GIT-UPLOAD-PACK', '']) {
    assert.equal(parses('proxy.decision', { ...ALLOW_ROW, service }), false, `service ${JSON.stringify(service)} was stored`)
    // On a deny, where no allowed profile pins the value, and with the
    // lengths that would make it the whole query: only the two services.
    const deny = { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, host: 'github.com', service, ...pathed('/op/fixture.git/info/refs', `?service=${service}`.length) }
    assert.equal(parses('proxy.decision', defined(deny)), false, `service ${JSON.stringify(service)} was stored on a deny`)
  }
  // The one key named for a query is a number: what a request carried in its
  // query is a length, and no key is a place for the target, a URL or a query.
  const keys = declaredKeys(PAYLOAD_SCHEMAS['proxy.decision'], 'd').map((d) => d.key)
  assert.deepEqual(keys.filter((k) => /query|url|uri|target|search|header/i.test(k)), ['queryBytes'])

  // An allow carries its lengths, a GET with 8 KiB in its query as plainly
  // as an empty one, and neither length admits text.
  const exfil = { ...FREE_ROW, ...pathed('/zod', 8_000) }
  assert.equal(parses('proxy.decision', exfil), true, why('proxy.decision', exfil))
  assert.equal(parses('proxy.decision', { ...FREE_ROW, ...pathed('/zod', 8_189) }), false, 'an allow carrying more than the upstream sends')
  for (const field of ['pathBytes', 'queryBytes']) {
    assert.equal(parses('proxy.decision', { ...FREE_ROW, [field]: undefined }), false, `an allow without ${field}`)
    for (const bad of ['12', '?text=zod', 1.5, -1, Number.POSITIVE_INFINITY, null]) {
      assert.equal(parses('proxy.decision', { ...FREE_ROW, [field]: bad }), false, `${field} took ${JSON.stringify(bad)}`)
    }
  }
  assert.equal(parses('proxy.decision', { ...FREE_ROW, pathBytes: 0 }), false, 'a path of no bytes')
  assert.equal(parses('proxy.decision', { ...FREE_ROW, queryBytes: 0 }), true)
})

test("a proxy.decision row's service is the route's own: the info/refs query of git-fetch or git-push, nothing else", () => {
  const infoRefs = (service: string): Record<string, unknown> => ({ service, ...pathed('/op/fixture.git/info/refs', `?service=${service}`.length) })
  const ok: ReadonlyArray<Record<string, unknown>> = [ALLOW_ROW, { ...PUSH_ROW, ...infoRefs('git-receive-pack'), method: 'GET' }, PUSH_ROW, UPSTREAM_ROW]
  for (const row of ok) assert.equal(parses('proxy.decision', defined(row)), true, why('proxy.decision', defined(row)))
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a git-fetch allow naming the push service', { ...ALLOW_ROW, ...infoRefs('git-receive-pack') }],
    ['a git-push allow naming the fetch service', { ...PUSH_ROW, method: 'GET', ...infoRefs('git-upload-pack') }],
    ['an upstream row of a fetch naming the push service', { ...UPSTREAM_ROW, ...infoRefs('git-receive-pack') }],
    ['a credential-free allow naming a service', { ...FREE_ROW, ...infoRefs('git-upload-pack') }],
    ['a github-pulls allow naming a service', { ...PUSH_ROW, reason: 'github-pulls', ...infoRefs('git-upload-pack') }],
    ['a service on a path that is no info/refs', { ...PUSH_ROW, service: 'git-receive-pack', queryBytes: 25 }],
    // On a deny, where no route shape holds the path: info/refs is where the path ends, not a part of it.
    [
      'a service on a path past info/refs',
      { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, host: 'github.com', service: 'git-upload-pack', ...pathed('/op/fixture.git/info/refs/x', 24) },
    ],
    ['a service that is not the whole query', { ...ALLOW_ROW, queryBytes: 40 }],
    ['a service with no query at all', { ...ALLOW_ROW, queryBytes: 0 }],
    ['an info/refs fetch naming no service', { ...ALLOW_ROW, service: undefined, queryBytes: 0 }],
    ['a query deny naming a service', { ...DENY_ROW, reason: 'query', hostRefusal: undefined, host: 'github.com', ...infoRefs('git-upload-pack') }],
    ['a bound route with a query but no service', { ...PUSH_ROW, queryBytes: 5 }],
    // A bare `?`: parseTarget reads an empty query, which matchRoute denies as 'query'.
    ['a bound route with a bare ?', { ...PUSH_ROW, queryBytes: 1 }],
    ['a github-pulls allow with a query', { ...PUSH_ROW, reason: 'github-pulls', ...pathed('/repos/op/fixture/pulls', 9) }],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.decision', defined(row)), false, `${what} was recorded`)
})

/** An allow of `reason` for `method` on `path`, a path with no query unless one is given. */
const routed = (reason: string, method: string, path: string, queryBytes = 0): Record<string, unknown> => ({
  ...ALLOW_ROW,
  reason,
  method,
  ...pathed(path, queryBytes),
  service: queryBytes === 0 ? undefined : reason === 'git-push' ? 'git-receive-pack' : 'git-upload-pack',
})

test("a proxy.decision allow is a request its reason admits: GET or HEAD on a credential-free host, and on a bound route its profile's shape on the repository it names", () => {
  const ok: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a fetch of info/refs', ALLOW_ROW],
    ['a fetch of info/refs without .git', routed('git-fetch', 'GET', '/op/fixture/info/refs', 24)],
    // matchRoute reads the repository without case, and its .git in any case.
    ['a fetch of info/refs in another spelling of the repository', routed('git-fetch', 'GET', '/Op/Fixture.GIT/info/refs', 24)],
    ['an upload-pack', routed('git-fetch', 'POST', '/op/fixture.git/git-upload-pack')],
    ['an upload-pack without .git', routed('git-fetch', 'POST', '/op/fixture/git-upload-pack')],
    ['a push of info/refs', routed('git-push', 'GET', '/op/fixture.git/info/refs', 25)],
    ['a receive-pack', PUSH_ROW],
    ['a pull request', routed('github-pulls', 'POST', '/repos/op/fixture/pulls')],
    ['a pull request in another spelling of the repository', routed('github-pulls', 'POST', '/repos/Op/Fixture/pulls')],
    ['a GET of a credential-free host', FREE_ROW],
    ['a HEAD of a credential-free host', { ...FREE_ROW, method: 'HEAD' }],
    ['an upstream row of a credential-free host', { ...UPSTREAM_ROW, ...FREE_ROW, stage: 'upstream', verdict: 'deny', method: 'HEAD' }],
    ['an upstream row of a pull request', { ...UPSTREAM_ROW, ...routed('github-pulls', 'POST', '/repos/op/fixture/pulls'), stage: 'upstream', verdict: 'deny' }],
  ]
  for (const [what, row] of ok) assert.equal(parses('proxy.decision', defined(row)), true, `${what}: ${why('proxy.decision', defined(row))}`)
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    // decide()'s judgeFree: GET and HEAD, nothing that writes.
    ['a POST to a credential-free host', { ...FREE_ROW, method: 'POST' }],
    ['a DELETE to a credential-free host', { ...FREE_ROW, method: 'DELETE' }],
    ['a PUT to a credential-free host, refused upstream', { ...UPSTREAM_ROW, ...FREE_ROW, stage: 'upstream', verdict: 'deny', method: 'PUT' }],
    // The method each shape takes.
    ['a push that GETs receive-pack', routed('git-push', 'GET', '/op/fixture.git/git-receive-pack')],
    ['a fetch that POSTs to info/refs', routed('git-fetch', 'POST', '/op/fixture.git/info/refs', 24)],
    ['a pull request listing pulls with a GET', routed('github-pulls', 'GET', '/repos/op/fixture/pulls')],
    // A path no profile names, with the credential on it.
    ['a fetch of /user/keys', routed('git-fetch', 'GET', '/user/keys')],
    ['a fetch of the repository web page', routed('git-fetch', 'GET', '/op/fixture')],
    ['a pull request on info/refs', routed('github-pulls', 'GET', '/op/fixture.git/info/refs')],
    ['a pull request on /user/keys', routed('github-pulls', 'POST', '/user/keys')],
    ['a pull request on issues', routed('github-pulls', 'POST', '/repos/op/fixture/issues')],
    ['info/refs in a spelling matchRoute does not read', routed('git-fetch', 'GET', '/op/fixture.git/INFO/REFS', 24)],
    ['a pull request on /Repos', routed('github-pulls', 'POST', '/Repos/op/fixture/pulls')],
    // Each profile's own endpoint.
    ['a fetch that posts to receive-pack', routed('git-fetch', 'POST', '/op/fixture.git/git-receive-pack')],
    ['a push that posts to upload-pack', routed('git-push', 'POST', '/op/fixture.git/git-upload-pack')],
    // The repository the row names is the one the path names.
    ['a fetch of another repository', routed('git-fetch', 'GET', '/evil/other.git/info/refs', 24)],
    ['a fetch of another repository, refused upstream', { ...UPSTREAM_ROW, ...pathed('/evil/other.git/info/refs', 24) }],
    ['a push to another repository', routed('git-push', 'POST', '/evil/other.git/git-receive-pack')],
    ['a pull request on another repository', routed('github-pulls', 'POST', '/repos/evil/other/pulls')],
    ['a fetch of a repository with two .git', routed('git-fetch', 'GET', '/op/fixture.git.git/info/refs', 24)],
    // A repository RepoSlug refuses: a name ending in .git reads two ways in a git URL, and . and .. are dot segments.
    ['a fetch of a repository named fixture.git, by two .git', { ...routed('git-fetch', 'GET', '/op/fixture.git.git/info/refs', 24), repo: 'op/fixture.git' }],
    ['a fetch of a repository named fixture.git, by one .git', { ...routed('git-fetch', 'GET', '/op/fixture.git/info/refs', 24), repo: 'op/fixture.git' }],
    ['a fetch of a repository named ..', { ...routed('git-fetch', 'GET', '/op/../info/refs', 24), repo: 'op/..' }],
    ['a fetch of a repository named .', { ...routed('git-fetch', 'GET', '/op/./info/refs', 24), repo: 'op/.' }],
    // The repository's text is compared as text: a dot in the path is a dot, not any character.
    ['a fetch of a repository one character from the bound one', routed('git-fetch', 'GET', '/op/fix.ure/info/refs', 24)],
    ['a pull request with a .git, which only a git URL reads', routed('github-pulls', 'POST', '/repos/op/fixture.git/pulls')],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.decision', defined(row)), false, `${what} was recorded`)
  for (const [what, row] of refused.slice(3)) {
    const reasons = why('proxy.decision', defined(row))
    assert.match(reasons, typeof row['repo'] === 'string' && RepoSlug.safeParse(row['repo']).success ? /a request of its profile on its repository/ : /as RepoSlug reads one/, what)
  }

  // A repository whose path, as the worker spelled it, is in a credential's
  // shape: the log leaves the lower-case name alone and censors the
  // upper-case spelling in the path, which no longer spells it. What survived
  // the censor is still compared: the owner, the slash, the .git and the shape.
  const akiaRepo = 'op/akiaabcdefghijklmnop'
  const spelled = '/op/AKIAABCDEFGHIJKLMNOP.git/info/refs'
  assert.equal(RepoSlug.parse(akiaRepo), akiaRepo)
  assert.equal(redactString(akiaRepo), akiaRepo)
  // matchRoute reads that spelling as this repository, so the request is one the grant allows.
  const match = matchRoute('GET', spelled, 'service=git-upload-pack')
  assert.equal(match.ok && match.repo, akiaRepo)
  const pullsPath = '/repos/op/AKIAABCDEFGHIJKLMNOP/pulls'
  assert.equal(recordable(pullsPath, EGRESS_PATH_BYTES), `/repos/op/${CENSOR}/pulls`)
  const censored = recordable(spelled, EGRESS_PATH_BYTES)
  assert.equal(censored, `/op/${CENSOR}.git/info/refs`)
  const row = { ...ALLOW_ROW, repo: akiaRepo, path: censored, pathBytes: spelled.length }
  const censoredOk: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a censored name with its .git', row],
    ['a censored name without .git', { ...row, path: `/op/${CENSOR}/info/refs`, pathBytes: spelled.length - 4 }],
    ['a censored owner', { ...row, repo: 'akiaabcdefghijklmnop/fixture', path: `/${CENSOR}/fixture.git/info/refs` }],
    ['a censored span inside a name', { ...row, repo: 'op/x-akiaabcdefghijklmnop-y', path: `/op/x-${CENSOR}-y.git/info/refs` }],
    ['a censored pull request', { ...routed('github-pulls', 'POST', `/repos/op/${CENSOR}/pulls`), repo: akiaRepo, pathBytes: pullsPath.length }],
  ]
  for (const [what, ok] of censoredOk) assert.equal(parses('proxy.decision', ok), true, `${what}: ${why('proxy.decision', ok)}`)
  const censoredRefused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a censored path taking a method its route does not', { ...row, method: 'POST' }],
    ["a censored path on another profile's endpoint", { ...row, path: `/op/${CENSOR}.git/git-receive-pack` }],
    // The rest of the repository survived the censor, and is not this one.
    ['a censored name under another owner', { ...row, path: `/evil/${CENSOR}/info/refs` }],
    ['a censored name under another owner, with .git', { ...row, path: `/evil/${CENSOR}.git/info/refs` }],
    ['a censored span with no owner and name around it', { ...row, path: `/${CENSOR}/info/refs` }],
    ['a censored owner of another name', { ...row, repo: 'akiaabcdefghijklmnop/fixture', path: `/${CENSOR}/other.git/info/refs` }],
    ['a censored name with two .git', { ...row, path: `/op/${CENSOR}.git.git/info/refs`, pathBytes: spelled.length + 4 }],
    ['a censored pull request on another owner', { ...routed('github-pulls', 'POST', `/repos/evil/${CENSOR}/pulls`), repo: akiaRepo, pathBytes: pullsPath.length + 2 }],
    ['a censored pull request with a .git', { ...routed('github-pulls', 'POST', `/repos/op/${CENSOR}.git/pulls`), repo: akiaRepo, pathBytes: pullsPath.length + 4 }],
    // A repository the log would itself censor is never recorded (the identifiers test), its row with it.
    ['a repository in a credential shape', { ...row, repo: `op/ghp_${'a'.repeat(36)}` }],
  ]
  for (const [what, refused] of censoredRefused) assert.equal(parses('proxy.decision', refused), false, `${what} was recorded`)

  // A row that judged one path and recorded another (an E8 bug, or a test) is
  // refused in time linear in its path however many spans the pass censored:
  // the spelling is scanned, never backtracked. A pattern of one unbounded
  // class per span took 12 s for eight spans on a 102-byte path, inside the
  // store's append, where it blocks the kernel's event loop.
  const hyphens = `op/${'-'.repeat(60)}`
  for (const spans of [8, 12, 40, 90]) {
    const path = `/op/${Array.from({ length: spans }, () => CENSOR).join('-')}x/info/refs`
    const inconsistent = { ...ALLOW_ROW, repo: hyphens, path, pathBytes: 500 }
    const began = performance.now()
    assert.equal(parses('proxy.decision', inconsistent), false, `${String(spans)} spans were recorded`)
    const took = performance.now() - began
    assert.ok(took < 250, `${String(spans)} censored spans took ${took.toFixed(0)} ms to refuse`)
    // And one whose every span stands for what the repository holds there is
    // taken as fast (a name holds at most 100 characters, so 33 spans of two).
    const kept = Math.min(spans, 33)
    const named = Array.from({ length: kept }, () => 'ab').join('-')
    const consistent = { ...ALLOW_ROW, repo: `op/${named}`, path: `/op/${Array.from({ length: kept }, () => CENSOR).join('-')}/info/refs`, pathBytes: 500 }
    const start = performance.now()
    assert.equal(parses('proxy.decision', consistent), true, `${String(spans)} spans: ${why('proxy.decision', consistent)}`)
    assert.ok(performance.now() - start < 250, `${String(spans)} censored spans took too long to take`)
  }
  // Each span stands for one character or more, and the literals between are found in order.
  for (const [what, repo, path, taken] of [
    ['a span for one character', 'op/x', `/op/${CENSOR}/info/refs`, true],
    ['two spans for two characters', 'op/xy', `/op/${CENSOR}${CENSOR}/info/refs`, true],
    ['two spans for one character', 'op/x', `/op/${CENSOR}${CENSOR}/info/refs`, false],
    ['a span for nothing', 'op/x', `/op/x${CENSOR}/info/refs`, false],
    // A .git survives the censor, so a span never stands for one.
    ['a span for part of the .git', 'op/x', `/op/${CENSOR}it/info/refs`, false],
    ['a .git after a span', 'op/x', `/op/${CENSOR}.GIT/info/refs`, true],
    ['literals out of order', 'op/a-b', `/op/${CENSOR}b${CENSOR}a${CENSOR}/info/refs`, false],
    ['a literal found again after its first place', 'op/ab-ab-c', `/op/${CENSOR}-${CENSOR}-c/info/refs`, true],
    ['a span across the slash', 'op/x', `/${CENSOR}/info/refs`, false],
    ['a span in the owner and one in the name', 'akiaabcdefghijklmnop/x-akiaabcdefghijklmnop', `/${CENSOR}/x-${CENSOR}/info/refs`, true],
    ['the case of a literal', 'op/x-akiaabcdefghijklmnop', `/OP/X-${CENSOR}/info/refs`, true],
    // A repository is an owner and a name, never a third part after them: the
    // owner and name spelled, then more, is a path no route reads as theirs.
    ['a third part after the name', 'op/fixture', '/op/fixture/extra/info/refs', false],
    ['a third part after the name, with .git', 'op/fixture', '/op/fixture/x.git/info/refs', false],
    ['a span for a third part after the name', 'op/fixture', `/op/fixture/${CENSOR}/info/refs`, false],
  ] as const) {
    const candidate = { ...ALLOW_ROW, repo, path, pathBytes: 500 }
    assert.equal(parses('proxy.decision', candidate), taken, `${what}: ${why('proxy.decision', candidate)}`)
  }
})

test('every id, name and answer is bounded where src/egress bounds it: taken at its limit, refused one past it', () => {
  /** A method deny naming its method alone: the row may leave out the host decide() read, as the session does one in a credential's shape. */
  const methodDeny = (method: string): Record<string, unknown> => ({ ...DENY_ROW, reason: 'method', hostRefusal: undefined, method })
  const pairs: ReadonlyArray<readonly [string, EventType, Record<string, unknown>, Record<string, unknown>]> = [
    // node:http's longest method is 11 letters; 24 is the bound, and a run cannot send one past it.
    ['a method', 'proxy.decision', methodDeny(`M${'-'.repeat(23)}`), methodDeny(`M${'-'.repeat(24)}`)],
    ['an agent id', 'proxy.grant.issued', { ...GRANT, agentId: 'a'.repeat(64) }, { ...GRANT, agentId: 'a'.repeat(65) }],
    ['a container name', 'proxy.grant.issued', { ...GRANT, sandbox: `aos-run-${'s'.repeat(120)}` }, { ...GRANT, sandbox: `aos-run-${'s'.repeat(121)}` }],
    ['an answer', 'proxy.decision', { ...UPSTREAM_ROW, address: '0000:0000:0000:0000:0000:ffff:255.255.255.255' }, { ...UPSTREAM_ROW, address: '0000:0000:0000:0000:0000:ffff:255.255.255.2555' }],
    ['a grant id', 'proxy.grant.issued', { ...GRANT, grantId: longRef('g') }, { ...GRANT, grantId: `${longRef('g')}g` }],
    ['a run id', 'proxy.grant.issued', { ...GRANT, runId: longRef('r') }, { ...GRANT, runId: `${longRef('r')}r` }],
    ['a binding id', 'egress.degraded', { schemaVersion: 1, check: 'binding', bindingId: longBinding(0), reason: 'r' }, { schemaVersion: 1, check: 'binding', bindingId: `${longBinding(0)}x`, reason: 'r' }],
    // RepoSlug's owner is at most 39 characters (routes.ts OWNER), so a row naming a longer one names a repository no grant holds.
    [
      "a repository's owner",
      'proxy.grant.issued',
      { ...GRANT, routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: [`${'o'.repeat(39)}/x`] }] },
      { ...GRANT, routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: [`${'o'.repeat(40)}/x`] }] },
    ],
  ]
  for (const [what, type, atLimit, onePast] of pairs) {
    assert.equal(parses(type, atLimit), true, `${what} at its limit: ${why(type, atLimit)}`)
    assert.equal(parses(type, onePast), false, `${what} one past its limit was recorded`)
  }
  assert.equal('0000:0000:0000:0000:0000:ffff:255.255.255.255'.length, 45)
})

test('a proxy.decision row says which stage judged it and is whole for what it says: an allow names its route, an upstream row its refusal and whether it left', () => {
  const ok: ReadonlyArray<Record<string, unknown>> = [ALLOW_ROW, DENY_ROW, UPSTREAM_ROW, SENT_PUSH_ROW, { ...DENY_ROW, count: 7 }]
  for (const row of ok) assert.equal(parses('proxy.decision', row), true, why('proxy.decision', row))
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a policy allow with a deny reason', { ...ALLOW_ROW, reason: 'not-allowed' }],
    ['a policy deny with an allow reason', { ...ALLOW_ROW, verdict: 'deny' }],
    ['a policy row with a refusal', { ...ALLOW_ROW, refusal: 'connect-failed' }],
    ['a policy row saying it was sent', { ...ALLOW_ROW, sent: true }],
    ['a policy row with an answer', { ...ALLOW_ROW, address: '140.82.112.3' }],
    ['a policy row with an error code', { ...DENY_ROW, code: 'ECONNREFUSED' }],
    ['an upstream row with a deny reason', { ...UPSTREAM_ROW, reason: 'not-allowed' }],
    ['an upstream row with no refusal', { ...UPSTREAM_ROW, refusal: undefined, address: undefined, denial: undefined }],
    ['an upstream row that does not say whether it was sent', { ...UPSTREAM_ROW, sent: undefined }],
    ['an upstream row saying sent in text', { ...UPSTREAM_ROW, sent: 'false' }],
    ['an unknown refusal', { ...UPSTREAM_ROW, refusal: 'rebound' }],
    ['an unknown stage', { ...ALLOW_ROW, stage: 'session' }],
    ['a route allow with no binding', { ...ALLOW_ROW, bindingId: undefined }],
    ['a route allow with no repository', { ...ALLOW_ROW, repo: undefined }],
    ['a credential-free allow naming a binding', { ...FREE_ROW, bindingId: 'github' }],
    ['a credential-free allow naming a repository', { ...FREE_ROW, repo: 'op/fixture' }],
    ['an upstream row on a route with no binding', { ...UPSTREAM_ROW, bindingId: undefined }],
    ['an allow with no host', { ...ALLOW_ROW, host: undefined }],
    // A credential-free allow with no host: no binding asks for one, so the allow's own rule must.
    ['a credential-free allow with no host', { ...FREE_ROW, host: undefined }],
    ['an upstream row of a credential-free host with no host', { ...UPSTREAM_ROW, ...FREE_ROW, stage: 'upstream', verdict: 'deny', host: undefined }],
    ['an allow with no method', { ...ALLOW_ROW, method: undefined }],
    ['an allow with no path', { ...ALLOW_ROW, path: undefined, pathBytes: undefined, queryBytes: undefined }],
    ['no why', { ...DENY_ROW, why: undefined }],
    ['an empty why', { ...DENY_ROW, why: '' }],
    ['a grant id with a slash', { ...ALLOW_ROW, grantId: 'grant/1' }],
    ['a host in another spelling', { ...ALLOW_ROW, host: 'GitHub.com' }],
    ['a host with its trailing dot', { ...ALLOW_ROW, host: 'github.com.' }],
    ['an IPv4 address as a host', { ...ALLOW_ROW, host: '192.168.5.2' }],
    ['an IPv4 address in hex parts as a host', { ...ALLOW_ROW, host: 'example.0x7f' }],
    ['a single label as a host', { ...ALLOW_ROW, host: 'localhost' }],
    ['a host with a port', { ...ALLOW_ROW, host: 'github.com:443' }],
    ['a host with an underscore', { ...ALLOW_ROW, host: 'git_hub.com' }],
    ['a repository in another spelling', { ...ALLOW_ROW, repo: 'Op/Fixture' }],
    ['a method in lower case', { ...ALLOW_ROW, method: 'get' }],
    ['an answer that is no address', { ...UPSTREAM_ROW, address: 'host.lima.internal' }],
    // An error's code, never its message, which may hold a host or an address.
    ['an error message as its code', { ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined, denial: undefined, code: 'getaddrinfo ENOTFOUND 192.168.5.2' }],
    ['an error code in lower case', { ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined, denial: undefined, code: 'econnrefused' }],
    ['an error code of 65 characters', { ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined, denial: undefined, code: `E${'X'.repeat(64)}` }],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.decision', defined(row)), false, `${what} was recorded`)
  // The error code at its bound is taken, so the 65 above is refused for its length.
  assert.equal(parses('proxy.decision', defined({ ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined, denial: undefined, code: `E${'X'.repeat(63)}` })), true)
})

test('an upstream row is a deny exactly when nothing of the request left: a credentialed push the host went quiet on is recorded as allowed and sent', () => {
  // The idle-timeout after the head and the pack were written: the host may
  // have applied the push, so the log must not call it refused.
  assert.equal(parses('proxy.decision', SENT_PUSH_ROW), true, why('proxy.decision', SENT_PUSH_ROW))
  assert.equal(parses('proxy.decision', { ...SENT_PUSH_ROW, verdict: 'deny' }), false, 'a sent push was recorded as a deny')
  // The same refusal before the head: nothing left, and the row is a deny.
  assert.equal(parses('proxy.decision', { ...SENT_PUSH_ROW, verdict: 'deny', sent: false }), true)
  assert.equal(parses('proxy.decision', { ...SENT_PUSH_ROW, verdict: 'allow', sent: false }), false, 'a request that never left was recorded as an allow')
  // Every refusal the upstream can meet after the head may come with sent; none other may.
  // The session's own (a challenge, a head it cannot pass on) are the host's answer, so neither comes without.
  for (const refusal of PROXY_UPSTREAM_REFUSALS) {
    const row = defined({ ...SENT_PUSH_ROW, refusal, ...(refusal === 'denied-address' ? { address: '192.168.5.2', denial: 'private' } : refusal === 'host-address' ? { address: '81.2.69.160' } : {}) })
    const afterSend = (PROXY_REFUSALS_AFTER_SEND as readonly string[]).includes(refusal)
    const answered = (SESSION_REFUSALS as readonly string[]).includes(refusal)
    assert.equal(parses('proxy.decision', row), afterSend, `${refusal} with a sent request: ${why('proxy.decision', row)}`)
    assert.equal(parses('proxy.decision', { ...row, verdict: 'deny', sent: false }), !answered, `${refusal} before the head: ${why('proxy.decision', { ...row, verdict: 'deny', sent: false })}`)
  }
  // A challenge, or an answer the session could not pass on, recorded as
  // unsent is refused for what it is, not only for its verdict.
  for (const refusal of SESSION_REFUSALS) {
    assert.match(why('proxy.decision', { ...SENT_PUSH_ROW, refusal, verdict: 'deny', sent: false }), /is the host answering the request, so the request was sent/, refusal)
  }
})

test("a coalesced deny stands for requests that had exactly its fields, and an overflow row names its reason, its count and a not-a-host, use-route or second-host deny's host refusal alone", () => {
  const ok: ReadonlyArray<Record<string, unknown>> = [
    { ...DENY_ROW, count: 7 },
    { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: '192-168-5-2.example', method: 'GET', bindingId: undefined, count: 3 },
    OVERFLOW_ROW,
    // Keyed by host refusal as well as reason: a flood of typos does not hide a probe of 192.168.5.2 or host.lima.internal,
    // nor a flood of tunnels to real hosts a CONNECT to one.
    ...PROXY_HOST_REFUSALS.map((hostRefusal) => ({ ...OVERFLOW_ROW, reason: 'not-a-host', hostRefusal })),
    ...PROXY_HOST_REFUSALS.map((hostRefusal) => ({ ...OVERFLOW_ROW, reason: 'use-route', hostRefusal })),
    ...PROXY_HOST_REFUSALS.map((hostRefusal) => ({ ...OVERFLOW_ROW, reason: 'second-host', hostRefusal })),
    { ...OVERFLOW_ROW, reason: 'use-route' },
    { ...OVERFLOW_ROW, reason: 'second-host' },
    { ...OVERFLOW_ROW, count: 1 },
    // A flood of pushes to a ref outside the run's prefix, on a bound route: coalesced under its host and binding (E8).
    { ...DENY_ROW, reason: 'push-ref', hostRefusal: undefined, host: 'github.com', method: 'POST', bindingId: 'github', count: 37 },
  ]
  for (const row of ok) assert.equal(parses('proxy.decision', defined(row)), true, why('proxy.decision', defined(row)))
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['an allow standing for two requests', { ...ALLOW_ROW, count: 2 }],
    ['an upstream row standing for two requests', { ...UPSTREAM_ROW, count: 2 }],
    ['a count of none', { ...DENY_ROW, count: 0 }],
    ['a count that is no integer', { ...DENY_ROW, count: 1.5 }],
    // The first request's path standing for all of them.
    ['a coalesced deny naming a path', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', count: 37, ...pathed('/') }],
    ['a coalesced deny naming a service', { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, host: 'github.com', count: 2, service: 'git-receive-pack' }],
    ['a coalesced deny naming a repository', { ...DENY_ROW, reason: 'repo', hostRefusal: undefined, host: 'github.com', count: 2, repo: 'op/fixture' }],
    ['an overflow row naming a host', { ...OVERFLOW_ROW, host: 'example.com' }],
    ['an overflow row naming a method', { ...OVERFLOW_ROW, method: 'GET' }],
    ['an overflow row naming a binding', { ...OVERFLOW_ROW, bindingId: 'github' }],
    ['a not-a-host overflow row naming no host refusal', { ...OVERFLOW_ROW, reason: 'not-a-host' }],
    ['an overflow row of another reason naming a host refusal', { ...OVERFLOW_ROW, hostRefusal: 'ip-literal' }],
    ['a port overflow row naming a host refusal', { ...OVERFLOW_ROW, reason: 'port', hostRefusal: 'ip-literal' }],
    ['a use-route overflow row naming its host', { ...OVERFLOW_ROW, reason: 'use-route', host: 'github.com' }],
    ['a use-route overflow row naming its method', { ...OVERFLOW_ROW, reason: 'use-route', method: 'CONNECT', hostRefusal: 'ip-literal' }],
    ['an overflow row with decide()\'s clause', { ...OVERFLOW_ROW, why: 'the host is neither credential-free nor bound for this run' }],
    ["an overflow row with decide()'s clause after the kernel's", { ...OVERFLOW_ROW, why: `${PROXY_OVERFLOW_WHY}; the host is neither credential-free nor bound for this run` }],
    // An overflow of one request is still counted by reason alone: what a coalesced row may not name, it may not either.
    ['an overflow row of one request naming a path', { ...OVERFLOW_ROW, count: 1, ...pathed('/') }],
    ['an overflow row of one request naming a service', { ...OVERFLOW_ROW, count: 1, service: 'git-upload-pack', ...pathed('/op/fixture.git/info/refs', 24) }],
    ['an overflow row of one request naming a repository', { ...OVERFLOW_ROW, count: 1, repo: 'op/fixture' }],
    ['an overflow row of one request with decide()\'s clause', { ...OVERFLOW_ROW, count: 1, why: 'the host is neither credential-free nor bound for this run' }],
    ['an overflow allow', { ...ALLOW_ROW, overflow: true }],
    ['an overflow upstream row', { ...UPSTREAM_ROW, overflow: true }],
    ['an overflow flag of false', { ...DENY_ROW, overflow: false }],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.decision', defined(row)), false, `${what} was recorded`)
  // An allow is one request for its own reason, not only because its path
  // could not stand for two: the rule says so wherever the row stands.
  for (const row of [{ ...ALLOW_ROW, count: 2 }, { ...UPSTREAM_ROW, count: 2 }, { ...SENT_PUSH_ROW, count: 3 }]) {
    assert.match(why('proxy.decision', row), /only a policy deny stands for more than one request/)
  }
  // PROXY_DENY_KEYS_PER_SECOND's doc counts what overflow rows add to a
  // second: one per deny reason the host refusal does not key, 12 for
  // not-a-host (one per host refusal), and 13 each for use-route and
  // second-host (one per host refusal, and one where a host was read).
  assert.equal(PROXY_DENY_REASONS.length - PROXY_DENIES_BY_HOST_REFUSAL.length, 19)
  assert.equal(PROXY_HOST_REFUSALS.length, 12)
  assert.deepEqual([...PROXY_DENIES_BY_HOST_REFUSAL].sort(), ['not-a-host', 'second-host', 'use-route'])
  // Likewise an overflow: a deny of the policy's alone, not only because an allow names a path.
  for (const row of [{ ...ALLOW_ROW, overflow: true }, { ...UPSTREAM_ROW, overflow: true }]) {
    assert.match(why('proxy.decision', row), /only a policy deny overflows/)
  }
})

test('a proxy.decision row names only what src/egress can produce: a not-a-host deny read no host, path or route, a binding comes with its host and a service with its path, a path with the length it had, a denied answer names its denial, a path is printable ASCII', () => {
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a not-a-host deny naming a host', { ...DENY_ROW, host: 'example.com' }],
    ['a not-a-host deny that does not say why', { ...DENY_ROW, hostRefusal: undefined }],
    ['a hostRefusal on another deny', { ...DENY_ROW, reason: 'not-allowed' }],
    ['a hostRefusal on an allow', { ...ALLOW_ROW, hostRefusal: 'port' }],
    ['a hostRefusal on an upstream row', { ...UPSTREAM_ROW, hostRefusal: 'special-use' }],
    ['a denied-address refusal naming no denial', { ...UPSTREAM_ROW, denial: undefined }],
    ['a denied-address refusal naming no answer', { ...UPSTREAM_ROW, address: undefined }],
    ['an answer that was no address, stored', { ...UPSTREAM_ROW, denial: 'not-an-address' }],
    ['a host-address refusal naming no answer', { ...UPSTREAM_ROW, refusal: 'host-address', address: undefined, denial: undefined }],
    ['a denial on another refusal', { ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined }],
    ['an answer on a refusal that names none', { ...UPSTREAM_ROW, refusal: 'connect-failed', denial: undefined }],
    ['a path length with no path', { ...DENY_ROW, pathBytes: 1, queryBytes: 0 }],
    ['a path with no lengths', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', path: '/' }],
    // decide() finds a binding only from a host, and parseTarget stops at a host that is none.
    ['a binding with no host', { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, bindingId: 'github' }],
    ['a not-a-host deny naming a binding', { ...DENY_ROW, bindingId: 'github' }],
    ['a not-a-host deny naming a repository', { ...DENY_ROW, repo: 'op/fixture' }],
    ['a not-a-host deny naming a path', { ...DENY_ROW, ...pathed('/mcp') }],
    // A service is the query of a path.
    ['a service with no path and no host', { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, service: 'git-upload-pack' }],
    ['a service with no path', { ...DENY_ROW, reason: 'not-granted', hostRefusal: undefined, host: 'github.com', service: 'git-upload-pack' }],
    // pathBytes is the length the path had: an uncut path's own, more than a cut one kept.
    ['an uncut path longer than its pathBytes', { ...FREE_ROW, path: '/abcdefgh', pathBytes: 1 }],
    ['an uncut path shorter than its pathBytes', { ...FREE_ROW, path: '/abcdefgh', pathBytes: 10 }],
    // A cut path is what recordable() keeps of a longer one: EGRESS_PATH_BYTES bytes, mark included, of a path longer than that.
    ['a cut path no longer than what was kept', { ...FREE_ROW, path: CUT_PATH, pathBytes: CUT_PATH.length - 1 }],
    ['a cut path as long as what was kept', { ...FREE_ROW, path: CUT_PATH, pathBytes: CUT_PATH.length }],
    ['a cut path of its budget, which recordable() keeps whole', { ...FREE_ROW, path: CUT_PATH, pathBytes: EGRESS_PATH_BYTES }],
    // A path cut by hand, short of the budget: no writer through recordable() makes one.
    ['a short cut path', { ...FREE_ROW, path: '/abc\u2026', pathBytes: 5 }],
    ['a short cut path of a long one', { ...FREE_ROW, path: '/abc\u2026', pathBytes: 5_000 }],
    ['a cut path a byte short of the budget', { ...FREE_ROW, path: `${CUT_PATH.slice(0, -2)}\u2026`, pathBytes: 5_000 }],
    // No deny's lengths outrun the longest target parseTarget reads.
    ['a deny carrying 2^52 bytes of path', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', path: CUT_PATH, pathBytes: 2 ** 52, queryBytes: 0 }],
    [
      'a deny carrying a byte more than the longest target',
      { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', path: CUT_PATH, pathBytes: EGRESS_REQUEST_TARGET_MAX_BYTES - 99, queryBytes: 100 },
    ],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.decision', defined(row)), false, `${what} was recorded`)
  const ok: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a cut path one byte past the budget', { ...FREE_ROW, path: CUT_PATH, pathBytes: EGRESS_PATH_BYTES + 1 }],
    ['a deny carrying the longest target', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host: 'example.com', path: CUT_PATH, pathBytes: EGRESS_REQUEST_TARGET_MAX_BYTES - 100, queryBytes: 100 }],
    // A path the redaction pass censored is no longer the request's length: pathBytes is the request's.
    ['a censored path', { ...FREE_ROW, path: `/${CENSOR}/x`, pathBytes: 50 }],
    ['a deny on a route, its binding found from its host', { ...DENY_ROW, reason: 'push-ref', hostRefusal: undefined, host: 'github.com', bindingId: 'github' }],
  ]
  for (const [what, row] of ok) assert.equal(parses('proxy.decision', defined(row)), true, `${what}: ${why('proxy.decision', defined(row))}`)
  // A path as parseTarget admits one, and recordable()'s cut mark at its end only.
  for (const path of ['/a\u0000b', '/a\nb', '/a b', '/a\tb', '/caf\u00e9', '/a\u2026b', '/\u2026\u2026', '/a\u007f']) {
    assert.equal(parses('proxy.decision', { ...FREE_ROW, ...pathed(path) }), false, `path ${JSON.stringify(path)} was stored`)
  }
  for (const path of ['/', '/zod/-/zod-4.6.7.tgz', '/a!"$%&\'()*+,-./:;<=>@[\\]^_`{|}~']) {
    assert.equal(parses('proxy.decision', { ...FREE_ROW, ...pathed(path) }), true, `path ${JSON.stringify(path)}: ${why('proxy.decision', { ...FREE_ROW, ...pathed(path) })}`)
  }
  // The cut mark ends only a path recordable() cut: what it made of one byte past the budget, its own pathBytes.
  const justOver = `/${'p'.repeat(EGRESS_PATH_BYTES)}`
  assert.equal(recordable(justOver, EGRESS_PATH_BYTES), CUT_PATH)
  assert.equal(parses('proxy.decision', { ...FREE_ROW, path: recordable(justOver, EGRESS_PATH_BYTES), pathBytes: justOver.length }), true)
  assert.equal(parses('proxy.decision', { ...FREE_ROW, path: '/a\u2026', pathBytes: 3 }), false, 'a path cut by hand to three bytes was recorded')
})

test('a policy deny names at most what decide() had read when its reason stopped it: no host before the host, no path before the path, a binding only past a bound route, and never a repository', () => {
  /** A policy deny of `reason` naming `fields`, and the host refusal a not-a-host deny always names. */
  const deny = (reason: string, fields: Record<string, unknown> = {}): Record<string, unknown> =>
    defined({ schemaVersion: 1, grantId: 'grant_1', stage: 'policy', verdict: 'deny', reason, count: 1, why: 'denied', ...(reason === 'not-a-host' ? { hostRefusal: 'ip-literal' } : {}), ...fields })
  const listed = (list: readonly string[], reason: string): boolean => list.includes(reason)
  const host = { host: 'github.com' }
  const path = { ...host, ...pathed('/op/fixture.git/git-upload-pack') }
  const binding = { ...host, bindingId: 'github' }
  for (const reason of PROXY_DENY_REASONS) {
    assert.equal(parses('proxy.decision', deny(reason)), true, `${reason} alone: ${why('proxy.decision', deny(reason))}`)
    assert.equal(parses('proxy.decision', deny(reason, host)), !listed(PROXY_DENIES_BEFORE_HOST, reason), `${reason} naming a host`)
    assert.equal(parses('proxy.decision', deny(reason, path)), !listed(PROXY_DENIES_BEFORE_PATH, reason), `${reason} naming a path`)
    assert.equal(parses('proxy.decision', deny(reason, binding)), listed(PROXY_DENIES_ON_A_ROUTE, reason), `${reason} naming a binding`)
    // Coalesced, under its host and binding, the same: a key names only what each request's row could.
    assert.equal(parses('proxy.decision', deny(reason, { ...binding, count: 9 })), listed(PROXY_DENIES_ON_A_ROUTE, reason), `${reason} coalesced with a binding`)
    // EgressDenied carries no repository, whatever the reason: the path, when kept, spells the one asked for.
    for (const fields of [{ repo: 'op/fixture' }, { ...host, repo: 'op/fixture' }, { ...binding, repo: 'op/fixture' }, { ...path, repo: 'op/fixture' }]) {
      assert.equal(parses('proxy.decision', deny(reason, fields)), false, `${reason} naming a repository with ${Object.keys(fields).join(', ')}`)
    }
  }
  // The probes, by name: what a CONNECT, an unreadable target or a wrong port never read.
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a CONNECT naming a binding', deny('use-route', { method: 'CONNECT', ...binding })],
    ['a CONNECT naming a host and why it was none', deny('use-route', { method: 'CONNECT', host: 'github.com', hostRefusal: 'ip-literal' })],
    ['a userinfo target naming a host and why it was none', deny('second-host', { method: 'GET', host: 'github.com', hostRefusal: 'special-use' })],
    ['a wrong port saying why its host was none', deny('port', { method: 'GET', hostRefusal: 'ip-literal' })],
    ['an unreadable target saying why its host was none', deny('target', { method: 'GET', hostRefusal: 'ip-literal' })],
    ['a not-allowed deny saying why its host was none', deny('not-allowed', { method: 'GET', hostRefusal: 'ip-literal' })],
    // decide() denies a CONNECT use-route before anything else, and only a CONNECT.
    ['a use-route deny of a GET', deny('use-route', { method: 'GET', hostRefusal: 'ip-literal' })],
    ['a CONNECT denied for its target', deny('target', { method: 'CONNECT' })],
    ['a CONNECT denied for its host', deny('not-a-host', { method: 'CONNECT' })],
    ['a CONNECT denied for its method', deny('method', { method: 'CONNECT', ...host })],
    ['a CONNECT naming a path', deny('use-route', { method: 'CONNECT', ...pathed('/') })],
    ['an unreadable target naming a host', deny('target', host)],
    ['an unreadable target naming a binding and a path', deny('target', { ...binding, ...pathed('/op/fixture.git/info/refs') })],
    ['a wrong port naming a path', deny('port', path)],
    ['a wrong port naming a binding', deny('port', binding)],
    ['a path deny naming a binding', deny('path', { ...binding, ...pathed('/op/fixture.git%2finfo/refs') })],
    ['a not-allowed deny naming a binding', deny('not-allowed', binding)],
    ['a repository deny naming the repository', deny('repo', { ...host, repo: 'evil/other' })],
    ['a not-granted deny naming the repository', deny('not-granted', { ...binding, repo: 'op/fixture' })],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.decision', row), false, `${what} was recorded`)
  const taken: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    // A CONNECT names where it was headed: a real host, or why its host was none.
    ['a CONNECT naming a host', deny('use-route', { method: 'CONNECT', host: 'github.com' })],
    ['a CONNECT to pmmcp, by its host refusal', deny('use-route', { method: 'CONNECT', hostRefusal: 'ip-literal' })],
    ['a CONNECT to pmmcp by name, by its host refusal', deny('use-route', { method: 'CONNECT', hostRefusal: 'special-use' })],
    ['a CONNECT whose method was not recorded', deny('use-route', { hostRefusal: 'ip-literal' })],
    ['a CONNECT a broken grant left unjudged', deny('malformed', { method: 'CONNECT' })],
    // So does a userinfo target, past its userinfo.
    ['a userinfo target naming the host past it', deny('second-host', { method: 'GET', host: 'registry.npmjs.org' })],
    ['a userinfo target before pmmcp, by its host refusal', deny('second-host', { method: 'GET', hostRefusal: 'ip-literal' })],
    // parseTarget reads the host before the port, and a port or path refusal names it.
    ['a wrong port naming its host', deny('port', { method: 'GET', host: 'example.com' })],
    ['a path deny naming its host and path', deny('path', { method: 'GET', host: 'registry.npmjs.org', ...pathed('/a/../b') })],
    ['a probe of pmmcp, by its host refusal', deny('not-a-host', { method: 'GET', hostRefusal: 'ip-literal' })],
    ['a push-ref deny on its route', deny('push-ref', { method: 'POST', ...binding, ...pathed('/op/fixture.git/git-receive-pack') })],
    // An upstream row keeps its allow's fields, its binding and repository among them.
    ['an upstream deny of a route', UPSTREAM_ROW],
  ]
  for (const [what, row] of taken) assert.equal(parses('proxy.decision', row), true, `${what}: ${why('proxy.decision', row)}`)
  // A host refusal rides exactly the reasons PROXY_DENIES_BY_HOST_REFUSAL names, coalesced too, and never beside a host.
  for (const reason of PROXY_DENY_REASONS) {
    const refusal = deny(reason, { hostRefusal: 'ip-literal' })
    assert.equal(parses('proxy.decision', refusal), listed(PROXY_DENIES_BY_HOST_REFUSAL, reason), `${reason} naming a host refusal: ${why('proxy.decision', refusal)}`)
    assert.equal(parses('proxy.decision', { ...refusal, count: 5 }), listed(PROXY_DENIES_BY_HOST_REFUSAL, reason), `${reason} coalesced with a host refusal`)
    assert.equal(parses('proxy.decision', deny(reason, { ...host, hostRefusal: 'ip-literal' })), false, `${reason} naming a host and a host refusal`)
  }
  // The tables are of deny reasons, and nested as decide() reads: the host, then the port, then the path, then a route.
  for (const reason of [...PROXY_DENIES_BEFORE_PATH, ...PROXY_DENIES_ON_A_ROUTE, ...PROXY_DENIES_BY_HOST_REFUSAL]) assert.ok(listed(PROXY_DENY_REASONS, reason), reason)
  for (const reason of PROXY_DENIES_BEFORE_HOST) assert.ok(listed(PROXY_DENIES_BEFORE_PATH, reason), reason)
  for (const reason of PROXY_DENIES_ON_A_ROUTE) assert.equal(listed(PROXY_DENIES_BEFORE_PATH, reason), false, reason)
  // A reason that names a host refusal reads no route: it stopped at a host.
  for (const reason of PROXY_DENIES_BY_HOST_REFUSAL) assert.equal(listed(PROXY_DENIES_ON_A_ROUTE, reason), false, reason)
})

test('no identifier a row names is one the redaction pass would censor: a grant naming one is not issued, and nothing stores a host, a repository or a binding as [REDACTED]', (t) => {
  const store = withStore(t)
  const host = 'sk-abcdefghij.example.com'
  const repo = `op/ghp_${'a'.repeat(36)}`
  const binding = 'sk-something'
  const ref = `ghp_${'a'.repeat(20)}`
  const akia = 'AKIAABCDEFGHIJKLMNOP'
  // Each fits its field's shape, as src/egress makes it, and the pass changes it.
  assert.equal(EgressHost.parse(host), host)
  assert.equal(RepoSlug.parse(repo), repo)
  assert.match(binding, BINDING_ID)
  assert.match(ref, RUN_REF)
  for (const id of [host, repo, binding, ref, `aos-run-${ref}`, akia]) assert.notEqual(redactString(id), id, `${id} is no credential shape`)
  const route = { bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }
  const tokenPath = recordable(`/${repo}.git/info/refs`, EGRESS_PATH_BYTES)
  const refused: ReadonlyArray<readonly [string, EventType, Record<string, unknown>]> = [
    ['a credential-free host', 'proxy.grant.issued', { ...GRANT, allow: [host] }],
    ['a bound host', 'proxy.grant.issued', { ...GRANT, routes: [{ ...route, host }] }],
    ['a repository', 'proxy.grant.issued', { ...GRANT, routes: [{ ...route, repos: ['op/fixture', repo] }] }],
    ['a binding id', 'proxy.grant.issued', { ...GRANT, routes: [{ ...route, bindingId: binding }] }],
    ['a grant id', 'proxy.grant.issued', { ...GRANT, grantId: ref }],
    ['a run id', 'proxy.grant.issued', { ...GRANT, runId: ref }],
    ['an agent id', 'proxy.grant.issued', { ...GRANT, agentId: ref }],
    ['a container name', 'proxy.grant.issued', { ...GRANT, sandbox: `aos-run-${ref}` }],
    ["an allow's host", 'proxy.decision', { ...FREE_ROW, host }],
    // The worker's own spelling of a host it was denied: E8 records such a deny without it.
    ["a deny's host", 'proxy.decision', { ...DENY_ROW, reason: 'not-allowed', hostRefusal: undefined, host }],
    // Its path censored too, so that only the repository's own field is refused.
    ["an allow's repository", 'proxy.decision', { ...ALLOW_ROW, repo, path: tokenPath, pathBytes: `/${repo}.git/info/refs`.length }],
    ["an allow's binding", 'proxy.decision', { ...ALLOW_ROW, bindingId: binding }],
    ["a decision's grant id", 'proxy.decision', { ...ALLOW_ROW, grantId: ref }],
    ['a method', 'proxy.decision', { ...DENY_ROW, reason: 'method', hostRefusal: undefined, method: akia }],
    ['an error code', 'proxy.decision', { ...UPSTREAM_ROW, refusal: 'connect-failed', address: undefined, denial: undefined, code: akia }],
    ["a revocation's grant id", 'proxy.grant.revoked', { ...REVOKED, grantId: ref }],
    ['a binding that failed to resolve', 'egress.degraded', { schemaVersion: 1, check: 'binding', bindingId: binding, reason: 'r' }],
  ]
  for (const [what, type, row] of refused) {
    assert.equal(parses(type, defined(row)), false, `${what} in a credential shape was recorded`)
    assert.match(why(type, defined(row)), /would be stored censored/, what)
    // Refused at the append, so the store never writes [REDACTED] where the row names a host or an id.
    assert.throws(() => store.append({ type, payload: defined(row) }), what)
  }
  assert.equal(store.query().length, 0)
  assert.equal(store.verifyChain().ok, true)
  // What the pass leaves alone is taken, held to redactString itself: a near miss of each shape, and each shape.
  for (const candidate of ['sk-abcdefg.example.com', 'sk-abcdefghij.example.com', 'ghp-aaaaaaaaaaaaaaaaaaaaaaaa.example.com', 'ghp-aaaaaaaaaaaaaaaaaaaaaaaa.com', 'xoxb-aaaaaaaaaa.example.com', 'xoxb-aaaa.example.com', 'akiaabcdefghijklmnop.example.com', 'eyaaaaaaaaaa.eyaaaaaaaaaa.aaaaaaaaaa.com', 'github.com']) {
    const host = EgressHost.parse(candidate)
    assert.equal(parses('proxy.grant.issued', { ...GRANT, allow: [host], routes: [] }), redactString(host) === host, host)
  }
  for (const candidate of [`op/ghp_${'a'.repeat(19)}`, repo, `op/github_pat_${'a'.repeat(20)}`, 'op/sk-abcdefg', 'op/sk-abcdefgh', 'sk-abcdefgh/x', 'op/akiaabcdefghijklmnop']) {
    const slug = RepoSlug.parse(candidate)
    assert.equal(parses('proxy.grant.issued', { ...GRANT, routes: [{ ...route, repos: [slug] }] }), redactString(slug) === slug, slug)
  }
})

/** A distinct route of one repository on github.com. */
const routeOf = (i: number, profiles: readonly string[] = ['git-fetch']): Record<string, unknown> => ({ bindingId: `b${String(i)}`, host: 'github.com', profiles, repos: [`op/r${String(i)}`] })

test('a proxy.grant.issued row: a canary serves no run and reaches nothing, an exec grant never holds git-push or github-pulls, and the hostile domain is never granted', () => {
  for (const grant of [GRANT, PUBLISH_GRANT, CANARY_GRANT]) assert.equal(parses('proxy.grant.issued', grant), true, JSON.stringify(grant))
  const route = (profiles: readonly string[]): Record<string, unknown> => ({ bindingId: 'github', host: 'github.com', profiles, repos: ['op/fixture'] })
  // At the bounds: taken.
  const atBounds: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['64 hosts', { ...GRANT, allow: Array.from({ length: 64 }, (_, i) => `h${String(i)}.example.com`) }],
    ['16 routes', { ...GRANT, routes: Array.from({ length: 16 }, (_, i) => routeOf(i)) }],
    ['64 repositories in one route', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: Array.from({ length: 64 }, (_, i) => `op/r${String(i)}`) }] }],
    ['every profile', { ...PUBLISH_GRANT, routes: [route([...PROXY_PROFILES])] }],
    ['a 253-character host', { ...GRANT, allow: [longHost(1)] }],
    ['a 100-character repository name', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: [`op/${'n'.repeat(100)}`] }] }],
    // A repository is in one route per host: the same name on a second bound host is another repository.
    ['one repository on two bound hosts', { ...GRANT, routes: [route(['git-fetch']), { ...route(['git-fetch']), bindingId: 'mirror', host: 'git.example.com' }] }],
    ['names RepoSlug admits that end near .git', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: ['op/fixture.gi', 'op/git', 'op/...', 'op/.github', 'op/a.git-x'] }] }],
  ]
  for (const [what, grant] of atBounds) assert.equal(parses('proxy.grant.issued', grant), true, `${what}: ${why('proxy.grant.issued', grant)}`)
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['an exec grant holding git-push', { ...GRANT, routes: [route(['git-fetch', 'git-push'])] }],
    ['an exec grant holding github-pulls', { ...GRANT, routes: [route(['github-pulls'])] }],
    ['a hostile grant', { ...GRANT, domain: 'hostile' }],
    ['a canary with a run', { ...CANARY_GRANT, runId: 'run_1' }],
    ['a canary with an agent', { ...CANARY_GRANT, agentId: 'coder' }],
    ['a canary reaching a host', { ...CANARY_GRANT, allow: ['registry.npmjs.org'] }],
    ['a canary holding a route', { ...CANARY_GRANT, routes: [route(['git-fetch'])] }],
    ['an exec grant with no run', { ...GRANT, runId: undefined }],
    ['a publish grant with no agent', { ...PUBLISH_GRANT, agentId: undefined }],
    ['a container that is not the kernel\'s', { ...GRANT, sandbox: 'colima-trusted' }],
    ['a container name with a space after the prefix', { ...GRANT, sandbox: 'aos-run-a b' }],
    ['a route naming its header', { ...GRANT, routes: [{ ...route(['git-fetch']), header: 'authorization' }] }],
    ['a route with no profile', { ...GRANT, routes: [route([])] }],
    ['a route with an unknown profile', { ...GRANT, routes: [route(['git-clone'])] }],
    ['a route with no repository', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: [] }] }],
    ['an address in allow', { ...GRANT, allow: ['127.0.0.1'] }],
    ['an unknown purpose', { ...GRANT, purpose: 'fetch' }],
    // The bounds that keep the largest row inside the log, one past each.
    ['65 hosts', { ...GRANT, allow: Array.from({ length: 65 }, (_, i) => `h${String(i)}.example.com`) }],
    ['17 routes', { ...GRANT, routes: Array.from({ length: 17 }, (_, i) => routeOf(i)) }],
    ['65 repositories in one route', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: Array.from({ length: 65 }, (_, i) => `op/r${String(i)}`) }] }],
    ['a 254-character host', { ...GRANT, allow: [`${longHost(1)}x`] }],
    ['a 101-character repository name', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: [`op/${'n'.repeat(101)}`] }] }],
    // Names RepoSlug refuses, which EgressGrant therefore never holds.
    ['a repository named fixture.git', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: ['op/fixture.git'] }] }],
    ['a repository named .git', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: ['op/.git'] }] }],
    ['a repository named ..', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: ['op/..'] }] }],
    ['a repository named .', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: ['op/.'] }] }],
    ['a bound repository beside one named ..', { ...GRANT, routes: [{ ...route(['git-fetch']), repos: ['op/fixture', 'op/..'] }] }],
    ['a host with an underscore', { ...GRANT, allow: ['git_hub.com'] }],
    // Ids the kernel makes, never text with a separator in it.
    ['a grant id with a slash', { ...GRANT, grantId: 'g/1' }],
    ['a run id with a slash', { ...GRANT, runId: 'run/1' }],
    ['an agent id with a slash', { ...GRANT, agentId: 'coder/1' }],
    // EgressGrant's rules (policy.ts), which decide() denies a grant for as malformed.
    ['a host listed twice in allow', { ...GRANT, allow: ['registry.npmjs.org', 'registry.npmjs.org'] }],
    ['a binding routed twice', { ...GRANT, routes: [route(['git-fetch']), { ...route(['git-fetch']), host: 'gitlab.com', repos: ['op/other'] }] }],
    ['a host both credential-free and bound', { ...GRANT, allow: ['github.com'] }],
    ['a profile listed twice', { ...GRANT, routes: [route(['git-fetch', 'git-fetch'])] }],
    ['a repository on a host in two routes', { ...GRANT, routes: [route(['git-fetch']), { ...route(['git-fetch']), bindingId: 'github-two' }] }],
  ]
  for (const [what, grant] of refused) assert.equal(parses('proxy.grant.issued', defined(grant)), false, `${what} was recorded`)
  assert.equal(`${longHost(1)}x`.length, 254)
  // Four profiles are refused for their number, before any check of their
  // repetition: the bound holds whatever the rules beneath it say.
  const four = PAYLOAD_SCHEMAS['proxy.grant.issued'].safeParse({ ...PUBLISH_GRANT, routes: [route(['git-fetch', 'git-push', 'github-pulls', 'git-fetch'])] })
  assert.equal(four.success, false)
  assert.ok(
    !four.success && four.error.issues.some((i) => i.code === 'too_big' && i.path.join('.') === 'routes.0.profiles'),
    four.success ? '' : JSON.stringify(four.error.issues),
  )
})

test('a proxy.grant.revoked row carries totals unless recovered, names a limit only when one revoked it, and says what a violation broke', () => {
  const ok: ReadonlyArray<Record<string, unknown>> = [
    REVOKED,
    { ...REVOKED, reason: 'limit', limit: 'maxRequests' },
    { ...REVOKED, reason: 'violation', detail: 'the 17th open flow' },
    { schemaVersion: 1, grantId: 'grant_1', reason: 'recovered' },
    { ...REVOKED, totals: { ...TOTALS, requests: 0, allowed: 0, denied: 0 } },
    { ...REVOKED, totals: { ...TOTALS, requests: 5, allowed: 5, denied: 0, refused: 2, failed: 3 } },
  ]
  for (const row of ok) assert.equal(parses('proxy.grant.revoked', row), true, why('proxy.grant.revoked', row))
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['an ended grant with no totals', { ...REVOKED, totals: undefined }],
    ['a recovered grant claiming totals', { ...REVOKED, reason: 'recovered' }],
    ['a limit revocation naming no limit', { ...REVOKED, reason: 'limit' }],
    ['a limit named on an exit', { ...REVOKED, limit: 'maxBytes' }],
    ['an unknown limit', { ...REVOKED, reason: 'limit', limit: 'maxCookies' }],
    ['a violation that says nothing', { ...REVOKED, reason: 'violation' }],
    ['totals with an unknown count', { ...REVOKED, totals: { ...TOTALS, headerBytes: 1 } }],
    ['totals with no failed count', { ...REVOKED, totals: { ...TOTALS, failed: undefined } }],
    ['a negative total', { ...REVOKED, totals: { ...TOTALS, denied: -1 } }],
    ['a total that is no integer', { ...REVOKED, totals: { ...TOTALS, sentBytes: 0.5 } }],
    ['an unknown reason', { ...REVOKED, reason: 'expired' }],
    ['a grant id with a slash', { ...REVOKED, grantId: 'g/1' }],
    // The counts agree with each other.
    ['allowed and denied that are not the requests', { ...REVOKED, totals: { ...TOTALS, allowed: 5, denied: 5, refused: 0, requests: 0 } }],
    ['requests no verdict accounts for', { ...REVOKED, totals: { ...TOTALS, requests: 4 } }],
    ['more refused than allowed', { ...REVOKED, totals: { ...TOTALS, requests: 10, allowed: 5, denied: 5, refused: 9 } }],
    ['more failed than allowed', { ...REVOKED, totals: { ...TOTALS, failed: 3 } }],
    ['refused and failed past the allowed', { ...REVOKED, totals: { ...TOTALS, requests: 6, allowed: 5, denied: 1, refused: 3, failed: 3 } }],
    ['sums past the safe integers', { ...REVOKED, totals: { ...TOTALS, requests: Number.MAX_SAFE_INTEGER, allowed: Number.MAX_SAFE_INTEGER, denied: 2 } }],
  ]
  for (const [what, row] of refused) assert.equal(parses('proxy.grant.revoked', defined(row)), false, `${what} was recorded`)
})

test('an egress.degraded row names its check, the domain an image or canary check failed on, and the binding a binding check failed for', () => {
  const ok: ReadonlyArray<Record<string, unknown>> = [
    SAMPLES['egress.degraded'],
    ...EGRESS_VARIANTS.filter(([type]) => type === 'egress.degraded').map(([, payload]) => payload),
    { schemaVersion: 1, check: 'sandbox', domain: 'hostile', reason: 'the hostile VM has no image' },
  ]
  for (const row of ok) assert.equal(parses('egress.degraded', row), true, JSON.stringify(row))
  const refused: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a binding check naming no binding', { schemaVersion: 1, check: 'binding', reason: 'r' }],
    ['a binding named on another check', { schemaVersion: 1, check: 'config', bindingId: 'github', reason: 'r' }],
    ['an image check naming no domain', { schemaVersion: 1, check: 'image', reason: 'r' }],
    ['a canary check naming no domain', { schemaVersion: 1, check: 'canary', reason: 'r' }],
    ['a config check naming a domain', { schemaVersion: 1, check: 'config', domain: 'trusted', reason: 'r' }],
    ['a binding check naming a domain', { schemaVersion: 1, check: 'binding', bindingId: 'github', domain: 'trusted', reason: 'r' }],
    ['an unknown check', { schemaVersion: 1, check: 'firewall', reason: 'r' }],
    ['an empty reason', { schemaVersion: 1, check: 'config', reason: '' }],
  ]
  for (const [what, row] of refused) assert.equal(parses('egress.degraded', row), false, `${what} was recorded`)
})

test("the egress rows name src/egress's vocabulary exactly, and take a sample of the hosts and repositories it makes", () => {
  // Copied, not imported (types.ts says why); held equal here.
  assert.deepEqual([...PROXY_ALLOW_REASONS], [...ALLOW_REASONS])
  assert.deepEqual([...PROXY_DENY_REASONS], [...DENY_REASONS])
  // The upstream's refusals, then the session's own.
  assert.deepEqual([...PROXY_UPSTREAM_REFUSALS], [...UPSTREAM_REFUSALS, ...SESSION_REFUSALS])
  assert.deepEqual([...PROXY_REFUSALS_AFTER_SEND], [...UPSTREAM_REFUSALS_AFTER_SEND, ...SESSION_REFUSALS])
  assert.deepEqual([...PROXY_HOST_REFUSALS], [...HOST_REFUSALS])
  assert.deepEqual([...PROXY_ADDRESS_DENIALS], [...ADDRESS_DENIALS])
  assert.deepEqual([...PROXY_PROFILES], [...EGRESS_PROFILES])
  assert.equal(EGRESS_TARGET_MAX_BYTES, MAX_PATH)
  assert.equal(`${EGRESS_REF.source}/${EGRESS_REF.flags}`, `${RUN_REF.source}/${RUN_REF.flags}`)
  assert.equal(`${EGRESS_BINDING_ID.source}/${EGRESS_BINDING_ID.flags}`, `${BINDING_ID.source}/${BINDING_ID.flags}`)
  // A sample of what src/egress admits is never refused. The claim for every
  // EgressHost and RepoSlug rests on the shapes being at least as wide as
  // host.ts and routes.ts, which these cases sample at their edges.
  for (const raw of ['github.com', 'GitHub.COM.', 'xn--bcher-kva.example', 'a1.b2', '1password.com', 'x-y.z9', longHost(7)]) {
    const host = EgressHost.parse(raw)
    assert.equal(parses('proxy.decision', { ...ALLOW_ROW, host }), true, host)
    // No route, so that github.com is not bound as well as credential-free.
    assert.equal(parses('proxy.grant.issued', { ...GRANT, allow: [host], routes: [] }), true, host)
  }
  // A repository row refuses what RepoSlug refuses, in the one spelling a row holds (lower case).
  // The owner at its edges too: 39 characters taken, 40 refused, and one starting with anything but a letter or a digit refused.
  for (const raw of ['op/fixture', 'op/fixture.git', 'op/.git', 'op/..', 'op/.', 'op/...', 'op/.github', 'op/a.git-x', 'op/git', 'op/x.gi', '-op/x', 'op/x/y', 'op/', '/x', 'op', `${'o'.repeat(39)}/x`, `${'o'.repeat(40)}/x`, '_op/x', '.op/x', 'o_p/x', 'o.p/x']) {
    const route = { bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: [raw] }
    assert.equal(parses('proxy.grant.issued', { ...GRANT, routes: [route] }), RepoSlug.safeParse(raw).success, raw)
  }
  for (const raw of ['Op/Fixture', 'a/b', 'my-org/my_repo.js', 'x/.github', 'o1/-x', longRepo(3)]) {
    const repo = RepoSlug.parse(raw)
    // Its path as the worker spelled it: matchRoute reads the repository without case.
    const row = { ...ALLOW_ROW, repo, ...pathed(`/${raw}.git/info/refs`, 24) }
    assert.equal(parses('proxy.decision', row), true, `${repo}: ${why('proxy.decision', row)}`)
  }
})

test('the copies the egress rows hold of src/egress and the event log are held to their sources', () => {
  // upstream.ts passes on an error code of exactly the shape a row takes, so every one it passes on has a row's shape (one in a credential's shape is refused there too, and no node or OpenSSL code is one).
  assert.equal(`${EGRESS_ERROR_CODE.source}/${EGRESS_ERROR_CODE.flags}`, `${ERROR_CODE.source}/${ERROR_CODE.flags}`)
  assert.equal(EGRESS_REQUEST_TARGET_MAX_BYTES, MAX_TARGET)
  assert.equal(EGRESS_CENSOR, CENSOR)
  // The credential shapes an identifier is refused for are the ones the store censors, in its order.
  assert.deepEqual(EGRESS_TOKEN_PATTERNS.map(String), TOKEN_PATTERNS.map(String))
  assert.equal(Object.isFrozen(EGRESS_TOKEN_PATTERNS), true)
  // routes.ts SERVICE_QUERY, held through matchRoute: the service an info/refs
  // query names is the one a row of that profile records, and no query
  // matchRoute admits names a service the row refuses.
  const services = (PAYLOAD_SCHEMAS['proxy.decision'] as unknown as z.ZodObject).shape['service']
  assert.ok(services instanceof z.ZodOptional && services.unwrap() instanceof z.ZodEnum)
  const enumerated = (services.unwrap() as z.ZodEnum).options.map(String)
  const admitted: string[] = []
  for (const service of [...enumerated, 'git-upload-archive', 'GIT-UPLOAD-PACK', 'constructor', '__proto__', '']) {
    const match = matchRoute('GET', '/op/fixture.git/info/refs', `service=${service}`)
    if (!match.ok) continue
    admitted.push(service)
    for (const reason of PROXY_ALLOW_REASONS.filter((r) => r !== 'allow-host')) {
      const row = { ...ALLOW_ROW, reason, service, ...pathed('/op/fixture.git/info/refs', `?service=${service}`.length) }
      // github-pulls has no info/refs route; the row is refused for its path as for its service.
      assert.equal(parses('proxy.decision', row), reason === match.profile, `${reason} with ${service}: ${why('proxy.decision', row)}`)
    }
  }
  assert.deepEqual(admitted, enumerated)
})
