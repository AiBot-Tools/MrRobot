// Event catalog — the 36 frozen event types and their payload schemas.
//
// Every payload is a strict zod object carrying `schemaVersion: 1`. Strict
// matters: an unknown key is either a caller bug or a drifted schema, and a
// hashed row is permanent, so it must be refused at the boundary rather than
// discovered later in an audit.
//
// Numbers are safe integers only, because the canonicalizer refuses anything
// else (no floats, no bigints). Money is integer micro-USD throughout (plan
// D4) and durations are integer milliseconds.
//
// Adding a type is decide-alone under CLAUDE.md, but the literal-equality
// test in test/events-types.test.ts must be updated in the same commit — that
// test is what keeps this list frozen rather than drifting silently.
//
// Payloads name ids, counts, hashes and decisions. Where a payload must carry
// free text that could contain a credential (an LLM prompt, a tool result),
// the store's redaction pass scrubs it; callers never redact by hand.

import { z } from 'zod'

const V = { schemaVersion: z.literal(1) }

const int = () => z.number().int()
const nonNegInt = () => z.number().int().nonnegative()

const SUBSYSTEMS = [
  'events',
  'control',
  'hub',
  'secrets',
  'sandbox',
  'router',
  'scheduler',
  'egress',
] as const

const RISK = ['read', 'write', 'irreversible'] as const
const TAINT = ['clean', 'tainted'] as const

// ── lifecycle ──────────────────────────────────────────────────────────────

/**
 * `degraded` is the set known degraded AT THIS INSTANT, which is empty by
 * construction: this event is appended before any subsystem is built, so that
 * it is the first row of every boot and a reader can find where a boot began.
 * The authority on what ended up degraded is the `subsystem.state` row per
 * subsystem that follows, and `status.get` live. The field is kept because a
 * future boot may know something is down before it starts.
 *
 * `configHash` is what makes two boots comparable: an operator reading the log
 * after a restart can tell whether the configuration changed under it without
 * the config itself — which holds hostnames and vault ids — ever entering the
 * log.
 */
export const KernelBootedPayload = z
  .object({ ...V, version: z.string(), configHash: z.string(), degraded: z.array(z.string()) })
  .strict()

export const KernelShutdownPayload = z
  .object({
    ...V,
    reason: z.enum(['requested', 'signal', 'error']),
    signal: z.string().optional(),
    uptimeMs: nonNegInt(),
  })
  .strict()

export const SubsystemStatePayload = z
  .object({
    ...V,
    subsystem: z.enum(SUBSYSTEMS),
    state: z.enum(['ok', 'degraded', 'absent']),
    reason: z.string().optional(),
  })
  .strict()

export const ChainAnchoredPayload = z
  .object({ ...V, seq: nonNegInt(), hash: z.string() })
  .strict()

// ── control plane ──────────────────────────────────────────────────────────

export const ControlConnectedPayload = z
  .object({ ...V, connectionId: z.string(), origin: z.string().optional() })
  .strict()

/** No token, ever — not even a prefix. The reason is the whole record. */
export const ControlRejectedPayload = z
  .object({
    ...V,
    reason: z.enum(['missing_token', 'bad_token', 'query_token', 'bad_origin', 'bad_upgrade']),
    origin: z.string().optional(),
  })
  .strict()

// ── subsystems ─────────────────────────────────────────────────────────────

export const HubConnectedPayload = z
  .object({ ...V, server: z.string(), toolCount: nonNegInt() })
  .strict()

export const HubDegradedPayload = z.object({ ...V, server: z.string(), reason: z.string() }).strict()

export const HubToolsClassifiedPayload = z
  .object({
    ...V,
    server: z.string(),
    exposed: nonNegInt(),
    kernelOnly: nonNegInt(),
    disabled: nonNegInt(),
    unclassified: z.array(z.string()),
  })
  .strict()

export const SandboxDegradedPayload = z
  .object({ ...V, driver: z.string(), reason: z.string() })
  .strict()

export const RouterDegradedPayload = z.object({ ...V, reason: z.string() }).strict()

export const SecretsDegradedPayload = z.object({ ...V, reason: z.string() }).strict()

// ── agents ─────────────────────────────────────────────────────────────────

export const AgentRegisteredPayload = z
  .object({
    ...V,
    agentId: z.string(),
    version: nonNegInt(),
    kind: z.enum(['standard', 'template', 'ephemeral']),
    role: z.string(),
    tier: nonNegInt(),
  })
  .strict()

export const AgentSpawnedPayload = z
  .object({
    ...V,
    agentId: z.string(),
    templateId: z.string(),
    parentRunId: z.string().optional(),
    tier: nonNegInt(),
  })
  .strict()

export const AgentSpawnRejectedPayload = z
  .object({ ...V, templateId: z.string(), reason: z.string() })
  .strict()

/** The CEO may only ask. Promotion itself is a human action. */
export const AgentPromotionRequestedPayload = z
  .object({ ...V, agentId: z.string(), requestedByRunId: z.string(), rationale: z.string() })
  .strict()

export const AgentPromotedPayload = z
  .object({
    ...V,
    agentId: z.string(),
    fromVersion: nonNegInt(),
    toVersion: nonNegInt(),
    byConnectionId: z.string(),
  })
  .strict()

export const AgentArchivedPayload = z
  .object({ ...V, agentId: z.string(), version: nonNegInt(), byConnectionId: z.string() })
  .strict()

// ── runs ───────────────────────────────────────────────────────────────────

export const RunQueuedPayload = z
  .object({ ...V, runId: z.string(), agentId: z.string(), lane: z.string(), goalId: z.string().optional() })
  .strict()

/**
 * The scheduler decided to fire an agent for a given minute.
 *
 * Written BEFORE the run is started, which is the point: it is the durable claim
 * on that minute. If starting then fails, the minute stays claimed and a restart
 * does not re-fire it — a job that cannot start must not be retried on every tick
 * and every reboot.
 *
 * It also answers "why did this run start?", which no other row does.
 */
export const RunScheduledPayload = z
  .object({ ...V, agentId: z.string(), schedule: z.string(), minute: z.string() })
  .strict()

export const RunStartedPayload = z
  .object({
    ...V,
    runId: z.string(),
    agentId: z.string(),
    lane: z.string(),
    tier: nonNegInt(),
    taint: z.enum(TAINT),
  })
  .strict()

export const RunParkedPayload = z
  .object({
    ...V,
    runId: z.string(),
    reason: z.enum(['approval', 'quarantine']),
    approvalId: z.string().optional(),
  })
  .strict()

export const RunResumedPayload = z.object({ ...V, runId: z.string(), parkedMs: nonNegInt() }).strict()

export const RunFinishedPayload = z
  .object({
    ...V,
    runId: z.string(),
    status: z.enum(['ok', 'error', 'killed', 'denied']),
    reason: z.string().optional(),
    costMicroUsd: nonNegInt(),
    llmCalls: nonNegInt(),
    toolCalls: nonNegInt(),
    durationMs: nonNegInt(),
  })
  .strict()

// ── model calls (invariant 4: two events, with prompt, content, tokens, cost)

export const LlmRequestPayload = z
  .object({
    ...V,
    ref: z.string(),
    attempt: nonNegInt(),
    prompt: z.string(),
    tools: z.array(z.string()),
    maxOutputTokens: nonNegInt().optional(),
  })
  .strict()

export const LlmResponsePayload = z
  .object({
    ...V,
    ref: z.string(),
    attempt: nonNegInt(),
    content: z.string(),
    finish: z.string(),
    inputTokens: nonNegInt(),
    outputTokens: nonNegInt(),
    cacheReadTokens: nonNegInt().optional(),
    cacheWriteTokens: nonNegInt().optional(),
    costMicroUsd: nonNegInt(),
    durationMs: nonNegInt(),
    error: z.string().optional(),
  })
  .strict()

// ── tools and the gate ─────────────────────────────────────────────────────

export const ToolGatePayload = z
  .object({
    ...V,
    toolRef: z.string(),
    decision: z.enum(['allow', 'needs-human', 'quarantine', 'deny']),
    reason: z.string(),
    risk: z.enum(RISK),
    taint: z.enum(TAINT),
  })
  .strict()

export const ToolCallPayload = z
  .object({
    ...V,
    ticketId: z.string(),
    toolRef: z.string(),
    argsHash: z.string(),
    quarantine: z.boolean(),
  })
  .strict()

/** Mirrors BoundedOutput: text is a prefix, sha256 covers the redacted whole. */
export const ToolResultPayload = z
  .object({
    ...V,
    ticketId: z.string(),
    toolRef: z.string(),
    ok: z.boolean(),
    text: z.string(),
    bytes: nonNegInt(),
    truncated: z.boolean(),
    sha256: z.string().optional(),
    durationMs: nonNegInt(),
  })
  .strict()

// ── human decisions ────────────────────────────────────────────────────────

export const ApprovalRequestedPayload = z
  .object({
    ...V,
    approvalId: z.string(),
    toolRef: z.string(),
    argsPreview: z.string(),
    risk: z.enum(RISK),
    expiresAt: z.string(),
  })
  .strict()

export const ApprovalResolvedPayload = z
  .object({
    ...V,
    approvalId: z.string(),
    decision: z.enum(['approved', 'denied', 'expired']),
    byConnectionId: z.string().optional(),
  })
  .strict()

export const QuarantineHeldPayload = z
  .object({ ...V, holdId: z.string(), toolRef: z.string(), reason: z.string() })
  .strict()

export const QuarantineReleasedPayload = z
  .object({ ...V, holdId: z.string(), byConnectionId: z.string() })
  .strict()

/**
 * A hold ended without a human ever seeing its content.
 *
 * Distinct from `quarantine.released` on purpose. That row carries a
 * `byConnectionId` and means a person reviewed the content and let the run have
 * it; writing one for a restart would put a false claim of human review into an
 * immutable audit log. Held content lives in memory only, so a crash destroys
 * it — the hold can therefore be ENDED but never released, and the log has to
 * be able to say which happened.
 */
export const QuarantineAbandonedPayload = z
  .object({ ...V, holdId: z.string(), reason: z.string() })
  .strict()

// ── sandboxes ──────────────────────────────────────────────────────────────

export const SandboxStartedPayload = z
  .object({
    ...V,
    sandboxId: z.string(),
    driver: z.string(),
    domain: z.string(),
    image: z.string(),
    memoryMb: nonNegInt(),
    pids: nonNegInt(),
    wallclockMs: nonNegInt(),
  })
  .strict()

export const SandboxKilledPayload = z
  .object({
    ...V,
    sandboxId: z.string(),
    reason: z.enum(['wallclock', 'requested', 'error', 'exited']),
    exitCode: int().optional(),
  })
  .strict()

// ── secrets and probes ─────────────────────────────────────────────────────

/** Never the value, never a digest of the value: an id, a purpose, a source. */
export const SecretAccessedPayload = z
  .object({ ...V, id: z.string(), purpose: z.string(), source: z.enum(['vault', 'env']) })
  .strict()

export const ProbeRecordedPayload = z
  .object({
    ...V,
    ref: z.string(),
    toolCalling: z.boolean(),
    toolChoiceForced: z.boolean().nullable(),
    latencyMs: nonNegInt().optional(),
    reason: z.string().optional(),
  })
  .strict()

// ── the frozen list ────────────────────────────────────────────────────────

export const EVENT_TYPES = [
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
] as const

export type EventType = (typeof EVENT_TYPES)[number]

export const PAYLOAD_SCHEMAS: Readonly<Record<EventType, z.ZodType>> = {
  'kernel.booted': KernelBootedPayload,
  'kernel.shutdown': KernelShutdownPayload,
  'subsystem.state': SubsystemStatePayload,
  'chain.anchored': ChainAnchoredPayload,
  'control.connected': ControlConnectedPayload,
  'control.rejected': ControlRejectedPayload,
  'hub.connected': HubConnectedPayload,
  'hub.degraded': HubDegradedPayload,
  'hub.tools.classified': HubToolsClassifiedPayload,
  'sandbox.degraded': SandboxDegradedPayload,
  'router.degraded': RouterDegradedPayload,
  'secrets.degraded': SecretsDegradedPayload,
  'agent.registered': AgentRegisteredPayload,
  'agent.spawned': AgentSpawnedPayload,
  'agent.spawn.rejected': AgentSpawnRejectedPayload,
  'agent.promotion.requested': AgentPromotionRequestedPayload,
  'agent.promoted': AgentPromotedPayload,
  'agent.archived': AgentArchivedPayload,
  'run.scheduled': RunScheduledPayload,
  'run.queued': RunQueuedPayload,
  'run.started': RunStartedPayload,
  'run.parked': RunParkedPayload,
  'run.resumed': RunResumedPayload,
  'run.finished': RunFinishedPayload,
  'llm.request': LlmRequestPayload,
  'llm.response': LlmResponsePayload,
  'tool.gate': ToolGatePayload,
  'tool.call': ToolCallPayload,
  'tool.result': ToolResultPayload,
  'approval.requested': ApprovalRequestedPayload,
  'approval.resolved': ApprovalResolvedPayload,
  'quarantine.held': QuarantineHeldPayload,
  'quarantine.released': QuarantineReleasedPayload,
  'quarantine.abandoned': QuarantineAbandonedPayload,
  'sandbox.started': SandboxStartedPayload,
  'sandbox.killed': SandboxKilledPayload,
  'secret.accessed': SecretAccessedPayload,
  'probe.recorded': ProbeRecordedPayload,
}

export function isEventType(t: string): t is EventType {
  return (EVENT_TYPES as readonly string[]).includes(t)
}
