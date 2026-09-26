// Control protocol v1 — FROZEN.
//
// This file is the contract between the kernel and every UI that will ever
// talk to it: the CLI now, a Tauri prototype in Phase 3, a SwiftUI app in
// Phase 5. CLAUDE.md change control puts it under ask-before, and the reason
// is not ceremony: a shipped UI parses these shapes, so a silent rename is a
// UI that breaks in the field with no version anywhere saying why. Changing
// anything here means a version bump and a migration note.
//
// Two structural rules do most of the security work, and both are asserted by
// literal equality rather than by inspection:
//
//   NO FRAME EVER CARRIES A CREDENTIAL. Authentication happens once, at the
//   HTTP upgrade, in a header (invariant 1). No command and no params field is
//   named token, auth or authorization, and a test walks every schema to keep
//   it that way. That matters beyond tidiness: D10 records that a browser
//   WebSocket cannot set Authorization, so a Phase 3 Tauri app must open the
//   socket from Rust — and if that turns out to be impossible, the amendment
//   is a connect ticket, which this freeze forces to be a VISIBLE v2 bump
//   rather than a quiet extra params field.
//
//   MONEY IS INTEGER MICRO-USD. Every result key matching /cost|usd|price/i is
//   an integer and ends in MicroUsd. A float dollar amount in a UI is a number
//   two implementations disagree about, and the log's costMicroUsd is frozen
//   into a hash chain.
//
// `EventEnvelope.type` is a plain string, deliberately. The event catalog will
// grow, and growing it must not be a protocol bump — a UI that does not know a
// type can still show its seq, timestamp and run.
//
// Deliberately absent, each a v2 bump: subscribe/filter, manifest or tool-view
// editing, any secrets or vault command, cron, goal-tree commands, egress
// views, pairing/channels, connect tickets.

import { z } from 'zod'

import { PROTOCOL_VERSION } from '../version.js'

export { PROTOCOL_VERSION }

// ── the frozen lists ───────────────────────────────────────────────────────

/** Every command v1 serves. Literal-equality tested; adding one is a bump. */
export const COMMANDS = [
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
] as const
export type Command = (typeof COMMANDS)[number]

export const ERROR_CODES = [
  'bad_request',
  'unknown_command',
  'not_found',
  'conflict',
  'forbidden',
  'not_implemented',
  'degraded',
  'payload_too_large',
  'internal',
] as const
export type ErrorCode = (typeof ERROR_CODES)[number]

export const RUN_STATUSES = ['queued', 'running', 'parked', 'finished'] as const
export const TAINTS = ['clean', 'tainted'] as const
export const SUBSYSTEMS = [
  'events',
  'control',
  'hub',
  'secrets',
  'sandbox',
  'router',
  'scheduler',
  'egress',
] as const

const int = (): z.ZodNumber => z.number().int()
const nonNegInt = (): z.ZodNumber => int().nonnegative()

// ── result schemas ─────────────────────────────────────────────────────────

export const RunSummary = z
  .object({
    runId: z.string(),
    agentId: z.string(),
    status: z.enum(RUN_STATUSES),
    taint: z.enum(TAINTS),
    startedAt: z.string().optional(),
    finishedAt: z.string().optional(),
    reason: z.string().optional(),
  })
  .strict()
export type RunSummary = z.output<typeof RunSummary>

export const RunDetail = RunSummary.extend({
  llmCalls: nonNegInt(),
  toolCalls: nonNegInt(),
  costMicroUsd: nonNegInt(),
  lastEventSeq: nonNegInt(),
}).strict()
export type RunDetail = z.output<typeof RunDetail>

/**
 * The id prefixes are load-bearing: the CLI dispatches `approve <id>` on them
 * rather than guessing, so a hold can never be routed to the approval path.
 */
export const ApprovalItem = z
  .object({
    approvalId: z.string().regex(/^apr_/),
    kind: z.enum(['tool', 'promotion']),
    runId: z.string().optional(),
    toolRef: z.string().optional(),
    argsHash: z.string().optional(),
    agentId: z.string().optional(),
    requestedAt: z.string(),
    expiresAt: z.string(),
  })
  .strict()
export type ApprovalItem = z.output<typeof ApprovalItem>

export const HoldItem = z
  .object({
    holdId: z.string().regex(/^hold_/),
    runId: z.string(),
    toolRef: z.string(),
    heldAt: z.string(),
  })
  .strict()
export type HoldItem = z.output<typeof HoldItem>

export const ApprovalsListResult = z
  .object({ approvals: z.array(ApprovalItem), holds: z.array(HoldItem) })
  .strict()
export type ApprovalsListResult = z.output<typeof ApprovalsListResult>

/**
 * The wire shape of a probe record. It carries no schemaVersion: that belongs
 * to the file on disk, which may migrate independently of the protocol.
 *
 * `toolChoiceForced` is always null in Phase 0 — nothing sends a forced tool
 * choice — but the field is frozen now so the Phase 1 forced pass needs no
 * bump. `costMicroUsd` is an integer: providers §8 shows a float `costUsd`,
 * superseded by D4.
 */
export const ProbeRecordResult = z
  .object({
    ref: z.string(),
    probedAt: nonNegInt(),
    modelIdSeen: z.string(),
    serverVersion: z.string().optional(),
    toolCalling: z.boolean(),
    toolChoiceForced: z.boolean().nullable(),
    finishSeen: z.string(),
    roundTrip: z.boolean(),
    usage: z.object({ input: nonNegInt(), output: nonNegInt() }).strict(),
    costMicroUsd: nonNegInt(),
    latencyMs: nonNegInt(),
    ttlHours: int().positive(),
    reason: z.string().optional(),
  })
  .strict()
export type ProbeRecordResult = z.output<typeof ProbeRecordResult>

export const ChainHead = z.object({ seq: nonNegInt(), hash: z.string() }).strict()

export const ChainVerifyResult = z.union([
  z.object({ ok: z.literal(true), count: nonNegInt(), head: ChainHead.nullable() }).strict(),
  z.object({ ok: z.literal(false), at: nonNegInt(), reason: z.string() }).strict(),
])
export type ChainVerifyResult = z.output<typeof ChainVerifyResult>

const SubsystemState = z
  .object({ state: z.enum(['ok', 'degraded', 'absent']), reason: z.string().optional() })
  .strict()

export const LaneStatus = z
  .object({ lane: z.string(), active: nonNegInt(), queued: nonNegInt(), cap: int().positive() })
  .strict()

export const StatusResult = z
  .object({
    kernel: z.object({ version: z.string(), bootedAt: z.string() }).strict(),
    state: z.enum(['ready', 'degraded']),
    subsystems: z
      .object({
        events: SubsystemState,
        control: SubsystemState,
        hub: SubsystemState,
        secrets: SubsystemState,
        sandbox: SubsystemState,
        router: SubsystemState,
        scheduler: SubsystemState,
        egress: SubsystemState,
      })
      .strict(),
    chainHead: ChainHead.nullable(),
    lanes: z.array(LaneStatus),
    /** Surfaced because D8 keeps the kernel degraded while it is on. */
    envFallback: z.boolean(),
  })
  .strict()
export type StatusResult = z.output<typeof StatusResult>

/** Never an auth header name, never an env var name (invariant 2). */
export const AgentSummary = z
  .object({
    id: z.string(),
    version: nonNegInt(),
    kind: z.enum(['standard', 'template', 'ephemeral']),
    role: z.string(),
    tier: nonNegInt(),
    status: z.enum(['active', 'archived']),
    modelPrimary: z.string(),
  })
  .strict()
export type AgentSummary = z.output<typeof AgentSummary>

export const ModelSummary = z
  .object({
    ref: z.string(),
    dialect: z.enum(['anthropic', 'openai-chat']),
    placeholder: z.boolean(),
    local: z.boolean(),
    probe: ProbeRecordResult.optional(),
    routable: z.boolean(),
    orchestrator: z.boolean(),
  })
  .strict()
export type ModelSummary = z.output<typeof ModelSummary>

/** `type` is a string, not an enum: the catalog grows without a bump. */
export const EventEnvelope = z
  .object({
    seq: nonNegInt(),
    id: z.string(),
    ts: z.string(),
    type: z.string(),
    runId: z.string().optional(),
    agentId: z.string().optional(),
    payload: z.unknown(),
    prevHash: z.string(),
    hash: z.string(),
  })
  .strict()
export type EventEnvelope = z.output<typeof EventEnvelope>

// ── per-command params and results ──────────────────────────────────────────

const Empty = z.object({}).strict()

export const COMMAND_SCHEMAS: Readonly<Record<Command, { params: z.ZodType; result: z.ZodType }>> = {
  'status.get': { params: Empty, result: StatusResult },
  'agents.list': {
    params: z.object({ includeArchived: z.boolean().optional() }).strict(),
    result: z.array(AgentSummary),
  },
  // Invariant 6: exactly one command promotes, and it takes a human's
  // approval id rather than an agent id, so a promotion cannot be requested
  // and granted by the same actor.
  'agent.promote': {
    params: z.object({ approvalId: z.string().regex(/^apr_/) }).strict(),
    result: z.object({ agentId: z.string(), kind: z.literal('standard') }).strict(),
  },
  'agent.archive': {
    params: z.object({ agentId: z.string(), reason: z.string().optional() }).strict(),
    result: z.object({ agentId: z.string(), status: z.literal('archived') }).strict(),
  },
  'run.start': {
    params: z
      .object({
        agentId: z.string(),
        input: z.string().max(65_536),
        /** Recorded now so Phase 1's goal tree needs no bump. */
        goalId: z.string().optional(),
        taint: z.enum(TAINTS).optional(),
      })
      .strict(),
    result: z.object({ runId: z.string() }).strict(),
  },
  'run.kill': {
    params: z.object({ runId: z.string(), reason: z.string().optional() }).strict(),
    result: z.object({ runId: z.string(), status: z.enum(RUN_STATUSES) }).strict(),
  },
  'runs.list': {
    params: z
      .object({ status: z.enum(RUN_STATUSES).optional(), limit: int().positive().max(200).optional() })
      .strict(),
    result: z.array(RunSummary),
  },
  'run.get': { params: z.object({ runId: z.string() }).strict(), result: RunDetail },
  'approvals.list': { params: Empty, result: ApprovalsListResult },
  // Kind `tool` only. A promotion presented here is bad_request with
  // 'use agent.promote', so exactly one command can promote.
  'approval.approve': {
    params: z.object({ approvalId: z.string().regex(/^apr_/) }).strict(),
    result: z.object({ approvalId: z.string(), resolved: z.literal(true) }).strict(),
  },
  'approval.deny': {
    params: z.object({ approvalId: z.string().regex(/^apr_/), reason: z.string().optional() }).strict(),
    result: z.object({ approvalId: z.string(), resolved: z.literal(true) }).strict(),
  },
  'quarantine.release': {
    params: z.object({ holdId: z.string().regex(/^hold_/) }).strict(),
    result: z
      .object({ holdId: z.string(), released: z.literal(true), runTainted: z.literal(true) })
      .strict(),
  },
  'events.query': {
    params: z
      .object({
        afterSeq: nonNegInt().optional(),
        limit: int().positive().max(1_000).optional(),
        types: z.array(z.string()).optional(),
        runId: z.string().optional(),
        text: z.string().optional(),
      })
      .strict(),
    result: z.array(EventEnvelope),
  },
  'chain.verify': { params: Empty, result: ChainVerifyResult },
  'models.list': { params: Empty, result: z.array(ModelSummary) },
  'model.probe': { params: z.object({ ref: z.string() }).strict(), result: ProbeRecordResult },
}

// ── envelopes ──────────────────────────────────────────────────────────────

export const CmdFrame = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    id: z.string().min(1),
    cmd: z.enum(COMMANDS),
    params: z.record(z.string(), z.unknown()).default({}),
  })
  .strict()
export type CmdFrame = z.output<typeof CmdFrame>

export const ProtocolError = z
  .object({ code: z.enum(ERROR_CODES), message: z.string() })
  .strict()
export type ProtocolError = z.output<typeof ProtocolError>

export const ReplyFrame = z.union([
  z.object({ v: z.literal(PROTOCOL_VERSION), id: z.string(), ok: z.literal(true), result: z.unknown() }).strict(),
  z
    .object({ v: z.literal(PROTOCOL_VERSION), id: z.string(), ok: z.literal(false), error: ProtocolError })
    .strict(),
])
export type ReplyFrame = z.output<typeof ReplyFrame>

export const HelloFrame = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    protocol: z.literal(PROTOCOL_VERSION),
    kernel: z.object({ version: z.string() }).strict(),
    status: StatusResult,
  })
  .strict()
export type HelloFrame = z.output<typeof HelloFrame>

export const EventFrame = z
  .object({ v: z.literal(PROTOCOL_VERSION), event: EventEnvelope })
  .strict()
export type EventFrame = z.output<typeof EventFrame>

// ── frame parsing ──────────────────────────────────────────────────────────

export type ParsedFrame =
  | { readonly ok: true; readonly frame: CmdFrame }
  | { readonly ok: false; readonly code: ErrorCode; readonly message: string; readonly id?: string }

/**
 * Parse one client frame from raw bytes.
 *
 * The size check comes BEFORE JSON.parse, and it measures BYTES rather than
 * characters. Parsing first would mean a hostile frame gets a full parse of
 * whatever it sent before being rejected, and `String.length` undercounts
 * multi-byte UTF-8 — a 1 MB limit measured in characters admits up to 4 MB.
 *
 * Pure, so the limit is testable without a socket. The transport enforces its
 * own hard ceiling at twice this (T29); anything between the two gets this
 * reply, anything above gets closed.
 */
export function parseFrame(bytes: Uint8Array | string, maxPayloadBytes: number): ParsedFrame {
  const size = typeof bytes === 'string' ? Buffer.byteLength(bytes, 'utf8') : bytes.byteLength
  if (size > maxPayloadBytes) {
    return {
      ok: false,
      code: 'payload_too_large',
      message: `frame is ${String(size)} bytes, over the ${String(maxPayloadBytes)} byte limit`,
    }
  }

  let json: unknown
  try {
    json = JSON.parse(typeof bytes === 'string' ? bytes : Buffer.from(bytes).toString('utf8'))
  } catch {
    return { ok: false, code: 'bad_request', message: 'frame is not valid JSON' }
  }

  const parsed = CmdFrame.safeParse(json)
  if (parsed.success) return { ok: true, frame: parsed.data }

  // An id, when the frame carried a usable one, so a client can correlate the
  // rejection with the request it sent.
  const id =
    typeof json === 'object' && json !== null && typeof (json as { id?: unknown }).id === 'string'
      ? (json as { id: string }).id
      : undefined

  const unknownCmd =
    typeof json === 'object' &&
    json !== null &&
    typeof (json as { cmd?: unknown }).cmd === 'string' &&
    !(COMMANDS as readonly string[]).includes((json as { cmd: string }).cmd)

  return {
    ok: false,
    code: unknownCmd ? 'unknown_command' : 'bad_request',
    message: parsed.error.message,
    ...(id === undefined ? {} : { id }),
  }
}
