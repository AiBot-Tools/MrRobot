// Control-plane views — pure projections onto the frozen protocol shapes.
//
// Pure and JSON-serialisable, with no method that reaches back into kernel
// state. That is what keeps the shell honest about holding nothing: a view is
// a snapshot the UI can render, not a handle it can act through. Every function
// here takes plain data and returns plain data, so a view cannot leak a client,
// a store, a secret ref or a closure over any of them.
//
// Two things are deliberately dropped on the way out:
//
//   A probe record's `schemaVersion`, which belongs to the file on disk and may
//   migrate independently of the wire.
//
//   Everything about an agent except the seven fields AgentSummary names. A
//   manifest carries a model binding, tool allowances and an egress list;
//   none of that is a UI's business, and an auth header name or env var name
//   leaving the kernel would be invariant 2 undone by a convenience.

import { VERSION } from '../version.js'
import type { EventRow } from '../events/chain.js'
import type { ProbeRecord, ModelCard } from '../models/registry.js'
import { routable } from '../models/registry.js'
import type { LaneDiagnostics } from '../runtime/lanes.js'
import type {
  AgentSummary,
  ApprovalItem,
  ApprovalsListResult,
  ChainVerifyResult,
  EventEnvelope,
  HoldItem,
  ModelSummary,
  ProbeRecordResult,
  RunDetail,
  RunSummary,
  StatusResult,
} from './protocol.js'

// ── events ─────────────────────────────────────────────────────────────────

export function eventView(row: EventRow): EventEnvelope {
  let payload: unknown
  try {
    payload = JSON.parse(row.payload)
  } catch {
    // The stored bytes are canonical JSON by construction; if they are not,
    // the chain is broken and that is chain.verify's story, not this one's.
    payload = null
  }
  return {
    seq: row.seq,
    id: row.id,
    ts: row.ts,
    type: row.type,
    ...(row.runId === null ? {} : { runId: row.runId }),
    ...(row.agentId === null ? {} : { agentId: row.agentId }),
    payload,
    prevHash: row.prevHash,
    hash: row.hash,
  }
}

// ── runs ───────────────────────────────────────────────────────────────────

export interface RunState {
  readonly runId: string
  readonly agentId: string
  readonly status: RunSummary['status']
  readonly taint: RunSummary['taint']
  readonly startedAt?: string | undefined
  readonly finishedAt?: string | undefined
  readonly reason?: string | undefined
  readonly llmCalls: number
  readonly toolCalls: number
  readonly costMicroUsd: number
  readonly lastEventSeq: number
}

export function runSummaryView(run: RunState): RunSummary {
  return {
    runId: run.runId,
    agentId: run.agentId,
    status: run.status,
    taint: run.taint,
    ...(run.startedAt === undefined ? {} : { startedAt: run.startedAt }),
    ...(run.finishedAt === undefined ? {} : { finishedAt: run.finishedAt }),
    ...(run.reason === undefined ? {} : { reason: run.reason }),
  }
}

export function runDetailView(run: RunState): RunDetail {
  return {
    ...runSummaryView(run),
    llmCalls: run.llmCalls,
    toolCalls: run.toolCalls,
    costMicroUsd: run.costMicroUsd,
    lastEventSeq: run.lastEventSeq,
  }
}

// ── approvals and holds ────────────────────────────────────────────────────

export interface ApprovalSource {
  readonly approvalId: string
  readonly kind: 'tool' | 'promotion'
  readonly runId?: string | undefined
  readonly toolRef?: string | undefined
  readonly argsHash?: string | undefined
  readonly agentId?: string | undefined
  readonly requestedAt: number
  readonly expiresAt: number
}

export interface HoldSource {
  readonly holdId: string
  readonly runId: string
  readonly toolRef: string
  readonly heldAt: number
}

/**
 * A `tool` approval carries run/tool/args; a `promotion` carries an agent.
 * Emitting the fields of the other kind would invite a UI to render an empty
 * "tool" row for a promotion and a human to approve the wrong thing.
 */
export function approvalItemView(source: ApprovalSource): ApprovalItem {
  const base = {
    approvalId: source.approvalId,
    kind: source.kind,
    requestedAt: new Date(source.requestedAt).toISOString(),
    expiresAt: new Date(source.expiresAt).toISOString(),
  }
  if (source.kind === 'promotion') {
    return { ...base, ...(source.agentId === undefined ? {} : { agentId: source.agentId }) }
  }
  return {
    ...base,
    ...(source.runId === undefined ? {} : { runId: source.runId }),
    ...(source.toolRef === undefined ? {} : { toolRef: source.toolRef }),
    ...(source.argsHash === undefined ? {} : { argsHash: source.argsHash }),
  }
}

export function holdItemView(source: HoldSource): HoldItem {
  return {
    holdId: source.holdId,
    runId: source.runId,
    toolRef: source.toolRef,
    heldAt: new Date(source.heldAt).toISOString(),
  }
}

export function approvalsListView(
  approvals: readonly ApprovalSource[],
  holds: readonly HoldSource[],
): ApprovalsListResult {
  // Two typed arrays, never one mixed list: a UI that had to sniff a prefix to
  // know which button to show would eventually show the wrong one.
  return { approvals: approvals.map(approvalItemView), holds: holds.map(holdItemView) }
}

// ── models ─────────────────────────────────────────────────────────────────

/** Drops schemaVersion: the wire shape and the file shape migrate apart. */
export function probeView(record: ProbeRecord): ProbeRecordResult {
  return {
    ref: record.ref,
    probedAt: record.probedAt,
    modelIdSeen: record.modelIdSeen,
    ...(record.serverVersion === undefined ? {} : { serverVersion: record.serverVersion }),
    toolCalling: record.toolCalling,
    toolChoiceForced: record.toolChoiceForced,
    finishSeen: record.finishSeen,
    roundTrip: record.roundTrip,
    usage: { input: record.usage.input, output: record.usage.output },
    costMicroUsd: record.costMicroUsd,
    latencyMs: record.latencyMs,
    ttlHours: record.ttlHours,
    ...(record.reason === undefined ? {} : { reason: record.reason }),
  }
}

export function modelSummaryView(
  ref: string,
  card: ModelCard,
  probe: ProbeRecord | undefined,
  now: number,
): ModelSummary {
  // No baseUrl, no path, no headers and above all no auth block: a UI has no
  // use for where a credential comes from, and naming the env var would be
  // half of finding it.
  return {
    ref,
    dialect: card.dialect,
    placeholder: card.placeholder,
    local: card.local,
    ...(probe === undefined ? {} : { probe: probeView(probe) }),
    routable: routable(card, probe, now),
    orchestrator: card.orchestrator,
  }
}

// ── agents ─────────────────────────────────────────────────────────────────

export interface AgentSource {
  readonly id: string
  readonly version: number
  readonly kind: AgentSummary['kind']
  readonly role: string
  readonly tier: number
  readonly status: AgentSummary['status']
  readonly modelPrimary: string
}

export function agentSummaryView(source: AgentSource): AgentSummary {
  return {
    id: source.id,
    version: source.version,
    kind: source.kind,
    role: source.role,
    tier: source.tier,
    status: source.status,
    modelPrimary: source.modelPrimary,
  }
}

// ── chain and status ───────────────────────────────────────────────────────

export type VerifyOutcome =
  | { readonly ok: true; readonly count: number; readonly head: string }
  | { readonly ok: false; readonly at: number; readonly reason: string }

export function chainVerifyView(outcome: VerifyOutcome, headSeq: number): ChainVerifyResult {
  if (!outcome.ok) return { ok: false, at: outcome.at, reason: outcome.reason }
  return {
    ok: true,
    count: outcome.count,
    head: outcome.count === 0 ? null : { seq: headSeq, hash: outcome.head },
  }
}

export interface StatusSource {
  readonly bootedAt: string
  readonly subsystems: StatusResult['subsystems']
  readonly chainHead: { seq: number; hash: string } | null
  readonly lanes: LaneDiagnostics
  readonly envFallback: boolean
}

export function statusView(source: StatusSource): StatusResult {
  const states = Object.values(source.subsystems).map((s) => s.state)
  // One degraded subsystem degrades the kernel. Reporting 'ready' while the
  // vault is unreachable would be the status line lying about the thing an
  // operator most needs to know.
  const state = states.some((s) => s !== 'ok') ? 'degraded' : 'ready'

  return {
    kernel: { version: VERSION, bootedAt: source.bootedAt },
    state,
    subsystems: source.subsystems,
    chainHead: source.chainHead,
    lanes: [
      { lane: 'main', ...source.lanes.lanes.main },
      { lane: 'subagent', ...source.lanes.lanes.subagent },
    ],
    envFallback: source.envFallback,
  }
}
