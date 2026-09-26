// Building an Observation from the event log.
//
// The harness never asks a run how it went. It reopens the log READ-ONLY after
// the run has finished and reads the run's own slice — which is the only account
// that cannot be authored by the thing being measured. A reopen while the daemon
// holds the database is the same thing `verify-chain` and `search` already do.
//
// Every payload read here is parsed through the event schemas rather than cast.
// A scorer that silently read `undefined` out of a renamed field would report a
// clean run for a kernel that had stopped recording, and that failure looks
// exactly like success.

import { EventStore } from '../events/store.js'
import type { EventRow } from '../events/chain.js'
import {
  LlmResponsePayload,
  RunFinishedPayload,
  RunStartedPayload,
  ToolCallPayload,
  ToolGatePayload,
  ToolResultPayload,
} from '../events/types.js'
import type { Expectation, Observation } from './types.js'

export interface Finished {
  readonly status: 'ok' | 'error' | 'killed' | 'denied'
  readonly reason: string | undefined
  readonly costMicroUsd: number
  readonly llmCalls: number
  readonly toolCalls: number
  readonly durationMs: number
}

/** The run's `run.finished`, or undefined when the run never reached one. */
export function finishedOf(rows: readonly EventRow[]): Finished | undefined {
  const row = rows.find((r) => r.type === 'run.finished')
  if (row === undefined) return undefined
  const p = RunFinishedPayload.parse(JSON.parse(row.payload))
  return {
    status: p.status,
    reason: p.reason,
    costMicroUsd: p.costMicroUsd,
    llmCalls: p.llmCalls,
    toolCalls: p.toolCalls,
    durationMs: p.durationMs,
  }
}

export function startedOf(rows: readonly EventRow[]): { taint: string; tier: number } | undefined {
  const row = rows.find((r) => r.type === 'run.started')
  if (row === undefined) return undefined
  const p = RunStartedPayload.parse(JSON.parse(row.payload))
  return { taint: p.taint, tier: p.tier }
}

export interface LlmResponse {
  readonly seq: number
  readonly ref: string
  readonly attempt: number
  readonly content: string
  readonly costMicroUsd: number
}

export function llmResponses(rows: readonly EventRow[]): LlmResponse[] {
  return rows
    .filter((r) => r.type === 'llm.response')
    .map((r) => {
      const p = LlmResponsePayload.parse(JSON.parse(r.payload))
      return {
        seq: r.seq,
        ref: p.ref,
        attempt: p.attempt,
        content: p.content,
        costMicroUsd: p.costMicroUsd,
      }
    })
}

export interface Gate {
  readonly seq: number
  readonly toolRef: string
  readonly decision: 'allow' | 'needs-human' | 'quarantine' | 'deny'
}

export function gates(rows: readonly EventRow[]): Gate[] {
  return rows
    .filter((r) => r.type === 'tool.gate')
    .map((r) => {
      const p = ToolGatePayload.parse(JSON.parse(r.payload))
      return { seq: r.seq, toolRef: p.toolRef, decision: p.decision }
    })
}

export interface ToolCall {
  readonly seq: number
  readonly ticketId: string
  readonly toolRef: string
}

export function toolCalls(rows: readonly EventRow[]): ToolCall[] {
  return rows
    .filter((r) => r.type === 'tool.call')
    .map((r) => {
      const p = ToolCallPayload.parse(JSON.parse(r.payload))
      return { seq: r.seq, ticketId: p.ticketId, toolRef: p.toolRef }
    })
}

export interface ToolResult {
  readonly seq: number
  readonly ticketId: string
  readonly toolRef: string
  readonly ok: boolean
}

export function toolResults(rows: readonly EventRow[]): ToolResult[] {
  return rows
    .filter((r) => r.type === 'tool.result')
    .map((r) => {
      const p = ToolResultPayload.parse(JSON.parse(r.payload))
      return { seq: r.seq, ticketId: p.ticketId, toolRef: p.toolRef, ok: p.ok }
    })
}

/**
 * The model's last message.
 *
 * Named `claims` everywhere downstream, and returned from the LOG rather than
 * from the run's reply, so there is one account of what the model said and the
 * scorers read the same bytes the chain covers.
 */
export function claimsOf(rows: readonly EventRow[]): string {
  const responses = llmResponses(rows)
  return responses[responses.length - 1]?.content ?? ''
}

/** A run's slice of a log, read-only, in seq order. */
export function readRunRows(dbPath: string, runId: string): EventRow[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return store.query({ runId }).slice().sort((a, b) => a.seq - b.seq)
  } finally {
    store.close()
  }
}

/** Every row in a log, read-only. Used for facts outside one run's slice. */
export function readWholeLog(dbPath: string): EventRow[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return store.query().slice().sort((a, b) => a.seq - b.seq)
  } finally {
    store.close()
  }
}

export function observe(input: {
  readonly runId: string
  readonly agentId: string
  /** The run's own slice. */
  readonly rows: readonly EventRow[]
  /** Every row in the log. A claim about a CHILD run resolves outside the slice. */
  readonly log?: readonly EventRow[]
  readonly expect: Expectation
}): Observation {
  return {
    runId: input.runId,
    agentId: input.agentId,
    rows: input.rows,
    log: input.log ?? input.rows,
    claims: claimsOf(input.rows),
    expect: input.expect,
  }
}
