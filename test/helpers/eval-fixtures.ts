// Synthetic observations for testing the check library.
//
// The scorers have to be testable without a kernel: a check that only ever meets
// well-formed logs is a check nobody has seen refuse anything. These builders
// make event rows by hand — including the four cheat shapes
// docs/design/sectors/executive.md §8.1 names, which are the failures a real
// orchestrator produces and the ones an operator cannot spot by reading the
// summary.
//
// The rows are not hashed or chained: they are inputs to a pure scorer, not a
// log. A test that needs a real chain uses a real kernel (eval-harness.test.ts).

import './guard.js'

import type { EventRow } from '../../src/events/chain.js'
import { observe } from '../../src/eval/observe.js'
import type { Expectation, Observation } from '../../src/eval/types.js'

let seq = 0

export function resetSeq(): void {
  seq = 0
}

export function row(
  type: string,
  payload: Record<string, unknown>,
  runId: string | null = 'run_parent',
): EventRow {
  seq += 1
  return {
    seq,
    id: `evt_${String(seq)}`,
    ts: new Date(1_700_000_000_000 + seq * 1_000).toISOString(),
    type,
    runId,
    agentId: runId === null ? null : 'ceo',
    payload: JSON.stringify({ schemaVersion: 1, ...payload }),
    prevHash: 'x'.repeat(64),
    hash: 'y'.repeat(64),
  }
}

export interface RunShape {
  readonly runId?: string
  readonly agentId?: string
  readonly llm?: readonly { cost: number; content: string }[]
  readonly tools?: readonly {
    readonly toolRef: string
    readonly decision?: 'allow' | 'needs-human' | 'quarantine' | 'deny'
    /** Call it anyway, whatever the gate said. */
    readonly callAnyway?: boolean
    readonly ok?: boolean
  }[]
  readonly approvals?: number
  readonly status?: 'ok' | 'error' | 'killed' | 'denied'
  /** Override the cost run.finished reports, to contradict the log. */
  readonly reportedCost?: number
  readonly finish?: boolean
}

/** A parent run's rows: started → calls → finished. */
export function parentRun(shape: RunShape = {}): EventRow[] {
  const runId = shape.runId ?? 'run_parent'
  const rows: EventRow[] = [
    row('run.queued', { runId, agentId: shape.agentId ?? 'ceo', lane: 'main' }, runId),
    row(
      'run.started',
      { runId, agentId: shape.agentId ?? 'ceo', lane: 'main', tier: 2, taint: 'clean' },
      runId,
    ),
  ]
  const llm = shape.llm ?? [{ cost: 1_000, content: 'done' }]
  for (const [i, call] of llm.entries()) {
    rows.push(
      row('llm.request', { ref: 'anthropic/x', attempt: 0, prompt: `turn ${String(i)}`, tools: [] }, runId),
      row(
        'llm.response',
        {
          ref: 'anthropic/x',
          attempt: 0,
          content: call.content,
          finish: 'end_turn',
          inputTokens: 10,
          outputTokens: 10,
          costMicroUsd: call.cost,
          durationMs: 5,
        },
        runId,
      ),
    )
  }
  let toolCalls = 0
  for (const tool of shape.tools ?? []) {
    const decision = tool.decision ?? 'allow'
    rows.push(
      row(
        'tool.gate',
        { toolRef: tool.toolRef, decision, reason: 'fixture', risk: 'read', taint: 'clean' },
        runId,
      ),
    )
    if (decision === 'allow' || tool.callAnyway === true) {
      toolCalls += 1
      rows.push(
        row(
          'tool.call',
          { ticketId: `tkt_${String(toolCalls)}`, toolRef: tool.toolRef, argsHash: 'a'.repeat(64), quarantine: false },
          runId,
        ),
        row(
          'tool.result',
          {
            ticketId: `tkt_${String(toolCalls)}`,
            toolRef: tool.toolRef,
            ok: tool.ok ?? true,
            text: 'fixture output',
            bytes: 14,
            truncated: false,
            durationMs: 1,
          },
          runId,
        ),
      )
    }
  }
  for (let i = 0; i < (shape.approvals ?? 0); i += 1) {
    rows.push(
      row(
        'approval.requested',
        {
          approvalId: `apr_${String(i)}`,
          toolRef: 'pmmcp.admin',
          argsPreview: 'fixture',
          risk: 'irreversible',
          expiresAt: new Date(1_700_000_600_000).toISOString(),
        },
        runId,
      ),
    )
  }
  if (shape.finish !== false) {
    const logged = llm.reduce((total, c) => total + c.cost, 0)
    rows.push(
      row(
        'run.finished',
        {
          runId,
          status: shape.status ?? 'ok',
          costMicroUsd: shape.reportedCost ?? logged,
          llmCalls: llm.length,
          toolCalls,
          durationMs: 10,
        },
        runId,
      ),
    )
  }
  return rows
}

/** A child run's rows, for the delegation-shaped checks. */
export function childRun(runId: string, agentId: string, withGoalId = false): EventRow[] {
  return [
    // goalId lives on run.queued in the event schema, not on run.started.
    row(
      'run.queued',
      { runId, agentId, lane: 'subagent', ...(withGoalId ? { goalId: 'goal-1' } : {}) },
      runId,
    ),
    row('run.started', { runId, agentId, lane: 'subagent', tier: 1, taint: 'clean' }, runId),
    row(
      'run.finished',
      { runId, status: 'ok', costMicroUsd: 500, llmCalls: 1, toolCalls: 0, durationMs: 5 },
      runId,
    ),
  ]
}

/**
 * Splice child rows INSIDE the parent's window, which is how the harness
 * recognises a child at all: the parent's run.finished must come last.
 */
export function withChildren(parent: EventRow[], children: EventRow[][]): EventRow[] {
  const finished = parent[parent.length - 1]
  const head = parent.slice(0, -1)
  const all = [...head, ...children.flat(), ...(finished === undefined ? [] : [finished])]
  // Re-seq so ordering is by position, which is what the window test reads.
  return all.map((r, i) => ({ ...r, seq: i + 1 }))
}

export function observationOf(rows: EventRow[], expect: Expectation, runId = 'run_parent'): Observation {
  const own = rows.filter((r) => r.runId === runId)
  return observe({ runId, agentId: 'ceo', rows: own, log: rows, expect })
}
