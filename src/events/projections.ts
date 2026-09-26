// Crash recovery, projected from the log.
//
// A kernel that died mid-run leaves three kinds of unfinished business: runs
// that started and never finished, approvals nobody answered, and quarantine
// holds nobody released. The log is the only record of them — approvals and
// holds live in memory, and so does run state.
//
// This module answers ONE question: what was open when the process stopped? It
// is a pure function of the rows and writes nothing. Deciding what to do about
// the answer belongs to boot, which is the only thing allowed to append.
//
// What this is NOT is a resume. Two properties of the design make resuming
// impossible rather than merely unimplemented:
//
//   Held output is never written to the log. quarantine.ts makes that choice
//   deliberately — the record is what an audit needs, and the content is not
//   worth persisting at the cost of putting attacker-chosen text in the log
//   forever. So a rebuilt hold has nothing to release.
//
//   Run state is not persisted either. An approval rebuilt as "pending" would
//   belong to a run that no longer exists: approving it would mint a ticket
//   nothing can consume, and tell an operator they had unblocked work they had
//   not. Fail closed and say the run is over.
//
// So recovery TERMINATES what it finds. Every run reaches a terminal state,
// every approval reaches a decision, every hold reaches an end. That is what
// "a restart orphans nothing" means.
//
// Idempotence is structural rather than bolted on: a run is open because it has
// no `run.finished` row, so once recovery writes one it is no longer open. The
// second restart finds nothing to do because the first one recorded what it
// did, in the same log, under the same rules.

import type { EventRow } from './chain.js'

/** A run that started and never reached a terminal row. */
export interface OrphanRun {
  readonly runId: string
  readonly agentId: string | null
  readonly startedAt: string
  /** The last row seen for this run, which bounds how long it ran. */
  readonly lastTs: string
  readonly lastSeq: number
  /** Counted from the log, not guessed: the run really did spend this. */
  readonly llmCalls: number
  readonly toolCalls: number
  readonly costMicroUsd: number
}

/** An approval that was requested and never resolved. */
export interface UnresolvedApproval {
  readonly approvalId: string
  readonly runId: string | null
  readonly toolRef: string
  readonly risk: string
  readonly requestedAt: string
  readonly expiresAt: string
  readonly seq: number
}

/** A hold that was taken and never released or abandoned. */
export interface UnreleasedHold {
  readonly holdId: string
  readonly runId: string | null
  readonly toolRef: string
  readonly reason: string
  readonly heldAt: string
  readonly seq: number
}

export interface Recovery {
  readonly orphanRuns: readonly OrphanRun[]
  readonly unresolvedApprovals: readonly UnresolvedApproval[]
  readonly unreleasedHolds: readonly UnreleasedHold[]
}

/** True when a recovery has nothing to do. */
export function isClean(recovery: Recovery): boolean {
  return (
    recovery.orphanRuns.length === 0 &&
    recovery.unresolvedApprovals.length === 0 &&
    recovery.unreleasedHolds.length === 0
  )
}

interface OpenRun {
  readonly runId: string
  agentId: string | null
  startedAt: string
  lastTs: string
  lastSeq: number
  llmCalls: number
  toolCalls: number
  costMicroUsd: number
}

function parse(payload: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(payload)
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {}
  } catch {
    // A payload that will not parse is still a row, and its seq and type still
    // count. Whether the bytes are intact is verifyChain's story, and boot has
    // already refused if they are not.
    return {}
  }
}

function numberAt(payload: Record<string, unknown>, key: string): number {
  const value = payload[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function stringAt(payload: Record<string, unknown>, key: string, fallback = ''): string {
  const value = payload[key]
  return typeof value === 'string' ? value : fallback
}

/**
 * Replay the log and report what is still open.
 *
 * Pure: it reads rows and returns a description. Nothing here appends, and
 * nothing here decides — a projection that also wrote would make "what was
 * open" and "what we did about it" the same step, and the second restart could
 * not tell them apart.
 */
export function projectRecovery(rows: readonly EventRow[]): Recovery {
  const open = new Map<string, OpenRun>()
  const approvals = new Map<string, UnresolvedApproval>()
  const holds = new Map<string, UnreleasedHold>()

  for (const row of rows) {
    const payload = parse(row.payload)

    // Per-run counters, kept for every row the run owns rather than only the
    // ones below, so an orphan's reported duration covers everything it did.
    if (row.runId !== null) {
      const run = open.get(row.runId)
      if (run !== undefined) {
        run.lastTs = row.ts
        run.lastSeq = row.seq
        if (row.agentId !== null) run.agentId = row.agentId
      }
    }

    switch (row.type) {
      case 'run.started': {
        const runId = stringAt(payload, 'runId', row.runId ?? '')
        if (runId === '') break
        open.set(runId, {
          runId,
          agentId: row.agentId,
          startedAt: row.ts,
          lastTs: row.ts,
          lastSeq: row.seq,
          llmCalls: 0,
          toolCalls: 0,
          costMicroUsd: 0,
        })
        break
      }
      case 'run.finished': {
        // Terminal, however it got there — including a terminal row a previous
        // recovery wrote. This is what makes recovery idempotent.
        open.delete(stringAt(payload, 'runId', row.runId ?? ''))
        break
      }
      case 'llm.response': {
        const run = row.runId === null ? undefined : open.get(row.runId)
        if (run === undefined) break
        run.llmCalls += 1
        run.costMicroUsd += numberAt(payload, 'costMicroUsd')
        break
      }
      case 'tool.result': {
        const run = row.runId === null ? undefined : open.get(row.runId)
        if (run !== undefined) run.toolCalls += 1
        break
      }
      case 'approval.requested': {
        const approvalId = stringAt(payload, 'approvalId')
        if (approvalId === '') break
        approvals.set(approvalId, {
          approvalId,
          runId: row.runId,
          toolRef: stringAt(payload, 'toolRef'),
          risk: stringAt(payload, 'risk'),
          requestedAt: row.ts,
          expiresAt: stringAt(payload, 'expiresAt'),
          seq: row.seq,
        })
        break
      }
      case 'approval.resolved': {
        // Any decision closes it, expiry included.
        approvals.delete(stringAt(payload, 'approvalId'))
        break
      }
      case 'quarantine.held': {
        const holdId = stringAt(payload, 'holdId')
        if (holdId === '') break
        holds.set(holdId, {
          holdId,
          runId: row.runId,
          toolRef: stringAt(payload, 'toolRef'),
          reason: stringAt(payload, 'reason'),
          heldAt: row.ts,
          seq: row.seq,
        })
        break
      }
      case 'quarantine.released':
      case 'quarantine.abandoned': {
        holds.delete(stringAt(payload, 'holdId'))
        break
      }
      default:
        break
    }
  }

  // Ordered by the log, so recovery writes its rows in the order the things it
  // is closing happened. An audit reads in one direction.
  return {
    orphanRuns: [...open.values()].sort((a, b) => a.lastSeq - b.lastSeq),
    unresolvedApprovals: [...approvals.values()].sort((a, b) => a.seq - b.seq),
    unreleasedHolds: [...holds.values()].sort((a, b) => a.seq - b.seq),
  }
}
