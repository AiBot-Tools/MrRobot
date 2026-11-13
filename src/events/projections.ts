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
// Delegation adds one more kind. A parent that delegated waits inside its
// `kernel.delegate` call for the child's outcome, and only then writes
// `delegation.result` and charges the child's spend to itself. A crash in that
// window leaves an admission with no result: the parent's accounting has a hole
// and the child's spend is charged to nobody. Recovery closes it the same way —
// a result row, from what the log says the child did — and an orphaned parent's
// bill counts every child it paid for, exactly as its live `run.finished` would.
//
// Egress adds another (egress plan W2). A grant is issued before its
// container starts and revoked once the kernel has a verdict on the container,
// and both rows are the kernel's: the grant table, like the session that
// serves it, lives in memory. A kernel that died between the two left a grant
// issued and never revoked, which reads as a reach the log never closed.
// Nothing can be served under it any more (the egress engine was in the dead
// process, and so was the container's one channel), so recovery closes it:
// `proxy.grant.revoked` with reason `recovered`, and no totals, since the
// counts died with the kernel that kept them (events/types.ts). A grant whose
// live revocation the store refused (src/egress/session.ts logs the failed
// append and ends the session all the same) reads the same, and is closed the
// same way at the next boot, by words that cover both (GRANT_RECOVERED_DETAIL).
//
// Idempotence is structural rather than bolted on: a run is open because it has
// no `run.finished` row, so once recovery writes one it is no longer open. The
// second restart finds nothing to do because the first one recorded what it
// did, in the same log, under the same rules. A grant likewise: it is open
// because it has no `proxy.grant.revoked` row.

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

/**
 * A delegation admitted and never given a result, with the result the log
 * supports.
 */
export interface DanglingDelegation {
  readonly parentRunId: string
  readonly childRunId: string
  /**
   * The child's own terminal status when it reached one before the crash, and
   * `error` when it did not — which is what recovery records for the child too.
   */
  readonly status: 'ok' | 'error' | 'killed' | 'denied'
  /** The child's spend, from its terminal row or counted from its rows. */
  readonly costMicroUsd: number
  /**
   * Fail closed. `clean` only when the log PROVES it: the child started clean,
   * executed no tool, and had no hold released. A `taints: true` tool on the
   * child's last turn leaves no row saying so before a crash, so anything short
   * of that proof is `tainted`.
   */
  readonly taint: 'clean' | 'tainted'
  readonly seq: number
}

/**
 * An egress grant issued and never revoked: its `proxy.grant.issued` row has no
 * `proxy.grant.revoked` row naming its id. Its run and agent are the issued
 * row's own columns (null for a canary grant, which serves no run).
 */
export interface OpenGrant {
  readonly grantId: string
  readonly runId: string | null
  readonly agentId: string | null
  /** The container the grant served, as its issued row names it: the boot sweep kills it by name. */
  readonly sandbox: string
  readonly seq: number
}

export interface Recovery {
  readonly orphanRuns: readonly OrphanRun[]
  readonly unresolvedApprovals: readonly UnresolvedApproval[]
  readonly unreleasedHolds: readonly UnreleasedHold[]
  readonly danglingDelegations: readonly DanglingDelegation[]
  readonly openGrants: readonly OpenGrant[]
}

/** True when a recovery has nothing to do. */
export function isClean(recovery: Recovery): boolean {
  return (
    recovery.orphanRuns.length === 0 &&
    recovery.unresolvedApprovals.length === 0 &&
    recovery.unreleasedHolds.length === 0 &&
    recovery.danglingDelegations.length === 0 &&
    recovery.openGrants.length === 0
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
  const grants = new Map<string, OpenGrant>()
  // Keyed by child run id. An admission leaves this map only on its result.
  const admitted = new Map<string, { parentRunId: string; seq: number }>()
  const finished = new Map<string, { status: string; costMicroUsd: number }>()
  // Evidence against a clean child, per run: a tool that executed, or a hold a
  // human released (D17). Kept for every run, since which ones are children is
  // known only once their admission is read.
  const startedTainted = new Set<string>()
  const touchedUntrusted = new Set<string>()

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
        if (stringAt(payload, 'taint') !== 'clean') startedTainted.add(runId)
        break
      }
      case 'run.finished': {
        // Terminal, however it got there — including a terminal row a previous
        // recovery wrote. This is what makes recovery idempotent.
        const runId = stringAt(payload, 'runId', row.runId ?? '')
        open.delete(runId)
        finished.set(runId, {
          status: stringAt(payload, 'status'),
          costMicroUsd: numberAt(payload, 'costMicroUsd'),
        })
        break
      }
      case 'delegation.admitted': {
        const childRunId = stringAt(payload, 'childRunId')
        if (childRunId === '') break
        admitted.set(childRunId, { parentRunId: stringAt(payload, 'parentRunId', row.runId ?? ''), seq: row.seq })
        break
      }
      case 'delegation.result': {
        admitted.delete(stringAt(payload, 'childRunId'))
        // The parent paid for this child: its live run.finished counts it, so an
        // orphaned parent's recovered bill has to as well.
        const run = row.runId === null ? undefined : open.get(row.runId)
        if (run !== undefined) run.costMicroUsd += numberAt(payload, 'costMicroUsd')
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
        // Every tool.result is a call the live run charged as a tool call,
        // one the loop denied after the gate among them (loop.ts
        // #deniedAfterGate), so this count is the live one. A denial's text
        // is the kernel's, not untrusted output; counting it as untrusted
        // input below fails safe.
        const run = row.runId === null ? undefined : open.get(row.runId)
        if (run !== undefined) run.toolCalls += 1
        if (row.runId !== null) touchedUntrusted.add(row.runId)
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
        if (row.runId !== null) touchedUntrusted.add(row.runId)
        holds.delete(stringAt(payload, 'holdId'))
        break
      case 'quarantine.abandoned': {
        holds.delete(stringAt(payload, 'holdId'))
        break
      }
      case 'proxy.grant.issued': {
        const grantId = stringAt(payload, 'grantId')
        if (grantId === '') break
        grants.set(grantId, { grantId, runId: row.runId, agentId: row.agentId, sandbox: stringAt(payload, 'sandbox'), seq: row.seq })
        break
      }
      case 'proxy.grant.revoked': {
        // Any reason closes it, a recovered one included: that is what makes
        // the second boot find nothing.
        grants.delete(stringAt(payload, 'grantId'))
        break
      }
      default:
        break
    }
  }

  const dangling: DanglingDelegation[] = []
  for (const [childRunId, admission] of admitted) {
    const done = finished.get(childRunId)
    const orphan = open.get(childRunId)
    const costMicroUsd = done?.costMicroUsd ?? orphan?.costMicroUsd ?? 0
    dangling.push({
      parentRunId: admission.parentRunId,
      childRunId,
      status: done === undefined ? 'error' : resultStatus(done.status),
      costMicroUsd,
      // A child admitted but never started has no run.started row to prove it
      // clean, and nothing to prove it tainted either; it ran nothing, so clean.
      taint:
        startedTainted.has(childRunId) || touchedUntrusted.has(childRunId) ? 'tainted' : 'clean',
      seq: admission.seq,
    })
    // The child's spend lands on the parent's bill here, because the result
    // row that would have carried it there is the one recovery is about to write.
    const parent = open.get(admission.parentRunId)
    if (parent !== undefined) parent.costMicroUsd += costMicroUsd
  }

  // Ordered by the log, so recovery writes its rows in the order the things it
  // is closing happened. An audit reads in one direction.
  return {
    orphanRuns: [...open.values()].sort((a, b) => a.lastSeq - b.lastSeq),
    unresolvedApprovals: [...approvals.values()].sort((a, b) => a.seq - b.seq),
    unreleasedHolds: [...holds.values()].sort((a, b) => a.seq - b.seq),
    danglingDelegations: dangling.sort((a, b) => a.seq - b.seq),
    openGrants: [...grants.values()].sort((a, b) => a.seq - b.seq),
  }
}

/**
 * Every run the log shows may have had a container: the run of each
 * `tool.call` to a sandbox tool (`sandbox.<name>`, which the runner appends
 * before it asks the driver for a container), of each `sandbox.started`, and
 * of each `proxy.grant.issued` that names one, in the order the log first
 * names them. Finished runs included, and that is the point: what the boot
 * sweep (egress plan W2) is to kill is a container of THIS log's that a VM
 * still runs, whichever kernel lost it (one that died, or one whose kill by
 * name no daemon answered), and a run's container is `aos-run-<runId>-<n>`.
 * A run another log names (another data directory's kernel, on the same VM)
 * is not here, so its containers are never this boot's to kill; nor is a
 * run started after these rows were read.
 */
export function sandboxRunIds(rows: readonly EventRow[]): string[] {
  const runs = new Set<string>()
  for (const row of rows) {
    if (row.runId === null) continue
    if (row.type === 'sandbox.started' || row.type === 'proxy.grant.issued') {
      runs.add(row.runId)
    } else if (row.type === 'tool.call' && stringAt(parse(row.payload), 'toolRef').startsWith('sandbox.')) {
      runs.add(row.runId)
    }
  }
  return [...runs]
}

/** A child's terminal status, as a delegation result can state it. */
function resultStatus(status: string): DanglingDelegation['status'] {
  return status === 'ok' || status === 'killed' || status === 'denied' ? status : 'error'
}
