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

/**
 * The docker CLI's own failure status (src/runtime/sandbox-tools.ts
 * DOCKER_CLI_FAILED, held equal by test/egress-boot.test.ts): an exit that
 * says nothing of the container, which may run on.
 */
const CLI_FAILED = 125

/**
 * Every container started under no run that the log never saw end on its
 * own: the sandboxId of each `sandbox.started` row appended with no run
 * whose name no later `sandbox.killed` row names as an exit the driver saw,
 * in the order the log started them. A `sandbox.killed` row ends the name
 * only when it carries an exit code and that code is not the docker CLI's
 * own failure (125), and its reason is not `error`: a canary given up at
 * boot's bound, one whose result rejected, one whose docker client exited
 * 125 or with no status were each sent a kill by name that may never have
 * landed (a paused VM), so the container may still run, as a run's container
 * may after a live kernel's kill missed it, which the sweep names by its run
 * whatever its end said. The kernel starts a container under no run only
 * for boot's egress canaries (egress plan W3, src/runtime/canary.ts), one per
 * domain, each named uniquely to its boot, and records every one's end; one
 * with no such end is a canary a kernel that died during its boot left
 * running, or one whose end it did not see, which the next boot's sweep
 * kills by name (src/kernel.ts sweepTargets). The hostile domain's canary has
 * no grant, so this row is the one that names it.
 */
export function openRunlessSandboxes(rows: readonly EventRow[]): string[] {
  const open = new Set<string>()
  for (const row of rows) {
    if (row.runId !== null) continue
    if (row.type !== 'sandbox.started' && row.type !== 'sandbox.killed') continue
    const payload = parse(row.payload)
    const name = stringAt(payload, 'sandboxId')
    if (name === '') continue
    if (row.type === 'sandbox.started') {
      open.add(name)
      continue
    }
    const exitCode = payload['exitCode']
    const seen = stringAt(payload, 'reason') !== 'error' && typeof exitCode === 'number' && exitCode !== CLI_FAILED
    if (seen) open.delete(name)
  }
  return [...open]
}

/** A sandbox domain, as a closure row names it. */
export type ClosableDomain = 'trusted' | 'hostile'

/**
 * The domains the log holds closed to sandbox.exec, each with its closure
 * row's reason, in domain order (egress plan W3's review, round 3): what a
 * boot keeps closed unless a canary of its own passes there. A boot records
 * every domain it leaves closed as one `sandbox.degraded` row with `closes`,
 * before it marks its sandbox (its `subsystem.state` row of `sandbox`): a
 * domain its canary closed, and each one the log already held closed that no
 * canary of that boot's passed on (src/kernel.ts). So the last boot that
 * marked its sandbox recorded the whole set, and its closure rows are the
 * set it left: a domain it did not record, it reopened. A boot that ended
 * before its mark (a crash among its canaries) cannot have reopened
 * anything, so its closure rows only join the set before it. A boot that
 * never runs a canary (egress disabled, a probe or a sweep that failed)
 * therefore keeps every closure, and only a canary that passes on a domain
 * reopens it.
 */
export function closedSandboxDomains(rows: readonly EventRow[]): Partial<Record<ClosableDomain, string>> {
  let held = new Map<ClosableDomain, string>()
  // This boot's closure rows so far, from its kernel.booted to its mark.
  let boot: Map<ClosableDomain, string> | undefined
  for (const row of rows) {
    if (row.type === 'kernel.booted') {
      boot = new Map()
      continue
    }
    if (row.type === 'sandbox.degraded') {
      const payload = parse(row.payload)
      const domain = payload['closes']
      if (domain !== 'trusted' && domain !== 'hostile') continue
      const reason = stringAt(payload, 'reason', `${domain}: an earlier boot closed this domain to sandbox.exec, and its row gave no reason`)
      boot?.set(domain, reason)
      held.set(domain, reason)
      continue
    }
    if (row.type === 'subsystem.state' && boot !== undefined && stringAt(parse(row.payload), 'subsystem') === 'sandbox') {
      held = boot
      boot = undefined
    }
  }
  const closed: Partial<Record<ClosableDomain, string>> = {}
  for (const domain of ['trusted', 'hostile'] as const) {
    const reason = held.get(domain)
    if (reason !== undefined) closed[domain] = reason
  }
  return closed
}

/** A child's terminal status, as a delegation result can state it. */
function resultStatus(status: string): DanglingDelegation['status'] {
  return status === 'ok' || status === 'killed' || status === 'denied' ? status : 'error'
}
