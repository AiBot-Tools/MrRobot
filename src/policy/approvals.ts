// Human approvals.
//
// When the gate says needs-human, the call stops here until a person decides.
// Three properties make this safe rather than decorative:
//
//   Bound. An approval is tied to (runId, toolRef, argsHash). Approving
//   "merge pull request 7" does not approve "merge pull request 9", and a
//   ticket minted from it is only valid for the exact arguments shown.
//
//   Fail closed. If nobody answers before the timeout, the request is DENIED
//   and recorded as expired. Waiting forever would turn a stalled approval
//   into a wedged run; defaulting to allow would turn operator inattention
//   into consent.
//
//   Human only. resolve() takes a HumanActor, which cannot be forged. A model
//   that talks kernel code into calling resolve gets a TypeError.
//
// Phase 0 keeps pending approvals in memory. Restart-safe projections rebuilt
// from the log are Phase 1, and rebuildFromLog() throws rather than silently
// returning an empty set — a projection that quietly claims "no approvals
// pending" after a restart would be worse than one that admits it is absent.

import { randomUUID } from 'node:crypto'

import { assertHumanActor, type HumanActor } from '../control/actor.js'
import { NotImplementedError, PolicyDenied } from '../errors.js'

export type ApprovalDecision = 'approved' | 'denied' | 'expired'

/**
 * What a human is being asked to decide.
 *
 * `kind` is not decoration. Protocol v1 gives promotions their own command
 * (`agent.promote`) so that exactly one call can promote an agent (invariant
 * 6), and the dispatcher needs to know which kind it is holding to refuse a
 * promotion presented to `approval.approve`. A `tool` request carries
 * runId/toolRef/argsHash; a `promotion` carries agentId.
 *
 * The id is prefixed `apr_` so the CLI can dispatch on it without guessing,
 * and can never route a quarantine hold (`hold_…`) down the approval path.
 */
export interface ApprovalRequest {
  readonly approvalId: string
  readonly kind: 'tool' | 'promotion'
  readonly runId?: string | undefined
  readonly toolRef?: string | undefined
  readonly argsHash?: string | undefined
  readonly agentId?: string | undefined
  readonly risk: string
  readonly argsPreview: string
  readonly requestedAt: number
  readonly expiresAt: number
}

export interface ApprovalOutcome {
  readonly approvalId: string
  readonly decision: ApprovalDecision
  readonly byConnectionId?: string
}

interface Pending {
  readonly request: ApprovalRequest
  readonly settle: (outcome: ApprovalOutcome) => void
  timer: NodeJS.Timeout
  resolved: boolean
}

export interface ApprovalsOptions {
  /** How long a request waits before it is denied. */
  readonly waitMs?: number
  /** Called when a request is created, so the caller can log and notify. */
  readonly onRequested?: (request: ApprovalRequest) => void
  /** Called when a request settles, so the caller can log the outcome. */
  readonly onResolved?: (outcome: ApprovalOutcome) => void
}

export class Approvals {
  readonly #pending = new Map<string, Pending>()
  readonly #waitMs: number
  readonly #onRequested: ((request: ApprovalRequest) => void) | undefined
  readonly #onResolved: ((outcome: ApprovalOutcome) => void) | undefined

  constructor(options: ApprovalsOptions = {}) {
    this.#waitMs = options.waitMs ?? 300_000
    this.#onRequested = options.onRequested
    this.#onResolved = options.onResolved
  }

  /**
   * Ask for a decision. Resolves when a human answers or the wait elapses.
   */
  request(input: {
    kind?: 'tool' | 'promotion'
    runId?: string
    toolRef?: string
    argsHash?: string
    agentId?: string
    risk: string
    argsPreview: string
  }): { request: ApprovalRequest; outcome: Promise<ApprovalOutcome> } {
    const approvalId = `apr_${randomUUID()}`
    const now = Date.now()
    const request: ApprovalRequest = {
      approvalId,
      kind: input.kind ?? 'tool',
      ...(input.runId === undefined ? {} : { runId: input.runId }),
      ...(input.toolRef === undefined ? {} : { toolRef: input.toolRef }),
      ...(input.argsHash === undefined ? {} : { argsHash: input.argsHash }),
      ...(input.agentId === undefined ? {} : { agentId: input.agentId }),
      risk: input.risk,
      argsPreview: input.argsPreview,
      requestedAt: now,
      expiresAt: now + this.#waitMs,
    }

    let settle!: (outcome: ApprovalOutcome) => void
    const outcome = new Promise<ApprovalOutcome>((resolve) => {
      settle = resolve
    })

    // The timer is deliberately NOT unref'd. A parked run is a real
    // obligation: the kernel must stay alive long enough to record the
    // expiry, rather than exiting out from under a run that is waiting and
    // leaving no outcome in the log. Shutdown settles everything through
    // close().
    const timer = setTimeout(() => {
      this.#finish(approvalId, { approvalId, decision: 'expired' })
    }, this.#waitMs)

    this.#pending.set(approvalId, { request, settle, timer, resolved: false })
    this.#onRequested?.(request)
    return { request, outcome }
  }

  /** Record a human's decision. Throws unless `actor` is a real HumanActor. */
  resolve(approvalId: string, actor: HumanActor, decision: 'approved' | 'denied'): ApprovalOutcome {
    assertHumanActor(actor, 'resolving an approval')

    const pending = this.#pending.get(approvalId)
    if (pending === undefined) {
      // Either it never existed or it already settled. Both are conflicts:
      // the answer the operator is giving no longer applies to anything.
      throw new PolicyDenied(approvalId, 'approval is not pending (unknown, expired or already resolved)')
    }

    return this.#finish(approvalId, {
      approvalId,
      decision,
      byConnectionId: actor.connectionId,
    })
  }

  /** Requests still waiting for an answer. */
  pending(): readonly ApprovalRequest[] {
    return [...this.#pending.values()].map((p) => p.request)
  }

  /** Stop every timer. Pending requests are denied as expired. */
  close(): void {
    for (const approvalId of [...this.#pending.keys()]) {
      this.#finish(approvalId, { approvalId, decision: 'expired' })
    }
  }

  #finish(approvalId: string, outcome: ApprovalOutcome): ApprovalOutcome {
    const pending = this.#pending.get(approvalId)
    if (pending === undefined || pending.resolved) return outcome
    pending.resolved = true
    clearTimeout(pending.timer)
    this.#pending.delete(approvalId)
    this.#onResolved?.(outcome)
    pending.settle(outcome)
    return outcome
  }
}

/**
 * Rebuild pending approvals from the event log after a restart.
 *
 * Phase 1. It throws rather than returning an empty projection, because
 * "nothing is pending" is a dangerous lie: a run parked on an approval before
 * the restart would look resolved, and the kernel would behave as though a
 * human had answered when none had.
 */
export function rebuildFromLog(): never {
  throw new NotImplementedError('approvals.rebuildFromLog')
}
