// The policy engine: gate, approval, ticket, log.
//
// Every agent tool call passes through check(). It runs the pure gate, logs
// the ruling, obtains a human decision when one is required, and — only then
// — mints a GateTicket. The hub refuses to execute anything without a ticket,
// so this is the single door.
//
// The ticket is bound to (runId, toolRef, argsHash). Binding to the argument
// hash is what stops the oldest trick in the book: get "delete the temp file"
// approved, then execute with a different path. The hub recomputes the hash
// from the arguments it is actually about to send and refuses on mismatch, so
// swapping arguments after approval fails at the last possible moment rather
// than succeeding quietly.

import { randomUUID } from 'node:crypto'

import { PolicyDenied } from '../errors.js'
import { canonicalize, sha256Hex } from '../events/canonical.js'
import { boundOutput } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import { decide, type GateInput } from './gate.js'
import type { Approvals } from './approvals.js'

export interface GateTicket {
  readonly ticketId: string
  readonly runId: string
  readonly toolRef: string
  readonly argsHash: string
  readonly quarantine: boolean
}

/** The hash a ticket is bound to. Canonical, so key order cannot change it. */
export function hashArgs(args: Record<string, unknown>): string {
  return sha256Hex(canonicalize(args))
}

export interface EngineOptions {
  readonly store: EventStore
  readonly approvals: Approvals
}

export class PolicyEngine {
  readonly #store: EventStore
  readonly #approvals: Approvals

  constructor(options: EngineOptions) {
    this.#store = options.store
    this.#approvals = options.approvals
  }

  /**
   * Decide and, if permitted, mint a ticket.
   *
   * @throws {PolicyDenied} on deny, on a human denial, and on timeout.
   */
  async check(input: GateInput): Promise<GateTicket> {
    const verdict = decide(input)
    const argsHash = hashArgs(input.args)

    // The ruling is logged before anything acts on it, so the record shows
    // what was decided even if the process dies in the next instant.
    this.#store.append({
      type: 'tool.gate',
      runId: input.scope.runId,
      agentId: input.scope.agentId,
      payload: {
        schemaVersion: 1,
        toolRef: input.toolRef,
        decision: verdict.decision,
        reason: verdict.reason,
        risk: input.view.risk,
        taint: input.scope.taint,
      },
    })

    if (verdict.decision === 'deny') {
      throw new PolicyDenied(input.toolRef, verdict.reason)
    }

    if (verdict.decision === 'needs-human') {
      const preview = boundOutput(canonicalize(input.args), 500)
      const { request, outcome } = this.#approvals.request({
        runId: input.scope.runId,
        toolRef: input.toolRef,
        argsHash,
        risk: input.view.risk,
        argsPreview: preview.text,
      })

      this.#store.append({
        type: 'approval.requested',
        runId: input.scope.runId,
        agentId: input.scope.agentId,
        payload: {
          schemaVersion: 1,
          approvalId: request.approvalId,
          toolRef: request.toolRef,
          argsPreview: request.argsPreview,
          risk: input.view.risk,
          expiresAt: new Date(request.expiresAt).toISOString(),
        },
      })

      const settled = await outcome
      this.#store.append({
        type: 'approval.resolved',
        runId: input.scope.runId,
        agentId: input.scope.agentId,
        payload: {
          schemaVersion: 1,
          approvalId: settled.approvalId,
          decision: settled.decision,
          ...(settled.byConnectionId === undefined ? {} : { byConnectionId: settled.byConnectionId }),
        },
      })

      if (settled.decision !== 'approved') {
        // Denied and expired are the same outcome for the call: no ticket.
        throw new PolicyDenied(
          input.toolRef,
          settled.decision === 'expired'
            ? 'approval expired before a human answered (fail closed)'
            : 'a human denied this call',
        )
      }
    }

    return {
      ticketId: randomUUID(),
      runId: input.scope.runId,
      toolRef: input.toolRef,
      argsHash,
      quarantine: verdict.decision === 'quarantine',
    }
  }

  /**
   * Check a ticket against the arguments about to be sent. The hub calls this
   * immediately before execution; a mismatch means the arguments changed
   * after the decision was made.
   */
  static assertTicketMatches(
    ticket: GateTicket,
    toolRef: string,
    args: Record<string, unknown>,
  ): void {
    if (ticket.toolRef !== toolRef) {
      throw new PolicyDenied(toolRef, `ticket was issued for ${ticket.toolRef}`)
    }
    if (ticket.argsHash !== hashArgs(args)) {
      throw new PolicyDenied(toolRef, 'ticket argsHash does not match the arguments being sent')
    }
  }
}
