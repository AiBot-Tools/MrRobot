// Egress enforcement: whether a sandboxed run may be given a channel.
//
// Invariant 2 says workers get credentials injected at the egress edge, never
// in env or files. That edge is the kernel's own egress engine (src/egress),
// reached by a trusted run only over its `docker -i` channel (egress plan,
// accepted by the operator on 2026-11-09). Boot decides once whether egress
// can run (kernel.ts: the egress probe, ok or degraded with the check that
// failed and its fix), and resolves each binding's value once, outside any
// run scope. A grant is issued only on that verdict.
//
// This throws rather than returning false, because the distinction that
// matters is between "egress is enforced and this host is denied" and "egress
// is not enforced at all". A boolean would let a caller treat the second as
// the first, and give a container a channel the kernel cannot serve.

import { KernelError } from '../errors.js'

/** Boot's verdict on egress: ok, or degraded with every failed check said. Never absent once built. */
export type EgressState = { readonly state: 'ok' } | { readonly state: 'degraded'; readonly reason: string }

/** What boot found of one binding's value: resolved, or why not, naming the binding and its envVar, never its value. */
export interface BindingStatus {
  readonly bindingId: string
  readonly envVar: string
  /** Undefined: resolved, checked as a bearer, and masked. */
  readonly problem?: string
}

/** The bindings a grant would route, and what boot found of every binding kernel.yaml holds. */
export interface GrantBindings {
  readonly used: readonly string[]
  readonly resolved: ReadonlyMap<string, BindingStatus>
}

/** Egress cannot serve this grant: its message says why, as boot recorded it. */
export class EgressUnavailable extends KernelError {
  constructor(message: string, options?: ErrorOptions) {
    super('AOS_EGRESS_UNAVAILABLE', message, options)
  }
}

/**
 * Throws EgressUnavailable, with the reason, unless egress is ok and every
 * binding `bindings.used` names resolved at boot. A binding boot never saw
 * (no status at all) is refused as unresolved: nothing here guesses that one
 * would have resolved.
 */
export function assertEgressEnforced(state: EgressState, bindings: GrantBindings): void {
  if (state.state !== 'ok') {
    throw new EgressUnavailable(`egress is degraded: ${state.reason}`)
  }
  for (const id of bindings.used) {
    const status = bindings.resolved.get(id)
    if (status === undefined) throw new EgressUnavailable(`egress binding ${id} was not resolved at boot`)
    if (status.problem !== undefined) {
      throw new EgressUnavailable(`egress binding ${id} (envVar ${status.envVar}) did not resolve at boot: ${status.problem}`)
    }
  }
}
