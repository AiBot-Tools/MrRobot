// Delegation — deliberately absent in Phase 0.
//
// Hermes-style `delegate_task` is the shape Phase 1 will take: an isolated
// context, its own model priority chain, its own budget. None of that exists
// yet, and the dangerous half-measure would be to offer the model a tool that
// looks like delegation and quietly does something simpler.
//
// So there is no delegation tool in any agent's tool array, and this throws.
// A run that reaches here has been given a capability the kernel cannot
// account for: a child run with no lane, no budget of its own and no line in
// the log tying its spend to its parent.

import { NotImplementedError } from '../errors.js'

export function assertDelegationAvailable(): never {
  throw new NotImplementedError('delegate-tool')
}
