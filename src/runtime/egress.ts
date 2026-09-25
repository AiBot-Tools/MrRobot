// Egress enforcement — deliberately absent in Phase 0.
//
// Invariant 2 says workers get credentials injected at the egress proxy edge,
// never in env or files. The proxy is a Phase 2 component; until it exists,
// nothing in the kernel may claim a container's network is controlled.
//
// This throws rather than returning false, because the distinction that
// matters is between "egress is enforced and this host is denied" and "egress
// is not enforced at all". A boolean would let a caller treat the second as
// the first.

import { NotImplementedError } from '../errors.js'

export function assertEgressEnforced(): never {
  throw new NotImplementedError('egress-proxy')
}
