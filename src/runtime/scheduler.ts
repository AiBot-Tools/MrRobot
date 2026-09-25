// Cron scheduler — deliberately absent in Phase 0.
//
// Manifests may carry a `schedule:` field; it parses, and nothing reads it.
// A scheduler that fired runs nobody asked for, before restart-safe
// projections exist (Phase 1), would produce runs the kernel cannot resume
// and approvals nobody is waiting on.

import { NotImplementedError } from '../errors.js'

export class Scheduler {
  start(): never {
    throw new NotImplementedError('scheduler')
  }
}
