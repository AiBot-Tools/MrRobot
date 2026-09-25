// Apple `container` driver — a stub, and loudly so.
//
// macOS 26 ships Apple's own container runtime; the operator is on 15.6.1, so
// it does not exist on this machine. Every method throws rather than returning
// a plausible answer: a driver that silently reported "no containers running"
// would let the kernel believe a run was sandboxed when nothing ran at all.
//
// `probe()` throws too. It would be tempting to have it report unavailable —
// that is the contract for a runtime that is merely absent — but this is not
// an absent runtime, it is unwritten code, and the two must not look alike in
// a degraded-subsystem view.

import { NotImplementedError } from '../errors.js'
import type { ProbeResult, RunningSandbox, SandboxDriver, SandboxSpec } from './driver.js'

export class AppleContainerDriver implements SandboxDriver {
  readonly name = 'apple-container'

  probe(): Promise<ProbeResult> {
    throw new NotImplementedError('apple-container')
  }

  run(_spec: SandboxSpec): RunningSandbox {
    throw new NotImplementedError('apple-container')
  }

  kill(_name: string): Promise<void> {
    throw new NotImplementedError('apple-container')
  }
}
