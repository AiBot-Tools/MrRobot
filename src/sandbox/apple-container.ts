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

  /**
   * Reports unavailable; does not throw.
   *
   * The driver contract says availability is never a throw, because a missing
   * container runtime is a degraded boot and not a dead kernel. Throwing here
   * made `sandbox.driver: apple-container` — a value kernel.yaml accepts —
   * refuse the whole boot, which is the opposite of what a stub should do.
   *
   * `run` and `kill` still throw: asking an absent runtime to execute something
   * has no degraded answer.
   */
  probe(): Promise<ProbeResult> {
    return Promise.resolve({
      ok: false,
      why:
        'the apple-container driver is not implemented: macOS 15 has no `container` binary. ' +
        'Use sandbox.driver: docker with Colima.',
    })
  }

  run(_spec: SandboxSpec): RunningSandbox {
    throw new NotImplementedError('apple-container')
  }

  kill(_name: string): Promise<void> {
    throw new NotImplementedError('apple-container')
  }
}
