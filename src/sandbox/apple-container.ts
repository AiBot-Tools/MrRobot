// Apple `container` driver — a stub, and loudly so.
//
// macOS 26 ships Apple's own container runtime; the operator is on 15.6.1, so
// it does not exist on this machine. Every method that would execute
// something throws rather than returning a plausible answer: a driver that
// silently reported "no containers running" would let the kernel believe a
// run was sandboxed when nothing ran at all.
//
// `probe()` reports unavailable instead, naming the stub, so a kernel.yaml
// that picks this driver boots degraded rather than dead, and the reason in
// the degraded-subsystem view says this is unwritten code, not an absent
// runtime. `commandRefusal()` answers too, refusing nothing: it is asked
// before anything runs, and run() refuses every spec, which
// `everyRunRefusal()` says, in the probe's words, before any approval: the
// stub's refusal is a fact of its code, not of a runtime's state, so no run
// is offered sandbox.exec on a kernel that names this driver, and no human
// is asked to approve an exec it would then refuse.

import { NotImplementedError } from '../errors.js'
import type { ProbeResult, RunningSandbox, SandboxDriver, SandboxSpec, SweepRequest, SweepResult } from './driver.js'

/** Why this driver runs nothing: probe()'s reason, and everyRunRefusal()'s. */
const STUB_WHY =
  'the apple-container driver is not implemented: macOS 15 has no `container` binary. ' +
  'Use sandbox.driver: docker with Colima.'

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
   * `run`, `kill`, `abandon` and `sweepOrphans` still throw: asking an
   * absent runtime to execute something has no degraded answer.
   * `commandRefusal` answers, as probe does: it is asked before anything is
   * executed.
   */
  probe(): Promise<ProbeResult> {
    return Promise.resolve({ ok: false, why: STUB_WHY })
  }

  run(_spec: SandboxSpec): RunningSandbox {
    throw new NotImplementedError('apple-container')
  }

  /**
   * Refuses no command for itself: run() refuses every spec, whatever its
   * command. Answers rather than throws, as the contract asks of a check made
   * before any approval: an absent runtime is the run's refusal, not the
   * command's.
   */
  commandRefusal(_command: readonly string[]): string | undefined {
    return undefined
  }

  /**
   * Refuses every run, as run() does whatever the spec: a fact of this
   * stub's code, read before any approval (SandboxDriver.everyRunRefusal).
   */
  everyRunRefusal(): string | undefined {
    return STUB_WHY
  }

  kill(_name: string): Promise<void> {
    throw new NotImplementedError('apple-container')
  }

  /** Throws, as kill does, though nothing could reach it: run() never starts anything to give up. */
  abandon(_name: string): Promise<void> {
    throw new NotImplementedError('apple-container')
  }

  /**
   * Throws, as kill does: no runtime answers, and a sweep that reported no
   * container left running would be a plausible answer from code that asked
   * nothing. Boot reads the throw as a sweep that could not run, beside a
   * probe that already reports this driver unavailable.
   */
  sweepOrphans(_request: SweepRequest): Promise<SweepResult> {
    throw new NotImplementedError('apple-container')
  }
}
