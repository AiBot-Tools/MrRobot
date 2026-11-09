// Sandbox driver interface.
//
// One process or container per run. The spec below is the whole surface a
// driver is given: everything in it is either a hard limit or a confined
// path, and there is deliberately no field for "extra arguments", "extra
// mounts" or "environment" — those would be the seams through which an agent
// widens its own container.
//
// Invariant 9 lives in the drivers that implement this, not here: read-only
// root, all capabilities dropped, no new privileges, non-root user, pid and
// memory and cpu caps, an internal network, mounts confined to the domain's
// mountRoot after symlink resolution, and a hard wallclock. Never privileged,
// never the docker socket, never the home directory.
//
// `probe()` reports availability rather than throwing, because a kernel with
// no container runtime must still boot degraded and say why.
//
// What a run writes is bounded too. A container is untrusted, and one that
// writes without end would otherwise grow the kernel's memory until the
// wallclock fires, or past it; so a driver keeps at most CAPTURE_MAX_BYTES of
// each stream, in memory that grows with the bytes kept and not with how the
// container cut its writes, keeps reading the rest so the container never
// blocks on a full pipe, and says that it cut.

import { MAX_LOGGED_OUTPUT } from '../events/bound.js'

/**
 * Most bytes of each of a run's two output streams a driver keeps: 1 MiB.
 *
 * Sized from MAX_LOGGED_OUTPUT because the log is where a run's output goes:
 * it stores at most that much of the REDACTED text, plus a digest of the
 * redacted whole (events/bound.ts), and this capture is that whole. It is a
 * multiple rather than equal because bound.ts redacts first and cuts second,
 * so that a cut never halves a credential and leaves its front in the log;
 * this cut is of raw bytes, before any redaction, and a capture no longer than
 * the log's limit would make it the cut that decides the stored prefix. Sixteen
 * times keeps the stored prefix well clear of it even where redaction shrinks
 * the text (a long token becomes [REDACTED]), and still holds what a run keeps
 * to 2 MiB however much its container writes. (The docker driver holds that in
 * blocks of its own, so the memory is about the bytes kept even when the
 * output arrives a byte at a time: docker.ts, Capture.)
 */
export const CAPTURE_MAX_BYTES = 16 * MAX_LOGGED_OUTPUT

/** Isolation domain. Each maps to its own VM and its own internal network. */
export type SandboxDomain = 'trusted' | 'hostile'

export interface SandboxLimits {
  readonly memoryMb: number
  readonly cpus: number
  readonly pids: number
  /** Hard wallclock. The driver kills the container when it elapses. */
  readonly wallclockMs: number
}

export interface SandboxSpec {
  /** Stable name for the container, used for kill and orphan sweeps. */
  readonly name: string
  readonly runId: string
  readonly agentId: string
  readonly domain: SandboxDomain
  readonly image: string
  readonly command: readonly string[]
  /**
   * Host path to mount as the run's workspace. The driver resolves symlinks
   * and refuses anything outside the domain's mountRoot; it is not trusted
   * as given.
   */
  readonly workspace: string
  readonly limits: SandboxLimits
}

export type ExitSignal = 'SIGKILL' | 'SIGTERM' | null

export interface SandboxResult {
  readonly name: string
  /** Null when the process was signalled rather than exiting. */
  readonly exitCode: number | null
  readonly signal: ExitSignal
  /** Set when the kernel stopped it, rather than it finishing on its own. */
  readonly killedBy?: 'wallclock' | 'requested'
  /**
   * The first CAPTURE_MAX_BYTES bytes of each stream at most, decoded as UTF-8
   * and cut on a character boundary. A byte that is not UTF-8 decodes to
   * U+FFFD, so the text is at most CAPTURE_MAX_BYTES UTF-16 units long.
   */
  readonly stdout: string
  readonly stderr: string
  /**
   * True when either stream carried more than CAPTURE_MAX_BYTES, and so was
   * cut. One flag for both, so it does not say which stream was cut, and a
   * stream's length does not say it either: the cut falls on a character
   * boundary, up to three bytes short of the cap. A reader that must name the
   * stream (sandbox.exec reporting a cut, plan S3) needs per-stream flags
   * added here first, beside this one.
   */
  readonly truncated: boolean
  readonly durationMs: number
}

export interface RunningSandbox {
  readonly name: string
  /** Resolves when the container exits, is killed, or overruns. */
  readonly result: Promise<SandboxResult>
}

export type ProbeResult =
  | { readonly ok: true; readonly version: string }
  | { readonly ok: false; readonly why: string }

export interface SandboxDriver {
  readonly name: string
  /** Availability, never a throw: a missing runtime is a degraded boot. */
  probe(): Promise<ProbeResult>
  /**
   * Throws, before starting anything, while a run under `spec.name` from an
   * earlier call has not finished: the name is how kill() and the wallclock
   * reach a container, so it must name exactly one.
   */
  run(spec: SandboxSpec): RunningSandbox
  /**
   * Idempotent: killing an unknown or already-dead container is not an error.
   * A run it ends reports `killedBy: 'requested'` and SIGKILL, unless its
   * wallclock had already fired.
   */
  kill(name: string): Promise<void>
}
