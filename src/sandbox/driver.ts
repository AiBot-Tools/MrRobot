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
// memory and cpu caps, no network (docker's --network none), mounts confined
// to the domain's mountRoot after symlink resolution, and a hard wallclock.
// Never privileged, never the docker socket, never the home directory.
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

/**
 * Prefix for every container the kernel creates, so orphans are findable, and
 * so that a name without it is someone else's container, which no driver
 * starts or kills (SandboxDriver.run, kill). Here rather than in a driver's
 * module so that whatever codes against this interface, the fake driver
 * among it, has the rule without importing a driver.
 */
export const CONTAINER_PREFIX = 'aos-run-'

/**
 * Isolation domain. Each maps to its own VM; its internal network is kept and
 * probed as defence in depth, and no run is put on it.
 */
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
  /**
   * The image the run asks for. A driver is not bound to run it as given: the
   * docker driver runs only the pinned sandbox.imageId, by id and with
   * --pull=never, and refuses a spec naming anything else, a tag among them,
   * and every spec while none is pinned; the fake driver refuses the same.
   * So a caller copies config.sandbox.imageId here, never config.sandbox.image
   * or a manifest's sandbox.image, which are tags.
   */
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
  /**
   * Null when the process was signalled rather than exiting, or never
   * started. A run the kernel's kill ended reports 137, the docker CLI's exit
   * for a killed container, with signal SIGKILL and killedBy; a 137 with no
   * killedBy is the run's own (the OOM killer's, or the worker's exit 137).
   * Tell a kill by killedBy, never by this code.
   */
  readonly exitCode: number | null
  readonly signal: ExitSignal
  /** Set when the kernel stopped it, rather than it finishing on its own. */
  readonly killedBy?: 'wallclock' | 'requested'
  /**
   * Set when the run's hard wallclock elapsed before it ended, whether or not
   * the kill the driver then sent ended it (killedBy 'wallclock' says it did).
   * A run that outlived its wallclock and then exited on its own, its kill
   * having reached no daemon, reports this and no killedBy: it is the one
   * trace that invariant 9's hard wallclock did not hold, and a caller logs it.
   */
  readonly overran?: true
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
   * Throws a ConfigError, before starting anything, for a `spec.name` that
   * does not start with CONTAINER_PREFIX: such a name is no container of the
   * kernel's, and the orphan sweep would never find it. And throws, before
   * starting anything, while a run under `spec.name` from an earlier call has
   * not finished: the name is how kill() and the wallclock reach a container,
   * so it must name exactly one. The name stays held until the result has
   * settled, and is free once `await result` has returned.
   */
  run(spec: SandboxSpec): RunningSandbox
  /**
   * Idempotent: killing an unknown or already-dead container is not an error.
   * A name without CONTAINER_PREFIX is someone else's container: a kill of it
   * is sent nowhere and ends nothing, and is not an error either.
   *
   * Resolves once the kill has been sent, not once the run has ended: the run
   * under that name may still be running, and its name still held, when this
   * returns; `await result` is what says it ended. A run it ends reports
   * `killedBy: 'requested'` and SIGKILL, unless its wallclock fired before
   * the run ended. A kill can also end nothing (it reached no daemon, or came
   * after the run had exited on its own), and the run then reports its own
   * exit.
   */
  kill(name: string): Promise<void>
}
