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
  readonly stdout: string
  readonly stderr: string
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
  run(spec: SandboxSpec): RunningSandbox
  /** Idempotent: killing an unknown or already-dead container is not an error. */
  kill(name: string): Promise<void>
}
