// Docker driver (invariant 9).
//
// The argv this file builds IS the sandbox. Everything that makes a container
// safe is a flag, and a flag that is absent fails open and silently: the
// container runs, the work succeeds, and nobody finds out the root filesystem
// was writable until something uses it. So the flag set is built in one pure
// function and then AUDITED by that same function before it is returned —
// exactly one bind mount, no --privileged, no docker socket, no home
// directory — and a future edit that widens any of those throws rather than
// producing a container.
//
// The spawn environment is exactly { DOCKER_HOST, PATH }, and that is a
// security property rather than a tidiness one. Measured, not assumed
// (docker CLI 29.3.1):
//
//   With DOCKER_HOST set, the CLI connects to exactly that socket and HOME
//   makes no difference — a ~/.docker/config.json naming another context is
//   ignored entirely. Without DOCKER_HOST, that context DOES decide the
//   endpoint.
//
// So omitting HOME is not a compatibility risk, it is the stronger posture:
// the endpoint depends solely on kernel config, and no edit to a dotfile can
// redirect a kernel container at another daemon. Credential helpers would
// matter only for registry pulls, which this driver never does — it runs
// `run`, `kill`, `version` and `ps` against a locally built image.
//
// The whole process environment is never passed. A worker that inherited the
// kernel's environment would receive every provider key the operator exported
// (invariant 2), which is the failure the egress proxy exists to prevent in
// Phase 2 and which must not be possible before it ships.

import { ConfigError } from '../errors.js'
import { confineWorkspace } from './confine.js'
import type {
  ProbeResult,
  RunningSandbox,
  SandboxDriver,
  SandboxResult,
  SandboxSpec,
} from './driver.js'

/** Prefix for every container the kernel creates, so orphans are findable. */
export const CONTAINER_PREFIX = 'aos-run-'

/** Where the workspace is mounted inside the container. */
export const WORKSPACE_TARGET = '/workspace'

/** Flags that must never appear, whatever a future edit intends. */
const FORBIDDEN_FLAGS = ['--privileged', '--cap-add', '--device', '--pid=host', '--userns=host']
const FORBIDDEN_SUBSTRINGS = ['docker.sock', '/var/run/docker']

export interface DomainConfig {
  readonly dockerHost: string
  readonly network: string
  readonly mountRoot: string
}

export interface DockerDefaults {
  readonly user: string
  readonly pidsLimit: number
  readonly memory: string
  readonly cpus: number
}

export interface BuildArgsInput {
  readonly spec: SandboxSpec
  readonly domain: DomainConfig
  readonly defaults: DockerDefaults
  readonly repoRoot: string
  /** Defaults to the current user's home; injected so a test can pin it. */
  readonly home?: string
}

/**
 * Build the full `docker run` argv for one spec.
 *
 * Confinement happens in here rather than at the call site, so there is no
 * path that reaches docker having skipped it.
 */
export function buildRunArgs(input: BuildArgsInput): string[] {
  const { spec, domain, defaults } = input
  const home = input.home ?? process.env['HOME'] ?? ''

  if (!spec.name.startsWith(CONTAINER_PREFIX)) {
    throw new ConfigError(`container name "${spec.name}" must start with ${CONTAINER_PREFIX}`)
  }

  // Resolved, proven to be inside the domain's mountRoot, and outside every
  // protected root. This is the path docker is given — never the request.
  const workspace = confineWorkspace(spec.workspace, domain.mountRoot, input.repoRoot)

  const args = [
    'run',
    // No detached container survives the kernel: the run owns its lifetime.
    '--rm',
    '--name',
    spec.name,
    // Invariant 9, one flag at a time.
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--user',
    defaults.user,
    '--pids-limit',
    String(defaults.pidsLimit),
    '--memory',
    defaults.memory,
    '--cpus',
    String(defaults.cpus),
    // An internal network has no route off the VM. Phase 2's egress proxy is
    // what will give a container the internet, one allowed hostname at a time.
    '--network',
    domain.network,
    // PID 1 that reaps zombies and forwards signals, so a kill actually kills.
    '--init',
    // The root is read-only, so scratch space has to come from somewhere that
    // cannot hold a setuid binary or be executed from.
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,nodev,size=64m',
    // Exactly one mount, and this is it.
    '--mount',
    `type=bind,source=${workspace},target=${WORKSPACE_TARGET}`,
    '--workdir',
    WORKSPACE_TARGET,
    spec.image,
    ...spec.command,
  ]

  auditRunArgs(args, home, workspace)
  return args
}

/**
 * Prove the argv says what it should, before it becomes a container.
 *
 * This is deliberately a separate pass over the finished array rather than a
 * set of conditions spread through the builder: it catches a widening
 * introduced anywhere above, including in `spec.command`.
 */
export function auditRunArgs(args: readonly string[], home: string, workspace: string): void {
  for (const arg of args) {
    for (const bad of FORBIDDEN_FLAGS) {
      if (arg === bad || arg.startsWith(`${bad}=`)) {
        throw new ConfigError(`docker args contain ${bad}, which invariant 9 forbids`)
      }
    }
    for (const bad of FORBIDDEN_SUBSTRINGS) {
      if (arg.includes(bad)) {
        throw new ConfigError(`docker args mention ${bad}: a container may never reach the daemon`)
      }
    }
  }

  const mounts = args.filter((a) => a === '--mount').length
  const volumes = args.filter((a) => a === '-v' || a === '--volume').length
  if (mounts !== 1 || volumes !== 0) {
    throw new ConfigError(
      `docker args must carry exactly one --mount and no -v (found ${String(mounts)} and ${String(volumes)})`,
    )
  }

  // The home directory, never — not as the workspace and not smuggled into a
  // command argument. An empty HOME would make this vacuous, so it is skipped
  // rather than compared against ''.
  if (home !== '') {
    if (workspace === home) {
      throw new ConfigError('the workspace may never be the home directory')
    }
    for (const arg of args) {
      if (arg.includes(`source=${home},`) || arg === home || arg.startsWith(`${home}/`)) {
        throw new ConfigError(`docker args reference the home directory (${home})`)
      }
    }
  }
}

// ── the driver ─────────────────────────────────────────────────────────────

export interface ChildLike {
  readonly stdout: { on(event: 'data', cb: (chunk: unknown) => void): void } | null
  readonly stderr: { on(event: 'data', cb: (chunk: unknown) => void): void } | null
  on(event: 'close', cb: (code: number | null, signal: string | null) => void): unknown
  on(event: 'error', cb: (error: Error) => void): unknown
}

export type SpawnFn = (
  command: string,
  args: readonly string[],
  options: { env: Record<string, string> },
) => ChildLike

export type ExecFileFn = (
  command: string,
  args: readonly string[],
  options: { env: Record<string, string> },
) => Promise<{ stdout: string; stderr: string }>

export interface DockerDriverOptions {
  readonly spawn: SpawnFn
  readonly execFile: ExecFileFn
  readonly domains: Readonly<Record<'trusted' | 'hostile', DomainConfig>>
  readonly defaults: DockerDefaults
  readonly repoRoot: string
  readonly binary?: string
  readonly path?: string
  readonly home?: string
}

export class DockerDriver implements SandboxDriver {
  readonly name = 'docker'
  readonly #options: DockerDriverOptions
  readonly #binary: string

  constructor(options: DockerDriverOptions) {
    this.#options = options
    this.#binary = options.binary ?? 'docker'
  }

  /**
   * The ONLY environment a docker invocation gets.
   *
   * Exactly two keys, always, and built from kernel config rather than copied
   * from the process — see this file's header for why HOME is not among them.
   */
  #env(domain: 'trusted' | 'hostile'): Record<string, string> {
    return {
      DOCKER_HOST: this.#options.domains[domain].dockerHost,
      PATH: this.#options.path ?? process.env['PATH'] ?? '/usr/bin:/bin',
    }
  }

  async probe(): Promise<ProbeResult> {
    try {
      const { stdout } = await this.#options.execFile(
        this.#binary,
        ['version', '--format', '{{.Server.Version}}'],
        { env: this.#env('trusted') },
      )
      const version = stdout.trim()
      if (version === '') return { ok: false, why: 'docker version reported no server version' }
      return { ok: true, version }
    } catch (e) {
      // Availability, never a throw: a kernel with no container runtime must
      // still boot and say why.
      return { ok: false, why: e instanceof Error ? e.message : String(e) }
    }
  }

  run(spec: SandboxSpec): RunningSandbox {
    const domain = this.#options.domains[spec.domain]
    const args = buildRunArgs({
      spec,
      domain,
      defaults: this.#options.defaults,
      repoRoot: this.#options.repoRoot,
      ...(this.#options.home === undefined ? {} : { home: this.#options.home }),
    })

    const startedAt = Date.now()
    let stdout = ''
    let stderr = ''
    let killedBy: SandboxResult['killedBy'] | undefined
    let settled = false

    const child = this.#options.spawn(this.#binary, args, { env: this.#env(spec.domain) })
    child.stdout?.on('data', (chunk) => {
      stdout += String(chunk)
    })
    child.stderr?.on('data', (chunk) => {
      stderr += String(chunk)
    })

    const result = new Promise<SandboxResult>((resolve) => {
      // The hard wallclock. A container that ignores SIGTERM is why this goes
      // straight to KILL by name: the kernel must be able to end a run it no
      // longer trusts without negotiating.
      const timer = setTimeout(() => {
        killedBy = 'wallclock'
        void this.kill(spec.name)
      }, spec.limits.wallclockMs)
      timer.unref?.()

      const finish = (exitCode: number | null, signal: string | null): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve({
          name: spec.name,
          exitCode,
          signal: signal === 'SIGKILL' || signal === 'SIGTERM' ? signal : null,
          ...(killedBy === undefined ? {} : { killedBy }),
          stdout,
          stderr,
          durationMs: Date.now() - startedAt,
        })
      }

      child.on('close', (code, signal) => {
        finish(code, killedBy === 'wallclock' ? 'SIGKILL' : signal)
      })
      child.on('error', (error) => {
        stderr += error.message
        finish(null, null)
      })
    })

    return { name: spec.name, result }
  }

  /** Idempotent: killing an unknown or already-dead container is not an error. */
  async kill(name: string): Promise<void> {
    try {
      await this.#options.execFile(this.#binary, ['kill', '--signal=KILL', name], {
        env: this.#env('trusted'),
      })
    } catch {
      // "No such container" is the normal outcome of a race between a
      // wallclock kill and a container that just exited.
    }
  }

  /**
   * Kill every container the kernel left behind.
   *
   * Run at boot: a kernel that crashed mid-run leaves a container holding a
   * workspace and a CPU, and nothing else will ever reap it.
   */
  async sweepOrphans(): Promise<string[]> {
    const killed: string[] = []
    for (const domain of ['trusted', 'hostile'] as const) {
      let stdout = ''
      try {
        ;({ stdout } = await this.#options.execFile(
          this.#binary,
          ['ps', '--quiet', '--no-trunc', '--filter', `name=${CONTAINER_PREFIX}`, '--format', '{{.Names}}'],
          { env: this.#env(domain) },
        ))
      } catch {
        continue
      }
      for (const name of stdout.split('\n').map((s) => s.trim()).filter((s) => s !== '')) {
        // Only ours. A filter is a request, not a guarantee.
        if (!name.startsWith(CONTAINER_PREFIX)) continue
        await this.kill(name)
        killed.push(name)
      }
    }
    return killed
  }
}
