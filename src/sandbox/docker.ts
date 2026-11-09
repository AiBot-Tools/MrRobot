// Docker driver (invariant 9).
//
// The argv this file builds IS the sandbox. Everything that makes a container
// safe is a flag, and a flag that is absent fails open and silently: the
// container runs, the work succeeds, and nobody finds out the root filesystem
// was writable until something uses it. So the flag set is built in one pure
// function and then AUDITED by that same function before it is returned —
// exactly one bind mount, read as docker reads it, no --privileged, no docker
// socket, no home directory, a --user that is not root and resource caps that
// are not 0, and nothing before the image that the builder did not emit — and
// a future edit that widens any of those throws rather than producing a
// container.
//
// The spawn environment is exactly { DOCKER_CONFIG, DOCKER_HOST, PATH }, and that
// is a security property rather than a tidiness one. DOCKER_CONFIG is a
// kernel-owned directory under the data dir, so not even the CLI's own config
// lookup reaches the operator's ~/.docker. Measured, not assumed
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

import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

import { ConfigError } from '../errors.js'
import { homeDirectory, realpathNearest } from '../agents/protected.js'
import { confineWorkspace } from './confine.js'
import { isCpus, isPidsLimit, isUnprivilegedUser, memoryBytes } from './limits.js'
import {
  CAPTURE_MAX_BYTES,
  type ProbeResult,
  type RunningSandbox,
  type SandboxDomain,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from './driver.js'

/** Prefix for every container the kernel creates, so orphans are findable. */
export const CONTAINER_PREFIX = 'aos-run-'

/** Every domain, each its own VM with its own daemon. */
const DOMAINS: readonly SandboxDomain[] = ['trusted', 'hostile']

/** Where the workspace is mounted inside the container. */
export const WORKSPACE_TARGET = '/workspace'

/** Flags that must never appear, whatever a future edit intends. */
const FORBIDDEN_FLAGS = ['--privileged', '--cap-add', '--device', '--pid=host', '--userns=host']
const FORBIDDEN_SUBSTRINGS = ['docker.sock', '/var/run/docker']

/**
 * Every option buildRunArgs emits, spelled as it emits it, and nothing else.
 * A `value` option takes the next element, as docker's flag parser does for
 * `--flag value`. Docker stops reading its own options at the first element
 * that is not one, which is the image, so this list is the whole of what
 * docker obeys. Adding a flag to the builder means adding it here: that is
 * the review point, not an inconvenience.
 */
const RUN_OPTIONS: ReadonlyMap<string, 'flag' | 'value'> = new Map([
  ['--rm', 'flag'],
  ['--name', 'value'],
  ['--read-only', 'flag'],
  ['--cap-drop=ALL', 'flag'],
  ['--security-opt=no-new-privileges', 'flag'],
  ['--user', 'value'],
  ['--pids-limit', 'value'],
  ['--memory', 'value'],
  ['--cpus', 'value'],
  ['--network', 'value'],
  ['--init', 'flag'],
  ['--tmpfs', 'value'],
  ['--mount', 'value'],
  ['--workdir', 'value'],
])

/**
 * What makes docker's CSV reader split a --mount value other than at its
 * commas: a double quote starts a quoted field (which may hold a comma), and a
 * line break ends the record. Other control characters are refused with them,
 * because nothing legitimate puts one in a path.
 */
const MOUNT_QUOTING = /["\p{Cc}]/u
/** And in a path written into that value, a comma starts a field of its own. */
const MOUNT_STRUCTURE = /[,"\p{Cc}]/u

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
  const home = input.home ?? homeDirectory()

  if (!spec.name.startsWith(CONTAINER_PREFIX)) {
    throw new ConfigError(`container name "${spec.name}" must start with ${CONTAINER_PREFIX}`)
  }

  // Resolved, proven to be inside the domain's mountRoot, and outside every
  // protected root. This is the path docker is given — never the request.
  const workspace = confineWorkspace(spec.workspace, domain.mountRoot, input.repoRoot)

  // The path is written into a CSV value below, and docker lets a later
  // `source=` overwrite an earlier one without a word. So a real directory
  // `x,source=` under the mountRoot, holding `etc`, passes every containment
  // check above and becomes `source=<root>/x,source=/etc`: the VM's /etc,
  // read-write. A workspace whose path docker would read as structure is
  // refused here, where the reason can be named; the audit refuses the
  // resulting value again on its own terms.
  if (MOUNT_STRUCTURE.test(workspace)) {
    throw new ConfigError(
      `mount confinement: the workspace ${JSON.stringify(workspace)} holds a comma, a double quote or a ` +
        "control character, which docker's --mount syntax reads as structure rather than as part of the path",
    )
  }

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
  //
  // Checked under both spellings of home a string can carry: as given and
  // fully resolved. The workspace is a resolved path (confineWorkspace), so
  // comparing it with an unresolved HOME misses whenever a component of HOME
  // is a symlink — which on macOS includes anything under /var, /tmp and /etc.
  // A command argument can use either spelling, so both are refused. Spellings
  // a string cannot see (an APFS case variant, a firmlink, a bind mount) are
  // refused by identity in confineWorkspace, on every run.
  if (home !== '') {
    const spellings = [...new Set([home, realpathNearest(home)])]
    for (const h of spellings) {
      if (workspace === h) {
        throw new ConfigError('the workspace may never be the home directory')
      }
      for (const arg of args) {
        if (arg.includes(`source=${h},`) || arg === h || arg.startsWith(`${h}/`)) {
          throw new ConfigError(`docker args reference the home directory (${h})`)
        }
      }
    }
  }

  // What docker itself obeys: the options between `run` and the image. A spec
  // field that lands in that slot (the image) is read as an option in any
  // spelling docker accepts — `--volume=/:/host`, `-v/x:/y`, `--user=0:0`,
  // `--read-only=false`, `--network=container:<id>` — none of which the
  // exact-string checks above see. So every element there must be one the
  // builder emits, each exactly once (docker keeps the LAST `--user`), and
  // the image is the first element that is not an option.
  if (args[0] !== 'run') {
    throw new ConfigError(`docker args must start with run (found ${JSON.stringify(args[0] ?? '')})`)
  }
  const seen = new Map<string, number>()
  const values = new Map<string, string>()
  let mount: string | undefined
  let at = 1
  for (let arg = args[at]; arg !== undefined && arg.startsWith('-'); arg = args[at]) {
    const kind = RUN_OPTIONS.get(arg)
    if (kind === undefined) {
      throw new ConfigError(
        `docker args carry ${JSON.stringify(arg)} before the image, which the builder never emits, and docker would obey it`,
      )
    }
    seen.set(arg, (seen.get(arg) ?? 0) + 1)
    if (kind === 'value') {
      at++
      if (arg === '--mount') mount = args[at]
      values.set(arg, args[at] ?? '')
    }
    at++
  }
  for (const option of RUN_OPTIONS.keys()) {
    const n = seen.get(option) ?? 0
    if (n !== 1) {
      throw new ConfigError(
        `docker args carry ${option} ${String(n)} time(s) before the image; the builder emits it exactly once`,
      )
    }
  }
  if (at >= args.length) {
    throw new ConfigError('docker args name no image after their options')
  }

  // Each once, by the count above, so this is the value docker uses.
  for (const option of CAP_VALUES.keys()) assertCapValue(option, values.get(option) ?? '')
  assertTheMount(mount ?? '', workspace)
}

/**
 * The values that make a container non-root and capped, and what each must be.
 * Each is well-formed to docker in a spelling that removes the property:
 * `--user 0:0` runs as root, and `--memory 0`, `--pids-limit 0` and `--cpus 0`
 * are no limit. The config schema refuses them too (sandbox/limits.ts), but a
 * driver can be handed its defaults by another path, and this audit is what
 * every argv meets.
 */
const CAP_VALUES: ReadonlyMap<string, readonly [admits: (value: string) => boolean, needs: string]> = new Map([
  ['--user', [isUnprivilegedUser, 'a numeric <uid>:<gid> with neither 0 (root)']],
  ['--memory', [(value: string) => memoryBytes(value) !== undefined, 'a positive whole number with a unit, k, m or g']],
  ['--pids-limit', [isPidsLimit, 'a positive whole number']],
  ['--cpus', [isCpus, 'a positive number']],
])

function assertCapValue(option: string, value: string): void {
  const cap = CAP_VALUES.get(option)
  if (cap !== undefined && !cap[0](value)) {
    throw new ConfigError(`docker args carry ${option} ${JSON.stringify(value)}; invariant 9 needs ${cap[1]}`)
  }
}

/**
 * Read the one --mount value as docker does, and require it to be exactly
 * `type=bind,source=<the confined workspace>,target=/workspace`.
 *
 * Docker reads the value as one CSV record, takes each field's key up to its
 * first `=` in any case, and lets a later field overwrite an earlier one, so
 * a second `source=` (or `src=`, or `type=volume`, or `bind-create-src`)
 * after the workspace decides what is mounted. Comparing the whole string
 * against a template would not catch that: the template is filled from the
 * same workspace string that carries the extra field.
 */
function assertTheMount(value: string, workspace: string): void {
  if (MOUNT_QUOTING.test(value)) {
    throw new ConfigError(
      `the --mount value ${JSON.stringify(value)} holds a double quote or a control character, so docker would not split it at its commas`,
    )
  }
  const fields = new Map<string, string>()
  for (const field of value.split(',')) {
    const eq = field.indexOf('=')
    if (eq === -1) {
      throw new ConfigError(`the --mount value has a field without a value (${JSON.stringify(field)})`)
    }
    const key = field.slice(0, eq).toLowerCase()
    if (fields.has(key)) {
      throw new ConfigError(`the --mount value names ${key} twice, and docker would use the last one`)
    }
    fields.set(key, field.slice(eq + 1))
  }
  const want: readonly (readonly [string, string])[] = [
    ['type', 'bind'],
    ['source', workspace],
    ['target', WORKSPACE_TARGET],
  ]
  if (fields.size !== want.length || want.some(([key, v]) => fields.get(key) !== v)) {
    throw new ConfigError(
      `the --mount value must be exactly type=bind,source=<the confined workspace>,target=${WORKSPACE_TARGET} ` +
        `(found ${JSON.stringify(value)})`,
    )
  }
}

// ── the driver ─────────────────────────────────────────────────────────────

/**
 * The output streams' chunks are what Node's child pipes emit: a Buffer each,
 * or a string had an encoding been set on the stream (the driver sets none).
 */
export interface ChildLike {
  readonly stdout: { on(event: 'data', cb: (chunk: Buffer | string) => void): void } | null
  readonly stderr: { on(event: 'data', cb: (chunk: Buffer | string) => void): void } | null
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
  /**
   * DOCKER_CONFIG for every invocation: a kernel-owned, normally empty
   * directory (`<dataDir>/docker`). Without it the CLI falls back to the
   * operator's ~/.docker, whose contexts and credential helpers the kernel
   * neither controls nor wants.
   */
  readonly dockerConfig?: string
}

/**
 * The size of each block a Capture owns. A pipe hands the kernel at most 64 KiB
 * a read, so a stream that arrives in large chunks fills a block or two per
 * chunk, and a short output costs one block.
 */
const CAPTURE_BLOCK_BYTES = 64 * 1024

/**
 * One output stream of a run: its first CAPTURE_MAX_BYTES kept, the rest read
 * and dropped. It never stops reading, because a pipe nobody drains fills and
 * the container then blocks on its next write until the wallclock kills it.
 *
 * Bytes until the end rather than text per chunk: a chunk boundary can fall
 * inside a multi-byte character, and decoding each chunk on its own turns both
 * halves into U+FFFD.
 *
 * Every chunk is COPIED into blocks the capture owns, never kept. A container
 * decides how its output is cut: one that writes a byte at a time, paced,
 * reaches the kernel as one-byte pipe chunks, and a Buffer kept per chunk
 * costs a few hundred bytes of the kernel's memory for each byte it holds. So
 * what a capture holds is the bytes it keeps, rounded up to one block, however
 * the stream arrived.
 */
class Capture {
  /** Every block is full but the last, so the blocks in order are the bytes. */
  readonly #blocks: Buffer[] = []
  /**
   * Bytes held. Up to one past the cap, so that a stream which carried more is
   * told apart from one that filled it exactly.
   */
  #held = 0

  add(chunk: Buffer | string): void {
    const room = CAPTURE_MAX_BYTES + 1 - this.#held
    if (room <= 0) return
    const bytes = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk
    let rest = bytes.length > room ? bytes.subarray(0, room) : bytes
    while (rest.length > 0) {
      const offset = this.#held % CAPTURE_BLOCK_BYTES
      let block = this.#blocks.at(-1)
      if (block === undefined || offset === 0) {
        block = Buffer.alloc(CAPTURE_BLOCK_BYTES)
        this.#blocks.push(block)
      }
      const copied = rest.copy(block, offset)
      this.#held += copied
      rest = rest.subarray(copied)
    }
  }

  get truncated(): boolean {
    return this.#held > CAPTURE_MAX_BYTES
  }

  text(): string {
    const all = Buffer.concat(this.#blocks, this.#held)
    if (!this.truncated) return all.toString('utf8')
    // The last byte held is the first one past the cap, there only to say that
    // the stream carried more: add() is the one place the cap is applied. What
    // is kept must not end inside a character, so the cut moves back to the
    // lead byte of a character the cap splits: the last lead in the final three
    // bytes kept (a character is at most four), and only when it declares more
    // bytes than are left before the cap. Nothing else moves the cut. Not a
    // whole character followed by a stray continuation byte (10xxxxxx) past the
    // cap: that character is kept. Not continuation bytes with no lead in
    // reach: they are not UTF-8, there is no character to keep whole, and the
    // cut stays at the cap. (Walking on until some lead byte would drop all of
    // a binary stream.)
    const cap = all.length - 1
    let end = cap
    for (let at = cap - 1; at >= cap - 3; at--) {
      const byte = all[at] ?? 0
      if ((byte & 0xc0) === 0x80) continue
      if (at + declaredLength(byte) > cap) end = at
      break
    }
    return all.subarray(0, end).toString('utf8')
  }
}

/**
 * The bytes of the UTF-8 character a lead byte starts, as the lead declares
 * them: 110xxxxx two, 1110xxxx three, 11110xxx four. Any other byte that is
 * not a continuation stands alone: ASCII, or a byte no character starts with.
 */
function declaredLength(lead: number): number {
  if ((lead & 0xe0) === 0xc0) return 2
  if ((lead & 0xf0) === 0xe0) return 3
  if ((lead & 0xf8) === 0xf0) return 4
  return 1
}

/** A run this driver is holding, by name. */
interface Held {
  readonly domain: SandboxDomain
  /** Mark the run as ended by kill(name), unless its wallclock already fired. */
  requested(): void
}

export class DockerDriver implements SandboxDriver {
  readonly name = 'docker'
  readonly #options: DockerDriverOptions
  readonly #binary: string
  /**
   * Every container this driver started whose `docker run` client has not yet
   * closed; a name dropped from here is killed on every domain. A container
   * name means something only to the daemon that holds it: a kill sent to the
   * other VM's socket answers "No such container", which is swallowed as the
   * normal race, and the container runs on. So a kill of a name held here goes
   * to the VM recorded with it, never to a default one.
   */
  readonly #running = new Map<string, Held>()

  constructor(options: DockerDriverOptions) {
    this.#options = options
    this.#binary = options.binary ?? 'docker'
  }

  /**
   * The ONLY environment a docker invocation gets.
   *
   * DOCKER_HOST and PATH, plus DOCKER_CONFIG when the kernel names one — all
   * built from kernel config rather than copied from the process. See this
   * file's header for why HOME is not among them.
   */
  #env(domain: 'trusted' | 'hostile'): Record<string, string> {
    return {
      ...(this.#options.dockerConfig === undefined ? {} : { DOCKER_CONFIG: this.#options.dockerConfig }),
      DOCKER_HOST: this.#options.domains[domain].dockerHost,
      PATH: this.#options.path ?? process.env['PATH'] ?? '/usr/bin:/bin',
    }
  }

  async probe(): Promise<ProbeResult> {
    let version: string
    try {
      const { stdout } = await this.#options.execFile(
        this.#binary,
        ['version', '--format', '{{.Server.Version}}'],
        { env: this.#env('trusted') },
      )
      version = stdout.trim()
      if (version === '') return { ok: false, why: 'docker version reported no server version' }
    } catch (e) {
      // Availability, never a throw: a kernel with no container runtime must
      // still boot and say why.
      return { ok: false, why: e instanceof Error ? e.message : String(e) }
    }

    // Invariant 9's "internal network", PROVEN per domain rather than assumed
    // from the name in kernel.yaml. Inside a Colima VM the Mac's loopback is
    // 192.168.5.2 (`host.lima.internal`, per Lima's user-mode network docs),
    // and pmmcp listens there unauthenticated: a container on a network with a
    // route out could call its vault and admin tools. `--internal` removes the
    // route; a network created by hand without it looks identical by name.
    for (const domain of DOMAINS) {
      const network = this.#options.domains[domain].network
      let internal: string
      try {
        const { stdout } = await this.#options.execFile(
          this.#binary,
          ['network', 'inspect', '--format', '{{.Internal}}', network],
          { env: this.#env(domain) },
        )
        internal = stdout.trim()
      } catch (e) {
        return {
          ok: false,
          why: `${domain}: network ${network} could not be inspected: ${e instanceof Error ? e.message : String(e)}`,
        }
      }
      if (internal !== 'true') {
        return {
          ok: false,
          why:
            `${domain}: network ${network} is not internal (Internal=${internal === '' ? '?' : internal}), so a ` +
            "container on it could reach the Mac's loopback (where pmmcp listens unauthenticated) and the " +
            `internet. Recreate it: docker network rm ${network} && docker network create --internal ${network}`,
        }
      }
    }
    return { ok: true, version }
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

    // Two live containers under one name, one on each VM, would leave
    // kill(name) unable to say which daemon to ask. Even on one VM, where
    // docker refuses the second itself, the refused run would overwrite the
    // first one's record and then erase it on exit.
    const holder = this.#running.get(spec.name)
    if (holder !== undefined) {
      throw new ConfigError(
        `container ${spec.name} is already running on the ${holder.domain} domain; a second one under that name could not be killed by name`,
      )
    }

    const startedAt = Date.now()
    const stdout = new Capture()
    const stderr = new Capture()
    let killedBy: SandboxResult['killedBy'] | undefined
    let settled = false

    const child = this.#options.spawn(this.#binary, args, { env: this.#env(spec.domain) })
    // Only once spawn has returned. A spawn that throws (Node refuses a NUL
    // in an argument synchronously) started nothing, and a record left behind
    // would refuse the name for the driver's lifetime and aim every later kill
    // of it at one VM.
    this.#running.set(spec.name, {
      domain: spec.domain,
      requested: () => {
        killedBy ??= 'requested'
      },
    })
    // Bounded, and drained past the bound: see Capture.
    child.stdout?.on('data', (chunk) => {
      stdout.add(chunk)
    })
    child.stderr?.on('data', (chunk) => {
      stderr.add(chunk)
    })

    const result = new Promise<SandboxResult>((resolve) => {
      // The hard wallclock. A container that ignores SIGTERM is why this goes
      // straight to KILL by name: the kernel must be able to end a run it no
      // longer trusts without negotiating. On the spec's own domain, which the
      // timer knows without asking anyone.
      //
      // Not yet hard enough, and to be closed when runs are wired (plan W1,
      // W2): this is one `docker kill` that nothing waits on, #killOn swallows
      // every failure (a transient "Cannot connect to the Docker daemon" too,
      // with no retry and no log line), and finish() below clears the timer
      // when the docker CLI child closes, though a CLI that dies first is
      // expected to leave its container running (the kill-by-name row of
      // docs/plan/phase-0-bootstrap.md; README, "Still needs validation"). The
      // deadline should stay armed until a kill by name succeeds or the daemon
      // says the container is gone.
      const timer = setTimeout(() => {
        killedBy = 'wallclock'
        void this.#killOn(spec.name, spec.domain)
      }, spec.limits.wallclockMs)
      timer.unref?.()

      const finish = (exitCode: number | null, signal: string | null): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        // Duplicates are refused while this entry stands, so it is this run's.
        this.#running.delete(spec.name)
        resolve({
          name: spec.name,
          exitCode,
          signal: signal === 'SIGKILL' || signal === 'SIGTERM' ? signal : null,
          ...(killedBy === undefined ? {} : { killedBy }),
          stdout: stdout.text(),
          stderr: stderr.text(),
          truncated: stdout.truncated || stderr.truncated,
          durationMs: Date.now() - startedAt,
        })
      }

      child.on('close', (code, signal) => {
        // The CLI exits 137 rather than by signal when its container is
        // killed; the kernel knows it sent KILL, so it says so.
        finish(code, killedBy === undefined ? signal : 'SIGKILL')
      })
      child.on('error', (error) => {
        stderr.add(error.message)
        finish(null, null)
      })
    })

    return { name: spec.name, result }
  }

  /**
   * Idempotent: killing an unknown or already-dead container is not an error.
   *
   * A container this driver started is killed on its own domain only. A name
   * it does not know (one that exited, one a previous kernel left, or one it
   * never ran) is tried on EVERY domain rather than refused: the map is
   * in-memory and empties on restart, so it cannot prove a name is dead, and a
   * kill that reaches no daemon leaves a container running. Asking a daemon
   * that lacks the name costs one "No such container". Both attempts start at
   * once, so a daemon that never answers cannot hold up the other VM's kill.
   *
   * A run it holds reports `killedBy: 'requested'` and SIGKILL, as the fake
   * driver does, unless its wallclock had already fired.
   */
  async kill(name: string): Promise<void> {
    const held = this.#running.get(name)
    held?.requested()
    const domains = held === undefined ? DOMAINS : [held.domain]
    await Promise.all(domains.map((domain) => this.#killOn(name, domain)))
  }

  /**
   * `docker kill` on one domain's daemon. Never rejects, and so far tells
   * nobody when a kill fails for a reason other than the container being
   * gone; see the wallclock in run().
   */
  async #killOn(name: string, domain: SandboxDomain): Promise<void> {
    try {
      await this.#options.execFile(this.#binary, ['kill', '--signal=KILL', name], {
        env: this.#env(domain),
      })
    } catch {
      // "No such container" is the normal outcome of a race between a
      // wallclock kill and a container that just exited, and of a kill asked
      // of a daemon that never held the name.
    }
  }

  /**
   * Kill every container the kernel left behind.
   *
   * Meant for boot: a kernel that crashed mid-run leaves a container holding
   * a workspace and a CPU, and nothing else will ever reap it. Nothing calls
   * it yet — boot only probes the driver, and no run starts a container — so
   * the boot sweep lands with the run wire-up (plan W2).
   */
  async sweepOrphans(): Promise<string[]> {
    const killed: string[] = []
    for (const domain of DOMAINS) {
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
        // On the daemon that listed it, which is the one that holds it.
        await this.#killOn(name, domain)
        killed.push(name)
      }
    }
    return killed
  }
}

/**
 * The real driver, wired to the real process APIs.
 *
 * This is the ONLY place in the kernel that imports node:child_process, and so
 * the only place that can spawn anything at all. The class above takes its
 * `spawn` and `execFile` as options precisely so that every test can drive it
 * without a process; this factory is where the production wiring lives, next to
 * the code that knows what a docker invocation must look like rather than in the
 * composer that merely asks for a driver.
 */
export function realDockerDriver(
  options: Omit<DockerDriverOptions, 'spawn' | 'execFile'>,
): DockerDriver {
  return new DockerDriver({
    ...options,
    spawn: (command, args, opts) => spawn(command, [...args], opts),
    execFile: (command, args, opts) => execFileAsync(command, [...args], opts),
  })
}
