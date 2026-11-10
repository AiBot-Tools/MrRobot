// Docker driver (invariant 9).
//
// The argv this file builds IS the sandbox. Everything that makes a container
// safe is a flag, and a flag that is absent fails open and silently: the
// container runs, the work succeeds, and nobody finds out the root filesystem
// was writable until something uses it. So the flag set is built in one pure
// function and then AUDITED by that same function before it is returned —
// exactly one bind mount, read as docker reads it, no --privileged, no docker
// socket, no home directory, a --user that is not root and resource caps that
// are not 0, nothing before the image that the builder did not emit, nothing
// there that widens the container by name (an environment, a published port, a
// terminal, a detached client, an extra host or resolver, a shared namespace,
// an unconfined security option, a device, another runtime, kernel parameters
// or cgroup parent, a supplementary group, a log driver, a writable root
// filesystem, another mount or network, a pull) in any spelling docker reads,
// exactly one --network, and that one none, exactly one -i on a run that asks
// for a channel and none on any other, and exactly one --pull=never before an
// image that is the pinned sandbox.imageId — and a future edit that widens
// any of those throws rather than producing a container.
//
// A container has no network at all: --network none gives it a loopback
// interface of its own and nothing else, so no route, no resolver, no address
// on any network of the VM's and no peer there. A worker's one way out is
// the kernel's egress engine (src/egress), over its own run's `docker run -i`
// channel: a spec's `channel`, which this driver opens on the trusted domain
// only (egress plan S2) and hands to its caller as the CLI's own stdin and
// stdout, reading none of it. Nothing asks for one yet, since the engine is
// not wired (egress plan W1): until it is, a worker reaches nothing. Each
// domain's internal network (aos-trusted and aos-hostile in kernel.yaml)
// stays all the same, and probe() still proves it Internal=true on that
// domain's own VM, as defence in depth, the operator's decision of
// 2026-11-09, to be revisited at the Phase 2 exit: no run is put on it, and
// the audit refuses a run on any network but none.
//
// The image is run by its id, never by a name. A tag is whatever image was
// last given it on that VM, so it pins nothing, and a name the VM lacks is
// pulled by default, by the VM's daemon over the VM's own route out, which no
// container's --network covers: what then runs is whatever the registry
// serves. So the image is the sha256 id the operator pinned, with
// --pull=never, and while no id is pinned the driver reports itself degraded
// and builds no run at all. The probe also asks each VM for the pinned id and
// reports the sandbox degraded, naming the domain, while one lacks it.
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
// matter only for registry pulls, which this driver never does. It runs
// `version`, `network inspect`, `image inspect`, `run`, `kill` and `ps`, and
// nothing else, and the image it runs is a locally built one, by its id and
// with --pull=never.
//
// The whole process environment is never passed. A worker that inherited the
// kernel's environment would receive every provider key the operator exported
// (invariant 2), which is the failure the kernel's egress engine (src/egress)
// exists to prevent in Phase 2, by injecting each credential at the kernel's
// edge and never in the container, and which must not be possible before it
// ships.

import { execFile, spawn } from 'node:child_process'
import { Readable, Writable } from 'node:stream'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

import { ConfigError } from '../errors.js'
import { recordable } from '../events/bound.js'
import { homeDirectory, realpathNearest } from '../agents/protected.js'
import { confineWorkspace } from './confine.js'
import {
  imageIdProblem,
  imageRefusal,
  isCpus,
  isImageId,
  isDockerNetworkMode,
  isNetworkName,
  isNoNetwork,
  isPidsLimit,
  isUnprivilegedUser,
  memoryBytes,
} from './limits.js'
import {
  CAPTURE_MAX_BYTES,
  CONTAINER_PREFIX,
  channelRefusal,
  readSpecOnce,
  type ProbeResult,
  type RunningSandbox,
  type SandboxChannel,
  type SandboxDomain,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from './driver.js'

// The prefix every kernel container's name carries: the interface's rule
// (driver.ts), re-exported for the callers that build names for this driver.
export { CONTAINER_PREFIX }

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
  ['--pull=never', 'flag'],
])

/**
 * The one option only a channel run carries: docker's -i (--interactive),
 * which keeps the container's stdin open and joined to the CLI's, so that
 * the CLI's stdin and stdout are one byte stream to the container. The audit
 * admits it exactly once on a run that asks for a channel, and never on any
 * other; RUN_OPTIONS is every other run's whole list.
 */
const CHANNEL_OPTION = '-i'
const CHANNEL_RUN_OPTIONS: ReadonlyMap<string, 'flag' | 'value'> = new Map([...RUN_OPTIONS, [CHANNEL_OPTION, 'flag']])

/**
 * What makes docker's CSV reader split a --mount value other than at its
 * commas: a double quote starts a quoted field (which may hold a comma), and a
 * line break ends the record. Other control characters are refused with them,
 * because nothing legitimate puts one in a path.
 */
const MOUNT_QUOTING = /["\p{Cc}]/u
/** And in a path written into that value, a comma starts a field of its own. */
const MOUNT_STRUCTURE = /[,"\p{Cc}]/u

/**
 * docker run's one-letter options (docker CLI 29) and whether each takes a
 * value. Docker's flag parser (pflag) reads a group such as `-it` as `-i -t`,
 * and `-eKEY` or `-e=KEY` as `-e KEY`: the first letter that takes a value
 * ends the group, and the rest of it is that value. A letter not listed is no
 * option of docker's, which then refuses the command; the group is read on
 * past it, so that a refused letter after it is still named.
 */
const SHORT_OPTIONS: ReadonlyMap<string, readonly [long: string, takesValue: boolean]> = new Map([
  ['a', ['--attach', true]],
  ['c', ['--cpu-shares', true]],
  ['d', ['--detach', false]],
  ['e', ['--env', true]],
  ['h', ['--hostname', true]],
  ['i', ['--interactive', false]],
  ['l', ['--label', true]],
  ['m', ['--memory', true]],
  ['p', ['--publish', true]],
  ['P', ['--publish-all', false]],
  ['q', ['--quiet', false]],
  ['t', ['--tty', false]],
  ['u', ['--user', true]],
  ['v', ['--volume', true]],
  ['w', ['--workdir', true]],
])

/**
 * Why an option widens the container, judged on the value it carries
 * (undefined when there is none) and whether that value shares its element
 * (`--flag=value`). Undefined passes it on to RUN_OPTIONS, which still
 * refuses anything the builder does not emit.
 */
type Widens = (value: string | undefined, inline: boolean) => string | undefined

/**
 * --pid, --ipc, --uts, --cgroupns, --userns, as docker reads them, which is
 * case-sensitively (PidMode.IsHost is n == "host"): `host` for each, and
 * `container:<id>` for the two that have a container mode, --pid and --ipc.
 * --uts, --cgroupns and --userns have none, and docker refuses one. Any other
 * value (`HOST`, `Container:<id>`, a `container:<id>` for --uts) is no mode
 * docker reads, so it widens nothing and is left to RUN_OPTIONS, which
 * refuses it as an option the builder never emits.
 */
function sharesNamespace(what: string, joinsContainers: boolean): Widens {
  return (value) => {
    const v = value ?? ''
    if (v === 'host') return `shares the VM's ${what} namespace with the container`
    if (joinsContainers && v.startsWith('container:')) return `shares another container's ${what} namespace with this one`
    return undefined
  }
}

/**
 * What docker makes of a --network value other than the network of that name:
 * the modes it gives a name of its own (host, container:<id>, bridge,
 * default), none of them internal, and any value that is not a plain network
 * name (sandbox/limits.ts), which its CLI may read as key=value fields whose
 * `name=` can say host. `none` is a plain name and no network at all: the
 * builder's own --network, which this admits, and the audit then holds the one
 * --network to (assertTheNetwork). A domain may not name it (domainNetwork).
 *
 * Docker compares the plain mode names case-sensitively (NetworkMode.IsHost is
 * n == "host"), so a plain `HOST` names a network called HOST. Only the
 * key=value spelling is lower-cased, and `name=HOST` is host. So host, bridge
 * and default are refused in any case, and the reason a case variant gets says
 * that, not that it is the mode.
 */
function networkMode(value: string): string | undefined {
  if (value === 'host') return "puts the container on the VM's own network stack, which reaches the Mac at 192.168.5.2"
  if (value.startsWith('container:')) return "puts the container in another container's network namespace"
  if (value === 'bridge' || value === 'default') return "puts the container on docker's default bridge, which has a route off the VM"
  const v = value.toLowerCase()
  if (isDockerNetworkMode(v)) {
    return (
      `spells ${v} in another case, which docker reads as a network of that name, but docker's key=value ` +
      `spelling lower-cases (name=${value} is ${v}), so no case of ${v} is admitted`
    )
  }
  if (!isNetworkName(value)) {
    return (
      'names no plain network (a letter or digit, then letters, digits, _, . or -), and docker reads a value ' +
      "holding = as key=value fields, whose name= can be host: the VM's own network stack"
    )
  }
  return undefined
}

/**
 * Why a domain may not name `network` as its internal network, or undefined
 * when it may: whatever networkMode refuses in a --network, and docker's none,
 * in any case. No run is put on a domain's network (every one is on none); it
 * is kept beside none as defence in depth, and probe() inspects it for
 * Internal=true. none is no network to inspect so: it is a predefined network
 * of docker's, not one created --internal, which docker neither removes nor
 * recreates, so probe()'s advice to recreate it would be a command docker
 * refuses, and a domain that named it would have no internal network at all.
 * Docker compares the name as spelled, so a plain NONE names a network called
 * NONE, but its key=value spelling lower-cases (name=NONE is none), so no case
 * of none is admitted, as with host, bridge and default (isNoNetwork).
 */
function domainNetwork(network: string): string | undefined {
  const mode = networkMode(network)
  if (mode !== undefined) return mode
  if (!isNoNetwork(network)) return undefined
  if (network === 'none') {
    return "is docker's none, no network at all, which every run is on already, and no internal network for probe() to prove"
  }
  return (
    "spells none in another case, which docker reads as a network of that name, but docker's key=value spelling " +
    `lower-cases (name=${network} is none), so no case of none is admitted`
  )
}

/**
 * What Go's strconv.ParseBool reads as true, and as false, exactly as it
 * spells them: docker's flag parser (pflag) reads a boolean flag's value with
 * it, and its daemon a --security-opt boolean. Any other spelling (`fALSE`,
 * `yes`) is one ParseBool refuses, and so docker.
 */
const PARSE_BOOL_TRUE: readonly string[] = ['1', 't', 'T', 'TRUE', 'true', 'True']
const PARSE_BOOL_FALSE: readonly string[] = ['0', 'f', 'F', 'FALSE', 'false', 'False']

/**
 * The --security-opt keys docker reads (docker CLI and daemon 29), spelled as
 * it spells them: it compares a key case-sensitively, so `SECCOMP` is none.
 */
const SECURITY_KEYS: readonly string[] = ['no-new-privileges', 'seccomp', 'apparmor', 'label', 'writable-cgroups', 'systempaths']

/**
 * --security-opt, read as docker's CLI reads it: split at the first `=`, or
 * at the first `:` in the older spelling, and compared case-sensitively, key
 * and value. The builder sets no-new-privileges and nothing else, so every
 * other key takes a confinement away or replaces it — and `seccomp=<file>`
 * has the CLI read that file on the Mac and send it as the filter. That is
 * what `seccomp=UNCONFINED` and `seccomp=BUILTIN` do, since the CLI takes only
 * `unconfined` and `builtin`, as spelled, for profiles of docker's own; and a
 * profile name is case-sensitive, so `apparmor=UNCONFINED` names an AppArmor
 * profile of its own, as `apparmor=DOCKER-DEFAULT` does. `seccomp=builtin`
 * replaces too: the daemon then applies docker's built-in profile in place of
 * the one it was configured with (daemon.json's seccomp-profile), which may be
 * stricter. scripts/colima-up.sh configures no daemon profile, so on the VMs
 * it starts this changes nothing; it is named all the same, since the
 * daemon's configuration is not this file's to know.
 *
 * What takes nothing away is left to RUN_OPTIONS, which refuses it as an
 * option the builder never emits. no-new-privileges and writable-cgroups are
 * ParseBool booleans: no-new-privileges is turned off only by a value it reads
 * as false, and the cgroups made writable only by one it reads as true; any
 * other value keeps the default, or is one docker refuses.
 * `apparmor=docker-default` names docker's own default profile, the one it
 * applies anyway: AppArmor has no daemon-level profile for it to replace.
 * Only `systempaths=unconfined`, as spelled, unmasks /proc and /sys: the CLI
 * acts on that string alone and sends any other systempaths on to the daemon,
 * which reads no such key. And one of these keys in another case is no key
 * docker reads, which it refuses.
 *
 * A key outside them is refused by name all the same, over-named on purpose:
 * docker 29 refuses it, but a later docker may read it, and this list must
 * hold if RUN_OPTIONS ever admits a --security-opt beyond the builder's.
 */
function unconfines(value: string | undefined): string | undefined {
  const opt = value ?? ''
  let at = opt.indexOf('=')
  if (at === -1 && opt !== 'no-new-privileges') at = opt.indexOf(':')
  const key = at === -1 ? opt : opt.slice(0, at)
  const v = at === -1 ? '' : opt.slice(at + 1)
  switch (key) {
    case 'no-new-privileges':
      return PARSE_BOOL_FALSE.includes(v) ? 'turns no-new-privileges off' : undefined
    case 'seccomp':
      if (v === 'unconfined') return 'removes the seccomp filter'
      if (v === 'builtin') return "replaces the daemon's own seccomp profile, if it was configured with one, with docker's built-in one"
      return 'replaces the default seccomp filter'
    case 'apparmor':
      if (v === 'unconfined') return 'removes the AppArmor profile'
      return v === 'docker-default' ? undefined : 'replaces the default AppArmor profile'
    case 'label':
      return 'changes or disables the SELinux labels'
    case 'writable-cgroups':
      return PARSE_BOOL_TRUE.includes(v) ? "makes the container's cgroup filesystem writable" : undefined
    case 'systempaths':
      return opt === 'systempaths=unconfined' ? 'unmasks the /proc and /sys paths docker hides' : undefined
  }
  if (SECURITY_KEYS.includes(key.toLowerCase())) return undefined
  return 'sets a security option the builder never sets'
}

/**
 * --read-only, a boolean. Docker's flag parser (pflag) gives a boolean a value
 * only in its own element, `--read-only=<v>`, and reads it with Go's
 * strconv.ParseBool: only a value it reads as false makes the root writable.
 * A value it cannot read (`fALSE`) is refused by docker, and by RUN_OPTIONS.
 */
function writableRoot(value: string | undefined, inline: boolean): string | undefined {
  if (!inline) return undefined
  return PARSE_BOOL_FALSE.includes(value ?? '') ? "makes the container's root filesystem writable" : undefined
}

/**
 * --pull, as the docker CLI reads it: `missing`, its default, pulls the image
 * when the VM lacks it, and `always` on every run. The pull is the VM's
 * daemon's, over the VM's own route out, which no container network covers,
 * and what runs is then whatever the registry served. Only `never` keeps a run
 * to an image already on the VM.
 *
 * Any other value (an empty one, `NEVER`, `yes`) is refused as a value the
 * builder never writes, over-named on purpose, as unconfines() names a key
 * docker 29 refuses. What docker makes of it is not claimed here: it refuses
 * some, and a later docker may read one as a pull. `--pull never`, in two
 * elements, pulls nothing and is left to RUN_OPTIONS, which refuses it as a
 * spelling the builder never emits.
 */
function pulls(value: string | undefined): string | undefined {
  if (value === 'never') return undefined
  if (value === 'missing' || value === 'always') {
    return (
      "has the VM's daemon pull the image over the VM's own route out, when the VM lacks it (missing, docker's " +
      'default) or on every run (always), so that what runs is whatever the registry serves; only never is admitted'
    )
  }
  return (
    'sets --pull to a value the builder never writes, refused whatever docker makes of it, since a later docker ' +
    'may read it as a pull; only never is admitted'
  )
}

/**
 * Options refused before the image, in every spelling docker reads:
 * `--flag value`, `--flag=value`, and a letter in a group. A string refuses
 * the option whatever its value; a function judges the value. RUN_OPTIONS,
 * above, is what the builder emits and refuses each of these anyway: this
 * list is what stays refused when an edit widens RUN_OPTIONS and the builder
 * together, and the reason the refusal gives. `--env`, `--dns` and
 * `--publish` stand for their families: `--env-file` (which also has the
 * docker CLI read a file on the Mac, `.env` among them), `--dns-search`,
 * `--dns-option`, `--dns-opt` and `--publish-all`. The `--env` family is
 * matched by prefix rather than spelled out because hygiene.test.ts refuses
 * Node's env-file flag written in any line of src/ code. `--privileged`,
 * `--cap-add` and `--device` are refused anywhere in the argv by
 * FORBIDDEN_FLAGS, above; `--device-cgroup-rule` and `--gpus` reach devices
 * past that exact match, and so are named here. `--detach` is here because
 * the run's hard wallclock lives as long as the docker client does: a client
 * that returns at once clears it. `--group-add`, the log options and
 * `--read-only=false` undo, by another route, what --user, --network none and
 * --read-only give, and a `--pull` other than never undoes the pinned image
 * id. A second `--network` or `--mount` written as the builder writes its own
 * is caught by the count of each option, and the one --network value is then
 * held to none (assertTheNetwork). A second one in any other spelling is
 * refused here, and not for what docker would make of it beside none (which a
 * later docker may read otherwise): a worker is on no network at all.
 */
const WIDENING: ReadonlyMap<string, string | Widens> = new Map<string, string | Widens>([
  ['--env', "sets variables in the container's environment, where no credential may be (invariant 2)"],
  [
    '--network',
    (value, inline) =>
      networkMode(value ?? '') ??
      (inline ? "names a network beside the builder's --network none, where a worker is on no network at all" : undefined),
  ],
  ['--net', "is --network under another name, a network beside the builder's --network none, where a worker is on no network at all"],
  ['--add-host', "writes a name into the container's /etc/hosts, host.lima.internal for the Mac among them"],
  ['--dns', "sets the container's resolver configuration"],
  ['--publish', 'publishes a container port on the VM'],
  ['--link', "joins another container's network and copies its environment into this one"],
  ['--tty', "allocates a pseudo-terminal, which merges the container's stderr into its stdout and rewrites its bytes"],
  ['--ipc', sharesNamespace('IPC', true)],
  ['--uts', sharesNamespace('UTS', false)],
  ['--cgroupns', sharesNamespace('cgroup', false)],
  ['--pid', sharesNamespace('PID', true)],
  ['--userns', sharesNamespace('user', false)],
  ['--security-opt', unconfines],
  ['--volumes-from', 'mounts every volume another container has'],
  ['--volume', 'binds a path or a volume beside the one workspace mount'],
  [
    '--mount',
    (_value, inline) =>
      inline ? 'adds a mount beside the one workspace mount, which the builder writes as --mount <value>' : undefined,
  ],
  ['--use-api-socket', "mounts the docker API socket, and with it the VM's daemon"],
  [
    '--detach',
    "returns as soon as the container starts, and the run's hard wallclock is cleared when the docker client exits, so the container outlives it",
  ],
  ['--device-cgroup-rule', 'lets the container use device nodes the default device cgroup denies'],
  ['--gpus', "gives the container the VM's GPUs, devices that --device would have to name"],
  ['--runtime', 'runs the container under an OCI runtime the builder never chose, with whatever confinement that one has'],
  ['--sysctl', "sets kernel parameters in the container's namespaces, its network stack's among them"],
  ['--cgroup-parent', "puts the container's cgroup under a parent the builder never chose"],
  ['--group-add', "gives the container's user a supplementary group, root's (0) as readily as any, though --user may not name root's group"],
  [
    '--log-driver',
    "has the VM's dockerd ship the container's output through a driver the builder never chose: syslog, gelf, fluentd " +
      "or splunk send it to an address such as 192.168.5.2, the Mac, over the VM's own route, which the container's " +
      '--network none does not cover',
  ],
  ['--log-opt', "configures the container's log driver, the address it ships the container's output to among them"],
  ['--read-only', writableRoot],
  ['--pull', pulls],
])

/** Options whose family shares their refusal: `--dns-search` is `--dns`'s. */
const WIDENING_FAMILIES = ['--env', '--dns', '--publish']

function widensAs(name: string): string | Widens | undefined {
  const family = WIDENING_FAMILIES.find((f) => name.startsWith(`${f}-`))
  return WIDENING.get(name) ?? (family === undefined ? undefined : WIDENING.get(family))
}

/**
 * What one element before the image widens, read as docker reads it, with
 * `next` the element after it (the value of `--flag value`), and the option as
 * the refusal names it. An option refused whatever its value is named without
 * one, because the value of `--env` is what must not be printed; one refused
 * for its value is named with the value that decided it.
 */
function widening(arg: string, next: string | undefined): { readonly named: string; readonly why: string } | undefined {
  const judge = (option: string, value: string | undefined, inline: boolean): string | undefined => {
    const rule = widensAs(option)
    return typeof rule === 'function' ? rule(value, inline) : rule
  }
  const valued = (option: string): boolean => typeof widensAs(option) === 'function'
  if (arg.startsWith('--')) {
    const eq = arg.indexOf('=')
    const name = eq === -1 ? arg : arg.slice(0, eq)
    const value = eq === -1 ? next : arg.slice(eq + 1)
    const why = judge(name, value, eq !== -1)
    if (why === undefined) return undefined
    if (!valued(name)) return { named: name, why }
    return { named: eq === -1 ? `${name} ${JSON.stringify(value ?? '')}` : JSON.stringify(arg), why }
  }
  for (let i = 1; i < arg.length; i++) {
    const letter = arg.charAt(i)
    const short = SHORT_OPTIONS.get(letter)
    if (short === undefined) continue
    const [long, takesValue] = short
    const rest = arg.slice(i + 1)
    const value = takesValue ? (rest === '' ? next : rest.replace(/^=/, '')) : undefined
    const why = judge(long, value, takesValue && rest !== '')
    if (why !== undefined) {
      const named = `-${letter} (${long})`
      return { named: valued(long) ? `${named} ${JSON.stringify(value ?? '')}` : named, why }
    }
    if (takesValue) break
  }
  return undefined
}

export interface DomainConfig {
  readonly dockerHost: string
  /**
   * The domain's internal network, which probe() proves Internal=true on the
   * domain's own VM, as defence in depth. No run is put on it: buildRunArgs
   * never reads it, and every run is --network none.
   */
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
  /**
   * The pinned image id, `sha256:<64 hex>` (kernel.yaml's sandbox.imageId), and
   * the only image a run may name: the spec's image is a request, held to it
   * by the audit, as its workspace is held to the mountRoot. Undefined while
   * the operator has pinned none, which refuses every run.
   */
  readonly imageId: string | undefined
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
  // Each of the spec's fields read once, and every decision below made from
  // that one reading (driver.ts, readSpecOnce): a channel judged false and
  // then emitted as -i, or a name checked for the prefix and then put in the
  // argv as another, is a spec read twice.
  const spec = readSpecOnce(input.spec)
  const { domain, defaults } = input
  const home = input.home ?? homeDirectory()

  if (!spec.name.startsWith(CONTAINER_PREFIX)) {
    throw new ConfigError(`container name "${spec.name}" must start with ${CONTAINER_PREFIX}`)
  }

  // A channel only where one is admitted (driver.ts, channelRefusal): never on
  // the hostile domain, and never for a value that is no boolean. Refused
  // before anything is resolved, as the fake driver refuses it, and decided
  // from the same reading the refusal judged.
  const refusedChannel = channelRefusal(spec)
  if (refusedChannel !== undefined) throw new ConfigError(refusedChannel)
  const channel = spec.channel === true

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
    // No network at all: a loopback of its own, and no route, resolver or
    // peer. The one way out is the kernel's egress engine over this run's
    // docker -i channel (egress plan S2, W1), one allowed host at a time. Not
    // the domain's internal network: probe() still proves that one internal,
    // as defence in depth, but no run is put on it.
    '--network',
    'none',
    // PID 1 that reaps zombies and forwards signals, so a kill actually kills.
    // On every run, with a channel or without: whatever the command, what it
    // orphans is reaped rather than left a zombie against --pids-limit, and a
    // SIGTERM ends it. A channel run's mux relies on it (images/worker/mux.mjs).
    '--init',
    // The channel (SandboxSpec.channel): the container's stdin held open and
    // joined to the CLI's, on a run that asks for one and on no other, which
    // the audit holds it to.
    ...(channel ? [CHANNEL_OPTION] : []),
    // The root is read-only, so scratch space has to come from somewhere that
    // cannot hold a setuid binary or be executed from.
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,nodev,size=64m',
    // Exactly one mount, and this is it.
    '--mount',
    `type=bind,source=${workspace},target=${WORKSPACE_TARGET}`,
    '--workdir',
    WORKSPACE_TARGET,
    // The image is never pulled: one the VM lacks fails the run, rather than
    // being fetched by the VM's daemon over the VM's own route. The audit
    // holds the image after it to the pinned id.
    '--pull=never',
    spec.image,
    ...spec.command,
  ]

  auditRunArgs(args, home, workspace, input.imageId, channel)
  return args
}

/**
 * Prove the argv says what it should, before it becomes a container.
 *
 * This is deliberately a separate pass over the finished array rather than a
 * set of conditions spread through the builder: it catches a widening
 * introduced anywhere above, including in `spec.command`.
 *
 * It takes no network: the one --network must be none whatever the domain
 * names (assertTheNetwork), and a domain's own network never reaches the argv.
 * What a domain may name is kernel.yaml's to refuse, and probe()'s.
 *
 * It takes whether the run asked for a channel, since that alone decides
 * whether -i belongs: exactly once on a run with one, never on a run without.
 * Without it, as by default, -i is refused. Which domain may have a channel
 * is the builder's to refuse (channelRefusal), before an argv exists.
 */
export function auditRunArgs(
  args: readonly string[],
  home: string,
  workspace: string,
  imageId: string | undefined,
  channel = false,
): void {
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
  // the image is the first element that is not an option. Before that, each
  // element is read for what it widens (WIDENING), so that the refusal names
  // it and holds whatever RUN_OPTIONS comes to admit. After the image, every
  // element is the command's, which docker passes on unread: `grep -e`,
  // `ls -t` and `ssh -p` are not docker's -e, -t and -p, and nothing from here
  // on reads them so.
  //
  // The whole-argv scans above still do: FORBIDDEN_FLAGS, the --mount and -v
  // count and the home check read the command too, so `grep -v x` is refused
  // as a second mount, `python train.py --device cpu` as a device and
  // `--privileged` as a command argument as the flag. That over-refusal is
  // kept on purpose until the operator decides otherwise (it narrows an
  // invariant 9 check), and the decision is one for the count and
  // FORBIDDEN_FLAGS together, both of which read what docker obeys: when
  // sandbox.exec commands are exposed (S3), they may move before the image,
  // where WIDENING and RUN_OPTIONS already read every element. Until then
  // FORBIDDEN_FLAGS stays whole-argv like the count. FORBIDDEN_SUBSTRINGS and
  // the home check stay whole-argv in either case: what they refuse is a path
  // the command itself could name, the docker socket or the operator's home.
  if (args[0] !== 'run') {
    throw new ConfigError(`docker args must start with run (found ${JSON.stringify(args[0] ?? '')})`)
  }
  // Every option this run's argv may carry: a channel run's list is every
  // other run's and -i.
  const admitted = channel ? CHANNEL_RUN_OPTIONS : RUN_OPTIONS
  const seen = new Map<string, number>()
  const values = new Map<string, string>()
  let mount: string | undefined
  let at = 1
  for (let arg = args[at]; arg !== undefined && arg.startsWith('-'); arg = args[at]) {
    const widened = widening(arg, args[at + 1])
    if (widened !== undefined) {
      throw new ConfigError(
        `docker args carry ${widened.named} before the image, which the builder never emits, and docker would obey it: ` +
          `it ${widened.why}, which invariant 9 refuses in any spelling`,
      )
    }
    const kind = admitted.get(arg)
    if (kind === undefined && arg === CHANNEL_OPTION) {
      throw new ConfigError(
        `docker args carry ${CHANNEL_OPTION} before the image on a run that asks for no channel: it would hold the ` +
          "container's stdin open and joined to the CLI's, which only a channel run has",
      )
    }
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
  for (const option of admitted.keys()) {
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
  // The image docker runs, which --pull=never (there exactly once, by the
  // count above) keeps it from pulling: it must be the pinned id.
  assertTheImage(args[at] ?? '', imageId)

  // Each once, by the count above, so this is the value docker uses — and,
  // for --network, the container's one network mode.
  for (const option of CAP_VALUES.keys()) assertCapValue(option, values.get(option) ?? '')
  assertTheMount(mount ?? '', workspace)
  assertTheNetwork(values.get('--network') ?? '')
}

/**
 * The image slot must hold the pinned id, exactly, and the pinned value must
 * be an id: imageRefusal (limits.ts) says why not, in the words the fake
 * driver uses for the same spec, and that is thrown whatever spec, edit or
 * config put the image there.
 */
function assertTheImage(image: string, imageId: string | undefined): void {
  const refused = imageRefusal(image, imageId)
  if (refused !== undefined) throw new ConfigError(refused)
}

/**
 * The one --network value must be none, exactly: no network at all, so the
 * container has its own loopback and nothing else (invariant 9, as the
 * operator worded it on 2026-11-09). Any other value is a network, and every
 * network gives a container something none does not: an address on the VM,
 * docker's embedded resolver, and peers, the domain's internal network among
 * them, which probe() proves has no route off the VM but which every other
 * container on it shares. The domain's network is not an alternative: no run
 * is put on it.
 *
 * Compared as spelled, since docker compares a network name so: a plain NONE
 * is a network called NONE. What docker makes of any other value is not
 * judged here: WIDENING's --network rule has already refused host, bridge,
 * default, container:<id> and anything but a plain name in every --network
 * before the image. This holds the value that is left to the one it must be.
 */
function assertTheNetwork(value: string): void {
  if (value !== 'none') {
    throw new ConfigError(
      `docker args put the container on network ${JSON.stringify(value)}; invariant 9 needs --network none, ` +
        'no network at all',
    )
  }
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
 * stdin is the CLI's: a channel run's output (with stdout, a Readable then,
 * its input), and closed at once on any other run.
 */
export interface ChildLike {
  readonly stdin: Writable | null
  readonly stdout: { on(event: 'data', cb: (chunk: Buffer | string) => void): void } | null
  readonly stderr: { on(event: 'data', cb: (chunk: Buffer | string) => void): void } | null
  on(event: 'close', cb: (code: number | null, signal: string | null) => void): unknown
  /**
   * The CLI's exit, which comes before 'close': Node closes a child only once
   * its pipes have ended as well, and a channel run's stdout is its caller's
   * to read, so the caller decides when that is. A spawn that started no
   * process emits 'error' and no 'exit'.
   */
  on(event: 'exit', cb: (code: number | null, signal: string | null) => void): unknown
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
  /**
   * kernel.yaml's sandbox.imageId: the one image every run executes, by id.
   * Undefined while none is pinned, and then probe() reports why and every
   * run() is refused (BuildArgsInput.imageId). Required rather than optional,
   * so that a caller that forgets it does not compile.
   */
  readonly imageId: string | undefined
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

/**
 * A channel run's two pipes as the channel its caller reads and writes, or
 * undefined when the child has them not: Node gives a child none only when
 * its spawn failed for want of file descriptors, and that spawn's 'error'
 * then ends the run. Each stream's 'error' is heard here at once, so that a
 * container that closes its stdin (the kernel's next write then fails,
 * EPIPE) never throws in the kernel for want of a listener, whoever reads the
 * channel and whenever they start listening; what is heard goes to the run's
 * stderr, as a spawn's error does.
 */
function channelOf(child: ChildLike, stderr: Capture): SandboxChannel | undefined {
  const { stdin, stdout } = child
  if (!(stdout instanceof Readable) || !(stdin instanceof Writable)) return undefined
  stdout.on('error', (error) => {
    stderr.add(`channel input: ${error.message}\n`)
  })
  stdin.on('error', (error) => {
    stderr.add(`channel output: ${error.message}\n`)
  })
  return { input: stdout, output: stdin }
}

/**
 * The most of docker's refusal a probe's reason quotes, in UTF-8 bytes. The
 * reason goes into the hash-chained log for good (sandbox.degraded.reason),
 * and a failed call's error is the command line and whatever the daemon
 * wrote to stderr, as much as execFile buffers: text the kernel does not
 * size. Docker's own refusals ("No such image", "Cannot connect to the Docker
 * daemon") come to a few hundred bytes, command line and all.
 */
export const PROBE_ERROR_BYTES = 1_024

/** What docker said when one of probe()'s calls failed: redacted, and cut to PROBE_ERROR_BYTES (recordable). */
function dockerSaid(e: unknown): string {
  return recordable(e instanceof Error ? e.message : String(e), PROBE_ERROR_BYTES)
}

/** A run this driver is holding, by name. */
interface Held {
  readonly domain: SandboxDomain
  /**
   * Mark the run as one kill(name) was sent for, unless its wallclock already
   * fired or its CLI has already exited (the kill then ended nothing). Whether
   * a kill sent before the exit ended it is the CLI's exit to say (run()).
   */
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
    // No run can be built without a pinned image, whatever the daemons say,
    // so none is asked anything: degraded, saying which key to set and how to
    // get its value, and nothing pulled now or at a run.
    const image = imageIdProblem(this.#options.imageId)
    if (image !== undefined) return { ok: false, why: image }
    // imageIdProblem has passed it, so it is an id, sha256:<64 hex>.
    const imageId = String(this.#options.imageId)

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
      return { ok: false, why: dockerSaid(e) }
    }

    // Each domain's internal network, PROVEN internal on its own VM rather
    // than assumed from the name in kernel.yaml. No run is put on it: every
    // run is --network none (buildRunArgs). It is kept, and proved, as
    // defence in depth (the operator's decision of 2026-11-09, until the
    // Phase 2 exit), so that a container that ever lands on it has no route
    // out. Inside a Colima VM the Mac's loopback is 192.168.5.2
    // (`host.lima.internal`, per Lima's user-mode network docs), and pmmcp
    // listens there unauthenticated: a container on a network with a route
    // out could call its vault and admin tools. `--internal` removes the
    // route; a network created by hand without it looks identical by name.
    for (const domain of DOMAINS) {
      const network = this.#options.domains[domain].network
      // A name docker keeps for a network of its own (host, bridge, default,
      // and none, which every run is on already), or reads as more than a
      // name, in any case, is not a network `inspect` can vouch for, and
      // docker refuses to remove or create the predefined ones, so the advice
      // below would be a command that cannot run. Each is refused here
      // without inspecting it (domainNetwork). kernel.yaml refuses these
      // names; a driver handed its domains by another path meets this.
      const notByName = domainNetwork(network)
      if (notByName !== undefined) {
        return {
          ok: false,
          why:
            `${domain}: network ${JSON.stringify(network)} is not one a domain may name: as --network it ` +
            `${notByName}. Name the domain's own internal network in kernel.yaml ` +
            `(docker network create --internal aos-${domain})`,
        }
      }
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
          why: `${domain}: network ${network} could not be inspected: ${dockerSaid(e)}`,
        }
      }
      if (internal !== 'true') {
        // What docker printed goes into the hash-chained log for good
        // (sandbox.degraded.reason), as #imageMissingOn's does: the boolean
        // {{.Internal}} prints is quoted, and anything else, text the kernel
        // does not size, only named.
        const printed = internal === 'false' ? 'false' : internal === '' ? '?' : 'something that is no boolean'
        return {
          ok: false,
          why:
            `${domain}: network ${network} is not internal (Internal=${printed}), so a ` +
            "container on it could reach the Mac's loopback (where pmmcp listens unauthenticated) and the " +
            `internet. Recreate it: docker network rm ${network} && docker network create --internal ${network}`,
        }
      }

      // The pinned image, on this domain's own VM, by id. Each run names it
      // with --pull=never, so a VM that lacks it pulls nothing, but every run
      // there fails at docker with no such image: an image built on the
      // trusted VM and never loaded into the hostile one would leave the
      // sandbox reported ok and every hostile run failing. And docker must
      // print the pin itself as the image's id: the pin is what it prints
      // (isImageId), and an id it prints differently is not the one pinned.
      // `image inspect` reads the VM's own store and never pulls.
      const missing = await this.#imageMissingOn(domain, imageId)
      if (missing !== undefined) return { ok: false, why: missing }
    }
    return { ok: true, version }
  }

  /**
   * Why the pinned image cannot run on `domain`'s VM, or undefined when that
   * VM's daemon has it and prints the pin as its id.
   */
  async #imageMissingOn(domain: SandboxDomain, imageId: string): Promise<string | undefined> {
    let printed: string
    try {
      const { stdout } = await this.#options.execFile(
        this.#binary,
        ['image', 'inspect', '--format', '{{.Id}}', imageId],
        { env: this.#env(domain) },
      )
      printed = stdout.trim()
    } catch (e) {
      // Loaded, never built here: a docker build is not reproducible (the
      // image config records when it was made), so a build on this VM gives
      // the image another id, and pinning that one breaks the other VM.
      return (
        `${domain}: the pinned sandbox.imageId ${imageId} could not be inspected on this domain's VM, so every run ` +
        `there would fail at docker, which is told never to pull it: ${dockerSaid(e)}. ` +
        'Load the worker image into this VM (docker save on the VM that built it, docker load on this one), so ' +
        'that both VMs hold it under the one pinned id'
      )
    }
    if (printed === imageId) return undefined
    // What docker says goes into the hash-chained log for good
    // (sandbox.degraded.reason), so it is bounded there: its refusal, above,
    // cut by dockerSaid, and what it printed shown only when it reads as an
    // id, which is bounded, and otherwise only named.
    const what = printed === '' ? 'no id' : isImageId(printed) ? `the id ${printed}` : 'something that is no image id'
    return (
      `${domain}: docker image inspect ${imageId} printed ${what} on this domain's VM, not the pinned ` +
      'sandbox.imageId: pin the id `docker image inspect --format {{.Id}}` prints for the worker image, the same ' +
      'on both VMs'
    )
  }

  run(given: SandboxSpec): RunningSandbox {
    // Read once, here, and decided from that reading alone (driver.ts,
    // readSpecOnce): the domain this picks the VM by, its mountRoot and its
    // environment, the channel the builder judges and the one whose pipes the
    // result hands over, and the name that is held and killed, are then one
    // domain, one channel and one name. `given` is read nowhere else.
    const spec = readSpecOnce(given)
    const domain = this.#options.domains[spec.domain]
    const args = buildRunArgs({
      spec,
      domain,
      defaults: this.#options.defaults,
      repoRoot: this.#options.repoRoot,
      imageId: this.#options.imageId,
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

    // buildRunArgs has refused any other value, and a channel off the trusted
    // domain, judging this same reading: -i is in the argv exactly when this
    // is true.
    const channel = spec.channel === true
    const startedAt = Date.now()
    const stdout = new Capture()
    const stderr = new Capture()
    /** Who sent a kill: whether it ended the run is the CLI's exit to say (finish). */
    let killSentBy: SandboxResult['killedBy'] | undefined
    /** The wallclock fired, whatever its kill then did. */
    let overran = false
    let settled = false
    /** When the CLI exited: where the run's wallclock and duration end. */
    let exitedAt: number | undefined

    const child = this.#options.spawn(this.#binary, args, { env: this.#env(spec.domain) })
    // Only once spawn has returned. A spawn that throws (Node refuses a NUL
    // in an argument synchronously) started nothing, and a record left behind
    // would refuse the name for the driver's lifetime and aim every later kill
    // of it at one VM.
    this.#running.set(spec.name, {
      domain: spec.domain,
      requested: () => {
        // A kill sent once the CLI has exited ends nothing: its container had
        // ended on its own, and the exit the CLI gave is the run's own, which
        // the result reports. A channel run's CLI closes only once its caller
        // has read the input to its end, and its name is held until then, so
        // a kill (a tear-down's, say) can come long after the exit.
        if (exitedAt === undefined) killSentBy ??= 'requested'
      },
    })
    // A channel run's stdin and stdout are its caller's, and the driver
    // writes and reads neither: its stdout is not captured, and the result's
    // stdout stays empty. Any other run's stdin is closed at once: without -i
    // the CLI reads none of it, and a pipe into the run left open is a way in
    // that nothing asked for.
    const opened = channel ? channelOf(child, stderr) : undefined
    if (opened === undefined) child.stdin?.destroy()
    if (!channel) {
      // Bounded, and drained past the bound: see Capture.
      child.stdout?.on('data', (chunk) => {
        stdout.add(chunk)
      })
    }
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
      // with no retry and no log line), and the timer is cleared when the
      // docker CLI child exits ('exit', below; finish() clears it too, for a
      // spawn that started nothing), though a CLI that dies first is expected
      // to leave its container running (the kill-by-name row of
      // docs/plan/phase-0-bootstrap.md; README, "Still needs validation"). A
      // channel gives any caller a way to make it die first: a caller that
      // destroys the channel's input (an egress session aborting on a
      // protocol violation, say) closes the read end of the CLI's stdout, the
      // CLI's next copy of container output fails with EPIPE (docker run
      // catches every signal to relay it and relays no SIGPIPE, so Go returns
      // the broken pipe as a write error rather than dying of it), and the
      // CLI is expected to exit while its --rm container runs on unattached,
      // its 'exit' clearing this timer. Not verified offline. Hence the
      // channel's rule, a run is ended by kill(name) and never by destroying
      // or abandoning its input (SandboxChannel), and the README row that
      // asks what the CLI does then. The deadline should stay armed until a
      // kill by name succeeds or the daemon says the container is gone, for
      // this case as for a CLI killed from outside. Until then, a wallclock
      // kill that ends nothing (it reached no daemon, and the container later
      // exited on its own) leaves the result no killedBy (finish, below):
      // `overran` is then the only trace of the breach, and W1 must log the
      // run from it, not from killedBy.
      const timer = setTimeout(() => {
        killSentBy = 'wallclock'
        overran = true
        void this.#killOn(spec.name, spec.domain)
      }, spec.limits.wallclockMs)
      timer.unref?.()

      const finish = (exitCode: number | null, signal: string | null): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        const endedAt = exitedAt ?? Date.now()
        // Duplicates are refused while this entry stands, so it is this run's.
        this.#running.delete(spec.name)
        // A kill the kernel sent ended the run only when the CLI's exit shows
        // one, and the CLI exits 137 when its container is killed: the kernel
        // sends only KILL, so a 143 (a container SIGTERMed) is never its kill.
        // A CLI that dies by a signal shows nothing of its container: it
        // forwards every signal it can catch to the container (sig-proxy) and
        // exits with the container's status, so one that dies by a signal met
        // one it cannot catch, a SIGKILL from outside, or one that came before
        // it had installed its handlers, and its container is expected to run
        // on (the wallclock note above). It reports that signal, and no
        // killedBy. Any other exit means the kill ended nothing: it reached no
        // daemon, or landed after the container had exited on its own, and
        // the run reports that exit, as the fake does for a script whose kill
        // ends nothing (ignoresKill); so does a spawn that started no process
        // ('error' below), even after a kill. A run the kernel did end says
        // so, with SIGKILL, and credits the wallclock's kill if the wallclock
        // fired before the run ended, and otherwise the requested kill: a
        // wallclock that fires after a requested kill reached no daemon is the
        // one whose kill a 137 shows, and a requested kill sent after the
        // wallclock fired (an operator's, a shutdown's) does not take the
        // credit from it, though it was the last kill sent. (A 137 the
        // container came to by another route, the OOM killer, after a kill
        // that reached no daemon, is credited to the kill: the CLI's exit
        // cannot tell the two apart; the fake refuses to script one,
        // ignoresKill with exitCode 137.) A 137 with no kill sent is the
        // run's own, and reports no killedBy; so is one whose only kill was
        // sent after the CLI had exited (the run's `requested`, and the timer
        // is cleared at the exit), which the fake gives for a kill of a run
        // that has ended.
        const endedBy = exitCode === 137 ? killSentBy : undefined
        resolve({
          name: spec.name,
          exitCode,
          signal: endedBy !== undefined ? 'SIGKILL' : signal === 'SIGKILL' || signal === 'SIGTERM' ? signal : null,
          ...(endedBy === undefined ? {} : { killedBy: endedBy }),
          ...(overran ? { overran: true as const } : {}),
          stdout: stdout.text(),
          stderr: stderr.text(),
          truncated: stdout.truncated || stderr.truncated,
          durationMs: endedAt - startedAt,
        })
      }

      // The run ends, for its wallclock and its duration, when the CLI exits,
      // which it does once its container has. Its result settles at 'close',
      // once its pipes have ended too, and a channel run's stdout ends when
      // its caller has read it: a caller that holds the input past the
      // deadline, after a container that exited in time, would otherwise have
      // the timer fire, send a kill to a container that is gone, and report a
      // wallclock breach that never happened (SandboxResult.overran), with
      // the hold counted as the run's time. On a run without a channel the
      // two come together, as the driver drains its stdout itself.
      child.on('exit', () => {
        exitedAt ??= Date.now()
        clearTimeout(timer)
      })
      child.on('close', (code, signal) => {
        finish(code, signal)
      })
      child.on('error', (error) => {
        stderr.add(error.message)
        // A spawn that started no process leaves Node's pipes pending, never
        // to end. The channel's are closed here, so that its input has ended
        // by the time the result settles, as a started run's has: its CLI
        // closes only once its pipes have.
        opened?.input.destroy()
        opened?.output.destroy()
        finish(null, null)
      })
    })

    return { name: spec.name, result, ...(opened === undefined ? {} : { channel: opened }) }
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
   * A run it holds and ends reports `killedBy: 'requested'` and SIGKILL, with
   * the CLI's 137, as the fake driver does, unless its wallclock fired before
   * the run ended.
   * One the kill does not end (see finish() in run()) reports its own exit.
   * It resolves once the `docker kill` has returned, before the CLI closes,
   * so the name is still held then; the run's result says when it ended.
   *
   * A name without CONTAINER_PREFIX is no container of the kernel's: run()
   * refuses one, so this driver never started it, and sweepOrphans skips one
   * a daemon lists. A kill of it is sent nowhere, which keeps the contract
   * (not an error) without reaching someone else's container on either VM.
   */
  async kill(name: string): Promise<void> {
    if (!name.startsWith(CONTAINER_PREFIX)) return
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
   *
   * Every domain is listed at once, as kill() asks every domain at once: a
   * daemon that accepts the connection and never answers `ps` (no execFile
   * timeout stands behind it) must not stop the other VM being listed and
   * swept. The names are those of the trusted VM, then the hostile one's.
   */
  async sweepOrphans(): Promise<string[]> {
    const swept = await Promise.all(DOMAINS.map((domain) => this.#sweepOn(domain)))
    return swept.flat()
  }

  /**
   * List one domain's orphans, then kill them all on it at once.
   *
   * By name, so never with `--quiet`: the docker CLI ignores a custom
   * `--format` when `--quiet` is set ("WARNING: Ignoring custom format,
   * because both --format and --quiet are set.") and prints container IDs,
   * which the prefix check below drops every one of, and the sweep would
   * kill nothing. Nor `--no-trunc`: it is for IDs and commands, and a name is
   * never cut short without it; on names it only adds a linked container's
   * legacy `--link` aliases, comma-joined, to the one name wanted.
   */
  async #sweepOn(domain: SandboxDomain): Promise<string[]> {
    let stdout: string
    try {
      ;({ stdout } = await this.#options.execFile(
        this.#binary,
        ['ps', '--filter', `name=${CONTAINER_PREFIX}`, '--format', '{{.Names}}'],
        { env: this.#env(domain) },
      ))
    } catch {
      return []
    }
    // Only ours. A filter is a request, not a guarantee.
    const names = stdout.split('\n').map((s) => s.trim()).filter((s) => s.startsWith(CONTAINER_PREFIX))
    // On the daemon that listed each, which is the one that holds it, and all
    // at once, so that one kill which never returns holds up no other.
    await Promise.all(names.map((name) => this.#killOn(name, domain)))
    return names
  }
}

/**
 * The two functions through which the driver reaches the docker CLI. Only
 * realDockerDriver binds them to node:child_process; a test hands its own.
 */
export type DockerProcesses = Pick<DockerDriverOptions, 'spawn' | 'execFile'>

/**
 * The real driver, wired to the real process APIs.
 *
 * This is the ONLY place in the kernel that imports node:child_process, and so
 * the only place that can spawn anything at all. The class above takes its
 * `spawn` and `execFile` as options precisely so that every test can drive it
 * without a process; this factory is where the production wiring lives, next to
 * the code that knows what a docker invocation must look like rather than in the
 * composer that merely asks for a driver. The composer (kernel.ts's
 * defaultDriver) builds a DockerDriver itself only when a test hands it its own
 * DockerProcesses, and then from that test's functions, never from these.
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
