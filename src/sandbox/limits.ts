// The values a container's --user, resource caps and network may take
// (invariant 9), and the one image it may run.
//
// Each is checked twice: by the kernel.yaml schema, so the operator's file
// cannot name one, and by the run-args audit (docker.ts), so no other path to
// the driver can either. A shape check alone is not enough, because docker
// reads well-formed values as the absence of the property: `--user 0:0` is
// root, `--user 65534:0` is root's group, `--memory 0`, `--pids-limit 0` (or
// -1) and `--cpus 0` are no limit at all, and `--network name=host` is the
// VM's own network stack.

/**
 * The largest uid or gid admitted. runc refuses an id above 2^31 - 1, and
 * bounding it here also rules out any reader that would wrap a larger one
 * round to 0.
 */
const ID_MAX = 2 ** 31 - 1

/** `uid:gid`, both numeric, and neither 0: not root, and not root's group. */
export function isUnprivilegedUser(value: string): boolean {
  const m = /^([1-9]\d{0,9}):([1-9]\d{0,9})$/.exec(value)
  return m !== null && Number(m[1]) <= ID_MAX && Number(m[2]) <= ID_MAX
}

const MEMORY_UNITS: Readonly<Record<string, number>> = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }

/**
 * The bytes a --memory value names, or undefined unless it is a positive whole
 * number followed by one unit, k, m or g in either case. No unit is refused as
 * well as 0: docker reads a bare number as bytes, and a fraction of one as 0.
 * The value must stay an exact integer, far below where docker's int64 would
 * overflow.
 */
export function memoryBytes(value: string): number | undefined {
  const m = /^([1-9]\d{0,15})([kmg])$/i.exec(value)
  const unit = MEMORY_UNITS[(m?.[2] ?? '').toLowerCase()]
  if (m === null || unit === undefined) return undefined
  const bytes = Number(m[1]) * unit
  return Number.isSafeInteger(bytes) ? bytes : undefined
}

/** A --pids-limit value: a positive whole number. */
export function isPidsLimit(value: string): boolean {
  return /^[1-9]\d{0,15}$/.test(value)
}

/** A --cpus value: a positive decimal number. */
export function isCpus(value: string): boolean {
  return /^\d{1,6}(\.\d{1,6})?$/.test(value) && Number(value) > 0
}

/**
 * A --network value docker reads as the name of a network: a letter or digit,
 * then letters, digits, `_`, `.` or `-`. Anything else may be read as more
 * than a name. The docker CLI (29) takes a value holding `\w+=\w+` anywhere
 * for its key=value syntax: CSV fields, each lower-cased, whose `name=` is the
 * network, so `name=host` and `NAME=HOST` are host, and `name=x,alias=y` adds
 * to the attachment. A plain name still admits the names docker gives a mode
 * of its own (host, bridge, default, none); the audit refuses those it must.
 */
export function isNetworkName(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value)
}

/**
 * The plain names docker keeps for networks of its own: `host`, the VM's own
 * network stack, and `bridge` and `default`, its default bridge, which has a
 * route off the VM. None is internal, and docker refuses to remove or create
 * a predefined network, so none can be made a domain's.
 *
 * Compared without regard to case, as the run-args audit (docker.ts) compares
 * them, though docker does not: it reads a plain mode name case-sensitively
 * (NetworkMode.IsHost is n == "host"), so a plain `HOST` names a network of
 * that name. Its key=value spelling lower-cases, and `name=HOST` is host, so
 * no case of these is admitted.
 *
 * Two more are predefined in moby (IsPreDefinedNetwork) and left out here:
 * `none`, docker's name for no network at all, which the egress plan's S1
 * moves every worker onto (and which probe() should then not inspect for
 * Internal, since there is no network to inspect), and `ingress`, swarm's
 * routing mesh, which exists only on a swarm node. probe() still inspects a
 * domain that names either, and its advice for one would be a command docker
 * refuses; that is S1's to settle, or the operator's.
 */
export function isDockerNetworkMode(value: string): boolean {
  return ['host', 'bridge', 'default'].includes(value.toLowerCase())
}

/**
 * An image id as docker prints one (`docker image inspect --format {{.Id}}`):
 * `sha256:` and 64 lower-case hex digits, nothing else. Not a name: a tag is
 * whatever image was last given it on that VM, and `name@sha256:<digest>` is a
 * repository digest, a name the daemon resolves and the CLI may pull. The id
 * names the image's own content, and the worker runs by nothing else (the
 * operator's decision, egress plan P4), always with --pull=never.
 */
export function isImageId(value: string): boolean {
  return /^sha256:[0-9a-f]{64}$/.test(value)
}

/**
 * Why `imageId` cannot pin the worker image, or undefined when it can: none is
 * pinned (kernel.yaml ships none until the image is built) or it is not an id.
 * The docker driver's probe() reports it, before asking any daemon anything,
 * and every run is refused for it (imageRefusal).
 */
export function imageIdProblem(imageId: string | undefined): string | undefined {
  if (imageId === undefined) {
    return (
      'sandbox.imageId is not set in config/kernel.yaml, which ships none: the worker image is built on the ' +
      "operator's VMs, and its id is theirs to pin. " +
      'The driver runs the worker image only by that pinned id, with --pull=never, and never pulls one, so no run ' +
      'can be built until it is set. Build the image with scripts/build-worker-image.sh, which is still to be ' +
      'written, on the trusted VM and load it into the hostile one, then set sandbox.imageId to the ' +
      'sha256:<64 hex> id it prints'
    )
  }
  if (!isImageId(imageId)) {
    return (
      `sandbox.imageId ${JSON.stringify(imageId)} is no image id: it must be sha256:<64 lower-case hex>, as ` +
      '`docker image inspect --format {{.Id}}` prints one; a tag or a repository digest is a name the VM resolves'
    )
  }
  return undefined
}

/**
 * Why a run whose image slot holds `image` is refused, or undefined when that
 * is the pinned id, exactly. A tag names whatever image was last given it on
 * that VM, a repository digest (`name@sha256:...`) is a name the daemon
 * resolves, and a different id is an image nobody pinned; with no valid id
 * pinned, every run is refused. The docker driver's audit throws this for its
 * image slot (docker.ts, assertTheImage), and the tests' fake driver for a
 * spec's image, in the same words, so that code tested against the fake meets
 * the refusals docker would.
 */
export function imageRefusal(image: string, imageId: string | undefined): string | undefined {
  const problem = imageIdProblem(imageId)
  if (problem !== undefined) return `docker args cannot be built: ${problem}`
  if (image === imageId) return undefined
  if (isImageId(image)) {
    return `docker args run image ${image}, which is not the pinned sandbox.imageId ${String(imageId)}; the driver runs no other`
  }
  return (
    `docker args run ${JSON.stringify(image)}, which is no image id but a name the VM's daemon resolves to whatever ` +
    `image it last gave that name; the driver runs only the pinned sandbox.imageId ${String(imageId)}`
  )
}
