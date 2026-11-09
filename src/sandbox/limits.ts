// The values a container's --user, resource caps and network may take
// (invariant 9).
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
 * a predefined network, so none can be made a domain's. Compared without
 * regard to case, as the run-args audit (docker.ts) compares them. `none`,
 * docker's name for no network at all, is left to the caller.
 */
export function isDockerNetworkMode(value: string): boolean {
  return ['host', 'bridge', 'default'].includes(value.toLowerCase())
}
