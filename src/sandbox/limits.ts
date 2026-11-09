// The values a container's --user and resource caps may take (invariant 9).
//
// Each is checked twice: by the kernel.yaml schema, so the operator's file
// cannot name one, and by the run-args audit (docker.ts), so no other path to
// the driver can either. A shape check alone is not enough, because docker
// reads well-formed values as the absence of the property: `--user 0:0` is
// root, `--user 65534:0` is root's group, `--memory 0`, `--pids-limit 0` (or
// -1) and `--cpus 0` are no limit at all.

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
