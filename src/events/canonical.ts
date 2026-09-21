// Canonical JSON for hashing.
//
// Contract: `canonicalize` produces bytes that are identical to RFC 8785
// (JSON Canonicalization Scheme) over the domain it accepts, so an external
// auditor running any JCS library reproduces our hashes. Where JCS would
// silently convert, this refuses instead — an audit log wants a loud failure,
// not a quiet reinterpretation:
//
//   JCS                                    here
//   0.1, 1e+21, 1e-7, 2**53  serialized    throws (safe integers only)
//   Date                     toJSON()      throws (plain objects only)
//   { a: undefined }         key dropped   throws (no undefined)
//
// Those restrictions are what make the hash reproducible across processes and
// languages: no float formatting, no implicit coercion, no dropped keys. Money
// is integer micro-USD and timestamps are ISO-8601 strings, so nothing the
// kernel logs needs a fraction. zod already enforces the value domain at every
// boundary, so these throws are assertions about kernel bugs, not a runtime
// path an event can take.
//
// Changing anything in this file changes every hash the kernel has ever
// written. It is change-controlled (CLAUDE.md: "Ask before ... chain
// hashing").

import { createHash } from 'node:crypto'

/** A high surrogate with no low after it, or a low with no high before it. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/**
 * Serialize `v` to canonical JSON.
 *
 * @throws {TypeError} on any value outside the accepted domain.
 */
export function canonicalize(v: unknown): string {
  if (v === null) return 'null'
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false'
    case 'string':
      // JCS string escaping is exactly JSON.stringify's, except that JCS
      // refuses lone surrogates rather than emitting an escape for them.
      if (LONE_SURROGATE.test(v)) {
        throw new TypeError('lone surrogate in event string: not canonicalizable')
      }
      return JSON.stringify(v)
    case 'number':
      // Rejects NaN, Infinity, every non-integer and anything past 2**53-1.
      // String(-0) is '0', which is what JCS emits.
      if (!Number.isSafeInteger(v)) {
        throw new TypeError(`non-safe-integer in event: ${String(v)}`)
      }
      return String(v)
    case 'object': {
      if (Array.isArray(v)) {
        return `[${v.map((item) => canonicalize(item)).join(',')}]`
      }
      const proto: unknown = Object.getPrototypeOf(v)
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError('only plain objects may be canonicalized')
      }
      const record = v as Record<string, unknown>
      // Default sort() compares UTF-16 code units, which is the order RFC 8785
      // requires. Code-point order would put U+FF01 before U+1F600; this does
      // not, and the test pins that difference.
      const keys = Object.keys(record).sort()
      const parts = keys.map((k) => `${canonicalize(k)}:${canonicalize(record[k])}`)
      return `{${parts.join(',')}}`
    }
    default:
      // undefined, bigint, function, symbol.
      throw new TypeError(`unsupported value type ${typeof v} in event`)
  }
}

/** Lowercase hex SHA-256 of a UTF-8 string. */
export function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

/** Canonicalize then hash: the one way the kernel derives a value's digest. */
export function canonicalHash(v: unknown): string {
  return sha256Hex(canonicalize(v))
}
