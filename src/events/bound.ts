// Bounded output for the event log.
//
// Contract: the log never stores a raw tool output larger than
// MAX_LOGGED_OUTPUT (CLAUDE.md, "Never"). What it stores instead is a
// redacted prefix plus a digest of the redacted whole, so an auditor can
// prove the prefix really is a prefix of what the kernel saw without the log
// having to hold the rest.
//
// Two decisions here are load-bearing:
//
// 1. Redact first, then measure and truncate. Truncating first could cut a
//    credential in half and leave the front of it stored forever.
// 2. The digest is over the REDACTED full text, never the raw text. A
//    sha256 of raw output in an append-only log is a permanent commitment to
//    whatever secret it contained: anyone holding a candidate value — or any
//    value from a small space, like a PIN — can confirm it offline. Hashing
//    the redacted text still proves prefix-hood and commits to nothing.

import { sha256Hex } from './canonical.js'
import { redactString } from './redact.js'

/** Largest redacted text stored inline, in bytes. */
export const MAX_LOGGED_OUTPUT = 65_536

export interface BoundedOutput {
  /** Redacted text, truncated on a UTF-8 code point boundary if needed. */
  readonly text: string
  readonly truncated: boolean
  /** Byte length of the redacted text before truncation. */
  readonly bytes: number
  /** sha256 of the full REDACTED text. Present only when truncated. */
  readonly sha256?: string
}

/**
 * Largest cut at or below `max` bytes that lands on a code point boundary.
 * The input is valid UTF-8, so it is enough to walk back over continuation
 * bytes (10xxxxxx): the first byte that is not one begins a code point, and
 * everything before it is complete.
 */
function utf8CutPoint(buf: Buffer, max: number): number {
  if (buf.length <= max) return buf.length
  let end = max
  while (end > 0) {
    const b = buf[end]
    if (b === undefined || (b & 0xc0) !== 0x80) break
    end--
  }
  return end
}

/**
 * Redact `raw`, then bound it. Below the limit the result is the redacted
 * text with no digest; above it, a boundary-safe prefix plus the digest of
 * the redacted whole.
 */
export function boundOutput(raw: string, max: number = MAX_LOGGED_OUTPUT): BoundedOutput {
  const redacted = redactString(raw)
  const buf = Buffer.from(redacted, 'utf8')
  const bytes = buf.length
  if (bytes <= max) {
    return { text: redacted, truncated: false, bytes }
  }
  const cut = utf8CutPoint(buf, max)
  return {
    text: buf.subarray(0, cut).toString('utf8'),
    truncated: true,
    bytes,
    sha256: sha256Hex(redacted),
  }
}
