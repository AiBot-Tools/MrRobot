// Value-scrubbing pass for the event log.
//
// Contract: nothing written to the log passes through here unscrubbed, and
// this runs BEFORE canonicalization and hashing. Order matters and is not
// negotiable — see src/events/bound.ts and the store's append path:
//
//   redact → bound → canonicalize → hash → insert
//
// Hashing after redaction is what makes the chain verifiable. If the hash were
// taken over the raw payload while the stored row held the redacted one, every
// row containing a credential would fail verifyChain, and the only "fix" would
// be to keep the raw bytes. So the stored bytes and the hashed bytes are the
// same bytes, always.
//
// This is defence in depth over pino's path-based redaction (src/log.ts),
// which cannot see into values at all. Here the key names AND the values are
// inspected, at any depth.
//
// Change-controlled: CLAUDE.md requires asking before touching redaction.

/**
 * Key names whose value is replaced wholesale, whatever it looks like.
 * Matching is case-insensitive and applies at any depth.
 */
export const DENY_KEYS =
  /^(authorization|proxy-authorization|cookie|set-cookie|api[_-]?key|x-api-key|token|access_token|refresh_token|id_token|secret|client_secret|password|passwd|private_key|credentials?)$/i

/**
 * Credential shapes recognised inside string values, wherever they appear —
 * in a message, a shell command, a URL, or a blob of JSON that arrived as a
 * string. Deliberately broader than a scanner's rules would be: a false
 * positive costs a censored log line, a false negative leaks a live key.
 */
export const TOKEN_PATTERNS: readonly RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*/g, // any bearer credential
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}/g, // OpenAI sk-…, Anthropic sk-ant-…
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g, // GitHub ghp_/gho_/ghu_/ghs_/ghr_
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g, // GitHub fine-grained
  /\bxox[abeprs]-[A-Za-z0-9-]{10,}/g, // Slack
  /\bxapp-[A-Za-z0-9-]{10,}/g, // Slack app-level
  /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g, // AWS access key id
  /\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWT
  /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/g,
]

export const CENSOR = '[REDACTED]'

/** Shortest value the mask will accept, so a common word can never be registered. */
export const MIN_MASK_LENGTH = 8

/**
 * Exact known secret values, registered by the secrets broker the moment it
 * resolves one and before the router can send it anywhere.
 *
 * Pattern matching only catches credential shapes we anticipated. A pmmcp
 * vault entry may be an opaque string of no recognisable form, so the broker
 * tells the mask what it just handled and every later occurrence is censored
 * by exact substring — which is why the mask runs before the regexes.
 */
export class SecretMask {
  static #values = new Set<string>()

  /** Register a secret. Returns false for values too short to be safe to match. */
  static register(value: string): boolean {
    if (typeof value !== 'string' || value.length < MIN_MASK_LENGTH) return false
    SecretMask.#values.add(value)
    return true
  }

  /** Forget every registered value. Tests use this; the daemon does not. */
  static clear(): void {
    SecretMask.#values.clear()
  }

  static get size(): number {
    return SecretMask.#values.size
  }

  /** Replace every registered value by exact substring, longest first. */
  static apply(s: string): string {
    if (SecretMask.#values.size === 0) return s
    // Longest first, so a secret that contains another secret is not left
    // half-censored by the shorter one.
    const values = [...SecretMask.#values].sort((a, b) => b.length - a.length)
    let out = s
    for (const v of values) out = out.split(v).join(CENSOR)
    return out
  }
}

/** Scrub a string: registered secrets first, then credential shapes. */
export function redactString(s: string): string {
  let out = SecretMask.apply(s)
  for (const re of TOKEN_PATTERNS) out = out.replace(re, CENSOR)
  return out
}

/**
 * Scrub a value of any shape. `key` is the property name this value was found
 * under, which is what lets a deny-listed key censor an otherwise
 * unrecognisable value.
 */
export function redactValue(v: unknown, key?: string): unknown {
  if (key !== undefined && DENY_KEYS.test(key)) return CENSOR
  if (typeof v === 'string') return redactString(v)
  if (Array.isArray(v)) return v.map((item) => redactValue(item))
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, item]) => [k, redactValue(item, k)]),
    )
  }
  return v
}
