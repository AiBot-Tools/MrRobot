// Control-plane authorisation at the HTTP upgrade (invariant 1).
//
// Authentication happens ONCE, here, before a WebSocket exists. After the
// upgrade there is no per-frame credential to check and no way to present one:
// the protocol freeze (T28) has no field for it. That is the whole design —
// a socket is either authorised or it was never opened.
//
// A token in the query string is refused even when a valid header is also
// present. It is not a fallback and not a convenience: a URL travels through
// process lists, shell history, proxy logs, browser history and crash
// reporters, none of which are places a credential survives being written
// down. Refusing the request rather than ignoring the parameter is the point —
// a client that sends one has a bug the operator needs to see, and silently
// honouring the header would hide it until the token leaked.
//
// Tokens are compared as sha256 DIGESTS with timingSafeEqual. Digesting first
// is what makes the comparison possible at all: timingSafeEqual throws on
// unequal lengths, so comparing raw tokens would either crash on a short
// guess or force a length check that leaks the real length. Digests are always
// 32 bytes, so every comparison takes the same shape.

import { createHash, timingSafeEqual } from 'node:crypto'

import { ConfigError } from '../errors.js'

/** The only path the control plane serves. */
export const CONTROL_PATH = '/v1'

/**
 * Enforced floor, not a recommendation. The README suggests
 * `openssl rand -hex 32`; the length is checked, the entropy is the
 * operator's.
 */
export const MIN_TOKEN_LENGTH = 32

/**
 * Query keys that make a request a refusal rather than a mistake.
 *
 * Wider than the three the plan names, because the failure is the same
 * whatever the parameter is called and a near-miss spelling is not a reason
 * to accept it.
 */
export const FORBIDDEN_QUERY_KEYS: readonly string[] = [
  'token',
  'access_token',
  'auth',
  'authorization',
  'bearer',
  'api_key',
  'apikey',
  'key',
  'secret',
  'password',
  'credential',
  'credentials',
]

export type RejectReason = 'missing_token' | 'bad_token' | 'query_token' | 'bad_origin' | 'bad_upgrade'

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0:0:0:0:0:0:0:1'])

/**
 * An http(s) origin on a loopback host, which is admitted without being
 * listed. Anything else — including `tauri://localhost` and the lookalike
 * `http://tauri.localhost`, which is a PUBLIC hostname under the localhost
 * TLD and not loopback at all — must appear in allowedOrigins (D10).
 */
export function isLoopbackHttpOrigin(value: string): boolean {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  const host = url.hostname.replace(/^\[|\]$/g, '')
  return LOOPBACK_HOSTS.has(host) || /^127\.\d+\.\d+\.\d+$/.test(host)
}

export function digestToken(raw: string): Buffer {
  return createHash('sha256').update(raw, 'utf8').digest()
}

/**
 * Validate the operator's token and return the form to digest.
 *
 * @throws {ConfigError} when absent or shorter than MIN_TOKEN_LENGTH after
 *   trimming. Refusing to boot is deliberate: a control plane with a weak or
 *   missing token is a control plane anyone on the machine can drive, and a
 *   warning at boot is a warning nobody reads.
 */
export function assertTokenUsable(raw: string | undefined): string {
  const token = (raw ?? '').trim()
  if (token === '') {
    throw new ConfigError(
      'AOS_CONTROL_TOKEN is not set. The control plane refuses to start without one.',
    )
  }
  if (token.length < MIN_TOKEN_LENGTH) {
    throw new ConfigError(
      `AOS_CONTROL_TOKEN is ${String(token.length)} characters after trimming; ` +
        `at least ${String(MIN_TOKEN_LENGTH)} are required. Try: openssl rand -hex 32`,
    )
  }
  return token
}

export interface UpgradeHeaders {
  readonly authorization?: string | string[] | undefined
  readonly origin?: string | string[] | undefined
}

export interface UpgradeAttempt {
  /** Request target as the server received it, e.g. `/v1?x=1`. */
  readonly url: string | undefined
  readonly headers: UpgradeHeaders
}

export interface AuthorizeOptions {
  readonly tokenDigest: Buffer
  readonly allowedOrigins: readonly string[]
}

export type AuthorizeResult =
  | { readonly ok: true; readonly origin?: string }
  | { readonly ok: false; readonly reason: RejectReason; readonly origin?: string }

function single(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined
  // A duplicated header is ambiguous, and ambiguity in an auth header is a
  // request to be refused rather than guessed at.
  if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined
  return value
}

/**
 * Decide whether one upgrade may become a socket.
 *
 * Checks run from structural facts to the credential, so the recorded reason
 * is the most fundamental true thing about the attempt — the same ordering
 * principle as the policy gate.
 */
export function authorizeUpgrade(
  attempt: UpgradeAttempt,
  options: AuthorizeOptions,
): AuthorizeResult {
  // A relative target needs a base to parse against; the base is discarded.
  let url: URL
  try {
    url = new URL(attempt.url ?? '/', 'http://127.0.0.1')
  } catch {
    return { ok: false, reason: 'bad_upgrade' }
  }

  if (url.pathname !== CONTROL_PATH) return { ok: false, reason: 'bad_upgrade' }

  for (const key of url.searchParams.keys()) {
    if (FORBIDDEN_QUERY_KEYS.includes(key.toLowerCase())) {
      // Refused, not ignored — even with a valid header alongside.
      return { ok: false, reason: 'query_token' }
    }
  }

  const origin = single(attempt.headers.origin)
  if (origin !== undefined) {
    const allowed = options.allowedOrigins.includes(origin) || isLoopbackHttpOrigin(origin)
    if (!allowed) return { ok: false, reason: 'bad_origin', origin }
  }

  const header = single(attempt.headers.authorization)
  if (header === undefined) return { ok: false, reason: 'missing_token', ...(origin === undefined ? {} : { origin }) }

  const match = /^Bearer (.+)$/.exec(header)
  if (match?.[1] === undefined) {
    return { ok: false, reason: 'missing_token', ...(origin === undefined ? {} : { origin }) }
  }

  const presented = digestToken(match[1].trim())
  if (!timingSafeEqual(presented, options.tokenDigest)) {
    return { ok: false, reason: 'bad_token', ...(origin === undefined ? {} : { origin }) }
  }

  return { ok: true, ...(origin === undefined ? {} : { origin }) }
}
