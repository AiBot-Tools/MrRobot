// Process logger.
//
// Contract: this logger records ids, types, sizes, hashes and decisions —
// never payloads, tool outputs, provider request bodies or the environment.
// Redaction here is a *backstop* for known structured fields, not the
// mechanism that keeps secrets out of the record: pino's redaction is strictly
// path-based, so it never inspects values, never touches `msg`, and its
// wildcard matches exactly one level. The event log's own value-scrubbing pass
// is what handles unknown shapes; see src/events.
//
// Never log a secret value (CLAUDE.md, "Never"). If a field might hold one,
// log its hash or its length instead.

import pino from 'pino'

/** Replacement written in place of a redacted value. */
export const CENSOR = '[REDACTED]'

/**
 * Paths pino redacts. Hyphenated keys require bracket notation, which is why
 * `x-api-key` appears four times rather than once: it is the header the pinned
 * Anthropic SDK actually sends, so losing it would leak a live provider
 * credential into the process log.
 *
 * Paths must never be built from user input (pino's own warning).
 */
export const REDACT_PATHS: readonly string[] = [
  'authorization',
  '*.authorization',
  'headers.authorization',
  'req.headers.authorization',
  'req.headers.cookie',
  '["x-api-key"]',
  '*["x-api-key"]',
  'headers["x-api-key"]',
  'req.headers["x-api-key"]',
  'apiKey',
  '*.apiKey',
  'api_key',
  '*.api_key',
  'token',
  '*.token',
  'secret',
  '*.secret',
  'password',
  '*.password',
  'env.*',
]

/** Level resolution, so tests and the daemon agree on the default. */
export function resolveLevel(env: NodeJS.ProcessEnv = process.env): string {
  const level = env['AOS_LOG_LEVEL']
  return level === undefined || level.trim() === '' ? 'info' : level
}

export interface LoggerOptions {
  readonly level?: string
  readonly destination?: pino.DestinationStream
}

/**
 * Build a logger with the kernel's redaction configuration. Tests construct
 * their own against a capture stream so they exercise the same paths the
 * daemon runs with.
 */
export function createLogger(options: LoggerOptions = {}): pino.Logger {
  const opts: pino.LoggerOptions = {
    level: options.level ?? resolveLevel(),
    redact: { paths: [...REDACT_PATHS], censor: CENSOR },
  }
  return options.destination === undefined ? pino(opts) : pino(opts, options.destination)
}

/** The process-wide logger. */
export const log: pino.Logger = createLogger()
