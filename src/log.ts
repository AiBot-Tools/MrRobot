// Process logger.
//
// Contract: this logger records ids, types, sizes, hashes and decisions —
// never payloads, tool outputs, provider request bodies or the environment.
// Redaction here is a *backstop*, not the mechanism that keeps secrets out of
// the record, and it has two layers:
//
//   - pino's path redaction (REDACT_PATHS) censors known structured fields.
//     It is strictly path-based: it never inspects values, never touches
//     `msg`, and its wildcard matches exactly one level.
//   - Every serialized line then passes through the event log's string
//     scrubber (redactString: values SecretMask has registered, then
//     TOKEN_PATTERNS) on every string in the record, at any depth — `msg`,
//     an error's message and stack, child bindings. This is what keeps a
//     credential that a library quotes in an error (a server echoing a bearer
//     in its 401 body) out of stdout and the launchd log.
//
// Never log a secret value (CLAUDE.md, "Never"). If a field might hold one,
// log its hash or its length instead.

import pino from 'pino'

import { redactString } from './events/redact.js'

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

/** Every string in a parsed record, scrubbed as the event log scrubs strings. */
function scrubStrings(v: unknown): unknown {
  if (typeof v === 'string') return redactString(v)
  if (Array.isArray(v)) return v.map(scrubStrings)
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, item]) => [k, scrubStrings(item)]))
  }
  return v
}

/**
 * One serialized pino line, scrubbed. Parsed rather than matched as text, so a
 * registered value is found even where JSON escaping changed its spelling (a
 * `"` or `\` in it) and the censor cannot split a JSON string. A line that
 * does not parse is scrubbed as text: never written unscrubbed.
 */
export function scrubLogLine(line: string): string {
  const body = line.endsWith('\n') ? line.slice(0, -1) : line
  try {
    return `${JSON.stringify(scrubStrings(JSON.parse(body)))}\n`
  } catch {
    return redactString(line)
  }
}

/** A destination that writes only scrubbed lines to `inner`. */
function scrubbing(inner: pino.DestinationStream): pino.DestinationStream {
  return {
    write(line: string): void {
      inner.write(scrubLogLine(line))
    },
  }
}

/**
 * Build a logger with the kernel's redaction configuration. Tests construct
 * their own against a capture stream so they exercise the same paths the
 * daemon runs with — the value scrubber included, since it wraps whatever
 * destination is given.
 */
export function createLogger(options: LoggerOptions = {}): pino.Logger {
  const opts: pino.LoggerOptions = {
    level: options.level ?? resolveLevel(),
    redact: { paths: [...REDACT_PATHS], censor: CENSOR },
  }
  return pino(opts, scrubbing(options.destination ?? pino.destination({ dest: 1, sync: true })))
}

/** The process-wide logger. */
export const log: pino.Logger = createLogger()
