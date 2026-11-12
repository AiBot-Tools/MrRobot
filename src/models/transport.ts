// Logging transport.
//
// The ONLY place bytes leave the router, and the only place a provider
// credential is attached to a request (invariant 2). Adapters are handed a
// fetch that already carries the credential; they never build one, and the
// one adapter that must hand a key to a vendor SDK (T20) receives it through
// a single documented seam, `perform`'s second argument, so the seam is
// greppable rather than diffuse.
//
// Invariant 4 lives here: every model call is exactly two events, llm.request
// before and llm.response after, WITH the prompt, the content, the tokens and
// the cost. Both are written even when the call throws — a network error that
// left no trace would be a call the log cannot account for, and the whole
// point of the pair is that a spend is never invisible.
//
// The credential is registered with SecretMask the moment it is resolved, so
// if it somehow appears inside a body, a header dump or an error message, the
// event redaction pass censors it by exact substring rather than hoping a
// pattern matches.

import { boundOutput, MAX_LOGGED_OUTPUT, PAYLOAD_TEXT_BUDGET } from '../events/bound.js'
import { canonicalize } from '../events/canonical.js'
import type { EventStore } from '../events/store.js'
import { redactString, redactValue, SecretMask } from '../events/redact.js'
import type { ModelCard } from './registry.js'
import { PROVIDER_TOOL_NAME } from '../mcp/names.js'

export type Dialect = ModelCard['dialect']

/** The two headers a provider credential may ride on. */
const AUTH_HEADERS = ['authorization', 'x-api-key'] as const

// ── the dialect-neutral call shape ─────────────────────────────────────────
//
// The router and the runtime loop speak this; adapters translate it to and
// from a wire format. Tool references are DOTTED here and everywhere else in
// the kernel — the `__` spelling exists only inside an adapter's request body
// (invariant 10).

export interface ToolSchema {
  /** Dotted ref, e.g. `pmmcp.recall`. */
  readonly ref: string
  readonly description: string
  readonly inputSchema: Record<string, unknown>
}

export interface ToolCall {
  readonly id: string
  /** Dotted ref, mapped back from the provider's `__` spelling. */
  readonly ref: string
  readonly args: unknown
}

/**
 * A tool call the model produced that the kernel cannot execute — most often
 * unparseable JSON arguments. It is data, not an exception: the model is told
 * what went wrong and gets to try again, which is what the providers document
 * as the expected handling.
 */
export interface ToolCallError {
  readonly id: string
  /** The name as the provider spelled it, which may not map to any ref. */
  readonly name: string
  readonly reason: string
  /**
   * The arguments exactly as the model emitted them: an object from the
   * Anthropic dialect, the raw (possibly unparseable) string from Chat
   * Completions. Kept only so the call can be REPLAYED — never executed.
   */
  readonly rawArgs: unknown
}

export type TurnMessage =
  | { readonly role: 'user'; readonly content: string }
  | {
      readonly role: 'assistant'
      readonly content: string
      readonly toolCalls?: readonly ToolCall[]
      /**
       * The provider's own assistant message, replayed verbatim when the card
       * sets `caps.preserveAssistantMessage`. Some compat servers reject a
       * reconstructed one (reasoning traces must round-trip untouched).
       */
      readonly raw?: unknown
      /**
       * Calls the kernel refused to execute (an un-offered name, arguments that
       * are not JSON). They go back on the wire as the calls they were, because
       * both dialects answer a call by its id: the error result the model reads
       * next is only valid if the call it answers is in the turn before it.
       * Dropping them left a result pointing at nothing — and, when the model
       * wrote no text, an assistant turn with no content at all.
       */
      readonly rejectedCalls?: readonly ToolCallError[]
    }
  | {
      readonly role: 'tool'
      readonly callId: string
      readonly ref: string
      readonly content: string
      readonly isError?: boolean
    }

/** Everything an adapter needs to build one request body. */
export interface AdapterRequest {
  readonly ref: string
  readonly card: ModelCard
  readonly system: string
  readonly messages: readonly TurnMessage[]
  readonly tools: readonly ToolSchema[]
  readonly maxOutputTokens?: number
}

/** What the adapter tells the transport about the call it is about to make. */
export interface CallContext {
  /** The prompt, already serialized by the adapter. */
  readonly prompt: string
  /** Dotted refs offered to the model on this call. */
  readonly tools: readonly string[]
  readonly maxOutputTokens?: number
}

export interface CallOutcome {
  readonly content: string
  readonly finish: string
  readonly inputTokens: number
  readonly outputTokens: number
  readonly cacheReadTokens?: number
  readonly cacheWriteTokens?: number
  readonly costMicroUsd: number
  /**
   * The model id the SERVER reported, which need not be the one asked for:
   * an alias, a router's substitution, or a quantisation the card cannot
   * know about. The probe records it so a silent swap is visible.
   */
  readonly modelSeen?: string
  readonly toolCalls?: readonly ToolCall[]
  readonly toolCallErrors?: readonly ToolCallError[]
  /** The raw assistant message, for `caps.preserveAssistantMessage` replay. */
  readonly raw?: unknown
}

/**
 * One request, built but not yet sent.
 *
 * Splitting build from send lets the transport write `llm.request` with the
 * real serialized prompt without the adapter building the body twice, and
 * keeps the retry loop in the router: a retry re-sends the same prepared
 * call rather than re-deriving it.
 */
export interface PreparedCall {
  readonly context: CallContext
  /**
   * @param fetchImpl a fetch that ALREADY carries the credential.
   * @param credential the resolved key, for the one vendor-SDK seam that
   *   demands it explicitly. Raw-fetch adapters ignore it; an adapter that
   *   uses it must not also stamp a header, and the transport refuses the
   *   request if two auth headers reach the wire.
   */
  perform(fetchImpl: typeof globalThis.fetch, credential: string | undefined): Promise<CallOutcome>
}

export interface ModelAdapter {
  readonly dialect: Dialect
  prepare(request: AdapterRequest): PreparedCall
}

// ── credential attachment ──────────────────────────────────────────────────

export class TransportError extends Error {
  readonly code = 'AOS_TRANSPORT'

  constructor(message: string) {
    super(message)
    this.name = 'TransportError'
  }
}

function presentAuthHeaders(headers: Headers): string[] {
  return AUTH_HEADERS.filter((name) => (headers.get(name) ?? '') !== '')
}

/**
 * Wrap a fetch so every request carries exactly the configured credential.
 *
 * The header is stamped only when the caller did not already set one, so an
 * adapter built on a vendor SDK that authenticates itself still passes — but
 * a request that would reach the wire with two auth headers, or with an auth
 * header on an endpoint configured to send none, is refused before a byte
 * moves. Both would be a credential going somewhere nobody decided it should.
 */
export function credentialedFetch(
  base: typeof globalThis.fetch,
  card: ModelCard,
  credential: string | undefined,
): typeof globalThis.fetch {
  return (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const inherited =
      init?.headers ?? (typeof input === 'object' && input instanceof Request ? input.headers : undefined)
    const headers = new Headers(inherited)

    for (const [name, value] of Object.entries(card.headers ?? {})) {
      if (!headers.has(name)) headers.set(name, value)
    }

    const already = presentAuthHeaders(headers)

    if (credential === undefined) {
      if (already.length > 0) {
        throw new TransportError(
          `${card.model}: an adapter set ${already.join(' and ')} on an endpoint configured with no credential`,
        )
      }
    } else {
      if (already.length === 0) {
        headers.set(
          card.auth.header,
          card.auth.scheme === 'Bearer' ? `Bearer ${credential}` : credential,
        )
      }
      const final = presentAuthHeaders(headers)
      if (final.length !== 1) {
        throw new TransportError(
          `${card.model}: ${String(final.length)} auth headers would reach the wire (${final.join(', ')}); exactly one is allowed`,
        )
      }
    }

    return base(input, { ...init, headers })
  }) as typeof globalThis.fetch
}

// ── the event pair ─────────────────────────────────────────────────────────

export interface TransportScope {
  readonly runId?: string
  readonly agentId?: string
}

export interface LoggingFetchOptions {
  readonly store: EventStore
  readonly scope: TransportScope
  readonly ref: string
  readonly card: ModelCard
  /** Resolved credential, or undefined for an endpoint that needs none. */
  readonly key?: string
  /** Underlying fetch. Injected so tests never open a socket. */
  readonly fetch?: typeof globalThis.fetch
  /** Attempt number, for the event pair. */
  readonly attempt?: number
}

/**
 * Wrap one provider call in the mandated event pair.
 *
 * `perform` receives a credentialed fetch and returns what the response
 * means. Throwing is fine: the response event is still written, with the
 * error and zero cost.
 */
export async function withCallEvents(
  options: LoggingFetchOptions,
  context: CallContext,
  perform: (fetchImpl: typeof globalThis.fetch, credential: string | undefined) => Promise<CallOutcome>,
): Promise<CallOutcome> {
  const { store, scope, ref, card, key } = options
  const attempt = options.attempt ?? 1

  // Register before the first byte moves, so a leak in any later message is
  // censored by exact substring rather than by a hopeful pattern.
  if (key !== undefined) SecretMask.register(key)

  const requestPayload = (prompt: string): Record<string, unknown> => ({
    schemaVersion: 1,
    ref,
    attempt,
    prompt,
    tools: [...context.tools],
    ...(context.maxOutputTokens === undefined ? {} : { maxOutputTokens: context.maxOutputTokens }),
  })
  appendLogged(
    store,
    {
      type: 'llm.request',
      ...(scope.runId === undefined ? {} : { runId: scope.runId }),
      ...(scope.agentId === undefined ? {} : { agentId: scope.agentId }),
    },
    context.prompt,
    requestPayload,
  )

  const startedAt = Date.now()
  const wire = credentialedFetch(options.fetch ?? globalThis.fetch, card, key)

  try {
    const outcome = await perform(wire, key)
    const durationMs = Date.now() - startedAt
    // The model's answer is bounded as the prompt is (appendLogged): an answer
    // dense in escapes (escaped JSON, code) takes up to six times its raw
    // bytes in the log's canonical JSON, and bounded by those raw bytes its
    // append would throw and end the run in error.
    const responsePayload = (content: string): Record<string, unknown> => ({
      schemaVersion: 1,
      ref,
      attempt,
      content,
      finish: outcome.finish,
      inputTokens: outcome.inputTokens,
      outputTokens: outcome.outputTokens,
      ...(outcome.cacheReadTokens === undefined ? {} : { cacheReadTokens: outcome.cacheReadTokens }),
      ...(outcome.cacheWriteTokens === undefined ? {} : { cacheWriteTokens: outcome.cacheWriteTokens }),
      costMicroUsd: outcome.costMicroUsd,
      durationMs,
    })
    appendLogged(
      store,
      {
        type: 'llm.response',
        ...(scope.runId === undefined ? {} : { runId: scope.runId }),
        ...(scope.agentId === undefined ? {} : { agentId: scope.agentId }),
      },
      outcome.content,
      responsePayload,
    )
    return outcome
  } catch (e) {
    // A failed call still cost time and may have cost money upstream. It gets
    // its own response event, with zero cost and the error recorded, so the
    // pair is never broken.
    const message = e instanceof Error ? e.message : String(e)
    store.append({
      type: 'llm.response',
      ...(scope.runId === undefined ? {} : { runId: scope.runId }),
      ...(scope.agentId === undefined ? {} : { agentId: scope.agentId }),
      payload: {
        schemaVersion: 1,
        ref,
        attempt,
        content: '',
        finish: 'error',
        inputTokens: 0,
        outputTokens: 0,
        costMicroUsd: 0,
        durationMs: Date.now() - startedAt,
        error: boundOutput(message, 2_000).text,
      },
    })
    throw e
  }
}

/**
 * The bytes `text` takes as a string in canonical JSON, its quotes aside:
 * JSON's escapes (canonical.ts), under which a quote, a backslash or a
 * newline takes two bytes and another C0 control six.
 */
function payloadBytes(text: string): number {
  return Buffer.byteLength(JSON.stringify(text)) - 2
}

/** The longest start of `text` whose payloadBytes is at most `keep`, whole code points only. */
function firstFitting(text: string, keep: number): string {
  let end = 0
  let used = 0
  for (const point of text) {
    const cost = payloadBytes(point)
    if (used + cost > keep) break
    used += cost
    end += point.length
  }
  return text.slice(0, end)
}

/**
 * The bytes the store measures `payload` by against MAX_LOGGED_OUTPUT: its
 * canonical JSON once redacted, redacted again as a text (store.ts append).
 */
function storedBytes(payload: Record<string, unknown>): number {
  return Buffer.byteLength(redactString(canonicalize(redactValue(payload))))
}

/**
 * The start of `redacted` (a text redacted once) that the log keeps in the
 * payload `payloadOf` builds around it, measured without redacting it again:
 * all of it when it fits, else the longest start of it, whole code points
 * only (canonical JSON refuses a lone surrogate), whose bytes in the
 * payload's canonical JSON are within its share, PAYLOAD_TEXT_BUDGET, and
 * within what the rest of the payload (a long tool list) leaves of
 * MAX_LOGGED_OUTPUT, that rest measured as the store measures it.
 *
 * It holds the store's measure exactly but where the store's own two passes
 * of redaction (the payload's values, then its canonical JSON as a text)
 * find in the text what its first pass did not: a registered secret that is
 * the text's canonical escape of itself, or that holds part of a [REDACTED]
 * the first pass wrote. appendLogged lets the store say so.
 */
function estimatedCut(redacted: string, payloadOf: (text: string) => Record<string, unknown>): string {
  const keep = Math.min(PAYLOAD_TEXT_BUDGET, MAX_LOGGED_OUTPUT - storedBytes(payloadOf('')))
  if (payloadBytes(redacted) <= keep) return redacted
  return keep <= 0 ? '' : firstFitting(redacted, keep)
}

/**
 * The start of `redacted` the store's own measure admits, cut on from
 * `from` (a start of it) by what the store measures the payload over its
 * limit, until it fits. Each step redacts the payload twice, as the store
 * does, so it is asked only once the store has refused an estimated cut.
 */
function fittedCut(redacted: string, payloadOf: (text: string) => Record<string, unknown>, from: string): string {
  let cut = from
  for (;;) {
    const over = storedBytes(payloadOf(cut)) - MAX_LOGGED_OUTPUT
    if (over <= 0 || cut === '') return cut
    const keep = payloadBytes(cut) - over
    cut = keep <= 0 ? '' : firstFitting(redacted, keep)
  }
}

/**
 * The one long text of a payload as the log keeps it (llm.request's prompt,
 * llm.response's content): redacted, and cut, at a code point, until the
 * payload `payloadOf` builds around it fits the store's limit, as the store
 * measures it. The log's canonical JSON escapes every quote, backslash and
 * control character in the text: the prompt is the provider's request body,
 * already JSON, so a tool result of many short quoted lines, which the body
 * shows as \" and \n, takes up to twice its size there, and an answer of
 * escaped JSON or code as much or more. Bounded by its raw bytes, such a text
 * is over the limit, and the append throws, ending the run in error. A cut
 * text is a start of the redacted text, cut after redaction, as boundOutput
 * cuts. What the provider is sent, and what the model answered, are not cut:
 * only what the log keeps of them. appendLogged keeps the same text, and asks
 * the store's measure only when its estimate does not fit.
 */
export function loggedText(text: string, payloadOf: (text: string) => Record<string, unknown>): string {
  const redacted = redactString(text)
  return fittedCut(redacted, payloadOf, estimatedCut(redacted, payloadOf))
}

/**
 * Append `event` with the payload `payloadOf` builds around what the log
 * keeps of `text` (loggedText), redacting that text once before the store's
 * own passes, where loggedText's measure would redact it twice more. Each
 * pass is quadratic in some texts (redact.ts's JWT pattern on a long run of
 * `-ey`), and a prompt carries every earlier result of its run, so every
 * pass more holds the daemon's event loop again on every later call. So the
 * text is cut by estimatedCut, which measures the rest of the payload as the
 * store does and the text by its escaped bytes, and the store's append is
 * its check: a payload it refuses for its size, and only that, is cut to
 * what the store's measure admits (fittedCut) and appended again. The store
 * refuses before it writes anything, so nothing is written twice; any other
 * refusal is the caller's, and is thrown as it came.
 */
export function appendLogged(
  store: Pick<EventStore, 'append'>,
  event: { readonly type: string; readonly runId?: string; readonly agentId?: string },
  text: string,
  payloadOf: (text: string) => Record<string, unknown>,
): void {
  const redacted = redactString(text)
  const estimate = estimatedCut(redacted, payloadOf)
  try {
    store.append({ ...event, payload: payloadOf(estimate) })
    return
  } catch (e) {
    // Measured only on a refusal: a payload within the limit was refused
    // for something a cut does not change.
    if (storedBytes(payloadOf(estimate)) <= MAX_LOGGED_OUTPUT) throw e
  }
  store.append({ ...event, payload: payloadOf(fittedCut(redacted, payloadOf, estimate)) })
}

/**
 * A rejected call's name, made safe to put back on the wire.
 *
 * It is never mapped to a ref and never executed, so rewriting it loses
 * nothing; what it must not do is fail the whole request. A name the model
 * emitted in this dialect already fits, but a run that fell back across
 * dialects replays a name one provider accepted to another that may not.
 */
export function replayName(name: string): string {
  if (PROVIDER_TOOL_NAME.test(name)) return name
  const cleaned = name.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64)
  return cleaned === '' ? 'invalid_tool' : cleaned
}

/** A rejected call's arguments as an object, for a dialect that needs one. */
export function replayInput(rawArgs: unknown): Record<string, unknown> {
  const asObject = (v: unknown): Record<string, unknown> | undefined =>
    typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined
  const direct = asObject(rawArgs)
  if (direct !== undefined) return direct
  if (typeof rawArgs === 'string') {
    try {
      const parsed = asObject(JSON.parse(rawArgs))
      if (parsed !== undefined) return parsed
    } catch {
      // Unparseable arguments are why the call was rejected. The error result
      // says so; the replayed call only has to be well-formed.
    }
  }
  return {}
}

/** A rejected call's arguments as a string, for a dialect that sends one. */
export function replayArguments(rawArgs: unknown): string {
  // Verbatim when it is already a string: the model should see exactly what
  // it sent next to the error explaining what was wrong with it.
  return typeof rawArgs === 'string' ? rawArgs : JSON.stringify(rawArgs ?? {})
}
