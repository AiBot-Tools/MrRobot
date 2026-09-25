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

import { boundOutput, PAYLOAD_TEXT_BUDGET } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import { SecretMask } from '../events/redact.js'
import type { ModelCard } from './registry.js'

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

  const prompt = boundOutput(context.prompt, PAYLOAD_TEXT_BUDGET)
  store.append({
    type: 'llm.request',
    ...(scope.runId === undefined ? {} : { runId: scope.runId }),
    ...(scope.agentId === undefined ? {} : { agentId: scope.agentId }),
    payload: {
      schemaVersion: 1,
      ref,
      attempt,
      prompt: prompt.text,
      tools: [...context.tools],
      ...(context.maxOutputTokens === undefined ? {} : { maxOutputTokens: context.maxOutputTokens }),
    },
  })

  const startedAt = Date.now()
  const wire = credentialedFetch(options.fetch ?? globalThis.fetch, card, key)

  try {
    const outcome = await perform(wire, key)
    store.append({
      type: 'llm.response',
      ...(scope.runId === undefined ? {} : { runId: scope.runId }),
      ...(scope.agentId === undefined ? {} : { agentId: scope.agentId }),
      payload: {
        schemaVersion: 1,
        ref,
        attempt,
        content: boundOutput(outcome.content, PAYLOAD_TEXT_BUDGET).text,
        finish: outcome.finish,
        inputTokens: outcome.inputTokens,
        outputTokens: outcome.outputTokens,
        ...(outcome.cacheReadTokens === undefined ? {} : { cacheReadTokens: outcome.cacheReadTokens }),
        ...(outcome.cacheWriteTokens === undefined ? {} : { cacheWriteTokens: outcome.cacheWriteTokens }),
        costMicroUsd: outcome.costMicroUsd,
        durationMs: Date.now() - startedAt,
      },
    })
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
