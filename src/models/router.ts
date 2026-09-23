// Model router.
//
// Binds a call to a model. Four rules make it safe rather than merely useful:
//
//   A ref the agent's manifest does not name is never called. The manifest is
//   the binding; a caller that passes anything else is refused before a
//   request event exists, because a spend the manifest did not authorise
//   should not appear in the log as though it had.
//
//   A model is routable only after a probe saw it call a tool, and only while
//   that observation is fresh (D28). The registry accepts an unprobed ref so
//   the shipped manifests boot; the router is where it stops.
//
//   At most ONE fallback per call sequence, and the move is never persisted.
//   A chain that keeps advancing turns a failing provider into a long quiet
//   spend on models nobody chose; a move that persisted would silently
//   rewrite a manifest the operator wrote.
//
//   Retries are capped by `budgets.maxRetries` and counted across the whole
//   sequence, not per ref, so a fallback cannot buy a fresh allowance.
//
// Error classes decide the shape of the response. 401/403 (auth) and 402
// (payment) fail loud and never fall back: a wrong key is not something a
// second model fixes, and quietly moving to another provider on a billing
// failure is how one forgets a subscription lapsed. 429, 5xx, timeouts,
// overload and a missing model put the ref in cooldown and advance.

import { BudgetExceeded, KernelError } from '../errors.js'
import type { EventStore } from '../events/store.js'
import { computeCost } from './cost.js'
import { routable, type ModelCard, type ProbeRecord } from './registry.js'
import {
  withCallEvents,
  type AdapterRequest,
  type CallOutcome,
  type Dialect,
  type ModelAdapter,
  type TransportScope,
} from './transport.js'

/** How long a ref stays out of the rotation after a retryable failure. */
export const DEFAULT_COOLDOWN_MS = 60_000
/** First backoff step; doubled per attempt. */
export const DEFAULT_RETRY_BASE_MS = 500

export type ProviderErrorKind =
  /** 401/403 — a wrong or revoked credential. */
  | 'auth'
  /** 402 — out of credit. */
  | 'payment'
  /** 429, 5xx, timeout, overloaded, connection reset. */
  | 'retryable'
  /** The endpoint does not know this model. Retrying it cannot help. */
  | 'model-missing'
  /** A 4xx the kernel caused: a malformed body, an unsupported parameter. */
  | 'fatal'

/**
 * A provider refused or failed a call.
 *
 * Adapters throw this so the router classifies once, here, rather than every
 * adapter inventing its own notion of "should I retry".
 */
export class ProviderError extends KernelError {
  readonly ref: string
  readonly kind: ProviderErrorKind
  readonly status: number | undefined
  /** From a `retry-after` header, when the provider sent one. */
  readonly retryAfterMs: number | undefined

  constructor(
    ref: string,
    kind: ProviderErrorKind,
    message: string,
    options: { status?: number; retryAfterMs?: number; cause?: unknown } = {},
  ) {
    super(
      'AOS_PROVIDER',
      `${ref}: ${message}`,
      options.cause === undefined ? undefined : { cause: options.cause },
    )
    this.ref = ref
    this.kind = kind
    this.status = options.status
    this.retryAfterMs = options.retryAfterMs
  }
}

/** The router refused to route. Distinct from a provider failing a call. */
export class RouterRefused extends KernelError {
  readonly ref: string
  readonly reason: string

  constructor(ref: string, reason: string) {
    super('AOS_ROUTER_REFUSED', `router refused ${ref}: ${reason}`, undefined)
    this.ref = ref
    this.reason = reason
  }
}

const MODEL_MISSING = /model[_ -]?not[_ -]?found|unknown model|no such model/i
const OVERLOADED = /overloaded|capacity|try again later/i
const TIMEOUT = /timed? ?out|ETIMEDOUT|ECONNRESET|ECONNREFUSED|socket hang up|fetch failed/i

/**
 * Classify a provider failure.
 *
 * Adapters call this with whatever they got; anything unrecognised is
 * `fatal`, which fails loud. Defaulting to `retryable` would turn a bug in
 * our own request body into three identical rejected requests.
 */
export function classifyProviderFailure(
  status: number | undefined,
  message: string,
): ProviderErrorKind {
  if (status === 401 || status === 403) return 'auth'
  if (status === 402) return 'payment'
  if (status === 404 || MODEL_MISSING.test(message)) return 'model-missing'
  if (status === 429 || status === 408 || (status !== undefined && status >= 500)) return 'retryable'
  if (status === undefined && (TIMEOUT.test(message) || OVERLOADED.test(message))) return 'retryable'
  if (status === undefined) return 'fatal'
  if (OVERLOADED.test(message)) return 'retryable'
  return 'fatal'
}

/** The manifest's model binding: what this agent is allowed to call. */
export interface ModelBinding {
  readonly primary: string
  readonly fallbacks: readonly string[]
}

export interface RouterOptions {
  readonly store: EventStore
  /** Model cards by ref, built once from providers.yaml. */
  readonly cards: ReadonlyMap<string, ModelCard>
  /** Probe records by ref. D28: no fresh probe, no routing. */
  readonly probes: (ref: string) => ProbeRecord | undefined
  /**
   * Resolve a card's credential. In Phase 0 the secrets broker (T24) supplies
   * this; the router never reads a vault or an environment variable itself.
   */
  readonly resolveCredential: (card: ModelCard, ref: string) => Promise<string | undefined>
  readonly maxRetries: number
  readonly adapters?: Partial<Record<Dialect, ModelAdapter>>
  readonly cooldownMs?: number
  readonly retryBaseMs?: number
  readonly now?: () => number
  readonly sleep?: (ms: number) => Promise<void>
  /** Injected so tests never open a socket. */
  readonly fetch?: typeof globalThis.fetch
}

/** What the caller asks for; the router supplies `ref` and `card`. */
export type RouteRequest = Omit<AdapterRequest, 'ref' | 'card'>

export interface RouteCall {
  readonly binding: ModelBinding
  readonly request: RouteRequest
  readonly scope?: TransportScope
  /** Pin a specific ref. It must be in the binding. */
  readonly ref?: string
  /** Remaining run budget, in micro-USD. Required for D16's fallback check. */
  readonly remainingMicroUsd?: number
}

export interface RouteResult {
  readonly requestedRef: string
  readonly servedRef: string
  readonly attempts: number
  readonly fellBack: boolean
  readonly outcome: CallOutcome
}

/**
 * The Phase 0 placeholder for a dialect with no adapter yet.
 *
 * It throws rather than returning an empty answer: a stub that produced a
 * plausible-looking result would let the runtime loop appear to work while
 * spending nothing and learning nothing.
 */
export class NotImplementedAdapter implements ModelAdapter {
  readonly dialect: Dialect

  constructor(dialect: Dialect) {
    this.dialect = dialect
  }

  prepare(request: AdapterRequest): never {
    throw new KernelError(
      'AOS_NOT_IMPLEMENTED',
      `not implemented in this phase: ${this.dialect} adapter (requested for ${request.ref})`,
    )
  }
}

const DEFAULT_ADAPTERS: Readonly<Record<Dialect, ModelAdapter>> = {
  anthropic: new NotImplementedAdapter('anthropic'),
  'openai-chat': new NotImplementedAdapter('openai-chat'),
}

/**
 * Cost of the most expensive turn a card can produce.
 *
 * A card with no declared limits has no bounded worst case, so D16's check
 * cannot be satisfied for it and the fallback is refused. That is the
 * fail-closed reading: an unbounded model is exactly the one that should not
 * be entered on a thin budget.
 */
export function worstCaseTurnMicroUsd(card: ModelCard): number | undefined {
  const limits = card.limits
  if (limits === undefined) return undefined
  return computeCost(
    {
      inputTokens: limits.contextTokens,
      outputTokens: limits.maxOutputTokens,
      cacheWrite5mTokens: 0,
      cacheWrite1hTokens: 0,
      cacheReadTokens: 0,
    },
    card.pricing,
  )
}

export class Router {
  readonly #options: RouterOptions
  readonly #adapters: Readonly<Record<Dialect, ModelAdapter>>
  readonly #cooldown = new Map<string, number>()
  readonly #now: () => number
  readonly #sleep: (ms: number) => Promise<void>

  constructor(options: RouterOptions) {
    this.#options = options
    this.#adapters = { ...DEFAULT_ADAPTERS, ...options.adapters }
    this.#now = options.now ?? Date.now
    this.#sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)))
  }

  /** Refs this binding may use, in priority order. */
  #chain(binding: ModelBinding): string[] {
    return [binding.primary, ...binding.fallbacks]
  }

  #cardFor(ref: string): ModelCard {
    const card = this.#options.cards.get(ref)
    if (card === undefined) throw new RouterRefused(ref, 'no provider entry')
    return card
  }

  /** D28: a ref is usable only with a fresh probe that saw a tool call. */
  #assertRoutable(ref: string): ModelCard {
    const card = this.#cardFor(ref)
    if (!routable(card, this.#options.probes(ref), this.#now())) {
      throw new RouterRefused(ref, 'no fresh probe reporting toolCalling: true')
    }
    return card
  }

  #degraded(reason: string, scope: TransportScope): void {
    this.#options.store.append({
      type: 'router.degraded',
      ...(scope.runId === undefined ? {} : { runId: scope.runId }),
      ...(scope.agentId === undefined ? {} : { agentId: scope.agentId }),
      payload: { schemaVersion: 1, reason },
    })
  }

  /**
   * Pick the one fallback this sequence is allowed, or explain why there is
   * none. D16: a pricier model is entered only when the remaining budget
   * covers one worst-case turn of it.
   */
  #chooseFallback(
    chain: readonly string[],
    fromIndex: number,
    fromCard: ModelCard,
    remainingMicroUsd: number | undefined,
  ): { ref: string; card: ModelCard; index: number } | { refusal: string } {
    const now = this.#now()
    let lastRefusal = 'no fallback is configured'

    for (let i = fromIndex + 1; i < chain.length; i++) {
      const ref = chain[i]
      if (ref === undefined) continue

      const until = this.#cooldown.get(ref)
      if (until !== undefined && until > now) {
        lastRefusal = `${ref} is in cooldown`
        continue
      }

      let card: ModelCard
      try {
        card = this.#assertRoutable(ref)
      } catch (e) {
        lastRefusal = e instanceof Error ? e.message : String(e)
        continue
      }

      const nextWorst = worstCaseTurnMicroUsd(card)
      if (nextWorst === undefined) {
        lastRefusal = `${ref} declares no limits, so one worst-case turn cannot be bounded`
        continue
      }

      const fromWorst = worstCaseTurnMicroUsd(fromCard)
      const pricier = fromWorst === undefined || nextWorst > fromWorst
      if (pricier) {
        if (remainingMicroUsd === undefined || remainingMicroUsd < nextWorst) {
          lastRefusal =
            `${ref} costs more per worst-case turn (${String(nextWorst)} microUSD) than the remaining ` +
            `budget (${remainingMicroUsd === undefined ? 'unknown' : String(remainingMicroUsd)} microUSD)`
          continue
        }
      }

      return { ref, card, index: i }
    }

    return { refusal: lastRefusal }
  }

  /**
   * Make one model call, with retries and at most one fallback.
   *
   * Every attempt — including one that fails — writes its own llm.request /
   * llm.response pair through the transport (invariant 4).
   */
  async call(input: RouteCall): Promise<RouteResult> {
    const scope = input.scope ?? {}
    const chain = this.#chain(input.binding)
    const requestedRef = input.ref ?? input.binding.primary

    if (!chain.includes(requestedRef)) {
      // Refused before any request event: the manifest is the binding, and a
      // call it never authorised must not appear in the log as a spend.
      throw new RouterRefused(requestedRef, 'not in this agent’s model binding')
    }

    let index = chain.indexOf(requestedRef)
    let card = this.#assertRoutable(requestedRef)
    let servedRef = requestedRef
    let fellBack = false

    const maxAttempts = 1 + this.#options.maxRetries
    let attempt = 0
    let lastError: unknown

    while (attempt < maxAttempts) {
      attempt++

      const adapter = this.#adapters[card.dialect]
      const credential = await this.#options.resolveCredential(card, servedRef)
      const prepared = adapter.prepare({ ...input.request, ref: servedRef, card })

      try {
        const outcome = await withCallEvents(
          {
            store: this.#options.store,
            scope,
            ref: servedRef,
            card,
            ...(credential === undefined ? {} : { key: credential }),
            ...(this.#options.fetch === undefined ? {} : { fetch: this.#options.fetch }),
            attempt,
          },
          prepared.context,
          (fetchImpl, key) => prepared.perform(fetchImpl, key),
        )

        if (fellBack) {
          this.#degraded(`served ${servedRef} after ${requestedRef} failed`, scope)
        }
        return { requestedRef, servedRef, attempts: attempt, fellBack, outcome }
      } catch (e) {
        lastError = e
        const kind =
          e instanceof ProviderError
            ? e.kind
            : classifyProviderFailure(undefined, e instanceof Error ? e.message : String(e))

        // A bad credential, a lapsed subscription, or our own malformed
        // request. None of these is fixed by another model.
        if (kind === 'auth' || kind === 'payment' || kind === 'fatal') throw e

        this.#cooldown.set(servedRef, this.#now() + (this.#options.cooldownMs ?? DEFAULT_COOLDOWN_MS))

        if (!fellBack) {
          const choice = this.#chooseFallback(chain, index, card, input.remainingMicroUsd)
          if ('refusal' in choice) {
            this.#degraded(`no fallback after ${servedRef} failed: ${choice.refusal}`, scope)
            // A model the endpoint does not know will not appear on a retry.
            if (kind === 'model-missing') throw e
          } else {
            this.#degraded(`falling back from ${servedRef} to ${choice.ref}`, scope)
            servedRef = choice.ref
            card = choice.card
            index = choice.index
            fellBack = true
            continue
          }
        } else if (kind === 'model-missing') {
          throw e
        }

        if (attempt < maxAttempts) {
          const after =
            e instanceof ProviderError && e.retryAfterMs !== undefined
              ? e.retryAfterMs
              : (this.#options.retryBaseMs ?? DEFAULT_RETRY_BASE_MS) * 2 ** (attempt - 1)
          await this.#sleep(after)
        }
      }
    }

    if (lastError !== undefined) throw lastError
    throw new BudgetExceeded(requestedRef, `no attempt was made within ${String(maxAttempts)} attempts`)
  }
}
