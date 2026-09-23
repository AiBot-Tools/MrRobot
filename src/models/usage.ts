// Usage normalisation.
//
// Two dialects report token counts differently, and the difference is a
// billing bug waiting to happen:
//
//   Anthropic  input_tokens, output_tokens, cache_creation_input_tokens,
//              cache_read_input_tokens. Billable input is the SUM of the
//              three input fields — the docs are explicit about this — so
//              reading input_tokens alone under-bills every cached request,
//              and the more caching works the wronger the number gets.
//
//   Chat       prompt_tokens, completion_tokens, with cached tokens reported
//              INSIDE prompt_tokens and broken out under
//              prompt_tokens_details.cached_tokens. So cached tokens must be
//              SUBTRACTED to get the uncached remainder, the mirror image of
//              the Anthropic case.
//
// Getting these backwards is invisible in testing with an empty cache, which
// is why both are normalised here, once, rather than at each call site.

import { z } from 'zod'

export interface NormalUsage {
  /** Tokens charged at the plain input rate. */
  readonly inputTokens: number
  readonly outputTokens: number
  /** Cache writes with a 5-minute lifetime. */
  readonly cacheWrite5mTokens: number
  readonly cacheWrite1hTokens: number
  readonly cacheReadTokens: number
  /** Provider-reported cost, when the provider reports one (OpenRouter). */
  readonly reportedCostUsd?: number
}

const AnthropicUsage = z
  .object({
    input_tokens: z.number().int().nonnegative(),
    output_tokens: z.number().int().nonnegative(),
    cache_creation_input_tokens: z.number().int().nonnegative().nullish(),
    cache_read_input_tokens: z.number().int().nonnegative().nullish(),
    cache_creation: z
      .object({
        ephemeral_5m_input_tokens: z.number().int().nonnegative().nullish(),
        ephemeral_1h_input_tokens: z.number().int().nonnegative().nullish(),
      })
      .nullish(),
  })
  .loose()

const ChatUsage = z
  .object({
    prompt_tokens: z.number().int().nonnegative(),
    completion_tokens: z.number().int().nonnegative(),
    prompt_tokens_details: z
      .object({ cached_tokens: z.number().int().nonnegative().nullish() })
      .loose()
      .nullish(),
    cost: z.number().nonnegative().nullish(),
  })
  .loose()

export function normaliseAnthropicUsage(raw: unknown): NormalUsage {
  const u = AnthropicUsage.parse(raw)
  const totalWrite = u.cache_creation_input_tokens ?? 0
  // When the breakdown is present it is authoritative; otherwise the whole
  // write is priced at the 5-minute rate, which is the cheaper of the two and
  // therefore the one that cannot silently over-bill.
  const write5m = u.cache_creation?.ephemeral_5m_input_tokens ?? undefined
  const write1h = u.cache_creation?.ephemeral_1h_input_tokens ?? undefined
  const has = write5m !== undefined || write1h !== undefined

  return {
    inputTokens: u.input_tokens,
    outputTokens: u.output_tokens,
    cacheWrite5mTokens: has ? (write5m ?? 0) : totalWrite,
    cacheWrite1hTokens: has ? (write1h ?? 0) : 0,
    cacheReadTokens: u.cache_read_input_tokens ?? 0,
  }
}

export function normaliseChatUsage(raw: unknown): NormalUsage {
  const u = ChatUsage.parse(raw)
  const cached = u.prompt_tokens_details?.cached_tokens ?? 0
  // Cached tokens are INSIDE prompt_tokens here, unlike Anthropic where they
  // sit beside it. Subtracting is what keeps the two dialects comparable.
  const uncached = Math.max(0, u.prompt_tokens - cached)

  return {
    inputTokens: uncached,
    outputTokens: u.completion_tokens,
    cacheWrite5mTokens: 0,
    cacheWrite1hTokens: 0,
    cacheReadTokens: cached,
    ...(u.cost === undefined || u.cost === null ? {} : { reportedCostUsd: u.cost }),
  }
}

/** Total tokens the provider will bill as input, across both dialects. */
export function billableInputTokens(usage: NormalUsage): number {
  return (
    usage.inputTokens + usage.cacheWrite5mTokens + usage.cacheWrite1hTokens + usage.cacheReadTokens
  )
}
