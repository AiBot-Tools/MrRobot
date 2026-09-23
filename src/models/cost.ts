// Cost arithmetic.
//
// Money is integer micro-USD everywhere (plan D4), and this is the only place
// a cost is computed. Two rules make the number reproducible:
//
//   Exact integers throughout. Each component is tokens × price, accumulated
//   as an integer numerator in micro-USD × 10^6, and divided once at the end.
//   No floating-point dollars, ever — two implementations must agree on the
//   frozen costMicroUsd in the event log, and float addition does not.
//
//   Round UP, once, at the end. A budget that under-bills is a budget that
//   can be exceeded, and rounding each component separately would compound
//   the error across a long run.
//
// The plan specifies accumulating in nano-USD and dividing by 1000. That is
// exact only when every price divides by 1000; this accumulates the raw
// numerator instead, which is exact for ANY integer price and produces the
// same answer for every price the table actually uses. The numerator stays
// far below the safe-integer ceiling: a million tokens at $50/MTok is 5e13,
// and five components of that are still under 9e15.

import type { ModelCard } from './registry.js'
import { billableInputTokens, type NormalUsage } from './usage.js'

/** Per-million-token prices, in micro-USD. */
export interface Prices {
  readonly inMicroUsdPerMTok: number
  readonly outMicroUsdPerMTok: number
  // Explicit undefined is accepted, because a parsed card carries these keys
  // with undefined values rather than omitting them.
  readonly cacheWrite5mMicroUsdPerMTok?: number | undefined
  readonly cacheWrite1hMicroUsdPerMTok?: number | undefined
  readonly cacheReadMicroUsdPerMTok?: number | undefined
}

export type CostSource = 'table' | 'provider'

export interface CostResult {
  readonly costMicroUsd: number
  readonly costSource: CostSource
  readonly billableInputTokens: number
}

const PER_MTOK = 1_000_000

/**
 * Compute a call's cost from token counts and a price table.
 *
 * Cache writes fall back to the plain input price when the table gives no
 * cache price, because charging nothing for a write that a provider does bill
 * would silently under-count a budget.
 */
export function computeCost(usage: NormalUsage, prices: Prices): number {
  const cacheWrite5m = prices.cacheWrite5mMicroUsdPerMTok ?? prices.inMicroUsdPerMTok
  const cacheWrite1h = prices.cacheWrite1hMicroUsdPerMTok ?? prices.inMicroUsdPerMTok
  const cacheRead = prices.cacheReadMicroUsdPerMTok ?? prices.inMicroUsdPerMTok

  const numerator =
    usage.inputTokens * prices.inMicroUsdPerMTok +
    usage.cacheWrite5mTokens * cacheWrite5m +
    usage.cacheWrite1hTokens * cacheWrite1h +
    usage.cacheReadTokens * cacheRead +
    usage.outputTokens * prices.outMicroUsdPerMTok

  // One rounding, upward, at the end.
  return Math.ceil(numerator / PER_MTOK)
}

/**
 * Cost for a call against a model card. When the card says the provider
 * reports cost (OpenRouter) and the provider did, that figure wins: it is
 * what will actually be invoiced, including upstream markups the table
 * cannot know about.
 */
export function costForCard(usage: NormalUsage, card: ModelCard): CostResult {
  const billable = billableInputTokens(usage)

  if (card.pricing.source === 'usage.cost' && usage.reportedCostUsd !== undefined) {
    return {
      costMicroUsd: Math.ceil(usage.reportedCostUsd * PER_MTOK),
      costSource: 'provider',
      billableInputTokens: billable,
    }
  }

  return {
    costMicroUsd: computeCost(usage, card.pricing),
    costSource: 'table',
    billableInputTokens: billable,
  }
}
