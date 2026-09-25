// Run budgets and the wallclock.
//
// CLAUDE.md lists disabling these among the things the kernel never does, so
// the shape here is chosen to make disabling them awkward rather than merely
// forbidden:
//
//   There is no `pause()`. D19 says the wallclock keeps running while a run is
//   parked for approval, and the way to guarantee that is to have nothing that
//   could stop it. A run waiting on a human is still a run holding a lane, a
//   workspace and a place in someone's attention.
//
//   No cap admits Infinity, zero or a negative. Infinity is "no budget" spelled
//   so it survives review; zero is a run that can never take a single step,
//   which is a disabled agent written as a typo. Both are refused where they
//   are introduced rather than discovered when a run behaves strangely.
//
//   A manifest may only LOWER a kernel cap. An agent's own file asking for more
//   than the operator allowed is refused at construction, not clamped quietly:
//   a clamp leaves the manifest saying something untrue.
//
// Counts are charged AFTER the work, because a call's cost is not knowable
// before it is made. So a cap of N permits exactly N and refuses the N+1th,
// which is what `spent >= cap` gives.

import { ConfigError } from '../errors.js'

/** The frozen set of reasons a run stops. The control plane matches on these. */
export const STOP_REASONS = ['usdMax', 'maxLlmCalls', 'maxToolCalls', 'wallclock'] as const
export type StopReason = (typeof STOP_REASONS)[number]

export type BudgetCheck = { readonly ok: true } | { readonly ok: false; readonly stop: StopReason }

const OK: BudgetCheck = Object.freeze({ ok: true })

export type ChargeKind = 'cost' | 'llm' | 'tool'

/** Caps in force for one run, after the kernel/manifest intersection. */
export interface BudgetCaps {
  /** Integer micro-USD. Money is never a float anywhere in the kernel. */
  readonly usdMax: number
  readonly maxLlmCalls: number
  readonly maxToolCalls: number
  readonly wallclockMs: number
}

/** The operator's ceilings, from kernel.yaml. */
export interface KernelBudgets {
  readonly defaultRunMicroUsd: number
  readonly defaultWallclockMs: number
  readonly maxLlmCallsPerRun: number
  readonly maxToolCallsPerRun: number
}

/** What an agent manifest may ask for. Every field may only lower. */
export interface ManifestBudget {
  readonly maxCostMicroUsd?: number | undefined
  readonly maxLlmCalls?: number | undefined
  readonly maxToolCalls?: number | undefined
  readonly maxWallclockMs?: number | undefined
}

function assertUsable(name: string, value: number): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new ConfigError(
      `budget ${name} must be a positive integer, got ${String(value)}. ` +
        'Infinity is "no budget" in disguise and zero is a run that can never take a step.',
    )
  }
  return value
}

/**
 * Intersect the operator's ceilings with what a manifest asks for.
 *
 * @throws {ConfigError} when a manifest asks for more than the kernel allows.
 */
export function resolveCaps(kernel: KernelBudgets, manifest: ManifestBudget = {}): BudgetCaps {
  const pick = (name: string, ceiling: number, asked: number | undefined): number => {
    assertUsable(`${name} (kernel)`, ceiling)
    if (asked === undefined) return ceiling
    assertUsable(`${name} (manifest)`, asked)
    if (asked > ceiling) {
      // Refused, not clamped. A clamp would leave the manifest asserting
      // something that is not true of any run it produces.
      throw new ConfigError(
        `manifest budget ${name} is ${String(asked)}, above the kernel ceiling ${String(ceiling)}. ` +
          'A manifest may only lower a cap.',
      )
    }
    return asked
  }

  return {
    usdMax: pick('usdMax', kernel.defaultRunMicroUsd, manifest.maxCostMicroUsd),
    maxLlmCalls: pick('maxLlmCalls', kernel.maxLlmCallsPerRun, manifest.maxLlmCalls),
    maxToolCalls: pick('maxToolCalls', kernel.maxToolCallsPerRun, manifest.maxToolCalls),
    wallclockMs: pick('wallclockMs', kernel.defaultWallclockMs, manifest.maxWallclockMs),
  }
}

export interface BudgetSpend {
  readonly costMicroUsd: number
  readonly llmCalls: number
  readonly toolCalls: number
  readonly elapsedMs: number
}

export interface BudgetOptions {
  /** Injected so tests need not mock the global clock. */
  readonly now?: () => number
}

export class Budget {
  readonly caps: BudgetCaps
  readonly #now: () => number
  #startedAt: number | undefined
  #costMicroUsd = 0
  #llmCalls = 0
  #toolCalls = 0

  constructor(caps: BudgetCaps, options: BudgetOptions = {}) {
    assertUsable('usdMax', caps.usdMax)
    assertUsable('maxLlmCalls', caps.maxLlmCalls)
    assertUsable('maxToolCalls', caps.maxToolCalls)
    assertUsable('wallclockMs', caps.wallclockMs)
    this.caps = caps
    this.#now = options.now ?? Date.now
  }

  /** Start the wallclock. Called once, at `run.started`. */
  start(): void {
    this.#startedAt ??= this.#now()
  }

  get started(): boolean {
    return this.#startedAt !== undefined
  }

  get spend(): BudgetSpend {
    return {
      costMicroUsd: this.#costMicroUsd,
      llmCalls: this.#llmCalls,
      toolCalls: this.#toolCalls,
      elapsedMs: this.#startedAt === undefined ? 0 : Math.max(0, this.#now() - this.#startedAt),
    }
  }

  /**
   * Record work that has already happened, and say whether the run may
   * continue.
   *
   * @throws {ConfigError} on a non-integer or negative amount — a float here
   *   would make a budget unreproducible, which is the same reason cost is
   *   integer micro-USD everywhere.
   */
  charge(kind: ChargeKind, amount = 1): BudgetCheck {
    if (!Number.isInteger(amount) || amount < 0) {
      throw new ConfigError(`budget charge must be a non-negative integer, got ${String(amount)}`)
    }
    if (kind === 'cost') this.#costMicroUsd += amount
    else if (kind === 'llm') this.#llmCalls += amount
    else this.#toolCalls += amount
    return this.check()
  }

  /**
   * May the run take another step?
   *
   * Order is deliberate: the wallclock is checked FIRST, so a run that has
   * overrun is reported as overrun rather than as whichever cap it happens to
   * cross next. An operator reading `usdMax` on a run that actually ran for an
   * hour would look in the wrong place.
   */
  check(): BudgetCheck {
    if (this.#startedAt !== undefined && this.#now() - this.#startedAt >= this.caps.wallclockMs) {
      return { ok: false, stop: 'wallclock' }
    }
    if (this.#costMicroUsd >= this.caps.usdMax) return { ok: false, stop: 'usdMax' }
    if (this.#llmCalls >= this.caps.maxLlmCalls) return { ok: false, stop: 'maxLlmCalls' }
    if (this.#toolCalls >= this.caps.maxToolCalls) return { ok: false, stop: 'maxToolCalls' }
    return OK
  }

  /** Milliseconds left on the wallclock, floored at zero. */
  remainingMs(): number {
    if (this.#startedAt === undefined) return this.caps.wallclockMs
    return Math.max(0, this.caps.wallclockMs - (this.#now() - this.#startedAt))
  }

  /** Micro-USD left, floored at zero. Used for D16's fallback check. */
  remainingMicroUsd(): number {
    return Math.max(0, this.caps.usdMax - this.#costMicroUsd)
  }
}
