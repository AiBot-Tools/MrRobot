// Soul loader (invariant 8).
//
// A soul is an agent's persona: plain Markdown under souls/, read at run
// start and prepended to its context. This module exports exactly two things,
// SOUL_BUDGET and loadSoul, and deliberately no writer. There is no save, no
// update, no path that takes content — the absence is the guarantee, and a
// test asserts the export list so a helpful future addition cannot slip in.
//
// Budgets exist because a soul is untrusted-ish input to the context window:
// it is operator-authored, but an oversized one silently eats the budget that
// should hold the actual task. Over-long souls are truncated and FLAGGED
// rather than rejected, so an agent still runs, and the flag tells the
// operator to trim it.
//
// A missing soul yields a marker rather than throwing. An agent with no
// persona is a degraded agent, not a dead kernel, and the marker makes the
// gap visible in the prompt itself instead of failing at boot.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { ConfigError } from '../errors.js'
import { SOUL_NAME } from './manifest.js'

export const SOUL_BUDGET = {
  /** Per-file cap, in characters. */
  perFile: 20_000,
  /** Cap across every soul loaded in one process. */
  total: 60_000,
} as const

export interface Soul {
  readonly name: string
  readonly text: string
  readonly truncated: boolean
  /** Character length before truncation. */
  readonly chars: number
  readonly missing: boolean
}

/**
 * Mutable budget counter, owned by the caller. The kernel keeps one for the
 * process; a test keeps its own, so tests cannot exhaust each other's budget.
 */
export interface SoulBudgetTracker {
  used: number
}

/**
 * Read one soul. Truncates at the per-file cap or whatever remains of the
 * total, whichever is smaller, and reports which happened.
 *
 * This is the module's only function, and it only reads. There is no writer
 * here by design, and souls.test.ts asserts the export list so a helpful
 * future addition cannot slip one in.
 */
export function loadSoul(
  soulsDir: string,
  name: string,
  tracker: SoulBudgetTracker = { used: 0 },
): Soul {
  // A soul is a basename, never a path. Second line of defence after the
  // manifest schema: nothing reads ../../etc/passwd by calling it a persona.
  if (!SOUL_NAME.test(name)) {
    throw new ConfigError(`soul "${name}" is not a plain <name>.md basename`)
  }

  let raw: string
  try {
    raw = readFileSync(join(soulsDir, name), 'utf8')
  } catch {
    return {
      name,
      text: `[soul ${name} is missing from ${soulsDir}]`,
      truncated: false,
      chars: 0,
      missing: true,
    }
  }

  const chars = raw.length
  const remaining = Math.max(0, SOUL_BUDGET.total - tracker.used)
  const allowed = Math.min(SOUL_BUDGET.perFile, remaining)

  if (chars <= allowed) {
    tracker.used += chars
    return Object.freeze({ name, text: raw, truncated: false, chars, missing: false })
  }

  tracker.used += allowed
  return Object.freeze({
    name,
    text: `${raw.slice(0, allowed)}\n\n[soul ${name} truncated: ${String(chars)} chars exceeded the budget]`,
    truncated: true,
    chars,
    missing: false,
  })
}
