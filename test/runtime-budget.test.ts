// T27b — run budgets and the wallclock.
//
// CLAUDE.md lists disabling these among the things the kernel never does, so
// the tests are about the ways a cap stops being a cap without anyone
// intending it:
//
//   Pause the wallclock while a run is parked and a run waits on a human for
//   an hour, then runs for its full allowance afterwards — the cap the
//   operator set was never the cap that applied (D19).
//   Clamp a manifest that asks for more instead of refusing it, and the
//   manifest goes on asserting something untrue of every run it produces.
//   Admit Infinity and "no budget" survives review, because it is spelled
//   like a number.
//   Charge before the work and a cap of N permits N-1, which looks like
//   nothing at all until someone counts.
//   Report whichever cap is crossed first in field order, and a run that
//   actually ran for an hour is filed under usdMax.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ConfigError } from '../src/errors.js'
import { Budget, resolveCaps, STOP_REASONS, type BudgetCaps } from '../src/runtime/budget.js'

const KERNEL = {
  defaultRunMicroUsd: 2_000_000,
  defaultWallclockMs: 600_000,
  maxLlmCallsPerRun: 50,
  maxToolCallsPerRun: 100,
}

const CAPS: BudgetCaps = {
  usdMax: 1_000,
  maxLlmCalls: 2,
  maxToolCalls: 3,
  wallclockMs: 10_000,
}

/** A budget on a clock the test drives by hand. No timers, no sleeps. */
function budgetAt(caps: Partial<BudgetCaps> = {}): { budget: Budget; advance(ms: number): void } {
  let clock = 1_000_000
  const budget = new Budget({ ...CAPS, ...caps }, { now: () => clock })
  return {
    budget,
    advance(ms) {
      clock += ms
    },
  }
}

// ── the caps ───────────────────────────────────────────────────────────────

test('usdMax stops with reason usdMax at the first charge that crosses it', () => {
  const { budget } = budgetAt()
  budget.start()

  assert.deepEqual(budget.charge('cost', 400), { ok: true })
  assert.deepEqual(budget.charge('cost', 400), { ok: true })
  // 1_200 >= 1_000: the first charge that crosses, not the one after it.
  assert.deepEqual(budget.charge('cost', 400), { ok: false, stop: 'usdMax' })
  assert.equal(budget.spend.costMicroUsd, 1_200)
  // It stays stopped: a budget is not a warning.
  assert.deepEqual(budget.check(), { ok: false, stop: 'usdMax' })
  assert.equal(budget.remainingMicroUsd(), 0)
})

test('maxLlmCalls and maxToolCalls stop with their own reason codes', () => {
  const llm = budgetAt().budget
  llm.start()
  // A cap of 2 permits exactly 2, because the charge records work that has
  // already happened — a call's cost is not knowable before it is made.
  assert.deepEqual(llm.charge('llm'), { ok: true })
  assert.deepEqual(llm.charge('llm'), { ok: false, stop: 'maxLlmCalls' })
  assert.equal(llm.spend.llmCalls, 2)

  const tool = budgetAt().budget
  tool.start()
  assert.deepEqual(tool.charge('tool'), { ok: true })
  assert.deepEqual(tool.charge('tool'), { ok: true })
  assert.deepEqual(tool.charge('tool'), { ok: false, stop: 'maxToolCalls' })

  // Each cap reports itself, never a neighbour.
  assert.deepEqual(budgetAt({ maxToolCalls: 1 }).budget.charge('tool'), {
    ok: false,
    stop: 'maxToolCalls',
  })
})

test('wallclock stops with reason wallclock', () => {
  const { budget, advance } = budgetAt()
  budget.start()

  advance(9_999)
  assert.deepEqual(budget.check(), { ok: true })
  assert.equal(budget.remainingMs(), 1)

  advance(1)
  assert.deepEqual(budget.check(), { ok: false, stop: 'wallclock' })
  assert.equal(budget.remainingMs(), 0)

  // The wallclock is reported ahead of every other cap, so a run that
  // overran is filed as overrun rather than as whichever cap it crossed on
  // the way — an operator reading "usdMax" would look in the wrong place.
  const both = budgetAt().budget
  both.start()
  both.charge('cost', 5_000)
  assert.deepEqual(both.check(), { ok: false, stop: 'usdMax' })
  const timed = budgetAt()
  timed.budget.start()
  timed.budget.charge('cost', 5_000)
  timed.advance(20_000)
  assert.deepEqual(timed.budget.check(), { ok: false, stop: 'wallclock' })
})

test('wallclock keeps running while parked (park, tick past the cap, resume → wallclock)', () => {
  const { budget, advance } = budgetAt()
  budget.start()
  assert.deepEqual(budget.check(), { ok: true })

  // The run parks for a human. There is deliberately no pause() to call: D19
  // says the clock keeps running, and the way to guarantee that is to have
  // nothing that could stop it. A parked run still holds a lane, a workspace
  // and a place in someone's attention.
  assert.equal('pause' in budget, false)
  assert.equal(typeof (budget as unknown as Record<string, unknown>)['pause'], 'undefined')

  advance(11_000)

  // Resumed after a slow approval, and immediately out of time.
  assert.deepEqual(budget.check(), { ok: false, stop: 'wallclock' })
  assert.equal(budget.spend.elapsedMs, 11_000)
})

// ── construction ───────────────────────────────────────────────────────────

test('a manifest budget above the kernel budget is refused; below is honoured', () => {
  // Nothing asked for: the operator's ceilings apply as they are.
  assert.deepEqual(resolveCaps(KERNEL), {
    usdMax: 2_000_000,
    maxLlmCalls: 50,
    maxToolCalls: 100,
    wallclockMs: 600_000,
  })

  // Lower is the whole point of a manifest budget.
  assert.deepEqual(resolveCaps(KERNEL, { maxCostMicroUsd: 500_000, maxLlmCalls: 10 }), {
    usdMax: 500_000,
    maxLlmCalls: 10,
    maxToolCalls: 100,
    wallclockMs: 600_000,
  })

  // Higher is refused, not clamped: a clamp leaves the manifest asserting
  // something untrue of every run it produces.
  for (const over of [
    { maxCostMicroUsd: 2_000_001 },
    { maxLlmCalls: 51 },
    { maxToolCalls: 101 },
    { maxWallclockMs: 600_001 },
  ]) {
    assert.throws(
      () => resolveCaps(KERNEL, over),
      (e: unknown) => e instanceof ConfigError && /may only lower a cap/.test(e.message),
      JSON.stringify(over),
    )
  }

  // Exactly equal is not "above".
  assert.equal(resolveCaps(KERNEL, { maxLlmCalls: 50 }).maxLlmCalls, 50)
})

test('Infinity, 0 and negative caps are refused at construction', () => {
  for (const bad of [Number.POSITIVE_INFINITY, 0, -1, 1.5, Number.NaN]) {
    // Infinity is "no budget" spelled so it survives review; zero is a
    // disabled agent written as a typo. Neither may reach a run.
    assert.throws(() => new Budget({ ...CAPS, usdMax: bad }), ConfigError, `usdMax ${String(bad)}`)
    assert.throws(
      () => new Budget({ ...CAPS, wallclockMs: bad }),
      ConfigError,
      `wallclockMs ${String(bad)}`,
    )
    assert.throws(
      () => resolveCaps({ ...KERNEL, maxLlmCallsPerRun: bad }),
      ConfigError,
      `kernel maxLlmCalls ${String(bad)}`,
    )
    assert.throws(
      () => resolveCaps(KERNEL, { maxLlmCalls: bad }),
      ConfigError,
      `manifest maxLlmCalls ${String(bad)}`,
    )
  }

  // A charge cannot be a float either: money that is not an integer is money
  // two implementations can disagree about.
  const { budget } = budgetAt()
  assert.throws(() => budget.charge('cost', 0.5), ConfigError)
  assert.throws(() => budget.charge('cost', -1), ConfigError)
})

test('reason codes equal the frozen literal list', () => {
  // The control plane matches on these; adding one is a protocol change.
  assert.deepEqual([...STOP_REASONS], ['usdMax', 'maxLlmCalls', 'maxToolCalls', 'wallclock'])
})

test('the wallclock only starts when the run does, and start is idempotent', () => {
  const { budget, advance } = budgetAt()

  // Queued in a lane is not running: time spent waiting for a slot is not the
  // agent's wallclock to spend.
  advance(50_000)
  assert.equal(budget.started, false)
  assert.deepEqual(budget.check(), { ok: true })
  assert.equal(budget.spend.elapsedMs, 0)

  budget.start()
  advance(5_000)
  budget.start()
  // A second start must not rewind the clock a run has already burned.
  assert.equal(budget.spend.elapsedMs, 5_000)
})
