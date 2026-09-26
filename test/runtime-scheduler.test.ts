// C.3 — the cron scheduler.
//
// A scheduled run is not a computation: it spends money and takes actions through
// tools. So the tests here are mostly about the four ways the scheduler declines
// to fire, because every one of them is a spend the operator did not ask for.
//
// The falsifiers:
//
//   Fire twice for the same minute — because the tick runs more often than once a
//   minute — and every job costs double. Two ticks inside one minute must fire once.
//   Lose the dedupe across a restart and a reboot inside a fired minute re-runs
//   the job. The claim is written to the log before the run starts, precisely so
//   a restart can read it back.
//   Queue instead of skipping when the agent is busy, and a job slower than its
//   interval builds a queue that never drains behind the per-agent serial lane.
//   Catch up after downtime and a three-hour outage becomes three runs launched
//   at once — at the moment the cause of the outage may still be true.
//
// The clock is injected. No test here sleeps, and none depends on the real minute.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { Scheduler, TICK_MS, scheduledInput } from '../src/runtime/scheduler.js'
import { minuteKey } from '../src/runtime/cron.js'
import { withStore } from './helpers/store.js'
import { storeFile } from './helpers/store.js'

type Store = ReturnType<typeof withStore>

interface Harness {
  readonly scheduler: Scheduler
  readonly starts: { agentId: string; input: string }[]
  setNow(iso: string): void
  setBusy(agentId: string, busy: boolean): void
}

function harness(
  store: Store,
  agents: readonly { agentId: string; schedule: string }[],
): Harness {
  const starts: { agentId: string; input: string }[] = []
  const busy = new Set<string>()
  let nowMs = Date.parse('2026-09-28T08:59:00')
  let counter = 0

  const scheduler = new Scheduler({
    store,
    agents: () => agents,
    isBusy: (agentId) => busy.has(agentId),
    startRun: (agentId, input) => {
      starts.push({ agentId, input })
      counter += 1
      return `run_${String(counter)}`
    },
    now: () => nowMs,
    // The tick is driven by hand, so start() must not install a real timer.
    setInterval: (() => ({ unref: () => undefined }) as never) as typeof globalThis.setInterval,
    clearInterval: (() => undefined) as typeof globalThis.clearInterval,
  })

  return {
    scheduler,
    starts,
    setNow: (iso) => {
      nowMs = Date.parse(iso)
    },
    setBusy: (agentId, isBusy) => {
      if (isBusy) busy.add(agentId)
      else busy.delete(agentId)
    },
  }
}

test('fires once per matching minute and never twice for the same minute', (t) => {
  const store = withStore(t)
  const h = harness(store, [{ agentId: 'ceo', schedule: '0 9 * * *' }])
  h.scheduler.start()

  // Before the minute: nothing.
  h.setNow('2026-09-28T08:59:30')
  assert.deepEqual(h.scheduler.tick(), [])
  assert.equal(h.starts.length, 0)

  // The matching minute fires.
  h.setNow('2026-09-28T09:00:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])
  assert.equal(h.starts.length, 1)

  // The tick runs twice a minute, so the SAME minute must not fire again. This is
  // the difference between a daily job and a job that runs twice a day.
  assert.ok(TICK_MS < 60_000, 'the tick must be finer than a minute for this to matter')
  h.setNow('2026-09-28T09:00:30')
  assert.deepEqual(h.scheduler.tick(), [])
  h.setNow('2026-09-28T09:00:59')
  assert.deepEqual(h.scheduler.tick(), [])
  assert.equal(h.starts.length, 1, 'the same minute fired more than once')

  // The next day's occurrence fires.
  h.setNow('2026-09-29T09:00:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])
  assert.equal(h.starts.length, 2)

  // The prompt names the agent, the schedule and the minute, so the log says why
  // the run exists.
  assert.match(h.starts[0]?.input ?? '', /Scheduled run for ceo \(0 9 \* \* \*\) at 2026-09-28T09:00/)
  assert.equal(h.starts[0]?.input, scheduledInput('ceo', '0 9 * * *', '2026-09-28T09:00'))
})

test('claims the minute in the log before starting, so a restart does not re-fire it', (t) => {
  const path = storeFile(t)
  const store = withStore(t, { path })
  const first = harness(store, [{ agentId: 'ceo', schedule: '0 9 * * *' }])
  first.scheduler.start()

  first.setNow('2026-09-28T09:00:00')
  assert.deepEqual(first.scheduler.tick(), ['ceo'])

  // The claim is durable, and it carries the minute — which is what makes it
  // readable back.
  const claims = store.query({ type: 'run.scheduled' })
  assert.equal(claims.length, 1)
  const payload = JSON.parse(claims[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(payload['agentId'], 'ceo')
  assert.equal(payload['minute'], '2026-09-28T09:00')
  assert.equal(payload['schedule'], '0 9 * * *')

  // A new process, same log, same minute. Without the seed this is the one
  // reliable way to run a job twice: reboot inside its minute.
  const second = harness(store, [{ agentId: 'ceo', schedule: '0 9 * * *' }])
  second.setNow('2026-09-28T09:00:20')
  second.scheduler.start()
  assert.deepEqual(second.scheduler.tick(), [], 'the restart re-fired a minute already claimed')
  assert.equal(second.starts.length, 0)

  // And the next occurrence still fires, so the seed did not wedge it.
  second.setNow('2026-09-29T09:00:00')
  assert.deepEqual(second.scheduler.tick(), ['ceo'])
})

test('skips a tick while the agent already has a run', (t) => {
  const store = withStore(t)
  const h = harness(store, [{ agentId: 'ceo', schedule: '* * * * *' }])
  h.scheduler.start()

  h.setNow('2026-09-28T09:00:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])

  // Its run is still going a minute later. Queued instead of skipped, a job
  // slower than its interval builds a queue that never drains — the per-agent
  // serial lane would run them one after another forever.
  h.setBusy('ceo', true)
  h.setNow('2026-09-28T09:01:00')
  assert.deepEqual(h.scheduler.tick(), [])
  h.setNow('2026-09-28T09:02:00')
  assert.deepEqual(h.scheduler.tick(), [])
  assert.equal(h.starts.length, 1)

  // A skipped minute is still CLAIMED, so it cannot fire when the run finishes
  // mid-minute. Otherwise clearing the flag at 09:02:30 would fire 09:02 late.
  h.setBusy('ceo', false)
  h.setNow('2026-09-28T09:02:30')
  assert.deepEqual(h.scheduler.tick(), [])
  assert.equal(h.starts.length, 1)

  // The next minute fires normally.
  h.setNow('2026-09-28T09:03:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])
  assert.equal(h.starts.length, 2)
})

test('never catches up on occurrences missed while it was not running', (t) => {
  const store = withStore(t)
  const h = harness(store, [{ agentId: 'ceo', schedule: '0 * * * *' }])
  h.scheduler.start()

  // It fires at 09:00, then the process is "down" for three hours: no ticks.
  h.setNow('2026-09-28T09:00:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])
  assert.equal(h.starts.length, 1)

  // Back at 12:00. Three occurrences were missed (10:00, 11:00, 12:00 is current).
  // Exactly ONE run starts — the current minute — not four.
  h.setNow('2026-09-28T12:00:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])
  assert.equal(h.starts.length, 2, 'the scheduler replayed missed occurrences')
  assert.match(h.starts[1]?.input ?? '', /at 2026-09-28T12:00/)

  // And coming back at a NON-matching minute fires nothing at all, rather than
  // firing the most recent missed occurrence late.
  const h2 = harness(store, [{ agentId: 'other', schedule: '0 * * * *' }])
  h2.scheduler.start()
  h2.setNow('2026-09-28T13:37:00')
  assert.deepEqual(h2.scheduler.tick(), [])
  assert.equal(h2.starts.length, 0)
})

test('a failing start still claims the minute, and one bad expression does not stop the others', (t) => {
  const store = withStore(t)
  const starts: string[] = []
  let nowMs = Date.parse('2026-09-28T09:00:00')
  let failNext = true

  const scheduler = new Scheduler({
    store,
    // The middle agent's expression is one the schema would have refused, so
    // reaching the scheduler with it is a bug. It must not take the others down.
    agents: () => [
      { agentId: 'first', schedule: '0 9 * * *' },
      { agentId: 'broken', schedule: '0 9 * * MON-FRI' },
      { agentId: 'third', schedule: '0 9 * * *' },
    ],
    isBusy: () => false,
    startRun: (agentId) => {
      if (agentId === 'first' && failNext) throw new Error('lane refused')
      starts.push(agentId)
      return `run_${agentId}`
    },
    now: () => nowMs,
    setInterval: (() => ({ unref: () => undefined }) as never) as typeof globalThis.setInterval,
    clearInterval: (() => undefined) as typeof globalThis.clearInterval,
  })
  scheduler.start()

  const fired = scheduler.tick()
  // `first` threw, `broken` was skipped with its reason, `third` ran anyway.
  assert.deepEqual(fired, ['third'])
  assert.deepEqual(starts, ['third'])

  // The failed one still claimed its minute. Otherwise a job that cannot start
  // would be retried on every tick of that minute, and again on every reboot.
  const claimed = store
    .query({ type: 'run.scheduled' })
    .map((r) => (JSON.parse(r.payload) as { agentId: string }).agentId)
  assert.deepEqual(claimed.sort(), ['first', 'third'])

  failNext = false
  nowMs = Date.parse('2026-09-28T09:00:30')
  assert.deepEqual(scheduler.tick(), [], 'a failed start was retried inside the same minute')
  assert.deepEqual(starts, ['third'])
})

test('diagnostics report each schedule and the minute it last fired', (t) => {
  const store = withStore(t)
  const h = harness(store, [
    { agentId: 'ceo', schedule: '0 9 * * *' },
    { agentId: 'idle', schedule: '0 3 * * *' },
  ])
  h.scheduler.start()
  h.setNow('2026-09-28T09:00:00')
  h.scheduler.tick()

  const d = h.scheduler.diagnostics()
  assert.deepEqual(
    d.map((x) => [x.agentId, x.schedule, x.lastFiredMinute]),
    [
      ['ceo', '0 9 * * *', '2026-09-28T09:00'],
      ['idle', '0 3 * * *', undefined],
    ],
  )
  assert.equal(minuteKey(new Date(Date.parse('2026-09-28T09:00:00'))), '2026-09-28T09:00')
  h.scheduler.stop()
})

test('start is idempotent and stop is safe before it', (t) => {
  const store = withStore(t)
  const h = harness(store, [{ agentId: 'ceo', schedule: '* * * * *' }])
  // Stopping a scheduler that never started must not throw: shutdown runs on a
  // boot that failed partway.
  h.scheduler.stop()
  h.scheduler.start()
  h.scheduler.start()
  h.setNow('2026-09-28T09:00:00')
  assert.deepEqual(h.scheduler.tick(), ['ceo'])
  assert.equal(h.starts.length, 1, 'starting twice doubled the fires')
  h.scheduler.stop()
  h.scheduler.stop()
})
