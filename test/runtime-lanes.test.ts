// T26 — lanes.
//
// Not one assertion in this file reads a clock. A concurrency test written
// with timestamps or sleeps asserts that a machine was fast enough, which is
// a different claim from the one being made and is the standard way a suite
// acquires a flaky test it later learns to ignore.
//
// Instead: every task blocks on a deferred promise the test resolves by hand,
// and every task bumps a counter on entry and drops it on exit. Concurrency
// is then a number the test observes directly, and the schedule is entirely
// the test's to choose.
//
// The falsifiers:
//
//   Give the per-agent lane any capacity above one and two runs of the same
//   agent interleave tool calls against one memory and one workspace — after
//   which "this run did that" stops being a true sentence.
//   Share one pool between main and subagent and a fan-out of delegated work
//   starves the CEO that ordered it.
//   Take the global slot before the agent lane and a scarce slot sits idle,
//   held by a task waiting on a busy agent, while other agents queue behind.
//   Release outside a `finally` and one throwing run permanently shrinks the
//   pool; enough of them stop the kernel with nothing anywhere saying why.
//   Leave an aborted waiter in the queue and a cancelled run still executes.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { Lanes, LaneAborted, Semaphore } from '../src/runtime/lanes.js'

interface Deferred<T> {
  readonly promise: Promise<T>
  resolve(value: T): void
  reject(error: unknown): void
}

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

/** Let every already-settled promise deliver. No timers, no durations. */
const settle = async (): Promise<void> => {
  for (let i = 0; i < 8; i++) await Promise.resolve()
}

interface Probe {
  /** A task that blocks until its gate is resolved. */
  task(id: string): () => Promise<string>
  readonly gates: Map<string, Deferred<void>>
  readonly started: string[]
  readonly finished: string[]
  /** Highest number of tasks in flight at once, overall and per agent. */
  readonly peak: { global: number; byAgent: Map<string, number> }
  open(id: string): Promise<void>
}

function probe(agentOf: (id: string) => string = () => 'a'): Probe {
  const gates = new Map<string, Deferred<void>>()
  const started: string[] = []
  const finished: string[] = []
  const active = { global: 0, byAgent: new Map<string, number>() }
  const peak = { global: 0, byAgent: new Map<string, number>() }

  return {
    gates,
    started,
    finished,
    peak,
    task(id) {
      const gate = deferred()
      gates.set(id, gate)
      return async () => {
        const agent = agentOf(id)
        started.push(id)
        active.global++
        active.byAgent.set(agent, (active.byAgent.get(agent) ?? 0) + 1)
        peak.global = Math.max(peak.global, active.global)
        peak.byAgent.set(agent, Math.max(peak.byAgent.get(agent) ?? 0, active.byAgent.get(agent) ?? 0))
        try {
          await gate.promise
          return id
        } finally {
          active.global--
          active.byAgent.set(agent, (active.byAgent.get(agent) ?? 1) - 1)
          finished.push(id)
        }
      }
    },
    async open(id) {
      gates.get(id)?.resolve()
      await settle()
    },
  }
}

// ── per-agent serialisation ────────────────────────────────────────────────

test('two runs for the same agent never overlap (maxActive per agent 1) and finish in order', async () => {
  const lanes = new Lanes({ main: 4, subagent: 8 })
  const p = probe()

  const first = lanes.enqueue({ agentId: 'ceo', lane: 'main' }, p.task('r1'))
  const second = lanes.enqueue({ agentId: 'ceo', lane: 'main' }, p.task('r2'))
  const third = lanes.enqueue({ agentId: 'ceo', lane: 'main' }, p.task('r3'))
  await settle()

  // Three runs, four free slots — and still only one running, because the
  // constraint that bites is the agent's own lane.
  assert.deepEqual(p.started, ['r1'])
  assert.equal(lanes.diagnostics().lanes.main.active, 1)

  await p.open('r1')
  assert.deepEqual(p.started, ['r1', 'r2'])
  await p.open('r2')
  await p.open('r3')

  assert.deepEqual(await Promise.all([first, second, third]), ['r1', 'r2', 'r3'])
  // FIFO: a later arrival never jumps an earlier one for the same agent.
  assert.deepEqual(p.finished, ['r1', 'r2', 'r3'])
  assert.equal(p.peak.byAgent.get('a'), 1)
})

test('different agents run concurrently up to the lane cap', async () => {
  const lanes = new Lanes({ main: 4, subagent: 8 })
  const p = probe((id) => id)

  const all = ['x', 'y', 'z'].map((id) => lanes.enqueue({ agentId: id, lane: 'main' }, p.task(id)))
  await settle()

  // Serialisation is per agent, not global: three agents, three in flight.
  assert.deepEqual(p.started.sort(), ['x', 'y', 'z'])
  for (const id of ['x', 'y', 'z']) await p.open(id)
  assert.deepEqual((await Promise.all(all)).sort(), ['x', 'y', 'z'])
})

// ── the global cap ─────────────────────────────────────────────────────────

test('global cap bounds concurrency (cap 2, 5 tasks → maxActive 2)', async () => {
  const lanes = new Lanes({ main: 2, subagent: 8 })
  const p = probe((id) => id)
  const ids = ['t1', 't2', 't3', 't4', 't5']

  // One agent each, so nothing is serialised by the agent lane and the cap is
  // the only thing holding them back.
  const all = ids.map((id) => lanes.enqueue({ agentId: id, lane: 'main' }, p.task(id)))
  await settle()

  assert.deepEqual(p.started, ['t1', 't2'])
  assert.deepEqual(lanes.diagnostics().lanes.main, { active: 2, queued: 3, cap: 2 })

  // Each completion admits exactly one waiter, in arrival order.
  await p.open('t1')
  assert.deepEqual(p.started, ['t1', 't2', 't3'])
  await p.open('t2')
  assert.deepEqual(p.started, ['t1', 't2', 't3', 't4'])
  await p.open('t3')
  await p.open('t4')
  await p.open('t5')

  await Promise.all(all)
  assert.equal(p.peak.global, 2, 'never more than the cap in flight')
  assert.deepEqual(lanes.diagnostics().lanes.main, { active: 0, queued: 0, cap: 2 })
})

test('subagent lane does not consume main slots', async () => {
  const lanes = new Lanes({ main: 1, subagent: 2 })
  const p = probe((id) => id)

  // Fill main completely.
  const m = lanes.enqueue({ agentId: 'ceo', lane: 'main' }, p.task('main-1'))
  // A fan-out of delegated work must not starve the agent that ordered it.
  const s1 = lanes.enqueue({ agentId: 'w1', lane: 'subagent' }, p.task('sub-1'))
  const s2 = lanes.enqueue({ agentId: 'w2', lane: 'subagent' }, p.task('sub-2'))
  const s3 = lanes.enqueue({ agentId: 'w3', lane: 'subagent' }, p.task('sub-3'))
  await settle()

  assert.deepEqual(p.started, ['main-1', 'sub-1', 'sub-2'])
  const d = lanes.diagnostics()
  assert.deepEqual(d.lanes.main, { active: 1, queued: 0, cap: 1 })
  assert.deepEqual(d.lanes.subagent, { active: 2, queued: 1, cap: 2 })

  // A subagent finishing frees a subagent slot and nothing else.
  await p.open('sub-1')
  assert.deepEqual(p.started, ['main-1', 'sub-1', 'sub-2', 'sub-3'])
  assert.equal(lanes.diagnostics().lanes.main.active, 1)

  for (const id of ['main-1', 'sub-2', 'sub-3']) await p.open(id)
  await Promise.all([m, s1, s2, s3])
})

test('a task waiting on a busy agent does not hold a global slot', async () => {
  const lanes = new Lanes({ main: 1, subagent: 8 })
  const p = probe((id) => id)

  const running = lanes.enqueue({ agentId: 'ceo', lane: 'main' }, p.task('ceo-1'))
  const queuedBehind = lanes.enqueue({ agentId: 'ceo', lane: 'main' }, p.task('ceo-2'))
  await settle()

  // ceo-2 is waiting for the CEO's own lane. If it had taken the single main
  // slot first, that slot would be idle and unavailable to everyone else.
  assert.deepEqual(lanes.diagnostics().lanes.main, { active: 1, queued: 0, cap: 1 })

  await p.open('ceo-1')
  await p.open('ceo-2')
  await Promise.all([running, queuedBehind])
})

// ── diagnostics, abort, failure ────────────────────────────────────────────

test('diagnostics reports active/queued/cap', async () => {
  const lanes = new Lanes({ main: 2, subagent: 3 })
  const p = probe((id) => id.slice(0, 2))

  assert.deepEqual(lanes.diagnostics(), {
    lanes: { main: { active: 0, queued: 0, cap: 2 }, subagent: { active: 0, queued: 0, cap: 3 } },
    agents: [],
  })

  const all = [
    lanes.enqueue({ agentId: 'aa', lane: 'main' }, p.task('aa-1')),
    lanes.enqueue({ agentId: 'aa', lane: 'main' }, p.task('aa-2')),
    lanes.enqueue({ agentId: 'bb', lane: 'main' }, p.task('bb-1')),
    lanes.enqueue({ agentId: 'cc', lane: 'main' }, p.task('cc-1')),
  ]
  await settle()

  const d = lanes.diagnostics()
  assert.deepEqual(d.lanes.main, { active: 2, queued: 1, cap: 2 })
  assert.deepEqual(d.lanes.subagent, { active: 0, queued: 0, cap: 3 })
  // aa has one run holding its lane and one behind it; cc holds its own lane
  // while queued for a main slot.
  assert.deepEqual(d.agents, [
    { agentId: 'aa', active: true, queued: 1 },
    { agentId: 'bb', active: true, queued: 0 },
    { agentId: 'cc', active: true, queued: 0 },
  ])

  for (const id of ['aa-1', 'bb-1', 'cc-1', 'aa-2']) await p.open(id)
  await Promise.all(all)

  // Every lane released, and idle agents forgotten rather than accumulated:
  // ephemeral agents arrive by the hundred.
  assert.deepEqual(lanes.diagnostics(), {
    lanes: { main: { active: 0, queued: 0, cap: 2 }, subagent: { active: 0, queued: 0, cap: 3 } },
    agents: [],
  })
})

test('aborting a queued run removes it without running', async () => {
  const lanes = new Lanes({ main: 1, subagent: 8 })
  const p = probe((id) => id)
  const controller = new AbortController()

  const running = lanes.enqueue({ agentId: 'x', lane: 'main' }, p.task('running'))
  const cancelled = lanes.enqueue(
    { agentId: 'y', lane: 'main', signal: controller.signal },
    p.task('cancelled'),
  )
  const after = lanes.enqueue({ agentId: 'z', lane: 'main' }, p.task('after'))
  await settle()

  assert.deepEqual(p.started, ['running'])
  assert.equal(lanes.diagnostics().lanes.main.queued, 2)

  controller.abort()
  await assert.rejects(cancelled, (e: unknown) => e instanceof LaneAborted && e.agentId === 'y')
  await settle()

  // Removed from the queue entirely: the slot that frees up goes to the run
  // behind it, not to a run nobody wants any more.
  assert.equal(lanes.diagnostics().lanes.main.queued, 1)
  await p.open('running')
  assert.deepEqual(p.started, ['running', 'after'])
  assert.equal(p.started.includes('cancelled'), false, 'an aborted task must never run')

  await p.open('after')
  await Promise.all([running, after])
})

test('a signal already aborted at enqueue never runs the task', async () => {
  const lanes = new Lanes({ main: 4, subagent: 8 })
  const p = probe()
  const signal = AbortSignal.abort()

  // Nothing is busy: the task would start immediately if the check came after
  // admission rather than before it.
  await assert.rejects(
    lanes.enqueue({ agentId: 'x', lane: 'main', signal }, p.task('never')),
    LaneAborted,
  )
  assert.deepEqual(p.started, [])
  assert.deepEqual(lanes.diagnostics().agents, [])
})

test('a throwing task releases its lane', async () => {
  const lanes = new Lanes({ main: 1, subagent: 8 })
  const p = probe((id) => id)

  const boom = lanes.enqueue({ agentId: 'x', lane: 'main' }, () =>
    Promise.reject(new Error('the run blew up')),
  )
  await assert.rejects(boom, /the run blew up/)

  // One failing run must not permanently shrink the pool. Enough of them and
  // the kernel stops with nothing anywhere saying why.
  assert.deepEqual(lanes.diagnostics().lanes.main, { active: 0, queued: 0, cap: 1 })
  assert.deepEqual(lanes.diagnostics().agents, [])

  const ok = lanes.enqueue({ agentId: 'x', lane: 'main' }, p.task('after-the-throw'))
  await settle()
  assert.deepEqual(p.started, ['after-the-throw'])
  await p.open('after-the-throw')
  assert.equal(await ok, 'after-the-throw')

  // And the same for an agent whose run throws while others queue behind it.
  const q = probe((id) => id)
  const first = lanes.enqueue({ agentId: 'y', lane: 'main' }, () => Promise.reject(new Error('nope')))
  const second = lanes.enqueue({ agentId: 'y', lane: 'main' }, q.task('y-2'))
  await assert.rejects(first, /nope/)
  await settle()
  assert.deepEqual(q.started, ['y-2'], 'the agent lane was released too')
  await q.open('y-2')
  assert.equal(await second, 'y-2')
})

test('an already-aborted signal is refused even when the lane is full', async () => {
  const lanes = new Lanes({ main: 1, subagent: 8 })
  const p = probe((id) => id)

  const running = lanes.enqueue({ agentId: 'x', lane: 'main' }, p.task('running'))
  await settle()
  assert.deepEqual(lanes.diagnostics().lanes.main, { active: 1, queued: 0, cap: 1 })

  // With no free slot this would JOIN the queue — and a listener added to a
  // signal that has already fired never runs, so it would wait for ever with
  // nothing left to wake it.
  await assert.rejects(
    lanes.enqueue({ agentId: 'y', lane: 'main', signal: AbortSignal.abort() }, p.task('doomed')),
    LaneAborted,
  )
  assert.equal(lanes.diagnostics().lanes.main.queued, 0)

  await p.open('running')
  await running
  assert.equal(p.started.includes('doomed'), false)
})

test('releasing a permit twice does not raise the cap', async () => {
  // Not reachable through Lanes today, which is exactly why it is pinned
  // here: the guard is invisible until an edit calls a release twice, and by
  // then the cap has silently become no cap at all.
  const sem = new Semaphore(1)
  const release = await sem.acquire('x', 'a slot')
  assert.equal(sem.active, 1)

  release()
  release()
  release()
  assert.equal(sem.active, 0, 'a double release must not go negative')

  // And the permit count is still one, not three.
  await sem.acquire('x', 'a slot')
  assert.equal(sem.active, 1)
  let secondStarted = false
  void sem.acquire('y', 'a slot').then(() => {
    secondStarted = true
  })
  await settle()
  assert.equal(secondStarted, false, 'the cap still holds after a double release')
})

test('a lane capacity below one is refused at construction', () => {
  assert.throws(() => new Lanes({ main: 0, subagent: 8 }), /positive integer/)
  assert.throws(() => new Lanes({ main: 4, subagent: -1 }), /positive integer/)
  assert.throws(() => new Lanes({ main: 1.5, subagent: 8 }), /positive integer/)
})
