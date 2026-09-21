// T10 — the ambient run scope and the writer claim.
//
// Two properties matter. The scope must survive the await boundaries that
// real work is full of, or kernel code would silently lose track of whose
// run it is. And it must be a closed, frozen record, because anything a run
// could add to it or change in it becomes a way to describe itself as more
// privileged than it is.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'

import { RunScope, runScope, withRunScope } from '../src/runtime/scope.js'
import { withStore } from './helpers/store.js'

const SCOPE: RunScope = {
  runId: 'run-a',
  agentId: 'ceo',
  taint: 'clean',
  tier: 0,
  lane: 'ceo',
}

const BOOT = { schemaVersion: 1 as const, version: '0.0.1', degraded: [] }

test('scope survives await boundaries', async () => {
  const seen: (string | undefined)[] = []

  await withRunScope(SCOPE, async () => {
    seen.push(runScope()?.runId)
    await delay(1)
    seen.push(runScope()?.runId)
    await Promise.all([
      (async () => {
        await delay(1)
        seen.push(runScope()?.runId)
      })(),
      (async () => {
        seen.push(runScope()?.runId)
      })(),
    ])
  })

  assert.deepEqual(seen, ['run-a', 'run-a', 'run-a', 'run-a'])
  assert.equal(runScope(), undefined, 'the scope must not leak past its own call')

  // Two concurrent runs must not see each other's identity.
  const observed: string[] = []
  await Promise.all([
    withRunScope({ ...SCOPE, runId: 'run-1' }, async () => {
      await delay(2)
      observed.push(runScope()?.runId ?? 'none')
    }),
    withRunScope({ ...SCOPE, runId: 'run-2' }, async () => {
      await delay(1)
      observed.push(runScope()?.runId ?? 'none')
    }),
  ])
  assert.deepEqual(observed.sort(), ['run-1', 'run-2'])
})

test('RunScope rejects unknown keys (a token cannot ride the scope)', () => {
  // The scope is ambient and reachable from anywhere in the kernel, so an
  // extra field here would be a credential channel that bypasses the broker
  // entirely. Strictness is what closes it.
  assert.throws(
    () => withRunScope({ ...SCOPE, token: 'sk-ant-FAKE' } as unknown as RunScope, () => 0),
    /unrecognized|unknown/i,
  )
  assert.throws(
    () => withRunScope({ ...SCOPE, apiKey: 'FAKE' } as unknown as RunScope, () => 0),
    /unrecognized|unknown/i,
  )
  // Malformed values are refused too, not coerced.
  assert.throws(() => withRunScope({ ...SCOPE, tier: -1 }, () => 0))
  assert.throws(() => withRunScope({ ...SCOPE, taint: 'sort-of' } as unknown as RunScope, () => 0))
  assert.throws(() => withRunScope({ ...SCOPE, runId: '' }, () => 0))
})

test('scope object is frozen', () => {
  withRunScope(SCOPE, () => {
    const scope = runScope()
    assert.ok(scope)
    assert.equal(Object.isFrozen(scope), true)
    // A run must not be able to launder its own taint or raise its own tier.
    assert.throws(() => {
      ;(scope as { taint: string }).taint = 'clean'
    }, TypeError)
    assert.throws(() => {
      ;(scope as { tier: number }).tier = 9
    }, TypeError)
    assert.equal(runScope()?.tier, 0)
  })
})

test('append inside a run scope refuses a foreign runId and accepts its own', (t) => {
  const store = withStore(t)

  withRunScope(SCOPE, () => {
    // Its own id: fine.
    const mine = store.append({ type: 'kernel.booted', payload: BOOT, runId: 'run-a' })
    assert.equal(mine.runId, 'run-a')

    // Omitted: the scope fills it in, so a run cannot write unattributed
    // history either.
    const implied = store.append({ type: 'kernel.booted', payload: BOOT })
    assert.equal(implied.runId, 'run-a')

    // Someone else's id: refused. This is the writer claim.
    assert.throws(
      () => store.append({ type: 'kernel.booted', payload: BOOT, runId: 'run-b' }),
      /writer claim: run run-a may not append events for run run-b/,
    )
  })

  assert.equal(store.query().length, 2, 'the refused append must not have been written')
  assert.equal(store.verifyChain().ok, true)
})

test('runScope() is undefined outside a run and kernel appends still work', (t) => {
  const store = withStore(t)
  assert.equal(runScope(), undefined)

  // Boot, shutdown and control-plane events are written by the kernel itself,
  // outside any run, and may name any run or none.
  const boot = store.append({ type: 'kernel.booted', payload: BOOT })
  assert.equal(boot.runId, null)
  const about = store.append({ type: 'kernel.booted', payload: BOOT, runId: 'run-zzz' })
  assert.equal(about.runId, 'run-zzz')

  assert.equal(store.query().length, 2)
  assert.equal(store.verifyChain().ok, true)
})
