// T09 — the sandbox driver interface and its fake.
//
// The fake's defaults are chosen to be the inconvenient ones: no runtime
// available, and no run permitted that the test did not ask for. Both make
// the kernel's degraded and bounded paths the ones that get exercised.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { SandboxSpec } from '../src/sandbox/driver.js'
import { fakeSandbox } from './helpers/fake-sandbox.js'

function spec(overrides: Partial<SandboxSpec> = {}): SandboxSpec {
  return {
    name: 'aos-run-abc',
    runId: 'run-abc',
    agentId: 'coder',
    domain: 'trusted',
    image: 'aos-worker:0.0.1',
    command: ['npm', 'test'],
    workspace: '/var/aos/workspaces/run-abc',
    limits: { memoryMb: 2048, cpus: 2, pids: 256, wallclockMs: 600_000 },
    ...overrides,
  }
}

test('reports unavailable by default with a reason', async () => {
  // Default unavailable, because "no Docker" is the state the kernel must
  // boot in and report, not an edge case. A reason is mandatory: a bare false
  // tells an operator nothing.
  const driver = fakeSandbox()
  const probe = await driver.probe()
  assert.equal(probe.ok, false)
  assert.equal(typeof (probe.ok ? '' : probe.why), 'string')
  assert.ok((probe.ok ? '' : probe.why).length > 0)

  const available = fakeSandbox({ probe: { ok: true, version: '27.0.0' } })
  const ok = await available.probe()
  assert.equal(ok.ok, true)
  assert.equal(ok.ok && ok.version, '27.0.0')
})

test('records the exact spec and returns the scripted exit', async () => {
  const driver = fakeSandbox({ script: [{ exitCode: 0, stdout: 'ok\n', durationMs: 120 }] })
  const requested = spec()
  const running = driver.run(requested)

  // The spec is recorded by identity, so a later test can assert on every
  // field the driver was given — limits included, since a widened limit is
  // exactly the kind of drift that must not pass unnoticed.
  assert.equal(driver.specs.length, 1)
  assert.deepEqual(driver.specs[0], requested)
  assert.equal(driver.specs[0]?.limits.wallclockMs, 600_000)
  assert.equal(driver.specs[0]?.domain, 'trusted')

  const result = await running.result
  assert.equal(result.name, 'aos-run-abc')
  assert.equal(result.exitCode, 0)
  assert.equal(result.signal, null)
  assert.equal(result.stdout, 'ok\n')
  assert.equal(result.killedBy, undefined, 'a normal exit was not killed by anyone')
})

test('simulateOverrun resolves with SIGKILL and killedBy wallclock', async () => {
  const driver = fakeSandbox({ script: [{ hangs: true }] })
  const running = driver.run(spec({ name: 'aos-run-slow' }))

  driver.simulateOverrun('aos-run-slow')
  const result = await running.result

  // The wallclock is a hard stop, so it must be distinguishable from both a
  // clean exit and an operator kill.
  assert.equal(result.exitCode, null)
  assert.equal(result.signal, 'SIGKILL')
  assert.equal(result.killedBy, 'wallclock')
  assert.equal(result.durationMs, 600_000)
})

test('kill is idempotent', async () => {
  const driver = fakeSandbox({ script: [{ hangs: true }] })
  const running = driver.run(spec({ name: 'aos-run-kill' }))

  await driver.kill('aos-run-kill')
  const result = await running.result
  assert.equal(result.killedBy, 'requested')
  assert.equal(result.signal, 'SIGKILL')

  // Killing again, and killing something that never ran, must both be
  // harmless: shutdown and orphan sweeps call kill without knowing state.
  await driver.kill('aos-run-kill')
  await driver.kill('aos-run-never-existed')
  assert.deepEqual(driver.kills, ['aos-run-kill', 'aos-run-kill', 'aos-run-never-existed'])

  // The first result stands; a second kill does not rewrite it.
  assert.equal((await running.result).killedBy, 'requested')
})

test('throws on an unscripted run', () => {
  const driver = fakeSandbox({ script: [{ exitCode: 0 }] })
  driver.run(spec({ name: 'aos-run-1' }))

  // A double that invented a clean exit here would let runtime code start
  // more containers than the test intended and still pass.
  assert.throws(() => driver.run(spec({ name: 'aos-run-2' })), /unscripted run/)
  // The attempt is still recorded so the failure can name what was tried.
  assert.equal(driver.specs.length, 2)
  assert.equal(driver.specs[1]?.name, 'aos-run-2')
})
