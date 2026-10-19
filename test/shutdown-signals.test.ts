// One Ctrl-C, one clean shutdown.
//
// Under `npm run dev` a single Ctrl-C reaches the daemon twice (the terminal's
// SIGINT to the process group, then npm's forwarded copy). The daemon used a
// once-listener, so the copy met Node's default action and killed the process
// mid-shutdown: on the operator's Mac the log lost its kernel.shutdown row.
// These tests hold the policy (src/shutdown-signals.ts) on a fake clock against
// an EventEmitter standing in for `process`. The load-bearing assertion is that
// a listener is still attached after the first signal: Node restores a signal's
// default action (terminate) once its last listener goes, which is what killed
// the daemon. Real processes are left out on purpose; hygiene.test.ts keeps
// node:child_process to the four test files that cannot do without it.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { DUPLICATE_WINDOW_MS, onShutdownSignals, signalGate } from '../src/shutdown-signals.js'

interface Recorder {
  readonly lines: { level: 'info' | 'error'; message: string }[]
  readonly exits: number[]
  readonly shutdowns: string[]
  finish(): void
  fail(error: Error): void
  clock: number
}

function recorder(): Recorder & { hooks: Parameters<typeof onShutdownSignals>[1] } {
  let settle: { resolve: () => void; reject: (e: Error) => void } | undefined
  const r = {
    lines: [] as Recorder['lines'],
    exits: [] as number[],
    shutdowns: [] as string[],
    clock: 0,
    finish: () => settle?.resolve(),
    fail: (e: Error) => settle?.reject(e),
  }
  return Object.assign(r, {
    hooks: {
      shutdown: (signal: string) => {
        r.shutdowns.push(signal)
        return new Promise<void>((resolve, reject) => {
          settle = { resolve, reject }
        })
      },
      exit: (code: number) => {
        r.exits.push(code)
      },
      log: {
        info: (_: Record<string, unknown>, message: string) => r.lines.push({ level: 'info', message }),
        error: (_: Record<string, unknown>, message: string) => r.lines.push({ level: 'error', message }),
      },
      now: () => r.clock,
    },
  })
}

test('the gate: the first signal shuts down, a repeat inside the window is ignored, a later one exits', () => {
  let clock = 0
  const gate = signalGate(() => clock)
  assert.equal(gate(), 'shutdown')
  clock = 5
  assert.equal(gate(), 'ignore')
  clock = DUPLICATE_WINDOW_MS - 1
  assert.equal(gate(), 'ignore')
  clock = DUPLICATE_WINDOW_MS
  assert.equal(gate(), 'exit')
})

test('one Ctrl-C delivered twice shuts the kernel down once, and a listener stays for the copy', async () => {
  const target = new EventEmitter()
  const r = recorder()
  const done = onShutdownSignals(target, r.hooks)

  target.emit('SIGINT', 'SIGINT')
  r.clock = 4
  // npm's forwarded copy, while the shutdown is still running.
  target.emit('SIGINT', 'SIGINT')
  assert.deepEqual(r.shutdowns, ['SIGINT'], 'the copy started a second shutdown')
  assert.deepEqual(r.exits, [], 'the copy forced an exit mid-shutdown')
  // The point of the fix: a listener is still there, so the OS default action
  // (terminate) never runs for a repeat.
  assert.equal(target.listenerCount('SIGINT'), 1)
  assert.equal(target.listenerCount('SIGTERM'), 1)
  assert.ok(r.lines.some((l) => /repeated signal ignored/.test(l.message)))

  r.finish()
  await done
})

test('a repeat after the window is the operator insisting on a hung shutdown, and exits at once', () => {
  const target = new EventEmitter()
  const r = recorder()
  void onShutdownSignals(target, r.hooks)
  target.emit('SIGTERM', 'SIGTERM')
  r.clock = DUPLICATE_WINDOW_MS + 500
  target.emit('SIGINT', 'SIGINT')
  assert.deepEqual(r.exits, [1])
  assert.ok(r.lines.some((l) => l.level === 'error' && /second signal during shutdown/.test(l.message)))
  r.finish()
})

test('a shutdown that fails is logged and still releases the daemon', async () => {
  const target = new EventEmitter()
  const r = recorder()
  const done = onShutdownSignals(target, r.hooks)
  target.emit('SIGINT', 'SIGINT')
  r.fail(new Error('the hub would not close'))
  await done
  assert.ok(r.lines.some((l) => l.level === 'error' && l.message === 'shutdown failed'))
})
