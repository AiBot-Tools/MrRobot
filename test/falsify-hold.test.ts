// src/falsify-hold.ts: what keeps the daemon off a tree a falsify run holds.
//
// The daemon calls it before anything else; these tests call it directly,
// in-process, against temp trees, so the falsify catalog can mutate it (an
// entry point itself is never mutated beside the tests that spawn one).

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { falsifyRefusal, lockHolder, type Kill } from '../src/falsify-hold.js'
import { tmpdir } from './helpers/tmpdir.js'

const lock = (root: string, value: unknown): void => {
  mkdirSync(join(root, '.falsify'), { recursive: true })
  writeFileSync(join(root, '.falsify', 'lock.json'), typeof value === 'string' ? value : JSON.stringify(value))
}

// Above any system's pid range (Linux tops out at 2^22, macOS below 100000),
// so no process can hold it: a real kill(pid, 0) answers ESRCH.
const NO_SUCH_PID = 2 ** 31 - 1

test('a tree no falsify run touched is no reason to refuse', (t) => {
  const root = tmpdir(t)
  assert.equal(lockHolder(root), undefined)
  assert.equal(falsifyRefusal(root), undefined)
  mkdirSync(join(root, '.falsify'))
  assert.equal(falsifyRefusal(root), undefined, 'an empty .falsify/ holds no mutant')
})

test('a journal refuses whether its run is live or dead: a source file may still be mutated', (t) => {
  const root = tmpdir(t)
  mkdirSync(join(root, '.falsify'))
  writeFileSync(join(root, '.falsify', 'journal.json'), '{}')
  assert.match(falsifyRefusal(root) ?? '', /journal\.json exists: a falsify run is in progress or was interrupted.*--recover/)
})

test('a lock held by a live process refuses, naming it; one whose pid is gone does not', (t) => {
  // The test runner that started this file is alive for its whole run, and is
  // not this process: it stands in for a falsify run, with a real kill(pid, 0).
  const root = tmpdir(t)
  const pid = process.ppid
  lock(root, { pid, started: 'x', runId: 'run-a' })
  assert.deepEqual(lockHolder(root), { pid, runId: 'run-a' })
  assert.match(falsifyRefusal(root) ?? '', new RegExp(`a falsify run \\(pid ${String(pid)}\\) holds this tree.*--recover`))
  lock(root, { pid: NO_SUCH_PID, started: 'x', runId: 'run-b' })
  assert.equal(lockHolder(root), undefined)
  assert.equal(falsifyRefusal(root), undefined)
})

test('a live pid that belongs to someone else (EPERM) holds the lock; a missing one (ESRCH) does not', (t) => {
  const root = tmpdir(t)
  lock(root, { pid: 4242, started: 'x', runId: '' })
  const answer = (code: string): Kill => () => {
    throw Object.assign(new Error(code), { code })
  }
  assert.deepEqual(lockHolder(root, answer('EPERM')), { pid: 4242, runId: undefined })
  assert.match(falsifyRefusal(root, answer('EPERM')) ?? '', /pid 4242/)
  assert.equal(lockHolder(root, answer('ESRCH')), undefined)
  assert.equal(falsifyRefusal(root, answer('ESRCH')), undefined)
})

test('this process\'s own lock, and a lock that cannot name a pid, hold nothing', (t) => {
  const root = tmpdir(t)
  const alive: Kill = () => undefined
  lock(root, { pid: process.pid, started: 'x', runId: 'mine' })
  assert.equal(lockHolder(root, alive), undefined, 'a run refused its own tree')
  for (const bad of ['', '{', '[]', { pid: 'x' }, { pid: 0 }, { pid: -1 }, { pid: 1.5 }]) {
    lock(root, bad)
    assert.equal(lockHolder(root, alive), undefined, JSON.stringify(bad))
  }
})
