// The anchor is a claim, and a store may only make it after earning it.
//
// `events.head` is the external record that lets a verifier notice a TRUNCATED
// log: a truncated chain is internally valid, so the only evidence is an anchor
// pointing past the tail. Anything that rewrites the anchor to match a damaged
// tail erases that evidence permanently.
//
// The store used to do exactly that for any writer that did not verify first —
// on close(), and every `anchorEvery` appends. The kernel always verified before
// appending, so the kernel was safe; the STORE was not, and the next caller to
// open a log and write to it would have blessed whatever it found. These tests
// fail against that store.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { join } from 'node:path'
import test from 'node:test'

import { readAnchor } from '../src/events/anchor.js'
import type { EventStore } from '../src/events/store.js'
import { storeFile, withStoreUnverified } from './helpers/store.js'
import { tamper } from './helpers/tamper.js'
import { tmpdir } from './helpers/tmpdir.js'

const BOOT = { schemaVersion: 1 as const, version: '0.0.1', configHash: 'h', degraded: [] }

function seed(store: EventStore, n: number): void {
  for (let i = 0; i < n; i++) store.append({ type: 'kernel.booted', payload: BOOT })
}

/** A five-row log anchored at 5, then cut to three rows with the counter hidden. */
function truncatedLog(t: Parameters<typeof withStoreUnverified>[0]): { path: string; head: string } {
  const path = storeFile(t)
  const head = join(tmpdir(t), 'events.head')
  const writer = withStoreUnverified(t, { path, headFile: head })
  seed(writer, 5)
  writer.close()
  assert.equal(readAnchor(head)?.seq, 5, 'setup: the clean log should close anchored at its tail')

  const tp = tamper(path)
  tp.deleteRow(5)
  tp.deleteRow(4)
  tp.setSequenceCounter(3)
  tp.restoreTriggers()
  tp.close()
  return { path, head }
}

test('a writer that never verified leaves the anchor exactly as it found it', (t) => {
  const { path, head } = truncatedLog(t)
  const store = withStoreUnverified(t, { path, headFile: head })
  assert.equal(store.trusted, false, 'an existing log is untrusted until verified')
  store.close()

  // Still pointing past the tail — which is the whole of the evidence.
  assert.equal(readAnchor(head)?.seq, 5)
  const reopened = withStoreUnverified(t, { path, headFile: head, readOnly: true })
  const result = reopened.verifyChain(reopened.readAnchor())
  assert.equal(result.ok, false)
  assert.match(result.ok ? '' : result.reason, /truncation/)
})

test('a pass WITHOUT the on-disk anchor does not earn trust, because a truncated log passes that', (t) => {
  // The subtle one. verifyChain() with no anchor checks internal consistency only,
  // and a truncated log is internally consistent. Re-anchoring after that pass is
  // how the old store erased the truncation: the next verifier found an anchor at
  // seq 3 matching a three-row log, and passed.
  const { path, head } = truncatedLog(t)
  const store = withStoreUnverified(t, { path, headFile: head })
  const blind = store.verifyChain()
  assert.equal(blind.ok, true, 'setup: the truncated log verifies on its own')
  assert.equal(store.trusted, false, 'a blind pass must not be trusted')
  store.close()

  assert.equal(readAnchor(head)?.seq, 5, 'close() re-anchored a truncated log')
})

test('an untrusted writer’s appends do not move the anchor either', (t) => {
  // The periodic anchor had the same flaw as close(): every `anchorEvery` rows it
  // anchored whatever tail existed, including one chained onto a truncation.
  const { path, head } = truncatedLog(t)
  const store = withStoreUnverified(t, { path, headFile: head, anchorEvery: 1 })
  store.append({ type: 'kernel.booted', payload: BOOT })
  store.close()

  assert.equal(readAnchor(head)?.seq, 5)
  const reopened = withStoreUnverified(t, { path, headFile: head, readOnly: true })
  const result = reopened.verifyChain(reopened.readAnchor())
  // Four rows now, anchor still at five: the truncation is still visible.
  assert.equal(result.ok, false)
  assert.match(result.ok ? '' : result.reason, /tail \(seq 4\) is behind the anchored head \(seq 5\)/)
})

test('a truncated log fails verification against its anchor, so it can never become trusted', (t) => {
  const { path, head } = truncatedLog(t)
  const store = withStoreUnverified(t, { path, headFile: head })
  const result = store.verifyChain(store.readAnchor())
  assert.equal(result.ok, false)
  assert.equal(store.trusted, false)
  store.close()
  assert.equal(readAnchor(head)?.seq, 5)
})

test('verifying against the on-disk anchor earns trust, and the clean path still anchors', (t) => {
  // The kernel's path, which must keep working: verify against the real anchor,
  // append, close, and the anchor lands on the new tail.
  const path = storeFile(t)
  const head = join(tmpdir(t), 'events.head')
  const first = withStoreUnverified(t, { path, headFile: head })
  seed(first, 3)
  first.close()

  const store = withStoreUnverified(t, { path, headFile: head })
  assert.equal(store.trusted, false)
  assert.equal(store.verifyChain(store.readAnchor()).ok, true)
  assert.equal(store.trusted, true)
  seed(store, 2)
  store.close()
  assert.equal(readAnchor(head)?.seq, 5)
})

test('an old anchor that happens to pass does not earn trust — only the one on disk does', (t) => {
  // A log ahead of an anchor is normal (the anchor is periodic), so an OLD anchor
  // passes on a healthy log. Accepting it would let a caller earn trust with any
  // anchor it kept around, including one from before a truncation.
  const path = storeFile(t)
  const head = join(tmpdir(t), 'events.head')
  const first = withStoreUnverified(t, { path, headFile: head })
  seed(first, 3)
  const old = first.writeAnchor()
  seed(first, 4)
  first.close()
  assert.ok(old)
  assert.equal(readAnchor(head)?.seq, 7)

  const store = withStoreUnverified(t, { path, headFile: head })
  assert.equal(store.verifyChain(old).ok, true, 'setup: an old anchor passes on a longer log')
  assert.equal(store.trusted, false)
})

test('a store that created its database is trusted from the start; a read-only one never is', (t) => {
  const head = join(tmpdir(t), 'events.head')
  const path = storeFile(t)
  const fresh = withStoreUnverified(t, { path, headFile: head })
  assert.equal(fresh.trusted, true, 'there was no history anyone could have altered')
  seed(fresh, 2)
  fresh.close()
  assert.equal(readAnchor(head)?.seq, 2)

  const reader = withStoreUnverified(t, { path, headFile: head, readOnly: true })
  assert.equal(reader.verifyChain(reader.readAnchor()).ok, true)
  // Trust is about WRITING an anchor, which a read-only store never does; it may
  // still report a pass, but closing it must not touch the file.
  reader.close()
  assert.equal(readAnchor(head)?.seq, 2)
})
