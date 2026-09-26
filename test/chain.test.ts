// T06 — chain verification and the anchor.
//
// Every test here damages a log the way someone with write access to the file
// actually could, and asserts that verification says so, precisely. The
// headline case is the one a chain cannot solve by itself: cut rows off the
// end and what remains is a valid chain. Only the anchor sees it.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { statSync } from 'node:fs'
import { join } from 'node:path'

import { readAnchor, writeAnchor, type Anchor } from '../src/events/anchor.js'
import { GENESIS, verifyChain } from '../src/events/chain.js'
import { sha256Hex } from '../src/events/canonical.js'
import { openDb } from '../src/events/db.js'
import { EventStore } from '../src/events/store.js'
import { storeFile, withStore, withStoreUnverified } from './helpers/store.js'
import { tamper } from './helpers/tamper.js'
import { tmpdir } from './helpers/tmpdir.js'

const BOOT = { schemaVersion: 1 as const, version: '0.0.1', configHash: 'h', degraded: [] }

function seed(store: EventStore, n: number): void {
  for (let i = 0; i < n; i++) {
    store.append({ type: 'kernel.booted', payload: { ...BOOT, degraded: [`boot-${String(i)}`] } })
  }
}

/** Seed a file-backed log, close it, and hand back a reader over the file. */
function damagedLog(t: Parameters<typeof withStore>[0], rows: number): { path: string } {
  const path = storeFile(t)
  const store = withStoreUnverified(t, { path })
  seed(store, rows)
  store.close()
  return { path }
}

function verifyFile(path: string, anchor?: Anchor): ReturnType<typeof verifyChain> {
  const db = openDb(path, { readOnly: true })
  try {
    return verifyChain(db, anchor)
  } finally {
    db.close()
  }
}

test('clean log verifies with count and head', (t) => {
  const store = withStore(t)
  seed(store, 5)
  const result = store.verifyChain()
  assert.equal(result.ok, true)
  assert.equal(result.ok && result.count, 5)
  assert.equal(result.ok && result.head, store.head())
})

test('edited payload → content mismatch', (t) => {
  const { path } = damagedLog(t, 3)
  const tp = tamper(path)
  tp.setPayload(2, '{"schemaVersion":1,"version":"0.0.1","degraded":["edited"]}')
  tp.close()

  const result = verifyFile(path)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 2)
  assert.match(result.ok ? '' : result.reason, /content: stored hash does not match/)
})

test('deleted middle row → gap at the right seq', (t) => {
  const { path } = damagedLog(t, 3)
  const tp = tamper(path)
  tp.deleteRow(2)
  tp.close()

  const result = verifyFile(path)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 2, 'the gap is reported where the missing row should be')
  assert.match(result.ok ? '' : result.reason, /gap: expected seq 2, found 3/)
})

test('swapped rows → link mismatch', (t) => {
  const { path } = damagedLog(t, 4)
  const tp = tamper(path)
  tp.swapRows(2, 3)
  tp.close()

  const result = verifyFile(path)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 2)
  assert.match(result.ok ? '' : result.reason, /link: prev_hash does not match/)
})

test('forged rehash of one row breaks the next link', (t) => {
  // The thorough forger edits a payload AND recomputes that row's hash, so the
  // row itself is internally consistent. The chain still catches it, one row
  // later, because the next row committed to the old hash.
  const { path } = damagedLog(t, 4)
  const tp = tamper(path)
  tp.forgeRow(2, '{"schemaVersion":1,"version":"0.0.1","degraded":["forged"]}')
  tp.close()

  const result = verifyFile(path)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 3, 'the break surfaces at the row after the forgery')
  assert.match(result.ok ? '' : result.reason, /link: prev_hash does not match/)
})

test('truncation is undetectable without an anchor and detected with one', (t) => {
  // Cut the last two rows and fix the counter that would otherwise betray it.
  // What remains is a genuinely valid chain — there is nothing inside the log
  // left to notice. This is the whole reason the anchor exists.
  const path = storeFile(t)
  const head = join(tmpdir(t), 'events.head')
  const store = withStoreUnverified(t, { path, headFile: head })
  seed(store, 5)
  const anchor = store.writeAnchor()
  assert.ok(anchor)
  assert.equal(anchor.seq, 5)
  store.close()

  const tp = tamper(path)
  tp.deleteRow(5)
  tp.deleteRow(4)
  tp.setSequenceCounter(3) // hide the high-water mark
  tp.restoreTriggers()
  tp.close()

  // Without the anchor: clean. Three rows, valid links, honest counter.
  const blind = verifyFile(path)
  assert.equal(blind.ok, true, 'a truncated log verifies fine on its own — that is the point')
  assert.equal(blind.ok && blind.count, 3)

  // With the anchor: caught, and the message names both positions.
  const seen = verifyFile(path, anchor)
  assert.equal(seen.ok, false)
  assert.match(seen.ok ? '' : seen.reason, /truncation: tail \(seq 3\) is behind the anchored head \(seq 5\)/)
})

test('log ahead of the anchor verifies (rows appended after the last anchor write)', (t) => {
  // The normal state of affairs between anchor writes. Requiring tail equality
  // here would fail every boot after a crash or power loss.
  const path = storeFile(t)
  const head = join(tmpdir(t), 'events.head')
  const store = withStore(t, { path, headFile: head })
  seed(store, 2)
  const anchor = store.writeAnchor()
  assert.ok(anchor)
  seed(store, 3)

  const result = store.verifyChain(anchor)
  assert.equal(result.ok, true, 'being ahead of the anchor is expected, not tampering')
  assert.equal(result.ok && result.count, 5)
})

test('anchor ahead of the log fails with truncation naming both seqs', (t) => {
  const store = withStore(t)
  seed(store, 2)
  const forged: Anchor = {
    schemaVersion: 1,
    genesis: GENESIS,
    seq: 9,
    hash: 'whatever',
    writtenAt: '2026-09-21T00:00:00.000Z',
  }
  const result = store.verifyChain(forged)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 2)
  assert.match(result.ok ? '' : result.reason, /truncation: tail \(seq 2\) is behind the anchored head \(seq 9\)/)
})

test('rewritten row at the anchored seq fails with rewrite', (t) => {
  // The log is long enough and the counter is fine; what changed is the
  // content at the position the anchor pinned.
  const path = storeFile(t)
  const head = join(tmpdir(t), 'events.head')
  const store = withStoreUnverified(t, { path, headFile: head })
  seed(store, 4)
  const anchor = store.writeAnchor()
  assert.ok(anchor)
  store.close()

  const tp = tamper(path)
  tp.rebaseGenesis(GENESIS) // rehash every row consistently…
  tp.forgeRow(4, '{"schemaVersion":1,"version":"0.0.1","degraded":["rewritten"]}')
  tp.close()

  const result = verifyFile(path, anchor)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 4)
  assert.match(result.ok ? '' : result.reason, /rewrite: row at anchored seq 4 has a different hash/)
})

test('logs from a different genesis do not verify', (t) => {
  // A log rebuilt under another genesis is internally consistent but is not
  // this kernel's log. The first link is where that shows.
  const { path } = damagedLog(t, 3)
  const tp = tamper(path)
  tp.rebaseGenesis(sha256Hex('some-other-project:events:v1'))
  tp.close()

  const result = verifyFile(path)
  assert.equal(result.ok, false)
  assert.equal(result.ok ? 0 : result.at, 1)
  assert.match(result.ok ? '' : result.reason, /link: prev_hash does not match/)

  // An anchor from another chain is refused outright rather than compared.
  const foreign: Anchor = {
    schemaVersion: 1,
    genesis: sha256Hex('some-other-project:events:v1'),
    seq: 1,
    hash: 'x',
    writtenAt: '2026-09-21T00:00:00.000Z',
  }
  const store = withStore(t)
  seed(store, 1)
  const result2 = store.verifyChain(foreign)
  assert.equal(result2.ok, false)
  assert.match(result2.ok ? '' : result2.reason, /anchor: belongs to a chain with a different genesis/)
})

test('checks seq continuity before prevHash so the reason is precise', (t) => {
  // A deleted row breaks both continuity and the following link. Reporting
  // the link first would send an operator looking for a forgery that is not
  // there, so the gap check runs first and names the missing position.
  const { path } = damagedLog(t, 4)
  const tp = tamper(path)
  tp.deleteRow(2)
  tp.close()

  const result = verifyFile(path)
  assert.equal(result.ok, false)
  assert.match(result.ok ? '' : result.reason, /^gap:/, 'a gap must be reported as a gap, not as a link break')
  assert.equal(result.ok ? 0 : result.at, 2)
})

test('anchor file round-trips with mode 0600', (t) => {
  const head = join(tmpdir(t), 'events.head')
  const anchor: Anchor = {
    schemaVersion: 1,
    genesis: GENESIS,
    seq: 3,
    hash: 'abc123',
    writtenAt: '2026-09-21T00:00:00.000Z',
  }
  writeAnchor(head, anchor)
  assert.deepEqual(readAnchor(head), anchor)
  assert.equal(statSync(head).mode & 0o777, 0o600, 'anchor must not be group- or world-readable')

  // Overwriting keeps the mode and leaves no temp file behind.
  writeAnchor(head, { ...anchor, seq: 4, hash: 'def456' })
  assert.equal(readAnchor(head)?.seq, 4)
  assert.equal(statSync(head).mode & 0o777, 0o600)

  // Absent file reads as undefined rather than throwing.
  assert.equal(readAnchor(join(tmpdir(t), 'nothing.head')), undefined)
})
