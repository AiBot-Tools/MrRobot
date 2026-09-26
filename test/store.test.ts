// T05a — the append-only store.
//
// The tests that matter here are the ones that attack the log: REPLACE
// statements that delete rows without firing a DELETE trigger, a tail deleted
// after the triggers are dropped, and a trigger rewritten to do nothing while
// keeping its name. Each is a real bypass that a naive implementation allows.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { GENESIS, hashRow, readAllRows, sequenceCounter } from '../src/events/chain.js'
import { openDb } from '../src/events/db.js'
import { EventStore } from '../src/events/store.js'
import { CENSOR } from '../src/events/redact.js'
import { closeVerified, storeFile, withStore, withStoreUnverified } from './helpers/store.js'

const BOOT = { schemaVersion: 1 as const, version: '0.0.1', configHash: 'h', degraded: [] }

function boot(store: EventStore, degraded: string[] = []): ReturnType<EventStore['append']> {
  return store.append({ type: 'kernel.booted', payload: { ...BOOT, degraded } })
}

test('append assigns seq = tail+1 and links prev_hash to GENESIS then to the previous hash', (t) => {
  const store = withStore(t)
  const first = boot(store)
  assert.equal(first.seq, 1)
  assert.equal(first.prevHash, GENESIS, 'the first row must link to the domain-separated genesis')

  const second = boot(store, ['docker'])
  assert.equal(second.seq, 2)
  assert.equal(second.prevHash, first.hash)

  const third = boot(store)
  assert.equal(third.seq, 3)
  assert.equal(third.prevHash, second.hash)
  assert.equal(store.head(), third.hash)

  const result = store.verifyChain()
  assert.equal(result.ok, true)
  assert.equal(result.ok && result.count, 3)
  assert.equal(result.ok && result.head, third.hash)
})

test('payload is stored redacted and hashed after redaction', (t) => {
  const store = withStore(t)
  // `degraded` is a free-text list, so a credential can reach it.
  const row = store.append({
    type: 'kernel.booted',
    payload: { ...BOOT, degraded: ['auth failed with sk-ant-api03-FAKEFAKEFAKE'] },
  })

  assert.ok(!row.payload.includes('sk-ant-api03-FAKEFAKEFAKE'), 'credential reached the stored payload')
  assert.ok(row.payload.includes(CENSOR))

  // The hash must be over the stored bytes. If it were taken over the raw
  // payload, this recomputation — and every audit — would fail.
  const { hash, ...unhashed } = row
  assert.equal(hashRow(unhashed), hash)
  const stored = readAllRows(store.db)[0]
  assert.equal(stored?.payload, row.payload)
})

test('UPDATE and DELETE raise errcode 1811 (or code ERR_SQLITE_ERROR)', (t) => {
  const store = withStore(t)
  boot(store)

  for (const sql of [
    "UPDATE events SET payload = '{}' WHERE seq = 1",
    'DELETE FROM events WHERE seq = 1',
  ]) {
    let caught: (NodeJS.ErrnoException & { errcode?: number }) | undefined
    try {
      store.db.exec(sql)
    } catch (e) {
      caught = e as NodeJS.ErrnoException & { errcode?: number }
    }
    assert.ok(caught, `${sql} must be refused`)
    assert.equal(caught.code, 'ERR_SQLITE_ERROR')
    assert.equal(caught.errcode, 1811)
    assert.match(caught.message, /append-only/)
  }
  assert.equal(store.query().length, 1, 'the row must still be there')
})

test('INSERT OR REPLACE and REPLACE INTO are refused with recursive_triggers OFF on a second connection', (t) => {
  // The documented bypass: REPLACE deletes the conflicting row, and the
  // DELETE trigger fires only when recursive_triggers is ON. A connection
  // opened by any other tool has it OFF by default, so the schema's own
  // append-only trigger — not the pragma — has to be what refuses this.
  const path = storeFile(t)
  const store = withStore(t, { path })
  const first = boot(store)
  closeVerified(store)

  const raw = openDb(path, { applyPragmas: false })
  t.after(() => {
    raw.close()
  })
  const pragma = raw.get('PRAGMA recursive_triggers')
  assert.equal(pragma?.['recursive_triggers'], 0, 'this connection must have the pragma OFF')

  for (const sql of [
    // Conflict on UNIQUE id: would silently delete the existing row.
    `INSERT OR REPLACE INTO events (seq, id, ts, type, payload, prev_hash, hash) ` +
      `VALUES (99, '${first.id}', 'x', 'kernel.booted', '{}', '${GENESIS}', 'forged-a')`,
    // Conflict on the primary key: would silently replace row 1.
    `REPLACE INTO events (seq, id, ts, type, payload, prev_hash, hash) ` +
      `VALUES (1, 'other-id', 'x', 'kernel.booted', '{}', '${GENESIS}', 'forged-b')`,
    // Conflict on UNIQUE hash.
    `REPLACE INTO events (seq, id, ts, type, payload, prev_hash, hash) ` +
      `VALUES (2, 'third-id', 'x', 'kernel.booted', '{}', '${GENESIS}', '${first.hash}')`,
  ]) {
    assert.throws(() => raw.exec(sql), /append-only/, `refused: ${sql.slice(0, 40)}`)
  }

  const rows = raw.all('SELECT seq, hash FROM events ORDER BY seq')
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.['hash'], first.hash, 'the original row must be untouched')
})

test('NULL seq and seq gaps are refused', (t) => {
  const path = storeFile(t)
  const store = withStore(t, { path })
  boot(store)
  closeVerified(store)

  const raw = openDb(path)
  t.after(() => {
    raw.close()
  })
  // NULL seq: AUTOINCREMENT would happily assign one, but then the row's seq
  // is not the value that was hashed.
  assert.throws(
    () =>
      raw.exec(
        `INSERT INTO events (seq, id, ts, type, payload, prev_hash, hash) ` +
          `VALUES (NULL, 'n1', 'x', 'kernel.booted', '{}', '${GENESIS}', 'h-null')`,
      ),
    /append-only/,
  )
  // A gap: seq 5 when the tail is 1.
  assert.throws(
    () =>
      raw.exec(
        `INSERT INTO events (seq, id, ts, type, payload, prev_hash, hash) ` +
          `VALUES (5, 'n2', 'x', 'kernel.booted', '{}', '${GENESIS}', 'h-gap')`,
      ),
    /append-only/,
  )
  assert.equal(raw.all('SELECT seq FROM events').length, 1)
})

test('unknown event type or bad payload is rejected before any write; head() unchanged', (t) => {
  const store = withStore(t)
  const before = store.head()
  assert.equal(before, GENESIS)

  assert.throws(
    () => store.append({ type: 'not.a.real.type', payload: {} }),
    /unknown event type/,
  )
  // Unknown key: strict schemas refuse rather than storing something the
  // catalog does not describe.
  assert.throws(
    () => store.append({ type: 'kernel.booted', payload: { ...BOOT, extra: true } }),
    /invalid payload/,
  )
  // Wrong schemaVersion.
  assert.throws(
    () => store.append({ type: 'kernel.booted', payload: { ...BOOT, schemaVersion: 2 } }),
    /invalid payload/,
  )
  // Missing required field.
  assert.throws(() => store.append({ type: 'kernel.booted', payload: {} }), /invalid payload/)

  assert.equal(store.head(), before, 'a rejected append must not touch the log')
  assert.equal(store.query().length, 0)
})

test('sqlite_sequence tracks max(seq) so a tail delete after trigger drop leaves a visible gap: append refuses and verifyChain reports truncation without an anchor', (t) => {
  // The attack: drop the triggers, delete the newest rows, and the remaining
  // prefix is a perfectly valid chain. Nothing inside the chain can see it.
  // AUTOINCREMENT is what betrays it — sqlite_sequence stays at the high-water
  // mark, so the counter ends up ahead of the tail.
  // Deliberately damaged below, so the harness must not verify this file.
  const path = storeFile(t)
  const store = withStoreUnverified(t, { path })
  boot(store)
  boot(store)
  const third = boot(store)
  assert.equal(third.seq, 3)
  store.close()

  const raw = openDb(path)
  raw.exec('DROP TRIGGER events_no_delete')
  raw.exec('DELETE FROM events WHERE seq = 3')
  assert.equal(sequenceCounter(raw), 3, 'the counter keeps the high-water mark')
  assert.equal(raw.all('SELECT seq FROM events').length, 2)
  raw.close()

  // Reopening now fails the trigger check, which is its own defence. Restore
  // the trigger so this test exercises the counter rather than that check.
  const restore = openDb(path)
  restore.exec(
    'CREATE TRIGGER events_no_delete BEFORE DELETE ON events ' +
      "BEGIN SELECT RAISE(ABORT, 'events is append-only: DELETE refused'); END",
  )
  restore.close()

  // Deliberately damaged: this store must NOT be chain-verified at teardown.
  const reopened = withStoreUnverified(t, { path })
  const result = reopened.verifyChain()
  assert.equal(result.ok, false)
  assert.match(result.ok ? '' : result.reason, /truncation: sqlite_sequence \(3\) is ahead of the tail \(2\)/)

  // And append refuses rather than writing a row that would paper over it.
  assert.throws(() => boot(reopened), /truncation: sqlite_sequence/)
})

test('readOnly connection cannot append', (t) => {
  const path = storeFile(t)
  const writer = withStore(t, { path })
  boot(writer)
  closeVerified(writer)

  const reader = new EventStore(path, { readOnly: true })
  t.after(() => {
    reader.close()
  })
  assert.throws(() => boot(reader), /read-only/)
  assert.equal(reader.query().length, 1, 'reading still works')
  assert.equal(reader.verifyChain().ok, true)
})

test('file DB opens WAL, synchronous=FULL, recursive_triggers=ON', (t) => {
  const path = storeFile(t)
  const store = withStore(t, { path })
  boot(store)

  assert.equal(store.db.get('PRAGMA journal_mode')?.['journal_mode'], 'wal')
  assert.equal(store.db.get('PRAGMA synchronous')?.['synchronous'], 2) // 2 = FULL
  assert.equal(store.db.get('PRAGMA recursive_triggers')?.['recursive_triggers'], 1)
  assert.ok(path.endsWith('events.db'))
})

test('reopen refuses when a trigger is dropped', (t) => {
  // Deliberately damaged below, so the harness must not verify this file.
  const path = storeFile(t)
  const store = withStoreUnverified(t, { path })
  boot(store)
  store.close()

  const raw = openDb(path)
  raw.exec('DROP TRIGGER events_no_update')
  raw.close()

  assert.throws(
    () => new EventStore(path),
    /integrity check failed: trigger events_no_update is missing/,
  )
})

test('reopen refuses when a trigger body is rewritten under the same name', (t) => {
  // The cheap disarm: keep the name, empty the body. A presence-only check
  // passes this and the log silently stops being append-only.
  // Deliberately damaged below, so the harness must not verify this file.
  const path = storeFile(t)
  const store = withStoreUnverified(t, { path })
  boot(store)
  store.close()

  const raw = openDb(path)
  raw.exec('DROP TRIGGER events_no_delete')
  raw.exec('CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT 1; END')
  raw.close()

  assert.throws(
    () => new EventStore(path),
    /integrity check failed: trigger events_no_delete has been rewritten/,
  )
})

test('listener errors are swallowed, logged, and append still commits', (t) => {
  const store = withStore(t)
  const seen: number[] = []
  const unsubscribe = store.subscribe(() => {
    throw new Error('subscriber exploded')
  })
  store.subscribe((row) => seen.push(row.seq))

  // The commit already happened before listeners ran; a subscriber must not
  // be able to unwind it.
  const row = boot(store)
  assert.equal(row.seq, 1)
  assert.equal(store.query().length, 1)
  assert.deepEqual(seen, [1], 'a throwing listener must not stop the next one')

  unsubscribe()
  boot(store)
  assert.deepEqual(seen, [1, 2])
  assert.equal(store.verifyChain().ok, true)
})
