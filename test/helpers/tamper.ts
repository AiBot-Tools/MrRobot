// Tamper helper — simulates an attacker with write access to the database
// file. Everything here is something SQLite genuinely permits once the
// triggers are gone, which is exactly the residual risk the design names:
// SQLite has no privilege model, so DROP TRIGGER, direct UPDATE and DELETE,
// and editing sqlite_sequence are all available to anyone who can open the
// file read-write.
//
// Stores damaged through this helper must never be opened with `withStore`,
// whose teardown verifies the chain: these tests assert that verification
// FAILS, on purpose.

import './guard.js'

import { openDb, type Db } from '../../src/events/db.js'
import { EXPECTED_TRIGGERS } from '../../src/events/schema.js'
import { hashRow, readAllRows, type EventRow } from '../../src/events/chain.js'

export interface Tamper {
  /** Rows as they currently stand. */
  rows(): EventRow[]
  /** Replace a row's payload, leaving its stored hash stale. */
  setPayload(seq: number, payload: string): void
  /** Replace a row's payload AND recompute its hash, so the row self-verifies. */
  forgeRow(seq: number, payload: string): void
  /** Remove a row. */
  deleteRow(seq: number): void
  /** Exchange the contents of two rows, keeping their seq values. */
  swapRows(a: number, b: number): void
  /** Overwrite the first row's prev_hash and rehash the whole chain from it. */
  rebaseGenesis(genesis: string): void
  /** Set sqlite_sequence, which is how a truncation hides its fingerprint. */
  setSequenceCounter(n: number): void
  restoreTriggers(): void
  close(): void
}

/** Open a connection with the append-only triggers removed. */
export function tamper(path: string): Tamper {
  const db: Db = openDb(path)
  for (const t of EXPECTED_TRIGGERS) db.exec(`DROP TRIGGER IF EXISTS ${t.name}`)

  const writeRow = (row: EventRow): void => {
    db.run(
      'UPDATE events SET id = ?, ts = ?, type = ?, run_id = ?, agent_id = ?, payload = ?, prev_hash = ?, hash = ? WHERE seq = ?',
      row.id,
      row.ts,
      row.type,
      row.runId,
      row.agentId,
      row.payload,
      row.prevHash,
      row.hash,
      row.seq,
    )
  }

  return {
    rows: () => readAllRows(db),
    setPayload(seq, payload) {
      db.run('UPDATE events SET payload = ? WHERE seq = ?', payload, seq)
    },
    forgeRow(seq, payload) {
      const row = readAllRows(db).find((r) => r.seq === seq)
      if (row === undefined) throw new Error(`no row at seq ${seq}`)
      const forged = { ...row, payload }
      const { hash: _old, ...unhashed } = forged
      writeRow({ ...forged, hash: hashRow(unhashed) })
    },
    deleteRow(seq) {
      db.run('DELETE FROM events WHERE seq = ?', seq)
    },
    swapRows(a, b) {
      const all = readAllRows(db)
      const rowA = all.find((r) => r.seq === a)
      const rowB = all.find((r) => r.seq === b)
      if (rowA === undefined || rowB === undefined) throw new Error('swapRows: missing row')
      // id and hash are UNIQUE, so park the row we are about to overwrite
      // onto throwaway values before its real values are reused elsewhere.
      writeRow({ ...rowB, id: `${rowB.id}-tmp`, hash: `${rowB.hash}-tmp` })
      writeRow({ ...rowB, seq: a })
      writeRow({ ...rowA, seq: b })
    },
    rebaseGenesis(genesis) {
      let prev = genesis
      for (const row of readAllRows(db)) {
        const { hash: _old, ...unhashed } = { ...row, prevHash: prev }
        const rehashed = { ...unhashed, hash: hashRow(unhashed) }
        writeRow(rehashed)
        prev = rehashed.hash
      }
    },
    setSequenceCounter(n) {
      db.run("UPDATE sqlite_sequence SET seq = ? WHERE name = 'events'", n)
    },
    restoreTriggers() {
      for (const t of EXPECTED_TRIGGERS) {
        db.exec(`DROP TRIGGER IF EXISTS ${t.name}`)
        db.exec(t.sql)
      }
    },
    close() {
      db.close()
    },
  }
}
