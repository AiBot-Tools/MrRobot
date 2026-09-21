// Event log DDL and the trigger integrity check.
//
// The three triggers are the kernel's append-only guarantee. They are
// change-controlled (CLAUDE.md: "Ask before ... the immutability triggers")
// and the exact text below is what boot compares against, so editing a body
// here is what an attacker would have to do, and is what the check catches.
//
// What the triggers cannot do, honestly stated: SQLite has no privilege
// model, so DROP TRIGGER, ALTER TABLE ... RENAME, DROP TABLE, PRAGMA
// writable_schema and editing the file directly all remain possible for
// anyone who can open the database read-write. The defences against that are
// elsewhere: a single writer process, mode 0600, every other consumer opening
// read-only, this integrity check at boot, the monotonic sqlite_sequence
// counter, the hash chain, and the external anchor.

import type { Db } from './db.js'

export const CREATE_EVENTS_TABLE =
  'CREATE TABLE IF NOT EXISTS events (' +
  'seq INTEGER PRIMARY KEY AUTOINCREMENT, ' +
  'id TEXT NOT NULL UNIQUE, ' +
  'ts TEXT NOT NULL, ' +
  'type TEXT NOT NULL, ' +
  'run_id TEXT, ' +
  'agent_id TEXT, ' +
  'payload TEXT NOT NULL, ' +
  'prev_hash TEXT NOT NULL, ' +
  'hash TEXT NOT NULL UNIQUE' +
  ') STRICT'

export const CREATE_EVENTS_INDEXES: readonly string[] = [
  'CREATE INDEX IF NOT EXISTS events_by_type ON events (type)',
  'CREATE INDEX IF NOT EXISTS events_by_run ON events (run_id)',
  'CREATE INDEX IF NOT EXISTS events_by_ts ON events (ts)',
]

export interface TriggerSpec {
  readonly name: string
  /** Exactly the text SQLite will store in sqlite_master.sql. */
  readonly sql: string
}

export const EXPECTED_TRIGGERS: readonly TriggerSpec[] = [
  {
    name: 'events_append_only',
    sql:
      'CREATE TRIGGER events_append_only BEFORE INSERT ON events ' +
      'WHEN NEW.seq IS NULL OR NEW.seq != (SELECT coalesce(max(seq), 0) + 1 FROM events) ' +
      'OR EXISTS (SELECT 1 FROM events WHERE id = NEW.id OR hash = NEW.hash) ' +
      "BEGIN SELECT RAISE(ABORT, 'events is append-only: seq must be tail+1 and id/hash unique'); END",
  },
  {
    name: 'events_no_delete',
    sql:
      'CREATE TRIGGER events_no_delete BEFORE DELETE ON events ' +
      "BEGIN SELECT RAISE(ABORT, 'events is append-only: DELETE refused'); END",
  },
  {
    name: 'events_no_update',
    sql:
      'CREATE TRIGGER events_no_update BEFORE UPDATE ON events ' +
      "BEGIN SELECT RAISE(ABORT, 'events is append-only: UPDATE refused'); END",
  },
]

/** Create the table, indexes and triggers if they are not already present. */
export function createSchema(db: Db): void {
  db.exec(CREATE_EVENTS_TABLE)
  for (const sql of CREATE_EVENTS_INDEXES) db.exec(sql)
  for (const t of EXPECTED_TRIGGERS) {
    const existing = db.get(
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
      t.name,
    )
    if (existing === undefined) db.exec(t.sql)
  }
}

/**
 * Whitespace-insensitive comparison. SQLite stores the CREATE statement
 * verbatim apart from the trailing semicolon, so this normalizes only
 * formatting: a rewritten body still differs and is still caught.
 */
function normalize(sql: string): string {
  return sql.replace(/\s+/g, ' ').trim()
}

export interface TriggerCheck {
  readonly ok: boolean
  /** Human-readable reason when not ok. */
  readonly reason?: string
}

/**
 * Compare every expected trigger against sqlite_master by NAME AND BODY.
 *
 * Checking names alone would pass a trigger rewritten to `BEGIN SELECT 1;
 * END`, which is the cheapest way to disarm the log while leaving it looking
 * intact, so the body is what is actually compared.
 */
export function checkTriggers(db: Db): TriggerCheck {
  const rows = db.all(
    "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'events' ORDER BY name",
  )
  const found = new Map<string, string>()
  for (const row of rows) {
    const name = row['name']
    const sql = row['sql']
    if (typeof name === 'string' && typeof sql === 'string') found.set(name, sql)
  }

  for (const expected of EXPECTED_TRIGGERS) {
    const actual = found.get(expected.name)
    if (actual === undefined) {
      return { ok: false, reason: `trigger ${expected.name} is missing` }
    }
    if (normalize(actual) !== normalize(expected.sql)) {
      return { ok: false, reason: `trigger ${expected.name} has been rewritten` }
    }
  }

  const extra = [...found.keys()].filter((n) => !EXPECTED_TRIGGERS.some((t) => t.name === n))
  if (extra.length > 0) {
    // An unexpected trigger on this table can rewrite what is being inserted.
    return { ok: false, reason: `unexpected trigger(s) on events: ${extra.join(', ')}` }
  }
  return { ok: true }
}
