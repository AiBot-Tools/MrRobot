// The kernel's only SQLite seam.
//
// Every database call in the kernel goes through this file so that swapping
// node:sqlite for another driver is a one-file change (plan D3: node:sqlite
// behind an adapter). Nothing else in src/ imports node:sqlite.
//
// Per-open pragmas are part of the contract, not a convenience:
//   journal_mode=WAL      readers never block the single writer (file DBs only)
//   synchronous=FULL      a committed event survives power loss
//   recursive_triggers=ON REPLACE fires the DELETE trigger; without it,
//                         INSERT OR REPLACE silently deletes rows
//
// The third one is defence in depth only. The schema's own append-only
// trigger refuses those statements even on a connection that never set the
// pragma, which is what `applyPragmas: false` exists to prove in tests.

import { DatabaseSync } from 'node:sqlite'

export interface OpenOptions {
  readonly readOnly?: boolean
  /**
   * Apply the kernel's pragmas. Default true. False simulates a connection
   * opened by some other tool with SQLite's defaults, which is how the tests
   * show the triggers — not the pragmas — are what hold the line.
   */
  readonly applyPragmas?: boolean
  /** Busy timeout in milliseconds. */
  readonly timeoutMs?: number
}

export interface Row {
  readonly [column: string]: unknown
}

/** Minimal statement surface; widen only when a caller truly needs more. */
export interface Db {
  exec(sql: string): void
  get(sql: string, ...params: unknown[]): Row | undefined
  all(sql: string, ...params: unknown[]): Row[]
  run(sql: string, ...params: unknown[]): void
  /** BEGIN IMMEDIATE … COMMIT, rolling back on any throw. */
  transaction<T>(fn: () => T): T
  close(): void
  readonly readOnly: boolean
}

/** True when this build of node:sqlite accepts a `timeout` constructor option. */
export function supportsTimeoutOption(): boolean {
  try {
    new DatabaseSync(':memory:', { timeout: 1 }).close()
    return true
  } catch {
    return false
  }
}

export function openDb(path: string, options: OpenOptions = {}): Db {
  const readOnly = options.readOnly ?? false
  const applyPragmas = options.applyPragmas ?? true
  const timeoutMs = options.timeoutMs ?? 5_000
  const isMemory = path === ':memory:'

  let handle: DatabaseSync
  if (supportsTimeoutOption()) {
    handle = new DatabaseSync(path, { readOnly, timeout: timeoutMs })
  } else {
    handle = new DatabaseSync(path, { readOnly })
    if (!readOnly) handle.exec(`PRAGMA busy_timeout = ${timeoutMs}`)
  }

  if (applyPragmas) {
    // WAL is a persistent property of a file database and cannot be set on a
    // read-only connection or an in-memory one.
    if (!readOnly && !isMemory) handle.exec('PRAGMA journal_mode = WAL')
    if (!readOnly) handle.exec('PRAGMA synchronous = FULL')
    handle.exec('PRAGMA recursive_triggers = ON')
  }

  return {
    readOnly,
    exec(sql: string): void {
      handle.exec(sql)
    },
    get(sql: string, ...params: unknown[]): Row | undefined {
      const stmt = handle.prepare(sql)
      const row: unknown = stmt.get(...(params as never[]))
      return row === undefined ? undefined : (row as Row)
    },
    all(sql: string, ...params: unknown[]): Row[] {
      const stmt = handle.prepare(sql)
      return stmt.all(...(params as never[])) as unknown as Row[]
    },
    run(sql: string, ...params: unknown[]): void {
      const stmt = handle.prepare(sql)
      stmt.run(...(params as never[]))
    },
    transaction<T>(fn: () => T): T {
      // IMMEDIATE, not DEFERRED: the store reads the tail and then writes
      // against it, so the write lock must be held from the first read or two
      // writers could compute the same seq.
      handle.exec('BEGIN IMMEDIATE')
      try {
        const result = fn()
        handle.exec('COMMIT')
        return result
      } catch (e) {
        try {
          handle.exec('ROLLBACK')
        } catch {
          // A failed rollback must not mask the original error.
        }
        throw e
      }
    },
    close(): void {
      handle.close()
    },
  }
}
