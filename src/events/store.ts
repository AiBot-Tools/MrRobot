// The append-only event store.
//
// Contract (CLAUDE.md invariant 5): every event is redacted, canonicalized,
// hashed and chained, and the table refuses UPDATE and DELETE. The append
// path is fixed and its order is load-bearing:
//
//   zod-parse → redact → bound → canonicalize → BEGIN IMMEDIATE →
//   read tail + counter → seq = tail+1 → hash → INSERT → COMMIT →
//   notify listeners
//
// Notes on the parts that are easy to get subtly wrong:
//
// * The store assigns seq itself rather than letting AUTOINCREMENT do it,
//   because seq is inside the hash and must be known before the row is
//   hashed. The read and the write therefore share one IMMEDIATE
//   transaction, so two writers cannot compute the same seq. The schema
//   trigger independently refuses anything that is not tail+1.
// * AUTOINCREMENT is kept anyway: it makes sqlite_sequence monotonic, so
//   deleting the tail and re-inserting it leaves the counter ahead of the
//   tail even though the rows look contiguous. Both append and verifyChain
//   check for that.
// * Hashing happens after redaction, over exactly the bytes stored, so an
//   auditor recomputes from the table alone.
// * Listener errors are swallowed. This is the one documented swallow in the
//   kernel: a subscriber must never be able to fail a commit that already
//   happened, and the event is already durable by the time they run.

import { randomUUID } from 'node:crypto'

import { ChainBroken, ConfigError } from '../errors.js'
import { log } from '../log.js'
import { readAnchor, writeAnchor, type Anchor } from './anchor.js'
import { boundOutput, MAX_LOGGED_OUTPUT } from './bound.js'
import { canonicalize } from './canonical.js'
import { GENESIS, hashRow, sequenceCounter, verifyChain, type EventRow, type VerifyResult } from './chain.js'
import { runScope } from '../runtime/scope.js'
import { openDb, type Db } from './db.js'
import { redactValue } from './redact.js'
import { checkTriggers, createSchema } from './schema.js'
import { isEventType, PAYLOAD_SCHEMAS, type EventType } from './types.js'

export interface AppendInput {
  readonly type: string
  readonly payload: unknown
  readonly runId?: string
  readonly agentId?: string
}

export interface StoreOptions {
  readonly readOnly?: boolean
  /**
   * Write the anchor every N appends. 0 disables periodic anchoring; the
   * anchor is still written on close(). Requires headFile.
   */
  readonly anchorEvery?: number
  /** Path to the anchor file, conventionally <dataDir>/events.head. */
  readonly headFile?: string
}

export type Listener = (row: EventRow) => void

export class EventStore {
  readonly #db: Db
  readonly #readOnly: boolean
  readonly #listeners = new Set<Listener>()
  readonly #headFile: string | undefined
  readonly #anchorEvery: number
  #closed = false

  constructor(path: string, options: StoreOptions = {}) {
    this.#readOnly = options.readOnly ?? false
    this.#headFile = options.headFile
    this.#anchorEvery = options.anchorEvery ?? 0
    if (this.#anchorEvery > 0 && this.#headFile === undefined) {
      throw new ConfigError('anchorEvery requires headFile: there is nowhere to write the anchor')
    }
    this.#db = openDb(path, { readOnly: this.#readOnly })

    // Order matters: an EXISTING log is validated, never repaired. Running
    // createSchema first would recreate a dropped trigger and turn the
    // clearest signal of tampering into a silent self-heal.
    const fresh =
      this.#db.get("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'events'") ===
      undefined
    if (fresh && !this.#readOnly) createSchema(this.#db)

    const triggers = checkTriggers(this.#db)
    if (!triggers.ok) {
      this.#db.close()
      this.#closed = true
      throw new ConfigError(`event log integrity check failed: ${triggers.reason ?? 'unknown'}`)
    }
  }

  /** Append one event. Synchronous and durable on return. */
  append(input: AppendInput): EventRow {
    if (this.#readOnly) {
      throw new ConfigError('event store is read-only: append refused')
    }
    if (!isEventType(input.type)) {
      throw new ConfigError(`unknown event type: ${input.type}`)
    }

    // Writer claim (invariant 2). Inside a run, every event belongs to that
    // run: code executing as run A cannot write history under run B's name,
    // whether by mistake or by a model talking it into passing a different
    // id. Kernel code outside any run scope is unrestricted — that is how
    // boot, shutdown and control-plane events get written.
    const scope = runScope()
    if (scope !== undefined && input.runId !== undefined && input.runId !== scope.runId) {
      throw new ConfigError(
        `writer claim: run ${scope.runId} may not append events for run ${input.runId}`,
      )
    }
    const type: EventType = input.type
    const schema = PAYLOAD_SCHEMAS[type]
    const parsed = schema.safeParse(input.payload)
    if (!parsed.success) {
      throw new ConfigError(`invalid payload for ${type}: ${parsed.error.message}`)
    }

    // Drop keys whose value is undefined before anything is hashed. A caller
    // writing `{ reason: maybeUndefined }` and a caller omitting `reason`
    // describe the same event, so they must produce the same bytes and the
    // same hash. Without this the first form also fails deep in the
    // canonicalizer with a TypeError instead of appending.
    //
    // Redaction runs before anything is measured, canonicalized or hashed.
    const payloadText = canonicalize(redactValue(stripUndefined(parsed.data)))

    // The ceiling from CLAUDE.md is enforced here rather than silently
    // truncating: the store cannot know which field of a payload is safe to
    // cut, so an oversized payload is a caller error. Call boundOutput at the
    // site that produced the text — it knows what the text means.
    const bound = boundOutput(payloadText)
    if (bound.truncated) {
      throw new ConfigError(
        `payload for ${type} is ${bound.bytes} bytes, over the ${MAX_LOGGED_OUTPUT} byte limit; ` +
          'bound the oversized field with boundOutput() before appending',
      )
    }

    const id = randomUUID()
    const ts = new Date().toISOString()
    const runId = input.runId ?? scope?.runId ?? null
    const agentId = input.agentId ?? null

    const row = this.#db.transaction((): EventRow => {
      const tailRow = this.#db.get('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1')
      const tailSeq = typeof tailRow?.['seq'] === 'number' ? (tailRow['seq'] as number) : 0
      const prevHash = typeof tailRow?.['hash'] === 'string' ? (tailRow['hash'] as string) : GENESIS

      // A counter ahead of the tail means rows were deleted after the
      // triggers were removed. Appending would hide it behind a valid-looking
      // chain, so refuse instead.
      const counter = sequenceCounter(this.#db)
      if (counter > tailSeq) {
        throw new ChainBroken(
          tailSeq,
          `truncation: sqlite_sequence (${counter}) is ahead of the tail (${tailSeq})`,
        )
      }

      const seq = tailSeq + 1
      const unhashed = { seq, id, ts, type, runId, agentId, payload: payloadText, prevHash }
      const hash = hashRow(unhashed)

      this.#db.run(
        'INSERT INTO events (seq, id, ts, type, run_id, agent_id, payload, prev_hash, hash) ' +
          'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        seq,
        id,
        ts,
        type,
        runId,
        agentId,
        payloadText,
        prevHash,
        hash,
      )
      return { ...unhashed, hash }
    })

    if (this.#anchorEvery > 0 && row.seq % this.#anchorEvery === 0) {
      this.writeAnchor(row)
    }
    this.#notify(row)
    return row
  }

  /**
   * Record the current head externally. Called periodically and on close, so
   * an unclean exit costs at most the rows since the last write — those rows
   * are ahead of the anchor, which verifyChain treats as normal.
   */
  writeAnchor(at?: EventRow): Anchor | undefined {
    if (this.#headFile === undefined) return undefined
    const seq = at?.seq ?? this.tailSeq()
    const hash = at?.hash ?? this.head()
    const anchor: Anchor = {
      schemaVersion: 1,
      genesis: GENESIS,
      seq,
      hash,
      writtenAt: new Date().toISOString(),
    }
    writeAnchor(this.#headFile, anchor)
    return anchor
  }

  /** The anchor on disk, or undefined when none has been written. */
  readAnchor(): Anchor | undefined {
    return this.#headFile === undefined ? undefined : readAnchor(this.#headFile)
  }

  /** Sequence number of the last row, or 0 when the log is empty. */
  tailSeq(): number {
    const row = this.#db.get('SELECT seq FROM events ORDER BY seq DESC LIMIT 1')
    const seq = row?.['seq']
    return typeof seq === 'number' ? seq : 0
  }

  /** Every listener runs; a throwing listener is logged and skipped. */
  #notify(row: EventRow): void {
    for (const listener of this.#listeners) {
      try {
        listener(row)
      } catch (e) {
        // Documented swallow: the event is already committed and durable, and
        // a subscriber must not be able to unwind it.
        log.error(
          { seq: row.seq, type: row.type, err: e instanceof Error ? e.message : String(e) },
          'event listener threw; event already committed',
        )
      }
    }
  }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** Rows in sequence order, optionally filtered. */
  query(filter: { type?: string; runId?: string; limit?: number } = {}): EventRow[] {
    const where: string[] = []
    const params: unknown[] = []
    if (filter.type !== undefined) {
      where.push('type = ?')
      params.push(filter.type)
    }
    if (filter.runId !== undefined) {
      where.push('run_id = ?')
      params.push(filter.runId)
    }
    const clause = where.length === 0 ? '' : ` WHERE ${where.join(' AND ')}`
    const limit = filter.limit === undefined ? '' : ` LIMIT ${Math.max(0, Math.floor(filter.limit))}`
    return this.#db
      .all(
        'SELECT seq, id, ts, type, run_id, agent_id, payload, prev_hash, hash FROM events' +
          `${clause} ORDER BY seq${limit}`,
        ...params,
      )
      .map(toEventRow)
  }

  /** Hash of the last row, or GENESIS when the log is empty. */
  head(): string {
    const row = this.#db.get('SELECT hash FROM events ORDER BY seq DESC LIMIT 1')
    const hash = row?.['hash']
    return typeof hash === 'string' ? hash : GENESIS
  }

  verifyChain(anchor?: Anchor): VerifyResult {
    return verifyChain(this.#db, anchor)
  }

  /** Escape hatch for tests and boot checks that need the raw connection. */
  get db(): Db {
    return this.#db
  }

  /** True once close() has run. Closing twice is a no-op. */
  get closed(): boolean {
    return this.#closed
  }

  close(): void {
    if (this.#closed) return
    // Anchor the verified tail on the way out, so a clean shutdown always
    // leaves an anchor that matches the log exactly.
    if (!this.#readOnly && this.#headFile !== undefined) {
      try {
        this.writeAnchor()
      } catch (e) {
        log.error({ err: e instanceof Error ? e.message : String(e) }, 'failed to write anchor on close')
      }
    }
    this.#closed = true
    this.#listeners.clear()
    this.#db.close()
  }
}

/** Recursively remove keys whose value is undefined. Arrays keep their shape. */
function stripUndefined(v: unknown): unknown {
  if (Array.isArray(v)) return v.map((item) => stripUndefined(item))
  if (v !== null && typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, item] of Object.entries(v as Record<string, unknown>)) {
      if (item !== undefined) out[k] = stripUndefined(item)
    }
    return out
  }
  return v
}

function toEventRow(r: Record<string, unknown>): EventRow {
  return {
    seq: r['seq'] as number,
    id: r['id'] as string,
    ts: r['ts'] as string,
    type: r['type'] as string,
    runId: (r['run_id'] ?? null) as string | null,
    agentId: (r['agent_id'] ?? null) as string | null,
    payload: r['payload'] as string,
    prevHash: r['prev_hash'] as string,
    hash: r['hash'] as string,
  }
}
