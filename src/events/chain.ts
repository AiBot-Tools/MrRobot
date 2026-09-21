// Hash chain over the event log.
//
// Each row commits to its own content and to the previous row's hash, so any
// edit, reorder or interior deletion changes a hash and breaks the link that
// follows it. Tail truncation is the one attack a self-contained chain cannot
// see — the remaining prefix is perfectly valid — which is what the external
// anchor and the monotonic sqlite_sequence counter are for.
//
// Change-controlled with the canonicalizer: altering GENESIS or the hashed
// field set invalidates every hash ever written.

import type { Anchor } from './anchor.js'
import { canonicalize, sha256Hex } from './canonical.js'
import type { Db } from './db.js'

/**
 * Domain-separated genesis (plan D11). A run of zeros would be indistinguishable
 * from another project's chain; this ties the first link to this kernel.
 */
export const GENESIS: string = sha256Hex('aos-kernel:events:v1')

/** A stored row, exactly as it appears in the table. */
export interface EventRow {
  readonly seq: number
  readonly id: string
  readonly ts: string
  readonly type: string
  readonly runId: string | null
  readonly agentId: string | null
  /** Canonical JSON of the REDACTED payload — the bytes that were hashed. */
  readonly payload: string
  readonly prevHash: string
  readonly hash: string
}

/** The hashed field set. `payload` is the stored (redacted) text, so a
 * verifier recomputes from what the table holds and nothing else. */
export function hashRow(row: Omit<EventRow, 'hash'>): string {
  return sha256Hex(
    canonicalize({
      agentId: row.agentId,
      id: row.id,
      payload: row.payload,
      prevHash: row.prevHash,
      runId: row.runId,
      seq: row.seq,
      ts: row.ts,
      type: row.type,
    }),
  )
}

export type VerifyResult =
  | { readonly ok: true; readonly count: number; readonly head: string }
  | { readonly ok: false; readonly at: number; readonly reason: string }

/** Read every row in sequence order, mapped to the EventRow shape. */
export function readAllRows(db: Db): EventRow[] {
  return db
    .all(
      'SELECT seq, id, ts, type, run_id, agent_id, payload, prev_hash, hash FROM events ORDER BY seq',
    )
    .map((r) => ({
      seq: r['seq'] as number,
      id: r['id'] as string,
      ts: r['ts'] as string,
      type: r['type'] as string,
      runId: (r['run_id'] ?? null) as string | null,
      agentId: (r['agent_id'] ?? null) as string | null,
      payload: r['payload'] as string,
      prevHash: r['prev_hash'] as string,
      hash: r['hash'] as string,
    }))
}

/** Value of sqlite_sequence for the events table, or 0 before the first insert. */
export function sequenceCounter(db: Db): number {
  const row = db.get("SELECT seq FROM sqlite_sequence WHERE name = 'events'")
  const v = row?.['seq']
  return typeof v === 'number' ? v : 0
}

/**
 * Verify the chain end to end.
 *
 * Checks run in this order so the reported reason is the most precise one
 * available: a gap is reported as a gap rather than as the link mismatch it
 * also causes.
 *   1. seq continuity (1, 2, 3, … with no holes)
 *   2. prevHash links
 *   3. content hashes recomputed from the stored bytes
 *   4. sqlite_sequence ahead of the tail, which is the fingerprint of a
 *      deleted-and-refilled tail
 *   5. the anchor, if one is supplied
 *
 * Anchor semantics: the log is expected to be AHEAD of its anchor, because
 * rows are appended between anchor writes. Only a log behind its anchor, or a
 * different hash at the anchored position, is evidence of tampering. Requiring
 * tail equality instead would fail every boot after a crash or power loss.
 */
export function verifyChain(db: Db, anchor?: Anchor): VerifyResult {
  const rows = readAllRows(db)
  let prev = GENESIS

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i]
    if (row === undefined) continue
    const expectedSeq = i + 1
    if (row.seq !== expectedSeq) {
      return { ok: false, at: expectedSeq, reason: `gap: expected seq ${expectedSeq}, found ${row.seq}` }
    }
    if (row.prevHash !== prev) {
      return { ok: false, at: row.seq, reason: 'link: prev_hash does not match the previous row' }
    }
    const recomputed = hashRow(row)
    if (recomputed !== row.hash) {
      return { ok: false, at: row.seq, reason: 'content: stored hash does not match the stored row' }
    }
    prev = row.hash
  }

  const counter = sequenceCounter(db)
  const tail = rows.length === 0 ? 0 : (rows[rows.length - 1]?.seq ?? 0)
  if (counter > tail) {
    return {
      ok: false,
      at: tail,
      reason: `truncation: sqlite_sequence (${counter}) is ahead of the tail (${tail})`,
    }
  }

  if (anchor !== undefined) {
    if (anchor.genesis !== GENESIS) {
      return { ok: false, at: 0, reason: 'anchor: belongs to a chain with a different genesis' }
    }
    if (tail < anchor.seq) {
      return {
        ok: false,
        at: tail,
        reason: `truncation: tail (seq ${tail}) is behind the anchored head (seq ${anchor.seq})`,
      }
    }
    if (anchor.seq > 0) {
      const anchored = rows[anchor.seq - 1]
      if (anchored === undefined || anchored.hash !== anchor.hash) {
        return {
          ok: false,
          at: anchor.seq,
          reason: `rewrite: row at anchored seq ${anchor.seq} has a different hash`,
        }
      }
    }
  }

  return { ok: true, count: rows.length, head: prev }
}
