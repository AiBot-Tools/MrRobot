// Store harness.
//
// Every test that writes events opens its store through `withStore`, which
// registers it and, in `t.after`, proves two things about it:
//
//   1. verifyChain().ok — the chain is intact end to end.
//   2. For every row, hashRow(stored row) === row.hash — recomputed from the
//      stored bytes, so a test cannot pass against a store whose hashes were
//      written over anything other than what is in the table.
//
// The second check is not redundant. verifyChain already recomputes content
// hashes, so this is a deliberate belt-and-braces: if verifyChain itself were
// weakened to skip the content step, this would still fail.
//
// A test that intends to break a chain must not use this helper, or must
// exclude its store — see `withStoreUnverified`.

import './guard.js'

import assert from 'node:assert/strict'
import { join } from 'node:path'
import type { TestContext } from 'node:test'

import { hashRow, readAllRows } from '../../src/events/chain.js'
import { EventStore, type StoreOptions } from '../../src/events/store.js'
import { tmpdir } from './tmpdir.js'

export interface WithStoreOptions extends StoreOptions {
  /**
   * Path to open. Omit for :memory:. Tests that reopen the same database
   * create the path once with `storeFile(t)` and pass it to every open, so
   * writer and reader agree on which file they mean.
   */
  readonly path?: string
}

function verifyStore(store: EventStore): void {
  const result = store.verifyChain()
  assert.equal(
    result.ok,
    true,
    result.ok ? '' : `chain verification failed at seq ${result.at}: ${result.reason}`,
  )
  for (const row of readAllRows(store.db)) {
    const { hash, ...unhashed } = row
    assert.equal(
      hashRow(unhashed),
      hash,
      `row ${row.seq} hash does not match a recomputation over the stored bytes`,
    )
  }
}

/**
 * Verify a store's chain and close it. Tests that must close a store before
 * the test ends call this instead of `close()`, because teardown order is not
 * guaranteed — the temp directory may already be gone by then.
 */
export function closeVerified(store: EventStore): void {
  verifyStore(store)
  verifiedByTest.add(store)
  store.close()
}

const verifiedByTest = new WeakSet<EventStore>()

/** Open a verified store. Its chain is checked when the test ends. */
export function withStore(t: TestContext, options: WithStoreOptions = {}): EventStore {
  const store = new EventStore(options.path ?? ':memory:', options)
  t.after(() => {
    if (!store.closed) {
      try {
        verifyStore(store)
      } finally {
        store.close()
      }
      return
    }
    if (!verifiedByTest.has(store)) {
      throw new Error(
        'withStore: the test closed this store without verifying it. Call closeVerified(store) ' +
          'instead of store.close(), or use withStoreUnverified and say why.',
      )
    }
  })
  return store
}

/**
 * Open a store WITHOUT the end-of-test chain verification. Only for tests
 * that deliberately damage a log; every such use states why.
 */
export function withStoreUnverified(t: TestContext, options: WithStoreOptions = {}): EventStore {
  const store = new EventStore(options.path ?? ':memory:', options)
  t.after(() => {
    store.close()
  })
  return store
}

/** A path to a database file in this test's temp directory. Not yet created. */
export function storeFile(t: TestContext, filename = 'events.db'): string {
  return join(tmpdir(t), filename)
}
