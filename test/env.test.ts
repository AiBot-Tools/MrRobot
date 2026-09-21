// T01 — the environment assumptions every later task depends on.
//
// These are not unit tests of our code; they are tripwires on the toolchain.
// If one fails, the failure message must tell the operator what to change
// rather than leave a later task to fail in a confusing way.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'

import { allowHost, clearAllowedHosts, NetworkBlocked } from './helpers/guard.js'
import { VERSION } from '../src/version.js'

test('tsx resolves a .js specifier to a .ts source', () => {
  // The import above is written `../src/version.js`; the file on disk is
  // `src/version.ts`. If this fails, the loader is not tsx (CLAUDE.md's
  // `.js` suffix convention, plan D2) and nothing else in the suite loads.
  assert.equal(VERSION, '0.0.1')
})

test('node major satisfies engines', () => {
  const pkg: unknown = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  assert.ok(typeof pkg === 'object' && pkg !== null, 'package.json did not parse to an object')
  const engines = (pkg as { engines?: { node?: unknown } }).engines
  const range = engines?.node
  assert.equal(typeof range, 'string', 'package.json engines.node must be a string')
  assert.ok(
    satisfies(process.versions.node, range as string),
    `this Node is ${process.version}, which does not satisfy engines.node "${range as string}". ` +
      'Install a supported Node (the plan recommends the current 24 or 26 line) and re-run.',
  )
})

test('node:sqlite present and RAISE(ABORT) throws errcode 1811 with code ERR_SQLITE_ERROR', () => {
  // Invariant 5's immutability triggers are enforced by SQLite, not by our
  // code. If RAISE(ABORT) ever stopped throwing, the event log would become
  // silently mutable, so the contract is asserted here before anything is built
  // on it: the thrown error must carry both the Node code and SQLite's
  // SQLITE_CONSTRAINT_TRIGGER (1811), and must preserve the message verbatim.
  const db = new DatabaseSync(':memory:')
  try {
    db.exec('CREATE TABLE events (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL)')
    db.exec(
      "CREATE TRIGGER events_no_update BEFORE UPDATE ON events " +
        "BEGIN SELECT RAISE(ABORT, 'events are append-only'); END",
    )
    db.exec("INSERT INTO events (seq, hash) VALUES (1, 'h1')")
    let caught: (NodeJS.ErrnoException & { errcode?: number }) | undefined
    try {
      db.exec("UPDATE events SET hash = 'tampered' WHERE seq = 1")
    } catch (e) {
      caught = e as NodeJS.ErrnoException & { errcode?: number }
    }
    assert.ok(caught, 'UPDATE must be refused by the append-only trigger')
    assert.equal(caught.code, 'ERR_SQLITE_ERROR')
    assert.equal(caught.errcode, 1811)
    assert.match(caught.message, /events are append-only/)
    const rows = db.prepare('SELECT hash FROM events WHERE seq = 1').all()
    assert.deepEqual(rows.map((r) => (r as { hash: string }).hash), ['h1'])
  } finally {
    db.close()
  }
})

test('DatabaseSync accepts the timeout option or the adapter fallback path is reachable', () => {
  // The store wants a busy timeout. Either the constructor takes one, or the
  // adapter must set it with a pragma; this records which world we are in so
  // T04 does not guess.
  let acceptsOption: boolean
  let db: DatabaseSync
  try {
    db = new DatabaseSync(':memory:', { timeout: 5_000 })
    acceptsOption = true
  } catch {
    db = new DatabaseSync(':memory:')
    acceptsOption = false
  }
  try {
    if (!acceptsOption) {
      // Fallback must exist, or the store has no way to set a busy timeout.
      db.exec('PRAGMA busy_timeout = 5000')
      const got = db.prepare('PRAGMA busy_timeout').get() as { timeout?: number } | undefined
      assert.equal(got?.timeout, 5_000)
    }
    assert.equal(typeof acceptsOption, 'boolean')
  } finally {
    db.close()
  }
})

test('t.mock.timers enable/tick/Date advance', (t) => {
  // The suite must never sleep on a real clock: heartbeats, wallclocks and
  // expiries are all tested through mocked timers.
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 })
  let fired = false
  setTimeout(() => {
    fired = true
  }, 1_000)
  assert.equal(fired, false)
  assert.equal(Date.now(), 0)
  t.mock.timers.tick(1_000)
  assert.equal(fired, true)
  assert.equal(Date.now(), 1_000)
})

test('--disable-warning=ExperimentalWarning is accepted', () => {
  // .npmrc passes this flag through node-options for every npm script. On a
  // Node too old to know the flag, every `npm run` dies before any test loads,
  // so the failure is made explicit here instead.
  const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '-e', '0'], {
    encoding: 'utf8',
  })
  assert.equal(
    r.status,
    0,
    `node rejected --disable-warning=ExperimentalWarning (${r.stderr.trim()}). ` +
      'The flag exists from v20.11.0; .npmrc sets it for every npm script.',
  )
})

test('guard throws on fetch to a non-loopback host before any socket opens', async (t) => {
  const server = net.createServer()
  const connections: number[] = []
  server.on('connection', () => connections.push(1))
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => {
    server.close()
  })

  await assert.rejects(
    () => fetch('https://example.invalid/'),
    (e: unknown) => e instanceof NetworkBlocked && e.code === 'AOS_TEST_NETWORK_BLOCKED',
  )
  // The tripwire must fire before anything is dialled, not after a failed DNS
  // lookup: no connection reached even a listener we control.
  assert.deepEqual(connections, [])
})

test('guard throws on net.Socket.connect to a non-loopback address', () => {
  const socket = new net.Socket()
  assert.throws(
    () => socket.connect(443, 'example.invalid'),
    (e: unknown) => e instanceof NetworkBlocked,
  )
  assert.throws(
    () => socket.connect({ host: '93.184.216.34', port: 80 }),
    (e: unknown) => e instanceof NetworkBlocked,
  )
  socket.destroy()
})

test('allowHost admits exactly the named host and nothing else', (t) => {
  t.after(() => {
    clearAllowedHosts()
  })
  allowHost('a.example')
  // Allowed host: the guard steps aside, so connect() returns instead of
  // throwing. The socket is destroyed at once — the point is that the tripwire
  // did not fire, not that anything is reachable, and the suite still opens no
  // connection of its own.
  const allowedSocket = new net.Socket()
  assert.doesNotThrow(() => {
    allowedSocket.connect(443, 'a.example')
  })
  allowedSocket.destroy()
  // Everything else is still refused, including a neighbouring name.
  const blockedSocket = new net.Socket()
  assert.throws(
    () => blockedSocket.connect(443, 'b.example'),
    (e: unknown) => e instanceof NetworkBlocked,
  )
  blockedSocket.destroy()
})

/**
 * Minimal semver range check for exactly the two comparator forms this project
 * uses (`^x.y.z` and `>=x.y.z`, joined by `||`). Anything else throws rather
 * than quietly returning a wrong answer — a permissive parser here would let an
 * unsupported Node through, which is the failure this test exists to prevent.
 */
function satisfies(version: string, range: string): boolean {
  const v = parse(version)
  return range.split('||').some((clause) => {
    const c = clause.trim()
    if (c.startsWith('^')) {
      const min = parse(c.slice(1))
      return v.major === min.major && cmp(v, min) >= 0
    }
    if (c.startsWith('>=')) return cmp(v, parse(c.slice(2))) >= 0
    throw new Error(`unsupported range syntax in engines.node: "${c}"`)
  })
}

interface Semver {
  readonly major: number
  readonly minor: number
  readonly patch: number
}

function parse(s: string): Semver {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(s.trim())
  if (m === null) throw new Error(`cannot parse version "${s}"`)
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) }
}

function cmp(a: Semver, b: Semver): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch
}
