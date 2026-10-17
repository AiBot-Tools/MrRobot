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
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'

import { allowHost, clearAllowedHosts, NetworkBlocked } from './helpers/guard.js'
import { VERSION } from '../src/version.js'
import { tmpdir } from './helpers/tmpdir.js'

const REPO_DIR = fileURLToPath(new URL('..', import.meta.url))

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
  // throwing. The point is that the tripwire did not fire, not that anything
  // is reachable: the lookup answers with an error itself, so not even a DNS
  // query leaves the machine (destroy() does not cancel a lookup in flight).
  const allowedSocket = new net.Socket()
  allowedSocket.on('error', () => undefined)
  const noLookup: net.LookupFunction = (_host, _options, callback) => {
    callback(new Error('no DNS in tests'), '', 4)
  }
  assert.doesNotThrow(() => {
    allowedSocket.connect({ port: 443, host: 'a.example', lookup: noLookup })
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

test('the test guard removes credential names from every test process except a live file on the live run', (t) => {
  // A key the operator exported in the shell that runs npm test must never be
  // visible to an offline test — on the live run too, where every offline file
  // runs beside the two live ones. Spawned, because the guard runs at import,
  // and run as a FILE, because argv[1] is how the guard knows which test it is.
  const root = tmpdir(t)
  // ESM, as in this repo, so the probe can await the guard at top level.
  writeFileSync(join(root, 'package.json'), '{"type":"module"}\n')
  const dir = join(root, 'test')
  mkdirSync(dir)
  const guard = fileURLToPath(new URL('./helpers/guard.ts', import.meta.url))
  const body =
    `await import(${JSON.stringify(guard)})\n` +
    "console.log(JSON.stringify({ key: process.env.ANTHROPIC_API_KEY ?? null, token: process.env.AOS_CONTROL_TOKEN ?? null, other: process.env.OPENROUTER_API_KEY ?? null, path: process.env.PATH === undefined ? null : 'kept' }))\n"
  const probe = (file: string, live: boolean, extra: readonly string[] = []): Record<string, unknown> => {
    const path = join(dir, file)
    writeFileSync(path, body)
    const result = spawnSync(process.execPath, ['--import', 'tsx', path, ...extra], {
      encoding: 'utf8',
      timeout: 30_000,
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        // The probe loads the real guard. Under a falsify run this process was
        // admitted by its run id; a child it spawns belongs to the same run.
        ...(process.env['AOS_FALSIFY_RUN'] === undefined ? {} : { AOS_FALSIFY_RUN: process.env['AOS_FALSIFY_RUN'] }),
        ANTHROPIC_API_KEY: 'qGuardCanaryKey',
        AOS_CONTROL_TOKEN: 'qGuardCanaryToken',
        OPENROUTER_API_KEY: 'qGuardCanaryOther',
        ...(live ? { AOS_LIVE_TESTS: '1' } : {}),
      },
    })
    assert.equal(result.status, 0, result.stderr)
    return JSON.parse(result.stdout.trim().split('\n').pop() ?? '{}') as Record<string, unknown>
  }
  const scrubbed = { key: null, token: null, other: null, path: 'kept' }
  assert.deepEqual(probe('cli.test.ts', false), scrubbed)
  assert.deepEqual(probe('live-probe.test.ts', false), scrubbed)
  assert.deepEqual(probe('cli.test.ts', true), scrubbed, 'an offline file kept credentials on the live run')
  // One process given several files (--test-isolation=none) is scrubbed even
  // when a live file comes first: the offline files after it share the process.
  assert.deepEqual(probe('live-probe.test.ts', true, [join(dir, 'cli.test.ts')]), scrubbed, 'a shared process kept credentials')
  assert.deepEqual(probe('not-live-probe.test.ts', true), scrubbed)
  assert.deepEqual(probe('live-probe.test.ts', true), {
    key: 'qGuardCanaryKey',
    token: 'qGuardCanaryToken',
    other: 'qGuardCanaryOther',
    path: 'kept',
  })
})

test('the test guard admits a mutated tree only for the falsify run that mutated it', (t) => {
  // The guard finds the repository from its own location, so a copy of it in a
  // temp tree with a journal stands in for the checkout.
  const root = tmpdir(t)
  writeFileSync(join(root, 'package.json'), '{"type":"module"}\n')
  mkdirSync(join(root, 'test', 'helpers'), { recursive: true })
  const guard = join(root, 'test', 'helpers', 'guard.ts')
  writeFileSync(guard, readFileSync(fileURLToPath(new URL('./helpers/guard.ts', import.meta.url))))
  // The guard reads the lock through the same module the daemon uses.
  mkdirSync(join(root, 'src'))
  writeFileSync(join(root, 'src', 'falsify-hold.ts'), readFileSync(fileURLToPath(new URL('../src/falsify-hold.ts', import.meta.url))))
  mkdirSync(join(root, '.falsify'))
  const journal = (text: string): void => writeFileSync(join(root, '.falsify', 'journal.json'), text)
  const load = (run?: string): ReturnType<typeof spawnSync> =>
    spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `await import(${JSON.stringify(guard)})`], {
      cwd: REPO_DIR,
      encoding: 'utf8',
      timeout: 30_000,
      env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ...(run === undefined ? {} : { AOS_FALSIFY_RUN: run }) },
    })

  journal(JSON.stringify({ file: 'src/policy/gate.ts', original: '', runId: 'run-a' }))
  // The run's own test processes: admitted.
  assert.equal(load('run-a').status, 0, 'the owning run was refused')
  // Anyone else — an operator's npm test beside it, a dead run's leftovers, a
  // different run — is refused, whatever pid the journal might once have named.
  for (const run of [undefined, 'run-b', '']) {
    const r = load(run)
    assert.notEqual(r.status, 0, `admitted with AOS_FALSIFY_RUN=${String(run)}`)
    assert.match(String(r.stderr), /src\/policy\/gate\.ts may be mutated/)
  }
  // A journal from before run ids, and an unreadable one, are refused too —
  // the second without pretending to name a file.
  journal(JSON.stringify({ file: 'src/policy/gate.ts', original: '', pid: 1 }))
  assert.notEqual(load('').status, 0)
  journal('')
  const unreadable = load()
  assert.notEqual(unreadable.status, 0)
  assert.match(String(unreadable.stderr), /unreadable.*git status/)

  // Between mutants a live run holds only its lock, and the next mutant is
  // seconds away: anyone but the run's own processes is refused then too.
  rmSync(join(root, '.falsify', 'journal.json'))
  const lock = (pid: number): void => writeFileSync(join(root, '.falsify', 'lock.json'), JSON.stringify({ pid, started: 'x', runId: 'run-a' }))
  lock(process.pid)
  assert.equal(load('run-a').status, 0, 'the run holding the lock was refused its own tests')
  for (const run of [undefined, 'run-b']) {
    const r = load(run)
    assert.notEqual(r.status, 0, `admitted beside a live run with AOS_FALSIFY_RUN=${String(run)}`)
    assert.match(String(r.stderr), new RegExp(`a falsify run \\(pid ${String(process.pid)}\\) holds this tree`))
  }
  // A lock whose pid is gone is a dead run's; with no journal the tree is clean.
  const gone = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' })
  lock(Number(gone.stdout))
  assert.equal(load().status, 0, 'a dead run\'s lock refused a clean tree')
})
