// T01 — the environment assumptions every later task depends on.
//
// These are not unit tests of our code; they are tripwires on the toolchain.
// If one fails, the failure message must tell the operator what to change
// rather than leave a later task to fail in a confusing way.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import dgram, { createSocket as esmCreateSocket, Socket as EsmDgramSocket } from 'node:dgram'
import dns, { resolve4 as esmResolve4 } from 'node:dns'
import { lookup as esmLookup, Resolver as EsmResolver } from 'node:dns/promises'
import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'
import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { DatabaseSync } from 'node:sqlite'

import {
  allowHost,
  belowGuard,
  clearAllowedHosts,
  connectTargets,
  isGuarded,
  isLoopbackHost,
  NetworkBlocked,
  sendTarget,
  serverRefused,
  socketLookupRefused,
} from './helpers/guard.js'
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

/** A refusal by the guard, at `layer`, naming `target`. */
const blockedAt =
  (layer: string, target: string) =>
  (e: unknown): boolean =>
    e instanceof NetworkBlocked && e.message.startsWith(`test network guard: refused ${layer} to ${target}. `)

test('guard refuses net.connect, net.createConnection and http.get to a non-loopback host before the real connect is reached', () => {
  // net.connect and net.createConnection, and so an http Agent, tls and
  // undici, hand Socket.connect node's normalized arguments, one array. A
  // stub stands under the guard: a call it lets through reaches the stub,
  // never the network, so a broken guard fails here and sends nothing.
  assert.ok(isGuarded(net.Socket.prototype.connect), 'the guard is installed')
  const reached: unknown[] = []
  const agent = new http.Agent()
  belowGuard(
    {
      'net.Socket.prototype.connect': function (this: unknown, ...args: unknown[]): unknown {
        reached.push(args[0])
        return this
      },
    },
    () => {
      const calls: readonly (readonly [string, () => unknown])[] = [
        ['net.connect({host, port})', () => net.connect({ host: '192.0.2.1', port: 9 })],
        ['net.connect(port, host)', () => net.connect(9, '192.0.2.1')],
        ['net.createConnection(port, host)', () => net.createConnection(9, '192.0.2.1')],
        ["net.createConnection('port', host)", () => Reflect.apply(net.createConnection, net, ['9', '192.0.2.1'])],
        ["socket.connect('port', host)", () => Reflect.apply(net.Socket.prototype.connect, new net.Socket(), ['9', '192.0.2.1'])],
        ['http.get(url)', () => http.get('http://192.0.2.1:9/', { agent })],
        ['http.get({host})', () => http.get({ host: '192.0.2.1', port: 9, agent })],
      ]
      for (const [what, call] of calls) assert.throws(call, blockedAt('socket connect', '192.0.2.1'), what)
      assert.throws(() => http.get({ host: 'b.example', port: 80, agent }), blockedAt('socket connect', 'b.example'), 'by name, before any lookup')
      // Shapes that read as loopback or as a unix socket to a guard that
      // reads them otherwise than node does.
      assert.throws(() => net.connect({ path: '', host: 'b.example', port: 9 }), blockedAt('socket connect', 'b.example'), 'node takes an empty path for none')
      assert.throws(
        () => Reflect.apply(net.Socket.prototype.connect, new net.Socket(), [Object.assign([{ host: 'localhost', port: 9 }], { host: 'b.example', port: 9 })]),
        blockedAt('socket connect', 'b.example'),
        'node reads an array it did not mark as the options itself',
      )
      // A lookup of the caller's own decides where 'localhost' goes.
      const asked: string[] = []
      const lookup = (hostname: string, _options: unknown, callback: (error: null, address: string, family: number) => void): void => {
        asked.push(hostname)
        callback(null, '127.0.0.1', 4)
      }
      const byLookup: readonly (readonly [string, () => unknown])[] = [
        ['net.connect({host, lookup})', () => net.connect({ host: 'localhost', port: 9, lookup })],
        ['net.connect({lookup}) with no host', () => net.connect({ port: 9, lookup })],
        ['tls.connect({host, lookup})', () => tls.connect({ host: 'localhost', port: 9, lookup })],
        ['http.get({host, lookup})', () => http.get({ host: 'localhost', port: 9, lookup, agent })],
      ]
      for (const [what, call] of byLookup) assert.throws(call, blockedAt('socket connect', 'localhost through a lookup of its own'), what)
      assert.deepEqual(asked, [], 'the lookup was never asked')
      assert.deepEqual(reached, [], 'nothing reached the layer under the guard')
      // What may pass still does, through that same layer: loopback by
      // address and by name, a unix domain socket, and a lookup that is
      // node's own or that an IP literal leaves unasked.
      net.connect({ host: '127.0.0.1', port: 9 })
      net.createConnection(9, 'localhost')
      net.connect('/tmp/aos-guard-test.sock')
      net.connect({ host: 'localhost', port: 9, lookup: dns.lookup })
      net.connect({ host: '127.0.0.1', port: 9, lookup })
      assert.equal(reached.length, 5)
    },
  )
  agent.destroy()
})

test('guard refuses a name lookup, a reverse lookup, a resolver query and a datagram that would leave the machine, before the real one runs', async (t) => {
  t.after(() => {
    clearAllowedHosts()
  })
  // Installed on every way in, the ESM bindings included (the in-image mux
  // imports lookup from node:dns/promises): checked first, so a guard that
  // is not there fails here and nothing below makes a real query.
  const owners: readonly (readonly [string, object])[] = [
    ['dns', dns],
    ['dns.promises', dns.promises],
    ['dns.Resolver.prototype', dns.Resolver.prototype],
    ['dns.promises.Resolver.prototype', dns.promises.Resolver.prototype],
  ]
  for (const [name, owner] of owners) {
    const methods = Object.getOwnPropertyNames(owner).filter((key) => /^(?:resolve|reverse)/.test(key) && typeof Reflect.get(owner, key) === 'function')
    assert.ok(methods.includes('resolve4') && methods.includes('reverse'), `${name}: ${methods.join(', ')}`)
    for (const key of methods) assert.ok(isGuarded(Reflect.get(owner, key)), `${name}.${key}`)
  }
  for (const [name, fn] of [
    ['dns.lookup', dns.lookup],
    ['dns.promises.lookup', dns.promises.lookup],
    ["node:dns/promises's named lookup", esmLookup],
    ['dns.lookupService', dns.lookupService],
    ['dns.promises.lookupService', dns.promises.lookupService],
    ["node:dns/promises's named Resolver", EsmResolver.prototype.resolve4],
    ['dgram send', dgram.Socket.prototype.send],
    ['dgram connect', dgram.Socket.prototype.connect],
    ['dgram.createSocket', dgram.createSocket],
    ["node:dgram's named createSocket", esmCreateSocket],
    ['dgram.Socket', dgram.Socket],
    ["node:dgram's named Socket", EsmDgramSocket],
  ] as const) {
    assert.ok(isGuarded(fn), name)
  }

  const calls: string[] = []
  const stub =
    (name: string, promise = false) =>
    (...args: unknown[]): unknown => {
      calls.push(`${name} ${String(args[0])}`)
      return promise ? Promise.resolve([]) : undefined
    }
  const none = (): void => {}
  allowHost('a.example')
  belowGuard(
    {
      'dns.lookup': stub('lookup'),
      'dns.lookupService': stub('lookupService'),
      'dns.Resolver.prototype.resolve4': stub('Resolver.resolve4'),
      'dns.Resolver.prototype.reverse': stub('Resolver.reverse'),
      'dns.resolve4': stub('dns.resolve4'),
      'dgram.Socket.prototype.send': stub('send'),
      'dgram.Socket.prototype.connect': stub('connect'),
    },
    () => {
      assert.throws(() => dns.lookup('b.example', none), blockedAt('dns lookup', 'b.example'))
      assert.throws(() => dns.lookup('192.0.2.1', {}, none), blockedAt('dns lookup', '192.0.2.1'))
      dns.lookup('localhost', none)
      dns.lookup('a.example', { all: true }, none)
      assert.throws(() => dns.lookupService('192.0.2.1', 22, none), blockedAt('reverse lookup', '192.0.2.1'))
      dns.lookupService('127.0.0.1', 22, none)

      // A query goes to the resolver's servers, whatever the name.
      const resolver = new dns.Resolver()
      resolver.setServers(['192.0.2.1'])
      assert.throws(() => resolver.resolve4('localhost', none), blockedAt('dns query', 'localhost via 192.0.2.1'))
      assert.throws(() => resolver.reverse('127.0.0.1', none), blockedAt('dns query', '127.0.0.1 via 192.0.2.1'))
      // The system's own servers, as a new Resolver and the module hold them.
      const system = new dns.Resolver()
      assert.throws(() => system.resolve4('github.com', none), (e: unknown) => e instanceof NetworkBlocked && /dns query to github\.com via /.test(e.message))
      assert.throws(() => dns.resolve4('github.com', none), (e: unknown) => e instanceof NetworkBlocked && /dns query to github\.com via /.test(e.message))
      // A test's own server on loopback, and a gated live test's allowed name, pass.
      resolver.setServers(['127.0.0.1:5353'])
      resolver.resolve4('github.com', none)
      system.resolve4('a.example', none)
      resolver.cancel()
      system.cancel()

      const udp = dgram.createSocket('udp4')
      try {
        assert.throws(() => udp.send('x', 53, '192.0.2.1'), blockedAt('udp send', '192.0.2.1'))
        assert.throws(() => udp.send(Buffer.from('x'), 0, 1, 53, '192.0.2.1', none), blockedAt('udp send', '192.0.2.1'))
        assert.throws(() => udp.connect(53, 'b.example'), blockedAt('udp connect', 'b.example'))
        udp.send('x', 53)
        udp.send('x', 53, '127.0.0.1', none)
        udp.connect(53, '127.0.0.1')
      } finally {
        udp.close()
      }
      // dgram asks a socket's lookup for every address, an IP literal
      // included, so a socket with a lookup of its own is refused when made.
      const lookup = (_hostname: string, _family: unknown, callback: (error: null, address: string, family: number) => void): void => callback(null, '127.0.0.1', 4)
      const refusedSocket = blockedAt('udp socket', '<every address> through a lookup of its own')
      assert.throws(() => dgram.createSocket({ type: 'udp4', lookup }), refusedSocket, 'createSocket')
      assert.throws(() => esmCreateSocket({ type: 'udp4', lookup }), refusedSocket, "node:dgram's named createSocket")
      assert.throws(() => Reflect.construct(dgram.Socket, [{ type: 'udp4', lookup }]), refusedSocket, 'new dgram.Socket')
      assert.throws(() => Reflect.construct(EsmDgramSocket, [{ type: 'udp4', lookup }]), refusedSocket, "new on node:dgram's named Socket")
      const own = dgram.createSocket({ type: 'udp4', lookup: dns.lookup })
      assert.ok(own instanceof dgram.Socket, 'a socket on the default lookup is made, and is a dgram.Socket')
      own.close()
    },
  )
  assert.deepEqual(calls, [
    'lookup localhost',
    'lookup a.example',
    'lookupService 127.0.0.1',
    'Resolver.resolve4 github.com',
    'Resolver.resolve4 a.example',
    'send x',
    'send x',
    'connect 53',
  ])

  // The promise APIs reject the same way.
  calls.length = 0
  const pending = belowGuard(
    {
      'dns.promises.lookup': stub('promises.lookup', true),
      'dns.promises.lookupService': stub('promises.lookupService', true),
      'dns.promises.Resolver.prototype.resolve4': stub('promises.Resolver.resolve4', true),
      'dns.promises.resolve4': stub('promises.resolve4', true),
    },
    () => {
      const queried = new EsmResolver()
      queried.setServers(['192.0.2.1'])
      return [
        dns.promises.lookup('b.example'),
        esmLookup('b.example', { all: true }),
        dns.promises.lookupService('192.0.2.1', 22),
        queried.resolve4('github.com'),
        dns.promises.resolve4('github.com'),
      ]
    },
  )
  for (const refused of pending) await assert.rejects(refused, NetworkBlocked)
  assert.deepEqual(calls, [])
  assert.throws(() => belowGuard({ 'dns.nothing': stub('nothing') }, () => undefined), /the guard wraps no dns\.nothing/)
})

test('the guard reads the host from every shape node hands Socket.connect and dgram send, and lets a query reach only a loopback server of its own', () => {
  // As net.connect, net.createConnection, an http Agent and tls call it: an
  // array is read as node's normalized arguments, [options, callback], and as
  // the options itself, which is how node reads an array it did not mark.
  assert.deepEqual(connectTargets([[{ host: '192.0.2.1', port: 9 }, null]]), ['192.0.2.1', 'localhost'])
  assert.deepEqual(connectTargets([[{ port: 9, host: 'b.example' }, null]]), ['b.example', 'localhost'])
  assert.deepEqual(connectTargets([[{ port: 9 }, null]]), ['localhost', 'localhost'])
  assert.deepEqual(connectTargets([[{ path: '/tmp/x.sock' }, null]]), ['localhost'])
  assert.deepEqual(connectTargets([[9, '192.0.2.1']]), ['<unparseable>', 'localhost'])
  assert.deepEqual(connectTargets([Object.assign([{ host: 'localhost', port: 9 }], { host: 'b.example', port: 9 })]), ['localhost', 'b.example'])
  // As a caller of socket.connect does.
  assert.deepEqual(connectTargets([{ host: '192.0.2.1', port: 9 }]), ['192.0.2.1'])
  assert.deepEqual(connectTargets([{ host: '', port: 9 }]), ['localhost'])
  assert.deepEqual(connectTargets([{ path: '/tmp/x.sock' }]), [])
  assert.deepEqual(connectTargets([{ path: '', host: 'b.example', port: 9 }]), ['b.example'], 'node takes an empty path for no path at all (`!!path`)')
  assert.deepEqual(connectTargets([443, 'b.example']), ['b.example'])
  assert.deepEqual(connectTargets([443]), ['localhost'])
  assert.deepEqual(connectTargets(['443', 'b.example']), ['b.example'], 'node reads a numeric string as a port')
  assert.deepEqual(connectTargets(['/tmp/x.sock', () => undefined]), [])
  // A lookup of the caller's own picks the address for any host but an IP literal.
  const custom = (): void => undefined
  assert.deepEqual(connectTargets([{ host: 'localhost', port: 9, lookup: custom }]), ['localhost through a lookup of its own'])
  assert.deepEqual(connectTargets([{ port: 9, lookup: custom }]), ['localhost through a lookup of its own'])
  assert.deepEqual(connectTargets([{ host: '127.0.0.1', port: 9, lookup: custom }]), ['127.0.0.1'])
  assert.deepEqual(connectTargets([{ host: 'localhost', port: 9, lookup: dns.lookup }]), ['localhost'], "node's own lookup")
  assert.deepEqual(connectTargets([{ host: 'localhost', port: 9, lookup: undefined }]), ['localhost'])
  assert.deepEqual(connectTargets([{ path: '/tmp/x.sock', lookup: custom }]), [])
  assert.equal(socketLookupRefused({ type: 'udp4', lookup: custom }), '<every address> through a lookup of its own')
  assert.equal(socketLookupRefused({ type: 'udp4', lookup: dns.lookup }), undefined)
  assert.equal(socketLookupRefused({ type: 'udp4' }), undefined)
  assert.equal(socketLookupRefused('udp4'), undefined)

  // send(msg, port, address), send(msg, offset, length, port, address), and with no address.
  assert.equal(sendTarget(['x', 53, '192.0.2.1']), '192.0.2.1')
  assert.equal(sendTarget(['x', 53, '192.0.2.1', () => undefined]), '192.0.2.1')
  assert.equal(sendTarget(['x', 0, 1, 53, '192.0.2.1']), '192.0.2.1')
  assert.equal(sendTarget(['x', 0, 1, 53, '192.0.2.1', () => undefined]), '192.0.2.1')
  assert.equal(sendTarget(['x', 53]), undefined)
  assert.equal(sendTarget(['x', 53, () => undefined]), undefined)
  assert.equal(sendTarget(['x', 0, 1, 53]), undefined)

  const system = new Set(['127.0.0.53', '8.8.8.8'])
  assert.equal(serverRefused(['127.0.0.1:5353'], system), undefined)
  assert.equal(serverRefused(['::1'], system), undefined)
  assert.equal(serverRefused(['[::1]:5353'], system), undefined)
  assert.equal(serverRefused(['127.0.0.53'], system), '127.0.0.53', "the system's own loopback resolver forwards off the machine")
  assert.equal(serverRefused(['127.0.0.1:5353', '8.8.8.8'], new Set()), '8.8.8.8')
  assert.equal(serverRefused(['[2001:db8::1]:53'], new Set()), '[2001:db8::1]:53')
  assert.equal(serverRefused([], new Set()), '<no server>')
})

/**
 * Spellings node reads as names, not loopback addresses (net.isIP gives 0),
 * and hands to getaddrinfo, which looks a name up in /etc/hosts and then asks
 * the system's resolver: a guard that trimmed, unbracketed or unzoned them
 * first let a lookup leave the machine.
 */
const NAMES_NOT_LOOPBACK = ['[::1]', ' localhost', 'localhost\n', '127.0.0.1%lo', '[127.0.0.1]', '127.0.0.1 '] as const
/** Spellings node dials on loopback as they are: localhost, and IP literals in 127/8, ::1 and ::ffff:127/104. */
const LOOPBACK_AS_GIVEN = ['localhost', 'LocalHost', '127.0.0.1', '127.255.0.9', '::1', '::1%lo', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1', '::FFFF:7f00:2'] as const

test('the guard reads a host as node does: a padded, bracketed or zoned loopback is a name, refused before node looks it up', async (t) => {
  t.after(() => {
    clearAllowedHosts()
  })
  for (const host of NAMES_NOT_LOOPBACK) {
    assert.equal(net.isIP(host), 0, `node reads ${JSON.stringify(host)} as a name`)
    assert.equal(isLoopbackHost(host), false, JSON.stringify(host))
  }
  for (const host of LOOPBACK_AS_GIVEN) assert.equal(isLoopbackHost(host), true, host)
  for (const host of ['::ffff:128.0.0.1', '::2', '128.0.0.1', '127.1', 'localhost.', '']) assert.equal(isLoopbackHost(host), false, JSON.stringify(host))

  // Through the entry points, with stubs under the guard: what it lets
  // through reaches a stub, never getaddrinfo or a socket.
  const reached: string[] = []
  const none = (): void => {}
  const udp = dgram.createSocket('udp6')
  allowHost('a.example')
  allowHost('k.example')
  try {
    belowGuard(
      {
        'net.Socket.prototype.connect': function (this: unknown, ...args: unknown[]): unknown {
          const first = args[0]
          const options: unknown = Array.isArray(first) ? first[0] : first
          reached.push(`connect ${String(typeof options === 'object' && options !== null ? Reflect.get(options, 'host') : options)}`)
          return this
        },
        'dns.lookup': (...args: unknown[]) => void reached.push(`lookup ${String(args[0])}`),
        'dgram.Socket.prototype.send': (...args: unknown[]) => void reached.push(`send ${String(args[2])}`),
        'dgram.Socket.prototype.connect': (...args: unknown[]) => void reached.push(`udp connect ${String(args[1])}`),
      },
      () => {
        for (const host of NAMES_NOT_LOOPBACK) {
          assert.throws(() => net.connect({ host, port: 9 }), blockedAt('socket connect', host), `net.connect ${JSON.stringify(host)}`)
          assert.throws(() => dns.lookup(host, none), blockedAt('dns lookup', host), `dns.lookup ${JSON.stringify(host)}`)
          assert.throws(() => udp.send('x', 53, host), blockedAt('udp send', host), `udp send ${JSON.stringify(host)}`)
          assert.throws(() => udp.connect(53, host), blockedAt('udp connect', host), `udp connect ${JSON.stringify(host)}`)
        }
        // allowHost admits the name as spelt: a padded one is another name to getaddrinfo.
        for (const host of [' a.example', 'a.example ', 'a.example\n', '\u212A.example']) {
          assert.throws(() => net.connect({ host, port: 443 }), blockedAt('socket connect', host), `net.connect ${JSON.stringify(host)}`)
          assert.throws(() => dns.lookup(host, none), blockedAt('dns lookup', host), `dns.lookup ${JSON.stringify(host)}`)
        }
        assert.deepEqual(reached, [], 'nothing reached the layer under the guard')
        for (const host of [...LOOPBACK_AS_GIVEN, 'A.Example']) {
          net.connect({ host, port: 9 })
          dns.lookup(host, none)
        }
        udp.send('x', 53, '::1')
        udp.connect(53, 'localhost')
      },
    )
  } finally {
    udp.close()
  }
  assert.deepEqual(
    reached,
    [...[...LOOPBACK_AS_GIVEN, 'A.Example'].flatMap((host) => [`connect ${host}`, `lookup ${host}`]), 'send ::1', 'udp connect localhost'],
  )
  // A URL's hostname spells an IPv6 address in brackets: fetch alone reads it unbracketed.
  assert.equal(new URL('http://[::1]:9/').hostname, '[::1]')
  await assert.rejects(fetch('http://[2001:db8::1]:9/'), blockedAt('fetch', '[2001:db8::1]'))
  await assert.rejects(fetch('http://[::1]:9/'), (e: unknown) => !(e instanceof NetworkBlocked), "fetch to [::1] passes the guard and meets the closed port")
})

test('a module-level resolve function taken before dns.setServers, or named by an ESM import, is judged by the servers it still asks', async (t) => {
  // dns.setServers makes a new default resolver and rebinds the module's
  // exports to it; a function taken before, and the ESM binding synced at
  // install, stay bound to the old one, whose servers are the system's.
  const before = dns.getServers()
  t.after(() => dns.setServers(before))
  const taken = dns.resolve4
  const takenPromise = dns.promises.resolve4
  for (const [name, fn] of [
    ['dns.resolve4', taken],
    ['dns.promises.resolve4', takenPromise],
    ["node:dns's named resolve4", esmResolve4],
  ] as const) {
    assert.ok(isGuarded(fn), name)
  }
  const calls: string[] = []
  const none = (): void => {}
  const refused = (e: unknown): boolean => e instanceof NetworkBlocked && /^test network guard: refused dns query to github\.com via /.test(e.message)
  const pending = belowGuard(
    {
      'dns.resolve4': (...args: unknown[]) => void calls.push(`resolve4 ${String(args[0])}`),
      'dns.promises.resolve4': (...args: unknown[]) => {
        calls.push(`promises.resolve4 ${String(args[0])}`)
        return Promise.resolve([])
      },
    },
    () => {
      dns.setServers(['127.0.0.1:5353'])
      assert.deepEqual(dns.getServers(), ['127.0.0.1:5353'], "the module's default resolver asks a loopback server now")
      assert.throws(() => taken('github.com', none), refused, 'taken before setServers')
      assert.throws(() => esmResolve4('github.com', none), refused, 'named by an ESM import')
      return takenPromise('github.com')
    },
  )
  await assert.rejects(pending, refused)
  assert.deepEqual(calls, [], 'nothing reached the function under the guard')
})

test('allowHost admits exactly the named host and nothing else', (t) => {
  t.after(() => {
    clearAllowedHosts()
  })
  allowHost('a.example')
  // Allowed host: the guard steps aside, so connect() returns instead of
  // throwing. The point is that the tripwire did not fire, not that anything
  // is reachable: a stub stands under the guard, so the call it lets through
  // reaches the stub, and nothing is looked up or dialled.
  const allowedSocket = new net.Socket()
  allowedSocket.on('error', () => undefined)
  const reached: unknown[] = []
  const noLookup: net.LookupFunction = (_host, _options, callback) => {
    callback(new Error('no DNS in tests'), '', 4)
  }
  belowGuard(
    {
      'net.Socket.prototype.connect': function (this: unknown, ...args: unknown[]): unknown {
        reached.push(args[0])
        return this
      },
    },
    () => {
      assert.doesNotThrow(() => {
        allowedSocket.connect({ port: 443, host: 'a.example' })
      })
      // An allowed name is no licence for a lookup of the caller's own,
      // which may answer any address for it.
      assert.throws(
        () => allowedSocket.connect({ port: 443, host: 'a.example', lookup: noLookup }),
        (e: unknown) => e instanceof NetworkBlocked && e.message.includes('a.example through a lookup of its own'),
      )
    },
  )
  assert.equal(reached.length, 1)
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
    "console.log(JSON.stringify({ key: process.env.ANTHROPIC_API_KEY ?? null, token: process.env.AOS_CONTROL_TOKEN ?? null, bearer: process.env.AOS_PMMCP_TOKEN ?? null, other: process.env.OPENROUTER_API_KEY ?? null, path: process.env.PATH === undefined ? null : 'kept' }))\n"
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
        // pmmcp's bearer, which kernel.yaml declares: matched by no provider pattern, only by its own name.
        AOS_PMMCP_TOKEN: 'qGuardCanaryBearer',
        OPENROUTER_API_KEY: 'qGuardCanaryOther',
        ...(live ? { AOS_LIVE_TESTS: '1' } : {}),
      },
    })
    assert.equal(result.status, 0, result.stderr)
    return JSON.parse(result.stdout.trim().split('\n').pop() ?? '{}') as Record<string, unknown>
  }
  const scrubbed = { key: null, token: null, bearer: null, other: null, path: 'kept' }
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
    bearer: 'qGuardCanaryBearer',
    other: 'qGuardCanaryOther',
    path: 'kept',
  })
})

/** config-files.test.ts's check that the guard removed every declared credential, run here as its own process. */
const SCRUB_CHECK = 'every credential name the shipped config declares is one test/helpers/guard.ts scrubs'

test("the check that the guard scrubbed every declared credential passes with them exported, and with a guard that deletes nothing fails by name, printing no value", (t) => {
  // That check is what notices the guard's delete loop breaking while its
  // pattern still matches. On that day the operator's shell may well export
  // a real token, and node:test prints what a failed assertion compared: a
  // check that compares the value prints the token it found. So run the real
  // check twice in its own process, with a canary for each declared name
  // exported: once as it runs in npm test, where it must pass, and once with
  // process.env behind a Proxy that ignores delete, which is that broken loop.
  const root = tmpdir(t)
  const preload = join(root, 'deletes-nothing.mjs')
  writeFileSync(preload, 'process.env = new Proxy(process.env, { deleteProperty: () => true })\n')
  const canaries = {
    // Letters only, so no window of one can turn up in a duration or a line number.
    AOS_CONTROL_TOKEN: 'qScrubCanaryControlZYXWVUTSRQPONMLKJ',
    AOS_PMMCP_TOKEN: 'qScrubCanaryBearerZYXWVUTSRQPONMLKJI',
    ANTHROPIC_API_KEY: 'qScrubCanaryProviderZYXWVUTSRQPONMLK',
  }
  const file = fileURLToPath(new URL('./config-files.test.ts', import.meta.url))
  const pattern = `^${SCRUB_CHECK.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`
  const run = (extra: readonly string[]): { status: number | null; printed: string } => {
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', ...extra, '--test-reporter=tap', `--test-name-pattern=${pattern}`, file],
      {
        encoding: 'utf8',
        timeout: 60_000,
        env: {
          PATH: process.env['PATH'] ?? '/usr/bin:/bin',
          // Under a falsify run this process was admitted by its run id; a child it spawns belongs to the same run.
          ...(process.env['AOS_FALSIFY_RUN'] === undefined ? {} : { AOS_FALSIFY_RUN: process.env['AOS_FALSIFY_RUN'] }),
          ...canaries,
        },
      },
    )
    return { status: result.status, printed: `${result.stdout}${result.stderr}` }
  }
  // As npm test runs it: the guard removes all three, and the one check passes.
  const scrubbed = run([])
  assert.equal(scrubbed.status, 0, scrubbed.printed)
  assert.match(scrubbed.printed, /^# tests 1$/m, `the pattern no longer finds the check:\n${scrubbed.printed}`)
  assert.match(scrubbed.printed, /^# pass 1$/m, scrubbed.printed)

  // The broken loop: the check fails, by name, at the first name it finds.
  const leaked = run(['--import', pathToFileURL(preload).href])
  assert.equal(leaked.status, 1, leaked.printed)
  assert.match(leaked.printed, /^# fail 1$/m, leaked.printed)
  assert.match(leaked.printed, /(?:ANTHROPIC_API_KEY|AOS_CONTROL_TOKEN|AOS_PMMCP_TOKEN) is still in an offline test's environment/, leaked.printed)
  for (const value of Object.values(canaries)) {
    for (let i = 0; i + 8 <= value.length; i += 1) {
      assert.equal(leaked.printed.includes(value.slice(i, i + 8)), false, `the check printed part of a credential it found:\n${leaked.printed}`)
    }
  }
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

test("README's one-command capture hands that command pmmcp's bearer from the line the installer writes, nothing for a missing line, and leaves the shell without it", (t) => {
  // Until D37 is answered capture:pmmcp reads no .env, and the README form is
  // how the operator gets the token into its environment without typing it
  // (zsh history) or exporting it (aos-install stops for an exported bearer).
  // Run as a shell runs it, against a scratch .env, with a stand-in for npm
  // that prints what the command was given.
  const readme = readFileSync(join(REPO_DIR, 'README.md'), 'utf8')
  const blocks = [...readme.matchAll(/^```bash\n([\s\S]*?)^```/gm)].map((m) => (m[1] ?? '').trim())
  const command = blocks.find((b) => b.endsWith(' npm run capture:pmmcp'))
  assert.ok(command !== undefined, 'README has no shell block that runs the capture')
  assert.match(command, /^AOS_PMMCP_TOKEN="\$\([^\n]*\)" npm run capture:pmmcp$/, 'the capture is no longer one command with the bearer set inline')
  const probe = `${command.replace(/ npm run capture:pmmcp$/, ' /usr/bin/env')}; printf 'after=%s\\n' "\${AOS_PMMCP_TOKEN-unset}"`
  const shell = (dotenv: string): { given: string | undefined; after: string | undefined } => {
    const dir = tmpdir(t)
    writeFileSync(join(dir, '.env'), dotenv, { mode: 0o600 })
    const run = spawnSync('/bin/sh', ['-c', probe], { cwd: dir, encoding: 'utf8', timeout: 10_000, env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' } })
    assert.equal(run.status, 0, run.stderr)
    const lines = run.stdout.split('\n')
    return {
      given: lines.find((l) => l.startsWith('AOS_PMMCP_TOKEN='))?.slice('AOS_PMMCP_TOKEN='.length),
      after: lines.find((l) => l.startsWith('after='))?.slice('after='.length),
    }
  }
  const value = 'qCaptureLineBearerZYXWVUTSRQPONMLKJ'
  // The line as the installer appends it, among the others: exactly its value, and the shell never holds it.
  assert.deepEqual(
    shell(`AOS_CONTROL_TOKEN=qCaptureOtherControlZYXWVUTSRQPONM\nANTHROPIC_API_KEY=qCaptureOtherKeyZYXWVUTSRQPONMLK\nAOS_PMMCP_TOKEN=${value}\n`),
    { given: value, after: 'unset' },
  )
  // No such line: the command is given a blank value, which the capture refuses as unset.
  assert.deepEqual(shell('AOS_CONTROL_TOKEN=qCaptureOtherControlZYXWVUTSRQPONM\n'), { given: '', after: 'unset' })
})
