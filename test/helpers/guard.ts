// Network tripwire for the whole test suite.
//
// Contract: importing this module makes any attempt to reach a non-loopback
// host throw *before* a socket is opened. The suite's offline guarantee rests
// on it, so T01 proves the tripwire rather than assuming it. Every test file's
// first import is this module.
//
// Why patch these layers: `fetch` is patched so the failure names the URL and
// happens before undici allocates anything, and `net.Socket.prototype.connect`
// is patched so anything bypassing fetch (a provider SDK, ws, an http Agent,
// tls, a raw socket) still cannot leave the machine; it reads the host from
// every shape node hands it, net.connect's normalized arguments included,
// as node reads it (an empty path is no unix socket, an unmarked array is
// the options), and refuses a lookup option of the caller's own, which picks
// the address for any host but an IP literal. A host passes as loopback only
// spelt as node dials it without a resolver: localhost, or an IP literal
// (isLoopbackHost), never trimmed or unbracketed but for a URL's hostname. A name lookup (dns.lookup, its
// promise twin and lookupService, which ask the system's resolver), a
// resolver query (dns.Resolver, its promise twin and the module-level resolve
// functions, which ask their servers, judged as they were bound at install
// and as they are now) and a datagram (dgram send and connect, and a socket
// made with a lookup of its own) are refused the same way, and the builtins'
// ESM exports are synced, so a named import sees the guarded function. Unix
// domain sockets carry no host and are left alone: the Docker
// driver talks to a socket path. What T01 cannot reach through the real entry
// points without risk it reaches through belowGuard(), a stub under the
// guard, so a broken guard sends nothing either.

import dgram from 'node:dgram'
import dns from 'node:dns'
import { existsSync, readFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import net from 'node:net'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { lockHolder } from '../../src/falsify-hold.js'

/**
 * Credentials never reach an offline test. Any name a provider key, the
 * control token or the pmmcp bearer would use is removed from this test
 * process's environment at import — so a key the operator exported in the
 * shell that runs `npm test` cannot be picked up, logged or sent by accident.
 *
 * The one exception is a test/live-*.test.ts file on the gated live run
 * (AOS_LIVE_TESTS=1). The gate alone is not enough: `AOS_LIVE_TESTS=1 npm
 * test` runs every file, and every offline one must still be scrubbed.
 * `node --test` gives each file its own process whose argv is exactly
 * [node, file]; anything else — an -e script, or --test-isolation=none, where
 * one process runs every file listed — is scrubbed.
 */
export const CREDENTIAL_NAME = /^(ANTHROPIC|OPENAI|OPENROUTER|MOONSHOT)_|_API_KEY$|^AOS_CONTROL_TOKEN$|^AOS_PMMCP_TOKEN$|^PMMCP_TOKEN$/

const LIVE_FILE = /[/\\]test[/\\]live-[^/\\]+\.test\.ts$/

/** True only in a live test file's own process on the gated run. */
export const KEEPS_CREDENTIALS =
  process.env['AOS_LIVE_TESTS'] === '1' && process.argv.length === 2 && LIVE_FILE.test(process.argv[1] ?? '')

if (!KEEPS_CREDENTIALS) {
  for (const name of Object.keys(process.env)) {
    if (CREDENTIAL_NAME.test(name)) delete process.env[name]
  }
}

/**
 * A falsify run that died (a closed terminal, a SIGKILL, a power cut) leaves a
 * source file mutated, and its journal is replayed only by the next falsify
 * start or `--recover`. Testing that tree would test a planted bug. The one
 * exception is the run that wrote the journal: it hands its id to its own test
 * processes (AOS_FALSIFY_RUN), and only they may test the tree it mutated. A
 * pid alone proves nothing — after a crash or a reboot it can name anything.
 */
function interruptedMutation(root: string): string | undefined {
  const path = join(root, '.falsify', 'journal.json')
  if (!existsSync(path)) return undefined
  let journal: { file?: unknown; runId?: unknown } = {}
  try {
    journal = JSON.parse(readFileSync(path, 'utf8')) as { file?: unknown; runId?: unknown }
  } catch {
    // Unreadable: it cannot name the file, so it must not pretend to.
  }
  if (typeof journal.runId === 'string' && journal.runId !== '' && process.env['AOS_FALSIFY_RUN'] === journal.runId) {
    return undefined
  }
  if (typeof journal.file !== 'string') {
    return (
      `${path} exists but is unreadable, so a falsify run may have left a source file mutated: ` +
      `run \`git status\`, \`git checkout\` any source file it lists that you did not change, then delete ${join(root, '.falsify')}`
    )
  }
  return (
    `a falsify run is in progress or was interrupted, and ${journal.file} may be mutated: ` +
    'run `npm run falsify -- --recover` (or git checkout the file and delete .falsify/) before testing'
  )
}

/**
 * A falsify run that holds this tree right now, and is not the one that
 * started this process. It mutates file after file while it holds the lock,
 * baselines included, so a test admitted between two mutants would load the
 * next one. Liveness is src/falsify-hold.ts's: the pid alone, since ps on every
 * test file would cost every run; a pid reused after a crash is a refusal that
 * `--recover` (which checks the start time) clears.
 */
function heldByAnotherRun(root: string): string | undefined {
  const holder = lockHolder(root)
  if (holder === undefined || (holder.runId !== undefined && holder.runId === process.env['AOS_FALSIFY_RUN'])) return undefined
  return (
    `a falsify run (pid ${String(holder.pid)}) holds this tree and mutates its files as it goes: let it finish before testing. ` +
    'If no falsify run is going, run `npm run falsify -- --recover`, which drops a stale lock'
  )
}

const root = fileURLToPath(new URL('../..', import.meta.url))
const mutated = interruptedMutation(root) ?? heldByAnotherRun(root)
if (mutated !== undefined) throw new Error(mutated)

/** Thrown instead of opening a connection the test suite must never make. */
export class NetworkBlocked extends Error {
  readonly code = 'AOS_TEST_NETWORK_BLOCKED'
  constructor(target: string, layer: string) {
    super(
      `test network guard: refused ${layer} to ${target}. ` +
        'Tests must not touch the network; use a loopback server or a test double, ' +
        'or call allowHost() if this is a gated live test.',
    )
    this.name = 'NetworkBlocked'
  }
}

const allowed = new Set<string>()

/** A-Z to a-z and nothing else: toLowerCase maps some non-ASCII letters (the Kelvin sign) onto ASCII ones, which a resolver does not. */
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => c.toLowerCase())

const LOOPBACK = new net.BlockList()
LOOPBACK.addSubnet('127.0.0.0', 8, 'ipv4')
LOOPBACK.addAddress('::1', 'ipv6')
LOOPBACK.addSubnet('::ffff:127.0.0.0', 104, 'ipv6')

/**
 * True for a host that node and getaddrinfo take to loopback as given,
 * asking no resolver: exactly `localhost` (ASCII case aside: getaddrinfo
 * answers it from /etc/hosts), or a string net.isIP reads as an address in
 * 127.0.0.0/8, ::1 or ::ffff:127.0.0.0/104, an IPv6 one with or without a
 * %zone. Nothing is trimmed or unbracketed, and no zone is cut from what is
 * not an IPv6 literal: node reads ' localhost', '[::1]' and '127.0.0.1%lo'
 * as names, not addresses, and hands them to getaddrinfo, which looks a name
 * up in /etc/hosts and then asks the system's resolver, and so the network.
 */
export function isLoopbackHost(host: string): boolean {
  if (/^localhost$/i.test(host)) return true
  const family = net.isIP(host)
  if (family === 4) return LOOPBACK.check(host, 'ipv4')
  if (family !== 6) return false
  const zone = host.indexOf('%')
  return LOOPBACK.check(zone === -1 ? host : host.slice(0, zone), 'ipv6')
}

/** A host a connect, a lookup or a datagram may name: loopback, or one allowHost admitted, spelt as it was (ASCII case aside). */
function permitted(host: string): boolean {
  return isLoopbackHost(host) || allowed.has(asciiLower(host))
}

/** A URL's hostname, which spells an IPv6 address in brackets (new URL('http://[::1]/').hostname is '[::1]'), as permitted() reads a host. */
function urlHostPermitted(hostname: string): boolean {
  return permitted(hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname)
}

/**
 * Admit exactly one non-loopback host, as spelt (ASCII case aside: nothing is
 * trimmed). Used only by the gated live tests. Returns a revoke function;
 * `clearAllowedHosts()` resets every allowance.
 */
export function allowHost(host: string): () => void {
  const key = asciiLower(host)
  allowed.add(key)
  return () => {
    allowed.delete(key)
  }
}

export function clearAllowedHosts(): void {
  allowed.clear()
}

function hostOfFetchInput(input: unknown): string {
  if (typeof input === 'string') return new URL(input).hostname
  if (input instanceof URL) return input.hostname
  if (typeof input === 'object' && input !== null && 'url' in input) {
    const url = (input as { url: unknown }).url
    if (typeof url === 'string') return new URL(url).hostname
  }
  // An input shape we cannot read is treated as non-loopback: fail closed.
  return '<unparseable>'
}

/** node's own name lookups, as dns exports them now (guarded) and as they were before the guard. */
const nodeLookups = new Set<unknown>([dns.lookup])

/**
 * A lookup option node would not replace with its own: options.lookup, for
 * net and tls (`options.lookup || dns.lookup`), and for dgram, which asks it.
 */
function ownLookupOf(options: object): boolean {
  const lookup: unknown = Reflect.get(options, 'lookup')
  return !lookup || nodeLookups.has(lookup) || lookup === dns.lookup
}

/**
 * What a connect's options dial: none for a unix domain socket, which node
 * takes a path for only when it is a non-empty string (net.js: `!!path`); the
 * host otherwise, node's default being localhost. A lookup of the caller's
 * own chooses the address for any host but an IP literal, so the guard cannot
 * know where that goes: it is refused, whatever the host is named.
 */
function hostOfOptions(options: object): string | undefined {
  const path: unknown = Reflect.get(options, 'path')
  if (typeof path === 'string' && path !== '') return undefined
  const given: unknown = Reflect.get(options, 'host')
  const host = typeof given === 'string' && given !== '' ? given : 'localhost'
  if (!ownLookupOf(options) && net.isIP(host) === 0) return `${host} through a lookup of its own`
  return host
}

/**
 * The hosts a Socket.prototype.connect call may dial: none for a unix domain
 * socket. net.connect and net.createConnection, and so everything built on
 * them (an http Agent, tls, undici), call it with node's normalized
 * arguments, one array marked as such whose first element is the options;
 * node reads any other array as the options itself. The guard cannot tell
 * the two apart for certain, so it reads an array both ways, and the call is
 * refused when either reading names a host it refuses. A shape that cannot
 * be read is no loopback host: fail closed.
 */
export function connectTargets(args: readonly unknown[]): readonly string[] {
  const first = args[0]
  const readings: (string | undefined)[] = []
  if (Array.isArray(first)) {
    const options: unknown = first[0]
    readings.push(typeof options === 'object' && options !== null ? hostOfOptions(options) : '<unparseable>', hostOfOptions(first))
  } else if (typeof first === 'object' && first !== null) {
    readings.push(hostOfOptions(first))
  } else if (typeof first === 'number' || (typeof first === 'string' && Number(first) >= 0)) {
    // A port, as a number or as a string node reads as one (net.js toNumber), then the host.
    const host = args[1]
    readings.push(typeof host === 'string' && host !== '' ? host : 'localhost')
  }
  // Otherwise connect(path[, listener]): a unix domain socket.
  return readings.filter((host): host is string => host !== undefined)
}

/** A datagram socket's options that carry a lookup of their own: dgram asks it for every address, an IP literal included, so nothing it sends can be judged. */
export function socketLookupRefused(options: unknown): string | undefined {
  if (typeof options !== 'object' || options === null) return undefined
  return ownLookupOf(options) ? undefined : '<every address> through a lookup of its own'
}

/**
 * The address a dgram send goes to, as node's Socket.prototype.send reads its
 * arguments (send(msg, offset, length, port, address) or send(msg, port,
 * address)), or undefined when none is given: an unconnected socket then
 * sends to loopback, and a connected one to the address its connect named.
 */
export function sendTarget(args: readonly unknown[]): string | undefined {
  const [, , length, port, address] = args
  const to: unknown = address || (port && typeof port !== 'function') ? address : length
  return typeof to === 'string' && to !== '' ? to : undefined
}

/** A DNS server as node:dns spells one (1.2.3.4, 1.2.3.4:53, ::1, [::1]:53): its address. */
function serverAddress(server: string): string {
  if (server.startsWith('[')) {
    const close = server.indexOf(']')
    return close === -1 ? server : server.slice(1, close)
  }
  return server.split(':').length === 2 ? server.slice(0, server.indexOf(':')) : server
}

/**
 * The server a resolver query would reach and the guard refuses, or
 * undefined. A query goes to the resolver's servers, whatever name it asks
 * for, so a loopback name proves nothing: it passes only when every server is
 * on loopback and none is one of the system's own (`system`), which, as
 * 127.0.0.53 or a local dnsmasq, forwards it off the machine.
 */
export function serverRefused(servers: readonly string[], system: ReadonlySet<string>): string | undefined {
  if (servers.length === 0) return '<no server>'
  return servers.find((server) => !isLoopbackHost(serverAddress(server)) || system.has(server))
}

/** The servers a resolver (or node:dns's default one, for the module) would ask. */
function serversOf(resolver: unknown): readonly string[] {
  const getServers: unknown = typeof resolver === 'object' && resolver !== null ? Reflect.get(resolver, 'getServers') : undefined
  if (typeof getServers !== 'function') return []
  const servers: unknown = Reflect.apply(getServers, resolver, [])
  return Array.isArray(servers) ? servers.filter((s): s is string => typeof s === 'string') : []
}

/** A name a lookup would resolve and the guard refuses: no name at all is node's to answer, and asks nobody. */
function nameRefused(name: unknown): string | undefined {
  if (typeof name !== 'string' || name === '') return undefined
  return permitted(name) ? undefined : name
}

type Guarded = (this: unknown, ...args: unknown[]) => unknown

/**
 * Stubs T01 (test/env.test.ts) puts under the guard with belowGuard(), by the
 * name of the function each stands in for: what a guarded function calls,
 * once it has let a call through, in place of the real one. T01 then drives
 * the real entry points (net.connect, http.get, dns.lookup, a Resolver, a
 * dgram socket) and proves the refusal comes first without the real call ever
 * running, even under a falsify mutant that breaks the guard. A stub only
 * narrows what a call reaches: the guard's check runs before it either way.
 */
const stubs = new Map<string, Guarded>()
const guardedNames = new Set<string>()
const installedFns = new WeakSet<object>()

/** True for a function the guard installed: T01 checks this before it calls one, so a guard that is not there never lets a real call run. */
export function isGuarded(fn: unknown): boolean {
  return typeof fn === 'function' && installedFns.has(fn)
}

/** Run `fn` with `swap`'s stubs under the guard, by guarded name (`net.Socket.prototype.connect`, `dns.lookup`, ...): T01 only. */
export function belowGuard<T>(swap: Readonly<Record<string, Guarded>>, fn: () => T): T {
  const names = Object.keys(swap)
  const unknown = names.filter((name) => !guardedNames.has(name))
  if (unknown.length > 0) throw new Error(`belowGuard: the guard wraps no ${unknown.join(', ')}`)
  for (const name of names) {
    const stub = swap[name]
    if (stub !== undefined) stubs.set(name, stub)
  }
  try {
    return fn()
  } finally {
    for (const name of names) stubs.delete(name)
  }
}

/**
 * Replace owner[key] with a function that first asks `refused` for the host
 * the call would reach and must not: one named throws a NetworkBlocked (or,
 * for a promise API, rejects with one) before anything is sent.
 */
function guard(
  owner: object,
  key: string,
  name: string,
  layer: string,
  refused: (self: unknown, args: readonly unknown[]) => string | undefined,
  promise = false,
): void {
  const real: unknown = Reflect.get(owner, key)
  if (typeof real !== 'function') throw new Error(`test network guard: ${name} is not a function in this node`)
  const guarded = function (this: unknown, ...args: unknown[]): unknown {
    const target = refused(this, args)
    if (target !== undefined) {
      const error = new NetworkBlocked(target, layer)
      if (promise) return Promise.reject(error)
      throw error
    }
    return Reflect.apply(stubs.get(name) ?? real, this, args)
  }
  Reflect.set(owner, key, guarded)
  installedFns.add(guarded)
  guardedNames.add(name)
}

/** Every query method a resolver (or node:dns's module, bound to its default resolver) has. */
function queryMethods(owner: object): string[] {
  return Object.getOwnPropertyNames(owner).filter((key) => /^(?:resolve|reverse)/.test(key) && typeof Reflect.get(owner, key) === 'function')
}

type FetchArgs = Parameters<typeof globalThis.fetch>

let installed = false

function install(): void {
  if (installed) return
  installed = true

  const realFetch = globalThis.fetch.bind(globalThis)
  globalThis.fetch = function guardedFetch(...args: FetchArgs): Promise<Response> {
    const host = hostOfFetchInput(args[0])
    if (!urlHostPermitted(host)) {
      return Promise.reject(new NetworkBlocked(host, 'fetch'))
    }
    return realFetch(...args)
  } as typeof globalThis.fetch

  guard(net.Socket.prototype, 'connect', 'net.Socket.prototype.connect', 'socket connect', (_self, args) => connectTargets(args).find((host) => !permitted(host)))

  // getaddrinfo asks the system's resolver, which may ask the network.
  guard(dns, 'lookup', 'dns.lookup', 'dns lookup', (_self, args) => nameRefused(args[0]))
  guard(dns.promises, 'lookup', 'dns.promises.lookup', 'dns lookup', (_self, args) => nameRefused(args[0]), true)
  guard(dns, 'lookupService', 'dns.lookupService', 'reverse lookup', (_self, args) => nameRefused(args[0]))
  guard(dns.promises, 'lookupService', 'dns.promises.lookupService', 'reverse lookup', (_self, args) => nameRefused(args[0]), true)

  // c-ares sends each query to the resolver's servers. A gated live test's
  // allowHost(name) admits a query for that name, as it admits the lookup.
  const system = new Set(dns.getServers())
  const queryRefused = (servers: readonly (readonly string[])[], name: unknown): string | undefined => {
    if (typeof name === 'string' && allowed.has(asciiLower(name))) return undefined
    for (const each of servers) {
      const server = serverRefused(each, system)
      if (server !== undefined) return `${typeof name === 'string' ? name : '<no name>'} via ${server}`
    }
    return undefined
  }
  // The module-level functions are bound to the default resolver as it is
  // now. dns.setServers makes a new one and rebinds the module's exports to
  // it, but a function taken before that, or named by an ESM import (synced
  // only below), still asks this one: its servers are judged, as well as the
  // module's servers of the moment.
  const atInstall = { dns: dns.getServers, promises: dns.promises.getServers }
  const resolvers: readonly (readonly [object, string, boolean, (self: unknown) => readonly (readonly string[])[]])[] = [
    [dns.Resolver.prototype, 'dns.Resolver.prototype', false, (self) => [serversOf(self)]],
    [dns.promises.Resolver.prototype, 'dns.promises.Resolver.prototype', true, (self) => [serversOf(self)]],
    [dns, 'dns', false, () => [serversOf(dns), atInstall.dns()]],
    [dns.promises, 'dns.promises', true, () => [serversOf(dns.promises), atInstall.promises()]],
  ]
  for (const [owner, prefix, promise, serversFor] of resolvers) {
    for (const key of queryMethods(owner)) {
      guard(owner, key, `${prefix}.${key}`, 'dns query', (self, args) => queryRefused(serversFor(self), args[0]), promise)
    }
  }

  guard(dgram.Socket.prototype, 'send', 'dgram.Socket.prototype.send', 'udp send', (_self, args) => {
    const address = sendTarget(args)
    return address !== undefined && !permitted(address) ? address : undefined
  })
  guard(dgram.Socket.prototype, 'connect', 'dgram.Socket.prototype.connect', 'udp connect', (_self, args) => {
    const address = args[1]
    return typeof address === 'string' && address !== '' && !permitted(address) ? address : undefined
  })
  // A datagram socket with a lookup of its own is refused when it is made:
  // createSocket, and the constructor itself, which createSocket calls by its
  // own binding and a caller may call by dgram's.
  guard(dgram, 'createSocket', 'dgram.createSocket', 'udp socket', (_self, args) => socketLookupRefused(args[0]))
  const RealSocket: unknown = dgram.Socket
  if (typeof RealSocket !== 'function') throw new Error('test network guard: dgram.Socket is not a constructor in this node')
  const GuardedSocket = new Proxy(RealSocket, {
    construct(target, args: unknown[], newTarget: unknown): object {
      const refused = socketLookupRefused(args[0])
      if (refused !== undefined) throw new NetworkBlocked(refused, 'udp socket')
      return Reflect.construct(target, args, newTarget as typeof target) as object
    },
  })
  Reflect.set(dgram, 'Socket', GuardedSocket)
  installedFns.add(GuardedSocket)

  // A named import of a builtin is a copy of the export until this: only now
  // does `import { lookup } from 'node:dns/promises'` (the in-image mux's
  // default probe) see the guarded function.
  syncBuiltinESMExports()
}

install()
