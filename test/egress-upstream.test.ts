// Egress plan E2 — the upstream (src/egress/upstream.ts): resolve after allow,
// check every answer, dial the checked address.
//
// The upstream is the last step before bytes leave the Mac for a worker, and
// it fails OPEN when it is wrong: the request reaches whatever the name
// resolved to, and the response comes back looking like any other. So each
// way it could reach somewhere nobody allowed is driven here, offline, with
// the resolver, the dialer and the interface list injected and every step
// they see recorded:
//
//   Resolve a name decide() did not allow, or one in a spelling nothing
//   compared, and the allowlist never judged what is dialled.
//   Check only the answer that is dialled, or only the A records, and a name
//   that resolves to one public and one private address (or a private AAAA
//   beside a public A) is treated as a public host.
//   Dial the name rather than the checked address, or let anything look it
//   up again, and the address dialled is one nobody checked: DNS rebinding.
//   Drop servername or rejectUnauthorized and any peer the name points at
//   gets the request, the credential with it.
//   Cache the Mac's interface list and an address it gains after boot is
//   dialled as a stranger's.
//
// No TLS key or certificate is used or committed (the repository is public):
// the TLS options are asserted as passed, and one test hands them to the real
// tls.connect against a loopback peer that only reads the ClientHello, which
// shows what Node puts on the wire with them, short of verification.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createSocket } from 'node:dgram'
import { getEventListeners } from 'node:events'
import { readFileSync } from 'node:fs'
import { Resolver } from 'node:dns/promises'
import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import { createServer as createNetServer, type AddressInfo } from 'node:net'
import { networkInterfaces, type NetworkInterfaceInfo } from 'node:os'
import { duplexPair, PassThrough, Readable, type Duplex } from 'node:stream'
import { checkServerIdentity, connect as tlsConnect } from 'node:tls'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

import { addressDenial, carriedAddresses } from '../src/egress/addr.js'
import { EgressAllow, mintEgressAllow, type JudgedBody } from '../src/egress/decision.js'
import { EgressHost } from '../src/egress/host.js'
import {
  createUpstream,
  systemUpstreamDeps,
  UPSTREAM_OWNED_HEADERS,
  UPSTREAM_REFUSALS,
  type DialOptions,
  type UpstreamCallOptions,
  type UpstreamDeps,
  type UpstreamHead,
  type UpstreamRefusal,
  type UpstreamRefused,
  type UpstreamResolver,
  type UpstreamResult,
  type UpstreamSocket,
  type UpstreamTarget,
} from '../src/egress/upstream.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')

const GITHUB = EgressHost.parse('github.com')
const PUBLIC_V4 = '140.82.112.3'
const PUBLIC_V4_B = '140.82.112.4'
const PUBLIC_V6 = '2606:50c0:8000::153'
/** A public IPv4 the fake Mac may hold on an interface, and its hex halves for the IPv6 forms that carry it. */
const OWN_V4 = '81.2.69.160'
const OWN_V4_HEX = '5102:45a0'
const OWN_V6 = '2a02:8010::1'

/** A head's one value of a header, by lower-case name, as decide() would have read it from the worker's. */
const headerOf = (head: UpstreamHead, lower: string): string | undefined =>
  Object.entries(head.headers).find(([name]) => name.toLowerCase() === lower)?.[1]
/**
 * The allow decide() would mint over `head`, with its content headers and
 * `body` as it judged them; the upstream takes nothing else, and each one
 * once.
 */
const allowFor = (head: UpstreamHead, body?: JudgedBody, host: EgressHost = GITHUB, port = 443): UpstreamTarget =>
  mintEgressAllow({
    host,
    port,
    method: head.method,
    path: head.path,
    content: { type: headerOf(head, 'content-type'), encoding: headerOf(head, 'content-encoding') },
    body,
  })
/** The allow for GET, the request most cases send. */
const allow = (host: EgressHost = GITHUB, port = 443): UpstreamTarget => allowFor(GET, undefined, host, port)
/** What a caller that skipped decide() would hand over: the shape of an allow, with no proof. */
const forged = (target: object): UpstreamTarget => target as UpstreamTarget

const GET: UpstreamHead = {
  method: 'GET',
  path: '/aos/fixture.git/info/refs?service=git-upload-pack',
  headers: { 'user-agent': 'git/2.47.0', accept: '*/*' },
}

// ── the fake world: a resolver, an interface list, a dialer and a host ────────

type Answer = readonly string[] | Error | 'hang' | (() => Promise<string[]>)
/**
 * How the fake handshake ends. The two `then-` forms finish it verified and,
 * in the same turn, before the upstream can write a byte, have the socket
 * report two errors (without being destroyed: a dialer whose socket does not
 * destroy itself on error) or close.
 */
type Handshake = 'verified' | 'unverified' | 'never' | 'closed' | 'verified-then-two-errors' | 'verified-then-closed' | Error

interface WorldOptions {
  readonly v4?: Answer
  readonly v6?: Answer
  readonly interfaces?: () => NodeJS.Dict<NetworkInterfaceInfo[]>
  readonly handshake?: Handshake
  /** How the fake host answers; the default is 200 and `ok`. */
  readonly serve?: (req: IncomingMessage, res: ServerResponse) => void
  /** In place of the fake HTTP host: the far end of the socket, to answer with raw bytes. */
  readonly raw?: (far: Duplex) => void
  readonly dial?: (options: DialOptions) => UpstreamSocket
  readonly connectTimeoutMs?: number
  readonly idleTimeoutMs?: number
}

interface Seen {
  readonly method: string
  readonly url: string
  readonly headers: IncomingHttpHeaders
  readonly rawHeaders: readonly string[]
  readonly body: string
}

interface Dialled {
  readonly socket: Duplex & { authorized: boolean }
  /** Every byte the client wrote, as the far end read it. */
  readonly raw: Buffer[]
  idle?: { readonly ms: number; readonly fire: () => void }
}

interface World {
  /** Every step any dependency saw, in order. */
  readonly steps: string[]
  readonly dials: DialOptions[]
  readonly dialled: Dialled[]
  readonly seen: Seen[]
  readonly deps: UpstreamDeps
}

/** An error as node:dns, net and tls make them: a code beside the message. */
function coded(code: string): Error {
  return Object.assign(new Error(`failed: ${code}`), { code })
}

function iface(address: string): NetworkInterfaceInfo {
  return address.includes(':')
    ? { address, netmask: 'ffff:ffff:ffff:ffff::', family: 'IPv6', mac: '02:00:00:00:00:01', internal: false, cidr: `${address}/64`, scopeid: 0 }
    : { address, netmask: '255.255.255.0', family: 'IPv4', mac: '02:00:00:00:00:01', internal: false, cidr: `${address}/24` }
}

/** A Mac with loopback, a private LAN address and a link-local one: nothing E1 does not already deny. */
const PLAIN_MAC: NodeJS.Dict<NetworkInterfaceInfo[]> = {
  lo0: [iface('127.0.0.1'), iface('::1')],
  en0: [iface('192.168.1.20'), iface('fe80::1c2b:3cff:fe4d:5e6f')],
}

function world(o: WorldOptions = {}): World {
  const steps: string[] = []
  const dials: DialOptions[] = []
  const dialled: Dialled[] = []
  const seen: Seen[] = []

  const answer = (family: 4 | 6, name: string, spec: Answer): Promise<string[]> => {
    steps.push(`resolve${String(family)} ${name}`)
    if (spec === 'hang') return new Promise<string[]>(() => undefined)
    if (spec instanceof Error) return Promise.reject(spec)
    if (typeof spec === 'function') return spec()
    return Promise.resolve([...spec])
  }
  const resolver = (): UpstreamResolver => {
    steps.push('resolver')
    return {
      resolve4: (name) => answer(4, name, o.v4 ?? [PUBLIC_V4]),
      resolve6: (name) => answer(6, name, o.v6 ?? []),
      cancel: () => {
        steps.push('cancel')
      },
    }
  }

  const host = createHttpServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      seen.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        rawHeaders: req.rawHeaders,
        body: Buffer.concat(chunks).toString('utf8'),
      })
      ;(o.serve ?? ((_req, r) => r.writeHead(200, { 'content-type': 'text/plain' }).end('ok')))(req, res)
    })
  })

  const fakeDial = (options: DialOptions): UpstreamSocket => {
    const [client, far] = duplexPair()
    const raw: Buffer[] = []
    // The far end may see the client vanish mid-write; that is the test's to
    // judge from what it recorded, not an error of the fake.
    far.on('error', () => undefined)
    far.on('data', (chunk: Buffer) => raw.push(chunk))
    const record: Dialled = { socket: Object.assign(client, { authorized: false }), raw }
    const socket = Object.assign(record.socket, {
      setTimeout: (ms: number, callback?: () => void): unknown => {
        record.idle = { ms, fire: () => callback?.() }
        return undefined
      },
    })
    dialled.push(record)
    if (o.raw === undefined) host.emit('connection', far)
    else o.raw(far)
    const shake = o.handshake ?? 'verified'
    setImmediate(() => {
      if (shake === 'never') return
      if (shake === 'closed') return void socket.destroy()
      if (shake instanceof Error) return void socket.destroy(shake)
      socket.authorized = shake !== 'unverified'
      socket.emit('secureConnect')
      if (shake === 'verified-then-two-errors') {
        socket.emit('error', coded('ECONNRESET'))
        socket.emit('error', coded('EPIPE'))
      }
      if (shake === 'verified-then-closed') socket.destroy()
    })
    return socket
  }

  const deps: UpstreamDeps = {
    resolver,
    dial: (options) => {
      steps.push(`dial ${options.host}`)
      dials.push(options)
      return (o.dial ?? fakeDial)(options)
    },
    interfaces: () => {
      steps.push('interfaces')
      return (o.interfaces ?? (() => PLAIN_MAC))()
    },
    connectTimeoutMs: o.connectTimeoutMs ?? 9_000,
    idleTimeoutMs: o.idleTimeoutMs ?? 30_000,
  }
  return { steps, dials, dialled, seen, deps }
}

function refusedAs(result: UpstreamResult, reason: UpstreamRefusal, label = ''): UpstreamRefused {
  assert.equal(result.ok, false, `${label}: expected a refusal for ${reason}`)
  if (result.ok) throw new Error('unreachable')
  assert.equal(result.reason, reason, `${label}: ${result.why}`)
  assert.ok(UPSTREAM_REFUSALS.includes(result.reason))
  assert.equal(Object.isFrozen(result), true, `${label}: a refusal is not frozen`)
  return result
}

async function bodyOf(res: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of res) chunks.push(Buffer.from(chunk as Uint8Array))
  return Buffer.concat(chunks).toString('utf8')
}

const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

async function until(what: string, done: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (done()) return
    await turn()
  }
  assert.fail(`timed out waiting for ${what}`)
}

const closed = (socket: Duplex): Promise<void> =>
  socket.destroyed ? Promise.resolve() : new Promise((resolve) => socket.once('close', () => resolve()))

/** `promise`, or a failure naming `what` once `ms` of real time pass: a request that never settles fails its test rather than hanging it. */
async function within<T>(what: string, ms: number, promise: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${String(ms)} ms`)), ms)
  })
  try {
    return await Promise.race([promise, deadline])
  } finally {
    clearTimeout(timer)
  }
}

/** A raw host: once the request head has arrived, it writes `response` as it stands, and nothing else. */
function answering(response: string): (far: Duplex) => void {
  return (far) => {
    let head = ''
    let answered = false
    far.on('data', (chunk: Buffer) => {
      head += chunk.toString('latin1')
      if (answered || !head.includes('\r\n\r\n')) return
      answered = true
      far.write(response)
    })
  }
}

/** Every byte the far end of a dialled socket read, as text. */
const wire = (d: Dialled | undefined): string => Buffer.concat(d?.raw ?? []).toString('latin1')

/** A body stream of `chunks`, each its own chunk. */
function bodyStream(...chunks: string[]): Readable {
  return Readable.from(chunks.map((c) => Buffer.from(c)))
}

// ── allow, then resolve ───────────────────────────────────────────────────────

test('a denied name is never resolved', async () => {
  // Every target and head here is refused before a resolver exists: nothing
  // is asked of DNS, of the interface list or of the dialer. The casts are a
  // caller that took the brand off a string nothing normalised.
  const cases: ReadonlyArray<readonly [string, UpstreamTarget, UpstreamHead, UpstreamRefusal]> = [
    // A deny is never minted: it is refused as what it is, not an allow decide() made.
    ['a deny verdict', forged({ verdict: 'deny', host: GITHUB, port: 443 }), GET, 'not-decided'],
    ['a verdict that is not exactly allow', forged({ verdict: 'Allow', host: GITHUB, port: 443 }), GET, 'not-decided'],
    // The shape of an allow is no proof decide() made it: only the one it
    // minted is resolved.
    ['an allow built by hand', forged({ verdict: 'allow', host: GITHUB, port: 443 }), GET, 'not-decided'],
    ['a spread copy of a minted allow', forged({ ...allow() }), GET, 'not-decided'],
    ['a JSON round-trip of a minted allow', forged(JSON.parse(JSON.stringify(allow())) as object), GET, 'not-decided'],
    ['an object whose prototype is a minted allow', forged(Object.create(allow()) as object), GET, 'not-decided'],
    ['a Proxy of a minted allow', forged(new Proxy(allow(), {})), GET, 'not-decided'],
    ['an object made from the prototype', forged(Object.create(EgressAllow.prototype, { verdict: { value: 'allow' }, host: { value: GITHUB }, port: { value: 443 } }) as object), GET, 'not-decided'],
    ['host.lima.internal', allow('host.lima.internal' as EgressHost), GET, 'not-a-host'],
    ['host.docker.internal', allow('host.docker.internal' as EgressHost), GET, 'not-a-host'],
    ['192.168.5.2', allow('192.168.5.2' as EgressHost), GET, 'not-a-host'],
    ['127.0.0.1', allow('127.0.0.1' as EgressHost), GET, 'not-a-host'],
    ['0x7f.1', allow('0x7f.1' as EgressHost), GET, 'not-a-host'],
    ['[::1]', allow('[::1]' as EgressHost), GET, 'not-a-host'],
    ['localhost', allow('localhost' as EgressHost), GET, 'not-a-host'],
    ['a name with a port', allow('github.com:443' as EgressHost), GET, 'not-a-host'],
    ['GitHub.com, a spelling no allowlist compared', allow('GitHub.com' as EgressHost), GET, 'not-a-host'],
    ['github.com. with its trailing dot', allow('github.com.' as EgressHost), GET, 'not-a-host'],
    ['an empty host', allow('' as EgressHost), GET, 'not-a-host'],
    ['a host that is not a string', allow(443 as unknown as EgressHost), GET, 'not-a-host'],
    ['port 80', allow(GITHUB, 80), GET, 'port'],
    ['port 8443', allow(GITHUB, 8443), GET, 'port'],
    ['port 0', allow(GITHUB, 0), GET, 'port'],
    ['port 443.5', allow(GITHUB, 443.5), GET, 'port'],
    ['a head that names Host', allow(), { ...GET, headers: { Host: 'evil.example' } }, 'head'],
  ]
  for (const [label, target, head, reason] of cases) {
    const w = world()
    const result = await createUpstream(w.deps).request(target, head)
    const refusal = refusedAs(result, reason, label)
    assert.deepEqual(w.steps, [], `${label}: something was asked before the refusal`)
    for (const leaked of ['lima', 'docker', '192.168', 'evil', 'GitHub']) {
      assert.equal(refusal.why.includes(leaked), false, `${label}: the refusal echoes ${leaked}`)
    }
  }

  // An aborted request is not resolved either.
  const w = world()
  const aborted = new AbortController()
  aborted.abort()
  refusedAs(await createUpstream(w.deps).request(allow(), GET, { signal: aborted.signal }), 'aborted')
  assert.deepEqual(w.steps, [])

  // And the control: the same world, allowed, is resolved once, in both families.
  const control = world()
  const ok = await createUpstream(control.deps).request(allow(), GET)
  assert.equal(ok.ok, true)
  assert.deepEqual(control.steps.slice(0, 3), ['resolver', 'resolve4 github.com', 'resolve6 github.com'])
})

test('an allow is an EgressAllow decide() minted over one request: frozen with its class, never constructed directly, and told apart from every copy', () => {
  const leading = Buffer.from('0032old new refs/heads/aos/run-1/x\0 report-status\n0000')
  const minted = mintEgressAllow({ host: GITHUB, port: 443, method: 'POST', path: '/aos/fixture.git/git-receive-pack', body: { leading } })
  assert.equal(EgressAllow.is(minted), true)
  assert.equal(minted.verdict, 'allow')
  assert.equal(minted.host, GITHUB)
  assert.equal(minted.port, 443)
  assert.equal(minted.method, 'POST')
  assert.equal(minted.path, '/aos/fixture.git/git-receive-pack')
  assert.deepEqual(minted.body, { length: undefined, leadingBytes: leading.length })
  assert.equal(allow().body, undefined)
  // No content headers judged is none of either, which the head must match.
  assert.deepEqual(minted.content, { type: undefined, encoding: undefined })
  const typed = mintEgressAllow({ host: GITHUB, port: 443, method: 'POST', path: '/x', content: { type: 'application/json', encoding: 'gzip' } })
  assert.deepEqual(typed.content, { type: 'application/json', encoding: 'gzip' })
  assert.equal(Object.isFrozen(typed.content), true)
  assert.throws(() => { (typed.content as { encoding: string | undefined }).encoding = undefined }, TypeError)
  // Text or none: a value coerced at comparison could match a head it should not.
  for (const content of [{ type: 5 }, { encoding: ['gzip'] }, { type: null }]) {
    assert.throws(() => mintEgressAllow({ host: GITHUB, port: 443, method: 'POST', path: '/x', content: content as unknown as { type?: string } }), TypeError)
  }
  // Frozen: the request the upstream checks is the one decide() allowed, for
  // as long as the allow lives. Modules are strict, so a write throws rather
  // than being dropped.
  assert.equal(Object.isFrozen(minted), true)
  assert.equal(Object.isFrozen(minted.body), true)
  const writable = minted as { host: string; port: number; method: string; path: string }
  assert.throws(() => { writable.host = 'evil.example' }, TypeError)
  assert.throws(() => { writable.port = 8443 }, TypeError)
  assert.throws(() => { writable.method = 'GET' }, TypeError)
  assert.throws(() => { writable.path = '/other-org/other.git/git-receive-pack' }, TypeError)
  assert.equal(minted.host, GITHUB)
  // The leading bytes are a private copy: neither the buffer decide() judged
  // nor the copy handed out can change what the upstream holds the body to.
  leading.fill(0x41)
  const out = EgressAllow.leadingOf(minted)
  assert.ok(out !== undefined)
  out.fill(0x42)
  assert.equal(Buffer.from(EgressAllow.leadingOf(minted) ?? []).toString('latin1'), '0032old new refs/heads/aos/run-1/x\0 report-status\n0000')
  assert.equal(EgressAllow.leadingOf(allow()), undefined)
  // Only bytes are bytes: a number would make a zeroed array of that length.
  assert.throws(() => mintEgressAllow({ host: GITHUB, port: 443, method: 'POST', path: '/x', body: { leading: 5 as unknown as Uint8Array } }), TypeError)
  // Spent once: true the first time, false ever after.
  const once = allow()
  assert.equal(EgressAllow.spend(once), true)
  assert.equal(EgressAllow.spend(once), false)
  assert.equal(EgressAllow.spend(once), false)
  // The constructor refuses without the module's own key, even one with the
  // same description.
  const Construct = EgressAllow as unknown as new (key: symbol, judged: object) => EgressAllow
  assert.throws(() => new Construct(Symbol('aos.egressAllow.mint'), { host: GITHUB, port: 443, method: 'GET', path: '/' }), TypeError)
  for (const lookalike of [
    { verdict: 'allow', host: GITHUB, port: 443 },
    { ...minted },
    structuredClone({ verdict: minted.verdict, host: minted.host, port: minted.port }),
    Object.create(minted) as object,
    new Proxy(minted, {}),
    null,
    'allow',
  ]) {
    assert.equal(EgressAllow.is(lookalike), false, String(lookalike))
  }
  // The class and its prototype are frozen: `is` cannot be swapped for one
  // that says yes, and nothing can be hung on the prototype for a copy to
  // inherit.
  assert.equal(Object.isFrozen(EgressAllow), true)
  assert.equal(Object.isFrozen(EgressAllow.prototype), true)
  const open = EgressAllow as unknown as { is: (value: unknown) => boolean; spend: (value: unknown) => boolean }
  assert.throws(() => { open.is = () => true }, TypeError)
  assert.throws(() => { open.spend = () => true }, TypeError)
  assert.equal(EgressAllow.is({ verdict: 'allow', host: GITHUB, port: 443 }), false)
})

test('decision.ts is pure and takes nothing but the EgressHost type', () => {
  const path = 'src/egress/decision.ts'
  const source = ts.createSourceFile(path, readFileSync(`${REPO}/${path}`, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const imports: string[] = []
  const names = new Set<string>()
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      imports.push(`${node.importClause?.isTypeOnly === true ? 'type ' : ''}${node.moduleSpecifier.text}`)
    }
    if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) imports.push('<re-export>')
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) imports.push('<import()>')
    if (ts.isIdentifier(node)) names.add(node.text)
    ts.forEachChild(node, visit)
  }
  visit(source)
  assert.deepEqual(imports, ['type ./host.js'])
  for (const name of ['process', 'globalThis', 'require', 'eval', 'Function', 'fetch']) assert.equal(names.has(name), false, name)
})

/** A push to another repository's receive-pack: the request an allow for something else must never carry. */
const RECEIVE_ELSEWHERE: UpstreamHead = {
  method: 'POST',
  path: '/other-org/other.git/git-receive-pack',
  headers: { 'content-type': 'application/x-git-receive-pack-request' },
}

test('an allow carries one request, the one decide() judged: a second request, another method or path, or a body declared otherwise is refused as not decided, before anything is resolved', async () => {
  // Probe P8: one allow for github.com, sent with GET info/refs and then with
  // a POST to another repository's receive-pack. The first is sent; the
  // second is refused, and nothing more is resolved or dialled.
  const w = world()
  const upstream = createUpstream(w.deps)
  const once = allow()
  const first = await upstream.request(once, GET)
  assert.equal(first.ok, true)
  if (first.ok) await bodyOf(first.response)
  const asked = w.steps.length
  for (const [label, head, body] of [['the same request again', GET, undefined], ["another repository's receive-pack", RECEIVE_ELSEWHERE, 'pack']] as const) {
    const stream = bodyStream(body ?? '')
    const refusal = refusedAs(await upstream.request(once, head, body === undefined ? {} : { body: { stream, length: body.length } }), 'not-decided', label)
    assert.match(refusal.why, /already carried a request/, label)
    if (body !== undefined) assert.equal(stream.destroyed, true, label)
  }
  assert.equal(w.steps.length, asked, 'a spent allow asked something of a dependency')
  assert.equal(w.dials.length, 1)
  assert.equal(w.seen.length, 1)

  // Spent when request() is called, before it awaits anything: two calls in
  // one turn with one allow send one request.
  const race = world()
  const twice = allow()
  const r = createUpstream(race.deps)
  const [a, b] = await Promise.all([r.request(twice, GET), r.request(twice, GET)])
  assert.equal(a.ok, true)
  if (a.ok) await bodyOf(a.response)
  refusedAs(b, 'not-decided', 'the second call in the same turn')
  assert.equal(race.dials.length, 1)

  // A refused request spends its allow too: there is no retry with it.
  const burnt = world()
  const u = createUpstream(burnt.deps)
  const used = allow()
  refusedAs(await u.request(used, { ...GET, headers: { Host: 'evil.example' } }), 'head')
  refusedAs(await u.request(used, GET), 'not-decided', 'the allow after its request was refused')
  assert.deepEqual(burnt.steps, [])

  // Fresh allows, each presented with a request other than the one it was
  // minted over.
  const cases: ReadonlyArray<readonly [string, UpstreamTarget, UpstreamHead, { readonly chunks: readonly string[]; readonly length?: number } | undefined, RegExp]> = [
    ['another path, the method the same', allowFor(GET), { ...GET, path: '/aos/other.git/info/refs?service=git-upload-pack' }, undefined, /another method or path/],
    ['another query on the same path', allowFor(GET), { ...GET, path: '/aos/fixture.git/info/refs?service=git-receive-pack' }, undefined, /another method or path/],
    ['another method, the path the same', allowFor(GET), { ...GET, method: 'HEAD' }, undefined, /another method or path/],
    ['a GET judged, a receive-pack sent', allowFor(GET), RECEIVE_ELSEWHERE, { chunks: ['pack'], length: 4 }, /another method or path/],
    ['a body where decide() judged none', allowFor(POST), POST, { chunks: ['hello'], length: 5 }, /a body where decide\(\) judged none/],
    ['no body where decide() judged one', allowFor(POST, { length: 5 }), POST, undefined, /none where it judged one/],
    ['another declared length', allowFor(POST, { length: 5 }), POST, { chunks: ['hello!'], length: 6 }, /declared length/],
    ['chunked where decide() judged a length', allowFor(POST, { length: 5 }), POST, { chunks: ['hello'] }, /declared length/],
    ['a length where decide() judged it chunked', allowFor(POST, {}), POST, { chunks: ['hello'], length: 5 }, /declared length/],
  ]
  for (const [label, target, head, body, why] of cases) {
    const each = world()
    const stream = body === undefined ? undefined : bodyStream(...body.chunks)
    const options = stream === undefined || body === undefined ? {} : { body: body.length === undefined ? { stream } : { stream, length: body.length } }
    const refusal = refusedAs(await createUpstream(each.deps).request(target, head, options), 'not-decided', label)
    assert.match(refusal.why, why, label)
    assert.deepEqual(each.steps, [], `${label}: something was asked before the refusal`)
    if (stream !== undefined) assert.equal(stream.destroyed, true, `${label}: the body was left undisposed`)
  }
})

test("a head whose Content-Type or Content-Encoding is not the one decide() judged is refused as not decided: one added, dropped, changed or respelled, in any case of its name, before anything is resolved", async () => {
  // How the host decodes the body is in these two: a push judged plain and
  // sent with Content-Encoding: gzip has the host gunzip it into a command
  // list nobody read. The allow carries the values decide() read, and the
  // head must carry exactly them.
  const push: UpstreamHead = { method: 'POST', path: '/aos/fixture.git/git-receive-pack', headers: { 'content-type': 'application/x-git-receive-pack-request' } }
  const gzipped: UpstreamHead = { ...push, headers: { ...push.headers, 'content-encoding': 'gzip' } }
  const plain = (): UpstreamTarget => allowFor(push, { length: 4 })
  const encoded = (): UpstreamTarget => allowFor(gzipped, { length: 4 })
  const cases: ReadonlyArray<readonly [string, () => UpstreamTarget, UpstreamHead, RegExp]> = [
    ['Content-Encoding added where decide() judged none', plain, gzipped, /Content-Encoding/],
    ['Content-Encoding added, its name in another case', plain, { ...push, headers: { ...push.headers, 'Content-Encoding': 'gzip' } }, /Content-Encoding/],
    ['Content-Encoding: identity added', plain, { ...push, headers: { ...push.headers, 'content-encoding': 'identity' } }, /Content-Encoding/],
    ['Content-Encoding dropped where decide() judged gzip', encoded, push, /Content-Encoding/],
    ['another Content-Encoding than the one judged', encoded, { ...push, headers: { ...push.headers, 'content-encoding': 'br' } }, /Content-Encoding/],
    ['the judged Content-Encoding respelled', encoded, { ...push, headers: { ...push.headers, 'content-encoding': 'GZIP' } }, /Content-Encoding/],
    ['Content-Type dropped', plain, { ...push, headers: {} }, /Content-Type/],
    ['another Content-Type', plain, { ...push, headers: { 'content-type': 'application/x-git-upload-pack-request' } }, /Content-Type/],
    ['the judged Content-Type respelled', plain, { ...push, headers: { 'Content-Type': 'Application/X-Git-Receive-Pack-Request' } }, /Content-Type/],
    ['Content-Type added where decide() judged none', () => allowFor(GET), { ...GET, headers: { ...GET.headers, 'content-type': 'text/plain' } }, /Content-Type/],
  ]
  for (const [label, target, head, why] of cases) {
    const each = world()
    const stream = bodyStream('0000')
    const options = head.method === 'GET' ? {} : { body: { stream, length: 4 } }
    const refusal = refusedAs(await createUpstream(each.deps).request(target(), head, options), 'not-decided', label)
    assert.match(refusal.why, why, label)
    assert.deepEqual(each.steps, [], `${label}: something was asked before the refusal`)
    if (head.method !== 'GET') assert.equal(stream.destroyed, true, `${label}: the body was left undisposed`)
  }
  // The control: the same values, a name in another case included, are sent.
  for (const [label, target, head] of [
    ['plain, as judged', plain, push],
    ['gzip, as judged', encoded, gzipped],
    ['the names in another case', encoded, { ...push, headers: { 'Content-Type': 'application/x-git-receive-pack-request', 'Content-Encoding': 'gzip' } }],
  ] as const) {
    const each = world()
    const sent = await createUpstream(each.deps).request(target(), head, { body: { stream: bodyStream('0000'), length: 4 } })
    assert.equal(sent.ok, true, label)
    if (sent.ok) await bodyOf(sent.response)
    assert.equal(each.dials.length, 1, label)
    // Sent as the head named them: the upstream holds the head to the allow and rewrites nothing.
    assert.equal(each.seen[0]?.headers['content-type'], 'application/x-git-receive-pack-request', label)
    assert.equal(each.seen[0]?.headers['content-encoding'], headerOf(head, 'content-encoding'), label)
  }
})

/** A push: the command list decide() reads and judges, then the pack it never reads. */
const PUSH: UpstreamHead = {
  method: 'POST',
  path: '/aos/fixture.git/git-receive-pack',
  headers: { 'content-type': 'application/x-git-receive-pack-request' },
}
const COMMANDS = '0067old new refs/heads/aos/run-1/fix\0report-status side-band-64k\n0000'
/** The same length, another ref: what a body that is not the judged one would carry. */
const OTHER_COMMANDS = COMMANDS.replace('refs/heads/aos/run-1/fix', 'refs/heads/main-----xxxx')
const PACK = 'PACK\0\0\0\x02\0\0\0\x01pack bytes nobody read'

test("a body whose leading bytes decide() judged is sent only if it begins with exactly them: one that differs, in any chunk, or ends first, is refused before its head or any byte is written", async () => {
  assert.equal(OTHER_COMMANDS.length, COMMANDS.length)
  const judged = (length?: number): UpstreamTarget => allowFor(PUSH, { length, leading: Buffer.from(COMMANDS, 'latin1') })
  const total = COMMANDS.length + PACK.length

  // As judged, however it is cut into chunks, declared or chunked: sent whole.
  const cuts: ReadonlyArray<readonly string[]> = [
    [COMMANDS + PACK],
    [COMMANDS, PACK],
    [COMMANDS.slice(0, 7), COMMANDS.slice(7, 40), COMMANDS.slice(40) + PACK],
    [...COMMANDS.split(''), PACK],
  ]
  for (const chunks of cuts) {
    for (const length of [total, undefined]) {
      const label = `${String(chunks.length)} chunks, ${length === undefined ? 'chunked' : 'declared'}`
      const w = world({ serve: (_req, res) => res.writeHead(204).end() })
      const stream = Readable.from(chunks.map((c) => Buffer.from(c, 'latin1')))
      const result = await within(label, 2_000, createUpstream(w.deps).request(judged(length), PUSH, { body: length === undefined ? { stream } : { stream, length } }))
      assert.equal(result.ok, true, label)
      await until('the body to arrive', () => w.seen.length === 1)
      // All ASCII, so the host's utf8 reading is the bytes sent.
      assert.equal(w.seen[0]?.body, COMMANDS + PACK, label)
      assert.equal(w.seen[0]?.headers['content-length'], length === undefined ? undefined : String(total), label)
    }
  }

  // Not as judged: refused, and the host reads nothing, not even the head.
  const differ: ReadonlyArray<readonly [string, readonly string[], number | undefined]> = [
    ['another ref, in one chunk', [OTHER_COMMANDS + PACK], total],
    ['another ref, chunked', [OTHER_COMMANDS + PACK], undefined],
    ['the right start, then another ref in a later chunk', [COMMANDS.slice(0, 20), OTHER_COMMANDS.slice(20) + PACK], undefined],
    ['the right start, then another ref, byte by byte', [...OTHER_COMMANDS.split(''), PACK], undefined],
    ['a body that ends before the judged bytes do', [COMMANDS.slice(0, 30)], undefined],
    ['an empty body', [], undefined],
  ]
  for (const [label, chunks, length] of differ) {
    const w = world()
    const stream = Readable.from(chunks.map((c) => Buffer.from(c, 'latin1')))
    const refusal = refusedAs(await within(label, 2_000, createUpstream(w.deps).request(judged(length), PUSH, { body: length === undefined ? { stream } : { stream, length } })), 'not-decided', label)
    assert.match(refusal.why, /does not begin with the bytes decide\(\) judged/, label)
    const [d] = w.dialled
    assert.ok(d !== undefined, label)
    await closed(d.socket)
    await turn()
    assert.equal(wire(d), '', `${label}: something was written`)
    assert.equal(w.seen.length, 0, label)
    assert.equal(stream.destroyed, true, label)
  }
})

// ── check every answer ────────────────────────────────────────────────────────

test('a name resolving to one public and one private address is refused', async () => {
  // Each case has a public answer beside a denied one, in either family and
  // in either order; the denied one need not be the one that would be
  // dialled. Both families are always asked, the interface list is never
  // read and nothing is dialled.
  const cases: ReadonlyArray<readonly [string, readonly string[], readonly string[], string]> = [
    ['192.168.5.2 after a public A', [PUBLIC_V4, '192.168.5.2'], [], '192.168.5.2'],
    ['192.168.5.2 before a public A', ['192.168.5.2', PUBLIC_V4], [], '192.168.5.2'],
    ['loopback beside a public A', [PUBLIC_V4, '127.0.0.1'], [], '127.0.0.1'],
    ['10/8 beside a public A', [PUBLIC_V4, '10.1.2.3'], [], '10.1.2.3'],
    ['CGNAT beside a public A', [PUBLIC_V4, '100.64.0.1'], [], '100.64.0.1'],
    ['the metadata address beside a public A', [PUBLIC_V4, '169.254.169.254'], [], '169.254.169.254'],
    ['0.0.0.0 beside a public A', [PUBLIC_V4, '0.0.0.0'], [], '0.0.0.0'],
    ['a private AAAA beside a public A', [PUBLIC_V4], ['fd00::1'], 'fd00::1'],
    ['a link-local AAAA beside a public A', [PUBLIC_V4], ['fe80::1'], 'fe80::1'],
    ['::1 beside a public A', [PUBLIC_V4], ['::1'], '::1'],
    ['IPv4-mapped loopback beside a public A', [PUBLIC_V4], ['::ffff:127.0.0.1'], '::ffff:127.0.0.1'],
    ['NAT64 of 192.168.5.2 beside a public A', [PUBLIC_V4], ['64:ff9b::c0a8:502'], '64:ff9b::c0a8:502'],
    ['6to4 of loopback beside a public AAAA', [], [PUBLIC_V6, '2002:7f00:1::'], '2002:7f00:1::'],
    ['a private AAAA beside a public AAAA', [], [PUBLIC_V6, 'fc00::5'], 'fc00::5'],
  ]
  for (const [label, v4, v6, denied] of cases) {
    const w = world({ v4, v6 })
    const refusal = refusedAs(await createUpstream(w.deps).request(allow(), GET), 'denied-address', label)
    assert.equal(refusal.address, denied, label)
    assert.deepEqual(refusal.denial, addressDenial(denied), label)
    assert.deepEqual(w.steps, ['resolver', 'resolve4 github.com', 'resolve6 github.com'], label)
    assert.equal(w.dials.length, 0, label)
  }
  const mapped = refusedAs(await createUpstream(world({ v6: ['::ffff:192.168.5.2'] }).deps).request(allow(), GET), 'denied-address')
  assert.deepEqual(mapped.denial, { reason: 'private', via: 'ipv4-mapped', embedded: '192.168.5.2' })

  // Text that is no address is denied, and is not repeated in the refusal.
  for (const junk of ['0x7f.1', '127.1', 'github.com', '1.2.3.4.5', 'fe80::1%en0', '']) {
    const w = world({ v4: [PUBLIC_V4, junk] })
    const refusal = refusedAs(await createUpstream(w.deps).request(allow(), GET), 'denied-address', junk)
    assert.deepEqual(refusal.denial, { reason: 'not-an-address' }, junk)
    assert.equal('address' in refusal, false, junk)
    assert.equal(w.dials.length, 0, junk)
  }

  // An answer of the other family is a resolver that is not answering what was asked.
  for (const [v4, v6] of [[[PUBLIC_V6], []], [[], [PUBLIC_V4]]] as const) {
    const w = world({ v4, v6 })
    refusedAs(await createUpstream(w.deps).request(allow(), GET), 'resolve-failed')
    assert.equal(w.dials.length, 0)
  }

  // The control: every answer public, in both families, and it is dialled.
  const w = world({ v4: [PUBLIC_V4, PUBLIC_V4_B], v6: [PUBLIC_V6] })
  const ok = await createUpstream(w.deps).request(allow(), GET)
  assert.equal(ok.ok, true)
  assert.equal(w.dials.length, 1)
})

test('a lookup that fails refuses; only "no such record" is an empty answer', async () => {
  const cases: ReadonlyArray<readonly [string, Answer, Answer, UpstreamRefusal | 'dialled', string | undefined]> = [
    ['NXDOMAIN in both families', coded('ENOTFOUND'), coded('ENOTFOUND'), 'no-address', undefined],
    ['no record in both families', coded('ENODATA'), coded('ENODATA'), 'no-address', undefined],
    ['two empty lists', [], [], 'no-address', undefined],
    ['no A, a public AAAA', coded('ENODATA'), [PUBLIC_V6], 'dialled', undefined],
    // An AAAA nobody saw may be the private one: fail closed.
    ['a public A and an AAAA that timed out', [PUBLIC_V4], coded('ETIMEOUT'), 'resolve-failed', 'ETIMEOUT'],
    ['an A that failed and a public AAAA', coded('ESERVFAIL'), [PUBLIC_V6], 'resolve-failed', 'ESERVFAIL'],
    ['a refused query', coded('EREFUSED'), [], 'resolve-failed', 'EREFUSED'],
    ['an error with no code', new Error('broken'), [], 'resolve-failed', undefined],
    // A code that is not one (lower case, a host in it) is not repeated.
    ['an error whose code is text', coded('lookup github.com failed'), [], 'resolve-failed', undefined],
    ['a resolver that throws', () => { throw coded('EBADNAME') }, [], 'resolve-failed', 'EBADNAME'],
    ['an answer that is not a list', () => Promise.resolve(PUBLIC_V4 as unknown as string[]), [], 'resolve-failed', undefined],
    ['a list that holds a number', () => Promise.resolve([PUBLIC_V4, 2130706433] as unknown as string[]), [], 'resolve-failed', undefined],
  ]
  for (const [label, v4, v6, expected, code] of cases) {
    const w = world({ v4, v6 })
    const result = await createUpstream(w.deps).request(allow(), GET)
    if (expected === 'dialled') {
      assert.equal(result.ok, true, label)
      assert.deepEqual(w.dials.map((d) => d.host), [PUBLIC_V6], label)
      continue
    }
    const refusal = refusedAs(result, expected, label)
    assert.equal(refusal.code, code, label)
    assert.equal(w.dials.length, 0, label)
    assert.equal(w.steps.includes('interfaces'), false, label)
  }
})

test('a resolver that cannot be made or cancelled is a refusal, never a rejection', async () => {
  // request() never rejects for a dependency that throws: a rejection the
  // session did not await would end the kernel.
  const unmade = world()
  const noResolver: UpstreamDeps = { ...unmade.deps, resolver: () => { throw coded('ENOMEM') } }
  const refusal = refusedAs(await createUpstream(noResolver).request(allow(), GET), 'resolve-failed', 'a factory that throws')
  assert.equal(refusal.code, 'ENOMEM')
  // Named for the dependency that failed, not as a throw somewhere in resolving.
  assert.match(refusal.why, /no resolver could be made/)
  assert.equal(unmade.dials.length, 0)

  // A cancel that throws, at the deadline and on an abort: refused, and
  // nothing is dialled.
  const uncancellable = (w: World): UpstreamDeps => ({
    ...w.deps,
    resolver: () => ({ ...w.deps.resolver(), cancel: () => { throw coded('ECANCELLED') } }),
  })
  const late = world({ v4: 'hang', connectTimeoutMs: 20 })
  const atDeadline = refusedAs(await within('the timed-out lookup', 2_000, createUpstream(uncancellable(late)).request(allow(), GET)), 'resolve-failed', 'a cancel that throws at the deadline')
  assert.equal(atDeadline.code, 'ECANCELLED')
  assert.match(atDeadline.why, /could not be cancelled/)
  const aborting = world({ v4: 'hang' })
  const abort = new AbortController()
  const pending = createUpstream(uncancellable(aborting)).request(allow(), GET, { signal: abort.signal })
  await until('the lookup', () => aborting.steps.includes('resolve6 github.com'))
  abort.abort()
  const onAbort = refusedAs(await within('the aborted lookup', 2_000, pending), 'resolve-failed', 'a cancel that throws on an abort')
  assert.equal(onAbort.code, 'ECANCELLED')
  assert.match(onAbort.why, /could not be cancelled/)
  assert.equal(late.dials.length + aborting.dials.length, 0)
})

// ── dial the checked address ──────────────────────────────────────────────────

test('connects to the checked address with no second lookup', async () => {
  const w = world({ v4: [PUBLIC_V4, PUBLIC_V4_B], v6: [PUBLIC_V6] })
  const upstream = createUpstream(w.deps)
  const result = await upstream.request(allow(), GET)
  assert.equal(result.ok, true)
  if (!result.ok) return
  assert.equal(result.address, PUBLIC_V4)
  assert.equal(result.response.statusCode, 200)
  assert.equal(await bodyOf(result.response), 'ok')

  // One resolver, both families once, the interface list read after the
  // answers and before the dial, and one dial, to the first checked answer.
  assert.deepEqual(w.steps, ['resolver', 'resolve4 github.com', 'resolve6 github.com', 'interfaces', `dial ${PUBLIC_V4}`])
  const [dialled] = w.dials
  assert.ok(dialled !== undefined)
  assert.equal(dialled.host, PUBLIC_V4)

  // The lookup it carries refuses, and asks nothing of any resolver: even a
  // net that did look the host up could not get another address.
  const second = await new Promise<{ err: NodeJS.ErrnoException | null; address: unknown }>((resolve) =>
    dialled.lookup('github.com', {}, (err, address) => resolve({ err, address })),
  )
  assert.equal(second.err?.code, 'ERR_EGRESS_SECOND_LOOKUP')
  assert.equal(second.address, '')
  assert.equal(w.steps.length, 5)

  // What the host saw: the request as asked, Host the decided host, sent
  // once, and Connection close.
  assert.equal(w.seen.length, 1)
  const [seen] = w.seen
  assert.ok(seen !== undefined)
  assert.equal(seen.method, 'GET')
  assert.equal(seen.url, GET.path)
  assert.deepEqual(seen.headers, { host: 'github.com', 'user-agent': 'git/2.47.0', accept: '*/*', connection: 'close' })
  assert.equal(seen.rawHeaders.filter((_, i) => i % 2 === 0 && seen.rawHeaders[i]?.toLowerCase() === 'host').length, 1)

  // With no A record, the AAAA answer is the one dialled.
  const v6 = world({ v4: coded('ENODATA'), v6: [PUBLIC_V6] })
  const viaV6 = await createUpstream(v6.deps).request(allow(), GET)
  assert.equal(viaV6.ok && viaV6.address, PUBLIC_V6)
  assert.deepEqual(v6.dials.map((d) => d.host), [PUBLIC_V6])
})

test('tls options carry servername=host and rejectUnauthorized=true', async () => {
  const api = EgressHost.parse('api.github.com')
  const w = world()
  const upstream = createUpstream(w.deps)
  for (const host of [GITHUB, api]) assert.equal((await upstream.request(allow(host), GET)).ok, true)
  assert.equal(w.dials.length, 2)
  for (const [i, host] of [GITHUB, api].entries()) {
    const options = w.dials[i]
    assert.ok(options !== undefined)
    // Exactly these, and nothing that would widen them: no ca, cert, key,
    // pfx, secureContext, session, socket, agent or timeout.
    assert.deepEqual(Object.keys(options).sort(), [
      'ALPNProtocols', 'checkServerIdentity', 'host', 'lookup', 'minVersion', 'port', 'rejectUnauthorized', 'servername',
    ])
    assert.equal(options.host, PUBLIC_V4)
    assert.equal(options.port, 443)
    assert.equal(options.servername, host)
    assert.equal(options.rejectUnauthorized, true)
    assert.equal(options.checkServerIdentity, checkServerIdentity)
    assert.equal(options.minVersion, 'TLSv1.2')
    assert.deepEqual(options.ALPNProtocols, ['http/1.1'])
  }

  // A socket that finishes the handshake unverified is destroyed before a
  // byte of the request is written; so is one whose handshake fails.
  const handshakes: ReadonlyArray<readonly [Handshake, UpstreamRefusal, string | undefined]> = [
    ['unverified', 'unverified', undefined],
    [coded('CERT_HAS_EXPIRED'), 'connect-failed', 'CERT_HAS_EXPIRED'],
    [coded('ERR_TLS_CERT_ALTNAME_INVALID'), 'connect-failed', 'ERR_TLS_CERT_ALTNAME_INVALID'],
    [coded('ECONNREFUSED'), 'connect-failed', 'ECONNREFUSED'],
    ['closed', 'connect-failed', undefined],
  ]
  for (const [handshake, reason, code] of handshakes) {
    const failing = world({ handshake })
    const refusal = refusedAs(await createUpstream(failing.deps).request(allow(), GET), reason, String(handshake))
    assert.equal(refusal.code, code)
    const [d] = failing.dialled
    assert.ok(d !== undefined)
    await closed(d.socket)
    await turn()
    assert.deepEqual(d.raw, [], `${String(handshake)}: a request byte was written`)
    assert.equal(failing.seen.length, 0)
  }

  // A dialer that throws is a failed dial.
  const throwing = world({ dial: () => { throw coded('EMFILE') } })
  assert.equal(refusedAs(await createUpstream(throwing.deps).request(allow(), GET), 'connect-failed').code, 'EMFILE')
})

/** The SNI names and ALPN protocols of one TLS ClientHello record, or undefined until all of it has arrived. */
function clientHello(bytes: Buffer): { readonly length: number; readonly sni: string[]; readonly alpn: string[] } | undefined {
  if (bytes.length < 5) return undefined
  assert.equal(bytes.readUInt8(0), 22, 'the first record is not a handshake record')
  const length = 5 + bytes.readUInt16BE(3)
  if (bytes.length < length) return undefined
  const hello = bytes.subarray(5, length)
  assert.equal(hello.readUInt8(0), 1, 'the first handshake message is not a ClientHello')
  let at = 4 + 2 + 32 // the message header, legacy_version, random
  at += 1 + hello.readUInt8(at) // legacy_session_id
  at += 2 + hello.readUInt16BE(at) // cipher_suites
  at += 1 + hello.readUInt8(at) // legacy_compression_methods
  const end = at + 2 + hello.readUInt16BE(at)
  at += 2
  const sni: string[] = []
  const alpn: string[] = []
  while (at < end) {
    const type = hello.readUInt16BE(at)
    const body = hello.subarray(at + 4, at + 4 + hello.readUInt16BE(at + 2))
    if (type === 0) {
      for (let p = 2; p < body.length; p += 3 + body.readUInt16BE(p + 1)) {
        sni.push(body.subarray(p + 3, p + 3 + body.readUInt16BE(p + 1)).toString('latin1'))
      }
    }
    if (type === 16) {
      for (let p = 2; p < body.length; p += 1 + body.readUInt8(p)) alpn.push(body.subarray(p + 1, p + 1 + body.readUInt8(p)).toString('latin1'))
    }
    at += 4 + body.length
  }
  return { length, sni, alpn }
}

test('the real tls.connect, given these options, sends one ClientHello naming the host and offering only http/1.1, looks nothing up, and writes no request byte to a peer it cannot verify', async (t: TestContext) => {
  // A loopback peer that reads the ClientHello and hangs up, as a peer that
  // has no certificate for the name would. Only the destination is swapped,
  // so the real stack can be reached at all; every other option is the
  // upstream's own, and the lookup it carries is counted, not replaced.
  const received: Buffer[] = []
  const peer = createNetServer((s) => {
    s.on('error', () => undefined)
    s.on('data', (chunk: Buffer) => {
      received.push(chunk)
      if (clientHello(Buffer.concat(received)) !== undefined) s.destroy()
    })
  })
  await new Promise<void>((resolve) => peer.listen(0, '127.0.0.1', resolve))
  t.after(() => peer.close())
  const { port } = peer.address() as AddressInfo
  let lookups = 0
  const w = world({
    dial: (options) =>
      tlsConnect({
        ...options,
        host: '127.0.0.1',
        port,
        lookup: (hostname, lookupOptions, callback) => {
          lookups++
          options.lookup(hostname, lookupOptions, callback)
        },
      }),
  })
  const refusal = refusedAs(await createUpstream(w.deps).request(allow(), { ...GET, headers: { ...GET.headers, authorization: 'Bearer stand-in-not-a-credential' } }), 'connect-failed')
  assert.equal(refusal.code, 'ECONNRESET')
  assert.equal(lookups, 0)

  const bytes = Buffer.concat(received)
  const hello = clientHello(bytes)
  assert.ok(hello !== undefined)
  assert.deepEqual(hello.sni, ['github.com'])
  assert.deepEqual(hello.alpn, ['http/1.1'])
  // The ClientHello, and nothing after it: no request line, no header.
  assert.equal(bytes.length, hello.length)
  for (const text of ['GET ', 'info/refs', 'stand-in-not-a-credential', 'user-agent']) assert.equal(bytes.includes(text), false, text)
})

// ── the Mac's own addresses ───────────────────────────────────────────────────

test("an answer that is one of the Mac's own interface addresses is refused, compared by value and by what it carries, and read when the request dials, never cached", async () => {
  // Before the Mac holds the address, it is a stranger's and is dialled.
  let listed: NodeJS.Dict<NetworkInterfaceInfo[]> = PLAIN_MAC
  const w = world({ v4: [OWN_V4], interfaces: () => listed })
  const upstream = createUpstream(w.deps)
  assert.equal((await upstream.request(allow(), GET)).ok, true)

  // It gains it (DHCP, a VPN, a public address on an interface): the very
  // next request reads the list again, and refuses.
  listed = { ...PLAIN_MAC, en1: [iface(OWN_V4)] }
  const refusal = refusedAs(await upstream.request(allow(), GET), 'host-address')
  assert.equal(refusal.address, OWN_V4)
  assert.equal(w.dials.length, 1)
  const second = w.steps.slice(w.steps.lastIndexOf('resolver'))
  assert.deepEqual(second, ['resolver', 'resolve4 github.com', 'resolve6 github.com', 'interfaces'])

  // By value and by what an IPv6 answer carries, as addr.ts judges it.
  const holding = (...addresses: string[]) => () => ({ ...PLAIN_MAC, en1: addresses.map(iface) })
  const cases: ReadonlyArray<readonly [string, readonly string[], readonly string[], () => NodeJS.Dict<NetworkInterfaceInfo[]>]> = [
    ['an IPv6 address in another spelling', [], [OWN_V6], holding('2a02:8010:0:0:0:0:0:1')],
    ['an IPv6 address in upper case', [], ['2A02:8010::1'], holding(OWN_V6)],
    ['a public A beside the Mac\'s own AAAA', [PUBLIC_V4], [OWN_V6], holding(OWN_V6)],
    ['IPv4-mapped', [], [`::ffff:${OWN_V4}`], holding(OWN_V4)],
    ['NAT64', [], [`64:ff9b::${OWN_V4_HEX}`], holding(OWN_V4)],
    ['6to4', [], [`2002:${OWN_V4_HEX}::1`], holding(OWN_V4)],
    // Teredo's client field is inverted: f7f7:f7f7 carries 8.8.8.8, public.
    ['the Teredo server', [], [`2001:0:${OWN_V4_HEX}:0:0:f7f7:f7f7`], holding(OWN_V4)],
  ]
  for (const [label, v4, v6, interfaces] of cases) {
    const each = world({ v4, v6, interfaces })
    refusedAs(await createUpstream(each.deps).request(allow(), GET), 'host-address', label)
    assert.equal(each.dials.length, 0, label)
  }
  // The control for the forms that carry an IPv4 address: the same answers,
  // with the Mac not holding it, are dialled.
  for (const answer of [`::ffff:${OWN_V4}`, `64:ff9b::${OWN_V4_HEX}`, `2002:${OWN_V4_HEX}::1`]) {
    const each = world({ v4: [], v6: [answer] })
    assert.equal((await createUpstream(each.deps).request(allow(), GET)).ok, true, answer)
  }

  // A zone names the link, not the address: a list with one is still read.
  const zoned = world({ interfaces: () => ({ en0: [{ ...iface('fe80::1'), address: 'fe80::1%en0' }] }) })
  assert.equal((await createUpstream(zoned.deps).request(allow(), GET)).ok, true)

  // Fail closed: a list that cannot be read, or that holds no address.
  for (const [label, interfaces] of [
    ['a read that throws', () => { throw coded('EPERM') }],
    ['an entry that is no address', () => ({ en0: [{ ...iface('192.168.1.2'), address: 'en0' }] })],
    ['an entry with no address', () => ({ en0: [{ ...iface('192.168.1.2'), address: undefined as unknown as string }] })],
    // A real list always holds loopback: one that yields no address is a read
    // that went wrong, and the Mac's own global addresses would go unchecked.
    ['an empty list', () => ({})],
    ['an interface with no entries', () => ({ en0: [] })],
    ['an interface listed as undefined', () => ({ en0: undefined })],
  ] as const) {
    const each = world({ interfaces })
    refusedAs(await createUpstream(each.deps).request(allow(), GET), 'interfaces-unreadable', label)
    assert.equal(each.dials.length, 0, label)
  }

  // What the comparison reads: the IPv4 an IPv6 answer carries, frozen.
  assert.deepEqual(carriedAddresses(`::ffff:${OWN_V4}`), [{ via: 'ipv4-mapped', address: OWN_V4 }])
  assert.deepEqual(carriedAddresses(`2001:0:${OWN_V4_HEX}:0:0:f7f7:f7f7`), [
    { via: 'teredo-server', address: OWN_V4 },
    { via: 'teredo-client', address: '8.8.8.8' },
  ])
  for (const none of [OWN_V4, OWN_V6, 'fe80::1%en0', 'github.com']) assert.deepEqual(carriedAddresses(none), [], none)
  for (const a of [`64:ff9b::${OWN_V4_HEX}`, OWN_V4]) {
    const carried = carriedAddresses(a)
    assert.equal(Object.isFrozen(carried), true, a)
    for (const c of carried) assert.equal(Object.isFrozen(c), true, a)
  }
})

// ── no agent, no pooling, no redirects ────────────────────────────────────────

test('one request is one resolution, one dial and one socket: a redirect is handed back, never followed, and the socket ends with its response', async () => {
  const w = world({
    serve: (_req, res) => res.writeHead(302, { location: 'https://evil.example/steal' }).end('moved'),
  })
  const upstream = createUpstream(w.deps)
  const first = await upstream.request(allow(), GET)
  assert.equal(first.ok, true)
  if (!first.ok) return
  assert.equal(first.response.statusCode, 302)
  assert.equal(first.response.headers.location, 'https://evil.example/steal')
  assert.equal(await bodyOf(first.response), 'moved')
  const [one] = w.dialled
  assert.ok(one !== undefined)
  await closed(one.socket)
  await turn()
  // Nothing went to the Location: one resolution, one dial, one request.
  assert.equal(w.steps.filter((s) => s === 'resolver').length, 1)
  assert.equal(w.dials.length, 1)
  assert.equal(w.seen.length, 1)

  // A second request resolves and dials again: no answer and no socket is kept.
  const second = await upstream.request(allow(), GET)
  assert.equal(second.ok, true)
  if (second.ok) await bodyOf(second.response)
  assert.equal(w.steps.filter((s) => s === 'resolver').length, 2)
  assert.equal(w.dials.length, 2)
  const two = w.dialled[1]
  assert.ok(two !== undefined)
  assert.notEqual(two.socket, one.socket)
  await closed(two.socket)

  // A response abandoned half-read ends its socket too: nothing is left open
  // to carry a second request.
  const half = world({ serve: (_req, res) => res.writeHead(200, { 'content-length': '10' }).write('half') })
  const abandoned = await createUpstream(half.deps).request(allow(), GET)
  assert.equal(abandoned.ok, true)
  if (!abandoned.ok) return
  abandoned.response.on('error', () => undefined)
  abandoned.response.destroy()
  const [halfSocket] = half.dialled
  assert.ok(halfSocket !== undefined)
  await closed(halfSocket.socket)

  // A body is streamed to the host as given.
  const post = world({ serve: (_req, res) => res.writeHead(200).end() })
  const body = 'x'.repeat(100_000)
  const upload: UpstreamHead = { method: 'POST', path: '/aos/fixture.git/git-upload-pack', headers: { 'content-type': 'application/x-git-upload-pack-request' } }
  const posted = await createUpstream(post.deps).request(
    allowFor(upload, { length: body.length }),
    upload,
    { body: { stream: Readable.from([Buffer.from(body.slice(0, 50_000)), Buffer.from(body.slice(50_000))]), length: body.length } },
  )
  assert.equal(posted.ok, true)
  await until('the body to arrive', () => post.seen.length === 1)
  assert.equal(post.seen[0]?.body, body)
  assert.equal(post.seen[0]?.headers['content-length'], String(body.length))
})

test('the head cannot set Host, Connection, framing or a hop-by-hop header, name one header twice, or carry a method or path HTTP would read another way', async () => {
  const heads: ReadonlyArray<readonly [string, UpstreamHead]> = [
    ...['Host', 'host', 'HOST', 'Connection', 'Content-Length', 'content-length', 'Keep-Alive', 'Proxy-Connection', 'Proxy-Authorization', 'Transfer-Encoding', 'TE', 'Trailer', 'Upgrade'].map(
      (name) => [name, { ...GET, headers: { [name]: 'x' } }] as const,
    ),
    ['Authorization in two cases', { ...GET, headers: { Authorization: 'Bearer one', authorization: 'Bearer two' } }],
    ['a value with CRLF', { ...GET, headers: { accept: '*/*\r\nX-Injected: 1' } }],
    ['a name with a space', { ...GET, headers: { 'x bad': '1' } }],
    ['a name with a colon', { ...GET, headers: { 'x:bad': '1' } }],
    ['a value that is not a string', { ...GET, headers: { accept: 1 as unknown as string } }],
    ['a lower-case method', { ...GET, method: 'get' }],
    ['CONNECT', { ...GET, method: 'CONNECT' }],
    ['a method with a space', { ...GET, method: 'GET /x HTTP/1.1\r\n' }],
    ['an empty method', { ...GET, method: '' }],
    ['an absolute-form path', { ...GET, path: 'https://evil.example/' }],
    ['an authority-form path', { ...GET, path: 'evil.example:443' }],
    ['an empty path', { ...GET, path: '' }],
    ['a path with a space', { ...GET, path: '/a b' }],
    ['a path with CRLF', { ...GET, path: '/a\r\nHost: evil.example' }],
    ['a path with a byte outside ASCII', { ...GET, path: '/é' }],
    ['a path over the bound', { ...GET, path: `/${'a'.repeat(8192)}` }],
  ]
  for (const [label, head] of heads) {
    const w = world()
    refusedAs(await createUpstream(w.deps).request(allow(), head), 'head', label)
    assert.deepEqual(w.steps, [], `${label}: something was asked before the refusal`)
  }
  // Frozen: read on every request.
  assert.equal(Object.isFrozen(UPSTREAM_OWNED_HEADERS), true)
  assert.throws(() => (UPSTREAM_OWNED_HEADERS as string[]).splice(0), TypeError)
  assert.equal(Object.isFrozen(UPSTREAM_REFUSALS), true)

  // What it does admit: any other header, a __proto__ named one included.
  const w = world()
  const ok = await createUpstream(w.deps).request(allow(), { ...GET, headers: { 'git-protocol': 'version=2', ['__proto__']: 'kept' } })
  assert.equal(ok.ok, true)
  await until('the request to arrive', () => w.seen.length === 1)
  assert.equal(w.seen[0]?.headers['git-protocol'], 'version=2')
  assert.equal(w.seen[0]?.rawHeaders.includes('__proto__'), true)
})

// ── one request, framed here ──────────────────────────────────────────────────

const POST: UpstreamHead = {
  method: 'POST',
  path: '/aos/fixture.git/git-upload-pack',
  headers: { 'content-type': 'application/x-git-upload-pack-request' },
}
/** A second request, as a body that runs past its declared length would carry it. */
const SMUGGLED = 'GET /smuggled HTTP/1.1\r\nHost: github.com\r\n\r\n'

/** The bytes the far end read after the request head. */
const afterHead = (d: Dialled | undefined): string => {
  const text = wire(d)
  const end = text.indexOf('\r\n\r\n')
  return end === -1 ? '' : text.slice(end + 4)
}

test('a body is held to the length it declares: no byte past it reaches the host, where it would be read as a second request, and one that ends short fails', async () => {
  // The upstream sets Content-Length from the declared length, never from the
  // head. A body that runs past it, by a chunk of its own or inside one with
  // the body, destroys the request before any byte of that chunk is written.
  const cases: ReadonlyArray<readonly [string, readonly string[]]> = [
    ['hello, then a request in a chunk of its own', ['hello', SMUGGLED]],
    ['hello and a request in one chunk', [`hello${SMUGGLED}`]],
    ['a 30-byte body in one chunk', ['x'.repeat(30)]],
    // One byte over, in a chunk of its own and inside one with the body: the
    // off-by-one a bound like this invites, which would put the sixth byte on
    // the verified connection before the end of the body was seen.
    ['hello, then one byte more in a chunk of its own', ['hello', 'X']],
    ['hello and one byte more in one chunk', ['helloX']],
  ]
  for (const [label, chunks] of cases) {
    const w = world()
    const stream = bodyStream(...chunks)
    const refusal = refusedAs(await within(label, 2_000, createUpstream(w.deps).request(allowFor(POST, { length: 5 }), POST, { body: { stream, length: 5 } })), 'body-length', label)
    assert.equal(refusal.why.includes('smuggled'), false, label)
    const [d] = w.dialled
    assert.ok(d !== undefined, label)
    await closed(d.socket)
    await turn()
    assert.ok(afterHead(d).length <= 5, `${label}: ${String(afterHead(d).length)} body bytes reached the host`)
    assert.equal(wire(d).includes('smuggled'), false, `${label}: the second request reached the host`)
    assert.equal(wire(d).includes('X'), false, `${label}: the byte past the declared length reached the host`)
    assert.equal(w.seen.some((seen) => seen.url === '/smuggled'), false, label)
    // A head, when one was written before the overflow, declared what was asked.
    if (wire(d) !== '') assert.match(wire(d), /\r\ncontent-length: 5\r\n/i, label)
    assert.equal(stream.destroyed, true, label)
  }

  // Short: the host waits for bytes that never come, so the request is
  // destroyed rather than left for the idle timeout, and the host never sees
  // a whole request.
  const short = world()
  refusedAs(await within('the short body', 2_000, createUpstream(short.deps).request(allowFor(POST, { length: 10 }), POST, { body: { stream: bodyStream('hello'), length: 10 } })), 'body-length')
  const [s] = short.dialled
  assert.ok(s !== undefined)
  await closed(s.socket)
  await turn()
  assert.equal(short.seen.length, 0)

  // Exactly the declared length, in any number of chunks, and none: sent as
  // given, with the upstream's Content-Length.
  for (const [label, chunks, length] of [['three chunks', ['he', 'll', 'o'], 5], ['an empty body', [], 0]] as const) {
    const w = world({ serve: (_req, res) => res.writeHead(204).end() })
    const result = await within(label, 2_000, createUpstream(w.deps).request(allowFor(POST, { length }), POST, { body: { stream: bodyStream(...chunks), length } }))
    assert.equal(result.ok, true, label)
    await until('the body to arrive', () => w.seen.length === 1)
    assert.equal(w.seen[0]?.body, chunks.join(''), label)
    assert.equal(w.seen[0]?.headers['content-length'], String(length), label)
    assert.equal(w.seen[0]?.headers['transfer-encoding'], undefined, label)
  }

  // A declared length that is no whole number of bytes, and a body that is
  // no stream, are refused before anything is resolved, and the stream is
  // disposed of.
  for (const length of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, '5' as unknown as number]) {
    const w = world()
    const stream = bodyStream('hello')
    refusedAs(await createUpstream(w.deps).request(allowFor(POST, { length: 5 }), POST, { body: { stream, length } }), 'head', String(length))
    assert.deepEqual(w.steps, [], String(length))
    assert.equal(stream.destroyed, true, String(length))
  }
  const notAStream = world()
  refusedAs(await createUpstream(notAStream.deps).request(allowFor(POST, { length: 5 }), POST, { body: { stream: 'hello' as unknown as Readable, length: 5 } }), 'head')
  assert.deepEqual(notAStream.steps, [])
})

test('a body that declares no length is sent chunked, framed by node:http whatever the method', async () => {
  // With neither a length nor chunked framing, node:http would write a GET's
  // body bare after its head, where the host reads it as a second request.
  for (const head of [GET, POST]) {
    const w = world({ serve: (_req, res) => res.writeHead(204).end() })
    const result = await within(head.method, 2_000, createUpstream(w.deps).request(allowFor(head, {}), head, { body: { stream: bodyStream('ab', SMUGGLED) } }))
    assert.equal(result.ok, true, head.method)
    if (result.ok) await bodyOf(result.response)
    await until('the body to arrive', () => w.seen.length === 1)
    assert.equal(w.seen[0]?.headers['transfer-encoding'], 'chunked', head.method)
    assert.equal(w.seen[0]?.headers['content-length'], undefined, head.method)
    assert.equal(w.seen[0]?.body, `ab${SMUGGLED}`, head.method)
    const [d] = w.dialled
    assert.ok(d !== undefined, head.method)
    await closed(d.socket)
    await turn()
    // One request: the second one is body, inside a chunk's frame.
    assert.equal(w.seen.length, 1, head.method)
    assert.ok(afterHead(d).startsWith('2\r\nab\r\n'), head.method)
  }
})

test('the request sent is the one checked: a head changed after request() is called changes nothing on the wire', async () => {
  // Mutated as soon as request() returns, while it resolves and dials.
  const w = world()
  const headers: Record<string, string> = { accept: '*/*' }
  const head = { method: 'GET', path: '/aos/fixture.git/info/refs?service=git-upload-pack', headers }
  const pending = createUpstream(w.deps).request(allowFor(head), head)
  head.method = 'DELETE'
  head.path = '/mutated'
  headers['accept'] = 'text/evil'
  headers['x-late'] = '1'
  assert.equal((await pending).ok, true)
  await until('the request to arrive', () => w.seen.length === 1)
  const [seen] = w.seen
  assert.equal(seen?.method, 'GET')
  assert.equal(seen?.url, '/aos/fixture.git/info/refs?service=git-upload-pack')
  assert.equal(seen?.headers['accept'], '*/*')
  assert.equal(seen?.headers['x-late'], undefined)

  // A head whose fields answer one thing when checked and another later.
  let reads = 0
  const shifting: UpstreamHead = {
    get method() {
      return reads++ === 0 ? 'GET' : 'DELETE'
    },
    get path() {
      return reads > 1 ? '/mutated' : '/checked'
    },
    headers: { accept: '*/*' },
  }
  const v = world()
  // Minted over what decide() saw on its one read; the upstream reads its own once, and they agree.
  const judged = mintEgressAllow({ host: GITHUB, port: 443, method: 'GET', path: '/checked' })
  assert.equal((await createUpstream(v.deps).request(judged, shifting)).ok, true)
  await until('the request to arrive', () => v.seen.length === 1)
  assert.equal(v.seen[0]?.method, 'GET')
  assert.equal(v.seen[0]?.url, '/checked')
})

test('a refused request disposes of its body, whatever refused it', async () => {
  // The body is the upstream's from the call on, so a refusal never leaves
  // the caller's stream paused for the life of its flow.
  const scenarios: ReadonlyArray<readonly [UpstreamRefusal, WorldOptions, UpstreamTarget, UpstreamHead, ((w: World) => void)?]> = [
    ['not-decided', {}, forged({ verdict: 'deny', host: GITHUB, port: 443 }), POST],
    ['not-decided', {}, forged({ verdict: 'allow', host: GITHUB, port: 443 }), POST],
    ['not-decided', {}, allowFor(GET), POST],
    ['not-a-host', {}, allowFor(POST, { length: 5 }, 'GitHub.com' as EgressHost), POST],
    ['port', {}, allowFor(POST, { length: 5 }, GITHUB, 80), POST],
    ['head', {}, allowFor(POST, { length: 5 }), { ...POST, headers: { Host: 'evil.example' } }],
    ['resolve-failed', { v4: coded('ESERVFAIL') }, allowFor(POST, { length: 5 }), POST],
    ['resolve-timeout', { v4: 'hang', connectTimeoutMs: 20 }, allowFor(POST, { length: 5 }), POST],
    ['no-address', { v4: [] }, allowFor(POST, { length: 5 }), POST],
    ['denied-address', { v4: ['192.168.5.2'] }, allowFor(POST, { length: 5 }), POST],
    ['host-address', { v4: [OWN_V4], interfaces: () => ({ en1: [iface(OWN_V4)] }) }, allowFor(POST, { length: 5 }), POST],
    ['interfaces-unreadable', { interfaces: () => { throw coded('EPERM') } }, allowFor(POST, { length: 5 }), POST],
    ['connect-failed', { handshake: coded('ECONNREFUSED') }, allowFor(POST, { length: 5 }), POST],
    ['connect-timeout', { handshake: 'never', connectTimeoutMs: 20 }, allowFor(POST, { length: 5 }), POST],
    ['unverified', { handshake: 'unverified' }, allowFor(POST, { length: 5 }), POST],
    ['upstream-failed', { handshake: 'verified-then-closed' }, allowFor(POST, { length: 5 }), POST],
    ['idle-timeout', { serve: () => undefined }, allowFor(POST, { length: 5 }), POST, (w) => {
      void until('the request to arrive', () => w.seen.length === 1).then(() => w.dialled[0]?.idle?.fire())
    }],
  ]
  for (const [reason, options, target, head, drive] of scenarios) {
    const w = world(options)
    const stream = bodyStream('hello')
    const pending = createUpstream(w.deps).request(target, head, { body: { stream, length: 5 } })
    drive?.(w)
    refusedAs(await within(reason, 2_000, pending), reason, reason)
    assert.equal(stream.destroyed, true, `${reason}: the body was left undisposed`)
  }
  const aborted = new AbortController()
  aborted.abort()
  const stream = bodyStream('hello')
  refusedAs(await createUpstream(world().deps).request(allowFor(POST, { length: 5 }), POST, { body: { stream, length: 5 }, signal: aborted.signal }), 'aborted')
  assert.equal(stream.destroyed, true, 'aborted: the body was left undisposed')
})

test('request() never rejects: a target, head or options that is no record or whose fields throw, and a dialer that returns no socket or one that throws, are refusals, and the body is disposed of', async () => {
  // A rejection the session did not await would end the kernel. The target
  // is judged before anything of it is read, so no getter or trap of a
  // caller's runs for it.
  let ran = 0
  const trap = (): never => {
    ran++
    throw new Error('a getter or trap of the caller ran')
  }
  const getterTarget = forged({ get verdict(): string { return trap() }, get host(): string { return trap() }, port: 443 })
  const trapTarget = forged(new Proxy({}, { get: trap, has: trap, getOwnPropertyDescriptor: trap, getPrototypeOf: trap, ownKeys: trap }))
  const thrower = (code: string) => (): never => {
    throw coded(code)
  }
  type Case = readonly [label: string, target: unknown, head: unknown, options: (stream: Readable) => unknown, reason: UpstreamRefusal, disposed: boolean]
  const body = (stream: Readable): UpstreamCallOptions => ({ body: { stream, length: 5 } })
  const cases: readonly Case[] = [
    ['a null target', null, POST, body, 'not-decided', true],
    ['a target that is a string', 'allow', POST, body, 'not-decided', true],
    ['a target whose verdict and host getters throw', getterTarget, POST, body, 'not-decided', true],
    ['a Proxy whose every trap throws', trapTarget, POST, body, 'not-decided', true],
    ['a null head', allowFor(POST, { length: 5 }), null, body, 'head', true],
    ['a head whose method getter throws', allowFor(POST, { length: 5 }), { get method(): string { return thrower('EMETHOD')() }, path: POST.path, headers: {} }, body, 'head', true],
    ['a head whose header record throws on reading its entries', allowFor(POST, { length: 5 }), { ...POST, headers: new Proxy({}, { ownKeys: thrower('EKEYS') }) }, body, 'head', true],
    ['null options', allow(), GET, () => null, 'head', false],
    ['options whose body getter throws', allow(), GET, () => ({ get body(): unknown { return thrower('EBODY')() } }), 'head', false],
    ['a null body', allow(), GET, () => ({ body: null }), 'head', false],
    ['a body whose length getter throws', allowFor(POST, { length: 5 }), POST, (stream) => ({ body: { stream, get length(): number { return thrower('ELENGTH')() } } }), 'head', true],
    ['a signal that is no AbortSignal', allowFor(POST, { length: 5 }), POST, (stream) => ({ body: { stream, length: 5 }, signal: { aborted: false } }), 'head', true],
    ['options whose signal getter throws', allowFor(POST, { length: 5 }), POST, (stream) => ({ body: { stream, length: 5 }, get signal(): unknown { return thrower('ESIGNAL')() } }), 'head', true],
  ]
  for (const [label, target, head, options, reason, disposed] of cases) {
    const w = world()
    const stream = bodyStream('hello')
    const result = await createUpstream(w.deps).request(target as UpstreamTarget, head as UpstreamHead, options(stream) as UpstreamCallOptions)
    refusedAs(result, reason, label)
    assert.deepEqual(w.steps, [], `${label}: something was asked before the refusal`)
    if (disposed) assert.equal(stream.destroyed, true, `${label}: the body was left undisposed`)
  }
  assert.equal(ran, 0, 'a getter or trap of a target ran')

  // A dialer that returns no socket: a failed dial, not a TypeError.
  for (const [label, made] of [['undefined', undefined], ['a plain object', {}], ['a Duplex with no setTimeout', new PassThrough()]] as const) {
    const w = world({ dial: () => made as unknown as UpstreamSocket })
    const stream = bodyStream('hello')
    const refusal = refusedAs(await createUpstream(w.deps).request(allowFor(POST, { length: 5 }), POST, body(stream) as UpstreamCallOptions), 'connect-failed', label)
    assert.match(refusal.why, /returned no socket/, label)
    assert.equal(stream.destroyed, true, `${label}: the body was left undisposed`)
  }

  // A socket that throws once it is driven: refused for where the throw
  // landed, and the socket is destroyed with nothing written.
  const throwing = (patch: (socket: UpstreamSocket) => void) => (options: DialOptions): UpstreamSocket => {
    const socket = world().deps.dial(options)
    patch(socket)
    return socket
  }
  const sockets: ReadonlyArray<readonly [string, (socket: UpstreamSocket) => void, UpstreamRefusal, string]> = [
    // The fake sets authorized as the handshake ends: a setter keeps that from throwing.
    ['an authorized that throws', (socket) => Object.defineProperty(socket, 'authorized', { get: thrower('EPROTO'), set: () => undefined }), 'connect-failed', 'EPROTO'],
    ['a setTimeout that throws', (socket) => Object.assign(socket, { setTimeout: thrower('EBADF') }), 'upstream-failed', 'EBADF'],
  ]
  for (const [label, patch, reason, code] of sockets) {
    let dialled: UpstreamSocket | undefined
    const w = world({
      dial: (options) => {
        dialled = throwing(patch)(options)
        return dialled
      },
    })
    const stream = bodyStream('hello')
    const refusal = refusedAs(await within(label, 2_000, createUpstream(w.deps).request(allowFor(POST, { length: 5 }), POST, body(stream) as UpstreamCallOptions)), reason, label)
    assert.equal(refusal.code, code, label)
    assert.equal(dialled?.destroyed, true, `${label}: the socket was left open`)
    assert.equal(stream.destroyed, true, `${label}: the body was left undisposed`)
  }
})

test('the dependencies are read once, when the upstream is made: a caller that writes to its deps object afterwards changes nothing', async () => {
  const w = world({ idleTimeoutMs: 12_345, serve: () => undefined })
  const deps = { ...w.deps } as { -readonly [K in keyof UpstreamDeps]: UpstreamDeps[K] }
  const upstream = createUpstream(deps)
  // Afterwards: the idle bound turned off, the deadline shortened, and every
  // dependency swapped for one that would answer anything.
  let swapped = 0
  deps.idleTimeoutMs = 0
  deps.connectTimeoutMs = 1
  deps.resolver = () => {
    swapped++
    return { resolve4: async () => ['127.0.0.1'], resolve6: async () => [], cancel: () => undefined }
  }
  deps.interfaces = () => {
    swapped++
    return {}
  }
  deps.dial = () => {
    swapped++
    throw coded('EACCES')
  }
  const waiting = upstream.request(allow(), GET)
  await until('the request to arrive', () => w.seen.length === 1)
  const [d] = w.dialled
  assert.equal(d?.idle?.ms, 12_345)
  d?.idle?.fire()
  refusedAs(await waiting, 'idle-timeout')
  assert.equal(swapped, 0)
  assert.deepEqual(w.dials.map((o) => o.host), [PUBLIC_V4])

  // A dependency that is no function is refused when the upstream is made, not at its first request.
  for (const name of ['resolver', 'dial', 'interfaces'] as const) {
    assert.throws(() => createUpstream({ ...world().deps, [name]: undefined }), TypeError, name)
  }
})

test('no request leaves a listener on its signal: completed, refused before the dial, or refused in the exchange', async () => {
  // A session that keeps one signal for a whole grant would otherwise gather
  // one abort listener per request.
  const signal = new AbortController().signal
  const listeners = (): number => getEventListeners(signal, 'abort').length

  const done = world()
  const ok = await createUpstream(done.deps).request(allow(), GET, { signal })
  assert.equal(ok.ok, true)
  if (ok.ok) await bodyOf(ok.response)
  await closed(done.dialled[0]?.socket ?? new PassThrough())
  await turn()
  assert.equal(listeners(), 0, 'a completed request left a listener')

  refusedAs(await createUpstream(world({ v4: ['192.168.5.2'] }).deps).request(allow(), GET, { signal }), 'denied-address')
  assert.equal(listeners(), 0, 'a request refused before the dial left a listener')

  const quiet = world({ serve: () => undefined })
  const waiting = createUpstream(quiet.deps).request(allow(), GET, { signal })
  await until('the request to arrive', () => quiet.seen.length === 1)
  quiet.dialled[0]?.idle?.fire()
  refusedAs(await waiting, 'idle-timeout')
  await turn()
  assert.equal(listeners(), 0, 'a request refused in the exchange left a listener')
})

test('a body chunk that is not bytes fails the request in every framing, and never throws into whatever pushed it', async () => {
  // An objectMode body that pushes an object: node:http's own write would
  // throw it back into the push, which in the session is a mux data handler.
  for (const length of [undefined, 7] as const) {
    const label = length === undefined ? 'chunked' : 'declared'
    const w = world()
    const stream = new Readable({ objectMode: true, read: () => undefined })
    const pending = createUpstream(w.deps).request(allowFor(POST, length === undefined ? {} : { length }), POST, { body: length === undefined ? { stream } : { stream, length } })
    stream.push(Buffer.from('ab'))
    await until('the first chunk to arrive', () => wire(w.dialled[0]).includes('ab'))
    assert.doesNotThrow(() => stream.push({ not: 'bytes' }), label)
    const refusal = refusedAs(await within(label, 2_000, pending), 'head', label)
    assert.match(refusal.why, /not bytes/, label)
    assert.equal(stream.destroyed, true, label)
    assert.equal(w.seen.length, 0, label)
  }
  // Strings are bytes, in their encoding, as node:http would take them.
  const strings = world({ serve: (_req, res) => res.writeHead(204).end() })
  const ok = await createUpstream(strings.deps).request(allowFor(POST, {}), POST, { body: { stream: Readable.from(['he', 'llo']) } })
  assert.equal(ok.ok, true)
  await until('the body to arrive', () => strings.seen.length === 1)
  assert.equal(strings.seen[0]?.body, 'hello')
})

test("a refusal destroys only the stream it was handed: a session's own PassThrough, fed by pipe(), leaves the worker's request open for the session's answer", async () => {
  // E8's shape: the worker's request reaches an unlistened node:http server
  // over one flow, and the session sends its body upstream. A POST that
  // declares 10 bytes and has sent 5, refused (here, for a denied address).
  const answer = async (handOver: 'own' | 'worker'): Promise<{ readonly status: number | string | undefined; readonly workerSocketDestroyed: boolean | undefined; readonly refused: UpstreamRefusal | undefined }> => {
    const [workerEnd, kernelEnd] = duplexPair()
    let workerSocketDestroyed: boolean | undefined
    let reason: UpstreamRefusal | undefined
    let answered = false
    const server = createHttpServer((req, res) => {
      const stream = handOver === 'own' ? req.pipe(new PassThrough()) : req
      void createUpstream(world({ v4: ['192.168.5.2'] }).deps)
        .request(allowFor(POST, { length: 10 }), POST, { body: { stream, length: 10 } })
        .then((result) => {
          reason = result.ok ? undefined : result.reason
          workerSocketDestroyed = req.socket.destroyed
          // Drain what is left, then answer.
          req.resume()
          if (!res.destroyed) res.writeHead(502, { connection: 'close' }).end()
          answered = true
        })
    })
    server.on('clientError', () => undefined)
    server.emit('connection', kernelEnd)
    let status: number | string | undefined
    const req = httpRequest({ method: 'POST', path: '/aos/fixture.git/git-upload-pack', headers: { host: 'github.com', 'content-length': '10' }, createConnection: () => workerEnd })
    req.on('response', (res) => {
      res.resume()
      status = res.statusCode
    })
    req.on('error', (e: NodeJS.ErrnoException) => {
      status = e.code ?? 'no code'
    })
    req.write('hello')
    await until('the session to answer', () => answered)
    // Ample turns for a 502 written to a live socket to be read.
    for (let i = 0; i < 20 && status === undefined; i++) await turn()
    if (status === undefined) req.destroy()
    return { status, workerSocketDestroyed, refused: reason }
  }
  // The documented way: the worker reads the session's 502.
  assert.deepEqual(await answer('own'), { status: 502, workerSocketDestroyed: false, refused: 'denied-address' })
  // The hazard UpstreamCallOptions.body names: the worker's own request,
  // destroyed half-read, takes its socket with it, and the worker reads a
  // reset where it waited for a status.
  const handed = await answer('worker')
  assert.equal(handed.refused, 'denied-address')
  assert.equal(handed.workerSocketDestroyed, true)
  assert.notEqual(handed.status, 502)
})

// ── what the host answers ─────────────────────────────────────────────────────

test('a 101 to a request that asked for no upgrade fails the request rather than hanging it', async () => {
  // node:http destroys the socket and says nothing on the request: only the
  // upstream's own close listener settles it.
  const w = world({ raw: answering('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n') })
  const refusal = refusedAs(await within('the 101', 2_000, createUpstream(w.deps).request(allow(), GET)), 'upstream-failed')
  assert.equal(refusal.code, undefined)
  assert.equal(w.dialled[0]?.socket.destroyed, true)
})

/** Responses a lenient parser would guess at, and the code the strict one refuses each with. */
const AMBIGUOUS: ReadonlyArray<readonly [label: string, response: string, code: string]> = [
  ['Content-Length beside Transfer-Encoding', 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n', 'HPE_INVALID_TRANSFER_ENCODING'],
  ['a header value with a bare control byte', 'HTTP/1.1 200 OK\r\nX-Odd: a\x01b\r\nContent-Length: 2\r\n\r\nok', 'HPE_INVALID_HEADER_TOKEN'],
]

/** Each ambiguous response fails the request with its strict code; the same host, framing once, is read. */
async function strictParserHolds(): Promise<void> {
  for (const [label, response, code] of AMBIGUOUS) {
    const w = world({ raw: answering(response) })
    const refusal = refusedAs(await within(label, 2_000, createUpstream(w.deps).request(allow(), GET)), 'upstream-failed', label)
    assert.equal(refusal.code, code, label)
    assert.equal(w.dialled[0]?.socket.destroyed, true, label)
  }
  const plain = world({ raw: answering('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello') })
  const ok = await within('the plain response', 2_000, createUpstream(plain.deps).request(allow(), GET))
  assert.equal(ok.ok, true)
  if (ok.ok) assert.equal(await bodyOf(ok.response), 'hello')
}

/** What node:http makes of `response` when nothing is asked of its parser: the status it read, or its error's code. */
function bareRequest(response: string): Promise<number | string> {
  const [client, far] = duplexPair()
  far.on('error', () => undefined)
  answering(response)(far)
  return new Promise((resolve) => {
    const req = httpRequest({ method: 'GET', path: '/', headers: { host: 'github.com', connection: 'close' }, createConnection: () => client })
    req.on('response', (res) => {
      res.resume()
      resolve(res.statusCode ?? 0)
    })
    req.on('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? 'no code'))
    req.end()
  })
}

test("the host's response is read by the strict parser: ambiguous framing fails the request", async () => {
  // A lenient parser would pick one of the two framings, and a host (or
  // whatever sits in front of it) that picked the other would desynchronise
  // what the worker is handed.
  await strictParserHolds()
})

const UNDER_THE_FLAG = 'the parser stays strict in a node started with --insecure-http-parser'

test(UNDER_THE_FLAG, async () => {
  // Strict "whatever NODE_OPTIONS says" is a claim about a process this one
  // is not: npm test starts no node with the flag, and without it node:http
  // is strict anyway, so the option that makes the upstream strict is never
  // exercised. So this test runs itself again, alone, in a node started with
  // the flag, where it takes the first branch.
  if (process.execArgv.includes('--insecure-http-parser')) {
    // The flag is live here: node:http, asked nothing of its parser, reads
    // what the upstream must refuse.
    for (const [label, response] of AMBIGUOUS) assert.equal(await bareRequest(response), 200, `${label}: the flag did not make node:http lenient`)
    await strictParserHolds()
    return
  }
  const pattern = `^${UNDER_THE_FLAG.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&')}$`
  const result = spawnSync(
    process.execPath,
    ['--insecure-http-parser', '--import', 'tsx', '--test-reporter=tap', `--test-name-pattern=${pattern}`, fileURLToPath(import.meta.url)],
    {
      encoding: 'utf8',
      timeout: 60_000,
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        // Under a falsify run this process was admitted by its run id; a child it spawns belongs to the same run.
        ...(process.env['AOS_FALSIFY_RUN'] === undefined ? {} : { AOS_FALSIFY_RUN: process.env['AOS_FALSIFY_RUN'] }),
      },
    },
  )
  const printed = `${result.stdout}${result.stderr}`
  assert.equal(result.status, 0, printed)
  // The one test ran, under the flag, and passed: not zero tests, not skipped.
  assert.match(printed, /^# tests 1$/m, `the pattern no longer finds this test:\n${printed}`)
  assert.match(printed, /^# pass 1$/m, printed)
  assert.match(printed, /insecure HTTP parsing/i, 'the child did not run with the flag')
})

test('errors and a close that land between the handshake and the request refuse it, write nothing and end nothing', async () => {
  // Two errors on a socket that does not destroy itself: the first is the
  // handshake's leftover listener's, the second only the upstream's guard's.
  // With no guard it would be thrown into the event loop.
  const errors = world({ handshake: 'verified-then-two-errors' })
  const refusal = refusedAs(await within('the errored socket', 2_000, createUpstream(errors.deps).request(allow(), GET)), 'upstream-failed')
  assert.equal(refusal.code, 'ECONNRESET')
  const [e] = errors.dialled
  assert.equal(e?.socket.destroyed, true)
  await turn()
  assert.equal(wire(e), '')

  // A close with no abort and no error: node:http would wait on a socket that
  // has already closed, and the request would never settle.
  const closing = world({ handshake: 'verified-then-closed' })
  const gone = refusedAs(await within('the closed socket', 2_000, createUpstream(closing.deps).request(allow(), GET)), 'upstream-failed')
  assert.equal(gone.code, undefined)
  assert.equal(wire(closing.dialled[0]), '')
  assert.equal(closing.seen.length, 0)
})

test('errors on the socket after the response is handed over end nothing', async () => {
  const w = world({ serve: (_req, res) => res.writeHead(200, { 'content-length': '10' }).write('half') })
  const result = await within('the response', 2_000, createUpstream(w.deps).request(allow(), GET))
  assert.equal(result.ok, true)
  if (!result.ok) return
  const aborted = new Promise<void>((resolve) => result.response.once('aborted', () => resolve()))
  result.response.on('error', () => undefined)
  const [d] = w.dialled
  assert.ok(d !== undefined)
  // node:http reports each one on the request: a listener that heard only
  // the first would leave the second to end the kernel.
  assert.doesNotThrow(() => {
    d.socket.emit('error', coded('ECONNRESET'))
    d.socket.emit('error', coded('EPIPE'))
  })
  await within('the response to abort', 2_000, aborted)
  assert.equal(d.socket.destroyed, true)
})

// ── bounded in time ───────────────────────────────────────────────────────────

test('the connect deadline bounds resolving and the handshake together, and an abort ends a request at any stage', async (t: TestContext) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })

  // A resolver that never answers: cancelled at the deadline, nothing dialled.
  const hung = world({ v4: 'hang', connectTimeoutMs: 5_000 })
  let settled = false
  const resolving = createUpstream(hung.deps).request(allow(), GET).finally(() => {
    settled = true
  })
  await turn()
  t.mock.timers.tick(4_999)
  await turn()
  assert.equal(settled, false)
  t.mock.timers.tick(1)
  refusedAs(await resolving, 'resolve-timeout')
  assert.deepEqual(hung.steps, ['resolver', 'resolve4 github.com', 'resolve6 github.com', 'cancel'])

  // A handshake that never finishes: the socket is destroyed at the deadline.
  const silent = world({ handshake: 'never', connectTimeoutMs: 5_000 })
  const dialling = createUpstream(silent.deps).request(allow(), GET)
  await until('the dial', () => silent.dials.length === 1)
  t.mock.timers.tick(5_000)
  refusedAs(await dialling, 'connect-timeout')
  assert.equal(silent.dialled[0]?.socket.destroyed, true)
  assert.deepEqual(silent.dialled[0]?.raw, [])

  // Aborted while resolving, and while dialling.
  const resolvingAbort = new AbortController()
  const r = world({ v4: 'hang' })
  const pending = createUpstream(r.deps).request(allow(), GET, { signal: resolvingAbort.signal })
  await turn()
  resolvingAbort.abort()
  refusedAs(await pending, 'aborted')
  assert.equal(r.steps.at(-1), 'cancel')
  const dialAbort = new AbortController()
  const d = world({ handshake: 'never' })
  const dialPending = createUpstream(d.deps).request(allow(), GET, { signal: dialAbort.signal })
  await until('the dial', () => d.dials.length === 1)
  dialAbort.abort()
  refusedAs(await dialPending, 'aborted')
  assert.equal(d.dialled[0]?.socket.destroyed, true)
})

test('after the handshake the idle timeout ends a quiet socket, and an abort ends one mid-response', async () => {
  // The host takes the request and never answers.
  const quiet = world({ idleTimeoutMs: 12_345, serve: () => undefined })
  const waiting = createUpstream(quiet.deps).request(allow(), GET)
  await until('the request to arrive', () => quiet.seen.length === 1)
  const [d] = quiet.dialled
  assert.ok(d !== undefined)
  assert.equal(d.idle?.ms, 12_345)
  d.idle?.fire()
  refusedAs(await waiting, 'idle-timeout')
  assert.equal(d.socket.destroyed, true)

  // A response that stalls mid-body is ended by an abort: the socket goes,
  // and the response reads as aborted.
  const stalling = world({ serve: (_req, res) => res.writeHead(200, { 'content-length': '10' }).write('half') })
  const abort = new AbortController()
  const result = await createUpstream(stalling.deps).request(allow(), GET, { signal: abort.signal })
  assert.equal(result.ok, true)
  if (!result.ok) return
  const ended = new Promise<string>((resolve) => {
    result.response.on('aborted', () => resolve('aborted'))
    result.response.on('error', () => undefined)
  })
  abort.abort()
  assert.equal(await ended, 'aborted')
  assert.equal(stalling.dialled[0]?.socket.destroyed, true)

  // An abort that lands between the handshake and the request still ends it.
  const late = new AbortController()
  const lateWorld = world({
    dial: (options) => {
      const socket = world().deps.dial(options)
      // After the upstream's own handshake listener, which is attached as
      // soon as the dial returns: the handshake is done, then the abort lands.
      queueMicrotask(() => socket.once('secureConnect', () => late.abort()))
      return socket
    },
  })
  refusedAs(await createUpstream(lateWorld.deps).request(allow(), GET, { signal: late.signal }), 'aborted')
})

// ── the real dependencies, and what the module may reach ──────────────────────

test('the system dependencies are a node:dns Resolver per request, tls.connect and os.networkInterfaces, and every limit is a whole number of milliseconds', () => {
  const deps = systemUpstreamDeps({ connectTimeoutMs: 9_000, idleTimeoutMs: 30_000 })
  assert.equal(deps.dial, tlsConnect)
  assert.equal(deps.interfaces, networkInterfaces)
  const one = deps.resolver()
  const two = deps.resolver()
  assert.ok(one instanceof Resolver)
  assert.notEqual(one, two)
  one.cancel()
  two.cancel()
  assert.equal(Object.isFrozen(deps), true)

  for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 31]) {
    for (const limits of [{ connectTimeoutMs: bad, idleTimeoutMs: 1_000 }, { connectTimeoutMs: 1_000, idleTimeoutMs: bad }]) {
      assert.throws(() => systemUpstreamDeps(limits), TypeError, String(bad))
      assert.throws(() => createUpstream({ ...world().deps, ...limits }), TypeError, String(bad))
    }
  }
})

test('the system resolver gives up near the connect deadline: two tries, each a third of it', async (t: TestContext) => {
  // A DNS server on loopback, made here, that reads every query and answers
  // none: what c-ares does with the options the upstream gives it, counted.
  const server = createSocket('udp4')
  const queries: number[] = []
  server.on('message', () => queries.push(Date.now()))
  await new Promise<void>((resolve) => server.bind(0, '127.0.0.1', () => resolve()))
  t.after(() => server.close())
  const connectTimeoutMs = 600
  const resolver = systemUpstreamDeps({ connectTimeoutMs, idleTimeoutMs: 1_000 }).resolver()
  assert.ok(resolver instanceof Resolver)
  const loopback = `127.0.0.1:${String(server.address().port)}`
  resolver.setServers([loopback])
  // The query goes to this server and nowhere else.
  assert.deepEqual(resolver.getServers(), [loopback])
  const started = Date.now()
  const failure: unknown = await resolver.resolve4('github.com').then(() => undefined, (e: unknown) => e)
  const elapsed = Date.now() - started
  assert.equal((failure as { code?: unknown } | undefined)?.code, 'ETIMEOUT')
  // Two tries, not c-ares's four.
  assert.equal(queries.length, 2)
  // c-ares waits about a per-try timeout, then backs off, so it gives up
  // near the deadline; with its default timeout it would take seconds.
  assert.ok(elapsed >= connectTimeoutMs / 3, `gave up after ${String(elapsed)} ms`)
  assert.ok(elapsed <= 3 * connectTimeoutMs, `gave up after ${String(elapsed)} ms`)
})

test('upstream.ts imports only the node modules it names, no Agent, https or fetch, and nothing from src but host.ts, addr.ts and decision.ts', () => {
  const path = 'src/egress/upstream.ts'
  const source = ts.createSourceFile(path, readFileSync(`${REPO}/${path}`, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const imports: string[] = []
  const names = new Set<string>()
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const bindings = node.importClause?.namedBindings
      const named = bindings !== undefined && ts.isNamedImports(bindings) ? bindings.elements.map((e) => (e.propertyName ?? e.name).text) : ['<not named>']
      imports.push(`${node.moduleSpecifier.text}: ${named.join(' ')}`)
    }
    if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) imports.push('<re-export>')
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) imports.push('<import()>')
    if (ts.isIdentifier(node)) names.add(node.text)
    ts.forEachChild(node, visit)
  }
  visit(source)
  assert.deepEqual(imports, [
    'node:dns/promises: Resolver',
    'node:http: request validateHeaderName validateHeaderValue ClientRequest IncomingMessage',
    'node:net: BlockList isIPv4 isIPv6 LookupFunction',
    'node:os: networkInterfaces NetworkInterfaceInfo',
    'node:stream: pipeline Readable Transform Duplex TransformCallback',
    'node:tls: checkServerIdentity connect',
    './addr.js: addressDenial carriedAddresses AddressDenial',
    // The check, never the mint: only decide() mints an allow.
    './decision.js: EgressAllow',
    './host.js: parseEgressHost EgressHost',
  ])
  // No pool to draw a socket from, no client that follows a redirect, and no
  // way to the environment or a loader.
  for (const name of ['Agent', 'globalAgent', 'fetch', 'process', 'globalThis', 'require', 'eval', 'Function']) {
    assert.equal(names.has(name), false, `upstream.ts names ${name}`)
  }
})
