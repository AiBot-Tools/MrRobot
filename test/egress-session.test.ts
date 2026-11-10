// Egress plan E8 — the route-mode session (src/egress/session.ts): one
// container's channel, demuxed into flows, each request judged, recorded,
// stripped, credentialed and sent.
//
// The session is where a worker's bytes become a request the kernel sends
// with the operator's credential on it, and it fails OPEN when it is wrong:
//
//   Forward a worker's Authorization, or inject a second one, and the host
//   reads a credential nobody bound, or two, and acts on whichever it likes.
//   Dial before the decision is recorded and a request leaves that the log
//   never holds.
//   Judge one header record and send another (node's headers drops a second
//   Content-Type; rawHeaders keeps both) and the host decodes a body nobody
//   judged.
//   Pass a 401 through and git asks for a password inside the container.
//   Write a row per deny and a container floods the chain; drop the count
//   and the log under-reports what it sent.
//   Let a broken frame through, or a ready the kernel refused, and the
//   channel is parsed past the point where it means anything.
//
// Everything is in-process: the mux is a FrameChannel over two PassThroughs,
// the worker is raw HTTP bytes on its flows, the upstream is the real
// createUpstream over an injected resolver and dialer whose far end is an
// in-memory node:http host, and the session's clock is a fake the tests
// advance. Nothing listens, resolves or dials.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { NetworkInterfaceInfo } from 'node:os'
import { duplexPair, PassThrough } from 'node:stream'
import { parse as parseYaml } from 'yaml'

import { MAX_TIMER_MS, parseKernelConfig } from '../src/config.js'
import { readAllRows } from '../src/events/chain.js'
import { PAYLOAD_SCHEMAS, PROXY_DENY_KEYS_PER_SECOND, PROXY_DENY_REASONS, PROXY_LIMITS, PROXY_OVERFLOW_WHY } from '../src/events/types.js'
import { encodeFrame, exitPayload, FrameChannel, FRAME_TYPE_CODES, type Frame, type FrameLimits, readGoPayload } from '../src/egress/frame.js'
import { EgressGrant } from '../src/egress/policy.js'
import {
  createEgressSession,
  DENY_WINDOW_MS,
  END_DRAIN_MS,
  REQUEST_STRIPPED,
  SessionLimits,
  type CredentialInjector,
  type EgressSession,
  type ReadyJudge,
  type SessionClock,
  type SessionEndReason,
  type SessionOutcome,
  type SessionRevokeReason,
} from '../src/egress/session.js'
import { createUpstream, UPSTREAM_OWNED_HEADERS, type Upstream } from '../src/egress/upstream.js'
import type { AppendInput, EventStore } from '../src/events/store.js'
import { withStore } from './helpers/store.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')

const RUN = 'run_1762700000000_k3x9q2'
const GRANT_ID = 'grant_1762700000000_a1'

/** What sandbox.exec's grant holds: a credential-free host, and git-fetch of the bound repository. */
const EXEC = EgressGrant.parse({
  runId: RUN,
  allow: ['registry.npmjs.org'],
  routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }],
})

/** Every profile on its host, and a credential-free host beside them: a grant that can be denied for every reason. */
const ALL = EgressGrant.parse({
  runId: RUN,
  allow: ['registry.npmjs.org'],
  routes: [
    { bindingId: 'github', host: 'github.com', profiles: ['git-fetch', 'git-push'], repos: ['op/fixture'] },
    { bindingId: 'github-api', host: 'api.github.com', profiles: ['github-pulls'], repos: ['op/fixture'] },
  ],
})

/** kernel.yaml's shipped egress.limits. */
const LIMITS: SessionLimits = Object.freeze({
  frameMaxBytes: 65_536,
  maxFlows: 16,
  maxHeaderBytes: 16_384,
  maxRequests: 2_000,
  maxBytes: 536_870_912,
  maxDenied: 20,
  idleMs: 60_000,
})

/** A binding value in no credential shape the redaction pass knows: only the session's own care keeps it out of a row. */
const VALUE = 'opaque-binding-value-7f3a9c2e1d5b'
const BEARER = `Bearer ${VALUE}`

const EMPTY = new Uint8Array(0)
const bytes = (text: string): Uint8Array => Buffer.from(text, 'latin1')

const FETCH = 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack'

/** One HTTP/1.1 request as a worker writes it. */
function http(method: string, target: string, headers: ReadonlyArray<readonly [string, string]> = [], body = ''): string {
  return `${method} ${target} HTTP/1.1\r\n${headers.map(([name, value]) => `${name}: ${value}\r\n`).join('')}\r\n${body}`
}

const statusOf = (text: string): number => Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0)

/** An answer's body, de-chunked when it was sent chunked. */
function bodyOf(text: string): string {
  const split = text.indexOf('\r\n\r\n')
  const head = text.slice(0, split)
  let rest = text.slice(split + 4)
  if (!/\r\ntransfer-encoding: chunked/i.test(head)) return rest
  let body = ''
  for (;;) {
    const eol = rest.indexOf('\r\n')
    const size = Number.parseInt(rest.slice(0, eol), 16)
    if (!(size > 0)) return body
    body += rest.slice(eol + 2, eol + 2 + size)
    rest = rest.slice(eol + 2 + size + 2)
  }
}

/** Real time, for streams to move; the session's own timers run on the fake clock. */
async function until(condition: () => boolean, what: string, ms = 3_000): Promise<void> {
  const deadline = Date.now() + ms
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise((resolve) => setImmediate(resolve))
  }
}

/** A few turns of the event loop: enough for bytes already written to a PassThrough to reach node:http and its handler. */
async function ticks(n = 8): Promise<void> {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve))
}

// ── the fake clock ───────────────────────────────────────────────────────────

class FakeClock implements SessionClock {
  #t = 0
  #next = 1
  readonly #timers = new Map<number, { readonly at: number; readonly fn: () => void }>()

  now(): number {
    return this.#t
  }

  setTimeout(fn: () => void, ms: number): unknown {
    const id = this.#next++
    this.#timers.set(id, { at: this.#t + ms, fn })
    return id
  }

  clearTimeout(handle: unknown): void {
    this.#timers.delete(handle as number)
  }

  /** Move time on, firing every timer due, in order. */
  advance(ms: number): void {
    const end = this.#t + ms
    for (;;) {
      const due = [...this.#timers].filter(([, timer]) => timer.at <= end).sort(([, a], [, b]) => a.at - b.at)[0]
      if (due === undefined) break
      this.#timers.delete(due[0])
      this.#t = Math.max(this.#t, due[1].at)
      due[1].fn()
    }
    this.#t = end
  }
}

// ── the mux and its workers ──────────────────────────────────────────────────

/** The far end of one flow: what a worker's connection to the mux looks like from the channel. */
class WorkerFlow {
  readonly flow: number
  readonly #mux: TestMux
  readonly chunks: Buffer[] = []
  kernelEnded = false
  kernelClosed = false
  muxEnded = false
  muxClosed = false
  /** When the kernel ends its side, end and close this one, as a worker that read its answer and hung up. */
  hangUpOnEnd = true

  constructor(mux: TestMux, flow: number) {
    this.#mux = mux
    this.flow = flow
  }

  write(data: string | Uint8Array): void {
    const all = typeof data === 'string' ? bytes(data) : data
    const max = this.#mux.limits?.frameMaxBytes ?? 65_536
    for (let at = 0; at < all.length; at += max) {
      const frame: Frame = { type: 'data', flow: this.flow, payload: all.subarray(at, at + max) }
      if (this.#mux.codec.sendRefusal(frame) !== undefined) return
      this.#mux.send(frame)
    }
  }

  end(): void {
    if (this.muxEnded || this.muxClosed) return
    this.muxEnded = true
    this.#mux.send({ type: 'end', flow: this.flow, payload: EMPTY })
  }

  close(): void {
    if (this.muxClosed) return
    this.muxClosed = true
    this.#mux.send({ type: 'close', flow: this.flow, payload: EMPTY })
  }

  text(): string {
    return Buffer.concat(this.chunks).toString('latin1')
  }

  onFrame(type: string, payload: Uint8Array, stale: boolean): void {
    if (type === 'data' && !stale) this.chunks.push(Buffer.from(payload))
    if (type === 'end') {
      this.kernelEnded = true
      if (this.hangUpOnEnd) {
        this.end()
        this.close()
      }
    }
    if (type === 'close') {
      this.kernelClosed = true
      this.close()
    }
  }
}

class TestMux {
  /** What the mux writes: the session reads it (the docker child's stdout). */
  readonly input = new PassThrough()
  /** What the session writes: the mux reads it (the docker child's stdin). */
  readonly output = new PassThrough()
  readonly codec = new FrameChannel({ role: 'mux' })
  readonly flows = new Map<number, WorkerFlow>()
  readonly kernelFrames: string[] = []
  limits: FrameLimits | undefined

  constructor() {
    this.output.on('data', (chunk: Buffer) => {
      const { frames, error } = this.codec.receive(chunk)
      for (const frame of frames) {
        this.kernelFrames.push(frame.type)
        if (frame.type === 'go') this.limits = readGoPayload(frame.payload)
        this.flows.get(frame.flow)?.onFrame(frame.type, frame.payload, frame.stale)
      }
      if (error !== undefined) throw error
    })
  }

  send(frame: Frame): void {
    this.input.write(this.codec.send(frame))
  }

  /** Bytes the codec would never send: a container that breaks the protocol. */
  raw(data: Uint8Array): void {
    this.input.write(data)
  }

  async handshake(report: Uint8Array = EMPTY): Promise<void> {
    this.send({ type: 'ready', flow: 0, payload: report })
    await until(() => this.limits !== undefined, 'go')
  }

  open(): WorkerFlow {
    const flow = this.codec.flowsOpened + 1
    const side = new WorkerFlow(this, flow)
    this.flows.set(flow, side)
    this.send({ type: 'open', flow, payload: EMPTY })
    return side
  }

  /** One request on a flow of its own; what the kernel answered, once it closed the flow. */
  async exchange(request: string | Uint8Array): Promise<string> {
    const side = this.open()
    side.write(request)
    await until(() => side.kernelClosed, `the kernel's close of flow ${String(side.flow)}`)
    return side.text()
  }
}

// ── the upstream host ────────────────────────────────────────────────────────

interface Seen {
  readonly method: string
  readonly url: string
  readonly rawHeaders: readonly string[]
  readonly body: Buffer
}

/** A Mac with loopback, a private LAN address and a link-local one. */
const PLAIN_MAC: NodeJS.Dict<NetworkInterfaceInfo[]> = {
  lo0: [
    { address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' },
    { address: '::1', netmask: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', family: 'IPv6', mac: '00:00:00:00:00:00', internal: true, cidr: '::1/128', scopeid: 0 },
  ],
  en0: [{ address: '192.168.1.20', netmask: '255.255.255.0', family: 'IPv4', mac: '02:00:00:00:00:01', internal: false, cidr: '192.168.1.20/24' }],
}

type Serve = (req: IncomingMessage, res: ServerResponse, body: Buffer) => void

const OK: Serve = (_req, res) => res.writeHead(200, { 'content-type': 'text/plain' }).end('upstream-ok')

/** A host that answers with a status llhttp reads and writeHead refuses (below 100): the session cannot pass the head on. */
const ODD_STATUS: Serve = (req) => {
  req.socket.end('HTTP/1.1 099 Odd\r\ncontent-length: 0\r\n\r\n')
}

interface HarnessOptions {
  readonly grant?: EgressGrant
  readonly limits?: Partial<SessionLimits>
  readonly serve?: Serve
  /** What the resolver answers for a name: one list for every name, or by name. */
  readonly v4?: readonly string[] | ((name: string) => readonly string[])
  readonly credential?: CredentialInjector
  readonly acceptReady?: ReadyJudge
  /** A store that refuses an append when this says so, as a broken one would. */
  readonly failAppend?: (input: AppendInput) => boolean
  /** The host answers on the head, before it has read the body: true when it did, and serve is not called. */
  readonly early?: (req: IncomingMessage, res: ServerResponse) => boolean
}

interface Harness {
  readonly store: EventStore
  readonly steps: string[]
  readonly seen: Seen[]
  readonly injected: string[]
  /** One entry per call of the upstream's request(). */
  readonly upstreamCalls: number[]
  readonly mux: TestMux
  readonly session: EgressSession
  readonly kills: number[]
  readonly clock: FakeClock
  /** The container exited, or was stopped, as W1 sees it: the channel's input ends, and the caller ends the session. */
  end(reason: SessionEndReason): Promise<SessionOutcome>
}

function harness(t: TestContext, o: HarnessOptions = {}): Harness {
  const store = withStore(t)
  const steps: string[] = []
  const seen: Seen[] = []
  const injected: string[] = []
  store.subscribe((row) => {
    const payload = JSON.parse(row.payload) as { stage?: string }
    steps.push(`row ${row.type}${payload.stage === undefined ? '' : ` ${payload.stage}`}`)
  })
  const host = createServer((req, res) => {
    if (o.early?.(req, res) === true) {
      seen.push({ method: req.method ?? '', url: req.url ?? '', rawHeaders: req.rawHeaders, body: Buffer.alloc(0) })
      steps.push('host answered on the head')
      return
    }
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      seen.push({ method: req.method ?? '', url: req.url ?? '', rawHeaders: req.rawHeaders, body })
      steps.push('host read a request')
      ;(o.serve ?? OK)(req, res, body)
    })
  })
  const upstream = createUpstream({
    resolver: () => {
      steps.push('resolver')
      return {
        resolve4: (name) => {
          steps.push(`resolve4 ${name}`)
          const v4 = o.v4 ?? ['140.82.112.3']
          return Promise.resolve([...(typeof v4 === 'function' ? v4(name) : v4)])
        },
        resolve6: () => Promise.resolve([]),
        cancel: () => undefined,
      }
    },
    dial: (options) => {
      steps.push(`dial ${options.host}`)
      const [client, far] = duplexPair()
      far.on('error', () => undefined)
      // A pair carries no destroy across: the host hanging up is a reset at the dialled end, as TCP's would be.
      far.once('close', () => client.destroy(Object.assign(new Error('the host hung up'), { code: 'ECONNRESET' })))
      far.once('data', () => steps.push('host read a byte'))
      host.emit('connection', far)
      const socket = Object.assign(client, { authorized: false, setTimeout: (): unknown => undefined })
      setImmediate(() => {
        socket.authorized = true
        socket.emit('secureConnect')
      })
      return socket
    },
    interfaces: () => PLAIN_MAC,
    connectTimeoutMs: 5_000,
    idleTimeoutMs: 5_000,
  })
  const upstreamCalls: number[] = []
  const counted: Upstream = {
    request: (...args) => {
      upstreamCalls.push(1)
      return upstream.request(...args)
    },
  }
  const mux = new TestMux()
  const kills: number[] = []
  const clock = new FakeClock()
  const session = createEgressSession({
    grantId: GRANT_ID,
    grant: o.grant ?? EXEC,
    agentId: 'coder',
    limits: { ...LIMITS, ...o.limits },
    channel: { input: mux.input, output: mux.output },
    store: {
      append: (input) => {
        if (o.failAppend?.(input) === true) throw new Error('the store refused the row')
        return store.append(input)
      },
    },
    upstream: counted,
    credential:
      o.credential ??
      ((bindingId, set) => {
        injected.push(bindingId)
        set('Authorization', BEARER)
      }),
    acceptReady: o.acceptReady ?? (() => undefined),
    kill: () => kills.push(1),
    clock,
  })
  const end = (reason: SessionEndReason): Promise<SessionOutcome> => {
    mux.input.end()
    return session.end(reason)
  }
  return { store, steps, seen, injected, upstreamCalls, mux, session, kills, clock, end }
}

type Row = Record<string, unknown>

function rows(store: EventStore, type?: string): Row[] {
  return readAllRows(store.db)
    .filter((row) => type === undefined || row.type === type)
    .map((row) => JSON.parse(row.payload) as Row)
}

/** Every value of one header the host read, by lower-case name. */
function headerValues(seen: Seen, lower: string): string[] {
  const out: string[] = []
  for (let i = 0; i + 1 < seen.rawHeaders.length; i += 2) if ((seen.rawHeaders[i] ?? '').toLowerCase() === lower) out.push(seen.rawHeaders[i + 1] ?? '')
  return out
}

/** The session's outcome, or a failure after `ms` of real time: a session that never revokes fails its test, never hangs it. */
async function doneOf(session: EgressSession, ms = 3_000): Promise<SessionOutcome> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      session.done,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('the session never revoked the grant')), ms)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

const settledYet = async (session: EgressSession): Promise<boolean> =>
  Promise.race([session.done.then(() => true), new Promise<boolean>((resolve) => setImmediate(() => resolve(false)))])

// ── git pkt-lines ────────────────────────────────────────────────────────────

const OLD = 'a'.repeat(40)
const NEW = 'b'.repeat(40)
const ZERO = '0'.repeat(40)
const CAPS = ' report-status side-band-64k quiet object-format=sha1 agent=git/2.47.1'
const PACK = 'PACK\x00\x00\x00\x02\x00\x00\x00\x00'

function pkt(payload: string): string {
  return (payload.length + 4).toString(16).padStart(4, '0') + payload
}

function commandList(refs: readonly (readonly [old: string, next: string, ref: string])[]): string {
  return refs.map(([old, next, ref], i) => pkt(`${old} ${next} ${ref}${i === 0 ? `\0${CAPS}` : ''}`)).join('') + '0000'
}

const RECEIVE_TYPE = 'application/x-git-receive-pack-request'

function push(list: string, extra: ReadonlyArray<readonly [string, string]> = [], pack = PACK): string {
  const body = list + pack
  return http('POST', 'http://github.com/op/fixture.git/git-receive-pack', [['Host', 'github.com'], ['Content-Type', RECEIVE_TYPE], ['Content-Length', String(body.length)], ...extra], body)
}

const PR = { title: 'aos change', head: `aos/${RUN}/fix`, base: 'main' }

function pulls(json: string): string {
  return http('POST', 'http://api.github.com/repos/op/fixture/pulls', [['Content-Type', 'application/json'], ['Content-Length', String(Buffer.byteLength(json))]], json)
}

// ── the acceptance tests ─────────────────────────────────────────────────────

/**
 * Every worker header no host may read, written out here rather than read
 * from REQUEST_STRIPPED, so a name dropped from the session's list fails this
 * test: the auth headers and cookies, the hop-by-hop headers (Proxy-
 * Authenticate among them, which the upstream refuses outright), Expect, and
 * the forwarding and client-address headers. Host, Content-Length and
 * Transfer-Encoding are the upstream's to set, and are driven on a push.
 */
const WORKER_ONLY: readonly string[] = Object.freeze([
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'private-token',
  'cookie',
  'cookie2',
  'connection',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'upgrade',
  'proxy-authenticate',
  'expect',
  'forwarded',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'x-client-ip',
  'client-ip',
  'true-client-ip',
  'x-cluster-client-ip',
  'cf-connecting-ip',
  'fastly-client-ip',
  'x-originating-ip',
])

/** The value a worker sends for one of WORKER_ONLY: what the host must never read. */
function workerValue(name: string): string {
  switch (name) {
    case 'connection':
      return 'keep-alive, X-Hop'
    case 'te':
      return 'trailers'
    case 'keep-alive':
      return 'timeout=5'
    default:
      return `worker ${name}`
  }
}

test('a routed request reaches the fake upstream with exactly one injected header and the worker Authorization stripped', async (t) => {
  const h = harness(t)
  await h.mux.handshake()
  const answer = await h.mux.exchange(
    http('GET', FETCH, [
      ['Host', 'github.com'],
      ['Authorization', 'Basic d29ya2VyOnNlY3JldA=='],
      ['authorization', 'Bearer worker-own-token'],
      // Every other one in the case a client might write it.
      ...WORKER_ONLY.filter((name) => name !== 'authorization').map((name) => [name.replace(/(^|-)([a-z])/g, (_m, dash: string, c: string) => dash + c.toUpperCase()), workerValue(name)] as const),
      ['X-Hop', 'named by Connection'],
      ['User-Agent', 'git/2.47.1'],
      ['Accept', '*/*'],
      ['Git-Protocol', 'version=2'],
    ]),
  )
  assert.equal(statusOf(answer), 200, answer)
  assert.equal(bodyOf(answer), 'upstream-ok')
  assert.equal(h.seen.length, 1)
  const seen = h.seen[0]
  assert.ok(seen !== undefined)
  assert.equal(seen.method, 'GET')
  assert.equal(seen.url, '/op/fixture.git/info/refs?service=git-upload-pack')
  // Exactly one auth header on the wire, and it is the binding's.
  assert.deepEqual(headerValues(seen, 'authorization'), [BEARER])
  assert.deepEqual(h.injected, ['github'])
  for (const name of WORKER_ONLY) {
    if (name === 'authorization') continue
    // Connection is the upstream's own (close), never the worker's.
    assert.deepEqual(headerValues(seen, name), name === 'connection' ? ['close'] : [], `${name} reached the host`)
  }
  assert.deepEqual(headerValues(seen, 'x-hop'), [], 'a header the Connection named reached the host')
  assert.deepEqual(headerValues(seen, 'host'), ['github.com'])
  // Every header the upstream sets or refuses itself is stripped, not left in for it to refuse.
  for (const name of UPSTREAM_OWNED_HEADERS) assert.ok(REQUEST_STRIPPED.includes(name), name)
  for (const [name, value] of [['user-agent', 'git/2.47.1'], ['accept', '*/*'], ['git-protocol', 'version=2']] as const) {
    assert.deepEqual(headerValues(seen, name), [value], name)
  }

  // A credential-free host gets no injection, and so no auth header at all.
  const free = await h.mux.exchange(http('GET', 'http://registry.npmjs.org/react', [['Authorization', 'Bearer worker-own-token'], ['Cookie', 'a=b']]))
  assert.equal(statusOf(free), 200, free)
  const second = h.seen[1]
  assert.ok(second !== undefined)
  assert.deepEqual(headerValues(second, 'authorization'), [])
  assert.deepEqual(headerValues(second, 'cookie'), [])
  assert.deepEqual(h.injected, ['github'], 'the injector ran for a credential-free host')

  const outcome = await h.end('exited')
  assert.equal(outcome.reason, 'exited')
  assert.deepEqual(h.kills, [])
})

test('proxy.decision is appended before the upstream sees a byte', async (t) => {
  const h = harness(t)
  await h.mux.handshake()
  const answer = await h.mux.exchange(http('GET', FETCH, [['Host', 'github.com']]))
  assert.equal(statusOf(answer), 200, answer)
  const decided = h.steps.indexOf('row proxy.decision policy')
  assert.ok(decided !== -1, h.steps.join(' | '))
  for (const step of ['resolver', 'resolve4 github.com', 'dial 140.82.112.3', 'host read a byte', 'host read a request']) {
    const at = h.steps.indexOf(step)
    assert.ok(at > decided, `${step} came before the decision: ${h.steps.join(' | ')}`)
  }
  // The row names the request in full, from the grant's run and agent.
  const [row] = rows(h.store, 'proxy.decision')
  assert.deepEqual(row, {
    schemaVersion: 1,
    grantId: GRANT_ID,
    stage: 'policy',
    verdict: 'allow',
    reason: 'git-fetch',
    count: 1,
    method: 'GET',
    host: 'github.com',
    path: '/op/fixture.git/info/refs',
    pathBytes: '/op/fixture.git/info/refs'.length,
    queryBytes: '?service=git-upload-pack'.length,
    service: 'git-upload-pack',
    bindingId: 'github',
    repo: 'op/fixture',
    why: row?.['why'],
  })
  const stored = readAllRows(h.store.db).find((r) => r.type === 'proxy.decision')
  assert.equal(stored?.runId, RUN)
  assert.equal(stored?.agentId, 'coder')

  // A deny never reaches the resolver at all.
  const before = h.steps.filter((s) => s === 'resolver').length
  const denied = await h.mux.exchange(http('GET', 'http://example.com/'))
  assert.equal(statusOf(denied), 403, denied)
  assert.equal(h.steps.filter((s) => s === 'resolver').length, before)
  await h.end('exited')
})

test('no row contains the binding value and verifyChain passes', async (t) => {
  let status = 200
  const h = harness(t, {
    grant: ALL,
    serve: (_req, res) => res.writeHead(status, { 'content-type': 'text/plain', 'www-authenticate': 'Basic realm="GitHub"' }).end(`status ${String(status)}`),
  })
  await h.mux.handshake()
  assert.equal(statusOf(await h.mux.exchange(http('GET', FETCH))), 200)
  status = 401
  assert.equal(statusOf(await h.mux.exchange(http('GET', FETCH))), 502)
  assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://example.com/', [['Authorization', BEARER]]))), 403)
  assert.equal(statusOf(await h.mux.exchange(push(commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]])))), 502)
  const outcome = await h.end('requested')
  assert.equal(outcome.reason, 'requested')
  const all = readAllRows(h.store.db)
  assert.ok(all.length >= 5)
  const base64 = Buffer.from(`x-access-token:${VALUE}`).toString('base64')
  for (const row of all) {
    assert.equal(row.payload.includes(VALUE), false, `${row.type} holds the binding value`)
    assert.equal(row.payload.includes(base64), false, `${row.type} holds the Basic form of it`)
  }
  assert.equal(h.store.verifyChain().ok, true)
  // Every row this grant wrote parses as its type and names the grant.
  for (const row of rows(h.store)) {
    assert.equal(row['grantId'], GRANT_ID)
  }
})

test('a malformed frame revokes with reason violation, calls kill once, and decodes nothing after it', async (t) => {
  const cases: ReadonlyArray<readonly [string, (mux: TestMux) => void, RegExp]> = [
    ['an unknown type', (mux) => mux.raw(Uint8Array.of(0, 0, 0, 0, 0x7f, 0, 0, 0, 0)), /unknown-type/],
    ['an open out of order', (mux) => mux.raw(encodeFrame({ type: 'open', flow: 2, payload: EMPTY })), /flow-order/],
    ['data on a flow never opened', (mux) => mux.raw(encodeFrame({ type: 'data', flow: 1, payload: bytes('GET') })), /unopened-flow/],
    ['a second ready', (mux) => mux.raw(encodeFrame({ type: 'ready', flow: 0, payload: EMPTY })), /ready-twice/],
    ['a go from the mux', (mux) => mux.raw(encodeFrame({ type: 'go', flow: 0, payload: new Uint8Array(8) })), /direction/],
  ]
  for (const [label, breakIt, detail] of cases) {
    await t.test(label, async (t) => {
      const h = harness(t)
      await h.mux.handshake()
      breakIt(h.mux)
      const outcome = await doneOf(h.session)
      assert.equal(outcome.reason, 'violation')
      assert.equal(outcome.limit, undefined)
      assert.match(outcome.detail ?? '', detail)
      assert.deepEqual(h.kills, [1])
      const [revoked] = rows(h.store, 'proxy.grant.revoked')
      assert.equal(revoked?.['reason'], 'violation')
      assert.match(String(revoked?.['detail']), detail)
      assert.deepEqual(revoked?.['totals'], { flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 })
      // end() after the session revoked itself changes nothing.
      assert.equal(await h.session.end('exited'), outcome)
      assert.equal(rows(h.store, 'proxy.grant.revoked').length, 1)
    })
  }
  // Before the handshake: anything but ready is refused, and go is never sent.
  const h = harness(t)
  h.mux.raw(encodeFrame({ type: 'open', flow: 1, payload: EMPTY }))
  const outcome = await doneOf(h.session)
  assert.equal(outcome.reason, 'violation')
  assert.match(outcome.detail ?? '', /not-ready/)
  assert.equal(h.mux.kernelFrames.includes('go'), false)
})

test("a frame past a channel limit revokes with reason limit naming it: frameMaxBytes, and the open past maxFlows", async (t) => {
  const big = harness(t, { limits: { frameMaxBytes: 16 } })
  await big.mux.handshake()
  big.mux.open()
  big.mux.raw(encodeFrame({ type: 'data', flow: 1, payload: new Uint8Array(17) }))
  const tooBig = await doneOf(big.session)
  assert.deepEqual([tooBig.reason, tooBig.limit], ['limit', 'frameMaxBytes'])
  assert.deepEqual(big.kills, [1])

  const many = harness(t, { limits: { maxFlows: 2 } })
  await many.mux.handshake()
  many.mux.open().hangUpOnEnd = false
  many.mux.open().hangUpOnEnd = false
  many.mux.raw(encodeFrame({ type: 'open', flow: 3, payload: EMPTY }))
  const tooMany = await doneOf(many.session)
  assert.deepEqual([tooMany.reason, tooMany.limit], ['limit', 'maxFlows'])
  assert.equal(rows(many.store, 'proxy.grant.revoked')[0]?.['limit'], 'maxFlows')
  assert.equal((tooMany.totals.flows), 2)
})

test('a ready the kernel refuses ends the grant before go: the command never runs', async (t) => {
  const reports: string[] = []
  const h = harness(t, {
    acceptReady: (report) => {
      reports.push(Buffer.from(report).toString('utf8'))
      return 'a self-test connect reached 192.168.5.2:8766'
    },
  })
  h.mux.send({ type: 'ready', flow: 0, payload: bytes('reach 192.168.5.2:8766 ok') })
  const outcome = await doneOf(h.session)
  assert.deepEqual(reports, ['reach 192.168.5.2:8766 ok'])
  assert.equal(outcome.reason, 'violation')
  assert.match(outcome.detail ?? '', /ready report was refused: a self-test connect reached 192\.168\.5\.2:8766/)
  assert.deepEqual(h.kills, [1])
  assert.deepEqual(h.mux.kernelFrames, [], 'the kernel sent a frame after a refused ready')
  assert.equal(Buffer.from(outcome.ready ?? EMPTY).toString('utf8'), 'reach 192.168.5.2:8766 ok')

  // A judge that throws refuses too.
  const thrown = harness(t, {
    acceptReady: () => {
      throw new Error('boom')
    },
  })
  thrown.mux.send({ type: 'ready', flow: 0, payload: EMPTY })
  assert.match((await doneOf(thrown.session)).detail ?? '', /the ready judge threw/)
})

test('an upstream 401 or 403 is answered 502, with no challenge, so git never prompts, and recorded as challenged; a cookie and hop-by-hop headers are not passed on', async (t) => {
  for (const status of [401, 403]) {
    const h = harness(t, {
      serve: (_req, res) => res.writeHead(status, { 'www-authenticate': 'Basic realm="GitHub"', 'content-type': 'text/plain' }).end('Bad credentials'),
    })
    await h.mux.handshake()
    const answer = await h.mux.exchange(http('GET', FETCH))
    assert.equal(statusOf(answer), 502, answer)
    assert.doesNotMatch(answer, /www-authenticate|Bad credentials/i)
    assert.equal(bodyOf(answer), `egress: the host refused the binding's credential (HTTP ${String(status)})\n`)
    // The request was sent and the host refused it: its allow row stands,
    // and an upstream row says the host challenged it, so a binding whose
    // credential expired is on record, not only in the worker's 502.
    const decisions = rows(h.store, 'proxy.decision')
    assert.deepEqual(
      decisions.map((r) => [r['stage'], r['verdict'], r['refusal'], r['sent'], r['bindingId']]),
      [
        ['policy', 'allow', undefined, undefined, 'github'],
        ['upstream', 'allow', 'challenged', true, 'github'],
      ],
    )
    assert.match(String(decisions[1]?.['why']), new RegExp(`HTTP ${String(status)} to the binding's credential`))
    for (const row of decisions) assert.equal(PAYLOAD_SCHEMAS['proxy.decision'].safeParse(row).success, true)
    const outcome = await h.end('exited')
    assert.deepEqual([outcome.totals.allowed, outcome.totals.refused, outcome.totals.failed], [1, 0, 1])
  }
  // A credential-free host that challenges is no binding's credential refused.
  const free = harness(t, { serve: (_req, res) => res.writeHead(401, { 'content-type': 'text/plain' }).end('no') })
  await free.mux.handshake()
  const refused = await free.mux.exchange(http('GET', 'http://registry.npmjs.org/react'))
  assert.equal(statusOf(refused), 502, refused)
  assert.equal(bodyOf(refused), 'egress: the host refused the request (HTTP 401)\n')
  assert.deepEqual(
    rows(free.store, 'proxy.decision').map((r) => [r['stage'], r['reason'], r['refusal'], r['sent'], r['why']]),
    [
      ['policy', 'allow-host', undefined, undefined, rows(free.store, 'proxy.decision')[0]?.['why']],
      ['upstream', 'allow-host', 'challenged', true, 'the host answered HTTP 401'],
    ],
  )
  await free.end('exited')

  const h = harness(t, {
    serve: (_req, res) =>
      res
        .writeHead(200, [
          'Content-Type', 'text/plain',
          'Set-Cookie', 'user_session=operator-session; HttpOnly',
          'Keep-Alive', 'timeout=5',
          'Connection', 'keep-alive, X-Hop',
          'X-Hop', 'named',
          'X-GitHub-Request-Id', 'ABCD',
        ])
        .end('body'),
  })
  await h.mux.handshake()
  const answer = await h.mux.exchange(http('GET', FETCH))
  assert.equal(statusOf(answer), 200, answer)
  assert.doesNotMatch(answer, /set-cookie|operator-session|keep-alive|x-hop/i)
  assert.match(answer, /X-GitHub-Request-Id: ABCD/)
  assert.match(answer, /\r\nconnection: close\r\n/i)
  assert.equal(bodyOf(answer), 'body')
  await h.end('exited')
})

test('a routed push reaches the fake upstream with the judged Content-Type and no Content-Encoding; a worker request whose two records disagree is refused, not sent', async (t) => {
  const h = harness(t, { grant: ALL, serve: (_req, res) => res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result' }).end('0000') })
  await h.mux.handshake()
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]])
  const answer = await h.mux.exchange(push(list))
  assert.equal(statusOf(answer), 200, answer)
  const seen = h.seen[0]
  assert.ok(seen !== undefined)
  assert.equal(seen.url, '/op/fixture.git/git-receive-pack')
  assert.deepEqual(headerValues(seen, 'content-type'), [RECEIVE_TYPE])
  assert.deepEqual(headerValues(seen, 'content-encoding'), [])
  assert.deepEqual(headerValues(seen, 'content-length'), [String(list.length + PACK.length)])
  assert.equal(seen.body.toString('latin1'), list + PACK, 'the body is the command list judged, then the rest')
  assert.deepEqual(headerValues(seen, 'authorization'), [BEARER])

  // Sent a byte at a time, the command list is read whole and judged the same.
  const side = h.mux.open()
  for (const byte of bytes(push(list))) side.write(Uint8Array.of(byte))
  await until(() => side.kernelClosed, 'the byte-at-a-time push')
  assert.equal(statusOf(side.text()), 200, side.text())
  assert.equal(h.seen[1]?.body.toString('latin1'), list + PACK)

  // Sent chunked, the body's framing is the upstream's: the worker's
  // Transfer-Encoding and Host are dropped, and the upstream frames the
  // body as decide() judged it.
  const whole = list + PACK
  const chunked = await h.mux.exchange(
    http(
      'POST',
      'http://github.com/op/fixture.git/git-receive-pack',
      [['Host', 'github.com'], ['Content-Type', RECEIVE_TYPE], ['Transfer-Encoding', 'chunked']],
      `${whole.length.toString(16)}\r\n${whole}\r\n0\r\n\r\n`,
    ),
  )
  assert.equal(statusOf(chunked), 200, chunked)
  const framed = h.seen[2]
  assert.ok(framed !== undefined)
  assert.equal(framed.body.toString('latin1'), whole)
  assert.deepEqual(headerValues(framed, 'host'), ['github.com'])
  assert.deepEqual(headerValues(framed, 'content-length').length + headerValues(framed, 'transfer-encoding').length, 1, 'the upstream framed the body once')

  // node's `headers` keeps the first of two Content-Types; the record the
  // session judges keeps both, and decide() refuses a head it would have to
  // choose from. Nothing is sent.
  const before = h.seen.length
  const two = await h.mux.exchange(push(list, [['Content-Type', 'application/x-git-upload-pack-request']]))
  assert.equal(statusOf(two), 403, two)
  assert.equal(h.seen.length, before)
  const twoHosts = await h.mux.exchange(http('GET', FETCH, [['Host', 'github.com'], ['Host', 'example.com']]))
  assert.equal(statusOf(twoHosts), 403, twoHosts)
  const encoded = await h.mux.exchange(push(list, [['Content-Encoding', 'gzip']]))
  assert.equal(statusOf(encoded), 403, encoded)
  assert.equal(h.seen.length, before)
  // A header named as an object's own keys is judged and sent like any other.
  const odd = await h.mux.exchange(http('GET', 'http://registry.npmjs.org/react', [['constructor', 'x'], ['__proto__', 'y'], ['toString', 'z']]))
  assert.equal(statusOf(odd), 200, odd)
  const sent = h.seen.at(-1)
  assert.ok(sent !== undefined)
  assert.deepEqual([headerValues(sent, 'constructor'), headerValues(sent, '__proto__'), headerValues(sent, 'tostring')], [['x'], ['y'], ['z']])
  await h.end('exited')
  assert.deepEqual(
    rows(h.store, 'proxy.decision').filter((r) => r['verdict'] === 'deny').map((r) => r['reason']).sort(),
    ['content-encoding', 'content-type', 'second-host'],
  )
})

test("a Connection header naming a header decide() read refuses the request unsent: dropping it as hop-by-hop would send a head nobody judged", async (t) => {
  const h = harness(t, { grant: ALL })
  await h.mux.handshake()
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]])
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['Content-Type', push(list, [['Connection', 'Content-Type']])],
    ['Content-Encoding, in another case and beside close', http('GET', 'http://registry.npmjs.org/react', [['Connection', 'close, CONTENT-ENCODING']])],
    ['Host', http('GET', FETCH, [['Host', 'github.com'], ['Connection', 'host']])],
    ['Content-Length', push(list, [['Connection', 'content-length']])],
  ]
  for (const [label, request] of cases) {
    const before = rows(h.store, 'proxy.decision').length
    const answer = await h.mux.exchange(request)
    assert.equal(statusOf(answer), 502, `${label}: ${answer}`)
    // The session refused it, never the upstream, which was not asked.
    assert.equal(bodyOf(answer), 'egress: the session refused the request (head)\n', label)
    const [allow, refused] = rows(h.store, 'proxy.decision').slice(before)
    assert.deepEqual([allow?.['stage'], allow?.['verdict']], ['policy', 'allow'], label)
    assert.deepEqual([refused?.['stage'], refused?.['verdict'], refused?.['refusal'], refused?.['sent']], ['upstream', 'deny', 'head', false], label)
    assert.match(String(refused?.['why']), /Connection header names a header decide\(\) judged/, label)
  }
  // Refused by the session: the upstream was never asked, so nothing was resolved or sent.
  assert.deepEqual(h.upstreamCalls, [])
  assert.equal(h.seen.length, 0)
  // A Connection naming only what decide() does not read is a hop-by-hop list like any other.
  assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://registry.npmjs.org/react', [['Connection', 'close, X-Hop'], ['X-Hop', '1']]))), 200)
  assert.deepEqual(headerValues(h.seen[0] ?? { method: '', url: '', rawHeaders: [], body: Buffer.alloc(0) }, 'x-hop'), [])
  await h.end('exited')
})

test('a request with an Expect node:http does not know is judged and sent like any other, its Expect dropped, never answered 417 unjudged', async (t) => {
  const h = harness(t)
  await h.mux.handshake()
  const answer = await h.mux.exchange(http('GET', 'http://registry.npmjs.org/react', [['Expect', 'x']]))
  assert.equal(statusOf(answer), 200, answer)
  assert.deepEqual(rows(h.store, 'proxy.decision').map((r) => [r['stage'], r['verdict'], r['reason']]), [['policy', 'allow', 'allow-host']])
  const seen = h.seen[0]
  assert.ok(seen !== undefined)
  assert.deepEqual(headerValues(seen, 'expect'), [])
  await h.end('exited')
})

test('a worker that half-closes once its request is written is answered, then the flow ends', async (t) => {
  const h = harness(t)
  await h.mux.handshake()
  const side = h.mux.open()
  side.write(http('GET', FETCH))
  side.end()
  await until(() => side.kernelClosed, 'the answered flow')
  assert.equal(statusOf(side.text()), 200, side.text())
  assert.equal(bodyOf(side.text()), 'upstream-ok')
  assert.equal(side.kernelEnded, true, 'the answer was cut, not ended')
  assert.equal(h.seen.length, 1)
  assert.deepEqual(rows(h.store, 'proxy.decision').map((r) => [r['stage'], r['verdict']]), [['policy', 'allow']])
  // A deny is answered the same way.
  const denied = h.mux.open()
  denied.write(http('GET', 'http://example.com/'))
  denied.end()
  await until(() => denied.kernelClosed, 'the denied flow')
  assert.equal(statusOf(denied.text()), 403, denied.text())
  await h.end('exited')
})

test('a deny of every reason the session can meet is recorded as a proxy.decision row with what decide() read', async (t) => {
  const h = harness(t, { grant: ALL, limits: { maxDenied: 1_000 } })
  await h.mux.handshake()
  const prefix = `refs/heads/aos/${RUN}/`
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['use-route', http('CONNECT', '192.168.5.2:8766', [['Host', '192.168.5.2:8766']])],
    ['not-allowed', http('GET', 'http://example.com/')],
    ['repo', http('GET', 'http://github.com/evil/other.git/info/refs?service=git-upload-pack')],
    ['not-granted', http('GET', 'http://api.github.com/op/fixture.git/info/refs?service=git-upload-pack')],
    ['body', http('GET', 'http://registry.npmjs.org/react', [['Content-Length', '0']])],
    ['content-type', http('POST', 'http://github.com/op/fixture/git-upload-pack', [['Content-Type', 'text/plain'], ['Transfer-Encoding', 'chunked']], '0\r\n\r\n')],
    ['content-encoding', http('GET', 'http://registry.npmjs.org/react', [['Content-Encoding', 'gzip'], ['Content-Encoding', 'br']])],
    ['override-header', http('GET', 'http://registry.npmjs.org/react', [['X-HTTP-Method-Override', 'DELETE']])],
    ['target', http('GET', '/react')],
    ['not-a-host', http('GET', 'http://192.168.5.2:8766/mcp')],
    ['not-a-host', http('GET', 'http://host.lima.internal:8766/mcp')],
    ['port', http('GET', 'https://example.com:8080/')],
    ['second-host', http('GET', 'http://user@registry.npmjs.org/')],
    ['second-host', http('GET', 'http://registry.npmjs.org/', [['Host', 'example.com']])],
    ['path', http('GET', 'http://registry.npmjs.org/a/../b')],
    ['no-route', http('GET', 'http://github.com/user/keys')],
    ['method', http('POST', 'http://registry.npmjs.org/react', [['Content-Length', '2']], 'xy')],
    ['query', http('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-archive')],
    ['push-commands', push(pkt('not a command') + '0000')],
    ['push-ref', push(commandList([[OLD, NEW, 'refs/heads/main']]))],
    ['push-delete', push(commandList([[OLD, ZERO, `${prefix}fix`]]))],
    ['pulls-body', pulls(JSON.stringify({ ...PR, draft: 'yes' }))],
    ['pulls-head', pulls(JSON.stringify({ ...PR, head: 'evil:x' }))],
  ]
  for (const [reason, request] of cases) {
    const answer = await h.mux.exchange(request)
    assert.equal(statusOf(answer), 403, `${reason}: ${answer}`)
    assert.match(answer, new RegExp(`egress: denied \\(${reason}\\)`))
    // Its own second: one row, with the detail a single deny keeps.
    h.clock.advance(DENY_WINDOW_MS)
    const last = rows(h.store, 'proxy.decision').at(-1)
    assert.equal(last?.['reason'], reason, request)
    assert.equal(last?.['count'], 1)
  }
  assert.equal(h.seen.length, 0, 'a denied request reached the host')
  const denied = rows(h.store, 'proxy.decision')
  assert.equal(denied.length, cases.length)
  // Every reason decide() gives but `malformed`, which needs a grant or a
  // request no session can hand it (the grant is parsed when the session is
  // made, and node:http reads every head as text): test/egress-policy.test.ts
  // drives that one.
  assert.deepEqual(new Set(denied.map((r) => r['reason'])), new Set(PROXY_DENY_REASONS.filter((r) => r !== 'malformed')))
  // What each names: a not-a-host deny why its host was none and no host;
  // a path deny its host; a route deny its binding; a CONNECT nothing read.
  const byReason = (reason: string): Row | undefined => denied.find((r) => r['reason'] === reason)
  assert.equal(byReason('not-a-host')?.['hostRefusal'], 'ip-literal')
  assert.equal(byReason('not-a-host')?.['host'], undefined)
  assert.equal(denied.filter((r) => r['reason'] === 'not-a-host')[1]?.['hostRefusal'], 'special-use')
  assert.equal(byReason('use-route')?.['method'], 'CONNECT')
  assert.equal(byReason('use-route')?.['host'], undefined)
  assert.equal(byReason('path')?.['host'], 'registry.npmjs.org')
  assert.equal(byReason('path')?.['path'], undefined)
  assert.equal(byReason('push-ref')?.['bindingId'], 'github')
  assert.equal(byReason('pulls-head')?.['bindingId'], 'github-api')
  assert.equal(byReason('not-allowed')?.['path'], '/')
  assert.equal(byReason('not-granted')?.['service'], 'git-upload-pack')
  assert.equal(byReason('query')?.['service'], undefined)
  assert.equal(byReason('query')?.['queryBytes'], '?service=git-upload-archive'.length)
  for (const row of denied) assert.equal(PAYLOAD_SCHEMAS['proxy.decision'].safeParse(row).success, true)
  const outcome = await h.end('exited')
  assert.equal(outcome.totals.denied, cases.length)
  assert.equal(outcome.totals.requests, cases.length)
})

test('deny rows are coalesced: one row per key per second with its count, overflow rows past the distinct keys, a deny host in a credential shape recorded without it', async (t) => {
  // One second, the second PROXY_DENY_KEYS_PER_SECOND bounds the keys of.
  assert.equal(DENY_WINDOW_MS, 1_000)
  const h = harness(t, { limits: { maxDenied: 10_000 } })
  await h.mux.handshake()
  // Five of the same deny in one second: one row, counted, with no path.
  for (let i = 0; i < 5; i++) assert.equal(statusOf(await h.mux.exchange(http('GET', `http://example.com/${String(i)}`))), 403)
  // The window is the second from the first deny: open a millisecond short of it, closed at it.
  h.clock.advance(DENY_WINDOW_MS - 1)
  assert.equal(rows(h.store, 'proxy.decision').length, 0, 'a deny row was written before its second closed')
  h.clock.advance(1)
  const [five] = rows(h.store, 'proxy.decision')
  assert.equal(five?.['count'], 5)
  assert.equal(five?.['host'], 'example.com')
  assert.equal(five?.['path'], undefined)
  assert.equal(five?.['pathBytes'], undefined)

  // More distinct keys than one second keeps: the rest are counted by reason,
  // and a not-a-host deny by its host refusal as well.
  const extra = 4
  for (let i = 0; i < PROXY_DENY_KEYS_PER_SECOND + extra; i++) {
    assert.equal(statusOf(await h.mux.exchange(http('GET', `http://h${String(i)}.example.com/`))), 403)
  }
  for (const target of ['http://192.168.5.2:8766/', 'http://10.0.0.1/', 'http://host.lima.internal/']) {
    assert.equal(statusOf(await h.mux.exchange(http('GET', target))), 403)
  }
  h.clock.advance(DENY_WINDOW_MS)
  const window = rows(h.store, 'proxy.decision').slice(1)
  const keyed = window.filter((r) => r['overflow'] === undefined)
  const overflow = window.filter((r) => r['overflow'] === true)
  assert.equal(keyed.length, PROXY_DENY_KEYS_PER_SECOND)
  assert.deepEqual(
    overflow.map((r) => [r['reason'], r['hostRefusal'], r['count']]),
    [
      ['not-allowed', undefined, extra],
      ['not-a-host', 'ip-literal', 2],
      ['not-a-host', 'special-use', 1],
    ],
  )
  for (const row of overflow) {
    assert.equal(row['why'], PROXY_OVERFLOW_WHY)
    assert.equal(row['host'], undefined)
  }

  // A host the redaction pass would change is the worker's text in a
  // credential's shape: recorded without it, never censored into the row.
  assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://sk-abcdefghijklmnop.example.com/'))), 403)
  h.clock.advance(DENY_WINDOW_MS)
  const shaped = rows(h.store, 'proxy.decision').at(-1)
  assert.equal(shaped?.['reason'], 'not-allowed')
  assert.equal(shaped?.['host'], undefined)
  await h.end('exited')
  assert.equal(readAllRows(h.store.db).some((r) => r.payload.includes('[REDACTED]')), false)

  // Rows merge only when they agree on every field they name: a GET and a
  // HEAD to one denied host are two rows, and so are not-granted denies on
  // two bindings of one host, each naming its own.
  const two = EgressGrant.parse({
    runId: RUN,
    allow: [],
    routes: [
      { bindingId: 'github-a', host: 'github.com', profiles: ['git-fetch'], repos: ['op/a'] },
      { bindingId: 'github-b', host: 'github.com', profiles: ['git-fetch'], repos: ['op/b'] },
    ],
  })
  const split = harness(t, { grant: two, limits: { maxDenied: 100 } })
  await split.mux.handshake()
  for (let i = 0; i < 2; i++) {
    for (const method of ['GET', 'HEAD']) assert.equal(statusOf(await split.mux.exchange(http(method, 'http://example.com/'))), 403)
    for (const repo of ['op/a', 'op/b']) {
      assert.equal(statusOf(await split.mux.exchange(http('GET', `http://github.com/${repo}.git/info/refs?service=git-receive-pack`))), 403)
    }
  }
  split.clock.advance(DENY_WINDOW_MS)
  assert.deepEqual(
    rows(split.store, 'proxy.decision').map((r) => [r['reason'], r['method'], r['bindingId'], r['count']]),
    [
      ['not-allowed', 'GET', undefined, 2],
      ['not-allowed', 'HEAD', undefined, 2],
      ['not-granted', 'GET', 'github-a', 2],
      ['not-granted', 'GET', 'github-b', 2],
    ],
  )
  await split.end('exited')
})

test('a deny row the store refuses ends the grant in error, after the rest of its window is on record', async (t) => {
  let decisions = 0
  const h = harness(t, { limits: { maxDenied: 100 }, failAppend: (input) => input.type === 'proxy.decision' && decisions++ === 0 })
  await h.mux.handshake()
  for (const host of ['a.example.com', 'b.example.com', 'c.example.com']) assert.equal(statusOf(await h.mux.exchange(http('GET', `http://${host}/`))), 403)
  h.clock.advance(DENY_WINDOW_MS)
  const outcome = await doneOf(h.session)
  assert.equal(outcome.reason, 'error')
  assert.equal(outcome.detail, '1 decision row could not be appended')
  assert.deepEqual(h.kills, [1])
  // The first was refused; the two after it are on record before the revocation, never after it.
  assert.deepEqual(
    readAllRows(h.store.db).map((r) => [r.type, (JSON.parse(r.payload) as Row)['host']]),
    [
      ['proxy.decision', 'b.example.com'],
      ['proxy.decision', 'c.example.com'],
      ['proxy.grant.revoked', undefined],
    ],
  )

  // An overflow row is a decision row like any other: one the store refuses
  // ends the grant in error too, once the keyed rows of its window are on record.
  const over = harness(t, { limits: { maxDenied: 100 }, failAppend: (input) => input.type === 'proxy.decision' && (input.payload as Row)['overflow'] === true })
  await over.mux.handshake()
  for (let i = 0; i < PROXY_DENY_KEYS_PER_SECOND + 2; i++) {
    assert.equal(statusOf(await over.mux.exchange(http('GET', `http://h${String(i)}.example.com/`))), 403)
  }
  assert.equal(await settledYet(over.session), false)
  over.clock.advance(DENY_WINDOW_MS)
  const overOutcome = await doneOf(over.session)
  assert.equal(overOutcome.reason, 'error')
  assert.equal(overOutcome.detail, '1 decision row could not be appended')
  assert.deepEqual(over.kills, [1])
  const overRows = readAllRows(over.store.db)
  assert.equal(overRows.filter((r) => r.type === 'proxy.decision').length, PROXY_DENY_KEYS_PER_SECOND)
  assert.equal(overRows.some((r) => (JSON.parse(r.payload) as Row)['overflow'] === true), false)
  assert.equal(overRows.at(-1)?.type, 'proxy.grant.revoked')
  assert.equal(overOutcome.totals.denied, PROXY_DENY_KEYS_PER_SECOND + 2)
})

test('a decision row the store refuses is counted and answered 502 before the grant ends in error, whatever was in hand', async (t) => {
  // The revocation runs at once when no other request is in hand (a GET is
  // judged in one turn), so a request counted after it began would be
  // missing from its totals, and a 502 written after it would never reach
  // the worker: its flow is cut, and no frame follows.
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]])
  const stage = (wanted: string) => (input: AppendInput): boolean => input.type === 'proxy.decision' && (input.payload as Row)['stage'] === wanted
  const cases: ReadonlyArray<{
    readonly label: string
    readonly options: HarnessOptions
    readonly request: string
    readonly text: string
    readonly counts: readonly [allowed: number, refused: number, failed: number]
    readonly sent: number
  }> = [
    { label: "a GET's allow row", options: { failAppend: stage('policy') }, request: http('GET', FETCH), text: 'egress: the decision could not be recorded, so nothing was sent\n', counts: [1, 1, 0], sent: 0 },
    { label: "a push's allow row, its body read first", options: { grant: ALL, failAppend: stage('policy') }, request: push(list), text: 'egress: the decision could not be recorded, so nothing was sent\n', counts: [1, 1, 0], sent: 0 },
    {
      label: 'the upstream row of a head the session refused',
      options: { credential: () => undefined, failAppend: stage('upstream') },
      request: http('GET', FETCH),
      text: 'egress: the session refused the request (head)\n',
      counts: [1, 1, 0],
      sent: 0,
    },
    {
      label: 'the upstream row of a challenge',
      options: { serve: (_req, res) => res.writeHead(401, { 'content-type': 'text/plain' }).end('no'), failAppend: stage('upstream') },
      request: http('GET', FETCH),
      text: "egress: the host refused the binding's credential (HTTP 401)\n",
      counts: [1, 0, 1],
      sent: 1,
    },
    {
      label: 'the upstream row of an answer the session cannot pass on',
      options: { serve: ODD_STATUS, failAppend: stage('upstream') },
      request: http('GET', FETCH),
      text: 'egress: the upstream answered with a head the session cannot pass on\n',
      counts: [1, 0, 1],
      sent: 1,
    },
  ]
  for (const { label, options, request, text, counts, sent } of cases) {
    await t.test(label, async (t) => {
      const h = harness(t, options)
      await h.mux.handshake()
      const side = h.mux.open()
      side.hangUpOnEnd = false
      side.write(request)
      const outcome = await doneOf(h.session)
      assert.equal(outcome.reason, 'error')
      assert.equal(outcome.detail, '1 decision row could not be appended')
      assert.deepEqual(h.kills, [1])
      // The worker read the session's answer before its flow was cut.
      await until(() => side.text().endsWith(text), `the 502 to reach the worker (it read ${JSON.stringify(side.text())})`)
      assert.equal(statusOf(side.text()), 502)
      assert.equal(bodyOf(side.text()), text)
      assert.equal(h.seen.length, sent)
      // The revocation's totals hold the request, as recorded.
      const { totals } = outcome
      assert.deepEqual([totals.requests, totals.allowed, totals.refused, totals.failed], [1, ...counts])
      const all = readAllRows(h.store.db)
      assert.equal(all.filter((r) => r.type === 'proxy.grant.revoked').length, 1)
      assert.equal(all.at(-1)?.type, 'proxy.grant.revoked')
      assert.deepEqual((JSON.parse(all.at(-1)?.payload ?? '{}') as Row)['totals'], totals)
    })
  }
})

test("a decision row the store refuses once the revocation has begun keeps the revocation's reason, and its detail counts the loss: a request still in hand, and the last deny window", async (t) => {
  // The grant is ending already, so the refusal cannot end it in error, and
  // a loss with no trace would leave totals no row backs: a request counted
  // failed, or denied, with nothing on record for it.
  const upstreamRows = (input: AppendInput): boolean => input.type === 'proxy.decision' && (input.payload as Row)['stage'] === 'upstream'
  const shape = (store: EventStore): unknown[] => readAllRows(store.db).map((r) => [r.type, (JSON.parse(r.payload) as Row)['stage']])

  await t.test("a broken frame while a request is upstream: its aborted row is refused, after the violation's own detail", async (t) => {
    const h = harness(t, { serve: () => undefined, failAppend: upstreamRows })
    await h.mux.handshake()
    h.mux.open().write(http('GET', FETCH))
    await until(() => h.seen.length === 1, 'the host to read the request')
    h.mux.raw(Uint8Array.of(0, 0, 0, 0, 0x7f, 0, 0, 0, 0))
    const outcome = await doneOf(h.session)
    assert.equal(outcome.reason, 'violation')
    assert.match(outcome.detail ?? '', /unknown-type.*; 1 decision row could not be appended$/)
    assert.deepEqual([outcome.totals.allowed, outcome.totals.refused, outcome.totals.failed], [1, 0, 1])
    assert.deepEqual(shape(h.store), [['proxy.decision', 'policy'], ['proxy.grant.revoked', undefined]])
    const [revoked] = rows(h.store, 'proxy.grant.revoked')
    assert.equal(revoked?.['detail'], outcome.detail)
    assert.equal(PAYLOAD_SCHEMAS['proxy.grant.revoked'].safeParse(revoked).success, true)
    assert.deepEqual(h.kills, [1])
  })

  await t.test("the caller's end() while a request is upstream: its aborted row is refused", async (t) => {
    const h = harness(t, { serve: () => undefined, failAppend: upstreamRows })
    await h.mux.handshake()
    h.mux.open().write(http('GET', FETCH))
    await until(() => h.seen.length === 1, 'the host to read the request')
    const outcome = await h.end('wallclock')
    assert.equal(outcome.reason, 'wallclock')
    assert.equal(outcome.detail, '1 decision row could not be appended')
    assert.deepEqual([outcome.totals.allowed, outcome.totals.refused, outcome.totals.failed], [1, 0, 1])
    assert.deepEqual(shape(h.store), [['proxy.decision', 'policy'], ['proxy.grant.revoked', undefined]])
    assert.equal(rows(h.store, 'proxy.grant.revoked')[0]?.['detail'], '1 decision row could not be appended')
    assert.deepEqual(h.kills, [])
  })

  await t.test('a deny, then the caller ends the grant: the window the revocation closes last is refused', async (t) => {
    const h = harness(t, { failAppend: (input) => input.type === 'proxy.decision' })
    await h.mux.handshake()
    for (const target of ['http://example.com/', 'http://example.org/']) assert.equal(statusOf(await h.mux.exchange(http('GET', target))), 403)
    const outcome = await h.end('exited')
    assert.equal(outcome.reason, 'exited')
    assert.equal(outcome.detail, '2 decision rows could not be appended')
    assert.equal(outcome.totals.denied, 2)
    assert.deepEqual(shape(h.store), [['proxy.grant.revoked', undefined]])
    assert.deepEqual(h.kills, [])
  })
})

test('per-grant limits revoke with reason limit naming each, after the decisions made under the grant', async (t) => {
  await t.test('maxRequests', async (t) => {
    const h = harness(t, { limits: { maxRequests: 2 } })
    await h.mux.handshake()
    assert.equal(statusOf(await h.mux.exchange(http('GET', FETCH))), 200)
    assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://example.com/'))), 403)
    const third = h.mux.open()
    third.write(http('GET', FETCH))
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'maxRequests'])
    assert.deepEqual(h.kills, [1])
    assert.equal(h.seen.length, 1)
    assert.deepEqual(outcome.totals.requests, 2)
    assert.equal(readAllRows(h.store.db).at(-1)?.type, 'proxy.grant.revoked', 'a decision came after the revocation')
  })
  await t.test('maxRequests, counted by flow: a flow whose head never finished costs one too', async (t) => {
    const h = harness(t, { limits: { maxRequests: 2 } })
    await h.mux.handshake()
    for (let i = 0; i < 2; i++) {
      const cut = h.mux.open()
      cut.write('GET http://github.com/op/fixture.git/info/refs HTTP/1.1\r\nHo')
      cut.end()
      cut.close()
      await until(() => cut.kernelClosed, 'the cut flow')
    }
    assert.equal(await settledYet(h.session), false, 'a head cut short ended the grant')
    h.mux.open()
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'maxRequests'])
    assert.deepEqual([outcome.totals.flows, outcome.totals.requests], [3, 0])
    assert.deepEqual(h.kills, [1])
  })
  await t.test('maxDenied', async (t) => {
    const h = harness(t, { limits: { maxDenied: 1 } })
    await h.mux.handshake()
    assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://example.com/'))), 403)
    // The deny past the bound ends the grant, and no frame follows it.
    h.mux.open().write(http('GET', 'http://example.com/'))
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'maxDenied'])
    // The window is closed before the revocation: the denies are on record first.
    assert.deepEqual(readAllRows(h.store.db).map((r) => r.type), ['proxy.decision', 'proxy.grant.revoked'])
    assert.equal(rows(h.store, 'proxy.decision')[0]?.['count'], 2)
  })
  await t.test('maxBytes', async (t) => {
    const h = harness(t, { limits: { maxBytes: 64 } })
    await h.mux.handshake()
    h.mux.open().write(http('GET', FETCH, [['User-Agent', 'x'.repeat(80)]]))
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'maxBytes'])
    assert.equal(h.seen.length, 0)
  })
  await t.test('maxBytes, counted on the answer as well: a small request whose answer is larger', async (t) => {
    const big = Buffer.alloc(4_096, 0x61)
    const h = harness(t, { limits: { maxBytes: 1_024 }, serve: (_req, res) => res.writeHead(200, { 'content-type': 'application/octet-stream' }).end(big) })
    await h.mux.handshake()
    const request = http('GET', FETCH)
    assert.ok(request.length < 1_024)
    const side = h.mux.open()
    side.hangUpOnEnd = false
    side.write(request)
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'maxBytes'])
    // The request went; the answer past the bound did not reach the worker, and its flow was cut, never ended.
    assert.equal(h.seen.length, 1)
    assert.equal(side.kernelEnded, false)
    assert.ok(side.text().length < big.length, `the worker read ${String(side.text().length)} bytes of the answer`)
  })
  await t.test('maxHeaderBytes', async (t) => {
    const h = harness(t, { limits: { maxHeaderBytes: 256 } })
    await h.mux.handshake()
    h.mux.open().write(http('GET', FETCH, [['X-Big', 'y'.repeat(400)]]))
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'maxHeaderBytes'])
    assert.equal(rows(h.store, 'proxy.decision').length, 0, 'a head past the bound was judged')
  })
  await t.test('idleMs, while a flow is open', async (t) => {
    const h = harness(t, { limits: { idleMs: 5_000 } })
    await h.mux.handshake()
    // No flow open: a command at work is the wallclock's, never idle.
    h.clock.advance(60_000)
    assert.equal(await settledYet(h.session), false)
    // A head that never finishes: the flow is open, and nothing moves on it.
    h.mux.open().write('GET http://github.com/')
    await new Promise((resolve) => setImmediate(resolve))
    h.clock.advance(4_999)
    assert.equal(await settledYet(h.session), false)
    h.clock.advance(1)
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'idleMs'])
    assert.equal(outcome.detail, 'the channel carried no flow frame from the mux, and no data from the kernel, for idleMs 5000 ms')
  })
  await t.test('idleMs, while the handshake is pending', async (t) => {
    const h = harness(t, { limits: { idleMs: 5_000 } })
    h.clock.advance(5_000)
    const outcome = await doneOf(h.session)
    assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'idleMs'])
    assert.deepEqual(h.kills, [1])
  })
  await t.test("idleMs, reset by each of the mux's flow frames and by the kernel's data: a lone open, the mux's end, the mux's close, an answer still arriving", async (t) => {
    // Each case moves something on the channel 4 s after the frame before
    // it, with a flow open throughout: the bound runs from that, so the
    // grant is revoked idleMs after it, never idleMs after the frame before.
    // The kill is read, not the outcome: a revocation waits for a request in
    // hand before it resolves, so only the kill says when it began.
    const read = async (h: Harness): Promise<void> => {
      await until(() => h.mux.input.readableLength === 0 && h.mux.input.writableLength === 0, 'the session to read the channel')
      await ticks()
    }
    const runsFromNow = async (h: Harness): Promise<void> => {
      h.clock.advance(4_999)
      assert.deepEqual(h.kills, [], 'the grant was revoked idle less than idleMs after the last frame')
      h.clock.advance(1)
      assert.deepEqual(h.kills, [1])
      const outcome = await doneOf(h.session)
      assert.deepEqual([outcome.reason, outcome.limit], ['limit', 'idleMs'])
    }
    const idle = { limits: { idleMs: 5_000 } } as const

    await t.test('a lone open', async (t) => {
      const h = harness(t, idle)
      await h.mux.handshake()
      // No flow open yet: the clock runs, and nothing counts it.
      h.clock.advance(4_000)
      h.mux.open().hangUpOnEnd = false
      await read(h)
      await runsFromNow(h)
    })

    await t.test("the mux's end, its request upstream and the host silent", async (t) => {
      const h = harness(t, { ...idle, serve: () => undefined })
      await h.mux.handshake()
      const side = h.mux.open()
      side.hangUpOnEnd = false
      side.write(http('GET', FETCH))
      await until(() => h.seen.length === 1, 'the host to read the request')
      h.clock.advance(4_000)
      side.end()
      await read(h)
      await runsFromNow(h)
    })

    await t.test("the mux's close, on a second flow", async (t) => {
      const h = harness(t, idle)
      await h.mux.handshake()
      h.mux.open().hangUpOnEnd = false
      const second = h.mux.open()
      second.hangUpOnEnd = false
      await read(h)
      h.clock.advance(4_000)
      second.close()
      await until(() => second.kernelClosed, "the kernel's close of the second flow")
      await read(h)
      await runsFromNow(h)
    })

    await t.test('an answer still arriving, the kernel sending its data', async (t) => {
      let held: ServerResponse | undefined
      const h = harness(t, {
        ...idle,
        serve: (_req, res) => {
          res.writeHead(200, { 'content-type': 'text/plain' }).write('first')
          held = res
        },
      })
      await h.mux.handshake()
      const side = h.mux.open()
      side.hangUpOnEnd = false
      side.write(http('GET', FETCH))
      await until(() => side.text().includes('first'), 'the first of the answer')
      h.clock.advance(4_000)
      held?.write('second')
      await until(() => side.text().includes('second'), 'the rest of the answer')
      await runsFromNow(h)
    })
  })
})

test('a worker request that does not parse as HTTP revokes with reason violation; one cut short is only its flow', async (t) => {
  const h = harness(t)
  await h.mux.handshake()
  const cut = h.mux.open()
  cut.write('GET http://github.com/op/fixture.git/info/refs HTTP/1.1\r\nHos')
  cut.end()
  cut.close()
  await until(() => cut.kernelClosed, 'the cut flow')
  assert.equal(await settledYet(h.session), false, 'a worker that hung up mid-head ended the grant')
  // Content-Length beside Transfer-Encoding: request smuggling, refused by
  // the strict parser, and the container gets no second try.
  h.mux.open().write('POST http://registry.npmjs.org/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n')
  const outcome = await doneOf(h.session)
  assert.equal(outcome.reason, 'violation')
  assert.match(outcome.detail ?? '', /did not parse as HTTP\/1\.1 \(HPE_/)
  assert.deepEqual(h.kills, [1])
  assert.equal(rows(h.store, 'proxy.decision').length, 0)

  // Whatever llhttp refuses a request for, the container gets one try: in the
  // head (the method, a header's name) or in a body read after the head was judged.
  const malformed: ReadonlyArray<readonly [string, string, string]> = [
    ['a lower-case method', 'get http://registry.npmjs.org/ HTTP/1.1\r\n\r\n', 'HPE_INVALID_METHOD'],
    ['a header name that is no token', 'GET http://registry.npmjs.org/ HTTP/1.1\r\nBad Header: x\r\n\r\n', 'HPE_INVALID_HEADER_TOKEN'],
    ['a chunk size that is no number', 'POST http://registry.npmjs.org/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n', 'HPE_INVALID_CHUNK_SIZE'],
  ]
  for (const [label, request, code] of malformed) {
    await t.test(label, async (t) => {
      const h = harness(t)
      await h.mux.handshake()
      h.mux.open().write(request)
      const outcome = await doneOf(h.session)
      assert.equal(outcome.reason, 'violation')
      assert.equal(outcome.detail, `a worker's request did not parse as HTTP/1.1 (${code})`)
      assert.deepEqual(h.kills, [1])
      assert.equal(h.seen.length, 0)
    })
  }

  // Bytes past a request that said Connection: close are no request of their
  // own (llhttp's HPE_CLOSED_CONNECTION): only the flow is cut, as a
  // pipelined second request's is, and the grant goes on serving.
  const closed = harness(t)
  await closed.mux.handshake()
  closed.mux.open().write(http('GET', 'http://example.com/', [['Connection', 'close']]) + 'GET http://example.com/b HTTP/1.1\r\n\r\n')
  await until(() => closed.mux.input.readableLength === 0, 'the session to read the flow')
  await ticks()
  assert.equal(await settledYet(closed.session), false, 'bytes after Connection: close ended the grant')
  assert.equal(statusOf(await closed.mux.exchange(http('GET', FETCH))), 200)
  const closedOutcome = await closed.end('exited')
  assert.equal(closedOutcome.reason, 'exited')
  assert.deepEqual(closed.kills, [])
  // The first request was judged; what followed it was not.
  assert.equal(closedOutcome.totals.requests, 2)
})

test("the injector must set exactly one Authorization: none, two, another header, an illegal value or a throw refuse the request unsent", async (t) => {
  const injectors: ReadonlyArray<readonly [string, CredentialInjector]> = [
    ['none', () => undefined],
    ['two', (_id, set) => {
      set('Authorization', BEARER)
      set('Authorization', BEARER)
    }],
    ['another header', (_id, set) => set('X-Api-Key', VALUE)],
    ['an illegal value', (_id, set) => set('Authorization', 'Bearer a\r\nX-Injected: 1')],
    ['a throw', () => {
      throw new Error('no ref')
    }],
  ]
  for (const [label, credential] of injectors) {
    const h = harness(t, { credential })
    await h.mux.handshake()
    const answer = await h.mux.exchange(http('GET', FETCH))
    assert.equal(statusOf(answer), 502, `${label}: ${answer}`)
    assert.equal(bodyOf(answer), 'egress: the session refused the request (head)\n', label)
    // Refused by the session itself, before the upstream is asked: no head
    // with a value HTTP refuses is left for the upstream to catch.
    assert.deepEqual(h.upstreamCalls, [], `${label}: the upstream was asked`)
    assert.equal(h.seen.length, 0, `${label}: the request was sent`)
    assert.equal(h.steps.includes('resolver'), false, `${label}: the host was resolved`)
    const decisions = rows(h.store, 'proxy.decision')
    assert.deepEqual(decisions.map((r) => [r['stage'], r['verdict'], r['refusal'], r['sent']]), [['policy', 'allow', undefined, undefined], ['upstream', 'deny', 'head', false]], label)
    const outcome = await h.end('exited')
    assert.equal(outcome.totals.refused, 1, label)
  }
})

test('an upstream refusal is answered 502 and recorded on an upstream row after its allow', async (t) => {
  const h = harness(t, { v4: ['127.0.0.1'] })
  await h.mux.handshake()
  const answer = await h.mux.exchange(http('GET', FETCH))
  assert.equal(statusOf(answer), 502, answer)
  assert.equal(bodyOf(answer), 'egress: the upstream refused the request (denied-address)\n')
  assert.equal(h.steps.some((s) => s.startsWith('dial')), false)
  const [allow, refused] = rows(h.store, 'proxy.decision')
  assert.deepEqual([allow?.['stage'], allow?.['verdict']], ['policy', 'allow'])
  assert.deepEqual(
    [refused?.['stage'], refused?.['verdict'], refused?.['reason'], refused?.['refusal'], refused?.['sent'], refused?.['address'], refused?.['denial']],
    ['upstream', 'deny', 'git-fetch', 'denied-address', false, '127.0.0.1', 'loopback'],
  )
  // A refused request with a body is answered too: the upstream destroys the
  // stream it was handed, which is the session's, never the worker's request.
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]])
  const pushed = harness(t, { grant: ALL, v4: ['192.168.5.2'] })
  await pushed.mux.handshake()
  const refusedPush = await pushed.mux.exchange(push(list))
  assert.equal(statusOf(refusedPush), 502, refusedPush)
  assert.match(bodyOf(refusedPush), /denied-address/)
  assert.equal(rows(pushed.store, 'proxy.decision')[1]?.['address'], '192.168.5.2')
  await pushed.end('exited')
  const outcome = await h.end('exited')
  assert.deepEqual([outcome.totals.allowed, outcome.totals.refused, outcome.totals.failed], [1, 1, 0])
})

test("a push still arriving when it is refused, challenged or answered early is drained: the worker reads its answer, the channel goes on, and nothing idles", async (t) => {
  // A pack larger than a flow's buffers is still being piped into the
  // stream the upstream was handed when the upstream refuses it, or the host
  // answers before reading it; either destroys that stream. A pipe that is
  // not undone leaves the worker's request paused with its flow full, which
  // stops the read of the whole channel: the worker's hangup is never read,
  // no other flow is served, and the grant is revoked idle, the container
  // killed for the kernel's stall.
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]])
  const big = push(list, [], PACK + 'x'.repeat(1 << 20))
  const onPost = (status: number, text: string) => (req: IncomingMessage, res: ServerResponse): boolean => {
    if (req.method !== 'POST') return false
    res.writeHead(status, { 'content-type': 'text/plain' }).end(text)
    return true
  }
  const cases: ReadonlyArray<readonly [string, HarnessOptions, number, string, readonly unknown[]]> = [
    ['an upstream refusal', { v4: (name) => (name === 'github.com' ? ['192.168.5.2'] : ['104.16.0.35']) }, 502, 'egress: the upstream refused the request (denied-address)\n', ['upstream', 'deny', 'denied-address', false]],
    ['a host that answers 401 before it reads the body', { early: onPost(401, 'no') }, 502, "egress: the host refused the binding's credential (HTTP 401)\n", ['upstream', 'allow', 'challenged', true]],
    ['a host that answers 413 before it reads the body, passed on', { early: onPost(413, 'too large') }, 413, 'too large', []],
    // Refused before the upstream is handed a stream: the request itself is drained.
    ['a head the session refuses itself, before the body has a gate', {}, 502, 'egress: the session refused the request (head)\n', ['upstream', 'deny', 'head', false]],
  ]
  for (const [label, options, status, text, upstreamRow] of cases) {
    await t.test(label, async (t) => {
      const h = harness(t, { grant: ALL, ...options })
      await h.mux.handshake()
      const answer = await h.mux.exchange(upstreamRow[2] === 'head' ? push(list, [['Connection', 'Content-Type']], PACK + 'x'.repeat(1 << 20)) : big)
      assert.equal(statusOf(answer), status, answer.slice(0, 200))
      assert.equal(bodyOf(answer), text)
      const decisions = rows(h.store, 'proxy.decision')
      assert.deepEqual(decisions[0]?.['stage'], 'policy')
      assert.deepEqual(decisions.slice(1).flatMap((r) => [r['stage'], r['verdict'], r['refusal'], r['sent']]), upstreamRow)
      // The channel is read on: a second flow is served.
      assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://registry.npmjs.org/react'))), 200)
      // No flow is left open, so nothing idles.
      h.clock.advance(LIMITS.idleMs)
      assert.equal(await settledYet(h.session), false, 'the grant was revoked once idleMs passed')
      const outcome = await h.end('exited')
      assert.deepEqual([outcome.reason, outcome.totals.flows, outcome.totals.requests], ['exited', 2, 2])
      assert.deepEqual(h.kills, [])
    })
  }
})

test('an upstream answer whose head node:http will not write is answered 502, counted failed and recorded as response-head, never a bare allow', async (t) => {
  const h = harness(t, { serve: ODD_STATUS })
  await h.mux.handshake()
  const answer = await h.mux.exchange(http('GET', FETCH))
  assert.equal(statusOf(answer), 502, answer)
  assert.equal(bodyOf(answer), 'egress: the upstream answered with a head the session cannot pass on\n')
  assert.doesNotMatch(answer, /Odd/)
  assert.equal(h.seen.length, 1)
  // The host read the request and answered: its allow row stands, and an
  // upstream row says the answer could not be passed on.
  const decisions = rows(h.store, 'proxy.decision')
  assert.deepEqual(
    decisions.map((r) => [r['stage'], r['verdict'], r['refusal'], r['sent'], r['bindingId']]),
    [
      ['policy', 'allow', undefined, undefined, 'github'],
      ['upstream', 'allow', 'response-head', true, 'github'],
    ],
  )
  assert.equal(decisions[1]?.['why'], 'the host answered HTTP 99 with a head the session cannot pass on')
  for (const row of decisions) assert.equal(PAYLOAD_SCHEMAS['proxy.decision'].safeParse(row).success, true)
  const outcome = await h.end('exited')
  assert.deepEqual([outcome.totals.requests, outcome.totals.allowed, outcome.totals.refused, outcome.totals.failed], [1, 1, 0, 1])
})

test('an upstream answer that breaks off mid-body reaches the worker as a cut flow, never a clean end', async (t) => {
  const h = harness(t, {
    serve: (req, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': '100' })
      res.write('partial')
      setImmediate(() => req.socket.destroy())
    },
  })
  await h.mux.handshake()
  const side = h.mux.open()
  side.hangUpOnEnd = false
  side.write(http('GET', FETCH))
  await until(() => side.kernelClosed, 'the cut')
  assert.equal(side.kernelEnded, false, 'the kernel ended a flow whose answer broke off: the worker would read it as whole')
  assert.match(side.text(), /^HTTP\/1\.1 200/)
  await h.end('exited')
})

test('a revocation while a request is upstream aborts it, and its upstream row comes before the revocation', async (t) => {
  const h = harness(t, { serve: () => undefined })
  await h.mux.handshake()
  const side = h.mux.open()
  side.write(http('GET', FETCH))
  await until(() => h.seen.length === 1, 'the host to read the request')
  // The caller ends the grant while the channel is still open: the request
  // is aborted at once, and the revocation waits for the channel at most
  // END_DRAIN_MS.
  const ending = h.session.end('wallclock')
  await until(() => rows(h.store, 'proxy.decision').length === 2, 'the aborted request to record how it ended')
  assert.equal(await settledYet(h.session), false)
  h.clock.advance(END_DRAIN_MS)
  const outcome = await ending
  assert.equal(outcome.reason, 'wallclock')
  assert.deepEqual(
    readAllRows(h.store.db).map((r) => {
      const payload = JSON.parse(r.payload) as Row
      return [r.type, payload['stage'], payload['refusal'], payload['sent']]
    }),
    [
      ['proxy.decision', 'policy', undefined, undefined],
      // It left, so the host may have acted on it: an allow that failed, never a deny.
      ['proxy.decision', 'upstream', 'aborted', true],
      ['proxy.grant.revoked', undefined, undefined, undefined],
    ],
  )
  assert.deepEqual([outcome.totals.allowed, outcome.totals.refused, outcome.totals.failed], [1, 0, 1])
  assert.deepEqual(h.kills, [], 'end() killed what its caller already ended')

  // The session revoking the grant itself (a broken frame) while a request
  // is upstream aborts it in the same breath, and waits for it to record how
  // it ended before the revocation is appended.
  const broken = harness(t, { serve: () => undefined })
  await broken.mux.handshake()
  broken.mux.open().write(http('GET', FETCH))
  await until(() => broken.seen.length === 1, 'the host to read the request')
  broken.mux.raw(Uint8Array.of(0, 0, 0, 0, 0x7f, 0, 0, 0, 0))
  const violated = await doneOf(broken.session)
  assert.equal(violated.reason, 'violation')
  assert.deepEqual(
    readAllRows(broken.store.db).map((r) => {
      const payload = JSON.parse(r.payload) as Row
      return [r.type, payload['stage'], payload['refusal'], payload['sent']]
    }),
    [
      ['proxy.decision', 'policy', undefined, undefined],
      ['proxy.decision', 'upstream', 'aborted', true],
      ['proxy.grant.revoked', undefined, undefined, undefined],
    ],
  )
  assert.deepEqual(broken.kills, [1])

  // The container's stdout ending while a request is upstream (the mux is
  // gone, and nothing would read the answer) aborts it at once, before the
  // caller's end() comes: the grant is not revoked yet, but the request no
  // longer runs.
  const gone = harness(t, { serve: () => undefined })
  await gone.mux.handshake()
  gone.mux.open().write(http('GET', FETCH))
  await until(() => gone.seen.length === 1, 'the host to read the request')
  gone.mux.input.end()
  await until(() => rows(gone.store, 'proxy.decision').length === 2, 'the request to be aborted once the input ended')
  assert.equal(await settledYet(gone.session), false, 'the input ending revoked the grant before the caller ended it')
  const goneOutcome = await gone.session.end('exited')
  assert.equal(goneOutcome.reason, 'exited')
  assert.deepEqual(
    readAllRows(gone.store.db).map((r) => {
      const payload = JSON.parse(r.payload) as Row
      return [r.type, payload['stage'], payload['refusal'], payload['sent']]
    }),
    [
      ['proxy.decision', 'policy', undefined, undefined],
      ['proxy.decision', 'upstream', 'aborted', true],
      ['proxy.grant.revoked', undefined, undefined, undefined],
    ],
  )
  assert.deepEqual(gone.kills, [])
})

test('a revocation while a request body is still being read cuts its flow: nothing is judged, and the revocation does not wait on it', async (t) => {
  // A push whose command list is half sent: the session is reading it for
  // decide(), and nothing more comes. A revocation that left the flow open
  // would wait for ever on a read that never finishes, the request in hand,
  // with no revocation recorded and W1's end() never returning.
  const whole = push(commandList([[OLD, NEW, `refs/heads/aos/${RUN}/fix`]]))
  const half = whole.slice(0, whole.indexOf('\r\n\r\n') + 4 + 20)
  const broken = Uint8Array.of(0, 0, 0, 0, 0x7f, 0, 0, 0, 0)
  const ends: ReadonlyArray<readonly [string, (h: Harness) => void, SessionRevokeReason, readonly number[]]> = [
    ['the caller ends it', (h) => void h.end('requested'), 'requested', []],
    ['a broken frame ends it', (h) => h.mux.raw(broken), 'violation', [1]],
    // The read of the command list completes inside the session's read of
    // that chunk, and the broken frame after it begins the revocation before
    // the request is judged: it is judged, recorded and sent never.
    [
      'the frame that completes the command list and a broken frame arrive in one chunk',
      (h) => h.mux.raw(Buffer.concat([encodeFrame({ type: 'data', flow: 1, payload: bytes(whole.slice(half.length)) }), broken])),
      'violation',
      [1],
    ],
  ]
  for (const [label, endIt, reason, kills] of ends) {
    await t.test(label, async (t) => {
      const h = harness(t, { grant: ALL })
      await h.mux.handshake()
      const side = h.mux.open()
      side.hangUpOnEnd = false
      side.write(half)
      await until(() => h.mux.input.readableLength === 0, 'the session to read the half-sent push')
      await ticks()
      assert.equal(await settledYet(h.session), false)
      endIt(h)
      const outcome = await doneOf(h.session)
      assert.equal(outcome.reason, reason)
      assert.deepEqual(h.kills, kills)
      // Nothing was judged: the body decide() needs never arrived whole.
      assert.deepEqual(rows(h.store, 'proxy.decision'), [])
      assert.deepEqual(readAllRows(h.store.db).map((r) => r.type), ['proxy.grant.revoked'])
      assert.deepEqual(h.upstreamCalls, [])
      assert.deepEqual([outcome.totals.flows, outcome.totals.requests], [1, 0])
    })
  }
})

test('CONNECT is denied use-route with a 403, and a second request on one flow cuts it before it is judged', async (t) => {
  const h = harness(t)
  await h.mux.handshake()
  const connect = await h.mux.exchange(http('CONNECT', 'github.com:443', [['Host', 'github.com:443']]))
  assert.equal(statusOf(connect), 403, connect)
  // Two requests in one write: the second cuts the flow, and only the first is judged.
  const piped = h.mux.open()
  piped.write(http('GET', 'http://example.com/a') + http('GET', 'http://example.com/b'))
  await until(() => piped.kernelClosed, 'the pipelined flow')
  const outcome = await h.end('exited')
  assert.equal(outcome.totals.requests, 2)
  assert.equal(outcome.totals.denied, 2)
})

test('end() records one revocation after every decision, with totals that add up; stdout, stderr and exit are kept; a cut stream is a violation only when the container exited', async (t) => {
  const h = harness(t, { grant: ALL })
  await h.mux.handshake()
  h.mux.send({ type: 'stdout', flow: 0, payload: bytes('hello ') })
  h.mux.send({ type: 'stdout', flow: 0, payload: bytes('world') })
  h.mux.send({ type: 'stderr', flow: 0, payload: bytes('warn') })
  assert.equal(statusOf(await h.mux.exchange(http('GET', FETCH))), 200)
  assert.equal(statusOf(await h.mux.exchange(http('GET', 'http://example.com/'))), 403)
  h.mux.send({ type: 'exit', flow: 0, payload: exitPayload(3) })
  await new Promise((resolve) => setImmediate(resolve))
  // A reason the revocation schema has no name for is refused, not recorded as one.
  assert.throws(() => void h.session.end('killed' as never), /no end reason killed/)
  const outcome = await h.end('exited')
  assert.equal(await h.session.end('wallclock'), outcome)
  assert.equal(outcome.reason, 'exited')
  assert.equal(outcome.exitStatus, 3)
  assert.equal(Buffer.from(outcome.stdout).toString('utf8'), 'hello world')
  assert.equal(Buffer.from(outcome.stderr).toString('utf8'), 'warn')
  assert.equal(outcome.stdoutTruncated, false)
  const all = readAllRows(h.store.db)
  assert.equal(all.at(-1)?.type, 'proxy.grant.revoked')
  assert.equal(all.filter((r) => r.type === 'proxy.grant.revoked').length, 1)
  const { totals } = outcome
  assert.equal(totals.flows, 2)
  assert.equal(totals.requests, totals.allowed + totals.denied)
  assert.deepEqual([totals.allowed, totals.denied, totals.refused, totals.failed], [1, 1, 0, 0])
  assert.equal(totals.receivedBytes, 'upstream-ok'.length)

  for (const [reason, expected] of [['exited', 'violation'], ['wallclock', 'wallclock']] as const) {
    const cut = harness(t)
    await cut.mux.handshake()
    cut.mux.raw(Uint8Array.of(0, 0, 0))
    cut.mux.input.end()
    await new Promise((resolve) => setImmediate(resolve))
    const ended = await cut.session.end(reason)
    assert.equal(ended.reason, expected, reason)
    if (expected === 'violation') assert.match(ended.detail ?? '', /truncated-header/)
    assert.deepEqual(cut.kills, [], 'a container that already ended was killed again')
  }
})

test("end() keeps reading the channel until its input ends: the command's last frames are kept, nothing is served after the call, and an input that never ends is waited for END_DRAIN_MS", async (t) => {
  // W1 may act on the child's 'exit' before its stdout has drained: the
  // frames still in the pipe are the command's last output and its status.
  const h = harness(t)
  await h.mux.handshake()
  const ending = h.session.end('exited')
  h.mux.send({ type: 'stdout', flow: 0, payload: bytes('last line') })
  // A request still in the pipe is not served: the container is gone.
  const late = h.mux.open()
  late.write(http('GET', FETCH))
  h.mux.send({ type: 'stderr', flow: 0, payload: bytes('last warning') })
  h.mux.send({ type: 'exit', flow: 0, payload: exitPayload(7) })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(await settledYet(h.session), false, 'end() revoked before the channel ended')
  h.mux.input.end()
  const outcome = await doneOf(h.session)
  assert.equal(await ending, outcome)
  assert.equal(outcome.reason, 'exited')
  assert.equal(outcome.exitStatus, 7)
  assert.equal(Buffer.from(outcome.stdout).toString('utf8'), 'last line')
  assert.equal(Buffer.from(outcome.stderr).toString('utf8'), 'last warning')
  assert.deepEqual(h.upstreamCalls, [])
  assert.deepEqual(rows(h.store, 'proxy.decision'), [])
  assert.deepEqual(h.mux.kernelFrames, ['go'], 'the kernel sent a frame after end()')
  assert.deepEqual(h.kills, [])
  assert.equal(outcome.totals.requests, 0)

  // A stream that the container's own exit left inside a frame is judged once the input ends.
  const cut = harness(t)
  await cut.mux.handshake()
  const cutEnding = cut.session.end('exited')
  cut.mux.raw(Uint8Array.of(0, 0, 0))
  cut.mux.input.end()
  const cutOutcome = await cutEnding
  assert.equal(cutOutcome.reason, 'violation')
  assert.match(cutOutcome.detail ?? '', /truncated-header/)
  assert.deepEqual(cut.kills, [], 'a container that already ended was killed again')

  // A channel that breaks the protocol after end() is a violation too, and is not killed again.
  const broken = harness(t)
  await broken.mux.handshake()
  const brokenEnding = broken.session.end('requested')
  broken.mux.raw(Uint8Array.of(0, 0, 0, 0, 0x7f, 0, 0, 0, 0))
  const brokenOutcome = await brokenEnding
  assert.equal(brokenOutcome.reason, 'violation')
  assert.match(brokenOutcome.detail ?? '', /unknown-type/)
  assert.deepEqual(broken.kills, [])

  // What a flow carries after end() is dropped unread, not judged or counted
  // against the session's own limits (maxBytes here): a flood of it changes
  // neither the reason nor what is recorded. The channel's own limits are
  // the next case's.
  const flood = harness(t, { limits: { maxBytes: 1_024 } })
  await flood.mux.handshake()
  const open = flood.mux.open()
  open.hangUpOnEnd = false
  await new Promise((resolve) => setImmediate(resolve))
  const floodEnding = flood.session.end('exited')
  open.write(http('GET', FETCH, [['X-Big', 'z'.repeat(4_000)]]))
  flood.mux.send({ type: 'open', flow: 2, payload: EMPTY })
  flood.mux.input.end()
  const floodOutcome = await floodEnding
  assert.deepEqual([floodOutcome.reason, floodOutcome.limit], ['exited', undefined])
  assert.deepEqual(flood.upstreamCalls, [])
  assert.deepEqual(flood.kills, [])

  // A frame past a channel limit after end() stops the read (the codec
  // decodes nothing after it), and the grant is revoked at once with the
  // caller's reason, never as the limit: frameMaxBytes, and an open past
  // maxFlows, which the flows the kernel cut count toward (it sends no close
  // once it ended, so a mux that closes its side and opens again reaches
  // it). The detail says the rest was not read; a violation still is one
  // (above), and nothing is killed.
  const oversize = harness(t, { limits: { frameMaxBytes: 16 } })
  await oversize.mux.handshake()
  void oversize.session.end('wallclock')
  oversize.mux.send({ type: 'stdout', flow: 0, payload: bytes('kept') })
  oversize.mux.raw(encodeFrame({ type: 'stdout', flow: 0, payload: new Uint8Array(17) }))
  oversize.mux.raw(encodeFrame({ type: 'exit', flow: 0, payload: exitPayload(0) }))
  const oversized = await doneOf(oversize.session)
  assert.deepEqual([oversized.reason, oversized.limit], ['wallclock', undefined])
  assert.match(oversized.detail ?? '', /^after end\(\), the channel refused a frame past frameMaxBytes, so nothing after it was read: /)
  assert.equal(Buffer.from(oversized.stdout).toString('utf8'), 'kept')
  assert.equal(oversized.exitStatus, undefined, 'a frame after the refused one was read')
  assert.deepEqual(oversize.kills, [])
  const [oversizeRow] = rows(oversize.store, 'proxy.grant.revoked')
  assert.deepEqual([oversizeRow?.['reason'], oversizeRow?.['limit']], ['wallclock', undefined])
  assert.equal(PAYLOAD_SCHEMAS['proxy.grant.revoked'].safeParse(oversizeRow).success, true)

  // A second end() while the first waits on the channel changes nothing:
  // the first caller's reason is the one a later channel limit records.
  const twice = harness(t, { limits: { frameMaxBytes: 16 } })
  await twice.mux.handshake()
  const first = twice.session.end('requested')
  assert.equal(twice.session.end('wallclock'), first)
  twice.mux.raw(encodeFrame({ type: 'stdout', flow: 0, payload: new Uint8Array(17) }))
  const twiceOutcome = await doneOf(twice.session)
  assert.deepEqual([twiceOutcome.reason, twiceOutcome.limit], ['requested', undefined])
  assert.match(twiceOutcome.detail ?? '', /^after end\(\), the channel refused a frame past frameMaxBytes/)
  assert.equal(rows(twice.store, 'proxy.grant.revoked')[0]?.['reason'], 'requested')
  assert.deepEqual(twice.kills, [])

  const reopened = harness(t, { limits: { maxFlows: 2 } })
  await reopened.mux.handshake()
  reopened.mux.open().hangUpOnEnd = false
  reopened.mux.open().hangUpOnEnd = false
  await ticks()
  void reopened.session.end('requested')
  for (const flow of [1, 2]) reopened.mux.raw(encodeFrame({ type: 'close', flow, payload: EMPTY }))
  reopened.mux.raw(encodeFrame({ type: 'open', flow: 3, payload: EMPTY }))
  const reopenedOutcome = await doneOf(reopened.session)
  assert.deepEqual([reopenedOutcome.reason, reopenedOutcome.limit], ['requested', undefined])
  assert.match(reopenedOutcome.detail ?? '', /past maxFlows/)
  assert.deepEqual(reopened.kills, [])
  assert.deepEqual(reopened.mux.kernelFrames, ['go'], 'the kernel sent a frame after end()')

  // An input that never ends: the revocation waits END_DRAIN_MS, no longer.
  const hung = harness(t)
  await hung.mux.handshake()
  const hungEnding = hung.session.end('wallclock')
  await new Promise((resolve) => setImmediate(resolve))
  hung.clock.advance(END_DRAIN_MS - 1)
  assert.equal(await settledYet(hung.session), false)
  hung.clock.advance(1)
  const hungOutcome = await doneOf(hung.session)
  assert.equal(await hungEnding, hungOutcome)
  assert.equal(hungOutcome.reason, 'wallclock')
  assert.equal(rows(hung.store, 'proxy.grant.revoked').length, 1)
})

test("SessionLimits holds kernel.yaml's egress.limits: the shipped values parse as they are, and each bound is config's", () => {
  const shipped = parseKernelConfig(parseYaml(readFileSync(`${REPO}/config/kernel.yaml`, 'utf8')), { repoRoot: REPO }).egress.limits
  assert.deepEqual(SessionLimits.parse(shipped), shipped)
  assert.deepEqual(Object.keys(SessionLimits.shape).sort(), [...PROXY_LIMITS].sort())
  for (const [name, max] of [['frameMaxBytes', 1_048_576], ['maxFlows', 256], ['maxHeaderBytes', 65_536], ['idleMs', MAX_TIMER_MS]] as const) {
    assert.equal(SessionLimits.safeParse({ ...LIMITS, [name]: max }).success, true, name)
    assert.equal(SessionLimits.safeParse({ ...LIMITS, [name]: max + 1 }).success, false, name)
    assert.equal(SessionLimits.safeParse({ ...LIMITS, [name]: 0 }).success, false, name)
  }
  // The frame type codes the tests write by hand are the codec's.
  assert.equal(FRAME_TYPE_CODES.open, 0x10)
})

test('a session refuses a grant it could not record, and options that are not what they say', (t) => {
  const store = withStore(t)
  const base = {
    grantId: GRANT_ID,
    grant: EXEC,
    limits: LIMITS,
    channel: { input: new PassThrough(), output: new PassThrough() },
    store,
    upstream: { request: () => Promise.reject(new Error('unused')) },
    credential: (() => undefined) as CredentialInjector,
    acceptReady: () => undefined,
    kill: () => undefined,
  }
  assert.throws(() => createEgressSession({ ...base, grantId: 'sk-abcdefghijklmnop' }), /shape of a credential/)
  assert.throws(() => createEgressSession({ ...base, agentId: 'ghp_' + 'a'.repeat(36) }), /shape of a credential/)
  // Every identifier the grant's rows may name: its run, a credential-free
  // host, and a route's binding, host and repositories. EgressGrant admits
  // each, so only the session's own check keeps a grant whose rows the store
  // would censor from running.
  const shaped = 'sk-abcdefghijklmnop'
  const route = { bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }
  const grants: ReadonlyArray<readonly [string, unknown]> = [
    ['the run', { runId: shaped, allow: [], routes: [] }],
    ['a credential-free host', { runId: RUN, allow: ['registry.npmjs.org', `${shaped}.example.com`], routes: [] }],
    ["a route's binding", { runId: RUN, allow: [], routes: [{ ...route, bindingId: shaped }] }],
    ["a route's host", { runId: RUN, allow: [], routes: [{ ...route, host: `${shaped}.example.com` }] }],
    ["a route's repository", { runId: RUN, allow: [], routes: [{ ...route, repos: ['op/fixture', `op/${shaped}`] }] }],
  ]
  for (const [what, grant] of grants) {
    const parsed = EgressGrant.parse(grant)
    assert.throws(() => createEgressSession({ ...base, grant: parsed }), /shape of a credential/, what)
  }
  // The same grant with plain identifiers runs.
  void createEgressSession({ ...base, grant: EgressGrant.parse({ runId: RUN, allow: ['registry.npmjs.org'], routes: [route] }) })
  assert.throws(() => createEgressSession({ ...base, grantId: 'grant id' }))
  assert.throws(() => createEgressSession({ ...base, limits: { ...LIMITS, idleMs: 0 } }))
  assert.throws(() => createEgressSession({ ...base, kill: undefined as unknown as () => void }), /kill must be a function/)
  assert.throws(() => createEgressSession({ ...base, channel: { input: {} as PassThrough, output: new PassThrough() } }), /stdout/)
})
