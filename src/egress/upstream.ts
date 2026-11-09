// The egress upstream (egress plan E2): resolve after allow, check every
// answer, dial the checked address.
//
// Contract: request() sends one HTTP/1.1 request, over TLS, to a host that
// decide() allowed, and hands back the response exactly as the host sent it.
// Every step that could take it somewhere else is closed:
//
//   * Only an allow is resolved, once, for the request it was minted over.
//     A target that is not an EgressAllow decide() minted (decision.ts: a
//     deny, or a literal, a copy or a Proxy of an allow, is not one) is
//     refused before anything of it is read, so no getter or trap of a
//     caller's runs. An allow is spent when request() is called, before
//     anything else is checked, whatever then becomes of the request, and a
//     spent one is refused: one allow carries one request. Its host must be
//     an EgressHost in its one spelling (a caller that cast the brand away is
//     caught) and its port 443. The head must name the method and path the
//     allow was minted over, and exactly the Content-Type and
//     Content-Encoding decide() read (none where it read none), since they
//     say how the host decodes the body decide() judged; and the body must be
//     declared as decide() judged it (none, chunked, or the same length) and
//     begin with the leading bytes decide() read, if it read any: anything
//     else is refused as not decided. All of that is refused before any
//     resolver is made, and so is a head or a body the upstream will not
//     send. The name is resolved through a fresh node:dns Resolver per
//     request, which queries the configured DNS servers directly (c-ares):
//     never /etc/hosts, never mDNS, never a search domain.
//   * Every answer is checked, in both families, before anything is dialled.
//     A and AAAA are always both asked, and the request is refused when any
//     answer is denied by addr.ts (loopback, RFC 1918 and with it
//     192.168.5.2, CGNAT, link-local, unique-local, and the IPv4 carried in
//     IPv4-mapped, NAT64, 6to4 and Teredo addresses), not only the one that
//     would be dialled: a name that resolves to one public and one private
//     address is not a public host. A resolver failure other than "no such
//     record" refuses too, because an answer nobody saw cannot be checked.
//   * The Mac's own interface addresses are denied, read from
//     os.networkInterfaces() when the request is about to dial, never cached:
//     an address the Mac gains after boot (a SLAAC IPv6 address, a public
//     IPv4 on an interface) is one of its own as soon as it has it. An
//     answer is compared as addr.ts judges it, by value (any spelling) and by
//     the IPv4 address it carries. A list that cannot be read refuses, and so
//     does one that lists no address at all: a real one always holds
//     loopback, so an empty one is a read that went wrong, and with it the
//     Mac's own global addresses would go unchecked.
//   * The dial goes to the exact checked address: tls.connect is given the
//     IP literal as host, so net does no lookup, and a lookup function that
//     refuses, so a second lookup cannot happen even if one were asked for.
//     servername is the host, so the ClientHello names it and the
//     certificate is checked against it (tls.checkServerIdentity, named
//     explicitly); rejectUnauthorized is true, the trust store is Node's
//     own (no ca, cert, key or session is passed), TLS 1.2 is the floor, and
//     only http/1.1 is offered. A socket that reports itself unverified is
//     destroyed before a byte of the request is written.
//   * No agent, no pooling, no redirects. The request is made with node:http
//     over that one socket (createConnection, no Agent, Connection: close),
//     and the socket ends with its one response. A 3xx, a 401 or anything
//     else is handed back; nothing is followed, retried or re-sent, and a
//     second request needs a second allow, and resolves and dials again. The
//     response is read by node:http's strict parser whatever NODE_OPTIONS or
//     the command line says (--insecure-http-parser), so a host's ambiguous
//     framing (Content-Length beside Transfer-Encoding, a bad header token)
//     fails the request rather than being guessed at.
//   * One request, framed here. Host is the decided host, Connection is
//     close, and the body's framing is the upstream's: a head that names
//     Host, Connection, Content-Length, Transfer-Encoding, any other
//     hop-by-hop header or one header twice in two cases is refused, as are a
//     method that is not an upper-case token or is CONNECT and a path that is
//     not origin-form. Every body passes through a gate that takes bytes
//     only, so an objectMode body's object fails the request as a stream
//     error, in every framing, rather than throwing into whatever pushed it.
//     A body with a declared length is sent with that Content-Length and held
//     to it: a chunk that would carry it past the length destroys the request
//     before any byte of that chunk is written, and a body that ends short
//     destroys it too ('body-length'). So no byte past the declared body
//     reaches the verified connection, where the host would read it as a
//     second request on a path decide() never judged. A body with no declared
//     length is sent chunked, which node:http frames whatever the method. A
//     body whose leading bytes decide() judged is held until it has begun
//     with exactly those bytes; one that differs in any of them, or ends
//     first, destroys the request before its head or any of them is written.
//   * Checked once. The target, the head, the body and the signal are read
//     when request() is called, before it awaits anything, and the request
//     sent is the one checked: a caller that changes its head afterwards
//     changes nothing on the wire. The dependencies are read once too, when
//     the upstream is made, and frozen.
//   * Bounded in time. connectTimeoutMs bounds resolving, connecting and the
//     handshake together; once the handshake is done, idleTimeoutMs ends a
//     socket that carries no byte either way for that long. An AbortSignal
//     ends a request at any stage, and no request leaves a listener on it.
//   * Every failure is a refusal: request() never rejects. A dependency that
//     throws (a resolver that cannot be made or cancelled, an interface list,
//     a dialer, a socket), a dialer that returns no socket, and a target,
//     head or options that is no record or whose fields throw, are each
//     refused, named for where the throw landed, and a socket already dialled
//     is destroyed. The body is the upstream's from the call on: it is piped
//     into the request, or destroyed on any refusal, so a refused request
//     never leaves the caller's stream paused (see UpstreamCallOptions.body
//     for what that means for a caller that answers a refusal).
//   * A refusal says whether the request left. Before the exchange nothing
//     of the request is written; in it, node:http takes the head to send on
//     the first body chunk or at end(), the injected credential with it, and
//     a failure after that (the host going quiet, the connection closing, an
//     abort, a body breaking its length) refuses a request the host may have
//     read and acted on. `sent` says which, read from node:http
//     (ClientRequest.headersSent), so the log never calls a sent request a
//     deny.
//
// What this does not detect, and every one is global unicast and dialled:
// on an IPv6 network, every LAN peer's global address in an on-link prefix
// of the Mac's interfaces (the router's LAN side, which often serves its
// admin UI, a NAS, a printer, the operator's other machines); the router's
// WAN address, a NAT hairpin to its port-forwards; a network-specific NAT64
// prefix (RFC 6052) that a DNS64 resolver synthesises for a private A record;
// an RFC 5969 6rd prefix, which carries an IPv4 address under a prefix only
// the ISP knows. Denying every address inside an on-link prefix of the Mac's
// interfaces (their cidr, read at dial time), LAN peers included, is open
// with the operator; until it is answered this denies the Mac's own
// addresses only, as the plan accepted. The bound on all of them is the
// same: the dial is TLS with verification on and servername set to the
// allowed host, so a peer that cannot present a publicly trusted
// certificate for that name gets a TCP connect and a ClientHello, and no
// request byte, header or credential.
//
// Nothing here logs or decides: decide() (E3) judges the request and mints
// the EgressAllow this takes, and the session (E8) appends proxy.decision
// before calling request(). A refusal carries a reason from
// UPSTREAM_REFUSALS, whether the request was sent, and a clause that never
// holds the host, an answer or a header; the answer, when one is the reason,
// is in `address`, and an error's code in `code`, for the caller to bound and
// log.
//
// The resolver, the dialer and the interface list are injected
// (systemUpstreamDeps builds the real ones), so the tests drive every step
// offline. No TLS key or certificate exists anywhere in this repository:
// that verification succeeds against a real host is proven only live.

import { Resolver } from 'node:dns/promises'
import {
  request as httpRequest,
  validateHeaderName,
  validateHeaderValue,
  type ClientRequest,
  type IncomingMessage,
} from 'node:http'
import { BlockList, isIPv4, isIPv6, type LookupFunction } from 'node:net'
import { networkInterfaces, type NetworkInterfaceInfo } from 'node:os'
import { pipeline, Readable, Transform, Duplex, type TransformCallback } from 'node:stream'
import { checkServerIdentity, connect as tlsConnect } from 'node:tls'

import { addressDenial, carriedAddresses, type AddressDenial } from './addr.js'
import { EgressAllow } from './decision.js'
import { parseEgressHost, type EgressHost } from './host.js'

/** The one port egress dials. decide() refuses any other; this refuses it again. */
export const UPSTREAM_PORT = 443

/** Why a request never reached the upstream, or ended before its response. Stable: decisions and their log rows name these. */
export const UPSTREAM_REFUSALS = Object.freeze([
  'not-decided',
  'not-a-host',
  'port',
  'head',
  'aborted',
  'resolve-failed',
  'resolve-timeout',
  'no-address',
  'denied-address',
  'host-address',
  'interfaces-unreadable',
  'connect-failed',
  'connect-timeout',
  'unverified',
  'upstream-failed',
  'body-length',
  'idle-timeout',
] as const)
export type UpstreamRefusal = (typeof UPSTREAM_REFUSALS)[number]

/**
 * The refusals that can land after node:http took the request's head to send
 * (UpstreamRefused.sent): the connection failing or the host going quiet
 * before a response, an abort, and the body breaking its length or carrying
 * a chunk that is not bytes. Each of them can land before the head too. Every
 * other refusal is met before anything of the request is written, so its
 * `sent` is always false. Stable: proxy.decision rows are held to it.
 */
export const UPSTREAM_REFUSALS_AFTER_SEND = Object.freeze(['head', 'aborted', 'upstream-failed', 'body-length', 'idle-timeout'] as const satisfies readonly UpstreamRefusal[])

/**
 * Headers the upstream sets itself (host, connection, and the body's framing,
 * content-length and transfer-encoding) and the other hop-by-hop headers: a
 * head that names one, in any case, is refused rather than having it dropped,
 * so a caller that forgot to strip one learns it. Frozen: read on every
 * request.
 */
export const UPSTREAM_OWNED_HEADERS: readonly string[] = Object.freeze([
  'host',
  'connection',
  'content-length',
  'keep-alive',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/** What decide() allowed: an EgressAllow it minted over this request. Only one of an EgressHost, on port 443, is resolved, and only once. */
export type UpstreamTarget = EgressAllow

/**
 * The request as the session will send it: the worker's headers already
 * stripped and the credential already injected, and Content-Type and
 * Content-Encoding exactly as decide() read them (EgressAllow.content), or
 * absent where it read none. Host, Connection and the body's framing are the
 * upstream's (UPSTREAM_OWNED_HEADERS); the body and its length go in
 * UpstreamCallOptions.
 */
export interface UpstreamHead {
  readonly method: string
  /** Origin-form: a path and query, starting with one slash. */
  readonly path: string
  readonly headers: Readonly<Record<string, string>>
}

export interface UpstreamBody {
  /** Streamed with backpressure. */
  readonly stream: Readable
  /** In bytes: sent as Content-Length, and the stream is held to it. None sends the body chunked. */
  readonly length?: number
}

export interface UpstreamCallOptions {
  /**
   * The request body; none ends the request at its head. It must be declared
   * as decide() judged it (EgressAllow.body). The upstream owns the stream
   * from the call on: it is piped into the request, or destroyed on any
   * refusal, so the caller neither reads nor disposes of it after the call.
   *
   * Destroyed means destroyed, whatever the stream is. A caller that will
   * answer a refusal itself (the session's 502) must hand over a stream it
   * owns, such as a PassThrough the worker's IncomingMessage is fed into
   * with .pipe() (not pipeline(), which destroys its source with its
   * destination), never that IncomingMessage: destroying an IncomingMessage
   * whose body has not all arrived destroys its socket, and the worker reads
   * a reset where it waited for a status. Once the PassThrough is destroyed
   * the pipe is undone; the caller drains what is left (resume()) and
   * answers.
   */
  readonly body?: UpstreamBody
  /** Ends the request at any stage: resolving, dialling, or mid-response. */
  readonly signal?: AbortSignal
}

export interface UpstreamResponse {
  readonly ok: true
  /** The address dialled, one of the answers, every one of which was checked. */
  readonly address: string
  /** As the host sent it: a redirect, a 401, anything. The socket ends with it. */
  readonly response: IncomingMessage
}

export interface UpstreamRefused {
  readonly ok: false
  readonly reason: UpstreamRefusal
  /**
   * Whether the request may have reached the host: true once node:http took
   * its head to send (ClientRequest.headersSent), the injected credential
   * with it, so the host may have read it and acted on it; false when no
   * byte of it was written. Read from node:http, never guessed, and true
   * only with a refusal in UPSTREAM_REFUSALS_AFTER_SEND. A caller logs a
   * refusal with `sent` true as a request that left and failed, never as
   * one that was refused.
   */
  readonly sent: boolean
  /** A clause; never holds the host, an answer or a header. */
  readonly why: string
  /** The answer that is the reason (denied-address, host-address); set only when it is an address. */
  readonly address?: string
  /** addr.ts's denial of that answer (denied-address). */
  readonly denial?: AddressDenial
  /** The resolver's or the socket's error code (ETIMEOUT, ECONNREFUSED, CERT_HAS_EXPIRED), when there is one. */
  readonly code?: string
}

export type UpstreamResult = UpstreamResponse | UpstreamRefused

/** One request's resolver: node:dns/promises Resolver, or a test's. */
export interface UpstreamResolver {
  resolve4(name: string): Promise<string[]>
  resolve6(name: string): Promise<string[]>
  /** Ends this resolver's outstanding queries: a timeout or an abort. */
  cancel(): void
}

/** What the dialer returns: tls.connect's TLSSocket, or a test's. */
export interface UpstreamSocket extends Duplex {
  /** True only after the handshake verified the certificate against servername. */
  readonly authorized: boolean
  setTimeout(ms: number, callback?: () => void): unknown
}

/** Exactly what tls.connect is given. */
export interface DialOptions {
  /** The checked answer, an IP literal: net looks nothing up. */
  readonly host: string
  readonly port: number
  /** The allowed host: the ClientHello's SNI and the name the certificate must carry. */
  readonly servername: EgressHost
  readonly rejectUnauthorized: true
  readonly checkServerIdentity: typeof checkServerIdentity
  readonly minVersion: 'TLSv1.2'
  readonly ALPNProtocols: string[]
  /** Refuses: the address is already checked, and nothing may resolve it again. */
  readonly lookup: LookupFunction
}

export interface UpstreamLimits {
  /** Bounds resolving, connecting and the TLS handshake, together. */
  readonly connectTimeoutMs: number
  /** Ends a handshaken socket that carries no byte either way for this long. */
  readonly idleTimeoutMs: number
}

export interface UpstreamDeps extends UpstreamLimits {
  /** A fresh resolver per request, so a timeout cancels only that request's queries. */
  readonly resolver: () => UpstreamResolver
  readonly dial: (options: DialOptions) => UpstreamSocket
  /** Read when a request is about to dial, never cached. */
  readonly interfaces: () => NodeJS.Dict<NetworkInterfaceInfo[]>
}

export interface Upstream {
  /** Never rejects: every failure, a throw included, is an UpstreamRefused. Spends the target. */
  request(target: UpstreamTarget, head: UpstreamHead, options?: UpstreamCallOptions): Promise<UpstreamResult>
}

/** setTimeout's ceiling: a longer delay fires at once. */
const MAX_TIMER_MS = 2_147_483_647

/** A path longer than this is no request a bound route has a use for. */
const MAX_PATH = 8192

/** The resolver codes that mean the name has no record of that family: an answer, not a failure. */
const NO_RECORD: ReadonlySet<string> = new Set(['ENODATA', 'ENOTFOUND'])

function refused(
  reason: UpstreamRefusal,
  why: string,
  extra: { readonly address?: string | undefined; readonly denial?: AddressDenial; readonly code?: string | undefined; readonly sent?: boolean } = {},
): UpstreamRefused {
  return Object.freeze({
    ok: false as const,
    reason,
    // Only the exchange can say true: everything before it writes nothing of the request.
    sent: extra.sent === true,
    why,
    ...(extra.address === undefined ? {} : { address: extra.address }),
    ...(extra.denial === undefined ? {} : { denial: extra.denial }),
    ...(extra.code === undefined ? {} : { code: extra.code }),
  })
}

/**
 * What an error's code may be to be passed on (UpstreamRefused.code): upper
 * case and bounded, as ETIMEOUT, ECONNREFUSED and CERT_HAS_EXPIRED are.
 * proxy.decision's `code` takes exactly this shape (src/events/types.ts
 * EGRESS_ERROR_CODE, held equal by test/events-types.test.ts), so every code
 * passed on can be recorded.
 */
export const ERROR_CODE = /^[A-Z][A-Z0-9_]{0,63}$/

/** An error's code when it is one (ERROR_CODE), never its message, which may hold a host or an address. */
function errorCode(e: unknown): string | undefined {
  if (typeof e !== 'object' || e === null || !('code' in e)) return undefined
  const { code } = e
  return typeof code === 'string' && ERROR_CODE.test(code) ? code : undefined
}

function checkTarget(target: unknown): { readonly ok: true; readonly allow: EgressAllow; readonly host: EgressHost } | UpstreamRefused {
  // First, and reading nothing of the target: a literal that says allow is
  // no proof decide() said it, and a getter or a Proxy trap of a caller's
  // must not run. A deny is never minted, so it is refused here too.
  if (!EgressAllow.is(target)) {
    return refused('not-decided', 'the target is not an allow decide() minted, so no allowlist is known to have judged it')
  }
  // Spent now, before anything else is checked: one allow carries one
  // request, whatever becomes of this one.
  if (!EgressAllow.spend(target)) {
    return refused('not-decided', 'the allow has already carried a request, and an allow is good for one')
  }
  // The allow's own frozen fields, read once.
  const host: unknown = target.host
  const parsed = typeof host === 'string' ? parseEgressHost(host) : undefined
  // A fixed point of the normaliser, not merely something it accepts: a host
  // in another spelling is one nothing compared against the allowlist.
  if (parsed === undefined || !parsed.ok || parsed.host !== host) {
    return refused('not-a-host', 'the host is not an egress host in its one spelling, so no allowlist judged it')
  }
  if (target.port !== UPSTREAM_PORT) return refused('port', `the port is not ${String(UPSTREAM_PORT)}, the only one egress dials`)
  return { ok: true, allow: target, host: parsed.host }
}

/** The body as request() was called with it, read once. */
interface TakenBody {
  readonly stream: unknown
  readonly length: unknown
}

/** A body the upstream will send: a stream, and the length it is held to, or none (chunked). */
interface SendableBody {
  readonly stream: Readable
  readonly length: number | undefined
}

/**
 * The request as checked, read once from the caller's objects and frozen: the
 * exchange sends this and reads nothing of the caller's again, so a head
 * changed after request() was called changes nothing on the wire.
 */
interface Prepared {
  readonly ok: true
  readonly method: string
  readonly path: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: SendableBody | undefined
}

function checkHead(head: UpstreamHead, host: EgressHost, taken: TakenBody | undefined): Prepared | UpstreamRefused {
  if (typeof head !== 'object' || head === null) return refused('head', 'the head is not a record')
  const method: unknown = head.method
  const path: unknown = head.path
  const given: unknown = head.headers
  if (typeof method !== 'string' || !/^[A-Z]{1,16}$/.test(method) || method === 'CONNECT') {
    return refused('head', 'the method is not an upper-case token, or is CONNECT, which the upstream never sends')
  }
  if (typeof path !== 'string' || path.length > MAX_PATH || !/^\/[\x21-\x7e]*$/.test(path)) {
    return refused('head', 'the path is not origin-form: one slash, then printable ASCII with no space, bounded')
  }
  if (typeof given !== 'object' || given === null) return refused('head', 'the head has no header record')
  let body: SendableBody | undefined
  if (taken !== undefined) {
    const { stream, length } = taken
    if (!(stream instanceof Readable)) return refused('head', 'the body is not a readable stream')
    if (length !== undefined && (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0)) {
      return refused('head', "the body's declared length is not a whole number of bytes")
    }
    body = Object.freeze({ stream, length })
  }
  // Null-prototype: a header named __proto__ is a header, not a prototype.
  const headers: Record<string, string> = Object.create(null) as Record<string, string>
  headers['host'] = host
  const seen = new Set<string>()
  for (const [name, value] of Object.entries(given)) {
    const lower = name.toLowerCase()
    if (UPSTREAM_OWNED_HEADERS.includes(lower)) {
      return refused('head', "the head names a header the upstream sets itself (Host, Connection, the body's framing) or a hop-by-hop header")
    }
    // Two spellings of one header: node:http would send only the last, so
    // which one reached the host would depend on the order of a record.
    if (seen.has(lower)) return refused('head', 'the head names one header twice, in two cases')
    seen.add(lower)
    try {
      if (typeof value !== 'string') throw new TypeError('not a string')
      validateHeaderName(name)
      validateHeaderValue(name, value)
    } catch {
      return refused('head', 'the head has a header name or value HTTP does not allow')
    }
    headers[name] = value
  }
  // The body's framing is the upstream's: a declared length is sent as it is
  // and the body held to it; no length is chunked, which node:http frames
  // even for a GET (with neither, it would write a GET's body bare).
  if (body !== undefined) {
    if (body.length === undefined) headers['transfer-encoding'] = 'chunked'
    else headers['content-length'] = String(body.length)
  }
  headers['connection'] = 'close'
  return Object.freeze({
    ok: true as const,
    method,
    path,
    headers: Object.freeze(headers),
    body,
  })
}

/** A header's value in a checked head, by lower-case name: checkHead admits each name in one case only. */
function headerValue(headers: Readonly<Record<string, string>>, lower: string): string | undefined {
  for (const [name, value] of Object.entries(headers)) if (name.toLowerCase() === lower) return value
  return undefined
}

/**
 * The request as checked is the one the allow was minted over: its method
 * and path, its content headers, and its body declared as decide() judged
 * it. Then the leading bytes decide() judged, if any, which the exchange
 * holds the body to.
 */
function matchAllow(allow: EgressAllow, prepared: Prepared): { readonly ok: true; readonly leading: Buffer | undefined } | UpstreamRefused {
  if (prepared.method !== allow.method || prepared.path !== allow.path) {
    return refused('not-decided', 'the head is not the request the allow was minted over: decide() judged another method or path')
  }
  // Exactly the values decide() read, and none where it read none: a
  // Content-Encoding added after the judging would have the host decode the
  // body into bytes nobody judged, and another Content-Type would have it
  // read them as another kind of request.
  if (headerValue(prepared.headers, 'content-type') !== allow.content.type) {
    return refused('not-decided', "the head's Content-Type is not the one decide() judged (or it names one where decide() judged none, or the reverse)")
  }
  if (headerValue(prepared.headers, 'content-encoding') !== allow.content.encoding) {
    return refused('not-decided', "the head's Content-Encoding is not the one decide() judged (or it names one where decide() judged none, or the reverse)")
  }
  const judged = allow.body
  const { body } = prepared
  if ((judged === undefined) !== (body === undefined)) {
    return refused('not-decided', 'the request carries a body where decide() judged none, or none where it judged one')
  }
  if (judged !== undefined && body !== undefined && judged.length !== body.length) {
    return refused('not-decided', "the body's declared length is not the one decide() judged (or it is chunked where decide() judged a length, or the reverse)")
  }
  if (judged === undefined || judged.leadingBytes === 0) return { ok: true, leading: undefined }
  const leading = EgressAllow.leadingOf(allow)
  if (leading?.length !== judged.leadingBytes) {
    return refused('not-decided', 'the allow does not hold the leading bytes it says decide() judged')
  }
  return { ok: true, leading: Buffer.from(leading.buffer, leading.byteOffset, leading.byteLength) }
}

/** The call as checked: what the dial and the exchange use, and nothing of the caller's but the body stream. */
interface Call {
  readonly ok: true
  readonly host: EgressHost
  readonly prepared: Prepared
  /** The bytes the body must begin with: the ones decide() judged. */
  readonly leading: Buffer | undefined
  readonly signal: AbortSignal | undefined
}

/** How far a request got: what a throw there is refused as, and what it leaves to dispose of. */
interface Progress {
  stage: 'call' | 'resolve' | 'dial' | 'exchange'
  /** The caller's body stream, once read: the upstream's from then on. */
  stream: Readable | undefined
  /** The dialled socket, once the dialer returned one. */
  socket: UpstreamSocket | undefined
  /**
   * The request, once node:http made one: whether it took the head to send is
   * what a throw in the exchange reports as sent. Defensive: nothing that can
   * throw synchronously follows the head being taken today (req.end() and
   * pipeline() are the last calls the exchange makes, and node:http stores
   * the head inside them), so this reads false on every path the suite can
   * reach, and a mutant of it is equivalent. It is kept so that a later step
   * after the head cannot record a request that left as one that never did.
   */
  request: ClientRequest | undefined
}

/**
 * Reads the call once, before anything is awaited. The target first, reading
 * nothing of a target that is not an allow and spending one that is; then
 * the options, so the body is the upstream's (at.stream) before any refusal
 * of the target, the head or the body is returned; then the head.
 */
function readCall(target: UpstreamTarget, head: UpstreamHead, options: UpstreamCallOptions, at: Progress): Call | UpstreamRefused {
  const checked = checkTarget(target)
  // A refused target is the reason, even when the options are bad too.
  const or = (refusal: UpstreamRefused): UpstreamRefused => (checked.ok ? refusal : checked)
  if (typeof options !== 'object' || options === null) return or(refused('head', 'the call options are not a record'))
  // The body before the signal: a signal that throws still leaves a stream
  // to dispose of.
  const { body } = options
  let taken: TakenBody | undefined
  if (body !== undefined) {
    if (typeof body !== 'object' || body === null) return or(refused('head', 'the body is not a record'))
    // The stream before its length: a length that throws still leaves a
    // stream to dispose of.
    const stream: unknown = body.stream
    if (stream instanceof Readable) at.stream = stream
    const length: unknown = body.length
    taken = { stream, length }
  }
  const signal: unknown = options.signal
  if (!checked.ok) return checked
  if (signal !== undefined && !(signal instanceof AbortSignal)) return refused('head', 'the signal is not an AbortSignal')
  const prepared = checkHead(head, checked.host, taken)
  if (!prepared.ok) return prepared
  const matched = matchAllow(checked.allow, prepared)
  if (!matched.ok) return matched
  return Object.freeze({ ok: true as const, host: checked.host, prepared, leading: matched.leading, signal })
}

type Answers = { readonly ok: true; readonly v4: readonly string[]; readonly v6: readonly string[] }

function answersOf(settled: PromiseSettledResult<unknown>, family: 'A' | 'AAAA'): { readonly ok: true; readonly list: readonly string[] } | UpstreamRefused {
  if (settled.status === 'rejected') {
    const code = errorCode(settled.reason)
    if (code !== undefined && NO_RECORD.has(code)) return { ok: true, list: [] }
    return refused('resolve-failed', `the ${family} lookup failed, and an answer nobody saw cannot be checked`, { code })
  }
  const list: unknown = settled.value
  if (!Array.isArray(list) || !list.every((answer): answer is string => typeof answer === 'string')) {
    return refused('resolve-failed', `the ${family} lookup answered something that is not a list of addresses`)
  }
  return { ok: true, list }
}

async function resolveBoth(resolver: UpstreamResolver, host: EgressHost): Promise<Answers | UpstreamRefused> {
  // Both families, always: every answer is checked, not only the one that
  // would be dialled. Each call is wrapped so a resolver that throws rather
  // than rejecting is a failed lookup, not an escaped exception.
  const [a, aaaa] = await Promise.allSettled([
    (async () => resolver.resolve4(host))(),
    (async () => resolver.resolve6(host))(),
  ])
  const v4 = answersOf(a, 'A')
  if (!v4.ok) return v4
  const v6 = answersOf(aaaa, 'AAAA')
  if (!v6.ok) return v6
  if (v4.list.length + v6.list.length === 0) return refused('no-address', 'the host has no A or AAAA record')
  return { ok: true, v4: v4.list, v6: v6.list }
}

type Own = { readonly ok: true; readonly has: (address: string) => boolean }

/**
 * The Mac's own addresses, read now. Fail closed: a list that cannot be read,
 * an entry that is no address, and a list that yields no address at all
 * refuse. A real list always holds loopback, so an empty one ({}, an
 * interface with no entries) is a read that went wrong, and with it every one
 * of the Mac's global addresses would go unchecked.
 */
function ownAddresses(read: () => NodeJS.Dict<NetworkInterfaceInfo[]>): Own | UpstreamRefused {
  const unreadable = (code?: string): UpstreamRefused =>
    refused('interfaces-unreadable', "the Mac's interface addresses could not be read, so an answer that is one of them cannot be told apart", { code })
  const v4 = new BlockList()
  const v6 = new BlockList()
  let listed = 0
  try {
    for (const entries of Object.values(read())) {
      for (const entry of entries ?? []) {
        const address: unknown = entry.address
        // A zone (fe80::1%en0) names the link, not the address.
        const [bare = ''] = typeof address === 'string' ? address.split('%') : []
        if (isIPv4(bare)) v4.addAddress(bare, 'ipv4')
        else if (isIPv6(bare)) v6.addAddress(bare, 'ipv6')
        else return unreadable()
        listed++
      }
    }
  } catch (e) {
    return unreadable(errorCode(e))
  }
  if (listed === 0) return unreadable()
  return {
    ok: true,
    // By value, not by spelling, and by the IPv4 address an IPv6 answer
    // carries, as addr.ts judges it: ::ffff:a.b.c.d is a.b.c.d.
    has: (address) =>
      isIPv4(address)
        ? v4.check(address, 'ipv4')
        : v6.check(address, 'ipv6') || carriedAddresses(address).some((carried) => v4.check(carried.address, 'ipv4')),
  }
}

/** Every answer allowed by addr.ts, of its own family, and none the Mac's own; then the one to dial. */
function checkAnswers(answers: Answers, read: () => NodeJS.Dict<NetworkInterfaceInfo[]>): { readonly ok: true; readonly address: string } | UpstreamRefused {
  const all: ReadonlyArray<readonly [address: string, isFamily: (text: string) => boolean]> = [
    ...answers.v4.map((address) => [address, isIPv4] as const),
    ...answers.v6.map((address) => [address, isIPv6] as const),
  ]
  for (const [address, isFamily] of all) {
    const denial = addressDenial(address)
    if (denial !== undefined) {
      return refused('denied-address', 'an answer is an address egress never dials, so the host is not a public one', {
        address: denial.reason === 'not-an-address' ? undefined : address,
        denial,
      })
    }
    if (!isFamily(address)) return refused('resolve-failed', 'an answer is an address of the other family')
  }
  const own = ownAddresses(read)
  if (!own.ok) return own
  for (const [address] of all) {
    if (own.has(address)) return refused('host-address', "an answer is one of the Mac's own interface addresses", { address })
  }
  // IPv4 first, then IPv6; one dial, to an address every answer beside it
  // was checked with.
  const [first] = [...answers.v4, ...answers.v6]
  if (first === undefined) return refused('no-address', 'the host has no A or AAAA record')
  return { ok: true, address: first }
}

/** A lookup that refuses: the address is a checked IP literal, and nothing may resolve the name again. */
const refuseLookup: LookupFunction = (_hostname, _options, callback) => {
  const e: NodeJS.ErrnoException = new Error('egress upstream: a second lookup was asked for; only the checked address is dialled')
  e.code = 'ERR_EGRESS_SECOND_LOOKUP'
  queueMicrotask(() => callback(e, '', 0))
}

function dialOptions(host: EgressHost, address: string): DialOptions {
  return {
    host: address,
    port: UPSTREAM_PORT,
    servername: host,
    rejectUnauthorized: true,
    checkServerIdentity,
    minVersion: 'TLSv1.2',
    ALPNProtocols: ['http/1.1'],
    lookup: refuseLookup,
  }
}

type Stopped = 'timeout' | 'aborted'

/** Resolves when the connect deadline passes or the signal aborts, whichever is first. */
function stopper(ms: number, signal: AbortSignal | undefined): { readonly stopped: Promise<Stopped>; readonly clear: () => void } {
  let clear = (): void => undefined
  const stopped = new Promise<Stopped>((resolve) => {
    const timer = setTimeout(() => resolve('timeout'), ms)
    const onAbort = (): void => resolve('aborted')
    signal?.addEventListener('abort', onAbort, { once: true })
    clear = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
    }
  })
  return { stopped, clear: () => clear() }
}

/** The handshake's end: verified or not, or the socket's failure. */
function handshake(socket: UpstreamSocket): Promise<{ readonly done: true } | { readonly done: false; readonly error: unknown }> {
  return new Promise((resolve) => {
    socket.once('secureConnect', () => resolve({ done: true }))
    socket.once('error', (error: unknown) => resolve({ done: false, error }))
    socket.once('close', () => resolve({ done: false, error: undefined }))
  })
}

/**
 * Passes on bytes and refuses anything else. Every body goes through it
 * first, in every framing, so a chunk that is not bytes (an objectMode body's
 * object) errors here, a stream error pipeline turns into a destroyed
 * request; written to node:http itself, it would throw into whatever pushed
 * it. A string is bytes in its encoding, as node:http would take it.
 */
function bytesOnly(refuse: () => void): Transform {
  return new Transform({
    writableObjectMode: true,
    // One chunk at a time on the object side, so backpressure still counts
    // in chunks of bytes, not in sixteen of them.
    writableHighWaterMark: 1,
    transform(chunk: unknown, encoding, callback) {
      if (chunk instanceof Uint8Array) return void callback(null, chunk)
      if (typeof chunk === 'string') return void callback(null, Buffer.from(chunk, Buffer.isEncoding(encoding) ? encoding : 'utf8'))
      refuse()
      callback(Object.assign(new Error('egress upstream: a body chunk is not bytes'), { code: 'ERR_EGRESS_BODY_CHUNK' }))
    },
  })
}

/**
 * Passes on exactly `length` bytes. A chunk that would carry the body past
 * them errors before any of it is passed on, and an end short of them errors
 * too; pipeline then destroys the request, so nothing past the declared body
 * is ever written, and a host still waiting for the rest sees the connection
 * end.
 */
function heldTo(length: number, mismatch: () => void): Transform {
  let passed = 0
  const fail = (callback: TransformCallback, why: string): void => {
    mismatch()
    callback(Object.assign(new Error(`egress upstream: ${why}`), { code: 'ERR_EGRESS_BODY_LENGTH' }))
  }
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      if (chunk.length > length - passed) return void fail(callback, 'the body is longer than its declared length')
      passed += chunk.length
      callback(null, chunk)
    },
    flush(callback) {
      if (passed !== length) return void fail(callback, 'the body ended short of its declared length')
      callback()
    },
  })
}

/**
 * Holds the body until it has begun with exactly `leading`, the bytes
 * decide() judged, then passes all of it on. Each chunk is compared as it
 * arrives, so a body that differs fails at the first byte that differs; one
 * that differs, or ends first, errors with none of what it held passed on.
 * Nothing having been written, neither the request's head nor any byte of a
 * body decide() did not judge reaches the host.
 */
function beginsWith(leading: Buffer, differs: () => void): Transform {
  const held: Buffer[] = []
  let matched = 0
  const fail = (callback: TransformCallback, why: string): void => {
    differs()
    callback(Object.assign(new Error(`egress upstream: ${why}`), { code: 'ERR_EGRESS_BODY_NOT_JUDGED' }))
  }
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      if (matched === leading.length) return void callback(null, chunk)
      const part = chunk.subarray(0, leading.length - matched)
      if (!part.equals(leading.subarray(matched, matched + part.length))) {
        return void fail(callback, 'the body does not begin with the bytes decide() judged')
      }
      matched += part.length
      held.push(chunk)
      if (matched < leading.length) return void callback()
      callback(null, Buffer.concat(held.splice(0)))
    },
    flush(callback) {
      if (matched !== leading.length) return void fail(callback, 'the body ended before the bytes decide() judged')
      callback()
    },
  })
}

type Ended = 'idle-timeout' | 'aborted' | 'body-length' | 'body-chunk' | 'not-judged'

/** One request over the handshaken socket, and its response. */
function exchange(socket: UpstreamSocket, address: string, call: Call, idleTimeoutMs: number, at: Progress): Promise<UpstreamResult> {
  const { prepared, leading, signal } = call
  return new Promise((resolve) => {
    let ended: Ended | undefined
    let settled = false
    const settle = (result: UpstreamResult): void => {
      if (settled) return
      settled = true
      resolve(result)
    }
    let req: ClientRequest | undefined
    // node:http stores the head on the first body chunk or at end(), and
    // writes nothing of the request before: from then on the host may have
    // it, the injected credential with it, so a failure past this point is
    // one the host may have acted on. A body held by beginsWith or heldTo
    // before its first chunk passes is never sent.
    const sent = (): boolean => req?.headersSent === true
    const failed = (code?: string): UpstreamRefused => {
      const after = { sent: sent() }
      switch (ended) {
        case undefined:
          return refused('upstream-failed', 'the connection failed or closed before a response arrived', { code, ...after })
        case 'aborted':
          return refused('aborted', 'the request was aborted', after)
        case 'idle-timeout':
          return refused('idle-timeout', 'the connection carried no byte for the idle timeout', after)
        case 'body-length':
          return refused('body-length', 'the body did not match its declared length, so the request was destroyed before any byte past it was written', after)
        case 'body-chunk':
          return refused('head', 'the body carried a chunk that is not bytes, so the request was destroyed', after)
        case 'not-judged':
          return refused('not-decided', 'the body does not begin with the bytes decide() judged, so the request was destroyed before its head or any of them was written', after)
      }
    }

    socket.setTimeout(idleTimeoutMs, () => {
      ended ??= 'idle-timeout'
      socket.destroy()
    })
    const onAbort = (): void => {
      ended ??= 'aborted'
      socket.destroy()
    }
    signal?.addEventListener('abort', onAbort, { once: true })
    socket.once('close', () => {
      // A signal the session keeps for a whole grant would otherwise gather
      // one listener per request.
      signal?.removeEventListener('abort', onAbort)
      // node:http reports a close before the response on the request, in this
      // same event and with its code; this settles one it did not see (a 101
      // to a request that asked for no upgrade: node:http destroys the socket
      // and says nothing), a turn later so that one wins.
      setImmediate(() => settle(failed()))
    })

    try {
      req = httpRequest({
        method: prepared.method,
        path: prepared.path,
        headers: prepared.headers,
        setHost: false,
        // Strict whatever NODE_OPTIONS or the command line says
        // (--insecure-http-parser): a host's ambiguous framing fails the
        // request rather than being guessed at.
        insecureHTTPParser: false,
        // No agent: this one socket, for this one request.
        createConnection: () => socket,
      })
    } catch (e) {
      socket.destroy()
      settle(refused('head', 'node:http refused the request head', { code: errorCode(e) }))
      return
    }
    at.request = req
    // With no agent the request is never kept alive: node:http ends the
    // socket when the response ends or is destroyed, and a response that
    // stalls is the idle timeout's.
    req.once('response', (response: IncomingMessage) => settle(Object.freeze({ ok: true as const, address, response })))
    // Not once: node:http reports every socket error on the request, after
    // the response has been handed over too (it reaches the response as an
    // abort), and a second error with no listener would end the kernel.
    req.on('error', (e: unknown) => {
      socket.destroy()
      settle(failed(errorCode(e)))
    })
    const { body } = prepared
    if (body === undefined) {
      req.end()
      return
    }
    // A body error destroys the request with it, which the error listener
    // above reports, or, after the response, the response sees as an abort.
    // Bytes only, first, in every framing; then held to the declared length;
    // then held until it begins with what decide() judged.
    const stages: Transform[] = [bytesOnly(() => (ended ??= 'body-chunk'))]
    if (body.length !== undefined) stages.push(heldTo(body.length, () => (ended ??= 'body-length')))
    if (leading !== undefined) stages.push(beginsWith(leading, () => (ended ??= 'not-judged')))
    pipeline([body.stream, ...stages, req], () => undefined)
  })
}

/** Read afresh at each call: an abort can land during any await, which narrowing does not see. */
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true
}

/** A dialer's result the upstream can drive: a Duplex with setTimeout, as tls.connect's TLSSocket is. */
function isSocket(value: unknown): value is UpstreamSocket {
  return value instanceof Duplex && 'setTimeout' in value && typeof value.setTimeout === 'function'
}

async function attempt(
  deps: UpstreamDeps,
  target: UpstreamTarget,
  head: UpstreamHead,
  options: UpstreamCallOptions,
  at: Progress,
): Promise<UpstreamResult> {
  const call = readCall(target, head, options, at)
  if (!call.ok) return call
  const { host, signal } = call
  if (isAborted(signal)) return refused('aborted', 'the request was aborted')

  at.stage = 'resolve'
  const stop = stopper(deps.connectTimeoutMs, signal)
  try {
    let resolver: UpstreamResolver
    try {
      resolver = deps.resolver()
    } catch (e) {
      return refused('resolve-failed', 'no resolver could be made, so the host cannot be resolved', { code: errorCode(e) })
    }
    const answers = await Promise.race([resolveBoth(resolver, host), stop.stopped])
    if (answers === 'timeout' || answers === 'aborted') {
      try {
        resolver.cancel()
      } catch (e) {
        return refused('resolve-failed', "the resolver's outstanding queries could not be cancelled", { code: errorCode(e) })
      }
      return answers === 'aborted'
        ? refused('aborted', 'the request was aborted')
        : refused('resolve-timeout', 'the host did not resolve within the connect timeout')
    }
    if (!answers.ok) return answers
    const dialled = checkAnswers(answers, deps.interfaces)
    if (!dialled.ok) return dialled

    let made: unknown
    try {
      made = deps.dial(dialOptions(host, dialled.address))
    } catch (e) {
      return refused('connect-failed', 'the dial failed', { code: errorCode(e) })
    }
    // Before a method of it is called: a dialer that returned no socket
    // (undefined, a plain object) is a failed dial, not a TypeError.
    if (!isSocket(made)) return refused('connect-failed', 'the dialer returned no socket')
    const socket = made
    at.socket = socket
    at.stage = 'dial'
    // Every error is reported, through the handshake, the check below or the
    // exchange; this listener keeps any number that land between them from
    // ending the kernel.
    let failure: unknown
    socket.on('error', (e: unknown) => {
      failure ??= e
    })
    const shaken = await Promise.race([handshake(socket), stop.stopped])
    if (shaken === 'timeout' || shaken === 'aborted') {
      socket.destroy()
      return shaken === 'aborted'
        ? refused('aborted', 'the request was aborted')
        : refused('connect-timeout', 'the connection and handshake did not finish within the connect timeout')
    }
    if (!shaken.done) {
      socket.destroy()
      return refused('connect-failed', 'the connection or the TLS handshake failed', { code: errorCode(shaken.error ?? failure) })
    }
    // rejectUnauthorized already destroys an unverified socket before this;
    // a dialer that did not is caught here, before a byte is written.
    if (socket.authorized !== true) {
      socket.destroy()
      return refused('unverified', 'the handshake finished without verifying the certificate against the host')
    }
    stop.clear()
    // An abort, an error or a close that lands after the handshake and before
    // this fires nothing the races above saw, and a socket destroyed now
    // would close before node:http listens for it: refuse here, before a
    // request exists, so nothing is written to that socket.
    if (isAborted(signal)) {
      socket.destroy()
      return refused('aborted', 'the request was aborted')
    }
    if (failure !== undefined || socket.destroyed) {
      socket.destroy()
      return refused('upstream-failed', 'the connection failed or closed after the handshake, before the request', { code: errorCode(failure) })
    }
    at.stage = 'exchange'
    return await exchange(socket, dialled.address, call, deps.idleTimeoutMs, at)
  } finally {
    stop.clear()
  }
}

/** A throw, refused for where it landed; `sent` is whether node:http had taken the request's head to send. */
function thrownAt(stage: Progress['stage'], code: string | undefined, sent: boolean): UpstreamRefused {
  switch (stage) {
    case 'call':
      return refused('head', 'the target, head or options could not be read: one is not a record, or a field of it threw', { code })
    case 'resolve':
      return refused('resolve-failed', 'resolving or checking the host threw', { code })
    case 'dial':
      return refused('connect-failed', 'the dialled socket threw before the request was made', { code })
    case 'exchange':
      return refused('upstream-failed', 'the request threw while it was being sent', { code, sent })
  }
}

async function send(deps: UpstreamDeps, target: UpstreamTarget, head: UpstreamHead, options: UpstreamCallOptions): Promise<UpstreamResult> {
  const at: Progress = { stage: 'call', stream: undefined, socket: undefined, request: undefined }
  let result: UpstreamResult
  try {
    // Everything the call is checked by is read in attempt's first, awaitless
    // stretch: what is checked is what is sent.
    result = await attempt(deps, target, head, options, at)
  } catch (e) {
    // Whatever the upstream touches may throw: a caller's head, options or
    // body (null, or a field that is a getter), a dialer's socket (an
    // authorized that throws), node:http itself. A rejection the session did
    // not await would end the kernel, so a throw is a refusal, named for the
    // stage it landed in, and a socket already dialled goes with it.
    at.socket?.destroy()
    result = thrownAt(at.stage, errorCode(e), at.request?.headersSent === true)
  }
  // The body is the upstream's from the call on: a refused request leaves no
  // stream paused for the life of the caller's flow. One already piped is
  // destroyed already, and destroying it again does nothing.
  if (!result.ok) at.stream?.destroy()
  return result
}

function assertLimit(name: keyof UpstreamLimits, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0 || value > MAX_TIMER_MS) {
    throw new TypeError(`egress upstream: ${name} must be a whole number of milliseconds from 1 to ${String(MAX_TIMER_MS)}, got ${String(value)}`)
  }
}

/**
 * The upstream, over injected dependencies. They are read once, here, into a
 * frozen snapshot, and checked: a caller that later writes to its own deps
 * object (idleTimeoutMs = 0 would turn the idle bound off, a new dial would
 * stand behind every check) changes nothing.
 */
export function createUpstream(deps: UpstreamDeps): Upstream {
  const d: UpstreamDeps = Object.freeze({
    resolver: deps.resolver,
    dial: deps.dial,
    interfaces: deps.interfaces,
    connectTimeoutMs: deps.connectTimeoutMs,
    idleTimeoutMs: deps.idleTimeoutMs,
  })
  for (const name of ['resolver', 'dial', 'interfaces'] as const) {
    if (typeof d[name] !== 'function') throw new TypeError(`egress upstream: ${name} must be a function`)
  }
  assertLimit('connectTimeoutMs', d.connectTimeoutMs)
  assertLimit('idleTimeoutMs', d.idleTimeoutMs)
  return Object.freeze({
    request: (target: UpstreamTarget, head: UpstreamHead, options: UpstreamCallOptions = {}) => send(d, target, head, options),
  })
}

/**
 * The real dependencies: a node:dns/promises Resolver per request (two tries,
 * each with a per-try timeout a third of the connect deadline: c-ares backs
 * off between them, so it gives up near the deadline that bounds the lookup
 * anyway, where its defaults would take seconds), tls.connect, and
 * os.networkInterfaces.
 */
export function systemUpstreamDeps(limits: UpstreamLimits): UpstreamDeps {
  assertLimit('connectTimeoutMs', limits.connectTimeoutMs)
  assertLimit('idleTimeoutMs', limits.idleTimeoutMs)
  const tryMs = Math.max(1, Math.floor(limits.connectTimeoutMs / 3))
  return Object.freeze({
    resolver: () => new Resolver({ timeout: tryMs, tries: 2 }),
    dial: tlsConnect,
    interfaces: networkInterfaces,
    connectTimeoutMs: limits.connectTimeoutMs,
    idleTimeoutMs: limits.idleTimeoutMs,
  })
}
