// The egress session (egress plan E8): one container's channel, routed.
//
// Contract: a sandboxed run reaches the network only through the stdin and
// stdout of its `docker run -i` child, and this is the kernel end of that
// one byte stream. One session is one grant: everything it records is
// attributed to the grant it was made with (runId, agentId, grantId), never to
// anything the container says. Everything the container writes is
// attacker-chosen (frame.ts says why the mux is no boundary), so:
//
//   * Frames are decoded by frame.ts's FrameChannel and nothing else. The
//     mux's ready is judged by the kernel's acceptReady before go is sent, so
//     a container whose self-test reached something it must not never gets
//     go, and its command never runs. Each open becomes one Duplex
//     (FlowSocket), fed to an http.Server that never listens: node:http's
//     strict parser (insecureHTTPParser off whatever NODE_OPTIONS says,
//     maxHeaderSize the grant's maxHeaderBytes) reads the worker's request, as
//     it would off a socket, and no port, address or listener exists.
//   * One request per flow. Every answer says Connection: close, and a flow
//     that carries a second request (pipelining) is cut before that request
//     is judged, so a flow holds at most one request in flight. A worker
//     that ends its side once its request is written (a half-close) is
//     answered, then the flow ends.
//   * Judged, then recorded, then sent. The head is read into ONE record,
//     built from rawHeaders (every value kept, in a null-prototype object:
//     node's headersDistinct throws on a header named `constructor` or
//     `__proto__`, and node's headers drops a second Content-Type), and
//     decide() and the upstream head both read only that record. When the
//     route judges the body's start (git-push's command list, github-pulls'
//     JSON), the session reads exactly what leadingNeed() asks, at most 64
//     KiB, and hands decide() those bytes. An allow's proxy.decision row is
//     appended before upstream.request() is called, so before anything is
//     resolved or dialled; an append that fails sends nothing. A deny is
//     answered 403 at once and never reaches the upstream. A decision row
//     the store refuses (the kernel's bug) is counted, whenever it is, and
//     the revocation's detail ends with the count (`<n> decision rows could
//     not be appended`). One refused while the grant is served, or while
//     end() waits on the channel, ends the grant in `error`, once the
//     request it judged is counted and answered 502, in that order, so the
//     revocation's totals hold it whenever it was made. One refused once the
//     revocation has begun (the upstream row of a request still in hand, a
//     deny of the window the revocation closes last) keeps the revocation's
//     reason, which already says why the grant ended; the count follows the
//     reason's own detail.
//   * Stripped, then injected. Of the worker's headers, every auth header
//     (Authorization, Proxy-Authorization, X-Api-Key and the rest of
//     REQUEST_STRIPPED), every cookie, every hop-by-hop header and every one a
//     Connection header names, the body's framing (the upstream frames it as
//     decide() judged it), Expect, every forwarding header (Forwarded, Via,
//     X-Forwarded-*, X-Real-IP and the like) and every header the upstream
//     sets or refuses itself (upstream.ts UPSTREAM_OWNED_HEADERS) are dropped,
//     each matched by the name a backend that folds names reads (policy.ts
//     canonicalHeaderName: Proxy_Authorization is Proxy-Authorization there),
//     as decide() reads every header. A Connection header that names one
//     decide() reads (Host, the framing, Content-Type, Content-Encoding)
//     refuses the request unsent (an upstream row naming `head`): dropping it
//     as hop-by-hop would send another record than the one judged. On a bound
//     route the kernel's CredentialInjector then sets exactly one header,
//     Authorization, through a setter it is handed: the session never holds a
//     SecretRef, never imports src/secrets (test/hygiene.test.ts pins both),
//     and refuses a request (not sent, an upstream row naming `head`) when the
//     injector sets none, two, another header or a value HTTP refuses. A
//     credential-free host gets no injection, and so no auth header at all:
//     exactly one on a bound route and none elsewhere, credentialedFetch's
//     rule (src/models/transport.ts).
//   * Answered without a prompt. An upstream 401 or 403 is answered 502, so
//     git never asks for a password, and recorded as an upstream row
//     (`challenged`, sent: the host read the request, and refused the
//     binding's credential, or a credential-free request); an answer whose
//     head node:http will not write to the worker (a status below 100) is
//     answered 502 and recorded the same way (`response-head`, sent); an
//     upstream refusal is answered 502 and recorded as an upstream row; a
//     response's Set-Cookie (a session minted for the operator's
//     credential), WWW-Authenticate, Proxy-Authenticate and hop-by-hop
//     headers are dropped. A response that breaks off mid-body cuts the
//     flow, so the worker reads a reset, never a short body as whole.
//   * Bounded per grant (SessionLimits, kernel.yaml's egress.limits):
//     frameMaxBytes and maxFlows by the channel; maxHeaderBytes by the
//     parser; maxRequests, flows opened (a flow carries at most one request,
//     so this bounds the requests, and a flow that never finished a head
//     costs one as well); maxDenied, denies; maxBytes, the flow bytes both
//     ways (every data frame's payload either way, heads included); and
//     idleMs, a channel that for that long carried none of the mux's flow
//     frames (an open, data, end or close), none of the kernel's data and
//     not the mux's ready, while the handshake is pending or a flow is open
//     (a command running with no flow open is the wallclock's, not this; the
//     kernel's own end and close of a flow are not the container's doing,
//     so they reset nothing). Passing one revokes the grant with
//     reason `limit` naming it, until the caller ends the session (below).
//   * Final on a violation. A frame the channel refuses, a ready the kernel
//     refuses, or a worker request node:http cannot parse (llhttp runs in the
//     kernel's process: a request that is not HTTP gets one try, whatever
//     llhttp refused it for) calls the kill callback once and revokes the
//     grant (`violation`, with the refusal's message as its detail); a frame
//     that breaks a limit, `limit` (until end(): see below). A worker that
//     hangs up mid-request, or writes past a request that said
//     Connection: close (cut as a pipelined second request is), is no
//     violation (its flow is cut): a head cut short is a hangup, so a
//     container may feed llhttp prefixes that never complete, at the cost
//     of a flow each, which maxRequests bounds, and of maxBytes.
//   * Deny rows are coalesced (events/types.ts ProxyDecisionPayload): denies
//     are held in a one-second window per grant and written when it closes,
//     one row per key (reason, decide()'s clause, host refusal, host, method,
//     binding) with its count, the path detail kept only on a row that stands
//     for one request; past PROXY_DENY_KEYS_PER_SECOND keys, the rest of the
//     window is counted on overflow rows, by reason and, for not-a-host,
//     use-route and second-host (PROXY_DENIES_BY_HOST_REFUSAL), host refusal,
//     so CONNECT 192.168.5.2:8766 is never counted with CONNECT
//     github.com:443. So a deny row can follow an allow row the worker sent
//     after it. A deny's host that the redaction pass would change (the
//     worker's text in a credential's shape) is recorded without it.
//   * Every decision before the revocation. Revoking stops every flow (no
//     frame is sent once it begins), aborts every upstream request, waits for
//     the requests in hand to append what they must, closes the deny window,
//     and only then appends proxy.grant.revoked, with the grant's totals.
//
// Who ends it: the session revokes on its own for a violation, a limit or a
// broken append (`error`), calling kill; otherwise the caller (the runner) calls
// end() with the driver's verdict on the container (exited, wallclock,
// requested, error). From that call on nothing is sent to the mux and no
// flow is served (every flow is cut, every upstream request aborted), but
// the channel is still read, until its input ends or END_DRAIN_MS pass,
// so the command's last stdout, stderr and exit frames are kept even when
// the caller acts on the child's 'exit' before its stdout has drained. A
// stream that ended inside a frame is a violation only when the container
// exited on its own: one the kernel killed is cut by the kill. A frame the
// channel refuses after the call is a violation still (recorded as one, and
// not killed again); one past a channel limit (frameMaxBytes, or an open
// past maxFlows, which the flows the kernel cut without a close still count
// toward) only stops the read: the grant is revoked at once with the
// caller's reason, its detail saying the rest was not read. The session's
// own limits no longer count: what a flow carries is dropped unread. Nothing
// here starts, stops or names a container; kill is the caller's. So is the
// wait for a container whose command has exited: the session tells the
// caller of the exit frame (`exited`), and the caller, which ends every
// container by a kill by name, bounds how long the container may run on
// after it (a flow held open by what the command left behind).
//
// Built by the sandbox runner (src/runtime/sandbox-tools.ts) for each exec
// grant, over that container's channel, once the grant is issued and before
// anything is awaited, and ended by it with the driver's verdict on the
// container (egress plan W1); and by the boot canary (src/runtime/canary.ts,
// egress plan W3) for the trusted domain's canary grant, which serves no run
// and reaches nothing, so its rows are appended under no run
// (SessionOptions.canary).

import {
  createServer,
  validateHeaderValue,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import type { Socket } from 'node:net'
import { Duplex, pipeline, Readable, Transform, Writable } from 'node:stream'
import { z } from 'zod'

import { KernelError } from '../errors.js'
import { recordable } from '../events/bound.js'
import { redactString } from '../events/redact.js'
import type { AppendInput } from '../events/store.js'
import {
  AGENT_SHAPE,
  EGRESS_DETAIL_BYTES,
  EGRESS_PATH_BYTES,
  EGRESS_WHY_BYTES,
  METHOD_SHAPE,
  PROXY_DENIES_BEFORE_PATH,
  PROXY_DENIES_BY_HOST_REFUSAL,
  PROXY_DENY_KEYS_PER_SECOND,
  PROXY_OVERFLOW_WHY,
} from '../events/types.js'
import { log } from '../log.js'
import { CAPTURE_MAX_BYTES } from '../sandbox/driver.js'
import { FRAME_MAX_BYTES_LIMIT, FrameChannel, FrameError, goPayload, MAX_FLOWS_LIMIT, type Frame, type FrameLimits, type ReceivedFrame } from './frame.js'
import { canonicalHeaderName, decide, EgressGrant, leadingNeed, type EgressAllowed, type EgressDenied, type EgressHeaders, type LeadingNeed } from './policy.js'
import { parseTarget, RUN_REF, type ParsedTarget, type RouteRefused } from './routes.js'
import { UPSTREAM_OWNED_HEADERS, type Upstream, type UpstreamBody, type UpstreamCallOptions, type UpstreamHead, type UpstreamRefused } from './upstream.js'

/** setTimeout's ceiling: a longer delay fires at once (config.ts MAX_TIMER_MS, held equal by test/egress-session.test.ts). */
const MAX_TIMER_MS = 2_147_483_647

/** The window deny rows are coalesced over, per grant: one second, the second PROXY_DENY_KEYS_PER_SECOND bounds the distinct rows of. */
export const DENY_WINDOW_MS = 1_000

/** How long end() keeps reading the channel for the command's last frames before it revokes without them. */
export const END_DRAIN_MS = 5_000

/**
 * The upstream-stage refusals the session gives itself, beside the
 * upstream's own (upstream.ts UPSTREAM_REFUSALS; events/types.ts
 * PROXY_UPSTREAM_REFUSALS names both): `challenged`, the host answered 401 or
 * 403; `response-head`, the host answered with a head node:http will not
 * write to the worker (a status below 100). The worker reads either as a
 * 502. Always sent: the host read the request and answered it.
 */
export const SESSION_REFUSALS = Object.freeze(['challenged', 'response-head'] as const)

/**
 * The per-grant limits, as kernel.yaml's egress.limits names and bounds them
 * (config.ts EgressLimits; test/egress-session.test.ts holds the two equal).
 * Extra keys are dropped, so the whole of egress.limits may be handed in.
 */
export const SessionLimits = z.object({
  frameMaxBytes: z.number().int().min(1).max(FRAME_MAX_BYTES_LIMIT),
  maxFlows: z.number().int().min(1).max(MAX_FLOWS_LIMIT),
  maxHeaderBytes: z.number().int().min(1).max(65_536),
  maxRequests: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  maxBytes: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  maxDenied: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  idleMs: z.number().int().min(1).max(MAX_TIMER_MS),
})
export type SessionLimits = Readonly<z.output<typeof SessionLimits>>

/** The limits a grant can be revoked on (events/types.ts PROXY_LIMITS). */
export type SessionLimitName = keyof SessionLimits

/** Why the caller says the container ended: the driver's verdict (sandbox.killed's reasons). */
export const SESSION_END_REASONS = Object.freeze(['exited', 'wallclock', 'requested', 'error'] as const)
export type SessionEndReason = (typeof SESSION_END_REASONS)[number]

/** Why a grant ended: the caller's reason, or the session's own (events/types.ts PROXY_REVOKE_REASONS but `recovered`). */
export type SessionRevokeReason = SessionEndReason | 'violation' | 'limit'

/**
 * Sets a binding's one credential header on a request head: the kernel builds
 * it over broker.use (src/secrets/broker.ts), so the value goes from the
 * broker into the head and nowhere else. It must call `set` exactly once,
 * with Authorization (the one header a binding may name, config.ts) and the
 * header's whole value (`Bearer <token>`, or `Basic <base64>`). The head is
 * built from what was set when it returns, so a call after that changes
 * nothing that is sent.
 */
export type CredentialInjector = (bindingId: string, set: (name: string, value: string) => void) => void

/**
 * Judges the mux's ready report (its self-test, egress plan E9): none to
 * accept it, or a clause saying why not, recorded as the revocation's detail.
 */
export type ReadyJudge = (report: Uint8Array) => string | undefined

/** The clock and timers the session reads: injected so tests drive the deny window and the idle bound. */
export interface SessionClock {
  now(): number
  setTimeout(callback: () => void, ms: number): unknown
  clearTimeout(handle: unknown): void
}

/** A grant's whole traffic (events/types.ts ProxyGrantTotals). */
export interface SessionTotals {
  readonly flows: number
  readonly requests: number
  readonly allowed: number
  readonly denied: number
  readonly refused: number
  readonly failed: number
  readonly sentBytes: number
  readonly receivedBytes: number
  readonly durationMs: number
}

/** What a session ended with: its revocation as recorded, and what the command printed and returned. */
export interface SessionOutcome {
  readonly reason: SessionRevokeReason
  readonly limit: SessionLimitName | undefined
  readonly detail: string | undefined
  /** The mux's ready report, once one arrived. */
  readonly ready: Uint8Array | undefined
  /** The command's exit status, once the exit frame arrived. */
  readonly exitStatus: number | undefined
  /** At most CAPTURE_MAX_BYTES of each stream, raw bytes, the caller decodes. */
  readonly stdout: Uint8Array
  readonly stdoutTruncated: boolean
  readonly stderr: Uint8Array
  readonly stderrTruncated: boolean
  readonly totals: SessionTotals
}

export interface SessionOptions {
  /** The grant's id, as proxy.grant.issued named it: every row this session writes names it. */
  readonly grantId: string
  readonly grant: EgressGrant
  /** The agent whose run the grant serves; every row is appended under it and the grant's run. */
  readonly agentId?: string
  /**
   * The boot's canary (egress plan W3, src/runtime/canary.ts): a grant that
   * serves no run and no agent and reaches nothing, as its
   * proxy.grant.issued row says (purpose `canary`). Its rows are appended
   * under no run and no agent: the grant's runId is decide()'s alone (the
   * push prefix it never reaches, since decide() denies every request under
   * a grant with no host). A canary grant naming a host, a route or an
   * agent is refused, so no session that records nothing of a run serves
   * any reach.
   */
  readonly canary?: true
  readonly limits: SessionLimits
  /** The docker child's stdout, which the mux writes, and its stdin, which the mux reads. */
  readonly channel: { readonly input: Readable; readonly output: Writable }
  readonly store: { append(input: AppendInput): unknown }
  readonly upstream: Upstream
  readonly credential: CredentialInjector
  readonly acceptReady: ReadyJudge
  /**
   * Called at most once, when the session revokes the grant on its own
   * before the caller ended it; the caller kills the container on its own
   * domain. Never called once end() was: the caller already ended the
   * container, and a revocation after that (a violation, a broken append)
   * is recorded without it.
   */
  readonly kill: () => unknown
  /**
   * Called at most once, with the command's status, when the mux's exit
   * frame arrives while the grant is still served (before end()): the
   * command has exited, and its container is due to end once its flows
   * retire (images/worker/mux.mjs). A descendant of the command that left
   * its process group may hold a flow open past that, so the caller bounds
   * the wait and kills the container by name past it (egress plan W1).
   * Unset, the session tells no one.
   */
  readonly exited?: (status: number) => unknown
  readonly clock?: SessionClock
}

export interface EgressSession {
  /**
   * Resolves once the revocation was attempted: proxy.grant.revoked
   * appended, or refused by the store (logged, and the outcome is the same).
   * Never rejects.
   */
  readonly done: Promise<SessionOutcome>
  /**
   * The container ended, or is being stopped: from the call on nothing is
   * served or sent, and the grant is revoked with the driver's reason once the
   * channel's input ends (its last stdout, stderr and exit frames kept), or
   * after END_DRAIN_MS on the session's clock if it does not, unless the
   * session already revoked. A frame the channel refuses in the meantime is
   * a violation still (no kill); one past a channel limit revokes at once
   * with this reason, the detail saying the rest was not read. `detail`,
   * when given, is the revocation's: the caller's words for its verdict (a
   * container it killed by name, and why). Idempotent: a second call
   * changes nothing.
   */
  end(reason: SessionEndReason, detail?: string): Promise<SessionOutcome>
}

/**
 * The worker's headers the session never forwards, by the name
 * canonicalHeaderName gives (policy.ts: Proxy_Authorization is
 * proxy-authorization here, as a folding backend reads it): every auth header
 * and cookie (the kernel's credential is the only one a host reads), the
 * hop-by-hop headers and the body's framing (the upstream frames the body as
 * decide() judged it), Expect, the forwarding headers (a container says
 * nothing about where a request came from), and every header the upstream
 * sets or refuses itself (UPSTREAM_OWNED_HEADERS: one left in would have it
 * refuse the request, where the session's rule is to drop it). A header a
 * Connection header names, and any X-Forwarded-*, is dropped as well, each by
 * that name too.
 */
const WORKER_STRIPPED: readonly string[] = [
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
  'transfer-encoding',
  'upgrade',
  'content-length',
  'host',
  'expect',
  'forwarded',
  'via',
  'x-real-ip',
  'x-client-ip',
  'client-ip',
  'true-client-ip',
  'x-cluster-client-ip',
  'cf-connecting-ip',
  'fastly-client-ip',
  'x-originating-ip',
]
export const REQUEST_STRIPPED: readonly string[] = Object.freeze([...new Set([...WORKER_STRIPPED, ...UPSTREAM_OWNED_HEADERS])])

/**
 * The headers decide() reads to judge a request: a Connection header that
 * names one would have it dropped as hop-by-hop from the head that is sent,
 * so the host would read another request than the one judged.
 */
const JUDGED_HEADERS: readonly string[] = Object.freeze(['host', 'content-length', 'transfer-encoding', 'content-type', 'content-encoding'])

/** The auth headers: on the wire, exactly one on a bound route (the injected Authorization), none elsewhere. */
const AUTH_HEADERS: readonly string[] = Object.freeze(['authorization', 'proxy-authorization', 'x-api-key', 'api-key', 'x-auth-token', 'private-token'])

/** The forwarding headers named by prefix. */
const FORWARDED_PREFIX = 'x-forwarded-'

/**
 * The upstream's response headers the worker never gets: the hop-by-hop ones
 * (the session frames its own answer), a cookie minted for the operator's
 * credential, and the challenges that would have a client ask for one. Each
 * is matched by the name canonicalHeaderName gives, as a header the host's
 * Connection names is, so Set_Cookie and WWW_Authenticate, which a client
 * that folds names reads as Set-Cookie and WWW-Authenticate, are dropped too.
 */
export const RESPONSE_STRIPPED: readonly string[] = Object.freeze([
  'connection',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'proxy-authenticate',
  'proxy-authorization',
  'set-cookie',
  'set-cookie2',
  'www-authenticate',
])

/**
 * The parse errors that mean the worker hung up mid-request, or wrote past a
 * request that said Connection: close (its flow is cut, as a pipelined second
 * request's is), not that it sent what HTTP is not.
 */
const HANGUPS: ReadonlySet<string> = new Set(['HPE_INVALID_EOF_STATE', 'HPE_CLOSED_CONNECTION'])

/** The upstream statuses answered 502: a challenge a client would answer by asking for a credential. */
const CHALLENGES: ReadonlySet<number> = new Set([401, 403])

/** The service each git profile's info/refs names, as its whole query (routes.ts SERVICE_QUERY). A Map: no query finds what an object inherits. */
const SERVICES: ReadonlyMap<string, 'git-upload-pack' | 'git-receive-pack'> = new Map([
  ['service=git-upload-pack', 'git-upload-pack'],
  ['service=git-receive-pack', 'git-receive-pack'],
])
const INFO_REFS = '/info/refs'

const BEFORE_PATH: readonly string[] = PROXY_DENIES_BEFORE_PATH
const BY_HOST_REFUSAL: readonly string[] = PROXY_DENIES_BY_HOST_REFUSAL

/** The text the redaction pass leaves as it is: an identifier recorded as written. */
const recordableAsIs = (text: string): boolean => redactString(text) === text

const OptionsData = z
  .object({
    grantId: z.string().regex(RUN_REF),
    grant: EgressGrant,
    agentId: z.string().regex(AGENT_SHAPE).optional(),
    canary: z.literal(true).optional(),
    limits: SessionLimits,
  })
  .strip()
  .superRefine((data, ctx) => {
    if (data.canary !== true) return
    if (data.grant.allow.length > 0 || data.grant.routes.length > 0) ctx.addIssue({ code: 'custom', message: 'a canary grant reaches nothing' })
    if (data.agentId !== undefined) ctx.addIssue({ code: 'custom', message: 'a canary grant serves no agent' })
  })

/** The worker's head, read once into one record: decide() and the upstream head read only this. */
type HeaderRecord = Readonly<Record<string, readonly string[]>>

function headerRecord(raw: readonly string[]): HeaderRecord {
  const record = Object.create(null) as Record<string, string[]>
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = (raw[i] ?? '').toLowerCase()
    const value = raw[i + 1] ?? ''
    const list = Object.hasOwn(record, name) ? record[name] : undefined
    if (list === undefined) record[name] = [value]
    else list.push(value)
  }
  for (const values of Object.values(record)) Object.freeze(values)
  return Object.freeze(record)
}

/** The names a Connection header lists (hop-by-hop by declaration), each as canonicalHeaderName spells it. */
function connectionNamed(values: readonly string[] | undefined): Set<string> {
  const named = new Set<string>()
  for (const value of values ?? []) for (const token of value.split(',')) named.add(canonicalHeaderName(token.trim()))
  return named
}

/** The head the upstream sends: the judged record, stripped, one value per name, and the credential not yet in it. */
function forwardedHeaders(record: HeaderRecord): Record<string, string> {
  const named = connectionNamed(record['connection'])
  const out = Object.create(null) as Record<string, string>
  for (const [name, values] of Object.entries(record)) {
    // By the name a folding backend reads (policy.ts canonicalHeaderName):
    // Proxy_Authorization, X_Forwarded_For and Content_Length are the
    // headers they alias there, so they are stripped as those are.
    const canonical = canonicalHeaderName(name)
    if (REQUEST_STRIPPED.includes(canonical) || named.has(canonical) || canonical.startsWith(FORWARDED_PREFIX)) continue
    // One field per name (RFC 9110 5.3): the judged values in order. A
    // Content-Type or Content-Encoding is one value here, decide() having
    // refused two, so it reaches the upstream exactly as decide() read it.
    out[name] = values.join(', ')
  }
  return out
}

/** The upstream's response headers the worker gets, as rawHeaders' flat list, with this session's Connection: close. */
function answeredHeaders(raw: readonly string[]): string[] {
  const named = new Set<string>()
  for (let i = 0; i + 1 < raw.length; i += 2) {
    if (canonicalHeaderName(raw[i] ?? '') === 'connection') for (const t of connectionNamed([raw[i + 1] ?? ''])) named.add(t)
  }
  const out: string[] = []
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i] ?? ''
    const canonical = canonicalHeaderName(name)
    if (RESPONSE_STRIPPED.includes(canonical) || named.has(canonical)) continue
    out.push(name, raw[i + 1] ?? '')
  }
  out.push('connection', 'close')
  return out
}

/** A request's path as a row records it: the path alone, its length and its query's, and the one service a query may name. */
function pathFields(parsed: ParsedTarget | RouteRefused, serviceOk: boolean): Record<string, unknown> {
  if (!parsed.ok) return {}
  const path = recordable(parsed.path, EGRESS_PATH_BYTES)
  const service = parsed.query === undefined ? undefined : SERVICES.get(parsed.query)
  return {
    path,
    pathBytes: parsed.path.length,
    queryBytes: parsed.query === undefined ? 0 : parsed.query.length + 1,
    // Only on an info/refs path as recorded (a cut path no longer ends with it).
    ...(serviceOk && service !== undefined && path.endsWith(INFO_REFS) ? { service } : {}),
  }
}

/** Bytes a stream (the command's stdout or stderr) carried: the first CAPTURE_MAX_BYTES kept in blocks of its own, the rest counted and dropped. */
class ByteCapture {
  static readonly BLOCK = 64 * 1024
  readonly #blocks: Buffer[] = []
  #held = 0
  #seen = 0

  add(bytes: Uint8Array): void {
    this.#seen += bytes.length
    let rest = bytes.subarray(0, Math.max(0, CAPTURE_MAX_BYTES - this.#held))
    while (rest.length > 0) {
      const offset = this.#held % ByteCapture.BLOCK
      let block = this.#blocks.at(-1)
      if (block === undefined || offset === 0) {
        block = Buffer.alloc(ByteCapture.BLOCK)
        this.#blocks.push(block)
      }
      const take = Math.min(rest.length, ByteCapture.BLOCK - offset)
      block.set(rest.subarray(0, take), offset)
      this.#held += take
      rest = rest.subarray(take)
    }
  }

  get truncated(): boolean {
    return this.#seen > this.#held
  }

  bytes(): Uint8Array {
    return new Uint8Array(Buffer.concat(this.#blocks, this.#held))
  }
}

/** What the session hands a flow's Duplex: how its reads, writes, end and close reach the channel. */
interface FlowHost {
  unblock(socket: FlowSocket): void
  write(socket: FlowSocket, chunk: Buffer, callback: (error?: Error | null) => void): void
  end(socket: FlowSocket): void
  close(socket: FlowSocket): void
}

/**
 * One flow, as node:http sees a socket. Its readable side is what the mux
 * sent on the flow; what node:http writes to it goes out as the flow's data,
 * its end as the flow's end, and its destruction as the flow's close.
 */
class FlowSocket extends Duplex {
  readonly flow: number
  readonly #host: FlowHost
  /** Requests node:http has handed over on this flow: at most one is judged. */
  requests = 0
  /** The mux sent its end: its close after it is a clean finish, not a reset. */
  muxEnded = false
  muxClosed = false
  kernelClosed = false

  constructor(flow: number, host: FlowHost) {
    super({ allowHalfOpen: true })
    this.flow = flow
    this.#host = host
    // A flow cut with an error after node:http let go of it (a CONNECT it
    // handed over) has no listener of node's: the error is the cut, and
    // with none here it would end the kernel.
    this.on('error', () => undefined)
  }

  override _read(): void {
    this.#host.unblock(this)
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.#host.write(this, chunk, callback)
  }

  override _final(callback: (error?: Error | null) => void): void {
    this.#host.end(this)
    callback()
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.#host.close(this)
    callback(error)
  }

  // What node:http may ask of a net.Socket: nothing here has a timer, a
  // Nagle buffer or a keep-alive probe of its own.
  setTimeout(): this {
    return this
  }

  setNoDelay(): this {
    return this
  }

  setKeepAlive(): this {
    return this
  }
}

function coded(code: string, message: string): Error {
  return Object.assign(new Error(message), { code })
}

/** What one request read of its body before decide(): the bytes, and whether the body ended within them. */
type Leading = { readonly ok: true; readonly bytes: Buffer; readonly ended: boolean } | { readonly ok: false }

/**
 * Read what leadingNeed() asks of a body, and no more than a chunk past it:
 * a push's command list (complete pkt-lines up to the flush, an invalid one,
 * or `max` bytes), or a pull request's whole body. The pkt-line walk is
 * incremental, so a body sent a byte at a time costs no more than one sent
 * whole. The request is paused when this resolves; nothing read is lost.
 */
function readLeading(req: IncomingMessage, need: Exclude<LeadingNeed, { readonly kind: 'none' }>): Promise<Leading> {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(4_096)
    let len = 0
    let at = 0
    let settled = false
    const listOver = (max: number): boolean => {
      for (;;) {
        if (at + 4 > len) return at + 4 > max
        const text = buf.toString('latin1', at, at + 4)
        if (!/^[0-9a-f]{4}$/.test(text)) return true
        const n = Number.parseInt(text, 16)
        // A flush ends the list; an empty or special packet, or one longer
        // than git writes, is a list scanCommandList refuses.
        if (n <= 4 || n > 65_520) return true
        if (at + n > max) return true
        if (at + n > len) return false
        at += n
      }
    }
    const finish = (result: Leading): void => {
      if (settled) return
      settled = true
      req.off('data', onData)
      req.off('end', onEnd)
      req.off('error', onGone)
      req.off('close', onGone)
      req.pause()
      resolve(result)
    }
    const onData = (chunk: Buffer): void => {
      if (len + chunk.length > buf.length) {
        const next = Buffer.alloc(Math.max(buf.length * 2, len + chunk.length))
        buf.copy(next, 0, 0, len)
        buf = next
      }
      chunk.copy(buf, len)
      len += chunk.length
      const enough = need.kind === 'whole-body' ? len >= need.length : len >= need.max || listOver(need.max)
      if (enough) finish({ ok: true, bytes: buf.subarray(0, len), ended: false })
    }
    const onEnd = (): void => finish({ ok: true, bytes: buf.subarray(0, len), ended: true })
    const onGone = (): void => finish({ ok: false })
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onGone)
    req.on('close', onGone)
  })
}

const defaultClock: SessionClock = Object.freeze({
  now: () => performance.now(),
  setTimeout: (callback: () => void, ms: number): unknown => {
    const timer = setTimeout(callback, ms)
    timer.unref()
    return timer
  },
  clearTimeout: (handle: unknown): void => {
    clearTimeout(handle as ReturnType<typeof setTimeout>)
  },
})

/** One deny row being counted: its fields, the detail kept only while it stands for one request, and its count. */
interface DenyEntry {
  readonly row: Readonly<Record<string, unknown>>
  readonly detail: Readonly<Record<string, unknown>>
  count: number
}

interface DenyWindow {
  readonly timer: unknown
  readonly entries: Map<string, DenyEntry>
  readonly overflow: Map<string, { readonly reason: string; readonly hostRefusal: string | undefined; count: number }>
}

/**
 * handshake until go is sent, open while flows are served, ending once the
 * caller's end() came (nothing is served or sent, the channel is still read
 * for the command's last frames), revoking once the revocation began.
 */
type State = 'handshake' | 'open' | 'ending' | 'revoking'

class Session implements EgressSession {
  readonly done: Promise<SessionOutcome>
  readonly #resolve: (outcome: SessionOutcome) => void
  readonly #grantId: string
  readonly #grant: EgressGrant
  /** The run every row is appended under: none for a canary's. */
  readonly #runId: string | undefined
  readonly #agentId: string | undefined
  readonly #limits: SessionLimits
  readonly #input: Readable
  readonly #output: Writable
  readonly #store: SessionOptions['store']
  readonly #upstream: Upstream
  readonly #credential: CredentialInjector
  readonly #acceptReady: ReadyJudge
  readonly #kill: () => unknown
  readonly #exited: ((status: number) => unknown) | undefined
  readonly #clock: SessionClock
  readonly #channel: FrameChannel
  readonly #server: Server
  readonly #flows = new Map<number, FlowSocket>()
  /** Flows whose readable side is full: the channel's read is paused while any is. */
  readonly #blocked = new Set<number>()
  /** Requests in hand: the revocation waits for each to append what it must. */
  readonly #inHand = new Set<Promise<void>>()
  readonly #aborts = new Set<AbortController>()
  readonly #drainWaiters: Array<() => void> = []
  /** end() calls waiting for the channel's input to end. */
  readonly #inputWaiters: Array<() => void> = []
  readonly #stdout = new ByteCapture()
  readonly #stderr = new ByteCapture()
  readonly #started: number
  #state: State = 'handshake'
  /** Frames may go to the mux: false once the revocation begins or the mux is gone. */
  #writable = true
  #inputEnded = false
  /** The caller's reason, once end() was called. */
  #endReason: SessionEndReason | undefined
  #endRefusal: FrameError | undefined
  #ready: Uint8Array | undefined
  #exitStatus: number | undefined
  #flowBytes = 0
  #lastActivity: number
  #idleTimer: unknown
  #window: DenyWindow | undefined
  #killed = false
  /** Decision rows the store refused, whenever: the revocation's detail says how many. */
  #unrecordedRows = 0
  readonly #totals = { requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0 }

  constructor(options: SessionOptions) {
    const data = OptionsData.parse({ grantId: options.grantId, grant: options.grant, agentId: options.agentId, canary: options.canary, limits: options.limits })
    for (const name of ['credential', 'acceptReady', 'kill'] as const) {
      if (typeof options[name] !== 'function') throw new TypeError(`egress session: ${name} must be a function`)
    }
    if (options.exited !== undefined && typeof options.exited !== 'function') throw new TypeError('egress session: exited must be a function')
    if (typeof options.upstream?.request !== 'function') throw new TypeError('egress session: upstream must be an Upstream')
    if (typeof options.store?.append !== 'function') throw new TypeError('egress session: store must append')
    const { input, output } = options.channel
    if (!(input instanceof Readable) || !(output instanceof Writable)) {
      throw new TypeError("egress session: the channel is the docker child's stdout (Readable) and stdin (Writable)")
    }
    // Every identifier a row names must be stored as written (events/types.ts
    // says why): a grant naming one the redaction pass would change is one
    // whose rows could not say where a run reached, so no session runs it.
    const ids = [
      data.grantId,
      data.grant.runId,
      ...(data.agentId === undefined ? [] : [data.agentId]),
      ...data.grant.allow,
      ...data.grant.routes.flatMap((route) => [route.bindingId, route.host, ...route.repos]),
    ]
    if (!ids.every(recordableAsIs)) {
      throw new KernelError('AOS_EGRESS_SESSION', 'egress session: an identifier of the grant is in the shape of a credential, so its rows could not record it')
    }
    this.#grantId = data.grantId
    this.#grant = data.grant
    this.#runId = data.canary === true ? undefined : data.grant.runId
    this.#agentId = data.agentId
    this.#limits = Object.freeze(data.limits)
    this.#input = input
    this.#output = output
    this.#store = options.store
    this.#upstream = options.upstream
    this.#credential = options.credential
    this.#acceptReady = options.acceptReady
    this.#kill = options.kill
    this.#exited = options.exited
    this.#clock = options.clock ?? defaultClock
    const frameLimits: FrameLimits = { frameMaxBytes: this.#limits.frameMaxBytes, maxFlows: this.#limits.maxFlows }
    this.#channel = new FrameChannel({ role: 'kernel', limits: frameLimits })
    this.#started = this.#clock.now()
    this.#lastActivity = this.#started

    let resolve: (outcome: SessionOutcome) => void = () => undefined
    this.done = new Promise<SessionOutcome>((r) => {
      resolve = r
    })
    this.#resolve = resolve

    this.#server = createServer({
      maxHeaderSize: this.#limits.maxHeaderBytes,
      // Strict whatever NODE_OPTIONS or the command line says: an ambiguous
      // head (Content-Length beside Transfer-Encoding) is a parse error here,
      // never a guess two hosts may make two ways.
      insecureHTTPParser: false,
      // Every head node:http reads reaches decide() and gets its row; one
      // without Host is judged as one (decide() takes the target's host).
      requireHostHeader: false,
      joinDuplicateHeaders: false,
      // An Upgrade is a request like any other, its Upgrade and Connection
      // stripped: egress opens no tunnel (node 24.9 and up; before it, with
      // no 'upgrade' listener, node:http does the same).
      shouldUpgradeCallback: () => false,
    })
    // A worker that ends its side once its request is written (a half-close,
    // as FlowSocket allows) is answered and then the flow ends: node:http's
    // default ends the flow at the worker's end, so the request would be
    // dropped unanswered. A property node:http reads at each end, which no
    // option sets and @types/node does not declare.
    Object.assign(this.#server, { httpAllowHalfOpen: true })
    this.#server.on('request', this.#onRequest)
    // An Expect node:http does not know would be answered 417 unjudged.
    this.#server.on('checkExpectation', this.#onRequest)
    this.#server.on('connect', this.#onConnect)
    this.#server.on('clientError', this.#onClientError)

    output.on('error', () => {
      this.#writable = false
      this.#releaseDrains()
    })
    output.on('drain', () => this.#releaseDrains())
    input.on('data', this.#onData)
    input.on('end', this.#onInputEnd)
    input.on('close', this.#onInputEnd)
    input.on('error', this.#onInputEnd)
    this.#armIdle()
  }

  end(reason: SessionEndReason, detail?: string): Promise<SessionOutcome> {
    if (!SESSION_END_REASONS.includes(reason)) throw new TypeError(`egress session: no end reason ${String(reason)}`)
    if (detail !== undefined && typeof detail !== 'string') throw new TypeError('egress session: an end detail is text')
    if (this.#state === 'revoking' || this.#state === 'ending') return this.done
    // The container is gone, or going: nothing more is served or sent, but
    // the channel is read until it ends, for the frames still in the pipe.
    this.#state = 'ending'
    this.#endReason = reason
    this.#stopFlows()
    void this.#untilInputEnds().then(() => {
      if (this.#state !== 'ending') return
      // A stream that ended inside a frame, from a container that exited on
      // its own, is the container's doing; one a kill cut is the kill's.
      const cut = this.#inputEnded ? this.#endRefusal : undefined
      if (reason === 'exited' && cut !== undefined) void this.#revoke('violation', undefined, cut.message)
      else void this.#revoke(reason, undefined, detail)
    })
    return this.done
  }

  /** Nothing more is sent to the mux or served: every flow is cut and every request upstream aborted. The channel is still read. */
  #stopFlows(): void {
    this.#writable = false
    this.#disarmIdle()
    this.#releaseDrains()
    this.#input.resume()
    for (const socket of [...this.#flows.values()]) socket.destroy()
    for (const controller of this.#aborts) controller.abort()
  }

  /** Resolves once the channel's input ended, the revocation began, or END_DRAIN_MS passed on the session's clock. */
  #untilInputEnds(): Promise<void> {
    if (this.#inputEnded) return Promise.resolve()
    return new Promise((resolve) => {
      const release = (): void => {
        this.#clock.clearTimeout(timer)
        resolve()
      }
      const timer = this.#clock.setTimeout(release, END_DRAIN_MS)
      this.#inputWaiters.push(release)
    })
  }

  #releaseInputWaiters(): void {
    for (const waiter of this.#inputWaiters.splice(0)) waiter()
  }

  // ── the channel ──────────────────────────────────────────────────────────

  /** Read afresh: a call can begin the revocation, which narrowing does not see. */
  #revoking(): boolean {
    return this.#state === 'revoking'
  }

  readonly #onData = (chunk: Buffer | string): void => {
    if (this.#state === 'revoking') return
    const bytes = typeof chunk === 'string' ? Buffer.from(chunk, 'latin1') : chunk
    const { frames, error } = this.#channel.receive(bytes)
    for (const frame of frames) {
      // A frame can end the grant (a limit, a refused ready): the rest are dropped.
      if (this.#revoking()) return
      this.#onFrame(frame)
    }
    if (error !== undefined && !this.#revoking()) {
      const ended = this.#endReason
      if (this.#state === 'ending' && ended !== undefined && error.reason === 'limit') {
        // The channel's bounds guard a grant still served. Once the caller
        // ended the container, a frame past one only stops the read (the
        // codec decodes nothing after it): the caller's verdict stands, and
        // the detail says what the outcome lacks. A violation still says the
        // container broke the protocol, so it is recorded as one.
        void this.#revoke(ended, undefined, `after end(), the channel refused a frame past ${String(error.limit)}, so nothing after it was read: ${error.message}`)
        return
      }
      this.#selfRevoke(error.reason, error.limit, error.message)
    }
  }

  readonly #onInputEnd = (): void => {
    if (this.#inputEnded) return
    this.#inputEnded = true
    if (this.#state !== 'revoking') {
      // The mux is gone: nothing more arrives, and nothing sent would be read.
      this.#endRefusal = this.#channel.finish()
      this.#stopFlows()
    }
    this.#releaseInputWaiters()
  }

  #onFrame(frame: ReceivedFrame): void {
    // Once the caller ended the container, only what the command printed and
    // returned is kept: no flow is opened or fed, and no ready is judged.
    if (this.#state === 'ending' && frame.type !== 'stdout' && frame.type !== 'stderr' && frame.type !== 'exit') return
    switch (frame.type) {
      case 'ready':
        return this.#onReady(frame.payload)
      case 'open': {
        this.#touch()
        // A flow carries at most one request: bounding the flows bounds the
        // requests, and a flow that never finishes a head is counted too.
        if (this.#channel.flowsOpened > this.#limits.maxRequests) {
          this.#selfRevoke('limit', 'maxRequests', `the worker opened more than maxRequests ${String(this.#limits.maxRequests)} flows, one request each`)
          return
        }
        const socket = new FlowSocket(frame.flow, this.#flowHost)
        this.#flows.set(frame.flow, socket)
        this.#armIdle()
        this.#server.emit('connection', socket)
        return
      }
      case 'data': {
        this.#touch()
        if (!this.#account(frame.payload.length)) return
        if (frame.stale) return
        const socket = this.#flows.get(frame.flow)
        if (socket === undefined || socket.destroyed) return
        const view = Buffer.from(frame.payload.buffer, frame.payload.byteOffset, frame.payload.byteLength)
        if (!socket.push(view)) {
          // Backpressure is the channel's (frame.ts): one full flow stops the
          // read of the whole stream until node:http has read it down.
          this.#blocked.add(frame.flow)
          this.#input.pause()
        }
        return
      }
      case 'end': {
        this.#touch()
        if (frame.stale) return
        const socket = this.#flows.get(frame.flow)
        if (socket === undefined) return
        socket.muxEnded = true
        if (!socket.destroyed) socket.push(null)
        return
      }
      case 'close': {
        this.#touch()
        const socket = this.#flows.get(frame.flow)
        if (socket === undefined) return
        socket.muxClosed = true
        // A close with no end before it is a cut: the worker reads a reset,
        // never a short request read as whole.
        if (!socket.destroyed) socket.destroy(socket.muxEnded ? undefined : coded('ECONNRESET', 'the worker cut the flow'))
        this.#retire(socket)
        return
      }
      case 'stdout':
        return this.#stdout.add(frame.payload)
      case 'stderr':
        return this.#stderr.add(frame.payload)
      case 'exit': {
        const status = frame.payload[0]
        this.#exitStatus = status
        // While the grant is served: once end() was called the container has
        // ended, or is being ended, already.
        if (this.#state !== 'ending' && status !== undefined) this.#tellExited(status)
        return
      }
      case 'go':
        // The channel refuses a go from the mux (direction).
        return
    }
  }

  #onReady(payload: Uint8Array): void {
    this.#touch()
    this.#ready = new Uint8Array(payload)
    let refusal: string | undefined
    try {
      const judged: unknown = this.#acceptReady(new Uint8Array(payload))
      refusal = judged === undefined ? undefined : typeof judged === 'string' && judged !== '' ? judged : 'the ready judge answered something that is not a clause'
    } catch {
      refusal = 'the ready judge threw'
    }
    if (refusal !== undefined) {
      this.#selfRevoke('violation', undefined, `the mux's ready report was refused: ${refusal}`)
      return
    }
    if (!this.#send({ type: 'go', flow: 0, payload: goPayload(this.#limits) })) return
    this.#state = 'open'
    this.#armIdle()
  }

  /** Send one frame. False when the channel or the mux cannot take it; a refusal that is no race is this end's bug, and ends the grant. */
  #send(frame: Frame): boolean {
    if (!this.#writable || this.#state === 'revoking') return false
    const refusal = this.#channel.sendRefusal(frame)
    if (refusal !== undefined) {
      if (refusal.refusal !== 'peer-closed') this.#selfRevoke('error', undefined, `the kernel end would send a frame the channel refuses: ${refusal.message}`)
      return false
    }
    this.#output.write(this.#channel.send(frame))
    return true
  }

  #releaseDrains(): void {
    for (const waiter of this.#drainWaiters.splice(0)) waiter()
  }

  readonly #flowHost: FlowHost = {
    unblock: (socket) => {
      this.#blocked.delete(socket.flow)
      if (this.#blocked.size === 0) this.#input.resume()
    },
    write: (socket, chunk, callback) => {
      const { frameMaxBytes } = this.#limits
      for (let at = 0; at < chunk.length; at += frameMaxBytes) {
        const payload = chunk.subarray(at, at + frameMaxBytes)
        if (!this.#account(payload.length) || !this.#send({ type: 'data', flow: socket.flow, payload })) {
          // The worker closed its side, the mux is gone, or the grant ended:
          // a write nobody reads, which node:http takes as a broken pipe.
          callback(coded('EPIPE', 'the flow is closed'))
          return
        }
      }
      this.#touch()
      if (!this.#output.writableNeedDrain) callback()
      else this.#drainWaiters.push(() => callback())
    },
    end: (socket) => {
      this.#send({ type: 'end', flow: socket.flow, payload: new Uint8Array(0) })
    },
    close: (socket) => {
      this.#blocked.delete(socket.flow)
      if (this.#blocked.size === 0) this.#input.resume()
      if (!socket.kernelClosed) {
        socket.kernelClosed = true
        this.#send({ type: 'close', flow: socket.flow, payload: new Uint8Array(0) })
      }
      this.#retire(socket)
    },
  }

  /** A flow both sides have closed is forgotten. */
  #retire(socket: FlowSocket): void {
    if (!socket.kernelClosed || !socket.muxClosed) return
    this.#flows.delete(socket.flow)
    this.#armIdle()
  }

  /** Count flow bytes against maxBytes; false, and the grant revoked, once they pass it. */
  #account(bytes: number): boolean {
    this.#flowBytes += bytes
    if (this.#flowBytes <= this.#limits.maxBytes) return true
    this.#selfRevoke('limit', 'maxBytes', `the flows carried more than maxBytes ${String(this.#limits.maxBytes)} bytes`)
    return false
  }

  // ── idle ─────────────────────────────────────────────────────────────────

  /** One of the mux's flow frames (an open, data, end or close), the kernel's data, or the mux's ready: idleMs counts from the last. */
  #touch(): void {
    this.#lastActivity = this.#clock.now()
  }

  /** Idle counts while the handshake is pending or a flow is open: a command running with no flow is the wallclock's. */
  #idleCounts(): boolean {
    if (this.#inputEnded) return false
    return this.#state === 'handshake' || (this.#state === 'open' && this.#flows.size > 0)
  }

  #armIdle(): void {
    if (!this.#idleCounts()) return this.#disarmIdle()
    if (this.#idleTimer !== undefined) return
    const wait = Math.max(1, this.#limits.idleMs - (this.#clock.now() - this.#lastActivity))
    this.#idleTimer = this.#clock.setTimeout(() => {
      this.#idleTimer = undefined
      if (!this.#idleCounts()) return
      if (this.#clock.now() - this.#lastActivity >= this.#limits.idleMs) {
        this.#selfRevoke('limit', 'idleMs', `the channel carried no flow frame from the mux, and no data from the kernel, for idleMs ${String(this.#limits.idleMs)} ms`)
        return
      }
      this.#armIdle()
    }, wait)
  }

  #disarmIdle(): void {
    if (this.#idleTimer === undefined) return
    this.#clock.clearTimeout(this.#idleTimer)
    this.#idleTimer = undefined
  }

  // ── requests ─────────────────────────────────────────────────────────────

  #track(work: Promise<void>): void {
    const held = work.catch((e: unknown) => this.#bug(e))
    this.#inHand.add(held)
    void held.finally(() => this.#inHand.delete(held))
  }

  /** An exception the session did not expect: a kernel bug, never the container's doing, and the grant ends. */
  #bug(e: unknown): void {
    log.error({ grantId: this.#grantId, code: e instanceof Error ? (e as { code?: unknown }).code : undefined }, 'egress session: unexpected failure; the grant is revoked')
    this.#selfRevoke('error', undefined, 'the session failed unexpectedly')
  }

  /**
   * A request node:http handed over. Taken at most once per flow: a second
   * (pipelined) request cuts the flow before it is judged. Returns the flow,
   * or none when the request is not to be judged.
   */
  #take(req: IncomingMessage): FlowSocket | undefined {
    const socket: unknown = req.socket
    if (!(socket instanceof FlowSocket)) {
      ;(socket as Socket | undefined)?.destroy()
      return undefined
    }
    if (this.#state !== 'open' || socket.requests++ > 0) {
      socket.destroy()
      return undefined
    }
    return socket
  }

  readonly #onRequest = (req: IncomingMessage, res: ServerResponse): void => {
    try {
      const socket = this.#take(req)
      if (socket === undefined) return
      this.#track(this.#handle(req, res, socket))
    } catch (e) {
      this.#bug(e)
    }
  }

  readonly #onConnect = (req: IncomingMessage, raw: Duplex): void => {
    try {
      const socket = this.#take(req)
      if (socket === undefined) {
        raw.destroy()
        return
      }
      // node:http has let go of the socket: what follows the head is drained.
      socket.resume()
      const headers = headerRecord(req.rawHeaders)
      const decision = decide(this.#grant, { method: req.method ?? '', target: req.url ?? '', headers: headers as EgressHeaders })
      this.#totals.requests++
      if (decision.verdict === 'allow') {
        // decide() opens no tunnel; an allow here is a decide() that broke.
        throw new Error('decide() allowed a CONNECT')
      }
      this.#denied(decision, req.method ?? '', parseTarget(req.url ?? ''))
      const text = `egress: denied (${decision.reason})\n`
      socket.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${String(Buffer.byteLength(text))}\r\nConnection: close\r\n\r\n${text}`)
    } catch (e) {
      raw.destroy()
      this.#bug(e)
    }
  }

  readonly #onClientError = (error: Error & { code?: unknown }, raw: Duplex): void => {
    try {
      raw.destroy()
      const code = typeof error.code === 'string' ? error.code : ''
      if (this.#state === 'revoking' || !code.startsWith('HPE_') || HANGUPS.has(code)) return
      if (code === 'HPE_HEADER_OVERFLOW') {
        this.#selfRevoke('limit', 'maxHeaderBytes', `a worker's request head ran past maxHeaderBytes ${String(this.#limits.maxHeaderBytes)} bytes`)
        return
      }
      // llhttp runs in the kernel, beside the provider keys: a container
      // that sends what HTTP is not gets one try.
      this.#selfRevoke('violation', undefined, `a worker's request did not parse as HTTP/1.1 (${/^[A-Z0-9_]{1,64}$/.test(code) ? code : 'HPE'})`)
    } catch (e) {
      this.#bug(e)
    }
  }

  async #handle(req: IncomingMessage, res: ServerResponse, socket: FlowSocket): Promise<void> {
    const controller = new AbortController()
    this.#aborts.add(controller)
    // The worker hung up, or the answer is done: whatever is still in flight upstream ends.
    res.on('close', () => controller.abort())
    try {
      await this.#serve(req, res, socket, controller.signal)
    } finally {
      this.#aborts.delete(controller)
    }
  }

  async #serve(req: IncomingMessage, res: ServerResponse, socket: FlowSocket, signal: AbortSignal): Promise<void> {
    const method = req.method ?? ''
    const target = req.url ?? ''
    const headers = headerRecord(req.rawHeaders)
    const head = { method, target, headers: headers as EgressHeaders }
    const need = leadingNeed(this.#grant, head)
    let read: Leading | undefined
    if (need.kind !== 'none') {
      read = await readLeading(req, need)
      if (!read.ok || this.#state !== 'open') {
        // The worker went away mid-body, or the grant ended: nothing judged.
        socket.destroy()
        return
      }
    }
    const leading = read?.ok === true ? read.bytes.subarray(0, need.kind === 'command-list' ? Math.min(read.bytes.length, need.max) : read.bytes.length) : undefined
    const decision = decide(this.#grant, leading === undefined ? head : { ...head, leading })
    this.#totals.requests++
    const parsed = parseTarget(target)
    if (decision.verdict === 'deny') {
      this.#denied(decision, method, parsed)
      req.resume()
      answer(res, 403, `egress: denied (${decision.reason})\n`)
      return
    }
    await this.#forward(req, res, decision, method, headers, parsed, read?.ok === true ? read : undefined, signal)
  }

  async #forward(
    req: IncomingMessage,
    res: ServerResponse,
    decision: EgressAllowed,
    method: string,
    headers: HeaderRecord,
    parsed: ParsedTarget | RouteRefused,
    read: { readonly bytes: Buffer; readonly ended: boolean } | undefined,
    signal: AbortSignal,
  ): Promise<void> {
    this.#totals.allowed++
    const routed = decision.bindingId !== undefined
    const fields: Record<string, unknown> = {
      schemaVersion: 1,
      grantId: this.#grantId,
      reason: decision.reason,
      count: 1,
      method,
      host: decision.host,
      ...pathFields(parsed, decision.reason === 'git-fetch' || decision.reason === 'git-push'),
      ...(routed ? { bindingId: decision.bindingId, repo: decision.repo } : {}),
    }
    // Recorded before anything is resolved or dialled: a request whose
    // decision the log does not hold is never sent. One the store refuses is
    // counted and answered before the grant ends: the revocation, which can
    // run at once when no other request is in hand, freezes the totals with
    // it, and the worker reads the 502 before its flow is cut.
    if (!this.#appendRow('proxy.decision', { ...fields, stage: 'policy', verdict: 'allow', why: recordable(decision.why, EGRESS_WHY_BYTES) })) {
      this.#totals.refused++
      req.resume()
      answer(res, 502, 'egress: the decision could not be recorded, so nothing was sent\n')
      this.#unrecorded()
      return
    }
    // A refusal the session makes itself (the head it would send) or the
    // upstream's: counted, recorded on an upstream row, answered 502, and
    // only then, when the row was refused, the grant ended.
    const refuse = (refusal: UpstreamRefused, by: 'session' | 'upstream'): void => {
      if (refusal.sent) this.#totals.failed++
      else this.#totals.refused++
      const address = refusal.address === undefined ? {} : { address: refusal.address.split('%')[0] }
      const code = refusal.code !== undefined && recordableAsIs(refusal.code) ? { code: refusal.code } : {}
      const recorded = this.#appendRow('proxy.decision', {
        ...fields,
        stage: 'upstream',
        verdict: refusal.sent ? 'allow' : 'deny',
        refusal: refusal.reason,
        sent: refusal.sent,
        ...address,
        ...(refusal.denial === undefined ? {} : { denial: refusal.denial.reason }),
        ...code,
        why: recordable(refusal.why, EGRESS_WHY_BYTES),
      })
      req.resume()
      answer(res, 502, `egress: the ${by} refused the request (${refusal.reason})\n`)
      if (!recorded) this.#unrecorded()
    }

    // The record decide() judged, and no other: its Content-Type and
    // Content-Encoding are the values the allow holds the upstream's head to.
    // A Connection naming one of the headers decide() read would have the
    // strip drop it, and send a head nobody judged: refused, unsent.
    const named = connectionNamed(headers['connection'])
    if (JUDGED_HEADERS.some((name) => named.has(name))) {
      refuse(Object.freeze({ ok: false as const, reason: 'head' as const, sent: false, why: "the worker's Connection header names a header decide() judged, which would be dropped from the head that is sent" }), 'session')
      return
    }
    const upstreamHeaders = forwardedHeaders(headers)
    if (routed) {
      const injected = this.#inject(decision.bindingId)
      if (injected === undefined) {
        refuse(Object.freeze({ ok: false as const, reason: 'head' as const, sent: false, why: "the kernel's credential closure did not set exactly one Authorization header" }), 'session')
        return
      }
      upstreamHeaders['authorization'] = injected
    }
    // Exactly one auth header on a bound route and none elsewhere, whatever
    // the strip above let through.
    const auth = Object.keys(upstreamHeaders).filter((name) => AUTH_HEADERS.includes(canonicalHeaderName(name)))
    if (auth.length !== (routed ? 1 : 0)) {
      refuse(Object.freeze({ ok: false as const, reason: 'head' as const, sent: false, why: 'the head would carry an auth header other than the one the binding injects' }), 'session')
      return
    }
    const upstreamHead: UpstreamHead = { method, path: decision.allow.path, headers: upstreamHeaders }

    // The upstream owns the stream it is handed and destroys it on a
    // refusal, so it gets one the session owns: what was read of the body
    // first, then the rest of the worker's request, piped (never pipeline(),
    // which would destroy the request, and the worker's socket, with it).
    let sentBytes = 0
    let options: UpstreamCallOptions = { signal }
    const judged = decision.allow.body
    if (judged !== undefined) {
      const gate = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          sentBytes += chunk.length
          callback(null, chunk)
        },
      })
      if (read !== undefined && read.bytes.length > 0) gate.write(read.bytes)
      if (read?.ended === true) gate.end()
      else {
        req.pipe(gate)
        // The gate can close with the body still arriving: the upstream
        // destroys it on a refusal, and so does a host that answers before
        // it read the body (a 401, a 413 passed on). The pipe undoes itself
        // on that close, and its unpipe() pauses the request, whatever
        // resume() came before; a paused request leaves its flow full,
        // which stops the read of the whole channel (#blocked): the
        // worker's hangup is never read, no other flow is served, and the
        // grant idles out. So the rest is drained once the gate is gone.
        gate.once('close', () => {
          req.unpipe(gate)
          req.resume()
        })
      }
      const body: UpstreamBody = judged.length === undefined ? { stream: gate } : { stream: gate, length: judged.length }
      options = { body, signal }
    }

    const result = await this.#upstream.request(decision.allow, upstreamHead, options)
    if (!result.ok) {
      if (result.sent) this.#totals.sentBytes += sentBytes
      refuse(result, 'upstream')
      return
    }
    const { response } = result
    try {
      const status = response.statusCode ?? 0
      if (CHALLENGES.has(status)) {
        // A challenge would have git ask for a password nobody holds in the
        // container: the worker reads a gateway failure instead, and the log
        // that the host refused the request it read (an expired or revoked
        // binding credential, a push the host would not take).
        response.destroy()
        this.#totals.failed++
        const recorded = this.#appendRow('proxy.decision', {
          ...fields,
          stage: 'upstream',
          verdict: 'allow',
          refusal: 'challenged',
          sent: true,
          why: routed ? `the host answered HTTP ${String(status)} to the binding's credential` : `the host answered HTTP ${String(status)}`,
        })
        req.resume()
        answer(res, 502, routed ? `egress: the host refused the binding's credential (HTTP ${String(status)})\n` : `egress: the host refused the request (HTTP ${String(status)})\n`)
        if (!recorded) this.#unrecorded()
        return
      }
      try {
        res.writeHead(status, answeredHeaders(response.rawHeaders))
      } catch {
        // The host read the request and answered with a head node:http will
        // not write (a status below 100, which llhttp reads): a request that
        // left and failed, counted and recorded as a challenge is, so a 502
        // the worker reads is never a bare allow in the log.
        response.destroy()
        this.#totals.failed++
        const recorded = this.#appendRow('proxy.decision', {
          ...fields,
          stage: 'upstream',
          verdict: 'allow',
          refusal: 'response-head',
          sent: true,
          why: `the host answered HTTP ${String(status)} with a head the session cannot pass on`,
        })
        req.resume()
        answer(res, 502, 'egress: the upstream answered with a head the session cannot pass on\n')
        if (!recorded) this.#unrecorded()
        return
      }
      const counter = new Transform({
        transform: (chunk: Buffer, _encoding, callback) => {
          this.#totals.receivedBytes += chunk.length
          callback(null, chunk)
        },
      })
      await new Promise<void>((resolve) => {
        // Either side breaking destroys the other: a body cut upstream cuts
        // the flow, so the worker reads a reset, never a short body as whole.
        pipeline(response, counter, res, (error) => {
          if (error !== undefined && error !== null) res.socket?.destroy()
          resolve()
        })
      })
    } finally {
      this.#totals.sentBytes += sentBytes
    }
  }

  /** The binding's one header value, set through the kernel's closure; none unless it set exactly one Authorization that HTTP admits. */
  #inject(bindingId: string): string | undefined {
    let calls = 0
    let value: string | undefined
    const set = (name: unknown, given: unknown): void => {
      calls++
      value = undefined
      if (typeof name !== 'string' || name.toLowerCase() !== 'authorization' || typeof given !== 'string' || given === '') return
      try {
        validateHeaderValue(name, given)
      } catch {
        return
      }
      value = given
    }
    try {
      this.#credential(bindingId, set)
    } catch {
      return undefined
    }
    return calls === 1 ? value : undefined
  }

  // ── rows ─────────────────────────────────────────────────────────────────

  /**
   * Append one row under the grant's run and agent (a canary's under
   * neither), and say whether the store took it. A refused decision row is counted for the revocation's
   * detail, and the caller decides what else it ends: it ends the grant
   * (#unrecorded) once the request it judged is counted and answered; the
   * revocation's own is logged, and done resolves all the same.
   */
  #appendRow(type: 'proxy.decision' | 'proxy.grant.revoked', payload: Record<string, unknown>): boolean {
    try {
      this.#store.append({
        type,
        payload,
        ...(this.#runId === undefined ? {} : { runId: this.#runId }),
        ...(this.#agentId === undefined ? {} : { agentId: this.#agentId }),
      })
      return true
    } catch (e) {
      log.error({ grantId: this.#grantId, type, code: e instanceof KernelError ? e.code : undefined }, 'egress session: a row could not be appended')
      if (type === 'proxy.decision') this.#unrecordedRows++
      return false
    }
  }

  /** A deny, held in the window, and the grant revoked once denies pass maxDenied. */
  #denied(decision: EgressDenied, method: string, parsed: ParsedTarget | RouteRefused): void {
    this.#totals.denied++
    const host = decision.host !== undefined && recordableAsIs(decision.host) ? decision.host : undefined
    const row: Record<string, unknown> = {
      schemaVersion: 1,
      grantId: this.#grantId,
      stage: 'policy',
      verdict: 'deny',
      reason: decision.reason,
      ...(METHOD_SHAPE.test(method) && recordableAsIs(method) ? { method } : {}),
      ...(host === undefined ? {} : { host }),
      // A binding is found from a host, so a row without the host names none.
      ...(host !== undefined && decision.bindingId !== undefined ? { bindingId: decision.bindingId } : {}),
      ...(decision.hostRefusal === undefined ? {} : { hostRefusal: decision.hostRefusal }),
      why: recordable(decision.why, EGRESS_WHY_BYTES),
    }
    const detail = BEFORE_PATH.includes(decision.reason) ? {} : pathFields(parsed, decision.reason !== 'query')
    const key = JSON.stringify([row['reason'], row['why'], row['hostRefusal'], row['host'], row['method'], row['bindingId']])
    const window = this.#window ?? this.#openWindow()
    const entry = window.entries.get(key)
    if (entry !== undefined) entry.count++
    else if (window.entries.size < PROXY_DENY_KEYS_PER_SECOND) window.entries.set(key, { row: Object.freeze(row), detail: Object.freeze(detail), count: 1 })
    else {
      const hostRefusal = BY_HOST_REFUSAL.includes(decision.reason) ? decision.hostRefusal : undefined
      const overflowKey = JSON.stringify([decision.reason, hostRefusal])
      const counted = window.overflow.get(overflowKey)
      if (counted !== undefined) counted.count++
      else window.overflow.set(overflowKey, { reason: decision.reason, hostRefusal, count: 1 })
    }
    if (this.#totals.denied > this.#limits.maxDenied) {
      this.#selfRevoke('limit', 'maxDenied', `the worker was denied more than maxDenied ${String(this.#limits.maxDenied)} times`)
    }
  }

  #openWindow(): DenyWindow {
    const window: DenyWindow = {
      timer: this.#clock.setTimeout(() => this.#flushDenies(), DENY_WINDOW_MS),
      entries: new Map(),
      overflow: new Map(),
    }
    this.#window = window
    return window
  }

  /**
   * The window closes: one row per key, a count of one keeping its path, then
   * the overflow. Every row is appended before a refused one ends the grant,
   * so none follows the revocation.
   */
  #flushDenies(): void {
    const window = this.#window
    if (window === undefined) return
    this.#window = undefined
    this.#clock.clearTimeout(window.timer)
    let refused = false
    for (const { row, detail, count } of window.entries.values()) {
      if (!this.#appendRow('proxy.decision', count === 1 ? { ...row, ...detail, count } : { ...row, count })) refused = true
    }
    for (const { reason, hostRefusal, count } of window.overflow.values()) {
      const appended = this.#appendRow('proxy.decision', {
        schemaVersion: 1,
        grantId: this.#grantId,
        stage: 'policy',
        verdict: 'deny',
        reason,
        count,
        overflow: true,
        ...(hostRefusal === undefined ? {} : { hostRefusal }),
        why: PROXY_OVERFLOW_WHY,
      })
      if (!appended) refused = true
    }
    if (refused) this.#unrecorded()
  }

  /**
   * A decision row the store refused: the kernel's bug, never the
   * container's doing, and the grant ends in error, its detail the count of
   * rows lost (#revoke). Once the revocation has begun this does nothing: the
   * grant is ending already, and #revoke counts the loss on its own reason.
   */
  #unrecorded(): void {
    this.#selfRevoke('error', undefined, undefined)
  }

  // ── the end ──────────────────────────────────────────────────────────────

  /**
   * Tell the caller the command exited: once, as the channel refuses a second
   * exit frame (after-exit). A callback that throws or rejects is logged,
   * never raised into the read.
   */
  #tellExited(status: number): void {
    if (this.#exited === undefined) return
    try {
      const told = this.#exited(status)
      if (told instanceof Promise) told.catch(() => log.error({ grantId: this.#grantId }, 'egress session: the exited callback failed'))
    } catch {
      log.error({ grantId: this.#grantId }, 'egress session: the exited callback threw')
    }
  }

  /** The session ends the grant itself: the container is killed once, unless the caller already ended it, then revoked. */
  #selfRevoke(reason: 'violation' | 'limit' | 'error', limit: SessionLimitName | undefined, detail: string | undefined): void {
    if (this.#state === 'revoking') return
    if (!this.#killed && this.#state !== 'ending') {
      this.#killed = true
      try {
        const killing = this.#kill()
        if (killing instanceof Promise) killing.catch(() => log.error({ grantId: this.#grantId }, 'egress session: the kill callback failed'))
      } catch {
        log.error({ grantId: this.#grantId }, 'egress session: the kill callback threw')
      }
    }
    void this.#revoke(reason, limit, detail)
  }

  async #revoke(reason: SessionRevokeReason, limit: SessionLimitName | undefined, detail: string | undefined): Promise<void> {
    if (this.#state === 'revoking') return
    this.#state = 'revoking'
    // Keep reading: a container whose stdout nobody drains blocks, and the
    // kill may not have landed. What it sends now is dropped unread.
    this.#stopFlows()
    this.#releaseInputWaiters()
    // Every request in hand appends its rows before the revocation does.
    while (this.#inHand.size > 0) await Promise.allSettled([...this.#inHand])
    this.#flushDenies()
    const totals: SessionTotals = Object.freeze({
      flows: this.#channel.flowsOpened,
      ...this.#totals,
      durationMs: Math.max(0, Math.round(this.#clock.now() - this.#started)),
    })
    // Read after the waits and the last flush: a row refused in them keeps
    // the reason (#unrecorded), and is on record here.
    const recordedDetail = withLoss(detail, this.#unrecordedRows)
    this.#appendRow('proxy.grant.revoked', {
      schemaVersion: 1,
      grantId: this.#grantId,
      reason,
      ...(limit === undefined ? {} : { limit }),
      ...(recordedDetail === undefined ? {} : { detail: recordedDetail }),
      totals,
    })
    this.#resolve(
      Object.freeze({
        reason,
        limit,
        detail: recordedDetail,
        ready: this.#ready,
        exitStatus: this.#exitStatus,
        stdout: this.#stdout.bytes(),
        stdoutTruncated: this.#stdout.truncated,
        stderr: this.#stderr.bytes(),
        stderrTruncated: this.#stderr.truncated,
        totals,
      }),
    )
  }
}

/**
 * The revocation's detail: its reason's own, then how many decision rows the
 * store refused, which always fits: the reason's own is cut so that both fit
 * EGRESS_DETAIL_BYTES, the revoked row's bound, so a loss is on record
 * whenever it happened, the window #revoke closes last included. Exported for
 * its test alone: today no detail long enough to be cut can meet a loss (the
 * one of arbitrary length, a ReadyJudge clause, is refused in the handshake,
 * before any decision row), so only a direct test holds the cut for the
 * detail a later change may add.
 */
export function withLoss(detail: string | undefined, lost: number): string | undefined {
  if (lost === 0) return detail === undefined ? undefined : recordable(detail, EGRESS_DETAIL_BYTES)
  const loss = `${String(lost)} decision row${lost === 1 ? '' : 's'} could not be appended`
  return detail === undefined ? loss : `${recordable(detail, EGRESS_DETAIL_BYTES - loss.length - 2)}; ${loss}`
}

/** The session's own answer, with Connection: close; a flow whose answer has begun is cut instead. */
function answer(res: ServerResponse, status: number, text: string): void {
  if (res.destroyed || res.writableEnded) return
  if (res.headersSent) {
    res.socket?.destroy()
    return
  }
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(Buffer.byteLength(text)),
    connection: 'close',
  })
  res.end(text)
}

/**
 * Open the session for one container's channel. The grant, its id, the agent
 * and the limits are parsed; a grant naming an identifier the redaction pass
 * would change is refused. Reading starts at once: the mux's first frame is
 * its ready.
 */
export function createEgressSession(options: SessionOptions): EgressSession {
  return new Session(options)
}
