// The channel's frame codec (egress plan E7).
//
// Contract: a sandboxed run reaches the kernel's egress engine only through
// the stdin and stdout of its `docker run -i` child, and this is how that one
// byte stream carries the run's TCP flows and its command's output. The
// kernel end decodes what the container wrote, and everything the container
// writes is attacker-chosen: the in-image mux (E9) shares a uid with the
// agent, so it is not a boundary, and the agent can write any bytes it likes.
// So the decoder is strict, bounded and final:
//
//   * Bounded. A frame is a 9-byte header and a payload. Each type has its
//     payload length (FRAME_RULES), and the data-bearing ones are bounded by
//     the grant's frameMaxBytes. The length is judged when the header's
//     ninth byte arrives, before a byte of the payload is held, so the
//     decoder never holds more than one header and one payload it admitted,
//     whatever length a header claims. Open flows are bounded by maxFlows.
//   * Strict. Every header is judged in a fixed order (CHECK ORDER below) and
//     every refusal has a stable name (FRAME_REFUSALS): an unknown type, a
//     type its sender never sends, a flow id the type does not take, a frame
//     out of the handshake, a length the type does not take, a flow that is
//     not open or a frame its sender may no longer send on it. Nothing is
//     skipped, guessed at or resynchronised.
//   * Final. The first refusal ends the channel: the session revokes the
//     grant and kills the container (proxy.grant.revoked, `limit` for
//     `oversize` and `max-flows`, which name frameMaxBytes and maxFlows,
//     `violation` for the rest). Every later receive() (until finish()),
//     finish() and sendRefusal() returns the same refusal, and receive()
//     decodes nothing more; send() throws it. A receive() after finish() is
//     the caller's error, refusal or none, and throws a TypeError.
//   * Chunking-blind. receive() may be fed the stream in any pieces, one byte
//     at a time included: the frames it hands out, in order across calls, and
//     the refusal after them are the same as for the stream in one piece.
//     That is why a refusal is returned beside the frames decoded before it
//     rather than thrown: a throw would lose the frames earlier in the same
//     piece, which a stream fed in other pieces would have handed out.
//
// The wire, all integers unsigned big-endian:
//
//   offset 0  4 bytes  payload length
//   offset 4  1 byte   type (FRAME_TYPE_CODES)
//   offset 5  4 bytes  flow id: 0 is the channel itself, flows are 1 and up
//   offset 9           payload
//
//   code  type    sent by  flow  payload
//   0x01  ready   mux      0     0..4096 bytes: the mux's self-test report (E9 writes it, W3 reads it)
//   0x02  go      kernel   0     8 bytes: frameMaxBytes, then maxFlows, 4 bytes each
//   0x10  open    mux      1+    none: a TCP connection the mux accepted, the next flow id
//   0x11  data    either   1+    1..frameMaxBytes bytes of the flow
//   0x12  end     either   1+    none: the sender's direction of the flow is finished (a FIN)
//   0x13  close   either   1+    none: the sender is done with the flow
//   0x20  stdout  mux      0     1..frameMaxBytes bytes of the command's stdout
//   0x21  stderr  mux      0     1..frameMaxBytes bytes of the command's stderr
//   0x22  exit    mux      0     1 byte: the command's exit status (128 + n for a death by signal n)
//
// The handshake. The mux's first frame is ready, sent after its self-test
// and before anything else; the kernel's first frame is go, sent only once it
// has read a ready it accepts, and it carries the grant's frameMaxBytes and
// maxFlows, which is how the mux, holding no config, learns them. Nothing but
// go follows ready until go has crossed. The mux listens and spawns the
// command only after go, so a container whose self-test reached something it
// must not (W3) is killed with its command never run.
//
// Flows. Only the mux opens them, as a worker connects to its listener, and
// numbers them 1, 2, 3, ...: each open names the next id, so an id is never
// reused and one the mux never opened is never named. On a flow each side
// sends any number of data frames, at most one end, then exactly one close,
// its last frame there. A close with no end before it from the same side
// says that side's direction was cut, not finished: the receiver resets
// rather than read a clean end of stream, which would pass a truncated body
// as whole. A flow is retired once both closes have crossed, this side's
// sent and the other side's received, and any frame naming a retired flow is
// a refusal.
//
// Data or an end that arrives on a flow after this side sent its close, and
// before the other side's close, was sent before the other side read that
// close: it is handed out marked `stale`, for the session to discard, never
// refused. Only the other side's close can follow its frames, so no frame of
// a flow is ever both in flight and refused.
//
// maxFlows bounds the flows not yet retired, and an open past it is refused
// (`max-flows`, a limit). The count the kernel holds the mux to is never more
// than the mux counts when it sends: the mux retires a flow only after its
// own close, which comes before any later frame of its in its stream, and
// after the kernel's close, which the kernel sent and so counted first. The
// mux therefore holds a connection back, rather than open it, while the cap
// is reached.
//
// After exit the mux sends no open, stdout, stderr or exit; its flows still
// open may finish.
//
// Backpressure is the channel's, not a flow's. The frames carry no credit or
// window, so the one way an end slows the other is to stop reading the
// channel: an end that cannot take more pauses its read of the whole stream
// (E8 the docker stdout, E9 its stdin) until what it holds has drained, and
// the other end's writes then back up into its own sockets and pipes. Nobody
// buffers a flow without bound to keep the others moving: the decoder holds
// one frame, and what an end holds for a flow beyond it is bounded by that
// end's own limits, never by what the other end sends. So a slow reader on
// one flow stalls every flow, and stdout, stderr and exit with them, and a
// worker that reads one connection only after another connection's answer
// arrives stalls until the grant's idleMs ends it. That is the price of a
// protocol with no window for a hostile container to inflate.
//
// CHECK ORDER. A frame can break more than one rule, and its refusal names
// the first it breaks in this order (within a step, in the order listed), so
// the two ends agree on the name a revocation records. Each rule is judged
// on its own, whatever the rules before it found: a frame breaks a rule when
// the right column holds of it. At the header's ninth byte:
//
//   1. unknown-type   the type byte names no type
//   2. direction      the type is one its sender never sends
//   3. channel-flow   a channel type (ready, go, stdout, stderr, exit) names a flow but 0
//      flow-zero      a flow type (open, data, end, close) names flow 0
//   4. ready-twice    a ready, once ready has crossed
//      not-ready      anything but a ready, an unknown type too, before ready has crossed
//      go-twice       a go, once go has crossed
//      before-go      anything but a ready or a go, an unknown type too, before go has crossed
//   5. length         a known type's payload is under its least, or past a fixed most
//      oversize       a data, stdout or stderr payload past frameMaxBytes, at an end that holds it
//   6. after-exit     an open, stdout, stderr or exit, once exit has crossed
//      flow-order     an open naming any flow but the one after the last opened
//      max-flows      an open while maxFlows flows are not yet retired, at an end that holds it
//      unopened-flow  a data, end or close naming a flow past the last opened
//      closed-flow    a data, end or close naming a flow up to the last opened that is not open (flow 0 too)
//      after-close    a data, end or close on an open flow its sender has closed
//      after-end      a data or end on an open flow its sender has ended
//      peer-closed    a data or end this end sends on an open flow the other end has closed
//
// and at the payload's last byte:
//
//   7. go-value       a go of 8 bytes naming a limit out of range, or, at an end that
//                     holds limits, any but those
//
// finish() refuses a stream that ended inside a header (truncated-header) or
// a payload (truncated-payload).
//
// The shared vectors (test/fixtures/egress-frame-vectors.json), which hold
// the mux's inline codec (E9) as well, carry one witness for each place two
// rules meet: wherever one frame can break two rules, X the first it breaks
// and Y another, at an end and a way (receiving or sending) that can meet it,
// a "check order" script there ends with a frame that breaks exactly the
// rules its name lists and is refused by the first. One witness per pair
// does not pin the order on every code path that reaches the pair (a type's
// fixed length or frameMaxBytes, before ready or between ready and go), so
// test/egress-frame.test.ts holds this file, and test/egress-mux.test.ts the
// inline codec, to a second evaluator of the rules above
// (test/helpers/frame-order.ts) in every state an end can reach under limits
// small enough to reach every one that matters (the cap, a retired flow,
// exit): every probe frame, each way, is refused by the first rule the
// evaluator finds it breaks, or by none. The walk also finds each place two
// rules meet and holds the vectors' names and frames to it.
//
// send() holds this end to the same rules, and to one more: once the other
// end's close has arrived on a flow, only this end's close may follow
// (peer-closed). A send it refuses throws, changes nothing and does not end
// the channel. Every other refusal of a send is this end's own bug, at either
// end: a frame no correct end sends. peer-closed is not a bug but a race,
// since the other end decides when its close arrives: a worker that drops its
// connection mid-response makes the mux close the flow while the session
// (E8) still has response bytes queued for it, and a session that closes a
// flow does the same to a mux still relaying. So once receive() hands out the
// other end's close on a flow, an end writes nothing more there but its own
// close, and whatever turns a stream's writes into frames (E8's per-flow
// Duplex _write, E9's socket reader) asks sendRefusal() before it sends, or
// catches FrameError, and never lets a throw escape into a stream's
// internals.
//
// A refusal's message is built from the frame's type name, its flow id, its
// length and the channel's limits, never from its payload, so it is safe to
// record as the revocation's detail as it stands (at most EGRESS_DETAIL_BYTES,
// and nothing the redaction pass would change).
//
// Pure: no I/O, no timers, no streams. The session (E8) owns those.

import { z } from 'zod'

import { KernelError } from '../errors.js'

/** The header: payload length (4), type (1), flow id (4). */
export const FRAME_HEADER_BYTES = 9
/** The most frameMaxBytes any grant may name: kernel.yaml's egress.limits bound (config.ts), held equal by test/egress-frame.test.ts. */
export const FRAME_MAX_BYTES_LIMIT = 1_048_576
/** The most maxFlows any grant may name, as kernel.yaml bounds it. */
export const MAX_FLOWS_LIMIT = 256
/** The longest ready payload: the mux sends it before go has told it frameMaxBytes, so it is bounded by the protocol. */
export const READY_MAX_BYTES = 4_096
/** The last flow id a header can carry: the mux opens no flow after it. */
export const MAX_FLOW_ID = 0xffff_ffff
/** go's payload: frameMaxBytes, then maxFlows. */
const GO_BYTES = 8
/** exit's payload: one status byte. */
const EXIT_BYTES = 1

/** The frame types, as FRAME_TYPE_CODES numbers them on the wire. */
export const FRAME_TYPES = Object.freeze(['ready', 'go', 'open', 'data', 'end', 'close', 'stdout', 'stderr', 'exit'] as const)
export type FrameType = (typeof FRAME_TYPES)[number]

/** Each type's byte on the wire. 0x00 is none, so an all-zero header is refused as unknown-type. */
export const FRAME_TYPE_CODES: Readonly<Record<FrameType, number>> = Object.freeze({
  ready: 0x01,
  go: 0x02,
  open: 0x10,
  data: 0x11,
  end: 0x12,
  close: 0x13,
  stdout: 0x20,
  stderr: 0x21,
  exit: 0x22,
})

/** A Map, so no code finds what an object inherits. */
const TYPE_OF_CODE: ReadonlyMap<number, FrameType> = new Map(FRAME_TYPES.map((type) => [FRAME_TYPE_CODES[type], type]))

/** The two ends of a channel. */
export const CHANNEL_ROLES = Object.freeze(['kernel', 'mux'] as const)
export type ChannelRole = (typeof CHANNEL_ROLES)[number]

const otherSide = (role: ChannelRole): ChannelRole => (role === 'kernel' ? 'mux' : 'kernel')

interface FrameRule {
  /** Who sends it. */
  readonly from: readonly ChannelRole[]
  /** A channel frame names flow 0; a flow frame names a flow, 1 and up. */
  readonly channel: boolean
  readonly minBytes: number
  /** A number of bytes, or the grant's frameMaxBytes. */
  readonly maxBytes: number | 'frameMaxBytes'
}

/** What each type is: who sends it, on which flow ids, with how long a payload. */
export const FRAME_RULES: Readonly<Record<FrameType, Readonly<FrameRule>>> = Object.freeze({
  ready: Object.freeze({ from: Object.freeze(['mux'] as const), channel: true, minBytes: 0, maxBytes: READY_MAX_BYTES }),
  go: Object.freeze({ from: Object.freeze(['kernel'] as const), channel: true, minBytes: GO_BYTES, maxBytes: GO_BYTES }),
  open: Object.freeze({ from: Object.freeze(['mux'] as const), channel: false, minBytes: 0, maxBytes: 0 }),
  data: Object.freeze({ from: CHANNEL_ROLES, channel: false, minBytes: 1, maxBytes: 'frameMaxBytes' }),
  end: Object.freeze({ from: CHANNEL_ROLES, channel: false, minBytes: 0, maxBytes: 0 }),
  close: Object.freeze({ from: CHANNEL_ROLES, channel: false, minBytes: 0, maxBytes: 0 }),
  stdout: Object.freeze({ from: Object.freeze(['mux'] as const), channel: true, minBytes: 1, maxBytes: 'frameMaxBytes' }),
  stderr: Object.freeze({ from: Object.freeze(['mux'] as const), channel: true, minBytes: 1, maxBytes: 'frameMaxBytes' }),
  exit: Object.freeze({ from: Object.freeze(['mux'] as const), channel: true, minBytes: EXIT_BYTES, maxBytes: EXIT_BYTES }),
})

/** Why a frame is refused, in the check order (CHECK ORDER above). Stable: revocations, tests and the shared vectors name these. */
export const FRAME_REFUSALS = Object.freeze([
  'unknown-type',
  'direction',
  'channel-flow',
  'flow-zero',
  'ready-twice',
  'not-ready',
  'go-twice',
  'before-go',
  'length',
  'oversize',
  'after-exit',
  'flow-order',
  'max-flows',
  'unopened-flow',
  'closed-flow',
  'after-close',
  'after-end',
  'peer-closed',
  'go-value',
  'truncated-header',
  'truncated-payload',
] as const)
export type FrameRefusal = (typeof FRAME_REFUSALS)[number]

/** The two limits a frame can break, as kernel.yaml's egress.limits and events/types.ts PROXY_LIMITS name them. */
export type FrameLimitName = 'frameMaxBytes' | 'maxFlows'

/** The refusals that are a grant's limit, not a broken protocol; a Map, so no refusal finds what an object inherits. */
const LIMIT_OF: ReadonlyMap<FrameRefusal, FrameLimitName> = new Map([
  ['oversize', 'frameMaxBytes'],
  ['max-flows', 'maxFlows'],
])

/** A refused frame. `reason` and `limit` are what the session's proxy.grant.revoked carries; the message is its detail. */
export class FrameError extends KernelError {
  readonly refusal: FrameRefusal
  readonly reason: 'violation' | 'limit'
  readonly limit: FrameLimitName | undefined

  constructor(refusal: FrameRefusal, message: string) {
    super('AOS_EGRESS_FRAME', `frame refused (${refusal}): ${message}`)
    this.refusal = refusal
    this.limit = LIMIT_OF.get(refusal)
    this.reason = this.limit === undefined ? 'violation' : 'limit'
  }
}

/**
 * The two limits a channel holds frames to. Extra keys are dropped, so
 * kernel.yaml's whole egress.limits may be handed in; the bounds are the ones
 * kernel.yaml admits.
 */
export const FrameLimits = z.object({
  frameMaxBytes: z.number().int().min(1).max(FRAME_MAX_BYTES_LIMIT),
  maxFlows: z.number().int().min(1).max(MAX_FLOWS_LIMIT),
})
export type FrameLimits = Readonly<z.output<typeof FrameLimits>>

/** One frame, as sent or as decoded. */
export interface Frame {
  readonly type: FrameType
  readonly flow: number
  readonly payload: Uint8Array
}

/** A decoded frame. `stale`: data or an end the other side sent before it read this side's close; the session discards it. */
export interface ReceivedFrame extends Frame {
  readonly stale: boolean
}

/** What one receive() decoded: the frames, in order, then the refusal that ended the channel, if one did. */
export interface ReceiveResult {
  readonly frames: readonly ReceivedFrame[]
  readonly error: FrameError | undefined
}

/** The kernel end holds the grant's limits from the start; the mux end learns them from go. */
export type ChannelOptions = { readonly role: 'kernel'; readonly limits: FrameLimits } | { readonly role: 'mux' }

const ChannelOptionsSchema = z.discriminatedUnion('role', [
  z.object({ role: z.literal('kernel'), limits: FrameLimits }).strict(),
  z.object({ role: z.literal('mux') }).strict(),
])

const FrameSchema = z
  .object({
    type: z.enum(FRAME_TYPES),
    flow: z.number().int().min(0).max(MAX_FLOW_ID),
    payload: z.instanceof(Uint8Array).refine((bytes) => bytes.length <= FRAME_MAX_BYTES_LIMIT, {
      message: `a payload is at most ${String(FRAME_MAX_BYTES_LIMIT)} bytes`,
    }),
  })
  .strict()

/**
 * The bytes of one frame, as the wire spells it. It checks only that the
 * frame can be spelled (a known type, a flow id a header holds, a payload of
 * at most FRAME_MAX_BYTES_LIMIT), not that anyone would accept it: a channel's
 * send() is what holds a frame to the rules, and tests use this to build the
 * frames a channel must refuse.
 */
export function encodeFrame(frame: Frame): Uint8Array {
  const { type, flow, payload } = FrameSchema.parse(frame)
  const bytes = new Uint8Array(FRAME_HEADER_BYTES + payload.length)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, payload.length)
  view.setUint8(4, FRAME_TYPE_CODES[type])
  view.setUint32(5, flow)
  bytes.set(payload, FRAME_HEADER_BYTES)
  return bytes
}

/** go's payload for `limits`. */
export function goPayload(limits: FrameLimits): Uint8Array {
  const { frameMaxBytes, maxFlows } = FrameLimits.parse(limits)
  const bytes = new Uint8Array(GO_BYTES)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, frameMaxBytes)
  view.setUint32(4, maxFlows)
  return bytes
}

/** The limits a go payload names, or none when it is not 8 bytes or names a limit out of range. */
export function readGoPayload(payload: Uint8Array): FrameLimits | undefined {
  if (!(payload instanceof Uint8Array) || payload.length !== GO_BYTES) return undefined
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
  const parsed = FrameLimits.safeParse({ frameMaxBytes: view.getUint32(0), maxFlows: view.getUint32(4) })
  return parsed.success ? Object.freeze(parsed.data) : undefined
}

/** exit's payload for a status: 0 to 255, 128 + n for a death by signal n. */
export function exitPayload(status: number): Uint8Array {
  if (!Number.isInteger(status) || status < 0 || status > 0xff) {
    throw new TypeError(`egress frame: an exit status is a whole number from 0 to 255, got ${String(status)}`)
  }
  return Uint8Array.of(status)
}

/** What one side has sent on one flow. */
interface Side {
  ended: boolean
  closed: boolean
}

type FlowState = Record<ChannelRole, Side>

/** A header whose payload is being read: admitted, so its bytes are held. */
interface Pending {
  readonly type: FrameType
  readonly flow: number
  readonly payload: Uint8Array
  fill: number
}

const hexByte = (code: number): string => `0x${code.toString(16).padStart(2, '0')}`

/** A type's frame with its article, as a refusal's message names it: "an open frame", "a data frame". */
const aFrame = (type: FrameType): string => `${/^[aeiou]/.test(type) ? 'an' : 'a'} ${type} frame`

/** A count of bytes, as a refusal's message spells it: "1 byte", "2 bytes". */
const byteCount = (n: number): string => `${String(n)} ${n === 1 ? 'byte' : 'bytes'}`

/**
 * One end of one channel: it decodes what the other end sends (receive,
 * finish) and spells what this end sends (send), and holds both to the same
 * rules, the state they share (the handshake, the flows and whose close has
 * crossed) between them. One per container, never reused.
 */
export class FrameChannel {
  readonly role: ChannelRole
  #limits: FrameLimits | undefined
  /** ready has crossed: received, at the kernel end; sent, at the mux end. */
  #ready = false
  /** go has crossed: sent, at the kernel end; received, at the mux end. */
  #go = false
  #exited = false
  #lastOpened = 0
  /** The flows not yet retired: at most maxFlows. */
  readonly #flows = new Map<number, FlowState>()
  readonly #header = new Uint8Array(FRAME_HEADER_BYTES)
  #headerFill = 0
  #pending: Pending | undefined
  #failure: FrameError | undefined
  #finished = false

  constructor(options: ChannelOptions) {
    const parsed = ChannelOptionsSchema.parse(options)
    this.role = parsed.role
    this.#limits = parsed.role === 'kernel' ? Object.freeze(parsed.limits) : undefined
  }

  /** The limits frames are held to: the kernel end's from the start, the mux end's once go has arrived. */
  get limits(): FrameLimits | undefined {
    return this.#limits
  }

  /** Flows opened and not yet retired. */
  get openFlows(): number {
    return this.#flows.size
  }

  /** Flows opened in all: the last flow id, since ids run from 1 with no gap. */
  get flowsOpened(): number {
    return this.#lastOpened
  }

  /** The refusal that ended the channel, if one has. */
  get failure(): FrameError | undefined {
    return this.#failure
  }

  /**
   * Decode the next piece of what the other end sent. Frames whole by the
   * end of the piece are handed out; a part frame is held for the next piece.
   * A refusal ends the channel: it comes back after the frames decoded
   * before it, and for every later call until finish(). A call after
   * finish() is the caller's error and throws, whether or not a refusal
   * ended the channel.
   */
  receive(chunk: Uint8Array): ReceiveResult {
    if (this.#finished) throw new TypeError("egress frame: receive() after finish(): the other end's stream has ended")
    if (!(chunk instanceof Uint8Array)) throw new TypeError('egress frame: receive() takes bytes')
    if (this.#failure !== undefined) return Object.freeze({ frames: Object.freeze([]), error: this.#failure })
    const from = otherSide(this.role)
    const frames: ReceivedFrame[] = []
    let at = 0
    for (;;) {
      if (this.#pending === undefined) {
        if (at >= chunk.length) break
        const take = Math.min(FRAME_HEADER_BYTES - this.#headerFill, chunk.length - at)
        this.#header.set(chunk.subarray(at, at + take), this.#headerFill)
        this.#headerFill += take
        at += take
        if (this.#headerFill < FRAME_HEADER_BYTES) break
        this.#headerFill = 0
        const view = new DataView(this.#header.buffer)
        const length = view.getUint32(0)
        const code = view.getUint8(4)
        const flow = view.getUint32(5)
        const admitted = this.#admit(code, flow, length, from)
        if (admitted instanceof FrameError) return this.#fail(frames, admitted)
        // Allocated only now, at the length admitted: a header's claim is
        // never a buffer before it is judged.
        this.#pending = { type: admitted, flow, payload: new Uint8Array(length), fill: 0 }
      }
      const pending = this.#pending
      const take = Math.min(pending.payload.length - pending.fill, chunk.length - at)
      // A copy, never a view of the caller's chunk: the bytes handed out are
      // the bytes that arrived, whatever the caller later does to its buffer.
      pending.payload.set(chunk.subarray(at, at + take), pending.fill)
      pending.fill += take
      at += take
      if (pending.fill < pending.payload.length) break
      this.#pending = undefined
      const refused = this.#check(pending.type, pending.payload)
      if (refused !== undefined) return this.#fail(frames, refused)
      // Stale is read when the frame is whole, not at its header: this end
      // may have sent its close while the payload was arriving.
      const stale = (pending.type === 'data' || pending.type === 'end') && this.#flows.get(pending.flow)?.[this.role].closed === true
      this.#apply(pending.type, pending.flow, pending.payload, from)
      frames.push(Object.freeze({ type: pending.type, flow: pending.flow, payload: pending.payload, stale }))
    }
    return Object.freeze({ frames: Object.freeze(frames), error: undefined })
  }

  /**
   * The other end's stream has ended. A stream that ended inside a frame is
   * refused, and so is every later call; the refusal that ended the channel,
   * if one did, is returned again. Open flows are not a refusal: a container
   * that exits mid-flow is the session's to account for.
   */
  finish(): FrameError | undefined {
    if (!this.#finished) {
      this.#finished = true
      if (this.#failure === undefined && this.#headerFill > 0) {
        this.#failure = new FrameError(
          'truncated-header',
          `the stream ended ${byteCount(this.#headerFill)} into a ${String(FRAME_HEADER_BYTES)}-byte header`,
        )
      } else if (this.#failure === undefined && this.#pending !== undefined) {
        const { type, flow, payload, fill } = this.#pending
        this.#failure = new FrameError(
          'truncated-payload',
          `the stream ended ${byteCount(fill)} into the ${String(payload.length)}-byte payload of ${aFrame(type)} on flow ${String(flow)}`,
        )
      }
      this.#pending = undefined
    }
    return this.#failure
  }

  /**
   * The bytes of a frame this end sends, held to the rules the other end
   * applies. A frame the other end would refuse throws its FrameError and
   * changes nothing; so does any send once the channel has ended.
   */
  send(frame: Frame): Uint8Array {
    if (this.#failure !== undefined) throw this.#failure
    const parsed = FrameSchema.parse(frame)
    const refused = this.#sendRefusal(parsed)
    if (refused !== undefined) throw refused
    const bytes = encodeFrame(parsed)
    this.#apply(parsed.type, parsed.flow, parsed.payload, this.role)
    return bytes
  }

  /**
   * The FrameError send() would throw for `frame`, or none: a query, which
   * changes nothing. A writer asks it before it sends, so that a flow the
   * other end has closed (peer-closed, a race, not a bug) is a frame it drops
   * rather than a throw inside a stream's _write.
   */
  sendRefusal(frame: Frame): FrameError | undefined {
    if (this.#failure !== undefined) return this.#failure
    return this.#sendRefusal(FrameSchema.parse(frame))
  }

  #sendRefusal({ type, flow, payload }: Frame): FrameError | undefined {
    const admitted = this.#admit(FRAME_TYPE_CODES[type], flow, payload.length, this.role)
    return admitted instanceof FrameError ? admitted : this.#check(type, payload)
  }

  #fail(frames: ReceivedFrame[], error: FrameError): ReceiveResult {
    this.#failure = error
    this.#pending = undefined
    this.#headerFill = 0
    return Object.freeze({ frames: Object.freeze(frames), error })
  }

  /** The limits, once the handshake has passed: the gate (step 4) has put go behind every frame that reads them. */
  #heldLimits(): FrameLimits {
    if (this.#limits === undefined) throw new Error('egress frame: no limits past go, which cannot happen')
    return this.#limits
  }

  /** Steps 1 to 6 of the check order, for a header `from` sent: the type it admits, or the refusal. */
  #admit(code: number, flow: number, length: number, from: ChannelRole): FrameType | FrameError {
    const type = TYPE_OF_CODE.get(code)
    if (type === undefined) return new FrameError('unknown-type', `type ${hexByte(code)} is no frame type`)
    const rule = FRAME_RULES[type]
    if (!rule.from.includes(from)) return new FrameError('direction', `the ${from} never sends ${aFrame(type)}`)
    if (rule.channel && flow !== 0) {
      return new FrameError('channel-flow', `${aFrame(type)} is the channel's and names flow 0, not flow ${String(flow)}`)
    }
    if (!rule.channel && flow === 0) {
      return new FrameError('flow-zero', `${aFrame(type)} names flow 0, which is the channel: flows are numbered from 1`)
    }

    if (type === 'ready') {
      if (this.#ready) return new FrameError('ready-twice', 'a second ready frame: the mux sends one, first')
    } else if (!this.#ready) {
      return new FrameError('not-ready', `${aFrame(type)} before ready: the mux's first frame is ready`)
    } else if (type === 'go') {
      if (this.#go) return new FrameError('go-twice', 'a second go frame: the kernel sends one, first')
    } else if (!this.#go) {
      return new FrameError('before-go', `${aFrame(type)} before go: nothing but go follows ready until go has crossed`)
    }

    if (rule.maxBytes === 'frameMaxBytes') {
      if (length < rule.minBytes) return new FrameError('length', `an empty ${type} frame on flow ${String(flow)}`)
      const { frameMaxBytes } = this.#heldLimits()
      if (length > frameMaxBytes) {
        return new FrameError(
          'oversize',
          `${aFrame(type)} of ${byteCount(length)} on flow ${String(flow)}, past frameMaxBytes ${String(frameMaxBytes)}`,
        )
      }
    } else if (length < rule.minBytes || length > rule.maxBytes) {
      const takes = rule.minBytes === rule.maxBytes ? byteCount(rule.minBytes) : `${String(rule.minBytes)} to ${String(rule.maxBytes)} bytes`
      return new FrameError('length', `${aFrame(type)} of ${byteCount(length)}: its payload is ${takes}`)
    }

    switch (type) {
      case 'open': {
        if (this.#exited) return new FrameError('after-exit', `an open of flow ${String(flow)} after exit`)
        const next = this.#lastOpened + 1
        if (flow !== next) {
          return new FrameError('flow-order', `an open of flow ${String(flow)}: the next flow is ${String(next)}`)
        }
        const { maxFlows } = this.#heldLimits()
        if (this.#flows.size >= maxFlows) {
          return new FrameError(
            'max-flows',
            `an open of flow ${String(flow)} with ${String(this.#flows.size)} flows open, at maxFlows ${String(maxFlows)}`,
          )
        }
        break
      }
      case 'data':
      case 'end':
      case 'close': {
        if (flow > this.#lastOpened) return new FrameError('unopened-flow', `${aFrame(type)} on flow ${String(flow)}, never opened`)
        const state = this.#flows.get(flow)
        if (state === undefined) {
          return new FrameError('closed-flow', `${aFrame(type)} on flow ${String(flow)}, which both sides have closed`)
        }
        if (state[from].closed) {
          return new FrameError('after-close', `${aFrame(type)} on flow ${String(flow)} after the ${from}'s own close`)
        }
        if (type !== 'close' && state[from].ended) {
          return new FrameError('after-end', `${aFrame(type)} on flow ${String(flow)} after the ${from}'s own end`)
        }
        // A send only: the other end's close has arrived, so this end's
        // frames there would be discarded unread. Only its close may follow.
        if (from === this.role && type !== 'close' && state[otherSide(from)].closed) {
          return new FrameError('peer-closed', `${aFrame(type)} on flow ${String(flow)} after the ${otherSide(from)}'s close`)
        }
        break
      }
      case 'stdout':
      case 'stderr':
      case 'exit':
        if (this.#exited) return new FrameError('after-exit', `${aFrame(type)} after exit`)
        break
      case 'ready':
      case 'go':
        break
    }
    return type
  }

  /** Step 7, on the whole payload: go's values, which the kernel end must send as its own limits. */
  #check(type: FrameType, payload: Uint8Array): FrameError | undefined {
    if (type !== 'go') return undefined
    const named = readGoPayload(payload)
    if (named === undefined) {
      return new FrameError(
        'go-value',
        `a go frame naming a limit out of range: frameMaxBytes is 1 to ${String(FRAME_MAX_BYTES_LIMIT)} and maxFlows 1 to ${String(MAX_FLOWS_LIMIT)}`,
      )
    }
    const held = this.#limits
    if (held !== undefined && (named.frameMaxBytes !== held.frameMaxBytes || named.maxFlows !== held.maxFlows)) {
      return new FrameError(
        'go-value',
        `a go frame naming frameMaxBytes ${String(named.frameMaxBytes)} and maxFlows ${String(named.maxFlows)}, ` +
          `not the channel's ${String(held.frameMaxBytes)} and ${String(held.maxFlows)}`,
      )
    }
    return undefined
  }

  /** A whole, checked frame `from` sent changes the state the two ends share. */
  #apply(type: FrameType, flow: number, payload: Uint8Array, from: ChannelRole): void {
    switch (type) {
      case 'ready':
        this.#ready = true
        break
      case 'go':
        this.#go = true
        this.#limits ??= readGoPayload(payload)
        break
      case 'open':
        this.#lastOpened = flow
        this.#flows.set(flow, { kernel: { ended: false, closed: false }, mux: { ended: false, closed: false } })
        break
      case 'end': {
        const state = this.#flows.get(flow)
        if (state !== undefined) state[from].ended = true
        break
      }
      case 'close': {
        const state = this.#flows.get(flow)
        if (state === undefined) break
        state[from].closed = true
        // Retired once both closes have crossed, and not before: a frame the
        // other end sent before it read this end's close is still arriving.
        if (state.kernel.closed && state.mux.closed) this.#flows.delete(flow)
        break
      }
      case 'exit':
        this.#exited = true
        break
      case 'data':
      case 'stdout':
      case 'stderr':
        break
    }
  }
}
