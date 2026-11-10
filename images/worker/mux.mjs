// @ts-check
// The in-image mux (egress plan E9): /opt/aos/mux.mjs in the worker image.
//
// Contract: a sandboxed run's container is started as
//
//   docker run --init -i --network none ... <image id> node /opt/aos/mux.mjs -- <command> [args...]
//
// and this file is the first process docker-init (tini, which --init makes
// PID 1) starts. --init is the driver's to pass (S2's argv, held by its audit;
// L1 checks it on the Mac), and the mux relies on it: as PID 1 a node process
// reaps only the children it spawned, so every grandchild the command orphans
// would stay a zombie counted against the container's pids cap until fork
// fails, and SIGTERM, which PID 1 takes no default action on, would do
// nothing. With tini as PID 1, orphans are reaped, a SIGTERM to the container
// ends the mux, and once the mux exits tini does too, so the kernel ends
// everything left in the container. Its stdin and stdout are the docker -i
// channel to the kernel's egress session (src/egress/session.ts), framed as
// src/egress/frame.ts says. With --network none the channel is the run's only
// way out: the mux listens on the container's own 127.0.0.1:3128, which the
// image names as HTTP(S)_PROXY (I1), and carries each connection a worker
// opens there to the kernel as one flow, beside the command's stdout, stderr
// and exit status.
//
// The mux is NOT a boundary. It runs under the agent's uid, so the agent can
// kill it, replace it or write any frame it likes, and the kernel parses
// everything on the channel as untrusted (frame.ts, session.ts). Its job is to
// be correct for an honest worker, never to enforce: it decides nothing about
// where a request may go (the kernel's decide() does, on the Mac), it holds
// no config and no secret, and it reads no environment variable and no file
// (test/egress-mux.test.ts pins that). The flow limits it applies,
// frameMaxBytes and maxFlows, it learns from the kernel's go frame; its own
// bounds (MAX_HELD, PROBE_TIMEOUT_MS, FLUSH_TIMEOUT_MS, EXIT_GRACE_MS,
// EXIT_GRACE_MAX_MS) are constants fixed here, never config. Its address is the literal
// 127.0.0.1:3128, which is kernel.yaml's egress.muxPort (config.ts holds it to
// 3128) and the image's proxy setting; nothing passes it a port.
//
// Node builtins only, and no build step: the image copies this file as it
// stands (I1), so it imports nothing but node: modules (test/hygiene.test.ts)
// and carries its own copy of the frame codec, MuxChannel below, which the
// shared vectors (test/fixtures/egress-frame-vectors.json) hold to frame.ts's
// mux end byte for byte and refusal for refusal (test/egress-mux.test.ts
// replays every mux script and runs the two side by side on random
// conversations).
//
// What it does, in order:
//
//   1. Self-test. Before anything else it tries to reach what a run must
//      never reach (SELF_TEST): the Mac's loopback as a Colima VM sees it
//      (192.168.5.2 on pmmcp's 8766 and the control plane's 7777,
//      host.lima.internal and host.docker.internal on 8766), the internet
//      (1.1.1.1:443), and a name lookup (example.com). Each probe is bounded
//      by PROBE_TIMEOUT_MS and all run at once.
//   2. Ready. It sends one ready frame carrying the self-test's report
//      (below), success or not: the kernel judges it (session.ts
//      acceptReady, W3's judge), and a container whose self-test reached
//      anything gets no go, so its command never runs.
//   3. Go. Nothing happens until the kernel's go arrives, carrying
//      frameMaxBytes and maxFlows. Only then does the mux listen on
//      127.0.0.1:3128 and, once listening, spawn the command, with no stdin,
//      its stdout and stderr piped into stdout and stderr frames, in its own
//      process group.
//   4. Relay, until the end (below).
//
// The ready report is ASCII JSON, at most READY_MAX_BYTES, keys in this order:
//
//   {"mux":1,"probes":[{"probe":"connect","target":"192.168.5.2:8766","reached":false,"error":"ENETUNREACH"},
//     ...,{"probe":"lookup","target":"example.com","reached":false,"error":"ENOTFOUND"}],"reached":0}
//
// one entry per SELF_TEST probe, in its order. `reached` is true when the
// probe met something: a TCP connection opened; a peer refused or reset it
// (ECONNREFUSED, ECONNRESET: something answered, so there is a route); or the
// lookup gave an address. `error` is the error's code (an upper-case name of
// at most 32 characters, EOTHER for anything else, ETIMEDOUT for a probe
// that did not settle in time), and null only for a connection that opened or
// a lookup that answered. The top-level `reached` counts the probes reached.
// A judge should accept only a report naming every probe, in order, none
// reached, each error one that says there is no route: ENETUNREACH for a
// connect by address (with --network none the container has loopback alone),
// EAI_AGAIN or ENOTFOUND for a connect by name and for the lookup (no
// resolver answers). Anything else is refused, ETIMEDOUT above all: a SYN
// that went unanswered went somewhere, so there is a route (W3's judge; L1
// confirms the codes in both VMs).
//
// Flows. A connection the listener accepts becomes the next flow (an open
// frame), unless maxFlows flows are not yet retired: then it is held, paused,
// until one retires (frame.ts: the mux holds a connection back rather than
// open it past the cap), and past MAX_HELD held connections a new one is
// destroyed. What the worker writes goes out as data frames of at most
// frameMaxBytes; its FIN as an end; its going away as the mux's close, with
// no end before it when it did not finish its side, which the kernel reads as
// a cut. The kernel's data is written to the socket and its end is the
// socket's FIN. The kernel's close after its end is clean: the mux sends its
// own close at once (nothing else may follow the kernel's close) and the
// socket lingers, drained and discarded, until the worker closes it, so the
// answer is flushed and no unread byte turns the close into a reset. The
// kernel's close with no end before it is a cut: the socket is reset (RST),
// never ended, so the worker reads a reset where an end would have passed a
// short answer as whole. (On Linux an RST that lands behind bytes the worker
// has not read yet can read as those bytes and then an end; the answer's own
// HTTP framing, which node:http always gives the session's answers, still
// shows it short.)
//
// Backpressure is the channel's (frame.ts). When a socket cannot take what
// the kernel sent, the mux stops reading stdin until that socket drains (or
// closes, or its flow retires); when stdout cannot take more, it pauses every
// flow's socket and the command's stdout and stderr until stdout drains, and
// pauses them again on every frame stdout refuses while it is full, not only
// the first: node resumes the command's pipes itself once the command exits
// (child_process's flushStdio), so a pause made once does not hold. So it
// buffers at most one stdin chunk, and beyond stdout's high-water mark at
// most one chunk from each flow's socket and each of the command's pipes
// (and its own small frames), whatever either end sends.
//
// The end. When the command exits, its process group is killed, and its exit
// status is sent once its stdout and stderr have closed (an exit frame: the
// status, or 128 + n for a death by signal n, 127 when the command could not
// be found, 126 when it could not be run). A descendant that left the group
// (setsid, a shell with job control) outlives that kill and may hold the
// pipes open, so the mux gives them a grace, then closes them and sends the
// status all the same. The grace is EXIT_GRACE_MS of time in which stdout
// takes frames: its clock stops while stdout is full, since the mux itself
// leaves the pipes unread then and a slow kernel should cost no output, and
// runs on from where it stopped once stdout drains, never from zero. However
// often stdout fills, the grace ends EXIT_GRACE_MAX_MS after the exit, full
// stdout or not, so a descendant that keeps writing faster than the kernel
// reads holds the status back no longer than that (and a kernel that reads
// nothing for that long loses what is still in the pipes then). Such a descendant may also
// hold a flow open: the kernel's idle limit and wallclock bound it, and once
// the mux exits tini does too, and the container's PID namespace ends
// whatever is left. After exit no flow opens: the listener closes and held
// connections are destroyed, and the flows still open finish. The mux then
// exits on its own once every flow has retired. It also exits, killing the
// command's group, when it reads the end of stdin (the kernel ended the
// channel), and on any frame it refuses. It sees stdin's end only when it
// reads it, and a socket that cannot take the kernel's data stops it reading
// stdin (Backpressure, above): so closing the channel need not end a run whose
// worker stopped reading, and the kernel ends such a run by killing its
// container by name. The mux's own exit code (MUX_EXIT) says how it ended; the
// command's status travels only in the exit frame. The mux's own complaints go
// to its stderr (docker's stderr, which the driver captures, bounded), never
// into a frame.

import { spawn as spawnChild } from 'node:child_process'
import { lookup as dnsLookup } from 'node:dns/promises'
import { connect as netConnect, createServer } from 'node:net'
import { constants as osConstants } from 'node:os'

/** @import { Readable, Writable, Duplex } from 'node:stream' */
/** @import { Socket } from 'node:net' */
/** @import { ChildProcess } from 'node:child_process' */

// ── the wire: an inline copy of src/egress/frame.ts's mux end ───────────────

/** The address the mux listens on, inside the container: the image's HTTP(S)_PROXY. */
export const MUX_HOST = '127.0.0.1'
export const MUX_PORT = 3128

/** The header: payload length (4), type (1), flow id (4). */
export const FRAME_HEADER_BYTES = 9
/** The longest ready payload. */
export const READY_MAX_BYTES = 4_096
/** The most frameMaxBytes a go may name. */
export const FRAME_MAX_BYTES_LIMIT = 1_048_576
/** The most maxFlows a go may name. */
export const MAX_FLOWS_LIMIT = 256
/** The last flow id a header can carry. */
export const MAX_FLOW_ID = 0xffff_ffff
const GO_BYTES = 8
const EXIT_BYTES = 1

/** @typedef {'ready' | 'go' | 'open' | 'data' | 'end' | 'close' | 'stdout' | 'stderr' | 'exit'} FrameType */
/** @typedef {'kernel' | 'mux'} Sender */

/** @type {readonly FrameType[]} */
export const FRAME_TYPES = Object.freeze(['ready', 'go', 'open', 'data', 'end', 'close', 'stdout', 'stderr', 'exit'])

/** Each type's byte on the wire. @type {Readonly<Record<FrameType, number>>} */
export const FRAME_TYPE_CODES = Object.freeze({
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

/** @type {ReadonlyMap<number, FrameType>} */
const TYPE_OF_CODE = new Map(FRAME_TYPES.map((type) => [FRAME_TYPE_CODES[type], type]))

/**
 * @typedef {object} FrameRule
 * @property {readonly Sender[]} from who sends it
 * @property {boolean} channel a channel frame names flow 0, a flow frame a flow from 1
 * @property {number} minBytes
 * @property {number | 'frameMaxBytes'} maxBytes
 */

/** @type {readonly Sender[]} */
const MUX = Object.freeze(['mux'])
/** @type {readonly Sender[]} */
const KERNEL = Object.freeze(['kernel'])
/** @type {readonly Sender[]} */
const EITHER = Object.freeze(['kernel', 'mux'])

/** What each type is: who sends it, on which flow ids, with how long a payload. @type {Readonly<Record<FrameType, FrameRule>>} */
export const FRAME_RULES = Object.freeze({
  ready: Object.freeze({ from: MUX, channel: true, minBytes: 0, maxBytes: READY_MAX_BYTES }),
  go: Object.freeze({ from: KERNEL, channel: true, minBytes: GO_BYTES, maxBytes: GO_BYTES }),
  open: Object.freeze({ from: MUX, channel: false, minBytes: 0, maxBytes: 0 }),
  data: Object.freeze({ from: EITHER, channel: false, minBytes: 1, maxBytes: /** @type {'frameMaxBytes'} */ ('frameMaxBytes') }),
  end: Object.freeze({ from: EITHER, channel: false, minBytes: 0, maxBytes: 0 }),
  close: Object.freeze({ from: EITHER, channel: false, minBytes: 0, maxBytes: 0 }),
  stdout: Object.freeze({ from: MUX, channel: true, minBytes: 1, maxBytes: /** @type {'frameMaxBytes'} */ ('frameMaxBytes') }),
  stderr: Object.freeze({ from: MUX, channel: true, minBytes: 1, maxBytes: /** @type {'frameMaxBytes'} */ ('frameMaxBytes') }),
  exit: Object.freeze({ from: MUX, channel: true, minBytes: EXIT_BYTES, maxBytes: EXIT_BYTES }),
})

/**
 * @typedef {'unknown-type' | 'direction' | 'channel-flow' | 'flow-zero' | 'ready-twice' | 'not-ready' | 'go-twice'
 *   | 'before-go' | 'length' | 'oversize' | 'after-exit' | 'flow-order' | 'max-flows' | 'unopened-flow' | 'closed-flow'
 *   | 'after-close' | 'after-end' | 'peer-closed' | 'go-value' | 'truncated-header' | 'truncated-payload'} FrameRefusal
 */

/** Why a frame is refused, in frame.ts's check order. @type {readonly FrameRefusal[]} */
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
])

/** A refused frame: the refusal's name is frame.ts's, the message is built from the header, never the payload. */
export class MuxFrameError extends Error {
  /**
   * @param {FrameRefusal} refusal
   * @param {string} message
   */
  constructor(refusal, message) {
    super(`frame refused (${refusal}): ${message}`)
    this.name = 'MuxFrameError'
    /** @readonly */
    this.refusal = refusal
  }
}

/**
 * @typedef {object} Frame
 * @property {FrameType} type
 * @property {number} flow
 * @property {Uint8Array} payload
 */
/** @typedef {Frame & { readonly stale: boolean }} ReceivedFrame */
/** @typedef {{ readonly frameMaxBytes: number, readonly maxFlows: number }} FrameLimits */
/** @typedef {{ readonly frames: readonly ReceivedFrame[], readonly error: MuxFrameError | undefined }} ReceiveResult */

const EMPTY = new Uint8Array(0)

/** @param {number} code */
const hexByte = (code) => `0x${code.toString(16).padStart(2, '0')}`
/** @param {FrameType} type */
const aFrame = (type) => `${/^[aeiou]/.test(type) ? 'an' : 'a'} ${type} frame`
/** @param {number} n */
const byteCount = (n) => `${String(n)} ${n === 1 ? 'byte' : 'bytes'}`
/** @param {Sender} sender @returns {Sender} */
const otherSide = (sender) => (sender === 'kernel' ? 'mux' : 'kernel')

/**
 * A frame as the wire spells it, or a TypeError when it cannot be spelt (an
 * unknown type, a flow id no header holds, a payload past FRAME_MAX_BYTES_LIMIT).
 * @param {Frame} frame
 * @returns {Uint8Array}
 */
export function encodeFrame(frame) {
  const { type, flow, payload } = spelt(frame)
  const bytes = new Uint8Array(FRAME_HEADER_BYTES + payload.length)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, payload.length)
  view.setUint8(4, FRAME_TYPE_CODES[type])
  view.setUint32(5, flow)
  bytes.set(payload, FRAME_HEADER_BYTES)
  return bytes
}

/**
 * @param {Frame} frame
 * @returns {Frame}
 */
function spelt(frame) {
  if (typeof frame !== 'object' || frame === null) throw new TypeError('mux frame: a frame is {type, flow, payload}')
  const { type, flow, payload } = frame
  if (typeof type !== 'string' || !Object.hasOwn(FRAME_TYPE_CODES, type)) throw new TypeError('mux frame: an unknown frame type')
  if (!Number.isInteger(flow) || flow < 0 || flow > MAX_FLOW_ID) throw new TypeError('mux frame: a flow id is a whole number from 0 to 2^32 - 1')
  if (!(payload instanceof Uint8Array) || payload.length > FRAME_MAX_BYTES_LIMIT) {
    throw new TypeError(`mux frame: a payload is at most ${String(FRAME_MAX_BYTES_LIMIT)} bytes`)
  }
  return { type, flow, payload }
}

/**
 * The limits a go payload names, or none when it is not 8 bytes or names one out of range.
 * @param {Uint8Array} payload
 * @returns {FrameLimits | undefined}
 */
export function readGoPayload(payload) {
  if (!(payload instanceof Uint8Array) || payload.length !== GO_BYTES) return undefined
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
  const frameMaxBytes = view.getUint32(0)
  const maxFlows = view.getUint32(4)
  if (frameMaxBytes < 1 || frameMaxBytes > FRAME_MAX_BYTES_LIMIT || maxFlows < 1 || maxFlows > MAX_FLOWS_LIMIT) return undefined
  return Object.freeze({ frameMaxBytes, maxFlows })
}

/**
 * exit's payload for a status, 0 to 255.
 * @param {number} status
 */
export function exitPayload(status) {
  if (!Number.isInteger(status) || status < 0 || status > 0xff) throw new TypeError(`mux frame: an exit status is 0 to 255, got ${String(status)}`)
  return Uint8Array.of(status)
}

/** @typedef {{ ended: boolean, closed: boolean }} Side */
/** @typedef {{ kernel: Side, mux: Side }} FlowState */

/**
 * The mux end of one channel, as frame.ts's FrameChannel is with role 'mux':
 * it decodes what the kernel sends (receive, finish) and spells what the mux
 * sends (send), holding both to the same rules in the same check order. One
 * per container.
 */
export class MuxChannel {
  /** @type {FrameLimits | undefined} */
  #limits = undefined
  /** The mux has sent ready. */
  #ready = false
  /** The kernel's go has arrived. */
  #go = false
  #exited = false
  #lastOpened = 0
  /** @type {Map<number, FlowState>} */
  #flows = new Map()
  #header = new Uint8Array(FRAME_HEADER_BYTES)
  #headerFill = 0
  /** @type {{ readonly type: FrameType, readonly flow: number, readonly payload: Uint8Array, fill: number } | undefined} */
  #pending = undefined
  /** @type {MuxFrameError | undefined} */
  #failure = undefined
  #finished = false

  /** The limits go named, once it arrived. */
  get limits() {
    return this.#limits
  }

  /** Flows opened and not yet retired. */
  get openFlows() {
    return this.#flows.size
  }

  /** Flows opened in all: the last flow id. */
  get flowsOpened() {
    return this.#lastOpened
  }

  /** The refusal that ended the channel, if one has. */
  get failure() {
    return this.#failure
  }

  /**
   * Decode the next piece of what the kernel sent: the frames whole by its
   * end, then the refusal that ended the channel, if one did.
   * @param {Uint8Array} chunk
   * @returns {ReceiveResult}
   */
  receive(chunk) {
    if (this.#finished) throw new TypeError("mux frame: receive() after finish(): the kernel's stream has ended")
    if (!(chunk instanceof Uint8Array)) throw new TypeError('mux frame: receive() takes bytes')
    if (this.#failure !== undefined) return Object.freeze({ frames: Object.freeze([]), error: this.#failure })
    /** @type {ReceivedFrame[]} */
    const frames = []
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
        const admitted = this.#admit(code, flow, length, 'kernel')
        if (admitted instanceof MuxFrameError) return this.#fail(frames, admitted)
        // Allocated only once its length is admitted.
        this.#pending = { type: admitted, flow, payload: new Uint8Array(length), fill: 0 }
      }
      const pending = this.#pending
      const take = Math.min(pending.payload.length - pending.fill, chunk.length - at)
      pending.payload.set(chunk.subarray(at, at + take), pending.fill)
      pending.fill += take
      at += take
      if (pending.fill < pending.payload.length) break
      this.#pending = undefined
      const refused = this.#check(pending.type, pending.payload)
      if (refused !== undefined) return this.#fail(frames, refused)
      const stale = (pending.type === 'data' || pending.type === 'end') && this.#flows.get(pending.flow)?.mux.closed === true
      this.#apply(pending.type, pending.flow, pending.payload, 'kernel')
      frames.push(Object.freeze({ type: pending.type, flow: pending.flow, payload: pending.payload, stale }))
    }
    return Object.freeze({ frames: Object.freeze(frames), error: undefined })
  }

  /**
   * The kernel's stream has ended: a stream that ended inside a frame is refused.
   * @returns {MuxFrameError | undefined}
   */
  finish() {
    if (!this.#finished) {
      this.#finished = true
      if (this.#failure === undefined && this.#headerFill > 0) {
        this.#failure = new MuxFrameError('truncated-header', `the stream ended ${byteCount(this.#headerFill)} into a ${String(FRAME_HEADER_BYTES)}-byte header`)
      } else if (this.#failure === undefined && this.#pending !== undefined) {
        const { type, flow, payload, fill } = this.#pending
        this.#failure = new MuxFrameError(
          'truncated-payload',
          `the stream ended ${byteCount(fill)} into the ${String(payload.length)}-byte payload of ${aFrame(type)} on flow ${String(flow)}`,
        )
      }
      this.#pending = undefined
    }
    return this.#failure
  }

  /**
   * The bytes of a frame the mux sends, held to the rules the kernel applies:
   * a frame the kernel would refuse throws its MuxFrameError and changes nothing.
   * @param {Frame} frame
   * @returns {Uint8Array}
   */
  send(frame) {
    if (this.#failure !== undefined) throw this.#failure
    const f = spelt(frame)
    const refused = this.#sendRefusal(f)
    if (refused !== undefined) throw refused
    const bytes = encodeFrame(f)
    this.#apply(f.type, f.flow, f.payload, 'mux')
    return bytes
  }

  /**
   * The refusal send() would throw for `frame`, or none. Changes nothing.
   * @param {Frame} frame
   * @returns {MuxFrameError | undefined}
   */
  sendRefusal(frame) {
    if (this.#failure !== undefined) return this.#failure
    return this.#sendRefusal(spelt(frame))
  }

  /** @param {Frame} frame */
  #sendRefusal({ type, flow, payload }) {
    const admitted = this.#admit(FRAME_TYPE_CODES[type], flow, payload.length, 'mux')
    return admitted instanceof MuxFrameError ? admitted : this.#check(type, payload)
  }

  /**
   * @param {ReceivedFrame[]} frames
   * @param {MuxFrameError} error
   * @returns {ReceiveResult}
   */
  #fail(frames, error) {
    this.#failure = error
    this.#pending = undefined
    this.#headerFill = 0
    return Object.freeze({ frames: Object.freeze(frames), error })
  }

  /** @returns {FrameLimits} */
  #heldLimits() {
    if (this.#limits === undefined) throw new Error('mux frame: no limits past go, which cannot happen')
    return this.#limits
  }

  /**
   * frame.ts's check order, steps 1 to 6, for a header `from` sent.
   * @param {number} code
   * @param {number} flow
   * @param {number} length
   * @param {Sender} from
   * @returns {FrameType | MuxFrameError}
   */
  #admit(code, flow, length, from) {
    const type = TYPE_OF_CODE.get(code)
    if (type === undefined) return new MuxFrameError('unknown-type', `type ${hexByte(code)} is no frame type`)
    const rule = FRAME_RULES[type]
    if (!rule.from.includes(from)) return new MuxFrameError('direction', `the ${from} never sends ${aFrame(type)}`)
    if (rule.channel && flow !== 0) return new MuxFrameError('channel-flow', `${aFrame(type)} is the channel's and names flow 0, not flow ${String(flow)}`)
    if (!rule.channel && flow === 0) return new MuxFrameError('flow-zero', `${aFrame(type)} names flow 0, which is the channel: flows are numbered from 1`)

    if (type === 'ready') {
      if (this.#ready) return new MuxFrameError('ready-twice', 'a second ready frame: the mux sends one, first')
    } else if (!this.#ready) {
      return new MuxFrameError('not-ready', `${aFrame(type)} before ready: the mux's first frame is ready`)
    } else if (type === 'go') {
      if (this.#go) return new MuxFrameError('go-twice', 'a second go frame: the kernel sends one, first')
    } else if (!this.#go) {
      return new MuxFrameError('before-go', `${aFrame(type)} before go: nothing but go follows ready until go has crossed`)
    }

    if (rule.maxBytes === 'frameMaxBytes') {
      if (length < rule.minBytes) return new MuxFrameError('length', `an empty ${type} frame on flow ${String(flow)}`)
      const { frameMaxBytes } = this.#heldLimits()
      if (length > frameMaxBytes) {
        return new MuxFrameError('oversize', `${aFrame(type)} of ${byteCount(length)} on flow ${String(flow)}, past frameMaxBytes ${String(frameMaxBytes)}`)
      }
    } else if (length < rule.minBytes || length > rule.maxBytes) {
      const takes = rule.minBytes === rule.maxBytes ? byteCount(rule.minBytes) : `${String(rule.minBytes)} to ${String(rule.maxBytes)} bytes`
      return new MuxFrameError('length', `${aFrame(type)} of ${byteCount(length)}: its payload is ${takes}`)
    }

    switch (type) {
      case 'open': {
        if (this.#exited) return new MuxFrameError('after-exit', `an open of flow ${String(flow)} after exit`)
        const next = this.#lastOpened + 1
        if (flow !== next) return new MuxFrameError('flow-order', `an open of flow ${String(flow)}: the next flow is ${String(next)}`)
        const { maxFlows } = this.#heldLimits()
        if (this.#flows.size >= maxFlows) {
          return new MuxFrameError('max-flows', `an open of flow ${String(flow)} with ${String(this.#flows.size)} flows open, at maxFlows ${String(maxFlows)}`)
        }
        break
      }
      case 'data':
      case 'end':
      case 'close': {
        if (flow > this.#lastOpened) return new MuxFrameError('unopened-flow', `${aFrame(type)} on flow ${String(flow)}, never opened`)
        const state = this.#flows.get(flow)
        if (state === undefined) return new MuxFrameError('closed-flow', `${aFrame(type)} on flow ${String(flow)}, which both sides have closed`)
        if (state[from].closed) return new MuxFrameError('after-close', `${aFrame(type)} on flow ${String(flow)} after the ${from}'s own close`)
        if (type !== 'close' && state[from].ended) return new MuxFrameError('after-end', `${aFrame(type)} on flow ${String(flow)} after the ${from}'s own end`)
        // A send only: once the kernel's close has arrived, only the mux's close may follow.
        if (from === 'mux' && type !== 'close' && state.kernel.closed) {
          return new MuxFrameError('peer-closed', `${aFrame(type)} on flow ${String(flow)} after the ${otherSide(from)}'s close`)
        }
        break
      }
      case 'stdout':
      case 'stderr':
      case 'exit':
        if (this.#exited) return new MuxFrameError('after-exit', `${aFrame(type)} after exit`)
        break
      case 'ready':
      case 'go':
        break
    }
    return type
  }

  /**
   * Step 7, on the whole payload: go names limits in range.
   * @param {FrameType} type
   * @param {Uint8Array} payload
   * @returns {MuxFrameError | undefined}
   */
  #check(type, payload) {
    if (type !== 'go') return undefined
    const named = readGoPayload(payload)
    if (named === undefined) {
      return new MuxFrameError(
        'go-value',
        `a go frame naming a limit out of range: frameMaxBytes is 1 to ${String(FRAME_MAX_BYTES_LIMIT)} and maxFlows 1 to ${String(MAX_FLOWS_LIMIT)}`,
      )
    }
    const held = this.#limits
    if (held !== undefined && (named.frameMaxBytes !== held.frameMaxBytes || named.maxFlows !== held.maxFlows)) {
      return new MuxFrameError('go-value', 'a go frame naming other limits than the channel holds')
    }
    return undefined
  }

  /**
   * A whole, checked frame `from` sent changes the state the two ends share.
   * @param {FrameType} type
   * @param {number} flow
   * @param {Uint8Array} payload
   * @param {Sender} from
   */
  #apply(type, flow, payload, from) {
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
        // Retired once both closes have crossed, and not before.
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

// ── the self-test ───────────────────────────────────────────────────────────

/**
 * @typedef {{ readonly probe: 'connect', readonly host: string, readonly port: number }
 *   | { readonly probe: 'lookup', readonly host: string }} Probe
 */

/** What a run must never reach, in the order the ready report names it. @type {readonly Probe[]} */
export const SELF_TEST = Object.freeze([
  // The Mac's loopback as a Colima VM reaches it (Lima rewrites 192.168.5.2
  // to 127.0.0.1): pmmcp, unauthenticated in warn mode, and the control plane.
  Object.freeze({ probe: /** @type {const} */ ('connect'), host: '192.168.5.2', port: 8766 }),
  Object.freeze({ probe: /** @type {const} */ ('connect'), host: '192.168.5.2', port: 7777 }),
  // The same, by the names Lima and Docker give the host.
  Object.freeze({ probe: /** @type {const} */ ('connect'), host: 'host.lima.internal', port: 8766 }),
  Object.freeze({ probe: /** @type {const} */ ('connect'), host: 'host.docker.internal', port: 8766 }),
  // The internet, by address, and any resolver at all.
  Object.freeze({ probe: /** @type {const} */ ('connect'), host: '1.1.1.1', port: 443 }),
  Object.freeze({ probe: /** @type {const} */ ('lookup'), host: 'example.com' }),
])

/** How long one probe may take before it is reported unreached, ETIMEDOUT. All run at once. */
export const PROBE_TIMEOUT_MS = 2_000

/** @typedef {{ readonly reached: boolean, readonly error: string | null }} ProbeOutcome */
/** @typedef {(host: string, port: number, timeoutMs: number) => Promise<ProbeOutcome>} ConnectProbe */
/** @typedef {(host: string, timeoutMs: number) => Promise<ProbeOutcome>} LookupProbe */
/** @typedef {{ readonly probe: 'connect' | 'lookup', readonly target: string, readonly reached: boolean, readonly error: string | null }} ProbeResult */

const ERROR_CODE = /^[A-Z][A-Z0-9_]{0,31}$/
/** Errors that mean a peer answered: there is a route, whatever it said. */
const ANSWERED = new Set(['ECONNREFUSED', 'ECONNRESET'])

/**
 * An error's code as the report spells it: an upper-case name, or EOTHER.
 * @param {unknown} error
 */
export function errorCode(error) {
  const code = typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined
  return typeof code === 'string' && ERROR_CODE.test(code) ? code : 'EOTHER'
}

/**
 * @param {unknown} error
 * @returns {ProbeOutcome}
 */
function failed(error) {
  const code = errorCode(error)
  return { reached: ANSWERED.has(code), error: code }
}

/** @typedef {(host: string, port: number) => Socket} Dial */
/** @type {Dial} */
const dialTcp = (host, port) => netConnect({ host, port, autoSelectFamily: false })

/**
 * Try a TCP connection: reached when it opens, or when a peer refuses or resets it.
 * @param {string} host
 * @param {number} port
 * @param {number} timeoutMs
 * @param {Dial} [dial]
 * @returns {Promise<ProbeOutcome>}
 */
export function connectProbe(host, port, timeoutMs, dial = dialTcp) {
  return new Promise((resolve) => {
    /** @type {Socket | undefined} */
    let socket
    /** @param {ProbeOutcome} outcome */
    const settle = (outcome) => {
      clearTimeout(timer)
      socket?.destroy()
      resolve(outcome)
    }
    const timer = setTimeout(() => settle({ reached: false, error: 'ETIMEDOUT' }), timeoutMs)
    try {
      socket = dial(host, port)
    } catch (e) {
      settle(failed(e))
      return
    }
    socket.once('connect', () => settle({ reached: true, error: null }))
    socket.once('error', (e) => settle(failed(e)))
  })
}

/** @typedef {(host: string) => Promise<readonly unknown[]>} Resolve */
/** @type {Resolve} */
const resolveName = (host) => dnsLookup(host, { all: true })

/**
 * Try a name lookup: reached when it gives any address.
 * @param {string} host
 * @param {number} timeoutMs
 * @param {Resolve} [resolveFn]
 * @returns {Promise<ProbeOutcome>}
 */
export function lookupProbe(host, timeoutMs, resolveFn = resolveName) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ reached: false, error: 'ETIMEDOUT' }), timeoutMs)
    /** @param {ProbeOutcome} outcome */
    const settle = (outcome) => {
      clearTimeout(timer)
      resolve(outcome)
    }
    let answer
    try {
      answer = resolveFn(host)
    } catch (e) {
      settle(failed(e))
      return
    }
    Promise.resolve(answer).then(
      (addresses) => settle(Array.isArray(addresses) && addresses.length > 0 ? { reached: true, error: null } : { reached: false, error: 'ENODATA' }),
      (e) => settle(failed(e)),
    )
  })
}

/**
 * Run every SELF_TEST probe at once, each bounded by timeoutMs (and again
 * here, so a probe that never settles is still reported).
 * @param {{ connect?: ConnectProbe, lookup?: LookupProbe, timeoutMs?: number }} [options]
 * @returns {Promise<readonly ProbeResult[]>}
 */
export async function selfTest(options = {}) {
  const connect = options.connect ?? connectProbe
  const lookup = options.lookup ?? lookupProbe
  const timeoutMs = options.timeoutMs ?? PROBE_TIMEOUT_MS
  return Promise.all(
    SELF_TEST.map(async (probe) => {
      const target = probe.probe === 'connect' ? `${probe.host}:${String(probe.port)}` : probe.host
      /** @type {ProbeOutcome} */
      let outcome
      try {
        const run = probe.probe === 'connect' ? connect(probe.host, probe.port, timeoutMs) : lookup(probe.host, timeoutMs)
        outcome = await bounded(run, timeoutMs)
      } catch (e) {
        outcome = failed(e)
      }
      const reached = outcome.reached === true
      const error = reached && outcome.error === null ? null : typeof outcome.error === 'string' && ERROR_CODE.test(outcome.error) ? outcome.error : 'EOTHER'
      return Object.freeze({ probe: probe.probe, target, reached, error })
    }),
  )
}

/**
 * A probe's answer, or ETIMEDOUT once its time (and a little more) is up.
 * @param {Promise<ProbeOutcome>} run
 * @param {number} timeoutMs
 * @returns {Promise<ProbeOutcome>}
 */
function bounded(run, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve({ reached: false, error: 'ETIMEDOUT' }), timeoutMs + 100)
    run.then(
      (outcome) => {
        clearTimeout(timer)
        resolve(outcome)
      },
      (e) => {
        clearTimeout(timer)
        reject(e)
      },
    )
  })
}

/**
 * The ready payload for a self-test's results: ASCII JSON, keys in a fixed order.
 * @param {readonly ProbeResult[]} results
 * @returns {Uint8Array}
 */
export function readyPayload(results) {
  const report = {
    mux: 1,
    probes: results.map(({ probe, target, reached, error }) => ({ probe, target, reached, error })),
    reached: results.filter((r) => r.reached).length,
  }
  const bytes = new TextEncoder().encode(JSON.stringify(report))
  if (bytes.length > READY_MAX_BYTES || bytes.some((b) => b > 0x7e)) throw new Error('mux: the self-test report does not fit a ready frame')
  return bytes
}

// ── the relay ───────────────────────────────────────────────────────────────

/** Most connections held back while maxFlows flows are open; past it a new one is destroyed. */
export const MAX_HELD = MAX_FLOWS_LIMIT
/** How long the mux waits for stdout to take its last frames before it exits anyway. */
export const FLUSH_TIMEOUT_MS = 5_000
/**
 * How long the command's pipes may stay open once it has exited (held by a
 * descendant that left its group) before the mux closes them and sends the
 * status, counted only while stdout takes frames: the clock stops while stdout
 * is full and runs on from where it stopped once it drains.
 */
export const EXIT_GRACE_MS = 2_000
/** The grace's bound in wall time from the exit: the pipes close then, full stdout or not. */
export const EXIT_GRACE_MAX_MS = 20_000

/** The mux's own exit codes: how its run ended, never the command's status (which is the exit frame's). */
export const MUX_EXIT = Object.freeze({
  /** The channel ended (stdin EOF), or the command exited and every flow retired. */
  ok: 0,
  /** The arguments were not `-- <command> [args...]`. */
  usage: 64,
  /** The mux would have sent a frame its own codec refuses: a bug here. */
  internal: 70,
  /** 127.0.0.1:3128 could not be listened on, so the command was never run. */
  listen: 71,
  /** The channel itself failed (a read or write error on stdin or stdout). */
  io: 74,
  /** The kernel sent a frame the mux refuses, or its stream ended inside one. */
  protocol: 76,
})

/** The address a listener is bound to, as the system reports it, and its close. @typedef {{ readonly host: string, readonly port: number, close(): void }} Listener */
/** @typedef {(host: string, port: number, onConnection: (socket: Duplex) => void) => Promise<Listener>} Listen */

/**
 * Listen on host:port for the worker's connections: half-open, so a worker
 * that finishes its request still reads the answer, and paused, so nothing is
 * read before its flow is open. The listener reports the address it is bound
 * to as the system gives it back, never the one it was asked for.
 * @type {Listen}
 */
export function listenTcp(host, port, onConnection) {
  return new Promise((resolve, reject) => {
    const server = createServer({ allowHalfOpen: true, pauseOnConnect: true }, onConnection)
    server.once('error', reject)
    server.listen({ host, port, exclusive: true }, () => {
      server.removeListener('error', reject)
      // Once listening, an accept that fails (no descriptor left) loses that
      // connection only.
      server.on('error', () => {})
      const address = server.address()
      if (typeof address !== 'object' || address === null) {
        server.close()
        reject(new Error('mux: the listener reports no TCP address'))
        return
      }
      resolve({ host: address.address, port: address.port, close: () => void server.close() })
    })
  })
}

/**
 * @typedef {object} CommandChild
 * @property {Readable} stdout
 * @property {Readable} stderr
 * @property {(event: 'error' | 'exit' | 'close', listener: (...args: any[]) => void) => unknown} once
 * @property {() => void} killTree SIGKILL to the command's whole process group
 */
/** @typedef {(command: string, args: readonly string[]) => CommandChild} Spawn */

/**
 * The options spawnCommand runs the command with, and nothing more (no env:
 * the command inherits the image's environment as it stands).
 * @typedef {{ readonly stdio: readonly ['ignore', 'pipe', 'pipe'], readonly detached: true, readonly shell: false }} CommandOptions
 */
/** @typedef {(command: string, args: string[], options: CommandOptions) => ChildProcess} SpawnProcess */

/**
 * node's spawn, handed spawnCommand's options as they are: nothing is spelt
 * again here, so what the injected spawn of the test is given is what node is.
 * @type {SpawnProcess}
 */
const spawnProcess = (command, args, options) => spawnChild(command, args, { ...options, stdio: [...options.stdio] })

/**
 * Run the command in its own process group (detached: so killTree's kill of
 * the group reaches every process it starts), with no stdin (the mux's own
 * stdin is the kernel's frames: a command that shared it, an npm or a git
 * that reads stdin, would eat them), with piped stdout and stderr, through no
 * shell, inheriting the image's environment as it stands (the mux reads none
 * of it). `spawn` is node's spawn but for a test.
 * @param {string} command
 * @param {readonly string[]} args
 * @param {SpawnProcess} [spawn]
 * @returns {CommandChild}
 */
export function spawnCommand(command, args, spawn = spawnProcess) {
  const child = spawn(command, [...args], { stdio: ['ignore', 'pipe', 'pipe'], detached: true, shell: false })
  const { stdout, stderr } = child
  if (stdout === null || stderr === null) throw new Error('mux: the command has no stdout or stderr pipe')
  return {
    stdout,
    stderr,
    once: (event, listener) => child.once(event, listener),
    killTree: () => {
      if (child.pid !== undefined) {
        try {
          process.kill(-child.pid, 'SIGKILL')
        } catch {
          // The group is gone already.
        }
      }
      child.kill('SIGKILL')
    },
  }
}

/**
 * @typedef {object} MuxOptions
 * @property {Readable} input the kernel's frames: docker -i stdin
 * @property {Writable} output the mux's frames: docker stdout
 * @property {Writable} [diagnostics] the mux's own complaints: docker stderr
 * @property {string} command
 * @property {readonly string[]} args
 * @property {ConnectProbe} [connect]
 * @property {LookupProbe} [lookup]
 * @property {number} [probeTimeoutMs]
 * @property {Listen} [listen]
 * @property {Spawn} [spawn]
 * @property {number} [flushTimeoutMs]
 * @property {number} [exitGraceMs]
 * @property {number} [exitGraceMaxMs]
 */

/**
 * @typedef {object} Flow
 * @property {Duplex} socket
 * @property {boolean} kernelEnded the kernel's end has arrived
 * @property {boolean} kernelClosed the kernel's close has arrived
 * @property {boolean} muxClosed the mux has sent its close
 */

/**
 * Run the mux over `input` and `output` until it is done: resolves with its
 * exit code (MUX_EXIT). Never rejects.
 * @param {MuxOptions} options
 * @returns {Promise<number>}
 */
export function runMux(options) {
  return new Mux(options).run()
}

class Mux {
  /** @type {Readable} */ #input
  /** @type {Writable} */ #output
  /** @type {Writable | undefined} */ #diagnostics
  /** @type {string} */ #command
  /** @type {readonly string[]} */ #args
  /** @type {ConnectProbe | undefined} */ #connect
  /** @type {LookupProbe | undefined} */ #lookup
  /** @type {number | undefined} */ #probeTimeoutMs
  /** @type {Listen} */ #listen
  /** @type {Spawn} */ #spawn
  /** @type {number} */ #flushTimeoutMs
  /** @type {number} */ #exitGraceMs
  /** @type {number} */ #exitGraceMaxMs

  #channel = new MuxChannel()
  /** @type {Map<number, Flow>} */
  #flows = new Map()
  /** Sockets whose flow has retired, drained until the worker closes them. @type {Set<Duplex>} */
  #lingering = new Set()
  /** Connections held back while maxFlows flows are open, in arrival order. @type {Duplex[]} */
  #held = []
  /** Sockets that could not take the kernel's data: stdin is not read while any is here. @type {Set<Duplex>} */
  #blockers = new Set()
  /** @type {Listener | undefined} */
  #listener = undefined
  /** @type {CommandChild | undefined} */
  #child = undefined
  /** The command's status once it has exited, until its exit frame is sent. @type {{ readonly status: number, readonly spawnError: unknown } | undefined} */
  #exitedWith = undefined
  /** The grace's clock, running while stdout takes frames. @type {ReturnType<typeof setTimeout> | undefined} */
  #graceTimer = undefined
  /** What is left of the grace's clock, as of #graceSince. */
  #graceLeft = 0
  /** When the grace's clock last started running (performance.now()). */
  #graceSince = 0
  /** The grace's bound in wall time. @type {ReturnType<typeof setTimeout> | undefined} */
  #graceLimit = undefined
  #outputBlocked = false
  #started = false
  /** The exit frame has been sent. */
  #exited = false
  #stopping = false
  /** @type {(code: number) => void} */
  #resolve = () => {}
  /** @type {Promise<number>} */
  #done

  /** @param {MuxOptions} options */
  constructor(options) {
    this.#input = options.input
    this.#output = options.output
    this.#diagnostics = options.diagnostics
    this.#command = options.command
    this.#args = Object.freeze([...options.args])
    this.#connect = options.connect
    this.#lookup = options.lookup
    this.#probeTimeoutMs = options.probeTimeoutMs
    this.#listen = options.listen ?? listenTcp
    this.#spawn = options.spawn ?? spawnCommand
    this.#flushTimeoutMs = options.flushTimeoutMs ?? FLUSH_TIMEOUT_MS
    this.#exitGraceMs = options.exitGraceMs ?? EXIT_GRACE_MS
    this.#exitGraceMaxMs = options.exitGraceMaxMs ?? EXIT_GRACE_MAX_MS
    this.#done = new Promise((resolve) => {
      this.#resolve = resolve
    })
  }

  /** @returns {Promise<number>} */
  async run() {
    this.#output.on('drain', () => this.#outputDrained())
    this.#output.on('error', () => this.#stop(MUX_EXIT.io, 'the channel to the kernel failed'))
    /** @type {Uint8Array} */
    let report
    try {
      report = readyPayload(
        await selfTest({
          ...(this.#connect === undefined ? {} : { connect: this.#connect }),
          ...(this.#lookup === undefined ? {} : { lookup: this.#lookup }),
          ...(this.#probeTimeoutMs === undefined ? {} : { timeoutMs: this.#probeTimeoutMs }),
        }),
      )
    } catch (e) {
      this.#stop(MUX_EXIT.internal, `the self-test failed: ${errorCode(e)}`)
      return this.#done
    }
    if (this.#stopping) return this.#done
    this.#write({ type: 'ready', flow: 0, payload: report })
    // Read only now: the kernel sends nothing before it has read ready.
    this.#input.on('data', (chunk) => this.#fromKernel(chunk))
    this.#input.on('end', () => this.#kernelEnded())
    // A stdin closed without an end (destroyed) has ended all the same.
    this.#input.on('close', () => this.#kernelEnded())
    this.#input.on('error', () => this.#stop(MUX_EXIT.io, 'the channel from the kernel failed'))
    return this.#done
  }

  // ── the kernel's side ──

  /** @param {unknown} chunk */
  #fromKernel(chunk) {
    if (this.#stopping) return
    if (!(chunk instanceof Uint8Array)) {
      this.#stop(MUX_EXIT.protocol, 'the channel from the kernel carried text, not bytes')
      return
    }
    const { frames, error } = this.#channel.receive(chunk)
    for (const frame of frames) {
      this.#onFrame(frame)
      if (this.#stopping) return
    }
    if (error !== undefined) this.#stop(MUX_EXIT.protocol, `the kernel sent a frame the mux refuses: ${error.message}`)
  }

  #kernelEnded() {
    if (this.#stopping) return
    const error = this.#channel.finish()
    if (error !== undefined) this.#stop(MUX_EXIT.protocol, `the channel from the kernel ended inside a frame: ${error.message}`)
    else this.#stop(MUX_EXIT.ok)
  }

  /** @param {ReceivedFrame} frame */
  #onFrame(frame) {
    switch (frame.type) {
      case 'go':
        this.#start()
        return
      case 'data': {
        const flow = this.#flows.get(frame.flow)
        if (frame.stale || flow === undefined) return
        this.#toWorker(flow, frame.payload)
        return
      }
      case 'end': {
        const flow = this.#flows.get(frame.flow)
        if (frame.stale || flow === undefined) return
        flow.kernelEnded = true
        if (flow.socket.writable) flow.socket.end()
        return
      }
      case 'close':
        this.#kernelClosed(frame.flow)
        return
      default:
        // The codec refuses every other type from the kernel (direction).
        return
    }
  }

  /**
   * @param {Flow} flow
   * @param {Uint8Array} payload
   */
  #toWorker(flow, payload) {
    const { socket } = flow
    if (socket.destroyed || !socket.writable) return
    if (socket.write(payload)) return
    if (!this.#blockers.has(socket)) {
      this.#blockers.add(socket)
      socket.once('drain', () => this.#unblock(socket))
    }
    this.#input.pause()
  }

  /** @param {Duplex} socket */
  #unblock(socket) {
    if (!this.#blockers.delete(socket)) return
    if (this.#blockers.size === 0 && !this.#stopping) this.#input.resume()
  }

  /** @param {number} id */
  #kernelClosed(id) {
    const flow = this.#flows.get(id)
    if (flow === undefined) return
    flow.kernelClosed = true
    if (!flow.muxClosed) {
      if (!flow.kernelEnded) {
        // A cut: the worker must read a reset, never a short answer as whole.
        reset(flow.socket)
      } else {
        // Clean: the answer is flushed and the socket drained until the
        // worker closes it, so no unread byte turns its close into a reset.
        this.#lingering.add(flow.socket)
        flow.socket.resume()
      }
      flow.muxClosed = true
      if (!this.#write({ type: 'close', flow: id, payload: EMPTY })) return
    }
    this.#retire(id, flow)
  }

  // ── go: listen, then run the command ──

  #start() {
    if (this.#started) return
    this.#started = true
    this.#listen(MUX_HOST, MUX_PORT, (socket) => this.#accepted(socket)).then(
      (listener) => {
        if (this.#stopping || this.#exited) {
          listener.close()
          return
        }
        this.#listener = listener
        this.#run()
      },
      (e) => this.#stop(MUX_EXIT.listen, `cannot listen on ${MUX_HOST}:${String(MUX_PORT)}: ${errorCode(e)}`),
    )
  }

  #run() {
    /** @type {CommandChild} */
    let child
    try {
      child = this.#spawn(this.#command, this.#args)
    } catch (e) {
      this.#commandEnded(spawnStatus(e), e)
      return
    }
    this.#child = child
    /** @type {unknown} */
    let spawnError
    child.stdout.on('data', (chunk) => this.#commandOutput('stdout', chunk))
    child.stderr.on('data', (chunk) => this.#commandOutput('stderr', chunk))
    if (this.#outputBlocked) {
      child.stdout.pause()
      child.stderr.pause()
    }
    child.once('error', (e) => {
      spawnError = e
    })
    // What the command left in its group is killed when it exits, so nothing
    // nobody waits for holds a flow or its pipes open; the pipes then close,
    // or, held by a descendant that left the group, are closed after the grace.
    child.once('exit', (code, signal) => {
      child.killTree()
      this.#exitedWith = { status: statusOf(code, signal, spawnError), spawnError }
      this.#startGrace()
    })
    child.once('close', (code, signal) => this.#commandEnded(statusOf(code, signal, spawnError), spawnError))
  }

  /**
   * The command has exited and its pipes are still open: they have
   * EXIT_GRACE_MS of time in which stdout takes frames, and EXIT_GRACE_MAX_MS
   * of wall time, whichever ends first.
   */
  #startGrace() {
    if (this.#exitedWith === undefined || this.#stopping || this.#exited || this.#graceLimit !== undefined) return
    this.#graceLeft = this.#exitGraceMs
    this.#graceLimit = setTimeout(() => this.#graceOver(), this.#exitGraceMaxMs)
    if (!this.#outputBlocked) this.#runGraceClock()
  }

  /** stdout takes frames: the grace's clock runs on from what it has left. */
  #runGraceClock() {
    if (this.#graceLimit === undefined || this.#graceTimer !== undefined) return
    this.#graceSince = performance.now()
    this.#graceTimer = setTimeout(() => this.#graceOver(), this.#graceLeft)
  }

  /** stdout is full, so the pipes are left unread by the mux, not held by a descendant: the clock stops, keeping what it has counted. */
  #stopGraceClock() {
    if (this.#graceTimer === undefined) return
    clearTimeout(this.#graceTimer)
    this.#graceTimer = undefined
    this.#graceLeft = Math.max(0, this.#graceLeft - (performance.now() - this.#graceSince))
  }

  #clearGrace() {
    clearTimeout(this.#graceTimer)
    clearTimeout(this.#graceLimit)
    this.#graceTimer = undefined
    this.#graceLimit = undefined
  }

  #graceOver() {
    const ended = this.#exitedWith
    this.#clearGrace()
    if (ended === undefined) return
    // Whatever still holds them writes to nothing from now on.
    this.#child?.stdout.destroy()
    this.#child?.stderr.destroy()
    this.#commandEnded(ended.status, ended.spawnError)
  }

  /**
   * @param {'stdout' | 'stderr'} type
   * @param {unknown} chunk
   */
  #commandOutput(type, chunk) {
    if (this.#stopping || this.#exited) return
    const bytes = chunk instanceof Uint8Array ? chunk : new TextEncoder().encode(String(chunk))
    this.#sendPieces(type, 0, bytes)
  }

  /**
   * @param {number} status
   * @param {unknown} spawnError
   */
  #commandEnded(status, spawnError) {
    this.#clearGrace()
    this.#exitedWith = undefined
    if (this.#stopping || this.#exited) return
    if (spawnError !== undefined && (status === 126 || status === 127)) {
      this.#sendPieces('stderr', 0, new TextEncoder().encode(`aos-mux: cannot run ${JSON.stringify(this.#command)}: ${errorCode(spawnError)}\n`))
    }
    if (!this.#write({ type: 'exit', flow: 0, payload: exitPayload(status) })) return
    this.#exited = true
    // After exit no flow opens.
    this.#listener?.close()
    for (const socket of this.#held.splice(0)) socket.destroy()
    this.#maybeDone()
  }

  // ── the worker's side ──

  /** @param {Duplex} socket */
  #accepted(socket) {
    // An error is followed by close, which is what the mux acts on.
    socket.on('error', () => {})
    if (this.#stopping || this.#exited) {
      socket.destroy()
      return
    }
    const limits = this.#channel.limits
    if (limits === undefined) {
      socket.destroy()
      return
    }
    if (this.#held.length > 0 || this.#channel.openFlows >= limits.maxFlows) {
      if (this.#held.length >= MAX_HELD) {
        socket.destroy()
        return
      }
      socket.pause()
      this.#held.push(socket)
      socket.once('close', () => {
        const at = this.#held.indexOf(socket)
        if (at !== -1) this.#held.splice(at, 1)
      })
      return
    }
    this.#open(socket)
  }

  /** @param {Duplex} socket */
  #open(socket) {
    const id = this.#channel.flowsOpened + 1
    if (id > MAX_FLOW_ID || socket.destroyed) {
      socket.destroy()
      return
    }
    if (!this.#write({ type: 'open', flow: id, payload: EMPTY })) {
      socket.destroy()
      return
    }
    /** @type {Flow} */
    const flow = { socket, kernelEnded: false, kernelClosed: false, muxClosed: false }
    this.#flows.set(id, flow)
    socket.on('data', (chunk) => {
      if (flow.muxClosed || flow.kernelClosed) return
      this.#sendPieces('data', id, chunk instanceof Uint8Array ? chunk : new TextEncoder().encode(String(chunk)))
    })
    socket.on('end', () => {
      if (flow.muxClosed || flow.kernelClosed) return
      this.#write({ type: 'end', flow: id, payload: EMPTY })
    })
    socket.on('close', () => this.#workerClosed(id, flow))
    if (this.#outputBlocked) socket.pause()
    else socket.resume()
  }

  /**
   * @param {number} id
   * @param {Flow} flow
   */
  #workerClosed(id, flow) {
    this.#lingering.delete(flow.socket)
    this.#unblock(flow.socket)
    if (flow.muxClosed || this.#stopping) return
    flow.muxClosed = true
    // The kernel's close has not come (it closes the mux's side too, in
    // #kernelClosed), and when it comes it retires the flow there.
    this.#write({ type: 'close', flow: id, payload: EMPTY })
  }

  /**
   * Both closes have crossed: the flow is gone, and a held connection may open.
   * @param {number} id
   * @param {Flow} flow
   */
  #retire(id, flow) {
    if (this.#flows.get(id) !== flow) return
    this.#flows.delete(id)
    // No more of the kernel's data can come for it, so its socket no longer holds stdin.
    this.#unblock(flow.socket)
    const limits = this.#channel.limits
    while (!this.#stopping && !this.#exited && limits !== undefined && this.#held.length > 0 && this.#channel.openFlows < limits.maxFlows) {
      const next = this.#held.shift()
      if (next !== undefined) this.#open(next)
    }
    this.#maybeDone()
  }

  #maybeDone() {
    if (this.#exited && this.#flows.size === 0) this.#stop(MUX_EXIT.ok)
  }

  // ── stdout ──

  /**
   * Send bytes as frames of at most frameMaxBytes. A flow the kernel has
   * closed takes nothing more (peer-closed): what is left is dropped.
   * @param {'data' | 'stdout' | 'stderr'} type
   * @param {number} flow
   * @param {Uint8Array} bytes
   */
  #sendPieces(type, flow, bytes) {
    const limits = this.#channel.limits
    if (limits === undefined) return
    for (let at = 0; at < bytes.length; at += limits.frameMaxBytes) {
      const frame = { type, flow, payload: bytes.subarray(at, at + limits.frameMaxBytes) }
      if (this.#channel.sendRefusal(frame)?.refusal === 'peer-closed') return
      if (!this.#write(frame)) return
    }
  }

  /**
   * Send one frame. False when nothing was sent: the mux is stopping, or its
   * codec refused the frame, which is a bug here and stops the mux.
   * @param {Frame} frame
   * @returns {boolean}
   */
  #write(frame) {
    if (this.#stopping) return false
    const refused = this.#channel.sendRefusal(frame)
    if (refused !== undefined) {
      this.#stop(MUX_EXIT.internal, `the mux would send a frame its codec refuses: ${refused.message}`)
      return false
    }
    if (this.#output.write(this.#channel.send(frame))) return true
    if (!this.#outputBlocked) {
      this.#outputBlocked = true
      this.#stopGraceClock()
    }
    // On every frame stdout refuses, not only the first: node resumes the
    // command's pipes once it exits (flushStdio, on the next tick), and a
    // pipe resumed under a full stdout would be framed into it without bound.
    // pause() is idempotent, so a resume costs at most one chunk.
    for (const flow of this.#flows.values()) if (!flow.muxClosed) flow.socket.pause()
    this.#child?.stdout.pause()
    this.#child?.stderr.pause()
    return true
  }

  #outputDrained() {
    if (!this.#outputBlocked || this.#stopping) return
    this.#outputBlocked = false
    for (const flow of this.#flows.values()) if (!flow.muxClosed) flow.socket.resume()
    this.#child?.stdout.resume()
    this.#child?.stderr.resume()
    // The command's pipes were left unread while stdout was full: the grace's clock runs on.
    this.#runGraceClock()
  }

  // ── the end ──

  /**
   * @param {number} code
   * @param {string} [why]
   */
  #stop(code, why) {
    if (this.#stopping) return
    this.#stopping = true
    if (why !== undefined) this.#diagnostics?.write(`aos-mux: ${why}\n`)
    this.#clearGrace()
    this.#child?.killTree()
    this.#listener?.close()
    for (const flow of this.#flows.values()) flow.socket.destroy()
    for (const socket of [...this.#lingering, ...this.#held]) socket.destroy()
    this.#flows.clear()
    this.#lingering.clear()
    this.#held.length = 0
    this.#blockers.clear()
    this.#input.pause()
    // What was written reaches the kernel before the mux exits, if it can
    // within FLUSH_TIMEOUT_MS.
    const timer = setTimeout(() => this.#resolve(code), this.#flushTimeoutMs)
    const flushed = () => {
      clearTimeout(timer)
      this.#resolve(code)
    }
    if (this.#output.destroyed || this.#output.writableEnded) {
      flushed()
      return
    }
    try {
      this.#output.write(EMPTY, flushed)
    } catch {
      flushed()
    }
  }
}

/** @param {Duplex} socket */
function reset(socket) {
  if ('resetAndDestroy' in socket && typeof socket.resetAndDestroy === 'function') {
    try {
      socket.resetAndDestroy()
      return
    } catch {
      // Not a TCP socket after all: destroyed below.
    }
  }
  socket.destroy()
}

/**
 * The status a command that could not be started is reported with: 127 when
 * it was not found, 126 when it was found and could not be run.
 * @param {unknown} error
 */
function spawnStatus(error) {
  return errorCode(error) === 'ENOENT' ? 127 : 126
}

/**
 * The exit frame's status: the exit code, 128 + n for a death by signal n, or
 * the spawn failure's status when the command never ran.
 * @param {unknown} code
 * @param {unknown} signal
 * @param {unknown} spawnError
 */
export function statusOf(code, signal, spawnError) {
  if (typeof signal === 'string') {
    const n = /** @type {Record<string, number | undefined>} */ (osConstants.signals)[signal]
    return Math.min(255, 128 + (typeof n === 'number' ? n : 0))
  }
  if (typeof code === 'number' && Number.isInteger(code) && code >= 0 && code <= 255) return code
  return spawnStatus(spawnError)
}

// ── the entry point ─────────────────────────────────────────────────────────

export const USAGE = 'usage: node mux.mjs -- <command> [args...]\n'

/**
 * The command the mux runs: `-- <command> [args...]`, and nothing else.
 * @param {readonly string[]} argv
 * @returns {{ readonly command: string, readonly args: readonly string[] } | undefined}
 */
export function parseArgs(argv) {
  const [separator, command, ...args] = argv
  if (separator !== '--' || command === undefined || command === '') return undefined
  return Object.freeze({ command, args: Object.freeze(args) })
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2))
  if (parsed === undefined) {
    process.stderr.write(USAGE)
    process.exit(MUX_EXIT.usage)
  }
  const code = await runMux({ input: process.stdin, output: process.stdout, diagnostics: process.stderr, ...parsed })
  process.exit(code)
}

// Run only as the program node was started with (node >= 22.18 and 24.2 set
// import.meta.main), never when a test imports the module.
if (import.meta.main) await main()
