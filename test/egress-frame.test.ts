// Egress plan E7 — the channel's frame codec (src/egress/frame.ts).
//
// Everything a sandboxed container sends the kernel's egress engine arrives
// as these frames over its docker -i stdout, and the container is hostile:
// the in-image mux shares a uid with the agent, which can write any bytes it
// likes. The codec fails OPEN when it is wrong in any of these ways, so each
// is held here at its edge and one past it:
//
//   A length judged after the payload is read is a 4 GiB buffer in the
//   process that holds the provider keys. An unknown type skipped or a bad
//   frame resynchronised over is a stream the kernel reads as something the
//   container never framed. An open past maxFlows, or a flow retired on one
//   close, is a cap that does not hold; a flow id reused is a late frame of
//   an old flow read as the new one's. A frame decoded differently in other
//   pieces is a decoder whose answer depends on how the kernel's reads fall.
//
// The shared vectors (test/fixtures/egress-frame-vectors.json) are written
// out byte by byte, independently of frame.ts, and the in-image mux (E9) is
// held to the same file, so the two ends agree on every byte and every
// refusal without the image importing the kernel.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'
import { z } from 'zod'

import { KernelConfig } from '../src/config.js'
import {
  CHANNEL_ROLES,
  encodeFrame,
  exitPayload,
  FRAME_HEADER_BYTES,
  FRAME_MAX_BYTES_LIMIT,
  FRAME_REFUSALS,
  FRAME_RULES,
  FRAME_TYPE_CODES,
  FRAME_TYPES,
  FrameChannel,
  FrameError,
  FrameLimits,
  goPayload,
  MAX_FLOW_ID,
  MAX_FLOWS_LIMIT,
  READY_MAX_BYTES,
  readGoPayload,
  type ChannelRole,
  type Frame,
  type FrameRefusal,
  type FrameType,
  type ReceivedFrame,
} from '../src/egress/frame.js'
import { redactString } from '../src/events/redact.js'
import { EGRESS_DETAIL_BYTES, PROXY_LIMITS, ProxyGrantRevokedPayload } from '../src/events/types.js'

const VECTORS_PATH = new URL('./fixtures/egress-frame-vectors.json', import.meta.url)
const MINIMAL_CONFIG = new URL('./fixtures/config/minimal.yaml', import.meta.url)
const SHIPPED_CONFIG = new URL('../config/kernel.yaml', import.meta.url)

// ── bytes, written independently of frame.ts ─────────────────────────────────

/** Hex as the vectors spell it: lower-case, spaces for reading. */
function bytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '')
  assert.match(clean, /^(?:[0-9a-f]{2})*$/, `not hex: ${hex}`)
  return Uint8Array.from(Buffer.from(clean, 'hex'))
}

const hexOf = (data: Uint8Array): string => Buffer.from(data).toString('hex')

/** A header, spelled by hand: length, type byte, flow id, all big-endian. */
function header(length: number, code: number, flow: number): Uint8Array {
  const out = Buffer.alloc(FRAME_HEADER_BYTES)
  out.writeUInt32BE(length, 0)
  out.writeUInt8(code, 4)
  out.writeUInt32BE(flow, 5)
  return Uint8Array.from(out)
}

function join(...parts: readonly Uint8Array[]): Uint8Array {
  return Uint8Array.from(Buffer.concat(parts))
}

const text = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'utf8'))
const frame = (type: FrameType, flow: number, payload: Uint8Array = new Uint8Array(0)): Frame => ({ type, flow, payload })

/** A deterministic PRNG (mulberry32), so a failing split is the same split on the next run. */
function prng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296
  }
}

function randomBytes(rng: () => number, length: number): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) out[i] = Math.floor(rng() * 256)
  return out
}

type Split = 'as-given' | 'whole' | 'bytes' | 'random'
const SPLITS: readonly Split[] = ['as-given', 'whole', 'bytes', 'random']

/** The same bytes in other pieces: whole, one byte at a time, or random cuts with empty pieces among them. */
function split(given: readonly Uint8Array[], how: Split, rng: () => number): Uint8Array[] {
  const all = join(...given)
  switch (how) {
    case 'as-given':
      return [...given]
    case 'whole':
      return [all]
    case 'bytes':
      return Array.from(all, (b) => Uint8Array.of(b))
    case 'random': {
      const out: Uint8Array[] = []
      let at = 0
      while (at < all.length) {
        if (rng() < 0.1) out.push(new Uint8Array(0))
        const take = 1 + Math.floor(rng() * 13)
        out.push(all.slice(at, at + take))
        at += take
      }
      return out
    }
  }
}

interface Fed {
  readonly frames: ReceivedFrame[]
  readonly error: FrameError | undefined
}

/**
 * Feed pieces in order; once a refusal comes, every later piece must bring it
 * again and nothing else. Every result, its frames list and each frame are
 * frozen: the session hands them on, and nothing it hands them to may change
 * what was decoded.
 */
function feed(channel: FrameChannel, pieces: readonly Uint8Array[]): Fed {
  const frames: ReceivedFrame[] = []
  let error: FrameError | undefined
  for (const piece of pieces) {
    const result = channel.receive(piece)
    assert.ok(Object.isFrozen(result), 'a receive result is frozen')
    assert.ok(Object.isFrozen(result.frames), "a receive result's frames are frozen")
    for (const f of result.frames) assert.ok(Object.isFrozen(f), 'a received frame is frozen')
    if (error !== undefined) {
      assert.deepEqual(result.frames, [], 'nothing is decoded after a refusal')
      assert.equal(result.error, error, 'a refusal is final: the same one, every time')
      continue
    }
    frames.push(...result.frames)
    error = result.error
  }
  return { frames, error }
}

interface Shown {
  readonly type: FrameType
  readonly flow: number
  readonly payload: string
  readonly stale: boolean
}

const shown = (f: ReceivedFrame): Shown => ({ type: f.type, flow: f.flow, payload: hexOf(f.payload), stale: f.stale })

/** What the kernel end is held to as shipped: kernel.yaml's egress.limits. */
function shippedLimits(): FrameLimits {
  const parsed = KernelConfig.parse(parseYaml(readFileSync(SHIPPED_CONFIG, 'utf8')))
  return FrameLimits.parse(parsed.egress.limits)
}

const kernelEnd = (limits: FrameLimits): FrameChannel => new FrameChannel({ role: 'kernel', limits })

/** A kernel end past the handshake: ready read, go sent. */
function handshaken(limits: FrameLimits): FrameChannel {
  const channel = kernelEnd(limits)
  assert.equal(channel.receive(encodeFrame(frame('ready', 0, text('{}')))).error, undefined)
  channel.send(frame('go', 0, goPayload(limits)))
  return channel
}

/** A mux end past the handshake: ready sent, go read. */
function muxHandshaken(limits: FrameLimits): FrameChannel {
  const channel = new FrameChannel({ role: 'mux' })
  channel.send(frame('ready', 0, text('{}')))
  assert.equal(channel.receive(encodeFrame(frame('go', 0, goPayload(limits)))).error, undefined)
  return channel
}

/** The types "an" goes before, written out here rather than derived as frame.ts derives them. */
const AN_TYPES: ReadonlySet<FrameType> = new Set(['open', 'end', 'exit'])

/** A refusal's message is the revocation row's detail for good, so it is English: "an open frame", "a data frame", "1 byte". */
function assertWording(error: FrameError): void {
  for (const type of FRAME_TYPES) {
    const wrong = AN_TYPES.has(type) ? `a ${type} frame` : `an ${type} frame`
    assert.equal(new RegExp(`\\b${wrong}\\b`).test(error.message), false, `"${wrong}" in: ${error.message}`)
  }
  assert.doesNotMatch(error.message, /\b1 bytes\b/, error.message)
}

function refusedWith(channel: FrameChannel, data: Uint8Array, refusal: FrameRefusal, label: string): FrameError {
  const { error } = channel.receive(data)
  assert.ok(error instanceof FrameError, `${label}: refused`)
  assert.equal(error.refusal, refusal, `${label}: ${error.message}`)
  assertWording(error)
  return error
}

// ── the acceptance tests ──────────────────────────────────────────────────────

test('the decoder refuses an oversize frame, an unknown type, flow id 0, a truncated header and the 17th open flow', () => {
  const limits = shippedLimits()
  // As shipped: frames of at most 64 KiB, and at most 16 open flows, so the
  // 17th is the one refused.
  assert.deepEqual(limits, { frameMaxBytes: 65_536, maxFlows: 16 })

  // Oversize: refused at the header's ninth byte, before a byte of payload
  // arrives, so a header's claim is never a buffer. One byte under the cap
  // and the cap itself pass.
  for (const claim of [limits.frameMaxBytes + 1, 0x7fff_ffff, 0xffff_ffff]) {
    const channel = handshaken(limits)
    channel.receive(encodeFrame(frame('open', 1)))
    const head = header(claim, FRAME_TYPE_CODES.data, 1)
    assert.equal(channel.receive(head.subarray(0, FRAME_HEADER_BYTES - 1)).error, undefined, 'eight bytes are not yet a header')
    const error = refusedWith(channel, head.subarray(FRAME_HEADER_BYTES - 1), 'oversize', `a data frame claiming ${String(claim)}`)
    assert.equal(error.reason, 'limit')
    assert.equal(error.limit, 'frameMaxBytes')
  }
  for (const type of ['stdout', 'stderr'] as const) {
    refusedWith(handshaken(limits), header(limits.frameMaxBytes + 1, FRAME_TYPE_CODES[type], 0), 'oversize', type)
  }
  {
    const channel = handshaken(limits)
    const fits = randomBytes(prng(7), limits.frameMaxBytes)
    const { frames, error } = channel.receive(join(encodeFrame(frame('open', 1)), encodeFrame(frame('data', 1, fits))))
    assert.equal(error, undefined)
    assert.deepEqual(frames.map((f) => [f.type, f.payload.length]), [['open', 0], ['data', limits.frameMaxBytes]])
  }

  // Unknown types: every byte that names none, 0x00 among them, so an
  // all-zero header is refused rather than read as an empty frame.
  const known = new Set<number>(Object.values(FRAME_TYPE_CODES))
  let unknown = 0
  for (let code = 0; code <= 0xff; code++) {
    if (known.has(code)) continue
    unknown++
    const error = refusedWith(handshaken(limits), header(0, code, 1), 'unknown-type', `type 0x${code.toString(16)}`)
    assert.equal(error.reason, 'violation')
    assert.equal(error.limit, undefined)
  }
  assert.equal(unknown, 256 - FRAME_TYPES.length)

  // Flow id 0 is the channel's: no flow frame names it, in either
  // direction, and no channel frame names anything else.
  for (const type of ['open', 'data', 'end', 'close'] as const) {
    const channel = handshaken(limits)
    if (type !== 'open') channel.receive(encodeFrame(frame('open', 1)))
    const payload = type === 'data' ? text('x') : new Uint8Array(0)
    refusedWith(channel, encodeFrame(frame(type, 0, payload)), 'flow-zero', `${type} on flow 0, to the kernel`)
  }
  for (const type of ['data', 'end', 'close'] as const) {
    const channel = muxHandshaken(limits)
    channel.send(frame('open', 1))
    const payload = type === 'data' ? text('x') : new Uint8Array(0)
    refusedWith(channel, encodeFrame(frame(type, 0, payload)), 'flow-zero', `${type} on flow 0, to the mux`)
    assert.throws(() => muxHandshaken(limits).send(frame(type, 0, payload)), (e: unknown) => e instanceof FrameError && e.refusal === 'flow-zero')
  }
  // The mux's own open names the next flow, never the channel: flow-zero, not
  // flow-order (which would say only that 0 is not the next id).
  assert.throws(() => muxHandshaken(limits).send(frame('open', 0)), (e: unknown) => e instanceof FrameError && e.refusal === 'flow-zero')
  // Every channel type, at the end that receives it, on a flow: ready and go
  // as much as the output and the exit, and go as the kernel sends it too.
  for (const type of ['stdout', 'stderr', 'exit'] as const) {
    refusedWith(handshaken(limits), encodeFrame(frame(type, 1, text('x'))), 'channel-flow', `${type} on flow 1`)
  }
  for (const flow of [1, 7]) {
    refusedWith(kernelEnd(limits), encodeFrame(frame('ready', flow)), 'channel-flow', `ready on flow ${String(flow)}, to the kernel`)
  }
  {
    const mux = new FrameChannel({ role: 'mux' })
    mux.send(frame('ready', 0))
    refusedWith(mux, encodeFrame(frame('go', 1, goPayload(limits))), 'channel-flow', 'go on flow 1, to the mux')
    assert.equal(mux.limits, undefined, 'a refused go teaches nothing')
    const kernel = kernelEnd(limits)
    assert.equal(kernel.receive(encodeFrame(frame('ready', 0))).error, undefined)
    assert.throws(() => kernel.send(frame('go', 1, goPayload(limits))), (e: unknown) => e instanceof FrameError && e.refusal === 'channel-flow')
  }

  // A truncated header: the stream ends one to eight bytes into one. And a
  // truncated payload, for the same reason: what arrived is not a frame.
  const whole = encodeFrame(frame('stdout', 0, text('abc')))
  for (let cut = 1; cut < FRAME_HEADER_BYTES; cut++) {
    const channel = handshaken(limits)
    assert.deepEqual(feed(channel, [whole.subarray(0, cut)]), { frames: [], error: undefined })
    const error = channel.finish()
    assert.equal(error?.refusal, 'truncated-header', `cut at ${String(cut)}`)
    assert.equal(channel.finish(), error, 'finish() is idempotent')
  }
  for (let cut = FRAME_HEADER_BYTES; cut < whole.length; cut++) {
    const channel = handshaken(limits)
    channel.receive(whole.subarray(0, cut))
    assert.equal(channel.finish()?.refusal, 'truncated-payload', `cut at ${String(cut)}`)
  }
  {
    const channel = handshaken(limits)
    channel.receive(whole)
    assert.equal(channel.finish(), undefined, 'a stream that ends between frames is whole')
  }

  // The 17th open flow: sixteen open and are handed out, the seventeenth is
  // refused, a limit, after the sixteen decoded in the same piece.
  const channel = handshaken(limits)
  const opens = Array.from({ length: limits.maxFlows + 1 }, (_, i) => encodeFrame(frame('open', i + 1)))
  const { frames, error } = feed(channel, [join(...opens)])
  assert.deepEqual(frames.map((f) => f.flow), Array.from({ length: 16 }, (_, i) => i + 1))
  assert.equal(channel.openFlows, 16)
  assert.equal(error?.refusal, 'max-flows')
  assert.equal(error?.reason, 'limit')
  assert.equal(error?.limit, 'maxFlows')
  assert.equal(channel.failure, error)
})

test('it round-trips input fed one byte at a time', () => {
  // A whole conversation between a mux end and a kernel end: the handshake,
  // more flows than maxFlows over the channel's life (as earlier ones
  // retire), data of 1 byte, of a header's length, of frameMaxBytes and in
  // between, payloads that look like headers, both orders of close, output
  // and an exit. Each frame is delivered to the other end as it is sent, in
  // pieces cut each way; each end must decode exactly what the other sent.
  const limits = shippedLimits()
  const rng = prng(0xe7)
  const lookalike = join(header(0, FRAME_TYPE_CODES.open, 9), header(0xffff_ffff, 0x7f, 0))
  const script: (readonly [ChannelRole, Frame])[] = [
    ['mux', frame('ready', 0, text('{"probes":[],"lookup":false}'))],
    ['kernel', frame('go', 0, goPayload(limits))],
  ]
  for (let flow = 1; flow <= 16; flow++) script.push(['mux', frame('open', flow)])
  const sizes = [1, FRAME_HEADER_BYTES, 2, limits.frameMaxBytes, 700, limits.frameMaxBytes - 1]
  for (let flow = 1; flow <= 8; flow++) {
    const size = sizes[(flow - 1) % sizes.length] ?? 1
    script.push(['mux', frame('data', flow, randomBytes(rng, size))])
    script.push(['kernel', frame('data', flow, flow === 3 ? lookalike : randomBytes(rng, Math.max(1, size >> 1)))])
    script.push(['mux', frame('end', flow)])
    script.push(['kernel', frame('data', flow, randomBytes(rng, 3))])
    script.push(['kernel', frame('end', flow)])
    // Either side may close first.
    if (flow % 2 === 0) script.push(['kernel', frame('close', flow)], ['mux', frame('close', flow)])
    else script.push(['mux', frame('close', flow)], ['kernel', frame('close', flow)])
  }
  // Eight retired, so eight more may open: flows 17 to 24, with 16 open.
  for (let flow = 17; flow <= 24; flow++) script.push(['mux', frame('open', flow)])
  // A close with no end before it: an abort, from each side.
  script.push(['mux', frame('data', 9, text('partial'))], ['mux', frame('close', 9)], ['kernel', frame('close', 9)])
  script.push(['kernel', frame('data', 10, text('cut'))], ['kernel', frame('close', 10)], ['mux', frame('close', 10)])
  script.push(['mux', frame('stdout', 0, randomBytes(rng, limits.frameMaxBytes))])
  script.push(['mux', frame('stderr', 0, text('warning: nothing\n'))])
  script.push(['mux', frame('exit', 0, exitPayload(0))])
  // After exit, open flows may still finish.
  script.push(['kernel', frame('data', 11, text('late'))], ['mux', frame('data', 11, text('ack'))])

  for (const how of SPLITS) {
    const ends: Record<ChannelRole, FrameChannel> = { kernel: kernelEnd(limits), mux: new FrameChannel({ role: 'mux' }) }
    const got: Record<ChannelRole, Shown[]> = { kernel: [], mux: [] }
    const sent: Record<ChannelRole, Shown[]> = { kernel: [], mux: [] }
    const cut = prng(0x5eed)
    for (const [from, f] of script) {
      const to: ChannelRole = from === 'kernel' ? 'mux' : 'kernel'
      const wire = ends[from].send(f)
      sent[from].push({ type: f.type, flow: f.flow, payload: hexOf(f.payload), stale: false })
      const { frames, error } = feed(ends[to], split([wire], how, cut))
      assert.equal(error, undefined, `${how}: ${error?.message ?? ''}`)
      got[to].push(...frames.map(shown))
    }
    assert.deepEqual(got.kernel, sent.mux, `${how}: the kernel decoded what the mux sent`)
    assert.deepEqual(got.mux, sent.kernel, `${how}: the mux decoded what the kernel sent`)
    for (const end of [ends.kernel, ends.mux]) {
      assert.equal(end.flowsOpened, 24)
      assert.equal(end.openFlows, 14, 'flows 1 to 10 retired; 11 to 24 open')
      assert.equal(end.finish(), undefined)
    }
    assert.deepEqual(ends.mux.limits, limits, 'the mux learnt its limits from go')
  }
})

// ── the shared vectors ────────────────────────────────────────────────────────

const VHex = z.string().regex(/^[0-9a-f ]*$/)
const VFrame = z.strictObject({ type: z.enum(FRAME_TYPES), flow: z.number().int().min(0).max(MAX_FLOW_ID), payload: VHex })
const VGot = z.strictObject({ ...VFrame.shape, stale: z.boolean() })
const VCounts = { openFlows: z.number().int().min(0).optional(), flowsOpened: z.number().int().min(0).optional() }
const VRefusal = z.enum(FRAME_REFUSALS)
const VStep = z.union([
  z.strictObject({ send: VFrame, wire: VHex, ...VCounts }),
  z.strictObject({ refuse: VFrame, refusal: VRefusal, ...VCounts }),
  z.strictObject({ receive: z.array(VHex).min(1), frames: z.array(VGot), refusal: VRefusal.optional(), ...VCounts }),
  z.strictObject({ finish: z.literal(true), refusal: VRefusal.optional(), ...VCounts }),
])
type VStep = z.output<typeof VStep>
const VScript = z
  .strictObject({
    name: z.string().min(1),
    role: z.enum(CHANNEL_ROLES),
    limits: z.strictObject({ frameMaxBytes: z.number().int(), maxFlows: z.number().int() }).optional(),
    steps: z.array(VStep).min(1),
  })
  .refine((s) => (s.limits !== undefined) === (s.role === 'kernel'), 'a kernel script names its limits; a mux script learns them from go')
type VScript = z.output<typeof VScript>
const Vectors = z.strictObject({
  about: z.array(z.string().min(1)).min(1),
  wire: z.strictObject({
    headerBytes: z.number(),
    readyMaxBytes: z.number(),
    frameMaxBytesLimit: z.number(),
    maxFlowsLimit: z.number(),
    maxFlowId: z.number(),
  }),
  types: z.record(z.enum(FRAME_TYPES), z.number().int()),
  limits: z.partialRecord(VRefusal, z.enum(PROXY_LIMITS)),
  frames: z.array(z.strictObject({ name: z.string().min(1), ...VFrame.shape, wire: VHex })).min(1),
  scripts: z.array(VScript).min(1),
})

const VECTORS = Vectors.parse(JSON.parse(readFileSync(VECTORS_PATH, 'utf8')))

const vframe = (f: z.output<typeof VFrame>): Frame => frame(f.type, f.flow, bytes(f.payload))
const vgot = (f: z.output<typeof VGot>): Shown => ({ type: f.type, flow: f.flow, payload: hexOf(bytes(f.payload)), stale: f.stale })

interface Snapshot {
  readonly openFlows: number
  readonly flowsOpened: number
  readonly limits: FrameLimits | undefined
  readonly failure: FrameError | undefined
}
const snapshot = (c: FrameChannel): Snapshot => ({ openFlows: c.openFlows, flowsOpened: c.flowsOpened, limits: c.limits, failure: c.failure })

/** Which way a refusal was met: decoding what the other end sent (finish() included), or holding this end's own send. */
type Side = 'receive' | 'send'
const SIDES: readonly Side[] = ['receive', 'send']

/** A refused frame as the wire spelt it: its type (none for a type byte that names none) and its payload's length. */
interface Refused {
  readonly type: FrameType | undefined
  readonly length: number
  /** The limits the channel held it to, if it held any yet. */
  readonly limits: FrameLimits | undefined
}

interface Met {
  readonly side: Side
  readonly error: FrameError
  /** The frame refused, for a refusal at a header or of a send; none for finish()'s. */
  readonly frame: Refused | undefined
}

/** The header at `at` in what a channel has been fed, if a whole one is there. */
function headerAt(received: Uint8Array, at: number, limits: FrameLimits | undefined): Refused | undefined {
  if (received.length - at < FRAME_HEADER_BYTES) return undefined
  const view = Buffer.from(received.buffer, received.byteOffset + at, FRAME_HEADER_BYTES)
  return { type: EV_TYPE_OF.get(view.readUInt8(4)), length: view.readUInt32BE(0), limits }
}

/**
 * Run one script on a fresh channel, every receive's pieces cut `how`.
 * Returns every refusal it met, which way, and the frame it refused. A
 * refusal met again only because the channel had already ended (a later
 * receive, finish() or send) is not returned: it was met where it ended the
 * channel.
 */
function replay(script: VScript, how: Split): Met[] {
  const channel = script.limits === undefined ? new FrameChannel({ role: 'mux' }) : kernelEnd(script.limits)
  const rng = prng(script.name.length * 7919)
  const met: Met[] = []
  // Everything the channel has been fed, and how much of it the frames handed out took.
  let received: Uint8Array = new Uint8Array(0)
  let decoded = 0
  script.steps.forEach((step: VStep, i) => {
    const at = `${script.name} [${how}] step ${String(i + 1)}`
    const ended = channel.failure !== undefined
    if ('send' in step) {
      const f = vframe(step.send)
      assert.equal(channel.sendRefusal(f), undefined, `${at}: sendRefusal says it sends`)
      assert.equal(hexOf(channel.send(f)), hexOf(bytes(step.wire)), at)
    } else if ('refuse' in step) {
      const f = vframe(step.refuse)
      const before = snapshot(channel)
      const asked = channel.sendRefusal(f)
      assert.equal(asked?.refusal, step.refusal, `${at}: sendRefusal: ${asked?.message ?? 'none'}`)
      assert.deepEqual(snapshot(channel), before, `${at}: sendRefusal changes nothing`)
      assert.throws(
        () => channel.send(f),
        (e: unknown) => {
          assert.ok(e instanceof FrameError, at)
          assert.equal(e.refusal, step.refusal, `${at}: ${e.message}`)
          assert.equal(e.message, asked?.message, `${at}: send throws what sendRefusal said`)
          assertWording(e)
          if (!ended) met.push({ side: 'send', error: e, frame: { type: f.type, length: f.payload.length, limits: before.limits } })
          return true
        },
        at,
      )
      assert.deepEqual(snapshot(channel), before, `${at}: a refused send changes nothing`)
    } else if ('receive' in step) {
      const pieces = step.receive.map(bytes)
      received = join(received, ...pieces)
      const { frames, error } = feed(channel, split(pieces, how, rng))
      assert.deepEqual(frames.map(shown), step.frames.map(vgot), at)
      assert.equal(error?.refusal, step.refusal, `${at}: ${error?.message ?? 'no refusal'}`)
      decoded += frames.reduce((n, f) => n + FRAME_HEADER_BYTES + f.payload.length, 0)
      if (error !== undefined) {
        assertWording(error)
        // The limits now are the ones the refused frame was judged by: a
        // refused go teaches none, and the frames before it are all decoded.
        if (!ended) met.push({ side: 'receive', error, frame: headerAt(received, decoded, channel.limits) })
      }
    } else {
      const error = channel.finish()
      assert.equal(error?.refusal, step.refusal, `${at}: ${error?.message ?? 'no refusal'}`)
      if (error !== undefined) {
        assertWording(error)
        if (!ended) met.push({ side: 'receive', error, frame: undefined })
      }
    }
    if (step.openFlows !== undefined) assert.equal(channel.openFlows, step.openFlows, `${at}: openFlows`)
    if (step.flowsOpened !== undefined) assert.equal(channel.flowsOpened, step.flowsOpened, `${at}: flowsOpened`)
  })
  return met
}

/**
 * Every refusal each end can meet, decoding (finish() included) and
 * sending, written out here rather than derived from FRAME_RULES. The rest
 * cannot be met there: a type the other end never sends is refused as
 * direction before any later rule (so the kernel never meets go-twice or
 * go-value receiving, and the mux never meets ready-twice, after-exit,
 * flow-order or max-flows receiving), a type this end never sends is
 * direction too (the kernel never meets ready-twice, after-exit, flow-order or
 * max-flows sending, the mux never go-twice or go-value), send() takes only a
 * frame encodeFrame can spell (never unknown-type), peer-closed is a send's
 * alone, and a truncated stream is finish()'s.
 */
const MEETS: Record<ChannelRole, Record<Side, readonly FrameRefusal[]>> = {
  kernel: {
    receive: [
      'unknown-type', 'direction', 'channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'before-go', 'length', 'oversize',
      'after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close', 'after-end',
      'truncated-header', 'truncated-payload',
    ],
    send: [
      'direction', 'channel-flow', 'flow-zero', 'not-ready', 'go-twice', 'before-go', 'length', 'oversize',
      'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed', 'go-value',
    ],
  },
  mux: {
    receive: [
      'unknown-type', 'direction', 'channel-flow', 'flow-zero', 'not-ready', 'go-twice', 'before-go', 'length', 'oversize',
      'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'go-value', 'truncated-header', 'truncated-payload',
    ],
    send: [
      'direction', 'channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'before-go', 'length', 'oversize',
      'after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed',
    ],
  },
}

// ── a second evaluator, for the check order ──────────────────────────────────
//
// The rules as frame.ts's CHECK ORDER table states them, each judged on its
// own whatever the rules before it found, written out here rather than read
// from frame.ts. It says which rules a frame breaks, never which one refuses
// it: that is the first of them in the check order. So it can say what a
// check-order script's last frame breaks (its name must list exactly that),
// and, walked over the states an end can reach, every place two rules meet.

/** The check order, written out: FRAME_REFUSALS lists it, then finish()'s two. */
const CHECK_ORDER: readonly FrameRefusal[] = [
  'unknown-type', 'direction', 'channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'go-twice', 'before-go',
  'length', 'oversize', 'after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close',
  'after-end', 'peer-closed', 'go-value',
]

interface EvRule {
  readonly code: number
  readonly from: readonly ChannelRole[]
  readonly channel: boolean
  readonly min: number
  readonly max: number | 'frameMaxBytes'
}

/** frame.ts's table of types, written out: code, sender, flow 0 or a flow, payload length. */
const EV_RULES: Readonly<Record<FrameType, EvRule>> = {
  ready: { code: 0x01, from: ['mux'], channel: true, min: 0, max: 4096 },
  go: { code: 0x02, from: ['kernel'], channel: true, min: 8, max: 8 },
  open: { code: 0x10, from: ['mux'], channel: false, min: 0, max: 0 },
  data: { code: 0x11, from: ['kernel', 'mux'], channel: false, min: 1, max: 'frameMaxBytes' },
  end: { code: 0x12, from: ['kernel', 'mux'], channel: false, min: 0, max: 0 },
  close: { code: 0x13, from: ['kernel', 'mux'], channel: false, min: 0, max: 0 },
  stdout: { code: 0x20, from: ['mux'], channel: true, min: 1, max: 'frameMaxBytes' },
  stderr: { code: 0x21, from: ['mux'], channel: true, min: 1, max: 'frameMaxBytes' },
  exit: { code: 0x22, from: ['mux'], channel: true, min: 1, max: 1 },
}
const EV_TYPES = Object.keys(EV_RULES) as FrameType[]
const EV_TYPE_OF: ReadonlyMap<number, FrameType> = new Map(EV_TYPES.map((t) => [EV_RULES[t].code, t]))
const otherEnd = (role: ChannelRole): ChannelRole => (role === 'kernel' ? 'mux' : 'kernel')

interface EvFlow {
  readonly kernel: { ended: boolean; closed: boolean }
  readonly mux: { ended: boolean; closed: boolean }
}

/** One end's state: what has crossed, and the flows not yet retired. */
interface EvState {
  readonly role: ChannelRole
  ready: boolean
  go: boolean
  exited: boolean
  last: number
  readonly flows: Map<number, EvFlow>
  limits: FrameLimits | undefined
}

const evFresh = (role: ChannelRole, limits: FrameLimits | undefined): EvState => ({
  role, ready: false, go: false, exited: false, last: 0, flows: new Map(), limits,
})
const evCopy = (s: EvState): EvState => ({
  ...s,
  flows: new Map([...s.flows].map(([id, f]) => [id, { kernel: { ...f.kernel }, mux: { ...f.mux } }])),
})
const evKey = (s: EvState): string =>
  JSON.stringify([s.ready, s.go, s.exited, s.last, s.limits ?? null, [...s.flows].map(([id, f]) => [id, f.kernel, f.mux])])

/** The limits a go payload names, if it is 8 bytes naming each in range. */
function evGoLimits(payload: Uint8Array): FrameLimits | undefined {
  if (payload.length !== 8) return undefined
  const view = Buffer.from(payload)
  const frameMaxBytes = view.readUInt32BE(0)
  const maxFlows = view.readUInt32BE(4)
  const inRange = frameMaxBytes >= 1 && frameMaxBytes <= 1_048_576 && maxFlows >= 1 && maxFlows <= 256
  return inRange ? { frameMaxBytes, maxFlows } : undefined
}

/**
 * Every rule a frame `from` sends breaks at an end in state `s`, each judged
 * on its own. `payload` is the frame's payload if it is at hand; go-value is
 * judged only on a go of 8 bytes whose payload is.
 */
function evBroken(s: EvState, from: ChannelRole, code: number, flow: number, length: number, payload: Uint8Array | undefined): Set<FrameRefusal> {
  const out = new Set<FrameRefusal>()
  const type = EV_TYPE_OF.get(code)
  if (type === undefined) out.add('unknown-type')
  if (type !== 'ready' && !s.ready) out.add('not-ready')
  if (type !== 'ready' && type !== 'go' && !s.go) out.add('before-go')
  if (type === undefined) return out
  const rule = EV_RULES[type]
  if (!rule.from.includes(from)) out.add('direction')
  if (rule.channel && flow !== 0) out.add('channel-flow')
  if (!rule.channel && flow === 0) out.add('flow-zero')
  if (type === 'ready' && s.ready) out.add('ready-twice')
  if (type === 'go' && s.go) out.add('go-twice')
  if (length < rule.min || (rule.max !== 'frameMaxBytes' && length > rule.max)) out.add('length')
  if (rule.max === 'frameMaxBytes' && s.limits !== undefined && length > s.limits.frameMaxBytes) out.add('oversize')
  if ((type === 'open' || type === 'stdout' || type === 'stderr' || type === 'exit') && s.exited) out.add('after-exit')
  if (type === 'open' && flow !== s.last + 1) out.add('flow-order')
  if (type === 'open' && s.limits !== undefined && s.flows.size >= s.limits.maxFlows) out.add('max-flows')
  if (type === 'data' || type === 'end' || type === 'close') {
    const state = s.flows.get(flow)
    if (flow > s.last) out.add('unopened-flow')
    if (flow <= s.last && state === undefined) out.add('closed-flow')
    if (state?.[from].closed === true) out.add('after-close')
    if (type !== 'close' && state?.[from].ended === true) out.add('after-end')
    if (type !== 'close' && from === s.role && state?.[otherEnd(from)].closed === true) out.add('peer-closed')
  }
  if (type === 'go' && length === 8 && payload !== undefined) {
    const named = evGoLimits(payload)
    const held = s.limits
    if (named === undefined || (held !== undefined && (named.frameMaxBytes !== held.frameMaxBytes || named.maxFlows !== held.maxFlows))) {
      out.add('go-value')
    }
  }
  return out
}

/** A frame that broke nothing changes the state both ends share. */
function evApply(s: EvState, from: ChannelRole, type: FrameType, flow: number, payload: Uint8Array): void {
  if (type === 'ready') s.ready = true
  if (type === 'go') {
    s.go = true
    s.limits ??= evGoLimits(payload)
  }
  if (type === 'exit') s.exited = true
  if (type === 'open') {
    s.last = flow
    s.flows.set(flow, { kernel: { ended: false, closed: false }, mux: { ended: false, closed: false } })
  }
  const state = s.flows.get(flow)
  if (state !== undefined && type === 'end') state[from].ended = true
  if (state !== undefined && type === 'close') {
    state[from].closed = true
    if (state.kernel.closed && state.mux.closed) s.flows.delete(flow)
  }
}

/** One frame's place in the check order: the first rule it breaks and each other one, as "X before Y". */
function pairsOf(breaks: ReadonlySet<FrameRefusal>): string[] {
  const [first, ...rest] = CHECK_ORDER.filter((r) => breaks.has(r))
  return first === undefined ? [] : rest.map((later) => `${first} before ${later}`)
}

/** What drives the walk: one payload of each type that breaks nothing, so every move is a frame an end may send. */
const EV_MOVES: Readonly<Record<FrameType, Uint8Array>> = {
  ready: text('ok'),
  go: Uint8Array.of(0, 0, 0, 4, 0, 0, 0, 2),
  open: new Uint8Array(0),
  data: text('a'),
  end: new Uint8Array(0),
  close: new Uint8Array(0),
  stdout: text('a'),
  stderr: text('a'),
  exit: Uint8Array.of(0),
}

/**
 * Every place two rules meet at one end, each way: "X before Y" wherever some
 * frame the end can meet breaks both, X the first it breaks. A walk of every
 * state the end can reach with frameMaxBytes 4 and maxFlows 2, moved only by
 * frames that break nothing, and at each state every frame of one of each
 * kind: every type byte (and one that names none), flow 0 to two past the
 * last opened, and payloads of 0, 1, 5, 8 and 4097 bytes, which fall below
 * every type's least, inside data's and exit's, past frameMaxBytes 4 and
 * exit's 1, at go's 8 and past ready's 4096, a go of 8 naming the channel's
 * limits, others in range and one out of it. Two flows reach the cap, and no
 * rule reads a flow but the one a frame names and how many are open, so a
 * walk that opens more finds nothing new (one that opens up to four, five
 * times the states, was run when this was written: the same pairs).
 */
function derivePairs(role: ChannelRole): Record<Side, Set<string>> {
  const out: Record<Side, Set<string>> = { receive: new Set(), send: new Set() }
  const LIMITS = { frameMaxBytes: 4, maxFlows: 2 }
  const MOST_OPENED = 2
  const start = evFresh(role, role === 'kernel' ? LIMITS : undefined)
  const seen = new Map<string, EvState>([[evKey(start), start]])
  const queue: EvState[] = [start]
  const goPayloads = [EV_MOVES.go, Uint8Array.of(0, 0, 0, 5, 0, 0, 0, 2), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 2)]
  for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
    const s = next
    for (const side of SIDES) {
      const from = side === 'send' ? role : otherEnd(role)
      // send() takes only a frame encodeFrame can spell: no unknown type.
      const codes = side === 'send' ? EV_TYPES.map((t) => EV_RULES[t].code) : [0x00, ...EV_TYPES.map((t) => EV_RULES[t].code)]
      for (const code of codes) {
        for (let flow = 0; flow <= s.last + 2; flow++) {
          for (const length of [0, 1, 5, 8, 4097]) {
            const payloads = code === EV_RULES.go.code && length === 8 ? goPayloads : [new Uint8Array(length)]
            for (const payload of payloads) {
              for (const pair of pairsOf(evBroken(s, from, code, flow, length, payload))) out[side].add(pair)
            }
          }
        }
      }
      for (const type of EV_TYPES) {
        for (let flow = 0; flow <= s.last + 1; flow++) {
          const payload = EV_MOVES[type]
          if (evBroken(s, from, EV_RULES[type].code, flow, payload.length, payload).size > 0) continue
          if (type === 'open' && flow > MOST_OPENED) continue
          const moved = evCopy(s)
          evApply(moved, from, type, flow, payload)
          const key = evKey(moved)
          if (seen.has(key)) continue
          seen.set(key, moved)
          queue.push(moved)
        }
      }
    }
  }
  return out
}

/**
 * Each place two rules meet, at each end and each way, as derivePairs()
 * finds them: the earlier, then every later one it can meet. Written out
 * here, so a change to the evaluator is a difference, not a new truth, and a
 * mux author (E9) can read what the vectors hold the mux to.
 */
const ORDER_PAIRS: Record<ChannelRole, Record<Side, Readonly<Partial<Record<FrameRefusal, readonly FrameRefusal[]>>>>> = {
  kernel: {
    receive: {
      'unknown-type': ['not-ready', 'before-go'],
      direction: ['channel-flow', 'not-ready', 'go-twice', 'length', 'go-value'],
      'channel-flow': ['ready-twice', 'not-ready', 'before-go', 'length', 'oversize', 'after-exit'],
      'flow-zero': ['not-ready', 'before-go', 'length', 'oversize', 'after-exit', 'flow-order', 'max-flows', 'closed-flow'],
      'ready-twice': ['length'],
      'not-ready': ['before-go', 'length', 'oversize', 'flow-order', 'unopened-flow'],
      'before-go': ['length', 'oversize', 'flow-order', 'unopened-flow'],
      length: ['after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close', 'after-end'],
      oversize: ['after-exit', 'unopened-flow', 'closed-flow', 'after-close', 'after-end'],
      'after-exit': ['flow-order', 'max-flows'],
      'flow-order': ['max-flows'],
      'after-close': ['after-end'],
    },
    send: {
      direction: ['channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'before-go', 'length', 'oversize', 'after-exit', 'flow-order', 'max-flows'],
      'channel-flow': ['not-ready', 'go-twice', 'length', 'go-value'],
      'flow-zero': ['not-ready', 'before-go', 'length', 'oversize', 'closed-flow'],
      'not-ready': ['before-go', 'length', 'oversize', 'unopened-flow', 'go-value'],
      'go-twice': ['length', 'go-value'],
      'before-go': ['length', 'oversize', 'unopened-flow'],
      length: ['unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed'],
      oversize: ['unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed'],
      'after-close': ['after-end'],
      'after-end': ['peer-closed'],
    },
  },
  mux: {
    receive: {
      'unknown-type': ['not-ready', 'before-go'],
      direction: ['channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'before-go', 'length', 'oversize', 'after-exit', 'flow-order', 'max-flows'],
      'channel-flow': ['not-ready', 'go-twice', 'length', 'go-value'],
      'flow-zero': ['not-ready', 'before-go', 'length', 'oversize', 'closed-flow'],
      'not-ready': ['before-go', 'length', 'unopened-flow', 'go-value'],
      'go-twice': ['length', 'go-value'],
      'before-go': ['length', 'unopened-flow'],
      length: ['unopened-flow', 'closed-flow', 'after-close', 'after-end'],
      oversize: ['unopened-flow', 'closed-flow', 'after-close', 'after-end'],
      'after-close': ['after-end'],
    },
    send: {
      direction: ['channel-flow', 'not-ready', 'go-twice', 'length', 'go-value'],
      'channel-flow': ['ready-twice', 'not-ready', 'before-go', 'length', 'oversize', 'after-exit'],
      'flow-zero': ['not-ready', 'before-go', 'length', 'oversize', 'after-exit', 'flow-order', 'max-flows', 'closed-flow'],
      'ready-twice': ['length'],
      'not-ready': ['before-go', 'length', 'flow-order', 'unopened-flow'],
      'before-go': ['length', 'flow-order', 'unopened-flow'],
      length: ['after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed'],
      oversize: ['after-exit', 'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed'],
      'after-exit': ['flow-order', 'max-flows'],
      'flow-order': ['max-flows'],
      'after-close': ['after-end'],
      'after-end': ['peer-closed'],
    },
  },
}

/**
 * The rules a check-order script's last frame breaks, by the evaluator, and
 * which way it meets them. Every frame before it is replayed and must break
 * nothing; the last step is a refused send, or a receive whose first frame,
 * starting where the earlier steps' frames ended, is the one refused.
 */
function lastFrameBreaks(script: VScript): { readonly side: Side; readonly breaks: Set<FrameRefusal> } {
  const s = evFresh(script.role, script.limits)
  let held = Buffer.alloc(0)
  for (const [i, step] of script.steps.entries()) {
    const at = `${script.name} step ${String(i + 1)}`
    const last = i === script.steps.length - 1
    if ('send' in step || 'refuse' in step) {
      const f = vframe('send' in step ? step.send : step.refuse)
      const breaks = evBroken(s, script.role, EV_RULES[f.type].code, f.flow, f.payload.length, f.payload)
      if (last) {
        assert.ok('refuse' in step, `${at}: a check-order script ends with its refused frame`)
        return { side: 'send', breaks }
      }
      assert.deepEqual([...breaks], [], `${at}: the evaluator says this frame breaks nothing`)
      evApply(s, script.role, f.type, f.flow, f.payload)
    } else if ('receive' in step) {
      if (last) assert.equal(held.length, 0, `${at}: the refused frame starts the last step`)
      held = Buffer.concat([held, ...step.receive.map((h) => Buffer.from(bytes(h)))])
      while (held.length >= FRAME_HEADER_BYTES) {
        const length = held.readUInt32BE(0)
        const code = held.readUInt8(4)
        const flow = held.readUInt32BE(5)
        const whole = held.length >= FRAME_HEADER_BYTES + length
        const payload = whole ? Uint8Array.from(held.subarray(FRAME_HEADER_BYTES, FRAME_HEADER_BYTES + length)) : undefined
        const breaks = evBroken(s, otherEnd(script.role), code, flow, length, payload)
        if (last) return { side: 'receive', breaks }
        assert.deepEqual([...breaks], [], `${at}: the evaluator says this frame breaks nothing`)
        const type = EV_TYPE_OF.get(code)
        if (payload === undefined || type === undefined) break
        evApply(s, otherEnd(script.role), type, flow, payload)
        held = held.subarray(FRAME_HEADER_BYTES + length)
      }
      assert.equal(last, false, `${at}: the last step holds a frame`)
    } else {
      assert.fail(`${at}: a check-order script ends with a frame, not finish()`)
    }
  }
  assert.fail(`${script.name}: no steps`)
}

/**
 * Every wrong payload length each end can meet, each way, as `type short` or
 * `type long` and the refusal: a payload under a type's least is `length`,
 * one past a fixed most is `length`, and one past frameMaxBytes is
 * `oversize`. Written out here; the test also derives it from EV_RULES and
 * who sends what, and holds the vectors to it, so an E9 mux replaying only
 * the mux scripts is held to every length check it makes.
 */
const LENGTH_CELLS: Record<ChannelRole, Record<Side, readonly string[]>> = {
  kernel: {
    receive: [
      'ready long length', 'open long length', 'data short length', 'data long oversize', 'end long length',
      'close long length', 'stdout short length', 'stdout long oversize', 'stderr short length', 'stderr long oversize',
      'exit short length', 'exit long length',
    ],
    send: ['go short length', 'go long length', 'data short length', 'data long oversize', 'end long length', 'close long length'],
  },
  mux: {
    receive: ['go short length', 'go long length', 'data short length', 'data long oversize', 'end long length', 'close long length'],
    send: [
      'ready long length', 'open long length', 'data short length', 'data long oversize', 'end long length',
      'close long length', 'stdout short length', 'stdout long oversize', 'stderr short length', 'stderr long oversize',
      'exit short length', 'exit long length',
    ],
  },
}

test('frame.ts matches the shared vectors, each receive fed as given, whole, a byte at a time and in random pieces', () => {
  // The constants the mux must share are the file's, so a change to one end
  // without the other fails here or in test/egress-mux.test.ts.
  assert.deepEqual(VECTORS.wire, {
    headerBytes: FRAME_HEADER_BYTES,
    readyMaxBytes: READY_MAX_BYTES,
    frameMaxBytesLimit: FRAME_MAX_BYTES_LIMIT,
    maxFlowsLimit: MAX_FLOWS_LIMIT,
    maxFlowId: MAX_FLOW_ID,
  })
  assert.deepEqual(VECTORS.types, FRAME_TYPE_CODES)

  for (const v of VECTORS.frames) {
    assert.equal(hexOf(encodeFrame(vframe(v))), hexOf(bytes(v.wire)), v.name)
  }
  const names = VECTORS.scripts.map((s) => s.name)
  assert.equal(new Set(names).size, names.length, 'every script has its own name')

  const met = new Map<FrameRefusal, FrameError>()
  const metBy: Record<ChannelRole, Record<Side, Set<FrameRefusal>>> = {
    kernel: { receive: new Set(), send: new Set() },
    mux: { receive: new Set(), send: new Set() },
  }
  for (const script of VECTORS.scripts) {
    for (const how of SPLITS) {
      for (const { side, error } of replay(script, how)) {
        met.set(error.refusal, error)
        metBy[script.role][side].add(error.refusal)
      }
    }
  }
  // Every refusal is pinned by some script, and the limits table says which
  // are a grant's limits.
  assert.deepEqual([...met.keys()].sort(), [...FRAME_REFUSALS].sort())
  for (const [refusal, error] of met) {
    assert.equal(error.limit, VECTORS.limits[refusal], refusal)
    assert.equal(error.reason, VECTORS.limits[refusal] === undefined ? 'violation' : 'limit', refusal)
  }
  // And each end's scripts alone meet every refusal that end can meet, each
  // way, so a mux codec (E9) that replays only the mux scripts is held to
  // every refusal a mux meets: none is pinned only at the kernel end.
  for (const role of CHANNEL_ROLES) {
    for (const side of ['receive', 'send'] as const) {
      assert.deepEqual([...metBy[role][side]].sort(), [...MEETS[role][side]].sort(), `${role}, ${side}`)
    }
  }
})

test('the vectors pin the check order: a script for each place two rules meet, at each end and each way, refused by the first it breaks', () => {
  // The evaluator is held to frame.ts's own tables, so it judges the rules
  // frame.ts and the vectors name; and the check order it reads is theirs.
  assert.deepEqual(FRAME_REFUSALS, [...CHECK_ORDER, 'truncated-header', 'truncated-payload'])
  for (const type of FRAME_TYPES) {
    const rule = EV_RULES[type]
    assert.equal(FRAME_TYPE_CODES[type], rule.code, type)
    assert.deepEqual(
      { from: [...FRAME_RULES[type].from], channel: FRAME_RULES[type].channel, min: FRAME_RULES[type].minBytes, max: FRAME_RULES[type].maxBytes },
      { from: [...rule.from], channel: rule.channel, min: rule.min, max: rule.max },
      type,
    )
  }
  assert.deepEqual([...EV_TYPES].sort(), [...FRAME_TYPES].sort())

  // A script's name lists exactly the rules its last frame breaks, in the
  // check order, so the first it names is the refusal the replay above
  // proved; the rest are each a place that rule meets the first.
  const named: Record<ChannelRole, Record<Side, Set<string>>> = {
    kernel: { receive: new Set(), send: new Set() },
    mux: { receive: new Set(), send: new Set() },
  }
  for (const script of VECTORS.scripts) {
    const m = /check order, ([a-z-]+) before ([a-z-]+(?: and [a-z-]+)*):/.exec(script.name)
    if (m === null) {
      assert.equal(script.name.includes('check order'), false, `${script.name}: a check-order name says X before Y:`)
      continue
    }
    const listed = [m[1], ...(m[2] ?? '').split(' and ')].map((name) => VRefusal.parse(name))
    const last = script.steps.at(-1)
    assert.ok(last !== undefined && 'refusal' in last && last.refusal === listed[0], `${script.name}: it ends refused with ${String(listed[0])}`)
    for (const step of script.steps.slice(0, -1)) {
      assert.equal('refusal' in step && step.refusal !== undefined, false, `${script.name}: only its last frame is refused`)
    }
    const { side, breaks } = lastFrameBreaks(script)
    assert.deepEqual(listed, CHECK_ORDER.filter((rule) => breaks.has(rule)), `${script.name}: its frame breaks exactly the rules it names`)
    for (const pair of pairsOf(breaks)) named[script.role][side].add(pair)
  }

  // Every place two rules meet, at each end and each way, is one the
  // evaluator finds over every state an end can reach, and the vectors have a
  // check-order script for each: none is left to a mux author's guess.
  for (const role of CHANNEL_ROLES) {
    const derived = derivePairs(role)
    for (const side of SIDES) {
      const table = Object.entries(ORDER_PAIRS[role][side]).flatMap(([earlier, laters]) => (laters ?? []).map((later) => `${earlier} before ${later}`))
      for (const [earlier, laters] of Object.entries(ORDER_PAIRS[role][side])) {
        for (const later of laters ?? []) {
          assert.ok(CHECK_ORDER.indexOf(earlier as FrameRefusal) < CHECK_ORDER.indexOf(later), `${role} ${side}: ${earlier} comes before ${later}`)
        }
      }
      assert.deepEqual([...derived[side]].sort(), [...table].sort(), `${role} ${side}: ORDER_PAIRS is every place the evaluator finds two rules meet`)
      assert.deepEqual([...named[role][side]].sort(), [...table].sort(), `${role} ${side}: a check-order script for each place two rules meet`)
    }
  }

  // The places review found unpinned, among them the four where a reorder
  // flipped a revocation between limit and violation or went unseen.
  for (const [role, side, pair] of [
    ['kernel', 'receive', 'flow-order before max-flows'],
    ['kernel', 'receive', 'after-exit before flow-order'],
    ['kernel', 'receive', 'after-close before after-end'],
    ['kernel', 'receive', 'oversize before unopened-flow'],
    ['kernel', 'receive', 'flow-zero before not-ready'],
    ['kernel', 'receive', 'ready-twice before length'],
    ['kernel', 'receive', 'direction before channel-flow'],
    ['kernel', 'send', 'after-end before peer-closed'],
    ['kernel', 'receive', 'channel-flow before oversize'],
    ['kernel', 'receive', 'flow-zero before oversize'],
    ['kernel', 'receive', 'not-ready before oversize'],
    ['kernel', 'receive', 'oversize before after-exit'],
    ['kernel', 'receive', 'before-go before length'],
    ['kernel', 'receive', 'length before closed-flow'],
    ['mux', 'send', 'before-go before length'],
    ['mux', 'send', 'oversize before after-exit'],
    ['mux', 'send', 'ready-twice before length'],
  ] as const) {
    assert.ok(named[role][side].has(pair), `${role} ${side}: ${pair}`)
  }
})

test('the vectors refuse every wrong payload length, each type at each end and each way, too short and too long', () => {
  // The cells, derived from the evaluator's table and who sends what, are
  // the ones written out, so a cell dropped from LENGTH_CELLS is a difference.
  for (const role of CHANNEL_ROLES) {
    for (const side of SIDES) {
      const sender = side === 'send' ? role : otherEnd(role)
      const derived = EV_TYPES.filter((t) => EV_RULES[t].from.includes(sender)).flatMap((t) => {
        const { min, max } = EV_RULES[t]
        return [...(min > 0 ? [`${t} short length`] : []), max === 'frameMaxBytes' ? `${t} long oversize` : `${t} long length`]
      })
      assert.deepEqual([...derived].sort(), [...LENGTH_CELLS[role][side]].sort(), `${role} ${side}: LENGTH_CELLS`)
    }
  }
  // And the vectors meet every one, at the end and way it names: each refused
  // frame's length is judged here, against the evaluator's table and the
  // limits the channel held it to, not read from the refusal.
  const met: Record<ChannelRole, Record<Side, Set<string>>> = {
    kernel: { receive: new Set(), send: new Set() },
    mux: { receive: new Set(), send: new Set() },
  }
  for (const script of VECTORS.scripts) {
    for (const { side, error, frame: refused } of replay(script, 'whole')) {
      if (error.refusal !== 'length' && error.refusal !== 'oversize') continue
      assert.ok(refused?.type !== undefined, `${script.name}: a ${error.refusal} refusal of a frame it can read`)
      const { min, max } = EV_RULES[refused.type]
      const short = refused.length < min
      if (!short) {
        const most = max === 'frameMaxBytes' ? refused.limits?.frameMaxBytes : max
        assert.ok(most !== undefined && refused.length > most, `${script.name}: ${refused.type} of ${String(refused.length)} is past its most`)
      }
      met[script.role][side].add(`${refused.type} ${short ? 'short' : 'long'} ${error.refusal}`)
    }
  }
  for (const role of CHANNEL_ROLES) {
    for (const side of SIDES) {
      assert.deepEqual([...met[role][side]].sort(), [...LENGTH_CELLS[role][side]].sort(), `${role} ${side}: a refusal for each wrong length`)
    }
  }
})

test('the vectors spell every frame type and drive both ends', () => {
  assert.deepEqual([...new Set(VECTORS.frames.map((f) => f.type))].sort(), [...FRAME_TYPES].sort())
  assert.deepEqual([...new Set(VECTORS.scripts.map((s) => s.role))].sort(), ['kernel', 'mux'])
  // Each end's scripts both decode and send, and each end meets a refused send.
  for (const role of CHANNEL_ROLES) {
    const steps = VECTORS.scripts.filter((s) => s.role === role).flatMap((s) => s.steps)
    for (const kind of ['send', 'refuse', 'receive', 'finish'] as const) {
      assert.ok(steps.some((step) => kind in step), `${role} has a ${kind} step`)
    }
  }
})

// ── the rules, beyond the vectors ─────────────────────────────────────────────

test('who sends what is fixed: each end refuses, from the other, every type the other never sends', () => {
  // Written out here rather than read from FRAME_RULES, so a rule changed in
  // frame.ts is a difference, not a new truth.
  const sends: Record<ChannelRole, readonly FrameType[]> = {
    mux: ['ready', 'open', 'data', 'end', 'close', 'stdout', 'stderr', 'exit'],
    kernel: ['go', 'data', 'end', 'close'],
  }
  const limits = shippedLimits()
  for (const role of CHANNEL_ROLES) {
    assert.deepEqual([...FRAME_TYPES].filter((t) => FRAME_RULES[t].from.includes(role)), sends[role], role)
  }
  for (const type of FRAME_TYPES) {
    const channelType = ['ready', 'go', 'stdout', 'stderr', 'exit'].includes(type)
    assert.equal(FRAME_RULES[type].channel, channelType, type)
    const flow = channelType ? 0 : 1
    if (!sends.mux.includes(type)) {
      refusedWith(handshaken(limits), header(0, FRAME_TYPE_CODES[type], flow), 'direction', `${type} to the kernel`)
    }
    if (!sends.kernel.includes(type)) {
      const mux = muxHandshaken(limits)
      refusedWith(mux, header(0, FRAME_TYPE_CODES[type], flow), 'direction', `${type} to the mux`)
      assert.throws(() => kernelEnd(limits).send(frame(type, flow)), (e: unknown) => e instanceof FrameError && e.refusal === 'direction')
    }
  }
})

test('a flow retires only once both closes have crossed: the 17th opens after one of sixteen has, never while one side alone has closed', () => {
  const limits = shippedLimits()
  const sixteen = (): FrameChannel => {
    const channel = handshaken(limits)
    for (let flow = 1; flow <= 16; flow++) assert.equal(channel.receive(encodeFrame(frame('open', flow))).error, undefined)
    return channel
  }
  const open17 = encodeFrame(frame('open', 17))

  const muxClosed = sixteen()
  muxClosed.receive(encodeFrame(frame('close', 5)))
  assert.equal(muxClosed.openFlows, 16)
  refusedWith(muxClosed, open17, 'max-flows', 'only the mux has closed flow 5')

  const kernelClosed = sixteen()
  kernelClosed.send(frame('close', 5))
  assert.equal(kernelClosed.openFlows, 16)
  refusedWith(kernelClosed, open17, 'max-flows', 'only the kernel has closed flow 5')

  const ended = sixteen()
  ended.receive(encodeFrame(frame('end', 5)))
  ended.send(frame('end', 5))
  refusedWith(ended, open17, 'max-flows', 'both ends of flow 5 are finished, but neither side has closed it')

  for (const first of CHANNEL_ROLES) {
    const both = sixteen()
    if (first === 'kernel') both.send(frame('close', 5))
    both.receive(encodeFrame(frame('close', 5)))
    if (first === 'mux') both.send(frame('close', 5))
    assert.equal(both.openFlows, 15, `${first} closed first`)
    assert.deepEqual(feed(both, [open17]).frames.map((f) => f.flow), [17])
    assert.equal(both.openFlows, 16)
    // Retired for good: its id is never named again, by either end.
    refusedWith(both, encodeFrame(frame('data', 5, text('late'))), 'closed-flow', 'data on retired flow 5')
  }
  const retired = sixteen()
  retired.receive(encodeFrame(frame('close', 5)))
  retired.send(frame('close', 5))
  assert.throws(() => retired.send(frame('data', 5, text('late'))), (e: unknown) => e instanceof FrameError && e.refusal === 'closed-flow')
  refusedWith(retired, encodeFrame(frame('open', 5)), 'flow-order', 'flow 5 opened again')
})

test('a frame is judged stale when it is whole: the kernel close sent while its payload arrived makes it stale', () => {
  // The mux sent the data before it could have read the kernel's close, so
  // it is in flight, not a violation; and whether it is stale depends on the
  // close, which can be sent between the header and the last payload byte.
  const limits = shippedLimits()
  const channel = handshaken(limits)
  channel.receive(encodeFrame(frame('open', 1)))
  const data = encodeFrame(frame('data', 1, text('abc')))
  assert.deepEqual(feed(channel, [data.subarray(0, FRAME_HEADER_BYTES + 1)]).frames, [])
  channel.send(frame('close', 1))
  const { frames, error } = feed(channel, [data.subarray(FRAME_HEADER_BYTES + 1)])
  assert.equal(error, undefined)
  assert.deepEqual(frames.map(shown), [{ type: 'data', flow: 1, payload: hexOf(text('abc')), stale: true }])
  // And a close from the mux then retires it, not stale: it is the handshake's other half.
  assert.deepEqual(feed(channel, [encodeFrame(frame('close', 1))]).frames.map(shown), [{ type: 'close', flow: 1, payload: '', stale: false }])
  assert.equal(channel.openFlows, 0)
})

test('a refusal is final: the rest of its piece is not decoded, later pieces bring it again, finish returns it, and send throws it', () => {
  const limits = shippedLimits()
  const channel = handshaken(limits)
  const valid = encodeFrame(frame('stdout', 0, text('before')))
  const bad = header(0, 0x7f, 0)
  const after = encodeFrame(frame('stdout', 0, text('after')))
  const first = channel.receive(join(valid, bad, after, after))
  assert.deepEqual(first.frames.map((f) => Buffer.from(f.payload).toString()), ['before'])
  assert.equal(first.error?.refusal, 'unknown-type')
  for (const piece of [after, new Uint8Array(0), valid]) {
    const again = channel.receive(piece)
    assert.deepEqual(again.frames, [])
    assert.equal(again.error, first.error)
  }
  assert.equal(channel.failure, first.error)
  assert.equal(channel.finish(), first.error)
  assert.throws(() => channel.send(frame('data', 1, text('x'))), (e: unknown) => e === first.error)
  assert.throws(() => channel.receive(valid), /after finish\(\)/)
})

test('a refusal is a proxy.grant.revoked the log can hold: reason and limit as PROXY_LIMITS names them, the message as its detail, never the payload', () => {
  // The session records a refusal as it stands: `limit` and the limit's
  // name for oversize and max-flows, `violation` with the message as detail
  // for the rest. So every message must fit EGRESS_DETAIL_BYTES, be one the
  // redaction pass leaves alone, and hold nothing the container chose but
  // numbers: never a byte of a payload.
  const marker = 'PAYLOAD-MARKER-e7'
  const limits = shippedLimits()
  const errors: FrameError[] = []
  for (const script of VECTORS.scripts) errors.push(...replay(script, 'whole').map((m) => m.error))
  const withMarker: [string, () => FrameError][] = [
    ['ready twice', () => refusedWith(handshaken(limits), encodeFrame(frame('ready', 0, text(marker))), 'ready-twice', 'ready')],
    ['stdout after exit', () => {
      const c = handshaken(limits)
      c.receive(encodeFrame(frame('exit', 0, exitPayload(1))))
      return refusedWith(c, encodeFrame(frame('stdout', 0, text(marker))), 'after-exit', 'stdout')
    }],
    ['exit too long', () => refusedWith(handshaken(limits), encodeFrame(frame('exit', 0, text(marker))), 'length', 'exit')],
    ['data never opened', () => refusedWith(handshaken(limits), encodeFrame(frame('data', 3, text(marker))), 'unopened-flow', 'data')],
    ['a go of the marker', () => {
      const m = new FrameChannel({ role: 'mux' })
      m.send(frame('ready', 0, new Uint8Array(0)))
      return refusedWith(m, encodeFrame(frame('go', 0, text(marker))), 'length', 'go')
    }],
  ]
  for (const [label, make] of withMarker) {
    const error = make()
    assert.equal(error.message.includes(marker), false, `${label}: ${error.message}`)
    errors.push(error)
  }
  assert.ok(errors.length > FRAME_REFUSALS.length)
  for (const error of errors) {
    assert.equal(error.code, 'AOS_EGRESS_FRAME')
    assert.equal(error.name, 'FrameError')
    assert.match(error.message, /^frame refused \([a-z-]+\): [\x20-\x7e]+$/, error.message)
    assert.ok(Buffer.byteLength(error.message) <= EGRESS_DETAIL_BYTES, error.message)
    assert.equal(redactString(error.message), error.message, 'the store would record it as written')
    const row = {
      schemaVersion: 1,
      grantId: 'grant-1',
      reason: error.reason,
      ...(error.limit === undefined ? {} : { limit: error.limit }),
      detail: error.message,
      totals: { flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 },
    }
    const parsed = ProxyGrantRevokedPayload.safeParse(row)
    assert.ok(parsed.success, `${error.refusal}: ${parsed.error?.message ?? ''}`)
  }
})

test('payloads are copies: changing a piece after receive() changes no frame, and a payload may span any number of pieces', () => {
  const limits = shippedLimits()
  const channel = handshaken(limits)
  const piece = encodeFrame(frame('stdout', 0, text('kept')))
  const { frames } = channel.receive(piece)
  piece.fill(0)
  assert.equal(Buffer.from(frames[0]?.payload ?? new Uint8Array(0)).toString(), 'kept')

  // One frame of FRAME_MAX_BYTES_LIMIT, in pieces that cut the header and
  // the payload anywhere: decoded once, whole, and equal to what was sent.
  const big = { frameMaxBytes: FRAME_MAX_BYTES_LIMIT, maxFlows: 1 }
  const wide = handshaken(big)
  const payload = randomBytes(prng(3), FRAME_MAX_BYTES_LIMIT)
  const wire = encodeFrame(frame('stdout', 0, payload))
  const pieces: Uint8Array[] = []
  for (let at = 0; at < wire.length; at += 4093) pieces.push(wire.slice(at, at + 4093))
  const fed = feed(wide, pieces)
  assert.equal(fed.error, undefined)
  assert.equal(fed.frames.length, 1)
  assert.equal(Buffer.compare(fed.frames[0]?.payload ?? new Uint8Array(0), payload), 0)
  refusedWith(wide, header(FRAME_MAX_BYTES_LIMIT + 1, FRAME_TYPE_CODES.stdout, 0), 'oversize', 'one past the protocol bound')
})

test("frame.ts's bounds are kernel.yaml's: frameMaxBytes 1 to 1 MiB and maxFlows 1 to 256, in config, in FrameLimits and in go", () => {
  // A grant's limits come from kernel.yaml and cross to the mux in go, so a
  // value config admits and go cannot carry (or the mux refuses) would be a
  // channel that never opens, and one go admits that config refuses would
  // be a bound nobody set.
  const minimal = parseYaml(readFileSync(MINIMAL_CONFIG, 'utf8')) as Record<string, unknown>
  const inConfig = (limits: { frameMaxBytes: number; maxFlows: number }): boolean =>
    KernelConfig.safeParse({ ...minimal, egress: { limits } }).success
  const cases: [number, number, boolean][] = [
    [1, 1, true],
    [FRAME_MAX_BYTES_LIMIT, MAX_FLOWS_LIMIT, true],
    [65_536, 16, true],
    [0, 16, false],
    [FRAME_MAX_BYTES_LIMIT + 1, 16, false],
    [65_536, 0, false],
    [65_536, MAX_FLOWS_LIMIT + 1, false],
    [1.5, 16, false],
  ]
  for (const [frameMaxBytes, maxFlows, admitted] of cases) {
    const limits = { frameMaxBytes, maxFlows }
    const label = JSON.stringify(limits)
    assert.equal(inConfig(limits), admitted, `kernel.yaml: ${label}`)
    assert.equal(FrameLimits.safeParse(limits).success, admitted, `FrameLimits: ${label}`)
    if (admitted) {
      assert.deepEqual(readGoPayload(goPayload(limits)), limits, `go: ${label}`)
    } else if (Number.isInteger(frameMaxBytes)) {
      const raw = Buffer.alloc(8)
      raw.writeUInt32BE(frameMaxBytes, 0)
      raw.writeUInt32BE(maxFlows, 4)
      assert.equal(readGoPayload(Uint8Array.from(raw)), undefined, `go: ${label}`)
      assert.throws(() => goPayload(limits), `goPayload: ${label}`)
    }
  }
  assert.equal(readGoPayload(new Uint8Array(7)), undefined)
  assert.equal(readGoPayload(new Uint8Array(9)), undefined)
  // The whole of egress.limits may be handed to a kernel end: it reads only its two.
  const shipped = KernelConfig.parse(parseYaml(readFileSync(SHIPPED_CONFIG, 'utf8'))).egress.limits
  assert.deepEqual(new FrameChannel({ role: 'kernel', limits: shipped }).limits, { frameMaxBytes: 65_536, maxFlows: 16 })
})

test('a channel is made for one end: a kernel end holds limits from the start, a mux end takes none and learns them from go', () => {
  const limits = shippedLimits()
  assert.throws(() => new FrameChannel({ role: 'kernel' } as never))
  assert.throws(() => new FrameChannel({ role: 'mux', limits } as never))
  assert.throws(() => new FrameChannel({ role: 'worker' } as never))
  assert.throws(() => new FrameChannel({ role: 'kernel', limits: { frameMaxBytes: 0, maxFlows: 1 } }))
  const mux = new FrameChannel({ role: 'mux' })
  assert.equal(mux.limits, undefined)
  mux.send(frame('ready', 0, new Uint8Array(0)))
  assert.equal(mux.limits, undefined)
  mux.receive(encodeFrame(frame('go', 0, goPayload({ frameMaxBytes: 9, maxFlows: 3 }))))
  assert.deepEqual(mux.limits, { frameMaxBytes: 9, maxFlows: 3 })
  // The kernel end sends go as its own limits, and nothing else.
  const kernel = kernelEnd(limits)
  assert.equal(kernel.receive(encodeFrame(frame('ready', 0, new Uint8Array(READY_MAX_BYTES)))).error, undefined, 'a ready of READY_MAX_BYTES')
  assert.throws(() => kernel.send(frame('go', 0, goPayload({ ...limits, maxFlows: 17 }))), (e: unknown) => e instanceof FrameError && e.refusal === 'go-value')
  assert.equal(hexOf(kernel.send(frame('go', 0, goPayload(limits)))), hexOf(join(header(8, 0x02, 0), goPayload(limits))))
})

test('the frame writer and the small payloads check what they spell', () => {
  assert.throws(() => encodeFrame(frame('data', MAX_FLOW_ID + 1, text('x'))))
  assert.throws(() => encodeFrame(frame('data', -1, text('x'))))
  assert.throws(() => encodeFrame(frame('data', 1.5, text('x'))))
  assert.throws(() => encodeFrame({ type: 'push' as FrameType, flow: 1, payload: text('x') }))
  assert.throws(() => encodeFrame({ type: 'data', flow: 1, payload: 'x' as unknown as Uint8Array }))
  assert.throws(() => encodeFrame(frame('data', 1, new Uint8Array(FRAME_MAX_BYTES_LIMIT + 1))))
  assert.equal(encodeFrame(frame('data', 1, new Uint8Array(FRAME_MAX_BYTES_LIMIT))).length, FRAME_HEADER_BYTES + FRAME_MAX_BYTES_LIMIT)
  // A Buffer is bytes: a node stream's chunk is decoded as any Uint8Array.
  const channel = handshaken(shippedLimits())
  assert.equal(channel.receive(Buffer.from(encodeFrame(frame('stdout', 0, text('b'))))).frames.length, 1)
  assert.throws(() => channel.receive('x' as unknown as Uint8Array), /takes bytes/)

  assert.deepEqual([...exitPayload(0)], [0])
  assert.deepEqual([...exitPayload(137)], [137])
  assert.deepEqual([...exitPayload(255)], [255])
  for (const bad of [-1, 256, 1.5, Number.NaN]) assert.throws(() => exitPayload(bad), /exit status/)
})

test('a go payload is read where its view starts: readGoPayload and a kernel send of go, given a subarray of a larger buffer', () => {
  // A Buffer from Node's pool is a view of a shared ArrayBuffer at a byteOffset
  // that is not 0, and so is any subarray. The bytes around this view are
  // 0xff, so a read from the start of the buffer names frameMaxBytes 4 GiB,
  // which no go admits: the kernel would refuse its own go as go-value.
  const limits = shippedLimits()
  const pool = new Uint8Array(64).fill(0xff)
  pool.set(goPayload(limits), 23)
  const view = pool.subarray(23, 23 + 8)
  assert.equal(view.byteOffset, 23)
  assert.deepEqual(readGoPayload(view), limits)
  const kernel = kernelEnd(limits)
  assert.equal(kernel.receive(encodeFrame(frame('ready', 0))).error, undefined)
  assert.equal(kernel.sendRefusal(frame('go', 0, view)), undefined)
  assert.equal(hexOf(kernel.send(frame('go', 0, view))), hexOf(join(header(8, 0x02, 0), goPayload(limits))))
  // A pooled Buffer decodes the same, wherever in the pool it sits.
  assert.deepEqual(readGoPayload(Buffer.from(goPayload(limits))), limits)
  // And a view of a go out of range is still refused, not read past its end.
  const short = pool.subarray(23, 23 + 7)
  assert.equal(readGoPayload(short), undefined)
})

test('the limits a channel holds frames to are frozen: a cast past Readonly cannot raise the bound the decoder applies', () => {
  const limits = { frameMaxBytes: 4, maxFlows: 2 }
  const kernel = handshaken(limits)
  assert.ok(Object.isFrozen(kernel.limits), "the kernel end's limits")
  assert.throws(() => {
    ;(kernel.limits as { frameMaxBytes: number }).frameMaxBytes = FRAME_MAX_BYTES_LIMIT
  }, TypeError)
  assert.equal(kernel.receive(encodeFrame(frame('open', 1))).error, undefined)
  refusedWith(kernel, header(5, FRAME_TYPE_CODES.data, 1), 'oversize', 'the bound is still the one the channel was made with')
  assert.ok(Object.isFrozen(muxHandshaken(limits).limits), "the mux end's limits, from go")
  // The caller's object is copied, not frozen in place.
  const given = { frameMaxBytes: 4, maxFlows: 2 }
  kernelEnd(given)
  assert.equal(Object.isFrozen(given), false)
})

test('sendRefusal is what send would throw, asked without sending: a writer drops a frame on a flow the other end has closed', () => {
  const limits = shippedLimits()
  const channel = handshaken(limits)
  channel.receive(encodeFrame(frame('open', 1)))
  const data = frame('data', 1, text('response'))
  assert.equal(channel.sendRefusal(data), undefined)
  assert.equal(channel.sendRefusal(data), undefined, 'asking twice is the same answer')
  channel.send(data)
  // The worker dropped its connection mid-response: the mux's close arrives
  // while the session still has response bytes queued. That is a race, not
  // the kernel's bug: the writer asks, drops the bytes and sends its close.
  channel.receive(encodeFrame(frame('close', 1)))
  const before = snapshot(channel)
  const refusal = channel.sendRefusal(data)
  assert.ok(refusal instanceof FrameError)
  assert.equal(refusal.refusal, 'peer-closed')
  assertWording(refusal)
  assert.equal(channel.sendRefusal(frame('end', 1))?.refusal, 'peer-closed')
  assert.deepEqual(snapshot(channel), before, 'asking changes nothing')
  assert.equal(channel.failure, undefined, 'a refused send does not end the channel')
  assert.equal(channel.sendRefusal(frame('close', 1)), undefined)
  channel.send(frame('close', 1))
  assert.equal(channel.openFlows, 0)
  // A frame nobody can spell is the caller's error, as it is for send().
  assert.throws(() => channel.sendRefusal({ type: 'push' as FrameType, flow: 1, payload: text('x') }))
  // Once the channel has ended, the refusal that ended it, as send() throws.
  const failure = refusedWith(channel, header(0, 0x7f, 0), 'unknown-type', 'the channel ends')
  assert.equal(channel.sendRefusal(frame('data', 2, text('x'))), failure)
  assert.equal(channel.sendRefusal({ type: 'push' as FrameType, flow: 1, payload: text('x') }), failure)
})
