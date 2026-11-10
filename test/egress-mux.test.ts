// Egress plan E9 — the in-image mux (images/worker/mux.mjs).
//
// The mux is the container's end of the docker -i channel: it frames the
// worker's connections to 127.0.0.1:3128 and the command's output onto
// stdout, and the kernel's answers off stdin. It is no boundary (the agent
// shares its uid), so nothing here proves the kernel safe; what it proves is
// that an honest run works and says what it reached. The mux is wrong in
// these ways, each held here:
//
//   A codec that disagrees with frame.ts by one refusal is a channel the
//   kernel revokes in the middle of an honest run, or one the mux reads
//   past the point where it means anything. A self-test that reports a
//   reached host as unreached, or runs the command before the kernel's go,
//   is a container whose escape the kernel never hears of. A relay that
//   buffers instead of pausing grows without bound inside a capped
//   container; one that reads a cut as a clean end hands git a short pack as
//   whole. A mux that never exits holds every run until the wallclock.
//
// Everything is in-process: the channel is two in-memory streams whose
// kernel end is frame.ts's own FrameChannel (so every frame the mux writes is
// judged by the codec the kernel runs), the worker's connections are
// in-memory sockets (and, for the TCP-only behaviours, real loopback ones),
// and the command is a fake child (whose exit resumes its pipes, as node's
// does), but for two tests that run real processes through spawnCommand,
// which reach nothing: a shell, a sleep and an echo, to pin what node's
// spawn is given (spawnCommand's process group, no stdin, no shell, no cwd or
// identity of its own), and a perl whose setsid() writer outlives it, to
// show node's own resume of the pipes at the exit costs the mux one chunk.
// Nothing is resolved or dialled off the machine: the probes are injected
// wherever the mux runs.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { readFileSync, realpathSync } from 'node:fs'
import net from 'node:net'
import { Duplex, PassThrough, Writable } from 'node:stream'
import ts from 'typescript'
import { parse as parseYaml } from 'yaml'
import { z } from 'zod'

import * as mux from '../images/worker/mux.mjs'
import { KernelConfig } from '../src/config.js'
import {
  encodeFrame,
  FRAME_HEADER_BYTES,
  FRAME_MAX_BYTES_LIMIT,
  FRAME_REFUSALS,
  FRAME_RULES,
  FRAME_TYPE_CODES,
  FRAME_TYPES,
  FrameChannel,
  FrameError,
  goPayload,
  MAX_FLOW_ID,
  MAX_FLOWS_LIMIT,
  READY_MAX_BYTES,
  readGoPayload,
  type Frame,
  type FrameLimits,
  type FrameRefusal,
  type FrameType,
  type ReceivedFrame,
} from '../src/egress/frame.js'
import { EgressGrant } from '../src/egress/policy.js'
import { createEgressSession, type SessionLimits } from '../src/egress/session.js'
import { createUpstream } from '../src/egress/upstream.js'
import { withStore } from './helpers/store.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')
const MUX_SOURCE = readFileSync(`${REPO}/images/worker/mux.mjs`, 'utf8')

// ── bytes ────────────────────────────────────────────────────────────────────

function bytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '')
  assert.match(clean, /^(?:[0-9a-f]{2})*$/, `not hex: ${hex}`)
  return Uint8Array.from(Buffer.from(clean, 'hex'))
}

const hexOf = (data: Uint8Array): string => Buffer.from(data).toString('hex')
const text = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'utf8'))
const join = (...parts: readonly Uint8Array[]): Uint8Array => Uint8Array.from(Buffer.concat(parts))
const frame = (type: FrameType, flow: number, payload: Uint8Array = new Uint8Array(0)): Frame => ({ type, flow, payload })

/** A header spelt by hand, so a frame frame.ts would not spell can be sent. */
function header(length: number, code: number, flow: number): Uint8Array {
  const out = Buffer.alloc(FRAME_HEADER_BYTES)
  out.writeUInt32BE(length, 0)
  out.writeUInt8(code, 4)
  out.writeUInt32BE(flow, 5)
  return Uint8Array.from(out)
}

/** mulberry32, so a failing conversation is the same one on the next run. */
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

const pick = <T>(rng: () => number, items: readonly T[]): T => {
  const item = items[Math.floor(rng() * items.length)]
  if (item === undefined) throw new Error('pick from nothing')
  return item
}

type Split = 'as-given' | 'whole' | 'bytes' | 'random'
const SPLITS: readonly Split[] = ['as-given', 'whole', 'bytes', 'random']

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

interface Shown {
  readonly type: string
  readonly flow: number
  readonly payload: string
  readonly stale: boolean
}
const shown = (f: { readonly type: string; readonly flow: number; readonly payload: Uint8Array; readonly stale: boolean }): Shown => ({
  type: f.type,
  flow: f.flow,
  payload: hexOf(f.payload),
  stale: f.stale,
})

/** A few turns of the event loop: enough for bytes written to an in-memory stream to reach their reader. */
async function ticks(n = 10): Promise<void> {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve))
}

/** The mux's exit code, or a failure once `ms` pass: a mux that never exits fails here, never hangs the file. */
async function exits<T>(done: Promise<T>, what = 'the mux to exit', ms = 3_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out waiting for ${what}`)), ms)
  })
  try {
    return await Promise.race([done, timeout])
  } finally {
    clearTimeout(timer)
  }
}

async function until(condition: () => boolean, what: string, ms = 3_000): Promise<void> {
  const deadline = Date.now() + ms
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise((resolve) => setImmediate(resolve))
  }
}

// ── the shared vectors ───────────────────────────────────────────────────────

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
const VScript = z.strictObject({
  name: z.string().min(1),
  role: z.enum(['kernel', 'mux']),
  limits: z.strictObject({ frameMaxBytes: z.number().int(), maxFlows: z.number().int() }).optional(),
  steps: z.array(VStep).min(1),
})
type VScript = z.output<typeof VScript>
const Vectors = z.object({
  wire: z.strictObject({ headerBytes: z.number(), readyMaxBytes: z.number(), frameMaxBytesLimit: z.number(), maxFlowsLimit: z.number(), maxFlowId: z.number() }),
  types: z.record(z.enum(FRAME_TYPES), z.number().int()),
  frames: z.array(z.strictObject({ name: z.string().min(1), ...VFrame.shape, wire: VHex })).min(1),
  scripts: z.array(VScript).min(1),
})
const VECTORS = Vectors.parse(JSON.parse(readFileSync(new URL('./fixtures/egress-frame-vectors.json', import.meta.url), 'utf8')))
const MUX_SCRIPTS = VECTORS.scripts.filter((s) => s.role === 'mux')

const vframe = (f: z.output<typeof VFrame>): Frame => frame(f.type, f.flow, bytes(f.payload))

/**
 * Every refusal a mux end can meet, receiving (finish() included) and
 * sending, as test/egress-frame.test.ts MEETS.mux writes it out: the mux
 * scripts meet every one there, so a codec that replays them all is held to
 * every refusal a mux meets.
 */
const MUX_MEETS: Readonly<Record<'receive' | 'send', readonly FrameRefusal[]>> = {
  receive: [
    'unknown-type', 'direction', 'channel-flow', 'flow-zero', 'not-ready', 'go-twice', 'before-go', 'length', 'oversize',
    'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'go-value', 'truncated-header', 'truncated-payload',
  ],
  send: [
    'direction', 'channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'before-go', 'length', 'oversize',
    'after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close', 'after-end', 'peer-closed',
  ],
}

interface Snapshot {
  readonly openFlows: number
  readonly flowsOpened: number
  readonly limits: unknown
  readonly failure: string | undefined
}
const snapshot = (c: mux.MuxChannel): Snapshot => ({ openFlows: c.openFlows, flowsOpened: c.flowsOpened, limits: c.limits, failure: c.failure?.refusal })

/** Replay one mux script on the inline codec, every receive's pieces cut `how`; the refusals it met, each way. */
function replay(script: VScript, how: Split): { readonly side: 'receive' | 'send'; readonly refusal: string }[] {
  const channel = new mux.MuxChannel()
  const rng = prng(script.name.length * 7919)
  const met: { side: 'receive' | 'send'; refusal: string }[] = []
  script.steps.forEach((step, i) => {
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
        (e: unknown) => e instanceof mux.MuxFrameError && e.refusal === step.refusal,
        at,
      )
      assert.deepEqual(snapshot(channel), before, `${at}: a refused send changes nothing`)
      if (!ended) met.push({ side: 'send', refusal: step.refusal })
    } else if ('receive' in step) {
      const got: Shown[] = []
      let error: mux.MuxFrameError | undefined
      for (const piece of split(step.receive.map(bytes), how, rng)) {
        const result = channel.receive(piece)
        if (error !== undefined) {
          assert.deepEqual(result.frames, [], `${at}: nothing is decoded after a refusal`)
          assert.equal(result.error, error, `${at}: a refusal is final`)
          continue
        }
        got.push(...result.frames.map(shown))
        error = result.error
      }
      assert.deepEqual(got, step.frames.map((f) => shown({ ...f, payload: bytes(f.payload) })), at)
      assert.equal(error?.refusal, step.refusal, `${at}: ${error?.message ?? 'no refusal'}`)
      if (error !== undefined && !ended) met.push({ side: 'receive', refusal: error.refusal })
    } else {
      const error = channel.finish()
      assert.equal(error?.refusal, step.refusal, `${at}: ${error?.message ?? 'no refusal'}`)
      if (error !== undefined && !ended) met.push({ side: 'receive', refusal: error.refusal })
      assert.throws(() => channel.receive(new Uint8Array(0)), TypeError, `${at}: receive() after finish() is the caller's error`)
    }
    if (step.openFlows !== undefined) assert.equal(channel.openFlows, step.openFlows, `${at}: openFlows`)
    if (step.flowsOpened !== undefined) assert.equal(channel.flowsOpened, step.flowsOpened, `${at}: flowsOpened`)
  })
  return met
}

test('it matches src/egress/frame.ts on the shared vectors', () => {
  // The constants are frame.ts's and the file's: a change to one end without
  // the other fails here.
  assert.deepEqual(VECTORS.wire, {
    headerBytes: mux.FRAME_HEADER_BYTES,
    readyMaxBytes: mux.READY_MAX_BYTES,
    frameMaxBytesLimit: mux.FRAME_MAX_BYTES_LIMIT,
    maxFlowsLimit: mux.MAX_FLOWS_LIMIT,
    maxFlowId: mux.MAX_FLOW_ID,
  })
  assert.deepEqual(
    [mux.FRAME_HEADER_BYTES, mux.READY_MAX_BYTES, mux.FRAME_MAX_BYTES_LIMIT, mux.MAX_FLOWS_LIMIT, mux.MAX_FLOW_ID],
    [FRAME_HEADER_BYTES, READY_MAX_BYTES, FRAME_MAX_BYTES_LIMIT, MAX_FLOWS_LIMIT, MAX_FLOW_ID],
  )
  assert.deepEqual(VECTORS.types, mux.FRAME_TYPE_CODES)
  assert.deepEqual(mux.FRAME_TYPE_CODES, FRAME_TYPE_CODES)
  assert.deepEqual([...mux.FRAME_TYPES], [...FRAME_TYPES])
  assert.deepEqual([...mux.FRAME_REFUSALS], [...FRAME_REFUSALS])
  for (const type of FRAME_TYPES) {
    const ours = mux.FRAME_RULES[type]
    const theirs = FRAME_RULES[type]
    assert.deepEqual(
      { from: [...ours.from], channel: ours.channel, min: ours.minBytes, max: ours.maxBytes },
      { from: [...theirs.from], channel: theirs.channel, min: theirs.minBytes, max: theirs.maxBytes },
      type,
    )
  }

  // Every frame spelt as the wire spells it, by both codecs.
  for (const v of VECTORS.frames) {
    assert.equal(hexOf(mux.encodeFrame(vframe(v))), hexOf(bytes(v.wire)), v.name)
    assert.equal(hexOf(mux.encodeFrame(vframe(v))), hexOf(encodeFrame(vframe(v))), v.name)
    if (v.type === 'go') assert.deepEqual(mux.readGoPayload(bytes(v.payload)), readGoPayload(bytes(v.payload)), v.name)
  }

  // Every mux script, each receive fed as given, whole, a byte at a time and
  // in random pieces, and the refusals met are every one a mux end can meet.
  assert.ok(MUX_SCRIPTS.length > 50, `only ${String(MUX_SCRIPTS.length)} mux scripts`)
  const met = { receive: new Set<string>(), send: new Set<string>() }
  for (const script of MUX_SCRIPTS) {
    for (const how of SPLITS) for (const { side, refusal } of replay(script, how)) met[side].add(refusal)
  }
  assert.deepEqual([...met.receive].sort(), [...MUX_MEETS.receive].sort(), 'receive')
  assert.deepEqual([...met.send].sort(), [...MUX_MEETS.send].sort(), 'send')
})

test("the inline codec agrees with frame.ts's mux end on random conversations, received in random pieces", () => {
  // The vectors pin each refusal and each place two meet; this runs the two
  // codecs side by side through states the scripts do not list (the cap
  // under other limits, retired flows, stale frames, exit with flows open),
  // so a rule the inline copy spells differently shows wherever it bites.
  const rng = prng(0xe9e9)
  const types = [...FRAME_TYPES]
  let compared = 0
  for (let round = 0; round < 600; round++) {
    const theirs = new FrameChannel({ role: 'mux' })
    const ours = new mux.MuxChannel()
    let readySent = false
    const steps = 1 + Math.floor(rng() * 50)
    for (let step = 0; step < steps; step++) {
      const at = `round ${String(round)} step ${String(step)}`
      const limits = theirs.limits
      const flows = theirs.flowsOpened
      const anyFlow = (): number => (rng() < 0.9 ? 1 + Math.floor(rng() * Math.max(1, flows)) : pick(rng, [0, flows + 1, flows + 2]))
      const size = (): number => pick(rng, [0, 1, 2, limits?.frameMaxBytes ?? 3, (limits?.frameMaxBytes ?? 3) + 1, 5])
      const r = rng()
      if (r < 0.45) {
        // The mux sends.
        let f: Frame
        if (!readySent && rng() < 0.8) f = frame('ready', 0, text('{}'))
        else {
          const type = rng() < 0.85 ? pick(rng, ['open', 'data', 'end', 'close', 'stdout', 'stderr', 'exit'] as const) : pick(rng, types)
          const flow = type === 'open' ? (rng() < 0.85 ? flows + 1 : anyFlow()) : FRAME_RULES[type].channel ? (rng() < 0.9 ? 0 : 1) : anyFlow()
          const length = type === 'exit' ? (rng() < 0.9 ? 1 : pick(rng, [0, 2])) : type === 'open' || type === 'end' || type === 'close' ? (rng() < 0.9 ? 0 : 1) : size()
          f = frame(type, flow, new Uint8Array(length))
        }
        const a = theirs.sendRefusal(f)
        const b = ours.sendRefusal(f)
        assert.equal(b?.refusal, a?.refusal, `${at}: sendRefusal of ${f.type} on ${String(f.flow)}`)
        if (a === undefined) {
          assert.equal(hexOf(ours.send(f)), hexOf(theirs.send(f)), at)
          if (f.type === 'ready') readySent = true
        } else {
          assert.throws(() => theirs.send(f), FrameError)
          assert.throws(() => ours.send(f), (e: unknown) => e instanceof mux.MuxFrameError && e.refusal === a.refusal, at)
        }
      } else if (r < 0.97) {
        // The kernel sends a few frames, mostly ones a kernel would.
        const parts: Uint8Array[] = []
        const count = 1 + Math.floor(rng() * 3)
        for (let i = 0; i < count; i++) {
          const k = rng()
          if (k < 0.04) parts.push(header(Math.floor(rng() * 3), pick(rng, [0x00, 0x03, 0x14, 0x23, 0xff]), 0))
          else if (k < 0.08) parts.push(header(4, FRAME_TYPE_CODES.data, 1).subarray(0, 1 + Math.floor(rng() * 8)))
          else if (limits === undefined && k < 0.6) {
            const payload = rng() < 0.85 ? goPayload({ frameMaxBytes: 1 + Math.floor(rng() * 4), maxFlows: 1 + Math.floor(rng() * 3) }) : new Uint8Array(rng() < 0.5 ? 8 : 7)
            parts.push(encodeFrame(frame('go', rng() < 0.95 ? 0 : 1, payload)))
          } else {
            const type = rng() < 0.85 ? pick(rng, ['data', 'end', 'close'] as const) : pick(rng, types)
            const flow = FRAME_RULES[type].channel ? (rng() < 0.9 ? 0 : 1) : anyFlow()
            const length = type === 'data' ? size() : type === 'go' ? 8 : rng() < 0.9 ? 0 : 1
            parts.push(encodeFrame(frame(type, flow, new Uint8Array(length))))
          }
        }
        for (const piece of split(parts, 'random', rng)) {
          if (theirs.failure !== undefined && rng() < 0.5) break
          const a = theirs.receive(piece)
          const b = ours.receive(piece)
          assert.deepEqual(b.frames.map(shown), a.frames.map(shown), `${at}: frames`)
          assert.equal(b.error?.refusal, a.error?.refusal, `${at}: ${a.error?.message ?? 'no refusal'}`)
        }
      } else {
        assert.equal(ours.finish()?.refusal, theirs.finish()?.refusal, `${at}: finish`)
        break
      }
      assert.deepEqual(
        { openFlows: ours.openFlows, flowsOpened: ours.flowsOpened, limits: ours.limits === undefined ? undefined : { ...ours.limits }, failure: ours.failure?.refusal },
        { openFlows: theirs.openFlows, flowsOpened: theirs.flowsOpened, limits: theirs.limits === undefined ? undefined : { ...theirs.limits }, failure: theirs.failure?.refusal },
        `${at}: state`,
      )
      compared++
    }
  }
  assert.ok(compared > 5_000, `only ${String(compared)} steps compared`)
})

// ── the relay's fakes ────────────────────────────────────────────────────────

/** A writable whose callbacks can be held, so a write past its high-water mark returns false, as a full pipe does. */
class Sink extends Writable {
  readonly #onChunk: (chunk: Buffer) => void
  #held = false
  readonly #pending: (() => void)[] = []

  constructor(onChunk: (chunk: Buffer) => void, highWaterMark = 16_384) {
    super({ highWaterMark })
    this.#onChunk = onChunk
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.#onChunk(chunk)
    if (this.#held) this.#pending.push(() => callback())
    else callback()
  }

  hold(): void {
    this.#held = true
  }

  release(): void {
    this.#held = false
    for (const callback of this.#pending.splice(0)) callback()
  }
}

/** The kernel's end of the channel: frame.ts's own codec judges every byte the mux writes. */
class KernelEnd {
  readonly toMux = new PassThrough()
  readonly fromMux: Sink
  readonly codec: FrameChannel
  readonly frames: ReceivedFrame[] = []
  error: FrameError | undefined

  constructor(limits: FrameLimits, highWaterMark?: number) {
    this.codec = new FrameChannel({ role: 'kernel', limits })
    this.fromMux = new Sink((chunk) => {
      const result = this.codec.receive(chunk)
      this.frames.push(...result.frames)
      this.error ??= result.error
    }, highWaterMark)
  }

  send(f: Frame): void {
    this.toMux.write(this.codec.send(f))
  }

  /** The kernel's data on a flow, cut to the frameMaxBytes it named, as the session cuts it; the frames' bytes, unsent. */
  dataFrames(flow: number, s: string): Uint8Array {
    const max = this.codec.limits?.frameMaxBytes ?? 1
    const all = text(s)
    const out: Uint8Array[] = []
    for (let at = 0; at < all.length; at += max) out.push(this.codec.send(frame('data', flow, all.subarray(at, at + max))))
    return join(...out)
  }

  sendData(flow: number, s: string): void {
    this.toMux.write(this.dataFrames(flow, s))
  }

  go(): void {
    const limits = this.codec.limits
    if (limits === undefined) throw new Error('a kernel end holds its limits')
    this.send(frame('go', 0, goPayload(limits)))
  }

  of(type: FrameType, flow?: number): ReceivedFrame[] {
    return this.frames.filter((f) => f.type === type && (flow === undefined || f.flow === flow))
  }

  dataOn(flow: number): string {
    return Buffer.concat(this.of('data', flow).map((f) => f.payload)).toString('utf8')
  }

  output(type: 'stdout' | 'stderr'): string {
    return Buffer.concat(this.of(type).map((f) => f.payload)).toString('utf8')
  }

  report(): unknown {
    const ready = this.of('ready')[0]
    assert.ok(ready !== undefined, 'the mux sent ready')
    return JSON.parse(Buffer.from(ready.payload).toString('ascii'))
  }
}

/** The mux's end of one worker connection, and the worker's hands on it. */
class FakeSocket extends Duplex {
  readonly written: Buffer[] = []
  /** The mux ended its side: the worker read a FIN. */
  finished = false
  /** The mux reset the connection: the worker read an RST. */
  wasReset = false
  #held = false
  readonly #pending: (() => void)[] = []

  constructor(writableHighWaterMark = 16_384) {
    super({ allowHalfOpen: true, writableHighWaterMark })
  }

  override _read(): void {}

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.written.push(chunk)
    if (this.#held) this.#pending.push(() => callback())
    else callback()
  }

  override _final(callback: (error?: Error | null) => void): void {
    this.finished = true
    callback()
  }

  resetAndDestroy(): this {
    this.wasReset = true
    this.destroy()
    return this
  }

  /** The worker stops reading what the mux writes. */
  hold(): void {
    this.#held = true
  }

  release(): void {
    this.#held = false
    for (const callback of this.#pending.splice(0)) callback()
  }

  say(s: string): void {
    this.push(Buffer.from(s, 'utf8'))
  }

  /** The worker's FIN. */
  fin(): void {
    this.push(null)
  }

  received(): string {
    return Buffer.concat(this.written).toString('utf8')
  }
}

/**
 * The command, as the mux sees it: two pipes, the three events node's
 * ChildProcess emits, and a group to kill. Its exit does what node's does:
 * 'exit', then, on the next tick, a resume() of every pipe still readable
 * (child_process's flushStdio), whatever the mux paused.
 */
class FakeChild extends EventEmitter {
  readonly stdout = new PassThrough()
  readonly stderr = new PassThrough()
  kills = 0

  killTree(): void {
    this.kills++
  }

  /** The command exits, and something it started outside its group still holds its pipes: 'exit', and no 'close'. */
  exitHeld(code: number | null, signal: string | null = null): void {
    this.emit('exit', code, signal)
    this.#flushStdio()
  }

  /** The command exits: 'exit', then its pipes close once read, then 'close'. */
  exit(code: number | null, signal: string | null = null): void {
    this.emit('exit', code, signal)
    this.#flushStdio()
    let open = 2
    const closed = (): void => {
      open--
      if (open === 0) this.emit('close', code, signal)
    }
    this.stdout.once('end', closed)
    this.stderr.once('end', closed)
    this.stdout.end()
    this.stderr.end()
  }

  /** node's onexit: process.nextTick(flushStdio), which resumes each stdio stream that is still readable. */
  #flushStdio(): void {
    process.nextTick(() => {
      for (const pipe of [this.stdout, this.stderr]) if (pipe.readable) pipe.resume()
    })
  }
}

const NO_ROUTE: mux.ConnectProbe = () => Promise.resolve({ reached: false, error: 'ENETUNREACH' })
const NO_DNS: mux.LookupProbe = () => Promise.resolve({ reached: false, error: 'EAI_AGAIN' })

interface RunOptions {
  readonly limits?: FrameLimits
  readonly outputHighWaterMark?: number
  readonly connect?: mux.ConnectProbe
  readonly lookup?: mux.LookupProbe
  readonly probeTimeoutMs?: number
  readonly listen?: mux.Listen
  readonly spawn?: mux.Spawn
  readonly command?: string
  readonly args?: readonly string[]
  readonly flushTimeoutMs?: number
  readonly exitGraceMs?: number
  readonly exitGraceMaxMs?: number
}

interface Run {
  readonly kernel: KernelEnd
  readonly child: FakeChild
  readonly done: Promise<number>
  readonly listens: { host: string; port: number }[]
  readonly spawned: (readonly [string, readonly string[]])[]
  readonly listener: { closed: boolean }
  readonly diagnostics: () => string
  /** A worker connects to 127.0.0.1:3128. */
  connect(socket?: FakeSocket): FakeSocket
}

function start(o: RunOptions = {}): Run {
  const kernel = new KernelEnd(o.limits ?? { frameMaxBytes: 4, maxFlows: 2 }, o.outputHighWaterMark)
  const child = new FakeChild()
  const listens: { host: string; port: number }[] = []
  const spawned: (readonly [string, readonly string[]])[] = []
  const listener = { closed: false }
  let accept: ((socket: Duplex) => void) | undefined
  let complaints = ''
  const diagnostics = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      complaints += chunk.toString('utf8')
      callback()
    },
  })
  const done = mux.runMux({
    input: kernel.toMux,
    output: kernel.fromMux,
    diagnostics,
    command: o.command ?? 'git',
    args: o.args ?? ['clone', 'http://github.com/op/fixture.git'],
    connect: o.connect ?? NO_ROUTE,
    lookup: o.lookup ?? NO_DNS,
    probeTimeoutMs: o.probeTimeoutMs ?? 1_000,
    flushTimeoutMs: o.flushTimeoutMs ?? 1_000,
    exitGraceMs: o.exitGraceMs ?? 1_000,
    // Past every wait below: a test that reaches it names its own.
    exitGraceMaxMs: o.exitGraceMaxMs ?? 10_000,
    listen:
      o.listen ??
      ((host, port, onConnection) => {
        listens.push({ host, port })
        accept = onConnection
        return Promise.resolve({ host, port, close: () => void (listener.closed = true) })
      }),
    spawn:
      o.spawn ??
      ((command, args) => {
        spawned.push([command, args])
        return child
      }),
  })
  return {
    kernel,
    child,
    done,
    listens,
    spawned,
    listener,
    diagnostics: () => complaints,
    connect(socket = new FakeSocket()) {
      assert.ok(accept !== undefined, 'the mux is listening')
      accept(socket)
      return socket
    },
  }
}

/** Run to the point where the command is running: ready read, go sent, listening, spawned. */
async function running(o: RunOptions = {}): Promise<Run> {
  const run = start(o)
  await until(() => run.kernel.of('ready').length === 1, 'ready')
  run.kernel.go()
  await until(() => run.spawned.length === 1, 'the command to be spawned')
  return run
}

// ── the relay ────────────────────────────────────────────────────────────────

test('the mux relays two flows over one channel, honours backpressure and exits on stdin EOF', async () => {
  const run = start({ limits: { frameMaxBytes: 4, maxFlows: 2 }, outputHighWaterMark: 16 })
  const { kernel, child } = run
  await until(() => kernel.of('ready').length === 1, 'ready')
  // Nothing runs before go: not the listener, not the command.
  await ticks()
  assert.deepEqual(run.listens, [])
  assert.deepEqual(run.spawned, [])
  kernel.go()
  await until(() => run.spawned.length === 1, 'the command')
  assert.deepEqual(run.listens, [{ host: '127.0.0.1', port: 3128 }], 'it listens on the container loopback, port 3128, only')
  assert.deepEqual(run.spawned, [['git', ['clone', 'http://github.com/op/fixture.git']]])

  // Two connections, two flows, numbered in order.
  const a = run.connect()
  const b = run.connect(new FakeSocket(8))
  await ticks()
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1, 2])
  a.say('GET http://a.example/ HTTP/1.1\r\n\r\n')
  b.say('GET http://b.example/ HTTP/1.1\r\n\r\n')
  await ticks()
  assert.equal(kernel.dataOn(1), 'GET http://a.example/ HTTP/1.1\r\n\r\n')
  assert.equal(kernel.dataOn(2), 'GET http://b.example/ HTTP/1.1\r\n\r\n')
  assert.ok(kernel.of('data').every((f) => f.payload.length <= 4), 'every data frame is at most the frameMaxBytes go named')

  // The kernel's answers reach their sockets.
  kernel.send(frame('data', 1, text('HTTP')))
  kernel.send(frame('data', 2, text('HTTP')))
  await ticks()
  assert.equal(a.received(), 'HTTP')
  assert.equal(b.received(), 'HTTP')

  // Backpressure from a worker: b stops reading, and once its socket is past
  // its high-water mark the mux stops reading the channel, so a's next frame
  // waits behind b's, unread: nobody buffers a flow without bound.
  b.hold()
  kernel.toMux.write(kernel.dataFrames(2, '/1.1 200 OK\r\n'))
  await ticks()
  assert.equal(kernel.toMux.isPaused(), true, 'the mux stopped reading stdin')
  kernel.send(frame('data', 1, text('/1.1')))
  await ticks()
  assert.equal(a.received(), 'HTTP', "a's frame waits while b is full")
  b.release()
  await ticks()
  assert.equal(kernel.toMux.isPaused(), false, 'b drained, so the mux reads stdin again')
  assert.equal(a.received(), 'HTTP/1.1')
  assert.equal(b.received(), 'HTTP/1.1 200 OK\r\n')

  // Backpressure from the kernel: stdout is full, so every flow's socket and
  // the command's pipes are paused, and what the worker writes waits in its
  // socket rather than in the mux.
  kernel.fromMux.hold()
  a.say('0123456789abcdefghijklmnopqrstuvwxyz')
  await ticks()
  assert.equal(a.isPaused(), true, "a's socket is paused")
  assert.equal(b.isPaused(), true, "b's socket is paused")
  assert.equal(child.stdout.isPaused(), true, "the command's stdout is paused")
  assert.equal(child.stderr.isPaused(), true, "the command's stderr is paused")
  const framesWhileFull = kernel.frames.length
  b.say('more from b')
  child.stdout.write('compiling\n')
  child.stderr.write('warning: slow\n')
  await ticks()
  assert.equal(kernel.frames.length, framesWhileFull, 'nothing new is framed while stdout is full')
  kernel.fromMux.release()
  await ticks()
  assert.equal(a.isPaused(), false)
  assert.equal(kernel.dataOn(1), 'GET http://a.example/ HTTP/1.1\r\n\r\n0123456789abcdefghijklmnopqrstuvwxyz')
  assert.equal(kernel.dataOn(2), 'GET http://b.example/ HTTP/1.1\r\n\r\nmore from b')
  assert.equal(kernel.output('stdout'), 'compiling\n')
  // The command's stderr is read again too: a stderr left paused would fill
  // its pipe, and the command would block on it, never exit, and hold the
  // container until the wallclock.
  await until(() => kernel.output('stderr') === 'warning: slow\n', "the command's stderr, framed once stdout drained")
  await ticks()
  assert.equal(child.stdout.isPaused(), false, "the command's stdout is read again")
  assert.equal(child.stderr.isPaused(), false, "the command's stderr is read again")

  // The kernel ends flow 1 cleanly: a reads a FIN, the mux closes the flow at
  // once (only its close may follow the kernel's), and the socket lingers
  // until the worker closes it. The kernel cuts flow 2: b reads a reset.
  kernel.send(frame('end', 1))
  kernel.send(frame('close', 1))
  kernel.send(frame('close', 2))
  await ticks()
  assert.equal(a.finished, true, 'a read a FIN')
  assert.equal(a.wasReset, false)
  assert.equal(b.wasReset, true, 'b read a reset, not a short answer as whole')
  assert.equal(b.finished, false, 'a cut flow is never ended')
  assert.deepEqual(kernel.of('close').map((f) => f.flow).sort(), [1, 2])
  assert.equal(kernel.codec.openFlows, 0, 'both flows retired')
  a.say('late bytes')
  await ticks()
  assert.equal(kernel.dataOn(1).endsWith('late bytes'), false, 'nothing is framed on a retired flow')

  // stdin ends while the command still runs: the mux kills it and exits, and
  // sends no exit frame (the kernel ended the channel).
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.ok(child.kills >= 1, "the command's group was killed")
  assert.equal(run.listener.closed, true)
  assert.deepEqual(kernel.of('exit'), [])
  assert.equal(kernel.error, undefined, 'the kernel refused nothing the mux sent')
  assert.equal(run.diagnostics(), '')
})

test('a worker that goes away while the mux waits on it no longer holds stdin, and its flow is closed as a cut', async () => {
  const run = await running({ limits: { frameMaxBytes: 4, maxFlows: 2 } })
  const { kernel } = run
  const a = run.connect()
  const b = run.connect(new FakeSocket(4))
  await ticks()
  b.hold()
  kernel.toMux.write(kernel.dataFrames(2, 'a long answer b never reads'))
  await ticks()
  assert.equal(kernel.toMux.isPaused(), true, 'b is full, so stdin waits')
  // b's worker is gone before the kernel says anything more of flow 2.
  b.destroy()
  await ticks()
  assert.equal(kernel.toMux.isPaused(), false, 'a socket that closed holds stdin no longer')
  assert.equal(kernel.of('close', 2).length, 1, "the mux's close for the flow b left")
  assert.equal(kernel.of('end', 2).length, 0, 'with no end before it: a cut, not a finished request')
  kernel.sendData(1, 'still served')
  await ticks()
  assert.equal(a.received(), 'still served')
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

test('a socket the kernel finished while it was full no longer holds stdin, and other flows are served', async () => {
  const run = await running({ limits: { frameMaxBytes: 4, maxFlows: 2 } })
  const { kernel } = run
  const a = run.connect()
  const b = run.connect(new FakeSocket(4))
  await ticks()
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1, 2])
  // b's worker stops reading, and the kernel's last data for b, its end and
  // its close arrive in one chunk: the data fills b and stops the mux reading
  // stdin, then the close retires the flow. No more of the kernel's data can
  // come for b, so b must hold stdin no longer, though it is still full: one
  // worker that stopped reading must not stall every other flow.
  b.hold()
  kernel.toMux.write(join(kernel.dataFrames(2, 'the whole answer for b'), kernel.codec.send(frame('end', 2)), kernel.codec.send(frame('close', 2))))
  await ticks()
  assert.equal(kernel.of('close', 2).length, 1, "the mux's close crossed")
  assert.equal(kernel.codec.openFlows, 1, 'flow 2 retired')
  assert.equal(b.writableLength > 0, true, 'b is still full')
  assert.equal(kernel.toMux.isPaused(), false, 'a socket whose flow retired holds stdin no longer')
  kernel.sendData(1, 'ok')
  await ticks()
  assert.equal(a.received(), 'ok', 'flow 1 is served while b sits full')
  // b's worker reads again: the whole answer, then the FIN.
  b.release()
  await ticks()
  assert.equal(b.received(), 'the whole answer for b')
  assert.equal(b.finished, true)
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

test("a stdin that ends behind a full socket is not read until the socket drains: closing the channel alone does not end that run", async () => {
  // What mux.mjs's header says W1 must know: the end of stdin is seen only
  // when the mux reads it, and a socket that cannot take the kernel's data
  // stops it reading. A run whose worker stopped reading is ended by the
  // kernel's kill of the container by name, not by closing the channel.
  const run = await running({ limits: { frameMaxBytes: 4, maxFlows: 2 } })
  const { kernel, child } = run
  const b = run.connect(new FakeSocket(4))
  await ticks()
  b.hold()
  kernel.sendData(1, 'an answer b does not read')
  kernel.toMux.end()
  let settled = false
  void run.done.then(() => (settled = true))
  await new Promise((resolve) => setTimeout(resolve, 50))
  assert.equal(kernel.toMux.isPaused(), true, 'stdin is unread behind b')
  assert.equal(settled, false, "the channel's end is not seen")
  assert.equal(child.kills, 0, 'and the command still runs')
  b.release()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok, 'once b drains, the end is read and the mux exits')
  assert.ok(child.kills >= 1)
  assert.equal(b.received(), 'an answer b does not read')
})

test("the command's output and exit are framed; after exit no flow opens, and the mux exits once every flow retires", async () => {
  const run = await running({ limits: { frameMaxBytes: 4, maxFlows: 2 } })
  const { kernel, child } = run
  const a = run.connect()
  await ticks()
  child.stdout.write('0123456789')
  child.stderr.write('warning\n')
  await ticks()
  assert.equal(kernel.output('stdout'), '0123456789')
  assert.ok(kernel.of('stdout').every((f) => f.payload.length <= 4))
  assert.equal(kernel.output('stderr'), 'warning\n')

  // The command exits with a flow still open: its status crosses once its
  // pipes have closed, its group is killed, and the listener closes.
  let settled = false
  void run.done.then(() => (settled = true))
  child.exit(3)
  await until(() => kernel.of('exit').length === 1, 'the exit frame')
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [3])
  assert.ok(child.kills >= 1, "what the command left behind is killed when it exits")
  assert.equal(run.listener.closed, true)
  const late = run.connect()
  await ticks()
  assert.equal(late.destroyed, true, 'a connection after exit is refused')
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1])

  // The open flow still finishes, and only then does the mux exit.
  a.say('GET / HTTP/1.1\r\n\r\n')
  a.fin()
  await ticks()
  assert.equal(kernel.of('end', 1).length, 1, "the worker's FIN is an end")
  kernel.sendData(1, 'HTTP/1.1 403\r\n\r\n')
  kernel.send(frame('end', 1))
  await ticks()
  assert.equal(settled, false, 'the mux waits on the open flow')
  assert.equal(a.received(), 'HTTP/1.1 403\r\n\r\n')
  kernel.send(frame('close', 1))
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.codec.openFlows, 0)
  assert.equal(kernel.error, undefined)
})

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

test('pipes a descendant holds open after the command exits are closed after the exit grace, and the status still crosses; a full stdout stops the grace\'s clock', async () => {
  // The group kill reaches nothing that left the group (setsid, a shell with
  // job control). Such a descendant holding the pipes would hold back 'close',
  // the exit frame and the mux's own exit until the kernel's wallclock.
  const run = await running({ exitGraceMs: 60 })
  const { kernel, child } = run
  child.stdout.write('started a daemon\n')
  await ticks()
  const exitedAt = Date.now()
  child.exitHeld(0)
  await ticks()
  assert.ok(child.kills >= 1, "the command's group is killed when it exits")
  assert.deepEqual(kernel.of('exit'), [], 'no status while the pipes may still carry output')
  child.stderr.write('a last word inside the grace\n')
  await until(() => kernel.of('exit').length === 1, 'the exit frame after the grace')
  const waited = Date.now() - exitedAt
  assert.ok(waited >= 50, `the status crossed ${String(waited)} ms after the exit, inside the grace`)
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [0])
  assert.deepEqual([child.stdout.destroyed, child.stderr.destroyed], [true, true], 'the pipes are closed: what holds them writes to nothing')
  assert.equal(kernel.output('stdout'), 'started a daemon\n')
  assert.equal(kernel.output('stderr'), 'a last word inside the grace\n')
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok, 'with no flow open, the mux exits')
  assert.equal(kernel.error, undefined)

  // While stdout is full the mux leaves the pipes unread itself: the grace's
  // clock does not run then, and runs once stdout drains, so a slow kernel
  // costs no output. Full before the exit:
  const slow = await running({ exitGraceMs: 30, outputHighWaterMark: 16 })
  slow.kernel.fromMux.hold()
  slow.child.stderr.write('0123456789abcdef')
  await ticks()
  slow.child.exitHeld(1)
  await sleep(120)
  assert.deepEqual([slow.child.stdout.destroyed, slow.child.stderr.destroyed], [false, false], 'the grace does not end while stdout is full')
  slow.child.stderr.write('written after the exit\n')
  slow.kernel.fromMux.release()
  await until(() => slow.kernel.of('exit').length === 1, 'the exit frame once stdout drained and the grace ran')
  assert.deepEqual([...(slow.kernel.of('exit')[0]?.payload ?? [])], [1])
  assert.equal(slow.kernel.output('stderr'), '0123456789abcdefwritten after the exit\n', 'nothing the command wrote is lost')
  assert.deepEqual([slow.child.stdout.destroyed, slow.child.stderr.destroyed], [true, true])
  assert.equal(await exits(slow.done), mux.MUX_EXIT.ok)
  assert.equal(slow.kernel.error, undefined)

  // And full only once the grace is under way: its clock stops there.
  const later = await running({ exitGraceMs: 60, outputHighWaterMark: 16 })
  later.child.exitHeld(2)
  await ticks()
  later.kernel.fromMux.hold()
  later.child.stderr.write('0123456789abcdef')
  await sleep(200)
  assert.deepEqual([later.child.stdout.destroyed, later.child.stderr.destroyed], [false, false], 'stdout filled inside the grace: the clock stopped there')
  later.child.stderr.write('and more\n')
  later.kernel.fromMux.release()
  await until(() => later.kernel.of('exit').length === 1, 'the exit frame once the clock ran on')
  assert.deepEqual([...(later.kernel.of('exit')[0]?.payload ?? [])], [2])
  assert.equal(later.kernel.output('stderr'), '0123456789abcdefand more\n')
  assert.equal(await exits(later.done), mux.MUX_EXIT.ok)
  assert.equal(later.kernel.error, undefined)
})

test("the grace's clock runs on from where it stopped: a descendant that fills stdout more often than the grace lasts does not hold the status back", async () => {
  // Restarted from zero at every drain, a grace of 100 ms never ends while
  // stdout drains every 80 ms; counted, its 40 ms spans of a stdout that
  // takes frames add up to it in three.
  const run = await running({ exitGraceMs: 100, outputHighWaterMark: 16 })
  const { kernel, child } = run
  const exitedAt = Date.now()
  child.exitHeld(0)
  const deadline = exitedAt + 2_500
  while (kernel.of('exit').length === 0 && Date.now() < deadline) {
    await sleep(40)
    if (child.stderr.destroyed) break
    kernel.fromMux.hold()
    child.stderr.write('0123456789abcdef')
    await sleep(40)
    kernel.fromMux.release()
  }
  await until(() => kernel.of('exit').length === 1, 'the exit frame', 500)
  const waited = Date.now() - exitedAt
  assert.ok(waited < 2_000, `the status crossed ${String(waited)} ms after the exit`)
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [0])
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

test('the grace ends EXIT_GRACE_MAX_MS after the exit, full stdout or not: a stdout that stays full holds the status back no longer', async () => {
  assert.ok(mux.EXIT_GRACE_MAX_MS > mux.EXIT_GRACE_MS)
  const run = await running({ exitGraceMs: 30, exitGraceMaxMs: 150, outputHighWaterMark: 16 })
  const { kernel, child } = run
  kernel.fromMux.hold()
  child.stderr.write('0123456789abcdef')
  await ticks()
  const exitedAt = Date.now()
  child.exitHeld(3)
  await sleep(60)
  assert.deepEqual([child.stdout.destroyed, child.stderr.destroyed], [false, false], 'inside the bound, a full stdout stops the clock')
  await until(() => child.stdout.destroyed && child.stderr.destroyed, 'the pipes to close at the bound', 1_500)
  const waited = Date.now() - exitedAt
  assert.ok(waited >= 140, `the pipes closed ${String(waited)} ms after the exit, before the bound`)
  // The exit frame is written behind what stdout still holds, and arrives once the kernel reads again.
  kernel.fromMux.release()
  await until(() => kernel.of('exit').length === 1, 'the exit frame')
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [3])
  assert.equal(kernel.output('stderr'), '0123456789abcdef')
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

test("node's resume of the command's pipes at its exit lasts one chunk under a full stdout: what a descendant writes then fills its pipe, not the mux", async () => {
  // node's child_process resumes a command's stdout and stderr on the tick
  // after it exits (flushStdio), whatever the mux paused. The mux pauses them
  // again at the next frame stdout refuses, so at most one chunk of each
  // crosses into stdout's buffer before the kernel reads again.
  const chunk = 1_024
  const framed = chunk + FRAME_HEADER_BYTES
  const run = await running({ limits: { frameMaxBytes: chunk, maxFlows: 2 }, outputHighWaterMark: chunk, exitGraceMs: 50 })
  const { kernel, child } = run
  kernel.fromMux.hold()
  child.stdout.write(Buffer.alloc(4 * chunk, 0x61))
  await ticks()
  assert.deepEqual([child.stdout.isPaused(), child.stderr.isPaused()], [true, true], 'a full stdout pauses the pipes')
  const before = kernel.fromMux.writableLength
  child.exitHeld(0)
  await ticks()
  assert.deepEqual([child.stdout.isPaused(), child.stderr.isPaused()], [false, false], 'node resumed them, as it does')
  for (let i = 0; i < 64; i++) child.stdout.write(Buffer.alloc(chunk, 0x62))
  for (let i = 0; i < 64; i++) child.stderr.write(Buffer.alloc(chunk, 0x63))
  await ticks(20)
  const grown = kernel.fromMux.writableLength - before
  assert.ok(grown <= 2 * framed, `stdout's buffer grew by ${String(grown)} bytes after the exit, past one chunk of each pipe`)
  assert.deepEqual([child.stdout.isPaused(), child.stderr.isPaused()], [true, true], 'the pipes are paused again')
  // Nothing is lost: once the kernel reads, all of it crosses, then the status.
  kernel.fromMux.release()
  await until(() => kernel.of('exit').length === 1, 'the exit frame')
  assert.equal(kernel.output('stdout'), 'a'.repeat(4 * chunk) + 'b'.repeat(64 * chunk))
  assert.equal(kernel.output('stderr'), 'c'.repeat(64 * chunk))
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [0])
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

test('a death by signal is 128 + n, a command that cannot be found is 127 and says so on stderr', async () => {
  assert.equal(mux.statusOf(null, 'SIGKILL', undefined), 137)
  assert.equal(mux.statusOf(null, 'SIGTERM', undefined), 143)
  assert.equal(mux.statusOf(0, null, undefined), 0)
  assert.equal(mux.statusOf(255, null, undefined), 255)
  // node's 'close' after a spawn that failed: a negative errno, and the error before it.
  assert.equal(mux.statusOf(-2, null, Object.assign(new Error('spawn'), { code: 'ENOENT' })), 127)
  assert.equal(mux.statusOf(-13, null, Object.assign(new Error('spawn'), { code: 'EACCES' })), 126)

  const killed = await running()
  killed.child.exit(null, 'SIGKILL')
  assert.equal(await exits(killed.done), mux.MUX_EXIT.ok)
  assert.deepEqual([...(killed.kernel.of('exit')[0]?.payload ?? [])], [137])

  const missing = start({
    command: 'no-such-command',
    spawn: () => {
      throw Object.assign(new Error('spawn no-such-command ENOENT'), { code: 'ENOENT' })
    },
  })
  await until(() => missing.kernel.of('ready').length === 1, 'ready')
  missing.kernel.go()
  assert.equal(await exits(missing.done), mux.MUX_EXIT.ok)
  assert.equal(missing.kernel.output('stderr'), 'aos-mux: cannot run "no-such-command": ENOENT\n')
  assert.deepEqual([...(missing.kernel.of('exit')[0]?.payload ?? [])], [127])
  assert.equal(missing.kernel.error, undefined)
})

test('maxFlows holds a connection back until a flow retires; past MAX_HELD a new one is destroyed', async () => {
  const run = await running({ limits: { frameMaxBytes: 64, maxFlows: 1 } })
  const { kernel } = run
  const first = run.connect()
  const second = run.connect()
  await ticks()
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1], 'the second connection is held, not opened past the cap')
  assert.equal(second.isPaused(), true)
  second.say('waiting')
  await ticks()
  assert.equal(kernel.dataOn(2), '', 'a held connection is not read')

  const held = Array.from({ length: mux.MAX_HELD - 1 }, () => run.connect())
  const over = run.connect()
  await ticks()
  assert.equal(over.destroyed, true, 'past MAX_HELD a connection is destroyed')
  assert.ok(held.every((s) => !s.destroyed))

  // Flow 1 retires (the kernel ends and closes it): the first held one opens as flow 2, and its bytes go out.
  kernel.send(frame('end', 1))
  kernel.send(frame('close', 1))
  await ticks()
  assert.equal(first.finished, true)
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1, 2])
  assert.equal(kernel.dataOn(2), 'waiting')
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

test('a frame the mux refuses ends it: the command is killed, the refusal is on its stderr, and it exits 76', async () => {
  const run = await running()
  run.kernel.toMux.write(encodeFrame(frame('data', 5, text('x'))))
  assert.equal(await exits(run.done), mux.MUX_EXIT.protocol)
  assert.match(run.diagnostics(), /^aos-mux: the kernel sent a frame the mux refuses: frame refused \(unopened-flow\)/)
  assert.ok(run.child.kills >= 1)
  assert.equal(run.listener.closed, true)

  // A stream that ends inside a frame is refused the same way.
  const cut = await running()
  cut.kernel.toMux.end(header(4, FRAME_TYPE_CODES.data, 1).subarray(0, 5))
  assert.equal(await exits(cut.done), mux.MUX_EXIT.protocol)
  assert.match(cut.diagnostics(), /truncated-header/)

  // A refusal names the frame, never its payload.
  const loud = await running()
  loud.kernel.toMux.write(encodeFrame(frame('stdout', 0, text('sk-the-payload-is-never-quoted'))))
  assert.equal(await exits(loud.done), mux.MUX_EXIT.protocol)
  assert.match(loud.diagnostics(), /direction/)
  assert.equal(loud.diagnostics().includes('sk-the-payload'), false)
})

test('the mux runs nothing until go: a channel that ends first, or a listener that fails, never runs the command', async () => {
  const early = start()
  await until(() => early.kernel.of('ready').length === 1, 'ready')
  early.kernel.toMux.end()
  assert.equal(await exits(early.done), mux.MUX_EXIT.ok)
  assert.deepEqual(early.listens, [])
  assert.deepEqual(early.spawned, [])

  const spawned: string[] = []
  const busy = start({
    listen: () => Promise.reject(Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE' })),
    spawn: (command) => {
      spawned.push(command)
      return new FakeChild()
    },
  })
  await until(() => busy.kernel.of('ready').length === 1, 'ready')
  busy.kernel.go()
  assert.equal(await exits(busy.done), mux.MUX_EXIT.listen)
  assert.equal(busy.diagnostics(), 'aos-mux: cannot listen on 127.0.0.1:3128: EADDRINUSE\n')
  assert.deepEqual(spawned, [], 'the command never ran')
})

test('stdin stays unread while any one socket is full, and a flow opened while stdout is full is not read until stdout drains', async () => {
  const run = await running({ limits: { frameMaxBytes: 4, maxFlows: 3 }, outputHighWaterMark: 16 })
  const { kernel } = run
  const a = run.connect(new FakeSocket(4))
  const b = run.connect(new FakeSocket(4))
  await ticks()
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1, 2])

  // Both workers stop reading, and one chunk carries an answer for each, so
  // the mux decodes both before it can pause: both sockets are past their mark.
  a.hold()
  b.hold()
  kernel.toMux.write(join(kernel.dataFrames(1, 'answer for a'), kernel.dataFrames(2, 'answer for b')))
  await ticks()
  assert.equal(kernel.toMux.isPaused(), true, 'stdin waits on the full sockets')
  a.release()
  await ticks()
  assert.equal(a.received(), 'answer for a')
  assert.equal(kernel.toMux.isPaused(), true, "a drained, but b is still full: stdin stays unread, so b's next frames cannot pile into its buffer")
  b.release()
  await ticks()
  assert.equal(b.received(), 'answer for b')
  assert.equal(kernel.toMux.isPaused(), false, 'both drained, so stdin is read again')

  // stdout is full: what a writes waits in a, and a connection opened now is
  // opened (one open frame) and then paused, unread.
  kernel.fromMux.hold()
  a.say('0123456789abcdefghij')
  await ticks()
  assert.equal(a.isPaused(), true)
  const buffered = kernel.fromMux.writableLength
  const c = run.connect()
  await ticks()
  assert.equal(c.isPaused(), true, 'a flow opened while stdout is full is not read')
  assert.equal(kernel.fromMux.writableLength, buffered + FRAME_HEADER_BYTES, 'only its open frame joined stdout')
  const request = 'GET http://c.example/ HTTP/1.1\r\n\r\n'
  c.say(request)
  await ticks()
  assert.equal(kernel.fromMux.writableLength, buffered + FRAME_HEADER_BYTES, 'nothing c wrote is framed while stdout is full')
  assert.equal(c.readableLength, request.length, 'it waits in its socket')
  kernel.fromMux.release()
  await ticks()
  assert.equal(c.isPaused(), false)
  assert.deepEqual(kernel.of('open').map((f) => f.flow), [1, 2, 3])
  assert.equal(kernel.dataOn(3), request)
  assert.equal(kernel.dataOn(1), '0123456789abcdefghij')

  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
  assert.equal(run.diagnostics(), '')
})

test("a worker that ends its socket after the kernel's clean end and close leaves the mux running, and it exits 0 on EOF with nothing to say", async () => {
  // The usual order after an answer with Connection: close: the kernel ends
  // and closes the flow, the mux sends its close at once, and the worker,
  // having read the answer, sends its FIN on the socket left lingering.
  const run = await running()
  const { kernel } = run
  const a = run.connect()
  await ticks()
  a.say('GET http://a.example/ HTTP/1.1\r\n\r\n')
  kernel.sendData(1, 'HTTP/1.1 403\r\nconnection: close\r\n\r\n')
  kernel.send(frame('end', 1))
  kernel.send(frame('close', 1))
  await ticks()
  assert.equal(a.finished, true)
  assert.equal(kernel.codec.openFlows, 0, 'the flow retired')
  let settled = false
  void run.done.then(() => (settled = true))
  a.fin()
  await ticks()
  assert.equal(settled, false, "a FIN on a retired flow's socket does not stop the mux")
  assert.equal(run.diagnostics(), '')
  assert.deepEqual(kernel.of('end', 1), [], 'nothing is framed on a retired flow')
  assert.equal(kernel.error, undefined)
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(run.diagnostics(), '')
})

test('the mux exits only once stdout has taken its last frames: a held stdout holds done, and the exit frame then arrives', async () => {
  // main() calls process.exit on done, which drops whatever stdout still holds.
  const run = await running()
  const { kernel, child } = run
  let settled = false
  void run.done.then(() => (settled = true))
  kernel.fromMux.hold()
  child.stderr.write('last words\n')
  child.exit(0)
  await ticks()
  assert.equal(settled, false, 'done waits on stdout')
  assert.deepEqual(kernel.of('exit'), [], 'the exit frame is still in stdout')
  kernel.fromMux.release()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.output('stderr'), 'last words\n')
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [0])
  assert.equal(kernel.error, undefined)
})

test('a stdout that never drains holds done for flushTimeoutMs and no longer: the mux exits though the kernel stopped reading', async () => {
  // Without the bound, a kernel that stopped reading would leave main()
  // waiting on done for ever, and the container would live until the wallclock.
  const run = await running({ flushTimeoutMs: 100 })
  const { kernel, child } = run
  kernel.fromMux.hold()
  child.stderr.write('words the kernel never reads\n')
  await ticks()
  const endedAt = Date.now()
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  const waited = Date.now() - endedAt
  assert.ok(waited >= 90 && waited < 1_000, `done came ${String(waited)} ms after stdin ended, with flushTimeoutMs 100`)
  assert.ok(child.kills >= 1)
})

test('a channel that ends between go and the listener opening never runs the command, and the listener is closed', async () => {
  let opened: (() => void) | undefined
  const closed: number[] = []
  const run = start({
    listen: (host, port) =>
      new Promise((resolve) => {
        opened = () => resolve({ host, port, close: () => void closed.push(1) })
      }),
  })
  await until(() => run.kernel.of('ready').length === 1, 'ready')
  run.kernel.go()
  await until(() => opened !== undefined, 'the mux to ask for its listener')
  run.kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  opened?.()
  await ticks()
  assert.deepEqual(run.spawned, [], 'the command never ran')
  assert.deepEqual(closed, [1], 'the listener that opened too late is closed')
})

test('at exit a held connection is destroyed and the open flow still finishes; at stdin EOF every socket the mux holds is destroyed', async () => {
  // The command exits with one flow open (maxFlows 1) and one connection held behind it.
  const exiting = await running({ limits: { frameMaxBytes: 64, maxFlows: 1 } })
  const first = exiting.connect()
  const second = exiting.connect()
  await ticks()
  assert.deepEqual(exiting.kernel.of('open').map((f) => f.flow), [1])
  exiting.child.exit(0)
  await until(() => exiting.kernel.of('exit').length === 1, 'the exit frame')
  await ticks()
  assert.equal(second.destroyed, true, 'a held connection never opens after exit: it is destroyed')
  assert.equal(first.destroyed, false, 'the open flow is not')
  first.say('GET / HTTP/1.1\r\n\r\n')
  first.fin()
  exiting.kernel.sendData(1, 'HTTP/1.1 403\r\n\r\n')
  exiting.kernel.send(frame('end', 1))
  exiting.kernel.send(frame('close', 1))
  assert.equal(await exits(exiting.done), mux.MUX_EXIT.ok)
  assert.equal(first.received(), 'HTTP/1.1 403\r\n\r\n')
  assert.equal(exiting.kernel.error, undefined)

  // stdin ends with a lingering socket (its flow closed cleanly), an open flow and a held connection.
  const ending = await running({ limits: { frameMaxBytes: 64, maxFlows: 1 } })
  const lingering = ending.connect()
  await ticks()
  ending.kernel.send(frame('end', 1))
  ending.kernel.send(frame('close', 1))
  await ticks()
  assert.equal(lingering.finished, true)
  const open = ending.connect()
  const held = ending.connect()
  await ticks()
  assert.deepEqual(ending.kernel.of('open').map((f) => f.flow), [1, 2])
  assert.deepEqual([lingering.destroyed, open.destroyed, held.destroyed], [false, false, false])
  ending.kernel.toMux.end()
  assert.equal(await exits(ending.done), mux.MUX_EXIT.ok)
  assert.deepEqual([lingering.destroyed, open.destroyed, held.destroyed], [true, true, true], 'the lingering socket, the open flow and the held connection')
  assert.equal(ending.kernel.error, undefined)
})

test('a socket the kernel closed cleanly is drained and discarded even while stdout is full', async () => {
  // A lingering socket left paused by a full stdout would never drain: its
  // flow has retired, so stdout's drain no longer resumes it, and unread
  // bytes turn the worker's close into a reset.
  const run = await running({ outputHighWaterMark: 16 })
  const { kernel } = run
  const a = run.connect()
  await ticks()
  kernel.fromMux.hold()
  a.say('0123456789abcdefghij')
  await ticks()
  assert.equal(a.isPaused(), true, 'stdout is full, so a is paused')
  kernel.send(frame('end', 1))
  kernel.send(frame('close', 1))
  await ticks()
  assert.equal(a.finished, true)
  assert.equal(a.isPaused(), false, 'the lingering socket is read')
  a.say('read by nobody')
  await ticks()
  assert.equal(a.readableLength, 0, 'and what it is sent is discarded')
  kernel.fromMux.release()
  await ticks()
  assert.equal(kernel.dataOn(1), '0123456789abcdefghij', 'nothing after the close is framed')
  assert.equal(kernel.codec.openFlows, 0)
  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

/** True once a process is gone: no such pid, or (Linux) a zombie its new parent has not reaped yet, which is dead all the same. */
function gone(pid: number): boolean {
  try {
    process.kill(pid, 0)
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ESRCH'
  }
  try {
    const stat = readFileSync(`/proc/${String(pid)}/stat`, 'utf8')
    return stat.slice(stat.lastIndexOf(')') + 2).startsWith('Z')
  } catch {
    return false
  }
}

/**
 * A command that starts a grandchild in its own process group, prints its
 * pid, and waits: a non-interactive shell has no job control, so its
 * background job stays in the shell's group.
 */
const GRANDPARENT = ['/bin/sh', ['-c', 'sleep 600 & echo $!; wait']] as const

/**
 * node's spawn as spawnCommand takes it, by its type alone: this file runs a
 * real process only through mux.spawnCommand, the image's one spawner, and
 * test/hygiene.test.ts names it as the one test that does.
 */
type SpawnProcess = NonNullable<Parameters<typeof mux.spawnCommand>[2]>

/** Run a command through spawnCommand's own spawn, to its close: what it printed and how it ended. */
async function ranForReal(t: TestContext, command: string, args: readonly string[]): Promise<{ readonly stdout: string; readonly stderr: string; readonly code: unknown }> {
  const child = mux.spawnCommand(command, args)
  t.after(() => child.killTree())
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')))
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')))
  const code = await exits(new Promise<unknown>((resolve) => child.once('close', (c: unknown) => resolve(c))), `${command} to finish`, 5_000)
  return { stdout, stderr, code }
}

test('spawnCommand runs the command in its own process group, with no stdin, no shell and no environment of its own, and killTree kills the group', async (t) => {
  // The options node's spawn is given, exactly: stdin is the mux's channel
  // and never the command's, detached makes the group killTree kills, and
  // there is no env (the command inherits the image's, the mux reads none).
  const asked: unknown[] = []
  const fake = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    pid: undefined,
    signals: [] as string[],
    kill(signal: string): boolean {
      this.signals.push(signal)
      return true
    },
  })
  const command = mux.spawnCommand('git', ['clone', 'http://github.com/op/fixture.git'], (file, args, options) => {
    asked.push({ file, args, options })
    return fake as unknown as ReturnType<SpawnProcess>
  })
  assert.deepEqual(asked, [{ file: 'git', args: ['clone', 'http://github.com/op/fixture.git'], options: { stdio: ['ignore', 'pipe', 'pipe'], detached: true, shell: false } }])
  assert.equal(command.stdout, fake.stdout)
  assert.equal(command.stderr, fake.stderr)
  let exited: unknown
  command.once('exit', (code: unknown) => (exited = code))
  fake.emit('exit', 3)
  assert.equal(exited, 3)
  // A child with no pid (its spawn failed) has no group to kill.
  command.killTree()
  assert.deepEqual(fake.signals, ['SIGKILL'])

  // For real: a shell that starts a grandchild in its group. killTree ends both.
  const real = mux.spawnCommand(...GRANDPARENT)
  let printed = ''
  real.stdout.on('data', (chunk: Buffer) => (printed += chunk.toString('utf8')))
  real.stderr.resume()
  const died = new Promise<unknown>((resolve) => real.once('exit', (_code: unknown, signal: unknown) => resolve(signal)))
  t.after(() => real.killTree())
  await until(() => printed.includes('\n'), 'the grandchild to start', 10_000)
  const grandchild = Number(printed.trim())
  assert.ok(Number.isInteger(grandchild) && grandchild > 1, printed)
  t.after(() => {
    try {
      process.kill(grandchild, 'SIGKILL')
    } catch {
      // Gone, as it should be.
    }
  })
  assert.equal(gone(grandchild), false, 'the grandchild runs')
  real.killTree()
  assert.equal(await exits(died, 'the command to die'), 'SIGKILL')
  await until(() => gone(grandchild), 'the grandchild to die with its group')

  // What node itself is given, through the default spawn and not the seam
  // above. stdin is /dev/null: a read meets its end at once. (A test process's
  // own stdin is a pipe node --test never writes to, so a command that shared
  // it would wait here until the bound, as one in the image would eat the
  // kernel's frames.)
  assert.deepEqual(await ranForReal(t, '/bin/sh', ['-c', 'if read x; then echo "read $x"; else echo eof; fi']), { stdout: 'eof\n', stderr: '', code: 0 })
  // No shell: an argument with a ; and a $ reaches the command as it is.
  assert.deepEqual(await ranForReal(t, '/bin/echo', ['a;b $X']), { stdout: 'a;b $X\n', stderr: '', code: 0 })
  // Nor a working directory, an identity or an argv[0] of its own: the
  // command runs where the mux runs, as whom it runs, named as it was asked.
  assert.deepEqual(await ranForReal(t, '/bin/sh', ['-c', 'pwd -P; id -u; id -g; echo "$0"']), {
    stdout: `${realpathSync(process.cwd())}\n${String(process.getuid?.())}\n${String(process.getgid?.())}\n/bin/sh\n`,
    stderr: '',
    code: 0,
  })
  // What the default spawn hands node is spawnCommand's options as they are,
  // stdio copied and nothing added (no cwd, env, uid, gid or argv0): the
  // options the injected spawn above was given are node's, key for key. A
  // stdin check alone cannot see an inherited stdin where the test's own is
  // /dev/null (--test-isolation=none under a redirect), and this can.
  assert.match(MUX_SOURCE, /^const spawnProcess = \(command, args, options\) => spawnChild\(command, args, \{ \.\.\.options, stdio: \[\.\.\.options\.stdio\] \}\)$/m)
  assert.equal(MUX_SOURCE.split('spawnChild(').length - 1, 1, 'node\'s spawn is called in the default spawn alone')
})

/**
 * A command that starts a descendant in a session of its own (so its group
 * kill misses it), prints the descendant's pid on stderr, and exits 0.3 s
 * later. The descendant writes 32 MiB to the stdout it shares, and gives up
 * after 30 s whatever happens.
 */
const LEAVES_A_WRITER = [
  'perl',
  [
    '-MPOSIX',
    '-e',
    'my $pid = fork() // die "fork: $!"; if ($pid == 0) { POSIX::setsid(); alarm 30; my $b = "x" x 65536; syswrite(STDOUT, $b) for 1 .. 512; exit 0 } syswrite(STDERR, "$pid\\n"); select(undef, undef, undef, 0.3); exit 0',
  ],
] as const

test("for real: a descendant writing once the command has exited under a full stdout fills its own pipe, not the mux, and the grace's bound closes the pipe on it", async (t) => {
  // node's own ChildProcess, not the fake: its flushStdio resumes the pipes
  // the mux paused, on the tick after the exit.
  let exited = false
  let real: mux.CommandChild | undefined
  const run = start({
    limits: { frameMaxBytes: 65_536, maxFlows: 2 },
    exitGraceMs: 50,
    exitGraceMaxMs: 800,
    command: LEAVES_A_WRITER[0],
    args: LEAVES_A_WRITER[1],
    spawn: (command, args) => {
      const child = mux.spawnCommand(command, args)
      child.once('exit', () => (exited = true))
      real = child
      return child
    },
  })
  const { kernel } = run
  const descendant = (): number => Number(kernel.output('stderr').trim())
  t.after(async () => {
    kernel.fromMux.release()
    await ticks()
    const pid = descendant()
    if (Number.isInteger(pid) && pid > 1) {
      try {
        process.kill(pid, 'SIGKILL')
      } catch {
        // Gone, as it should be.
      }
    }
    kernel.toMux.end()
  })
  await until(() => kernel.of('ready').length === 1, 'ready')
  // The kernel reads nothing from here: stdout is full before the command exits.
  kernel.fromMux.hold()
  kernel.go()
  await until(() => exited, 'the command to exit', 5_000)
  let most = 0
  for (const stop = Date.now() + 300; Date.now() < stop && most <= 4 * 1_048_576; ) {
    most = Math.max(most, kernel.fromMux.writableLength)
    await sleep(5)
  }
  assert.ok(most < 1_048_576, `stdout's buffer held ${String(most)} bytes once the command had exited`)
  assert.ok(real !== undefined)
  const pipes = real
  assert.deepEqual([pipes.stdout.isPaused(), pipes.stderr.isPaused()], [true, true], 'node resumed the pipes, and the mux paused them again')
  // The bound closes the pipes though stdout stays full; the status then crosses behind what stdout holds.
  await until(() => pipes.stdout.destroyed && pipes.stderr.destroyed, "the grace's bound to close the pipes", 3_000)
  kernel.fromMux.release()
  await until(() => kernel.of('exit').length === 1, 'the exit frame')
  assert.deepEqual([...(kernel.of('exit')[0]?.payload ?? [])], [0])
  const received = kernel.output('stdout').length
  assert.ok(received > 0 && received < 32 * 1_048_576, `${String(received)} bytes of the descendant's 32 MiB crossed before its pipe was closed`)
  const pid = descendant()
  assert.ok(Number.isInteger(pid) && pid > 1, kernel.output('stderr'))
  await until(() => gone(pid), 'the descendant to die on its closed pipe', 5_000)
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

// ── the self-test ────────────────────────────────────────────────────────────

test('a self-test connect success is reported in READY', async () => {
  // The probes, in order: the Mac's loopback as a VM sees it, by address and
  // by name, the internet, and a resolver.
  assert.deepEqual(
    mux.SELF_TEST.map((p) => (p.probe === 'connect' ? `connect ${p.host}:${String(p.port)}` : `lookup ${p.host}`)),
    [
      'connect 192.168.5.2:8766',
      'connect 192.168.5.2:7777',
      'connect host.lima.internal:8766',
      'connect host.docker.internal:8766',
      'connect 1.1.1.1:443',
      'lookup example.com',
    ],
  )

  // Nothing reached: every probe named, with the error that says so.
  const quiet = start()
  await until(() => quiet.kernel.of('ready').length === 1, 'ready')
  assert.deepEqual(quiet.kernel.report(), {
    mux: 1,
    probes: [
      { probe: 'connect', target: '192.168.5.2:8766', reached: false, error: 'ENETUNREACH' },
      { probe: 'connect', target: '192.168.5.2:7777', reached: false, error: 'ENETUNREACH' },
      { probe: 'connect', target: 'host.lima.internal:8766', reached: false, error: 'ENETUNREACH' },
      { probe: 'connect', target: 'host.docker.internal:8766', reached: false, error: 'ENETUNREACH' },
      { probe: 'connect', target: '1.1.1.1:443', reached: false, error: 'ENETUNREACH' },
      { probe: 'lookup', target: 'example.com', reached: false, error: 'EAI_AGAIN' },
    ],
    reached: 0,
  })
  quiet.kernel.toMux.end()
  await exits(quiet.done)

  // A connection that opened, a peer that refused (there is a route), and a
  // lookup that answered are each reached; a probe that never settles, one
  // that throws and one that answers nonsense are not, and say why.
  const calls: string[] = []
  const loud = start({
    probeTimeoutMs: 30,
    connect: (host, port) => {
      calls.push(`${host}:${String(port)}`)
      if (host === '1.1.1.1') return Promise.resolve({ reached: true, error: null })
      if (port === 7777) return Promise.resolve({ reached: true, error: 'ECONNREFUSED' })
      if (host === 'host.lima.internal') return new Promise(() => {})
      if (host === 'host.docker.internal') throw Object.assign(new Error('boom'), { code: 'ERR_BROKEN' })
      return Promise.resolve({ reached: 'yes', error: 'not a code' } as unknown as mux.ProbeOutcome)
    },
    lookup: () => Promise.resolve({ reached: true, error: null }),
  })
  await until(() => loud.kernel.of('ready').length === 1, 'ready')
  assert.deepEqual(loud.kernel.report(), {
    mux: 1,
    probes: [
      { probe: 'connect', target: '192.168.5.2:8766', reached: false, error: 'EOTHER' },
      { probe: 'connect', target: '192.168.5.2:7777', reached: true, error: 'ECONNREFUSED' },
      { probe: 'connect', target: 'host.lima.internal:8766', reached: false, error: 'ETIMEDOUT' },
      { probe: 'connect', target: 'host.docker.internal:8766', reached: false, error: 'ERR_BROKEN' },
      { probe: 'connect', target: '1.1.1.1:443', reached: true, error: null },
      { probe: 'lookup', target: 'example.com', reached: true, error: null },
    ],
    reached: 3,
  })
  assert.deepEqual(calls.sort(), ['1.1.1.1:443', '192.168.5.2:7777', '192.168.5.2:8766', 'host.docker.internal:8766', 'host.lima.internal:8766'])
  // The report is the kernel's to judge: the mux still runs nothing until go.
  await ticks()
  assert.deepEqual(loud.listens, [])
  assert.deepEqual(loud.spawned, [])
  assert.equal(loud.kernel.error, undefined, 'the report fits a ready frame the kernel accepts')
  loud.kernel.toMux.end()
  assert.equal(await exits(loud.done), mux.MUX_EXIT.ok)
})

test('the default probes: a loopback connection and a refusal are reached; a dial that throws, one that hangs and a failed lookup are not', async (t) => {
  // A real loopback listener: the one place a connection may open in a test.
  const server = net.createServer((socket) => socket.destroy())
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => server.close())
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  assert.deepEqual(await mux.connectProbe('127.0.0.1', address.port, 2_000), { reached: true, error: null })

  // A port nothing listens on: the peer answers with a refusal, so there is a route.
  const closed = net.createServer()
  await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve))
  const free = closed.address()
  assert.ok(free !== null && typeof free === 'object')
  await new Promise<void>((resolve) => closed.close(() => resolve()))
  assert.deepEqual(await mux.connectProbe('127.0.0.1', free.port, 2_000), { reached: true, error: 'ECONNREFUSED' })

  // A dial that throws (as one refused before any socket opens does) is not
  // reached. Injected, never a real dial to a host off the machine: a test
  // never relies on the guard to stop one.
  const refusedDial = (): net.Socket => {
    throw Object.assign(new Error('refused before any socket'), { code: 'AOS_TEST_NETWORK_BLOCKED' })
  }
  assert.deepEqual(await mux.connectProbe('192.168.5.2', 8766, 2_000, refusedDial), { reached: false, error: 'AOS_TEST_NETWORK_BLOCKED' })
  // A dial that never connects is ETIMEDOUT, and its socket is destroyed.
  const pending = new net.Socket()
  assert.deepEqual(await mux.connectProbe('203.0.113.1', 443, 20, () => pending), { reached: false, error: 'ETIMEDOUT' })
  assert.equal(pending.destroyed, true)

  assert.deepEqual(await mux.lookupProbe('example.com', 1_000, () => Promise.resolve([{ address: '93.184.215.14', family: 4 }])), { reached: true, error: null })
  assert.deepEqual(await mux.lookupProbe('example.com', 1_000, () => Promise.resolve([])), { reached: false, error: 'ENODATA' })
  assert.deepEqual(
    await mux.lookupProbe('example.com', 1_000, () => Promise.reject(Object.assign(new Error('getaddrinfo'), { code: 'ENOTFOUND' }))),
    { reached: false, error: 'ENOTFOUND' },
  )
  assert.deepEqual(await mux.lookupProbe('example.com', 20, () => new Promise(() => {})), { reached: false, error: 'ETIMEDOUT' })
  assert.deepEqual(
    await mux.lookupProbe('example.com', 1_000, () => {
      throw new Error('no code at all')
    }),
    { reached: false, error: 'EOTHER' },
  )
  assert.equal(mux.errorCode({ code: 'a'.repeat(40) }), 'EOTHER')
  assert.equal(mux.errorCode({ code: 'E'.repeat(40) }), 'EOTHER')
})

test('on real loopback sockets: a half-close is relayed as an end and the answer still arrives; a clean end is a FIN, a cut is a reset', async (t) => {
  const asked: { host: string; port: number }[] = []
  const bound: string[] = []
  let port = 0
  const run = start({
    listen: async (host, wanted, onConnection) => {
      asked.push({ host, port: wanted })
      // The host the mux asks for, on a port of the test's: listenTcp binds
      // what it is given, as the system reports it back.
      const listener = await mux.listenTcp(host, 0, onConnection)
      bound.push(listener.host)
      port = listener.port
      t.after(() => listener.close())
      return listener
    },
  })
  const { kernel } = run
  // Real sockets keep the process alive: whatever this test meets, they and the mux are ended.
  const sockets: net.Socket[] = []
  t.after(() => {
    for (const socket of sockets) socket.destroy()
    kernel.toMux.end()
  })
  await until(() => kernel.of('ready').length === 1, 'ready')
  kernel.go()
  await until(() => run.spawned.length === 1, 'the command')
  assert.deepEqual(asked, [{ host: '127.0.0.1', port: 3128 }])
  assert.deepEqual(bound, ['127.0.0.1'], 'the listener is bound to the container loopback alone, not every address')

  // A worker writes its request and half-closes; the kernel answers, ends and closes.
  const worker = net.connect({ host: '127.0.0.1', port, allowHalfOpen: true })
  sockets.push(worker)
  const got: Buffer[] = []
  worker.on('data', (chunk: Buffer) => got.push(chunk))
  const ended = new Promise<void>((resolve) => worker.once('end', resolve))
  worker.end('GET http://a.example/ HTTP/1.1\r\n\r\n')
  await until(() => kernel.of('end', 1).length === 1, "the worker's end")
  assert.equal(kernel.dataOn(1), 'GET http://a.example/ HTTP/1.1\r\n\r\n')
  kernel.send(frame('data', 1, text('HTTP')))
  kernel.send(frame('data', 1, text('/1.1')))
  kernel.send(frame('end', 1))
  kernel.send(frame('close', 1))
  await exits(ended, "the worker's clean end")
  assert.equal(Buffer.concat(got).toString('utf8'), 'HTTP/1.1', 'the whole answer, then a clean end')
  worker.destroy()

  // A worker whose answer the kernel cuts reads a reset, not a clean end.
  // (The mux resets; it never ends a cut flow. An RST that lands behind bytes
  // the worker has not read yet may read on Linux as those bytes and then an
  // end, which the answer's own HTTP framing still shows short; so the cut
  // here comes once the worker has read what came before it.)
  const cut = net.connect({ host: '127.0.0.1', port })
  sockets.push(cut)
  // Reading, as a worker waiting on its answer is: an RST is seen by a socket that reads.
  let partial = ''
  cut.on('data', (chunk: Buffer) => (partial += chunk.toString('utf8')))
  const reset = new Promise<string>((resolve) => {
    cut.once('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? 'none'))
    cut.once('end', () => resolve('a clean end'))
  })
  cut.write('GET http://b.example/ HTTP/1.1\r\n\r\n')
  await until(() => kernel.dataOn(2) !== '', 'the second request')
  kernel.sendData(2, 'HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\npartial')
  await until(() => partial.endsWith('partial'), 'the worker to read the answer so far')
  kernel.send(frame('close', 2))
  assert.equal(await exits(reset, 'the reset'), 'ECONNRESET')

  kernel.toMux.end()
  assert.equal(await exits(run.done), mux.MUX_EXIT.ok)
  assert.equal(kernel.error, undefined)
})

// ── the mux and the kernel's session ─────────────────────────────────────────

/** kernel.yaml's shipped egress.limits, as the session takes them. */
const SESSION_LIMITS: SessionLimits = Object.freeze({
  frameMaxBytes: 65_536,
  maxFlows: 16,
  maxHeaderBytes: 16_384,
  maxRequests: 2_000,
  maxBytes: 536_870_912,
  maxDenied: 20,
  idleMs: 60_000,
})

const GRANT = EgressGrant.parse({
  runId: 'run_1762700000000_k3x9q2',
  allow: ['registry.npmjs.org'],
  routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }],
})

/** What may say there is no route, by probe (mux.mjs's header): with --network none a connect by address meets ENETUNREACH, and a name finds no resolver. */
const NO_ROUTE_CODES = {
  address: new Set(['ENETUNREACH']),
  name: new Set(['ENETUNREACH', 'EAI_AGAIN', 'ENOTFOUND']),
  lookup: new Set(['EAI_AGAIN', 'ENOTFOUND']),
} as const

const targetOf = (p: mux.Probe): string => (p.probe === 'connect' ? `${p.host}:${String(p.port)}` : p.host)

/**
 * A minimal judge for these tests, holding the report to what mux.mjs's
 * header says a judge must (W3's will be no weaker): every probe named, in
 * order, none reached, each with an error that says there is no route. A
 * probe that timed out is refused: a SYN dropped on a real route times out.
 */
const judge = (report: Uint8Array): string | undefined => {
  const parsed = z
    .strictObject({
      mux: z.literal(1),
      probes: z.array(z.strictObject({ probe: z.enum(['connect', 'lookup']), target: z.string(), reached: z.boolean(), error: z.string().nullable() })),
      reached: z.number().int(),
    })
    .safeParse(JSON.parse(Buffer.from(report).toString('ascii')))
  if (!parsed.success) return 'the report is not one the judge reads'
  const { probes } = parsed.data
  if (probes.length !== mux.SELF_TEST.length || probes.some((p, i) => p.target !== targetOf(mux.SELF_TEST[i] ?? { probe: 'lookup', host: '' }))) {
    return 'the report does not name every probe, in order'
  }
  const reached = probes.filter((p) => p.reached).length
  if (reached !== 0 || parsed.data.reached !== 0) return `the self-test reached ${String(Math.max(reached, parsed.data.reached))} of what it must not`
  for (const [i, p] of probes.entries()) {
    const probe = mux.SELF_TEST[i]
    const codes = probe === undefined || probe.probe === 'lookup' ? NO_ROUTE_CODES.lookup : net.isIP(probe.host) === 0 ? NO_ROUTE_CODES.name : NO_ROUTE_CODES.address
    if (p.probe !== probe?.probe || p.error === null || !codes.has(p.error)) return `the self-test met ${p.error ?? 'no error'} at ${p.target}, which does not say there is no route`
  }
  return undefined
}

test('the minimal judge accepts only a report naming every probe in order, none reached, each with an error that says there is no route', () => {
  type Result = mux.ProbeResult
  const quiet = (p: mux.Probe): Result => ({
    probe: p.probe,
    target: targetOf(p),
    reached: false,
    error: p.probe === 'lookup' ? 'ENOTFOUND' : net.isIP(p.host) === 0 ? 'EAI_AGAIN' : 'ENETUNREACH',
  })
  const results = mux.SELF_TEST.map(quiet)
  assert.equal(judge(mux.readyPayload(results)), undefined)
  const changed = (at: number, change: Partial<Result>): Uint8Array => mux.readyPayload(results.map((r, i) => (i === at ? { ...r, ...change } : r)))
  const address = mux.SELF_TEST.findIndex((p) => p.probe === 'connect' && net.isIP(p.host) !== 0)
  const name = mux.SELF_TEST.findIndex((p) => p.probe === 'connect' && net.isIP(p.host) === 0)
  const lookup = mux.SELF_TEST.findIndex((p) => p.probe === 'lookup')
  assert.ok(address !== -1 && name !== -1 && lookup !== -1)
  assert.equal(judge(changed(name, { error: 'ENETUNREACH' })), undefined, 'a name the container resolved and could not route to')
  for (const [at, error] of [
    [address, 'ETIMEDOUT'],
    [address, 'EHOSTUNREACH'],
    [address, 'EOTHER'],
    [address, 'EAI_AGAIN'],
    [name, 'ETIMEDOUT'],
    [lookup, 'ETIMEDOUT'],
    [lookup, 'ENETUNREACH'],
    [lookup, null],
  ] as const) {
    assert.match(judge(changed(at, { error })) ?? 'accepted', /which does not say there is no route$/, `${results[at]?.target ?? ''} ${String(error)}`)
  }
  assert.match(judge(changed(address, { reached: true, error: 'ECONNREFUSED' })) ?? 'accepted', /reached 1 of what it must not/)
  assert.match(judge(mux.readyPayload(results.slice(1))) ?? 'accepted', /does not name every probe/)
  assert.match(judge(mux.readyPayload([...results].reverse())) ?? 'accepted', /does not name every probe/)
})

function sessionOver(t: TestContext, toKernel: PassThrough, toMux: PassThrough, kills: number[]): ReturnType<typeof createEgressSession> {
  const store = withStore(t)
  const touched: string[] = []
  t.after(() => assert.deepEqual(touched, [], 'nothing was resolved or dialled'))
  return createEgressSession({
    grantId: 'grant_1762700000000_a1',
    grant: GRANT,
    agentId: 'coder',
    limits: SESSION_LIMITS,
    channel: { input: toKernel, output: toMux },
    store,
    upstream: createUpstream({
      resolver: () => {
        touched.push('resolver')
        throw new Error('nothing is resolved here')
      },
      dial: () => {
        touched.push('dial')
        throw new Error('nothing is dialled here')
      },
      interfaces: () => ({}),
      connectTimeoutMs: 1_000,
      idleTimeoutMs: 1_000,
    }),
    credential: () => {
      throw new Error('no credential is injected here')
    },
    acceptReady: judge,
    kill: () => kills.push(1),
  })
}

test("against the kernel's own session: a worker's request is judged, denied and answered over the channel, and the run ends exited", async (t) => {
  const toKernel = new PassThrough()
  const toMux = new PassThrough()
  const kills: number[] = []
  const session = sessionOver(t, toKernel, toMux, kills)
  const child = new FakeChild()
  let accept: ((socket: Duplex) => void) | undefined
  const done = mux.runMux({
    input: toMux,
    output: toKernel,
    command: 'node',
    args: ['fetch.js'],
    connect: NO_ROUTE,
    lookup: NO_DNS,
    listen: (host, port, onConnection) => {
      accept = onConnection
      return Promise.resolve({ host, port, close: () => {} })
    },
    spawn: () => child,
  })
  await until(() => accept !== undefined, 'the mux to be listening (the session accepted its ready and sent go)')

  const worker = new FakeSocket()
  accept?.(worker)
  worker.say('GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n')
  await until(() => worker.finished, 'the answer and its end')
  assert.match(worker.received(), /^HTTP\/1\.1 403 /, 'a host the grant does not name is denied')
  assert.match(worker.received(), /\r\nconnection: close\r\n/i)
  worker.fin()
  child.stdout.write('done\n')
  child.exit(0)
  assert.equal(await exits(done), mux.MUX_EXIT.ok, 'the mux exits once the command has and its flow retired')
  toKernel.end()
  const outcome = await exits(session.end('exited'), 'the session to end')
  assert.equal(outcome.reason, 'exited')
  assert.equal(outcome.exitStatus, 0)
  assert.equal(Buffer.from(outcome.stdout).toString('utf8'), 'done\n')
  assert.equal(outcome.totals.flows, 1)
  assert.equal(outcome.totals.denied, 1)
  assert.deepEqual(kills, [])
})

test("against the kernel's own session: a self-test that reached something gets no go, and its command never runs", async (t) => {
  const toKernel = new PassThrough()
  const toMux = new PassThrough()
  const kills: number[] = []
  const session = sessionOver(t, toKernel, toMux, kills)
  const listens: string[] = []
  const spawned: string[] = []
  const done = mux.runMux({
    input: toMux,
    output: toKernel,
    command: 'node',
    args: ['fetch.js'],
    connect: (host, port) => Promise.resolve(host === '192.168.5.2' && port === 8766 ? { reached: true, error: null } : { reached: false, error: 'ENETUNREACH' }),
    lookup: NO_DNS,
    listen: (host) => {
      listens.push(host)
      return Promise.reject(new Error('never listened'))
    },
    spawn: (command) => {
      spawned.push(command)
      return new FakeChild()
    },
  })
  const outcome = await exits(session.done, 'the session to revoke')
  assert.equal(outcome.reason, 'violation')
  assert.match(outcome.detail ?? '', /the self-test reached 1 of what it must not/)
  assert.deepEqual(kills, [1], 'the session asked for the container to be killed')
  // The kill ends the container's stdin.
  toMux.end()
  assert.equal(await exits(done), mux.MUX_EXIT.ok)
  assert.deepEqual(listens, [])
  assert.deepEqual(spawned, [])
})

// ── what the mux is ──────────────────────────────────────────────────────────

test('parseArgs takes -- and a command with its arguments, and nothing else', () => {
  assert.deepEqual(mux.parseArgs(['--', 'git', 'clone', '--depth', '1', 'http://github.com/op/fixture.git']), {
    command: 'git',
    args: ['clone', '--depth', '1', 'http://github.com/op/fixture.git'],
  })
  assert.deepEqual(mux.parseArgs(['--', 'node']), { command: 'node', args: [] })
  for (const argv of [[], ['--'], ['--', ''], ['git', 'clone'], ['--canary'], ['-', 'git']]) {
    assert.equal(mux.parseArgs(argv), undefined, JSON.stringify(argv))
  }
})

/** What the mux may use of process: its stdio, its argv, exit, and kill (of the command's group). */
const PROCESS_USES = new Set(['argv', 'exit', 'kill', 'stdin', 'stdout', 'stderr'])

/**
 * Names that reach process by a spelling no scan can follow: the global
 * object (globalThis, global), whose computed members can name anything, and
 * eval and Function, which run a string as code. The mux needs none of them.
 */
const REACHES_ANYTHING = new Set(['globalThis', 'global', 'eval', 'Function'])

/**
 * What the mux imports, module by module, by the name each is exported as,
 * and nothing more: node:vm, node:worker_threads, node:fs or child_process's
 * exec* would each run or read what no scan of process sees.
 */
const MUX_IMPORTS: Readonly<Record<string, readonly string[]>> = {
  'node:child_process': ['spawn'],
  'node:dns/promises': ['lookup'],
  'node:net': ['connect', 'createServer'],
  'node:os': ['constants'],
}

/** An identifier that names a property (x.global, { eval: 1 }), not a binding. */
const isPropertyName = (node: ts.Identifier): boolean =>
  (ts.isPropertyAccessExpression(node.parent) || ts.isPropertyAssignment(node.parent)) && node.parent.name === node

/**
 * Every way a file reaches process, as a name: process.<name> for a property
 * read off it, and anything else (process['env'], globalThis.process, a
 * destructuring, process passed on, the node:process module, a string
 * 'process' handed to Reflect or an index) as what it is. So is every use of
 * a REACHES_ANYTHING name (but as the name of a property: x.global), every
 * import(), which can load a module by a computed name, every name or
 * string `constructor` but a class's own declaration (x.constructor, a
 * destructuring of it, a 'constructor' handed to Reflect: a function's
 * constructor is Function, whatever the function), and every element access keyed by
 * anything but a variable (x['constr' + 'uctor'], globalThis['pro' +
 * 'cess']): the mux keys its own by variables alone. A tripwire for code
 * written to slip past it, not a proof: a key built into a variable first is
 * beyond any scan, and the mux is no boundary.
 */
function processUses(path: string, text: string): string[] {
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS)
  const uses: string[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && node.text === 'process') {
      const parent = node.parent
      if (ts.isPropertyAccessExpression(parent) && parent.expression === node) uses.push(parent.name.text)
      else uses.push(`process in ${parent.getText(source)}`)
    } else if (ts.isIdentifier(node) && REACHES_ANYTHING.has(node.text) && !isPropertyName(node)) {
      uses.push(`${node.text} in ${node.parent.getText(source)}`)
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      uses.push(`import() in ${node.getText(source)}`)
    } else if (ts.isStringLiteralLike(node) && /^(?:node:)?process$/.test(node.text)) {
      uses.push(`'${node.text}' in ${node.parent.getText(source)}`)
    } else if (ts.isIdentifier(node) && node.text === 'constructor') {
      uses.push(`constructor in ${node.parent.getText(source)}`)
    } else if (ts.isStringLiteralLike(node) && node.text === 'constructor') {
      uses.push(`'constructor' in ${node.parent.getText(source)}`)
    } else if (ts.isElementAccessExpression(node) && !ts.isIdentifier(node.argumentExpression)) {
      uses.push(`an access by a computed key in ${node.getText(source)}`)
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return uses
}

/** Every module a file's import declarations name, and each module it re-exports from as `re-export <module>`. */
function importedModules(path: string, text: string): string[] {
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS)
  const out: string[] = []
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement)) out.push(ts.isStringLiteral(statement.moduleSpecifier) ? statement.moduleSpecifier.text : statement.moduleSpecifier.getText(source))
    else if (ts.isExportDeclaration(statement) && statement.moduleSpecifier !== undefined) out.push(`re-export ${statement.moduleSpecifier.getText(source)}`)
  }
  return out
}

/** What a file would reach past the mux's stdio, argv, exit, kill and MUX_IMPORTS: empty for the mux, and for nothing that reads the environment or runs a string. */
function overreach(path: string, text: string): string[] {
  const out = processUses(path, text).filter((use) => !PROCESS_USES.has(use))
  for (const module of importedModules(path, text)) if (!Object.hasOwn(MUX_IMPORTS, module)) out.push(`an import of ${module}`)
  for (const [module, names] of Object.entries(MUX_IMPORTS)) {
    for (const name of importsFrom(path, text, module)) if (!names.includes(name)) out.push(`${name} of ${module}`)
  }
  return out
}

/** What a file imports from `module`, by the name each is exported as: '*' for a namespace, 'default' for a default import. */
function importsFrom(path: string, text: string, module: string): string[] {
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS)
  const names: string[] = []
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.moduleSpecifier.text !== module) continue
    const clause = statement.importClause
    if (clause === undefined) {
      names.push('(for its side effects)')
      continue
    }
    if (clause.name !== undefined) names.push('default')
    const bindings = clause.namedBindings
    if (bindings !== undefined && ts.isNamespaceImport(bindings)) names.push('*')
    else if (bindings !== undefined) for (const element of bindings.elements) names.push((element.propertyName ?? element.name).text)
  }
  return names
}

test('the mux holds no config and no secret: it reads no environment variable and no file, and binds the literal 127.0.0.1:3128 kernel.yaml names', () => {
  // Code only: what the header says about the environment is prose.
  const code = MUX_SOURCE.split('\n')
    .filter((line) => !/^\s*(?:\/\/|\*|\/\*\*)/.test(line))
    .join('\n')
  assert.ok(code.includes('runMux'), 'the scan sees the code')
  // Of process it uses its stdio, argv, exit and kill, and of node: modules
  // what MUX_IMPORTS names: nothing else, by any spelling the scan knows.
  const uses = processUses('images/worker/mux.mjs', MUX_SOURCE)
  assert.ok(uses.includes('kill') && uses.includes('argv'), `the scan sees process: ${uses.join(', ')}`)
  assert.deepEqual(uses.filter((use) => !PROCESS_USES.has(use)), [], 'it reaches process only for its stdio, argv, exit and kill')
  assert.deepEqual(importedModules('images/worker/mux.mjs', MUX_SOURCE).sort(), Object.keys(MUX_IMPORTS).sort(), 'it imports these modules and no other')
  for (const [module, names] of Object.entries(MUX_IMPORTS)) {
    assert.deepEqual(importsFrom('images/worker/mux.mjs', MUX_SOURCE, module).sort(), [...names].sort(), `of ${module} it imports ${names.join(' and ')} alone`)
  }
  assert.deepEqual(overreach('images/worker/mux.mjs', MUX_SOURCE), [])
  for (const probe of [
    'const home = process.env.HOME',
    "const home = process['env']",
    'const home = globalThis.process.env',
    "process.loadEnvFile('/opt/aos/env')",
    'const { env } = process',
    'const p = process\np.env',
    "import { env } from 'node:process'",
    "import proc from 'process'",
    "const p = Reflect.get(globalThis, 'process')",
    // Spellings only deliberate code would use, all refused by name.
    "const home = globalThis['pro' + 'cess'].env",
    "const home = global['pro' + 'cess'].env",
    "const p = Reflect.get(globalThis, 'pro' + 'cess')",
    "const home = Function('return process.env')()",
    "const home = new Function('return pro' + 'cess.env')()",
    "const home = eval('pro' + 'cess').env",
    "const home = (0, eval)('process.env')",
    "const os = await import('node:' + 'os')",
    // A function's constructor is Function, reached without naming it.
    "const home = (() => {}).constructor('return pro' + 'cess.env')()",
    "const home = await (async () => {}).constructor('return pro' + 'cess.env')()",
    "const home = (() => {})['constructor']('return pro' + 'cess.env')()",
    "const home = (() => {})['constr' + 'uctor']('return pro' + 'cess.env')()",
    "const F = Reflect.get(() => {}, 'constructor')",
    "const { constructor: F } = () => {}",
    // Modules that run a string or another program, or read a file.
    "import vm from 'node:vm'\nconst p = vm.runInThisContext('pro' + 'cess')",
    "import { runInThisContext } from 'node:vm'\nrunInThisContext('pro' + 'cess')",
    "import { Worker } from 'node:worker_threads'\nnew Worker('postMessage(pro' + 'cess.env)', { eval: true })",
    "import { execFileSync } from 'node:child_process'\nexecFileSync('/usr/bin/env')",
    "import * as cp from 'node:child_process'\ncp.execSync('env')",
    "import cp from 'node:child_process'\ncp.exec('env')",
    "import { readFileSync } from 'node:fs'\nreadFileSync('/proc/self/environ')",
    "import { homedir } from 'node:os'\nhomedir()",
    "export { execFileSync } from 'node:child_process'",
  ]) {
    assert.notDeepEqual(overreach('probe.mjs', probe), [], probe)
  }
  assert.deepEqual(processUses('probe.mjs', "process.stdout.write('x')\nprocess.exit(process.argv.length)"), ['stdout', 'exit', 'argv'])
  assert.deepEqual(processUses('probe.mjs', 'const a = socket.global\nconst b = { eval: 1 }.eval'), [], 'a property that shares a name reaches nothing')
  assert.deepEqual(overreach('probe.mjs', "import { spawn } from 'node:child_process'\nconst codes = { a: 1 }\nconst k = 'a'\nspawn('git', [String(codes[k])])\nclass C { constructor() {} }"), [], 'an access by a variable and a class constructor reach nothing')
  assert.equal(/\benv\s*:/.test(code), false, 'it sets no environment for the command')
  assert.equal(/node:fs|readFile|openSync|createReadStream/.test(code), false, 'it reads no file')
  // node:os reads HOME and the passwd entry for homedir() and userInfo(): the
  // mux takes the signal numbers from it and nothing else.
  assert.equal(/\b(?:homedir|userInfo)\b/.test(code), false, 'it reads no home directory and no passwd entry')
  assert.deepEqual(importsFrom('images/worker/mux.mjs', MUX_SOURCE, 'node:os'), ['constants'], 'of node:os it imports constants alone')
  assert.deepEqual(importsFrom('probe.mjs', "import os, { homedir as h } from 'node:os'\nimport * as all from 'node:os'\nimport 'node:os'", 'node:os'), ['default', 'homedir', '*', '(for its side effects)'])
  assert.equal(/process\.argv/.test(code.replace('process.argv.slice(2)', '')), false, 'argv is read once, for the command')
  assert.match(code, /^if \(import\.meta\.main\) await main\(\)$/m, 'it runs only as the program, never when imported')
  // The contract the driver's argv is held to (S2): docker-init is PID 1, and reaps what the command orphans.
  assert.match(MUX_SOURCE, /^\/\/ {3}docker run --init -i --network none \.\.\. <image id> node \/opt\/aos\/mux\.mjs -- <command> \[args\.\.\.\]$/m)
  assert.equal(mux.MUX_HOST, '127.0.0.1')
  assert.equal(mux.MUX_PORT, 3128)
  const shipped = KernelConfig.parse(parseYaml(readFileSync(`${REPO}/config/kernel.yaml`, 'utf8')))
  assert.equal(mux.MUX_PORT, shipped.egress.muxPort, "the port the mux binds is the one kernel.yaml's egress.muxPort names")
})
