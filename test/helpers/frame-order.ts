// A second evaluator of the channel's frame rules, for the check order (egress
// plans E7 and E9), shared by test/egress-frame.test.ts and
// test/egress-mux.test.ts.
//
// The rules as src/egress/frame.ts's CHECK ORDER table states them, each
// judged on its own whatever the rules before it found, written out here
// rather than read from frame.ts. It says which rules a frame breaks, never
// which one refuses it: that is the first of them in the check order. So it
// can say what a check-order script's last frame breaks (its name must list
// exactly that), and, walked over the states an end can reach, every place
// two rules meet. And, walked with a real codec beside it (differential), it
// holds that codec to the first rule broken for every probe frame in every
// state the walk reaches, not one witness per pair: frame.ts reaches the same
// pair along different code paths (a type's fixed length or frameMaxBytes,
// before ready or between ready and go), and a reorder on a path no witness
// takes would pass every vector.
//
// Pure: it imports the network guard, as every helper does, and frame.ts's
// types, nothing else, so the mux's test holds the inline codec to the same
// evaluator with no second copy of it.

import './guard.js'

import type { ChannelRole, FrameLimits, FrameRefusal, FrameType } from '../../src/egress/frame.js'

/** Which way a refusal was met: decoding what the other end sent (finish() included), or holding this end's own send. */
export type Side = 'receive' | 'send'
export const SIDES: readonly Side[] = ['receive', 'send']

/** The check order, written out: FRAME_REFUSALS lists it, then finish()'s two. */
export const CHECK_ORDER: readonly FrameRefusal[] = [
  'unknown-type', 'direction', 'channel-flow', 'flow-zero', 'ready-twice', 'not-ready', 'go-twice', 'before-go',
  'length', 'oversize', 'after-exit', 'flow-order', 'max-flows', 'unopened-flow', 'closed-flow', 'after-close',
  'after-end', 'peer-closed', 'go-value',
]

export interface EvRule {
  readonly code: number
  readonly from: readonly ChannelRole[]
  readonly channel: boolean
  readonly min: number
  readonly max: number | 'frameMaxBytes'
}

/** frame.ts's table of types, written out: code, sender, flow 0 or a flow, payload length. */
export const EV_RULES: Readonly<Record<FrameType, EvRule>> = {
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
export const EV_TYPES = Object.keys(EV_RULES) as FrameType[]
export const EV_TYPE_OF: ReadonlyMap<number, FrameType> = new Map(EV_TYPES.map((t) => [EV_RULES[t].code, t]))
export const otherEnd = (role: ChannelRole): ChannelRole => (role === 'kernel' ? 'mux' : 'kernel')

interface EvFlow {
  readonly kernel: { ended: boolean; closed: boolean }
  readonly mux: { ended: boolean; closed: boolean }
}

/** One end's state: what has crossed, and the flows not yet retired. */
export interface EvState {
  readonly role: ChannelRole
  ready: boolean
  go: boolean
  exited: boolean
  last: number
  readonly flows: Map<number, EvFlow>
  limits: FrameLimits | undefined
}

export const evFresh = (role: ChannelRole, limits: FrameLimits | undefined): EvState => ({
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
export function evBroken(s: EvState, from: ChannelRole, code: number, flow: number, length: number, payload: Uint8Array | undefined): Set<FrameRefusal> {
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

/** The refusal a frame meets: the first rule it breaks in the check order, or none. */
export function firstBroken(breaks: ReadonlySet<FrameRefusal>): FrameRefusal | undefined {
  return CHECK_ORDER.find((rule) => breaks.has(rule))
}

/** A frame that broke nothing changes the state both ends share. */
export function evApply(s: EvState, from: ChannelRole, type: FrameType, flow: number, payload: Uint8Array): void {
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
export function pairsOf(breaks: ReadonlySet<FrameRefusal>): string[] {
  const [first, ...rest] = CHECK_ORDER.filter((r) => breaks.has(r))
  return first === undefined ? [] : rest.map((later) => `${first} before ${later}`)
}

/** The limits the walk runs under: small enough to reach the cap, a retired flow and exit in a few frames. */
export const WALK_LIMITS: FrameLimits = Object.freeze({ frameMaxBytes: 4, maxFlows: 2 })

/** The most flows the walk opens: two reach the cap, and no rule reads a flow but the one a frame names and how many are open. */
const MOST_OPENED = 2

/** What drives the walk: one payload of each type that breaks nothing, so every move is a frame an end may send. */
const EV_MOVES: Readonly<Record<FrameType, Uint8Array>> = {
  ready: new TextEncoder().encode('ok'),
  go: Uint8Array.of(0, 0, 0, 4, 0, 0, 0, 2),
  open: new Uint8Array(0),
  data: new TextEncoder().encode('a'),
  end: new Uint8Array(0),
  close: new Uint8Array(0),
  stdout: new TextEncoder().encode('a'),
  stderr: new TextEncoder().encode('a'),
  exit: Uint8Array.of(0),
}

/** A frame the walk moved by: sent by this end, or received from the other. */
export interface WalkMove {
  readonly side: Side
  readonly type: FrameType
  readonly flow: number
  readonly payload: Uint8Array
}

/** A frame the walk asks of a state: any type byte, flow and length, so it may break any rule. */
export interface Probe {
  readonly code: number
  readonly flow: number
  readonly length: number
  readonly payload: Uint8Array
}

const GO_PROBES: readonly Uint8Array[] = [EV_MOVES.go, Uint8Array.of(0, 0, 0, 5, 0, 0, 0, 2), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 2)]

/**
 * The probes at a state, one way: every type byte (and, received, one that
 * names none; send() takes only a frame encodeFrame can spell), flow 0 to two
 * past the last opened, and payloads of 0, 1, 5, 8 and 4097 bytes, which fall
 * below every positive least, inside data's and exit's, past frameMaxBytes 4
 * and exit's 1, at go's 8 and past ready's 4096: a go of 8 naming the walk's
 * limits, others in range and one out of it.
 */
export function probesAt(s: EvState, side: Side): Probe[] {
  const codes = side === 'send' ? EV_TYPES.map((t) => EV_RULES[t].code) : [0x00, ...EV_TYPES.map((t) => EV_RULES[t].code)]
  const out: Probe[] = []
  for (const code of codes) {
    for (let flow = 0; flow <= s.last + 2; flow++) {
      for (const length of [0, 1, 5, 8, 4097]) {
        const payloads = code === EV_RULES.go.code && length === 8 ? GO_PROBES : [new Uint8Array(length)]
        for (const payload of payloads) out.push({ code, flow, length, payload })
      }
    }
  }
  return out
}

/**
 * Every state an end of `role` can reach with frameMaxBytes 4 and maxFlows 2
 * (WALK_LIMITS; a kernel end holds them from the start, a mux end learns them
 * from go), moved only by frames that break nothing, each handed to `visit`
 * once with the moves that reached it. A walk that opens more than two flows
 * finds nothing new (one that opens up to four, five times the states, was
 * run when this was written: the same pairs).
 */
export function walkStates(role: ChannelRole, visit: (s: EvState, path: readonly WalkMove[]) => void): number {
  const start = evFresh(role, role === 'kernel' ? WALK_LIMITS : undefined)
  const seen = new Set<string>([evKey(start)])
  const queue: Array<readonly [EvState, readonly WalkMove[]]> = [[start, []]]
  let states = 0
  for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
    const [s, path] = next
    states++
    visit(s, path)
    for (const side of SIDES) {
      const from = side === 'send' ? role : otherEnd(role)
      for (const type of EV_TYPES) {
        for (let flow = 0; flow <= s.last + 1; flow++) {
          const payload = EV_MOVES[type]
          if (evBroken(s, from, EV_RULES[type].code, flow, payload.length, payload).size > 0) continue
          if (type === 'open' && flow > MOST_OPENED) continue
          const moved = evCopy(s)
          evApply(moved, from, type, flow, payload)
          const key = evKey(moved)
          if (seen.has(key)) continue
          seen.add(key)
          queue.push([moved, [...path, { side, type, flow, payload }]])
        }
      }
    }
  }
  return states
}

/** The wire of a probe, its type byte as given (one that names no type included): LENGTH(4) TYPE(1) FLOW(4) PAYLOAD. */
export function probeWire(probe: Probe): Uint8Array {
  const wire = Buffer.alloc(9 + probe.payload.length)
  wire.writeUInt32BE(probe.length, 0)
  wire.writeUInt8(probe.code, 4)
  wire.writeUInt32BE(probe.flow, 5)
  Buffer.from(probe.payload).copy(wire, 9)
  return Uint8Array.from(wire)
}

/** What a codec must answer for the differential: frame.ts's FrameChannel, or the mux's inline MuxChannel. */
export interface CodecEnd {
  receive(chunk: Uint8Array): { readonly frames: readonly unknown[]; readonly error?: { readonly refusal: string } | undefined }
  sendRefusal(frame: { readonly type: FrameType; readonly flow: number; readonly payload: Uint8Array }): { readonly refusal: string } | undefined
}

/**
 * Hold a codec to the evaluator in every state the walk reaches: for every
 * probe, each way, the codec's refusal (receive() on an end `build` rebuilt
 * from the walk's path, which a refusal or an accepted frame changes, so one
 * per probe; and sendRefusal(), which changes nothing, so one end per state)
 * must be the first rule the evaluator finds broken in the check order, or
 * none, in which case receive() hands back the frame. Returns the probes
 * compared and every one that differed, described.
 */
export function differential(role: ChannelRole, build: (path: readonly WalkMove[]) => CodecEnd): { readonly states: number; readonly checks: number; readonly mismatches: readonly string[] } {
  let checks = 0
  const mismatches: string[] = []
  const states = walkStates(role, (s, path) => {
    const where = (): string => JSON.stringify({ ready: s.ready, go: s.go, exited: s.exited, last: s.last, flows: [...s.flows] })
    const sending = build(path)
    for (const side of SIDES) {
      const from = side === 'send' ? role : otherEnd(role)
      for (const probe of probesAt(s, side)) {
        checks++
        const expected = firstBroken(evBroken(s, from, probe.code, probe.flow, probe.length, probe.payload))
        let got: string | undefined
        if (side === 'send') {
          const type = EV_TYPE_OF.get(probe.code)
          if (type === undefined) continue
          got = sending.sendRefusal({ type, flow: probe.flow, payload: probe.payload })?.refusal
        } else {
          const result = build(path).receive(probeWire(probe))
          got = result.error?.refusal
          if (got === undefined && result.frames.length !== 1) got = `${String(result.frames.length)} frames`
        }
        if (got !== expected && mismatches.length < 20) {
          mismatches.push(`${role} ${side} at ${where()}: code ${String(probe.code)} flow ${String(probe.flow)} length ${String(probe.length)} payload ${Buffer.from(probe.payload).toString('hex').slice(0, 16)}: expected ${String(expected)}, got ${String(got)}`)
        }
      }
    }
  })
  return { states, checks, mismatches }
}
