// Fake egress ends: the container's mux and the upstream host, in process.
//
// A channel run's container is played through the fake driver's channel
// (FakeSandbox.channels): FakeMux speaks the mux's side of the frame protocol
// (src/egress/frame.ts, role 'mux') over the container's stdout and stdin,
// sends the ready report the kernel's judge accepts (src/egress/ready.ts),
// opens a flow per worker request and reads the kernel's answer. The upstream
// is the real createUpstream (src/egress/upstream.ts) over an injected
// resolver and dialer whose far end is an in-memory node:http host, so a
// request the kernel allows really is resolved, dialled and answered, and
// nothing listens, resolves or dials outside this process. `steps` records,
// in order, each resolve and dial, so a test can hold the decision row before
// the dial.
//
// Boot's egress canaries (src/runtime/canary.ts) are played the same way, as
// the worker image's mux plays them (canaryPlayer): the trusted one over its
// channel, a ready report, then CANARY_REQUEST on a flow and the exit status
// the mux sends for the kernel's answer; the hostile one as its self-test's
// line on stdout.

import './guard.js'

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { NetworkInterfaceInfo } from 'node:os'
import { duplexPair } from 'node:stream'

import { encodeFrame, exitPayload, FrameChannel, readGoPayload, type Frame, type FrameLimits } from '../../src/egress/frame.js'
import { probeTarget, SELF_TEST } from '../../src/egress/ready.js'
import { createUpstream, type Upstream, type UpstreamDeps, type UpstreamLimits } from '../../src/egress/upstream.js'
import { CANARY_PREFIX } from '../../src/runtime/canary.js'
import type { SandboxDomain, SandboxSpec } from '../../src/sandbox/driver.js'
import type { FakeChannel, ScriptedExit } from './fake-sandbox.js'

const EMPTY = new Uint8Array(0)

/** A report the kernel's judge accepts: every probe met, in order, by an error that says there is no route. */
export function quietReport(): Uint8Array {
  const probes = SELF_TEST.map((probe) => ({
    probe: probe.probe,
    target: probeTarget(probe),
    reached: false,
    error: probe.probe === 'lookup' ? 'ENOTFOUND' : /^[0-9.]+$/.test(probe.host) ? 'ENETUNREACH' : 'EAI_AGAIN',
  }))
  return Buffer.from(JSON.stringify({ mux: 1, probes, reached: 0 }), 'ascii')
}

/**
 * A report the kernel's judge refuses, as a container whose network is not
 * the --network none the kernel asked for would send it: its probe of
 * 192.168.5.2:8766 (pmmcp, on the Mac's loopback as a VM sees it) `reached`,
 * or `timed out` (ETIMEDOUT: a SYN that went somewhere), every other probe
 * as quietReport gives it.
 */
export function refusedReport(how: 'reached' | 'timed out'): Uint8Array {
  const quiet = JSON.parse(Buffer.from(quietReport()).toString('ascii')) as {
    mux: 1
    probes: { probe: string; target: string; reached: boolean; error: string | null }[]
    reached: number
  }
  const [first, ...rest] = quiet.probes
  if (first?.target !== '192.168.5.2:8766') throw new Error('SELF_TEST no longer starts with 192.168.5.2:8766')
  const probe = how === 'reached' ? { ...first, reached: true, error: null } : { ...first, error: 'ETIMEDOUT' }
  return Buffer.from(JSON.stringify({ mux: 1, probes: [probe, ...rest], reached: how === 'reached' ? 1 : 0 }), 'ascii')
}

/** A probe's kind, as the judge reads its codes: a connect by address or by name, or the lookup. */
export type ProbeKind = 'address' | 'name' | 'lookup'

/**
 * The errors a judge must refuse, by kind of probe (the mux's header, egress
 * plan E9's review round 2): a SYN that timed out or a host that is
 * unreachable went somewhere, EOTHER is no code that says there is no
 * route, an address is never looked up, and a lookup meets no network. The
 * minimal judge in test/egress-mux.test.ts and the boot canary's tests
 * (test/egress-boot.test.ts) refuse every one of these.
 */
export const REFUSED_PROBE_ERRORS: readonly { readonly kind: ProbeKind; readonly error: string | null }[] = Object.freeze([
  { kind: 'address', error: 'ETIMEDOUT' },
  { kind: 'address', error: 'EHOSTUNREACH' },
  { kind: 'address', error: 'EOTHER' },
  { kind: 'address', error: 'EAI_AGAIN' },
  { kind: 'name', error: 'ETIMEDOUT' },
  { kind: 'lookup', error: 'ETIMEDOUT' },
  { kind: 'lookup', error: 'ENETUNREACH' },
  { kind: 'lookup', error: null },
])

/** A probe's kind as a judge reads it. */
export function probeKind(probe: { readonly probe: 'connect' | 'lookup'; readonly host: string }): ProbeKind {
  return probe.probe === 'lookup' ? 'lookup' : /^[0-9.]+$/.test(probe.host) ? 'address' : 'name'
}

/**
 * quietReport with the first probe of `kind` met by `error` instead: a
 * report a judge must refuse, naming that probe and that code. The target
 * changed is returned beside it.
 */
export function reportWith(kind: ProbeKind, error: string | null): { readonly report: Uint8Array; readonly target: string } {
  const at = SELF_TEST.findIndex((probe) => probeKind(probe) === kind)
  const probe = SELF_TEST[at]
  if (probe === undefined) throw new Error(`SELF_TEST has no ${kind} probe`)
  const quiet = JSON.parse(Buffer.from(quietReport()).toString('ascii')) as {
    mux: 1
    probes: { probe: string; target: string; reached: boolean; error: string | null }[]
    reached: number
  }
  const probes = quiet.probes.map((p, i) => (i === at ? { ...p, error } : p))
  return { report: Buffer.from(JSON.stringify({ ...quiet, probes }), 'ascii'), target: probeTarget(probe) }
}

/**
 * The trusted canary's one request, as the worker image's mux's CANARY_REQUEST
 * spells it (test/egress-mux.test.ts holds the two equal): pmmcp on the
 * Mac's loopback as a Colima VM reaches it, which the kernel must deny.
 */
export const CANARY_REQUEST = 'GET http://192.168.5.2:8766/mcp HTTP/1.1\r\nHost: 192.168.5.2:8766\r\nConnection: close\r\n\r\n'

/** How a test has boot's canaries played (canaryPlayer). */
export interface CanaryPlay {
  /** The self-test report each domain's canary sends: the trusted one's ready, the hostile one's stdout line. Unset, quietReport(). */
  readonly report?: Readonly<Partial<Record<SandboxDomain, Uint8Array>>>
  /** The trusted canary's exit status in place of the mux's own (0 for a 403, 1 otherwise). */
  readonly status?: number
  /** False: the trusted canary sends no request once it has go, and goes straight to its exit frame (status, or 0). */
  readonly request?: false
  /** What a domain's canary does in place of the mux: exit as given, at once, or hang until killed. */
  readonly instead?: Readonly<Partial<Record<SandboxDomain, ScriptedExit | 'hang'>>>
  /** Every trusted canary's answer to its request, as the mux read it, in order. */
  readonly answers?: string[]
  /** How long the trusted canary waits, once it has read its answer, before its exit frame (real time). */
  readonly exitDelayMs?: number
  /**
   * What else the trusted canary sends, as a mux that broke the protocol or
   * its bounds would: `frame`, once go has come, a second ready report,
   * which the channel refuses (ready-twice), in place of its request; `flow`,
   * once it has read its answer, a second flow, past a maxRequests of 1, in
   * place of its exit frame. Either way it then runs until the kernel kills it.
   */
  readonly extra?: 'frame' | 'flow'
}

/**
 * FakeSandboxOptions.play for boot's egress canaries (a spec named under
 * CANARY_PREFIX), each played as the worker image's mux plays it: the
 * trusted one sends its ready report over the channel and, once the kernel
 * sends go, CANARY_REQUEST on a flow of its own; it sends 0 in its exit
 * frame when the kernel's answer begins with a 403, and 1 otherwise, and
 * then its container exits 0. One whose ready the kernel refuses gets no go,
 * and runs until the kernel kills it. The hostile one writes its report as
 * one line on stdout and exits 0. Every other spec is left to the script.
 */
export function canaryPlayer(play: CanaryPlay = {}): (spec: SandboxSpec, container: FakeChannel | undefined) => Promise<ScriptedExit> | undefined {
  return (spec, container) => {
    if (!spec.name.startsWith(CANARY_PREFIX)) return undefined
    const instead = play.instead?.[spec.domain]
    if (instead === 'hang') return new Promise<ScriptedExit>(() => undefined)
    if (instead !== undefined) return Promise.resolve(instead)
    const report = play.report?.[spec.domain] ?? quietReport()
    if (container === undefined) return Promise.resolve({ stdout: `${Buffer.from(report).toString('ascii')}\n` })
    return playTrustedCanary(container, report, play)
  }
}

async function playTrustedCanary(container: FakeChannel, report: Uint8Array, play: CanaryPlay): Promise<ScriptedExit> {
  let gone = false
  let ended: () => void = () => undefined
  const end = new Promise<undefined>((resolve) => {
    ended = () => resolve(undefined)
  })
  const leave = (): void => {
    gone = true
    ended()
  }
  container.stdin.once('end', leave)
  container.stdin.once('close', leave)
  const mux = new FakeMux(container)
  mux.send({ type: 'ready', flow: 0, payload: report })
  await until(() => mux.limits !== undefined || gone, 'go, or the container ended')
  // No go: the kernel refused the ready and killed the container, which
  // ended the run; what this resolves to is not read. Nor once the kernel
  // killed it mid-request (its log refused a row, say): a container that
  // has ended writes nothing more.
  if (gone) return {}
  if (play.request === false) {
    mux.exit(play.status ?? 0)
    return {}
  }
  if (play.extra === 'frame') {
    mux.raw(encodeFrame({ type: 'ready', flow: 0, payload: EMPTY }))
    await end
    return {}
  }
  const answer = await Promise.race([mux.request(CANARY_REQUEST), end])
  if (gone || answer === undefined) return {}
  play.answers?.push(answer)
  if (play.extra === 'flow') {
    mux.send({ type: 'open', flow: 2, payload: EMPTY })
    await end
    return {}
  }
  if (play.exitDelayMs !== undefined) {
    const delay = play.exitDelayMs
    await Promise.race([new Promise((resolve) => setTimeout(resolve, delay)), end])
    if (gone) return {}
  }
  mux.exit(play.status ?? (answer.startsWith('HTTP/1.1 403 ') ? 0 : 1))
  return {}
}

/** Real time, for streams to move. */
export async function until(condition: () => boolean, what: string, ms = 5_000): Promise<void> {
  const deadline = Date.now() + ms
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise((resolve) => setImmediate(resolve))
  }
}

interface Flow {
  readonly chunks: Buffer[]
  kernelClosed: boolean
  muxEnded: boolean
  muxClosed: boolean
}

/** The mux's side of one channel run's container. */
export class FakeMux {
  readonly #container: FakeChannel
  readonly #codec = new FrameChannel({ role: 'mux' })
  readonly #flows = new Map<number, Flow>()
  /** What the kernel sent, by type, in order. */
  readonly kernelFrames: string[] = []
  limits: FrameLimits | undefined

  constructor(container: FakeChannel) {
    this.#container = container
    container.stdin.on('data', (chunk: Buffer) => {
      const { frames, error } = this.#codec.receive(chunk)
      for (const frame of frames) {
        this.kernelFrames.push(frame.type)
        if (frame.type === 'go') this.limits = readGoPayload(frame.payload)
        const flow = this.#flows.get(frame.flow)
        if (flow === undefined) continue
        if (frame.type === 'data' && !frame.stale) flow.chunks.push(Buffer.from(frame.payload))
        if (frame.type === 'end') {
          // A worker that read its answer and hung up.
          this.#end(frame.flow, flow)
          this.#close(frame.flow, flow)
        }
        if (frame.type === 'close') {
          flow.kernelClosed = true
          this.#close(frame.flow, flow)
        }
      }
      if (error !== undefined) throw error
    })
  }

  send(frame: Frame): void {
    this.#container.stdout.write(this.#codec.send(frame))
  }

  /** Bytes the codec would never send: a container that breaks the protocol. */
  raw(bytes: Uint8Array): void {
    this.#container.stdout.write(bytes)
  }

  /** The ready report, then the kernel's go. */
  async ready(report: Uint8Array = quietReport()): Promise<void> {
    this.send({ type: 'ready', flow: 0, payload: report })
    await until(() => this.limits !== undefined, 'go')
  }

  /** One worker request on a flow of its own; what the kernel answered, once it closed the flow. */
  async request(raw: string): Promise<string> {
    const id = this.#codec.flowsOpened + 1
    const flow: Flow = { chunks: [], kernelClosed: false, muxEnded: false, muxClosed: false }
    this.#flows.set(id, flow)
    this.send({ type: 'open', flow: id, payload: EMPTY })
    this.send({ type: 'data', flow: id, payload: Buffer.from(raw, 'latin1') })
    await until(() => flow.kernelClosed, `the kernel's close of flow ${String(id)}`)
    return Buffer.concat(flow.chunks).toString('latin1')
  }

  stdout(text: string): void {
    this.send({ type: 'stdout', flow: 0, payload: Buffer.from(text, 'utf8') })
  }

  stderr(text: string): void {
    this.send({ type: 'stderr', flow: 0, payload: Buffer.from(text, 'utf8') })
  }

  /** The command's exit status, as the mux sends it once its pipes have closed. */
  exit(status: number): void {
    this.send({ type: 'exit', flow: 0, payload: exitPayload(status) })
  }

  #end(id: number, flow: Flow): void {
    if (flow.muxEnded || flow.muxClosed) return
    flow.muxEnded = true
    this.send({ type: 'end', flow: id, payload: EMPTY })
  }

  #close(id: number, flow: Flow): void {
    if (flow.muxClosed) return
    flow.muxClosed = true
    this.send({ type: 'close', flow: id, payload: EMPTY })
  }
}

/** A request the in-memory host read. */
export interface SeenRequest {
  readonly method: string
  readonly url: string
  readonly rawHeaders: readonly string[]
}

export interface FakeUpstream {
  readonly upstream: Upstream
  /** `resolve4 <name>` and `dial <host>`, in order, as the upstream asked. */
  readonly steps: string[]
  readonly seen: SeenRequest[]
}

/** A Mac with loopback and a private LAN address: no answer below is one of its own. */
const PLAIN_MAC: NodeJS.Dict<NetworkInterfaceInfo[]> = {
  lo0: [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' }],
  en0: [{ address: '192.168.1.20', netmask: '255.255.255.0', family: 'IPv4', mac: '02:00:00:00:00:01', internal: false, cidr: '192.168.1.20/24' }],
}

const OK = (_req: IncomingMessage, res: ServerResponse): void => {
  res.writeHead(200, { 'content-type': 'text/plain' }).end('upstream-ok')
}

export interface FakeUpstreamDeps {
  /**
   * systemUpstreamDeps's place: deps over the in-process resolver and dialer,
   * carrying the timeouts it is handed, each call's recorded in `limits`.
   */
  readonly deps: (limits: UpstreamLimits) => UpstreamDeps
  readonly limits: UpstreamLimits[]
  /** `resolve4 <name>` and `dial <host>`, in order, as the upstream asked. */
  readonly steps: string[]
  readonly seen: SeenRequest[]
}

/**
 * The real upstream over an in-process resolver (every name a public
 * address) and dialer (a duplex pair whose far end an unlistened node:http
 * server reads, its TLS handshake reported done), `onStep` told of each
 * resolve and dial as it is asked, before it answers.
 */
export function fakeUpstream(onStep: (step: string) => void = () => undefined, serve = OK): FakeUpstream {
  const { deps, steps, seen } = fakeUpstreamDeps(onStep, serve)
  return { upstream: createUpstream(deps({ connectTimeoutMs: 5_000, idleTimeoutMs: 5_000 })), steps, seen }
}

/**
 * fakeUpstream's resolver, dialer and host as the deps systemUpstreamDeps
 * would build, for boot to make its production upstream over
 * (BootOptions.egressUpstreamDeps): the timeouts are boot's, recorded.
 */
export function fakeUpstreamDeps(onStep: (step: string) => void = () => undefined, serve = OK): FakeUpstreamDeps {
  const limits: UpstreamLimits[] = []
  const steps: string[] = []
  const seen: SeenRequest[] = []
  const step = (text: string): void => {
    steps.push(text)
    onStep(text)
  }
  const host = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      seen.push({ method: req.method ?? '', url: req.url ?? '', rawHeaders: req.rawHeaders })
      serve(req, res)
    })
  })
  const resolver: UpstreamDeps['resolver'] = () => ({
    resolve4: (name) => {
      step(`resolve4 ${name}`)
      return Promise.resolve(['140.82.112.3'])
    },
    resolve6: () => Promise.resolve([]),
    cancel: () => undefined,
  })
  const dial: UpstreamDeps['dial'] = (options) => {
    step(`dial ${String(options.host)}`)
    const [client, far] = duplexPair()
    far.on('error', () => undefined)
    far.once('close', () => client.destroy(Object.assign(new Error('the host hung up'), { code: 'ECONNRESET' })))
    host.emit('connection', far)
    const socket = Object.assign(client, { authorized: false, setTimeout: (): unknown => undefined })
    setImmediate(() => {
      socket.authorized = true
      socket.emit('secureConnect')
    })
    return socket
  }
  const deps = (given: UpstreamLimits): UpstreamDeps => {
    limits.push({ connectTimeoutMs: given.connectTimeoutMs, idleTimeoutMs: given.idleTimeoutMs })
    return {
      resolver,
      dial,
      interfaces: () => PLAIN_MAC,
      connectTimeoutMs: given.connectTimeoutMs,
      idleTimeoutMs: given.idleTimeoutMs,
    }
  }
  return { deps, limits, steps, seen }
}
