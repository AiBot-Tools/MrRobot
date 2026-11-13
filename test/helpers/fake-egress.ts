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

import './guard.js'

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { NetworkInterfaceInfo } from 'node:os'
import { duplexPair } from 'node:stream'

import { exitPayload, FrameChannel, readGoPayload, type Frame, type FrameLimits } from '../../src/egress/frame.js'
import { probeTarget, SELF_TEST } from '../../src/egress/ready.js'
import { createUpstream, type Upstream, type UpstreamDeps, type UpstreamLimits } from '../../src/egress/upstream.js'
import type { FakeChannel } from './fake-sandbox.js'

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
