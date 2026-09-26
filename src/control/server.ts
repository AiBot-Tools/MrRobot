// Control server — loopback socket, header-only auth (invariant 1).
//
// Three properties, each enforced structurally rather than by convention:
//
//   It binds 127.0.0.1, spelled as a literal. `0.0.0.0` on a laptop that joins
//   a café network is a kernel anyone on that network can drive, and the one
//   character between the two is not a difference a config default should be
//   trusted with.
//
//   It refuses to construct without a usable token. Not a warning at boot — a
//   throw. A control plane with no token is a control plane every process on
//   the machine can drive, and there is no useful degraded version of that.
//
//   It keeps only the token's sha256 digest. The raw value is validated,
//   digested and dropped, so a heap dump, a crash report or an object
//   inspection finds a digest.
//
// `maxPayload` is set to TWICE the protocol's limit, deliberately. `ws`
// enforces its own ceiling by closing the socket with 1009 and the frame never
// reaches a handler — MEASURED, not assumed (ws 8.21.3: RangeError
// 'Max payload size exceeded', code WS_ERR_UNSUPPORTED_MESSAGE_LENGTH,
// status 1009, and the connection's message handler is never called). So a
// frame between 1x and 2x gets the protocol's `payload_too_large` reply from
// the dispatcher's own byte check, and only something truly enormous gets the
// hard close. A single ceiling would mean the polite reply could never happen.
//
// One thing that ceiling does NOT do by itself: the same measurement showed
// the oversized frame emits an `error` event on the server-side socket, and an
// unhandled 'error' event ENDS THE PROCESS. Without the handler below, any
// client could stop the daemon with one frame. That is why every connection
// gets an error handler before anything else.

// ── dispatch ───────────────────────────────────────────────────────────────
//
// One `HumanActor` is minted per authenticated CONNECTION, here, and nowhere
// else. Every action that invariants 3 and 6 reserve for a person — promote,
// archive, approve, deny, release — demands one, and the actor's private-field
// brand cannot be forged by an object literal, a JSON round-trip or
// Object.create. So "a human did this" is a structural fact about the call
// path rather than a claim in a comment: the only way to obtain an actor is to
// have completed an authenticated upgrade.
//
// A bad frame gets a reply and the socket survives, because a UI with a bug
// should see its mistake rather than be disconnected mid-session. Three of
// them close it, because at that point the peer is not speaking this protocol
// and every further frame is noise. An oversized frame is one of the three:
// a client that keeps sending them is doing the same thing as one sending
// garbage.

import { createServer, type IncomingMessage, type Server as HttpServer } from 'node:http'
import type { Duplex } from 'node:stream'
import { randomUUID } from 'node:crypto'
import { WebSocketServer, type WebSocket } from 'ws'

import { ConfigError, PolicyDenied } from '../errors.js'
import type { EventRow } from '../events/chain.js'
import type { EventStore } from '../events/store.js'
import { log } from '../log.js'
import { VERSION } from '../version.js'
import type { Approvals } from '../policy/approvals.js'
import type { Quarantine } from '../policy/quarantine.js'
import { mintHumanActor, type HumanActor } from './actor.js'
import {
  assertTokenUsable,
  authorizeUpgrade,
  digestToken,
  type RejectReason,
} from './auth.js'
import {
  approvalsListView,
  eventView,
  type RunState,
} from './views.js'
import {
  COMMAND_SCHEMAS,
  parseFrame,
  PROTOCOL_VERSION,
  type AgentSummary,
  type Command,
  type ErrorCode,
  type ModelSummary,
  type ProbeRecordResult,
  type RunDetail,
  type RunSummary,
  type StatusResult,
} from './protocol.js'

/** Consecutive-or-not bad frames a connection may send before it is closed. */
export const MAX_BAD_FRAMES = 3

/** A handler's refusal, carrying the protocol code the reply should use. */
export class ControlError extends Error {
  readonly code: ErrorCode

  constructor(code: ErrorCode, message: string) {
    super(message)
    this.name = 'ControlError'
    this.code = code
  }
}

/**
 * Everything the dispatcher needs from the kernel, and nothing more.
 *
 * Passed in rather than reached for, so the control plane owns no kernel state
 * and T33's boot decides what each capability really is. A test supplies real
 * components for what it exercises.
 */
export interface ControlSurface {
  readonly store: EventStore
  readonly approvals: Approvals
  readonly quarantine: Quarantine
  readonly status: () => StatusResult
  readonly agents: (includeArchived: boolean) => AgentSummary[]
  /** Resolves the promotion approval AND promotes, as one human action. */
  readonly promote: (approvalId: string, actor: HumanActor) => { agentId: string }
  readonly archive: (agentId: string, actor: HumanActor, reason: string | undefined) => void
  readonly startRun: (input: {
    agentId: string
    input: string
    goalId?: string | undefined
    taint?: 'clean' | 'tainted' | undefined
  }) => string
  readonly killRun: (runId: string, reason: string | undefined) => RunSummary['status']
  readonly runs: (filter: { status?: RunSummary['status']; limit?: number }) => RunSummary[]
  readonly run: (runId: string) => RunDetail | undefined
  readonly models: () => ModelSummary[]
  readonly probeModel: (ref: string) => Promise<ProbeRecordResult>
}

/** The host, as a literal. Not a parameter, not a default. */
export const CONTROL_HOST = '127.0.0.1' as const

export interface ControlConnection {
  readonly socket: WebSocket
  readonly connectionId: string
  readonly origin: string | undefined
}

export interface ControlServerOptions {
  readonly store: EventStore
  readonly port: number
  /** The operator's raw token. Validated, digested, and then dropped. */
  readonly token: string | undefined
  readonly allowedOrigins?: readonly string[]
  readonly maxPayloadBytes: number
  /** Absent means auth only: the upgrade works and no command is served. */
  readonly surface?: ControlSurface | undefined
  readonly onConnection?: (connection: ControlConnection) => void
}

export class ControlServer {
  readonly #store: EventStore
  readonly #port: number
  readonly #allowedOrigins: readonly string[]
  readonly #maxPayloadBytes: number
  readonly #onConnection: ((connection: ControlConnection) => void) | undefined
  readonly #surface: ControlSurface | undefined
  readonly #sockets = new Set<WebSocket>()
  #unsubscribe: (() => void) | undefined
  /** The digest. The raw token is never a field on this object. */
  readonly #tokenDigest: Buffer
  readonly #http: HttpServer
  readonly #wss: WebSocketServer
  #boundPort: number | undefined

  constructor(options: ControlServerOptions) {
    // Throws when absent or under the floor. Validated here so no partially
    // constructed server can exist with a token nobody checked.
    const token = assertTokenUsable(options.token)
    this.#tokenDigest = digestToken(token)

    this.#store = options.store
    this.#port = options.port
    this.#allowedOrigins = options.allowedOrigins ?? []
    this.#maxPayloadBytes = options.maxPayloadBytes
    this.#onConnection = options.onConnection
    this.#surface = options.surface

    // Event fan-out: every appended event reaches every authenticated client.
    if (options.surface !== undefined) {
      this.#unsubscribe = options.store.subscribe((row) => {
        this.#broadcast(row)
      })
    }

    // Every plain HTTP request is a 404. The control plane is a WebSocket
    // endpoint; there is no page to serve and nothing to discover by probing.
    this.#http = createServer((_req, res) => {
      res.writeHead(404, { 'content-type': 'text/plain', connection: 'close' })
      res.end('not found\n')
    })

    this.#wss = new WebSocketServer({ noServer: true, maxPayload: 2 * this.#maxPayloadBytes })
    this.#http.on('upgrade', (req, socket, head) => {
      this.#handleUpgrade(req, socket, head)
    })
  }

  get port(): number {
    return this.#boundPort ?? this.#port
  }

  /**
   * The address actually bound, read back from the socket.
   *
   * Exposed so a test can assert the loopback bind rather than trusting that
   * the literal reached `listen` — a loopback client reaches a 0.0.0.0
   * listener perfectly well, so nothing about a successful connection proves
   * the server is not on every interface.
   */
  get boundAddress(): string | undefined {
    const address = this.#http.address()
    return typeof address === 'object' && address !== null ? address.address : undefined
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve, reject) => {
      this.#http.once('error', reject)
      // The literal. A bind address is not something to take from config.
      this.#http.listen(this.#port, CONTROL_HOST, () => {
        this.#http.removeListener('error', reject)
        resolve()
      })
    })
    const address = this.#http.address()
    this.#boundPort = typeof address === 'object' && address !== null ? address.port : this.#port
    return this.#boundPort
  }

  #reject(socket: Duplex, reason: RejectReason, origin: string | undefined): void {
    // The wire says only "unauthorized". Naming which check failed would tell
    // someone probing the socket whether their token was wrong or their origin
    // was — the reason belongs in the log, not the response.
    try {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
    } catch {
      // A socket that died mid-rejection is already rejected.
    }
    socket.destroy()

    // No token, ever — not even a prefix or a length.
    this.#store.append({
      type: 'control.rejected',
      payload: { schemaVersion: 1, reason, ...(origin === undefined ? {} : { origin }) },
    })
    log.warn({ reason, origin }, 'control upgrade rejected')
  }

  #handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    const verdict = authorizeUpgrade(
      { url: req.url, headers: { authorization: req.headers.authorization, origin: req.headers.origin } },
      { tokenDigest: this.#tokenDigest, allowedOrigins: this.#allowedOrigins },
    )

    if (!verdict.ok) {
      this.#reject(socket, verdict.reason, verdict.origin)
      return
    }

    this.#wss.handleUpgrade(req, socket, head, (ws) => {
      const connectionId = randomUUID()

      // BEFORE anything else. An oversized frame makes `ws` emit 'error' on
      // this socket, and an unhandled 'error' event ends the process — one
      // frame from any client would stop the daemon.
      ws.on('error', (error: Error & { code?: string }) => {
        log.warn({ connectionId, code: error.code, message: error.message }, 'control socket error')
      })

      this.#store.append({
        type: 'control.connected',
        payload: {
          schemaVersion: 1,
          connectionId,
          ...(verdict.origin === undefined ? {} : { origin: verdict.origin }),
        },
      })

      this.#sockets.add(ws)
      ws.on('close', () => {
        this.#sockets.delete(ws)
      })

      // ONE actor per connection, minted here and nowhere else. Its
      // private-field brand cannot be forged, so "a human did this" is a fact
      // about the call path rather than a claim in a comment.
      if (this.#surface !== undefined) this.#serve(ws, mintHumanActor(connectionId))

      this.#onConnection?.({ socket: ws, connectionId, origin: verdict.origin })
    })
  }

  #send(socket: WebSocket, frame: unknown): void {
    if (socket.readyState !== socket.OPEN) return
    try {
      socket.send(JSON.stringify(frame))
    } catch (e) {
      log.warn({ err: e }, 'control send failed')
    }
  }

  #broadcast(row: EventRow): void {
    const frame = { v: PROTOCOL_VERSION, event: eventView(row) }
    for (const socket of this.#sockets) this.#send(socket, frame)
  }

  /** Attach the dispatcher to one authenticated socket. */
  #serve(socket: WebSocket, actor: HumanActor): void {
    const surface = this.#surface
    if (surface === undefined) return

    // The first frame, before any command. A UI knows the protocol version and
    // the kernel's state without having to ask.
    this.#send(socket, {
      v: PROTOCOL_VERSION,
      protocol: PROTOCOL_VERSION,
      kernel: { version: VERSION },
      status: surface.status(),
    })

    let badFrames = 0
    socket.on('message', (data: Buffer, isBinary: boolean) => {
      void (async () => {
        // Bytes, not characters, and before JSON.parse — the same check the
        // protocol defines, so an oversized frame is refused identically here
        // and in a unit test.
        const parsed = parseFrame(isBinary ? new Uint8Array(data) : data.toString('utf8'), this.#maxPayloadBytes)

        if (!parsed.ok) {
          badFrames++
          this.#send(socket, {
            v: PROTOCOL_VERSION,
            id: parsed.id ?? 'unknown',
            ok: false,
            error: { code: parsed.code, message: parsed.message },
          })
          // A UI with a bug should see its mistake, not be disconnected
          // mid-session. Three of them and the peer is not speaking this
          // protocol, so every further frame is noise.
          if (badFrames >= MAX_BAD_FRAMES) socket.close(1008, 'too many bad frames')
          return
        }

        const { id, cmd, params } = parsed.frame
        try {
          const schema = COMMAND_SCHEMAS[cmd]
          const args = schema.params.safeParse(params)
          if (!args.success) {
            throw new ControlError('bad_request', args.error.message)
          }
          const result = await this.#run(cmd, args.data as Record<string, unknown>, surface, actor)

          // Validated against the FROZEN schema before it leaves. A UI parses
          // these shapes, so the kernel must not be able to send one the
          // freeze does not allow — a drifting view is caught here rather than
          // in someone's app.
          const checked = schema.result.safeParse(result)
          if (!checked.success) {
            throw new ControlError(
              'internal',
              `${cmd} produced a result the protocol does not allow: ${checked.error.message}`,
            )
          }
          this.#send(socket, { v: PROTOCOL_VERSION, id, ok: true, result: checked.data })
        } catch (e) {
          const { code, message } = toControlError(e)
          this.#send(socket, { v: PROTOCOL_VERSION, id, ok: false, error: { code, message } })
        }
      })()
    })
  }

  async #run(
    cmd: Command,
    params: Record<string, unknown>,
    surface: ControlSurface,
    actor: HumanActor,
  ): Promise<unknown> {
    const str = (key: string): string => String(params[key] ?? '')
    const maybe = (key: string): string | undefined =>
      typeof params[key] === 'string' ? (params[key] as string) : undefined

    switch (cmd) {
      case 'status.get':
        return surface.status()

      case 'agents.list':
        return surface.agents(params['includeArchived'] === true)

      case 'agent.promote': {
        // Invariant 6: the ONLY command that promotes, and it takes a human's
        // approval rather than an agent id, so requesting and granting cannot
        // be the same act.
        const pending = surface.approvals.pending().find((a) => a.approvalId === str('approvalId'))
        if (pending === undefined) throw new ControlError('not_found', 'no such pending approval')
        if (pending.kind !== 'promotion') {
          throw new ControlError('bad_request', 'that approval is not a promotion; use approval.approve')
        }
        // The protocol shape is the dispatcher's to produce: a promotion
        // always yields a standard agent, which is a protocol fact rather
        // than something each surface should have to remember.
        return { agentId: surface.promote(str('approvalId'), actor).agentId, kind: 'standard' }
      }

      case 'agent.archive':
        surface.archive(str('agentId'), actor, maybe('reason'))
        return { agentId: str('agentId'), status: 'archived' }

      case 'run.start':
        return {
          runId: surface.startRun({
            agentId: str('agentId'),
            input: str('input'),
            goalId: maybe('goalId'),
            taint: maybe('taint') as 'clean' | 'tainted' | undefined,
          }),
        }

      case 'run.kill':
        return { runId: str('runId'), status: surface.killRun(str('runId'), maybe('reason')) }

      case 'runs.list':
        return surface.runs({
          ...(maybe('status') === undefined ? {} : { status: maybe('status') as RunSummary['status'] }),
          ...(typeof params['limit'] === 'number' ? { limit: params['limit'] } : {}),
        })

      case 'run.get': {
        const detail = surface.run(str('runId'))
        if (detail === undefined) throw new ControlError('not_found', 'no such run')
        return detail
      }

      case 'approvals.list':
        return approvalsListView(surface.approvals.pending(), surface.quarantine.pending())

      case 'approval.approve': {
        const pending = surface.approvals.pending().find((a) => a.approvalId === str('approvalId'))
        if (pending === undefined) throw new ControlError('not_found', 'no such pending approval')
        // Exactly one command can promote, and this is not it.
        if (pending.kind === 'promotion') {
          throw new ControlError('bad_request', 'use agent.promote')
        }
        surface.approvals.resolve(str('approvalId'), actor, 'approved')
        return { approvalId: str('approvalId'), resolved: true }
      }

      case 'approval.deny':
        // Both kinds: denying a promotion needs no promotion path.
        surface.approvals.resolve(str('approvalId'), actor, 'denied')
        return { approvalId: str('approvalId'), resolved: true }

      case 'quarantine.release': {
        const released = surface.quarantine.release(str('holdId'), actor)
        // D17: a release always taints the run, so the reply says so rather
        // than leaving a UI to infer it.
        return { holdId: released.holdId, released: true, runTainted: true }
      }

      case 'events.query': {
        const types = Array.isArray(params['types']) ? (params['types'] as string[]) : undefined
        const text = maybe('text')
        const afterSeq = typeof params['afterSeq'] === 'number' ? params['afterSeq'] : 0
        const limit = typeof params['limit'] === 'number' ? params['limit'] : 200
        const rows = surface.store
          .query(maybe('runId') === undefined ? {} : { runId: str('runId') })
          .filter((r) => r.seq > afterSeq)
          .filter((r) => types === undefined || types.includes(r.type))
          .filter((r) => text === undefined || r.payload.includes(text))
          .slice(0, limit)
        return rows.map(eventView)
      }

      case 'chain.verify': {
        const outcome = surface.store.verifyChain()
        if (!outcome.ok) return { ok: false, at: outcome.at, reason: outcome.reason }
        return {
          ok: true,
          count: outcome.count,
          head: outcome.count === 0 ? null : { seq: outcome.count, hash: outcome.head },
        }
      }

      case 'models.list':
        return surface.models()

      case 'model.probe':
        return surface.probeModel(str('ref'))
    }
  }

  async close(): Promise<void> {
    this.#unsubscribe?.()
    for (const client of this.#wss.clients) client.terminate()
    await new Promise<void>((resolve) => this.#wss.close(() => resolve()))
    await new Promise<void>((resolve) => this.#http.close(() => resolve()))
  }
}

/** Map any thrown value onto a protocol error code. */
function toControlError(e: unknown): { code: ErrorCode; message: string } {
  if (e instanceof ControlError) return { code: e.code, message: e.message }
  // A refusal a human already answered, or one that no longer applies, is a
  // conflict rather than a bad request: the caller did nothing wrong, the
  // world moved.
  if (e instanceof PolicyDenied) return { code: 'conflict', message: e.reason }
  if (e instanceof TypeError) return { code: 'forbidden', message: e.message }
  const message = e instanceof Error ? e.message : String(e)
  if (/not implemented in this phase/.test(message)) return { code: 'not_implemented', message }
  return { code: 'internal', message }
}

/** Thrown by nothing here; re-exported so callers need one import for the seam. */
export { ConfigError }
