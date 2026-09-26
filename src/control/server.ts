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

import { createServer, type IncomingMessage, type Server as HttpServer } from 'node:http'
import type { Duplex } from 'node:stream'
import { randomUUID } from 'node:crypto'
import { WebSocketServer, type WebSocket } from 'ws'

import { ConfigError } from '../errors.js'
import type { EventStore } from '../events/store.js'
import { log } from '../log.js'
import {
  assertTokenUsable,
  authorizeUpgrade,
  digestToken,
  type RejectReason,
} from './auth.js'

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
  /** The dispatcher (T30) attaches here. */
  readonly onConnection?: (connection: ControlConnection) => void
}

export class ControlServer {
  readonly #store: EventStore
  readonly #port: number
  readonly #allowedOrigins: readonly string[]
  readonly #maxPayloadBytes: number
  readonly #onConnection: ((connection: ControlConnection) => void) | undefined
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

      this.#onConnection?.({ socket: ws, connectionId, origin: verdict.origin })
    })
  }

  async close(): Promise<void> {
    for (const client of this.#wss.clients) client.terminate()
    await new Promise<void>((resolve) => this.#wss.close(() => resolve()))
    await new Promise<void>((resolve) => this.#http.close(() => resolve()))
  }
}

/** Thrown by nothing here; re-exported so callers need one import for the seam. */
export { ConfigError }
