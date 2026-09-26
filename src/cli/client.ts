// Control-plane client for the CLI.
//
// The token goes in the Authorization header, unconditionally and by
// construction: there is no branch here that reads a URL parameter, no option
// that would put one there, and no "global client" fallback that a later edit
// could reach for. A URL travels through process lists, shell history and proxy
// logs; the server refuses a query-string credential outright (T29), so a
// client that sent one would not work anyway — but the reason it cannot is
// that the code has nowhere to put it.
//
// The URL is hard-coded loopback. A control client that could be pointed at
// another host would be a way to send the operator's token somewhere else.

import { WebSocket } from 'ws'

import {
  CONTROL_PATH,
} from '../control/auth.js'
import { PROTOCOL_VERSION, type ErrorCode } from '../control/protocol.js'

/** A refusal from the kernel, carrying the protocol code. */
export class ControlCallError extends Error {
  readonly code: ErrorCode | 'transport'

  constructor(code: ErrorCode | 'transport', message: string) {
    super(message)
    this.name = 'ControlCallError'
    this.code = code
  }
}

export interface EventNotice {
  readonly type: string
  readonly runId?: string
  readonly payload?: unknown
}

export interface ControlClient {
  readonly hello: { kernel: { version: string }; status: unknown }
  call(cmd: string, params?: Record<string, unknown>): Promise<unknown>
  onEvent(listener: (event: EventNotice) => void): void
  close(): void
}

interface Frame {
  readonly id?: string
  readonly ok?: boolean
  readonly result?: unknown
  readonly error?: { code: ErrorCode; message: string }
  readonly protocol?: number
  readonly kernel?: { version: string }
  readonly status?: unknown
  readonly event?: EventNotice
}

export interface ConnectOptions {
  readonly port: number
  readonly token: string
  readonly timeoutMs?: number
}

export async function connectControl(options: ConnectOptions): Promise<ControlClient> {
  // Loopback, hard-coded. Not a parameter.
  const url = `ws://127.0.0.1:${String(options.port)}${CONTROL_PATH}`
  const socket = new WebSocket(url, {
    // The only place the token appears. No query-string branch exists.
    headers: { Authorization: `Bearer ${options.token}` },
  })

  const pending = new Map<string, (frame: Frame) => void>()
  const listeners: ((event: EventNotice) => void)[] = []
  let hello: Frame | undefined
  let closed = false

  socket.on('error', () => {
    closed = true
  })
  socket.on('close', () => {
    closed = true
    for (const settle of pending.values()) {
      settle({ ok: false, error: { code: 'internal', message: 'the control plane closed the connection' } })
    }
    pending.clear()
  })

  const first = new Promise<Frame>((resolve, reject) => {
    const timer = setTimeout(() => reject(new ControlCallError('transport', 'no hello frame')), options.timeoutMs ?? 5_000)
    timer.unref?.()
    socket.on('message', (data: Buffer) => {
      const frame = JSON.parse(data.toString('utf8')) as Frame
      if (frame.protocol !== undefined && hello === undefined) {
        hello = frame
        clearTimeout(timer)
        resolve(frame)
        return
      }
      if (frame.event !== undefined) {
        for (const listener of listeners) listener(frame.event)
        return
      }
      if (frame.id !== undefined) {
        const settle = pending.get(frame.id)
        if (settle !== undefined) {
          pending.delete(frame.id)
          settle(frame)
        }
      }
    })
    socket.on('error', (e: Error) => reject(new ControlCallError('transport', e.message)))
  })

  await new Promise<void>((resolve, reject) => {
    socket.on('open', () => resolve())
    socket.on('error', (e: Error) => reject(new ControlCallError('transport', e.message)))
  })
  const helloFrame = await first

  let n = 0
  return {
    hello: {
      kernel: helloFrame.kernel ?? { version: 'unknown' },
      status: helloFrame.status,
    },
    onEvent(listener) {
      listeners.push(listener)
    },
    async call(cmd, params = {}) {
      if (closed) throw new ControlCallError('transport', 'the connection is closed')
      n++
      const id = `cli${String(n)}`
      const reply = await new Promise<Frame>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new ControlCallError('transport', `no reply to ${cmd}`)),
          options.timeoutMs ?? 5_000,
        )
        timer.unref?.()
        pending.set(id, (frame) => {
          clearTimeout(timer)
          resolve(frame)
        })
        socket.send(JSON.stringify({ v: PROTOCOL_VERSION, id, cmd, params }))
      })
      if (reply.ok !== true) {
        throw new ControlCallError(reply.error?.code ?? 'internal', reply.error?.message ?? 'unknown error')
      }
      return reply.result
    },
    close() {
      closed = true
      try {
        socket.close()
      } catch {
        // Already gone.
      }
    },
  }
}
