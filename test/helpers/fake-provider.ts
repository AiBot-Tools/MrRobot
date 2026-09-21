// Fake provider for both dialects the router speaks.
//
// It answers a fixed script and nothing else. When the script runs out it
// THROWS `unscripted call` rather than improvising: a double, having invented
// an extra turn, would let a router bug that loops forever look like a pass.
//
// Wire shapes below are the real ones, taken from the verified provider
// research, because the point of this double is to catch code that guesses
// them wrong:
//
//   Anthropic   content blocks, `stop_reason`, and usage with
//               input_tokens / output_tokens / cache_creation_input_tokens /
//               cache_read_input_tokens. Billable input is the SUM of those
//               three input fields, which is the arithmetic the cost code
//               must get right.
//   Chat        choices[].message.tool_calls[].function.arguments is a JSON
//   Completions STRING, not an object, and the model is documented as not
//               always producing valid JSON. usage is prompt_tokens /
//               completion_tokens with prompt_tokens_details.cached_tokens.
//
// Token counts are chosen so a cost computed at the fixed prices below lands
// on an exact integer number of micro-USD, with no rounding to hide behind.

import './guard.js'

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

/** Fixed prices for the fake, in micro-USD per million tokens. */
export const FAKE_PRICING = {
  inMicroUsdPerMTok: 3_000_000,
  outMicroUsdPerMTok: 15_000_000,
  cacheWriteMicroUsdPerMTok: 3_750_000,
  cacheReadMicroUsdPerMTok: 300_000,
} as const

export interface ScriptedResponse {
  readonly status: number
  readonly body: unknown
  readonly headers?: Record<string, string>
  /** Raw body text, used to serve deliberately malformed JSON. */
  readonly rawBody?: string
}

export interface RecordedRequest {
  readonly method: string
  readonly url: string
  readonly headers: Record<string, string>
  readonly body: unknown
}

export interface FakeProvider {
  /** Drop-in replacement for globalThis.fetch. */
  readonly fetch: typeof globalThis.fetch
  readonly requests: RecordedRequest[]
  /** Serve the same script over a loopback HTTP server. */
  serve(): Promise<{ url: string; close: () => Promise<void> }>
}

// ── scripted response builders ─────────────────────────────────────────────

/** Anthropic reply asking for a tool call. */
export function anthropicToolUse(options: {
  name: string
  input: Record<string, unknown>
  inputTokens?: number
  outputTokens?: number
  cacheWriteTokens?: number
  cacheReadTokens?: number
}): ScriptedResponse {
  return {
    status: 200,
    body: {
      id: 'msg_fake_tool',
      type: 'message',
      role: 'assistant',
      model: 'claude-sonnet-5',
      content: [{ type: 'tool_use', id: 'toolu_fake1', name: options.name, input: options.input }],
      stop_reason: 'tool_use',
      stop_sequence: null,
      usage: {
        input_tokens: options.inputTokens ?? 1_000,
        output_tokens: options.outputTokens ?? 100,
        cache_creation_input_tokens: options.cacheWriteTokens ?? 0,
        cache_read_input_tokens: options.cacheReadTokens ?? 0,
      },
    },
  }
}

/** Anthropic reply ending the turn. */
export function anthropicEndTurn(options: {
  text: string
  inputTokens?: number
  outputTokens?: number
  cacheWriteTokens?: number
  cacheReadTokens?: number
}): ScriptedResponse {
  return {
    status: 200,
    body: {
      id: 'msg_fake_end',
      type: 'message',
      role: 'assistant',
      model: 'claude-sonnet-5',
      content: [{ type: 'text', text: options.text }],
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: options.inputTokens ?? 1_000,
        output_tokens: options.outputTokens ?? 100,
        cache_creation_input_tokens: options.cacheWriteTokens ?? 0,
        cache_read_input_tokens: options.cacheReadTokens ?? 0,
      },
    },
  }
}

/** Chat Completions reply with tool calls. `arguments` is a STRING. */
export function chatToolCalls(options: {
  name: string
  argumentsJson: string
  promptTokens?: number
  completionTokens?: number
  cachedTokens?: number
}): ScriptedResponse {
  return {
    status: 200,
    body: {
      id: 'chatcmpl-fake-tool',
      object: 'chat.completion',
      created: 1_758_000_000,
      model: 'fake-model',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: null,
            tool_calls: [
              {
                id: 'call_fake1',
                type: 'function',
                function: { name: options.name, arguments: options.argumentsJson },
              },
            ],
          },
          finish_reason: 'tool_calls',
        },
      ],
      usage: {
        prompt_tokens: options.promptTokens ?? 1_000,
        completion_tokens: options.completionTokens ?? 100,
        total_tokens: (options.promptTokens ?? 1_000) + (options.completionTokens ?? 100),
        prompt_tokens_details: { cached_tokens: options.cachedTokens ?? 0 },
      },
    },
  }
}

/** Chat Completions reply that stops. */
export function chatStop(options: {
  text: string
  promptTokens?: number
  completionTokens?: number
  cachedTokens?: number
}): ScriptedResponse {
  return {
    status: 200,
    body: {
      id: 'chatcmpl-fake-stop',
      object: 'chat.completion',
      created: 1_758_000_000,
      model: 'fake-model',
      choices: [
        { index: 0, message: { role: 'assistant', content: options.text }, finish_reason: 'stop' },
      ],
      usage: {
        prompt_tokens: options.promptTokens ?? 1_000,
        completion_tokens: options.completionTokens ?? 100,
        total_tokens: (options.promptTokens ?? 1_000) + (options.completionTokens ?? 100),
        prompt_tokens_details: { cached_tokens: options.cachedTokens ?? 0 },
      },
    },
  }
}

/** Any HTTP status with an arbitrary body — 429 with retry-after, 500, … */
export function http(status: number, body: unknown, headers?: Record<string, string>): ScriptedResponse {
  return headers === undefined ? { status, body } : { status, body, headers }
}

/** A 200 whose body is not JSON at all. */
export function malformedJson(): ScriptedResponse {
  return { status: 200, body: undefined, rawBody: '{"id":"trunc' }
}

// ── the provider ───────────────────────────────────────────────────────────

export function fakeProvider(script: readonly ScriptedResponse[]): FakeProvider {
  const requests: RecordedRequest[] = []
  let index = 0

  const nextResponse = (): ScriptedResponse => {
    const scripted = script[index]
    index++
    if (scripted === undefined) {
      throw new Error(
        `unscripted call: the provider script has ${String(script.length)} response(s) and call ` +
          `${String(index)} was made. Extend the script or fix the caller's loop.`,
      )
    }
    return scripted
  }

  const bodyText = (scripted: ScriptedResponse): string =>
    scripted.rawBody ?? JSON.stringify(scripted.body)

  const fetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const headers: Record<string, string> = {}
    new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).forEach(
      (value, key) => {
        headers[key] = value
      },
    )
    const rawRequestBody = typeof init?.body === 'string' ? init.body : undefined
    let parsed: unknown
    if (rawRequestBody !== undefined) {
      try {
        parsed = JSON.parse(rawRequestBody)
      } catch {
        parsed = rawRequestBody
      }
    }
    requests.push({
      method: init?.method ?? (input instanceof Request ? input.method : 'GET'),
      url,
      headers,
      body: parsed,
    })

    // Throwing here surfaces as a rejected fetch, which is what a caller that
    // over-loops deserves to see.
    const scripted = nextResponse()
    return new Response(bodyText(scripted), {
      status: scripted.status,
      headers: { 'content-type': 'application/json', ...scripted.headers },
    })
  }) as typeof globalThis.fetch

  return {
    fetch,
    requests,
    async serve() {
      const server: Server = createServer((req, res) => {
        const chunks: Buffer[] = []
        req.on('data', (c: Buffer) => chunks.push(c))
        req.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8')
          let parsed: unknown
          if (raw !== '') {
            try {
              parsed = JSON.parse(raw)
            } catch {
              parsed = raw
            }
          }
          const headers: Record<string, string> = {}
          for (const [k, v] of Object.entries(req.headers)) {
            if (typeof v === 'string') headers[k] = v
          }
          requests.push({ method: req.method ?? 'GET', url: req.url ?? '/', headers, body: parsed })

          let scripted: ScriptedResponse
          try {
            scripted = nextResponse()
          } catch (e) {
            res.writeHead(599, { 'content-type': 'text/plain' })
            res.end(e instanceof Error ? e.message : 'unscripted call')
            return
          }
          res.writeHead(scripted.status, {
            'content-type': 'application/json',
            ...scripted.headers,
          })
          res.end(bodyText(scripted))
        })
      })

      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
      const address = server.address() as AddressInfo
      return {
        url: `http://127.0.0.1:${String(address.port)}`,
        close: () =>
          new Promise<void>((resolve, reject) => {
            server.close((err) => (err === undefined ? resolve() : reject(err)))
          }),
      }
    },
  }
}
