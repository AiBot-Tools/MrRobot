// T20 — Anthropic Messages adapter.
//
// This file is mostly about credentials, because the pinned SDK makes the
// obvious implementation wrong in a way nothing else catches.
//
// `new Anthropic({...})` substitutes an environment variable per credential
// field and ONLY when that field is `undefined`, and `authHeaders()` sends
// BOTH X-Api-Key and Authorization when both fields are non-null (verified
// against node_modules/@anthropic-ai/sdk/client.mjs 0.127.0, l.70, 76-81,
// 363-375). So the natural spelling —
//
//   ...(usesApiKey ? { apiKey: key } : { authToken: key })
//
// — leaves the other field `undefined`, lets ANTHROPIC_API_KEY or
// ANTHROPIC_AUTH_TOKEN fill it in, and sends a second credential nobody
// configured on every single request. That is the falsifier for the two
// poisoned-env tests below, and it is invisible on a machine where those
// variables happen to be unset — which is to say, invisible in CI and loud
// in production.
//
// The other falsifiers: raise the SDK's maxRetries above 0 and one event pair
// covers three wire requests (invariant 4 broken silently); map stop_reason
// onto a closed set and a new one is swallowed; reconstruct tool_results as
// separate user messages and the model quietly stops calling tools in
// parallel; read input_tokens alone and every cached request under-bills.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'
import { fakeProvider, http, FAKE_PRICING, type ScriptedResponse } from './helpers/fake-provider.js'
import { AnthropicAdapter } from '../src/models/anthropic.js'
import type { ModelCard } from '../src/models/registry.js'
import { ProviderError, Router, type ModelBinding, type RouteRequest } from '../src/models/router.js'

const KEY = 'Hn5rT8wQ2xZ6vB9mK3pL7dG1sA4fJ0cY'
const POISON_API_KEY = 'POISONED-api-key-must-never-be-sent-4821'
const POISON_AUTH_TOKEN = 'POISONED-auth-token-must-never-be-sent-9137'
const POISON_BASE_URL = 'https://poisoned.invalid'

const PRICES = {
  inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
  outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
  cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
  source: 'table',
} as const

function card(over: Partial<ModelCard> = {}): ModelCard {
  return {
    dialect: 'anthropic',
    baseUrl: 'https://api.anthropic.test',
    path: '/v1/messages',
    auth: { header: 'x-api-key', scheme: 'none', vaultId: 'anthropic-api-key' },
    headers: { 'anthropic-version': '2023-06-01' },
    model: 'claude-sonnet-5',
    local: false,
    placeholder: false,
    pricing: { ...PRICES },
    limits: { contextTokens: 200_000, maxOutputTokens: 8_192 },
    caps: {
      toolChoice: 'auto',
      parallelToolCalls: true,
      strictSchema: null,
      sampling: 'none',
      streamUsage: null,
      preserveAssistantMessage: false,
    },
    orchestrator: false,
    ...over,
  }
}

const REF = 'anthropic/claude-sonnet-5'
const BINDING: ModelBinding = { primary: REF, fallbacks: [] }


const REQUEST: RouteRequest = {
  system: 'you are a test',
  messages: [{ role: 'user', content: 'ping' }],
  tools: [{ ref: 'pmmcp.recall', description: 'recall a memory', inputSchema: { type: 'object' } }],
}

/** An Anthropic message body with an arbitrary stop_reason and usage. */
function anthropicMessage(over: {
  content?: unknown[]
  stop_reason?: string
  usage?: Record<string, unknown>
}): ScriptedResponse {
  return http(200, {
    id: 'msg_fake',
    type: 'message',
    role: 'assistant',
    model: 'claude-sonnet-5',
    content: over.content ?? [{ type: 'text', text: 'pong' }],
    stop_reason: over.stop_reason ?? 'end_turn',
    stop_sequence: null,
    usage: over.usage ?? {
      input_tokens: 1_000,
      output_tokens: 100,
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: 0,
    },
  })
}

interface Harness {
  readonly router: Router
  readonly store: ReturnType<typeof withStore>
  readonly provider: ReturnType<typeof fakeProvider>
}

function harness(
  t: Parameters<typeof withStore>[0],
  script: readonly ScriptedResponse[],
  options: { card?: ModelCard; maxRetries?: number } = {},
): Harness {
  const store = withStore(t)
  const provider = fakeProvider(script)
  const router = new Router({
    store,
    cards: new Map([[REF, options.card ?? card()]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve(KEY),
    maxRetries: options.maxRetries ?? 0,
    adapters: { anthropic: new AnthropicAdapter() },
    fetch: provider.fetch,
    sleep: () => Promise.resolve(),
  })
  return { router, store, provider }
}

/** Poison every environment variable the SDK would otherwise read. */
function poisonEnv(t: Parameters<typeof withStore>[0]): void {
  const saved = {
    ANTHROPIC_API_KEY: process.env['ANTHROPIC_API_KEY'],
    ANTHROPIC_AUTH_TOKEN: process.env['ANTHROPIC_AUTH_TOKEN'],
    ANTHROPIC_BASE_URL: process.env['ANTHROPIC_BASE_URL'],
  }
  process.env['ANTHROPIC_API_KEY'] = POISON_API_KEY
  process.env['ANTHROPIC_AUTH_TOKEN'] = POISON_AUTH_TOKEN
  process.env['ANTHROPIC_BASE_URL'] = POISON_BASE_URL
  t.after(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  })
}

function authHeadersOf(headers: Record<string, string>): string[] {
  return ['authorization', 'x-api-key'].filter((h) => (headers[h] ?? '') !== '')
}

function payloads(store: Harness['store'], type: string): Record<string, unknown>[] {
  return store.query({ type }).map((row) => JSON.parse(row.payload) as Record<string, unknown>)
}

// ── credentials ────────────────────────────────────────────────────────────

test('x-api-key header when auth.header is x-api-key; Authorization Bearer via authToken when auth.header is Authorization', async (t) => {
  for (const header of ['x-api-key', 'Authorization'] as const) {
    const scheme = header === 'Authorization' ? 'Bearer' : 'none'
    const h = harness(t, [anthropicMessage({})], {
      card: card({ auth: { header, scheme, vaultId: 'anthropic-api-key' } }),
    })

    await h.router.call({ binding: BINDING, request: REQUEST })

    const sent = h.provider.requests[0]
    assert.ok(sent !== undefined)
    if (header === 'x-api-key') {
      assert.equal(sent.headers['x-api-key'], KEY)
      assert.equal(sent.headers['authorization'], undefined)
    } else {
      assert.equal(sent.headers['authorization'], `Bearer ${KEY}`)
      assert.equal(sent.headers['x-api-key'], undefined)
    }
  }
})

test('exactly one auth header is present on the wire (x-api-key XOR authorization) with ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN both poisoned', async (t) => {
  poisonEnv(t)

  for (const header of ['x-api-key', 'Authorization'] as const) {
    const scheme = header === 'Authorization' ? 'Bearer' : 'none'
    const h = harness(t, [anthropicMessage({})], {
      card: card({ auth: { header, scheme, vaultId: 'anthropic-api-key' } }),
    })

    await h.router.call({ binding: BINDING, request: REQUEST })

    const sent = h.provider.requests[0]
    assert.ok(sent !== undefined, `${header}: no request reached the wire`)
    // The falsifier is the one-field spread: it leaves the other credential
    // field undefined, the env fills it, and authHeaders() sends both.
    assert.deepEqual(authHeadersOf(sent.headers), [header.toLowerCase()])
  }
})

test('poisoned ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN and ANTHROPIC_BASE_URL are ignored — fake fetch receives the configured key and URL', async (t) => {
  poisonEnv(t)
  const h = harness(t, [anthropicMessage({})])

  await h.router.call({ binding: BINDING, request: REQUEST })

  const sent = h.provider.requests[0]
  assert.ok(sent !== undefined)
  assert.equal(sent.headers['x-api-key'], KEY)
  assert.ok(
    sent.url.startsWith('https://api.anthropic.test/'),
    `the request went to ${sent.url}, not the card’s baseUrl`,
  )

  const wire = JSON.stringify(sent)
  for (const poison of [POISON_API_KEY, POISON_AUTH_TOKEN, POISON_BASE_URL]) {
    assert.ok(!wire.includes(poison), `${poison} reached the wire`)
  }
  for (const row of h.store.query()) {
    assert.ok(!row.payload.includes(KEY), `the credential reached a ${row.type} payload`)
  }
})

// ── retries and request shape ──────────────────────────────────────────────

test('maxRetries is 0 so a 500 produces exactly one request event', async (t) => {
  const h = harness(t, [http(500, { error: 'boom' })], { maxRetries: 0 })

  await assert.rejects(
    () => h.router.call({ binding: BINDING, request: REQUEST }),
    (e: unknown) => e instanceof ProviderError && e.status === 500,
  )

  // One wire request, one event pair. An SDK-level retry would make three
  // provider calls hide behind a single llm.request/llm.response pair.
  assert.equal(h.provider.requests.length, 1)
  assert.equal(payloads(h.store, 'llm.request').length, 1)
  assert.equal(payloads(h.store, 'llm.response').length, 1)
})

test('never sends temperature, top_p or top_k', async (t) => {
  const h = harness(t, [anthropicMessage({})])

  await h.router.call({ binding: BINDING, request: REQUEST })

  const body = h.provider.requests[0]?.body as Record<string, unknown>
  assert.ok(body !== undefined)
  for (const key of ['temperature', 'top_p', 'top_k']) {
    assert.equal(key in body, false, `${key} reached the request body`)
  }
  // tool_choice is auto and nothing else: a forced call would be the router
  // deciding tool authority, which belongs to the gate.
  assert.deepEqual(body['tool_choice'], { type: 'auto' })
  // Invariant 10: `__` on the wire.
  assert.deepEqual(
    (body['tools'] as { name: string }[]).map((x) => x.name),
    ['pmmcp__recall'],
  )
})

// ── response mapping ───────────────────────────────────────────────────────

test('tool_use maps to ToolCalls with dotted refs', async (t) => {
  const h = harness(t, [
    anthropicMessage({
      content: [
        { type: 'text', text: 'looking that up' },
        { type: 'tool_use', id: 'toolu_1', name: 'pmmcp__recall', input: { query: 'x' } },
        // A tool that was never offered must not become an executable call.
        { type: 'tool_use', id: 'toolu_2', name: 'pmmcp__set_secret', input: {} },
      ],
      stop_reason: 'tool_use',
    }),
  ])

  const result = await h.router.call({ binding: BINDING, request: REQUEST })

  assert.deepEqual(result.outcome.toolCalls, [
    { id: 'toolu_1', ref: 'pmmcp.recall', args: { query: 'x' } },
  ])
  assert.equal(result.outcome.toolCallErrors?.length, 1)
  assert.equal(result.outcome.toolCallErrors?.[0]?.name, 'pmmcp__set_secret')
  assert.equal(result.outcome.content, 'looking that up')
})

test('parallel tool_results go back in one user message', async (t) => {
  const h = harness(t, [anthropicMessage({})])

  await h.router.call({
    binding: BINDING,
    request: {
      ...REQUEST,
      messages: [
        { role: 'user', content: 'ping' },
        {
          role: 'assistant',
          content: '',
          toolCalls: [
            { id: 'toolu_1', ref: 'pmmcp.recall', args: { q: 'a' } },
            { id: 'toolu_2', ref: 'pmmcp.recall', args: { q: 'b' } },
          ],
        },
        { role: 'tool', callId: 'toolu_1', ref: 'pmmcp.recall', content: 'A' },
        { role: 'tool', callId: 'toolu_2', ref: 'pmmcp.recall', content: 'B', isError: true },
      ],
    },
  })

  const body = h.provider.requests[0]?.body as { messages: { role: string; content: unknown }[] }
  assert.deepEqual(
    body.messages.map((m) => m.role),
    ['user', 'assistant', 'user'],
  )
  // Both results in ONE user message. Splitting them teaches the model to
  // stop calling tools in parallel.
  const results = body.messages[2]?.content as { type: string; tool_use_id: string }[]
  assert.equal(results.length, 2)
  assert.deepEqual(
    results.map((r) => r.tool_use_id),
    ['toolu_1', 'toolu_2'],
  )
  assert.deepEqual(
    results.map((r) => r.type),
    ['tool_result', 'tool_result'],
  )
  assert.equal((results[1] as { is_error?: boolean }).is_error, true)
})

test('stop_reason surfaces verbatim in llm.response.finish', async (t) => {
  // A value outside the set this adapter was written against. Mapping onto a
  // closed enum would swallow it.
  const h = harness(t, [anthropicMessage({ stop_reason: 'model_context_window_exceeded' })])

  const result = await h.router.call({ binding: BINDING, request: REQUEST })

  assert.equal(result.outcome.finish, 'model_context_window_exceeded')
  assert.equal(payloads(h.store, 'llm.response')[0]?.['finish'], 'model_context_window_exceeded')
})

test('usage with cache fields costs exactly the hand-computed integer', async (t) => {
  const h = harness(t, [
    anthropicMessage({
      usage: {
        input_tokens: 1_000,
        output_tokens: 100,
        cache_creation_input_tokens: 2_000,
        cache_read_input_tokens: 5_000,
      },
    }),
  ])

  const result = await h.router.call({ binding: BINDING, request: REQUEST })

  //   1_000 uncached input * 3 USD/MTok      = 3_000_000_000
  //   2_000 cache write    * 3.75 USD/MTok   = 7_500_000_000
  //   5_000 cache read     * 0.30 USD/MTok   = 1_500_000_000
  //     100 output         * 15 USD/MTok     = 1_500_000_000
  //                              sum / 1e6   =        13_500 micro-USD
  assert.equal(result.outcome.costMicroUsd, 13_500)

  const [response] = payloads(h.store, 'llm.response')
  assert.equal(response?.['costMicroUsd'], 13_500)
  // Billable input is the SUM of the three input fields; reading input_tokens
  // alone under-bills every cached request.
  assert.equal(response?.['inputTokens'], 1_000)
  assert.equal(response?.['cacheWriteTokens'], 2_000)
  assert.equal(response?.['cacheReadTokens'], 5_000)
})
