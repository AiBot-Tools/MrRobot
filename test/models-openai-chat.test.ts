// T21 — OpenAI-compatible Chat Completions adapter.
//
// The servers behind this dialect are llama.cpp, Ollama, OpenRouter and
// Moonshot, not OpenAI, and most of what this file pins down is where they
// differ from each other and from Anthropic. The falsifiers:
//
//   Send `tool_choice: "none"` instead of omitting the field and a server that
//   does not know the parameter rejects every call — "none" and absent are not
//   the same thing to it.
//   Send a named `{type:"function"}` choice and the kernel has told the model
//   which tool to call, which is the gate's decision, not the router's.
//   Reconstruct the assistant message and a reasoning trace the server
//   requires back untouched is gone.
//   Let `JSON.parse` of `function.arguments` throw and a model producing
//   slightly malformed JSON — which the providers document as normal — kills
//   the run instead of being told to try again.
//   Add cached tokens instead of subtracting them and every cached request
//   over-bills; the Anthropic dialect is the mirror image, so copying that
//   arithmetic across is the easy mistake.
//   Group tool results into one message the way the Anthropic adapter must and
//   the body is malformed here.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'
import { fakeProvider, http, malformedJson, FAKE_PRICING, type ScriptedResponse } from './helpers/fake-provider.js'
import { TOKEN_PATTERNS } from '../src/events/redact.js'
import { OpenAiChatAdapter } from '../src/models/openai-chat.js'
import type { ModelCard } from '../src/models/registry.js'
import { ProviderError, Router, type ModelBinding, type RouteRequest } from '../src/models/router.js'

const KEY = 'Rt4yU8iO2pA6sD0fG5hJ9kL3zX7cV1bN'
/** Used only by the leak test, so no earlier test can register it for us. */
const LEAK_KEY = 'Wq9eR3tY7uI1oP5aS8dF2gH6jK0lZ4xC'

const PRICES = {
  inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
  outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
  cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
  source: 'table',
} as const

type Caps = ModelCard['caps']

const CAPS: Caps = {
  toolChoice: 'auto',
  parallelToolCalls: null,
  strictSchema: null,
  sampling: 'temperature',
  streamUsage: null,
  preserveAssistantMessage: false,
}

function card(over: Partial<ModelCard> = {}): ModelCard {
  return {
    dialect: 'openai-chat',
    baseUrl: 'https://openrouter.test',
    path: '/api/v1/chat/completions',
    auth: { header: 'Authorization', scheme: 'Bearer', vaultId: 'openrouter-api-key' },
    model: 'moonshotai/kimi-k2',
    local: false,
    // The shipped config/providers.yaml must mark every non-anthropic entry
    // placeholder: true in Phase 0, and `routable()` refuses a placeholder —
    // so no compat model routes at all until the operator verifies the entry
    // and clears the flag. That interaction is pinned by its own test below;
    // these cards are what a verified entry looks like afterwards.
    placeholder: false,
    pricing: { ...PRICES },
    limits: { contextTokens: 128_000, maxOutputTokens: 4_096 },
    caps: { ...CAPS },
    orchestrator: false,
    ...over,
  }
}

const REF = 'openrouter/moonshotai/kimi-k2'
const BINDING: ModelBinding = { primary: REF, fallbacks: [] }


const REQUEST: RouteRequest = {
  system: 'you are a test',
  messages: [{ role: 'user', content: 'ping' }],
  tools: [{ ref: 'pmmcp.recall', description: 'recall a memory', inputSchema: { type: 'object' } }],
}

/** A Chat Completions body with an arbitrary message and usage. */
function completion(over: { message?: unknown; finish?: string; usage?: unknown }): ScriptedResponse {
  return http(200, {
    id: 'chatcmpl-fake',
    object: 'chat.completion',
    created: 1_758_000_000,
    model: 'fake-model',
    choices: [
      {
        index: 0,
        message: over.message ?? { role: 'assistant', content: 'pong' },
        finish_reason: over.finish ?? 'stop',
      },
    ],
    usage: over.usage ?? {
      prompt_tokens: 1_000,
      completion_tokens: 100,
      total_tokens: 1_100,
      prompt_tokens_details: { cached_tokens: 0 },
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
  options: { card?: ModelCard; credential?: string; maxRetries?: number } = {},
): Harness {
  const store = withStore(t)
  const provider = fakeProvider(script)
  const router = new Router({
    store,
    cards: new Map([[REF, options.card ?? card()]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve(options.credential ?? KEY),
    maxRetries: options.maxRetries ?? 0,
    adapters: { 'openai-chat': new OpenAiChatAdapter() },
    fetch: provider.fetch,
    sleep: () => Promise.resolve(),
  })
  return { router, store, provider }
}

function bodyOf(h: Harness): Record<string, unknown> {
  const body = h.provider.requests[0]?.body
  assert.ok(body !== undefined && typeof body === 'object', 'no request body was recorded')
  return body as Record<string, unknown>
}

function payloads(store: Harness['store'], type: string): Record<string, unknown>[] {
  return store.query({ type }).map((row) => JSON.parse(row.payload) as Record<string, unknown>)
}

// ── request shape ──────────────────────────────────────────────────────────

test('omits tool_choice for caps none and sends required as a string', async (t) => {
  // caps none: the endpoint does not know the parameter, so it is absent —
  // not sent as the string "none".
  const none = harness(t, [completion({})], {
    card: card({ caps: { ...CAPS, toolChoice: 'none' } }),
  })
  await none.router.call({ binding: BINDING, request: REQUEST })
  assert.equal('tool_choice' in bodyOf(none), false)
  // The tools themselves are still offered; only the choice field is omitted.
  assert.equal(Array.isArray(bodyOf(none)['tools']), true)

  const required = harness(t, [completion({})], {
    card: card({ caps: { ...CAPS, toolChoice: 'required' } }),
  })
  await required.router.call({ binding: BINDING, request: REQUEST })
  // A STRING, not an object. An object is the named-choice shape.
  assert.equal(bodyOf(required)['tool_choice'], 'required')

  // `forced` is downgraded: Phase 0 never tells the model which tool to call.
  const forced = harness(t, [completion({})], {
    card: card({ caps: { ...CAPS, toolChoice: 'forced' } }),
  })
  await forced.router.call({ binding: BINDING, request: REQUEST })
  assert.equal(bodyOf(forced)['tool_choice'], 'auto')

  // No tools offered: a choice would be an error on every server.
  const bare = harness(t, [completion({})])
  await bare.router.call({ binding: BINDING, request: { ...REQUEST, tools: [] } })
  assert.equal('tool_choice' in bodyOf(bare), false)
  assert.equal('tools' in bodyOf(bare), false)
})

test('capability flags shape the body: parallel_tool_calls only when false, strict only when strictSchema', async (t) => {
  // Defaults (null) send neither field. An unknown field is what llama.cpp
  // throws on, so silence is the compatible choice.
  const silent = harness(t, [completion({})])
  await silent.router.call({ binding: BINDING, request: REQUEST })
  assert.equal('parallel_tool_calls' in bodyOf(silent), false)
  const silentTools = bodyOf(silent)['tools'] as { function: Record<string, unknown> }[]
  assert.equal('strict' in (silentTools[0]?.function ?? {}), false)

  const flagged = harness(t, [completion({})], {
    card: card({ caps: { ...CAPS, parallelToolCalls: false, strictSchema: true } }),
  })
  await flagged.router.call({ binding: BINDING, request: REQUEST })
  assert.equal(bodyOf(flagged)['parallel_tool_calls'], false)
  const flaggedTools = bodyOf(flagged)['tools'] as { function: Record<string, unknown> }[]
  assert.equal(flaggedTools[0]?.function['strict'], true)
  assert.equal(flaggedTools[0]?.function['name'], 'pmmcp__recall')

  // parallelToolCalls: true is the default everywhere; sending it is a field
  // for a server to reject.
  const on = harness(t, [completion({})], {
    card: card({ caps: { ...CAPS, parallelToolCalls: true } }),
  })
  await on.router.call({ binding: BINDING, request: REQUEST })
  assert.equal('parallel_tool_calls' in bodyOf(on), false)
})

test('replays the raw assistant message including reasoning_content', async (t) => {
  const raw = {
    role: 'assistant',
    content: null,
    reasoning_content: 'the model’s own trace, which the server wants back untouched',
    tool_calls: [
      { id: 'call_1', type: 'function', function: { name: 'pmmcp__recall', arguments: '{"q":"a"}' } },
    ],
  }
  const h = harness(t, [completion({})], {
    card: card({ caps: { ...CAPS, preserveAssistantMessage: true } }),
  })

  await h.router.call({
    binding: BINDING,
    request: {
      ...REQUEST,
      messages: [
        { role: 'user', content: 'ping' },
        // `content` and `toolCalls` are deliberately WRONG here: if the adapter
        // reconstructs rather than replays, the assertion below sees them.
        { role: 'assistant', content: 'reconstructed', raw },
        { role: 'tool', callId: 'call_1', ref: 'pmmcp.recall', content: 'A' },
      ],
    },
  })

  const messages = bodyOf(h)['messages'] as Record<string, unknown>[]
  assert.deepEqual(messages[2], raw)
})

test('tool results are one message each, not grouped like the Anthropic dialect', async (t) => {
  const h = harness(t, [completion({})])

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
            { id: 'call_1', ref: 'pmmcp.recall', args: { q: 'a' } },
            { id: 'call_2', ref: 'pmmcp.recall', args: { q: 'b' } },
          ],
        },
        { role: 'tool', callId: 'call_1', ref: 'pmmcp.recall', content: 'A' },
        { role: 'tool', callId: 'call_2', ref: 'pmmcp.recall', content: 'B' },
      ],
    },
  })

  const messages = bodyOf(h)['messages'] as Record<string, unknown>[]
  assert.deepEqual(
    messages.map((m) => m['role']),
    ['system', 'user', 'assistant', 'tool', 'tool'],
  )
  assert.equal(messages[3]?.['tool_call_id'], 'call_1')
  assert.equal(messages[4]?.['tool_call_id'], 'call_2')
  // An assistant turn with only tool calls sends content: null, not "".
  assert.equal(messages[2]?.['content'], null)
  const calls = messages[2]?.['tool_calls'] as { function: { arguments: unknown } }[]
  // arguments is a STRING on this wire, both directions.
  assert.equal(typeof calls[0]?.function.arguments, 'string')
})

// ── response mapping ───────────────────────────────────────────────────────

test('invalid JSON arguments become a ToolCallError', async (t) => {
  const h = harness(t, [
    completion({
      message: {
        role: 'assistant',
        content: null,
        tool_calls: [
          { id: 'call_ok', type: 'function', function: { name: 'pmmcp__recall', arguments: '{"q":"a"}' } },
          // Truncated mid-object. Documented as normal model output.
          { id: 'call_bad', type: 'function', function: { name: 'pmmcp__recall', arguments: '{"q":' } },
          // A tool that was never offered must not become an executable call.
          { id: 'call_unknown', type: 'function', function: { name: 'pmmcp__set_secret', arguments: '{}' } },
        ],
      },
      finish: 'tool_calls',
    }),
  ])

  // The run survives: a malformed argument is data, not an exception.
  const result = await h.router.call({ binding: BINDING, request: REQUEST })

  assert.deepEqual(result.outcome.toolCalls, [
    { id: 'call_ok', ref: 'pmmcp.recall', args: { q: 'a' } },
  ])
  assert.equal(result.outcome.toolCallErrors?.length, 2)
  assert.equal(result.outcome.toolCallErrors?.[0]?.id, 'call_bad')
  assert.match(String(result.outcome.toolCallErrors?.[0]?.reason), /not valid JSON/)
  assert.equal(result.outcome.toolCallErrors?.[1]?.id, 'call_unknown')
  assert.equal(result.outcome.finish, 'tool_calls')
})

test('usage normalisation with cached_tokens', async (t) => {
  const h = harness(t, [
    completion({
      usage: {
        // Cached tokens are INSIDE prompt_tokens here — the mirror image of
        // Anthropic, where they sit beside input_tokens.
        prompt_tokens: 1_000,
        completion_tokens: 100,
        total_tokens: 1_100,
        prompt_tokens_details: { cached_tokens: 400 },
      },
    }),
  ])

  const result = await h.router.call({ binding: BINDING, request: REQUEST })

  //     600 uncached input * 3 USD/MTok    = 1_800_000_000
  //     400 cache read     * 0.30 USD/MTok =   120_000_000
  //     100 output         * 15 USD/MTok   = 1_500_000_000
  //                             sum / 1e6  =         3_420 micro-USD
  assert.equal(result.outcome.costMicroUsd, 3_420)
  assert.equal(result.outcome.inputTokens, 600)
  assert.equal(result.outcome.cacheReadTokens, 400)

  const [response] = payloads(h.store, 'llm.response')
  assert.equal(response?.['inputTokens'], 600)
  assert.equal(response?.['cacheReadTokens'], 400)
  assert.equal(response?.['costMicroUsd'], 3_420)
})

test('usage.cost is authoritative when pricing.source is usage.cost', async (t) => {
  const h = harness(t, [
    completion({
      usage: {
        prompt_tokens: 1_000,
        completion_tokens: 100,
        total_tokens: 1_100,
        // What OpenRouter will actually invoice, markup included. The table
        // cannot know it.
        cost: 0.0123,
      },
    }),
  ], { card: card({ pricing: { ...PRICES, source: 'usage.cost' } }) })

  const result = await h.router.call({ binding: BINDING, request: REQUEST })

  // 0.0123 USD -> 12_300 micro-USD, not the 4_500 the table would compute.
  assert.equal(result.outcome.costMicroUsd, 12_300)
  assert.equal(payloads(h.store, 'llm.response')[0]?.['costMicroUsd'], 12_300)
})

test('a truncated body is retryable; a valid body of the wrong shape is not', async (t) => {
  const truncated = harness(t, [malformedJson()], { maxRetries: 0 })
  await assert.rejects(
    () => truncated.router.call({ binding: BINDING, request: REQUEST }),
    (e: unknown) => e instanceof ProviderError && e.kind === 'retryable',
  )

  // A 200 carrying something that is not a Chat Completions body means the
  // baseUrl or path is wrong. Retrying cannot fix configuration.
  const wrongShape = harness(t, [http(200, { message: 'hello from some other API' })], {
    maxRetries: 0,
  })
  await assert.rejects(
    () => wrongShape.router.call({ binding: BINDING, request: REQUEST }),
    (e: unknown) => e instanceof ProviderError && e.kind === 'fatal',
  )
})

test('a placeholder entry is never routable, so no compat model routes until the operator verifies it', async (t) => {
  const h = harness(t, [], { card: card({ placeholder: true }) })

  await assert.rejects(
    () => h.router.call({ binding: BINDING, request: REQUEST }),
    (e: unknown) => e instanceof Error && /toolCalling/.test(e.message),
  )
  // Refused before any spend could be recorded.
  assert.equal(h.store.query().length, 0)
  assert.equal(h.provider.requests.length, 0)
})

// ── credentials ────────────────────────────────────────────────────────────

test('Bearer comes from the broker seam and the literal ollama value is allowed', async (t) => {
  const hosted = harness(t, [completion({})])
  await hosted.router.call({ binding: BINDING, request: REQUEST })
  const sent = hosted.provider.requests[0]
  assert.ok(sent !== undefined)
  assert.equal(sent.headers['authorization'], `Bearer ${KEY}`)
  assert.equal(sent.headers['x-api-key'], undefined)
  // The adapter never sees the key: it sets content-type and nothing else.
  assert.equal(sent.headers['content-type'], 'application/json')

  // A loopback endpoint needs a placeholder token, not a secret. `ollama` is
  // the one literal providers.yaml may carry, and it still rides the same
  // broker seam rather than being spelled into the adapter.
  const local = harness(t, [completion({})], {
    card: card({
      local: true,
      baseUrl: 'http://127.0.0.1:11434',
      path: '/v1/chat/completions',
      auth: { header: 'Authorization', scheme: 'Bearer', value: 'ollama' },
      model: 'qwen3:8b',
    }),
    credential: 'ollama',
  })
  await local.router.call({ binding: BINDING, request: REQUEST })
  assert.equal(local.provider.requests[0]?.headers['authorization'], 'Bearer ollama')
})

test('credentials never appear in either event', async (t) => {
  // Guard the guard: an opaque key, so only SecretMask can censor it. A key
  // shaped like `sk-…` would be caught by the regex pass whether or not the
  // transport ever registered it.
  assert.equal(
    TOKEN_PATTERNS.some((re) => {
      re.lastIndex = 0
      return re.test(LEAK_KEY)
    }),
    false,
  )

  // Seeded into the outgoing prompt AND echoed back by the provider: the two
  // places a leak actually happens.
  const h = harness(t, [completion({ message: { role: 'assistant', content: `key is ${LEAK_KEY}` } })], {
    credential: LEAK_KEY,
  })

  await h.router.call({
    binding: BINDING,
    request: { ...REQUEST, system: `you are a test, key ${LEAK_KEY}` },
  })

  for (const row of h.store.query()) {
    assert.ok(!row.payload.includes(LEAK_KEY), `the credential reached a ${row.type} payload`)
  }
  // It did travel, on the wire, exactly once.
  assert.equal(h.provider.requests[0]?.headers['authorization'], `Bearer ${LEAK_KEY}`)
})
