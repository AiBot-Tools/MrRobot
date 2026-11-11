// T19 — logging transport and router.
//
// Invariant 4 is the spine of this file: every provider call, successful or
// not, is exactly two events carrying the prompt, the content, the tokens and
// the cost. A retry is another call, so it is another pair; a fallback is
// another call, so it is another pair. Nothing a run spends is invisible.
//
// The falsifiers, stated once so the tests below are read as proofs:
//
//   Move SecretMask.register after the llm.request append and the credentials
//   test fails — that ordering is the only thing standing between a prompt
//   that happens to contain a key and a key frozen into a hash chain.
//   Emit the response event only on success and the failed-attempt test fails.
//   Reset the attempt counter per ref and the retry-cap test passes six
//   attempts instead of three.
//   Let the chain advance twice and the fallback test sees three refs.
//   Fall back on a 401 and the auth test sees a second provider request.
//   Drop D16's check and the pricier-fallback test spends a budget it does
//   not have.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'
import { chatStop, fakeProvider, http, FAKE_PRICING, type ScriptedResponse } from './helpers/fake-provider.js'
import { TOKEN_PATTERNS } from '../src/events/redact.js'
import { toolName } from '../src/mcp/names.js'
import { costForCard } from '../src/models/cost.js'
import type { ModelCard } from '../src/models/registry.js'
import { normaliseChatUsage } from '../src/models/usage.js'
import {
  classifyProviderFailure,
  ProviderError,
  Router,
  RouterRefused,
  worstCaseTurnMicroUsd,
  type ModelBinding,
  type RouteRequest,
} from '../src/models/router.js'
import { loggedText, withCallEvents, type AdapterRequest, type ModelAdapter, type PreparedCall } from '../src/models/transport.js'
import { MAX_LOGGED_OUTPUT, PAYLOAD_TEXT_BUDGET } from '../src/events/bound.js'
import { canonicalize } from '../src/events/canonical.js'

// An OPAQUE credential: long enough for SecretMask to register
// (MIN_MASK_LENGTH = 8), distinctive enough that a substring search cannot
// match by accident, and — deliberately — of no shape any TOKEN_PATTERN
// recognises. A key spelled `sk-ant-…` would be censored by the regex pass
// whether or not the mask was ever told about it, which would make the
// credentials test pass against a transport that registers the mask too late.
// A pmmcp vault entry is opaque in exactly this way, so this is also the
// realistic case.
const KEY = 'Kx7fQ2mR9tLpZ4vB8nJ3wS6yH1dG5aC0'

/**
 * Credentials used by the leak test alone.
 *
 * SecretMask is a process-wide registry, so a key any earlier test resolved
 * is already registered by the time the leak test runs — which would mask a
 * transport that registers too late. These two are touched nowhere else, so
 * the ordering inside `withCallEvents` is the only thing that can censor them.
 */
const CRED_KEYS = {
  Authorization: 'Zq3wE7rT9yU1iO5pA2sD4fG6hJ8kL0mN',
  'x-api-key': 'Vb6nM2cX4zQ8wE1rT5yU7iO3pA9sD0fG',
} as const

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
    dialect: 'openai-chat',
    baseUrl: 'http://127.0.0.1:1',
    path: '/v1/chat/completions',
    auth: { header: 'Authorization', scheme: 'Bearer', vaultId: 'fake-key' },
    model: 'fake-model',
    local: false,
    placeholder: false,
    pricing: { ...PRICES },
    limits: { contextTokens: 100_000, maxOutputTokens: 4_000 },
    caps: {
      toolChoice: 'auto',
      parallelToolCalls: true,
      strictSchema: null,
      sampling: 'temperature',
      streamUsage: null,
      preserveAssistantMessage: false,
    },
    orchestrator: false,
    ...over,
  }
}

/** A probe fresh enough to route, for every ref. */

/**
 * A minimal Chat Completions adapter.
 *
 * It exists so this file tests the router and the transport against a real
 * wire shape rather than against a mock of themselves. T21 ships the
 * production one; this stays small on purpose.
 */
function chatAdapter(): ModelAdapter {
  return {
    dialect: 'openai-chat',
    prepare(request: AdapterRequest): PreparedCall {
      const body = {
        model: request.card.model,
        messages: [
          { role: 'system', content: request.system },
          ...request.messages.map((m) =>
            m.role === 'tool'
              ? { role: 'tool', tool_call_id: m.callId, content: m.content }
              : { role: m.role, content: m.content },
          ),
        ],
        // Invariant 10: `__` on the wire, dotted everywhere else.
        tools: request.tools.map((t) => ({
          type: 'function',
          function: { name: toolName(t.ref), description: t.description, parameters: t.inputSchema },
        })),
      }

      return {
        context: { prompt: JSON.stringify(body), tools: request.tools.map((t) => t.ref) },
        async perform(fetchImpl) {
          const response = await fetchImpl(`${request.card.baseUrl}${request.card.path}`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          })

          if (!response.ok) {
            const text = await response.text()
            throw new ProviderError(
              request.ref,
              classifyProviderFailure(response.status, text),
              `HTTP ${String(response.status)}`,
              { status: response.status },
            )
          }

          const json = (await response.json()) as {
            choices: { message: { content: string | null }; finish_reason: string }[]
            usage: unknown
          }
          const usage = normaliseChatUsage(json.usage)
          const { costMicroUsd } = costForCard(usage, request.card)
          const choice = json.choices[0]

          return {
            content: choice?.message.content ?? '',
            finish: choice?.finish_reason ?? 'unknown',
            inputTokens: usage.inputTokens,
            outputTokens: usage.outputTokens,
            cacheReadTokens: usage.cacheReadTokens,
            costMicroUsd,
          }
        },
      }
    },
  }
}

const REQUEST: RouteRequest = {
  system: 'you are a test',
  messages: [{ role: 'user', content: 'ping' }],
  tools: [{ ref: 'pmmcp.recall', description: 'recall', inputSchema: { type: 'object' } }],
}

interface Harness {
  readonly router: Router
  readonly store: ReturnType<typeof withStore>
  readonly provider: ReturnType<typeof fakeProvider>
  readonly sleeps: number[]
}

function harness(
  t: Parameters<typeof withStore>[0],
  script: readonly ScriptedResponse[],
  options: {
    cards?: ReadonlyMap<string, ModelCard>
    credential?: string
    maxRetries?: number
    adapters?: Router['call'] extends never ? never : Record<string, ModelAdapter>
    useDefaultAdapters?: boolean
  } = {},
): Harness {
  const store = withStore(t)
  const provider = fakeProvider(script)
  const sleeps: number[] = []

  const router = new Router({
    store,
    cards: options.cards ?? new Map([['fake/primary', card()]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve(options.credential ?? KEY),
    maxRetries: options.maxRetries ?? 2,
    ...(options.useDefaultAdapters === true ? {} : { adapters: { 'openai-chat': chatAdapter() } }),
    fetch: provider.fetch,
    sleep: (ms) => {
      sleeps.push(ms)
      return Promise.resolve()
    },
  })

  return { router, store, provider, sleeps }
}

const SOLO: ModelBinding = { primary: 'fake/primary', fallbacks: [] }

function payloads(store: Harness['store'], type: string): Record<string, unknown>[] {
  return store.query({ type }).map((row) => JSON.parse(row.payload) as Record<string, unknown>)
}

// ── the event pair ─────────────────────────────────────────────────────────

test('one call = llm.request then llm.response with prompt, content, tokens, costMicroUsd === 4500', async (t) => {
  const h = harness(t, [chatStop({ text: 'pong', promptTokens: 1_000, completionTokens: 100 })])

  const result = await h.router.call({ binding: SOLO, request: REQUEST })

  const rows = h.store.query()
  assert.deepEqual(
    rows.map((r) => r.type),
    ['llm.request', 'llm.response'],
  )

  const [response] = payloads(h.store, 'llm.response')
  // 1000 input at 3 USD/MTok + 100 output at 15 USD/MTok, in micro-USD:
  // (1000 * 3_000_000 + 100 * 15_000_000) / 1_000_000 = 4500. Exact, no rounding.
  assert.equal(response?.['costMicroUsd'], 4_500)
  assert.equal(result.outcome.costMicroUsd, 4_500)
  assert.equal(response?.['inputTokens'], 1_000)
  assert.equal(response?.['outputTokens'], 100)
  assert.equal(response?.['finish'], 'stop')
  assert.equal(result.servedRef, 'fake/primary')
  assert.equal(result.attempts, 1)
})

test('request event carries the prompt and response event carries the content', async (t) => {
  const h = harness(t, [chatStop({ text: 'the content' })])

  await h.router.call({ binding: SOLO, request: REQUEST })

  const [request] = payloads(h.store, 'llm.request')
  const [response] = payloads(h.store, 'llm.response')

  assert.ok(String(request?.['prompt']).includes('you are a test'))
  assert.ok(String(request?.['prompt']).includes('ping'))
  // Dotted in the event, `__` on the wire (invariant 10).
  assert.deepEqual(request?.['tools'], ['pmmcp.recall'])
  assert.ok(String(request?.['prompt']).includes('pmmcp__recall'))
  assert.equal(response?.['content'], 'the content')
})

test('credentials never appear in either event — key seeded in both authorization and x-api-key', async (t) => {
  for (const header of ['Authorization', 'x-api-key'] as const) {
    const key = CRED_KEYS[header]
    // Guard the guard: if a future edit gives one of these a recognisable
    // shape, the regex pass would censor it and this test would stop proving
    // anything about SecretMask's ordering.
    assert.equal(
      TOKEN_PATTERNS.some((re) => {
        re.lastIndex = 0
        return re.test(key)
      }),
      false,
      `${header}: the credential must be opaque, so only SecretMask can censor it`,
    )

    const scheme = header === 'Authorization' ? 'Bearer' : 'none'
    const cards = new Map([
      ['fake/primary', card({ auth: { header, scheme, vaultId: 'fake-key' } })],
    ])
    // The key is seeded into the outgoing prompt AND echoed back in the
    // provider's content: the two places a leak actually happens.
    const h = harness(t, [chatStop({ text: `your key is ${key}` })], { cards, credential: key })

    await h.router.call({
      binding: SOLO,
      request: { ...REQUEST, system: `you are a test, key ${key}` },
    })

    for (const row of h.store.query()) {
      assert.ok(
        !row.payload.includes(key),
        `${header}: the credential reached a ${row.type} payload — SecretMask must register before the request event`,
      )
    }

    // It did travel, on exactly the configured header and no other.
    const sent = h.provider.requests[0]
    assert.ok(sent !== undefined)
    assert.equal(sent.headers[header.toLowerCase()], scheme === 'Bearer' ? `Bearer ${key}` : key)
    assert.equal(sent.headers[header === 'Authorization' ? 'x-api-key' : 'authorization'], undefined)
  }
})

test('a failed HTTP attempt still emits llm.response with error and zero cost', async (t) => {
  const h = harness(t, [http(500, { error: 'boom' })], { maxRetries: 0 })

  await assert.rejects(
    () => h.router.call({ binding: SOLO, request: REQUEST }),
    (e: unknown) => e instanceof ProviderError && e.kind === 'retryable' && e.status === 500,
  )

  const [response] = payloads(h.store, 'llm.response')
  assert.equal(response?.['finish'], 'error')
  assert.equal(response?.['costMicroUsd'], 0)
  assert.equal(response?.['inputTokens'], 0)
  assert.ok(String(response?.['error']).includes('500'))
})

// ── retries ────────────────────────────────────────────────────────────────

test('each retry attempt is its own event pair (429 then 200 → four events, attempt 1,2)', async (t) => {
  const h = harness(t, [http(429, { error: 'slow down' }), chatStop({ text: 'pong' })], {
    maxRetries: 2,
  })

  const result = await h.router.call({ binding: SOLO, request: REQUEST })

  const llm = h.store.query().filter((r) => r.type.startsWith('llm.'))
  assert.equal(llm.length, 4)
  assert.deepEqual(
    payloads(h.store, 'llm.request').map((p) => p['attempt']),
    [1, 2],
  )
  assert.deepEqual(
    payloads(h.store, 'llm.response').map((p) => p['attempt']),
    [1, 2],
  )
  assert.equal(result.attempts, 2)
  assert.equal(result.fellBack, false)
  assert.deepEqual(h.sleeps, [500])
})

test('retry cap is honoured (three 429s, cap 2 → throws, six events)', async (t) => {
  const h = harness(
    t,
    [http(429, { error: 'a' }), http(429, { error: 'b' }), http(429, { error: 'c' })],
    { maxRetries: 2 },
  )

  await assert.rejects(
    () => h.router.call({ binding: SOLO, request: REQUEST }),
    (e: unknown) => e instanceof ProviderError && e.status === 429,
  )

  const llm = h.store.query().filter((r) => r.type.startsWith('llm.'))
  assert.equal(llm.length, 6)
  assert.equal(h.provider.requests.length, 3)
  // No fourth attempt was even prepared.
  assert.deepEqual(h.sleeps, [500, 1_000])
})

// ── fallback ───────────────────────────────────────────────────────────────

test('fallback advances once and records requested vs served', async (t) => {
  const cards = new Map([
    ['fake/primary', card()],
    // Cheaper than the primary, so D16's budget check is not what is under
    // test here.
    [
      'fake/cheap',
      card({ model: 'cheap-model', pricing: { ...PRICES, inMicroUsdPerMTok: 1, outMicroUsdPerMTok: 1 } }),
    ],
    ['fake/third', card({ model: 'third-model' })],
  ])
  // The fallback fails too. A router without the one-move cap would walk on
  // to fake/third; this one retries the model it already moved to.
  const h = harness(t, [http(500, { error: 'a' }), http(500, { error: 'b' }), chatStop({ text: 'pong' })], {
    cards,
  })

  const result = await h.router.call({
    binding: { primary: 'fake/primary', fallbacks: ['fake/cheap', 'fake/third'] },
    request: REQUEST,
    remainingMicroUsd: 2_000_000,
  })

  assert.equal(result.requestedRef, 'fake/primary')
  assert.equal(result.servedRef, 'fake/cheap')
  assert.equal(result.fellBack, true)
  assert.equal(result.attempts, 3)

  assert.deepEqual(
    payloads(h.store, 'llm.request').map((p) => p['ref']),
    ['fake/primary', 'fake/cheap', 'fake/cheap'],
  )
  const degraded = payloads(h.store, 'router.degraded').map((p) => String(p['reason']))
  assert.ok(degraded.some((r) => r.includes('falling back from fake/primary to fake/cheap')))
  // At most one fallback per call sequence: the third ref is never reached,
  // in a degraded reason or on the wire.
  assert.ok(!degraded.some((r) => r.includes('falling back') && r.includes('fake/third')))
  assert.equal(
    h.provider.requests.filter((r) => JSON.stringify(r.body).includes('third-model')).length,
    0,
  )
  assert.equal(h.provider.requests.length, 3)
})

test('auth failure never falls back', async (t) => {
  const cards = new Map([
    ['fake/primary', card()],
    ['fake/cheap', card({ pricing: { ...PRICES, inMicroUsdPerMTok: 1, outMicroUsdPerMTok: 1 } })],
  ])
  const h = harness(t, [http(401, { error: 'invalid x-api-key' })], { cards })

  await assert.rejects(
    () => h.router.call({
      binding: { primary: 'fake/primary', fallbacks: ['fake/cheap'] },
      request: REQUEST,
      remainingMicroUsd: 2_000_000,
    }),
    (e: unknown) => e instanceof ProviderError && e.kind === 'auth' && e.status === 401,
  )

  assert.equal(h.provider.requests.length, 1)
  const llm = h.store.query().filter((r) => r.type.startsWith('llm.'))
  assert.equal(llm.length, 2)
  assert.equal(payloads(h.store, 'router.degraded').length, 0)
})

test('fallback to a pricier model is refused when the remaining budget cannot cover one worst-case turn', async (t) => {
  const pricey = card({
    model: 'pricey-model',
    pricing: { ...PRICES, inMicroUsdPerMTok: 60_000_000, outMicroUsdPerMTok: 300_000_000 },
  })
  const cards = new Map([
    ['fake/primary', card()],
    ['fake/pricey', pricey],
  ])
  // 100_000 context + 4_000 output at those prices is 7_200_000 micro-USD.
  assert.equal(worstCaseTurnMicroUsd(pricey), 7_200_000)

  const h = harness(t, [http(429, { error: 'slow down' })], { cards, maxRetries: 0 })

  await assert.rejects(
    () => h.router.call({
      binding: { primary: 'fake/primary', fallbacks: ['fake/pricey'] },
      request: REQUEST,
      remainingMicroUsd: 1_000_000,
    }),
    (e: unknown) => e instanceof ProviderError && e.status === 429,
  )

  assert.equal(h.provider.requests.length, 1)
  assert.deepEqual(
    payloads(h.store, 'llm.request').map((p) => p['ref']),
    ['fake/primary'],
  )
  const reasons = payloads(h.store, 'router.degraded').map((p) => String(p['reason']))
  assert.ok(
    reasons.some((r) => r.includes('fake/pricey') && r.includes('7200000') && r.includes('1000000')),
    `expected a budget refusal naming both figures, got ${JSON.stringify(reasons)}`,
  )
})

// ── binding and stubs ──────────────────────────────────────────────────────

/** The bytes `text` takes as a string in canonical JSON, its quotes aside. */
const payloadBytes = (text: string): number => Buffer.byteLength(JSON.stringify(text)) - 2

test("llm.request's prompt is bounded by the bytes it takes in the payload's canonical JSON, so a prompt of escapes is cut to fit and its row is written", async (t) => {
  // The prompt is the provider's request body, already JSON; the log's
  // canonical JSON escapes each quote, backslash and newline in it again.
  // Bounded by its raw bytes, a prompt of them took twice that in the
  // payload and the append threw, with no llm.request and no llm.response.
  const store = withStore(t)
  const options = { store, scope: { runId: 'run_p', agentId: 'coder' }, ref: 'openai/fake', card: card() }
  const answer = (): Promise<{ content: string; finish: string; inputTokens: number; outputTokens: number; costMicroUsd: number }> =>
    Promise.resolve({ content: 'ok', finish: 'stop', inputTokens: 1, outputTokens: 1, costMicroUsd: 1 })
  const tools = Array.from({ length: 400 }, (_, i) => `pmmcp.a_tool_of_some_length_${String(i)}`)
  const cases: readonly (readonly [string, string, readonly string[]])[] = [
    ['quotes and backslashes', JSON.stringify({ messages: ['\\"'.repeat(PAYLOAD_TEXT_BUDGET / 3)] }), ['pmmcp.recall']],
    ['short lines of quotes', JSON.stringify({ content: 'print("abcdefg")\n'.repeat(4_300) }), []],
    ['a long tool list beside a prompt within its share', 'x'.repeat(PAYLOAD_TEXT_BUDGET), tools],
  ]
  for (const [what, prompt, offered] of cases) {
    await withCallEvents(options, { prompt, tools: offered }, answer)
    const row = store.query({ type: 'llm.request' }).at(-1)
    assert.ok(row !== undefined, what)
    assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, `${what}: ${String(Buffer.byteLength(row.payload))} bytes`)
    const logged = (JSON.parse(row.payload) as { prompt: string }).prompt
    assert.ok(prompt.startsWith(logged) && logged.length < prompt.length, `${what}: a start of the prompt, cut`)
    assert.ok(payloadBytes(logged) <= PAYLOAD_TEXT_BUDGET, what)
    // Cut no more than it must: to its share, or to what the tool list leaves.
    assert.ok(Buffer.byteLength(row.payload) > MAX_LOGGED_OUTPUT - 2_048, `${what}: ${String(Buffer.byteLength(row.payload))} bytes`)
  }
  assert.equal(store.query({ type: 'llm.response' }).length, cases.length)

  // Within its share, in the bytes it takes in the payload, a prompt is kept
  // whole; one byte past, it is cut to its share; and a prompt of escapes is
  // cut by those bytes, not by its raw length.
  const pay = (text: string): Record<string, unknown> => ({ schemaVersion: 1, ref: 'r', attempt: 1, prompt: text, tools: [] })
  const fits = 'y'.repeat(PAYLOAD_TEXT_BUDGET)
  assert.equal(loggedText(fits, pay), fits)
  assert.equal(loggedText(`${fits}y`, pay), fits)
  assert.equal(loggedText('"'.repeat(PAYLOAD_TEXT_BUDGET), pay), '"'.repeat(PAYLOAD_TEXT_BUDGET / 2))
  // Redacted first, then cut: a credential shape is never stored, whole or in part.
  const token = `ghp_${'Q7xK'.repeat(9)}`
  const across = loggedText(`${'z'.repeat(PAYLOAD_TEXT_BUDGET - 10)} ${token}`, pay)
  assert.equal(across.includes('ghp_'), false)
  assert.ok(across.endsWith(' [REDACTED'), across.slice(-20))
  // A payload whose stored size grows past what its prompt's share leaves is
  // cut on, by what it is over, until it fits.
  const echoing = (text: string): Record<string, unknown> => ({ ...pay(text), tail: text.slice(-20_000) })
  const cut = loggedText('w'.repeat(PAYLOAD_TEXT_BUDGET), echoing)
  assert.ok(Buffer.byteLength(canonicalize(echoing(cut))) <= MAX_LOGGED_OUTPUT)
  assert.ok(cut.length > 0 && cut.length < PAYLOAD_TEXT_BUDGET)
})

test('a prompt whose cut falls inside a surrogate pair keeps whole characters, and its llm.request row is written', async (t) => {
  // JSON leaves an emoji unescaped (4 UTF-8 bytes) and escapes a lone
  // surrogate (6), so the cut is made with 7 bytes of the share left before
  // two emoji: the first fits whole and the second does not. Cut by UTF-16
  // units, the first emoji's high surrogate (6) would fit and its low would
  // not, leaving a lone surrogate that canonical JSON refuses: the append, or
  // the measure before it, would throw.
  const emoji = '\u{1F600}'
  const prompt = `${'a'.repeat(PAYLOAD_TEXT_BUDGET - 7)}${emoji}${emoji}b`
  const pay = (text: string): Record<string, unknown> => ({ schemaVersion: 1, ref: 'r', attempt: 1, prompt: text, tools: [] })
  const logged = loggedText(prompt, pay)
  assert.equal(logged, `${'a'.repeat(PAYLOAD_TEXT_BUDGET - 7)}${emoji}`)
  assert.doesNotMatch(logged, /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/, 'a lone surrogate')
  assert.doesNotThrow(() => canonicalize({ prompt: logged }))
  assert.equal(payloadBytes(logged), PAYLOAD_TEXT_BUDGET - 3)

  const store = withStore(t)
  const options = { store, scope: { runId: 'run_u', agentId: 'coder' }, ref: 'openai/fake', card: card() }
  await withCallEvents(options, { prompt, tools: [] }, () =>
    Promise.resolve({ content: 'ok', finish: 'stop', inputTokens: 1, outputTokens: 1, costMicroUsd: 1 }),
  )
  const [row] = store.query({ type: 'llm.request' })
  assert.ok(row !== undefined, 'no llm.request row')
  assert.equal((JSON.parse(row.payload) as { prompt: string }).prompt, logged)
  assert.equal(store.query({ type: 'llm.response' }).length, 1)
})

test("llm.response's content is bounded by the bytes it takes in the payload's canonical JSON, so an answer of escapes is cut to fit and its row is written", async (t) => {
  // An answer dense in escapes (escaped JSON, code): each quote, backslash
  // and newline takes two bytes in the log's canonical JSON. Bounded by its
  // raw bytes, a 60 KB answer of these lines took some 80 KB there, the
  // append threw, and the call, and the run, ended in error.
  const store = withStore(t)
  const options = { store, scope: { runId: 'run_c', agentId: 'coder' }, ref: 'openai/fake', card: card() }
  const content = 'say "hi" \\\\ \n'.repeat(Math.ceil(60_000 / 13))
  assert.ok(Buffer.byteLength(content) >= 60_000 && Buffer.byteLength(content) < PAYLOAD_TEXT_BUDGET, 'within the raw share')
  const outcome = await withCallEvents(options, { prompt: 'p', tools: [] }, () =>
    Promise.resolve({ content, finish: 'stop', inputTokens: 1, outputTokens: 16_000, costMicroUsd: 1 }),
  )
  assert.equal(outcome.content, content, 'what the model answered is not cut')
  const [row] = store.query({ type: 'llm.response' })
  assert.ok(row !== undefined, 'no llm.response row')
  assert.ok(Buffer.byteLength(row.payload) <= MAX_LOGGED_OUTPUT, `${String(Buffer.byteLength(row.payload))} bytes`)
  const logged = (JSON.parse(row.payload) as { content: string; finish: string; outputTokens: number }).content
  assert.ok(content.startsWith(logged) && logged.length < content.length, 'a start of the answer, cut')
  assert.ok(payloadBytes(logged) <= PAYLOAD_TEXT_BUDGET)
  assert.ok(payloadBytes(logged) > PAYLOAD_TEXT_BUDGET - 32, 'cut no more than its share asks')
  // The rest of the row as it was: the answer's finish and its tokens.
  assert.equal((JSON.parse(row.payload) as { finish: string }).finish, 'stop')
  assert.equal((JSON.parse(row.payload) as { outputTokens: number }).outputTokens, 16_000)
  // Redacted first, then cut, as the prompt is.
  const token = `ghp_${'Q7xK'.repeat(9)}`
  await withCallEvents(options, { prompt: 'p', tools: [] }, () =>
    Promise.resolve({ content: `${'"'.repeat(PAYLOAD_TEXT_BUDGET / 2 - 5)} ${token}`, finish: 'stop', inputTokens: 1, outputTokens: 1, costMicroUsd: 1 }),
  )
  const second = store.query({ type: 'llm.response' }).at(-1)
  assert.ok(second !== undefined)
  assert.equal(second.payload.includes('ghp_'), false)
})

test('router refuses a ref not bound to the agent → no request event', async (t) => {
  const cards = new Map([
    ['fake/primary', card()],
    ['fake/elsewhere', card()],
  ])
  const h = harness(t, [], { cards })

  await assert.rejects(
    () => h.router.call({ binding: SOLO, request: REQUEST, ref: 'fake/elsewhere' }),
    (e: unknown) => e instanceof RouterRefused && e.ref === 'fake/elsewhere',
  )

  assert.equal(h.store.query().length, 0)
  assert.equal(h.provider.requests.length, 0)
})

test('router refuses a ref with no fresh probe (D28)', async (t) => {
  const store = withStore(t)
  const router = new Router({
    store,
    cards: new Map([['fake/primary', card()]]),
    probes: () => undefined,
    resolveCredential: () => Promise.resolve(KEY),
    maxRetries: 2,
    adapters: { 'openai-chat': chatAdapter() },
    fetch: fakeProvider([]).fetch,
  })

  await assert.rejects(
    () => router.call({ binding: SOLO, request: REQUEST }),
    (e: unknown) => e instanceof RouterRefused && /toolCalling/.test(e.message),
  )
  assert.equal(store.query().length, 0)
})

test('NotImplementedAdapter throws loudly for a real dialect', async (t) => {
  const cards = new Map([
    [
      'fake/primary',
      card({ dialect: 'anthropic', auth: { header: 'x-api-key', scheme: 'none', vaultId: 'k' } }),
    ],
  ])
  const h = harness(t, [], { cards, useDefaultAdapters: true })

  await assert.rejects(
    () => h.router.call({ binding: SOLO, request: REQUEST }),
    (e: unknown) =>
      e instanceof Error && /not implemented in this phase: anthropic adapter/.test(e.message),
  )

  // A stub must not look like a call that happened.
  assert.equal(h.store.query().length, 0)
  assert.equal(h.provider.requests.length, 0)
})
