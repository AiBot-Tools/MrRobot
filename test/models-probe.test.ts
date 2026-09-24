// T22 — aos probe.
//
// The probe is what makes a model routable, so its definition of success is
// the definition of "this model works". Every falsifier here is a way of
// loosening that definition into one that passes a model an agent loop cannot
// actually drive:
//
//   accept any tool call and a model that invents a tool name passes;
//   accept more than one and a model that cannot be asked for a single call
//   passes, which is the only granularity the gate can authorise;
//   skip the nonce check and a model emitting tool-shaped text passes without
//   having read the request at all;
//   skip the round trip and a model that falls over the moment it is handed a
//   tool result passes — the failure then arrives mid-run, after the spend.
//
// And in the other direction: short-circuit on a MISSING capability key and a
// perfectly good model is marked unroutable because we guessed a JSON key name
// wrong. The pre-checks may only ever say no.
//
// Served over a real loopback socket rather than an injected fetch: the
// pre-checks use a bare fetch that never touches the transport, and their URL,
// method and body are part of what is being tested.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { dirname, join, basename } from 'node:path'

import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'
import {
  anthropicEndTurn,
  anthropicToolUse,
  fakeProvider,
  http,
  FAKE_PRICING,
  type ScriptedResponse,
} from './helpers/fake-provider.js'
import type { ModelCard } from '../src/models/registry.js'
import { probe, probeFile, readProbeRecord, PROBE_TOOL_REF } from '../src/models/probe.js'

const KEY = 'Pz2mN6bV0cX4zL8kJ1hG5fD9sA3wQ7eR'
const NONCE = 'nonce-4f2a91c0'

const PRICES = {
  inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
  outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
  cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
  source: 'table',
} as const

const CAPS: ModelCard['caps'] = {
  toolChoice: 'auto',
  parallelToolCalls: null,
  strictSchema: null,
  sampling: 'none',
  streamUsage: null,
  preserveAssistantMessage: false,
}

function anthropicCard(baseUrl: string, over: Partial<ModelCard> = {}): ModelCard {
  return {
    dialect: 'anthropic',
    baseUrl,
    path: '/v1/messages',
    auth: { header: 'x-api-key', scheme: 'none', vaultId: 'k' },
    headers: { 'anthropic-version': '2023-06-01' },
    model: 'claude-sonnet-5',
    local: true,
    placeholder: false,
    pricing: { ...PRICES },
    limits: { contextTokens: 200_000, maxOutputTokens: 4_096 },
    caps: { ...CAPS },
    orchestrator: false,
    ...over,
  }
}

function chatCard(baseUrl: string, over: Partial<ModelCard> = {}): ModelCard {
  return {
    dialect: 'openai-chat',
    baseUrl,
    path: '/v1/chat/completions',
    auth: { header: 'Authorization', scheme: 'Bearer', value: 'ollama' },
    model: 'bonsai-7b',
    local: true,
    placeholder: false,
    pricing: { ...PRICES },
    limits: { contextTokens: 32_000, maxOutputTokens: 2_048 },
    caps: { ...CAPS },
    orchestrator: false,
    ...over,
  }
}

/** A Chat Completions reply, so the compat cases can be scripted precisely. */
function chat(message: unknown, finish = 'tool_calls'): ScriptedResponse {
  return http(200, {
    id: 'chatcmpl-probe',
    object: 'chat.completion',
    created: 1_758_000_000,
    model: 'bonsai-7b-q4',
    choices: [{ index: 0, message, finish_reason: finish }],
    usage: { prompt_tokens: 100, completion_tokens: 10, total_tokens: 110 },
  })
}

function chatToolCall(name: string, args: string): unknown {
  return {
    role: 'assistant',
    content: null,
    tool_calls: [{ id: 'call_1', type: 'function', function: { name, arguments: args } }],
  }
}

interface Served {
  readonly url: string
  readonly provider: ReturnType<typeof fakeProvider>
}

/** Serve a script over loopback and shut it down when the test ends. */
async function serve(t: TestContext, script: readonly ScriptedResponse[]): Promise<Served> {
  const provider = fakeProvider(script)
  const { url, close } = await provider.serve()
  t.after(() => close())
  return { url, provider }
}

/** The happy-path anthropic script: one well-formed call, then a completion. */
const GOOD_ANTHROPIC: readonly ScriptedResponse[] = [
  anthropicToolUse({ name: 'probe__echo', input: { nonce: NONCE }, inputTokens: 1_000, outputTokens: 100 }),
  anthropicEndTurn({ text: 'done', inputTokens: 1_200, outputTokens: 20 }),
]

// ── the verdict ────────────────────────────────────────────────────────────

test('toolCalling true only with exactly one well-formed probe_echo call and a successful round trip', async (t) => {
  const store = withStore(t)
  const dataDir = tmpdir(t)
  const { url, provider } = await serve(t, GOOD_ANTHROPIC)

  const { record } = await probe({
    store,
    dataDir,
    ref: 'anthropic/claude-sonnet-5',
    card: anthropicCard(url),
    credential: KEY,
    nonce: NONCE,
  })

  assert.equal(record.toolCalling, true)
  assert.equal(record.roundTrip, true)
  // The finish that PROVED the tool call, not the one that ended the turn.
  assert.equal(record.finishSeen, 'tool_use')
  // What the server said it was, which need not be what we asked for.
  assert.equal(record.modelIdSeen, 'claude-sonnet-5')
  // Both calls are counted: a probe is a real spend, and an operator running
  // probes across a provider list should see what it cost.
  //   call 1: 1_000 in * 3 + 100 out * 15 USD/MTok = 4_500 micro-USD
  //   call 2: 1_200 in * 3 +  20 out * 15 USD/MTok = 3_900 micro-USD
  assert.deepEqual(record.usage, { input: 2_200, output: 120 })
  assert.equal(record.costMicroUsd, 8_400)
  assert.equal(record.ttlHours, 24)
  assert.equal(provider.requests.length, 2)

  // Dotted in the kernel, `__` on the wire (invariant 10).
  assert.equal(PROBE_TOOL_REF, 'probe.echo')
  const body = provider.requests[0]?.body as { tools: { name: string }[] }
  assert.deepEqual(body.tools.map((x) => x.name), ['probe__echo'])
})

test('wrong tool name or nonce → toolCalling false with reason', async (t) => {
  const dataDir = tmpdir(t)

  const cases: { name: string; script: readonly ScriptedResponse[]; match: RegExp }[] = [
    {
      name: 'a tool we never offered',
      script: [chat(chatToolCall('some__other_tool', `{"nonce":"${NONCE}"}`))],
      match: /no usable tool call \(rejected: some__other_tool\)/,
    },
    {
      name: 'a nonce the model invented',
      script: [chat(chatToolCall('probe__echo', '{"nonce":"not-the-one"}'))],
      match: /echoed "not-the-one" instead of the nonce/,
    },
    {
      name: 'no tool call at all',
      script: [chat({ role: 'assistant', content: 'I could call probe__echo here.' }, 'stop')],
      match: /made no tool call/,
    },
    {
      name: 'two calls when asked for one',
      script: [
        chat({
          role: 'assistant',
          content: null,
          tool_calls: [
            { id: 'a', type: 'function', function: { name: 'probe__echo', arguments: `{"nonce":"${NONCE}"}` } },
            { id: 'b', type: 'function', function: { name: 'probe__echo', arguments: `{"nonce":"${NONCE}"}` } },
          ],
        }),
      ],
      match: /made 2 tool calls when asked for one/,
    },
  ]

  for (const c of cases) {
    const store = withStore(t)
    const { url, provider } = await serve(t, c.script)
    const { record } = await probe({
      store,
      dataDir,
      ref: `local/${c.name.replace(/[^a-z]+/g, '-')}`,
      card: chatCard(url),
      credential: KEY,
      nonce: NONCE,
    })

    assert.equal(record.toolCalling, false, c.name)
    assert.equal(record.roundTrip, false, c.name)
    assert.match(String(record.reason), c.match, c.name)
    // No round trip was attempted: the verdict was already no.
    assert.equal(provider.requests.length, 1, c.name)
  }
})

test('toolChoiceForced is null in Phase 0 (no forced pass is sent)', async (t) => {
  const store = withStore(t)
  const { url, provider } = await serve(t, GOOD_ANTHROPIC)

  const { record } = await probe({
    store,
    dataDir: tmpdir(t),
    ref: 'anthropic/claude-sonnet-5',
    card: anthropicCard(url),
    credential: KEY,
    nonce: NONCE,
  })

  assert.equal(record.toolChoiceForced, null)
  assert.equal(
    (JSON.parse(store.query({ type: 'probe.recorded' })[0]?.payload ?? '{}') as Record<string, unknown>)[
      'toolChoiceForced'
    ],
    null,
  )
  // Exactly two requests: the tool call and the round trip. A third would be
  // a forced pass, which this phase does not send.
  assert.equal(provider.requests.length, 2)
})

// ── pre-checks may only ever say no ────────────────────────────────────────

test('llama.cpp /props supports_tool_calls === false short-circuits without a chat request', async (t) => {
  const store = withStore(t)
  const dataDir = tmpdir(t)
  const { url, provider } = await serve(t, [
    http(200, { build_info: 'b4321', chat_template_caps: { supports_tool_calls: false } }),
  ])

  const { record } = await probe({
    store,
    dataDir,
    ref: 'llama/bonsai-7b',
    card: chatCard(url),
    credential: KEY,
    nonce: NONCE,
  })

  assert.equal(record.toolCalling, false)
  assert.match(String(record.reason), /supports_tool_calls: false/)
  assert.equal(record.serverVersion, 'b4321')
  assert.equal(record.costMicroUsd, 0)

  // A refusal is a result. Writing nothing would leave the operator to re-run
  // the probe to find out what it already knew.
  assert.deepEqual(readProbeRecord(dataDir, 'llama/bonsai-7b'), record)
  // One request, and it was the /props GET. No token was spent.
  assert.equal(provider.requests.length, 1)
  assert.equal(provider.requests[0]?.method, 'GET')
  assert.equal(provider.requests[0]?.url, '/props')
  assert.equal(store.query({ type: 'llm.request' }).length, 0)
})

test('missing chat_template_caps does not short-circuit (the chat probe runs)', async (t) => {
  const store = withStore(t)
  // The key name is a guess from llama.cpp's caps struct. If it is wrong, the
  // object is absent — and a probe that treated absence as "no tools" would
  // mark every good local model unroutable on that guess alone.
  const { url, provider } = await serve(t, [
    http(200, { build_info: 'b4321' }),
    chat(chatToolCall('probe__echo', `{"nonce":"${NONCE}"}`)),
    chat({ role: 'assistant', content: 'done' }, 'stop'),
  ])

  const { record } = await probe({
    store,
    dataDir: tmpdir(t),
    ref: 'llama/bonsai-7b',
    card: chatCard(url),
    credential: KEY,
    nonce: NONCE,
  })

  assert.equal(record.toolCalling, true)
  assert.equal(record.serverVersion, 'b4321')
  assert.equal(provider.requests.length, 3)
})

test('ollama /api/show without tools capability short-circuits', async (t) => {
  const store = withStore(t)
  const { url, provider } = await serve(t, [http(200, { capabilities: ['completion', 'vision'] })])

  const { record } = await probe({
    store,
    dataDir: tmpdir(t),
    ref: 'ollama/qwen3:8b',
    card: chatCard(url, { model: 'qwen3:8b' }),
    credential: 'ollama',
    nonce: NONCE,
  })

  assert.equal(record.toolCalling, false)
  assert.match(String(record.reason), /without tools/)
  assert.equal(provider.requests.length, 1)
  assert.equal(provider.requests[0]?.method, 'POST')
  assert.equal(provider.requests[0]?.url, '/api/show')
  assert.deepEqual(provider.requests[0]?.body, { model: 'qwen3:8b' })

  // The same endpoint reporting tools proceeds to the real probe.
  const store2 = withStore(t)
  const ok = await serve(t, [
    http(200, { capabilities: ['completion', 'tools'] }),
    chat(chatToolCall('probe__echo', `{"nonce":"${NONCE}"}`)),
    chat({ role: 'assistant', content: 'done' }, 'stop'),
  ])
  const second = await probe({
    store: store2,
    dataDir: tmpdir(t),
    ref: 'ollama/qwen3:8b',
    card: chatCard(ok.url, { model: 'qwen3:8b' }),
    credential: 'ollama',
    nonce: NONCE,
  })
  assert.equal(second.record.toolCalling, true)
  assert.equal(ok.provider.requests.length, 3)

  // And an /api/show that reports no capabilities array at all proceeds too:
  // the pre-check may only ever say no, never "I could not tell".
  const store3 = withStore(t)
  const quiet = await serve(t, [
    http(200, { model_info: {} }),
    chat(chatToolCall('probe__echo', `{"nonce":"${NONCE}"}`)),
    chat({ role: 'assistant', content: 'done' }, 'stop'),
  ])
  const third = await probe({
    store: store3,
    dataDir: tmpdir(t),
    ref: 'ollama/qwen3:8b',
    card: chatCard(quiet.url, { model: 'qwen3:8b' }),
    credential: 'ollama',
    nonce: NONCE,
  })
  assert.equal(third.record.toolCalling, true)
  assert.equal(quiet.provider.requests.length, 3)
})

// ── the log and the wire ───────────────────────────────────────────────────

test('probe emits llm.request/llm.response pairs through the same transport', async (t) => {
  const store = withStore(t)
  const { url } = await serve(t, GOOD_ANTHROPIC)

  await probe({
    store,
    dataDir: tmpdir(t),
    ref: 'anthropic/claude-sonnet-5',
    card: anthropicCard(url),
    credential: KEY,
    nonce: NONCE,
  })

  // Invariant 4 holds for a probe exactly as for a run: two pairs, numbered.
  assert.deepEqual(
    store.query().map((r) => r.type),
    ['llm.request', 'llm.response', 'llm.request', 'llm.response', 'probe.recorded'],
  )
  assert.deepEqual(
    store.query({ type: 'llm.request' }).map((r) => (JSON.parse(r.payload) as { attempt: number }).attempt),
    [1, 2],
  )
  // The credential travelled but was never written down.
  for (const row of store.query()) assert.ok(!row.payload.includes(KEY))
})

test('probe never sends temperature to anthropic and never a named tool_choice to llama.cpp', async (t) => {
  const store = withStore(t)
  const anthropic = await serve(t, GOOD_ANTHROPIC)
  await probe({
    store,
    dataDir: tmpdir(t),
    ref: 'anthropic/claude-sonnet-5',
    card: anthropicCard(anthropic.url),
    credential: KEY,
    nonce: NONCE,
  })

  for (const request of anthropic.provider.requests) {
    const body = request.body as Record<string, unknown>
    for (const key of ['temperature', 'top_p', 'top_k']) assert.equal(key in body, false)
  }

  const store2 = withStore(t)
  const llama = await serve(t, [
    http(200, { build_info: 'b1' }),
    chat(chatToolCall('probe__echo', `{"nonce":"${NONCE}"}`)),
    chat({ role: 'assistant', content: 'done' }, 'stop'),
  ])
  await probe({
    store: store2,
    dataDir: tmpdir(t),
    ref: 'llama/bonsai-7b',
    card: chatCard(llama.url),
    credential: KEY,
    nonce: NONCE,
  })

  for (const request of llama.provider.requests.slice(1)) {
    const body = request.body as Record<string, unknown>
    const choice = body['tool_choice']
    // A string, never the `{type:'function', function:{name}}` named shape.
    assert.equal(typeof choice, 'string')
    assert.equal(choice, 'auto')
    for (const key of ['temperature', 'top_p', 'top_k']) assert.equal(key in body, false)
  }
})

// ── where the record lives ─────────────────────────────────────────────────

test('record is written outside providers.yaml', async (t) => {
  const store = withStore(t)
  const dataDir = tmpdir(t)
  const { url } = await serve(t, GOOD_ANTHROPIC)

  const { record, path } = await probe({
    store,
    dataDir,
    ref: 'anthropic/claude-sonnet-5',
    card: anthropicCard(url),
    credential: KEY,
    nonce: NONCE,
  })

  // A probe verdict is observed state, not configuration. Writing it back
  // into providers.yaml would make a file the operator edits by hand also a
  // file the kernel rewrites underneath them.
  assert.equal(dirname(path), join(dataDir, 'probes'))
  assert.equal(basename(path), 'anthropic%2Fclaude-sonnet-5.json')
  assert.ok(!path.includes('providers.yaml'))
  assert.ok(!path.includes(`${process.cwd()}/config`))

  // It round-trips through its own schema.
  assert.deepEqual(readProbeRecord(dataDir, 'anthropic/claude-sonnet-5'), record)
  assert.equal(readProbeRecord(dataDir, 'anthropic/never-probed'), undefined)
})

test('probe record path stays under <dataDir>/probes for a ref containing / : and ..', () => {
  const dataDir = '/tmp/aos-test'
  const probes = join(dataDir, 'probes')

  for (const ref of ['openrouter/moonshotai/kimi-k3', 'ollama/qwen3:8b', 'anthropic/../../x']) {
    const path = probeFile(dataDir, ref)
    // One flat file directly under probes/ — the encoding is what stops a
    // ref from steering the write anywhere else.
    assert.equal(dirname(path), probes, ref)
    assert.equal(basename(path).includes('/'), false, ref)
    assert.ok(path.startsWith(`${probes}/`), ref)
  }

  assert.equal(basename(probeFile(dataDir, 'anthropic/../../x')), 'anthropic%2F..%2F..%2Fx.json')
  assert.equal(basename(probeFile(dataDir, 'ollama/qwen3:8b')), 'ollama%2Fqwen3%3A8b.json')
})
