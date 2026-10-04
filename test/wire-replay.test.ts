// Rejected tool calls go back on the wire as the calls they were.
//
// Both dialects answer a call by its id, and a real server refuses a result
// that answers a call not in the turn before it. The kernel used to drop a
// rejected call (an un-offered name, unparseable arguments) from the replayed
// assistant turn while still sending the error result for it — and when the
// model had written no text, the turn it replayed was empty, which the kernel's
// own Anthropic encoder refused, killing the run with `error` instead of telling
// the model. The fakes answer anything, so none of it showed until a delegated
// writer named a tool it was not offered.
//
// The falsifiers: drop rejectedCalls from the replay and every strict fake below
// answers 400; parse the rejected call into an executable one and the executor
// double records a call; rewrite a Chat-dialect call's arguments and the model
// no longer sees what it actually sent.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test from 'node:test'

import { AnthropicAdapter } from '../src/models/anthropic.js'
import { OpenAiChatAdapter } from '../src/models/openai-chat.js'
import type { ModelCard } from '../src/models/registry.js'
import { Router, type RouteRequest } from '../src/models/router.js'
import { writeProbeRecord } from '../src/models/probe.js'
import {
  anthropicEndTurn,
  anthropicToolUse,
  chatStop,
  FAKE_PRICING,
  fakeProvider,
  type ScriptEntry,
} from './helpers/fake-provider.js'
import { rows, runThroughControl, withKernel } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'
import { anthropicHistoryViolations, chatHistoryViolations, strictly } from './helpers/wire-rules.js'
import { rejectedCallReplays } from './helpers/replay-body.js'

const PRICES = {
  inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
  outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
  cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
  source: 'table',
} as const

const CAPS = {
  toolChoice: 'auto',
  parallelToolCalls: null,
  strictSchema: null,
  sampling: 'none',
  streamUsage: null,
  preserveAssistantMessage: false,
} as const

const ANTHROPIC_REF = 'anthropic/claude-sonnet-5'
const CHAT_REF = 'openrouter/moonshotai/kimi-k2'

const ANTHROPIC_CARD: ModelCard = {
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
  caps: { ...CAPS },
  orchestrator: false,
}

const CHAT_CARD: ModelCard = {
  dialect: 'openai-chat',
  baseUrl: 'https://openrouter.test',
  path: '/api/v1/chat/completions',
  auth: { header: 'Authorization', scheme: 'Bearer', vaultId: 'openrouter-api-key' },
  model: 'moonshotai/kimi-k2',
  local: false,
  placeholder: false,
  pricing: { ...PRICES },
  limits: { contextTokens: 128_000, maxOutputTokens: 4_096 },
  caps: { ...CAPS },
  orchestrator: false,
}

/** One call through a router holding both dialects; returns the body sent. */
async function send(
  t: Parameters<typeof withStore>[0],
  ref: string,
  reply: ScriptEntry,
  request: RouteRequest,
): Promise<unknown> {
  const provider = fakeProvider([reply])
  const router = new Router({
    store: withStore(t),
    cards: new Map([
      [ANTHROPIC_REF, ANTHROPIC_CARD],
      [CHAT_REF, CHAT_CARD],
    ]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve('Hn5rT8wQ2xZ6vB9mK3pL7dG1sA4fJ0cY'),
    maxRetries: 0,
    adapters: { anthropic: new AnthropicAdapter(), 'openai-chat': new OpenAiChatAdapter() },
    fetch: provider.fetch,
    sleep: () => Promise.resolve(),
  })
  await router.call({ binding: { primary: ref, fallbacks: [] }, request })
  return provider.requests[0]?.body
}

/** The history the loop builds when the model's only output was a rejected call. */
function afterRejection(name: string, rawArgs: unknown, id: string, reason: string): RouteRequest {
  return {
    system: 'you are a test',
    tools: [{ ref: 'pmmcp.recall', description: 'recall', inputSchema: { type: 'object' } }],
    messages: [
      { role: 'user', content: 'go' },
      { role: 'assistant', content: '', rejectedCalls: [{ id, name, reason, rawArgs }] },
      { role: 'tool', callId: id, ref: name, content: `[error] ${reason}`, isError: true },
    ],
  }
}

test('the strict fakes refuse exactly the histories the kernel used to send', () => {
  // Without this the validator could be vacuous and every test below would pass
  // against the bug. These are the pre-fix shapes, byte for byte in structure.
  assert.deepEqual(
    anthropicHistoryViolations({
      messages: [
        { role: 'user', content: 'go' },
        { role: 'assistant', content: [] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_x', content: 'e', is_error: true }] },
      ],
    }),
    [
      'messages[1]: an assistant turn with no content',
      'messages[2]: tool_result toolu_x answers no tool_use in the turn before',
    ],
  )
  assert.deepEqual(
    chatHistoryViolations({
      messages: [
        { role: 'user', content: 'go' },
        { role: 'assistant', content: null },
        { role: 'tool', tool_call_id: 'call_x', content: 'e' },
      ],
    }),
    [
      'messages[1]: an assistant turn with no content and no tool_calls',
      'messages[2]: tool message call_x answers no tool_call in the assistant turn before',
    ],
  )
  // And the other direction: a call left unanswered.
  assert.deepEqual(
    anthropicHistoryViolations({
      messages: [
        { role: 'user', content: 'go' },
        { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_y', name: 'a', input: {} }] },
        { role: 'user', content: 'next' },
      ],
    }),
    ['messages[1]: tool_use toolu_y has no tool_result immediately after'],
  )
})

test('Anthropic: an un-offered call is replayed as its own tool_use, so the error result pairs', async (t) => {
  const rejected: string[][] = []
  const body = (await send(
    t,
    ANTHROPIC_REF,
    strictly('anthropic', anthropicEndTurn({ text: 'ok' }), rejected),
    afterRejection('web__search', { q: 'x' }, 'toolu_bad', 'the model named a tool that was not offered on this call'),
  )) as { messages: { role: string; content: { type: string; id?: string; name?: string; input?: unknown }[] }[] }

  assert.deepEqual(rejected, [])
  const replayed = body.messages[1]?.content
  assert.deepEqual(replayed, [{ type: 'tool_use', id: 'toolu_bad', name: 'web__search', input: { q: 'x' } }])
})

test('Chat Completions: an un-offered call is replayed in tool_calls, so the tool message pairs', async (t) => {
  const rejected: string[][] = []
  const body = (await send(
    t,
    CHAT_REF,
    strictly('openai-chat', chatStop({ text: 'ok' }), rejected),
    afterRejection('web__search', '{"q":"x"}', 'call_bad', 'the model named a tool that was not offered on this call'),
  )) as { messages: { role: string; content: unknown; tool_calls?: unknown[] }[] }

  assert.deepEqual(rejected, [])
  assert.deepEqual(body.messages[2]?.tool_calls, [
    { id: 'call_bad', type: 'function', function: { name: 'web__search', arguments: '{"q":"x"}' } },
  ])
})

test('a rejected call survives a fallback to the other dialect', async (t) => {
  // A run that falls back mid-flight replays one provider's rejected call to
  // another. Chat hands over a raw string (here unparseable) and a name the
  // Anthropic alphabet does not allow; the replay must still be well-formed,
  // because a 400 here ends the run exactly as the original bug did.
  const rejected: string[][] = []
  const toAnthropic = (await send(
    t,
    ANTHROPIC_REF,
    strictly('anthropic', anthropicEndTurn({ text: 'ok' }), rejected),
    afterRejection('search the web!', '{"q": broken', 'call_bad', 'arguments are not valid JSON'),
  )) as { messages: { content: { name: string; input: unknown }[] }[] }
  const block = toAnthropic.messages[1]?.content[0]
  assert.equal(block?.name, 'search_the_web_')
  assert.deepEqual(block?.input, {}, 'unparseable arguments must become an empty object, not a crash')

  // Anthropic hands over an object; Chat needs a string.
  const toChat = (await send(
    t,
    CHAT_REF,
    strictly('openai-chat', chatStop({ text: 'ok' }), rejected),
    afterRejection('web__search', { q: 'x' }, 'toolu_bad', 'the model named a tool that was not offered on this call'),
  )) as { messages: { tool_calls?: { function: { arguments: string } }[] }[] }
  assert.equal(toChat.messages[2]?.tool_calls?.[0]?.function.arguments, '{"q":"x"}')
  assert.deepEqual(rejected, [])
})

test('a real kernel: a worker that names a tool it was not offered is told, and its run ends ok', async (t) => {
  // The case that surfaced the bug: the shipped writer, offered nothing, asks
  // for pmmcp__recall with no text. Before the fix the next request could not
  // even be encoded and the run ended `error`.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const rejected: string[][] = []
  const provider = fakeProvider([
    anthropicToolUse({ name: 'pmmcp__recall', input: { query: 'findings' } }),
    strictly('anthropic', anthropicEndTurn({ text: 'I have no tools; here is the write-up from the brief.' }), rejected),
  ])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-replay' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(ANTHROPIC_REF))
    },
  })

  const finished = await runThroughControl(kernel, 'write it up', 'writer')
  await kernel.shutdown()

  assert.deepEqual(rejected, [], 'the replayed history is one the real API refuses')
  assert.equal(finished['status'], 'ok', JSON.stringify(finished))
  // Told, not executed: no tool row of any kind, and the pmmcp double saw no recall.
  const logged = rows(fx.dbPath)
  assert.deepEqual(logged.filter((r) => r.type.startsWith('tool.')), [])
  assert.equal(mock.calls.filter((c) => c.tool === 'recall').length, 0)
})

test('the live replay body, offline: both shapes reach the wire well-formed, and each is logged', async (t) => {
  // The same body test/live-anthropic.test.ts sends to the real API. Here it
  // proves the assertions can pass and fail, and pins the two request shapes the
  // live run is there to settle: a tools field that does not name the replayed
  // call, and no tools field at all — the shipped writer's exact request.
  const rejected: string[][] = []
  const provider = fakeProvider([
    strictly('anthropic', anthropicEndTurn({ text: 'ok' }), rejected),
    strictly('anthropic', anthropicEndTurn({ text: 'ok' }), rejected),
  ])
  const store = withStore(t)
  const router = new Router({
    store,
    cards: new Map([[ANTHROPIC_REF, ANTHROPIC_CARD]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve('Hn5rT8wQ2xZ6vB9mK3pL7dG1sA4fJ0cY'),
    maxRetries: 0,
    adapters: { anthropic: new AnthropicAdapter() },
    fetch: provider.fetch,
    sleep: () => Promise.resolve(),
  })

  await rejectedCallReplays({ router, store, ref: ANTHROPIC_REF })

  assert.deepEqual(rejected, [])
  type Body = { tools?: { name: string }[]; messages: { content: unknown }[] }
  const [withTools, withoutTools] = provider.requests.map((r) => r.body as Body)
  assert.deepEqual(withTools?.tools?.map((tool) => tool.name), ['kernel__echo'])
  assert.equal(withoutTools !== undefined && 'tools' in withoutTools, false, 'an empty tool list still sent a tools field')
  for (const body of [withTools, withoutTools]) {
    const replayed = (body?.messages[1]?.content as { type: string; name: string }[])[0]
    assert.deepEqual([replayed?.type, replayed?.name], ['tool_use', 'web__search'])
  }
})
