// T08 — the fake provider.
//
// These tests pin the wire details that a router can get wrong in ways no
// type system catches: tool-call arguments arriving as a JSON string, cache
// token fields that must be added to the billable input, and the difference
// between a retryable 429, a 500, and a 200 whose body is not JSON.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  anthropicEndTurn,
  anthropicToolUse,
  chatStop,
  chatToolCalls,
  FAKE_PRICING,
  fakeProvider,
  http,
  malformedJson,
} from './helpers/fake-provider.js'

const JSON_HEADERS = { 'content-type': 'application/json', 'x-api-key': 'fake-key-not-real' }

test('records method, url, headers and parsed body of every call', async () => {
  const provider = fakeProvider([anthropicEndTurn({ text: 'hi' })])
  await provider.fetch('https://api.anthropic.test/v1/messages', {
    method: 'POST',
    headers: { ...JSON_HEADERS, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-5', messages: [{ role: 'user', content: 'hello' }] }),
  })

  assert.equal(provider.requests.length, 1)
  const req = provider.requests[0]
  assert.equal(req?.method, 'POST')
  assert.equal(req?.url, 'https://api.anthropic.test/v1/messages')
  // Headers are recorded so a test can prove exactly one auth header went out
  // and that no stray environment credential rode along.
  assert.equal(req?.headers['anthropic-version'], '2023-06-01')
  assert.equal(req?.headers['x-api-key'], 'fake-key-not-real')
  assert.equal(req?.headers['authorization'], undefined)
  const body = req?.body as { model: string; messages: unknown[] }
  assert.equal(body.model, 'claude-sonnet-5')
  assert.equal(body.messages.length, 1)
})

test('anthropic script returns tool_use then end_turn in order', async () => {
  const provider = fakeProvider([
    anthropicToolUse({ name: 'pmmcp__recall', input: { query: 'goals' }, cacheWriteTokens: 500, cacheReadTokens: 2_000 }),
    anthropicEndTurn({ text: 'done', outputTokens: 40 }),
  ])

  const first = (await (await provider.fetch('https://x.test/v1/messages', { method: 'POST' })).json()) as {
    stop_reason: string
    content: { type: string; name?: string; input?: Record<string, unknown> }[]
    usage: Record<string, number>
  }
  assert.equal(first.stop_reason, 'tool_use')
  assert.equal(first.content[0]?.type, 'tool_use')
  assert.equal(first.content[0]?.name, 'pmmcp__recall')
  // Anthropic delivers tool input already parsed, unlike Chat Completions.
  assert.deepEqual(first.content[0]?.input, { query: 'goals' })

  // Billable input is the sum of three fields, not just input_tokens. Getting
  // this wrong under-bills every cached request.
  const u = first.usage
  assert.equal(u['input_tokens'], 1_000)
  assert.equal(u['cache_creation_input_tokens'], 500)
  assert.equal(u['cache_read_input_tokens'], 2_000)
  const billableIn = (u['input_tokens'] ?? 0) + (u['cache_creation_input_tokens'] ?? 0) + (u['cache_read_input_tokens'] ?? 0)
  assert.equal(billableIn, 3_500)

  // Cost lands on an exact integer at the fixed prices, so a rounding bug has
  // nowhere to hide.
  const cost =
    (1_000 * FAKE_PRICING.inMicroUsdPerMTok +
      500 * FAKE_PRICING.cacheWriteMicroUsdPerMTok +
      2_000 * FAKE_PRICING.cacheReadMicroUsdPerMTok +
      100 * FAKE_PRICING.outMicroUsdPerMTok) /
    1_000_000
  assert.equal(Number.isInteger(cost), true)
  assert.equal(cost, 6_975)

  const second = (await (await provider.fetch('https://x.test/v1/messages', { method: 'POST' })).json()) as {
    stop_reason: string
    content: { text?: string }[]
  }
  assert.equal(second.stop_reason, 'end_turn')
  assert.equal(second.content[0]?.text, 'done')
  assert.equal(provider.requests.length, 2)
})

test('openai script returns tool_calls with string arguments then stop', async () => {
  const provider = fakeProvider([
    chatToolCalls({ name: 'pmmcp__recall', argumentsJson: '{"query":"goals"}' }),
    chatStop({ text: 'done', cachedTokens: 256 }),
  ])

  const first = (await (await provider.fetch('https://x.test/v1/chat/completions', { method: 'POST' })).json()) as {
    choices: { finish_reason: string; message: { tool_calls?: { function: { arguments: unknown } }[] } }[]
  }
  assert.equal(first.choices[0]?.finish_reason, 'tool_calls')
  const args = first.choices[0]?.message.tool_calls?.[0]?.function.arguments
  // The trap: arguments is a STRING here and an object in the Anthropic
  // dialect. Code that forgets to parse gets a string where it wants fields.
  assert.equal(typeof args, 'string')
  assert.deepEqual(JSON.parse(args as string), { query: 'goals' })

  const second = (await (await provider.fetch('https://x.test/v1/chat/completions', { method: 'POST' })).json()) as {
    choices: { finish_reason: string; message: { content: string } }[]
    usage: { prompt_tokens: number; prompt_tokens_details?: { cached_tokens?: number } }
  }
  assert.equal(second.choices[0]?.finish_reason, 'stop')
  assert.equal(second.choices[0]?.message.content, 'done')
  assert.equal(second.usage.prompt_tokens_details?.cached_tokens, 256)
})

test('serves the same script over a loopback http server', async (t) => {
  const provider = fakeProvider([anthropicEndTurn({ text: 'over the wire' })])
  const served = await provider.serve()
  t.after(() => served.close())

  // A real socket, on loopback, which the network guard permits.
  const res = await fetch(`${served.url}/v1/messages`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ model: 'claude-sonnet-5' }),
  })
  assert.equal(res.status, 200)
  const parsed = (await res.json()) as { content: { text?: string }[] }
  assert.equal(parsed.content[0]?.text, 'over the wire')

  const req = provider.requests[0]
  assert.equal(req?.method, 'POST')
  assert.equal(req?.url, '/v1/messages')
  assert.equal((req?.body as { model: string }).model, 'claude-sonnet-5')
})

test('429 carries retry-after; 500 and malformed JSON are distinguishable', async () => {
  const provider = fakeProvider([
    http(429, { type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } }, { 'retry-after': '3' }),
    http(500, { type: 'error', error: { type: 'api_error', message: 'boom' } }),
    malformedJson(),
  ])

  const rateLimited = await provider.fetch('https://x.test/v1/messages', { method: 'POST' })
  assert.equal(rateLimited.status, 429)
  assert.equal(rateLimited.headers.get('retry-after'), '3', 'the retry budget depends on this header')

  const serverError = await provider.fetch('https://x.test/v1/messages', { method: 'POST' })
  assert.equal(serverError.status, 500)

  // A 200 whose body is truncated: the status says success and parsing fails.
  // Code that trusts the status and skips error handling on parse breaks here.
  const truncated = await provider.fetch('https://x.test/v1/messages', { method: 'POST' })
  assert.equal(truncated.status, 200)
  await assert.rejects(() => truncated.json())
})

test('never resolves more calls than scripted (throws unscripted call)', async () => {
  const provider = fakeProvider([anthropicEndTurn({ text: 'only one' })])
  await provider.fetch('https://x.test/v1/messages', { method: 'POST' })

  // The double refuses to invent a second turn. A router that loops forever
  // fails loudly here instead of passing against an endlessly agreeable fake.
  await assert.rejects(
    () => provider.fetch('https://x.test/v1/messages', { method: 'POST' }),
    /unscripted call/,
  )
  // The over-call is still recorded, so the failure message can show what was
  // attempted.
  assert.equal(provider.requests.length, 2)
})
