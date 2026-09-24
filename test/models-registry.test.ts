// T18 — provider registry, usage normalisation and cost.
//
// Cost is frozen into the event log, so two implementations must agree on it
// exactly. The worked example below is hand-computed from the published
// per-million-token prices, and the arithmetic is integer throughout: a float
// dollar anywhere makes the log's costMicroUsd unreproducible.

import './helpers/guard.js'

import { freshProbe } from './helpers/probe.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parse as parseYaml } from 'yaml'

import { computeCost, costForCard } from '../src/models/cost.js'
import { parseProviders, routable, type ModelCard } from '../src/models/registry.js'
import { billableInputTokens, normaliseAnthropicUsage, normaliseChatUsage } from '../src/models/usage.js'

// Published prices, micro-USD per million tokens.
const OPUS_5 = {
  inMicroUsdPerMTok: 5_000_000,
  cacheWrite5mMicroUsdPerMTok: 6_250_000,
  cacheWrite1hMicroUsdPerMTok: 10_000_000,
  cacheReadMicroUsdPerMTok: 500_000,
  outMicroUsdPerMTok: 25_000_000,
}

const VALID = `
version: 1
entries:
  anthropic/claude-sonnet-5:
    dialect: anthropic
    baseUrl: https://api.anthropic.com
    path: /v1/messages
    auth:
      header: x-api-key
      scheme: none
      vaultId: anthropic-api-key
      envVar: ANTHROPIC_API_KEY
    headers:
      anthropic-version: "2023-06-01"
    model: claude-sonnet-5
    local: false
    placeholder: false
    pricing:
      inMicroUsdPerMTok: 2000000
      outMicroUsdPerMTok: 10000000
      cacheWrite5mMicroUsdPerMTok: 2500000
      cacheReadMicroUsdPerMTok: 200000
      source: table
    caps:
      toolChoice: auto
      parallelToolCalls: true
      strictSchema: null
      sampling: none
      streamUsage: true
      preserveAssistantMessage: false
  ollama/qwen3:8b:
    dialect: openai-chat
    baseUrl: http://127.0.0.1:11434
    path: /v1/chat/completions
    auth:
      header: Authorization
      scheme: Bearer
      value: ollama
    model: qwen3:8b
    local: true
    placeholder: true
    pricing:
      inMicroUsdPerMTok: 0
      outMicroUsdPerMTok: 0
      source: table
    caps:
      toolChoice: none
      parallelToolCalls: null
      strictSchema: null
      sampling: temperature
      streamUsage: null
      preserveAssistantMessage: true
`

function load(yaml: string): ReturnType<typeof parseProviders> {
  return parseProviders(parseYaml(yaml))
}

function card(overrides: Partial<ModelCard> = {}): ModelCard {
  const base = load(VALID).entries['anthropic/claude-sonnet-5']
  assert.ok(base)
  return { ...base, ...overrides }
}

test('parses an anthropic and an openai-chat entry', () => {
  const file = load(VALID)
  const anthropic = file.entries['anthropic/claude-sonnet-5']
  const ollama = file.entries['ollama/qwen3:8b']

  assert.equal(anthropic?.dialect, 'anthropic')
  assert.equal(anthropic?.auth.vaultId, 'anthropic-api-key')
  assert.equal(anthropic?.auth.envVar, 'ANTHROPIC_API_KEY')
  assert.equal(anthropic?.placeholder, false)
  // orchestrator is set by a human after the eval harness, never by code.
  assert.equal(anthropic?.orchestrator, false)

  assert.equal(ollama?.dialect, 'openai-chat')
  assert.equal(ollama?.local, true)
  assert.equal(ollama?.auth.value, 'ollama')
})

test('refuses a local entry with a non-loopback baseUrl and a non-local entry that is not https', () => {
  assert.throws(
    () => load(VALID.replace('baseUrl: http://127.0.0.1:11434', 'baseUrl: http://models.example.com')),
    /local entries must use a loopback baseUrl/,
  )
  assert.throws(
    () => load(VALID.replace('baseUrl: https://api.anthropic.com', 'baseUrl: http://api.anthropic.com')),
    /non-local entries must use https/,
  )
})

test('refuses a local-entry credential other than value: ollama, and any literal credential in headers', () => {
  // Any other literal in this file would be a secret in a file that holds none.
  assert.throws(() => load(VALID.replace('value: ollama', 'value: sk-FAKE')), /invalid/)

  // A credential dressed as a custom header, caught by key name…
  assert.throws(
    () =>
      load(
        VALID.replace('      anthropic-version: "2023-06-01"', '      anthropic-version: "2023-06-01"\n      authorization: "Bearer FAKE"'),
      ),
    /would hold a credential/,
  )
  // …and by value shape, under an innocent key name.
  assert.throws(
    () =>
      load(
        VALID.replace('      anthropic-version: "2023-06-01"', '      anthropic-version: "2023-06-01"\n      x-trace: "sk-ant-api03-FAKEFAKEFAKE"'),
      ),
    /holds a literal credential/,
  )
})

test('refuses a non-local entry without vaultId (envVar alone is not a credential path)', () => {
  // envVar is a secondary, consulted only when the vault fails and the
  // operator has opted in. Accepting it alone would move a production key out
  // of the vault with nothing saying so.
  const envOnly = VALID.replace('      vaultId: anthropic-api-key\n', '')
  assert.throws(() => load(envOnly), /envVar may only accompany a vaultId|needs auth.vaultId/)

  const neither = VALID.replace('      vaultId: anthropic-api-key\n      envVar: ANTHROPIC_API_KEY\n', '')
  assert.throws(() => load(neither), /a non-local entry needs auth.vaultId/)
})

test('accepts vaultId+envVar together', () => {
  // The shipped Claude entry carries both: the vault is primary, the env name
  // is the fallback the operator can enable.
  const file = load(VALID)
  const entry = file.entries['anthropic/claude-sonnet-5']
  assert.equal(entry?.auth.vaultId, 'anthropic-api-key')
  assert.equal(entry?.auth.envVar, 'ANTHROPIC_API_KEY')

  // vaultId alone is fine too.
  const vaultOnly = VALID.replace('      envVar: ANTHROPIC_API_KEY\n', '')
  assert.equal(load(vaultOnly).entries['anthropic/claude-sonnet-5']?.auth.envVar, undefined)
})

test('refuses a non-placeholder non-anthropic entry', () => {
  // CLAUDE.md: model ids are placeholders except the Claude entry. This keeps
  // that true in code rather than in a comment.
  assert.throws(
    () => load(VALID.replace('    local: true\n    placeholder: true', '    local: true\n    placeholder: false')),
    /every non-anthropic entry must be placeholder: true in Phase 0/,
  )
})

test('pricing must be integer micro-USD', () => {
  // A fractional price is a float in the cost path, and a float in the cost
  // path is a costMicroUsd two implementations can disagree about.
  assert.throws(() => load(VALID.replace('inMicroUsdPerMTok: 2000000', 'inMicroUsdPerMTok: 2.5')), /invalid/)
  assert.throws(() => load(VALID.replace('outMicroUsdPerMTok: 10000000', 'outMicroUsdPerMTok: -1')), /invalid/)
})

test('computes Anthropic cost with cache tiers to an exact integer', () => {
  // Hand-computed at Opus 5 prices:
  //   1000 input       × $5.00/MTok  = $0.005000
  //    500 5m writes   × $6.25/MTok  = $0.003125
  //   2000 cache reads × $0.50/MTok  = $0.001000
  //    100 output      × $25.00/MTok = $0.002500
  //                                    ---------
  //                                    $0.011625 = 11625 micro-USD
  const usage = normaliseAnthropicUsage({
    input_tokens: 1000,
    output_tokens: 100,
    cache_creation_input_tokens: 500,
    cache_read_input_tokens: 2000,
  })
  const cost = computeCost(usage, OPUS_5)
  assert.equal(cost, 11_625)
  assert.equal(Number.isInteger(cost), true)
})

test('cost rounds up at sub-micro-USD boundaries (1 token at 6.25 → 7 micro-USD)', () => {
  // One token priced at $6.25/MTok costs 6.25 micro-USD. Rounding down would
  // let a budget be exceeded by accumulating fractions.
  const usage = normaliseAnthropicUsage({
    input_tokens: 0,
    output_tokens: 0,
    cache_creation_input_tokens: 1,
  })
  assert.equal(computeCost(usage, OPUS_5), 7)

  // A free local model still costs nothing, so rounding up never invents a charge.
  assert.equal(
    computeCost(usage, { inMicroUsdPerMTok: 0, outMicroUsdPerMTok: 0, cacheWrite5mMicroUsdPerMTok: 0 }),
    0,
  )

  // Rounding happens once, at the end, not per component: three fractional
  // components sum to 18.75 micro-USD and round to 19, not to 21.
  const three = normaliseAnthropicUsage({ input_tokens: 0, output_tokens: 0, cache_creation_input_tokens: 3 })
  assert.equal(computeCost(three, OPUS_5), 19)
})

test('openrouter usage.cost overrides computed cost with costSource provider', () => {
  // When a provider reports what it will invoice, that figure wins: it
  // includes upstream markups the table cannot know about.
  const usage = normaliseChatUsage({
    prompt_tokens: 1000,
    completion_tokens: 100,
    prompt_tokens_details: { cached_tokens: 200 },
    cost: 0.0042,
  })
  assert.equal(usage.reportedCostUsd, 0.0042)

  const reported = costForCard(usage, card({ pricing: { ...card().pricing, source: 'usage.cost' } }))
  assert.equal(reported.costSource, 'provider')
  assert.equal(reported.costMicroUsd, 4_200)

  // With a table-priced card the same usage is computed locally instead.
  const computed = costForCard(usage, card())
  assert.equal(computed.costSource, 'table')
  assert.notEqual(computed.costMicroUsd, 4_200)
})

test('anthropic inputTokens = input + cache_creation + cache_read', () => {
  // The docs are explicit that billable input is the sum. Reading
  // input_tokens alone under-bills every cached request, and the better the
  // cache works the wronger it gets.
  const usage = normaliseAnthropicUsage({
    input_tokens: 1000,
    output_tokens: 100,
    cache_creation_input_tokens: 500,
    cache_read_input_tokens: 2000,
  })
  assert.equal(billableInputTokens(usage), 3_500)

  // The Chat dialect is the mirror image: cached tokens sit INSIDE
  // prompt_tokens, so they are subtracted, and the billable total is
  // prompt_tokens again — not prompt_tokens plus cached.
  const chat = normaliseChatUsage({
    prompt_tokens: 1000,
    completion_tokens: 100,
    prompt_tokens_details: { cached_tokens: 200 },
  })
  assert.equal(chat.inputTokens, 800)
  assert.equal(chat.cacheReadTokens, 200)
  assert.equal(billableInputTokens(chat), 1_000)

  // A 5m/1h breakdown is honoured when present.
  const split = normaliseAnthropicUsage({
    input_tokens: 10,
    output_tokens: 1,
    cache_creation_input_tokens: 300,
    cache_creation: { ephemeral_5m_input_tokens: 100, ephemeral_1h_input_tokens: 200 },
  })
  assert.equal(split.cacheWrite5mTokens, 100)
  assert.equal(split.cacheWrite1hTokens, 200)
})

test('routable requires probe.toolCalling and an unexpired ttl', () => {
  const now = 1_000_000
  const real = card()
  const fresh = freshProbe('anthropic/claude-sonnet-5', { probedAt: now - 1_000, ttlHours: 1 })

  assert.equal(routable(real, fresh, now), true)
  // Never probed: a manifest could otherwise name any string and fail
  // mid-run with a confusing provider error instead of at bind time.
  assert.equal(routable(real, undefined, now), false)
  // Probed and found lacking.
  assert.equal(routable(real, { ...fresh, toolCalling: false }, now), false)
  // Stale: capabilities change under a model id without warning.
  assert.equal(routable(real, { ...fresh, probedAt: now - 2 * 3_600_000 }, now), false)
  // A placeholder entry is never bindable, however good its probe.
  assert.equal(routable(card({ placeholder: true }), fresh, now), false)
})
