// T11 — the one mapping between dotted refs and provider tool names.
//
// The collision test is the one that matters. `a.b` and `a__b` both become
// `a__b`, so a tool call coming back from a model could mean either. If the
// kernel guessed, the gate could authorise one tool while the hub ran the
// other — a capability escalation that no other check would catch, because
// every layer would look internally consistent.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildNameTable, PROVIDER_TOOL_NAME, toolName, toolRef } from '../src/mcp/names.js'

test("toolName('pmmcp.recall') === 'pmmcp__recall'", () => {
  assert.equal(toolName('pmmcp.recall'), 'pmmcp__recall')
  assert.equal(toolName('github.create_pull_request'), 'github__create_pull_request')
  // Every dot maps, not just the first.
  assert.equal(toolName('a.b.c'), 'a__b__c')
  // Nothing else is touched: dashes, digits and existing underscores survive.
  assert.equal(toolName('vercel.deploy-preview_v2'), 'vercel__deploy-preview_v2')
})

test('toolRef round-trips every name in a table', () => {
  const refs = ['pmmcp.recall', 'pmmcp.remember', 'github.create_pull_request', 'a.b.c']
  const table = buildNameTable(refs)

  for (const ref of refs) {
    const name = toolName(ref)
    assert.equal(table.nameByRef.get(ref), name)
    assert.equal(toolRef(name, table), ref, `${name} must map back to ${ref}`)
  }

  // A name nobody registered is an error, never a guess. There is no
  // string-level inverse: `a__b` could be `a.b` or a tool actually named
  // `a__b`, and only the table knows which.
  assert.throws(() => toolRef('unknown__tool', table), /unknown provider tool name/)
})

test('collision (a.b vs a__b) is rejected at load with both refs named', () => {
  // The underscored form here is a legitimate MCP tool name — servers are
  // allowed to use underscores — so this is a real input, not a contrived one.
  let message = ''
  try {
    buildNameTable(['x.a__b', 'x.a.b'])
  } catch (e) {
    message = e instanceof Error ? e.message : String(e)
  }
  assert.match(message, /collision/)
  // Both sides must be named, or an operator cannot tell which two tools to
  // rename.
  assert.match(message, /x\.a__b/)
  assert.match(message, /x\.a\.b/)
  assert.match(message, /x__a__b/)

  // Listing the same ref twice is not a collision; it is just a duplicate.
  const table = buildNameTable(['pmmcp.recall', 'pmmcp.recall'])
  assert.equal(table.nameByRef.size, 1)
})

test('names failing ^[a-zA-Z0-9_-]{1,64}$ after mapping are rejected (70 chars, colon)', () => {
  // 70 characters after mapping: allowed by Anthropic's 128 limit, refused by
  // OpenAI's 64. Validating against the stricter rule keeps a tool from being
  // reachable on one provider and missing on another.
  const long = `server.${'t'.repeat(62)}`
  assert.equal(toolName(long).length, 70)
  assert.equal(PROVIDER_TOOL_NAME.test(toolName(long)), false)
  assert.throws(() => buildNameTable([long]), /fails the provider tool-name rule/)

  // A colon survives the mapping and is not in the shared alphabet.
  assert.throws(() => buildNameTable(['server.tool:v2']), /not a dotted reference|fails the provider/)
  // Exactly 64 is fine; 65 is not.
  assert.equal(buildNameTable([`s.${'t'.repeat(61)}`]).nameByRef.size, 1)
  assert.throws(() => buildNameTable([`s.${'t'.repeat(62)}`]), /fails the provider/)

  // A bare, undotted name is not a ref at all.
  assert.throws(() => buildNameTable(['recall']), /not a dotted reference/)
})

test('refs stay dotted in events and mapped in provider tool arrays', () => {
  // The two spellings must not bleed into each other's territory. This is the
  // shape of the contract the router and the gate both depend on.
  const refs = ['pmmcp.recall', 'github.create_pull_request']
  const table = buildNameTable(refs)

  // What goes to the provider: mapped, and every entry passes the rule.
  const providerToolArray = refs.map((ref) => ({ name: table.nameByRef.get(ref) }))
  for (const tool of providerToolArray) {
    assert.ok(tool.name)
    assert.equal(PROVIDER_TOOL_NAME.test(tool.name), true)
    assert.ok(!tool.name.includes('.'), 'a dot must never reach a provider tool array')
  }
  assert.deepEqual(providerToolArray.map((t) => t.name), ['pmmcp__recall', 'github__create_pull_request'])

  // What goes into an event payload or a gate decision: the dotted ref.
  const gateInput = { toolRef: toolRef('pmmcp__recall', table) }
  assert.equal(gateInput.toolRef, 'pmmcp.recall')
  assert.ok(gateInput.toolRef.includes('.'), 'the kernel records dotted refs, not provider names')
})
