// T07 — the mock MCP server itself.
//
// A test double is only useful if its failure modes match the real thing.
// These tests pin the ones that would otherwise mislead the hub's tests:
// a throwing tool resolves rather than rejecting, an unknown tool does the
// same, and the client does not follow cursors on its own.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'

import { FakeTransport, mockMcp, MOCK_TOOL_NAMES, pagedMcp } from './helpers/mock-mcp.js'

interface TextContent {
  type: string
  text: string
}

function textOf(result: unknown): string {
  const content = (result as { content?: TextContent[] }).content ?? []
  return content.map((c) => c.text).join('')
}

function isError(result: unknown): boolean {
  return (result as { isError?: boolean }).isError === true
}

test('lists the tool set with inputSchemas', async (t) => {
  const mcp = await mockMcp()
  t.after(() => mcp.close())

  const listed = await mcp.client.listTools()
  assert.deepEqual(
    listed.tools.map((tool) => tool.name).sort(),
    [...MOCK_TOOL_NAMES].sort(),
  )
  const recall = listed.tools.find((tool) => tool.name === 'recall')
  assert.ok(recall, 'recall must be listed')
  assert.equal(recall.inputSchema.type, 'object')
  const props = recall.inputSchema.properties as Record<string, unknown> | undefined
  assert.ok(props?.['query'], 'inputSchema must describe its arguments')
  // A dotted name survives the protocol untouched; mapping to `__` is the
  // kernel's job at the provider boundary, not the server's.
  assert.ok(listed.tools.some((tool) => tool.name === 'weird.name'))
})

test('boom resolves isError:true, not a rejection', async (t) => {
  const mcp = await mockMcp()
  t.after(() => mcp.close())

  // This is the trap. A thrown tool does NOT reject the call; it resolves
  // with isError set. Kernel code that only tries/catches would treat a
  // failed tool as a success.
  const result = await mcp.client.callTool({ name: 'boom', arguments: {} })
  assert.equal(isError(result), true)
  assert.match(textOf(result), /kaboom/)
  assert.deepEqual(mcp.calls.map((c) => c.tool), ['boom'])
})

test('unknown tool resolves isError:true with -32602 text', async (t) => {
  const mcp = await mockMcp()
  t.after(() => mcp.close())

  const result = await mcp.client.callTool({ name: 'nope', arguments: {} })
  assert.equal(isError(result), true)
  assert.match(textOf(result), /-32602/)
  assert.match(textOf(result), /nope/)
  // It never reached a handler, so nothing was recorded.
  assert.deepEqual(mcp.calls, [])
})

test('paged server yields nextCursor and the client does not auto-paginate', async (t) => {
  const paged = await pagedMcp(5, 2)
  t.after(() => paged.close())

  const first = await paged.client.listTools()
  assert.equal(first.tools.length, 2, 'one page only — the client does not follow cursors for us')
  assert.equal(first.nextCursor, '2')

  const names: string[] = first.tools.map((tool) => tool.name)
  let cursor: string | undefined = first.nextCursor
  let pages = 1
  while (cursor !== undefined) {
    const page = await paged.client.listTools({ cursor })
    names.push(...page.tools.map((tool) => tool.name))
    cursor = page.nextCursor
    pages++
  }
  assert.equal(pages, 3)
  assert.deepEqual(names, [...paged.toolNames])
})

test('FakeTransport is assignable to Transport without a cast', async () => {
  // If this ever needs a cast, the hub's one sanctioned cast is no longer the
  // only one, and the seam has drifted.
  const fake = new FakeTransport()
  const asTransport: Transport = fake
  await asTransport.start()
  assert.equal(fake.started, true)

  let closed = false
  fake.onclose = () => {
    closed = true
  }
  await asTransport.send({ jsonrpc: '2.0', id: 1, method: 'ping' })
  assert.equal(fake.sent.length, 1)
  await asTransport.close()
  assert.equal(fake.closed, true)
  assert.equal(closed, true, 'close must notify the owner')
})

test('records every call and throws on an unscripted tool', async (t) => {
  const mcp = await mockMcp()
  t.after(() => mcp.close())

  await mcp.client.callTool({ name: 'recall', arguments: { query: 'goals', limit: 3 } })
  await mcp.client.callTool({ name: 'weird.name', arguments: {} })
  assert.deepEqual(mcp.calls, [
    { tool: 'recall', args: { query: 'goals', limit: 3 } },
    { tool: 'weird.name', args: {} },
  ])

  // "Unscripted" at this layer means a tool the fixture does not define: the
  // server answers with an error rather than inventing a plausible result,
  // so a kernel bug that calls the wrong tool cannot pass silently.
  const result = await mcp.client.callTool({ name: 'not_a_fixture_tool', arguments: {} })
  assert.equal(isError(result), true)
  assert.equal(mcp.calls.length, 2, 'an unscripted tool must not be recorded as handled')
})
