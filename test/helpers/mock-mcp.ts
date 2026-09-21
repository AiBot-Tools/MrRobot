// In-process MCP server for hub tests.
//
// The hub must be testable without a live pmmcp, so this builds a real MCP
// client and server joined by an in-memory transport pair. It is a real
// protocol conversation, not a stub of our own client.
//
// IMPORTANT — the tool set here is a FIXTURE, not a description of pmmcp.
// The names were chosen to exercise specific kernel behaviour:
//
//   recall                 an ordinary exposed read
//   get_secret             a kernel-only tool. Its input shape { key } is the
//                          fixture's GUESS and is UNVERIFIED against the real
//                          pmmcp, which the operator has since confirmed takes
//                          `label`. Nothing may infer the live shape from here.
//   boom                   throws, to prove a thrown tool resolves isError
//   coding_agent           stays disabled for agents (nested LLM calls would
//                          bypass the router, budgets, taint and the log)
//   weird.name             a dotted name, to exercise the __ mapping
//   unclassified_new_tool  unknown to tool-views, so it must default kernel-only
//
// Every call is recorded, and an unscripted tool throws rather than returning
// something plausible: a test double that invents answers hides bugs.

import './guard.js'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type JSONRPCMessage,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js'
import * as z from 'zod'

export interface RecordedCall {
  readonly tool: string
  readonly args: Record<string, unknown>
}

export interface MockMcp {
  readonly client: Client
  readonly server: McpServer
  /** Every tools/call this server handled, in order. */
  readonly calls: RecordedCall[]
  close(): Promise<void>
}

/** The fixture tool names, in registration order. */
export const MOCK_TOOL_NAMES: readonly string[] = [
  'recall',
  'get_secret',
  'boom',
  'coding_agent',
  'weird.name',
  'unclassified_new_tool',
]

export async function mockMcp(): Promise<MockMcp> {
  const calls: RecordedCall[] = []
  const record = (tool: string, args: Record<string, unknown>): void => {
    calls.push({ tool, args })
  }

  const server = new McpServer({ name: 'mock-pmmcp', version: '0.0.1' })

  server.registerTool(
    'recall',
    {
      description: 'Recall from memory (fixture)',
      inputSchema: { query: z.string(), limit: z.number().int().optional() },
    },
    ({ query, limit }) => {
      record('recall', { query, limit })
      return { content: [{ type: 'text' as const, text: `recalled ${query} ${String(limit ?? 0)}` }] }
    },
  )

  server.registerTool(
    'get_secret',
    // UNVERIFIED fixture shape. The live pmmcp takes `label`, not `key`; this
    // exists only so a kernel-only classification has something to point at.
    { description: 'Vault read (fixture; arg name UNVERIFIED)', inputSchema: { key: z.string() } },
    ({ key }) => {
      record('get_secret', { key })
      return { content: [{ type: 'text' as const, text: 'fixture-value-not-a-secret' }] }
    },
  )

  server.registerTool('boom', { description: 'always throws' }, () => {
    record('boom', {})
    throw new Error('kaboom')
  })

  server.registerTool('coding_agent', { description: 'nested LLM call (must stay disabled)' }, () => {
    record('coding_agent', {})
    return { content: [{ type: 'text' as const, text: 'should never be reachable by an agent' }] }
  })

  server.registerTool('weird.name', { description: 'dotted name for the __ mapping' }, () => {
    record('weird.name', {})
    return { content: [{ type: 'text' as const, text: 'dotted' }] }
  })

  server.registerTool('unclassified_new_tool', { description: 'absent from tool-views' }, () => {
    record('unclassified_new_tool', {})
    return { content: [{ type: 'text' as const, text: 'unclassified' }] }
  })

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await server.connect(serverTransport)
  const client = new Client({ name: 'aos-hub-test', version: '0.0.1' })
  await client.connect(clientTransport)

  return {
    client,
    server,
    calls,
    async close() {
      await client.close()
      await server.close()
    },
  }
}

export interface PagedMcp {
  readonly client: Client
  readonly server: Server
  readonly toolNames: readonly string[]
  close(): Promise<void>
}

/**
 * A server that paginates tools/list. McpServer never paginates, so this uses
 * the low-level Server — the hub has to follow cursors itself, and that is
 * only testable against something that actually issues them.
 */
export async function pagedMcp(total = 5, pageSize = 2): Promise<PagedMcp> {
  const tools: Tool[] = Array.from({ length: total }, (_, i) => ({
    name: `t${String(i)}`,
    description: `tool ${String(i)}`,
    inputSchema: { type: 'object' as const, properties: {} },
  }))

  // The tools capability is mandatory: without it, registering a tools/list
  // handler throws.
  const server = new Server({ name: 'paged', version: '0.0.1' }, { capabilities: { tools: {} } })

  server.setRequestHandler(ListToolsRequestSchema, (req) => {
    const cursor = req.params?.cursor
    const start = cursor === undefined ? 0 : Number(cursor)
    const page = tools.slice(start, start + pageSize)
    const next = start + pageSize < tools.length ? String(start + pageSize) : undefined
    return next === undefined ? { tools: page } : { tools: page, nextCursor: next }
  })

  server.setRequestHandler(CallToolRequestSchema, (req) => ({
    content: [{ type: 'text' as const, text: `called ${req.params.name}` }],
  }))

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await server.connect(serverTransport)
  const client = new Client({ name: 'aos-hub-test', version: '0.0.1' })
  await client.connect(clientTransport)

  return {
    client,
    server,
    toolNames: tools.map((t) => t.name),
    async close() {
      await client.close()
      await server.close()
    },
  }
}

/**
 * A Transport that does nothing, for failure-path tests. It implements the
 * interface structurally, with no cast — the one sanctioned cast in the
 * kernel is in the hub, and nothing in the tests needs it.
 */
export class FakeTransport implements Transport {
  onclose?: () => void
  onerror?: (error: Error) => void
  onmessage?: (message: JSONRPCMessage) => void
  sessionId?: string
  readonly sent: JSONRPCMessage[] = []
  started = false
  closed = false

  async start(): Promise<void> {
    this.started = true
  }

  async send(message: JSONRPCMessage): Promise<void> {
    this.sent.push(message)
  }

  async close(): Promise<void> {
    this.closed = true
    this.onclose?.()
  }
}
