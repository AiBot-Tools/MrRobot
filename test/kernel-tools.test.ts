// The kernel-native tool runner, alone.
//
// KernelTools is the execute half of invariant 3 for tools that have no MCP
// server. The loop in front of it gates every call, but the runner must not rely
// on that: the hub re-checks the ticket and the exposure at execution, and a
// runner that trusted its caller would be the one door in the kernel where a
// ticket issued for `delegate {taskId: t1}` could run `delegate {taskId: t9}`.
// So each refusal is exercised here with no loop at all, and each one must leave
// the handler unrun and the log without a `tool.call`.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test, { type TestContext } from 'node:test'

import { PolicyDenied } from '../src/errors.js'
import { PAYLOAD_TEXT_BUDGET } from '../src/events/bound.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { hashArgs, type GateTicket } from '../src/policy/engine.js'
import { Budget } from '../src/runtime/budget.js'
import { KernelTools, type KernelToolContext, type KernelToolHandler } from '../src/runtime/kernel-tools.js'
import { withStore } from './helpers/store.js'

const VIEWS = parseToolViews({
  version: 1,
  servers: {
    kernel: {
      default: 'kernel-only',
      tools: {
        delegate: { exposure: 'agent', risk: 'write' },
        mint: { exposure: 'kernel-only', risk: 'write' },
      },
    },
  },
})

function setup(t: TestContext, run?: KernelToolHandler['run']) {
  const store = withStore(t)
  const ran: Record<string, unknown>[] = []
  const handler = (name: string): KernelToolHandler => ({
    name,
    description: name,
    inputSchema: { type: 'object' },
    run: async (args, ctx) => {
      ran.push(args)
      return run === undefined ? { ok: true, text: `ran ${name}` } : run(args, ctx)
    },
  })
  const tools = new KernelTools({ store, views: VIEWS, handlers: [handler('delegate'), handler('mint')] })
  const budget = new Budget({ usdMax: 1_000, maxLlmCalls: 1, maxToolCalls: 1, wallclockMs: 60_000 })
  const ctx: KernelToolContext = {
    runId: 'run_k',
    agent: {
      agentId: 'ceo',
      tier: 2,
      lane: 'main',
      model: { primary: 'anthropic/claude-sonnet-5', fallbacks: [] },
      toolAllow: ['kernel.delegate'],
      system: '',
      role: 'orchestrator',
    },
    budget,
  }
  const ticket = (toolRef: string, args: Record<string, unknown>): GateTicket => ({
    ticketId: 'tkt_1',
    runId: 'run_k',
    toolRef,
    argsHash: hashArgs(args),
    quarantine: false,
  })
  const toolRows = () => store.query().filter((r) => r.type === 'tool.call' || r.type === 'tool.result')
  return { tools, ctx, ticket, ran, toolRows }
}

test('a ticket issued for other arguments runs nothing and logs nothing', async (t) => {
  const { tools, ctx, ticket, ran, toolRows } = setup(t)
  const issued = ticket('kernel.delegate', { taskId: 't1', brief: 'research' })

  await assert.rejects(
    tools.call(issued, { taskId: 't9', brief: 'research' }, ctx),
    (e: unknown) => e instanceof PolicyDenied && /argsHash does not match/.test(e.message),
  )
  assert.deepEqual(ran, [], 'the handler ran under a ticket bound to different arguments')
  assert.deepEqual(toolRows(), [])
})

test('key order is not a difference: the ticket binds canonical arguments', async (t) => {
  const { tools, ctx, ticket, ran } = setup(t)
  const issued = ticket('kernel.delegate', { taskId: 't1', brief: 'research' })
  const outcome = await tools.call(issued, { brief: 'research', taskId: 't1' }, ctx)
  assert.equal(outcome.ok, true)
  assert.equal(ran.length, 1)
})

test('a tool agents may not call is refused even under a matching ticket', async (t) => {
  // A forged or stale ticket buys nothing: exposure is re-read at execution.
  const { tools, ctx, ticket, ran, toolRows } = setup(t)
  await assert.rejects(
    tools.call(ticket('kernel.mint', {}), {}, ctx),
    (e: unknown) => e instanceof PolicyDenied && /exposure is kernel-only/.test(e.message),
  )
  assert.deepEqual(ran, [])
  assert.deepEqual(toolRows(), [])
})

test('a ticket for a non-kernel ref is refused before any handler is looked up', async (t) => {
  const { tools, ctx, ticket, ran, toolRows } = setup(t)
  await assert.rejects(
    tools.call(ticket('pmmcp.recall', {}), {}, ctx),
    (e: unknown) => e instanceof PolicyDenied && /not a kernel tool/.test(e.message),
  )
  assert.deepEqual(ran, [])
  assert.deepEqual(toolRows(), [])
})

test('a call is logged before it runs and after, and a throwing handler is a failed call', async (t) => {
  const { tools, ctx, ticket, toolRows } = setup(t, () => Promise.reject(new Error('child launch failed')))
  const outcome = await tools.call(ticket('kernel.delegate', { taskId: 't1' }), { taskId: 't1' }, ctx)

  assert.equal(outcome.ok, false)
  assert.match(outcome.text, /child launch failed/)
  const rows = toolRows()
  assert.deepEqual(rows.map((r) => r.type), ['tool.call', 'tool.result'])
  const call = JSON.parse(rows[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(call['argsHash'], hashArgs({ taskId: 't1' }))
  assert.equal(call['toolRef'], 'kernel.delegate')
})

test('a kernel tool result is bounded exactly as an MCP result is', async (t) => {
  const huge = 'x'.repeat(PAYLOAD_TEXT_BUDGET * 3)
  const { tools, ctx, ticket, toolRows } = setup(t, () => Promise.resolve({ ok: true, text: huge }))
  const outcome = await tools.call(ticket('kernel.delegate', {}), {}, ctx)

  assert.equal(outcome.truncated, true)
  const result = JSON.parse(toolRows()[1]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(result['truncated'], true)
  assert.ok(String(result['text']).length <= PAYLOAD_TEXT_BUDGET, 'the log holds more than the payload budget')
  assert.equal(typeof result['sha256'], 'string', 'a truncated result must carry the hash of what was cut')
})
