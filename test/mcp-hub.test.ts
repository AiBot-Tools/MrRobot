// T23 — the MCP hub.
//
// The hub is the only thing in the kernel that holds an MCP connection, so
// every test here is about what it refuses rather than what it does.
//
// The falsifiers, stated once:
//
//   Trust the ticket's own word about the tool and a forged ticket for
//   get_secret executes get_secret — the single worst outcome in the kernel,
//   and the one an unforgeable ticket would NOT prevent, because kernel code
//   can mint a real one. Re-deriving exposure at execution time is what makes
//   forgery worthless.
//   Skip the argsHash check and an approved "delete /tmp/x" runs as
//   "delete /etc/x".
//   Put the client on the agent view and invariant 2 is gone: an agent's code
//   path can reach the server with no gate at all.
//   Log a kernel-only result and the next get_secret freezes a credential
//   into a chain that by design cannot be rewritten.
//   Treat only rejections as failure and a tool that threw is recorded as a
//   success, because MCP reports a thrown tool as isError on a 200.
//   Stop after the first page of tools/list and every tool past the page
//   boundary silently does not exist.
//   Resume a dead session by id and the heartbeat reconnects to nothing for
//   ever, because the id is precisely what the server forgot.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { parse as parseYaml } from 'yaml'

import { StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { withStore } from './helpers/store.js'
import { mockMcp, pagedMcp, type MockMcp } from './helpers/mock-mcp.js'
import { McpHub, splitRef } from '../src/mcp/hub.js'
import { toolName } from '../src/mcp/names.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { hashArgs, type GateTicket } from '../src/policy/engine.js'
import { PolicyDenied } from '../src/errors.js'

const VIEWS = parseToolViews(
  parseYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall: { exposure: agent, risk: read }
      boom: { exposure: agent, risk: read }
      weird.name: { exposure: agent, risk: read }
      get_secret: { exposure: kernel-only }
      coding_agent: { exposure: disabled }
  paged:
    default: kernel-only
    tools:
      t0: { exposure: agent, risk: read }
      t4: { exposure: agent, risk: read }
`),
)

/** A well-formed ticket for a tool and arguments. Forgeable on purpose. */
function ticketFor(toolRef: string, args: Record<string, unknown>): GateTicket {
  return {
    ticketId: 'tkt_test',
    runId: 'run_test',
    toolRef,
    argsHash: hashArgs(args),
    quarantine: false,
  }
}

interface Wired {
  readonly hub: McpHub
  readonly store: ReturnType<typeof withStore>
  readonly mock: MockMcp
}

async function wire(t: TestContext, options: { pingIntervalMs?: number } = {}): Promise<Wired> {
  const store = withStore(t)
  const mock = await mockMcp()
  const hub = new McpHub({
    store,
    views: VIEWS,
    ...(options.pingIntervalMs === undefined ? {} : { pingIntervalMs: options.pingIntervalMs }),
  })
  t.after(async () => {
    await hub.close()
    await mock.close().catch(() => undefined)
  })
  const status = await hub.connect('pmmcp', () => Promise.resolve(mock.client))
  assert.equal(status, 'connected')
  return { hub, store, mock }
}

function payloads(store: Wired['store'], type: string): Record<string, unknown>[] {
  return store.query({ type }).map((row) => JSON.parse(row.payload) as Record<string, unknown>)
}

// ── connection and classification ──────────────────────────────────────────

test('connects over InMemoryTransport and lists all pages', async (t) => {
  const store = withStore(t)
  // Five tools across three pages. The SDK does not follow cursors for us, so
  // a hub that called listTools once would see two tools and silently lose
  // three — including any the operator had classified.
  const paged = await pagedMcp(5, 2)
  const hub = new McpHub({ store, views: VIEWS })
  t.after(async () => {
    await hub.close()
    await paged.close().catch(() => undefined)
  })

  assert.equal(await hub.connect('paged', () => Promise.resolve(paged.client)), 'connected')
  assert.equal(payloads(store, 'hub.connected')[0]?.['toolCount'], 5)

  const classified = payloads(store, 'hub.tools.classified')[0]
  assert.equal(classified?.['exposed'], 2)
  // t1, t2, t3 were never classified, and they are on pages 1 and 2.
  assert.deepEqual(classified?.['unclassified'], ['t1', 't2', 't3'])
})

test('unclassified tools are logged and default to kernel-only', async (t) => {
  const { hub, store } = await wire(t)

  const classified = payloads(store, 'hub.tools.classified')[0]
  assert.deepEqual(classified?.['unclassified'], ['unclassified_new_tool'])
  // New tools appear on upstream servers without warning. Until a human
  // classifies one it must be unreachable, not quietly available.
  assert.equal(
    hub.agentView().tools.some((x) => x.ref === 'pmmcp.unclassified_new_tool'),
    false,
  )
  await assert.rejects(
    () => hub.call(ticketFor('pmmcp.unclassified_new_tool', {}), {}),
    (e: unknown) => e instanceof PolicyDenied && /exposure is kernel-only/.test(e.message),
  )
})

test('agent view exposes only agent tools named with __ and keys are exactly [tools, call]', async (t) => {
  const { hub } = await wire(t)
  const view = hub.agentView()

  // Exactly two keys. A client, a server id or a session here would be a
  // handle an agent's code path could reach through — invariant 2 is the
  // claim that no such handle exists.
  assert.deepEqual(Object.keys(view), ['tools', 'call'])

  assert.deepEqual(
    view.tools.map((x) => x.ref).sort(),
    ['pmmcp.boom', 'pmmcp.recall', 'pmmcp.weird.name'],
  )
  // Every exposed ref reaches a model through the one mapping, `__`-spelled.
  assert.deepEqual(
    view.tools.map((x) => toolName(x.ref)).sort(),
    ['pmmcp__boom', 'pmmcp__recall', 'pmmcp__weird__name'],
  )
  // Neither the kernel-only nor the disabled tool is visible.
  for (const hidden of ['pmmcp.get_secret', 'pmmcp.coding_agent']) {
    assert.equal(view.tools.some((x) => x.ref === hidden), false, hidden)
  }
  assert.ok(view.tools.every((x) => typeof x.inputSchema === 'object'))
})

// ── the three refusals ─────────────────────────────────────────────────────

test('call without a ticket throws PolicyDenied', async (t) => {
  const { hub, mock } = await wire(t)

  for (const bogus of [undefined, null, {}, { toolRef: 'pmmcp.recall' }]) {
    await assert.rejects(
      () => hub.call(bogus as unknown as GateTicket, { query: 'x' }),
      (e: unknown) => e instanceof PolicyDenied && /without a gate ticket/.test(e.message),
    )
  }
  assert.equal(mock.calls.length, 0)
})

test('call with a ticket whose argsHash mismatches throws', async (t) => {
  const { hub, mock, store } = await wire(t)

  // Approved for one query, executed with another: the oldest trick there is.
  const ticket = ticketFor('pmmcp.recall', { query: 'the approved one' })
  await assert.rejects(
    () => hub.call(ticket, { query: 'something else entirely' }),
    (e: unknown) => e instanceof PolicyDenied && /argsHash does not match/.test(e.message),
  )

  assert.equal(mock.calls.length, 0)
  // Refused before anything was recorded as having been attempted.
  assert.equal(store.query({ type: 'tool.call' }).length, 0)

  // The same ticket with its own arguments works.
  const ok = await hub.call(ticket, { query: 'the approved one' })
  assert.equal(ok.ok, true)
  assert.equal(mock.calls.length, 1)
})

test('call re-checks exposure and throws on a forged ticket for a kernel-only tool', async (t) => {
  const { hub, mock, store } = await wire(t)

  // A perfectly well-formed ticket with a correct argsHash. Nothing about the
  // ticket is wrong; the tool is. An unforgeable ticket would not help here,
  // because kernel code can mint a real one — only re-deriving exposure at
  // execution time does.
  const forged = ticketFor('pmmcp.get_secret', { key: 'anthropic-api-key' })
  await assert.rejects(
    () => hub.call(forged, { key: 'anthropic-api-key' }),
    (e: unknown) => e instanceof PolicyDenied && /exposure is kernel-only/.test(e.message),
  )

  // The disabled tool is refused the same way, for everyone.
  await assert.rejects(
    () => hub.call(ticketFor('pmmcp.coding_agent', {}), {}),
    (e: unknown) => e instanceof PolicyDenied && /exposure is disabled/.test(e.message),
  )

  assert.equal(mock.calls.length, 0)
  assert.equal(store.query({ type: 'tool.call' }).length, 0)
})

// ── the kernel-only door ───────────────────────────────────────────────────

test('callKernelOnly reaches get_secret and the result is never appended to the log', async (t) => {
  const { hub, store, mock } = await wire(t)

  const result = await hub.callKernelOnly(
    'pmmcp',
    'get_secret',
    { key: 'anthropic-api-key' },
    'resolve the anthropic provider credential at boot',
  )

  assert.equal(result.ok, true)
  assert.equal(mock.calls.length, 1)
  assert.equal(mock.calls[0]?.tool, 'get_secret')

  // Nothing about the call or its result reaches the chain. A tool.result for
  // get_secret would freeze a credential into a log that cannot be rewritten
  // by design; the broker logs secret.accessed { id, purpose, source } instead.
  assert.equal(store.query({ type: 'tool.call' }).length, 0)
  assert.equal(store.query({ type: 'tool.result' }).length, 0)

  const whole = JSON.stringify(store.query())
  const returned = JSON.stringify(result.content)
  assert.ok(returned.length > 0)
  assert.ok(!whole.includes('anthropic-api-key'), 'the secret id reached the log')

  // Disabled means nobody, the kernel included.
  await assert.rejects(
    () => hub.callKernelOnly('pmmcp', 'coding_agent', {}, 'anything'),
    (e: unknown) => e instanceof PolicyDenied && /disabled for every caller/.test(e.message),
  )
  // And a call site that cannot say why does not get to reach a vault.
  await assert.rejects(
    () => hub.callKernelOnly('pmmcp', 'get_secret', {}, '  '),
    (e: unknown) => e instanceof PolicyDenied && /must state its purpose/.test(e.message),
  )
})

// ── failures ───────────────────────────────────────────────────────────────

test('isError results and rejections are both failures', async (t) => {
  const { hub, store, mock } = await wire(t)

  // MCP reports a tool that threw as isError on a successful response, not as
  // a rejection. Watching only for rejections records a failure as a success.
  const thrown = await hub.call(ticketFor('pmmcp.boom', {}), {})
  assert.equal(thrown.ok, false)
  assert.equal(payloads(store, 'tool.result')[0]?.['ok'], false)

  // A transport-level failure is the other half of the same question.
  await mock.close()
  const rejected = await hub.call(ticketFor('pmmcp.recall', { query: 'x' }), { query: 'x' })
  assert.equal(rejected.ok, false)
  assert.equal(payloads(store, 'tool.result')[1]?.['ok'], false)
  // Both were still recorded: a failed call is a call.
  assert.equal(store.query({ type: 'tool.call' }).length, 2)
})

test('404 on ping triggers close and a fresh connect (factory called twice)', async (t) => {
  const store = withStore(t)
  const first = await mockMcp()
  const second = await mockMcp()

  let closed = false
  const patched = first.client as unknown as Record<string, unknown>
  patched['ping'] = () => Promise.reject(new StreamableHTTPError(404, 'session not found'))
  const realClose = first.client.close.bind(first.client)
  patched['close'] = async () => {
    closed = true
    await realClose()
  }

  let calls = 0
  const factory = (): Promise<typeof first.client> => {
    calls++
    return Promise.resolve(calls === 1 ? first.client : second.client)
  }

  const hub = new McpHub({ store, views: VIEWS })
  t.after(async () => {
    await hub.close()
    await first.close().catch(() => undefined)
    await second.close().catch(() => undefined)
  })

  assert.equal(await hub.connect('pmmcp', factory), 'connected')
  assert.equal(calls, 1)

  assert.equal(await hub.heartbeat('pmmcp'), 'reconnected')
  // Closed, then a FRESH transport from the factory. Resuming by session id
  // would reconnect to the very thing the server has forgotten.
  assert.equal(closed, true)
  assert.equal(calls, 2)
  assert.equal(hub.status('pmmcp'), 'connected')

  // The replacement client is the one that serves calls now.
  await hub.call(ticketFor('pmmcp.recall', { query: 'after' }), { query: 'after' })
  assert.equal(second.calls.length, 1)
  assert.equal(first.calls.length, 0)
})

test('heartbeat pings on the configured interval', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] })

  const store = withStore(t)
  const mock = await mockMcp()
  let pings = 0
  ;(mock.client as unknown as Record<string, unknown>)['ping'] = () => {
    pings++
    return Promise.resolve({})
  }

  const hub = new McpHub({ store, views: VIEWS, pingIntervalMs: 1_000 })
  t.after(async () => {
    await hub.close()
    await mock.close().catch(() => undefined)
  })
  await hub.connect('pmmcp', () => Promise.resolve(mock.client))

  assert.equal(pings, 0)
  t.mock.timers.tick(1_000)
  assert.equal(pings, 1)
  t.mock.timers.tick(2_000)
  assert.equal(pings, 3)
})

test('connect failure yields degraded status and hub.degraded, not a throw', async (t) => {
  const store = withStore(t)
  const hub = new McpHub({ store, views: VIEWS })
  t.after(() => hub.close())

  // The kernel is specified to boot without pmmcp. A hub that threw here would
  // turn a missing optional dependency into a dead control plane.
  const status = await hub.connect('pmmcp', () => Promise.reject(new Error('ECONNREFUSED 127.0.0.1:8123')))

  assert.equal(status, 'degraded')
  assert.equal(hub.status('pmmcp'), 'absent')
  assert.match(String(payloads(store, 'hub.degraded')[0]?.['reason']), /ECONNREFUSED/)
  assert.equal(store.query({ type: 'hub.connected' }).length, 0)

  // Nothing is callable while degraded.
  await assert.rejects(
    () => hub.call(ticketFor('pmmcp.recall', {}), {}),
    (e: unknown) => e instanceof PolicyDenied && /not connected/.test(e.message),
  )
  assert.deepEqual(hub.agentView().tools, [])
})

test('splitRef splits at the first dot so a dotted tool name survives', () => {
  assert.deepEqual(splitRef('pmmcp.recall'), { serverId: 'pmmcp', tool: 'recall' })
  // `weird.name` is ONE tool on the pmmcp server, not a server called
  // pmmcp.weird. Splitting at the last dot would call the wrong thing.
  assert.deepEqual(splitRef('pmmcp.weird.name'), { serverId: 'pmmcp', tool: 'weird.name' })
  assert.equal(splitRef('nodots'), undefined)
  assert.equal(splitRef('.leading'), undefined)
  assert.equal(splitRef('trailing.'), undefined)
})
