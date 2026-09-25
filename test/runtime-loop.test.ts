// T27a — the run loop.
//
// The loop is where every invariant built so far has to hold at the same
// time, so the tests are mostly about ORDER and about the branches that do
// not execute.
//
// The falsifiers:
//
//   Execute before the gate and invariant 3 is gone — no amount of logging
//   afterwards puts it back.
//   Drop a denied call instead of answering it and the model loops on a tool
//   it will never be allowed to use, burning the budget it was given for
//   something else.
//   Freeze taint at run start and a taints:true tool and a released
//   quarantine hold both become silently ineffective (D17).
//   Give the model the full tool output while the log keeps the bounded one
//   and an operator reading the log is reading something the model never saw
//   (D18).
//   Let an approval that arrives after the wallclock elapsed still execute
//   and the cap the operator set was never the cap that applied (D19).
//   Offer a delegation tool and a child run exists with no lane, no budget
//   and no line in the log tying its spend to its parent.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { parse as parseYaml } from 'yaml'

import { withStore } from './helpers/store.js'
import { freshProbe } from './helpers/probe.js'
import { mockMcp, type MockMcp } from './helpers/mock-mcp.js'
import { fakeProvider, http, FAKE_PRICING, type ScriptedResponse } from './helpers/fake-provider.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews, type ToolViewsFile } from '../src/mcp/tool-views.js'
import { OpenAiChatAdapter } from '../src/models/openai-chat.js'
import { Router } from '../src/models/router.js'
import type { ModelCard } from '../src/models/registry.js'
import { Approvals } from '../src/policy/approvals.js'
import { PolicyEngine } from '../src/policy/engine.js'
import { Quarantine } from '../src/policy/quarantine.js'
import { mintHumanActor } from '../src/control/actor.js'
import { Budget } from '../src/runtime/budget.js'
import { Lanes } from '../src/runtime/lanes.js'
import { RunLoop, type RunAgent, type ToolContext } from '../src/runtime/loop.js'
import { assertDelegationAvailable } from '../src/runtime/delegate.js'
import { assertEgressEnforced } from '../src/runtime/egress.js'
import { Scheduler } from '../src/runtime/scheduler.js'
import { NotImplementedError } from '../src/errors.js'
import { MAX_LOGGED_OUTPUT, PAYLOAD_TEXT_BUDGET } from '../src/events/bound.js'

const REF = 'anthropic/claude-sonnet-5'
const KEY = 'Yt7bN3mQ9wE5rT1uI6oP2aS8dF4gH0jK'

const PRICES = {
  inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
  outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
  cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
  cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
  source: 'table',
} as const

const CARD: ModelCard = {
  dialect: 'openai-chat',
  baseUrl: 'https://model.test',
  path: '/v1/chat/completions',
  auth: { header: 'Authorization', scheme: 'Bearer', vaultId: 'k' },
  model: 'test-model',
  local: false,
  placeholder: false,
  pricing: { ...PRICES },
  limits: { contextTokens: 100_000, maxOutputTokens: 4_096 },
  caps: {
    toolChoice: 'auto',
    parallelToolCalls: null,
    strictSchema: null,
    sampling: 'none',
    streamUsage: null,
    preserveAssistantMessage: false,
  },
  orchestrator: false,
}

type ViewSpec = Record<string, { exposure: string; risk?: string; taints?: boolean; quarantine?: boolean }>

function views(tools: ViewSpec): ToolViewsFile {
  return parseToolViews({ version: 1, servers: { pmmcp: { default: 'kernel-only', tools } } })
}

/** One Chat Completions turn. 1_000 in + 100 out = 4_500 micro-USD exactly. */
function turn(message: unknown, finish = 'tool_calls'): ScriptedResponse {
  return http(200, {
    id: 'chatcmpl-loop',
    object: 'chat.completion',
    created: 1_758_000_000,
    model: 'test-model',
    choices: [{ index: 0, message, finish_reason: finish }],
    usage: { prompt_tokens: 1_000, completion_tokens: 100, total_tokens: 1_100 },
  })
}

const COST_PER_TURN = 4_500

function toolCall(ref: string, args: unknown, id = 'call_1'): unknown {
  return {
    role: 'assistant',
    content: null,
    tool_calls: [
      {
        id,
        type: 'function',
        function: { name: ref.replace(/\./g, '__'), arguments: JSON.stringify(args) },
      },
    ],
  }
}

const done = (text = 'all finished'): ScriptedResponse =>
  turn({ role: 'assistant', content: text }, 'stop')

interface Wired {
  readonly loop: RunLoop
  readonly store: ReturnType<typeof withStore>
  readonly mock: MockMcp
  readonly quarantine: Quarantine
  readonly approvals: Approvals
  readonly budget: Budget
  readonly agent: RunAgent
  readonly provider: ReturnType<typeof fakeProvider>
  advance(ms: number): void
}

async function wire(
  t: TestContext,
  options: {
    script: readonly ScriptedResponse[]
    views: ToolViewsFile
    toolAllow?: readonly string[]
    caps?: Partial<{ usdMax: number; maxLlmCalls: number; maxToolCalls: number; wallclockMs: number }>
    approvalWaitMs?: number
    fetch?: typeof globalThis.fetch
  },
): Promise<Wired> {
  const store = withStore(t)
  const mock = await mockMcp()
  const hub = new McpHub({ store, views: options.views })
  t.after(async () => {
    await hub.close()
    await mock.close().catch(() => undefined)
  })
  await hub.connect('pmmcp', () => Promise.resolve(mock.client))

  const provider = fakeProvider(options.script)
  const router = new Router({
    store,
    cards: new Map([[REF, CARD]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve(KEY),
    maxRetries: 0,
    adapters: { 'openai-chat': new OpenAiChatAdapter() },
    fetch: options.fetch ?? provider.fetch,
  })

  const approvals = new Approvals({ waitMs: options.approvalWaitMs ?? 300_000 })
  const engine = new PolicyEngine({ store, approvals })
  const quarantine = new Quarantine({ store })

  let clock = 5_000_000
  const budget = new Budget(
    { usdMax: 1_000_000, maxLlmCalls: 20, maxToolCalls: 20, wallclockMs: 600_000, ...options.caps },
    { now: () => clock },
  )

  const agent: RunAgent = {
    agentId: 'researcher',
    tier: 1,
    lane: 'main',
    model: { primary: REF, fallbacks: [] },
    toolAllow: options.toolAllow ?? ['pmmcp.recall'],
    system: 'you are a test agent',
  }

  const loop = new RunLoop({
    store,
    lanes: new Lanes({ main: 4, subagent: 8 }),
    router,
    engine,
    quarantine,
    views: options.views,
    agentView: () => hub.agentView(),
    budgetFor: () => budget,
  })

  return {
    loop,
    store,
    mock,
    quarantine,
    approvals,
    budget,
    agent,
    provider,
    advance(ms) {
      clock += ms
    },
  }
}

/** Event types from run.queued onward — the hub's boot events precede it. */
const types = (w: Wired): string[] => {
  const all = w.store.query().map((r) => r.type)
  const at = all.indexOf('run.queued')
  return at === -1 ? all : all.slice(at)
}
const payload = (w: Wired, type: string, n = 0): Record<string, unknown> =>
  JSON.parse(w.store.query({ type })[n]?.payload ?? '{}') as Record<string, unknown>

/** Approve or deny every approval the moment it is requested. */
function autoAnswer(w: Wired, decision: 'approved' | 'denied'): void {
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      try {
        w.approvals.resolve(id, mintHumanActor('conn-test'), decision)
      } catch {
        // Already settled: the run moved on without us.
      }
    })
  })
}

// ── the happy path ─────────────────────────────────────────────────────────

test('happy path event sequence run.started, llm.request, llm.response, tool.gate, tool.call, tool.result, llm.request, llm.response, run.finished with non-zero exact cost', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'find something' })

  assert.deepEqual(types(w), [
    'run.queued',
    'run.started',
    'llm.request',
    'llm.response',
    'tool.gate',
    'tool.call',
    'tool.result',
    'llm.request',
    'llm.response',
    'run.finished',
  ])

  assert.equal(out.status, 'ok')
  // Two turns at 1_000 in * 3 + 100 out * 15 USD/MTok = 4_500 micro-USD each.
  assert.equal(out.costMicroUsd, COST_PER_TURN * 2)
  assert.equal(out.llmCalls, 2)
  assert.equal(out.toolCalls, 1)
  assert.equal(out.finalText, 'all finished')
  assert.equal(payload(w, 'run.finished')['costMicroUsd'], COST_PER_TURN * 2)
  assert.equal(w.mock.calls.length, 1)
})

test('every tool call emits tool.gate before tool.call before tool.result', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    script: [
      turn(toolCall('pmmcp.recall', { query: 'a' }, 'c1')),
      turn(toolCall('pmmcp.recall', { query: 'b' }, 'c2')),
      done(),
    ],
  })

  await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'twice' })

  const order = types(w).filter((x) => x.startsWith('tool.'))
  // Nothing executes before the gate. Two calls, two complete triples, never
  // interleaved and never a call without its ruling in front of it.
  assert.deepEqual(order, [
    'tool.gate',
    'tool.call',
    'tool.result',
    'tool.gate',
    'tool.call',
    'tool.result',
  ])
})

test('every event in the run carries the run’s runId', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })

  await w.loop.start({ runId: 'run_42', agent: w.agent, prompt: 'go' })

  // Everything from run.queued onward. The hub's boot events are the kernel's
  // own and carry no run.
  const rows = w.store.query()
  const at = rows.findIndex((r) => r.type === 'run.queued')
  assert.ok(at >= 0)
  for (const row of rows.slice(at)) {
    assert.equal(row.runId, 'run_42', `${row.type} lost its runId`)
  }
})

// ── the branches that do not execute ───────────────────────────────────────

test('a denied call never reaches the executor (mock records zero calls)', async (t) => {
  const w = await wire(t, {
    // Exposed to agents, but this manifest does not list it. Default deny is
    // structural here: the offered list is the hub's agent view INTERSECTED
    // with the manifest, so an unlisted tool is never offered, and a model
    // that names one anyway is answered without anything being gated or run.
    // The gate's own manifest rule stays as defence in depth behind that.
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    toolAllow: [],
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  assert.equal(w.mock.calls.length, 0)
  assert.deepEqual(types(w).filter((x) => x.startsWith('tool.')), [])
  assert.equal((w.provider.requests[0]?.body as { tools?: unknown[] }).tools, undefined)
  assert.equal(out.status, 'ok')

  // The model is TOLD. A call that vanished would leave it retrying a tool it
  // can never use, burning a budget meant for something else.
  const second = w.provider.requests[1]?.body as { messages: { role: string; content: string }[] }
  const toolMessage = second.messages.find((m) => m.role === 'tool')
  assert.ok(toolMessage !== undefined, 'the model received no answer for its call')
  assert.match(toolMessage.content, /^\[error\] .*not offered/)
})

test('a tool call whose args resolve under souls/ is denied protected-path before any executor call', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    // A path, not prose. PROTECTED_PATH requires `souls` at a path boundary,
    // so a sentence that merely mentions souls is not a denial — the rule is
    // about arguments that ARE paths.
    script: [turn(toolCall('pmmcp.recall', { query: 'souls/ceo.md' })), done()],
  })

  await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  // Invariant 8. No human approval makes this safe, so it is a deny and not
  // a park, and nothing runs.
  assert.equal(w.mock.calls.length, 0)
  assert.equal(payload(w, 'tool.gate')['decision'], 'deny')
  assert.match(String(payload(w, 'tool.gate')['reason']), /protected-path/)
  assert.equal(w.store.query({ type: 'approval.requested' }).length, 0)

  // A denied call is ANSWERED, not dropped. Silence would leave the model
  // retrying a tool it can never use, burning a budget meant for something
  // else — and the denial would be invisible in the conversation.
  const second = w.provider.requests[1]?.body as { messages: { role: string; content: string }[] }
  const answer = second.messages.find((m) => m.role === 'tool')
  assert.ok(answer !== undefined, 'the model received no answer for its denied call')
  assert.match(answer.content, /^\[denied\] .*protected-path/)
})

// ── approvals ──────────────────────────────────────────────────────────────

test('irreversible tool parks the run until a human approves, then executes', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'irreversible' } }),
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })
  autoAnswer(w, 'approved')

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  assert.deepEqual(types(w), [
    'run.queued',
    'run.started',
    'llm.request',
    'llm.response',
    'run.parked',
    'tool.gate',
    'approval.requested',
    'approval.resolved',
    'run.resumed',
    'tool.call',
    'tool.result',
    'llm.request',
    'llm.response',
    'run.finished',
  ])
  assert.equal(payload(w, 'run.parked')['reason'], 'approval')
  assert.equal(payload(w, 'approval.resolved')['decision'], 'approved')
  assert.equal(w.mock.calls.length, 1)
  assert.equal(out.status, 'ok')
})

test('approval timeout denies and the run continues', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'irreversible' } }),
    // Nobody answers.
    approvalWaitMs: 5,
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  // Fail closed: an unanswered request is a denial, not a permission.
  assert.equal(payload(w, 'approval.resolved')['decision'], 'expired')
  assert.equal(w.mock.calls.length, 0)
  assert.deepEqual(types(w).filter((x) => x === 'run.resumed'), ['run.resumed'])
  // And the run carries on rather than dying: one refused tool is not a
  // failed run.
  assert.equal(out.status, 'ok')
  assert.equal(out.llmCalls, 2)
})

test('an approval arriving after wallclock expiry is refused with conflict', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'irreversible' } }),
    caps: { wallclockMs: 1_000 },
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })
  // The human says yes, but only after the run's own clock has run out. D19:
  // the wallclock does not pause while parked, so this approval buys nothing.
  w.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const id = (JSON.parse(row.payload) as { approvalId: string }).approvalId
    queueMicrotask(() => {
      w.advance(5_000)
      try {
        w.approvals.resolve(id, mintHumanActor('conn-late'), 'approved')
      } catch {
        // Already settled.
      }
    })
  })

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  assert.equal(payload(w, 'approval.resolved')['decision'], 'approved')
  // Approved, and still did not run.
  assert.equal(w.mock.calls.length, 0)
  assert.equal(out.status, 'killed')
  assert.equal(out.reason, 'wallclock')
  assert.equal(payload(w, 'run.finished')['reason'], 'wallclock')
})

// ── taint ──────────────────────────────────────────────────────────────────

test('tainted run’s write tool is parked (through the loop)', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'write' } }),
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })
  autoAnswer(w, 'denied')

  // A run that started tainted — a Telegram ingress run, say.
  await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go', taint: 'tainted' })

  assert.equal(payload(w, 'run.started')['taint'], 'tainted')
  assert.equal(payload(w, 'tool.gate')['decision'], 'needs-human')
  assert.match(String(payload(w, 'tool.gate')['reason']), /tainted/)
  assert.equal(w.mock.calls.length, 0)
})

test('a taints:true tool taints the run so the next write needs a human', async (t) => {
  const w = await wire(t, {
    views: views({
      recall: { exposure: 'agent', risk: 'read', taints: true },
      'weird.name': { exposure: 'agent', risk: 'write' },
    }),
    toolAllow: ['pmmcp.recall', 'pmmcp.weird.name'],
    script: [
      turn(toolCall('pmmcp.recall', { query: 'untrusted' }, 'c1')),
      turn(toolCall('pmmcp.weird.name', { body: 'write it down' }, 'c2')),
      done(),
    ],
  })
  autoAnswer(w, 'denied')

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  const gates = w.store.query({ type: 'tool.gate' }).map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.equal(gates[0]?.['decision'], 'allow')
  // Taint is re-derived each turn. Freezing it at run start would make a
  // taints:true tool silently ineffective.
  assert.equal(gates[1]?.['decision'], 'needs-human')
  assert.match(String(gates[1]?.['reason']), /tainted/)
  assert.equal(out.taint, 'tainted')
  assert.equal(w.mock.calls.length, 1, 'only the first tool ran')
})

test('a released quarantined output taints the run so the next write needs a human', async (t) => {
  const provider = fakeProvider([
    turn(toolCall('pmmcp.recall', { query: 'untrusted page' }, 'c1')),
    turn(toolCall('pmmcp.weird.name', { body: 'act on it' }, 'c2')),
    done(),
  ])

  let released = false
  const w = await wire(t, {
    views: views({
      recall: { exposure: 'agent', risk: 'read', quarantine: true },
      'weird.name': { exposure: 'agent', risk: 'write' },
    }),
    toolAllow: ['pmmcp.recall', 'pmmcp.weird.name'],
    script: [],
    // The human releases the hold BETWEEN turns, which is when a release
    // really happens: the loop is waiting on the provider.
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      if (released) return provider.fetch(input, init)
      const pending = wRef?.quarantine.pending() ?? []
      if (pending.length > 0) {
        released = true
        wRef?.quarantine.release(pending[0]!.holdId, mintHumanActor('conn-release'))
      }
      return provider.fetch(input, init)
    }) as typeof globalThis.fetch,
  })
  const wRef: Wired | undefined = w
  autoAnswer(w, 'denied')

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  // D17 end to end: executed, held, placeholder to the model; the release is
  // what makes the run tainted, and from then on a write needs a human.
  assert.equal(w.store.query({ type: 'quarantine.held' }).length, 1)
  assert.equal(w.store.query({ type: 'quarantine.released' }).length, 1)

  const firstBody = provider.requests[1]?.body as { messages: { role: string; content: string }[] }
  const placeholder = firstBody.messages.find((m) => m.role === 'tool')
  assert.match(String(placeholder?.content), /^\[quarantined\] pmmcp\.recall ran/)
  assert.equal(String(placeholder?.content).includes('recalled'), false, 'the held output leaked')

  const gates = w.store.query({ type: 'tool.gate' }).map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.equal(gates[1]?.['decision'], 'needs-human')
  assert.equal(out.taint, 'tainted')
})

// ── budgets, bounds, and the absent tools ──────────────────────────────────

test('budget caps stop the run through the loop with the T27b reason codes', async (t) => {
  const llm = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    caps: { maxLlmCalls: 1 },
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })
  const a = await llm.loop.start({ runId: 'run_1', agent: llm.agent, prompt: 'go' })
  assert.equal(a.status, 'killed')
  assert.equal(a.reason, 'maxLlmCalls')
  assert.equal(payload(llm, 'run.finished')['reason'], 'maxLlmCalls')

  const tools = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    caps: { maxToolCalls: 1 },
    script: [
      turn(toolCall('pmmcp.recall', { query: 'a' }, 'c1')),
      turn(toolCall('pmmcp.recall', { query: 'b' }, 'c2')),
      done(),
    ],
  })
  const b = await tools.loop.start({ runId: 'run_2', agent: tools.agent, prompt: 'go' })
  assert.equal(b.reason, 'maxToolCalls')

  const money = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    caps: { usdMax: COST_PER_TURN },
    script: [turn(toolCall('pmmcp.recall', { query: 'x' })), done()],
  })
  const c = await money.loop.start({ runId: 'run_3', agent: money.agent, prompt: 'go' })
  assert.equal(c.reason, 'usdMax')
})

test('tool output larger than MAX_LOGGED_OUTPUT is bounded identically for the log and the model', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    script: [turn(toolCall('pmmcp.recall', { query: 'x'.repeat(MAX_LOGGED_OUTPUT) })), done()],
  })

  const out = await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })
  // The run SURVIVES a huge output. Bounding the text to the store's full
  // limit would push the payload envelope over it and kill the run instead.
  assert.equal(out.status, 'ok')

  const logged = payload(w, 'tool.result')
  const body = w.provider.requests[1]?.body as { messages: { role: string; content: string }[] }
  const toModel = body.messages.find((m) => m.role === 'tool')?.content

  // D18, one truth. Two would mean an operator reading the log is reading
  // something the model never saw, and a redaction bug would be invisible on
  // the side that matters.
  assert.equal(toModel, logged['text'])
  assert.equal(logged['truncated'], true)
  assert.equal(typeof logged['sha256'], 'string')
  assert.ok(Buffer.byteLength(String(toModel), 'utf8') <= PAYLOAD_TEXT_BUDGET)
})

test('the model’s tool list never contains a delegation or spawn tool and assertDelegationAvailable throws NotImplemented', async (t) => {
  const w = await wire(t, {
    views: views({
      recall: { exposure: 'agent', risk: 'read' },
      'weird.name': { exposure: 'agent', risk: 'write' },
    }),
    toolAllow: ['pmmcp.recall', 'pmmcp.weird.name'],
    script: [done()],
  })

  await w.loop.start({ runId: 'run_1', agent: w.agent, prompt: 'go' })

  const body = w.provider.requests[0]?.body as { tools?: { function: { name: string } }[] }
  const offered = (body.tools ?? []).map((x) => x.function.name)
  assert.deepEqual(offered.sort(), ['pmmcp__recall', 'pmmcp__weird__name'])
  for (const name of offered) {
    assert.equal(/deleg|spawn|subagent|child|task/i.test(name), false, name)
  }

  // A tool that looked like delegation and quietly did something simpler
  // would be worse than none. All three Phase 0 stubs throw rather than
  // returning a plausible answer.
  assert.throws(() => assertDelegationAvailable(), NotImplementedError)
  assert.throws(() => assertEgressEnforced(), NotImplementedError)
  assert.throws(() => new Scheduler().start(), NotImplementedError)
})

test('ToolContext keys are exactly [agentId, args, runId, toolRef]', () => {
  // The gate never sees anything a model could set. An extra field here is
  // how a `modelDecision` or an `allow` reaches a future branch.
  const context: ToolContext = {
    runId: 'run_1',
    agentId: 'researcher',
    toolRef: 'pmmcp.recall',
    args: { query: 'x' },
  }
  assert.deepEqual(Object.keys(context).sort(), ['agentId', 'args', 'runId', 'toolRef'])
})

test('run.start on a degraded router finishes with reason router-degraded rather than hanging', async (t) => {
  const w = await wire(t, {
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    script: [done()],
  })

  // No probe for this ref: the router refuses to route to it (D28). The run
  // must end with a reason rather than wait for something that will never
  // happen.
  const stranded = new RunLoop({
    store: w.store,
    lanes: new Lanes({ main: 4, subagent: 8 }),
    router: new Router({
      store: w.store,
      cards: new Map([[REF, CARD]]),
      probes: () => undefined,
      resolveCredential: () => Promise.resolve(KEY),
      maxRetries: 0,
      adapters: { 'openai-chat': new OpenAiChatAdapter() },
      fetch: w.provider.fetch,
    }),
    engine: new PolicyEngine({ store: w.store, approvals: w.approvals }),
    quarantine: w.quarantine,
    views: views({ recall: { exposure: 'agent', risk: 'read' } }),
    agentView: () => ({ tools: [], call: () => Promise.reject(new Error('unused')) }),
    budgetFor: () => new Budget({ usdMax: 1_000, maxLlmCalls: 2, maxToolCalls: 2, wallclockMs: 1_000 }),
  })

  const out = await stranded.start({ runId: 'run_9', agent: w.agent, prompt: 'go' })
  assert.equal(out.status, 'error')
  assert.match(String(out.reason), /toolCalling|router refused/)
  assert.equal(w.store.query({ type: 'run.finished' }).length, 1)
})
