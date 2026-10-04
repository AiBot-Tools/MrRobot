// Memory is per agent: the gate pins a namespaced tool to the caller's own
// namespace.
//
// pmmcp namespaces memory by project_id, and the MODEL chooses that argument.
// Before this rule nothing in the hub, the gate or the loop looked at it, so the
// first `recall` exposed to an agent would have read `aos/ceo` — or any other
// agent's memory — on request, and the per-agent namespaces in every manifest would
// have existed on paper only. Found by grepping for the check before recommending
// the exposure, not by a test; these are the tests.
//
// Three layers, each tested:
//
//   the pure gate denies a namespace argument that is not the agent's own, and an
//   absent one, before any approval could be asked for;
//   tool-views.yaml refuses to expose a pmmcp tool that makes no namespace decision
//   at all, so the one-line exposure that would have opened this is a parse error;
//   through the real run loop, against the pmmcp double, the researcher asking for
//   `aos/ceo` never reaches the server, and asking for its own namespace does.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test from 'node:test'
import { parse as parseYaml } from 'yaml'

import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { OpenAiChatAdapter } from '../src/models/openai-chat.js'
import type { ModelCard } from '../src/models/registry.js'
import { Router } from '../src/models/router.js'
import { Approvals } from '../src/policy/approvals.js'
import { PolicyEngine } from '../src/policy/engine.js'
import { decide, type GateInput } from '../src/policy/gate.js'
import { Quarantine } from '../src/policy/quarantine.js'
import { Budget } from '../src/runtime/budget.js'
import { Lanes } from '../src/runtime/lanes.js'
import { RunLoop, type RunAgent } from '../src/runtime/loop.js'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { writeProbeRecord } from '../src/models/probe.js'
import {
  anthropicEndTurn,
  anthropicToolUse,
  FAKE_PRICING,
  fakeProvider,
  http,
  type ScriptedResponse,
} from './helpers/fake-provider.js'
import { bootOn, fixture, REPO_ROOT, rows, runThroughControl } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const OWN = 'aos/agent/researcher'

function gate(args: Record<string, unknown>, extra: Partial<GateInput> = {}): ReturnType<typeof decide> {
  return decide({
    view: { exposure: 'agent', risk: 'read', taints: false, quarantine: false, namespaceArg: 'project_id' },
    scope: { runId: 'run-1', agentId: 'researcher', taint: 'clean', projectId: OWN },
    manifestAllows: true,
    toolRef: 'pmmcp.recall',
    args,
    ...extra,
  })
}

// ── the pure gate ──────────────────────────────────────────────────────────

test('the gate allows a namespaced tool addressed to the agent’s own namespace', () => {
  assert.equal(gate({ project_id: OWN, query: 'x' }).decision, 'allow')
})

test('the gate denies another agent’s namespace, and the CEO’s above all', () => {
  for (const other of ['aos/ceo', 'aos/agent/writer', 'aos/shared']) {
    const verdict = gate({ project_id: other, query: 'x' })
    assert.equal(verdict.decision, 'deny', `${other} was not denied`)
    assert.match(verdict.reason, new RegExp(`may only address ${OWN}`))
    assert.match(verdict.reason, new RegExp(other.replace('/', '\\/')))
  }
})

test('the gate denies an absent namespace argument rather than letting the server default it', () => {
  // A tool that defaults to some namespace server-side would otherwise be a way
  // round the pin: omit the argument and let pmmcp pick.
  const verdict = gate({ query: 'x' })
  assert.equal(verdict.decision, 'deny')
  assert.match(verdict.reason, /an unnamed namespace/)
  // Non-string values are refused the same way, not coerced.
  assert.equal(gate({ project_id: ['aos/agent/researcher'] }).decision, 'deny')
})

test('an agent with no memory namespace may not call a namespaced tool at all', () => {
  const verdict = gate(
    { project_id: OWN },
    { scope: { runId: 'run-1', agentId: 'nobody', taint: 'clean' } },
  )
  assert.equal(verdict.decision, 'deny')
  assert.match(verdict.reason, /has none/)
})

test('a wrong namespace is a DENY even on a tool that would otherwise need a human', () => {
  // Rule order matters: widening an agent's memory is a manifest change, not a
  // per-call approval, so this must never become a card a tired operator clicks.
  const verdict = gate(
    { project_id: 'aos/ceo' },
    { view: { exposure: 'agent', risk: 'irreversible', taints: false, quarantine: false, namespaceArg: 'project_id' } },
  )
  assert.equal(verdict.decision, 'deny')
})

test('`namespaceArg: none` pins nothing, and a tool with no namespaceArg is untouched', () => {
  const none = decide({
    view: { exposure: 'agent', risk: 'read', taints: false, quarantine: false, namespaceArg: 'none' },
    scope: { runId: 'run-1', agentId: 'researcher', taint: 'clean', projectId: OWN },
    manifestAllows: true,
    toolRef: 'pmmcp.ping',
    args: {},
  })
  assert.equal(none.decision, 'allow')
})

// ── the policy file ────────────────────────────────────────────────────────

const exposing = (extra: string): string => `
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall:
        exposure: agent
        risk: read
${extra}`

test('tool-views refuses an exposed pmmcp tool that makes no namespace decision', () => {
  // The one-line exposure that would have opened every namespace is now a parse
  // error naming the fix.
  assert.throws(
    () => parseToolViews(parseYaml(exposing(''))),
    /pmmcp\.recall is exposed to agents but declares no namespaceArg/,
  )
  // Either decision, written out, parses.
  const pinned = parseToolViews(parseYaml(exposing('        namespaceArg: project_id\n')))
  assert.equal(pinned.servers['pmmcp']?.tools['recall']?.namespaceArg, 'project_id')
  const none = parseToolViews(parseYaml(exposing('        namespaceArg: none\n')))
  assert.equal(none.servers['pmmcp']?.tools['recall']?.namespaceArg, 'none')
})

test('a kernel-only pmmcp tool needs no namespace decision, and other servers are not affected', () => {
  // The kernel addresses namespaces itself (the goal writer, the broker), so the
  // rule is about what AGENTS can reach and nothing else.
  parseToolViews(
    parseYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall: { exposure: kernel-only, risk: read }
  github:
    default: kernel-only
    tools:
      search_code: { exposure: agent, risk: read }
`),
  )
})

// ── through the real run loop, against the pmmcp double ────────────────────

const REF = 'anthropic/claude-sonnet-5'
const CARD: ModelCard = {
  dialect: 'openai-chat',
  baseUrl: 'https://model.test',
  path: '/v1/chat/completions',
  auth: { header: 'Authorization', scheme: 'Bearer', vaultId: 'k' },
  model: 'test-model',
  local: false,
  placeholder: false,
  pricing: {
    inMicroUsdPerMTok: FAKE_PRICING.inMicroUsdPerMTok,
    outMicroUsdPerMTok: FAKE_PRICING.outMicroUsdPerMTok,
    cacheWrite5mMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
    cacheWrite1hMicroUsdPerMTok: FAKE_PRICING.cacheWriteMicroUsdPerMTok,
    cacheReadMicroUsdPerMTok: FAKE_PRICING.cacheReadMicroUsdPerMTok,
    source: 'table',
  },
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

function turn(message: unknown, finish = 'tool_calls'): ScriptedResponse {
  return http(200, {
    id: 'chatcmpl-ns',
    object: 'chat.completion',
    created: 1_758_000_000,
    model: 'test-model',
    choices: [{ index: 0, message, finish_reason: finish }],
    usage: { prompt_tokens: 1_000, completion_tokens: 100, total_tokens: 1_100 },
  })
}

function recall(projectId: string, id: string): ScriptedResponse {
  return turn({
    role: 'assistant',
    content: null,
    tool_calls: [
      {
        id,
        type: 'function',
        function: { name: 'pmmcp__recall', arguments: JSON.stringify({ project_id: projectId, query: 'plan' }) },
      },
    ],
  })
}

test('through the loop: the researcher asking for aos/ceo never reaches pmmcp; its own namespace does', async (t) => {
  // The researcher is exactly the agent whose manifest names `recall` as its
  // first entry. The CEO's namespace holds something it must never read.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const views = parseToolViews(
    parseYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall: { exposure: agent, risk: read, namespaceArg: project_id }
`),
  )
  const hub = new McpHub({ store, views })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)

  // Seed through the server, so the memories are where a real recall would find them.
  const seedClient = await mock.connect()
  await seedClient.callTool({
    name: 'remember',
    arguments: { project_id: 'aos/ceo', content: 'CEO-ONLY: the operator’s acquisition plan' },
  })
  await seedClient.callTool({
    name: 'remember',
    arguments: { project_id: OWN, content: 'researcher note: the plan for sqlite comparisons' },
  })
  const recallsBefore = mock.calls.filter((c) => c.tool === 'recall').length

  const provider = fakeProvider([
    recall('aos/ceo', 'call_1'),
    recall(OWN, 'call_2'),
    turn({ role: 'assistant', content: 'done' }, 'stop'),
  ])
  const router = new Router({
    store,
    cards: new Map([[REF, CARD]]),
    probes: freshProbe,
    resolveCredential: () => Promise.resolve('Yt7bN3mQ9wE5rT1uI6oP2aS8dF4gH0jK'),
    maxRetries: 0,
    adapters: { 'openai-chat': new OpenAiChatAdapter() },
    fetch: provider.fetch,
  })
  const approvals = new Approvals({ waitMs: 300_000 })
  t.after(() => {
    approvals.close()
  })
  const agent: RunAgent = {
    agentId: 'researcher',
    tier: 1,
    lane: 'main',
    model: { primary: REF, fallbacks: [] },
    toolAllow: ['pmmcp.recall'],
    system: 'test researcher',
    projectId: OWN,
  }
  const loop = new RunLoop({
    store,
    lanes: new Lanes({ main: 4, subagent: 8 }),
    router,
    engine: new PolicyEngine({ store, approvals }),
    quarantine: new Quarantine({ store }),
    views,
    agentView: () => hub.agentView(),
    budgetFor: () =>
      new Budget({ usdMax: 1_000_000, maxLlmCalls: 10, maxToolCalls: 10, wallclockMs: 600_000 }),
  })

  const outcome = await loop.start({ runId: 'run_ns', agent, prompt: 'recall the plan' })
  assert.equal(outcome.status, 'ok', String(outcome.reason))

  // Exactly one recall reached the server, and it was the researcher's own.
  const recalls = mock.calls.filter((c) => c.tool === 'recall').slice(recallsBefore)
  assert.equal(recalls.length, 1, `${String(recalls.length)} recalls reached pmmcp`)
  assert.equal(recalls[0]?.args['project_id'], OWN)

  // The denial is in the record, with the reason, before any execution.
  const gates = store
    .query({ type: 'tool.gate' })
    .map((r) => JSON.parse(r.payload) as { decision: string; reason: string })
  assert.equal(gates[0]?.decision, 'deny')
  assert.match(gates[0]?.reason ?? '', /may only address aos\/agent\/researcher, not aos\/ceo/)
  assert.equal(gates[1]?.decision, 'allow')

  // And the CEO's memory never entered the run: not in a tool result, not in a
  // prompt sent to the model.
  const everything = JSON.stringify(store.query())
  assert.equal(everything.includes('acquisition plan'), false, 'the CEO’s memory reached the researcher’s run')
  assert.equal(JSON.stringify(provider.requests).includes('acquisition plan'), false)
  assert.equal(everything.includes('sqlite comparisons'), true, 'the researcher’s own memory did not come back')
})

test('a real kernel pins each agent to ITS OWN manifest namespace, not one the loop was handed', async (t) => {
  // The loop-level test above builds its RunAgent by hand, so it cannot see the
  // one step that decides which namespace a real run is pinned to: the kernel
  // mapping each manifest's memory.projectId onto the run. Were that mapping to
  // hand every agent the CEO's namespace, the gate would faithfully pin the
  // researcher to aos/ceo — the exact read the pin exists to prevent — and every
  // gate-level test would still pass.
  //
  // Nothing in the shipped fleet can call a namespaced tool (tool-views.yaml
  // exposes nothing), so this boots the real kernel on a fixture whose views
  // expose recall with its namespace argument, and a researcher allowed to use it.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const shipped = parseYaml(readFileSync(join(REPO_ROOT, 'config', 'tool-views.yaml'), 'utf8')) as {
    servers: { pmmcp: { tools: Record<string, unknown> } }
  }
  shipped.servers.pmmcp.tools['recall'] = { exposure: 'agent', risk: 'read', namespaceArg: 'project_id' }
  const base = fixture(t)
  const fx = { ...base, toolViews: parseToolViews(shipped) }
  writeProbeRecord(fx.dataDir, freshProbe('anthropic/claude-sonnet-5'))

  const agentsDir = join(tmpdir(t), 'agents')
  for (const id of ['ceo', 'researcher', 'writer']) {
    mkdirSync(join(agentsDir, id, 'history'), { recursive: true })
    const yaml = readFileSync(join(REPO_ROOT, 'agents', id, 'agent.yaml'), 'utf8')
    writeFileSync(
      join(agentsDir, id, 'agent.yaml'),
      id === 'researcher' ? yaml.replace(/^  allow: \[\]$/m, '  allow: [pmmcp.recall]') : yaml,
    )
    writeFileSync(join(agentsDir, id, 'AGENTS.md'), `# ${id}\n`)
  }

  const provider = fakeProvider([
    anthropicToolUse({ name: 'pmmcp__recall', input: { project_id: OWN, query: 'plan' } }),
    anthropicToolUse({ name: 'pmmcp__recall', input: { project_id: 'aos/ceo', query: 'plan' } }),
    anthropicEndTurn({ text: 'done' }),
  ])
  const kernel = await bootOn(t, fx, {
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-namespace' },
    clientFactory: mock.connect,
    fetch: provider.fetch,
    agentsDir,
  })
  const finished = await runThroughControl(kernel, 'recall the plan', 'researcher')
  await kernel.shutdown()
  assert.equal(finished['status'], 'ok', JSON.stringify(finished))

  const decisions = rows(fx.dbPath)
    .filter((r) => r.type === 'tool.gate')
    .map((r) => JSON.parse(r.payload) as { decision: string; reason: string })
  assert.deepEqual(
    decisions.map((d) => d.decision),
    ['allow', 'deny'],
    `the researcher's own namespace must pass and the CEO's must not: ${JSON.stringify(decisions)}`,
  )
  assert.match(decisions[1]?.reason ?? '', /may only address aos\/agent\/researcher, not aos\/ceo/)
  // And what reached pmmcp was the researcher's namespace, once.
  const reached = mock.calls.filter((c) => c.tool === 'recall').map((c) => c.args['project_id'])
  assert.deepEqual(reached, [OWN])
})
