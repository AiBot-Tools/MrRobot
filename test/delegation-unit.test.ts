// The Delegation class against a fake launcher, for what an end-to-end run cannot
// easily produce: a tainted child, a failed child, a parent killed mid-wait, the
// children cap, depth, and tier. Each is a refusal or a propagation that must hold
// whatever the model does.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import test, { type TestContext } from 'node:test'
import { parse as parseYaml } from 'yaml'

import { AgentRegistry } from '../src/agents/registry.js'
import { parseKernelConfig } from '../src/config.js'
import { ConfigError } from '../src/errors.js'
import { GoalWriter } from '../src/goals/writer.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { parseProviders } from '../src/models/registry.js'
import { Budget } from '../src/runtime/budget.js'
import { Delegation, type LaunchInput } from '../src/runtime/delegate.js'
import type { KernelToolContext, KernelToolHandler } from '../src/runtime/kernel-tools.js'
import type { RunAgent, RunOutcome } from '../src/runtime/loop.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const PLAN = {
  objective: { title: 'o', successCriteria: ['c'] },
  milestones: [
    {
      id: 'm1',
      title: 'm',
      tasks: [
        { id: 't1', title: 'one', template: 'researcher', acceptance: ['a'], dependsOn: [] },
        { id: 't2', title: 'two', template: 'writer', acceptance: ['a'], dependsOn: [] },
        { id: 't3', title: 'three', template: 'researcher', acceptance: ['a'], dependsOn: [] },
      ],
    },
  ],
}

const read = (p: string): unknown => parseYaml(readFileSync(`${REPO_ROOT}/${p}`, 'utf8'))

interface Harness {
  readonly adopt: KernelToolHandler
  readonly delegate: KernelToolHandler
  readonly launched: LaunchInput[]
  readonly killed: string[]
  readonly ctx: (overrides?: Partial<KernelToolContext>) => KernelToolContext
  readonly delegation: Delegation
  readonly store: ReturnType<typeof withStore>
}

async function harness(
  t: TestContext,
  outcome: (input: LaunchInput, runId: string) => Promise<RunOutcome>,
): Promise<Harness> {
  const store = withStore(t)
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const views = parseToolViews(read('config/tool-views.yaml'))
  const hub = new McpHub({ store, views })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)
  const config = parseKernelConfig(read('config/kernel.yaml'), { repoRoot: REPO_ROOT })
  const agents = new AgentRegistry({
    providers: new Set(Object.keys(parseProviders(read('config/providers.yaml')).entries)),
    toolViews: views,
    store,
    budgets: config.budgets,
  })
  agents.load(`${REPO_ROOT}/agents`)

  const launched: LaunchInput[] = []
  const killed: string[] = []
  let n = 0
  const delegation = new Delegation({
    store,
    agents,
    writer: new GoalWriter({ store, hub, goals: config.goals }),
    launch: (input) => {
      launched.push(input)
      n += 1
      const runId = `run_child_${String(n)}`
      return { runId, outcome: outcome(input, runId) }
    },
    kill: (runId) => {
      killed.push(runId)
    },
  })
  const [adopt, delegate] = delegation.handlers()
  assert.ok(adopt && delegate)

  const ceo: RunAgent = {
    agentId: 'ceo',
    tier: 2,
    lane: 'main',
    model: { primary: 'anthropic/claude-sonnet-5', fallbacks: [] },
    toolAllow: ['kernel.adopt_plan', 'kernel.delegate'],
    system: '',
    projectId: 'aos/ceo',
    role: 'orchestrator',
  }
  const budget = new Budget({ usdMax: 1_000_000, maxLlmCalls: 50, maxToolCalls: 50, wallclockMs: 600_000 })
  budget.start()
  return {
    adopt,
    delegate,
    launched,
    killed,
    delegation,
    store,
    ctx: (overrides = {}) => ({ runId: 'run_parent', agent: ceo, budget, ...overrides }),
  }
}

const ok = (input: LaunchInput, runId: string, extra: Partial<RunOutcome> = {}): Promise<RunOutcome> =>
  Promise.resolve({
    runId,
    status: 'ok',
    costMicroUsd: 5_000,
    llmCalls: 1,
    toolCalls: 0,
    finalText: `done: ${input.agentId}`,
    taint: 'clean',
    ...extra,
  })

test('a tainted child taints the parent: untrusted material does not launder through an agent', async (t) => {
  const h = await harness(t, (input, runId) => ok(input, runId, { taint: 'tainted' }))
  await h.adopt.run({ plan: PLAN }, h.ctx())
  const result = await h.delegate.run({ taskId: 't1', brief: 'go' }, h.ctx())
  assert.equal(result.ok, true)
  assert.equal(result.taints, true)
})

test('a failed child is still charged to the parent, and the parent learns it failed', async (t) => {
  const h = await harness(t, (input, runId) => ok(input, runId, { status: 'error', reason: 'boom', costMicroUsd: 7_000 }))
  const ctx = h.ctx()
  await h.adopt.run({ plan: PLAN }, ctx)
  const before = ctx.budget.spend.costMicroUsd
  const result = await h.delegate.run({ taskId: 't1', brief: 'go' }, ctx)
  assert.equal(result.ok, false)
  assert.match(result.text, /"status":"error"/)
  assert.equal(ctx.budget.spend.costMicroUsd - before, 7_000, 'a failed child spent money the parent was not charged for')
})

test('a child runs under a ceiling carved from what the parent has left', async (t) => {
  const h = await harness(t, ok)
  const ctx = h.ctx()
  await h.adopt.run({ plan: PLAN }, ctx)
  ctx.budget.charge('cost', 400_000)
  await h.delegate.run({ taskId: 't1', brief: 'go' }, ctx)
  assert.equal(h.launched[0]?.ceiling.usdMax, 600_000)
  assert.ok((h.launched[0]?.ceiling.wallclockMs ?? Infinity) <= 600_000)
})

test('a parent with nothing left may not delegate', async (t) => {
  const h = await harness(t, ok)
  const ctx = h.ctx()
  await h.adopt.run({ plan: PLAN }, ctx)
  ctx.budget.charge('cost', 1_000_000)
  const result = await h.delegate.run({ taskId: 't1', brief: 'go' }, ctx)
  assert.equal(result.ok, false)
  assert.match(result.text, /no budget left/)
  assert.equal(h.launched.length, 0)
})

test('killing the parent kills the child it is waiting on', async (t) => {
  let release: (o: RunOutcome) => void = () => undefined
  const h = await harness(t, (_input, runId) => {
    return new Promise<RunOutcome>((resolve) => {
      release = (o) => resolve(o)
      void runId
    })
  })
  const controller = new AbortController()
  const ctx = h.ctx({ signal: controller.signal })
  await h.adopt.run({ plan: PLAN }, ctx)
  const pending = h.delegate.run({ taskId: 't1', brief: 'go' }, ctx)
  await Promise.resolve()
  controller.abort()
  assert.deepEqual(h.killed, ['run_child_1'], 'the child outlived the parent that was paying for it')
  release({ runId: 'run_child_1', status: 'killed', costMicroUsd: 100, llmCalls: 0, toolCalls: 0, finalText: '', taint: 'clean' })
  const result = await pending
  assert.match(result.text, /"status":"killed"/)
})

test('the children cap is the manifest’s spawn.maxChildren', async (t) => {
  // The CEO manifest says 4. A five-task plan can adopt, but the fifth delegation
  // is refused.
  const h = await harness(t, ok)
  const five = {
    ...PLAN,
    milestones: [
      {
        id: 'm1',
        title: 'm',
        tasks: [1, 2, 3, 4, 5].map((i) => ({
          id: `t${String(i)}`,
          title: `task ${String(i)}`,
          template: 'researcher',
          acceptance: ['a'],
          dependsOn: [],
        })),
      },
    ],
  }
  const ctx = h.ctx()
  await h.adopt.run({ plan: five }, ctx)
  for (const i of [1, 2, 3, 4]) {
    assert.equal((await h.delegate.run({ taskId: `t${String(i)}`, brief: 'go' }, ctx)).ok, true)
  }
  const fifth = await h.delegate.run({ taskId: 't5', brief: 'go' }, ctx)
  assert.equal(fifth.ok, false)
  assert.match(fifth.text, /at most 4 children/)
  assert.equal(h.launched.length, 4)
})

test('a delegated child may not delegate, whatever its manifest says: depth is 1', async (t) => {
  const h = await harness(t, ok)
  const ctx = h.ctx()
  await h.adopt.run({ plan: PLAN }, ctx)
  await h.delegate.run({ taskId: 't1', brief: 'go' }, ctx)
  // The child's run id, trying to delegate as if it were an orchestrator.
  const asChild = h.ctx({ runId: 'run_child_1' })
  const result = await h.delegate.run({ taskId: 't2', brief: 'go' }, asChild)
  assert.equal(result.ok, false)
  assert.match(result.text, /depth is capped at 1/)
})

test('a target above the caller’s tier is refused: limits only narrow', async (t) => {
  const h = await harness(t, ok)
  // A tier 1 caller; the writer is tier 2.
  const ctx = h.ctx({ agent: { ...h.ctx().agent, tier: 1 } })
  await h.adopt.run({ plan: PLAN }, ctx)
  const result = await h.delegate.run({ taskId: 't2', brief: 'go' }, ctx)
  assert.equal(result.ok, false)
  assert.match(result.text, /writer is tier 2, above the caller's tier 1/)
})

test('a plan naming a template that is not a standing worker is refused at adoption', async (t) => {
  // `ceo` is registered but is an orchestrator; `worker-template` is a template.
  // Neither is something a plan may hand a task to.
  const h = await harness(t, ok)
  for (const template of ['ceo', 'worker-template']) {
    const bad = JSON.parse(JSON.stringify(PLAN).replace('"researcher"', `"${template}"`)) as typeof PLAN
    const result = await h.adopt.run({ plan: bad }, h.ctx({ runId: `run_${template}` }))
    assert.equal(result.ok, false, `${template} was accepted as a delegation target`)
    assert.match(result.text, new RegExp(`names template ${template}`))
  }
})

test('the registry refuses a kernel tool in a worker’s manifest', (t) => {
  const store = withStore(t)
  const views = parseToolViews(read('config/tool-views.yaml'))
  const config = parseKernelConfig(read('config/kernel.yaml'), { repoRoot: REPO_ROOT })
  const agents = new AgentRegistry({
    providers: new Set(Object.keys(parseProviders(read('config/providers.yaml')).entries)),
    toolViews: views,
    store,
    budgets: config.budgets,
  })
  // A temp fleet holding one worker that asks for a kernel tool.
  const root = tmpdir(t)
  mkdirSync(`${root}/sneaky/history`, { recursive: true })
  writeFileSync(
    `${root}/sneaky/agent.yaml`,
    `id: sneaky
version: 1
kind: standard
role: worker
soul: worker.md
tier: 2
model:
  primary: anthropic/claude-sonnet-5
tools:
  allow: [kernel.delegate]
memory:
  projectId: aos/agent/sneaky
`,
  )
  writeFileSync(`${root}/sneaky/AGENTS.md`, '# sneaky\n')
  assert.throws(
    () => agents.load(root),
    (e: unknown) => {
      assert.ok(e instanceof ConfigError)
      assert.match(e.message, /kernel tool, but sneaky is role: worker/)
      return true
    },
  )
})
