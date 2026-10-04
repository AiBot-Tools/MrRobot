// The goal writer, against the pmmcp double.
//
// This is the first component that WRITES to the operator's long-term memory, so
// the tests are mostly about the shapes of failure. Three matter more than the
// happy path:
//
//   a create whose result holds no readable id must fail the write, not invent
//   one — a fabricated goal id is a goal nothing can ever update, and in the log
//   it is indistinguishable from a real one;
//   the kernel must never write `done`, because `review` sits between
//   `in_progress` and `done` precisely so that finishing is a decision;
//   a failed status update must not take down the run that triggered it, while
//   still being loud.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test, { type TestContext } from 'node:test'
import { readFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'

import { PolicyDenied } from '../src/errors.js'
import type { EventStore } from '../src/events/store.js'
import { GoalsUnavailable, GoalWriteFailed, GoalWriter, goalIdOf } from '../src/goals/writer.js'
import { parsePlan } from '../src/goals/plan.js'
import { goalToolsUnusable, requiredArgs } from '../src/goals/tools.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews, type ToolViewsFile } from '../src/mcp/tool-views.js'
import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { pmmcpMock, type PmmcpMock } from './helpers/mock-pmmcp.js'
import { withStore } from './helpers/store.js'

const PROJECT = 'aos/ceo'

function shippedConfig(): KernelConfig {
  return parseKernelConfig(parseYaml(readFileSync(`${REPO_ROOT}/config/kernel.yaml`, 'utf8')), {
    repoRoot: REPO_ROOT,
  })
}

function toolViews(): ToolViewsFile {
  return parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8')))
}

async function wired(
  t: TestContext,
  options: Parameters<typeof pmmcpMock>[0] = {},
): Promise<{ store: EventStore; hub: McpHub; mock: PmmcpMock; writer: GoalWriter }> {
  const mock = pmmcpMock(options)
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const hub = new McpHub({ store, views: toolViews() })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)
  const goals = shippedConfig().goals
  const reason = goalToolsUnusable(hub, goals)
  const writer = new GoalWriter({
    store,
    hub,
    goals,
    ...(reason === undefined ? {} : { degradedReason: reason }),
  })
  return { store, hub, mock, writer }
}

const PLAN = `\`\`\`json
{
  "objective": { "title": "compare two log storage options", "successCriteria": ["both written up"] },
  "milestones": [
    {
      "id": "m1",
      "title": "research",
      "tasks": [
        { "id": "t1", "title": "write up sqlite", "template": "researcher", "acceptance": ["docs/sqlite.md exists"] },
        { "id": "t2", "title": "write up append-only", "template": "researcher", "acceptance": ["docs/append.md exists"] }
      ]
    }
  ],
  "questionsForOperator": ["which matters more, write latency or auditability?"]
}
\`\`\``

function payloads(store: EventStore, type: string): Record<string, unknown>[] {
  return store
    .query()
    .filter((r) => r.type === type)
    .map((r) => JSON.parse(r.payload) as Record<string, unknown>)
}

test("the shipped config's goal tools are usable against the double, which declares pmmcp's source", async (t) => {
  // kernel.yaml and the double both carry what pmmcp's source declares, so this
  // asserts they AGREE; the drift test against a live capture settles whether
  // the source matches what FastMCP actually serves.
  const { hub } = await wired(t)
  assert.equal(goalToolsUnusable(hub, shippedConfig().goals), undefined)
  // And every argument the kernel will send is named in one place.
  const args = requiredArgs(shippedConfig().goals)
  assert.deepEqual(
    args.map((a) => a.tool),
    ['create_goal', 'update_goal', 'get_goal_tree', 'list_goals'],
  )
})

test('a renamed tool or argument degrades the writer with a reason that names it', async (t) => {
  const { hub } = await wired(t)
  const config = shippedConfig().goals

  const renamedTool = goalToolsUnusable(hub, { ...config, tools: { ...config.tools, create: 'make_goal' } })
  assert.match(String(renamedTool), /declares no tool "make_goal"/)
  assert.match(String(renamedTool), /kernel\.yaml/, 'the reason must say where to fix it')

  const renamedArg = goalToolsUnusable(hub, { ...config, args: { ...config.args, title: 'name' } })
  assert.match(String(renamedArg), /does not accept name/)
  // Every disagreement at once: an operator fixing four names one boot at a time
  // restarts four times.
  const both = goalToolsUnusable(hub, {
    ...config,
    args: { ...config.args, title: 'name', status: 'state' },
  })
  assert.match(String(both), /create_goal/)
  assert.match(String(both), /update_goal\b/)
})

test('a validated plan becomes objective → milestone → task with the SERVER’s ids', async (t) => {
  const { store, mock, writer } = await wired(t)
  assert.equal(writer.available, true)

  const plan = parsePlan(PLAN, { knownTemplates: ['researcher'] })
  const tree = await writer.materialise(plan, PROJECT, 'run_1')

  // Ids came back from the server, not from the kernel.
  assert.equal(mock.state.goals.has(tree.objectiveGoalId), true)
  assert.equal(tree.milestones.size, 1)
  assert.equal(tree.tasks.size, 2)
  const objective = mock.state.goals.get(tree.objectiveGoalId)
  assert.equal(objective?.kind, 'objective')
  assert.equal(objective?.parentId, undefined)

  const milestoneId = tree.milestones.get('m1')
  assert.equal(mock.state.goals.get(String(milestoneId))?.parentId, tree.objectiveGoalId)
  for (const planId of ['t1', 't2']) {
    const taskId = tree.tasks.get(planId)
    const goal = mock.state.goals.get(String(taskId))
    assert.equal(goal?.kind, 'task')
    assert.equal(goal?.parentId, milestoneId, `${planId} does not hang from the milestone`)
    assert.equal(goal?.status, 'pending', 'a new task starts pending, not in progress')
  }

  // Every goal is in the run's own namespace and nowhere else.
  for (const goal of mock.state.goals.values()) assert.equal(goal.projectId, PROJECT)

  // The record: one goal.created per goal, carrying the plan id it came from, and
  // one plan.adopted with counts rather than the plan itself.
  const created = payloads(store, 'goal.created')
  assert.equal(created.length, 4)
  assert.deepEqual(
    created.map((c) => `${String(c['kind'])}:${String(c['planTaskId'] ?? '-')}`),
    ['objective:-', 'milestone:m1', 'task:t1', 'task:t2'],
  )
  const adopted = payloads(store, 'plan.adopted')
  assert.equal(adopted.length, 1)
  assert.equal(adopted[0]?.['milestones'], 1)
  assert.equal(adopted[0]?.['tasks'], 2)
  assert.equal(adopted[0]?.['questions'], 1)
  assert.equal(adopted[0]?.['objectiveGoalId'], tree.objectiveGoalId)
})

test('a bare-string id is accepted; a prose result fails the write and names what was written', async (t) => {
  // The result shape is UNCONFIRMED, so both plausible forms work.
  const bare = await wired(t, { goalIdShape: 'bare' })
  const plan = parsePlan(PLAN, { knownTemplates: ['researcher'] })
  const tree = await bare.writer.materialise(plan, PROJECT, 'run_1')
  assert.equal(bare.mock.state.goals.has(tree.objectiveGoalId), true)

  // And prose is refused rather than mined for something id-shaped.
  const prose = await wired(t, { goalIdShape: 'prose' })
  await assert.rejects(
    () => prose.writer.materialise(plan, PROJECT, 'run_2'),
    (e: unknown) => {
      assert.ok(e instanceof GoalWriteFailed)
      assert.match(e.message, /returned no readable goal id/)
      // Nothing had been written yet, and the error says so rather than leaving
      // the caller to guess what is on the server.
      assert.deepEqual(e.written, [])
      return true
    },
  )
  // The server did create the objective — the write is partial, which is a FACT,
  // and no goal.created claimed an id for it.
  assert.equal(payloads(prose.store, 'goal.created').length, 0)
  assert.equal(payloads(prose.store, 'plan.adopted').length, 0)
})

test('a failure partway through reports the ids already written', async (t) => {
  // Partial failure is the case this gets wrong quietly. A caller that believed
  // "the whole write failed" would leave an objective and a milestone on the
  // server that nothing knows about. The failure is injected by count rather than
  // arranged by timing, so it lands on the third create every run.
  const { store, mock, writer } = await wired(t, { failAfter: { create_goal: 2 } })
  const plan = parsePlan(PLAN, { knownTemplates: ['researcher'] })

  await assert.rejects(
    () => writer.materialise(plan, PROJECT, 'run_1'),
    (e: unknown) => {
      assert.ok(e instanceof GoalWriteFailed, `threw ${String(e)}`)
      // The two ids that DO exist on the server, named.
      assert.equal(e.written.length, 2, `written: ${e.written.join(', ')}`)
      for (const id of e.written) assert.equal(mock.state.goals.has(id), true)
      return true
    },
  )

  // Recorded as far as it got, and not adopted: a partial tree is a fact, and
  // `plan.adopted` would claim a whole one.
  const created = payloads(store, 'goal.created')
  assert.deepEqual(
    created.map((c) => String(c['kind'])),
    ['objective', 'milestone'],
  )
  assert.equal(payloads(store, 'plan.adopted').length, 0)
})

/** A tree the KERNEL wrote, so its goals carry goal.created rows in this store. */
async function written(writer: GoalWriter): Promise<{ task: string; objective: string }> {
  const tree = await writer.materialise(parsePlan(PLAN, { knownTemplates: ['researcher'] }), PROJECT, 'run_0')
  return { task: String(tree.tasks.get('t1')), objective: tree.objectiveGoalId }
}

test('the kernel may set in_progress, blocked and review — and never done; review reaches pmmcp as in_progress at 100%', async (t) => {
  const { store, mock, writer } = await wired(t)
  const { task } = await written(writer)

  await writer.setStatus(task, 'in_progress', { projectId: PROJECT, runId: 'run_1' })
  assert.equal(mock.state.goals.get(task)?.status, 'in_progress')
  await writer.setStatus(task, 'review', { projectId: PROJECT, runId: 'run_1' })
  // pmmcp has no `review`: in_progress with progress 100, per goals.statuses.
  assert.equal(mock.state.goals.get(task)?.status, 'in_progress')
  assert.equal(mock.state.goals.get(task)?.progressPct, 100)
  const sent = mock.calls.filter((c) => c.tool === 'update_goal').map((c) => c.args)
  assert.deepEqual(sent, [
    { goal_id: task, status: 'in_progress' },
    { goal_id: task, status: 'in_progress', progress_pct: 100 },
  ])

  // `done` is a decision, not a transition. Refused before any call is made.
  const before = mock.calls.length
  await assert.rejects(
    () => writer.setStatus(task, 'done' as 'review', { projectId: PROJECT }),
    (e: unknown) => {
      assert.ok(e instanceof PolicyDenied)
      assert.match(e.message, /a decision, not a transition/)
      return true
    },
  )
  assert.equal(mock.calls.length, before, 'a refused status still reached the server')

  // The kernel's log keeps the kernel's vocabulary.
  const moves = payloads(store, 'goal.status')
  assert.deepEqual(
    moves.map((m) => `${String(m['to'])}:${String(m['by'])}`),
    ['in_progress:kernel', 'review:kernel'],
  )
  assert.equal(moves[0]?.['runId'], 'run_1')
})

test('a goal this kernel did not create, or created in another namespace, is never moved', async (t) => {
  // pmmcp's update_goal takes no project_id and moves ANY goal by id. The
  // kernel's own goal.created record is the only namespace check there is.
  const { store, mock, writer } = await wired(t)
  const foreign = mock.seedTree('aos/agent/researcher')
  await assert.rejects(
    () => writer.setStatus(foreign.task, 'in_progress', { projectId: PROJECT }),
    (e: unknown) => e instanceof PolicyDenied && /did not create that goal/.test(e.message),
  )

  const { task } = await written(writer)
  const afterWrite = mock.calls.length
  await assert.rejects(
    () => writer.setStatus(task, 'in_progress', { projectId: 'aos/agent/researcher' }),
    (e: unknown) => e instanceof PolicyDenied && /created in aos\/ceo, not aos\/agent\/researcher/.test(e.message),
  )
  assert.equal(mock.calls.length - afterWrite, 0, 'a refused move reached the server')
  assert.equal(mock.calls.filter((c) => c.tool === 'update_goal').length, 0)
  assert.equal(mock.state.goals.get(foreign.task)?.status, 'pending')
  assert.equal(payloads(store, 'goal.status').length, 0)
})

test('pmmcp answering a refusal as SUCCESSFUL text is a failure, and trySetStatus keeps the run alive', async (t) => {
  const { store, mock, writer } = await wired(t)
  const { task } = await written(writer)
  // The operator closed it in pmmcp; completed → blocked is not in pmmcp's table,
  // and pmmcp says so as "Error: Cannot transition…" with no error flag.
  mock.state.goals.get(task)!.status = 'completed'

  await assert.rejects(
    () => writer.setStatus(task, 'blocked', { projectId: PROJECT }),
    (e: unknown) => e instanceof GoalWriteFailed && /did not confirm .*Cannot transition from 'completed' to 'blocked'/.test(e.message),
  )
  assert.equal(mock.state.goals.get(task)?.status, 'completed')
  assert.equal(payloads(store, 'goal.status').length, 0, 'a move that did not happen was recorded')

  // Gone from the server: "Goal x not found." is success text too.
  mock.state.goals.delete(task)
  await assert.rejects(() => writer.setStatus(task, 'blocked', { projectId: PROJECT }), /not found/)

  // The lifecycle path must not take the run down with it: a stale goal is
  // something an operator can see and fix, a killed run is work lost.
  const ok = await writer.trySetStatus(task, 'review', { projectId: PROJECT, runId: 'run_1' })
  assert.equal(ok, false)
  assert.equal(payloads(store, 'goal.status').length, 0)
})

test('a degraded writer refuses before touching the server', async (t) => {
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const hub = new McpHub({ store, views: toolViews() })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)
  const writer = new GoalWriter({
    store,
    hub,
    goals: shippedConfig().goals,
    degradedReason: 'pmmcp declares no tool "create_goal"',
  })

  assert.equal(writer.available, false)
  const plan = parsePlan(PLAN, { knownTemplates: ['researcher'] })
  await assert.rejects(() => writer.materialise(plan, PROJECT, 'run_1'), GoalsUnavailable)
  await assert.rejects(() => writer.setStatus('goal-1', 'review', { projectId: PROJECT }), GoalsUnavailable)
  assert.equal(mock.calls.length, 0, 'a degraded writer still called the server')
})

test('goalIdOf reads the shapes a server might return and refuses the rest', () => {
  const text = (t: string): { type: 'text'; text: string }[] => [{ type: 'text', text: t }]
  // pmmcp's own reply, first line only, and only at the start.
  assert.equal(goalIdOf(text('✅ Goal created: goal_0123456789ab\n   Title: x')), 'goal_0123456789ab')
  assert.equal(goalIdOf(text('Error: Parent goal not found: goal_0123456789ab')), undefined)
  assert.equal(goalIdOf(text('Error creating goal: ✅ Goal created: goal_x')), undefined)
  assert.equal(goalIdOf(text('{"id":"goal-1"}')), 'goal-1')
  assert.equal(goalIdOf(text('{"goal_id":"goal-2"}')), 'goal-2')
  assert.equal(goalIdOf(text('{"goalId":"goal-3"}')), 'goal-3')
  assert.equal(goalIdOf(text('"goal-4"')), 'goal-4')
  assert.equal(goalIdOf(text('goal-5')), 'goal-5')
  // A sentence is not an id, however id-shaped a word in it looks.
  assert.equal(goalIdOf(text('I created goal-6 for you')), undefined)
  assert.equal(goalIdOf(text('{"ok":true}')), undefined)
  assert.equal(goalIdOf(text('')), undefined)
  assert.equal(goalIdOf(undefined), undefined)
  assert.equal(goalIdOf(text('{"id":"   "}')), undefined)
})
