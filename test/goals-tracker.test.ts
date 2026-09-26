// Goal tracking across a real run lifecycle.
//
// The unit tests in goals-writer.test.ts prove the writer; this proves the
// WIRING, which is where this kind of feature actually fails: a status update
// that never fires, fires for the wrong agent, or fires and takes the run down
// with it. Everything here goes through a real kernel — the control plane starts
// the run, the pmmcp double is the server, and the assertions read the double's
// state and the event log rather than any return value.
//
// The four claims:
//
//   a run started with a goalId moves that goal to in_progress, then to review
//   when it finishes well and blocked when it does not — and NEVER to done;
//   a plan in a finished CEO result becomes an objective → milestone → task tree
//   in the CEO's own namespace;
//   a worker emitting the same plan-shaped JSON writes nothing, because only an
//   orchestrator may have a plan adopted;
//   a restart blocks the goals of runs it orphaned, without re-executing anything.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test, { type TestContext } from 'node:test'

import { connectControl } from '../src/cli/client.js'
import { GoalTracker } from '../src/goals/tracker.js'
import { GoalWriter } from '../src/goals/writer.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { anthropicEndTurn, fakeProvider, type ScriptedResponse } from './helpers/fake-provider.js'
import { bootOn, fixture, REPO_ROOT, rows, TEST_TOKEN, withKernel } from './helpers/kernel.js'
import type { Kernel } from '../src/kernel.js'
import { pmmcpMock, type PmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'
import { Writable } from 'node:stream'
import { createLogger } from '../src/log.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseKernelConfig } from '../src/config.js'
import { readFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'

const REAL_REF = 'anthropic/claude-sonnet-5'
const VAULT_ID = 'anthropic-api-key'
const CEO_PROJECT = 'aos/ceo'

const PLAN_TEXT = `Here is the plan.

\`\`\`json
{
  "objective": { "title": "compare two log storage options", "successCriteria": ["both written up"] },
  "milestones": [
    {
      "id": "m1",
      "title": "research both options",
      "tasks": [
        { "id": "t1", "title": "write up sqlite", "template": "researcher", "acceptance": ["docs/sqlite.md exists"] },
        { "id": "t2", "title": "write up append-only", "template": "writer", "acceptance": ["docs/append.md exists"] }
      ]
    }
  ]
}
\`\`\`

I will delegate these next.`

async function bootWithGoals(
  t: TestContext,
  script: readonly ScriptedResponse[],
  extra: Parameters<typeof withKernel>[1] = {},
): Promise<{ mock: PmmcpMock; kernel: Awaited<ReturnType<typeof withKernel>>['kernel']; dbPath: string }> {
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-goals' } })
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider(script)
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
    ...extra,
  })
  return { mock, kernel, dbPath: fx.dbPath }
}

/** Start a run over the control plane, optionally naming a goal, and wait. */
async function runWithGoal(
  kernel: Awaited<ReturnType<typeof withKernel>>['kernel'],
  input: string,
  goalId?: string,
  agentId = 'ceo',
): Promise<Record<string, unknown>> {
  const client = await connectControl({ port: kernel.port, token: TEST_TOKEN, timeoutMs: 20_000 })
  try {
    const early = new Map<string, Record<string, unknown>>()
    let mine: string | undefined
    let settle: (p: Record<string, unknown>) => void = () => undefined
    const finished = new Promise<Record<string, unknown>>((resolve) => {
      settle = resolve
    })
    client.onEvent((event) => {
      if (event.type !== 'run.finished') return
      const payload = event.payload as Record<string, unknown> | null
      if (payload === null || typeof payload['runId'] !== 'string') return
      if (payload['runId'] === mine) settle(payload)
      else early.set(payload['runId'], payload)
    })
    const started = (await client.call('run.start', {
      agentId,
      input,
      ...(goalId === undefined ? {} : { goalId }),
    })) as { runId: string }
    mine = started.runId
    const already = early.get(started.runId)
    if (already !== undefined) settle(already)
    const timeout = new Promise<Record<string, unknown>>((_, reject) => {
      const timer = setTimeout(() => reject(new Error('run did not finish')), 20_000)
      timer.unref?.()
    })
    return await Promise.race([finished, timeout])
  } finally {
    client.close()
  }
}

function statuses(dbPath: string): string[] {
  return rows(dbPath)
    .filter((r) => r.type === 'goal.status')
    .map((r) => {
      const p = JSON.parse(r.payload) as { to: string; by: string }
      return `${p.to}:${p.by}`
    })
}

test('a run naming a goal moves it to in_progress, then review — never done', async (t) => {
  const { mock, kernel, dbPath } = await bootWithGoals(t, [
    anthropicEndTurn({ text: 'the task is done', inputTokens: 900, outputTokens: 20 }),
  ])
  const { task } = mock.seedTree(CEO_PROJECT)

  const finished = await runWithGoal(kernel, 'do the task', task)
  assert.equal(finished['status'], 'ok', String(finished['reason']))

  // Drained through shutdown, because the updates are queued off the append.
  await kernel.shutdown()
  assert.equal(mock.state.goals.get(task)?.status, 'review')
  assert.deepEqual(statuses(dbPath), ['in_progress:kernel', 'review:kernel'])

  // The kernel never closed it. That is the point of `review` existing.
  assert.equal(
    rows(dbPath).some((r) => r.type === 'goal.status' && r.payload.includes('"to":"done"')),
    false,
  )
})

test('a run that fails moves its goal to blocked, not abandoned', async (t) => {
  // No provider script: the run errors, which is the ordinary failure an operator
  // meets. `blocked` is a state something can act on; `abandoned` would be the
  // kernel giving up on the operator's behalf.
  const { mock, kernel, dbPath } = await bootWithGoals(t, [])
  const { task } = mock.seedTree(CEO_PROJECT)

  const finished = await runWithGoal(kernel, 'do the task', task)
  assert.notEqual(finished['status'], 'ok')

  await kernel.shutdown()
  assert.equal(mock.state.goals.get(task)?.status, 'blocked')
  assert.deepEqual(statuses(dbPath), ['in_progress:kernel', 'blocked:kernel'])
})

test('a run with no goalId touches no goal at all', async (t) => {
  const { mock, kernel, dbPath } = await bootWithGoals(t, [
    anthropicEndTurn({ text: 'no goal here', inputTokens: 900, outputTokens: 10 }),
  ])
  mock.seedTree(CEO_PROJECT)
  const before = [...mock.state.goals.values()].map((g) => g.status)

  await runWithGoal(kernel, 'just answer')
  await kernel.shutdown()

  assert.deepEqual([...mock.state.goals.values()].map((g) => g.status), before)
  assert.deepEqual(statuses(dbPath), [])
})

test('a plan in a finished CEO result becomes a goal tree in the CEO’s namespace', async (t) => {
  const { mock, kernel, dbPath } = await bootWithGoals(t, [
    anthropicEndTurn({ text: PLAN_TEXT, inputTokens: 1_200, outputTokens: 300 }),
  ])

  const finished = await runWithGoal(kernel, 'plan the comparison')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  await kernel.shutdown()

  // Four goals, in the CEO's own namespace, hierarchically.
  const goals = [...mock.state.goals.values()]
  assert.equal(goals.length, 4, goals.map((g) => `${g.kind}:${g.title}`).join(', '))
  for (const goal of goals) assert.equal(goal.projectId, CEO_PROJECT)
  const objective = goals.find((g) => g.kind === 'objective')
  const milestone = goals.find((g) => g.kind === 'milestone')
  const tasks = goals.filter((g) => g.kind === 'task')
  assert.equal(objective?.title, 'compare two log storage options')
  assert.equal(milestone?.parentId, objective?.id)
  assert.equal(tasks.length, 2)
  for (const task of tasks) assert.equal(task.parentId, milestone?.id)
  // Every goal starts pending: adopting a plan is not starting work.
  for (const goal of goals) assert.equal(goal.status, 'pending')

  const logged = rows(dbPath)
  assert.equal(logged.filter((r) => r.type === 'goal.created').length, 4)
  const adopted = logged.filter((r) => r.type === 'plan.adopted')
  assert.equal(adopted.length, 1)
  const payload = JSON.parse(adopted[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(payload['tasks'], 2)
  assert.equal(payload['projectId'], CEO_PROJECT)
  assert.equal(payload['objectiveGoalId'], objective?.id)
})

test('a result that is not a plan, and one that is a broken plan, write nothing', async (t) => {
  const { mock, kernel, dbPath } = await bootWithGoals(t, [
    anthropicEndTurn({ text: 'Just some prose, and `{"answer": 42}` for good measure.', inputTokens: 900, outputTokens: 20 }),
  ])
  await runWithGoal(kernel, 'answer briefly')
  await kernel.shutdown()
  assert.equal(mock.state.goals.size, 0)
  assert.equal(rows(dbPath).filter((r) => r.type === 'plan.adopted').length, 0)
})

test('a plan whose task names an unregistered template is refused, and nothing is written', async (t) => {
  const broken = PLAN_TEXT.replace(/"template": "(researcher|writer)"/g, '"template": "nonexistent-agent"')
  const { mock, kernel, dbPath } = await bootWithGoals(t, [
    anthropicEndTurn({ text: broken, inputTokens: 1_200, outputTokens: 300 }),
  ])
  await runWithGoal(kernel, 'plan the comparison')
  await kernel.shutdown()

  // Refused before the first create: a partial tree from a plan that could never
  // run is worse than none.
  assert.equal(mock.state.goals.size, 0)
  assert.equal(rows(dbPath).filter((r) => r.type === 'goal.created').length, 0)
  assert.equal(rows(dbPath).filter((r) => r.type === 'plan.adopted').length, 0)
})

test('only an orchestrator may have a plan adopted from its result', async (t) => {
  // The claim is about the tracker's gate, not about any agent that exists: a
  // worker emitting plan-shaped JSON must not be able to write the CEO's tree.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const hub = new McpHub({
    store,
    views: parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8'))),
  })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)
  const config = parseKernelConfig(
    parseYaml(readFileSync(`${REPO_ROOT}/config/kernel.yaml`, 'utf8')),
    { repoRoot: REPO_ROOT },
  )
  const writer = new GoalWriter({ store, hub, goals: config.goals })

  const tracker = new GoalTracker({
    store,
    writer,
    adoptFromRuns: true,
    projectIdOf: () => CEO_PROJECT,
    // The whole point of the test: this agent is not an orchestrator.
    isOrchestrator: (agentId) => agentId === 'ceo',
    knownTemplates: () => ['researcher', 'writer', 'worker'],
  })
  const detach = tracker.attach()
  t.after(() => {
    detach()
  })

  const emit = (runId: string, agentId: string): void => {
    store.append({ type: 'run.queued', runId, agentId, payload: { schemaVersion: 1, runId, agentId, lane: 'main' } })
    store.append({
      type: 'llm.response',
      runId,
      agentId,
      payload: {
        schemaVersion: 1,
        ref: 'anthropic/x',
        attempt: 0,
        content: PLAN_TEXT,
        finish: 'end_turn',
        inputTokens: 10,
        outputTokens: 10,
        costMicroUsd: 1,
        durationMs: 1,
      },
    })
    store.append({
      type: 'run.finished',
      runId,
      agentId,
      payload: { schemaVersion: 1, runId, status: 'ok', costMicroUsd: 1, llmCalls: 1, toolCalls: 0, durationMs: 1 },
    })
  }

  emit('run_worker', 'worker')
  await tracker.drain()
  assert.equal(mock.state.goals.size, 0, 'a worker wrote a goal tree')

  emit('run_ceo', 'ceo')
  await tracker.drain()
  assert.equal(mock.state.goals.size, 4, 'the orchestrator’s plan was not adopted')
})

test('a non-plan result is quiet; a plan that did not parse is loud', async (t) => {
  // The guard this pins is log hygiene, and a falsifier found nothing testing it:
  // removing `looksLikePlan` changed no goal state, only the log, because every
  // ordinary orchestrator turn would then be put through the parser and refused.
  // A warning per turn trains the operator to ignore the log, which costs exactly
  // when it matters.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const store = withStore(t)
  const hub = new McpHub({
    store,
    views: parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8'))),
  })
  t.after(async () => {
    await hub.close()
  })
  await hub.connect('pmmcp', mock.connect)
  const config = parseKernelConfig(
    parseYaml(readFileSync(`${REPO_ROOT}/config/kernel.yaml`, 'utf8')),
    { repoRoot: REPO_ROOT },
  )

  const lines: string[] = []
  const stream = new Writable({
    write(chunk: Buffer, _enc, done) {
      lines.push(String(chunk))
      done()
    },
  })
  const tracker = new GoalTracker({
    store,
    writer: new GoalWriter({ store, hub, goals: config.goals }),
    adoptFromRuns: true,
    projectIdOf: () => CEO_PROJECT,
    isOrchestrator: () => true,
    knownTemplates: () => ['researcher', 'writer'],
    logger: createLogger({ level: 'warn', destination: stream }),
  })
  const detach = tracker.attach()
  t.after(() => {
    detach()
  })

  const finish = (runId: string, content: string): void => {
    store.append({ type: 'run.queued', runId, agentId: 'ceo', payload: { schemaVersion: 1, runId, agentId: 'ceo', lane: 'main' } })
    store.append({
      type: 'llm.response',
      runId,
      agentId: 'ceo',
      payload: {
        schemaVersion: 1, ref: 'anthropic/x', attempt: 0, content, finish: 'end_turn',
        inputTokens: 10, outputTokens: 10, costMicroUsd: 1, durationMs: 1,
      },
    })
    store.append({
      type: 'run.finished',
      runId,
      agentId: 'ceo',
      payload: { schemaVersion: 1, runId, status: 'ok', costMicroUsd: 1, llmCalls: 1, toolCalls: 0, durationMs: 1 },
    })
  }

  // An ordinary turn: prose, and some JSON that is not a plan.
  finish('run_prose', 'The biggest risk is the shared vault. ```json\n{"answer":42}\n```')
  await tracker.drain()
  assert.deepEqual(lines, [], `an ordinary turn logged: ${lines.join('')}`)
  assert.equal(mock.state.goals.size, 0)

  // A turn that WAS trying to be a plan and got it wrong: loud, with the reason.
  finish('run_broken', '```json\n{"objective":{"title":"x","successCriteria":["c"]},"milestones":[]}\n```')
  await tracker.drain()
  assert.equal(lines.length, 1, `expected exactly one warning, got: ${lines.join('')}`)
  assert.match(lines[0] ?? '', /a plan-shaped result was refused/)
  assert.match(lines[0] ?? '', /milestones/, 'the warning must carry the reason')
  assert.equal(mock.state.goals.size, 0)
})

test('a goal update that fails does not fail the run that triggered it', async (t) => {
  // A stale goal status is something an operator can see and fix; a run killed by
  // its own bookkeeping is work lost. The goal named here does not exist on the
  // server, so every update for this run fails.
  const { mock, kernel, dbPath } = await bootWithGoals(t, [
    anthropicEndTurn({ text: 'done anyway', inputTokens: 900, outputTokens: 10 }),
  ])
  const finished = await runWithGoal(kernel, 'do the task', 'goal-does-not-exist')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  await kernel.shutdown()

  // Nothing was recorded, because nothing happened on the server.
  assert.deepEqual(statuses(dbPath), [])
  assert.equal(mock.state.goals.size, 0)
})

test('a restart blocks the goals of runs it orphaned, and re-executes nothing', async (t) => {
  // The Phase 1 exit criterion's shape for goals: a kernel that died mid-run left
  // a task goal reading in_progress, and without this nothing would ever move it.
  //
  // One fixture, two boots against the SAME data dir — the pattern the existing
  // restart test uses, because a second `withKernel` would silently get a fresh
  // temp directory and the second kernel would see an empty log.
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: 'vault-fixture-credential-goals' } })
  t.after(async () => {
    await mock.close()
  })
  const { task } = mock.seedTree(CEO_PROJECT)
  const fx = fixture(t)
  const boot = (): Promise<Kernel> =>
    bootOn(t, fx, {
      env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
      clientFactory: mock.connect,
    })

  // Boot once and write what a crash leaves behind through the KERNEL'S OWN
  // store: a run that named the goal, started, and never finished. Using the
  // kernel's handle rather than a second writable one means the first kernel's
  // tracker sees it too, so the in_progress status is set by the real path rather
  // than poked into the double — which is the state the restart has to clean up.
  const first = await boot()
  const orphanRunId = 'run_orphaned_by_a_restart'
  first.store.append({
    type: 'run.queued',
    runId: orphanRunId,
    agentId: 'ceo',
    payload: { schemaVersion: 1, runId: orphanRunId, agentId: 'ceo', lane: 'main', goalId: task },
  })
  first.store.append({
    type: 'run.started',
    runId: orphanRunId,
    agentId: 'ceo',
    payload: { schemaVersion: 1, runId: orphanRunId, agentId: 'ceo', lane: 'main', tier: 2, taint: 'clean' },
  })
  // shutdown drains the tracker's queue, so the status is settled after this.
  await first.shutdown()
  assert.equal(
    mock.state.goals.get(task)?.status,
    'in_progress',
    'the first kernel did not move the goal, so the restart has nothing to clean up',
  )

  const second = await boot()
  // Recovery closed the run out; the goal move is queued off that, so give the
  // serial queue a turn before reading the server.
  await new Promise((resolve) => {
    setTimeout(resolve, 250)
  })
  const orphaned = second.recovered.orphanRuns.map((r) => r.runId)
  await second.shutdown()

  assert.deepEqual(orphaned, [orphanRunId], 'the restart did not see the run as orphaned')
  assert.equal(mock.state.goals.get(task)?.status, 'blocked')

  const logged = rows(fx.dbPath)
  assert.ok(
    logged.some(
      (r) =>
        r.type === 'goal.status' &&
        r.payload.includes('"to":"blocked"') &&
        r.payload.includes('orphaned'),
    ),
    'no blocked status naming the restart',
  )
  // Nothing was re-executed: the orphan produced no new model call.
  assert.equal(logged.filter((r) => r.type === 'llm.request').length, 0)
})
