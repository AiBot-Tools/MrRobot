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
import { EventStore, type AppendInput } from '../src/events/store.js'
import type { EventRow } from '../src/events/chain.js'
import { GoalsUnavailable, GoalWriteFailed, GoalWriter, goalIdOf } from '../src/goals/writer.js'
import { createGoal, getGoalTree, updateGoal } from '../src/goals/pmmcp.js'
import { parsePlan } from '../src/goals/plan.js'
import { GOALS_REASON_BYTES, goalToolsUnusable, requiredArgs, watchGoalTools } from '../src/goals/tools.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews, type ToolViewsFile } from '../src/mcp/tool-views.js'
import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { GOAL_RESULT_OUTPUT, PMMCP_TOOLS, pmmcpMock, type JsonObjectSchema, type PmmcpMock } from './helpers/mock-pmmcp.js'
import { closeVerified, withStore } from './helpers/store.js'

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
  given?: EventStore,
): Promise<{ store: EventStore; hub: McpHub; mock: PmmcpMock; writer: GoalWriter }> {
  const mock = pmmcpMock(options)
  t.after(async () => {
    await mock.close()
  })
  const store = given ?? withStore(t)
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

/** A store that refuses one event type, as a full disk or a closed handle would. */
class RefusingStore extends EventStore {
  readonly #refused: string
  constructor(refused: string) {
    super(':memory:')
    this.#refused = refused
  }
  override append(input: AppendInput): EventRow {
    if (input.type === this.#refused) throw new Error(`this store refuses ${input.type}`)
    return super.append(input)
  }
}

function refusing(t: TestContext, type: string): RefusingStore {
  const store = new RefusingStore(type)
  // What it took is chained like any store's: verified at the end.
  t.after(() => {
    closeVerified(store)
  })
  return store
}

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

/** A captured goal tool's schema, edited: the server after a pmmcp upgrade. */
function edited(tool: string, edit: (schema: JsonObjectSchema) => JsonObjectSchema): Record<string, JsonObjectSchema> {
  const spec = PMMCP_TOOLS.find((s) => s.name === tool)
  assert.ok(spec !== undefined)
  return { [tool]: edit(spec.inputSchema) }
}

test('a live goal tool that newly requires an argument the kernel does not send degrades goals by name', async (t) => {
  // pmmcp's P4 makes project_id required on update_goal. The names check alone
  // passes that server (project_id is just one more property), and every
  // update would then fail as success text.
  const { hub } = await wired(t, {
    schemas: edited('update_goal', (s) => ({
      ...s,
      properties: { ...s.properties, project_id: { type: 'string' } },
      required: ['goal_id', 'project_id'],
    })),
  })
  assert.match(
    String(goalToolsUnusable(hub, shippedConfig().goals)),
    /pmmcp\.update_goal requires project_id, which the kernel does not send on every call/,
  )

  // An argument the kernel sends only sometimes is not enough either.
  const { hub: parentRequired } = await wired(t, {
    schemas: edited('create_goal', (s) => ({ ...s, required: ['title', 'project_id', 'parent_goal_id'] })),
  })
  assert.match(String(goalToolsUnusable(parentRequired, shippedConfig().goals)), /requires parent_goal_id/)
})

test('a live argument whose type no longer admits what the kernel sends degrades goals by name', async (t) => {
  const { hub } = await wired(t, {
    schemas: edited('create_goal', (s) => ({ ...s, properties: { ...s.properties, goal_type: { type: 'integer' } } })),
  })
  assert.match(
    String(goalToolsUnusable(hub, shippedConfig().goals)),
    /pmmcp\.create_goal\.goal_type is integer, but the kernel sends a string/,
  )
})

test('an extra optional live argument is not drift: a server after P4 that only adds project_id still serves', async (t) => {
  const { hub } = await wired(t, {
    schemas: edited('update_goal', (s) => ({
      ...s,
      properties: { ...s.properties, project_id: { anyOf: [{ type: 'string' }, { type: 'null' }], default: null } },
    })),
  })
  assert.equal(goalToolsUnusable(hub, shippedConfig().goals), undefined)
})

test('a live branch the kernel cannot type is unknown, not narrower: a $ref status still serves', async (t) => {
  // What pydantic emits for Optional[GoalStatus] with a str Enum.
  const { hub } = await wired(t, {
    schemas: edited('update_goal', (s) => ({
      ...s,
      properties: { ...s.properties, status: { anyOf: [{ $ref: '#/$defs/GoalStatus' }, { type: 'null' }], default: null } },
    })),
  })
  assert.equal(goalToolsUnusable(hub, shippedConfig().goals), undefined)
})

test('a live enum that leaves out a value the kernel sends degrades goals by name; one that holds them serves', async (t) => {
  const withStatus = (values: string[]): Record<string, JsonObjectSchema> =>
    edited('update_goal', (s) => ({
      ...s,
      properties: { ...s.properties, status: { anyOf: [{ type: 'string', enum: values }, { type: 'null' }], default: null } },
    }))
  const { hub } = await wired(t, { schemas: withStatus(['pending', 'active', 'done', 'blocked']) })
  assert.match(
    String(goalToolsUnusable(hub, shippedConfig().goals)),
    /pmmcp\.update_goal\.status accepts only pending, active, done, blocked, not in_progress/,
  )
  const { hub: holds } = await wired(t, { schemas: withStatus(['pending', 'in_progress', 'completed', 'abandoned', 'blocked']) })
  assert.equal(goalToolsUnusable(holds, shippedConfig().goals), undefined)

  const { hub: kinds } = await wired(t, {
    schemas: edited('create_goal', (s) => ({
      ...s,
      properties: { ...s.properties, goal_type: { type: 'string', enum: ['objective', 'task'], default: 'objective' } },
    })),
  })
  assert.match(String(goalToolsUnusable(kinds, shippedConfig().goals)), /create_goal\.goal_type accepts only objective, task, not milestone/)
})

test('two goals.args entries naming one wire key degrade goals, and a call built from them never leaves', async (t) => {
  const { hub, mock } = await wired(t)
  const goals = shippedConfig().goals
  const clashing = { ...goals, args: { ...goals.args, kind: 'title' } }
  assert.match(String(goalToolsUnusable(hub, clashing)), /goals\.args gives title to two arguments of pmmcp\.create_goal/)
  const before = mock.calls.length
  await assert.rejects(
    () => createGoal({ hub, goals: clashing, serverId: 'pmmcp' }, { project_id: PROJECT, goal_type: 'task', title: 'T', parent_goal_id: 'g1' }, 'test'),
    GoalWriteFailed,
  )
  assert.equal(mock.calls.length, before, 'a call with one value overwriting another reached the server')
})

test('a goals.statuses entry the kernel may not send degrades goals at boot, naming the line', async (t) => {
  const { hub } = await wired(t)
  const goals = shippedConfig().goals
  const reason = goalToolsUnusable(hub, { ...goals, statuses: { ...goals.statuses, review: 'completed' } })
  assert.match(String(reason), /kernel\.yaml goals\.statuses\.review is "completed"; the kernel sends only in_progress, blocked/)
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

// ── contract P6: typed results (§6 step 2.1.6) ───────────────────────────────

const P6 = { refusals: 'p5', outputs: { create_goal: 'structured', update_goal: 'structured' } } as const
const plan = (): ReturnType<typeof parsePlan> => parsePlan(PLAN, { knownTemplates: ['researcher'] })

test('a create is read from structuredContent when there is one, with or without a text block beside it', async (t) => {
  // P6's JSON, pmmcp's prose naming the same goal, or no text at all.
  for (const structuredText of ['json', 'prose', 'none'] as const) {
    const { store, mock, writer } = await wired(t, { ...P6, structuredText })
    const tree = await writer.materialise(plan(), PROJECT, 'run_1')
    assert.ok(mock.state.goals.has(tree.objectiveGoalId), structuredText)
    assert.equal(payloads(store, 'goal.created').length, 4)
    assert.equal(payloads(store, 'goal.unconfirmed').length, 0)
  }
})

test('a typed create the kernel will not confirm is refused, records the orphan, and writes no goal.created', async (t) => {
  const ONE = 'goal_000000000001'
  // [why, double, refusal, the orphan row's goalId]
  const cases: [string, Parameters<typeof pmmcpMock>[0], RegExp, string | undefined][] = [
    // Both forms agree, on another project: only the project check can refuse it.
    ['another project', { ...P6, skew: { create_goal: { fields: { project_id: 'aos/elsewhere' } } } }, /pmmcp reports it in aos\/elsewhere, not aos\/ceo/, ONE],
    // Only structuredContent names another goal: only the agreement check can,
    // and with two ids for one write the row claims neither and names both.
    ['forms that disagree on the goal', { ...P6, skew: { create_goal: { fields: { goal_id: 'goal_ffffffffffff' }, where: 'structured' } } }, /disagree: the text names goal_000000000001, structuredContent goal_ffffffffffff/, undefined],
    // The same, with pmmcp's prose as the text: it names the goal it wrote.
    ['prose that names another goal', { ...P6, structuredText: 'prose', skew: { create_goal: { fields: { goal_id: 'goal_ffffffffffff' }, where: 'structured' } } }, /disagree: the text names goal_000000000001, structuredContent goal_ffffffffffff/, undefined],
    // Both forms name one goal and differ elsewhere: that goal is the orphan.
    ['forms that disagree on another field', { ...P6, skew: { create_goal: { fields: { project_id: 'aos/elsewhere' }, where: 'structured' } } }, /both name goal_000000000001 and disagree on a field other than goal_id/, ONE],
    // A field the kernel never read, which the SDK's validator admits.
    ['a result it does not read', { ...P6, skew: { create_goal: { fields: { created_at: '2026-10-19T00:00:00Z' } } } }, /not a P6 goal result \(it names goal_000000000001\)/, ONE],
    // The same, its structured id unconfirmed by the text: claim neither, name both.
    ['a result it does not read, naming another goal', { ...P6, skew: { create_goal: { fields: { goal_id: 'goal_ffffffffffff', created_at: 'x' }, where: 'structured' } } }, /not a P6 goal result \(the text names goal_000000000001, structuredContent goal_ffffffffffff\)/, undefined],
  ]
  for (const [why, options, reason, orphan] of cases) {
    const { store, mock, writer } = await wired(t, options)
    await assert.rejects(
      () => writer.materialise(plan(), PROJECT, 'run_1'),
      (e: unknown) => {
        assert.ok(e instanceof GoalWriteFailed, why)
        assert.match(e.message, reason, why)
        return true
      },
    )
    assert.equal(payloads(store, 'goal.created').length, 0, `${why}: a goal.created was written`)
    const orphans = payloads(store, 'goal.unconfirmed')
    assert.equal(orphans.length, 1, why)
    assert.equal(orphans[0]?.['projectId'], PROJECT)
    assert.equal(orphans[0]?.['tool'], 'create_goal')
    assert.match(String(orphans[0]?.['reason']), reason, why)
    // pmmcp did write it; the row names it wherever one id is certain.
    assert.equal(mock.state.goals.size, 1, why)
    assert.ok(mock.state.goals.has(ONE), why)
    assert.equal(orphans[0]?.['goalId'], orphan, why)
  }
})

test('a result the SDK refuses mid-tree is a GoalWriteFailed naming what was written, and the orphan is recorded', async (t) => {
  // The third create breaks its own outputSchema; the SDK client throws.
  const { store, mock, writer } = await wired(t, { ...P6, skew: { create_goal: { fields: { progress_pct: 'x' }, fromCall: 3 } } })
  await assert.rejects(
    () => writer.materialise(plan(), PROJECT, 'run_1'),
    (e: unknown) => {
      assert.ok(e instanceof GoalWriteFailed, `escaped as ${String(e)}`)
      assert.equal(e.written.length, 2)
      return true
    },
  )
  assert.equal(mock.state.goals.size, 3, 'pmmcp wrote the third goal before the client refused its reply')
  assert.equal(payloads(store, 'goal.created').length, 2)
  assert.equal(payloads(store, 'goal.unconfirmed').length, 1)
})

test('a refused move names the goal the kernel asked to move, and any other id pmmcp named is in the reason', async (t) => {
  // [why, update_goal skew, refusal]: the SDK refusing the reply, and the strict
  // parse refusing a reply that also names another goal.
  const cases: [string, Record<string, unknown>, RegExp][] = [
    ['the SDK refuses the reply', { progress_pct: 'x' }, /output schema/],
    ['a result it does not read', { goal_id: 'goal_ffffffffffff', created_at: 'x' }, /not a P6 goal result \(it names goal_ffffffffffff\)/],
    // A parser message past the record's bound: the ids lead, so the cut takes only its tail.
    [
      'a refusal longer than the record',
      { goal_id: 'goal_ffffffffffff', ...Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`unread_field_${String(i).padStart(2, '0')}`, 'x'])) },
      /^update_goal returned structuredContent that is not a P6 goal result \(it names goal_ffffffffffff\): .*…$/s,
    ],
  ]
  for (const [why, fields, reason] of cases) {
    const { store, writer } = await wired(t, { ...P6, skew: { update_goal: { fields } } })
    const { task } = await written(writer)
    await assert.rejects(() => writer.setStatus(task, 'in_progress', { projectId: PROJECT }), GoalWriteFailed, why)
    const orphans = payloads(store, 'goal.unconfirmed')
    assert.equal(orphans.length, 1, why)
    assert.equal(orphans[0]?.['tool'], 'update_goal', why)
    assert.equal(orphans[0]?.['goalId'], task, `${why}: the row does not name the goal that may have moved`)
    assert.match(String(orphans[0]?.['reason']), reason, why)
  }
})

test('what pmmcp says in a refused create reaches goal.unconfirmed redacted, whole and well-formed, and the refusal stays a GoalWriteFailed', async (t) => {
  // Fabricated, as everywhere in the tests.
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${'Q'.repeat(1_000)}\n-----END RSA PRIVATE KEY-----`
  // The reason is "pmmcp reports it in <project_id>, not aos/ceo": 20 units of
  // preamble put this emoji's high surrogate at unit 499, where a 500 cut halves it.
  const split = `${'x'.repeat(479)}\u{1F600}tail`
  const cases: [string, string][] = [
    ['a credential across the cut', pem],
    ['an astral character across the cut', split],
    ['a lone surrogate', 'proj\ud800x'],
  ]
  for (const [why, project] of cases) {
    const { store, mock, writer } = await wired(t, { ...P6, skew: { create_goal: { fields: { project_id: project } } } })
    await assert.rejects(
      () => writer.materialise(plan(), PROJECT, 'run_1'),
      (e: unknown) => {
        assert.ok(e instanceof GoalWriteFailed, `${why}: escaped as ${String(e)}`)
        assert.ok(!e.message.includes('QQQQ'), `${why}: the refusal carries the key`)
        return true
      },
    )
    assert.equal(mock.state.goals.size, 1, why)
    const orphans = payloads(store, 'goal.unconfirmed')
    assert.equal(orphans.length, 1, `${why}: the orphan went unrecorded`)
    const reason = String(orphans[0]?.['reason'])
    assert.ok(!reason.includes('QQQQ'), `${why}: the key body is in the log`)
    assert.match(reason, /^pmmcp reports it in /, why)
    assert.ok(Buffer.byteLength(reason, 'utf8') <= 500, why)
    assert.equal(orphans[0]?.['goalId'], 'goal_000000000001', why)
    assert.equal(store.verifyChain().ok, true, why)
  }
})

test('a goal.unconfirmed the store will not take still leaves the refusal a GoalWriteFailed', async (t) => {
  const store = refusing(t, 'goal.unconfirmed')
  const { writer } = await wired(t, { ...P6, skew: { create_goal: { fields: { project_id: 'aos/elsewhere' } } } }, store)
  await assert.rejects(
    () => writer.materialise(plan(), PROJECT, 'run_1'),
    (e: unknown) => {
      assert.ok(e instanceof GoalWriteFailed, `escaped as ${String(e)}`)
      assert.match(e.message, /pmmcp reports it in aos\/elsewhere/)
      return true
    },
  )
})

test('a goal id pmmcp gave that no record holds verbatim is an orphan with a record, never a goal.created', async (t) => {
  // Fabricated, as everywhere in the tests: shaped like a key, so the log masks it.
  const cases: [string, string][] = [
    ['a lone surrogate', 'goal_\ud800'],
    ['an id shaped like a credential', 'sk-ant-abcdefgh1234'],
    ['an id past 128 bytes in fewer than 128 units', `goal_${'é'.repeat(100)}`],
  ]
  for (const [why, id] of cases) {
    const { store, mock, writer } = await wired(t, { ...P6, skew: { create_goal: { fields: { goal_id: id } } } })
    await assert.rejects(
      () => writer.materialise(plan(), PROJECT, 'run_1'),
      (e: unknown) => {
        assert.ok(e instanceof GoalWriteFailed, `${why}: escaped as ${String(e)}`)
        return true
      },
    )
    assert.equal(mock.state.goals.size, 1, why)
    assert.equal(payloads(store, 'goal.created').length, 0, `${why}: a goal.created names a goal that is not pmmcp's`)
    const orphans = payloads(store, 'goal.unconfirmed')
    assert.equal(orphans.length, 1, why)
    assert.equal(orphans[0]?.['goalId'], undefined, why)
    assert.match(String(orphans[0]?.['reason']), /goal id is not recordable verbatim/, why)
  }
})

test('a typed goal id longer than any record holds is refused, and the orphan is recorded without a cut id', async (t) => {
  const long = `goal_${'f'.repeat(200)}`
  const { store, writer } = await wired(t, { ...P6, skew: { create_goal: { fields: { goal_id: long } } } })
  await assert.rejects(() => writer.materialise(plan(), PROJECT, 'run_1'), GoalWriteFailed)
  assert.equal(payloads(store, 'goal.created').length, 0)
  const orphans = payloads(store, 'goal.unconfirmed')
  assert.equal(orphans.length, 1)
  assert.equal(orphans[0]?.['goalId'], undefined, 'a cut id names some other goal')
  assert.match(String(orphans[0]?.['reason']), /^pmmcp's goal id is not recordable verbatim; .*not a P6 goal result/s)
})

test("a move is confirmed from structuredContent: P6's JSON-only reply is a move, and a reply naming another status, goal or project, or a review below 100 %, is not recorded", async (t) => {
  const { store, writer } = await wired(t, P6)
  const { task } = await written(writer)
  await writer.setStatus(task, 'in_progress', { projectId: PROJECT })
  await writer.setStatus(task, 'review', { projectId: PROJECT })
  assert.deepEqual(payloads(store, 'goal.status').map((p) => p['to']), ['in_progress', 'review'])
  assert.equal(payloads(store, 'goal.unconfirmed').length, 0)

  // Each skew bends both forms alike, so only the field check under test can refuse.
  const cases: [string, Record<string, unknown>, number, 'in_progress' | 'review', RegExp][] = [
    ['another status', { status: 'blocked' }, 1, 'in_progress', /pmmcp reports status blocked/],
    ['another goal', { goal_id: 'goal_ffffffffffff' }, 1, 'in_progress', /pmmcp reports goal_id goal_ffffffffffff/],
    ['another project', { project_id: 'aos/elsewhere' }, 1, 'in_progress', /pmmcp reports project_id aos\/elsewhere/],
    ['a review below 100 %', { progress_pct: 50 }, 2, 'review', /pmmcp reports progress_pct 50/],
    // A long project is quoted bounded, so what follows it still reaches the record.
    ['a review below 100 % in a long project', { project_id: 'x'.repeat(600), progress_pct: 50 }, 2, 'review', /project_id x+…, progress_pct 50$/],
  ]
  for (const [why, fields, fromCall, to, reason] of cases) {
    const w = await wired(t, { ...P6, skew: { update_goal: { fields, fromCall } } })
    const target = (await written(w.writer)).task
    if (to === 'review') await w.writer.setStatus(target, 'in_progress', { projectId: PROJECT })
    const before = payloads(w.store, 'goal.status').length
    await assert.rejects(
      () => w.writer.setStatus(target, to, { projectId: PROJECT }),
      (e: unknown) => {
        assert.ok(e instanceof GoalWriteFailed, why)
        assert.match(e.message, reason, why)
        return true
      },
    )
    assert.equal(payloads(w.store, 'goal.status').length, before, `${why}: the move was recorded`)
    const orphans = payloads(w.store, 'goal.unconfirmed')
    assert.equal(orphans.length, 1, why)
    assert.equal(orphans[0]?.['goalId'], target, why)
    assert.match(String(orphans[0]?.['reason']), reason, `${why}: the record lost what the refusal said`)
  }
})

test('with P5 refusals a refused move is isError, a failure with no orphan, and trySetStatus keeps the run alive', async (t) => {
  const { store, mock, writer } = await wired(t, P6)
  const { task } = await written(writer)
  const goal = mock.state.goals.get(task)
  assert.ok(goal)
  goal.status = 'abandoned'
  await assert.rejects(() => writer.setStatus(task, 'in_progress', { projectId: PROJECT }), /invalid_transition/)
  assert.equal(await writer.trySetStatus(task, 'in_progress', { projectId: PROJECT }), false)
  assert.equal(payloads(store, 'goal.status').length, 0)
  assert.equal(payloads(store, 'goal.unconfirmed').length, 0, 'pmmcp refused, so nothing was written to orphan')
})

test("a live goal tool whose outputSchema the writer cannot read degrades goals at boot, by name; no schema, FastMCP's {result} and the P6 schema all serve", async (t) => {
  const goals = shippedConfig().goals
  for (const options of [{}, { outputs: { create_goal: 'wrapped', update_goal: 'wrapped' } }, P6] as const) {
    const { hub } = await wired(t, options)
    assert.equal(goalToolsUnusable(hub, goals), undefined, JSON.stringify(options))
  }
  const withProps = (extra: Record<string, unknown>, required?: string[]): Record<string, unknown> => ({
    ...GOAL_RESULT_OUTPUT,
    properties: { ...(GOAL_RESULT_OUTPUT['properties'] as Record<string, unknown>), ...extra },
    ...(required === undefined ? {} : { required }),
  })
  const cases: [string, Record<string, Record<string, unknown>>, RegExp][] = [
    ['a field it does not read', { create_goal: withProps({ created_at: { type: 'string' } }) }, /pmmcp\.create_goal returns created_at, which the kernel's P6 result does not read/],
    ['a field pmmcp may leave out', { update_goal: withProps({}, ['goal_id', 'project_id', 'status']) }, /pmmcp\.update_goal may leave out progress_pct/],
    ['a status enum without what the kernel sends', { update_goal: withProps({ status: { type: 'string', enum: ['pending', 'active', 'blocked'] } }) }, /leaves out in_progress/],
    ['a shape that is not a goal result', { create_goal: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] } }, /pmmcp\.create_goal returns ok, which the kernel's P6 result does not read/],
    // The SDK demands a required name whether or not it is declared.
    ['a required field it does not declare', { create_goal: withProps({}, ['goal_id', 'progress_pct', 'project_id', 'status', 'created_at']) }, /pmmcp\.create_goal requires created_at, which the kernel's P6 result does not read/],
    // pydantic's Literal is a const: an enum of one.
    ['a status Literal without what the kernel sends', { update_goal: withProps({ status: { type: 'string', const: 'pending' } }) }, /pmmcp\.update_goal returns status from pending, which leaves out in_progress/],
    // Not a member of the kernel's field table, whatever Object.prototype says.
    // FastMCP's wrapper sends {result} and nothing else.
    ['a {result} wrapper that requires more', { create_goal: { type: 'object', properties: { result: { type: 'string' } }, required: ['result', 'created_at'] } }, /pmmcp\.create_goal requires created_at beside FastMCP's \{result\}/],
    ['a field named like a prototype member', { create_goal: withProps({ constructor: { type: 'string' } }) }, /pmmcp\.create_goal returns constructor, which the kernel's P6 result does not read/],
  ]
  for (const [why, outputSchemas, reason] of cases) {
    const { hub } = await wired(t, { outputSchemas })
    assert.match(String(goalToolsUnusable(hub, goals)), reason, why)
  }
})

test('a pmmcp redeployed under a running kernel is re-checked when the hub re-lists it, and the writer only ever degrades', async (t) => {
  const { store, hub, writer } = await wired(t)
  const unwatch = watchGoalTools({ store, hub, goals: shippedConfig().goals, writer })
  t.after(unwatch)
  assert.equal(writer.available, true)

  // The redeployed server returns a field the writer does not read.
  const redeployed = pmmcpMock({
    outputSchemas: {
      create_goal: { ...GOAL_RESULT_OUTPUT, properties: { ...(GOAL_RESULT_OUTPUT['properties'] as Record<string, unknown>), created_at: { type: 'string' } } },
    },
  })
  t.after(async () => {
    await redeployed.close()
  })
  await hub.connect('pmmcp', redeployed.connect)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(writer.available, false)
  assert.match(String(writer.degradedReason), /returns created_at/)
  const degraded = payloads(store, 'goals.degraded')
  assert.equal(degraded.length, 1)
  await assert.rejects(() => writer.materialise(plan(), PROJECT, 'run_1'), GoalsUnavailable)

  // A good server again does not restore it: no event says goals came back.
  const good = pmmcpMock()
  t.after(async () => {
    await good.close()
  })
  await hub.connect('pmmcp', good.connect)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(writer.available, false)

  // Nor does a writer already off record each later drift again.
  const again = pmmcpMock({ outputSchemas: { update_goal: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] } } })
  t.after(async () => {
    await again.close()
  })
  await hub.connect('pmmcp', again.connect)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(payloads(store, 'goals.degraded').length, 1, 'a writer already degraded recorded another degradation')
  assert.match(String(writer.degradedReason), /returns created_at/, 'the first reason is the one that stands')
})

test('a reconnected pmmcp whose drift fills the reason past any payload, or with a lone surrogate, degrades with one bounded record and ends nothing', async (t) => {
  const P = GOAL_RESULT_OUTPUT['properties'] as Record<string, unknown>
  const many = Object.fromEntries(Array.from({ length: 900 }, (_, i) => [`created_${String(i).padStart(4, '0')}_${'n'.repeat(80)}`, { type: 'string' }]))
  const cases: [string, Record<string, Record<string, unknown>>][] = [
    ['900 fields it does not read', { create_goal: { ...GOAL_RESULT_OUTPUT, properties: { ...P, ...many } } }],
    ['a status enum value with a lone surrogate', { update_goal: { ...GOAL_RESULT_OUTPUT, properties: { ...P, status: { type: 'string', enum: ['pending', 'x\ud800'] } } } }],
  ]
  // A throw out of the re-check's microtask would be uncaught, and in the daemon
  // nothing catches one: it would end the process.
  const uncaught: unknown[] = []
  const onUncaught = (e: unknown): void => {
    uncaught.push(e)
  }
  const listeners = process.listeners('uncaughtException')
  process.removeAllListeners('uncaughtException')
  process.on('uncaughtException', onUncaught)
  t.after(() => {
    process.removeListener('uncaughtException', onUncaught)
    for (const l of listeners) process.on('uncaughtException', l)
  })
  for (const [why, outputSchemas] of cases) {
    const { store, hub, writer } = await wired(t)
    const unwatch = watchGoalTools({ store, hub, goals: shippedConfig().goals, writer })
    t.after(unwatch)
    const redeployed = pmmcpMock({ outputSchemas })
    t.after(async () => {
      await redeployed.close()
    })
    await hub.connect('pmmcp', redeployed.connect)
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(uncaught, [], why)
    assert.equal(writer.available, false, why)
    const degraded = payloads(store, 'goals.degraded')
    assert.equal(degraded.length, 1, `${why}: the degradation went unrecorded`)
    assert.ok(Buffer.byteLength(String(degraded[0]?.['reason']), 'utf8') <= GOALS_REASON_BYTES + 200, why)
    assert.equal(store.verifyChain().ok, true, why)
  }

  // A store that will not take the record: still no throw out of the microtask,
  // and the writer is degraded for the drift itself, not for the lost row.
  const store = refusing(t, 'goals.degraded')
  const { hub, writer } = await wired(t, {}, store)
  t.after(watchGoalTools({ store, hub, goals: shippedConfig().goals, writer }))
  const redeployed = pmmcpMock({ outputSchemas: { create_goal: { ...GOAL_RESULT_OUTPUT, properties: { ...P, created_at: { type: 'string' } } } } })
  t.after(async () => {
    await redeployed.close()
  })
  await hub.connect('pmmcp', redeployed.connect)
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(uncaught, [], 'a store that refused the record ended the process')
  assert.match(String(writer.degradedReason), /returns created_at/)
})

test("FastMCP's {result} wrapper reads as the prose it wraps", async (t) => {
  const { store, writer } = await wired(t, { outputs: { create_goal: 'wrapped', update_goal: 'wrapped' } })
  const tree = await writer.materialise(plan(), PROJECT, 'run_1')
  await writer.setStatus(String(tree.tasks.get('t1')), 'in_progress', { projectId: PROJECT })
  assert.equal(payloads(store, 'goal.created').length, 4)
  assert.equal(payloads(store, 'goal.status').length, 1)
  assert.equal(payloads(store, 'goal.unconfirmed').length, 0)
})

test('a FastMCP {result} that says something its text does not is refused and recorded, not read as prose', async (t) => {
  const { store, mock, writer } = await wired(t, {
    outputs: { create_goal: 'wrapped', update_goal: 'wrapped' },
    skew: { create_goal: { fields: { result: '✅ Goal created: goal_ffffffffffff' }, where: 'structured' } },
  })
  await assert.rejects(
    () => writer.materialise(plan(), PROJECT, 'run_1'),
    (e: unknown) => {
      assert.ok(e instanceof GoalWriteFailed, `escaped as ${String(e)}`)
      assert.match(e.message, /the text and structuredContent of create_goal disagree/)
      return true
    },
  )
  assert.equal(mock.state.goals.size, 1)
  assert.equal(payloads(store, 'goal.created').length, 0)
  const orphans = payloads(store, 'goal.unconfirmed')
  assert.equal(orphans.length, 1)
  assert.equal(orphans[0]?.['goalId'], undefined)
  assert.match(String(orphans[0]?.['reason']), /disagree: the text names goal_000000000001, structuredContent goal_ffffffffffff/)

  // A {result} that names the same goal and differs elsewhere: that goal is the orphan.
  const same = await wired(t, {
    outputs: { create_goal: 'wrapped', update_goal: 'wrapped' },
    skew: { create_goal: { fields: { result: '✅ Goal created: goal_000000000001' }, where: 'structured' } },
  })
  await assert.rejects(() => same.writer.materialise(plan(), PROJECT, 'run_1'), GoalWriteFailed)
  const named = payloads(same.store, 'goal.unconfirmed')
  assert.equal(named.length, 1)
  assert.equal(named[0]?.['goalId'], 'goal_000000000001')
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

test('every goal call goes through its typed wrapper: create carries project_id, update never does, and a status that is a decision never reaches pmmcp', async (t) => {
  const { store, hub, mock, writer } = await wired(t)
  const { task } = await written(writer)
  const creates = mock.calls.filter((c) => c.tool === 'create_goal')
  assert.equal(creates.length, 4)
  for (const c of creates) {
    assert.equal(c.args['project_id'], PROJECT)
    for (const key of Object.keys(c.args)) {
      assert.ok(['project_id', 'goal_type', 'title', 'parent_goal_id'].includes(key), `create_goal was sent ${key}`)
    }
  }
  // An objective has no parent key at all: neither null nor ''.
  assert.equal(creates.filter((c) => 'parent_goal_id' in c.args).length, 3)

  // kernel.yaml maps review onto a decision. The wrapper refuses it before the
  // wire; the writer before the wrappers sent `completed` to pmmcp.
  const goals = shippedConfig().goals
  const closing = new GoalWriter({ store, hub, goals: { ...goals, statuses: { ...goals.statuses, review: 'completed' } } })
  const before = mock.calls.length
  await assert.rejects(
    () => closing.setStatus(task, 'review', { projectId: PROJECT }),
    (e: unknown) => {
      assert.ok(e instanceof GoalWriteFailed)
      assert.match(e.message, /^pmmcp\.update_goal refused before the wire/)
      return true
    },
  )
  assert.equal(mock.calls.length, before, 'an unsendable status reached the server')
  assert.notEqual(mock.state.goals.get(task)?.status, 'completed')
  assert.equal(payloads(store, 'goal.status').length, 0)
})

test('the typed goal calls refuse what the kernel must never send, and put the configured names on the wire', async (t) => {
  const { hub, mock } = await wired(t)
  const goals = shippedConfig().goals
  const c = { hub, goals, serverId: 'pmmcp' }
  const before = mock.calls.length
  for (const attempt of [
    () => updateGoal(c, { goal_id: 'g', status: 'blocked', project_id: PROJECT } as never, 'test'),
    () => createGoal(c, { goal_type: 'objective', title: 't' } as never, 'test'),
    () => createGoal(c, { project_id: PROJECT, goal_type: 'objective', title: 't', parent_goal_id: null } as never, 'test'),
    () => getGoalTree(c, { goal_id: '' }, 'test'),
  ]) {
    await assert.rejects(attempt, GoalWriteFailed)
  }
  assert.equal(mock.calls.length, before, 'a refused call reached the server')

  const seeded = mock.seedTree(PROJECT)
  const tree = await getGoalTree(c, { goal_id: seeded.objective }, 'test')
  assert.equal(tree.ok, true)
  assert.deepEqual(mock.calls.at(-1)?.args, { goal_id: seeded.objective })

  // The schemas speak pmmcp's names; kernel.yaml still names the keys sent.
  const renamed = { ...c, goals: { ...goals, args: { ...goals.args, goalId: 'id' } } }
  await getGoalTree(renamed, { goal_id: seeded.objective }, 'test')
  assert.deepEqual(mock.calls.at(-1)?.args, { id: seeded.objective })
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
