// The plan parser: what it accepts and, mostly, what it refuses.
//
// This parse is the only thing between a model's structure-shaped text and a
// durable goal tree in the operator's long-term memory. Every test here is a
// refusal that has to happen, because the failures are quiet: a dangling
// dependency is a fan-out that never completes, a cycle is a DAG the kernel
// advances forever, and a duplicate id makes the tree ambiguous to address the
// moment anything tries to update a status.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  assertPlanCoherent,
  extractJson,
  looksLikePlan,
  parsePlan,
  PlanInvalid,
  ProposedPlan,
  tasksOf,
} from '../src/goals/plan.js'

/** A minimal plan that must parse, as the baseline every refusal deviates from. */
function good(): Record<string, unknown> {
  return {
    objective: { title: 'compare two log storage options', successCriteria: ['both written up'] },
    milestones: [
      {
        id: 'm1',
        title: 'research',
        tasks: [
          {
            id: 't1',
            title: 'write up sqlite',
            template: 'researcher',
            acceptance: ['a file exists at docs/sqlite.md'],
          },
          {
            id: 't2',
            title: 'write up append-only log',
            template: 'researcher',
            dependsOn: [],
            acceptance: ['a file exists at docs/append.md'],
          },
        ],
      },
    ],
  }
}

const wrap = (plan: unknown): string =>
  `Here is my plan.\n\n\`\`\`json\n${JSON.stringify(plan, null, 2)}\n\`\`\`\n\nI will now delegate.`

test('a well-formed plan parses, and defaults fill in', () => {
  const plan = parsePlan(wrap(good()))
  assert.equal(plan.objective.title, 'compare two log storage options')
  assert.equal(plan.milestones.length, 1)
  assert.deepEqual(plan.assumptions, [])
  assert.deepEqual(plan.risks, [])
  assert.deepEqual(plan.questionsForOperator, [])
  // dependsOn and irreversible default to empty rather than undefined, so every
  // consumer reads an array and none has to handle both shapes.
  assert.deepEqual(plan.milestones[0]?.tasks[0]?.dependsOn, [])
  assert.deepEqual(plan.milestones[0]?.tasks[0]?.irreversible, [])
  assert.equal(tasksOf(plan).length, 2)
  assert.deepEqual(
    tasksOf(plan).map((t) => `${t.milestoneId}/${t.task.id}`),
    ['m1/t1', 'm1/t2'],
  )
})

test('a task with no acceptance check is refused', () => {
  // The decomposition rubric: one task, one owned artifact, one acceptance check.
  // Without one, completion is whatever the worker says it is.
  const plan = good()
  const milestones = plan['milestones'] as { tasks: Record<string, unknown>[] }[]
  milestones[0]!.tasks[0]!['acceptance'] = []
  assert.throws(() => parsePlan(wrap(plan)), (e: unknown) => {
    assert.ok(e instanceof PlanInvalid)
    assert.match(e.message, /acceptance/)
    return true
  })
})

test('a duplicate id is refused, across both levels of the tree', () => {
  const plan = good()
  const milestones = plan['milestones'] as { id: string; tasks: { id: string }[] }[]
  milestones[0]!.tasks[1]!.id = 't1'
  assert.throws(() => parsePlan(wrap(plan)), /duplicate id t1/)

  // And a milestone colliding with a task, which a per-level check would miss.
  const collide = good()
  const ms = collide['milestones'] as { id: string; tasks: { id: string }[] }[]
  ms[0]!.id = 't2'
  assert.throws(() => parsePlan(wrap(collide)), /duplicate id t2/)
})

test('a dependency on a task that is not in the plan is refused', () => {
  const plan = good()
  const milestones = plan['milestones'] as { tasks: Record<string, unknown>[] }[]
  milestones[0]!.tasks[0]!['dependsOn'] = ['t9']
  assert.throws(() => parsePlan(wrap(plan)), /t1 depends on t9, which is not a task in this plan/)
})

test('a self-dependency and a cycle are both refused, and the cycle is named', () => {
  const selfDep = good()
  const a = selfDep['milestones'] as { tasks: Record<string, unknown>[] }[]
  a[0]!.tasks[0]!['dependsOn'] = ['t1']
  assert.throws(() => parsePlan(wrap(selfDep)), /t1 depends on itself/)

  // A two-step cycle, reported as the path that closes it: "there is a cycle" is
  // not something an operator can act on.
  const cyclic = good()
  const b = cyclic['milestones'] as { tasks: Record<string, unknown>[] }[]
  b[0]!.tasks[0]!['dependsOn'] = ['t2']
  b[0]!.tasks[1]!['dependsOn'] = ['t1']
  assert.throws(() => parsePlan(wrap(cyclic)), (e: unknown) => {
    assert.ok(e instanceof PlanInvalid)
    assert.match(e.message, /cycle/)
    assert.match(e.message, /t1 → t2 → t1|t2 → t1 → t2/)
    return true
  })
})

test('a longer cycle is found, not just a two-step one', () => {
  const plan = ProposedPlan.parse({
    objective: { title: 'o', successCriteria: ['c'] },
    milestones: [
      {
        id: 'm1',
        title: 'm',
        tasks: [
          { id: 'a', title: 'a', template: 'x', acceptance: ['c'], dependsOn: ['c'] },
          { id: 'b', title: 'b', template: 'x', acceptance: ['c'], dependsOn: ['a'] },
          { id: 'c', title: 'c', template: 'x', acceptance: ['c'], dependsOn: ['b'] },
        ],
      },
    ],
  })
  assert.throws(() => assertPlanCoherent(plan, []), /cycle/)
})

test('a task naming an unregistered template is refused when templates are known', () => {
  // A task whose template does not exist is a task nothing can ever run, and the
  // failure would otherwise surface as a spawn refusal much later.
  assert.throws(
    () => parsePlan(wrap(good()), { knownTemplates: ['writer'] }),
    /t1 names template researcher, which is not a registered agent or template/,
  )
  // With the template present it parses.
  const plan = parsePlan(wrap(good()), { knownTemplates: ['researcher', 'writer'] })
  assert.equal(plan.milestones[0]?.tasks.length, 2)
})

test('an unexpected key is refused rather than dropped', () => {
  // `.strict()` everywhere on purpose: a model inventing a field means it thought
  // something mattered, and silently discarding it is worse than refusing.
  const plan = good()
  plan['budget'] = 1_000
  assert.throws(() => parsePlan(wrap(plan)), (e: unknown) => {
    assert.ok(e instanceof PlanInvalid)
    assert.match(e.message, /budget|unrecognized/i)
    return true
  })
})

test('more than three operator questions is refused', () => {
  const plan = good()
  plan['questionsForOperator'] = ['a', 'b', 'c', 'd']
  assert.throws(() => parsePlan(wrap(plan)), /questionsForOperator/)
})

test('a plan with no milestones, or a milestone with no tasks, is refused', () => {
  const empty = good()
  empty['milestones'] = []
  assert.throws(() => parsePlan(wrap(empty)), /milestones/)

  const noTasks = good()
  ;(noTasks['milestones'] as { tasks: unknown[] }[])[0]!.tasks = []
  assert.throws(() => parsePlan(wrap(noTasks)), /tasks/)
})

test('extractJson finds a fenced block, a bare object, and gives up honestly', () => {
  assert.equal(extractJson('```json\n{"a":1}\n```'), '{"a":1}')
  assert.equal(extractJson('```\n{"a":1}\n```'), '{"a":1}')
  assert.equal(extractJson('prose {"a":{"b":2}} more prose'), '{"a":{"b":2}}')
  // A brace inside a string must not close the object early.
  assert.equal(extractJson('{"a":"}"}'), '{"a":"}"}')
  // An escaped quote must not flip the string state.
  assert.equal(extractJson('{"a":"x\\"}y"}'), '{"a":"x\\"}y"}')
  assert.equal(extractJson('no object here'), undefined)
  assert.equal(extractJson('{"unclosed": 1'), undefined)
})

test('a message with no JSON, or unparseable JSON, is refused with the reason', () => {
  assert.throws(() => parsePlan('I will just do it myself.'), /contains no JSON object/)
  assert.throws(() => parsePlan('```json\n{not json}\n```'), /does not parse/)
})

test('looksLikePlan distinguishes an attempted plan from any other JSON', () => {
  // Used to decide whether to try parsing at all, so a false positive means a
  // refusal logged for a message that was never a plan.
  assert.equal(looksLikePlan(wrap(good())), true)
  assert.equal(looksLikePlan('```json\n{"answer": 42}\n```'), false)
  assert.equal(looksLikePlan('no json at all'), false)
})
