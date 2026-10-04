// The Phase 1 runtime checks, written once and run against two targets.
//
// A live test that only runs when someone remembers to set AOS_LIVE_TESTS=1 is a
// test whose assertions nobody has seen fail. The Phase 0 live file already has
// two of those. So every check here is a BODY — a function that takes whatever
// it runs against — and it is called twice:
//
//   test/runtime-bodies.test.ts   every `npm test`, against the pmmcp double and
//                                 a scripted provider. Proves the assertions.
//   test/live-runtime.test.ts     gated, against the operator's pmmcp and the real
//                                 model. Proves the wiring and the guesses.
//
// What a live run of these settles, that nothing offline can:
//
//   goalTreeRoundTrip — the MODELLED goal tool names and arguments in
//     config/kernel.yaml, against the server that actually exists. The first
//     assertion is the boot check itself, so a wrong guess fails naming the tool.
//   planToTree — whether a real model's plan survives the `.strict()` parser.
//     Models emit extra keys, trailing prose and near-miss shapes; a parser that
//     refuses all of them would make plan adoption dead on arrival, and the
//     failure message here carries the parser's own reason.
//   evalHarnessAssumptions — whether the eval harness's own gates hold against a
//     REAL provider's accounting. If cost does not reconcile with the logged calls
//     on a live response (cache tokens, retries), the harness is miscalibrated and
//     every score it produces is suspect.
//
// None of this writes to `aos/ceo`. The goal-writing bodies take a project id and
// the live file passes `aos/agent/aos-live-test`, which is the whole of what a
// live run leaves in the operator's memory.

import './guard.js'

import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import type { EventStore } from '../../src/events/store.js'
import { CEO_CHECKS } from '../../src/eval/checks.js'
import { runCase, type EvalTarget } from '../../src/eval/harness.js'
import { claimsOf, readRunRows } from '../../src/eval/observe.js'
import { CEO_SUITE } from '../../src/eval/suite.js'
import type { CaseResult } from '../../src/eval/types.js'
import { parsePlan, PlanInvalid } from '../../src/goals/plan.js'
import { goalToolsUnusable, type GoalsConfig } from '../../src/goals/tools.js'
import { GoalWriter } from '../../src/goals/writer.js'
import type { McpHub } from '../../src/mcp/hub.js'
import { REPO_ROOT, rows } from './kernel.js'

/** The only namespace a live runtime test writes to. */
export const LIVE_TEST_PROJECT = 'aos/agent/aos-live-test'
/** The orchestrator the live fleet runs, whose memory is that namespace. */
export const LIVE_ORCHESTRATOR = 'live-ceo'

// ── fleet ──────────────────────────────────────────────────────────────────

/**
 * A fleet whose orchestrator writes into the test namespace.
 *
 * The real `ceo` manifest names `aos/ceo`, and a live plan adopted from it would
 * leave goals in the operator's own tree. So this copies the real researcher and
 * writer (the templates a plan names) and adds a `live-ceo` that is the shipped
 * CEO in every respect except where it remembers.
 */
export function liveFleet(dir: string, modelRef: string): string {
  const agents = join(dir, 'agents')
  for (const id of ['researcher', 'writer']) {
    mkdirSync(join(agents, id, 'history'), { recursive: true })
    writeFileSync(
      join(agents, id, 'agent.yaml'),
      readFileSync(join(REPO_ROOT, 'agents', id, 'agent.yaml'), 'utf8'),
    )
    writeFileSync(join(agents, id, 'AGENTS.md'), `# ${id}\n`)
  }
  mkdirSync(join(agents, LIVE_ORCHESTRATOR, 'history'), { recursive: true })
  writeFileSync(
    join(agents, LIVE_ORCHESTRATOR, 'agent.yaml'),
    `id: ${LIVE_ORCHESTRATOR}
version: 1
kind: standard
role: orchestrator
soul: ceo.md
tier: 2
model:
  primary: ${modelRef}
  fallbacks: []
tools:
  servers: [pmmcp]
  allow: []
memory:
  projectId: ${LIVE_TEST_PROJECT}
`,
  )
  writeFileSync(join(agents, LIVE_ORCHESTRATOR, 'AGENTS.md'), `# ${LIVE_ORCHESTRATOR}\n`)
  return agents
}

// ── plans ──────────────────────────────────────────────────────────────────

/**
 * An objective that asks for a plan in the kernel's schema, verbatim.
 *
 * Deliberately explicit. The CEO's soul does not teach the ProposedPlan shape —
 * that is the plan-phase item, not built yet — so a live test that hoped the model
 * would produce one unprompted would be measuring the soul, not the pipeline. This
 * measures the pipeline: real model, real parser, real server.
 */
export const PLAN_REQUEST = `Produce a plan for this objective and output ONLY a JSON object in a \`\`\`json fenced block, with no other keys than the ones shown.

Objective: compare two ways of storing an append-only event log — a SQLite table with triggers, and a flat append-only file with a separate index.

Required shape (every key shown is required unless marked optional; do not add keys):
\`\`\`json
{
  "objective": { "title": "<at most 200 chars>", "successCriteria": ["<at least one>"] },
  "milestones": [
    {
      "id": "m1",
      "title": "<at most 200 chars>",
      "tasks": [
        { "id": "t1", "title": "<at most 200 chars>", "template": "researcher", "acceptance": ["<how a machine can tell it is done>"], "dependsOn": [] },
        { "id": "t2", "title": "<at most 200 chars>", "template": "writer", "acceptance": ["<how a machine can tell it is done>"], "dependsOn": ["t1"] }
      ]
    }
  ],
  "assumptions": [],
  "risks": [],
  "questionsForOperator": []
}
\`\`\`

Use exactly one milestone with between two and four tasks. "template" must be "researcher" or "writer".`

/** A plan the offline double answers with, shaped exactly as PLAN_REQUEST asks. */
export const SCRIPTED_PLAN = `\`\`\`json
{
  "objective": { "title": "compare two append-only log stores", "successCriteria": ["both options written up and compared"] },
  "milestones": [
    {
      "id": "m1",
      "title": "research and write up",
      "tasks": [
        { "id": "t1", "title": "research sqlite with triggers", "template": "researcher", "acceptance": ["a findings note with sources exists"], "dependsOn": [] },
        { "id": "t2", "title": "write the comparison", "template": "writer", "acceptance": ["a comparison document cites both notes"], "dependsOn": ["t1"] }
      ]
    }
  ],
  "assumptions": [],
  "risks": [],
  "questionsForOperator": []
}
\`\`\``

const SMALL_PLAN = parsePlanOrThrow(SCRIPTED_PLAN)

function parsePlanOrThrow(text: string): ReturnType<typeof parsePlan> {
  return parsePlan(text, { knownTemplates: ['researcher', 'writer'] })
}

// ── bodies ─────────────────────────────────────────────────────────────────

export interface GoalTreeContext {
  readonly hub: McpHub
  readonly store: EventStore
  readonly goals: GoalsConfig
  readonly projectId: string
  readonly runId: string
}

/**
 * Write a tree, read it back through the server, move a task, refuse `done`.
 *
 * The read-back asks pmmcp for the objective's tree. pmmcp's listings carry
 * titles and status icons but NO ids (Goal.to_display), so the check is that
 * every title the kernel wrote comes back under the id the server handed out —
 * which fails for the one outcome that matters: an id the server does not know.
 */
export async function goalTreeRoundTrip(ctx: GoalTreeContext): Promise<void> {
  // The boot check, first. Against the live server this IS the test of the
  // configured names, and its reason names every tool and argument that disagrees.
  const unusable = goalToolsUnusable(ctx.hub, ctx.goals)
  assert.equal(unusable, undefined, `the configured goal tools do not match the server: ${String(unusable)}`)

  const writer = new GoalWriter({ store: ctx.store, hub: ctx.hub, goals: ctx.goals })
  const tree = await writer.materialise(SMALL_PLAN, ctx.projectId, ctx.runId)
  assert.equal(tree.milestones.size, 1)
  assert.equal(tree.tasks.size, 2)

  const a = ctx.goals.args
  const shown = await ctx.hub.callKernelOnly(
    'pmmcp',
    ctx.goals.tools.get,
    { [a.goalId]: tree.objectiveGoalId },
    'runtime test: read back the tree just written',
  )
  assert.equal(shown.ok, true, `reading the tree back failed: ${JSON.stringify(shown.content)}`)
  const text = JSON.stringify(shown.content)
  const titles = [
    SMALL_PLAN.objective.title,
    ...SMALL_PLAN.milestones.flatMap((m) => [m.title, ...m.tasks.map((t) => t.title)]),
  ]
  for (const title of titles) {
    assert.ok(text.includes(JSON.stringify(title).slice(1, -1)), `"${title}" is not in the tree the server returned`)
  }

  // A task moves the way a run would move it.
  const task = tree.tasks.get('t1')
  assert.ok(task)
  await writer.setStatus(task, 'in_progress', { projectId: ctx.projectId, runId: ctx.runId })
  await writer.setStatus(task, 'review', { projectId: ctx.projectId, runId: ctx.runId })

  // And the kernel still refuses to close it — before any call is made.
  await assert.rejects(
    () => writer.setStatus(task, 'done' as 'review', { projectId: ctx.projectId }),
    /a decision, not a transition/,
  )

  const created = ctx.store.query({ type: 'goal.created' })
  assert.equal(created.length, 4, 'objective + milestone + two tasks')
  assert.equal(ctx.store.query({ type: 'plan.adopted' }).length, 1)
  assert.deepEqual(
    ctx.store
      .query({ type: 'goal.status' })
      .map((r) => (JSON.parse(r.payload) as { to: string }).to),
    ['in_progress', 'review'],
  )
}

export interface PlanToTreeContext {
  readonly dbPath: string
  /** Starts the orchestrator on PLAN_REQUEST and resolves its run.finished. */
  readonly run: () => Promise<Record<string, unknown>>
  /** Shuts the kernel down, which drains the goal tracker. */
  readonly shutdown: () => Promise<void>
  readonly projectId: string
}

/**
 * A real orchestrator run whose plan becomes a tree in the given namespace.
 *
 * On failure it re-parses the model's own words and puts the parser's reason in
 * the message, because "no plan.adopted" alone tells the operator nothing about
 * whether the model, the parser or the server was at fault.
 */
export async function planToTree(ctx: PlanToTreeContext): Promise<{ tasks: number }> {
  const finished = await ctx.run()
  assert.equal(finished['status'], 'ok', String(finished['reason'] ?? ''))
  const runId = String(finished['runId'])
  await ctx.shutdown()

  const all = rows(ctx.dbPath)
  const adopted = all.filter((r) => r.type === 'plan.adopted')
  if (adopted.length !== 1) {
    const claims = claimsOf(readRunRows(ctx.dbPath, runId))
    let reason = 'the result parsed as a plan, so the refusal was downstream of the parser'
    try {
      parsePlanOrThrow(claims)
    } catch (e) {
      reason = e instanceof PlanInvalid ? e.message : String(e)
    }
    const degraded = all.filter((r) => r.type === 'goals.degraded').map((r) => r.payload)
    assert.fail(
      `no plan was adopted from ${runId}. Parser: ${reason}. ` +
        (degraded.length > 0 ? `goals.degraded: ${degraded.join('; ')}. ` : '') +
        `The model said:\n${claims.slice(0, 2_000)}`,
    )
  }

  const payload = JSON.parse(adopted[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(payload['projectId'], ctx.projectId, 'the tree was written somewhere other than the test namespace')
  assert.equal(payload['runId'], runId)
  const tasks = payload['tasks'] as number
  const milestones = payload['milestones'] as number
  assert.ok(tasks >= 2, `a plan with ${String(tasks)} task(s) is not an orchestration`)

  const created = all.filter((r) => r.type === 'goal.created').map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.equal(created.length, 1 + milestones + tasks, 'goal.created does not match what plan.adopted counts')
  for (const goal of created) {
    assert.equal(goal['projectId'], ctx.projectId)
  }
  return { tasks }
}

/**
 * One eval case against a real run, asserting the harness's OWN assumptions.
 *
 * Not "the case passes" — that is the model's business and the scorecard's job.
 * What must hold regardless of the model is that the gates the harness is built
 * on are calibrated against real accounting: a run ends once, every response has
 * a request, and the reported cost is the sum of the logged calls. If any of those
 * fails on a live provider, every score the harness has ever produced is suspect.
 */
export async function evalHarnessAssumptions(target: EvalTarget): Promise<CaseResult> {
  const small = CEO_SUITE.find((c) => c.id === 'ceo-inline-small-objective')
  assert.ok(small, 'the shipped suite lost its small case')
  const result = await runCase(target, small, CEO_CHECKS)
  const byId = new Map(result.checks.map((c) => [c.id, c]))
  for (const id of ['run-reached-terminal', 'llm-events-paired', 'cost-reconciles-with-log']) {
    const check = byId.get(id)
    assert.equal(check?.verdict, 'pass', `${id}: ${check?.detail ?? 'did not run'}`)
  }
  return result
}
