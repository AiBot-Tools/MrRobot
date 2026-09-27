// Delegation: an orchestrator adopts a plan, then hands its tasks to workers.
//
// Two kernel tools, both orchestrator-only and both gated as `write`:
//
//   kernel.adopt_plan({ plan })          validate a ProposedPlan and write the goal
//                                        tree NOW, returning task → goal ids
//   kernel.delegate({ taskId, brief })   run ONE task of that plan on the agent the
//                                        plan named, and return what came back
//
// Why two, and why in that order. Goal ancestry needs goal ids, and a plan found
// in a run's final message is only adopted after the run ends — too late for that
// run to hand ids to children. Adopting mid-run fixes that, and it lets delegation
// be expressed as "this task of the plan I adopted" rather than "this agent, this
// goal id": the model never supplies a goal id or picks an arbitrary target. The
// kernel resolves both from a plan it has already validated and written.
//
// WHAT THE KERNEL REFUSES, each logged as `delegation.refused` with the reason the
// model is told:
//
//   no plan adopted in this run, or a task that is not in it;
//   a task already delegated in this run (double dispatch, made impossible
//   rather than scored after the fact);
//   a task whose `dependsOn` has not finished well (the plan's DAG, enforced);
//   more children than the manifest's `spawn.maxChildren`;
//   a target that is not an active standard worker, or has a higher tier than the
//   caller (limits only narrow);
//   a caller that is itself a delegated child (depth 1, a kernel ceiling);
//   a parent with nothing left to give.
//
// MONEY. A child runs under a CEILING carved from what the parent has left, and
// its spend is charged to the parent when it finishes. Without the charge a $2
// parent could fund several $1.90 children; without the ceiling one child could
// spend the whole envelope before the parent noticed. `delegation.admitted` and
// `delegation.result` tie every child's spend to the parent that caused it.
//
// TAINT. A child that finished tainted returns a result that taints the parent:
// untrusted material does not become trusted by passing through another agent.

import type { AgentRegistry } from '../agents/registry.js'
import type { EventStore } from '../events/store.js'
import { parsePlan, PlanInvalid, tasksOf, type PlanTask, type ProposedPlan } from '../goals/plan.js'
import { GoalWriteFailed, GoalsUnavailable, type GoalWriter, type WrittenTree } from '../goals/writer.js'
import { log } from '../log.js'
import type { BudgetCaps } from './budget.js'
import type { KernelToolContext, KernelToolHandler, KernelToolResult } from './kernel-tools.js'
import type { RunOutcome } from './loop.js'

/** A child waits at most its own wallclock plus this, as a backstop. */
const WAIT_GRACE_MS = 5_000
/** Briefs are model-authored and become a child's whole prompt. Bounded. */
const BRIEF_MAX = 8_000

export interface LaunchInput {
  readonly agentId: string
  readonly input: string
  readonly goalId: string
  readonly ceiling: Partial<BudgetCaps>
}

export interface DelegationOptions {
  readonly store: EventStore
  readonly agents: AgentRegistry
  readonly writer: GoalWriter
  /** Start a child run and hand back its outcome. The kernel's run path, not a shortcut. */
  readonly launch: (input: LaunchInput) => { runId: string; outcome: Promise<RunOutcome> }
  readonly kill: (runId: string, reason: string) => void
}

interface AdoptedPlan {
  readonly plan: ProposedPlan
  readonly tree: WrittenTree
  readonly tasks: ReadonlyMap<string, PlanTask>
}

interface ChildRecord {
  readonly childRunId: string
  status?: RunOutcome['status']
}

interface RunState {
  adopted?: AdoptedPlan
  /** taskId → the child serving it. */
  readonly children: Map<string, ChildRecord>
}

export class Delegation {
  readonly #o: DelegationOptions
  readonly #runs = new Map<string, RunState>()
  /** Runs that are themselves delegated children: they may not delegate. */
  readonly #childRuns = new Set<string>()

  constructor(options: DelegationOptions) {
    this.#o = options
  }

  handlers(): KernelToolHandler[] {
    return [
      {
        name: 'adopt_plan',
        description:
          'Adopt a plan: the kernel validates it and writes it as your goal tree now, then returns ' +
          'each task id with its goal id. Call this once, before delegating any task.',
        inputSchema: {
          type: 'object',
          properties: {
            plan: {
              type: 'object',
              description:
                'A ProposedPlan: { objective: { title, successCriteria[] }, milestones: [{ id, title, ' +
                'tasks: [{ id, title, template, acceptance[], dependsOn[] }] }], assumptions[], risks[], ' +
                'questionsForOperator[] }. `template` must name a registered worker.',
            },
          },
          required: ['plan'],
        },
        run: (args, ctx) => this.#adoptPlan(args, ctx),
      },
      {
        name: 'delegate',
        description:
          'Run one task of your adopted plan on the worker the plan named. Waits for it to finish and ' +
          'returns its run id, status, cost and result. A task whose dependsOn has not finished well ' +
          'is refused.',
        inputSchema: {
          type: 'object',
          properties: {
            taskId: { type: 'string', description: 'A task id from the plan you adopted.' },
            brief: {
              type: 'string',
              description:
                'Everything the worker needs: it starts with no context but this and the task. ' +
                `At most ${String(BRIEF_MAX)} characters.`,
            },
          },
          required: ['taskId', 'brief'],
        },
        run: (args, ctx) => this.#delegate(args, ctx),
      },
    ]
  }

  /** Forget a finished run's state. Called by the kernel on run.finished. */
  forget(runId: string): void {
    this.#runs.delete(runId)
    this.#childRuns.delete(runId)
  }

  #state(runId: string): RunState {
    let state = this.#runs.get(runId)
    if (state === undefined) {
      state = { children: new Map() }
      this.#runs.set(runId, state)
    }
    return state
  }

  #refuse(parentRunId: string, reason: string, taskId?: string): KernelToolResult {
    this.#o.store.append({
      type: 'delegation.refused',
      runId: parentRunId,
      payload: {
        schemaVersion: 1,
        parentRunId,
        ...(taskId === undefined ? {} : { taskId: taskId.slice(0, 64) }),
        reason: reason.slice(0, 500),
      },
    })
    return { ok: false, text: `[refused] ${reason}` }
  }

  /** Agents a plan may name: active standard workers. */
  #delegable(): string[] {
    return this.#o.agents
      .list()
      .filter((r) => r.status === 'active' && r.manifest.kind === 'standard' && r.manifest.role === 'worker')
      .map((r) => r.manifest.id)
  }

  async #adoptPlan(args: Record<string, unknown>, ctx: KernelToolContext): Promise<KernelToolResult> {
    const { runId, agent } = ctx
    const state = this.#state(runId)
    if (state.adopted !== undefined) {
      return this.#refuse(runId, 'a plan was already adopted in this run; delegate its tasks')
    }
    if (agent.projectId === undefined) {
      return this.#refuse(runId, `${agent.agentId} has no memory namespace to write a goal tree into`)
    }
    const raw = args['plan']
    if (typeof raw !== 'object' || raw === null) {
      return this.#refuse(runId, 'plan must be an object')
    }

    let plan: ProposedPlan
    try {
      plan = parsePlan(JSON.stringify(raw), { knownTemplates: this.#delegable() })
    } catch (e) {
      if (e instanceof PlanInvalid) return this.#refuse(runId, e.message)
      throw e
    }

    let tree: WrittenTree
    try {
      tree = await this.#o.writer.materialise(plan, agent.projectId, runId)
    } catch (e) {
      if (e instanceof GoalsUnavailable || e instanceof GoalWriteFailed) {
        return this.#refuse(runId, e.message)
      }
      throw e
    }

    const tasks = new Map(tasksOf(plan).map(({ task }) => [task.id, task]))
    state.adopted = { plan, tree, tasks }
    return {
      ok: true,
      text: JSON.stringify({
        objectiveGoalId: tree.objectiveGoalId,
        tasks: [...tasks.values()].map((t) => ({
          taskId: t.id,
          goalId: tree.tasks.get(t.id),
          template: t.template,
          dependsOn: t.dependsOn,
        })),
      }),
    }
  }

  async #delegate(args: Record<string, unknown>, ctx: KernelToolContext): Promise<KernelToolResult> {
    const { runId, agent, budget } = ctx
    const taskId = typeof args['taskId'] === 'string' ? args['taskId'] : undefined
    const brief = typeof args['brief'] === 'string' ? args['brief'] : undefined
    if (taskId === undefined || taskId === '') return this.#refuse(runId, 'taskId is required')
    if (brief === undefined || brief.trim() === '') return this.#refuse(runId, 'brief is required', taskId)
    if (brief.length > BRIEF_MAX) {
      return this.#refuse(runId, `brief is ${String(brief.length)} characters; the limit is ${String(BRIEF_MAX)}`, taskId)
    }

    // Depth 1. A worker is never offered this tool, and the registry refuses it in
    // a worker's manifest; this is the third wall, keyed on the run rather than
    // the agent, so it holds whatever a manifest says.
    if (this.#childRuns.has(runId)) {
      return this.#refuse(runId, 'a delegated run may not delegate: depth is capped at 1', taskId)
    }

    const state = this.#state(runId)
    const adopted = state.adopted
    if (adopted === undefined) {
      return this.#refuse(runId, 'no plan adopted in this run: call kernel.adopt_plan first', taskId)
    }
    const task = adopted.tasks.get(taskId)
    const goalId = adopted.tree.tasks.get(taskId)
    if (task === undefined || goalId === undefined) {
      return this.#refuse(runId, `${taskId} is not a task in the adopted plan`, taskId)
    }
    if (state.children.has(taskId)) {
      return this.#refuse(runId, `${taskId} was already delegated in this run`, taskId)
    }
    for (const dep of task.dependsOn) {
      const done = state.children.get(dep)
      if (done?.status !== 'ok') {
        return this.#refuse(
          runId,
          `${taskId} depends on ${dep}, which has ${done === undefined ? 'not been delegated' : `finished ${done.status ?? 'no status yet'}`}`,
          taskId,
        )
      }
    }

    const record = this.#o.agents.get(agent.agentId)
    const maxChildren = record?.manifest.spawn?.maxChildren ?? 0
    if (state.children.size >= maxChildren) {
      return this.#refuse(runId, `${agent.agentId} may run at most ${String(maxChildren)} children per run`, taskId)
    }

    const target = this.#o.agents.get(task.template)
    if (
      target === undefined ||
      target.status !== 'active' ||
      target.manifest.kind !== 'standard' ||
      target.manifest.role !== 'worker'
    ) {
      return this.#refuse(runId, `${task.template} is not an active standard worker`, taskId)
    }
    if (target.manifest.tier > agent.tier) {
      return this.#refuse(
        runId,
        `${task.template} is tier ${String(target.manifest.tier)}, above the caller's tier ${String(agent.tier)}`,
        taskId,
      )
    }

    // The slice. Whole remaining micro-USD and wallclock, and the child's own caps
    // still apply beneath them — the intersection happens where the budget is built.
    const ceilingMicroUsd = budget.remainingMicroUsd()
    const ceilingWallclockMs = budget.remainingMs()
    if (ceilingMicroUsd < 1 || ceilingWallclockMs < 1) {
      return this.#refuse(runId, 'the parent run has no budget left to delegate with', taskId)
    }

    const input =
      `Task ${task.id}: ${task.title}\n\n` +
      `Done when:\n${task.acceptance.map((a) => `- ${a}`).join('\n')}\n\n` +
      `Brief:\n${brief}`

    const launched = this.#o.launch({
      agentId: target.manifest.id,
      input,
      goalId,
      ceiling: { usdMax: ceilingMicroUsd, wallclockMs: ceilingWallclockMs },
    })
    const child: ChildRecord = { childRunId: launched.runId }
    state.children.set(taskId, child)
    this.#childRuns.add(launched.runId)
    this.#o.store.append({
      type: 'delegation.admitted',
      runId,
      payload: {
        schemaVersion: 1,
        parentRunId: runId,
        childRunId: launched.runId,
        agentId: target.manifest.id,
        taskId,
        goalId,
        ceilingMicroUsd,
        ceilingWallclockMs,
      },
    })

    // Killing the parent kills the child: a child outliving the run that is paying
    // for it is spend nobody is waiting on.
    const onAbort = (): void => {
      this.#o.kill(launched.runId, `parent ${runId} was stopped`)
    }
    ctx.signal?.addEventListener('abort', onAbort, { once: true })

    let outcome: RunOutcome
    try {
      outcome = await withTimeout(launched.outcome, ceilingWallclockMs + WAIT_GRACE_MS, () => {
        this.#o.kill(launched.runId, 'the delegation outlived its ceiling')
      })
    } finally {
      ctx.signal?.removeEventListener('abort', onAbort)
    }
    child.status = outcome.status

    // Charged whatever the outcome: a failed child still spent the money.
    budget.charge('cost', outcome.costMicroUsd)
    this.#o.store.append({
      type: 'delegation.result',
      runId,
      payload: {
        schemaVersion: 1,
        parentRunId: runId,
        childRunId: launched.runId,
        status: outcome.status,
        costMicroUsd: outcome.costMicroUsd,
        taint: outcome.taint,
      },
    })

    return {
      ok: outcome.status === 'ok',
      taints: outcome.taint === 'tainted',
      text: JSON.stringify({
        runId: launched.runId,
        taskId,
        goalId,
        status: outcome.status,
        ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
        costMicroUsd: outcome.costMicroUsd,
        result: outcome.finalText,
      }),
    }
  }
}

/** Resolve with the promise, or run `onTimeout` and keep waiting for it to settle. */
async function withTimeout<T>(promise: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  const timer = setTimeout(() => {
    log.warn({ ms }, 'a delegated child exceeded its ceiling; killing it')
    onTimeout()
  }, ms)
  timer.unref?.()
  try {
    // The kill makes the child finish, so the promise still settles — with the
    // killed status, which is the true account of what happened.
    return await promise
  } finally {
    clearTimeout(timer)
  }
}
