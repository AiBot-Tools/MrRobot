// Writing a goal tree into pmmcp, and moving its statuses.
//
// WHO WRITES, AND WHY IT IS NOT AN AGENT TOOL CALL
//
// Invariant 3 governs AGENT tool calls: gate → (human) → (quarantine) → execute →
// log. This is not one. The kernel validates a plan the model proposed and writes
// the tree itself, through `callKernelOnly`, exactly as the secrets broker reads
// the vault — the goal tools stay `kernel-only` in tool-views.yaml and no agent
// can reach them. The model proposes structure; the kernel decides whether that
// structure is admissible and is the only thing that writes it. That is the same
// split as "the model never makes an access-control decision", applied to the
// operator's long-term memory.
//
// WHAT IT REFUSES
//
//   It never claims a goal id it did not get back from the server. A create whose
//   result cannot be read as an id fails the write rather than inventing one,
//   because a fabricated id is a goal nothing can ever update.
//
//   It never writes `done`. The status vocabulary has `review` between
//   `in_progress` and `done` precisely so that finishing is a decision, and a
//   kernel that closed its own goals would make every completion self-reported.
//   pmmcp has no `review`, so it is SENT per `goals.statuses` (in_progress, with
//   progress 100) and stays `review` in the kernel's log.
//
//   It never moves a goal it did not create. pmmcp's `update_goal` takes a
//   goal_id and no project_id, so the server will move ANY goal by id; the
//   kernel's own `goal.created` record, and the namespace it names, is the only
//   check that a run's status update lands in that run's tree.
//
//   It never reads a reply as success without pmmcp's own confirmation. pmmcp
//   answers errors as SUCCESSFUL text ("Error: Cannot transition…", "Goal x not
//   found."), so `ok` from the transport proves nothing on its own.
//
//   It stops at the FIRST failure and reports what it had written. A partial tree
//   is a fact on the server; pretending the whole write failed would leave goals
//   nothing knows about.

import { PolicyDenied } from '../errors.js'
import type { EventStore } from '../events/store.js'
import type { McpHub } from '../mcp/hub.js'
import { log } from '../log.js'
import type { GoalsConfig } from './tools.js'
import { tasksOf, type ProposedPlan } from './plan.js'

/**
 * The statuses the kernel may set, and the only ones it will.
 *
 * `done` and `abandoned` are absent on purpose: both are decisions, and neither
 * is the kernel's to make. A run finishing well moves its task to `review`.
 */
export const KERNEL_SETTABLE = ['in_progress', 'blocked', 'review'] as const
export type KernelStatus = (typeof KERNEL_SETTABLE)[number]

export interface GoalWriterOptions {
  readonly store: EventStore
  readonly hub: McpHub
  readonly goals: GoalsConfig
  readonly serverId?: string
  /** Why the goals path is unusable, from the boot check. Absent means usable. */
  readonly degradedReason?: string | undefined
}

export interface WrittenTree {
  readonly objectiveGoalId: string
  /** Plan milestone id → server goal id. */
  readonly milestones: ReadonlyMap<string, string>
  /** Plan task id → server goal id. */
  readonly tasks: ReadonlyMap<string, string>
}

export class GoalsUnavailable extends Error {
  readonly code = 'AOS_GOALS_UNAVAILABLE'
  constructor(reason: string) {
    super(`goals unavailable: ${reason}`)
    this.name = 'GoalsUnavailable'
  }
}

/** A create call whose result held no id. Never turned into a guess. */
export class GoalWriteFailed extends Error {
  readonly code = 'AOS_GOAL_WRITE_FAILED'
  /** What had already been written when this failed. */
  readonly written: readonly string[]
  constructor(message: string, written: readonly string[]) {
    super(message)
    this.name = 'GoalWriteFailed'
    this.written = written
  }
}

/** Text of an MCP content array, which is all the hub hands back. */
function textOf(content: unknown): string {
  if (!Array.isArray(content)) return ''
  return content
    .map((block) => {
      if (typeof block !== 'object' || block === null) return ''
      const text = (block as { text?: unknown }).text
      return typeof text === 'string' ? text : ''
    })
    .join('')
}

/**
 * The goal id in a create result.
 *
 * pmmcp's result shape is unconfirmed, so this accepts the two forms a server
 * plausibly returns — a JSON object with an id field, or a bare string — and
 * refuses everything else rather than picking something that looks id-shaped out
 * of prose. `id`, `goal_id` and `goalId` are all tried because the casing is part
 * of what nobody has read yet.
 */
export function goalIdOf(content: unknown): string | undefined {
  const text = textOf(content).trim()
  if (text === '') return undefined
  // pmmcp's own reply (src/tools/goals.py): "✅ Goal created: goal_<hex>" then
  // detail lines. Matched first and only at the start, so an error sentence
  // that happens to quote an id is never read as a creation.
  const created = /^✅ Goal created: (\S+)/u.exec(text)
  if (created?.[1] !== undefined) return created[1]
  try {
    const parsed: unknown = JSON.parse(text)
    if (typeof parsed === 'string' && parsed.trim() !== '') return parsed.trim()
    if (typeof parsed === 'object' && parsed !== null) {
      for (const key of ['id', 'goal_id', 'goalId']) {
        const value = (parsed as Record<string, unknown>)[key]
        if (typeof value === 'string' && value.trim() !== '') return value.trim()
      }
    }
    return undefined
  } catch {
    // Not JSON. A bare id is acceptable; a sentence is not, and a space is the
    // cheapest reliable way to tell them apart without inventing a format.
    return /\s/.test(text) ? undefined : text
  }
}

export class GoalWriter {
  readonly #o: GoalWriterOptions
  readonly #serverId: string

  constructor(options: GoalWriterOptions) {
    this.#o = options
    this.#serverId = options.serverId ?? 'pmmcp'
  }

  get available(): boolean {
    return this.#o.degradedReason === undefined
  }

  get degradedReason(): string | undefined {
    return this.#o.degradedReason
  }

  #assertAvailable(): void {
    const reason = this.#o.degradedReason
    if (reason !== undefined) throw new GoalsUnavailable(reason)
  }

  async #call(tool: string, args: Record<string, unknown>, purpose: string): Promise<unknown> {
    const result = await this.#o.hub.callKernelOnly(this.#serverId, tool, args, purpose)
    if (!result.ok) {
      throw new GoalWriteFailed(`${this.#serverId}.${tool} failed: ${textOf(result.content)}`, [])
    }
    return result.content
  }

  /**
   * Create one goal and return the id the SERVER gave it.
   *
   * @throws {GoalWriteFailed} when the result holds no readable id.
   */
  async #create(input: {
    projectId: string
    kind: 'objective' | 'milestone' | 'task'
    title: string
    parentId?: string
    planTaskId?: string
    written: string[]
  }): Promise<string> {
    const a = this.#o.goals.args
    const args: Record<string, unknown> = {
      [a.projectId]: input.projectId,
      [a.kind]: input.kind,
      [a.title]: input.title,
      ...(input.parentId === undefined ? {} : { [a.parentId]: input.parentId }),
    }
    const content = await this.#call(
      this.#o.goals.tools.create,
      args,
      `create ${input.kind} goal in ${input.projectId}`,
    ).catch((e: unknown) => {
      if (e instanceof GoalWriteFailed) throw new GoalWriteFailed(e.message, input.written)
      throw e
    })

    const goalId = goalIdOf(content)
    if (goalId === undefined) {
      // Never a guess: a fabricated id is a goal nothing can ever update, and it
      // would be indistinguishable from a real one in the log. The server's own
      // words go in the message, because pmmcp reports errors as text.
      throw new GoalWriteFailed(
        `${this.#serverId}.${this.#o.goals.tools.create} returned no readable goal id for ` +
          `${input.kind} "${input.title}": ${textOf(content).slice(0, 300)}`,
        input.written,
      )
    }

    this.#o.store.append({
      type: 'goal.created',
      payload: {
        schemaVersion: 1,
        projectId: input.projectId,
        goalId,
        kind: input.kind,
        title: input.title,
        ...(input.parentId === undefined ? {} : { parentId: input.parentId }),
        ...(input.planTaskId === undefined ? {} : { planTaskId: input.planTaskId }),
      },
    })
    input.written.push(goalId)
    return goalId
  }

  /**
   * Write a validated plan as objective → milestone → task.
   *
   * Depth-first per milestone so a failure leaves a shallower tree rather than a
   * wide one with no tasks under it, and every id is the server's.
   *
   * @throws {GoalsUnavailable} when the goal tools are not usable.
   * @throws {GoalWriteFailed} carrying the ids already written.
   */
  async materialise(plan: ProposedPlan, projectId: string, runId: string): Promise<WrittenTree> {
    this.#assertAvailable()
    const written: string[] = []

    const objectiveGoalId = await this.#create({
      projectId,
      kind: 'objective',
      title: plan.objective.title,
      written,
    })

    const milestones = new Map<string, string>()
    const tasks = new Map<string, string>()
    for (const milestone of plan.milestones) {
      const milestoneGoalId = await this.#create({
        projectId,
        kind: 'milestone',
        title: milestone.title,
        parentId: objectiveGoalId,
        planTaskId: milestone.id,
        written,
      })
      milestones.set(milestone.id, milestoneGoalId)
      for (const task of milestone.tasks) {
        const taskGoalId = await this.#create({
          projectId,
          kind: 'task',
          title: task.title,
          parentId: milestoneGoalId,
          planTaskId: task.id,
          written,
        })
        tasks.set(task.id, taskGoalId)
      }
    }

    this.#o.store.append({
      type: 'plan.adopted',
      runId,
      payload: {
        schemaVersion: 1,
        runId,
        projectId,
        objectiveGoalId,
        title: plan.objective.title,
        milestones: plan.milestones.length,
        tasks: tasksOf(plan).length,
        questions: plan.questionsForOperator.length,
      },
    })

    return { objectiveGoalId, milestones, tasks }
  }

  /**
   * Move a goal, and record it.
   *
   * @throws {PolicyDenied} for a status the kernel may not set — `done` above
   *   all, which is a decision and not a transition.
   */
  async setStatus(
    goalId: string,
    to: KernelStatus,
    context: { projectId: string; runId?: string; reason?: string },
  ): Promise<void> {
    this.#assertAvailable()
    if (!(KERNEL_SETTABLE as readonly string[]).includes(to)) {
      throw new PolicyDenied(
        `goal ${goalId}`,
        `the kernel may set ${KERNEL_SETTABLE.join(', ')} and nothing else; ` +
          `"${to}" is a decision, not a transition`,
      )
    }
    const owner = this.ownerOf(goalId)
    if (owner === undefined) {
      throw new PolicyDenied(
        `goal ${goalId}`,
        'this kernel did not create that goal, and pmmcp moves any goal by id, so it is not moved',
      )
    }
    if (owner !== context.projectId) {
      throw new PolicyDenied(
        `goal ${goalId}`,
        `it was created in ${owner}, not ${context.projectId}`,
      )
    }

    const a = this.#o.goals.args
    const sent = this.#o.goals.statuses[to]
    const content = await this.#call(
      this.#o.goals.tools.updateStatus,
      {
        [a.goalId]: goalId,
        [a.status]: sent,
        // `review` is finished work awaiting the operator; 100 is how that shows
        // in pmmcp, which has no review status of its own.
        ...(to === 'review' ? { [a.progress]: 100 } : {}),
      },
      `move goal ${goalId} to ${to}`,
    )
    const reply = textOf(content).trim()
    const confirmed = /^✅ Goal updated: (\S+)/u.exec(reply)
    if (confirmed?.[1] !== goalId) {
      throw new GoalWriteFailed(
        `${this.#serverId}.${this.#o.goals.tools.updateStatus} did not confirm ${goalId} → ${sent}: ` +
          reply.slice(0, 300),
        [],
      )
    }
    this.#o.store.append({
      type: 'goal.status',
      ...(context.runId === undefined ? {} : { runId: context.runId }),
      payload: {
        schemaVersion: 1,
        projectId: context.projectId,
        goalId,
        to,
        by: 'kernel',
        ...(context.runId === undefined ? {} : { runId: context.runId }),
        ...(context.reason === undefined ? {} : { reason: context.reason.slice(0, 500) }),
      },
    })
  }

  /**
   * The namespace this kernel created a goal in, from its own log, or undefined.
   *
   * The log rather than memory: it survives a restart, and it is the record an
   * operator can read for themselves.
   */
  ownerOf(goalId: string): string | undefined {
    for (const row of this.#o.store.query({ type: 'goal.created' })) {
      const payload = JSON.parse(row.payload) as { goalId?: unknown; projectId?: unknown }
      if (payload.goalId === goalId && typeof payload.projectId === 'string') return payload.projectId
    }
    return undefined
  }

  /**
   * Move a goal, swallowing failure into a log line.
   *
   * For the run lifecycle, where the status update must never take down the run
   * that triggered it: a task goal that could not be moved is a stale status an
   * operator can see and fix, while a run killed by its own bookkeeping is work
   * lost. The failure is loud in the log and absent from the chain, because
   * nothing happened on the server to record.
   */
  async trySetStatus(
    goalId: string,
    to: KernelStatus,
    context: { projectId: string; runId?: string; reason?: string },
  ): Promise<boolean> {
    try {
      await this.setStatus(goalId, to, context)
      return true
    } catch (e) {
      log.warn(
        {
          goalId,
          to,
          runId: context.runId,
          err: e instanceof Error ? e.message : String(e),
        },
        'goal status update failed; the goal is now stale on the server',
      )
      return false
    }
  }
}
