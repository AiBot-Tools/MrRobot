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
//   It reads contract P6's typed result when pmmcp sends one, and today's prose
//   when it does not (§6 step 2). A typed success it will not confirm (another
//   project, a text that says something else, a shape it does not read) may
//   still have been written, so it is refused AND recorded as `goal.unconfirmed`.
//
//   It stops at the FIRST failure and reports what it had written. A partial tree
//   is a fact on the server; pretending the whole write failed would leave goals
//   nothing knows about.

import { isDeepStrictEqual } from 'node:util'

import { z } from 'zod'

import { PolicyDenied } from '../errors.js'
import type { EventStore } from '../events/store.js'
import type { McpHub } from '../mcp/hub.js'
import { GoalResult, type GoalResultValue } from '../mcp/pmmcp-schemas.js'
import { log } from '../log.js'
import { GoalWriteFailed, GoalsUnavailable } from './errors.js'
import { createGoal, updateGoal, type GoalCall, type GoalCallResult } from './pmmcp.js'
import type { GoalsConfig } from './tools.js'
import { tasksOf, type ProposedPlan } from './plan.js'

export { GoalWriteFailed, GoalsUnavailable } from './errors.js'

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

/** What a goal call's success said: the typed P6 result, or prose to read the old way. */
type Reply = { readonly kind: 'prose' } | { readonly kind: 'typed'; readonly value: GoalResultValue }

/** A typed success the kernel will not confirm; pmmcp may already have acted on it. */
class UnconfirmedReply extends Error {
  readonly goalId: string | undefined
  constructor(goalId: string | undefined, reason: string) {
    super(reason)
    this.goalId = goalId
  }
}

/** The JSON text P6 sends beside its result, or pmmcp's prose naming the same goal. */
function agrees(text: string, structured: Readonly<Record<string, unknown>>, goalId: string): boolean {
  try {
    return isDeepStrictEqual(JSON.parse(text), structured)
  } catch {
    // Not JSON: prose may still name the goal.
  }
  return /^✅ Goal (?:created|updated): (\S+)/u.exec(text)?.[1] === goalId
}

/**
 * Read a success. No structuredContent, or FastMCP's `{result: <the text>}`
 * wrapping of a `-> str` tool, is prose. Anything else must be a P6 goal result,
 * parsed strictly, whose text block (if any) says the same thing.
 *
 * @throws {UnconfirmedReply} for a typed success the kernel will not read.
 */
function replyOf(tool: string, result: GoalCallResult): Reply {
  const structured = result.structuredContent
  if (structured === undefined) return { kind: 'prose' }
  const text = textOf(result.content)
  const keys = Object.keys(structured)
  if (keys.length === 1 && keys[0] === 'result' && typeof structured['result'] === 'string') {
    if (structured['result'] !== text) throw new UnconfirmedReply(undefined, `the text and structuredContent of ${tool} disagree`)
    return { kind: 'prose' }
  }
  const named = typeof structured['goal_id'] === 'string' ? structured['goal_id'] : undefined
  const parsed = GoalResult.safeParse(structured)
  if (!parsed.success) {
    throw new UnconfirmedReply(named, `${tool} returned structuredContent that is not a P6 goal result: ${z.prettifyError(parsed.error)}`)
  }
  const trimmed = text.trim()
  if (trimmed !== '' && !agrees(trimmed, structured, parsed.data.goal_id)) {
    throw new UnconfirmedReply(parsed.data.goal_id, `the text and structuredContent of ${tool} disagree`)
  }
  return { kind: 'typed', value: parsed.data }
}

export class GoalWriter {
  readonly #o: GoalWriterOptions
  readonly #serverId: string
  readonly #pmmcp: GoalCall

  constructor(options: GoalWriterOptions) {
    this.#o = options
    this.#serverId = options.serverId ?? 'pmmcp'
    this.#pmmcp = { hub: options.hub, goals: options.goals, serverId: this.#serverId }
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

  /**
   * A call the transport answered, or a failed write carrying what was written.
   *
   * Any error but the kernel's own refusals becomes GoalWriteFailed, so
   * kernel.adopt_plan refuses with a record instead of throwing. The SDK refuses
   * a success that breaks the tool's own outputSchema, or that has none: pmmcp
   * has answered, so it may have written, and that is recorded.
   */
  async #answered(
    tool: string,
    call: Promise<GoalCallResult>,
    projectId: string,
    written: readonly string[],
  ): Promise<GoalCallResult> {
    let result: GoalCallResult
    try {
      result = await call
    } catch (e) {
      if (e instanceof GoalWriteFailed || e instanceof GoalsUnavailable || e instanceof PolicyDenied) throw e
      const message = e instanceof Error ? e.message : String(e)
      if (/output schema|structured content/i.test(message)) this.#recordUnconfirmed(tool, projectId, undefined, message)
      throw new GoalWriteFailed(`${this.#serverId}.${tool} failed: ${message}`, written)
    }
    if (!result.ok) {
      throw new GoalWriteFailed(`${this.#serverId}.${tool} failed: ${textOf(result.content)}`, written)
    }
    return result
  }

  #recordUnconfirmed(tool: string, projectId: string, goalId: string | undefined, reason: string): void {
    this.#o.store.append({
      type: 'goal.unconfirmed',
      payload: {
        schemaVersion: 1,
        projectId,
        tool,
        ...(goalId === undefined ? {} : { goalId: goalId.slice(0, 128) }),
        reason: reason.slice(0, 500),
      },
    })
  }

  /** Record the orphan, then the refusal to throw. */
  #unconfirmed(tool: string, projectId: string, goalId: string | undefined, reason: string, written: readonly string[]): GoalWriteFailed {
    this.#recordUnconfirmed(tool, projectId, goalId, reason)
    return new GoalWriteFailed(`${this.#serverId}.${tool} answered with a result the kernel will not confirm: ${reason}`, written)
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
    const tool = this.#o.goals.tools.create
    const result = await this.#answered(
      tool,
      createGoal(
        this.#pmmcp,
        {
          project_id: input.projectId,
          goal_type: input.kind,
          title: input.title,
          ...(input.parentId === undefined ? {} : { parent_goal_id: input.parentId }),
        },
        `create ${input.kind} goal in ${input.projectId}`,
      ).catch((e: unknown) => {
        if (e instanceof GoalWriteFailed) throw new GoalWriteFailed(e.message, input.written)
        throw e
      }),
      input.projectId,
      input.written,
    )
    const content = result.content

    let reply: Reply
    try {
      reply = replyOf(tool, result)
    } catch (e) {
      if (e instanceof UnconfirmedReply) throw this.#unconfirmed(tool, input.projectId, e.goalId, e.message, input.written)
      throw e
    }
    if (reply.kind === 'typed' && reply.value.project_id !== input.projectId) {
      const where = `pmmcp reports it in ${reply.value.project_id}, not ${input.projectId}`
      throw this.#unconfirmed(tool, input.projectId, reply.value.goal_id, where, input.written)
    }

    const goalId = reply.kind === 'typed' ? reply.value.goal_id : goalIdOf(content)
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

    const sent = this.#o.goals.statuses[to]
    const tool = this.#o.goals.tools.updateStatus
    const result = await this.#answered(
      tool,
      updateGoal(
        this.#pmmcp,
        {
          goal_id: goalId,
          // A string from kernel.yaml; updateGoal refuses one that is not sendable.
          status: sent,
          // `review` is finished work awaiting the operator; 100 is how that shows
          // in pmmcp, which has no review status of its own.
          ...(to === 'review' ? { progress_pct: 100 } : {}),
        },
        `move goal ${goalId} to ${to}`,
      ),
      context.projectId,
      [],
    )

    let answer: Reply
    try {
      answer = replyOf(tool, result)
    } catch (e) {
      if (e instanceof UnconfirmedReply) throw this.#unconfirmed(tool, context.projectId, goalId, e.message, [])
      throw e
    }
    if (answer.kind === 'typed') {
      // P6 says where the goal now is; every part of it must be the move asked
      // for, and the project the kernel's own goal.created names.
      const v = answer.value
      const off: string[] = []
      if (v.goal_id !== goalId) off.push(`goal_id ${v.goal_id}`)
      if (v.status !== sent) off.push(`status ${v.status}`)
      if (v.project_id !== context.projectId) off.push(`project_id ${v.project_id}`)
      if (to === 'review' && v.progress_pct !== 100) off.push(`progress_pct ${String(v.progress_pct)}`)
      if (off.length > 0) {
        throw this.#unconfirmed(tool, context.projectId, goalId, `did not confirm ${goalId} → ${sent}: pmmcp reports ${off.join(', ')}`, [])
      }
    } else {
      const reply = textOf(result.content).trim()
      const confirmed = /^✅ Goal updated: (\S+)/u.exec(reply)
      if (confirmed?.[1] !== goalId) {
        throw new GoalWriteFailed(
          `${this.#serverId}.${this.#o.goals.tools.updateStatus} did not confirm ${goalId} → ${sent}: ` +
            reply.slice(0, 300),
          [],
        )
      }
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
