// The ProposedPlan: the artifact a plan turns into before anything acts on it.
//
// Shape from docs/design/sectors/executive.md §4.2. Trimmed to what Phase 1
// uses — budget estimates, lane classes and activation groups are in the design
// and are not parsed here, because a field nothing reads is a field that drifts
// out of step with the code silently.
//
// Everything about this file is refusal. A plan arrives as text from a model, and
// it is the input to writing a goal tree into the operator's long-term memory, so
// the parse is the only thing standing between a hallucinated structure and a
// durable one. Four refusals in particular are not optional:
//
//   a duplicate id, because ids are what the tree is addressed by afterwards;
//   a dangling `dependsOn`, because a dependency on a task that does not exist
//     is a DAG that can never be satisfied and a fan-out that never completes;
//   a CYCLE, because the kernel advances the DAG and a cycle is a kernel that
//     never finishes the objective;
//   an unknown `template`, because a task naming an agent that does not exist is
//     a task nothing can ever run.
//
// The parse is strict (`.strict()` throughout): an unexpected key is a model
// inventing structure, and accepting it would mean silently dropping whatever it
// thought that key meant.

import * as z from 'zod'

/**
 * Bounds on every model-authored string that reaches the event log.
 *
 * Not cosmetic. A goal title is written into `goal.created`, whose schema bounds
 * it at the same 200 — so without a bound HERE, a long title would be refused at
 * append, after the goal had already been created on the server, and the failure
 * would land halfway through writing a tree. Refusing the plan is the cheap end
 * of that: bounding by refusal rather than truncation, as everywhere else.
 */
const TITLE_MAX = 200
const LINE_MAX = 500
const title = (): z.ZodString => z.string().min(1).max(TITLE_MAX)
const line = (): z.ZodString => z.string().min(1).max(LINE_MAX)

/** A task: one owned artifact, at least one acceptance check. */
export const PlanTask = z
  .object({
    id: z.string().min(1).max(64),
    title: title(),
    /** The agent or template that runs it. Existence is checked separately. */
    template: z.string().min(1),
    /** Ids of tasks in THIS plan that must finish first. */
    dependsOn: z.array(z.string().min(1)).default([]),
    /**
     * How a machine can tell this task is done. At least one, by the
     * decomposition rubric: a task with no acceptance check cannot be verified
     * and its completion is whatever the worker says it is.
     */
    acceptance: z.array(line()).min(1),
    /**
     * The irreversible inventory, NAMED IN ADVANCE. An approval later requested
     * for a tool that is not in some task's inventory is a planner miss, and the
     * eval harness scores it as one.
     */
    irreversible: z
      .array(z.object({ toolRef: z.string().min(1).max(128), why: line() }).strict())
      .default([]),
  })
  .strict()
export type PlanTask = z.infer<typeof PlanTask>

export const PlanMilestone = z
  .object({
    id: z.string().min(1).max(64),
    title: title(),
    tasks: z.array(PlanTask).min(1),
  })
  .strict()
export type PlanMilestone = z.infer<typeof PlanMilestone>

export const ProposedPlan = z
  .object({
    objective: z
      .object({
        title: title(),
        successCriteria: z.array(line()).min(1),
      })
      .strict(),
    milestones: z.array(PlanMilestone).min(1),
    assumptions: z.array(line()).default([]),
    risks: z.array(line()).default([]),
    /** Bounded at parse: a plan that asks twenty questions has not planned. */
    questionsForOperator: z.array(line()).max(3).default([]),
  })
  .strict()
export type ProposedPlan = z.infer<typeof ProposedPlan>

export { TITLE_MAX, LINE_MAX }

/** Refused with the reason a human can act on, never a generic parse error. */
export class PlanInvalid extends Error {
  readonly code = 'AOS_PLAN_INVALID'
  constructor(reason: string) {
    super(`plan refused: ${reason}`)
    this.name = 'PlanInvalid'
  }
}

/** Every task in a plan, flattened, with the milestone it belongs to. */
export function tasksOf(plan: ProposedPlan): { milestoneId: string; task: PlanTask }[] {
  return plan.milestones.flatMap((m) => m.tasks.map((task) => ({ milestoneId: m.id, task })))
}

/**
 * Structural checks the zod schema cannot express, in the order that makes the
 * first failure the most useful one.
 *
 * @throws {PlanInvalid}
 */
export function assertPlanCoherent(plan: ProposedPlan, knownTemplates: readonly string[]): void {
  const tasks = tasksOf(plan)

  // Ids, across the WHOLE plan and across both levels: a milestone and a task
  // sharing an id would make the goal tree ambiguous to address later.
  const ids = new Map<string, string>()
  for (const m of plan.milestones) {
    if (ids.has(m.id)) throw new PlanInvalid(`duplicate id ${m.id}`)
    ids.set(m.id, 'milestone')
  }
  for (const { task } of tasks) {
    if (ids.has(task.id)) throw new PlanInvalid(`duplicate id ${task.id}`)
    ids.set(task.id, 'task')
  }

  const taskIds = new Set(tasks.map((t) => t.task.id))
  for (const { task } of tasks) {
    for (const dep of task.dependsOn) {
      if (dep === task.id) throw new PlanInvalid(`${task.id} depends on itself`)
      if (!taskIds.has(dep)) {
        throw new PlanInvalid(`${task.id} depends on ${dep}, which is not a task in this plan`)
      }
    }
  }

  // A cycle means the kernel advances the DAG forever. Reported with the cycle
  // itself: "there is a cycle" is not something an operator can fix.
  const cycle = findCycle(tasks.map((t) => t.task))
  if (cycle !== undefined) {
    throw new PlanInvalid(`dependsOn forms a cycle: ${cycle.join(' → ')}`)
  }

  if (knownTemplates.length > 0) {
    const known = new Set(knownTemplates)
    for (const { task } of tasks) {
      if (!known.has(task.template)) {
        throw new PlanInvalid(
          `${task.id} names template ${task.template}, which is not a registered agent or template`,
        )
      }
    }
  }
}

/** The first cycle found, as the path that closes it, or undefined. */
function findCycle(tasks: readonly PlanTask[]): string[] | undefined {
  const deps = new Map(tasks.map((t) => [t.id, t.dependsOn]))
  const state = new Map<string, 'open' | 'closed'>()
  const stack: string[] = []

  const walk = (id: string): string[] | undefined => {
    const seen = state.get(id)
    if (seen === 'closed') return undefined
    if (seen === 'open') {
      // The path from where this id first appeared, closed by itself.
      const from = stack.indexOf(id)
      return [...stack.slice(from), id]
    }
    state.set(id, 'open')
    stack.push(id)
    for (const dep of deps.get(id) ?? []) {
      const found = walk(dep)
      if (found !== undefined) return found
    }
    stack.pop()
    state.set(id, 'closed')
    return undefined
  }

  for (const task of tasks) {
    const found = walk(task.id)
    if (found !== undefined) return found
  }
  return undefined
}

/**
 * The first JSON object in a model's message.
 *
 * Models put prose around structure whatever the prompt says, so a fenced
 * ```json block is tried first and a balanced brace scan second. Nothing here
 * repairs malformed JSON: a plan that does not parse is refused, because the
 * alternative is guessing what the model meant and writing that guess into the
 * operator's memory.
 */
export function extractJson(text: string): string | undefined {
  const fenced = /```(?:json)?\s*\n([\s\S]*?)```/.exec(text)
  if (fenced?.[1] !== undefined) return fenced[1].trim()

  const start = text.indexOf('{')
  if (start === -1) return undefined
  let depth = 0
  let inString = false
  let escaped = false
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i]
    if (escaped) {
      escaped = false
      continue
    }
    if (ch === '\\') {
      escaped = true
      continue
    }
    if (ch === '"') {
      inString = !inString
      continue
    }
    if (inString) continue
    if (ch === '{') depth += 1
    else if (ch === '}') {
      depth -= 1
      if (depth === 0) return text.slice(start, i + 1)
    }
  }
  return undefined
}

export interface ParseOptions {
  /** Agent and template ids a task may name. Empty skips the check. */
  readonly knownTemplates?: readonly string[]
}

/**
 * Parse a plan out of a model message.
 *
 * @throws {PlanInvalid} with a reason naming what was wrong.
 */
export function parsePlan(text: string, options: ParseOptions = {}): ProposedPlan {
  const json = extractJson(text)
  if (json === undefined) throw new PlanInvalid('the message contains no JSON object')

  let raw: unknown
  try {
    raw = JSON.parse(json)
  } catch (e) {
    throw new PlanInvalid(`the JSON does not parse: ${e instanceof Error ? e.message : String(e)}`)
  }

  const parsed = ProposedPlan.safeParse(raw)
  if (!parsed.success) {
    // The first issue, with its path: a dump of every zod issue is unreadable in
    // a log line and the first one is almost always the real problem.
    const issue = parsed.error.issues[0]
    const at = issue === undefined || issue.path.length === 0 ? '' : ` at ${issue.path.join('.')}`
    throw new PlanInvalid(`${issue?.message ?? 'schema mismatch'}${at}`)
  }

  assertPlanCoherent(parsed.data, options.knownTemplates ?? [])
  return parsed.data
}

/** True when a message looks like it is trying to be a plan at all. */
export function looksLikePlan(text: string): boolean {
  const json = extractJson(text)
  if (json === undefined) return false
  return json.includes('"objective"') && json.includes('"milestones"')
}
