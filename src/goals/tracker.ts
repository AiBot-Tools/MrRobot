// Keeping a goal tree in step with the runs that serve it.
//
// Three lifecycle facts, each from the event log rather than from a caller:
//
//   a run that named a goal starts       → that task goal moves to `in_progress`
//   it finishes well                     → `review`, never `done`
//   it fails, is killed, or is orphaned  → `blocked`
//
// WHY A SUBSCRIBER AND NOT A CALL IN THE RUN LOOP
//
// The loop must not hold a pmmcp handle or wait on a network round trip to finish
// a run. It appends; this reads what it appended. That also means the tracker sees
// exactly what an operator reading the log later sees, and cannot be told a run
// started by anything other than the run having actually started.
//
// Two hazards that shape the code. The store's listener fan-out swallows errors by
// design, so nothing here does its work inside the listener: each row schedules
// work on a serial queue with its own catch, which also avoids appending an event
// from inside the append that triggered it. And a restart loses the runId → goalId
// map, so it is seeded from the log the way the scheduler seeds its fired minutes.

import type pino from 'pino'

import type { EventRow } from '../events/chain.js'
import type { EventStore } from '../events/store.js'
import { log as defaultLog } from '../log.js'
import {
  GoalCreatedPayload,
  RunFinishedPayload,
  RunQueuedPayload,
  RunStartedPayload,
} from '../events/types.js'
import { claimsOf } from '../eval/observe.js'
import { looksLikePlan, parsePlan, PlanInvalid } from './plan.js'
import type { GoalWriter } from './writer.js'

export interface GoalTrackerOptions {
  readonly store: EventStore
  readonly writer: GoalWriter
  /** Adopt a plan found in a finished orchestrator run. `goals.adoptFromRuns`. */
  readonly adoptFromRuns: boolean
  /** The memory namespace an agent writes to, or undefined if it has none. */
  readonly projectIdOf: (agentId: string) => string | undefined
  /** True only for `role: orchestrator`. Nothing else may adopt a plan. */
  readonly isOrchestrator: (agentId: string) => boolean
  /** Agent and template ids a plan's tasks may name. */
  readonly knownTemplates: () => readonly string[]
  /**
   * Injected so a test can read what this logged.
   *
   * Not incidental: whether a refusal is logged at all is part of the contract
   * here. Most orchestrator turns are not plans, and a warning per turn would
   * train the operator to ignore the log — so "quiet for a non-plan, loud for a
   * plan that did not parse" is a behaviour with a test, and the only way to test
   * it is to be able to see the output.
   */
  readonly logger?: pino.Logger
}

export class GoalTracker {
  readonly #o: GoalTrackerOptions
  readonly #log: pino.Logger
  /** runId → the goal it serves, for runs that have not finished. */
  readonly #goalOf = new Map<string, string>()
  /**
   * goalId → the namespace the KERNEL created it in, from `goal.created`.
   *
   * A goal's namespace is where it was written, not where the run serving it
   * lives. A delegated researcher works a task goal in `aos/ceo`; addressing its
   * status updates to `aos/agent/researcher` fails on the server and would leave
   * the goal stale with only a log line to show for it. So the kernel's own
   * record of where it wrote each goal is the authority, and the running agent's
   * namespace is only the fallback for goals the kernel did not create.
   */
  readonly #namespaceOf = new Map<string, string>()
  /** Serial, so two updates to one goal cannot race each other. */
  #queue: Promise<void> = Promise.resolve()
  #unsubscribe: (() => void) | undefined

  constructor(options: GoalTrackerOptions) {
    this.#o = options
    this.#log = options.logger ?? defaultLog
  }

  /** Rebuild the runId → goalId map for runs the log shows still open. */
  seedFromLog(rows: readonly EventRow[]): void {
    for (const row of rows) this.#learnNamespace(row)
    const finished = new Set<string>()
    for (const row of rows) {
      if (row.type === 'run.finished' && row.runId !== null) finished.add(row.runId)
    }
    for (const row of rows) {
      if (row.type !== 'run.queued' || row.runId === null) continue
      if (finished.has(row.runId)) continue
      const goalId = RunQueuedPayload.parse(JSON.parse(row.payload)).goalId
      if (goalId !== undefined) this.#goalOf.set(row.runId, goalId)
    }
  }

  attach(): () => void {
    const off = this.#o.store.subscribe((row) => {
      this.#observe(row)
    })
    this.#unsubscribe = off
    return off
  }

  detach(): void {
    this.#unsubscribe?.()
    this.#unsubscribe = undefined
  }

  /** Every scheduled update, settled. For tests and for shutdown. */
  async drain(): Promise<void> {
    await this.#queue
  }

  /** The goal a live run serves, if it named one. */
  goalFor(runId: string): string | undefined {
    return this.#goalOf.get(runId)
  }

  #enqueue(work: () => Promise<void>, context: Record<string, unknown>): void {
    this.#queue = this.#queue.then(work).catch((e: unknown) => {
      // The store swallows listener errors, so this is the only place a failure
      // here can be seen. Loud, and never fatal: a stale goal status is something
      // an operator can fix, and nothing about it should stop the kernel.
      this.#log.warn(
        { ...context, err: e instanceof Error ? e.message : String(e) },
        'goal tracking failed',
      )
    })
  }

  #learnNamespace(row: EventRow): void {
    if (row.type !== 'goal.created') return
    const p = GoalCreatedPayload.parse(JSON.parse(row.payload))
    this.#namespaceOf.set(p.goalId, p.projectId)
  }

  /** Where a goal lives: where the kernel wrote it, else the running agent's own. */
  #projectFor(goalId: string, agentId: string): string | undefined {
    return this.#namespaceOf.get(goalId) ?? this.#o.projectIdOf(agentId)
  }

  #observe(row: EventRow): void {
    // Before the runId check: goal.created carries no run.
    this.#learnNamespace(row)
    if (row.runId === null) return
    const runId = row.runId

    if (row.type === 'run.queued') {
      const goalId = RunQueuedPayload.parse(JSON.parse(row.payload)).goalId
      if (goalId !== undefined) this.#goalOf.set(runId, goalId)
      return
    }

    if (row.type === 'run.started') {
      const goalId = this.#goalOf.get(runId)
      if (goalId === undefined) return
      const agentId = RunStartedPayload.parse(JSON.parse(row.payload)).agentId
      const projectId = this.#projectFor(goalId, agentId)
      if (projectId === undefined) return
      this.#enqueue(
        async () => {
          await this.#o.writer.trySetStatus(goalId, 'in_progress', {
            projectId,
            runId,
            reason: `run ${runId} started`,
          })
        },
        { runId, goalId },
      )
      return
    }

    if (row.type === 'run.finished') {
      const finished = RunFinishedPayload.parse(JSON.parse(row.payload))
      const goalId = this.#goalOf.get(runId)
      this.#goalOf.delete(runId)
      const agentId = row.agentId
      if (agentId === null) return

      const goalProject = goalId === undefined ? undefined : this.#projectFor(goalId, agentId)
      if (goalId !== undefined && goalProject !== undefined) {
        // `review` and never `done`: a run finishing is evidence, not a verdict.
        // Anything other than ok is `blocked`, which is a state something can act
        // on, rather than `abandoned`, which would be the kernel giving up on the
        // operator's behalf.
        const to = finished.status === 'ok' ? 'review' : 'blocked'
        this.#enqueue(
          async () => {
            await this.#o.writer.trySetStatus(goalId, to, {
              projectId: goalProject,
              runId,
              reason: `run ${runId} finished ${finished.status}`,
            })
          },
          { runId, goalId, to },
        )
      }

      const projectId = this.#o.projectIdOf(agentId)
      if (
        projectId !== undefined &&
        this.#o.adoptFromRuns &&
        finished.status === 'ok' &&
        this.#o.isOrchestrator(agentId)
      ) {
        this.#enqueue(
          async () => {
            await this.#adopt(runId, projectId)
          },
          { runId, agentId },
        )
      }
      return
    }
  }

  /**
   * Try to read a plan out of a finished orchestrator run and write the tree.
   *
   * A message that was never trying to be a plan is not a failure and is not
   * logged: most CEO turns are not plans, and a warning per turn would train the
   * operator to ignore the log. A message that WAS trying and did not parse is
   * logged with the reason, because that is a model producing structure the kernel
   * refused and the operator needs to see it.
   */
  async #adopt(runId: string, projectId: string): Promise<void> {
    if (!this.#o.writer.available) return
    const rows = this.#o.store.query({ runId })
    // A run that already adopted a plan mid-run (kernel.adopt_plan) must not get
    // a second tree because its final message restated the plan.
    if (rows.some((r) => r.type === 'plan.adopted')) return
    const claims = claimsOf(rows)
    if (!looksLikePlan(claims)) return

    let plan
    try {
      plan = parsePlan(claims, { knownTemplates: this.#o.knownTemplates() })
    } catch (e) {
      if (e instanceof PlanInvalid) {
        this.#log.warn({ runId, reason: e.message }, 'a plan-shaped result was refused')
        return
      }
      throw e
    }
    await this.#o.writer.materialise(plan, projectId, runId)
  }

  /**
   * Mark the goals of runs a restart found open as blocked.
   *
   * Never re-execution: a restart that re-issued paid work is the anti-pattern
   * the crash-recovery design names. The goal is moved to a state the CEO's next
   * continuation can act on, and the run stays orphaned in the log.
   */
  async blockOrphans(orphanRunIds: readonly string[]): Promise<void> {
    for (const runId of orphanRunIds) {
      const goalId = this.#goalOf.get(runId)
      if (goalId === undefined) continue
      this.#goalOf.delete(runId)
      const queued = this.#o.store.query({ runId }).find((r) => r.type === 'run.queued')
      const agentId = queued?.agentId ?? null
      const projectId = agentId === null ? this.#namespaceOf.get(goalId) : this.#projectFor(goalId, agentId)
      if (projectId === undefined) continue
      await this.#o.writer.trySetStatus(goalId, 'blocked', {
        projectId,
        runId,
        reason: `run ${runId} was orphaned by a restart`,
      })
    }
  }
}
