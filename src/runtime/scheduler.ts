// Cron scheduler.
//
// Ticks once a minute, asks each scheduled agent's expression whether this
// minute matches, and starts a run if it does. Four rules make that safe to
// leave running unattended, and each of them exists because a scheduled run is
// not a computation — it spends money and takes actions through tools.
//
//   NO CATCH-UP. Occurrences missed while the kernel was down are skipped and
//   logged, never replayed. The worst moment to launch a backlog is immediately
//   after an outage: whatever caused it may still be true, so the runs would
//   likely fail after burning a model call each. Skipping is recoverable by hand
//   in one command; actions already taken are not.
//
//   NO OVERLAP. If the agent already has a run in flight, the tick is skipped
//   rather than queued. The per-agent serial lane would serialise them, so a job
//   slower than its interval would build a queue that never drains.
//
//   NO DOUBLE FIRE. Every fire is keyed by the local minute it fired for, and a
//   minute fires at most once — across a repeated hour at the end of daylight
//   saving, and across a restart inside the same minute, because the key is
//   recovered from the log rather than kept only in memory.
//
//   NO NEW LANE. A scheduled run goes on the agent's own lane, like any other.
//   A lane named for the scheduler would be a queue nothing else fills and a
//   plausible place for a later edit to start work no gate had approved.
//
// Time is LOCAL, because `0 9 * * 1-5` means nine in the morning where the
// operator is. A repeated local hour cannot double-fire (same minute key), and a
// skipped one simply does not fire that day.

import { log } from '../log.js'
import type { EventStore } from '../events/store.js'
import { cronMatches, minuteKey, parseCron, type CronExpr } from './cron.js'

/** One agent with a schedule, as the scheduler needs it. */
export interface ScheduledAgent {
  readonly agentId: string
  /** The expression as written in the manifest. */
  readonly schedule: string
}

export interface SchedulerOptions {
  readonly store: EventStore
  /** Agents to consider on every tick, read fresh so a reload is picked up. */
  readonly agents: () => readonly ScheduledAgent[]
  /**
   * Start a run. The scheduler does not know how — it asks, and whatever comes
   * back is an ordinary run: same lane, same gate, same budget.
   */
  readonly startRun: (agentId: string, input: string) => string
  /** True when this agent already has a run queued or running. */
  readonly isBusy: (agentId: string) => boolean
  readonly now?: () => number
  /** Injected so a test drives ticks instead of waiting a minute. */
  readonly setInterval?: typeof globalThis.setInterval
  readonly clearInterval?: typeof globalThis.clearInterval
}

/** How often the tick runs. Cron has minute resolution; this is half of it. */
export const TICK_MS = 30_000

/** The prompt a scheduled run starts with. */
export function scheduledInput(agentId: string, schedule: string, minute: string): string {
  return (
    `Scheduled run for ${agentId} (${schedule}) at ${minute}. ` +
    'Carry out this agent’s standing instructions for a scheduled invocation.'
  )
}

export class Scheduler {
  readonly #o: SchedulerOptions
  readonly #now: () => number
  /** Last minute key fired, per agent. Seeded from the log at start(). */
  readonly #fired = new Map<string, string>()
  readonly #compiled = new Map<string, CronExpr>()
  #timer: ReturnType<typeof setInterval> | undefined
  #started = false

  constructor(options: SchedulerOptions) {
    this.#o = options
    this.#now = options.now ?? Date.now
  }

  /**
   * Begin ticking.
   *
   * The first thing it does is read the log for the last scheduled run per
   * agent, so a restart inside a minute that already fired does not fire it
   * again. Without that seed the dedupe would live only in memory, and a restart
   * would be the one reliable way to double-fire a job.
   */
  start(): void {
    if (this.#started) return
    this.#started = true
    this.#seedFromLog()

    const every = this.#o.setInterval ?? setInterval
    this.#timer = every(() => {
      this.tick()
    }, TICK_MS)
    // The scheduler must not hold the process open by itself: a kernel with
    // nothing to do should still be able to exit.
    this.#timer.unref?.()

    log.info({ agents: this.#o.agents().length }, 'scheduler started')
  }

  stop(): void {
    if (this.#timer !== undefined) {
      const clear = this.#o.clearInterval ?? clearInterval
      clear(this.#timer)
      this.#timer = undefined
    }
    this.#started = false
  }

  /**
   * One tick. Public so a test drives it directly rather than waiting.
   *
   * Returns the agent ids it started, which is what makes the skip rules
   * observable without reading the log.
   */
  tick(): readonly string[] {
    const at = new Date(this.#now())
    const key = minuteKey(at)
    const started: string[] = []

    for (const agent of this.#o.agents()) {
      let expr: CronExpr
      try {
        expr = this.#exprFor(agent)
      } catch (e) {
        // A manifest that reached here with a bad expression is a bug — the
        // schema validates it at load. Logged and skipped rather than allowed to
        // stop every other agent's schedule.
        log.error(
          { agentId: agent.agentId, schedule: agent.schedule, err: e instanceof Error ? e.message : String(e) },
          'scheduler: unusable expression, skipping this agent',
        )
        continue
      }

      if (!cronMatches(expr, at)) continue
      if (this.#fired.get(agent.agentId) === key) continue

      // Claimed BEFORE the run starts, in memory AND in the log. If startRun
      // throws — or the process dies between the claim and the start — the
      // minute stays claimed: a job that cannot start must not be retried on
      // every tick, nor re-fired by the next reboot.
      this.#fired.set(agent.agentId, key)
      this.#o.store.append({
        type: 'run.scheduled',
        agentId: agent.agentId,
        payload: { schemaVersion: 1, agentId: agent.agentId, schedule: agent.schedule, minute: key },
      })

      if (this.#o.isBusy(agent.agentId)) {
        log.warn(
          { agentId: agent.agentId, schedule: agent.schedule, minute: key },
          'scheduler: skipped, the agent already has a run in flight',
        )
        continue
      }

      try {
        const runId = this.#o.startRun(agent.agentId, scheduledInput(agent.agentId, agent.schedule, key))
        started.push(agent.agentId)
        log.info({ agentId: agent.agentId, schedule: agent.schedule, minute: key, runId }, 'scheduler: started a run')
      } catch (e) {
        log.error(
          { agentId: agent.agentId, minute: key, err: e instanceof Error ? e.message : String(e) },
          'scheduler: could not start the run',
        )
      }
    }

    return started
  }

  /**
   * True while the tick is installed.
   *
   * Observable because "is the scheduler actually ticking?" is a question an
   * operator has, and because a kernel that built a scheduler and never started
   * it would look identical from the outside otherwise — the schedules would
   * simply never fire.
   */
  get running(): boolean {
    return this.#timer !== undefined
  }

  /** What the scheduler believes, for status and for tests. */
  diagnostics(): readonly { agentId: string; schedule: string; lastFiredMinute: string | undefined }[] {
    return this.#o.agents().map((a) => ({
      agentId: a.agentId,
      schedule: a.schedule,
      lastFiredMinute: this.#fired.get(a.agentId),
    }))
  }

  #exprFor(agent: ScheduledAgent): CronExpr {
    const cached = this.#compiled.get(agent.schedule)
    if (cached !== undefined) return cached
    const expr = parseCron(agent.schedule)
    this.#compiled.set(agent.schedule, expr)
    return expr
  }

  /**
   * Recover the last fired minute per agent from the log.
   *
   * A scheduled run is identifiable by its prompt, which carries the minute it
   * fired for. Reading it back is what makes dedupe survive a restart — and it
   * is also why the minute is in the prompt rather than only in a local variable.
   */
  /**
   * Recover the last fired minute per agent from the log.
   *
   * This is what makes dedupe survive a restart. Without it the claim would live
   * only in memory and a restart inside a fired minute would be the one reliable
   * way to run a job twice.
   */
  #seedFromLog(): void {
    for (const row of this.#o.store.query({ type: 'run.scheduled' })) {
      const payload = JSON.parse(row.payload) as { agentId?: string; minute?: string }
      if (typeof payload.agentId !== 'string' || typeof payload.minute !== 'string') continue
      // Rows arrive in seq order, so the last one wins.
      this.#fired.set(payload.agentId, payload.minute)
    }
  }
}
