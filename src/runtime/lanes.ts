// Lanes — who may run, and how many at once.
//
// Two constraints, and they are not the same constraint:
//
//   Per agent, strictly serial. One agent is one conversation with one
//   memory and one workspace; two of its runs in flight at once would
//   interleave tool calls against the same state, and the gate authorises a
//   call for a run, not for a moment in time. Serial per agent is what makes
//   "this run did that" a true sentence.
//
//   Per lane, a global cap. `main` and `subagent` are separate pools so a
//   fan-out of delegated work cannot starve the CEO: a burst of subagents
//   fills the subagent pool and leaves every main slot free.
//
// The order matters. A task takes its AGENT lane first and only then queues
// for a global slot. The other way round, a task would hold a scarce global
// slot while waiting for an agent that is busy — the slot doing nothing while
// other agents queue behind it.
//
// Admission is FIFO in both places. Without it a steadily-arriving agent can
// keep jumping a waiter that has been queued since the start, and a run that
// never begins is worse than a run that is slow.
//
// Everything here is counters and promises. There are no timers and no
// timestamps, so its behaviour is deterministic and its tests cannot flake.

import { KernelError } from '../errors.js'

export const LANE_NAMES = ['main', 'subagent'] as const
export type LaneName = (typeof LANE_NAMES)[number]

/** A queued task was aborted before it started. It never ran. */
export class LaneAborted extends KernelError {
  readonly agentId: string

  constructor(agentId: string, where: string) {
    super('AOS_LANE_ABORTED', `run for ${agentId} was aborted while waiting for ${where}`, undefined)
    this.agentId = agentId
  }
}

type Release = () => void

interface Waiter {
  readonly resolve: (release: Release) => void
  readonly reject: (error: unknown) => void
  readonly onAbort: (() => void) | undefined
  readonly signal: AbortSignal | undefined
}

/**
 * A counting semaphore with FIFO admission and abortable waiting.
 *
 * `release` is idempotent: a double release would hand out a permit that was
 * never taken, which is how a cap silently becomes no cap at all.
 *
 * The already-aborted check in `acquire` is load-bearing rather than a
 * shortcut. A listener added to a signal that has ALREADY fired never runs,
 * so an aborted waiter that reached the queue would sit there for ever with
 * nothing left to wake it.
 *
 * @internal Exported for its own tests; the kernel uses `Lanes`.
 */
export class Semaphore {
  readonly #cap: number
  #active = 0
  #waiters: Waiter[] = []

  constructor(cap: number) {
    if (!Number.isInteger(cap) || cap < 1) {
      throw new KernelError('AOS_CONFIG', `lane capacity must be a positive integer, got ${String(cap)}`)
    }
    this.#cap = cap
  }

  get cap(): number {
    return this.#cap
  }

  get active(): number {
    return this.#active
  }

  get queued(): number {
    return this.#waiters.length
  }

  get idle(): boolean {
    return this.#active === 0 && this.#waiters.length === 0
  }

  acquire(agentId: string, where: string, signal?: AbortSignal): Promise<Release> {
    if (signal?.aborted === true) return Promise.reject(new LaneAborted(agentId, where))

    if (this.#active < this.#cap) {
      this.#active++
      return Promise.resolve(this.#makeRelease())
    }

    return new Promise<Release>((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        signal,
        onAbort:
          signal === undefined
            ? undefined
            : () => {
                // Removed from the queue, so the task is never called at all.
                this.#waiters = this.#waiters.filter((w) => w !== waiter)
                reject(new LaneAborted(agentId, where))
              },
      }
      if (signal !== undefined && waiter.onAbort !== undefined) {
        signal.addEventListener('abort', waiter.onAbort, { once: true })
      }
      this.#waiters.push(waiter)
    })
  }

  #makeRelease(): Release {
    let released = false
    return () => {
      if (released) return
      released = true

      const next = this.#waiters.shift()
      if (next === undefined) {
        this.#active--
        return
      }
      // The permit passes straight to the next waiter: #active is unchanged
      // because one holder is simply replaced by another.
      if (next.signal !== undefined && next.onAbort !== undefined) {
        next.signal.removeEventListener('abort', next.onAbort)
      }
      next.resolve(this.#makeRelease())
    }
  }
}

export interface LaneCaps {
  readonly main: number
  readonly subagent: number
}

export interface EnqueueRequest {
  readonly agentId: string
  readonly lane: LaneName
  /** Aborting before the task starts removes it from the queue unrun. */
  readonly signal?: AbortSignal | undefined
}

export interface LaneReport {
  readonly active: number
  readonly queued: number
  readonly cap: number
}

export interface AgentReport {
  readonly agentId: string
  /** True while one of this agent's runs holds its serial lane. */
  readonly active: boolean
  readonly queued: number
}

export interface LaneDiagnostics {
  readonly lanes: Readonly<Record<LaneName, LaneReport>>
  readonly agents: readonly AgentReport[]
}

export class Lanes {
  readonly #lanes: Record<LaneName, Semaphore>
  readonly #agents = new Map<string, Semaphore>()

  constructor(caps: LaneCaps) {
    this.#lanes = { main: new Semaphore(caps.main), subagent: new Semaphore(caps.subagent) }
  }

  #agentLane(agentId: string): Semaphore {
    let lane = this.#agents.get(agentId)
    if (lane === undefined) {
      // Capacity one: this IS the serialisation.
      lane = new Semaphore(1)
      this.#agents.set(agentId, lane)
    }
    return lane
  }

  /**
   * Run `task` once its agent is free and its lane has a slot.
   *
   * @throws {LaneAborted} when the signal fires before the task starts. The
   *   task is not called; a task already running is not interrupted here,
   *   because stopping work in flight is the run loop's business, not the
   *   queue's.
   */
  async enqueue<T>(request: EnqueueRequest, task: () => Promise<T>): Promise<T> {
    const { agentId, lane, signal } = request

    const agentLane = this.#agentLane(agentId)

    // The prune is the OUTERMOST step, so it also runs when acquiring the
    // agent lane is what failed — an enqueue with an already-aborted signal
    // rejects before any inner block is entered, and would otherwise leave
    // the lane it just created in the map for ever.
    try {
      const releaseAgent = await agentLane.acquire(agentId, `the ${agentId} lane`, signal)
      try {
        const releaseSlot = await this.#lanes[lane].acquire(agentId, `a ${lane} slot`, signal)
        try {
          // Aborted between being admitted and starting: still never runs.
          if (signal?.aborted === true) throw new LaneAborted(agentId, `a ${lane} slot`)
          return await task()
        } finally {
          // `finally`, so a task that throws releases its slot. Otherwise one
          // failing run permanently shrinks the pool, and enough of them stop
          // the kernel with no error anywhere saying why.
          releaseSlot()
        }
      } finally {
        releaseAgent()
      }
    } finally {
      // Keep the map bounded: ephemeral agents come and go by the hundred.
      if (agentLane.idle) this.#agents.delete(agentId)
    }
  }

  diagnostics(): LaneDiagnostics {
    const agents: AgentReport[] = []
    for (const [agentId, lane] of this.#agents) {
      agents.push({ agentId, active: lane.active > 0, queued: lane.queued })
    }
    agents.sort((a, b) => a.agentId.localeCompare(b.agentId))

    return {
      lanes: {
        main: { active: this.#lanes.main.active, queued: this.#lanes.main.queued, cap: this.#lanes.main.cap },
        subagent: {
          active: this.#lanes.subagent.active,
          queued: this.#lanes.subagent.queued,
          cap: this.#lanes.subagent.cap,
        },
      },
      agents,
    }
  }
}
