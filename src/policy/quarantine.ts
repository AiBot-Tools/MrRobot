// Quarantine (invariant 3).
//
// Some tools return content the kernel will not let a run act on until a
// person has looked at it — a web page, an inbound message, anything an
// outsider chose the words of. hold() takes that output out of the run's
// reach; release() puts it back, and marks the run tainted from that moment.
//
// The taint is the whole point. Once a run has read attacker-influenced text,
// its later decisions are suspect, so the gate stops letting it write without
// a human (T13 rule 5). Releasing without tainting would launder untrusted
// content into a trusted run, which is the exact failure quarantine exists to
// prevent — so release does both or neither.
//
// Held output lives in memory only and is never written to the log. The log
// records that a hold happened, its id, the tool and the reason; the content
// itself is available to the operator through the control plane while the
// process lives. A crash loses the content and keeps the record, which is the
// right way round: the record is what an audit needs.
//
// Phase 0 keeps holds in memory. rebuildFromLog() throws rather than
// returning an empty set, because "nothing is held" after a restart would let
// a run proceed as though a human had reviewed something they never saw.

import { randomUUID } from 'node:crypto'

import { assertHumanActor, type HumanActor } from '../control/actor.js'
import { ConfigError } from '../errors.js'
import type { EventRow } from '../events/chain.js'
import { projectRecovery, type UnreleasedHold } from '../events/projections.js'
import type { BoundedOutput } from '../events/bound.js'
import type { EventStore } from '../events/store.js'

export interface Hold {
  readonly holdId: string
  readonly runId: string
  readonly toolRef: string
  readonly reason: string
  readonly heldAt: number
}

export interface ReleasedHold extends Hold {
  readonly output: BoundedOutput
  readonly byConnectionId: string
}

interface Entry {
  readonly hold: Hold
  readonly output: BoundedOutput
  released: boolean
}

export interface QuarantineOptions {
  readonly store: EventStore
  /** Called when a run becomes tainted, so the runtime can update its scope. */
  readonly onTainted?: (runId: string) => void
}

export class Quarantine {
  readonly #store: EventStore
  readonly #entries = new Map<string, Entry>()
  readonly #tainted = new Set<string>()
  readonly #onTainted: ((runId: string) => void) | undefined

  constructor(options: QuarantineOptions) {
    this.#store = options.store
    this.#onTainted = options.onTainted
  }

  /** Withhold a tool's output from the run until a human releases it. */
  hold(runId: string, toolRef: string, output: BoundedOutput, reason = 'tool output is quarantined'): Hold {
    const holdId = `hold_${randomUUID()}`
    const hold: Hold = { holdId, runId, toolRef, reason, heldAt: Date.now() }
    this.#entries.set(holdId, { hold, output, released: false })

    this.#store.append({
      type: 'quarantine.held',
      runId,
      payload: { schemaVersion: 1, holdId, toolRef, reason },
    })
    return hold
  }

  /** Holds still awaiting a decision. Content is deliberately not included. */
  pending(): readonly Hold[] {
    return [...this.#entries.values()].filter((e) => !e.released).map((e) => e.hold)
  }

  /**
   * Release held output to the run. Requires a human, and taints the run.
   *
   * @throws {TypeError} if `actor` is not a genuine HumanActor.
   * @throws {ConfigError} if the hold is unknown or already released.
   */
  release(holdId: string, actor: HumanActor): ReleasedHold {
    assertHumanActor(actor, 'releasing quarantined output')

    const entry = this.#entries.get(holdId)
    if (entry === undefined) {
      throw new ConfigError(`quarantine hold ${holdId} is unknown`)
    }
    if (entry.released) {
      throw new ConfigError(`quarantine hold ${holdId} has already been released`)
    }

    entry.released = true
    // Taint before the event is written, so no ordering of observers can see
    // released content attached to a run that still reads clean.
    this.#tainted.add(entry.hold.runId)
    this.#onTainted?.(entry.hold.runId)

    this.#store.append({
      type: 'quarantine.released',
      runId: entry.hold.runId,
      payload: { schemaVersion: 1, holdId, byConnectionId: actor.connectionId },
    })

    return { ...entry.hold, output: entry.output, byConnectionId: actor.connectionId }
  }

  /**
   * Read held output. Refused while the hold stands: this is what makes the
   * hold a hold rather than a label.
   */
  read(holdId: string): BoundedOutput {
    const entry = this.#entries.get(holdId)
    if (entry === undefined) {
      throw new ConfigError(`quarantine hold ${holdId} is unknown`)
    }
    if (!entry.released) {
      throw new ConfigError(
        `quarantine hold ${holdId} has not been released; a human must review it first`,
      )
    }
    return entry.output
  }

  /** Whether this run has been tainted by a release. */
  isTainted(runId: string): boolean {
    return this.#tainted.has(runId)
  }
}

/**
 * Rebuild outstanding holds from the event log after a restart. Phase 1.
 *
 * It throws rather than returning an empty set: a run resumed against an
 * empty projection would proceed as though a human had reviewed content they
 * never saw.
 */
/**
 * Which holds were still standing when the process stopped.
 *
 * Read from the log, and returned as records only — a rebuilt hold can never be
 * RELEASED. Held content lives in memory and is never written to the log (see
 * this file's header: the record is what an audit needs, and putting
 * attacker-chosen text in an immutable log forever is a worse trade). A crash
 * therefore destroys the content and keeps the record.
 *
 * So there is nothing to give a run back, and boot ends each of these with a
 * `quarantine.abandoned` row rather than a `quarantine.released` one. The
 * distinction is the point: released means a person read it and allowed it,
 * abandoned means nobody ever saw it. Recording the first when the second
 * happened would be a false claim of human review, in the one place that cannot
 * be edited afterwards.
 */
export function rebuildFromLog(rows: readonly EventRow[]): readonly UnreleasedHold[] {
  return projectRecovery(rows).unreleasedHolds
}
