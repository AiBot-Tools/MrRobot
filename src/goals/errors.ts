// The goal path's two failures, apart from writer.ts so the typed pmmcp calls
// (pmmcp.ts) can throw them without importing the writer that imports them.

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
