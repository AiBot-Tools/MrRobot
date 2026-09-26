// Eval harness types.
//
// The harness exists for one decision a human has to make and code may not:
// whether a model is good enough to orchestrate. CLAUDE.md: "`orchestrator:
// true` is set by the human after the eval harness, never by code." So this
// produces evidence, never a verdict about authority.
//
// Two rules shape every type here, both from docs/design/sectors/executive.md
// §8.1:
//
//   SCORED FROM THE LOG, NEVER FROM THE CLAIMS. An Observation is built from
//   event rows. The model's own final text is present as `claims`, named that
//   way on purpose, and no check may treat it as evidence of anything having
//   happened — only as something to be contradicted by the log.
//
//   A CHECK THAT CANNOT RUN SAYS SO. `n/a` is a first-class verdict, distinct
//   from `pass`. Four of the designed CEO checks need delegation events the
//   kernel does not yet emit; reporting those as passes would turn an
//   unfinished kernel into a clean scorecard, which is the single most
//   expensive lie this harness could tell. The count of `n/a` checks is part of
//   every report.

import type { EventRow } from '../events/chain.js'

/**
 * A gate must hold: one failure fails the case, whatever the score says.
 * A scorer is graded in [0,1] and compared against a threshold.
 */
export type CheckKind = 'gate' | 'score'

/** `n/a` means the run contained nothing this check could examine. */
export type CheckVerdict = 'pass' | 'fail' | 'n/a'

export interface CheckOutcome {
  readonly verdict: CheckVerdict
  /** Only for `score` checks that ran. In [0,1]. */
  readonly score?: number
  /** One line an operator can act on. Names the evidence, not the conclusion. */
  readonly detail: string
}

export interface CheckResult extends CheckOutcome {
  readonly id: string
  readonly kind: CheckKind
  readonly title: string
}

/** What a case says must be observable. Declared, never inferred from prose. */
export interface Expectation {
  /** Hard ceilings. A run that exceeds one has failed regardless of output. */
  readonly maxCostMicroUsd?: number
  readonly maxLlmCalls?: number
  readonly maxToolCalls?: number
  /** The run must finish with one of these. Default: `['ok']`. */
  readonly status?: readonly ('ok' | 'error' | 'killed' | 'denied')[]
  /** At least this many successful tool calls must appear in the log. */
  readonly minToolCalls?: number
  /** At least this many child runs carrying a goalId. */
  readonly minChildRuns?: number
  /** Irreversible tools the plan named in advance, for the approvals bound. */
  readonly irreversibleInventory?: readonly string[]
  /** Escalations the case allows on top of the inventory. */
  readonly allowedEscalations?: number
  /** Strings that must appear nowhere in the run's slice of the log. */
  readonly forbiddenInLog?: readonly string[]
}

export interface EvalCase {
  readonly id: string
  /** What is being measured, in one line. */
  readonly title: string
  readonly agentId: string
  /** The operator objective handed to the run. */
  readonly input: string
  readonly expect: Expectation
}

/**
 * Everything a check may look at.
 *
 * `rows` is the run's own slice of the event log in seq order. `claims` is the
 * model's last message — untrusted by construction: it is what the scorers are
 * there to contradict.
 */
export interface Observation {
  readonly runId: string
  readonly agentId: string
  readonly rows: readonly EventRow[]
  /**
   * Every row in the log. A claim naming a CHILD run resolves outside this
   * run's slice, so ref resolution needs the whole thing; `rows` stays the
   * slice, because a check about THIS run must not be satisfied by another's
   * events.
   */
  readonly log: readonly EventRow[]
  readonly claims: string
  readonly expect: Expectation
}

export interface Check {
  readonly id: string
  readonly kind: CheckKind
  readonly title: string
  /** Why this check exists. Read in the report next to a failure. */
  readonly why: string
  run(observation: Observation): CheckOutcome
}

export interface CaseResult {
  readonly caseId: string
  readonly title: string
  readonly runId: string
  readonly checks: readonly CheckResult[]
  /** Ids of failed gates. Empty means the case is admissible. */
  readonly gatesFailed: readonly string[]
  /** Ids of checks that could not run. Reported, never counted as passes. */
  readonly notApplicable: readonly string[]
  /** Mean of the scorers that ran, or undefined when none did. */
  readonly score: number | undefined
}

export interface SuiteResult {
  readonly cases: readonly CaseResult[]
  readonly gatesFailed: number
  readonly notApplicable: number
  readonly score: number | undefined
}
