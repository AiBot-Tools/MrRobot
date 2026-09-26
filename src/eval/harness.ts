// The harness: drive a case, then score it from the log.
//
// Two halves, deliberately separate. `evaluate` is pure — an Observation and a
// check set in, a CaseResult out — so the scoring can be tested against
// synthetic observations including the cheat fixtures, with no kernel, no
// provider and no clock. `runCase` is the driver, and it goes through the
// CONTROL PLANE: the same loopback socket, bearer token and `run.start` command
// `aos run` uses. Nothing in the harness reaches into the kernel's internals,
// which is what lets one command score a doubled kernel in the test suite and
// the operator's live daemon on the Mac without behaving differently.
//
// The scoring reads the log after the run has finished, read-only. It never asks
// the run how it went.

import { connectControl } from '../cli/client.js'
import { observe, readRunRows, readWholeLog } from './observe.js'
import type {
  CaseResult,
  Check,
  CheckResult,
  EvalCase,
  Observation,
  SuiteResult,
} from './types.js'

/** Where a case is run and where its log can be read. */
export interface EvalTarget {
  readonly port: number
  readonly token: string
  /** The daemon's events.db. Reopened read-only, never written. */
  readonly dbPath: string
  /**
   * Ceiling on ONE RUN. A case that hangs must fail, not stall the suite.
   *
   * Separate from the connect timeout on purpose: they are different failures
   * with different right answers. A frontier model can legitimately take minutes,
   * while a loopback handshake that has not completed in ten seconds is a daemon
   * that is not there — and one number for both means a short run ceiling makes
   * the harness unable to connect at all.
   */
  readonly timeoutMs?: number
  readonly connectTimeoutMs?: number
}

export const DEFAULT_CASE_TIMEOUT_MS = 120_000
export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000

/** Score one observation. Pure: same input, same result, no clock, no IO. */
export function evaluate(
  evalCase: Pick<EvalCase, 'id' | 'title'>,
  observation: Observation,
  checks: readonly Check[],
): CaseResult {
  const results: CheckResult[] = checks.map((check) => {
    const outcome = check.run(observation)
    return {
      id: check.id,
      kind: check.kind,
      title: check.title,
      verdict: outcome.verdict,
      ...(outcome.score === undefined ? {} : { score: outcome.score }),
      detail: outcome.detail,
    }
  })

  const gatesFailed = results
    .filter((r) => r.kind === 'gate' && r.verdict === 'fail')
    .map((r) => r.id)
  const notApplicable = results.filter((r) => r.verdict === 'n/a').map((r) => r.id)
  const scores = results
    .filter((r) => r.kind === 'score' && r.verdict !== 'n/a' && r.score !== undefined)
    .map((r) => r.score as number)

  return {
    caseId: evalCase.id,
    title: evalCase.title,
    runId: observation.runId,
    checks: results,
    gatesFailed,
    notApplicable,
    // undefined, not 1: a suite where every scorer was n/a has measured nothing,
    // and a default of "perfect" is how that becomes a passing grade.
    score: scores.length === 0 ? undefined : scores.reduce((a, b) => a + b, 0) / scores.length,
  }
}

export function summarise(cases: readonly CaseResult[]): SuiteResult {
  const scores = cases.map((c) => c.score).filter((s): s is number => s !== undefined)
  return {
    cases,
    gatesFailed: cases.reduce((n, c) => n + c.gatesFailed.length, 0),
    notApplicable: cases.reduce((n, c) => n + c.notApplicable.length, 0),
    score: scores.length === 0 ? undefined : scores.reduce((a, b) => a + b, 0) / scores.length,
  }
}

export interface RunRecord {
  readonly runId: string
  readonly finished: Record<string, unknown>
}

/**
 * Start a case's run over the control plane and wait for it to finish.
 *
 * Buffered, like the CLI: the daemon broadcasts as it appends, so a fast run can
 * finish before the reply naming its id has been parsed, and a listener matching
 * only on an id it does not yet know would wait for an event that already went
 * past.
 */
export async function startAndWait(target: EvalTarget, evalCase: EvalCase): Promise<RunRecord> {
  const timeoutMs = target.timeoutMs ?? DEFAULT_CASE_TIMEOUT_MS
  const client = await connectControl({
    port: target.port,
    token: target.token,
    timeoutMs: target.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
  })
  try {
    const early = new Map<string, Record<string, unknown>>()
    let mine: string | undefined
    let settle: (payload: Record<string, unknown>) => void = () => undefined
    const finished = new Promise<Record<string, unknown>>((resolve) => {
      settle = resolve
    })
    client.onEvent((event) => {
      if (event.type !== 'run.finished') return
      const payload = event.payload as Record<string, unknown> | null
      if (payload === null || typeof payload['runId'] !== 'string') return
      if (payload['runId'] === mine) settle(payload)
      else early.set(payload['runId'], payload)
    })

    const started = (await client.call('run.start', {
      agentId: evalCase.agentId,
      input: evalCase.input,
    })) as { runId: string }
    mine = started.runId
    const already = early.get(started.runId)
    if (already !== undefined) settle(already)

    const timeout = new Promise<Record<string, unknown>>((_, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`eval case ${evalCase.id}: run ${started.runId} did not finish`)),
        timeoutMs,
      )
      timer.unref?.()
    })
    const payload = await Promise.race([finished, timeout])
    return { runId: started.runId, finished: payload }
  } finally {
    client.close()
  }
}

/** Drive one case and score it. */
export async function runCase(
  target: EvalTarget,
  evalCase: EvalCase,
  checks: readonly Check[],
): Promise<CaseResult> {
  const record = await startAndWait(target, evalCase)
  // Read-only, after the fact. The run's own slice for claims about this run,
  // and the whole log for ids that belong to its children.
  const rows = readRunRows(target.dbPath, record.runId)
  const log = readWholeLog(target.dbPath)
  const observation = observe({
    runId: record.runId,
    agentId: evalCase.agentId,
    rows,
    log,
    expect: evalCase.expect,
  })
  return evaluate(evalCase, observation, checks)
}

/** Drive a suite in declaration order. Sequential on purpose: one operator, one
 * machine, and a concurrent suite would make every child-run count ambiguous. */
export async function runSuite(
  target: EvalTarget,
  cases: readonly EvalCase[],
  checks: readonly Check[],
): Promise<SuiteResult> {
  const results: CaseResult[] = []
  for (const evalCase of cases) {
    results.push(await runCase(target, evalCase, checks))
  }
  return summarise(results)
}
