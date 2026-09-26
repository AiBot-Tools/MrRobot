// Rendering an eval result for a human and for a file.
//
// The report's job is to be unflattering. Two numbers are always printed
// together: the score, and how many checks could not run. A score of 1.00 over
// four checks with twelve n/a is not a good result, and a report that shows only
// the first number invites exactly that misreading — which matters here, because
// the human reads this before deciding whether a model may orchestrate.

import type { CaseResult, SuiteResult } from './types.js'

const MARK: Record<string, string> = { pass: 'PASS', fail: 'FAIL', 'n/a': ' n/a' }

function fmtScore(score: number | undefined): string {
  return score === undefined ? '  —  ' : score.toFixed(2).padStart(5)
}

export function renderCase(result: CaseResult): string {
  const lines: string[] = []
  lines.push(`${result.caseId}  ${result.title}`)
  lines.push(`  run ${result.runId}`)
  for (const check of result.checks) {
    const score = check.score === undefined ? '' : ` [${check.score.toFixed(2)}]`
    lines.push(`  ${MARK[check.verdict] ?? '????'} ${check.id}${score}  ${check.detail}`)
  }
  // Same ordering rule as the suite summary: the verdict, then the number.
  lines.push(
    result.gatesFailed.length === 0
      ? `  gates: all passed   score ${fmtScore(result.score)}   ` +
        `did not run ${String(result.notApplicable.length)}`
      : `  gates: ${String(result.gatesFailed.length)} FAILED (${result.gatesFailed.join(', ')})   ` +
        `score ${fmtScore(result.score)}   did not run ${String(result.notApplicable.length)}`,
  )
  return lines.join('\n')
}

export function renderSuite(suite: SuiteResult): string {
  const lines = suite.cases.map(renderCase)
  const checks = suite.cases.flatMap((c) => c.checks)
  const scorersRun = checks.filter((c) => c.kind === 'score' && c.verdict !== 'n/a').length
  const scorersTotal = checks.filter((c) => c.kind === 'score').length
  lines.push('')

  // The verdict FIRST, then the number. A first draft printed "score 1.00" on
  // the line above "3 gate failures", because the only scorer that ran happened
  // to pass — which is how a run that proved nothing reads as a good result. A
  // score is never the headline here.
  lines.push(
    suite.gatesFailed === 0
      ? 'GATES: all passed. This is evidence for a human decision, not the decision.'
      : `GATES: ${String(suite.gatesFailed)} FAILED — this run is not evidence that the model ` +
        'may orchestrate.',
  )
  lines.push(
    `score ${fmtScore(suite.score)} over ${String(scorersRun)} of ${String(scorersTotal)} scorer(s) ` +
      `that ran; ${String(suite.notApplicable)} of ${String(checks.length)} checks did not run`,
  )
  if (suite.notApplicable > 0) {
    lines.push(
      'A check that could not run is NOT a pass. Each one above says what would ' +
        'make it runnable; until then the score covers less than the check list suggests.',
    )
  }
  lines.push(`${String(suite.cases.length)} case(s), ${String(checks.length)} check(s)`)
  return lines.join('\n')
}

/** 0 only when every gate that ran passed. Scores never decide the exit code. */
export function exitCode(suite: SuiteResult): number {
  return suite.gatesFailed === 0 ? 0 : 1
}

/** The machine-readable form, for recording a baseline next to a commit. */
export function toJson(suite: SuiteResult): string {
  return `${JSON.stringify(suite, null, 2)}\n`
}
