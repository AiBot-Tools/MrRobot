// The installer's last line: its own exit code and what that run's end was.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), once the
//   flags were taken (usage and --help print none). npm 10 re-raises a SIGINT
//   it forwarded, so `npm run aos-install` can end with 130 for a run the
//   installer finished: this line is the run's word (README), so it names how
//   this run ended, never only what its code can mean.
//
//   Every Ending is built here: the gate's outcome (outcomeEnding), a refusal
//   or a stop before the gate (refusedEnding, stoppedEnding), a signal that
//   ended the run before the stopped window ever opened (signalEnding, whose
//   words, signalEnded, are also what the installer says as the signal
//   comes, so the two lines match), and a defect (defectEnding). `reported`
//   says whether the end report (S8) was printed: a line points at "the end
//   report above" only then, and at "above" (the lines that said why)
//   otherwise. EOF and an interrupt at a
//   question are told apart, and either at the jobs check (its question, its
//   wait or a count) is named as the check's; an interrupt may have been the
//   terminal's Ctrl-C, a SIGINT, a SIGHUP or a SIGTERM (each answers the open
//   prompt), so it is "interrupted", never named Ctrl-C. Pure: nothing is
//   printed here.

import type { GateOutcome, Phase } from '../../src/install/gate.js'
import { signalWords, type HandledSignal } from './signals.js'

/** How the run ended: the installer's own exit code, and what it means for this run. */
export interface Ending {
  readonly code: number
  readonly why: string
}

const phases = (applied: readonly Phase[]): string => `the ${applied.join(' and ')} steps were applied`

/** What was done before the run ended short of the window: nothing, or the phases applied (the end report lists them). */
const beforeIt = (applied: readonly Phase[], reported: boolean): string =>
  applied.length === 0 ? 'nothing was changed' : `nothing live was done (${phases(applied)}: see the end report${reported ? ' above' : ''})`

/** The gate's outcome in words. `reported`: the end report was printed after it. */
export function outcomeEnding(outcome: GateOutcome, reported: boolean): Ending {
  const report = reported ? 'see the end report above' : 'see above'
  switch (outcome.kind) {
    case 'refused':
      return { code: 2, why: 'refused before any change: see above' }
    case 'nothing-to-do':
      return { code: 0, why: 'nothing was done: nothing to do, or nothing the installer can do now, as said above' }
    case 'dry-run':
      return { code: 0, why: 'a dry run: nothing was changed, stopped or started' }
    case 'not-a-terminal':
      return { code: 3, why: 'changes are needed, but stdin is not a terminal: nothing was changed' }
    case 'declined':
      return { code: 0, why: `declined: ${beforeIt(outcome.applied, reported)}` }
    case 'aborted': {
      // The jobs check is its question, its wait and its counts: an end there is named as the check's, whichever it was.
      const where = outcome.at === 'jobs' ? 'at the jobs check' : 'at a question'
      if (outcome.by === 'eof') return { code: outcome.exitCode, why: `aborted, the input ended ${where}: ${beforeIt(outcome.applied, reported)}` }
      if (outcome.by === 'interrupt') return { code: outcome.exitCode, why: `aborted, interrupted ${where}: ${beforeIt(outcome.applied, reported)}` }
      if (outcome.by === 'quit') return { code: outcome.exitCode, why: `aborted at the jobs wait (q): ${beforeIt(outcome.applied, reported)}` }
      return { code: outcome.exitCode, why: `pmmcp's jobs could not be counted, so nothing was stopped: ${report}` }
    }
    case 'failed':
      if (outcome.exitCode === 2) return { code: 2, why: `refused before any change: ${report}` }
      if (outcome.exitCode === 4) return { code: 4, why: `a live step failed, and pmmcp is not in its intended state: ${report}` }
      return { code: outcome.exitCode, why: `a step failed, and the state is as ${reported ? 'the end report above says' : 'said above'}` }
    case 'done':
      return { code: 0, why: `done: ${report}` }
  }
}

/** A refusal before the gate (the preflight, the lock, the config, the .env screen, discovery's stops): exit 2. */
export function refusedEnding(): Ending {
  return { code: 2, why: 'refused before any change: see above' }
}

/** Discovery or the TUI check stopped by a defect (a leak, a halted runner, a refusal of the runner's only a defect makes, discovery's own): exit 1, before any change. */
export function stoppedEnding(): Ending {
  return { code: 1, why: 'stopped before any change: see above' }
}

/**
 * What a signal that ends the run is, in words: said as it comes and again
 * as the last line's why. It ends the run only before the stopped window
 * ever opened (signals.ts: inside it a signal is trapped, and from its first
 * opening until the end report it is held, and the run ends with the gate's
 * code), so that is where it says it came.
 */
export function signalEnded(signal: HandledSignal): string {
  return `ended by ${signal === 'SIGINT' ? 'SIGINT (Ctrl-C)' : signalWords(signal)} before the stopped window opened: nothing more was done`
}

/** A signal that ended the run before the stopped window ever opened: 128 + its number. */
export function signalEnding(code: number, signal: HandledSignal): Ending {
  return { code, why: signalEnded(signal) }
}

/** A defect main did not expect: 4 once the window had opened (pmmcp may be stopped), 1 before. No end report is printed then. */
export function defectEnding(code: 1 | 4): Ending {
  return {
    code,
    why: code === 4 ? 'a defect (report it) once the stopped window had opened: pmmcp may be stopped, see above' : 'a defect (report it) before the stopped window: see above',
  }
}

/** The installer's last line. */
export function exitLine(ending: Ending): string {
  return `aos-install: exit ${String(ending.code)}: ${ending.why}`
}
