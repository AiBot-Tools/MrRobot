// What a signal does to the installer, by where the run is.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), from its
//   SIGINT, SIGHUP and SIGTERM handlers, with what the run is doing at that
//   moment. The decision is pure (onSignal) and so is the exit code of a
//   defect (defectExit); handleSignal applies one through the effects it is
//   handed, so each branch is tested without a terminal, a found install or
//   a real signal.
//
//   In order:
//     A repeat of the signal handled last, within REPEAT_MS of it, is the
//       same one delivered twice and does nothing: on macOS /bin/sh is bash,
//       which execs npm's one script command, and npm forwards the Ctrl-C
//       the terminal already sent to the whole foreground group, so each
//       Ctrl-C arrives twice, about a millisecond apart. A second one would
//       find the prompt the first answered closed and end the run.
//     A prompt or the jobs wait open: it is that prompt's answer (the gate
//       and the applier read it as a no or an abort).
//     Inside the stopped window (the applier's `window`, from L1's start to
//       L5's end): trapped, whatever the signal. The steps there run in
//       sessions of their own (A3), so neither a Ctrl-C nor a closed
//       terminal reaches them, and the installer goes on to the start and
//       its checks; it says so at once, and again at the end.
//     After the window, once it had opened in this run, until the end report
//       is printed (`reporting`: windowChanged sets it at the first opening,
//       the entry point clears it once the report is out): held. Those
//       last checks (.env's ACL, the facts again) and the report say
//       whether pmmcp is left stopped and what is left to do, so the run
//       goes on to them, and ends with the gate's own code (a 4 stays a 4);
//       it says so at once, and again at the end.
//     While pmmcp's jobs are counted: the count ends, and the gate ends the
//       run (130).
//     Anywhere else (before the window ever opened): the run ends at once,
//       with the status the signal's own default would give a shell (128 +
//       its number: 130, 129, 143), and the lock is released. Then nothing
//       is half done that a re-run does not pick up from the state on disk.
//
//   A defect (an error main did not expect) exits 4 once the window had
//   opened (pmmcp may be stopped, and the manual start is printed), 1 before.

/** The signals the installer handles. */
export type HandledSignal = 'SIGINT' | 'SIGHUP' | 'SIGTERM'

export const HANDLED_SIGNALS: readonly HandledSignal[] = ['SIGINT', 'SIGHUP', 'SIGTERM']

/** The status a signal's default action would leave for a shell: 128 + its number. */
export const SIGNAL_EXIT: Readonly<Record<HandledSignal, number>> = { SIGINT: 130, SIGHUP: 129, SIGTERM: 143 }

/** Within this many milliseconds of the signal handled last, the same signal is that one delivered again. */
export const REPEAT_MS = 100

/** What the run is doing when a signal arrives. */
export interface SignalView {
  /** A question or the jobs wait is open, and takes the signal as its answer. */
  readonly promptOpen: boolean
  /** Inside the stopped window. */
  readonly windowOpen: boolean
  /** The window opened in this run, and the end report is not printed yet. */
  readonly reporting: boolean
  /** stop-pmmcp-server.sh --jobs runs. */
  readonly counting: boolean
  /** The signal handled last (a repeat is not one), and when, in milliseconds. */
  readonly last: { readonly signal: HandledSignal; readonly at: number } | undefined
}

export type SignalDecision =
  | { readonly kind: 'repeat' }
  | { readonly kind: 'answered' }
  | { readonly kind: 'trapped' }
  | { readonly kind: 'held' }
  | { readonly kind: 'count-aborted' }
  | { readonly kind: 'exit'; readonly code: number }

/** What `signal`, arriving at `now`, does. See the contract above. */
export function onSignal(view: SignalView, signal: HandledSignal, now: number): SignalDecision {
  const last = view.last
  if (last !== undefined && last.signal === signal && now >= last.at && now - last.at < REPEAT_MS) return { kind: 'repeat' }
  if (view.promptOpen) return { kind: 'answered' }
  if (view.windowOpen) return { kind: 'trapped' }
  if (view.reporting) return { kind: 'held' }
  if (view.counting) return { kind: 'count-aborted' }
  return { kind: 'exit', code: SIGNAL_EXIT[signal] }
}

/** The exit code of a defect: 4 once the stopped window had opened (pmmcp may be stopped), 1 before. */
export function defectExit(windowOpened: boolean): 1 | 4 {
  return windowOpened ? 4 : 1
}

/** Where the run is as to the stopped window. */
export interface WindowMarks {
  windowOpen: boolean
  /** The window opened at some point in this run: a defect exits 4 from then on (defectExit). */
  windowOpened: boolean
  /** From the window's first opening until the end report is printed: a signal outside the window is held. */
  reporting: boolean
}

/**
 * The applier opened (true) or closed (false) the stopped window (its
 * `window` callback). The first opening sets `windowOpened` and `reporting`,
 * which a close leaves set: after the window the run still owes its report.
 */
export function windowChanged(marks: WindowMarks, open: boolean): void {
  marks.windowOpen = open
  if (!open) return
  marks.windowOpened = true
  marks.reporting = true
}

/** The run's side of the decision, kept between signals. */
export interface SignalState {
  readonly windowOpen: boolean
  readonly reporting: boolean
  readonly counting: boolean
  last: { readonly signal: HandledSignal; readonly at: number } | undefined
  /** Every signal the window trapped, for the end of the run. */
  readonly trapped: Set<HandledSignal>
  /** Every signal held after the window until the end report, for the end of the run. */
  readonly held: Set<HandledSignal>
}

/** How a decision is carried out. */
export interface SignalEffects {
  promptOpen(): boolean
  /** Answer the open prompt or wait as interrupted. */
  answer(): void
  /** Say that the window goes on. */
  trapped(signal: HandledSignal): void
  /** Say that the run goes on to its end report. */
  held(signal: HandledSignal): void
  /** End the jobs count. */
  abortCount(): void
  /** End the run now. */
  exit(code: number, signal: HandledSignal): void
}

/** Decide what `signal` does and do it; returns the decision. */
export function handleSignal(state: SignalState, signal: HandledSignal, now: number, effects: SignalEffects): SignalDecision {
  const decision = onSignal({ promptOpen: effects.promptOpen(), windowOpen: state.windowOpen, reporting: state.reporting, counting: state.counting, last: state.last }, signal, now)
  if (decision.kind === 'repeat') return decision
  state.last = { signal, at: now }
  if (decision.kind === 'answered') effects.answer()
  else if (decision.kind === 'trapped') {
    state.trapped.add(signal)
    effects.trapped(signal)
  } else if (decision.kind === 'held') {
    state.held.add(signal)
    effects.held(signal)
  } else if (decision.kind === 'count-aborted') effects.abortCount()
  else effects.exit(decision.code, signal)
  return decision
}

/** What a trapped signal is, in words. */
export function signalWords(signal: HandledSignal): string {
  return signal === 'SIGINT' ? 'Ctrl-C' : signal === 'SIGHUP' ? 'SIGHUP (the terminal closed)' : 'SIGTERM'
}
