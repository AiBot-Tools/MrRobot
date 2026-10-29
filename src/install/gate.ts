// The installer's confirmation gate: what the operator answers before
// anything changes, and types before anything live changes.
//
// CONTRACT
//
//   Who calls it: the installer (scripts/install.ts), with the plan
//   planInstall made (src/install/plan.ts) and the IO it injects (GateIO):
//   whether stdin is a terminal, how a line is printed and a question asked,
//   the jobs count (stop-pmmcp-server.sh --jobs through the A3 runner, read
//   from stdout's first line alone), a pause between counts, and `apply`,
//   which carries out steps (A6). Nothing here starts a program, touches a
//   file, reads the clock or keeps a value: the plan holds names, paths and
//   commands only, and every line it prints or asks is stripped of terminal
//   control and scrubbed (redactString) first. The kernel never imports it.
//
//   In order:
//     1. The plan is printed (describe).
//     2. A plan with stops is refused: they are printed and nothing is
//        asked (exit 2).
//     3. Nothing to do: exit 0, with no prompt. It says everything the
//        installer makes is in place only when the plan blocks nothing
//        (Plan.blocked); otherwise that there is nothing it can do now, and
//        the notes above say why. A dry run adds its closing line.
//     4. A dry run prints every step as would-do, every question it would
//        ask, the words it would ask the operator to type, and that nothing
//        was changed; nothing is asked, counted or applied (exit 0).
//     5. A stdin that is not a terminal ends the run before any prompt:
//        changes are needed, and only an operator at a terminal may confirm
//        them (a pipe of "y" lines is not one), so nothing is asked or
//        applied (exit 3).
//     6. A fresh install asks one typed word, `install` (plan Q24: it also
//        covers the first stop and start of the just-installed service), then
//        applies its whole sequence; any other answer changes nothing.
//     7. Otherwise each offer is asked, y/N: only y or yes is yes. The
//        restart is asked only when nothing else that opens the window was
//        accepted (that window restarts pmmcp anyway), and an offer that
//        needs the update only once the update was accepted. Then, when
//        non-live steps would run (each one not offered, and each offered one
//        accepted), "Apply the non-live steps ... now? [y/N]", and only a yes
//        applies them (S5), live items or not.
//     8. Only then, and only when a live item was accepted: the warning
//        (S6); the first typed confirmation, `stop pmmcp`; the jobs check;
//        the exact sequence in one line and the second typed confirmation,
//        the folder name `Persistent-Memory-MCP` (S6b); and only past both,
//        apply('live', …). The jobs check prompts only when something runs:
//        `running jobs: 0` goes straight on. N jobs are listed (their display
//        lines as the stop script gave them) and "Wait for them to finish?
//        [Y/n]" counts again every 10 s until none runs (q, EOF or Ctrl-C at
//        the wait aborts, nothing stopped yet), or, on n or no, goes on to
//        the second confirmation, saying the stop waits up to 300 s for them
//        and then stops anyway. A count of unknown, or one that failed,
//        aborts with nothing stopped, its stderr shown; Ctrl-C during a
//        count aborts as Ctrl-C at a prompt does. A plan whose jobs check
//        cannot run (Plan.jobsGate) aborts there too, though the planner
//        offers nothing live for one.
//
//   A typed confirmation is the exact word, in its case, spaces around it
//   aside. Every prompt defaults to the answer that changes nothing.
//
//   How it ends (GateOutcome, with the installer's exit code): refused (2),
//   nothing to do (0), dry run (0), not a terminal (3), declined (0: a no, a
//   wrong word, or nothing chosen), aborted (EOF or Ctrl-C at a prompt or the
//   wait, or Ctrl-C during a jobs count: 130; q at the wait: 0; a jobs
//   count that is unknown or failed: 1),
//   failed (apply's own code), done (0). Whatever ends the run before
//   apply('live', …) leaves pmmcp as it was, and `applied` lists the phases
//   that did run.

import { redactString } from '../events/redact.js'
import {
  PMMCP_FOLDER,
  describe,
  nonLiveNumbers,
  nothingToDo,
  opensWindow,
  select,
  sequence,
  warning,
  wouldDo,
  type OfferId,
  type Plan,
  type Step,
} from './plan.js'

/** The first typed confirmation (S6). */
export const FIRST_CONFIRMATION = 'stop pmmcp'

/** The second (S6b): the folder the stop script finds pmmcp's processes by. */
export const SECOND_CONFIRMATION = PMMCP_FOLDER

/** The one typed word a fresh install asks (S3b). */
export const INSTALL_CONFIRMATION = 'install'

/** How long the jobs check waits between counts. */
export const JOBS_POLL_MS = 10_000

/** How long the stop script's own job wait lasts before it stops anyway (its default --wait-timeout). */
const STOP_WAIT_S = 300

/** A line the operator typed, or how the input ended. */
export type Answer = { readonly kind: 'line'; readonly text: string } | { readonly kind: 'eof' } | { readonly kind: 'interrupt' }

/** How a pause between job counts ended: its time ran out, or the operator typed q, closed the input or pressed Ctrl-C. */
export type Pause = 'elapsed' | 'quit' | 'eof' | 'interrupt'

/**
 * `stop-pmmcp-server.sh --jobs`, as the runner read it: stdout's first line
 * alone, its stderr to show; or the operator's Ctrl-C while it ran, an
 * interrupt outside the window (130), never a failed count.
 */
export type JobsAnswer =
  | { readonly state: 'counted'; readonly running: number; readonly display: readonly string[] }
  | { readonly state: 'unknown'; readonly stderr: readonly string[] }
  | { readonly state: 'failed'; readonly why: string; readonly stderr: readonly string[] }
  | { readonly state: 'interrupt' }

export type Phase = 'non-live' | 'live' | 'fresh-install'

/** What apply reports: done, or the exit code its failure means (1 a step failed, 2 refused before a change, 4 a live step failed). */
export type Applied = { readonly ok: true } | { readonly ok: false; readonly exitCode: 1 | 2 | 4 }

export interface GateIO {
  /** stdin is a terminal: only then is anything asked. */
  readonly interactive: boolean
  /** Show one line (already stripped and scrubbed here). */
  print(line: string): void
  /** Ask one question and read one line. */
  ask(question: string): Promise<Answer>
  /** Count pmmcp's jobs (the jobs check); Ctrl-C while the count runs answers `interrupt`. */
  countJobs(): Promise<JobsAnswer>
  /** Wait `ms` between counts, or less when the operator types q, closes the input or presses Ctrl-C. */
  pause(ms: number): Promise<Pause>
  /** Carry out steps, in order: the non-live ones (S5), the live window past both confirmations (S7), or a fresh install's sequence. */
  apply(phase: Phase, steps: readonly Step[]): Promise<Applied>
}

export interface GateOptions {
  readonly dryRun: boolean
  /** Where the runner's logs of this run are, for the dry run's last line. */
  readonly logs?: string
}

/** Where the run ended. */
export type Checkpoint = 'offer' | 'non-live' | 'first-confirmation' | 'jobs' | 'second-confirmation' | 'install'

export type GateOutcome =
  | { readonly kind: 'refused'; readonly exitCode: 2 }
  | { readonly kind: 'nothing-to-do'; readonly exitCode: 0 }
  | { readonly kind: 'dry-run'; readonly exitCode: 0 }
  | { readonly kind: 'not-a-terminal'; readonly exitCode: 3 }
  | { readonly kind: 'declined'; readonly at: Checkpoint; readonly applied: readonly Phase[]; readonly exitCode: 0 }
  | {
      readonly kind: 'aborted'
      readonly at: Checkpoint
      readonly by: 'eof' | 'interrupt' | 'quit' | 'jobs'
      readonly applied: readonly Phase[]
      readonly exitCode: 0 | 1 | 130
    }
  | { readonly kind: 'failed'; readonly phase: Phase; readonly applied: readonly Phase[]; readonly exitCode: 1 | 2 | 4 }
  | { readonly kind: 'done'; readonly applied: readonly Phase[]; readonly exitCode: 0 }

/** Walk the plan through the operator's answers. See the contract above. */
export function runGate(plan: Plan, io: GateIO, options: GateOptions): Promise<GateOutcome> {
  return new Gate(plan, io, options).run()
}

/** Terminal control: CSI and other escape sequences, then every C0 and C1 control but tab. */
const CONTROL = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|[\x00-\x08\x0a-\x1f\x7f-\x9f]/g

/** A line as it may be shown: no terminal control, scrubbed. */
const shown = (line: string): string => redactString(line.replace(CONTROL, ''))

const without = (question: string): string => question.replace(/ \[[yYnN]\/[yYnN]\]$/, '')

class Gate {
  readonly #plan: Plan
  readonly #io: GateIO
  readonly #options: GateOptions
  readonly #applied: Phase[] = []

  constructor(plan: Plan, io: GateIO, options: GateOptions) {
    this.#plan = plan
    this.#io = io
    this.#options = options
  }

  async run(): Promise<GateOutcome> {
    const plan = this.#plan
    for (const line of describe(plan)) this.#print(line)
    if (plan.stops.length > 0) {
      this.#print('refused, and nothing was changed:')
      for (const stop of plan.stops) this.#print(`  - ${stop}`)
      return { kind: 'refused', exitCode: 2 }
    }
    if (nothingToDo(plan)) {
      this.#print(plan.blocked.length === 0 ? 'nothing to do: everything the installer makes is in place' : 'nothing the installer can do now: see the notes above')
      if (this.#options.dryRun) this.#dryRunEnd()
      return { kind: 'nothing-to-do', exitCode: 0 }
    }
    if (this.#options.dryRun) {
      for (const line of wouldDo(plan)) this.#print(line)
      if (plan.kind === 'fresh-install') this.#print(`would ask you to type \`${INSTALL_CONFIRMATION}\` before anything is installed`)
      else if (plan.offers.some((o) => o.live)) {
        this.#print(`would ask you to type \`${FIRST_CONFIRMATION}\` and then, after the jobs check, \`${SECOND_CONFIRMATION}\`, before any live step`)
      }
      this.#dryRunEnd()
      return { kind: 'dry-run', exitCode: 0 }
    }
    if (!this.#io.interactive) {
      this.#print('stdin is not a terminal: changes are needed, and only an operator at a terminal may confirm them, so nothing was changed. Run npm run aos-install in a terminal (or with --dry-run)')
      return { kind: 'not-a-terminal', exitCode: 3 }
    }
    return plan.kind === 'fresh-install' ? this.#freshInstall() : this.#choose()
  }

  // ── S3b ──

  async #freshInstall(): Promise<GateOutcome> {
    const typed = await this.#typed(`Type \`${INSTALL_CONFIRMATION}\` to begin`, INSTALL_CONFIRMATION, 'install')
    if (typed !== undefined) return typed
    const failed = await this.#apply('fresh-install', this.#plan.steps)
    if (failed !== undefined) return failed
    return this.#done()
  }

  // ── S4, S5 ──

  async #choose(): Promise<GateOutcome> {
    const plan = this.#plan
    const accepted = new Set<OfferId>()
    for (const offer of plan.offers) {
      if (offer.requires !== undefined && !accepted.has(offer.requires)) continue
      if (offer.impliedByWindow && opensWindow(plan, accepted)) {
        this.#print(`${without(offer.question)}: yes, by the changes above, which restart pmmcp once`)
        continue
      }
      const yes = await this.#yesNo(offer.question, 'offer', false)
      if (typeof yes !== 'boolean') return yes
      if (yes) accepted.add(offer.id)
    }
    const { nonLive, live } = select(plan, accepted)
    if (nonLive.length === 0 && live.length === 0) {
      this.#print('nothing chosen, so nothing was changed')
      return this.#declined('offer')
    }
    if (nonLive.length > 0) {
      const yes = await this.#yesNo(`Apply the non-live ${nonLiveNumbers(plan, nonLive)} now? [y/N]`, 'non-live', false)
      if (typeof yes !== 'boolean') return yes
      if (!yes) {
        this.#print('nothing was changed')
        return this.#declined('non-live')
      }
      const failed = await this.#apply('non-live', nonLive)
      if (failed !== undefined) return failed
    }
    if (live.length === 0) return this.#done()
    return this.#window(live)
  }

  // ── S6, S6b, S7 ──

  async #window(live: readonly Step[]): Promise<GateOutcome> {
    for (const line of warning(this.#plan, live)) this.#print(line)
    const first = await this.#first()
    if (first !== undefined) return first
    const jobs = await this.#jobsGate()
    if (jobs !== undefined) return jobs
    const second = await this.#second(live)
    if (second !== undefined) return second
    const failed = await this.#apply('live', live)
    if (failed !== undefined) return failed
    return this.#done()
  }

  /** S6's typed confirmation. */
  #first(): Promise<GateOutcome | undefined> {
    return this.#typed(`Type \`${FIRST_CONFIRMATION}\` to continue`, FIRST_CONFIRMATION, 'first-confirmation')
  }

  /** S6b: the exact sequence in one line, then the folder name typed. */
  #second(live: readonly Step[]): Promise<GateOutcome | undefined> {
    this.#print(sequence(live))
    return this.#typed(`Second confirmation: type the folder name \`${SECOND_CONFIRMATION}\` to stop it now`, SECOND_CONFIRMATION, 'second-confirmation')
  }

  /** The jobs check between the confirmations: undefined to go on, or how the run ends with nothing stopped. */
  async #jobsGate(): Promise<GateOutcome | undefined> {
    const gate = this.#plan.jobsGate
    if (!gate.available) {
      this.#print(`pmmcp's jobs cannot be counted: ${gate.why}. Nothing was stopped`)
      return this.#aborted('jobs', 'jobs')
    }
    let asked = false
    for (;;) {
      const count = await this.#io.countJobs()
      if (count.state === 'interrupt') {
        this.#print('interrupted while counting the jobs: nothing was stopped')
        return this.#aborted('jobs', 'interrupt')
      }
      if (count.state !== 'counted') {
        this.#print(
          count.state === 'unknown'
            ? 'stop-pmmcp-server.sh --jobs could not count the running jobs (running jobs: unknown), so nothing was stopped:'
            : `stop-pmmcp-server.sh --jobs gave no count (${count.why}), so nothing was stopped:`,
        )
        for (const line of count.stderr) this.#print(`  ${line}`)
        return this.#aborted('jobs', 'jobs')
      }
      if (count.running === 0) return undefined
      this.#print(`${String(count.running)} pmmcp ${count.running === 1 ? 'job is' : 'jobs are'} running:`)
      // As the stop script gave them: its job lines carry their own indent.
      for (const line of count.display) this.#print(line)
      if (!asked) {
        asked = true
        const wait = await this.#yesNo('Wait for them to finish? [Y/n]', 'jobs', true)
        if (typeof wait !== 'boolean') return wait
        if (!wait) {
          this.#print(`not waiting: the stop waits up to ${String(STOP_WAIT_S)} s for ${count.running === 1 ? 'it' : 'them'}, then stops anyway`)
          return undefined
        }
        this.#print(`waiting: counted again every ${String(JOBS_POLL_MS / 1000)} s; type q to abort (nothing is stopped yet)`)
      }
      const paused = await this.#io.pause(JOBS_POLL_MS)
      if (paused !== 'elapsed') {
        this.#print('aborted while waiting for the jobs: nothing was stopped')
        return this.#aborted('jobs', paused)
      }
    }
  }

  #dryRunEnd(): void {
    this.#print(`dry run: nothing was changed, nothing was stopped or started${this.#options.logs === undefined ? '' : ` (probe output in ${this.#options.logs})`}`)
  }

  // ── asking ──

  /** y/N (or Y/n): only y or yes is yes, only n or no is no, anything else the default; EOF or Ctrl-C ends the run. */
  async #yesNo(question: string, at: Checkpoint, byDefault: boolean): Promise<boolean | GateOutcome> {
    const answer = await this.#ask(question)
    if (answer.kind !== 'line') return this.#aborted(at, answer.kind)
    const text = answer.text.trim().toLowerCase()
    if (byDefault) return !(text === 'n' || text === 'no')
    return text === 'y' || text === 'yes'
  }

  /** A typed confirmation: undefined when the exact word came back, else how the run ends. */
  async #typed(question: string, word: string, at: Checkpoint): Promise<GateOutcome | undefined> {
    const answer = await this.#ask(question)
    if (answer.kind !== 'line') return this.#aborted(at, answer.kind)
    if (answer.text.trim() === word) return undefined
    const done = this.#applied.length === 0 ? 'nothing was changed' : `nothing live was done (the ${this.#applied.join(' and ')} steps above were applied)`
    this.#print(`that is not \`${word}\`, so ${at === 'install' ? 'nothing was installed and ' : ''}${done}`)
    return this.#declined(at)
  }

  #ask(question: string): Promise<Answer> {
    return this.#io.ask(shown(question))
  }

  #print(line: string): void {
    this.#io.print(shown(line))
  }

  // ── outcomes ──

  async #apply(phase: Phase, steps: readonly Step[]): Promise<GateOutcome | undefined> {
    const result = await this.#io.apply(phase, steps)
    if (result.ok) {
      this.#applied.push(phase)
      return undefined
    }
    return { kind: 'failed', phase, applied: [...this.#applied], exitCode: result.exitCode }
  }

  #declined(at: Checkpoint): GateOutcome {
    return { kind: 'declined', at, applied: [...this.#applied], exitCode: 0 }
  }

  #aborted(at: Checkpoint, by: 'eof' | 'interrupt' | 'quit' | 'jobs'): GateOutcome {
    const exitCode = by === 'quit' ? 0 : by === 'jobs' ? 1 : 130
    return { kind: 'aborted', at, by, applied: [...this.#applied], exitCode }
  }

  #done(): GateOutcome {
    return { kind: 'done', applied: [...this.#applied], exitCode: 0 }
  }
}
