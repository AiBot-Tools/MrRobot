// The installer's terminal: its questions and the jobs wait.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), as the
//   gate's and the applier's ask and pause. One readline interface per
//   question or wait, closed once answered: between prompts the terminal is
//   as the shell left it, so a Ctrl-C there is a signal (scripts/install/
//   signals.ts) rather than a keystroke. readline edits the line itself only
//   when both ends are a terminal.
//
//   Nothing is asked of a stdin that is not a terminal, nor once stdout is
//   lost (scripts/install/output.ts): a question no one can see is answered
//   as the input ending (eof), which every caller reads as the answer that
//   changes nothing, rather than waited on for good.
//
//   Input typed ahead is not an answer: text typed while discovery or the
//   jobs count ran waits in the terminal's buffer and reaches the next
//   readline interface at once, so `Persistent-Memory-MCP` typed early would
//   answer the second confirmation before the jobs listing and the sequence
//   line were shown. A line that arrives within TYPE_AHEAD_MS of the
//   question being printed was typed before it: it is dropped, said so, and
//   the question is shown again. No one reads a question and answers it that
//   fast.
//
//   A Ctrl-C delivered as a signal while a question or the wait is open
//   answers it (interrupt()); a read error on stdin ends it as eof.

import { createInterface, type Interface } from 'node:readline'
import type { Readable, Writable } from 'node:stream'

import type { Answer, Pause } from '../../src/install/gate.js'
import { shownLine } from './run.js'

/** A line back sooner than this after the question was printed was typed before it. */
export const TYPE_AHEAD_MS = 100

export interface TerminalOptions {
  readonly input: Readable
  readonly output: Writable
  /** stdin is a terminal: only then is anything asked. */
  readonly interactive: boolean
  /** Both ends are a terminal: readline edits the line itself. */
  readonly raw: boolean
  /** Whether output still reaches the operator (Output.stdoutWorks). */
  readonly outputWorks: () => boolean
  /** A line of the installer's own, between questions. */
  readonly print: (line: string) => void
  /** The clock type-ahead is judged by, in milliseconds (default Date.now). */
  readonly now?: () => number
}

export class Terminal {
  readonly interactive: boolean
  readonly #o: TerminalOptions
  readonly #now: () => number
  #pending: (() => void) | undefined

  constructor(options: TerminalOptions) {
    this.#o = options
    this.interactive = options.interactive
    this.#now = options.now ?? Date.now
  }

  /** A question or the wait is open. */
  get promptOpen(): boolean {
    return this.#pending !== undefined
  }

  /** A Ctrl-C delivered as a signal while a prompt or the wait is open answers it; false when none is. */
  interrupt(): boolean {
    const pending = this.#pending
    if (pending === undefined) return false
    pending()
    return true
  }

  ask(question: string): Promise<Answer> {
    if (!this.interactive || !this.#o.outputWorks()) return Promise.resolve({ kind: 'eof' })
    return new Promise<Answer>((resolveAnswer) => {
      const rl = this.#interface()
      let settled = false
      const done = (answer: Answer): void => {
        if (settled) return
        settled = true
        this.#pending = undefined
        rl.close()
        if (answer.kind !== 'line' && this.#o.outputWorks()) this.#o.output.write('\n')
        resolveAnswer(answer)
      }
      this.#pending = (): void => done({ kind: 'interrupt' })
      rl.on('SIGINT', () => done({ kind: 'interrupt' }))
      rl.on('close', () => done({ kind: 'eof' }))
      rl.on('error', () => done({ kind: 'eof' }))
      let asked = this.#now()
      rl.setPrompt(`${shownLine(question)} `)
      rl.on('line', (text) => {
        if (this.#now() - asked < TYPE_AHEAD_MS) {
          this.#o.print('(dropped what was typed before the question was shown: answer it now)')
          asked = this.#now()
          rl.prompt()
          return
        }
        done({ kind: 'line', text })
      })
      rl.prompt()
    })
  }

  /** Wait `ms`, or less when the operator types q, closes the input or presses Ctrl-C. */
  pause(ms: number): Promise<Pause> {
    return new Promise<Pause>((resolvePause) => {
      let settled = false
      const rl = this.interactive && this.#o.outputWorks() ? this.#interface() : undefined
      const done = (how: Pause): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        this.#pending = undefined
        rl?.close()
        resolvePause(how)
      }
      const timer = setTimeout(() => done('elapsed'), ms)
      this.#pending = (): void => done('interrupt')
      rl?.on('line', (line) => {
        if (line.trim().toLowerCase() === 'q') done('quit')
      })
      rl?.on('SIGINT', () => done('interrupt'))
      rl?.on('close', () => done('eof'))
      rl?.on('error', () => done('eof'))
    })
  }

  #interface(): Interface {
    return createInterface({ input: this.#o.input, output: this.#o.output, terminal: this.#o.raw, historySize: 0 })
  }
}
