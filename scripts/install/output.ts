// The installer's own output: what it says on stdout and stderr, which may
// go away while it runs.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), for every
//   line it, the gate and the applier print, and its terminal for the
//   prompts. say() puts one line on stdout, warn() one on stderr, each made
//   showable first (shownLine: no terminal control, scrubbed), so no line
//   holds a value; each is also kept, in order, in memory, as the run's
//   transcript.
//
//   A write error on either stream is recorded and never thrown: an 'error'
//   event nothing listens for ends Node at once, and inside the stopped
//   window that would leave pmmcp stopped and launchd disabled with nothing
//   to start it again. EPIPE (`npm run aos-install 2>&1 | tee log`, where
//   the same Ctrl-C ends tee), EIO (a closed terminal) or any other code is
//   read the same way: that stream is lost, and nothing more is written to
//   it. While stdout is lost, its lines go to stderr if that still works;
//   with both lost, only to the transcript.
//
//   keep(dir): once output was lost, the transcript, which stream went and
//   how, and the exit code go to <dir>/installer.out (O_EXCL, O_NOFOLLOW,
//   0600), the run's log folder, so what the installer said, the end report
//   and its manual start included, can still be read. Nothing is written
//   there while output works.
//
//   flush(then): `then` runs once what was written has been handed on
//   (process.exit alone can cut a pipe's last lines on macOS); at once for
//   a stream that is lost.

import { closeSync, constants, fchmodSync, openSync, writeSync } from 'node:fs'
import { join } from 'node:path'

import { shownLine } from './run.js'

/** The part of a writable stream the installer uses: process.stdout and process.stderr are ones. */
export interface OutStream {
  write(chunk: string, callback?: (error?: Error | null) => void): boolean
  on(event: 'error', listener: (error: Error) => void): unknown
  readonly destroyed?: boolean
}

/** Which stream went, and how. */
export interface Lost {
  readonly stream: 'stdout' | 'stderr'
  readonly code: string
}

/** The file keep() writes in the run's log folder. */
export const TRANSCRIPT_FILE = 'installer.out'

/** An error by its errno or Node code, else its class: never its message. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

export class Output {
  readonly #stdout: OutStream
  readonly #stderr: OutStream
  readonly #transcript: string[] = []
  #lostOut: string | undefined
  #lostErr: string | undefined
  #first: Lost | undefined

  constructor(stdout: OutStream, stderr: OutStream) {
    this.#stdout = stdout
    this.#stderr = stderr
    stdout.on('error', (e) => this.#lose('stdout', errnoOf(e)))
    stderr.on('error', (e) => this.#lose('stderr', errnoOf(e)))
  }

  /** The first stream that was lost, and how; undefined while both work. */
  get lost(): Lost | undefined {
    return this.#first
  }

  /** Whether stdout still takes lines: the terminal's prompts are asked only then. */
  get stdoutWorks(): boolean {
    return this.#lostOut === undefined && this.#stdout.destroyed !== true
  }

  /** What the run said, in order. */
  get transcript(): readonly string[] {
    return [...this.#transcript]
  }

  /** One line on stdout (on stderr once stdout is lost). */
  say(line: string): void {
    const text = shownLine(line)
    this.#transcript.push(text)
    if (this.stdoutWorks) this.#write('stdout', `${text}\n`)
    else this.#write('stderr', `${text}\n`)
  }

  /** One line on stderr. */
  warn(line: string): void {
    const text = shownLine(line)
    this.#transcript.push(`! ${text}`)
    this.#write('stderr', `${text}\n`)
  }

  /** Usage and other text the installer wrote itself, as it is, on one stream. */
  raw(stream: 'stdout' | 'stderr', text: string): void {
    this.#transcript.push(...text.replace(/\n$/, '').split('\n'))
    this.#write(stream, text)
  }

  /**
   * Once output was lost: the transcript, the loss and `code` in
   * <dir>/installer.out. Its path, or why it could not be written; undefined
   * when output works or there is no folder.
   */
  keep(dir: string | undefined, code: number): string | undefined {
    const lost = this.#first
    if (lost === undefined || dir === undefined) return undefined
    const path = join(dir, TRANSCRIPT_FILE)
    const text = [
      `${lost.stream} went away (${lost.code}) during this run; the installer went on. What it said:`,
      ...this.#transcript,
      `exit ${String(code)}`,
      '',
    ].join('\n')
    let fd: number
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    } catch (e) {
      return `${path} could not be created (${errnoOf(e)})`
    }
    try {
      fchmodSync(fd, 0o600)
      writeSync(fd, text)
      return path
    } catch (e) {
      return `${path} could not be written (${errnoOf(e)})`
    } finally {
      closeSync(fd)
    }
  }

  /** Run `then` once both streams have handed on what was written to them. */
  flush(then: () => void): void {
    this.#drain('stdout', () => this.#drain('stderr', then))
  }

  #drain(stream: 'stdout' | 'stderr', then: () => void): void {
    const s = stream === 'stdout' ? this.#stdout : this.#stderr
    if (this.#isLost(stream) || s.destroyed === true) {
      then()
      return
    }
    let called = false
    const once = (): void => {
      if (called) return
      called = true
      then()
    }
    try {
      s.write('', once)
    } catch {
      once()
    }
  }

  #isLost(stream: 'stdout' | 'stderr'): boolean {
    return (stream === 'stdout' ? this.#lostOut : this.#lostErr) !== undefined
  }

  #write(stream: 'stdout' | 'stderr', text: string): void {
    const s = stream === 'stdout' ? this.#stdout : this.#stderr
    if (this.#isLost(stream) || s.destroyed === true) return
    try {
      s.write(text, (e) => {
        if (e !== undefined && e !== null) this.#lose(stream, errnoOf(e))
      })
    } catch (e) {
      this.#lose(stream, errnoOf(e))
    }
  }

  #lose(stream: 'stdout' | 'stderr', code: string): void {
    if (stream === 'stdout') this.#lostOut ??= code
    else this.#lostErr ??= code
    this.#first ??= { stream, code }
  }
}
