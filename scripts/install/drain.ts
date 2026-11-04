// What pmmcp's stop is waiting on, read from its stdout while it runs.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), while
//   L1's stop-pmmcp-server.sh runs inside the stopped window. The applier
//   says when that stop starts (its pid and its stdout file, <step>.out) and
//   when it has exited (ApplyOptions.stopping); the entry point follows the
//   file with a DrainWatch, every POLL_MS and once more when a Ctrl-C comes,
//   so the force-quit (scripts/install/force-quit.ts) knows which service the
//   stop is draining, and since when. It only reads: it signals nothing and
//   runs nothing.
//
//   What it reads: the stop's own lines, as its graceful_kill logs them
//   (stop-pmmcp-server.sh's `log`: three spaces, then the line):
//     Sent SIGTERM to PID <n> (<label>) — waiting for clean drain (up to <s>s)
//     PID <n> (<label>) drained and exited cleanly after <s>s ✓
//     PID <n> (<label>) exited cleanly after <s>s total ✓
//   The target is the last "Sent SIGTERM" line with no later line of the
//   other two for the same pid and label; there is none while the stop
//   counts jobs, stops Qdrant (docker stop -t 60, which logs no such line) or
//   is between services. The progress the stop draws while it waits (a
//   carriage return, then an erase sequence, then the next line) is split at
//   every \r and \n, and control sequences are stripped (run.ts shownLine)
//   before a line is read. Only a whole line counts: what follows the last
//   \r or \n waits for the next read, so a line split across reads is read
//   once, whole, and UTF-8 (the dash is three bytes) is decoded across reads.
//   A run of more than MAX_LINE characters with no break is no line of the
//   stop's and is dropped up to its break. The pid is a whole number above 1
//   and at most 2^31 - 1; anything else is no line of the stop's.
//
//   `seenAt` is when the installer first read the target's line, not when the
//   stop wrote it: at most a poll later. The force-quit says the wait as the
//   time since then.
//
//   The file is read through the runner's readLogFrom (never through a link,
//   non-blocking, this account's regular file only), from where the last read
//   ended. A read that fails leaves the target as it was: the force-quit
//   confirms any target with ps before it offers or does anything.

import { readLogFrom, shownLine } from './run.js'

/** How often the entry point reads the stop's stdout while it runs. */
export const POLL_MS = 1000

/** A run of this many characters with no line break is no line of the stop's. */
export const MAX_LINE = 4096

/** The most read at once: the stop writes a few hundred bytes a second while it waits, and a poll reads on until a read comes back short. */
export const READ_BYTES = 1024 * 1024

/** The service the stop has sent SIGTERM and is waiting for. */
export interface DrainTarget {
  readonly pid: number
  readonly label: string
  /** The first wait the stop gave it, in seconds (its "up to"). */
  readonly upTo: number
  /** When the installer first read the line, in milliseconds. */
  readonly seenAt: number
}

/** A SIGKILL the operator typed force-quit for, as the run folder's log and the end report say it. */
export interface ForceQuitRecord {
  readonly label: string
  readonly pid: number
  /** How long the stop had waited on it, as the force-quit counts that (since seenAt), in whole seconds. */
  readonly seconds: number
}

/** The line the end report and the run folder's force-quit.log give a force-quit. */
export function forceQuitLine(r: ForceQuitRecord): string {
  return `force-quit: ${shownLine(r.label)} (PID ${String(r.pid)}) SIGKILLed at your typed force-quit after ${String(r.seconds)}s`
}

const SENT = /^Sent SIGTERM to PID ([0-9]{1,10}) \((.+)\) — waiting for clean drain \(up to ([0-9]{1,9})s\)$/
const DRAINED = /^PID ([0-9]{1,10}) \((.+)\) (?:drained and exited cleanly after [0-9]+s|exited cleanly after [0-9]+s total)(?: ✓)?$/

const MAX_PID = 2 ** 31 - 1

const pidOf = (text: string): number | undefined => {
  const n = Number(text)
  return Number.isInteger(n) && n > 1 && n <= MAX_PID && String(n) === text ? n : undefined
}

/** The stop's lines, fed as they come; `target` is what it waits on now. */
export class DrainReader {
  readonly #decoder = new TextDecoder('utf-8')
  #carry = ''
  #dropping = false
  #target: DrainTarget | undefined

  /** What the stop is waiting on, as the lines read so far say. */
  get target(): DrainTarget | undefined {
    return this.#target
  }

  /** The next bytes of the stop's stdout, read at `at` (milliseconds). */
  feed(chunk: Uint8Array, at: number): void {
    let text = this.#carry + this.#decoder.decode(chunk, { stream: true })
    this.#carry = ''
    if (this.#dropping) {
      const end = text.search(/[\r\n]/)
      if (end < 0) return
      text = text.slice(end + 1)
      this.#dropping = false
    }
    const pieces = text.split(/[\r\n]/)
    const rest = pieces.pop() ?? ''
    for (const piece of pieces) this.#line(piece, at)
    if (rest.length > MAX_LINE) this.#dropping = true
    else this.#carry = rest
  }

  #line(raw: string, at: number): void {
    if (raw.length > MAX_LINE) return
    const line = shownLine(raw).trim()
    const sent = SENT.exec(line)
    if (sent !== null) {
      const pid = pidOf(sent[1] ?? '')
      const label = sent[2] ?? ''
      if (pid === undefined || label === '') return
      const same = this.#target !== undefined && this.#target.pid === pid && this.#target.label === label
      if (!same) this.#target = { pid, label, upTo: Number(sent[3]), seenAt: at }
      return
    }
    const drained = DRAINED.exec(line)
    if (drained === null) return
    const t = this.#target
    if (t !== undefined && pidOf(drained[1] ?? '') === t.pid && drained[2] === t.label) this.#target = undefined
  }
}

export type ReadFrom = (path: string, offset: number, max: number) => Buffer

/** A DrainReader on a file that grows: each poll reads what was written since the last. */
export class DrainWatch {
  readonly path: string
  readonly #reader = new DrainReader()
  readonly #read: ReadFrom
  #offset = 0

  constructor(path: string, read: ReadFrom = readLogFrom) {
    this.path = path
    this.#read = read
  }

  /** Read what the stop wrote since the last poll; a read that fails changes nothing. */
  poll(at: number): void {
    for (;;) {
      let chunk: Buffer
      try {
        chunk = this.#read(this.path, this.#offset, READ_BYTES)
      } catch {
        return
      }
      if (chunk.length === 0) return
      this.#offset += chunk.length
      this.#reader.feed(chunk, at)
      if (chunk.length < READ_BYTES) return
    }
  }

  get target(): DrainTarget | undefined {
    return this.#reader.target
  }
}
