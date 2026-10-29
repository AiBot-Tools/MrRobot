// The installer's lock: one npm run aos-install at a time.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), once its
//   preflight passed (so .gitignore ignores /.aos/ and .aos is spelled so
//   and not a link), before anything else is written or run.
//
//   <repo>/.aos/install.lock: created with O_EXCL and O_NOFOLLOW, 0600 (umask
//   aside), under a .aos made 0700 when missing and refused when it is a
//   link or not a folder, another account's, or writable by group or others.
//   It holds {pid, started}. release() removes it, and only while it still
//   names this process.
//
//   A lock that is there already is taken over, once, and only while the
//   path is still the file read, when it is stale:
//     - its pid no longer runs (kill 0, where EPERM is someone else's live
//       process);
//     - the machine booted after it was taken (in-process: now less
//       os.uptime()), so whatever has that pid now is not the installer that
//       took it: a lock left by a run that a reboot, a crash or a SIGKILL
//       ended may name a pid macOS has given out again (pids wrap at 99999);
//     - the process with that pid started after the lock was taken (`ps -o
//       etime=` through the runner, the one program this may start, and only
//       for a live pid, read as the earliest the process can have started).
//   A pid whose start cannot be told counts as the installer's: refused, not
//   taken. Taking one over says why.
//
//   Refused, each with what to do and every path shell-quoted: a live
//   holder; a lock that names no pid; a symbolic link, a directory or
//   anything else but a regular file at the path (re-running never helps
//   there, so each names its removal).

import { chmodSync, closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, unlinkSync, writeSync } from 'node:fs'
import { uptime } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'

import { shellWord } from '../../src/install/plan.js'
import { parseEtime } from './discover.js'
import { InstallRunError, readOut, shownLine, type Runner } from './run.js'

const LockRecord = z.object({ pid: z.number().int().positive(), started: z.string() })
type LockRecord = z.infer<typeof LockRecord>

/** The lock's path in a checkout. */
export function lockPath(root: string): string {
  return join(root, '.aos', 'install.lock')
}

/** A boot later than the lock by less than this is read as the same moment: os.uptime is in whole seconds, and a clock may step. */
export const BOOT_SLACK_MS = 10_000

/** How long ps is given to describe the holder's pid. */
const PS_MS = 10_000

export interface Lock {
  readonly path: string
  release(): void
}

/** The earliest the process with a pid can have started (ms since the epoch), 'gone' when ps finds none, undefined when it cannot be told. */
export type StartOf = (pid: number) => Promise<number | 'gone' | undefined>

export interface LockOptions {
  readonly root: string
  /** Where the takeover is said. */
  readonly print: (line: string) => void
  /** The holder's start, asked only for a live pid (startWithPs over the run's runner). */
  readonly startOf: StartOf
  /** When the machine booted, ms since the epoch (default: now less os.uptime()). */
  readonly bootedAt?: () => number
  /** Whether a pid runs (default: kill 0, EPERM counting as running). */
  readonly alive?: (pid: number) => boolean
}

/** An error by its errno or Node code, else its class: never its message. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

/** Whether a pid runs: kill 0, where EPERM is someone else's live process. Never this process. */
export function pidRuns(pid: number): boolean {
  if (pid === process.pid) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return errnoOf(e) === 'EPERM'
  }
}

/** What is at the lock's path. */
type Held =
  | { readonly kind: 'gone' }
  | { readonly kind: 'link' }
  | { readonly kind: 'directory' }
  | { readonly kind: 'special' }
  | { readonly kind: 'unreadable'; readonly code: string }
  | { readonly kind: 'file'; readonly record: LockRecord | undefined; readonly dev: number; readonly ino: number }

/** What is at `path`, read through a descriptor that is the file there, never through a link, never blocking on a FIFO. */
function readLock(path: string): Held {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (e) {
    const code = errnoOf(e)
    if (code === 'ENOENT') return { kind: 'gone' }
    if (code === 'ELOOP' || code === 'EMLINK') return { kind: 'link' }
    return { kind: 'unreadable', code }
  }
  try {
    const st = fstatSync(fd)
    if (st.isDirectory()) return { kind: 'directory' }
    if (!st.isFile()) return { kind: 'special' }
    if (st.size > 4096) return { kind: 'file', record: undefined, dev: st.dev, ino: st.ino }
    const buf = Buffer.alloc(st.size)
    let got = 0
    while (got < st.size) {
      const n = readSync(fd, buf, got, st.size - got, got)
      if (n <= 0) break
      got += n
    }
    let json: unknown
    try {
      json = JSON.parse(buf.subarray(0, got).toString('utf8'))
    } catch {
      return { kind: 'file', record: undefined, dev: st.dev, ino: st.ino }
    }
    const parsed = LockRecord.safeParse(json)
    return { kind: 'file', record: parsed.success ? parsed.data : undefined, dev: st.dev, ino: st.ino }
  } finally {
    closeSync(fd)
  }
}

/** Why a held lock is stale, or undefined while its holder may still be the installer that took it. */
async function staleness(record: LockRecord, o: LockOptions): Promise<string | undefined> {
  const alive = o.alive ?? pidRuns
  if (!alive(record.pid)) return 'which no longer runs'
  const started = Date.parse(record.started)
  if (Number.isNaN(started)) return undefined
  const booted = (o.bootedAt ?? ((): number => Date.now() - uptime() * 1000))()
  if (booted > started + BOOT_SLACK_MS) return 'from before the machine last started, so the process with that pid now is not the installer that took it'
  const start = await o.startOf(record.pid)
  if (start === 'gone') return 'which no longer runs'
  if (start !== undefined && start > started) return 'which now belongs to a process that started after the lock was taken (the pid was given out again)'
  return undefined
}

/**
 * Take <root>/.aos/install.lock, or say why it cannot be taken. See the
 * contract above.
 */
export async function takeLock(o: LockOptions): Promise<Lock | string> {
  const dir = join(o.root, '.aos')
  try {
    mkdirSync(dir, { mode: 0o700 })
    // umask only clears bits; 0700 must hold whatever it is.
    chmodSync(dir, 0o700)
  } catch (e) {
    if (errnoOf(e) !== 'EEXIST') return `cannot make ${dir} (${errnoOf(e)})`
  }
  try {
    const st = lstatSync(dir)
    if (st.isSymbolicLink() || !st.isDirectory()) return `${dir} is not a directory (a link is not one): the installer keeps its lock only in a real one`
    const me = process.geteuid?.()
    if (me !== undefined && st.uid !== me) return `${dir} belongs to uid ${String(st.uid)}, not this account`
    if ((st.mode & 0o022) !== 0) return `${dir} is writable by group or others: chmod go-w ${shellWord(dir)}, then re-run`
  } catch (e) {
    return `cannot examine ${dir} (${errnoOf(e)})`
  }
  const path = lockPath(o.root)
  const remove = `if no npm run aos-install is running, remove it (rm ${shellWord(path)}), then re-run`
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let fd: number
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    } catch (e) {
      if (errnoOf(e) !== 'EEXIST') return `cannot create ${path} (${errnoOf(e)})`
      const held = readLock(path)
      if (held.kind === 'gone') continue
      if (held.kind === 'link') return `${path} is a symbolic link, not the installer's lock: remove the link (rm ${shellWord(path)}), then re-run`
      if (held.kind === 'directory') {
        return `${path} is a directory, not the installer's lock: move what you keep in it elsewhere and remove it (rmdir ${shellWord(path)}), then re-run`
      }
      if (held.kind === 'special') return `${path} is not a regular file, not the installer's lock: remove it (rm ${shellWord(path)}), then re-run`
      if (held.kind === 'unreadable') return `${path} is there but cannot be read (${held.code}): ${remove}`
      if (held.record === undefined) return `${path} is there but names no installer's pid: ${remove}`
      const { pid, started } = held.record
      const why = await staleness(held.record, o)
      if (why === undefined) {
        return `another npm run aos-install (pid ${String(pid)}, since ${shownLine(started).slice(0, 40)}) holds ${path}: let it finish; ${remove}`
      }
      // Only the file just read: one another installer put there meanwhile is not this one's to remove.
      try {
        const now = lstatSync(path)
        if (now.dev !== held.dev || now.ino !== held.ino) continue
        unlinkSync(path)
      } catch (e2) {
        if (errnoOf(e2) !== 'ENOENT') return `cannot remove the stale ${path} (${errnoOf(e2)})`
      }
      o.print(`took over ${path}: it named pid ${String(pid)}, ${why}`)
      continue
    }
    try {
      // umask only clears bits; 0600 must hold whatever it is.
      fchmodSync(fd, 0o600)
      writeSync(fd, `${JSON.stringify({ pid: process.pid, started: new Date().toISOString() })}\n`)
      fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
    return {
      path,
      release: (): void => {
        const held = readLock(path)
        if (held.kind !== 'file' || held.record?.pid !== process.pid) return
        try {
          unlinkSync(path)
        } catch {
          // Gone already, or not ours to remove now: a later run reads its pid as not running.
        }
      },
    }
  }
  return `cannot take ${path}: another installer took it at the same moment; re-run`
}

/**
 * The holder's start by `ps -o etime= -p <pid>` through the runner: the
 * earliest it can have started (etime counts whole seconds), 'gone' when ps
 * finds no such process, undefined when ps gives no answer it can read.
 */
export function startWithPs(runner: Runner, cwd: string): StartOf {
  return async (pid: number): Promise<number | 'gone' | undefined> => {
    const before = Date.now()
    let result
    try {
      result = await runner.run({ step: `ps-lock-${String(pid)}`, command: 'ps', args: ['-o', 'etime=', '-p', String(pid)], cwd, timeoutMs: PS_MS })
    } catch (e) {
      if (e instanceof InstallRunError && e.code !== 'AOS_INSTALL_RUN_LEAK' && e.code !== 'AOS_INSTALL_RUN_HALTED') return undefined
      throw e
    }
    if (result.timedOut || !result.exited || result.signal !== null) return undefined
    let out: string
    try {
      out = readOut(result)
    } catch {
      return undefined
    }
    if (result.code === 1 && out.trim() === '') return 'gone'
    if (result.code !== 0) return undefined
    const elapsed = parseEtime((out.split('\n')[0] ?? '').trim())
    return elapsed === undefined ? undefined : before - (elapsed + 1) * 1000
  }
}
