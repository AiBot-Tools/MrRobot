// One kernel per event log: the kernel's hold on its data directory.
//
// CONTRACT
//
//   bootKernel takes <dataDir>/kernel.lock (DATA_LOCK_FILE) before it opens
//   the event log, and so before crash recovery and the orphan sweep, and
//   holds it until shutdown has closed the log. A second kernel on the same
//   data directory, in this process or another, is refused there, before it
//   writes anything. Without the hold it would read the live kernel's open
//   runs as a dead kernel's: close them as orphans, revoke their egress
//   grants `recovered` with a detail saying nothing has been served since,
//   while the live kernel goes on serving them, and kill their containers by
//   name in the boot sweep, and only then fail on the control port.
//
//   The hold is SQLite's own exclusive lock on that file (an empty
//   database), taken through events/db.ts with BEGIN EXCLUSIVE and no busy
//   wait, and never committed. It is a POSIX advisory lock, which the OS
//   drops when the process that holds it ends, however it ends (a SIGKILL, a
//   crash, a power cut): there is no stale lock to judge, no pid to check and
//   none that can be given out again. SQLite tracks its locks per file within
//   a process too, so a second kernel in the same process is refused as one
//   in another process is. release() rolls back and closes; a test that
//   simulates a SIGKILL releases it as the OS would.
//
//   So kernel.lock is never stale, and must never be removed. A refusal
//   means a kernel holds it now (one the operator may not see, a launchd
//   daemon in Phase 3). Removed while that kernel runs, the next hold makes
//   a new kernel.lock on a new inode and locks that one, while the live
//   kernel still holds its lock on the unlinked file, so a second kernel is
//   let onto the same log: it closes the live kernel's runs as orphans,
//   revokes its grants `recovered`, kills its containers in the sweep, and
//   both append to one events.db. Nothing here can see a removal made after
//   a hold was taken, so the refusal says so where the operator reads it:
//   the lock is never stale, never remove it, stop the other kernel.
//
//   Refused, as a ConfigError naming the path: a hold another kernel has; a
//   lock path, or a journal path beside it, that is a link or anything but a
//   regular file; a file SQLite cannot lock for another reason; one whose
//   mode lets another account read it and cannot be made 0600. The lock
//   file is created 0600, and a looser one tightened, BEFORE SQLite opens it:
//   SQLite makes <dataDir>/kernel.lock-journal at BEGIN EXCLUSIVE, gives it
//   the lock file's own mode, keeps it while the hold lasts and removes it at
//   release. So both are 0600 like everything else in the data directory,
//   though neither holds any data: the lock file is an empty database, and
//   the journal holds only SQLite's journal header (no page is ever
//   journaled). The OS drops a killed kernel's lock but not its journal,
//   which stays until the next kernel's hold takes it over and removes it at
//   that hold's release.

import { chmodSync, closeSync, lstatSync, openSync } from 'node:fs'
import { join } from 'node:path'

import { ConfigError } from './errors.js'
import { openDb, type Db } from './events/db.js'

/** The hold's file in the data directory. */
export const DATA_LOCK_FILE = 'kernel.lock'

/** The rollback journal SQLite keeps beside the lock file while the hold lasts. */
export const DATA_LOCK_JOURNAL = `${DATA_LOCK_FILE}-journal`

/** A kernel's hold on its data directory. */
export interface DataLock {
  readonly path: string
  /** Drop the hold. Idempotent. */
  release(): void
}

/** SQLITE_BUSY: the lock is someone else's. */
const SQLITE_BUSY = 5

/** True when `e` is SQLite saying the database is locked. */
function busy(e: unknown): boolean {
  if (typeof e !== 'object' || e === null) return false
  const errcode = (e as { errcode?: unknown }).errcode
  return errcode === SQLITE_BUSY || (e instanceof Error && /database is locked/i.test(e.message))
}

/**
 * Make `path` a private regular file, or leave it absent: refused when it is
 * a link or anything but a regular file, tightened to 0600 when its mode lets
 * another account in, and, when `create` says so and it is absent, created
 * 0600 (exclusively, so a link planted meanwhile is refused, not followed).
 */
function keepLockFile(path: string, create: boolean): void {
  for (let attempt = 0; attempt < 2; attempt++) {
    let st: ReturnType<typeof lstatSync>
    try {
      st = lstatSync(path)
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code
      if (code !== 'ENOENT') throw new ConfigError(`${path} cannot be examined (${String(code)})`)
      if (!create) return
      try {
        closeSync(openSync(path, 'wx', 0o600))
        return
      } catch (made) {
        const madeCode = (made as NodeJS.ErrnoException).code
        // Made by someone else since the lstat: examined again, as it stands.
        if (madeCode === 'EEXIST') continue
        throw new ConfigError(`${path} cannot be created (${String(madeCode)})`)
      }
    }
    if (st.isSymbolicLink() || !st.isFile()) {
      throw new ConfigError(
        `${path} is not a regular file (a link is not one), so it is not the kernel's: remove it, then start the kernel again`,
      )
    }
    const mode = st.mode & 0o777
    if ((mode & 0o077) === 0) return
    try {
      chmodSync(path, 0o600)
    } catch (e) {
      throw new ConfigError(
        `${path} has mode 0${mode.toString(8)}, so other accounts can read it, and it could not be made 0600: ` +
          `${e instanceof Error ? e.message : String(e)}`,
      )
    }
    return
  }
  throw new ConfigError(`${path} keeps changing under the kernel, so it is not the kernel's lock`)
}

/**
 * Why a boot is refused while another kernel holds `dataDir`: what a second
 * kernel would do, that the lock is never stale (so a kernel holds it now),
 * that removing it while that kernel runs lets a second one onto the same
 * log, and what to do instead. It never tells the operator to remove the
 * file: the one sentence that names its removal forbids it.
 */
export function lockHeldRefusal(dataDir: string, path: string): string {
  return (
    `another kernel holds ${dataDir} (${path} is locked): one kernel per event log. A second one would close the ` +
    "live kernel's runs as orphans, revoke its egress grants and kill its containers. The lock is never stale: the " +
    'OS drops it when the kernel holding it ends, however it ends, so a kernel holds it now, perhaps one you do not ' +
    `see (a launchd job, another terminal). Never remove ${DATA_LOCK_FILE}: one removed while its kernel runs lets ` +
    'a second kernel onto the same log. Stop the other kernel (Ctrl-C in the terminal running its `npm run dev`, ' +
    'or stop its launchd job), or give this one its own dataDir'
  )
}

/**
 * Take the hold on `dataDir`, or throw a ConfigError saying why it cannot be
 * taken. See the contract above.
 */
export function holdDataDir(dataDir: string): DataLock {
  const path = join(dataDir, DATA_LOCK_FILE)
  // Both before SQLite opens the lock: the journal it makes takes the lock
  // file's mode, and a journal path that is a link would be followed.
  keepLockFile(path, true)
  keepLockFile(join(dataDir, DATA_LOCK_JOURNAL), false)
  let db: Db
  try {
    // No pragmas: the file holds no table, and WAL would add files to hold none.
    db = openDb(path, { applyPragmas: false, timeoutMs: 0 })
  } catch (e) {
    throw new ConfigError(`${path} cannot be opened as the kernel's lock: ${e instanceof Error ? e.message : String(e)}`)
  }
  try {
    db.exec('BEGIN EXCLUSIVE')
  } catch (e) {
    db.close()
    if (busy(e)) {
      throw new ConfigError(lockHeldRefusal(dataDir, path))
    }
    throw new ConfigError(`${path} cannot be locked: ${e instanceof Error ? e.message : String(e)}`)
  }
  let released = false
  return {
    path,
    release(): void {
      if (released) return
      released = true
      try {
        db.exec('ROLLBACK')
      } catch {
        // Nothing was written; the close below drops the lock either way.
      }
      db.close()
    },
  }
}
