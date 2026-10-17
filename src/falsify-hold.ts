// What a falsify run (scripts/falsify) leaves in a tree, read without loading
// the runner.
//
// CONTRACT
//
//   While `npm run falsify` runs it holds <root>/.falsify/lock.json (its pid,
//   its start time, its run id), and while a source file holds a mutant it
//   keeps the file's original bytes in <root>/.falsify/journal.json. Either
//   means src/ may hold a deliberately planted bug, a disabled check or a
//   credentials path, now or seconds from now. So the daemon does not boot on
//   such a tree (src/main.ts), and the test suite's guard admits only the
//   run's own test processes.
//
//   Liveness here is the pid alone (kill 0; EPERM is someone else's live
//   process). The runner's own check adds the start time, which needs ps; a
//   daemon boot or a test load should not spawn one. A pid reused after a
//   crash therefore reads as live: a refusal, which `npm run falsify --
//   --recover` (start time included) clears.
//
//   Kept out of src/main.ts so the falsify catalog can mutate it: an entry
//   point is never mutated beside the tests that spawn entry points.

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

export const FALSIFY_JOURNAL = join('.falsify', 'journal.json')
export const FALSIFY_LOCK = join('.falsify', 'lock.json')

/** process.kill's signature, injectable so a test can answer EPERM without another user's process. */
export type Kill = (pid: number, signal: 0) => void

/** The live run holding the lock at root, or undefined: no lock, an unreadable one, this process's own, or a pid that is gone. */
export function lockHolder(
  root: string,
  kill: Kill = (pid, signal) => {
    process.kill(pid, signal)
  },
): { readonly pid: number; readonly runId: string | undefined } | undefined {
  let lock: { pid?: unknown; runId?: unknown }
  try {
    lock = JSON.parse(readFileSync(join(root, FALSIFY_LOCK), 'utf8')) as { pid?: unknown; runId?: unknown }
  } catch {
    return undefined
  }
  const { pid, runId } = lock
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0 || pid === process.pid) return undefined
  try {
    kill(pid, 0)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EPERM') return undefined
  }
  return { pid, runId: typeof runId === 'string' && runId !== '' ? runId : undefined }
}

/** Why the daemon must not boot on this tree, or undefined when no falsify run has it. */
export function falsifyRefusal(root: string, kill?: Kill): string | undefined {
  if (existsSync(join(root, FALSIFY_JOURNAL))) {
    return (
      `${join(root, FALSIFY_JOURNAL)} exists: a falsify run is in progress or was interrupted, and a source ` +
      'file may still be mutated. Let it finish, or run: npm run falsify -- --recover'
    )
  }
  const holder = lockHolder(root, kill)
  if (holder !== undefined) {
    return (
      `a falsify run (pid ${String(holder.pid)}) holds this tree and mutates its source files as it goes. Let it finish; ` +
      'if none is going, run: npm run falsify -- --recover'
    )
  }
  return undefined
}
