// An account that file modes bind, for tests of what a mode refuses.
//
// Root reads, writes and searches whatever the mode bits say, so a suite run
// as root (a container) cannot see an EACCES. These run the part of a test
// that must meet one as nobody (65534), by seteuid, and put the effective uid
// back however it ends; run as anyone else, the test's own account is bound
// by modes already and nothing changes. Only the effective uid moves: the
// real one stays, so the change can be undone, and nothing here spawns.

import './guard.js'

import { chownSync } from 'node:fs'

/** The account a root suite takes on. */
export const NOBODY = 65534

/** Whether the suite runs as root, so asNobody changes the effective uid. */
export const AS_ROOT = process.geteuid?.() === 0

/** The uid files made inside asNobody belong to: nobody under root, else the suite's own. */
export const BOUND_UID: number = AS_ROOT ? NOBODY : (process.geteuid?.() ?? NOBODY)

/** Give paths to the account asNobody runs as (a no-op unless the suite runs as root). */
export function handTo(...paths: readonly string[]): void {
  if (!AS_ROOT) return
  for (const p of paths) chownSync(p, NOBODY, NOBODY)
}

/** Run `fn` as an account file modes bind; the effective uid is put back when it settles. */
export async function asNobody<T>(fn: () => T | Promise<T>): Promise<T> {
  if (!AS_ROOT) return fn()
  const seteuid = process.seteuid
  if (seteuid === undefined) throw new Error('process.seteuid is not available here')
  seteuid(NOBODY)
  try {
    return await fn()
  } finally {
    seteuid(0)
  }
}
