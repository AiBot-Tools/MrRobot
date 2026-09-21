// Per-test temporary directory, removed when the test ends.
//
// Every store, data dir and workspace a test touches lives under one of these,
// never under the repo and never under a shared path: tests must not see each
// other's state, and a crashed test must not leave a database behind.

import './guard.js'

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir as osTmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestContext } from 'node:test'

/** Make a scratch directory and register its removal on `t.after`. */
export function tmpdir(t: TestContext): string {
  const dir = mkdtempSync(join(osTmpdir(), 'aos-test-'))
  t.after(() => {
    rmSync(dir, { recursive: true, force: true })
  })
  return dir
}
