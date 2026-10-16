// A throwaway copy of this checkout, for tests that run entry points as
// programs.
//
// An entry point finds its repository from its cwd (src/main.ts, the CLI) or
// from its own file (scripts/eval.ts). Spawned from the real checkout, a
// regression — or a falsify mutant — that makes one open <repo>/.env would
// read the operator's real keys before any assertion could object. Spawned
// from here, it opens the TRAP below: mode 0644 and a name no config declares,
// so the loader refuses it loudly and nothing is read.
//
// The copy is taken when the test file loads, so a falsify run that has just
// mutated src/ is exercised as mutated. node_modules is linked, not copied.

import './guard.js'

import { chmodSync, cpSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '')

const COPIED_DIRS = ['src', 'scripts', 'config', 'agents', 'souls'] as const
// .npmrc too, so anything that does reach npm keeps its cache in the copy's
// .aos/, deleted with it, never in ~/.npm (the operator's footprint rule).
const COPIED_FILES = ['package.json', 'tsconfig.json', '.gitignore', '.npmrc'] as const

/** What the trap holds: refused for its mode before its content is ever parsed. */
export const TRAP_DOTENV = 'NODE_OPTIONS=--require=/nonexistent/aos-dotenv-trap.js\n'

export interface ShadowCheckout {
  readonly root: string
  dispose(): void
}

export function shadowCheckout(): ShadowCheckout {
  const root = mkdtempSync(join(tmpdir(), 'aos-checkout-'))
  for (const dir of COPIED_DIRS) cpSync(join(REPO, dir), join(root, dir), { recursive: true })
  for (const file of COPIED_FILES) cpSync(join(REPO, file), join(root, file))
  symlinkSync(join(REPO, 'node_modules'), join(root, 'node_modules'))
  const trap = join(root, '.env')
  writeFileSync(trap, TRAP_DOTENV, { mode: 0o644 })
  chmodSync(trap, 0o644)
  return { root, dispose: () => rmSync(root, { recursive: true, force: true }) }
}
