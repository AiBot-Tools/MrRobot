// A real child for the tests of the installer's process runner
// (scripts/install/run.ts).
//
// The runner runs what the installer runs and nothing more: no shell, no
// env, no mkfifo or cat, nothing for a test's sake (CLAUDE.md: no bypass of
// the gate "for testing"). So a test that needs a real child (one that
// writes its streams, reads its stdin, leads a process group, makes a FIFO
// or prints its environment) runs it as the installer runs pmmcp's facts: a
// checkout's .venv/bin/python by absolute path, on `scripts/pmmcp_facts.py
// --json`. Here that python is a script whose body does what the test
// needs, with every path it needs written into it; the facts' arguments are
// ignored. Each lives in a mkdtemp folder of its own, never pmmcp's.

import './guard.js'

import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { TestContext } from 'node:test'

import { tmpdir } from './tmpdir.js'

/** What a test hands the runner, spread into its spec. */
export interface StandIn {
  readonly command: string
  readonly args: readonly string[]
  readonly cwd: string
}

/** A word a /bin/sh body can hold, whatever it contains: single-quoted. */
export const shWord = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`

/**
 * A stand-in .venv/bin/python whose body runs under `interpreter` (/bin/sh
 * by default; a test that reads the environment it was given uses node,
 * which adds no name of its own as a shell adds PWD and SHLVL). A /bin/sh one
 * carries a line of its own, so its bytes are never a stop or start script's.
 */
export function pythonStandIn(t: TestContext, body: string, interpreter = '/bin/sh'): StandIn {
  const cwd = join(tmpdir(t), 'stand-in')
  mkdirSync(join(cwd, '.venv', 'bin'), { recursive: true })
  const command = join(cwd, '.venv', 'bin', 'python')
  const mark = interpreter === '/bin/sh' ? "# a stand-in for a checkout's .venv/bin/python\n" : ''
  writeFileSync(command, `#!${interpreter}\n${mark}${body}\n`)
  chmodSync(command, 0o755)
  return { command, args: ['scripts/pmmcp_facts.py', '--json'], cwd }
}
