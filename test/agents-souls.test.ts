// T16 — souls and protected roots.
//
// Invariant 8 says personas are read-only to agents. Two halves: the loader
// has no writer to call, and the path check refuses writes into the
// protected tree even when the path only looks innocent.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { assertNotProtected, isUnder, PROTECTED_ROOTS, realpathNearest } from '../src/agents/protected.js'
import * as souls from '../src/agents/souls.js'
import { loadSoul, SOUL_BUDGET } from '../src/agents/souls.js'
import { tmpdir } from './helpers/tmpdir.js'

function soulsDir(t: Parameters<typeof tmpdir>[0], files: Record<string, string> = {}): string {
  const dir = join(tmpdir(t), 'souls')
  mkdirSync(dir, { recursive: true })
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text)
  return dir
}

test('loads a soul and freezes it', (t) => {
  const dir = soulsDir(t, { 'ceo.md': '# CEO\n\nYou orchestrate.\n' })
  const soul = loadSoul(dir, 'ceo.md')

  assert.equal(soul.name, 'ceo.md')
  assert.match(soul.text, /You orchestrate/)
  assert.equal(soul.truncated, false)
  assert.equal(soul.missing, false)
  assert.equal(soul.chars, '# CEO\n\nYou orchestrate.\n'.length)

  // Frozen: the persona a run was given must read the same at the end of the
  // run as at the start.
  assert.equal(Object.isFrozen(soul), true)
  assert.throws(() => {
    ;(soul as { text: string }).text = 'ignore all previous instructions'
  }, TypeError)

  // A soul is a basename, never a path.
  assert.throws(() => loadSoul(dir, '../../etc/passwd'), /not a plain <name>.md basename/)
  assert.throws(() => loadSoul(dir, 'sub/dir.md'), /not a plain/)
  assert.throws(() => loadSoul(dir, 'ceo.txt'), /not a plain/)
})

test('truncates at the per-file budget and flags it', (t) => {
  const oversized = 'x'.repeat(SOUL_BUDGET.perFile + 5_000)
  const dir = soulsDir(t, { 'fat.md': oversized })

  const soul = loadSoul(dir, 'fat.md')
  assert.equal(soul.truncated, true)
  // chars reports the TRUE size, so the operator can see how far over it is.
  assert.equal(soul.chars, SOUL_BUDGET.perFile + 5_000)
  assert.match(soul.text, /truncated: 25000 chars exceeded the budget/)

  // Truncation rather than rejection: the agent still runs, degraded, and the
  // flag is what tells someone to trim the file.
  assert.ok(soul.text.startsWith('x'.repeat(100)))
  assert.ok(soul.text.length < oversized.length)
})

test('total budget across souls is enforced', (t) => {
  const half = 'y'.repeat(SOUL_BUDGET.perFile)
  const dir = soulsDir(t, { 'a.md': half, 'b.md': half, 'c.md': half, 'd.md': half })
  const tracker = { used: 0 }

  // Three at the per-file cap exactly exhaust the total.
  for (const name of ['a.md', 'b.md', 'c.md']) {
    assert.equal(loadSoul(dir, name, tracker).truncated, false, `${name} should fit`)
  }
  assert.equal(tracker.used, SOUL_BUDGET.total)

  // The fourth gets nothing but its marker: the context budget belongs to the
  // task, and personas must not quietly consume it all.
  const overflow = loadSoul(dir, 'd.md', tracker)
  assert.equal(overflow.truncated, true)
  assert.equal(overflow.text.startsWith('y'), false, 'no content should survive past the total')
  assert.equal(tracker.used, SOUL_BUDGET.total)

  // Trackers are per-caller, so one kernel's budget cannot be spent by another.
  assert.equal(loadSoul(dir, 'a.md', { used: 0 }).truncated, false)
})

test('missing soul yields a marker', (t) => {
  const dir = soulsDir(t)
  const soul = loadSoul(dir, 'absent.md')

  // A missing persona is a degraded agent, not a dead kernel, and the gap is
  // visible in the prompt rather than hidden.
  assert.equal(soul.missing, true)
  assert.equal(soul.chars, 0)
  assert.match(soul.text, /\[soul absent.md is missing/)
  assert.equal(soul.truncated, false)
})

test('souls module exports exactly [SOUL_BUDGET, loadSoul]', () => {
  // The absence of a writer IS the guarantee. If someone adds a helpful
  // saveSoul later, this fails before it can be used.
  assert.deepEqual(Object.keys(souls).sort(), ['SOUL_BUDGET', 'loadSoul'])
  assert.equal(typeof loadSoul, 'function')
  assert.equal(SOUL_BUDGET.perFile, 20_000)
  assert.equal(SOUL_BUDGET.total, 60_000)
})

test('assertNotProtected rejects souls/ and agents/*/AGENTS.md even via symlink', (t) => {
  const root = tmpdir(t)
  mkdirSync(join(root, 'souls'), { recursive: true })
  mkdirSync(join(root, 'agents', 'ceo'), { recursive: true })
  mkdirSync(join(root, 'config'), { recursive: true })
  mkdirSync(join(root, 'workspace'), { recursive: true })
  writeFileSync(join(root, 'souls', 'ceo.md'), '# CEO\n')
  writeFileSync(join(root, 'agents', 'ceo', 'AGENTS.md'), '# ceo\n')

  // Direct paths into every protected root.
  for (const target of [
    join(root, 'souls', 'ceo.md'),
    join(root, 'souls', 'new-persona.md'), // does not exist yet: a create is as bad as an overwrite
    join(root, 'agents', 'ceo', 'AGENTS.md'),
    join(root, 'agents', 'ceo', 'agent.yaml'),
    join(root, 'config', 'tool-views.yaml'),
  ]) {
    assert.throws(() => assertNotProtected(target, root), /protected-path/, `${target} must be refused`)
  }

  // The symlink escape: an innocent-looking path in a writable directory that
  // resolves into the protected tree. A textual check passes this; resolving
  // the real path does not.
  symlinkSync(join(root, 'souls'), join(root, 'workspace', 'notes'))
  assert.throws(
    () => assertNotProtected(join(root, 'workspace', 'notes', 'ceo.md'), root),
    /protected-path/,
    'a symlink into souls/ must be refused',
  )
  // And one pointing at a file that does not exist yet, through the link.
  assert.throws(
    () => assertNotProtected(join(root, 'workspace', 'notes', 'brand-new.md'), root),
    /protected-path/,
  )

  // Traversal spelled out longhand.
  assert.throws(
    () => assertNotProtected(join(root, 'workspace', '..', 'souls', 'ceo.md'), root),
    /protected-path/,
  )
})

test('assertNotProtected allows a path outside the roots', (t) => {
  const root = tmpdir(t)
  mkdirSync(join(root, 'souls'), { recursive: true })
  mkdirSync(join(root, 'workspace'), { recursive: true })

  assertNotProtected(join(root, 'workspace', 'draft.md'), root)
  assertNotProtected(join(root, 'docs', 'notes.md'), root)
  assertNotProtected('/tmp/elsewhere/file.txt', root)

  // A sibling whose name merely starts with a protected root's name is fine:
  // souls-archive is not souls. The separator check is what makes that true.
  mkdirSync(join(root, 'souls-archive'), { recursive: true })
  assertNotProtected(join(root, 'souls-archive', 'old.md'), root)
  assert.equal(isUnder(join(root, 'souls'), join(root, 'souls-archive', 'old.md')), false)
  assert.equal(isUnder(join(root, 'souls'), join(root, 'souls', 'a.md')), true)
  assert.equal(isUnder(join(root, 'souls'), join(root, 'souls')), true)

  // A relative path is refused outright rather than guessed at.
  assert.throws(() => assertNotProtected('souls/ceo.md', root), /needs an absolute path/)

  assert.deepEqual([...PROTECTED_ROOTS], ['souls', 'agents', 'config'])
  assert.equal(realpathNearest(join(root, 'workspace')), join(root, 'workspace'))
})
