import './helpers/guard.js'

// src/gitignore.ts against git itself. The property that matters is one-sided:
// whenever the matcher says "ignored", `git check-ignore` must agree, under
// core.ignorecase false (Linux) and true (the macOS default). The reverse may
// fail on purpose — those are the fail-closed choices, and each one is pinned
// below so a change to them is a decision, not an accident.
//
// git runs with no system or global config, so an operator's own excludes file
// cannot make git agree for the wrong reason.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { test, type TestContext } from 'node:test'

import { gitignoresAos } from '../src/config.js'
import { rootGitignoreIgnores } from '../src/gitignore.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'

const GIT_ENV = {
  PATH: process.env['PATH'] ?? '/usr/bin:/bin',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  HOME: '/nonexistent',
  XDG_CONFIG_HOME: '/nonexistent',
}

function gitRepo(t: TestContext): string {
  const repo = tmpdir(t)
  const init = spawnSync('git', ['init', '-q', repo], { env: GIT_ENV, encoding: 'utf8' })
  assert.equal(init.status, 0, init.stderr)
  writeFileSync(join(repo, '.env'), 'x\n')
  mkdirSync(join(repo, '.aos'))
  writeFileSync(join(repo, '.aos', 'events.db'), 'x')
  return repo
}

function gitIgnores(repo: string, entry: string, ignorecase: boolean): boolean {
  const r = spawnSync('git', ['-C', repo, '-c', `core.ignorecase=${String(ignorecase)}`, 'check-ignore', '-q', entry], {
    env: GIT_ENV,
    encoding: 'utf8',
  })
  assert.ok(r.status === 0 || r.status === 1, `git check-ignore failed: ${r.stderr}`)
  return r.status === 0
}

// [gitignore text, what the matcher answers for the file .env, why]
const DOTENV_CASES: readonly (readonly [string, boolean, string])[] = [
  ['.env\n', true, 'plain'],
  ['/.env\n', true, 'anchored'],
  ['.env*\n!.env.example\n', true, 'the shipped pair'],
  ['/.env*\n', true, 'anchored glob'],
  ['*\n', true, 'everything'],
  ['/**\n', true, 'everything, anchored'],
  ['**/.env\n', true, 'leading **/ matches zero directories'],
  ['*.env\n', true, '* matches the empty string and the leading dot'],
  ['.e[n]v\n', true, 'a bracket class'],
  ['.e[!x]v\n', true, 'a negated bracket class'],
  ['.e?v\n', true, '?'],
  ['\\.env\n', true, 'an escaped ordinary character'],
  ['.env   \n', true, 'trailing spaces are trimmed'],
  ['\xEF\xBB\xBF.env\n', true, 'a UTF-8 BOM is skipped, as git does'],
  ['.env\n\\!.env\n', true, '\\! is a literal !, not a negation'],
  ['.env\n!*.example\n', true, 'a negation that cannot match .env'],
  ['.env\n!.env/\n', true, 'a directory-only negation does not touch a file'],
  ['', false, 'no lines'],
  [' .env\n', false, 'a leading space is part of the pattern'],
  ['.env\t\n', false, 'a trailing tab is part of the pattern'],
  ['.env\\ \n', false, 'an escaped trailing space is kept'],
  ['.env/\n', false, 'directory-only'],
  ['foo/.env\n', false, 'needs a directory'],
  ['.env/**\n', false, 'everything inside, not the entry'],
  ['# .env\n', false, 'a comment'],
  ['.env\n!.env\n', false, 'negated'],
  ['.env*\n!*\n', false, '!* un-ignores everything'],
  ['.env*\n!*.env\n', false, '!*.env matches .env'],
  ['.env*\n!.en?\n', false, '!.en? matches .env'],
  ['.env*\n![.]env\n', false, 'a bracket negation'],
  ['.env*\n!\\.env\n', false, 'an escaped negation'],
  ['.env*\n!**/.env\n', false, 'a **/ negation'],
  ['.env*\n!/.env*\n', false, 'an anchored negation'],
  ['.env\n!.env \n', false, 'a negation with trailing spaces'],
]

// Where the matcher answers false and git (at least sometimes) says true: the
// fail-closed choices from the contract, pinned.
const FAIL_CLOSED: readonly (readonly [string, string])[] = [
  ['.env\r\n', 'an ignoring line with a CR'],
  ['.ENV\n', 'an ignoring line that matches only under core.ignorecase'],
  ['.e[[:alpha:]]v\n', 'a POSIX class'],
  ['.env\n!.ENV\n', 'a negation that matches only under core.ignorecase still un-ignores'],
  ['.env\n!.env\r\n', 'a negation with a CR still un-ignores'],
  ['.env\n!.e[[:alpha:]]v\n', 'an unmodelled negation still un-ignores'],
]

test('the matcher agrees with git check-ignore on what ignores <repo>/.env', (t) => {
  const repo = gitRepo(t)
  for (const [text, expected, why] of DOTENV_CASES) {
    writeFileSync(join(repo, '.gitignore'), Buffer.from(text, 'latin1'))
    assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), expected, `matcher: ${why}`)
    assert.equal(gitIgnores(repo, '.env', false), expected, `git: ${why}`)
  }
})

test('every fail-closed choice answers "not ignored", whatever git says', (t) => {
  const repo = gitRepo(t)
  for (const [text, why] of FAIL_CLOSED) {
    writeFileSync(join(repo, '.gitignore'), Buffer.from(text, 'latin1'))
    assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), false, why)
  }
  // And git really does disagree on the ignorecase pair, which is why they are
  // here: the macOS default would ignore .ENV and honour !.ENV.
  writeFileSync(join(repo, '.gitignore'), '.ENV\n')
  assert.equal(gitIgnores(repo, '.env', true), true)
  writeFileSync(join(repo, '.gitignore'), '.env\n!.ENV\n')
  assert.equal(gitIgnores(repo, '.env', true), false)
})

test('a symlinked or missing .gitignore ignores nothing', (t) => {
  const repo = gitRepo(t)
  assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), false)
  const real = join(tmpdir(t), 'gitignore')
  writeFileSync(real, '.env*\n/.aos/\n')
  symlinkSync(real, join(repo, '.gitignore'))
  assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), false)
  assert.equal(gitignoresAos(repo), false)
})

test('the matcher agrees with git on what ignores the directory <repo>/.aos', (t) => {
  const repo = gitRepo(t)
  const cases: readonly (readonly [string, boolean])[] = [
    ['/.aos/\n', true],
    ['.aos/\n', true],
    ['/.aos\n', true],
    ['.aos\n', true],
    ['.a*/\n', true],
    ['/.aos/\n!.aos\n', false],
    ['/.aos/\n!/.aos/\n', false],
    ['.aos/**\n', false],
    ['.aos/*\n', false],
    ['  /.aos/\n', false],
    ['node_modules/\n', false],
  ]
  for (const [text, expected] of cases) {
    writeFileSync(join(repo, '.gitignore'), text)
    assert.equal(gitignoresAos(repo), expected, `matcher: ${JSON.stringify(text)}`)
    // git answers for the directory entry itself; .aos/** ignores the contents
    // but not the directory, so a later ! line could re-include a file in it.
    assert.equal(gitIgnores(repo, '.aos', false), expected, `git: ${JSON.stringify(text)}`)
  }
})

test('soundness over generated .gitignore files: "ignored" is never claimed where git disagrees', (t) => {
  const repo = gitRepo(t)
  const POOL = [
    '.env', '/.env', '.env*', '/.env*', '*', '**', '/**', '**/.env', '*.env', '.e*', '.en?', '.e[a-z]v', '.e[!a]v',
    '.ENV', '.Env*', '.env/', '.env/**', 'foo/.env', ' .env', '.env\t', '.env  ', '.env\\ ', '\\.env', '\\!.env',
    '.env\r', '.e[[:alpha:]]v', '#.env', '.aos', '/.aos/', '.aos/', '.a?s', '[.]aos',
  ]
  // A fixed-seed generator, so a failure names a reproducible input.
  let seed = 0x5eed
  const next = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff
    return seed % n
  }
  const failures: string[] = []
  for (let i = 0; i < 150; i++) {
    const lines: string[] = []
    const count = 1 + next(4)
    for (let j = 0; j < count; j++) lines.push((next(3) === 0 ? '!' : '') + (POOL[next(POOL.length)] ?? ''))
    const text = `${lines.join('\n')}\n`
    writeFileSync(join(repo, '.gitignore'), text)
    for (const [entry, kind] of [['.env', 'file'], ['.aos', 'dir']] as const) {
      if (!rootGitignoreIgnores(repo, entry, kind)) continue
      for (const ignorecase of [false, true]) {
        if (!gitIgnores(repo, entry, ignorecase)) failures.push(`${entry} ignorecase=${String(ignorecase)}: ${JSON.stringify(text)}`)
      }
    }
  }
  assert.deepEqual(failures, [])
})

test('git tracks no credentials file: .env.example is the only .env* in the index', () => {
  // .gitignore does not apply to a tracked file, so a force-added .env passes
  // every ignore check and rides the next commit into this PUBLIC repository.
  const tracked = spawnSync('git', ['ls-files', '-z', '--', '.env*', '**/.env*'], { cwd: REPO_ROOT, encoding: 'utf8' })
  assert.equal(tracked.status, 0, tracked.stderr)
  assert.deepEqual(tracked.stdout.split('\0').filter((p) => p !== ''), ['.env.example'])
})
