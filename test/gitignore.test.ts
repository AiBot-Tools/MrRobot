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
import { mkdirSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs'
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
  ['***/.env\n', true, 'so does a leading run of three stars'],
  ['*.env\n', true, '* matches the empty string and the leading dot'],
  ['.e[n]v\n', true, 'a bracket class'],
  ['.e[!x]v\n', true, 'a negated bracket class'],
  ['.e[!E]v\n', true, 'a class member is not folded, so git applies [!E] to e under either setting'],
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
  // Shapes the first version missed (verification of ff5ebaa): git applies each.
  ['.env*\n!***/.env\n', false, 'a run of three stars is **/ to git'],
  ['.env*\n!/***/.env\n', false, 'anchored, three stars'],
  ['.env*\n!.**/*\n', false, "git's literal-prefix rule: .**/ can match zero directories"],
  ['.env*\n!.e[n/]v\n', false, 'a / inside a bracket anchors the pattern but is a class member'],
  ['.env*\n![!/]env\n', false, 'a negated class holding /'],
  ['.env*\n!.env\0junk\n', false, 'git reads a pattern only up to its first NUL'],
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
  ['.e[!A-Z]v\n', 'an ignoring line git applies only WITHOUT core.ignorecase (folded, [!A-Z] refuses e)'],
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
  // The macOS default refuses [!A-Z] for 'e', so crediting that line would be
  // a false "ignored" there.
  writeFileSync(join(repo, '.gitignore'), '.e[!A-Z]v\n')
  assert.equal(gitIgnores(repo, '.env', false), true)
  assert.equal(gitIgnores(repo, '.env', true), false)
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
  // One subdirectory per generated file, each with its own .gitignore, .env
  // and .aos: a .gitignore applies to the entries directly beside it exactly
  // as the root one does to root entries, and git judges a whole batch in one
  // `check-ignore --stdin` per core.ignorecase setting.
  const repo = gitRepo(t)
  const BASE = [
    '.env', '.env*', '/.env', '/.env*', '*', '**/.env', '***/.env', '*.env', '.e[n]v', '.e[!A-Z]v', '.E*', '.env\r',
    '.aos', '/.aos/', '.aos/', '.a?s', '.[!A-Z]os/', '.**', '.env/**', 'foo/.env',
  ]
  const BITS = [
    '.', 'e', 'n', 'v', 'E', 'V', 'a', 'o', 's', 'A', '*', '**', '***', '?', '[', ']', '!', '^', '-', '/', '\\', ' ',
    '\t', '\r', '\0', '[!A-Z]', '[n/]', '[!/]', '[a-z]', '[E]', '[z-a]', '[--/]', '[:alpha:]', '#', '**/', '/**', '\\.',
  ]
  // mulberry32, fixed seed: reproducible, and unlike an LCG's low bits it
  // reaches every combination.
  let seed = 0x5eed
  const next = (n: number): number => {
    seed = (seed + 0x6d2b79f5) | 0
    let x = Math.imul(seed ^ (seed >>> 15), seed | 1)
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61)
    return Math.floor((((x ^ (x >>> 14)) >>> 0) / 4294967296) * n)
  }
  const texts: string[] = []
  for (let i = 0; i < 2500; i++) {
    const lines: string[] = []
    for (let j = 0, count = 1 + next(4); j < count; j++) {
      let line = next(3) === 0 ? '' : (BASE[next(BASE.length)] ?? '')
      for (let k = 0, edits = next(4); k < edits; k++) {
        const at = next(line.length + 1)
        line = line.slice(0, at) + (BITS[next(BITS.length)] ?? '') + line.slice(at)
      }
      lines.push((next(5) < 2 ? '!' : '') + line)
    }
    const text = `${lines.join('\n')}\n`
    const dir = join(repo, `c${String(i)}`)
    mkdirSync(join(dir, '.aos'), { recursive: true })
    writeFileSync(join(dir, '.aos', 'f'), 'x')
    writeFileSync(join(dir, '.env'), 'x')
    writeFileSync(join(dir, '.gitignore'), Buffer.from(text, 'latin1'))
    texts.push(text)
  }
  const paths = texts.flatMap((_, i) => [`c${String(i)}/.env`, `c${String(i)}/.aos`])
  const ignoredBy = (ignorecase: boolean): Set<string> => {
    const r = spawnSync('git', ['-C', repo, '-c', `core.ignorecase=${String(ignorecase)}`, 'check-ignore', '--stdin'], {
      env: GIT_ENV,
      encoding: 'utf8',
      input: `${paths.join('\n')}\n`,
      maxBuffer: 1 << 24,
    })
    assert.ok(r.status === 0 || r.status === 1, `git check-ignore failed: ${r.stderr}`)
    return new Set(r.stdout.split('\n').filter((p) => p !== ''))
  }
  const git = { exact: ignoredBy(false), folded: ignoredBy(true) }
  const failures: string[] = []
  let claimed = 0
  texts.forEach((text, i) => {
    for (const [entry, kind] of [['.env', 'file'], ['.aos', 'dir']] as const) {
      if (!rootGitignoreIgnores(join(repo, `c${String(i)}`), entry, kind)) continue
      claimed += 1
      const path = `c${String(i)}/${entry}`
      if (!git.exact.has(path) || !git.folded.has(path)) failures.push(`${entry}: ${JSON.stringify(text)}`)
    }
  })
  assert.deepEqual(failures, [])
  // A generator that never produces an "ignored" would pass vacuously.
  assert.ok(claimed > 400, `only ${String(claimed)} "ignored" answers were exercised`)
})

test('a .aos that is a symlink is not ignored, even by /.aos/: git judges it a file', (t) => {
  // `mv .aos data && ln -s data .aos`: git stages the link and everything in
  // data/, so whatever is written through .aos would reach a commit.
  const repo = gitRepo(t)
  writeFileSync(join(repo, '.gitignore'), '/.aos/\n.aos\n')
  rmSync(join(repo, '.aos'), { recursive: true })
  mkdirSync(join(repo, 'data'))
  symlinkSync('data', join(repo, '.aos'))
  assert.equal(gitignoresAos(repo), false)
})

test('a .gitignore of 100 MiB or more ignores nothing: git 2.50 skips the whole file', (t) => {
  const repo = gitRepo(t)
  const path = join(repo, '.gitignore')
  writeFileSync(path, '.env*\n/.aos/\n')
  assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), true)
  // One byte under: git appends its newline, the total is exactly the limit,
  // and `size > PATTERN_MAX_FILE_SIZE` lets it through (dir.c, v2.50.1).
  truncateSync(path, 100 * 1024 * 1024 - 1) // sparse: costs no disk
  assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), true)
  truncateSync(path, 100 * 1024 * 1024)
  assert.equal(rootGitignoreIgnores(repo, '.env', 'file'), false)
  assert.equal(gitignoresAos(repo), false)
})

test('git tracks no credentials file: .env.example is the only .env* in the index, in any case', () => {
  // .gitignore does not apply to a tracked file, so a force-added .env passes
  // every ignore check and rides the next commit into this PUBLIC repository.
  // Matched without case: on APFS a .Env is the same file to the loader.
  const tracked = spawnSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 1 << 24 })
  assert.equal(tracked.status, 0, tracked.stderr)
  const envish = tracked.stdout.split('\0').filter((p) => /(^|\/)\.env/i.test(p))
  assert.deepEqual(envish, ['.env.example'])
})
