// The one .env writer (src/secrets/dotenv-append.ts).
//
// The file it writes holds the operator's real keys, so these tests are about
// what it leaves alone: every existing byte, every file the loader refuses, and
// every value it generates, which must never be said. Every repository here is
// a mkdtemp directory, and every call goes through appendIn, which refuses any
// other root (hygiene.test.ts holds the calls to it), so nothing here can reach
// this checkout's .env. The suite may run as root (CI does), so each call says
// who runs it: the operator's uid unless a test is about root.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import fs, {
  appendFileSync,
  chmodSync,
  constants,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir as osTmpdir } from 'node:os'
import { join, sep } from 'node:path'
import test, { type TestContext } from 'node:test'
import { inspect } from 'node:util'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { assertTokenUsable } from '../src/control/auth.js'
import { ConfigError } from '../src/errors.js'
import { SecretMask, redactString } from '../src/events/redact.js'
import { parseProviders } from '../src/models/registry.js'
import {
  CREATED_HEADER,
  DotenvWriteError,
  GENERATED_LENGTH,
  MIN_GENERATED_LENGTH,
  appendCredentials,
  credentialNames,
  inspectCredentials,
  type AppendOptions,
  type AppendResult,
  type InspectOptions,
  type InspectResult,
} from '../src/secrets/dotenv-append.js'
import { DOTENV_MAX_BYTES, loadDotenv } from '../src/secrets/dotenv.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'

const ACCEPTED = new Set(['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY'])
/** The operator's uid on the Mac: the writer refuses root, and CI may be root. */
const OPERATOR_UID = 501
const KEY = 'qKeyVa1ueFor7estsOnlyZYXWVUTSRQPONM'

interface Who {
  readonly uid?: number
  /** 'process': leave euid to the writer's own default, process.geteuid(). */
  readonly euid?: number | 'process'
  readonly accepted?: ReadonlySet<string>
  readonly digests?: readonly string[]
  /** inspectIn only. */
  readonly valueLength?: number
}

/**
 * The only way these tests call the writer: `repo` must be a scratch
 * directory under the OS temp dir, never this checkout or anything in it.
 */
function appendIn(repo: string, generate: ReadonlyMap<string, () => string>, who: Who = {}): AppendResult {
  const real = realpathSync(repo)
  assert.ok(real.startsWith(realpathSync(osTmpdir()) + sep), `${repo} is not a scratch directory`)
  const checkout = realpathSync(REPO_ROOT)
  assert.ok(real !== checkout && !real.startsWith(checkout + sep), `${repo} is this checkout`)
  const euid = who.euid ?? OPERATOR_UID
  const options: AppendOptions = {
    repoRoot: repo,
    accepted: who.accepted ?? ACCEPTED,
    generate,
    ...(who.uid === undefined ? {} : { uid: who.uid }),
    ...(euid === 'process' ? {} : { euid }),
    ...(who.digests === undefined ? {} : { digests: who.digests }),
  }
  return appendCredentials(options)
}

/**
 * The only way these tests read a .env through the writer's inspection: held
 * to scratch directories as appendIn is, since it reads the file it is given.
 */
function inspectIn(repo: string, names: readonly string[], who: Who = {}): InspectResult {
  const real = realpathSync(repo)
  assert.ok(real.startsWith(realpathSync(osTmpdir()) + sep), `${repo} is not a scratch directory`)
  const checkout = realpathSync(REPO_ROOT)
  assert.ok(real !== checkout && !real.startsWith(checkout + sep), `${repo} is this checkout`)
  const euid = who.euid ?? OPERATOR_UID
  const options: InspectOptions = {
    repoRoot: repo,
    accepted: who.accepted ?? ACCEPTED,
    names,
    ...(who.uid === undefined ? {} : { uid: who.uid }),
    ...(euid === 'process' ? {} : { euid }),
    ...(who.digests === undefined ? {} : { digests: who.digests }),
    ...(who.valueLength === undefined ? {} : { valueLength: who.valueLength }),
  }
  return inspectCredentials(options)
}

/** A generator per name that records what it made and how often it was asked. */
function generators(...names: string[]): { generate: Map<string, () => string>; made: Map<string, string>; calls: () => number } {
  const made = new Map<string, string>()
  let calls = 0
  const generate = new Map<string, () => string>()
  for (const name of names) {
    generate.set(name, () => {
      calls += 1
      const value = randomBytes(32).toString('hex')
      made.set(name, value)
      return value
    })
  }
  return { generate, made, calls: () => calls }
}

/** A scratch repository whose .gitignore ignores .env, with an optional .env written at `mode`. */
function repoWith(t: TestContext, env?: string | Buffer, mode = 0o600): string {
  const repo = tmpdir(t)
  writeFileSync(join(repo, '.gitignore'), '/.env\n')
  if (env !== undefined) {
    writeFileSync(join(repo, '.env'), env, { mode })
    chmodSync(join(repo, '.env'), mode)
  }
  return repo
}

/** Everything about a path that a write, a chmod or a link would change. */
function snapshot(path: string): string {
  if (!existsSync(path) && !isLink(path)) return 'absent'
  const st = lstatSync(path)
  const body = st.isSymbolicLink()
    ? `-> ${readlinkSync(path)}`
    : st.isDirectory()
      ? readdirSync(path).sort().join(',')
      : readFileSync(path).toString('base64')
  return JSON.stringify({ mode: st.mode, ino: st.ino, nlink: st.nlink, size: st.size, mtime: st.mtimeMs, ctime: st.ctimeMs, body })
}

function isLink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink()
  } catch {
    return false
  }
}

/** The ConfigError message `fn` throws, asserting it throws one. */
function refusal(fn: () => unknown): string {
  try {
    fn()
  } catch (e) {
    assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
    return e.message
  }
  assert.fail('expected a ConfigError')
}

/** The DotenvWriteError the writer throws, asserting it throws one. */
function thrown(fn: () => unknown): DotenvWriteError {
  try {
    fn()
  } catch (e) {
    assert.ok(e instanceof DotenvWriteError, `threw ${String(e)}`)
    assert.ok(e instanceof ConfigError, 'a DotenvWriteError is no longer a ConfigError')
    return e
  }
  assert.fail('expected a DotenvWriteError')
}

/** A refusal: the message, after asserting the error says the file was not written. */
function untouched(fn: () => unknown): string {
  const e = thrown(fn)
  assert.equal(e.written, false, `a refusal said the file may have changed: ${e.message}`)
  return e.message
}

const modeOf = (path: string): number => lstatSync(path).mode & 0o777

/** Run `fn` (synchronous) with everything the writer could print through captured into `said`. */
function quietly<T>(said: string[], fn: () => T): T {
  const say = (s: string): void => {
    said.push(s)
  }
  const out = process.stdout.write.bind(process.stdout)
  const err = process.stderr.write.bind(process.stderr)
  const { log, error, warn, info, debug } = console
  process.stdout.write = ((chunk: string | Uint8Array) => (say(String(chunk)), true)) as typeof process.stdout.write
  process.stderr.write = ((chunk: string | Uint8Array) => (say(String(chunk)), true)) as typeof process.stderr.write
  console.log = console.error = console.warn = console.info = console.debug = (...args: unknown[]) => say(args.map(String).join(' '))
  try {
    return fn()
  } finally {
    process.stdout.write = out
    process.stderr.write = err
    Object.assign(console, { log, error, warn, info, debug })
  }
}

/** Whether any 8 characters of `value` appear in `text`. */
function echoes(text: string, value: string): boolean {
  for (let i = 0; i + 8 <= value.length; i += 1) if (text.includes(value.slice(i, i + 8))) return true
  return false
}

/** An errno error as node:fs throws one. */
const errno = (code: string, syscall: string): NodeJS.ErrnoException => Object.assign(new Error(`${code}: i/o error, ${syscall}`), { code, syscall })

test('creates a missing .env at 0600 with O_EXCL, only when .gitignore ignores it and no case variant exists', (t) => {
  t.after(() => SecretMask.clear())

  // No .gitignore, or one that re-includes .env: refused, nothing created, nothing generated.
  for (const gitignore of [undefined, '.env\n!.env\n', '.env/\n']) {
    const repo = tmpdir(t)
    if (gitignore !== undefined) writeFileSync(join(repo, '.gitignore'), gitignore)
    const g = generators('AOS_CONTROL_TOKEN')
    assert.match(untouched(() => appendIn(repo, g.generate)), /is not ignored by .*\.gitignore: add the line \/\.env/, String(gitignore))
    assert.equal(existsSync(join(repo, '.env')), false)
    assert.equal(g.calls(), 0)
  }

  // A case variant beside the missing .env: git would stage it, so nothing is created.
  {
    const repo = repoWith(t)
    writeFileSync(join(repo, '.Env'), `ANTHROPIC_API_KEY=${KEY}\n`, { mode: 0o600 })
    const before = snapshot(join(repo, '.Env'))
    const g = generators('AOS_CONTROL_TOKEN')
    assert.match(untouched(() => appendIn(repo, g.generate)), /\.Env on disk, not \.env.*Rename it to \.env/)
    assert.equal(snapshot(join(repo, '.Env')), before)
    assert.deepEqual(readdirSync(repo).sort(), ['.Env', '.gitignore'])
    assert.equal(g.calls(), 0)
  }

  // A dangling symlink at .env: nothing is created where it points.
  {
    const repo = repoWith(t)
    const target = join(tmpdir(t), 'target.env')
    symlinkSync(target, join(repo, '.env'))
    assert.match(untouched(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate)), /is a symbolic link/)
    assert.equal(existsSync(target), false)
  }

  // The real thing: 0600, two comment lines, then the generated names in order.
  {
    const repo = repoWith(t)
    const g = generators('AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN')
    const result = appendIn(repo, g.generate)
    const path = join(repo, '.env')
    // The header is lines 1 and 2, so the names are on 3 and 4.
    assert.deepEqual(result, {
      path,
      created: true,
      appended: [
        { name: 'AOS_CONTROL_TOKEN', line: 3 },
        { name: 'AOS_PMMCP_TOKEN', line: 4 },
      ],
      present: [],
      blank: [],
      digests: [],
    })
    assert.equal(modeOf(path), 0o600)
    assert.equal(lstatSync(path).nlink, 1)
    assert.equal(
      readFileSync(path, 'utf8'),
      `${CREATED_HEADER}AOS_CONTROL_TOKEN=${g.made.get('AOS_CONTROL_TOKEN') ?? ''}\nAOS_PMMCP_TOKEN=${g.made.get('AOS_PMMCP_TOKEN') ?? ''}\n`,
    )
    // The header is comments only: no name, no value, no placeholder.
    assert.ok(CREATED_HEADER.split('\n').every((l) => l === '' || l.startsWith('#')))
    assert.doesNotMatch(CREATED_HEADER, /replace-me|=/i)
  }

  // Nothing to write: a missing file stays missing.
  {
    const repo = repoWith(t)
    assert.deepEqual(appendIn(repo, new Map()), { path: join(repo, '.env'), created: false, appended: [], present: [], blank: [], digests: [] })
    assert.equal(existsSync(join(repo, '.env')), false)
  }

  // O_EXCL: a .env that appears while the values are made (the operator's
  // editor, a second installer) is never written over.
  {
    const repo = repoWith(t)
    const path = join(repo, '.env')
    const theirs = `ANTHROPIC_API_KEY=${KEY}\n`
    const racing = new Map<string, () => string>([
      [
        'AOS_CONTROL_TOKEN',
        () => {
          writeFileSync(path, theirs, { mode: 0o600 })
          chmodSync(path, 0o600)
          return randomBytes(32).toString('hex')
        },
      ],
    ])
    const before = (): string => readFileSync(path, 'utf8')
    assert.match(untouched(() => appendIn(repo, racing)), /appeared while the installer was preparing it; nothing was written/)
    assert.equal(before(), theirs)
    assert.equal(modeOf(path), 0o600)
  }
})

test('a created .env is 0600 whatever the umask, and one refused once created is removed again, so a missing file stays missing', (t) => {
  t.after(() => SecretMask.clear())
  // A umask that strips the owner's write bit narrows open()'s 0600 to 0400;
  // only the fchmod makes the file what the contract says.
  {
    const repo = repoWith(t)
    const previous = process.umask(0o277)
    let result: AppendResult
    try {
      result = appendIn(repo, generators('AOS_CONTROL_TOKEN').generate)
    } finally {
      process.umask(previous)
    }
    assert.equal(result.created, true)
    assert.equal(modeOf(join(repo, '.env')), 0o600)
  }
  // The file it creates is checked as the loader would check it before a
  // byte goes in. Refused there (here: it is not the owner the loader will
  // require), the empty file is removed, and nothing else is left beside it.
  {
    const repo = repoWith(t)
    const me = process.getuid?.() ?? 0
    const message = untouched(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, { uid: me + 1 }))
    assert.match(message, /is owned by uid \d+, not you .*Nothing was written, and the empty file this created was removed$/)
    assert.equal(existsSync(join(repo, '.env')), false)
    assert.deepEqual(readdirSync(repo).sort(), ['.gitignore'])
  }
})

test('a .env created on a filesystem that will not keep 0600 is removed, and the refusal names no chmod for a file that is gone', (t) => {
  t.after(() => SecretMask.clear())
  // Some filesystems (FAT, some network mounts) take a chmod and keep their
  // own mode. Stood in for here by an fchmod that leaves 0644, swapped into
  // the writer's own binding of node:fs for this one call. No command makes
  // such a file private, and the writer removes it, so the loader's "Run:
  // chmod 600 <path>" would send the operator to fix a file that is gone.
  const repo = repoWith(t)
  const realFchmod = fs.fchmodSync
  const fchmod = t.mock.method(fs, 'fchmodSync', (fd: number) => realFchmod(fd, 0o644))
  syncBuiltinESMExports()
  let message: string
  try {
    message = untouched(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate))
  } finally {
    fchmod.mock.restore()
    syncBuiltinESMExports()
  }
  assert.equal(fchmod.mock.callCount(), 1, 'the writer no longer calls fchmodSync through node:fs, so this test proves nothing')
  assert.equal(
    message,
    `${join(repo, '.env')} was created, but its filesystem did not keep mode 0600 (it shows 0644), so a credentials file cannot be private there. ` +
      'Nothing was written, and the empty file this created was removed',
  )
  assert.doesNotMatch(message, /chmod/)
  assert.deepEqual(readdirSync(repo).sort(), ['.gitignore'])
})

test('appends only absent names, after a newline when the file lacks a final one, and leaves every existing byte as it was', (t) => {
  t.after(() => SecretMask.clear())
  // Each file, and the lines the loader will number the new names: after the
  // last line, and after the newline the writer adds where the file lacks one.
  const fixtures: [string, Record<string, number>][] = [
    [`# mine\nANTHROPIC_API_KEY=${KEY}`, { AOS_CONTROL_TOKEN: 3 }],
    [`# mine\nANTHROPIC_API_KEY=${KEY}\n`, { AOS_CONTROL_TOKEN: 3 }],
    [`# mine\r\nANTHROPIC_API_KEY=${KEY}\r\n`, { AOS_CONTROL_TOKEN: 3 }],
    [`# only a comment, no final newline`, { AOS_CONTROL_TOKEN: 2, ANTHROPIC_API_KEY: 3 }],
    ['', { AOS_CONTROL_TOKEN: 1, ANTHROPIC_API_KEY: 2 }],
  ]
  for (const [original, at] of fixtures) {
    const repo = repoWith(t, original)
    const path = join(repo, '.env')
    const ino = lstatSync(path).ino
    const g = generators('AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY')
    const result = appendIn(repo, g.generate)
    const hadKey = original.includes('ANTHROPIC_API_KEY')
    assert.deepEqual(result, {
      path,
      created: false,
      appended: Object.entries(at).map(([name, line]) => ({ name, line })),
      present: hadKey ? [{ name: 'ANTHROPIC_API_KEY', line: 2 }] : [],
      blank: [],
      digests: [],
    }, JSON.stringify(original))
    const now = readFileSync(path)
    // Every original byte, untouched, at the start.
    assert.equal(now.subarray(0, Buffer.byteLength(original)).toString('utf8'), original)
    // Then one newline only where the file lacked one, then the new lines.
    const lead = original === '' || original.endsWith('\n') ? '' : '\n'
    const expected = [...g.made].map(([name, value]) => `${name}=${value}\n`).join('')
    assert.equal(now.subarray(Buffer.byteLength(original)).toString('utf8'), lead + expected, JSON.stringify(original))
    // Appended in place: the same file, the same mode.
    assert.equal(lstatSync(path).ino, ino)
    assert.equal(modeOf(path), 0o600)

    // A second run finds every name where the first put it and changes nothing.
    const after = snapshot(path)
    const again = generators('AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY')
    assert.deepEqual(appendIn(repo, again.generate), {
      path,
      created: false,
      appended: [],
      present: [
        { name: 'AOS_CONTROL_TOKEN', line: at['AOS_CONTROL_TOKEN'] },
        { name: 'ANTHROPIC_API_KEY', line: at['ANTHROPIC_API_KEY'] ?? 2 },
      ],
      blank: [],
      digests: [],
    })
    assert.equal(snapshot(path), after)
    assert.equal(again.calls(), 0)
  }
})

test('a name present on any line, blank included, is never appended again', (t) => {
  t.after(() => SecretMask.clear())
  // Each file, whether its line holds a value, and the line it is on.
  const fixtures: [string, 'present' | 'blank', number][] = [
    ['AOS_CONTROL_TOKEN=\n', 'blank', 1],
    ['AOS_CONTROL_TOKEN=   \n', 'blank', 1],
    ['AOS_CONTROL_TOKEN=""\n', 'blank', 1],
    ["  export AOS_CONTROL_TOKEN = ''\n", 'blank', 1],
    ['# no final newline\nAOS_CONTROL_TOKEN=', 'blank', 2],
    [`export AOS_CONTROL_TOKEN="${'a'.repeat(40)}"\n`, 'present', 1],
    [`# a comment\nAOS_CONTROL_TOKEN=${'b'.repeat(40)}\n`, 'present', 2],
    // Every name present and no final newline: not even a newline is added.
    [`# a comment\nAOS_CONTROL_TOKEN=${'c'.repeat(40)}`, 'present', 2],
  ]
  for (const [original, kind, line] of fixtures) {
    const repo = repoWith(t, original)
    const path = join(repo, '.env')
    const before = snapshot(path)
    const g = generators('AOS_CONTROL_TOKEN')
    const entry = [{ name: 'AOS_CONTROL_TOKEN', line }]
    assert.deepEqual(
      appendIn(repo, g.generate),
      { path, created: false, appended: [], present: kind === 'present' ? entry : [], blank: kind === 'blank' ? entry : [], digests: [] },
      original,
    )
    assert.equal(snapshot(path), before, original)
    assert.equal(g.calls(), 0, original)
  }
  // A commented-out line is not one: the name is appended.
  const repo = repoWith(t, '# AOS_CONTROL_TOKEN=old\n')
  assert.deepEqual(appendIn(repo, generators('AOS_CONTROL_TOKEN').generate).appended, [{ name: 'AOS_CONTROL_TOKEN', line: 2 }])
})

test('a blank line is reported apart from a set one, by line number: the loader reads it as unset, so it is not done', (t) => {
  t.after(() => SecretMask.clear())
  // The operator kept the template's shape and filled in one key.
  const original = `ANTHROPIC_API_KEY=${KEY}\n# the control plane's bearer\nAOS_CONTROL_TOKEN=\n`
  const repo = repoWith(t, original)
  const path = join(repo, '.env')
  const g = generators('AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY')
  const result = appendIn(repo, g.generate)
  assert.deepEqual(result, {
    path,
    created: false,
    appended: [{ name: 'AOS_PMMCP_TOKEN', line: 4 }],
    present: [{ name: 'ANTHROPIC_API_KEY', line: 1 }],
    blank: [{ name: 'AOS_CONTROL_TOKEN', line: 3 }],
    digests: [],
  })
  // The blank line is left as it was, and the one name made is the one written.
  assert.deepEqual([...g.made.keys()], ['AOS_PMMCP_TOKEN'])
  assert.equal(readFileSync(path, 'utf8'), `${original}AOS_PMMCP_TOKEN=${g.made.get('AOS_PMMCP_TOKEN') ?? ''}\n`)
  // Why blank is not present: the daemon would boot without that name.
  const loaded = loadDotenv(path, { repoRoot: repo, accepted: ACCEPTED, wanted: [...ACCEPTED], shell: {} })
  assert.deepEqual(Object.keys(loaded.values).sort(), ['ANTHROPIC_API_KEY', 'AOS_PMMCP_TOKEN'])
  // And a re-run says so again, by the same line, rather than "nothing to do".
  assert.deepEqual(appendIn(repo, generators('AOS_CONTROL_TOKEN').generate).blank, [{ name: 'AOS_CONTROL_TOKEN', line: 3 }])
})

test('a .env its owner cannot write: with nothing missing it is nothing to do, and a missing name is refused by its mode bits with the fix', (t) => {
  t.after(() => SecretMask.clear())
  // The loader reads a 0400 file, so the writer must not fail on one it has
  // no reason to write. Mode bits, not EACCES, decide: root (CI) can open any
  // file for writing, the operator cannot open this one.
  const token = randomBytes(32).toString('hex')
  for (const mode of [0o400, 0o500]) {
    const repo = repoWith(t, `AOS_CONTROL_TOKEN=${token}\nANTHROPIC_API_KEY=\n`, mode)
    const path = join(repo, '.env')
    const before = snapshot(path)
    assert.deepEqual(loadDotenv(path, { repoRoot: repo, accepted: ACCEPTED, wanted: ['AOS_CONTROL_TOKEN'], shell: {} }).values, { AOS_CONTROL_TOKEN: token })

    const done = generators('AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY')
    assert.deepEqual(appendIn(repo, done.generate), {
      path,
      created: false,
      appended: [],
      present: [{ name: 'AOS_CONTROL_TOKEN', line: 1 }],
      blank: [{ name: 'ANTHROPIC_API_KEY', line: 2 }],
      digests: [],
    })
    assert.equal(snapshot(path), before)

    const more = generators('AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN')
    assert.match(
      untouched(() => appendIn(repo, more.generate)),
      new RegExp(`has mode 0${mode.toString(8)}: its owner cannot write it, so AOS_PMMCP_TOKEN cannot be added\\. Run: chmod 600 .*\\.env, then re-run`),
    )
    assert.equal(snapshot(path), before)
    assert.equal(more.calls(), 0, 'a value was made for a file that cannot take it')
  }
})

test('refuses, changing nothing, every file the loader refuses: symlink, group or other mode bits, another owner, a second hard link, over 64 KiB, invalid UTF-8, NUL, a placeholder, an undeclared name, a duplicate', (t) => {
  t.after(() => SecretMask.clear())
  const fine = `ANTHROPIC_API_KEY=${KEY}\n`
  const me = process.getuid?.() ?? 0
  interface Case {
    readonly why: string
    readonly setup: (repo: string) => void
    readonly refused: RegExp
    readonly who?: Who
    /** Other paths the refusal must leave alone too. */
    readonly watch?: (repo: string) => string[]
  }
  const outside = join(tmpdir(t), 'outside')
  mkdirSync(outside)
  const cases: Case[] = [
    {
      why: 'a symlink to a 0600 file',
      setup: (repo) => {
        writeFileSync(join(outside, 'target.env'), fine, { mode: 0o600 })
        symlinkSync(join(outside, 'target.env'), join(repo, '.env'))
      },
      refused: /is a symbolic link/,
      watch: () => [join(outside, 'target.env')],
    },
    ...[0o644, 0o640, 0o604, 0o620, 0o602, 0o660, 0o606].map((mode) => ({
      why: `mode 0${mode.toString(8)}`,
      setup: (repo: string) => {
        writeFileSync(join(repo, '.env'), fine, { mode })
        chmodSync(join(repo, '.env'), mode)
      },
      refused: new RegExp(`has mode 0${mode.toString(8)}: .*chmod 600`),
    })),
    {
      why: 'another owner',
      setup: (repo) => writeFileSync(join(repo, '.env'), fine, { mode: 0o600 }),
      refused: /is owned by uid \d+, not you/,
      who: { uid: me + 1 },
    },
    {
      why: 'a second hard link',
      setup: (repo) => {
        writeFileSync(join(repo, '.env'), fine, { mode: 0o600 })
        linkSync(join(repo, '.env'), join(outside, `linked-${String(Date.now())}.env`))
      },
      refused: /another hard link/,
    },
    {
      // Read-only, open() admits a directory, so this reaches the same fstat
      // check that refuses a FIFO (whose reader would receive the token): a
      // test cannot make a FIFO without a process, and hygiene admits none
      // here. Without that check the read fails raw (EISDIR), not refused.
      why: 'a directory',
      setup: (repo) => mkdirSync(join(repo, '.env'), { mode: 0o700 }),
      refused: /^\/.*\/\.env is not a regular file$/,
    },
    {
      why: 'over 64 KiB already',
      setup: (repo) => writeFileSync(join(repo, '.env'), `${fine}#${'x'.repeat(DOTENV_MAX_BYTES)}\n`, { mode: 0o600 }),
      refused: /bytes; a credentials file is at most 65536/,
    },
    {
      why: 'over 64 KiB after the append',
      setup: (repo) => writeFileSync(join(repo, '.env'), `${fine}#${'x'.repeat(DOTENV_MAX_BYTES - fine.length - 20)}\n`, { mode: 0o600 }),
      refused: /would be \d+ bytes after the append; a credentials file is at most 65536\. Nothing was written/,
    },
    {
      why: 'invalid UTF-8',
      setup: (repo) => writeFileSync(join(repo, '.env'), Buffer.from([0x41, 0x3d, 0xff, 0xfe, 0x0a]), { mode: 0o600 }),
      refused: /is not valid UTF-8/,
    },
    {
      why: 'a NUL byte',
      setup: (repo) => writeFileSync(join(repo, '.env'), `ANTHROPIC_API_KEY=${KEY}\0\n`, { mode: 0o600 }),
      refused: /contains a NUL byte/,
    },
    {
      why: 'a placeholder copied from .env.example',
      setup: (repo) => writeFileSync(join(repo, '.env'), 'ANTHROPIC_API_KEY=replace-me-with-your-anthropic-api-key\n', { mode: 0o600 }),
      refused: /line 1: ANTHROPIC_API_KEY still holds the \.env\.example placeholder/,
    },
    {
      why: 'an undeclared name',
      setup: (repo) => writeFileSync(join(repo, '.env'), `${fine}NODE_OPTIONS=--require=/tmp/evil.js\n`, { mode: 0o600 }),
      refused: /line 2: a name this kernel does not read/,
    },
    {
      why: 'a duplicate',
      setup: (repo) => writeFileSync(join(repo, '.env'), `${fine}# again\n${fine}`, { mode: 0o600 }),
      refused: /line 3: ANTHROPIC_API_KEY is already set on line 1/,
    },
  ]
  for (const c of cases) {
    const repo = repoWith(t)
    c.setup(repo)
    const watched = [join(repo, '.env'), ...(c.watch?.(repo) ?? [])]
    const before = watched.map(snapshot)
    const listing = readdirSync(repo).sort()
    const g = generators('AOS_CONTROL_TOKEN')
    const message = untouched(() => appendIn(repo, g.generate, c.who))
    assert.match(message, c.refused, c.why)
    assert.deepEqual(watched.map(snapshot), before, `${c.why}: a refused file was changed`)
    assert.deepEqual(readdirSync(repo).sort(), listing, `${c.why}: a file was added beside it`)
    // Refused before any value existed, except where only the append's size says so.
    if (c.why !== 'over 64 KiB after the append') assert.equal(g.calls(), 0, c.why)
    // An undeclared name is not quoted: it may be a pasted key.
    assert.equal(message.includes('NODE_OPTIONS'), false, c.why)
  }
})

test('refuses a generated value the loader would refuse', (t) => {
  t.after(() => SecretMask.clear())
  const long = 'q'.repeat(MIN_GENERATED_LENGTH)
  const bad: [string, string, RegExp][] = [
    ['blank', '', /is 0 characters; a generated value has at least 32/],
    ['short', 'abc123def456', /is 12 characters; a generated value has at least 32/],
    ['31 characters', 'x'.repeat(MIN_GENERATED_LENGTH - 1), /is 31 characters/],
    ['whitespace', `${long} tail`, /would be refused by the \.env loader .*holds whitespace/],
    ['a newline that would start another line', `${long}\nNODE_OPTIONS=--require=/tmp/evil.js`, /would be refused by the \.env loader/],
    ['a newline that would set another accepted name', `${long}\nANTHROPIC_API_KEY=${long}`, /would not read back from \.env as written/],
    ['a carriage return', `${long}\r`, /would not read back from \.env as written|would be refused/],
    ['a hash', `${long}#x`, /would be refused by the \.env loader/],
    ['quotes the loader would strip', `"${long}"`, /would not read back from \.env as written/],
    ['a single quote', `${long}'`, /would be refused by the \.env loader/],
    ['a backtick', `${long}\``, /would be refused by the \.env loader/],
    ['a smart quote', `“${long}”`, /would be refused by the \.env loader .*outside printable ASCII/],
    ['a joined NAME=value line', `AOS_PMMCP_TOKEN=${long}`, /would be refused by the \.env loader .*whole NAME=value line/],
    ['the template placeholder', `replace-me-${long}`, /would be refused by the \.env loader .*placeholder/],
  ]
  for (const [why, value, refused] of bad) {
    const generate = new Map([['AOS_CONTROL_TOKEN', () => value]])
    // A missing file is not created.
    const empty = repoWith(t)
    assert.match(untouched(() => appendIn(empty, generate)), refused, why)
    assert.equal(existsSync(join(empty, '.env')), false, why)
    // An existing one is not touched.
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
    const before = snapshot(join(repo, '.env'))
    const message = untouched(() => appendIn(repo, generate))
    assert.match(message, refused, why)
    assert.match(message, /^the value generated for AOS_CONTROL_TOKEN .*; nothing was written$/, why)
    assert.equal(snapshot(join(repo, '.env')), before, why)
  }
  // A generated name the config does not declare is refused before anything is made.
  const repo = repoWith(t)
  const g = generators('AOS_SOMETHING_ELSE')
  assert.match(untouched(() => appendIn(repo, g.generate)), /AOS_SOMETHING_ELSE is not a credential name the config declares/)
  assert.equal(g.calls(), 0)
  assert.equal(existsSync(join(repo, '.env')), false)
})

test('reports names and line numbers only: no generated value appears in its result, its errors or anything printed', (t) => {
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const made: string[] = []
  const generate = (...names: string[]): Map<string, () => string> =>
    new Map(
      names.map((name) => [
        name,
        () => {
          const value = randomBytes(32).toString('hex')
          made.push(value)
          return value
        },
      ]),
    )
  const said: string[] = []
  const quiet = <T>(fn: () => T): T => quietly(said, fn)
  const messages: string[] = []
  const refusedQuietly = (fn: () => unknown): void => {
    messages.push(quiet(() => untouched(fn)))
  }

  // Successes: a create, then an append.
  const created = repoWith(t)
  const results: AppendResult[] = [quiet(() => appendIn(created, generate('AOS_CONTROL_TOKEN')))]
  results.push(quiet(() => appendIn(created, generate('AOS_PMMCP_TOKEN'))))

  // Failures after a value was made: the file too big for it, and the file
  // replaced under it.
  const full = repoWith(t, `#${'x'.repeat(DOTENV_MAX_BYTES - 40)}\n`)
  refusedQuietly(() => appendIn(full, generate('AOS_CONTROL_TOKEN')))
  const replaced = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  const swap = new Map([
    [
      'AOS_CONTROL_TOKEN',
      () => {
        const value = randomBytes(32).toString('hex')
        made.push(value)
        writeFileSync(join(replaced, '.env.tmp'), `ANTHROPIC_API_KEY=${KEY}\n`, { mode: 0o600 })
        renameSync(join(replaced, '.env.tmp'), join(replaced, '.env'))
        return value
      },
    ],
  ])
  refusedQuietly(() => appendIn(replaced, swap))
  // A refused value, and a refused file whose lines hold a canary.
  const canary = 'Kc7Rq2Wm9Zp4Xv8Ls3Ny6Bt1Hd5Fg0Jk'
  made.push(canary)
  refusedQuietly(() => appendIn(repoWith(t), new Map([['AOS_CONTROL_TOKEN', () => `${canary} with a space`]])))
  refusedQuietly(() => appendIn(repoWith(t, `ANTHROPIC_API_KEY=${canary}\nANTHROPIC_API_KEY=${canary}\n`), generate('AOS_CONTROL_TOKEN')))
  refusedQuietly(() => appendIn(repoWith(t, `ANTHROPIC_API_KEY=${canary}#tail\n`), generate('AOS_CONTROL_TOKEN')))

  assert.equal(made.length >= 5, true, 'the values these checks look for were never made')
  assert.equal(messages.length, 5)
  const everything = [JSON.stringify(results), ...messages, ...said]
  for (const text of everything) {
    for (const value of made) assert.equal(echoes(text, value), false, `"${text}" echoes part of a value`)
  }
  assert.deepEqual(said, [], 'the writer printed something')
  // And each generated value was masked before it was written, even where the
  // write was then refused: anything that quotes one later is censored.
  for (const value of made.filter((v) => v !== canary)) {
    assert.equal(redactString(`x ${value} x`).includes(value), false, 'a generated value is not masked')
  }
})

test('a file replaced during the append is reported, not silently lost', (t) => {
  t.after(() => SecretMask.clear())
  // An editor touching the file after the writer read it, while its values
  // were being made: a save that renames a new file over the path, and one
  // that rewrites it in place (same inode, new size) with no final newline,
  // which an append computed from the old last byte would join onto.
  const saves: [string, (path: string, editors: string) => void][] = [
    [
      'renamed over it',
      (path, editors) => {
        writeFileSync(`${path}.swp`, editors, { mode: 0o600 })
        chmodSync(`${path}.swp`, 0o600)
        renameSync(`${path}.swp`, path)
      },
    ],
    ['rewritten in place', (path, editors) => writeFileSync(path, editors)],
  ]
  for (const [why, save] of saves) {
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
    const path = join(repo, '.env')
    const editors = `ANTHROPIC_API_KEY=${KEY}\n# edited, no final newline`
    const generate = new Map([
      [
        'AOS_CONTROL_TOKEN',
        () => {
          save(path, editors)
          return randomBytes(32).toString('hex')
        },
      ],
    ])
    assert.match(
      untouched(() => appendIn(repo, generate)),
      /changed while the installer read it \(an editor saving it\?\); nothing was written\. Re-run npm run aos-install/,
      why,
    )
    // The editor's file is what is there, byte for byte, and a re-run then appends to it.
    assert.equal(readFileSync(path, 'utf8'), editors, why)
    const g = generators('AOS_CONTROL_TOKEN')
    assert.deepEqual(appendIn(repo, g.generate).appended, [{ name: 'AOS_CONTROL_TOKEN', line: 3 }], why)
    assert.equal(readFileSync(path, 'utf8'), `${editors}\nAOS_CONTROL_TOKEN=${g.made.get('AOS_CONTROL_TOKEN') ?? ''}\n`, why)
  }

  // Saves that only one of inode, mtime and size tells from the file that was
  // read. Both files start at one fixed mtime, so a coarse filesystem clock
  // cannot make a real change look like none.
  const STAMP = 1_700_000_000
  const subtle: [string, (path: string, editors: string) => void][] = [
    [
      'renamed over it at the same size and mtime',
      (path, editors) => {
        writeFileSync(`${path}.swp`, editors, { mode: 0o600 })
        chmodSync(`${path}.swp`, 0o600)
        utimesSync(`${path}.swp`, STAMP, STAMP)
        renameSync(`${path}.swp`, path)
      },
    ],
    ['rewritten in place at the same size', (path, editors) => writeFileSync(path, editors)],
    [
      // cp -p over it: the same inode, new bytes, and the source's mtime put back.
      'rewritten in place to a new size with its mtime put back',
      (path, editors) => {
        writeFileSync(path, `${editors}# and longer\n`)
        utimesSync(path, STAMP, STAMP)
      },
    ],
  ]
  for (const [why, save] of subtle) {
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n# original\n`)
    const path = join(repo, '.env')
    utimesSync(path, STAMP, STAMP)
    const editors = `ANTHROPIC_API_KEY=${KEY}\n# replaced\n`
    const generate = new Map([
      [
        'AOS_CONTROL_TOKEN',
        () => {
          save(path, editors)
          return randomBytes(32).toString('hex')
        },
      ],
    ])
    assert.match(untouched(() => appendIn(repo, generate)), /changed while the installer read it .*nothing was written/, why)
    assert.equal(readFileSync(path, 'utf8').startsWith(editors), true, why)
    assert.equal(readFileSync(path, 'utf8').includes('AOS_CONTROL_TOKEN'), false, why)
  }

  // The same bytes, newly exposed: a chmod or a second link leaves size and
  // mtime alone, so the descriptor the writer appends through is held to the
  // loader's rules again, and nothing goes into a file others can now read.
  const outside = tmpdir(t)
  const exposures: [string, (path: string) => void, RegExp][] = [
    ['made readable by others', (path) => chmodSync(path, 0o644), /has mode 0644: .*chmod 600/],
    ['hard-linked elsewhere', (path) => linkSync(path, join(outside, 'copy.env')), /another hard link/],
  ]
  for (const [why, expose, refused] of exposures) {
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
    const path = join(repo, '.env')
    const generate = new Map([
      [
        'AOS_CONTROL_TOKEN',
        () => {
          expose(path)
          return randomBytes(32).toString('hex')
        },
      ],
    ])
    assert.match(untouched(() => appendIn(repo, generate)), refused, why)
    assert.equal(readFileSync(path, 'utf8'), `ANTHROPIC_API_KEY=${KEY}\n`, why)
  }
})

test('after an append, loadDotenv with the shipped credentialNames returns every appended name', (t) => {
  t.after(() => SecretMask.clear())
  const read = (p: string): unknown => parseYaml(readFileSync(join(REPO_ROOT, p), 'utf8'))
  const config = parseKernelConfig(read('config/kernel.yaml'), { repoRoot: REPO_ROOT })
  const providers = parseProviders(read('config/providers.yaml'))
  // As the installer builds it: through the writer's re-export, never the loader.
  const names = credentialNames(config, providers)
  const control = config.control.tokenEnv
  assert.ok(names.has(control))

  // Created, then the operator's provider key added by hand, then a re-run.
  for (const original of [undefined, `ANTHROPIC_API_KEY=${KEY}`]) {
    const repo = repoWith(t, original)
    const g = generators(control)
    const result = appendIn(repo, g.generate, { accepted: names })
    // On the line after the header, or after the operator's key and the newline its file lacked.
    assert.deepEqual(result.appended, [{ name: control, line: original === undefined ? 3 : 2 }])
    const loaded = loadDotenv(join(repo, '.env'), { repoRoot: repo, accepted: names, wanted: [...names], shell: {} })
    const value = g.made.get(control)
    assert.ok(value !== undefined)
    assert.equal(loaded.values[control], value)
    if (original !== undefined) assert.equal(loaded.values['ANTHROPIC_API_KEY'], KEY)
    // The control plane would boot on it.
    assert.equal(assertTokenUsable(loaded.values[control]), value)
  }
})

test('refuses to run as root', (t) => {
  t.after(() => SecretMask.clear())
  for (const original of [undefined, `ANTHROPIC_API_KEY=${KEY}\n`]) {
    const repo = repoWith(t, original)
    const before = snapshot(join(repo, '.env'))
    const g = generators('AOS_CONTROL_TOKEN')
    assert.match(untouched(() => appendIn(repo, g.generate, { euid: 0 })), /refusing to write \.env as root.*without sudo/)
    assert.equal(snapshot(join(repo, '.env')), before)
    assert.equal(g.calls(), 0)
  }
  // Left to its own default, the writer asks the process who it is: refused
  // under sudo or a root CI, admitted as the operator.
  const repo = repoWith(t)
  if (process.geteuid?.() === 0) {
    assert.match(untouched(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, { euid: 'process' })), /as root/)
    assert.equal(existsSync(join(repo, '.env')), false)
  } else {
    assert.equal(appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, { euid: 'process' }).created, true)
  }
})

test('inspectCredentials reports each name present, blank or missing by line, through the writer\'s refusals, and opens nothing for writing', (t) => {
  t.after(() => SecretMask.clear())
  const NAMES = ['AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY']
  const WRITE_FLAGS = constants.O_WRONLY | constants.O_RDWR | constants.O_CREAT | constants.O_APPEND | constants.O_TRUNC
  // The flags of every open of a .env for the duration of `fn` (its
  // .gitignore is read too, through readFileSync, which opens with 'r').
  const opens = <T>(fn: () => T): { result: T; flags: (string | number | undefined)[] } => {
    const realOpen = fs.openSync
    const flags: (string | number | undefined)[] = []
    const open = t.mock.method(fs, 'openSync', (...args: Parameters<typeof fs.openSync>) => {
      if (String(args[0]).endsWith(`${sep}.env`)) flags.push(args[1] as string | number | undefined)
      return realOpen(...args)
    })
    syncBuiltinESMExports()
    try {
      return { result: fn(), flags }
    } finally {
      open.mock.restore()
      syncBuiltinESMExports()
    }
  }

  // The installer's S2 screen: one set, one blank, one missing, each by line.
  const token = randomBytes(32).toString('hex')
  const original = `# mine\nAOS_CONTROL_TOKEN=${token}\n\nANTHROPIC_API_KEY=\n`
  for (const mode of [0o600, 0o400]) {
    const repo = repoWith(t, original, mode)
    const path = join(repo, '.env')
    const before = snapshot(path)
    const { result, flags } = opens(() => inspectIn(repo, NAMES))
    assert.deepEqual(result, {
      path,
      found: true,
      present: [{ name: 'AOS_CONTROL_TOKEN', line: 2 }],
      blank: [{ name: 'ANTHROPIC_API_KEY', line: 4 }],
      missing: ['AOS_PMMCP_TOKEN'],
      writable: mode === 0o600,
      fits: true,
      digests: [],
    })
    assert.ok(flags.length >= 1, 'the writer no longer opens .env through node:fs, so this test proves nothing')
    assert.deepEqual(flags.filter((f) => typeof f !== 'number' || (f & WRITE_FLAGS) !== 0), [], 'inspect opened .env for writing')
    assert.equal(snapshot(path), before)
    assert.equal(JSON.stringify(result).includes(token.slice(0, 8)), false)
    if (mode === 0o600) {
      // What it says is missing is exactly what an append then adds, where it said.
      const g = generators('AOS_CONTROL_TOKEN', 'AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY')
      const appended = appendIn(repo, g.generate)
      assert.deepEqual(appended.appended.map((a) => a.name), result.missing)
      assert.deepEqual([appended.present, appended.blank], [result.present, result.blank])
    } else {
      // A 0400 file it calls unwritable is one the writer refuses to add a missing name to.
      assert.match(untouched(() => appendIn(repo, generators('AOS_PMMCP_TOKEN').generate)), /its owner cannot write it/)
    }
  }

  // No file: everything missing, and nothing created.
  {
    const repo = repoWith(t)
    const { result, flags } = opens(() => inspectIn(repo, [...NAMES, 'AOS_CONTROL_TOKEN']))
    assert.deepEqual(result, { path: join(repo, '.env'), found: false, present: [], blank: [], missing: NAMES, writable: true, fits: true, digests: [] })
    assert.ok(flags.length >= 1)
    assert.deepEqual(flags.filter((f) => typeof f !== 'number' || (f & WRITE_FLAGS) !== 0), [])
    assert.deepEqual(readdirSync(repo).sort(), ['.gitignore'])
  }

  // Every refusal the writer makes before it would make a value, made the
  // same way, word for word, and nothing changed by either.
  const me = process.getuid?.() ?? 0
  const outside = tmpdir(t)
  const fine = `ANTHROPIC_API_KEY=${KEY}\n`
  const put = (repo: string, text: string | Buffer, mode = 0o600): void => {
    writeFileSync(join(repo, '.env'), text, { mode })
    chmodSync(join(repo, '.env'), mode)
  }
  const refused: [string, (repo: string) => void, Who, readonly string[]][] = [
    ['root', (repo) => put(repo, fine), { euid: 0 }, NAMES],
    ['not ignored', (repo) => writeFileSync(join(repo, '.gitignore'), '# nothing\n'), {}, NAMES],
    ['a case variant', (repo) => writeFileSync(join(repo, '.ENV'), fine, { mode: 0o600 }), {}, NAMES],
    ['a symlink', (repo) => symlinkSync(join(outside, 'target.env'), join(repo, '.env')), {}, NAMES],
    ['an undeclared name asked for', (repo) => put(repo, fine), {}, ['AOS_SOMETHING_ELSE']],
    ['mode 0644', (repo) => put(repo, fine, 0o644), {}, NAMES],
    ['another owner', (repo) => put(repo, fine), { uid: me + 1 }, NAMES],
    ['a second hard link', (repo) => (put(repo, fine), linkSync(join(repo, '.env'), join(outside, `linked-${String(Date.now())}`))), {}, NAMES],
    ['a directory', (repo) => mkdirSync(join(repo, '.env')), {}, NAMES],
    ['over 64 KiB', (repo) => put(repo, `${fine}#${'x'.repeat(DOTENV_MAX_BYTES)}\n`), {}, NAMES],
    ['invalid UTF-8', (repo) => put(repo, Buffer.from([0x41, 0x3d, 0xff, 0x0a])), {}, NAMES],
    ['a NUL byte', (repo) => put(repo, `${fine}\0\n`), {}, NAMES],
    ['a placeholder', (repo) => put(repo, 'ANTHROPIC_API_KEY=replace-me-with-your-key\n'), {}, NAMES],
    ['a duplicate', (repo) => put(repo, `${fine}${fine}`), {}, NAMES],
  ]
  for (const [why, setup, who, names] of refused) {
    const repo = repoWith(t)
    setup(repo)
    const listing = readdirSync(repo).sort()
    const before = snapshot(join(repo, '.env'))
    const inspected = refusal(() => inspectIn(repo, names, who))
    const g = generators(...names)
    assert.equal(untouched(() => appendIn(repo, g.generate, who)), inspected, why)
    assert.equal(g.calls(), 0, why)
    assert.equal(snapshot(join(repo, '.env')), before, why)
    assert.deepEqual(readdirSync(repo).sort(), listing, why)
  }
})

/** Run `fn` with node:fs's fsyncSync doing what it does, then `after` once, on its first call: a hook into the window after the write. */
function afterFirstFsync<T>(t: TestContext, after: () => void, fn: () => T): T {
  const realFsync = fs.fsyncSync
  const fsync = t.mock.method(fs, 'fsyncSync', (fd: number) => {
    realFsync(fd)
    if (fsync.mock.callCount() === 0) after()
  })
  syncBuiltinESMExports()
  try {
    return fn()
  } finally {
    const calls = fsync.mock.callCount()
    fsync.mock.restore()
    syncBuiltinESMExports()
    assert.ok(calls >= 1, 'the writer no longer syncs through node:fs, so this test proves nothing')
  }
}

test('a .env replaced, or rewritten to another value, after the write is reported, and the error says the file may have changed', (t) => {
  t.after(() => SecretMask.clear())
  // The window between the write and the checks after it, reached through the
  // fsync that ends the write: an editor's save-by-rename there carries the new
  // lines away with the old inode; a rewrite in place leaves a value that is
  // not the one generated. Neither is lost silently, and neither is a refusal:
  // bytes went in, so `written` says the file may have changed.
  const editors = `ANTHROPIC_API_KEY=${KEY}\n# saved by an editor\n`
  const renameOver = (path: string) => (): void => {
    writeFileSync(`${path}.swp`, editors, { mode: 0o600 })
    chmodSync(`${path}.swp`, 0o600)
    renameSync(`${path}.swp`, path)
  }
  // Appended to, then replaced.
  {
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
    const path = join(repo, '.env')
    const e = afterFirstFsync(t, renameOver(path), () => thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate)))
    assert.match(e.message, /was replaced while the installer wrote it \(an editor saving it\?\): the new lines are not in your file\. Re-run/)
    assert.equal(e.written, true)
    assert.equal(readFileSync(path, 'utf8'), editors)
  }
  // Created, then replaced.
  {
    const repo = repoWith(t)
    const path = join(repo, '.env')
    const e = afterFirstFsync(t, renameOver(path), () => thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate)))
    assert.match(e.message, /was replaced while the installer wrote it .*the new lines are not in your file/)
    assert.equal(e.written, true)
    assert.equal(readFileSync(path, 'utf8'), editors)
  }
  // Appended to, then rewritten in place with another value for the new name.
  {
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
    const path = join(repo, '.env')
    const theirs = `ANTHROPIC_API_KEY=${KEY}\nAOS_CONTROL_TOKEN=${'z'.repeat(40)}\n`
    const ino = lstatSync(path).ino
    const e = afterFirstFsync(t, () => writeFileSync(path, theirs), () => thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate)))
    assert.equal(lstatSync(path).ino, ino, 'the rewrite was not in place, so this is the replaced case again')
    assert.equal(e.message, `${path} does not read back AOS_CONTROL_TOKEN as written: check the file by hand`)
    assert.equal(e.written, true)
  }
  // Created, then rewritten in place the same way: the create path reads back too.
  {
    const repo = repoWith(t)
    const path = join(repo, '.env')
    const theirs = `AOS_CONTROL_TOKEN=${'y'.repeat(40)}\n`
    let ino = -1
    const rewrite = (): void => {
      ino = lstatSync(path).ino
      writeFileSync(path, theirs)
    }
    const e = afterFirstFsync(t, rewrite, () => thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate)))
    assert.equal(lstatSync(path).ino, ino, 'the rewrite was not in place, so this is the replaced case again')
    assert.equal(e.message, `${path} does not read back AOS_CONTROL_TOKEN as written: check the file by hand`)
    assert.equal(e.written, true)
    assert.equal(readFileSync(path, 'utf8'), theirs)
  }
})

test('a created .env refused after the path came to name another file is left to that file, and the refusal says what may be left and how to fix it', (t) => {
  t.after(() => SecretMask.clear())
  // Between the create and the refusal another process moved the new file
  // away and put an empty one of its own at the path. That one is not this
  // call's to remove, though it is empty too: only the inode the descriptor
  // holds is. Stood in for by an fchmod that does the move, swapped into the
  // writer's binding of node:fs. Where the refusal is the filesystem's own
  // mode, a re-run would fail the same way, so the fix is not "re-run".
  const me = process.getuid?.() ?? 0
  const cases: [string, number, Who, string][] = [
    ['a filesystem that will not keep 0600', 0o644, {}, 'delete it; this filesystem cannot hold a credentials file'],
    ['another owner', 0o600, { uid: me + 1 }, 'delete it, then re-run npm run aos-install'],
  ]
  for (const [why, mode, who, fix] of cases) {
    const repo = repoWith(t)
    const path = join(repo, '.env')
    const realFchmod = fs.fchmodSync
    const fchmod = t.mock.method(fs, 'fchmodSync', (fd: number) => {
      realFchmod(fd, mode)
      renameSync(path, join(repo, 'moved-away'))
      writeFileSync(path, '', { mode: 0o600 })
    })
    syncBuiltinESMExports()
    let e: DotenvWriteError
    try {
      e = thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, who))
    } finally {
      fchmod.mock.restore()
      syncBuiltinESMExports()
    }
    assert.equal(fchmod.mock.callCount(), 1, 'the writer no longer calls fchmodSync through node:fs, so this test proves nothing')
    assert.ok(e.message.endsWith(`Nothing was written to it, but ${path} may be left empty: ${fix}`), `${why}: ${e.message}`)
    assert.equal(e.written, true, why)
    // The other process's file is still there, as it left it.
    assert.equal(readFileSync(path, 'utf8'), '', why)
    assert.deepEqual(readdirSync(repo).sort(), ['.env', '.gitignore', 'moved-away'], why)
  }

  // Or the path still names the file this call created, but another process
  // wrote into it through the path before the refusal: the file is no longer
  // the empty one this call made, so its bytes are not this call's to remove.
  {
    const repo = repoWith(t)
    const path = join(repo, '.env')
    const realFchmod = fs.fchmodSync
    const fchmod = t.mock.method(fs, 'fchmodSync', (fd: number) => {
      realFchmod(fd, 0o600)
      appendFileSync(path, '#')
    })
    syncBuiltinESMExports()
    let e: DotenvWriteError
    try {
      e = thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, { uid: me + 1 }))
    } finally {
      fchmod.mock.restore()
      syncBuiltinESMExports()
    }
    assert.equal(fchmod.mock.callCount(), 1, 'the writer no longer calls fchmodSync through node:fs, so this test proves nothing')
    assert.ok(e.message.endsWith(`Nothing was written to it, but ${path} may be left empty: delete it, then re-run npm run aos-install`), e.message)
    assert.equal(e.written, true)
    assert.equal(readFileSync(path, 'utf8'), '#')
  }
})

test('a raw error while a created .env is prepared is named by its code and not kept, and the empty file is removed, or left as for any refusal', (t) => {
  t.after(() => SecretMask.clear())
  // The fchmod after the O_EXCL create fails with an errno no branch names.
  // Its text is the thrower's, so it is named as failure() names one (by its
  // code) and not kept as the cause, which util.inspect would print; where the
  // path then names another file, that file is left, as after a refusal.
  const CANARY = 'Vb7Qx2Lm9Rt4Wz6Kp1Hs8Dn3Fj5Gc0Ya'
  for (const moved of [false, true]) {
    const repo = repoWith(t)
    const path = join(repo, '.env')
    const fchmod = t.mock.method(fs, 'fchmodSync', () => {
      if (moved) {
        renameSync(path, join(repo, 'moved-away'))
        writeFileSync(path, '', { mode: 0o600 })
      }
      throw errno('EIO', `fchmod ${CANARY}`)
    })
    syncBuiltinESMExports()
    let e: DotenvWriteError
    try {
      e = thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate))
    } finally {
      fchmod.mock.restore()
      syncBuiltinESMExports()
    }
    assert.equal(fchmod.mock.callCount(), 1, 'the writer no longer calls fchmodSync through node:fs, so this test proves nothing')
    const said = moved
      ? `${path} could not be prepared (EIO). Nothing was written to it, but ${path} may be left empty: delete it, then re-run npm run aos-install`
      : `${path} could not be prepared (EIO). Nothing was written, and the empty file this created was removed`
    assert.equal(e.message, said)
    assert.equal(e.written, moved)
    assert.equal(e.cause, undefined)
    for (const text of [String(e.stack), inspect(e), inspect(e, { showHidden: true, depth: Infinity })]) {
      assert.equal(echoes(text, CANARY), false, `"${text}" quotes the raw error`)
    }
    assert.deepEqual(readdirSync(repo).sort(), moved ? ['.env', '.gitignore', 'moved-away'] : ['.gitignore'])
  }
})

test('a generator that throws is reported by its code or class only: nothing of its message is in the error, its inspection or anything printed, and nothing is written', (t) => {
  t.after(() => SecretMask.clear())
  // A generator's error may quote the value it was making, which SecretMask
  // has not seen yet. Node's printer for an uncaught error is util.inspect,
  // which prints a cause's message too, so the raw error is not kept, and
  // what the message names is held to the shape of a code or a class name:
  // both are set by whoever threw.
  const SECRET = 'Zq8Wm3Xv7Ls2Ny5Bt9Hd4Fg1Jk6Rp0Cw'
  const named = (name: string): Error => Object.assign(new Error('x'), { name })
  const throwers: [string, () => never, string][] = [
    ['an Error quoting the value', () => { throw new Error(`entropy source returned ${SECRET}`) }, 'Error'],
    ['a RangeError with a Node code', () => { throw Object.assign(new RangeError(`size ${SECRET}`), { code: 'ERR_OUT_OF_RANGE' }) }, 'ERR_OUT_OF_RANGE'],
    ['an errno error', () => { throw Object.assign(new Error(`EIO: ${SECRET}`), { code: 'EIO' }) }, 'EIO'],
    ['a code that is the value', () => { throw Object.assign(new Error('x'), { code: SECRET }) }, 'Error'],
    ['a class name that is the value', () => { throw named(SECRET) }, 'an unknown error'],
    ['a string', () => { throw SECRET }, 'an unknown error'],
  ]
  for (const [why, make, name] of throwers) {
    for (const original of [undefined, `ANTHROPIC_API_KEY=${KEY}\n`]) {
      const repo = repoWith(t, original)
      const path = join(repo, '.env')
      const before = snapshot(path)
      const said: string[] = []
      const e = quietly(said, () => thrown(() => appendIn(repo, new Map([['AOS_CONTROL_TOKEN', make]]))))
      assert.equal(e.message, `${path} was not written: ${name}`, why)
      assert.equal(e.written, false, why)
      assert.equal(e.cause, undefined, why)
      assert.equal(snapshot(path), before, why)
      for (const text of [e.message, String(e.stack), inspect(e), inspect(e, { showHidden: true, depth: Infinity }), ...said]) {
        assert.equal(echoes(text, SECRET), false, `${why}: "${text}" quotes the generator`)
      }
      assert.deepEqual(said, [], why)
    }
  }
})

test('a write that cannot be synced says so and to check the last line; any raw error once bytes are in says the file may have changed', (t) => {
  t.after(() => SecretMask.clear())
  for (const original of [undefined, `ANTHROPIC_API_KEY=${KEY}\n`]) {
    const kind = original === undefined ? 'created' : 'appended'
    // The fsync that ends the write fails: the bytes are in, maybe not on disk.
    {
      const repo = repoWith(t, original)
      const path = join(repo, '.env')
      const fsync = t.mock.method(fs, 'fsyncSync', () => {
        throw errno('EIO', 'fsync')
      })
      syncBuiltinESMExports()
      let e: DotenvWriteError
      try {
        e = thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate))
      } finally {
        fsync.mock.restore()
        syncBuiltinESMExports()
      }
      assert.equal(fsync.mock.callCount(), 1, `${kind}: the writer no longer syncs through node:fs, so this test proves nothing`)
      assert.equal(e.message, `${path} was written but could not be synced (EIO): check its last line by hand before re-running`, kind)
      assert.equal(e.written, true, kind)
      assert.match(readFileSync(path, 'utf8'), /\nAOS_CONTROL_TOKEN=[0-9a-f]{64}\n$/, kind)
    }
    // The close after the synced write fails: an errno no branch names.
    {
      const repo = repoWith(t, original)
      const path = join(repo, '.env')
      const realFsync = fs.fsyncSync
      const realClose = fs.closeSync
      const synced = new Set<number>()
      const fsync = t.mock.method(fs, 'fsyncSync', (fd: number) => {
        realFsync(fd)
        synced.add(fd)
      })
      const close = t.mock.method(fs, 'closeSync', (fd: number) => {
        realClose(fd)
        if (synced.delete(fd)) throw errno('EIO', 'close')
      })
      syncBuiltinESMExports()
      let e: DotenvWriteError
      try {
        e = thrown(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate))
      } finally {
        fsync.mock.restore()
        close.mock.restore()
        syncBuiltinESMExports()
      }
      assert.equal(e.message, `${path} may have been changed before EIO: check it by hand`, kind)
      assert.equal(e.written, true, kind)
      assert.equal(e.cause, undefined, kind)
    }
  }
})

test('a created .env is synced, then its directory, so the new entry outlives a crash; an append syncs the file alone', (t) => {
  t.after(() => SecretMask.clear())
  const synced = (repo: string, fn: () => unknown): string[] => {
    const realFsync = fs.fsyncSync
    const seen: string[] = []
    const fsync = t.mock.method(fs, 'fsyncSync', (fd: number) => {
      const st = fs.fstatSync(fd)
      seen.push(st.isDirectory() ? (st.ino === lstatSync(repo).ino ? 'the repository' : 'another directory') : st.ino === lstatSync(join(repo, '.env')).ino ? '.env' : 'another file')
      realFsync(fd)
    })
    syncBuiltinESMExports()
    try {
      fn()
    } finally {
      fsync.mock.restore()
      syncBuiltinESMExports()
    }
    return seen
  }
  const created = repoWith(t)
  assert.deepEqual(synced(created, () => appendIn(created, generators('AOS_CONTROL_TOKEN').generate)), ['.env', 'the repository'])
  assert.deepEqual(synced(created, () => appendIn(created, generators('AOS_PMMCP_TOKEN').generate)), ['.env'])
})

test('inspectCredentials says whether the missing names fit within 64 KiB at the generated length, as the writer then finds', (t) => {
  t.after(() => SecretMask.clear())
  // AOS_PMMCP_TOKEN=<64 characters>\n is 81 bytes. A file of `#`, k x's and a
  // newline, or the same without the newline (which the writer then adds),
  // comes to k + 83 bytes after the append: at k = 65453 exactly 64 KiB.
  const LINE = Buffer.byteLength(`AOS_PMMCP_TOKEN=\n`) + GENERATED_LENGTH
  assert.equal(GENERATED_LENGTH, 64)
  assert.equal(LINE, 81)
  const k = DOTENV_MAX_BYTES - 83
  for (const final of ['\n', '']) {
    for (const [extra, fits] of [[0, true], [1, false]] as const) {
      const repo = repoWith(t, `#${'x'.repeat(k + extra)}${final}`)
      const seen = inspectIn(repo, ['AOS_PMMCP_TOKEN'])
      assert.deepEqual([seen.missing, seen.fits], [['AOS_PMMCP_TOKEN'], fits], `${JSON.stringify(final)} + ${String(extra)}`)
      if (fits) {
        assert.deepEqual(appendIn(repo, generators('AOS_PMMCP_TOKEN').generate).appended.map((a) => a.name), ['AOS_PMMCP_TOKEN'])
        assert.equal(lstatSync(join(repo, '.env')).size, DOTENV_MAX_BYTES)
      } else {
        assert.match(untouched(() => appendIn(repo, generators('AOS_PMMCP_TOKEN').generate)), new RegExp(`would be ${String(DOTENV_MAX_BYTES + 1)} bytes after the append`))
      }
    }
  }
  // At another length, if the caller generates another: one character less fits.
  const tight = repoWith(t, `#${'x'.repeat(k + 1)}\n`)
  assert.equal(inspectIn(tight, ['AOS_PMMCP_TOKEN'], { valueLength: GENERATED_LENGTH - 1 }).fits, true)
  assert.deepEqual(appendIn(tight, new Map([['AOS_PMMCP_TOKEN', () => 'p'.repeat(GENERATED_LENGTH - 1)]])).appended.map((a) => a.name), ['AOS_PMMCP_TOKEN'])
  // Nothing missing: nothing to fit, whatever the size.
  const full = repoWith(t, `AOS_PMMCP_TOKEN=${KEY}\n#${'x'.repeat(DOTENV_MAX_BYTES - 60)}\n`)
  assert.equal(inspectIn(full, ['AOS_PMMCP_TOKEN']).fits, true)
  // No file: the one created must fit too, and one that would not is not created.
  const none = repoWith(t)
  assert.equal(inspectIn(none, ['AOS_PMMCP_TOKEN']).fits, true)
  assert.equal(inspectIn(none, ['AOS_PMMCP_TOKEN'], { valueLength: DOTENV_MAX_BYTES }).fits, false)
  const huge = new Map([['AOS_PMMCP_TOKEN', () => 'h'.repeat(DOTENV_MAX_BYTES)]])
  assert.match(untouched(() => appendIn(none, huge)), /would be \d+ bytes when created; a credentials file is at most 65536\. Nothing was written$/)
  assert.deepEqual(readdirSync(none).sort(), ['.gitignore'])
})

test('inspectCredentials with no file says whether the operator may create one in the repository, by the directory\'s mode bits', (t) => {
  t.after(() => SecretMask.clear())
  const me = process.getuid?.() ?? 0
  const gid = process.getgid?.() ?? 0
  // The repository's mode, who the operator is, and whether a .env may be made there.
  const cases: [string, number, Who, boolean][] = [
    ['owned, 0755', 0o755, {}, true],
    ['owned, 0555', 0o555, {}, false],
    ['owned, 0655 (write, no search)', 0o655, {}, false],
    ['owned by another, in its group, 0775', 0o775, { uid: me + 1 }, true],
    ['owned by another, in its group, 0755', 0o755, { uid: me + 1 }, false],
    // The group's bits decide for a member, though the others' allow more.
    ['owned by another, in its group, 0757', 0o757, { uid: me + 1 }, false],
    // Write without search, where the process itself (the owner) may read the .gitignore.
    ['owned by another, in its group, 0765', 0o765, { uid: me + 1 }, false],
  ]
  for (const [why, mode, who, writable] of cases) {
    const repo = repoWith(t)
    assert.equal(lstatSync(repo).gid, gid, 'the scratch directory is not in this process\'s group, so these cases prove nothing')
    chmodSync(repo, mode)
    try {
      // Without search, the operator cannot read the repository's .gitignore
      // either, so for them preflight refuses first; only root gets this far.
      if (me !== 0 && (mode & 0o100) === 0) {
        assert.match(refusal(() => inspectIn(repo, ['AOS_CONTROL_TOKEN'], who)), /is not ignored by/, why)
        continue
      }
      assert.equal(inspectIn(repo, ['AOS_CONTROL_TOKEN'], who).writable, writable, why)
      // As the operator (not root), the writer then meets what inspect said
      // (where it may search the directory, so that the create is what fails).
      if (me !== 0 && who.uid === undefined && !writable && (mode & 0o100) !== 0) {
        assert.match(untouched(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, { euid: 'process' })), /cannot create .*: EACCES/, why)
      }
    } finally {
      chmodSync(repo, 0o700)
    }
  }
  // Neither the owner nor in the group: the others' bits, which only root can arrange here.
  if (me === 0) {
    for (const [mode, writable] of [[0o773, true], [0o775, false]] as const) {
      const repo = repoWith(t)
      fs.chownSync(repo, me + 1, gid + 54321)
      chmodSync(repo, mode)
      assert.equal(inspectIn(repo, ['AOS_CONTROL_TOKEN']).writable, writable, mode.toString(8))
    }
  }
})

test('a .env that cannot be examined or read is refused by its errno, the same way by inspect and the writer, with nothing written', (t) => {
  t.after(() => SecretMask.clear())
  // An EIO from fstat or read is the filesystem's, not the file's content:
  // a ConfigError naming the code, so the installer reports it like any
  // refusal, rather than a raw error escaping the dry run.
  for (const call of ['fstatSync', 'readSync'] as const) {
    const repo = repoWith(t, `ANTHROPIC_API_KEY=${KEY}\n`)
    const path = join(repo, '.env')
    const ino = lstatSync(path).ino
    const before = snapshot(path)
    const realFstat = fs.fstatSync
    const realRead = fs.readSync
    const isEnv = (fd: number): boolean => realFstat(fd).ino === ino
    const failing = call === 'fstatSync'
      ? t.mock.method(fs, 'fstatSync', ((fd: number, ...rest: unknown[]) => {
          if (isEnv(fd)) throw errno('EIO', 'fstat')
          return (realFstat as (fd: number, ...rest: unknown[]) => unknown)(fd, ...rest)
        }) as typeof fs.fstatSync)
      : t.mock.method(fs, 'readSync', ((fd: number, ...rest: unknown[]) => {
          if (isEnv(fd)) throw errno('EIO', 'read')
          return (realRead as (fd: number, ...rest: unknown[]) => number)(fd, ...rest)
        }) as typeof fs.readSync)
    syncBuiltinESMExports()
    let inspected: string
    let written: string
    try {
      inspected = refusal(() => inspectIn(repo, ['AOS_CONTROL_TOKEN']))
      written = untouched(() => appendIn(repo, generators('AOS_CONTROL_TOKEN').generate))
    } finally {
      failing.mock.restore()
      syncBuiltinESMExports()
    }
    assert.ok(failing.mock.callCount() >= 2, `${call}: the writer no longer calls it through node:fs, so this test proves nothing`)
    assert.equal(inspected, `cannot read ${path}: EIO`, call)
    assert.equal(written, inspected, call)
    assert.equal(snapshot(path), before, call)
  }
})

test('digests: each listed name that holds a value is given as pmmcp\'s sha256 digest of it, never the value; a blank or missing name has none', (t) => {
  t.after(() => SecretMask.clear())
  // KNOWN's digest as pmmcp makes it: digest_of in src/transport/http_auth.py
  // ("sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest(), run at
  // persistent-memory-mcp dfcc99a), the line rotate_http_auth_token.py
  // --digest-stdin and http_auth check --expect read.
  const KNOWN = 'aos-kernel-digest-fixture-0123456789abcdef'
  const KNOWN_DIGEST = 'sha256:661beb83e38e9e7d4ab4687e2d0318685cab984f63005862b7f15ae2d2a215ec'
  const digestOf = (value: string): string => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`
  assert.equal(digestOf(KNOWN), KNOWN_DIGEST)
  const ALL = ['AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY', 'AOS_CONTROL_TOKEN']
  const clean = (result: unknown, ...values: string[]): void => {
    for (const value of values) assert.equal(echoes(JSON.stringify(result), value), false, 'a value is in the result')
  }

  // Set (plain and quoted, as the loader reads it), blank, missing.
  for (const line of [`AOS_PMMCP_TOKEN=${KNOWN}`, `export AOS_PMMCP_TOKEN="${KNOWN}"`]) {
    const repo = repoWith(t, `${line}\nANTHROPIC_API_KEY=\n`)
    const seen = inspectIn(repo, ALL, { digests: ALL })
    assert.deepEqual(seen.digests, [{ name: 'AOS_PMMCP_TOKEN', digest: KNOWN_DIGEST }], line)
    clean(seen, KNOWN)
    // Appended: the new value's digest, beside the one found, in the order listed.
    const g = generators('AOS_CONTROL_TOKEN')
    const done = appendIn(repo, g.generate, { digests: ALL })
    const made = g.made.get('AOS_CONTROL_TOKEN') ?? ''
    assert.deepEqual(done.digests, [
      { name: 'AOS_PMMCP_TOKEN', digest: KNOWN_DIGEST },
      { name: 'AOS_CONTROL_TOKEN', digest: digestOf(made) },
    ], line)
    clean(done, KNOWN, made)
    // A re-run with nothing to add gives the same, and inspect agrees.
    const again = appendIn(repo, generators('AOS_CONTROL_TOKEN').generate, { digests: ALL })
    assert.deepEqual([again.appended, again.digests], [[], done.digests], line)
    assert.deepEqual(inspectIn(repo, ALL, { digests: ALL }).digests, done.digests, line)
  }

  // Created: the generated value's digest; and none asked, none given.
  {
    const repo = repoWith(t)
    assert.deepEqual(inspectIn(repo, ALL, { digests: ALL }).digests, [])
    const g = generators('AOS_PMMCP_TOKEN')
    const done = appendIn(repo, g.generate, { digests: ['AOS_PMMCP_TOKEN', 'ANTHROPIC_API_KEY'] })
    const made = g.made.get('AOS_PMMCP_TOKEN') ?? ''
    assert.deepEqual(done.digests, [{ name: 'AOS_PMMCP_TOKEN', digest: digestOf(made) }])
    assert.match(done.digests[0]?.digest ?? '', /^sha256:[0-9a-f]{64}$/)
    clean(done, made)
    assert.deepEqual(appendIn(repo, generators('AOS_PMMCP_TOKEN').generate).digests, [])
  }

  // A name the config does not declare is refused, before anything is made.
  {
    const repo = repoWith(t, `AOS_PMMCP_TOKEN=${KNOWN}\n`)
    const before = snapshot(join(repo, '.env'))
    const g = generators('AOS_CONTROL_TOKEN')
    const refused = /^AOS_SOMETHING_ELSE is not a credential name the config declares, so it is not written to \.env$/
    assert.match(refusal(() => inspectIn(repo, ['AOS_PMMCP_TOKEN'], { digests: ['AOS_SOMETHING_ELSE'] })), refused)
    assert.match(untouched(() => appendIn(repo, g.generate, { digests: ['AOS_SOMETHING_ELSE'] })), refused)
    assert.equal(g.calls(), 0)
    assert.equal(snapshot(join(repo, '.env')), before)
  }
})
