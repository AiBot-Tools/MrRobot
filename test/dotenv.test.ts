// The .env loader (src/secrets/dotenv.ts).
//
// The file it reads holds the operator's real keys, so the tests are about what
// it refuses and what it never says. Every fixture is a mkdtemp file written
// 0600 by the test; nothing here opens the repository's own .env, and no fake
// value resembles a real key shape, so an absent value proves the exact-value
// mask rather than the pattern redactor.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { chmodSync, linkSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { ConfigError } from '../src/errors.js'
import { SecretMask, redactString } from '../src/events/redact.js'
import { parseProviders } from '../src/models/registry.js'
import {
  DOTENV_MAX_BYTES,
  credentialEnv,
  credentialNames,
  dotenvPathFrom,
  gitignoresDotenv,
  loadDotenv,
  parseDotenv,
  type DotenvOptions,
} from '../src/secrets/dotenv.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'
import { daemonEnv } from '../src/main.js'
import { liveCredential } from './helpers/live-env.js'

const ACCEPTED = new Set(['AOS_CONTROL_TOKEN', 'ANTHROPIC_API_KEY'])
const TOKEN = 'qTok3nVa1ueFor7estsOnly0123456789abcdef'
const KEY = 'qKeyVa1ueFor7estsOnlyZYXWVUTSRQPONM'

function write(t: TestContext, text: string | Buffer, mode = 0o600, name = 'creds.env'): string {
  const dir = tmpdir(t)
  const path = join(dir, name)
  writeFileSync(path, text, { mode })
  chmodSync(path, mode)
  return path
}

function opts(overrides: Partial<DotenvOptions> = {}): DotenvOptions {
  return {
    // A repo root the fixture paths are outside of, so only the file checks apply.
    repoRoot: REPO_ROOT,
    accepted: ACCEPTED,
    wanted: [...ACCEPTED],
    shell: {},
    ...overrides,
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

test('loadDotenv returns the wanted names from a 0600 file and leaves process.env unchanged', (t) => {
  t.after(() => SecretMask.clear())
  const before = JSON.stringify(Object.entries(process.env).sort())
  const path = write(t, `AOS_CONTROL_TOKEN=${TOKEN}\nANTHROPIC_API_KEY=${KEY}\n`)
  const loaded = loadDotenv(path, opts())
  assert.equal(loaded.found, true)
  assert.deepEqual(loaded.values, { AOS_CONTROL_TOKEN: TOKEN, ANTHROPIC_API_KEY: KEY })
  assert.deepEqual(loaded.shadowed, [])
  assert.equal(JSON.stringify(Object.entries(process.env).sort()), before, 'the loader wrote process.env')
})

test('a non-empty shell value wins over the file, and the name is reported as shadowed', (t) => {
  t.after(() => SecretMask.clear())
  const path = write(t, `AOS_CONTROL_TOKEN=${TOKEN}\nANTHROPIC_API_KEY=${KEY}\n`)
  const loaded = loadDotenv(path, opts({ shell: { ANTHROPIC_API_KEY: 'fromTheShell' } }))
  assert.deepEqual(loaded.values, { AOS_CONTROL_TOKEN: TOKEN })
  assert.deepEqual(loaded.shadowed, ['ANTHROPIC_API_KEY'])
  const env = credentialEnv(ACCEPTED, { ANTHROPIC_API_KEY: 'fromTheShell' }, loaded)
  assert.deepEqual(env, { AOS_CONTROL_TOKEN: TOKEN, ANTHROPIC_API_KEY: 'fromTheShell' })
})

test('an exported empty value does not shadow the file', (t) => {
  t.after(() => SecretMask.clear())
  const path = write(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  const loaded = loadDotenv(path, opts({ shell: { ANTHROPIC_API_KEY: '' } }))
  assert.deepEqual(loaded.values, { ANTHROPIC_API_KEY: KEY })
  assert.deepEqual(loaded.shadowed, [])
  assert.deepEqual(credentialEnv(ACCEPTED, { ANTHROPIC_API_KEY: '' }, loaded), {
    AOS_CONTROL_TOKEN: undefined,
    ANTHROPIC_API_KEY: KEY,
  })
})

test('only wanted names leave the loader: a caller wanting AOS_CONTROL_TOKEN never receives ANTHROPIC_API_KEY', (t) => {
  t.after(() => SecretMask.clear())
  const path = write(t, `AOS_CONTROL_TOKEN=${TOKEN}\nANTHROPIC_API_KEY=${KEY}\n`)
  const loaded = loadDotenv(path, opts({ wanted: ['AOS_CONTROL_TOKEN'] }))
  assert.deepEqual(Object.keys(loaded.values), ['AOS_CONTROL_TOKEN'])
  // Not even registered with the mask: a value nobody asked for was never handled.
  assert.equal(redactString(`x ${KEY} x`).includes(KEY), true)
})

test('a name the config does not declare is refused without being quoted, every bad line listed with the accepted names', (t) => {
  const path = write(
    t,
    [
      `AOS_CONTROL_TOKEN=${TOKEN}`,
      'AOS_LIVE_TESTS=1',
      'NODE_OPTIONS=--require=/tmp/evil.js',
      'ANTHROPIC_CUSTOM_HEADERS=x-evil:1',
      'AOS_DATA_DIR=',
      'anthropic_api_key=lower',
      'qPastedKeyWhereANameBelongs0123=',
    ].join('\n'),
  )
  const message = refusal(() => loadDotenv(path, opts()))
  for (const line of [2, 3, 4, 5, 6, 7]) {
    assert.match(message, new RegExp(`line ${String(line)}: a name this kernel does not read`))
  }
  assert.match(message, /\(accepted: ANTHROPIC_API_KEY, AOS_CONTROL_TOKEN\)/)
  for (const unquoted of ['AOS_LIVE_TESTS', 'NODE_OPTIONS', 'ANTHROPIC_CUSTOM_HEADERS', 'AOS_DATA_DIR', 'anthropic_api_key', 'qPastedKey']) {
    assert.equal(message.includes(unquoted), false, `${unquoted} was quoted`)
  }
})

test('a file readable or writable by group or others is refused with chmod 600 and the absolute path', (t) => {
  for (const mode of [0o644, 0o640, 0o604, 0o620, 0o602]) {
    const path = write(t, `ANTHROPIC_API_KEY=${KEY}\n`, mode)
    const message = refusal(() => loadDotenv(path, opts()))
    assert.match(message, new RegExp(`has mode 0${mode.toString(8)}`))
    assert.ok(message.includes(`chmod 600 ${path}`), message)
  }
})

test('a symlinked .env is refused even when its target is 0600', (t) => {
  const target = write(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  const link = join(tmpdir(t), 'link.env')
  symlinkSync(target, link)
  assert.match(refusal(() => loadDotenv(link, opts())), /is a symbolic link/)
})

test('a directory or a device at the path is refused as not a regular file', (t) => {
  const dir = join(tmpdir(t), 'adir')
  mkdirSync(dir, { mode: 0o700 })
  assert.match(refusal(() => loadDotenv(dir, opts())), /is not a regular file/)
  assert.match(refusal(() => loadDotenv('/dev/null', opts())), /is not a regular file/)
})

test('a file owned by another uid is refused', (t) => {
  const path = write(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  const me = process.getuid?.() ?? 0
  assert.match(refusal(() => loadDotenv(path, opts({ uid: me + 1 }))), /is owned by uid \d+, not you/)
})

test('a file with a second hard link is refused', (t) => {
  const path = write(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  linkSync(path, join(tmpdir(t), 'elsewhere.env'))
  assert.match(refusal(() => loadDotenv(path, opts())), /another hard link/)
})

test('a file over 64 KiB is refused before it is parsed', (t) => {
  // Garbage that would also fail the grammar: the size refusal must come first.
  const path = write(t, `not a line\n${'#'.repeat(DOTENV_MAX_BYTES)}`)
  assert.match(refusal(() => loadDotenv(path, opts())), /bytes; a credentials file is at most 65536/)
})

test('a missing file is not an error: found is false and no values are returned', (t) => {
  const loaded = loadDotenv(join(tmpdir(t), 'absent.env'), opts())
  assert.deepEqual(loaded, { path: loaded.path, found: false, values: {}, shadowed: [] })
})

test('grammar accepts comments, blank lines, export prefixes, CRLF, matched quotes and a leading BOM', (t) => {
  t.after(() => SecretMask.clear())
  const text = `﻿# credentials\r\n\r\n   \r\n  # indented comment\r\nexport AOS_CONTROL_TOKEN = "${TOKEN}"\r\nANTHROPIC_API_KEY='${KEY}'   \r\n`
  const path = write(t, text)
  assert.deepEqual(loadDotenv(path, opts()).values, { AOS_CONTROL_TOKEN: TOKEN, ANTHROPIC_API_KEY: KEY })
})

test('grammar refuses by line number: inner whitespace, an unmatched quote, an unquoted #, a bare CR, and a value that is itself NAME=value', () => {
  const cases: [string, RegExp][] = [
    ['ANTHROPIC_API_KEY=two words', /line 1: ANTHROPIC_API_KEY holds whitespace/],
    ['ANTHROPIC_API_KEY="unterminated', /line 1: ANTHROPIC_API_KEY has an unmatched quote/],
    ["ANTHROPIC_API_KEY='mixed\"", /line 1: ANTHROPIC_API_KEY has an unmatched quote/],
    ['ANTHROPIC_API_KEY=abc#comment', /line 1: ANTHROPIC_API_KEY holds whitespace, a quote, a backtick or '#'/],
    ['ANTHROPIC_API_KEY=a`b', /line 1: ANTHROPIC_API_KEY holds whitespace/],
    ['ANTHROPIC_API_KEY=ab\rcd', /line 1: a stray carriage return/],
    ['ANTHROPIC_API_KEY=AOS_CONTROL_TOKEN=abc', /line 1: ANTHROPIC_API_KEY holds a whole NAME=value line/],
    ['just some text', /line 1: not NAME=value/],
    ['=novalue', /line 1: not NAME=value/],
  ]
  for (const [text, pattern] of cases) {
    assert.match(refusal(() => parseDotenv(`${text}\n`, ACCEPTED)), pattern, text)
  }
})

test('a NUL byte or invalid UTF-8 is refused', (t) => {
  const nul = write(t, `ANTHROPIC_API_KEY=${KEY}\0\n`)
  assert.match(refusal(() => loadDotenv(nul, opts())), /contains a NUL byte/)
  const bad = write(t, Buffer.from([0x41, 0x3d, 0xff, 0xfe, 0x0a]))
  assert.match(refusal(() => loadDotenv(bad, opts())), /is not valid UTF-8/)
})

test('a whitespace-only value is unset and never swallows the next line', (t) => {
  // Node's own parser (util.parseEnv, --env-file) gives ANTHROPIC_API_KEY the
  // whole next line here. This grammar is per line.
  t.after(() => SecretMask.clear())
  const path = write(t, `ANTHROPIC_API_KEY=   \nAOS_CONTROL_TOKEN=${TOKEN}\n`)
  assert.deepEqual(loadDotenv(path, opts()).values, { AOS_CONTROL_TOKEN: TOKEN })
})

test('a name defined twice is refused, naming both lines', () => {
  assert.match(
    refusal(() => parseDotenv(`ANTHROPIC_API_KEY=${KEY}\n# x\nANTHROPIC_API_KEY=${KEY}\n`, ACCEPTED)),
    /line 3: ANTHROPIC_API_KEY is already set on line 1/,
  )
  // A blank first assignment still counts: the second is a contradiction.
  assert.match(refusal(() => parseDotenv(`ANTHROPIC_API_KEY=\nANTHROPIC_API_KEY=${KEY}\n`, ACCEPTED)), /already set on line 1/)
})

test('a blank value means unset, never the empty string', () => {
  const parsed = parseDotenv(`ANTHROPIC_API_KEY=\nAOS_CONTROL_TOKEN=""\n`, ACCEPTED)
  assert.equal(parsed.size, 0)
  assert.equal(parsed.has('ANTHROPIC_API_KEY'), false)
})

test('a value still holding the .env.example placeholder is refused, so the template cannot reach a provider', () => {
  assert.match(
    refusal(() => parseDotenv('ANTHROPIC_API_KEY=replace-me-with-your-anthropic-api-key\n', ACCEPTED)),
    /line 1: ANTHROPIC_API_KEY still holds the \.env\.example placeholder/,
  )
  assert.match(refusal(() => parseDotenv('AOS_CONTROL_TOKEN=REPLACE-ME\n', ACCEPTED)), /placeholder/)
})

test('no refusal message contains any 8-character window of a value or a line', (t) => {
  const canaryKey = 'Kc7Rq2Wm9Zp4Xv8Ls3Ny6Bt1'
  const canaryLine = 'Ld5Fh8Jk2Mn6Qw9Er3Ty7Ui0'
  const fixtures = [
    `ANTHROPIC_API_KEY=${canaryKey} tail`,
    `ANTHROPIC_API_KEY="${canaryKey}`,
    `ANTHROPIC_API_KEY=${canaryKey}#x`,
    `${canaryLine}`,
    `${canaryLine}=${canaryKey}`,
    `ANTHROPIC_API_KEY=${canaryKey}\nANTHROPIC_API_KEY=${canaryKey}`,
    `ANTHROPIC_API_KEY=AOS_CONTROL_TOKEN=${canaryKey}`,
  ]
  for (const text of fixtures) {
    const path = write(t, `${text}\n`)
    const message = refusal(() => loadDotenv(path, opts()))
    for (const secret of [canaryKey, canaryLine]) {
      for (let i = 0; i + 8 <= secret.length; i += 1) {
        assert.equal(message.includes(secret.slice(i, i + 8)), false, `"${message}" echoes part of a secret`)
      }
    }
  }
})

test('every returned value is registered with SecretMask before loadDotenv returns', (t) => {
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const path = write(t, `AOS_CONTROL_TOKEN=${TOKEN}\nANTHROPIC_API_KEY=${KEY}\n`)
  loadDotenv(path, opts())
  const redacted = redactString(`token ${TOKEN} key ${KEY}`)
  assert.equal(redacted.includes(TOKEN), false, 'the token was not masked')
  assert.equal(redacted.includes(KEY), false, 'the key was not masked')
})

test('inside the repository only <repo>/.env is read, and only while .gitignore ignores it', (t) => {
  t.after(() => SecretMask.clear())
  const repo = tmpdir(t)
  const env = join(repo, '.env')
  writeFileSync(env, `ANTHROPIC_API_KEY=${KEY}\n`, { mode: 0o600 })
  chmodSync(env, 0o600)
  const inRepo = opts({ repoRoot: repo })

  assert.match(refusal(() => loadDotenv(env, inRepo)), /is not ignored by .*\.gitignore: add the line \/\.env/)
  writeFileSync(join(repo, '.gitignore'), '.env\n!.env\n')
  assert.match(refusal(() => loadDotenv(env, inRepo)), /is not ignored/)
  for (const line of ['/.env', '.env', '.env*', '.env*\n!.env.example']) {
    writeFileSync(join(repo, '.gitignore'), `node_modules/\n${line}\n`)
    assert.equal(gitignoresDotenv(repo), true, line)
    assert.deepEqual(loadDotenv(env, inRepo).values, { ANTHROPIC_API_KEY: KEY }, line)
  }

  // Any other in-repo path is refused, the template above all.
  mkdirSync(join(repo, 'config'))
  for (const other of [join(repo, 'config', '.env'), join(repo, '.env.example'), join(repo, 'creds.env')]) {
    assert.match(refusal(() => loadDotenv(other, inRepo)), /the only credentials file read inside the repository is/, other)
  }

  // Outside the repository the fence does not apply; the file checks still do.
  const outside = write(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  assert.deepEqual(loadDotenv(outside, inRepo).values, { ANTHROPIC_API_KEY: KEY })
})

test('credentialNames on the shipped config is exactly AOS_CONTROL_TOKEN and ANTHROPIC_API_KEY, and grows with a declared tokenEnv or envVar', () => {
  const read = (p: string): unknown => parseYaml(readFileSync(join(REPO_ROOT, p), 'utf8'))
  const config = parseKernelConfig(read('config/kernel.yaml'), { repoRoot: REPO_ROOT })
  const providers = parseProviders(read('config/providers.yaml'))
  assert.deepEqual([...credentialNames(config, providers)].sort(), ['ANTHROPIC_API_KEY', 'AOS_CONTROL_TOKEN'])

  const withToken = {
    ...config,
    mcp: { servers: { pmmcp: { ...config.mcp.servers['pmmcp']!, tokenEnv: 'PMMCP_TOKEN' } } },
  }
  assert.deepEqual([...credentialNames(withToken, providers)].sort(), ['ANTHROPIC_API_KEY', 'AOS_CONTROL_TOKEN', 'PMMCP_TOKEN'])
})

test('dotenvPathFrom reads --dotenv once, resolves it against the base, and refuses a repeat, a missing value or an option', () => {
  assert.equal(dotenvPathFrom(['--config', 'x'], '/base'), undefined)
  assert.equal(dotenvPathFrom(['--dotenv', '.env'], '/base'), '/base/.env')
  assert.equal(dotenvPathFrom(['agents', '--dotenv=/abs/creds.env'], '/base'), '/abs/creds.env')
  assert.match(refusal(() => dotenvPathFrom(['--dotenv'], '/base')), /needs a path/)
  assert.match(refusal(() => dotenvPathFrom(['--dotenv', '--config'], '/base')), /needs a path/)
  assert.match(refusal(() => dotenvPathFrom(['--dotenv='], '/base')), /needs a path/)
  assert.match(refusal(() => dotenvPathFrom(['--dotenv', 'a', '--dotenv', 'b'], '/base')), /may be given once/)
})

test('daemonEnv without --dotenv never opens a trap .env in the repo root and returns exactly the credential names from the shell', (t) => {
  t.after(() => SecretMask.clear())
  const read = (p: string): unknown => parseYaml(readFileSync(join(REPO_ROOT, p), 'utf8'))
  const config = parseKernelConfig(read('config/kernel.yaml'), { repoRoot: REPO_ROOT })
  const providers = parseProviders(read('config/providers.yaml'))

  // A trap: a repo root whose .env would be refused (0644, an undeclared name)
  // the moment anything opened it.
  const repo = tmpdir(t)
  writeFileSync(join(repo, '.gitignore'), '/.env\n')
  writeFileSync(join(repo, '.env'), 'NODE_OPTIONS=--require=/tmp/evil.js\n', { mode: 0o644 })
  chmodSync(join(repo, '.env'), 0o644)
  const shell = { ANTHROPIC_API_KEY: 'fromTheShell', PATH: '/usr/bin', NODE_OPTIONS: '--inspect' }

  const plain = daemonEnv(['--config', 'x.yaml'], { repoRoot: repo, config, providers, shell })
  assert.equal(plain.loaded, undefined)
  // Exactly the credential names: nothing else from the shell rides along.
  assert.deepEqual(plain.env, { AOS_CONTROL_TOKEN: undefined, ANTHROPIC_API_KEY: 'fromTheShell' })

  // The trap is armed: with the flag, the same file is opened and refused.
  assert.match(
    refusal(() => daemonEnv(['--dotenv', '.env'], { repoRoot: repo, config, providers, shell })),
    /has mode 0644/,
  )
})

test('liveCredential refuses unless AOS_LIVE_TESTS=1 in the env it is given, and opens nothing then', (t) => {
  // A trap path: opening it would be refused with chmod 600, so the gate's own
  // error proves nothing was opened.
  const trap = write(t, 'ANTHROPIC_API_KEY=x\n', 0o644)
  for (const env of [{}, { AOS_LIVE_TESTS: '0' }, { AOS_LIVE_TESTS: 'true' }]) {
    assert.throws(() => liveCredential('ANTHROPIC_API_KEY', env, trap), /for AOS_LIVE_TESTS=1 only/)
  }
})

test('liveCredential prefers a non-empty shell value and otherwise reads the given .env', (t) => {
  t.after(() => SecretMask.clear())
  const path = write(t, `ANTHROPIC_API_KEY=${KEY}\n`)
  assert.equal(liveCredential('ANTHROPIC_API_KEY', { AOS_LIVE_TESTS: '1', ANTHROPIC_API_KEY: 'fromTheShell' }, path), 'fromTheShell')
  assert.equal(liveCredential('ANTHROPIC_API_KEY', { AOS_LIVE_TESTS: '1' }, path), KEY)
  assert.equal(liveCredential('ANTHROPIC_API_KEY', { AOS_LIVE_TESTS: '1' }, join(tmpdir(t), 'absent.env')), undefined)
})

test('credentialEnv on its own: a non-empty shell value beats any file value, an empty one does not, and only the given names come back', () => {
  // The loader already drops a name the shell sets, so this rule is enforced
  // twice. Tested here without the loader, so neither copy can rot unseen.
  const loaded = { path: '/x/.env', found: true, values: { A: 'fromFile', B: 'fileB', C: 'fileC' }, shadowed: [] }
  assert.deepEqual(credentialEnv(['A', 'B', 'D'], { A: 'fromShell', B: '', D: undefined, E: 'stray' }, loaded), {
    A: 'fromShell',
    B: 'fileB',
    D: undefined,
  })
  assert.deepEqual(credentialEnv(['A'], { A: 'fromShell' }, undefined), { A: 'fromShell' })
})
