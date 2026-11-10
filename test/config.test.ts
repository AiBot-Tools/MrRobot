// T17 — kernel.yaml schema.
//
// Config is where a security property is easiest to lose by accident: one
// edited string and the control plane listens to the world, or the event log
// moves somewhere an agent can reach. These tests are about which mistakes
// the file is CAPABLE of expressing, not about whether the shipped file is
// currently correct.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { homedir, userInfo } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import {
  DEFAULT_BASIC_USER,
  EGRESS_MUX_PORT,
  EGRESS_PUSH_PREFIX,
  KernelConfig,
  MAX_TIMER_MS,
  assertAosEntry,
  assertDataLocation,
  assertNoSecretKeys,
  bindingKeyProblem,
  expandHome,
  gitignoresAos,
  parseKernelConfig,
} from '../src/config.js'
import { parseProviders } from '../src/models/registry.js'
import { pushBranchPrefix } from '../src/egress/routes.js'
import { PROXY_LIMITS } from '../src/events/types.js'
import { tmpdir } from './helpers/tmpdir.js'
import { homeDirectory } from '../src/agents/protected.js'

// The real checkout, wherever it is: the location rules read its .gitignore.
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = new URL('./fixtures/config/', import.meta.url)

function fixture(name: string): unknown {
  return parseYaml(readFileSync(new URL(name, FIXTURES), 'utf8'))
}

function parse(doc: unknown, repoRoot = REPO_ROOT): ReturnType<typeof parseKernelConfig> {
  return parseKernelConfig(doc, { repoRoot })
}

test('parses a valid fixture', () => {
  const config = parse(fixture('valid.yaml'))

  assert.equal(config.version, 1)
  assert.equal(config.control.host, '127.0.0.1')
  assert.equal(config.control.port, 7777)
  assert.equal(config.dataDir, '/var/lib/aos')
  assert.equal(config.mcp.servers['pmmcp']?.url, 'http://127.0.0.1:8766/mcp')
  assert.equal(config.mcp.servers['pmmcp']?.tokenEnv, 'AOS_PMMCP_TOKEN')
  assert.equal(config.secrets.keyArg, 'label')
  assert.equal(config.sandbox.domains.hostile.network, 'aos-hostile')
  assert.equal(config.budgets.maxRetries, 2)

  // The minimal fixture proves the defaults are usable: everything a safe
  // default exists for is omitted, and the result is still complete.
  const minimal = parse(fixture('minimal.yaml'))
  assert.equal(minimal.control.host, '127.0.0.1')
  assert.equal(minimal.control.port, 7777)
  assert.equal(minimal.events.anchorEvery, 100)
  assert.equal(minimal.lanes.main, 4)
  assert.equal(minimal.budgets.approvalWaitMs, 300_000)
  assert.equal(minimal.sandbox.defaults.user, '65534:65534')
  assert.deepEqual(minimal.control.allowedOrigins, [])
})

test('rejects control.host other than 127.0.0.1', () => {
  // There is no spelling of this file that binds the control plane to a
  // public interface. Not a validated string; a literal.
  for (const host of ['0.0.0.0', '::', 'localhost', '192.168.1.10', '127.0.0.2']) {
    const doc = fixture('valid.yaml') as { control: { host: string } }
    doc.control.host = host
    assert.throws(() => parse(doc), /invalid/, `control.host: ${host} must be refused`)
  }
})

test('rejects unknown keys', () => {
  // A typo that parses is a setting the operator believes is active.
  const doc = fixture('valid.yaml') as Record<string, unknown>
  assert.throws(() => parse({ ...doc, budgts: { maxRetries: 0 } }), /invalid/)

  const nested = fixture('valid.yaml') as { control: Record<string, unknown> }
  nested.control['allowOrigins'] = []
  assert.throws(() => parse(nested), /invalid/)

  const sandbox = fixture('valid.yaml') as { sandbox: Record<string, unknown> }
  sandbox.sandbox['privileged'] = true
  assert.throws(() => parse(sandbox), /invalid/)
})

test('rejects a secret-looking key anywhere and names the path', () => {
  // The walk runs on the RAW document, before parsing drops unknown keys, so
  // a secret hiding under a key the schema never reads is still caught.
  const cases: [Record<string, unknown>, RegExp][] = [
    [{ version: 1, apiKey: 'sk-FAKE' }, /apiKey/],
    [{ version: 1, control: { token: 'FAKE' } }, /control\.token/],
    [{ version: 1, mcp: { servers: { pmmcp: { password: 'FAKE' } } } }, /mcp\.servers\.pmmcp\.password/],
    [{ version: 1, sandbox: { domains: { trusted: { client_secret: 'FAKE' } } } }, /client_secret/],
    [{ version: 1, list: [{ authorization: 'Bearer FAKE' }] }, /list\.0\.authorization/],
  ]
  for (const [doc, path] of cases) {
    assert.throws(() => parse(doc), /holds no secrets/, `${JSON.stringify(doc)} must be refused`)
    // The path is named: "there is a secret somewhere in your config" is not
    // an actionable error.
    assert.throws(() => parse(doc), path)
  }

  // Referencing a secret by environment variable NAME is the supported way,
  // and must keep working.
  assert.doesNotThrow(() => assertNoSecretKeys({ tokenEnv: 'AOS_PMMCP_TOKEN', vaultId: 'anthropic-api-key' }))
})

test('rejects a non-loopback pmmcp url', () => {
  for (const url of [
    'https://pmmcp.example.com/mcp',
    'http://10.0.0.5:8766/mcp',
    'http://0.0.0.0:8766/mcp',
    'not-a-url',
  ]) {
    const doc = fixture('valid.yaml') as { mcp: { servers: Record<string, { url: string }> } }
    const server = doc.mcp.servers['pmmcp']
    if (server !== undefined) server.url = url
    assert.throws(() => parse(doc), /invalid/, `${url} must be refused`)
  }

  // pmmcp is mandatory: a config without it would boot a kernel with no
  // memory and no vault, which is a silent degradation.
  const noPmmcp = fixture('valid.yaml') as { mcp: { servers: Record<string, unknown> } }
  delete noPmmcp.mcp.servers['pmmcp']
  assert.throws(() => parse(noPmmcp), /must include pmmcp/)
})

/** valid.yaml with `tokenEnv` set on pmmcp, or on a second server beside it. */
function declaringTokenEnv(tokenEnv: unknown, server = 'pmmcp'): unknown {
  const doc = fixture('valid.yaml') as { mcp: { servers: Record<string, Record<string, unknown>> } }
  doc.mcp.servers[server] = { url: 'http://127.0.0.1:9911/mcp', ...doc.mcp.servers[server], tokenEnv }
  return doc
}

test("a tokenEnv beginning PMMCP_ is refused, naming pmmcp's load_config", () => {
  // PMMCP_ is pmmcp's own prefix (D34): its load_config reads an exported
  // PMMCP_<SECTION>__<KEY> as a setting, and a pmmcp checkout up to 53ea308
  // will not start under any PMMCP_ name that is no setting. A kernel bearer
  // the operator exports must never be the reason pmmcp does not start, or a
  // setting it silently takes. The rule is the server entry's, so it holds for
  // every MCP server, not only pmmcp.
  for (const name of ['PMMCP_TOKEN', 'PMMCP_TOKEN_CEO', 'PMMCP_TOKEN_GOALS_LIVE', 'PMMCP_SERVER__TOKEN', 'PMMCP_SERVER', 'PMMCP_']) {
    for (const server of ['pmmcp', 'github']) {
      assert.throws(
        () => parse(declaringTokenEnv(name, server)),
        (e: unknown) =>
          e instanceof Error &&
          /kernel\.yaml is invalid/.test(e.message) &&
          /tokenEnv must not start with PMMCP_/.test(e.message) &&
          /pmmcp's load_config/.test(e.message) &&
          // Placed on the server that declared it.
          e.message.includes(`"${server}"`) &&
          // The way out is named, not only the refusal, and it is the server's
          // own: AOS_PMMCP_TOKEN is pmmcp's bearer, so another server told to
          // take it would declare pmmcp's name and be sent pmmcp's bearer.
          (server === 'pmmcp'
            ? /Name it AOS_PMMCP_TOKEN/.test(e.message)
            : /Give github an AOS_ name of its own, not AOS_PMMCP_TOKEN: that is pmmcp's bearer/.test(e.message) &&
              !/Name it AOS_PMMCP_TOKEN/.test(e.message)),
        `${server}.tokenEnv: ${name} must be refused, naming load_config and ${server}'s way out`,
      )
    }
  }

  // A prefix, not a substring: the shipped name and names that merely hold
  // PMMCP_ further in still parse, and keep their spelling.
  for (const name of ['AOS_PMMCP_TOKEN', 'AOS_PMMCP_TOKEN_CEO', 'XPMMCP_TOKEN']) {
    assert.equal(parse(declaringTokenEnv(name)).mcp.servers['pmmcp']?.tokenEnv, name)
    assert.equal(parse(declaringTokenEnv(name, 'github')).mcp.servers['github']?.tokenEnv, name)
  }
})

test('a tokenEnv that is not an upper-case .env name is refused', () => {
  // The name is looked up in the shell and in <repo>/.env. One neither can
  // spell the way the operator typed it is a bearer that is never found: the
  // hub would degrade over a "missing" value the operator believes is set.
  for (const name of [
    '',
    'aos_pmmcp_token',
    'Aos_Pmmcp_Token',
    // Lower case is refused before any prefix rule: pmmcp reads its settings
    // without regard to case, so each of these would set or stop pmmcp from a
    // shell that exports it, past a prefix check that reads PMMCP_ by spelling.
    // Lower case in the first letter alone counts as much as anywhere after it.
    'pmmcp_token',
    'pMMCP_SERVER__PORT',
    'Pmmcp_SERVER__PORT',
    'aOS_PMMCP_TOKEN',
    'AOS-PMMCP-TOKEN',
    'AOS.PMMCP.TOKEN',
    'AOS PMMCP TOKEN',
    ' AOS_PMMCP_TOKEN',
    'AOS_PMMCP_TOKEN ',
    'AOS_PMMCP_TOKEN\n',
    '1AOS_TOKEN',
    '_AOS_TOKEN',
    'AOS_PMMCP_TOKEN=qJoinedValue0123',
    '\u00C4OS_TOKEN',
    '\uFF21OS_TOKEN',
  ]) {
    assert.throws(
      () => parse(declaringTokenEnv(name)),
      (e: unknown) => e instanceof Error && /tokenEnv must be an upper-case \.env name/.test(e.message),
      `tokenEnv: ${JSON.stringify(name)} must be refused`,
    )
  }
  // Not a string at all, as YAML reads `tokenEnv: 42` or `tokenEnv: true`.
  for (const value of [42, true, null, ['AOS_PMMCP_TOKEN']]) {
    assert.throws(() => parse(declaringTokenEnv(value)), /kernel\.yaml is invalid/, `tokenEnv: ${JSON.stringify(value)} must be refused`)
  }

  // What a shell export and a .env line share: these parse unchanged.
  for (const name of ['AOS_PMMCP_TOKEN', 'GITHUB_TOKEN', 'A', 'X1', 'A_1__B']) {
    assert.equal(parse(declaringTokenEnv(name)).mcp.servers['pmmcp']?.tokenEnv, name)
  }
  // No tokenEnv at all is still a server that sends no bearer.
  const none = fixture('valid.yaml') as { mcp: { servers: Record<string, Record<string, unknown>> } }
  delete none.mcp.servers['pmmcp']?.['tokenEnv']
  assert.equal(parse(none).mcp.servers['pmmcp']?.tokenEnv, undefined)
})

test('inside the repo, the data dir and mount roots live only under .aos/', () => {
  // Operator decision (2026-10): everything in the program folder. The fence
  // is .aos/, which git ignores, so the event log is never committed and never
  // sits among the source an agent's repo access could reach.
  const shipped = fixture('valid.yaml') as { dataDir: string }
  shipped.dataDir = './.aos'
  assert.equal(parse(shipped).dataDir, join(REPO_ROOT, '.aos'), 'relative to the repo root, not the cwd')

  const elsewhere = fixture('valid.yaml') as { dataDir: string }
  elsewhere.dataDir = join(REPO_ROOT, 'src', 'data')
  assert.throws(() => parse(elsewhere), /inside the repository but outside .*\.aos/)

  const mount = (root: string): unknown => {
    const doc = fixture('valid.yaml') as { sandbox: { domains: { hostile: { mountRoot: string } } } }
    doc.sandbox.domains.hostile.mountRoot = root
    return doc
  }
  assert.equal(
    parse(mount('./.aos/workspaces/hostile')).sandbox.domains.hostile.mountRoot,
    join(REPO_ROOT, '.aos', 'workspaces', 'hostile'),
  )
  // A mount root must be under .aos/workspaces/: .aos/ itself holds the log.
  assert.throws(() => parse(mount('./.aos')), /outside .*workspaces/)
  assert.throws(() => parse(mount('workspaces/hostile')), /inside the repository but outside/)
  assert.throws(() => parse(mount('./hostile')), /inside the repository but outside/)
})

test('inside the repo is admitted only while .gitignore ignores /.aos/', (t) => {
  const repo = tmpdir(t)
  const doc = (): unknown => {
    const d = fixture('valid.yaml') as { dataDir: string }
    d.dataDir = './.aos'
    return d
  }
  assert.throws(() => parse(doc(), repo), /\.gitignore does not ignore \/\.aos\//)
  writeFileSync(join(repo, '.gitignore'), 'node_modules/\n.aos-backup/\n')
  assert.throws(() => parse(doc(), repo), /does not ignore/, 'a look-alike line is not the line')
  for (const line of ['/.aos/', '.aos/', '/.aos', '.aos']) {
    writeFileSync(join(repo, '.gitignore'), `node_modules/\n${line}\n`)
    assert.equal(parse(doc(), repo).dataDir, join(repo, '.aos'), line)
  }
  // And the real checkout ignores it, which the shipped config depends on.
  assert.equal(gitignoresAos(REPO_ROOT), true, 'this repository no longer ignores /.aos/')
})

test('never $HOME, and never a directory that contains the repository or $HOME', (t) => {
  const home = fixture('valid.yaml') as { dataDir: string }
  home.dataDir = homedir()
  assert.throws(() => parse(home), /must not be \$HOME itself/)

  const parent = fixture('valid.yaml') as { dataDir: string }
  parent.dataDir = dirname(REPO_ROOT)
  assert.throws(() => parse(parent), /contains the repository/)

  // A mount root containing $HOME hands a container everything (invariant 9).
  const above = fixture('valid.yaml') as { sandbox: { domains: { trusted: { mountRoot: string } } } }
  above.sandbox.domains.trusted.mountRoot = dirname(homedir())
  assert.throws(() => parse(above), /contains (the repository|\$HOME)/)

  // The $HOME rule on its own. On the operator's Mac the repo sits under $HOME,
  // so a folder above home also contains the repo and trips that check first;
  // a fake home beside a temp repo separates the two. os.homedir() reads $HOME.
  const sandboxRoot = tmpdir(t)
  mkdirSync(join(sandboxRoot, 'people', 'op'), { recursive: true })
  mkdirSync(join(sandboxRoot, 'repo'))
  writeFileSync(join(sandboxRoot, 'repo', '.gitignore'), '/.aos/\n')
  const savedHome = process.env['HOME']
  process.env['HOME'] = join(sandboxRoot, 'people', 'op')
  try {
    const aboveHome = fixture('valid.yaml') as { sandbox: { domains: { trusted: { mountRoot: string } } } }
    aboveHome.sandbox.domains.trusted.mountRoot = join(sandboxRoot, 'people')
    assert.throws(() => parse(aboveHome, join(sandboxRoot, 'repo')), /which contains \$HOME/)
  } finally {
    if (savedHome === undefined) delete process.env['HOME']
    else process.env['HOME'] = savedHome
  }

  // Outside the repo and under home is still fine, and ~ expands.
  const under = fixture('valid.yaml') as { dataDir: string }
  under.dataDir = '~/.aos'
  assert.equal(parse(under).dataDir, join(homedir(), '.aos'))
  assert.equal(expandHome('~'), homedir())
  assert.equal(expandHome('/absolute/path'), '/absolute/path')

  // AOS_DATA_DIR is typed in a shell: relative to the cwd, not the repo.
  const dir = tmpdir(t)
  mkdirSync(join(dir, 'data'))
  const cwd = process.cwd()
  process.chdir(dir)
  try {
    assert.equal(parseKernelConfig(fixture('valid.yaml'), { repoRoot: REPO_ROOT, dataDirOverride: 'data' }).dataDir, join(process.cwd(), 'data'))
  } finally {
    process.chdir(cwd)
  }
})

test('$HOME and the repository are recognised under any spelling; .aos is admitted only as spelled', (t) => {
  // On the operator's APFS volume /users/op and /Users/op are one directory.
  // Real directories stand in for $HOME and the repo; an identity function
  // makes the "-ALIAS" spellings resolve to them, as the filesystem would.
  // Resolved first: on macOS os.tmpdir() is under /var, a link to /private/var,
  // and assertDataLocation compares resolved paths, so the aliases must be
  // keyed by what it will actually see.
  const base = realpathSync(tmpdir(t))
  const home = join(base, 'people', 'op')
  const repo = join(base, 'people', 'op', 'MrRobot')
  mkdirSync(join(repo, '.aos'), { recursive: true })
  writeFileSync(join(repo, '.gitignore'), '/.aos/\n')
  const aliases: Record<string, string> = {
    [`${home}-ALIAS`]: home,
    [`${join(base, 'people')}-ALIAS`]: join(base, 'people'),
    [`${repo}-ALIAS`]: repo,
  }
  // An alias covers everything beneath it, as a real one would.
  const unalias = (p: string): string => {
    for (const [alias, real] of Object.entries(aliases)) {
      if (p === alias || p.startsWith(`${alias}/`)) return real + p.slice(alias.length)
    }
    return p
  }
  const id = (p: string): string | undefined => {
    try {
      const st = statSync(unalias(p), { bigint: true })
      return `${String(st.dev)}:${String(st.ino)}`
    } catch {
      return undefined
    }
  }
  const check = (target: string, allowed = '.aos'): void => assertDataLocation(target, 'dataDir', repo, allowed, { home, id })

  assert.throws(() => check(`${home}-ALIAS`), /must not be \$HOME itself/)
  assert.throws(() => check(`${join(base, 'people')}-ALIAS`), /contains (the repository|\$HOME)/)
  assert.throws(() => check(join(`${repo}-ALIAS`, 'data')), /inside the repository but outside/)
  // Inside .aos by identity but not as spelled: refused, never vouched for.
  assert.throws(() => check(join(`${repo}-ALIAS`, '.aos', 'x')), /inside the repository but outside/)
  // And the plain spelling still works.
  assert.doesNotThrow(() => check(join(repo, '.aos', 'x')))
})

test('a .aos that is a link is refused wherever it points and whatever kernel.yaml names: git does not ignore a link, and would commit it', (t) => {
  // `/.aos/` in .gitignore matches directories only; to git a symlink is a
  // file, so `git add -A` stages the link (and its target path) whatever it
  // points at, and whether or not any configured path goes through it.
  type Doc = { dataDir: string; sandbox: { domains: { trusted: { mountRoot: string }; hostile: { mountRoot: string } } } }
  const doc = (): Doc => fixture('valid.yaml') as Doc
  const outside = tmpdir(t)
  mkdirSync(join(outside, 'workspaces', 'hostile'), { recursive: true })
  for (const target of ['aos-data', '.', outside]) {
    const repo = tmpdir(t)
    writeFileSync(join(repo, '.gitignore'), '/.aos/\n')
    if (target === 'aos-data') mkdirSync(join(repo, 'aos-data', 'workspaces', 'hostile'), { recursive: true })
    symlinkSync(target, join(repo, '.aos'))
    const data = doc()
    data.dataDir = './.aos'
    assert.throws(() => parse(data, repo), /\.aos is a link.*Remove the link/, target)
    const mount = doc()
    mount.dataDir = tmpdir(t)
    mount.sandbox.domains.hostile.mountRoot = './.aos/workspaces/hostile'
    assert.throws(() => parse(mount, repo), /\.aos is a link/, target)
    // Nothing configured under .aos at all (the refusal's old advice: name the
    // target instead): the link is still in the repo, and still committed.
    const elsewhere = doc()
    elsewhere.dataDir = tmpdir(t)
    elsewhere.sandbox.domains.trusted.mountRoot = tmpdir(t)
    elsewhere.sandbox.domains.hostile.mountRoot = tmpdir(t)
    assert.throws(() => parse(elsewhere, repo), /\.aos is a link/, target)
  }
  // Spelled through an alias of the repository, which no spelling test of the
  // configured path recognises: the entry is judged, not the path.
  const repo = tmpdir(t)
  writeFileSync(join(repo, '.gitignore'), '/.aos/\n')
  symlinkSync(outside, join(repo, '.aos'))
  const alias = join(tmpdir(t), 'alias')
  symlinkSync(repo, alias)
  const aliased = doc()
  aliased.dataDir = join(alias, '.aos')
  aliased.sandbox.domains.trusted.mountRoot = join(alias, '.aos', 'workspaces', 'trusted')
  aliased.sandbox.domains.hostile.mountRoot = join(alias, '.aos', 'workspaces', 'hostile')
  assert.throws(() => parse(aliased, alias), /\.aos is a link/)
  assert.throws(() => parse(aliased, repo), /\.aos is a link/)
})

test('a link or any spelling beneath a real .aos is accepted: git never descends into an ignored directory', (t) => {
  // `ln -s /Volumes/Big/workspaces .aos/workspaces`: /.aos/ excludes the whole
  // directory, so nothing under it can be committed. Its target is a place the
  // operator could name outright.
  const repo = tmpdir(t)
  writeFileSync(join(repo, '.gitignore'), '/.aos/\n')
  mkdirSync(join(repo, '.aos'))
  const big = tmpdir(t)
  mkdirSync(join(big, 'workspaces', 'trusted'), { recursive: true })
  mkdirSync(join(big, 'workspaces', 'hostile'), { recursive: true })
  symlinkSync(join(big, 'workspaces'), join(repo, '.aos', 'workspaces'))
  assert.doesNotThrow(() => parse(fixture('valid.yaml'), repo))
})

test('a .aos stored under another case or folding is refused: git judges the name as it is on disk', (t) => {
  // On case-insensitive APFS ./.aos finds a directory stored as .AOS, or as
  // .aoſ (U+017F folds to 's' under Unicode case folding, not under JS's
  // toLowerCase), neither of which /.aos/ covers. A listing that answers with
  // the stored spelling, as APFS's would, stands in for that volume.
  const repo = tmpdir(t)
  for (const stored of ['.AOS', '.Aos', '.ao\u017F']) {
    const readdir = (dir: string): string[] => (dir === realpathSync(repo) ? [stored, '.gitignore'] : [])
    assert.throws(
      () => assertAosEntry(repo, readdir),
      new RegExp(`${stored.replace('.', '\\.')} on disk, not \\.aos.*Rename it to \\.aos`),
      stored,
    )
  }
  // The real listing: no .aos yet, which is a first boot, not a problem.
  assert.doesNotThrow(() => assertAosEntry(repo))
  mkdirSync(join(repo, '.aos'))
  assert.doesNotThrow(() => assertAosEntry(repo))
})

test('an empty HOME is treated as unset: the never-$HOME checks still see the real home directory', () => {
  // os.homedir() answers '' for HOME='', and '' resolves to the cwd — which
  // used to turn "not $HOME" into "not the repository".
  const passwdHome = userInfo().homedir
  const saved = process.env['HOME']
  process.env['HOME'] = ''
  try {
    assert.equal(homeDirectory(), passwdHome)
    const doc = fixture('valid.yaml') as { dataDir: string }
    doc.dataDir = passwdHome
    // Named by its passwd spelling: with the bug, the cwd stood in for $HOME,
    // and on the Mac (repo under home) a looser match passed either way.
    const named = realpathSync(passwdHome).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    assert.throws(() => parse(doc), new RegExp(`must not be \\$HOME itself \\(${named}\\)`))
  } finally {
    if (saved === undefined) delete process.env['HOME']
    else process.env['HOME'] = saved
  }
})

test('rejects an allowedOrigins entry that is not tauri://localhost or loopback http(s)', () => {
  const withOrigins = (origins: string[]): unknown => {
    const doc = fixture('valid.yaml') as { control: { allowedOrigins: string[] } }
    doc.control.allowedOrigins = origins
    return doc
  }

  // The Tauri webview origin and loopback pages are the only callers that
  // can legitimately exist (D10).
  assert.doesNotThrow(() => parse(withOrigins(['tauri://localhost'])))
  assert.doesNotThrow(() => parse(withOrigins(['http://127.0.0.1:1420', 'http://localhost:5173'])))

  for (const origin of [
    'https://app.example.com',
    'http://evil.example.com',
    'file://',
    'tauri://evil',
    '*',
  ]) {
    assert.throws(() => parse(withOrigins([origin])), /invalid/, `${origin} must be refused`)
  }
})

test('budgets cannot be zero or negative', () => {
  // A budget that can be switched off is not a budget. No field admits
  // "unlimited", including by spelling it 0.
  const fields = [
    'defaultRunMicroUsd',
    'defaultWallclockMs',
    'maxLlmCallsPerRun',
    'maxToolCallsPerRun',
    'approvalWaitMs',
  ] as const

  for (const field of fields) {
    for (const value of [0, -1]) {
      const doc = fixture('valid.yaml') as { budgets: Record<string, number> }
      doc.budgets[field] = value
      assert.throws(() => parse(doc), /invalid/, `budgets.${field} = ${String(value)} must be refused`)
    }
  }

  // maxRetries is the one field allowed to be 0 — no retries is a valid
  // policy — but it is capped, so a typo cannot mean "retry forever".
  const noRetries = fixture('valid.yaml') as { budgets: Record<string, number> }
  noRetries.budgets['maxRetries'] = 0
  assert.equal(parse(noRetries).budgets.maxRetries, 0)

  const tooMany = fixture('valid.yaml') as { budgets: Record<string, number> }
  tooMany.budgets['maxRetries'] = 99
  assert.throws(() => parse(tooMany), /invalid/)

  // Lane caps and payload size are positive too.
  const lanes = fixture('valid.yaml') as { lanes: Record<string, number> }
  lanes.lanes['main'] = 0
  assert.throws(() => parse(lanes), /invalid/)
})

test('sandbox.defaults.user is never root or its group, and memory is a positive size with a unit', () => {
  // Invariant 9: non-root, and a memory cap. A shape check alone admits both
  // failures, because docker reads 0:0 as root and a memory of 0 as no limit.
  // The run-args audit refuses them again (test/sandbox-docker.test.ts).
  for (const user of ['0:0', '0:65534', '65534:0', '00:00', '0', 'root', '4294967296:4294967296', '2147483648:1']) {
    const doc = fixture('valid.yaml') as { sandbox: { defaults: Record<string, unknown> } }
    doc.sandbox.defaults['user'] = user
    assert.throws(() => parse(doc), /sandbox\.defaults\.user must be <uid>:<gid>, both numeric and neither 0/, `user: ${user}`)
  }
  for (const memory of ['0', '0g', '512', '0.5g', '-1g', '1t', '2gb', '9999999999999999g', '']) {
    const doc = fixture('valid.yaml') as { sandbox: { defaults: Record<string, unknown> } }
    doc.sandbox.defaults['memory'] = memory
    assert.throws(() => parse(doc), /sandbox\.defaults\.memory must be a positive whole number with a unit/, `memory: ${memory}`)
  }

  const ok = fixture('valid.yaml') as { sandbox: { defaults: Record<string, unknown> } }
  ok.sandbox.defaults['user'] = '501:20'
  ok.sandbox.defaults['memory'] = '512M'
  const parsed = parse(ok)
  assert.equal(parsed.sandbox.defaults.user, '501:20')
  assert.equal(parsed.sandbox.defaults.memory, '512M')
  // The schema's defaults pass its rule when written out. (A zod default is
  // returned as given, not parsed, so only writing it out checks it.)
  const defaults = parse(fixture('minimal.yaml')).sandbox.defaults
  const written = fixture('valid.yaml') as { sandbox: { defaults: Record<string, unknown> } }
  written.sandbox.defaults['user'] = defaults.user
  written.sandbox.defaults['memory'] = defaults.memory
  assert.deepEqual([defaults.user, defaults.memory], ['65534:65534', '2g'])
  assert.doesNotThrow(() => parse(written))
})

test('sandbox.imageId must be sha256:<64 hex>', () => {
  // Egress plan P4: every run executes the image by this id, with
  // --pull=never. A tag names whatever image was last given it on that VM,
  // and a repository digest is a name the daemon resolves, so neither pins
  // anything. The run-args audit refuses them again (test/sandbox-docker.test.ts).
  const id = `sha256:${'0123456789abcdef'.repeat(4)}`
  const withId = (imageId: unknown): unknown => {
    const doc = fixture('valid.yaml') as { sandbox: Record<string, unknown> }
    doc.sandbox['imageId'] = imageId
    return doc
  }
  for (const imageId of [
    'aos-worker:0.0.1',
    'aos-worker',
    `aos-worker@${id}`,
    id.slice('sha256:'.length),
    id.toUpperCase(),
    `sha256:${'0123456789ABCDEF'.repeat(4)}`,
    id.slice(0, -1),
    `${id}0`,
    `sha512:${'0'.repeat(64)}`,
    `${id}\n`,
    ` ${id}`,
    '',
    // Lower case, the right length, and not hex. digest.Parse refuses it, so
    // docker reads the whole string as the TAG of repository
    // docker.io/library/sha256, whatever image the VM last gave that name.
    `sha256:${'g'.repeat(64)}`,
    `sha256:${'0123456789abcdef'.repeat(4).slice(0, 63)}g`,
    `sha256:${'z'.repeat(64)}`,
  ]) {
    assert.throws(() => parse(withId(imageId)), /sandbox\.imageId must be sha256:<64 lower-case hex>/, JSON.stringify(imageId))
  }
  for (const imageId of [123, null, true, [id]]) {
    assert.throws(() => parse(withId(imageId)), /kernel\.yaml is invalid/, JSON.stringify(imageId))
  }

  assert.equal(parse(withId(id)).sandbox.imageId, id)
  // Optional: kernel.yaml ships none until the image is built, and the
  // sandbox subsystem is then degraded, naming the key (sandbox-docker,
  // config-files and kernel-boot tests).
  assert.equal(parse(fixture('valid.yaml')).sandbox.imageId, undefined)
  assert.equal(parse(fixture('minimal.yaml')).sandbox.imageId, undefined)

  // The tag stays beside it, and stays required: a name only, the one the
  // build script gives the image, which no run executes.
  assert.equal(parse(withId(id)).sandbox.image, 'aos-worker:0.0.1')
  for (const pinned of [undefined, id]) {
    const doc = withId(pinned) as { sandbox: Record<string, unknown> }
    delete doc.sandbox['image']
    assert.throws(
      () => parse(doc),
      (e: unknown) =>
        e instanceof Error && /^kernel\.yaml is invalid/.test(e.message) && /"path": \[\s*"sandbox",\s*"image"\s*\]/.test(e.message),
      `no sandbox.image, imageId ${String(pinned)}`,
    )
  }
  for (const image of ['', 7, null]) {
    const doc = withId(id) as { sandbox: Record<string, unknown> }
    doc.sandbox['image'] = image
    assert.throws(() => parse(doc), /kernel\.yaml is invalid/, JSON.stringify(image))
  }
})

test('a sandbox domain network must be a plain network name: name=host and the like are refused at boot', () => {
  // Invariant 9's internal network. The docker CLI reads a --network value
  // holding = as key=value fields, lower-cased, whose name= is the network,
  // so `name=host` is the VM's own network stack, while probe() inspects a
  // network of that literal name. The run-args audit refuses it again
  // (test/sandbox-docker.test.ts).
  for (const network of ['name=host', 'NAME=HOST', 'name=aos-trusted,alias=x', 'container:abc', 'aos trusted', '-aos', '']) {
    for (const domain of ['trusted', 'hostile'] as const) {
      const doc = fixture('valid.yaml') as { sandbox: { domains: Record<string, { network: string }> } }
      const entry = doc.sandbox.domains[domain]
      assert.ok(entry !== undefined)
      entry.network = network
      assert.throws(
        () => parse(doc),
        /a sandbox domain network must be a plain network name/,
        `${domain}: ${JSON.stringify(network)}`,
      )
    }
  }
  // A plain name passes, `none` among them (the egress plan's S1 runs on it).
  for (const network of ['aos-trusted', 'aos_hostile.2', 'none', '0net']) {
    const doc = fixture('valid.yaml') as { sandbox: { domains: Record<string, { network: string }> } }
    const entry = doc.sandbox.domains['trusted']
    assert.ok(entry !== undefined)
    entry.network = network
    assert.equal(parse(doc).sandbox.domains.trusted.network, network)
  }
})

test('a sandbox domain network may not be host, bridge or default, in any case; none still passes', () => {
  // Plain names, but docker's own, and not one of them internal: probe()
  // would degrade the kernel and advise `docker network rm host && docker
  // network create --internal host`, which docker refuses for a predefined
  // network. Refused without regard to case, as the run-args audit refuses
  // them (test/sandbox-docker.test.ts), so no name boots that every run
  // refuses. Docker reads a plain HOST as a network of that name, not as
  // host, so the message gives the reason a case variant is refused: the
  // key=value spelling, which lower-cases.
  for (const network of ['host', 'HOST', 'bridge', 'Bridge', 'default', 'DEFAULT']) {
    for (const domain of ['trusted', 'hostile'] as const) {
      const doc = fixture('valid.yaml') as { sandbox: { domains: Record<string, { network: string }> } }
      const entry = doc.sandbox.domains[domain]
      assert.ok(entry !== undefined)
      entry.network = network
      assert.throws(
        () => parse(doc),
        (e: unknown) =>
          e instanceof Error &&
          e.message.includes('a sandbox domain network may not be host, bridge or default, nor any of them in another case') &&
          e.message.includes("a plain HOST names a separate network called HOST, but docker's key=value spelling lower-cases (name=HOST is host)") &&
          !e.message.includes('HOST would name a network of its own') &&
          !e.message.includes('in any case:'),
        `${domain}: ${JSON.stringify(network)}`,
      )
    }
  }
  // Names that hold one of them pass: only the whole name is docker's.
  for (const network of ['none', 'host-net', 'aos-bridge', 'defaults']) {
    const doc = fixture('valid.yaml') as { sandbox: { domains: Record<string, { network: string }> } }
    const entry = doc.sandbox.domains['hostile']
    assert.ok(entry !== undefined)
    entry.network = network
    assert.equal(parse(doc).sandbox.domains.hostile.network, network)
  }
})

test('secrets.source defaults to env; envFallback defaults to false and needs source: vault', () => {
  // pmmcp's get_secret never returns plaintext, so the environment is the
  // working credential path and the vault is dormant.
  assert.equal(parse(fixture('minimal.yaml')).secrets.source, 'env')
  assert.equal(parse(fixture('minimal.yaml')).secrets.envFallback, false)
  assert.equal(parse(fixture('valid.yaml')).secrets.envFallback, false)

  // A fallback FROM the vault means nothing without the vault.
  const onWithEnv = fixture('valid.yaml') as { secrets: { envFallback: boolean } }
  onWithEnv.secrets.envFallback = true
  assert.throws(() => parse(onWithEnv), /needs secrets\.source: vault/)

  const on = fixture('valid.yaml') as { secrets: { envFallback: boolean; source: string } }
  on.secrets.envFallback = true
  on.secrets.source = 'vault'
  assert.equal(parse(on).secrets.envFallback, true, 'it can be turned on deliberately, with the vault')

  // keyArg carries the operator-confirmed argument name.
  assert.equal(parse(fixture('minimal.yaml')).secrets.keyArg, 'label')
})

test('a ~ in sandbox dockerHost is expanded; a relative socket path is refused', () => {
  // DOCKER_HOST goes to the docker CLI, which the driver spawns without a
  // shell. Nothing downstream expands ~, so an unexpanded value is a config
  // that reads correctly and cannot connect — the exact failure this repo
  // refuses to ship. Colima keeps its sockets under $HOME, so ~ is the form an
  // operator writes.
  const doc = fixture('valid.yaml') as {
    sandbox: { domains: Record<string, { dockerHost: string }> }
  }
  doc.sandbox.domains['trusted']!.dockerHost = 'unix://~/.colima/trusted/docker.sock'
  doc.sandbox.domains['hostile']!.dockerHost = 'unix://~/.colima/hostile/docker.sock'

  const config = parse(doc)
  assert.equal(config.sandbox.domains.trusted.dockerHost, `unix://${join(homedir(), '.colima/trusted/docker.sock')}`)
  assert.equal(config.sandbox.domains.hostile.dockerHost, `unix://${join(homedir(), '.colima/hostile/docker.sock')}`)
  // Three slashes, not two: the expanded form is an absolute path.
  assert.match(config.sandbox.domains.trusted.dockerHost, /^unix:\/\/\//)
  assert.equal(config.sandbox.domains.trusted.dockerHost.includes('~'), false)

  // An absolute socket is passed through unchanged.
  const plain = fixture('valid.yaml')
  assert.equal(parse(plain).sandbox.domains.trusted.dockerHost, 'unix:///var/run/colima-trusted.sock')

  // A relative path would never resolve, so it is refused rather than handed
  // to docker to fail on.
  for (const bad of ['unix://relative/docker.sock', 'unix://./docker.sock', 'unix://']) {
    const broken = fixture('valid.yaml') as { sandbox: { domains: Record<string, { dockerHost: string }> } }
    broken.sandbox.domains['trusted']!.dockerHost = bad
    assert.throws(() => parse(broken), /must resolve to an absolute socket path/, bad)
  }
})

test('a ~ mountRoot resolves; a relative one resolves against the repo root, never the cwd', () => {
  // The old rule refused relative mountRoots because they resolved against
  // whatever directory the daemon started in. They now resolve against the
  // repository root, so `npm run dev` from anywhere mounts the same folder.
  const doc = fixture('valid.yaml') as { sandbox: { domains: Record<string, { mountRoot: string }> } }
  doc.sandbox.domains['trusted']!.mountRoot = '~/.aos/workspaces/trusted'
  doc.sandbox.domains['hostile']!.mountRoot = '~/.aos/workspaces/hostile'

  const config = parse(doc)
  assert.equal(config.sandbox.domains.trusted.mountRoot, join(homedir(), '.aos/workspaces/trusted'))
  assert.equal(config.sandbox.domains.hostile.mountRoot, join(homedir(), '.aos/workspaces/hostile'))

  const sibling = fixture('valid.yaml') as { sandbox: { domains: Record<string, { mountRoot: string }> } }
  sibling.sandbox.domains['trusted']!.mountRoot = '../aos-outside/trusted'
  assert.equal(parse(sibling).sandbox.domains.trusted.mountRoot, resolve(REPO_ROOT, '../aos-outside/trusted'))
})

test('control.port refuses a privileged port but allows the literal 0', () => {
  // 0 means "ask the OS for an ephemeral port", which is how parallel test
  // processes avoid colliding. It is not a privileged port; the floor exists to
  // refuse 1-1023, where a bind would need privileges the daemon must not have.
  const doc = fixture('valid.yaml') as { control: { port: number } }
  doc.control.port = 0
  assert.equal(parse(doc).control.port, 0)

  for (const port of [1, 22, 80, 443, 1023, 65_536, -1, 1.5]) {
    const broken = fixture('valid.yaml') as { control: { port: number } }
    broken.control.port = port
    assert.throws(() => parse(broken), /is invalid/, String(port))
  }
})

// ── egress (egress plan E5) ─────────────────────────────────────────────────

/** valid.yaml with `egress` set as given, or with no egress section at all. */
function withEgress(egress?: unknown): Record<string, unknown> {
  const doc = fixture('valid.yaml') as Record<string, unknown>
  if (egress !== undefined) doc['egress'] = egress
  return doc
}

/** A binding as an operator would write one, with `overrides` laid over it. */
function binding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { host: 'github.com', scheme: 'Basic', envVar: 'AOS_GITHUB_TOKEN', profiles: ['git-fetch'], repos: ['op/fixture'], ...overrides }
}

/** valid.yaml holding `bindings` and nothing else in its egress section. */
function withBindings(bindings: Record<string, unknown>): Record<string, unknown> {
  return withEgress({ bindings })
}

/** The issues a kernel.yaml refusal's message lists, as zod wrote them. */
function issuesOf(message: string): unknown {
  return JSON.parse(message.slice(message.indexOf('[')))
}

/** The message `fn` throws, asserting it is a kernel.yaml refusal. */
function invalid(fn: () => unknown, label: string): string {
  try {
    fn()
  } catch (e) {
    assert.ok(e instanceof Error, label)
    assert.match(e.message, /kernel\.yaml is invalid/, label)
    return e.message
  }
  assert.fail(`${label} was accepted`)
}

test('egress is strict, ships disabled, and refuses a non-EgressHost binding host, a PMMCP_ envVar, a hostile entry and a DENY_KEYS-named key', () => {
  // The shipped file: disabled, no binding, the plan's limits and mux port,
  // and exactly the plan's four keys (no domain: egress serves the trusted
  // domain alone). No binding ships, because any binding widens what a run
  // can reach.
  const shipped = parse(parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')))
  assert.deepEqual(shipped.egress, {
    enabled: false,
    muxPort: 3128,
    limits: { frameMaxBytes: 65_536, maxFlows: 16, maxHeaderBytes: 16_384, maxRequests: 2_000, maxBytes: 536_870_912, maxDenied: 20, idleMs: 60_000 },
    bindings: {},
  })
  // No egress section at all is the same section: every field has its safe default.
  assert.deepEqual(parse(withEgress()).egress, shipped.egress)
  assert.deepEqual(parse(fixture('minimal.yaml')).egress, shipped.egress)

  // Strict at every level, both schemes' bindings included: a typo or a
  // stale key is refused, never taken for a setting or silently dropped.
  const bearer = (overrides: Record<string, unknown>): Record<string, unknown> =>
    binding({ host: 'api.github.com', scheme: 'Bearer', profiles: ['github-pulls'], ...overrides })
  assert.equal(parse(withBindings({ api: bearer({}) })).egress.bindings['api']?.scheme, 'Bearer')
  for (const [label, egress, key] of [
    ['egress.enable', { enable: true }, 'enable'],
    ['egress.limits.maxFlow', { limits: { maxFlow: 4 } }, 'maxFlow'],
    ['a Basic binding field', { bindings: { github: binding({ methods: ['GET'] }) } }, 'methods'],
    ['a Basic binding vaultId', { bindings: { github: binding({ vaultId: 'github-pat' }) } }, 'vaultId'],
    ['a Bearer binding field', { bindings: { api: bearer({ methods: ['GET'] }) } }, 'methods'],
    ['a Bearer binding vaultId', { bindings: { api: bearer({ vaultId: 'github-pat' }) } }, 'vaultId'],
    ['a Bearer binding repo', { bindings: { api: bearer({ repo: 'op/fixture' }) } }, 'repo'],
  ] as const) {
    const message = invalid(() => parse(withEgress(egress)), label)
    assert.match(message, new RegExp(`"code": "unrecognized_keys",\\s*"keys": \\[\\s*"${key}"\\s*\\]`), label)
  }
  invalid(() => parse(withEgress({ enabled: 'false' })), 'egress.enabled: "false"')

  // A binding host is an EgressHost: never an address in any notation, a
  // name the Mac, a VM or the LAN answers, a port, a wildcard or a URL.
  for (const host of [
    '192.168.5.2',
    '127.0.0.1',
    '2130706433',
    '0x7f.1',
    '[::1]',
    '::1',
    'host.lima.internal',
    'host.docker.internal',
    'gateway.docker.internal',
    'localhost',
    'api.localhost',
    'mac.local',
    'github',
    'github.com:443',
    '*.github.com',
    'https://github.com',
    'op@github.com',
    'githüb.com',
    '',
  ]) {
    const message = invalid(() => parse(withBindings({ github: binding({ host }) })), `host ${JSON.stringify(host)}`)
    assert.match(message, /not an egress host/, host)
    assert.ok(message.includes('"host"'), `the refusal of ${JSON.stringify(host)} names the key`)
  }
  // One name in one spelling: the host and the repositories are normalised.
  const parsed = parse(withBindings({ github: binding({ host: 'GitHub.com.', repos: ['Op/Fixture'] }) })).egress.bindings['github']
  assert.equal(parsed?.host, 'github.com')
  assert.deepEqual(parsed?.repos, ['op/fixture'])

  // A PMMCP_ envVar is refused as an MCP tokenEnv is (D34), naming the way out.
  for (const envVar of ['PMMCP_GITHUB_TOKEN', 'PMMCP_SERVER', 'PMMCP_']) {
    const message = invalid(() => parse(withBindings({ github: binding({ envVar }) })), envVar)
    assert.match(message, /egress binding envVar must not start with PMMCP_/, envVar)
    assert.match(message, /pmmcp's load_config/, envVar)
    assert.match(message, /53ea308/, envVar)
    assert.match(message, /Give the binding an AOS_ name of its own/, envVar)
  }
  // Not upper case is refused before any prefix rule, as a tokenEnv is: pmmcp
  // reads its settings without regard to case.
  for (const envVar of ['pmmcp_github_token', 'aos_github_token', 'AOS-GITHUB-TOKEN', '1AOS', 'AOS_GITHUB_TOKEN=x', '']) {
    const message = invalid(() => parse(withBindings({ github: binding({ envVar }) })), envVar)
    assert.match(message, /egress binding envVar must be an upper-case \.env name/, envVar)
  }
  // A prefix, not a substring.
  assert.equal(parse(withBindings({ github: binding({ envVar: 'AOS_PMMCP_GITHUB' }) })).egress.bindings['github']?.envVar, 'AOS_PMMCP_GITHUB')

  // Only the trusted domain: the hostile domain gets no channel and no
  // egress, so the section names no domain at all, and whichever way
  // kernel.yaml tries to name one is an unknown key.
  for (const [label, egress] of [
    ['domain: hostile', { domain: 'hostile' }],
    ['domain: trusted', { domain: 'trusted' }],
    ['domain: [trusted, hostile]', { domain: ['trusted', 'hostile'] }],
    ['egress.hostile', { hostile: { enabled: true } }],
    ['egress.domains', { domains: { trusted: {}, hostile: {} } }],
    ['a Basic binding domain', { bindings: { github: binding({ domain: 'hostile' }) } }],
    ['a Bearer binding domain', { bindings: { api: bearer({ domain: 'hostile' }) } }],
  ] as const) {
    assert.match(invalid(() => parse(withEgress(egress)), label), /Unrecognized key/, label)
  }

  // A key DENY_KEYS names, anywhere in the section, binding ids included, is
  // refused before parsing and named: kernel.yaml holds no secrets.
  for (const [egress, path] of [
    [{ bindings: { token: binding() } }, /egress\.bindings\.token\b/],
    [{ bindings: { 'api-key': binding() } }, /egress\.bindings\.api-key\b/],
    [{ bindings: { github: binding({ token: 'FAKE' }) } }, /egress\.bindings\.github\.token\b/],
    [{ bindings: { github: binding({ secret: 'FAKE' }) } }, /egress\.bindings\.github\.secret\b/],
    [{ limits: { password: 'FAKE' } }, /egress\.limits\.password\b/],
    [{ credentials: { github: 'FAKE' } }, /egress\.credentials\b/],
  ] as const) {
    assert.throws(() => parse(withEgress(egress)), /holds no secrets/, String(path))
    assert.throws(() => parse(withEgress(egress)), path)
  }
})

test("an egress binding names a credential of its own: never the control plane's bearer or an MCP server's", () => {
  // Either would be sent to the binding's host: pmmcp's bearer to GitHub.
  for (const [envVar, whose] of [
    ['AOS_CONTROL_TOKEN', /AOS_CONTROL_TOKEN is the control plane's bearer \(control\.tokenEnv\)/],
    ['AOS_PMMCP_TOKEN', /AOS_PMMCP_TOKEN is mcp server pmmcp's bearer \(mcp\.servers\.pmmcp\.tokenEnv\)/],
  ] as const) {
    const message = invalid(() => parse(withBindings({ github: binding({ envVar }) })), envVar)
    assert.match(message, whose, envVar)
    assert.match(message, /the binding would send it to github\.com/, envVar)
    assert.match(message, /"egress",\s*"bindings",\s*"github",\s*"envVar"/, envVar)
  }
  // Another server's bearer, declared beside pmmcp, is held the same way.
  const second = withBindings({ github: binding({ envVar: 'AOS_GITHUB_MCP_TOKEN' }) }) as { mcp: { servers: Record<string, unknown> } }
  second.mcp.servers['github'] = { url: 'http://127.0.0.1:9911/mcp', tokenEnv: 'AOS_GITHUB_MCP_TOKEN' }
  assert.match(invalid(() => parse(second), 'a second server'), /mcp server github's bearer/)

  // One credential for two hosts is the operator's to choose (one PAT for
  // git on github.com and pull requests on api.github.com): admitted.
  const shared = parse(
    withBindings({
      'github-git': binding({ profiles: ['git-fetch', 'git-push'] }),
      'github-api': binding({ host: 'api.github.com', scheme: 'Bearer', profiles: ['github-pulls'] }),
    }),
  )
  assert.deepEqual(Object.values(shared.egress.bindings).map((b) => b.envVar), ['AOS_GITHUB_TOKEN', 'AOS_GITHUB_TOKEN'])
})

test('an egress binding whose id, host or repository the redaction pass would change is refused, naming the key', () => {
  // The store parses a row before it redacts it, so each of these would be
  // stored censored, in a grant row that fails its own schema read back.
  const ghp = `ghp_${'a1'.repeat(18)}`
  for (const [bindings, path] of [
    [{ 'sk-abcdefghij': binding() }, /"bindings",\s*"sk-abcdefghij"\s*\]/],
    [{ 'xoxb-abcdefghij': binding() }, /"bindings",\s*"xoxb-abcdefghij"\s*\]/],
    [{ github: binding({ host: 'sk-abcdefghij.example.com' }) }, /"github",\s*"host"/],
    [{ github: binding({ host: 'xoxb-abcdefghij.example.com' }) }, /"github",\s*"host"/],
    [{ github: binding({ host: `ey${'a'.repeat(10)}.ey${'b'.repeat(10)}.${'c'.repeat(10)}` }) }, /"github",\s*"host"/],
    [{ github: binding({ repos: ['op/fixture', `op/${ghp}`] }) }, /"github",\s*"repos",\s*1/],
    [{ github: binding({ repos: [`OP/${ghp.toUpperCase().replace('GHP_', 'ghp_')}`] }) }, /"github",\s*"repos",\s*0/],
  ] as const) {
    const message = invalid(() => parse(withBindings(bindings)), String(path))
    assert.match(message, /in the shape of a credential, so the event log would store it censored/, String(path))
    assert.match(message, path)
  }
  // The same names one character short of a credential's shape are kept as they are.
  const kept = parse(withBindings({ 'sk-abcdefg': binding({ host: 'sk-abcdefg.example.com', repos: ['op/ghp_short'] }) }))
  assert.deepEqual(kept.egress.bindings['sk-abcdefg']?.repos, ['op/ghp_short'])
  assert.equal(kept.egress.bindings['sk-abcdefg']?.host, 'sk-abcdefg.example.com')
})

test('an egress binding: Bearer or Basic (x-access-token unless it names a user), header Authorization, pushes under aos/, profiles and repositories non-empty and unique, a repository on a host in one binding', () => {
  // Basic names its user; Bearer has none, and parse refuses one.
  const parsed = parse(
    withBindings({
      git: binding(),
      user: binding({ host: 'git.example.com', basicUser: 'aos-bot' }),
      api: binding({ host: 'api.github.com', scheme: 'Bearer', profiles: ['github-pulls'] }),
    }),
  ).egress.bindings
  assert.deepEqual(parsed['git'], {
    host: 'github.com',
    header: 'Authorization',
    scheme: 'Basic',
    basicUser: DEFAULT_BASIC_USER,
    envVar: 'AOS_GITHUB_TOKEN',
    profiles: ['git-fetch'],
    repos: ['op/fixture'],
    pushPrefix: 'aos/',
  })
  assert.equal(DEFAULT_BASIC_USER, 'x-access-token')
  assert.equal(parsed['user']?.scheme === 'Basic' ? parsed['user'].basicUser : undefined, 'aos-bot')
  assert.equal(parsed['api']?.scheme, 'Bearer')
  assert.equal(Object.hasOwn(parsed['api'] ?? {}, 'basicUser'), false)
  assert.match(
    invalid(() => parse(withBindings({ api: binding({ scheme: 'Bearer', basicUser: 'x-access-token' }) })), 'Bearer with a user'),
    /basicUser is the user of a Basic credential/,
  )
  for (const basicUser of ['', 'x:y', 'x y', '-x', 'x\n', 'é']) {
    invalid(() => parse(withBindings({ git: binding({ basicUser }) })), `basicUser ${JSON.stringify(basicUser)}`)
  }
  for (const scheme of ['none', 'bearer', 'Token', 'Digest', undefined]) {
    const message = invalid(() => parse(withBindings({ git: binding({ scheme }) })), `scheme ${String(scheme)}`)
    assert.match(message, /scheme is Bearer or Basic/, String(scheme))
  }

  // The header and the push prefix can only be what the kernel does.
  assert.equal(parse(withBindings({ git: binding({ header: 'Authorization', pushPrefix: 'aos/' }) })).egress.bindings['git']?.header, 'Authorization')
  for (const header of ['x-api-key', 'authorization', 'Proxy-Authorization', 'Cookie']) {
    assert.match(invalid(() => parse(withBindings({ git: binding({ header }) })), header), /header is Authorization/, header)
  }
  for (const pushPrefix of ['', 'main', 'aos', 'refs/heads/aos/', 'aos/../', 'bots/aos/']) {
    assert.match(invalid(() => parse(withBindings({ git: binding({ pushPrefix }) })), pushPrefix), /pushPrefix is aos\//, pushPrefix)
  }

  // Profiles are the three routes.ts serves, each once, at least one.
  for (const profiles of [[], ['git-fetch', 'git-fetch'], ['git-clone'], ['git-fetch', 'git-push', 'github-pulls', 'git-fetch'], 'git-fetch']) {
    invalid(() => parse(withBindings({ git: binding({ profiles }) })), `profiles ${JSON.stringify(profiles)}`)
  }
  assert.deepEqual(
    parse(withBindings({ git: binding({ profiles: ['git-fetch', 'git-push', 'github-pulls'] }) })).egress.bindings['git']?.profiles,
    ['git-fetch', 'git-push', 'github-pulls'],
  )
  // Repositories are owner/name, at least one, each once in any case, at most 64.
  for (const repos of [[], ['fixture'], ['op/fixture.git'], ['op/..'], ['op/a/b'], ['op/fixture', 'Op/Fixture'], Array.from({ length: 65 }, (_, i) => `op/r${String(i)}`)]) {
    invalid(() => parse(withBindings({ git: binding({ repos }) })), `repos ${JSON.stringify(repos).slice(0, 60)}`)
  }
  assert.equal(parse(withBindings({ git: binding({ repos: Array.from({ length: 64 }, (_, i) => `op/r${String(i)}`) }) })).egress.bindings['git']?.repos.length, 64)
  // One repository twice in one binding is that binding's one issue, at its
  // repos, never also a clash of the binding with itself.
  const doubled = issuesOf(invalid(() => parse(withBindings({ git: binding({ repos: ['op/fixture', 'Op/Fixture'] }) })), 'a repository twice in one binding'))
  assert.deepEqual(doubled, [
    { code: 'custom', path: ['egress', 'bindings', 'git', 'repos'], message: 'a binding lists a repository twice (owner/name is read without case)' },
  ])

  // A repository on a host is in one binding: a request to it would not say
  // whose credential it carries. The same repository on two hosts is two.
  const twice = invalid(
    () => parse(withBindings({ fetch: binding(), push: binding({ profiles: ['git-push'], repos: ['other/repo', 'OP/fixture'] }) })),
    'one repository bound twice on one host',
  )
  assert.match(twice, /op\/fixture on github\.com is already bound by binding fetch/)
  assert.match(twice, /"push",\s*"repos",\s*1/)
  assert.doesNotThrow(() => parse(withBindings({ git: binding(), api: binding({ host: 'api.github.com', scheme: 'Bearer', profiles: ['github-pulls'] }) })))

  // Binding ids are what decisions name: lower-case letters, digits and -.
  for (const id of ['GitHub', 'github_git', '1github', '-github', 'git hub', 'a'.repeat(64)]) {
    invalid(() => parse(withBindings({ [id]: binding() })), `id ${JSON.stringify(id)}`)
  }
  assert.doesNotThrow(() => parse(withBindings({ ['a'.repeat(63)]: binding() })))

  // The plan's acceptance names the prefix the push check holds.
  assert.equal(EGRESS_PUSH_PREFIX, pushBranchPrefix('r').slice(0, -'r/'.length))
})

test('egress.limits names exactly the limits a grant is revoked on, each a positive whole number, the three that size kernel memory bounded, idleMs a timer delay Node keeps; muxPort is 3128 alone', () => {
  // events/types.ts PROXY_LIMITS is what a proxy.grant.revoked {limit} row may
  // name, and E5 must use those names.
  assert.deepEqual(Object.keys(parse(withEgress()).egress.limits).sort(), [...PROXY_LIMITS].sort())
  for (const name of PROXY_LIMITS) {
    for (const value of [0, -1, 1.5, '16', null, Number.MAX_SAFE_INTEGER + 1]) {
      invalid(() => parse(withEgress({ limits: { [name]: value } })), `limits.${name}: ${String(value)}`)
    }
    assert.equal(parse(withEgress({ limits: { [name]: 1 } })).egress.limits[name], 1)
  }
  // What the kernel holds for one hostile container is bounded, at the bound and past it.
  for (const [name, max] of [['frameMaxBytes', 1_048_576], ['maxFlows', 256], ['maxHeaderBytes', 65_536]] as const) {
    assert.equal(parse(withEgress({ limits: { [name]: max } })).egress.limits[name], max)
    invalid(() => parse(withEgress({ limits: { [name]: max + 1 } })), `limits.${name}: ${String(max + 1)}`)
  }
  // The counters have no bound but a whole number's.
  assert.equal(parse(withEgress({ limits: { maxBytes: 8 * 1024 ** 3 } })).egress.limits.maxBytes, 8 * 1024 ** 3)
  // idleMs is a timer's delay: Node fires one past 2^31 - 1 ms after 1 ms, so
  // 30 days would revoke every grant as idle at once. At the bound and past it.
  assert.equal(MAX_TIMER_MS, 2 ** 31 - 1)
  assert.equal(parse(withEgress({ limits: { idleMs: MAX_TIMER_MS } })).egress.limits.idleMs, MAX_TIMER_MS)
  for (const idleMs of [MAX_TIMER_MS + 1, 2_592_000_000]) {
    assert.match(invalid(() => parse(withEgress({ limits: { idleMs } })), `idleMs ${String(idleMs)}`), /"idleMs"/)
  }

  // The mux port is the one the worker image bakes in and its mux binds: no
  // other, privileged or not.
  assert.equal(EGRESS_MUX_PORT, 3128)
  for (const muxPort of [0, 80, 443, 1023, 1024, 3129, 8080, 65_535, 65_536, -1, 3128.5, '3128', null]) {
    const message = invalid(() => parse(withEgress({ muxPort })), `muxPort ${String(muxPort)}`)
    assert.match(message, /egress\.muxPort is 3128: the port the worker image's HTTP\(S\)_PROXY names and its mux binds/, String(muxPort))
  }
  assert.equal(parse(withEgress({ muxPort: 3128 })).egress.muxPort, 3128)
  assert.equal(parse(withEgress({ enabled: true })).egress.enabled, true)
})

test('a key naming part of a JavaScript object is refused anywhere in kernel.yaml, naming its path: __proto__ as one the schema drops, constructor and prototype as a precaution', () => {
  const valid = readFileSync(new URL('valid.yaml', FIXTURES), 'utf8')
  const bound = (id: string): string =>
    `${valid}\negress:\n  bindings:\n    ${id}:\n      host: github.com\n      scheme: Basic\n      envVar: AOS_GITHUB_TOKEN\n      profiles: [git-fetch]\n      repos: [op/fixture]\n`
  // The parser makes `__proto__:` an own key, and zod's record drops it: the
  // binding would vanish with no error, and its .env line would then be
  // refused as a name the kernel does not read.
  const raw = parseYaml(bound('__proto__')) as { egress: { bindings: Record<string, unknown> } }
  assert.equal(Object.hasOwn(raw.egress.bindings, '__proto__'), true)
  assert.equal(Object.getPrototypeOf(raw.egress.bindings), Object.prototype)
  // What the refusals say holds of the schema without the walk: __proto__ is
  // dropped, while constructor and prototype are read as ordinary keys (a
  // record keeps them, a strict section reports them as unknown), so those
  // two are refused as a precaution, not because they would be lost.
  const schemaOnly = (id: string): Record<string, unknown> => {
    const result = KernelConfig.safeParse(parseYaml(bound(id)))
    assert.ok(result.success, id)
    return result.data.egress.bindings
  }
  assert.deepEqual(Object.keys(schemaOnly('__proto__')), [])
  for (const id of ['constructor', 'prototype']) {
    assert.equal(Object.hasOwn(schemaOnly(id), id), true, id)
    const strict = KernelConfig.safeParse(parseYaml(valid.replace('lanes:\n', `lanes:\n  ${id}: 2\n`)))
    assert.equal(strict.success, false, id)
    assert.match(strict.error?.message ?? '', new RegExp(`unrecognized_keys[\\s\\S]*"${id}"`), id)
  }
  const dropped = 'the schema drops a __proto__ entry with no error, so the setting would vanish from the parsed config'
  const precaution =
    'constructor and prototype name parts of a JavaScript object, and kernel.yaml refuses both as a precaution, though the schema would read either as an ordinary key'
  for (const [id, reason] of [['__proto__', dropped], ['constructor', precaution], ['prototype', precaution]] as const) {
    assert.throws(
      () => parse(parseYaml(bound(id))),
      (e: unknown) =>
        e instanceof Error &&
        e.message === `kernel.yaml key "${id}" at egress.bindings.${id} is not a name a setting can have: ${reason}. Rename it.`,
      id,
    )
  }
  // The precaution does not make a lookup by name safe: a parsed record is a
  // plain object, so code resolving an id from outside the file asks
  // Object.hasOwn (egress plan E6), never `in` or a bare index.
  const shipped = parse(parseYaml(valid)).egress.bindings
  assert.equal('constructor' in shipped, true)
  assert.equal(Object.hasOwn(shipped, 'constructor'), false)
  // Anywhere in the document: an MCP server's name, a key under a section, an
  // entry in a list.
  for (const [text, path] of [
    [valid.replace('mcp:\n  servers:\n', 'mcp:\n  servers:\n    __proto__:\n      url: http://127.0.0.1:9911/mcp\n'), 'mcp.servers.__proto__'],
    [valid.replace('lanes:\n', 'lanes:\n  constructor: 2\n'), 'lanes.constructor'],
    [`${valid}\nlist:\n  - prototype: 1\n`, 'list.0.prototype'],
  ] as const) {
    assert.throws(() => parse(parseYaml(text)), (e: unknown) => e instanceof Error && e.message.includes(`at ${path} is not a name a setting can have`), path)
  }
  // A name that merely contains one is a name like any other.
  assert.deepEqual(Object.keys(parse(parseYaml(bound('proto-mirror'))).egress.bindings), ['proto-mirror'])
})

test('bindingKeyProblem: a binding envVar that is a provider key is named, with the host it would be sent to; the shipped files have none', () => {
  // kernel.yaml's schema never sees providers.yaml, so a binding on
  // ANTHROPIC_API_KEY passes parse and credentialNames alike. Boot (W1)
  // refuses what this returns, before any binding is resolved.
  const providersRaw = parseYaml(readFileSync(join(REPO_ROOT, 'config', 'providers.yaml'), 'utf8')) as {
    entries: Record<string, { auth: Record<string, unknown> }>
  }
  const providers = parseProviders(providersRaw)
  const shipped = parse(parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')))
  assert.equal(bindingKeyProblem(shipped, providers), undefined)

  const anthropic = parse(withBindings({ github: binding({ envVar: 'ANTHROPIC_API_KEY' }), forge: binding({ host: 'git.example.com' }) }))
  assert.equal(anthropic.egress.bindings['github']?.envVar, 'ANTHROPIC_API_KEY')
  assert.equal(
    bindingKeyProblem(anthropic, providers),
    'an egress binding envVar names a credential of its own: egress.bindings.github.envVar ANTHROPIC_API_KEY is the key of ' +
      'provider anthropic/claude-sonnet-5 (auth.envVar in providers.yaml), and the binding would send it to github.com. ' +
      'Give the binding an AOS_ name of its own',
  )
  // A clean binding beside it is not named; one of its own is no problem.
  assert.equal(bindingKeyProblem(anthropic, providers)?.includes('forge'), false)
  assert.equal(bindingKeyProblem(parse(withBindings({ github: binding() })), providers), undefined)

  // Any provider's key, a placeholder's included, and every entry that shares it.
  for (const ref of ['openrouter/moonshotai/kimi-k3', 'moonshot/kimi-k3']) {
    const entry = providersRaw.entries[ref]
    assert.ok(entry, ref)
    entry.auth['envVar'] = 'AOS_MOONSHOT_KEY'
  }
  const shared = parse(withBindings({ api: binding({ host: 'api.github.com', scheme: 'Bearer', envVar: 'AOS_MOONSHOT_KEY', profiles: ['github-pulls'] }) }))
  assert.match(
    bindingKeyProblem(shared, parseProviders(providersRaw)) ?? '',
    /^an egress binding envVar names a credential of its own: egress\.bindings\.api\.envVar AOS_MOONSHOT_KEY is the key of provider openrouter\/moonshotai\/kimi-k3, moonshot\/kimi-k3 \(auth\.envVar in providers\.yaml\), and the binding would send it to api\.github\.com\./,
  )
  // Two bindings on provider keys: both named, in one message.
  const both = parse(withBindings({ github: binding({ envVar: 'ANTHROPIC_API_KEY' }), api: binding({ host: 'api.github.com', envVar: 'AOS_MOONSHOT_KEY' }) }))
  const message = bindingKeyProblem(both, parseProviders(providersRaw)) ?? ''
  assert.match(message, /egress\.bindings\.github\.envVar ANTHROPIC_API_KEY .*; egress\.bindings\.api\.envVar AOS_MOONSHOT_KEY /)
})

test('until the wiring task, nothing in src calls bindingKeyProblem, and kernel.yaml says a provider key is refused only once W1 lands', () => {
  // A comment telling the operator a provider-key binding "is refused at
  // boot" would be false today: it parses and boots, harmless only because
  // no request uses a binding before W1. W1 calls the check and rewrites
  // both halves of this test in the same commit.
  const sources = readdirSync(join(REPO_ROOT, 'src'), { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith('.ts'))
  const callers = sources.filter((f) => /\bbindingKeyProblem\s*\(/.test(readFileSync(join(REPO_ROOT, 'src', f), 'utf8').replace(/export function bindingKeyProblem\(/, '')))
  assert.deepEqual(callers, [])
  const yaml = readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')
  const comment = yaml.split('\n').filter((line) => /^\s*#/.test(line)).map((line) => line.replace(/^\s*#\s?/, '')).join(' ')
  assert.match(comment, /A provider's key will be refused at boot once the wiring task \(W1\) lands; until then no request uses a binding\./)
  assert.doesNotMatch(comment, /provider's key is refused at boot/)
})
