// T35 — hygiene meta-tests.
//
// Every other test asks whether a component behaves. These ask whether the
// SHAPE of the repository still holds, because a whole class of mistake passes
// every behavioural test:
//
//   A second ad-hoc `.replace('.', '__')` in the router or the hub would map
//   tool names correctly today and drift from names.ts the day either changes.
//   Invariant 10 says there is one mapping; nothing but a scan can say there is
//   still one.
//
//   A test that opens a writable EventStore of its own gets no chain
//   verification at teardown, so it can pass against a log it corrupted.
//
//   A second `as Transport` cast would be a second place the MCP SDK's types
//   are overridden, and CLAUDE.md sanctions exactly one.
//
//   A `NODE_ENV === 'test'` branch anywhere in src/ is a gate bypass whether or
//   not it was written as one.
//
// These are greps, and greps are crude. They are worth it because the thing
// being protected is an absence, and an absence has no behaviour to test.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')

interface SourceFile {
  /** Path relative to the repo root, e.g. `src/mcp/hub.ts`. */
  readonly path: string
  readonly text: string
  readonly lines: readonly string[]
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(join(REPO, dir))) {
    const rel = `${dir}/${entry}`
    if (statSync(join(REPO, rel)).isDirectory()) walk(rel, out)
    else if (rel.endsWith('.ts')) out.push(rel)
  }
  return out
}

function files(dir: string): SourceFile[] {
  return walk(dir).map((path) => {
    const text = readFileSync(join(REPO, path), 'utf8')
    return { path, text, lines: text.split('\n') }
  })
}

/**
 * This file is excluded from the pools it scans.
 *
 * Every rule below is spelled out as a pattern, so the scanner contains a
 * literal copy of each thing it forbids — `new DatabaseSync(`, `as Transport`,
 * `NODE_ENV`. Left in the pool it would violate nearly every rule it enforces.
 * Its own patterns are data, and the tripwire test above is what proves the
 * pools are not empty after this exclusion.
 */
const SELF = 'test/hygiene.test.ts'

const SRC = files('src')
const TEST = files('test').filter((f) => f.path !== SELF)
/** `test/*.test.ts` only — not the helpers, which have their own rules. */
const TEST_FILES = TEST.filter((f) => /^test\/[^/]+\.test\.ts$/.test(f.path))

/** Lines that are code rather than comment or blank. */
function codeLines(file: SourceFile): { n: number; text: string }[] {
  const out: { n: number; text: string }[] = []
  let inBlock = false
  file.lines.forEach((raw, i) => {
    const line = raw.trim()
    if (inBlock) {
      if (line.includes('*/')) inBlock = false
      return
    }
    if (line.startsWith('/*')) {
      if (!line.includes('*/')) inBlock = true
      return
    }
    if (line === '' || line.startsWith('//') || line.startsWith('*')) return
    out.push({ n: i + 1, text: raw })
  })
  return out
}

/** Files whose CODE (not prose) imports a module. */
function importersOf(pool: readonly SourceFile[], module: string): string[] {
  const pattern = new RegExp(
    `(?:^|\\s)(?:import|export)[^\\n]*from\\s+['"]${module.replace(/[/\\]/g, '\\$&')}['"]|require\\(\\s*['"]${module.replace(/[/\\]/g, '\\$&')}['"]`,
  )
  return pool.filter((f) => codeLines(f).some((l) => pattern.test(l.text))).map((f) => f.path)
}

/** Code lines in a pool matching a pattern, as `path:line  text`. */
function hits(pool: readonly SourceFile[], pattern: RegExp): string[] {
  const found: string[] = []
  for (const file of pool) {
    for (const line of codeLines(file)) {
      if (pattern.test(line.text)) found.push(`${file.path}:${String(line.n)}  ${line.text.trim()}`)
    }
  }
  return found
}

/** The file part of a `path:line  text` hit. */
function pathsOf(found: readonly string[]): string[] {
  return [...new Set(found.map((h) => h.split(':')[0] ?? h))].sort()
}

test('the scanner sees the repository it thinks it does', () => {
  // A grep that matches nothing passes every rule below. This is the tripwire:
  // if the walk is pointed at an empty directory, or codeLines() strips
  // everything, every other test in this file becomes vacuous and silent.
  assert.ok(SRC.length > 30, `only found ${String(SRC.length)} source files`)
  assert.ok(TEST_FILES.length > 30, `only found ${String(TEST_FILES.length)} test files`)
  assert.ok(SRC.some((f) => f.path === 'src/mcp/names.ts'))
  assert.ok(SRC.some((f) => f.path === 'src/kernel.ts'))
  assert.ok(TEST_FILES.some((f) => f.path === 'test/live-anthropic.test.ts'))

  // codeLines must keep code and drop comments, or the bypass scans below
  // would be satisfied by a keyword sitting in a sentence.
  const probe: SourceFile = {
    path: 'probe.ts',
    text: '',
    lines: ['// NODE_ENV mentioned in prose', '/* block', 'NODE_ENV in a block */', "const x = 'NODE_ENV'"],
  }
  assert.deepEqual(
    codeLines(probe).map((l) => l.text),
    ["const x = 'NODE_ENV'"],
  )
})

test('every test file imports helpers/guard.js first', () => {
  // The offline guarantee rests on the tripwire being installed before anything
  // else in the file can open a socket. "First import" is the only position
  // that guarantees it: a module imported earlier runs earlier.
  for (const file of TEST_FILES) {
    const firstImport = codeLines(file).find((l) => /^\s*(import|export)\b/.test(l.text))
    assert.ok(firstImport, `${file.path} has no imports at all`)
    // Either form: a bare side-effect import, or a named one that also installs
    // the tripwire by loading the module.
    assert.match(
      firstImport.text,
      /(?:from\s+)?['"]\.\/helpers\/guard\.js['"]/,
      `${file.path} imports ${firstImport.text.trim()} before the network guard`,
    )
  }
  // And the helpers do the same, so a helper cannot be the hole.
  for (const file of TEST.filter((f) => f.path.startsWith('test/helpers/') && f.path !== 'test/helpers/guard.ts')) {
    assert.match(
      file.text,
      /(?:from\s+)?['"]\.\/guard\.js['"]/,
      `${file.path} does not import the guard`,
    )
  }
})

test('no test opens a writable EventStore outside test/helpers', () => {
  // A store opened through withStore/withKernel has its chain verified at
  // teardown. One a test opens itself does not, so it can pass against a log it
  // corrupted — which is the one thing the event log's tests must never be able
  // to do.
  //
  // Read-only opens are unrestricted: they cannot damage a chain, and the
  // daemon-less CLI commands and the kernel harness need them to read a log back.
  const constructions = hits(TEST, /new EventStore\(/)
  for (const hit of constructions) {
    const [path, rest] = [hit.split(':')[0] ?? '', hit]
    if (path.startsWith('test/helpers/')) continue
    if (/readOnly:\s*true/.test(rest)) continue
    // store.test.ts asserts the constructor REFUSES certain databases, so the
    // construction there is the thing under test and never yields a store.
    assert.equal(
      path,
      'test/store.test.ts',
      `${hit}\nopen it through withStore/withKernel, or pass { readOnly: true }`,
    )
    assert.match(rest, /\(\)\s*=>\s*new EventStore/, `${hit}\na writable store outside a throws-assertion`)
  }

  // bootKernel opens its own store, so any test calling it directly must also
  // verify that log. withKernel does it for you; kernel-boot.test.ts controls
  // boot itself (refusals, crash simulation) and calls verifyAt explicitly.
  const booters = pathsOf(hits(TEST, /\bbootKernel\(/)).filter((p) => !p.startsWith('test/helpers/'))
  for (const path of booters) {
    const file = TEST.find((f) => f.path === path)
    assert.ok(file)
    assert.match(
      file.text,
      /\bverifyAt\(|expectBootRefusal\(/,
      `${path} calls bootKernel but never verifies the log it wrote`,
    )
  }
  assert.deepEqual(booters, ['test/kernel-boot.test.ts'])
})

test('new DatabaseSync( appears only in src/events/db.ts and test/env.test.ts', () => {
  // One place opens a database in the product: db.ts, which sets the per-open
  // pragmas every reader and writer depends on. A second construction would be
  // a connection with no WAL, no busy timeout and no recursive triggers, and
  // nothing about it would look wrong.
  //
  // env.test.ts is the exception and not an oversight: it proves node:sqlite's
  // own behaviour (RAISE(ABORT) surfacing as SQLITE_CONSTRAINT_TRIGGER, the
  // timeout option) and must therefore reach the driver without db.ts in the way.
  const constructions = hits([...SRC, ...TEST], /new DatabaseSync\(/)
  assert.deepEqual(pathsOf(constructions), ['src/events/db.ts', 'test/env.test.ts'])

  // The file set alone is not enough: a second construction INSIDE db.ts would
  // skip openDb's pragma setup while sitting in the whitelisted file. What
  // prevents that is the module's public surface — openDb is the only export
  // that yields a handle, so an unconfigured one cannot leave the module without
  // changing a list a human reads.
  //
  // db.ts constructs three times, all legitimately: the capability probe that
  // decides whether this build accepts a `timeout` option, and openDb's two
  // branches for builds that do and do not.
  const db = SRC.find((f) => f.path === 'src/events/db.ts')
  assert.ok(db)
  const exported = db.lines
    .filter((l) => /^export /.test(l))
    .map((l) => /^export (?:async )?(?:function|const|class|interface|type) (\w+)/.exec(l)?.[1])
    .filter((name): name is string => name !== undefined)
  assert.deepEqual(exported.sort(), ['Db', 'OpenOptions', 'Row', 'openDb', 'supportsTimeoutOption'])
  // supportsTimeoutOption returns a boolean, not a database. openDb is the only
  // door, and it is the one that sets journal_mode, synchronous and the
  // busy timeout.
  assert.match(db.text, /export function supportsTimeoutOption\(\): boolean/)
  assert.match(db.text, /export function openDb\([^)]*\): Db/)
})

test("the '__' provider-tool-name mapping exists only in src/mcp/names.ts", () => {
  // Invariant 10: `toolName`/`toolRef` are the only mapping. A second ad-hoc
  // conversion would agree with names.ts today and drift the day either side
  // changes — and every behavioural test would still pass, because both would be
  // producing the same string right now.
  const mapping = hits(SRC, /(?:replace|replaceAll|split)\(\s*['"](?:\.|__)['"]|['"]__['"]/)
  assert.deepEqual(pathsOf(mapping), ['src/mcp/names.ts'], mapping.join('\n'))

  // Regex-based dot mapping is the same mistake spelled differently.
  const viaRegex = hits(SRC, /(?:replace|replaceAll)\(\s*\/\\?\.\//)
  assert.deepEqual(pathsOf(viaRegex).filter((p) => p !== 'src/mcp/names.ts'), [], viaRegex.join('\n'))
})

test("'as Transport' appears only in src/mcp/hub.ts", () => {
  // CLAUDE.md sanctions exactly one cast at the MCP Transport seam, and names
  // the file. A second one is a second place the SDK's types are overridden,
  // which is the seam widening rather than being crossed.
  assert.deepEqual(pathsOf(hits(SRC, /\bas Transport\b/)), ['src/mcp/hub.ts'])
  // And it stays a single occurrence, not a file with several.
  assert.equal(hits(SRC, /\bas Transport\b/).length, 1)
})

test('node:child_process is imported only by src/sandbox/docker.ts, test/env.test.ts and test/entrypoints.test.ts', () => {
  // The only module that may spawn a process is the one that knows what a
  // docker invocation must look like — the argv audit, the two-key environment,
  // the wallclock kill. A second importer is a second way to run something, and
  // it would not have any of that.
  //
  // Matched as an IMPORT rather than a mention, so a comment explaining the rule
  // does not violate it.
  //
  // Two test files are whitelisted, each for a reason that cannot be met another
  // way. env.test.ts proves Node's own behaviour (it spawns a node to check a
  // flag). entrypoints.test.ts runs the CLI and the daemon AS PROGRAMS, which is
  // the only way to catch a file that is not wired as one — and one was not:
  // src/cli/index.ts exported runCli and nothing called it.
  assert.deepEqual(importersOf([...SRC, ...TEST], 'node:child_process'), [
    'src/sandbox/docker.ts',
    'test/entrypoints.test.ts',
    'test/env.test.ts',
  ])
  // The composer asks for a driver and does not wire processes itself.
  assert.equal(importersOf(SRC, 'node:child_process').includes('src/kernel.ts'), false)
})

test('src/ never imports test/', () => {
  // A product that imports its own test doubles ships them. The direction is
  // one-way by construction, and nothing but a scan says it still is.
  const leaks = hits(SRC, /from\s+['"][^'"]*\/test\/|from\s+['"]\.\.?\/(?:\.\.\/)*test\//)
  assert.deepEqual(leaks, [])
  for (const file of SRC) {
    assert.equal(/helpers\/(guard|store|kernel|mock-mcp|fake-)/.test(file.text), false, file.path)
  }
})

test('dependency direction: src/runtime, src/models, src/mcp, src/agents, src/policy never import mintHumanActor or src/secrets internals; only src/control/server.ts imports mintHumanActor', () => {
  // mintHumanActor is the only way to make an actor the approvals path accepts.
  // It belongs to the one module that can know a human is on the other end of a
  // socket. Anywhere else it is a forgery kit: a subsystem that can mint one can
  // approve its own irreversible tool call (invariants 3 and 6).
  assert.deepEqual(pathsOf(hits(SRC, /\bmintHumanActor\b/)), [
    'src/control/actor.ts',
    'src/control/server.ts',
  ])

  // The lower layers take an actor as an argument and never manufacture one.
  const LOWER = ['src/runtime/', 'src/models/', 'src/mcp/', 'src/agents/', 'src/policy/']
  for (const file of SRC.filter((f) => LOWER.some((d) => f.path.startsWith(d)))) {
    assert.equal(/\bmintHumanActor\b/.test(file.text), false, `${file.path} can mint a human actor`)
    // The broker is kernel-only (invariant 2). A lower layer reaching into it
    // would be a subsystem able to resolve a credential for itself.
    assert.equal(
      /from '[^']*secrets\//.test(file.text),
      false,
      `${file.path} imports the secrets broker`,
    )
  }
  // Exactly one composer wires the broker in.
  assert.deepEqual(importersOf(SRC, './secrets/broker.js'), ['src/kernel.ts'])
})

test('no source file contains a gate bypass keyword', () => {
  // CLAUDE.md: never add a bypass of the gate "for testing". A NODE_ENV branch
  // is one whether or not it was written as one — it makes the policy decision
  // depend on how the process was started, which is not a thing the gate is
  // allowed to consider.
  const bypass = hits(SRC, /bypassGate|skipGate|AOS_SKIP_POLICY|NODE_ENV|AOS_UNSAFE|allowAll|disableGate/i)
  assert.deepEqual(bypass, [], bypass.join('\n'))

  // The gate's own decision must not read the environment at all.
  for (const path of ['src/policy/engine.ts', 'src/policy/gate.ts']) {
    const file = SRC.find((f) => f.path === path)
    if (file === undefined) continue
    assert.equal(/process\.env/.test(file.text), false, `${path} reads the environment`)
  }
})

test('no test is skipped or todo except test/live-*.test.ts', () => {
  // D29 admits exactly one gated file, whitelisted by NAME. Any other skip is a
  // test that stopped running while still reporting a line that reads like a
  // pass, which is worse than a deleted test because it looks like coverage.
  const skips = hits(TEST, /\bskip\s*:|\btodo\s*:|\.skip\(|\.todo\(|{\s*skip\s*}/)
  const offenders = pathsOf(skips).filter((p) => !/^test\/live-[^/]*\.test\.ts$/.test(p))
  assert.deepEqual(offenders, [], skips.join('\n'))

  // And the one gated file reads its gate from the environment, so it cannot be
  // switched on by an edit that looks like a constant.
  const live = TEST.find((f) => f.path === 'test/live-anthropic.test.ts')
  assert.ok(live)
  assert.match(
    live.text,
    /const LIVE = process\.env\['AOS_LIVE_TESTS'\] === '1'/,
    'the live gate is no longer read from AOS_LIVE_TESTS',
  )
  // Every skip states a reason: "skipped" with no reason is indistinguishable
  // from "passed" in a scroll-back. The reason may sit on the lines below the
  // `skip:` key, so the whole expression is read rather than the one line.
  const skipLines = live.lines
    .map((text, i) => ({ n: i, text }))
    .filter((l) => /\bskip\s*:/.test(l.text))
  assert.ok(skipLines.length >= 2, `found ${String(skipLines.length)} skips in the live file`)
  for (const line of skipLines) {
    const window = live.lines.slice(line.n, line.n + 8).join('\n')
    const reasons = [...window.matchAll(/'([^']{12,})'/g)].map((m) => m[1] ?? '')
    assert.ok(
      reasons.length > 0,
      `test/live-anthropic.test.ts:${String(line.n + 1)} skips with no stated reason`,
    )
    // And the reason says what to DO, not merely that something is absent.
    assert.ok(
      reasons.some((r) => /AOS_LIVE_TESTS|ANTHROPIC_API_KEY|PMMCP_/.test(r)),
      `test/live-anthropic.test.ts:${String(line.n + 1)} does not name what is missing`,
    )
  }
})

test('no source file writes to souls/ or AGENTS.md', () => {
  // Invariant 8: souls and AGENTS.md are read-only to agents, and the guarantee
  // is that NO code path writes them — not that the gate refuses, which would
  // put a model's persona one bug away from being editable by the model.
  const WRITE = /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|rmSync|unlinkSync|renameSync|mkdirSync|chmodSync|copyFileSync|truncateSync)\s*\(/

  // Only three modules in src/ write to the filesystem at all, and each writes
  // under the data directory. A fourth is a new writer and must be looked at.
  assert.deepEqual(pathsOf(hits(SRC, WRITE)), [
    'src/events/anchor.ts',
    'src/kernel.ts',
    'src/models/probe.ts',
  ])

  // No write call site anywhere mentions a protected path.
  const suspicious = hits(SRC, WRITE).filter((h) => /soul|AGENTS|agent\.yaml/i.test(h))
  assert.deepEqual(suspicious, [], suspicious.join('\n'))

  // The soul loader has no writer at all, which is the absence souls.ts claims
  // in its own header.
  const souls = SRC.find((f) => f.path === 'src/agents/souls.ts')
  assert.ok(souls)
  assert.equal(WRITE.test(souls.text), false, 'src/agents/souls.ts can write')
  assert.match(souls.text, /import \{ readFileSync \} from 'node:fs'/)
})
