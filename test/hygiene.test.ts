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
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, posix, relative } from 'node:path'
import ts from 'typescript'

import { ENTRY_POINTS } from './helpers/checkout.js'
import { tmpdir } from './helpers/tmpdir.js'

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

test('node:child_process is imported only by src/sandbox/docker.ts and four test files that need real processes', () => {
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
  // src/cli/index.ts exported runCli and nothing called it. falsify.test.ts
  // proves the mutation runner's safety properties, and each one is about a
  // real process: a hung test's whole process GROUP is killed, a runner that is
  // SIGKILLed mid-mutant is recovered from its journal, and the script refuses
  // bad input as a program. gitignore.test.ts holds src/gitignore.ts to git's
  // own `check-ignore`, the only authority on what a .gitignore means, and asks
  // git's index whether a .env was force-added. helpers/checkout.ts holds
  // runEntry/spawnEntry, the one way a test runs an entry point, so that the
  // cwd of every such run is the shadow copy's, set in one place.
  assert.deepEqual(importersOf([...SRC, ...TEST], 'node:child_process'), [
    'src/sandbox/docker.ts',
    'test/entrypoints.test.ts',
    'test/env.test.ts',
    'test/falsify.test.ts',
    'test/gitignore.test.ts',
    'test/helpers/checkout.ts',
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

  // And EVERY gated file reads its gate from the environment, so none can be
  // switched on by an edit that looks like a constant. This once checked only
  // live-anthropic.test.ts by name, which meant the rule admitting `live-*` files
  // by pattern and the rule checking their gate had quietly diverged: a second
  // live file would have been admitted to skip and never checked.
  const liveFiles = TEST.filter((f) => /^test\/live-[^/]*\.test\.ts$/.test(f.path))
  assert.deepEqual(
    liveFiles.map((f) => f.path).sort(),
    ['test/live-anthropic.test.ts', 'test/live-runtime.test.ts'],
    'the set of gated live files changed; add the new one here deliberately',
  )
  for (const live of liveFiles) {
    assert.match(
      live.text,
      /const LIVE = process\.env\['AOS_LIVE_TESTS'\] === '1'/,
      `${live.path} does not read its gate from AOS_LIVE_TESTS`,
    )
    // A second gate, where one exists, obeys the same rule.
    if (live.text.includes('AOS_LIVE_PMMCP_WRITES')) {
      assert.match(
        live.text,
        /const WRITES = process\.env\['AOS_LIVE_PMMCP_WRITES'\] === '1'/,
        `${live.path} does not read its pmmcp-writes gate from the environment`,
      )
    }
  }
  // Every skip states a reason: "skipped" with no reason is indistinguishable
  // from "passed" in a scroll-back. The reason may sit on the lines below the
  // `skip:` key, so the whole expression is read rather than the one line. Checked
  // in EVERY live file, for the same reason the gate is.
  for (const live of liveFiles) {
    const skipLines = live.lines
      .map((text, i) => ({ n: i, text }))
      .filter((l) => /\bskip\s*:/.test(l.text))
    assert.ok(skipLines.length >= 2, `found ${String(skipLines.length)} skips in ${live.path}`)
    for (const line of skipLines) {
      // The skip EXPRESSION, not a fixed window: from `skip:` to the line that
      // closes it with `false`. A fixed window let one reasonless branch hide
      // behind its neighbours' reasons — a falsifier replaced one branch of a
      // ternary chain with bare `true` and nothing noticed.
      const end = live.lines.findIndex((l, i) => i >= line.n && /\bfalse\b/.test(l))
      const window = live.lines.slice(line.n, end === -1 ? line.n + 1 : end + 1).join('\n')
      assert.doesNotMatch(
        window,
        /[?:]\s*true\b/,
        `${live.path}:${String(line.n + 1)} has a skip branch of bare \`true\` — a skip with no reason`,
      )
      const reasons = [...window.matchAll(/'([^']{12,})'/g)].map((m) => m[1] ?? '')
      assert.ok(reasons.length > 0, `${live.path}:${String(line.n + 1)} skips with no stated reason`)
      // And the reason says what to DO, not merely that something is absent.
      assert.ok(
        reasons.some((r) => /AOS_LIVE_TESTS|AOS_LIVE_PMMCP_WRITES|ANTHROPIC_API_KEY|PMMCP_/.test(r)),
        `${live.path}:${String(line.n + 1)} does not name what is missing`,
      )
    }
  }
})

test('no source file writes to souls/ or AGENTS.md', () => {
  // Invariant 8: souls and AGENTS.md are read-only to agents, and the guarantee
  // is that NO code path writes them — not that the gate refuses, which would
  // put a model's persona one bug away from being editable by the model.
  const WRITE = /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|writeSync|rmSync|unlinkSync|renameSync|mkdirSync|chmodSync|fchmodSync|copyFileSync|truncateSync)\s*\(/

  // Only four modules in src/ write to the filesystem at all. Three write
  // under the data directory; the fourth is the .env writer, which writes
  // <repo>/.env and nothing else (its own rules below). A fifth is a new writer
  // and must be looked at.
  assert.deepEqual(pathsOf(hits(SRC, WRITE)), [
    'src/events/anchor.ts',
    'src/kernel.ts',
    'src/models/probe.ts',
    'src/secrets/dotenv-append.ts',
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

const SCRIPTS = files('scripts')

/**
 * The repository modules a file imports by relative specifier, resolved to
 * their .ts paths: `./dotenv.js` in src/secrets/x.ts is src/secrets/dotenv.ts,
 * as surely as `../secrets/dotenv.js` elsewhere is. Static imports, re-exports
 * and import() alike, read from the syntax tree, so a comment is not one.
 */
function relativeImports(file: SourceFile): string[] {
  const out: string[] = []
  const add = (spec: string): void => {
    if (spec.startsWith('.')) out.push(posix.normalize(posix.join(posix.dirname(file.path), spec)).replace(/\.js$/, '.ts'))
  }
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier)) {
      add(node.moduleSpecifier.text)
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const spec = node.arguments[0]
      if (spec !== undefined && ts.isStringLiteralLike(spec)) add(spec.text)
    }
    ts.forEachChild(node, visit)
  }
  visit(parsed(file))
  return out
}

/** The files in `pool` that import `target` (a repo-relative .ts path) directly. */
function importersOfModule(pool: readonly SourceFile[], target: string): string[] {
  return pool.filter((f) => relativeImports(f).includes(target)).map((f) => f.path).sort()
}

test('only the entry points, the .env writer, the live helper and three tests import secrets/dotenv.js; kernel.ts, config.ts and the broker never do', () => {
  // The operator's .env is opened from exactly three entry points, by flag. A
  // library module that imported the loader would be a fourth door with no
  // argv to say whether it should open anything. The writer imports it for its
  // grammar and to read back what it wrote, and is held to its own callers
  // below. Resolved, not matched as text: the writer's `./dotenv.js` names no
  // `secrets/` directory, so a text match on `secrets/dotenv.js` misses it.
  assert.deepEqual(importersOfModule([...SRC, ...TEST, ...SCRIPTS], 'src/secrets/dotenv.ts'), [
    'scripts/eval.ts',
    'src/cli/index.ts',
    'src/main.ts',
    'src/secrets/dotenv-append.ts',
    'test/config-files.test.ts',
    'test/dotenv-append.test.ts',
    'test/dotenv.test.ts',
    'test/helpers/live-env.ts',
  ])
})

test('the kernel never imports src/install: only src/install itself, the installer (scripts/install.ts, scripts/install/*) and its tests do', () => {
  // src/install holds the installer's planner and its confirmation gate:
  // what may change in pmmcp and .env, and what the operator must type
  // before anything live does. The kernel, the daemon, the CLI and eval have
  // no install to plan, and one that reached the gate could be made to walk
  // it. Resolved imports (static, re-exports and import()), by path, and
  // followed: nothing the kernel's entry points import reaches src/install
  // either, however deep.
  const INSTALL = /^src\/install\//
  const importers = [...SRC, ...TEST, ...SCRIPTS].filter((f) => relativeImports(f).some((p) => INSTALL.test(p))).map((f) => f.path).sort()
  assert.ok(importers.includes('scripts/install/discover.ts') && importers.includes('test/install-plan.test.ts'), `the scan sees no importer of src/install: ${importers.join(', ')}`)
  for (const path of importers) {
    assert.match(path, /^(?:src\/install\/[^/]+\.ts|scripts\/install\.ts|scripts\/install\/[^/]+\.ts|test\/install-[\w-]+\.test\.ts)$/, `${path} imports src/install`)
  }
  for (const root of ['src/kernel.ts', 'src/main.ts', 'src/cli/index.ts', 'scripts/eval.ts']) {
    const reached = [...reachedFrom([root], [...SRC, ...SCRIPTS])]
    assert.ok(reached.length > 1, `the import walk from ${root} reaches nothing`)
    assert.deepEqual(reached.filter((p) => INSTALL.test(p)), [], `${root} reaches src/install`)
  }
})

/** Every TypeScript or JavaScript file under `root`/`dir`, whatever its extension: .ts, .mts, .cts, .tsx, .js, .mjs, .cjs, .jsx. */
function scriptSources(root: string, dir: string, out: SourceFile[] = []): SourceFile[] {
  for (const entry of readdirSync(join(root, dir))) {
    const rel = `${dir}/${entry}`
    if (statSync(join(root, rel)).isDirectory()) scriptSources(root, rel, out)
    else if (/\.(?:[cm]?[jt]s|[jt]sx)$/.test(rel)) {
      const text = readFileSync(join(root, rel), 'utf8')
      out.push({ path: rel, text, lines: text.split('\n') })
    }
  }
  return out
}

test('in scripts/, node:child_process is imported only by scripts/falsify.ts, scripts/falsify/runner.ts and scripts/install/run.ts', (t) => {
  // The installer runs pmmcp's stop and start scripts, git and docker, and
  // scripts/install/run.ts is where the rules for that live: an allowlisted
  // environment with no DOCKER_*, PMMCP_*, AOS_* or credential name, stdin
  // that carries a digest or nothing, output to two 0600 files, and the stop
  // and start scripts detached, never timed out or signalled. A second
  // importer would be a way to run something with none of that. The mutation
  // runner and its entry point spawn the test processes they judge. Read
  // from the syntax tree of every TypeScript and JavaScript file under
  // scripts/ (.mjs, .cjs and .js included, which node runs as readily), so a
  // comment is not an import. Any string in code that names the module (or
  // the spawn bindings beneath it) counts, however it reaches a loader:
  // import declarations and re-exports, import(), require(), `import x =
  // require()`, createRequire(import.meta.url)(...), process.getBuiltinModule
  // and a name held in a variable first.
  const SPAWNS = /child_process|spawn_sync|process_wrap/
  const imports = (file: SourceFile): boolean => {
    const kind = /\.[cm]?js$/.test(file.path) ? ts.ScriptKind.JS : /\.jsx$/.test(file.path) ? ts.ScriptKind.JSX : /\.tsx$/.test(file.path) ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    const source = ts.createSourceFile(file.path, file.text, ts.ScriptTarget.Latest, true, kind)
    let found = false
    const visit = (node: ts.Node): void => {
      if (found) return
      if (ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
        found = SPAWNS.test(node.text)
      }
      if (!found) ts.forEachChild(node, visit)
    }
    visit(source)
    return found
  }
  assert.deepEqual(scriptSources(REPO, 'scripts').filter(imports).map((f) => f.path).sort(), ['scripts/falsify.ts', 'scripts/falsify/runner.ts', 'scripts/install/run.ts'])
  // The scan sees every form: each of these is an import of the module.
  for (const text of [
    "import { spawn } from 'child_process'",
    "export { spawn } from 'node:child_process'",
    "const cp = await import('node:child_process')",
    "const cp = require('child_process')",
    "import cp = require('node:child_process')",
    "import { createRequire } from 'node:module'\nconst cp = createRequire(import.meta.url)('node:child_process')",
    "import { createRequire } from 'node:module'\nconst req = createRequire(import.meta.url)\nconst cp = req('child_process')",
    "const cp = process.getBuiltinModule('node:child_process')",
    "const name = 'node:child_process'\nconst cp = await import(name)",
    'const cp = await import(`node:${"child_process"}`)',
    "const sync = process.binding('spawn_sync')",
  ]) {
    assert.equal(imports({ path: 'scripts/x.ts', text, lines: text.split('\n') }), true, text)
    assert.equal(imports({ path: 'scripts/x.mjs', text: text.replace(/^import cp = require/, 'const cp = require'), lines: [] }), true, text)
  }
  assert.equal(imports({ path: 'scripts/x.ts', text: "// import { spawn } from 'node:child_process'\n/* require('child_process') */\nconst s = 1", lines: [] }), false)
  // And it walks every extension node runs, not only .ts.
  const root = tmpdir(t)
  mkdirSync(join(root, 'scripts', 'deep'), { recursive: true })
  for (const name of ['a.ts', 'b.mjs', 'c.cjs', 'd.js', 'deep/e.mts', 'deep/f.cts', 'g.sh', 'h.json']) {
    writeFileSync(join(root, 'scripts', name), "import 'node:child_process'\n")
  }
  assert.deepEqual(
    scriptSources(root, 'scripts').filter(imports).map((f) => f.path).sort(),
    ['scripts/a.ts', 'scripts/b.mjs', 'scripts/c.cjs', 'scripts/d.js', 'scripts/deep/e.mts', 'scripts/deep/f.cts'],
  )
})

/** Files reached from `roots` through relative imports, `roots` included. */
function reachedFrom(roots: readonly string[], pool: readonly SourceFile[]): Set<string> {
  const byPath = new Map(pool.map((f) => [f.path, f]))
  const seen = new Set<string>()
  const stack = [...roots]
  for (let path = stack.pop(); path !== undefined; path = stack.pop()) {
    if (seen.has(path)) continue
    seen.add(path)
    const file = byPath.get(path)
    if (file !== undefined) stack.push(...relativeImports(file))
  }
  return seen
}

// ── The .env write scan ─────────────────────────────────────────────────────
//
// CLAUDE.md allows exactly one writer of <repo>/.env. The scan below reads
// src/ and scripts/ with the compiler and follows each write's path as far as
// natural code takes it: through consts and lets, parameters and the calls
// that bind them, a helper's return, object literals and the properties
// written to them, path.join/resolve, template text, imports by name,
// default and namespace (re-exports and `export *` included), and fs
// functions under any name (renamed, aliased, destructured from the module or
// from import(), called through .call/.apply or handed on as values). Where
// it cannot follow a path in a file that speaks of .env, the write counts.
//
// It is a tripwire for natural code, not a proof against code written to
// evade it: whoever wants a second writer can write one this cannot see. It
// deliberately does not follow, and a reviewer reads these by eye:
//   - .call/.apply through one of the pool's own functions (only fs's);
//   - a pool function handed on as a value (`[path].forEach(drop)`), where
//     only fs's own functions count as written-through values;
//   - a class's static property (`Paths.env`) in a paths module: an
//     importer that writes it is not taken to speak of .env;
//   - a helper reached through import() of a pool module;
//   - a write two modules away: a helper whose path parameter is written by
//     another helper in a third module;
//   - a nested destructuring pattern (`const { promises: { writeFile } } = fs`);
//   - an object or instance a `let` holds (`let io = new Io()`), and a
//     method a class inherits (`new Sub().put`, where Sub extends Io);
//   - a method's callers in its own module other than its siblings'
//     `this.m(…)`: a write through its parameter there is unseen; and a
//     `this.m(…)` in an object literal's arrow property, whose `this` is
//     the enclosing one, not the object's.
// What it does follow across modules: functions, and methods of an object
// literal or class a module exports (by name, as its default, or through a
// namespace import: `m.io.put`, `new m.Io().put`), whose parameter a write in
// their own module takes as its path, directly or through a sibling called on
// `this` (`this.raw(f, t)`), that sibling a method or a property holding a
// function (`raw = (f, t) => …`, `raw: function (f, t) {…}`), called from a
// method, an accessor, a class's constructor or field, or an object
// literal's function property (`put: function (f, t) {…}`); an object
// literal's property that names such a function (`{ put }`, `{ put: put }`),
// on the write side and the paths side alike; and a function under a second
// name (`const save = put`).

/** Where each fs call takes a path it writes, creates, moves or deletes. */
const PATH_ARGS: ReadonlyMap<string, readonly number[]> = new Map<string, readonly number[]>([
  ...['writeFileSync', 'writeFile', 'appendFileSync', 'appendFile', 'createWriteStream', 'truncateSync', 'truncate'].map((c): [string, number[]] => [c, [0]]),
  // `new fs.WriteStream(path)` creates or truncates it, as createWriteStream does.
  ['WriteStream', [0]],
  ...['rmSync', 'rm', 'unlinkSync', 'unlink', 'chmodSync', 'chmod', 'chownSync', 'chown', 'utimesSync', 'utimes'].map((c): [string, number[]] => [c, [0]]),
  // macOS changes a link's own mode, owner and times through these.
  ...['lchmodSync', 'lchmod', 'lchownSync', 'lchown', 'lutimesSync', 'lutimes'].map((c): [string, number[]] => [c, [0]]),
  // Through a descriptor, which is the file it opened (callTails): fchmod
  // works through one opened read-only, so the open alone does not show it.
  ...['fchmodSync', 'fchmod', 'fchownSync', 'fchown', 'futimesSync', 'futimes'].map((c): [string, number[]] => [c, [0]]),
  // Both ends. From .env, a copy puts its keys in a second file, a link gives
  // it a second name and a move takes it away; to .env, each one writes it.
  ...['copyFileSync', 'copyFile', 'cpSync', 'cp', 'linkSync', 'link', 'symlinkSync', 'symlink', 'renameSync', 'rename'].map(
    (c): [string, number[]] => [c, [0, 1]],
  ),
  // Only when its flags can write: see opensReadOnly.
  ...['openSync', 'open'].map((c): [string, number[]] => [c, [0]]),
])

/** A FileHandle's own metadata writes: the file is the handle, which works opened read-only. */
const HANDLE_WRITES = new Set(['chmod', 'chown', 'utimes'])

/** Calls that read the bytes of the file their first argument names. */
const READ_CALLS = new Set(['readFileSync', 'readFile', 'createReadStream', 'openSync', 'open'])

/** The loader's calls, which read .env's values whatever path they are given: in the installer, a read of .env. */
const LOADER_READS = new Set(['loadDotenv', 'oneCredential'])
const INSTALLER = /^scripts\/install(?:\.ts$|\/)/

/** Names an open() flags expression may be built from and still only read. */
const READ_ONLY_FLAGS = new Set(['constants', 'fs', 'O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY', 'O_NOATIME', 'O_NOCTTY'])

/** No flags, 'r', or read-only constants or'd together. Anything else, a variable included, might write. */
function opensReadOnly(flags: ts.Expression | undefined): boolean {
  if (flags === undefined) return true
  if (ts.isStringLiteralLike(flags)) return /^(?:r|rs|sr)$/.test(flags.text)
  let readOnly = true
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node)) {
      if (!READ_ONLY_FLAGS.has(node.text)) readOnly = false
    } else if (!ts.isPropertyAccessExpression(node) && !ts.isParenthesizedExpression(node) && node.kind !== ts.SyntaxKind.BarToken) {
      if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.BarToken) readOnly = false
    }
    ts.forEachChild(node, visit)
  }
  visit(flags)
  return readOnly
}

const DECLARATIONS = new WeakMap<ts.Identifier, ts.Node | null>()

/** The declaration an identifier names, by lexical scope within its file: a const or let, a parameter, a function. */
function declarationOf(id: ts.Identifier): ts.Node | undefined {
  const seen = DECLARATIONS.get(id)
  if (seen !== undefined) return seen ?? undefined
  const found = lexicalDeclaration(id)
  DECLARATIONS.set(id, found ?? null)
  return found
}

function lexicalDeclaration(id: ts.Identifier): ts.Node | undefined {
  const named = (n: ts.BindingName | undefined): boolean => n !== undefined && ts.isIdentifier(n) && n.text === id.text
  for (let scope: ts.Node | undefined = id.parent; scope !== undefined; scope = scope.parent) {
    if (ts.isFunctionLike(scope)) {
      const p = scope.parameters.find((q) => named(q.name))
      if (p !== undefined) return p
    }
    if (ts.isSourceFile(scope) || ts.isBlock(scope) || ts.isModuleBlock(scope) || ts.isCaseClause(scope) || ts.isDefaultClause(scope)) {
      for (const st of scope.statements) {
        if (ts.isVariableStatement(st)) {
          const d = st.declarationList.declarations.find((v) => named(v.name))
          if (d !== undefined) return d
        }
        if (ts.isFunctionDeclaration(st) && named(st.name)) return st
        if (ts.isClassDeclaration(st) && named(st.name)) return st
      }
    }
    if ((ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) && scope.initializer !== undefined && ts.isVariableDeclarationList(scope.initializer)) {
      const d = scope.initializer.declarations.find((v) => named(v.name))
      if (d !== undefined) return d
    }
  }
  return undefined
}

/**
 * A name a `const { property: name } = from` (or `{ name }`) binds, by
 * lexical scope as lexicalDeclaration finds the rest: the property it takes
 * and what it takes it from. Top-level elements of an object pattern only;
 * a rest element is no one property.
 */
function destructured(id: ts.Identifier): { readonly property: string; readonly from: ts.Expression } | undefined {
  for (let scope: ts.Node | undefined = id.parent; scope !== undefined; scope = scope.parent) {
    if (!(ts.isSourceFile(scope) || ts.isBlock(scope) || ts.isModuleBlock(scope) || ts.isCaseClause(scope) || ts.isDefaultClause(scope))) continue
    for (const st of scope.statements) {
      if (!ts.isVariableStatement(st)) continue
      for (const d of st.declarationList.declarations) {
        if (!ts.isObjectBindingPattern(d.name) || d.initializer === undefined) continue
        const el = d.name.elements.find((x) => ts.isIdentifier(x.name) && x.name.text === id.text)
        if (el === undefined) continue
        const key = el.propertyName ?? el.name
        if (el.dotDotDotToken !== undefined || !(ts.isIdentifier(key) || ts.isStringLiteral(key))) return undefined
        return { property: key.text, from: d.initializer }
      }
    }
  }
  return undefined
}

/**
 * A path as far as the scan can know it: the whole string (`exact`), or only
 * how it ends, after a part the scan cannot see. UNSEEN knows nothing. How a
 * path ends is enough to tell it is not .env: whatever `root` holds,
 * `${root}/.aos/install.lock` is not. An unseen part that can hold no '/' (a
 * pid, a clock: a WORD) also keeps what its segment starts with, in `head`:
 * whatever the pid, `${lock}.${process.pid}` ends in a segment that starts
 * `install.lock.`, which .env does not. `anchored` when that start follows a
 * '/' the scan saw; otherwise it is the string's own start, which a prefix
 * runs on into.
 */
interface Tail {
  readonly exact: boolean
  readonly text: string
  readonly head?: { readonly text: string; readonly anchored: boolean }
}
const UNSEEN: Tail = { exact: false, text: '' }
const WORD: Tail = { exact: false, text: '', head: { text: '', anchored: false } }
const known = (text: string): Tail => ({ exact: true, text })
function then(a: Tail, b: Tail): Tail {
  if (b.exact) return a.exact ? known(a.text + b.text) : { exact: false, text: a.text + b.text, ...(a.head === undefined ? {} : { head: a.head }) }
  if (b.head === undefined || b.head.anchored) return b
  // b's last segment starts where b does, so it runs on from a's end.
  const slash = a.text.lastIndexOf('/')
  if (slash >= 0) return { exact: false, text: b.text, head: { text: a.text.slice(slash + 1) + b.head.text, anchored: true } }
  if (a.exact) return { exact: false, text: b.text, head: { text: a.text + b.head.text, anchored: false } }
  return { exact: false, text: b.text, ...(a.head === undefined ? {} : { head: a.head }) }
}
const product = (a: readonly Tail[], b: readonly Tail[]): Tail[] => a.flatMap((x) => b.map((y) => then(x, y)))
/** Whether a value can hold no '/' at all: then a replace() with no '/' in it is still a WORD. */
const slashFree = (t: Tail): boolean => (t.exact ? !t.text.includes('/') : t.head !== undefined && !t.head.anchored && !(t.head.text + t.text).includes('/'))
/** The most values one path is followed with; past it, the path is unseen. */
const MAX_TAILS = 16
function capped(tails: readonly Tail[]): Tail[] {
  const unique = [...new Map(tails.map((t) => [JSON.stringify(t), t])).values()]
  return unique.length <= MAX_TAILS ? unique : [UNSEEN]
}

/** Whether a path's last segment is .env, is not, or may be. */
type Verdict = 'dotenv' | 'other' | 'unknown'

const DOTENV = '.env'

function verdictOf(tail: Tail): Verdict {
  // Lower case: APFS folds case, so .ENV is the operator's .env there.
  const text = tail.text.toLowerCase()
  // After an unseen part, the text up to the first slash runs into that
  // part's last segment; every segment after a slash is whole, and `..`
  // takes one back, as path.join and the filesystem both read it.
  const cut = tail.exact ? -1 : text.indexOf('/')
  const whole: string[] = []
  let lost = false
  for (const segment of tail.exact ? text.split('/') : cut < 0 ? [] : text.slice(cut + 1).split('/')) {
    if (segment === '..') lost = whole.pop() === undefined || lost
    else if (segment !== '' && segment !== '.') whole.push(segment)
  }
  const last = whole.at(-1)
  if (last !== undefined) return last === DOTENV ? 'dotenv' : 'other'
  if (tail.exact) return 'other'
  if (lost) return 'unknown'
  // The last segment is the one the unseen part falls in, ending with `end`
  // and, when the head is known, starting with it. It may be .env, or `.` or
  // `..`, which would make the last segment an unseen one before it.
  const end = cut < 0 ? text : text.slice(0, cut)
  const head = tail.head?.text.toLowerCase()
  const fits = (name: string): boolean => name.endsWith(end) && (head === undefined || (name.startsWith(head) && head.length + end.length <= name.length))
  return fits(DOTENV) || fits('..') || fits('.') ? 'unknown' : 'other'
}

function verdictOfAll(tails: readonly Tail[]): Verdict {
  const verdicts = tails.map(verdictOf)
  return verdicts.includes('dotenv') ? 'dotenv' : verdicts.includes('unknown') ? 'unknown' : 'other'
}

/** Each parameter of a call being followed, bound to its arguments in order; undefined when the scan cannot line them up. */
type Bound = ReadonlyMap<ts.ParameterDeclaration, readonly (readonly Tail[])[] | undefined>
const NO_BOUND: Bound = new Map()

/** The most nodes one path is worked out through; past it, what is left is unseen, so a file cannot stall the scan. */
const MAX_STEPS = 10_000

interface Trace {
  /** The modules a relative import can be followed into, by repo-relative path. */
  readonly pool: ReadonlyMap<string, ts.SourceFile>
  readonly bound: Bound
  /** Parameters taken to hold these values wherever they are read: how writeParams asks what a caller's argument reaches. */
  readonly assume: Bound
  /** The nodes being worked out, so a cycle reads as unseen rather than looping. */
  readonly active: Set<ts.Node>
  /** What each node was worked out to, under each binding: a value built from itself k times is worked out k times, not k! times. */
  readonly memo: Map<ts.Node, Map<Bound, readonly Tail[]>>
  readonly steps: { left: number }
}

const traceIn = (pool: ReadonlyMap<string, ts.SourceFile>, assume: Bound = NO_BOUND): Trace => ({
  pool,
  bound: NO_BOUND,
  assume,
  active: new Set(),
  memo: new Map(),
  steps: { left: MAX_STEPS },
})

type Fn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression | ts.MethodDeclaration

/** An expression without the parentheses, casts and awaits that leave its value a path. */
function unwrapped(node: ts.Expression): ts.Expression {
  let e = node
  while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) || ts.isSatisfiesExpression(e) || ts.isTypeAssertionExpression(e) || ts.isAwaitExpression(e)) {
    e = e.expression
  }
  return e
}

/** Every value `node` may have, as a path. Frozen: it is the memo's own copy. */
function tailsOf(node: ts.Expression, trace: Trace): readonly Tail[] {
  const e = unwrapped(node)
  const cached = trace.memo.get(e)?.get(trace.bound)
  if (cached !== undefined) return cached
  if (trace.active.has(e) || trace.steps.left <= 0) return [UNSEEN]
  trace.steps.left -= 1
  trace.active.add(e)
  try {
    const tails = Object.freeze(capped(tailsWithin(e, trace)))
    let byBinding = trace.memo.get(e)
    if (byBinding === undefined) trace.memo.set(e, (byBinding = new Map()))
    byBinding.set(trace.bound, tails)
    return tails
  } finally {
    trace.active.delete(e)
  }
}

function tailsWithin(e: ts.Expression, trace: Trace): readonly Tail[] {
  if (ts.isStringLiteralLike(e)) return [known(e.text)]
  if (ts.isNumericLiteral(e) || ts.isBigIntLiteral(e)) return [WORD]
  if (ts.isTemplateExpression(e)) {
    let tails = [known(e.head.text)]
    for (const span of e.templateSpans) tails = product(product(tails, tailsOf(span.expression, trace)), [known(span.literal.text)])
    return tails
  }
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind
    if (op === ts.SyntaxKind.PlusToken) return product(tailsOf(e.left, trace), tailsOf(e.right, trace))
    if (op === ts.SyntaxKind.QuestionQuestionToken || op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.AmpersandAmpersandToken) {
      return [...tailsOf(e.left, trace), ...tailsOf(e.right, trace)]
    }
    return op === ts.SyntaxKind.CommaToken ? tailsOf(e.right, trace) : [UNSEEN]
  }
  if (ts.isConditionalExpression(e)) return [...tailsOf(e.whenTrue, trace), ...tailsOf(e.whenFalse, trace)]
  if (ts.isIdentifier(e)) {
    if (e.text === 'DOTENV_FILE') return [known('.env')]
    const decl = bindingOf(e, trace.pool)
    return decl === undefined ? [UNSEEN] : bindingTails(decl, trace)
  }
  if (ts.isPropertyAccessExpression(e)) {
    // A pid holds no '/'.
    if (isGlobal(e.expression, 'process') && (e.name.text === 'pid' || e.name.text === 'ppid')) return [WORD]
    return memberTails(e, trace)
  }
  if (ts.isCallExpression(e)) return callTails(e, trace)
  // this.x, x[k], new URL(…) and the rest: unseen.
  return [UNSEEN]
}

/** `name` itself, declared nowhere in its file: the global. */
const isGlobal = (e: ts.Expression, name: string): boolean => ts.isIdentifier(e) && e.text === name && declarationOf(e) === undefined && importOf(e) === undefined

/** The values a declaration may hold as a path: a const or let by everything it is given, a parameter by what it is passed. */
function bindingTails(decl: ts.Node, trace: Trace): readonly Tail[] {
  if (ts.isParameter(decl)) return parameterTails(decl, trace)
  if (ts.isExportAssignment(decl)) return functionOf(decl) !== undefined ? [UNSEEN] : tailsOf(decl.expression, trace)
  if (!ts.isVariableDeclaration(decl) || !ts.isIdentifier(decl.name)) return [UNSEEN]
  const holder = decl.parent.parent
  if (ts.isForOfStatement(holder)) {
    const list = unwrapped(holder.expression)
    return ts.isArrayLiteralExpression(list) ? list.elements.flatMap((el) => (ts.isSpreadElement(el) ? [UNSEEN] : tailsOf(el, trace))) : [UNSEEN]
  }
  if (ts.isForInStatement(holder)) return [UNSEEN]
  const out = decl.initializer === undefined ? [] : functionOf(decl) !== undefined ? [UNSEEN] : [...tailsOf(decl.initializer, trace)]
  for (const value of assignmentsTo(decl)) out.push(...(value === undefined ? [UNSEEN] : tailsOf(value, trace)))
  return out
}

function parameterTails(p: ts.ParameterDeclaration, trace: Trace): readonly Tail[] {
  const rest = p.dotDotDotToken !== undefined
  for (const given of [trace.bound, trace.assume]) {
    if (!given.has(p)) continue
    const args = given.get(p)
    // A rest parameter whole is an array, not a path; join() spreads it (argumentTails).
    if (args === undefined || rest) return [UNSEEN]
    const arg = args[0]
    if (arg !== undefined) return [...arg]
    return p.initializer === undefined ? [] : tailsOf(p.initializer, trace)
  }
  // Outside a call being followed: the default and what every caller in this
  // file passes, and unseen when a caller may be where the scan cannot look.
  const out = p.initializer === undefined ? [] : [...tailsOf(p.initializer, trace)]
  const index = p.parent.parameters.indexOf(p)
  const passed = (calls: readonly ts.CallExpression[]): void => {
    for (const call of calls) {
      const args = argumentTails(call.arguments, { ...trace, bound: NO_BOUND })
      if (args === undefined) out.push(UNSEEN)
      else out.push(...(args[index] ?? []))
    }
  }
  const sites = callSites(p.parent)
  if (sites === undefined || rest || !ts.isIdentifier(p.name)) {
    // A method may be called from wherever its object reaches, so it stays
    // unseen; what a sibling passes it through `this` is followed as well.
    if (!rest && ts.isIdentifier(p.name)) passed(thisCallSites(p.parent))
    return [...out, UNSEEN]
  }
  passed(sites)
  return out
}

/**
 * The calls of a method through `this` from its siblings in the same class
 * (of the same staticness) or object literal: `this.raw(f, t)` from `put`.
 * The method may be a property holding a function (`raw = (f) => …`,
 * `raw: function (f) {…}`). The callers are its siblings' bodies: methods,
 * accessors, a class's constructor and fields, and a property holding a
 * function expression, whose `this` is the object it is called on; not an
 * object literal's arrow property, whose `this` is the enclosing one, nor
 * inside a function or class of their own, which bind another `this`. An
 * arrow inside a body keeps it.
 */
function thisCallSites(fn: ts.SignatureDeclaration): ts.CallExpression[] {
  const self = memberOf(fn)
  if (self === undefined) return []
  const name = propertyKey(self.name)
  const owner = self.parent
  if (name === undefined || !(ts.isClassLike(owner) || ts.isObjectLiteralExpression(owner))) return []
  const isStatic = (member: ts.Node): boolean =>
    ts.isClassStaticBlockDeclaration(member) || ((ts.canHaveModifiers(member) ? ts.getModifiers(member) : undefined) ?? []).some((m) => m.kind === ts.SyntaxKind.StaticKeyword)
  const out: ts.CallExpression[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isClassLike(node)) return
    if (ts.isCallExpression(node)) {
      const callee = unwrapped(node.expression)
      if (ts.isPropertyAccessExpression(callee) && callee.expression.kind === ts.SyntaxKind.ThisKeyword && callee.name.text === name) out.push(node)
    }
    ts.forEachChild(node, visit)
  }
  // A property holding a function expression is read from inside it: the
  // visit stops at a function's edge, and this one's `this` is the object's.
  const functionHeld = (member: ts.Node): ts.FunctionExpression | undefined => {
    if (!(ts.isPropertyDeclaration(member) || ts.isPropertyAssignment(member)) || member.initializer === undefined) return undefined
    const value = unwrapped(member.initializer)
    return ts.isFunctionExpression(value) ? value : undefined
  }
  const siblings: readonly ts.Node[] = ts.isObjectLiteralExpression(owner)
    ? owner.properties.filter((m) => ts.isMethodDeclaration(m) || ts.isAccessor(m) || functionHeld(m) !== undefined)
    : owner.members.filter((m) => isStatic(m) === isStatic(self))
  for (const member of siblings) ts.forEachChild(functionHeld(member) ?? member, visit)
  return out
}

/** The class member or object literal property a function is: a method, or the property whose value it is (`raw = (f) => …`, `raw: function (f) {…}`). */
function memberOf(fn: ts.SignatureDeclaration): ts.MethodDeclaration | ts.PropertyDeclaration | ts.PropertyAssignment | undefined {
  if (ts.isMethodDeclaration(fn)) return fn
  if (!ts.isArrowFunction(fn) && !ts.isFunctionExpression(fn)) return undefined
  // Out through what unwrapped() sees through, as classMethod and literalMethod read the value.
  let at: ts.Node = fn
  while (ts.isParenthesizedExpression(at.parent) || ts.isAsExpression(at.parent) || ts.isNonNullExpression(at.parent) || ts.isSatisfiesExpression(at.parent) || ts.isTypeAssertionExpression(at.parent)) {
    at = at.parent
  }
  const prop = at.parent
  return (ts.isPropertyDeclaration(prop) || ts.isPropertyAssignment(prop)) && prop.initializer === at ? prop : undefined
}

/** Every call of a function by name, when those are all there are: none for an export, a method, a callback or a function used as a value. */
function callSites(fn: ts.SignatureDeclaration): ts.CallExpression[] | undefined {
  const binding = ts.isFunctionDeclaration(fn)
    ? fn
    : (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isVariableDeclaration(fn.parent) && fn.parent.initializer === fn
      ? fn.parent
      : undefined
  if (binding === undefined) return undefined
  if (isExported(ts.isFunctionDeclaration(binding) ? binding : binding.parent.parent)) return undefined
  const sites: ts.CallExpression[] = []
  for (const ref of referencesTo(binding)) {
    if (!ts.isCallExpression(ref.parent) || ref.parent.expression !== ref) return undefined
    sites.push(ref.parent)
  }
  return sites
}

/** `x.name`, for an `x` the scan can follow: a namespace import's export, or a property of an object a variable holds. */
function memberTails(e: ts.PropertyAccessExpression, trace: Trace): readonly Tail[] {
  const object = unwrapped(e.expression)
  if (!ts.isIdentifier(object)) return [UNSEEN]
  const ns = namespaceOf(object, trace.pool)
  if (ns !== undefined) {
    const decl = exportedBinding(ns, e.name.text, trace.pool, 0)
    return decl === undefined ? [UNSEEN] : bindingTails(decl, trace)
  }
  const decl = bindingOf(object, trace.pool)
  return decl !== undefined && ts.isVariableDeclaration(decl) ? propertyTails(decl, e.name.text, trace) : [UNSEEN]
}

/**
 * `x.name`: the matching property of each object literal `x` is given, or a
 * function of this repository returns, and every `x.name = …`. Unseen when
 * `x` holds anything else, or goes where it could be changed unseen: passed,
 * spread, indexed or exported by name.
 */
function propertyTails(decl: ts.VariableDeclaration, name: string, trace: Trace): Tail[] {
  const holder = decl.parent.parent
  if (ts.isForOfStatement(holder) || ts.isForInStatement(holder)) return [UNSEEN]
  const out: Tail[] = []
  for (const value of [...(decl.initializer === undefined ? [] : [decl.initializer]), ...assignmentsTo(decl)]) {
    const given = value === undefined ? undefined : unwrapped(value)
    if (given !== undefined && ts.isCallExpression(given)) out.push(...returnedProperty(given, name, trace))
    else if (given !== undefined && ts.isObjectLiteralExpression(given)) out.push(...literalProperty(given, name, trace))
    else out.push(UNSEEN)
  }
  for (const ref of referencesTo(decl)) {
    const use = ref.parent
    // The whole object given again: read above, through assignmentsTo.
    if (ts.isBinaryExpression(use) && use.left === ref && isAssignment(use.operatorToken.kind)) continue
    if (!ts.isPropertyAccessExpression(use) || use.expression !== ref) {
      out.push(UNSEEN)
      continue
    }
    const write = use.parent
    if (use.name.text === name && ts.isBinaryExpression(write) && write.left === use && isAssignment(write.operatorToken.kind)) {
      out.push(...(SIMPLE_ASSIGN.has(write.operatorToken.kind) ? tailsOf(write.right, trace) : [UNSEEN]))
    }
  }
  return out
}

/** Property `name` of an object literal: unseen where a spread, a computed key or an accessor could supply it. */
function literalProperty(literal: ts.ObjectLiteralExpression, name: string, trace: Trace): Tail[] {
  const out: Tail[] = []
  for (const prop of literal.properties) {
    if (ts.isSpreadAssignment(prop) || ts.isComputedPropertyName(prop.name)) out.push(UNSEEN)
    else if (propertyKey(prop.name) !== name) continue
    else if (ts.isPropertyAssignment(prop)) out.push(...tailsOf(prop.initializer, trace))
    else if (ts.isShorthandPropertyAssignment(prop)) out.push(...tailsOf(prop.name, trace))
    else out.push(UNSEEN)
  }
  return out
}

/** Property `name` of what a call returns: each object literal the called function returns, its parameters bound to the call's arguments. */
function returnedProperty(call: ts.CallExpression, name: string, trace: Trace): Tail[] {
  const fn = calledFunction(call.expression, trace.pool)
  if (fn === undefined || fn.body === undefined) return [UNSEEN]
  const inner: Trace = { ...trace, bound: bindCall(fn, call, trace) }
  const out: Tail[] = []
  for (const value of returnedValues(fn)) {
    const literal = unwrapped(value)
    out.push(...(ts.isObjectLiteralExpression(literal) ? literalProperty(literal, name, inner) : [UNSEEN]))
  }
  return out
}

const propertyKey = (name: ts.PropertyName): string | undefined => (ts.isComputedPropertyName(name) ? undefined : name.text)

/** A function's parameters bound to a call's arguments, on top of the bindings already followed. */
function bindCall(fn: Fn, call: ts.CallExpression, trace: Trace): Bound {
  const args = argumentTails(call.arguments, trace)
  const bound = new Map(trace.bound)
  fn.parameters.forEach((p, i) => bound.set(p, args === undefined ? undefined : p.dotDotDotToken !== undefined ? args.slice(i) : args.slice(i, i + 1)))
  return bound
}

function callTails(call: ts.CallExpression, trace: Trace): readonly Tail[] {
  const fn = calledFunction(call.expression, trace.pool)
  if (fn !== undefined) return returnTails(fn, bindCall(fn, call, trace), trace)
  const callee = unwrapped(call.expression)
  const name = builtinName(callee, trace.pool)
  const first = call.arguments[0]
  const whole = first !== undefined && !ts.isSpreadElement(first) ? first : undefined
  // A descriptor is the file it opens: writeFileSync(fd, …) writes that path.
  if ((name === 'openSync' || name === 'open') && whole !== undefined) return tailsOf(whole, trace)
  const path = pathFunction(callee)
  if (path === 'join' || path === 'resolve') return joinTails(call.arguments, trace)
  // What holds no '/': a clock, a date in ISO form.
  if ((ts.isPropertyAccessExpression(callee) && ((isGlobal(callee.expression, 'Date') || isGlobal(callee.expression, 'performance')) && callee.name.text === 'now')) || name === 'toISOString') {
    return [WORD]
  }
  // String(x) and x.toString() are x, for every value tailsOf gives a path; a number is a WORD.
  if (ts.isIdentifier(callee) && isGlobal(callee, 'String')) return whole === undefined ? [known('')] : tailsOf(whole, trace)
  if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'toString') return tailsOf(callee.expression, trace)
  // A replace that puts no '/' into a value holding none leaves it holding none.
  if (ts.isPropertyAccessExpression(callee) && (callee.name.text === 'replace' || callee.name.text === 'replaceAll')) {
    const by = call.arguments[1]
    if (by !== undefined && ts.isStringLiteralLike(by) && !by.text.includes('/') && tailsOf(callee.expression, trace).every(slashFree)) return [WORD]
  }
  return [UNSEEN]
}

/** The expressions a function returns: its expression body, or each return in its block (not in a function nested in it). */
function returnedValues(fn: Fn): ts.Expression[] {
  const body = fn.body
  if (body === undefined) return []
  if (!ts.isBlock(body)) return [body]
  const out: ts.Expression[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionLike(node)) return
    if (ts.isReturnStatement(node) && node.expression !== undefined) out.push(node.expression)
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(body, visit)
  return out
}

/** What a function returns, its parameters bound as `bound` says. */
function returnTails(fn: Fn, bound: Bound, trace: Trace): Tail[] {
  if (fn.body === undefined) return [UNSEEN]
  const inner: Trace = { ...trace, bound }
  return returnedValues(fn).flatMap((value) => tailsOf(value, inner))
}

/** Each argument's values in order, spreads opened where the scan can: an array literal, or a rest parameter the call being followed binds. */
function argumentTails(args: readonly ts.Expression[], trace: Trace): (readonly Tail[])[] | undefined {
  const out: (readonly Tail[])[] = []
  for (const arg of args) {
    if (!ts.isSpreadElement(arg)) {
      out.push(tailsOf(arg, trace))
      continue
    }
    const spread = unwrapped(arg.expression)
    if (ts.isArrayLiteralExpression(spread) && !spread.elements.some((el) => ts.isSpreadElement(el))) {
      out.push(...spread.elements.map((el) => tailsOf(el, trace)))
      continue
    }
    const rest = ts.isIdentifier(spread) ? declarationOf(spread) : undefined
    const bound = rest !== undefined && ts.isParameter(rest) && rest.dotDotDotToken !== undefined ? trace.bound.get(rest) : undefined
    if (bound === undefined) return undefined
    out.push(...bound)
  }
  return out
}

/**
 * path.join and path.resolve: segments joined by '/'. Where resolve starts
 * again at an absolute segment the last segment is the same, and that is all
 * a verdict reads.
 */
function joinTails(args: readonly ts.Expression[], trace: Trace): Tail[] {
  const [first, ...rest] = argumentTails(args, trace) ?? []
  if (first === undefined) return [UNSEEN]
  let tails: Tail[] = [...first]
  for (const next of rest) tails = capped(tails.flatMap((a) => next.map((b) => then(then(a, known('/')), b))))
  return tails
}

const FS_MODULE = /^(?:node:)?fs(?:\/promises)?$/
const PATH_MODULE = /^(?:node:)?path(?:\/(?:posix|win32))?$/

/** The import that binds `id` in its file: the module it names, and the export bound (`default`, `*` or a name). */
function importOf(id: ts.Identifier): { readonly module: string; readonly name: string } | undefined {
  for (const st of id.getSourceFile().statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue
    const clause = st.importClause
    const module = st.moduleSpecifier.text
    if (clause?.name?.text === id.text) return { module, name: 'default' }
    const bindings = clause?.namedBindings
    if (bindings !== undefined && ts.isNamespaceImport(bindings) && bindings.name.text === id.text) return { module, name: '*' }
    const el = bindings !== undefined && ts.isNamedImports(bindings) ? bindings.elements.find((e) => e.name.text === id.text) : undefined
    if (el !== undefined) return { module, name: (el.propertyName ?? el.name).text }
  }
  return undefined
}

/**
 * Which module object `e` is: node:fs (or fs/promises) or node:path, as an
 * import, its `promises`/`posix`/`win32`, or a local that holds one. Bare
 * `fs`, `fsp`, `promises`, `path`, `posix` and `win32` that nothing in the file
 * declares are taken for them, as the scan's own examples write them.
 */
function moduleBinding(node: ts.Expression, depth = 0): 'fs' | 'path' | undefined {
  const e = unwrapped(node)
  if (depth > 8) return undefined
  // `await import('node:fs/promises')`: the await is unwrapped above.
  if (ts.isCallExpression(e) && e.expression.kind === ts.SyntaxKind.ImportKeyword) {
    const spec = e.arguments[0]
    if (spec === undefined || !ts.isStringLiteralLike(spec)) return undefined
    return FS_MODULE.test(spec.text) ? 'fs' : PATH_MODULE.test(spec.text) ? 'path' : undefined
  }
  if (ts.isPropertyAccessExpression(e)) {
    const of = moduleBinding(e.expression, depth + 1)
    if (of === 'fs' && e.name.text === 'promises') return 'fs'
    if (of === 'path' && (e.name.text === 'posix' || e.name.text === 'win32')) return 'path'
    return undefined
  }
  if (!ts.isIdentifier(e)) return undefined
  const local = declarationOf(e)
  if (local !== undefined) return ts.isVariableDeclaration(local) && ts.isIdentifier(local.name) && local.initializer !== undefined ? moduleBinding(local.initializer, depth + 1) : undefined
  const from = importOf(e)
  if (from === undefined) return /^(?:fs|fsp|promises)$/.test(e.text) ? 'fs' : /^(?:path|posix|win32)$/.test(e.text) ? 'path' : undefined
  if (FS_MODULE.test(from.module) && (from.name === 'default' || from.name === '*' || from.name === 'promises')) return 'fs'
  if (PATH_MODULE.test(from.module) && (from.name === 'default' || from.name === '*' || from.name === 'posix' || from.name === 'win32')) return 'path'
  return undefined
}

/**
 * The node:fs export `e` provably is, under any name: an import renamed
 * (`writeFileSync as put`), a module object's member (`fs.writeFileSync`,
 * `fs['writeFileSync']`), or a const that holds one (`const put = fs.rmSync`),
 * here or in a module of the pool. A bare name nothing in the file declares
 * or imports is taken at its word, as the scan's own examples write it.
 */
function fsFunction(node: ts.Expression, pool: ReadonlyMap<string, ts.SourceFile>, depth = 0): string | undefined {
  const e = unwrapped(node)
  if (depth > 8) return undefined
  if (ts.isPropertyAccessExpression(e)) return moduleBinding(e.expression) === 'fs' ? e.name.text : undefined
  if (ts.isElementAccessExpression(e)) {
    const key = e.argumentExpression
    return ts.isStringLiteralLike(key) && moduleBinding(e.expression) === 'fs' ? key.text : undefined
  }
  if (!ts.isIdentifier(e)) return undefined
  const local = declarationOf(e)
  const from = local === undefined ? importOf(e) : undefined
  if (local === undefined && from === undefined) {
    // `const { writeFileSync: put } = fs`, or `= await import('node:fs')`.
    const element = destructured(e)
    if (element !== undefined && moduleBinding(element.from, depth + 1) === 'fs') return element.property
    return PATH_ARGS.has(e.text) || READ_CALLS.has(e.text) ? e.text : undefined
  }
  if (from !== undefined && FS_MODULE.test(from.module)) return from.name === 'default' || from.name === '*' ? undefined : from.name
  const decl = local ?? bindingOf(e, pool)
  return decl !== undefined && ts.isVariableDeclaration(decl) && ts.isIdentifier(decl.name) && decl.initializer !== undefined
    ? fsFunction(decl.initializer, pool, depth + 1)
    : undefined
}

/** The name a callee is matched by: the fs export it is, else its own name (any `x.writeFileSync` included), as before. */
function builtinName(callee: ts.Expression, pool: ReadonlyMap<string, ts.SourceFile>): string | undefined {
  const e = unwrapped(callee)
  const fs = fsFunction(e, pool)
  if (fs !== undefined) return fs
  if (ts.isIdentifier(e)) return e.text
  if (ts.isPropertyAccessExpression(e)) return e.name.text
  if (ts.isElementAccessExpression(e) && ts.isStringLiteralLike(e.argumentExpression)) return e.argumentExpression.text
  return undefined
}

/** `join` or `resolve` from node:path: imported under any name, bare, or called on a path module object. */
function pathFunction(callee: ts.Expression): string | undefined {
  const e = unwrapped(callee)
  if (ts.isPropertyAccessExpression(e)) return moduleBinding(e.expression) === 'path' ? e.name.text : undefined
  if (!ts.isIdentifier(e) || declarationOf(e) !== undefined) return undefined
  const from = importOf(e)
  if (from === undefined || from.module.startsWith('.')) return e.text
  return PATH_MODULE.test(from.module) ? from.name : undefined
}

/**
 * The function a callee names, in its own file or through a relative import:
 * a function by name, under a second name (`const save = put`), a namespace
 * import's export, or a method: of an object literal a const holds or a
 * module exports as its default, of a class, by name or a module's default
 * (static, `Io.put`), or of an instance (`new Io().put`, or a const or
 * default export that holds
 * `new Io()`), each also through a namespace import (`m.io.put`). An object
 * literal's property may name the function (`{ put }`, `{ put: put }`).
 */
function calledFunction(callee: ts.Expression, pool: ReadonlyMap<string, ts.SourceFile>, depth = 0): Fn | undefined {
  const e = unwrapped(callee)
  if (depth > 8) return undefined
  if (ts.isIdentifier(e)) {
    const decl = bindingOf(e, pool)
    if (decl === undefined) return undefined
    const alias = constAlias(decl)
    return functionOf(decl) ?? (alias === undefined ? undefined : calledFunction(alias, pool, depth + 1))
  }
  if (!ts.isPropertyAccessExpression(e)) return undefined
  const object = unwrapped(e.expression)
  const name = e.name.text
  if (ts.isNewExpression(object)) {
    const made = namedBinding(object.expression, pool)
    return made !== undefined && ts.isClassDeclaration(made) ? classMethod(made, name, false) : undefined
  }
  const ns = ts.isIdentifier(object) ? namespaceOf(object, pool) : undefined
  if (ns !== undefined) {
    const decl = exportedBinding(ns, name, pool, 0)
    return decl === undefined ? undefined : functionOf(decl)
  }
  const decl = namedBinding(object, pool)
  return decl === undefined ? undefined : methodOf(decl, name, pool, depth)
}

/** The declaration a name, or a namespace import's member (`m.io`), binds. */
function namedBinding(node: ts.Expression, pool: ReadonlyMap<string, ts.SourceFile>): ts.Node | undefined {
  const e = unwrapped(node)
  if (ts.isIdentifier(e)) return bindingOf(e, pool)
  if (!ts.isPropertyAccessExpression(e)) return undefined
  const object = unwrapped(e.expression)
  const ns = ts.isIdentifier(object) ? namespaceOf(object, pool) : undefined
  return ns === undefined ? undefined : exportedBinding(ns, e.name.text, pool, 0)
}

/** Method `name` of what a declaration holds: a class (its statics), or the object literal or instance a const or a default export is. */
function methodOf(decl: ts.Node, name: string, pool: ReadonlyMap<string, ts.SourceFile>, depth: number): Fn | undefined {
  if (ts.isClassDeclaration(decl)) return classMethod(decl, name, true)
  const held = ts.isVariableDeclaration(decl) && isConst(decl) ? decl.initializer : ts.isExportAssignment(decl) && !decl.isExportEquals ? decl.expression : undefined
  const value = held === undefined ? undefined : unwrapped(held)
  if (value === undefined) return undefined
  if (ts.isObjectLiteralExpression(value)) return literalMethod(value, name, pool, depth)
  if (ts.isNewExpression(value)) {
    const made = namedBinding(value.expression, pool)
    return made !== undefined && ts.isClassDeclaration(made) ? classMethod(made, name, false) : undefined
  }
  return undefined
}

const isConst = (decl: ts.VariableDeclaration): boolean => ts.isVariableDeclarationList(decl.parent) && (decl.parent.flags & ts.NodeFlags.Const) !== 0

/** The name a const gives a second name to: `const save = put` is `put`. */
function constAlias(decl: ts.Node): ts.Identifier | undefined {
  if (!ts.isVariableDeclaration(decl) || decl.initializer === undefined || !isConst(decl)) return undefined
  const value = unwrapped(decl.initializer)
  return ts.isIdentifier(value) ? value : undefined
}

/**
 * An object literal's method `name`: `put(f) {…}`, `put: (f) => …` /
 * `put: function (f) {…}`, or a property that names a function, the
 * shorthand `{ put }` or `{ put: put }`, followed as a callee by that name.
 */
function literalMethod(literal: ts.ObjectLiteralExpression, name: string, pool: ReadonlyMap<string, ts.SourceFile>, depth: number): Fn | undefined {
  for (const prop of literal.properties) {
    if (ts.isSpreadAssignment(prop) || propertyKey(prop.name) !== name) continue
    if (ts.isMethodDeclaration(prop)) return prop.body === undefined ? undefined : prop
    if (ts.isShorthandPropertyAssignment(prop)) return calledFunction(prop.name, pool, depth + 1)
    if (ts.isPropertyAssignment(prop)) {
      const fn = unwrapped(prop.initializer)
      if (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) return fn
      return ts.isIdentifier(fn) ? calledFunction(fn, pool, depth + 1) : undefined
    }
  }
  return undefined
}

/** A class's method `name`, static or not: a method, or a field holding an arrow or function. */
function classMethod(cls: ts.ClassDeclaration, name: string, isStatic: boolean): Fn | undefined {
  for (const member of cls.members) {
    if (member.name === undefined || propertyKey(member.name) !== name) continue
    const staticMember = ((ts.canHaveModifiers(member) ? ts.getModifiers(member) : undefined) ?? []).some((m) => m.kind === ts.SyntaxKind.StaticKeyword)
    if (staticMember !== isStatic) continue
    if (ts.isMethodDeclaration(member)) return member.body === undefined ? undefined : member
    if (ts.isPropertyDeclaration(member) && member.initializer !== undefined) {
      const fn = unwrapped(member.initializer)
      return ts.isArrowFunction(fn) || ts.isFunctionExpression(fn) ? fn : undefined
    }
  }
  return undefined
}

function functionOf(decl: ts.Node): Fn | undefined {
  if (ts.isFunctionDeclaration(decl)) return decl.body === undefined ? undefined : decl
  const init = ts.isVariableDeclaration(decl) ? decl.initializer : ts.isExportAssignment(decl) ? decl.expression : undefined
  if (init === undefined) return undefined
  const fn = unwrapped(init)
  return ts.isArrowFunction(fn) || ts.isFunctionExpression(fn) ? fn : undefined
}

const SIMPLE_ASSIGN = new Set([ts.SyntaxKind.EqualsToken, ts.SyntaxKind.QuestionQuestionEqualsToken, ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.AmpersandAmpersandEqualsToken])
const isAssignment = (kind: ts.SyntaxKind): boolean => kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment

/** What a variable is given after its declaration; undefined for a write the scan cannot read (`p += …`, `[p] = …`, `for (p of …)`). */
function assignmentsTo(decl: ts.VariableDeclaration): (ts.Expression | undefined)[] {
  const out: (ts.Expression | undefined)[] = []
  for (const ref of referencesTo(decl)) {
    const use = ref.parent
    if (ts.isBinaryExpression(use) && use.left === ref && isAssignment(use.operatorToken.kind)) out.push(SIMPLE_ASSIGN.has(use.operatorToken.kind) ? use.right : undefined)
    else if (((ts.isForOfStatement(use) || ts.isForInStatement(use)) && use.initializer === ref) || isDestructured(ref)) out.push(undefined)
  }
  return out
}

/** Whether an identifier is written by a destructuring assignment: `[p] = …`, `({ p } = …)`. */
function isDestructured(id: ts.Identifier): boolean {
  let node: ts.Node = id
  const pattern = (n: ts.Node): boolean =>
    ts.isArrayLiteralExpression(n) || ts.isObjectLiteralExpression(n) || ts.isShorthandPropertyAssignment(n) || ts.isPropertyAssignment(n) || ts.isSpreadElement(n) || ts.isSpreadAssignment(n)
  while (pattern(node.parent)) node = node.parent
  if (node === id) return false
  const top = node.parent
  return (
    (ts.isBinaryExpression(top) && top.left === node && top.operatorToken.kind === ts.SyntaxKind.EqualsToken) ||
    ((ts.isForOfStatement(top) || ts.isForInStatement(top)) && top.initializer === node)
  )
}

const REFERENCES = new WeakMap<ts.Node, ts.Identifier[]>()

/** The identifiers in a declaration's file that name it, by scope: never a property's name, an import's remote name or a type. Worked out once per declaration. */
function referencesTo(decl: ts.VariableDeclaration | ts.FunctionDeclaration): ts.Identifier[] {
  const seen = REFERENCES.get(decl)
  if (seen !== undefined) return seen
  const name = decl.name
  const out: ts.Identifier[] = []
  if (name !== undefined && ts.isIdentifier(name)) {
    const visit = (node: ts.Node): void => {
      if (ts.isTypeNode(node)) return
      if (ts.isIdentifier(node) && node !== name && node.text === name.text && !isPropertyName(node) && declarationOf(node) === decl) out.push(node)
      ts.forEachChild(node, visit)
    }
    visit(decl.getSourceFile())
  }
  REFERENCES.set(decl, out)
  return out
}

function isPropertyName(id: ts.Identifier): boolean {
  const p = id.parent
  if (ts.isPropertyAccessExpression(p) || ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p) || ts.isMethodDeclaration(p) || ts.isPropertySignature(p)) return p.name === id
  if (ts.isGetAccessor(p) || ts.isSetAccessor(p) || ts.isEnumMember(p)) return p.name === id
  if (ts.isBindingElement(p) || ts.isImportSpecifier(p)) return p.propertyName === id
  if (ts.isExportSpecifier(p)) return p.propertyName !== undefined && p.name === id
  return ts.isLabeledStatement(p) || ts.isBreakOrContinueStatement(p)
}

const isExported = (node: ts.Node): boolean => ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
const isDefault = (node: ts.Node): boolean => ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)

/** A name's declaration: by scope in its own file, else through a relative import into the pool. */
function bindingOf(id: ts.Identifier, pool: ReadonlyMap<string, ts.SourceFile>): ts.Node | undefined {
  return declarationOf(id) ?? importedBinding(id.getSourceFile(), id.text, pool, 0)
}

/** The pool's module a relative specifier in `from` names. */
function moduleAt(from: ts.SourceFile, spec: ts.Expression, pool: ReadonlyMap<string, ts.SourceFile>): ts.SourceFile | undefined {
  if (!ts.isStringLiteral(spec) || !spec.text.startsWith('.')) return undefined
  return pool.get(posix.normalize(posix.join(posix.dirname(from.fileName), spec.text)).replace(/\.js$/, '.ts'))
}

/** What a named or default import binds `name` to in `module`, followed into the module it comes from. */
function importedBinding(module: ts.SourceFile, name: string, pool: ReadonlyMap<string, ts.SourceFile>, hops: number): ts.Node | undefined {
  for (const st of module.statements) {
    if (!ts.isImportDeclaration(st)) continue
    const clause = st.importClause
    const bindings = clause?.namedBindings
    const el = bindings !== undefined && ts.isNamedImports(bindings) ? bindings.elements.find((e) => e.name.text === name) : undefined
    const remote = clause?.name?.text === name ? 'default' : el === undefined ? undefined : (el.propertyName ?? el.name).text
    if (remote === undefined) continue
    const from = moduleAt(module, st.moduleSpecifier, pool)
    return from === undefined ? undefined : exportedBinding(from, remote, pool, hops + 1)
  }
  return undefined
}

/** The pool's module `id` names when it is a namespace import (`import * as paths`). */
function namespaceOf(id: ts.Identifier, pool: ReadonlyMap<string, ts.SourceFile>): ts.SourceFile | undefined {
  if (declarationOf(id) !== undefined) return undefined
  const module = id.getSourceFile()
  for (const st of module.statements) {
    if (!ts.isImportDeclaration(st)) continue
    const bindings = st.importClause?.namedBindings
    if (bindings !== undefined && ts.isNamespaceImport(bindings) && bindings.name.text === id.text) return moduleAt(module, st.moduleSpecifier, pool)
  }
  return undefined
}

/** A top-level const, let, function or class named `name` in `st`. */
function declaredIn(st: ts.Statement, name: string): ts.Node | undefined {
  if (ts.isVariableStatement(st)) return st.declarationList.declarations.find((d) => ts.isIdentifier(d.name) && d.name.text === name)
  if (ts.isClassDeclaration(st)) return st.name?.text === name ? st : undefined
  return ts.isFunctionDeclaration(st) && st.name?.text === name && st.body !== undefined ? st : undefined
}

/** A module-level name in `module`: its own declaration, or what it imports under that name. */
function moduleLevel(module: ts.SourceFile, name: string, pool: ReadonlyMap<string, ts.SourceFile>, hops: number): ts.Node | undefined {
  for (const own of module.statements) {
    const found = declaredIn(own, name)
    if (found !== undefined) return found
  }
  return importedBinding(module, name, pool, hops + 1)
}

/** The declaration a module exports as `name` (`default` included): its own, one it re-exports, or one an `export *` passes on. */
function exportedBinding(module: ts.SourceFile, name: string, pool: ReadonlyMap<string, ts.SourceFile>, hops: number): ts.Node | undefined {
  if (hops > 8) return undefined
  for (const st of module.statements) {
    if (name === 'default') {
      if (ts.isFunctionDeclaration(st) && isExported(st) && isDefault(st)) return st.body === undefined ? undefined : st
      if (ts.isClassDeclaration(st) && isExported(st) && isDefault(st)) return st
      if (ts.isExportAssignment(st) && !st.isExportEquals) {
        const value = unwrapped(st.expression)
        return ts.isIdentifier(value) ? moduleLevel(module, value.text, pool, hops) : st
      }
    }
    if (!ts.isExportDeclaration(st)) {
      const own = isExported(st) && !isDefault(st) ? declaredIn(st, name) : undefined
      if (own !== undefined) return own
      continue
    }
    const from = st.moduleSpecifier === undefined ? undefined : moduleAt(module, st.moduleSpecifier, pool)
    if (st.exportClause === undefined) {
      const passed = from === undefined || name === 'default' ? undefined : exportedBinding(from, name, pool, hops + 1)
      if (passed !== undefined) return passed
      continue
    }
    const el = ts.isNamedExports(st.exportClause) ? st.exportClause.elements.find((e) => e.name.text === name) : undefined
    if (el === undefined) continue
    const local = (el.propertyName ?? el.name).text
    if (st.moduleSpecifier !== undefined) return from === undefined ? undefined : exportedBinding(from, local, pool, hops + 1)
    return moduleLevel(module, local, pool, hops)
  }
  return undefined
}

/** Every name a module exports: its own, its default, and what it re-exports, `export *` followed. */
function exportNames(module: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>, hops = 0): string[] {
  if (hops > 8) return []
  const out: string[] = []
  for (const st of module.statements) {
    if (ts.isExportDeclaration(st)) {
      const from = st.moduleSpecifier === undefined ? undefined : moduleAt(module, st.moduleSpecifier, pool)
      if (st.exportClause === undefined) out.push(...(from === undefined ? [] : exportNames(from, pool, hops + 1).filter((n) => n !== 'default')))
      else if (ts.isNamedExports(st.exportClause)) out.push(...st.exportClause.elements.map((e) => e.name.text))
    } else if (ts.isExportAssignment(st)) {
      if (!st.isExportEquals) out.push('default')
    } else if (isExported(st)) {
      if (isDefault(st)) out.push('default')
      else if (ts.isVariableStatement(st)) out.push(...st.declarationList.declarations.flatMap((d) => (ts.isIdentifier(d.name) ? [d.name.text] : [])))
      else if (ts.isFunctionDeclaration(st) && st.name !== undefined) out.push(st.name.text)
    }
  }
  return out
}

/** Whether a module-level binding is, holds or returns .env's path: called with arguments the scan cannot see, a function counts by what it returns. */
function holdsDotenv(decl: ts.Node, pool: ReadonlyMap<string, ts.SourceFile>): boolean {
  const trace = traceIn(pool)
  // `export const where = envPath`: the function it is a second name for.
  const alias = constAlias(decl)
  const fn = functionOf(decl) ?? (alias === undefined ? undefined : calledFunction(alias, pool))
  if (fn !== undefined) return verdictOfAll(returnTails(fn, new Map(fn.parameters.map((p): [ts.ParameterDeclaration, undefined] => [p, undefined])), trace)) === 'dotenv'
  const value = ts.isVariableDeclaration(decl) ? decl.initializer : ts.isExportAssignment(decl) ? decl.expression : undefined
  const init = value === undefined ? undefined : unwrapped(value)
  if (init === undefined || !ts.isObjectLiteralExpression(init)) return verdictOfAll(bindingTails(decl, trace)) === 'dotenv'
  return init.properties.some((prop) => {
    const key = ts.isSpreadAssignment(prop) ? undefined : propertyKey(prop.name)
    if (key === undefined) return false
    const tails = ts.isVariableDeclaration(decl) ? propertyTails(decl, key, trace) : literalProperty(init, key, trace)
    return verdictOfAll(tails) === 'dotenv'
  })
}

/**
 * Whether a file speaks of .env's path: names it in a string ('.env', or a
 * path ending /.env, in any case), a template's text (`${root}/.env`) or the
 * loader's DOTENV_FILE, or imports, from a module the pool holds, a binding
 * that is, holds or returns it. In such a file a write whose path the scan
 * cannot follow is taken for a write of .env. Prose that mentions the file
 * ("which reads .env") is not its path.
 */
function speaksOfDotenv(source: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>): boolean {
  let found = false
  const visit = (node: ts.Node): void => {
    if (found) return
    if (ts.isImportDeclaration(node)) found = importsDotenv(node, source, pool)
    else if (ts.isStringLiteralLike(node)) {
      const text = node.text.toLowerCase()
      found = text === DOTENV || text.endsWith(`/${DOTENV}`)
    } else if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) found = /(?:^|\/)\.env(?![\w.-])/i.test(node.text)
    else if (ts.isIdentifier(node) && node.text === 'DOTENV_FILE') found = true
    else ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

function importsDotenv(st: ts.ImportDeclaration, source: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>): boolean {
  const module = moduleAt(source, st.moduleSpecifier, pool)
  const clause = st.importClause
  if (module === undefined || clause === undefined) return false
  const bindings = clause.namedBindings
  const names = [
    ...(clause.name === undefined ? [] : ['default']),
    ...(bindings === undefined
      ? []
      : ts.isNamedImports(bindings)
        ? bindings.elements.map((el) => (el.propertyName ?? el.name).text)
        : // A namespace brings every export, re-exports included.
          exportNames(module, pool)),
  ]
  return names.some((name) => {
    const decl = exportedBinding(module, name, pool, 0)
    return decl !== undefined && holdsDotenv(decl, pool)
  })
}

/**
 * A call that writes, creates, moves, copies, links or deletes a path, or a
 * write function handed on as a value: what it is reported as, and the paths
 * it writes as far as the scan can follow them.
 */
interface WriteCall {
  readonly node: ts.Node
  readonly name: string
  readonly tails: (trace: Trace) => readonly Tail[]
}

/** The arguments a call passes its callee: `f.call(self, …)` and `f.apply(self, […])` pass theirs on; undefined when they cannot be lined up. */
function passedArguments(call: ts.CallExpression, viaCall: 'call' | 'apply' | undefined): readonly ts.Expression[] | undefined {
  if (viaCall === undefined) return call.arguments
  if (viaCall === 'call') return call.arguments.slice(1)
  const list = call.arguments[1]
  const given = list === undefined ? undefined : unwrapped(list)
  return given !== undefined && ts.isArrayLiteralExpression(given) ? given.elements : undefined
}

/** The tails of `args` at `positions`: unseen at a position a spread may fill. */
function tailsAt(args: readonly ts.Expression[] | undefined, positions: readonly number[], trace: Trace): Tail[] {
  if (args === undefined) return [UNSEEN]
  const tails: Tail[] = []
  for (const i of positions) {
    const arg = args[i]
    if (args.slice(0, i + 1).some((a) => ts.isSpreadElement(a))) tails.push(UNSEEN)
    else if (arg !== undefined) tails.push(...tailsOf(arg, trace))
  }
  return tails
}

/** By whether calls into other modules count: worked out once per file and rule. */
const WRITE_CALLS = { across: new WeakMap<ts.SourceFile, WriteCall[]>(), within: new WeakMap<ts.SourceFile, WriteCall[]>() }

/**
 * Every write in a file: an fs write call by whatever name it is made
 * (renamed, aliased, through a module object, `.call`/`.apply`), a
 * FileHandle's chmod/chown/utimes, an fs write function used as a value
 * (its path unseen), and, when `across` is set, a call into another module's
 * function that writes the path a parameter gives it (writeParams).
 */
function writeCallsIn(source: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>, across: boolean): WriteCall[] {
  const cache = across ? WRITE_CALLS.across : WRITE_CALLS.within
  const cached = cache.get(source)
  if (cached !== undefined) return cached
  const out: WriteCall[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node) || ts.isTypeNode(node)) return
    if (ts.isCallExpression(node)) {
      const write = writeOf(node, source, pool, across)
      if (write !== undefined) out.push(write)
    } else if (ts.isNewExpression(node)) {
      // `new fs.WriteStream(path)`: a constructor that opens its path for writing.
      const name = builtinName(node.expression, pool)
      const positions = name === undefined ? undefined : PATH_ARGS.get(name)
      const args = node.arguments ?? []
      if (name !== undefined && positions !== undefined) out.push({ node, name, tails: (trace) => tailsAt(args, positions, trace) })
    } else if ((ts.isIdentifier(node) && !isPropertyName(node)) || ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = valueUse(node, pool)
      if (name !== undefined) {
        out.push({ node, name, tails: () => [UNSEEN] })
        return
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  cache.set(source, out)
  return out
}

function writeOf(call: ts.CallExpression, source: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>, across: boolean): WriteCall | undefined {
  let callee = unwrapped(call.expression)
  let viaCall: 'call' | 'apply' | undefined
  if (ts.isPropertyAccessExpression(callee) && (callee.name.text === 'call' || callee.name.text === 'apply')) {
    const target = builtinName(callee.expression, pool)
    if (target !== undefined && PATH_ARGS.has(target)) {
      viaCall = callee.name.text
      callee = unwrapped(callee.expression)
    }
  }
  const args = passedArguments(call, viaCall)
  const name = builtinName(callee, pool)
  const positions = name === undefined ? undefined : PATH_ARGS.get(name)
  if (name !== undefined && positions !== undefined) {
    if ((name === 'openSync' || name === 'open') && args !== undefined && opensReadOnly(args[1])) return undefined
    // A FileHandle's chmod(mode): the file is the handle, not the argument.
    if (HANDLE_WRITES.has(name) && ts.isPropertyAccessExpression(callee) && moduleBinding(callee.expression) === undefined) {
      const handle = callee.expression
      return { node: call, name, tails: (trace) => tailsOf(handle, trace) }
    }
    return { node: call, name, tails: (trace) => tailsAt(args, positions, trace) }
  }
  if (!across) return undefined
  const fn = calledFunction(callee, pool)
  if (fn === undefined || fn.getSourceFile() === source) return undefined
  const through = writeParams(fn, pool)
  if (through.length === 0) return undefined
  return { node: call, name: callee.getText(source), tails: (trace) => tailsAt(args, through, trace) }
}

/** The fs write function `node` is, when it is used as a value rather than called: handed to forEach, bound, exported, stored. */
function valueUse(node: ts.Expression, pool: ReadonlyMap<string, ts.SourceFile>): string | undefined {
  const name = fsFunction(node, pool)
  if (name === undefined || !PATH_ARGS.has(name)) return undefined
  let at: ts.Node = node
  while (ts.isParenthesizedExpression(at.parent) || ts.isAsExpression(at.parent) || ts.isNonNullExpression(at.parent) || ts.isSatisfiesExpression(at.parent)) at = at.parent
  const parent = at.parent
  // Called, or constructed: the call is the write.
  if ((ts.isCallExpression(parent) || ts.isNewExpression(parent)) && parent.expression === at) return undefined
  if (ts.isPropertyAccessExpression(parent) && parent.expression === at && (parent.name.text === 'call' || parent.name.text === 'apply')) {
    if (ts.isCallExpression(parent.parent) && parent.parent.expression === parent) return undefined
  }
  // A declaration's own name; an alias, followed wherever it is used; typeof is not a use.
  if ((ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent) || ts.isFunctionDeclaration(parent)) && parent.name === at) return undefined
  if (ts.isVariableDeclaration(parent) && parent.initializer === at && ts.isIdentifier(parent.name)) return undefined
  if (ts.isTypeOfExpression(parent)) return undefined
  return name
}

const WRITE_PARAMS = new WeakMap<Fn, readonly number[]>()

/**
 * The parameters whose value a function writes as a path: those that, taken
 * to be .env, make a write in its module .env, and taken to be another file,
 * do not. A function that writes .env whatever it is given (the writer) has
 * none; its callers hand it no path. One level: a write two modules away is
 * not followed.
 */
function writeParams(fn: Fn, pool: ReadonlyMap<string, ts.SourceFile>): readonly number[] {
  const seen = WRITE_PARAMS.get(fn)
  if (seen !== undefined) return seen
  const writes = writeCallsIn(fn.getSourceFile(), pool, false)
  const out: number[] = []
  if (writes.length > 0) {
    fn.parameters.forEach((p, i) => {
      if (p.dotDotDotToken !== undefined) return
      const assume = (probe: Tail): Bound => new Map(fn.parameters.map((q): [ts.ParameterDeclaration, (readonly Tail[])[]] => [q, [q === p ? [probe] : [UNSEEN]]]))
      const asEnv = assume(known('/.env'))
      const asOther = assume(known('/other'))
      const through = writes.some((w) => verdictOfAll(w.tails(traceIn(pool, asEnv))) === 'dotenv' && verdictOfAll(w.tails(traceIn(pool, asOther))) !== 'dotenv')
      if (through) out.push(i)
    })
  }
  WRITE_PARAMS.set(fn, out)
  return out
}

/** Whether a file reads .env's values: a read call whose path is .env, or, in the installer, the loader's own calls. */
function readsDotenv(source: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>): boolean {
  const installer = INSTALLER.test(source.fileName)
  return calls(source).some((call) => {
    if (installer && isLoaderCall(call.expression)) return true
    const callee = builtinName(call.expression, pool)
    return callee !== undefined && READ_CALLS.has(callee) && verdictOfAll(tailsAt(call.arguments, [0], traceIn(pool))) === 'dotenv'
  })
}

/**
 * Whether a callee is one of the loader's reads under any name: by its own
 * (`loadDotenv`, `d.loadDotenv`, `d['loadDotenv']`), as the import it binds
 * (`loadDotenv as load`), destructured (`const { loadDotenv: load } = d`,
 * or from import()), or as a const that names one (`const load = loadDotenv`).
 */
function isLoaderCall(callee: ts.Expression, depth = 0): boolean {
  const e = unwrapped(callee)
  if (depth > 8) return false
  const own = ts.isIdentifier(e)
    ? e.text
    : ts.isPropertyAccessExpression(e)
      ? e.name.text
      : ts.isElementAccessExpression(e) && ts.isStringLiteralLike(e.argumentExpression)
        ? e.argumentExpression.text
        : undefined
  if (own !== undefined && LOADER_READS.has(own)) return true
  if (!ts.isIdentifier(e)) return false
  const local = declarationOf(e)
  if (local !== undefined) {
    return ts.isVariableDeclaration(local) && local.initializer !== undefined && isLoaderCall(local.initializer, depth + 1)
  }
  const from = importOf(e)
  if (from !== undefined) return LOADER_READS.has(from.name)
  const element = destructured(e)
  return element !== undefined && LOADER_READS.has(element.property)
}

/** Which of the scan's rules apply: following each path (always), and the two that stand in where a path cannot be followed. */
interface Rules {
  /** In a file that reads .env's values, every write counts: a read and a write make a copy. */
  readonly copy: boolean
  /** In a file that speaks of .env, a write the scan cannot follow counts. */
  readonly unseen: boolean
}
const ALL_RULES: Rules = { copy: true, unseen: true }

/**
 * The calls in a file that write, create, move, copy, link or delete .env,
 * or may, as `callee:line`. A call counts when a path it takes is .env, or
 * when the scan cannot follow that path and the file speaks of .env; in a
 * file that reads .env's bytes every such call counts, since a read and a
 * write make a copy. An open() counts only with flags that can write. A
 * message that names .env, or a lock file beside one, is not one.
 */
function dotenvWrites(source: ts.SourceFile, pool: ReadonlyMap<string, ts.SourceFile>, rules: Rules = ALL_RULES): string[] {
  const speaks = rules.unseen && speaksOfDotenv(source, pool)
  const reads = rules.copy && readsDotenv(source, pool)
  const out: string[] = []
  for (const write of writeCallsIn(source, pool, true)) {
    const verdict = reads ? 'dotenv' : verdictOfAll(write.tails(traceIn(pool)))
    if (verdict === 'dotenv' || (verdict === 'unknown' && speaks)) {
      out.push(`${write.name}:${String(source.getLineAndCharacterOfPosition(write.node.getStart(source)).line + 1)}`)
    }
  }
  return out
}

/** src/ and scripts/ as the compiler reads them, by path: the pool the scan follows imports through. */
const WRITE_POOL: ReadonlyMap<string, ts.SourceFile> = new Map([...SRC, ...SCRIPTS].map((f) => [f.path, parsed(f)]))

test('only src/secrets/dotenv-append.ts opens .env for writing in src/ or scripts/, and only scripts/install.ts, scripts/install/* and their tests import it; the kernel, main, cli and eval never do', () => {
  // CLAUDE.md: exactly one code path writes <repo>/.env, the installer's.
  // A second writer, or a kernel that could reach this one, would be a way
  // to change the operator's keys that no confirmation stands in front of.
  const WRITER = 'src/secrets/dotenv-append.ts'
  const writers = [...WRITE_POOL.values()].map((s) => ({ path: s.fileName, writes: dotenvWrites(s, WRITE_POOL) })).filter((f) => f.writes.length > 0)
  assert.deepEqual(writers.map((f) => f.path), [WRITER])
  // The writer's write calls: the create, the fchmod through its descriptor,
  // the append, and the removal of a file it created and then refused. Its
  // read-only opens are not writes. A new write call here is looked at.
  const callees = (writes: readonly string[]): string[] => writes.map((w) => w.split(':')[0] ?? '').sort()
  const WRITES = ['fchmodSync', 'openSync', 'openSync', 'unlinkSync']
  assert.deepEqual(callees(writers[0]?.writes ?? []), WRITES, JSON.stringify(writers[0]?.writes))
  // The writer reads .env and speaks of it, so either stand-in rule alone
  // flags every write in it, followed or not. With both off, each of those
  // calls must still be found by following its path to .env, through the
  // writer's own helpers (dotenvPathIn, append, create, appendTo, removeCreated).
  const writer = WRITE_POOL.get(WRITER)
  assert.ok(writer !== undefined && readsDotenv(writer, WRITE_POOL) && speaksOfDotenv(writer, WRITE_POOL), 'the scan no longer sees the writer read .env')
  assert.deepEqual(callees(dotenvWrites(writer, WRITE_POOL, { copy: false, unseen: false })), WRITES, 'the scan no longer follows the writer\'s path to .env')

  // And in src/ the write-mode open flags are the writer's alone.
  const WRITE_FLAGS = new Set(['O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_APPEND', 'O_TRUNC'])
  const flagged = SRC.filter((f) => {
    let found = false
    const visit = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && WRITE_FLAGS.has(node.text)) found = true
      else ts.forEachChild(node, visit)
    }
    visit(parsed(f))
    return found
  })
  assert.deepEqual(flagged.map((f) => f.path), [WRITER])

  // Who imports the writer: the installer and its tests, nothing else.
  const importers = importersOfModule([...SRC, ...TEST, ...SCRIPTS], WRITER)
  assert.ok(importers.includes('test/dotenv-append.test.ts'), 'the scan no longer sees the writer\'s own test importing it')
  for (const path of importers) {
    assert.match(path, /^(?:scripts\/install\.ts|scripts\/install\/[^/]+\.ts|test\/(?:dotenv-append|install-[\w-]+)\.test\.ts)$/, `${path} imports the .env writer`)
  }
  // Nor through anything they import, however deep.
  for (const root of ['src/kernel.ts', 'src/main.ts', 'src/cli/index.ts', 'scripts/eval.ts']) {
    const reached = reachedFrom([root], [...SRC, ...SCRIPTS])
    assert.equal(reached.has(WRITER), false, `${root} reaches the .env writer`)
  }
  // The walk is real: the daemon reaches the kernel and the loader.
  const daemon = reachedFrom(['src/main.ts'], [...SRC, ...SCRIPTS])
  assert.ok(daemon.has('src/kernel.ts') && daemon.has('src/secrets/dotenv.ts'), 'the import walk reaches nothing')
})

/** The scan over files written out here, by path: a scratch pool of their own. */
function scanFiles(files: Readonly<Record<string, string>>): Record<string, string[]> {
  const pool = new Map(Object.entries(files).map(([path, text]) => [path, ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)]))
  return Object.fromEntries([...pool].map(([path, source]) => [path, dotenvWrites(source, pool)]))
}
const scanOne = (text: string, path = 'scripts/install.ts'): string[] => scanFiles({ [path]: text })[path] ?? []

test('the .env write scan follows a path through a const, a parameter and a helper\'s return, and passes a lock file beside a message that names .env', () => {
  // The rule above is only as good as this: the plan's installer entry point
  // takes a lock with O_EXCL and reports the .env path, and must pass; a
  // second writer must not, however its path is spelled or passed around.
  const entryPoint = [
    "import { closeSync, openSync, writeSync } from 'node:fs'",
    "import { join } from 'node:path'",
    'export function main(root: string): string {',
    "  const lock = openSync(join(root, '.aos', 'install.lock'), 'wx')",
    '  writeSync(lock, String(process.pid))',
    '  closeSync(lock)',
    "  return `${join(root, '.env')}: names appended`",
    '}',
  ].join('\n')
  assert.deepEqual(scanOne(entryPoint), [])
  // Reading it is not writing it.
  assert.deepEqual(scanOne("openSync(join(root, '.env'), constants.O_RDONLY | constants.O_NOFOLLOW); readFileSync(join(root, DOTENV_FILE))"), [])

  const secondWriters = [
    "writeFileSync(join(root, '.env'), 'x')",
    "const p = join(root, DOTENV_FILE); appendFileSync(p, 'x')",
    "let p = ''; p = resolve(root, '.env'); createWriteStream(p)",
    'openSync(`${root}/.env`, constants.O_WRONLY | constants.O_APPEND)',
    "openSync(join(root, '.env'), flags)",
    "function put(file: string): void { writeFileSync(file, 'x') }\nput(join(root, '.env'))",
    "const envAt = (r: string): string => join(r, '.env')\nfs.openSync(envAt(root), 'a')",
    'function envAt(r: string): string { return join(r, DOTENV_FILE) }\nrenameSync(tmp, envAt(root))',
    "for (const f of [join(root, '.env')]) unlinkSync(f)",
  ]
  for (const text of secondWriters) assert.equal(scanOne(text).length, 1, text)
})

test('the .env write scan passes the installer\'s lock, logs and state file beside a message that names .env: through a paths object, a path helper and a paths module', () => {
  // A7 holds .aos/install.lock (O_EXCL plus pid, a stale one taken over); A3
  // writes each step's output to a 0600 file under .aos/install/<stamp>/ and
  // its state to .aos/install/active.json. In a file that speaks of .env every
  // write must be one the scan can follow, so these are the shapes it follows.
  const pathsObject = [
    "import { closeSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'",
    "import { join } from 'node:path'",
    'export function main(root: string): string {',
    "  const paths = { env: join(root, '.env'), lock: join(root, '.aos', 'install.lock') }",
    '  type Paths = typeof paths',
    '  let lock: number',
    "  try { lock = openSync(paths.lock, 'wx') } catch {",
    "    if (alive(Number(readFileSync(paths.lock, 'utf8')))) throw new Error('another install is running')",
    '    unlinkSync(paths.lock)',
    "    lock = openSync(paths.lock, 'wx')",
    '  }',
    '  // A descriptor is the file it opened.',
    '  writeFileSync(lock, String(process.pid))',
    '  closeSync(lock)',
    '  unlinkSync(paths.lock)',
    '  return `${paths.env}: names appended`',
    '}',
  ].join('\n')
  assert.deepEqual(scanOne(pathsObject), [])

  const pathHelper = [
    "import { closeSync, openSync, writeSync } from 'node:fs'",
    "import { join } from 'node:path'",
    'export function main(root: string): string {',
    '  const at = (...parts: string[]): string => join(root, ...parts)',
    "  const lock = openSync(at('.aos', 'install.lock'), 'wx')",
    '  writeSync(lock, String(process.pid))',
    '  closeSync(lock)',
    "  return `${at('.env')}: names appended`",
    '}',
  ].join('\n')
  assert.deepEqual(scanOne(pathHelper), [])

  const logs = [
    "import { appendFileSync, mkdirSync, openSync, renameSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs'",
    "import { join } from 'node:path'",
    'export function logTo(root: string, step: string): number {',
    "  const stamp = new Date().toISOString().replace(/[:.]/g, '-')",
    "  const dir = join(root, '.aos', 'install', stamp)",
    '  mkdirSync(dir, { recursive: true, mode: 0o700 })',
    '  const log = join(dir, `${step}.log`)',
    "  const fd = openSync(log, 'wx', 0o600)",
    "  appendFileSync(log, `appending to ${join(root, '.env')}\\n`)",
    '  truncateSync(log)',
    "  const active = join(root, '.aos', 'install', 'active.json')",
    '  writeFileSync(`${active}.tmp`, JSON.stringify({ step, pid: process.pid }), { mode: 0o600 })',
    '  renameSync(`${active}.tmp`, active)',
    "  for (const old of [join(dir, 'stdout.log'), join(dir, 'stderr.log')]) unlinkSync(old)",
    '  return fd',
    '}',
  ].join('\n')
  assert.deepEqual(scanOne(logs, 'scripts/install/run.ts'), [])

  // A paths module: its helpers are followed into, so the lock beside the
  // message passes, and the module itself, which writes nothing, does too.
  const paths = [
    "import { join } from 'node:path'",
    "export const envPath = (root: string): string => join(root, '.env')",
    "export function lockPath(root: string): string { return join(root, '.aos', 'install.lock') }",
    "export const installDir = (root: string): string => join(root, '.aos', 'install')",
    "export const LOCK_NAME = 'install.lock'",
    "export const files = { env: join(process.cwd(), '.env') }",
  ].join('\n')
  const entry = [
    "import { openSync, writeFileSync, writeSync } from 'node:fs'",
    "import { join } from 'node:path'",
    "import { envPath, installDir, lockPath } from './install/paths.js'",
    'export function main(root: string): string {',
    "  const lock = openSync(lockPath(root), 'wx')",
    '  writeSync(lock, String(process.pid))',
    "  writeFileSync(join(installDir(root), 'active.json'), '{}')",
    '  return `${envPath(root)}: names appended`',
    '}',
  ].join('\n')
  assert.deepEqual(scanFiles({ 'scripts/install/paths.ts': paths, 'scripts/install.ts': entry }), { 'scripts/install/paths.ts': [], 'scripts/install.ts': [] })
  const asNamespace = [
    "import { openSync } from 'node:fs'",
    "import { join } from 'node:path'",
    "import * as paths from './install/paths.js'",
    'export function main(root: string): string {',
    "  openSync(paths.lockPath(root), 'wx')",
    "  openSync(join(root, '.aos', paths.LOCK_NAME), 'wx')",
    '  return `${paths.envPath(root)}: names appended`',
    '}',
  ].join('\n')
  assert.deepEqual(scanFiles({ 'scripts/install/paths.ts': paths, 'scripts/install.ts': asNamespace })['scripts/install.ts'], [])
  // The same helpers as an object's properties, shorthand or named: in a
  // file that speaks of .env the lock's open must be followed to pass.
  const pathsObject2 = `${paths}\nexport const at = { lockPath, envPath: envPath, dir: installDir }`
  const viaObject = [
    "import { openSync } from 'node:fs'",
    "import { at } from './install/paths.js'",
    'export function main(root: string): string {',
    "  openSync(at.lockPath(root), 'wx')",
    "  openSync(join(at.dir(root), 'active.json'), 'wx')",
    "  return `${at.envPath(root)} (${join(root, '.env')}): names appended`",
    '}',
  ].join('\n')
  assert.deepEqual(scanFiles({ 'scripts/install/paths.ts': pathsObject2, 'scripts/install.ts': viaObject }), { 'scripts/install/paths.ts': [], 'scripts/install.ts': [] })

  // A write helper of its own, followed to each call: the paths it is given
  // are what it writes. `process.stdout.write` is a property, not a call of it.
  const helpers = [
    "import { appendFileSync, writeFileSync } from 'node:fs'",
    "import { join } from 'node:path'",
    'export function record(root: string): void {',
    '  function write(file: string, text: string): void { writeFileSync(file, text) }',
    '  const append = (file: string, text: string): void => appendFileSync(file, text)',
    "  write(join(root, '.aos', 'install', 'active.json'), '{}')",
    "  append(join(root, '.aos', 'install', 'run.log'), `checked ${join(root, '.env')}\\n`)",
    "  process.stdout.write('done\\n')",
    '}',
  ].join('\n')
  assert.deepEqual(scanOne(helpers, 'scripts/install/run.ts'), [])
  // A file whose name only ends in .env is another file: pmmcp's beside the lock.
  assert.deepEqual(scanOne("const base = join(root, '.aos', 'pmmcp')\nwriteFileSync(base + '.env', 'x')\nconsole.log(join(root, '.env'))"), [])

  // A path given on the command line is the operator's (eval's --json): in
  // a file whose prose mentions .env but which never builds its path, it is
  // not taken for one. The scan cannot see what the operator will type, so
  // that limit is held by the programs themselves: eval and capture-pmmcp
  // refuse a path that names this checkout's .env however it is spelled
  // (namesRepoDotenv; entrypoints.test.ts runs both against the trap).
  assert.deepEqual(scanOne("writeFileSync(flag(argv, 'json'), report)\nprocess.stderr.write('export it, or run npm run eval, which reads .env\\n')", 'scripts/eval.ts'), [])

  // A7's stale-lock takeover and A3's stamped logs: a pid or a clock holds no
  // '/', so the segment it ends keeps the start the scan saw, which .env lacks.
  // And a lock helper's { fd, path }, followed into the object it returns.
  const speaking = "\nconsole.log(`${join(root, '.env')}: names appended`)"
  const locks = [
    "const lock = join(root, '.aos', 'install.lock')\nconst tmp = `${lock}.${process.pid}`\nwriteFileSync(tmp, String(process.pid), { flag: 'wx' })\nrenameSync(tmp, lock)",
    "const lock = join(root, '.aos', 'install.lock')\nwriteFileSync(lock + '.' + String(process.pid), 'x')",
    "function takeLock(root: string): { fd: number; path: string } {\n  const path = join(root, '.aos', 'install.lock')\n  const fd = openSync(path, 'wx')\n  return { fd, path }\n}\nconst lock = takeLock(root)\nwriteSync(lock.fd, String(process.pid))\ncloseSync(lock.fd)\nunlinkSync(lock.path)",
    "const stamp = new Date().toISOString().replace(/[:.]/g, '-')\nwriteFileSync(join(root, '.aos', 'install', `${stamp}.json`), '{}')\nwriteFileSync(`${join(root, '.aos', 'install', 'run')}-${stamp}-${Date.now()}`, '{}')",
    // The fs functions under other names, and a FileHandle's chmod: each followed to its path.
    "import { writeFileSync as put } from 'node:fs'\nput(join(root, '.aos', 'install.lock'), String(process.pid))",
    "import { promises } from 'node:fs'\nconst fsp = promises\nconst h = await fsp.open(join(root, '.aos', 'install.lock'), 'r')\nawait h.chmod(0o600)",
    "import fs from 'node:fs'\nconst rm = fs.rmSync\nrm(join(root, '.aos', 'install', 'old'), { recursive: true })\nfs['writeFileSync'].call(null, join(root, '.aos', 'install.lock'), 'x')",
    "import { writeFileSync } from 'node:fs'\nwriteFileSync.apply(null, [join(root, '.aos', 'install.lock'), String(process.pid)])",
    // An await, and a spread of known segments, are followed.
    "async function lockPath(r: string): Promise<string> { return join(r, '.aos', 'install.lock') }\nwriteFileSync(await lockPath(root), String(process.pid))",
    "writeFileSync(join(root, ...['.aos', 'install.lock']), String(process.pid))",
    // path's own join, called on the module as the examples here write it; a numbered or radix-36 suffix.
    "writeFileSync(path.join(root, '.aos', 'install.lock'), String(process.pid))",
    "const lock = join(root, '.aos', 'install.lock')\nwriteFileSync(lock + '.' + 1, 'x')\nwriteFileSync(`${lock}.${Date.now().toString(36)}`, 'x')",
    // An fs module object's own chmod takes the path, not a handle; a destructured
    // fs function, from the module or from import(); a WriteStream constructed.
    "fsp.chmod(join(root, '.aos', 'x'), 0o600)",
    "import fs from 'node:fs'\nconst { writeFileSync: put } = fs\nput(join(root, '.aos', 'install.lock'), String(process.pid))",
    "const { writeFile: put } = await import('node:fs/promises')\nawait put(join(root, '.aos', 'install', 'state.json'), '{}')",
    "import fs from 'node:fs'\nconst log = new fs.WriteStream(join(root, '.aos', 'install', 'run.log'))\nlog.end()",
  ]
  for (const text of locks) assert.deepEqual(scanOne(`${text}${speaking}`), [], text)
  // .envrc and .env.example are other files: naming them is not speaking of .env.
  assert.deepEqual(scanOne("writeFileSync(target, 'x')\nconsole.log(`${home}/.envrc`, join(root, '.env.example'))"), [])
  // An fs function handed on as a value writes a path the scan cannot see:
  // only in a file that speaks of .env is that taken for a write of it.
  assert.deepEqual(scanOne("import { unlinkSync } from 'node:fs'\n;[join(root, '.aos', 'a.log')].forEach(unlinkSync)"), [])
  // A helper in another module, called with a path under .aos, writes that path.
  const io = "import { writeFileSync } from 'node:fs'\nexport function put(file: string, text: string): void { writeFileSync(file, text) }"
  const record = `import { put } from './io.js'\nexport function record(root: string): void {\n  put(join(root, '.aos', 'install', 'active.json'), '{}')${speaking}\n}`
  assert.deepEqual(scanFiles({ 'scripts/install/io.ts': io, 'scripts/install/run.ts': record }), { 'scripts/install/io.ts': [], 'scripts/install/run.ts': [] })
  // So does a method of its object literal or class, and the helper under a second name.
  const ioMethods = [
    io,
    'export const io = { put(file: string, text: string): void { writeFileSync(file, text) } }',
    'export class Io { put(file: string, text: string): void { writeFileSync(file, text) } }',
    // A property naming the helper, shorthand or not, and a sibling through `this`.
    'export const short = { put, again: put }',
    'export class Raw {\n  save(file: string, text: string): void { this.raw(file, text) }\n  private raw(f: string, t: string): void { writeFileSync(f, t) }\n}',
    // A sibling through `this` that is a property holding a function, and a caller that is one.
    'export class Field {\n  save(file: string, text: string): void { this.raw(file, text) }\n  private raw = (f: string, t: string): void => writeFileSync(f, t)\n}',
    'export const lit = {\n  save: function (file: string, text: string): void { this.raw(file, text) },\n  raw: (f: string, t: string): void => writeFileSync(f, t),\n}',
  ].join('\n')
  const recordVia = [
    "import { Field, Io, Raw, io, lit, put, short } from './io.js'",
    "import * as m from './io.js'",
    "import dio from './dio.js'",
    "import Dcls from './dcls.js'",
    'export function record(root: string): void {',
    "  io.put(join(root, '.aos', 'install', 'active.json'), '{}')",
    "  new Io().put(join(root, '.aos', 'install', 'run.log'), 'x')",
    '  const save = put',
    "  save(join(root, '.aos', 'install', 'state.json'), '{}')",
    "  short.put(join(root, '.aos', 'install', 'a.json'), '{}')",
    "  short.again(join(root, '.aos', 'install', 'b.json'), '{}')",
    "  new Raw().save(join(root, '.aos', 'install', 'c.json'), '{}')",
    "  m.io.put(join(root, '.aos', 'install', 'd.json'), '{}')",
    "  new m.Io().put(join(root, '.aos', 'install', 'e.json'), '{}')",
    "  dio.put(join(root, '.aos', 'install', 'f.json'), '{}')",
    "  new Field().save(join(root, '.aos', 'install', 'g.json'), '{}')",
    "  lit.save(join(root, '.aos', 'install', 'h.json'), '{}')",
    `  new Dcls().put(join(root, '.aos', 'install', 'i.json'), '{}')${speaking}`,
    '}',
  ].join('\n')
  const dio = "import { writeFileSync } from 'node:fs'\nexport default { put(file: string, text: string): void { writeFileSync(file, text) } }"
  const dcls = "import { writeFileSync } from 'node:fs'\nexport default class { put(file: string, text: string): void { writeFileSync(file, text) } }"
  assert.deepEqual(
    scanFiles({ 'scripts/install/io.ts': ioMethods, 'scripts/install/dio.ts': dio, 'scripts/install/dcls.ts': dcls, 'scripts/install/run.ts': recordVia }),
    { 'scripts/install/io.ts': [], 'scripts/install/dio.ts': [], 'scripts/install/dcls.ts': [], 'scripts/install/run.ts': [] },
  )
  // The installer's own calls into the writer, which writes .env whatever it
  // is handed: they pass no path, so they are not a second writer.
  const writer = WRITE_POOL.get('src/secrets/dotenv-append.ts')?.text ?? ''
  assert.ok(writer.includes('export function appendCredentials('), 'the writer moved')
  const installer = [
    "import { appendCredentials, credentialNames, inspectCredentials, mintedCredentialNames } from '../src/secrets/dotenv-append.js'",
    'export function credentials(root: string, config: KernelConfig, providers: ProvidersFile): void {',
    '  const accepted = credentialNames(config, providers)',
    "  const seen = inspectCredentials({ repoRoot: root, accepted, names: ['AOS_CONTROL_TOKEN'] })",
    "  if (seen.missing.length > 0) appendCredentials({ repoRoot: root, accepted, generatable: mintedCredentialNames(config), providers, generate: new Map([['AOS_CONTROL_TOKEN', () => 'x']]) })",
    "  console.log(`${join(root, '.env')}: ${seen.missing.join(', ')}`)",
    '}',
  ].join('\n')
  assert.deepEqual(scanFiles({ 'src/secrets/dotenv-append.ts': writer, 'scripts/install.ts': installer })['scripts/install.ts'], [])
  // The loader read as a read of .env is the installer's rule only: eval and
  // the daemon read it and write other files by design.
  const loaded = "const got = loadDotenv(join(root, DOTENV_FILE), opts)\nwriteFileSync(join(root, '.aos', 'install', 'state.json'), JSON.stringify(Object.keys(got.values)))"
  assert.deepEqual(scanOne(loaded, 'scripts/report.ts'), [])
})

test('the .env write scan works out a path built from itself once per binding, and past its step budget calls a path unseen rather than stall', () => {
  // `p = join(p, …)` k times was followed into every order of the k
  // assignments: k! walks, so nine of them in a 300-function file took
  // minutes, and npm test with it. Each node is now worked out once per
  // binding, and any path that would take more than MAX_STEPS nodes is
  // unseen: flagged in a file that speaks of .env, like any path the scan
  // cannot follow.
  const chain = (k: number, segment: (i: number) => string): string =>
    ["let p = join(root, '.aos')", ...Array.from({ length: k }, (_, i) => `if (c${String(i)}) p = join(p, '${segment(i)}')`), "writeFileSync(p, 'x')"].join('\n')
  const functions = Array.from({ length: 300 }, (_, i) => `export function g${String(i)}(a: string): string { const b = join(a, 'x${String(i)}'); return b }`).join('\n')
  const started = Date.now()
  assert.deepEqual(scanOne(`${functions}\n${chain(9, (i) => `d${String(i)}`)}`), [])
  // Once each node, it is a fraction of a second; every order of nine, minutes.
  assert.ok(Date.now() - started < 10_000, `the scan took ${String(Date.now() - started)} ms over a self-built path`)
  // Worked out, not given up on: every value it can hold ends in .aos or x,
  // so in a file that speaks of .env it still passes. Walked in every order,
  // six of them run past the step budget and the path would be unseen.
  assert.deepEqual(scanOne(`${chain(6, () => 'x')}\nconsole.log(join(root, '.env'))`), [])
  // A path no binding repeats, past the budget: f14 calls f13 twice, each
  // call its own binding, 2^14 of them. Unseen, so flagged here, though every
  // value it could hold is a file under .aos.
  const doubling = [
    'const f0 = (x: string): string => x',
    ...Array.from({ length: 14 }, (_, i) => `const f${String(i + 1)} = (x: string): string => f${String(i)}(x) + f${String(i)}(x)`),
    "writeFileSync(join(root, '.aos', f14('a')), 'x')",
    "console.log(join(root, '.env'))",
  ].join('\n')
  assert.equal(scanOne(doubling).length, 1)
  // And without .env spoken of, an unseen path is not a write of it.
  assert.deepEqual(scanOne(doubling.replace("console.log(join(root, '.env'))", '')), [])
})

test('the .env write scan flags a second writer however its path arrives: a copy, link or move from .env, a field, a method, a property, an import, a read and a write, an fs function under another name, a helper in another module, any case, and a path it cannot follow in a file that speaks of .env', () => {
  const at = 'scripts/install/env.ts'
  const secondWriters = [
    // From .env: the source of a copy, a link or a move.
    "copyFileSync(join(root, '.env'), join(root, '.aos', 'env.bak'))",
    "await copyFile(join(root, DOTENV_FILE), join(root, '.aos', 'env.bak'))",
    "await fs.promises.cp(join(root, '.env'), backup)",
    "linkSync(join(root, '.env'), join(root, '.aos', 'env'))",
    "symlink(join(root, '.env'), join(root, '.aos', 'env'), () => undefined)",
    "renameSync(join(root, '.env'), join(root, '.aos', 'env.old'))",
    // A class field, an object-literal method, a property write.
    "export class Env {\n  private readonly file: string\n  constructor(root: string) { this.file = join(root, '.env') }\n  put(text: string): void { writeFileSync(this.file, text) }\n}",
    "const io = { put: (file: string, text: string): void => writeFileSync(file, text) }\nexport function restore(root: string, text: string): void { io.put(join(root, '.env'), text) }",
    "export function restore(root: string, text: string): void {\n  const where: { env?: string } = {}\n  where.env = join(root, '.env')\n  writeFileSync(where.env, text)\n}",
    // Its bytes read, and any file written: a copy by hand.
    "writeFileSync(join(root, '.aos', 'env.bak'), readFileSync(join(root, '.env')))",
    "createReadStream(join(root, DOTENV_FILE)).pipe(createWriteStream(join(root, '.aos', 'env.bak')))",
    // A path the scan cannot follow, in a file that speaks of .env.
    "const target = process.argv[2] ?? ''\nwriteFileSync(target, 'x')\nconsole.log(`left ${join(root, '.env')} alone`)",
    "rmSync(root, { recursive: true, force: true })\nconsole.log(`${root}/.env is gone`)",
    "const paths = { env: join(root, '.env') }\nwriteFileSync(paths['env'], 'x')",
    "const { env } = { env: join(root, '.env') }\nwriteFileSync(env, 'x')",
    "export class Env {\n  file = join(root, DOTENV_FILE)\n  put(text: string): void { writeFileSync(this.file, text) }\n}",
    "openSync(`${base}.env`, 'w')",
    "rmSync(`${root}.old/..`, { recursive: true, force: true })\nconst env = join(root, '.env')",
    "writeFileSync([root, '.env'].join('/'), 'x')",
    // path.join reads `..` as the filesystem would.
    "writeFileSync(join(root, '.env', 'old', '..'), 'x')",
    // A helper a caller the scan cannot see may call: exported, or handed on as a value.
    "export function put(file: string, text: string): void { writeFileSync(file, text) }\nexport const envFile = join(root, '.env')",
    "function put(file: string): void { writeFileSync(file, 'x') }\n[join(root, '.env')].forEach(put)",
    // A value given where the scan cannot read it.
    "let p = join(root, '.aos', 'x')\n;[p] = [join(root, '.env')]\nwriteFileSync(p, 'x')",
    "let p = join(root, '.aos')\np += '/../.env'\nwriteFileSync(p, 'x')",
    "const paths = { lock: join(root, '.aos', 'install.lock') }\nObject.assign(paths, { lock: join(root, '.env') })\nwriteFileSync(paths.lock, 'x')",
    // More values than the scan carries, and a path built from itself.
    "for (const f of ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', join(root, '.env')]) unlinkSync(f)",
    "let p = join(root, '.aos', 'x')\np = `${p}/../../.env`\nwriteFileSync(p, 'x')",
    // A default, both branches of a choice, the comma operator, `.` as a segment.
    "const envAt = (r = join(root, '.env')): string => r\nwriteFileSync(envAt(), 'x')",
    "function put(file = join(root, '.env')): void { writeFileSync(file, 'x') }\nput()",
    "writeFileSync(dry ? join(root, '.aos', 'plan.txt') : join(root, '.env'), 'x')",
    "writeFileSync((0, join(root, '.env')), 'x')",
    "writeFileSync(join(root, '.env', '.'), 'x')",
    // A spread, a getter, a loop over objects or keys, a spread in a loop or a call.
    "const base = { env: join(root, '.env') }\nconst paths = { ...base, lock: join(root, '.aos', 'install.lock') }\nwriteFileSync(paths.env, 'x')",
    "const paths = { get env(): string { return join(root, '.env') } }\nwriteFileSync(paths.env, 'x')",
    "for (const o of [{ p: join(root, '.env') }]) writeFileSync(o.p, 'x')",
    "for (const f in { [join(root, '.env')]: 1 }) unlinkSync(f)",
    "const extra = [join(root, '.env')]\nfor (const f of [...extra, join(root, '.aos', 'install.lock')]) rmSync(f, { force: true })",
    "function put(file: string): void { writeFileSync(file, 'x') }\nconst targets = [join(root, '.env')]\nput(...targets)",
    // A compound write to a property, and a rest parameter used whole.
    "const p = { f: join(root, '.e') }\np.f += 'nv'\nwriteFileSync(p.f, 'x')\nconsole.log(join(root, '.env'))",
    "function put(...files: string[]): void { writeFileSync(`${files}`, 'x') }\nput(join(root, '.aos', 'a'), join(root, '.env'))",
    "const at = (...parts: string[]): string => `${parts}`\nwriteFileSync(at(join(root, '.aos', 'a'), join(root, '.env')), 'x')",
    // The fs function under another name, handed on as a value, called through call/apply/bind.
    "import { writeFileSync as put } from 'node:fs'\nput(join(root, '.env'), 'x')",
    "import { writeFileSync } from 'node:fs'\nconst put = writeFileSync\nput(join(root, '.env'), 'x')",
    "import * as fs from 'node:fs'\nconst put = fs.writeFileSync\nput(join(root, '.env'), 'x')",
    "import { unlinkSync } from 'node:fs'\n;[join(root, '.env')].forEach(unlinkSync)",
    "import * as fs from 'node:fs'\n;[join(root, '.env')].forEach(fs['unlinkSync'])",
    "import fs from 'node:fs'\nawait Promise.all([join(root, '.env')].map(fs.promises.unlink))",
    "import fs from 'node:fs'\nfs['writeFileSync'](join(root, '.env'), 'x')",
    "import { writeFileSync } from 'node:fs'\nwriteFileSync.call(null, join(root, '.env'), 'x')",
    "import { writeFileSync } from 'node:fs'\nwriteFileSync.apply(null, [join(root, '.env'), 'x'])",
    "import { writeFileSync } from 'node:fs'\nconst put = writeFileSync.bind(null, join(root, '.env'))\nput('x')",
    // Its mode, owner or times: through a descriptor opened only to read, a link's own, a FileHandle's.
    "import { fchmodSync, openSync } from 'node:fs'\nfchmodSync(openSync(join(root, '.env'), 'r'), 0o644)",
    "import { lchmodSync } from 'node:fs'\nlchmodSync(join(root, '.env'), 0o644)",
    "import { lutimesSync } from 'node:fs'\nlutimesSync(join(root, DOTENV_FILE), 0, 0)",
    "import { open } from 'node:fs/promises'\nconst h = await open(join(root, '.env'), 'r')\nawait h.chmod(0o644)",
    // Any case: on APFS, .ENV is the operator's .env.
    "writeFileSync(join(root, '.ENV'), 'x')",
    "copyFileSync(join(root, '.Env'), backup)",
    "writeFileSync(target, 'x')\nconsole.log(join(root, '.ENV'))",
    "writeFileSync(target, 'x')\nconsole.log(`${root}/.ENV`)",
    "writeFileSync(`${root}/.E${'v'.replace('v', 'NV')}`, 'x')\nconsole.log(join(root, '.env'))",
    // A part the scan cannot see may hold a '/': the start it saw before it is no guide.
    "export function stage(root: string, suffix: string): void {\n  writeFileSync(`${join(root, '.aos', 'install.lock')}.${suffix}`, 'x')\n  console.log(join(root, '.env'))\n}",
    "export function stage(root: string, suffix: string): void {\n  writeFileSync(join(root, '.aos', 'install.lock') + '.' + suffix, 'x')\n  console.log(join(root, '.env'))\n}",
    "export function stage(root: string, name: string): void {\n  writeFileSync(`${join(root, '.aos', 'x')}.${name.replace(':', '-')}`, 'x')\n  console.log(join(root, '.env'))\n}",
    "writeFileSync(`${join(root, '.aos', 'x')}.${'v'.replace('v', '/../../.env')}`, 'x')",
    // A segment with no '/' in it, after a '/' the scan saw: what came before that '/' is not its start.
    "writeFileSync(join(root, 'abc') + `/${'v'.replace('v', '.env')}`, 'x')",
    // `..` as the last segment makes the one before it last.
    "export function stage(root: string, x: string): void {\n  writeFileSync(`${x}..`, 'x')\n  console.log(join(root, '.env'))\n}",
    // A WORD that may be empty, after .env, leaves the last segment .env.
    "const stamp = new Date().toISOString()\nwriteFileSync(join(root, '.env') + stamp.replace(/.*/, ''), 'x')",
    // What only looks like a pid or a word: another object's pid (a lock
    // file's, which may hold '/../.env'), and String() of a parameter.
    "const lock = join(root, '.aos', 'install.lock')\nconst old = JSON.parse(readFileSync(lock, 'utf8'))\nwriteFileSync(`${lock}.${old.pid}`, 'x')\nconsole.log(join(root, '.env'))",
    "export function stage(root: string, suffix: string): void {\n  writeFileSync(`${join(root, '.aos', 'install.lock')}.${String(suffix)}`, 'x')\n  console.log(join(root, '.env'))\n}",
    // An fs function destructured from the module or from import(), and a WriteStream constructed.
    "import fs from 'node:fs'\nconst { writeFileSync: put } = fs\nput(join(root, '.env'), 'x')",
    "const { writeFile: put } = await import('node:fs/promises')\nawait put(join(root, '.env'), 'x')",
    "import fs from 'node:fs'\nnew fs.WriteStream(join(root, '.env'))",
    "import { WriteStream } from 'node:fs'\nnew WriteStream(join(root, '.env'))",
    // An argument list it cannot read, in a file that names .env.
    "import { writeFileSync } from 'node:fs'\nwriteFileSync.apply(null, args)\nconsole.log(join(root, '.env'))",
    // The fs module's own chmod takes a path, not a handle: followed to .env.
    "fsp.chmod(join(root, '.e' + 'nv'), 0o644)",
  ]
  for (const text of secondWriters) assert.equal(scanOne(text, at).length, 1, text)

  // In the installer, the loader's own reads are reads of .env: a write
  // beside one can carry its values out, as the plan's "no backup copy" forbids.
  for (const [path, text] of [
    ['scripts/install/state.ts', "const got = loadDotenv(join(root, DOTENV_FILE), opts)\nwriteFileSync(join(root, '.aos', 'install', 'state.json'), JSON.stringify(got.values))"],
    ['scripts/install.ts', "import { oneCredential } from '../src/secrets/dotenv.js'\nconst token = oneCredential('AOS_PMMCP_TOKEN', path, opts)\nwriteFileSync(join(root, '.aos', 'install', 'digest'), digestOf(token))"],
    // Under another name: renamed, a const for it, a namespace's, destructured from import().
    ['scripts/install/env.ts', "import { loadDotenv as load } from '../../src/secrets/dotenv.js'\nconst got = load(path, opts)\nwriteFileSync(join(root, '.aos', 'install', 'state.json'), JSON.stringify(got.values))"],
    ['scripts/install/env.ts', "import { loadDotenv } from '../../src/secrets/dotenv.js'\nconst load = loadDotenv\nconst got = load(path, opts)\nwriteFileSync(join(root, '.aos', 'install', 'state.json'), JSON.stringify(got.values))"],
    ['scripts/install/env.ts', "import * as d from '../../src/secrets/dotenv.js'\nconst got = d.loadDotenv(path, opts)\nwriteFileSync(join(root, '.aos', 'install', 'state.json'), JSON.stringify(got.values))"],
    ['scripts/install/env.ts', "const { oneCredential: one } = await import('../../src/secrets/dotenv.js')\nconst token = one('AOS_PMMCP_TOKEN', path, opts)\nwriteFileSync(join(root, '.aos', 'install', 'digest'), token)"],
  ] as const) {
    assert.equal(scanOne(text, path).length, 1, text)
  }

  // Through an import, into a module that writes nothing and spells .env
  // where the writer does not: a helper, a field, a re-export, a namespace.
  const paths = [
    "import { join } from 'node:path'",
    "export const envPath = (root: string): string => join(root, '.env')",
    "export const files = { env: join(process.cwd(), '.env') }",
    // The helper under a second name.
    'export const where = envPath',
  ].join('\n')
  const viaImport = [
    "import { where } from './paths.js'\nexport function restore(root: string, text: string): void { writeFileSync(where(root), text) }",
    "import { where } from './paths.js'\nexport class Env {\n  file = where(process.cwd())\n  put(text: string): void { writeFileSync(this.file, text) }\n}",
    "import { envPath } from './paths.js'\nexport function restore(root: string, text: string): void { writeFileSync(envPath(root), text) }",
    "import { envPath } from './paths.js'\nexport class Env {\n  private readonly file: string\n  constructor(root: string) { this.file = envPath(root) }\n  put(text: string): void { writeFileSync(this.file, text) }\n}",
    "import { dotenvAt } from './index.js'\nexport function restore(root: string, text: string): void { writeFileSync(dotenvAt(root), text) }",
    "import * as where from './paths.js'\nexport function restore(root: string, text: string): void { writeFileSync(where.envPath(root), text) }",
    "import { files } from './paths.js'\nexport class Env {\n  target = files.env\n  put(text: string): void { writeFileSync(this.target, text) }\n}",
    "import * as where from './paths.js'\nexport class Env {\n  target = where.envPath(process.cwd())\n  put(text: string): void { writeFileSync(this.target, text) }\n}",
  ]
  for (const text of viaImport) {
    const found = scanFiles({ 'scripts/install/paths.ts': paths, 'scripts/install/index.ts': "export { envPath as dotenvAt } from './paths.js'", [at]: text })
    assert.deepEqual(found['scripts/install/paths.ts'], [], text)
    assert.deepEqual(found['scripts/install/index.ts'], [], text)
    assert.deepEqual(found[at]?.map((w) => w.split(':')[0]), ['writeFileSync'], text)
  }

  // A default export, and a namespace of a barrel that only re-exports.
  const envClass = (file: string): string => `export class Env {\n  file = ${file}\n  put(t: string): void { writeFileSync(this.file, t) }\n}`
  const restore = "import envAt from './paths.js'\nexport function restore(root: string, t: string): void { writeFileSync(envAt(root), t) }"
  const viaModules: [Record<string, string>, string][] = [
    [{ 'scripts/install/paths.ts': "import { join } from 'node:path'\nexport default function (root: string): string { return join(root, '.env') }" }, restore],
    [{ 'scripts/install/paths.ts': "import { join } from 'node:path'\nexport default (root: string): string => join(root, '.env')" }, restore],
    [{ 'scripts/install/paths.ts': "import { join } from 'node:path'\nconst envPath = (root: string): string => join(root, '.env')\nexport default envPath" }, `import envAt from './paths.js'\n${envClass('envAt(process.cwd())')}`],
    [{ 'scripts/install/paths.ts': paths, 'scripts/install/index.ts': "export { envPath } from './paths.js'" }, `import * as where from './index.js'\n${envClass('where.envPath(process.cwd())')}`],
    [{ 'scripts/install/paths.ts': paths, 'scripts/install/index.ts': "export * from './paths.js'" }, `import * as where from './index.js'\n${envClass('where.envPath(process.cwd())')}`],
    // The helper as an object's property, shorthand or named.
    [{ 'scripts/install/paths.ts': `${paths}\nexport const at = { envPath }` }, "import { at } from './paths.js'\nexport function restore(root: string, t: string): void { writeFileSync(at.envPath(root), t) }"],
    [{ 'scripts/install/paths.ts': `${paths}\nexport const at = { env: envPath }` }, "import { at } from './paths.js'\nexport function restore(root: string, t: string): void { writeFileSync(at.env(root), t) }"],
  ]
  for (const [modules, text] of viaModules) {
    const found = scanFiles({ ...modules, [at]: text })
    for (const path of Object.keys(modules)) assert.deepEqual(found[path], [], `${path} for ${text}`)
    assert.deepEqual(found[at]?.map((w) => w.split(':')[0]), ['writeFileSync'], text)
  }

  // A write helper in a module that never names .env, handed .env's path:
  // the call is the write, by name, default or namespace, directly or
  // through a helper of its own; and in a file that speaks of .env, handed a
  // path the scan cannot follow.
  const io = "import { writeFileSync } from 'node:fs'\nexport function put(file: string, text: string): void { writeFileSync(file, text) }"
  const viaHelper: [string, string, string][] = [
    [io, "import { put } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { put(envPath(root), t) }", 'put'],
    [
      "import { writeFileSync } from 'node:fs'\nfunction write(file: string, text: string): void { writeFileSync(file, text) }\nexport function put(file: string, text: string): void { write(file, text) }",
      "import * as io from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    ["import { writeFileSync } from 'node:fs'\nexport default function (file: string, text: string): void { writeFileSync(file, text) }", "import put from './io.js'\nexport function restore(root: string, t: string): void { put(join(root, '.env'), t) }", 'put'],
    [io, "import { put } from './io.js'\nexport class Env {\n  target = join(process.cwd(), '.env')\n  save(t: string): void { put(this.target, t) }\n}", 'put'],
    // A method of an object literal or a class the module exports, an
    // instance it exports, and the helper under a second name.
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = { put(file: string, text: string): void { writeFileSync(file, text) } }",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = { put: (file: string, text: string): void => writeFileSync(file, text) }",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io { put(file: string, text: string): void { writeFileSync(file, text) } }",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { new Io().put(envPath(root), t) }",
      'new Io().put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io { put(file: string, text: string): void { writeFileSync(file, text) } }",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void {\n  const io = new Io()\n  io.put(envPath(root), t)\n}",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io { static put(file: string, text: string): void { writeFileSync(file, text) } }",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { Io.put(envPath(root), t) }",
      'Io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nclass Io { put(file: string, text: string): void { writeFileSync(file, text) } }\nexport const io = new Io()",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [io, "import { put } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void {\n  const save = put\n  save(envPath(root), t)\n}", 'save'],
    // A property that names the helper, shorthand or not; an object a module
    // exports as its default; a sibling a method reaches through `this`; an
    // object or class reached through a namespace import.
    [
      "import { writeFileSync } from 'node:fs'\nfunction put(file: string, text: string): void { writeFileSync(file, text) }\nexport const io = { put }",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nfunction put(file: string, text: string): void { writeFileSync(file, text) }\nexport const io = { put: put }",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport default { put(file: string, t: string): void { writeFileSync(file, t) } }",
      "import io from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io {\n  put(f: string, t: string): void { this.raw(f, t) }\n  private raw(f: string, t: string): void { writeFileSync(f, t) }\n}",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { new Io().put(envPath(root), t) }",
      'new Io().put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io {\n  static put(f: string, t: string): void { this.raw(f, t) }\n  static raw(f: string, t: string): void { writeFileSync(f, t) }\n}",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { Io.put(envPath(root), t) }",
      'Io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = {\n  put(f: string, t: string): void { this.raw(f, t) },\n  raw(f: string, t: string): void { writeFileSync(f, t) },\n}",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = { put(file: string, text: string): void { writeFileSync(file, text) } }",
      "import * as m from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { m.io.put(envPath(root), t) }",
      'm.io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io { put(file: string, text: string): void { writeFileSync(file, text) } }",
      "import * as m from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { new m.Io().put(envPath(root), t) }",
      'new m.Io().put',
    ],
    // A class the module exports as its default, an instance's or a static method.
    [
      "import { writeFileSync } from 'node:fs'\nexport default class Io { put(f: string, t: string): void { writeFileSync(f, t) } }",
      "import Io from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { new Io().put(envPath(root), t) }",
      'new Io().put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport default class { static put(f: string, t: string): void { writeFileSync(f, t) } }",
      "import Io from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { Io.put(envPath(root), t) }",
      'Io.put',
    ],
    // A sibling reached through `this` that is a property holding a function:
    // a class's arrow or function field, an object literal's arrow or
    // function property; and a caller that is an object literal's function
    // property, whose `this` is the object.
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io {\n  put(f: string, t: string): void { this.raw(f, t) }\n  private raw = (f: string, t: string): void => writeFileSync(f, t)\n}",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { new Io().put(envPath(root), t) }",
      'new Io().put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io {\n  put(f: string, t: string): void { this.raw(f, t) }\n  private raw = function (f: string, t: string): void { writeFileSync(f, t) }\n}",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void {\n  const io = new Io()\n  io.put(envPath(root), t)\n}",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport class Io {\n  static put(f: string, t: string): void { this.raw(f, t) }\n  static raw = (f: string, t: string): void => writeFileSync(f, t)\n}",
      "import { Io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { Io.put(envPath(root), t) }",
      'Io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = {\n  put(f: string, t: string): void { this.raw(f, t) },\n  raw: function (f: string, t: string): void { writeFileSync(f, t) },\n}",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = {\n  put(f: string, t: string): void { this.raw(f, t) },\n  raw: (f: string, t: string): void => writeFileSync(f, t),\n}",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    [
      "import { writeFileSync } from 'node:fs'\nexport const io = {\n  put: function (f: string, t: string): void { this.raw(f, t) },\n  raw(f: string, t: string): void { writeFileSync(f, t) },\n}",
      "import { io } from './io.js'\nimport { envPath } from './paths.js'\nexport function restore(root: string, t: string): void { io.put(envPath(root), t) }",
      'io.put',
    ],
    // A spread fills the position the helper writes: what lands there is unseen.
    [
      "import { writeFileSync } from 'node:fs'\nexport function put(text: string, file: string): void { writeFileSync(file, text) }",
      "import { put } from './io.js'\nexport function restore(root: string): void { put(...['x', join(root, '.env')]) }",
      'put',
    ],
  ]
  for (const [helper, text, callee] of viaHelper) {
    const found = scanFiles({ 'scripts/install/paths.ts': paths, 'scripts/install/io.ts': helper, [at]: text })
    assert.deepEqual(found['scripts/install/io.ts'], [], text)
    assert.deepEqual(found[at]?.map((w) => w.split(':')[0]), [callee], text)
  }
})

test('a test calls appendCredentials and inspectCredentials only through appendIn and inspectIn helpers that refuse any repository but a scratch directory', () => {
  // The writer's tests are the one place an offline test writes a .env, and
  // its inspection reads the one it is handed. Each call must go through a
  // helper that first proves its root is a temp directory and not this
  // checkout, which on the operator's Mac holds the real <repo>/.env. The
  // writer comes in one way, under its own names: one static import that
  // names each as itself. A rename, a namespace or default import, a
  // re-export, import() or a path spelled in a string would put it under a
  // name the call check below does not follow.
  const WRITER_SPEC = /(?:^|\/)dotenv-append(?:\.[cm]?[jt]s)?$/
  const HELPERS = new Map([
    ['appendCredentials', 'appendIn'],
    ['inspectCredentials', 'inspectIn'],
  ])
  const INERT = new Set(['CREATED_HEADER', 'MIN_GENERATED_LENGTH', 'GENERATED_LENGTH', 'DotenvWriteError', 'credentialNames', 'mintedCredentialNames'])
  const viaHelper = new Map<string, number>()
  let imports = 0
  for (const file of TEST) {
    const source = parsed(file)
    const at = (node: ts.Node): string => `${file.path}:${String(source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1)}`
    const visit = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node)) {
        if (ts.isStringLiteral(node.moduleSpecifier) && WRITER_SPEC.test(node.moduleSpecifier.text)) {
          const clause = node.importClause
          assert.equal(clause?.name, undefined, `${at(node)} default-imports the .env writer`)
          const bindings = clause?.namedBindings
          assert.ok(bindings === undefined || ts.isNamedImports(bindings), `${at(node)} imports the .env writer as a namespace`)
          for (const el of bindings !== undefined && ts.isNamedImports(bindings) ? bindings.elements : []) {
            assert.equal(el.propertyName, undefined, `${at(el)} imports ${(el.propertyName ?? el.name).text} from the .env writer as ${el.name.text}`)
            // A function of the writer's that opens .env has a helper here; a constant, a type or its error class does not open anything.
            assert.ok(el.isTypeOnly || clause?.isTypeOnly === true || HELPERS.has(el.name.text) || INERT.has(el.name.text), `${at(el)} imports ${el.name.text} from the .env writer, which this rule holds to no helper`)
          }
          imports += 1
        }
        return
      }
      if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier)) {
        assert.equal(WRITER_SPEC.test(node.moduleSpecifier.text), false, `${at(node)} re-exports the .env writer`)
        return
      }
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const spec = node.arguments[0]
        assert.ok(spec !== undefined && ts.isStringLiteralLike(spec), `${at(node)} imports a module this rule cannot name`)
      }
      if (ts.isStringLiteralLike(node) && /dotenv-append/.test(node.text)) assert.fail(`${at(node)} names the .env writer's module in a string`)
      const helper = ts.isIdentifier(node) ? HELPERS.get(node.text) : undefined
      if (ts.isIdentifier(node) && helper !== undefined) {
        let fn: ts.Node | undefined = node.parent
        while (fn !== undefined && !ts.isFunctionDeclaration(fn)) fn = fn.parent
        const call = node.parent
        assert.ok(
          fn !== undefined && ts.isFunctionDeclaration(fn) && fn.name?.text === helper && ts.isCallExpression(call) && call.expression === node,
          `${at(node)} reaches ${node.text} outside an ${helper} helper`,
        )
        const body = fn.getText(source)
        assert.match(body, /realpathSync\(osTmpdir\(\)\)/, `${file.path}: ${helper} does not hold its root to the temp directory`)
        assert.match(body, /realpathSync\(REPO_ROOT\)/, `${file.path}: ${helper} does not refuse this checkout`)
        viaHelper.set(node.text, (viaHelper.get(node.text) ?? 0) + 1)
      }
      ts.forEachChild(node, visit)
    }
    visit(source)
  }
  assert.ok(imports >= 1 && [...HELPERS.keys()].every((name) => (viaHelper.get(name) ?? 0) >= 1), 'no test imports and calls the .env writer and its inspection; the rule no longer sees them')
})

test('nothing in src/ or scripts/ writes process.env or uses Node\'s .env loaders, and the loader imports no write API', () => {
  // Values reach the kernel only through bootKernel's env. Anything written
  // into process.env is inherited by every child process and read by the
  // Anthropic SDK's own ambient lookups.
  const forbidden = [
    /process\.env(\[[^\]]+\]|\.[A-Za-z_]+)\s*=[^=]/,
    /Object\.assign\(\s*process\.env/,
    /delete\s+process\.env/,
    /loadEnvFile/,
    /parseEnv\b/,
    /from\s+['"]dotenv['"]/,
    /--env-file/,
  ]
  // In the mutation catalog only a one-line mutant literal is exempt: its
  // from/to strings are deliberate copies of the bugs (X16 writes process.env),
  // applied and reverted by the falsifier. The rest of the file is code that
  // runs — falsify.test.ts imports it on every npm test — and is scanned.
  const MUTANT_LITERAL = /^\s*\{ id: '[A-Z]+\d*', file: /
  for (const file of [...SRC, ...SCRIPTS]) {
    for (const line of codeLines(file)) {
      if (file.path === 'scripts/falsify/catalog.ts' && MUTANT_LITERAL.test(line.text)) continue
      for (const pattern of forbidden) {
        assert.equal(pattern.test(line.text), false, `${file.path}:${String(line.n)} matches ${String(pattern)}`)
      }
    }
  }
  const loader = SRC.find((f) => f.path === 'src/secrets/dotenv.ts')
  assert.ok(loader, 'src/secrets/dotenv.ts is missing')
  for (const write of ['writeFileSync', 'appendFileSync', 'createWriteStream', 'writeSync', 'copyFileSync', 'renameSync', 'unlinkSync', 'rmSync', 'O_WRONLY', 'O_RDWR', 'O_CREAT']) {
    assert.equal(codeLines(loader).some((l) => l.text.includes(write)), false, `the loader uses ${write}`)
  }
})

/** A test file as the compiler reads it: comments are trivia, strings are nodes. */
function parsed(file: SourceFile): ts.SourceFile {
  return ts.createSourceFile(file.path, file.text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
}

/** Every string a file spells out in code, and its line: literals and template text, never comments or import specifiers. */
function codeStrings(source: ts.SourceFile): { value: string; node: ts.Node; line: number }[] {
  const out: { value: string; node: ts.Node; line: number }[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      out.push({ value: node.text, node, line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1 })
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return out
}

/** Every call in a file. */
function calls(source: ts.SourceFile): ts.CallExpression[] {
  const out: ts.CallExpression[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) out.push(node)
    ts.forEachChild(node, visit)
  }
  visit(source)
  return out
}

/** The name a call is made through: `spawnSync(...)` and `cp.spawnSync(...)` both give spawnSync. */
function calleeName(call: ts.CallExpression): string | undefined {
  const e = call.expression
  if (ts.isIdentifier(e)) return e.text
  if (ts.isPropertyAccessExpression(e)) return e.name.text
  return undefined
}

/** Names that are node:child_process exports in this file, under any alias it imports them as. */
function childProcessNames(source: ts.SourceFile): Set<string> {
  const names = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])
  for (const st of source.statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue
    if (!/^(node:)?child_process$/.test(st.moduleSpecifier.text)) continue
    const bindings = st.importClause?.namedBindings
    if (bindings !== undefined && ts.isNamedImports(bindings)) for (const el of bindings.elements) names.add(el.name.text)
  }
  return names
}

const within = (node: ts.Node, outer: ts.Node): boolean => node.getStart() >= outer.getStart() && node.getEnd() <= outer.getEnd()

test('no test runs an entry point except through runEntry/spawnEntry, which run it from the shadow checkout', () => {
  // src/main.ts and the CLI take their repository from the cwd, eval from its
  // own file. Run from this checkout, one regression that defaults to
  // <repo>/.env reads the operator's keys; run from shadowCheckout(), it hits
  // a trap. The helpers set the cwd themselves and refuse one passed in, so
  // what is left to hold is that no test names an entry point anywhere else.
  // Read from the syntax tree: a comment, an apostrophe in one, or another
  // spelling of the path cannot hide a run.
  // A path to one: the whole string (`join('src', 'main.ts')`'s last part, a
  // template, './src/main.ts'), or one with a directory inside a longer
  // string (`execSync('node --import tsx src/main.ts')`). A bare file name in
  // prose, like an assertion message, is not a path.
  const ENTRY_NAME =
    /^(?:\.{0,2}\/)?(?:[\w.-]+\/)*(?:main|index|eval|capture-pmmcp|install)\.ts$|(?:^|[\s'"=])(?:\.{0,2}\/)?(?:[\w.-]+\/)+(?:main|index|eval|capture-pmmcp|install)\.ts(?![\w.])/
  const HELPER = new Set(['runEntry', 'spawnEntry'])
  let viaHelper = 0
  const seen = new Set<string>()
  for (const file of TEST) {
    if (file.path === 'test/helpers/checkout.ts') continue
    const source = parsed(file)
    const helperCalls = calls(source).filter((c) => HELPER.has(calleeName(c) ?? ''))
    for (const s of codeStrings(source)) {
      if (!ENTRY_NAME.test(s.value)) continue
      const ok = helperCalls.some((c) => c.arguments[1] === s.node)
      assert.ok(ok, `${file.path}:${String(s.line)} names an entry point (${s.value}) outside runEntry/spawnEntry`)
      viaHelper += 1
      seen.add(s.value)
    }
    // entrypoints.test.ts runs node only to run entry points, so no node run
    // there may go around the helpers, whatever its argv holds or is built from.
    if (file.path === 'test/entrypoints.test.ts') {
      const spawners = childProcessNames(source)
      for (const c of calls(source)) {
        const first = c.arguments[0]
        if (!spawners.has(calleeName(c) ?? '') || first === undefined) continue
        assert.notEqual(first.getText(source), 'process.execPath', `${file.path}: a node run that goes around runEntry/spawnEntry`)
      }
    }
  }
  assert.ok(viaHelper >= 12, `only ${String(viaHelper)} entry-point runs were found; the rule no longer sees them`)
  assert.deepEqual([...seen].sort(), [...ENTRY_POINTS].sort(), 'an entry point is no longer run as a program by any test')
})

test('no test runs npm or npx: npm writes its logs and cache under ~/.npm and calls the registry', () => {
  // The operator's footprint rule keeps everything in the program folder, and
  // npm honours this repo's .npmrc only when run from the repo root. Tests run
  // programs as `node --import tsx <file>`, which needs neither. Read from the
  // syntax tree: a call split over lines, `/usr/bin/env npx`, or
  // `const NPX = 'npx'` is caught as surely as a one-line spawnSync('npx').
  for (const file of TEST) {
    const source = parsed(file)
    const spawners = childProcessNames(source)
    const strings = codeStrings(source)
    // A constant naming npm is how a spawn hides it (`spawnSync(NPX, ...)`).
    // A container's command, like a sandbox spec's ['npm', 'test'], runs in
    // the container, not here, and is not flagged.
    for (const s of strings) {
      const named = ts.isVariableDeclaration(s.node.parent) && s.node.parent.initializer === s.node
      assert.equal(named && /^np[mx]$/.test(s.value), false, `${file.path}:${String(s.line)} names npm as a program`)
    }
    for (const c of calls(source)) {
      if (!spawners.has(calleeName(c) ?? '')) continue
      for (const s of strings) {
        if (within(s.node, c)) assert.equal(/(?:^|[\s/])np[mx](?:\s|$)/.test(s.value), false, `${file.path}:${String(s.line)} runs npm`)
      }
    }
  }
})

/** The top-level arguments of the first `name(` call on a line, or undefined. */
function callArgs(text: string, name: string): string[] | undefined {
  const start = text.indexOf(`${name}(`)
  if (start === -1) return undefined
  const args: string[] = []
  let depth = 0
  let quote: string | undefined
  let current = ''
  for (const ch of text.slice(start + name.length + 1)) {
    if (quote !== undefined) {
      current += ch
      if (ch === quote) quote = undefined
    } else if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch
      current += ch
    } else if ('([{'.includes(ch)) {
      depth += 1
      current += ch
    } else if (')]}'.includes(ch) && depth > 0) {
      depth -= 1
      current += ch
    } else if (ch === ')') {
      if (current.trim() !== '') args.push(current.trim())
      return args
    } else if (ch === ',' && depth === 0) {
      args.push(current.trim())
      current = ''
    } else {
      current += ch
    }
  }
  return undefined
}

test('liveCredential is called only in test/live-*.test.ts behind LIVE, or with an explicit path', () => {
  // The one test path that opens the repository's real .env must be reachable
  // only on the operator's gated live run. dotenv.test.ts tests the helper
  // itself, with AOS_LIVE_TESTS=1 in a literal env, so there every call must
  // name its file: dropping the path argument would make an offline test open
  // the operator's real <repo>/.env.
  const calls = TEST.filter((f) => f.path !== 'test/helpers/live-env.ts').flatMap((f) =>
    codeLines(f)
      .filter((l) => l.text.includes('liveCredential('))
      .map((l) => ({ path: f.path, n: l.n, text: l.text })),
  )
  const live = calls.filter((c) => c.path !== 'test/dotenv.test.ts')
  assert.ok(live.length >= 2, 'the live files no longer take their key through liveCredential')
  for (const call of live) {
    assert.match(call.path, /^test\/live-[^/]+\.test\.ts$/, `${call.path}:${String(call.n)}`)
    assert.match(call.text, /LIVE \?/, `${call.path}:${String(call.n)} calls liveCredential outside the LIVE gate`)
  }
  const unit = calls.filter((c) => c.path === 'test/dotenv.test.ts')
  assert.ok(unit.length >= 3, 'dotenv.test.ts no longer tests liveCredential')
  // A backstop: liveCredential itself refuses the default path outside a live
  // process (KEEPS_CREDENTIALS). A call that leaves the path out may appear
  // only as a thunk handed to assert.throws, proving exactly that refusal.
  for (const call of unit) {
    const args = callArgs(call.text, 'liveCredential')?.length
    if (args === 3) continue
    assert.match(call.text, /\(\)\s*=>\s*liveCredential\(/, `${call.path}:${String(call.n)} leaves liveCredential's path to its default`)
  }
})
