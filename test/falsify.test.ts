// The mutation runner, and the catalog it runs.
//
// The runner edits source files in the working tree, so the properties that
// matter most are the ones about putting them back: after a kill, a survivor, a
// hang, an unusable anchor, a red baseline — and after the runner itself is
// SIGKILLed mid-mutant. Those are driven for real here, against a scratch
// fixture and real node:test subprocesses, because a process-group kill and a
// crash journal only mean something against real processes.
//
// The catalog half is static and runs on every `npm test`: each anchor must
// still match exactly once and leave a parseable file. Without it, a refactor
// that moves an anchor would turn its mutant into "invalid" the next time
// someone runs the falsifier — or worse, nobody would notice until then.
//
// The falsifiers: restore the file only on the happy path and the hang/invalid
// cases leave it mutated; count a load failure as a kill and a syntax-error
// mutant reads as caught; drop the journal and a SIGKILL leaves a mutant in the
// tree with nothing to recover it.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'

import { CATALOG } from '../scripts/falsify/catalog.js'
import {
  judge,
  problems,
  recoverInterrupted,
  runSuites,
  unusable,
  type Mutant,
  type Suite,
} from '../scripts/falsify/runner.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'

const MODULE = `// fixture module
export function add(a: number, b: number): number {
  return a + b
}
`
const TEST_FILE = `import test from 'node:test'
import assert from 'node:assert/strict'
import { add } from './mod.ts'

test('adds', () => {
  assert.equal(add(2, 3), 5)
})
`

/** A scratch repo: one module, one test, and the real node_modules for tsx. */
function fixture(t: TestContext): { root: string; original: string } {
  const root = tmpdir(t)
  writeFileSync(join(root, 'mod.ts'), MODULE)
  writeFileSync(join(root, 'mod.test.ts'), TEST_FILE)
  writeFileSync(join(root, 'package.json'), '{"type":"module"}')
  symlinkSync(join(REPO_ROOT, 'node_modules'), join(root, 'node_modules'))
  return { root, original: MODULE }
}

const m = (id: string, from: string, to: string): Mutant => ({ id, file: 'mod.ts', from, to, why: id })
const CONTROL = m('C', '// fixture module', '// fixture module (control)')

function suite(mutants: Mutant[], control = CONTROL, root?: string): Suite {
  return { name: 'fixture', tests: [root === undefined ? 'mod.test.ts' : join(root, 'mod.test.ts')], mutants, control }
}

const verdicts = (reports: Awaited<ReturnType<typeof runSuites>>): Record<string, string> =>
  Object.fromEntries(reports.flatMap((r) => r.outcomes.map((o) => [o.id, o.verdict])))

// ── the runner, for real ───────────────────────────────────────────────────

test('each verdict is reached for its own reason, and the file is put back after every one', async (t) => {
  const { root, original } = fixture(t)
  t.after(() => {
    spawnSync('pkill', ['-KILL', '-f', root])
  })
  const reports = await runSuites(
    [
      suite([
        m('kill', 'return a + b', 'return a - b'),
        m('live', 'return a + b', 'return b + a'),
        m('hang', 'return a + b', 'for (;;) {}\n  return a + b'),
        m('gone', 'return a * b', 'return 0'),
        m('twice', 'number', 'string'),
        m('syntax', 'return a + b', 'return a +'),
        m('load', '// fixture module', "throw new Error('the module fails at import')"),
      ], CONTROL, root),
    ],
    { root, timeoutMs: 8_000 },
  )

  assert.deepEqual(verdicts(reports), {
    kill: 'killed',
    live: 'survived',
    hang: 'hung',
    gone: 'invalid',
    // Which of three would it edit? Guessing would make the mutant mean
    // something different from what its line in the catalog says.
    twice: 'invalid',
    syntax: 'invalid',
    // Parses, but every test file fails to load: that is not the suite
    // catching a bug, and it must not be scored as one.
    load: 'invalid',
    C: 'survived',
  })
  const byId = new Map(reports[0]?.outcomes.map((o) => [o.id, o]))
  assert.deepEqual(byId.get('kill')?.detail, ['adds'])
  assert.match(byId.get('gone')?.detail[0] ?? '', /anchor not found/)
  assert.match(byId.get('twice')?.detail[0] ?? '', /anchor matches 3 times/)
  assert.match(byId.get('syntax')?.detail[0] ?? '', /does not parse/)

  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original, 'a mutant was left in the file')
  assert.equal(existsSync(join(root, '.falsify', 'journal.json')), false, 'the journal outlived the run')

  // Only the kill is a success; every other verdict is reported as a problem.
  assert.deepEqual(
    problems(reports).map((p) => p.split(':')[0]),
    ['fixture/live', 'fixture/hang', 'fixture/gone', 'fixture/twice', 'fixture/syntax', 'fixture/load'],
  )

  // The hung mutant's test process — and the per-file child node:test spawned
  // under it — are gone. Killing only the direct child would still read
  // `hung`, and leave the file's process spinning on a core indefinitely.
  // (The suite names its test file by absolute path so the fixture's unique
  // directory appears on every one of those command lines.)
  let leftover = ''
  for (let i = 0; i < 20; i++) {
    leftover = spawnSync('pgrep', ['-fl', root], { encoding: 'utf8' }).stdout.trim()
    if (leftover === '') break
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  assert.equal(leftover, '', 'a hung mutant left a test process running')
})

test('a test process that throws still leaves the file restored', async (t) => {
  const { root, original } = fixture(t)
  let calls = 0
  await assert.rejects(
    runSuites([suite([m('kill', 'return a + b', 'return a - b')])], {
      root,
      timeoutMs: 8_000,
      // Baseline passes; the mutant's run blows up mid-flight.
      runTests: () => {
        calls += 1
        if (calls === 1) return Promise.resolve({ timedOut: false, code: 0, failing: [], passing: ['adds'] })
        return Promise.reject(new Error('the test process could not be started'))
      },
    }),
    /could not be started/,
  )
  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original, 'the mutant outlived a thrown run')
  assert.equal(existsSync(join(root, '.falsify', 'journal.json')), false)
})

test('a red baseline refuses the suite: every mutant would read as killed', async (t) => {
  const { root, original } = fixture(t)
  writeFileSync(join(root, 'mod.test.ts'), TEST_FILE.replace('5)', '6)'))
  const reports = await runSuites([suite([m('kill', 'return a + b', 'return a - b')])], { root, timeoutMs: 8_000 })

  assert.equal(reports[0]?.outcomes.length, 0)
  assert.match(reports[0]?.refused ?? '', /baseline is not green/)
  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original)
})

test('a control that is killed flags the suite as untrustworthy', async (t) => {
  const { root } = fixture(t)
  const reports = await runSuites([suite([], m('C', 'return a + b', 'return a - b'))], { root, timeoutMs: 8_000 })
  assert.deepEqual(problems(reports), ['fixture/C: the control was killed — the suite is not trustworthy'])
})

test('a dirty file refuses the suite before anything is edited', async (t) => {
  const { root, original } = fixture(t)
  const reports = await runSuites([suite([m('kill', 'return a + b', 'return a - b')])], {
    root,
    timeoutMs: 8_000,
    assertClean: (files) => {
      throw new Error(`uncommitted changes in ${files.join(', ')}`)
    },
  })
  assert.match(reports[0]?.refused ?? '', /uncommitted changes in mod\.ts/)
  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original)
})

test('a runner SIGKILLed mid-mutant leaves a journal, and the next start restores from it', async (t) => {
  // The one exit no `finally` can cover. The journal is written before the
  // edit, so the mutated file is always recoverable.
  const { root, original } = fixture(t)
  const driver = join(root, 'drive.ts')
  writeFileSync(
    driver,
    `import { runSuites } from ${JSON.stringify(join(REPO_ROOT, 'scripts/falsify/runner.ts'))}
await runSuites([{ name: 'f', tests: [${JSON.stringify(join(root, 'mod.test.ts'))}], control: { id: 'C', file: 'mod.ts', from: '// fixture module', to: '// c', why: '' },
  mutants: [{ id: 'hang', file: 'mod.ts', from: 'return a + b', to: 'for (;;) {}\\n  return a + b', why: '' }] }],
  { root: ${JSON.stringify(root)}, timeoutMs: 120000 })
`,
  )
  const child = spawn(process.execPath, ['--import', 'tsx', driver], { cwd: root, stdio: 'ignore', detached: true })
  const journal = join(root, '.falsify', 'journal.json')
  const deadline = Date.now() + 60_000
  while (!(existsSync(journal) && readFileSync(join(root, 'mod.ts'), 'utf8') !== original)) {
    assert.ok(Date.now() < deadline, 'the runner never reached its mutant')
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  // Kill the runner, then the test process it was waiting on: that one runs in
  // its own process group (so a timeout can kill it whole), and its command
  // line carries the fixture's unique path, which is how it is found here.
  process.kill(-(child.pid ?? 0), 'SIGKILL')
  await new Promise((resolve) => child.once('exit', resolve))
  spawnSync('pkill', ['-KILL', '-f', root])

  assert.notEqual(readFileSync(join(root, 'mod.ts'), 'utf8'), original, 'nothing was left to recover')
  assert.equal(recoverInterrupted(root), 'mod.ts')
  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original)
  assert.equal(existsSync(journal), false)
  assert.equal(recoverInterrupted(root), undefined, 'recovery is not idempotent')
})

test('a hang is never a kill, and a failure with no named test is never a kill', () => {
  assert.equal(judge({ timedOut: true, code: null, failing: ['adds'], passing: [] }).verdict, 'hung')
  assert.equal(judge({ timedOut: false, code: 1, failing: ['test/x.test.ts'], passing: [] }).verdict, 'invalid')
  assert.equal(judge({ timedOut: false, code: 1, failing: [], passing: [] }).verdict, 'invalid')
  assert.equal(judge({ timedOut: false, code: 1, failing: ['adds'], passing: [] }).verdict, 'killed')
  assert.equal(judge({ timedOut: false, code: 0, failing: [], passing: ['adds'] }).verdict, 'survived')
})

// ── the catalog, statically ────────────────────────────────────────────────

test('every catalog anchor still matches exactly once and leaves a file that parses', () => {
  const broken: string[] = []
  for (const s of CATALOG) {
    for (const mutant of [...s.mutants, s.control]) {
      const why = unusable(mutant, readFileSync(join(REPO_ROOT, mutant.file), 'utf8'))
      if (why !== undefined) broken.push(`${s.name}/${mutant.id} (${mutant.file}): ${why}`)
    }
  }
  assert.deepEqual(broken, [], 'the code moved under the catalog; update scripts/falsify/catalog.ts')
})

test('the catalog is well-formed: unique ids, real test files, and controls that touch only comments', () => {
  for (const s of CATALOG) {
    const ids = s.mutants.map((mu) => mu.id)
    assert.equal(new Set(ids).size, ids.length, `${s.name} has duplicate mutant ids`)
    assert.ok(s.mutants.length > 0, `${s.name} has no mutants`)
    for (const file of s.tests) assert.ok(existsSync(join(REPO_ROOT, file)), `${s.name}: ${file} does not exist`)
    // A control that changes behaviour could be killed for a real reason and
    // teach the reader to ignore a killed control.
    const edited = s.control.from.trimStart()
    assert.ok(edited.startsWith('//') || edited.startsWith('/*'), `${s.name}'s control edits code, not a comment`)
  }
  const suites = CATALOG.map((s) => s.name)
  assert.equal(new Set(suites).size, suites.length)
  // `--only` names mutants across suites, so an id must mean one mutant in the
  // whole catalog, not just within its suite.
  const all = CATALOG.flatMap((s) => s.mutants.map((mu) => mu.id))
  assert.deepEqual(all.filter((id, i) => all.indexOf(id) !== i), [], 'a mutant id is reused across suites')
})

test('npm run falsify is a program: bad input is refused with usage, --list runs nothing', () => {
  const run = (args: string[]) =>
    spawnSync('npx', ['tsx', 'scripts/falsify.ts', ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 60_000 })

  const bogus = run(['no-such-suite'])
  assert.equal(bogus.status, 2, bogus.stderr)
  assert.match(bogus.stderr, /unknown suite: no-such-suite/)
  assert.match(bogus.stderr, /suites: delegation, recovery, replay, namespace, goals, anchor, eval, integrity, redaction, schedule, registry, restart, sandbox/)

  const badOnly = run(['--only', 'D99'])
  assert.equal(badOnly.status, 2)
  assert.match(badOnly.stderr, /unknown mutant: D99/)

  const list = run(['--list', 'replay'])
  assert.equal(list.status, 0, list.stderr)
  assert.match(list.stdout, /^replay {2}\(test\/wire-replay\.test\.ts/m)
  assert.match(list.stdout, /R1 +src\/runtime\/loop\.ts/)
  assert.doesNotMatch(list.stdout, /^delegation/m)
  // Listing touched nothing.
  assert.equal(existsSync(join(REPO_ROOT, '.falsify', 'journal.json')), false)
})
