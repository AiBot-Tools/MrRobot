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

import { CREDENTIAL_NAME } from './helpers/guard.js'

import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'

import { CATALOG } from '../scripts/falsify/catalog.js'
import {
  CHILD_CREDENTIAL_NAME,
  childEnv,
  clearStaleLock,
  JournalUnreadable,
  judge,
  liveRun,
  processStarted,
  PS_CLOCK,
  problems,
  recoverInterrupted,
  RESTORING_SIGNALS,
  runSuites,
  unusable,
  type Mutant,
  type Suite,
} from '../scripts/falsify/runner.js'
import { ENTRY_POINTS } from './helpers/checkout.js'
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

/** A runner in its own process, on a fixture whose one mutant hangs its test. */
function hangingRun(t: TestContext, preamble = ''): { root: string; original: string; child: ReturnType<typeof spawn> } {
  const { root, original } = fixture(t)
  const driver = join(root, 'drive.ts')
  writeFileSync(
    driver,
    `${preamble}
import { runSuites } from ${JSON.stringify(join(REPO_ROOT, 'scripts/falsify/runner.ts'))}
await runSuites([{ name: 'f', tests: [${JSON.stringify(join(root, 'mod.test.ts'))}], control: { id: 'C', file: 'mod.ts', from: '// fixture module', to: '// c', why: '' },
  mutants: [{ id: 'hang', file: 'mod.ts', from: 'return a + b', to: 'for (;;) {}\\n  return a + b', why: '' }] }],
  { root: ${JSON.stringify(root)}, timeoutMs: 120000 })
`,
  )
  const child = spawn(process.execPath, ['--import', 'tsx', driver], { cwd: root, stdio: 'ignore', detached: true })
  t.after(() => spawnSync('pkill', ['-KILL', '-f', root]))
  return { root, original, child }
}

async function untilMutated(root: string, original: string): Promise<void> {
  const deadline = Date.now() + 60_000
  while (!(existsSync(join(root, '.falsify', 'journal.json')) && readFileSync(join(root, 'mod.ts'), 'utf8') !== original)) {
    assert.ok(Date.now() < deadline, 'the runner never reached its mutant')
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
}

test('every restoring signal mid-mutant restores the file, kills the hung test group, and releases the lock', async (t) => {
  assert.deepEqual([...RESTORING_SIGNALS], ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'])
  const codes: Record<string, number> = { SIGINT: 130, SIGTERM: 143, SIGHUP: 129, SIGQUIT: 131 }
  for (const signal of RESTORING_SIGNALS) {
    const { root, original, child } = hangingRun(t)
    await untilMutated(root, original)
    // The lock names the live runner by pid and start time, and the journal
    // names its run, which is what lets the test guard tell its own children.
    assert.equal(liveRun(root), child.pid, signal)
    const journal = JSON.parse(readFileSync(join(root, '.falsify', 'journal.json'), 'utf8')) as { runId?: unknown }
    assert.equal(typeof journal.runId, 'string', signal)
    // And a second runner on the same tree refuses rather than "recovering" it.
    await assert.rejects(runSuites([], { root, timeoutMs: 1_000 }), /already in progress/)

    child.kill(signal)
    const code = await new Promise<number | null>((resolve) => child.once('exit', (c) => resolve(c)))
    assert.equal(code, codes[signal], signal)
    assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original, `${signal} left the mutant in place`)
    assert.equal(existsSync(join(root, '.falsify', 'journal.json')), false, signal)
    assert.equal(existsSync(join(root, '.falsify', 'lock.json')), false, `${signal} left the lock`)
    // The hung test ran detached in its own group; nothing of it may survive.
    await new Promise((resolve) => setTimeout(resolve, 300))
    const left = spawnSync('pgrep', ['-f', root], { encoding: 'utf8' }).stdout.trim()
    assert.equal(left, '', `${signal} left the test process group running`)
  }
})

test('a second signal during cleanup does not kill the run before it restores: npm forwards Ctrl-C, a closing terminal sends SIGHUP twice', async (t) => {
  // The second signal is sent from inside the run's own exit, while its cleanup
  // is done but the process is still alive: the worst moment for the default
  // action to be back. A run whose listener is gone dies of it, by signal.
  const { root, original, child } = hangingRun(
    t,
    `const realExit = process.exit.bind(process)
process.exit = ((code) => {
  process.kill(process.pid, 'SIGINT')
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300)
  return realExit(code)
})`,
  )
  await untilMutated(root, original)
  child.kill('SIGINT')
  const [code, signal] = await new Promise<[number | null, NodeJS.Signals | null]>((resolve) =>
    child.once('exit', (c, s) => resolve([c, s])),
  )
  assert.deepEqual([code, signal], [130, null], 'the second signal killed the run mid-cleanup')
  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original)
  assert.equal(existsSync(join(root, '.falsify', 'lock.json')), false)
})

test('the lock is held for the whole run: a second runner refuses during the first one\'s baseline too', async (t) => {
  const { root } = fixture(t)
  // A baseline that takes a while: the window a per-mutant journal left open.
  writeFileSync(join(root, 'slow.test.ts'), "import test from 'node:test'\ntest('slow', async () => { await new Promise((r) => setTimeout(r, 8000)) })\n")
  const driver = join(root, 'drive.ts')
  writeFileSync(
    driver,
    `import { runSuites } from ${JSON.stringify(join(REPO_ROOT, 'scripts/falsify/runner.ts'))}
await runSuites([{ name: 'f', tests: [${JSON.stringify(join(root, 'slow.test.ts'))}], control: { id: 'C', file: 'mod.ts', from: '// fixture module', to: '// c', why: '' }, mutants: [] }],
  { root: ${JSON.stringify(root)}, timeoutMs: 120000 })
`,
  )
  const child = spawn(process.execPath, ['--import', 'tsx', driver], { cwd: root, stdio: 'ignore', detached: true })
  t.after(() => spawnSync('pkill', ['-KILL', '-f', root]))
  const deadline = Date.now() + 30_000
  while (!existsSync(join(root, '.falsify', 'lock.json'))) {
    assert.ok(Date.now() < deadline, 'the runner never took its lock')
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  assert.equal(existsSync(join(root, '.falsify', 'journal.json')), false, 'expected the baseline, with no mutant applied')
  await assert.rejects(runSuites([], { root, timeoutMs: 1_000 }), /already in progress/)
  child.kill('SIGTERM')
  await new Promise((resolve) => child.once('exit', resolve))
})

test('a reused pid does not pass for a live run: liveness is the pid AND its start time', async (t) => {
  const { root, original } = fixture(t)
  // An unrelated live process holds the number a dead runner left in its lock.
  const other = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'])
  t.after(() => other.kill('SIGKILL'))
  const pid = other.pid ?? 0
  mkdirSync(join(root, '.falsify'))
  const lock = (started: string): void =>
    writeFileSync(join(root, '.falsify', 'lock.json'), JSON.stringify({ pid, started, runId: 'dead-run' }))
  // The dead run had also left a file mutated.
  writeFileSync(join(root, 'mod.ts'), MODULE.replace('a + b', 'a - b'))
  writeFileSync(
    join(root, '.falsify', 'journal.json'),
    JSON.stringify({ file: 'mod.ts', original: Buffer.from(original).toString('base64'), runId: 'dead-run' }),
  )

  lock('Thu Jan  1 00:00:00 1970')
  assert.equal(liveRun(root), undefined, 'a reused pid passed for the dead run')
  // So recovery and a new run both go ahead.
  const reports = await runSuites([suite([], CONTROL, root)], { root, timeoutMs: 30_000 })
  assert.equal(readFileSync(join(root, 'mod.ts'), 'utf8'), original)
  assert.deepEqual(problems(reports), [])

  // With the true start time, the same pid IS the owner.
  lock(processStarted(pid) ?? '')
  assert.equal(liveRun(root), pid)
  await assert.rejects(runSuites([], { root, timeoutMs: 1_000 }), /already in progress/)
})

test('liveness does not depend on the zone or on ps: start times are UTC, and a live pid ps cannot vouch for is held', async (t) => {
  // BSD ps and procps print local time; the Mac changes zone with its
  // location, so a long run would stop matching its own lock.
  assert.deepEqual({ ...PS_CLOCK }, { LC_ALL: 'C', TZ: 'UTC0' })
  const utc = spawnSync('ps', ['-o', 'lstart=', '-p', String(process.pid)], {
    encoding: 'utf8',
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', LC_ALL: 'C', TZ: 'UTC0' },
  }).stdout.trim()
  assert.equal(processStarted(process.pid), utc)

  const { root } = fixture(t)
  const other = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'])
  t.after(() => other.kill('SIGKILL'))
  const pid = other.pid ?? 0
  mkdirSync(join(root, '.falsify'))
  writeFileSync(join(root, '.falsify', 'lock.json'), JSON.stringify({ pid, started: processStarted(pid), runId: 'live' }))
  assert.equal(liveRun(root), pid)
  // Without ps the live pid cannot be told from a reused one, so it is held:
  // --recover and a second run refuse rather than write over a live mutant.
  const savedPath = process.env['PATH']
  process.env['PATH'] = join(root, 'no-such-dir')
  t.after(() => {
    process.env['PATH'] = savedPath
  })
  assert.equal(processStarted(pid), undefined)
  assert.equal(liveRun(root), pid, 'a live run read as dead because ps could not answer')
  assert.equal(clearStaleLock(root), false)
  // And a run that cannot read its own start time takes no lock at all.
  rmSync(join(root, '.falsify', 'lock.json'))
  await assert.rejects(runSuites([], { root, timeoutMs: 1_000 }), /cannot read this process's start time/)
  // A pid that is gone is dead, ps or no ps.
  other.kill('SIGKILL')
  await new Promise((resolve) => other.once('exit', resolve))
  writeFileSync(join(root, '.falsify', 'lock.json'), JSON.stringify({ pid, started: 'x', runId: 'dead' }))
  assert.equal(liveRun(root), undefined)
})

test('runners started together on a stale lock: exactly one takes it, the rest refuse', async (t) => {
  // A lock left by a SIGKILL whose pid now belongs to an unrelated process (a
  // reboot, a busy machine): judging it takes a ps call, and breaking it by
  // check-then-delete let a late breaker delete the lock an earlier one had
  // just taken, so both ran. The drivers wait at a common gate so they reach
  // the lock within a millisecond of each other.
  //
  // The gate is set only once every driver has loaded and said so. A gate fixed
  // at spawn time (it was spawn + 8 s) is missed on a loaded machine, where six
  // tsx start-ups take longer, and the test then failed without running the race.
  const { root } = fixture(t)
  const other = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'])
  t.after(() => other.kill('SIGKILL'))
  mkdirSync(join(root, '.falsify'))
  writeFileSync(join(root, '.falsify', 'lock.json'), JSON.stringify({ pid: other.pid, started: 'Thu Jan  1 00:00:00 1970', runId: 'stale' }))
  const driver = join(root, 'race.ts')
  writeFileSync(
    driver,
    `import { existsSync, readFileSync } from 'node:fs'
import { runSuites } from ${JSON.stringify(join(REPO_ROOT, 'scripts/falsify/runner.ts'))}
const go = process.argv[2]
process.stdout.write('ready\\n')
// Wait cheaply for the gate, then spin on the clock so all six leave together.
while (!existsSync(go)) await new Promise((r) => setTimeout(r, 5))
const gate = Number(readFileSync(go, 'utf8'))
if (Date.now() > gate) process.stdout.write('late\\n')
while (Date.now() < gate) {}
try {
  await runSuites([{ name: 'f', tests: [], mutants: [], control: { id: 'C', file: 'mod.ts', from: '// fixture module', to: '// c', why: '' } }], {
    root: ${JSON.stringify(root)},
    timeoutMs: 10_000,
    log: (line) => { if (line.endsWith(': baseline')) process.stdout.write('holding\\n') },
    runTests: async () => {
      await new Promise((r) => setTimeout(r, 3_000))
      return { timedOut: false, code: 1, failing: [], passing: [] }
    },
  })
} catch (e) {
  process.stdout.write('refused: ' + (e instanceof Error ? e.message : String(e)) + '\\n')
}
`,
  )
  t.after(() => spawnSync('pkill', ['-KILL', '-f', driver]))
  const go = join(root, 'go')
  const runs = Array.from({ length: 6 }, () => {
    const child = spawn(process.execPath, ['--import', 'tsx', driver, go], { cwd: root, stdio: ['ignore', 'pipe', 'inherit'] })
    let out = ''
    child.stdout.on('data', (c: Buffer) => (out += c.toString('utf8')))
    return {
      // A driver that dies before it is ready settles too, and fails below.
      ready: new Promise<void>((resolve) => {
        child.stdout.on('data', () => out.includes('ready') && resolve())
        child.on('close', () => resolve())
      }),
      closed: new Promise<string>((resolve) => child.on('close', () => resolve(out))),
    }
  })
  await Promise.all(runs.map((r) => r.ready))
  // Renamed into place, so no driver can read a half-written gate.
  writeFileSync(`${go}.tmp`, String(Date.now() + 1_000))
  renameSync(`${go}.tmp`, go)
  const outs = await Promise.all(runs.map((r) => r.closed))
  assert.equal(outs.filter((o) => o.includes('ready')).length, 6, outs.join('---'))
  assert.equal(outs.filter((o) => o.includes('late')).length, 0, 'a driver missed the gate, so the race was not run')
  assert.equal(outs.filter((o) => o.includes('holding')).length, 1, outs.join('---'))
  for (const o of outs.filter((x) => !x.includes('holding'))) {
    assert.match(o, /refused: .*(already in progress|starting on|removing a stale lock)/, o)
  }
  assert.equal(existsSync(join(root, '.falsify', 'lock.json')), false, 'the holder left its lock')
  assert.equal(existsSync(join(root, '.falsify', 'lock.break')), false)
})

test('an unreadable journal stops recovery with what to do, and a leftover temp journal means nothing was edited', (t) => {
  const { root } = fixture(t)
  mkdirSync(join(root, '.falsify'))
  writeFileSync(join(root, '.falsify', 'journal.json'), '')
  assert.throws(() => recoverInterrupted(root), (e: unknown) => e instanceof JournalUnreadable && /git status/.test(e.message))
  // The journal is renamed into place only once whole; a temp file with no
  // journal is a run that died before its edit.
  rmSync(join(root, '.falsify', 'journal.json'))
  writeFileSync(join(root, '.falsify', 'journal.json.tmp'), '{"file":')
  assert.equal(recoverInterrupted(root), undefined)
  assert.equal(existsSync(join(root, '.falsify', 'journal.json.tmp')), false)
})

test('test processes get no live-test flag and no credential from the runner, and their own run id', () => {
  const env = childEnv(
    {
      PATH: '/usr/bin',
      AOS_LIVE_TESTS: '1',
      AOS_LIVE_PMMCP_WRITES: '1',
      ANTHROPIC_API_KEY: 'k',
      OPENROUTER_API_KEY: 'k',
      AOS_CONTROL_TOKEN: 't',
      PMMCP_TOKEN: 't',
      NODE_OPTIONS: '--inspect',
      NODE_TEST_CONTEXT: 'child',
      AOS_FALSIFY_RUN: 'someone-else',
    },
    { AOS_FALSIFY_RUN: 'mine' },
  )
  assert.deepEqual(env, { PATH: '/usr/bin', AOS_FALSIFY_RUN: 'mine' })
  // The same names the test guard scrubs, so the two cannot drift apart.
  assert.equal(CHILD_CREDENTIAL_NAME.source, CREDENTIAL_NAME.source)
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
  // Under a falsify run (the runner suite mutates runner.ts and falsify.ts),
  // one file holds a mutant right now; its anchors are judged against the
  // original the run journaled, which is the source as committed.
  let journaled: { file: string; text: string } | undefined
  try {
    const j = JSON.parse(readFileSync(join(REPO_ROOT, '.falsify', 'journal.json'), 'utf8')) as { file?: unknown; original?: unknown; runId?: unknown }
    if (j.runId === process.env['AOS_FALSIFY_RUN'] && typeof j.file === 'string' && typeof j.original === 'string') {
      journaled = { file: j.file, text: Buffer.from(j.original, 'base64').toString('utf8') }
    }
  } catch {
    // No journal: nothing is mutated.
  }
  const source = (file: string): string => (journaled?.file === file ? journaled.text : readFileSync(join(REPO_ROOT, file), 'utf8'))
  const broken: string[] = []
  for (const s of CATALOG) {
    for (const mutant of [...s.mutants, s.control]) {
      const why = unusable(mutant, source(mutant.file))
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

test('no mutant that could steer an entry point at a credentials file runs beside a test that spawns entry points from this checkout', () => {
  // entrypoints.test.ts spawns the daemon, the CLI and eval from
  // shadowCheckout()'s copy, against a trap .env. That copy is the first line;
  // this is the second, in case a regression points a spawn back at this
  // checkout, which on the operator's Mac holds the real <repo>/.env. A mutant
  // on an entry point, or one that writes a .env path into the code, would then
  // have a test-spawned process read the real keys before an assertion killed
  // it. Such mutants belong in a suite of in-process tests against a trap repo.
  const SPAWNS = 'test/entrypoints.test.ts'
  const ENTRY = new Set<string>(ENTRY_POINTS)
  // `.env` not preceded by an identifier character (so not `process.env`):
  // '.env', '/.env', `${base}/.env`, './.env' all count.
  const NAMES_THE_FILE = /(?<![\w$])\.env\b|DOTENV_FILE/
  const hazards: string[] = []
  for (const s of CATALOG) {
    if (!s.tests.includes(SPAWNS)) continue
    for (const mu of s.mutants) {
      if (ENTRY.has(mu.file) || (NAMES_THE_FILE.test(mu.to) && !NAMES_THE_FILE.test(mu.from))) hazards.push(`${s.name}/${mu.id}`)
    }
  }
  assert.deepEqual(hazards, [])
})

test('no mutant can let a test open the real .env through liveCredential', () => {
  // The runner withholds the live flag and every credential from its test
  // processes, which defeats any mutant that widens the guard's
  // KEEPS_CREDENTIALS. It cannot defeat one on liveCredential's own no-path
  // gate: dotenv.test.ts hands liveCredential { AOS_LIVE_TESTS: '1' } itself,
  // so with that gate gone the default path, the operator's real <repo>/.env,
  // is opened. Such a mutant must never be in the catalog.
  const LIVE_ENV = 'test/helpers/live-env.ts'
  const GATE = 'if (path === undefined && !KEEPS_CREDENTIALS) {'
  assert.ok(readFileSync(join(REPO_ROOT, LIVE_ENV), 'utf8').includes(GATE), 'the no-path gate moved; update this rule')
  const LIVE_FLAG = "process.env['AOS_LIVE_TESTS'] === '1'"
  const hazards: string[] = []
  for (const s of CATALOG) {
    for (const mu of s.mutants) {
      // live-env.ts: nothing that touches the gate, its condition, or the default path.
      if (mu.file === LIVE_ENV && /KEEPS_CREDENTIALS|path === undefined|REPO_ROOT, '\.env'/.test(mu.from)) hazards.push(`${s.name}/${mu.id}`)
      // guard.ts: a mutant of the live check must keep it conditioned on the flag the runner strips.
      if (mu.file === 'test/helpers/guard.ts' && mu.from.includes(LIVE_FLAG) && !mu.to.includes(LIVE_FLAG)) hazards.push(`${s.name}/${mu.id}`)
      if (mu.file === 'test/helpers/guard.ts' && /export const KEEPS_CREDENTIALS/.test(mu.from)) hazards.push(`${s.name}/${mu.id}`)
    }
  }
  assert.deepEqual(hazards, [])
})

test('npm run falsify is a program: bad input and unknown options are refused with usage; --list, --help and --recover run nothing', () => {
  const run = (args: string[]) =>
    spawnSync(process.execPath, ['--import', 'tsx', 'scripts/falsify.ts', ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 60_000 })

  const bogus = run(['no-such-suite'])
  assert.equal(bogus.status, 2, bogus.stderr)
  assert.match(bogus.stderr, /unknown suite: no-such-suite/)
  assert.match(bogus.stderr, /suites: delegation, recovery, replay, namespace, goals, anchor, eval, integrity, redaction, schedule, registry, restart, sandbox, dotenv, dotenvDefault, dotenvAppend, gitignore, runner/)

  const badOnly = run(['--only', 'D99'])
  assert.equal(badOnly.status, 2)
  assert.match(badOnly.stderr, /unknown mutant: D99/)

  const list = run(['--list', 'replay'])
  assert.equal(list.status, 0, list.stderr)
  assert.match(list.stdout, /^replay {2}\(test\/wire-replay\.test\.ts/m)
  assert.match(list.stdout, /R1 +src\/runtime\/loop\.ts/)
  assert.doesNotMatch(list.stdout, /^delegation/m)

  // An option it does not read is refused, never ignored: a typo or --help
  // must not run the whole catalog against the working tree.
  const help = run(['--help'])
  assert.equal(help.status, 0, help.stderr)
  assert.match(help.stdout, /^usage: npm run falsify/)
  for (const typo of [['--lsit'], ['--dry-run', 'replay'], ['-x']]) {
    const r = run(typo)
    assert.equal(r.status, 2, `${typo.join(' ')}: ${r.stdout}`)
    assert.match(r.stderr, /unknown option/)
    assert.doesNotMatch(r.stderr, /baseline/)
  }
  // An option that takes a value, given none, or a selection naming nothing,
  // is refused: `--only` alone used to select all 207 mutants.
  for (const bad of [['--only'], ['--timeout'], ['--only', '--list'], ['--only', ','], ['replay', '--only', 'D1']]) {
    const r = run(bad)
    assert.equal(r.status, 2, `${bad.join(' ')}: ${r.stdout}`)
    assert.match(r.stderr, /needs a value|names no mutant/, bad.join(' '))
    assert.doesNotMatch(r.stderr, /baseline/)
  }
  // Some named ids outside the suites named, or a second --only, would be
  // dropped while the rest still ended in "every mutant was caught".
  for (const [bad, why] of [
    [['dotenv', '--only', 'X31,D1', '--list'], /not in the suites named \(dotenv\): D1/],
    [['--only', 'D1', '--only', 'X31', '--list'], /--only given more than once/],
    [['--timeout', '5000', '--timeout', '6000', '--list'], /--timeout given more than once/],
  ] as const) {
    const r = run([...bad])
    assert.equal(r.status, 2, `${bad.join(' ')}: ${r.stdout}`)
    assert.match(r.stderr, why)
  }
  // --recover acts on this tree. Under a falsify run (the runner suite), the
  // run that spawned this test holds the tree, and --recover must leave it be.
  const journalPath = join(REPO_ROOT, '.falsify', 'journal.json')
  const before = existsSync(journalPath) ? readFileSync(journalPath, 'utf8') : undefined
  const ownRun = process.env['AOS_FALSIFY_RUN']
  let lockedByOwnRun = false
  try {
    lockedByOwnRun = ownRun !== undefined && (JSON.parse(readFileSync(join(REPO_ROOT, '.falsify', 'lock.json'), 'utf8')) as { runId?: unknown }).runId === ownRun
  } catch {
    // No lock: no run holds this tree.
  }
  const recover = run(['--recover'])
  if (lockedByOwnRun) {
    assert.equal(recover.status, 2, recover.stdout)
    assert.match(recover.stderr, /a falsify run is in progress/)
  } else {
    assert.equal(recover.status, 0, recover.stderr)
    assert.match(recover.stdout, /nothing to recover/)
  }
  // None of it touched anything.
  assert.equal(existsSync(journalPath) ? readFileSync(journalPath, 'utf8') : undefined, before)
})
