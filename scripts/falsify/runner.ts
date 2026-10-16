// Mutation runner: does the suite notice when the code is wrong?
//
// A test that passes proves little until it has been seen to FAIL against the
// bug it claims to catch. Each mutant here is one such bug, written down: a
// single exact edit to a source file, the tests that should catch it, and why
// it matters. The runner applies it, runs those tests, and puts the file back.
//
// Verdicts:
//   killed    at least one named test failed — the suite caught the bug
//   survived  every test passed — a real gap, or a mutant that changes nothing
//   hung      the tests did not finish inside the timeout. NOT a kill: a hang is
//             a test with no bound, and the one time this repo met one, the
//             "hang" was a lost-wakeup race in the test, not the mutant working
//   invalid   the mutant could not be judged: its anchor did not match exactly
//             once, it left the file unparseable, or the test files failed to
//             load at all. A syntax error fails every test, which would read as
//             a kill and prove nothing, so it is never counted as one
//
// Every suite also runs its tests UNMUTATED first (a red baseline makes every
// mutant look killed) and runs a control — an edit to a comment — that must
// survive; a control that is "killed" means the suite is flaky and nothing it
// reports can be trusted.
//
// Safety. The runner edits files in the working tree, so it is built so that no
// exit path leaves a mutant behind, and no two runs share a tree:
//   a run holds .falsify/lock for its whole length (created exclusively),
//     naming its pid AND that process's start time (from ps, in UTC and the
//     C locale, so a zone change mid-run does not orphan it), so a pid reused
//     by an unrelated process after a crash or reboot never passes for a live
//     run; a live pid ps cannot vouch for counts as held, never as dead; a
//     run that cannot read its own start time takes no lock; a stale lock is
//     removed only under .falsify/lock.break, after a re-read, so runners
//     started together on one cannot each delete the other's fresh lock;
//   the original bytes are written to a journal BEFORE the edit (to a temp
//     file, fsync'd, then renamed), and a run that finds a journal restores it
//     first — a SIGKILL or power cut mid-mutant is recovered by the next start
//     or by `npm run falsify -- --recover`;
//   restore happens in `finally`, and SIGINT, SIGTERM, SIGHUP (a closed
//     terminal, a dropped SSH session) and SIGQUIT restore, kill the running
//     test process group, and release the lock before exiting; the handlers
//     stay registered until then, so a second signal (npm forwards Ctrl-C to
//     its child, a closing terminal sends SIGHUP twice) cannot kill cleanup;
//   the journal names its run, and the run hands that id to its own test
//     processes (AOS_FALSIFY_RUN), so test/helpers/guard.ts admits a mutated
//     tree only for them; src/main.ts refuses to boot while any journal exists;
//   test processes get no live-test flag and no credential from the runner's
//     environment, so no mutant can turn a test into one that reads a real key;
//   the test process runs in its own process group and the whole group is
//     killed on timeout, so a hung child cannot outlive the verdict.

import { spawn, spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import ts from 'typescript'

export interface Mutant {
  /** Short, stable id: what a report and `--only` refer to. */
  readonly id: string
  /** Repo-relative path of the file to edit. */
  readonly file: string
  /** Exact text to replace. Must occur exactly once in the file. */
  readonly from: string
  readonly to: string
  /** The bug this stands for, in one line. */
  readonly why: string
}

export interface Suite {
  readonly name: string
  /** Repo-relative test files that should kill every mutant in the suite. */
  readonly tests: readonly string[]
  readonly mutants: readonly Mutant[]
  /** An edit that changes no behaviour. It must survive. */
  readonly control: Mutant
}

export type Verdict = 'killed' | 'survived' | 'hung' | 'invalid'

export interface Outcome {
  readonly suite: string
  readonly id: string
  readonly verdict: Verdict
  /** Failing test names for a kill; the reason for anything else. */
  readonly detail: readonly string[]
  readonly control: boolean
  readonly ms: number
}

export interface SuiteReport {
  readonly suite: string
  /** Why the suite's mutants were not run, when they were not. */
  readonly refused?: string
  readonly outcomes: readonly Outcome[]
}

export interface TestRun {
  readonly timedOut: boolean
  /** Exit code of the test process; null when it was killed. */
  readonly code: number | null
  /** Names from `not ok` lines, in order, deduplicated. */
  readonly failing: readonly string[]
  /** Names from `ok` lines. */
  readonly passing: readonly string[]
}

export type RunTests = (tests: readonly string[], timeoutMs: number) => Promise<TestRun>

export interface RunnerOptions {
  readonly root: string
  readonly timeoutMs: number
  /** Injected so the runner's own tests can drive it without node:test. */
  readonly runTests?: RunTests
  /** Called with the files a suite will edit; throws to refuse. */
  readonly assertClean?: (files: readonly string[]) => void
  readonly log?: (line: string) => void
}

/** Where the journal and the lock live, relative to the root: read by test/helpers/guard.ts and src/main.ts too. */
export const JOURNAL_DIR = '.falsify'
export const JOURNAL = 'journal.json'
export const LOCK = 'lock.json'
/** Held, exclusively and briefly, by whoever is removing a stale lock. */
export const LOCK_BREAK = 'lock.break'
/** The variable a run sets in its own test processes, naming itself. */
export const RUN_ENV = 'AOS_FALSIFY_RUN'

interface Journal {
  readonly file: string
  /** The original bytes, base64 — exact, whatever the encoding. */
  readonly original: string
  /** The run that wrote it; only that run's own test processes may test the tree. */
  readonly runId: string
}

interface Lock {
  readonly pid: number
  /** The owner's start time as `ps` reports it: with the pid, an identity no reused pid shares. */
  readonly started: string
  readonly runId: string
}

/**
 * Every signal whose default action would end the run without a restore.
 * SIGKILL cannot be caught; the journal covers it.
 */
export const RESTORING_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'] as const
const SIGNAL_NUMBERS: Partial<Record<NodeJS.Signals, number>> = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGTERM: 15 }

/** Credential names, as test/helpers/guard.ts scrubs them (falsify.test.ts keeps the two equal). */
export const CHILD_CREDENTIAL_NAME = /^(ANTHROPIC|OPENAI|OPENROUTER|MOONSHOT)_|_API_KEY$|^AOS_CONTROL_TOKEN$|^PMMCP_TOKEN$/

/**
 * The environment a test process gets: the runner's, minus what must never
 * reach a mutated test. NODE_TEST_CONTEXT would switch the nested run to the
 * parent's binary protocol and leave no TAP to read; NODE_OPTIONS is the
 * runner's own. AOS_LIVE_* would make a mutant that weakens the guard's live
 * check (X31) turn an offline test into one that opens the real <repo>/.env,
 * and a credential has no business in a mutation run at all.
 */
export function childEnv(env: NodeJS.ProcessEnv, extra: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  const kept = Object.entries(env).filter(
    ([k]) =>
      k !== 'NODE_TEST_CONTEXT' && k !== 'NODE_OPTIONS' && k !== RUN_ENV && !k.startsWith('AOS_LIVE_') && !CHILD_CREDENTIAL_NAME.test(k),
  )
  return { ...Object.fromEntries(kept), ...extra }
}

// ── journal and lock ───────────────────────────────────────────────────────

function journalPath(root: string): string {
  return join(root, JOURNAL_DIR, JOURNAL)
}

function lockPath(root: string): string {
  return join(root, JOURNAL_DIR, LOCK)
}

/** Write, fsync, rename, fsync the directory: the journal is whole or absent, never half. */
function writeDurably(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true })
  const tmp = `${path}.tmp`
  const fd = openSync(tmp, 'w', 0o600)
  try {
    writeSync(fd, text)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  renameSync(tmp, path)
  try {
    const dir = openSync(dirname(path), 'r')
    try {
      fsyncSync(dir)
    } finally {
      closeSync(dir)
    }
  } catch {
    // A platform that cannot fsync a directory: the rename is still atomic.
  }
}

/** Why a journal cannot be used, phrased as what the operator does next. */
export class JournalUnreadable extends Error {}

function readJournal(root: string): Journal | undefined {
  const path = journalPath(root)
  if (!existsSync(path)) {
    // A temp file with no journal: the run died before its rename, so before
    // its edit. Nothing was mutated.
    rmSync(`${path}.tmp`, { force: true })
    return undefined
  }
  let parsed: Partial<Journal>
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<Journal>
  } catch {
    parsed = {}
  }
  if (typeof parsed.file !== 'string' || typeof parsed.original !== 'string') {
    throw new JournalUnreadable(
      `${path} is unreadable, so it cannot say which file a run left mutated: run \`git status\`, ` +
        `\`git checkout\` any source file it lists as modified that you did not change, then delete ${dirname(path)}`,
    )
  }
  return { file: parsed.file, original: parsed.original, runId: typeof parsed.runId === 'string' ? parsed.runId : '' }
}

/**
 * Put back whatever an interrupted run left mutated. Returns the file it
 * restored, or undefined when there was nothing to do.
 *
 * @throws {JournalUnreadable} when the journal cannot be parsed.
 */
export function recoverInterrupted(root: string): string | undefined {
  const journal = readJournal(root)
  if (journal === undefined) return undefined
  writeFileSync(join(root, journal.file), Buffer.from(journal.original, 'base64'))
  rmSync(journalPath(root))
  return journal.file
}

/** How ps is told to render a start time: one zone and one locale, whatever the machine's. */
export const PS_CLOCK = { LC_ALL: 'C', TZ: 'UTC0' } as const

/**
 * The start time `ps` reports for `pid`, or undefined when it reports none (no
 * such process, or no ps to ask). Rendered in UTC and the C locale: both BSD
 * ps and procps print local time, and the Mac moves its zone with its
 * location, so a run hours long would otherwise stop matching its own lock.
 */
export function processStarted(pid: number): string | undefined {
  const r = spawnSync('ps', ['-o', 'lstart=', '-p', String(pid)], {
    encoding: 'utf8',
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ...PS_CLOCK },
  })
  const out = typeof r.stdout === 'string' ? r.stdout.trim() : ''
  return r.status === 0 && out !== '' ? out : undefined
}

/** Whether a process with this pid exists at all (EPERM: it does, and is someone else's). */
function pidExists(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM'
  }
}

function readLock(root: string): Lock | undefined {
  try {
    const lock = JSON.parse(readFileSync(lockPath(root), 'utf8')) as Partial<Lock>
    if (typeof lock.pid !== 'number' || typeof lock.started !== 'string' || typeof lock.runId !== 'string') return undefined
    return { pid: lock.pid, started: lock.started, runId: lock.runId }
  } catch {
    return undefined
  }
}

/**
 * The pid of a live run holding this tree's lock, if any. Live means the pid
 * exists AND started when the lock says it did: after a crash or a reboot the
 * same number can belong to anything.
 */
export function liveRun(root: string): number | undefined {
  const lock = readLock(root)
  if (lock === undefined || lock.pid === process.pid) return undefined
  if (!pidExists(lock.pid)) return undefined
  const started = processStarted(lock.pid)
  // The pid is alive and ps cannot say when it started: it may well be the
  // run. Fail closed: a false "dead" lets --recover or a second run write
  // over a live run's mutant.
  if (started === undefined) return lock.pid
  return started === lock.started ? lock.pid : undefined
}

/** The lock file's bytes, or undefined when there is none. */
function lockText(root: string): string | undefined {
  try {
    return readFileSync(lockPath(root), 'utf8')
  } catch {
    return undefined
  }
}

/** How long an unreadable lock is taken for one a starting run is still writing. */
const LOCK_WRITE_GRACE_MS = 10_000

/**
 * Remove the lock if it is still exactly `judged`, a lock already found stale.
 * Under lock.break, taken exclusively: two runners that both judged the same
 * stale lock must not both remove "it", because the second would be removing
 * the fresh lock the first has taken since. Every removal of a lock that is
 * not one's own happens under lock.break, so the lock cannot change between
 * the re-read here and the removal.
 */
function breakStaleLock(root: string, judged: string): void {
  const path = join(root, JOURNAL_DIR, LOCK_BREAK)
  let fd: number
  try {
    fd = openSync(path, 'wx', 0o600)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
    throw new Error(`another run is removing a stale lock on ${root} at this moment; if none is, delete ${path} and try again`)
  }
  try {
    closeSync(fd)
    if (lockText(root) === judged) rmSync(lockPath(root), { force: true })
  } finally {
    rmSync(path, { force: true })
  }
}

/**
 * Why the lock at root may not be broken now, or undefined when it is stale.
 * A live owner holds it; so does an unreadable lock written in the last few
 * seconds, which is a run between creating the file and writing it.
 */
function lockHeld(root: string): string | undefined {
  const live = liveRun(root)
  if (live !== undefined) return `a falsify run is already in progress on ${root} (pid ${String(live)})`
  if (readLock(root) === undefined) {
    let age = Infinity
    try {
      age = Date.now() - statSync(lockPath(root)).mtimeMs
    } catch {
      // Gone already.
    }
    if (age < LOCK_WRITE_GRACE_MS) return `another falsify run is starting on ${root} at this moment`
  }
  return undefined
}

/** Drop a lock whose owner is gone. Returns true when one was dropped. */
export function clearStaleLock(root: string): boolean {
  const judged = lockText(root)
  if (judged === undefined || lockHeld(root) !== undefined) return false
  breakStaleLock(root, judged)
  return lockText(root) === undefined
}

function acquireLock(root: string, runId: string): void {
  mkdirSync(join(root, JOURNAL_DIR), { recursive: true })
  // Without its start time a lock cannot tell this run from a later process
  // given the same pid, so a run that cannot read it does not take one.
  const started = processStarted(process.pid)
  if (started === undefined) {
    throw new Error('cannot read this process\'s start time with ps, so a lock could not tell this run from a reused pid; is ps on PATH?')
  }
  const lock: Lock = { pid: process.pid, started, runId }
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let fd: number
    try {
      fd = openSync(lockPath(root), 'wx', 0o600)
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
      const judged = lockText(root)
      const held = lockHeld(root)
      if (held !== undefined) throw new Error(held)
      if (judged !== undefined) breakStaleLock(root, judged)
      continue
    }
    try {
      writeSync(fd, JSON.stringify(lock))
      fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
    return
  }
  throw new Error(`could not take ${lockPath(root)}: another run is starting at the same moment`)
}

function releaseLock(root: string, runId: string): void {
  if (readLock(root)?.runId === runId) rmSync(lockPath(root), { force: true })
}

/** Test process groups in flight, so a signal exit can kill them too. */
const ACTIVE_GROUPS = new Set<number>()

function killActiveGroups(): void {
  for (const pid of ACTIVE_GROUPS) {
    try {
      process.kill(-pid, 'SIGKILL')
    } catch {
      // Already gone.
    }
  }
  ACTIVE_GROUPS.clear()
}

// ── mutation ───────────────────────────────────────────────────────────────

/** Occurrences of `needle` in `haystack`, non-overlapping. */
export function occurrences(haystack: string, needle: string): number {
  if (needle === '') return 0
  let n = 0
  for (let at = haystack.indexOf(needle); at !== -1; at = haystack.indexOf(needle, at + needle.length)) n++
  return n
}

/** Syntax errors a TypeScript parse finds; empty when the text parses. */
export function syntaxErrors(fileName: string, text: string): string[] {
  const out = ts.transpileModule(text, {
    fileName,
    reportDiagnostics: true,
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  })
  return (out.diagnostics ?? []).map((d) => ts.flattenDiagnosticMessageText(d.messageText, '\n'))
}

/**
 * Why a mutant cannot be applied to `text`, or undefined when it can. Checked
 * before any file is touched.
 */
export function unusable(mutant: Mutant, text: string): string | undefined {
  if (mutant.from === mutant.to) return 'the edit changes nothing'
  const n = occurrences(text, mutant.from)
  if (n !== 1) {
    return n === 0
      ? 'anchor not found — the code moved; update the catalog'
      : `anchor matches ${String(n)} times — make it unique`
  }
  const errors = syntaxErrors(mutant.file, text.replace(mutant.from, () => mutant.to))
  return errors.length === 0 ? undefined : `the mutant does not parse: ${errors[0] ?? ''}`
}

// ── test process ───────────────────────────────────────────────────────────

/** Parse node:test TAP for test names. */
export function parseTap(stdout: string): { failing: string[]; passing: string[] } {
  const failing: string[] = []
  const passing: string[] = []
  for (const line of stdout.split('\n')) {
    const m = /^\s*(not ok|ok) \d+ - (.*?)(?: # .*)?$/.exec(line)
    if (m === null) continue
    const name = m[2] ?? ''
    const bucket = m[1] === 'ok' ? passing : failing
    if (!bucket.includes(name)) bucket.push(name)
  }
  return { failing, passing }
}

/** The real test process: node:test under tsx, in its own process group. */
export function nodeTestRunner(root: string, extraEnv: Readonly<Record<string, string>> = {}): RunTests {
  return (tests, timeoutMs) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, ['--import', 'tsx', '--test', '--test-reporter=tap', ...tests], {
        cwd: root,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: childEnv(process.env, extraEnv),
      })
      if (child.pid !== undefined) ACTIVE_GROUPS.add(child.pid)
      let stdout = ''
      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8')
      })
      child.stderr.resume()
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        // The whole group: a test that spawned a kernel or a server must not
        // outlive the verdict, and neither may the runner's own grandchildren.
        try {
          if (child.pid !== undefined) process.kill(-child.pid, 'SIGKILL')
        } catch {
          // Already gone between the timer firing and the kill.
        }
      }, timeoutMs)
      child.on('close', (code) => {
        clearTimeout(timer)
        if (child.pid !== undefined) ACTIVE_GROUPS.delete(child.pid)
        resolve({ timedOut, code, ...parseTap(stdout) })
      })
    })
}

// ── verdicts ───────────────────────────────────────────────────────────────

/** A failing name that is a test FILE means the file itself did not load. */
const isFileLevel = (name: string): boolean => /\.test\.ts$/.test(name)

export function judge(run: TestRun): { verdict: Verdict; detail: string[] } {
  if (run.timedOut) return { verdict: 'hung', detail: ['the tests did not finish inside the timeout'] }
  const named = run.failing.filter((n) => !isFileLevel(n))
  if (named.length > 0) return { verdict: 'killed', detail: named }
  if (run.failing.length > 0 || run.code !== 0) {
    // Failed with no test to name: a load or syntax failure, which fails every
    // test and so says nothing about whether the suite catches this bug.
    return {
      verdict: 'invalid',
      detail: [`the test files failed without a named test failing (exit ${String(run.code)})`],
    }
  }
  return { verdict: 'survived', detail: [] }
}

// ── the run ────────────────────────────────────────────────────────────────

export async function runSuites(suites: readonly Suite[], options: RunnerOptions): Promise<SuiteReport[]> {
  const { root, timeoutMs } = options
  const runId = randomUUID()
  const runTests = options.runTests ?? nodeTestRunner(root, { [RUN_ENV]: runId })
  const log = options.log ?? (() => undefined)

  // The whole run holds the lock, baselines included: a second run started
  // between two mutants would otherwise read one of this run's mutants as its
  // "original" and write it back after this run had restored it.
  acquireLock(root, runId)

  let current: Journal | undefined
  const restore = (): void => {
    if (current === undefined) return
    writeFileSync(join(root, current.file), Buffer.from(current.original, 'base64'))
    rmSync(journalPath(root), { force: true })
    current = undefined
  }
  // `on`, not `once`: once removes the listener before it runs, and with the
  // last listener gone Node restores the default action, so a second signal
  // during cleanup (npm forwards Ctrl-C to its child; a closing terminal sends
  // SIGHUP twice) would kill the run mid-restore. With the listener kept, a
  // later signal only queues behind the synchronous cleanup and its exit.
  let exiting = false
  const onSignal = (signal: NodeJS.Signals): void => {
    if (exiting) return
    exiting = true
    restore()
    killActiveGroups()
    releaseLock(root, runId)
    process.exit(128 + (SIGNAL_NUMBERS[signal] ?? 15))
  }
  for (const signal of RESTORING_SIGNALS) process.on(signal, onSignal)

  const reports: SuiteReport[] = []
  try {
    const recovered = recoverInterrupted(root)
    if (recovered !== undefined) log(`restored ${recovered}, left mutated by an interrupted run`)
    for (const suite of suites) {
      const files = [...new Set([...suite.mutants, suite.control].map((m) => m.file))]
      try {
        options.assertClean?.(files)
      } catch (e) {
        reports.push({ suite: suite.name, refused: e instanceof Error ? e.message : String(e), outcomes: [] })
        continue
      }

      log(`${suite.name}: baseline`)
      const baseline = await runTests(suite.tests, timeoutMs)
      const base = judge(baseline)
      if (base.verdict !== 'survived') {
        reports.push({
          suite: suite.name,
          refused: `the unmutated baseline is not green (${base.verdict}: ${base.detail.join('; ')}); every mutant would read as killed`,
          outcomes: [],
        })
        continue
      }

      const outcomes: Outcome[] = []
      for (const [mutant, control] of [
        ...suite.mutants.map((m) => [m, false] as const),
        [suite.control, true] as const,
      ]) {
        const started = Date.now()
        const path = join(root, mutant.file)
        const original = readFileSync(path)
        const text = original.toString('utf8')
        const why = unusable(mutant, text)
        if (why !== undefined) {
          outcomes.push({ suite: suite.name, id: mutant.id, verdict: 'invalid', detail: [why], control, ms: 0 })
          log(`  ${mutant.id}: invalid — ${why}`)
          continue
        }
        current = { file: mutant.file, original: original.toString('base64'), runId }
        writeDurably(journalPath(root), JSON.stringify(current))
        try {
          writeFileSync(path, text.replace(mutant.from, () => mutant.to))
          const judged = judge(await runTests(suite.tests, timeoutMs))
          outcomes.push({ suite: suite.name, id: mutant.id, ...judged, control, ms: Date.now() - started })
          log(`  ${mutant.id}: ${judged.verdict}`)
        } finally {
          restore()
        }
      }
      reports.push({ suite: suite.name, outcomes })
    }
  } finally {
    restore()
    killActiveGroups()
    releaseLock(root, runId)
    for (const signal of RESTORING_SIGNALS) process.removeListener(signal, onSignal)
  }
  return reports
}

// ── reporting ──────────────────────────────────────────────────────────────

/** What went wrong across a run; empty means every mutant was caught. */
export function problems(reports: readonly SuiteReport[]): string[] {
  const out: string[] = []
  for (const r of reports) {
    if (r.refused !== undefined) out.push(`${r.suite}: not run — ${r.refused}`)
    for (const o of r.outcomes) {
      if (o.control) {
        if (o.verdict !== 'survived') out.push(`${r.suite}/${o.id}: the control was ${o.verdict} — the suite is not trustworthy`)
      } else if (o.verdict !== 'killed') {
        out.push(`${r.suite}/${o.id}: ${o.verdict}${o.detail.length > 0 ? ` — ${o.detail.join('; ')}` : ''}`)
      }
    }
  }
  return out
}

export function render(reports: readonly SuiteReport[], mutants: ReadonlyMap<string, Mutant>): string {
  const lines: string[] = []
  for (const r of reports) {
    lines.push(`${r.suite}${r.refused === undefined ? '' : `  NOT RUN: ${r.refused}`}`)
    for (const o of r.outcomes) {
      const tag = o.control ? `${o.verdict.toUpperCase()} (control)` : o.verdict.toUpperCase()
      lines.push(`  ${tag.padEnd(20)} ${o.id.padEnd(6)} ${mutants.get(`${r.suite}/${o.id}`)?.why ?? ''}`)
      for (const d of o.detail.slice(0, 2)) lines.push(`${' '.repeat(29)}${d}`)
    }
  }
  const bad = problems(reports)
  lines.push('', bad.length === 0 ? 'every mutant was caught; every control survived' : `${String(bad.length)} problem(s):`)
  for (const b of bad) lines.push(`  ${b}`)
  return lines.join('\n')
}
