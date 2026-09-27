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
// exit path leaves a mutant behind:
//   the original bytes are written to a journal BEFORE the edit, and a run that
//     finds a journal restores it first — a SIGKILL mid-mutant is recovered by
//     the next start;
//   restore happens in `finally`, and SIGINT/SIGTERM restore before exiting;
//   the test process runs in its own process group and the whole group is
//     killed on timeout, so a hung child cannot outlive the verdict.

import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

const JOURNAL_DIR = '.falsify'
const JOURNAL = 'journal.json'

interface Journal {
  readonly file: string
  /** The original bytes, base64 — exact, whatever the encoding. */
  readonly original: string
}

// ── journal ────────────────────────────────────────────────────────────────

function journalPath(root: string): string {
  return join(root, JOURNAL_DIR, JOURNAL)
}

/**
 * Put back whatever an interrupted run left mutated. Returns the file it
 * restored, or undefined when there was nothing to do.
 */
export function recoverInterrupted(root: string): string | undefined {
  const path = journalPath(root)
  if (!existsSync(path)) return undefined
  const journal = JSON.parse(readFileSync(path, 'utf8')) as Journal
  writeFileSync(join(root, journal.file), Buffer.from(journal.original, 'base64'))
  rmSync(path)
  return journal.file
}

function writeJournal(root: string, journal: Journal): void {
  const path = journalPath(root)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(journal))
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
export function nodeTestRunner(root: string): RunTests {
  return (tests, timeoutMs) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, ['--import', 'tsx', '--test', '--test-reporter=tap', ...tests], {
        cwd: root,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        // A runner started from inside node:test inherits NODE_TEST_CONTEXT,
        // which switches the nested run to the parent's binary protocol and
        // leaves no TAP to read. Options are the runner's own to set.
        env: Object.fromEntries(
          Object.entries(process.env).filter(([k]) => k !== 'NODE_TEST_CONTEXT' && k !== 'NODE_OPTIONS'),
        ),
      })
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
  const runTests = options.runTests ?? nodeTestRunner(root)
  const log = options.log ?? (() => undefined)

  const recovered = recoverInterrupted(root)
  if (recovered !== undefined) log(`restored ${recovered}, left mutated by an interrupted run`)

  let current: Journal | undefined
  const restore = (): void => {
    if (current === undefined) return
    writeFileSync(join(root, current.file), Buffer.from(current.original, 'base64'))
    rmSync(journalPath(root), { force: true })
    current = undefined
  }
  const onSignal = (signal: NodeJS.Signals): void => {
    restore()
    process.exit(signal === 'SIGINT' ? 130 : 143)
  }
  process.once('SIGINT', onSignal)
  process.once('SIGTERM', onSignal)

  const reports: SuiteReport[] = []
  try {
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
        current = { file: mutant.file, original: original.toString('base64') }
        writeJournal(root, current)
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
    process.removeListener('SIGINT', onSignal)
    process.removeListener('SIGTERM', onSignal)
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
