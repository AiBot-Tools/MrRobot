// Run the mutation catalog: does the suite catch the bugs it claims to?
//
//   npm run falsify                    # every suite
//   npm run falsify -- delegation      # one suite (or several, space-separated)
//   npm run falsify -- --only D1,W3    # named mutants, across suites
//   npm run falsify -- --list          # the catalog, without running anything
//
// It EDITS SOURCE FILES in the working tree, one mutant at a time, and puts
// each back before the next. A run killed outright (SIGKILL, a power cut) is
// recovered by the next start from the journal in .falsify/. By default it
// refuses to touch a file with uncommitted changes, so `git checkout` is always
// a second way back; --allow-dirty lifts that for a deliberate local run.
//
// Exit 0 only when every mutant was killed, every control survived and every
// baseline was green. Slow by design: each mutant is a full run of its suite's
// test files. Nothing here spends money or touches the network.

import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { CATALOG } from './falsify/catalog.js'
import { problems, render, runSuites, type Mutant, type Suite } from './falsify/runner.js'

const USAGE = 'usage: npm run falsify -- [suite ...] [--only ID,ID] [--timeout MS] [--allow-dirty] [--list]'

function flag(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`)
  return i === -1 ? undefined : argv[i + 1]
}

function gitClean(root: string): (files: readonly string[]) => void {
  return (files) => {
    const diff = spawnSync('git', ['diff', '--quiet', 'HEAD', '--', ...files], { cwd: root })
    if (diff.status !== 0) {
      throw new Error(
        `uncommitted changes in ${files.join(', ')} — commit them, or pass --allow-dirty to rely on the journal alone`,
      )
    }
  }
}

async function main(argv: readonly string[]): Promise<number> {
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
  const valueOf = new Set(['--only', '--timeout'])
  const positional = argv.filter((a, i) => !a.startsWith('--') && !valueOf.has(argv[i - 1] ?? ''))

  const unknown = positional.filter((name) => !CATALOG.some((s) => s.name === name))
  if (unknown.length > 0) {
    process.stderr.write(`unknown suite: ${unknown.join(', ')}\nsuites: ${CATALOG.map((s) => s.name).join(', ')}\n${USAGE}\n`)
    return 2
  }
  const only = flag(argv, 'only')?.split(',').filter((s) => s !== '')
  const known = new Set(CATALOG.flatMap((s) => s.mutants.map((m) => m.id)))
  const missing = (only ?? []).filter((id) => !known.has(id))
  if (missing.length > 0) {
    process.stderr.write(`unknown mutant: ${missing.join(', ')}\n${USAGE}\n`)
    return 2
  }
  const timeoutMs = Number(flag(argv, 'timeout') ?? 240_000)
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000) {
    process.stderr.write(`--timeout must be an integer of at least 1000 ms\n${USAGE}\n`)
    return 2
  }

  const suites: Suite[] = CATALOG.filter((s) => positional.length === 0 || positional.includes(s.name))
    .map((s) => (only === undefined ? s : { ...s, mutants: s.mutants.filter((m) => only.includes(m.id)) }))
    .filter((s) => s.mutants.length > 0)

  const byId = new Map<string, Mutant>()
  for (const s of CATALOG) for (const m of [...s.mutants, s.control]) byId.set(`${s.name}/${m.id}`, m)

  if (argv.includes('--list')) {
    for (const s of suites) {
      process.stdout.write(`${s.name}  (${s.tests.join(' ')})\n`)
      for (const m of s.mutants) process.stdout.write(`  ${m.id.padEnd(6)} ${m.file}  ${m.why}\n`)
    }
    return 0
  }

  const reports = await runSuites(suites, {
    root,
    timeoutMs,
    ...(argv.includes('--allow-dirty') ? {} : { assertClean: gitClean(root) }),
    log: (line) => process.stderr.write(`${line}\n`),
  })
  process.stdout.write(`${render(reports, byId)}\n`)
  return problems(reports).length === 0 ? 0 : 1
}

// Only when run as the entry point, compared as resolved paths (see eval.ts).
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((e: unknown) => {
      process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`)
      process.exit(1)
    })
}
