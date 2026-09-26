// Operator-only: run the orchestration eval suite against a live daemon.
//
//   npm run dev                      # in one shell, with .env sourced
//   AOS_CONTROL_TOKEN=… npm run eval # in another
//
// THIS SPENDS REAL MONEY. Every case is a real run against whatever model the
// agent is bound to, under that agent's real budget. The suite's ceilings are
// per-case and well inside D30's per-run caps, but the total is the sum of them.
//
// What it is for: CLAUDE.md says `orchestrator: true` on a model card is "set by
// the human after the eval harness, never by code". This produces the evidence
// for that decision and nothing else — it writes no config, sets no flag, and
// changes no manifest. Its exit code is 0 only when every gate that ran passed,
// and a 0 with a large "not applicable" count is not a good result: read the
// report, not the exit code.
//
// It reads the event log read-only, the same way `verify-chain` does while the
// daemon holds the database.

import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { CEO_CHECKS } from '../src/eval/checks.js'
import { runSuite, type EvalTarget } from '../src/eval/harness.js'
import { exitCode, renderSuite, toJson } from '../src/eval/report.js'
import { CEO_SUITE } from '../src/eval/suite.js'

function flag(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`)
  return i === -1 ? undefined : argv[i + 1]
}

async function main(argv: readonly string[]): Promise<number> {
  const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
  const configPath = flag(argv, 'config') ?? join(repoRoot, 'config', 'kernel.yaml')
  const config = parseKernelConfig(parseYaml(readFileSync(configPath, 'utf8')), { repoRoot })

  const token = process.env[config.control.tokenEnv]
  if (token === undefined || token.trim() === '') {
    process.stderr.write(`${config.control.tokenEnv} is not set\n`)
    return 2
  }
  const portArg = flag(argv, 'port')
  const port = portArg === undefined ? config.control.port : Number(portArg)
  if (!Number.isInteger(port) || port <= 0) {
    process.stderr.write(`--port must be a positive integer, got ${String(portArg)}\n`)
    return 2
  }

  const only = flag(argv, 'case')
  const cases = only === undefined ? CEO_SUITE : CEO_SUITE.filter((c) => c.id === only)
  if (cases.length === 0) {
    process.stderr.write(`no case ${String(only)}; known: ${CEO_SUITE.map((c) => c.id).join(', ')}\n`)
    return 2
  }

  const target: EvalTarget = {
    port,
    token,
    dbPath: join(config.dataDir, 'events.db'),
  }

  process.stdout.write(
    `running ${String(cases.length)} case(s) against 127.0.0.1:${String(port)} — this spends real money\n\n`,
  )
  const suite = await runSuite(target, cases, CEO_CHECKS)
  process.stdout.write(`${renderSuite(suite)}\n`)

  const jsonPath = flag(argv, 'json')
  if (jsonPath !== undefined) {
    writeFileSync(jsonPath, toJson(suite))
    process.stdout.write(`\nwrote ${jsonPath}\n`)
  }
  return exitCode(suite)
}

// Only when run as the entry point. Compared as resolved paths rather than by
// suffix: a suffix test matches any file whose name happens to end the same way.
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((e: unknown) => {
      process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`)
      process.exit(1)
    })
}
