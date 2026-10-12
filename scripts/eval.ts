// Operator-only: run the orchestration eval suite against a live daemon.
//
//   npm run dev    # in one shell (reads ./.env through --dotenv)
//   npm run eval   # in another (reads only AOS_CONTROL_TOKEN from ./.env)
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
import { parseProviders } from '../src/models/registry.js'
import { assertTokenUsable } from '../src/control/auth.js'
import { credentialNames, dotenvPathFrom, oneCredential } from '../src/secrets/dotenv.js'
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

  // The shell first, then the file --dotenv names (npm run eval passes .env):
  // only the control token, never a provider key — this process needs none.
  // Parsed as the daemon parses it: either form, and a second one refused.
  let dotenvPath: string | undefined
  try {
    dotenvPath = dotenvPathFrom(argv, repoRoot)
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`)
    return 2
  }
  const token = oneCredential(config.control.tokenEnv, dotenvPath, {
    repoRoot,
    accepted:
      dotenvPath === undefined
        ? new Set([config.control.tokenEnv])
        : credentialNames(config, parseProviders(parseYaml(readFileSync(join(repoRoot, 'config', 'providers.yaml'), 'utf8')))),
    shell: process.env,
  })
  if (token === undefined || token.trim() === '') {
    process.stderr.write(
      `${config.control.tokenEnv} is not set` +
        (dotenvPath === undefined ? ' (export it, or run npm run eval, which reads .env)\n' : ` (export it, or add it to ${dotenvPath})\n`),
    )
    return 2
  }
  // The daemon's own rules (length, printable ASCII), before anything spends.
  try {
    assertTokenUsable(token)
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`)
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
    token: token.trim(),
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
