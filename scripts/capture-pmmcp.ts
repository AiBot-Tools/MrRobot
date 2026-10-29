// Operator-only: capture pmmcp's live tool schemas.
//
// The capture is the reference for everything this repo believes about pmmcp's
// tool surface: the double serves the goal and vault tools from it verbatim,
// src/mcp/pmmcp-schemas.ts types them and is held to it, and
// `test/pmmcp-drift.test.ts` checks the rest of the double's argument names
// against it on every test run. Re-run this on the Mac with pmmcp up after a
// pmmcp upgrade, and the tests name every disagreement.
//
//   npm run capture:pmmcp [-- OUT] [-- --config PATH]
//
// kernel.yaml declares pmmcp's bearer (`tokenEnv: AOS_PMMCP_TOKEN`), and this
// reads no .env (decision D37 is open), so that variable must be in its
// environment: README gives the one-command form, which exports nothing. A
// declared name left unset is refused before anything is dialled.
//
// It writes test/fixtures/pmmcp-listtools.json (or OUT, never this checkout's
// .env, which it refuses however it is spelled) and nothing else. It
// makes one outbound connection, to the loopback URL in kernel.yaml, and calls
// tools/list only — no tool is invoked, so nothing in the operator's memory or
// vault is read or written.
//
// The capture is a schema record and is safe to commit: tool names, descriptions,
// input schemas and output schemas (kept since contract §6 step 2.1.3, so the
// next capture shows whether pmmcp's goal tools publish a typed P6 result,
// FastMCP's `{result: string}`, or nothing; see src/mcp/capture.ts). It contains no memory contents and no secret. Check it
// anyway before committing — a description written by whoever authored the
// server is text this repo has never seen.

import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { parse as parseYaml } from 'yaml'

import { namesRepoDotenv } from '../src/agents/protected.js'
import { parseKernelConfig } from '../src/config.js'
import { captureOf } from '../src/mcp/capture.js'
import { listToolPages, streamableHttpTransport } from '../src/mcp/hub.js'
import { redactString } from '../src/events/redact.js'
import { bearerRefusal } from '../src/secrets/broker.js'
import { VERSION } from '../src/version.js'

export const CAPTURE_PATH = 'test/fixtures/pmmcp-listtools.json'

async function main(argv: readonly string[]): Promise<number> {
  const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
  // --config exists so the offline test can point this at a closed port: pmmcp's
  // gate runs in warn mode, so with a bearer set the shipped config would reach
  // the operator's live pmmcp.
  const args = [...argv]
  let configPath = join(repoRoot, 'config', 'kernel.yaml')
  const flag = args.indexOf('--config')
  if (flag !== -1) {
    const value = args[flag + 1]
    if (value === undefined) {
      process.stderr.write('--config needs a path\n')
      return 1
    }
    configPath = resolve(value)
    args.splice(flag, 2)
  }
  // Refused before anything is dialled: the capture must not land on the
  // operator's keys, however the path is spelled.
  const out = args[0] ?? join(repoRoot, CAPTURE_PATH)
  if (namesRepoDotenv(out, repoRoot)) {
    process.stderr.write(`${out} names this checkout's credentials file, which holds your keys: give the capture another path\n`)
    return 1
  }
  const config = parseKernelConfig(parseYaml(readFileSync(configPath, 'utf8')), { repoRoot })

  const server = config.mcp.servers['pmmcp']
  if (server === undefined) {
    process.stderr.write('config/kernel.yaml declares no pmmcp server\n')
    return 1
  }
  const tokenEnv = server.tokenEnv
  const token = tokenEnv === undefined ? undefined : process.env[tokenEnv]
  if (tokenEnv !== undefined && (token === undefined || token.trim() === '')) {
    process.stderr.write(`${tokenEnv} is not set\n`)
    return 1
  }
  // A bearer the HTTP library would refuse makes it throw with the whole header
  // value in its message, which would land on this terminal: refuse by name.
  // One that passes is masked before it is sent, because a server that echoes
  // it in a refusal puts it in the SDK's error, and that error is printed.
  const refusal = token === undefined ? undefined : bearerRefusal(tokenEnv ?? 'the bearer', token)
  if (refusal !== undefined) {
    process.stderr.write(`${refusal}\n`)
    return 1
  }

  const client = new Client({ name: 'aos-capture', version: VERSION })
  await client.connect(streamableHttpTransport(server.url, token))
  try {
    // Paginated: a server that pages its tool list would otherwise be captured
    // one page deep, and a short capture reads exactly like a shrunken server.
    const { tools, pages } = await listToolPages(client)
    const capture = captureOf(tools, { capturedAt: new Date().toISOString(), server: 'pmmcp', url: server.url, pages })
    writeFileSync(out, `${JSON.stringify(capture, null, 2)}\n`)
    process.stdout.write(`captured ${String(tools.length)} tools to ${out}\n`)
    return 0
  } finally {
    await client.close()
  }
}

// Only when run as the entry point. Compared as resolved paths rather than by
// suffix: a suffix test matches any file whose name happens to end the same way.
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((e: unknown) => {
      process.stderr.write(`${redactString(e instanceof Error ? e.message : String(e))}\n`)
      process.exit(1)
    })
}
