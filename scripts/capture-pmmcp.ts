// Operator-only: capture pmmcp's live tool schemas.
//
// Everything this repo believes about pmmcp's tool surface — every goal tool
// name, every argument name, the status vocabulary — is a GUESS made on a Linux
// box, recorded as `provenance: 'modelled'` in test/helpers/mock-pmmcp.ts. This
// script is how those guesses become facts: run it once on the Mac with pmmcp
// up, and `test/pmmcp-drift.test.ts` starts checking the double against the real
// server on every test run instead of skipping.
//
//   PMMCP_TOKEN=... npm run capture:pmmcp
//
// It writes test/fixtures/pmmcp-listtools.json and nothing else. It makes one
// outbound connection, to the loopback URL in config/kernel.yaml, and calls
// tools/list only — no tool is invoked, so nothing in the operator's memory or
// vault is read or written.
//
// The capture is a schema record and is safe to commit: tool names, descriptions
// and input schemas. It contains no memory contents and no secret. Check it
// anyway before committing — a description written by whoever authored the
// server is text this repo has never seen.

import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { listAllTools, streamableHttpTransport } from '../src/mcp/hub.js'
import { VERSION } from '../src/version.js'

export const CAPTURE_PATH = 'test/fixtures/pmmcp-listtools.json'

interface Capture {
  readonly capturedAt: string
  readonly server: string
  readonly url: string
  readonly toolCount: number
  readonly tools: readonly { name: string; description?: string; inputSchema: unknown }[]
}

async function main(argv: readonly string[]): Promise<number> {
  const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
  const configPath = join(repoRoot, 'config', 'kernel.yaml')
  const config = parseKernelConfig(parseYaml(readFileSync(configPath, 'utf8')), { repoRoot })

  const server = config.mcp.servers['pmmcp']
  if (server === undefined) {
    process.stderr.write('config/kernel.yaml declares no pmmcp server\n')
    return 1
  }
  const tokenEnv = server.tokenEnv ?? 'PMMCP_TOKEN'
  const token = process.env[tokenEnv]
  if (token === undefined || token.trim() === '') {
    process.stderr.write(`${tokenEnv} is not set\n`)
    return 1
  }

  const client = new Client({ name: 'aos-capture', version: VERSION })
  await client.connect(streamableHttpTransport(server.url, token))
  try {
    // Paginated: a server that pages its tool list would otherwise be captured
    // one page deep, and a short capture reads exactly like a shrunken server.
    const tools = await listAllTools(client)
    const capture: Capture = {
      capturedAt: new Date().toISOString(),
      server: 'pmmcp',
      url: server.url,
      toolCount: tools.length,
      tools: tools
        .map((t) => ({
          name: t.name,
          ...(t.description === undefined ? {} : { description: t.description }),
          inputSchema: t.inputSchema,
        }))
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    }
    const out = argv[0] ?? join(repoRoot, CAPTURE_PATH)
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
      process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`)
      process.exit(1)
    })
}
