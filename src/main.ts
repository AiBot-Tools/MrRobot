// Daemon entry point: `npm run dev`.
//
// This file does three things and nothing else — read the config files, boot,
// and arrange for a clean shutdown. Everything interesting is in kernel.ts,
// because a daemon entry point that also makes decisions is a second place to
// look when the kernel behaves differently under launchd than under a test.
//
// A signal shuts the kernel down rather than killing the process: shutdown
// writes `kernel.shutdown` and the anchor, and an exit that skipped both would
// leave the next boot looking at a log ahead of its anchor for no reason. The
// second signal is not polite — if a shutdown hangs, the operator gets their
// terminal back.

import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { bootKernel } from './kernel.js'
import { parseKernelConfig } from './config.js'
import { parseProviders } from './models/registry.js'
import { parseToolViews } from './mcp/tool-views.js'
import { log } from './log.js'
import { VERSION } from './version.js'

function readYaml(path: string): unknown {
  return parseYaml(readFileSync(path, 'utf8'))
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const repoRoot = resolve(process.cwd())
  const configPath = configPathFrom(argv, repoRoot)

  const config = parseKernelConfig(readYaml(configPath), {
    repoRoot,
    ...(process.env['AOS_DATA_DIR'] === undefined ? {} : { dataDirOverride: process.env['AOS_DATA_DIR'] }),
  })
  const providers = parseProviders(readYaml(join(repoRoot, 'config', 'providers.yaml')))
  const toolViews = parseToolViews(readYaml(join(repoRoot, 'config', 'tool-views.yaml')))

  const kernel = await bootKernel({ config, repoRoot, providers, toolViews })

  log.info(
    { version: VERSION, port: kernel.port, dataDir: config.dataDir, degraded: kernel.degraded },
    `aos-kernel listening on 127.0.0.1:${String(kernel.port)}`,
  )
  if (kernel.degraded.length > 0) {
    // Named on stderr as well as in the log: an operator who started the
    // daemon expects to be told what is missing without querying for it.
    log.warn({ degraded: kernel.degraded }, 'booted degraded — run `aos agents` or status.get for reasons')
  }

  await new Promise<void>((resolveExit) => {
    let shuttingDown = false
    const stop = (signal: string): void => {
      if (shuttingDown) {
        // A hung shutdown must not trap the operator.
        log.error({ signal }, 'second signal during shutdown; exiting immediately')
        process.exit(1)
      }
      shuttingDown = true
      log.info({ signal }, 'shutting down')
      void kernel
        .shutdown('signal', signal)
        .catch((e: unknown) => {
          log.error({ err: e instanceof Error ? e.message : String(e) }, 'shutdown failed')
        })
        .finally(resolveExit)
    }
    process.once('SIGINT', () => stop('SIGINT'))
    process.once('SIGTERM', () => stop('SIGTERM'))
  })

  return 0
}

function configPathFrom(argv: readonly string[], repoRoot: string): string {
  const i = argv.indexOf('--config')
  const given = i === -1 ? undefined : argv[i + 1]
  return given === undefined ? join(repoRoot, 'config', 'kernel.yaml') : resolve(repoRoot, given)
}

// Only when run as the entry point, so importing this module in a test does
// not start a daemon. Compared as resolved paths rather than by suffix: a
// suffix test matches any file whose name happens to end the same way.
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  main()
    .then((code) => process.exit(code))
    .catch((e: unknown) => {
      log.error({ err: e instanceof Error ? e.message : String(e) }, 'kernel failed to boot')
      process.exit(1)
    })
}
