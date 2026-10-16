// Daemon entry point: `npm run dev`.
//
// This file does four things and nothing else — read the config files, assemble
// the credential environment (the shell, then the file `--dotenv` names; npm run
// dev passes `--dotenv .env`), boot, and arrange for a clean shutdown. Everything interesting is in kernel.ts,
// because a daemon entry point that also makes decisions is a second place to
// look when the kernel behaves differently under launchd than under a test.
//
// A signal shuts the kernel down rather than killing the process: shutdown
// writes `kernel.shutdown` and the anchor, and an exit that skipped both would
// leave the next boot looking at a log ahead of its anchor for no reason. The
// second signal is not polite — if a shutdown hangs, the operator gets their
// terminal back.

import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { ConfigError } from './errors.js'
import { bootKernel } from './kernel.js'
import { parseKernelConfig, type KernelConfig } from './config.js'
import { parseProviders, type ProvidersFile } from './models/registry.js'
import { credentialEnv, credentialNames, dotenvPathFrom, loadDotenv, type DotenvResult } from './secrets/dotenv.js'
import { parseToolViews } from './mcp/tool-views.js'
import { log } from './log.js'
import { VERSION } from './version.js'

function readYaml(path: string): unknown {
  return parseYaml(readFileSync(path, 'utf8'))
}

/**
 * The journal `npm run falsify` keeps while a source file is mutated
 * (scripts/falsify/runner.ts JOURNAL_DIR/JOURNAL). While it exists, a file in
 * src/ may hold a deliberately planted bug — a disabled check, a credentials
 * path — so the daemon does not start, whether the run is live or died.
 */
export const FALSIFY_JOURNAL = join('.falsify', 'journal.json')
export const FALSIFY_LOCK = join('.falsify', 'lock.json')

/**
 * The pid of a live falsify run holding this tree, or undefined. Between two
 * mutants (a baseline) there is no journal, but the next mutant is seconds
 * away. Live means the pid exists: a reused pid after a crash is a refusal
 * that `npm run falsify -- --recover` (which also checks the start time) clears.
 */
function falsifyHolder(repoRoot: string): number | undefined {
  let pid: unknown
  try {
    pid = (JSON.parse(readFileSync(join(repoRoot, FALSIFY_LOCK), 'utf8')) as { pid?: unknown }).pid
  } catch {
    return undefined
  }
  if (typeof pid !== 'number' || pid === process.pid) return undefined
  try {
    process.kill(pid, 0)
    return pid
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM' ? pid : undefined
  }
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const repoRoot = resolve(process.cwd())
  if (existsSync(join(repoRoot, FALSIFY_JOURNAL))) {
    throw new ConfigError(
      `${join(repoRoot, FALSIFY_JOURNAL)} exists: a falsify run is in progress or was interrupted, and a source ` +
        'file may still be mutated. Let it finish, or run: npm run falsify -- --recover',
    )
  }
  const holder = falsifyHolder(repoRoot)
  if (holder !== undefined) {
    throw new ConfigError(
      `a falsify run (pid ${String(holder)}) holds this tree and mutates its source files as it goes. Let it finish; ` +
        'if none is going, run: npm run falsify -- --recover',
    )
  }
  const configPath = configPathFrom(argv, repoRoot)

  const config = parseKernelConfig(readYaml(configPath), {
    repoRoot,
    ...(process.env['AOS_DATA_DIR'] === undefined ? {} : { dataDirOverride: process.env['AOS_DATA_DIR'] }),
  })
  const providers = parseProviders(readYaml(join(repoRoot, 'config', 'providers.yaml')))
  const toolViews = parseToolViews(readYaml(join(repoRoot, 'config', 'tool-views.yaml')))

  // The credentials, and nothing else: bootKernel gets an env holding exactly
  // the names the config declares, from the shell or the operator's .env.
  // process.env is never written, so no child process and no SDK ambient read
  // sees a file-sourced value.
  const { env, loaded } = daemonEnv(argv, { repoRoot, config, providers, shell: process.env })
  if (loaded === undefined) {
    log.info('credentials: shell only (no --dotenv)')
  } else if (!loaded.found) {
    log.info({ path: loaded.path }, `credentials: shell only (${loaded.path} not found)`)
  } else {
    const fromFile = Object.keys(loaded.values)
    log.info({ path: loaded.path, names: fromFile }, `credentials: .env (${fromFile.join(', ') || 'none'})`)
  }
  if (loaded !== undefined && loaded.shadowed.length > 0) {
    log.warn(
      { names: loaded.shadowed },
      `the shell overrides .env for ${loaded.shadowed.join(', ')}; unset them to use .env`,
    )
  }
  const kernel = await bootKernel({ config, repoRoot, providers, toolViews, env })

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

/**
 * The env a daemon boots with: exactly the configured credential names, each
 * from a shell value that is not blank or else the file `--dotenv` names.
 * Without the flag no file is opened, so importing this module opens nothing;
 * a test that passes the flag runs from shadowCheckout()'s copy, against its
 * trap .env, never from the operator's checkout.
 */
export function daemonEnv(
  argv: readonly string[],
  ctx: {
    readonly repoRoot: string
    readonly config: KernelConfig
    readonly providers: ProvidersFile
    readonly shell: Readonly<Record<string, string | undefined>>
  },
): { readonly env: Record<string, string | undefined>; readonly loaded: DotenvResult | undefined; readonly names: ReadonlySet<string> } {
  const names = credentialNames(ctx.config, ctx.providers)
  const path = dotenvPathFrom(argv, ctx.repoRoot)
  const loaded =
    path === undefined
      ? undefined
      : loadDotenv(path, { repoRoot: ctx.repoRoot, accepted: names, wanted: [...names], shell: ctx.shell })
  return { env: credentialEnv(names, ctx.shell, loaded), loaded, names }
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
