// The key a gated live test spends, from the shell or the operator's <repo>/.env.
//
// The ONLY test code allowed to open the repository's real .env, and only when
// the run is the operator's gated live run (AOS_LIVE_TESTS=1). Every other test
// either passes an explicit env or reads nothing: the guard has already removed
// credential names from the offline process, and no entry point a test starts
// is given --dotenv.

import { KEEPS_CREDENTIALS } from './guard.js'

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../../src/config.js'
import { parseProviders } from '../../src/models/registry.js'
import { credentialNames, oneCredential } from '../../src/secrets/dotenv.js'
import { REPO_ROOT } from './kernel.js'

/**
 * A non-blank shell value for `name`, else the file's (through the same loader
 * and refusals as `npm run dev`), else undefined. The file is `path` when one
 * is given — tests of this helper pass a temp file — and otherwise the real
 * <repo>/.env, which only a live test's own process may open.
 *
 * @throws {Error} unless AOS_LIVE_TESTS=1 in `env`, and, with no `path`,
 *   unless this process is a test/live-*.test.ts file on the live run
 *   (KEEPS_CREDENTIALS) — enforced here, at run time, so no call form an
 *   offline test could write reaches the real file.
 */
export function liveCredential(
  name: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
  path?: string,
): string | undefined {
  if (env['AOS_LIVE_TESTS'] !== '1') throw new Error('liveCredential is for AOS_LIVE_TESTS=1 only')
  if (path === undefined && !KEEPS_CREDENTIALS) {
    throw new Error('liveCredential opens <repo>/.env only from a test/live-*.test.ts process on AOS_LIVE_TESTS=1; pass a path')
  }
  const read = (p: string): unknown => parseYaml(readFileSync(join(REPO_ROOT, p), 'utf8'))
  const accepted = credentialNames(
    parseKernelConfig(read('config/kernel.yaml'), { repoRoot: REPO_ROOT }),
    parseProviders(read('config/providers.yaml')),
  )
  return oneCredential(name, path ?? join(REPO_ROOT, '.env'), { repoRoot: REPO_ROOT, accepted, shell: env })
}
