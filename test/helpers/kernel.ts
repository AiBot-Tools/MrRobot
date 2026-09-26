// Kernel harness.
//
// `bootKernel` opens its own store, so a kernel-level test cannot use
// `withStore`. That must not mean the kernel's log escapes the verification
// every other writing test submits to — the kernel is the component that
// writes the most events, and it would be the worst one to leave unchecked.
//
// So this helper shuts the kernel down at the end of the test and then reopens
// the database READ-ONLY to run the same two checks withStore runs: the chain
// verifies end to end, and every stored row's hash recomputes from the stored
// bytes. Reopening is what makes it possible at all — verification has to
// happen after `shutdown()` has written `kernel.shutdown` and the anchor, and
// by then the kernel's own handle is closed.
//
// Nothing here reaches the network or a container runtime: pmmcp is pointed at
// a closed loopback port and the sandbox driver is a double.

import './guard.js'

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { TestContext } from 'node:test'
import { parse as parseYaml } from 'yaml'

import { hashRow, readAllRows } from '../../src/events/chain.js'
import { EventStore } from '../../src/events/store.js'
import { parseKernelConfig, type KernelConfig } from '../../src/config.js'
import { parseProviders, type ProvidersFile } from '../../src/models/registry.js'
import { parseToolViews, type ToolViewsFile } from '../../src/mcp/tool-views.js'
import { bootKernel, type BootOptions, type Kernel } from '../../src/kernel.js'
import { fakeSandbox } from './fake-sandbox.js'
import { tmpdir } from './tmpdir.js'

export const REPO_ROOT = new URL('../..', import.meta.url).pathname.replace(/\/$/, '')

/** A token at or above the control plane's floor. */
export const TEST_TOKEN = 'k'.repeat(40)

/**
 * A port nothing is listening on, so the hub's connect fails the way a missing
 * pmmcp fails rather than hanging. 1 is privileged and unbindable here, which
 * makes the refusal immediate.
 */
const CLOSED_PMMCP_PORT = 9

export interface KernelFixture {
  readonly dataDir: string
  readonly configPath: string
  readonly config: KernelConfig
  readonly providers: ProvidersFile
  readonly toolViews: ToolViewsFile
  readonly dbPath: string
  readonly headFile: string
}

export interface FixtureOptions {
  /** Extra YAML appended to the generated kernel.yaml, for per-test overrides. */
  readonly kernelYaml?: (base: string) => string
  readonly anchorEvery?: number
  readonly envFallback?: boolean
}

/** Build a temp data dir and a kernel.yaml pointing at it. */
export function fixture(t: TestContext, options: FixtureOptions = {}): KernelFixture {
  const root = tmpdir(t)
  const dataDir = join(root, 'data')
  const work = join(root, 'work')
  mkdirSync(dataDir, { recursive: true })
  mkdirSync(work, { recursive: true })

  const base = `
version: 1
dataDir: ${dataDir}
control:
  # 0: the OS picks a free port, so parallel test files never collide.
  port: 0
  allowedOrigins: []
events:
  anchorEvery: ${String(options.anchorEvery ?? 100)}
mcp:
  servers:
    pmmcp:
      url: http://127.0.0.1:${String(CLOSED_PMMCP_PORT)}/mcp
      tokenEnv: PMMCP_TOKEN
secrets:
  envFallback: ${String(options.envFallback ?? false)}
sandbox:
  image: aos-worker:test
  domains:
    trusted: { dockerHost: "unix:///tmp/t.sock", network: aos-trusted, mountRoot: ${work} }
    hostile: { dockerHost: "unix:///tmp/h.sock", network: aos-hostile, mountRoot: ${work} }
`
  const text = options.kernelYaml === undefined ? base : options.kernelYaml(base)
  const configPath = join(root, 'kernel.yaml')
  writeFileSync(configPath, text)

  // The SHIPPED files, deliberately: a boot test that invented its own
  // providers and tool views would pass while the real pair did not.
  const read = (name: string): unknown =>
    parseYaml(readFileSync(join(REPO_ROOT, 'config', name), 'utf8'))

  return {
    dataDir,
    configPath,
    config: parseKernelConfig(parseYaml(text), { repoRoot: REPO_ROOT }),
    providers: parseProviders(read('providers.yaml')) as ProvidersFile,
    toolViews: parseToolViews(read('tool-views.yaml')),
    dbPath: join(dataDir, 'events.db'),
    headFile: join(dataDir, 'events.head'),
  }
}

export interface WithKernelOptions extends FixtureOptions {
  readonly env?: Record<string, string | undefined>
  readonly sandboxDriver?: BootOptions['sandboxDriver']
  readonly clientFactory?: BootOptions['clientFactory']
  readonly now?: () => number
}

export interface BootedKernel {
  readonly kernel: Kernel
  readonly fx: KernelFixture
}

/**
 * Boot a kernel whose log is verified when the test ends.
 *
 * The kernel is shut down in teardown if the test has not already done so, and
 * the chain is then checked by reopening the file.
 */
export async function withKernel(
  t: TestContext,
  options: WithKernelOptions = {},
): Promise<BootedKernel> {
  const fx = fixture(t, options)
  const kernel = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN, ...options.env },
    sandboxDriver: options.sandboxDriver ?? fakeSandbox(),
    ...(options.clientFactory === undefined ? {} : { clientFactory: options.clientFactory }),
    ...(options.now === undefined ? {} : { now: options.now }),
  })

  registerVerify(t, fx.dbPath, async () => {
    await kernel.shutdown()
  })
  return { kernel, fx }
}

/**
 * Register the same end-of-test verification withStore performs, for a store
 * this test does not own a handle to.
 */
export function registerVerify(t: TestContext, dbPath: string, close: () => Promise<void>): void {
  t.after(async () => {
    await close()
    verifyAt(dbPath)
  })
}

/** verifyChain plus a per-row rehash, over a read-only reopen. */
export function verifyAt(dbPath: string): void {
  if (!existsSync(dbPath)) return
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    const result = store.verifyChain(store.readAnchor())
    assert.equal(
      result.ok,
      true,
      result.ok ? '' : `kernel log failed verification at seq ${String(result.at)}: ${result.reason}`,
    )
    for (const row of readAllRows(store.db)) {
      const { hash, ...unhashed } = row
      assert.equal(
        hashRow(unhashed),
        hash,
        `row ${String(row.seq)} hash does not match a recomputation over the stored bytes`,
      )
    }
  } finally {
    store.close()
  }
}
