// Phase 1 live runtime tests — gated, and run against the real things.
//
// Everything Phase 1 built was proven against doubles: the pmmcp goal tools whose
// names are MODELLED, a plan parser that has only ever seen plans written by the
// person who wrote the parser, and an eval harness whose gates assume a provider
// accounts for cost the way the double does. These tests take the same bodies
// that test/runtime-bodies.test.ts runs offline on every `npm test` and point them
// at the operator's pmmcp and the real model.
//
// THREE GATES, EACH NAMED IN ITS SKIP REASON:
//
//   AOS_LIVE_TESTS=1          spends money and needs the network (D29), as in
//                             the Phase 0 live file.
//   AOS_LIVE_PMMCP_WRITES=1   a SECOND, separate opt-in for anything that writes
//                             to the operator's long-term memory. Spending money is
//                             reversible in the sense that it ends; a goal written
//                             into pmmcp stays there. Everything these tests write
//                             goes to `aos/agent/aos-live-test` — never `aos/ceo` —
//                             and nothing here deletes it, because the kernel has no
//                             delete and a test must not grow one.
//   the credentials           each test names the ones it needs.
//
// The only other file allowed to skip is live-anthropic.test.ts, by the hygiene
// rule that admits `test/live-*.test.ts` by name and requires each to read its gate
// from the environment.

import { allowHost } from './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { parse as parseYaml } from 'yaml'

import { connectControl } from '../src/cli/client.js'
import { parseKernelConfig } from '../src/config.js'
import { McpHub, streamableHttpTransport } from '../src/mcp/hub.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { parseProviders } from '../src/models/registry.js'
import type { Kernel } from '../src/kernel.js'
import { fakeSandbox } from './helpers/fake-sandbox.js'
import { REPO_ROOT, runThroughControl, TEST_TOKEN, withKernel } from './helpers/kernel.js'
import {
  evalHarnessAssumptions,
  goalTreeRoundTrip,
  LIVE_ORCHESTRATOR,
  LIVE_TEST_PROJECT,
  liveFleet,
  PLAN_REQUEST,
  planToTree,
} from './helpers/runtime-bodies.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const LIVE = process.env['AOS_LIVE_TESTS'] === '1'
const WRITES = process.env['AOS_LIVE_PMMCP_WRITES'] === '1'
const ANTHROPIC_HOST = 'api.anthropic.com'

// PMMCP_TOKEN is optional: pmmcp takes no bearer. Set it only for a server that does.
const hasPmmcp = (): boolean => process.env['PMMCP_URL'] !== undefined

/** The one non-placeholder ref in providers.yaml, read rather than hard-coded. */
function realRef(): string {
  const file = parseProviders(parseYaml(readFileSync(`${REPO_ROOT}/config/providers.yaml`, 'utf8')))
  const real = Object.entries(file.entries).filter(([, e]) => !e.placeholder)
  assert.equal(real.length, 1, 'providers.yaml must carry exactly one non-placeholder entry')
  return real[0]![0]
}

function shippedGoals(): ReturnType<typeof parseKernelConfig>['goals'] {
  return parseKernelConfig(parseYaml(readFileSync(`${REPO_ROOT}/config/kernel.yaml`, 'utf8')), {
    repoRoot: REPO_ROOT,
  }).goals
}

/**
 * Probe over the control socket. D28: the router refuses an unprobed ref, so
 * without this a run finishes router-degraded at zero cost and every assertion
 * after it is measuring the refusal.
 */
async function probe(kernel: Kernel, ref: string): Promise<void> {
  const client = await connectControl({ port: kernel.port, token: TEST_TOKEN, timeoutMs: 180_000 })
  try {
    const result = (await client.call('model.probe', { ref })) as { toolCalling: boolean; reason?: string }
    assert.equal(result.toolCalling, true, `${ref} did not report tool calling: ${result.reason ?? 'no reason'}`)
  } finally {
    client.close()
  }
}

// ── 1. the modelled goal tool names, against the real server ───────────────

test(
  'live pmmcp: the configured goal tools match the server, and a tree round-trips through it',
  {
    // Reasons inline, where the hygiene rule reads them: each names what to set.
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !hasPmmcp()
        ? 'set PMMCP_URL (PMMCP_TOKEN only if the server wants a bearer)'
        : !WRITES
          ? 'set AOS_LIVE_PMMCP_WRITES=1 as well: this writes goals into pmmcp under aos/agent/aos-live-test, and they are not deleted afterwards'
          : false,
  },
  async (t) => {
    const store = withStore(t)
    const hub = new McpHub({
      store,
      views: parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8'))),
    })
    t.after(async () => {
      await hub.close()
    })
    // A real Streamable HTTP session, through the one sanctioned transport seam.
    const state = await hub.connect('pmmcp', async () => {
      const client = new Client({ name: 'aos-live-runtime', version: '0.0.1' })
      await client.connect(
        streamableHttpTransport(process.env['PMMCP_URL'] ?? '', process.env['PMMCP_TOKEN']),
      )
      return client
    })
    assert.equal(state, 'connected', 'pmmcp did not connect')

    await goalTreeRoundTrip({
      hub,
      store,
      goals: shippedGoals(),
      projectId: LIVE_TEST_PROJECT,
      runId: `run_live_${String(Date.now())}`,
    })
  },
)

// ── 2. a real model's plan through the strict parser into the real server ──

test(
  'live model + pmmcp: an orchestrator’s plan survives the strict parser and becomes a tree in the test namespace',
  {
    // Reasons inline, where the hygiene rule reads them: each names what to set.
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !hasPmmcp()
        ? 'set PMMCP_URL (PMMCP_TOKEN only if the server wants a bearer)'
        : !WRITES
          ? 'set AOS_LIVE_PMMCP_WRITES=1 as well: this writes goals into pmmcp under aos/agent/aos-live-test, and they are not deleted afterwards'
          : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)
    const ref = realRef()
    const pmmcpUrl = process.env['PMMCP_URL'] ?? ''

    // The vault is the credential path, exactly as in the Phase 0 exit criterion:
    // envFallback off AND the variable it would fall back to poisoned.
    const { kernel, fx } = await withKernel(t, {
      envFallback: false,
      env: {
        PMMCP_TOKEN: process.env['PMMCP_TOKEN'],
        ANTHROPIC_API_KEY: 'poisoned-not-a-real-key-this-must-never-be-used',
      },
      sandboxDriver: fakeSandbox(),
      kernelYaml: (base) => base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `url: ${pmmcpUrl}`),
      agentsDir: liveFleet(tmpdir(t), ref),
    })
    assert.equal(kernel.status().subsystems.hub.state, 'ok', kernel.status().subsystems.hub.reason ?? '')
    await probe(kernel, ref)

    await planToTree({
      dbPath: fx.dbPath,
      run: () => runThroughControl(kernel, PLAN_REQUEST, LIVE_ORCHESTRATOR),
      shutdown: () => kernel.shutdown(),
      projectId: LIVE_TEST_PROJECT,
    })
  },
)

// ── 3. the eval harness's own gates, against real provider accounting ─────

test(
  'live model: the eval harness’s gates hold against a real provider’s accounting',
  {
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : process.env['ANTHROPIC_API_KEY'] === undefined
        ? 'ANTHROPIC_API_KEY is not set'
        : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)
    const ref = realRef()

    // No pmmcp: this needs only a model, and the env fallback (D8) is the
    // cheapest honest way to get one. It is not an exit-criterion test.
    const { kernel, fx } = await withKernel(t, {
      envFallback: true,
      env: { ANTHROPIC_API_KEY: process.env['ANTHROPIC_API_KEY'] },
      sandboxDriver: fakeSandbox(),
    })
    await probe(kernel, ref)

    const result = await evalHarnessAssumptions({
      port: kernel.port,
      token: TEST_TOKEN,
      dbPath: fx.dbPath,
      timeoutMs: 180_000,
    })
    // Recorded in the TAP output, so a live run leaves the scorecard behind.
    t.diagnostic(
      `ceo-inline-small-objective: gates failed [${result.gatesFailed.join(', ')}], ` +
        `score ${String(result.score)}, did not run ${String(result.notApplicable.length)}`,
    )
  },
)
