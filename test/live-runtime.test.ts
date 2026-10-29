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
import { bootCrashable, bootOn, fixture, REPO_ROOT, rows, runThroughControl, TEST_TOKEN, withKernel } from './helpers/kernel.js'
import {
  evalHarnessAssumptions,
  goalTreeRoundTrip,
  LIVE_ORCHESTRATOR,
  LIVE_TEST_PROJECT,
  liveFleet,
  objectiveFanOut,
  PLAN_REQUEST,
  restartMidFanOut,
  planToTree,
} from './helpers/runtime-bodies.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'
import { liveCredential } from './helpers/live-env.js'

const LIVE = process.env['AOS_LIVE_TESTS'] === '1'
// From the shell, else <repo>/.env — and only on the gated live run.
const KEY = LIVE ? liveCredential('ANTHROPIC_API_KEY') : undefined
const WRITES = process.env['AOS_LIVE_PMMCP_WRITES'] === '1'
const ANTHROPIC_HOST = 'api.anthropic.com'

// AOS_PMMCP_TOKEN is optional: pmmcp's bearer gate runs in warn mode and serves a
// request without one. Give PMMCP_URL inline on the one command, never exported:
// pmmcp's load_config refuses to start from a shell that exports a PMMCP_ name.
const hasPmmcp = (): boolean => process.env['PMMCP_URL'] !== undefined

/**
 * The fixture's kernel.yaml pointed at the live pmmcp, declaring the shipped
 * bearer name when AOS_PMMCP_TOKEN is set, so the kernel sends it as the
 * shipped config makes it. Unset, nothing is declared and nothing is sent:
 * pmmcp's gate runs in warn mode and serves a request without one.
 */
const livePmmcp = (url: string) => (base: string): string =>
  base.replace(
    /url: http:\/\/127\.0\.0\.1:\d+\/mcp/,
    `url: ${url}${(process.env['AOS_PMMCP_TOKEN'] ?? '').trim() === '' ? '' : '\n      tokenEnv: AOS_PMMCP_TOKEN'}`,
  )

/**
 * Every micro-dollar the log records, probe included. That is the bill: the
 * restart check crashes before its child's request leaves the process.
 */
const loggedCost = (dbPath: string): number =>
  rows(dbPath)
    .filter((r) => r.type === 'llm.response')
    .reduce((n, r) => n + Number((JSON.parse(r.payload) as { costMicroUsd?: unknown }).costMicroUsd ?? 0), 0)

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
        ? 'set PMMCP_URL (AOS_PMMCP_TOKEN only once pmmcp enforces its bearer)'
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
        streamableHttpTransport(process.env['PMMCP_URL'] ?? '', process.env['AOS_PMMCP_TOKEN']),
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
      : !hasPmmcp() || KEY === undefined
        ? 'set PMMCP_URL (AOS_PMMCP_TOKEN only once pmmcp enforces its bearer), and put ANTHROPIC_API_KEY in the shell or .env'
        : !WRITES
          ? 'set AOS_LIVE_PMMCP_WRITES=1 as well: this writes goals into pmmcp under aos/agent/aos-live-test, and they are not deleted afterwards'
          : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)
    const ref = realRef()
    const pmmcpUrl = process.env['PMMCP_URL'] ?? ''

    // The key from the environment, as in the Phase 0 exit criterion: pmmcp's
    // get_secret masks by design, so pmmcp is the goal store here, not the vault.
    const { kernel, fx } = await withKernel(t, {
      env: {
        AOS_PMMCP_TOKEN: process.env['AOS_PMMCP_TOKEN'],
        ANTHROPIC_API_KEY: KEY,
      },
      sandboxDriver: fakeSandbox(),
      kernelYaml: livePmmcp(pmmcpUrl),
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
      : KEY === undefined
        ? 'ANTHROPIC_API_KEY is in neither the shell nor .env'
        : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)
    const ref = realRef()

    // No pmmcp: this needs only a model, and the environment (secrets.source:
    // env, as shipped) is where the key comes from. Not an exit-criterion test.
    const { kernel, fx } = await withKernel(t, {
      env: { ANTHROPIC_API_KEY: KEY },
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

// ── 4. Phase 1 exit: one objective → tree + two children + a trustworthy summary ─

test(
  'live model + pmmcp, Phase 1 exit: one objective becomes a tree in the test namespace, two child runs, and a summary the log backs',
  {
    // Reasons inline, where the hygiene rule reads them: each names what to set.
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !hasPmmcp() || KEY === undefined
        ? 'set PMMCP_URL (AOS_PMMCP_TOKEN only once pmmcp enforces its bearer), and put ANTHROPIC_API_KEY in the shell or .env'
        : !WRITES
          ? 'set AOS_LIVE_PMMCP_WRITES=1 as well: this writes goals into pmmcp under aos/agent/aos-live-test, and they are not deleted afterwards'
          : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)
    const ref = realRef()
    const pmmcpUrl = process.env['PMMCP_URL'] ?? ''

    // The shipped CEO, delegating, but remembering in the test namespace.
    const { kernel, fx } = await withKernel(t, {
      env: {
        AOS_PMMCP_TOKEN: process.env['AOS_PMMCP_TOKEN'],
        ANTHROPIC_API_KEY: KEY,
      },
      sandboxDriver: fakeSandbox(),
      kernelYaml: livePmmcp(pmmcpUrl),
      agentsDir: liveFleet(tmpdir(t), ref, { delegation: true }),
    })
    assert.equal(kernel.status().subsystems.hub.state, 'ok', kernel.status().subsystems.hub.reason ?? '')
    await probe(kernel, ref)

    const result = await objectiveFanOut(
      { port: kernel.port, token: TEST_TOKEN, dbPath: fx.dbPath, timeoutMs: 600_000 },
      { agentId: LIVE_ORCHESTRATOR, projectId: LIVE_TEST_PROJECT },
    )
    // Recorded in the TAP output, for the README checklist: this run's calls,
    // its children's, and the probe's.
    t.diagnostic(`runId=${result.runId} costMicroUsd=${String(loggedCost(fx.dbPath))} score=${String(result.score)} notApplicable=${result.notApplicable.join(',') || 'none'}`)
  },
)

// ── 5. Phase 1 exit: a restart mid-run orphans nothing ─────────────────────

test(
  "live model + pmmcp, Phase 1 exit: a kernel that dies with a child in its first model call orphans nothing, and the real pmmcp blocks that child's goal",
  {
    // Reasons inline, where the hygiene rule reads them: each names what to set.
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !hasPmmcp() || KEY === undefined
        ? 'set PMMCP_URL (AOS_PMMCP_TOKEN only once pmmcp enforces its bearer), and put ANTHROPIC_API_KEY in the shell or .env'
        : !WRITES
          ? 'set AOS_LIVE_PMMCP_WRITES=1 as well: this writes goals into pmmcp under aos/agent/aos-live-test, and they are not deleted afterwards'
          : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)
    const ref = realRef()
    const pmmcpUrl = process.env['PMMCP_URL'] ?? ''
    const fx = fixture(t, {
      kernelYaml: livePmmcp(pmmcpUrl),
    })
    const agentsDir = liveFleet(tmpdir(t), ref, { delegation: true })
    const env = { AOS_PMMCP_TOKEN: process.env['AOS_PMMCP_TOKEN'], ANTHROPIC_API_KEY: KEY }

    // A dead process reads no reply. After the crash the old kernel gets headers
    // and a body that never ends, as the offline script's hang does: a promise
    // that never settles would leave the SDK's 10-minute request timer armed and
    // hold this file open after its last test. The crash lands before the
    // child's request is sent; a response that still lands late is cancelled.
    let crashed = false
    const hung = (): Response =>
      new Response(new ReadableStream<Uint8Array>({ start: () => undefined }), { status: 200, headers: { 'content-type': 'application/json' } })
    const fetch: typeof globalThis.fetch = async (input, init) => {
      if (crashed) return hung()
      const response = await globalThis.fetch(input, init)
      if (!crashed) return response
      await response.body?.cancel()
      return hung()
    }

    const result = await restartMidFanOut({
      dbPath: fx.dbPath,
      agentId: LIVE_ORCHESTRATOR,
      waitMs: 600_000,
      boot: async () => {
        const booted = await bootCrashable(t, fx, { env, sandboxDriver: fakeSandbox(), fetch, agentsDir })
        assert.equal(booted.kernel.status().subsystems.hub.state, 'ok', booted.kernel.status().subsystems.hub.reason ?? '')
        await probe(booted.kernel, ref)
        return {
          kernel: booted.kernel,
          crash: async () => {
            crashed = true
            await booted.crash()
            // Its pmmcp session dies with it.
            await booted.kernel.hub.close()
          },
        }
      },
      // The probe record is on disk; a restarted kernel must not call a model.
      reboot: () => bootOn(t, fx, { env, sandboxDriver: fakeSandbox(), agentsDir }),
    })
    // The child's first call is logged as a request and never sent, so this is the bill.
    t.diagnostic(`ceoRunId=${result.ceoRunId} inFlight=${result.inFlight} costMicroUsd=${String(loggedCost(fx.dbPath))}`)
  },
)
