// T34 — the two gated live tests.
//
// This is the ONLY file in the suite allowed to skip, and only because D29 says
// so: a live test that ran by default would spend the operator's money on every
// `npm test` and fail on every machine without a key. The gate is
// AOS_LIVE_TESTS=1 and nothing else, and every skip states its own reason —
// "skipped" with no reason is indistinguishable from "passed" in a scroll-back.
//
// Both tests boot a REAL kernel on a temp data dir and drive it over the real
// control socket, because that is the path `aos run` takes. Both PROBE FIRST:
// the router refuses an unprobed ref (D28), so without that step a run would
// finish `router-degraded` with zero cost and the test would be measuring
// nothing.
//
// Only the second is the Phase 0 exit criterion. The first proves the provider
// path using D8's env fallback, and a credential from the environment can never
// stand in for a credential from the vault — that substitution is the whole
// thing invariant 2 exists to prevent.

import { allowHost } from './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { EventStore } from '../src/events/store.js'
import { connectControl } from '../src/cli/client.js'
import { REPO_ROOT, TEST_TOKEN, withKernel, type BootedKernel } from './helpers/kernel.js'
import { fakeSandbox } from './helpers/fake-sandbox.js'
import { parseProviders } from '../src/models/registry.js'
import { parse as parseYaml } from 'yaml'
import { AnthropicAdapter } from '../src/models/anthropic.js'
import { Router } from '../src/models/router.js'
import { freshProbe } from './helpers/probe.js'
import { rejectedCallReplays } from './helpers/replay-body.js'
import { withStore } from './helpers/store.js'

/**
 * The ref actually shipped in providers.yaml, read rather than hard-coded.
 *
 * The plan names `anthropic/claude-opus-5`; D13 answered sonnet-5 and that is
 * what config/providers.yaml carries. Reading the file means this test cannot
 * drift from the shipped config, whichever way that decision moves next.
 */
function realRef(): string {
  const file = parseProviders(parseYaml(readFileSync(`${REPO_ROOT}/config/providers.yaml`, 'utf8')))
  const real = Object.entries(file.entries).filter(([, e]) => !e.placeholder)
  assert.equal(real.length, 1, 'providers.yaml must carry exactly one non-placeholder entry')
  return real[0]![0]
}

const LIVE = process.env['AOS_LIVE_TESTS'] === '1'
const ANTHROPIC_HOST = 'api.anthropic.com'

interface Row {
  readonly seq: number
  readonly type: string
  readonly payload: string
}

function rows(dbPath: string): Row[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return store.query().map((r) => ({ seq: r.seq, type: r.type, payload: r.payload }))
  } finally {
    store.close()
  }
}

function payloadOf(all: readonly Row[], type: string): Record<string, unknown> {
  const row = all.find((r) => r.type === type)
  assert.ok(row, `no ${type} row in the log`)
  return JSON.parse(row.payload) as Record<string, unknown>
}

/** Positions in the log, so "in this order" can be asserted rather than assumed. */
function seqOf(all: readonly Row[], type: string): number {
  const row = all.find((r) => r.type === type)
  assert.ok(row, `no ${type} row in the log`)
  return row.seq
}

/** Probe over the control socket, then run, then return the finish payload. */
async function probeThenRun(
  booted: BootedKernel,
  ref: string,
  prompt: string,
): Promise<Record<string, unknown>> {
  const client = await connectControl({
    port: booted.kernel.port,
    token: TEST_TOKEN,
    // A live model call can take a while; the default 5 s would time out the
    // socket before the provider answered and blame the wrong thing.
    timeoutMs: 180_000,
  })
  try {
    // D28: the router refuses a ref with no fresh probe reporting toolCalling.
    // Failing HERE with the probe's own reason is the point — a run that
    // finishes `router-degraded` would otherwise look like a provider problem.
    const probe = (await client.call('model.probe', { ref })) as {
      toolCalling: boolean
      reason?: string
      modelIdSeen?: string
    }
    assert.equal(
      probe.toolCalling,
      true,
      `${ref} did not report tool calling: ${probe.reason ?? 'no reason given'}`,
    )

    const early = new Map<string, Record<string, unknown>>()
    let mine: string | undefined
    let settle: (payload: Record<string, unknown>) => void = () => undefined
    const finished = new Promise<Record<string, unknown>>((resolve) => {
      settle = resolve
    })
    client.onEvent((event) => {
      if (event.type !== 'run.finished') return
      const payload = event.payload as Record<string, unknown> | null
      if (payload === null || typeof payload['runId'] !== 'string') return
      if (payload['runId'] === mine) settle(payload)
      else early.set(payload['runId'], payload)
    })

    const started = (await client.call('run.start', { agentId: 'ceo', input: prompt })) as {
      runId: string
    }
    mine = started.runId
    const done = early.get(started.runId)
    if (done !== undefined) settle(done)

    const timeout = new Promise<Record<string, unknown>>((_, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`run ${started.runId} did not finish within 180s`)),
        180_000,
      )
      timer.unref?.()
    })
    return await Promise.race([finished, timeout])
  } finally {
    client.close()
  }
}

// ── 1. the provider path only ──────────────────────────────────────────────

test(
  'LLM half of the exit criterion: run ceo "reply with the word pong" finishes with non-zero cost against the real Claude entry and the chain verifies',
  { skip: !LIVE ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)' : process.env['ANTHROPIC_API_KEY'] === undefined ? 'ANTHROPIC_API_KEY is not set' : false },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)

    const ref = realRef()
    // No pmmcp: the key comes from the environment (secrets.source: env, as
    // shipped). That is why this test is not the exit criterion — it proves the
    // provider, not the pmmcp connection.
    const booted = await withKernel(t, {
      env: { ANTHROPIC_API_KEY: process.env['ANTHROPIC_API_KEY'] },
      sandboxDriver: fakeSandbox(),
    })

    const finish = await probeThenRun(booted, ref, 'reply with the word pong')
    assert.equal(finish['status'], 'ok', String(finish['reason'] ?? ''))
    // The whole claim: a run that finishes having spent nothing never reached
    // the provider.
    assert.ok((finish['costMicroUsd'] as number) > 0, 'the run finished with zero cost')
    assert.ok((finish['llmCalls'] as number) > 0)

    await booted.kernel.shutdown()
    const all = rows(booted.fx.dbPath)

    // From the environment, and said so. If this ever reads 'vault' the test has
    // stopped testing what it claims to.
    assert.equal(payloadOf(all, 'secret.accessed')['source'], 'env')
    assert.equal(payloadOf(all, 'probe.recorded')['toolCalling'], true)

    // Invariant 4: two events per model call, cost on the response.
    const requests = all.filter((r) => r.type === 'llm.request')
    const responses = all.filter((r) => r.type === 'llm.response')
    assert.equal(requests.length, responses.length)
    assert.ok(responses.length > 0)
    assert.ok(
      responses.some((r) => ((JSON.parse(r.payload) as { costMicroUsd: number }).costMicroUsd ?? 0) > 0),
    )

    // Invariant 5, on a log a real provider wrote to.
    const store = new EventStore(booted.fx.dbPath, { readOnly: true })
    try {
      assert.equal(store.verifyChain(store.readAnchor()).ok, true)
    } finally {
      store.close()
    }

    // And the key is nowhere in it, though it went out on the wire.
    const key = process.env['ANTHROPIC_API_KEY'] ?? ''
    assert.ok(key.length > 0)
    assert.equal(JSON.stringify(all).includes(key), false, 'the credential reached the event log')
  },
)

// ── 2. the Phase 0 exit criterion ──────────────────────────────────────────

test(
  'Phase 0 exit criterion: with pmmcp connected, probe then run ceo finishes with non-zero cost, the key from the environment',
  {
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : process.env['PMMCP_URL'] === undefined || process.env['ANTHROPIC_API_KEY'] === undefined
        ? 'set PMMCP_URL (PMMCP_TOKEN only if the server wants a bearer) and ANTHROPIC_API_KEY (read -rs, never from a file)'
        : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)

    const ref = realRef()
    const pmmcpUrl = process.env['PMMCP_URL'] ?? ''
    const key = process.env['ANTHROPIC_API_KEY'] ?? ''

    // pmmcp's get_secret returns only a masked sentence, by design, so the key
    // comes from the environment (secrets.source: env, as shipped) and pmmcp is
    // the memory and goal store. The criterion is both at once: pmmcp really
    // connected, and a real run that really spent money.
    const booted = await withKernel(t, {
      env: { PMMCP_TOKEN: process.env['PMMCP_TOKEN'], ANTHROPIC_API_KEY: key },
      sandboxDriver: fakeSandbox(),
      // No clientFactory: the hub opens a real Streamable HTTP session to the
      // operator's pmmcp. The guard already admits loopback.
      kernelYaml: (base) => base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `url: ${pmmcpUrl}`),
    })

    const status = booted.kernel.status()
    assert.equal(status.subsystems.hub.state, 'ok', status.subsystems.hub.reason ?? '')
    assert.equal(status.subsystems.secrets.state, 'ok', status.subsystems.secrets.reason ?? '')
    assert.equal(booted.fx.config.secrets.source, 'env')

    const finish = await probeThenRun(booted, ref, 'reply with the word pong')
    assert.equal(finish['status'], 'ok', String(finish['reason'] ?? ''))
    assert.ok((finish['costMicroUsd'] as number) > 0, 'the run finished with zero cost')

    await booted.kernel.shutdown()
    const all = rows(booted.fx.dbPath)

    // In this order: pmmcp connected and its tools were classified, the key was
    // resolved, the model was probed, and only then did a run spend money.
    const connected = seqOf(all, 'hub.connected')
    const classified = seqOf(all, 'hub.tools.classified')
    const accessed = seqOf(all, 'secret.accessed')
    const probed = seqOf(all, 'probe.recorded')
    const finished = seqOf(all, 'run.finished')
    assert.ok(
      connected < classified && classified < accessed && accessed < probed && probed < finished,
      `log order was ${[connected, classified, accessed, probed, finished].join(' < ')}`,
    )
    assert.equal(payloadOf(all, 'secret.accessed')['source'], 'env')

    // Nothing unclassified was exposed: unclassified pmmcp tools stay
    // kernel-only by the literal default (invariant 7).
    const tools = payloadOf(all, 'hub.tools.classified')
    assert.equal(tools['exposed'], 0, 'a pmmcp tool is exposed to agents')
    assert.ok((tools['kernelOnly'] as number) > 0)

    assert.equal(payloadOf(all, 'probe.recorded')['toolCalling'], true)

    const store = new EventStore(booted.fx.dbPath, { readOnly: true })
    try {
      assert.equal(store.verifyChain(store.readAnchor()).ok, true)
    } finally {
      store.close()
    }

    // The key went out on the wire and is nowhere in the log.
    assert.equal(JSON.stringify(all).includes(key), false, 'the API key reached the log')
  },
)

// ── 3. a rejected tool call, replayed to the real API ─────────────────────

test(
  'a rejected tool call replayed to the real Messages API is accepted, with a tools field that omits it and with no tools field at all',
  { skip: !LIVE ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)' : process.env['ANTHROPIC_API_KEY'] === undefined ? 'ANTHROPIC_API_KEY is not set' : false },
  async (t) => {
    // Settles the one rule the docs leave open (test/helpers/replay-body.ts):
    // whether history may carry a tool_use for a tool the request does not
    // offer. The kernel does this on every rejected call, and for a worker
    // offered nothing it sends no tools field at all. A 400 is a kernel bug.
    //
    // Straight through the router, not a whole kernel: nothing else is under
    // test, and two small calls are the whole cost. The probe record is a
    // fixture — D28 gates BINDING a model, which test 1 exercises for real; it
    // is not what this request shape depends on.
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)

    const ref = realRef()
    const card = parseProviders(parseYaml(readFileSync(`${REPO_ROOT}/config/providers.yaml`, 'utf8'))).entries[ref]
    assert.ok(card, `${ref} is not in providers.yaml`)
    const key = process.env['ANTHROPIC_API_KEY'] ?? ''
    const store = withStore(t)
    const router = new Router({
      store,
      cards: new Map([[ref, card]]),
      probes: freshProbe,
      resolveCredential: () => Promise.resolve(key),
      maxRetries: 1,
      adapters: { anthropic: new AnthropicAdapter() },
    })

    await rejectedCallReplays({ router, store, ref })

    // The key went out on the wire and must be nowhere in what was logged.
    assert.equal(JSON.stringify(store.query()).includes(key), false, 'the credential reached the event log')
  },
)
