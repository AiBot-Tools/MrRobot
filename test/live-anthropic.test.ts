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
    // envFallback ON and no pmmcp: the shipped entry's vault path fails and the
    // broker falls back to this entry's own auth.envVar (D8). That is why this
    // test cannot be the exit criterion — it proves the provider, not the vault.
    const booted = await withKernel(t, {
      envFallback: true,
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
  'Phase 0 exit criterion: with pmmcp connected and envFallback off, probe then run ceo finishes with non-zero cost paid from the vault',
  {
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : process.env['PMMCP_URL'] === undefined || process.env['PMMCP_TOKEN'] === undefined
        ? 'PMMCP_URL and PMMCP_TOKEN must both be set, and the Anthropic key must already be in the pmmcp vault under the vaultId providers.yaml names'
        : false,
  },
  async (t) => {
    const revoke = allowHost(ANTHROPIC_HOST)
    t.after(revoke)

    const ref = realRef()
    const pmmcpUrl = process.env['PMMCP_URL'] ?? ''

    // The vault is the ONLY working credential path here, and it is made the
    // only one twice over: envFallback is off, AND the environment variable the
    // entry would fall back to is poisoned. A test that merely turned the
    // fallback off could still pass on a kernel that ignored the setting.
    const booted = await withKernel(t, {
      envFallback: false,
      env: {
        PMMCP_TOKEN: process.env['PMMCP_TOKEN'],
        ANTHROPIC_API_KEY: 'poisoned-not-a-real-key-this-must-never-be-used',
      },
      sandboxDriver: fakeSandbox(),
      // No clientFactory: the hub opens a real Streamable HTTP session to the
      // operator's pmmcp. The guard already admits loopback.
      kernelYaml: (base) => base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `url: ${pmmcpUrl}`),
    })

    // Before running: the vault is genuinely up, and the kernel is not degraded
    // in the two places that matter.
    const status = booted.kernel.status()
    assert.equal(status.subsystems.hub.state, 'ok', status.subsystems.hub.reason ?? '')
    assert.equal(status.subsystems.secrets.state, 'ok', status.subsystems.secrets.reason ?? '')
    assert.equal(status.envFallback, false)

    const finish = await probeThenRun(booted, ref, 'reply with the word pong')
    assert.equal(finish['status'], 'ok', String(finish['reason'] ?? ''))
    assert.ok((finish['costMicroUsd'] as number) > 0, 'the run finished with zero cost')

    await booted.kernel.shutdown()
    const all = rows(booted.fx.dbPath)

    // In this order. The order is the argument: the vault connected, its tools
    // were classified, the key came OUT of the vault, the model was probed, and
    // only then did a run spend money.
    const connected = seqOf(all, 'hub.connected')
    const classified = seqOf(all, 'hub.tools.classified')
    const accessed = seqOf(all, 'secret.accessed')
    const probed = seqOf(all, 'probe.recorded')
    const finished = seqOf(all, 'run.finished')
    assert.ok(
      connected < classified && classified < accessed && accessed < probed && probed < finished,
      `log order was ${[connected, classified, accessed, probed, finished].join(' < ')}`,
    )

    // THE assertion. 'env' here would mean the fallback ran despite being off,
    // and the criterion would be unmet however green the rest looked.
    assert.equal(payloadOf(all, 'secret.accessed')['source'], 'vault')

    // The broker confirmed kernel.yaml's secrets.keyArg against the LIVE
    // get_secret schema. Reaching a vault-sourced credential at all is that
    // confirmation: the broker throws SecretsSchemaMismatch otherwise, so this
    // is the moment keyArg stops being "unverified".
    assert.equal(booted.fx.config.secrets.keyArg, 'label')

    // Nothing unclassified was exposed: the shipped file names nine tools and
    // the rest stay kernel-only by the literal default (invariant 7).
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

    // The poisoned value must appear nowhere: not used, not logged.
    assert.equal(
      JSON.stringify(all).includes('poisoned-not-a-real-key'),
      false,
      'the poisoned env value reached the log',
    )
  },
)
