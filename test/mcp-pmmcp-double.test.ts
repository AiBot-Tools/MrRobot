// The kernel against a pmmcp double.
//
// Until now every kernel-level test booted with pmmcp ABSENT, which is the
// normal state on a Linux box and the wrong thing to only ever test: the
// interesting invariants are the ones that need a vault and a server with 49
// tools on it. This file boots the kernel with pmmcp CONNECTED and offline.
//
// What that reaches which nothing else did:
//
//   invariant 7 at real cardinality — 49 tools, nineteen classified, nothing
//   exposed to agents, forty defaulting closed;
//   the vault as the credential path, rather than the D8 env fallback;
//   `broker.start()`'s schema confirmation, which fails closed on the
//   operator's Mac if `secrets.keyArg` is wrong — and which boot never called;
//   an idle-expired session, through the -32001 path a real pmmcp uses rather
//   than the 404 a test server can be made to emit.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test, { type TestContext } from 'node:test'
import { parse as parseYaml } from 'yaml'

import { SecretsSchemaMismatch } from '../src/errors.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews, type ToolViewsFile } from '../src/mcp/tool-views.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { SecretsBroker } from '../src/secrets/broker.js'
import type { EventStore } from '../src/events/store.js'
import { anthropicEndTurn, fakeProvider } from './helpers/fake-provider.js'
import { REPO_ROOT, rows, runThroughControl, withKernel } from './helpers/kernel.js'
import { PMMCP_TOOLS, PMMCP_TOOL_COUNT, pmmcpMock, type PmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'
import { withStore } from './helpers/store.js'

const REAL_REF = 'anthropic/claude-sonnet-5'
const VAULT_ID = 'anthropic-api-key'
const VAULT_VALUE = 'vault-fixture-credential-4be21a'

/**
 * A vault answering for the one credential the shipped providers.yaml names.
 *
 * `revealSecrets` by default, because every caller here tests the DORMANT
 * `secrets.source: vault` path, which only a plaintext-returning pmmcp could
 * serve. The real pmmcp masks; the tests that say so pass `revealSecrets: false`.
 */
function vaultMock(t: TestContext, options: Parameters<typeof pmmcpMock>[0] = {}): PmmcpMock {
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: VAULT_VALUE }, revealSecrets: true, ...options })
  t.after(async () => {
    await mock.close()
  })
  return mock
}

/** The SHIPPED policy file. A test that invented its own would prove nothing. */
function toolViews(): ToolViewsFile {
  return parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8')))
}

/** A verified store and a hub on it, both closed when the test ends. */
function hubOn(t: TestContext): { store: EventStore; hub: McpHub } {
  const store = withStore(t)
  const hub = new McpHub({ store, views: toolViews() })
  t.after(async () => {
    await hub.close()
  })
  return { store, hub }
}

/** Parsed payloads of one event type, in order. */
function payloads(store: EventStore, type: string): Record<string, unknown>[] {
  return store
    .query()
    .filter((r) => r.type === type)
    .map((r) => JSON.parse(r.payload) as Record<string, unknown>)
}

test('a 49-tool server classifies closed: nothing exposed, nineteen pinned, thirty defaulted', async (t) => {
  // Invariant 7 at the cardinality the operator's machine actually has. The
  // shipped policy file classifies nineteen of 49, and the claim is that the
  // other thirty are unreachable by an agent because the DEFAULT is closed —
  // not because somebody remembered to write them down.
  const mock = vaultMock(t, { padTo: PMMCP_TOOL_COUNT })
  const { store, hub } = hubOn(t)
  assert.equal(await hub.connect('pmmcp', mock.connect), 'connected')

  const classified = payloads(store, 'hub.tools.classified')
  assert.equal(classified.length, 1)
  const counts = classified[0] as {
    exposed: number
    kernelOnly: number
    disabled: number
    unclassified: string[]
  }

  assert.equal(counts.exposed, 0, 'no pmmcp tool is exposed to agents')
  assert.equal(counts.disabled, 2, 'the two nested-LLM tools, and only those')
  assert.equal(counts.unclassified.length, PMMCP_TOOL_COUNT - 19, 'thirty of 49 are unclassified')
  assert.equal(
    counts.kernelOnly,
    PMMCP_TOOL_COUNT - 2,
    'every tool that is not one of the two disabled ones is kernel-only',
  )
  assert.equal(counts.exposed + counts.kernelOnly + counts.disabled, PMMCP_TOOL_COUNT)

  // The default is kernel-only specifically, not disabled: an unclassified tool
  // is still the kernel's to call. Proving that needs a call, because the counts
  // above cannot distinguish "closed" from "closed for the wrong reason".
  assert.equal(counts.unclassified.includes('create_goal'), true)
  const kernelCall = await hub.callKernelOnly(
    'pmmcp',
    'create_goal',
    { project_id: 'aos/ceo', kind: 'objective', title: 'reachable by the kernel' },
    'test: an unclassified tool defaults to kernel-only, not disabled',
  )
  assert.equal(kernelCall.ok, true)

  // And the agent view is empty — the same claim from the other side: there is
  // no list an agent could read a pmmcp tool off of.
  assert.deepEqual(hub.agentView().tools, [])
})

test('the broker reads a credential out of the vault and the value never lands in the log', async (t) => {
  const mock = vaultMock(t)
  const { store, hub } = hubOn(t)
  await hub.connect('pmmcp', mock.connect)

  const broker = new SecretsBroker({ store, source: 'vault', hub, keyArg: 'label', envFallback: false })
  // The schema confirmation the operator's boot depends on, against a server
  // that declares the confirmed argument.
  assert.equal(await broker.start(), 'ready')

  const ref = await broker.ref(VAULT_ID, 'test: provider credential')
  assert.equal(ref.source, 'vault', 'the vault answered, so no fallback was consulted')
  assert.equal(
    broker.use(ref, (v) => v),
    VAULT_VALUE,
  )

  // The vault was asked on the confirmed argument name, once.
  const asked = mock.calls.filter((c) => c.tool === 'get_secret')
  assert.equal(asked.length, 1)
  assert.deepEqual(asked[0]?.args, { label: VAULT_ID })

  // `secret.accessed` names what and why, never what came back — and there is no
  // `tool.result` for a kernel-only call that returns a credential.
  assert.deepEqual(payloads(store, 'secret.accessed'), [
    { schemaVersion: 1, id: VAULT_ID, purpose: 'test: provider credential', source: 'vault' },
  ])
  assert.equal(payloads(store, 'tool.result').length, 0)
  assert.equal(JSON.stringify(store.query()).includes(VAULT_VALUE), false, 'the credential reached the log')
})

test('a vault that disagrees about its own argument name fails the broker closed', async (t) => {
  // The stub table records: `keyArg` is unverified until a live pmmcp confirms
  // it. This is what "fails closed" has to mean — a server declaring `name`
  // while kernel.yaml says `label` is protocol drift, and the broker refuses
  // rather than sending a request the vault will answer with nothing.
  const mock = vaultMock(t, { secretArg: 'name' })
  const { store, hub } = hubOn(t)
  await hub.connect('pmmcp', mock.connect)

  const broker = new SecretsBroker({ store, source: 'vault', hub, keyArg: 'label', envFallback: false })
  await assert.rejects(() => broker.start(), SecretsSchemaMismatch)
  // Nothing was asked of the vault: the refusal comes off the declared schema,
  // before a malformed request exists.
  assert.equal(mock.calls.filter((c) => c.tool === 'get_secret').length, 0)
})

test('boot degrades secrets, loudly, when the live vault declares a different argument', async (t) => {
  // The defect this file was written to find: `broker.start()` is the only thing
  // that confirms `secrets.keyArg` against the live schema, and boot never
  // called it. With pmmcp connected and the wrong keyArg the kernel reported
  // `secrets: ok`, and every credential fetch failed later with a message about
  // the vault returning nothing — pointing at the vault rather than at the one
  // line of kernel.yaml that was wrong.
  const mock = vaultMock(t, { secretArg: 'name' })
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    secretsSource: 'vault',
  })

  const secrets = kernel.status().subsystems.secrets
  assert.equal(secrets.state, 'degraded', 'a vault that cannot be addressed is not a ready vault')
  assert.match(String(secrets.reason), /label/, 'the reason must name the argument that is wrong')
  assert.match(String(secrets.reason), /keyArg/, 'and where to fix it')
  // The hub is fine: the server is there and answering. Only the vault path is
  // unusable, and the two must not be conflated.
  assert.equal(kernel.status().subsystems.hub.state, 'ok')
  assert.equal(kernel.degraded.includes('secrets'), true)

  // Recorded, not just reported: an operator reading the log afterwards sees why
  // the vault was unusable during that boot.
  const captured = kernel.status().subsystems.secrets.reason
  await kernel.shutdown()
  const degradations = rows(fx.dbPath)
    .filter((r) => r.type === 'secrets.degraded')
    .map((r) => (JSON.parse(r.payload) as { reason: string }).reason)
  assert.equal(degradations.length >= 1, true, 'the degradation was reported but never recorded')
  assert.equal(
    degradations.some((r) => r.includes('label')),
    true,
    `no logged reason names the argument; reported: ${String(captured)}`,
  )
})

test('the Phase 0 exit shape: pmmcp connected, the credential from the environment, the vault never asked', async (t) => {
  // As close as a Linux box gets to the exit criterion: pmmcp connected and
  // answering exactly as the real one does (a MASKED get_secret), the key from
  // the environment, the gate, the log and the cost arithmetic all real, and
  // only the provider doubled.
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: VAULT_VALUE } })
  t.after(async () => {
    await mock.close()
  })
  const envValue = 'env-fixture-credential-exit-shape'
  const provider = fakeProvider([anthropicEndTurn({ text: 'pong', inputTokens: 1_000, outputTokens: 100 })])
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: envValue },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  const status = kernel.status()
  assert.equal(status.subsystems.hub.state, 'ok', status.subsystems.hub.reason ?? '')
  assert.equal(status.subsystems.secrets.state, 'ok', status.subsystems.secrets.reason ?? '')
  assert.equal(status.subsystems.router.state, 'ok', status.subsystems.router.reason ?? '')

  const finished = await runThroughControl(kernel, 'reply with the word pong')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  assert.ok((finished['costMicroUsd'] as number) > 0, 'a run that spent nothing never reached a provider')

  assert.deepEqual(mock.calls.filter((c) => c.tool === 'get_secret'), [], 'the env source asked the vault')
  assert.equal(provider.requests[0]?.headers['x-api-key'], envValue)
  await kernel.shutdown()
  const accessed = rows(fx.dbPath)
    .filter((r) => r.type === 'secret.accessed')
    .map((r) => (JSON.parse(r.payload) as { source: string }).source)
  assert.deepEqual(accessed, ['env'])
  assert.equal(JSON.stringify(rows(fx.dbPath)).includes(envValue), false, 'the credential reached the log')
})

test('source: vault against the REAL pmmcp reply refuses the masked sentence, so the ref is unroutable and says why', async (t) => {
  const mock = pmmcpMock({ secrets: { [VAULT_ID]: VAULT_VALUE } })
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider([anthropicEndTurn({ text: 'pong', inputTokens: 1, outputTokens: 1 })])
  const { kernel } = await withKernel(t, {
    clientFactory: mock.connect,
    secretsSource: 'vault',
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  const router = kernel.status().subsystems.router
  assert.equal(router.state, 'degraded')
  assert.match(router.reason ?? '', /a message, not a credential/)
  // The masked tail of the key never surfaced in the reason.
  assert.equal((router.reason ?? '').includes(VAULT_VALUE.slice(-4)), false)
  assert.equal(provider.requests.length, 0, 'a masked sentence went out as the API key')
})

test('the dormant vault path: a pmmcp that returned plaintext would pay for a run from the VAULT', async (t) => {
  // Kept for the day pmmcp authenticates its callers and hands a value to one
  // of them. `revealSecrets` is that hypothetical server; the real one masks.
  const mock = vaultMock(t)
  const provider = fakeProvider([
    anthropicEndTurn({ text: 'pong', inputTokens: 1_000, outputTokens: 100 }),
  ])

  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    secretsSource: 'vault',
    fetch: provider.fetch,
    // routable() consults the persisted probe record, so it has to be on disk
    // before boot decides whether anything can be served.
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })

  const status = kernel.status()
  assert.equal(status.subsystems.secrets.state, 'ok', status.subsystems.secrets.reason ?? '')
  assert.equal(status.subsystems.router.state, 'ok', status.subsystems.router.reason ?? '')

  const finished = await runThroughControl(kernel, 'reply with the word pong')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  assert.ok((finished['costMicroUsd'] as number) > 0, 'a run that spent nothing never reached a provider')

  // The credential came out of the vault, once, at boot.
  const asked = mock.calls.filter((c) => c.tool === 'get_secret')
  assert.deepEqual(asked.map((c) => c.args), [{ label: VAULT_ID }])
  await kernel.shutdown()
  const accessed = rows(fx.dbPath)
    .filter((r) => r.type === 'secret.accessed')
    .map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.deepEqual(accessed, [
    {
      schemaVersion: 1,
      id: VAULT_ID,
      purpose: `provider credential for ${REAL_REF}`,
      source: 'vault',
    },
  ])

  // It went out on the wire and is nowhere in the log.
  assert.equal(provider.requests.length, 1)
  assert.equal(provider.requests[0]?.headers['x-api-key'], VAULT_VALUE)
  assert.equal(JSON.stringify(rows(fx.dbPath)).includes(VAULT_VALUE), false)

  // envFallback stayed off, so ANTHROPIC_API_KEY was never consulted: the vault
  // is the credential path here, not a preference.
  assert.equal(kernel.config.secrets.envFallback, false)
})

test('an idle-expired session is noticed by the heartbeat and replaced, and the goals survive', async (t) => {
  // A real pmmcp session expires and then answers -32001, not 404. The hub's
  // reconnect was only ever tested through the 404 branch; this is the other
  // one, and it is the one the operator's machine will produce.
  const mock = vaultMock(t)
  const { hub } = hubOn(t)
  await hub.connect('pmmcp', mock.connect)
  const tree = mock.seedTree('aos/ceo')

  mock.expireSession()
  assert.equal(await hub.heartbeat('pmmcp'), 'reconnected')
  assert.equal(mock.sessions.length, 2, 'a fresh session, not a retry on the dead one')
  assert.equal(hub.status('pmmcp'), 'connected')

  // The new session reaches the same state: a reconnect must not look like a
  // wiped memory to the CEO's next continuation.
  const read = await hub.callKernelOnly(
    'pmmcp',
    'get_goal_tree',
    { goal_id: tree.objective },
    'test: the goal survived the reconnect',
  )
  assert.equal(read.ok, true)
  // pmmcp's tree carries titles, not ids.
  assert.match(JSON.stringify(read.content), /seeded objective/)
  assert.doesNotMatch(JSON.stringify(read.content), /not found/)
})

test('the hub describes every declared tool with the schema the double declares', async (t) => {
  // hub.describe() is what the broker's schema confirmation reads. If the double
  // stopped declaring an inputSchema, that confirmation would pass over nothing
  // and the fail-closed test above would go green for the wrong reason.
  const mock = vaultMock(t)
  const { hub } = hubOn(t)
  await hub.connect('pmmcp', mock.connect)
  for (const spec of PMMCP_TOOLS) {
    const described = hub.describe('pmmcp', spec.name)
    assert.notEqual(described, undefined, `${spec.name} is not described`)
    assert.deepEqual(
      Object.keys((described?.inputSchema['properties'] ?? {}) as Record<string, unknown>),
      Object.keys(spec.inputSchema.properties),
      `${spec.name} describes different properties than it declares`,
    )
  }
})
