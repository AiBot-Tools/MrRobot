// T24 — the secrets broker.
//
// Everything here is one question asked several ways: can a credential reach
// somewhere it was never meant to go? The places it could go are the event
// log, an agent's run, and — through D8 — the process environment.
//
// The falsifiers:
//
//   Put the value on the ref and every log line, error message and debugger
//   view that touches a ref carries a live credential.
//   Register the mask AFTER appending secret.accessed and the very first
//   event about a secret is the one that leaks it; worse, a vault entry can
//   be an opaque string, so no regex would catch what the mask missed.
//   Let ref() run inside a run scope and the vault becomes reachable by
//   anything an agent can steer kernel code into calling.
//   Read process.env before the vault, or with envFallback off, and D8's
//   "default off, vault is primary" becomes a lie that is true only when the
//   variable happens to be unset.
//   Accept a live schema that lacks the argument and a renamed pmmcp
//   parameter looks like a missing secret instead of a protocol drift.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { parse as parseYaml } from 'yaml'

import { withStore } from './helpers/store.js'
import { mockMcp, type MockMcp } from './helpers/mock-mcp.js'
import { McpHub } from '../src/mcp/hub.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { SecretMask, redactString, CENSOR } from '../src/events/redact.js'
import { withRunScope } from '../src/runtime/scope.js'
import { PolicyDenied, SecretsSchemaMismatch } from '../src/errors.js'
import { assertSecretSchema, SecretRef, SecretsBroker } from '../src/secrets/broker.js'

const VIEWS = parseToolViews(
  parseYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall: { exposure: agent, risk: read }
      get_secret: { exposure: kernel-only }
`),
)

const RUN = { runId: 'run_1', agentId: 'ceo', taint: 'clean', tier: 1, lane: 'main' } as const

interface Wired {
  readonly broker: SecretsBroker
  readonly store: ReturnType<typeof withStore>
  readonly mock: MockMcp
  readonly hub: McpHub
}

async function wire(
  t: TestContext,
  options: { keyArg?: string; envFallback?: boolean; env?: NodeJS.ProcessEnv; secretArg?: string; noHub?: boolean } = {},
): Promise<Wired> {
  const store = withStore(t)
  const mock = await mockMcp(options.secretArg === undefined ? {} : { secretArg: options.secretArg })
  const hub = new McpHub({ store, views: VIEWS })
  t.after(async () => {
    await hub.close()
    await mock.close().catch(() => undefined)
  })
  await hub.connect('pmmcp', () => Promise.resolve(mock.client))

  const broker = new SecretsBroker({
    store,
    ...(options.noHub === true ? {} : { hub }),
    keyArg: options.keyArg ?? 'label',
    envFallback: options.envFallback ?? false,
    ...(options.env === undefined ? {} : { env: options.env }),
  })
  return { broker, store, mock, hub }
}

/** The mock's value for an id. Never a real secret; long enough to mask. */
const valueFor = (id: string): string => `fixture-secret-for-${id}`

function payloads(store: Wired['store'], type: string): Record<string, unknown>[] {
  return store.query({ type }).map((row) => JSON.parse(row.payload) as Record<string, unknown>)
}

// ── the handle carries nothing ─────────────────────────────────────────────

test('SecretRef carries no value; secret.accessed payload keys are exactly [id, purpose, source]', async (t) => {
  const { broker, store } = await wire(t)
  await broker.start()

  const ref = await broker.ref('anthropic-api-key', 'bind the anthropic provider credential')
  const value = valueFor('anthropic-api-key')

  assert.ok(ref instanceof SecretRef)
  assert.equal(ref.id, 'anthropic-api-key')
  assert.equal(ref.source, 'vault')

  // No property, no enumeration, no serialisation yields it. The value lives
  // in a WeakMap keyed by the handle, so there is nothing to reach.
  assert.equal(Object.values(ref).includes(value), false)
  assert.equal(JSON.stringify(ref).includes(value), false)
  assert.deepEqual(JSON.parse(JSON.stringify(ref)), { id: 'anthropic-api-key', source: 'vault' })
  assert.equal(String(ref).includes(value), false)
  assert.equal(Object.getOwnPropertyNames(ref).sort().join(','), 'id,source')

  const [accessed] = payloads(store, 'secret.accessed')
  assert.deepEqual(Object.keys(accessed ?? {}).sort(), ['id', 'purpose', 'schemaVersion', 'source'])
  assert.equal(accessed?.['source'], 'vault')
  assert.equal(accessed?.['purpose'], 'bind the anthropic provider credential')
})

test('JSON of the whole log contains neither the value nor its sha256', async (t) => {
  const { broker, store } = await wire(t)
  await broker.start()
  await broker.ref('anthropic-api-key', 'boot')

  const whole = JSON.stringify(store.query())
  assert.equal(whole.includes(valueFor('anthropic-api-key')), false)
  // Not even a digest: a hash of a low-entropy secret is a lookup away from
  // the secret, and the log is the one artefact that cannot be rewritten.
  const { createHash } = await import('node:crypto')
  const digest = createHash('sha256').update(valueFor('anthropic-api-key')).digest('hex')
  assert.equal(whole.includes(digest), false)
})

test('use hands the value to the callback only', async (t) => {
  const { broker } = await wire(t)
  await broker.start()
  const ref = await broker.ref('anthropic-api-key', 'boot')

  let seen: string | undefined
  const result = broker.use(ref, (v) => {
    seen = v
    return `header:${v.length}`
  })

  assert.equal(seen, valueFor('anthropic-api-key'))
  // What comes back is the callback's answer, not the credential.
  assert.equal(result, `header:${valueFor('anthropic-api-key').length}`)

  // A handle this broker did not mint has no value to hand over.
  const alien = Object.create(SecretRef.prototype) as SecretRef
  assert.throws(() => broker.use(alien, (v) => v), PolicyDenied)
})

test('fetched values are registered with the mask so later events are censored', async (t) => {
  SecretMask.clear()
  const { broker, store } = await wire(t)
  await broker.start()

  const value = valueFor('opaque-entry')
  // Nothing about this value looks like a credential, so only the mask can
  // censor it — which is the realistic case for a vault entry.
  assert.equal(redactString(value), value)

  await broker.ref('opaque-entry', 'boot')
  assert.equal(redactString(value), CENSOR)

  // And it stays censored in anything appended afterwards.
  store.append({
    type: 'llm.request',
    payload: { schemaVersion: 1, ref: 'anthropic/x', attempt: 1, prompt: `key is ${value}`, tools: [] },
  })
  assert.equal(payloads(store, 'llm.request')[0]?.['prompt'], `key is ${CENSOR}`)
})

// ── failing closed ─────────────────────────────────────────────────────────

test('keyArg absent from the live schema fails closed', async (t) => {
  // The server declares `key`; the kernel is configured for `label`. A
  // renamed pmmcp parameter must look like a protocol drift, not a missing
  // secret — sending the wrong name would return nothing and fall through.
  const { broker } = await wire(t, { secretArg: 'key', keyArg: 'label' })

  await assert.rejects(
    () => broker.start(),
    (e: unknown) =>
      e instanceof SecretsSchemaMismatch &&
      /has no "label"/.test(e.message) &&
      /it has key/.test(e.message),
  )

  // The pure check, on the shapes a server can actually return.
  assert.throws(() => assertSecretSchema(undefined, 'label', 'pmmcp.get_secret'), SecretsSchemaMismatch)
  assert.throws(() => assertSecretSchema({}, 'label', 'pmmcp.get_secret'), SecretsSchemaMismatch)
  assert.throws(
    () => assertSecretSchema({ properties: { key: {} } }, 'label', 'pmmcp.get_secret'),
    SecretsSchemaMismatch,
  )
  assertSecretSchema({ properties: { label: { type: 'string' } } }, 'label', 'pmmcp.get_secret')
})

test('broker is degraded without a hub and ref() throws with why', async (t) => {
  const { broker, store } = await wire(t, { noHub: true })

  assert.equal(await broker.start(), 'degraded')
  assert.match(String(broker.degradedReason), /vault is unreachable/)
  assert.match(String(payloads(store, 'secrets.degraded')[0]?.['reason']), /unreachable/)

  await assert.rejects(
    () => broker.ref('anthropic-api-key', 'boot'),
    (e: unknown) => e instanceof PolicyDenied && /envFallback is off/.test(e.message),
  )
})

// ── D8: the env fallback ───────────────────────────────────────────────────

test('envFallback:false ignores process.env even when the var is set', async (t) => {
  const env = { ANTHROPIC_API_KEY: 'env-value-that-must-not-be-used' }
  // No hub, so the vault path cannot succeed. The variable is right there.
  const { broker, store } = await wire(t, { noHub: true, envFallback: false, env })

  await broker.start()
  await assert.rejects(
    () => broker.ref('anthropic-api-key', 'boot', { envVar: 'ANTHROPIC_API_KEY' }),
    (e: unknown) => e instanceof PolicyDenied && /envFallback is off/.test(e.message),
  )

  // Nothing was resolved, so nothing was recorded and nothing was masked.
  assert.equal(store.query({ type: 'secret.accessed' }).length, 0)
  assert.equal(redactString(env.ANTHROPIC_API_KEY), env.ANTHROPIC_API_KEY)
})

test("envFallback:true reads the var, logs source:'env', and reports degraded", async (t) => {
  const env = { ANTHROPIC_API_KEY: 'env-value-0f3a91b7c2d5e8' }
  const { broker, store } = await wire(t, { noHub: true, envFallback: true, env })

  // Standing degradation: reading credentials from the environment is a
  // weaker posture than the vault, and the operator should see it while true.
  assert.equal(await broker.start(), 'degraded')
  assert.ok(
    payloads(store, 'secrets.degraded').some((p) => /envFallback is ON/.test(String(p['reason']))),
  )

  const ref = await broker.ref('anthropic-api-key', 'boot', { envVar: 'ANTHROPIC_API_KEY' })
  assert.equal(ref.source, 'env')
  assert.equal(payloads(store, 'secret.accessed')[0]?.['source'], 'env')
  assert.equal(broker.use(ref, (v) => v), env.ANTHROPIC_API_KEY)
})

test('env fallback uses auth.envVar only when the vault path failed AND envFallback is true', async (t) => {
  const env = { ANTHROPIC_API_KEY: 'env-value-must-not-win-4b2c' }

  // 1. Vault ok + fallback ON -> the vault wins and the variable is untouched.
  const ok = await wire(t, { envFallback: true, env })
  await ok.broker.start()
  const fromVault = await ok.broker.ref('anthropic-api-key', 'boot', { envVar: 'ANTHROPIC_API_KEY' })
  assert.equal(fromVault.source, 'vault')
  assert.equal(ok.broker.use(fromVault, (v) => v), valueFor('anthropic-api-key'))
  assert.equal(redactString(env.ANTHROPIC_API_KEY), env.ANTHROPIC_API_KEY)

  // 2. Vault failed + fallback OFF -> refused.
  const off = await wire(t, { noHub: true, envFallback: false, env })
  await off.broker.start()
  await assert.rejects(
    () => off.broker.ref('anthropic-api-key', 'boot', { envVar: 'ANTHROPIC_API_KEY' }),
    PolicyDenied,
  )

  // 3. Vault failed + fallback ON -> this entry's own variable, and no other.
  const on = await wire(t, { noHub: true, envFallback: true, env })
  await on.broker.start()
  const fromEnv = await on.broker.ref('anthropic-api-key', 'boot', { envVar: 'ANTHROPIC_API_KEY' })
  assert.equal(fromEnv.source, 'env')

  // 4. An entry with no envVar never falls back, however open the setting is.
  await assert.rejects(
    () => on.broker.ref('openrouter-api-key', 'boot'),
    (e: unknown) => e instanceof PolicyDenied && /declares no auth.envVar/.test(e.message),
  )
})

test('env-fallback values are registered with the mask before any llm.request is appended', async (t) => {
  SecretMask.clear()
  const value = 'env-value-registered-first-77ac31'
  const { broker, store } = await wire(t, {
    noHub: true,
    envFallback: true,
    env: { ANTHROPIC_API_KEY: value },
  })
  await broker.start()

  assert.equal(redactString(value), value)
  await broker.ref('anthropic-api-key', 'boot', { envVar: 'ANTHROPIC_API_KEY' })

  // The ordering is the whole defence: by the time anything can append a
  // payload containing this value, the mask already knows it.
  assert.equal(redactString(value), CENSOR)
  assert.equal(store.query({ type: 'llm.request' }).length, 0)

  store.append({
    type: 'llm.request',
    payload: { schemaVersion: 1, ref: 'anthropic/x', attempt: 1, prompt: `auth ${value}`, tools: [] },
  })
  const rows = store.query()
  const maskedAt = rows.findIndex((r) => r.type === 'secret.accessed')
  const requestAt = rows.findIndex((r) => r.type === 'llm.request')
  assert.ok(maskedAt >= 0 && requestAt > maskedAt, 'the secret was accounted for before the first request')
  assert.equal(payloads(store, 'llm.request')[0]?.['prompt'], `auth ${CENSOR}`)
})

// ── the scope rule ─────────────────────────────────────────────────────────

test('ref() refuses inside an agent run scope; use() is allowed and still never returns the value', async (t) => {
  const { broker, store } = await wire(t)
  await broker.start()

  // Resolved at boot, outside any run.
  const ref = await broker.ref('anthropic-api-key', 'boot')
  const before = store.query({ type: 'secret.accessed' }).length

  await withRunScope(RUN, async () => {
    // A run may not reach the vault, even through kernel code it does not
    // control: "resolve me the anthropic key" is a sentence a model can
    // produce, and the gate is not in this path.
    await assert.rejects(
      () => broker.ref('openrouter-api-key', 'on a run’s behalf'),
      (e: unknown) => e instanceof PolicyDenied && /may not resolve a secret \(run run_1\)/.test(e.message),
    )

    // use() IS permitted here: the router attaches the provider credential
    // during the run. It hands the value to a callback and returns that
    // callback's answer, so the run gains the ability to USE a credential the
    // kernel already resolved, never to obtain one.
    const header = broker.use(ref, (v) => `Bearer ${v.slice(0, 4)}`)
    assert.equal(header, 'Bearer fixt')
  })

  // The refusal resolved nothing and recorded nothing.
  assert.equal(store.query({ type: 'secret.accessed' }).length, before)
})

test('a purpose is required, so no call site reaches a vault without saying why', async (t) => {
  const { broker } = await wire(t)
  await broker.start()
  await assert.rejects(
    () => broker.ref('anthropic-api-key', '   '),
    (e: unknown) => e instanceof PolicyDenied && /without a stated purpose/.test(e.message),
  )
})
