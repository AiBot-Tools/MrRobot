// Egress plan W1b, as the egress suite holds it (F1): a trusted exec's grant
// is in the log before its container is spawned, and it is revoked when the
// container ends, with the driver's verdict on it, whether its channel was
// served or not; a hostile-domain manifest that names egress is refused at
// load, a hostile-domain exec is never planned a grant or a channel, a
// hostile-domain publish is refused for its domain, and a grant's row names
// the domain its container runs on, so none is ever recorded for the hostile
// one.
//
// test/sandbox-exec.test.ts holds most of this and more, but it waits on the
// runner as the runner waits on its container, without a bound of its own:
// under a mutant of the egress session that never has a container killed
// (EG330) or never ends a flow, its calls never settle, and the falsifier
// reads the whole suite as hung, a verdict that is never a kill. So the
// egress suite runs this file instead: every wait here is bounded, and a
// call that has not settled in time has every container the fake runs ended,
// as its wallclock would end it, before the test fails, so nothing of it
// outlives the test.
//
// The falsifiers, each held here (scripts/falsify/catalog.ts EGRESS_COVERAGE):
//
//   The grant's row appended after the spawn (EG665): the container's first
//   bytes may be judged under a grant the log does not hold yet.
//   A grant the driver refused a container for, or one no channel served,
//   left open (EG666, EG667); a served one never revoked (EG674); every end
//   revoked as `exited` (EG668).
//   A hostile manifest that names egress loaded (EG677).
//   A hostile exec planned a grant (EG664); a hostile publish planned one,
//   its refusal left to what follows the domain check (EG675).
//   A grant's row naming the trusted domain whatever its container's (EG676).
//
// Everything is in process: the driver is test/helpers/fake-sandbox.ts and
// the upstream test/helpers/fake-egress.ts's, over an injected resolver and
// dialer. Nothing listens, resolves or dials.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { AgentRegistry } from '../src/agents/registry.js'
import type { EgressHost } from '../src/egress/host.js'
import { EgressGrant } from '../src/egress/policy.js'
import { acceptReady } from '../src/egress/ready.js'
import type { CredentialInjector } from '../src/egress/session.js'
import type { EventStore } from '../src/events/store.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { hashArgs, type GateTicket } from '../src/policy/engine.js'
import { grantIssuedRow, SandboxTools, type SandboxCallContext, type SandboxEgress, type SandboxToolsOptions } from '../src/runtime/sandbox-tools.js'
import type { SandboxDriver } from '../src/sandbox/driver.js'
import { fakeUpstream, until } from './helpers/fake-egress.js'
import { fakeSandbox, type FakeSandbox, type ScriptedExit } from './helpers/fake-sandbox.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const REF = 'anthropic/claude-sonnet-5'
const IMAGE = `sha256:${'ab'.repeat(32)}`
const EXEC = 'sandbox.exec'
const PUBLISH = 'sandbox.publish'
/** The home the fake driver's audit refuses, as the real driver refuses the operator's. */
const FAKE_HOME = '/Users/operator'
/** How long a call may take to settle here before the test ends its containers and fails. */
const SETTLE_MS = 5_000

/** The tool-views file the daemon ships: sandbox.exec is agent, write, taints. */
const VIEWS = parseToolViews(parseYaml(readFileSync(join(REPO_ROOT, 'config', 'tool-views.yaml'), 'utf8')))

/** kernel.yaml's shipped egress.limits. */
const LIMITS = Object.freeze({
  frameMaxBytes: 65_536,
  maxFlows: 16,
  maxHeaderBytes: 16_384,
  maxRequests: 2_000,
  maxBytes: 536_870_912,
  maxDenied: 20,
  idleMs: 60_000,
})

/** One binding of every profile, on the fixture repository; an exec's grant holds its git-fetch alone. */
const GITHUB = Object.freeze({ host: 'github.com', profiles: ['git-fetch', 'git-push', 'github-pulls'], repos: ['op/fixture'] })

/**
 * A worker on `domain` whose manifest names egress (a hostile one only as a
 * forged record, or with `egress` for the registry to refuse). A hostile one
 * also holds sandbox.publish, which the registry admits and the runner
 * refuses there.
 */
function manifest(domain: 'trusted' | 'hostile', egress: boolean = domain === 'trusted'): string {
  return [
    'id: coder',
    'version: 1',
    'kind: standard',
    'role: worker',
    'soul: worker.md',
    `tier: ${domain === 'hostile' ? '3' : '2'}`,
    'model:',
    `  primary: ${REF}`,
    'tools:',
    `  allow: [${domain === 'hostile' ? `${EXEC}, ${PUBLISH}` : EXEC}]`,
    'sandbox:',
    `  domain: ${domain}`,
    ...(egress ? ['egress:', '  allow: [registry.npmjs.org]', '  bind: [github]'] : []),
    'memory:',
    '  projectId: aos/agent/coder',
    '',
  ].join('\n')
}

/** The registry the runner reads agents from, with kernel.yaml's github binding. */
function registryOn(store: EventStore): AgentRegistry {
  return new AgentRegistry({
    providers: new Set([REF]),
    toolViews: VIEWS,
    store,
    budgets: { defaultRunMicroUsd: 2_000_000, defaultWallclockMs: 600_000, maxLlmCallsPerRun: 50, maxToolCallsPerRun: 100 },
    egressBindings: { github: { host: GITHUB.host as EgressHost, repos: GITHUB.repos } },
  })
}

/** An agents directory holding coder's manifest `yaml`. */
function agentsDir(t: TestContext, yaml: string): string {
  const dir = join(tmpdir(t), 'agents')
  mkdirSync(join(dir, 'coder'), { recursive: true })
  writeFileSync(join(dir, 'coder', 'agent.yaml'), yaml)
  return dir
}

interface Harness {
  readonly store: EventStore
  readonly driver: FakeSandbox
  readonly tools: SandboxTools
}

function harness(
  t: TestContext,
  options: {
    readonly domain?: 'trusted' | 'hostile'
    readonly exits: readonly ScriptedExit[]
    /** The driver the runner is handed, over the fake. */
    readonly over?: (fake: FakeSandbox) => SandboxDriver
    /** What the runner reads agents from, in place of the registry. */
    readonly agents?: (registry: AgentRegistry) => SandboxToolsOptions['agents']
  },
): Harness {
  const store = withStore(t)
  const agents = registryOn(store)
  agents.load(agentsDir(t, manifest(options.domain ?? 'trusted')))
  const root = tmpdir(t)
  mkdirSync(join(root, 'trusted'))
  mkdirSync(join(root, 'hostile'))
  const driver = fakeSandbox({ imageId: IMAGE, script: options.exits, home: FAKE_HOME })
  const credential: CredentialInjector = (_bindingId, set) => set('Authorization', 'Bearer opaque-binding-value-5d1c8e')
  const egress: SandboxEgress = {
    state: { state: 'ok' },
    bindings: { github: GITHUB },
    resolved: new Map([['github', { bindingId: 'github', envVar: 'AOS_GITHUB_TOKEN' }]]),
    limits: LIMITS,
    upstream: fakeUpstream().upstream,
    credential,
    acceptReady,
  }
  const tools = new SandboxTools({
    store,
    views: VIEWS,
    driver: options.over?.(driver) ?? driver,
    agents: options.agents?.(agents) ?? agents,
    sandbox: {
      imageId: IMAGE,
      domains: {
        trusted: { dockerHost: 'unix:///nowhere/trusted.sock', network: 'aos-trusted', mountRoot: join(root, 'trusted') },
        hostile: { dockerHost: 'unix:///nowhere/hostile.sock', network: 'aos-hostile', mountRoot: join(root, 'hostile') },
      },
      defaults: { user: '65534:65534', pidsLimit: 256, memory: '2g', cpus: 2, wallclockMs: 120_000 },
    },
    egress,
    // Short, so a container the runner never sees end is given up soon after
    // its wallclock (context's budget, below), whatever a mutant broke.
    killWaitMs: 1_000,
    resultGraceMs: 500,
  })
  return { store, driver, tools }
}

/** A ticket as the engine mints one, for a direct call of the runner. */
function ticketFor(runId: string, args: Record<string, unknown>, toolRef: string = EXEC): GateTicket {
  return { ticketId: 'tkt-1', runId, toolRef, argsHash: hashArgs(args), quarantine: false }
}

/** The registry's record of each agent, its manifest's egress replaced by `egress`: a record that reached the runner without the registry's load. */
const forged =
  (egress: { readonly allow: readonly string[]; readonly bind: readonly string[] }) =>
  (registry: AgentRegistry): SandboxToolsOptions['agents'] => ({
    get: (id) => {
      const record = registry.get(id)
      return record === undefined
        ? undefined
        : { ...record, manifest: { ...record.manifest, egress: { allow: egress.allow.map((host) => host as EgressHost), bind: [...egress.bind] } } }
    },
  })

/** A run with 10 s left: its container's wallclock. */
const context = (runId: string, over: Partial<SandboxCallContext> = {}): SandboxCallContext => ({
  runId,
  agentId: 'coder',
  budget: { remainingMs: () => 10_000 },
  ...over,
})

/**
 * What `call` settles with, or the test's failure: one that has not settled
 * in SETTLE_MS has every container the fake runs ended as its wallclock
 * would end it, and is waited on as long again, so nothing of it outlives
 * the test, which then fails.
 */
async function settled<T>(call: Promise<T>, driver: FakeSandbox, what: string): Promise<T> {
  const late = Symbol('late')
  let timer: NodeJS.Timeout | undefined
  const bound = new Promise<typeof late>((resolve) => {
    timer = setTimeout(() => resolve(late), SETTLE_MS)
  })
  const first = await Promise.race([call, bound])
  clearTimeout(timer)
  if (first !== late) return first as T
  for (const spec of driver.specs) driver.simulateOverrun(spec.name)
  let after: NodeJS.Timeout | undefined
  await Promise.race([
    call.then(
      () => undefined,
      () => undefined,
    ),
    new Promise((resolve) => {
      after = setTimeout(resolve, SETTLE_MS)
    }),
  ])
  clearTimeout(after)
  assert.fail(`${what} did not settle within ${String(SETTLE_MS)} ms`)
}

interface Row {
  readonly seq: number
  readonly type: string
  readonly runId: string | null
  readonly payload: Record<string, unknown>
}

const rowsOf = (store: EventStore, type: string): Row[] =>
  store.query({ type }).map((r) => ({ seq: r.seq, type: r.type, runId: r.runId, payload: JSON.parse(r.payload) as Record<string, unknown> }))

const ZERO_TOTALS = { flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 }

test("an exec's grant is in the log before its container is spawned, and is revoked when the container ends, with the driver's verdict: its own exit, its wallclock, the run's stop", { timeout: 30_000 }, async (t) => {
  const h = harness(t, { exits: [{ hangs: true }, { hangs: true }, { hangs: true }] })
  // What the log held of grants at each spawn, read as the driver is called.
  const atSpawn: number[] = []
  const spawn = h.driver.run.bind(h.driver)
  h.driver.run = (spec) => {
    atSpawn.push(rowsOf(h.store, 'proxy.grant.issued').length)
    return spawn(spec)
  }
  const args = { command: ['git', 'fetch'] }
  const nth = async (n: number): Promise<string> => {
    await until(() => h.driver.specs.length === n, `container ${String(n)}`)
    return h.driver.specs[n - 1]?.name ?? ''
  }

  // Its own exit (with no exit frame from its mux: the command's status is unknown).
  const exited = h.tools.call(ticketFor('run_a', args), args, context('run_a'))
  h.driver.simulateExit(await nth(1))
  await settled(exited, h.driver, 'the exec whose container exited')
  // Its wallclock.
  const overran = h.tools.call(ticketFor('run_b', args), args, context('run_b'))
  h.driver.simulateOverrun(await nth(2))
  await settled(overran, h.driver, 'the exec whose container overran')
  // The run's stop: the runner's kill by name ends it.
  const stop = new AbortController()
  const stopped = h.tools.call(ticketFor('run_c', args), args, context('run_c', { signal: stop.signal }))
  await nth(3)
  stop.abort()
  await settled(stopped, h.driver, 'the exec whose run was stopped')

  assert.deepEqual(atSpawn, [1, 2, 3], "a container was spawned before the log held its grant")
  assert.deepEqual(h.driver.specs.map((s) => [s.domain, s.channel]), [['trusted', true], ['trusted', true], ['trusted', true]])
  const issued = rowsOf(h.store, 'proxy.grant.issued')
  const started = rowsOf(h.store, 'sandbox.started')
  const killed = rowsOf(h.store, 'sandbox.killed')
  const revoked = rowsOf(h.store, 'proxy.grant.revoked')
  assert.deepEqual(issued.map((r) => [r.runId, r.payload['sandbox']]), h.driver.specs.map((s) => [s.runId, s.name]))
  // One grant per container, each revoked once, in its own run, with the driver's verdict.
  assert.deepEqual(revoked.map((r) => [r.runId, r.payload['grantId'], r.payload['reason']]), [
    ['run_a', issued[0]?.payload['grantId'], 'exited'],
    ['run_b', issued[1]?.payload['grantId'], 'wallclock'],
    ['run_c', issued[2]?.payload['grantId'], 'requested'],
  ])
  assert.deepEqual(killed.map((r) => r.payload['reason']), ['exited', 'wallclock', 'requested'])
  // Issued, then started, then ended, then revoked, for each.
  for (const i of [0, 1, 2]) {
    const order = [issued[i]?.seq, started[i]?.seq, killed[i]?.seq, revoked[i]?.seq].map((seq) => seq ?? -1)
    assert.deepEqual([...order].sort((a, b) => a - b), order, `run ${String(i)}: ${order.join(' < ')}`)
  }
  assert.deepEqual(h.tools.liveGrants(), [])
})

test('a grant whose container the driver refused before it started is revoked at once, and one no channel served is revoked unserved when its container ends', { timeout: 30_000 }, async (t) => {
  const args = { command: ['git', 'fetch'] }
  // The driver refuses the spec: nothing ran, so nothing crossed a channel.
  {
    const h = harness(t, {
      exits: [],
      over: (fake) => ({
        name: fake.name,
        probe: () => fake.probe(),
        run: () => {
          throw new Error('the fake driver refuses this spec')
        },
        kill: (name) => fake.kill(name),
        abandon: (name) => fake.abandon(name),
        commandRefusal: (command) => fake.commandRefusal(command),
        everyRunRefusal: () => fake.everyRunRefusal(),
        sweepOrphans: (request) => fake.sweepOrphans(request),
      }),
    })
    await settled(
      h.tools.call(ticketFor('run_r', args), args, context('run_r')).catch(() => undefined),
      h.driver,
      'the exec the driver refused',
    )
    const issued = rowsOf(h.store, 'proxy.grant.issued')
    assert.equal(issued.length, 1)
    assert.deepEqual(
      rowsOf(h.store, 'proxy.grant.revoked').map((r) => [r.runId, r.payload]),
      [['run_r', { schemaVersion: 1, grantId: issued[0]?.payload['grantId'], reason: 'error', detail: 'the driver refused the container before it started', totals: ZERO_TOTALS }]],
    )
    assert.deepEqual(h.tools.liveGrants(), [])
  }
  // The driver runs it and gives it no channel: the runner kills it by name
  // at once, and its grant is revoked as unserved once it ends.
  {
    const h = harness(t, {
      exits: [{ hangs: true }],
      over: (fake) => ({
        name: fake.name,
        probe: () => fake.probe(),
        run: (spec) => {
          const running = fake.run(spec)
          return { name: running.name, result: running.result }
        },
        kill: (name) => fake.kill(name),
        abandon: (name) => fake.abandon(name),
        commandRefusal: (command) => fake.commandRefusal(command),
        everyRunRefusal: () => fake.everyRunRefusal(),
        sweepOrphans: (request) => fake.sweepOrphans(request),
      }),
    })
    await settled(h.tools.call(ticketFor('run_u', args), args, context('run_u')), h.driver, 'the exec given no channel')
    assert.equal(h.driver.specs[0]?.channel, true)
    const issued = rowsOf(h.store, 'proxy.grant.issued')
    assert.equal(issued.length, 1)
    assert.deepEqual(
      rowsOf(h.store, 'proxy.grant.revoked').map((r) => [r.runId, r.payload]),
      [['run_u', { schemaVersion: 1, grantId: issued[0]?.payload['grantId'], reason: 'error', detail: 'the driver gave the run no channel', totals: ZERO_TOTALS }]],
    )
    assert.deepEqual(h.tools.liveGrants(), [])
  }
})

test('a hostile-domain manifest that names egress is refused at load, so only a forged record brings one to the runner', (t) => {
  const store = withStore(t)
  assert.throws(
    () => registryOn(store).load(agentsDir(t, manifest('hostile', true))),
    /coder\/agent\.yaml: coder holds egress.*, but it is sandboxed in the hostile domain\. .*the hostile domain gets no channel and no egress/,
  )
  assert.equal(store.query({ type: 'agent.registered' }).length, 0, 'a refused fleet left registrations behind')
  // Without its egress, the same manifest loads.
  const loaded = registryOn(store)
  loaded.load(agentsDir(t, manifest('hostile', false)))
  assert.equal(loaded.get('coder')?.manifest.sandbox?.domain, 'hostile')
})

test('a hostile-domain exec is planned no grant and asks for no channel, whatever its record names', { timeout: 30_000 }, async (t) => {
  // The registry refuses egress on a hostile manifest at load; one that
  // reached the runner anyway (forged here) runs as every hostile run does.
  const h = harness(t, { domain: 'hostile', exits: [{ stdout: 'ran\n' }], agents: forged({ allow: ['registry.npmjs.org'], bind: ['github'] }) })
  const args = { command: ['curl', 'http://registry.npmjs.org/'] }
  const out = await settled(h.tools.call(ticketFor('run_h', args), args, context('run_h')), h.driver, 'the hostile exec')
  assert.equal(out.ok, true, out.text)
  const spec = h.driver.specs[0]
  assert.equal(spec?.domain, 'hostile')
  assert.equal(spec !== undefined && 'channel' in spec, false, 'a hostile run asked for a channel')
  assert.deepEqual(rowsOf(h.store, 'proxy.grant.issued'), [])
  assert.deepEqual(rowsOf(h.store, 'proxy.grant.revoked'), [])
  assert.deepEqual(h.tools.liveGrants(), [])
})

test('a hostile-domain publish is refused for its domain, before the gate and at execution, with no grant, no channel and no container, whatever its record names', { timeout: 30_000 }, async (t) => {
  // A forged record whose egress binds github, which holds git-fetch,
  // git-push and github-pulls on op/fixture: on the trusted domain, a
  // publish's one repository. The domain is refused first, so nothing after
  // it (the bindings, the grant, its row, the driver's refusal of a hostile
  // channel) is what stops it.
  const h = harness(t, { domain: 'hostile', exits: [{ stdout: 'opened\n' }], agents: forged({ allow: [], bind: ['github'] }) })
  const refusal =
    "coder is not sandboxed in the trusted domain, and sandbox.publish reaches its repository only through the kernel's " +
    'egress engine, which serves the trusted domain alone; no container was started'
  // Before the gate, as the loop asks it of the offer and of the call.
  assert.equal(h.tools.egressRefusal(PUBLISH, 'coder'), refusal)
  assert.equal(h.tools.egressRefusal(PUBLISH, 'coder', 'run_p'), refusal)
  const args = { branch: 'fix/readme', title: 'Fix the README', body: 'Opened by the fixture run.' }
  const out = await settled(h.tools.call(ticketFor('run_p', args, PUBLISH), args, context('run_p')), h.driver, 'the hostile publish')
  assert.equal(out.ok, false)
  assert.equal(out.text, `[refused] ${refusal}`)
  assert.deepEqual(h.driver.specs, [], 'a hostile publish reached the driver')
  assert.deepEqual(rowsOf(h.store, 'proxy.grant.issued'), [])
  assert.deepEqual(rowsOf(h.store, 'proxy.grant.revoked'), [])
  assert.deepEqual(rowsOf(h.store, 'sandbox.started'), [])
  assert.deepEqual(h.tools.liveGrants(), [])
})

test("a grant's row names the domain its container runs on, so a grant for a container on the hostile domain is refused, never recorded as a trusted one", () => {
  // The builder #planGrant, #planPublish and #issue share. Each plan refuses
  // the hostile domain before it builds a row, so only a dropped check
  // brings one here; the row then says where the container runs, which
  // proxy.grant.issued refuses, and #issue throws before the spawn, where a
  // row that said trusted would be appended for a container on the hostile
  // domain.
  const grant = EgressGrant.parse({ runId: 'run_g', allow: ['registry.npmjs.org'], routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }] })
  const trusted = grantIssuedRow('grant_1_0123456789ab', { name: 'aos-run-run_g-1', domain: 'trusted' }, 'run_g', 'coder', grant, 'exec')
  assert.deepEqual(trusted, {
    payload: {
      schemaVersion: 1,
      grantId: 'grant_1_0123456789ab',
      purpose: 'exec',
      runId: 'run_g',
      agentId: 'coder',
      sandbox: 'aos-run-run_g-1',
      domain: 'trusted',
      allow: ['registry.npmjs.org'],
      routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }],
    },
  })
  for (const purpose of ['exec', 'publish'] as const) {
    assert.deepEqual(
      grantIssuedRow('grant_1_0123456789ab', { name: 'aos-run-run_g-1', domain: 'hostile' }, 'run_g', 'coder', grant, purpose),
      { refusal: 'the grant is not one proxy.grant.issued can record (1 issue(s)), so it is not issued; no container was started' },
      purpose,
    )
  }
})
