// Egress plan W3 — the boot image-id check and the per-domain canary.
//
// Egress is the kernel's own engine reached over a trusted run's docker -i
// channel, and it is only as good as the two things a boot can check before
// it serves anything: that each VM holds the worker image under the one id
// kernel.yaml pins (the probe's `docker image inspect --format {{.Id}}`, on
// each domain's own socket), and that a container on each domain really has
// no way out but that channel. The canary shows the second: one container on
// each domain, run as any other is (the pinned image by id, --pull=never,
// --network none), whose mux's self-test must fail every direct connect and
// the lookup, judged by the same acceptReady every exec's ready is; the
// trusted one must also complete one framed round trip, a request the kernel
// denies and records. Egress is ok only when both pass.
//
// The falsifiers, each held here:
//
//   A boot that reads only the trusted VM's image id, or reads a mismatch as
//   ok, hands the hostile domain's runs an image docker refuses to run, or
//   another image under the pin.
//   A canary judged more weakly than an exec's ready (a timed-out probe let
//   through, a reached one named as nothing) is a VM with a route the kernel
//   calls ok.
//   A canary whose round trip is not held to a deny the kernel recorded is a
//   channel that may carry nothing at all, or carry it past the engine.
//   A canary named alike on two boots can be ended by a kill an earlier
//   boot's sweep left pending, and one the log names nowhere is never swept
//   once a kernel dies during its boot.
//   A grant a dead kernel left open, a run's or a canary's, that the next
//   boot does not close stays open in the log for ever (egress plan W2).
//   A Basic binding whose derived value boot does not mask puts base64 of the
//   credential in a row the moment a host echoes the header it was sent
//   (egress plan W1): the redaction pass reads no bare base64.
//
// Everything is in process: the driver is test/helpers/fake-sandbox.ts, and
// each canary's container is played as the worker image's mux plays it
// (test/helpers/fake-egress.ts canaryPlayer). Nothing is resolved or dialled.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { GRANT_RECOVERED_DETAIL, sweepTargets, type Kernel } from '../src/kernel.js'
import { readAllRows } from '../src/events/chain.js'
import { closedSandboxDomains, openRunlessSandboxes, projectRecovery } from '../src/events/projections.js'
import { EventStore } from '../src/events/store.js'
import { acceptReady, SELF_TEST, probeTarget } from '../src/egress/ready.js'
import { DENY_WINDOW_MS } from '../src/egress/session.js'
import { EGRESS_DETAIL_BYTES } from '../src/events/types.js'
import { redactString, SecretMask } from '../src/events/redact.js'
import {
  CANARY_COMMANDS,
  CANARY_MIN_WALLCLOCK_MS,
  CANARY_PREFIX,
  CANARY_WALLCLOCK_MS,
  CANARY_WORKSPACE,
  canaryName,
  canaryNonce,
  runCanary,
  type CanaryOptions,
} from '../src/runtime/canary.js'
import { DOCKER_CLI_FAILED } from '../src/runtime/sandbox-tools.js'
import { containerRunId, type RunningSandbox, type SandboxDomain, type SandboxDriver, type SandboxSpec } from '../src/sandbox/driver.js'
import {
  canaryPlayer,
  probeKind,
  quietReport,
  REFUSED_PROBE_ERRORS,
  refusedReport,
  reportWith,
  type CanaryPlay,
} from './helpers/fake-egress.js'
import { fakeSandbox, type FakeSandbox, type FakeSandboxOptions } from './helpers/fake-sandbox.js'
import { anthropicEndTurn, anthropicToolUse, fakeProvider } from './helpers/fake-provider.js'
import { bootOn as bootFixture, fixture, REPO_ROOT, runThroughControl, withKernel as bootFresh, type KernelFixture, type WithKernelOptions } from './helpers/kernel.js'
import { freshProbe } from './helpers/probe.js'
import { tmpdir } from './helpers/tmpdir.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { closeVerified, withStore } from './helpers/store.js'

/** The pinned worker image id. */
const IMAGE = `sha256:${'ab'.repeat(32)}`
/** Another image's id, as a VM loaded with another build prints it. */
const OTHER = `sha256:${'cd'.repeat(32)}`

/**
 * How long boot waits on a canary in this file, in place of CANARY_WAIT_MS
 * (30 s), unless a test names its own. Under the in-process fake a canary
 * that passes or fails ends in milliseconds; one a broken kernel never ends
 * (a refused ready whose container is never killed, egress suite mutant
 * EG330) must be given up while its test still runs, before the canary
 * player stops waiting for go at 5 s (fake-egress.ts until) and fails the
 * test: a boot that finished after its test had ended would leave a kernel
 * nobody shuts down, and the file would never exit, which the falsifier
 * reads as hung, never as a kill.
 */
const TEST_CANARY_WAIT_MS = 3_000

/** helpers/kernel.ts withKernel, with this file's canary wait. */
const withKernel = (t: TestContext, options: WithKernelOptions = {}) => bootFresh(t, { canaryWaitMs: TEST_CANARY_WAIT_MS, ...options })

/** helpers/kernel.ts bootOn, with this file's canary wait. */
const bootOn = (t: TestContext, fx: KernelFixture, options: Parameters<typeof bootFixture>[2] = {}): Promise<Kernel> =>
  bootFixture(t, fx, { canaryWaitMs: TEST_CANARY_WAIT_MS, ...options })

/** kernel.yaml's sandbox block with IMAGE pinned, and egress enabled (or not). */
const yaml =
  (enabled = true) =>
  (base: string): string =>
    `${base.replace('  image: aos-worker:test\n', `  image: aos-worker:test\n  imageId: "${IMAGE}"\n`)}\negress:\n  enabled: ${String(enabled)}\n`

/** A driver whose daemons answer, holding IMAGE (unless `extra` says a VM holds another), whose canaries are played as `play` says. */
const driverWith = (play: CanaryPlay = {}, extra: FakeSandboxOptions = {}): FakeSandbox =>
  fakeSandbox({ imageId: IMAGE, probe: { ok: true, version: 'fake 1' }, play: canaryPlayer(play), ...extra })

interface Row {
  readonly seq: number
  readonly type: string
  readonly runId: string | null
  readonly agentId: string | null
  readonly payload: Record<string, unknown>
}

/** Every row of the log, run and agent columns included. */
function allRows(dbPath: string): Row[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return store.query().map((r) => ({ seq: r.seq, type: r.type, runId: r.runId, agentId: r.agentId, payload: JSON.parse(r.payload) as Record<string, unknown> }))
  } finally {
    store.close()
  }
}

const ofType = (all: readonly Row[], type: string): Row[] => all.filter((r) => r.type === type)
const egressRows = (dbPath: string): Record<string, unknown>[] => ofType(allRows(dbPath), 'egress.degraded').map((r) => r.payload)

/** The canary names a boot used, by domain, from the specs its driver was handed. */
function canaryNames(driver: FakeSandbox): { trusted: string; hostile: string } {
  const named = (domain: string): string => driver.specs.find((s) => s.domain === domain && s.name.startsWith(CANARY_PREFIX))?.name ?? ''
  return { trusted: named('trusted'), hostile: named('hostile') }
}

/** The judge's clause for refusedReport('reached'). */
const REACHED = 'the self-test reached 1 of what it must not (192.168.5.2:8766)'

/** The sandbox's reason for a domain closed by a canary whose self-test report was refused with `clause`. */
const closes = (domain: SandboxDomain, name: string, clause: string): string =>
  `${domain}: the boot canary (${name}) found that a container on this domain may have a route the kernel did not give ` +
  `it (its self-test report was refused: ${clause}), so this domain runs no sandbox.exec until a boot whose canary ` +
  "there passes: check the VM's Docker (it must honour --network none) and the worker image, then restart the kernel " +
  'with egress enabled, so that its canaries run'

/** The fix a failed self-test report names. */
const FIX_NETWORK =
  "a container on this domain has a route the kernel did not give it: check the VM's Docker (it must honour --network none) and the worker image, then restart the kernel"

async function bootWith(t: TestContext, driver: FakeSandbox, options: { readonly enabled?: boolean; readonly canaryWaitMs?: number } = {}) {
  return withKernel(t, {
    kernelYaml: yaml(options.enabled ?? true),
    sandboxDriver: driver,
    ...(options.canaryWaitMs === undefined ? {} : { canaryWaitMs: options.canaryWaitMs }),
  })
}

// ── the acceptance rows ──────────────────────────────────────────────────────

test('both canaries passing gives egress ok', async (t) => {
  const answers: string[] = []
  const driver = driverWith({ answers })
  const { kernel, fx } = await bootWith(t, driver)
  assert.equal(kernel.status().subsystems.sandbox.state, 'ok', kernel.status().subsystems.sandbox.reason ?? '')
  assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' })
  assert.equal(kernel.degraded.includes('egress'), false, kernel.degraded.join(', '))
  assert.deepEqual(egressRows(fx.dbPath), [])

  // One container per domain, named by this boot's kernel.booted seq and one
  // nonce, run as any other is: the pinned image, the domain's own command,
  // a channel on the trusted domain only, and the canary's wallclock.
  const all = allRows(fx.dbPath)
  const booted = ofType(all, 'kernel.booted')
  assert.equal(booted.length, 1)
  const names = canaryNames(driver)
  const shape = /^aos-run-canary-([0-9]+)-([0-9a-f]{12})-(trusted|hostile)$/
  const [, seq, nonce] = shape.exec(names.trusted) ?? []
  assert.equal(seq, String(booted[0]?.seq), names.trusted)
  assert.equal(names.hostile, canaryName(Number(seq), nonce ?? '', 'hostile'))
  for (const name of [names.trusted, names.hostile]) assert.equal(containerRunId(name), undefined, `${name} reads as a run's container`)
  assert.equal(driver.specs.length, 2)
  for (const spec of driver.specs) {
    const trusted = spec.domain === 'trusted'
    assert.equal(spec.image, IMAGE)
    assert.deepEqual(spec.command, CANARY_COMMANDS[spec.domain])
    // The worker image's mux, in its canary mode on the trusted domain and its self-test mode on the hostile one (test/egress-mux.test.ts holds what each reads).
    assert.equal(spec.command.at(-1), trusted ? '--canary' : '--self-test')
    assert.equal(spec.channel === true, trusted, spec.domain)
    assert.equal(spec.limits.wallclockMs, CANARY_WALLCLOCK_MS)
    assert.equal(spec.workspace, join(fx.config.sandbox.domains[spec.domain].mountRoot, CANARY_WORKSPACE))
    assert.equal(lstatSync(spec.workspace).isDirectory(), true)
    assert.equal(lstatSync(spec.workspace).mode & 0o777, 0o700)
  }
  assert.deepEqual(driver.channels.map((c) => c.name), [names.trusted], 'the hostile domain was given a channel')

  // The trusted canary's grant, issued before its container started, under
  // no run and no agent, reaching nothing, and naming its container.
  const issued = ofType(all, 'proxy.grant.issued')
  assert.equal(issued.length, 1)
  const grant = issued[0]
  assert.deepEqual([grant?.runId, grant?.agentId], [null, null])
  assert.deepEqual(
    { ...grant?.payload, grantId: undefined },
    { schemaVersion: 1, grantId: undefined, purpose: 'canary', sandbox: names.trusted, domain: 'trusted', allow: [], routes: [] },
  )
  const started = ofType(all, 'sandbox.started')
  assert.deepEqual(started.map((r) => [r.runId, r.payload['sandboxId'], r.payload['domain'], r.payload['image']]), [
    [null, names.trusted, 'trusted', IMAGE],
    [null, names.hostile, 'hostile', IMAGE],
  ])
  assert.ok((grant?.seq ?? Infinity) < (started[0]?.seq ?? -1), 'the grant was issued after its container started')

  // Its one framed round trip: one request, judged, denied before anything
  // was resolved or dialled, and recorded under the canary's grant; the mux
  // read the kernel's 403 and said so in its exit frame.
  const decisions = ofType(all, 'proxy.decision')
  assert.equal(decisions.length, 1)
  assert.equal(decisions[0]?.runId, null)
  assert.deepEqual(
    [decisions[0]?.payload['grantId'], decisions[0]?.payload['verdict'], decisions[0]?.payload['reason'], decisions[0]?.payload['hostRefusal']],
    [grant?.payload['grantId'], 'deny', 'not-a-host', 'ip-literal'],
  )
  assert.equal(answers.length, 1)
  assert.match(answers[0] ?? '', /^HTTP\/1\.1 403 /)
  const revoked = ofType(all, 'proxy.grant.revoked')
  assert.equal(revoked.length, 1)
  assert.equal(revoked[0]?.runId, null)
  assert.equal(revoked[0]?.payload['reason'], 'exited')
  const totals = revoked[0]?.payload['totals'] as Record<string, number> | undefined
  assert.deepEqual([totals?.['requests'], totals?.['denied'], totals?.['allowed']], [1, 1, 0])
  // Both ended on their own, exit 0, and nothing was killed or given up.
  assert.deepEqual(ofType(all, 'sandbox.killed').map((r) => [r.runId, r.payload['sandboxId'], r.payload['reason'], r.payload['exitCode']]).sort(), [
    [null, names.hostile, 'exited', 0],
    [null, names.trusted, 'exited', 0],
  ])
  assert.deepEqual([driver.kills, driver.abandons], [[], []])
  assert.deepEqual(kernel.sandboxTools.liveGrants(), [])

  // A second boot of the same log names its canaries anew: a later seq, the
  // same shape. Both of the first boot's ended, so its sweep asks nothing.
  await kernel.shutdown()
  const next = driverWith()
  const again = await bootOn(t, fx, { sandboxDriver: next })
  assert.deepEqual(again.status().subsystems.egress, { state: 'ok' })
  const renamed = canaryNames(next)
  const [, seq2] = shape.exec(renamed.trusted) ?? []
  assert.ok(Number(seq2) > Number(seq), `${renamed.trusted} after ${names.trusted}`)
  assert.notEqual(renamed.hostile, names.hostile)
  assert.deepEqual(next.sweepRequests, [], 'a canary that ended was swept')
})

test("each boot names its canaries with a fresh random nonce, so two data directories booted to the same seq name theirs apart", async (t) => {
  // A second checkout's log reaches the same kernel.booted seq as this one:
  // without the nonce, its canaries would share these names on one VM, and
  // docker would refuse the second `docker run --name` (exit 125), a failure
  // read as the VM's, or one log's sweep would kill the other's canary.
  const shape = /^aos-run-canary-([0-9]+)-([0-9a-f]{12})-(trusted|hostile)$/
  const drivers = [driverWith(), driverWith()]
  const named = []
  for (const driver of drivers) {
    const { kernel } = await bootWith(t, driver)
    assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' })
    await kernel.shutdown()
    const names = canaryNames(driver)
    const [, seq, nonce] = shape.exec(names.trusted) ?? []
    // One nonce names both of a boot's canaries.
    assert.equal(names.hostile, canaryName(Number(seq), nonce ?? '', 'hostile'))
    named.push({ seq, nonce, names })
  }
  assert.equal(named[0]?.seq, named[1]?.seq, 'two fresh logs booted to different seqs')
  assert.notEqual(named[0]?.nonce, named[1]?.nonce)
  assert.notEqual(named[0]?.names.trusted, named[1]?.names.trusted)
  assert.notEqual(named[0]?.names.hostile, named[1]?.names.hostile)
  // canaryNonce itself: twelve hex digits, fresh at every call.
  const nonces = Array.from({ length: 64 }, () => canaryNonce())
  for (const nonce of nonces) assert.match(nonce, /^[0-9a-f]{12}$/)
  assert.equal(new Set(nonces).size, nonces.length)
})

test('a canary that reaches 192.168.5.2 degrades egress with egress.degraded naming the probe', async (t) => {
  for (const domain of ['trusted', 'hostile'] as const) {
    const driver = driverWith({ report: { [domain]: refusedReport('reached') } })
    const { kernel, fx } = await bootWith(t, driver)
    const name = canaryNames(driver)[domain]
    const why =
      `the ${domain} domain's canary (${name}) did not pass: its self-test report was refused: the self-test reached 1 of ` +
      `what it must not (192.168.5.2:8766). So no run is given egress: ${FIX_NETWORK}`
    // And its domain is closed to sandbox.exec (the test below holds what that refuses).
    assert.deepEqual(kernel.status().subsystems.sandbox, { state: 'degraded', reason: `fake: ${closes(domain, name, REACHED)}` }, domain)
    assert.deepEqual(kernel.status().subsystems.egress, { state: 'degraded', reason: why }, domain)
    assert.deepEqual(egressRows(fx.dbPath), [{ schemaVersion: 1, check: 'canary', domain, reason: why }], domain)
    const all = allRows(fx.dbPath)
    if (domain === 'trusted') {
      // Its ready refused: no go, so its request never crossed, the
      // container killed by name, and the grant revoked as a violation.
      assert.deepEqual(ofType(all, 'proxy.decision'), [], 'a request crossed a channel whose ready was refused')
      assert.deepEqual(driver.kills, [name])
      assert.deepEqual(ofType(all, 'proxy.grant.revoked').map((r) => [r.payload['reason'], r.payload['detail']]), [
        ['violation', "the mux's ready report was refused: the self-test reached 1 of what it must not (192.168.5.2:8766)"],
      ])
    } else {
      // The hostile domain gets no channel and no grant, whatever it reached.
      assert.deepEqual([ofType(all, 'proxy.grant.issued').length, ofType(all, 'proxy.decision').length], [1, 1], 'the trusted canary did not run as it should')
      assert.deepEqual(driver.channels.map((c) => c.name), [canaryNames(driver).trusted])
    }
  }
})

/** A model ref with a fresh probe record, as a run of the test fleet needs. */
const REAL_REF = 'anthropic/claude-sonnet-5'

/**
 * The shipped ceo and worker-template, and one tier 2 worker on each domain
 * whose manifest lists sandbox.exec and holds no egress: `boxer-trusted` and
 * `boxer-hostile`. A test-only agents dir (BootOptions.agentsDir): no
 * shipped manifest holds a sandbox tool.
 */
function boxFleet(t: TestContext): string {
  const dir = join(tmpdir(t), 'agents')
  const files: Record<string, string> = {}
  for (const domain of ['trusted', 'hostile'] as const) {
    files[`boxer-${domain}`] = [
      `id: boxer-${domain}`,
      'version: 1',
      'kind: standard',
      'role: worker',
      'soul: worker.md',
      'tier: 2',
      'model:',
      `  primary: ${REAL_REF}`,
      'tools:',
      '  allow: [sandbox.exec]',
      'sandbox:',
      `  domain: ${domain}`,
      'memory:',
      `  projectId: aos/agent/boxer-${domain}`,
      '',
    ].join('\n')
  }
  for (const shipped of ['ceo', 'worker-template']) {
    files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
  }
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, 'history'), { recursive: true })
    writeFileSync(join(dir, name, 'agent.yaml'), text)
    writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
  }
  return dir
}

const offeredNames = (body: unknown): string[] => ((body as { tools?: { name: string }[] } | undefined)?.tools ?? []).map((tool) => tool.name)

test('a canary whose self-test reached 192.168.5.2 on a domain leaves no exec runnable on that domain', async (t) => {
  // The canary is the only evidence of a domain's network the kernel has for
  // a run with no channel (every hostile run, and every trusted run with no
  // egress): one whose self-test report was refused closes its domain to
  // sandbox.exec, not only to egress. A sandbox.degraded row names the
  // domain; no run on it is offered the tool, a call of it is denied before
  // the gate asks anyone, and no container is started for it. The other
  // domain runs as before.
  for (const domain of ['trusted', 'hostile'] as const) {
    const other: SandboxDomain = domain === 'trusted' ? 'hostile' : 'trusted'
    const driver = driverWith({ report: { [domain]: refusedReport('reached') } }, { script: [{ stdout: 'v24\n', durationMs: 3 }] })
    const exec = () => anthropicToolUse({ name: 'sandbox__exec', input: { command: ['node', '--version'] } })
    const provider = fakeProvider([exec(), anthropicEndTurn({ text: 'refused' }), exec(), anthropicEndTurn({ text: 'ran' })])
    const { kernel, fx } = await withKernel(t, {
      kernelYaml: yaml(true),
      sandboxDriver: driver,
      agentsDir: boxFleet(t),
      env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-5e2a7c' },
      fetch: provider.fetch,
      beforeBoot: (f) => {
        writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
      },
    })
    const name = canaryNames(driver)[domain]
    const reason = closes(domain, name, REACHED)
    const refusal = `${reason}; no container was started`

    // Boot: the sandbox is degraded naming the domain, in a row of its own.
    assert.deepEqual(kernel.status().subsystems.sandbox, { state: 'degraded', reason: `fake: ${reason}` }, domain)
    assert.deepEqual(ofType(allRows(fx.dbPath), 'sandbox.degraded').map((r) => r.payload), [{ schemaVersion: 1, driver: 'fake', reason, closes: domain }], domain)
    assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${domain}`), refusal, domain)
    assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${other}`), undefined, domain)
    // Not the runner's to refuse for any other tool, nor for an agent it does not admit.
    assert.equal(kernel.sandboxTools.domainRefusal('sandbox.other', `boxer-${domain}`), undefined, domain)
    assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', 'ceo'), undefined, domain)

    // A run on the closed domain is shown no sandbox tool, so the call its
    // model makes anyway names no tool it holds: nothing is gated, no human
    // is asked, and no container starts. (A call that reaches the gate is
    // denied before it with this reason: test/sandbox-exec.test.ts.)
    const closedRun = await runThroughControl(kernel, 'which node?', `boxer-${domain}`)
    assert.equal(closedRun['status'], 'ok', String(closedRun['reason']))
    assert.deepEqual(offeredNames(provider.requests[0]?.body), [], domain)
    const gates = (runId: unknown) =>
      ofType(allRows(fx.dbPath), 'tool.gate')
        .filter((r) => r.runId === runId)
        .map((r) => [r.payload['toolRef'], r.payload['decision']])
    assert.deepEqual(gates(closedRun['runId']), [], domain)
    assert.deepEqual(driver.specs.filter((s) => !s.name.startsWith(CANARY_PREFIX)), [], `${domain}: a container was started on a closed domain`)
    assert.deepEqual(ofType(allRows(fx.dbPath), 'approval.requested'), [], domain)

    // A run on the other domain is offered the tool, and its exec runs there.
    const openRun = await runThroughControl(kernel, 'which node?', `boxer-${other}`)
    assert.equal(openRun['status'], 'ok', String(openRun['reason']))
    assert.deepEqual(offeredNames(provider.requests[2]?.body), ['sandbox__exec'], domain)
    assert.deepEqual(gates(openRun['runId']), [['sandbox.exec', 'allow']], domain)
    const ran = driver.specs.filter((s) => !s.name.startsWith(CANARY_PREFIX))
    assert.deepEqual(ran.map((s) => s.domain), [other], domain)
    await kernel.shutdown()
  }

  // A report that a probe reached something closes the domain however the
  // container then ended: a hostile mux that wrote it and exited 1.
  {
    const line = `${Buffer.from(refusedReport('reached')).toString('ascii')}\n`
    const driver = driverWith({ instead: { hostile: { exitCode: 1, stdout: line } } })
    const { kernel, fx } = await bootWith(t, driver)
    const reason = closes('hostile', canaryNames(driver).hostile, REACHED)
    assert.deepEqual(kernel.status().subsystems.sandbox, { state: 'degraded', reason: `fake: ${reason}` })
    assert.deepEqual(ofType(allRows(fx.dbPath), 'sandbox.degraded').map((r) => r.payload['reason']), [reason])
    await kernel.shutdown()
  }
  // A canary that failed for anything but its report closes nothing: no
  // evidence of a route, so the sandbox stays ok and only egress is degraded.
  {
    const driver = driverWith({ status: 1 })
    const { kernel, fx } = await bootWith(t, driver)
    assert.equal(kernel.status().subsystems.sandbox.state, 'ok')
    assert.equal(kernel.status().subsystems.egress.state, 'degraded')
    assert.deepEqual(ofType(allRows(fx.dbPath), 'sandbox.degraded'), [])
    await kernel.shutdown()
  }
})

/** Each `sandbox.degraded` row that closes a domain, as [domain, reason], in the log's order. */
const closureRows = (dbPath: string): [unknown, unknown][] =>
  ofType(allRows(dbPath), 'sandbox.degraded')
    .filter((r) => r.payload['closes'] !== undefined)
    .map((r) => [r.payload['closes'], r.payload['reason']])

test('a domain a canary closed stays closed across restarts until a boot whose canary there passes: egress disabled, a failed probe, a failed sweep and a canary that failed for anything else each keep it closed', async (t) => {
  // The canary is the only evidence of a domain's network for a run with no
  // channel, and a boot that runs none, or whose canary there failed for
  // anything but its report, has no new evidence: so the closure an earlier
  // boot's canary recorded stands, recorded again by each such boot, and
  // only a canary that passes on the domain reopens it. Each domain, on a
  // log of its own: a boot that kept only one of them closed is a domain
  // whose every run with no channel starts containers again.
  const agentsDir = boxFleet(t)
  for (const domain of ['trusted', 'hostile'] as const) {
    const other: SandboxDomain = domain === 'trusted' ? 'hostile' : 'trusted'
    const fx = fixture(t, { kernelYaml: yaml(true) })
    const disabled: KernelFixture = { ...fx, config: { ...fx.config, egress: { ...fx.config.egress, enabled: false } } }

    // Boot 1: the domain's canary reached 192.168.5.2, which closes it.
    const first = driverWith({ report: { [domain]: refusedReport('reached') } })
    const one = await bootOn(t, fx, { sandboxDriver: first, agentsDir })
    const reason = closes(domain, canaryNames(first)[domain], REACHED)
    const refusal = `${reason}; no container was started`
    assert.equal(one.sandboxTools.domainRefusal('sandbox.exec', `boxer-${domain}`), refusal, domain)
    assert.equal(one.sandboxTools.domainRefusal('sandbox.exec', `boxer-${other}`), undefined, domain)
    await one.shutdown()
    assert.deepEqual(closureRows(fx.dbPath), [[domain, reason]], domain)

    /**
     * A boot that keeps the domain closed, as the first one left it, and the
     * other one open: one closure row of its own (the count grows by exactly
     * one, so a boot that held the domain closed in memory and wrote no row,
     * which the next boot would read as open, is caught), naming the first
     * canary's reason.
     */
    const keeps = async (label: string, boot: () => Promise<Kernel>): Promise<void> => {
      const at = `${domain}, ${label}`
      const before = closureRows(fx.dbPath).length
      const kernel = await boot()
      const after = closureRows(fx.dbPath)
      assert.equal(after.length, before + 1, `${at}: no closure row of its own`)
      assert.deepEqual(after.at(-1), [domain, reason], `${at}: its closure row is not the closing canary's`)
      assert.equal(kernel.status().subsystems.sandbox.state, 'degraded', at)
      assert.ok((kernel.status().subsystems.sandbox.reason ?? '').includes(reason), `${at}: ${kernel.status().subsystems.sandbox.reason ?? ''}`)
      assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${domain}`), refusal, at)
      assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${other}`), undefined, at)
      await kernel.shutdown()
    }

    // Boot 2: egress disabled (the shipped default), so no canary runs.
    {
      const driver = driverWith()
      await keeps('egress disabled', () => bootOn(t, disabled, { sandboxDriver: driver, agentsDir }))
      assert.deepEqual(driver.specs, [], `${domain}: a canary ran with egress disabled`)
    }
    // Boot 3: a probe that failed (no daemon answers), so no canary runs.
    {
      const driver = fakeSandbox({ imageId: IMAGE, play: canaryPlayer() })
      await keeps('a failed probe', () => bootOn(t, fx, { sandboxDriver: driver, agentsDir }))
      assert.deepEqual(driver.specs, [], domain)
    }
    // Boot 4: a sweep that did not finish (a VM it could not list), so no canary runs.
    {
      seedRunlessCanaries(t, fx, [`aos-run-canary-2-0000000000aa-${domain}`])
      const driver = driverWith({}, { sweepUnlisted: [domain] })
      await keeps('a failed sweep', () => bootOn(t, fx, { sandboxDriver: driver, agentsDir }))
      assert.deepEqual(driver.specs, [], domain)
    }
    // Boot 5: the domain's canary never ends, a failure that is no evidence
    // either way; the other one passes, and its domain stays open.
    {
      const driver = driverWith({ instead: { [domain]: 'hang' } })
      await keeps('a canary that never ended', async () => {
        const kernel = await bootOn(t, fx, { sandboxDriver: driver, agentsDir, canaryWaitMs: 200 })
        assert.deepEqual(driver.specs.map((s) => s.domain).sort(), ['hostile', 'trusted'], domain)
        assert.deepEqual(egressRows(fx.dbPath).at(-1)?.['domain'], domain)
        return kernel
      })
    }
    // Boot 5b: egress disabled once more, after the boot whose canary there
    // failed for anything else. It reads the closure from that boot's rows,
    // so a boot 5 that kept the domain closed only in memory would have it
    // reopened here, with no canary of any boot having passed there.
    {
      const driver = driverWith()
      await keeps('egress disabled after a canary that failed for anything else', () => bootOn(t, disabled, { sandboxDriver: driver, agentsDir }))
      assert.deepEqual(driver.specs, [], domain)
    }
    // Boot 5c: the domain's canary is refused again, for another reason (its
    // probe of 192.168.5.2:8766 timed out): the closure is this boot's, naming
    // its own canary and its code, not the first canary's.
    {
      const driver = driverWith({ report: { [domain]: refusedReport('timed out') } })
      const before = closureRows(fx.dbPath).length
      const kernel = await bootOn(t, fx, { sandboxDriver: driver, agentsDir })
      const again = closes(domain, canaryNames(driver)[domain], "the self-test's probe of 192.168.5.2:8766 met ETIMEDOUT, which does not say there is no route")
      assert.notEqual(again, reason)
      const after = closureRows(fx.dbPath)
      assert.equal(after.length, before + 1, domain)
      assert.deepEqual(after.at(-1), [domain, again], `${domain}: the closure kept the earlier canary's reason`)
      assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${domain}`), `${again}; no container was started`, domain)
      assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${other}`), undefined, domain)
      await kernel.shutdown()
    }
    // Boot 6: both canaries pass, which reopens the domain: no closure
    // row, the sandbox ok, and an exec there runs again.
    {
      const before = closureRows(fx.dbPath).length
      const driver = driverWith()
      const kernel = await bootOn(t, fx, { sandboxDriver: driver, agentsDir })
      assert.equal(closureRows(fx.dbPath).length, before, `${domain}: a domain whose canary passed was recorded closed`)
      assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' }, domain)
      assert.equal(kernel.status().subsystems.sandbox.state, 'ok', kernel.status().subsystems.sandbox.reason ?? '')
      assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${domain}`), undefined, domain)
      await kernel.shutdown()
    }
    // Boot 7: egress disabled again, and nothing is closed to keep.
    {
      const before = closureRows(fx.dbPath).length
      const kernel = await bootOn(t, disabled, { sandboxDriver: driverWith(), agentsDir })
      assert.equal(closureRows(fx.dbPath).length, before, domain)
      assert.equal(kernel.sandboxTools.domainRefusal('sandbox.exec', `boxer-${domain}`), undefined, domain)
      assert.equal(kernel.status().subsystems.sandbox.state, 'ok', kernel.status().subsystems.sandbox.reason ?? '')
      await kernel.shutdown()
    }
  }
})

test('closedSandboxDomains reads the set the last boot that marked its sandbox recorded, and a boot that ended before its mark only adds to it', (t) => {
  const store = withStore(t)
  // As a boot writes them: kernel.booted, then the subsystems marked before
  // the sandbox's (events first), none of which is the sandbox's mark.
  const boot = (): void => {
    store.append({ type: 'kernel.booted', payload: { schemaVersion: 1, version: 'test', configHash: 'h', degraded: [] } })
    store.append({ type: 'subsystem.state', payload: { schemaVersion: 1, subsystem: 'events', state: 'ok' } })
  }
  const close = (domain: SandboxDomain, reason: string): void => {
    store.append({ type: 'sandbox.degraded', payload: { schemaVersion: 1, driver: 'fake', reason, closes: domain } })
  }
  const markSandbox = (state: 'ok' | 'degraded'): void => {
    store.append({ type: 'subsystem.state', payload: { schemaVersion: 1, subsystem: 'sandbox', state } })
  }
  const closed = () => closedSandboxDomains(readAllRows(store.db))
  assert.deepEqual(closed(), {})
  // A boot that closed the hostile domain, and marked its sandbox.
  boot()
  close('hostile', 'hostile: reached')
  // A sandbox.degraded row that closes nothing (a probe's) is no closure.
  store.append({ type: 'sandbox.degraded', payload: { schemaVersion: 1, driver: 'fake', reason: 'hostile: docker image inspect failed' } })
  markSandbox('degraded')
  // Another subsystem's mark is not the sandbox's.
  store.append({ type: 'subsystem.state', payload: { schemaVersion: 1, subsystem: 'egress', state: 'ok' } })
  assert.deepEqual(closed(), { hostile: 'hostile: reached' })
  // A boot that closed the trusted domain and died before its mark: it
  // reopened nothing, so both are closed.
  boot()
  close('trusted', 'trusted: timed out')
  assert.deepEqual(closed(), { trusted: 'trusted: timed out', hostile: 'hostile: reached' })
  // A boot that kept the hostile domain closed, and marked: the trusted
  // closure, which it did not record, it reopened.
  boot()
  close('hostile', 'hostile: reached')
  markSandbox('degraded')
  assert.deepEqual(closed(), { hostile: 'hostile: reached' })
  // A boot that recorded none and marked: nothing is closed.
  boot()
  markSandbox('ok')
  assert.deepEqual(closed(), {})
  // A boot that has not yet marked (the one reading the log) changes nothing.
  boot()
  assert.deepEqual(closed(), {})
  // A closure names one of the two domains, or the log refuses the row.
  assert.throws(() => store.append({ type: 'sandbox.degraded', payload: { schemaVersion: 1, driver: 'fake', reason: 'r', closes: 'mac' } }))
})

test('a canary whose probe timed out degrades egress, naming the probe and the code', async (t) => {
  // The minimal judge's list (test/egress-mux.test.ts, through
  // REFUSED_PROBE_ERRORS): ETIMEDOUT, EHOSTUNREACH and EOTHER above all, an
  // address met by a lookup's code, a lookup met by a connect's or by none.
  assert.ok(REFUSED_PROBE_ERRORS.some((e) => e.kind === 'address' && e.error === 'ETIMEDOUT'))
  for (const domain of ['trusted', 'hostile'] as const) {
    for (const { kind, error } of REFUSED_PROBE_ERRORS) {
      const { report, target } = reportWith(kind, error)
      const driver = driverWith({ report: { [domain]: report } })
      const { kernel, fx } = await bootWith(t, driver)
      const label = `${domain} ${target} ${String(error)}`
      const name = canaryNames(driver)[domain]
      const met = error ?? 'no error'
      const why =
        `the ${domain} domain's canary (${name}) did not pass: its self-test report was refused: the self-test's probe ` +
        `of ${target} met ${met}, which does not say there is no route. So no run is given egress: ${FIX_NETWORK}`
      assert.deepEqual(egressRows(fx.dbPath), [{ schemaVersion: 1, check: 'canary', domain, reason: why }], label)
      assert.deepEqual(kernel.status().subsystems.egress, { state: 'degraded', reason: why }, label)
      if (domain === 'trusted') assert.deepEqual(ofType(allRows(fx.dbPath), 'proxy.decision'), [], label)
      await kernel.shutdown()
    }
  }
  // The probe named is the kernel's own target for the probe of that kind.
  assert.equal(reportWith('address', 'ETIMEDOUT').target, '192.168.5.2:8766')
  assert.equal(reportWith('name', 'ETIMEDOUT').target, probeTarget(SELF_TEST.find((p) => probeKind(p) === 'name') ?? SELF_TEST[0]!))
})

test("a mountRoot whose canary workspace cannot be made degrades egress on each domain sharing it, naming each canary, and never refuses the boot", async (t) => {
  // <mountRoot>/aos_canary is made by makeWorkspace, which refuses one that
  // is there and is no directory of its own (and a mountRoot that does not
  // exist). That is a canary that could not run, as any other failure to
  // start one is: egress degraded, check `canary`, naming the domain; never
  // the whole boot refused for a share the operator can fix. The fixture's
  // two domains share one mountRoot, so both canaries fail so.
  const driver = driverWith()
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: yaml(true),
    sandboxDriver: driver,
    beforeBoot: (f) => {
      writeFileSync(join(f.config.sandbox.domains.trusted.mountRoot, CANARY_WORKSPACE), 'no directory\n')
    },
  })
  assert.equal(fx.config.sandbox.domains.trusted.mountRoot, fx.config.sandbox.domains.hostile.mountRoot)
  assert.equal(kernel.status().subsystems.egress.state, 'degraded')
  const rows = egressRows(fx.dbPath)
  assert.deepEqual(rows.map((r) => [r['check'], r['domain']]), [
    ['canary', 'trusted'],
    ['canary', 'hostile'],
  ])
  for (const row of rows) {
    const domain = String(row['domain'])
    assert.match(String(row['reason']), new RegExp(`^the ${domain} domain's canary \\(aos-run-canary-[0-9]+-[0-9a-f]{12}-${domain}\\) did not pass: its workspace could not be made \\(`), domain)
    assert.match(String(row['reason']), /is there and is no directory of its own\)\. So no run is given egress: check the domain's mountRoot/, domain)
  }
  // No canary container was started, and neither domain is closed: a
  // workspace that could not be made is no evidence of a route.
  assert.deepEqual(driver.specs, [])
  assert.deepEqual(closureRows(fx.dbPath), [])
  assert.equal(kernel.status().subsystems.sandbox.state, 'ok', kernel.status().subsystems.sandbox.reason ?? '')
})

test('an image id mismatch on either domain degrades sandbox and egress', async (t) => {
  for (const domain of ['trusted', 'hostile'] as const) {
    for (const printed of [OTHER, '', 'aos-worker:test']) {
      const label = `${domain} printed ${JSON.stringify(printed)}`
      const driver = driverWith({}, { vmImageIds: { [domain]: printed } })
      const { kernel, fx } = await bootWith(t, driver)
      const what = printed === OTHER ? `the id ${OTHER}` : printed === '' ? 'no id' : 'something that is no image id'
      const probeWhy =
        `${domain}: docker image inspect ${IMAGE} printed ${what} on this domain's VM, not the pinned sandbox.imageId: ` +
        'pin the id `docker image inspect --format {{.Id}}` prints for the worker image, the same on both VMs'
      assert.deepEqual(kernel.status().subsystems.sandbox, { state: 'degraded', reason: `fake: ${probeWhy}` }, label)
      const why =
        `sandbox.imageId could not be confirmed on the ${domain} domain's VM by that id (fake: ${probeWhy}), so neither a ` +
        "run's container nor a canary can run there: do as that says, then restart the kernel"
      assert.deepEqual(egressRows(fx.dbPath), [{ schemaVersion: 1, check: 'image', domain, reason: why }], label)
      assert.deepEqual(kernel.status().subsystems.egress, { state: 'degraded', reason: why }, label)
      assert.ok(kernel.degraded.includes('sandbox') && kernel.degraded.includes('egress'), label)
      // No canary ran on a sandbox the probe failed.
      assert.deepEqual(driver.specs, [], label)
      await kernel.shutdown()
    }
  }
  // An inspect that failed (a daemon gone between the probe's calls): the
  // image could not be checked, which the row says, in the probe's words, not
  // that the VM lacks it.
  {
    const said =
      `hostile: the pinned sandbox.imageId ${IMAGE} could not be inspected on this domain's VM, so every run there would ` +
      'fail at docker, which is told never to pull it: Cannot connect to the Docker daemon. Load the worker image into ' +
      'this VM (docker save on the VM that built it, docker load on this one), so that both VMs hold it under the one pinned id'
    const driver = fakeSandbox({ imageId: IMAGE, probe: { ok: false, why: said, imageOn: 'hostile' }, play: canaryPlayer() })
    const { kernel, fx } = await bootWith(t, driver)
    assert.deepEqual(egressRows(fx.dbPath), [
      {
        schemaVersion: 1,
        check: 'image',
        domain: 'hostile',
        reason:
          `sandbox.imageId could not be confirmed on the hostile domain's VM by that id (fake: ${said}), so neither a run's ` +
          'container nor a canary can run there: do as that says, then restart the kernel',
      },
    ])
    await kernel.shutdown()
  }
  // Both VMs wrong: the probe stops at the first, trusted, as the real one does.
  {
    const driver = driverWith({}, { vmImageIds: { trusted: OTHER, hostile: OTHER } })
    const { kernel, fx } = await bootWith(t, driver)
    assert.deepEqual(egressRows(fx.dbPath).map((r) => [r['check'], r['domain']]), [['image', 'trusted']])
    await kernel.shutdown()
  }
  // The image's failure does not hide the sweep's: each is a row of its own.
  {
    const fx = fixture(t, { kernelYaml: yaml() })
    seedRunlessCanaries(t, fx, ['aos-run-canary-1-000000000000-trusted'])
    const driver = driverWith({}, { vmImageIds: { hostile: OTHER }, sweepUnlisted: ['trusted'] })
    const kernel = await bootOn(t, fx, { sandboxDriver: driver })
    assert.deepEqual(egressRows(fx.dbPath).map((r) => [r['check'], r['domain']]), [
      ['image', 'hostile'],
      ['sandbox', undefined],
    ])
    assert.match(String(egressRows(fx.dbPath)[1]?.['reason']), /^the sandbox is degraded \(fake: the orphan sweep did not finish: the trusted VM could not be listed/)
    await kernel.shutdown()
  }
})

// ── what else the canary holds ───────────────────────────────────────────────

test('a canary runs only while egress is enabled and the sandbox is ok', async (t) => {
  // Disabled: the key is named, and no container is run for it.
  {
    const driver = driverWith()
    const { kernel, fx } = await bootWith(t, driver, { enabled: false })
    assert.deepEqual(egressRows(fx.dbPath).map((r) => r['check']), ['config'])
    assert.deepEqual(driver.specs, [])
    await kernel.shutdown()
  }
  // A runtime that does not answer: the sandbox is named, and nothing is run.
  {
    const driver = fakeSandbox({ imageId: IMAGE, play: canaryPlayer() })
    const { kernel, fx } = await bootWith(t, driver)
    assert.deepEqual(egressRows(fx.dbPath).map((r) => r['check']), ['sandbox'])
    assert.deepEqual(driver.specs, [])
    await kernel.shutdown()
  }
  // A binding that did not resolve does not keep the canaries from running:
  // their verdict is the network's, whatever the credential says.
  {
    const driver = driverWith({ report: { hostile: refusedReport('timed out') } })
    const { kernel, fx } = await withKernel(t, {
      kernelYaml: (base) =>
        `${yaml(true)(base)}  bindings:\n    gh:\n      host: github.com\n      scheme: Basic\n      envVar: AOS_GITHUB_TOKEN\n      profiles: [git-fetch]\n      repos: [op/fixture]\n`,
      sandboxDriver: driver,
    })
    assert.deepEqual(egressRows(fx.dbPath).map((r) => [r['check'], r['domain'] ?? r['bindingId']]), [
      ['binding', 'gh'],
      ['canary', 'hostile'],
    ])
    assert.equal(driver.specs.length, 2)
    await kernel.shutdown()
  }
})

test("the trusted canary's round trip must end in the kernel's deny: an answer it did not read as a 403, a mux that predates --canary, and one that never ends each degrade egress, naming the domain and the fix", async (t) => {
  const failed = async (play: CanaryPlay, domain: 'trusted' | 'hostile', canaryWaitMs?: number) => {
    const driver = driverWith(play)
    const { kernel, fx } = await bootWith(t, driver, canaryWaitMs === undefined ? {} : { canaryWaitMs })
    const rows = egressRows(fx.dbPath)
    assert.deepEqual(rows.map((r) => [r['check'], r['domain']]), [['canary', domain]])
    const name = canaryNames(driver)[domain]
    const reason = String(rows[0]?.['reason'])
    assert.ok(reason.startsWith(`the ${domain} domain's canary (${name}) did not pass: `), reason)
    await kernel.shutdown()
    return { reason, driver, all: allRows(fx.dbPath), name }
  }
  const REBUILD = /So no run is given egress: rebuild the worker image \(scripts\/build-worker-image\.sh\), so its mux has --canary and --self-test, pin the id it prints as sandbox\.imageId, and restart the kernel$/

  // The mux read something other than the kernel's 403: its exit frame says 1.
  {
    const { reason, all } = await failed({ status: 1 }, 'trusted')
    assert.match(reason, /: its mux read no 403 for its request \(status 1\)\. /)
    assert.match(reason, REBUILD)
    assert.equal(ofType(all, 'proxy.decision').length, 1, 'the request was not judged')
  }
  // A mux that sent no request at all and says 0: no round trip crossed the
  // channel, so the channel was shown to carry nothing.
  {
    const { reason, all } = await failed({ request: false }, 'trusted')
    assert.match(reason, /: its one request was not judged and denied over the channel \(requests 0, denied 0, allowed 0\)\. /)
    assert.match(reason, REBUILD)
    assert.equal(ofType(all, 'proxy.decision').length, 0)
  }
  // An image whose mux has no --canary: usage, exit 64, no ready at all.
  {
    const { reason, all } = await failed({ instead: { trusted: { exitCode: 64, stderr: 'usage: ... -- <command> [args...]\n' } } }, 'trusted')
    assert.match(reason, /: its mux exited 64 with no ready report, as one that does not know --canary does\. /)
    assert.match(reason, REBUILD)
    assert.equal(ofType(all, 'proxy.grant.revoked').length, 1, 'the grant was left open')
  }
  {
    const { reason } = await failed({ instead: { hostile: { exitCode: 64, stderr: 'usage\n' } } }, 'hostile')
    assert.match(reason, /: its mux exited 64, as one that does not know --self-test does\. /)
    assert.match(reason, REBUILD)
  }
  // A hostile canary whose line passes but whose mux did not exit 0.
  {
    const { reason } = await failed({ instead: { hostile: { exitCode: 1, stdout: `${Buffer.from(quietReport()).toString('ascii')}\n` } } }, 'hostile')
    assert.match(reason, /: its mux exited 1\. So no run is given egress: check that the VM answers/)
  }
  // A hostile canary that wrote no report line, or more than one.
  for (const stdout of ['', `${Buffer.from(quietReport()).toString('ascii')}`, `${Buffer.from(quietReport()).toString('ascii')}\nmore\n`]) {
    const { reason } = await failed({ instead: { hostile: { stdout } } }, 'hostile')
    assert.match(reason, /: its mux wrote no single self-test report line\. /, JSON.stringify(stdout))
  }
  // One that never ends is given up at boot's bound: its CLI ended and its
  // container killed by name (abandon), its end an error, its grant revoked.
  {
    const { reason, driver, all, name } = await failed({ instead: { trusted: 'hang' } }, 'trusted', 300)
    assert.match(reason, /: it did not end within 300 ms, so its container was given up and killed by name\. So no run is given egress: check that the VM answers \(scripts\/colima-up\.sh\), then restart the kernel$/)
    assert.deepEqual(driver.abandons, [name])
    assert.deepEqual(ofType(all, 'sandbox.killed').filter((r) => r.payload['sandboxId'] === name).map((r) => r.payload['reason']), ['error'])
    assert.deepEqual(ofType(all, 'proxy.grant.revoked').map((r) => [r.payload['reason'], r.payload['detail']]), [
      ['error', 'the canary did not end within 300 ms, and was given up'],
    ])
  }
})

// ── a canary's every way of failing (src/runtime/canary.ts runCanary) ─────────

/** `base`, whose run() of a canary's spec is `run`'s; every other call is the base's. */
function overRun(base: FakeSandbox, run: (spec: SandboxSpec) => RunningSandbox): SandboxDriver {
  return {
    name: base.name,
    probe: (signal) => base.probe(signal),
    run: (spec) => (spec.name.startsWith(CANARY_PREFIX) ? run(spec) : base.run(spec)),
    kill: (name) => base.kill(name),
    abandon: (name) => base.abandon(name),
    commandRefusal: (command) => base.commandRefusal(command),
    everyRunRefusal: () => base.everyRunRefusal(),
    sweepOrphans: (request) => base.sweepOrphans(request),
  }
}

/**
 * One domain's canary run on its own (runCanary), as boot runs it, over
 * `driver`, into a store `wrap` may make refuse rows: its verdict, and the
 * rows the store took.
 */
async function canaryOn(
  t: TestContext,
  domain: SandboxDomain,
  driver: SandboxDriver,
  over: {
    readonly wrap?: (store: EventStore) => CanaryOptions['store']
    readonly waitMs?: number
    readonly wallclockMs?: number
    readonly egressLimits?: CanaryOptions['egressLimits']
    readonly name?: string
  } = {},
) {
  const store = withStore(t)
  const name = over.name ?? canaryName(5, '0000000000cd', domain)
  const verdict = await runCanary({
    driver,
    store: over.wrap?.(store) ?? store,
    domain,
    name,
    imageId: IMAGE,
    workspace: tmpdir(t),
    limits: { memoryMb: 512, cpus: 1, pids: 64, wallclockMs: over.wallclockMs ?? 600_000 },
    egressLimits: over.egressLimits ?? fixture(t, { kernelYaml: yaml() }).config.egress.limits,
    acceptReady,
    waitMs: over.waitMs ?? 2_000,
  })
  const rows = store.query().map((r) => ({ type: r.type, runId: r.runId, payload: JSON.parse(r.payload) as Record<string, unknown> }))
  return { verdict, rows, name }
}

/** A store that refuses every row of `type` (and takes the rest), as a log that cannot record one does. */
const refusing =
  (type: string) =>
  (store: EventStore): CanaryOptions['store'] => ({
    append: (input) => {
      if (input.type === type) throw new Error(`test: the log refuses ${type}`)
      return store.append(input)
    },
  })

const revocations = (rows: readonly { type: string; payload: Record<string, unknown> }[]) =>
  rows.filter((r) => r.type === 'proxy.grant.revoked').map((r) => [r.payload['reason'], r.payload['detail']])

test("a canary the driver refuses, gives no channel or loses fails, its container killed by name and the trusted one's grant revoked, never left open", async (t) => {
  // The driver refuses the spec before anything started: nothing to record
  // but the grant, which served nothing.
  for (const domain of ['trusted', 'hostile'] as const) {
    const base = driverWith()
    const driver = overRun(base, () => {
      throw new Error('test: the daemon refused the spec')
    })
    const { verdict, rows, name } = await canaryOn(t, domain, driver)
    assert.equal(verdict.ok, false, domain)
    assert.match(verdict.ok ? '' : verdict.why, new RegExp(`^the ${domain} domain's canary \\(${name}\\) did not pass: the driver refused it: test: the daemon refused the spec\\. So no run is given egress: check that the VM answers`), domain)
    assert.equal(verdict.ok || verdict.closes === undefined, true, `${domain}: a refused spec closes the domain`)
    assert.deepEqual(rows.filter((r) => r.type.startsWith('sandbox.')), [], domain)
    assert.deepEqual(revocations(rows), domain === 'trusted' ? [['error', 'the driver refused the canary before it started']] : [], domain)
    assert.deepEqual(rows.filter((r) => r.type === 'proxy.grant.issued').length, domain === 'trusted' ? 1 : 0, domain)
  }

  // A trusted canary the driver gave no channel: killed by name at once,
  // its grant revoked unserved, its end recorded.
  {
    const base = driverWith()
    const driver = overRun(base, (spec) => {
      const running = base.run(spec)
      return { name: running.name, result: running.result }
    })
    const { verdict, rows, name } = await canaryOn(t, 'trusted', driver)
    assert.deepEqual(verdict, {
      ok: false,
      why: `the trusted domain's canary (${name}) did not pass: the driver gave the canary no channel. So no run is given egress: check that the VM answers (scripts/colima-up.sh), then restart the kernel`,
    })
    assert.deepEqual(base.kills, [name], 'a canary with no channel was left to its wallclock')
    assert.deepEqual(revocations(rows), [['error', 'the driver gave the canary no channel']])
    assert.deepEqual(rows.filter((r) => r.type === 'sandbox.killed').map((r) => r.payload['reason']), ['requested'])
  }

  // A result that rejects says nothing of the container: killed by name,
  // its end an error, the trusted one's session ended and its grant revoked.
  for (const domain of ['trusted', 'hostile'] as const) {
    const base = driverWith({ instead: { [domain]: 'hang' } })
    const driver = overRun(base, (spec) => {
      const running = base.run(spec)
      return { ...running, result: Promise.reject(new Error('test: the result was lost')) }
    })
    const { verdict, rows, name } = await canaryOn(t, domain, driver)
    assert.match(verdict.ok ? '' : verdict.why, new RegExp(`did not pass: the driver lost the canary: test: the result was lost, so its container was killed by name\\. So no run`), domain)
    assert.deepEqual(base.kills, [name], domain)
    assert.deepEqual(rows.filter((r) => r.type === 'sandbox.killed').map((r) => r.payload), [{ schemaVersion: 1, sandboxId: name, reason: 'error' }], domain)
    assert.deepEqual(revocations(rows).map(([reason]) => reason), domain === 'trusted' ? ['error'] : [], domain)
  }
})

test("a trusted canary no session served has its grant revoked unserved, with a detail the row holds, whether its result settles, never does or is lost", async (t) => {
  // The driver gave it no channel, or its egress session would not start
  // (here: limits the session's schema refuses, whose error message runs past
  // the revoked row's bound). Killed by name at once either way; and when its
  // result then never settles (a paused VM), boot gives it up at its wait, or
  // when the driver loses it, kills it by name again, and either way still
  // revokes the grant, so none is left open for the next boot to find.
  const limits = fixture(t, { kernelYaml: yaml() }).config.egress.limits
  const refusedLimits = { ...limits, frameMaxBytes: 0, maxFlows: 0, maxHeaderBytes: 0, maxRequests: 0, maxBytes: 0, maxDenied: 0, idleMs: 0 }
  const NO_CHANNEL = 'the driver gave the canary no channel'
  const WOULD_NOT_START = 'the egress session would not start: '
  const waitMs = 200
  for (const unserved of ['no channel', 'session'] as const) {
    for (const ends of ['settles', 'never settles', 'is lost'] as const) {
      const label = `${unserved}, ${ends}`
      const base = driverWith()
      const driver = overRun(base, (spec) => {
        const running = base.run(spec)
        const result =
          ends === 'settles'
            ? running.result
            : ends === 'never settles'
              ? new Promise<never>(() => undefined)
              : Promise.reject(new Error('test: the result was lost'))
        return unserved === 'no channel' ? { name: running.name, result } : { ...running, result }
      })
      const { verdict, rows, name } = await canaryOn(t, 'trusted', driver, {
        waitMs,
        ...(unserved === 'session' ? { egressLimits: refusedLimits } : {}),
      })
      // Killed by name at once, and once more when its result was lost.
      assert.deepEqual(base.kills, ends === 'is lost' ? [name, name] : [name], `${label}: the canary no session served was not killed by name at once`)
      assert.deepEqual(base.abandons, ends === 'never settles' ? [name] : [], label)
      assert.deepEqual(rows.filter((r) => r.type === 'proxy.grant.issued').length, 1, label)
      const revoked = revocations(rows)
      assert.equal(revoked.length, 1, `${label}: the grant was left open`)
      const [reason, detail] = revoked[0] ?? []
      assert.equal(reason, 'error', label)
      if (unserved === 'no channel') {
        assert.equal(detail, NO_CHANNEL, label)
      } else {
        // The session's refusal, quoted and cut at the row's bound.
        assert.ok(String(detail).startsWith(WOULD_NOT_START), `${label}: ${String(detail)}`)
        assert.ok(String(detail).endsWith('…'), `${label}: the detail was not cut, so it does not show the bound`)
        assert.ok(Buffer.byteLength(String(detail)) <= EGRESS_DETAIL_BYTES, label)
      }
      assert.deepEqual(rows.filter((r) => r.type === 'sandbox.killed').map((r) => r.payload['reason']), [ends === 'settles' ? 'requested' : 'error'], label)
      assert.equal(verdict.ok, false, label)
      const why = verdict.ok ? '' : verdict.why
      assert.ok(why.startsWith(`the trusted domain's canary (${name}) did not pass: `), `${label}: ${why}`)
      const said = {
        settles: unserved === 'no channel' ? NO_CHANNEL : WOULD_NOT_START,
        'never settles': `it did not end within ${String(waitMs)} ms, so its container was given up and killed by name`,
        'is lost': 'the driver lost the canary: test: the result was lost, so its container was killed by name',
      }[ends]
      assert.ok(why.includes(said), `${label}: ${why}`)
      assert.equal(verdict.ok || verdict.closes === undefined, true, `${label}: a canary no session served closes its domain`)
    }
  }
})

test('a canary whose docker client exits 125 or with no status is killed by name, and fails', async (t) => {
  // mayRunOn: a client that says nothing of its container may leave it
  // running, so it is killed by name, as an exec's is.
  const exits = [
    { exitCode: DOCKER_CLI_FAILED, stderr: 'docker: error during connect\n' },
    { exitCode: null, signal: 'SIGKILL' as const },
  ]
  for (const domain of ['trusted', 'hostile'] as const) {
    for (const exit of exits) {
      const label = `${domain} ${String(exit.exitCode)}`
      const base = driverWith({ instead: { [domain]: exit } })
      const { verdict, rows, name } = await canaryOn(t, domain, base)
      assert.equal(verdict.ok, false, label)
      assert.match(verdict.ok ? '' : verdict.why, /its docker client ended with no word of its container/, label)
      assert.deepEqual(base.kills, [name], `${label}: the container was not killed by name`)
      const killed = rows.filter((r) => r.type === 'sandbox.killed').map((r) => r.payload['exitCode'])
      assert.deepEqual(killed, [exit.exitCode ?? undefined], label)
      if (domain === 'trusted') assert.equal(revocations(rows).length, 1, label)
    }
  }
})

test("a trusted canary whose session revokes its grant, for a limit or for a frame the channel refuses, fails naming the revocation and its detail, and a rebuilt image as its fix", async (t) => {
  // The mux broke its bounds or the protocol: its ready passed, so this is
  // no evidence of a route, but egress is not served, and the reason keeps
  // what the session saw it do.
  const FIX = 'So no run is given egress: rebuild the worker image (scripts/build-worker-image.sh), so its mux has --canary and --self-test, pin the id it prints as sandbox.imageId, and restart the kernel'
  const limits = fixture(t, { kernelYaml: yaml() }).config.egress.limits
  // A second flow past maxRequests 1, once its one request was answered.
  {
    const base = driverWith({ extra: 'flow' })
    const { verdict, rows, name } = await canaryOn(t, 'trusted', base, { egressLimits: { ...limits, maxRequests: 1 } })
    const detail = 'the worker opened more than maxRequests 1 flows, one request each'
    assert.deepEqual(revocations(rows), [['limit', detail]])
    assert.deepEqual(verdict, {
      ok: false,
      why: `the trusted domain's canary (${name}) did not pass: the egress session revoked its grant (limit maxRequests: ${detail}). ${FIX}`,
    })
    assert.deepEqual(base.kills, [name], 'the container was not killed by name')
  }
  // A second ready report once go has come: a frame the channel refuses.
  {
    const base = driverWith({ extra: 'frame' })
    const { verdict, rows, name } = await canaryOn(t, 'trusted', base)
    const revoked = revocations(rows)
    assert.equal(revoked.length, 1)
    const [reason, detail] = revoked[0] ?? []
    assert.equal(reason, 'violation')
    assert.match(String(detail), /ready-twice/)
    assert.deepEqual(verdict, {
      ok: false,
      why: `the trusted domain's canary (${name}) did not pass: the egress session revoked its grant (violation: ${String(detail)}). ${FIX}`,
    })
    assert.deepEqual(rows.filter((r) => r.type === 'proxy.decision'), [], 'a request crossed after the violation')
    assert.deepEqual(base.kills, [name])
  }
})

test('runCanary refuses a name that is no canary name, or one the log would not record as it is, before anything is issued, run or recorded', async (t) => {
  // Boot hands it canaryName's output; a run's container name, or one the
  // redaction pass would change (so no row could name the container the
  // sweep must kill), is a caller's mistake, refused outright.
  for (const [domain, name] of [
    ['trusted', 'aos-run-run_1700000000000_x-1'],
    ['hostile', 'aos-run-canar-1-0000000000cd-hostile'],
    ['trusted', `${CANARY_PREFIX}1-AKIAIOSFODNN7EXAMPLE-trusted`],
  ] as const) {
    const base = driverWith()
    const { verdict, rows } = await canaryOn(t, domain, base, { name })
    // The verdict's reason is bounded and redacted as its row will be: a
    // name the pass changes is shown as the pass leaves it.
    const shown = redactString(name)
    assert.equal(shown === name, !name.includes('AKIA'), name)
    assert.deepEqual(
      verdict,
      {
        ok: false,
        why:
          `the ${domain} domain's canary (${shown}) did not pass: its name is not a canary name the log records as it is. ` +
          'So no run is given egress: check that the VM answers (scripts/colima-up.sh), then restart the kernel',
      },
      name,
    )
    assert.deepEqual([base.specs, base.kills, rows], [[], [], []], `${name}: something was run, killed or recorded`)
  }
})

test("a canary whose row the log refuses fails once its container has ended, whatever its own verdict, and a report that closed its domain still closes it", async (t) => {
  // sandbox.started refused: the container is killed by name and the
  // canary fails with the log's refusal.
  for (const domain of ['trusted', 'hostile'] as const) {
    const base = driverWith()
    const { verdict, name } = await canaryOn(t, domain, base, { wrap: refusing('sandbox.started') })
    assert.match(verdict.ok ? '' : verdict.why, new RegExp(`^the ${domain} domain's canary \\(${name}\\) did not pass: the log refused its sandbox\\.started row \\(test: the log refuses sandbox\\.started\\)\\. `), domain)
    assert.ok(base.kills.includes(name), `${domain}: a container the log could not record was left running`)
  }
  // The trusted canary's decision row refused: the deny the mux read as a
  // 403 is no row the log holds (the session appends it late, from its deny
  // window, and counts the loss in the revocation's detail, whatever its
  // reason), so the round trip shows nothing, and the canary fails.
  {
    const base = driverWith()
    const { verdict, rows, name } = await canaryOn(t, 'trusted', base, { wrap: refusing('proxy.decision') })
    assert.deepEqual(rows.filter((r) => r.type === 'proxy.decision'), [])
    assert.deepEqual(revocations(rows), [['exited', '1 decision row could not be appended']])
    assert.deepEqual(verdict, {
      ok: false,
      why:
        `the trusted domain's canary (${name}) did not pass: its one request's deny is not one decision row the log holds ` +
        '(rows recorded 0, denies 0; 1 decision row could not be appended). So no run is given egress: check that the VM ' +
        'answers (scripts/colima-up.sh), then restart the kernel',
    })
  }
  // The same refusal while the container runs on (it waits past the deny
  // window before its exit frame, and its kill by name lands nowhere): the
  // window's flush meets the refusal, and the session ends the grant itself,
  // in error, so the canary fails on that, though the container then exits 0.
  {
    const base = driverWith({ exitDelayMs: DENY_WINDOW_MS + 300 })
    const driver: SandboxDriver = { ...overRun(base, (spec) => base.run(spec)), kill: (name) => (name.startsWith(CANARY_PREFIX) ? Promise.resolve() : base.kill(name)) }
    const { verdict, rows, name } = await canaryOn(t, 'trusted', driver, { wrap: refusing('proxy.decision'), waitMs: 10_000 })
    assert.deepEqual(revocations(rows), [['error', '1 decision row could not be appended']])
    assert.deepEqual(rows.filter((r) => r.type === 'sandbox.killed').map((r) => [r.payload['reason'], r.payload['exitCode']]), [['exited', 0]])
    assert.deepEqual(verdict, {
      ok: false,
      why:
        `the trusted domain's canary (${name}) did not pass: its grant was revoked error, not on its exit (1 decision row ` +
        'could not be appended). So no run is given egress: check that the VM answers (scripts/colima-up.sh), then restart the kernel',
    })
  }
  // A hostile report that reached something, from a canary whose
  // sandbox.started the log refused: the log's refusal is said, and the
  // domain is closed all the same.
  {
    const base = driverWith({ report: { hostile: refusedReport('reached') } })
    const { verdict, name } = await canaryOn(t, 'hostile', base, { wrap: refusing('sandbox.started') })
    assert.match(verdict.ok ? '' : verdict.why, /did not pass: the log refused its sandbox\.started row/)
    assert.equal(verdict.ok ? undefined : verdict.closes, closes('hostile', name, REACHED))
  }
})

test("a canary's wallclock is the lower of its own and sandbox.defaults.wallclockMs, and one below what a canary needs is not run", async (t) => {
  {
    const base = driverWith()
    const { verdict } = await canaryOn(t, 'hostile', base, { wallclockMs: CANARY_MIN_WALLCLOCK_MS })
    assert.deepEqual(verdict, { ok: true })
    assert.equal(base.specs[0]?.limits.wallclockMs, CANARY_MIN_WALLCLOCK_MS)
  }
  {
    const base = driverWith()
    await canaryOn(t, 'hostile', base, { wallclockMs: 600_000 })
    assert.equal(base.specs[0]?.limits.wallclockMs, CANARY_WALLCLOCK_MS)
  }
  for (const domain of ['trusted', 'hostile'] as const) {
    const base = driverWith()
    const { verdict, rows, name } = await canaryOn(t, domain, base, { wallclockMs: CANARY_MIN_WALLCLOCK_MS - 1 })
    assert.deepEqual(verdict, {
      ok: false,
      why:
        `the ${domain} domain's canary (${name}) did not pass: sandbox.defaults.wallclockMs (${String(CANARY_MIN_WALLCLOCK_MS - 1)} ms) ` +
        `is less than the ${String(CANARY_MIN_WALLCLOCK_MS)} ms a canary needs, so it was not run. So no run is given egress: ` +
        `raise sandbox.defaults.wallclockMs in config/kernel.yaml to ${String(CANARY_MIN_WALLCLOCK_MS)} or more, then restart the kernel`,
    })
    assert.deepEqual([base.specs, rows], [[], []], `${domain}: a canary was run, or a row written, under a cap it cannot pass`)
  }
  // Through boot: kernel.yaml's cap is the canary's when it is lower.
  {
    const driver = driverWith()
    const { kernel } = await withKernel(t, {
      kernelYaml: (base) => yaml(true)(base.replace('sandbox:\n', 'sandbox:\n  defaults:\n    wallclockMs: 16000\n')),
      sandboxDriver: driver,
    })
    assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' })
    assert.deepEqual(driver.specs.map((s) => s.limits.wallclockMs), [16_000, 16_000])
    await kernel.shutdown()
  }
})

test('a boot whose orphan sweep did not finish runs no canary, though the probe passed', async (t) => {
  const fx = fixture(t, { kernelYaml: yaml() })
  seedRunlessCanaries(t, fx, ['aos-run-canary-1-000000000000-trusted'])
  const driver = driverWith({}, { sweepUnlisted: ['trusted'] })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  assert.equal(kernel.status().subsystems.sandbox.state, 'degraded')
  assert.deepEqual(driver.specs, [], 'a canary ran on a boot whose sweep did not finish')
  assert.deepEqual(egressRows(fx.dbPath).map((r) => [r['check'], r['domain']]), [['sandbox', undefined]])
  await kernel.shutdown()
})

/**
 * Rows a kernel that died during its boot left: each canary's sandbox.started
 * under no run, and the trusted one's grant, with no end; or, for a name in
 * `ended`, its own exit 0, and for one in `ends`, the sandbox.killed row given
 * (its reason and exit code).
 */
function seedRunlessCanaries(
  t: TestContext,
  fx: KernelFixture,
  names: readonly string[],
  ended: readonly string[] = [],
  ends: Readonly<Record<string, { readonly reason: string; readonly exitCode?: number }>> = {},
): void {
  const store = withStore(t, { path: fx.dbPath, headFile: fx.headFile })
  for (const name of names) {
    const domain = name.endsWith('-trusted') ? 'trusted' : 'hostile'
    if (domain === 'trusted') {
      store.append({
        type: 'proxy.grant.issued',
        payload: { schemaVersion: 1, grantId: `grant_${name.split('-')[3] ?? '0'}_${name.split('-')[4] ?? 'c'}`, purpose: 'canary', sandbox: name, domain: 'trusted', allow: [], routes: [] },
      })
    }
    store.append({
      type: 'sandbox.started',
      payload: { schemaVersion: 1, sandboxId: name, driver: 'docker', domain, image: IMAGE, memoryMb: 512, pids: 256, wallclockMs: CANARY_WALLCLOCK_MS },
    })
    if (ended.includes(name)) {
      store.append({ type: 'sandbox.killed', payload: { schemaVersion: 1, sandboxId: name, reason: 'exited', exitCode: 0 } })
    }
    const end = Object.hasOwn(ends, name) ? ends[name] : undefined
    if (end !== undefined) store.append({ type: 'sandbox.killed', payload: { schemaVersion: 1, sandboxId: name, ...end } })
  }
  closeVerified(store)
}

test("a canary whose end the driver did not see stays named to the next boot's sweep: given up, its result lost, or its docker client exiting 125 or with no status", async (t) => {
  // Each of these appended sandbox.killed after a kill by name the kernel
  // did not wait on, or could not see land (a paused VM): the container may
  // still run, so the row is no proof it ended, as a run's container's is
  // not. An exit the driver saw, of the container's own or at its
  // wallclock, ends the name.
  const unseen = {
    'aos-run-canary-4-000000000001-trusted': { reason: 'error' },
    'aos-run-canary-4-000000000002-hostile': { reason: 'error', exitCode: 0 },
    'aos-run-canary-4-000000000003-trusted': { reason: 'exited', exitCode: DOCKER_CLI_FAILED },
    'aos-run-canary-4-000000000004-hostile': { reason: 'requested' },
    'aos-run-canary-4-000000000005-trusted': { reason: 'wallclock' },
  } as const
  const seen = {
    'aos-run-canary-4-000000000006-hostile': { reason: 'exited', exitCode: 0 },
    'aos-run-canary-4-000000000007-trusted': { reason: 'exited', exitCode: 1 },
    'aos-run-canary-4-000000000008-hostile': { reason: 'wallclock', exitCode: 137 },
    'aos-run-canary-4-000000000009-trusted': { reason: 'requested', exitCode: 137 },
  } as const
  const fx = fixture(t, { kernelYaml: yaml() })
  seedRunlessCanaries(t, fx, [...Object.keys(unseen), ...Object.keys(seen)], [], { ...unseen, ...seen })
  const store = new EventStore(fx.dbPath, { readOnly: true })
  const all = readAllRows(store.db)
  store.close()
  assert.deepEqual(openRunlessSandboxes(all), Object.keys(unseen))
  // The sweep names those, and each trusted canary whose grant these rows
  // left open besides, whatever its end said.
  const openGrants = Object.keys(seen).filter((name) => name.endsWith('-trusted'))
  assert.deepEqual([...sweepTargets(all, projectRecovery(all)).names].sort(), [...Object.keys(unseen), ...openGrants].sort())

  // A canary boot gave up at its bound, as boot records it: named to the next boot's sweep, which kills it.
  const fx2 = fixture(t, { kernelYaml: yaml() })
  const hung = driverWith({ instead: { hostile: 'hang' } })
  const first = await bootOn(t, fx2, { sandboxDriver: hung, canaryWaitMs: 200 })
  const given = canaryNames(hung).hostile
  assert.deepEqual(hung.abandons, [given])
  await first.shutdown()
  const next = driverWith({}, { orphans: { hostile: [given] } })
  const second = await bootOn(t, fx2, { sandboxDriver: next })
  assert.deepEqual(next.sweepRequests.map((r) => [...r.names]), [[given]])
  assert.deepEqual(next.sweeps, [[given]])
  await second.shutdown()
})

test("the next boot's sweep kills by name a canary of either domain that a kernel which died during its boot left running, and none that ended", async (t) => {
  const left = { trusted: 'aos-run-canary-7-0123456789ab-trusted', hostile: 'aos-run-canary-7-0123456789ab-hostile' }
  const done = 'aos-run-canary-3-ba9876543210-hostile'
  const fx = fixture(t, { kernelYaml: yaml() })
  seedRunlessCanaries(t, fx, [done], [done])
  seedRunlessCanaries(t, fx, [left.trusted, left.hostile])
  // A run's container with no end is the run's to sweep, by its run id, never named outright.
  {
    const store = withStore(t, { path: fx.dbPath, headFile: fx.headFile })
    store.append({
      type: 'sandbox.started',
      runId: 'run_box',
      agentId: 'coder',
      payload: { schemaVersion: 1, sandboxId: 'aos-run-run_box-1', driver: 'docker', domain: 'trusted', image: IMAGE, memoryMb: 512, pids: 256, wallclockMs: 1_000 },
    })
    closeVerified(store)
  }

  // The projection and the targets: the hostile one by its started row alone
  // (it has no grant), the trusted one by both; the one that ended by neither.
  {
    const store = new EventStore(fx.dbPath, { readOnly: true })
    const all = readAllRows(store.db)
    store.close()
    assert.deepEqual(openRunlessSandboxes(all), [left.trusted, left.hostile])
    assert.deepEqual(sweepTargets(all, projectRecovery(all)), { runIds: ['run_box'], names: [left.trusted, left.hostile] })
  }

  const driver = driverWith({}, { orphans: { trusted: [left.trusted, 'aos-run-canary-9-ffffffffffff-trusted'], hostile: [left.hostile, done] } })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  assert.deepEqual(driver.sweepRequests.map((r) => [[...r.runIds], [...r.names]]), [[['run_box'], [left.trusted, left.hostile]]])
  assert.deepEqual(driver.sweeps, [[left.trusted, left.hostile]], "another log's canary, or one that ended, was killed")
  assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' })
  // This boot's own canaries are named anew, so no kill the sweep sent can reach them.
  const names = canaryNames(driver)
  assert.ok(![left.trusted, left.hostile, done].includes(names.trusted) && ![left.trusted, left.hostile, done].includes(names.hostile))
  await kernel.shutdown()
})

test("a grant a dead kernel left open, a run's exec grant or a canary's, is revoked recovered at the next boot, once, under its own run and agent, before the run it served is closed", async (t) => {
  // The log a kernel that died mid-exec, and mid-boot, leaves: a run's exec
  // grant with no revocation, and a trusted canary's grant with no end.
  const fx = fixture(t, { kernelYaml: yaml() })
  {
    const store = withStore(t, { path: fx.dbPath, headFile: fx.headFile })
    store.append({ type: 'run.started', runId: 'run_dead', agentId: 'coder', payload: { schemaVersion: 1, runId: 'run_dead', agentId: 'coder', lane: 'main', tier: 2, taint: 'clean' } })
    store.append({
      type: 'proxy.grant.issued',
      runId: 'run_dead',
      agentId: 'coder',
      payload: {
        schemaVersion: 1,
        grantId: 'grant_run_dead',
        purpose: 'exec',
        runId: 'run_dead',
        agentId: 'coder',
        sandbox: 'aos-run-run_dead-1',
        domain: 'trusted',
        allow: ['registry.npmjs.org'],
        routes: [],
      },
    })
    closeVerified(store)
  }
  const canary = 'aos-run-canary-5-00000000abcd-trusted'
  seedRunlessCanaries(t, fx, [canary])
  {
    const store = new EventStore(fx.dbPath, { readOnly: true })
    const all = readAllRows(store.db)
    store.close()
    assert.deepEqual(projectRecovery(all).openGrants.map((g) => g.grantId), ['grant_run_dead', 'grant_5_00000000abcd'])
  }

  const kernel = await bootOn(t, fx, { sandboxDriver: driverWith() })
  // This boot's own canaries, under grants of their own, pass as ever.
  assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' })
  await kernel.shutdown()
  const all = allRows(fx.dbPath)
  const recovered = ofType(all, 'proxy.grant.revoked').filter((r) => r.payload['reason'] === 'recovered')
  // Each once, under the grant's own run and agent (a canary's under none),
  // with the boot's fixed words and no totals: the counts died with the
  // kernel that kept them.
  assert.deepEqual(
    recovered.map((r) => [r.runId, r.agentId, r.payload]),
    [
      ['run_dead', 'coder', { schemaVersion: 1, grantId: 'grant_run_dead', reason: 'recovered', detail: GRANT_RECOVERED_DETAIL }],
      [null, null, { schemaVersion: 1, grantId: 'grant_5_00000000abcd', reason: 'recovered', detail: GRANT_RECOVERED_DETAIL }],
    ],
  )
  // After this boot's kernel.booted, and before the run the grant served is
  // closed, the order a live kernel writes them in.
  const booted = ofType(all, 'kernel.booted').map((r) => r.seq)
  const closed = ofType(all, 'run.finished').find((r) => r.runId === 'run_dead')
  assert.ok(closed !== undefined, 'the dead run was not closed')
  for (const r of recovered) {
    assert.ok((booted[0] ?? Infinity) < r.seq, 'a grant was revoked before kernel.booted')
    assert.ok(r.seq < closed.seq, 'a grant was revoked after the run it served was closed')
  }
  // Nothing is left open, this boot's canary grant included.
  {
    const store = new EventStore(fx.dbPath, { readOnly: true })
    const rows = readAllRows(store.db)
    store.close()
    assert.deepEqual(projectRecovery(rows).openGrants, [])
  }

  // A second boot finds nothing to close, and appends no other.
  const again = await bootOn(t, fx, { sandboxDriver: driverWith() })
  await again.shutdown()
  assert.equal(ofType(allRows(fx.dbPath), 'proxy.grant.revoked').filter((r) => r.payload['reason'] === 'recovered').length, 2)
})

test("a Basic binding's derived value is masked at boot under the binding's own user, so the redaction every row passes through hides it", async (t) => {
  // The redaction pass reads no bare base64: only the kernel's mask keeps
  // base64(<basicUser>:<value>) out of the log, registered at boot before
  // anything can quote it (kernel.ts resolveBinding). No host echoes a
  // header here: the mask is shown through redactString, which every row
  // passes through, and boot's own rows.
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const value = 'offline-binding-value-7c31d9a2f4'
  const basic = (user: string): string => Buffer.from(`${user}:${value}`, 'utf8').toString('base64')
  assert.equal(redactString(`echoed ${basic('aos-bot')} back`), `echoed ${basic('aos-bot')} back`, 'the patterns alone hide it')
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: (base) =>
      `${yaml(true)(base)}  bindings:\n    gh:\n      host: github.com\n      scheme: Basic\n      basicUser: aos-bot\n      envVar: AOS_GITHUB_TOKEN\n      profiles: [git-fetch]\n      repos: [op/fixture]\n`,
    sandboxDriver: driverWith(),
    env: { AOS_GITHUB_TOKEN: value },
  })
  assert.deepEqual(kernel.status().subsystems.egress, { state: 'ok' })
  // The value, and its Basic form under the binding's own user.
  assert.equal(redactString(`x ${value} y`), 'x [REDACTED] y')
  assert.equal(redactString(`echoed ${basic('aos-bot')} back`), 'echoed [REDACTED] back')
  assert.equal(redactString(JSON.stringify({ authorization: `Basic ${basic('aos-bot')}` })).includes(basic('aos-bot')), false)
  for (const row of allRows(fx.dbPath)) {
    const text = JSON.stringify(row.payload)
    assert.equal(text.includes(value) || text.includes(basic('aos-bot')), false, row.type)
  }
  await kernel.shutdown()
})
