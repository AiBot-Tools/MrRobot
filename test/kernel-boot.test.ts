// T33 — kernel boot, degraded mode.
//
// Degradation is the normal case on this machine, not the error case: no
// pmmcp, no Docker, no provider credential. The kernel must come up anyway and
// say precisely what is missing, because an operator whose kernel will not
// start has no way to ask it why.
//
// The falsifiers:
//
//   Report `ready` while the vault is unreachable and status.get is lying
//   about the one thing an operator most needs to know.
//   Append to a log before verifying it and the damage becomes permanent: the
//   new rows chain onto whatever is there and the whole thing verifies from
//   then on (invariant 5).
//   Require the log to EQUAL its anchor and every boot after a crash or power
//   loss is refused — the anchor becomes a denial-of-service on yourself.
//   Let the control plane come up without its token and invariant 1 is gone;
//   that is the one subsystem that cannot be degraded.
//   Rebuild pending approvals as an empty set after a restart and a run parked
//   on a human decision looks answered.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml'
import { WebSocket } from 'ws'
import { createServer, type IncomingHttpHeaders } from 'node:http'
import type { AddressInfo } from 'node:net'

import {
  bootKernel,
  callTaints,
  configHash,
  defaultDriver,
  EGRESS_CONNECT_TIMEOUT_MS,
  egressUpstreamOptions,
  PROBE_REASON_BYTES,
  PROBE_WAIT_MS,
  probeAtBoot,
  project,
  STUBS,
  SUBSYSTEM_ORDER,
  SWEEP_REASON_BYTES,
  SWEEP_WAIT_MS,
  sweepAtBoot,
  sweepTargets,
  sweptReason,
} from '../src/kernel.js'
import { AppleContainerDriver } from '../src/sandbox/apple-container.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { isClean, projectRecovery } from '../src/events/projections.js'
import { rebuildFromLog as rebuildApprovals } from '../src/policy/approvals.js'
import { rebuildFromLog as rebuildQuarantine } from '../src/policy/quarantine.js'
import { ConfigError, NotImplementedError } from '../src/errors.js'
import { EventStore } from '../src/events/store.js'
import { readAllRows } from '../src/events/chain.js'
import { EGRESS_REASON_BYTES } from '../src/events/types.js'
import { parseKernelConfig } from '../src/config.js'
import { readAnchor } from '../src/events/anchor.js'
import { CONTROL_PATH } from '../src/control/auth.js'
import { VERSION } from '../src/version.js'
import {
  bootCrashable,
  bootOn,
  fixture,
  REPO_ROOT,
  rows,
  runThroughControl,
  TEST_TOKEN,
  verifyAt,
  withKernel,
  type KernelFixture,
} from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'
import { DATA_LOCK_FILE, DATA_LOCK_JOURNAL, holdDataDir, lockHeldRefusal } from '../src/data-lock.js'
import { closeVerified, withStore } from './helpers/store.js'
import { SANDBOX_SERVER } from '../src/runtime/sandbox-tools.js'
import { join } from 'node:path'
import { fakeSandbox, type FakeChannel } from './helpers/fake-sandbox.js'
import { CANARY_PREFIX } from '../src/runtime/canary.js'
import type { SandboxDriver } from '../src/sandbox/driver.js'
import { anthropicEndTurn, anthropicToolUse, fakeProvider } from './helpers/fake-provider.js'
import { mintHumanActor } from '../src/control/actor.js'
import { freshProbe } from './helpers/probe.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { mockMcp } from './helpers/mock-mcp.js'
import { MIN_MASK_LENGTH, redactString, SecretMask } from '../src/events/redact.js'
import { canaryPlayer, FakeMux, fakeUpstream, fakeUpstreamDeps, refusedReport, until } from './helpers/fake-egress.js'
import { connectControl } from '../src/cli/client.js'


/** Rows as bootKernel sees them: read-only reopen, ordered by seq. */
function allRows(dbPath: string): ReturnType<typeof readAllRows> {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return readAllRows(store.db)
  } finally {
    store.close()
  }
}

function payloadOf(dbPath: string, type: string): Record<string, unknown> {
  const row = rows(dbPath).find((r) => r.type === type)
  assert.ok(row, `no ${type} row`)
  return JSON.parse(row.payload) as Record<string, unknown>
}

/**
 * Boot, expecting a refusal.
 *
 * If the boot unexpectedly SUCCEEDS the kernel is shut down before the
 * assertion fails. Without that, a mutation which removes a refusal leaves a
 * listening socket and an open database behind, and the test file hangs instead
 * of failing — a hang says "something is wrong somewhere", a failure says what.
 */
async function expectBootRefusal(
  fx: ReturnType<typeof fixture>,
  env: Record<string, string | undefined>,
  pattern: RegExp,
): Promise<void> {
  let booted: Awaited<ReturnType<typeof bootKernel>> | undefined
  try {
    booted = await bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env,
      sandboxDriver: fakeSandbox(),
    })
  } catch (e) {
    assert.match(e instanceof Error ? e.message : String(e), pattern)
    return
  }
  await booted.shutdown()
  assert.fail(`boot succeeded but should have been refused with ${String(pattern)}`)
}

/** The one non-placeholder ref in the shipped providers.yaml. */
const REAL_REF = 'anthropic/claude-sonnet-5'

/** The orphan sweep's listing, as the docker driver asks each VM for it (docker.ts #sweepOn). */
const SWEEP_PS = ['ps', '--filter', 'name=aos-run-', '--format', '{{.Names}}']

test('boots DEGRADED with hub, sandbox and router degraded, each with a reason, secrets and control ok, over a real WS connection', async (t) => {
  const { kernel, fx } = await withKernel(t)

  const status = kernel.status()
  // One degraded subsystem degrades the kernel. Anything else would be a
  // status line that reads fine while the vault is unreachable.
  assert.equal(status.state, 'degraded')
  assert.equal(status.kernel.version, VERSION)

  // Each degraded subsystem names WHY. "degraded" with no reason is an
  // operator opening a debugger.
  for (const name of ['hub', 'sandbox', 'router'] as const) {
    assert.equal(status.subsystems[name].state, 'degraded', name)
    assert.ok((status.subsystems[name].reason ?? '').length > 0, `${name} has no reason`)
  }
  assert.match(status.subsystems.hub.reason ?? '', /did not connect|ECONN|EACCES|fetch failed/)
  assert.match(status.subsystems.sandbox.reason ?? '', /no container runtime/)
  // No key exported, so nothing is routable — and the reason names the variable.
  assert.match(status.subsystems.router.reason ?? '', /no routable model/)
  // secrets.source: env needs no pmmcp, so a missing pmmcp does not degrade it.
  assert.equal(status.subsystems.secrets.state, 'ok', status.subsystems.secrets.reason ?? '')

  // Egress is built (egress plan W1), so never absent: degraded, saying why,
  // here both that the shipped config disables it and that no container
  // runtime answers.
  assert.equal(status.subsystems.egress.state, 'degraded')
  assert.match(status.subsystems.egress.reason ?? '', /egress\.enabled is false/)
  assert.match(status.subsystems.egress.reason ?? '', /the sandbox is degraded \(fake: fake driver: no container runtime configured for this test\)/)

  // The scheduler is real now, and ok even with nothing to run — which it says,
  // because "ok" alone would leave an operator wondering whether it found their
  // schedule.
  assert.equal(status.subsystems.scheduler.state, 'ok')
  assert.match(status.subsystems.scheduler.reason ?? '', /no agent declares a schedule/)

  // The two that must be ok for the kernel to be worth talking to.
  assert.equal(status.subsystems.events.state, 'ok')
  assert.equal(status.subsystems.control.state, 'ok')
  assert.deepEqual([...kernel.degraded].sort(), ['egress', 'hub', 'router', 'sandbox'])

  // And the control plane really serves, over a real socket with a real
  // handshake — not merely "the object was constructed".
  const hello = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const socket = new WebSocket(`ws://127.0.0.1:${String(kernel.port)}${CONTROL_PATH}`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    })
    socket.on('error', reject)
    socket.once('message', (data: Buffer) => {
      const frame = JSON.parse(data.toString('utf8')) as Record<string, unknown>
      socket.close()
      resolve(frame)
    })
  })
  assert.equal(hello['protocol'], 1)
  const helloStatus = hello['status'] as { state: string } | undefined
  assert.equal(helloStatus?.state, 'degraded', 'the hello frame hides the degradation')

  // The chain head is real, so `status.get` is answerable straight after boot.
  assert.ok((status.chainHead?.seq ?? 0) > 0)
  // Protocol v1's `envFallback` reads "a credential may come from the
  // environment", which secrets.source: env makes the designed path.
  assert.equal(status.envFallback, true)
  assert.ok(fx.dataDir.length > 0, 'the fixture has no data dir')
})

test('with sandbox.imageId unset, boot marks the sandbox degraded, naming the key and the build script, and asks docker nothing', async (t) => {
  // Egress plan P4. kernel.yaml ships no image id, because no worker image is
  // built yet. The driver boot builds from kernel.yaml (defaultDriver), with
  // only the docker CLI's two process functions swapped for ones that answer
  // as a healthy daemon would, is what reports it: the verdict is the id's
  // alone, and nothing is asked of a daemon, let alone pulled. The orphan
  // sweep (egress plan W2) asks nothing either on a log with no sandbox run:
  // it kills only what the log names.
  const driverFor = (fx: KernelFixture, calls: string[][]): SandboxDriver =>
    defaultDriver(fx.config, REPO_ROOT, {
      spawn: (_command, args) => {
        calls.push([...args])
        throw new Error('no run starts at boot')
      },
      execFile: (_command, args) => {
        calls.push([...args])
        return Promise.resolve({
          stdout: args[0] === 'network' ? 'true\n' : args[0] === 'image' ? `${args[args.length - 1] ?? ''}\n` : '29.5.2\n',
          stderr: '',
        })
      },
    })

  const fx = fixture(t)
  assert.equal(fx.config.sandbox.imageId, undefined)
  const calls: string[][] = []
  const kernel = await bootOn(t, fx, { sandboxDriver: driverFor(fx, calls) })
  const sandbox = kernel.status().subsystems.sandbox
  const reason = sandbox.reason ?? ''
  assert.equal(sandbox.state, 'degraded')
  assert.ok(reason.startsWith('docker: sandbox.imageId is not set in config/kernel.yaml'), reason)
  assert.ok(reason.includes('scripts/build-worker-image.sh'), reason)
  assert.ok(kernel.degraded.includes('sandbox'))
  assert.deepEqual(calls, [], 'boot asked docker something')
  await kernel.shutdown()
  const degraded = payloadOf(fx.dbPath, 'sandbox.degraded')
  assert.equal(degraded['driver'], 'docker')
  assert.equal(`docker: ${String(degraded['reason'])}`, reason)

  // A log that holds a sandbox run, under an id since unpinned: the sweep
  // lists each VM, whatever the probe says, since such a kernel may have
  // left its containers running and only the sweep ends them. Nothing else
  // is asked.
  const unpinned = fixture(t)
  seedSandboxRuns(t, unpinned, ['run_unpinned'])
  const swept: string[][] = []
  const again = await bootOn(t, unpinned, { sandboxDriver: driverFor(unpinned, swept) })
  assert.equal(again.status().subsystems.sandbox.state, 'degraded')
  await again.shutdown()
  assert.deepEqual(swept, [SWEEP_PS, SWEEP_PS], 'boot asked docker something besides the sweep')

  // Pinned, the same driver goes on to the daemons, and the sandbox is ok.
  const id = `sha256:${'0123456789abcdef'.repeat(4)}`
  const pinned = fixture(t, { kernelYaml: (base) => base.replace('  image: aos-worker:test\n', `  image: aos-worker:test\n  imageId: ${id}\n`) })
  assert.equal(pinned.config.sandbox.imageId, id)
  const asked: string[][] = []
  const ok = await bootOn(t, pinned, { sandboxDriver: driverFor(pinned, asked) })
  assert.equal(ok.status().subsystems.sandbox.state, 'ok', ok.status().subsystems.sandbox.reason ?? '')
  assert.deepEqual(asked.map((a) => a[0]), ['version', 'network', 'image', 'network', 'image'])
  // Each VM asked for kernel.yaml's pinned id, by that id.
  assert.deepEqual(asked.filter((a) => a[0] === 'image').map((a) => a.join(' ')), [
    `image inspect --format {{.Id}} ${id}`,
    `image inspect --format {{.Id}} ${id}`,
  ])
  await ok.shutdown()
  assert.equal(rows(pinned.dbPath).some((r) => r.type === 'sandbox.degraded'), false)
})

// ── the orphan sweep (egress plan W2) ──────────────────────────────────────
//
// A kernel that died left its containers running with no wallclock: the
// timers were the dead process's. Boot kills them by name, on every VM,
// before it says the sandbox is ok, and only those its own log names.

const PINNED_ID = `sha256:${'0123456789abcdef'.repeat(4)}`
const pinnedYaml = (base: string): string => base.replace('  image: aos-worker:test\n', `  image: aos-worker:test\n  imageId: ${PINNED_ID}\n`)

/**
 * The log a kernel that died mid-exec leaves: each run started, with its
 * sandbox.exec tool call (which the runner appends before it asks the driver
 * for a container), and never finished, unless `finished` names it.
 */
function seedSandboxRuns(t: TestContext, fx: KernelFixture, runIds: readonly string[], finished: readonly string[] = []): void {
  const store = withStore(t, { path: fx.dbPath, headFile: fx.headFile })
  for (const runId of runIds) {
    store.append({
      type: 'run.started',
      runId,
      agentId: 'coder',
      payload: { schemaVersion: 1, runId, agentId: 'coder', lane: 'main', tier: 2, taint: 'clean' },
    })
    store.append({
      type: 'tool.call',
      runId,
      agentId: 'coder',
      payload: { schemaVersion: 1, ticketId: `ticket_${runId}`, toolRef: 'sandbox.exec', argsHash: 'h', quarantine: false },
    })
    if (finished.includes(runId)) {
      store.append({
        type: 'run.finished',
        runId,
        payload: { schemaVersion: 1, runId, status: 'ok', costMicroUsd: 0, llmCalls: 0, toolCalls: 1, durationMs: 1 },
      })
    }
  }
  closeVerified(store)
}

test('boot sweeps orphans on both domains before marking sandbox', async (t) => {
  // The driver boot builds from kernel.yaml (defaultDriver), over docker CLI
  // functions that answer as two healthy daemons would, each listing what a
  // dead kernel left on its VM beside a live kernel's container (a run of
  // another data directory's log, on the same VM) and one that is no one's
  // of ours.
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_a', 'run_b', 'run_c'])
  const DOMAIN_OF: Readonly<Record<string, string>> = { 'unix:///tmp/t.sock': 'trusted', 'unix:///tmp/h.sock': 'hostile' }
  const LISTED: Readonly<Record<string, string>> = {
    trusted: 'aos-run-run_a-1\nsomeone-elses\naos-run-run_b-2\naos-run-run_live-1\n',
    hostile: '\naos-run-run_c-1\n',
  }
  const sandboxMarked = (): boolean =>
    rows(fx.dbPath).some((r) => r.type === 'subsystem.state' && (JSON.parse(r.payload) as { subsystem?: string }).subsystem === 'sandbox')
  const booted = (): boolean => rows(fx.dbPath).some((r) => r.type === 'kernel.booted')
  const swept: { domain: string; args: string[]; marked: boolean; booted: boolean }[] = []
  const driver = defaultDriver(fx.config, REPO_ROOT, {
    spawn: () => {
      throw new Error('no run starts at boot')
    },
    execFile: (_command, args, options) => {
      const domain = DOMAIN_OF[options.env['DOCKER_HOST'] ?? ''] ?? '?'
      if (args[0] === 'ps' || args[0] === 'kill') swept.push({ domain, args: [...args], marked: sandboxMarked(), booted: booted() })
      const answer =
        args[0] === 'ps'
          ? (LISTED[domain] ?? '')
          : args[0] === 'kill'
            ? `${args[args.length - 1] ?? ''}\n`
            : args[0] === 'network'
              ? 'true\n'
              : args[0] === 'image'
                ? `${args[args.length - 1] ?? ''}\n`
                : '29.5.2\n'
      return Promise.resolve({ stdout: answer, stderr: '' })
    },
  })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  const sandbox = kernel.status().subsystems.sandbox
  await kernel.shutdown()

  // Each VM listed once, by name, and each orphan killed by name on the VM
  // that listed it; the live kernel's container and the one that is not the
  // kernel's left alone.
  assert.deepEqual(
    swept.filter((s) => s.args[0] === 'ps').map((s) => [s.domain, s.args.join(' ')]),
    [
      ['trusted', SWEEP_PS.join(' ')],
      ['hostile', SWEEP_PS.join(' ')],
    ],
  )
  assert.deepEqual(
    swept.filter((s) => s.args[0] === 'kill').map((s) => [s.domain, s.args.join(' ')]).sort(),
    [
      ['hostile', 'kill --signal=KILL aos-run-run_c-1'],
      ['trusted', 'kill --signal=KILL aos-run-run_a-1'],
      ['trusted', 'kill --signal=KILL aos-run-run_b-2'],
    ],
  )
  // All of it after this boot's kernel.booted and before the sandbox's mark.
  for (const call of swept) {
    assert.equal(call.booted, true, `${call.args.join(' ')} came before kernel.booted`)
    assert.equal(call.marked, false, `${call.args.join(' ')} came after the sandbox was marked`)
  }
  // The sandbox is ok, its reason naming what the sweep killed, in the
  // order the VMs listed them.
  assert.equal(sandbox.state, 'ok', sandbox.reason ?? '')
  assert.equal(sandbox.reason, sweptReason(['aos-run-run_a-1', 'aos-run-run_b-2', 'aos-run-run_c-1']))
  assert.equal(
    sandbox.reason,
    'the orphan sweep killed by name 3 containers a previous kernel left running: aos-run-run_a-1, aos-run-run_b-2, aos-run-run_c-1',
  )
  const mark = rows(fx.dbPath)
    .filter((r) => r.type === 'subsystem.state')
    .map((r) => JSON.parse(r.payload) as Record<string, unknown>)
    .find((p) => p['subsystem'] === 'sandbox')
  assert.deepEqual(mark, { schemaVersion: 1, subsystem: 'sandbox', state: 'ok', reason: sandbox.reason })
  assert.equal(rows(fx.dbPath).some((r) => r.type === 'sandbox.degraded'), false)
})

test("boot asks the sweep for every run its log shows may have had a container, a finished one's included, and every open grant's container, and nothing for a log with none", async (t) => {
  // A fresh log: the driver is not asked to sweep at all.
  const fresh = fixture(t, { kernelYaml: pinnedYaml })
  const idle = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID, orphans: ['aos-run-run_x-1'] })
  const first = await bootOn(t, fresh, { sandboxDriver: idle })
  assert.deepEqual(first.status().subsystems.sandbox, { state: 'ok' })
  await first.shutdown()
  assert.deepEqual(idle.sweepRequests, [])

  // A finished run's container a live kernel failed to kill is swept too; a
  // run that never called a sandbox tool is not asked for; an open grant's
  // container is named outright (a canary's, which serves no run, as well).
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_done', 'run_open'], ['run_done'])
  const extra = withStore(t, { path: fx.dbPath, headFile: fx.headFile })
  extra.append({
    type: 'run.started',
    runId: 'run_chat',
    agentId: 'ceo',
    payload: { schemaVersion: 1, runId: 'run_chat', agentId: 'ceo', lane: 'main', tier: 2, taint: 'clean' },
  })
  extra.append({
    type: 'proxy.grant.issued',
    payload: { schemaVersion: 1, grantId: 'grant_canary', purpose: 'canary', sandbox: 'aos-run-canary-trusted', domain: 'trusted', allow: [], routes: [] },
  })
  closeVerified(extra)
  const driver = fakeSandbox({
    probe: { ok: true, version: '29.5.2' },
    imageId: PINNED_ID,
    orphans: { trusted: ['aos-run-run_done-1', 'aos-run-canary-trusted', 'aos-run-run_chat-1'], hostile: ['aos-run-run_open-2'] },
  })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  const sandbox = kernel.status().subsystems.sandbox
  await kernel.shutdown()
  assert.equal(driver.sweepRequests.length, 1)
  assert.deepEqual([...(driver.sweepRequests[0]?.runIds ?? [])].sort(), ['run_done', 'run_open'])
  assert.deepEqual(driver.sweepRequests[0]?.names, ['aos-run-canary-trusted'])
  assert.deepEqual(driver.sweeps, [['aos-run-run_done-1', 'aos-run-canary-trusted', 'aos-run-run_open-2']])
  assert.deepEqual(sandbox, { state: 'ok', reason: sweptReason(['aos-run-run_done-1', 'aos-run-canary-trusted', 'aos-run-run_open-2']) })
})

test('a boot whose sweep killed nothing marks the sandbox ok with no reason, and every boot of a log with a sandbox run sweeps once', async (t) => {
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_gone'])
  const driver = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID, orphans: ['someone-elses'] })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  const sandbox = kernel.status().subsystems.sandbox
  await kernel.shutdown()
  assert.deepEqual(driver.sweeps, [[]])
  assert.deepEqual(sandbox, { state: 'ok' })
  // The run is closed now, and still the log's: the next boot sweeps for it again.
  const next = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID })
  const again = await bootOn(t, fx, { sandboxDriver: next })
  await again.shutdown()
  assert.deepEqual(next.sweepRequests.map((r) => r.runIds), [['run_gone']])
})

test("a sandbox degraded by its probe still sweeps, and its reason names what the sweep killed after the probe's", async (t) => {
  // No runtime answers the probe here, but the VMs still list what a dead
  // kernel left: the sweep runs whatever the probe said, and the reason
  // keeps both.
  const fx = fixture(t)
  seedSandboxRuns(t, fx, ['run_old'])
  const driver = fakeSandbox({ orphans: ['aos-run-run_old-3'] })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  const sandbox = kernel.status().subsystems.sandbox
  await kernel.shutdown()
  assert.deepEqual(driver.sweeps, [['aos-run-run_old-3']])
  assert.equal(sandbox.state, 'degraded')
  assert.equal(
    sandbox.reason,
    'fake: fake driver: no container runtime configured for this test; ' +
      'the orphan sweep killed by name 1 container a previous kernel left running: aos-run-run_old-3',
  )
  // The row for the probe's failure says the probe's reason alone.
  assert.deepEqual(
    rows(fx.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => (JSON.parse(r.payload) as { reason?: string }).reason),
    ['fake driver: no container runtime configured for this test'],
  )
})

/** What every sweep problem ends with: a container may still run, and what to do. */
const SWEEP_LEFT_TEXT =
  'so a container a previous kernel left may still be running, past its wallclock. Check that each VM answers ' +
  '(scripts/colima-up.sh), then restart the kernel to sweep again'

test('a sweep that throws degrades a sandbox whose probe passed, naming the sweep, and egress with it; a probe failure keeps its own reason', async (t) => {
  // A driver that breaks the contract (sweepOrphans never rejects) or the
  // apple-container stub (which throws): boot completes, and the sandbox is
  // not ok while what a dead kernel left may still run.
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_lost'])
  const base = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID })
  const throwing: SandboxDriver = {
    name: base.name,
    probe: () => base.probe(),
    run: (spec) => base.run(spec),
    kill: (name) => base.kill(name),
    abandon: (name) => base.abandon(name),
    commandRefusal: (command) => base.commandRefusal(command),
    everyRunRefusal: () => base.everyRunRefusal(),
    sweepOrphans: () => {
      throw new Error('the VM went away mid-listing')
    },
  }
  const kernel = await bootOn(t, fx, { sandboxDriver: throwing })
  const status = kernel.status()
  await kernel.shutdown()
  const problem = `the orphan sweep failed: the VM went away mid-listing, ${SWEEP_LEFT_TEXT}`
  assert.equal(status.subsystems.sandbox.state, 'degraded')
  assert.equal(status.subsystems.sandbox.reason, `fake: ${problem}`)
  assert.ok(kernel.degraded.includes('sandbox'))
  assert.deepEqual(
    rows(fx.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => JSON.parse(r.payload) as Record<string, unknown>),
    [{ schemaVersion: 1, driver: 'fake', reason: problem }],
  )
  // Egress serves only a container on a sandbox that is ok.
  assert.ok((status.subsystems.egress.reason ?? '').includes(`the sandbox is degraded (fake: ${problem})`), status.subsystems.egress.reason ?? '')

  // The apple-container stub: its probe failed and the sweep it cannot run
  // did too. Each is a row of its own, and the sandbox's reason names both,
  // the probe's first: the probe's alone would never tell an operator
  // reading status that a container this log names may still be running.
  const stubbed = fixture(t)
  seedSandboxRuns(t, stubbed, ['run_stubbed'])
  const stub = await bootOn(t, stubbed, { sandboxDriver: new AppleContainerDriver() })
  const stubStatus = stub.status()
  const stubSandbox = stubStatus.subsystems.sandbox
  await stub.shutdown()
  const stubRows = rows(stubbed.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => String((JSON.parse(r.payload) as { reason?: string }).reason))
  assert.equal(stubRows.length, 2)
  assert.match(stubRows[0] ?? '', /^the apple-container driver is not implemented/)
  assert.match(stubRows[1] ?? '', /^the orphan sweep failed: not implemented/)
  assert.ok((stubRows[1] ?? '').endsWith(SWEEP_LEFT_TEXT))
  assert.deepEqual(stubSandbox, { state: 'degraded', reason: `apple-container: ${stubRows[0] ?? ''}; ${stubRows[1] ?? ''}` })
  // Egress names both as well, as the sandbox's reason.
  assert.ok(
    (stubStatus.subsystems.egress.reason ?? '').includes(`the sandbox is degraded (apple-container: ${stubRows[0] ?? ''}; the orphan sweep failed`),
    stubStatus.subsystems.egress.reason ?? '',
  )
})

test('a driver whose probe and sweep answer with no result of their shape boots degraded, naming both, never refused', async (t) => {
  // The driver contract types what probe() and sweepOrphans() resolve with,
  // and a driver that breaks it (a null probe, a `{}` sweep) must not refuse
  // the boot: reading `.ok` of null or iterating a missing `swept` would
  // throw out of the Promise.all boot waits on.
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_shape'])
  const base = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID })
  const broken: SandboxDriver = {
    name: base.name,
    probe: () => Promise.resolve(null as unknown as Awaited<ReturnType<SandboxDriver['probe']>>),
    run: (spec) => base.run(spec),
    kill: (name) => base.kill(name),
    abandon: (name) => base.abandon(name),
    commandRefusal: (command) => base.commandRefusal(command),
    everyRunRefusal: () => base.everyRunRefusal(),
    sweepOrphans: () => Promise.resolve({} as unknown as Awaited<ReturnType<SandboxDriver['sweepOrphans']>>),
  }
  const kernel = await bootOn(t, fx, { sandboxDriver: broken })
  const status = kernel.status()
  await kernel.shutdown()
  const probeWhy =
    'fake probe answered with no probe result (ok true with a version, or ok false with a why), so the sandbox is not known to work'
  const sweepWhy =
    'the orphan sweep failed: the driver answered with no sweep result (swept, unlisted and failed, each a list of ' +
    `its own shape), ${SWEEP_LEFT_TEXT}`
  assert.deepEqual(status.subsystems.sandbox, { state: 'degraded', reason: `fake: ${probeWhy}; ${sweepWhy}` })
  assert.ok(kernel.degraded.includes('sandbox'))
  assert.deepEqual(
    rows(fx.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => (JSON.parse(r.payload) as { reason?: string }).reason),
    [probeWhy, sweepWhy],
  )
  // A probe that answers `ok` with no boolean is no working runtime either.
  const truthy = fixture(t, { kernelYaml: pinnedYaml })
  const yes: SandboxDriver = {
    ...broken,
    probe: () => Promise.resolve({ ok: 'yes' } as unknown as Awaited<ReturnType<SandboxDriver['probe']>>),
  }
  const again = await bootOn(t, truthy, { sandboxDriver: yes })
  const truthySandbox = again.status().subsystems.sandbox
  await again.shutdown()
  assert.deepEqual(truthySandbox, { state: 'degraded', reason: `fake: ${probeWhy}` })
})

test('a sweep that could not list a VM, or whose kill a daemon refused, degrades the sandbox naming each, and egress with it', async (t) => {
  // The production driver turns neither into a throw: a VM that cannot be
  // listed and a refused kill are in its result, and either may leave a
  // container of this log's running.
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_a'])
  const driver = fakeSandbox({
    probe: { ok: true, version: '29.5.2' },
    imageId: PINNED_ID,
    orphans: { trusted: ['aos-run-run_a-1', 'aos-run-run_a-2'] },
    sweepUnlisted: ['hostile'],
    sweepKillRefused: ['aos-run-run_a-2'],
  })
  const kernel = await bootOn(t, fx, { sandboxDriver: driver })
  const status = kernel.status()
  await kernel.shutdown()
  const problem =
    'the orphan sweep did not finish: the hostile VM could not be listed (Cannot connect to the Docker daemon); ' +
    `aos-run-run_a-2 could not be killed on the trusted VM (Error response from daemon: refused), ${SWEEP_LEFT_TEXT}`
  assert.deepEqual(status.subsystems.sandbox, {
    state: 'degraded',
    reason: `fake: ${problem}; ${sweptReason(['aos-run-run_a-1'])}`,
  })
  assert.deepEqual(
    rows(fx.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => (JSON.parse(r.payload) as { reason?: string }).reason),
    [problem],
  )
  assert.ok((status.subsystems.egress.reason ?? '').includes(`the sandbox is degraded (fake: ${problem}`), status.subsystems.egress.reason ?? '')
})

test("a sweep that never settles is given up at boot's bound: the boot completes, the sandbox degraded saying so, egress naming it, and the sweep told to stop", { timeout: 60_000 }, async (t) => {
  // A paused VM accepts the connection and never answers. Boot waits its
  // bound (SWEEP_WAIT_MS, here the test's) and goes on, so the operator can
  // read why from the booted kernel; the sweep's signal is aborted, so a
  // listing the VM answers later kills nothing.
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, fx, ['run_paused'])
  const driver = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID, sweepHangs: true })
  const started = Date.now()
  const kernel = await bootOn(t, fx, { sandboxDriver: driver, sweepWaitMs: 50 })
  const elapsed = Date.now() - started
  const status = kernel.status()
  await kernel.shutdown()
  // The bound boot was handed, and no other: waited for, and well short of
  // SWEEP_WAIT_MS (a boot that waited its own 30 s for a test's sweep, as
  // one ignoring the bound it is handed would, fails here, and the test's
  // timeout stays over it so the kernel is still shut down).
  assert.ok(elapsed >= 45, 'the bound was not waited for')
  assert.ok(elapsed < 10_000, `boot waited ${String(elapsed)} ms, not the 50 ms it was handed`)
  const problem = `the orphan sweep did not finish within 50 ms: a runtime accepted and never answered, and the sweep was told to stop, ${SWEEP_LEFT_TEXT}`
  assert.deepEqual(status.subsystems.sandbox, { state: 'degraded', reason: `fake: ${problem}` })
  assert.deepEqual(
    rows(fx.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => (JSON.parse(r.payload) as { reason?: string }).reason),
    [problem],
  )
  assert.ok((status.subsystems.egress.reason ?? '').includes(`the sandbox is degraded (fake: ${problem})`), status.subsystems.egress.reason ?? '')
  assert.equal(driver.sweepRequests.length, 1)
  assert.equal(driver.sweepRequests[0]?.signal.aborted, true, 'the sweep given up was not told to stop')
})

/** What a sandbox probe given up at boot's bound says. */
const probeLate = (ms: number): string =>
  `the probe did not finish within ${String(ms)} ms: a runtime accepted and never answered, and the probe was told to stop, ` +
  'so the sandbox is not known to work. Check that each VM answers (scripts/colima-up.sh), then restart the kernel'

test("a probe that never settles is given up at boot's bound: the boot completes with the sandbox degraded, egress naming it, and the probe told to stop", { timeout: 60_000 }, async (t) => {
  // A paused trusted VM accepts the connection and never answers `docker
  // version`. Once sandbox.imageId is pinned the probe asks it, and boot
  // waits its bound (PROBE_WAIT_MS, here the test's) and goes on, so the
  // operator can read why from the booted kernel.
  const fx = fixture(t, { kernelYaml: pinnedYaml })
  const driver = fakeSandbox({ probeHangs: true, imageId: PINNED_ID })
  const started = Date.now()
  const kernel = await bootOn(t, fx, { sandboxDriver: driver, probeWaitMs: 50 })
  const elapsed = Date.now() - started
  const status = kernel.status()
  await kernel.shutdown()
  // The bound boot was handed, and no other (a boot that waited its own 30 s
  // fails here, and the test's timeout stays over it so the kernel is still
  // shut down).
  assert.ok(elapsed >= 45, 'the bound was not waited for')
  assert.ok(elapsed < 10_000, `boot waited ${String(elapsed)} ms, not the 50 ms it was handed`)
  const why = probeLate(50)
  assert.deepEqual(status.subsystems.sandbox, { state: 'degraded', reason: `fake: ${why}` })
  assert.deepEqual(
    rows(fx.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => JSON.parse(r.payload) as Record<string, unknown>),
    [{ schemaVersion: 1, driver: 'fake', reason: why }],
  )
  assert.ok((status.subsystems.egress.reason ?? '').includes(`the sandbox is degraded (fake: ${why})`), status.subsystems.egress.reason ?? '')
  assert.equal(driver.probeSignals.length, 1)
  assert.equal(driver.probeSignals[0]?.aborted, true, 'the probe given up was not told to stop')

  // The driver boot builds from kernel.yaml (defaultDriver), on a log with a
  // sandbox run: a trusted VM that accepts and never answers holds both the
  // probe's `docker version` and the sweep's listings, and each call ends
  // only once boot stops waiting (rejecting then, as Node's execFile does
  // once its child is ended). The probe and the sweep go out together, so the
  // boot is held one bound, not two; each call is handed a signal that ends
  // its CLI by SIGKILL, and every one is aborted by the time boot completes.
  const paused = fixture(t, { kernelYaml: pinnedYaml })
  seedSandboxRuns(t, paused, ['run_paused'])
  const calls: { args: string[]; signal: AbortSignal | undefined; killSignal: string | undefined; earlierStopped: boolean }[] = []
  const held = defaultDriver(paused.config, REPO_ROOT, {
    spawn: () => {
      throw new Error('no run starts at boot')
    },
    execFile: (_command, args, options) => {
      calls.push({
        args: [...args],
        signal: options.signal,
        killSignal: options.killSignal,
        earlierStopped: calls.some((c) => c.signal?.aborted === true),
      })
      return new Promise((_resolve, reject) => {
        options.signal?.addEventListener('abort', () => {
          reject(new Error('The operation was aborted'))
        })
      })
    },
  })
  const heldStart = Date.now()
  const again = await bootOn(t, paused, { sandboxDriver: held, probeWaitMs: 50, sweepWaitMs: 50 })
  const heldElapsed = Date.now() - heldStart
  const heldStatus = again.status()
  await again.shutdown()
  assert.ok(heldElapsed < 10_000, `boot waited ${String(heldElapsed)} ms on a paused VM`)
  assert.deepEqual(calls.map((c) => c.args.join(' ')), [
    'version --format {{.Server.Version}}',
    SWEEP_PS.join(' '),
    SWEEP_PS.join(' '),
  ])
  for (const call of calls) {
    assert.equal(call.earlierStopped, false, `${call.args.join(' ')} went out only once another call had been given up`)
    assert.equal(call.signal?.aborted, true, `${call.args.join(' ')} was never told to stop`)
    assert.equal(call.killSignal, 'SIGKILL', `${call.args.join(' ')} would end its CLI by a signal a held CLI may ignore`)
  }
  const sweepWhy = `the orphan sweep did not finish within 50 ms: a runtime accepted and never answered, and the sweep was told to stop, ${SWEEP_LEFT_TEXT}`
  assert.deepEqual(heldStatus.subsystems.sandbox, { state: 'degraded', reason: `docker: ${why}; ${sweepWhy}` })
  assert.deepEqual(
    rows(paused.dbPath).filter((r) => r.type === 'sandbox.degraded').map((r) => (JSON.parse(r.payload) as { reason?: string }).reason),
    [why, sweepWhy],
  )
})

test('probeAtBoot gives a probe that never settles up at its bound and tells it to stop, reads a throw or a rejection as a failed probe, and passes a settled one through', async () => {
  // Raced against the test's own clock: a probeAtBoot that waited for the
  // probe itself would never return, and this fails in 5 s rather than at
  // the file's timeout.
  const within = <T>(p: Promise<T>, ms: number): Promise<T | 'unsettled'> =>
    Promise.race([p, new Promise<'unsettled'>((resolve) => setTimeout(() => resolve('unsettled'), ms).unref())])
  const started = Date.now()
  const hanging = fakeSandbox({ probeHangs: true })
  const hung = await within(probeAtBoot(hanging, 50), 5_000)
  assert.notEqual(hung, 'unsettled', 'probeAtBoot waited for a probe that never settles')
  assert.ok(Date.now() - started >= 45, 'the bound was not waited for')
  assert.deepEqual(hung, { ok: false, why: probeLate(50) })
  assert.equal(hanging.probeSignals[0]?.aborted, true, 'the probe given up was not told to stop')
  // A probe that settles in time is passed through, and its signal is never aborted.
  const ok = fakeSandbox({ probe: { ok: true, version: '29.5.2' }, imageId: PINNED_ID })
  assert.deepEqual(await probeAtBoot(ok, 10_000), { ok: true, version: '29.5.2' })
  assert.equal(ok.probeSignals[0]?.aborted, false)
  const down = fakeSandbox()
  assert.deepEqual(await probeAtBoot(down, 10_000), { ok: false, why: 'fake driver: no container runtime configured for this test' })
  // A driver that breaks the contract, by rejecting or by throwing.
  const over = (probe: SandboxDriver['probe']): SandboxDriver => ({ ...fakeSandbox(), probe })
  assert.deepEqual(await probeAtBoot(over(() => Promise.reject(new Error('lost'))), 10_000), { ok: false, why: 'fake probe threw: lost' })
  assert.deepEqual(
    await probeAtBoot(over(() => {
      throw new Error('sync')
    }), 10_000),
    { ok: false, why: 'fake probe threw: sync' },
  )
  // A driver that breaks the contract by what it answers: no ProbeResult is a
  // failed probe, never a refused boot (`.ok` of null) and never a working
  // runtime (a truthy `ok` that is no `true`).
  const noResult =
    'fake probe answered with no probe result (ok true with a version, or ok false with a why), so the sandbox is not known to work'
  const answers: readonly unknown[] = [
    null,
    undefined,
    'ok',
    {},
    { ok: 'yes', version: '29.5.2' },
    { ok: 1, version: '29.5.2' },
    { ok: true },
    { ok: true, version: 29 },
    { ok: false },
    { ok: false, why: 7 },
  ]
  for (const answer of answers) {
    assert.deepEqual(
      await probeAtBoot(over(() => Promise.resolve(answer as Awaited<ReturnType<SandboxDriver['probe']>>)), 10_000),
      { ok: false, why: noResult },
      `answer ${JSON.stringify(answer) ?? 'undefined'}`,
    )
  }
  // An answer whose reading throws is a throw, named as one.
  const getter = { get ok(): boolean { throw new Error('getter') } }
  assert.deepEqual(
    await probeAtBoot(over(() => Promise.resolve(getter as unknown as Awaited<ReturnType<SandboxDriver['probe']>>)), 10_000),
    { ok: false, why: 'fake probe threw: getter' },
  )
  // A well-formed answer is taken field by field, nothing else of it kept.
  const extra = { ok: true, version: '29.5.2', why: 'ignored' } as unknown as Awaited<ReturnType<SandboxDriver['probe']>>
  assert.deepEqual(await probeAtBoot(over(() => Promise.resolve(extra)), 10_000), { ok: true, version: '29.5.2' })
  // A failure's reason of any size, answered or thrown, is redacted and
  // bounded for the sandbox.degraded row boot appends.
  const token = `ghp_${'Q7xK'.repeat(9)}`
  const loud = `${token} ${'w'.repeat(100_000)}`
  for (const verdict of [
    await probeAtBoot(over(() => Promise.resolve({ ok: false, why: loud })), 10_000),
    await probeAtBoot(over(() => Promise.reject(new Error(loud))), 10_000),
  ]) {
    assert.equal(verdict.ok, false)
    const why = verdict.ok ? '' : verdict.why
    assert.ok(!why.includes(token), 'a credential in the reason was kept')
    assert.ok(Buffer.byteLength(why) <= PROBE_REASON_BYTES, `${String(Buffer.byteLength(why))} bytes`)
    assert.ok(Buffer.byteLength(why) > PROBE_REASON_BYTES - 8, 'the reason was cut further than its bound')
  }
  assert.equal(PROBE_REASON_BYTES, 4_096)
  // The default bound is PROBE_WAIT_MS.
  assert.equal(PROBE_WAIT_MS, 30_000)
})

test('sweepAtBoot asks nothing of empty targets, gives a sweep that never settles up at its bound and tells it to stop, and reads a throw or a rejection as a problem, never as nothing swept', async () => {
  const targets = { runIds: ['run_x'], names: [] }
  const quiet = fakeSandbox({ sweepHangs: true })
  assert.deepEqual(await sweepAtBoot(quiet, { runIds: [], names: [] }, 10), { swept: [] })
  assert.deepEqual(quiet.sweepRequests, [], 'empty targets asked the driver')

  const started = Date.now()
  const hanging = fakeSandbox({ sweepHangs: true })
  const hung = await sweepAtBoot(hanging, targets, 50)
  assert.ok(Date.now() - started >= 45, 'the bound was not waited for')
  assert.match(hung.problem ?? '', /^the orphan sweep did not finish within 50 ms: a runtime accepted and never answered/)
  assert.ok((hung.problem ?? '').endsWith(SWEEP_LEFT_TEXT))
  assert.deepEqual(hung.swept, [])
  assert.equal(hanging.sweepRequests[0]?.signal.aborted, true)
  // A sweep that settles in time is not raced against the bound, and its signal is never aborted.
  const settles = fakeSandbox({ orphans: ['aos-run-run_x-1', 'other', 'aos-run-run_y-1'] })
  assert.deepEqual(await sweepAtBoot(settles, targets, 10_000), { swept: ['aos-run-run_x-1'] })
  assert.equal(settles.sweepRequests[0]?.signal.aborted, false)
  assert.deepEqual(settles.sweepRequests[0]?.runIds, ['run_x'])
  const over = (sweepOrphans: SandboxDriver['sweepOrphans']): SandboxDriver => ({ ...fakeSandbox(), sweepOrphans })
  assert.deepEqual(await sweepAtBoot(over(() => Promise.reject(new Error('lost'))), targets, 10_000), {
    swept: [],
    problem: `the orphan sweep failed: lost, ${SWEEP_LEFT_TEXT}`,
  })
  assert.deepEqual(
    await sweepAtBoot(over(() => {
      throw new Error('sync')
    }), targets, 10_000),
    { swept: [], problem: `the orphan sweep failed: sync, ${SWEEP_LEFT_TEXT}` },
  )
  // A driver that breaks the contract by what it answers: no SweepResult is
  // the sweep's failure, named, never a rejection that refuses the boot, and
  // never a sweep read from a shape it lacks (a `swept` that is a string
  // read as its characters).
  const noSweep =
    'the orphan sweep failed: the driver answered with no sweep result (swept, unlisted and failed, each a list of ' +
    `its own shape), ${SWEEP_LEFT_TEXT}`
  const answers: readonly unknown[] = [
    {},
    undefined,
    null,
    { swept: 'aos-run-run_x-1', unlisted: [], failed: [] },
    { swept: [1], unlisted: [], failed: [] },
    { swept: [], failed: [] },
    { swept: [], unlisted: [{ domain: 'default', why: 'x' }], failed: [] },
    { swept: [], unlisted: [{ domain: 'trusted' }], failed: [] },
    { swept: [], unlisted: [], failed: [{ name: 'aos-run-run_x-1', domain: 'trusted' }] },
    { swept: [], unlisted: [], failed: [{ domain: 'trusted', why: 'refused' }] },
  ]
  for (const answer of answers) {
    assert.deepEqual(
      await sweepAtBoot(over(() => Promise.resolve(answer as Awaited<ReturnType<SandboxDriver['sweepOrphans']>>)), targets, 10_000),
      { swept: [], problem: noSweep },
      `answer ${JSON.stringify(answer) ?? 'undefined'}`,
    )
  }
  // What a failing driver says is redacted and bounded before boot records
  // it, and what to do still follows it whole.
  const token = `ghp_${'Q7xK'.repeat(9)}`
  const loud = await sweepAtBoot(over(() => Promise.reject(new Error(`${token} ${'x'.repeat(5_000)}`))), targets, 10_000)
  assert.ok(!(loud.problem ?? '').includes(token), 'a credential in the error reached the reason')
  assert.ok(Buffer.byteLength(loud.problem ?? '') <= SWEEP_REASON_BYTES)
  assert.ok((loud.problem ?? '').endsWith(`, ${SWEEP_LEFT_TEXT}`))
  // So is what a runtime said of a VM it could not list.
  const said = await sweepAtBoot(
    over(() => Promise.resolve({ swept: [], unlisted: [{ domain: 'trusted', why: `${token} ${'y'.repeat(5_000)}` }], failed: [] })),
    targets,
    10_000,
  )
  assert.ok(!(said.problem ?? '').includes(token))
  assert.ok(Buffer.byteLength(said.problem ?? '') <= SWEEP_REASON_BYTES)
  assert.ok((said.problem ?? '').endsWith(`, ${SWEEP_LEFT_TEXT}`))
  // The default bound is SWEEP_WAIT_MS.
  assert.equal(SWEEP_WAIT_MS, 30_000)
})

test('sweepTargets names every run of the log that called a sandbox tool, started a container or was issued a grant, and every open grant\'s container, and nothing else', (t) => {
  const store = withStore(t)
  const append = store.append.bind(store)
  const started = (runId: string): unknown =>
    append({ type: 'run.started', runId, agentId: 'coder', payload: { schemaVersion: 1, runId, agentId: 'coder', lane: 'main', tier: 2, taint: 'clean' } })
  const call = (runId: string, toolRef: string): unknown =>
    append({ type: 'tool.call', runId, agentId: 'coder', payload: { schemaVersion: 1, ticketId: `t_${runId}_${toolRef}`, toolRef, argsHash: 'h', quarantine: false } })
  started('run_exec')
  call('run_exec', 'sandbox.exec')
  started('run_mcp')
  call('run_mcp', 'pmmcp.recall')
  started('run_box')
  append({
    type: 'sandbox.started',
    runId: 'run_box',
    agentId: 'coder',
    payload: { schemaVersion: 1, sandboxId: 'aos-run-run_box-1', driver: 'fake', domain: 'trusted', image: 'i', memoryMb: 1, pids: 1, wallclockMs: 1 },
  })
  started('run_grant')
  append({
    type: 'proxy.grant.issued',
    runId: 'run_grant',
    agentId: 'coder',
    payload: { schemaVersion: 1, grantId: 'grant_g', purpose: 'exec', runId: 'run_grant', agentId: 'coder', sandbox: 'aos-run-run_grant-1', domain: 'trusted', allow: [], routes: [] },
  })
  append({
    type: 'proxy.grant.issued',
    payload: { schemaVersion: 1, grantId: 'grant_c', purpose: 'canary', sandbox: 'aos-run-canary-trusted', domain: 'trusted', allow: [], routes: [] },
  })
  const all = readAllRows(store.db)
  const targets = sweepTargets(all, projectRecovery(all))
  assert.deepEqual(targets, {
    runIds: ['run_exec', 'run_box', 'run_grant'],
    names: ['aos-run-run_grant-1', 'aos-run-canary-trusted'],
  })
  // The literal the projection reads a sandbox tool by is the runner's server id.
  assert.equal(SANDBOX_SERVER, 'sandbox')
})

// ── one kernel per log (src/data-lock.ts) ─────────────────────────────────

test('a second kernel on the same data directory is refused before it writes anything, and one boots once the first has shut down or died', async (t) => {
  // Without the hold, a second kernel would read the live one's open runs as
  // a dead kernel's: close them as orphans, revoke their grants `recovered`
  // and kill their containers in the sweep, and only then fail on its port.
  const fx = fixture(t)
  seedSandboxRuns(t, fx, ['run_live'])
  const first = await bootOn(t, fx)
  // Every file in the data directory is the operator's alone while the
  // kernel runs: the lock, and the journal SQLite keeps beside it while the
  // hold lasts (made with the lock file's mode, so the lock is made 0600
  // before SQLite opens it), as much as the log. Read before the second
  // kernel below, whose own hold tightens what it finds.
  assertPrivate(fx.dataDir, [DATA_LOCK_FILE, DATA_LOCK_JOURNAL, 'events.db'])
  const before = rows(fx.dbPath)
  const second = fakeSandbox({ orphans: ['aos-run-run_live-1'] })
  // A second kernel that boots after all is shut down before the test fails,
  // so a broken hold fails here rather than hanging the file on its socket.
  let refusal: unknown
  try {
    const booted = await bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
      sandboxDriver: second,
    })
    await booted.shutdown()
  } catch (e) {
    refusal = e
  }
  assert.ok(
    refusal instanceof ConfigError &&
      refusal.message.startsWith(`another kernel holds ${fx.dataDir} (${join(fx.dataDir, DATA_LOCK_FILE)} is locked): one kernel per event log`),
    `a second kernel on a live data directory was not refused: ${String(refusal)}`,
  )
  // Nothing written, nothing swept, nothing asked.
  assert.deepEqual(rows(fx.dbPath), before)
  assert.deepEqual(second.sweepRequests, [])
  await first.shutdown()
  // Released, the journal is gone with the hold.
  assert.equal(existsSync(join(fx.dataDir, DATA_LOCK_JOURNAL)), false)

  // A lock file left looser than 0600 (by a kernel before this rule, or by
  // hand) is tightened before SQLite opens it, so its journal is made 0600
  // too.
  chmodSync(join(fx.dataDir, DATA_LOCK_FILE), 0o644)
  const loose = await bootOn(t, fx)
  assertPrivate(fx.dataDir, [DATA_LOCK_FILE, DATA_LOCK_JOURNAL])
  await loose.shutdown()

  // Shut down, the directory is free.
  const { kernel: next, crash } = await bootCrashable(t, fx)
  // Dead (the OS drops a dead process's lock; crash() drops it as the OS
  // would), free again.
  await crash()
  // Released twice is released once.
  next.lock.release()
  const after = await bootOn(t, fx)
  await after.shutdown()
})

test('a boot refused after it took the data directory leaves it free, and a lock path that is not a regular file is refused by name', async (t) => {
  const fx = fixture(t)
  // An agents tree with a directory and no agent.yaml: refused while agents
  // load, long after the lock was taken and the log opened.
  const agentsDir = join(tmpdir(t), 'agents')
  mkdirSync(join(agentsDir, 'broken'), { recursive: true })
  await assert.rejects(
    bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      agentsDir,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
      sandboxDriver: fakeSandbox(),
    }),
    /ENOENT/,
  )
  const kernel = await bootOn(t, fx)
  await kernel.shutdown()

  // A link at the lock's path is no lock of the kernel's, and nothing is written.
  const linked = fixture(t)
  mkdirSync(linked.dataDir, { recursive: true })
  symlinkSync(join(tmpdir(t), 'elsewhere'), join(linked.dataDir, DATA_LOCK_FILE))
  await expectBootRefusal(linked, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /kernel\.lock is not a regular file \(a link is not one\)/)
  assert.equal(existsSync(linked.dbPath), false, 'a refused boot opened the log')
  const dir = fixture(t)
  mkdirSync(join(dir.dataDir, DATA_LOCK_FILE), { recursive: true })
  await expectBootRefusal(dir, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /kernel\.lock is not a regular file/)
  // So is a link at the journal's path, before SQLite opens anything and
  // would follow it to make the journal wherever it points.
  const journal = fixture(t)
  mkdirSync(journal.dataDir, { recursive: true })
  const target = join(tmpdir(t), 'journal-target')
  symlinkSync(target, join(journal.dataDir, DATA_LOCK_JOURNAL))
  await expectBootRefusal(journal, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /kernel\.lock-journal is not a regular file \(a link is not one\)/)
  assert.equal(existsSync(target), false, 'the journal link was followed')
  assert.equal(existsSync(journal.dbPath), false, 'a refused boot opened the log')

  // A log that is no database, refused as the store opens it, before the
  // boot's own try: the data directory is free again, so once the file is put
  // right the next boot in this process takes it, rather than being refused
  // as a second kernel.
  const damaged = fixture(t)
  mkdirSync(damaged.dataDir, { recursive: true })
  writeFileSync(damaged.dbPath, 'no kernel wrote this, and it is no SQLite database\n'.repeat(64), { mode: 0o600 })
  await expectBootRefusal(damaged, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /not a database/)
  rmSync(damaged.dbPath)
  const repaired = await bootOn(t, damaged)
  await repaired.shutdown()
})

/** Every file in `dir` is 0600, and those `expected` name are among them. */
function assertPrivate(dir: string, expected: readonly string[]): void {
  const files = readdirSync(dir).filter((name) => lstatSync(join(dir, name)).isFile())
  for (const name of expected) assert.ok(files.includes(name), `${name} is not in ${dir}: ${files.join(', ')}`)
  for (const name of files) {
    const mode = lstatSync(join(dir, name)).mode & 0o777
    assert.equal(mode, 0o600, `${name} is 0${mode.toString(8)}`)
  }
}

test('holdDataDir is exclusive within a process, and free again once released', (t) => {
  const dataDir = tmpdir(t)
  const one = holdDataDir(dataDir)
  assert.throws(() => holdDataDir(dataDir), (e: unknown) => e instanceof ConfigError && /another kernel holds/.test(e.message))
  one.release()
  const two = holdDataDir(dataDir)
  two.release()
})

test('the refusal of a held data directory says the lock is never stale and must never be removed, and tells the operator to stop the other kernel, never to remove the file', (t) => {
  // An operator who meets a lock file that looks stale (a launchd daemon
  // running unseen, say) and removes it lets the next hold make a new
  // kernel.lock on a new inode and lock that one, beside the live kernel's
  // lock on the unlinked file: a second kernel on the same log. The kernel
  // cannot see a removal made after its hold was taken, so the refusal is
  // where this is said.
  const dataDir = tmpdir(t)
  const one = holdDataDir(dataDir)
  t.after(() => one.release())
  let message = ''
  try {
    holdDataDir(dataDir)
  } catch (e) {
    assert.ok(e instanceof ConfigError, String(e))
    message = e.message
  }
  assert.equal(message, lockHeldRefusal(dataDir, join(dataDir, DATA_LOCK_FILE)))
  assert.match(message, /The lock is never stale: the OS drops it when the kernel holding it ends, however it ends, so a kernel holds it now/)
  assert.match(message, /Never remove kernel\.lock: one removed while its kernel runs lets a second kernel onto the same log\./)
  assert.match(message, /Stop the other kernel \(Ctrl-C in the terminal running its `npm run dev`, or stop its launchd job\), or give this one its own dataDir$/)
  // Every sentence that names the file's removal forbids it: none tells the
  // operator to remove, delete or rm it, as the stale-lock reflex would.
  const sentences = message.split(/(?<=\.) /)
  const naming = sentences.filter((s) => /remov|delet|\brm\b|unlink/i.test(s))
  assert.deepEqual(naming, ['Never remove kernel.lock: one removed while its kernel runs lets a second kernel onto the same log.'])
  // README's .aos row says the same where the operator reads the layout.
  const row = readFileSync(join(REPO_ROOT, 'README.md'), 'utf8').split('\n').find((l) => l.startsWith('| `.aos/kernel.lock`')) ?? ''
  assert.match(row, /`kernel\.lock` is never stale, so never remove it: a boot refused with `another kernel holds` means a kernel holds it now/)
  assert.match(row, /one removed while its kernel runs lets a second kernel onto the same log/)
  assert.match(row, /stop the other kernel instead \|$/)
})

test("the lock's journal holds SQLite's journal header while the hold lasts and goes at release, and one a killed kernel left is taken over by the next hold and goes at its release", (t) => {
  // README's .aos table and data-lock.ts's header say what this holds: the
  // journal is no empty file, and the OS drops a dead kernel's lock but not
  // its journal, which the next kernel's hold takes over.
  const dataDir = tmpdir(t)
  const journal = join(dataDir, DATA_LOCK_JOURNAL)
  const one = holdDataDir(dataDir)
  assert.ok(existsSync(journal), 'no journal while the hold lasts')
  const header = readFileSync(journal)
  assert.ok(header.length >= 28, 'the journal is empty while the hold lasts')
  // SQLite's journal header and nothing else: no page journaled (a record
  // count of 0, of a database of 0 pages), and the file is one header, its
  // own sector size long (512 bytes here).
  assert.equal(header.readUInt32BE(8), 0, 'the journal records a page')
  assert.equal(header.readUInt32BE(16), 0)
  assert.equal(header.readUInt32BE(20), header.length, 'the journal holds more than its header')
  assertPrivate(dataDir, [DATA_LOCK_FILE, DATA_LOCK_JOURNAL])
  one.release()
  assert.equal(existsSync(journal), false, 'the journal outlived the hold')
  // A SIGKILL leaves the journal as it was while the hold lasted (the OS
  // drops the lock, not the file); laid back as such a kernel left it.
  writeFileSync(journal, header, { mode: 0o600 })
  const next = holdDataDir(dataDir)
  assert.ok(existsSync(journal), "the next hold keeps no journal of its own")
  assertPrivate(dataDir, [DATA_LOCK_FILE, DATA_LOCK_JOURNAL])
  next.release()
  assert.equal(existsSync(journal), false, 'a journal a killed kernel left outlived the next hold')
})

test('sweptReason names every container that fits and is cut, never over its bound', () => {
  assert.equal(sweptReason(['aos-run-a-1']), 'the orphan sweep killed by name 1 container a previous kernel left running: aos-run-a-1')
  const many = Array.from({ length: 200 }, (_, i) => `aos-run-run_${String(i)}-1`)
  const text = sweptReason(many)
  assert.ok(text.startsWith('the orphan sweep killed by name 200 containers a previous kernel left running: aos-run-run_0-1, '))
  assert.ok(Buffer.byteLength(text) <= SWEEP_REASON_BYTES)
  assert.ok(text.endsWith('…'))
})

test('kernel.booted is the first event of this boot (seq = tail+1 at boot start) and carries configHash', async (t) => {
  const fx = fixture(t)

  // Fresh data dir: the tail is 0, so the first boot's marker is seq 1.
  const first = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  await first.shutdown()

  const afterFirst = rows(fx.dbPath)
  assert.equal(afterFirst[0]?.seq, 1)
  assert.equal(afterFirst[0]?.type, 'kernel.booted')

  const booted = JSON.parse(afterFirst[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(booted['version'], VERSION)
  // The hash of the config, not the config: kernel.yaml holds hostnames and
  // vault ids, and none of that belongs in the log. The hash is what makes two
  // boots comparable.
  assert.equal(booted['configHash'], configHash(fx.config))
  assert.match(String(booted['configHash']), /^[0-9a-f]{64}$/)
  // Empty because nothing has been built yet — this row is written before the
  // first subsystem exists, which is what makes it the boot's first row.
  assert.deepEqual(booted['degraded'], [])

  // Reboot on the SAME data dir: the claim is about every boot, not the first.
  // The tail read before booting is what the new marker must follow.
  const tailBefore = afterFirst[afterFirst.length - 1]?.seq ?? 0
  assert.ok(tailBefore > 1)

  const second = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  await second.shutdown()

  const all = rows(fx.dbPath)
  const boots = all.filter((r) => r.type === 'kernel.booted')
  assert.equal(boots.length, 2)
  assert.equal(boots[1]?.seq, tailBefore + 1, 'the second boot marker does not follow the previous tail')
  // Nothing was written between the previous tail and the marker: re-anchoring
  // touches a file, not the log.
  assert.equal(all.find((r) => r.seq === tailBefore + 1)?.type, 'kernel.booted')

  verifyAt(fx.dbPath)
})

test('each subsystem emits subsystem.state in order', async (t) => {
  const { kernel, fx } = await withKernel(t)
  await kernel.shutdown()

  const states = rows(fx.dbPath)
    .filter((r) => r.type === 'subsystem.state')
    .map((r) => (JSON.parse(r.payload) as { subsystem: string }).subsystem)

  // Exactly the eight, exactly once, in the documented order. The order is not
  // cosmetic: secrets is built before the router so the redaction mask is armed
  // before anything can put a credential on the wire, and control is last
  // because it must not accept a connection until everything it reports on has
  // been decided.
  assert.deepEqual(states, [...SUBSYSTEM_ORDER])
  assert.equal(new Set(states).size, states.length, 'a subsystem reported twice')
  assert.equal(states.indexOf('secrets') < states.indexOf('router'), true)
  assert.equal(states[states.length - 1], 'control')

  // And every row carries a state the protocol admits.
  for (const row of rows(fx.dbPath).filter((r) => r.type === 'subsystem.state')) {
    const p = JSON.parse(row.payload) as { state: string }
    assert.ok(['ok', 'degraded', 'absent'].includes(p.state), p.state)
  }

  verifyAt(fx.dbPath)
})

test('boot refuses without AOS_CONTROL_TOKEN', async (t) => {
  const fx = fixture(t)

  for (const env of [{}, { AOS_CONTROL_TOKEN: '' }, { AOS_CONTROL_TOKEN: '   ' }, { AOS_CONTROL_TOKEN: 'short' }]) {
    await expectBootRefusal(fx, env, /AOS_CONTROL_TOKEN/)
  }

  // Refused BEFORE the store is opened: a boot that cannot legally serve must
  // not leave a half-boot in the log to be explained later. The database is
  // not merely empty — it was never created, which is the strongest form of
  // "nothing happened".
  assert.equal(existsSync(fx.dbPath), false, 'a refused boot created a database')
})

test('boot creates dataDir 0700 when it does not exist', async (t) => {
  // A first boot on a clean machine has no .aos/. The store cannot open a
  // database in a directory that is not there, so without this the operator's
  // very first `npm run dev` fails with "unable to open database file" and no
  // hint that a mkdir was all it needed.
  const fx = fixture(t)
  rmSync(fx.dataDir, { recursive: true, force: true })
  assert.equal(existsSync(fx.dataDir), false)

  const kernel = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  await kernel.shutdown()

  assert.equal(existsSync(fx.dbPath), true)
  // 0700, not whatever the umask suggests: the log holds prompts, model
  // responses and tool output, and the anchor beside it is trust-bearing —
  // anything that can rewrite it can hide a truncation.
  assert.equal(statSync(fx.dataDir).mode & 0o777, 0o700, 'dataDir is not 0700')
  verifyAt(fx.dbPath)
})

test('boot makes an existing dataDir 0700 and the log 0600: npm leaves .aos at the umask\'s 0755', async (t) => {
  // .npmrc puts npm's cache in .aos/npm-cache, so `npm install` and even a bare
  // `npm run dev` create .aos before the kernel runs, and mkdir changes nothing
  // on a directory that exists. The log must still end up private.
  const fx = fixture(t)
  rmSync(fx.dataDir, { recursive: true, force: true })
  mkdirSync(join(fx.dataDir, 'npm-cache', '_logs'), { recursive: true, mode: 0o755 })
  chmodSync(fx.dataDir, 0o755)
  const boot = (): Promise<Awaited<ReturnType<typeof bootKernel>>> =>
    bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
      sandboxDriver: fakeSandbox(),
    })
  // Modes are read while the kernel runs (the -wal and -shm exist only then)
  // and asserted after it is down, so a failure cannot leave it holding the
  // process open.
  const modes = (): Record<string, number> =>
    Object.fromEntries(
      [fx.dataDir, fx.dbPath, `${fx.dbPath}-wal`, `${fx.dbPath}-shm`]
        .filter((p) => existsSync(p))
        .map((p) => [p, statSync(p).mode & 0o777]),
    )
  const expected = (seen: Record<string, number>): Record<string, number> =>
    Object.fromEntries(Object.keys(seen).map((p) => [p, p === fx.dataDir ? 0o700 : 0o600]))
  const kernel = await boot()
  const first = modes()
  await kernel.shutdown()
  assert.ok(fx.dbPath in first)
  assert.deepEqual(first, expected(first), 'the data dir or the log is readable by other accounts')
  // A log that predates this, at 0644 in a 0755 dir, is tightened on the next boot too.
  chmodSync(fx.dbPath, 0o644)
  chmodSync(fx.dataDir, 0o755)
  const again = await boot()
  const second = modes()
  await again.shutdown()
  assert.deepEqual(second, expected(second))
  verifyAt(fx.dbPath)
})

test('boot refuses when verifyChain fails against the anchor', async (t) => {
  const fx = fixture(t)
  const { kernel } = await withKernel(t, { kernelYaml: () => readFileSync(fx.configPath, 'utf8') })
  await kernel.shutdown()

  // The anchor now names a row the log does not have at that hash. This is the
  // rewrite case: the log was edited under a valid-looking chain.
  const anchor = readAnchor(fx.headFile)
  assert.ok(anchor)
  writeFileSync(fx.headFile, `${JSON.stringify({ ...anchor, hash: 'f'.repeat(64) })}\n`)

  await expectBootRefusal(fx, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /verification failed.*rewrite|rewrite/)

  // Nothing was appended. Appending to a log the kernel cannot verify would
  // make the damage permanent: every later row chains onto it, and the whole
  // thing verifies from then on.
  const after = rows(fx.dbPath)
  assert.equal(after.filter((r) => r.type === 'kernel.booted').length, 1, 'the refused boot appended')
})

test('boot refuses when the anchor is ahead of the log', async (t) => {
  const fx = fixture(t)
  const { kernel } = await withKernel(t, { kernelYaml: () => readFileSync(fx.configPath, 'utf8') })
  await kernel.shutdown()

  const anchor = readAnchor(fx.headFile)
  assert.ok(anchor)
  const tail = rows(fx.dbPath).length
  // An anchor past the tail is the truncation signature: rows were removed
  // from the end, and the remaining prefix verifies perfectly on its own. The
  // anchor is the only thing that can notice.
  writeFileSync(fx.headFile, `${JSON.stringify({ ...anchor, seq: tail + 5 })}\n`)

  await expectBootRefusal(
    fx,
    { AOS_CONTROL_TOKEN: TEST_TOKEN },
    /truncation: tail \(seq \d+\) is behind the anchored head/,
  )
})

test('boot succeeds after an unclean exit where the log is ahead of events.head, then re-anchors', async (t) => {
  // anchorEvery 5 so a handful of appends crosses an anchor boundary and the
  // anchor is genuinely behind when we skip shutdown().
  const fx = fixture(t, { anchorEvery: 5 })

  const first = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  // Append past the anchor point and then DO NOT run the clean shutdown path:
  // this is SIGKILL, power loss, or a panic. The anchor and kernel.shutdown are
  // never written, which is exactly what leaves the log ahead of its anchor.
  //
  // The extra row when the tail lands ON a multiple of anchorEvery is not
  // decoration: append() anchors at exactly those rows, so stopping there would
  // leave the log EQUAL to its anchor and the test would prove nothing. Boot's
  // own row count decides where we land, so this is computed rather than
  // counted by hand.
  const ANCHOR_EVERY = 5
  const unclean = (i: number): void => {
    first.store.append({
      type: 'subsystem.state',
      payload: { schemaVersion: 1, subsystem: 'events', state: 'ok', reason: `unclean-${String(i)}` },
    })
  }
  for (let i = 0; i < 7; i++) unclean(i)
  if (first.store.tailSeq() % ANCHOR_EVERY === 0) unclean(7)
  const tailBeforeCrash = first.store.tailSeq()
  assert.notEqual(tailBeforeCrash % ANCHOR_EVERY, 0, 'the tail landed on an anchor boundary')
  const anchorBefore = readAnchor(fx.headFile)
  assert.ok(anchorBefore)
  assert.ok(anchorBefore.seq < tailBeforeCrash, 'the anchor is not actually behind; the test proves nothing')
  // Release the socket, then drop the RAW database handle.
  //
  // Not store.close(): that is the clean path and it anchors the tail on the
  // way out, which would leave the log equal to its anchor and make the whole
  // test vacuous. A SIGKILL does not get to write an anchor, so neither does
  // this — the fd simply goes away.
  await first.server.close()
  first.store.db.close()
  first.lock.release()

  // This is the case a tail-equality check would refuse — and refusing it
  // would mean every crash needs manual intervention before the kernel starts.
  //
  // The reboot uses a LARGE anchorEvery on the same data directory so that no
  // append during boot can auto-anchor. That isolates the claim: if the anchor
  // has moved up to the pre-crash tail by the time boot returns, the boot-time
  // re-anchor did it, and not append() or shutdown().
  const rebootConfig = parseKernelConfig(
    parseYaml(readFileSync(fx.configPath, 'utf8').replace('anchorEvery: 5', 'anchorEvery: 1000')),
    { repoRoot: REPO_ROOT },
  )
  const second = await bootKernel({
    config: rebootConfig,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  // Read the anchor and the tail BEFORE shutting down — shutdown anchors again,
  // so these are the only moment the boot-time re-anchor is observable — but
  // assert only AFTER the kernel is down. Asserting first would leak a running
  // kernel on failure and turn a clear assertion error into a hung test file.
  const bootedAtSeq = second.store.tailSeq()
  const anchorAtBoot = readAnchor(fx.headFile)
  await second.shutdown()

  assert.ok(bootedAtSeq > tailBeforeCrash, 'the second boot did not append')
  assert.ok(anchorAtBoot)
  assert.equal(
    anchorAtBoot.seq,
    tailBeforeCrash,
    'boot did not re-anchor to the tail it just verified, so the next boot would still ' +
      'measure truncation from before the crash',
  )

  // Re-anchored: events.head now names the tail, so the next boot's truncation
  // check starts from what this boot verified rather than from before the crash.
  const anchorAfter = readAnchor(fx.headFile)
  assert.ok(anchorAfter)
  const finalRows = rows(fx.dbPath)
  assert.equal(anchorAfter.seq, finalRows.length)
  assert.equal(anchorAfter.seq > anchorBefore.seq, true)

  verifyAt(fx.dbPath)
})

test('shutdown writes the anchor and a second boot verifies against it', async (t) => {
  const fx = fixture(t)
  const first = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  await first.shutdown()

  const anchor = readAnchor(fx.headFile)
  assert.ok(anchor)
  const after = rows(fx.dbPath)
  // The anchor names the shutdown row itself: a clean exit leaves an anchor
  // that matches the log exactly, so nothing is "ahead" on the next boot.
  assert.equal(anchor.seq, after.length)
  assert.equal(after[after.length - 1]?.type, 'kernel.shutdown')

  const shutdown = payloadOf(fx.dbPath, 'kernel.shutdown')
  assert.equal(shutdown['reason'], 'requested')
  assert.equal(typeof shutdown['uptimeMs'], 'number')

  // Shutdown is idempotent: a second call must not append a second row or
  // touch a closed store.
  await first.shutdown()
  assert.equal(rows(fx.dbPath).length, after.length)

  const second = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  await second.shutdown()
  verifyAt(fx.dbPath)
})

test('control is marked ok only after it binds, and a bind failure refuses the boot', async (t) => {
  // Control is the one subsystem that cannot be degraded: a control plane that
  // came up without its token, or could not bind loopback, is not a degraded
  // kernel but a breach of invariant 1.
  const held = await withKernel(t)
  const port = held.kernel.port
  assert.ok(port > 1024)

  // A second kernel told to use the port the first already holds. The bind
  // fails, so the boot must fail — and must not have already written a row
  // claiming control was ok.
  const fx = fixture(t, { kernelYaml: (base) => base.replace('port: 0', `port: ${String(port)}`) })
  await assert.rejects(
    () =>
      bootKernel({
        config: fx.config,
        repoRoot: REPO_ROOT,
        providers: fx.providers,
        toolViews: fx.toolViews,
        env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
        sandboxDriver: fakeSandbox(),
      }),
    /EADDRINUSE|address already in use|listen/i,
  )

  // The failed boot's own log: it got as far as kernel.booted, and then stopped
  // without claiming control. Marking control before the listen resolves would
  // leave that claim in the log forever.
  const written = rows(fx.dbPath)
  assert.ok(written.some((r) => r.type === 'kernel.booted'), 'the second boot never started')
  const controlRows = written.filter(
    (r) => r.type === 'subsystem.state' && (JSON.parse(r.payload) as { subsystem: string }).subsystem === 'control',
  )
  assert.deepEqual(controlRows, [], 'a boot that could not bind still logged control ok')

  verifyAt(fx.dbPath)
})

test('a refused boot neither repairs the anchor nor leaks the store handle', async (t) => {
  // Two claims, both about the failure path.
  //
  // The anchor must SURVIVE a refusal. The clean close anchors the tail on its
  // way out, so closing normally here would overwrite the forged anchor with a
  // fresh valid one — the tampered log would refuse exactly once and boot clean
  // every time after. That would make the anchor worthless: an attacker
  // truncates the log, the operator sees one refusal, restarts, and the kernel
  // comes up happily on the shortened chain.
  //
  // And the handle must go. A leak is a lingering lock and a descriptor per
  // restart attempt.
  const fx = fixture(t)
  const { kernel } = await withKernel(t, { kernelYaml: () => readFileSync(fx.configPath, 'utf8') })
  await kernel.shutdown()

  // Make the log fail verification, so every later boot refuses AFTER opening
  // the store — which is the only way to reach the leak.
  const anchor = readAnchor(fx.headFile)
  assert.ok(anchor)
  writeFileSync(fx.headFile, `${JSON.stringify({ ...anchor, hash: 'e'.repeat(64) })}\n`)

  const forged = readAnchor(fx.headFile)?.hash
  assert.equal(forged, 'e'.repeat(64))

  // /dev/fd, not /proc/self/fd: macOS has no /proc. On Linux /dev/fd is a link
  // to /proc/self/fd, so both count the same thing.
  const openFds = (): number => readdirSync('/dev/fd').length
  // One refusal first, so any one-off allocation is already made and the
  // measurement below is about the repeated leak rather than about startup.
  await expectBootRefusal(fx, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /rewrite/)

  // The evidence is still there. This is the assertion that matters: without it
  // the loop below would pass for the wrong reason on a kernel that repaired
  // the anchor and then refused for some other reason.
  assert.equal(
    readAnchor(fx.headFile)?.hash,
    forged,
    'the refused boot rewrote the anchor, so the next boot would accept the tampered log',
  )

  const before = openFds()
  for (let i = 0; i < 5; i++) {
    await expectBootRefusal(fx, { AOS_CONTROL_TOKEN: TEST_TOKEN }, /rewrite/)
  }
  const after = openFds()

  // Still refusing after five more attempts: the refusal is permanent until a
  // human investigates, not a once-per-tamper inconvenience.
  assert.equal(readAnchor(fx.headFile)?.hash, forged)

  // Five refused boots, each opening a database. If the handle were kept, the
  // descriptor count would climb by at least one per attempt.
  assert.ok(
    after - before <= 2,
    `open descriptors went from ${String(before)} to ${String(after)} across five refused boots; ` +
      'the store is not being closed on the failure path',
  )
})

test('a run pays for a model call with a credential resolved at boot', async (t) => {
  // The regression test for a real defect: the router resolves a credential on
  // every provider call, and those calls happen INSIDE the run's scope — where
  // the broker refuses to resolve ("a run may not resolve a secret", and it is
  // right to: a run that can ask for a secret can be talked into asking for
  // someone else's). Resolution therefore happens at boot and the router only
  // looks up what boot already resolved. Wired the other way round, no run can
  // ever make a model call, and the Phase 0 exit criterion is unreachable.
  //
  // Offline: the provider is a double and pmmcp is absent; the credential comes
  // from the environment, the shipped `secrets.source: env`. No socket leaves
  // the machine.
  const provider = fakeProvider([anthropicEndTurn({ text: 'pong', inputTokens: 1_000, outputTokens: 100 })])
  const KEY = 'offline-fixture-credential-9c1f0b'

  const { kernel, fx } = await withKernel(t, {
    env: { ANTHROPIC_API_KEY: KEY },
    fetch: provider.fetch,
    // routable() consults the persisted probe record, so it has to be on disk
    // before boot decides whether anything can be served.
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })

  // Boot resolved the credential, from the environment, and said so — once, at
  // boot, not once per call.
  const accessed = rows(fx.dbPath).filter((r) => r.type === 'secret.accessed')
  assert.equal(accessed.length, 1, 'the credential was not resolved exactly once at boot')
  const access = JSON.parse(accessed[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(access['source'], 'env')
  assert.equal(access['id'], 'anthropic-api-key')
  assert.match(String(access['purpose']), /provider credential/)

  // With a fresh probe and a resolved credential, the router is servable.
  assert.equal(
    kernel.status().subsystems.router.state,
    'ok',
    kernel.status().subsystems.router.reason ?? 'router is not servable',
  )

  const finished = await runThroughControl(kernel, 'reply with the word pong')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  // Non-zero cost is the whole claim: a run that finishes having spent nothing
  // never reached the provider.
  assert.ok((finished['costMicroUsd'] as number) > 0, 'the run finished with zero cost')
  assert.equal(finished['llmCalls'], 1)

  // Exactly one provider call, carrying the credential in the card's header.
  assert.equal(provider.requests.length, 1)
  assert.equal(provider.requests[0]?.headers['x-api-key'], KEY)
  assert.equal(provider.requests[0]?.headers['anthropic-version'], '2023-06-01')

  // Invariant 4: two events per model call, with the cost on the response.
  const logged = rows(fx.dbPath)
  assert.equal(logged.filter((r) => r.type === 'llm.request').length, 1)
  const responses = logged.filter((r) => r.type === 'llm.response')
  assert.equal(responses.length, 1)
  const response = JSON.parse(responses[0]?.payload ?? '{}') as Record<string, unknown>
  assert.ok((response['costMicroUsd'] as number) > 0)
  assert.equal(response['content'], 'pong')

  // And the key is nowhere in the log, though it went out on the wire.
  const everything = JSON.stringify(logged)
  assert.equal(everything.includes(KEY), false, 'the credential reached the event log')
})

test('boot resolves a credential only for a ref the router can serve', async (t) => {
  // With a vault that answers for any label, resolving eagerly for every entry
  // would make a vault call per model — including the four placeholders the
  // router refuses outright (D28). Those calls cost nothing in a fixture and
  // real reach on the operator's machine: a credential fetched is a credential
  // in the process, and fetching one for a model nothing can use is reach taken
  // for no purpose.
  // The dormant vault path, against a fixture vault that returns plaintext.
  const mock = await mockMcp()
  const { kernel, fx } = await withKernel(t, {
    clientFactory: () => Promise.resolve(mock.client),
    secretsSource: 'vault',
  })
  assert.equal(kernel.status().subsystems.hub.state, 'ok')

  const accessed = rows(fx.dbPath)
    .filter((r) => r.type === 'secret.accessed')
    .map((r) => (JSON.parse(r.payload) as { id: string; source: string }))

  // Exactly one, for the one non-placeholder entry, out of the vault.
  assert.equal(
    accessed.length,
    1,
    `resolved ${String(accessed.length)} credentials: ${accessed.map((a) => a.id).join(', ')}`,
  )
  assert.equal(accessed[0]?.id, 'anthropic-api-key')
  assert.equal(accessed[0]?.source, 'vault')

  // And the vault was asked once, for that label and no other.
  const vaultCalls = mock.calls.filter((c) => c.tool === 'get_secret')
  assert.equal(vaultCalls.length, 1, `vault calls: ${JSON.stringify(vaultCalls)}`)
  assert.equal(vaultCalls[0]?.args['label'], 'anthropic-api-key')
})

test('a run with no credential path refuses before the wire', async (t) => {
  // No vault and no env fallback. The ref is otherwise servable — the probe is
  // fresh — so the only thing missing is the credential, and the run must say
  // so rather than send an unauthenticated request and report whatever 401 the
  // provider chose to give. A round trip to learn what boot already knew is a
  // round trip that leaks the attempt to the provider's logs.
  const provider = fakeProvider([anthropicEndTurn({ text: 'should never be reached' })])
  const { kernel, fx } = await withKernel(t, {
    envFallback: false,
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })

  // Boot could not resolve it, and the router says so with the reason.
  assert.equal(kernel.status().subsystems.router.state, 'degraded')
  assert.match(kernel.status().subsystems.router.reason ?? '', /ANTHROPIC_API_KEY is not set/)
  assert.equal(rows(fx.dbPath).filter((r) => r.type === 'secret.accessed').length, 0)

  const finish = await runThroughControl(kernel, 'reply with the word pong')
  assert.equal(finish['status'], 'error')
  assert.equal(finish['costMicroUsd'], 0)
  assert.match(String(finish['reason']), /ANTHROPIC_API_KEY is not set/)

  // Nothing went out. This is the claim: refused at the router, not at the
  // provider.
  assert.equal(provider.requests.length, 0, 'an unauthenticated request was sent')
})

test('a restart mid-run orphans nothing: every run reaches a terminal state and no approval or hold is left open', async (t) => {
  // The Phase 1 criterion. A kernel that died mid-run left three kinds of
  // dangling work in the log and nowhere else, because runs, approvals and holds
  // all live in memory. None of it is RESTORED — run state is not persisted, so a
  // restored approval would resolve nothing, and held content is not persisted,
  // so a restored hold has nothing to give back. All of it is closed out.
  const fx = fixture(t)

  // Boot once, then write the shape a crash leaves: a run started and never
  // finished, an approval nobody answered, a hold nobody released.
  const first = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  const RUN = 'run_crashed_midway'
  first.store.append({
    type: 'run.started',
    runId: RUN,
    agentId: 'ceo',
    payload: { schemaVersion: 1, runId: RUN, agentId: 'ceo', lane: 'main', tier: 2, taint: 'clean' },
  })
  // Real work, so the recovery row cannot honestly claim zero.
  first.store.append({
    type: 'llm.response',
    runId: RUN,
    payload: {
      schemaVersion: 1, ref: 'anthropic/claude-sonnet-5', attempt: 1, content: 'thinking',
      finish: 'tool_use', inputTokens: 100, outputTokens: 20, costMicroUsd: 4_200, durationMs: 300,
    },
  })
  first.store.append({
    type: 'tool.result',
    runId: RUN,
    payload: {
      schemaVersion: 1, ticketId: 't1', toolRef: 'web.fetch', ok: true,
      text: 'page', bytes: 4, truncated: false, durationMs: 10,
    },
  })
  first.store.append({
    type: 'approval.requested',
    runId: RUN,
    payload: {
      schemaVersion: 1, approvalId: 'apr_unanswered', toolRef: 'github.merge_pull_request',
      argsPreview: '{"pr":7}', risk: 'irreversible',
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    },
  })
  first.store.append({
    type: 'quarantine.held',
    runId: RUN,
    payload: { schemaVersion: 1, holdId: 'hold_unreleased', toolRef: 'web.fetch', reason: 'untrusted page' },
  })

  // The crash: release the socket and drop the raw handle, so no clean shutdown
  // and no anchor write. (store.close() would anchor — see the unclean-exit test.)
  await first.server.close()
  first.store.db.close()
  first.lock.release()

  // Everything is open at this point, per the projection.
  const open = projectRecovery(allRows(fx.dbPath))
  assert.equal(open.orphanRuns.length, 1, 'the crashed run does not read as open')
  assert.equal(open.unresolvedApprovals.length, 1)
  assert.equal(open.unreleasedHolds.length, 1)

  // The restart.
  const second = await bootKernel({
    config: fx.config,
    repoRoot: REPO_ROOT,
    providers: fx.providers,
    toolViews: fx.toolViews,
    env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
    sandboxDriver: fakeSandbox(),
  })
  const reported = second.recovered
  await second.shutdown()

  // Boot said what it found, so an operator is not left to infer it.
  assert.deepEqual(reported.orphanRuns.map((r) => r.runId), [RUN])
  assert.deepEqual(reported.unresolvedApprovals.map((a) => a.approvalId), ['apr_unanswered'])
  assert.deepEqual(reported.unreleasedHolds.map((h) => h.holdId), ['hold_unreleased'])

  const after = rows(fx.dbPath)
  const payloadsOf = (type: string): Record<string, unknown>[] =>
    after.filter((r) => r.type === type).map((r) => JSON.parse(r.payload) as Record<string, unknown>)

  // 1. The run reached a terminal state, with the numbers the log actually holds.
  const finished = payloadsOf('run.finished').filter((p) => p['runId'] === RUN)
  assert.equal(finished.length, 1, 'the orphaned run has no terminal row')
  assert.equal(finished[0]?.['status'], 'error')
  assert.match(String(finished[0]?.['reason']), /orphaned by a kernel restart/)
  // Counted, not zeroed: the run spent this and the bill has to show it.
  assert.equal(finished[0]?.['costMicroUsd'], 4_200)
  assert.equal(finished[0]?.['llmCalls'], 1)
  assert.equal(finished[0]?.['toolCalls'], 1)

  // 2. The approval reached a decision, and NOT one that implies a person made it.
  const resolved = payloadsOf('approval.resolved').filter((p) => p['approvalId'] === 'apr_unanswered')
  assert.equal(resolved.length, 1)
  assert.equal(resolved[0]?.['decision'], 'expired')
  assert.equal(resolved[0]?.['byConnectionId'], undefined, 'the recovery named a connection')

  // 3. The hold ended as ABANDONED, not released. The distinction is the point:
  // released means a human read the content and allowed it; the content did not
  // survive the crash, so claiming that would be a false audit record.
  const abandoned = payloadsOf('quarantine.abandoned')
  assert.equal(abandoned.length, 1)
  assert.equal(abandoned[0]?.['holdId'], 'hold_unreleased')
  assert.match(String(abandoned[0]?.['reason']), /restart/)
  assert.equal(payloadsOf('quarantine.released').length, 0, 'recovery claimed a human release')

  // kernel.booted is STILL the first row of this boot, even though this boot had
  // work to do. Test 2 only ever proves that on a boot with nothing to recover,
  // so the case where it could actually break is this one: recovery rows written
  // before the marker would be attributable to no boot at all, and an auditor
  // could not tell which restart closed which orphan.
  const bootMarkers = after.filter((r) => r.type === 'kernel.booted').map((r) => r.seq)
  assert.equal(bootMarkers.length, 2, 'expected two boots in this log')
  const secondBootAt = bootMarkers[1]
  assert.ok(secondBootAt !== undefined)
  const recoveryRows = after.filter(
    (r) =>
      r.seq > (bootMarkers[0] ?? 0) &&
      (r.type === 'approval.resolved' ||
        r.type === 'quarantine.abandoned' ||
        (r.type === 'run.finished' && (JSON.parse(r.payload) as { reason?: string }).reason?.includes('orphaned'))),
  )
  assert.equal(recoveryRows.length, 3, 'expected one recovery row per open item')
  for (const row of recoveryRows) {
    assert.ok(
      row.seq > secondBootAt,
      `${row.type} at seq ${String(row.seq)} was written before this boot's kernel.booted at ${String(secondBootAt)}`,
    )
  }

  // And nothing is left open, which is the whole claim.
  const remaining = projectRecovery(allRows(fx.dbPath))
  assert.equal(isClean(remaining), true, JSON.stringify(remaining))

  verifyAt(fx.dbPath)
})

test('recovery is idempotent: a second restart writes no further recovery rows', async (t) => {
  // Idempotence is structural rather than bolted on — a run is open because it
  // has no terminal row, so writing one closes it. This test is what proves the
  // structure holds, because the alternative failure is quiet: a kernel that
  // re-terminated on every boot would append a run.finished per restart and the
  // log would fill with them.
  const fx = fixture(t)
  const boot = async (): Promise<Awaited<ReturnType<typeof bootKernel>>> =>
    bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
      sandboxDriver: fakeSandbox(),
    })

  const first = await boot()
  first.store.append({
    type: 'run.started',
    runId: 'run_x',
    agentId: 'ceo',
    payload: { schemaVersion: 1, runId: 'run_x', agentId: 'ceo', lane: 'main', tier: 2, taint: 'clean' },
  })
  await first.server.close()
  first.store.db.close()
  first.lock.release()

  // Captured, then shut down, THEN asserted. Asserting first leaks a running
  // kernel on failure and turns a clear assertion error into a hung test file.
  const second = await boot()
  const secondRecovered = second.recovered
  await second.shutdown()
  assert.equal(secondRecovered.orphanRuns.length, 1, 'the first restart found nothing to close')
  assert.equal(rows(fx.dbPath).filter((r) => r.type === 'run.finished').length, 1)

  // Two more clean restarts. Each finds nothing, and writes nothing.
  for (const pass of [1, 2]) {
    const again = await boot()
    const found = again.recovered
    await again.shutdown()
    assert.equal(isClean(found), true, `restart ${String(pass)} found work to redo: ${JSON.stringify(found)}`)
    assert.equal(
      rows(fx.dbPath).filter((r) => r.type === 'run.finished').length,
      1,
      `restart ${String(pass)} wrote a second terminal row for the same run`,
    )
  }

  verifyAt(fx.dbPath)
})

test('a scheduled agent fires through a real kernel on the minute it matches', async (t) => {
  // End to end: the manifest's cron expression, the scheduler boot started, and a
  // run on the agent's OWN lane through the same path the control plane uses.
  // There is no cron lane, and a scheduled run is an ordinary run.
  //
  // The clock is fixed, so both boots below see the same minute and the restart
  // property is deterministic rather than a race with the wall clock.
  const FIXED = Date.parse('2026-09-28T09:00:00')
  const fx = fixture(t)

  // The shipped ceo manifest carries no schedule, so one is added in a temp
  // agents tree rather than by editing the shipped file.
  const agentsDir = join(tmpdir(t), 'agents')
  for (const id of ['ceo', 'worker-template']) {
    mkdirSync(join(agentsDir, id, 'history'), { recursive: true })
    const shipped = readFileSync(join(REPO_ROOT, 'agents', id, 'agent.yaml'), 'utf8')
    writeFileSync(
      join(agentsDir, id, 'agent.yaml'),
      id === 'ceo' ? `${shipped}\nschedule: "* * * * *"\n` : shipped,
    )
  }
  writeFileSync(join(agentsDir, 'ceo', 'AGENTS.md'), '# ceo\n')

  const boot = async (): Promise<Awaited<ReturnType<typeof bootKernel>>> =>
    bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      agentsDir,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
      sandboxDriver: fakeSandbox(),
      now: () => FIXED,
    })

  const kernel = await boot()
  // Everything observed BEFORE shutdown is captured first and asserted after.
  // Asserting here would leak a running kernel on failure and hang the file.
  const schedulerState = kernel.status().subsystems.scheduler
  const seen = kernel.scheduler.diagnostics().map((d) => [d.agentId, d.schedule])
  const runningAfterBoot = kernel.scheduler.running
  const firstTick = kernel.scheduler.tick()
  const secondTick = kernel.scheduler.tick()
  await kernel.shutdown()
  const runningAfterShutdown = kernel.scheduler.running

  // Boot STARTED it. Without this, a kernel that built a scheduler and never
  // started it would look identical from outside and no schedule would ever fire.
  assert.equal(runningAfterBoot, true, 'boot did not start the scheduler')
  // And shutdown stopped it, so a closed store cannot be appended to by a tick.
  assert.equal(runningAfterShutdown, false, 'shutdown left the scheduler ticking')

  // It is ok and it FOUND the schedule, which the reason must not claim otherwise.
  assert.equal(schedulerState.state, 'ok')
  assert.equal(schedulerState.reason, undefined, 'it did not see the ceo schedule')
  assert.deepEqual(seen, [['ceo', '* * * * *']])

  // One tick, one run. A second tick in the same minute fires nothing.
  assert.deepEqual(firstTick, ['ceo'])
  assert.deepEqual(secondTick, [])

  const all = rows(fx.dbPath)
  const claims = all.filter((r) => r.type === 'run.scheduled')
  assert.equal(claims.length, 1, 'the minute was claimed more or less than once')
  const claim = JSON.parse(claims[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(claim['agentId'], 'ceo')
  assert.equal(claim['schedule'], '* * * * *')
  assert.equal(claim['minute'], '2026-09-28T09:00')

  const queued = all.filter((r) => r.type === 'run.queued')
  assert.equal(queued.length, 1)
  const q = JSON.parse(queued[0]?.payload ?? '{}') as Record<string, unknown>
  assert.equal(q['agentId'], 'ceo')
  // The ceo is an orchestrator, so its lane is main — not a lane named for cron.
  assert.equal(q['lane'], 'main')

  // Restart inside the same minute. start() seeds the claim back from the log, so
  // the job must NOT run again — a reboot is otherwise the one reliable way to
  // double-fire a schedule, and an operator restarts the daemon for many reasons.
  const again = await boot()
  const afterRestart = again.scheduler.tick()
  await again.shutdown()
  assert.deepEqual(afterRestart, [], 'a restart re-fired a minute already claimed')
  assert.equal(
    rows(fx.dbPath).filter((r) => r.type === 'run.queued').length,
    1,
    'the restart started a second run for the same minute',
  )

  verifyAt(fx.dbPath)
})

test('a run killed while it waits for its lane: run.get shows it finished, and the scheduler no longer finds its agent busy', async (t) => {
  // Run A of researcher holds the agent's lane, in a model call; run B of
  // researcher queues behind it, and `aos kill B` arrives. B never starts.
  // Its run.finished is what the daemon's run view and the scheduler's busy
  // check read: without it B stays queued for the kernel's life and every
  // scheduled job of researcher is skipped until a restart.
  let clock = Date.parse('2026-09-28T09:00:00')
  const agentsDir = join(tmpdir(t), 'agents')
  for (const id of ['ceo', 'worker-template', 'researcher']) {
    mkdirSync(join(agentsDir, id, 'history'), { recursive: true })
    const shipped = readFileSync(join(REPO_ROOT, 'agents', id, 'agent.yaml'), 'utf8')
    writeFileSync(join(agentsDir, id, 'agent.yaml'), id === 'researcher' ? `${shipped}\nschedule: "* * * * *"\n` : shipped)
    writeFileSync(join(agentsDir, id, 'AGENTS.md'), `# ${id}\n`)
  }
  const provider = fakeProvider([anthropicEndTurn({ text: 'A' }), anthropicEndTurn({ text: 'scheduled' })])
  let release: () => void = () => undefined
  const held = new Promise<void>((resolve) => {
    release = resolve
  })
  let calls = 0
  const fetch: typeof globalThis.fetch = async (input, init) => {
    calls += 1
    if (calls === 1) await held
    return provider.fetch(input, init)
  }
  const { kernel, fx } = await withKernel(t, {
    agentsDir,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b' },
    fetch,
    now: () => clock,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  t.after(() => release())
  // Bounded, so a run that never ends fails the test, saying which, rather
  // than hang the file.
  const seen = (type: string, runId?: string): Promise<void> =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        stop()
        reject(new Error(`no ${type}${runId === undefined ? '' : ` for ${runId}`} within 10 s`))
      }, 10_000)
      timer.unref?.()
      const stop = kernel.store.subscribe((row) => {
        if (row.type !== type || (runId !== undefined && row.runId !== runId)) return
        clearTimeout(timer)
        stop()
        resolve()
      })
    })

  const client = await connectControl({ port: kernel.port, token: TEST_TOKEN, timeoutMs: 20_000 })
  t.after(() => client.close())
  const inCall = seen('llm.request')
  const a = (await client.call('run.start', { agentId: 'researcher', input: 'first' })) as { runId: string }
  await inCall
  const b = (await client.call('run.start', { agentId: 'researcher', input: 'second' })) as { runId: string }
  const bEnded = seen('run.finished', b.runId)
  const killed = (await client.call('run.kill', { runId: b.runId })) as { status: string }
  await bEnded
  const detailB = (await client.call('run.get', { runId: b.runId })) as Record<string, unknown>
  const aWhileB = (await client.call('run.get', { runId: a.runId })) as Record<string, unknown>

  const aEnded = seen('run.finished', a.runId)
  release()
  await aEnded
  // The next minute: researcher has no run in flight, so its job fires.
  clock += 60_000
  const scheduledEnded = seen('run.finished')
  const fired = kernel.scheduler.tick()
  await scheduledEnded

  assert.equal(killed.status, 'queued')
  assert.deepEqual(
    [detailB['status'], detailB['reason'], detailB['llmCalls'], detailB['toolCalls'], detailB['costMicroUsd']],
    ['finished', 'requested', 0, 0, 0],
  )
  assert.equal(aWhileB['status'], 'running')
  assert.deepEqual(fired, ['researcher'], 'the scheduler still found researcher busy')
  const bRows = rows(fx.dbPath).filter((r) => r.type.startsWith('run.') && (JSON.parse(r.payload) as { runId?: string }).runId === b.runId)
  assert.deepEqual(bRows.map((r) => r.type), ['run.queued', 'run.finished'])
  assert.equal(provider.requests.length, 2, 'B called the model')
})

test('envFallback:true shows secrets degraded in status.get', async (t) => {
  // D8: while env fallback is on, a credential MAY come from the environment
  // rather than the vault. A kernel reporting ready in that state would be
  // hiding exactly the thing an operator needs to know.
  const noVault = await withKernel(t, { envFallback: true, secretsSource: 'vault' })
  assert.equal(noVault.kernel.status().envFallback, true)
  assert.equal(noVault.kernel.status().subsystems.secrets.state, 'degraded')
  assert.equal(noVault.kernel.status().state, 'degraded')

  // With no vault, the reason is the missing vault. That alone would let this
  // test pass for the wrong reason, so the same claim is made again with the
  // vault UP: envFallback must degrade secrets on its own, and say why.
  const mock = await mockMcp()
  const withVault = await withKernel(t, {
    envFallback: true,
    secretsSource: 'vault',
    clientFactory: () => Promise.resolve(mock.client),
  })
  const status = withVault.kernel.status()
  assert.equal(status.subsystems.hub.state, 'ok', 'the mock hub did not connect')
  assert.equal(status.subsystems.secrets.state, 'degraded')
  // The wording is the broker's, because boot now derives this mark from
  // broker.start() rather than re-deriving it from config: one place decides
  // what a degraded vault means, and it is the component that owns the vault.
  assert.match(status.subsystems.secrets.reason ?? '', /envFallback is ON/)
  assert.match(status.subsystems.secrets.reason ?? '', /environment/)
  assert.equal(status.state, 'degraded', 'a connected vault made the kernel look ready with fallback on')

  // And with fallback OFF and the vault up, secrets is finally ok — so the
  // degradation above is attributable to the flag and nothing else.
  const clean = await withKernel(t, {
    clientFactory: () => Promise.resolve(mock.client),
    secretsSource: 'vault',
  })
  assert.equal(clean.kernel.status().subsystems.secrets.state, 'ok')
  assert.equal(clean.kernel.status().envFallback, false)
})

test('pmmcp is dialled with the declared bearer, with none when a config declares no tokenEnv, and never when the declared one is unset', async (t) => {
  // The shipped config declares pmmcp's bearer (the kernel is its client
  // aos-kernel). A loopback recorder stands in for pmmcp: the claim is what the
  // kernel SENDS, which a mock client factory would never see.
  const shipped = parseKernelConfig(parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')), { repoRoot: REPO_ROOT })
  const tokenEnv = shipped.mcp.servers['pmmcp']?.tokenEnv
  assert.equal(tokenEnv, 'AOS_PMMCP_TOKEN')
  const seen: IncomingHttpHeaders[] = []
  const server = createServer((req, res) => {
    seen.push(req.headers)
    req.resume()
    res.writeHead(404).end()
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const url = `url: http://127.0.0.1:${String((server.address() as AddressInfo).port)}/mcp`
  const pointAt = (extra: string) => (base: string): string =>
    base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `${url}${extra}`)
  const declared = `\n      tokenEnv: ${tokenEnv}`

  // Declared and set, as shipped: the bearer goes in the Authorization header.
  const bearer = 'pmmcp-bearer-for-this-test-only'
  const withToken = await withKernel(t, { kernelYaml: pointAt(declared), env: { [tokenEnv]: bearer } })
  assert.ok(seen.length > 0, 'a set tokenEnv was never dialled')
  assert.ok(seen.every((h) => h.authorization === `Bearer ${bearer}`), 'the declared bearer was not sent')
  await withToken.kernel.shutdown()

  // Declared and unset: refused with the variable named, before any request.
  seen.length = 0
  const unset = await withKernel(t, { kernelYaml: pointAt(declared) })
  assert.equal(seen.length, 0, 'a declared tokenEnv left unset still dialled')
  assert.match(unset.kernel.status().subsystems.hub.reason ?? '', /AOS_PMMCP_TOKEN is not set/)
  await unset.kernel.shutdown()

  // A config without the line (the fixture's own): dialled, and nothing that
  // looks like a credential goes with it, even with the shipped name set.
  seen.length = 0
  const tokenless = await withKernel(t, { kernelYaml: pointAt(''), env: { [tokenEnv]: bearer } })
  assert.equal(tokenless.fx.config.mcp.servers['pmmcp']?.tokenEnv, undefined)
  assert.ok(seen.length > 0, 'the kernel never dialled pmmcp')
  assert.ok(seen.every((h) => h.authorization === undefined), 'a bearer went to a server whose config declares none')
  assert.doesNotMatch(tokenless.kernel.status().subsystems.hub.reason ?? '', /is not set/)
  await tokenless.kernel.shutdown()
})

test('a declared pmmcp bearer that cannot be a header is refused by name, never dialled, and no part of it reaches the log', async (t) => {
  // openssl rand -base64 64 wraps at 64 columns: a newline mid-token. The HTTP
  // library would throw with the whole header value in its message, and that
  // message used to become a chained hub.degraded reason.
  t.after(() => SecretMask.clear())
  let dialled = 0
  const server = createServer((req, res) => {
    dialled += 1
    req.resume()
    res.writeHead(404).end()
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const url = `url: http://127.0.0.1:${String((server.address() as AddressInfo).port)}/mcp`
  const head = 'qBearerHeadCanary0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL'
  const tail = 'qBearerTailCanaryZYXWVU98765=='
  for (const token of [`${head}\n${tail}`, `${head} ${tail}`, `\u201C${head}${tail}\u201D`]) {
    const booted = await withKernel(t, {
      kernelYaml: (base) => base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `${url}\n      tokenEnv: AOS_PMMCP_TOKEN`),
      env: { AOS_PMMCP_TOKEN: token },
    })
    const reason = booted.kernel.status().subsystems.hub.reason ?? ''
    assert.match(reason, /AOS_PMMCP_TOKEN (contains whitespace|contains a character outside printable ASCII)/, JSON.stringify(token))
    await booted.kernel.shutdown()
    const logged = allRows(booted.fx.dbPath).map((r) => r.payload).join('\n')
    for (const secret of [head, tail]) {
      for (let i = 0; i + 8 <= secret.length; i += 1) {
        assert.equal(logged.includes(secret.slice(i, i + 8)), false, 'part of the bearer reached the event log')
      }
    }
  }
  assert.equal(dialled, 0, 'a bearer that cannot be a header was sent anyway')
})

test('a declared pmmcp bearer too short for the mask is refused by name and never dialled', async (t) => {
  // SecretMask declines anything under MIN_MASK_LENGTH, so a short loopback dev
  // bearer would be sent unmasked, and a server echoing it would chain it into
  // the log for good.
  t.after(() => SecretMask.clear())
  let dialled = 0
  const server = createServer((req, res) => {
    dialled += 1
    req.resume()
    res.writeHead(401).end(`unauthorized: ${String(req.headers.authorization)}`)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const url = `url: http://127.0.0.1:${String((server.address() as AddressInfo).port)}/mcp`
  const short = 'Qz7#kd!'
  const booted = await withKernel(t, {
    kernelYaml: (base) => base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `${url}\n      tokenEnv: AOS_PMMCP_TOKEN`),
    env: { AOS_PMMCP_TOKEN: short },
  })
  const reason = booted.kernel.status().subsystems.hub.reason ?? ''
  assert.match(reason, new RegExp(`AOS_PMMCP_TOKEN is under ${String(MIN_MASK_LENGTH)} characters, so it cannot be masked`))
  await booted.kernel.shutdown()
  assert.equal(allRows(booted.fx.dbPath).map((r) => r.payload).join('\n').includes(short), false, 'the short bearer reached the event log')
  assert.equal(dialled, 0, 'a bearer the log cannot mask was sent anyway')
})

test('a valid pmmcp bearer is masked before connecting, so a server that echoes it into an error leaves no trace in the log', async (t) => {
  t.after(() => SecretMask.clear())
  // An opaque value, nothing like a key shape, so only the exact-value mask
  // can be what keeps it out: the pattern redactor would not recognise it.
  const bearer = 'qOpaqueBearerCanary0123456789abcdefghij'
  const server = createServer((req, res) => {
    req.resume()
    // A misbehaving server: it quotes the credential back in its refusal, which
    // the MCP client puts in the error the hub records as its degraded reason.
    // Bare, without the `Bearer ` the pattern redactor would recognise.
    res.writeHead(401, { 'content-type': 'text/plain' }).end(`unauthorized: ${String(req.headers.authorization).replace(/^Bearer /, '')}`)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const url = `url: http://127.0.0.1:${String((server.address() as AddressInfo).port)}/mcp`
  const booted = await withKernel(t, {
    kernelYaml: (base) => base.replace(/url: http:\/\/127\.0\.0\.1:\d+\/mcp/, `${url}\n      tokenEnv: AOS_PMMCP_TOKEN`),
    env: { AOS_PMMCP_TOKEN: bearer },
  })
  await booted.kernel.shutdown()
  const logged = allRows(booted.fx.dbPath).map((r) => r.payload).join('\n')
  assert.match(logged, /unauthorized/, 'the server\'s refusal never reached the log, so this proves nothing')
  for (let i = 0; i + 8 <= bearer.length; i += 1) {
    assert.equal(logged.includes(bearer.slice(i, i + 8)), false, 'part of the bearer reached the event log')
  }
})

test("boot hands the registry kernel.yaml's egress bindings: a bound host in allow refuses the boot by file, a bind of its id boots", async (t) => {
  // bootKernel builds the only production registry, so this is where a
  // binding becomes something a manifest can name or must not list. A boot
  // that handed the registry no bindings would load the first manifest and
  // refuse the second, both silently wrong once the operator adds one.
  const egress = `
egress:
  bindings:
    github-git:
      host: github.com
      scheme: Basic
      envVar: AOS_GITHUB_TOKEN
      profiles: [git-fetch]
      repos: [op/fixture]
`
  const worker = (id: string, lines: string): string => `
id: ${id}
version: 1
kind: standard
role: worker
soul: worker.md
tier: 2
model:
  primary: ${REAL_REF}
sandbox:
  domain: trusted
egress:
${lines}
memory:
  projectId: aos/agent/${id}
`
  // The shipped fleet, and one worker beside it.
  const fleet = (id: string, lines: string): string => {
    const dir = join(tmpdir(t), 'agents')
    const files: Record<string, string> = { [id]: worker(id, lines) }
    for (const shipped of ['ceo', 'worker-template']) {
      files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
    }
    for (const [name, yaml] of Object.entries(files)) {
      mkdirSync(join(dir, name, 'history'), { recursive: true })
      writeFileSync(join(dir, name, 'agent.yaml'), yaml)
      writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
    }
    return dir
  }

  const fx = fixture(t, { kernelYaml: (base) => `${base}${egress}` })
  assert.deepEqual(Object.keys(fx.config.egress.bindings), ['github-git'])
  let booted: Awaited<ReturnType<typeof bootKernel>> | undefined
  let refusal: unknown
  try {
    booted = await bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      agentsDir: fleet('reacher', '  allow: [github.com]'),
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN },
      sandboxDriver: fakeSandbox(),
    })
  } catch (e) {
    refusal = e
  }
  // Shut down before asserting, so a boot that should have refused leaves no
  // socket or open database behind to hang the file.
  await booted?.shutdown()
  assert.equal(booted, undefined, 'a manifest listing a bound host in egress.allow booted')
  assert.ok(refusal instanceof ConfigError, `refused with ${String(refusal)}`)
  assert.match(refusal.message, /reacher\/agent\.yaml: egress\.allow lists github\.com, the host of binding github-git in kernel\.yaml/)
  verifyAt(fx.dbPath)

  const { kernel } = await withKernel(t, {
    kernelYaml: (base) => `${base}${egress}`,
    agentsDir: fleet('fetcher', '  bind: [github-git]'),
  })
  assert.deepEqual(kernel.agents.get('fetcher')?.manifest.egress, { allow: [], bind: ['github-git'] })
})

// ── sandbox.exec, wired (egress plan W1a) ───────────────────────────────────

/** The tool names a provider request offered, as the Anthropic dialect spells them. */
function offeredNames(body: unknown): string[] {
  const tools = (body as { tools?: { name: string }[] } | undefined)?.tools ?? []
  return tools.map((tool) => tool.name)
}

test("the daemon's run view is tainted by every row that taints a run in the loop, and by no other", () => {
  // runs.list and run.get show what the gate reads. A run the loop gates as
  // tainted and the view shows clean leaves the operator approving its next
  // write in the belief that nothing untrusted reached it.
  const views = parseToolViews({
    version: 1,
    servers: {
      pmmcp: {
        default: 'kernel-only',
        tools: {
          scrape: { exposure: 'agent', risk: 'read', taints: true, namespaceArg: 'none' },
          recall: { exposure: 'agent', risk: 'read', namespaceArg: 'none' },
        },
      },
    },
  })
  const clean = {
    runId: 'run_v',
    agentId: 'coder',
    status: 'running' as const,
    taint: 'clean' as const,
    llmCalls: 0,
    toolCalls: 0,
    costMicroUsd: 0,
    lastEventSeq: 0,
  }
  const after = (type: string, payload: Record<string, unknown>): string =>
    project(clean, type, JSON.stringify({ schemaVersion: 1, ...payload }), 1, '2026-11-12T00:00:00.000Z', (ref) => callTaints(views, ref)).taint
  // A sandbox tool's call always taints, whatever a view says of it: the
  // runner marks every call it logs, refused or not.
  assert.equal(callTaints(views, 'sandbox.exec'), true)
  assert.equal(after('tool.call', { ticketId: 't1', toolRef: 'sandbox.exec', argsHash: 'h', quarantine: false }), 'tainted')
  // Another tool's, as its view says.
  assert.equal(after('tool.call', { ticketId: 't2', toolRef: 'pmmcp.scrape', argsHash: 'h', quarantine: false }), 'tainted')
  assert.equal(after('tool.call', { ticketId: 't3', toolRef: 'pmmcp.recall', argsHash: 'h', quarantine: false }), 'clean')
  assert.equal(after('tool.call', { ticketId: 't4', toolRef: 'kernel.delegate', argsHash: 'h', quarantine: false }), 'clean')
  // A delegated child's result, as the child ended.
  const result = { parentRunId: 'run_v', childRunId: 'run_c', status: 'ok', costMicroUsd: 1 }
  assert.equal(after('delegation.result', { ...result, taint: 'tainted' }), 'tainted')
  assert.equal(after('delegation.result', { ...result, taint: 'clean' }), 'clean')
  // A gate's ruling or a result alone taints nothing: only the call.
  assert.equal(after('tool.gate', { toolRef: 'sandbox.exec', decision: 'allow' }), 'clean')
  assert.equal(after('tool.result', { ticketId: 't1', toolRef: 'sandbox.exec', ok: true }), 'clean')
  // And taint never clears.
  const tainted = { ...clean, taint: 'tainted' as const }
  assert.equal(project(tainted, 'tool.call', JSON.stringify({ toolRef: 'pmmcp.recall' }), 2, '2026-11-12T00:00:00.000Z', () => false).taint, 'tainted')
})

test('the shipped fleet declares no sandbox: block, and no shipped agent is offered any sandbox tool', async (t) => {
  // bootKernel hands the run loop the sandbox runner (W1a), which offers a
  // sandbox tool only to a manifest that may hold one and lists it. No
  // shipped manifest does, so what each shipped agent is offered is what it
  // was before: the CEO its two kernel tools, the pair nothing.
  const provider = fakeProvider([0, 1, 2].map(() => anthropicEndTurn({ text: 'done' })))
  const { kernel } = await withKernel(t, {
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  for (const record of kernel.agents.list()) {
    assert.equal(record.manifest.sandbox, undefined, `${record.manifest.id} ships with a sandbox: block`)
  }
  const ran = ['ceo', 'researcher', 'writer']
  for (const agentId of ran) {
    const finished = await runThroughControl(kernel, 'anything', agentId)
    assert.equal(finished['status'], 'ok', `${agentId}: ${String(finished['reason'])}`)
  }
  const offers = provider.requests.map((r) => offeredNames(r.body))
  assert.deepEqual(offers, [['kernel__adopt_plan', 'kernel__delegate'], [], []])
  assert.equal(offers.flat().some((name) => name.startsWith('sandbox__')), false)
})

test('a test fleet worker with a sandbox: block is offered sandbox.exec, runs it through the fake driver, and its second exec waits for a human', async (t) => {
  // BootOptions.agentsDir: the shipped fleet and one tier 2 worker on the
  // trusted domain whose manifest lists sandbox.exec. The daemon's own
  // wiring, end to end: the loop offers the tool, the gate allows the first
  // exec of a clean run, the runner runs one container through the driver
  // boot was handed, logs it, taints the run, and the second exec waits for
  // a human, who denies it.
  const image = `sha256:${'cd'.repeat(32)}`
  const dir = join(tmpdir(t), 'agents')
  const files: Record<string, string> = {
    coder: [
      'id: coder',
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
      '  domain: trusted',
      'memory:',
      '  projectId: aos/agent/coder',
      '',
    ].join('\n'),
  }
  for (const shipped of ['ceo', 'worker-template', 'researcher', 'writer']) {
    files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
  }
  for (const [name, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, name, 'history'), { recursive: true })
    writeFileSync(join(dir, name, 'agent.yaml'), yaml)
    writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
  }
  const driver = fakeSandbox({ imageId: image, probe: { ok: true, version: 'fake 1' }, script: [{ stdout: 'v24.15.0\n', durationMs: 4 }] })
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['node', '--version'] } }),
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['make', 'install'] } }),
    anthropicEndTurn({ text: 'done' }),
  ])
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: (base) => base.replace('  image: aos-worker:test\n', `  image: aos-worker:test\n  imageId: "${image}"\n`),
    agentsDir: dir,
    sandboxDriver: driver,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.equal(fx.config.sandbox.imageId, image)
  assert.equal(kernel.status().subsystems.sandbox.state, 'ok')
  // Egress is built and disabled (kernel.yaml ships egress.enabled false),
  // and this worker holds none: no channel, no grant.
  assert.equal(kernel.status().subsystems.egress.state, 'degraded')

  // While its second exec waits for a human, the daemon's view of the run
  // (run.get, which runs.list shares) is read: the first exec tainted it, as
  // the gate reads it, so the view says so too.
  const client = await connectControl({ port: kernel.port, token: TEST_TOKEN, timeoutMs: 20_000 })
  t.after(() => client.close())
  let asked: Record<string, unknown> | undefined
  let whileAsked: Record<string, unknown> | undefined
  let listed: unknown
  const stop = kernel.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    asked = JSON.parse(row.payload) as Record<string, unknown>
    const id = String(asked['approvalId'])
    void (async () => {
      try {
        whileAsked = (await client.call('run.get', { runId: row.runId })) as Record<string, unknown>
        listed = await client.call('runs.list', {})
      } finally {
        kernel.approvals.resolve(id, mintHumanActor('conn-test'), 'denied')
      }
    })()
  })
  t.after(stop)
  const finished = await runThroughControl(kernel, 'which node, then install', 'coder')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  const runId = String(finished['runId'])
  assert.deepEqual([whileAsked?.['runId'], whileAsked?.['status'], whileAsked?.['taint']], [runId, 'parked', 'tainted'])
  assert.deepEqual(
    (listed as { runId: string; taint: string }[]).filter((r) => r.runId === runId).map((r) => r.taint),
    ['tainted'],
  )

  // Offered to the worker whose manifest lists it, under its provider name.
  assert.deepEqual(offeredNames(provider.requests[0]?.body), ['sandbox__exec'])

  // One container, on the manifest's domain, of the pinned image by id, in
  // the run's own workspace under the trusted mountRoot, with no channel.
  assert.equal(driver.specs.length, 1)
  const spec = driver.specs[0]
  assert.ok(spec !== undefined)
  assert.equal(spec.domain, 'trusted')
  assert.equal(spec.image, image)
  assert.deepEqual(spec.command, ['node', '--version'])
  assert.equal(spec.workspace, join(fx.config.sandbox.domains.trusted.mountRoot, runId))
  assert.equal('channel' in spec, false, 'an exec asks for no channel')
  assert.equal(driver.channels.length, 0)

  // The one run's calls, in order: the boot wrote none of these.
  const logged = rows(fx.dbPath)
  const flow = logged.map((r) => r.type).filter((type) => /^(tool\.|sandbox\.|approval\.)/.test(type))
  assert.deepEqual(flow, [
    'tool.gate',
    'tool.call',
    'sandbox.started',
    'sandbox.killed',
    'tool.result',
    'tool.gate',
    'approval.requested',
    'approval.resolved',
  ])
  const gates = logged.filter((r) => r.type === 'tool.gate').map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.deepEqual(gates.map((g) => [g['toolRef'], g['decision'], g['risk'], g['taint']]), [
    ['sandbox.exec', 'allow', 'write', 'clean'],
    ['sandbox.exec', 'needs-human', 'write', 'tainted'],
  ])
  // The run is tainted by what the container printed: its second exec waited
  // for a human, who was shown what it would run.
  assert.equal(asked?.['toolRef'], 'sandbox.exec')
  assert.equal(asked?.['argsPreview'], '{"command":["make","install"]}')
  const killed = logged.filter((r) => r.type === 'sandbox.killed').map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.deepEqual(killed, [{ schemaVersion: 1, sandboxId: `aos-run-${runId}-1`, reason: 'exited', exitCode: 0 }])
  const [result] = logged.filter((r) => r.type === 'tool.result').map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  assert.equal(result?.['ok'], true)
  assert.match(String(result?.['text']), /^aos-run-\S+ on the trusted domain, no network, exited 0 after 4 ms\n--- stdout \(9 bytes\) ---\nv24\.15\.0\n/)
  // Denied: the model is told, and nothing else ran.
  const third = JSON.stringify(provider.requests[2]?.body)
  assert.ok(third.includes('[denied] a human denied this call'), third.slice(-400))
  assert.equal(kernel.store.verifyChain(kernel.store.readAnchor()).ok, true)
})

// ── egress, wired (egress plan W1) ──────────────────────────────────────────

/** A pinned image id the fake driver holds, so the sandbox probe can pass. */
const EGRESS_IMAGE = `sha256:${'ef'.repeat(32)}`

/** kernel.yaml's sandbox block with that id pinned, and `extra` appended. */
const pinned = (extra = '') => (base: string): string =>
  `${base.replace('  image: aos-worker:test\n', `  image: aos-worker:test\n  imageId: "${EGRESS_IMAGE}"\n`)}${extra}`

/** The payloads of `type` under runs' grants, boot's canary grant's aside (its issued row's purpose is `canary`). */
function runPayloads(dbPath: string, type: string): Record<string, unknown>[] {
  const all = rows(dbPath).map((r) => ({ type: r.type, payload: JSON.parse(r.payload) as Record<string, unknown> }))
  const canaries = new Set(all.filter((r) => r.type === 'proxy.grant.issued' && r.payload['purpose'] === 'canary').map((r) => r.payload['grantId']))
  return all.filter((r) => r.type === type && !canaries.has(r.payload['grantId'])).map((r) => r.payload)
}

/** The proxy.grant.revoked payloads of runs' grants, boot's canary grant's aside. */
const runRevocations = (dbPath: string): Record<string, unknown>[] => runPayloads(dbPath, 'proxy.grant.revoked')

/** The channels of runs' containers, boot's egress canaries' aside. */
const runChannels = (driver: ReturnType<typeof fakeSandbox>): FakeChannel[] => driver.channels.filter((c) => !c.name.startsWith(CANARY_PREFIX))

/**
 * A driver whose daemon answers, holding the pinned image on both VMs, whose
 * containers run boot's egress canaries as the worker image's mux does, so
 * both pass (canaryPlayer; test/egress-boot.test.ts holds them).
 */
const answering = (script: Parameters<typeof fakeSandbox>[0] = {}): ReturnType<typeof fakeSandbox> =>
  fakeSandbox({ imageId: EGRESS_IMAGE, probe: { ok: true, version: 'fake 1' }, play: canaryPlayer(), ...script })

const GITHUB_BINDING = `
egress:
  enabled: true
  bindings:
    github-git:
      host: github.com
      scheme: Basic
      envVar: AOS_GITHUB_TOKEN
      profiles: [git-fetch]
      repos: [op/fixture]
`

/** A binding value in no credential shape: only the kernel's own mask keeps it, and its Basic form, out of the log. */
const GITHUB_VALUE = 'offline-binding-value-4f2a9c71e0'

function egressRows(dbPath: string): Record<string, unknown>[] {
  return rows(dbPath)
    .filter((r) => r.type === 'egress.degraded')
    .map((r) => JSON.parse(r.payload) as Record<string, unknown>)
}

test('with no container runtime, egress is degraded and names the sandbox reason; with egress.enabled false it names the key', async (t) => {
  // Enabled, but no container runtime answers (the fake's default probe).
  {
    const { kernel, fx } = await withKernel(t, { kernelYaml: (base) => `${base}\negress:\n  enabled: true\n` })
    const egress = kernel.status().subsystems.egress
    assert.equal(egress.state, 'degraded')
    assert.match(egress.reason ?? '', /^the sandbox is degraded \(fake: fake driver: no container runtime configured for this test\), and egress serves only a container on the trusted domain: fix the sandbox first/)
    assert.deepEqual(
      egressRows(fx.dbPath).map((r) => [r['check'], r['domain'], r['bindingId']]),
      [['sandbox', undefined, undefined]],
      'one row, for the one check that failed',
    )
    assert.match(String(egressRows(fx.dbPath)[0]?.['reason']), /no container runtime configured for this test/)
  }
  // Enabled, no container runtime, and a binding whose value is unset: the
  // sandbox's failure does not hide the binding's, so each failed check has
  // its row, and the subsystem's reason names both.
  {
    const { kernel, fx } = await withKernel(t, { kernelYaml: (base) => `${base}${GITHUB_BINDING}` })
    assert.equal(kernel.status().subsystems.sandbox.state, 'degraded')
    assert.deepEqual(
      egressRows(fx.dbPath).map((r) => [r['check'], r['bindingId']]),
      [
        ['sandbox', undefined],
        ['binding', 'github-git'],
      ],
    )
    const reason = kernel.status().subsystems.egress.reason ?? ''
    assert.match(reason, /^the sandbox is degraded \(fake: fake driver: no container runtime configured for this test\)/)
    assert.match(reason, /; egress binding github-git \(envVar AOS_GITHUB_TOKEN\) did not resolve: AOS_GITHUB_TOKEN is not set/)
  }
  // Disabled, as kernel.yaml ships it, on a sandbox that is ok, with a
  // binding whose value is set: the key is named, and the value is not read.
  {
    const disabled = GITHUB_BINDING.replace('  enabled: true\n', '  enabled: false\n')
    const { kernel, fx } = await withKernel(t, { kernelYaml: pinned(disabled), sandboxDriver: answering(), env: { AOS_GITHUB_TOKEN: GITHUB_VALUE } })
    assert.equal(kernel.status().subsystems.sandbox.state, 'ok')
    const egress = kernel.status().subsystems.egress
    assert.equal(egress.state, 'degraded')
    assert.match(egress.reason ?? '', /^egress\.enabled is false in config\/kernel\.yaml, so no run is given a channel: set egress\.enabled: true/)
    assert.deepEqual(egressRows(fx.dbPath).map((r) => r['check']), ['config'])
    // A disabled egress resolves no binding's value: no access is recorded for nothing.
    assert.equal(rows(fx.dbPath).filter((r) => r.type === 'secret.accessed').length, 0)
  }
  // Both: every failed check is named, each in a row of its own, and never absent.
  {
    const { kernel, fx } = await withKernel(t)
    assert.equal(kernel.status().subsystems.egress.state, 'degraded')
    assert.deepEqual(egressRows(fx.dbPath).map((r) => r['check']), ['config', 'sandbox'])
    const states = rows(fx.dbPath)
      .filter((r) => r.type === 'subsystem.state')
      .map((r) => JSON.parse(r.payload) as { subsystem: string; state: string })
      .filter((p) => p.subsystem === 'egress')
    assert.deepEqual(states.map((p) => p.state), ['degraded'])
  }
})

test("kernel.yaml's shipped bindings, with egress enabled and AOS_GITHUB_TOKEN held nowhere, leave egress degraded for every run, one whose manifest binds neither included, as kernel.yaml, README and .env.example say", async (t) => {
  // The shipped egress section as written, enabled: its two bindings, and a
  // worker whose manifest has egress but binds neither (a credential-free host).
  const shippedEgress = (parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')) as { egress: Record<string, unknown> }).egress
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: pinned(`\n${stringifyYaml({ egress: { ...shippedEgress, enabled: true } })}`),
    sandboxDriver: answering(),
    agentsDir: testFleet(t, { reacher: egressWorker('reacher', ['  allow: [registry.npmjs.org]']) }),
  })
  assert.equal(kernel.status().subsystems.sandbox.state, 'ok')
  assert.equal(kernel.status().subsystems.egress.state, 'degraded')
  // Each shipped binding failed, by name, and nothing else did: the canaries passed.
  assert.deepEqual(
    egressRows(fx.dbPath).map((r) => [r['check'], r['bindingId']]),
    [
      ['binding', 'github-git'],
      ['binding', 'github-api'],
    ],
  )
  // So the worker that binds neither is refused sandbox.exec, before any human is asked, for the bindings it never named.
  assert.match(
    kernel.sandboxTools.egressRefusal('sandbox.exec', 'reacher') ?? '',
    /^egress is degraded: egress binding github-git \(envVar AOS_GITHUB_TOKEN\) did not resolve: AOS_GITHUB_TOKEN is not set[^;]*; egress binding github-api \(envVar AOS_GITHUB_TOKEN\) did not resolve: AOS_GITHUB_TOKEN is not set[^;]*; no container was started$/,
  )
  // What the operator reads before enabling egress says so, in each place
  // that names the bindings; flattened, a comment's leading `#` dropped.
  const flat = (file: string): string => readFileSync(join(REPO_ROOT, file), 'utf8').replace(/^[ \t]*# ?/gm, '').replace(/\s+/g, ' ')
  for (const [file, says] of [
    ['config/kernel.yaml', 'unless both resolve (AOS_GITHUB_TOKEN held in the shell or .env), egress is degraded for every run, one whose manifest binds neither included, so remove them before enabling egress without the token'],
    ['README.md', 'with egress enabled, both must resolve or egress is degraded for every run, one whose manifest binds neither included, so hold the token, or remove the two bindings from kernel.yaml before you enable egress without it'],
    ['README.md', 'With egress enabled both bindings must resolve or egress is degraded for every run: hold the token, or remove the two bindings from `config/kernel.yaml` before you enable egress without it'],
    ['.env.example', 'with egress enabled both must resolve or egress is degraded for every run'],
  ] as const) {
    assert.ok(flat(file).includes(says), `${file} does not say: ${says}`)
  }
})

test('degraded lists egress until the probe passes', async (t) => {
  // Enabled, the sandbox ok, and the one binding's value unset: degraded,
  // naming the binding and its envVar, never a value.
  {
    const { kernel, fx } = await withKernel(t, { kernelYaml: pinned(GITHUB_BINDING), sandboxDriver: answering() })
    assert.ok(kernel.degraded.includes('egress'), kernel.degraded.join(', '))
    const [row, ...more] = egressRows(fx.dbPath)
    assert.deepEqual(more, [])
    assert.deepEqual([row?.['check'], row?.['bindingId']], ['binding', 'github-git'])
    assert.match(String(row?.['reason']), /^egress binding github-git \(envVar AOS_GITHUB_TOKEN\) did not resolve: AOS_GITHUB_TOKEN is not set/)
    assert.match(kernel.status().subsystems.egress.reason ?? '', /egress binding github-git \(envVar AOS_GITHUB_TOKEN\) did not resolve/)
  }
  // A value that is no bearer (whitespace in it, or too short to mask) is
  // refused by name, and never echoed.
  for (const [value, problem] of [
    ['two words-0123456789', /AOS_GITHUB_TOKEN contains whitespace/],
    ['short12', /AOS_GITHUB_TOKEN is under \d+ characters, so it cannot be masked/],
  ] as const) {
    const { kernel, fx } = await withKernel(t, { kernelYaml: pinned(GITHUB_BINDING), sandboxDriver: answering(), env: { AOS_GITHUB_TOKEN: value } })
    assert.ok(kernel.degraded.includes('egress'), value)
    const reason = String(egressRows(fx.dbPath)[0]?.['reason'])
    assert.match(reason, problem)
    assert.equal(reason.includes(value), false, 'the reason quoted the value')
  }
  // Every check passes: egress is ok, and no longer listed.
  {
    SecretMask.clear()
    t.after(() => SecretMask.clear())
    const { kernel, fx } = await withKernel(t, { kernelYaml: pinned(GITHUB_BINDING), sandboxDriver: answering(), env: { AOS_GITHUB_TOKEN: GITHUB_VALUE } })
    assert.equal(kernel.status().subsystems.egress.state, 'ok', kernel.status().subsystems.egress.reason ?? '')
    assert.equal(kernel.degraded.includes('egress'), false, kernel.degraded.join(', '))
    assert.deepEqual(egressRows(fx.dbPath), [])
    // Resolved once, at boot, through the broker, with its purpose.
    const accessed = rows(fx.dbPath)
      .filter((r) => r.type === 'secret.accessed')
      .map((r) => JSON.parse(r.payload) as Record<string, unknown>)
    assert.deepEqual(accessed, [{ schemaVersion: 1, id: 'egress.bindings.github-git', purpose: 'egress credential for github.com', source: 'env' }])
    // The value and its Basic form are both masked before anything can quote them.
    const basic = Buffer.from(`x-access-token:${GITHUB_VALUE}`).toString('base64')
    assert.equal(redactString(`x ${GITHUB_VALUE} y`), 'x [REDACTED] y')
    assert.equal(redactString(`Authorization: Basic ${basic}`).includes(basic), false)
    for (const row of rows(fx.dbPath)) {
      assert.equal(row.payload.includes(GITHUB_VALUE) || row.payload.includes(basic), false, row.type)
    }
  }
})

test('a binding read from the vault, a binding id the mask holds, and a long sandbox reason each degrade egress in their own terms, and the boot completes', async (t) => {
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  // secrets.source: vault, the binding's value set in the environment: a
  // binding names an envVar and no vault id, so it is read from the
  // environment only, and refused here, naming both keys, before the broker
  // is asked anything (the D8 fallback included).
  {
    const { kernel, fx } = await withKernel(t, {
      secretsSource: 'vault',
      kernelYaml: pinned(GITHUB_BINDING),
      sandboxDriver: answering(),
      env: { AOS_GITHUB_TOKEN: GITHUB_VALUE },
    })
    assert.equal(kernel.status().subsystems.egress.state, 'degraded')
    const failed = egressRows(fx.dbPath)
    assert.deepEqual(failed.map((r) => [r['check'], r['bindingId']]), [['binding', 'github-git']])
    assert.equal(
      failed[0]?.['reason'],
      'egress binding github-git (envVar AOS_GITHUB_TOKEN) did not resolve: bindings are read from the environment only ' +
        '(envVar AOS_GITHUB_TOKEN; a binding names no vault id), and secrets.source is vault: set secrets.source: env, ' +
        'and AOS_GITHUB_TOKEN in .env',
    )
    const accessed = rows(fx.dbPath).filter((r) => r.type === 'secret.accessed' && r.payload.includes('egress.bindings'))
    assert.deepEqual(accessed, [], 'the broker was asked for a binding')
  }
  // A binding id that holds a value the mask took after kernel.yaml was
  // read: its row is recorded as no binding's, check config, so no row
  // stores a binding id censored.
  {
    const masked = GITHUB_BINDING.replace('    github-git:\n', '    gh-mask5e2c8a1f:\n')
    const { kernel, fx } = await withKernel(t, {
      kernelYaml: pinned(masked),
      sandboxDriver: answering(),
      beforeBoot: () => {
        assert.ok(SecretMask.register('mask5e2c8a1f'))
      },
    })
    assert.equal(kernel.status().subsystems.egress.state, 'degraded')
    const failed = egressRows(fx.dbPath)
    assert.deepEqual(failed.map((r) => [r['check'], 'bindingId' in r]), [['config', false]])
    for (const row of rows(fx.dbPath)) assert.equal(row.payload.includes('mask5e2c8a1f'), false, row.type)
    SecretMask.clear()
  }
  // A sandbox driver's reason past EGRESS_REASON_BYTES (one of a driver
  // other than docker's, which bounds nothing): the egress.degraded row is
  // cut to its bound, and the boot completes.
  {
    const why = `a long driver text ${'z'.repeat(EGRESS_REASON_BYTES * 2)}`
    const { kernel, fx } = await withKernel(t, {
      kernelYaml: (base) => `${base}\negress:\n  enabled: true\n`,
      sandboxDriver: fakeSandbox({ probe: { ok: false, why } }),
    })
    assert.equal(kernel.status().subsystems.egress.state, 'degraded')
    const failed = egressRows(fx.dbPath)
    assert.deepEqual(failed.map((r) => r['check']), ['sandbox'])
    const reason = String(failed[0]?.['reason'])
    assert.ok(Buffer.byteLength(reason) <= EGRESS_REASON_BYTES, `${String(Buffer.byteLength(reason))} bytes`)
    assert.match(reason, /^the sandbox is degraded \(fake: a long driver text z+…$/)
    assert.equal(kernel.status().subsystems.egress.reason, reason)
  }
  // The same long driver text and one unresolved binding: the first failed
  // check, whole at its row's bound, does not fit beside the count of the
  // rest, so egress's reason is that check cut to fit, then the count: never
  // the count alone, naming no failed check.
  {
    const why = `a long driver text ${'z'.repeat(EGRESS_REASON_BYTES * 2)}`
    const { kernel, fx } = await withKernel(t, {
      kernelYaml: (base) => `${base}${GITHUB_BINDING}`,
      sandboxDriver: fakeSandbox({ probe: { ok: false, why } }),
    })
    assert.deepEqual(egressRows(fx.dbPath).map((r) => r['check']), ['sandbox', 'binding'])
    const reason = kernel.status().subsystems.egress.reason ?? ''
    assert.ok(Buffer.byteLength(reason) <= EGRESS_REASON_BYTES, `${String(Buffer.byteLength(reason))} bytes`)
    assert.ok(reason.startsWith('the sandbox is degraded (fake: a long driver text'), reason.slice(0, 80))
    assert.ok(
      reason.endsWith("…; and 1 more failed egress check(s), each named in this boot's egress.degraded rows"),
      reason.slice(-120),
    )
  }
})

test("many unresolved bindings boot degraded: each named in its own row, and egress's reason bounded, the rest counted", async (t) => {
  // 260 bindings of 55-character ids and 52-character envVars, none set:
  // each failure's row is bounded on its own, and the subsystem's reason,
  // echoed into subsystem.state, status.get and every exec refusal, names
  // the first ones whole and counts the rest, never 70 KB past the store's
  // limit, which would refuse the boot it describes.
  const count = 260
  const id = (i: number): string => `binding-${String(i).padStart(3, '0')}-`.padEnd(55, 'x')
  const envVar = (i: number): string => `AOS_BINDING_${String(i).padStart(3, '0')}_`.padEnd(52, 'X')
  const bindings = Array.from(
    { length: count },
    (_, i) =>
      `    ${id(i)}:\n      host: github.com\n      scheme: Bearer\n      envVar: ${envVar(i)}\n      profiles: [git-fetch]\n      repos: [op/r${String(i)}]\n`,
  ).join('')
  // A worker whose manifest has egress (a credential-free host, so none of
  // the 260 is its own). Every exec refusal of it echoes EgressState's
  // reason (tool.gate's reason and tool.result's text, both unbounded
  // strings), so that reason, and not only the subsystem's, is the bounded
  // one. Its model calls sandbox__exec though it is not offered.
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['npm', 'ci'] } }),
    anthropicEndTurn({ text: 'refused' }),
  ])
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: pinned(`\negress:\n  enabled: true\n  bindings:\n${bindings}`),
    sandboxDriver: answering(),
    agentsDir: testFleet(t, { reacher: egressWorker('reacher', ['  allow: [registry.npmjs.org]']) }),
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  const egress = kernel.status().subsystems.egress
  assert.equal(egress.state, 'degraded')
  const reason = egress.reason ?? ''
  assert.ok(Buffer.byteLength(reason) <= EGRESS_REASON_BYTES, `${String(Buffer.byteLength(reason))} bytes`)
  assert.match(reason, /^egress binding binding-000-x+ \(envVar AOS_BINDING_000_X+\) did not resolve: AOS_BINDING_000_X+ is not set/)
  const shown = reason.match(/egress binding binding-\d{3}-x+ \(envVar/g)?.length ?? 0
  assert.ok(shown >= 1 && shown < count, `${String(shown)} shown`)
  assert.match(reason, new RegExp(`; and ${String(count - shown)} more failed egress check\\(s\\), each named in this boot's egress\\.degraded rows$`))
  // Every failure has its row, naming its binding.
  const failed = egressRows(fx.dbPath)
  assert.equal(failed.length, count)
  assert.deepEqual(
    failed.map((r) => r['bindingId']),
    Array.from({ length: count }, (_, i) => id(i)),
  )
  // The subsystem.state row holds the same bounded reason.
  const [state] = rows(fx.dbPath)
    .filter((r) => r.type === 'subsystem.state')
    .map((r) => JSON.parse(r.payload) as { subsystem: string; state: string; reason?: string })
    .filter((p) => p.subsystem === 'egress')
  assert.deepEqual([state?.state, state?.reason], ['degraded', reason])
  // The runner the loop holds refuses its exec with that bounded reason,
  // before the gate as at the offer: a reason of every binding joined would
  // make a tool.gate row past the store's limit, and end the run in error.
  const refusal = kernel.sandboxTools.egressRefusal('sandbox.exec', 'reacher', 'run_bounded')
  assert.equal(refusal, `egress is degraded: ${reason}; no container was started`)
  assert.equal(kernel.sandboxTools.egressRefusal('sandbox.exec', 'reacher'), refusal)
  // So the run is offered nothing, its model's call of the tool anyway is
  // refused as one not offered, never run, and the run ends ok.
  const finished = await runThroughControl(kernel, 'install', 'reacher')
  assert.equal(finished['status'], 'ok', String(finished['reason']))
  assert.deepEqual(offeredNames(provider.requests[0]?.body), [], 'the tool was offered')
  assert.equal(rows(fx.dbPath).filter((r) => r.type === 'tool.call' || (r.type === 'sandbox.started' && !r.payload.includes(CANARY_PREFIX))).length, 0)
  assert.deepEqual(kernel.sandboxTools.liveGrants(), [])
})

test('boot refuses a binding whose envVar is a provider key, naming the binding and the provider', async (t) => {
  // KernelConfig never sees providers.yaml, so it parses; boot, where both
  // files are in hand, refuses before it resolves anything or writes a row.
  const fx = fixture(t, {
    kernelYaml: (base) =>
      `${base}\negress:\n  bindings:\n    github-git:\n      host: github.com\n      scheme: Basic\n      envVar: ANTHROPIC_API_KEY\n      profiles: [git-fetch]\n      repos: [op/fixture]\n`,
  })
  assert.equal(fx.config.egress.bindings['github-git']?.envVar, 'ANTHROPIC_API_KEY')
  let refusal: unknown
  let booted: Awaited<ReturnType<typeof bootKernel>> | undefined
  try {
    booted = await bootKernel({
      config: fx.config,
      repoRoot: REPO_ROOT,
      providers: fx.providers,
      toolViews: fx.toolViews,
      env: { AOS_CONTROL_TOKEN: TEST_TOKEN, ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b' },
      sandboxDriver: fakeSandbox(),
    })
  } catch (e) {
    refusal = e
  }
  await booted?.shutdown()
  assert.equal(booted, undefined, 'a binding on a provider key booted')
  assert.ok(refusal instanceof ConfigError, `refused with ${String(refusal)}`)
  assert.match(
    refusal.message,
    /egress\.bindings\.github-git\.envVar ANTHROPIC_API_KEY is the key of provider anthropic\/claude-sonnet-5 \(auth\.envVar in providers\.yaml\), and the binding would send it to github\.com/,
  )
  assert.equal(refusal.message.includes('offline-fixture-credential-9c1f0b'), false)
  // Refused before the store: nothing was written.
  assert.equal(existsSync(fx.dbPath), false, 'the refused boot wrote an event log')
})

test("a booted kernel serves a trusted worker's exec over its channel: the grant before the spawn, the binding's Basic credential from the broker on the bound host alone, and the chain verifies", async (t) => {
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const dir = join(tmpdir(t), 'agents')
  const files: Record<string, string> = {
    fetcher: [
      'id: fetcher',
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
      '  domain: trusted',
      'egress:',
      '  bind: [github-git]',
      'memory:',
      '  projectId: aos/agent/fetcher',
      '',
    ].join('\n'),
  }
  for (const shipped of ['ceo', 'worker-template']) {
    files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
  }
  for (const [name, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, name, 'history'), { recursive: true })
    writeFileSync(join(dir, name, 'agent.yaml'), yaml)
    writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
  }
  const order: string[] = []
  const up = fakeUpstream((step) => order.push(step))
  const driver = answering({ script: [{ hangs: true }] })
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['git', 'fetch'] } }),
    anthropicEndTurn({ text: 'fetched' }),
  ])
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: pinned(GITHUB_BINDING),
    agentsDir: dir,
    sandboxDriver: driver,
    egressUpstream: up.upstream,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b', AOS_GITHUB_TOKEN: GITHUB_VALUE },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.equal(kernel.status().subsystems.egress.state, 'ok', kernel.status().subsystems.egress.reason ?? '')
  kernel.store.subscribe((row) => {
    if (row.type === 'proxy.decision' || row.type.startsWith('proxy.grant.') || row.type.startsWith('sandbox.')) order.push(row.type)
  })
  const finished = runThroughControl(kernel, 'fetch the fixture', 'fetcher')
  await until(() => runChannels(driver).length === 1, 'the channel', 20_000)
  const mux = new FakeMux(runChannels(driver)[0]!)
  await mux.ready()
  const answer = await mux.request('GET http://github.com/op/fixture.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n\r\n')
  assert.match(answer, /^HTTP\/1\.1 200 /)
  mux.exit(0)
  driver.simulateExit(runChannels(driver)[0]!.name)
  const done = await finished
  assert.equal(done['status'], 'ok', String(done['reason']))

  assert.deepEqual(
    order.filter((step) => step !== 'sandbox.started' && step !== 'sandbox.killed'),
    ['proxy.grant.issued', 'proxy.decision', 'resolve4 github.com', 'dial 140.82.112.3', 'proxy.grant.revoked'],
  )
  assert.ok(order.indexOf('proxy.grant.issued') < order.indexOf('sandbox.started'))
  const basic = Buffer.from(`x-access-token:${GITHUB_VALUE}`).toString('base64')
  const seen = up.seen[0]
  const auth: string[] = []
  for (let i = 0; i + 1 < (seen?.rawHeaders.length ?? 0); i += 2) if (seen?.rawHeaders[i]?.toLowerCase() === 'authorization') auth.push(seen.rawHeaders[i + 1] ?? '')
  assert.deepEqual(auth, [`Basic ${basic}`])
  for (const row of rows(fx.dbPath)) {
    assert.equal(row.payload.includes(GITHUB_VALUE) || row.payload.includes(basic), false, row.type)
  }
  assert.equal(kernel.store.verifyChain(kernel.store.readAnchor()).ok, true)
})

/** A test fleet: the shipped ceo and worker-template, and each manifest given, in a temp agents dir. */
function testFleet(t: Parameters<typeof tmpdir>[0], manifests: Record<string, readonly string[]>): string {
  const dir = join(tmpdir(t), 'agents')
  const files: Record<string, string> = {}
  for (const [name, lines] of Object.entries(manifests)) files[name] = [...lines, ''].join('\n')
  for (const shipped of ['ceo', 'worker-template']) {
    files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
  }
  for (const [name, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, name, 'history'), { recursive: true })
    writeFileSync(join(dir, name, 'agent.yaml'), yaml)
    writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
  }
  return dir
}

/** A tier 2 trusted worker that lists sandbox.exec, with `egress` (its manifest lines) appended. */
function egressWorker(id: string, egress: readonly string[]): readonly string[] {
  return [
    `id: ${id}`,
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
    '  domain: trusted',
    'egress:',
    ...egress,
    'memory:',
    `  projectId: aos/agent/${id}`,
  ]
}

test("two bindings on two hosts: each host is sent its own binding's credential, in its own scheme and user, and no row holds either", async (t) => {
  // A Bearer binding on github.com and a Basic one on gitlab.com whose user
  // is not GitHub's default: the credential injector reads the binding the
  // route names (never another's), writes each scheme as its own, and boot
  // masks the Basic form with the binding's own user, so a host that echoes
  // the header it was sent puts nothing a row would keep.
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const bearerValue = 'offline-bearer-value-7d3e91a0c2'
  const basicValue = 'offline-basic-value-0b8c4e2f19'
  const kernelYaml = pinned(`
egress:
  enabled: true
  bindings:
    github-bearer:
      host: github.com
      scheme: Bearer
      envVar: AOS_GITHUB_BEARER
      profiles: [git-fetch]
      repos: [op/fixture]
    lab-basic:
      host: gitlab.com
      scheme: Basic
      basicUser: aos-bot
      envVar: AOS_LAB_TOKEN
      profiles: [git-fetch]
      repos: [op/other]
`)
  const dir = testFleet(t, { fetcher: egressWorker('fetcher', ['  bind: [github-bearer, lab-basic]']) })
  // Each host answers with the Authorization it was sent: an echo the worker
  // then prints, as a careless script would.
  const echo = (req: Parameters<NonNullable<Parameters<typeof fakeUpstream>[1]>>[0], res: Parameters<NonNullable<Parameters<typeof fakeUpstream>[1]>>[1]): void => {
    res.writeHead(200, { 'content-type': 'text/plain' }).end(`you sent ${String(req.headers.authorization)}`)
  }
  const up = fakeUpstream(() => undefined, echo)
  const driver = answering({ script: [{ hangs: true }] })
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['git', 'fetch', '--all'] } }),
    anthropicEndTurn({ text: 'fetched' }),
  ])
  const { kernel, fx } = await withKernel(t, {
    kernelYaml,
    agentsDir: dir,
    sandboxDriver: driver,
    egressUpstream: up.upstream,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b', AOS_GITHUB_BEARER: bearerValue, AOS_LAB_TOKEN: basicValue },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.equal(kernel.status().subsystems.egress.state, 'ok', kernel.status().subsystems.egress.reason ?? '')
  const finished = runThroughControl(kernel, 'fetch both', 'fetcher')
  await until(() => runChannels(driver).length === 1, 'the channel', 20_000)
  const mux = new FakeMux(runChannels(driver)[0]!)
  await mux.ready()
  const answers: string[] = []
  for (const [host, repo] of [
    ['github.com', 'op/fixture'],
    ['gitlab.com', 'op/other'],
  ] as const) {
    answers.push(
      await mux.request(`GET http://${host}/${repo}.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: ${host}\r\n\r\n`),
    )
  }
  for (const answer of answers) {
    assert.match(answer, /^HTTP\/1\.1 200 /)
    mux.stdout(`${answer}\n`)
  }
  mux.exit(0)
  driver.simulateExit(runChannels(driver)[0]!.name)
  const done = await finished
  assert.equal(done['status'], 'ok', String(done['reason']))

  // Each host saw exactly one Authorization, its own binding's.
  const sent = (want: string): string[] => {
    const out: string[] = []
    for (const seen of up.seen) {
      const pairs: [string, string][] = []
      for (let i = 0; i + 1 < seen.rawHeaders.length; i += 2) pairs.push([seen.rawHeaders[i]?.toLowerCase() ?? '', seen.rawHeaders[i + 1] ?? ''])
      if (!pairs.some(([name, value]) => name === 'host' && value === want)) continue
      for (const [name, value] of pairs) if (name === 'authorization') out.push(value)
    }
    return out
  }
  const basicForm = Buffer.from(`aos-bot:${basicValue}`).toString('base64')
  assert.deepEqual(sent('github.com'), [`Bearer ${bearerValue}`])
  assert.deepEqual(sent('gitlab.com'), [`Basic ${basicForm}`])
  assert.equal(up.seen.length, 2)

  // Boot masked the Basic form under the binding's own user, not GitHub's.
  assert.equal(redactString(`x ${basicForm} y`), 'x [REDACTED] y')
  assert.equal(redactString(`x ${bearerValue} y`), 'x [REDACTED] y')
  assert.equal(redactString(`x ${basicValue} y`), 'x [REDACTED] y')
  // The echo the worker printed reached tool.result censored, and no row
  // holds either value or the Basic form.
  const result = rows(fx.dbPath).find((r) => r.type === 'tool.result')
  assert.ok(result?.payload.includes('you sent'), 'the echo is not in the result')
  for (const row of rows(fx.dbPath)) {
    for (const secret of [bearerValue, basicValue, basicForm]) {
      assert.equal(row.payload.includes(secret), false, `${row.type} holds ${secret.slice(0, 12)}…`)
    }
  }
  assert.equal(kernel.store.verifyChain(kernel.store.readAnchor()).ok, true)
})

test("a booted kernel refuses a mux whose ready report says its self-test reached the Mac's loopback: no go, the container killed by name, the grant revoked as a violation, and nothing served", async (t) => {
  // The judge boot hands every session (src/egress/ready.ts acceptReady) is
  // the kernel's one check, before the command runs, that the container's
  // network is the --network none it asked for. One that accepted every
  // report would send go to a container that reached 192.168.5.2:8766.
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const dir = testFleet(t, { fetcher: egressWorker('fetcher', ['  bind: [github-git]']) })
  const up = fakeUpstream(() => undefined)
  const driver = answering({ script: [{ hangs: true }] })
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['git', 'fetch'] } }),
    anthropicEndTurn({ text: 'the exec was refused' }),
  ])
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: pinned(GITHUB_BINDING),
    agentsDir: dir,
    sandboxDriver: driver,
    egressUpstream: up.upstream,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b', AOS_GITHUB_TOKEN: GITHUB_VALUE },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.equal(kernel.status().subsystems.egress.state, 'ok', kernel.status().subsystems.egress.reason ?? '')
  const finished = runThroughControl(kernel, 'fetch the fixture', 'fetcher')
  await until(() => runChannels(driver).length === 1, 'the channel', 20_000)
  const name = runChannels(driver)[0]!.name
  const mux = new FakeMux(runChannels(driver)[0]!)
  mux.send({ type: 'ready', flow: 0, payload: refusedReport('reached') })
  const done = await finished
  assert.equal(done['status'], 'ok', String(done['reason']))

  assert.equal(mux.kernelFrames.includes('go'), false, 'the container was sent go, so its command ran')
  assert.deepEqual(driver.kills, [name], 'the container was not killed by name, once')
  const payloadsOf = (type: string): Record<string, unknown>[] =>
    rows(fx.dbPath).filter((r) => r.type === type).map((r) => JSON.parse(r.payload) as Record<string, unknown>)
  const revoked = runRevocations(fx.dbPath)
  assert.deepEqual(revoked.map((r) => [r['reason'], r['detail']]), [
    ['violation', "the mux's ready report was refused: the self-test reached 1 of what it must not (192.168.5.2:8766)"],
  ])
  assert.deepEqual(payloadsOf('tool.result').map((r) => r['ok']), [false])
  assert.deepEqual(runPayloads(fx.dbPath, 'proxy.decision'), [], 'a request was judged under a refused grant')
  assert.equal(up.seen.length, 0, 'an upstream was sent a request')
  assert.deepEqual(kernel.sandboxTools.liveGrants(), [])
})

test("boot hands each session kernel.yaml's egress.limits: the go frame carries its frameMaxBytes and maxFlows, and a request past its maxRequests ends the grant", async (t) => {
  // Every other boot row runs on the defaults, which a wiring that dropped
  // the operator's bounds would keep: small ones, held from the go frame the
  // mux reads and from the revocation a second request earns.
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const dir = testFleet(t, { fetcher: egressWorker('fetcher', ['  bind: [github-git]']) })
  const up = fakeUpstream(() => undefined)
  const driver = answering({ script: [{ hangs: true }] })
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['git', 'fetch'] } }),
    anthropicEndTurn({ text: 'fetched once' }),
  ])
  const limited = `${GITHUB_BINDING}  limits:\n    frameMaxBytes: 4096\n    maxFlows: 2\n    maxRequests: 1\n`
  const { kernel, fx } = await withKernel(t, {
    kernelYaml: pinned(limited),
    agentsDir: dir,
    sandboxDriver: driver,
    egressUpstream: up.upstream,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b', AOS_GITHUB_TOKEN: GITHUB_VALUE },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.deepEqual(
    { frameMaxBytes: fx.config.egress.limits.frameMaxBytes, maxFlows: fx.config.egress.limits.maxFlows, maxRequests: fx.config.egress.limits.maxRequests },
    { frameMaxBytes: 4096, maxFlows: 2, maxRequests: 1 },
  )
  assert.equal(kernel.status().subsystems.egress.state, 'ok', kernel.status().subsystems.egress.reason ?? '')
  const finished = runThroughControl(kernel, 'fetch the fixture', 'fetcher')
  await until(() => runChannels(driver).length === 1, 'the channel', 20_000)
  const name = runChannels(driver)[0]!.name
  const mux = new FakeMux(runChannels(driver)[0]!)
  await mux.ready()
  assert.deepEqual(mux.limits, { frameMaxBytes: 4096, maxFlows: 2 })
  const first = await mux.request('GET http://github.com/op/fixture.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n\r\n')
  assert.match(first, /^HTTP\/1\.1 200 /)
  // A second flow, one past maxRequests: the grant ends at its open.
  mux.send({ type: 'open', flow: 2, payload: new Uint8Array(0) })
  const done = await finished
  assert.equal(done['status'], 'ok', String(done['reason']))
  const revoked = runRevocations(fx.dbPath)
  assert.deepEqual(revoked.map((r) => [r['reason'], r['limit']]), [['limit', 'maxRequests']])
  assert.deepEqual(driver.kills, [name], 'the container was not killed by name, once')
  assert.equal(up.seen.length, 1, 'the request past maxRequests was sent')
})

test('egressUpstreamOptions reads its idle bound from kernel.yaml and its connect deadline from EGRESS_CONNECT_TIMEOUT_MS', () => {
  // The helper alone; that boot builds its upstream through it is held by
  // the test after this one.
  const base = parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')) as Record<string, unknown>
  const egress = (base['egress'] ?? {}) as Record<string, unknown>
  const config = parseKernelConfig({ ...base, egress: { ...egress, limits: { idleMs: 12_345 } } }, { repoRoot: REPO_ROOT })
  assert.deepEqual(egressUpstreamOptions(config), { connectTimeoutMs: EGRESS_CONNECT_TIMEOUT_MS, idleTimeoutMs: 12_345 })
  assert.equal(EGRESS_CONNECT_TIMEOUT_MS, 10_000)
  const shipped = parseKernelConfig(base, { repoRoot: REPO_ROOT })
  assert.deepEqual(egressUpstreamOptions(shipped), { connectTimeoutMs: 10_000, idleTimeoutMs: shipped.egress.limits.idleMs })
})

test("with no upstream injected, boot builds its own from egressUpstreamOptions(config), kernel.yaml's idle bound and EGRESS_CONNECT_TIMEOUT_MS, and a trusted run's request goes through it", async (t) => {
  // Every other test that sends traffic injects a whole upstream, which
  // hides the timeouts boot builds the daemon's under. Here boot builds its
  // own (productionUpstream) over in-process deps in systemUpstreamDeps's
  // place: the options it hands them are held, and so is that the upstream
  // made from them is the one a run's session sends through.
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const dir = join(tmpdir(t), 'agents')
  const fetcher = [
    'id: fetcher',
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
    '  domain: trusted',
    'egress:',
    '  bind: [github-git]',
    'memory:',
    '  projectId: aos/agent/fetcher',
    '',
  ].join('\n')
  const files: Record<string, string> = { fetcher }
  for (const shipped of ['ceo', 'worker-template']) {
    files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
  }
  for (const [name, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, name, 'history'), { recursive: true })
    writeFileSync(join(dir, name, 'agent.yaml'), yaml)
    writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
  }
  const up = fakeUpstreamDeps()
  const driver = answering({ script: [{ hangs: true }] })
  const provider = fakeProvider([
    anthropicToolUse({ name: 'sandbox__exec', input: { command: ['git', 'fetch'] } }),
    anthropicEndTurn({ text: 'fetched' }),
  ])
  const binding = GITHUB_BINDING.replace('  enabled: true\n', '  enabled: true\n  limits:\n    idleMs: 12345\n')
  assert.notEqual(binding, GITHUB_BINDING)
  const { kernel } = await withKernel(t, {
    kernelYaml: pinned(binding),
    agentsDir: dir,
    sandboxDriver: driver,
    egressUpstreamDeps: up.deps,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b', AOS_GITHUB_TOKEN: GITHUB_VALUE },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.equal(kernel.config.egress.limits.idleMs, 12_345)
  assert.deepEqual(up.limits, [{ connectTimeoutMs: EGRESS_CONNECT_TIMEOUT_MS, idleTimeoutMs: 12_345 }])
  assert.equal(kernel.status().subsystems.egress.state, 'ok', kernel.status().subsystems.egress.reason ?? '')
  const finished = runThroughControl(kernel, 'fetch the fixture', 'fetcher')
  await until(() => runChannels(driver).length === 1, 'the channel', 20_000)
  const mux = new FakeMux(runChannels(driver)[0]!)
  await mux.ready()
  const answer = await mux.request('GET http://github.com/op/fixture.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n\r\n')
  assert.match(answer, /^HTTP\/1\.1 200 /)
  mux.exit(0)
  driver.simulateExit(runChannels(driver)[0]!.name)
  const done = await finished
  assert.equal(done['status'], 'ok', String(done['reason']))
  assert.deepEqual(up.steps, ['resolve4 github.com', 'dial 140.82.112.3'])
  assert.deepEqual(up.seen.map((r) => [r.method, r.url]), [['GET', '/op/fixture.git/info/refs?service=git-upload-pack']])
  // Built once, at boot.
  assert.equal(up.limits.length, 1)
  assert.equal(kernel.store.verifyChain(kernel.store.readAnchor()).ok, true)
})

test("the daemon hands the sandbox runner boot's egress verdict: a worker whose manifest names egress is offered sandbox.exec while egress is ok, and not while it is degraded", async (t) => {
  // Boot decides once whether egress can serve a grant, and the runner reads
  // that verdict, never one of its own: a kernel whose egress is degraded
  // (egress.enabled false, as shipped) shows such a worker no sandbox tool,
  // since every exec of it would be refused with the egress reason.
  const fleet = (): string => {
    const dir = join(tmpdir(t), 'agents')
    const files: Record<string, string> = {
      reacher: [
        'id: reacher',
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
        '  domain: trusted',
        'egress:',
        '  allow: [registry.npmjs.org]',
        'memory:',
        '  projectId: aos/agent/reacher',
        '',
      ].join('\n'),
    }
    for (const shipped of ['ceo', 'worker-template']) {
      files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
    }
    for (const [name, yaml] of Object.entries(files)) {
      mkdirSync(join(dir, name, 'history'), { recursive: true })
      writeFileSync(join(dir, name, 'agent.yaml'), yaml)
      writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
    }
    return dir
  }
  for (const [label, extra, state, names] of [
    ['egress degraded', '', 'degraded', []],
    ['egress ok', '\negress:\n  enabled: true\n', 'ok', ['sandbox__exec']],
  ] as const) {
    const provider = fakeProvider([anthropicEndTurn({ text: 'nothing to do' })])
    const { kernel } = await withKernel(t, {
      kernelYaml: pinned(extra),
      agentsDir: fleet(),
      sandboxDriver: answering(),
      env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b' },
      fetch: provider.fetch,
      beforeBoot: (f) => {
        writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
      },
    })
    assert.equal(kernel.status().subsystems.egress.state, state, label)
    const finished = await runThroughControl(kernel, 'anything', 'reacher')
    assert.equal(finished['status'], 'ok', `${label}: ${String(finished['reason'])}`)
    assert.deepEqual(offeredNames(provider.requests[0]?.body), [...names], label)
  }
})
