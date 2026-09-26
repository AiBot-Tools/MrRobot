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

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'
import { WebSocket } from 'ws'

import { bootKernel, configHash, STUBS, SUBSYSTEM_ORDER } from '../src/kernel.js'
import { isClean, projectRecovery } from '../src/events/projections.js'
import { rebuildFromLog as rebuildApprovals } from '../src/policy/approvals.js'
import { rebuildFromLog as rebuildQuarantine } from '../src/policy/quarantine.js'
import { NotImplementedError } from '../src/errors.js'
import { EventStore } from '../src/events/store.js'
import { readAllRows } from '../src/events/chain.js'
import { parseKernelConfig } from '../src/config.js'
import { readAnchor } from '../src/events/anchor.js'
import { CONTROL_PATH } from '../src/control/auth.js'
import { VERSION } from '../src/version.js'
import { fixture, REPO_ROOT, TEST_TOKEN, verifyAt, withKernel } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'
import { join } from 'node:path'
import { fakeSandbox } from './helpers/fake-sandbox.js'
import { anthropicEndTurn, fakeProvider } from './helpers/fake-provider.js'
import { freshProbe } from './helpers/probe.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { connectControl } from '../src/cli/client.js'
import { mockMcp } from './helpers/mock-mcp.js'

/** Rows of a closed kernel log, read back read-only. */
function rows(dbPath: string): { seq: number; type: string; payload: string }[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return store.query().map((r) => ({ seq: r.seq, type: r.type, payload: r.payload }))
  } finally {
    store.close()
  }
}

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

/**
 * Start a run over the real control socket and wait for it to finish.
 *
 * Through the wire rather than through the surface object: this is the path
 * `aos run` takes, so a test that exercises it proves the protocol as well as
 * the loop.
 */
async function runThroughControl(
  kernel: Awaited<ReturnType<typeof bootKernel>>,
  prompt: string,
): Promise<Record<string, unknown>> {
  const client = await connectControl({ port: kernel.port, token: TEST_TOKEN, timeoutMs: 120_000 })
  try {
    // Buffered, for the same reason the CLI buffers: the daemon broadcasts as
    // it appends, so a fast run can finish before the reply naming it is
    // parsed. Matching only on an id we do not yet know loses that event.
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
    const alreadyDone = early.get(started.runId)
    if (alreadyDone !== undefined) settle(alreadyDone)

    // Bounded: a run that never finishes must fail with what the log says, not
    // hang the file until the runner gives up with no diagnosis.
    const timeout = new Promise<Record<string, unknown>>((_, reject) => {
      const timer = setTimeout(() => reject(new Error(`run ${started.runId} did not finish`)), 20_000)
      timer.unref?.()
    })
    return await Promise.race([finished, timeout])
  } finally {
    client.close()
  }
}

test('boots DEGRADED with hub, secrets and sandbox degraded, each with a reason, and control ok, over a real WS connection', async (t) => {
  const { kernel, fx } = await withKernel(t)

  const status = kernel.status()
  // One degraded subsystem degrades the kernel. Anything else would be a
  // status line that reads fine while the vault is unreachable.
  assert.equal(status.state, 'degraded')
  assert.equal(status.kernel.version, VERSION)

  // Each degraded subsystem names WHY. "degraded" with no reason is an
  // operator opening a debugger.
  for (const name of ['hub', 'secrets', 'sandbox', 'router'] as const) {
    assert.equal(status.subsystems[name].state, 'degraded', name)
    assert.ok((status.subsystems[name].reason ?? '').length > 0, `${name} has no reason`)
  }
  assert.match(status.subsystems.hub.reason ?? '', /PMMCP_TOKEN is not set|did not connect|ECONN|EACCES/)
  assert.match(status.subsystems.secrets.reason ?? '', /no vault/)
  assert.match(status.subsystems.sandbox.reason ?? '', /no container runtime/)
  assert.match(status.subsystems.router.reason ?? '', /no routable model/)

  // Absent is not degraded: egress is not built at all, and it says so in its own
  // words rather than in a status string invented here.
  assert.equal(status.subsystems.egress.state, 'absent')
  assert.match(status.subsystems.egress.reason ?? '', /not implemented/)

  // The scheduler is real now, and ok even with nothing to run — which it says,
  // because "ok" alone would leave an operator wondering whether it found their
  // schedule.
  assert.equal(status.subsystems.scheduler.state, 'ok')
  assert.match(status.subsystems.scheduler.reason ?? '', /no agent declares a schedule/)

  // The two that must be ok for the kernel to be worth talking to.
  assert.equal(status.subsystems.events.state, 'ok')
  assert.equal(status.subsystems.control.state, 'ok')
  assert.deepEqual([...kernel.degraded].sort(), ['egress', 'hub', 'router', 'sandbox', 'secrets'])

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
  assert.equal(status.envFallback, false)
  assert.ok(fx.dataDir.length > 0, 'the fixture has no data dir')
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
  // A first boot on a clean machine has no ~/.aos. The store cannot open a
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

  const openFds = (): number => readdirSync('/proc/self/fd').length
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
  // Offline: the provider is a double and the vault is absent, so the credential
  // comes from the env fallback (D8). No socket leaves the machine.
  const provider = fakeProvider([anthropicEndTurn({ text: 'pong', inputTokens: 1_000, outputTokens: 100 })])
  const KEY = 'offline-fixture-credential-9c1f0b'

  const { kernel, fx } = await withKernel(t, {
    envFallback: true,
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
  const mock = await mockMcp()
  const { kernel, fx } = await withKernel(t, {
    clientFactory: () => Promise.resolve(mock.client),
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
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
  assert.match(kernel.status().subsystems.router.reason ?? '', /envFallback is off|vault/)
  assert.equal(rows(fx.dbPath).filter((r) => r.type === 'secret.accessed').length, 0)

  const finish = await runThroughControl(kernel, 'reply with the word pong')
  assert.equal(finish['status'], 'error')
  assert.equal(finish['costMicroUsd'], 0)
  assert.match(String(finish['reason']), /credential|envFallback|vault/)

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

test('envFallback:true shows secrets degraded in status.get', async (t) => {
  // D8: while env fallback is on, a credential MAY come from the environment
  // rather than the vault. A kernel reporting ready in that state would be
  // hiding exactly the thing an operator needs to know.
  const noVault = await withKernel(t, { envFallback: true })
  assert.equal(noVault.kernel.status().envFallback, true)
  assert.equal(noVault.kernel.status().subsystems.secrets.state, 'degraded')
  assert.equal(noVault.kernel.status().state, 'degraded')

  // With no vault, the reason is the missing vault. That alone would let this
  // test pass for the wrong reason, so the same claim is made again with the
  // vault UP: envFallback must degrade secrets on its own, and say why.
  const mock = await mockMcp()
  const withVault = await withKernel(t, {
    envFallback: true,
    clientFactory: () => Promise.resolve(mock.client),
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
  })
  const status = withVault.kernel.status()
  assert.equal(status.subsystems.hub.state, 'ok', 'the mock hub did not connect')
  assert.equal(status.subsystems.secrets.state, 'degraded')
  assert.match(status.subsystems.secrets.reason ?? '', /envFallback is on/)
  assert.equal(status.state, 'degraded', 'a connected vault made the kernel look ready with fallback on')

  // And with fallback OFF and the vault up, secrets is finally ok — so the
  // degradation above is attributable to the flag and nothing else.
  const clean = await withKernel(t, {
    clientFactory: () => Promise.resolve(mock.client),
    env: { PMMCP_TOKEN: 'unused-because-the-factory-is-injected' },
  })
  assert.equal(clean.kernel.status().subsystems.secrets.state, 'ok')
  assert.equal(clean.kernel.status().envFallback, false)
})
