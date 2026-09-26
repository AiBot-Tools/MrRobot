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
import { existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'
import { WebSocket } from 'ws'

import { bootKernel, configHash, STUBS, SUBSYSTEM_ORDER } from '../src/kernel.js'
import { rebuildFromLog as rebuildApprovals } from '../src/policy/approvals.js'
import { rebuildFromLog as rebuildQuarantine } from '../src/policy/quarantine.js'
import { NotImplementedError } from '../src/errors.js'
import { EventStore } from '../src/events/store.js'
import { parseKernelConfig } from '../src/config.js'
import { readAnchor } from '../src/events/anchor.js'
import { CONTROL_PATH } from '../src/control/auth.js'
import { VERSION } from '../src/version.js'
import { fixture, REPO_ROOT, TEST_TOKEN, verifyAt, withKernel } from './helpers/kernel.js'
import { fakeSandbox } from './helpers/fake-sandbox.js'
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

  // Absent is not degraded: these are not built at all, and they say so in
  // their own words rather than in a status string invented here.
  assert.equal(status.subsystems.scheduler.state, 'absent')
  assert.equal(status.subsystems.egress.state, 'absent')
  assert.match(status.subsystems.scheduler.reason ?? '', /not implemented/)
  assert.match(status.subsystems.egress.reason ?? '', /not implemented/)

  // The two that must be ok for the kernel to be worth talking to.
  assert.equal(status.subsystems.events.state, 'ok')
  assert.equal(status.subsystems.control.state, 'ok')
  assert.deepEqual([...kernel.degraded].sort(), ['egress', 'hub', 'router', 'sandbox', 'scheduler', 'secrets'])

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

test('pending approvals are not rebuilt after restart (documented gap)', async (t) => {
  const { kernel } = await withKernel(t)

  // The gap is REAL and it throws. "Nothing is pending" after a restart would
  // be a dangerous lie: a run parked on a human decision would look answered,
  // and the kernel would behave as though someone had said yes.
  assert.throws(() => rebuildApprovals(), NotImplementedError)
  assert.throws(() => rebuildQuarantine(), NotImplementedError)
  assert.deepEqual(kernel.approvals.pending(), [])

  // And the gap is named where an operator will look, in its own words.
  const listed = STUBS.map((s) => s.id)
  assert.ok(listed.includes('approvals-projection'), listed.join(', '))
  assert.ok(listed.includes('quarantine-projection'))
  for (const stub of STUBS) {
    assert.ok(stub.where.startsWith('src/'), stub.where)
    assert.ok(stub.how.length > 20, `${stub.id} does not say how it refuses`)
  }
  // Every id is unique, so README cannot list one twice and miss another.
  assert.equal(new Set(listed).size, listed.length)
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
