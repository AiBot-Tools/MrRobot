import './helpers/guard.js'

// The Phase 2 live bodies (test/helpers/sandbox-bodies.ts, egress plan L1,
// and test/helpers/egress-bodies.ts, L2), offline, on every npm test: the
// same bodies test/live-sandbox.test.ts and test/live-egress.test.ts run on
// the operator's Mac, here against the fake driver, each container played as
// the worker image would act. A body's assertions are seen to pass here, and
// each a container or a VM can make fail is seen to fail on what it is there
// to catch (a way out of --network none: an interface, a route or a route
// table unread, a target reached, or a connect by address or by name that
// timed out or was refused, a lookup a resolver answered; a network report
// that leaves a target out or puts them out of order; a probe, cat or
// self-test that exits other than 0 or prints no report; a byte the channel
// changed or dropped; a cat that never sees its EOF; a container that never
// says it is up, never beats, or that its kill or a sweep left running; a VM
// that still lists a container its kill ended; a sweep that lists nothing,
// could not list a VM, or whose kill a daemon refused; a kill whose exit is
// not the CLI's 137; a wallclock whose kill reached no daemon, landed late or
// was never needed; no process listed, a command as PID 1, a zombie; a
// self-test that leaves a probe out or that the judge refuses; a canary
// refused, on either domain; an answer from outside the container; and for
// the exit each fault exitActor plays), so a live run that passes means the
// VMs held, not that a check was vacuous. What only the kernel or the driver
// decides is seen only to pass (README "Live sandbox and egress tests" names
// each).
//
// The VMs, offline: a beating container runs until a kill by name reaches it
// (kill, abandon, which sends one, or a sweep's), as a container outlives its
// docker CLI, and until then the fake's `docker ps` lists it on its domain.

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import type { IncomingMessage, ServerResponse } from 'node:http'

import { SecretMask } from '../src/events/redact.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { CANARY_COMMANDS, CANARY_PREFIX } from '../src/runtime/canary.js'
import { PUBLISH_ARGV } from '../src/runtime/sandbox-tools.js'
import type { SandboxDomain, SandboxDriver, SandboxSpec, SweepResult } from '../src/sandbox/driver.js'
import { basicOf, boundRepo, EXIT_PUBLISH, EXIT_REF, exitActor, exitApprovals, exitFleet, exitKernelYaml, exitScript, marked, phase2Exit, pinnedSandbox, quotedHeads, recording, scrubbed, type ExitFault } from './helpers/egress-bodies.js'
import { canaryPlayer, fakeUpstreamDeps, quietReport, refusedReport, type CanaryPlay } from './helpers/fake-egress.js'
import { anthropicToolUse, fakeProvider } from './helpers/fake-provider.js'
import { fakeSandbox, type FakeChannel, type FakeSandbox, type FakeSandboxOptions, type ScriptedExit } from './helpers/fake-sandbox.js'
import { bootOn, fixture, REPO_ROOT } from './helpers/kernel.js'
import { freshProbe } from './helpers/probe.js'
import {
  BEATING,
  BEATING_OUT,
  canariesPass,
  channelInputDestroyed,
  channelRoundTrip,
  clientKilledThenKillByName,
  hostileWallclock,
  INIT_MARK,
  INIT_PROBE,
  initProblems,
  initReaps,
  killedByName,
  NETWORK_MARK,
  NETWORK_PROBE,
  NETWORK_TARGETS,
  networkLine,
  networkNone,
  networkProblems,
  nodeProxyWarning,
  PROXY_MARK,
  proxyProblems,
  type InitReport,
  type NetworkReport,
  type SandboxBodyContext,
} from './helpers/sandbox-bodies.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const IMAGE = `sha256:${'5a'.repeat(32)}`

/** kernel.yaml's shipped egress.limits. */
const EGRESS_LIMITS = Object.freeze({ frameMaxBytes: 65_536, maxFlows: 16, maxHeaderBytes: 16_384, maxRequests: 2_000, maxBytes: 536_870_912, maxDenied: 20, idleMs: 60_000 })

/** What the image's node prints for the network probe in a container that has only its loopback. */
function quietNetwork(): NetworkReport {
  return {
    interfaces: [{ name: 'lo', operstate: 'unknown', addresses: ['127.0.0.1', '::1'] }],
    routes: 0,
    probes: NETWORK_TARGETS.map((t) => ({ target: `${t.host}:${String(t.port)}`, kind: t.kind, reached: false, error: t.kind === 'address' ? 'ENETUNREACH' : 'EAI_AGAIN' })),
    lookup: { error: 'EAI_AGAIN' },
  }
}

/** What it prints for the init probe under --init: docker-init PID 1, the command beneath it, no zombie. */
function reapedInit(): InitReport {
  return { pid1: 'docker-init', self: 7, processes: [{ pid: 1, comm: 'docker-init', state: 'S' }, { pid: 7, comm: 'sh', state: 'S' }, { pid: 9, comm: 'cat', state: 'R' }] }
}

const same = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i])

interface Acting {
  /** The network probe's report; unset, quietNetwork(). */
  readonly network?: NetworkReport
  readonly init?: InitReport
  /** The channel's `cat` changes the byte at this offset. */
  readonly flipAt?: number
  /** No kill by name reaches a beating container, the sweep's included: it beats on, as one on a VM no kill reached would. */
  readonly beatsOn?: boolean
  /** A beating container writes its beat once, and never again, as one whose writes never land where the Mac reads them. */
  readonly beatsOnce?: boolean
  /** The VMs' `docker ps` lists nothing, as one whose output the sweep cannot read (`--quiet` beside `--format`). */
  readonly sweepListsNothing?: boolean
  /** The sweep's kill reports the container killed, and it beats on. */
  readonly sweepMisses?: boolean
  /** A kill by name of a beating container, the sweep's included, lets it exit on its own, 0, as a kill the CLI's exit does not show. */
  readonly killExits0?: boolean
  /** The self-test's report, as the VM's mux would print it; unset, quietReport(). */
  readonly selfTest?: Uint8Array
  /** How boot's canaries are played (canaryPlayer). */
  readonly canary?: CanaryPlay
  /** The proxy probe's two lines, past PROXY_MARK; unset, both refused, as with no channel and nothing at 3128. `<nonce>` is the probe's own. */
  readonly proxy?: readonly [string, string]
  /** A probe, the self-test or `cat` exits with this code, having printed what it would. */
  readonly exits?: Partial<Record<'network' | 'init' | 'selfTest' | 'proxy' | 'cat', number>>
  /** The network probe prints nothing. */
  readonly networkSilent?: boolean
  /** `cat` never ends on its stdin's EOF, so its wallclock ends it. */
  readonly catIgnoresEof?: boolean
  /** `cat` drops the first byte it reads, and ends on EOF. */
  readonly catShort?: boolean
  /** A beating container beats but never writes /workspace/up. */
  readonly neverUp?: boolean
  /** The VMs' `docker ps` lists a container still once a kill by name or its wallclock ended it, as a VM whose listing never drops it. */
  readonly listsKilled?: boolean
  /** The hostile `sleep 600` exits 0 on its own, at once. */
  readonly sleepExits0?: boolean
  /** Every run ends a minute later than it would, as on a VM whose kills land late. */
  readonly endsLate?: boolean
  /**
   * The body's sweep number `at` (0 its first) reports `unlisted`: the
   * hostile VM could not be listed, as a daemon that refuses `docker ps`,
   * whatever it swept besides; or `failed`: each name it was asked for listed
   * and its kill refused, as a daemon that refuses `docker kill`, sweeping
   * nothing.
   */
  readonly sweepFault?: { readonly at: number; readonly reports: 'unlisted' | 'failed' }
}

/** The beating containers the VMs run, by name: each runs until a kill by name lands on it. */
type Beating = Map<string, { readonly domain: SandboxDomain; readonly stop: () => void }>

/** What the VMs hold besides: the containers `docker ps` lists though they were ended (listsKilled), and the fake driver, once made. */
interface Vms {
  readonly beating: Beating
  readonly ghosts: Map<string, SandboxDomain>
  fake?: FakeSandbox
}

/**
 * Each container of the bodies played as the image acts, by its command:
 * the probes print their reports, `cat` copies its stdin to its stdout until
 * the stdin ends, a beating container writes its workspace every few
 * milliseconds (its stdout too, on a channel, until its reader goes away)
 * and runs until a kill by name reaches it, `sleep` runs until killed, the
 * self-test prints its report, the canaries are played as boot's are
 * (canaryPlayer), and the proxy probe's fetches are refused.
 */
function actor(t: TestContext, vms: Vms, acting: Acting = {}): NonNullable<FakeSandboxOptions['play']> {
  const canaries = canaryPlayer(acting.canary)
  const { beating } = vms
  const exit = (what: keyof NonNullable<Acting['exits']>): { exitCode?: number } => {
    const code = acting.exits?.[what]
    return code === undefined ? {} : { exitCode: code }
  }
  return (spec: SandboxSpec, container: FakeChannel | undefined): Promise<ScriptedExit> | undefined => {
    if (spec.name.startsWith(CANARY_PREFIX)) return canaries(spec, container)
    const command = spec.command
    if (same(command, ['node', '-e', NETWORK_PROBE])) {
      return Promise.resolve({ stdout: acting.networkSilent === true ? '' : `${NETWORK_MARK}${JSON.stringify(acting.network ?? quietNetwork())}\n`, ...exit('network') })
    }
    if (same(command, INIT_PROBE)) {
      const init = acting.init ?? reapedInit()
      const stats = init.processes.map((p) => `${INIT_MARK}stat ${String(p.pid)} (${p.comm}) ${p.state} 1 1 1 0 -1\n`).join('')
      return Promise.resolve({ stdout: `${INIT_MARK}pid1 ${init.pid1}\n${INIT_MARK}self ${String(init.self)}\n${stats}`, ...exit('init') })
    }
    if (same(command, CANARY_COMMANDS.hostile)) return Promise.resolve({ stdout: `${Buffer.from(acting.selfTest ?? quietReport()).toString('ascii')}\n`, ...exit('selfTest') })
    if (same(command, ['cat']) && container !== undefined) {
      return new Promise<ScriptedExit>((resolve) => {
        let at = 0
        container.stdin.on('data', (chunk: Buffer) => {
          const copy = Buffer.from(chunk)
          const flip = acting.flipAt
          if (flip !== undefined && flip >= at && flip < at + copy.length) copy[flip - at] = (copy[flip - at] ?? 0) ^ 0xff
          container.stdout.write(acting.catShort === true && at === 0 ? copy.subarray(1) : copy)
          at += copy.length
        })
        container.stdin.on('end', () => {
          // A cat that never sees the EOF runs until its wallclock, which the fake leaves to the test.
          if (acting.catIgnoresEof === true) vms.fake?.simulateOverrun(spec.name)
          else resolve(exit('cat'))
        })
      })
    }
    if (same(command, BEATING) || same(command, BEATING_OUT)) {
      if (acting.neverUp !== true) writeFileSync(join(spec.workspace, 'up'), '')
      let n = 0
      const once = (): void => {
        writeFileSync(join(spec.workspace, 'beat'), `${String(++n)}\n`)
        // Its stdout is the channel's input, until the kernel destroys it.
        if (container !== undefined && !container.stdout.destroyed && !container.stdout.writableEnded) container.stdout.write(`${String(n)}\n`)
      }
      once()
      const timer = acting.beatsOnce === true ? undefined : setInterval(once, 2)
      const stop = (): void => clearInterval(timer)
      t.after(stop)
      beating.set(spec.name, { domain: spec.domain, stop })
      return new Promise<ScriptedExit>(() => undefined)
    }
    if (same(command, ['sleep', '600'])) {
      if (acting.listsKilled === true) vms.ghosts.set(spec.name, spec.domain)
      return acting.sleepExits0 === true ? Promise.resolve({}) : new Promise<ScriptedExit>(() => undefined)
    }
    if (command[0] === 'node' && command[1] === '-e' && (command[2] ?? '').includes(PROXY_MARK)) {
      const nonce = /res\.end\("([^"]+)"\)/.exec(command[2] ?? '')?.[1] ?? ''
      const [loopback, external] = acting.proxy ?? ['loopback refused ECONNREFUSED', 'external refused ECONNREFUSED']
      return Promise.resolve({ stdout: `${PROXY_MARK}${loopback.replace('<nonce>', nonce)}\n${PROXY_MARK}${external}\n`, ...exit('proxy') })
    }
    return undefined
  }
}

/**
 * The fake driver as the VMs act with a beating container on them: a kill
 * by name (kill, abandon, a sweep's) stops its beat, as it stops the
 * container whatever became of its CLI, and `docker ps` lists each beating
 * container on its domain until then.
 */
function onVms(fake: FakeSandbox, vms: Vms, acting: Acting): SandboxDriver {
  const { beating } = vms
  let sweepsSeen = 0
  const land = (name: string): void => {
    if (acting.beatsOn === true) return
    const ended = beating.get(name)
    ended?.stop()
    if (ended !== undefined && acting.listsKilled === true) vms.ghosts.set(name, ended.domain)
    beating.delete(name)
  }
  return {
    name: fake.name,
    probe: (signal) => fake.probe(signal),
    run: (spec) => {
      const running = fake.run(spec)
      if (acting.endsLate !== true) return running
      return { ...running, result: running.result.then((result) => ({ ...result, durationMs: result.durationMs + 61_000 })) }
    },
    commandRefusal: (command) => fake.commandRefusal(command),
    everyRunRefusal: () => fake.everyRunRefusal(),
    kill: async (name) => {
      if (acting.killExits0 === true && beating.has(name)) {
        land(name)
        fake.simulateExit(name)
        return
      }
      await fake.kill(name)
      land(name)
    },
    abandon: async (name) => {
      await fake.abandon(name)
      land(name)
    },
    sweepOrphans: async (request) => {
      const fault = acting.sweepFault?.at === sweepsSeen++ ? acting.sweepFault.reports : undefined
      if (fault === 'failed') {
        return { swept: [], unlisted: [], failed: request.names.map((name) => ({ name, domain: fake.specs.find((s) => s.name === name)?.domain ?? 'trusted', why: 'Error response from daemon: refused' })) }
      }
      const sweep = async (): Promise<SweepResult> => {
        if (acting.killExits0 === true) {
          const named = [...beating.keys()].filter((name) => request.names.includes(name))
          for (const name of named) {
            land(name)
            fake.simulateExit(name)
          }
          return { swept: named, unlisted: [], failed: [] }
        }
        const swept = await fake.sweepOrphans(request)
        if (acting.sweepMisses !== true) for (const name of swept.swept) land(name)
        return swept
      }
      const result = await sweep()
      return fault === 'unlisted' ? { ...result, unlisted: [...result.unlisted, { domain: 'hostile', why: 'Cannot connect to the Docker daemon' }] } : result
    },
  }
}

function context(t: TestContext, acting: Acting = {}, over: Partial<SandboxBodyContext> = {}): SandboxBodyContext & { readonly fake: FakeSandbox } {
  const root = tmpdir(t)
  const mountRoots = { trusted: join(root, 'trusted'), hostile: join(root, 'hostile') }
  for (const dir of Object.values(mountRoots)) mkdirSync(dir)
  const vms: Vms = { beating: new Map(), ghosts: new Map() }
  const listed = (domain: SandboxDomain): string[] =>
    acting.sweepListsNothing === true
      ? []
      : [...[...vms.beating].filter(([, b]) => b.domain === domain).map(([name]) => name), ...[...vms.ghosts].filter(([name, d]) => d === domain && !vms.beating.has(name)).map(([name]) => name)]
  const orphans = Object.defineProperties({}, { trusted: { get: () => listed('trusted') }, hostile: { get: () => listed('hostile') } }) as Partial<Record<SandboxDomain, readonly string[]>>
  const fake = fakeSandbox({ imageId: IMAGE, probe: { ok: true, version: 'fake 1' }, play: actor(t, vms, acting), orphans })
  vms.fake = fake
  return { driver: onVms(fake, vms, acting), fake, imageId: IMAGE, mountRoots, caps: { memoryMb: 2048, cpus: 2, pids: 256 }, pauseMs: 20, waitMs: 5_000, made: () => undefined, ...over }
}

test('the live network body, offline: a container with lo up, no route and every probe unreachable passes on both domains, down addressless fallback devices beside it; another interface, a route or a route table unread, a reach, a timeout or a refusal by address or by name, a lookup a resolver answered, or a target missing or out of order fails it', async (t) => {
  const ctx = context(t)
  const reports = await networkNone(ctx)
  assert.deepEqual(Object.keys(reports), ['trusted', 'hostile'])
  // One container on each domain, with no channel, of the pinned image.
  assert.deepEqual(ctx.fake.specs.map((s) => [s.domain, s.image, s.channel]), [['trusted', IMAGE, undefined], ['hostile', IMAGE, undefined]])

  const quiet = quietNetwork()
  const lo = quiet.interfaces[0]!
  const first = quiet.probes[0]!
  // The first target by name, and the probes with one in its place.
  const byName = quiet.probes.findIndex((p) => p.kind === 'name')
  const named = quiet.probes[byName]!
  assert.equal(named.target, 'host.lima.internal:8766')
  const probeAt = (i: number, probe: NetworkReport['probes'][number]): NetworkReport['probes'] => [...quiet.probes.slice(0, i), probe, ...quiet.probes.slice(i + 1)]
  // A VM kernel with sit, ipip and ip6_tunnel loaded: each new namespace has their down, addressless fallback devices.
  const fallback = { ...quiet, interfaces: [{ name: 'ip6tnl0', operstate: 'down', addresses: [] }, lo, { name: 'sit0', operstate: 'down', addresses: [] }, { name: 'tunl0', operstate: 'down', addresses: [] }] }
  assert.deepEqual(networkProblems(fallback), [])
  await networkNone(context(t, { network: fallback }))
  const failing: readonly [string, NetworkReport, RegExp][] = [
    ['an interface up with an address', { ...quiet, interfaces: [{ name: 'eth0', operstate: 'up', addresses: ['172.17.0.2'] }, lo] }, /interface eth0, up, holding 172\.17\.0\.2/],
    ['an interface up with no address', { ...quiet, interfaces: [{ name: 'eth0', operstate: 'up', addresses: [] }, lo] }, /interface eth0, up, with no address/],
    ['an interface down with an address', { ...quiet, interfaces: [lo, { name: 'sit0', operstate: 'down', addresses: ['10.0.0.1'] }] }, /interface sit0, down, holding 10\.0\.0\.1/],
    ['an interface whose state was unread', { ...quiet, interfaces: [lo, { name: 'tunl0', operstate: 'unread', addresses: [] }] }, /interface tunl0, unread, with no address/],
    ['no lo', { ...quiet, interfaces: [] }, /has no lo/],
    ['a route', { ...quiet, routes: 1 }, /holds 1 route/],
    ['a reached target', { ...quiet, probes: [{ ...first, reached: true, error: null }, ...quiet.probes.slice(1)] }, /192\.168\.5\.2:8766 was reached/],
    ['a timed-out connect', { ...quiet, probes: [{ ...first, error: 'ETIMEDOUT' }, ...quiet.probes.slice(1)] }, /192\.168\.5\.2:8766 met ETIMEDOUT/],
    ['an address met by EAI_AGAIN', { ...quiet, probes: [{ ...first, error: 'EAI_AGAIN' }, ...quiet.probes.slice(1)] }, /met EAI_AGAIN/],
    ['a refused connect', { ...quiet, probes: [{ ...first, error: 'ECONNREFUSED' }, ...quiet.probes.slice(1)] }, /192\.168\.5\.2:8766 met ECONNREFUSED/],
    // A name target too: a connect by name that timed out or was refused was resolved, and went somewhere.
    ['a name met by a timed-out connect', { ...quiet, probes: probeAt(byName, { ...named, error: 'ETIMEDOUT' }) }, /host\.lima\.internal:8766 met ETIMEDOUT/],
    ['a name met by a refused connect', { ...quiet, probes: probeAt(byName, { ...named, error: 'ECONNREFUSED' }) }, /host\.lima\.internal:8766 met ECONNREFUSED/],
    ['a target left out', { ...quiet, probes: quiet.probes.slice(1) }, /not every target in order/],
    ['two targets out of order', { ...quiet, probes: [quiet.probes[1]!, first, ...quiet.probes.slice(2)] }, /not every target in order/],
    ['a lookup answered', { ...quiet, lookup: { error: null } }, /lookup of github\.com met null/],
    // A resolver that answered, if only to fail: the container reached one.
    ['a lookup a resolver failed', { ...quiet, lookup: { error: 'ESERVFAIL' } }, /lookup of github\.com met ESERVFAIL/],
    ['a lookup a resolver refused', { ...quiet, lookup: { error: 'ECONNREFUSED' } }, /lookup of github\.com met ECONNREFUSED/],
    // The probe's -1: /proc/net/route unread, so no route table shows there is none.
    ['a route table that could not be read', { ...quiet, routes: -1 }, /\/proc\/net\/route could not be read, so nothing shows the container has no route/],
  ]
  for (const [why, report, problem] of failing) {
    assert.match(networkProblems(report).join('\n'), problem, why)
    await assert.rejects(networkNone(context(t, { network: report })), /a way out/, why)
  }
  assert.deepEqual(networkProblems(quiet), [])
  // A probe that exits other than 0, or prints no report, fails it too.
  await assert.rejects(networkNone(context(t, { exits: { network: 1 } })), /trusted: the probe exited 1: /)
  await assert.rejects(networkNone(context(t, { networkSilent: true })), /trusted's probe printed no aos-network-probe  ?line/)
})

test("the live network body's record: each interface with its operstate and addresses, the routes, each target's code and the lookup, on one line; the live test prints its reports through it", () => {
  const quiet = quietNetwork()
  const fallback = { ...quiet, interfaces: [quiet.interfaces[0]!, { name: 'sit0', operstate: 'down', addresses: [] }] }
  const line = networkLine('hostile', fallback)
  assert.ok(line.startsWith('hostile: interfaces lo unknown [127.0.0.1 ::1], sit0 down []; routes 0; 192.168.5.2:8766 ENETUNREACH; '), line)
  assert.ok(line.endsWith('; github.com:443 EAI_AGAIN; lookup EAI_AGAIN'), line)
  assert.ok(networkLine('trusted', { ...quiet, probes: [{ ...quiet.probes[0]!, reached: true, error: null }] }).includes('; 192.168.5.2:8766 reached; '))
  // test/live-sandbox.test.ts never runs offline: what it prints of a
  // report is held here, to networkLine, never an interface interpolated
  // itself (an object prints as [object Object]).
  const live = readFileSync(join(REPO_ROOT, 'test', 'live-sandbox.test.ts'), 'utf8')
  assert.ok(live.includes('    for (const domain of DOMAINS) t.diagnostic(networkLine(domain, reports[domain]))\n'), "live-sandbox no longer prints each VM's report through networkLine")
  assert.doesNotMatch(live, /\binterfaces\b(?!\s*\()[^\n]*\.join\(/, 'live-sandbox joins a report\'s interfaces itself')
  assert.doesNotMatch(live, /report\.interfaces/, 'live-sandbox reads a report\'s interfaces itself')
})

test('the live channel body, offline: random bytes written to cat over the channel come back the same, and its stdin end ends the container; one byte changed fails it', async (t) => {
  const ctx = context(t)
  const record = await channelRoundTrip(ctx, 4 * 1024 * 1024 + 17)
  assert.equal(record.bytes, 4 * 1024 * 1024 + 17)
  assert.deepEqual(ctx.fake.specs.map((s) => [s.domain, s.command, s.channel]), [['trusted', ['cat'], true]])
  await assert.rejects(channelRoundTrip(context(t, { flipAt: 1_000_003 }), 2 * 1024 * 1024), /not the bytes sent/)
  // A byte dropped, a cat that exits other than 0 on its own, and one that
  // never sees the EOF and runs until its wallclock.
  await assert.rejects(channelRoundTrip(context(t, { catShort: true }), 2 * 1024 * 1024), /2097151 of 2097152 bytes came back/)
  await assert.rejects(channelRoundTrip(context(t, { exits: { cat: 1 } }), 1024), /cat exited 1: /)
  await assert.rejects(channelRoundTrip(context(t, { catIgnoresEof: true }), 1024), /the container did not end on its stdin's EOF: its wallclock kill ended it, exit 137/)
})

test('the live init body, offline: docker-init as PID 1 and no zombie passes on both domains; a command as PID 1 or a zombie fails it', async (t) => {
  await initReaps(context(t))
  const reaped = reapedInit()
  assert.match(initProblems({ ...reaped, pid1: 'node', self: 1 }).join('\n'), /PID 1 is node, not docker-init[\s\S]*the command is PID 1/)
  const zombie = { ...reaped, processes: [...reaped.processes, { pid: 12, comm: 'sleep', state: 'Z' }] }
  assert.match(initProblems(zombie).join('\n'), /sleep \(pid 12\) is a zombie/)
  await assert.rejects(initReaps(context(t, { init: zombie })), /sleep/)
  // A probe that exits other than 0, or lists no process (so no zombie could show).
  await assert.rejects(initReaps(context(t, { exits: { init: 1 } })), /trusted: the init probe exited 1: /)
  await assert.rejects(initReaps(context(t, { init: { ...reaped, processes: [] } })), /trusted's init probe listed no process/)
})

test("the live client-kill body, offline: a beating container its client's SIGKILL and a kill by name end is gone from both VMs, and a sweep lists and kills a beating one by name; one that never says it is up, never beats, writes on after them, is still listed, is not listed, beats on after the sweep, whose CLI then exits other than 137, or whose sweep could not list a VM or kill fails it", { timeout: 60_000 }, async (t) => {
  const ctx = context(t)
  const ends = await clientKilledThenKillByName(ctx)
  for (const domain of ['trusted', 'hostile'] as const) {
    // Given up, as the real driver gives up a run: no exit status, SIGKILL, no killedBy.
    assert.deepEqual([ends[domain].abandoned.exitCode, ends[domain].abandoned.signal, ends[domain].abandoned.killedBy], [null, 'SIGKILL', undefined], domain)
    // Swept: the docker CLI's 137.
    assert.equal(ends[domain].swept.exitCode, 137, domain)
  }
  // Per domain: the client-killed container (given up, killed by name, swept,
  // listing nothing), then the beating one swept twice, killing it once.
  const names = ctx.fake.specs.map((s) => s.name)
  assert.deepEqual(names.length, 4)
  assert.deepEqual(ctx.fake.abandons, [names[0], names[2]])
  assert.deepEqual(ctx.fake.kills, [names[0], names[2]])
  assert.deepEqual(ctx.fake.sweepRequests.map((r) => r.names), [[names[0]], [names[1]], [names[1]], [names[2]], [names[3]], [names[3]]])
  assert.deepEqual(ctx.fake.sweeps, [[], [names[1]], [], [], [names[3]], []])
  assert.deepEqual(ctx.fake.specs.map((s) => s.domain), ['trusted', 'trusted', 'hostile', 'hostile'])

  await assert.rejects(clientKilledThenKillByName(context(t, { beatsOnce: true })), /never beat across 20 ms/)
  await assert.rejects(clientKilledThenKillByName(context(t, { beatsOn: true })), /still writes its workspace after its client's SIGKILL and the kill by name/)
  await assert.rejects(clientKilledThenKillByName(context(t, { sweepListsNothing: true })), /a sweep did not list and kill aos-run-live_sweep_/)
  await assert.rejects(clientKilledThenKillByName(context(t, { sweepMisses: true })), /still writes its workspace after the sweep killed it by name/)
  await assert.rejects(clientKilledThenKillByName(context(t, { killExits0: true })), /the docker CLI of a container another client killed exited 0, not 137/)
  await assert.rejects(clientKilledThenKillByName(context(t, { neverUp: true }, { waitMs: 200 })), /trusted: aos-run-live_cli_\S+ never wrote \/workspace\/up/)
  // A VM whose `docker ps` still lists the container its kills ended.
  await assert.rejects(clientKilledThenKillByName(context(t, { listsKilled: true })), /trusted: a VM still runs aos-run-live_cli_\S+, or could not be listed/)
  // A sweep that could not list a VM, or whose kill a daemon refused: the
  // sweep of the client-killed container (the body's first), and the sweep of
  // the running one (its second), each read whole, not by what it swept.
  for (const reports of ['unlisted', 'failed'] as const) {
    await assert.rejects(clientKilledThenKillByName(context(t, { sweepFault: { at: 0, reports } })), /trusted: a VM still runs aos-run-live_cli_\S+, or could not be listed/, reports)
    await assert.rejects(clientKilledThenKillByName(context(t, { sweepFault: { at: 1, reports } })), /trusted: a sweep did not list and kill aos-run-live_sweep_\S+, which runs/, reports)
  }
})

test('the live kill-by-name body, offline: a kill by name ends a beating container with the CLI\'s 137, credited to the kill, on both VMs; a kill whose exit is not 137, or that leaves it beating, fails it', async (t) => {
  const ctx = context(t)
  const ends = await killedByName(ctx)
  for (const domain of ['trusted', 'hostile'] as const) assert.deepEqual([ends[domain].exitCode, ends[domain].signal, ends[domain].killedBy], [137, 'SIGKILL', 'requested'], domain)
  assert.deepEqual(ctx.fake.kills, ctx.fake.specs.map((s) => s.name))
  assert.deepEqual(ctx.fake.sweeps, [[], []])
  await assert.rejects(killedByName(context(t, { killExits0: true })), /a kill by name ended the run with exit 0, signal null, killedBy undefined/)
  await assert.rejects(killedByName(context(t, { beatsOn: true })), /still writes its workspace after its kill by name/)
  await assert.rejects(killedByName(context(t, { listsKilled: true })), /trusted: a VM still runs aos-run-live_kill_\S+, or could not be listed/)
})

test('the live destroyed-input body, offline: a channel run whose input is destroyed is recorded, then a kill by name stops it and a sweep finds nothing; one the kill leaves beating fails it', async (t) => {
  const ctx = context(t)
  const record = await channelInputDestroyed(ctx)
  // The fake's CLI never ends on its own: only the kill ends the run, and the container ran on until it.
  assert.deepEqual([record.cliEndedFirst, record.containerRanOn, record.end.exitCode, record.end.killedBy], [false, true, 137, 'requested'])
  assert.deepEqual(ctx.fake.specs.map((s) => [s.domain, s.command, s.channel]), [['trusted', BEATING_OUT, true]])
  assert.equal(ctx.fake.channels[0]?.stdout.destroyed, true)
  // One sweep, for its name, finding nothing.
  assert.deepEqual([ctx.fake.sweepRequests.map((r) => r.names), ctx.fake.sweeps], [[[ctx.fake.specs[0]?.name]], [[]]])
  await assert.rejects(channelInputDestroyed(context(t, { beatsOn: true })), /still writes its workspace after its input was destroyed and it was killed by name/)
  await assert.rejects(channelInputDestroyed(context(t, { listsKilled: true })), /trusted: a VM still runs aos-run-live_pipe_gone_\S+, or could not be listed/)
})

test('the live wallclock body, offline: a hostile run killed at its wallclock passes; one whose kill never lands, that ends on its own, whose kill lands a minute late, that a VM still lists, or whose sweep could not list a VM or kill fails it', async (t) => {
  const ctx = context(t)
  const end = await hostileWallclock(ctx, 5_000, (name) => ctx.fake.simulateOverrun(name))
  assert.deepEqual([end.killedBy, end.exitCode, end.overran], ['wallclock', 137, true])
  assert.deepEqual(ctx.fake.specs.map((s) => [s.domain, s.command, s.limits.wallclockMs]), [['hostile', ['sleep', '600'], 5_000]])
  const stuck = context(t, {}, { waitMs: 200 })
  await assert.rejects(hostileWallclock(stuck, 5_000), /did not settle within 200 ms/)
  for (const spec of stuck.fake.specs) stuck.fake.simulateOverrun(spec.name)
  // Its sleep ends on its own, so no wallclock killed it.
  await assert.rejects(hostileWallclock(context(t, { sleepExits0: true }), 5_000), /the hostile run ended 0 with killedBy undefined/)
  const late = context(t, { endsLate: true })
  await assert.rejects(hostileWallclock(late, 5_000, (name) => late.fake.simulateOverrun(name)), /the hostile run lasted 66000 ms, a minute past its wallclock/)
  const listed = context(t, { listsKilled: true })
  await assert.rejects(hostileWallclock(listed, 5_000, (name) => listed.fake.simulateOverrun(name)), /a VM still runs aos-run-live_wall_\S+, or could not be listed/)
  // Its sweep could not list a VM, or a daemon refused its kill.
  for (const reports of ['unlisted', 'failed'] as const) {
    const faulty = context(t, { sweepFault: { at: 0, reports } })
    await assert.rejects(hostileWallclock(faulty, 5_000, (name) => faulty.fake.simulateOverrun(name)), /a VM still runs aos-run-live_wall_\S+, or could not be listed/, reports)
  }
})

test("the live canary body, offline: both canaries pass as boot runs them, and each VM's self-test report is one the judge accepts; a canary refused, or a self-test that reached something or met another code, fails it", async (t) => {
  const ctx = context(t)
  const store = withStore(t)
  const record = await canariesPass(ctx, store, EGRESS_LIMITS)
  assert.deepEqual(record.verdicts, { trusted: { ok: true }, hostile: { ok: true } })
  for (const domain of ['trusted', 'hostile'] as const) {
    assert.ok(record.codes[domain].every(([, code]) => code === 'ENETUNREACH' || code === 'EAI_AGAIN' || code === 'ENOTFOUND'), domain)
  }
  // The trusted canary over a channel, the hostile one without; each self-test without.
  assert.deepEqual(ctx.fake.specs.map((s) => [s.domain, s.channel === true, s.name.startsWith(CANARY_PREFIX)]), [
    ['trusted', true, true],
    ['trusted', false, false],
    ['hostile', false, true],
    ['hostile', false, false],
  ])
  for (const how of ['reached', 'timed out'] as const) {
    await assert.rejects(canariesPass(context(t, { selfTest: refusedReport(how) }), withStore(t), EGRESS_LIMITS), /trusted: the judge refused the VM's self-test report/, how)
  }
  // A canary refused, on either domain: the trusted one's ready report the
  // judge refuses, or its round trip that did not meet the kernel's deny.
  await assert.rejects(canariesPass(context(t, { canary: { report: { hostile: refusedReport('reached') } } }), withStore(t), EGRESS_LIMITS), /hostile's canary did not pass/)
  await assert.rejects(canariesPass(context(t, { canary: { report: { trusted: refusedReport('reached') } } }), withStore(t), EGRESS_LIMITS), /trusted's canary did not pass/)
  await assert.rejects(canariesPass(context(t, { canary: { status: 1 } }), withStore(t), EGRESS_LIMITS), /trusted's canary did not pass/)
  // A self-test that exits other than 0, or whose report leaves a probe out.
  await assert.rejects(canariesPass(context(t, { exits: { selfTest: 1 } }), withStore(t), EGRESS_LIMITS), /trusted: the self-test exited 1: /)
  const quiet = JSON.parse(Buffer.from(quietReport()).toString('ascii')) as { probes: unknown[] }
  const fewer = Buffer.from(JSON.stringify({ ...quiet, probes: quiet.probes.slice(1) }), 'ascii')
  await assert.rejects(canariesPass(context(t, { selfTest: fewer }), withStore(t), EGRESS_LIMITS), /trusted: the VM's self-test report does not name every probe the kernel runs, in order/)
})

test('the live node-proxy body, offline: fetches its proxy settings send nowhere are recorded, a loopback answer only from its own server, with whether node warned; an answer from outside the container fails it', async (t) => {
  const refused = await nodeProxyWarning(context(t))
  assert.deepEqual([refused.warned, refused.loopback], [false, 'refused'])
  assert.equal(refused.stdout, `${PROXY_MARK}loopback refused ECONNREFUSED\n${PROXY_MARK}external refused ECONNREFUSED`)
  // Node bypassing the proxy for loopback: its own server answers, which is recorded, not refused.
  const bypassed = await nodeProxyWarning(context(t, { proxy: ['loopback answered 200 <nonce>', 'external refused ECONNREFUSED'] }))
  assert.equal(bypassed.loopback, 'answered')
  for (const [why, proxy, problem] of [
    ['the loopback fetch answered by another server', ['loopback answered 200 something-else', 'external refused ECONNREFUSED'], /answered by something else/],
    ['the external fetch answered', ['loopback refused ECONNREFUSED', 'external answered 200 <html>'], /http:\/\/github\.com\/ in a container with no channel was not refused/],
    ['no lines', ['', ''], /printed no loopback and external line/],
    ['the loopback fetch neither answered nor refused', ['loopback hung ETIMEDOUT', 'external refused ECONNREFUSED'], /the loopback fetch neither answered nor was refused: loopback hung ETIMEDOUT/],
  ] as const) {
    await assert.rejects(nodeProxyWarning(context(t, { proxy })), /reached something through its proxy settings/, why)
    assert.match(proxyProblems(`${PROXY_MARK}${proxy[0]}\n${PROXY_MARK}${proxy[1]}\n`, 'n').join('\n'), problem, why)
  }
  await assert.rejects(nodeProxyWarning(context(t, { exits: { proxy: 1 } })), /the proxy probe exited 1: /)
})

// ── the Phase 2 exit (egress plan L2) ───────────────────────────────────────

/** A binding value in no credential shape: only the kernel's own mask keeps it, and its Basic form, out of the log. */
const BINDING_VALUE = 'offline-binding-value-4f2a9c71e0'

/** GitHub as the fixture repository's two hosts answer the exit's requests: git's smart HTTP, and a pull request opened. */
/**
 * The repository as GitHub spells it in the addresses it answers with: the
 * operator's own case, where config reads the slug without case
 * (aibot-tools/aos-fixture), so the body must read an address's repository
 * without case too.
 */
const GITHUB_SPELLING = 'AiBot-Tools/aos-fixture'

function fixtureHost(repo: string): (req: IncomingMessage, res: ServerResponse) => void {
  assert.equal(GITHUB_SPELLING.toLowerCase(), repo, 'the bindings no longer name the fixture repository GITHUB_SPELLING spells')
  return (req, res) => {
    const url = req.url ?? ''
    if (url === `/repos/${repo}/pulls` && req.method === 'POST') {
      res.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ number: 7, html_url: `https://github.com/${GITHUB_SPELLING}/pull/7` }))
      return
    }
    for (const service of ['git-upload-pack', 'git-receive-pack']) {
      if (url === `/${repo}.git/info/refs?service=${service}` || (url === `/${repo}.git/${service}` && req.method === 'POST')) {
        res.writeHead(200, { 'content-type': `application/x-${service}-${url.includes('info/refs') ? 'advertisement' : 'result'}` }).end('0000')
        return
      }
    }
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found')
  }
}

/**
 * A kernel booted for the exit offline, its containers played by exitActor
 * (with `fault`, one acting as that fault names), its model scripted by
 * `script`, and with `basicUser`, the github-git binding naming that user
 * for its Basic credential in place of GitHub's default. The hostile
 * domain's mountRoot is a directory of its own, as on the Mac (the
 * fixture's base gives both domains one), so a body that took the hostile
 * root for the run's workspace is seen to.
 */
async function offlineExit(
  t: TestContext,
  options: { readonly fault?: ExitFault; readonly script?: (repo: string) => ReturnType<typeof exitScript>; readonly basicUser?: string } = {},
) {
  SecretMask.clear()
  t.after(() => SecretMask.clear())
  const yaml = (base: string): string => apartRoots(exitKernelYaml(pinnedSandbox(IMAGE))(base))
  const user = options.basicUser
  const fx = fixture(t, { kernelYaml: user === undefined ? yaml : (base) => withBasicUser(yaml(base), user) })
  const roots = fx.config.sandbox.domains
  assert.notEqual(roots.hostile.mountRoot, roots.trusted.mountRoot, 'the exit fixture gives both domains one mountRoot')
  mkdirSync(roots.hostile.mountRoot, { recursive: true })
  writeProbeRecord(fx.dataDir, freshProbe(EXIT_REF))
  // The shipped bindings' repository, read from them.
  const repo = boundRepo(fx)
  const up = fakeUpstreamDeps(() => undefined, fixtureHost(repo))
  const basic = basicOf(fx, BINDING_VALUE)
  const fault = options.fault === undefined ? undefined : { fault: options.fault, value: BINDING_VALUE, basic }
  const fake = fakeSandbox({ imageId: IMAGE, probe: { ok: true, version: 'fake 1' }, play: exitActor(repo, fault) })
  const rec = recording(fake)
  const provider = fakeProvider((options.script ?? exitScript)(repo))
  const kernel = await bootOn(t, fx, {
    sandboxDriver: rec.driver,
    env: { ANTHROPIC_API_KEY: 'offline-fixture-credential-9c1f0b', AOS_GITHUB_TOKEN: BINDING_VALUE },
    fetch: provider.fetch,
    agentsDir: exitFleet(join(tmpdir(t), 'agents')),
    egressUpstreamDeps: up.deps,
  })
  const made: string[] = []
  return {
    repo,
    up,
    rec,
    fx,
    basic,
    made,
    exit: () => phase2Exit({ kernel, fx, specs: rec.specs, value: BINDING_VALUE, timeoutMs: 60_000, made: (workspace) => made.push(workspace) }),
  }
}

/** `yaml` with the hostile domain's mountRoot a sibling of the trusted one's, `<trusted>-hostile`: the line the fixture's base writes for it. */
function apartRoots(yaml: string): string {
  const line = /^ {4}hostile: \{ (.*), mountRoot: (\S+) \}$/m.exec(yaml)
  assert.ok(line !== null, 'the exit kernel.yaml no longer writes the hostile domain as this reads it')
  return yaml.replace(line[0], `    hostile: { ${line[1] ?? ''}, mountRoot: ${line[2] ?? ''}-hostile }`)
}

/** `yaml` with the github-git binding's Basic credential naming `user`: the line after its scheme, as stringify writes the shipped section. */
function withBasicUser(yaml: string, user: string): string {
  const at = yaml.indexOf('    github-git:\n')
  const scheme = yaml.indexOf('      scheme: Basic\n', at)
  assert.ok(at !== -1 && scheme !== -1 && yaml.indexOf('\n    github-api:', at) > scheme, 'the exit kernel.yaml no longer writes github-git as this reads it')
  const end = scheme + '      scheme: Basic\n'.length
  return `${yaml.slice(0, end)}      basicUser: ${user}\n${yaml.slice(end)}`
}

test('the live Phase 2 exit body, offline: clone, change, test, push aos/<runId>/<branch> and a pull request, every flow a decision of the run, the loopback denied, and the binding value nowhere it must not be', { timeout: 120_000 }, async (t) => {
  const { repo, up, rec, fx, basic: basicForm, made, exit } = await offlineExit(t)
  assert.equal(repo, 'aibot-tools/aos-fixture')
  const record = await exit()
  // The address as the host gave it, in GitHub's own spelling of the repository.
  assert.equal(record.pullRequest, `https://github.com/${GITHUB_SPELLING}/pull/7`)
  assert.deepEqual(record.approvals, [...exitApprovals(repo).map((a) => a.toolRef)])
  // The run's workspace, told the caller once, to remove.
  assert.deepEqual(made, [join(fx.config.sandbox.domains.trusted.mountRoot, record.runId)])

  // What the hosts saw, which only an in-process host shows: the clone, the
  // publisher's default branch, push and pull request, nothing for the
  // loopback, and on each host its own binding's credential, once.
  assert.deepEqual(up.seen.map((s) => `${s.method} ${s.url}`), [
    `GET /${repo}.git/info/refs?service=git-upload-pack`,
    `POST /${repo}.git/git-upload-pack`,
    `GET /${repo}.git/info/refs?service=git-upload-pack`,
    `GET /${repo}.git/info/refs?service=git-receive-pack`,
    `POST /${repo}.git/git-receive-pack`,
    `POST /repos/${repo}/pulls`,
  ])
  const auth = (i: number): string[] => {
    const raw = up.seen[i]?.rawHeaders ?? []
    const sent: string[] = []
    for (let j = 0; j + 1 < raw.length; j += 2) if (raw[j]?.toLowerCase() === 'authorization') sent.push(raw[j + 1] ?? '')
    return sent
  }
  // GitHub's default user for the Basic form, as the shipped binding names none.
  assert.equal(basicForm, Buffer.from(`x-access-token:${BINDING_VALUE}`).toString('base64'))
  for (const i of [0, 1, 2, 3, 4]) assert.deepEqual(auth(i), [`Basic ${basicForm}`], String(up.seen[i]?.url))
  assert.deepEqual(auth(5), [`Bearer ${BINDING_VALUE}`])
  // The publish was the approved one: its branch, title and body in the pull request's command line.
  const published = rec.specs.find((s) => s.command.includes(PUBLISH_ARGV[1] ?? ''))
  assert.ok(published?.command.includes(`--branch=${EXIT_PUBLISH.branch}`) && published.command.includes(`--title=${EXIT_PUBLISH.title}`))
  // Every container of the run on the trusted domain, under its run id.
  assert.deepEqual([...new Set(rec.specs.filter((s) => !s.name.startsWith(CANARY_PREFIX)).map((s) => [s.domain, s.runId].join(' ')))], [`trusted ${record.runId}`])
})

test('the live Phase 2 exit body, offline, fails on each thing a container can make it catch: a route out, or no route said only on stderr or beside a connect, a request never sent, cut short or a flow with none, a call that fails, whatever its output says, a clone that asked for no pack, a failed, missing, extra or nested test, or a test summary read from a test\'s name or output, from above or with no plan line, from stderr (under a stdout heading of its own included) or from a stdout not shown whole, a push elsewhere, unsaid, said on stderr or after words of its own, or said of another branch, run, repository or host (one that only starts as github.com included), a pull request said from another branch or run, after words of its own or with more after them, at an address of another repository, host or number, or into another base, a command line without the mux, a probe whose parent is not the mux (docker-init, or another node program), a variable named like a credential, a password or a secret in PID 1\'s, the mux\'s or the command\'s environment, a look at PID 1 that prints its lines on stderr or that is not JSON, and the binding value or its Basic form in PID 1\'s, the mux\'s or the command\'s environment, PID 1\'s command line, a workspace entry\'s name, a link\'s target or a file\'s contents (a git object included) or the log, masked or not, never quoting it or ten characters of it', { timeout: 180_000 }, async (t) => {
  const failing: readonly [ExitFault, RegExp][] = [
    ['direct-connects', /^a direct connect to 192\.168\.5\.2:8766 met something other than no route: its stdout is "connected\\n"$/],
    ['direct-said-on-stderr', /^a direct connect to 192\.168\.5\.2:8766 met something other than no route: its stdout is "connected\\n"$/],
    ['direct-said-both', /^a direct connect to 192\.168\.5\.2:8766 met something other than no route: its stdout is "ENETUNREACH\\nconnected\\n"$/],
    ['direct-fails', /^call 1 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['ls-remote-silent-ip', /the git request for 192\.168\.5\.2 \(call 2\) was not its grant's one deny at the policy/],
    ['ls-remote-silent-name', /the git request for host\.lima\.internal \(call 3\) was not its grant's one deny at the policy/],
    ['ls-remote-other-ip', /git ls-remote through the proxy was not denied \(call 2\)/],
    ['ls-remote-other-name', /git ls-remote through the proxy was not denied \(call 3\)/],
    ['clone-offline', /^the clone asked for no pack of aibot-tools\/aos-fixture:\n$/],
    ['clone-refs-only', /^the clone asked for no pack of aibot-tools\/aos-fixture:\n\{(?=[^\n]*"method":"GET")(?=[^\n]*"path":"\/aibot-tools\/aos-fixture\.git\/info\/refs")(?=[^\n]*"reason":"git-fetch")[^\n]*\}$/],
    ['clone-cut', /^a request the kernel allowed failed upstream: \{(?=[^\n]*"reason":"git-fetch")(?=[^\n]*"refusal":"aborted")(?=[^\n]*"stage":"upstream")/],
    ['clone-fails', /^call 4 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 128 after \d+ ms$/],
    ['extra-request', /a request of the run besides the two for the loopback was denied/],
    ['flow-silent', /: a flow carried no judged request/],
    ['edit-fails', /^call 5 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['edit-prints-exited', /^call 5 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['edit-unwritten', /the edit wrote no sum-negative\.test\.js/],
    ['edit-other', /sum-negative\.test\.js is not the second test the edit writes/],
    ['add-fails', /^call 6 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 128 after \d+ ms$/],
    ['commit-fails', /^call 7 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['tests-fail', /^call 8 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['one-test', /node --test did not pass both tests/],
    ['fail-reported', /node --test reported a failed test/],
    ['pass-named', /^node --test did not pass both tests\n/],
    ['fail-named', /^node --test reported a failed test\n/],
    ['tests-extra', /^node --test did not run exactly the two tests$/],
    ['tests-nested', /^node --test did not run exactly the two tests$/],
    ['summary-printed', /^node --test did not pass both tests\n/],
    ['tap-unplanned', /^node --test did not pass both tests\n/],
    ['summary-on-stderr', /^node --test did not pass both tests\n/],
    // The summary read is the one-test stream under the kernel's own heading.
    ['tap-heading-on-stderr', /^node --test did not pass both tests\n[\s\S]*'# pass 1'/],
    ['tap-windowed', /^the result does not show its stdout whole, so no line of it is read: --- stdout \(its end, redacted: \d+ bytes, of the \d+ bytes it printed\) ---$/],
    ['quoted-unmasked', /node --test did not pass both tests/],
    ['pid1-fails', /^call 9 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['pid1-silent', /^no @\/proc\/1\/environ  line in:\n$/],
    ['pid1-on-stderr', /^no @\/proc\/1\/environ  line in:\n$/],
    ['pid1-garbled', /^the @\/proc\/1\/environ line is not JSON: @\/proc\/1\/environ \["PATH=[^"\n]*",<the binding value>\]$/],
    ['cmdline-bare', /PID 1's command line holds no \/opt\/aos\/mux\.mjs/],
    ['cmdline-value', /^PID 1's command line holds the kernel's mask \(\[REDACTED\]: a credential the log masked\) in argument \d+\n/],
    ['cmdline-unmasked', /^PID 1's command line holds the binding value in argument \d+\n/],
    ['environ-value', /PID 1's environment holds the kernel's mask \(\[REDACTED\]: a credential the log masked\) in GIT_HTTP_EXTRA \(entry 6\)/],
    ['environ-unmasked', /PID 1's environment holds the binding value in GIT_HTTP_EXTRA \(entry 6\)/],
    ['environ-basic-unmasked', /PID 1's environment holds its Basic form in GIT_HTTP_EXTRA \(entry 6\)/],
    ['mux-environ-value', /^the mux's environment holds the kernel's mask \(\[REDACTED\]: a credential the log masked\) in GIT_HTTP_EXTRA \(entry 6\)\n/],
    ['command-environ-value', /^the command's environment holds the kernel's mask \(\[REDACTED\]: a credential the log masked\) in GIT_HTTP_EXTRA \(entry 6\)\n/],
    ['mux-not-parent', /^the probe's parent is not the mux: it runs \/sbin\/docker-init -- node \/opt\/aos\/mux\.mjs -- node -e /],
    ['mux-parent-other-node', /^the probe's parent is not the mux: it runs node \/opt\/aos\/publish\.mjs -- node -e /],
    ['mux-environ-token-name', /^the mux's environment holds GH_TOKEN\n/],
    ['command-environ-token-name', /^the command's environment holds GH_TOKEN\n/],
    ['mux-environ-unmasked', /^the mux's environment holds the binding value in GIT_HTTP_EXTRA \(entry 6\)\n/],
    ['command-environ-unmasked', /^the command's environment holds the binding value in GIT_HTTP_EXTRA \(entry 6\)\n/],
    ['mux-environ-basic-unmasked', /^the mux's environment holds its Basic form in GIT_HTTP_EXTRA \(entry 6\)\n/],
    ['command-environ-basic-unmasked', /^the command's environment holds its Basic form in GIT_HTTP_EXTRA \(entry 6\)\n/],
    ['environ-token-name', /^PID 1's environment holds GH_TOKEN\n/],
    ['environ-key-name', /^PID 1's environment holds ANTHROPIC_API_KEY\n/],
    ['environ-password-name', /^PID 1's environment holds GIT_PASSWORD\n/],
    ['environ-secret-name', /^PID 1's environment holds AWS_SECRET\n/],
    ['push-elsewhere', /a request of the run besides the two for the loopback was denied/],
    ['push-skipped', /the publish pushed nothing/],
    ['pr-skipped', /the publish opened no pull request/],
    ['pr-into-other', /^the publish opened no pull request:\n[\s\S]*\nopened pull request #7: https:\/\/github\.com\/\S+\/pull\/7 \(from aos\/\S+ into dev\)\n/],
    ['publish-unsaid', /the publish does not say it pushed the approved branch/],
    ['publish-said-elsewhere', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-other-run', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-other-repo', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-other-host', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-host-suffix', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-prefixed', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-separated', /^the publish does not say it pushed the approved branch$/],
    ['publish-said-on-stderr', /^the publish does not say it pushed the approved branch$/],
    ['pr-said-elsewhere', /^the publish opened no pull request:\n[\s\S]*\nopened pull request #7: https:\/\/github\.com\/\S+\/pull\/7 \(from aos\/\S+\/other into main\)\n/],
    ['pr-said-other-run', /^the publish opened no pull request:\n[\s\S]*\nopened pull request #7: https:\/\/github\.com\/\S+\/pull\/7 \(from aos\/live_other_\w+\/phase2-exit into main\)\n/],
    ['pr-said-other-repo', /^the publish says it opened its pull request in aibot-tools\/aos-other, not aibot-tools\/aos-fixture\n/],
    ['pr-said-other-host', /^the publish opened no pull request:\n[\s\S]*\nopened pull request #7: https:\/\/gitlab\.com\/AiBot-Tools\/aos-fixture\/pull\/7 \(from aos\/\S+\/phase2-exit into main\)\n/],
    ['pr-said-other-number', /^the publish says it opened pull request #7 at the address of #8\n/],
    ['pr-said-prefixed', /^the publish opened no pull request:\n[\s\S]*\nnever opened pull request #7: https:\/\/github\.com\/AiBot-Tools\/aos-fixture\/pull\/7 \(from aos\/\S+\/phase2-exit into main\)\n/],
    ['pr-said-suffixed', /^the publish opened no pull request:\n[\s\S]*\nopened pull request #7: https:\/\/github\.com\/AiBot-Tools\/aos-fixture\/pull\/7 \(from aos\/\S+\/phase2-exit into main\), then closed it\n/],
    ['pr-unsaid', /the publish opened no pull request:\n[^\n]* exited 0 after \d+ ms\n--- stdout \(\d+ bytes\) ---\npushed c{40} to refs\/heads\/aos\/[^\n]*\n\n--- stderr/],
    ['publish-fails', /^call 10 did not exit 0: aos-run-\S+ on the trusted domain, [^\n]*, exited 1 after \d+ ms$/],
    ['workspace-file', /[/]\.git[/]config holds the binding value\n/],
    ['workspace-name', /^the workspace entry \.git[/]refs[/]heads[/]<the binding value> is named with the binding value\n/],
    ['workspace-name-basic', /^the workspace entry \.git[/]refs[/]tags[/]<its Basic form> is named with its Basic form\n/],
    ['workspace-basic', /[/]\.git[/]config holds its Basic form\n/],
    ['workspace-link', /^the workspace link notes has a target holding the binding value\n/],
    ['workspace-link-basic', /^the workspace link notes has a target holding its Basic form\n/],
    ['workspace-object', /[/]\.git[/]objects[/][0-9a-f]{2}[/][0-9a-f]{38} holds the binding value\n/],
    ['workspace-pack', /[/]\.git[/]objects[/]pack[/]pack-c{40}\.pack holds the binding value\n/],
    ['object-corrupt', /[/]\.git[/]objects[/]ab[/]c{38} is a loose git object that does not inflate/],
    ['pack-huge', /[/]\.git[/]objects[/]pack[/]pack-c{40}\.pack is 16777217 bytes, more than the scan inflates/],
    ['printed-masked', /tool\.result \(seq \d+\) of the run holds the kernel's mask \(\[REDACTED\]\)/],
    ['mask-lost', /tool\.result \(seq \d+\) holds the binding value\n/],
    ['mask-lost-basic', /tool\.result \(seq \d+\) holds its Basic form\n/],
  ]
  for (const [fault, problem] of failing) {
    const { exit, basic } = await offlineExit(t, { fault })
    await assert.rejects(exit(), (e: unknown) => {
      assert.ok(e instanceof Error, fault)
      assert.match(e.message, problem, fault)
      // What node:test prints of a failure: its message, and an assertion's
      // actual and expected values. None holds the value or its Basic form.
      const printed = JSON.stringify({ message: e.message, actual: (e as { actual?: unknown }).actual, expected: (e as { expected?: unknown }).expected, stack: e.stack })
      assert.equal(printed.includes(BINDING_VALUE) || printed.includes(basic), false, `${fault}: the failure quotes the binding value or its Basic form`)
      // Nor any ten characters of the value, as JSON.parse's own error quotes the text past where it stopped.
      const pieces = Array.from({ length: BINDING_VALUE.length - 9 }, (_, i) => BINDING_VALUE.slice(i, i + 10))
      assert.deepEqual(pieces.filter((piece) => printed.includes(piece)), [], `${fault}: the failure quotes part of the binding value`)
      return true
    })
  }
})

test("the live Phase 2 exit body's failure text: each result's head is scrubbed whole before it is cut, so a value the cut would split is replaced, never left half in the message; a marked line that is not JSON fails with the line scrubbed, never JSON.parse's own error", () => {
  const basic = Buffer.from(`x-access-token:${BINDING_VALUE}`).toString('base64')
  const quote = scrubbed(BINDING_VALUE, basic)
  const pieces = (text: string): string[] => Array.from({ length: BINDING_VALUE.length - 9 }, (_, i) => BINDING_VALUE.slice(i, i + 10)).filter((piece) => text.includes(piece))
  // The value straddles the 200th character, the cut.
  const heads = quotedHeads([`${'x'.repeat(190)}${BINDING_VALUE} and on`, `${basic} then`], quote)
  assert.equal(heads, `${'x'.repeat(190)}<the bindi\n---\n<its Basic form> then`)
  assert.deepEqual(pieces(heads), [])
  // The value bare in the list: JSON.parse would quote ten characters past where it stopped.
  const line = `@/proc/1/environ ["PATH=/bin",${BINDING_VALUE}]`
  assert.throws(
    () => marked(`${line}\n`, '@/proc/1/environ ', quote),
    (e: unknown) => e instanceof Error && e.message === 'the @/proc/1/environ line is not JSON: @/proc/1/environ ["PATH=/bin",<the binding value>]' && pieces(String(e.stack)).length === 0,
  )
  assert.deepEqual(marked('@/proc/1/environ ["PATH=/bin"]\n', '@/proc/1/environ ', quote), ['PATH=/bin'])
})

test('the live Phase 2 exit body, offline: a call the gate asks a human about that is not the next of the exit is denied on the control plane, before it runs, and fails the body, the run\'s workspace still told the caller to remove', { timeout: 120_000 }, async (t) => {
  // The model asks to publish another branch than the one the exit approves.
  const elsewhere = (repo: string): ReturnType<typeof exitScript> => {
    const script = exitScript(repo)
    script[script.length - 2] = anthropicToolUse({ name: 'sandbox__publish', input: { ...EXIT_PUBLISH, branch: 'not-the-exit' } })
    return script
  }
  const { rec, fx, made, exit } = await offlineExit(t, { script: elsewhere })
  await assert.rejects(exit(), /the gate asked a human about a call that is not the next of the exit, which was denied/)
  // Denied before it ran: no publish container was started.
  assert.equal(rec.specs.some((s) => s.command.includes(PUBLISH_ARGV[1] ?? '')), false)
  // The run's workspace, which its execs filled, was told the caller though
  // the body failed: told when run.start named the run, not once it passed.
  const runIds = [...new Set(rec.specs.filter((s) => !s.name.startsWith(CANARY_PREFIX)).map((s) => s.runId))]
  assert.equal(runIds.length, 1)
  assert.deepEqual(made, [join(fx.config.sandbox.domains.trusted.mountRoot, runIds[0] ?? '')])
  assert.equal(existsSync(made[0] ?? ''), true)
})

test("the live Phase 2 exit body, offline, under a github-git basicUser of kernel.yaml's own: the Basic form it looks for is the one the kernel sends and masks, built from that user", { timeout: 120_000 }, async (t) => {
  const { repo, up, fx, basic, exit } = await offlineExit(t, { basicUser: 'aos-bot' })
  const git = fx.config.egress.bindings['github-git']
  assert.ok(git?.scheme === 'Basic' && git.basicUser === 'aos-bot', 'the kernel.yaml did not name aos-bot as the basicUser')
  assert.equal(basic, Buffer.from(`aos-bot:${BINDING_VALUE}`).toString('base64'))
  await exit()
  const sent = up.seen.filter((s) => s.url.startsWith(`/${repo}.git/`)).map((s) => s.rawHeaders.filter((_, i, raw) => raw[i - 1]?.toLowerCase() === 'authorization'))
  assert.deepEqual(sent, Array.from({ length: 5 }, () => [`Basic ${basic}`]))
  // That form, in the workspace or (the mask lost) the log, is found there.
  for (const [fault, problem] of [
    ['workspace-basic', /[/]\.git[/]config holds its Basic form\n/],
    ['mask-lost-basic', /tool\.result \(seq \d+\) holds its Basic form\n/],
  ] as const) {
    const faulty = await offlineExit(t, { basicUser: 'aos-bot', fault })
    await assert.rejects(faulty.exit(), problem, fault)
  }
})
