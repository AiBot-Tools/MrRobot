// The Phase 2 sandbox checks (egress plan L1), written once and run against two targets.
//
// As runtime-bodies.ts does for Phase 1, every check is a BODY: a function
// handed the driver it runs against, called twice:
//
//   test/sandbox-bodies.test.ts   every `npm test`, against the fake driver
//                                 (test/helpers/fake-sandbox.ts), with each
//                                 container played as the image would act.
//                                 Proves the assertions, and that each fails
//                                 on what it is there to catch.
//   test/live-sandbox.test.ts     gated (AOS_LIVE_TESTS=1, AOS_LIVE_DOCKER=1),
//                                 against the real DockerDriver on the
//                                 operator's two Colima VMs and the built
//                                 worker image. Proves the VMs.
//
// What only the live run settles (the plan's L1, its Notes, and README's
// NEEDS VALIDATION rows): that a container run with --network none has no
// interface up but its loopback and no route to 192.168.5.2,
// host.lima.internal, the other VM or the internet, on either VM; that the
// docker -i channel through Colima's forwarded socket carries 64 MiB of
// arbitrary bytes intact, and how fast; that its stdin's end ends the
// container; that a docker CLI killed by SIGKILL, and the kill by name the
// driver sends with it, stop a container seen to run; that a sweep lists a
// running container by name and kills it, and that a kill by name, the
// driver's or another client's, ends its CLI with 137; what a channel run's
// CLI does when the reader of its stdout goes away, and that a kill by name
// still ends its container; that a hostile run's wallclock kill reaches the
// hostile VM; that PID 1 is docker-init and reaps what a command orphans;
// that both canaries pass, and what codes each VM's self-test met; and
// whether the image's node prints the EnvHttpProxyAgent warning, and sends a
// request to its own loopback server to its proxy.
//
// What abandon cannot show: whether a container outlives a SIGKILL of its
// CLI alone, since abandon kills it by name at once (README's row says so).
//
// Every container here is one the driver builds as it builds any other: the
// pinned image by id with --pull=never, --network none, the caps, a wallclock,
// a workspace under its domain's mountRoot (makeWorkspace) and a name under
// the kernel's prefix. No body spawns anything itself, and none speaks to a
// daemon but through the driver.

import './guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { acceptReady, probeTarget, SELF_TEST } from '../../src/egress/ready.js'
import type { EventStore } from '../../src/events/store.js'
import type { SessionLimits } from '../../src/egress/session.js'
import { CANARY_COMMANDS, CANARY_WORKSPACE, canaryName, canaryNonce, runCanary, type CanaryVerdict } from '../../src/runtime/canary.js'
import { makeWorkspace } from '../../src/runtime/sandbox-tools.js'
import {
  containerName,
  type RunningSandbox,
  type SandboxDomain,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from '../../src/sandbox/driver.js'

export const DOMAINS: readonly SandboxDomain[] = Object.freeze(['trusted', 'hostile'])

/** What every body runs against. */
export interface SandboxBodyContext {
  readonly driver: SandboxDriver
  /** sandbox.imageId: the image every container runs, by id. */
  readonly imageId: string
  /** Each domain's mountRoot: a body's workspaces are made under it (makeWorkspace), and `made` names each. */
  readonly mountRoots: Readonly<Record<SandboxDomain, string>>
  /** sandbox.defaults' caps, as a spec carries them. */
  readonly caps: { readonly memoryMb: number; readonly cpus: number; readonly pids: number }
  /** How long a body waits for a container to show a change (a beat, a kill): seconds on the Mac, a moment offline. */
  readonly pauseMs: number
  /** How long a body waits for any one container to end before it fails. */
  readonly waitMs: number
  /** Told each workspace a body makes, so the caller removes it. */
  readonly made: (workspace: string) => void
}

/** A run id of the shape a workspace and a container name take: one directory name, no `-`. */
export function bodyRunId(what: string): string {
  return `live_${what}_${String(Date.now())}_${randomBytes(3).toString('hex')}`
}

/** The spec a body's container runs under: everything a run's has, nothing more. */
function specOf(ctx: SandboxBodyContext, domain: SandboxDomain, runId: string, command: readonly string[], options: { readonly wallclockMs: number; readonly channel?: true }): SandboxSpec {
  const workspace = makeWorkspace(domain, ctx.mountRoots[domain], runId)
  ctx.made(workspace)
  return {
    name: containerName(runId, 1),
    runId,
    agentId: 'live-sandbox-test',
    domain,
    image: ctx.imageId,
    command,
    workspace,
    limits: { ...ctx.caps, wallclockMs: options.wallclockMs },
    ...(options.channel === true ? { channel: true } : {}),
  }
}

/** `promise`, or a failure naming `what` once `ms` have passed. */
export async function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${String(ms)} ms`)), ms)
  })
  try {
    return await Promise.race([promise, late])
  } finally {
    clearTimeout(timer)
  }
}

const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

/** One container run to its end, its result. */
async function ran(ctx: SandboxBodyContext, spec: SandboxSpec): Promise<SandboxResult> {
  const running = ctx.driver.run(spec)
  return within(running.result, ctx.waitMs, `${spec.name} on the ${spec.domain} domain`)
}

/** The one line of `stdout` that starts with `marker`, as JSON. */
function markedJson(stdout: string, marker: string, what: string): unknown {
  const line = stdout.split('\n').find((l) => l.startsWith(marker))
  assert.ok(line !== undefined, `${what} printed no ${marker} line:\n${stdout.slice(0, 2_000)}`)
  return JSON.parse(line.slice(marker.length)) as unknown
}

// ── network none ───────────────────────────────────────────────────────────

/** What the network probe's report starts with, on its one line of stdout. */
export const NETWORK_MARK = 'aos-network-probe '

/**
 * Where the probe tries to go, by address and by name: pmmcp and the kernel's
 * control port on the Mac's loopback as a Colima VM reaches it
 * (192.168.5.2), the shared usernet's gateway and the address Lima gives a
 * guest on it (where the other VM is reached), the internet by address
 * (1.1.1.1, and an address github.com has answered), and the names the VM
 * would resolve for the Mac (host.lima.internal, host.docker.internal) and
 * the internet (github.com). With no interface up but the container's own
 * loopback, every one has no route, and the interface listing shows that for
 * every address on the usernet, the other VM's whatever it is.
 */
export const NETWORK_TARGETS: readonly { readonly kind: 'address' | 'name'; readonly host: string; readonly port: number }[] = Object.freeze([
  { kind: 'address', host: '192.168.5.2', port: 8766 },
  { kind: 'address', host: '192.168.5.2', port: 7777 },
  { kind: 'address', host: '192.168.5.1', port: 22 },
  { kind: 'address', host: '192.168.5.15', port: 22 },
  { kind: 'address', host: '1.1.1.1', port: 443 },
  { kind: 'address', host: '140.82.112.3', port: 443 },
  { kind: 'name', host: 'host.lima.internal', port: 8766 },
  { kind: 'name', host: 'host.docker.internal', port: 8766 },
  { kind: 'name', host: 'github.com', port: 443 },
])

/**
 * The probe, a node program for the image's node (`node -e`): every target
 * connected to at once, each bounded at 3 s, a lookup of github.com, each
 * interface /sys/class/net lists with its operstate and the addresses
 * os.networkInterfaces() gives it, and the routes /proc/net/route holds, as
 * one line of JSON after NETWORK_MARK.
 */
export const NETWORK_PROBE = [
  "const net = require('node:net'), dns = require('node:dns'), fs = require('node:fs'), os = require('node:os')",
  `const targets = ${JSON.stringify(NETWORK_TARGETS)}`,
  'const probe = (t) => new Promise((done) => {',
  '  const s = net.connect({ host: t.host, port: t.port })',
  '  let settled = false',
  "  const end = (reached, error) => { if (settled) return; settled = true; clearTimeout(timer); s.destroy(); done({ target: t.host + ':' + t.port, kind: t.kind, reached, error }) }",
  "  const timer = setTimeout(() => end(false, 'ETIMEDOUT'), 3000)",
  "  s.once('connect', () => end(true, null))",
  "  s.once('error', (e) => end(false, e.code || 'EOTHER'))",
  '})',
  "const lookup = () => new Promise((done) => dns.lookup('github.com', (e) => done({ error: e ? e.code || 'EOTHER' : null })))",
  "const routes = () => { try { return fs.readFileSync('/proc/net/route', 'utf8').trim().split('\\n').length - 1 } catch (e) { return -1 } }",
  "const state = (name) => { try { return fs.readFileSync('/sys/class/net/' + name + '/operstate', 'utf8').trim() } catch (e) { return 'unread' } }",
  'const interfaces = () => { const held = os.networkInterfaces(); return fs.readdirSync(\'/sys/class/net\').sort().map((name) => ({ name, operstate: state(name), addresses: (held[name] || []).map((a) => a.address) })) }',
  'Promise.all(targets.map(probe)).then(async (probes) => {',
  `  const report = { interfaces: interfaces(), routes: routes(), probes, lookup: await lookup() }`,
  `  process.stdout.write(${JSON.stringify(NETWORK_MARK)} + JSON.stringify(report) + '\\n')`,
  '})',
].join('\n')

/** One network interface a container has: its name, its operstate, and the addresses it holds. */
export interface NetworkInterface {
  readonly name: string
  readonly operstate: string
  readonly addresses: readonly string[]
}

export interface NetworkReport {
  readonly interfaces: readonly NetworkInterface[]
  readonly routes: number
  readonly probes: readonly { readonly target: string; readonly kind: 'address' | 'name'; readonly reached: boolean; readonly error: string | null }[]
  readonly lookup: { readonly error: string | null }
}

/** The codes that say there is no route: by address, the network is unreachable; by name, that too or no answer. */
const NO_ROUTE: Readonly<Record<'address' | 'name' | 'lookup', readonly string[]>> = Object.freeze({
  address: ['ENETUNREACH'],
  name: ['ENETUNREACH', 'EAI_AGAIN', 'ENOTFOUND'],
  lookup: ['EAI_AGAIN', 'ENOTFOUND'],
})

/**
 * What in `report` shows a way out, or nothing: no lo; an interface besides
 * lo that is not down or holds an address; a route; a target the report
 * leaves out or reached, or one that met a code that does not say there is
 * no route (ETIMEDOUT above all: a SYN that timed out went somewhere). An
 * interface besides lo that is down and addressless is no way out: a VM
 * kernel with sit, ipip, ip_gre or ip6_tunnel loaded makes such a fallback
 * device (sit0, tunl0, gre0, ip6tnl0) in every new network namespace, and the
 * report records it.
 */
export function networkProblems(report: NetworkReport): string[] {
  const problems: string[] = []
  if (!report.interfaces.some((i) => i.name === 'lo')) problems.push('the container has no lo')
  for (const i of report.interfaces) {
    if (i.name === 'lo') continue
    if (i.operstate !== 'down' || i.addresses.length > 0) {
      problems.push(`the container has interface ${i.name}, ${i.operstate}, ${i.addresses.length === 0 ? 'with no address' : `holding ${i.addresses.join(', ')}`}: besides lo, only an interface that is down and addressless is no way out`)
    }
  }
  // The probe reports -1 for a /proc/net/route it could not read, which shows no route table at all.
  if (report.routes !== 0) problems.push(report.routes < 0 ? '/proc/net/route could not be read, so nothing shows the container has no route' : `/proc/net/route holds ${String(report.routes)} route(s)`)
  const expected = NETWORK_TARGETS.map((t) => `${t.host}:${String(t.port)}`)
  const seen = report.probes.map((p) => p.target)
  if (JSON.stringify(seen) !== JSON.stringify(expected)) problems.push(`the report names ${seen.join(', ')}, not every target in order`)
  for (const p of report.probes) {
    if (p.reached) problems.push(`${p.target} was reached`)
    else if (p.error === null || !NO_ROUTE[p.kind].includes(p.error)) problems.push(`${p.target} met ${String(p.error)}, which does not say there is no route`)
  }
  if (report.lookup.error === null || !NO_ROUTE.lookup.includes(report.lookup.error)) {
    problems.push(`the lookup of github.com met ${String(report.lookup.error)}, which does not say there is no resolver`)
  }
  return problems
}

/**
 * A VM's network report as one line, for the live run's record (README's
 * NEEDS VALIDATION rows): each interface with its operstate and addresses
 * (`sit0 down []`), the routes, what each target met, and the lookup.
 */
export function networkLine(domain: SandboxDomain, report: NetworkReport): string {
  const interfaces = report.interfaces.map((i) => `${i.name} ${i.operstate} [${i.addresses.join(' ')}]`).join(', ')
  const probes = report.probes.map((p) => `${p.target} ${p.reached ? 'reached' : String(p.error)}`).join('; ')
  return `${domain}: interfaces ${interfaces}; routes ${String(report.routes)}; ${probes}; lookup ${String(report.lookup.error)}`
}

/**
 * 'network none has no route to 192.168.5.2, host.lima.internal, the other
 * VM or the internet in either VM': the probe on each domain, no channel,
 * its report judged. Returns each VM's report, for the record.
 */
export async function networkNone(ctx: SandboxBodyContext): Promise<Record<SandboxDomain, NetworkReport>> {
  const reports: Partial<Record<SandboxDomain, NetworkReport>> = {}
  for (const domain of DOMAINS) {
    const result = await ran(ctx, specOf(ctx, domain, bodyRunId('net'), ['node', '-e', NETWORK_PROBE], { wallclockMs: 60_000 }))
    assert.equal(result.exitCode, 0, `${domain}: the probe exited ${String(result.exitCode)}: ${result.stderr.slice(0, 2_000)}`)
    const report = markedJson(result.stdout, NETWORK_MARK, `${domain}'s probe`) as NetworkReport
    assert.deepEqual(networkProblems(report), [], `${domain}: a container run with --network none has a way out`)
    reports[domain] = report
  }
  return { trusted: reports.trusted!, hostile: reports.hostile! }
}

// ── the -i channel ─────────────────────────────────────────────────────────

/**
 * 'the -i channel is binary-safe for 64 MiB': `cat` on the trusted domain over
 * a channel, `bytes` of random bytes written to its stdin and read back from
 * its stdout, held to their length and sha256, then its stdin ended, which
 * must end the container (cat's exit 0: stdin's EOF reached it through docker
 * -i and Colima's socket). Returns the time it took, for the record.
 */
export async function channelRoundTrip(ctx: SandboxBodyContext, bytes: number): Promise<{ readonly bytes: number; readonly ms: number; readonly mibPerSecond: number }> {
  const spec = specOf(ctx, 'trusted', bodyRunId('pipe'), ['cat'], { wallclockMs: Math.max(ctx.waitMs, 60_000), channel: true })
  const running: RunningSandbox = ctx.driver.run(spec)
  const channel = running.channel
  assert.ok(channel !== undefined, 'a channel run has no channel')
  const sent = createHash('sha256')
  const got = createHash('sha256')
  let received = 0
  channel.input.on('data', (chunk: Buffer) => {
    got.update(chunk)
    received += chunk.length
  })
  const started = Date.now()
  const CHUNK = 64 * 1024
  for (let at = 0; at < bytes; at += CHUNK) {
    const block = randomBytes(Math.min(CHUNK, bytes - at))
    sent.update(block)
    if (!channel.output.write(block)) await within(once(channel.output, 'drain'), ctx.waitMs, 'the channel draining')
  }
  channel.output.end()
  const result = await within(running.result, ctx.waitMs, `${spec.name}'s end after its stdin's EOF`)
  const ms = Date.now() - started
  // Its kill first: a cat its wallclock killed exits 137, which says less.
  assert.equal(result.killedBy, undefined, `the container did not end on its stdin's EOF: its ${String(result.killedBy)} kill ended it, exit ${String(result.exitCode)}`)
  assert.equal(result.exitCode, 0, `cat exited ${String(result.exitCode)}: ${result.stderr.slice(0, 2_000)}`)
  assert.equal(received, bytes, `${String(received)} of ${String(bytes)} bytes came back`)
  assert.equal(got.digest('hex'), sent.digest('hex'), 'the bytes that came back are not the bytes sent')
  return { bytes, ms, mibPerSecond: Math.round((2 * bytes) / (1024 * 1024) / Math.max(ms / 1000, 0.001)) }
}

// ── PID 1 ──────────────────────────────────────────────────────────────────

/** What each line of the init probe's report starts with. */
export const INIT_MARK = 'aos-init '

/**
 * The init probe, for the image's sh: PID 1's name, the probe's own pid,
 * then a shell that orphans a `sleep 1` and exits, three seconds, and every
 * process's /proc stat line. The orphan is reparented to PID 1, which under
 * --init is docker-init, and must have reaped it by then.
 */
export const INIT_PROBE = [
  'sh',
  '-c',
  `echo "${INIT_MARK}pid1 $(cat /proc/1/comm)"; echo "${INIT_MARK}self $$"; sh -c 'sleep 1 &'; sleep 3; ` +
    `for f in /proc/[0-9]*/stat; do echo "${INIT_MARK}stat $(cat "$f" 2>/dev/null)"; done`,
]

/** The init probe's lines, read: PID 1's name, the probe's pid, and each process's pid, name and state. */
export function readInit(stdout: string): InitReport {
  const lines = stdout.split('\n').filter((l) => l.startsWith(INIT_MARK)).map((l) => l.slice(INIT_MARK.length))
  const field = (key: string): string => (lines.find((l) => l.startsWith(`${key} `)) ?? '').slice(key.length + 1)
  const processes = lines
    .filter((l) => l.startsWith('stat '))
    .map((l) => l.slice('stat '.length))
    .filter((l) => l !== '')
    .map((stat) => {
      const close = stat.lastIndexOf(')')
      return { pid: Number(stat.slice(0, stat.indexOf(' '))), comm: stat.slice(stat.indexOf('(') + 1, close), state: stat.slice(close + 2, close + 3) }
    })
  return { pid1: field('pid1'), self: Number(field('self')), processes }
}

export interface InitReport {
  readonly pid1: string
  readonly self: number
  readonly processes: readonly { readonly pid: number; readonly comm: string; readonly state: string }[]
}

/** What in `report` shows no init reaping: PID 1 not docker-init, the command as PID 1, or a zombie. */
export function initProblems(report: InitReport): string[] {
  const problems: string[] = []
  if (report.pid1 !== 'docker-init') problems.push(`PID 1 is ${report.pid1}, not docker-init: the run has no --init`)
  if (report.self === 1) problems.push('the command is PID 1')
  for (const p of report.processes.filter((each) => each.state === 'Z')) problems.push(`${p.comm} (pid ${String(p.pid)}) is a zombie`)
  return problems
}

/** 'a run's PID 1 is docker-init, and what its command orphans is reaped', on each domain. */
export async function initReaps(ctx: SandboxBodyContext): Promise<Record<SandboxDomain, InitReport>> {
  const reports: Partial<Record<SandboxDomain, InitReport>> = {}
  for (const domain of DOMAINS) {
    const result = await ran(ctx, specOf(ctx, domain, bodyRunId('init'), INIT_PROBE, { wallclockMs: 60_000 }))
    assert.equal(result.exitCode, 0, `${domain}: the init probe exited ${String(result.exitCode)}: ${result.stderr.slice(0, 2_000)}`)
    const report = readInit(result.stdout)
    assert.ok(report.processes.length > 0, `${domain}'s init probe listed no process:\n${result.stdout.slice(0, 2_000)}`)
    assert.deepEqual(initProblems(report), [], domain)
    reports[domain] = report
  }
  return { trusted: reports.trusted!, hostile: reports.hostile! }
}

// ── the docker client killed, and kills by name ─────────────────────────────

/**
 * A container that says it has started, then writes a beat to its workspace
 * every second until it is killed: only the workspace shows, from the Mac,
 * whether it still runs.
 */
export const BEATING = ['sh', '-c', 'touch /workspace/up; i=0; while :; do i=$((i+1)); echo $i > /workspace/beat; sleep 1; done']

const beat = (workspace: string): string => (existsSync(join(workspace, 'beat')) ? readFileSync(join(workspace, 'beat'), 'utf8') : '')

/** A beating container on `domain`, once it says it is up and its beat has moved across a pause (ctx.pauseMs, past the beat's second on the Mac). */
async function beatingOn(ctx: SandboxBodyContext, domain: SandboxDomain, what: string, command: readonly string[] = BEATING, channel = false): Promise<{ readonly runId: string; readonly spec: SandboxSpec; readonly running: RunningSandbox }> {
  const runId = bodyRunId(what)
  const spec = specOf(ctx, domain, runId, command, { wallclockMs: 300_000, ...(channel ? { channel: true as const } : {}) })
  const running = ctx.driver.run(spec)
  // A channel's input is read at once, as RunningSandbox says a caller must.
  running.channel?.input.on('data', () => undefined)
  // A wait bounded by its own count, ctx.waitMs in steps, so it ends
  // whatever the check after it says.
  const step = Math.min(ctx.pauseMs, 250)
  for (let waited = 0; !existsSync(join(spec.workspace, 'up')) && waited < ctx.waitMs; waited += step) await pause(step)
  assert.ok(existsSync(join(spec.workspace, 'up')), `${domain}: ${spec.name} never wrote /workspace/up`)
  await beats(ctx, spec, domain)
  return { runId, spec, running }
}

/** The container's beat moves across a pause: it runs, and its writes land where the Mac reads them. */
async function beats(ctx: SandboxBodyContext, spec: SandboxSpec, domain: SandboxDomain): Promise<void> {
  const before = beat(spec.workspace)
  await pause(ctx.pauseMs)
  assert.notEqual(beat(spec.workspace), before, `${domain}: ${spec.name} never beat across ${String(ctx.pauseMs)} ms, so nothing here shows it runs`)
}

/** The container's beat stays put across a pause, after one to let a kill land. */
async function stopped(ctx: SandboxBodyContext, spec: SandboxSpec, domain: SandboxDomain, after: string): Promise<void> {
  await pause(ctx.pauseMs)
  const before = beat(spec.workspace)
  await pause(ctx.pauseMs)
  assert.equal(beat(spec.workspace), before, `${domain}: ${spec.name} still writes its workspace after ${after}`)
}

/** A sweep of both VMs for `name` finds nothing to kill, and lists both. */
async function sweptNothing(ctx: SandboxBodyContext, runId: string, name: string, domain: SandboxDomain): Promise<void> {
  const sweep = await ctx.driver.sweepOrphans({ runIds: [runId], names: [name], signal: AbortSignal.timeout(ctx.waitMs) })
  assert.deepEqual(sweep, { swept: [], unlisted: [], failed: [] }, `${domain}: a VM still runs ${name}, or could not be listed`)
}

/**
 * 'killing the docker client then kill-by-name leaves no aos-run-
 * container': on each domain, a beating container; once its beat is seen to
 * move, the driver gives up on it (abandon: SIGKILL to its docker CLI, and a
 * kill by name on its domain), and then sends the kill by name the runner
 * sends after an end that says nothing of the container (mayRunOn). The beat
 * must then stop, and a sweep of both VMs for its name must find nothing to
 * kill. Then the sweep's own evidence, on a container that runs: a second
 * beating container is swept by name (the boot sweep's `docker ps --filter
 * name=aos-run- --format {{.Names}}` and kill, README's NEEDS VALIDATION
 * row), which must name it in `swept`, its run must end with the docker
 * CLI's 137 (the exit of a CLI whose container another client killed, which
 * the driver credits to no kill of its own), its beat must stop, and a
 * second sweep must find nothing. abandon itself kills by name, so whether a
 * container outlives a SIGKILL of its CLI alone is not observable here.
 */
export async function clientKilledThenKillByName(ctx: SandboxBodyContext): Promise<Record<SandboxDomain, { readonly abandoned: SandboxResult; readonly swept: SandboxResult }>> {
  const ends: Partial<Record<SandboxDomain, { readonly abandoned: SandboxResult; readonly swept: SandboxResult }>> = {}
  for (const domain of DOMAINS) {
    const given = await beatingOn(ctx, domain, 'cli')
    await ctx.driver.abandon(given.spec.name)
    const abandoned = await within(given.running.result, ctx.waitMs, `${given.spec.name}'s docker client, once SIGKILLed`)
    assert.equal(abandoned.killedBy, undefined, `${domain}: a run given up is no requested kill`)
    await ctx.driver.kill(given.spec.name)
    await stopped(ctx, given.spec, domain, "its client's SIGKILL and the kill by name")
    await sweptNothing(ctx, given.runId, given.spec.name, domain)

    const running = await beatingOn(ctx, domain, 'sweep')
    const sweep = await ctx.driver.sweepOrphans({ runIds: [running.runId], names: [running.spec.name], signal: AbortSignal.timeout(ctx.waitMs) })
    assert.deepEqual(sweep, { swept: [running.spec.name], unlisted: [], failed: [] }, `${domain}: a sweep did not list and kill ${running.spec.name}, which runs`)
    const swept = await within(running.running.result, ctx.waitMs, `${running.spec.name}'s docker client, once its container was swept`)
    assert.equal(swept.exitCode, 137, `${domain}: the docker CLI of a container another client killed exited ${String(swept.exitCode)}, not 137`)
    await stopped(ctx, running.spec, domain, 'the sweep killed it by name')
    await sweptNothing(ctx, running.runId, running.spec.name, domain)
    ends[domain] = { abandoned, swept }
  }
  return { trusted: ends.trusted!, hostile: ends.hostile! }
}

/**
 * A kill by name ends a running container's run with the docker CLI's 137,
 * which the driver credits to the kill (killedBy requested, SIGKILL: finish()
 * in DockerDriver.run credits a kill only on a 137, README's NEEDS
 * VALIDATION row), on each domain; its beat stops, and a sweep finds nothing.
 */
export async function killedByName(ctx: SandboxBodyContext): Promise<Record<SandboxDomain, SandboxResult>> {
  const ends: Partial<Record<SandboxDomain, SandboxResult>> = {}
  for (const domain of DOMAINS) {
    const { runId, spec, running } = await beatingOn(ctx, domain, 'kill')
    await ctx.driver.kill(spec.name)
    const end = await within(running.result, ctx.waitMs, `${spec.name} once killed by name`)
    assert.deepEqual([end.exitCode, end.signal, end.killedBy], [137, 'SIGKILL', 'requested'], `${domain}: a kill by name ended the run with exit ${String(end.exitCode)}, signal ${String(end.signal)}, killedBy ${String(end.killedBy)}`)
    await stopped(ctx, spec, domain, 'its kill by name')
    await sweptNothing(ctx, runId, spec.name, domain)
    ends[domain] = end
  }
  return { trusted: ends.trusted!, hostile: ends.hostile! }
}

/** BEATING, its beat copied to its stdout too, so the docker CLI has container output to copy. */
export const BEATING_OUT = ['sh', '-c', 'touch /workspace/up; i=0; while :; do i=$((i+1)); echo $i > /workspace/beat; echo $i; sleep 1; done']

export interface DestroyedInputRecord {
  /** The docker CLI had ended, its run settled, before the kill by name. */
  readonly cliEndedFirst: boolean
  /** The container still beat after its input was destroyed (and after its CLI ended, when it had). */
  readonly containerRanOn: boolean
  readonly end: SandboxResult
}

/**
 * What the docker CLI of a channel run does when the reader of its stdout
 * goes away (README's NEEDS VALIDATION row for `docker run -i`): on the
 * trusted domain, a beating container that copies its beat to its stdout,
 * over a channel; once it beats, the channel's input is destroyed, as an
 * egress session aborting on a violation destroys it. Recorded, not judged:
 * whether the CLI then ends before any kill, and whether the container runs
 * on after it. Judged: a kill by name then stops the beat, the run's result
 * settles, and a sweep finds nothing, whatever the CLI did.
 */
export async function channelInputDestroyed(ctx: SandboxBodyContext): Promise<DestroyedInputRecord> {
  const { runId, spec, running } = await beatingOn(ctx, 'trusted', 'pipe_gone', BEATING_OUT, true)
  const channel = running.channel
  assert.ok(channel !== undefined, 'a channel run has no channel')
  channel.input.destroy()
  let settled: SandboxResult | undefined
  void running.result.then((result) => {
    settled = result
  })
  // Two pauses: the CLI's next copy of a beat meets the closed pipe within the first.
  await pause(2 * ctx.pauseMs)
  const cliEndedFirst = settled !== undefined
  const before = beat(spec.workspace)
  await pause(ctx.pauseMs)
  const containerRanOn = beat(spec.workspace) !== before
  await ctx.driver.kill(spec.name)
  const end = await within(running.result, ctx.waitMs, `${spec.name} once its input was destroyed and it was killed by name`)
  await stopped(ctx, spec, 'trusted', 'its input was destroyed and it was killed by name')
  await sweptNothing(ctx, runId, spec.name, 'trusted')
  return { cliEndedFirst, containerRanOn, end }
}

// ── the hostile wallclock ──────────────────────────────────────────────────

/**
 * 'a hostile wallclock kills on the hostile socket': a hostile `sleep` far
 * longer than its wallclock must be killed at the wallclock, which only a
 * kill sent to the hostile VM's own daemon does (one sent to the trusted VM's
 * finds no such container there, and the run would end only when its sleep
 * did), and leave nothing on either VM. `overrun`, offline only, stands in for
 * the wallclock's timer, which the fake driver leaves to the test.
 */
export async function hostileWallclock(ctx: SandboxBodyContext, wallclockMs: number, overrun?: (name: string) => void): Promise<SandboxResult> {
  const runId = bodyRunId('wall')
  const spec = specOf(ctx, 'hostile', runId, ['sleep', '600'], { wallclockMs })
  const running = ctx.driver.run(spec)
  overrun?.(spec.name)
  const end = await within(running.result, ctx.waitMs, `${spec.name} at its wallclock of ${String(wallclockMs)} ms`)
  assert.equal(end.killedBy, 'wallclock', `the hostile run ended ${String(end.exitCode)} with killedBy ${String(end.killedBy)}`)
  assert.equal(end.exitCode, 137)
  assert.ok(end.durationMs < wallclockMs + 60_000, `the hostile run lasted ${String(end.durationMs)} ms, a minute past its wallclock`)
  const sweep = await ctx.driver.sweepOrphans({ runIds: [runId], names: [spec.name], signal: AbortSignal.timeout(ctx.waitMs) })
  assert.deepEqual(sweep, { swept: [], unlisted: [], failed: [] }, `a VM still runs ${spec.name}, or could not be listed`)
  return end
}

// ── the canaries, and each VM's self-test ──────────────────────────────────

/** The probes a self-test report names, each its target and the code it met; none for a report that is not one. */
function selfTestProbes(report: string): readonly { readonly target: string; readonly error: string | null }[] {
  try {
    const probes = (JSON.parse(report) as { probes?: unknown }).probes
    return Array.isArray(probes) ? probes.map((p) => ({ target: String((p as { target?: unknown }).target), error: ((p as { error?: unknown }).error ?? null) as string | null })) : []
  } catch {
    return []
  }
}

export interface CanaryRecord {
  readonly verdicts: Readonly<Record<SandboxDomain, CanaryVerdict>>
  /** Each VM's self-test probes, as its mux reported them: target, then the code it met. */
  readonly codes: Readonly<Record<SandboxDomain, readonly (readonly [string, string | null])[]>>
}

/**
 * 'both canaries pass, and each VM's self-test meets only codes the judge
 * accepts': each domain's boot canary run as boot runs it (runCanary, into
 * `store`), then the mux's self-test (`--self-test`, the hostile canary's
 * command, no channel) on each VM, its report judged by acceptReady, the
 * judge every exec's ready is held to. Returns what each VM met.
 */
export async function canariesPass(ctx: SandboxBodyContext, store: EventStore, egressLimits: SessionLimits): Promise<CanaryRecord> {
  const verdicts: Partial<Record<SandboxDomain, CanaryVerdict>> = {}
  const codes: Partial<Record<SandboxDomain, (readonly [string, string | null])[]>> = {}
  for (const domain of DOMAINS) {
    const workspace = makeWorkspace(domain, ctx.mountRoots[domain], CANARY_WORKSPACE)
    const verdict = await runCanary({
      driver: ctx.driver,
      store,
      domain,
      name: canaryName(1, canaryNonce(), domain),
      imageId: ctx.imageId,
      workspace,
      limits: { ...ctx.caps, wallclockMs: 600_000 },
      egressLimits,
      acceptReady,
      waitMs: ctx.waitMs,
    })
    assert.deepEqual(verdict, { ok: true }, `${domain}'s canary did not pass`)
    verdicts[domain] = verdict

    const result = await ran(ctx, specOf(ctx, domain, bodyRunId('self'), CANARY_COMMANDS.hostile, { wallclockMs: 60_000 }))
    assert.equal(result.exitCode, 0, `${domain}: the self-test exited ${String(result.exitCode)}: ${result.stderr.slice(0, 2_000)}`)
    const report = result.stdout.trim()
    // Its targets first, by name, then the judge, which refuses a report
    // that leaves one out too, but says only that it does not name them all.
    const probes = selfTestProbes(report)
    assert.deepEqual(probes.map((p) => p.target), SELF_TEST.map(probeTarget), `${domain}: the VM's self-test report does not name every probe the kernel runs, in order`)
    assert.equal(acceptReady(Buffer.from(report, 'utf8')), undefined, `${domain}: the judge refused the VM's self-test report`)
    codes[domain] = probes.map((p) => [p.target, p.error] as const)
  }
  // The trusted canary's round trip is in the log: its grant, the deny of its one request, the grant revoked.
  const types = store.query().map((r) => r.type)
  for (const type of ['proxy.grant.issued', 'proxy.decision', 'proxy.grant.revoked']) assert.ok(types.includes(type), `the canaries left no ${type}`)
  return { verdicts: { trusted: verdicts.trusted!, hostile: verdicts.hostile! }, codes: { trusted: codes.trusted!, hostile: codes.hostile! } }
}

// ── the image's node and its proxy settings ────────────────────────────────

/** The EnvHttpProxyAgent warning Node 22.22 prints for every process under NODE_USE_ENV_PROXY=1 (I1's review). */
export const ENV_PROXY_WARNING = /EnvHttpProxyAgent is experimental/

/** What each line of the proxy probe's report starts with. */
export const PROXY_MARK = 'aos-proxy '

/**
 * The proxy probe, for the image's node: a server of its own on 127.0.0.1,
 * on a port the kernel picks, that answers with a nonce; a fetch of it, and
 * one of a host outside (http://github.com/), each line `loopback` or
 * `external`, then `answered <status> <body>` or `refused <code>`. Under the
 * image's NODE_USE_ENV_PROXY=1, HTTP_PROXY=http://127.0.0.1:3128 and an
 * empty NO_PROXY, a request goes to 3128, where nothing listens with no
 * channel, unless Node bypasses the proxy for it.
 */
export function proxyProbe(nonce: string): readonly string[] {
  const program = [
    "const http = require('node:http')",
    `const server = http.createServer((req, res) => res.end(${JSON.stringify(nonce)}))`,
    "const said = (what) => (r) => r.text().then((body) => console.log('" + PROXY_MARK + "' + what + ' answered ' + r.status + ' ' + body))",
    "const refused = (what) => (e) => console.log('" + PROXY_MARK + "' + what + ' refused ' + String((e.cause && e.cause.code) || e.message))",
    "server.listen(0, '127.0.0.1', async () => {",
    "  const port = server.address().port",
    "  await fetch('http://127.0.0.1:' + port + '/').then(said('loopback'), refused('loopback'))",
    "  await fetch('http://github.com/').then(said('external'), refused('external'))",
    '  server.close()',
    '})',
  ].join('\n')
  return ['node', '-e', program]
}

export interface ProxyRecord {
  readonly warned: boolean
  /** A fetch of the container's own loopback server: answered by it (Node bypassed the proxy), or refused (it went to 3128). */
  readonly loopback: 'answered' | 'refused'
  readonly stdout: string
  readonly stderr: string
}

/** What in the proxy probe's lines shows something outside the container answered, or nothing. */
export function proxyProblems(stdout: string, nonce: string): string[] {
  const lines = stdout.split('\n').filter((l) => l.startsWith(PROXY_MARK)).map((l) => l.slice(PROXY_MARK.length))
  const problems: string[] = []
  const loopback = lines.find((l) => l.startsWith('loopback '))
  const external = lines.find((l) => l.startsWith('external '))
  if (loopback === undefined || external === undefined) return [`the probe printed no loopback and external line:\n${stdout.slice(0, 2_000)}`]
  // Answered, it must be by the probe's own server: anything else answered from outside.
  if (loopback.startsWith('loopback answered ') && !loopback.endsWith(` ${nonce}`)) problems.push(`a fetch of the container's own 127.0.0.1 server was answered by something else: ${loopback}`)
  else if (!loopback.startsWith('loopback answered ') && !loopback.startsWith('loopback refused ')) problems.push(`the loopback fetch neither answered nor was refused: ${loopback}`)
  if (!external.startsWith('external refused ')) problems.push(`a fetch of http://github.com/ in a container with no channel was not refused: ${external}`)
  return problems
}

/**
 * 'the image's node reaches nothing through its proxy settings with no
 * channel': the proxy probe on the trusted domain, no channel. Judged:
 * nothing outside the container answered, the external fetch refused and a
 * loopback answer only the probe's own. Recorded (README's NEEDS VALIDATION
 * row for the image asks both of its Node): whether a request to a server
 * the run itself listens on at 127.0.0.1 went to the proxy with NO_PROXY
 * empty, and whether node prints the EnvHttpProxyAgent warning, which L2
 * must not mistake for a failure.
 */
export async function nodeProxyWarning(ctx: SandboxBodyContext): Promise<ProxyRecord> {
  const nonce = `aos-proxy-probe-${randomBytes(8).toString('hex')}`
  const result = await ran(ctx, specOf(ctx, 'trusted', bodyRunId('undici'), proxyProbe(nonce), { wallclockMs: 60_000 }))
  assert.equal(result.exitCode, 0, `the proxy probe exited ${String(result.exitCode)}: ${result.stderr.slice(0, 2_000)}`)
  assert.deepEqual(proxyProblems(result.stdout, nonce), [], 'the image\'s node reached something through its proxy settings')
  return {
    warned: ENV_PROXY_WARNING.test(result.stderr),
    loopback: result.stdout.includes(`${PROXY_MARK}loopback answered `) ? 'answered' : 'refused',
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim().slice(0, 400),
  }
}
