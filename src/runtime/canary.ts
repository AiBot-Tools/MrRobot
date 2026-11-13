// The boot canary (egress plan W3): one container on each domain, at boot,
// that shows the domain's network is the --network none the kernel asks for,
// and on the trusted domain that the egress engine judges and records what
// crosses a channel, before any run is given egress.
//
// Contract: boot runs both canaries once the sandbox probe has passed (so the
// pinned image is on each VM by its id: src/sandbox/docker.ts probe) and the
// orphan sweep has finished, while egress is enabled, at once, each bounded
// by `waitMs`, before the sandbox's mark, and egress is ok only when both
// pass (src/kernel.ts). Each is a container the driver runs as it runs any
// other, under every rule of invariant 9 and the driver's audit (the pinned
// image by id with --pull=never, --network none, a channel on the trusted
// domain only, a wallclock no more than sandbox.defaults.wallclockMs), from
// the worker image's own mux (MUX_ARGV, which every channel exec's command
// starts with too):
//
//   trusted:  node /opt/aos/mux.mjs --canary     (with a channel)
//   hostile:  node /opt/aos/mux.mjs --self-test  (no channel)
//
// Both mux modes start with the self-test (images/worker/mux.mjs SELF_TEST),
// whose report the kernel judges with the same judge every exec's ready is
// judged by (src/egress/ready.ts acceptReady): every direct connect and the
// lookup must have failed, each with a code that says there is no route,
// ETIMEDOUT, EHOSTUNREACH and EOTHER refused above all. The trusted canary
// then completes one framed round trip over its channel: its mux sends one
// request of its own (mux.mjs CANARY_REQUEST, for pmmcp on the Mac's
// loopback as a VM sees it) through its listener, as a worker's goes, and
// the kernel's egress session, under a canary grant that serves no run and
// reaches nothing, denies it and appends its proxy.decision row, which the
// log must hold; the mux's exit frame says it read the kernel's 403. The
// hostile canary writes its report as one line on stdout, the driver's
// capture of a run with no channel, and does nothing else.
//
// A report the judge refuses fails egress and closes its domain to
// sandbox.exec as well (CanaryVerdict.closes, routed): a run with no channel
// has no self-test of its own, so the canary is the only evidence of that
// domain's network the kernel has. The closure is recorded and kept across
// boots (src/kernel.ts, src/events/projections.ts closedSandboxDomains):
// only a later boot's canary that passes on that domain reopens it, so a
// boot that runs none (egress disabled, a probe or a sweep that failed) or
// one whose canary there failed for anything else keeps it closed. Every
// other failure (a driver that refuses, a container that never ends, a
// round trip not completed) fails egress alone, and reopens nothing.
//
// Recorded: each canary's sandbox.started and sandbox.killed, under no run
// and no agent; on the trusted domain, its proxy.grant.issued (purpose
// `canary`, its `sandbox` the container's name) before the container starts,
// the deny, and proxy.grant.revoked with the grant's totals. A failed canary
// is one egress.degraded row of boot's (check `canary`, naming the domain),
// whose reason names what failed (a probe and the code it met, a round trip
// not completed, a container that never ended) and what fixes it; a closed
// domain is one sandbox.degraded row of boot's besides, naming the domain
// (`closes`), at this boot and at every later one until a canary there passes.
//
// Names: each canary is named uniquely per boot, `aos-run-canary-<seq>-
// <nonce>-<domain>` (canaryName), `<seq>` the boot's own kernel.booted row,
// which no earlier boot of the log had, and `<nonce>` random, so that two
// logs on one VM do not share a name either. No name is a run's container
// (containerRunId reads none from it: its last part is a domain, not a
// number). The next boot's sweep (src/kernel.ts sweepTargets) kills by name
// a canary a kernel that died during its boot left running, or one whose end
// this kernel did not see (given up, its result lost, its docker client
// exiting 125 or with no status): either one by its sandbox.started row
// under no run with no sandbox.killed after it that records an exit the
// driver saw (src/events/projections.ts openRunlessSandboxes), appended in
// the tick the driver starts it, before anything is awaited, and the trusted
// one by its open grant's `sandbox` as well, issued before it starts. A name
// is never reused, so no kill an earlier boot's sweep sent and a paused VM
// still holds can end a canary of this boot's (plan W3's note). The hostile
// canary needs no kernel to end it besides: its self-test's probes are
// bounded (PROBE_TIMEOUT_MS each, at once) and so is its one write
// (FLUSH_TIMEOUT_MS), and with no channel and no network nothing can hold it
// open, so it exits within seconds of its start.
//
// Never rejects: a driver that refuses or throws, a container that never
// ends, a log that refuses a row, each is a failed canary saying so.

import { randomBytes } from 'node:crypto'

import { EgressGrant } from '../egress/policy.js'
import { createEgressSession, type EgressSession, type ReadyJudge, type SessionLimits, type SessionOutcome } from '../egress/session.js'
import type { Upstream } from '../egress/upstream.js'
import { recordable } from '../events/bound.js'
import { redactString } from '../events/redact.js'
import type { AppendInput } from '../events/store.js'
import { EGRESS_DETAIL_BYTES, EGRESS_REASON_BYTES, ProxyGrantIssuedPayload } from '../events/types.js'
import { log } from '../log.js'
import { CONTAINER_PREFIX, type SandboxDomain, type SandboxDriver, type SandboxResult, type SandboxSpec } from '../sandbox/driver.js'
import { endReason, KILL_WAIT_MS, mayRunOn, MUX_ARGV } from './sandbox-tools.js'

/**
 * Every canary container's name starts so: the kernel's prefix, then
 * `canary-`. No run's container does: the kernel names a run `run_<ms>_<id>`
 * (src/kernel.ts), so a run's container is `aos-run-run_...-<n>`.
 */
export const CANARY_PREFIX = `${CONTAINER_PREFIX}canary-`

/** The canary's workspace under each domain's mountRoot (sandbox-tools.ts makeWorkspace): one directory, reused by every boot, which the mux never writes. */
export const CANARY_WORKSPACE = 'aos_canary'

/**
 * What each domain's canary runs: the worker image's mux (MUX_ARGV, the one
 * every channel exec's command starts with) in its canary mode (trusted, over
 * the channel) or its self-test mode (hostile, no channel).
 */
export const CANARY_COMMANDS: Readonly<Record<SandboxDomain, readonly string[]>> = Object.freeze({
  trusted: Object.freeze([...MUX_ARGV, '--canary']),
  hostile: Object.freeze([...MUX_ARGV, '--self-test']),
})

/**
 * Each canary container's hard wallclock (the driver kills it by name when
 * it elapses), unless sandbox.defaults.wallclockMs, the operator's cap on
 * every container, is lower: then that. The self-test takes at most some
 * 2 s (mux.mjs PROBE_TIMEOUT_MS, all probes at once), the round trip at most
 * 10 s (CANARY_TIMEOUT_MS), and a docker run's start a second or two.
 * test/egress-mux.test.ts holds the three bounds here to the mux's own and
 * to each other: CANARY_WAIT_MS past this by KILL_WAIT_MS at least, this at
 * least CANARY_MIN_WALLCLOCK_MS, and that at least the mux's probes, its
 * round trip (or its one write) and a container's start.
 */
export const CANARY_WALLCLOCK_MS = 20_000

/**
 * The least wallclock a canary is run under: its self-test's probes (2 s),
 * its round trip's bound (10 s) and a container's start and its mux's exit.
 * A cap below it is a canary that could be killed at its wallclock before
 * its round trip's own bound, a failure read as the VM's: so the canary is
 * not run, and fails naming the key.
 */
export const CANARY_MIN_WALLCLOCK_MS = 15_000

/**
 * How long boot waits for each canary's result before it gives the container
 * up (SandboxDriver.abandon) and records the canary failed: its wallclock and
 * a grace of at least KILL_WAIT_MS, so the driver's kill at the wallclock has
 * as long to land as any kill by name is given, before a daemon that accepts
 * and never answers (a paused VM) is given up. A test hands its own
 * (BootOptions.canaryWaitMs).
 */
export const CANARY_WAIT_MS = 30_000

/** The mux's exit for arguments it does not read (mux.mjs MUX_EXIT.usage): an image whose mux predates the canary. */
export const MUX_USAGE_EXIT = 64

/** decide()'s run id for a canary grant: never recorded (the session appends a canary's rows under no run), and never reached (a canary grant has no host). */
const CANARY_GRANT_RUN = 'canary'

const ZERO_TOTALS = Object.freeze({ flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 })

/** The one upstream a canary's session holds: it refuses every request unsent, and a canary grant lets none reach it. */
const NOWHERE: Upstream = Object.freeze({
  request: () => Promise.resolve({ ok: false as const, reason: 'not-decided' as const, sent: false, why: 'a canary grant reaches nothing' }),
})

/** A canary's name, unique to this boot and this log (see the header). */
export function canaryName(bootSeq: number, nonce: string, domain: SandboxDomain): string {
  return `${CANARY_PREFIX}${String(bootSeq)}-${nonce}-${domain}`
}

/** A fresh nonce for canaryName: 6 random bytes, as hex. */
export function canaryNonce(): string {
  return randomBytes(6).toString('hex')
}

/**
 * What a canary came to. A failed one's `why` is its egress.degraded reason;
 * `closes`, set only when its self-test report was refused (routed), is the
 * sandbox's reason for running no sandbox.exec on that domain at all.
 */
export type CanaryVerdict = { readonly ok: true } | { readonly ok: false; readonly why: string; readonly closes?: string }

export interface CanaryOptions {
  readonly driver: SandboxDriver
  readonly store: { append(input: AppendInput): unknown }
  readonly domain: SandboxDomain
  /** canaryName's. */
  readonly name: string
  /** sandbox.imageId, which the probe has found on the domain's VM by that id. */
  readonly imageId: string
  /** <mountRoot>/CANARY_WORKSPACE, made by the caller (makeWorkspace). */
  readonly workspace: string
  /** sandbox.defaults' caps, as an exec's are given; the canary's wallclock is the lower of CANARY_WALLCLOCK_MS and this one's. */
  readonly limits: { readonly memoryMb: number; readonly cpus: number; readonly pids: number; readonly wallclockMs: number }
  /** kernel.yaml's egress.limits, as every exec's session is given them. */
  readonly egressLimits: SessionLimits
  readonly acceptReady: ReadyJudge
  /** Unset, CANARY_WAIT_MS. */
  readonly waitMs?: number
}

/** `promise`'s value, or `late` once `ms` have passed. */
async function within<T>(promise: Promise<T>, ms: number): Promise<{ readonly value: T } | { readonly late: true }> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<{ readonly late: true }>((resolve) => {
    timer = setTimeout(() => resolve({ late: true }), ms)
  })
  try {
    return await Promise.race([promise.then((value) => ({ value })), late])
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Run one domain's canary, and say whether it passed. Never rejects (see the
 * header). The caller has checked that egress is enabled and the sandbox's
 * probe passed.
 */
export async function runCanary(options: CanaryOptions): Promise<CanaryVerdict> {
  try {
    return await canary(options)
  } catch (e) {
    // A driver or a log that broke its contract: the canary did not pass.
    return failed(options, `it could not be run: ${e instanceof Error ? e.message : String(e)}`, FIX_RESTART)
  }
}

const FIX_RESTART = 'check that the VM answers (scripts/colima-up.sh), then restart the kernel'
const FIX_IMAGE =
  "rebuild the worker image (scripts/build-worker-image.sh), so its mux has --canary and --self-test, pin the id it prints as sandbox.imageId, and restart the kernel"
const FIX_NETWORK =
  "a container on this domain has a route the kernel did not give it: check the VM's Docker (it must honour --network none) and the worker image, then restart the kernel"

/** A failed canary's verdict: which domain's canary, what failed, and what fixes it, bounded for its egress.degraded row. */
function failed(options: Pick<CanaryOptions, 'domain' | 'name'>, what: string, fix: string): { readonly ok: false; readonly why: string } {
  const why = `the ${options.domain} domain's canary (${options.name}) did not pass: ${what}. So no run is given egress: ${fix}`
  return { ok: false, why: recordable(why, EGRESS_REASON_BYTES) }
}

/**
 * A canary whose self-test report the judge refused (`clause`, the judge's
 * own words): a probe that reached what --network none keeps out, one that
 * met a code that does not say there is no route (a SYN that timed out went
 * somewhere), or a report the judge does not read as one. The kernel then
 * has no evidence that a container on the domain is cut off, and some that
 * one is not, so the domain is closed to sandbox.exec (`closes`), not only
 * to egress: a run with no channel (every hostile run, and every trusted run
 * whose manifest has no egress) has no self-test of its own, and this is the
 * only evidence of that domain's network the kernel has. It stays closed
 * at every later boot, however often the kernel restarts, until one whose
 * canary on the domain passes (src/kernel.ts), which needs egress enabled:
 * the reason says so. The operator's decision, put to them with egress plan
 * W3's review round 2: until then, the conservative reading.
 */
function routed(options: Pick<CanaryOptions, 'domain' | 'name'>, clause: string): CanaryVerdict {
  const closes =
    `${options.domain}: the boot canary (${options.name}) found that a container on this domain may have a route the ` +
    `kernel did not give it (its self-test report was refused: ${clause}), so this domain runs no sandbox.exec until a ` +
    "boot whose canary there passes: check the VM's Docker (it must honour --network none) and the worker image, then " +
    'restart the kernel with egress enabled, so that its canaries run'
  return { ...failed(options, `its self-test report was refused: ${clause}`, FIX_NETWORK), closes: recordable(closes, EGRESS_REASON_BYTES) }
}

async function canary(options: CanaryOptions): Promise<CanaryVerdict> {
  const { driver, store, domain, name } = options
  const waitMs = options.waitMs ?? CANARY_WAIT_MS
  if (!name.startsWith(CANARY_PREFIX) || redactString(name) !== name) {
    return failed(options, 'its name is not a canary name the log records as it is', FIX_RESTART)
  }
  // Before anything is issued or run: a cap the canary cannot pass under.
  const wallclockMs = Math.min(CANARY_WALLCLOCK_MS, options.limits.wallclockMs)
  if (!(wallclockMs >= CANARY_MIN_WALLCLOCK_MS)) {
    return failed(
      options,
      `sandbox.defaults.wallclockMs (${String(options.limits.wallclockMs)} ms) is less than the ${String(CANARY_MIN_WALLCLOCK_MS)} ms ` +
        'a canary needs, so it was not run',
      `raise sandbox.defaults.wallclockMs in config/kernel.yaml to ${String(CANARY_MIN_WALLCLOCK_MS)} or more, then restart the kernel`,
    )
  }
  const channel = domain === 'trusted'
  // A kill by name sent and not waited on, which never throws or rejects
  // here: a driver whose kill does is no reason to leave the canary's
  // verdict unsaid (an exec's kill is sent the same way).
  const killByName = (): void => {
    void Promise.resolve()
      .then(() => driver.kill(name))
      .catch(() => undefined)
  }
  const spec: SandboxSpec = {
    name,
    // A canary serves no run: these two are the spec's typing only, and no
    // driver reads them.
    runId: CANARY_GRANT_RUN,
    agentId: 'kernel',
    domain,
    image: options.imageId,
    command: CANARY_COMMANDS[domain],
    workspace: options.workspace,
    limits: { memoryMb: options.limits.memoryMb, cpus: options.limits.cpus, pids: options.limits.pids, wallclockMs },
    ...(channel ? { channel: true } : {}),
  }

  // The trusted canary's grant, issued BEFORE the spawn, as an exec's is:
  // the container's first byte on its channel is judged under a grant the
  // log already holds, and while it is open the sweep names its container.
  const grantId = `grant_${String(Date.now())}_${randomBytes(6).toString('hex')}`
  if (channel) {
    const payload = { schemaVersion: 1, grantId, purpose: 'canary', sandbox: name, domain: 'trusted', allow: [], routes: [] }
    if (!ProxyGrantIssuedPayload.safeParse(payload).success || redactString(grantId) !== grantId) {
      return failed(options, 'its grant is not one proxy.grant.issued records', FIX_RESTART)
    }
    store.append({ type: 'proxy.grant.issued', payload })
  }
  // The grant of a canary no session served, revoked in error. Its detail is
  // bounded as the revoked row's is: an unserved one may quote a session's
  // refusal (a schema error's message among them) of any length, and a row
  // the log refuses would leave the grant open until the next boot.
  const revokeUnserved = (detail: string): void => {
    if (!channel) return
    store.append({
      type: 'proxy.grant.revoked',
      payload: { schemaVersion: 1, grantId, reason: 'error', detail: recordable(detail, EGRESS_DETAIL_BYTES), totals: ZERO_TOTALS },
    })
  }

  let running: ReturnType<SandboxDriver['run']>
  try {
    running = driver.run(spec)
  } catch (e) {
    // Refused before anything started (SandboxDriver.run): nothing to record
    // but the grant, which served nothing.
    revokeUnserved('the driver refused the canary before it started')
    return failed(options, `the driver refused it: ${e instanceof Error ? e.message : String(e)}`, FIX_RESTART)
  }

  // The decision rows the log took, of the session's: the round trip is
  // shown only by a deny the log holds. A deny row the session appends late
  // (its deny window, flushed as it ends) and the log refuses is counted in
  // the revocation's detail, on its own reason, `exited` among them: so it
  // is counted here, where the store says so.
  const recorded = { decisions: 0, denies: 0 }
  const sessionStore = {
    append: (input: AppendInput): unknown => {
      const appended = store.append(input)
      if (input.type === 'proxy.decision') {
        recorded.decisions++
        const verdict = typeof input.payload === 'object' && input.payload !== null ? (input.payload as Record<string, unknown>)['verdict'] : undefined
        if (verdict === 'deny') recorded.denies++
      }
      return appended
    },
  }

  // The session listens on the channel at once, before anything is awaited:
  // a channel run's result settles only once its input has been read to its
  // end (RunningSandbox.result).
  let session: EgressSession | undefined
  let unserved: string | undefined
  if (channel) {
    if (running.channel === undefined) {
      unserved = 'the driver gave the canary no channel'
    } else {
      try {
        session = createEgressSession({
          grantId,
          grant: EgressGrant.parse({ runId: CANARY_GRANT_RUN, allow: [], routes: [] }),
          canary: true,
          limits: options.egressLimits,
          channel: { input: running.channel.input, output: running.channel.output },
          store: sessionStore,
          upstream: NOWHERE,
          credential: () => undefined,
          acceptReady: options.acceptReady,
          kill: killByName,
        })
      } catch (e) {
        unserved = `the egress session would not start: ${e instanceof Error ? e.message : String(e)}`
      }
    }
    if (session === undefined) killByName()
  }

  // A row the log refuses (the kernel's bug, never the container's) fails
  // the canary, once its container has ended: a container the log cannot
  // record is not left running.
  let refusedRow: string | undefined
  const append = (input: AppendInput): void => {
    try {
      store.append(input)
    } catch (e) {
      refusedRow ??= `the log refused its ${input.type} row (${e instanceof Error ? e.message : String(e)})`
    }
  }
  append({
    type: 'sandbox.started',
    payload: {
      schemaVersion: 1,
      sandboxId: name,
      driver: driver.name,
      domain,
      image: options.imageId,
      memoryMb: options.limits.memoryMb,
      pids: options.limits.pids,
      wallclockMs,
    },
  })
  if (refusedRow !== undefined) killByName()

  // A result that rejects breaks the driver's contract (it settles and never
  // rejects) and says nothing of the container: killed by name, as an
  // exec's is, and recorded as an error.
  const waited = await within(
    running.result.then(
      (result) => ({ result }),
      (e: unknown) => ({ rejected: e }),
    ),
    waitMs,
  )
  if ('late' in waited) {
    // The driver never answered: its CLI is ended and the container killed
    // by name (abandon), within a bound, and its end recorded as an error.
    log.warn({ sandboxId: name, driver: driver.name, waitMs }, 'the boot canary never ended; boot gave it up')
    await within(
      Promise.resolve()
        .then(() => driver.abandon(name))
        .catch(() => undefined),
      KILL_WAIT_MS,
    )
    append({ type: 'sandbox.killed', payload: { schemaVersion: 1, sandboxId: name, reason: 'error' } })
    const detail = `the canary did not end within ${String(waitMs)} ms, and was given up`
    if (session !== undefined) await session.end('error', detail)
    else if (unserved !== undefined) revokeUnserved(unserved)
    return failed(options, `it did not end within ${String(waitMs)} ms, so its container was given up and killed by name`, FIX_RESTART)
  }
  if ('rejected' in waited.value) {
    await within(
      Promise.resolve()
        .then(() => driver.kill(name))
        .catch(() => undefined),
      KILL_WAIT_MS,
    )
    append({ type: 'sandbox.killed', payload: { schemaVersion: 1, sandboxId: name, reason: 'error' } })
    const e = waited.value.rejected
    const detail = `the driver lost the canary: ${e instanceof Error ? e.message : String(e)}`
    if (session !== undefined) await session.end('error', recordable(detail, EGRESS_DETAIL_BYTES))
    else if (unserved !== undefined) revokeUnserved(unserved)
    return failed(options, `${detail}, so its container was killed by name`, FIX_RESTART)
  }
  const result = waited.value.result
  const reason = endReason(result)
  append({
    type: 'sandbox.killed',
    payload: { schemaVersion: 1, sandboxId: name, reason, ...(result.exitCode === null ? {} : { exitCode: result.exitCode }) },
  })
  // A docker client that says nothing of its container: killed by name, as
  // an exec's is.
  const runsOn = mayRunOn(result)
  if (runsOn !== undefined) killByName()

  let verdict: CanaryVerdict
  if (!channel) {
    verdict = selfTestVerdict(options, result, runsOn, wallclockMs)
  } else if (session === undefined) {
    revokeUnserved(unserved ?? 'the canary was served no channel')
    verdict = failed(options, unserved ?? 'it was served no channel', FIX_RESTART)
  } else {
    verdict = canaryVerdict(options, result, runsOn, await session.end(reason), wallclockMs, recorded)
  }
  // The log's refusal is the one said, but a domain the report closed stays
  // closed: the row the log refused is no evidence the network is cut off.
  if (refusedRow !== undefined) {
    return { ...failed(options, refusedRow, FIX_RESTART), ...(verdict.ok || verdict.closes === undefined ? {} : { closes: verdict.closes }) }
  }
  return verdict
}

/** How the container ended, when it did not end as a passing canary's does: on its own, exit 0. */
function endedBadly(result: SandboxResult, runsOn: string | undefined, wallclockMs: number): string | undefined {
  if (runsOn !== undefined) return `its docker client ended with no word of its container (${runsOn})`
  const reason = endReason(result)
  if (reason === 'wallclock') return `it was still running at its ${String(wallclockMs)} ms wallclock and was killed`
  if (reason === 'requested') return 'it was killed by name before it ended'
  if (result.exitCode !== 0) return `its mux exited ${String(result.exitCode)}`
  return undefined
}

/**
 * The hostile canary passed when its mux exited 0 having written exactly one
 * report line the ready judge accepts. A line is judged first, however the
 * container ended: a report that a probe reached something closes the domain
 * (routed) even from a mux that then failed.
 */
function selfTestVerdict(options: CanaryOptions, result: SandboxResult, runsOn: string | undefined, wallclockMs: number): CanaryVerdict {
  const line = result.stdout.endsWith('\n') && !result.truncated ? result.stdout.slice(0, -1) : undefined
  const single = line !== undefined && !line.includes('\n')
  if (single) {
    const refused = judged(options.acceptReady, Buffer.from(line, 'utf8'))
    if (refused !== undefined) return routed(options, refused)
  }
  if (result.exitCode === MUX_USAGE_EXIT && result.killedBy === undefined) {
    return failed(options, `its mux exited ${String(MUX_USAGE_EXIT)}, as one that does not know --self-test does`, FIX_IMAGE)
  }
  const ended = endedBadly(result, runsOn, wallclockMs)
  if (ended !== undefined) return failed(options, ended, FIX_RESTART)
  if (!single) return failed(options, 'its mux wrote no single self-test report line', FIX_IMAGE)
  return { ok: true }
}

/**
 * The trusted canary passed when the session accepted its ready, judged
 * exactly one request and denied it, the log holds that deny as the one
 * decision row of the grant, the mux's exit frame said 0 (it read the
 * kernel's 403), and the container ended on its own, exit 0.
 */
function canaryVerdict(
  options: CanaryOptions,
  result: SandboxResult,
  runsOn: string | undefined,
  outcome: SessionOutcome,
  wallclockMs: number,
  recorded: { readonly decisions: number; readonly denies: number },
): CanaryVerdict {
  // Judged again here, from the report the session kept, so the clause is
  // the judge's own words, whatever the session's detail says around them.
  const refused = outcome.ready === undefined ? undefined : judged(options.acceptReady, outcome.ready)
  if (refused !== undefined) return routed(options, refused)
  if (outcome.reason === 'violation' || outcome.reason === 'limit') {
    return failed(options, `the egress session revoked its grant (${outcome.reason}${outcome.limit === undefined ? '' : ` ${outcome.limit}`}: ${outcome.detail ?? 'no detail'})`, FIX_IMAGE)
  }
  if (outcome.ready === undefined) {
    if (result.exitCode === MUX_USAGE_EXIT && result.killedBy === undefined) {
      return failed(options, `its mux exited ${String(MUX_USAGE_EXIT)} with no ready report, as one that does not know --canary does`, FIX_IMAGE)
    }
    const ended = endedBadly(result, runsOn, wallclockMs)
    return failed(options, `its mux sent no ready report${ended === undefined ? '' : ` (${ended})`}`, FIX_IMAGE)
  }
  const t = outcome.totals
  if (t.requests !== 1 || t.denied !== 1 || t.allowed !== 0) {
    return failed(
      options,
      `its one request was not judged and denied over the channel (requests ${String(t.requests)}, denied ${String(t.denied)}, allowed ${String(t.allowed)})`,
      FIX_IMAGE,
    )
  }
  const ended = endedBadly(result, runsOn, wallclockMs)
  if (ended !== undefined) return failed(options, ended, FIX_RESTART)
  // The session ended the grant itself, in error, while the container ran
  // on (a decision row the log refused as the deny window flushed, say).
  if (outcome.reason !== 'exited') {
    return failed(options, `its grant was revoked ${outcome.reason}, not on its exit (${outcome.detail ?? 'no detail'})`, FIX_RESTART)
  }
  if (recorded.decisions !== 1 || recorded.denies !== 1) {
    return failed(
      options,
      `its one request's deny is not one decision row the log holds (rows recorded ${String(recorded.decisions)}, denies ` +
        `${String(recorded.denies)}${outcome.detail === undefined ? '' : `; ${outcome.detail}`})`,
      FIX_RESTART,
    )
  }
  if (outcome.exitStatus !== 0) {
    return failed(
      options,
      outcome.exitStatus === undefined
        ? 'its mux sent no exit status for its round trip'
        : `its mux read no 403 for its request (status ${String(outcome.exitStatus)})`,
      FIX_IMAGE,
    )
  }
  return { ok: true }
}

/** The judge's clause, or undefined when it accepts: a judge that throws, or answers with no clause, refuses. */
function judged(judge: ReadyJudge, report: Uint8Array): string | undefined {
  try {
    const said: unknown = judge(report)
    if (said === undefined) return undefined
    return typeof said === 'string' && said !== '' ? said : 'the ready judge answered something that is not a clause'
  } catch {
    return 'the ready judge threw'
  }
}
