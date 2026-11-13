// Kernel boot.
//
// Every subsystem is built here, in an order chosen for what must be true
// before the next thing exists:
//
//   The store comes first, and its chain is verified against the external
//   anchor before anything is written to it. A kernel that appended to a log
//   it had not checked would destroy the evidence it exists to keep — the new
//   rows chain onto whatever is there, making a tampered log verify from then
//   on. Refusal is the only safe answer (invariant 5).
//
//   The secrets broker is built before the router because the router's
//   resolveCredential closure captures it — the language enforces that much.
//   What the ORDER does not buy is an armed redaction mask: the broker
//   registers a value with the mask when it RESOLVES one, which happens on a
//   run's first model call, not at boot. So the mask is armed by the first
//   resolution, wherever that happens, and construction order is not a
//   security property. Saying otherwise would be a comment doing the work the
//   code does not.
//
//   The control server is built LAST and is the one subsystem that cannot be
//   degraded. Everything else answers "unavailable, and here is why"; a
//   control plane that came up without its token, or on the wrong interface,
//   is not a degraded kernel but a breach of invariant 1, so boot refuses.
//
// Degradation is the normal case, not the error case. No pmmcp, no Docker and
// no provider credential all produce a kernel that boots, serves its control
// plane, and says precisely what is missing — because the alternative is an
// operator who cannot ask the kernel why it will not start.

import { chmodSync, mkdirSync, statSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { z } from 'zod'

import { VERSION } from './version.js'
import { log } from './log.js'
import { ConfigError, PolicyDenied } from './errors.js'
import { holdDataDir, type DataLock } from './data-lock.js'
import { bindingKeyProblem, type EgressBinding, type KernelConfig } from './config.js'

import { EventStore } from './events/store.js'
import { canonicalize } from './events/canonical.js'
import { recordable } from './events/bound.js'
import { redactString, SecretMask } from './events/redact.js'
import { EGRESS_REASON_BYTES } from './events/types.js'
import { acceptReady } from './egress/ready.js'
import type { CredentialInjector } from './egress/session.js'
import { createUpstream, systemUpstreamDeps, type Upstream, type UpstreamDeps, type UpstreamLimits } from './egress/upstream.js'
import { readAllRows, type EventRow } from './events/chain.js'
import { isClean, projectRecovery, sandboxRunIds, type Recovery } from './events/projections.js'
import { GoalTracker } from './goals/tracker.js'
import { Delegation } from './runtime/delegate.js'
import { KernelTools } from './runtime/kernel-tools.js'
import { isSandboxRef, SandboxTools } from './runtime/sandbox-tools.js'
import { GoalWriter } from './goals/writer.js'
import { goalToolsUnusable, watchGoalTools } from './goals/tools.js'

import { AgentRegistry, type AgentRecord } from './agents/registry.js'
import { loadSoul, type SoulBudgetTracker } from './agents/souls.js'
import { resolveView, type ToolViewsFile } from './mcp/tool-views.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'

import { McpHub, streamableHttpTransport, type ClientFactory } from './mcp/hub.js'
import { bearerRefusal, SecretsBroker, type SecretRef } from './secrets/broker.js'
import {
  parseProviders,
  routable,
  type ModelCard,
  type ProbeRecord,
  type ProvidersFile,
} from './models/registry.js'
import { Router } from './models/router.js'
import { AnthropicAdapter } from './models/anthropic.js'
import { OpenAiChatAdapter } from './models/openai-chat.js'
import { probe, readProbeRecord } from './models/probe.js'
import { Approvals } from './policy/approvals.js'
import { Quarantine } from './policy/quarantine.js'
import { PolicyEngine } from './policy/engine.js'
import { Lanes } from './runtime/lanes.js'
import { Budget, resolveCaps, type BudgetCaps } from './runtime/budget.js'
import { RunLoop, type RunAgent, type RunOutcome } from './runtime/loop.js'
import type { BindingStatus, EgressState } from './runtime/egress.js'
import { Scheduler } from './runtime/scheduler.js'
import { AppleContainerDriver } from './sandbox/apple-container.js'
import { DockerDriver, realDockerDriver, type DockerProcesses } from './sandbox/docker.js'
import type { ProbeResult as SandboxProbe, SandboxDriver, SweepRequest, SweepResult } from './sandbox/driver.js'
import { assertTokenUsable } from './control/auth.js'
import { ControlServer, type ControlSurface } from './control/server.js'
import type { HumanActor } from './control/actor.js'
import type {
  AgentSummary,
  ModelSummary,
  ProbeRecordResult,
  RunDetail,
  RunSummary,
  StatusResult,
} from './control/protocol.js'
import {
  agentSummaryView,
  modelSummaryView,
  probeView,
  runDetailView,
  runSummaryView,
  statusView,
  type RunState,
} from './control/views.js'

/**
 * What is not built yet, and how it says so.
 *
 * Consumed by stubs.test.ts and README. Every entry is a thing that THROWS or
 * reports unavailable rather than silently doing nothing, because a stub that
 * no-ops is indistinguishable from a working feature until the day it matters.
 */
export const STUBS: readonly { id: string; where: string; how: string }[] = [
  {
    id: 'apple-container-driver',
    where: 'src/sandbox/apple-container.ts',
    how: 'probe() reports unavailable with a reason so boot degrades; run(), kill(), abandon() and sweepOrphans() throw NotImplementedError. macOS 15 has no `container` binary',
  },
]

/**
 * How long the egress upstream may take to resolve, connect and finish its
 * TLS handshake for one request (upstream.ts connectTimeoutMs). Its idle
 * bound, once connected, is kernel.yaml's egress.limits.idleMs.
 */
export const EGRESS_CONNECT_TIMEOUT_MS = 10_000

/**
 * How long boot waits for the sandbox driver's probe (SandboxDriver.probe)
 * before it marks the sandbox degraded without its answer: as with the sweep
 * below, a daemon that accepts a connection and never answers `docker
 * version` or an inspect (a paused VM) must not hold the boot, since the
 * booted kernel is how an operator reads why. Past it the probe is told to
 * stop (its signal): DockerDriver asks nothing more and ends the docker CLI
 * it waits on, by SIGKILL. A test hands its own (BootOptions.probeWaitMs).
 */
export const PROBE_WAIT_MS = 30_000

/**
 * Run `driver`'s probe for boot, and wait `waitMs` at most. Never rejects:
 * a probe that throws or rejects (a driver breaking its contract) is a
 * failed probe naming the throw, one that answers with no ProbeResult
 * (probeVerdict) a failed probe saying so, and one that has not settled
 * within `waitMs` a failed probe naming the bound, which is then told to
 * stop (its signal aborted), so a docker CLI a paused VM holds is ended and
 * an answer that comes late is not read. Exported so a test can hold the
 * bound without waiting PROBE_WAIT_MS.
 */
export async function probeAtBoot(driver: SandboxDriver, waitMs: number = PROBE_WAIT_MS): Promise<SandboxProbe> {
  const stop = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<SandboxProbe>((resolve) => {
    timer = setTimeout(() => {
      stop.abort()
      resolve({
        ok: false,
        why:
          `the probe did not finish within ${String(waitMs)} ms: a runtime accepted and never answered, and the ` +
          'probe was told to stop, so the sandbox is not known to work. Check that each VM answers ' +
          '(scripts/colima-up.sh), then restart the kernel',
      })
    }, waitMs)
  })
  // Called inside then(): a driver that throws rather than rejecting is caught
  // too. The catch follows probeVerdict, so a reading of the answer that
  // throws (a getter, a revoked Proxy) is a failed probe as well.
  const probed = Promise.resolve()
    .then(() => driver.probe(stop.signal))
    .then((answer: unknown): SandboxProbe => probeVerdict(driver.name, answer))
    .catch((e: unknown): SandboxProbe => ({
      ok: false,
      why: recordable(`${driver.name} probe threw: ${e instanceof Error ? e.message : String(e)}`, PROBE_REASON_BYTES),
    }))
  try {
    return await Promise.race([probed, late])
  } finally {
    clearTimeout(timer)
  }
}

/**
 * The most of a failed probe's reason boot records. A driver bounds its own
 * (DockerDriver's PROBE_ERROR_BYTES for what docker said), so this is wide
 * of every reason a driver that keeps its contract gives, and it holds the
 * one a driver that breaks it gives (a throw, a `why` of any size) to a
 * sandbox.degraded row the store takes.
 */
export const PROBE_REASON_BYTES = 4_096

const ProbeAnswer = z.union([
  z.object({ ok: z.literal(true), version: z.string() }),
  z.object({ ok: z.literal(false), why: z.string() }),
])

/**
 * A probe's answer as boot reads it, parsed: a driver that breaks the
 * contract by answering with no ProbeResult (null, `{}`, an `ok` that is no
 * boolean, a failure with no `why`) has failed its probe, since the sandbox
 * is then not known to work. Boot must neither refuse (reading `.ok` of
 * null), nor read a truthy `ok` as a working runtime, nor append a
 * sandbox.degraded row with no reason, which the store refuses. A failure's
 * reason is redacted and bounded (PROBE_REASON_BYTES).
 */
function probeVerdict(driverName: string, answer: unknown): SandboxProbe {
  const parsed = ProbeAnswer.safeParse(answer)
  if (!parsed.success) {
    return {
      ok: false,
      why:
        `${driverName} probe answered with no probe result (ok true with a version, or ok false with a why), ` +
        'so the sandbox is not known to work',
    }
  }
  const probe = parsed.data
  return probe.ok ? { ok: true, version: probe.version } : { ok: false, why: recordable(probe.why, PROBE_REASON_BYTES) }
}

/**
 * How long boot waits for the orphan sweep (SandboxDriver.sweepOrphans)
 * before it marks the sandbox subsystem without it: a daemon that accepts a
 * connection and never answers `docker ps` or `docker kill` (a paused VM)
 * must not hold the boot, since the booted kernel is how an operator reads
 * why. Past it the sweep is told to stop (SweepRequest.signal): it lists
 * nothing more and sends no kill it has not sent. A test hands its own
 * (BootOptions.sweepWaitMs).
 */
export const SWEEP_WAIT_MS = 30_000

/** The most of a sweep's reason boot records: the swept names, or why the sweep did not finish. */
export const SWEEP_REASON_BYTES = 1_024

/**
 * What boot's orphan sweep came to: the names it killed by name, and, when it
 * did not do all it was asked, why (the sandbox is then degraded).
 */
export interface SweepOutcome {
  readonly swept: readonly string[]
  readonly problem?: string
}

/** What the boot sweep is to kill, from this boot's log (SweepRequest, less the signal boot adds). */
export interface SweepTargets {
  readonly runIds: readonly string[]
  readonly names: readonly string[]
}

/**
 * The boot sweep's targets, from the log as boot read it, before recovery
 * wrote anything: every run that may have had a container (sandboxRunIds),
 * and every grant left open's container by name (a canary's included, which
 * serves no run). Nothing else: a container with the prefix that this log
 * does not name may be a live kernel's, on another data directory.
 */
export function sweepTargets(rows: readonly EventRow[], recovered: Recovery): SweepTargets {
  const runIds = new Set(sandboxRunIds(rows))
  for (const grant of recovered.openGrants) if (grant.runId !== null) runIds.add(grant.runId)
  const names = new Set(recovered.openGrants.map((g) => g.sandbox).filter((name) => name !== ''))
  return { runIds: [...runIds], names: [...names] }
}

/** Why a sweep did not finish: a container may still run, and what to do. */
const SWEEP_LEFT =
  'so a container a previous kernel left may still be running, past its wallclock. Check that each VM answers ' +
  '(scripts/colima-up.sh), then restart the kernel to sweep again'

/**
 * A sweep's problem: `head` (what failed, which may quote a runtime or a
 * driver) redacted and cut so that SWEEP_LEFT always follows it whole, and
 * the whole within SWEEP_REASON_BYTES.
 */
function sweepProblem(head: string): string {
  const tail = `, ${SWEEP_LEFT}`
  return `${recordable(head, SWEEP_REASON_BYTES - Buffer.byteLength(tail))}${tail}`
}

/**
 * Run `driver`'s orphan sweep over `targets`, for boot, and wait `waitMs` at
 * most. Asks the driver nothing when the targets name nothing: a log with no
 * sandbox run has no container to sweep, and its boot asks no runtime
 * anything. Never rejects: a sweep that throws (the apple-container stub,
 * which runs nothing), rejects or answers with no SweepResult (a driver
 * breaking its contract) is a problem named in the outcome, and so is one
 * that left a VM unlisted or a kill refused, and one that has not settled
 * within `waitMs`, which is then told to stop (its signal aborted), so a
 * listing a VM answers late kills nothing. Exported so a test can hold the
 * bound without waiting SWEEP_WAIT_MS.
 */
export async function sweepAtBoot(driver: SandboxDriver, targets: SweepTargets, waitMs: number = SWEEP_WAIT_MS): Promise<SweepOutcome> {
  if (targets.runIds.length === 0 && targets.names.length === 0) return { swept: [] }
  const stop = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<SweepOutcome>((resolve) => {
    timer = setTimeout(() => {
      stop.abort()
      resolve({
        swept: [],
        problem:
          `the orphan sweep did not finish within ${String(waitMs)} ms: a runtime accepted and never answered, ` +
          `and the sweep was told to stop, ${SWEEP_LEFT}`,
      })
    }, waitMs)
  })
  const request: SweepRequest = { runIds: targets.runIds, names: targets.names, signal: stop.signal }
  // Called inside then(): a driver that throws rather than rejecting is caught
  // too. The catch follows sweepOutcome, not beside it in the same then(), so
  // an answer sweepOutcome refuses (no SweepResult: `{}`, undefined) is a
  // named problem as well, and never a rejection that refuses the boot.
  const swept = Promise.resolve()
    .then(() => driver.sweepOrphans(request))
    .then((result: unknown): SweepOutcome => sweepOutcome(result))
    .catch((e: unknown): SweepOutcome => ({
      swept: [],
      problem: sweepProblem(`the orphan sweep failed: ${e instanceof Error ? e.message : String(e)}`),
    }))
  try {
    return await Promise.race([swept, late])
  } finally {
    clearTimeout(timer)
  }
}

const SweepDomain = z.enum(['trusted', 'hostile'])
const SweepAnswer = z.object({
  swept: z.array(z.string()),
  unlisted: z.array(z.object({ domain: SweepDomain, why: z.string() })),
  failed: z.array(z.object({ name: z.string(), domain: SweepDomain, why: z.string() })),
})

/**
 * A finished sweep's outcome: a problem naming each VM it could not list and
 * each kill refused, if any. Throws for an answer that is no SweepResult
 * (sweepAtBoot names it as the sweep's failure): read as one, a `swept` that
 * is a string would be its characters, and a missing `failed` a throw.
 */
function sweepOutcome(answer: unknown): SweepOutcome {
  const parsed = SweepAnswer.safeParse(answer)
  if (!parsed.success) {
    throw new Error('the driver answered with no sweep result (swept, unlisted and failed, each a list of its own shape)')
  }
  const result: SweepResult = parsed.data
  const swept = Object.freeze([...result.swept])
  const parts = [
    ...result.unlisted.map((u) => `the ${u.domain} VM could not be listed (${u.why})`),
    ...result.failed.map((f) => `${f.name} could not be killed on the ${f.domain} VM (${f.why})`),
  ]
  if (parts.length === 0) return { swept }
  return { swept, problem: sweepProblem(`the orphan sweep did not finish: ${parts.join('; ')}`) }
}

/**
 * What the sandbox subsystem's reason says of a sweep that killed
 * something: how many, and their names as they fit. A name is there only
 * once its daemon answered the kill by name, or said the container no
 * longer ran.
 */
export function sweptReason(swept: readonly string[]): string {
  const n = swept.length
  return recordable(
    `the orphan sweep killed by name ${String(n)} container${n === 1 ? '' : 's'} a previous kernel left running: ${swept.join(', ')}`,
    SWEEP_REASON_BYTES,
  )
}

/**
 * What a boot's `proxy.grant.revoked` says of a grant it found issued and
 * never revoked (egress plan W2). Fixed text, well inside
 * EGRESS_DETAIL_BYTES, quoting nothing from the log. It names both ways a
 * grant is left so: the kernel that issued it died first, or it ran on
 * after the store refused the session's own revocation row (session.ts
 * logs that and ends the session all the same), which a boot cannot tell
 * apart.
 */
export const GRANT_RECOVERED_DETAIL =
  'no revocation of this grant was recorded: the kernel that issued it stopped first, or its revocation could not ' +
  'be appended. Either way nothing is served under it now (the session that served it has ended, and no other ' +
  'kernel holds this log), and its counts are not in the log'

/**
 * The production upstream's two timeouts, as boot hands them to
 * systemUpstreamDeps: the connect deadline the kernel fixes
 * (EGRESS_CONNECT_TIMEOUT_MS) and kernel.yaml's egress.limits.idleMs.
 * Exported so a test can hold both, since every test that sends traffic
 * injects an upstream of its own.
 */
export function egressUpstreamOptions(config: KernelConfig): UpstreamLimits {
  return { connectTimeoutMs: EGRESS_CONNECT_TIMEOUT_MS, idleTimeoutMs: config.egress.limits.idleMs }
}

/**
 * The upstream boot builds when none is injected, and the one place it is
 * built: createUpstream over `deps` (systemUpstreamDeps, the real resolver,
 * dialer and interfaces) made from egressUpstreamOptions(config). `deps`
 * takes the options and never chooses them, so a test that hands boot a
 * factory of its own (BootOptions.egressUpstreamDeps) holds the timeouts the
 * daemon's upstream runs under, which no test that injects a whole upstream
 * can see.
 */
export function productionUpstream(
  config: KernelConfig,
  deps: (limits: UpstreamLimits) => UpstreamDeps = systemUpstreamDeps,
): Upstream {
  return createUpstream(deps(egressUpstreamOptions(config)))
}

export interface BootOptions {
  readonly config: KernelConfig
  /** Repository root, for protected-path resolution and the souls directory. */
  readonly repoRoot: string
  /**
   * Where agent manifests live. Defaults to `<repoRoot>/agents`.
   *
   * Explicit rather than derived so a test can supply a manifest tree without
   * editing the shipped files, and so the boot path's inputs are visible in one
   * place. It does not widen what an agent can reach: manifests are
   * operator-authored config, and what they may GRANT is still bounded by the
   * tool views.
   */
  readonly agentsDir?: string
  readonly providers: ProvidersFile
  readonly toolViews: ToolViewsFile
  readonly env?: NodeJS.ProcessEnv
  /** Injected by tests so no boot spawns docker. */
  readonly sandboxDriver?: SandboxDriver
  /**
   * Tests only: how long boot waits for the orphan sweep, in place of
   * SWEEP_WAIT_MS, so a test can hold a sweep that never settles to its
   * bound without waiting 30 s.
   */
  readonly sweepWaitMs?: number
  /**
   * Tests only: how long boot waits for the sandbox probe, in place of
   * PROBE_WAIT_MS, so a test can hold a probe that never settles to its
   * bound without waiting 30 s.
   */
  readonly probeWaitMs?: number
  /** Injected by tests so no boot opens a socket to a real pmmcp. */
  readonly clientFactory?: ClientFactory
  /**
   * The egress upstream (src/egress/upstream.ts) a run's allowed requests are
   * sent through. Injected by tests, over an in-process resolver and dialer,
   * so no test resolves or dials; boot builds the real one otherwise, which
   * resolves only a name decide() allowed and dials only the address it
   * checked.
   */
  readonly egressUpstream?: Upstream
  /**
   * Tests only: what boot builds its production upstream over, in place of
   * systemUpstreamDeps (productionUpstream), handed the options boot chose,
   * so a test can hold them and serve the run in process. Unread when
   * egressUpstream is given.
   */
  readonly egressUpstreamDeps?: (limits: UpstreamLimits) => UpstreamDeps
  readonly fetch?: typeof globalThis.fetch
  readonly now?: () => number
}

export interface Kernel {
  readonly store: EventStore
  /**
   * The control server. Exposed because `port` comes from it and because a
   * test simulating a SIGKILL must be able to release the socket without
   * running the clean-shutdown path that writes the anchor.
   */
  readonly server: ControlServer
  readonly config: KernelConfig
  /** The port actually bound, which differs from config when it asked for 0. */
  readonly port: number
  readonly bootedAt: string
  readonly degraded: readonly string[]
  /** What this boot found open from a previous process, and closed. */
  readonly recovered: Recovery
  readonly agents: AgentRegistry
  readonly hub: McpHub
  readonly router: Router
  readonly lanes: Lanes
  readonly approvals: Approvals
  readonly quarantine: Quarantine
  readonly scheduler: Scheduler
  /**
   * The sandbox runner the run loop holds: its refusals as the loop reads
   * them (egressRefusal, with boot's egress verdict) and its grant table
   * (liveGrants), held by tests the way the hub and the router are.
   */
  readonly sandboxTools: SandboxTools
  /**
   * The kernel's hold on its data directory (src/data-lock.ts), taken before
   * the log is opened and dropped by shutdown once the log is closed.
   * Exposed so a test simulating a SIGKILL can drop it as the OS would,
   * beside the socket and the raw database handle.
   */
  readonly lock: DataLock
  status(): StatusResult
  shutdown(reason?: 'requested' | 'signal' | 'error', signal?: string): Promise<void>
}

type Subsystems = StatusResult['subsystems']
type SubsystemName = keyof Subsystems

/** The order subsystem.state rows are written in. Asserted by the boot test. */
export const SUBSYSTEM_ORDER: readonly SubsystemName[] = [
  'events',
  'hub',
  'secrets',
  'sandbox',
  'router',
  'egress',
  // After egress, because the scheduler is built once the lanes and the run loop
  // exist — it starts runs through the same path the control plane does, and it
  // cannot be reported ready before the thing it would start runs with.
  'scheduler',
  'control',
]

/**
 * A stable digest of the configuration this kernel booted with.
 *
 * Canonicalised first, so a reordered YAML file is the same config. The config
 * itself never enters the log — it holds hostnames, vault ids and env var
 * names — but its hash lets an operator reading the log after a restart see
 * that something changed under them.
 */
export function configHash(config: KernelConfig): string {
  return createHash('sha256').update(canonicalize(config)).digest('hex')
}

/** A mutable projection of one run, kept from the log itself. */
interface LiveRun {
  state: RunState
  readonly controller: AbortController
}

export async function bootKernel(options: BootOptions): Promise<Kernel> {
  const { config, repoRoot, providers, toolViews } = options
  const env = options.env ?? process.env
  const now = options.now ?? Date.now
  const startedAtMs = now()
  const bootedAt = new Date(startedAtMs).toISOString()

  // Before the store, before any event: the control plane's token. Refusing
  // here costs nothing and writes nothing, so a boot with no token does not
  // leave a half-boot in the log to be explained later.
  const token = env[config.control.tokenEnv]
  // Throws when absent or under the 32-char floor.
  assertTokenUsable(token)
  // Where kernel.yaml and providers.yaml are both in hand, and before any
  // binding is resolved: a binding whose envVar is a provider's key would
  // have that key injected into requests to the binding's host. A refused
  // boot, not a degraded egress: the operator's config names one credential
  // for two uses, and no reading of it is safe. Before the store, so it
  // writes nothing.
  const sharedKey = bindingKeyProblem(config, providers)
  if (sharedKey !== undefined) throw new ConfigError(sharedKey)

  // The store cannot open a database in a directory that does not exist, and on
  // a first boot .aos/ does not: without this, a clean machine fails with
  // "unable to open database file" and no hint that a mkdir was all it needed.
  //
  // 0700, not the umask's guess. The log holds prompts, model responses and tool
  // output, and events.head beside it is trust-bearing — anything that can
  // rewrite the anchor can hide a truncation. Created after the token check, so
  // a boot that cannot legally serve still creates nothing.
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 })
  // mkdir changes nothing on a directory that exists, and on the shipped flow
  // one always does: npm creates .aos first, at the umask's 0755, for the cache
  // .npmrc keeps in .aos/npm-cache. So the mode is enforced as it stands.
  keepPrivate(config.dataDir, 0o700)

  // One kernel per log, established before the log is opened, and so before
  // recovery and the orphan sweep: a second kernel on this data directory
  // would read the live one's open runs as a dead kernel's, close them, revoke
  // their grants and kill their containers. Refused here, it writes nothing.
  // The lock file and its journal are made 0600 by holdDataDir itself.
  const lock = holdDataDir(config.dataDir)

  const dbPath = join(config.dataDir, 'events.db')
  let store: EventStore
  try {
    // The constructor compares every expected trigger's stored DDL against the
    // canonical text and throws when one is missing or altered, so "the
    // append-only triggers are intact" is established by the store existing.
    store = new EventStore(dbPath, {
      anchorEvery: config.events.anchorEvery,
      headFile: join(config.dataDir, 'events.head'),
    })
    try {
      // SQLite creates the database at the umask's 0644, and its -wal and -shm
      // with the database's mode, so once the database is 0600 they follow.
      for (const file of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) keepPrivate(file, 0o600)
    } catch (e) {
      store.db.close()
      throw e
    }
  } catch (e) {
    // A log refused before the boot's own try below (one that is no database,
    // a trigger altered, a mode that cannot be tightened) holds the data
    // directory no longer, so a corrected boot in this process may take it.
    lock.release()
    throw e
  }

  const subsystems: Partial<Record<SubsystemName, Subsystems[SubsystemName]>> = {}
  const degraded: string[] = []
  const emitted: SubsystemName[] = []
  const mark = (name: SubsystemName, state: 'ok' | 'degraded' | 'absent', reason?: string): void => {
    subsystems[name] = { state, ...(reason === undefined ? {} : { reason }) }
    if (state !== 'ok') degraded.push(name)
    emitted.push(name)
    store.append({
      type: 'subsystem.state',
      payload: { schemaVersion: 1, subsystem: name, state, ...(reason === undefined ? {} : { reason }) },
    })
  }

  try {
    // ── events: verify before writing ──────────────────────────────────────
    const anchor = store.readAnchor()
    const verified = store.verifyChain(anchor)
    if (!verified.ok) {
      // Refusal, not repair. Appending to an unverified log makes the damage
      // permanent: every later row chains onto it and the whole thing verifies
      // from here on.
      throw new ConfigError(
        `event log verification failed at seq ${String(verified.at)}: ${verified.reason}. ` +
          'The kernel will not append to a log it cannot verify. Investigate with ' +
          '`aos verify-chain` before restarting.',
      )
    }
    // Re-anchor to the verified tail. An unclean exit leaves the log AHEAD of
    // its anchor, which is normal and not tampering; this moves the anchor up
    // so the next boot's truncation check starts from what we just verified.
    store.writeAnchor()

    const hash = configHash(config)
    // The first row of this boot, always. `degraded` is empty because nothing
    // has been built yet — see KernelBootedPayload.
    store.append({
      type: 'kernel.booted',
      payload: { schemaVersion: 1, version: VERSION, configHash: hash, degraded: [] },
    })
    // ── crash recovery: close out what the last process left open ─────────
    //
    // Runs, approvals and holds all live in memory, so a kernel that died
    // mid-run left them dangling in the log and nowhere else. Every one of them
    // is TERMINATED here rather than restored: run state is not persisted, so a
    // restored approval would be a decision that resolves nothing, and held
    // content is not persisted either, so a restored hold has nothing to give
    // back. See src/events/projections.ts.
    //
    // Before the subsystems are marked, because "the event log is in order"
    // should mean verified AND settled, and after kernel.booted, so every row
    // written here is attributable to this boot.
    // Captured BEFORE recovery closes the orphans out. Recovery appends a
    // `run.finished` per orphan, so a later read would show them finished and the
    // goal tracker would never learn which goals those runs had been serving.
    const rowsAtBoot = readAllRows(store.db)
    const recovered = projectRecovery(rowsAtBoot)
    // Children before parents, with each dangling admission's result between:
    // the order the live kernel writes them in (child finishes, parent records
    // the result, parent finishes), so the log reads the same way after a crash
    // as it would have without one.
    const childIds = new Set(recovered.danglingDelegations.map((d) => d.childRunId))
    const closeOrphan = (run: (typeof recovered.orphanRuns)[number]): void => {
      store.append({
        type: 'run.finished',
        runId: run.runId,
        ...(run.agentId === null ? {} : { agentId: run.agentId }),
        payload: {
          schemaVersion: 1,
          runId: run.runId,
          status: 'error',
          reason: 'orphaned by a kernel restart',
          // Counted from the log rather than zeroed: the run really did spend
          // this, and a recovery row claiming zero cost would understate the
          // bill and hide the work.
          costMicroUsd: run.costMicroUsd,
          llmCalls: run.llmCalls,
          toolCalls: run.toolCalls,
          durationMs: Math.max(0, Math.round(Date.parse(run.lastTs) - Date.parse(run.startedAt))),
        },
      })
    }
    // Grants first: the live kernel revokes an exec's grant inside its tool
    // call, before its run's terminal row, so a grant left open is closed
    // before the run it served. `recovered`, with no totals: the counts died
    // with the kernel that kept them, and zeros would claim nothing crossed.
    // Nothing can be served under it now: the engine and the container's one
    // channel were in the dead process, and no live kernel holds this log
    // (the data directory's lock, taken above, says so). The boot sweep,
    // below, kills by name the containers this log names that a VM still
    // runs.
    for (const grant of recovered.openGrants) {
      store.append({
        type: 'proxy.grant.revoked',
        ...(grant.runId === null ? {} : { runId: grant.runId }),
        ...(grant.agentId === null ? {} : { agentId: grant.agentId }),
        payload: {
          schemaVersion: 1,
          grantId: grant.grantId,
          reason: 'recovered',
          detail: GRANT_RECOVERED_DETAIL,
        },
      })
    }
    for (const run of recovered.orphanRuns) if (childIds.has(run.runId)) closeOrphan(run)
    for (const d of recovered.danglingDelegations) {
      store.append({
        type: 'delegation.result',
        runId: d.parentRunId,
        payload: {
          schemaVersion: 1,
          parentRunId: d.parentRunId,
          childRunId: d.childRunId,
          status: d.status,
          costMicroUsd: d.costMicroUsd,
          taint: d.taint,
        },
      })
    }
    for (const run of recovered.orphanRuns) if (!childIds.has(run.runId)) closeOrphan(run)
    for (const approval of recovered.unresolvedApprovals) {
      store.append({
        type: 'approval.resolved',
        ...(approval.runId === null ? {} : { runId: approval.runId }),
        // `expired` and no byConnectionId: nobody answered, and the fail-closed
        // decision for an unanswered request is the one the timeout would have
        // given it. Recording `denied` would imply a person said no.
        payload: { schemaVersion: 1, approvalId: approval.approvalId, decision: 'expired' },
      })
    }
    for (const hold of recovered.unreleasedHolds) {
      store.append({
        type: 'quarantine.abandoned',
        ...(hold.runId === null ? {} : { runId: hold.runId }),
        payload: {
          schemaVersion: 1,
          holdId: hold.holdId,
          reason: 'the kernel restarted; held content lives in memory and did not survive',
        },
      })
    }
    if (!isClean(recovered)) {
      log.warn(
        {
          orphanRuns: recovered.orphanRuns.map((r) => r.runId),
          delegations: recovered.danglingDelegations.map((d) => d.childRunId),
          approvals: recovered.unresolvedApprovals.length,
          holds: recovered.unreleasedHolds.length,
          grants: recovered.openGrants.map((g) => g.grantId),
        },
        'closed out work left open by a previous process',
      )
    }

    mark('events', 'ok')

    // ── registries ────────────────────────────────────────────────────────
    const cards = new Map<string, ModelCard>(Object.entries(providers.entries))
    const agents = new AgentRegistry({
      providers: new Set(cards.keys()),
      toolViews,
      store,
      // So a manifest asking for more than the operator allows is refused when the
      // file is read, not on the first run that reaches for it.
      budgets: config.budgets,
      // So a manifest's egress.bind names only a binding kernel.yaml holds, and
      // its egress.allow no host one binds. The grant issuer reads both again
      // at each exec (SandboxTools), from the record.
      egressBindings: config.egress.bindings,
    })
    agents.load(options.agentsDir ?? join(repoRoot, 'agents'))

    const probes = (ref: string): ProbeRecord | undefined => readProbeRecord(config.dataDir, ref)

    // ── hub (degradable) ──────────────────────────────────────────────────
    const hub = new McpHub({
      store,
      views: toolViews,
      pingIntervalMs: config.mcp.servers['pmmcp']?.heartbeatMs ?? 240_000,
      pingTimeoutMs: config.mcp.servers['pmmcp']?.pingTimeoutMs ?? 10_000,
    })
    const hubState = await connectHub(hub, config, env, options.clientFactory)

    // ── secrets: the router's resolveCredential closes over this ──────────
    const broker = new SecretsBroker({
      store,
      source: config.secrets.source,
      ...(hubState.ok ? { hub } : {}),
      keyArg: config.secrets.keyArg,
      envFallback: config.secrets.envFallback,
      env,
    })

    mark('hub', hubState.ok ? 'ok' : 'degraded', hubState.reason)

    // The vault's own boot step, and the only thing that confirms
    // `secrets.keyArg` against the LIVE schema. Boot used to skip it and derive
    // the secrets mark from config alone, which meant a connected pmmcp
    // declaring a different argument name booted as `secrets: ok` and then
    // failed every credential fetch with a message about the vault returning
    // nothing — pointing at the vault rather than at the one line of
    // kernel.yaml that was wrong.
    //
    // start() THROWS on that drift, deliberately. Boot turns it into a DEGRADED
    // secrets subsystem rather than a refused boot: the control plane is how an
    // operator would read the reason, and refusing to start takes it away. The
    // vault path is closed either way — ref() has nothing to fall back to with
    // envFallback off, and the throw is recorded before anything asks.
    //
    // D8: env fallback keeps the vault path degraded for as long as it is on. A
    // kernel reporting ready while a credential may be coming from the
    // environment would be hiding the thing an operator most needs to know;
    // broker.start() is what declares that standing degradation.
    let secretsReason: string | undefined
    try {
      await broker.start()
      secretsReason = broker.degradedReason
    } catch (e) {
      secretsReason = e instanceof Error ? e.message : String(e)
      store.append({
        type: 'secrets.degraded',
        payload: { schemaVersion: 1, reason: secretsReason },
      })
    }
    if (config.secrets.source === 'vault' && !hubState.ok) {
      // Said better than the broker can: the broker knows only that it has no
      // hub, while boot knows why the hub is not there.
      secretsReason = `no vault: ${hubState.reason ?? 'pmmcp is not connected'}`
    }
    mark('secrets', secretsReason === undefined ? 'ok' : 'degraded', secretsReason)

    // ── goals (degradable, and not a status.get subsystem) ────────────────
    //
    // Reported as an EVENT rather than a subsystem key: `StatusResult.subsystems`
    // is a strict object in protocol v1, which CLAUDE.md freezes, and a new key
    // there is a version bump plus a migration note. The reason is what matters
    // and it lands in the log either way.
    const goalsReason = hubState.ok
      ? goalToolsUnusable(hub, config.goals)
      : `pmmcp is not connected: ${hubState.reason ?? 'no vault and no memory'}`
    if (goalsReason !== undefined) {
      store.append({ type: 'goals.degraded', payload: { schemaVersion: 1, reason: goalsReason } })
      log.warn({ reason: goalsReason }, 'no goal tree can be written or read')
    }
    const goalWriter = new GoalWriter({
      store,
      hub,
      goals: config.goals,
      ...(goalsReason === undefined ? {} : { degradedReason: goalsReason }),
    })
    // A pmmcp redeployed under a running kernel is re-checked on reconnect.
    const unwatchGoals = watchGoalTools({ store, hub, goals: config.goals, writer: goalWriter })
    const goalTracker = new GoalTracker({
      store,
      writer: goalWriter,
      adoptFromRuns: config.goals.adoptFromRuns,
      // A manifest's own namespace, never a global one: `aos/ceo` is the CEO's
      // because its manifest says so, and an agent with no memory block writes
      // nowhere.
      projectIdOf: (agentId) => agents.get(agentId)?.manifest.memory.projectId,
      // Only an orchestrator may have a plan adopted from its result. A worker
      // emitting plan-shaped JSON must not be able to write the CEO's goal tree.
      isOrchestrator: (agentId) => agents.get(agentId)?.manifest.role === 'orchestrator',
      knownTemplates: () => agents.list().map((r) => r.manifest.id),
    })
    goalTracker.seedFromLog(rowsAtBoot)

    // ── sandbox (degradable) ──────────────────────────────────────────────
    const driver = options.sandboxDriver ?? defaultDriver(config, repoRoot)
    // probe() is contracted never to throw, because a missing container runtime
    // is a degraded boot and not a dead kernel. Guarded anyway (probeAtBoot):
    // a driver that breaks that contract must not be able to refuse the boot,
    // which is exactly what an earlier apple-container stub did. Bounded
    // (PROBE_WAIT_MS): a VM that never answers degrades the sandbox rather
    // than holding the boot, and the probe is then told to stop.
    //
    // The orphan sweep (egress plan W2), whatever the probe says, and before
    // the mark: a kernel that died left its containers running with no
    // wallclock (the timers were the dead process's), on either VM, and
    // nothing else will ever end them. Only what this log names (sweepTargets:
    // every run of its that may have had a container, every grant left open),
    // so a live kernel's containers on the same VM, another data directory's,
    // are never this boot's to kill; and none at all, with no runtime asked
    // anything, for a log with no sandbox run. A sandbox is ok only once the
    // sweep has done all it was asked, so that ok means no container of this
    // log's is left running that the sweep could reach. Bounded
    // (SWEEP_WAIT_MS): a VM that never answers degrades the sandbox rather
    // than holding the boot, and the sweep is then told to stop.
    //
    // The two at once, since neither reads the other: a paused VM holds the
    // boot one bound, not one per call.
    const [sandboxProbe, sweep] = await Promise.all([
      probeAtBoot(driver, options.probeWaitMs ?? PROBE_WAIT_MS),
      sweepAtBoot(driver, sweepTargets(rowsAtBoot, recovered), options.sweepWaitMs ?? SWEEP_WAIT_MS),
    ])
    if (!sandboxProbe.ok) {
      store.append({
        type: 'sandbox.degraded',
        payload: { schemaVersion: 1, driver: driver.name, reason: sandboxProbe.why },
      })
    }
    if (sweep.problem !== undefined) {
      store.append({
        type: 'sandbox.degraded',
        payload: { schemaVersion: 1, driver: driver.name, reason: sweep.problem },
      })
      log.warn({ driver: driver.name, reason: sweep.problem, swept: sweep.swept }, 'the orphan sweep did not finish')
    } else if (sweep.swept.length > 0) {
      log.warn({ driver: driver.name, swept: sweep.swept }, 'killed by name containers a previous kernel left running')
    }
    // Why the sandbox is degraded: the probe's reason, then the sweep's, each
    // also in a sandbox.degraded row of its own. Both when both failed: the
    // probe's alone would never tell an operator reading status that a
    // container this log names may still be running. Each is bounded where it
    // is made (a driver's probe reason, sweepProblem's SWEEP_REASON_BYTES).
    const sandboxWhys = [...(sandboxProbe.ok ? [] : [sandboxProbe.why]), ...(sweep.problem === undefined ? [] : [sweep.problem])]
    const sandboxWhy = sandboxWhys.length === 0 ? undefined : sandboxWhys.join('; ')
    const sweptNote = sweep.swept.length > 0 ? sweptReason(sweep.swept) : undefined
    mark(
      'sandbox',
      sandboxWhy === undefined ? 'ok' : 'degraded',
      sandboxWhy === undefined
        ? sweptNote
        : `${driver.name}: ${sandboxWhy}${sweptNote === undefined ? '' : `; ${sweptNote}`}`,
    )

    // ── credentials: resolved ONCE, here, outside any run scope ───────────
    //
    // The broker refuses to resolve inside a run (`a run may not resolve a
    // secret`), and it is right to: a run that can ask for a secret is a run
    // that can be talked into asking for someone else's. But the router needs a
    // credential on every provider call, and those calls happen inside the
    // run's scope — so resolution happens now and the router only ever looks up
    // what boot already resolved.
    //
    // A failure here is not a boot failure. No vault and no env fallback is the
    // normal state on a machine with pmmcp down; it makes that ref unroutable
    // and the reason is what the router reports.
    const credentials = new Map<string, SecretRef>()
    const credentialFailures = new Map<string, string>()
    for (const [ref, card] of cards) {
      // A placeholder is refused by the router regardless (D28), and resolving
      // its credential would be a vault call for a model nothing can use.
      if (card.placeholder) continue
      if (card.auth.value !== undefined || card.auth.vaultId === undefined) continue
      try {
        credentials.set(
          ref,
          await broker.ref(card.auth.vaultId, `provider credential for ${ref}`, {
            ...(card.auth.envVar === undefined ? {} : { envVar: card.auth.envVar }),
          }),
        )
      } catch (e) {
        credentialFailures.set(ref, e instanceof Error ? e.message : String(e))
      }
    }

    // ── router (degradable per ref) ───────────────────────────────────────
    const resolveCredential = (card: ModelCard, ref: string): Promise<string | undefined> => {
      // A loopback endpoint's placeholder token, and the no-credential case.
      if (card.auth.value !== undefined) return Promise.resolve(card.auth.value)
      if (card.auth.vaultId === undefined) return Promise.resolve(undefined)

      const held = credentials.get(ref)
      if (held === undefined) {
        // Refused rather than returning undefined, for the MESSAGE.
        //
        // Nothing would reach the wire either way: the anthropic adapter refuses
        // an absent credential itself ("an Anthropic entry needs a credential"),
        // and it passes an explicit null for the field it is not using so the
        // SDK never falls back to an ambient ANTHROPIC_API_KEY. But that refusal
        // can only say a credential is missing, where this one says WHY — the
        // vault returned nothing, or envFallback is off, as boot found it. The
        // reason is what an operator needs, and it exists only here.
        return Promise.reject(
          new ConfigError(
            `${ref}: ${credentialFailures.get(ref) ?? 'no credential was resolved for this ref at boot'}`,
          ),
        )
      }
      // `use` is the accounted-for door: the access was logged when the ref was
      // minted, and the value's life is this call. The router's contract needs
      // the string itself to stamp a header, which is the seam.
      return Promise.resolve(broker.use(held, (value) => value))
    }
    const router = new Router({
      store,
      cards,
      probes,
      resolveCredential,
      // The real adapters. Without these the router falls back to
      // NotImplementedAdapter for both dialects and every run finishes with
      // `not implemented in this phase: anthropic adapter` and zero cost —
      // which is the Phase 0 exit criterion failing silently.
      adapters: { anthropic: new AnthropicAdapter(), 'openai-chat': new OpenAiChatAdapter() },
      maxRetries: config.budgets.maxRetries,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      now,
    })
    const routerReason = routerDegradation(cards, probes, now(), credentials, credentialFailures)
    if (routerReason !== undefined) {
      store.append({ type: 'router.degraded', payload: { schemaVersion: 1, reason: routerReason } })
    }
    mark('router', routerReason === undefined ? 'ok' : 'degraded', routerReason)

    // ── egress (degradable): built, so ok or degraded, never absent ────────
    //
    // Ok only once every check passes; otherwise one egress.degraded row per
    // failed check, each saying what failed and the key or command that fixes
    // it, as sandbox.degraded does, and the subsystem's reason joins them, as
    // many as fit EGRESS_REASON_BYTES (egressSummary). In
    // order: the config (egress.enabled), the sandbox (egress serves only a
    // container on the trusted domain, so a sandbox that cannot run one is
    // egress that cannot), and each binding's value, resolved here, ONCE,
    // outside any run scope, as the provider keys are above, and only while
    // egress is enabled: a disabled egress uses no credential, and resolving
    // one would record an access for nothing.
    const egressFailures: EgressFailure[] = []
    if (!config.egress.enabled) {
      egressFailures.push({
        check: 'config',
        reason:
          'egress.enabled is false in config/kernel.yaml, so no run is given a channel: set egress.enabled: true ' +
          'once the worker image is built and pinned (sandbox.imageId), to serve the egress a trusted manifest names',
      })
    }
    if (sandboxWhy !== undefined) {
      egressFailures.push({
        check: 'sandbox',
        reason:
          `the sandbox is degraded (${driver.name}: ${sandboxWhy}), and egress serves only a container on the ` +
          "trusted domain: fix the sandbox first, as the sandbox subsystem's reason says",
      })
    }
    const bindingRefs = new Map<string, SecretRef>()
    const bindingStatus = new Map<string, BindingStatus>()
    if (config.egress.enabled) {
      for (const [id, binding] of Object.entries(config.egress.bindings)) {
        const resolved = await resolveBinding(broker, config, id, binding)
        if ('ref' in resolved) {
          bindingRefs.set(id, resolved.ref)
          bindingStatus.set(id, { bindingId: id, envVar: binding.envVar })
          continue
        }
        bindingStatus.set(id, { bindingId: id, envVar: binding.envVar, problem: resolved.problem })
        egressFailures.push({
          check: 'binding',
          bindingId: id,
          reason: `egress binding ${id} (envVar ${binding.envVar}) did not resolve: ${resolved.problem}`,
        })
      }
    }
    // W3's seam: the pinned image id as each VM holds it, and a canary on each
    // domain (judged by src/egress/ready.ts's acceptReady), join these checks
    // here, each a failure of its own naming its domain (check 'image' or
    // 'canary'), and egress is ok only when they pass too. Each canary is to
    // be named uniquely per boot, and that name recorded as its grant's
    // `sandbox` (plan W3's note): the sweep's kills are left to finish once
    // boot stops waiting, so one held by a paused VM could end a canary this
    // boot started under a name an earlier boot's canary used.
    const egressReasons: string[] = []
    for (const failure of egressFailures) {
      // A binding id the log would store censored is recorded as no binding's.
      const named = failure.bindingId !== undefined && redactString(failure.bindingId) === failure.bindingId
      const reason = recordable(failure.reason, EGRESS_REASON_BYTES)
      egressReasons.push(reason)
      store.append({
        type: 'egress.degraded',
        payload: {
          schemaVersion: 1,
          check: failure.bindingId !== undefined && !named ? 'config' : failure.check,
          ...(named ? { bindingId: failure.bindingId } : {}),
          reason,
        },
      })
    }
    const egressState: EgressState =
      egressReasons.length === 0 ? { state: 'ok' } : { state: 'degraded', reason: egressSummary(egressReasons) }
    mark('egress', egressState.state, egressState.state === 'ok' ? undefined : egressState.reason)
    const upstream = options.egressUpstream ?? productionUpstream(config, options.egressUpstreamDeps)
    // The one header a binding injects, set from the broker's value and
    // nowhere else: the session hands its setter in, and never holds a
    // SecretRef. A binding boot did not resolve sets none, and the session
    // refuses that request unsent.
    const credential: CredentialInjector = (bindingId, set) => {
      const ref = bindingRefs.get(bindingId)
      const binding = Object.hasOwn(config.egress.bindings, bindingId) ? config.egress.bindings[bindingId] : undefined
      if (ref === undefined || binding === undefined) return
      broker.use(ref, (value) => {
        set(binding.header, binding.scheme === 'Bearer' ? `Bearer ${value}` : `Basic ${basicValue(binding.basicUser, value)}`)
      })
    }

    // ── lanes, policy, loop ──────────────────────────────────────────────
    const lanes = new Lanes({ main: config.lanes.main, subagent: config.lanes.subagent })
    const approvals = new Approvals({ waitMs: config.budgets.approvalWaitMs })
    const runs = new Map<string, LiveRun>()
    const quarantine = new Quarantine({
      store,
      onTainted: (runId) => {
        const live = runs.get(runId)
        if (live !== undefined) live.state = { ...live.state, taint: 'tainted' }
      },
    })
    const engine = new PolicyEngine({ store, approvals })
    // ── delegation: kernel-native tools, offered to an orchestrator only ──
    //
    // `launch` and `kill` close over `surface`, which is built last — the same
    // late binding the scheduler uses. Children start through the control plane's
    // own run path, so a delegated run is an ordinary run: same registry checks,
    // same lane, same gate, same log.
    const delegation = new Delegation({
      store,
      agents,
      writer: goalWriter,
      launch: (input) =>
        surface.launch({ agentId: input.agentId, input: input.input, goalId: input.goalId, ceiling: input.ceiling }),
      kill: (runId, reason) => {
        try {
          surface.killRun(runId, reason)
        } catch {
          // Already finished and gone: nothing left to stop.
        }
      },
    })
    const kernelTools = new KernelTools({ store, views: toolViews, handlers: delegation.handlers() })
    // ── sandbox tools: sandbox.exec, a worker's commands in a container ───
    //
    // Built whatever the sandbox subsystem's mark: a driver whose runtime does
    // not answer refuses each call itself, and the call's result says why. A
    // kernel whose config lets no exec run (a driver that runs nothing, the
    // apple-container stub, or no image id pinned: configRefusal) offers the
    // tool to no run. Every sandbox.* ref goes to this runner, never to the
    // hub, and is offered only to a run whose agent's manifest, read from the
    // registry, may hold it (sandboxToolProblem) and lists it. Each exec runs
    // --network none; one whose manifest has egress on the trusted domain is
    // issued a grant before its container starts and served over its channel
    // by the egress engine, while egress is ok (egressRefusal otherwise), and
    // the hostile domain gets no channel and no grant. No shipped manifest
    // lists a sandbox tool or holds egress.
    const sandboxTools = new SandboxTools({
      store,
      views: toolViews,
      driver,
      agents,
      sandbox: config.sandbox,
      egress: {
        state: egressState,
        bindings: config.egress.bindings,
        resolved: bindingStatus,
        limits: config.egress.limits,
        upstream,
        credential,
        acceptReady,
      },
    })

    const loop = new RunLoop({
      store,
      lanes,
      router,
      engine,
      quarantine,
      views: toolViews,
      agentView: () => hub.agentView(),
      budgetFor: (agent, ceiling) => {
        const caps = resolveCaps(config.budgets, agents.get(agent.agentId)?.manifest.budget ?? {})
        // A ceiling only ever LOWERS: the budget is the intersection of the
        // kernel's caps, the manifest's, and the slice a parent handed down.
        return new Budget(
          {
            usdMax: Math.min(caps.usdMax, ceiling?.usdMax ?? caps.usdMax),
            maxLlmCalls: Math.min(caps.maxLlmCalls, ceiling?.maxLlmCalls ?? caps.maxLlmCalls),
            maxToolCalls: Math.min(caps.maxToolCalls, ceiling?.maxToolCalls ?? caps.maxToolCalls),
            wallclockMs: Math.min(caps.wallclockMs, ceiling?.wallclockMs ?? caps.wallclockMs),
          },
          { now },
        )
      },
      kernelTools,
      sandboxTools,
    })

    // ── scheduler ─────────────────────────────────────────────────────────
    //
    // Built after the loop, because it starts runs through the same path the
    // control plane does: a scheduled run is an ordinary run on the agent's own
    // lane, with the same gate and the same budget. There is no cron lane.
    const scheduled = (): { agentId: string; schedule: string }[] =>
      agents
        .list()
        .filter((r) => r.status === 'active' && r.manifest.schedule !== undefined)
        .map((r) => ({ agentId: r.manifest.id, schedule: r.manifest.schedule as string }))

    const scheduler = new Scheduler({
      store,
      agents: scheduled,
      // Read fresh from the live run map rather than a snapshot, so a job whose
      // previous run is still going is skipped instead of queued behind it.
      isBusy: (agentId) =>
        [...runs.values()].some((r) => r.state.agentId === agentId && r.state.status !== 'finished'),
      startRun: (agentId, input) => surface.startRun({ agentId, input }),
      now,
    })

    // The run projection is read from the LOG, not kept alongside it. One
    // source of truth means status can never disagree with history.
    const unsubscribe = store.subscribe((row) => {
      if (row.runId === null) return
      if (row.type === 'run.finished') delegation.forget(row.runId)
      const live = runs.get(row.runId)
      if (live === undefined) return
      live.state = project(live.state, row.type, row.payload, row.seq, row.ts, (ref) => callTaints(toolViews, ref))
    })

    // Attached here, with the run projection, because both read the same stream.
    // Orphan goals are blocked only now: recovery ran before the hub existed, so
    // this is the first moment a status update can reach the server at all.
    const detachGoals = goalTracker.attach()
    if (recovered.orphanRuns.length > 0 && goalWriter.available) {
      // Not awaited: boot must not wait on a network round trip per orphan, and a
      // failure here is a stale goal, which the tracker logs. It rides the
      // tracker's queue, so shutdown's drain does wait for it.
      void goalTracker
        .blockOrphans(recovered.orphanRuns.map((r) => r.runId))
        .catch((e: unknown) => {
          log.warn(
            { err: e instanceof Error ? e.message : String(e) },
            'blocking orphaned runs’ goals failed',
          )
        })
    }

    // ── control plane: last, and not degradable ──────────────────────────
    const surface = buildSurface({
      store,
      approvals,
      quarantine,
      agents,
      cards,
      probes,
      runs,
      loop,
      lanes,
      config,
      repoRoot,
      subsystems: () => subsystems as Subsystems,
      bootedAt,
      now,
      broker,
      router,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    })
    const server = new ControlServer({
      store,
      port: config.control.port,
      token,
      allowedOrigins: config.control.allowedOrigins,
      maxPayloadBytes: config.control.maxPayloadBytes,
      surface,
    })
    // Started before control binds, so a schedule is live the moment the kernel
    // is. Marked in SUBSYSTEM_ORDER's position regardless of where it is built.
    scheduler.start()
    mark(
      'scheduler',
      'ok',
      scheduled().length === 0 ? 'running; no agent declares a schedule' : undefined,
    )

    await server.listen()
    mark('control', 'ok')

    let stopped = false
    const kernel: Kernel = {
      store,
      server,
      config,
      port: server.port,
      bootedAt,
      degraded,
      recovered,
      agents,
      hub,
      router,
      lanes,
      approvals,
      quarantine,
      scheduler,
      sandboxTools,
      lock,
      status: () => surface.status(),
      async shutdown(reason = 'requested', signal) {
        if (stopped) return
        stopped = true
        unsubscribe()
        unwatchGoals()
        detachGoals()
        scheduler.stop()
        for (const live of runs.values()) live.controller.abort()
        approvals.close()
        await server.close()
        // Before the hub closes: a queued goal update needs the connection it was
        // going to use, and dropping it silently is the one outcome worse than a
        // slow shutdown.
        await goalTracker.drain()
        await hub.close()
        store.append({
          type: 'kernel.shutdown',
          payload: {
            schemaVersion: 1,
            reason,
            ...(signal === undefined ? {} : { signal }),
            uptimeMs: Math.max(0, now() - startedAtMs),
          },
        })
        // close() anchors the tail on the way out, so the anchor names the
        // kernel.shutdown row itself and a clean exit always leaves an anchor
        // matching the log exactly. An explicit writeAnchor() here would write
        // the same anchor twice — one path, not two.
        store.close()
        // Last: the next kernel may take the data directory once this one
        // writes nothing more to it.
        lock.release()
      },
    }

    log.info(
      { port: kernel.port, degraded, configHash: hash },
      degraded.length === 0 ? 'kernel ready' : 'kernel booted degraded',
    )
    return kernel
  } catch (e) {
    // The RAW handle, not store.close().
    //
    // The clean close anchors the tail on its way out. On this path the log has
    // just FAILED verification, and anchoring it would overwrite the forged or
    // stale anchor with a fresh, valid one — so a tampered log would refuse
    // exactly once and then boot clean every time after, which defeats the only
    // defence there is against rows removed from the end of the chain.
    //
    // The handle still has to go: a leak is a lingering lock and a descriptor
    // per restart attempt.
    if (!store.closed) store.db.close()
    // After the log's handle: a refused boot holds the data directory no longer.
    lock.release()
    throw e
  }
}

// ── helpers ────────────────────────────────────────────────────────────────

/** One failed egress check, as boot records it (egress.degraded). */
interface EgressFailure {
  readonly check: 'config' | 'sandbox' | 'binding'
  readonly bindingId?: string
  readonly reason: string
}

/**
 * The egress subsystem's reason, and EgressState's, from each failed check's
 * reason as its egress.degraded row holds it: all of them joined while that
 * fits EGRESS_REASON_BYTES, and otherwise the first ones, whole, as many as
 * fit beside a count of the rest, which this boot's egress.degraded rows
 * name one by one. Bounded because it is echoed far: into subsystem.state,
 * status.get, and every exec refusal (assertEgressEnforced, so tool.gate's
 * reason and tool.result's text), and kernel.yaml admits any number of
 * bindings, so a joined reason of a few hundred unresolved ones would make
 * those rows past the store's limit and refuse the boot it describes. A
 * first reason that does not fit beside the count is cut to (recordable).
 */
function egressSummary(reasons: readonly string[]): string {
  const joined = reasons.join('; ')
  if (Buffer.byteLength(joined) <= EGRESS_REASON_BYTES) return joined
  const rest = (more: number): string =>
    `; and ${String(more)} more failed egress check(s), each named in this boot's egress.degraded rows`
  let kept = ''
  let shown = 0
  for (const reason of reasons) {
    const next = shown === 0 ? reason : `${kept}; ${reason}`
    if (Buffer.byteLength(next) + Buffer.byteLength(rest(reasons.length - shown - 1)) > EGRESS_REASON_BYTES) break
    kept = next
    shown += 1
  }
  if (shown === 0) {
    const tail = rest(reasons.length - 1)
    return `${recordable(reasons[0] ?? '', EGRESS_REASON_BYTES - Buffer.byteLength(tail))}${tail}`
  }
  return `${kept}${rest(reasons.length - shown)}`
}

/**
 * Resolve one binding's value through the broker, once, at boot: its ref, or
 * why not, naming the binding's envVar and never its value. Read from the
 * environment only (a binding names an envVar and no vault id: the vault is
 * dormant), checked as a bearer (bearerRefusal: whitespace, a character
 * outside printable ASCII, a joined NAME=value line, or one too short to
 * mask), and, for a Basic binding, its derived value (base64 of
 * `<basicUser>:<value>`) registered with SecretMask before anything can
 * quote it: a host that echoes the header it was sent would otherwise put a
 * function of the credential in a row.
 */
async function resolveBinding(
  broker: SecretsBroker,
  config: KernelConfig,
  id: string,
  binding: EgressBinding,
): Promise<{ readonly ref: SecretRef } | { readonly problem: string }> {
  if (config.secrets.source !== 'env') {
    return {
      problem:
        `bindings are read from the environment only (envVar ${binding.envVar}; a binding names no vault id), and ` +
        `secrets.source is ${config.secrets.source}: set secrets.source: env, and ${binding.envVar} in .env`,
    }
  }
  let ref: SecretRef
  try {
    ref = await broker.ref(`egress.bindings.${id}`, `egress credential for ${binding.host}`, { envVar: binding.envVar })
  } catch (e) {
    return { problem: e instanceof PolicyDenied ? e.reason : e instanceof Error ? e.message : String(e) }
  }
  const refusal = broker.use(ref, (value) => bearerRefusal(binding.envVar, value))
  if (refusal !== undefined) return { problem: refusal }
  if (binding.scheme === 'Basic') {
    const user = binding.basicUser
    const masked = broker.use(ref, (value) => SecretMask.register(basicValue(user, value)))
    if (!masked) return { problem: `${binding.envVar}'s Basic credential could not be masked` }
  }
  return { ref }
}

/** A Basic credential's value: base64 of `<user>:<value>` (RFC 7617). */
function basicValue(user: string, value: string): string {
  return Buffer.from(`${user}:${value}`, 'utf8').toString('base64')
}

/**
 * The sandbox driver boot builds from kernel.yaml when no test hands it one.
 * Exported, with the docker CLI's two process functions injectable, so that a
 * test can prove what kernel.yaml's sandbox block reaches the driver (the
 * pinned image id above all) with no docker binary. Boot passes none: the
 * process wiring lives in the docker module, which is the one place allowed to
 * import node:child_process.
 */
export function defaultDriver(config: KernelConfig, repoRoot: string, processes?: DockerProcesses): SandboxDriver {
  if (config.sandbox.driver === 'apple-container') return new AppleContainerDriver()
  // Boot only constructs and probes it: nothing spawns until a run asks for a
  // container, which a sandbox.exec does, through the runner boot hands the
  // loop.
  const options = {
    domains: config.sandbox.domains,
    defaults: config.sandbox.defaults,
    // Unset until the operator pins the built worker image; the probe then
    // reports the sandbox degraded, naming the key.
    imageId: config.sandbox.imageId,
    dockerConfig: join(config.dataDir, 'docker'),
    repoRoot,
  }
  // The two functions by name, never a spread of what was handed: TypeScript
  // checks no excess property on an argument that is not a literal, so a
  // DockerProcesses value carrying an imageId, domains or a dockerConfig of
  // its own would, spread last, override what kernel.yaml holds, and the test
  // meant to prove kernel.yaml decides would prove something else.
  return processes === undefined
    ? realDockerDriver(options)
    : new DockerDriver({ ...options, spawn: processes.spawn, execFile: processes.execFile })
}

/**
 * Make `path` unreadable to other accounts if it is not already: absent is
 * fine (nothing to protect yet), anything else that cannot be tightened is a
 * refusal, since the log would otherwise sit readable by every local account.
 */
function keepPrivate(path: string, mode: number): void {
  let current: number
  try {
    current = statSync(path).mode & 0o777
  } catch {
    return
  }
  if ((current & 0o077) === 0) return
  try {
    chmodSync(path, mode)
  } catch (e) {
    throw new ConfigError(
      `${path} has mode 0${current.toString(8)}, so other accounts can read it, and it could not be made 0${mode.toString(8)}: ` +
        `${e instanceof Error ? e.message : String(e)}`,
    )
  }
  log.info({ path, from: `0${current.toString(8)}`, to: `0${mode.toString(8)}` }, 'tightened a data path other accounts could read')
}

async function connectHub(
  hub: McpHub,
  config: KernelConfig,
  env: NodeJS.ProcessEnv,
  factory: ClientFactory | undefined,
): Promise<{ ok: boolean; reason?: string }> {
  const server = config.mcp.servers['pmmcp']
  if (server === undefined) return { ok: false, reason: 'kernel.yaml declares no pmmcp server' }

  let clientFactory = factory
  if (clientFactory === undefined) {
    // No tokenEnv means no bearer is sent. A DECLARED tokenEnv that is unset
    // refuses (the shipped AOS_PMMCP_TOKEN included, though pmmcp's gate runs
    // in warn mode): the operator said this server wants a credential, and
    // connecting without one would be a guess.
    const tokenEnv = server.tokenEnv
    const token = tokenEnv === undefined ? undefined : env[tokenEnv]
    if (tokenEnv !== undefined && (token === undefined || token.trim() === '')) {
      return {
        ok: false,
        reason: `${tokenEnv} is not set, so the kernel has no vault and no memory`,
      }
    }
    if (token !== undefined) {
      // The same checks a provider key gets. A bearer holding a newline makes
      // the HTTP library throw with the whole header value in its message, and
      // that message becomes a chained hub.degraded reason — so refuse it here,
      // by name, and mask the value before anything can quote it.
      const refusal = bearerRefusal(tokenEnv ?? 'the pmmcp bearer', token)
      if (refusal !== undefined) return { ok: false, reason: `${refusal}: the kernel has no vault and no memory` }
    }
    const url = server.url
    clientFactory = async (): Promise<Client> => {
      const client = new Client({ name: 'aos-kernel', version: VERSION })
      await client.connect(streamableHttpTransport(url, token))
      return client
    }
  }

  try {
    const state = await hub.connect('pmmcp', clientFactory)
    return state === 'connected'
      ? { ok: true }
      : { ok: false, reason: `pmmcp at ${server.url} did not connect` }
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) }
  }
}

/**
 * Why the router cannot serve, or undefined when it can.
 *
 * Phase 0's honest answer is usually "nothing is routable": every non-Claude
 * entry is a placeholder the router refuses, and the Claude entry needs both a
 * fresh probe and a credential. Reporting the router as ok while no ref can be
 * served would make `status.get` useless for the one question it exists to
 * answer.
 */
function routerDegradation(
  cards: ReadonlyMap<string, ModelCard>,
  probes: (ref: string) => ProbeRecord | undefined,
  nowMs: number,
  credentials: ReadonlyMap<string, SecretRef>,
  failures: ReadonlyMap<string, string>,
): string | undefined {
  const usable: string[] = []
  const why: string[] = []
  for (const [ref, card] of cards) {
    if (!routable(card, probes(ref), nowMs)) {
      why.push(`${ref}: ${card.placeholder ? 'placeholder' : 'no fresh probe reporting toolCalling'}`)
      continue
    }
    // What boot actually resolved, not a guess about whether it could have.
    const hasCredential =
      card.auth.value !== undefined ||
      card.auth.vaultId === undefined ||
      credentials.has(ref)
    if (!hasCredential) {
      why.push(`${ref}: ${failures.get(ref) ?? 'no credential resolved at boot'}`)
      continue
    }
    usable.push(ref)
  }
  if (usable.length > 0) return undefined
  return `no routable model: ${why.join('; ')}`
}

/**
 * Whether a call of `ref` that reached its tool.call taints its run, as the
 * run loop reads it: a sandbox tool always does (SandboxTools.call, whatever
 * its view says), and any other whose view says `taints: true`.
 */
export function callTaints(views: ToolViewsFile, ref: string): boolean {
  if (isSandboxRef(ref)) return true
  const at = ref.indexOf('.')
  if (at <= 0) return false
  return resolveView(views, ref.slice(0, at), ref.slice(at + 1)).taints
}

/**
 * The daemon's view of a run, from its rows. Taint is read from every row
 * that taints a run in the loop, so runs.list and run.get show what the gate
 * reads: the run's start, a held output released, a call of a tool that
 * taints (`callTaints`, from its tool.call: the loop marks the run once the
 * call has executed, which follows it), and a delegated child's tainted
 * result. Taint never clears.
 *
 * @internal Exported for its own tests; the kernel reads it through the
 *   store's subscription in bootKernel.
 */
export function project(
  state: RunState,
  type: string,
  payloadText: string,
  seq: number,
  ts: string,
  callTaintsOf: (ref: string) => boolean,
): RunState {
  let payload: Record<string, unknown> = {}
  try {
    payload = JSON.parse(payloadText) as Record<string, unknown>
  } catch {
    // A payload that will not parse is still a row: the seq still advances.
  }
  const next: RunState = { ...state, lastEventSeq: seq }
  const num = (key: string): number => (typeof payload[key] === 'number' ? (payload[key] as number) : 0)

  switch (type) {
    case 'run.started':
      return {
        ...next,
        status: 'running',
        startedAt: ts,
        taint: payload['taint'] === 'tainted' ? 'tainted' : next.taint,
      }
    case 'run.parked':
      return { ...next, status: 'parked' }
    case 'run.resumed':
      return { ...next, status: 'running' }
    case 'run.finished':
      return {
        ...next,
        status: 'finished',
        finishedAt: ts,
        ...(typeof payload['reason'] === 'string'
          ? { reason: payload['reason'] }
          : { reason: String(payload['status'] ?? 'unknown') }),
        llmCalls: num('llmCalls'),
        toolCalls: num('toolCalls'),
        costMicroUsd: num('costMicroUsd'),
      }
    case 'llm.response':
      return { ...next, llmCalls: next.llmCalls + 1, costMicroUsd: next.costMicroUsd + num('costMicroUsd') }
    case 'tool.result':
      return { ...next, toolCalls: next.toolCalls + 1 }
    case 'tool.call':
      return typeof payload['toolRef'] === 'string' && callTaintsOf(payload['toolRef'])
        ? { ...next, taint: 'tainted' }
        : next
    case 'delegation.result':
      return payload['taint'] === 'tainted' ? { ...next, taint: 'tainted' } : next
    case 'quarantine.released':
      return { ...next, taint: 'tainted' }
    default:
      return next
  }
}

interface SurfaceDeps {
  readonly store: EventStore
  readonly approvals: Approvals
  readonly quarantine: Quarantine
  readonly agents: AgentRegistry
  readonly cards: ReadonlyMap<string, ModelCard>
  readonly probes: (ref: string) => ProbeRecord | undefined
  readonly runs: Map<string, LiveRun>
  readonly loop: RunLoop
  readonly lanes: Lanes
  readonly config: KernelConfig
  readonly repoRoot: string
  readonly subsystems: () => Subsystems
  readonly bootedAt: string
  readonly now: () => number
  readonly broker: SecretsBroker
  readonly router: Router
  readonly fetch?: typeof globalThis.fetch
}

/**
 * The control surface, plus one method the protocol never sees.
 *
 * `launch` is `startRun` that also hands back the run's outcome. Delegation needs
 * it — a parent waits on its child's result, cost and taint — and the protocol does
 * not: `run.start` stays exactly as v1 froze it. Both share one body, so a child
 * run is started by precisely the code that starts an operator's run.
 */
type KernelSurface = ControlSurface & {
  readonly launch: (input: {
    agentId: string
    input: string
    goalId?: string | undefined
    taint?: 'clean' | 'tainted' | undefined
    ceiling?: Partial<BudgetCaps> | undefined
  }) => { runId: string; outcome: Promise<RunOutcome> }
}

function buildSurface(d: SurfaceDeps): KernelSurface {
  const souls: SoulBudgetTracker = { used: 0 }

  const runAgent = (record: AgentRecord): RunAgent => {
    const m = record.manifest
    const soul = loadSoul(join(d.repoRoot, 'souls'), m.soul, souls)
    return {
      agentId: m.id,
      tier: m.tier,
      lane: m.role === 'orchestrator' ? 'main' : 'subagent',
      model: m.model,
      toolAllow: m.tools.allow,
      system: soul.text,
      projectId: m.memory.projectId,
      role: m.role,
    }
  }

  const launch: KernelSurface['launch'] = (input) => {
    const record = d.agents.get(input.agentId)
    if (record === undefined || record.status !== 'active') {
      throw new ConfigError(`no active agent ${input.agentId}`)
    }
    if (record.manifest.kind === 'template') {
      throw new ConfigError(`${input.agentId} is a template: spawn from it, do not run it`)
    }
    const runId = `run_${String(d.now())}_${Math.random().toString(36).slice(2, 8)}`
    const controller = new AbortController()
    d.runs.set(runId, {
      controller,
      state: {
        runId,
        agentId: input.agentId,
        status: 'queued',
        taint: input.taint ?? 'clean',
        llmCalls: 0,
        toolCalls: 0,
        costMicroUsd: 0,
        lastEventSeq: d.store.tailSeq(),
      },
    })

    // Not awaited here: run.start returns a runId and the run's progress is the
    // event stream. The outcome is handed back for the one in-process caller that
    // waits on it (delegation). The catch is not optional — an unhandled
    // rejection would take the daemon down with it — and a failure becomes an
    // error outcome rather than a rejection, so a waiting parent is never left
    // holding a promise that throws.
    const outcome = d.loop
      .start({
        runId,
        agent: runAgent(record),
        prompt: input.input,
        signal: controller.signal,
        ...(input.taint === undefined ? {} : { taint: input.taint }),
        ...(input.goalId === undefined ? {} : { goalId: input.goalId }),
        ...(input.ceiling === undefined ? {} : { ceiling: input.ceiling }),
      })
      .catch((e: unknown): RunOutcome => {
        const reason = e instanceof Error ? e.message : String(e)
        log.error({ runId, err: reason }, 'run failed')
        return {
          runId,
          status: 'error',
          reason,
          costMicroUsd: 0,
          llmCalls: 0,
          toolCalls: 0,
          finalText: '',
          taint: 'clean',
        }
      })
    return { runId, outcome }
  }

  return {
    store: d.store,
    approvals: d.approvals,
    quarantine: d.quarantine,

    status: () => {
      const tail = d.store.tailSeq()
      return statusView({
        bootedAt: d.bootedAt,
        subsystems: d.subsystems(),
        chainHead: tail === 0 ? null : { seq: tail, hash: d.store.head() },
        lanes: d.lanes.diagnostics(),
        // Protocol v1's field: true whenever a credential may come from the
        // environment, which `source: env` makes the designed path.
        envFallback: d.config.secrets.source === 'env' || d.config.secrets.envFallback,
      })
    },

    agents: (includeArchived) =>
      d.agents
        .list()
        .filter((r) => includeArchived || r.status === 'active')
        .map(
          (r): AgentSummary =>
            agentSummaryView({
              id: r.manifest.id,
              version: r.manifest.version,
              kind: r.manifest.kind,
              role: r.manifest.role,
              tier: r.manifest.tier,
              status: r.status,
              modelPrimary: r.manifest.model.primary,
            }),
        ),

    promote: (approvalId, actor) => {
      const pending = d.approvals.pending().find((p) => p.approvalId === approvalId)
      if (pending === undefined || pending.kind !== 'promotion' || pending.agentId === undefined) {
        throw new ConfigError(`${approvalId} is not a pending promotion approval`)
      }
      // One human action: the approval resolves AND the agent is promoted.
      // Two calls would leave a window in which the approval is spent and the
      // promotion did not happen.
      d.approvals.resolve(approvalId, actor, 'approved')
      const promoted = d.agents.promote(pending.agentId, actor)
      return { agentId: promoted.manifest.id }
    },

    archive: (agentId, actor, reason) => {
      // `reason` is the operator's note; the registry records the archive
      // itself, so the note is logged rather than silently dropped.
      log.info({ agentId, reason }, 'agent archive requested')
      d.agents.archive(agentId, actor)
    },

    startRun: (input) => launch(input).runId,
    launch: (input) => launch(input),

    killRun: (runId, reason) => {
      const live = d.runs.get(runId)
      if (live === undefined) throw new ConfigError(`no such run ${runId}`)
      if (live.state.status === 'finished') return 'finished'
      log.info({ runId, reason }, 'run kill requested')
      live.controller.abort()
      return live.state.status
    },

    runs: (filter) => {
      const all = [...d.runs.values()].map((r) => runSummaryView(r.state))
      const matched = filter.status === undefined ? all : all.filter((r) => r.status === filter.status)
      return filter.limit === undefined ? matched : matched.slice(-filter.limit)
    },

    run: (runId): RunDetail | undefined => {
      const live = d.runs.get(runId)
      return live === undefined ? undefined : runDetailView(live.state)
    },

    models: (): ModelSummary[] => {
      const nowMs = d.now()
      return [...d.cards.entries()].map(([ref, card]) =>
        modelSummaryView(ref, card, d.probes(ref), nowMs),
      )
    },

    probeModel: async (ref): Promise<ProbeRecordResult> => {
      const card = d.cards.get(ref)
      if (card === undefined) throw new ConfigError(`${ref} is not in providers.yaml`)
      let credential: string | undefined
      if (card.auth.value !== undefined) credential = card.auth.value
      else if (card.auth.vaultId !== undefined) {
        const secret = await d.broker.ref(card.auth.vaultId, `probe of ${ref}`, {
          ...(card.auth.envVar === undefined ? {} : { envVar: card.auth.envVar }),
        })
        credential = d.broker.use(secret, (v) => v)
      }
      const result = await probe({
        store: d.store,
        dataDir: d.config.dataDir,
        ref,
        card,
        ...(credential === undefined ? {} : { credential }),
        ...(d.fetch === undefined ? {} : { fetch: d.fetch }),
      })
      return probeView(result.record)
    },
  }
}
