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

import { execFile, spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { promisify } from 'node:util'
import { join } from 'node:path'

const execFileAsync = promisify(execFile)

import { VERSION } from './version.js'
import { log } from './log.js'
import { ConfigError, NotImplementedError } from './errors.js'
import type { KernelConfig } from './config.js'

import { EventStore } from './events/store.js'
import { canonicalize } from './events/canonical.js'
import { SecretMask } from './events/redact.js'

import { AgentRegistry, type AgentRecord } from './agents/registry.js'
import { loadSoul, type SoulBudgetTracker } from './agents/souls.js'
import { type ToolViewsFile } from './mcp/tool-views.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'

import { McpHub, streamableHttpTransport, type ClientFactory } from './mcp/hub.js'
import { SecretsBroker, type SecretRef } from './secrets/broker.js'
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
import { Budget, resolveCaps } from './runtime/budget.js'
import { RunLoop, type RunAgent } from './runtime/loop.js'
import { assertEgressEnforced } from './runtime/egress.js'
import { Scheduler } from './runtime/scheduler.js'
import { assertDelegationAvailable } from './runtime/delegate.js'
import { AppleContainerDriver } from './sandbox/apple-container.js'
import { DockerDriver } from './sandbox/docker.js'
import type { SandboxDriver } from './sandbox/driver.js'
import { assertTokenUsable } from './control/auth.js'
import { ControlServer, type ControlSurface } from './control/server.js'
import { mintHumanActor, type HumanActor } from './control/actor.js'
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
    how: 'every method throws NotImplementedError; macOS 15 has no `container` binary',
  },
  {
    id: 'egress-proxy',
    where: 'src/runtime/egress.ts',
    how: 'assertEgressEnforced() throws NotImplementedError, so no run can reach the network',
  },
  {
    id: 'scheduler',
    where: 'src/runtime/scheduler.ts',
    how: 'Scheduler.start() throws NotImplementedError; a manifest carrying `schedule:` is refused at parse',
  },
  {
    id: 'delegate-tool',
    where: 'src/runtime/delegate.ts',
    how: 'assertDelegationAvailable() throws NotImplementedError; no delegation tool is offered to any model',
  },
  {
    id: 'approvals-projection',
    where: 'src/policy/approvals.ts',
    how: 'rebuildFromLog() throws NotImplementedError rather than returning an empty set after a restart',
  },
  {
    id: 'quarantine-projection',
    where: 'src/policy/quarantine.ts',
    how: 'rebuildFromLog() throws NotImplementedError rather than returning an empty set after a restart',
  },
]

export interface BootOptions {
  readonly config: KernelConfig
  /** Repository root, for protected-path resolution and the agents/souls dirs. */
  readonly repoRoot: string
  readonly providers: ProvidersFile
  readonly toolViews: ToolViewsFile
  readonly env?: NodeJS.ProcessEnv
  /** Injected by tests so no boot spawns docker. */
  readonly sandboxDriver?: SandboxDriver
  /** Injected by tests so no boot opens a socket to a real pmmcp. */
  readonly clientFactory?: ClientFactory
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
  readonly agents: AgentRegistry
  readonly hub: McpHub
  readonly router: Router
  readonly lanes: Lanes
  readonly approvals: Approvals
  readonly quarantine: Quarantine
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
  'scheduler',
  'egress',
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

  // The store cannot open a database in a directory that does not exist, and on
  // a first boot ~/.aos does not: without this, a clean machine fails with
  // "unable to open database file" and no hint that a mkdir was all it needed.
  //
  // 0700, not the umask's guess. The log holds prompts, model responses and tool
  // output, and events.head beside it is trust-bearing — anything that can
  // rewrite the anchor can hide a truncation. Created after the token check, so
  // a boot that cannot legally serve still creates nothing.
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 })

  const dbPath = join(config.dataDir, 'events.db')
  // The constructor compares every expected trigger's stored DDL against the
  // canonical text and throws when one is missing or altered, so "the
  // append-only triggers are intact" is established by the store existing.
  const store = new EventStore(dbPath, {
    anchorEvery: config.events.anchorEvery,
    headFile: join(config.dataDir, 'events.head'),
  })

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
    mark('events', 'ok')

    // ── registries ────────────────────────────────────────────────────────
    const cards = new Map<string, ModelCard>(Object.entries(providers.entries))
    const agents = new AgentRegistry({
      providers: new Set(cards.keys()),
      toolViews,
      store,
    })
    agents.load(join(repoRoot, 'agents'))

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
      ...(hubState.ok ? { hub } : {}),
      keyArg: config.secrets.keyArg,
      envFallback: config.secrets.envFallback,
      env,
    })

    mark('hub', hubState.ok ? 'ok' : 'degraded', hubState.reason)
    // D8: env fallback keeps the vault path degraded for as long as it is on.
    // A kernel reporting ready while a credential may be coming from the
    // environment would be hiding the thing an operator most needs to know.
    const secretsReason = !hubState.ok
      ? `no vault: ${hubState.reason ?? 'pmmcp is not connected'}`
      : config.secrets.envFallback
        ? 'envFallback is on: a credential may come from the environment rather than the vault'
        : undefined
    mark('secrets', secretsReason === undefined ? 'ok' : 'degraded', secretsReason)

    // ── sandbox (degradable) ──────────────────────────────────────────────
    const driver = options.sandboxDriver ?? defaultDriver(config, repoRoot)
    // probe() never throws: a missing container runtime is a degraded boot,
    // not a dead kernel.
    const sandboxProbe = await driver.probe()
    if (!sandboxProbe.ok) {
      store.append({
        type: 'sandbox.degraded',
        payload: { schemaVersion: 1, driver: driver.name, reason: sandboxProbe.why },
      })
    }
    mark(
      'sandbox',
      sandboxProbe.ok ? 'ok' : 'degraded',
      sandboxProbe.ok ? undefined : `${driver.name}: ${sandboxProbe.why}`,
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

    // ── absent by design, and saying so ──────────────────────────────────
    mark('scheduler', 'absent', stubReason('scheduler', () => new Scheduler().start()))
    mark('egress', 'absent', stubReason('egress-proxy', assertEgressEnforced))

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
    const loop = new RunLoop({
      store,
      lanes,
      router,
      engine,
      quarantine,
      views: toolViews,
      agentView: () => hub.agentView(),
      budgetFor: (agent) =>
        new Budget(
          resolveCaps(config.budgets, agents.get(agent.agentId)?.manifest.budget ?? {}),
          { now },
        ),
    })

    // The run projection is read from the LOG, not kept alongside it. One
    // source of truth means status can never disagree with history.
    const unsubscribe = store.subscribe((row) => {
      if (row.runId === null) return
      const live = runs.get(row.runId)
      if (live === undefined) return
      live.state = project(live.state, row.type, row.payload, row.seq, row.ts)
    })

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
      agents,
      hub,
      router,
      lanes,
      approvals,
      quarantine,
      status: () => surface.status(),
      async shutdown(reason = 'requested', signal) {
        if (stopped) return
        stopped = true
        unsubscribe()
        for (const live of runs.values()) live.controller.abort()
        approvals.close()
        await server.close()
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
    throw e
  }
}

// ── helpers ────────────────────────────────────────────────────────────────

/** The reason string for something absent by design, taken from its own throw. */
function stubReason(id: string, call: () => unknown): string {
  try {
    call()
  } catch (e) {
    if (e instanceof NotImplementedError) return e.message
    return e instanceof Error ? e.message : String(e)
  }
  // If a stub stops throwing, that is a real change and must not be reported
  // as "absent" — the honesty tests exist to catch exactly this.
  throw new ConfigError(`${id} is listed as absent but did not refuse when called`)
}

function defaultDriver(config: KernelConfig, repoRoot: string): SandboxDriver {
  if (config.sandbox.driver === 'apple-container') return new AppleContainerDriver()
  // The driver is constructed, not used: nothing spawns until a run asks for a
  // container, and in Phase 0 nothing does. Boot only probes it.
  return new DockerDriver({
    spawn: (command, args, options) => spawn(command, [...args], options),
    execFile: (command, args, options) => execFileAsync(command, [...args], options),
    domains: config.sandbox.domains,
    defaults: config.sandbox.defaults,
    repoRoot,
  })
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
    const tokenEnv = server.tokenEnv
    const token = tokenEnv === undefined ? undefined : env[tokenEnv]
    if (token === undefined || token.trim() === '') {
      return {
        ok: false,
        reason: `${tokenEnv ?? 'pmmcp token'} is not set, so the kernel has no vault and no memory`,
      }
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

function project(
  state: RunState,
  type: string,
  payloadText: string,
  seq: number,
  ts: string,
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

function buildSurface(d: SurfaceDeps): ControlSurface {
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
    }
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
        envFallback: d.config.secrets.envFallback,
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

    startRun: (input) => {
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

      // Deliberately not awaited: run.start returns a runId and the run's
      // progress is the event stream. The catch is not optional — an unhandled
      // rejection here would take the daemon down with it.
      void d.loop
        .start({
          runId,
          agent: runAgent(record),
          prompt: input.input,
          signal: controller.signal,
          ...(input.taint === undefined ? {} : { taint: input.taint }),
          ...(input.goalId === undefined ? {} : { goalId: input.goalId }),
        })
        .catch((e: unknown) => {
          log.error({ runId, err: e instanceof Error ? e.message : String(e) }, 'run failed')
        })
      return runId
    },

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

/** Re-exported so callers need not reach into control/actor. */
export { mintHumanActor, type HumanActor }
