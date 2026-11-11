// Agent registry (invariant 6).
//
// Loads manifests, validates them against the rest of the configuration, and
// owns the three lifecycle actions that change what an agent may do.
//
// The division of authority is the point:
//
//   spawnEphemeral   the CEO may do this, and the child is CLAMPED to the
//                    template — never above its tier, never a host or a
//                    binding the template does not list, never a tool it
//                    does not have.
//   requestPromotion the CEO may only ASK. It files an approval and changes
//                    nothing, so a model cannot argue its way to more reach.
//   promote/archive  a human only, proved by the HumanActor brand.
//
// Archive never deletes. Files stay on disk and history is kept, because an
// audit of what an agent did needs the manifest it did it under.
//
// Sandbox tools (`sandbox.exec`) are held here too: only a worker with a
// sandbox: block, at tier 2 or more, may list one (sandboxToolProblem), so no
// other agent is ever offered one.
//
// Cross-file checks happen at load, not at first use. A model reference with
// no provider entry, or a tool the views make kernel-only, is a configuration
// error someone should see while reading config — not a mid-run failure.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { assertHumanActor, type HumanActor } from '../control/actor.js'
import { parseEgressHost, type EgressHost } from '../egress/host.js'
import { BINDING_ID } from '../egress/policy.js'
import { ConfigError } from '../errors.js'
import { redactString } from '../events/redact.js'
import type { EventStore } from '../events/store.js'
import { resolveView, type ToolViewsFile } from '../mcp/tool-views.js'
import { resolveCaps, type KernelBudgets } from '../runtime/budget.js'
import { KERNEL_SERVER } from '../runtime/kernel-tools.js'
import { SANDBOX_SERVER, sandboxToolProblem } from '../runtime/sandbox-tools.js'
import { parseManifest, Tier, type AgentManifest } from './manifest.js'

export interface AgentRecord {
  readonly manifest: AgentManifest
  readonly status: 'active' | 'archived'
  readonly dir: string
}

export interface RegistryDeps {
  /** Model refs that exist in providers.yaml. */
  readonly providers: ReadonlySet<string>
  readonly toolViews: ToolViewsFile
  readonly store: EventStore
  /**
   * The operator's per-run ceilings, so a manifest asking for more is refused
   * HERE.
   *
   * Required rather than optional deliberately. `resolveCaps` already refuses an
   * over-ceiling budget, but only when a run starts — so a bad manifest loaded
   * clean and failed at the first run, which is the worst place to find a config
   * error. An optional dep would let a call site skip the check by omission,
   * which is the same failure one level up.
   */
  readonly budgets: KernelBudgets
  /**
   * kernel.yaml's egress bindings (config.egress.bindings), keyed by id: the
   * ids a manifest's egress.bind may name, and the hosts its egress.allow may
   * not. Only each binding's host is read. Required for the reason budgets
   * is: a registry built without it would skip the bound-host check by
   * omission, so a manifest could list as credential-free a host the
   * operator bound.
   */
  readonly egressBindings: Readonly<Record<string, { readonly host: EgressHost }>>
}

/**
 * The risks a tier may hold, from plan D15.
 *
 * Tier is meant to be the gate's posture for an agent, and until now it did no
 * work at load: a tier 1 manifest could list a `write` tool and the only thing
 * stopping it was the gate at call time. That is a refusal in the right place but
 * at the wrong moment — an operator wants to hear it when the file is read, with
 * the file named, not on the first run that happens to reach for it.
 */
const RISKS_BY_TIER: Readonly<Record<number, readonly string[]>> = {
  0: [],
  1: ['read'],
  2: ['read', 'write'],
  // Tier 3 may REQUEST an irreversible tool. It is still human-gated, always.
  3: ['read', 'write', 'irreversible'],
}

/** The tier egress starts at: tier 2 is the first that runs sandboxed in the trusted domain (plan D15). */
const EGRESS_MIN_TIER = 2

/**
 * Freeze `record` and its manifest all the way down, and return the record.
 *
 * Object.freeze alone is shallow: on a record it fixes status while
 * manifest.tier, egress.bind and every other list in the manifest stay
 * writable, so whatever held a record could widen that agent's reach with no
 * event row. Only kernel code holds records, so this is defense in depth,
 * and it matters most for egress.bind, the credential-bearing routes the
 * grant issuer reads from the record (egress plan W1).
 */
function freezeRecord(record: AgentRecord): AgentRecord {
  freezeManifest(record.manifest)
  return Object.freeze(record)
}

/**
 * Freeze every object and array in a manifest, depth first. A manifest is
 * zod output, plain objects, arrays and primitives with no cycles, so the walk
 * ends. A part already frozen (a child's model, shared with its template) is
 * walked again rather than trusted: Object.isFrozen is true of a shallow
 * freeze too.
 */
function freezeManifest(value: unknown): void {
  if (typeof value !== 'object' || value === null) return
  for (const part of Object.values(value)) freezeManifest(part)
  Object.freeze(value)
}

/**
 * The index of the first requested entry a spawn refusal may not repeat, or
 * -1. Such an entry is no string, or not in its field's shape (`shaped`), or
 * is text redactString changes: a refusal naming one in a credential's shape
 * would be stored censored in its agent.spawn.rejected row. None of these can
 * be in a template's list, since a loaded manifest holds only entries that
 * pass the same tests (the schema, and #egressProblem), so the refusal names
 * the index alone, as the load path does.
 */
function unnameable(entries: readonly string[], shaped: (entry: string) => boolean): number {
  return entries.findIndex((entry) => typeof entry !== 'string' || !shaped(entry) || redactString(entry) !== entry)
}

/** An egress host in its one spelling: what a template's allow list holds. */
function isSpelledHost(host: string): boolean {
  const seen = parseEgressHost(host)
  return seen.ok && seen.host === host
}

export class AgentRegistry {
  readonly #agents = new Map<string, AgentRecord>()
  readonly #deps: RegistryDeps
  /**
   * Each binding's host, by id, copied at construction from the binding
   * record's own keys. A manifest's id is looked up here, never in the
   * record: a parsed record is a plain object, so `'constructor' in bindings`
   * is true and `bindings['constructor']` is Object, and a manifest
   * `bind: [constructor]` (a valid binding id) would pass as known with no
   * host behind it (egress plan E6).
   */
  readonly #bindingHosts: ReadonlyMap<string, EgressHost>
  /** The bindings on each host, so a refusal names whose host a manifest listed. */
  readonly #boundHosts: ReadonlyMap<string, readonly string[]>

  constructor(deps: RegistryDeps) {
    this.#deps = deps
    const hosts = new Map<string, EgressHost>()
    const bound = new Map<string, string[]>()
    for (const [id, binding] of Object.entries(deps.egressBindings)) {
      hosts.set(id, binding.host)
      bound.set(binding.host, [...(bound.get(binding.host) ?? []), id])
    }
    this.#bindingHosts = hosts
    this.#boundHosts = bound
  }

  /** Load every agents/<id>/agent.yaml under `agentsDir`. */
  /**
   * Read every manifest, validate every one, and only then register any.
   *
   * Two phases on purpose. A single pass registers as it walks, so a fleet with
   * one bad manifest left the earlier ones registered and their
   * `agent.registered` rows in the log — from a boot that then refused. The boot
   * refusal was correct; the half-written record of a fleet that never existed
   * was not. All-or-nothing means the log says either "this fleet loaded" or
   * nothing at all.
   */
  load(agentsDir: string): void {
    const pending: { manifest: AgentManifest; dir: string }[] = []
    const seen = new Map<string, string>()

    for (const entry of readdirSync(agentsDir)) {
      const dir = join(agentsDir, entry)
      if (!statSync(dir).isDirectory()) continue
      const file = join(dir, 'agent.yaml')
      const manifest = parseManifest(parseYaml(readFileSync(file, 'utf8')), file)
      this.#validate(manifest, file)

      const already = seen.get(manifest.id) ?? (this.#agents.has(manifest.id) ? 'a previous load' : undefined)
      if (already !== undefined) {
        throw new ConfigError(`duplicate agent id ${manifest.id} (second copy at ${file})`)
      }
      if (manifest.id !== entry) {
        throw new ConfigError(`${file}: id "${manifest.id}" does not match its directory "${entry}"`)
      }
      seen.set(manifest.id, file)
      pending.push({ manifest, dir })
    }

    for (const record of pending) {
      this.#register({ manifest: record.manifest, status: 'active', dir: record.dir })
    }
  }

  #validate(manifest: AgentManifest, source: string): void {
    const refs = [manifest.model.primary, ...manifest.model.fallbacks]
    for (const ref of refs) {
      if (!this.#deps.providers.has(ref)) {
        // Refused, not dropped (plan D14): silently removing a fallback would
        // leave an agent with a shorter chain than its author intended and no
        // sign of it anywhere.
        throw new ConfigError(`${source}: model ref ${ref} is not in providers.yaml`)
      }
    }

    for (const ref of manifest.tools.allow) {
      const dot = ref.indexOf('.')
      const serverId = ref.slice(0, dot)
      const tool = ref.slice(dot + 1)
      const view = resolveView(this.#deps.toolViews, serverId, tool)
      if (view.exposure !== 'agent') {
        throw new ConfigError(
          `${source}: tools.allow names ${ref}, which is ${view.exposure}. ` +
            'A manifest cannot grant what the tool views withhold.',
        )
      }
      // Kernel tools start runs and write goal trees. They are the orchestrator's
      // alone: a worker that could delegate would make depth 1 a matter of which
      // manifest happened to list the tool. The loop refuses to OFFER them to a
      // worker as well; this refuses to LOAD the manifest that asks.
      if (serverId === KERNEL_SERVER && manifest.role !== 'orchestrator') {
        throw new ConfigError(
          `${source}: tools.allow names ${ref}, a kernel tool, but ${manifest.id} is role: ` +
            `${manifest.role}. Kernel tools are for the orchestrator only.`,
        )
      }
    }
    // Before the tier rule, so a sandbox tool below tier 2 is refused in the
    // sandbox's own words rather than only as a write tool too high for its tier.
    const sandboxed = this.#sandboxToolProblem(manifest)
    if (sandboxed !== undefined) throw new ConfigError(`${source}: ${sandboxed}`)
    const tiered = this.#tierToolProblem(manifest)
    if (tiered !== undefined) throw new ConfigError(`${source}: ${tiered}`)

    // Throws with the cap it exceeded and by how much. A manifest may only lower.
    resolveCaps(this.#deps.budgets, manifest.budget ?? {})

    const egress = this.#egressProblem(manifest)
    if (egress !== undefined) throw new ConfigError(`${source}: ${egress}`)
  }

  /**
   * Why `manifest` may not hold the sandbox tools it lists, or undefined.
   * Sandbox tools (`sandbox.exec`) run a worker's commands in a container of
   * its own domain, so only a manifest sandboxToolProblem admits may list one:
   * a worker, with a sandbox: block, at tier 2 or more. The loop offers a tool
   * only to a manifest that lists it, so no other agent is ever offered one;
   * the runner asks again at each call. Asked at load and of every spawned
   * child, which keeps its template's role and sandbox but may lower its tier.
   */
  #sandboxToolProblem(manifest: AgentManifest): string | undefined {
    for (const ref of manifest.tools.allow) {
      if (ref.slice(0, ref.indexOf('.')) !== SANDBOX_SERVER) continue
      const why = sandboxToolProblem(manifest)
      if (why !== undefined) return `tools.allow names ${ref}: ${why}`
    }
    return undefined
  }

  /**
   * Why `manifest`'s tier may not hold the tools it lists, or undefined: a
   * tool's risk is one its tier holds (RISKS_BY_TIER), and tier 0 holds none.
   * Asked at load and of every spawned child, since a child that lowers its
   * tier and keeps the template's tools would hold what no loaded manifest
   * may. The tools are the template's (a spawn admits no other), so naming
   * one repeats nothing a caller wrote.
   */
  #tierToolProblem(manifest: AgentManifest): string | undefined {
    for (const ref of manifest.tools.allow) {
      const dot = ref.indexOf('.')
      const view = resolveView(this.#deps.toolViews, ref.slice(0, dot), ref.slice(dot + 1))
      const allowed = RISKS_BY_TIER[manifest.tier] ?? []
      if (!allowed.includes(view.risk)) {
        return (
          `tools.allow names ${ref}, which is ${view.risk} risk, but tier ` +
          `${String(manifest.tier)} may hold ${allowed.length === 0 ? 'no tools' : allowed.join(' or ')}. ` +
          'Raise the tier deliberately or drop the tool.'
        )
      }
    }
    if (manifest.tier === 0 && manifest.tools.allow.length > 0) return 'tier 0 means no tools, but tools.allow is not empty'
    return undefined
  }

  /**
   * Why `manifest` may not hold the egress it names, or undefined. Asked of
   * every manifest at load and of every spawned child, since a child that
   * narrows its tier below 2 and keeps the template's hosts would hold what
   * no loaded manifest may.
   *
   * Egress (a host in allow, or a binding in bind) is for a worker's
   * sandboxed run only:
   *
   *   * Never an orchestrator. It runs in process, not in a sandbox, and it
   *     is the one agent that starts runs and writes goal trees: content it
   *     fetched would steer delegation itself. A worker fetches; the
   *     orchestrator delegates to one.
   *   * Only in the trusted domain. Egress reaches a run only through the
   *     channel of its sandbox, and the hostile domain gets no channel and no
   *     egress (docs/design/agent-fleet.md); a manifest with no sandbox has no
   *     run egress could reach.
   *   * Tier 2 or more, the first tier that runs sandboxed in the trusted
   *     domain (plan D15).
   *
   * Then each entry: a bind names a binding kernel.yaml holds (looked up in
   * #bindingHosts, never the record; one in a credential's shape is refused
   * without being repeated), and an allow host is no binding's host
   * (a bound host is reached only through its binding's profiles and
   * repositories, and a request to a host both bound and credential-free
   * would not say whether a credential belongs on it), and is one the event
   * log stores as written (a host in a credential's shape would be recorded
   * censored, in a grant row naming nothing it could read back; events/types.ts
   * refuses such a row, so a grant naming one could never be issued).
   */
  #egressProblem(manifest: AgentManifest): string | undefined {
    const { allow, bind } = manifest.egress
    if (allow.length === 0 && bind.length === 0) return undefined
    const who = `${manifest.id} holds egress`

    if (manifest.role === 'orchestrator') {
      return (
        `${who}, but it is role: orchestrator. Egress is for a worker's sandboxed run: the orchestrator runs in ` +
        'process and starts every other run, so content it fetched would steer delegation. Drop egress, or give it to a worker.'
      )
    }
    if (manifest.sandbox?.domain !== 'trusted') {
      const has = manifest.sandbox === undefined ? 'declares no sandbox' : 'is sandboxed in the hostile domain'
      return (
        `${who}, but it ${has}. Egress reaches only a run sandboxed in the trusted domain; the hostile domain ` +
        'gets no channel and no egress. Set sandbox.domain: trusted, or drop egress.'
      )
    }
    // Written to fail closed: `tier < 2` is false for NaN, and a tier that
    // is no number compares false whichever way the test is written.
    if (!(manifest.tier >= EGRESS_MIN_TIER)) {
      return (
        `${who} at tier ${String(manifest.tier)}, but egress needs tier ${String(EGRESS_MIN_TIER)} or more, the first ` +
        'that runs sandboxed in the trusted domain. Raise the tier deliberately or drop egress.'
      )
    }

    for (const [i, id] of bind.entries()) {
      // As for an allow host below, and before the id is named: an id in a
      // credential's shape is no binding (kernel.yaml refuses one), and the
      // refusal must not repeat it.
      if (redactString(id) !== id) {
        return (
          `egress.bind[${String(i)}] is in the shape of a credential, so it names no binding: kernel.yaml refuses ` +
          'such an id. Name a binding the operator configured'
        )
      }
      if (!this.#bindingHosts.has(id)) {
        return `egress.bind names ${id}, which is no binding in kernel.yaml's egress.bindings. A manifest binds only a credential the operator configured.`
      }
    }
    for (const [i, host] of allow.entries()) {
      // Before the host is named: a refusal must not echo text in a credential's shape.
      if (redactString(host) !== host) {
        return (
          `egress.allow[${String(i)}] is a host in the shape of a credential, so the event log would store it censored, ` +
          'a grant row naming nothing it could read back: rename it'
        )
      }
      const owners = this.#boundHosts.get(host)
      if (owners !== undefined) {
        return (
          `egress.allow lists ${host}, the host of binding${owners.length === 1 ? '' : 's'} ${owners.join(', ')} in kernel.yaml. A bound host is reached ` +
          "only through a binding's profiles on its repositories, never credential-free: drop it from allow, and bind it if the agent needs it."
        )
      }
    }
    return undefined
  }

  #register(record: AgentRecord): void {
    // Frozen to the last list: a record handed to a run must not be editable by it.
    this.#agents.set(record.manifest.id, freezeRecord(record))
    this.#deps.store.append({
      type: 'agent.registered',
      agentId: record.manifest.id,
      payload: {
        schemaVersion: 1,
        agentId: record.manifest.id,
        version: record.manifest.version,
        kind: record.manifest.kind,
        role: record.manifest.role,
        tier: record.manifest.tier,
      },
    })
  }

  get(agentId: string): AgentRecord | undefined {
    return this.#agents.get(agentId)
  }

  list(): readonly AgentRecord[] {
    return [...this.#agents.values()]
  }

  /**
   * Spawn an ephemeral child from a template. Every requested capability is
   * clamped to the template's: the child can be narrower, never wider.
   *
   * @throws {ConfigError} and logs agent.spawn.rejected when it would widen.
   */
  spawnEphemeral(input: {
    templateId: string
    childId: string
    parentRunId?: string
    tier?: number
    egressAllow?: readonly string[]
    egressBind?: readonly string[]
    toolsAllow?: readonly string[]
  }): AgentRecord {
    // Before any other check: every later one compares the tier, and a
    // comparison with NaN, or with a value that is no number, is false
    // whichever way it is written, so `tier > t.tier` alone would admit it.
    if (input.tier !== undefined && !Tier.safeParse(input.tier).success) {
      const given = typeof input.tier === 'number' ? String(input.tier) : `of type ${typeof input.tier}`
      return this.#rejectSpawn(input.templateId, `requested tier ${given} is not a tier: an integer from 0 to 3`)
    }

    const template = this.#agents.get(input.templateId)
    if (template === undefined || template.manifest.kind !== 'template') {
      return this.#rejectSpawn(input.templateId, `no template named ${input.templateId}`)
    }
    // An archived template is retired, with whatever it held (a binding's
    // credential among it): no child inherits from it. Its id is a loaded
    // manifest's, so naming it repeats nothing a caller wrote.
    if (template.status !== 'active') {
      return this.#rejectSpawn(input.templateId, `template ${input.templateId} is archived: an archived template is no spawn source`)
    }

    const t = template.manifest
    const tier = input.tier ?? t.tier
    if (tier > t.tier) {
      return this.#rejectSpawn(
        input.templateId,
        `requested tier ${String(tier)} exceeds template tier ${String(t.tier)}`,
      )
    }

    const egress: readonly string[] = input.egressAllow ?? t.egress.allow
    // Before any requested entry is named, here and for bind below: the
    // request is the caller's text, never shape-checked until now.
    const unnamedHost = unnameable(egress, isSpelledHost)
    if (unnamedHost !== -1) {
      return this.#rejectSpawn(
        input.templateId,
        `egress.allow[${String(unnamedHost)}] of the request is no egress host in its one spelling, or is in the ` +
          "shape of a credential, so it is in no template's allow list, and it is not repeated here",
      )
    }
    const outsideEgress = egress.filter((host) => !t.egress.allow.some((allowed) => allowed === host))
    if (outsideEgress.length > 0) {
      return this.#rejectSpawn(
        input.templateId,
        `egress ${outsideEgress.join(', ')} is not in the template's allow list`,
      )
    }

    const bind = input.egressBind ?? t.egress.bind
    const unnamedBind = unnameable(bind, (id) => BINDING_ID.test(id))
    if (unnamedBind !== -1) {
      return this.#rejectSpawn(
        input.templateId,
        `egress.bind[${String(unnamedBind)}] of the request is no binding id, or is in the shape of a credential, ` +
          "so it is in no template's bind list, and it is not repeated here",
      )
    }
    const outsideBind = bind.filter((id) => !t.egress.bind.includes(id))
    if (outsideBind.length > 0) {
      return this.#rejectSpawn(
        input.templateId,
        `egress.bind ${outsideBind.join(', ')} is not in the template's bind list`,
      )
    }

    const tools = input.toolsAllow ?? t.tools.allow
    const outsideTools = tools.filter((ref) => !t.tools.allow.includes(ref))
    if (outsideTools.length > 0) {
      return this.#rejectSpawn(
        input.templateId,
        `tools ${outsideTools.join(', ')} are not in the template's allow list`,
      )
    }

    if (this.#agents.has(input.childId)) {
      return this.#rejectSpawn(input.templateId, `agent id ${input.childId} already exists`)
    }

    const manifest: AgentManifest = {
      ...t,
      id: input.childId,
      kind: 'ephemeral',
      tier,
      // Every egress field by name, each the template's own entries that the
      // request kept: a field this literal did not name would be dropped from
      // the child (or, spread from the template, inherited unclamped), and an
      // entry is the template's text, never the request's.
      egress: {
        allow: t.egress.allow.filter((host) => egress.includes(host)),
        bind: t.egress.bind.filter((id) => bind.includes(id)),
      },
      tools: { servers: [...t.tools.servers], allow: [...tools] },
      // An ephemeral agent may not spawn: maxDepth is 1 by construction.
      ...(t.spawn === undefined ? {} : { spawn: { templates: [], maxChildren: 0, maxDepth: 1 } }),
    }

    // The template passed these at load; a child that lowered its tier below
    // egress's while keeping the template's hosts, below a sandbox tool's while
    // keeping the template's, or below a tool's risk while keeping the
    // template's tools, would not.
    const egressProblem = this.#egressProblem(manifest)
    if (egressProblem !== undefined) return this.#rejectSpawn(input.templateId, egressProblem)
    const sandboxProblem = this.#sandboxToolProblem(manifest)
    if (sandboxProblem !== undefined) return this.#rejectSpawn(input.templateId, sandboxProblem)
    const toolProblem = this.#tierToolProblem(manifest)
    if (toolProblem !== undefined) return this.#rejectSpawn(input.templateId, toolProblem)

    const record: AgentRecord = { manifest, status: 'active', dir: template.dir }
    // Logged, then registered: an append that throws (a closed store, a row
    // its schema refuses) leaves no agent holding reach the log never saw.
    this.#deps.store.append({
      type: 'agent.spawned',
      agentId: input.childId,
      payload: {
        schemaVersion: 1,
        agentId: input.childId,
        templateId: input.templateId,
        tier,
        ...(input.parentRunId === undefined ? {} : { parentRunId: input.parentRunId }),
      },
    })
    this.#agents.set(input.childId, freezeRecord(record))
    return record
  }

  #rejectSpawn(templateId: string, reason: string): never {
    this.#deps.store.append({
      type: 'agent.spawn.rejected',
      payload: { schemaVersion: 1, templateId, reason },
    })
    throw new ConfigError(`spawn rejected: ${reason}`)
  }

  /**
   * File a promotion request. Changes nothing: the CEO may ask, and only a
   * human may act.
   */
  requestPromotion(agentId: string, requestedByRunId: string, rationale: string): void {
    const record = this.#agents.get(agentId)
    if (record === undefined) throw new ConfigError(`unknown agent ${agentId}`)
    this.#deps.store.append({
      type: 'agent.promotion.requested',
      agentId,
      payload: { schemaVersion: 1, agentId, requestedByRunId, rationale },
    })
  }

  /** Promote an ephemeral agent to standard. Human only. */
  promote(agentId: string, actor: HumanActor): AgentRecord {
    assertHumanActor(actor, 'promoting an agent')
    const record = this.#agents.get(agentId)
    if (record === undefined) throw new ConfigError(`unknown agent ${agentId}`)

    const promoted: AgentRecord = {
      ...record,
      manifest: { ...record.manifest, kind: 'standard', version: record.manifest.version + 1 },
    }
    this.#agents.set(agentId, freezeRecord(promoted))
    this.#deps.store.append({
      type: 'agent.promoted',
      agentId,
      payload: {
        schemaVersion: 1,
        agentId,
        fromVersion: record.manifest.version,
        toVersion: promoted.manifest.version,
        byConnectionId: actor.connectionId,
      },
    })
    return promoted
  }

  /** Archive an agent. Human only, and nothing is deleted from disk. */
  archive(agentId: string, actor: HumanActor): AgentRecord {
    assertHumanActor(actor, 'archiving an agent')
    const record = this.#agents.get(agentId)
    if (record === undefined) throw new ConfigError(`unknown agent ${agentId}`)

    const archived: AgentRecord = { ...record, status: 'archived' }
    this.#agents.set(agentId, freezeRecord(archived))
    this.#deps.store.append({
      type: 'agent.archived',
      agentId,
      payload: {
        schemaVersion: 1,
        agentId,
        version: record.manifest.version,
        byConnectionId: actor.connectionId,
      },
    })
    return archived
  }
}
