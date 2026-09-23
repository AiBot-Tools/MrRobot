// Agent registry (invariant 6).
//
// Loads manifests, validates them against the rest of the configuration, and
// owns the three lifecycle actions that change what an agent may do.
//
// The division of authority is the point:
//
//   spawnEphemeral   the CEO may do this, and the child is CLAMPED to the
//                    template — never above its tier, never a host the
//                    template does not list, never a tool it does not have.
//   requestPromotion the CEO may only ASK. It files an approval and changes
//                    nothing, so a model cannot argue its way to more reach.
//   promote/archive  a human only, proved by the HumanActor brand.
//
// Archive never deletes. Files stay on disk and history is kept, because an
// audit of what an agent did needs the manifest it did it under.
//
// Cross-file checks happen at load, not at first use. A model reference with
// no provider entry, or a tool the views make kernel-only, is a configuration
// error someone should see while reading config — not a mid-run failure.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { assertHumanActor, type HumanActor } from '../control/actor.js'
import { ConfigError } from '../errors.js'
import type { EventStore } from '../events/store.js'
import { resolveView, type ToolViewsFile } from '../mcp/tool-views.js'
import { parseManifest, type AgentManifest } from './manifest.js'

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
}

export class AgentRegistry {
  readonly #agents = new Map<string, AgentRecord>()
  readonly #deps: RegistryDeps

  constructor(deps: RegistryDeps) {
    this.#deps = deps
  }

  /** Load every agents/<id>/agent.yaml under `agentsDir`. */
  load(agentsDir: string): void {
    for (const entry of readdirSync(agentsDir)) {
      const dir = join(agentsDir, entry)
      if (!statSync(dir).isDirectory()) continue
      const file = join(dir, 'agent.yaml')
      const manifest = parseManifest(parseYaml(readFileSync(file, 'utf8')), file)
      this.#validate(manifest, file)

      if (this.#agents.has(manifest.id)) {
        throw new ConfigError(`duplicate agent id ${manifest.id} (second copy at ${file})`)
      }
      if (manifest.id !== entry) {
        throw new ConfigError(`${file}: id "${manifest.id}" does not match its directory "${entry}"`)
      }

      this.#register({ manifest, status: 'active', dir })
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
    }

    if (manifest.tier === 0 && manifest.tools.allow.length > 0) {
      throw new ConfigError(`${source}: tier 0 means no tools, but tools.allow is not empty`)
    }
  }

  #register(record: AgentRecord): void {
    // Frozen: a record handed to a run must not be editable by it.
    this.#agents.set(record.manifest.id, Object.freeze(record))
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
    toolsAllow?: readonly string[]
  }): AgentRecord {
    const template = this.#agents.get(input.templateId)
    if (template === undefined || template.manifest.kind !== 'template') {
      return this.#rejectSpawn(input.templateId, `no template named ${input.templateId}`)
    }

    const t = template.manifest
    const tier = input.tier ?? t.tier
    if (tier > t.tier) {
      return this.#rejectSpawn(
        input.templateId,
        `requested tier ${String(tier)} exceeds template tier ${String(t.tier)}`,
      )
    }

    const egress = input.egressAllow ?? t.egress.allow
    const outsideEgress = egress.filter((host) => !t.egress.allow.includes(host))
    if (outsideEgress.length > 0) {
      return this.#rejectSpawn(
        input.templateId,
        `egress ${outsideEgress.join(', ')} is not in the template's allow list`,
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
      egress: { allow: [...egress] },
      tools: { servers: [...t.tools.servers], allow: [...tools] },
      // An ephemeral agent may not spawn: maxDepth is 1 by construction.
      ...(t.spawn === undefined ? {} : { spawn: { templates: [], maxChildren: 0, maxDepth: 1 } }),
    }

    const record: AgentRecord = { manifest, status: 'active', dir: template.dir }
    this.#agents.set(input.childId, Object.freeze(record))
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
    this.#agents.set(agentId, Object.freeze(promoted))
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
    this.#agents.set(agentId, Object.freeze(archived))
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
