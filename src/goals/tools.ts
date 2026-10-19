// Checking the configured pmmcp goal tools against the connected server.
//
// The goal tool names and arguments in config/kernel.yaml match the operator's
// live capture of 2026-10-18, and src/goals/pmmcp.ts types every call. A
// capture is still a past fact, so the kernel does not assume: at boot it asks
// the hub what the connected server declares and compares the names, the
// arguments the server requires, and the type of every value the kernel sends.
//
// The result is a DEGRADATION, not a refusal. A kernel that will not start
// because one tool is named differently takes away the control plane the operator
// would read the reason on, which is the same argument the secrets broker's
// schema check settled. Goal writing is disabled while the subsystem is degraded,
// so nothing guesses at a call the server would reject.
//
// The reason string is the whole product of this file. "goals degraded" is
// useless; "pmmcp declares no tool `create_goal` (it has: …)" is one line of YAML
// away from fixed.

import { recordable } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import { log } from '../log.js'
import type { McpHub } from '../mcp/hub.js'
import { GOAL_TYPES, inputShape, SENDABLE_STATUSES } from '../mcp/pmmcp-schemas.js'
import type { KernelConfig } from '../config.js'
import type { GoalWriter } from './writer.js'

export type GoalsConfig = KernelConfig['goals']

/** The arguments the kernel will actually send, per configured tool. */
export function requiredArgs(goals: GoalsConfig): { tool: string; args: string[] }[] {
  const a = goals.args
  // pmmcp's update and tree tools take no project_id; the kernel's own
  // goal.created record is the namespace check for those (see writer.ts).
  return [
    { tool: goals.tools.create, args: [a.projectId, a.kind, a.title, a.parentId] },
    { tool: goals.tools.updateStatus, args: [a.goalId, a.status, a.progress] },
    { tool: goals.tools.get, args: [a.goalId] },
    { tool: goals.tools.list, args: [a.projectId] },
  ]
}

export interface SentArg {
  /** As kernel.yaml goals.args names it on the wire. */
  readonly name: string
  readonly type: 'string' | 'number'
  /** False for an argument some calls leave out (an objective's parent; progress outside review). */
  readonly always: boolean
  /** The values it can carry, where the kernel sends from a closed set. */
  readonly values?: readonly string[]
}

/** What src/goals/pmmcp.ts puts on the wire, per tool the kernel calls. */
export function sentArgs(goals: GoalsConfig): { tool: string; args: SentArg[] }[] {
  const a = goals.args
  const s = (name: string, always = true): SentArg => ({ name, type: 'string', always })
  const statuses = [...new Set(Object.values(goals.statuses))]
  return [
    {
      tool: goals.tools.create,
      args: [s(a.projectId), { ...s(a.kind), values: GOAL_TYPES }, s(a.title), s(a.parentId, false)],
    },
    {
      tool: goals.tools.updateStatus,
      args: [s(a.goalId), { ...s(a.status), values: statuses }, { name: a.progress, type: 'number', always: false }],
    },
    { tool: goals.tools.get, args: [s(a.goalId)] },
  ]
}

/** Room for every problem a real drift names; a reason past it is a server listing junk. */
export const GOALS_REASON_BYTES = 8_192

/** The JSON type the kernel's P6 result (GoalResult) reads for each field. */
const RESULT_TYPES: Readonly<Record<string, 'string' | 'number'>> = {
  goal_id: 'string',
  project_id: 'string',
  status: 'string',
  progress_pct: 'number',
}

/**
 * Why a create or update result the server declares is one the writer cannot
 * read. No schema (today's pmmcp) and FastMCP's `{result: string}` wrapper are
 * prose and serve. A P6 result must be GoalResult's four fields, all required,
 * of types that admit what the writer reads, with a status enum (if any) that
 * holds every status the kernel will see. Anything else would be refused per
 * call AFTER pmmcp had written the goal, one orphan per run; named here, it is
 * one degradation and no write.
 */
export function outputProblems(where: string, schema: unknown, statuses: readonly string[]): string[] {
  if (schema === undefined) return []
  let shape
  try {
    shape = inputShape(schema, { strict: false })
  } catch (e) {
    return [`${where} declares an outputSchema the kernel cannot read: ${e instanceof Error ? e.message : String(e)}`]
  }
  const names = Object.keys(shape.properties)
  if (names.length === 1 && names[0] === 'result' && (shape.properties['result']?.types ?? []).includes('string')) {
    // The SDK demands a required name the wrapper never sends.
    const unsent = shape.required.filter((n) => n !== 'result')
    return unsent.length === 0 ? [] : [`${where} requires ${unsent.join(', ')} beside FastMCP's {result}, which never sends them`]
  }
  if (!names.includes('goal_id')) {
    return [`${where} returns ${names.join(', ') || 'nothing'}, which the kernel's P6 result does not read`]
  }
  const problems: string[] = []
  // Own keys only: `constructor` is not a field the kernel reads.
  const extra = names.filter((n) => !Object.hasOwn(RESULT_TYPES, n))
  if (extra.length > 0) problems.push(`${where} returns ${extra.join(', ')}, which the kernel's P6 result does not read`)
  // The SDK's validator demands every required name, declared or not; one the
  // kernel does not read is refused by the strict parse whenever it is sent.
  const demanded = shape.required.filter((n) => !Object.hasOwn(RESULT_TYPES, n) && !names.includes(n))
  if (demanded.length > 0) problems.push(`${where} requires ${demanded.join(', ')}, which the kernel's P6 result does not read`)
  for (const [name, type] of Object.entries(RESULT_TYPES)) {
    const live = shape.properties[name]
    if (live === undefined) {
      problems.push(`${where} does not return ${name}`)
      continue
    }
    if (!shape.required.includes(name)) problems.push(`${where} may leave out ${name}, which the kernel requires`)
    const admitted = live.types.length === 0 || live.types.includes(type) || (type === 'number' && live.types.includes('integer'))
    if (!admitted) problems.push(`${where} returns ${name} as ${live.types.join('|')}, not ${type}`)
  }
  const allowed = shape.properties['status']?.enum
  if (allowed !== undefined) {
    const missing = [...new Set(statuses)].filter((s) => !allowed.includes(s))
    if (missing.length > 0) problems.push(`${where} returns status from ${allowed.map(String).join(', ')}, which leaves out ${missing.join(', ')}`)
  }
  return problems
}

/** The property names a described tool declares, or undefined when it declares none. */
function declaredArgs(schema: Record<string, unknown> | undefined): string[] | undefined {
  const properties = schema?.['properties']
  if (typeof properties !== 'object' || properties === null) return undefined
  return Object.keys(properties as Record<string, unknown>).sort()
}

/**
 * Why the goals subsystem cannot serve, or undefined when it can.
 *
 * Every disagreement is collected into one reason rather than reporting the
 * first: an operator fixing four names one boot at a time is an operator who
 * restarts four times.
 */
export function goalToolsUnusable(
  hub: McpHub,
  goals: GoalsConfig,
  serverId = 'pmmcp',
): string | undefined {
  if (hub.status(serverId) !== 'connected') {
    return `${serverId} is not connected, so no goal tree can be written or read`
  }

  const problems: string[] = []
  for (const { tool, args } of requiredArgs(goals)) {
    const described = hub.describe(serverId, tool)
    if (described === undefined) {
      problems.push(`${serverId} declares no tool "${tool}"`)
      continue
    }
    const declared = declaredArgs(described.inputSchema)
    if (declared === undefined) {
      problems.push(`${serverId}.${tool} declares no inputSchema.properties`)
      continue
    }
    const missing = args.filter((arg) => !declared.includes(arg))
    if (missing.length > 0) {
      problems.push(
        `${serverId}.${tool} does not accept ${missing.join(', ')} (it declares ${declared.join(', ')})`,
      )
    }
  }

  // Past the names: what the server requires and what it accepts. A tool or
  // argument that is missing is already a problem above.
  for (const { tool, args } of sentArgs(goals)) {
    const described = hub.describe(serverId, tool)
    if (described === undefined) continue
    let shape
    try {
      shape = inputShape(described.inputSchema, { strict: false })
    } catch (e) {
      problems.push(`${serverId}.${tool} declares an inputSchema the kernel cannot read: ${e instanceof Error ? e.message : String(e)}`)
      continue
    }
    // Two goals.args entries naming one key: the later value would silently
    // replace the earlier on the wire.
    const names = args.map((arg) => arg.name)
    const doubled = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))]
    if (doubled.length > 0) {
      problems.push(`kernel.yaml goals.args gives ${doubled.join(', ')} to two arguments of ${serverId}.${tool}`)
    }
    const always = new Set(args.filter((arg) => arg.always).map((arg) => arg.name))
    for (const name of shape.required) {
      if (!always.has(name)) problems.push(`${serverId}.${tool} requires ${name}, which the kernel does not send on every call`)
    }
    for (const arg of args) {
      const live = shape.properties[arg.name]
      if (live === undefined || live.types.length === 0) continue
      const admitted = live.types.includes(arg.type) || (arg.type === 'number' && live.types.includes('integer'))
      if (!admitted) problems.push(`${serverId}.${tool}.${arg.name} is ${live.types.join('|')}, but the kernel sends a ${arg.type}`)
      const outside = (arg.values ?? []).filter((v) => live.enum !== undefined && !live.enum.includes(v))
      if (outside.length > 0) {
        problems.push(`${serverId}.${tool}.${arg.name} accepts only ${(live.enum ?? []).map(String).join(', ')}, not ${outside.join(', ')}`)
      }
    }
  }

  // What comes back: a create is `pending`, a move is whatever was sent.
  const sentStatuses = Object.values(goals.statuses)
  for (const [tool, statuses] of [
    [goals.tools.create, ['pending']],
    [goals.tools.updateStatus, sentStatuses],
  ] as const) {
    problems.push(...outputProblems(`${serverId}.${tool}`, hub.describe(serverId, tool)?.outputSchema, statuses))
  }

  // Not the server's to judge: a status the kernel may never send. The typed
  // update refuses it per call; here it is named once, at boot, instead of as
  // a stale goal per run.
  for (const [status, sent] of Object.entries(goals.statuses)) {
    if (!(SENDABLE_STATUSES as readonly string[]).includes(sent)) {
      // An allowlist in code, on purpose: what the kernel may send is not config,
      // so a pmmcp that renamed these would need SENDABLE_STATUSES changed.
      problems.push(
        `kernel.yaml goals.statuses.${status} is "${sent}"; the kernel sends only ${SENDABLE_STATUSES.join(', ')} ` +
          '(src/mcp/pmmcp-schemas.ts SENDABLE_STATUSES)',
      )
    }
  }

  if (problems.length === 0) return undefined
  // The problems quote the server (property names, enum values), so they are
  // bounded and made well-formed here, once, for every place the reason goes:
  // the goals.degraded row at boot and on reconnect, the log line, the refusal.
  return `${recordable(problems.join('; '), GOALS_REASON_BYTES)}. Set goals.tools / goals.args in kernel.yaml, or run \`npm run capture:pmmcp\` to read the live schemas.`
}

/**
 * Re-run the check each time the hub re-lists the server's tools.
 *
 * Boot checks once, but pmmcp can be redeployed under a running kernel, and the
 * hub's heartbeat then reconnects and re-lists it. A drift found then degrades
 * the writer and is recorded, like a boot drift. It never restores the writer:
 * there is no event that says goals came back, so a restart is what does that.
 *
 * Deferred a microtask: the hub records the listing before it installs the new
 * tool descriptions, in the same synchronous run. That also takes the work out
 * of the store's listener guard, where nothing would catch a throw and the
 * daemon would end, so the body catches its own. It fails closed: a re-check
 * that cannot finish degrades the writer too.
 */
export function watchGoalTools(options: {
  readonly store: EventStore
  readonly hub: McpHub
  readonly goals: GoalsConfig
  readonly writer: GoalWriter
  readonly serverId?: string
}): () => void {
  const serverId = options.serverId ?? 'pmmcp'
  return options.store.subscribe((row) => {
    if (row.type !== 'hub.tools.classified') return
    const payload = JSON.parse(row.payload) as { server?: unknown }
    if (payload.server !== serverId) return
    queueMicrotask(() => {
      if (!options.writer.available) return
      try {
        const reason = goalToolsUnusable(options.hub, options.goals, serverId)
        if (reason === undefined) return
        // Degraded before the append, so a failed append cannot leave it writing.
        options.writer.degrade(reason)
        options.store.append({ type: 'goals.degraded', payload: { schemaVersion: 1, reason } })
        log.warn({ reason }, 'the reconnected pmmcp no longer serves the goal tools; no goal tree can be written or read')
      } catch (e) {
        const err = e instanceof Error ? e.message : String(e)
        options.writer.degrade(recordable(`the re-check after ${serverId} reconnected failed: ${err}`, GOALS_REASON_BYTES))
        log.error({ err }, 'the goal tools could not be re-checked after a reconnect; goal writing is off until a restart')
      }
    })
  })
}
