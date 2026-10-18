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

import type { McpHub } from '../mcp/hub.js'
import { inputShape, SENDABLE_STATUSES } from '../mcp/pmmcp-schemas.js'
import type { KernelConfig } from '../config.js'

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
}

/** What src/goals/pmmcp.ts puts on the wire, per tool the kernel calls. */
export function sentArgs(goals: GoalsConfig): { tool: string; args: SentArg[] }[] {
  const a = goals.args
  const s = (name: string, always = true): SentArg => ({ name, type: 'string', always })
  return [
    { tool: goals.tools.create, args: [s(a.projectId), s(a.kind), s(a.title), s(a.parentId, false)] },
    { tool: goals.tools.updateStatus, args: [s(a.goalId), s(a.status), { name: a.progress, type: 'number', always: false }] },
    { tool: goals.tools.get, args: [s(a.goalId)] },
  ]
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
    const always = new Set(args.filter((arg) => arg.always).map((arg) => arg.name))
    for (const name of shape.required) {
      if (!always.has(name)) problems.push(`${serverId}.${tool} requires ${name}, which the kernel does not send on every call`)
    }
    for (const arg of args) {
      const types = shape.properties[arg.name]?.types
      if (types === undefined || types.length === 0) continue
      const admitted = types.includes(arg.type) || (arg.type === 'number' && types.includes('integer'))
      if (!admitted) problems.push(`${serverId}.${tool}.${arg.name} is ${types.join('|')}, but the kernel sends a ${arg.type}`)
    }
  }

  // Not the server's to judge: a status the kernel may never send. The typed
  // update refuses it per call; here it is named once, at boot, instead of as
  // a stale goal per run.
  for (const [status, sent] of Object.entries(goals.statuses)) {
    if (!(SENDABLE_STATUSES as readonly string[]).includes(sent)) {
      problems.push(`kernel.yaml goals.statuses.${status} is "${sent}"; the kernel sends only ${SENDABLE_STATUSES.join(', ')}`)
    }
  }

  if (problems.length === 0) return undefined
  return `${problems.join('; ')}. Set goals.tools / goals.args / goals.statuses in kernel.yaml, or run \`npm run capture:pmmcp\` to read the live schemas.`
}
