// Checking the configured pmmcp goal tools against the connected server.
//
// The goal tool names and arguments in config/kernel.yaml are read from pmmcp's
// source, not yet from its live `listTools`. The kernel therefore does not
// assume: at boot it asks the hub what the server declares and compares.
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

  if (problems.length === 0) return undefined
  return `${problems.join('; ')}. Set goals.tools / goals.args in kernel.yaml, or run \`npm run capture:pmmcp\` to read the live schemas.`
}
