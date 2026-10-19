// Typed calls to pmmcp's goal tools.
//
// Every call is parsed against its SENT schema (src/mcp/pmmcp-schemas.ts)
// before it reaches the hub. An argument the kernel never meant to send, a
// status that is a decision, a kind pmmcp does not have, or a missing
// project_id is refused here, as GoalWriteFailed, and never becomes a call.
// pmmcp would accept most of those: its schema types goal_type and status as
// plain strings, and FastMCP drops an argument it does not declare without a
// word.
//
// The schemas speak pmmcp's live argument names. kernel.yaml `goals.tools` and
// `goals.args` still name the tool and the keys on the wire (identical to the
// live names as shipped), and the boot check in tools.ts holds those names and
// their types to the server actually connected.

import { z } from 'zod'

import type { KernelOnlyResult, McpHub } from '../mcp/hub.js'
import {
  CreateGoalSent,
  GetGoalTreeSent,
  UpdateGoalSent,
  type CreateGoalArgs,
  type GetGoalTreeArgs,
  type UpdateGoalArgs,
} from '../mcp/pmmcp-schemas.js'
import { GoalWriteFailed } from './errors.js'
import type { GoalsConfig } from './tools.js'

/** Each live argument the kernel sends, and the goals.args entry naming it on the wire. */
export const WIRE_ARG = {
  project_id: 'projectId',
  goal_type: 'kind',
  title: 'title',
  parent_goal_id: 'parentId',
  goal_id: 'goalId',
  status: 'status',
  progress_pct: 'progress',
} as const satisfies Record<string, keyof GoalsConfig['args']>

export interface GoalCall {
  readonly hub: McpHub
  readonly goals: GoalsConfig
  readonly serverId: string
}

/** The hub's own result type, so the two cannot drift apart. */
export type GoalCallResult = KernelOnlyResult

/** The status arrives from kernel.yaml goals.statuses as any string; the schema decides. */
export type UpdateGoalRequest = Omit<UpdateGoalArgs, 'status'> & { readonly status: string }

function sendable<T extends Record<string, unknown>>(schema: z.ZodType<T>, tool: string, args: unknown): T {
  const parsed = schema.safeParse(args)
  if (!parsed.success) {
    throw new GoalWriteFailed(`${tool} refused before the wire: ${z.prettifyError(parsed.error)}`, [])
  }
  return parsed.data
}

function onWire(goals: GoalsConfig, args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [live, value] of Object.entries(args)) {
    // Only names WIRE_ARG holds can get here: the strict schemas refuse the rest.
    const key = goals.args[WIRE_ARG[live as keyof typeof WIRE_ARG]]
    if (key in out) throw new GoalWriteFailed(`kernel.yaml goals.args names ${key} for two arguments`, [])
    out[key] = value
  }
  return out
}

async function send(
  c: GoalCall,
  tool: string,
  schema: z.ZodType<Record<string, unknown>>,
  args: unknown,
  purpose: string,
): Promise<GoalCallResult> {
  const checked = sendable(schema, `${c.serverId}.${tool}`, args)
  return c.hub.callKernelOnly(c.serverId, tool, onWire(c.goals, checked), purpose)
}

/** @throws {GoalWriteFailed} before any call, when `args` is not sendable. */
export function createGoal(c: GoalCall, args: CreateGoalArgs, purpose: string): Promise<GoalCallResult> {
  return send(c, c.goals.tools.create, CreateGoalSent, args, purpose)
}

/** @throws {GoalWriteFailed} before any call, when `args` is not sendable. */
export function updateGoal(c: GoalCall, args: UpdateGoalRequest, purpose: string): Promise<GoalCallResult> {
  return send(c, c.goals.tools.updateStatus, UpdateGoalSent, args, purpose)
}

/** @throws {GoalWriteFailed} before any call, when `args` is not sendable. */
export function getGoalTree(c: GoalCall, args: GetGoalTreeArgs, purpose: string): Promise<GoalCallResult> {
  return send(c, c.goals.tools.get, GetGoalTreeSent, args, purpose)
}
