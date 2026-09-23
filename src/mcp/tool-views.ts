// Tool-view policy (invariant 7).
//
// Decides, per MCP tool, whether an agent may see it at all. Three exposures:
//
//   disabled     nobody may call it, kernel included
//   kernel-only  the kernel may call it; it is never in an agent's tool array
//   agent        the agent may request it, subject to the gate
//
// The design rule is that the DEFAULT is the safe answer and the exception is
// what must be written down. A server's default is the literal 'kernel-only'
// — not a value an operator picks — so a tool nobody has classified is
// unreachable by agents rather than quietly available. New tools appear on
// upstream servers all the time; that is the case this protects against.
//
// Two sets are forced regardless of what the file says, because they are the
// ones where a single editing mistake is unrecoverable:
//
//   FORCED_KERNEL_ONLY  vault and admin tools, plus anything whose name
//                       contains "secret". Exposing one to an agent hands
//                       out credentials directly, defeating invariant 2.
//   FORCED_DISABLED     coding_agent and session_insight_agent. These make
//                       nested model calls inside another server, which would
//                       bypass the router, budgets, taint and the event log
//                       wholesale — an agent could spend money and act with
//                       nothing of it in the record.
//
// Forcing is not a warning and not a silent downgrade: a file that tries to
// widen either set is REFUSED at parse. Ask-before applies to any exposure
// change (CLAUDE.md change control), so the refusal is what makes that rule
// enforceable rather than advisory.

import { z } from 'zod'

import { ConfigError } from '../errors.js'
import { PROVIDER_TOOL_NAME, toolName } from './names.js'

export const EXPOSURES = ['disabled', 'kernel-only', 'agent'] as const
export const RISKS = ['read', 'write', 'irreversible'] as const

export type Exposure = (typeof EXPOSURES)[number]
export type Risk = (typeof RISKS)[number]

/** Always kernel-only, whatever a file says. */
export const FORCED_KERNEL_ONLY: readonly string[] = [
  'get_secret',
  'set_secret',
  'audit_secrets',
  'admin',
  'restore_backup',
  'delete_context_source',
  'index_project',
]

/** Always disabled: nested LLM calls that would bypass every kernel control. */
export const FORCED_DISABLED: readonly string[] = ['coding_agent', 'session_insight_agent']

/** Any tool whose name mentions a secret is treated as one. */
export const SECRETISH = /secret/i

/** MCP's own tool-name rule, which is wider than any provider's. */
const MCP_TOOL_NAME = /^[A-Za-z0-9._-]{1,128}$/

const ToolView = z
  .object({
    exposure: z.enum(EXPOSURES),
    risk: z.enum(RISKS).default('write'),
    taints: z.boolean().default(false),
    quarantine: z.boolean().default(false),
    note: z.string().optional(),
  })
  .strict()

const ServerViews = z
  .object({
    // Literal, not a choice. An operator cannot make a server's unclassified
    // tools agent-visible by changing one line.
    default: z.literal('kernel-only'),
    tools: z.record(z.string().regex(MCP_TOOL_NAME), ToolView).default({}),
  })
  .strict()

export const ToolViewsFile = z
  .object({
    version: z.literal(1),
    servers: z.record(z.string().min(1), ServerViews).default({}),
  })
  .strict()
  .superRefine((file, ctx) => {
    for (const [serverId, server] of Object.entries(file.servers)) {
      for (const [toolName_, view] of Object.entries(server.tools)) {
        const at = ['servers', serverId, 'tools', toolName_]

        const mustBeKernelOnly =
          FORCED_KERNEL_ONLY.includes(toolName_) || SECRETISH.test(toolName_)
        if (mustBeKernelOnly && view.exposure !== 'kernel-only') {
          ctx.addIssue({
            code: 'custom',
            path: at,
            message:
              `${serverId}.${toolName_} must be kernel-only (it is a secret or admin tool), ` +
              `but the file says "${view.exposure}". Exposing it would hand an agent credentials.`,
          })
        }

        if (FORCED_DISABLED.includes(toolName_) && view.exposure !== 'disabled') {
          ctx.addIssue({
            code: 'custom',
            path: at,
            message:
              `${serverId}.${toolName_} must be disabled, but the file says "${view.exposure}". ` +
              'It makes nested model calls that bypass the router, budgets, taint and the log.',
          })
        }

        if (view.exposure === 'agent') {
          const mapped = toolName(`${serverId}.${toolName_}`)
          if (!PROVIDER_TOOL_NAME.test(mapped)) {
            ctx.addIssue({
              code: 'custom',
              path: at,
              message:
                `${serverId}.${toolName_} is exposed to agents but maps to "${mapped}", which ` +
                `fails the provider tool-name rule ${String(PROVIDER_TOOL_NAME)}.`,
            })
          }
        }
      }
    }
  })

export type ToolViewsFile = z.output<typeof ToolViewsFile>
export type ResolvedView = z.output<typeof ToolView>

/** The view every unclassified tool gets: reachable by the kernel, not by agents. */
export const DEFAULT_VIEW: ResolvedView = Object.freeze({
  exposure: 'kernel-only',
  risk: 'write',
  taints: false,
  quarantine: false,
})

export function parseToolViews(input: unknown): ToolViewsFile {
  const result = ToolViewsFile.safeParse(input)
  if (!result.success) {
    throw new ConfigError(`tool-views.yaml is invalid: ${result.error.message}`)
  }
  // Forced entries are injected when absent, so resolveView answers correctly
  // for a tool the file never mentions.
  for (const server of Object.values(result.data.servers)) {
    for (const name of FORCED_KERNEL_ONLY) {
      server.tools[name] ??= { ...DEFAULT_VIEW }
    }
    for (const name of FORCED_DISABLED) {
      server.tools[name] ??= { ...DEFAULT_VIEW, exposure: 'disabled' }
    }
  }
  return result.data
}

/** The view for one tool. Unknown server or tool resolves to kernel-only. */
export function resolveView(file: ToolViewsFile, serverId: string, tool: string): ResolvedView {
  // Forcing is applied here too, so a resolve cannot be wrong even if a file
  // reached this point by some path that skipped parseToolViews.
  if (FORCED_DISABLED.includes(tool)) return { ...DEFAULT_VIEW, exposure: 'disabled' }
  if (FORCED_KERNEL_ONLY.includes(tool) || SECRETISH.test(tool)) return { ...DEFAULT_VIEW }
  return file.servers[serverId]?.tools[tool] ?? { ...DEFAULT_VIEW }
}

export interface Classification {
  /** Tools the file describes, with their resolved views. */
  readonly classified: ReadonlyMap<string, ResolvedView>
  /** Listed tools the file says nothing about. They resolve to kernel-only. */
  readonly unclassified: readonly string[]
}

/**
 * Split a server's live tool list into what the file classifies and what it
 * does not. The unclassified list is what the kernel reports so a human can
 * decide; until then those tools stay kernel-only by default.
 */
export function classify(
  file: ToolViewsFile,
  serverId: string,
  listed: readonly string[],
): Classification {
  const classified = new Map<string, ResolvedView>()
  const unclassified: string[] = []
  const declared = file.servers[serverId]?.tools ?? {}

  for (const tool of listed) {
    const forced =
      FORCED_DISABLED.includes(tool) || FORCED_KERNEL_ONLY.includes(tool) || SECRETISH.test(tool)
    if (Object.prototype.hasOwnProperty.call(declared, tool) || forced) {
      classified.set(tool, resolveView(file, serverId, tool))
    } else {
      unclassified.push(tool)
    }
  }

  return { classified, unclassified }
}
