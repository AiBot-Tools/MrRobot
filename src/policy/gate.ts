// The policy gate (invariant 3).
//
// One pure function turns a proposed tool call into a decision. It is pure on
// purpose: the same input always yields the same decision, so a gate ruling
// can be replayed from the event log and checked, and nothing about when or
// how often it ran can change the answer.
//
// THE MODEL NEVER DECIDES. Every field of GateInput comes from config, the
// manifest, or the run's own scope — never from model output, and never from
// tool arguments. The schema is strict so a caller cannot smuggle in an extra
// field like `modelDecision` or `allow` and have some future branch read it.
// Arguments are the one piece of model-influenced data here, and they are
// used only to REFUSE (protected paths), never to permit.
//
// Rule order, first match wins. It runs from structural facts to contextual
// ones so the reported reason is the most fundamental true thing:
//
//   1. exposure is not 'agent'           deny      the tool is not for agents
//   2. not in the agent's manifest       deny      default deny
//   3. an argument points at souls or
//      an AGENTS.md                      deny      invariant 8, read-only personas
//   4. risk is 'irreversible'            needs-human   always, no exceptions
//   5. tainted run, risk is not 'read'   needs-human   invariant 3
//   6. the tool-view says quarantine     quarantine
//   7. otherwise                         allow
//
// Rules 4 and 5 are needs-human rather than deny: the operator can say yes.
// Rules 1 to 3 are deny, because no human approval makes them safe.

import { z } from 'zod'

import { EXPOSURES, RISKS } from '../mcp/tool-views.js'

export const GateDecisions = ['allow', 'needs-human', 'quarantine', 'deny'] as const
export type GateDecision = (typeof GateDecisions)[number]

/** The resolved tool-view for the tool being called. */
const ViewInput = z
  .object({
    exposure: z.enum(EXPOSURES),
    risk: z.enum(RISKS),
    taints: z.boolean(),
    quarantine: z.boolean(),
  })
  .strict()

/** The run's own scope facts. Not supplied by the model. */
const ScopeInput = z
  .object({
    runId: z.string().min(1),
    agentId: z.string().min(1),
    taint: z.enum(['clean', 'tainted']),
  })
  .strict()

export const GateInput = z
  .object({
    view: ViewInput,
    scope: ScopeInput,
    /** Whether this agent's manifest lists this toolRef. Resolved by the kernel. */
    manifestAllows: z.boolean(),
    toolRef: z.string().min(1),
    /** Model-influenced. Used only to refuse, never to permit. */
    args: z.record(z.string(), z.unknown()),
  })
  .strict()

export type GateInput = z.infer<typeof GateInput>

export interface GateVerdict {
  readonly decision: GateDecision
  readonly reason: string
}

/** Paths that are read-only to every agent (invariant 8). */
export const PROTECTED_PATH = /(^|[\\/])(souls([\\/]|$)|AGENTS\.md$)/i

/** True when any string anywhere in the arguments points at a protected path. */
export function mentionsProtectedPath(value: unknown): boolean {
  if (typeof value === 'string') return PROTECTED_PATH.test(value)
  if (Array.isArray(value)) return value.some((item) => mentionsProtectedPath(item))
  if (value !== null && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).some((item) =>
      mentionsProtectedPath(item),
    )
  }
  return false
}

/**
 * Decide whether a tool call may proceed. Pure: no clock, no randomness, no
 * I/O, no state.
 */
export function decide(input: GateInput): GateVerdict {
  const parsed = GateInput.parse(input)
  const { view, scope, manifestAllows, toolRef, args } = parsed

  if (view.exposure !== 'agent') {
    return { decision: 'deny', reason: `${toolRef} is ${view.exposure}, not exposed to agents` }
  }

  if (!manifestAllows) {
    return {
      decision: 'deny',
      reason: `${toolRef} is not in agent ${scope.agentId}'s manifest (default deny)`,
    }
  }

  if (mentionsProtectedPath(args)) {
    return {
      decision: 'deny',
      reason: 'protected-path: souls and AGENTS.md are read-only to agents',
    }
  }

  if (view.risk === 'irreversible') {
    return { decision: 'needs-human', reason: `${toolRef} is irreversible and always needs a human` }
  }

  if (scope.taint === 'tainted' && view.risk !== 'read') {
    return {
      decision: 'needs-human',
      reason: `run ${scope.runId} is tainted and ${toolRef} is a ${view.risk} tool`,
    }
  }

  if (view.quarantine) {
    return { decision: 'quarantine', reason: `${toolRef} output is quarantined before use` }
  }

  return { decision: 'allow', reason: `${toolRef} is allowed for ${scope.agentId}` }
}
