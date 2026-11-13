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
// used only to REFUSE (protected paths, and a runner's own refusal of them,
// which the kernel works out from them before the gate), never to permit. So
// is the runner's refusal itself, whatever it is of (runnerRefusal).
//
// Rule order, first match wins. It runs from structural facts to contextual
// ones so the reported reason is the most fundamental true thing:
//
//   1. exposure is not 'agent'           deny      the tool is not for agents
//   2. not in the agent's manifest       deny      default deny
//   3. an argument points at souls or
//      an AGENTS.md                      deny      invariant 8, read-only personas
//   3b. the tool's namespace argument
//      is not the agent's own namespace  deny      memory is per agent
//   3c. the tool's runner refuses the
//      call whoever approves it (its     deny      no human is asked to
//      caller, the kernel's config or              approve what never runs
//      its arguments)
//   4. risk is 'irreversible'            needs-human   always, no exceptions
//   5. tainted run, risk is not 'read'   needs-human   invariant 3
//   6. the tool-view says quarantine     quarantine
//   7. otherwise                         allow
//
// Rules 4 and 5 are needs-human rather than deny: the operator can say yes.
// Rules 1 to 3c are deny, because no human approval makes them safe, or, for
// 3c, makes them run.

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
    /** From tool-views.yaml: the argument to pin, or 'none'. Absent: not namespaced. */
    namespaceArg: z.string().min(1).optional(),
  })
  .strict()

/** The run's own scope facts. Not supplied by the model. */
const ScopeInput = z
  .object({
    runId: z.string().min(1),
    agentId: z.string().min(1),
    taint: z.enum(['clean', 'tainted']),
    /** The agent's `memory.projectId`, from its manifest. Never from the model. */
    projectId: z.string().min(1).optional(),
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
    /**
     * Why the tool's own runner refuses this call whatever a human says,
     * worked out by the kernel before the gate (sandbox tools', in the run
     * loop's #handleToolCall, from #sandboxHolderProblem,
     * SandboxTools.configRefusal, domainRefusal, egressRefusal and
     * argsRefusal): its caller,
     * an agent whose manifest, read from the registry, may not hold the tool
     * (SandboxTools.holderProblem), or a kernel with no runner for it; the
     * kernel's own sandbox config, whose driver runs nothing or which pins
     * no image id to run (SandboxTools.configRefusal); its manifest's
     * domain, closed at boot by a canary that showed a route out
     * (SandboxTools.domainRefusal); the egress its grant would need
     * (SandboxTools.egressRefusal); or its arguments, a
     * command the approval preview would cut, redact or show unreadably, one
     * past the runner's bounds, or one the driver's audit refuses
     * (SandboxTools.argsRefusal).
     * Absent: the runner refuses nothing it can tell before it runs, or the
     * kernel does not ask. Used only to refuse, as the arguments are.
     */
    runnerRefusal: z.string().min(1).optional(),
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
  const { view, scope, manifestAllows, toolRef, args, runnerRefusal } = parsed

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

  // Memory is per agent. The model chooses this argument, so it is used here
  // the only way the gate uses arguments: to refuse. Absent is refused too — a
  // tool that defaulted to some namespace server-side would otherwise be a way
  // around the pin. Deny rather than needs-human, for the same reason as rule 3:
  // widening an agent's memory is a manifest change, not a per-call approval.
  const pinned = view.namespaceArg
  if (pinned !== undefined && pinned !== 'none') {
    const asked = args[pinned]
    if (scope.projectId === undefined) {
      return {
        decision: 'deny',
        reason: `${toolRef} reads a memory namespace and agent ${scope.agentId} has none`,
      }
    }
    if (asked !== scope.projectId) {
      return {
        decision: 'deny',
        reason:
          `namespace: ${toolRef} may only address ${scope.projectId}, ` +
          `not ${typeof asked === 'string' ? asked : 'an unnamed namespace'}`,
      }
    }
  }

  // Deny, before any rule that would ask a human: the runner refuses this
  // call however it is decided, so asking would only have a human approve a
  // command that never runs, or one they were never shown whole.
  if (runnerRefusal !== undefined) {
    return { decision: 'deny', reason: runnerRefusal }
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
