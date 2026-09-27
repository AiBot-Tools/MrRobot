// The run loop — where the gate, the router, the hub and the budget meet.
//
// One rule shapes everything: NOTHING EXECUTES BEFORE THE GATE. Every tool
// call the model proposes goes decision → (human) → execute → log, in that
// order, and the branches that do not execute still produce a result the
// model can read. A denied call that simply vanished would leave the model
// looping on a tool it will never be allowed to use, burning the budget it
// was given to do something else.
//
// What the model is told is exactly what the log stores (D18). The bounded,
// redacted text is computed once and used for both. Two truths here would be
// worse than either alone: an operator reading the log would be reading
// something the model never saw, and a redaction bug would be invisible on
// the side that matters.
//
// Taint is re-derived every turn rather than carried. A `taints: true` tool
// and a released quarantine hold (D17) both make a run tainted mid-flight,
// and from that point a write needs a human. Freezing taint at run start
// would make both of those silently ineffective.
//
// Delegation is offered to orchestrators only. The kernel-native tools
// (`kernel.adopt_plan`, `kernel.delegate`) join the tool array when the agent's
// role is `orchestrator` AND its manifest allows them; a worker is never offered
// one, and a worker that names one anyway is refused by the gate and the kernel
// runner. There is no branch here that creates a run: the delegate tool asks
// the kernel to launch one, under a ceiling carved from this run's budget.

import { canonicalize, sha256Hex } from '../events/canonical.js'
import { boundOutput, type BoundedOutput } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import { PolicyDenied } from '../errors.js'
import { decide, type GateDecision } from '../policy/gate.js'
import type { PolicyEngine } from '../policy/engine.js'
import type { Quarantine } from '../policy/quarantine.js'
import { resolveView, type ToolViewsFile } from '../mcp/tool-views.js'
import type { AgentView } from '../mcp/hub.js'
import type { ModelBinding, Router } from '../models/router.js'
import type { ToolCall, ToolSchema, TurnMessage } from '../models/transport.js'
import { Budget, type BudgetCaps, type StopReason } from './budget.js'
import type { KernelTools } from './kernel-tools.js'
import type { Lanes, LaneName } from './lanes.js'
import { withRunScope } from './scope.js'

/** What the loop tells the gate about one proposed call. Nothing else. */
export interface ToolContext {
  readonly runId: string
  readonly agentId: string
  readonly toolRef: string
  readonly args: Record<string, unknown>
}

export type RunStatus = 'ok' | 'error' | 'killed' | 'denied'

/** Mutable facts about a run in flight. Taint is the only one so far. */
interface RunState {
  taintedByTool: boolean
}

export interface RunOutcome {
  readonly runId: string
  readonly status: RunStatus
  readonly reason?: string
  readonly costMicroUsd: number
  readonly llmCalls: number
  readonly toolCalls: number
  readonly finalText: string
  readonly taint: 'clean' | 'tainted'
}

export interface RunAgent {
  readonly agentId: string
  readonly tier: number
  readonly lane: LaneName
  readonly model: ModelBinding
  /** Dotted refs this manifest allows. Default deny: absent means no. */
  readonly toolAllow: readonly string[]
  readonly system: string
  /** The manifest's memory namespace, which the gate pins namespaced tools to. */
  readonly projectId?: string
  /** From the manifest. Only an orchestrator is ever offered kernel tools. */
  readonly role?: 'orchestrator' | 'worker'
}

export interface RunRequest {
  readonly runId: string
  readonly agent: RunAgent
  readonly prompt: string
  /** Taint the run starts with — a Telegram ingress run starts tainted. */
  readonly taint?: 'clean' | 'tainted'
  readonly signal?: AbortSignal | undefined
  readonly goalId?: string
  /**
   * A ceiling below the agent's own caps — how a delegated child runs on a slice
   * of what its parent had left rather than on a fresh allowance of its own. It
   * can only lower: the budget is the intersection, never the ceiling alone.
   */
  readonly ceiling?: Partial<BudgetCaps>
}

export interface LoopOptions {
  readonly store: EventStore
  readonly lanes: Lanes
  readonly router: Router
  readonly engine: PolicyEngine
  readonly quarantine: Quarantine
  readonly views: ToolViewsFile
  readonly agentView: () => AgentView
  readonly budgetFor: (agent: RunAgent, ceiling?: Partial<BudgetCaps>) => Budget
  /** Kernel-native tools (delegation). Absent: none are offered. */
  readonly kernelTools?: KernelTools
  /** Hard ceiling on turns, independent of the budget's call caps. */
  readonly maxTurns?: number
}

/** The placeholder a quarantined tool's output is replaced with. */
export function quarantinePlaceholder(holdId: string, toolRef: string): string {
  return (
    `[quarantined] ${toolRef} ran and its output is held as ${holdId}. ` +
    'A human must release it before you can read it. Continue without it.'
  )
}

export class RunLoop {
  readonly #o: LoopOptions

  constructor(options: LoopOptions) {
    this.#o = options
  }

  async start(request: RunRequest): Promise<RunOutcome> {
    const { runId, agent } = request
    const budget = this.#o.budgetFor(agent, request.ceiling)

    this.#o.store.append({
      type: 'run.queued',
      runId,
      agentId: agent.agentId,
      payload: {
        schemaVersion: 1,
        runId,
        agentId: agent.agentId,
        lane: agent.lane,
        ...(request.goalId === undefined ? {} : { goalId: request.goalId }),
      },
    })

    return this.#o.lanes.enqueue(
      { agentId: agent.agentId, lane: agent.lane, signal: request.signal },
      () => this.#run(request, budget),
    )
  }

  /**
   * Taint NOW, from every source at once.
   *
   * Three things can taint a run and they arrive at different moments: the
   * request itself (a Telegram ingress run starts tainted), a `taints: true`
   * tool executed this turn, and a human releasing a quarantine hold (D17).
   * Reading only some of them is the same bug as freezing taint at run start,
   * and it is invisible until the run reaches its next write.
   */
  #taintOf(request: RunRequest, state: RunState): 'clean' | 'tainted' {
    if (request.taint === 'tainted') return 'tainted'
    if (state.taintedByTool) return 'tainted'
    return this.#o.quarantine.isTainted(request.runId) ? 'tainted' : 'clean'
  }

  /**
   * Enter a run scope reflecting the CURRENT taint.
   *
   * RunScope is frozen, so a run whose taint changes mid-flight needs a fresh
   * scope rather than a mutated one. Re-entering per turn keeps the scope
   * honest; the writer claim only cares about runId, which never changes.
   */
  async #inScope<T>(request: RunRequest, tainted: boolean, fn: () => Promise<T>): Promise<T> {
    return withRunScope(
      {
        runId: request.runId,
        agentId: request.agent.agentId,
        taint: tainted ? 'tainted' : 'clean',
        tier: request.agent.tier,
        lane: request.agent.lane,
      },
      fn,
    )
  }

  async #run(request: RunRequest, budget: Budget): Promise<RunOutcome> {
    const { runId, agent } = request
    const startedAt = Date.now()
    const state: RunState = { taintedByTool: false }
    let finalText = ''
    let status: RunStatus = 'ok'
    let reason: string | undefined

    const taintNow = (): boolean => this.#taintOf(request, state) === 'tainted'

    budget.start()
    await this.#inScope(request, taintNow(), () => {
      this.#o.store.append({
        type: 'run.started',
        runId,
        agentId: agent.agentId,
        payload: {
          schemaVersion: 1,
          runId,
          agentId: agent.agentId,
          lane: agent.lane,
          tier: agent.tier,
          taint: taintNow() ? 'tainted' : 'clean',
        },
      })
      return Promise.resolve()
    })

    const messages: TurnMessage[] = [{ role: 'user', content: request.prompt }]
    const maxTurns = this.#o.maxTurns ?? 32

    try {
      for (let turn = 0; turn < maxTurns; turn++) {
        const before = budget.check()
        if (!before.ok) {
          status = 'killed'
          reason = before.stop
          break
        }

        const tools = this.#toolsFor(agent)
        const result = await this.#inScope(request, taintNow(), () =>
          this.#o.router.call({
            binding: agent.model,
            request: { system: agent.system, messages: [...messages], tools },
            scope: { runId, agentId: agent.agentId },
            remainingMicroUsd: budget.remainingMicroUsd(),
          }),
        )

        budget.charge('cost', result.outcome.costMicroUsd)
        const afterLlm = budget.charge('llm')
        finalText = result.outcome.content

        const calls = result.outcome.toolCalls ?? []
        const callErrors = result.outcome.toolCallErrors ?? []
        if (calls.length === 0 && callErrors.length === 0) break

        messages.push({
          role: 'assistant',
          content: result.outcome.content,
          ...(calls.length === 0 ? {} : { toolCalls: calls }),
          // Replayed, never executed: only `calls` reaches the gate below.
          ...(callErrors.length === 0 ? {} : { rejectedCalls: callErrors }),
          ...(result.outcome.raw === undefined ? {} : { raw: result.outcome.raw }),
        })

        // A malformed call is told to the model, not silently dropped: the
        // model cannot correct what it is never told about.
        for (const bad of callErrors) {
          messages.push({
            role: 'tool',
            callId: bad.id,
            ref: bad.name,
            content: `[error] ${bad.reason}`,
            isError: true,
          })
        }

        for (const call of calls) {
          const outcome = await this.#handleToolCall(request, budget, call, state)
          if (outcome.taints) state.taintedByTool = true
          messages.push({
            role: 'tool',
            callId: call.id,
            ref: call.ref,
            content: outcome.text,
            ...(outcome.isError ? { isError: true } : {}),
          })
          if (outcome.stop !== undefined) {
            status = 'killed'
            reason = outcome.stop
          }
        }
        if (reason !== undefined) break

        if (!afterLlm.ok) {
          status = 'killed'
          reason = afterLlm.stop
          break
        }
      }
    } catch (e) {
      status = 'error'
      reason = e instanceof Error ? e.message : String(e)
    }

    const spend = budget.spend
    await this.#inScope(request, taintNow(), () => {
      this.#o.store.append({
        type: 'run.finished',
        runId,
        agentId: agent.agentId,
        payload: {
          schemaVersion: 1,
          runId,
          status,
          ...(reason === undefined ? {} : { reason }),
          costMicroUsd: spend.costMicroUsd,
          llmCalls: spend.llmCalls,
          toolCalls: spend.toolCalls,
          durationMs: Math.max(0, Date.now() - startedAt),
        },
      })
      return Promise.resolve()
    })

    return {
      runId,
      status,
      ...(reason === undefined ? {} : { reason }),
      costMicroUsd: spend.costMicroUsd,
      llmCalls: spend.llmCalls,
      toolCalls: spend.toolCalls,
      finalText,
      taint: taintNow() ? 'tainted' : 'clean',
    }
  }

  /**
   * The tool array the model sees.
   *
   * The hub's agent view plus the kernel's own tools, intersected with the
   * manifest — default deny. Kernel tools are offered to an orchestrator only:
   * the registry already refuses them in any other manifest, and this refuses
   * them again at the point of offer, so a worker cannot be shown a delegation
   * tool even if a manifest somehow listed one.
   */
  #toolsFor(agent: RunAgent): ToolSchema[] {
    const allowed = new Set(agent.toolAllow)
    const kernel =
      agent.role === 'orchestrator' && this.#o.kernelTools !== undefined
        ? this.#o.kernelTools.schemas()
        : []
    return [...this.#o.agentView().tools, ...kernel].filter((t) => allowed.has(t.ref))
  }

  async #handleToolCall(
    request: RunRequest,
    budget: Budget,
    call: ToolCall,
    state: RunState,
  ): Promise<{ text: string; isError: boolean; taints: boolean; stop?: StopReason }> {
    const { runId, agent } = request
    const args = (typeof call.args === 'object' && call.args !== null
      ? (call.args as Record<string, unknown>)
      : {}) as Record<string, unknown>

    const context: ToolContext = { runId, agentId: agent.agentId, toolRef: call.ref, args }
    const at = call.ref.indexOf('.')
    const serverId = at <= 0 ? call.ref : call.ref.slice(0, at)
    const toolName = at <= 0 ? call.ref : call.ref.slice(at + 1)
    const view = resolveView(this.#o.views, serverId, toolName)

    const gateInput = {
      view: {
        exposure: view.exposure,
        risk: view.risk,
        taints: view.taints,
        quarantine: view.quarantine,
        ...(view.namespaceArg === undefined ? {} : { namespaceArg: view.namespaceArg }),
      },
      scope: {
        runId,
        agentId: agent.agentId,
        taint: this.#taintOf(request, state),
        ...(agent.projectId === undefined ? {} : { projectId: agent.projectId }),
      },
      manifestAllows: agent.toolAllow.includes(call.ref),
      toolRef: call.ref,
      args: context.args,
    }

    // The pure gate runs first so the loop knows whether to park BEFORE the
    // engine blocks on a human. Re-deciding is free and safe: that is what
    // purity buys.
    const verdict: GateDecision = decide(gateInput).decision
    const parked = verdict === 'needs-human'
    const parkedAt = Date.now()

    if (parked) {
      this.#o.store.append({
        type: 'run.parked',
        runId,
        agentId: agent.agentId,
        payload: { schemaVersion: 1, runId, reason: 'approval' },
      })
    }

    let ticket
    try {
      ticket = await this.#inScope(request, gateInput.scope.taint === 'tainted', () =>
        this.#o.engine.check(gateInput),
      )
    } catch (e) {
      if (parked) this.#resume(request, parkedAt)
      if (e instanceof PolicyDenied) {
        // Denied calls still produce a result. A call that vanished would
        // leave the model retrying a tool it can never use.
        return { text: `[denied] ${e.reason}`, isError: true, taints: false }
      }
      throw e
    }
    if (parked) this.#resume(request, parkedAt)

    // D19: the wallclock ran while the run was parked. An approval that
    // arrives after it expired does not buy an execution.
    const afterPark = budget.check()
    if (!afterPark.ok) {
      return {
        text: `[conflict] the approval arrived after the run's ${afterPark.stop} cap elapsed; the tool did not run`,
        isError: true,
        taints: false,
        stop: afterPark.stop,
      }
    }

    // The hash the ticket is bound to is recomputed from the arguments that
    // are actually about to be sent.
    const argsHash = sha256Hex(canonicalize(context.args))
    if (ticket.argsHash !== argsHash) {
      return { text: '[denied] arguments changed after the decision', isError: true, taints: false }
    }

    // Kernel tools execute through the kernel's own runner, which logs and
    // re-checks exactly as the hub does; everything else through the hub. Either
    // way the gate above has already ruled and the ticket is bound to these args.
    const kernelTools = this.#o.kernelTools
    const isKernel = kernelTools?.isKernelRef(call.ref) === true
    if (isKernel && agent.role !== 'orchestrator') {
      return { text: '[denied] kernel tools are for the orchestrator only', isError: true, taints: false }
    }
    const executed =
      isKernel && kernelTools !== undefined
        ? await kernelTools.call(ticket, context.args, {
            runId,
            agent,
            budget,
            signal: request.signal,
          })
        : await this.#o.agentView().call(ticket, context.args)
    const resultTaints = view.taints || ('taints' in executed && executed.taints === true)
    const charged = budget.charge('tool')

    const bounded: BoundedOutput = {
      text: executed.text,
      truncated: executed.truncated,
      bytes: executed.bytes,
      ...(executed.sha256 === undefined ? {} : { sha256: executed.sha256 }),
    }

    if (ticket.quarantine) {
      // Executed, then held. The model gets a placeholder; a human decides
      // whether the output ever reaches the conversation (D17).
      const hold = this.#o.quarantine.hold(runId, call.ref, bounded)
      return {
        text: quarantinePlaceholder(hold.holdId, call.ref),
        isError: false,
        taints: resultTaints,
        ...(charged.ok ? {} : { stop: charged.stop }),
      }
    }

    // D18: exactly the bounded, redacted text the log stores.
    return {
      text: bounded.text,
      isError: !executed.ok,
      taints: resultTaints,
      ...(charged.ok ? {} : { stop: charged.stop }),
    }
  }

  #resume(request: RunRequest, parkedAt: number): void {
    this.#o.store.append({
      type: 'run.resumed',
      runId: request.runId,
      agentId: request.agent.agentId,
      payload: { schemaVersion: 1, runId: request.runId, parkedMs: Math.max(0, Date.now() - parkedAt) },
    })
  }
}
