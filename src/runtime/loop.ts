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
// A stopped run takes no further step. Its signal (`aos kill`, a shutdown, a
// parent's kill of the child it delegated to) is read before every model call
// and every tool call, after every model call, and once the turns are spent,
// and once it has aborted the run ends `killed`, its reason STOP_REQUESTED,
// rather than call the provider again or start another tool. What is in
// flight when it aborts is the tool's to end: a sandbox exec's container is
// killed by name (SandboxTools), a delegated child is killed; a model call
// already sent runs to its answer, which is then not the run's end (an
// answer with no tool call ends it `killed` too), and none of its tool calls
// then runs; a call a human approves after the stop does not run either, and
// its tool.result says so. (The approval itself is still awaited: a run
// stopped while parked holds its lane until a human answers or the approval
// expires.)
//
// A stopped run's reason follows one rule, wherever the stop finds it. The
// budget is read at the moment of the stop (a once-listener on the signal
// latches Budget.check), and the reason is the wallclock's if it has run out
// by the time the stop is read, else the cap the latch saw run out, else
// `requested`. So a cap that ran out before the stop keeps its reason, and a
// child its parent kills for outliving its ceiling (delegate.ts) ends
// `wallclock` when its own wallclock has run out by then, as it would have
// unkilled, and `requested` when it has not (one its lane admitted late,
// whose wallclock started late, or one killed while still queued, whose
// wallclock never started). A count or cost cap that a call in flight at the
// stop then used up is not the reason, whether that call was a model call, a
// tool call or one parked on a human that the human then approved (it never
// runs, and its tool.result is still charged as a tool call): the cap
// permitted that call, and the stop is why no step follows it. A run stopped
// before its lane admits it (queued behind its agent's other run, or behind
// a full lane) never starts, and still ends: run.finished `killed`,
// `requested`, with nothing spent, so all that waits on a run's end (the
// daemon's run view and the scheduler's busy check, a client waiting for
// run.finished, delegation) sees it end.
//
// No tool call reaches the gate once a cap has run out, whether the turn's
// model call used the last of one, a call before it in the same answer did,
// or the wallclock elapsed while a human was asked of one: the gate would
// only be followed by a refusal (D19), and a human would be asked to approve
// a call the loop then refuses. The run ends with the first cap it met, and
// so does a run whose turns maxTurns spent with a cap run out by then, stopped
// or not; a run whose last permitted model call gave its final answer ends
// `ok`, the cap having permitted that call.
//
// Delegation is offered to orchestrators only. The kernel-native tools
// (`kernel.adopt_plan`, `kernel.delegate`) join the tool array when the agent's
// role is `orchestrator` AND its manifest allows them; a worker is never offered
// one, and a worker that names one anyway is refused by the gate and the kernel
// runner. There is no branch here that creates a run: the delegate tool asks
// the kernel to launch one, under a ceiling carved from this run's budget.
//
// Sandbox tools (`sandbox.exec`) go to the kernel's sandbox runner, never to
// the hub, and are offered only to a run whose agent's manifest, read from the
// registry by its id, may hold the tool and lists it (SandboxTools.
// holderProblem), whatever the RunAgent's own tool list says, on a kernel
// whose sandbox config lets a call of it run (SandboxTools.configRefusal: a
// driver that runs one, and an image id pinned), and, for a manifest with
// egress on the trusted domain, whose egress can serve its grant
// (SandboxTools.egressRefusal: egress ok, and every binding it routes
// resolved at boot): a run of any other, or on any other kernel, is never
// shown one. Before the gate, the runner is asked whether it would refuse
// the call whoever approved it, for its caller (that manifest again, or no
// runner wired at all), for the kernel's sandbox config (configRefusal), for
// its egress (egressRefusal, with the run's id) or for its arguments on
// their own, and the gate denies such a call (its rule 3c) rather than ask a
// human to approve a command that would then never run. A caller the
// registry stops admitting while a human is asked (archived, or reloaded
// without the tool) is denied after the gate, with a tool.result saying so.

import { canonicalize, sha256Hex } from '../events/canonical.js'
import { boundOutput, PAYLOAD_TEXT_BUDGET, type BoundedOutput } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import { PolicyDenied } from '../errors.js'
import { decide, type GateDecision } from '../policy/gate.js'
import type { PolicyEngine } from '../policy/engine.js'
import type { Quarantine } from '../policy/quarantine.js'
import { resolveView, type ToolViewsFile } from '../mcp/tool-views.js'
import type { AgentView } from '../mcp/hub.js'
import type { ModelBinding, Router } from '../models/router.js'
import type { ToolCall, ToolSchema, TurnMessage } from '../models/transport.js'
import { Budget, type BudgetCaps, type BudgetCheck, type StopReason } from './budget.js'
import type { KernelTools } from './kernel-tools.js'
import { LaneAborted, type Lanes, type LaneName } from './lanes.js'
import { isSandboxRef, type SandboxTools } from './sandbox-tools.js'
import { withRunScope } from './scope.js'

/** What the loop tells the gate about one proposed call. Nothing else. */
export interface ToolContext {
  readonly runId: string
  readonly agentId: string
  readonly toolRef: string
  readonly args: Record<string, unknown>
}

export type RunStatus = 'ok' | 'error' | 'killed' | 'denied'

/**
 * run.finished's reason for a run stopped through its signal (`aos kill`, a
 * shutdown, a parent's kill of its child), beside the budget's StopReasons:
 * the word sandbox.killed records for a container killed at the run's stop.
 */
export const STOP_REQUESTED = 'requested'

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
  /**
   * The sandbox runner (`sandbox.exec`). Every sandbox.* ref is routed to it
   * and never to the hub. Absent: none is offered, and a call of one (a hub
   * view that offers one, which config refuses by reserving the server id)
   * is denied by the gate, before any human is asked, and never reaches the
   * hub.
   */
  readonly sandboxTools?: SandboxTools
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

    // Only a refusal of the lane itself, before the run began: an error the
    // run's own body throws is #run's to record, and it records every one.
    let began = false
    try {
      return await this.#o.lanes.enqueue(
        { agentId: agent.agentId, lane: agent.lane, signal: request.signal },
        () => {
          began = true
          return this.#run(request, budget)
        },
      )
    } catch (e) {
      if (began || !(e instanceof LaneAborted)) throw e
      return this.#finishUnstarted(request)
    }
  }

  /**
   * The end of a run stopped while it waited for its lane: run.finished
   * `killed`, STOP_REQUESTED, with nothing spent and no run.started before
   * it, since it never started. Without it a queued run killed would stay
   * `queued` in the daemon's run view for the kernel's life, its agent busy
   * to the scheduler, which then skips every job of that agent until a
   * restart.
   */
  async #finishUnstarted(request: RunRequest): Promise<RunOutcome> {
    const { runId, agent } = request
    const taint = this.#taintOf(request, { taintedByTool: false })
    await this.#inScope(request, taint === 'tainted', () => {
      this.#o.store.append({
        type: 'run.finished',
        runId,
        agentId: agent.agentId,
        payload: {
          schemaVersion: 1,
          runId,
          status: 'killed',
          reason: STOP_REQUESTED,
          costMicroUsd: 0,
          llmCalls: 0,
          toolCalls: 0,
          durationMs: 0,
        },
      })
      return Promise.resolve()
    })
    return {
      runId,
      status: 'killed',
      reason: STOP_REQUESTED,
      costMicroUsd: 0,
      llmCalls: 0,
      toolCalls: 0,
      finalText: '',
      taint,
    }
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
    const stopped = (): boolean => request.signal?.aborted === true
    // The budget as it stood at the moment of the stop (the header's rule):
    // latched by a once-listener on the signal, so that a charge made after
    // the stop, by the model call, the tool call or the parked call in flight
    // when it came, is never what the stop is blamed on. A cap of N permits
    // the Nth call and refuses the next, and the stop, not the cap, is why no
    // step follows that call.
    let atStop: BudgetCheck | undefined
    const latch = (): void => {
      atStop ??= budget.check()
    }
    // Why a stopped run ends: the wallclock if it has run out by now (a run
    // past its time when its end is read overran it, whichever came first),
    // else a cap that had run out when the stop came, else STOP_REQUESTED.
    const stopReason = (): string => {
      const now = budget.check()
      if (!now.ok && now.stop === 'wallclock') return now.stop
      const then = atStop ?? now
      return then.ok ? STOP_REQUESTED : then.stop
    }

    budget.start()
    // After start, so the latch reads a running budget: a signal that
    // aborted before the run began latches it now, within every cap.
    const signal = request.signal
    if (signal?.aborted === true) latch()
    else signal?.addEventListener('abort', latch, { once: true })
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

    // Set when the model gives its final answer: the one way the turn loop
    // ends with no cap read after it (the cap permitted that call).
    let answered = false
    try {
      for (let turn = 0; turn < maxTurns; turn++) {
        // The stop first: its reason reads the budget as it stood at the
        // stop, not after a charge made since by a call then in flight.
        if (stopped()) {
          status = 'killed'
          reason = stopReason()
          break
        }
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
        // Answered after the stop: not the run's end, whether the answer is
        // final text or tool calls, none of which then runs. The latch read
        // the budget before this call's charge, which the turn's `before`
        // found within every cap.
        if (stopped()) {
          status = 'killed'
          reason = stopReason()
          break
        }
        if (calls.length === 0 && callErrors.length === 0) {
          answered = true
          break
        }

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
          // Not one more tool once the run is stopped (during the call
          // before): its reason is the stop's (stopReason), whatever that
          // call's charge used up after it.
          if (stopped()) {
            status = 'killed'
            reason = stopReason()
            break
          }
          // Nor once a cap has run out: this turn's model call used the last
          // of one, a call before this one did, or the wallclock elapsed
          // while a human was asked of one. The call would only reach the
          // gate to be refused after it (#handleToolCall's afterPark check),
          // so none does, and no human is asked to approve a call the loop
          // then refuses while the run holds its lane past its cap. The
          // first cap met is the run's reason, recorded here, where it is
          // met: afterLlm, the next turn's read before its model call, or
          // the read after the turns would record the same cap, since no
          // charge falls between.
          const now = budget.check()
          if (!now.ok) {
            if (reason === undefined) {
              status = 'killed'
              reason = now.stop
            }
            break
          }
          const outcome = await this.#handleToolCall(request, budget, call, state)
          if (outcome.taints) state.taintedByTool = true
          messages.push({
            role: 'tool',
            callId: call.id,
            ref: call.ref,
            content: outcome.text,
            ...(outcome.isError ? { isError: true } : {}),
          })
          // A cap this call's charge used up ends the run, by that cap,
          // unless the run was stopped while the call was in flight (or
          // parked): the stop is then why no step follows, and its reason is
          // the stop's, read from the budget as the stop found it.
          if (outcome.stop !== undefined) {
            status = 'killed'
            reason = stopped() ? stopReason() : outcome.stop
          }
        }
        if (reason !== undefined) break

        if (!afterLlm.ok) {
          status = 'killed'
          reason = afterLlm.stop
          break
        }
      }
      // A stop no read above met: one during the last tool call of the last
      // turn maxTurns allows, read nowhere since. The run still ends killed.
      if (reason === undefined && stopped()) {
        status = 'killed'
        reason = stopReason()
      }
      // Turns spent by maxTurns, not ended by a final answer: a cap that has
      // run out by now (the wallclock while a human was asked of the last
      // call, say) is the run's reason, stopped or not, so whether the run
      // reports its overrun does not depend on whether someone stopped it.
      if (reason === undefined && !answered) {
        const now = budget.check()
        if (!now.ok) {
          status = 'killed'
          reason = now.stop
        }
      }
    } catch (e) {
      status = 'error'
      reason = e instanceof Error ? e.message : String(e)
    } finally {
      // A parent's signal outlives its child's run: no listener is left on it.
      signal?.removeEventListener('abort', latch)
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
   * tool even if a manifest somehow listed one. Sandbox tools likewise, to a
   * run whose agent's manifest, read from the registry by its id rather than
   * from the RunAgent, may hold one and lists it (holderProblem): a RunAgent
   * whose toolAllow names sandbox.exec is not shown it otherwise, nor is any
   * run on a kernel whose sandbox config refuses every call of it
   * (configRefusal), nor one whose egress the kernel cannot serve
   * (egressRefusal).
   */
  #toolsFor(agent: RunAgent): ToolSchema[] {
    const allowed = new Set(agent.toolAllow)
    const kernel =
      agent.role === 'orchestrator' && this.#o.kernelTools !== undefined
        ? this.#o.kernelTools.schemas()
        : []
    // Nor on a kernel whose sandbox config lets no call of the tool run (a
    // driver that runs nothing, or no image id pinned: configRefusal), nor to
    // a run whose manifest has egress the kernel cannot serve (egress not ok,
    // or a binding it routes unresolved: egressRefusal): the gate would deny
    // every call, and a model shown the tool would spend its model calls
    // retrying it.
    const sandbox = this.#o.sandboxTools
    const boxed =
      sandbox === undefined
        ? []
        : sandbox
            .schemas()
            .filter(
              (t) =>
                sandbox.holderProblem(t.ref, agent.agentId) === undefined &&
                sandbox.configRefusal(t.ref) === undefined &&
                sandbox.egressRefusal(t.ref, agent.agentId) === undefined,
            )
    return [...this.#o.agentView().tools, ...kernel, ...boxed].filter((t) => allowed.has(t.ref))
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

    // Before the gate, so that the gate denies (its rule 3c) a sandbox call
    // the runner would refuse whoever approved it, for its caller, for the
    // kernel's own sandbox config or for its arguments, rather than ask a
    // human to approve a command that then never runs. The most fundamental
    // first: who may hold the tool, then whether any call of it can run.
    const sandboxTools = this.#o.sandboxTools
    const isSandbox = isSandboxRef(call.ref)
    const runnerRefusal = isSandbox
      ? (this.#sandboxHolderProblem(call.ref, agent.agentId) ??
        sandboxTools?.configRefusal(call.ref) ??
        sandboxTools?.egressRefusal(call.ref, agent.agentId, runId) ??
        sandboxTools?.argsRefusal(call.ref, context.args))
      : undefined

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
      ...(runnerRefusal === undefined ? {} : { runnerRefusal }),
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

    // A run stopped while a human was asked: the approval buys nothing, as
    // one after the wallclock buys nothing (below), and the call's ticket is
    // closed with its tool.result.
    if (request.signal?.aborted === true) {
      return this.#deniedAfterGate(request, budget, ticket, '[killed] the run was stopped while its call was decided; the tool did not run')
    }

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
    // A sandbox tool, from a run whose agent's manifest, read from the
    // registry now, may no longer hold it (archived, or reloaded without it,
    // while a human was asked): denied, whatever the RunAgent's own tool list
    // said to the gate, and recorded as the call's tool.result, so the log
    // holds what the model is told. The same check the gate was handed, so a
    // kernel with no runner is refused here too, and never reaches the hub.
    if (isSandbox) {
      const problem = this.#sandboxHolderProblem(call.ref, agent.agentId)
      if (problem !== undefined) return this.#deniedAfterGate(request, budget, ticket, `[denied] ${problem}`)
    }
    const executed =
      isKernel && kernelTools !== undefined
        ? await kernelTools.call(ticket, context.args, {
            runId,
            agent,
            budget,
            signal: request.signal,
          })
        : isSandbox && sandboxTools !== undefined
          ? await sandboxTools.call(ticket, context.args, {
              runId,
              agentId: agent.agentId,
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

  /**
   * Why the run's agent may not call the sandbox tool `ref`, read now, or
   * undefined: no runner wired into this kernel, or the runner's reading of
   * the agent's manifest in the registry (SandboxTools.holderProblem). Asked
   * before the gate and again after it, as one check.
   */
  #sandboxHolderProblem(ref: string, agentId: string): string | undefined {
    const sandboxTools = this.#o.sandboxTools
    return sandboxTools === undefined
      ? 'no sandbox runner is wired into this kernel'
      : sandboxTools.holderProblem(ref, agentId)
  }

  /**
   * A call the gate allowed and the loop refuses before it executes: told to
   * the model, and recorded as the call's tool.result under its ticket, bounded
   * as any result is. No tool.call precedes it: nothing was about to run. It
   * is charged to the budget as a tool call, as every call the log holds a
   * tool.result for is, so a run's live count is the one recovery reads back
   * from those rows (projectRecovery), and a model that keeps calling it
   * meets the run's tool-call cap.
   */
  #deniedAfterGate(
    request: RunRequest,
    budget: Budget,
    ticket: { readonly ticketId: string; readonly toolRef: string },
    text: string,
  ): { text: string; isError: boolean; taints: boolean; stop?: StopReason } {
    const bounded = boundOutput(text, PAYLOAD_TEXT_BUDGET)
    this.#o.store.append({
      type: 'tool.result',
      runId: request.runId,
      agentId: request.agent.agentId,
      payload: {
        schemaVersion: 1,
        ticketId: ticket.ticketId,
        toolRef: ticket.toolRef,
        ok: false,
        text: bounded.text,
        bytes: bounded.bytes,
        truncated: bounded.truncated,
        ...(bounded.sha256 === undefined ? {} : { sha256: bounded.sha256 }),
        durationMs: 0,
      },
    })
    const charged = budget.charge('tool')
    return { text: bounded.text, isError: true, taints: false, ...(charged.ok ? {} : { stop: charged.stop }) }
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
