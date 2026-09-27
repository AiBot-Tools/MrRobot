// Kernel-native tools: the tools the kernel itself implements.
//
// Everything an agent calls goes gate → (human) → (quarantine) → execute → log
// (invariant 3). MCP tools execute through the hub, which does the logging and
// re-checks exposure at the last moment. A kernel-native tool must meet the SAME
// contract, not a lighter one because the code happens to live in-process — so
// this runner is the hub's execute half, reproduced for tools that have no server:
//
//   the ticket must be bound to exactly this tool and these arguments;
//   exposure is re-derived from tool-views.yaml at execution, so a forged or
//   stale ticket for a tool agents may not call buys nothing;
//   `tool.call` is written before anything runs and `tool.result` after, bounded
//   exactly as an MCP result is.
//
// The policy for these tools lives where every other tool's does: a `kernel`
// server in config/tool-views.yaml. Which agents may hold them is the registry's
// call, at load.

import { PolicyDenied } from '../errors.js'
import { boundOutput, PAYLOAD_TEXT_BUDGET } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import type { ToolOutcome } from '../mcp/hub.js'
import { resolveView, type ToolViewsFile } from '../mcp/tool-views.js'
import type { ToolSchema } from '../models/transport.js'
import { PolicyEngine, type GateTicket } from '../policy/engine.js'
import type { Budget } from './budget.js'
import type { RunAgent } from './loop.js'

/** The server id kernel-native tools are addressed under: `kernel.delegate`. */
export const KERNEL_SERVER = 'kernel'

export interface KernelToolContext {
  readonly runId: string
  readonly agent: RunAgent
  readonly budget: Budget
  readonly signal?: AbortSignal | undefined
}

export interface KernelToolResult {
  readonly ok: boolean
  readonly text: string
  /** Whether the result carries untrusted material into the calling run. */
  readonly taints?: boolean
}

export interface KernelToolHandler {
  /** The tool name after `kernel.`, e.g. `delegate`. */
  readonly name: string
  readonly description: string
  readonly inputSchema: Record<string, unknown>
  run(args: Record<string, unknown>, ctx: KernelToolContext): Promise<KernelToolResult>
}

export interface KernelToolsOptions {
  readonly store: EventStore
  readonly views: ToolViewsFile
  readonly handlers: readonly KernelToolHandler[]
}

export class KernelTools {
  readonly #o: KernelToolsOptions
  readonly #byName: Map<string, KernelToolHandler>

  constructor(options: KernelToolsOptions) {
    this.#o = options
    this.#byName = new Map(options.handlers.map((h) => [h.name, h]))
  }

  /** Schemas for every kernel tool the policy file exposes to agents. */
  schemas(): ToolSchema[] {
    return [...this.#byName.values()]
      .filter((h) => resolveView(this.#o.views, KERNEL_SERVER, h.name).exposure === 'agent')
      .map((h) => ({
        ref: `${KERNEL_SERVER}.${h.name}`,
        description: h.description,
        inputSchema: h.inputSchema,
      }))
  }

  isKernelRef(ref: string): boolean {
    return ref.startsWith(`${KERNEL_SERVER}.`)
  }

  /**
   * Execute a kernel tool under a gate ticket, logging exactly as the hub does.
   *
   * @throws {PolicyDenied} on a ticket that does not match, or a tool agents may
   *   not call — the same refusals, in the same order, as `McpHub.call`.
   */
  async call(
    ticket: GateTicket,
    args: Record<string, unknown>,
    ctx: KernelToolContext,
  ): Promise<ToolOutcome & { readonly taints: boolean }> {
    const ref = ticket.toolRef
    PolicyEngine.assertTicketMatches(ticket, ref, args)
    if (!this.isKernelRef(ref)) throw new PolicyDenied(ref, 'not a kernel tool')
    const name = ref.slice(KERNEL_SERVER.length + 1)
    const view = resolveView(this.#o.views, KERNEL_SERVER, name)
    if (view.exposure !== 'agent') {
      throw new PolicyDenied(ref, `exposure is ${view.exposure}; agents may only call agent tools`)
    }
    const handler = this.#byName.get(name)
    if (handler === undefined) throw new PolicyDenied(ref, `the kernel implements no tool ${name}`)

    this.#o.store.append({
      type: 'tool.call',
      runId: ticket.runId,
      payload: {
        schemaVersion: 1,
        ticketId: ticket.ticketId,
        toolRef: ref,
        argsHash: ticket.argsHash,
        quarantine: ticket.quarantine,
      },
    })

    const startedAt = Date.now()
    let result: KernelToolResult
    try {
      result = await handler.run(args, ctx)
    } catch (e) {
      // A handler that threw is a failed call the model can read, not a crashed
      // run: the same treatment an MCP tool that threw gets.
      result = { ok: false, text: e instanceof Error ? e.message : String(e) }
    }

    const bounded = boundOutput(result.text, PAYLOAD_TEXT_BUDGET)
    const outcome = {
      ok: result.ok,
      text: bounded.text,
      bytes: bounded.bytes,
      truncated: bounded.truncated,
      ...(bounded.sha256 === undefined ? {} : { sha256: bounded.sha256 }),
      durationMs: Date.now() - startedAt,
      taints: result.taints === true,
    }

    this.#o.store.append({
      type: 'tool.result',
      runId: ticket.runId,
      payload: {
        schemaVersion: 1,
        ticketId: ticket.ticketId,
        toolRef: ref,
        ok: outcome.ok,
        text: outcome.text,
        bytes: outcome.bytes,
        truncated: outcome.truncated,
        ...(outcome.sha256 === undefined ? {} : { sha256: outcome.sha256 }),
        durationMs: outcome.durationMs,
      },
    })
    return outcome
  }
}
