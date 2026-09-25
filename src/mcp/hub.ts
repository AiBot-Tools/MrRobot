// MCP hub — the kernel's only MCP client (invariants 2, 3, 7, 10).
//
// Agents never hold an MCP connection. They are handed a VIEW: a list of tool
// descriptions and one function that refuses to do anything without a gate
// ticket. The client, the transport and the session id stay in here, so there
// is no object an agent could be given that reaches the server directly.
//
// Three refusals guard every execution, in this order, and each one catches a
// different failure:
//
//   no ticket            nothing reached the gate at all
//   argsHash mismatch    the arguments changed after the decision was made
//   exposure re-check    the ticket names a tool agents may not call
//
// The third is the one that matters most and the one most easily left out. A
// GateTicket is a plain object: nothing stops code inside the kernel from
// building one that looks right. Making it unforgeable would help, but it
// would not help enough — the honest defence is that the hub re-derives the
// tool's exposure from the policy file at the moment of execution and refuses
// anything that is not `agent`, so a forged ticket for `get_secret` buys
// exactly nothing. Structure, not authenticity, is what holds invariant 3.
//
// Kernel-only calls take a separate door that appends NO event carrying a
// result. `get_secret` returns a credential; a `tool.result` for it would put
// that credential in a hash chain that by design cannot be rewritten. Callers
// log their own domain event with safe fields instead — the secrets broker
// appends `secret.accessed { id, purpose, source }` and never the value.

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { McpError } from '@modelcontextprotocol/sdk/types.js'

import { PolicyDenied } from '../errors.js'
import { boundOutput } from '../events/bound.js'
import type { EventStore } from '../events/store.js'
import { log } from '../log.js'
import { PolicyEngine, type GateTicket } from '../policy/engine.js'
import { buildNameTable, toolName, type NameTable } from './names.js'
import { classify, resolveView, type ResolvedView, type ToolViewsFile } from './tool-views.js'
import type { ToolSchema } from '../models/transport.js'

/** pmmcp sessions idle-expire; CLAUDE.md fixes the heartbeat at 240 s. */
export const DEFAULT_PING_INTERVAL_MS = 240_000
export const DEFAULT_PING_TIMEOUT_MS = 10_000

/**
 * JSON-RPC codes that mean "this session no longer exists". Re-initialise
 * rather than retry: the server has forgotten us, so every later request on
 * this client would fail the same way.
 *
 * The plan names -32001 (RequestTimeout). -32000 (ConnectionClosed) is the
 * same situation reported a different way and is included, because the
 * alternative — sitting degraded until a human notices — is strictly worse.
 */
const SESSION_GONE_CODES = new Set([-32000, -32001])

function isSessionGone(e: unknown): boolean {
  if (e instanceof StreamableHTTPError) return e.code === 404
  if (e instanceof McpError) return SESSION_GONE_CODES.has(e.code)
  return false
}

/**
 * The one sanctioned `as Transport` cast in the kernel (CLAUDE.md names
 * hub.ts as its location, so no transports.ts exists and a hygiene test
 * asserts it appears nowhere else).
 *
 * It is needed ONLY because of `exactOptionalPropertyTypes`: the interface
 * declares `sessionId?: string` while the concrete class declares
 * `sessionId: string | undefined`, which that flag makes incompatible. The
 * runtime shapes agree exactly; this is a type-level seam, not a claim about
 * behaviour.
 */
export function streamableHttpTransport(url: string, token: string): Transport {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  })
  return transport as Transport
}

export type ClientFactory = () => Promise<Client>

export interface HubOptions {
  readonly store: EventStore
  readonly views: ToolViewsFile
  readonly pingIntervalMs?: number
  readonly pingTimeoutMs?: number
}

export interface ToolDescription {
  readonly description: string
  readonly inputSchema: Record<string, unknown>
}

interface ServerState {
  readonly serverId: string
  readonly factory: ClientFactory
  client: Client
  views: Map<string, ResolvedView>
  described: Map<string, ToolDescription>
  names: NameTable
  status: 'connected' | 'degraded'
  timer?: ReturnType<typeof setInterval>
}

/**
 * Everything an agent's turn is allowed to know about tools.
 *
 * Exactly two keys. Anything else here — a client, a server id, a session —
 * would be a handle an agent's code path could reach through, and invariant 2
 * is the claim that no such handle exists.
 */
export interface AgentView {
  readonly tools: readonly ToolSchema[]
  readonly call: (ticket: GateTicket, args: Record<string, unknown>) => Promise<ToolOutcome>
}

export interface ToolOutcome {
  readonly ok: boolean
  readonly text: string
  readonly bytes: number
  readonly truncated: boolean
  readonly sha256?: string
  readonly durationMs: number
}

/** Split a dotted ref at its FIRST dot: `pmmcp.weird.name` is one tool. */
export function splitRef(ref: string): { serverId: string; tool: string } | undefined {
  const at = ref.indexOf('.')
  if (at <= 0 || at === ref.length - 1) return undefined
  return { serverId: ref.slice(0, at), tool: ref.slice(at + 1) }
}

function isGateTicket(value: unknown): value is GateTicket {
  if (typeof value !== 'object' || value === null) return false
  const t = value as Record<string, unknown>
  return (
    typeof t['ticketId'] === 'string' &&
    typeof t['runId'] === 'string' &&
    typeof t['toolRef'] === 'string' &&
    typeof t['argsHash'] === 'string' &&
    typeof t['quarantine'] === 'boolean'
  )
}

/** Follow `nextCursor` to the end. The SDK does not paginate for us. */
export interface ListedTool {
  readonly name: string
  // `| undefined` explicitly: with exactOptionalPropertyTypes, the SDK's own
  // optional fields are not assignable to a bare `?:`.
  readonly description?: string | undefined
  readonly inputSchema?: unknown
}

export async function listAllTools(client: Client): Promise<ListedTool[]> {
  const all: ListedTool[] = []
  let cursor: string | undefined
  // A server that returned the same cursor forever would hang the kernel at
  // boot, so the walk is bounded and the bound is loud.
  for (let page = 0; page < 100; page++) {
    const result = cursor === undefined ? await client.listTools() : await client.listTools({ cursor })
    all.push(...result.tools)
    cursor = result.nextCursor
    if (cursor === undefined) return all
  }
  throw new Error('tools/list did not terminate after 100 pages')
}

export class McpHub {
  readonly #store: EventStore
  readonly #views: ToolViewsFile
  readonly #pingIntervalMs: number
  readonly #pingTimeoutMs: number
  readonly #servers = new Map<string, ServerState>()

  constructor(options: HubOptions) {
    this.#store = options.store
    this.#views = options.views
    this.#pingIntervalMs = options.pingIntervalMs ?? DEFAULT_PING_INTERVAL_MS
    this.#pingTimeoutMs = options.pingTimeoutMs ?? DEFAULT_PING_TIMEOUT_MS
  }

  status(serverId: string): 'connected' | 'degraded' | 'absent' {
    return this.#servers.get(serverId)?.status ?? 'absent'
  }

  #degrade(serverId: string, reason: string): void {
    this.#store.append({
      type: 'hub.degraded',
      payload: { schemaVersion: 1, server: serverId, reason },
    })
  }

  /**
   * Connect a server and classify what it offers.
   *
   * A failure DEGRADES rather than throws: the kernel is specified to boot
   * without pmmcp, and a hub that threw at boot would turn a missing optional
   * dependency into a dead control plane.
   */
  async connect(serverId: string, factory: ClientFactory): Promise<'connected' | 'degraded'> {
    let client: Client
    try {
      client = await factory()
    } catch (e) {
      this.#degrade(serverId, `connect failed: ${e instanceof Error ? e.message : String(e)}`)
      const existing = this.#servers.get(serverId)
      if (existing !== undefined) existing.status = 'degraded'
      return 'degraded'
    }

    try {
      const state = await this.#adopt(serverId, factory, client)
      this.#arm(state)
      return 'connected'
    } catch (e) {
      this.#degrade(serverId, `tool discovery failed: ${e instanceof Error ? e.message : String(e)}`)
      try {
        await client.close()
      } catch {
        // Closing a client that never worked must not mask the real reason.
      }
      return 'degraded'
    }
  }

  async #adopt(serverId: string, factory: ClientFactory, client: Client): Promise<ServerState> {
    const listed = await listAllTools(client)
    const names = listed.map((t) => t.name)
    const { classified, unclassified } = classify(this.#views, serverId, names)

    const views = new Map<string, ResolvedView>()
    for (const name of names) views.set(name, classified.get(name) ?? resolveView(this.#views, serverId, name))

    const described = new Map<string, ToolDescription>()
    for (const tool of listed) {
      described.set(tool.name, {
        description: tool.description ?? '',
        inputSchema:
          typeof tool.inputSchema === 'object' && tool.inputSchema !== null
            ? (tool.inputSchema as Record<string, unknown>)
            : { type: 'object' },
      })
    }

    // D9 collision and provider-regex checks run over the agent-visible set:
    // a name the kernel never offers to a model cannot collide in a model's
    // tool array. Building the table is what refuses a bad one.
    const exposedRefs = names
      .filter((name) => views.get(name)?.exposure === 'agent')
      .map((name) => `${serverId}.${name}`)
    const table = buildNameTable(exposedRefs)

    let exposed = 0
    let kernelOnly = 0
    let disabled = 0
    for (const view of views.values()) {
      if (view.exposure === 'agent') exposed++
      else if (view.exposure === 'disabled') disabled++
      else kernelOnly++
    }

    this.#store.append({
      type: 'hub.connected',
      payload: { schemaVersion: 1, server: serverId, toolCount: names.length },
    })
    this.#store.append({
      type: 'hub.tools.classified',
      payload: { schemaVersion: 1, server: serverId, exposed, kernelOnly, disabled, unclassified: [...unclassified] },
    })

    if (unclassified.length > 0) {
      // Loud, because an unclassified tool is a decision waiting for a human,
      // not a problem the kernel can resolve on its own.
      log.warn(
        { server: serverId, unclassified },
        'unclassified MCP tools default to kernel-only until tool-views.yaml classifies them',
      )
    }

    const previous = this.#servers.get(serverId)
    const state: ServerState = {
      serverId,
      factory,
      client,
      views,
      described,
      names: table,
      status: 'connected',
      ...(previous?.timer === undefined ? {} : { timer: previous.timer }),
    }
    this.#servers.set(serverId, state)
    return state
  }

  #arm(state: ServerState): void {
    if (state.timer !== undefined) clearInterval(state.timer)
    const timer = setInterval(() => {
      void this.heartbeat(state.serverId)
    }, this.#pingIntervalMs)
    // The kernel should not be held alive by a heartbeat alone.
    timer.unref?.()
    state.timer = timer
  }

  /**
   * One heartbeat. A dead session is re-initialised with a FRESH transport
   * from the factory — never resumed by session id, because the id is exactly
   * what the server has forgotten.
   */
  async heartbeat(serverId: string): Promise<'ok' | 'reconnected' | 'degraded'> {
    const state = this.#servers.get(serverId)
    if (state === undefined) return 'degraded'

    try {
      await state.client.ping({ timeout: this.#pingTimeoutMs })
      return 'ok'
    } catch (e) {
      if (!isSessionGone(e)) {
        state.status = 'degraded'
        this.#degrade(serverId, `ping failed: ${e instanceof Error ? e.message : String(e)}`)
        return 'degraded'
      }
    }

    try {
      await state.client.close()
    } catch {
      // The session is already gone; a failed close tells us nothing new.
    }

    const outcome = await this.connect(serverId, state.factory)
    return outcome === 'connected' ? 'reconnected' : 'degraded'
  }

  /**
   * The tool surface for an agent turn, plus the one gated door.
   *
   * Refs stay dotted here. `toolName` is the only place a `__` name is
   * produced (invariant 10), and the adapters call it when they build a
   * request body — emitting mapped names from the hub as well would put the
   * mapping in two places, which is the one thing that invariant forbids.
   */
  agentView(): AgentView {
    const tools: ToolSchema[] = []
    for (const state of this.#servers.values()) {
      if (state.status !== 'connected') continue
      for (const [name, view] of state.views) {
        if (view.exposure !== 'agent') continue
        const described = state.described.get(name)
        tools.push({
          ref: `${state.serverId}.${name}`,
          description: described?.description ?? '',
          inputSchema: described?.inputSchema ?? { type: 'object' },
        })
      }
    }
    return { tools, call: (ticket, args) => this.call(ticket, args) }
  }

  /** Execute one agent tool call. Refuses three ways before it acts. */
  async call(ticket: GateTicket, args: Record<string, unknown>): Promise<ToolOutcome> {
    if (!isGateTicket(ticket)) {
      throw new PolicyDenied('<unknown>', 'the hub was called without a gate ticket')
    }

    const ref = ticket.toolRef
    PolicyEngine.assertTicketMatches(ticket, ref, args)

    const split = splitRef(ref)
    if (split === undefined) throw new PolicyDenied(ref, 'not a dotted <server>.<tool> reference')

    const state = this.#servers.get(split.serverId)
    if (state === undefined || state.status !== 'connected') {
      throw new PolicyDenied(ref, `server ${split.serverId} is not connected`)
    }

    // The re-check. Derived from the policy file now, not taken from the
    // ticket, so a ticket minted for — or forged for — a kernel-only tool
    // still cannot execute one.
    const view = resolveView(this.#views, split.serverId, split.tool)
    if (view.exposure !== 'agent') {
      throw new PolicyDenied(ref, `exposure is ${view.exposure}; agents may only call agent tools`)
    }
    if (!state.views.has(split.tool)) {
      throw new PolicyDenied(ref, `${split.tool} is not a tool ${split.serverId} offers`)
    }

    this.#store.append({
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
    let ok: boolean
    let text: string
    try {
      const result = await state.client.callTool({ name: split.tool, arguments: args })
      // A tool that threw comes back as isError with content, not a rejection.
      // Treating only rejections as failure would record an error as a success.
      ok = result.isError !== true
      text = renderContent(result.content)
    } catch (e) {
      ok = false
      text = e instanceof Error ? e.message : String(e)
    }

    const bounded = boundOutput(text)
    const outcome: ToolOutcome = {
      ok,
      text: bounded.text,
      bytes: bounded.bytes,
      truncated: bounded.truncated,
      ...(bounded.sha256 === undefined ? {} : { sha256: bounded.sha256 }),
      durationMs: Date.now() - startedAt,
    }

    this.#store.append({
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

  /**
   * Call a tool the kernel may use and an agent may not.
   *
   * Appends NOTHING. `get_secret` returns a credential, and a `tool.result`
   * for it would freeze that credential into a chain that cannot be rewritten
   * by design. The caller logs its own event with safe fields — the broker's
   * `secret.accessed { id, purpose, source }` names what was fetched and why,
   * never what came back.
   *
   * `purpose` is recorded by that caller, not here; it is required so no call
   * site can reach a vault without having written down why.
   */
  async callKernelOnly(
    serverId: string,
    tool: string,
    args: Record<string, unknown>,
    purpose: string,
  ): Promise<{ ok: boolean; content: unknown }> {
    if (purpose.trim() === '') {
      throw new PolicyDenied(`${serverId}.${tool}`, 'a kernel-only call must state its purpose')
    }

    const state = this.#servers.get(serverId)
    if (state === undefined || state.status !== 'connected') {
      throw new PolicyDenied(`${serverId}.${tool}`, `server ${serverId} is not connected`)
    }

    const view = resolveView(this.#views, serverId, tool)
    if (view.exposure === 'disabled') {
      // Disabled means nobody, kernel included.
      throw new PolicyDenied(`${serverId}.${tool}`, 'this tool is disabled for every caller')
    }

    const result = await state.client.callTool({ name: tool, arguments: args })
    return { ok: result.isError !== true, content: result.content }
  }

  /** Stop every heartbeat and close every client. */
  async close(): Promise<void> {
    for (const state of this.#servers.values()) {
      if (state.timer !== undefined) clearInterval(state.timer)
      try {
        await state.client.close()
      } catch {
        // Shutdown must not fail because a server already went away.
      }
    }
    this.#servers.clear()
  }
}

/** Flatten MCP content blocks to text for the log. */
function renderContent(content: unknown): string {
  if (!Array.isArray(content)) return typeof content === 'string' ? content : JSON.stringify(content ?? null)
  return content
    .map((block) => {
      if (typeof block !== 'object' || block === null) return String(block)
      const b = block as Record<string, unknown>
      return b['type'] === 'text' && typeof b['text'] === 'string' ? b['text'] : JSON.stringify(b)
    })
    .join('\n')
}

/** Re-exported so callers need not reach into names.ts for the one mapping. */
export { toolName }
