// In-process pmmcp double.
//
// `mock-mcp.ts` is a FIXTURE: six tools chosen to exercise specific hub
// branches. This is a different thing — a stateful stand-in for the operator's
// pmmcp, with the goal hierarchy, the validated status transitions, the
// project_id namespacing, the vault and the idle-expiring session all modelled,
// so the CEO's goal planning and the eval harness can be built and scored on a
// Linux box with no pmmcp anywhere near it.
//
// WHAT IS CONFIRMED AND WHAT IS MODELLED
//
// Confirmed means served exactly as the operator's live capture declares it
// (test/fixtures/pmmcp-listtools.json, 2026-10-18), AND typed by the kernel in
// src/mcp/pmmcp-schemas.ts, which test/pmmcp-schemas.test.ts holds to that
// capture: the goal tools and get_secret/set_secret. The reply texts, the
// status vocabulary and the transition table are still read from pmmcp's
// source, because a listTools capture shows arguments and nothing else. Every
// other tool's argument NAMES are checked against the capture by
// test/pmmcp-drift.test.ts; their types are not, and `PMMCP_TOOLS[].provenance`
// says which is which.
//
// Two deliberate design choices, because a double can fail in both directions:
//
//   STRICTER than the real server is safe. The kernel then handles refusals it
//   may never meet. So the rules CLAUDE.md states — hierarchy, validated
//   transitions, auto_resume off — are enforced hard.
//
//   INVENTED strictness is not safe. A rule the real server does not have would
//   bend the kernel's design around a phantom. So parent-rollup (refusing to
//   finish a milestone with a live child) is OFF by default and opt-in, because
//   nothing has confirmed pmmcp does that.
//
// Built on the low-level `Server`, not `McpServer`: the declared JSON Schema is
// what the broker's `assertSecretSchema` and the drift check read, so the mock
// must state it literally rather than have zod infer it. It also lets a session
// refuse `ping` once expired, which is what makes the hub's reconnect path
// reachable without a 404 from a real HTTP server.

import './guard.js'

import { readFileSync } from 'node:fs'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  PingRequestSchema,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js'

// ─── goal model ────────────────────────────────────────────────────────────

/** objective → milestone → task, the hierarchy CLAUDE.md names. */
export const GOAL_KINDS = ['objective', 'milestone', 'task'] as const
export type GoalKind = (typeof GOAL_KINDS)[number]

/**
 * The kind a goal of each kind must hang from. An objective is a root; a
 * milestone hangs from an objective; a task from a milestone. Depth is
 * therefore exactly three and cannot be bypassed by parenting a task to an
 * objective.
 */
export const PARENT_KIND: Readonly<Record<GoalKind, GoalKind | undefined>> = {
  objective: undefined,
  milestone: 'objective',
  task: 'milestone',
}

/** pmmcp's vocabulary (src/storage/goal_store.py `_VALID_STATUSES`). No `review`. */
export const GOAL_STATUSES = ['pending', 'in_progress', 'completed', 'abandoned', 'blocked'] as const
export type GoalStatus = (typeof GOAL_STATUSES)[number]

/**
 * pmmcp's `_STATUS_TRANSITIONS`, verbatim. Setting a goal to the status it
 * already has is allowed (a no-op), which is what lets the kernel send `review`
 * as `in_progress` after a run already moved the task there.
 */
export const GOAL_TRANSITIONS: Readonly<Record<GoalStatus, readonly GoalStatus[]>> = {
  pending: ['in_progress', 'abandoned', 'blocked'],
  in_progress: ['completed', 'blocked', 'abandoned', 'pending'],
  blocked: ['in_progress', 'abandoned', 'pending'],
  completed: ['in_progress'],
  abandoned: ['pending'],
}

/** At rest, for the opt-in subtree check. */
export const TERMINAL_STATUSES: readonly GoalStatus[] = ['completed', 'abandoned']

export interface MockGoal {
  readonly id: string
  readonly projectId: string
  readonly kind: GoalKind
  readonly parentId: string | undefined
  readonly title: string
  status: GoalStatus
  progressPct: number
  readonly metadata: Record<string, unknown>
  /** Monotonic, so a test can assert ordering without a clock. */
  readonly createdAt: number
  updatedAt: number
}

export interface MockMemory {
  readonly id: string
  readonly projectId: string
  readonly content: string
  readonly tags: readonly string[]
}

export interface AuditEntry {
  readonly action: 'get_secret' | 'set_secret'
  readonly label: string
  readonly ok: boolean
  readonly at: number
}

/**
 * The server's backing store. It outlives any one session, which is the point:
 * a reconnect after an idle expiry must find the goals still there.
 */
export interface PmmcpState {
  readonly goals: Map<string, MockGoal>
  readonly memories: Map<string, MockMemory>
  readonly secrets: Map<string, string>
  readonly audit: AuditEntry[]
  /** Statuses set by anything other than an explicit update. Must stay empty. */
  readonly autoTransitions: { from: GoalStatus; to: GoalStatus; goalId: string }[]
}

// ─── tool declarations ─────────────────────────────────────────────────────

export interface JsonObjectSchema {
  readonly type: 'object'
  /** Modelled tools declare `{type, description}`; captured ones carry pydantic's full form. */
  readonly properties: Readonly<Record<string, Readonly<Record<string, unknown>>>>
  readonly required?: readonly string[]
}

interface CapturedTool {
  readonly name: string
  readonly description?: string
  readonly inputSchema?: { readonly properties?: Record<string, unknown>; readonly required?: readonly string[] }
}

const CAPTURED: readonly CapturedTool[] = (
  JSON.parse(readFileSync(new URL('../fixtures/pmmcp-listtools.json', import.meta.url), 'utf8')) as {
    tools: CapturedTool[]
  }
).tools

/**
 * A tool exactly as the operator's live capture declares it, minus pydantic's
 * schema `title`. Served verbatim so the double's arguments ARE the live ones,
 * in the live form, and stay independent of the kernel's own transcript in
 * src/mcp/pmmcp-schemas.ts, which is what the drift guard holds to this file.
 */
function captured(name: string): { description: string; inputSchema: JsonObjectSchema } {
  const tool = CAPTURED.find((t) => t.name === name)
  if (tool?.inputSchema?.properties === undefined) {
    throw new Error(`test/fixtures/pmmcp-listtools.json has no ${name} with properties`)
  }
  return {
    description: tool.description ?? name,
    inputSchema: {
      type: 'object',
      properties: tool.inputSchema.properties as JsonObjectSchema['properties'],
      ...(tool.inputSchema.required === undefined ? {} : { required: [...tool.inputSchema.required] }),
    },
  }
}

export interface PmmcpToolSpec {
  readonly name: string
  readonly description: string
  readonly inputSchema: JsonObjectSchema
  /**
   * `confirmed`: served verbatim from the live capture and typed in
   * src/mcp/pmmcp-schemas.ts, which is held to it; exactly the tools there.
   * `source`: read from pmmcp's Python source (55f3c1a), names checked against
   * the capture. `modelled`: a guess, names checked against the capture.
   */
  readonly provenance: 'confirmed' | 'source' | 'modelled'
  readonly source: string
}

const str = (description: string): { type: string; description: string } => ({
  type: 'string',
  description,
})
const num = (description: string): { type: string; description: string } => ({
  type: 'number',
  description,
})
const ARR = (description: string): { type: string; description: string } => ({
  type: 'array',
  description,
})

/**
 * The modelled tool surface. pmmcp exposes 64 (the live capture,
 * test/fixtures/pmmcp-listtools.json, 2026-10-18); this names the 26 the kernel
 * has a reason to know about — every tool config/tool-views.yaml pins, plus
 * goals and memory — and leaves the rest to `padTo`, which registers visibly
 * fake placeholders rather than inventing plausible names. Argument names that
 * the capture corrected say so in `source`; `provenance` still records only
 * what the drift test's no-capture branch may claim.
 */
export const PMMCP_TOOLS: readonly PmmcpToolSpec[] = [
  {
    name: 'remember',
    description: 'Store a memory in a project namespace',
    inputSchema: {
      type: 'object',
      properties: {
        key: str('what the memory is about'),
        value: str('text'),
        project_id: str('namespace; absent means global scope on the live server'),
        type: str('fact, preference, skill, decision, …'),
        extra: str('optional extra text'),
      },
      required: ['key', 'value'],
    },
    provenance: 'modelled',
    source: 'argument names from the live capture (test/fixtures/pmmcp-listtools.json, 2026-10-18); the double still refuses a call without project_id',
  },
  {
    name: 'recall',
    description: 'Search memories in a project namespace',
    inputSchema: {
      type: 'object',
      properties: { project_id: str('namespace'), query: str('substring'), limit: num('max hits') },
      required: ['project_id', 'query'],
    },
    provenance: 'modelled',
    source: 'CLAUDE.md environment facts',
  },
  {
    name: 'create_goal',
    ...captured('create_goal'),
    provenance: 'confirmed',
    source: 'live capture 2026-10-18; replies from pmmcp src/tools/goals.py @55f3c1a',
  },
  {
    name: 'update_goal',
    ...captured('update_goal'),
    provenance: 'confirmed',
    source: 'live capture 2026-10-18: no project_id; replies from pmmcp src/tools/goals.py @55f3c1a',
  },
  {
    name: 'list_goals',
    ...captured('list_goals'),
    provenance: 'confirmed',
    source: 'live capture 2026-10-18; replies from pmmcp src/tools/goals.py @55f3c1a',
  },
  {
    name: 'get_goal_tree',
    ...captured('get_goal_tree'),
    provenance: 'confirmed',
    source: 'live capture 2026-10-18: no project_id; replies from pmmcp src/tools/goals.py @55f3c1a',
  },
  {
    name: 'complete_goal',
    description: 'Shorthand to mark a goal as completed (100% progress)',
    inputSchema: { type: 'object', properties: { goal_id: str('Goal to mark as completed') }, required: ['goal_id'] },
    provenance: 'source',
    source: 'pmmcp src/tools/goals.py complete_goal @55f3c1a; the kernel never calls it',
  },
  {
    name: 'get_secret',
    ...captured('get_secret'),
    provenance: 'confirmed',
    source: 'live capture 2026-10-18 (label first confirmed in DECISIONS Q24); replies from pmmcp src/tools/security.py',
  },
  {
    name: 'set_secret',
    ...captured('set_secret'),
    provenance: 'confirmed',
    source: 'live capture 2026-10-18; the kernel never calls it',
  },
  {
    name: 'audit_secrets',
    description: 'Read the vault access log',
    inputSchema: {
      type: 'object',
      properties: { hours: num('look-back window'), include_threat_scores: { type: 'boolean' } },
    },
    provenance: 'modelled',
    source: 'argument names from the live capture (test/fixtures/pmmcp-listtools.json, 2026-10-18)',
  },
  {
    name: 'admin',
    description: 'Administrative surface (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { action: str('what to do') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced kernel-only',
  },
  {
    name: 'restore_backup',
    description: 'Overwrite memory from a backup (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { backup_id: str('id') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced kernel-only',
  },
  {
    name: 'delete_context_source',
    description: 'Destroy indexed context (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { source_id: str('id') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced kernel-only',
  },
  {
    name: 'index_project',
    description: 'Rewrite the project index (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { project_id: str('namespace') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced kernel-only',
  },
  {
    name: 'forget',
    description: 'Delete a memory by key',
    inputSchema: { type: 'object', properties: { key: str('key'), project_id: str('Project scope, or global if None'), type: str('memory type') }, required: ['key'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'delete_secret',
    description: 'Delete a vault entry',
    inputSchema: { type: 'object', properties: { label: str('label'), project_id: str('project') }, required: ['label'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'list_secrets',
    description: 'List vault metadata (zero plaintext output)',
    inputSchema: { type: 'object', properties: { project_id: str('project') } },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'set_secret_expiry',
    description: 'Set a vault entry expiry',
    inputSchema: { type: 'object', properties: { label: str('label'), expires_at: str('ISO time'), project_id: str('project') }, required: ['label', 'expires_at'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'get_audit_logs',
    description: 'Read the vault access audit',
    inputSchema: { type: 'object', properties: { project_id: str('project') } },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'save_secret_template',
    description: 'Save a vault template',
    inputSchema: { type: 'object', properties: { name: str('name'), fields: ARR('fields'), project_id: str('project') }, required: ['name', 'fields'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'get_secret_template',
    description: 'Read a vault template',
    inputSchema: { type: 'object', properties: { name: str('name'), project_id: str('project') }, required: ['name'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'repair_and_heal',
    description: 'Repair pmmcp stores (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { project_id: str('project') } },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'index_git_history',
    description: 'Index git history (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { project_id: str('project'), full: { type: 'boolean' }, max_commits: num('max') }, required: ['project_id'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'scrape_context',
    description: 'Fetch and index URLs (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { url: str('url'), context_type: str('type'), max_depth: num('depth'), max_pages: num('pages'), delay_ms: num('ms') }, required: ['url'] },
    provenance: 'source',
    source: 'pmmcp src/tools @55f3c1a; pinned kernel-only in config/tool-views.yaml',
  },
  {
    name: 'coding_agent',
    description: 'Nested LLM call (the double refuses to model it)',
    inputSchema: {
      type: 'object',
      properties: { task: str('task'), project_id: str('namespace'), file_hint: str('file') },
    },
    provenance: 'modelled',
    source: 'forced disabled in config/tool-views.yaml; argument names from the live capture (2026-10-18)',
  },
  {
    name: 'session_insight_agent',
    description: 'Nested LLM call (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { session_id: str('id') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced disabled',
  },
]

/** pmmcp's real tool count, from the live capture of 2026-10-18. */
export const PMMCP_TOOL_COUNT = 64

/**
 * The tools nobody may reach, kernel included, or may reach only through the
 * broker. Their handlers throw instead of returning something plausible: if a
 * test ever gets a result from one of these, a forced classification has been
 * bypassed, and a helpful mock would hide exactly that.
 */
const REFUSED = new Set([
  'forget',
  'delete_secret',
  'list_secrets',
  'set_secret_expiry',
  'get_audit_logs',
  'save_secret_template',
  'get_secret_template',
  'repair_and_heal',
  'index_git_history',
  'scrape_context',
  'admin',
  'restore_backup',
  'delete_context_source',
  'index_project',
  'coding_agent',
  'session_insight_agent',
])

// ─── the double ────────────────────────────────────────────────────────────

export interface RecordedPmmcpCall {
  readonly tool: string
  readonly args: Record<string, unknown>
  readonly session: number
}

export interface PmmcpSession {
  readonly index: number
  readonly server: Server
  readonly client: Client
  expired: boolean
  lastActivityMs: number
}

export interface PmmcpMockOptions {
  /** The name `get_secret` declares. Overridden only to test the fail-closed path. */
  readonly secretArg?: string
  /** Vault entries present at start. */
  readonly secrets?: Readonly<Record<string, string>>
  /**
   * Make `get_secret` return the plaintext. The REAL pmmcp never does: it
   * answers `Secret '<label>' exists (masked): ****abcd` or `Secret '<label>'
   * not found.` (src/tools/security.py), both as successful text. Only the
   * dormant `secrets.source: vault` path's own tests turn this on, to prove it
   * against a hypothetical pmmcp that hands a value over.
   */
  readonly revealSecrets?: boolean
  /** Register placeholders until tools/list reports this many. */
  readonly padTo?: number
  /**
   * Declare a different inputSchema for the named tools: a server whose
   * arguments changed after the capture, for the kernel's boot check to meet.
   * Handlers are unchanged.
   */
  readonly schemas?: Readonly<Record<string, JsonObjectSchema>>
  /**
   * Idle window. A call or ping arriving more than this after the session's last
   * activity expires it, the way pmmcp's sessions idle-expire. Needs `now`.
   */
  readonly idleMs?: number
  readonly now?: () => number
  /**
   * What `create_goal` returns the new id as.
   *
   * `pmmcp` (the default) is the real reply, read from its source: "✅ Goal
   * created: goal_<hex>" and detail lines. `json` and `bare` are other shapes
   * the writer also reads; `prose` is a sentence with no readable id, which the
   * writer must refuse rather than guess at.
   */
  readonly goalIdShape?: 'pmmcp' | 'json' | 'bare' | 'prose'
  /**
   * Fault injection: calls to a tool BEYOND this count return an isError result.
   *
   * Named explicitly rather than arranged by timing. Partial failure is the case
   * a writer gets wrong — it is the difference between "the write failed" and "the
   * write left three goals on the server" — and a test that provokes it with a
   * race would pass or fail for reasons unrelated to the code.
   */
  readonly failAfter?: Readonly<Record<string, number>>
  /**
   * `list_goals` and `get_goal_tree` answer as if no goal existed. A server that
   * accepts a create and then does not know the goal is the failure the runtime
   * round-trip's read-back exists to catch, and it cannot be produced by an
   * error result.
   */
  readonly forgetsGoals?: boolean
  /**
   * Refuse to finish a milestone or objective while a child is not terminal.
   * OFF by default: nothing has confirmed pmmcp does this, and a double that
   * invents a rule makes the kernel depend on it.
   */
  readonly strictRollup?: boolean
}

export interface PmmcpMock {
  readonly state: PmmcpState
  readonly calls: readonly RecordedPmmcpCall[]
  readonly sessions: readonly PmmcpSession[]
  readonly toolNames: readonly string[]
  readonly secretArg: string
  /** A ClientFactory: each call is a fresh session over the same state. */
  connect(): Promise<Client>
  /** The live session, or undefined before the first connect. */
  session(): PmmcpSession | undefined
  /** Forget the live session, as an idle expiry would. */
  expireSession(): void
  /** Seed a goal tree without going through the wire. Returns the ids. */
  seedTree(projectId: string): { objective: string; milestone: string; task: string }
  close(): Promise<void>
}

/** Text content, the only shape the hub reads. Structures go through JSON. */
function ok(value: unknown): CallToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  return { content: [{ type: 'text', text }] }
}

function fail(message: string): CallToolResult {
  // A domain refusal is an isError result, not a protocol error: that is the
  // MCP convention, and the hub already proves it treats both as failures.
  return { content: [{ type: 'text', text: message }], isError: true }
}

export function pmmcpMock(options: PmmcpMockOptions = {}): PmmcpMock {
  const secretArg = options.secretArg ?? 'label'
  const now = options.now ?? ((): number => Date.now())
  const strictRollup = options.strictRollup ?? false
  const revealSecrets = options.revealSecrets ?? false

  const state: PmmcpState = {
    goals: new Map(),
    memories: new Map(),
    secrets: new Map(Object.entries(options.secrets ?? {})),
    audit: [],
    autoTransitions: [],
  }
  const calls: RecordedPmmcpCall[] = []
  const sessions: PmmcpSession[] = []
  let seq = 0
  const nextId = (prefix: string): string => {
    seq += 1
    return `${prefix}-${String(seq)}`
  }
  // pmmcp's shape: `goal_` + 12 hex (uuid4().hex[:12]); deterministic here.
  const nextGoalId = (): string => {
    seq += 1
    return `goal_${seq.toString(16).padStart(12, '0')}`
  }

  const specs: PmmcpToolSpec[] = PMMCP_TOOLS.map((spec): PmmcpToolSpec => {
    if (spec.name === 'get_secret' && secretArg !== 'label') {
      return {
        ...spec,
        inputSchema: {
          type: 'object',
          properties: { [secretArg]: str('vault label') },
          required: [secretArg],
        },
        // Overriding the captured argument name makes it a guess again.
        provenance: 'modelled',
        source: `secretArg override: ${secretArg}`,
      }
    }
    const replaced = options.schemas?.[spec.name]
    return replaced === undefined ? spec : { ...spec, inputSchema: replaced, provenance: 'modelled', source: 'schemas override' }
  })

  const tools: Tool[] = specs.map((spec) => ({
    name: spec.name,
    description: spec.description,
    inputSchema: {
      type: 'object' as const,
      properties: { ...spec.inputSchema.properties },
      ...(spec.inputSchema.required === undefined ? {} : { required: [...spec.inputSchema.required] }),
    },
  }))

  const padTo = options.padTo
  if (padTo !== undefined) {
    // Visibly fake. The 34 unmodelled pmmcp tools have real names nobody on this
    // machine has read, and inventing plausible ones would be fiction that later
    // looks like knowledge.
    for (let i = tools.length; i < padTo; i += 1) {
      tools.push({
        name: `unmodelled_placeholder_${String(i - specs.length + 1)}`,
        description: 'stands in for one of the pmmcp tools nobody here has read the name of',
        inputSchema: { type: 'object' as const, properties: {} },
      })
    }
  }

  const goalsOf = (projectId: string): MockGoal[] =>
    [...state.goals.values()].filter((g) => g.projectId === projectId)

  function seedTree(projectId: string): { objective: string; milestone: string; task: string } {
    const mk = (kind: GoalKind, title: string, parentId: string | undefined): string => {
      const id = nextGoalId()
      const at = now()
      state.goals.set(id, {
        id,
        projectId,
        kind,
        parentId,
        title,
        status: 'pending',
        progressPct: 0,
        metadata: {},
        createdAt: at,
        updatedAt: at,
      })
      return id
    }
    const objective = mk('objective', 'seeded objective', undefined)
    const milestone = mk('milestone', 'seeded milestone', objective)
    const task = mk('task', 'seeded task', milestone)
    return { objective, milestone, task }
  }

  // ── handlers ─────────────────────────────────────────────────────────────

  type Handler = (args: Record<string, unknown>) => CallToolResult

  const need = (args: Record<string, unknown>, key: string): string | undefined => {
    const v = args[key]
    return typeof v === 'string' && v !== '' ? v : undefined
  }

  const handlers = new Map<string, Handler>()

  handlers.set('remember', (args) => {
    const projectId = need(args, 'project_id')
    const key = need(args, 'key')
    const content = need(args, 'value')
    if (projectId === undefined) return fail('project_id is required')
    if (key === undefined) return fail('key is required')
    if (content === undefined) return fail('value is required')
    const id = nextId('mem')
    state.memories.set(id, { id, projectId, content, tags: [] })
    return ok({ id })
  })

  handlers.set('recall', (args) => {
    const projectId = need(args, 'project_id')
    const query = need(args, 'query')
    if (projectId === undefined) return fail('project_id is required')
    if (query === undefined) return fail('query is required')
    const rawLimit = args['limit']
    const limit = typeof rawLimit === 'number' && rawLimit > 0 ? Math.floor(rawLimit) : 10
    // Namespaced: a project never sees another project's memories. This is the
    // property the kernel's aos/ceo · aos/agent/<id> · aos/shared split rests on.
    const hits = [...state.memories.values()]
      .filter((m) => m.projectId === projectId && m.content.includes(query))
      .slice(0, limit)
      .map((m) => ({ id: m.id, content: m.content, tags: m.tags }))
    return ok({ hits })
  })

  // pmmcp reports failure as SUCCESSFUL text (src/tools/goals.py): "Error: …",
  // "Goal x not found.". Only a missing required argument is a transport-level
  // error, because FastMCP rejects it before the tool body runs.
  const said = (text: string): CallToolResult => ok(text)

  handlers.set('create_goal', (args) => {
    const projectId = need(args, 'project_id')
    const title = need(args, 'title')
    if (projectId === undefined) return fail('project_id is required')
    if (title === undefined) return fail('title is required')
    const kindRaw = need(args, 'goal_type') ?? 'objective'
    if (!(GOAL_KINDS as readonly string[]).includes(kindRaw)) {
      return said(`Error: Invalid goal_type: ${kindRaw}. Must be one of {'objective', 'milestone', 'task'}`)
    }
    const kind = kindRaw as GoalKind
    const parentId = need(args, 'parent_goal_id')
    if (parentId !== undefined && !state.goals.has(parentId)) {
      return said(`Error: Parent goal not found: ${parentId}`)
    }
    // STRICTER than pmmcp, which checks only that the parent exists: the kernel
    // always writes objective → milestone → task in one project, so holding it
    // to that costs nothing and catches a writer that ever stops doing so.
    const wantParent = PARENT_KIND[kind]
    if (wantParent === undefined && parentId !== undefined) {
      return said('Error: an objective is a root and takes no parent_goal_id (stricter than pmmcp)')
    }
    if (wantParent !== undefined) {
      const parent = parentId === undefined ? undefined : state.goals.get(parentId)
      if (parent === undefined) return said(`Error: a ${kind} requires a parent_goal_id (stricter than pmmcp)`)
      if (parent.projectId !== projectId || parent.kind !== wantParent) {
        return said(`Error: a ${kind} hangs from a ${wantParent} in ${projectId} (stricter than pmmcp)`)
      }
    }
    const priority = typeof args['priority'] === 'number' ? Math.max(1, Math.min(5, args['priority'])) : 3
    const id = nextGoalId()
    const at = now()
    state.goals.set(id, {
      id,
      projectId,
      kind,
      parentId,
      title,
      status: 'pending',
      progressPct: 0,
      metadata: {},
      createdAt: at,
      updatedAt: at,
    })
    const shape = options.goalIdShape ?? 'pmmcp'
    if (shape === 'bare') return ok(id)
    if (shape === 'prose') return ok(`I have created the ${kind} for you.`)
    if (shape === 'json') return ok({ id, kind, status: 'pending' })
    return said(
      `✅ Goal created: ${id}\n` +
        `   Title: ${title}\n` +
        `   Type: ${kind} | Priority: ${String(priority)}\n` +
        '   Status: pending | auto_resume: false\n' +
        '   Confirmation required: always',
    )
  })

  // pmmcp's Goal.to_display: icon, [O|M|T], title, (pct%) when non-zero. No id.
  const ICON: Readonly<Record<GoalStatus, string>> = {
    pending: '⬜',
    in_progress: '🔵',
    completed: '✅',
    abandoned: '⛔',
    blocked: '🔴',
  }
  const display = (g: MockGoal, indent = 0): string =>
    `${'  '.repeat(indent)}${ICON[g.status]} [${g.kind[0]?.toUpperCase() ?? '?'}] ${g.title}` +
    (g.progressPct > 0 ? ` (${g.progressPct.toFixed(0)}%)` : '')

  const childrenOf = (id: string): MockGoal[] =>
    [...state.goals.values()].filter((g) => g.parentId === id).sort((x, y) => x.createdAt - y.createdAt)
  const tree = (g: MockGoal, indent: number): string =>
    [display(g, indent), ...childrenOf(g.id).map((c) => tree(c, indent + 1))].join('\n')

  handlers.set('get_goal_tree', (args) => {
    const goalId = need(args, 'goal_id')
    if (goalId === undefined) return fail('goal_id is required')
    const goal = options.forgetsGoals === true ? undefined : state.goals.get(goalId)
    if (goal === undefined) return said(`Goal ${goalId} not found.`)
    return said(tree(goal, 0))
  })

  handlers.set('list_goals', (args) => {
    const projectId = need(args, 'project_id')
    if (projectId === undefined) return fail('project_id is required')
    const status = need(args, 'status')
    const goalType = need(args, 'goal_type')
    const rootOnly = args['root_only'] !== false
    const goals =
      options.forgetsGoals === true
        ? []
        : goalsOf(projectId)
            .filter((g) => (rootOnly ? g.parentId === undefined : true))
            .filter((g) => (status === undefined ? true : g.status === status))
            .filter((g) => (goalType === undefined ? true : g.kind === goalType))
            .sort((x, y) => x.createdAt - y.createdAt)
    if (goals.length === 0) {
      return said(`No goals found for project '${projectId}'${status === undefined ? '' : ` (status=${status})`}.`)
    }
    return said([`## Goals for ${projectId} (${String(goals.length)})`, ...goals.map((g) => display(g))].join('\n'))
  })

  const move = (goal: MockGoal, next: GoalStatus): string | undefined => {
    const legal = GOAL_TRANSITIONS[goal.status]
    if (next !== goal.status && !legal.includes(next)) {
      return `Error: Cannot transition from '${goal.status}' to '${next}'. Allowed: {${legal.map((x) => `'${x}'`).join(', ')}}`
    }
    if (strictRollup && next === 'completed' && goal.kind !== 'task') {
      const live = childrenOf(goal.id).filter((g) => !TERMINAL_STATUSES.includes(g.status))
      if (live.length > 0) return `Error: ${goal.id} has ${String(live.length)} child goal(s) not yet at rest`
    }
    goal.status = next
    if (next === 'completed') goal.progressPct = 100
    goal.updatedAt = now()
    // pmmcp's _update_parent_progress: the immediate parent's PROGRESS follows
    // its children (completed 100, in_progress 50); its status never does.
    const parent = goal.parentId === undefined ? undefined : state.goals.get(goal.parentId)
    if (parent !== undefined) {
      const kids = childrenOf(parent.id)
      const done = kids.filter((k) => k.status === 'completed').length
      const working = kids.filter((k) => k.status === 'in_progress').length
      parent.progressPct = Math.round(((done * 100 + working * 50) / kids.length) * 10) / 10
    }
    return undefined
  }

  handlers.set('update_goal', (args) => {
    const goalId = need(args, 'goal_id')
    if (goalId === undefined) return fail('goal_id is required')
    const goal = state.goals.get(goalId)
    if (goal === undefined) return said(`Goal ${goalId} not found.`)
    const status = need(args, 'status')
    if (status !== undefined) {
      if (!(GOAL_STATUSES as readonly string[]).includes(status)) return said(`Error: Invalid status: ${status}`)
      const refused = move(goal, status as GoalStatus)
      if (refused !== undefined) return said(refused)
    }
    const pct = args['progress_pct']
    if (typeof pct === 'number') {
      if (pct < 0 || pct > 100) return said('Error: progress_pct must be between 0.0 and 100.0')
      goal.progressPct = pct
    }
    return said(`✅ Goal updated: ${goalId}\n   ${display(goal)}`)
  })

  handlers.set('complete_goal', (args) => {
    const goalId = need(args, 'goal_id')
    if (goalId === undefined) return fail('goal_id is required')
    const goal = state.goals.get(goalId)
    if (goal === undefined) return said(`Goal ${goalId} not found.`)
    const refused = move(goal, 'completed')
    if (refused !== undefined) return said(refused)
    return said(`✅ Completed: ${goal.title}`)
  })

  handlers.set('get_secret', (args) => {
    const label = need(args, secretArg)
    if (label === undefined) return fail(`${secretArg} is required`)
    const value = state.secrets.get(label)
    state.audit.push({ action: 'get_secret', label, ok: value !== undefined, at: now() })
    if (!revealSecrets) {
      // pmmcp's own replies, verbatim in shape: success text either way.
      if (value === undefined) return ok(`Secret '${label}' not found.`)
      const masked = value.length > 4 ? '*'.repeat(value.length - 4) + value.slice(-4) : '****'
      return ok(`Secret '${label}' exists (masked): ${masked}`)
    }
    if (value === undefined) return fail(`no vault entry ${label}`)
    return ok(value)
  })

  handlers.set('set_secret', (args) => {
    const label = need(args, secretArg)
    const value = args['value']
    if (label === undefined) return fail(`${secretArg} is required`)
    if (typeof value !== 'string') return fail('value is required')
    state.secrets.set(label, value)
    state.audit.push({ action: 'set_secret', label, ok: true, at: now() })
    return ok({ label })
  })

  handlers.set('audit_secrets', () => {
    // The double keeps no clock, so `hours` selects nothing: the last 50 entries come back.
    const limit = 50
    // Labels and outcomes. Never a value: the audit log of a vault is a place a
    // secret must not appear, in the double as much as in the real one.
    const entries = state.audit.slice(-limit).map((e) => ({ action: e.action, label: e.label, ok: e.ok }))
    return ok({ entries })
  })

  for (const name of REFUSED) {
    handlers.set(name, () => {
      throw new Error(
        `mock pmmcp refuses to model ${name}: it is forced kernel-only or disabled in ` +
          'config/tool-views.yaml, so a call reaching this handler means a classification was bypassed',
      )
    })
  }

  // ── sessions ─────────────────────────────────────────────────────────────

  const SESSION_GONE = -32001 // matches hub.ts SESSION_GONE_CODES

  function build(client: Client): PmmcpSession {
    const server = new Server(
      { name: 'mock-pmmcp', version: '0.0.1' },
      { capabilities: { tools: {} } },
    )
    const session: PmmcpSession = {
      index: sessions.length,
      server,
      client,
      expired: false,
      lastActivityMs: now(),
    }

    /** Expire on idle, then refuse. Both halves, or expiry is unobservable. */
    const gate = (): void => {
      const at = now()
      const idleMs = options.idleMs
      if (!session.expired && idleMs !== undefined && at - session.lastActivityMs > idleMs) {
        session.expired = true
      }
      if (session.expired) {
        throw new McpError(SESSION_GONE, 'session expired; re-initialise')
      }
      session.lastActivityMs = at
    }

    // Overrides the SDK's automatic ping handler. An expired session that still
    // answers ping is a session the hub's heartbeat can never notice.
    server.setRequestHandler(PingRequestSchema, () => {
      gate()
      return {}
    })

    server.setRequestHandler(ListToolsRequestSchema, () => {
      gate()
      return { tools }
    })

    server.setRequestHandler(CallToolRequestSchema, (req) => {
      gate()
      const name = req.params.name
      const args = (req.params.arguments ?? {}) as Record<string, unknown>
      calls.push({ tool: name, args, session: session.index })
      const budget = options.failAfter?.[name]
      if (budget !== undefined) {
        const soFar = calls.filter((c) => c.tool === name).length
        if (soFar > budget) {
          return fail(`injected failure: ${name} call ${String(soFar)} exceeds the allowed ${String(budget)}`)
        }
      }
      const handler = handlers.get(name)
      if (handler === undefined) {
        // An unscripted tool is a protocol error, not a plausible answer. A
        // double that invents results hides the bug it was built to find.
        throw new McpError(ErrorCode.MethodNotFound, `mock pmmcp has no tool ${name}`)
      }
      const before = new Map([...state.goals].map(([id, g]) => [id, g.status]))
      const result = handler(args)
      // auto_resume is OFF: the only thing that moves a status is an explicit
      // update. Anything else is recorded, and a test asserts it stays empty.
      for (const [id, status] of before) {
        const after = state.goals.get(id)?.status
        const explicit = (name === 'update_goal' || name === 'complete_goal') && id === args['goal_id']
        if (after !== undefined && after !== status && !explicit) {
          state.autoTransitions.push({ goalId: id, from: status, to: after })
        }
      }
      return result
    })

    sessions.push(session)
    return session
  }

  async function connect(): Promise<Client> {
    // Order matters: the session holds its client, so the client exists before
    // the session does. Nothing here needs a cast to get there.
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    const client = new Client({ name: 'aos-kernel-test', version: '0.0.1' })
    const session = build(client)
    await session.server.connect(serverTransport)
    await client.connect(clientTransport)
    return client
  }

  return {
    state,
    calls,
    sessions,
    toolNames: tools.map((t) => t.name),
    secretArg,
    connect,
    session: () => sessions[sessions.length - 1],
    expireSession() {
      const live = sessions[sessions.length - 1]
      if (live === undefined) throw new Error('no session to expire')
      live.expired = true
    },
    seedTree,
    async close() {
      for (const s of sessions) {
        // A session the hub already dropped throws on close; the double's job is
        // to release handles, not to police the order they were released in.
        await s.client.close().catch(() => undefined)
        await s.server.close().catch(() => undefined)
      }
    },
  }
}
