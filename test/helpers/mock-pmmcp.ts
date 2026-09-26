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
// Exactly one thing here is confirmed against the live server: `get_secret`
// takes `label` (DECISIONS Q24). Everything else — every goal tool name, every
// argument name, the status vocabulary, the transition table — is MODELLED from
// docs/design and CLAUDE.md's environment notes, and is recorded as such in
// `PMMCP_TOOLS[].provenance`. That table is the single place the guesses live,
// and `test/pmmcp-drift.test.ts` turns every one of them into a checked fact
// the moment the operator drops a real `listTools` capture into
// test/fixtures/pmmcp-listtools.json. Until then, nothing in the kernel may
// treat a `modelled` name as known-good.
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

export const GOAL_STATUSES = [
  'pending',
  'in_progress',
  'blocked',
  'review',
  'done',
  'abandoned',
] as const
export type GoalStatus = (typeof GOAL_STATUSES)[number]

/**
 * Legal transitions. The load-bearing entries:
 *
 *   `review` does NOT reach `done` by itself and is not a synonym for it
 *   (design/agent-fleet KC15: "goal-status projection where `review` is not
 *   `done`"). A judge's verdict is advisory; something has to move it.
 *
 *   `done` and `abandoned` are terminal. Nothing reopens a finished goal, so a
 *   projection can treat them as final without a tiebreak rule.
 */
export const GOAL_TRANSITIONS: Readonly<Record<GoalStatus, readonly GoalStatus[]>> = {
  pending: ['in_progress', 'abandoned'],
  in_progress: ['blocked', 'review', 'abandoned'],
  blocked: ['in_progress', 'abandoned'],
  review: ['in_progress', 'done', 'abandoned'],
  done: [],
  abandoned: [],
}

/** Terminal statuses, for a subtree-at-rest check. */
export const TERMINAL_STATUSES: readonly GoalStatus[] = ['done', 'abandoned']

export interface MockGoal {
  readonly id: string
  readonly projectId: string
  readonly kind: GoalKind
  readonly parentId: string | undefined
  readonly title: string
  status: GoalStatus
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
  readonly properties: Readonly<Record<string, { type: string; description?: string }>>
  readonly required?: readonly string[]
}

export interface PmmcpToolSpec {
  readonly name: string
  readonly description: string
  readonly inputSchema: JsonObjectSchema
  /**
   * `confirmed` means the operator read this off a live `listTools`. Exactly one
   * entry may carry it until the capture exists.
   */
  readonly provenance: 'confirmed' | 'modelled'
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

/**
 * The modelled tool surface. pmmcp exposes 49; this names the 15 the kernel has
 * a reason to know about — the nine pinned in config/tool-views.yaml, plus goals
 * and memory — and leaves the other 34 to `padTo`, which registers visibly fake
 * placeholders rather than inventing plausible names.
 */
export const PMMCP_TOOLS: readonly PmmcpToolSpec[] = [
  {
    name: 'remember',
    description: 'Store a memory in a project namespace',
    inputSchema: {
      type: 'object',
      properties: { project_id: str('namespace'), content: str('text'), tags: { type: 'array' } },
      required: ['project_id', 'content'],
    },
    provenance: 'modelled',
    source: 'CLAUDE.md environment facts: namespacing is by project_id',
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
    description: 'Create an objective, milestone or task',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: str('namespace'),
        kind: str('objective | milestone | task'),
        title: str('one line'),
        parent_id: str('required for milestone and task'),
        metadata: { type: 'object' },
      },
      required: ['project_id', 'kind', 'title'],
    },
    provenance: 'modelled',
    source: 'docs/design/agent-fleet.md §6.1; DECISIONS Q24 is still open',
  },
  {
    name: 'get_goal',
    description: 'Read one goal',
    inputSchema: {
      type: 'object',
      properties: { project_id: str('namespace'), goal_id: str('id') },
      required: ['project_id', 'goal_id'],
    },
    provenance: 'modelled',
    source: 'docs/design/agent-fleet.md §6.1',
  },
  {
    name: 'list_goals',
    description: 'List goals in a project, optionally filtered',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: str('namespace'),
        parent_id: str('direct children of this goal'),
        status: str('one status'),
      },
      required: ['project_id'],
    },
    provenance: 'modelled',
    source: 'docs/design/agent-fleet.md §6.1',
  },
  {
    name: 'update_goal_status',
    description: 'Move a goal to a new status, if the transition is legal',
    inputSchema: {
      type: 'object',
      properties: { project_id: str('namespace'), goal_id: str('id'), status: str('new status') },
      required: ['project_id', 'goal_id', 'status'],
    },
    provenance: 'modelled',
    source: 'CLAUDE.md environment facts: validated status transitions. Vocabulary UNCONFIRMED',
  },
  {
    name: 'get_secret',
    description: 'Read a vault entry',
    // The one confirmed argument name in this file.
    inputSchema: { type: 'object', properties: { label: str('vault label') }, required: ['label'] },
    provenance: 'confirmed',
    source: 'DECISIONS Q24: arg is `label`, read off the live listTools',
  },
  {
    name: 'set_secret',
    description: 'Write a vault entry',
    inputSchema: {
      type: 'object',
      properties: { label: str('vault label'), value: str('secret') },
      required: ['label', 'value'],
    },
    provenance: 'modelled',
    source: 'paired with get_secret; only `label` is confirmed',
  },
  {
    name: 'audit_secrets',
    description: 'Read the vault access log',
    inputSchema: { type: 'object', properties: { limit: num('max entries') } },
    provenance: 'modelled',
    source: 'CLAUDE.md environment facts names audit_secrets; its args are a guess',
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
    name: 'coding_agent',
    description: 'Nested LLM call (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { prompt: str('task') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced disabled',
  },
  {
    name: 'session_insight_agent',
    description: 'Nested LLM call (the double refuses to model it)',
    inputSchema: { type: 'object', properties: { session_id: str('id') } },
    provenance: 'modelled',
    source: 'named in config/tool-views.yaml as forced disabled',
  },
]

/** pmmcp's real tool count, from CLAUDE.md's environment facts. */
export const PMMCP_TOOL_COUNT = 49

/**
 * The tools nobody may reach, kernel included, or may reach only through the
 * broker. Their handlers throw instead of returning something plausible: if a
 * test ever gets a result from one of these, a forced classification has been
 * bypassed, and a helpful mock would hide exactly that.
 */
const REFUSED = new Set([
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
  /** Register placeholders until tools/list reports this many. */
  readonly padTo?: number
  /**
   * Idle window. A call or ping arriving more than this after the session's last
   * activity expires it, the way pmmcp's sessions idle-expire. Needs `now`.
   */
  readonly idleMs?: number
  readonly now?: () => number
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

  const specs: PmmcpToolSpec[] = PMMCP_TOOLS.map((spec) =>
    spec.name === 'get_secret' && secretArg !== 'label'
      ? {
          ...spec,
          inputSchema: {
            type: 'object',
            properties: { [secretArg]: str('vault label') },
            required: [secretArg],
          },
          // Overriding the one confirmed name makes it a guess again.
          provenance: 'modelled',
          source: `secretArg override: ${secretArg}`,
        }
      : spec,
  )

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
      const id = nextId('goal')
      const at = now()
      state.goals.set(id, {
        id,
        projectId,
        kind,
        parentId,
        title,
        status: 'pending',
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
    const content = need(args, 'content')
    if (projectId === undefined) return fail('project_id is required')
    if (content === undefined) return fail('content is required')
    const rawTags = args['tags']
    const tags = Array.isArray(rawTags) ? rawTags.map((t) => String(t)) : []
    const id = nextId('mem')
    state.memories.set(id, { id, projectId, content, tags })
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

  handlers.set('create_goal', (args) => {
    const projectId = need(args, 'project_id')
    const kindRaw = need(args, 'kind')
    const title = need(args, 'title')
    if (projectId === undefined) return fail('project_id is required')
    if (title === undefined) return fail('title is required')
    if (kindRaw === undefined || !(GOAL_KINDS as readonly string[]).includes(kindRaw)) {
      return fail(`kind must be one of ${GOAL_KINDS.join(', ')}`)
    }
    const kind = kindRaw as GoalKind
    const wantParent = PARENT_KIND[kind]
    const parentId = need(args, 'parent_id')
    if (wantParent === undefined) {
      if (parentId !== undefined) return fail('an objective is a root and takes no parent_id')
    } else {
      if (parentId === undefined) return fail(`a ${kind} requires a parent_id`)
      const parent = state.goals.get(parentId)
      if (parent === undefined || parent.projectId !== projectId) {
        return fail(`no goal ${parentId} in ${projectId}`)
      }
      if (parent.kind !== wantParent) {
        return fail(`a ${kind} hangs from a ${wantParent}, not a ${parent.kind}`)
      }
    }
    const metaRaw = args['metadata']
    const metadata =
      typeof metaRaw === 'object' && metaRaw !== null && !Array.isArray(metaRaw)
        ? { ...(metaRaw as Record<string, unknown>) }
        : {}
    const id = nextId('goal')
    const at = now()
    state.goals.set(id, {
      id,
      projectId,
      kind,
      parentId,
      title,
      status: 'pending',
      metadata,
      createdAt: at,
      updatedAt: at,
    })
    return ok({ id, kind, status: 'pending' })
  })

  const view = (g: MockGoal): Record<string, unknown> => ({
    id: g.id,
    kind: g.kind,
    title: g.title,
    status: g.status,
    parent_id: g.parentId ?? null,
    metadata: g.metadata,
  })

  handlers.set('get_goal', (args) => {
    const projectId = need(args, 'project_id')
    const goalId = need(args, 'goal_id')
    if (projectId === undefined) return fail('project_id is required')
    if (goalId === undefined) return fail('goal_id is required')
    const goal = state.goals.get(goalId)
    // A goal in another project is NOT FOUND, not forbidden: the answer must not
    // confirm that an id exists somewhere else.
    if (goal === undefined || goal.projectId !== projectId) return fail(`no goal ${goalId} in ${projectId}`)
    return ok(view(goal))
  })

  handlers.set('list_goals', (args) => {
    const projectId = need(args, 'project_id')
    if (projectId === undefined) return fail('project_id is required')
    const parentId = need(args, 'parent_id')
    const status = need(args, 'status')
    if (status !== undefined && !(GOAL_STATUSES as readonly string[]).includes(status)) {
      return fail(`status must be one of ${GOAL_STATUSES.join(', ')}`)
    }
    const goals = goalsOf(projectId)
      .filter((g) => (parentId === undefined ? true : g.parentId === parentId))
      .filter((g) => (status === undefined ? true : g.status === status))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .map(view)
    return ok({ goals })
  })

  handlers.set('update_goal_status', (args) => {
    const projectId = need(args, 'project_id')
    const goalId = need(args, 'goal_id')
    const status = need(args, 'status')
    if (projectId === undefined) return fail('project_id is required')
    if (goalId === undefined) return fail('goal_id is required')
    if (status === undefined || !(GOAL_STATUSES as readonly string[]).includes(status)) {
      return fail(`status must be one of ${GOAL_STATUSES.join(', ')}`)
    }
    const goal = state.goals.get(goalId)
    if (goal === undefined || goal.projectId !== projectId) return fail(`no goal ${goalId} in ${projectId}`)
    const next = status as GoalStatus
    const legal = GOAL_TRANSITIONS[goal.status]
    if (!legal.includes(next)) {
      return fail(
        legal.length === 0
          ? `${goalId} is ${goal.status}, which is terminal`
          : `${goalId} cannot go ${goal.status} → ${next}; legal: ${legal.join(', ')}`,
      )
    }
    if (strictRollup && next === 'done' && goal.kind !== 'task') {
      const live = goalsOf(projectId).filter(
        (g) => g.parentId === goalId && !TERMINAL_STATUSES.includes(g.status),
      )
      if (live.length > 0) {
        return fail(`${goalId} has ${String(live.length)} child goal(s) not yet at rest`)
      }
    }
    goal.status = next
    goal.updatedAt = now()
    return ok({ id: goalId, status: next })
  })

  handlers.set('get_secret', (args) => {
    const label = need(args, secretArg)
    if (label === undefined) return fail(`${secretArg} is required`)
    const value = state.secrets.get(label)
    state.audit.push({ action: 'get_secret', label, ok: value !== undefined, at: now() })
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

  handlers.set('audit_secrets', (args) => {
    const rawLimit = args['limit']
    const limit = typeof rawLimit === 'number' && rawLimit > 0 ? Math.floor(rawLimit) : 50
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
        if (after !== undefined && after !== status && name !== 'update_goal_status') {
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
