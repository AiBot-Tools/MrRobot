// pmmcp's goal and vault tool arguments, typed from its live `listTools`.
//
// Two layers, kept apart on purpose:
//
//   LIVE schemas transcribe what pmmcp declares, every property with its type,
//   nullability, item type, default and requiredness, as captured on 2026-10-18
//   (test/fixtures/pmmcp-listtools.json). test/pmmcp-schemas.test.ts holds each
//   one equal to the capture through `inputShape`, so a re-capture that differs
//   fails there rather than on the wire.
//
//   SENT schemas are what the kernel will put on the wire: a strict subset of the
//   live arguments, with no defaults (a default would put `null` and `''` on the
//   wire for fields the kernel never meant to send). They carry the kernel's
//   own rules that the live schema cannot state: pmmcp types `goal_type` and
//   `status` as plain strings, with the vocabulary only in prose, so the kernel's
//   narrowing is its own. They are defined field by field rather than derived
//   with `.pick()`, which keeps the live defaults.
//
// Written by hand, not generated. zod's `fromJSONSchema` yields untyped,
// non-strict schemas, so a generator would have to emit source and would still
// need the same equivalence test; for six tools the checked transcript is the
// smaller correct thing.

import { z } from 'zod'

const nullableString = z.string().nullable().default(null)
const nullableStrings = z.array(z.string()).nullable().default(null)

export const CreateGoalLive = z
  .object({
    title: z.string(),
    project_id: z.string(),
    description: z.string().default(''),
    goal_type: z.string().default('objective'),
    parent_goal_id: nullableString,
    priority: z.int().default(3),
    acceptance_criteria: nullableStrings,
    tags: nullableStrings,
    related_files: nullableStrings,
  })
  .strict()

export const UpdateGoalLive = z
  .object({
    goal_id: z.string(),
    status: nullableString,
    progress_pct: z.number().nullable().default(null),
    title: nullableString,
    description: nullableString,
    priority: z.int().nullable().default(null),
    blockers: nullableStrings,
    tags: nullableStrings,
    acceptance_criteria: nullableStrings,
    related_files: nullableStrings,
  })
  .strict()

export const GetGoalTreeLive = z.object({ goal_id: z.string() }).strict()

export const ListGoalsLive = z
  .object({
    project_id: z.string(),
    status: nullableString,
    goal_type: nullableString,
    root_only: z.boolean().default(true),
  })
  .strict()

export const GetSecretLive = z.object({ label: z.string(), project_id: nullableString }).strict()

/** Typed only: nothing in the kernel writes the vault, and P3 keeps it that way. */
export const SetSecretLive = z
  .object({
    label: z.string(),
    value: z.string(),
    project_id: nullableString,
    description: nullableString,
    tags: nullableStrings,
  })
  .strict()

export const PMMCP_LIVE = {
  create_goal: CreateGoalLive,
  update_goal: UpdateGoalLive,
  get_goal_tree: GetGoalTreeLive,
  list_goals: ListGoalsLive,
  get_secret: GetSecretLive,
  set_secret: SetSecretLive,
} as const

export type PmmcpLiveTool = keyof typeof PMMCP_LIVE

// ─── what the kernel sends ─────────────────────────────────────────────────

/** pmmcp's goal kinds (goal_type), from its source; the live schema says only "string". */
export const GOAL_TYPES = ['objective', 'milestone', 'task'] as const

/**
 * The statuses the kernel may SEND. `completed` and `abandoned` are decisions,
 * and `review` does not exist in pmmcp (it goes as in_progress at 100 %), so a
 * goals.statuses entry that maps anywhere else is refused before the wire.
 */
export const SENDABLE_STATUSES = ['in_progress', 'blocked'] as const

const id = z.string().min(1)

/** create_goal always carries project_id: an absent one is global scope. */
export const CreateGoalSent = z
  .object({
    project_id: id,
    goal_type: z.enum(GOAL_TYPES),
    title: z.string().min(1),
    parent_goal_id: id.optional(),
  })
  .strict()

/** No project_id: the live update_goal declares none (the kernel's own log is the namespace check). */
export const UpdateGoalSent = z
  .object({
    goal_id: id,
    status: z.enum(SENDABLE_STATUSES),
    progress_pct: z.number().min(0).max(100).optional(),
  })
  .strict()

export const GetGoalTreeSent = z.object({ goal_id: id }).strict()

/** No project_id: the vault lookup stays global, as it has always been. */
export const GetSecretSent = z.object({ label: id }).strict()

export type CreateGoalArgs = z.infer<typeof CreateGoalSent>
export type UpdateGoalArgs = z.infer<typeof UpdateGoalSent>
export type GetGoalTreeArgs = z.infer<typeof GetGoalTreeSent>
export type GetSecretArgs = z.infer<typeof GetSecretSent>

// ─── comparing a schema with the capture ───────────────────────────────────

export interface PropertyShape {
  /** Sorted; an array type is written `array<item types>`. */
  readonly types: readonly string[]
  readonly default?: unknown
}

export interface InputShape {
  readonly required: readonly string[]
  readonly properties: Readonly<Record<string, PropertyShape>>
}

// The bounds z.int() emits on its own; any other bound narrows the live schema.
const SAFE = Number.MAX_SAFE_INTEGER
const TOP_KEYS = new Set(['type', 'properties', 'required', 'title', 'description', '$schema', 'additionalProperties'])
const PROPERTY_KEYS = new Set(['type', 'anyOf', 'items', 'default', 'title', 'description', 'minimum', 'maximum'])
const BRANCH_KEYS = new Set(['type', 'items', 'minimum', 'maximum'])
const ITEM_KEYS = new Set(['type'])

function record(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${where} is not a JSON Schema object`)
  }
  return value as Record<string, unknown>
}

function onlyKnown(node: Record<string, unknown>, known: ReadonlySet<string>, where: string, strict: boolean): void {
  if (!strict) return
  for (const key of Object.keys(node)) {
    if (!known.has(key)) throw new Error(`${where} uses JSON Schema keyword "${key}", which inputShape does not compare`)
  }
  for (const bound of ['minimum', 'maximum'] as const) {
    if (bound in node && Math.abs(Number(node[bound])) !== SAFE) {
      throw new Error(`${where} has ${bound} ${String(node[bound])}, which narrows the live schema`)
    }
  }
}

function typesOf(node: Record<string, unknown>, where: string, strict: boolean): string[] {
  const raw = node['type']
  const names = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw.map(String) : []
  return names.map((name) => {
    if (name !== 'array') return name
    if (node['items'] === undefined && !strict) return 'array<>'
    const items = record(node['items'], `${where}.items`)
    onlyKnown(items, ITEM_KEYS, `${where}.items`, strict)
    return `array<${typesOf(items, `${where}.items`, strict).join('|')}>`
  })
}

/**
 * The comparable shape of a tool's input schema: per property its types, its
 * item types and its default, plus the required set, in a form where zod's
 * `type: ['string', 'null']` and pydantic's `anyOf: [{type: string}, {type:
 * null}]` read the same.
 *
 * Strict (the default) throws on any keyword it does not compare, so a schema
 * narrower than the server's (an enum, a pattern, a length) cannot pass as
 * equal by being ignored. `strict: false` reads a connected server's schema at
 * boot, where a keyword this file does not know is not a reason to stop.
 */
export function inputShape(schema: unknown, options: { readonly strict?: boolean } = {}): InputShape {
  const strict = options.strict ?? true
  const top = record(schema, 'schema')
  onlyKnown(top, TOP_KEYS, 'schema', strict)
  if (top['type'] !== 'object') throw new Error('schema is not type: object')
  const properties = record(top['properties'] ?? {}, 'schema.properties')
  const shaped: Record<string, PropertyShape> = {}
  for (const [name, value] of Object.entries(properties)) {
    const where = `properties.${name}`
    const node = record(value, where)
    onlyKnown(node, PROPERTY_KEYS, where, strict)
    const types = typesOf(node, where, strict)
    const branches = node['anyOf']
    if (branches !== undefined) {
      if (!Array.isArray(branches)) throw new Error(`${where}.anyOf is not an array`)
      branches.forEach((branch, i) => {
        const b = record(branch, `${where}.anyOf[${String(i)}]`)
        onlyKnown(b, BRANCH_KEYS, `${where}.anyOf[${String(i)}]`, strict)
        types.push(...typesOf(b, `${where}.anyOf[${String(i)}]`, strict))
      })
    }
    if (types.length === 0 && strict) throw new Error(`${where} declares no type`)
    shaped[name] = {
      types: [...new Set(types)].sort(),
      ...('default' in node ? { default: node['default'] } : {}),
    }
  }
  const required = top['required']
  return {
    required: Array.isArray(required) ? required.map(String).sort() : [],
    properties: shaped,
  }
}

/** The JSON Schema a LIVE schema stands for, as the kernel compares it. */
export function liveJsonSchema(tool: PmmcpLiveTool): unknown {
  return z.toJSONSchema(PMMCP_LIVE[tool], { io: 'input' })
}
