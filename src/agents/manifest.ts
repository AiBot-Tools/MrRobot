// Agent manifest schema.
//
// A manifest is the written statement of what one agent may do. It is data,
// not code, and it is the only place an agent's reach is declared — there is
// no runtime call that grants an agent a tool it does not list here.
//
// The schema is strict, which is how absent features stay absent. `schedule:`
// is the worked example: cron is Phase 1, so a manifest carrying it is
// refused with a message saying so, rather than parsed and silently ignored.
// An ignored field is indistinguishable from a working one until the day it
// matters.
//
// Tier meaning (plan D15), enforced by the gate and the sandbox manager:
//   0  no tools at all
//   1  read-only MCP tools
//   2  write tools, and sandboxed execution in the trusted domain
//   3  may request irreversible tools — still human-gated, always

import { z } from 'zod'

import { ConfigError } from '../errors.js'

export const AGENT_ID = /^[a-z][a-z0-9-]{1,31}$/
/** A soul is a basename under souls/, never a path: no separators, no dots. */
export const SOUL_NAME = /^[a-z0-9][a-z0-9-]*\.md$/
export const MEMORY_PROJECT = /^aos\/(ceo|shared|agent\/[a-z0-9-]+)$/
/** A dotted tool ref, matching src/mcp/names.ts. */
export const TOOL_REF = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$/
/** provider/model, e.g. anthropic/claude-sonnet-5. */
export const MODEL_REF = /^[a-z0-9-]+\/[A-Za-z0-9._:/-]+$/

const ModelBinding = z
  .object({
    primary: z.string().regex(MODEL_REF),
    // A fallback list is a priority chain. Three is the cap: past that, a
    // failing primary turns into a long silent spend rather than an error.
    fallbacks: z.array(z.string().regex(MODEL_REF)).max(3).default([]),
  })
  .strict()

const Tools = z
  .object({
    servers: z.array(z.string().min(1)).default([]),
    allow: z.array(z.string().regex(TOOL_REF)).default([]),
  })
  .strict()

const Sandbox = z
  .object({
    domain: z.enum(['trusted', 'hostile']),
    image: z.string().min(1).optional(),
  })
  .strict()

const Egress = z
  .object({
    // Parsed and frozen now; enforced by the Phase 2 proxy. Recording it
    // early means a manifest cannot quietly acquire hosts later.
    allow: z.array(z.string().min(1)).default([]),
  })
  .strict()

const Budget = z
  .object({
    maxCostMicroUsd: z.number().int().nonnegative().optional(),
    maxLlmCalls: z.number().int().nonnegative().optional(),
    maxToolCalls: z.number().int().nonnegative().optional(),
    maxWallclockMs: z.number().int().nonnegative().optional(),
  })
  .strict()

const Spawn = z
  .object({
    templates: z.array(z.string().regex(AGENT_ID)).default([]),
    maxChildren: z.number().int().nonnegative().default(0),
    // Depth is a literal 1: an ephemeral agent may not spawn. Deeper trees
    // would let one delegation become an unbounded fan-out.
    maxDepth: z.literal(1).default(1),
  })
  .strict()

const Memory = z.object({ projectId: z.string().regex(MEMORY_PROJECT) }).strict()

export const AgentManifest = z
  .object({
    id: z.string().regex(AGENT_ID),
    version: z.number().int().min(1),
    kind: z.enum(['standard', 'template', 'ephemeral']),
    role: z.enum(['orchestrator', 'worker']),
    soul: z.string().regex(SOUL_NAME),
    tier: z.number().int().min(0).max(3),
    model: ModelBinding,
    tools: Tools.default({ servers: [], allow: [] }),
    sandbox: Sandbox.optional(),
    egress: Egress.default({ allow: [] }),
    budget: Budget.optional(),
    spawn: Spawn.optional(),
    memory: Memory,
  })
  .strict()

export type AgentManifest = z.output<typeof AgentManifest>

/**
 * Parse a manifest, with a specific message for the Phase 0 gaps an operator
 * is most likely to hit.
 */
export function parseManifest(input: unknown, source: string): AgentManifest {
  if (typeof input === 'object' && input !== null && 'schedule' in input) {
    throw new ConfigError(`${source}: schedule: not implemented in Phase 0`)
  }
  const result = AgentManifest.safeParse(input)
  if (!result.success) {
    throw new ConfigError(`${source} is invalid: ${result.error.message}`)
  }
  return result.data
}
