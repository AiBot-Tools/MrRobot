// Agent manifest schema.
//
// A manifest is the written statement of what one agent may do. It is data,
// not code, and it is the only place an agent's reach is declared — there is
// no runtime call that grants an agent a tool it does not list here.
//
// The schema is strict, which is how absent features stay absent, and how a
// present one stays honest. `schedule:` is the worked example: it is now a cron
// expression the scheduler really runs, and it is VALIDATED here rather than at
// fire time — a bad expression must be a refusal at load with the file named, not
// a job that silently never fires. An unvalidated field is indistinguishable
// from a working one until the day it matters.
//
// Tier meaning (plan D15), enforced by the gate and the sandbox manager:
//   0  no tools at all
//   1  read-only MCP tools
//   2  write tools, and sandboxed execution in the trusted domain
//   3  may request irreversible tools — still human-gated, always

import { z } from 'zod'

import { EgressHost } from '../egress/host.js'
import { BINDING_ID } from '../egress/policy.js'
import { ConfigError } from '../errors.js'
import { parseCron } from '../runtime/cron.js'

export const AGENT_ID = /^[a-z][a-z0-9-]{1,31}$/
/** A soul is a basename under souls/, never a path: no separators, no dots. */
export const SOUL_NAME = /^[a-z0-9][a-z0-9-]*\.md$/
export const MEMORY_PROJECT = /^aos\/(ceo|shared|agent\/[a-z0-9-]+)$/
/** A dotted tool ref, matching src/mcp/names.ts. */
export const TOOL_REF = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$/
/** provider/model, e.g. anthropic/claude-sonnet-5. */
export const MODEL_REF = /^[a-z0-9-]+\/[A-Za-z0-9._:/-]+$/

/**
 * A tier (plan D15): an integer from 0 to 3. Exported so a tier that arrives
 * by any other path than a manifest (spawnEphemeral's request) is held to the
 * same rule before it is compared with anything.
 */
export const Tier = z.number().int().min(0).max(3)

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
    // Parsed, and not honoured: the docker driver runs only kernel.yaml's
    // pinned sandbox.imageId (sha256:<64 hex>), by id and with --pull=never,
    // and refuses a run whose spec names anything else, a tag above all
    // (src/sandbox/docker.ts, imageRefusal in src/sandbox/limits.ts). A spec
    // built from this field is refused unless it holds that very id, so the
    // image a run asks for comes from config.sandbox.imageId, never from here
    // or from config.sandbox.image, which is a tag too.
    image: z.string().min(1).optional(),
  })
  .strict()

/**
 * The most hosts and bindings one manifest's egress names: EgressGrant's own
 * bounds on `allow` and `routes` (src/egress/policy.ts), so the grant a run
 * of this agent is issued (egress plan W1) can hold all of it.
 */
export const MAX_EGRESS_ALLOW = 64
export const MAX_EGRESS_BIND = 16

/**
 * What a sandboxed run of this agent may reach, through the kernel's egress
 * engine (egress plan W1): an exec of a run on the trusted domain is issued
 * a grant of these hosts and of git-fetch on these bindings, and only while
 * boot found egress ok (src/runtime/egress.ts assertEgressEnforced).
 *
 *   allow  credential-free hosts, each an EgressHost (src/egress/host.ts):
 *          one spelling, so `Docs.Example.com.` is `docs.example.com`, and
 *          never an IP literal, a port, a wildcard or a special-use name
 *          (192.168.5.2 and host.lima.internal are the Mac's loopback as a
 *          VM sees it). Read-only there: GET and HEAD with no body
 *          (src/egress/policy.ts).
 *   bind   ids of kernel.yaml's egress.bindings: a credential for one host,
 *          used only through that binding's profiles on its repositories.
 *          A manifest names the id, never a value or an env var.
 *
 * Neither lists an entry twice: the grant refuses a host or a binding named
 * twice, so a manifest that did could never run. Strict like every section:
 * a key the schema does not name (`binds:`, an `envVar:` or a `token:`) is
 * refused with the file named, never stripped and taken for no egress at
 * all. Which agents may hold egress, which ids exist and which hosts are
 * bound are cross-file questions, answered by the registry at load
 * (src/agents/registry.ts).
 */
const Egress = z
  .object({
    allow: z.array(EgressHost).max(MAX_EGRESS_ALLOW).default([]),
    bind: z
      .array(
        z.string().regex(BINDING_ID, {
          message: 'an egress.bind entry is a binding id: lower-case letters, digits and -, starting with a letter, at most 63 characters',
        }),
      )
      .max(MAX_EGRESS_BIND)
      .default([]),
  })
  .strict()
  .superRefine((egress, ctx) => {
    // After normalisation, so `GitHub.com` and `github.com.` are one host listed twice.
    if (new Set(egress.allow).size !== egress.allow.length) {
      ctx.addIssue({ code: 'custom', path: ['allow'], message: 'egress.allow lists a host twice (compared in its one spelling)' })
    }
    if (new Set(egress.bind).size !== egress.bind.length) {
      ctx.addIssue({ code: 'custom', path: ['bind'], message: 'egress.bind names a binding twice' })
    }
  })

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
    tier: Tier,
    model: ModelBinding,
    // Factories, not objects (tools and egress alike): zod copies an object
    // default shallowly, so every manifest that omitted the section would
    // share its arrays, one tools.allow among them, and a push onto one
    // agent's would reach them all.
    tools: Tools.default(() => ({ servers: [], allow: [] })),
    sandbox: Sandbox.optional(),
    egress: Egress.default(() => ({ allow: [], bind: [] })),
    budget: Budget.optional(),
    spawn: Spawn.optional(),
    memory: Memory,
    /**
     * A five-field cron expression, or absent.
     *
     * Validated HERE rather than by the scheduler, so a bad expression is a
     * refusal at load with the file named — not a job that silently never fires,
     * which is the failure an operator cannot see. The parser refuses everything
     * it does not implement, so an accepted string is one the scheduler can run.
     */
    schedule: z
      .string()
      .min(1)
      .superRefine((value, ctx) => {
        try {
          parseCron(value)
        } catch (e) {
          // The parser's own reason, verbatim: it names what to write instead,
          // and re-wording it here would lose that.
          ctx.addIssue({ code: 'custom', message: e instanceof Error ? e.message : String(e) })
        }
      })
      .optional(),
  })
  .strict()

export type AgentManifest = z.output<typeof AgentManifest>

/**
 * Parse a manifest, with a specific message for the Phase 0 gaps an operator
 * is most likely to hit.
 */
export function parseManifest(input: unknown, source: string): AgentManifest {
  const result = AgentManifest.safeParse(input)
  if (!result.success) {
    throw new ConfigError(`${source} is invalid: ${result.error.message}`)
  }
  return result.data
}
