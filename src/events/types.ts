// Event catalog — the 50 frozen event types and their payload schemas.
//
// Every payload is a strict zod object carrying `schemaVersion: 1`. Strict
// matters: an unknown key is either a caller bug or a drifted schema, and a
// hashed row is permanent, so it must be refused at the boundary rather than
// discovered later in an audit.
//
// Numbers are safe integers only, because the canonicalizer refuses anything
// else (no floats, no bigints). Money is integer micro-USD throughout (plan
// D4) and durations are integer milliseconds.
//
// Adding a type is decide-alone under CLAUDE.md, but the literal-equality
// test in test/events-types.test.ts must be updated in the same commit — that
// test is what keeps this list frozen rather than drifting silently.
//
// Payloads name ids, counts, hashes and decisions. Where a payload must carry
// free text that could contain a credential (an LLM prompt, a tool result),
// the store's redaction pass scrubs it; callers never redact by hand.

import { z } from 'zod'

const V = { schemaVersion: z.literal(1) }

const int = () => z.number().int()
const nonNegInt = () => z.number().int().nonnegative()

const SUBSYSTEMS = [
  'events',
  'control',
  'hub',
  'secrets',
  'sandbox',
  'router',
  'scheduler',
  'egress',
] as const

const RISK = ['read', 'write', 'irreversible'] as const
const TAINT = ['clean', 'tainted'] as const

// ── lifecycle ──────────────────────────────────────────────────────────────

/**
 * `degraded` is the set known degraded AT THIS INSTANT, which is empty by
 * construction: this event is appended before any subsystem is built, so that
 * it is the first row of every boot and a reader can find where a boot began.
 * The authority on what ended up degraded is the `subsystem.state` row per
 * subsystem that follows, and `status.get` live. The field is kept because a
 * future boot may know something is down before it starts.
 *
 * `configHash` is what makes two boots comparable: an operator reading the log
 * after a restart can tell whether the configuration changed under it without
 * the config itself — which holds hostnames and vault ids — ever entering the
 * log.
 */
export const KernelBootedPayload = z
  .object({ ...V, version: z.string(), configHash: z.string(), degraded: z.array(z.string()) })
  .strict()

export const KernelShutdownPayload = z
  .object({
    ...V,
    reason: z.enum(['requested', 'signal', 'error']),
    signal: z.string().optional(),
    uptimeMs: nonNegInt(),
  })
  .strict()

export const SubsystemStatePayload = z
  .object({
    ...V,
    subsystem: z.enum(SUBSYSTEMS),
    state: z.enum(['ok', 'degraded', 'absent']),
    reason: z.string().optional(),
  })
  .strict()

export const ChainAnchoredPayload = z
  .object({ ...V, seq: nonNegInt(), hash: z.string() })
  .strict()

// ── control plane ──────────────────────────────────────────────────────────

export const ControlConnectedPayload = z
  .object({ ...V, connectionId: z.string(), origin: z.string().optional() })
  .strict()

/** No token, ever — not even a prefix. The reason is the whole record. */
export const ControlRejectedPayload = z
  .object({
    ...V,
    reason: z.enum(['missing_token', 'bad_token', 'query_token', 'bad_origin', 'bad_upgrade']),
    origin: z.string().optional(),
  })
  .strict()

// ── subsystems ─────────────────────────────────────────────────────────────

export const HubConnectedPayload = z
  .object({ ...V, server: z.string(), toolCount: nonNegInt() })
  .strict()

export const HubDegradedPayload = z.object({ ...V, server: z.string(), reason: z.string() }).strict()

export const HubToolsClassifiedPayload = z
  .object({
    ...V,
    server: z.string(),
    exposed: nonNegInt(),
    kernelOnly: nonNegInt(),
    disabled: nonNegInt(),
    unclassified: z.array(z.string()),
  })
  .strict()

export const SandboxDegradedPayload = z
  .object({ ...V, driver: z.string(), reason: z.string() })
  .strict()

export const RouterDegradedPayload = z.object({ ...V, reason: z.string() }).strict()

export const SecretsDegradedPayload = z.object({ ...V, reason: z.string() }).strict()

/**
 * The configured pmmcp goal tools disagree with what the server declares, so no
 * goal tree can be written.
 *
 * A sibling of hub/router/secrets/sandbox `.degraded`, and deliberately an event
 * rather than a key in `status.get`: `StatusResult.subsystems` is a strict object
 * in the frozen protocol v1, and a new key there is a version bump. The reason is
 * the product — it names the tool or argument that disagrees, which is one line of
 * kernel.yaml away from fixed.
 */
export const GoalsDegradedPayload = z.object({ ...V, reason: z.string() }).strict()

// ── goals ──────────────────────────────────────────────────────────────────

/** Titles are model-authored and reach the log, so they are bounded at parse. */
const goalTitle = (): z.ZodString => z.string().min(1).max(200)

/**
 * A plan was validated and written into the agent's own memory namespace.
 *
 * Counts rather than the plan itself: the goal ids are each recorded by their own
 * `goal.created`, and duplicating a whole plan here would put an unbounded
 * model-authored structure into a chain that cannot be rewritten.
 */
export const PlanAdoptedPayload = z
  .object({
    ...V,
    runId: z.string(),
    projectId: z.string(),
    objectiveGoalId: z.string(),
    title: goalTitle(),
    milestones: nonNegInt(),
    tasks: nonNegInt(),
    questions: nonNegInt(),
  })
  .strict()

export const GoalCreatedPayload = z
  .object({
    ...V,
    projectId: z.string(),
    goalId: z.string(),
    kind: z.enum(['objective', 'milestone', 'task']),
    parentId: z.string().optional(),
    title: goalTitle(),
    /** The plan id this goal came from, so the tree can be traced to its plan. */
    planTaskId: z.string().optional(),
  })
  .strict()

/**
 * A goal moved.
 *
 * `from` is optional because the kernel does not always know it — a status set
 * from a run lifecycle hook knows where it is going, not necessarily where the
 * server had it. `by` says who moved it, and `kernel` is the only value the
 * kernel writes: a model never moves a goal directly.
 */
// ── delegation ─────────────────────────────────────────────────────────────

/**
 * A delegation was admitted: a child run exists, serving one task of a plan the
 * parent adopted. The tie between a child's spend and its parent's lives here.
 */
export const DelegationAdmittedPayload = z
  .object({
    ...V,
    parentRunId: z.string(),
    childRunId: z.string(),
    agentId: z.string(),
    taskId: z.string(),
    goalId: z.string(),
    /** The ceiling the child ran under, carved from what the parent had left. */
    ceilingMicroUsd: nonNegInt(),
    ceilingWallclockMs: nonNegInt(),
  })
  .strict()

/** The child finished; its cost was charged to the parent. */
export const DelegationResultPayload = z
  .object({
    ...V,
    parentRunId: z.string(),
    childRunId: z.string(),
    status: z.enum(['ok', 'error', 'killed', 'denied']),
    costMicroUsd: nonNegInt(),
    taint: z.enum(TAINT),
  })
  .strict()

/** A delegation the kernel refused, with the reason the model was told. */
export const DelegationRefusedPayload = z
  .object({
    ...V,
    parentRunId: z.string(),
    taskId: z.string().max(64).optional(),
    reason: z.string().max(500),
  })
  .strict()

export const GoalStatusPayload = z
  .object({
    ...V,
    projectId: z.string(),
    goalId: z.string(),
    from: z.string().optional(),
    to: z.string(),
    by: z.enum(['kernel', 'human']),
    reason: z.string().max(500).optional(),
    runId: z.string().optional(),
  })
  .strict()

/**
 * pmmcp answered a goal call with a success the kernel would not confirm: a
 * typed (contract P6) one in another project, with two forms that disagree, of
 * a shape it does not read, or refused by the SDK against the tool's own
 * schema; or a create, typed or prose, whose goal id the kernel cannot record
 * verbatim (masked, ill-formed, or past 128 bytes). pmmcp
 * may have written it, so the goal may exist with no `goal.created` or
 * `goal.status` claiming it; this row is that orphan's record (operator
 * decision, 2026-10-19). `goalId` is the goal the row is about: for a create,
 * the id pmmcp reported, when it reported one unambiguously and it fits
 * verbatim; for a move, the goal the kernel asked to move. Any other id pmmcp
 * named is in `reason`.
 */
export const GoalUnconfirmedPayload = z
  .object({
    ...V,
    projectId: z.string(),
    tool: z.string().max(128),
    goalId: z.string().max(128).optional(),
    reason: z.string().max(500),
  })
  .strict()

// ── agents ─────────────────────────────────────────────────────────────────

export const AgentRegisteredPayload = z
  .object({
    ...V,
    agentId: z.string(),
    version: nonNegInt(),
    kind: z.enum(['standard', 'template', 'ephemeral']),
    role: z.string(),
    tier: nonNegInt(),
  })
  .strict()

export const AgentSpawnedPayload = z
  .object({
    ...V,
    agentId: z.string(),
    templateId: z.string(),
    parentRunId: z.string().optional(),
    tier: nonNegInt(),
  })
  .strict()

export const AgentSpawnRejectedPayload = z
  .object({ ...V, templateId: z.string(), reason: z.string() })
  .strict()

/** The CEO may only ask. Promotion itself is a human action. */
export const AgentPromotionRequestedPayload = z
  .object({ ...V, agentId: z.string(), requestedByRunId: z.string(), rationale: z.string() })
  .strict()

export const AgentPromotedPayload = z
  .object({
    ...V,
    agentId: z.string(),
    fromVersion: nonNegInt(),
    toVersion: nonNegInt(),
    byConnectionId: z.string(),
  })
  .strict()

export const AgentArchivedPayload = z
  .object({ ...V, agentId: z.string(), version: nonNegInt(), byConnectionId: z.string() })
  .strict()

// ── runs ───────────────────────────────────────────────────────────────────

export const RunQueuedPayload = z
  .object({ ...V, runId: z.string(), agentId: z.string(), lane: z.string(), goalId: z.string().optional() })
  .strict()

/**
 * The scheduler decided to fire an agent for a given minute.
 *
 * Written BEFORE the run is started, which is the point: it is the durable claim
 * on that minute. If starting then fails, the minute stays claimed and a restart
 * does not re-fire it — a job that cannot start must not be retried on every tick
 * and every reboot.
 *
 * It also answers "why did this run start?", which no other row does.
 */
export const RunScheduledPayload = z
  .object({ ...V, agentId: z.string(), schedule: z.string(), minute: z.string() })
  .strict()

export const RunStartedPayload = z
  .object({
    ...V,
    runId: z.string(),
    agentId: z.string(),
    lane: z.string(),
    tier: nonNegInt(),
    taint: z.enum(TAINT),
  })
  .strict()

export const RunParkedPayload = z
  .object({
    ...V,
    runId: z.string(),
    reason: z.enum(['approval', 'quarantine']),
    approvalId: z.string().optional(),
  })
  .strict()

export const RunResumedPayload = z.object({ ...V, runId: z.string(), parkedMs: nonNegInt() }).strict()

export const RunFinishedPayload = z
  .object({
    ...V,
    runId: z.string(),
    status: z.enum(['ok', 'error', 'killed', 'denied']),
    reason: z.string().optional(),
    costMicroUsd: nonNegInt(),
    llmCalls: nonNegInt(),
    toolCalls: nonNegInt(),
    durationMs: nonNegInt(),
  })
  .strict()

// ── model calls (invariant 4: two events, with prompt, content, tokens, cost)

export const LlmRequestPayload = z
  .object({
    ...V,
    ref: z.string(),
    attempt: nonNegInt(),
    prompt: z.string(),
    tools: z.array(z.string()),
    maxOutputTokens: nonNegInt().optional(),
  })
  .strict()

export const LlmResponsePayload = z
  .object({
    ...V,
    ref: z.string(),
    attempt: nonNegInt(),
    content: z.string(),
    finish: z.string(),
    inputTokens: nonNegInt(),
    outputTokens: nonNegInt(),
    cacheReadTokens: nonNegInt().optional(),
    cacheWriteTokens: nonNegInt().optional(),
    costMicroUsd: nonNegInt(),
    durationMs: nonNegInt(),
    error: z.string().optional(),
  })
  .strict()

// ── tools and the gate ─────────────────────────────────────────────────────

export const ToolGatePayload = z
  .object({
    ...V,
    toolRef: z.string(),
    decision: z.enum(['allow', 'needs-human', 'quarantine', 'deny']),
    reason: z.string(),
    risk: z.enum(RISK),
    taint: z.enum(TAINT),
  })
  .strict()

export const ToolCallPayload = z
  .object({
    ...V,
    ticketId: z.string(),
    toolRef: z.string(),
    argsHash: z.string(),
    quarantine: z.boolean(),
  })
  .strict()

/** Mirrors BoundedOutput: text is a prefix, sha256 covers the redacted whole. */
export const ToolResultPayload = z
  .object({
    ...V,
    ticketId: z.string(),
    toolRef: z.string(),
    ok: z.boolean(),
    text: z.string(),
    bytes: nonNegInt(),
    truncated: z.boolean(),
    sha256: z.string().optional(),
    durationMs: nonNegInt(),
  })
  .strict()

// ── human decisions ────────────────────────────────────────────────────────

export const ApprovalRequestedPayload = z
  .object({
    ...V,
    approvalId: z.string(),
    toolRef: z.string(),
    argsPreview: z.string(),
    risk: z.enum(RISK),
    expiresAt: z.string(),
  })
  .strict()

export const ApprovalResolvedPayload = z
  .object({
    ...V,
    approvalId: z.string(),
    decision: z.enum(['approved', 'denied', 'expired']),
    byConnectionId: z.string().optional(),
  })
  .strict()

export const QuarantineHeldPayload = z
  .object({ ...V, holdId: z.string(), toolRef: z.string(), reason: z.string() })
  .strict()

export const QuarantineReleasedPayload = z
  .object({ ...V, holdId: z.string(), byConnectionId: z.string() })
  .strict()

/**
 * A hold ended without a human ever seeing its content.
 *
 * Distinct from `quarantine.released` on purpose. That row carries a
 * `byConnectionId` and means a person reviewed the content and let the run have
 * it; writing one for a restart would put a false claim of human review into an
 * immutable audit log. Held content lives in memory only, so a crash destroys
 * it — the hold can therefore be ENDED but never released, and the log has to
 * be able to say which happened.
 */
export const QuarantineAbandonedPayload = z
  .object({ ...V, holdId: z.string(), reason: z.string() })
  .strict()

// ── sandboxes ──────────────────────────────────────────────────────────────

export const SandboxStartedPayload = z
  .object({
    ...V,
    sandboxId: z.string(),
    driver: z.string(),
    domain: z.string(),
    image: z.string(),
    memoryMb: nonNegInt(),
    pids: nonNegInt(),
    wallclockMs: nonNegInt(),
  })
  .strict()

export const SandboxKilledPayload = z
  .object({
    ...V,
    sandboxId: z.string(),
    reason: z.enum(['wallclock', 'requested', 'error', 'exited']),
    exitCode: int().optional(),
  })
  .strict()

// ── secrets and probes ─────────────────────────────────────────────────────

/** Never the value, never a digest of the value: an id, a purpose, a source. */
export const SecretAccessedPayload = z
  .object({ ...V, id: z.string(), purpose: z.string(), source: z.enum(['vault', 'env']) })
  .strict()

export const ProbeRecordedPayload = z
  .object({
    ...V,
    ref: z.string(),
    toolCalling: z.boolean(),
    toolChoiceForced: z.boolean().nullable(),
    latencyMs: nonNegInt().optional(),
    reason: z.string().optional(),
  })
  .strict()

// ── egress (egress plan E4) ────────────────────────────────────────────────
//
// What the egress engine writes: a grant when one container's channel opens
// and its revocation when the channel closes, a decision for each request a
// worker sends through it, and egress.degraded when a boot cannot run egress
// at all. Nothing appends these yet; the wiring task (W1) does.
//
// Three rules hold every field:
//
//   * No credential, and no function of one. A binding is named by its
//     bindingId, never by a header value, a fingerprint or a digest: a sha256
//     of a credential in an append-only log is a permanent, offline
//     confirmable commitment to it (bound.ts), and the boot's secret.accessed
//     row already records which binding was resolved. No key matches
//     DENY_KEYS (redact.ts) either, which would censor its value wholesale.
//     No count includes a request's headers, which carry the injected
//     credential: their length would be one more function of it. pathBytes
//     and queryBytes count the request-target alone, which the worker wrote.
//   * No query string. A query is where a URL carries a token
//     (`?access_token=`), and a worker's request is attacker-chosen text, so
//     `path` is the path alone and refuses `?` and `#`. The one query a route
//     reads, git's `service=`, is stored as `service`: a closed enum of its two
//     values, held to the route that reads it, so no other byte of a query can
//     reach the log through it. How much a request carried is stored as
//     numbers instead (`pathBytes`, `queryBytes`): a GET that takes a
//     workspace out in its query is told apart from an empty one, and not a
//     byte of the query is kept.
//   * Free text is bounded in bytes. `path`, `why`, `detail` and `reason` each
//     have a budget (EGRESS_*_BYTES) in UTF-8 bytes, as recordable() counts,
//     and a writer passes recordable(text, budget) (bound.ts): redacted, cut on
//     a code point boundary, with no lone surrogate. Raw text over the budget,
//     in bytes, is refused here, and a refused append loses the very record
//     it was writing.
//
// Identifiers are never censored. The store parses a payload before it
// redacts it (store.ts), so an id, a host, a repository, a binding, a method
// or an error code in a credential's shape (sk-abcdefghij.example.com,
// op/ghp_...) would pass here and be stored as `[REDACTED]...`: a row that no
// longer says which host a run could reach, and that fails this schema when
// it is read back (W2's recovery reads grants back). Each identifier field is
// refused here when one of the redaction pass's credential shapes matches it
// (EGRESS_TOKEN_PATTERNS): a grant the kernel cannot record is not issued, as
// one past PROXY_GRANT_MAX_REPOS is not, and config refuses such a binding
// host, repository or id before a grant is built (E5, E6). A registered secret
// value (redact.ts SecretMask) is the broker's, unknown here: the issuer (W1)
// checks a grant's identifiers against redactString before it appends. A deny
// whose host the worker spelled in a credential's shape is recorded without
// it (E8). Only `path` and the free text may hold the mark.
//
// The vocabulary (decide()'s reasons, the upstream's refusals, the host and
// address classifiers' reasons, the profiles, the id shapes, the target's
// bound) is src/egress's, copied rather than imported: this catalog sits
// beneath every other layer and imports nothing but zod.
// test/events-types.test.ts holds every copy equal to its source, so a reason
// added there and not here fails the suite, not an append. The shapes are
// bounds, not policy: a host here is any lower-case LDH name of two or more
// labels that does not end in a number, which every EgressHost is, and
// whether a run may reach it is decide()'s to say; the row records what it
// said. Where a row's fields depend on each other (an allow's method and path
// on its route and repository; what a deny names, by how far decide() read
// before its reason stopped it, PROXY_DENIES_*; a binding found only from a
// host; a path and the length it had; a refusal that names its answer; a
// grant EgressGrant would refuse), the schema holds them to what src/egress
// can produce, and test/egress-policy.test.ts records a deny of every reason
// decide() gives with exactly the fields it gave. It does not hold every
// field decide() may or may not have read: a method deny names a host when a
// route or a credential-free host refused the method, and none when the
// method was no token, and the row may name it or not either way. It cannot
// hold a row to the request itself: that the host, method and path a row
// names are the ones the worker sent is the session's to get right (E8), and
// the schema checks only that the fields agree.

/** decide()'s reasons to allow (src/egress/policy.ts ALLOW_REASONS). */
export const PROXY_ALLOW_REASONS = Object.freeze(['allow-host', 'git-fetch', 'git-push', 'github-pulls'] as const)

/** decide()'s reasons to deny (policy.ts DENY_REASONS, routes.ts ROUTE_REFUSALS among them). */
export const PROXY_DENY_REASONS = Object.freeze([
  'malformed',
  'use-route',
  'not-allowed',
  'repo',
  'not-granted',
  'body',
  'content-type',
  'content-encoding',
  'override-header',
  'target',
  'not-a-host',
  'port',
  'second-host',
  'path',
  'no-route',
  'method',
  'query',
  'push-commands',
  'push-ref',
  'push-delete',
  'pulls-body',
  'pulls-head',
] as const)

/**
 * The deny reasons decide() gives before it has read a host (policy.ts
 * judgeHead, routes.ts parseTarget): a CONNECT, a target it cannot read, and
 * a host that is none. A row of one names no host, and so no binding.
 */
export const PROXY_DENIES_BEFORE_HOST = Object.freeze(['use-route', 'target', 'not-a-host'] as const)

/**
 * The deny reasons decide() gives before it has read a path: those before the
 * host, and a port other than 443, which parseTarget refuses once it has read
 * the host and before it reads the path. A row of one names no path, and so
 * no length and no service.
 */
export const PROXY_DENIES_BEFORE_PATH = Object.freeze([...PROXY_DENIES_BEFORE_HOST, 'port'] as const)

/**
 * The deny reasons decide() can give once a request has reached a bound
 * route (policy.ts judgeRoute, past the repository): a profile the grant does
 * not hold, a body or content header the route refuses, a command list or a
 * pull request it judged, and leading bytes that were not what it asked for.
 * Only a deny of one of these names a binding: the rest are given before a
 * route is found, or on a credential-free host.
 */
export const PROXY_DENIES_ON_A_ROUTE = Object.freeze([
  'malformed',
  'not-granted',
  'body',
  'content-type',
  'content-encoding',
  'push-commands',
  'push-ref',
  'push-delete',
  'pulls-body',
  'pulls-head',
] as const)

/**
 * Why the upstream refused a request decide() allowed (src/egress/upstream.ts
 * UPSTREAM_REFUSALS), then the ones the session gives itself
 * (src/egress/session.ts SESSION_REFUSALS), each the host's answer, which the
 * worker was answered 502 for: `challenged`, the host answered 401 or 403, so
 * a binding whose credential expired or was revoked, or a push the host
 * refused, is on record; `response-head`, the host answered with a head
 * node:http will not write (a status below 100), so a request that left and
 * failed is never a bare allow.
 */
export const PROXY_UPSTREAM_REFUSALS = Object.freeze([
  'not-decided',
  'not-a-host',
  'port',
  'head',
  'aborted',
  'resolve-failed',
  'resolve-timeout',
  'no-address',
  'denied-address',
  'host-address',
  'interfaces-unreadable',
  'connect-failed',
  'connect-timeout',
  'unverified',
  'upstream-failed',
  'body-length',
  'idle-timeout',
  'challenged',
  'response-head',
] as const)

/**
 * The refusals the upstream can meet after node:http took the request's head
 * to send (upstream.ts UPSTREAM_REFUSALS_AFTER_SEND), then the session's
 * (`challenged`, `response-head`), which are met only once the host answered:
 * only with one of these can an upstream row say the request was sent.
 */
export const PROXY_REFUSALS_AFTER_SEND = Object.freeze(['head', 'aborted', 'upstream-failed', 'body-length', 'idle-timeout', 'challenged', 'response-head'] as const)

/** The session's own refusals (src/egress/session.ts SESSION_REFUSALS): each is the host's answer, so it never comes with an unsent request. */
const PROXY_ANSWERED_REFUSALS: readonly string[] = Object.freeze(['challenged', 'response-head'])

/** Why a target's host is no EgressHost (src/egress/host.ts HOST_REFUSALS). */
export const PROXY_HOST_REFUSALS = Object.freeze([
  'empty',
  'too-long',
  'non-ascii',
  'userinfo',
  'ip-literal',
  'syntax',
  'port',
  'wildcard',
  'label',
  'special-use',
  'single-label',
  'punycode',
] as const)

/** Why an answer was denied (src/egress/addr.ts ADDRESS_DENIALS). */
export const PROXY_ADDRESS_DENIALS = Object.freeze([
  'not-an-address',
  'this-network',
  'unspecified',
  'loopback',
  'private',
  'shared',
  'link-local',
  'unique-local',
  'ipv4-compatible',
  'ietf-protocol',
  'documentation',
  'benchmarking',
  'special-purpose',
  'multicast',
  'broadcast',
  'reserved',
  'not-global-unicast',
] as const)

/** The binding profiles (src/egress/routes.ts EGRESS_PROFILES). */
export const PROXY_PROFILES = Object.freeze(['git-fetch', 'git-push', 'github-pulls'] as const)

/** The profiles that write to a bound repository, which only a sandbox.publish grant holds (egress plan S4). */
const WRITE_PROFILES: readonly string[] = Object.freeze(['git-push', 'github-pulls'])

/**
 * The service each git profile's info/refs request names, its whole query
 * (routes.ts SERVICE_QUERY, held to it by test/events-types.test.ts through
 * matchRoute). A Map: no reason finds what an object inherits.
 */
const PROFILE_SERVICE: ReadonlyMap<string, string> = new Map([
  ['git-fetch', 'git-upload-pack'],
  ['git-push', 'git-receive-pack'],
])

/**
 * The per-grant limits a grant can be revoked on, as kernel.yaml's
 * egress.limits names them (egress plan E5, which must use these names).
 */
export const PROXY_LIMITS = Object.freeze([
  'frameMaxBytes',
  'maxFlows',
  'maxHeaderBytes',
  'maxRequests',
  'maxBytes',
  'maxDenied',
  'idleMs',
] as const)

/**
 * Why a grant ended. The first four are sandbox.killed's; `recovered` is a
 * grant a boot found issued and never revoked (egress plan W2).
 */
export const PROXY_REVOKE_REASONS = Object.freeze([
  'exited',
  'wallclock',
  'requested',
  'error',
  'violation',
  'limit',
  'recovered',
] as const)

/** The checks a boot's egress probe runs, each a reason egress is degraded (egress plan W1, W3). */
export const EGRESS_CHECKS = Object.freeze(['config', 'sandbox', 'binding', 'image', 'canary'] as const)

/** A request's path, its query never among it, in UTF-8 bytes. A longer path is stored as recordable() cuts it. */
export const EGRESS_PATH_BYTES = 1_024
/** decide()'s or the upstream's clause, which never holds the request, in UTF-8 bytes. */
export const EGRESS_WHY_BYTES = 500
/** What a revocation says happened (the frame a violation broke), in UTF-8 bytes. */
export const EGRESS_DETAIL_BYTES = 500
/** egress.degraded's reason, in UTF-8 bytes: the check that failed and the command or key that fixes it. */
export const EGRESS_REASON_BYTES = 2_048

/** The most path and query an allowed request carries, `?` included (src/egress/routes.ts MAX_PATH): all ASCII, so bytes. */
export const EGRESS_TARGET_MAX_BYTES = 8_192

/**
 * The longest request-target parseTarget reads at all, scheme and host
 * included (src/egress/routes.ts MAX_TARGET): a longer one is denied
 * 'target' before a path is read, so no row's path and query, `?` included,
 * add up to more.
 */
export const EGRESS_REQUEST_TARGET_MAX_BYTES = 8_492

/**
 * The redaction pass's mark (src/events/redact.ts CENSOR), copied as the rest
 * of this vocabulary is. A path recordable() censored no longer spells the
 * request's, nor its length or its repository, so a row whose path holds it
 * is held to its route's method and shape alone.
 */
export const EGRESS_CENSOR = '[REDACTED]'

/**
 * The redaction pass's credential shapes (src/events/redact.ts
 * TOKEN_PATTERNS), copied as CENSOR is and held equal by
 * test/events-types.test.ts. An identifier one of them matches is refused
 * (the header says why): the pass would store it censored.
 */
export const EGRESS_TOKEN_PATTERNS: readonly RegExp[] = Object.freeze([
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*/g,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bxox[abeprs]-[A-Za-z0-9-]{10,}/g,
  /\bxapp-[A-Za-z0-9-]{10,}/g,
  /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g,
  /\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/g,
])

/**
 * Whether the redaction pass leaves an identifier as it is. It replaces only
 * what a pattern matches, so it changes the text exactly when one matches;
 * search() reads a global pattern from its start and leaves its lastIndex.
 */
const uncensored = (text: string): boolean => EGRESS_TOKEN_PATTERNS.every((pattern) => text.search(pattern) === -1)
const UNCENSORED = 'an identifier in a credential shape would be stored censored, naming nothing: it is never recorded, and a grant naming one is not issued'

/** recordable()'s mark of a cut (bound.ts): the one character of a path that is not ASCII, and only at its end. */
const CUT_MARK = '\u2026'

/**
 * The most distinct deny rows the session (E8) keeps for one grant in one
 * second. Past them, the rest of that second's denies are counted on
 * overflow rows, one per deny reason and, for not-a-host, one per host
 * refusal, both closed lists: so a grant writes at most this many deny rows
 * a second, plus 21 (the deny reasons but not-a-host) plus 12 (the host
 * refusals), however many requests its container sends. Allowed requests are
 * not among them: each is its own row, as many as egress.limits.maxRequests
 * lets a grant make.
 */
export const PROXY_DENY_KEYS_PER_SECOND = 16

/** An overflow row's why: the kernel's clause, saying what the row does not record. */
export const PROXY_OVERFLOW_WHY =
  "denies past the second's bound on distinct rows, counted by reason, and a not-a-host deny by its host refusal too: their hosts, methods, paths, bindings and clauses are not recorded"

/**
 * The most repositories one grant row names, across its routes. With every
 * other field at its bound (64 hosts of 253 characters, 16 routes) the row
 * stays well inside MAX_LOGGED_OUTPUT; EgressGrant admits 16 routes of 64
 * repositories each, which no row could hold, so a grant past this is one the
 * kernel cannot record, and therefore does not issue.
 */
export const PROXY_GRANT_MAX_REPOS = 128

/** A run's id as a ref may hold it (src/egress/routes.ts RUN_REF); a grant's id has the same shape. */
export const EGRESS_REF = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
/** A binding's id, as kernel.yaml keys it (src/egress/policy.ts BINDING_ID). */
export const EGRESS_BINDING_ID = /^[a-z][a-z0-9-]{0,62}$/
/** A lower-case LDH name of two or more labels, at most 253 characters: every EgressHost (host.ts) is one. */
const EGRESS_HOST_SHAPE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
/** owner/name, lower-case: every RepoSlug (routes.ts) is one. */
const REPO_SHAPE = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9._-]{1,100}$/
/** A container the kernel made: sandbox/driver.ts CONTAINER_PREFIX, then what docker admits in a name. */
const SANDBOX_NAME_SHAPE = /^aos-run-[A-Za-z0-9_.-]{1,120}$/
/** An agent id a row is appended under: the egress session (src/egress/session.ts) parses its agentId with this one. */
export const AGENT_SHAPE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
/** A method as node:http reads one (http.METHODS: upper-case letters and a hyphen, as in M-SEARCH); the session names a deny's method only in this shape. */
export const METHOD_SHAPE = /^[A-Z][A-Z-]{0,23}$/
/**
 * An origin-form path as parseTarget (routes.ts) admits one: a slash, then
 * printable ASCII with no space, no `?` and no `#`; and recordable()'s `…`
 * after a path it cut.
 */
const PATH_SHAPE = /^\/[\x21\x22\x24-\x3e\x40-\x7e]*\u2026?$/
/** An answer, as text: an IPv4 or IPv6 address, an IPv4-mapped one at the longest. */
const ADDRESS_SHAPE = /^[0-9A-Fa-f:.]{2,45}$/
/** A resolver's or a socket's error code (ETIMEOUT, ECONNREFUSED, CERT_HAS_EXPIRED), as upstream.ts ERROR_CODE passes one on. */
export const EGRESS_ERROR_CODE = /^[A-Z][A-Z0-9_]{0,63}$/

/** An identifier of `shape` that the redaction pass leaves as it is (the header says why). */
const egressId = (shape: RegExp): z.ZodString => z.string().regex(shape).refine(uncensored, UNCENSORED)
const egressRef = (): z.ZodString => egressId(EGRESS_REF)
/** A last label a URL parser reads as an IPv4 number (host.ts NUMERIC_LABEL): a host here is a name, never an address. */
const NUMERIC_LAST_LABEL = /(?:^|\.)(?:[0-9]+|0x[0-9a-f]*)$/
const egressHost = (): z.ZodString =>
  egressId(EGRESS_HOST_SHAPE)
    .refine((host) => !NUMERIC_LAST_LABEL.test(host), 'a host is a name, and one ending in a number is an IPv4 address')
const egressBinding = (): z.ZodString => egressId(EGRESS_BINDING_ID)
/**
 * A repository as RepoSlug (routes.ts isRepoName) admits one: its name never
 * a dot segment, and never ending in .git, which a git URL reads as the same
 * repository without it. REPO_SHAPE is lower-case, so .git in any case is
 * this one spelling.
 */
const egressRepo = (): z.ZodString =>
  egressId(REPO_SHAPE).refine((repo) => {
    const name = repo.slice(repo.indexOf('/') + 1)
    return name !== '.' && name !== '..' && !name.endsWith('.git')
  }, 'a repository is owner/name, the name neither . nor .. and not ending in .git, as RepoSlug reads one')
/** At most `maxBytes` of UTF-8, as recordable() bounds it: z.string().max counts UTF-16 units, which 'é' halves. */
const withinBytes = (maxBytes: number) => (text: string): boolean => Buffer.byteLength(text, 'utf8') <= maxBytes
const egressText = (maxBytes: number): z.ZodString =>
  z.string().min(1).refine(withinBytes(maxBytes), `at most ${String(maxBytes)} bytes of UTF-8: pass it through recordable()`)

const PROXY_REASONS = Object.freeze([...PROXY_ALLOW_REASONS, ...PROXY_DENY_REASONS] as const)
const isAllowReason = (reason: string): boolean => (PROXY_ALLOW_REASONS as readonly string[]).includes(reason)
const isAfterSend = (refusal: string): boolean => (PROXY_REFUSALS_AFTER_SEND as readonly string[]).includes(refusal)
const isBeforeHost = (reason: string): boolean => (PROXY_DENIES_BEFORE_HOST as readonly string[]).includes(reason)
const isBeforePath = (reason: string): boolean => (PROXY_DENIES_BEFORE_PATH as readonly string[]).includes(reason)
const isOnARoute = (reason: string): boolean => (PROXY_DENIES_ON_A_ROUTE as readonly string[]).includes(reason)
/** The bytes of `?service=<service>`: an info/refs request's whole query. */
const serviceQueryBytes = (service: string): number => `?service=${service}`.length
const INFO_REFS = '/info/refs'

/** One request shape of a profile: its method, and its path around the repository (`<before>/<repo><after>`). */
interface RouteShape {
  readonly method: 'GET' | 'POST'
  readonly before: string
  /** A git URL's repository may carry one `.git`, which GitHub reads as the same repository. */
  readonly git: boolean
  readonly after: string
}

/**
 * The request shapes of each profile, as routes.ts matchRoute reads them
 * (its header lists them): git-fetch is GET /<repo>[.git]/info/refs or POST
 * /<repo>[.git]/git-upload-pack, git-push the same with git-receive-pack,
 * github-pulls POST /repos/<repo>/pulls. A Map: no reason finds what an
 * object inherits.
 */
const ROUTE_SHAPES: ReadonlyMap<string, readonly RouteShape[]> = new Map([
  [
    'git-fetch',
    [
      { method: 'GET', before: '', git: true, after: INFO_REFS },
      { method: 'POST', before: '', git: true, after: '/git-upload-pack' },
    ],
  ],
  [
    'git-push',
    [
      { method: 'GET', before: '', git: true, after: INFO_REFS },
      { method: 'POST', before: '', git: true, after: '/git-receive-pack' },
    ],
  ],
  ['github-pulls', [{ method: 'POST', before: '/repos', git: false, after: '/pulls' }]],
])

/** A character a repository's owner or name holds (routes.ts OWNER, REPO_NAME): never a slash. */
const REPO_CHARACTERS = '[a-z0-9._-]+'

/**
 * The repository part of a path as a pattern, read as matchRoute reads it,
 * without case: its text exactly, but for each span the redaction pass
 * censored, which stands for one or more repository characters. No
 * credential shape the pass censors matches a slash in a path (the two that
 * may hold one need a space first), and none runs on into a `.git` after it
 * (EGRESS_TOKEN_PATTERNS), so a censored span stays inside the owner or the
 * name, and the slash between them and a `.git` after the name survive it.
 */
function spelledRepo(named: string): RegExp {
  const parts = named.split(EGRESS_CENSOR).map((part) => part.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))
  return new RegExp(`^${parts.join(REPO_CHARACTERS)}$`, 'i')
}

/**
 * Whether a bound allow's method and path are a request of its profile on its
 * repository. The repository's part of the path is read as matchRoute reads
 * it, without case and with an optional `.git`; the rest is compared exactly.
 * A span the redaction pass censored no longer spells what it held, so it is
 * read as any run of repository characters, and what survived the censor is
 * still compared: `/evil/[REDACTED]/info/refs` is no path of op/fixture.
 */
function isRouteOf(reason: string, method: string, path: string, repo: string): boolean {
  return (ROUTE_SHAPES.get(reason) ?? []).some((shape) => {
    const start = `${shape.before}/`
    if (method !== shape.method || !path.startsWith(start) || !path.endsWith(shape.after)) return false
    const spelled = spelledRepo(path.slice(start.length, path.length - shape.after.length))
    return spelled.test(repo) || (shape.git && spelled.test(`${repo}.git`))
  })
}

/**
 * One request a worker sent through a grant's channel, as judged (egress
 * plan E8).
 *
 * `stage: 'policy'` is decide()'s verdict and reason, appended before anything
 * is resolved or dialled. An allow is always one request, on its own row.
 * Denies are coalesced, so a grant's container cannot flood the chain, and
 * `count` is how many requests a deny row stands for: requests every one of
 * which had exactly the fields the row names, never one that differed in
 * any. So the session (E8) merges two denies only when they agree on every
 * field the merged row names, and a row never says a request went to a host,
 * or was denied for a reason or a clause, that it did not. A coalesced row
 * (count over 1) names no path, query length or service, which its requests
 * need not share: its key is the reason, decide()'s clause, the host refusal,
 * the host, the method and the binding. At most PROXY_DENY_KEYS_PER_SECOND
 * keys are kept per grant per second; past them, the rest of that second's
 * denies are counted on overflow rows (`overflow: true`), one per reason and,
 * for not-a-host, one per host refusal. An overflow row names its reason, its
 * count and a not-a-host deny's host refusal, nothing else, and says so in
 * PROXY_OVERFLOW_WHY. parseTarget reads the host before the port, so a
 * loopback probe is not-a-host whatever port it names (192.168.5.2:8766,
 * 192.168.5.2:7777 and host.lima.internal:8766 as well as 192.168.5.2), and
 * only an egress host on a wrong port is a port deny, which names that host.
 * Among a flood of other denies a probe is therefore its own row, or a count
 * under not-a-host and its own host refusal (ip-literal for 192.168.5.2,
 * special-use for host.lima.internal), never a count under another host's,
 * and never one a typo shares.
 *
 * `stage: 'upstream'` is the upstream's refusal of a request decide() allowed:
 * it follows that request's allow row, keeps its allow reason and fields,
 * says why in `refusal`, with the answer (`address`, `denial`) or the error's
 * `code` where one is the reason, and says in `sent` whether the request
 * left. Not sent (an answer that is not global unicast, a dial that failed, a
 * certificate that did not verify, an abort or a timeout before the head was
 * written): nothing of it reached the host, and the verdict is deny. Sent
 * (its head, the injected credential with it, was taken to send before the
 * host stopped answering, the connection closed, the wallclock aborted it or
 * the body broke its length): the host may have acted on it, a push applied
 * or a pull request opened, so the verdict stays allow, and the row records a
 * request that left and failed. The log never calls a sent request a deny.
 * `challenged` and `response-head` are the session's own (E8): the host
 * answered 401 or 403, or with a head node:http will not write, which the
 * worker reads as a 502, so the request was sent and the row is an allow.
 *
 * An allowed request is named in full: its host, method and path, how many
 * bytes its path and query held, and on a bound route the binding whose
 * credential rides it and the repository. Its method and path are a request
 * its reason admits: GET or HEAD on a credential-free host, and on a bound
 * route one of its profile's shapes (ROUTE_SHAPES) on the repository it
 * names. A deny names at most what decide() had read when it stopped: no host
 * before the host (PROXY_DENIES_BEFORE_HOST; a not-a-host deny says why in
 * `hostRefusal`), no path before the path (PROXY_DENIES_BEFORE_PATH), a
 * binding only past a bound route (PROXY_DENIES_ON_A_ROUTE), and never a
 * repository, which an EgressDenied does not carry (its path, when kept,
 * spells the one asked for). A binding is found only from a host, and a
 * service is the query of a path. An uncut, uncensored path is `pathBytes`
 * long; a cut one is what recordable() keeps of a path longer than
 * EGRESS_PATH_BYTES, exactly that many bytes with its mark; and no path and
 * query outrun the longest target parseTarget reads. The run is the row's own
 * runId, from the kernel's grant map, never from the container, and
 * `grantId` joins the row to its grant.
 */
export const ProxyDecisionPayload = z
  .object({
    ...V,
    grantId: egressRef(),
    stage: z.enum(['policy', 'upstream']),
    verdict: z.enum(['allow', 'deny']),
    reason: z.enum(PROXY_REASONS),
    refusal: z.enum(PROXY_UPSTREAM_REFUSALS).optional(),
    sent: z.boolean().optional(),
    count: z.number().int().positive(),
    overflow: z.literal(true).optional(),
    method: egressId(METHOD_SHAPE).optional(),
    host: egressHost().optional(),
    path: z.string().regex(PATH_SHAPE).refine(withinBytes(EGRESS_PATH_BYTES), `a path is at most ${String(EGRESS_PATH_BYTES)} bytes: pass it through recordable()`).optional(),
    /** The path's length as the request had it, before any cut. */
    pathBytes: z.number().int().positive().optional(),
    /** The query's length, its `?` included; 0 when the target has none. */
    queryBytes: nonNegInt().optional(),
    service: z.enum(['git-upload-pack', 'git-receive-pack']).optional(),
    bindingId: egressBinding().optional(),
    repo: egressRepo().optional(),
    hostRefusal: z.enum(PROXY_HOST_REFUSALS).optional(),
    address: z.string().regex(ADDRESS_SHAPE).optional(),
    denial: z.enum(PROXY_ADDRESS_DENIALS).optional(),
    code: egressId(EGRESS_ERROR_CODE).optional(),
    why: egressText(EGRESS_WHY_BYTES),
  })
  .strict()
  .superRefine((row, ctx) => {
    const issue = (message: string): void => ctx.addIssue({ code: 'custom', message })
    const allowed = isAllowReason(row.reason)
    const policyDeny = row.stage === 'policy' && row.verdict === 'deny'
    const overflow = row.overflow === true
    const notAHost = row.stage === 'policy' && row.reason === 'not-a-host'

    if (row.stage === 'policy') {
      if (row.verdict === 'allow' && !allowed) issue('a policy allow names one of the reasons decide() allows for')
      if (row.verdict === 'deny' && allowed) issue('a policy deny names one of the reasons decide() denies for')
      if (row.refusal !== undefined || row.sent !== undefined || row.address !== undefined || row.denial !== undefined || row.code !== undefined) {
        issue('only an upstream row names a refusal, whether the request was sent, an answer, a denial or an error code')
      }
    } else {
      if (!allowed) issue('an upstream row keeps the reason decide() allowed the request for')
      if (row.refusal === undefined || row.sent === undefined) {
        issue('an upstream row names its refusal and whether the request was sent')
      } else {
        if (row.verdict !== (row.sent ? 'allow' : 'deny')) {
          issue('an upstream row is a deny exactly when nothing of the request left: one that was sent is an allow that failed')
        }
        if (row.sent && !isAfterSend(row.refusal)) issue('only a refusal the upstream can meet after the head was written comes with a sent request')
        if (!row.sent && PROXY_ANSWERED_REFUSALS.includes(row.refusal)) issue('a challenge, or a head the session could not pass on, is the host answering the request, so the request was sent')
      }
    }

    // What one row stands for.
    if (row.count !== 1 && !policyDeny) issue('only a policy deny stands for more than one request')
    // A deny names no repository at all (beneath), so neither does a coalesced one.
    if (row.count > 1 && (row.path !== undefined || row.pathBytes !== undefined || row.queryBytes !== undefined || row.service !== undefined)) {
      issue('a coalesced deny names no path, query length or service: it stands only for what its requests shared')
    }
    if (overflow) {
      // Stated for itself: an allow or an upstream row always names its host,
      // method and path, so the check beneath refuses one as well.
      if (!policyDeny) issue('only a policy deny overflows')
      // Its key is the reason, and a not-a-host deny's host refusal, which the
      // rules beneath require there and refuse elsewhere: both closed lists.
      // A repository no deny names (beneath).
      const named = [row.method, row.host, row.path, row.pathBytes, row.queryBytes, row.service, row.bindingId]
      if (named.some((field) => field !== undefined)) issue("an overflow row names its reason, its count and a not-a-host deny's host refusal alone")
      if (row.why !== PROXY_OVERFLOW_WHY) issue('an overflow row says what it counted by, in PROXY_OVERFLOW_WHY')
    }

    // A host that was none, a binding found from a host, and an answer that was refused.
    if (row.hostRefusal !== undefined && !(row.stage === 'policy' && row.reason === 'not-a-host')) {
      issue('hostRefusal says why a not-a-host deny read no host')
    }
    if (notAHost && row.hostRefusal === undefined) issue("a not-a-host deny says why the target's host was none, on an overflow row too")
    // What a deny had read when its reason stopped decide() (PROXY_DENIES_*).
    // An upstream row keeps its allow's fields, so only a policy deny is held here.
    if (policyDeny) {
      if (isBeforeHost(row.reason) && row.host !== undefined) {
        issue('a deny decide() gives before it reads a host names none: a CONNECT, a target it cannot read, a host that is none')
      }
      if (isBeforePath(row.reason) && row.path !== undefined) issue('a deny decide() gives before it reads a path names none: parseTarget refuses the port before the path')
      if (row.bindingId !== undefined && !isOnARoute(row.reason)) issue('a deny names a binding only for a reason decide() gives past a bound route')
      if (row.repo !== undefined) issue('a deny names no repository: decide() denies with none, and the path, when kept, spells the one asked for')
    }
    if (row.bindingId !== undefined && row.host === undefined) issue('a binding is found only from a host, so a row naming one names the host')
    if (row.denial !== undefined && row.refusal !== 'denied-address') issue('denial belongs to a denied-address refusal')
    if (row.address !== undefined && row.refusal !== 'denied-address' && row.refusal !== 'host-address') {
      issue('address is the answer a denied-address or host-address refusal names')
    }
    if (row.refusal === 'denied-address') {
      if (row.denial === undefined) issue('a denied-address refusal names its denial')
      else if ((row.address === undefined) !== (row.denial === 'not-an-address')) {
        issue('a denied-address refusal names its answer, unless the answer was no address at all, which is never stored')
      }
    }
    if (row.refusal === 'host-address' && row.address === undefined) issue('a host-address refusal names the answer')

    // The path, how much the request carried, and the one query stored.
    if ((row.path === undefined) !== (row.pathBytes === undefined) || (row.path === undefined) !== (row.queryBytes === undefined)) {
      issue("a path comes with its length and its query's, and neither length comes without it")
    }
    // Censored, a path is no longer the request's, nor as long as it was.
    if (row.path !== undefined && row.pathBytes !== undefined && !row.path.includes(EGRESS_CENSOR)) {
      if (!row.path.endsWith(CUT_MARK) && row.pathBytes !== row.path.length) issue('an uncut path is as long as the request had it: pathBytes is its length')
      // recordable() cuts a path only past its budget, and keeps exactly the
      // budget, the mark's three bytes included: a path is ASCII, so nothing
      // shorter is cut short of it.
      if (row.path.endsWith(CUT_MARK) && Buffer.byteLength(row.path, 'utf8') !== EGRESS_PATH_BYTES) {
        issue(`a cut path is what recordable() keeps of it: exactly ${String(EGRESS_PATH_BYTES)} bytes, its mark included`)
      }
      if (row.path.endsWith(CUT_MARK) && row.pathBytes <= EGRESS_PATH_BYTES) issue(`a cut path was longer than the ${String(EGRESS_PATH_BYTES)} bytes recordable() keeps`)
    }
    if (row.pathBytes !== undefined && row.queryBytes !== undefined && row.pathBytes + row.queryBytes > EGRESS_REQUEST_TARGET_MAX_BYTES) {
      issue(`no row's path and query add up to more than the ${String(EGRESS_REQUEST_TARGET_MAX_BYTES)} bytes of the longest target parseTarget reads`)
    }
    if (row.service !== undefined) {
      if (row.path === undefined) issue('service is the query of an info/refs request, so a row naming one names its path')
      // allow-host and github-pulls read none: PROFILE_SERVICE names no service for them.
      if (allowed && PROFILE_SERVICE.get(row.reason) !== row.service) {
        issue("an allowed request's service is its own profile's: git-fetch reads git-upload-pack, git-push git-receive-pack, and no other route reads one")
      }
      if (row.reason === 'query') issue('a query deny refused a query that names no service, and the query is not stored')
      if (row.path !== undefined && !row.path.endsWith(INFO_REFS)) issue('service is the query of an info/refs request')
      if (row.queryBytes !== undefined && row.queryBytes !== serviceQueryBytes(row.service)) issue('service is the whole query: ?service=<it>')
    }

    if (allowed) {
      if (row.host === undefined || row.method === undefined || row.path === undefined) {
        issue('an allowed request names its host, method and path')
      }
      const free = row.reason === 'allow-host'
      if (free && (row.bindingId !== undefined || row.repo !== undefined)) {
        issue('a credential-free host carries no binding and no repository')
      }
      if (!free && (row.bindingId === undefined || row.repo === undefined)) {
        issue('a request on a bound route names its binding and repository')
      }
      // decide()'s judgeFree: read-only.
      if (free && row.method !== undefined && row.method !== 'GET' && row.method !== 'HEAD') issue('a credential-free host admits GET and HEAD only')
      // The request the credential rode is one its profile names, on the repository the row names.
      if (!free && row.method !== undefined && row.path !== undefined && row.repo !== undefined && !isRouteOf(row.reason, row.method, row.path, row.repo)) {
        issue("a bound allow's method and path are a request of its profile on its repository")
      }
      if (row.path !== undefined && row.pathBytes !== undefined && row.queryBytes !== undefined) {
        if (row.pathBytes + row.queryBytes > EGRESS_TARGET_MAX_BYTES) {
          issue(`an allowed request carries at most ${String(EGRESS_TARGET_MAX_BYTES)} bytes of path and query, the most the upstream sends`)
        }
        if (PROFILE_SERVICE.has(row.reason) && row.path.endsWith(INFO_REFS) && row.service === undefined) {
          issue('an info/refs request of a git route names the service it asked for')
        }
        if (!free && row.service === undefined && row.queryBytes !== 0) issue('a bound route takes no query but an info/refs service')
      }
    }
  })

/** A bound host as one grant holds it: whose credential, which profiles, which repositories. Never the header or its value. */
const ProxyGrantRoute = z
  .object({
    bindingId: egressBinding(),
    host: egressHost(),
    profiles: z.array(z.enum(PROXY_PROFILES)).min(1).max(PROXY_PROFILES.length),
    repos: z.array(egressRepo()).min(1).max(64),
  })
  .strict()

/**
 * What one container's channel may reach: issued before the container starts
 * (egress plan W1), and named by every decision made under it.
 *
 * One container is one grant, so a decision is attributed by the channel it
 * came in on, never by anything the container says. `purpose` is what the
 * grant serves. An `exec` grant holds only git-fetch and credential-free
 * hosts, so a row naming git-push or github-pulls for one is refused here as
 * well as never built: only a human-approved sandbox.publish holds the
 * profiles that write (S4). A `canary` grant is the boot's channel check (W3):
 * no run, no agent, nothing to reach. Only the trusted domain is ever granted;
 * the hostile domain gets no channel and no egress.
 *
 * A route names its binding by id, its host, the profiles this grant holds of
 * it and its repositories. Which header the binding injects is configuration
 * (kernel.booted's configHash), and its value is the broker's alone. The row
 * holds the rules EgressGrant (src/egress/policy.ts) holds a grant to: a host
 * listed once and either credential-free or bound, never both; a binding
 * routed once; a profile listed once a route; a repository on a host in one
 * route. decide() denies every request under a grant that breaks one as
 * malformed, so a row that broke one would record a reach the kernel never
 * gave, and could not say whether a credential rides a host.
 */
export const ProxyGrantIssuedPayload = z
  .object({
    ...V,
    grantId: egressRef(),
    purpose: z.enum(['exec', 'publish', 'canary']),
    runId: egressRef().optional(),
    agentId: egressId(AGENT_SHAPE).optional(),
    sandbox: egressId(SANDBOX_NAME_SHAPE),
    domain: z.literal('trusted'),
    allow: z.array(egressHost()).max(64),
    routes: z.array(ProxyGrantRoute).max(16),
  })
  .strict()
  .superRefine((grant, ctx) => {
    const issue = (message: string): void => ctx.addIssue({ code: 'custom', message })
    const routes = grant.routes ?? []
    if (grant.purpose === 'canary') {
      if (grant.runId !== undefined || grant.agentId !== undefined) issue('a canary grant serves no run and no agent')
      if ((grant.allow ?? []).length > 0 || routes.length > 0) issue('a canary grant reaches nothing')
    } else if (grant.runId === undefined || grant.agentId === undefined) {
      issue('an exec or publish grant names its run and its agent')
    }
    if (grant.purpose === 'exec' && routes.some((route) => (route.profiles ?? []).some((p) => WRITE_PROFILES.includes(p)))) {
      issue('an exec grant holds no git-push and no github-pulls: only sandbox.publish writes')
    }
    if (routes.reduce((sum, route) => sum + (route.repos ?? []).length, 0) > PROXY_GRANT_MAX_REPOS) {
      issue(`a grant row names at most ${String(PROXY_GRANT_MAX_REPOS)} repositories`)
    }
    // EgressGrant's rules, as policy.ts holds a grant to them.
    if (new Set(grant.allow).size !== grant.allow.length) issue('a host is listed twice in allow')
    if (new Set(routes.map((route) => route.bindingId)).size !== routes.length) issue('a binding is routed twice')
    const bound = new Set<string>()
    for (const route of routes) {
      if (grant.allow.includes(route.host)) issue('a host is both credential-free and bound')
      if (new Set(route.profiles).size !== route.profiles.length) issue('a route lists a profile twice')
      for (const repo of route.repos) {
        const key = `${route.host} ${repo}`
        if (bound.has(key)) issue('a repository on a host is in two routes')
        bound.add(key)
      }
    }
  })

/**
 * A grant's whole traffic, in place of a row per flow.
 *
 * `requests` are the requests decide() judged, every one of them `allowed` or
 * `denied` (a coalesced or overflow deny counted once per request). Of the
 * allowed ones, `refused` are those the upstream refused before any byte of
 * them left, and `failed` those it sent that ended before a response (its
 * upstream rows with `sent` true). `sentBytes` are the request body bytes sent
 * to upstream hosts and `receivedBytes` the response body bytes received from
 * them: never a head, since a request's head carries the injected credential,
 * and a count with it in would be a function of the credential's length.
 */
const ProxyGrantTotals = z
  .object({
    flows: nonNegInt(),
    requests: nonNegInt(),
    allowed: nonNegInt(),
    denied: nonNegInt(),
    refused: nonNegInt(),
    failed: nonNegInt(),
    sentBytes: nonNegInt(),
    receivedBytes: nonNegInt(),
    durationMs: nonNegInt(),
  })
  .strict()
  .superRefine((totals, ctx) => {
    const issue = (message: string): void => ctx.addIssue({ code: 'custom', message })
    // Each sum is of safe integers: one past 2^53 is at least 2^53 as a
    // float, never equal to a safe integer, so neither check passes in error.
    if (totals.allowed + totals.denied !== totals.requests) issue('every request judged was allowed or denied: allowed and denied add up to requests')
    if (totals.refused + totals.failed > totals.allowed) issue('the upstream refuses or fails only requests decide() allowed')
  })

/**
 * A grant ended: its container exited, the wallclock or a kill stopped it, an
 * error ended it, it broke the channel's protocol (`violation`, with `detail`
 * saying how), or it hit a per-grant limit (`limit` names which). Every
 * decision under it is before this row.
 *
 * `totals` are the flows the mux opened, the requests judged and how each
 * ended, the body bytes each way, and how long the grant lived
 * (ProxyGrantTotals). A `recovered` grant, one a boot found issued and never
 * revoked (W2), carries none: the kernel that kept the counts died with them,
 * and zeros would claim that nothing happened.
 */
export const ProxyGrantRevokedPayload = z
  .object({
    ...V,
    grantId: egressRef(),
    reason: z.enum(PROXY_REVOKE_REASONS),
    limit: z.enum(PROXY_LIMITS).optional(),
    detail: egressText(EGRESS_DETAIL_BYTES).optional(),
    totals: ProxyGrantTotals.optional(),
  })
  .strict()
  .superRefine((revoked, ctx) => {
    const issue = (message: string): void => ctx.addIssue({ code: 'custom', message })
    if ((revoked.limit !== undefined) !== (revoked.reason === 'limit')) issue('a limit is named exactly when a limit revoked the grant')
    if (revoked.reason === 'violation' && revoked.detail === undefined) issue('a violation says what the container broke')
    if ((revoked.totals === undefined) !== (revoked.reason === 'recovered')) {
      issue('a revocation carries totals, except a recovered one, whose counts died with the kernel that kept them')
    }
  })

/**
 * Egress cannot run (egress plan W1, W3). `check` is the check that failed,
 * and `reason` says what failed and the command or key that fixes it, as
 * sandbox.degraded's does. `domain` is the VM an image or a canary check failed
 * on; `bindingId` the binding whose credential did not resolve or was refused.
 */
export const EgressDegradedPayload = z
  .object({
    ...V,
    check: z.enum(EGRESS_CHECKS),
    domain: z.enum(['trusted', 'hostile']).optional(),
    bindingId: egressBinding().optional(),
    reason: egressText(EGRESS_REASON_BYTES),
  })
  .strict()
  .superRefine((degraded, ctx) => {
    const issue = (message: string): void => ctx.addIssue({ code: 'custom', message })
    if ((degraded.bindingId !== undefined) !== (degraded.check === 'binding')) issue('a binding is named exactly when the binding check failed')
    if ((degraded.check === 'image' || degraded.check === 'canary') && degraded.domain === undefined) {
      issue('an image or canary check names the domain it failed on')
    }
    if ((degraded.check === 'config' || degraded.check === 'binding') && degraded.domain !== undefined) {
      issue('a config or binding check is of no domain')
    }
  })

// ── the frozen list ────────────────────────────────────────────────────────

export const EVENT_TYPES = [
  'kernel.booted',
  'kernel.shutdown',
  'subsystem.state',
  'chain.anchored',
  'control.connected',
  'control.rejected',
  'hub.connected',
  'hub.degraded',
  'hub.tools.classified',
  'sandbox.degraded',
  'router.degraded',
  'secrets.degraded',
  'goals.degraded',
  'agent.registered',
  'agent.spawned',
  'agent.spawn.rejected',
  'agent.promotion.requested',
  'agent.promoted',
  'agent.archived',
  'run.scheduled',
  'run.queued',
  'run.started',
  'run.parked',
  'run.resumed',
  'run.finished',
  'llm.request',
  'llm.response',
  'tool.gate',
  'tool.call',
  'tool.result',
  'approval.requested',
  'approval.resolved',
  'quarantine.held',
  'quarantine.released',
  'quarantine.abandoned',
  'sandbox.started',
  'sandbox.killed',
  'secret.accessed',
  'probe.recorded',
  'plan.adopted',
  'goal.created',
  'goal.status',
  'goal.unconfirmed',
  'delegation.admitted',
  'delegation.result',
  'delegation.refused',
  'proxy.decision',
  'proxy.grant.issued',
  'proxy.grant.revoked',
  'egress.degraded',
] as const

export type EventType = (typeof EVENT_TYPES)[number]

export const PAYLOAD_SCHEMAS: Readonly<Record<EventType, z.ZodType>> = {
  'kernel.booted': KernelBootedPayload,
  'kernel.shutdown': KernelShutdownPayload,
  'subsystem.state': SubsystemStatePayload,
  'chain.anchored': ChainAnchoredPayload,
  'control.connected': ControlConnectedPayload,
  'control.rejected': ControlRejectedPayload,
  'hub.connected': HubConnectedPayload,
  'hub.degraded': HubDegradedPayload,
  'hub.tools.classified': HubToolsClassifiedPayload,
  'sandbox.degraded': SandboxDegradedPayload,
  'router.degraded': RouterDegradedPayload,
  'secrets.degraded': SecretsDegradedPayload,
  'goals.degraded': GoalsDegradedPayload,
  'agent.registered': AgentRegisteredPayload,
  'agent.spawned': AgentSpawnedPayload,
  'agent.spawn.rejected': AgentSpawnRejectedPayload,
  'agent.promotion.requested': AgentPromotionRequestedPayload,
  'agent.promoted': AgentPromotedPayload,
  'agent.archived': AgentArchivedPayload,
  'run.scheduled': RunScheduledPayload,
  'run.queued': RunQueuedPayload,
  'run.started': RunStartedPayload,
  'run.parked': RunParkedPayload,
  'run.resumed': RunResumedPayload,
  'run.finished': RunFinishedPayload,
  'llm.request': LlmRequestPayload,
  'llm.response': LlmResponsePayload,
  'tool.gate': ToolGatePayload,
  'tool.call': ToolCallPayload,
  'tool.result': ToolResultPayload,
  'approval.requested': ApprovalRequestedPayload,
  'approval.resolved': ApprovalResolvedPayload,
  'quarantine.held': QuarantineHeldPayload,
  'quarantine.released': QuarantineReleasedPayload,
  'quarantine.abandoned': QuarantineAbandonedPayload,
  'sandbox.started': SandboxStartedPayload,
  'sandbox.killed': SandboxKilledPayload,
  'secret.accessed': SecretAccessedPayload,
  'probe.recorded': ProbeRecordedPayload,
  'plan.adopted': PlanAdoptedPayload,
  'goal.created': GoalCreatedPayload,
  'goal.status': GoalStatusPayload,
  'goal.unconfirmed': GoalUnconfirmedPayload,
  'delegation.admitted': DelegationAdmittedPayload,
  'delegation.result': DelegationResultPayload,
  'delegation.refused': DelegationRefusedPayload,
  'proxy.decision': ProxyDecisionPayload,
  'proxy.grant.issued': ProxyGrantIssuedPayload,
  'proxy.grant.revoked': ProxyGrantRevokedPayload,
  'egress.degraded': EgressDegradedPayload,
}

export function isEventType(t: string): t is EventType {
  return (EVENT_TYPES as readonly string[]).includes(t)
}
