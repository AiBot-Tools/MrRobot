// kernel.yaml schema and loader.
//
// Configuration is data, and this is where that data is checked before any of
// it can hurt. Three refinements do the real work:
//
//   The control host is the LITERAL '127.0.0.1'. Not a validated string, not
//   a default an operator can edit: there is no spelling of kernel.yaml that
//   binds the control plane to a public interface (invariant 1).
//
//   dataDir and every mountRoot live in `<repo>/.aos` (the shipped default,
//   operator decision 2026-10: everything in the program folder) or outside
//   the repository — never elsewhere inside it, never $HOME itself, and never
//   a directory that CONTAINS the repository or $HOME. Inside the repo they are
//   admitted only while .gitignore ignores `/.aos/`, so the event log can never
//   be committed. A mountRoot containing $HOME or the repo would hand a
//   container everything (invariant 9).
//
//   A walk of the raw document rejects any key whose name looks like a
//   secret, or that names part of a JavaScript object (`__proto__`, which
//   the schema would drop, and `constructor` and `prototype`, as a
//   precaution), naming the path. CLAUDE.md says kernel.yaml holds no
//   secrets; this makes that structural rather than a habit, and the path is
//   named because "there is a secret somewhere in your config" is not an
//   actionable error.
//
// Every numeric field is positive and no field admits "unlimited". A budget
// that can be switched off is not a budget.

import { isAbsolute, join, resolve, sep } from 'node:path'
import { z } from 'zod'

import { ConfigError } from './errors.js'
import { rootGitignoreIgnores } from './gitignore.js'
import { entryProblem, homeDirectory, identify, isSpelledUnder, isUnder, realpathNearest, type Identify } from './agents/protected.js'
import { EgressHost } from './egress/host.js'
import { BINDING_ID } from './egress/policy.js'
import { EGRESS_PROFILES, EgressProfileName, PUSH_ROOT, RepoSlug } from './egress/routes.js'
import { DENY_KEYS, redactString } from './events/redact.js'
import type { ProvidersFile } from './models/registry.js'
import { isDockerNetworkMode, isImageId, isNetworkName, isNoNetwork, isUnprivilegedUser, memoryBytes } from './sandbox/limits.js'

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

const posInt = () => z.number().int().positive()

/** A URL whose hostname is loopback. */
function isLoopbackUrl(value: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(value).hostname.replace(/^\[|\]$/g, '')) ||
      /^127\.\d+\.\d+\.\d+$/.test(new URL(value).hostname)
  } catch {
    return false
  }
}

/** tauri://localhost, or an http(s) origin on a loopback hostname (D10). */
function isAllowedOrigin(value: string): boolean {
  if (value === 'tauri://localhost') return true
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    const host = url.hostname.replace(/^\[|\]$/g, '')
    return LOOPBACK_HOSTS.has(host) || /^127\.\d+\.\d+\.\d+$/.test(host)
  } catch {
    return false
  }
}

const Control = z
  .object({
    // Literal, not a choice. See the file header.
    host: z.literal('127.0.0.1').default('127.0.0.1'),
    // A privileged port is refused; the literal 0 is allowed and means "let
    // the OS pick an ephemeral one", which is how parallel test processes avoid
    // colliding and why ControlServer reads its bound port back from the
    // socket. 0 is not a privileged port — it is a request, and the OS answers
    // with something well above the floor.
    port: z
      .union([z.literal(0), z.number().int().min(1024).max(65_535)])
      .default(7777),
    tokenEnv: z.literal('AOS_CONTROL_TOKEN').default('AOS_CONTROL_TOKEN'),
    allowedOrigins: z
      .array(z.string())
      .default([])
      .refine((list) => list.every(isAllowedOrigin), {
        message: 'allowedOrigins entries must be tauri://localhost or an http(s) loopback origin',
      }),
    maxPayloadBytes: posInt().default(1_048_576),
  })
  .strict()

const Events = z.object({ anchorEvery: posInt().default(100) }).strict()

/**
 * The name a tokenEnv may take: upper case, digits and `_`, starting with a
 * letter, as `.env.example` and every credential name here are. A shell cannot
 * export a name holding `-`, `.` or a space and the `.env` loader reads no line
 * that holds one, so such a bearer is never found and the hub degrades over a
 * value the operator believes is set. Upper case also closes the way round the
 * prefix rule below: pmmcp reads its settings without regard to case
 * (pydantic-settings, case_sensitive=False), so an exported
 * `pmmcp_server__port` sets its port as `PMMCP_SERVER__PORT` would (checked
 * against pmmcp's e646096, 2026-10-29).
 */
const TOKEN_ENV_NAME = /^[A-Z][A-Z0-9_]*$/

/**
 * `PMMCP_` is pmmcp's own prefix (decision D34). Its load_config reads an
 * exported `PMMCP_<SECTION>__<KEY>` as a setting, in any case, and refuses to
 * start under a misspelt section or a bare section name (`PMMCP_SERVER`); a
 * pmmcp checkout up to 53ea308 refuses to start under any `PMMCP_` name that
 * is no setting (pydantic extra_forbidden, checked 2026-10-28; the narrower
 * reading is pmmcp's 235992d, checked 2026-10-29). A kernel bearer may be
 * exported from the operator's shell (a non-blank export wins at boot), and
 * that shell may be the one that starts pmmcp, so no kernel credential name
 * enters that namespace, whichever pmmcp is installed.
 */
const PMMCP_PREFIX = 'PMMCP_'

/** Why no credential name the kernel reads may start with PMMCP_ (decision D34), for every refusal of one. */
const PMMCP_PREFIX_WHY =
  "pmmcp's own prefix: pmmcp's load_config reads an exported PMMCP_<SECTION>__<KEY> as a setting, in any case, and " +
  'refuses to start under a bare section name such as PMMCP_SERVER, and a pmmcp checkout up to 53ea308 refuses to ' +
  'start under any PMMCP_ name that is no setting (decision D34)'

/** The server whose bearer is AOS_PMMCP_TOKEN, as pmmcp's client aos-kernel. */
const PMMCP_SERVER = 'pmmcp'

const TokenEnv = z.string().regex(TOKEN_ENV_NAME, {
  message: 'mcp server tokenEnv must be an upper-case .env name: A-Z, 0-9 and _, starting with a letter',
})

/**
 * The prefix refusal, its way out worded by server. Only pmmcp's bearer is
 * AOS_PMMCP_TOKEN: a second server told the same would declare pmmcp's name,
 * and the hub would send pmmcp's bearer to that service.
 */
function prefixRefusal(server: string): string {
  const wayOut =
    server === PMMCP_SERVER
      ? 'Name it AOS_PMMCP_TOKEN, or another name that does not start with PMMCP_'
      : `Give ${server} an AOS_ name of its own, not AOS_PMMCP_TOKEN: that is pmmcp's bearer, and ${server} would be sent it`
  return `mcp server tokenEnv must not start with PMMCP_, ${PMMCP_PREFIX_WHY}. ${wayOut}`
}

const McpServer = z
  .object({
    url: z.string().refine(isLoopbackUrl, { message: 'mcp server url must have a loopback hostname' }),
    tokenEnv: TokenEnv.optional(),
    heartbeatMs: posInt().default(240_000),
    requestTimeoutMs: posInt().default(30_000),
    pingTimeoutMs: posInt().default(10_000),
    listToolsTimeoutMs: posInt().default(15_000),
  })
  .strict()

/**
 * The server ids tool-views.yaml gives the kernel's own tools: `kernel`
 * (src/runtime/kernel-tools.ts KERNEL_SERVER) and `sandbox`
 * (src/runtime/sandbox-tools.ts SANDBOX_SERVER), held equal to both by
 * test/config.test.ts. No MCP server may take either: the hub classifies a
 * server's tools by the tool-views section of its own id, so an MCP server
 * called sandbox would have its `exec` exposed to agents as sandbox.exec is,
 * and the hub would run it, with none of the kernel's checks behind it.
 */
export const KERNEL_NATIVE_SERVERS: readonly string[] = ['kernel', 'sandbox']

const Mcp = z
  .object({
    servers: z.record(z.string().min(1), McpServer).superRefine((servers, ctx) => {
      for (const server of Object.keys(servers)) {
        if (KERNEL_NATIVE_SERVERS.includes(server)) {
          ctx.addIssue({
            code: 'custom',
            path: [server],
            message:
              `mcp server id ${server} is the kernel's own: tool-views.yaml's ${server} section classifies the ` +
              "kernel's native tools, and an MCP server of that name would have its tools exposed by it. Name the server otherwise",
          })
        }
      }
      for (const [server, entry] of Object.entries(servers)) {
        if (typeof entry.tokenEnv === 'string' && entry.tokenEnv.startsWith(PMMCP_PREFIX)) {
          ctx.addIssue({ code: 'custom', path: [server, 'tokenEnv'], message: prefixRefusal(server) })
        }
      }
    }),
  })
  .strict()
  .refine((m) => PMMCP_SERVER in m.servers, { message: 'mcp.servers must include pmmcp' })

/**
 * Where provider credentials come from.
 *
 * `env` (the default): each entry's own `auth.envVar`, from the env bootKernel
 * receives — a shell export that is not blank, else the operator's <repo>/.env, read by
 * the entry point's --dotenv (src/secrets/dotenv.ts), never by this module.
 *
 * `vault`: pmmcp's `get_secret`, then `envFallback` if that is on (D8). Kept,
 * DORMANT: pmmcp's `get_secret` never returns plaintext — it answers with a
 * masked sentence by design — so against the real server this path can only
 * refuse. It exists for a pmmcp that one day authenticates its callers and
 * hands a value to exactly one of them.
 */
const Secrets = z
  .object({
    source: z.enum(['env', 'vault']).default('env'),
    // Confirmed against the live get_secret schema; the broker still asserts
    // it at runtime and fails closed if the server disagrees.
    keyArg: z.string().min(1).default('label'),
    envFallback: z.boolean().default(false),
  })
  .strict()
  .refine((s) => !(s.source === 'env' && s.envFallback), {
    message: 'secrets.envFallback is a fallback FROM the vault, so it needs secrets.source: vault',
  })

/**
 * The pmmcp goal tools, as CONFIG rather than constants.
 *
 * The defaults match the operator's live capture of 2026-10-18, which the
 * typed wrappers in src/goals/pmmcp.ts and src/mcp/pmmcp-schemas.ts are held
 * to: `update_goal` (goal_id, status, progress_pct — and NO project_id),
 * `get_goal_tree` (goal_id only), `parent_goal_id` and `goal_type`.
 *
 * Still config, and still checked against the connected server at boot, which
 * DEGRADES the goals subsystem with a reason naming any tool or argument that
 * disagrees, any argument it requires that the kernel does not send, and any
 * type that no longer admits what it sends: a pmmcp upgrade is one line of
 * YAML, not a patch.
 */
const GoalTools = z
  .object({
    create: z.string().min(1).default('create_goal'),
    updateStatus: z.string().min(1).default('update_goal'),
    get: z.string().min(1).default('get_goal_tree'),
    list: z.string().min(1).default('list_goals'),
  })
  .strict()

const GoalArgs = z
  .object({
    projectId: z.string().min(1).default('project_id'),
    goalId: z.string().min(1).default('goal_id'),
    parentId: z.string().min(1).default('parent_goal_id'),
    kind: z.string().min(1).default('goal_type'),
    title: z.string().min(1).default('title'),
    status: z.string().min(1).default('status'),
    /** Sent as 100 with `review`, so a finished task is visible as finished. */
    progress: z.string().min(1).default('progress_pct'),
  })
  .strict()

/**
 * Kernel status → the status pmmcp is sent.
 *
 * pmmcp's vocabulary is pending, in_progress, completed, abandoned, blocked.
 * It has no `review`, and the kernel never sets `completed` (finishing is the
 * operator's decision). So `review` is sent as `in_progress` with progress 100,
 * and stays `review` in the kernel's own log.
 */
const GoalStatuses = z
  .object({
    in_progress: z.string().min(1).default('in_progress'),
    blocked: z.string().min(1).default('blocked'),
    review: z.string().min(1).default('in_progress'),
  })
  .strict()

const Goals = z
  .object({
    /**
     * Adopt a plan found in a finished orchestrator run and write the tree.
     *
     * On by default because it is the designed behaviour, and the write is
     * confined to the agent's own memory namespace and logged as
     * `plan.adopted` + `goal.created`. Off is for an operator who wants the CEO
     * observed before it writes anything durable.
     */
    adoptFromRuns: z.boolean().default(true),
    tools: GoalTools.prefault({}),
    args: GoalArgs.prefault({}),
    statuses: GoalStatuses.prefault({}),
  })
  .strict()

/**
 * The longest delay a Node timer takes, 2^31 - 1 ms (about 24.8 days):
 * setTimeout and socket.setTimeout given more fire after 1 ms, with a
 * TimeoutOverflowWarning. Every delay kernel.yaml names that becomes a timer
 * is bounded by it: an idle limit past it would revoke every grant as idle at
 * once, and a container wallclock past it would kill every container 1 ms
 * after it starts (the driver's wallclock is a setTimeout, docker.ts), so each
 * is refused here, not discovered at the first grant or run.
 */
export const MAX_TIMER_MS = 2_147_483_647

const SandboxDomain = z
  .object({
    dockerHost: z.string().startsWith('unix://'),
    // The domain's internal network. No run is put on it (every run is
    // --network none); probe() proves it Internal=true on the domain's VM, as
    // defence in depth. A plain name: docker reads `name=host` as host
    // (sandbox/limits.ts), and probe() would inspect a network of that literal
    // name. Nor one docker keeps for itself: host, bridge and default are never
    // internal, and docker refuses to recreate one --internal; none is no
    // network at all, the one every run is on already, and no internal network
    // to prove. Nor any of those in another case: a plain HOST names a network
    // of that name, but docker's key=value spelling lower-cases (name=HOST is
    // host). probe() refuses every such name without inspecting it, with
    // container:<id>; this refuses them earlier, so that no kernel boots on a
    // domain whose sandbox probe() would report degraded.
    network: z.string().refine(isNetworkName, {
      message:
        'a sandbox domain network must be a plain network name (a letter or digit, then letters, digits, _, . or -): ' +
        'docker reads a value holding = as key=value fields, whose name= can be host',
    }).refine((value) => !isDockerNetworkMode(value), {
      message:
        'a sandbox domain network may not be host, bridge or default, nor any of them in another case: docker keeps ' +
        'those names for networks of its own, none of them internal, and refuses to recreate one --internal; a plain ' +
        "HOST names a separate network called HOST, but docker's key=value spelling lower-cases (name=HOST is host)",
    }).refine((value) => !isNoNetwork(value), {
      message:
        'a sandbox domain network may not be none, nor none in another case: every run is on --network none already, ' +
        "and a domain's network is its own internal one beside it, which the sandbox probe proves Internal=true as " +
        "defence in depth; docker's none is no network to prove internal, and a plain NONE names a separate network " +
        "called NONE, but docker's key=value spelling lower-cases (name=NONE is none)",
    }),
    // Absolute, a ~ path, or RELATIVE TO THE REPOSITORY ROOT (resolved in
    // parseKernelConfig) — never relative to whatever directory the daemon
    // started in, which would put a container's mount somewhere nobody chose.
    mountRoot: z.string().min(1),
  })
  .strict()

const Sandbox = z
  .object({
    driver: z.enum(['docker', 'apple-container']).default('docker'),
    // The worker image's NAME: the tag the image build script (egress plan I1,
    // scripts/build-worker-image.sh, not yet written) gives what it builds, so
    // that `docker images` shows which image is the kernel's. Never what a run
    // executes: a tag is whatever image was last given it on that VM, and a
    // name the VM lacks would be pulled.
    image: z.string().min(1),
    // What every run executes, by id and with --pull=never (sandbox/docker.ts):
    // the id that script prints, as `docker image inspect --format {{.Id}}`
    // does. Optional because kernel.yaml ships none until the image is built;
    // while it is unset the sandbox subsystem is degraded, naming this key,
    // and no run is built.
    imageId: z
      .string()
      .refine(isImageId, {
        message:
          'sandbox.imageId must be sha256:<64 lower-case hex>, the id `docker image inspect --format {{.Id}}` prints: ' +
          'a tag or a repository digest (name@sha256:...) is a name the VM resolves, and could be pulled',
      })
      .optional(),
    domains: z.object({ trusted: SandboxDomain, hostile: SandboxDomain }).strict(),
    defaults: z
      .object({
        // Shape alone admits root (0:0, or 65534:0 for root's group) and no
        // memory limit at all (0): docker reads both as well-formed. See
        // sandbox/limits.ts; the run-args audit checks them again.
        user: z
          .string()
          .refine(isUnprivilegedUser, { message: 'sandbox.defaults.user must be <uid>:<gid>, both numeric and neither 0 (root)' })
          .default('65534:65534'),
        pidsLimit: posInt().default(256),
        memory: z
          .string()
          .refine((value) => memoryBytes(value) !== undefined, {
            message: 'sandbox.defaults.memory must be a positive whole number with a unit, k, m or g (2g, 512m)',
          })
          .default('2g'),
        cpus: posInt().default(2),
        // One container's hard wallclock, at most: sandbox.exec gives a
        // container what is left of its run's budget, never more than this
        // (src/runtime/sandbox-tools.ts). A timer's delay, so at most
        // MAX_TIMER_MS.
        wallclockMs: posInt().max(MAX_TIMER_MS).default(600_000),
      })
      .strict()
      .prefault({}),
  })
  .strict()

// ── egress (egress plan E5) ─────────────────────────────────────────────────
//
// What the kernel's egress engine (src/egress) may do for a sandboxed run,
// as data. Only the .env loader reads it yet (a binding's envVar is a name it
// accepts, and the daemon loads that value into kernel memory at boot);
// egress itself is the stub that refuses (src/runtime/egress.ts) until the
// wiring task (W1). It ships disabled with no binding, and every field is
// strict, because each one decides what a run can reach:
//
//   A binding is a credential for one host, named by the .env name its value
//   is read from (never a value, never a vault id: the vault is dormant), the
//   profiles it may be used for and the repositories it may be used on
//   (src/egress/routes.ts). Its envVar joins the names the .env loader admits
//   (credentialNames, src/secrets/dotenv.ts); the installer mints none. It
//   names a credential of its own: never a bearer the kernel holds for
//   another use, which it would send to the binding's host (the control
//   token and MCP bearers here; a provider's key by bindingKeyProblem, once
//   the wiring task calls it at boot, where kernel.yaml and providers.yaml
//   are both read: nothing calls it yet).
//
//   Every identifier a grant row records (a binding's id, its host, its
//   repositories) must be one the redaction pass leaves alone: the store
//   parses a row before it redacts it, so `sk-abcdefghij.example.com` would
//   be stored as `[REDACTED].example.com`, a grant that no longer says where
//   a run could reach and that fails its own schema read back (events/types.ts
//   EGRESS_TOKEN_PATTERNS). Refused here, naming the key, so no boot learns it
//   at the first grant.
//
//   Only the trusted domain is served, so the section names no domain: the
//   hostile domain gets no channel and no egress (docs/design/agent-fleet.md,
//   the egress plan's operator decision on hostile egress), and a `domain`
//   or `hostile` key is refused as unknown.

/** The Basic user a binding names unless it says another: GitHub's, for a token sent over git. */
export const DEFAULT_BASIC_USER = 'x-access-token'

/**
 * Where a binding's pushes and pull requests land, the run's id after it:
 * refs/heads/aos/<runId>/. The push and pull-request checks hold the
 * kernel's own prefix (routes.ts PUSH_ROOT), so this field can name only
 * that one: a binding says where its writes land, and cannot move them.
 */
export const EGRESS_PUSH_PREFIX = `${PUSH_ROOT}/`

/**
 * A Basic credential's user: no `:`, which would end it (RFC 7617), and
 * nothing a header could read as two values.
 */
const BASIC_USER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/** The most repositories one binding names: EgressRoute's own bound (src/egress/policy.ts). */
const MAX_BINDING_REPOS = 64

/** Whether the redaction pass would store `text` as something else (the section header says why that is refused). */
const censoredInLog = (text: string): boolean => redactString(text) !== text

const CENSORED_WHY =
  'is in the shape of a credential, so the event log would store it censored, a grant row naming nothing it could ' +
  'read back: rename it'

const BindingFields = {
  host: EgressHost,
  // Bearer and Basic are both Authorization schemes, and the session (egress
  // plan E8) strips every Authorization a worker sends before it injects the
  // binding's, so exactly one reaches the host (the rule credentialedFetch
  // keeps). A header it does not strip could arrive beside the worker's own.
  header: z
    .literal('Authorization', {
      error: "an egress binding's header is Authorization: Bearer and Basic are both Authorization schemes",
    })
    .default('Authorization'),
  envVar: z.string().regex(TOKEN_ENV_NAME, {
    message: 'an egress binding envVar must be an upper-case .env name: A-Z, 0-9 and _, starting with a letter',
  }),
  profiles: z.array(EgressProfileName).min(1).max(EGRESS_PROFILES.length),
  repos: z.array(RepoSlug).min(1).max(MAX_BINDING_REPOS),
  pushPrefix: z
    .literal(EGRESS_PUSH_PREFIX, {
      error:
        `an egress binding's pushPrefix is ${EGRESS_PUSH_PREFIX}: every push and pull request lands under ` +
        `refs/heads/${EGRESS_PUSH_PREFIX}<runId>/, the prefix the kernel's push check holds`,
    })
    .default(EGRESS_PUSH_PREFIX),
}

const EgressBinding = z
  .discriminatedUnion(
    'scheme',
    [
      z
        .object({
          ...BindingFields,
          scheme: z.literal('Bearer'),
          basicUser: z
            .never({ error: 'basicUser is the user of a Basic credential: a Bearer binding sends the value alone' })
            .optional(),
        })
        .strict(),
      z
        .object({
          ...BindingFields,
          scheme: z.literal('Basic'),
          basicUser: z
            .string()
            .regex(BASIC_USER, {
              message: 'an egress binding basicUser is letters, digits, ., _ and -, starting with a letter or digit, at most 64',
            })
            .default(DEFAULT_BASIC_USER),
        })
        .strict(),
    ],
    { error: "an egress binding's scheme is Bearer or Basic" },
  )
  .superRefine((binding, ctx) => {
    const issue = (path: (string | number)[], message: string): void => ctx.addIssue({ code: 'custom', path, message })
    if (binding.envVar.startsWith(PMMCP_PREFIX)) {
      issue(
        ['envVar'],
        `an egress binding envVar must not start with PMMCP_, ${PMMCP_PREFIX_WHY}. Give the binding an AOS_ name of its own`,
      )
    }
    if (new Set(binding.profiles).size !== binding.profiles.length) issue(['profiles'], 'a binding lists a profile twice')
    if (new Set(binding.repos).size !== binding.repos.length) {
      issue(['repos'], 'a binding lists a repository twice (owner/name is read without case)')
    }
    if (censoredInLog(binding.host)) issue(['host'], `the binding's host ${CENSORED_WHY}`)
    binding.repos.forEach((repo, i) => {
      if (censoredInLog(repo)) issue(['repos', i], `the repository ${CENSORED_WHY}`)
    })
    // Half of the Basic credential, and the one half kernel.yaml holds: the
    // https://<token>@github.com habit puts the token here, in a file that is
    // committed to a public repository. The value is never echoed.
    if (binding.scheme === 'Basic' && censoredInLog(binding.basicUser)) {
      issue(
        ['basicUser'],
        'the basicUser is in the shape of a credential: kernel.yaml is committed and holds no secrets; put the token in .env under envVar, and keep basicUser a user name (x-access-token for GitHub)',
      )
    }
  })

export type EgressBinding = z.output<typeof EgressBinding>

const EgressBindings = z
  .record(
    z.string().regex(BINDING_ID, {
      message: 'an egress binding id is lower-case letters, digits and -, starting with a letter, at most 63 characters',
    }),
    EgressBinding,
  )
  .superRefine((bindings, ctx) => {
    // A repository on a host is in one binding only: a request to it would
    // not say whose credential it carries (EgressGrant refuses the same).
    // One listed twice in one binding is that binding's own issue, named
    // there, not a clash with itself.
    const owner = new Map<string, string>()
    for (const [id, binding] of Object.entries(bindings)) {
      if (censoredInLog(id)) ctx.addIssue({ code: 'custom', path: [id], message: `the binding id ${CENSORED_WHY}` })
      binding.repos.forEach((repo, i) => {
        const key = `${binding.host} ${repo}`
        const earlier = owner.get(key)
        if (earlier === undefined) {
          owner.set(key, id)
          return
        }
        if (earlier === id) return
        ctx.addIssue({
          code: 'custom',
          path: [id, 'repos', i],
          message: `${repo} on ${binding.host} is already bound by binding ${earlier}: a request to it would not say whose credential it carries`,
        })
      })
    }
  })

/**
 * A count or size the session holds a grant to (events/types.ts PROXY_LIMITS
 * names the same seven): a grant past one is revoked with reason `limit`.
 * The three that size what the kernel holds for a container (one frame, the
 * open flows, one request's head) are bounded too: the container is hostile,
 * and the kernel holds the provider keys. idleMs is a timer's delay, so at
 * most MAX_TIMER_MS.
 */
const EgressLimits = z
  .object({
    frameMaxBytes: posInt().max(1_048_576).default(65_536),
    maxFlows: posInt().max(256).default(16),
    maxHeaderBytes: posInt().max(65_536).default(16_384),
    maxRequests: posInt().default(2_000),
    maxBytes: posInt().default(536_870_912),
    maxDenied: posInt().default(20),
    idleMs: posInt().max(MAX_TIMER_MS).default(60_000),
  })
  .strict()
  .prefault({})

/**
 * Where the in-image mux listens, inside the container's own network
 * namespace (--network none): the port the worker image bakes into its
 * HTTP(S)_PROXY (egress plan I1) and the mux binds (E9, which holds no
 * config). Another port here would disagree with the image, so the field
 * names only this one, as a binding's header and pushPrefix do.
 */
export const EGRESS_MUX_PORT = 3128

// No `domain` key: egress serves the trusted domain alone (the section header).
const Egress = z
  .object({
    enabled: z.boolean().default(false),
    muxPort: z
      .literal(EGRESS_MUX_PORT, {
        error: `egress.muxPort is ${String(EGRESS_MUX_PORT)}: the port the worker image's HTTP(S)_PROXY names and its mux binds`,
      })
      .default(EGRESS_MUX_PORT),
    limits: EgressLimits,
    bindings: EgressBindings.default({}),
  })
  .strict()

const Lanes = z
  .object({ main: posInt().default(4), subagent: posInt().default(8) })
  .strict()
  .prefault({})

const Budgets = z
  .object({
    defaultRunMicroUsd: posInt().default(2_000_000),
    defaultWallclockMs: posInt().default(600_000),
    maxRetries: z.number().int().min(0).max(3).default(2),
    maxLlmCallsPerRun: posInt().default(50),
    maxToolCallsPerRun: posInt().default(100),
    approvalWaitMs: posInt().default(300_000),
  })
  .strict()
  .prefault({})

export const KernelConfig = z
  .object({
    version: z.literal(1),
    // Relative to the repository root, not the shell's working directory.
    dataDir: z.string().min(1).default('./.aos'),
    control: Control.prefault({}),
    events: Events.prefault({}),
    mcp: Mcp,
    secrets: Secrets.prefault({}),
    goals: Goals.prefault({}),
    sandbox: Sandbox,
    egress: Egress.prefault({}),
    lanes: Lanes,
    budgets: Budgets,
  })
  .strict()
  .superRefine((config, ctx) => {
    // A binding's envVar names a credential of its own. One that is a bearer
    // the kernel already holds would be sent to the binding's host: the
    // control plane's token, or an MCP server's (pmmcp's among them).
    // Providers' keys are in providers.yaml, which this schema never sees:
    // bindingKeyProblem will hold a binding to those once W1 calls it where
    // both files are read (nothing calls it yet).
    const held = new Map<string, string>([[config.control.tokenEnv, "the control plane's bearer (control.tokenEnv)"]])
    for (const [server, entry] of Object.entries(config.mcp.servers)) {
      if (entry.tokenEnv !== undefined) held.set(entry.tokenEnv, `mcp server ${server}'s bearer (mcp.servers.${server}.tokenEnv)`)
    }
    for (const [id, binding] of Object.entries(config.egress.bindings)) {
      const whose = held.get(binding.envVar)
      if (whose === undefined) continue
      ctx.addIssue({
        code: 'custom',
        path: ['egress', 'bindings', id, 'envVar'],
        message: `an egress binding envVar names a credential of its own: ${binding.envVar} is ${whose}, and the binding would send it to ${binding.host}`,
      })
    }
  })

export type KernelConfig = z.output<typeof KernelConfig>

/**
 * Why these bindings may not run beside these providers, or undefined. A
 * binding whose envVar is a provider's key (auth.envVar in providers.yaml)
 * would send that key, the most valuable bearer the kernel holds, to the
 * binding's host. KernelConfig refuses the control token and an MCP bearer
 * itself, but never sees providers.yaml, so this is checked where both files
 * are read. Pure, and nothing calls it yet: boot (egress plan W1) throws what
 * it returns as a ConfigError before it resolves any binding.
 */
export function bindingKeyProblem(config: KernelConfig, providers: ProvidersFile): string | undefined {
  const keyOf = new Map<string, string[]>()
  for (const [ref, entry] of Object.entries(providers.entries)) {
    const envVar = entry.auth.envVar
    if (envVar !== undefined) keyOf.set(envVar, [...(keyOf.get(envVar) ?? []), ref])
  }
  const clashes: string[] = []
  for (const [id, binding] of Object.entries(config.egress.bindings)) {
    const refs = keyOf.get(binding.envVar)
    if (refs === undefined) continue
    clashes.push(
      `egress.bindings.${id}.envVar ${binding.envVar} is the key of provider ${refs.join(', ')} ` +
        `(auth.envVar in providers.yaml), and the binding would send it to ${binding.host}`,
    )
  }
  if (clashes.length === 0) return undefined
  return `an egress binding envVar names a credential of its own: ${clashes.join('; ')}. Give the binding an AOS_ name of its own`
}

/** Expand a leading ~ to the current user's home directory. */
export function expandHome(p: string): string {
  if (p === '~') return homeDirectory()
  if (p.startsWith(`~${sep}`) || p.startsWith('~/')) return resolve(homeDirectory(), p.slice(2))
  return p
}

/**
 * Expand a leading `~` inside a `unix://` docker host.
 *
 * DOCKER_HOST is handed to the docker CLI, which the driver spawns WITHOUT a
 * shell, so nothing downstream would ever expand it: a literal
 * `unix://~/.colima/...` arrives at the daemon lookup as a relative path whose
 * first segment is the character `~`, and the connection simply fails. Colima
 * keeps its sockets under $HOME, so the `~` form is the one an operator
 * actually writes — which makes expanding it here the difference between a
 * config that works and one that looks right and does not.
 */
export function expandDockerHost(value: string): string {
  const real = expandHome(value.slice('unix://'.length))
  if (!isAbsolute(real)) {
    throw new ConfigError(
      `sandbox dockerHost "${value}" must resolve to an absolute socket path, got "${real}". ` +
        'DOCKER_HOST is passed to the docker CLI without a shell, so a relative path never resolves.',
    )
  }
  return `unix://${real}`
}

/**
 * Keys kernel.yaml refuses as names, though only one of them is lost. The
 * yaml parser makes `__proto__: ...` an own key, and zod's record drops it,
 * so a binding or an MCP server named `__proto__` would vanish from the
 * parsed config with no error (a strict object reports it as unknown).
 *
 * zod reads `constructor` and `prototype` as ordinary keys: a record keeps
 * the entry, a strict object reports it as unknown. They are refused as a
 * precaution, since no setting is named either. That does not make a lookup
 * by name safe: a parsed record is a plain object, so `bindings['constructor']`
 * is Object and `'constructor' in bindings` is true with no such binding.
 * Code that resolves an id from outside the file (a manifest's bind, a
 * grant's binding) asks Object.hasOwn or a Map, never `in` or a bare index
 * (egress plan E6).
 */
const OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/** What a refusal of an OBJECT_KEYS name says about it. */
function objectKeyWhy(key: string): string {
  return key === '__proto__'
    ? 'the schema drops a __proto__ entry with no error, so the setting would vanish from the parsed config'
    : 'constructor and prototype name parts of a JavaScript object, and kernel.yaml refuses both as a precaution, ' +
        'though the schema would read either as an ordinary key'
}

/**
 * Walk every key in the document; reject anything that looks like a secret,
 * and any key OBJECT_KEYS names, each by its path.
 */
export function assertNoSecretKeys(value: unknown, path: string[] = []): void {
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoSecretKeys(item, [...path, String(i)]))
    return
  }
  if (value === null || typeof value !== 'object') return
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (DENY_KEYS.test(key)) {
      throw new ConfigError(
        `kernel.yaml holds no secrets: key "${key}" at ${[...path, key].join('.')} looks like one. ` +
          'Reference an environment variable or a vault id instead.',
      )
    }
    if (OBJECT_KEYS.has(key)) {
      throw new ConfigError(
        `kernel.yaml key "${key}" at ${[...path, key].join('.')} is not a name a setting can have: ${objectKeyWhy(key)}. Rename it.`,
      )
    }
    assertNoSecretKeys(item, [...path, key])
  }
}

export interface LoadOptions {
  /** Repository root, used for the outside-the-repo refinements. */
  readonly repoRoot: string
  /** AOS_DATA_DIR override, which wins over the file's dataDir. */
  readonly dataDirOverride?: string
}

/** Parse and refine a kernel.yaml document. */
export function parseKernelConfig(input: unknown, options: LoadOptions): KernelConfig {
  // The no-secrets walk runs on the RAW document, before parsing drops
  // unknown keys, so a secret hiding in a key the schema never reads is still
  // caught.
  assertNoSecretKeys(input)

  const result = KernelConfig.safeParse(input)
  if (!result.success) {
    throw new ConfigError(`kernel.yaml is invalid: ${result.error.message}`)
  }
  const config = result.data

  // Paths in kernel.yaml are relative to the repository root, so `npm run dev`
  // from any directory finds the same log. AOS_DATA_DIR is typed in a shell,
  // so a relative one means the shell's working directory.
  const inFile = (p: string): string => resolve(options.repoRoot, expandHome(p))
  const dataDir =
    options.dataDirOverride === undefined ? inFile(config.dataDir) : resolve(expandHome(options.dataDirOverride))
  assertAosEntry(options.repoRoot)
  assertDataLocation(dataDir, 'dataDir', options.repoRoot, '.aos')
  const mountRoot = {
    trusted: inFile(config.sandbox.domains.trusted.mountRoot),
    hostile: inFile(config.sandbox.domains.hostile.mountRoot),
  }
  for (const [name, root] of Object.entries(mountRoot)) {
    assertDataLocation(root, `sandbox.domains.${name}.mountRoot`, options.repoRoot, join('.aos', 'workspaces'))
  }

  return {
    ...config,
    dataDir,
    sandbox: {
      ...config.sandbox,
      domains: {
        trusted: {
          ...config.sandbox.domains.trusted,
          dockerHost: expandDockerHost(config.sandbox.domains.trusted.dockerHost),
          mountRoot: mountRoot.trusted,
        },
        hostile: {
          ...config.sandbox.domains.hostile,
          dockerHost: expandDockerHost(config.sandbox.domains.hostile.dockerHost),
          mountRoot: mountRoot.hostile,
        },
      },
    },
  }
}

/**
 * True when the repository's .gitignore ignores the top-level directory `.aos`,
 * read with git's rules and failing closed (src/gitignore.ts). Ignoring the
 * directory itself, not just its contents, is what stops a later `!` line from
 * re-including the event log.
 */
export function gitignoresAos(repoRoot: string): boolean {
  return rootGitignoreIgnores(repoRoot, '.aos', 'dir')
}

/**
 * <repo>/.aos as git judges it, whatever kernel.yaml or AOS_DATA_DIR point at.
 * To git a symlink is a file, so `/.aos/` does not cover a linked .aos and
 * `git add -A` stages the link with the path it names; nor does `/.aos/` cover
 * one stored as .AOS (or any other folding of the name) under
 * core.ignorecase=false, which writing to ./.aos on APFS would fill. Judged
 * here, whether or not a configured path uses it, because the commit happens
 * anyway. Only .aos itself: git never descends into an ignored directory, so
 * what is beneath it, a link included, is ignored with it.
 */
export function assertAosEntry(repoRoot: string, readdir?: (dir: string) => readonly string[]): void {
  const repo = realpathNearest(repoRoot)
  const problem = entryProblem(repo, '.aos', readdir)
  if (problem?.kind === 'link') {
    throw new ConfigError(
      `${join(repo, '.aos')} is a link: git does not ignore a link, and git add -A would commit it with the path it names. ` +
        `Remove the link (rm ${join(repo, '.aos')}); to keep the data elsewhere, name that place as dataDir or a mountRoot in kernel.yaml, or in AOS_DATA_DIR`,
    )
  }
  if (problem?.kind === 'spelling') {
    throw new ConfigError(
      `${join(repo, problem.actual)} is spelled ${problem.actual} on disk, not .aos: git judges the name as stored, ` +
        `and /.aos/ does not cover it under core.ignorecase=false. Rename it to .aos`,
    )
  }
}

/**
 * Where the event log and the container mounts may live.
 *
 * Inside the repository: only under `<repo>/<allowed>`, and only while
 * .gitignore ignores `/.aos/`. Anywhere: never $HOME itself, and never a
 * directory that contains the repository or $HOME. Paths are compared after
 * symlink resolution, so a link cannot launder one location into another.
 */
export function assertDataLocation(
  target: string,
  field: string,
  repoRoot: string,
  allowed: string,
  // Seams for tests: an alias of $HOME or the repository cannot be made on a
  // case-sensitive filesystem without root.
  opts: { readonly home?: string; readonly id?: Identify } = {},
): void {
  const id = opts.id ?? identify
  const real = realpathNearest(target)
  const repo = realpathNearest(repoRoot)
  const home = realpathNearest(opts.home ?? homeDirectory())
  const fence = join(repo, allowed)

  // Forbidden zones by identity as well as spelling (isUnder), so a
  // case-variant or firmlinked spelling of $HOME or the repository is still
  // recognised.
  if (real === home || (isUnder(home, real, id) && isUnder(real, home, id))) {
    throw new ConfigError(`${field} must not be $HOME itself (${home})`)
  }
  if (isUnder(real, repo, id)) {
    throw new ConfigError(`${field} resolves to ${real}, which contains the repository (${repo})`)
  }
  if (isUnder(real, home, id)) {
    throw new ConfigError(`${field} resolves to ${real}, which contains $HOME (${home})`)
  }
  if (isUnder(repo, real, id)) {
    // The allowed zone by spelling only, and it must be what it says: a
    // `.aos` that is a link puts the data wherever the link points, which
    // `/.aos/` in .gitignore does not cover.
    const realFence = realpathNearest(fence)
    if (realFence !== fence) {
      throw new ConfigError(
        `${fence} is a link to ${realFence}: git does not ignore what is written through it. ` +
          `Make ${allowed} a real directory.`,
      )
    }
    if (!isSpelledUnder(fence, real)) {
      throw new ConfigError(
        `${field} resolves to ${real}, inside the repository but outside ${fence}. ` +
          'Inside the repo, the event log and container mounts live only under .aos/, which git ignores.',
      )
    }
    if (!gitignoresAos(repoRoot)) {
      throw new ConfigError(
        `${field} is under ${join(repo, '.aos')}, but .gitignore does not ignore /.aos/. ` +
          'Add the line `/.aos/` first: the event log must never be committed.',
      )
    }
  }
}
