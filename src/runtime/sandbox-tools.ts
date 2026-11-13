// Sandbox tools: a worker's commands, run in a container (egress plan S3).
//
// `sandbox.exec` runs one command in one container of the run's own sandbox
// domain, and nothing else: no network (every run is --network none), the
// pinned worker image by id, and the run's own workspace,
// <mountRoot>/<runId>, at /workspace. A second exec of the same run sees what
// the first left there; no other run's does.
//
// Its one way out is the kernel's egress engine (egress plan W1), and only
// for a run on the trusted domain whose manifest names egress: such an exec
// is issued a grant BEFORE its container starts (proxy.grant.issued: the
// manifest's credential-free hosts and, of each binding it binds, git-fetch
// alone, never git-push or github-pulls, which only a human-approved
// sandbox.publish may hold), its container gets the driver's channel (docker
// -i) and runs the worker image's mux around its command (muxCommand: the
// image's entrypoint is empty), and an egress session (src/egress/session.ts)
// serves that channel under the grant, every request a proxy.decision of the
// run before any dial. The grant is entered in an in-memory table and revoked
// (proxy.grant.revoked, with its totals) once the driver has a verdict on the
// container: its exit, its wallclock, the run's stop, or the session's own
// revocation for a violation or a limit, which kills the container by name on
// its own domain. Nothing here ever ends the container's stdin: a mux whose
// worker stopped reading may never read that end. So a container still
// running EXIT_KILL_GRACE_MS after its command's exit frame (a flow held open
// by a descendant the command left behind) is killed by name too, and its
// grant revoked `requested`, saying why; and a grant whose container the
// kernel killed by name because its docker client said nothing of it (no
// exit status, or 125) is revoked `error`, never read as the container's own
// violation. No grant is issued, and the exec is refused with the reason, at
// the offer and before the gate as well as here, while boot found egress
// degraded, while a binding it routes did not resolve at boot
// (assertEgressEnforced), when an identifier the grant names (a host, a
// repository, a binding id, the run's id or the agent's) is one the event log
// would store censored, the field named by its place, never quoted, or when
// its row is one proxy.grant.issued could not record (more than
// PROXY_GRANT_MAX_REPOS repositories across its bindings, which the registry
// refuses in a manifest at load). A hostile-domain run gets no channel and no
// grant, whatever its manifest says: only the trusted domain is granted, by
// code. And a domain boot closed runs no exec at all, egress or none
// (closedDomains, domainRefusal): a canary's self-test report there was
// refused, at this boot or an earlier one no canary there has passed since,
// so a container there may have a route the kernel did not give it, and a
// run with no channel has no self-test of its own (src/runtime/canary.ts).
//
// It meets the contract every agent tool meets, as kernel-tools.ts reproduces
// the hub's execute half for tools that have no server:
//
//   the ticket must be bound to exactly this tool and these arguments, and to
//   this run;
//   exposure is re-derived from tool-views.yaml (its `sandbox` server) at
//   execution, so a forged or stale ticket buys nothing;
//   the agent is re-read from the registry at execution, never taken from the
//   caller, and must still be one sandboxToolProblem admits, with the tool in
//   its manifest;
//   `tool.call` is written before anything runs and `tool.result` after,
//   bounded as an MCP result is, and between them `sandbox.started` once the
//   driver has started the container and `sandbox.killed` once it has ended,
//   so every started row has its end. A docker client that ended with no
//   exit status (killed by a signal it cannot catch, or never started), or
//   with 125, its own failure (a daemon connection lost mid-run among them),
//   says nothing of its container, which may run on with the driver's
//   wallclock timer cleared (docker.ts), so the container is killed by name
//   before that row is written. That kill is awaited for KILL_WAIT_MS at most,
//   so it never holds the call. The driver's result is awaited for the
//   container's wallclock and RESULT_GRACE_MS more at most, and once the run
//   is stopped (its kill by name sent then) for RESULT_GRACE_MS from the
//   stop at most: DockerDriver settles it only once the docker CLI closes,
//   and its wallclock is a kill by name through the same daemon, so a daemon
//   that accepts and never answers (a paused VM) would hold the call, and
//   the run, for good. Past that bound the runner gives the container up (SandboxDriver.abandon: the
//   driver ends the docker CLI it spawned, by SIGKILL, and kills the
//   container by name on its domain, awaited for KILL_WAIT_MS at most), and
//   records sandbox.killed with reason error, the result saying the driver
//   never answered.
//
// Its arguments are held to what a human is shown of them: approval.requested
// previews at most APPROVAL_PREVIEW_BYTES of their redacted canonical JSON
// (policy/engine.ts), and the ticket binds all of them, so an exec whose
// arguments that preview would not show as they run is refused, whoever
// approved it: one the preview would cut (a command padded past it runs a
// tail the human never saw), one it would redact (redact.ts shows a span
// shaped like a credential as [REDACTED], and the PEM pattern hides all that
// stands between its markers), and one holding a character a screen shows as
// nothing or uses to reorder the text around it. So is one the driver's own
// audit refuses for its command alone (SandboxDriver.commandRefusal: the
// real driver's whole-argv scans, and its home check, an argument that is
// the operator's home or a path under it). The run loop asks those checks
// (argsRefusal) before the gate, and whether the kernel's sandbox config
// lets any exec run (configRefusal: a driver that runs one, and a pinned
// image id), and the gate denies such a call before any human is asked
// (GateInput.runnerRefusal), so no human approves a command the runner
// then refuses; the runner refuses it again at execution. Its output
// reaches the model and the log with each stream bounded to its own share,
// counted in the bytes it takes in the logged JSON, so stderr, and the end of
// each, where a failure is, is never lost to a long stdout, and a stream of
// quotes or backslashes never pushes tool.result past the store's limit. Of
// each stream at most STREAM_WINDOW_BYTES is read and redacted: all of a
// shorter one, the end of a longer one, and the start of one the driver
// capped (it keeps the first CAPTURE_MAX_BYTES, cut before any redaction),
// because redact.ts's PEM pattern takes time quadratic in a text of BEGIN
// lines with no END after them, and a MiB of those would block the daemon's
// event loop for seconds. The window bounds that pattern's cost, and no
// other's: the JWT pattern takes time quadratic in a run of the characters
// its segments take in which it starts at many places (`-ey` repeated), some
// 2 s over one window, so a window holding such a run is withheld before any
// redaction reads it (JWT_RUN_STARTS_MAX): never redacted, never shown, the
// bytes its stream printed, or its capture kept, said in its place. A window
// is never shown on its cut side: not the CAPTURE_EDGE_BYTES there, where the
// cut may split a credential, nor a private key block the cut splits, from
// its marker on. An end window is read from its cut, or, when a token's
// match may hold the character before it, from the first character past it
// that none may hold (tokenFreeStart), and what that skips is not shown: no
// match of the token patterns runs across where it is read from, so its
// redaction matches each token the stream's matches there and no other, and
// breaks no marker the stream's keeps, nor keeps one it breaks. A window
// whose start a key block may hold, however the stream's redaction pairs the
// markers, is shown from where the blocks that may hold it end instead,
// wherever that is, and not at all when none ends: all before that may be a
// block's body, a credential the cut split among it. Those blocks are read
// as a union, not as one pairing (pemOpenAt): every BEGIN, one inside
// another marker included, held open to the first END after it that no
// token pattern, run first, can break (an AWS key id inside it, or a token's
// run into it, breaks one), and the blocks that overlap taken as one. So an
// end window shows an end of what a redaction of the whole stream shows,
// and no more. None of this follows a value the kernel's own mask holds
// (SecretMask), which no worker holds, nor, at a start window's cut, a token
// of a shape with an unbounded part that crosses it and runs on more than
// CAPTURE_EDGE_BYTES before it. A result that shows a stream by its window, or
// withholds one, is marked cut, and tool.result's bytes and sha256 describe
// what is shown of each stream before its share is cut, redacted: the
// windows short of their cut sides, not the streams.
//
// Its result TAINTS the run, always, whatever tool-views.yaml says of it: a
// container runs whatever the model asked for, on a workspace a container
// wrote, and what it prints is attacker-influenced. From then on every write
// in the run, the next exec among them, waits for a human (invariant 3).
//
// Who may hold these tools is the registry's call, at load, through
// sandboxToolProblem: a worker, with a sandbox: block, at tier 2 or more.
// bootKernel builds this runner, and the run loop routes every sandbox.* ref
// to it and never to the hub (egress plan W1a). The loop offers a sandbox
// tool only to a run whose agent's manifest, read from the registry by its
// id (holderProblem), may hold it and lists it, whatever the run's own tool
// list says, and only on a kernel whose sandbox config lets a call of it run
// (configRefusal: a driver that runs one, and a pinned image id); it denies
// a call from any other before the gate, so no human is asked to approve
// it, and again after it, with its tool.result, should the registry change
// while a human is asked; the runner reads the registry again at the call.
// No shipped manifest lists one.
//
// Its hard wallclock is what is left of the run's budget, at most
// sandbox.defaults.wallclockMs: a container never outlives the run that
// started it, nor the operator's cap on one container. The driver enforces it
// (docker.ts): kill by name when it elapses.

import { randomBytes } from 'node:crypto'
import { lstatSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'

import type { AgentManifest } from '../agents/manifest.js'
import type { AgentRecord } from '../agents/registry.js'
import { MAX_TIMER_MS, type KernelConfig } from '../config.js'
import { EgressGrant } from '../egress/policy.js'
import { createEgressSession, type CredentialInjector, type EgressSession, type ReadyJudge, type SessionClock, type SessionEndReason, type SessionLimits, type SessionOutcome } from '../egress/session.js'
import type { Upstream } from '../egress/upstream.js'
import { PROXY_GRANT_MAX_REPOS, ProxyGrantIssuedPayload } from '../events/types.js'
import { PolicyDenied } from '../errors.js'
import { boundOutput, PAYLOAD_TEXT_BUDGET } from '../events/bound.js'
import { canonicalize, sha256Hex } from '../events/canonical.js'
import { redactString } from '../events/redact.js'
import type { EventStore } from '../events/store.js'
import { log } from '../log.js'
import type { ToolOutcome } from '../mcp/hub.js'
import { resolveView, type ToolViewsFile } from '../mcp/tool-views.js'
import type { ToolSchema } from '../models/transport.js'
import { APPROVAL_PREVIEW_BYTES, approvalPreview, PolicyEngine, type GateTicket } from '../policy/engine.js'
import {
  CAPTURE_MAX_BYTES,
  containerName,
  type RunningSandbox,
  type SandboxDomain,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from '../sandbox/driver.js'
import { imageIdProblem, memoryBytes } from '../sandbox/limits.js'
import { assertEgressEnforced, type BindingStatus, type EgressState } from './egress.js'

/** The server id sandbox tools are addressed under: `sandbox.exec`. */
export const SANDBOX_SERVER = 'sandbox'

/** Whether `ref` is a sandbox tool's, which the run loop routes to SandboxTools and never to the hub. */
export function isSandboxRef(ref: string): boolean {
  return ref.startsWith(`${SANDBOX_SERVER}.`)
}

/** The tier a sandbox tool starts at: tier 2 is the first that runs sandboxed (plan D15). */
export const SANDBOX_MIN_TIER = 2

/**
 * A run id as it may stand as one directory under a mountRoot and in a
 * container's name: the kernel's `run_<ms>_<base36>`, and nothing a path reads
 * as two components (no separator, no dot, so never `..`) or docker reads as
 * other than a name. No `-` either, which egress/routes.ts RUN_REF admits in a
 * ref: a run's containers are `aos-run-<runId>-<n>`, so with a `-` in one id
 * the prefix of run_1's (`aos-run-run_1-`) would also be the start of run
 * run_1-2's, and a run's containers could not be told by their prefix. The
 * kernel never mints one.
 */
export const WORKSPACE_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_]{0,63}$/

/** Most arguments, bytes in one argument, and bytes in all of them, that one exec takes. */
export const MAX_EXEC_ARGS = 256
export const MAX_EXEC_ARG_BYTES = 4_096
export const MAX_EXEC_BYTES = 65_536

/**
 * The longest the runner waits on a kill by name it must send before it
 * records a container's end. The real driver's kill asks every domain for a
 * name it no longer holds, with no execFile timeout behind it (docker.ts
 * kill, #killOn), so one VM whose daemon accepts and never answers would
 * otherwise hold the call, its run and the run's lane for good, with no
 * sandbox.killed row written.
 */
export const KILL_WAIT_MS = 10_000

/**
 * How long past a container's wallclock the runner waits on the driver's
 * result before it gives the container up (SandboxDriver.abandon), and how
 * long past the run being stopped, when that comes sooner. The driver's
 * wallclock is a kill by name sent when it elapses, as the stop's is, and
 * the result settles once the docker CLI then closes: within a second or two
 * through a daemon that answers, and never through one that accepts and never
 * answers (a paused Colima VM), whose kill holds as long as its run does.
 * Thirty seconds is ample for the first and bounds the second. The wait is at
 * most a timer's limit (MAX_TIMER_MS) in all.
 */
export const RESULT_GRACE_MS = 30_000

/**
 * The docker CLI's own failure status: `docker run` exits 125 when the error
 * is the CLI's or the daemon's rather than the container's, a daemon
 * connection lost mid-run among them (Colima's forwarded socket dropping as
 * the Mac sleeps), after which its --rm container runs on in the VM. A
 * container's own `exit 125` looks the same, and a kill of a name no daemon
 * holds is harmless, so either is killed by name.
 */
export const DOCKER_CLI_FAILED = 125

/**
 * How long a channel run's container may run on once its mux has sent the
 * command's exit frame, before the kernel kills it by name on its own
 * domain. An honest mux exits as soon as its last flow retires, flushing its
 * stdout for at most its FLUSH_TIMEOUT_MS (5 s, images/worker/mux.mjs), so
 * this is longer than that. A descendant of the command that left its
 * process group (setsid), which the mux's group kill misses, may hold a flow
 * open past it, and would keep the container, its grant, the exec call and
 * the run's lane up until an egress limit or the wallclock ended it (egress
 * plan W1: every run ends by the driver's kill by name).
 */
export const EXIT_KILL_GRACE_MS = 10_000

/**
 * A character approval.requested's preview leaves raw (canonical JSON escapes
 * only the C0 controls, each as \n or \u001b and the like) that a screen shows
 * as nothing or uses to reorder the text around it: DEL, the C1 controls, the
 * format controls (Cf: bidi overrides and isolates such as U+202E, zero-width
 * characters, the BOM, the soft hyphen), the line and paragraph separators,
 * and every other default-ignorable code point (the Hangul fillers U+115F,
 * U+1160, U+3164 and U+FFA0, the variation selectors, the combining grapheme
 * joiner, U+17B4 and U+180B). A human approving a command holding one may not
 * read it as it runs: the Hangul fillers are letters to JavaScript and Python,
 * so `node -e` code can name an invisible variable. An emoji written with
 * VS16 (U+FE0F) is refused with them, as one joined by U+200D is.
 */
const UNSEEN = /[\u007F-\u009F\u2028\u2029\p{Cf}\p{Default_Ignorable_Code_Point}]/u

/**
 * Why `manifest` may not hold a sandbox tool, or undefined when it may. Asked
 * by the registry of every manifest that lists one, at load and of every
 * spawned child, and by the runner again at each call:
 *
 *   * Never an orchestrator. It runs in process and starts every other run,
 *     so what a container printed would steer delegation itself. A worker
 *     runs commands; the orchestrator delegates to one.
 *   * Only with a sandbox: block, which names the domain (the VM) its
 *     containers run on. Without one there is no domain to run in.
 *   * Tier 2 or more, the first tier that runs sandboxed (plan D15).
 */
export function sandboxToolProblem(manifest: Pick<AgentManifest, 'id' | 'role' | 'tier' | 'sandbox'>): string | undefined {
  const who = `${manifest.id} lists a sandbox tool`
  if (manifest.role === 'orchestrator') {
    return (
      `${who}, but it is role: orchestrator. Sandbox tools are a worker's: the orchestrator runs in process and ` +
      'starts every other run, so what a container printed would steer delegation. Give the tool to a worker.'
    )
  }
  if (manifest.sandbox === undefined) {
    return `${who}, but it declares no sandbox: block, so there is no domain to run its containers in. Add sandbox.domain, or drop the tool.`
  }
  // Written to fail closed: `tier < 2` is false for NaN.
  if (!(manifest.tier >= SANDBOX_MIN_TIER)) {
    return (
      `${who} at tier ${String(manifest.tier)}, but sandbox tools need tier ${String(SANDBOX_MIN_TIER)} or more, ` +
      'the first that runs sandboxed. Raise the tier deliberately or drop the tool.'
    )
  }
  return undefined
}

/** What the caller knows of the run a sandbox tool is called in. Nothing the model said. */
export interface SandboxCallContext {
  readonly runId: string
  /** Looked up in the registry: the manifest is read there, never from the caller. */
  readonly agentId: string
  /** The run's budget: the container's wallclock is what is left of it, at most sandbox.defaults.wallclockMs. */
  readonly budget: { remainingMs(): number }
  /** The run's own: an abort kills the container by name. */
  readonly signal?: AbortSignal | undefined
}

export interface SandboxToolsOptions {
  readonly store: EventStore
  readonly views: ToolViewsFile
  readonly driver: SandboxDriver
  /** The registry. A call's agent is read here, at the call. */
  readonly agents: { get(agentId: string): AgentRecord | undefined }
  /** kernel.yaml's sandbox block, as parsed: the pinned image id, each domain's mountRoot, the caps. */
  readonly sandbox: Pick<KernelConfig['sandbox'], 'imageId' | 'domains' | 'defaults'>
  /** Unset, KILL_WAIT_MS. A test's shorter bound, so a kill that never answers is met in milliseconds. */
  readonly killWaitMs?: number
  /** Unset, RESULT_GRACE_MS. A test's shorter grace, so a driver that never answers is given up in milliseconds. */
  readonly resultGraceMs?: number
  /** Unset, EXIT_KILL_GRACE_MS. A test's shorter grace, so a container that outlives its command is killed in milliseconds. */
  readonly exitKillGraceMs?: number
  /**
   * The kernel's egress engine, as boot built it (SandboxEgress). Unset, no
   * exec is given a channel, and one whose manifest has egress on the
   * trusted domain is refused: there is nothing to serve its grant.
   */
  readonly egress?: SandboxEgress
  /**
   * The domains boot closed to sandbox.exec, each with the sandbox's reason:
   * one whose boot canary's self-test report was refused (src/runtime/
   * canary.ts routed), at this boot or at an earlier one after which no
   * canary there has passed (src/kernel.ts, closedSandboxDomains), so a
   * container there may have a route the kernel did not give it. Every exec
   * on such a domain is refused, egress or none (domainRefusal). Unset, or a
   * domain left out, runs as before.
   */
  readonly closedDomains?: Readonly<Partial<Record<SandboxDomain, string>>>
}

/**
 * What an exec's grant is served with: boot's verdict on egress and on each
 * binding, kernel.yaml's bindings and per-grant limits, and the pieces of
 * one session (src/egress/session.ts), the credential injector among them,
 * which the kernel builds over broker.use: this module never holds a
 * SecretRef, nor reaches src/secrets.
 */
export interface SandboxEgress {
  readonly state: EgressState
  /** kernel.yaml's egress.bindings, as parsed: read by Object.hasOwn only. */
  readonly bindings: Readonly<Record<string, { readonly host: string; readonly profiles: readonly string[]; readonly repos: readonly string[] }>>
  /** What boot found of each binding's value. */
  readonly resolved: ReadonlyMap<string, BindingStatus>
  /** kernel.yaml's egress.limits: maxRequests counts the flows a container opens (session.ts). */
  readonly limits: SessionLimits
  readonly upstream: Upstream
  readonly credential: CredentialInjector
  readonly acceptReady: ReadyJudge
  /** Unset, real timers. A test's clock, for the session's deny window, idle bound and end drain. */
  readonly clock?: SessionClock
}

/**
 * The worker image's mux, as a container runs it: images/worker/Dockerfile
 * copies it to /opt/aos/mux.mjs, and the image has `ENTRYPOINT []`, so
 * docker runs a spec's command as given, after the image. A channel run's
 * command is therefore the mux's `--` mode wrapping the agent's argv
 * (muxCommand; mux.mjs parseArgs): the mux reads the kernel's frames on
 * stdin, sends its ready report, waits for go, runs the command and frames
 * its flows and its exit on stdout. A run with no channel runs the agent's
 * argv itself. Boot's canary runs the mux's other two modes
 * (src/runtime/canary.ts CANARY_COMMANDS), from this same constant.
 */
export const MUX_ARGV: readonly string[] = Object.freeze(['node', '/opt/aos/mux.mjs'])

/** A channel run's container command: the mux, `--`, then the agent's argv as given (mux.mjs parseArgs). */
export function muxCommand(command: readonly string[]): readonly string[] {
  return Object.freeze([...MUX_ARGV, '--', ...command])
}

/** The profiles an exec grant may hold of a binding: git-fetch alone. git-push and github-pulls are sandbox.publish's (S4). */
export const EXEC_PROFILES: readonly string[] = Object.freeze(['git-fetch'])

/**
 * A grant issued whose end has not yet come: one row of the in-memory grant
 * table. It leaves the table once its session has ended and the grant's
 * revocation was attempted (appended, or refused by the store and left in the
 * log as open, for the next boot to close as `recovered`), or once the runner
 * revoked an unserved grant, so it is never a grant the kernel still serves.
 */
export interface LiveGrant {
  readonly grantId: string
  readonly purpose: 'exec'
  readonly runId: string
  readonly agentId: string
  /** Its container's name: one container is one grant. */
  readonly sandbox: string
  readonly grant: EgressGrant
}
type Issued = LiveGrant

/** What a served grant came to, for the call's result. */
interface EgressEnd {
  readonly grantId: string
  readonly outcome: SessionOutcome
  /** The session revoked the grant on its own and had the container killed by name. */
  readonly revokedBySession: boolean
  /**
   * The grace after the command's exit frame past which the kernel killed
   * the container by name, it not having ended by then; undefined when no
   * such kill ended it.
   */
  readonly killedAfterExitMs?: number
}

/**
 * A grant no channel ever carried (the driver gave its run no channel, or its
 * session would not start): its container is killed by name at once, by the
 * kernel, and the grant revoked unserved, `detail` saying why.
 */
interface Unserved {
  readonly grantId: string
  readonly detail: string
}

/** A served grant's end: called once the driver has a verdict on the container, and what the kernel did to end it. Idempotent. */
interface Served {
  end(reason: SessionEndReason, detail?: string, killedAfterExitMs?: number): Promise<EgressEnd | undefined>
  /** Set when no session serves the grant: the container was killed by name at once, by the kernel, not by a stop. */
  readonly unserved?: Unserved
}

/** proxy.grant.revoked's totals for a grant no channel ever carried. */
const ZERO_TOTALS = Object.freeze({ flows: 0, requests: 0, allowed: 0, denied: 0, refused: 0, failed: 0, sentBytes: 0, receivedBytes: 0, durationMs: 0 })

/**
 * The first identifier of a grant row the redaction pass would store as
 * something else (a credential's shape, or a value the kernel's mask holds),
 * by its place in the row, never by its text: one that holds a secret must
 * not be quoted where the reason is shown. Undefined when every one is
 * recorded as it is. events/types.ts refuses a credential's shape in a row
 * already, but cannot see the mask's values; this sees both.
 */
function censoredField(ids: {
  readonly grantId?: string
  readonly runId: string
  readonly agentId: string
  readonly sandbox?: string
  readonly grant: EgressGrant
}): string | undefined {
  const changed = (text: string): boolean => redactString(text) !== text
  if (ids.grantId !== undefined && changed(ids.grantId)) return 'grant id'
  if (changed(ids.runId)) return 'run id'
  if (changed(ids.agentId)) return 'agent id'
  if (ids.sandbox !== undefined && changed(ids.sandbox)) return 'container name'
  for (const [i, host] of ids.grant.allow.entries()) if (changed(host)) return `credential-free host allow[${String(i)}]`
  for (const [i, route] of ids.grant.routes.entries()) {
    if (changed(route.bindingId)) return `binding id routes[${String(i)}]`
    if (changed(route.host)) return `bound host routes[${String(i)}]`
    for (const [j, repo] of route.repos.entries()) if (changed(repo)) return `repository routes[${String(i)}].repos[${String(j)}]`
  }
  return undefined
}

/** The stand-in for a grant's id where a row is judged before the issue mints one: the id's own shape. */
const PLANNED_GRANT_ID = 'grant_0_000000000000'

/** The proxy.grant.issued row of an exec grant: one builder for the row #planGrant judges and the row #issue appends. */
function issuedRow(grantId: string, sandbox: string, runId: string, agentId: string, grant: EgressGrant) {
  return {
    schemaVersion: 1,
    grantId,
    purpose: 'exec' as const,
    runId,
    agentId,
    sandbox,
    domain: 'trusted' as const,
    allow: [...grant.allow],
    routes: grant.routes.map((route) => ({ bindingId: route.bindingId, host: route.host, profiles: [...route.profiles], repos: [...route.repos] })),
  }
}

function unrecordableRefusal(issues: number): string {
  return `the grant is not one proxy.grant.issued can record (${String(issues)} issue(s)), so it is not issued; no container was started`
}

function censoredRefusal(field: string): string {
  return (
    `the grant's ${field} is in the shape of a credential, or holds a value the kernel holds as secret, so the ` +
    'event log would store it censored, and a grant whose row cannot say where a run could reach is not ' +
    'issued; no container was started'
  )
}

const NUL = '\u0000'

/** sandbox.exec's arguments. Strict: a key it does not name is refused, never ignored. */
const ExecArgs = z
  .object({
    command: z
      .array(
        z
          .string()
          .refine((arg) => Buffer.byteLength(arg) <= MAX_EXEC_ARG_BYTES, {
            message: `an argument is at most ${String(MAX_EXEC_ARG_BYTES)} bytes`,
          })
          // Node refuses an argument holding NUL synchronously, and C would
          // read it as the argument's end.
          .refine((arg) => !arg.includes(NUL), { message: 'an argument may not hold a NUL character' }),
      )
      .min(1)
      .max(MAX_EXEC_ARGS)
      .refine((argv) => (argv[0] ?? '') !== '', { message: 'command[0], the program, may not be empty' })
      .refine((argv) => argv.reduce((n, arg) => n + Buffer.byteLength(arg), 0) <= MAX_EXEC_BYTES, {
        message: `the command is at most ${String(MAX_EXEC_BYTES)} bytes in all`,
      }),
  })
  .strict()

/**
 * One of ExecArgs' refusals, in words that quote nothing the model sent.
 * zod's own text for keys the schema does not take quotes each key, raw, and
 * a key of quotes or control characters takes several times its size in the
 * log's JSON, past what tool.result can hold. Every other issue's path is
 * `command` and an index, and its message zod's or ExecArgs' own, which quote
 * no value.
 */
function issueText(issue: z.core.$ZodIssue): string {
  if (issue.code === 'unrecognized_keys') {
    const n = issue.keys.length
    return `(arguments): ${String(n)} ${n === 1 ? 'key' : 'keys'} it does not take; it takes only command`
  }
  return `${issue.path.map(String).join('.') || '(arguments)'}: ${issue.message}`
}

/**
 * sandbox.exec's command, or why the runner refuses `args` on them alone, in
 * the order #exec reads them: ExecArgs' bounds, then what a human approving
 * the call would not be shown as it runs (previewRefusal), then what
 * `driver`'s audit refuses of a command (commandRefusal: the real driver's
 * whole-argv scans and its home check). Each refusal names what the model
 * sent by its place only, but for a short argument the audit refuses.
 */
function execCommand(
  args: Record<string, unknown>,
  driver: Pick<SandboxDriver, 'commandRefusal'>,
): { readonly command: readonly string[] } | { readonly refusal: string } {
  const parsed = ExecArgs.safeParse(args)
  if (!parsed.success) {
    const issues = parsed.error.issues.map(issueText).join('; ')
    return { refusal: `sandbox.exec takes {command: [program, ...args]}: ${issues}` }
  }
  const { command } = parsed.data
  const unshown = previewRefusal(args, command)
  if (unshown !== undefined) return { refusal: unshown }
  // Before the workspace is made: the driver's audit would refuse it too,
  // after, in docker's terms rather than the command's.
  const flagged = commandRefusal(command, driver)
  if (flagged !== undefined) return { refusal: flagged }
  return { command }
}

/**
 * What a wait on a driver's result came to: its result, its rejection, or
 * nothing within the bound, from the container's start (`bound`) or from the
 * run being stopped (`stopped`).
 */
type Waited =
  | { readonly result: SandboxResult }
  | { readonly rejected: unknown }
  | { readonly late: 'bound' | 'stopped' }

/**
 * What every model offered sandbox.exec is told of it. One text for every
 * run (the loop asks schemas() for none in particular), so it says both
 * cases: a container has no network of its own, and reaches only the hosts
 * its manifest's egress grants, through the kernel, over the HTTP_PROXY the
 * worker image sets, when its manifest names egress (on the trusted domain,
 * the only one the registry admits egress on), and nothing at all otherwise.
 * And how: the engine routes a request sent in absolute form and opens no
 * tunnel (policy.ts denies every CONNECT `use-route`), and CONNECT is what a
 * client sends for an https:// URL through a proxy, so a host is named with
 * an http:// URL, which the kernel sends on over TLS itself (upstream.ts).
 * git needs no telling: the image's /etc/gitconfig rewrites https:// to
 * http:// (images/worker/gitconfig).
 */
export const EXEC_DESCRIPTION =
  'Run one command in a fresh container of your sandbox. The container has no network of its own: if your ' +
  'manifest grants egress, it reaches the hosts that grant names, and nothing else, through the kernel, over the ' +
  'HTTP_PROXY its image sets; otherwise it reaches nothing. Name such a host with an http:// URL and no port ' +
  '(http://<host>/<path>): the kernel makes the TLS connection to it itself. An https:// URL sent through the ' +
  'proxy asks it for a tunnel (CONNECT), which is always refused; git rewrites https:// remotes for you. The ' +
  'command is an argv (no shell unless you name one, e.g. ["sh", "-c", "..."]), run in /workspace, your run\'s ' +
  'own workspace, which persists between calls in this run. The root filesystem is read-only and /tmp is a small ' +
  'scratch tmpfs. You get the exit status and the output. The output is untrusted: once a run has used this tool, ' +
  'every later write in it, the next sandbox.exec included, waits for a human.'

const EXEC_SCHEMA: Record<string, unknown> = {
  type: 'object',
  properties: {
    command: {
      type: 'array',
      items: { type: 'string' },
      minItems: 1,
      maxItems: MAX_EXEC_ARGS,
      description: 'The program and its arguments.',
    },
  },
  required: ['command'],
  additionalProperties: false,
}

/** What a tool's work came to, before it is bounded for the log and the model. */
interface Done {
  readonly ok: boolean
  readonly text: string
  /**
   * Set when the text is not all the call came to: what it shows before any
   * cut to fit, redacted already (each stream whole, or its window short of
   * its cut side, or the line that withholds it, before describe() cut one to
   * its share; or a refusal before it was cut to the budget). Set whenever a
   * stream is shown by its window or withheld, even when nothing is then cut
   * to fit, so tool.result is marked cut. What tool.result's bytes and sha256
   * then describe, as they describe the whole of any text boundOutput cuts.
   */
  readonly whole?: string
}

export class SandboxTools {
  readonly #o: SandboxToolsOptions
  /**
   * Each exec's container gets the next number: a name is unique within this
   * kernel's life, and starts with its run's `aos-run-<runId>-`, which no other
   * run's does (WORKSPACE_RUN_ID admits no `-`).
   */
  #seq = 0
  /**
   * The grant table, by id: every grant issued whose revocation has not yet
   * been attempted (LiveGrant). In memory: a kernel that dies leaves its
   * grants issued in the log, and the next boot revokes each `recovered`
   * (projectRecovery's openGrants, egress plan W2), as it does a grant whose
   * revocation row the store refused, which this table has already dropped.
   */
  readonly #grants = new Map<string, LiveGrant>()

  constructor(options: SandboxToolsOptions) {
    this.#o = options
  }

  /**
   * The grants issued whose revocation has not yet been attempted, oldest
   * first (LiveGrant). A grant whose revocation row the store refused is not
   * listed, though the log shows it open until the next boot closes it.
   */
  liveGrants(): readonly LiveGrant[] {
    return [...this.#grants.values()]
  }

  /** Schemas for every sandbox tool the policy file exposes to agents. */
  schemas(): ToolSchema[] {
    if (resolveView(this.#o.views, SANDBOX_SERVER, 'exec').exposure !== 'agent') return []
    return [{ ref: `${SANDBOX_SERVER}.exec`, description: EXEC_DESCRIPTION, inputSchema: EXEC_SCHEMA }]
  }

  isSandboxRef(ref: string): boolean {
    return isSandboxRef(ref)
  }

  /**
   * Why the agent `agentId` may not be offered or run `ref`, read from the
   * registry now, or undefined when it may: one the registry does not hold,
   * an archived one, one sandboxToolProblem refuses, or one whose manifest
   * does not list the tool. The run loop asks it of every sandbox schema it
   * would offer a run, and of every sandbox call before the gate and again
   * before it executes, so a run whose own tool list names a sandbox tool its
   * manifest may not hold is never offered it and is denied it, without a
   * human asked; call() asks it once more.
   */
  holderProblem(ref: string, agentId: string): string | undefined {
    const held = this.#holderOf(ref, agentId)
    return 'problem' in held ? held.problem : undefined
  }

  /**
   * Why the runner would refuse `args` for `ref` on the arguments alone, or
   * undefined: what #exec refuses before it reads anything but them
   * (execCommand), the driver's audit of the command among it. The run loop
   * asks it before the gate, and hands the answer to it
   * (GateInput.runnerRefusal), so a call the runner refuses
   * whoever approved it is denied before any human is asked to approve it.
   * Undefined for a ref with no arguments the runner reads: call() refuses
   * a tool the kernel does not implement at execution.
   */
  argsRefusal(ref: string, args: Record<string, unknown>): string | undefined {
    if (ref !== `${SANDBOX_SERVER}.exec`) return undefined
    const checked = execCommand(args, this.#o.driver)
    return 'refusal' in checked ? checked.refusal : undefined
  }

  /**
   * Why the runner would refuse every call of `ref`, whatever its arguments
   * and whoever approved it, on the kernel's own sandbox config, or
   * undefined: the driver kernel.yaml names runs no spec at all, as its own
   * code says (SandboxDriver.everyRunRefusal: the apple-container stub,
   * whose run() throws whatever it is handed), or kernel.yaml pins no image
   * id, or one that is no id (imageIdProblem), so no container can be
   * built; the driver first, as no image id makes a stub run. The run loop
   * asks it of every sandbox schema it would offer, so no run on such a
   * kernel is shown the tool, and before the gate, beside argsRefusal,
   * handing the answer to it (GateInput.runnerRefusal), so no human is asked
   * to approve an exec on a kernel that can run none; #exec refuses it again
   * at execution. Whether a daemon answers now is not read here: the boot's
   * probe of it is stale by the time of a call, and a fresh one would ask a
   * daemon before every approval.
   */
  configRefusal(ref: string): string | undefined {
    if (ref !== `${SANDBOX_SERVER}.exec`) return undefined
    return this.#o.driver.everyRunRefusal() ?? imageIdProblem(this.#o.sandbox.imageId)
  }

  /**
   * Why the runner would refuse every exec of the agent `agentId` for its
   * manifest's domain, whatever its arguments, its egress and whoever
   * approved it, or undefined: boot closed that domain to sandbox.exec, its
   * canary having shown a container there may have a route the kernel did
   * not give it (SandboxToolsOptions.closedDomains). The run loop asks it of
   * every sandbox schema it would offer, so no run on that domain is shown
   * the tool, and before the gate, handing the answer to it
   * (GateInput.runnerRefusal), so no human is asked to approve an exec that
   * would be refused; #exec asks it again. Undefined for an agent the
   * registry does not admit (holderProblem says why).
   */
  domainRefusal(ref: string, agentId: string): string | undefined {
    if (ref !== `${SANDBOX_SERVER}.exec`) return undefined
    const held = this.#holderOf(ref, agentId)
    if ('problem' in held) return undefined
    const domain = held.manifest.sandbox?.domain
    return domain === undefined ? undefined : this.#closedRefusal(domain)
  }

  /** Why `domain` runs no exec (closedDomains), as a refusal says it, or undefined. */
  #closedRefusal(domain: SandboxDomain): string | undefined {
    const closed = this.#o.closedDomains
    const reason = closed !== undefined && Object.hasOwn(closed, domain) ? closed[domain] : undefined
    return reason === undefined ? undefined : `${reason}; no container was started`
  }

  /**
   * Why the runner would refuse every exec of the agent `agentId` for its
   * egress, whatever its arguments and whoever approved it, or undefined:
   * its manifest, read from the registry now, has egress on the trusted
   * domain and egress is not ok (boot's verdict), a binding it routes did not
   * resolve at boot, the grant would name an identifier the log would store
   * censored (the run's id among them, when `runId` is given), or its
   * proxy.grant.issued row is one the store could not record (#planGrant
   * judges the row it would append). The
   * run loop asks it of every sandbox schema it would offer (no runId), so
   * no such run is shown the tool, and before the gate (with the run's id),
   * handing the answer to it (GateInput.runnerRefusal), so no human is asked
   * to approve an exec that would be refused; #exec asks it again. Undefined
   * for a manifest with no egress and for every hostile-domain run, which
   * runs with no channel, as every run did before egress.
   */
  egressRefusal(ref: string, agentId: string, runId?: string): string | undefined {
    if (ref !== `${SANDBOX_SERVER}.exec`) return undefined
    const held = this.#holderOf(ref, agentId)
    if ('problem' in held) return undefined
    // A run id that is no ref (the offer's placeholder) is judged by the
    // exec's own: only the agent's egress and boot's verdict are read here.
    const planned = this.#planGrant(held.manifest, runId ?? 'offer', agentId)
    return planned !== undefined && 'refusal' in planned ? planned.refusal : undefined
  }

  /**
   * Execute a sandbox tool under a gate ticket, logging exactly as the hub
   * does, and tainting the run.
   *
   * @throws {PolicyDenied} on a ticket that does not match these arguments,
   *   this tool or this run, a tool agents may not call, one the kernel does
   *   not implement, or an agent that may not hold it: the hub's refusals, in
   *   its order, then the registry's, all before anything is logged or run.
   */
  async call(
    ticket: GateTicket,
    args: Record<string, unknown>,
    ctx: SandboxCallContext,
  ): Promise<ToolOutcome & { readonly taints: boolean }> {
    const ref = ticket.toolRef
    PolicyEngine.assertTicketMatches(ticket, ref, args)
    if (!this.isSandboxRef(ref)) throw new PolicyDenied(ref, 'not a sandbox tool')
    if (ticket.runId !== ctx.runId) {
      throw new PolicyDenied(ref, `the ticket was issued for run ${ticket.runId}, and this call is run ${ctx.runId}'s`)
    }
    const name = ref.slice(SANDBOX_SERVER.length + 1)
    const view = resolveView(this.#o.views, SANDBOX_SERVER, name)
    if (view.exposure !== 'agent') {
      throw new PolicyDenied(ref, `exposure is ${view.exposure}; agents may only call agent tools`)
    }
    if (name !== 'exec') throw new PolicyDenied(ref, `the kernel implements no sandbox tool ${name}`)
    const manifest = this.#holder(ref, ctx.agentId)

    this.#o.store.append({
      type: 'tool.call',
      runId: ticket.runId,
      agentId: ctx.agentId,
      payload: {
        schemaVersion: 1,
        ticketId: ticket.ticketId,
        toolRef: ref,
        argsHash: ticket.argsHash,
        quarantine: ticket.quarantine,
      },
    })

    const startedAt = Date.now()
    let done: Done
    try {
      done = await this.#exec(args, ctx, manifest)
    } catch (e) {
      // A refusal or a failure is a failed call the model can read, not a
      // crashed run: what an MCP tool that threw gets.
      done = failed(e instanceof Error ? e.message : String(e))
    }

    const bounded = boundOutput(done.text, PAYLOAD_TEXT_BUDGET)
    // A text cut to fit is marked cut, with the size and the digest of the
    // redacted whole it stands for, as boundOutput marks one it cuts. That
    // whole was redacted as it was built (describe()'s windows, a refusal's
    // text), so it is hashed as it is: a second pass would only cost time,
    // and could pair a key block's markers across the two streams' headings.
    const whole = done.whole
    const digest = whole === undefined ? bounded.sha256 : sha256Hex(whole)
    const outcome = {
      ok: done.ok,
      text: bounded.text,
      bytes: whole === undefined ? bounded.bytes : Buffer.byteLength(whole),
      truncated: bounded.truncated || whole !== undefined,
      ...(digest === undefined ? {} : { sha256: digest }),
      durationMs: Date.now() - startedAt,
      // Always, refused or not: a refusal names nothing the model did not
      // send, but a container that ran printed what it liked, and the call
      // is marked the same either way so no branch forgets it.
      taints: true,
    }

    this.#o.store.append({
      type: 'tool.result',
      runId: ticket.runId,
      agentId: ctx.agentId,
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
   * The manifest of the agent calling `ref`, read from the registry now, or a
   * refusal: an agent the registry does not hold, an archived one, one
   * sandboxToolProblem refuses, or one whose manifest does not list the tool.
   * The registry refused such a manifest at load; this refuses a caller that
   * claims an agent it is not, or a record that changed since.
   */
  #holder(ref: string, agentId: string): AgentManifest {
    const held = this.#holderOf(ref, agentId)
    if ('problem' in held) throw new PolicyDenied(ref, held.problem)
    return held.manifest
  }

  /** The manifest #holder admits, or why it refuses: holderProblem's reading. */
  #holderOf(ref: string, agentId: string): { readonly manifest: AgentManifest } | { readonly problem: string } {
    const record = this.#o.agents.get(agentId)
    if (record === undefined) return { problem: `no agent ${agentId} is registered` }
    if (record.status !== 'active') return { problem: `agent ${agentId} is ${record.status}` }
    const problem = sandboxToolProblem(record.manifest)
    if (problem !== undefined) return { problem }
    if (!record.manifest.tools.allow.includes(ref)) {
      return { problem: `${ref} is not in agent ${agentId}'s manifest (default deny)` }
    }
    return { manifest: record.manifest }
  }

  /** One command in one container, start to end. */
  async #exec(args: Record<string, unknown>, ctx: SandboxCallContext, manifest: AgentManifest): Promise<Done> {
    // Asked of the loop before the gate too (argsRefusal), and again here,
    // for a caller that did not ask, or a ticket minted without it.
    const checked = execCommand(args, this.#o.driver)
    if ('refusal' in checked) throw new Error(`[refused] ${checked.refusal}`)
    const { command } = checked
    if (ctx.signal?.aborted === true) throw new Error('[refused] the run was stopped before the container started')

    // Asked of the loop before the gate too (configRefusal), and again here,
    // each on its own, so neither rests on the other's reading: before the
    // workspace, which a driver that runs nothing would leave behind empty.
    const runsNothing = this.#o.driver.everyRunRefusal()
    if (runsNothing !== undefined) throw new Error(`[refused] ${runsNothing}`)
    const { imageId, domains, defaults } = this.#o.sandbox
    const unpinned = imageIdProblem(imageId)
    if (unpinned !== undefined || imageId === undefined) throw new Error(`[refused] ${unpinned ?? 'no image id'}`)

    // The manifest's own domain. #holder admitted only a manifest with one;
    // this says so to the compiler without choosing a domain for it.
    const box = manifest.sandbox
    if (box === undefined) throw new Error(`[refused] ${manifest.id} declares no sandbox: block`)
    const domain = box.domain

    // A domain boot closed (its canary showed a route out): asked of the
    // loop before the gate too (domainRefusal), and again here.
    const closed = this.#closedRefusal(domain)
    if (closed !== undefined) throw new Error(`[refused] ${closed}`)

    // The grant this exec would be issued, or why none can be: asked of the
    // loop before the gate too (egressRefusal), and again here. Undefined for
    // a manifest with no egress, and for every hostile-domain run, whatever
    // its manifest says: that domain gets no channel and no grant.
    const planned = this.#planGrant(manifest, ctx.runId, ctx.agentId)
    if (planned !== undefined && 'refusal' in planned) throw new Error(`[refused] ${planned.refusal}`)

    // What is left of the run's budget, at most the operator's cap on one
    // container. Floored: a timer converts its delay to whole milliseconds.
    const wallclockMs = Math.min(Math.floor(ctx.budget.remainingMs()), defaults.wallclockMs)
    if (!(wallclockMs >= 1)) throw new Error("[refused] the run's wallclock has elapsed; no container was started")

    // Last before the run, as the one step here that changes anything: a call
    // refused above leaves no workspace behind. One the driver refuses below
    // (it holds another image id than kernel.yaml pins, say) leaves the run's
    // empty workspace, which the run's next exec reuses.
    const workspace = this.#workspace(domain, domains[domain].mountRoot, ctx.runId)

    this.#seq += 1
    const memoryMb = Math.ceil((memoryBytes(defaults.memory) ?? 0) / (1024 * 1024))
    const spec: SandboxSpec = {
      name: containerName(ctx.runId, this.#seq),
      runId: ctx.runId,
      agentId: ctx.agentId,
      domain,
      image: imageId,
      // A channel run's container runs the worker image's mux around the
      // command (muxCommand): with no mux, the session would read the
      // command's own stdout as frames, no ready report would come, and the
      // run would fail closed every time.
      command: planned === undefined ? command : muxCommand(command),
      workspace,
      limits: { memoryMb, cpus: defaults.cpus, pids: defaults.pidsLimit, wallclockMs },
      // A channel only for a grant, which only a trusted run with egress is
      // planned. A run without one has no -i, and its stdin is closed at once.
      ...(planned === undefined ? {} : { channel: true }),
    }

    // Issued BEFORE the spawn: the container's first byte on its channel is
    // judged under a grant the log already holds.
    const issued = planned === undefined ? undefined : this.#issue(planned.grant, spec, ctx)

    let running: RunningSandbox
    try {
      running = this.#o.driver.run(spec)
    } catch (e) {
      // The driver refuses before it starts anything (SandboxDriver.run), so
      // there is no container to record, and the grant served nothing.
      const why = e instanceof Error ? e.message : String(e)
      if (issued !== undefined) this.#revokeUnserved(issued, ctx, 'the driver refused the container before it started')
      throw new Error(`[refused] ${why}`)
    }
    const kill = (): void => {
      void this.#killByName(spec.name)
    }
    // A channel run's command has exited once its mux sends the exit frame,
    // and the container is due to end once its flows retire. One still
    // running EXIT_KILL_GRACE_MS later (a flow a descendant of the command
    // holds open) is killed by name, unless the run was stopped by then,
    // whose own kill went out at the stop. Cleared once the result is in.
    const graceMs = this.#exitKillGraceMs()
    let exitTimer: NodeJS.Timeout | undefined
    let killedAfterExit = false
    const exited = (): void => {
      if (exitTimer !== undefined) return
      exitTimer = setTimeout(() => {
        if (ctx.signal?.aborted === true) return
        killedAfterExit = true
        kill()
      }, graceMs)
    }
    // The session listens on the channel at once, before anything is
    // awaited: the result of a channel run settles only once its input has
    // been read to its end (RunningSandbox.result).
    const served = issued === undefined ? undefined : this.#serve(issued, running, spec, ctx, exited)
    try {
      this.#o.store.append({
        type: 'sandbox.started',
        runId: ctx.runId,
        agentId: ctx.agentId,
        payload: {
          schemaVersion: 1,
          sandboxId: spec.name,
          driver: this.#o.driver.name,
          domain,
          image: imageId,
          memoryMb,
          pids: defaults.pidsLimit,
          wallclockMs,
        },
      })
    } catch (e) {
      // A container the log cannot record is not left running, and the call
      // fails only once it has ended, or been given up past its wallclock and
      // a grace, with the log's refusal, whatever the driver's result says.
      kill()
      const waited = await this.#within(running.result, this.#resultBound(spec), ctx.signal)
      clearTimeout(exitTimer)
      if ('late' in waited) await this.#giveUp(spec.name)
      await served?.end('error')
      throw e
    }

    const signal = ctx.signal
    signal?.addEventListener('abort', kill, { once: true })
    if (signal?.aborted === true) kill()
    const boundMs = this.#resultBound(spec)
    let waited: Waited
    try {
      waited = await this.#within(running.result, boundMs, signal)
    } finally {
      signal?.removeEventListener('abort', kill)
      clearTimeout(exitTimer)
    }
    if ('late' in waited) {
      // The driver never answered: no result past the container's wallclock
      // and a grace, or past the grace from the run being stopped, whose kill
      // by name went out then. Its CLI is ended and its container killed by
      // name (abandon), and its end recorded as an error, so the started row
      // is closed and the run goes on; what the result would have said, if it
      // ever settles, is not read.
      log.warn(
        { sandboxId: spec.name, driver: this.#o.driver.name, boundMs, late: waited.late },
        'sandbox result never came; the run gave the container up',
      )
      const sent = await this.#giveUp(spec.name)
      this.#o.store.append({
        type: 'sandbox.killed',
        runId: ctx.runId,
        agentId: ctx.agentId,
        payload: { schemaVersion: 1, sandboxId: spec.name, reason: 'error' },
      })
      await served?.end('error')
      const within =
        waited.late === 'stopped'
          ? `within ${String(this.#graceMs())} ms of the run being stopped, which sent a kill by name to it,`
          : `within ${String(boundMs)} ms of its start (its wallclock of ${String(wallclockMs)} ms and a grace of ` +
            `${String(this.#graceMs())} ms),`
      throw new Error(`[error] the driver never answered: ${spec.name} had no result ${within} so the run gave it up; ${sent}`)
    }
    if ('rejected' in waited) {
      // A driver's result settles and never rejects (SandboxDriver.run). One
      // that did says nothing of its container: it is killed by name, and its
      // end recorded, so no started row is left open on a container that runs.
      const e = waited.rejected
      const sent = await this.#killByName(spec.name)
      this.#o.store.append({
        type: 'sandbox.killed',
        runId: ctx.runId,
        agentId: ctx.agentId,
        payload: { schemaVersion: 1, sandboxId: spec.name, reason: 'error' },
      })
      await served?.end('error')
      throw new Error(`[error] the driver lost ${spec.name}: ${e instanceof Error ? e.message : String(e)}; ${sent}`)
    }
    const result = waited.result

    // An end that says nothing of the container (mayRunOn): such a client is
    // expected to leave its --rm container running, its wallclock timer
    // cleared at the client's exit (docker.ts), so the container is killed by
    // name before the log records its end. A name no daemon holds is
    // harmless to kill.
    const runsOn = mayRunOn(result)
    const sent = runsOn === undefined ? undefined : `${await this.#killByName(spec.name)}, ${runsOn}`

    this.#o.store.append({
      type: 'sandbox.killed',
      runId: ctx.runId,
      agentId: ctx.agentId,
      payload: {
        schemaVersion: 1,
        sandboxId: spec.name,
        reason: endReason(result),
        ...(result.exitCode === null ? {} : { exitCode: result.exitCode }),
      },
    })
    // The container has ended, by the driver's verdict, and the grant is
    // revoked with it, its totals recorded, once what is still in the
    // channel has been read: the command's last output and its exit status.
    // Ended by the kernel's own kill by name, it is revoked with the
    // kernel's reason, never the container's: a docker client that says
    // nothing of its container (mayRunOn) is `error`, so a stream its kill
    // cut inside a frame is not read as the container's violation; one
    // still running past its command's exit is `requested`, saying why.
    const egress =
      served === undefined
        ? undefined
        : runsOn !== undefined
          ? await served.end('error', `the kernel killed the container by name, ${runsOn}`)
          : killedAfterExit && result.killedBy === 'requested'
            ? await served.end(
                'requested',
                `the command exited, and its container was still running ${String(graceMs)} ms later, so the kernel killed it by name`,
                graceMs,
              )
            : await served.end(endReason(result))
    return describe(spec, result, sent, egress, served?.unserved)
  }

  /**
   * The grant an exec of `manifest` in run `runId` would be issued, or why it
   * cannot be, or undefined when it gets none: a manifest with no egress, or
   * any run on the hostile domain, whatever its manifest says (only the
   * trusted domain is granted, by code: kernel.yaml's egress names no
   * domain). An exec grant holds the manifest's credential-free hosts and,
   * of each binding it binds, git-fetch alone (EXEC_PROFILES): never
   * git-push or github-pulls, which only a human-approved sandbox.publish may
   * hold. A binding with no profile an exec may use adds no route. Refused
   * with the egress reason when egress is not ok, or a binding it routes did
   * not resolve at boot (assertEgressEnforced), when an identifier it names
   * is one the log would store censored (#censoredField), and when the row
   * #issue would append is one proxy.grant.issued refuses. Bindings are
   * read with Object.hasOwn, never `in` or a bare index (kernel.yaml admits a
   * binding id `constructor`).
   */
  #planGrant(manifest: AgentManifest, runId: string, agentId: string): { readonly grant: EgressGrant } | { readonly refusal: string } | undefined {
    if (manifest.sandbox?.domain !== 'trusted') return undefined
    const { allow, bind } = manifest.egress
    if (allow.length === 0 && bind.length === 0) return undefined
    const egress = this.#o.egress
    if (egress === undefined) {
      return { refusal: `${manifest.id} has egress, and no egress engine is wired into this kernel, so its exec gets no channel; no container was started` }
    }
    const routes: { bindingId: string; host: string; profiles: string[]; repos: string[] }[] = []
    const unknown: string[] = []
    for (const id of bind) {
      const binding = Object.hasOwn(egress.bindings, id) ? egress.bindings[id] : undefined
      if (binding === undefined) {
        unknown.push(id)
        continue
      }
      const profiles = binding.profiles.filter((p) => EXEC_PROFILES.includes(p))
      if (profiles.length === 0) continue
      routes.push({ bindingId: id, host: binding.host, profiles, repos: [...binding.repos] })
    }
    try {
      assertEgressEnforced(egress.state, { used: routes.map((r) => r.bindingId), resolved: egress.resolved })
    } catch (e) {
      return { refusal: `${e instanceof Error ? e.message : String(e)}; no container was started` }
    }
    if (unknown.length > 0) {
      return { refusal: `${manifest.id}'s egress.bind names ${String(unknown.length)} binding(s) kernel.yaml does not hold; no container was started` }
    }
    const parsed = EgressGrant.safeParse({ runId, allow: [...allow], routes })
    if (!parsed.success) {
      return { refusal: `the grant ${manifest.id}'s egress would be issued is not one the egress engine reads (${String(parsed.error.issues.length)} issue(s)); no container was started` }
    }
    const field = censoredField({ runId, agentId, grant: parsed.data })
    if (field !== undefined) return { refusal: censoredRefusal(field) }
    // The row #issue would append, judged now, so that a grant
    // proxy.grant.issued cannot record is refused here, at the offer and
    // before the gate, never once a human has approved its exec and its
    // workspace is made: EgressGrant admits 16 routes of 64 repositories,
    // and a row names at most PROXY_GRANT_MAX_REPOS of them. What only the
    // issue mints, the grant's id and the container's name, stands in by
    // its shape. The registry refuses a manifest whose bindings name more at
    // load; this holds for a record that reached the runner otherwise.
    const repos = parsed.data.routes.reduce((n, route) => n + route.repos.length, 0)
    if (repos > PROXY_GRANT_MAX_REPOS) {
      return {
        refusal:
          `the grant ${manifest.id}'s egress would be issued names ${String(repos)} repositories across its bindings, ` +
          `and a proxy.grant.issued row names at most ${String(PROXY_GRANT_MAX_REPOS)}, so it could not be recorded and ` +
          'is not issued; no container was started',
      }
    }
    const row = ProxyGrantIssuedPayload.safeParse(issuedRow(PLANNED_GRANT_ID, containerName(runId, this.#seq + 1), runId, agentId, parsed.data))
    if (!row.success) return { refusal: unrecordableRefusal(row.error.issues.length) }
    return { grant: parsed.data }
  }

  /**
   * Issue `grant` for `spec`'s container: every identifier the row records
   * checked against the redaction pass (a grant the kernel cannot record is
   * not issued), proxy.grant.issued appended, and the grant entered in the
   * table. Before the spawn, so a refusal here starts nothing.
   */
  #issue(grant: EgressGrant, spec: SandboxSpec, ctx: SandboxCallContext): Issued {
    const grantId = `grant_${String(Date.now())}_${randomBytes(6).toString('hex')}`
    const field = censoredField({ grantId, runId: ctx.runId, agentId: ctx.agentId, sandbox: spec.name, grant })
    if (field !== undefined) throw new Error(`[refused] ${censoredRefusal(field)}`)
    const payload = issuedRow(grantId, spec.name, ctx.runId, ctx.agentId, grant)
    // #planGrant judged this row before the gate, by its stand-ins; judged
    // again as it will be appended.
    const recordable = ProxyGrantIssuedPayload.safeParse(payload)
    if (!recordable.success) throw new Error(`[refused] ${unrecordableRefusal(recordable.error.issues.length)}`)
    this.#o.store.append({ type: 'proxy.grant.issued', runId: ctx.runId, agentId: ctx.agentId, payload })
    const live: LiveGrant = Object.freeze({ grantId, purpose: 'exec', runId: ctx.runId, agentId: ctx.agentId, sandbox: spec.name, grant })
    this.#grants.set(grantId, live)
    return live
  }

  /**
   * Revoke a grant whose container never served it (the driver refused the
   * spec, or gave the run no channel): proxy.grant.revoked `error`, with
   * zero totals, since nothing crossed a channel under it.
   */
  #revokeUnserved(issued: Issued, ctx: SandboxCallContext, detail: string): void {
    this.#grants.delete(issued.grantId)
    this.#o.store.append({
      type: 'proxy.grant.revoked',
      runId: ctx.runId,
      agentId: ctx.agentId,
      payload: { schemaVersion: 1, grantId: issued.grantId, reason: 'error', detail, totals: ZERO_TOTALS },
    })
  }

  /**
   * Run the egress session over `running`'s channel under `issued`, and the
   * means to end it: end(reason, detail) takes the driver's verdict on the
   * container, or the kernel's own when its kill by name ended it, and
   * resolves once the grant is revoked, with what the session read of the
   * command. The session's own revocation (a violation, a limit, a broken
   * append) kills the container by name, on its own domain, through the
   * driver; the command's exit frame is told to `exited`, which bounds how
   * long the container may run on after it; nothing here ever ends the
   * container's stdin, since a mux whose worker stopped reading may never
   * read that end (egress plan W1's note). A run the driver gave no channel,
   * or a session that would not start, is killed by name at once and its
   * grant revoked as unserved once it ends (Served.unserved), and its result
   * says the kernel killed it and why, never that the run was stopped; nor,
   * its mux having had no go, that its command exited, and it is never ok,
   * whatever the docker client (the mux) exited (describe).
   */
  #serve(issued: Issued, running: RunningSandbox, spec: SandboxSpec, ctx: SandboxCallContext, exited: () => void): Served {
    const egress = this.#o.egress
    const channel = running.channel
    let session: EgressSession | undefined
    let unserved: string | undefined
    let revokedBySession = false
    if (egress === undefined || channel === undefined) {
      unserved = 'the driver gave the run no channel'
    } else {
      try {
        session = createEgressSession({
          grantId: issued.grantId,
          grant: issued.grant,
          agentId: ctx.agentId,
          limits: egress.limits,
          channel: { input: channel.input, output: channel.output },
          store: this.#o.store,
          upstream: egress.upstream,
          credential: egress.credential,
          acceptReady: egress.acceptReady,
          kill: () => {
            revokedBySession = true
            void this.#killByName(spec.name)
          },
          exited,
          ...(egress.clock === undefined ? {} : { clock: egress.clock }),
        })
      } catch (e) {
        unserved = `the egress session would not start: ${e instanceof Error ? e.message : String(e)}`
      }
    }
    const never: Unserved | undefined =
      session === undefined ? { grantId: issued.grantId, detail: unserved ?? 'the grant served no channel' } : undefined
    if (session === undefined) void this.#killByName(spec.name)
    // The table holds a grant until its revocation is attempted, and the
    // session's own revocation (a violation, a limit, a refused ready report,
    // a broken append) comes before the runner has the driver's verdict on
    // the container, which may run on, through a kill by name no daemon
    // answers, until its wallclock and the grace. So the grant leaves the
    // table once the session has ended and its revocation was attempted
    // (done, which never rejects): proxy.grant.revoked appended, or refused
    // by the store, the grant then left open in the log for the next boot to
    // close as `recovered`. Whoever revoked it, liveGrants never lists a
    // grant the session no longer serves; end() below drops it as well.
    if (session !== undefined) void session.done.then(() => this.#grants.delete(issued.grantId))
    let ended: Promise<EgressEnd | undefined> | undefined
    return {
      ...(never === undefined ? {} : { unserved: never }),
      end: (reason, detail, killedAfterExitMs) => {
        ended ??= (async (): Promise<EgressEnd | undefined> => {
          try {
            if (session === undefined) {
              this.#revokeUnserved(issued, ctx, never?.detail ?? 'the grant served no channel')
              return undefined
            }
            const outcome = await session.end(reason, detail)
            return {
              grantId: issued.grantId,
              outcome,
              revokedBySession,
              ...(killedAfterExitMs === undefined ? {} : { killedAfterExitMs }),
            }
          } finally {
            this.#grants.delete(issued.grantId)
          }
        })()
        return ended
      },
    }
  }

  /** How long a channel run's container may outlive its command's exit frame: EXIT_KILL_GRACE_MS, or a test's. */
  #exitKillGraceMs(): number {
    return this.#o.exitKillGraceMs ?? EXIT_KILL_GRACE_MS
  }

  /** The grace past a container's wallclock its result is awaited for: RESULT_GRACE_MS, or a test's. */
  #graceMs(): number {
    return this.#o.resultGraceMs ?? RESULT_GRACE_MS
  }

  /**
   * How long the runner waits on `spec`'s result from its start: its
   * wallclock and the grace, at most a timer's limit (a longer delay fires at
   * once).
   */
  #resultBound(spec: SandboxSpec): number {
    return Math.min(spec.limits.wallclockMs + this.#graceMs(), MAX_TIMER_MS)
  }

  /**
   * What `result` comes to within `boundMs`: the result, the reason it
   * rejected, or `late`. Once `signal` aborts (the run was stopped, and the
   * caller's kill by name sent), the wait ends at the grace from then
   * (#graceMs) if that comes sooner: what is left of a container's wallclock
   * buys a stopped run nothing, and a daemon that never answers would
   * otherwise hold its run.finished row and its lane until the bound. Its
   * rejection is handled here, so a result that rejects after the wait has
   * ended raises nothing unhandled. The timers are not unref'd, for the
   * reason #send's is not, and the abort listener is removed when the wait
   * ends.
   */
  async #within(result: Promise<SandboxResult>, boundMs: number, signal?: AbortSignal): Promise<Waited> {
    let timer: NodeJS.Timeout | undefined
    let stopped: (() => void) | undefined
    const late = new Promise<Waited>((resolve) => {
      const startedAt = Date.now()
      timer = setTimeout(() => {
        resolve({ late: 'bound' })
      }, boundMs)
      if (signal === undefined) return
      stopped = (): void => {
        const graceMs = this.#graceMs()
        // The bound still holds when it ends first.
        if (graceMs >= boundMs - (Date.now() - startedAt)) return
        clearTimeout(timer)
        timer = setTimeout(() => {
          resolve({ late: 'stopped' })
        }, graceMs)
      }
      if (signal.aborted) stopped()
      else signal.addEventListener('abort', stopped, { once: true })
    })
    try {
      return await Promise.race([
        result.then(
          (settled): Waited => ({ result: settled }),
          (e: unknown): Waited => ({ rejected: e }),
        ),
        late,
      ])
    } finally {
      clearTimeout(timer)
      if (stopped !== undefined) signal?.removeEventListener('abort', stopped)
    }
  }

  /** Kill `name` by name, and say so for the result text (#send). */
  async #killByName(name: string): Promise<string> {
    return this.#send(name, 'kill by name', `a kill by name was sent to ${name}`, () => this.#o.driver.kill(name))
  }

  /**
   * Give `name` up (SandboxDriver.abandon: its docker CLI ended, and a kill
   * by name sent), and say so for the result text (#send).
   */
  async #giveUp(name: string): Promise<string> {
    return this.#send(
      name,
      'abandon',
      `the driver was asked to end its docker client and kill ${name} by name`,
      () => this.#o.driver.abandon(name),
    )
  }

  /**
   * Ask the driver to `ask` about `name` (a kill by name, or a give-up),
   * and say what came of it after `said`. Never rejects, and waits
   * KILL_WAIT_MS at most (killWaitMs in a test), so the caller always
   * records the container's end: the real driver's kill and abandon never
   * reject, but may never settle (docker.ts #killOn has no timeout), and
   * another's that rejects or throws is logged and said, never thrown.
   */
  async #send(name: string, what: string, said: string, ask: () => Promise<void>): Promise<string> {
    const waitMs = this.#o.killWaitMs ?? KILL_WAIT_MS
    // An async function, so a driver's kill that throws as it is called
    // rejects instead, and the kill is sent now, before any await.
    const killing = (async (): Promise<void> => {
      await ask()
    })()
    // Not unref'd: a process with nothing else left to do waits out the
    // bound and records the container's end, rather than exit with the call
    // pending and its sandbox.started row open.
    let timer: NodeJS.Timeout | undefined
    const late = new Promise<{ readonly late: true }>((resolve) => {
      timer = setTimeout(() => {
        resolve({ late: true })
      }, waitMs)
    })
    try {
      // The rejection is handled here, so a kill that rejects after the wait
      // has ended raises nothing unhandled.
      const ended = await Promise.race([
        killing.then(
          () => ({ late: false as const }),
          (e: unknown) => ({ late: false as const, refused: e instanceof Error ? e.message : String(e) }),
        ),
        late,
      ])
      if (ended.late) {
        log.warn({ sandboxId: name, driver: this.#o.driver.name, waitMs }, `sandbox ${what} went unanswered`)
        return `${said}, and no daemon answered within ${String(waitMs)} ms`
      }
      if ('refused' in ended) {
        log.warn({ sandboxId: name, driver: this.#o.driver.name }, `sandbox ${what} failed`)
        return `${said}, and the driver refused it: ${driverText(ended.refused)}`
      }
      return said
    } finally {
      clearTimeout(timer)
    }
  }

  /** The run's workspace, <mountRoot>/<runId> (makeWorkspace). */
  #workspace(domain: SandboxDomain, mountRoot: string, runId: string): string {
    return makeWorkspace(domain, mountRoot, runId)
  }
}

/**
 * A container's workspace, <mountRoot>/<name>: made if it is not there, as a
 * directory only the operator reads, and refused unless it is one, and no
 * link. `name` is a run's id, or the boot canary's own (src/runtime/canary.ts
 * CANARY_WORKSPACE), and must be one directory name (WORKSPACE_RUN_ID). The
 * mountRoot itself is the VM's share (scripts/colima-up.sh makes it), never
 * made here: a missing one is a VM that shares nothing. The driver then
 * confines the path again (confine.ts) before it mounts it. The one
 * directory any sandbox code makes: test/hygiene.test.ts holds this file to
 * this one mkdirSync.
 */
export function makeWorkspace(domain: SandboxDomain, mountRoot: string, runId: string): string {
  if (!WORKSPACE_RUN_ID.test(runId)) {
    throw new Error(
      '[refused] the run id is not one directory name and one container prefix (a letter or digit, then letters, ' +
        'digits or _, at most 64), so it names no workspace',
    )
  }
  const workspace = join(mountRoot, runId)
  try {
    mkdirSync(workspace, { mode: 0o700 })
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ENOENT') {
      throw new Error(
        `[refused] the ${domain} domain's mountRoot ${mountRoot} does not exist: it is the VM's share, which ` +
          'scripts/colima-up.sh makes with the VM',
      )
    }
    if (code !== 'EEXIST') throw new Error(`[refused] the workspace ${workspace} cannot be made: ${String(code)}`)
  }
  // lstat, so a link is no directory, wherever it points: another run's
  // workspace inside the same mountRoot among the places.
  if (!lstatSync(workspace).isDirectory()) {
    throw new Error(`[refused] the workspace ${workspace} is there and is no directory of its own`)
  }
  return workspace
}

/** sandbox.killed's reason, from the driver's verdict. */
export function endReason(result: SandboxResult): 'wallclock' | 'requested' | 'error' | 'exited' {
  if (result.killedBy !== undefined) return result.killedBy
  // The wallclock fired and its kill ended nothing (it reached no daemon),
  // and the container then exited on its own: the one trace that the hard
  // wallclock did not hold (SandboxResult.overran), so it is a wallclock end.
  if (result.overran === true) return 'wallclock'
  // A docker CLI that died of a signal, or a spawn that started nothing.
  if (result.exitCode === null) return 'error'
  return 'exited'
}

/**
 * Why a run's end says nothing of its container, which may then run on, or
 * undefined when it says the container has ended. No exit status: a docker
 * client killed by a signal it cannot catch (the OOM killer on the Mac, a
 * SIGKILL from outside), or a spawn that started nothing. 125 with no kill
 * credited: the CLI's own failure (DOCKER_CLI_FAILED).
 */
export function mayRunOn(result: SandboxResult): string | undefined {
  if (result.exitCode === null) return 'as a docker client with no exit status may leave its container running'
  if (result.killedBy === undefined && result.exitCode === DOCKER_CLI_FAILED) {
    return (
      `as a docker client that exits ${String(DOCKER_CLI_FAILED)}, its own failure (a lost daemon connection among ` +
      'them), may leave its container running'
    )
  }
  return undefined
}

/**
 * Why a human asked to approve `args` would not be shown them as they run, or
 * undefined. approval.requested shows APPROVAL_PREVIEW_BYTES of their
 * redacted canonical JSON (policy/engine.ts), judged here as the engine
 * judges it, and the ticket binds all of them, so a part the preview cuts, a
 * span it redacts, or a character a screen does not show as itself would run
 * unseen, whoever approved it. Nothing of the arguments is echoed: a span
 * that redaction would hide is named by its place only.
 */
function previewRefusal(args: Record<string, unknown>, command: readonly string[]): string | undefined {
  const preview = approvalPreview(args)
  if (preview.truncated) {
    return (
      `sandbox.exec's arguments come to ${String(preview.bytes)} bytes as a human approving the call is ` +
      `shown them (redacted canonical JSON), and approval.requested shows at most ${String(APPROVAL_PREVIEW_BYTES)}: ` +
      'a human could approve a command whose end they never saw. Keep each command within that, and write a ' +
      'longer script in steps.'
    )
  }
  // The preview is the canonical JSON redacted (redact.ts): any difference is
  // a span it would show as [REDACTED], and the PEM pattern hides everything
  // between its BEGIN and END markers, a whole command among it.
  if (preview.text !== canonicalize(args)) {
    const at = command.findIndex((arg) => redactString(arg) !== arg)
    const where = at === -1 ? "sandbox.exec's arguments hold, across more than one of them," : `command[${String(at)}] holds`
    return (
      `${where} a span the log redacts as a credential (a PEM private key block, a bearer token, a provider, ` +
      'GitHub, Slack or AWS key, a JWT, or a value the kernel holds as secret), so a human approving this call ' +
      'would be shown [REDACTED] in its place, and could approve a command they cannot read. A worker never holds ' +
      'a credential: keep anything of that shape out of the command, and make a test key inside the container ' +
      'rather than writing one into it.'
    )
  }
  for (const [index, arg] of command.entries()) {
    const unseen = UNSEEN.exec(arg)
    if (unseen === null) continue
    const point = `U+${(unseen[0].codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`
    return (
      `command[${String(index)}] holds ${point}, a character a screen shows as nothing or uses to reorder the text ` +
      'around it (a format, bidi or C1 control, a filler or variation selector, or a line separator), so a human ' +
      'approving this call would not read the command as it runs. Write it as an escape the program decodes, or ' +
      'leave it out.'
    )
  }
  return undefined
}

/**
 * Why `driver`'s audit would refuse `command`, said in the command's terms,
 * or undefined. The real driver's audit reads every element of the docker
 * argv, the command's included (docker.ts commandAuditRefusal): its
 * whole-argv scans refuse `-v` or `--device` anywhere in a command as a
 * second mount or a device, an over-refusal kept until the operator decides
 * whether those scans stop at the image, and the docker socket; its home
 * check refuses an argument that is the operator's home or a path under it,
 * in either spelling. The driver is asked of the whole command, so this
 * refuses exactly the commands its run() refuses, and then of each argument
 * alone, to name the first it refuses on its own: the audit refuses a
 * command only for one of those.
 */
function commandRefusal(command: readonly string[], driver: Pick<SandboxDriver, 'commandRefusal'>): string | undefined {
  const audit = driver.commandRefusal(command)
  if (audit === undefined) return undefined
  const at = command.findIndex((arg) => driver.commandRefusal([arg]) !== undefined)
  const arg = command[at]
  const own = arg === undefined ? undefined : driver.commandRefusal([arg])
  if (arg === undefined || own === undefined) return audit
  // Quoted when short, as a flag is; a long argument that mentions the
  // docker socket is named by its place.
  const named = Buffer.byteLength(arg) <= 64 ? `command[${String(at)}], ${JSON.stringify(arg)},` : `command[${String(at)}]`
  if (own.startsWith('docker args reference the home directory')) {
    // The audit's text names the home in its resolved spelling, which the
    // model need not be told: the argument is named instead.
    return (
      `${named} names the operator's home directory, or a path under it, which no container sees: the sandbox's ` +
      "audit refuses such an argument wherever it stands in the docker run's arguments, in either spelling of the " +
      "home. Name a path under /workspace, the run's own workspace, instead."
    )
  }
  const advice = own.startsWith('docker args mention ')
    ? 'Leave it out: no container reaches the docker daemon, so no command needs its socket.'
    : 'Spell it another way if the program has one (--verbose for -v), or leave it out.'
  return (
    `${named} is refused wherever it stands in a command, for now: the sandbox's audit reads the command as part of ` +
    `the docker run's own arguments, and refuses it there (${own}), until the operator decides whether that check ` +
    `stops at the image. ${advice}`
  )
}

/**
 * Bytes of PAYLOAD_TEXT_BUDGET that describe() leaves to the lines around the
 * two streams (each stream's own, the end, the capture note) and to what a
 * later redaction may add (boundOutput redacts the text again, and the store
 * once more): a text this leaves room for is never cut there, and its
 * tool.result always fits the store's limit.
 */
export const DESCRIBE_RESERVE = 4_096

/**
 * Bytes on a window's cut side that are never shown or hashed: those just
 * before the end of a stream's start, and just after where its end is read
 * from. Each cut is made before anything is redacted (the driver's at
 * CAPTURE_MAX_BYTES, and describe()'s own at STREAM_WINDOW_BYTES), so a
 * credential a cut splits (a token short of the length its pattern needs, a
 * value the kernel holds as secret with its first or last part gone, a PEM
 * block whose other marker lies past the cut) stands there unredacted. A key
 * block a cut splits is also dropped from its marker on, however long it is
 * (pemCut); this covers the rest, which is a few KiB at most for every
 * credential a tool prints. An end window is read from past any token its
 * cut splits, however long (tokenFreeStart), and this edge is dropped after
 * that; one whose start a key block may hold is read from where the blocks
 * that may hold it end, an END's end, instead (pemOpenAt), with no edge: all
 * before that may be a block's body, and the window's cut, with whatever it
 * split, lies before it. So at an end window this edge holds back only a
 * value the kernel's mask holds, which no worker holds. Every token pattern
 * but AWS's has an unbounded part: the PEM pattern's body, which pemCut and
 * pemOpenAt hold, and for the rest Bearer's \s+ and its token, a JWT's
 * segments, and the tails of the provider, GitHub and Slack keys. A token of
 * one of those shapes that crosses a start window's cut, and runs on more
 * than this far before it, may be shown in part (a JWT whose first segment
 * does, which the window's redaction does not match). Only output written to
 * defeat the patterns holds one, and no worker holds a credential to put in
 * it.
 */
export const CAPTURE_EDGE_BYTES = 16_384

/**
 * The most of one stream describe() reads and redacts, in UTF-8 bytes as the
 * driver returned them: the largest share a stream can be shown, and
 * CAPTURE_EDGE_BYTES beyond it on the window's cut side. A stream within it is
 * read whole; a longer one by its end, and one the driver capped by its
 * start. redact.ts's PEM pattern takes time quadratic in a text of BEGIN lines
 * with no END after them (a 1 MiB capture of them takes some 11 s on one
 * core, the daemon's event loop blocked throughout, on an exec that needs no
 * human), and over a window of this size some 60 ms. That bounds the PEM
 * pattern's cost alone: the JWT pattern's, quadratic in a run of `-ey`, is
 * some 2 s over one window, and is held by JWT_RUN_STARTS_MAX. Redaction may
 * shrink a window (a key block is [REDACTED]), and a stream is then shown
 * less of than its share: never more than its window.
 */
export const STREAM_WINDOW_BYTES = PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE + CAPTURE_EDGE_BYTES

/**
 * The most places redact.ts's JWT pattern may start in one run of `text`, a
 * stretch of the characters its segments take ([A-Za-z0-9_-]) that anything
 * else ends, a `.` among them, for a window holding it to be redacted. The
 * pattern (TOKEN_PATTERNS) starts at every `ey` with no word character before
 * it, so inside a run at every `-ey`, and from each start scans the rest of
 * its run, and of the two after it when a `.` and `ey` join them, before it
 * fails: a run of `-ey` repeated takes time quadratic in its length, some 2 s
 * over one window, the event loop blocked throughout, and again on every
 * later redaction of the result while the model holds it (each llm.request).
 * Each start's scan ends within three runs, so with no run holding more
 * than this many starts a pass scans a window at most three times over for
 * each start a run may hold, some 3 ms (measured over a window: 2.5 ms for
 * runs of 16 starts each, 6.5 ms at 32, 11 ms at 64). Output no one
 * wrote to defeat the pattern holds no run like it: a token is one start or
 * two, and random base64url holds `-ey` once in some 260 000 characters. A
 * window holding one is withheld whole, not cut around it: a cut inside the
 * run could split whatever credential it holds.
 */
export const JWT_RUN_STARTS_MAX = 16

/** A character a JWT segment takes: [A-Za-z0-9_-]. */
function segmentChar(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === 0x5f || c === 0x2d
}

/** A character a regular expression's \b reads as a word character: [A-Za-z0-9_]. */
function wordChar(c: number): boolean {
  return segmentChar(c) && c !== 0x2d
}

/**
 * The most places redact.ts's JWT pattern starts in any one run of `text`
 * (JWT_RUN_STARTS_MAX), in one pass and no regular expression: an `ey` with
 * no word character before it.
 */
export function jwtRunStarts(text: string): number {
  let most = 0
  let starts = 0
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (!segmentChar(c)) {
      starts = 0
      continue
    }
    if (c === 0x65 && text.charCodeAt(i + 1) === 0x79 && (i === 0 || !wordChar(text.charCodeAt(i - 1)))) {
      starts += 1
      if (starts > most) most = starts
    }
  }
  return most
}

/**
 * A character a match of redact.ts's token patterns (TOKEN_PATTERNS, the PEM
 * pattern aside) may hold, white space aside: Bearer's credential takes
 * [A-Za-z0-9._~+/-] and the `=` that pads it, and every other pattern's
 * prefix and run take only those. The one white space any of them takes is
 * Bearer's \s+, just after the word. Held to redact.ts by
 * test/sandbox-exec.test.ts, which pins the patterns this is read from.
 */
function tokenChar(c: number): boolean {
  return segmentChar(c) || c === 0x2e || c === 0x7e || c === 0x2b || c === 0x2f || c === 0x3d
}

/** White space as the Bearer pattern's \s reads it, Unicode spaces among it. */
const WHITE_SPACE = /\s/

/**
 * Where an end window whose cut is at `from` in `raw` is read from: the first
 * place at or after it that no match of redact.ts's token patterns runs
 * across. That is `from` when no match can hold the character before it,
 * else the first character at or after `from` that none can: one tokenChar
 * refuses, or white space with no `Bearer` just before its run (read back
 * over white space, past the cut too). No match of any pattern, at its turn,
 * holds that character, so each ends before it or starts after it, and \b
 * reads the same beside it in the window as in the stream (it is no word
 * character): a redaction of what follows it matches each token a redaction
 * of all of `raw` matches there, and no other. What lies between `from` and
 * that place, among it the rest of any token the cut split, is not read. A
 * value the kernel's mask holds (SecretMask), which no worker holds, is not
 * followed. Linear: past the cut it reads each character once, and back from
 * it only over the white space before it.
 */
export function tokenFreeStart(raw: string, from: number): number {
  if (from <= 0) return 0
  let i = from - 1
  while (i < raw.length) {
    if (tokenChar(raw.charCodeAt(i))) {
      i += 1
      continue
    }
    if (!WHITE_SPACE.test(raw.charAt(i))) return Math.max(i, from)
    let run = i
    while (run > 0 && WHITE_SPACE.test(raw.charAt(run - 1))) run--
    const word = run - 'Bearer'.length
    if (!(word >= 0 && raw.startsWith('Bearer', word))) return Math.max(i, from)
    while (i < raw.length && WHITE_SPACE.test(raw.charAt(i))) i++
  }
  return raw.length
}

/**
 * The most a driver's own text takes in describe()'s head, in payload bytes:
 * a kill's refusal, or a signal no docker client reports. The head is not cut
 * to a share, and a driver's text is not the runner's: one of 40 000 quotes
 * would escape past what tool.result holds, and the call would fail at its
 * last append with the container already gone and its end recorded.
 */
export const DRIVER_TEXT_BYTES = 512

/** A driver's text for the head: redacted, then cut to DRIVER_TEXT_BYTES in payload bytes, and said to be. */
function driverText(text: string): string {
  const redacted = redactString(text)
  if (payloadBytes(redacted) <= DRIVER_TEXT_BYTES) return redacted
  return `${firstFitting(redacted, DRIVER_TEXT_BYTES)} [cut: ${String(Buffer.byteLength(redacted))} bytes in all]`
}

/**
 * The two markers of redact.ts's PEM pattern (TOKEN_PATTERNS), which hides
 * all that stands between a BEGIN and the first END after it. Held to it by
 * test/sandbox-exec.test.ts, so the two cannot drift apart.
 */
export const PEM_BEGIN = /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/
export const PEM_END = /-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/

/**
 * The bytes `text` takes as a string in an event's canonical JSON, its quotes
 * aside: JSON's escapes (canonical.ts), under which a quote, a backslash or a
 * newline takes two bytes and another C0 control six. What the store measures
 * against MAX_LOGGED_OUTPUT, so what each stream's share is counted in: by raw
 * bytes, a stream of quotes or backslashes (`cat package-lock.json`) would
 * fill a tool.result past the store's limit, and the call would fail at its
 * last append with the container already gone.
 */
function payloadBytes(text: string): number {
  return Buffer.byteLength(JSON.stringify(text)) - 2
}

/**
 * The amounts each of two streams keeps of `budget`: both whole when they
 * fit, else each its half, and a stream shorter than its half leaves the rest
 * to the other.
 */
function streamShares(stdout: number, stderr: number, budget: number): readonly [number, number] {
  const room = Math.max(0, budget)
  if (stdout + stderr <= room) return [stdout, stderr]
  const half = Math.floor(room / 2)
  if (stdout <= half) return [stdout, room - stdout]
  if (stderr <= half) return [room - stderr, stderr]
  return [half, room - half]
}

/** The code point of `text` that ends at `end`, a pair of surrogates whole. */
function codePointBefore(text: string, end: number): string {
  const low = text.charCodeAt(end - 1)
  const high = end >= 2 ? text.charCodeAt(end - 2) : 0
  const pair = low >= 0xdc00 && low <= 0xdfff && high >= 0xd800 && high <= 0xdbff
  return text.slice(pair ? end - 2 : end - 1, end)
}

/** The longest end of `text` whose payloadBytes is at most `keep`, whole code points only. */
function lastFitting(text: string, keep: number): string {
  let start = text.length
  let used = 0
  while (start > 0) {
    const point = codePointBefore(text, start)
    const cost = payloadBytes(point)
    if (used + cost > keep) break
    used += cost
    start -= point.length
  }
  return text.slice(start)
}

/** The longest start of `text` whose payloadBytes is at most `keep`, whole code points only. */
function firstFitting(text: string, keep: number): string {
  let end = 0
  let used = 0
  for (const point of text) {
    const cost = payloadBytes(point)
    if (used + cost > keep) break
    used += cost
    end += point.length
  }
  return text.slice(0, end)
}

/** The first `max` UTF-8 bytes of `text` at most, cut on a code point boundary. */
function utf8Head(text: string, max: number): string {
  const buf = Buffer.from(text, 'utf8')
  if (buf.length <= max) return text
  let end = Math.max(0, max)
  for (let b = buf[end]; b !== undefined && (b & 0xc0) === 0x80; b = buf[end]) end--
  return buf.subarray(0, end).toString('utf8')
}

/** The last `max` UTF-8 bytes of `text` at most, cut on a code point boundary. */
function utf8Tail(text: string, max: number): string {
  const buf = Buffer.from(text, 'utf8')
  if (buf.length <= max) return text
  let start = buf.length - Math.max(0, max)
  for (let b = buf[start]; b !== undefined && (b & 0xc0) === 0x80; b = buf[start]) start++
  return buf.subarray(start).toString('utf8')
}

/** Where the first PEM_END in `text` ends, or -1 when it holds none. */
function firstEndAfter(text: string): number {
  const end = PEM_END.exec(text)
  return end === null ? -1 : end.index + end[0].length
}

/**
 * redact.ts's AWS access key id pattern (TOKEN_PATTERNS), the one token
 * pattern that can match inside a PEM marker. Held to it by
 * test/sandbox-exec.test.ts, so the two cannot drift apart.
 */
export const AWS_KEY_ID = /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/

/**
 * Whether the END `marker`, at `at` in `raw`, still closes a block once
 * redact.ts's token patterns have run over the stream, as they do before its
 * PEM pattern (TOKEN_PATTERNS): a token they match that overlaps the marker
 * becomes [REDACTED], no END is left there, and the block it would have
 * closed runs on to the next END that is. A marker holds only upper case,
 * digits, space, `-` and `_`, and every token's prefix but AWS's holds lower
 * case, so only these overlap one: an AWS id inside it, and a token whose run
 * reaches into its leading `-----END` (Bearer's credential, sk-'s, Slack's, a
 * JWT's last segment), which needs a character such a run takes, or a `.`,
 * just before the marker, or white space with Bearer before it
 * (`Bearer\n-----END`). Judged generously, so an END a token may break is
 * taken as one it does: pemOpenAt holds a block open from every BEGIN,
 * whichever ENDs this refuses, so refusing one only holds a block open
 * longer, and hides more. A value the kernel's own mask holds (SecretMask,
 * which runs before the patterns) is not followed: no worker holds one.
 */
export function pemEndHolds(raw: string, at: number, marker: string): boolean {
  if (AWS_KEY_ID.test(marker)) return false
  if (at > 0 && /[A-Za-z0-9._~+/-]/.test(raw.charAt(at - 1))) return false
  let space = at
  while (space > 0 && /\s/.test(raw.charAt(space - 1))) space--
  if (space === at) return true
  const word = space - 'Bearer'.length
  return !(word >= 0 && raw.startsWith('Bearer', word) && (word === 0 || !/\w/.test(raw.charAt(word - 1))))
}

/**
 * Where the private key blocks redact.ts's PEM pattern may hide, around `at`
 * in `raw`, end: undefined when none of them holds `at` (one that starts at
 * `at`, or ends there, does not), null when one does and no END ends it, else
 * where the blocks that overlap the one holding it end: the end of the END
 * that ends the last of them. Read as a union, not as one pairing of the
 * markers: every BEGIN, each one inside another marker included, is held
 * open from where it starts to the first END that pemEndHolds admits
 * starting at or after where it ends, read greedily, and blocks that overlap
 * are one. Over-approximating so:
 *
 *   each block redact.ts hides starts at a BEGIN of `raw` (a marker holds no
 *   `[` or `]`, so no [REDACTED] stands inside one), its marker there ending
 *   no later than the greedy one (a token pattern, run first, may cut it short,
 *   and the pattern backtracks into it when nothing follows it);
 *   the block ends at the first END that survives those patterns after its
 *   marker, and an END pemEndHolds admits is one that survives, so that END
 *   starts no later than the one taken here, and the one taken here ends no
 *   earlier (one that starts inside it reaches its PRIVATE KEY-----, or one
 *   past it);
 *
 * so each such block lies inside one held open here, whichever ENDs
 * pemEndHolds refuses and however the patterns pair the markers: refusing an
 * END only holds a block open longer. A pairing of one chain (a BEGIN opens a
 * block when none is open, the END that closes it ends it, and the next
 * BEGIN is sought past it) is not this: a refused END the stream's redaction
 * keeps leaves the chain open past the block it closed, and the chain then
 * closes on an END inside the next BEGIN's marker, and never opens the block
 * that BEGIN opens. A value the kernel's mask holds (SecretMask) is not
 * followed (pemEndHolds). Two passes, linear but for a binary search for
 * each BEGIN's END: every END, then every BEGIN, each sought one character
 * past the last one's start, each marker some 130 characters at most, and
 * pemEndHolds reading back over the white space before an END, which no
 * other END shares.
 */
function pemOpenAt(raw: string, at: number): number | null | undefined {
  // Every END pemEndHolds admits, each inside another marker included, in
  // order of where it starts.
  const end = new RegExp(PEM_END.source, 'g')
  const heldStarts: number[] = []
  const heldEnds: number[] = []
  for (let m = end.exec(raw); m !== null; m = end.exec(raw)) {
    if (pemEndHolds(raw, m.index, m[0])) {
      heldStarts.push(m.index)
      heldEnds.push(m.index + m[0].length)
    }
    end.lastIndex = m.index + 1
  }
  // The end of the first of them that starts at or after `from`, or Infinity.
  const closeAt = (from: number): number => {
    let lo = 0
    let hi = heldStarts.length
    while (lo < hi) {
      const mid = (lo + hi) >>> 1
      if ((heldStarts[mid] ?? Infinity) < from) lo = mid + 1
      else hi = mid
    }
    return heldEnds[lo] ?? Infinity
  }
  // Every BEGIN, in order: [where it starts, closeAt(where it ends)], those
  // that overlap merged, until the one holding `at` is known.
  const begin = new RegExp(PEM_BEGIN.source, 'g')
  let start = -1
  let reach = -1
  for (let m = begin.exec(raw); m !== null; m = begin.exec(raw)) {
    if (m.index >= reach) {
      if (start < at && at < reach) break
      if (m.index >= at) return undefined
      start = m.index
    }
    reach = Math.max(reach, closeAt(m.index + m[0].length))
    begin.lastIndex = m.index + 1
  }
  if (!(start < at && at < reach)) return undefined
  return reach === Infinity ? null : reach
}

/**
 * What may be shown of `read`, a window redacted, on the side its cut is on:
 * not its CAPTURE_EDGE_BYTES there, nor a private key block the cut splits.
 * redact.ts hid every block whose two markers the window holds, so a marker
 * left in `read` is one whose other, if any, lies past the cut. Of a start,
 * nothing from the first BEGIN left on: in the stream as printed, the
 * pattern pairs it with the first END past the cut and hides all between,
 * any later BEGIN among it. Of an end, nothing up to the first END left.
 * streamOf reads an end window here only from where no token's match runs
 * across (tokenFreeStart), so its token patterns match what the stream's
 * match there, and only when no block pemOpenAt holds open holds that place,
 * so no block the stream's redaction hides crosses it: the window's
 * redaction is then the stream's there, and an END left here closes none of
 * its blocks, but for a value the kernel's mask holds, which no worker holds
 * and neither reads as the other does. It is held to as one that may, which
 * costs only what stands before it.
 */
function pemCut(read: string, side: 'start' | 'end'): string {
  const bytes = Buffer.byteLength(read)
  if (side === 'start') {
    const edge = utf8Head(read, bytes - CAPTURE_EDGE_BYTES)
    const begin = read.search(PEM_BEGIN)
    return begin === -1 || begin >= edge.length ? edge : read.slice(0, begin)
  }
  const edge = utf8Tail(read, bytes - CAPTURE_EDGE_BYTES)
  const after = firstEndAfter(read)
  return after <= read.length - edge.length ? edge : read.slice(after)
}

/** One stream as describe() read it. */
interface Stream {
  readonly label: 'stdout' | 'stderr'
  /**
   * What is shown of the stream, redacted: all of it, or a window of it short
   * of its cut side; or, when `withheld`, the line said in its place.
   */
  readonly text: string
  /**
   * Set when `text` is a window: of its start, for a stream the driver
   * capped, or of its end, for one longer than STREAM_WINDOW_BYTES; and the
   * bytes the driver returned of the stream, as printed.
   */
  readonly window?: { readonly side: 'start' | 'end'; readonly printed: number }
  /**
   * Set when what was to be read of the stream held a run JWT_RUN_STARTS_MAX
   * refuses: `text` says so. `capped` when the driver capped the stream, so
   * that `printed` is what its capture kept, not all it printed.
   */
  readonly withheld?: { readonly printed: number; readonly capped: boolean }
}

/**
 * A stream withheld in place of being read (JWT_RUN_STARTS_MAX), or
 * undefined when `read`, the part of it to be redacted, may be. Said by its
 * byte count alone, with no digest: a digest of text no redaction has read
 * would commit the log to whatever it holds (bound.ts). Of a stream the
 * driver `capped`, that count is what its capture kept: the stream printed
 * at least that, and may have printed more.
 */
function withheld(label: Stream['label'], read: string, printed: number, capped: boolean): Stream | undefined {
  if (jwtRunStarts(read) <= JWT_RUN_STARTS_MAX) return undefined
  const count = capped ? `its capture kept ${String(printed)} bytes` : `the stream printed ${String(printed)} bytes`
  return {
    label,
    text:
      `[withheld: what would be read of this stream holds a run of letters, digits, - and _ in which redact.ts's ` +
      `JWT pattern starts at more than ${String(JWT_RUN_STARTS_MAX)} places, which redaction reads in time ` +
      `quadratic in the run's length, so none of it is redacted or shown; ${count}]`,
    withheld: { printed, capped },
  }
}

/**
 * Read one stream: whole and redacted when it is within STREAM_WINDOW_BYTES,
 * else a window of it, redacted and then cut short of its cut side (pemCut).
 * A stream the driver capped is read from its start: its end is the middle of
 * what the container printed, at the driver's cut. The driver reports one
 * `truncated` for both streams, and its cut moves back at most three bytes,
 * to a character's start (docker.ts Capture), so a stream within three bytes
 * of the cap is taken as one it capped. A stream that filled the cap exactly
 * while the other was cut is taken so too, and shows its start: less of it,
 * nothing it did not print. An end window is read from its cut, or from the
 * first character past it that no token's match may hold when one may hold
 * the character before it (tokenFreeStart), and what that skips is not
 * shown, a token the cut splits among it, however long, and all of the
 * stream past the cut when no such character follows: no match runs across
 * where it is read from, so its redaction matches each token the stream's
 * matches there, and no other. A window whose start a key block may hold,
 * however the stream's redaction pairs the markers (pemOpenAt), is read from
 * where the blocks that may hold it end, and shows nothing when none ends:
 * all before that may be key body the stream's redaction would hide, a
 * credential its cut splits among it. What an end window shows is then an
 * end of what a redaction of the whole stream shows, but for a value the
 * kernel's mask holds (SecretMask). What is to be read is first held to
 * JWT_RUN_STARTS_MAX, and withheld past it.
 */
function streamOf(label: Stream['label'], raw: string, truncated: boolean): Stream {
  const printed = Buffer.byteLength(raw)
  if (truncated && printed >= CAPTURE_MAX_BYTES - 3) {
    const read = utf8Head(raw, STREAM_WINDOW_BYTES)
    const window = { side: 'start', printed } as const
    return withheld(label, read, printed, true) ?? { label, text: pemCut(redactString(read), 'start'), window }
  }
  if (printed <= STREAM_WINDOW_BYTES) return withheld(label, raw, printed, false) ?? { label, text: redactString(raw) }
  const cut = raw.length - utf8Tail(raw, STREAM_WINDOW_BYTES).length
  const from = tokenFreeStart(raw, cut)
  const tail = raw.slice(from)
  const window = { side: 'end', printed } as const
  const closes = pemOpenAt(raw, from)
  if (closes === null) return { label, text: '', window }
  if (closes !== undefined) {
    const read = raw.slice(closes)
    return withheld(label, read, printed, false) ?? { label, text: redactString(read), window }
  }
  return withheld(label, tail, printed, false) ?? { label, text: pemCut(redactString(tail), 'end'), window }
}

/**
 * One stream as the model and the log read it, within `keep` payload bytes,
 * and the whole it stands for: what is shown of it before its share is cut.
 * A stream read whole, or by its end, keeps its end, where a failure is; one
 * the driver capped keeps its start. A heading's byte counts are of the
 * redacted text, but for the bytes a windowed or withheld stream printed.
 */
function streamPart(stream: Stream, keep: number): { readonly cut: string; readonly whole: string } {
  const { label, text, window } = stream
  const bytes = Buffer.byteLength(text)
  const heading = (shown: number): string => {
    const kept = stream.withheld
    if (kept?.capped === true) {
      return `--- ${label} (withheld: the ${String(kept.printed)} bytes its capture kept; the stream may have carried more) ---`
    }
    if (kept !== undefined) return `--- ${label} (withheld: ${String(kept.printed)} bytes printed) ---`
    if (window?.side === 'start') {
      return (
        `--- ${label} (its start, redacted: ${String(shown)} bytes, of the ${String(window.printed)} bytes its ` +
        'capture kept; the stream may have carried more) ---'
      )
    }
    if (window?.side === 'end') {
      return `--- ${label} (its end, redacted: ${String(shown)} bytes, of the ${String(window.printed)} bytes it printed) ---`
    }
    if (shown === bytes) return `--- ${label} (${String(bytes)} bytes) ---`
    return `--- ${label} (${String(bytes)} bytes, cut to its last ${String(shown)}) ---`
  }
  const whole = `${heading(bytes)}\n${text}`
  if (payloadBytes(text) <= keep) return { cut: whole, whole }
  const shown = window?.side === 'start' ? firstFitting(text, keep) : lastFitting(text, keep)
  return { cut: `${heading(Buffer.byteLength(shown))}\n${shown}`, whole }
}

/**
 * What the model and the log read of one container's end: how it ended, the
 * exit status among it, first, then each stream, said whole or cut.
 *
 * Each stream is bounded to its own share of PAYLOAD_TEXT_BUDGET, counted in
 * payload bytes, before the two are joined: a run that prints more than the
 * budget to stdout and its failure to stderr would otherwise reach the model
 * with no stderr, cut by boundOutput from the end of the joined text.
 * Redacted as read, before anything is measured or cut, as boundOutput
 * redacts, so a cut to a share never leaves part of a credential its pattern
 * would match whole.
 */
function describe(spec: SandboxSpec, result: SandboxResult, sent: string | undefined, egress?: EgressEnd, unserved?: Unserved): Done {
  const wallclock = `${String(spec.limits.wallclockMs)} ms`
  // A grant that went unserved was a channel run's as much as a served one:
  // its docker client's exit is the mux's, and with no session nobody sent
  // the mux a go, so its command never ran and has no exit status at all.
  const channel = egress !== undefined || unserved !== undefined
  // On a channel run the command's own exit status is the exit frame's: the
  // docker client's exit is the mux's, which says how the mux ended.
  const commandExit = egress?.outcome.exitStatus
  const status = commandExit ?? result.exitCode
  const code = result.exitCode === null ? '' : ` (exit ${String(result.exitCode)})`
  let how: string
  if (result.killedBy === 'wallclock') how = `was killed at its wallclock of ${wallclock}${code}`
  else if (result.killedBy === 'requested' && egress?.revokedBySession === true) {
    how = `was killed by name when its egress grant was revoked${code}`
  } else if (result.killedBy === 'requested' && egress?.killedAfterExitMs !== undefined) {
    const exited = commandExit === undefined ? '' : ` ${String(commandExit)}`
    how = `was killed by name, still running ${String(egress.killedAfterExitMs)} ms after its command exited${exited}${code}`
  } else if (result.killedBy === 'requested' && unserved !== undefined) {
    // The kernel's own kill of a container whose grant nothing could serve:
    // the run was not stopped, and the head must not say it was.
    how = `was killed by name by the kernel, which could not serve its egress grant${code}`
  } else if (result.killedBy === 'requested') how = `was killed: the run was stopped${code}`
  else if (result.overran === true) {
    how = `outlived its wallclock of ${wallclock}: the kill it was sent ended nothing, and it then exited on its own${code}`
  } else if (channel && commandExit === undefined) {
    how = `ended with no exit status from its command (${clientEnd(result)})`
  } else if (status === null) {
    // The driver's own text, bounded: a SandboxDriver other than docker.ts's
    // may report anything here, and the head is not cut to a share.
    const signal = result.signal ?? undefined
    how = `ended with no exit status (${signal === undefined ? 'the docker client did not start' : driverText(String(signal))})`
  } else how = `exited ${String(status)}`
  const network = egress === undefined ? 'no network' : egressSaid(egress)
  const head = [
    `${spec.name} on the ${spec.domain} domain, ${network}, ${how} after ${String(result.durationMs)} ms` +
      (sent === undefined ? '' : `; ${sent}`),
  ]
  const revoked = egress === undefined ? undefined : revocationSaid(egress)
  if (revoked !== undefined) head.push(revoked)
  if (unserved !== undefined) {
    head.push(redactString(`[egress grant ${unserved.grantId} revoked unserved: ${utf8Head(unserved.detail, DRIVER_TEXT_BYTES)}]`))
  }
  // On a channel run each stream is the session's capture of the command's
  // frames, cut on its own; the docker client's stderr (the mux's own
  // complaints) follows the command's. An unserved grant's command never
  // ran, so its run's stderr is the docker client's alone, and said to be.
  const clientErr = result.stderr === '' ? '' : `[the docker client's stderr]\n${result.stderr}`
  const outText = egress === undefined ? result.stdout : decoded(egress.outcome.stdout)
  const errText =
    egress !== undefined
      ? `${decoded(egress.outcome.stderr)}${clientErr === '' ? '' : `\n${clientErr}`}`
      : channel
        ? clientErr
        : result.stderr
  const outCut = egress === undefined ? result.truncated : egress.outcome.stdoutTruncated
  const errCut = egress === undefined ? result.truncated : egress.outcome.stderrTruncated || result.truncated
  if (outCut || errCut) {
    head.push(
      `[output cut: a stream carried more than ${String(CAPTURE_MAX_BYTES)} bytes, and the driver kept only its ` +
        'first; such a stream is shown from its start]',
    )
  }
  const stdout = streamOf('stdout', outText, outCut)
  const stderr = streamOf('stderr', errText, errCut)
  const room = PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE - payloadBytes(head.join('\n'))
  const [outKeep, errKeep] = streamShares(payloadBytes(stdout.text), payloadBytes(stderr.text), room)
  const out = streamPart(stdout, outKeep)
  const err = streamPart(stderr, errKeep)
  const text = [...head, out.cut, err.cut].join('\n')
  // A channel run is ok only by its command's own exit status, from the exit
  // frame, and a grant that ended with its container: the mux's exit says
  // nothing of the command. A grant that went unserved ran no command, so
  // its run is never ok, whatever the mux exited.
  const exitedOk =
    unserved !== undefined
      ? false
      : egress === undefined
        ? result.exitCode === 0
        : commandExit === 0 && egress.outcome.reason === 'exited'
  const ok = result.killedBy === undefined && result.overran !== true && exitedOk
  // A stream shown by its window, or withheld, is not all the container
  // printed: the result is marked cut even when its text then fits whole.
  const partial = [stdout, stderr].some((stream) => stream.window !== undefined || stream.withheld !== undefined)
  if (!partial && out.cut === out.whole && err.cut === err.whole) return { ok, text }
  return { ok, text, whole: [...head, out.whole, err.whole].join('\n') }
}

/**
 * How a channel run's docker client ended, for one whose command sent no exit
 * status: the client's exit is the mux's (MUX_EXIT, which never uses 125),
 * except when the client says nothing of its container (mayRunOn): no exit
 * status, or 125, its own failure.
 */
function clientEnd(result: SandboxResult): string {
  if (result.exitCode === null) {
    const signal = result.signal ?? undefined
    const why = signal === undefined ? 'it did not start' : driverText(String(signal))
    return `the docker client ended with no exit status (${why}) before the mux sent one`
  }
  if (result.killedBy === undefined && result.exitCode === DOCKER_CLI_FAILED) {
    return `the docker client exited ${String(DOCKER_CLI_FAILED)}, its own failure, before the mux sent one`
  }
  return `the mux exited ${String(result.exitCode)} before it sent one`
}

/** A session's captured bytes as text: UTF-8, a byte that is none read as U+FFFD, as the driver decodes a stream. */
function decoded(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('utf8')
}

/** How a channel run reached the network, for the result's head: its grant and the grant's totals. */
function egressSaid(egress: EgressEnd): string {
  const t = egress.outcome.totals
  return (
    `no network but the kernel's egress engine (grant ${egress.grantId}: ${String(t.requests)} request(s), ` +
    `${String(t.allowed)} allowed, ${String(t.denied)} denied)`
  )
}

/** Why a channel run's grant ended, when not with its container's exit: a line for the result's head, redacted and bounded. */
function revocationSaid(egress: EgressEnd): string | undefined {
  const { reason, limit, detail } = egress.outcome
  if (reason === 'exited') return undefined
  const why = `${reason}${limit === undefined ? '' : ` (${limit})`}${detail === undefined ? '' : `: ${utf8Head(detail, DRIVER_TEXT_BYTES)}`}`
  return redactString(`[egress grant ${egress.grantId} revoked: ${why}]`)
}

/**
 * A failed call: its text redacted, and cut to PAYLOAD_TEXT_BUDGET less
 * DESCRIBE_RESERVE in payload bytes, its whole kept for tool.result's bytes
 * and sha256. A refusal of the runner's names what the model sent by place
 * only, but a driver's or the log's error is theirs, and boundOutput cuts by
 * raw bytes, past which a text of quotes or control characters escapes in the
 * log's JSON to more than tool.result can hold: the call would then fail at
 * its last append, with tool.call written and no tool.result.
 */
function failed(message: string): Done {
  const text = redactString(message)
  const budget = PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE
  if (payloadBytes(text) <= budget) return { ok: false, text }
  return { ok: false, text: firstFitting(text, budget), whole: text }
}
