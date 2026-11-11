// Sandbox tools: a worker's commands, run in a container (egress plan S3).
//
// `sandbox.exec` runs one command in one container of the run's own sandbox
// domain, and nothing else: no network (every run is --network none), no
// channel (so no egress, whatever the manifest's egress says, until the wiring
// task W1 gives exec a grant), the pinned worker image by id, and the run's
// own workspace, <mountRoot>/<runId>, at /workspace. A second exec of the same
// run sees what the first left there; no other run's does.
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
//   so it never holds the call. The driver's result itself has no bound of the
//   runner's: DockerDriver settles it only once the docker CLI closes, and its
//   wallclock is a kill by name through the same daemon, so a daemon that
//   accepts and never answers (a paused VM) holds the call, and the run, past
//   the container's wallclock, until the wiring task bounds that wait (egress
//   plan W1).
//
// Its arguments are held to what a human is shown of them: approval.requested
// previews at most APPROVAL_PREVIEW_BYTES of their redacted canonical JSON
// (policy/engine.ts), and the ticket binds all of them, so an exec whose
// arguments that preview would not show as they run is refused, whoever
// approved it: one the preview would cut (a command padded past it runs a
// tail the human never saw), one it would redact (redact.ts shows a span
// shaped like a credential as [REDACTED], and the PEM pattern hides all that
// stands between its markers), and one holding a character a screen shows as
// nothing or uses to reorder the text around it. The human is still asked
// first, since the gate is generic; the runner refuses after. Its output
// reaches the model and the log with each stream bounded to its own share,
// counted in the bytes it takes in the logged JSON, so stderr, and the end of
// each, where a failure is, is never lost to a long stdout, and a stream of
// quotes or backslashes never pushes tool.result past the store's limit. Of
// each stream at most STREAM_WINDOW_BYTES is read and redacted: all of a
// shorter one, the end of a longer one, and the start of one the driver
// capped (it keeps the first CAPTURE_MAX_BYTES, cut before any redaction),
// because redact.ts's PEM pattern takes time quadratic in a text of BEGIN
// lines with no END after them, and a MiB of those would block the daemon's
// event loop for seconds. A window is never shown on its cut side: not the
// CAPTURE_EDGE_BYTES there, where the cut may split a credential, nor a
// private key block the cut splits, from its marker on. tool.result's bytes
// and sha256 describe what was read, redacted: the windows, not the streams.
//
// Its result TAINTS the run, always, whatever tool-views.yaml says of it: a
// container runs whatever the model asked for, on a workspace a container
// wrote, and what it prints is attacker-influenced. From then on every write
// in the run, the next exec among them, waits for a human (invariant 3).
//
// Who may hold these tools is the registry's call, at load, through
// sandboxToolProblem: a worker, with a sandbox: block, at tier 2 or more. The
// loop offers a tool only to a manifest that lists it, so no other agent is
// ever offered one. This runner is built and tested, and not yet wired into
// bootKernel or the run loop (egress plan W1); no shipped manifest lists it.
//
// Its hard wallclock is what is left of the run's budget, at most
// sandbox.defaults.wallclockMs: a container never outlives the run that
// started it, nor the operator's cap on one container. The driver enforces it
// (docker.ts): kill by name when it elapses.

import { lstatSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'

import type { AgentManifest } from '../agents/manifest.js'
import type { AgentRecord } from '../agents/registry.js'
import type { KernelConfig } from '../config.js'
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
  CONTAINER_PREFIX,
  type RunningSandbox,
  type SandboxDomain,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from '../sandbox/driver.js'
import { wholeArgvRefusal } from '../sandbox/docker.js'
import { imageIdProblem, memoryBytes } from '../sandbox/limits.js'

/** The server id sandbox tools are addressed under: `sandbox.exec`. */
export const SANDBOX_SERVER = 'sandbox'

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
 * The docker CLI's own failure status: `docker run` exits 125 when the error
 * is the CLI's or the daemon's rather than the container's, a daemon
 * connection lost mid-run among them (Colima's forwarded socket dropping as
 * the Mac sleeps), after which its --rm container runs on in the VM. A
 * container's own `exit 125` looks the same, and a kill of a name no daemon
 * holds is harmless, so either is killed by name.
 */
export const DOCKER_CLI_FAILED = 125

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

const EXEC_DESCRIPTION =
  'Run one command in a fresh container of your sandbox, with no network. The command is an argv (no shell ' +
  'unless you name one, e.g. ["sh", "-c", "..."]), run in /workspace, your run\'s own workspace, which persists ' +
  'between calls in this run. The root filesystem is read-only and /tmp is a small scratch tmpfs. You get the exit ' +
  'status and the output. The output is untrusted: once a run has used this tool, every later write in it, the ' +
  'next sandbox.exec included, waits for a human.'

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
   * When the text was cut to fit: all that was read before the cut, redacted
   * already (each stream whole or as its window, before describe() cut one to
   * its share, or a refusal before it was cut to the budget). What
   * tool.result's bytes and sha256 then describe, as they describe the whole
   * of any text boundOutput cuts.
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

  constructor(options: SandboxToolsOptions) {
    this.#o = options
  }

  /** Schemas for every sandbox tool the policy file exposes to agents. */
  schemas(): ToolSchema[] {
    if (resolveView(this.#o.views, SANDBOX_SERVER, 'exec').exposure !== 'agent') return []
    return [{ ref: `${SANDBOX_SERVER}.exec`, description: EXEC_DESCRIPTION, inputSchema: EXEC_SCHEMA }]
  }

  isSandboxRef(ref: string): boolean {
    return ref.startsWith(`${SANDBOX_SERVER}.`)
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
    const record = this.#o.agents.get(agentId)
    if (record === undefined) throw new PolicyDenied(ref, `no agent ${agentId} is registered`)
    if (record.status !== 'active') throw new PolicyDenied(ref, `agent ${agentId} is ${record.status}`)
    const problem = sandboxToolProblem(record.manifest)
    if (problem !== undefined) throw new PolicyDenied(ref, problem)
    if (!record.manifest.tools.allow.includes(ref)) {
      throw new PolicyDenied(ref, `${ref} is not in agent ${agentId}'s manifest (default deny)`)
    }
    return record.manifest
  }

  /** One command in one container, start to end. */
  async #exec(args: Record<string, unknown>, ctx: SandboxCallContext, manifest: AgentManifest): Promise<Done> {
    const parsed = ExecArgs.safeParse(args)
    if (!parsed.success) {
      const issues = parsed.error.issues.map(issueText).join('; ')
      throw new Error(`[refused] sandbox.exec takes {command: [program, ...args]}: ${issues}`)
    }
    const { command } = parsed.data
    const unshown = previewRefusal(args, command)
    if (unshown !== undefined) throw new Error(`[refused] ${unshown}`)
    // Before the workspace is made: the driver's audit would refuse it too,
    // after, in docker's terms rather than the command's.
    const flagged = commandRefusal(command)
    if (flagged !== undefined) throw new Error(`[refused] ${flagged}`)
    if (ctx.signal?.aborted === true) throw new Error('[refused] the run was stopped before the container started')

    const { imageId, domains, defaults } = this.#o.sandbox
    const unpinned = imageIdProblem(imageId)
    if (unpinned !== undefined || imageId === undefined) throw new Error(`[refused] ${unpinned ?? 'no image id'}`)

    // The manifest's own domain. #holder admitted only a manifest with one;
    // this says so to the compiler without choosing a domain for it.
    const box = manifest.sandbox
    if (box === undefined) throw new Error(`[refused] ${manifest.id} declares no sandbox: block`)
    const domain = box.domain

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
      name: `${CONTAINER_PREFIX}${ctx.runId}-${String(this.#seq)}`,
      runId: ctx.runId,
      agentId: ctx.agentId,
      domain,
      image: imageId,
      command,
      workspace,
      limits: { memoryMb, cpus: defaults.cpus, pids: defaults.pidsLimit, wallclockMs },
      // No channel: no egress until W1 issues exec a grant, and the hostile
      // domain never gets one. A run without one has no -i, and its stdin is
      // closed at once.
    }

    let running: RunningSandbox
    try {
      running = this.#o.driver.run(spec)
    } catch (e) {
      // The driver refuses before it starts anything (SandboxDriver.run), so
      // there is no container to record.
      throw new Error(`[refused] ${e instanceof Error ? e.message : String(e)}`)
    }
    const kill = (): void => {
      void this.#killByName(spec.name)
    }
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
      // fails only once it has ended (its wallclock bounds the wait), with the
      // log's refusal, whatever the driver's result says.
      kill()
      await running.result.then(
        () => undefined,
        () => undefined,
      )
      throw e
    }

    const signal = ctx.signal
    signal?.addEventListener('abort', kill, { once: true })
    if (signal?.aborted === true) kill()
    let result: SandboxResult
    try {
      result = await running.result
    } catch (e) {
      // A driver's result settles and never rejects (SandboxDriver.run). One
      // that did says nothing of its container: it is killed by name, and its
      // end recorded, so no started row is left open on a container that runs.
      const sent = await this.#killByName(spec.name)
      this.#o.store.append({
        type: 'sandbox.killed',
        runId: ctx.runId,
        agentId: ctx.agentId,
        payload: { schemaVersion: 1, sandboxId: spec.name, reason: 'error' },
      })
      throw new Error(`[error] the driver lost ${spec.name}: ${e instanceof Error ? e.message : String(e)}; ${sent}`)
    } finally {
      signal?.removeEventListener('abort', kill)
    }

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
    return describe(spec, result, sent)
  }

  /**
   * Kill `name` by name, and say so for the result text. Never rejects, and
   * waits KILL_WAIT_MS at most (killWaitMs in a test), so the caller always
   * records the container's end: the real driver's kill never rejects, but
   * may never settle (docker.ts #killOn has no timeout), and another's that
   * rejects or throws is logged and said, never thrown.
   */
  async #killByName(name: string): Promise<string> {
    const waitMs = this.#o.killWaitMs ?? KILL_WAIT_MS
    // An async function, so a driver's kill that throws as it is called
    // rejects instead, and the kill is sent now, before any await.
    const killing = (async (): Promise<void> => {
      await this.#o.driver.kill(name)
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
        log.warn({ sandboxId: name, driver: this.#o.driver.name, waitMs }, 'sandbox kill by name went unanswered')
        return `a kill by name was sent to ${name}, and no daemon answered within ${String(waitMs)} ms`
      }
      if ('refused' in ended) {
        log.warn({ sandboxId: name, driver: this.#o.driver.name }, 'sandbox kill by name failed')
        return `a kill by name was sent to ${name}, and the driver refused it: ${ended.refused}`
      }
      return `a kill by name was sent to ${name}`
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * The run's workspace, <mountRoot>/<runId>: made if it is not there, as a
   * directory only the operator reads, and refused unless it is one, and no
   * link. The mountRoot itself is the VM's share (scripts/colima-up.sh makes
   * it), never made here: a missing one is a VM that shares nothing. The
   * driver then confines the path again (confine.ts) before it mounts it.
   */
  #workspace(domain: SandboxDomain, mountRoot: string, runId: string): string {
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
function mayRunOn(result: SandboxResult): string | undefined {
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
 * Why the driver's whole-argv audit would refuse `command`, said in the
 * command's terms, or undefined. The audit reads every element of the docker
 * argv, the command's included (docker.ts wholeArgvRefusal), so `-v` or
 * `--device` anywhere in a command is refused as a second mount or a device,
 * an over-refusal kept until the operator decides whether those scans stop at
 * the image. Asked beside the builder's one --mount, as the fake driver asks,
 * so this refuses exactly the commands the audit refuses, and names the first
 * argument that it refuses on its own: the audit refuses a command only for
 * one of those.
 */
function commandRefusal(command: readonly string[]): string | undefined {
  const audit = wholeArgvRefusal(['--mount', ...command])
  if (audit === undefined) return undefined
  const at = command.findIndex((arg) => wholeArgvRefusal(['--mount', arg]) !== undefined)
  const arg = command[at]
  const own = arg === undefined ? undefined : wholeArgvRefusal(['--mount', arg])
  if (arg === undefined || own === undefined) return audit
  // Quoted when short, as a flag is; a long argument that mentions the
  // docker socket is named by its place.
  const named = Buffer.byteLength(arg) <= 64 ? `command[${String(at)}], ${JSON.stringify(arg)},` : `command[${String(at)}]`
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
 * before the end of a stream's start, and just after the start of its end.
 * Each cut is made before anything is redacted (the driver's at
 * CAPTURE_MAX_BYTES, and describe()'s own at STREAM_WINDOW_BYTES), so a
 * credential a cut splits (a token short of the length its pattern needs, a
 * value the kernel holds as secret with its first or last part gone, a PEM
 * block whose other marker lies past the cut) stands there unredacted. A key
 * block a cut splits is also dropped from its marker on, however long it is
 * (pemCut); this covers the rest, which is a few KiB at most.
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
 * human), and over a window of this size some 60 ms. Redaction may shrink a
 * window (a key block is [REDACTED]), and a stream is then shown less of than
 * its share: never more than its window.
 */
export const STREAM_WINDOW_BYTES = PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE + CAPTURE_EDGE_BYTES

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

/**
 * What may be shown of `read`, a window redacted, on the side its cut is on:
 * not its CAPTURE_EDGE_BYTES there, nor a private key block the cut splits.
 * redact.ts hid every block whose two markers the window holds, so a marker
 * left in `read` is one whose other lies past the cut. Of a start, nothing
 * from the first BEGIN left on: in the stream as printed, the pattern pairs
 * it with the first END past the cut and hides all between, any later BEGIN
 * among it. Of an end, nothing up to the first END left, which closes a block
 * whose BEGIN lies before the window.
 */
function pemCut(read: string, side: 'start' | 'end'): string {
  const bytes = Buffer.byteLength(read)
  if (side === 'start') {
    const edge = utf8Head(read, bytes - CAPTURE_EDGE_BYTES)
    const begin = read.search(PEM_BEGIN)
    return begin === -1 || begin >= edge.length ? edge : read.slice(0, begin)
  }
  const edge = utf8Tail(read, bytes - CAPTURE_EDGE_BYTES)
  const end = PEM_END.exec(read)
  const after = end === null ? -1 : end.index + end[0].length
  return after <= read.length - edge.length ? edge : read.slice(after)
}

/** One stream as describe() read it. */
interface Stream {
  readonly label: 'stdout' | 'stderr'
  /** What was read of the stream, redacted: all of it, or a window of it short of its cut side. */
  readonly text: string
  /**
   * Set when `text` is a window: of its start, for a stream the driver
   * capped, or of its end, for one longer than STREAM_WINDOW_BYTES; and the
   * bytes the driver returned of the stream, as printed.
   */
  readonly window?: { readonly side: 'start' | 'end'; readonly printed: number }
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
 * nothing it did not print.
 */
function streamOf(label: Stream['label'], raw: string, truncated: boolean): Stream {
  const printed = Buffer.byteLength(raw)
  if (truncated && printed >= CAPTURE_MAX_BYTES - 3) {
    const read = redactString(utf8Head(raw, STREAM_WINDOW_BYTES))
    return { label, text: pemCut(read, 'start'), window: { side: 'start', printed } }
  }
  if (printed <= STREAM_WINDOW_BYTES) return { label, text: redactString(raw) }
  const read = redactString(utf8Tail(raw, STREAM_WINDOW_BYTES))
  return { label, text: pemCut(read, 'end'), window: { side: 'end', printed } }
}

/**
 * One stream as the model and the log read it, within `keep` payload bytes,
 * and the whole it stands for: what was read of it. A stream read whole, or
 * by its end, keeps its end, where a failure is; one the driver capped keeps
 * its start. A heading's byte counts are of the redacted text, but for the
 * bytes a windowed stream printed.
 */
function streamPart(stream: Stream, keep: number): { readonly cut: string; readonly whole: string } {
  const { label, text, window } = stream
  const bytes = Buffer.byteLength(text)
  const heading = (shown: number): string => {
    if (window?.side === 'start') {
      return (
        `--- ${label} (its start, redacted: ${String(shown)} bytes, of the ${String(window.printed)} bytes its ` +
        'capture kept; the stream carried more) ---'
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
function describe(spec: SandboxSpec, result: SandboxResult, sent: string | undefined): Done {
  const wallclock = `${String(spec.limits.wallclockMs)} ms`
  const code = result.exitCode === null ? '' : ` (exit ${String(result.exitCode)})`
  let how: string
  if (result.killedBy === 'wallclock') how = `was killed at its wallclock of ${wallclock}${code}`
  else if (result.killedBy === 'requested') how = `was killed: the run was stopped${code}`
  else if (result.overran === true) {
    how = `outlived its wallclock of ${wallclock}: the kill it was sent ended nothing, and it then exited on its own${code}`
  } else if (result.exitCode === null) how = `ended with no exit status (${result.signal ?? 'the docker client did not start'})`
  else how = `exited ${String(result.exitCode)}`
  const head = [
    `${spec.name} on the ${spec.domain} domain, no network, ${how} after ${String(result.durationMs)} ms` +
      (sent === undefined ? '' : `; ${sent}`),
  ]
  if (result.truncated) {
    head.push(
      `[output cut: a stream carried more than ${String(CAPTURE_MAX_BYTES)} bytes, and the driver kept only its ` +
        'first; such a stream is shown from its start]',
    )
  }
  const stdout = streamOf('stdout', result.stdout, result.truncated)
  const stderr = streamOf('stderr', result.stderr, result.truncated)
  const room = PAYLOAD_TEXT_BUDGET - DESCRIBE_RESERVE - payloadBytes(head.join('\n'))
  const [outKeep, errKeep] = streamShares(payloadBytes(stdout.text), payloadBytes(stderr.text), room)
  const out = streamPart(stdout, outKeep)
  const err = streamPart(stderr, errKeep)
  const text = [...head, out.cut, err.cut].join('\n')
  const ok = result.killedBy === undefined && result.overran !== true && result.exitCode === 0
  if (out.cut === out.whole && err.cut === err.whole) return { ok, text }
  return { ok, text, whole: [...head, out.whole, err.whole].join('\n') }
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
