// Sandbox driver interface.
//
// One process or container per run. The spec below is the whole surface a
// driver is given: everything in it is a hard limit, a confined path, or the
// one switch `channel`, and there is deliberately no field for "extra
// arguments", "extra mounts" or "environment" — those would be the seams
// through which an agent widens its own container.
//
// `channel` opens no way out by itself. It keeps the container's stdin and
// stdout open as one byte stream between the container and the kernel
// (docker's -i), handed to the caller as RunningSandbox.channel, and what
// crosses it is for the caller to decide: the kernel's egress engine
// (src/egress), which the sandbox runner serves it with under a grant
// (egress plan W1). A driver reads none of it and writes none of it. It is
// refused on the hostile domain (channelRefusal), whose runs reach nothing at
// all, and a run without one has no -i, and the kernel's end of its stdin is
// closed at once.
//
// Invariant 9 lives in the drivers that implement this, not here: read-only
// root, all capabilities dropped, no new privileges, non-root user, pid and
// memory and cpu caps, no network (docker's --network none), mounts confined
// to the domain's mountRoot after symlink resolution, and a hard wallclock.
// Never privileged, never the docker socket, never the home directory.
//
// `probe()` reports availability rather than throwing, because a kernel with
// no container runtime must still boot degraded and say why.
//
// What a run writes is bounded too. A container is untrusted, and one that
// writes without end would otherwise grow the kernel's memory until the
// wallclock fires, or past it; so a driver keeps at most CAPTURE_MAX_BYTES of
// each stream, in memory that grows with the bytes kept and not with how the
// container cut its writes, keeps reading the rest so the container never
// blocks on a full pipe, and says that it cut.

import type { Readable, Writable } from 'node:stream'

import { ConfigError } from '../errors.js'
import { MAX_LOGGED_OUTPUT } from '../events/bound.js'

/**
 * Most bytes of each of a run's two output streams a driver keeps: 1 MiB.
 *
 * Sized from MAX_LOGGED_OUTPUT because the log is where a run's output goes:
 * it stores at most that much of the REDACTED text, plus a digest of the
 * redacted whole (events/bound.ts), and this capture is that whole. It is a
 * multiple rather than equal because bound.ts redacts first and cuts second,
 * so that a cut never halves a credential and leaves its front in the log;
 * this cut is of raw bytes, before any redaction, and a capture no longer than
 * the log's limit would make it the cut that decides the stored prefix. Sixteen
 * times keeps the stored prefix well clear of it even where redaction shrinks
 * the text (a long token becomes [REDACTED]), and still holds what a run keeps
 * to 2 MiB however much its container writes. (The docker driver holds that in
 * blocks of its own, so the memory is about the bytes kept even when the
 * output arrives a byte at a time: docker.ts, Capture.)
 */
export const CAPTURE_MAX_BYTES = 16 * MAX_LOGGED_OUTPUT

/**
 * Prefix for every container the kernel creates, so orphans are findable, and
 * so that a name without it is someone else's container, which no driver
 * starts or kills (SandboxDriver.run, kill). Here rather than in a driver's
 * module so that whatever codes against this interface, the fake driver
 * among it, has the rule without importing a driver.
 */
export const CONTAINER_PREFIX = 'aos-run-'

/**
 * Isolation domain. Each maps to its own VM; its internal network is kept and
 * probed as defence in depth, and no run is put on it.
 */
export type SandboxDomain = 'trusted' | 'hostile'

export interface SandboxLimits {
  readonly memoryMb: number
  readonly cpus: number
  readonly pids: number
  /** Hard wallclock. The driver kills the container when it elapses. */
  readonly wallclockMs: number
}

export interface SandboxSpec {
  /** Stable name for the container, used for kill and orphan sweeps. */
  readonly name: string
  readonly runId: string
  readonly agentId: string
  readonly domain: SandboxDomain
  /**
   * The image the run asks for. A driver is not bound to run it as given: the
   * docker driver runs only the pinned sandbox.imageId, by id and with
   * --pull=never, and refuses a spec naming anything else, a tag among them,
   * and every spec while none is pinned; the fake driver refuses the same.
   * So a caller copies config.sandbox.imageId here, never config.sandbox.image
   * or a manifest's sandbox.image, which are tags.
   */
  readonly image: string
  readonly command: readonly string[]
  /**
   * Host path to mount as the run's workspace. The driver resolves symlinks
   * and refuses anything outside the domain's mountRoot; it is not trusted
   * as given.
   */
  readonly workspace: string
  readonly limits: SandboxLimits
  /**
   * Keep the container's stdin and stdout open to the kernel as one byte
   * stream, RunningSandbox.channel: docker's -i. Absent or false, the run
   * has no -i, the container's stdin reads nothing, and its stdout is
   * captured into the result. Admitted on the trusted domain only
   * (channelRefusal): a hostile run reaches nothing at all, so it has no
   * channel either.
   */
  readonly channel?: boolean
}

/**
 * Why `spec` may not run with the channel it asks for, or undefined when it
 * may: it asks for none (absent or false), or asks on the trusted domain. The
 * hostile domain runs work nothing vouches for, and such a run reaches nothing
 * at all: no network, and no channel to the kernel either (the egress plan
 * the operator accepted on 2026-11-09). A value that is not a boolean is
 * refused rather than read as either. The docker driver throws this before it
 * builds anything (buildRunArgs), and the tests' fake driver throws it in the
 * same words, so that code tested against the fake meets the refusal docker's
 * driver gives. Both hand it the spec as readSpecOnce returned it, and decide
 * whether the run has a channel from that same reading, never from the spec
 * they were handed.
 */
export function channelRefusal(spec: Pick<SandboxSpec, 'name' | 'domain' | 'channel'>): string | undefined {
  const asked: unknown = spec.channel
  if (asked === undefined || asked === false) return undefined
  if (asked !== true) {
    return `container ${spec.name}: channel must be true or false, and is a value of type ${typeof asked}`
  }
  if (spec.domain === 'trusted') return undefined
  return (
    `container ${spec.name} asks for a channel on the ${String(spec.domain)} domain, whose runs reach nothing at ` +
    'all: no network, and no channel to the kernel either. A channel is for the trusted domain only'
  )
}

/**
 * `spec` as plain data, each of its fields read exactly once, frozen. A
 * driver decides several things from one field, and would otherwise read it
 * each time: the domain picks the VM, its mountRoot and environment, and
 * whether a channel is admitted (channelRefusal); the name is checked, held
 * and killed by; the channel decides both the -i in the argv and whether the
 * result hands over the CLI's pipes. The kernel builds a spec as plain data,
 * but a field that is a getter, or a spec that is a Proxy, could answer each
 * read differently: a channel that reads false when it is judged on the
 * hostile domain and true when the pipes are handed over, or a domain that
 * reads trusted when the channel is judged and hostile when the VM is
 * chosen, would open a channel to the hostile domain. So a driver's run()
 * takes its spec through this at its entry and decides only from what it
 * returns, and so does buildRunArgs for a spec handed to it directly.
 *
 * One reading holds only for a value that is what its type says. A domain
 * that is an object is converted at each use as a property key, and one
 * whose toString answers trusted and then hostile would have a run built
 * against the trusted domain's mountRoot and workspace and spawned and killed
 * on the hostile VM, however few times the field was read. So each field is
 * judged here, on the copy, and a spec is refused with a ConfigError, before
 * anything is decided from it, when its name, runId, agentId, image or
 * workspace is no string, its domain is neither 'trusted' nor 'hostile', its
 * command is no array of strings, or its limits are not four numbers. Its
 * channel is copied as read and judged by channelRefusal, in that one's own
 * words.
 *
 * Every key of SandboxSpec is named, by a type that requires each one, and
 * anything not taken out of that reading by name reaches the copy whole: a
 * field added to the interface fails to compile here until it is read and
 * judged, rather than being dropped from every driver's reading, which for a
 * field that restricts a run would fail open.
 */
export function readSpecOnce(spec: SandboxSpec): SandboxSpec {
  const read: { readonly [K in keyof Required<SandboxSpec>]: SandboxSpec[K] | undefined } = {
    name: spec.name,
    runId: spec.runId,
    agentId: spec.agentId,
    domain: spec.domain,
    image: spec.image,
    command: spec.command,
    workspace: spec.workspace,
    limits: spec.limits,
    channel: spec.channel,
  }
  const { name, runId, agentId, domain, image, command, workspace, limits, channel, ...rest } = read
  if (typeof name !== 'string') throw fieldRefusal('a container spec', 'name', 'a string', typeOf(name))
  const who = `container ${name}`
  if (typeof runId !== 'string') throw fieldRefusal(who, 'runId', 'a string', typeOf(runId))
  if (typeof agentId !== 'string') throw fieldRefusal(who, 'agentId', 'a string', typeOf(agentId))
  if (domain !== 'trusted' && domain !== 'hostile') {
    const other: unknown = domain
    const held = typeof other === 'string' ? 'another string' : typeOf(other)
    throw fieldRefusal(who, 'domain', "'trusted' or 'hostile'", held)
  }
  if (typeof image !== 'string') throw fieldRefusal(who, 'image', 'a string', typeOf(image))
  const argv = commandOnce(who, command)
  if (typeof workspace !== 'string') throw fieldRefusal(who, 'workspace', 'a string', typeOf(workspace))
  if (typeof limits !== 'object' || limits === null) throw fieldRefusal(who, 'limits', 'an object', typeOf(limits))
  // The limits the same way, each of SandboxLimits' keys named.
  const caps: { readonly [K in keyof Required<SandboxLimits>]: SandboxLimits[K] | undefined } = {
    memoryMb: limits.memoryMb,
    cpus: limits.cpus,
    pids: limits.pids,
    wallclockMs: limits.wallclockMs,
  }
  const { memoryMb, cpus, pids, wallclockMs, ...otherCaps } = caps
  const judged = Object.freeze({
    ...otherCaps,
    memoryMb: limitOf(who, 'memoryMb', memoryMb),
    cpus: limitOf(who, 'cpus', cpus),
    pids: limitOf(who, 'pids', pids),
    wallclockMs: limitOf(who, 'wallclockMs', wallclockMs),
  })
  return Object.freeze({
    ...rest,
    name,
    runId,
    agentId,
    domain,
    image,
    command: argv,
    workspace,
    limits: judged,
    ...(channel === undefined ? {} : { channel }),
  })
}

/** A spec's command, copied element by element from one reading of it, frozen. */
function commandOnce(who: string, command: unknown): readonly string[] {
  // An array only: spread over a string, a command would be its characters.
  if (!Array.isArray(command)) throw fieldRefusal(who, 'command', 'an array of strings', typeOf(command))
  const copy: string[] = []
  for (const arg of command) {
    const each: unknown = arg
    if (typeof each !== 'string') throw fieldRefusal(who, `command[${String(copy.length)}]`, 'a string', typeOf(each))
    copy.push(each)
  }
  return Object.freeze(copy)
}

/** One of a spec's limits, which must be a number: a timer converts whatever it is given, once per timer. */
function limitOf(who: string, field: keyof SandboxLimits, value: unknown): number {
  if (typeof value !== 'number') throw fieldRefusal(who, `limits.${field}`, 'a number', typeOf(value))
  return value
}

/**
 * Why a spec field is refused, naming the field and what it held (`held`, its
 * type from typeOf), never its value: what does not have the type it should
 * may not even turn into a string the same way twice.
 */
function fieldRefusal(who: string, field: string, wanted: string, held: string): ConfigError {
  return new ConfigError(`${who}: ${field} must be ${wanted}, and is ${held}`)
}

/** What a value is, by its type alone. */
function typeOf(value: unknown): string {
  return value === null ? 'null' : `a value of type ${typeof value}`
}

export type ExitSignal = 'SIGKILL' | 'SIGTERM' | null

export interface SandboxResult {
  readonly name: string
  /**
   * Null when the process was signalled rather than exiting, or never
   * started. A run the kernel's kill ended reports 137, the docker CLI's exit
   * for a killed container, with signal SIGKILL and killedBy; a 137 with no
   * killedBy is the run's own (the OOM killer's, or the worker's exit 137).
   * Tell a kill by killedBy, never by this code.
   */
  readonly exitCode: number | null
  readonly signal: ExitSignal
  /** Set when the kernel stopped it, rather than it finishing on its own. */
  readonly killedBy?: 'wallclock' | 'requested'
  /**
   * Set when the run's hard wallclock elapsed before it ended, whether or not
   * the kill the driver then sent ended it (killedBy 'wallclock' says it did).
   * A run that outlived its wallclock and then exited on its own, its kill
   * having reached no daemon, reports this and no killedBy: it is the one
   * trace that invariant 9's hard wallclock did not hold, and a caller logs it.
   *
   * The run ends, for the wallclock, when the docker CLI exits, which it does
   * once its container has: on a channel run the result settles only later,
   * once the caller has read the channel's input to its end (RunningSandbox.
   * result), and time the caller holds it after the exit is no time the
   * container ran, so it never sets this.
   */
  readonly overran?: true
  /**
   * The first CAPTURE_MAX_BYTES bytes of each stream at most, decoded as UTF-8
   * and cut on a character boundary. A byte that is not UTF-8 decodes to
   * U+FFFD, so the text is at most CAPTURE_MAX_BYTES UTF-16 units long.
   *
   * On a channel run stdout is empty: the container's stdout is the
   * channel's input (RunningSandbox.channel), which a driver never reads, so
   * what the container wrote there is the caller's to keep, and `truncated`
   * then speaks for stderr alone.
   */
  readonly stdout: string
  readonly stderr: string
  /**
   * True when either stream carried more than CAPTURE_MAX_BYTES, and so was
   * cut. One flag for both, so it does not say which stream was cut, and a
   * stream's length does not say it either: the cut falls on a character
   * boundary, up to three bytes short of the cap. A reader that must name the
   * stream (sandbox.exec reporting a cut, plan S3) needs per-stream flags
   * added here first, beside this one.
   */
  readonly truncated: boolean
  /**
   * From the start of the run to the docker CLI's exit (or, for a spawn that
   * started nothing, its failure), as the wallclock counts it: on a channel
   * run, not the time the caller then held the channel's input open, which
   * the result waits for (see `overran`).
   */
  readonly durationMs: number
}

/**
 * A channel run's byte stream, from the kernel's side: `input` is the
 * container's stdout, which the kernel reads, and `output` its stdin, which
 * the kernel writes. Both are the runtime's own pipes, raw bytes both ways,
 * and they end when the run does, whenever the container decides: a write
 * after that is refused (EPIPE, or a destroyed stream once Node has closed a
 * child's stdin on its exit). A driver listens for each stream's 'error'
 * itself, from the moment it starts the run, so that no caller's listener
 * coming late lets one throw in the kernel; what it hears before the run
 * ends lands in the result's stderr.
 *
 * A caller ends a channel run with kill(name), never by destroying the input
 * or leaving it unread. Destroying it closes the read end of the docker CLI's
 * stdout, and the CLI's next copy of container output then fails with EPIPE
 * (docker run catches every signal to relay it, so a broken pipe is a write
 * error to it, not a death by SIGPIPE). The CLI is then expected to exit
 * while its --rm container runs on unattached; its exit clears the run's
 * wallclock, so the container runs past its hard wallclock with nothing to
 * kill it (docker.ts, the wallclock note; README, "Still needs validation").
 * An input left unread blocks the container on a full pipe until its
 * wallclock (RunningSandbox.result). The output may be ended, which the
 * container reads as the end of its stdin, but that ends the run only if
 * the container reads it.
 */
export interface SandboxChannel {
  readonly input: Readable
  readonly output: Writable
}

export interface RunningSandbox {
  readonly name: string
  /**
   * Resolves when the container exits, is killed, or overruns.
   *
   * On a channel run, only once the channel's input has ended as well: the
   * docker CLI is done only once its pipes are. When the CLI exits, Node
   * resumes the input (flushStdio), so an input read through 'data'
   * listeners, or not read at all, flows to its end: what is still in it
   * goes to the listeners it has, and is lost to a reader not yet listening.
   * An input read through a 'readable' listener stays paused (resume()
   * leaves such a stream so), and so does one its reader pauses again after
   * that with bytes unread: either holds this open until it is read to its
   * end. So a caller that takes the channel listens on its input at once,
   * before it awaits this, and while the container runs it keeps reading, or
   * the container blocks on a full pipe until its wallclock. The wallclock
   * and durationMs stop at the CLI's exit, so the time the caller holds the
   * input after that counts in neither.
   */
  readonly result: Promise<SandboxResult>
  /**
   * Present on a run whose spec asked for a channel, and only there. Absent
   * there too when the runtime gave the run no pipes, which Node does only
   * for a spawn that failed for want of file descriptors and so started
   * nothing; its result then says that it failed.
   *
   * Its caller ends the run with kill(name), whatever made it decide to (a
   * protocol violation on the channel among them), and never by destroying
   * or abandoning the input: that is expected to leave the container running
   * past its wallclock (SandboxChannel).
   */
  readonly channel?: SandboxChannel
}

export type ProbeResult =
  | { readonly ok: true; readonly version: string }
  | { readonly ok: false; readonly why: string }

export interface SandboxDriver {
  readonly name: string
  /** Availability, never a throw: a missing runtime is a degraded boot. */
  probe(): Promise<ProbeResult>
  /**
   * Throws a ConfigError, before starting anything, for a `spec.name` that
   * does not start with CONTAINER_PREFIX: such a name is no container of the
   * kernel's, and the orphan sweep would never find it. Throws one, before
   * starting anything, for a spec whose channel channelRefusal refuses: one
   * on the hostile domain, or one that is no boolean; and for a spec whose
   * fields are not of their types (readSpecOnce). And throws, before
   * starting anything, while a run under `spec.name` from an earlier call has
   * not finished: the name is how kill() and the wallclock reach a container,
   * so it must name exactly one. The name stays held until the result has
   * settled, and is free once `await result` has returned. It reads `spec`
   * once (readSpecOnce), and every one of these decisions, and the run, is
   * made from that one reading.
   */
  run(spec: SandboxSpec): RunningSandbox
  /**
   * Why run() would refuse a spec for its command alone, in the words run()
   * throws, or undefined: what the driver's own audit reads of a command
   * (DockerDriver: its whole-argv scans and its home check, docker.ts
   * commandAuditRefusal). Asked before a human is asked to approve a command
   * (sandbox.exec's argsRefusal), so a command run() would refuse whoever
   * approved it is refused first, without one. Starts nothing, reads no spec
   * and never throws. Undefined says nothing of the rest of a spec, which
   * run() still judges.
   */
  commandRefusal(command: readonly string[]): string | undefined
  /**
   * Why run() refuses every spec, whatever it holds, or undefined: a fact
   * of the driver's own code, never of a runtime's state now (probe() reads
   * that, at boot). AppleContainerDriver, a stub, runs
   * nothing; DockerDriver refuses no spec for itself. Asked before any
   * sandbox tool is offered and before a human is asked to approve a call
   * (sandbox.exec's configRefusal), so no run is shown a tool no call of
   * which can run, and no human approves one. Starts nothing and never
   * throws.
   */
  everyRunRefusal(): string | undefined
  /**
   * Idempotent: killing an unknown or already-dead container is not an error.
   * A name without CONTAINER_PREFIX is someone else's container: a kill of it
   * is sent nowhere and ends nothing, and is not an error either.
   *
   * Resolves once the kill has been sent, not once the run has ended: the run
   * under that name may still be running, and its name still held, when this
   * returns; `await result` is what says it ended. A run it ends reports
   * `killedBy: 'requested'` and SIGKILL, unless its wallclock fired before
   * the run ended. A kill can also end nothing (it reached no daemon, or came
   * after the run had exited on its own), and the run then reports its own
   * exit.
   */
  kill(name: string): Promise<void>
  /**
   * Give up on the run under `name`, for a caller that waited past its
   * wallclock for a result the driver never gave (a daemon that accepts and
   * never answers, a paused VM): end the process the driver spawned for it,
   * if one is still running (the docker CLI, by SIGKILL: the one process a
   * driver may signal, and its own child), and kill the container by name,
   * on the run's own domain when the driver still holds the name, else on
   * every domain, as kill() does. A name without CONTAINER_PREFIX is sent
   * nowhere.
   *
   * Never rejects. Resolves once the kill by name has been answered, which a
   * daemon that never answers never does, so a caller bounds the wait. The
   * run's result may settle after this (the CLI ended by a signal reports no
   * exit status and no killedBy) or never; a caller that gave up on it reads
   * nothing more from it, and records the container's end itself.
   */
  abandon(name: string): Promise<void>
}
