// Fake sandbox driver.
//
// Records every spec it is handed and answers from a script. Two deliberate
// behaviours:
//
//   probe() reports UNAVAILABLE by default. The kernel must boot degraded
//   with no container runtime, so the default has to be the hard case; a
//   test wanting availability opts in.
//
//   An unscripted run THROWS. A driver double that invents a clean exit
//   would let runtime code call the sandbox more times than intended — or
//   for the wrong run — and still pass.
//
//   No image id is pinned unless the test pins one (`imageId`), as
//   kernel.yaml ships none, and then every run is REFUSED, as the real driver
//   refuses it.
//
// Where the real driver refuses or reports something, so does this: a spec
// whose command the audit's whole-argv scans refuse (a forbidden flag, the
// docker socket, a --mount or a -v anywhere in it, so `go test -v` too), or,
// given the home a test hands it (`home`), its home check, is refused in its
// words (commandAuditRefusal, src/sandbox/docker.ts), and commandRefusal()
// says so of the command, as the real driver's does; a spec
// whose image is not the pinned id, exactly, is refused, a tag among them, and
// every spec while no valid id is pinned, with the real driver's own words
// (imageRefusal, src/sandbox/limits.ts); a probe scripted ok reports the
// sandbox degraded instead while no valid id is pinned (none, or a value that
// is no id), as the real driver never reports ok without one; a name without
// the kernel's container prefix is refused, and a kill of one ends nothing; a
// second run under a name whose result has not settled is refused, whether
// the run hangs or not. A kill or an overrun ends a hung run on a later
// macrotask, as the real one's run ends when the docker CLI closes, after
// `docker kill` has returned: so the name is still held, and the result not
// yet settled, when `await kill()` returns, and the name is free once
// `await result` has returned. A kill reports `killedBy: 'requested'` with
// SIGKILL, unless the wallclock fired before the run ended, and an overrun
// `killedBy: 'wallclock'` with SIGKILL and `overran`; either reports the
// docker CLI's exit code for a killed container, 137, and what the script
// says the run wrote before it ended (stdout, stderr, truncated), as the real
// driver returns what it captured up to the kill. A kill of a run that has
// ended changes nothing. And a script may say that a kill ends nothing
// (`ignoresKill`), as the real driver's kill that reaches no daemon or lands
// after the container exited: the run then exits on its own, with its
// scripted exit and no killedBy, and says it overran if the wallclock had
// fired. test/sandbox-docker.test.ts drives both through the same steps for
// these. An abandon (SandboxDriver.abandon) ends a hung run as the real
// driver's SIGKILL of its docker CLI does, on a later macrotask: no exit
// status, SIGKILL and no killedBy, whatever its script says of kills; it
// changes nothing for a run that has ended or whose end is already queued,
// and every name it is passed is recorded (abandons). A hung run is never
// ended by the fake on its own, wallclock or not: one that nothing kills,
// overruns, abandons or exits (simulateExit, a test's word that its
// container exited on its own) is a driver that never answers.
//
// What still differs: when a run whose kill ended nothing exits, which here is
// just after that kill, and on the real driver whenever its container does.
// And when a run that does not hang exits: inside run(), so a kill sent before
// its result settles, in the same tick, reaches a name still held and ends
// nothing, as the real driver's kill sent after the CLI's exit; its scripted
// 137 is then the run's own, with no killedBy. On the real driver a kill sent
// while the name is held but before the CLI's exit is credited with a 137
// that follows it (killedBy requested, SIGKILL): a run a kill ends is
// scripted `hangs` here.
// And a command that names the operator's home, which the real driver's audit
// refuses, and the fake, unless a test hands it one, knows no home to refuse.
// And the reason a probe gives with no valid id pinned and a probe scripted
// not ok (or none scripted): the scripted (or default) reason here, where the
// real driver names sandbox.imageId before asking any daemon anything.
// Degraded on both. A probe scripted ok or not stands for everything the real
// driver asks the daemons, the pinned image's presence on each VM among it.
//
// And a script may not describe a result the real driver cannot return.
// assertDriverShaped refuses a stream longer than its capture keeps, a cut
// with no stream near the cap, a kill that ends nothing followed by an exit
// of 137, which the real driver credits to that kill, and a signal beside an
// exit code, which it reports only for a run its kill ended: 137, SIGKILL and
// killedBy, the shape the fake gives a hung run's kill itself. And run()
// refuses any stdout on a channel run, whose stdout the real driver never
// reads. A script's exitCode null is the run's exit as it stands, a docker
// CLI killed by a signal or a spawn that started nothing, never a clean 0.
// Runtime code is tested against this fake, and could otherwise come to rely
// on a result shape it will never meet.
//
// A spec is read once, at run()'s entry, and every decision is made from
// that reading (readSpecOnce), as the real driver reads it: a field that
// answers each read differently cannot have the fake judge one value and run
// another. A spec whose fields are not of their types (a domain that is an
// object, a command that is a string) is refused by that reading, in the
// real driver's words, before anything starts and with no scripted exit
// spent on it.
//
// A channel's output is a pipe into its container, as Node's child.stdin is:
// ending it ends the container's stdin while the run goes on, and a write is
// acknowledged only once the container's stdin has taken it, so a container
// that reads nothing fills it and write() returns false.
//
// A channel (SandboxSpec.channel) is refused where the real driver refuses
// it, on the hostile domain or as a value that is no boolean, in the same
// words (channelRefusal), before anything starts. A channel run's result has
// its channel, whose container ends a test plays the container with
// (FakeSandbox.channels): what it writes to the container's stdout is the
// channel's input, and what the kernel writes to the channel's output it
// reads as the container's stdin. When the container exits the fake does what
// Node does to a child that exits: it destroys the channel's output (a write
// after that fails, as on the real driver, and what was written before stays
// readable on the container's stdin, which then ends), ends the container's
// stdout and resumes the input (flushStdio); and the result settles only once
// the input has ended or been destroyed, as the real driver's settles only
// once the docker CLI's pipes have closed. An 'error' on either stream of the
// channel is heard, as the real driver hears it, and lands in the result's
// stderr after the scripted stderr, in the real driver's words. A run that
// does not hang exits inside run(): its container stdout is ended, and its
// channel's output destroyed, before run() returns, so such a script stands
// for a container that read nothing and wrote nothing to its channel, and a
// write to its container stdout throws (FakeChannel.stdout). A script that
// hangs is a container that runs until its kill or overrun.
//
// Nothing here executes anything. It never spawns a process, never touches
// docker, and never reads the filesystem.

import './guard.js'

import { PassThrough, type Readable, Writable } from 'node:stream'

import { ConfigError } from '../../src/errors.js'
import {
  CAPTURE_MAX_BYTES,
  CONTAINER_PREFIX,
  channelRefusal,
  readSpecOnce,
  type ProbeResult,
  type RunningSandbox,
  type SandboxChannel,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from '../../src/sandbox/driver.js'
import { commandAuditRefusal } from '../../src/sandbox/docker.js'
import { imageIdProblem, imageRefusal } from '../../src/sandbox/limits.js'

export interface ScriptedExit {
  /** Unset, 0. Null, as the real driver reports a docker CLI killed by a signal, or a spawn that started nothing. */
  readonly exitCode?: number | null
  /** Only beside exitCode null: the signal a docker CLI was killed by. */
  readonly signal?: SandboxResult['signal']
  readonly stdout?: string
  readonly stderr?: string
  /**
   * As the real driver reports a stream cut at CAPTURE_MAX_BYTES, so only
   * with a stream that reaches within three bytes of the cap.
   */
  readonly truncated?: boolean
  readonly durationMs?: number
  /** Do not resolve on its own: the run ends only by kill or overrun. */
  readonly hangs?: boolean
  /**
   * With `hangs` only: every kill of this run ends nothing, a requested one
   * and the wallclock's alike, as the real driver's kill that reaches no
   * daemon. The run then exits on its own, with this script's exit and no
   * killedBy, just after the first kill or overrun; after an overrun it says
   * it overran, which is then the only trace that the wallclock did not hold.
   * Never with exitCode 137, which the real driver credits to the kill.
   */
  readonly ignoresKill?: boolean
}

export interface FakeSandboxOptions {
  readonly probe?: ProbeResult
  readonly script?: readonly ScriptedExit[]
  /**
   * The pinned image id, as the real driver is handed kernel.yaml's
   * sandbox.imageId: the only image a spec may name. Unset, as kernel.yaml
   * ships it, every run is refused and no probe reports ok.
   */
  readonly imageId?: string | undefined
  /**
   * The home the audit's home check refuses, as the real driver is handed
   * one (DockerDriverOptions.home) or reads the OS's. Unset, none: no command
   * is refused for naming a home.
   */
  readonly home?: string
}

/** A channel run's container ends, for a test to play the container with. */
export interface FakeChannel {
  /** The run's name. */
  readonly name: string
  /**
   * The container's stdout: what a test writes here is the channel's input.
   * Ended by the fake when the container exits: for a run that hangs, when
   * its kill or overrun ends it; for one that does not, inside run(), so it
   * is already ended when run() returns, and such a script stands for a
   * container that wrote nothing. A write to it after the container exited
   * throws, naming the run, rather than being Node's write after end: script
   * `hangs` for a container that writes to its channel.
   */
  readonly stdout: Writable
  /**
   * The container's stdin: what the kernel wrote to the channel's output.
   * Ended when the container exits, as Node destroys a child's stdin then,
   * and what was written before stays readable.
   */
  readonly stdin: Readable
}

export interface FakeSandbox extends SandboxDriver {
  /** Every spec passed to run(), in order. */
  readonly specs: SandboxSpec[]
  /** Every channel run's container ends, in the order the runs started. */
  readonly channels: FakeChannel[]
  /** Names passed to kill(), including repeats. */
  readonly kills: string[]
  /** Names passed to abandon(), including repeats. */
  readonly abandons: string[]
  /** End a hanging run as a wallclock overrun would, on a later macrotask. */
  simulateOverrun(name: string): void
  /**
   * End a hanging run as its container exiting on its own does, on a later
   * macrotask: its scripted exit, no killedBy, its channel's pipes closed as
   * Node closes a child's (the result settles once the input is read to its
   * end). What a channel run's container does once its command is done, its
   * mux having sent the exit frame, which a test writes before this. A run
   * that has ended, or whose end is queued, is left as it is.
   */
  simulateExit(name: string): void
}

const UNAVAILABLE: ProbeResult = {
  ok: false,
  why: 'fake driver: no container runtime configured for this test',
}

/**
 * setImmediate as it was when this module loaded, before any test could mock
 * it: a test that mocks timers to drive the real driver's wallclock must not
 * also stop every hung run on the fake from ending.
 */
const realSetImmediate = setImmediate

/**
 * Run `fn` on a later macrotask, after every continuation the current one has
 * queued: what makes a kill of a hung run end it after `await kill()` returns.
 */
function later(fn: () => void): void {
  realSetImmediate(fn)
}

/**
 * The fewest stream bytes the real driver could have decoded to `text`: each
 * character's own UTF-8 bytes, but one byte for a U+FFFD, which a byte that is
 * not UTF-8 decodes to. The most is the text's own UTF-8 length, since a
 * U+FFFD stands for at most three.
 */
function fewestBytes(text: string): number {
  return Buffer.byteLength(text) - 2 * (text.match(/�/g)?.length ?? 0)
}

/**
 * Refuse a scripted exit the real driver cannot return (DockerDriver.run,
 * docker.ts Capture). It keeps at most CAPTURE_MAX_BYTES of each stream; and it
 * reports a cut only for a stream that carried more, which it cuts at most
 * three bytes short of the cap, on a character boundary. It credits an exit of
 * 137 to the kill sent before it (finish() in run()), so a kill that ends
 * nothing and then a 137 is a result it never gives. It reports a signal
 * beside an exit code only for a run its kill ended (137, SIGKILL and
 * killedBy), a shape the fake makes itself from a hung run's kill, so a
 * script's signal comes with a null exit code: a docker CLI killed by a
 * signal ({null, SIGKILL or SIGTERM}). And refuse one that says nothing:
 * `ignoresKill` on a run that does not hang, which has ended before any kill
 * could reach it.
 */
function assertDriverShaped(scripted: ScriptedExit, index: number): void {
  const streams = [
    ['stdout', scripted.stdout ?? ''],
    ['stderr', scripted.stderr ?? ''],
  ] as const
  for (const [label, text] of streams) {
    if (fewestBytes(text) > CAPTURE_MAX_BYTES) {
      throw new Error(
        `scripted exit ${String(index)}: its ${label} is ${String(fewestBytes(text))} bytes or more, and the real driver ` +
          `keeps at most CAPTURE_MAX_BYTES (${String(CAPTURE_MAX_BYTES)}) and reports truncated. Script the first ` +
          'CAPTURE_MAX_BYTES with truncated: true.',
      )
    }
  }
  if (scripted.truncated === true && streams.every(([, text]) => Buffer.byteLength(text) < CAPTURE_MAX_BYTES - 3)) {
    throw new Error(
      `scripted exit ${String(index)}: truncated with no stream within three bytes of CAPTURE_MAX_BYTES ` +
        `(${String(CAPTURE_MAX_BYTES)}), which the real driver never reports. Script the stream that was cut at its cap.`,
    )
  }
  if (scripted.ignoresKill === true && scripted.exitCode === 137) {
    throw new Error(
      `scripted exit ${String(index)}: ignoresKill with exitCode 137, which the real driver reports as ended by the ` +
        "kill sent before it (killedBy, SIGKILL): the docker CLI exits 137 for a container killed by any route, the " +
        "kernel's kill, the OOM killer or the worker's own exit 137 alike, and the driver cannot tell them apart. " +
        'Drop ignoresKill to script a kill that ends the run, or script another exit.',
    )
  }
  if (scripted.ignoresKill === true && scripted.hangs !== true) {
    throw new Error(
      `scripted exit ${String(index)}: ignoresKill on a run that does not hang, which has ended before any kill ` +
        'reaches it, so no kill could end it anyway. Add hangs: true.',
    )
  }
  // The exit and signal ownExit reports, as it reads them.
  const exitCode = scripted.exitCode === undefined ? 0 : scripted.exitCode
  const signal = scripted.signal ?? null
  if (signal !== null && exitCode !== null) {
    throw new Error(
      `scripted exit ${String(index)}: signal ${signal} beside exitCode ${String(exitCode)}, a pair the real driver ` +
        'returns only for a run its kill ended (137, SIGKILL and killedBy), which the fake reports itself for a hung ' +
        "run's kill or overrun. A docker CLI killed by a signal exits with no code: script exitCode: null beside the " +
        'signal, or drop the signal for an exit of its own.',
    )
  }
}

/**
 * The exit a run reports when it ends on its own, as its script says; and,
 * with the kill's exit code, signal and credit in place of the script's, the
 * one a killed run reports: what the script says it wrote before it ended,
 * and how long it ran.
 */
function ownExit(spec: SandboxSpec, scripted: ScriptedExit, overran: boolean): SandboxResult {
  return {
    name: spec.name,
    // Unscripted, 0; scripted null, null: the exit of a docker CLI that died
    // by a signal, or of a spawn that started nothing, which `?? 0` would
    // turn into a clean exit.
    exitCode: scripted.exitCode === undefined ? 0 : scripted.exitCode,
    signal: scripted.signal ?? null,
    ...(overran ? { overran: true as const } : {}),
    stdout: scripted.stdout ?? '',
    stderr: scripted.stderr ?? '',
    truncated: scripted.truncated ?? false,
    durationMs: overran ? Math.max(scripted.durationMs ?? 0, spec.limits.wallclockMs) : (scripted.durationMs ?? 1),
  }
}

/** A run that hangs, and what has been sent to end it. */
interface Hung {
  readonly spec: SandboxSpec
  readonly scripted: ScriptedExit
  readonly resolve: (result: SandboxResult) => void
  /** Who sent the kill that ends it: the real driver's killSentBy. */
  killedBy?: 'requested' | 'wallclock'
  overran: boolean
  /** Its end is queued (later): a second kill queues nothing. */
  ending: boolean
  /** It was given up (abandon): its docker CLI ended by SIGKILL, whatever its container did. */
  abandoned?: true
}

/**
 * Settle a channel run's result as the real driver's settles: once the
 * container's stdout has ended and the input has been read to that end, or
 * destroyed. The input is resumed first, as Node's flushStdio resumes a
 * child's stdout when it exits, so what is still in it flows to whatever
 * listens, and is lost to a reader not yet listening; one read through a
 * 'readable' listener stays paused, as resume() leaves it, and holds the
 * result until it is read to its end, as on the real driver.
 */
function settleOnInputEnd(input: PassThrough, settle: () => void): void {
  if (!input.destroyed && !input.writableEnded) input.end()
  input.resume()
  if (input.readableEnded || input.destroyed) {
    settle()
    return
  }
  input.once('end', settle)
  input.once('close', settle)
}

/**
 * A channel run's pipes on the fake, from both ends: the channel its caller
 * holds, the container's ends a test plays the container with, and what the
 * real driver would have heard on the channel.
 */
interface FakePipes {
  readonly channel: SandboxChannel
  readonly container: FakeChannel
  /**
   * The container exits: what Node does to a child's pipes when it exits
   * (its stdin destroyed, then its stdout resumed), and `settle` once the
   * input has ended (settleOnInputEnd).
   */
  exit(settle: () => void): void
  /** Every 'error' heard on the channel so far, in the real driver's words. */
  heard(): string
}

function fakePipes(name: string): FakePipes {
  /** The container's stdout, which the kernel reads as the channel's input. */
  const input = new PassThrough()
  /** The container's stdin, from which it reads what the kernel wrote. */
  const stdin = new PassThrough()
  /**
   * The kernel's end of the container's stdin, as Node's child.stdin is: each
   * write forwarded, and acknowledged once the container's stdin takes it, so
   * that a container that reads nothing fills it as it fills a pipe.
   * Destroyed when the container exits, as Node destroys a child's stdin, so
   * that a write after that fails as it does on the real driver: its
   * callback has the error, and the stream emits none.
   */
  const output = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      stdin.write(chunk, callback)
    },
    final(callback) {
      stdin.end()
      callback()
    },
    destroy(error, callback) {
      if (!stdin.destroyed && !stdin.writableEnded) stdin.end()
      callback(error)
    },
  })
  let exited = false
  // The container's side of its stdout. A test's write to it once it has
  // ended, by the container's exit or by the test's own end(), is a mistake in
  // the test, never something a container does, so it throws where it is
  // made, rather than becoming Node's write after end: an 'error' on the
  // input, which the channel's listener below would hear as the kernel's, and
  // which would destroy the input under the kernel's reader. Only the
  // container's side writes to it: the kernel reads the input.
  const late = (): never => {
    throw new Error(
      `fake sandbox: a write to the container stdout of ${name} after ` +
        `${exited ? 'its container exited' : 'it was ended'}. A run scripted without hangs exits inside run(), so ` +
        'its container writes nothing; script hangs: true, and end the run by kill or overrun, for a container ' +
        'that writes to its channel',
    )
  }
  const write = input.write.bind(input) as (...args: unknown[]) => boolean
  input.write = ((...args: unknown[]): boolean => {
    if (exited || input.writableEnded) late()
    return write(...args)
  }) as PassThrough['write']
  const end = input.end.bind(input) as (...args: unknown[]) => PassThrough
  input.end = ((...args: unknown[]): PassThrough => {
    const [chunk] = args
    if (chunk !== undefined && chunk !== null && typeof chunk !== 'function' && (exited || input.writableEnded)) late()
    return end(...args)
  }) as PassThrough['end']
  // As the real driver hears each stream's 'error' from the moment it starts
  // the run (docker.ts, channelOf), so that none throws in the kernel, and
  // adds it to the run's stderr.
  const heard: string[] = []
  input.on('error', (error) => {
    heard.push(`channel input: ${error.message}\n`)
  })
  output.on('error', (error) => {
    heard.push(`channel output: ${error.message}\n`)
  })
  return {
    channel: { input, output },
    container: { name, stdout: input, stdin },
    exit(settle) {
      exited = true
      output.destroy()
      settleOnInputEnd(input, settle)
    },
    heard: () => heard.join(''),
  }
}

export function fakeSandbox(options: FakeSandboxOptions = {}): FakeSandbox {
  const specs: SandboxSpec[] = []
  const channels: FakeChannel[] = []
  const kills: string[] = []
  const script = options.script ?? []
  script.forEach(assertDriverShaped)
  /** Every name whose result has not settled: what run() refuses to start again. */
  const running = new Set<string>()
  /** Every hung run that has not ended, by name. */
  const pending = new Map<string, Hung>()
  const started = new Map<string, SandboxSpec>()
  let index = 0

  /**
   * End a hung run on a later macrotask, and judge then who ended it, as the
   * real driver judges in finish() when the CLI closes: a wallclock that
   * fires after a requested kill was sent, and before the run ended, is the
   * one that ended it.
   */
  const end = (hung: Hung): void => {
    if (hung.ending) return
    hung.ending = true
    later(() => {
      pending.delete(hung.spec.name)
      const { spec, scripted, killedBy, overran } = hung
      const own = ownExit(spec, scripted, overran)
      // As the real driver reports a run it gave up: its CLI killed by a
      // signal, so no exit status and no killedBy, whatever kill came before.
      if (hung.abandoned === true) {
        hung.resolve({ ...own, exitCode: null, signal: 'SIGKILL' })
        return
      }
      // As the real driver reports a run its kill ended: the CLI's 137, with
      // SIGKILL, and what it captured before the kill.
      hung.resolve(killedBy === undefined ? own : { ...own, exitCode: 137, signal: 'SIGKILL', killedBy })
    })
  }

  const abandons: string[] = []

  return {
    name: 'fake',
    specs,
    channels,
    kills,
    abandons,

    async probe(): Promise<ProbeResult> {
      const probe = options.probe ?? UNAVAILABLE
      // As the real driver: never ok without a pinned id, whatever a daemon
      // would say.
      const unpinned = imageIdProblem(options.imageId)
      if (probe.ok && unpinned !== undefined) return { ok: false, why: unpinned }
      return probe
    },

    run(given: SandboxSpec): RunningSandbox {
      specs.push(given)
      // Read once, and every decision below made from that reading, as the
      // real driver reads it (readSpecOnce): `given` is read nowhere else.
      const spec = readSpecOnce(given)
      // As the real driver does (buildRunArgs): a name without the prefix is
      // no container of the kernel's, and is refused before anything starts,
      // with no scripted exit spent on it.
      if (!spec.name.startsWith(CONTAINER_PREFIX)) {
        throw new ConfigError(`container name "${spec.name}" must start with ${CONTAINER_PREFIX}`)
      }
      // As the real driver does (buildRunArgs): a channel on the hostile
      // domain, or one that is no boolean, is refused before anything starts,
      // with no scripted exit spent on it.
      const refusedChannel = channelRefusal(spec)
      if (refusedChannel !== undefined) throw new ConfigError(refusedChannel)
      // As the real driver's audit does first (wholeArgvRefusal, then its
      // home check), over the argv its builder writes: a command that carries
      // a forbidden flag, the docker socket, a --mount or a -v is refused,
      // `go test -v` among them, and one that names the home a test gave,
      // with no scripted exit spent on it. The audit's one --mount stands for
      // the builder's own, which with the rest of its options passes these.
      const scanned = commandAuditRefusal(spec.command, options.home ?? '')
      if (scanned !== undefined) throw new ConfigError(scanned)
      // As the real driver's audit does (buildRunArgs): the image must be the
      // pinned id, exactly, and with none pinned no run is built at all.
      // Refused before anything starts, with no scripted exit spent on it.
      const image = imageRefusal(spec.image, options.imageId)
      if (image !== undefined) throw new ConfigError(image)
      // As the real driver does (SandboxDriver.run): a name still running is
      // refused before anything starts, and no scripted exit is spent on it.
      if (running.has(spec.name)) {
        throw new ConfigError(
          `container ${spec.name} is already running on the ${started.get(spec.name)?.domain ?? '?'} domain; ` +
            'a second one under that name could not be killed by name',
        )
      }
      const scripted = script[index]
      index++
      if (scripted === undefined) {
        throw new Error(
          `unscripted run: the fake sandbox has ${String(script.length)} scripted exit(s) and run ` +
            `${String(index)} (${spec.name}) was requested. Extend the script or fix the caller.`,
        )
      }
      const channel = spec.channel === true
      if (channel && (scripted.stdout ?? '') !== '') {
        throw new Error(
          `scripted exit ${String(index - 1)}: stdout on a channel run (${spec.name}), whose stdout the real driver ` +
            "never reads: it is the channel's input, and the result's stdout is empty. Write it to the run's " +
            'FakeSandbox.channels entry instead.',
        )
      }
      started.set(spec.name, spec)
      running.add(spec.name)

      // The channel's input is the container's stdout, and its output the
      // container's stdin.
      const pipes = channel ? fakePipes(spec.name) : undefined
      if (pipes !== undefined) channels.push(pipes.container)

      const result = new Promise<SandboxResult>((resolve) => {
        const settle = (ended: SandboxResult): void => {
          if (pipes === undefined) resolve(ended)
          else pipes.exit(() => resolve({ ...ended, stderr: ended.stderr + pipes.heard() }))
        }
        if (scripted.hangs === true) {
          pending.set(spec.name, { spec, scripted, resolve: settle, overran: false, ending: false })
          return
        }
        settle(ownExit(spec, scripted, false))
      })
      // The name is free once the result has settled, and before any caller's
      // continuation of it runs: this reaction is the result's first, so it
      // runs first. The real driver frees the name in finish(), before it
      // resolves. Freed when it resolves instead, a run that does not hang
      // would free its name before run() returned, and the same tick could
      // start the name twice, which the real driver refuses.
      void result.finally(() => {
        running.delete(spec.name)
      })

      return { name: spec.name, result, ...(pipes === undefined ? {} : { channel: pipes.channel }) }
    },

    commandRefusal(command: readonly string[]): string | undefined {
      // As run() refuses the command, and the real driver's says.
      return commandAuditRefusal(command, options.home ?? '')
    },

    everyRunRefusal(): string | undefined {
      // As the real driver: none for itself. An unpinned id is run()'s
      // refusal of a spec, and the runner's configRefusal reads it first.
      return undefined
    },

    async kill(name: string): Promise<void> {
      kills.push(name)
      // As the real driver does: a name without the prefix is sent nowhere.
      // run() refuses one, so none is pending; this keeps the two alike
      // should that ever change.
      if (!name.startsWith(CONTAINER_PREFIX)) return
      const hung = pending.get(name)
      if (hung === undefined) return // already finished; kill is idempotent
      if (hung.scripted.ignoresKill !== true) hung.killedBy ??= 'requested'
      end(hung)
    },

    async abandon(name: string): Promise<void> {
      abandons.push(name)
      // As the real driver does: a name without the prefix is sent nowhere.
      if (!name.startsWith(CONTAINER_PREFIX)) return
      const hung = pending.get(name)
      if (hung === undefined) return // ended: its CLI is gone, and a kill by name of it ends nothing
      // Its end already queued is its CLI's exit, after which the real
      // driver signals nothing.
      if (hung.ending) return
      // Its CLI is SIGKILLed whatever the container does, so a script that
      // ignores kills ends here too, as a CLI killed by a signal reports.
      hung.abandoned = true
      end(hung)
    },

    simulateOverrun(name: string): void {
      const hung = pending.get(name)
      if (hung === undefined) return // ended: the real driver's timer is cleared
      hung.overran = true
      if (hung.scripted.ignoresKill !== true) hung.killedBy = 'wallclock'
      end(hung)
    },

    simulateExit(name: string): void {
      const hung = pending.get(name)
      if (hung === undefined) return // ended already
      end(hung)
    },
  }
}
