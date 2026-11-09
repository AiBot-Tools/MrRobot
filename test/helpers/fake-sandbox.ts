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
// these.
//
// What still differs: when a run whose kill ended nothing exits, which here is
// just after that kill, and on the real driver whenever its container does.
// And the reason a probe gives with no valid id pinned and a probe scripted
// not ok (or none scripted): the scripted (or default) reason here, where the
// real driver names sandbox.imageId before asking any daemon anything.
// Degraded on both. A probe scripted ok or not stands for everything the real
// driver asks the daemons, the pinned image's presence on each VM among it.
//
// And a script may not describe a result the real driver cannot return: a
// stream longer than its capture keeps, a cut with no stream near the cap, or
// a kill that ends nothing followed by an exit of 137, which the real driver
// credits to that kill (assertDriverShaped). Runtime code is tested against
// this fake, and could otherwise come to rely on a result shape it will never
// meet.
//
// Nothing here executes anything. It never spawns a process, never touches
// docker, and never reads the filesystem.

import './guard.js'

import { ConfigError } from '../../src/errors.js'
import {
  CAPTURE_MAX_BYTES,
  CONTAINER_PREFIX,
  type ProbeResult,
  type RunningSandbox,
  type SandboxDriver,
  type SandboxResult,
  type SandboxSpec,
} from '../../src/sandbox/driver.js'
import { imageIdProblem, imageRefusal } from '../../src/sandbox/limits.js'

export interface ScriptedExit {
  readonly exitCode?: number | null
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
}

export interface FakeSandbox extends SandboxDriver {
  /** Every spec passed to run(), in order. */
  readonly specs: SandboxSpec[]
  /** Names passed to kill(), including repeats. */
  readonly kills: string[]
  /** End a hanging run as a wallclock overrun would, on a later macrotask. */
  simulateOverrun(name: string): void
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
 * nothing and then a 137 is a result it never gives. And refuse one that says
 * nothing: `ignoresKill` on a run that does not hang, which has ended before
 * any kill could reach it.
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
    exitCode: scripted.exitCode ?? 0,
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
}

export function fakeSandbox(options: FakeSandboxOptions = {}): FakeSandbox {
  const specs: SandboxSpec[] = []
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
      // As the real driver reports a run its kill ended: the CLI's 137, with
      // SIGKILL, and what it captured before the kill.
      hung.resolve(killedBy === undefined ? own : { ...own, exitCode: 137, signal: 'SIGKILL', killedBy })
    })
  }

  return {
    name: 'fake',
    specs,
    kills,

    async probe(): Promise<ProbeResult> {
      const probe = options.probe ?? UNAVAILABLE
      // As the real driver: never ok without a pinned id, whatever a daemon
      // would say.
      const unpinned = imageIdProblem(options.imageId)
      if (probe.ok && unpinned !== undefined) return { ok: false, why: unpinned }
      return probe
    },

    run(spec: SandboxSpec): RunningSandbox {
      specs.push(spec)
      // As the real driver does (buildRunArgs): a name without the prefix is
      // no container of the kernel's, and is refused before anything starts,
      // with no scripted exit spent on it.
      if (!spec.name.startsWith(CONTAINER_PREFIX)) {
        throw new ConfigError(`container name "${spec.name}" must start with ${CONTAINER_PREFIX}`)
      }
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
      started.set(spec.name, spec)
      running.add(spec.name)

      const result = new Promise<SandboxResult>((resolve) => {
        if (scripted.hangs === true) {
          pending.set(spec.name, { spec, scripted, resolve, overran: false, ending: false })
          return
        }
        resolve(ownExit(spec, scripted, false))
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

      return { name: spec.name, result }
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

    simulateOverrun(name: string): void {
      const hung = pending.get(name)
      if (hung === undefined) return // ended: the real driver's timer is cleared
      hung.overran = true
      if (hung.scripted.ignoresKill !== true) hung.killedBy = 'wallclock'
      end(hung)
    },
  }
}
