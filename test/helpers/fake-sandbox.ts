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
// Nothing here executes anything. It never spawns a process, never touches
// docker, and never reads the filesystem.

import './guard.js'

import type {
  ProbeResult,
  RunningSandbox,
  SandboxDriver,
  SandboxResult,
  SandboxSpec,
} from '../../src/sandbox/driver.js'

export interface ScriptedExit {
  readonly exitCode?: number | null
  readonly signal?: SandboxResult['signal']
  readonly stdout?: string
  readonly stderr?: string
  readonly durationMs?: number
  /** Do not resolve on its own: the run ends only by kill or overrun. */
  readonly hangs?: boolean
}

export interface FakeSandboxOptions {
  readonly probe?: ProbeResult
  readonly script?: readonly ScriptedExit[]
}

export interface FakeSandbox extends SandboxDriver {
  /** Every spec passed to run(), in order. */
  readonly specs: SandboxSpec[]
  /** Names passed to kill(), including repeats. */
  readonly kills: string[]
  /** End a hanging run as a wallclock overrun would. */
  simulateOverrun(name: string): void
}

const UNAVAILABLE: ProbeResult = {
  ok: false,
  why: 'fake driver: no container runtime configured for this test',
}

export function fakeSandbox(options: FakeSandboxOptions = {}): FakeSandbox {
  const specs: SandboxSpec[] = []
  const kills: string[] = []
  const script = options.script ?? []
  const pending = new Map<string, (result: SandboxResult) => void>()
  const started = new Map<string, SandboxSpec>()
  let index = 0

  const settle = (name: string, result: SandboxResult): void => {
    const resolve = pending.get(name)
    if (resolve === undefined) return // already finished; kill is idempotent
    pending.delete(name)
    resolve(result)
  }

  return {
    name: 'fake',
    specs,
    kills,

    async probe(): Promise<ProbeResult> {
      return options.probe ?? UNAVAILABLE
    },

    run(spec: SandboxSpec): RunningSandbox {
      specs.push(spec)
      const scripted = script[index]
      index++
      if (scripted === undefined) {
        throw new Error(
          `unscripted run: the fake sandbox has ${String(script.length)} scripted exit(s) and run ` +
            `${String(index)} (${spec.name}) was requested. Extend the script or fix the caller.`,
        )
      }
      started.set(spec.name, spec)

      const result = new Promise<SandboxResult>((resolve) => {
        pending.set(spec.name, resolve)
        if (scripted.hangs !== true) {
          resolve({
            name: spec.name,
            exitCode: scripted.exitCode ?? 0,
            signal: scripted.signal ?? null,
            stdout: scripted.stdout ?? '',
            stderr: scripted.stderr ?? '',
            durationMs: scripted.durationMs ?? 1,
          })
          pending.delete(spec.name)
        }
      })

      return { name: spec.name, result }
    },

    async kill(name: string): Promise<void> {
      kills.push(name)
      settle(name, {
        name,
        exitCode: null,
        signal: 'SIGKILL',
        killedBy: 'requested',
        stdout: '',
        stderr: '',
        durationMs: 0,
      })
    },

    simulateOverrun(name: string): void {
      const spec = started.get(name)
      settle(name, {
        name,
        exitCode: null,
        signal: 'SIGKILL',
        killedBy: 'wallclock',
        stdout: '',
        stderr: '',
        durationMs: spec?.limits.wallclockMs ?? 0,
      })
    },
  }
}
