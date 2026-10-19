// Turning the OS's shutdown signals into exactly one clean kernel shutdown.
//
// One Ctrl-C under `npm run dev` reaches the daemon TWICE: the terminal sends
// SIGINT to the whole foreground process group, and npm's run-script signal
// manager forwards its own copy to the child a few milliseconds later. With a
// once-listener the copy found no handler, Node's default action killed the
// process mid-shutdown, and the log lost its `kernel.shutdown` row and anchor.
// Seen on the operator's Mac (npm 11.19.1) with pmmcp connected, where closing
// the hub outlasts npm's forward; without pmmcp the shutdown wins the race.
//
// So both signals keep one listener for the life of the process, and the OS
// default never runs. The first signal starts the shutdown. A repeat inside
// DUPLICATE_WINDOW_MS is the same keypress arriving twice and is ignored. A
// repeat after it is the operator insisting on a shutdown that hangs, and exits
// at once, as before.

export const DUPLICATE_WINDOW_MS = 1_000

export type SignalAction = 'shutdown' | 'ignore' | 'exit'

/** The decision for each signal in arrival order; pure, so the policy is testable on a fake clock. */
export function signalGate(now: () => number = Date.now): () => SignalAction {
  let firstAt: number | undefined
  return () => {
    const at = now()
    if (firstAt === undefined) {
      firstAt = at
      return 'shutdown'
    }
    return at - firstAt < DUPLICATE_WINDOW_MS ? 'ignore' : 'exit'
  }
}

export interface SignalTarget {
  on(event: 'SIGINT' | 'SIGTERM', listener: (signal: NodeJS.Signals) => void): unknown
}

export interface ShutdownHooks {
  readonly shutdown: (signal: string) => Promise<void>
  readonly exit: (code: number) => void
  readonly log: {
    info(fields: Record<string, unknown>, message: string): void
    error(fields: Record<string, unknown>, message: string): void
  }
  readonly now?: () => number
}

/** Resolves once a signal-started shutdown has finished, successfully or not. */
export function onShutdownSignals(target: SignalTarget, hooks: ShutdownHooks): Promise<void> {
  return new Promise<void>((resolveExit) => {
    const gate = signalGate(hooks.now)
    const handle = (signal: NodeJS.Signals): void => {
      const action = gate()
      if (action === 'ignore') {
        hooks.log.info({ signal }, 'repeated signal ignored: the shutdown is already under way')
        return
      }
      if (action === 'exit') {
        // A hung shutdown must not trap the operator.
        hooks.log.error({ signal }, 'second signal during shutdown; exiting immediately')
        hooks.exit(1)
        return
      }
      hooks.log.info({ signal }, 'shutting down')
      void hooks
        .shutdown(signal)
        .catch((e: unknown) => {
          hooks.log.error({ err: e instanceof Error ? e.message : String(e) }, 'shutdown failed')
        })
        .finally(resolveExit)
    }
    target.on('SIGINT', handle)
    target.on('SIGTERM', handle)
  })
}
