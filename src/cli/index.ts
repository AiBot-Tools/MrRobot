// aos — the operator's console.
//
// Two groups of commands, split by whether they need the daemon:
//
//   `verify-chain` and `search` open the event database READ-ONLY and talk to
//   nothing. They are the commands an operator reaches for when the kernel is
//   the thing that is wrong, so they must work when it is not running — and
//   read-only means an investigation cannot become a write. Neither reads
//   AOS_CONTROL_TOKEN: a command that needs no credential must not touch one,
//   because a process that never reads a secret cannot leak it.
//
//   Everything else opens a socket, and the token rides the Authorization
//   header only (src/cli/client.ts has nowhere else to put it).
//
// `approve <id>` and `deny <id>` dispatch on the id's PREFIX rather than
// guessing. `hold_…` is a quarantine hold and `apr_…` is an approval, and an
// approval is further split by kind — a promotion goes to agent.promote,
// because invariant 6 gives promotion exactly one command. Guessing here would
// mean an operator typing `approve` on a hold could silently approve a tool
// call, or a promotion could be granted by the command meant for tool calls.
//
// `deny` on a hold is refused with usage. A hold is released or left held;
// there is no third outcome, and inventing one would suggest the output had
// been discarded when it is still sitting in the log.

import { parseArgs } from 'node:util'
import { readFileSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { ConfigError } from '../errors.js'
import { EventStore } from '../events/store.js'
import { redactString } from '../events/redact.js'
import { expandHome, parseKernelConfig, type KernelConfig } from '../config.js'
import { connectControl, ControlCallError, type ControlClient } from './client.js'
import type { ApprovalItem, HoldItem } from '../control/protocol.js'

/** Exactly these nine. A tenth is a new command, not a flag on an old one. */
export const CLI_COMMANDS = [
  'agents',
  'verify-chain',
  'search',
  'probe',
  'run',
  'kill',
  'approve',
  'deny',
  'approvals',
] as const
export type CliCommand = (typeof CLI_COMMANDS)[number]

/** Commands that open a socket, and therefore read the token. */
export const SOCKET_COMMANDS: readonly CliCommand[] = [
  'agents',
  'probe',
  'run',
  'kill',
  'approve',
  'deny',
  'approvals',
]

/** The file the store lives in, under the data directory. */
export const EVENTS_DB_FILE = 'events.db'

export const USAGE = `aos — Agentic OS console

  aos agents [--include-archived]
  aos verify-chain                      (no daemon; read-only)
  aos search [--type T] [--run R] [--text X] [--limit N]   (no daemon; read-only)
  aos probe <modelRef>
  aos run <agentId> <input>
  aos kill <runId> [--reason R]
  aos approvals
  aos approve <apr_…|hold_…>
  aos deny <apr_…> [--reason R]

  --config <path>   kernel.yaml (default ./config/kernel.yaml)
`

export interface CliIo {
  out(line: string): void
  err(line: string): void
  readonly env: Record<string, string | undefined>
  readonly cwd: string
  /** Injected only by tests, so no test opens a real socket by accident. */
  readonly connect?: typeof connectControl
}

const OPTIONS = {
  config: { type: 'string' },
  'include-archived': { type: 'boolean' },
  type: { type: 'string' },
  run: { type: 'string' },
  text: { type: 'string' },
  limit: { type: 'string' },
  reason: { type: 'string' },
} as const

function isCommand(value: string | undefined): value is CliCommand {
  return value !== undefined && (CLI_COMMANDS as readonly string[]).includes(value)
}

function loadConfig(io: CliIo, configPath: string | undefined): KernelConfig {
  const path = resolve(io.cwd, configPath ?? join('config', 'kernel.yaml'))
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    throw new ConfigError(`cannot read ${path}. Pass --config <path>.`)
  }
  // The override wins over the file, and is expanded here so a relative
  // AOS_DATA_DIR cannot silently mean "wherever the CLI happened to run".
  const override = io.env['AOS_DATA_DIR']
  return parseKernelConfig(parseYaml(text), {
    repoRoot: io.cwd,
    ...(override === undefined || override === ''
      ? {}
      : { dataDirOverride: isAbsolute(expandHome(override)) ? expandHome(override) : resolve(io.cwd, override) }),
  })
}

function dbPath(config: KernelConfig): string {
  return join(config.dataDir, EVENTS_DB_FILE)
}

async function withClient<T>(
  io: CliIo,
  config: KernelConfig,
  fn: (client: ControlClient) => Promise<T>,
): Promise<T> {
  // Read ONLY here, so the read is on the path that needs it.
  const token = (io.env[config.control.tokenEnv] ?? '').trim()
  if (token === '') {
    throw new ConfigError(`${config.control.tokenEnv} is not set; this command needs it.`)
  }
  const connect = io.connect ?? connectControl
  const client = await connect({ port: config.control.port, token })
  try {
    return await fn(client)
  } finally {
    client.close()
  }
}

/**
 * Run one command. Returns the process exit code.
 *
 * 0 success · 1 a refusal or a failed run · 2 usage.
 */
export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  let parsed
  try {
    parsed = parseArgs({ args: [...argv], options: OPTIONS, allowPositionals: true, strict: true })
  } catch (e) {
    io.err(e instanceof Error ? e.message : String(e))
    io.err(USAGE)
    return 2
  }

  const [command, ...rest] = parsed.positionals
  if (!isCommand(command)) {
    io.err(command === undefined ? 'no command given' : `unknown command: ${command}`)
    io.err(USAGE)
    return 2
  }

  try {
    return await dispatch(command, rest, parsed.values, io)
  } catch (e) {
    if (e instanceof ControlCallError) {
      io.err(`${e.code}: ${e.message}`)
      return 1
    }
    io.err(e instanceof Error ? e.message : String(e))
    return 1
  }
}

type Values = Record<string, string | boolean | undefined>

async function dispatch(
  command: CliCommand,
  positionals: readonly string[],
  values: Values,
  io: CliIo,
): Promise<number> {
  const configPath = typeof values['config'] === 'string' ? values['config'] : undefined
  const config = loadConfig(io, configPath)

  switch (command) {
    case 'verify-chain':
      return verifyChain(io, config)

    case 'search':
      return search(io, config, values)

    case 'agents':
      return withClient(io, config, async (client) => {
        const agents = (await client.call('agents.list', {
          includeArchived: values['include-archived'] === true,
        })) as { id: string; kind: string; tier: number; status: string; modelPrimary: string }[]
        for (const a of agents) {
          io.out(`${a.id}\t${a.kind}\tT${String(a.tier)}\t${a.status}\t${a.modelPrimary}`)
        }
        return 0
      })

    case 'approvals':
      return withClient(io, config, async (client) => {
        const listed = (await client.call('approvals.list')) as {
          approvals: ApprovalItem[]
          holds: HoldItem[]
        }
        for (const a of listed.approvals) {
          io.out(`${a.approvalId}\t${a.kind}\t${a.toolRef ?? a.agentId ?? ''}\texpires ${a.expiresAt}`)
        }
        for (const h of listed.holds) io.out(`${h.holdId}\thold\t${h.toolRef}\theld ${h.heldAt}`)
        return 0
      })

    case 'probe': {
      const ref = positionals[0]
      if (ref === undefined) return usage(io, 'probe needs a model ref')
      return withClient(io, config, async (client) => {
        const record = (await client.call('model.probe', { ref })) as { toolCalling: boolean; reason?: string }
        io.out(`${ref}\ttoolCalling=${String(record.toolCalling)}${record.reason === undefined ? '' : `\t${record.reason}`}`)
        return record.toolCalling ? 0 : 1
      })
    }

    case 'kill': {
      const runId = positionals[0]
      if (runId === undefined) return usage(io, 'kill needs a runId')
      return withClient(io, config, async (client) => {
        const result = (await client.call('run.kill', {
          runId,
          ...(typeof values['reason'] === 'string' ? { reason: values['reason'] } : {}),
        })) as { runId: string; status: string }
        io.out(`${result.runId}\t${result.status}`)
        return 0
      })
    }

    case 'run': {
      const agentId = positionals[0]
      const input = positionals.slice(1).join(' ')
      if (agentId === undefined || input === '') return usage(io, 'run needs an agentId and an input')
      return withClient(io, config, async (client) => {
        // Subscribing before the call is not enough. The daemon broadcasts as
        // it appends, so a fast run can finish before the reply frame that
        // names it is even parsed — and a listener that only matches a runId it
        // does not yet know would drop that event and wait forever.
        //
        // So every run.finished is BUFFERED until the id is known, and the
        // buffer is consulted once it is. The buffer only holds finishes that
        // land in the window between subscribing and reading the reply, which
        // is one round trip.
        type Outcome = { status: string; reason?: string }
        const early = new Map<string, Outcome>()
        let mine: string | undefined
        let settle: (outcome: Outcome) => void = () => undefined
        const finished = new Promise<Outcome>((resolve) => {
          settle = resolve
        })
        client.onEvent((event) => {
          if (event.type !== 'run.finished') return
          const payload = event.payload as { runId?: string; status?: string; reason?: string } | null
          if (payload === null || typeof payload.runId !== 'string') return
          const outcome: Outcome = {
            status: payload.status ?? 'error',
            ...(payload.reason === undefined ? {} : { reason: payload.reason }),
          }
          if (payload.runId === mine) settle(outcome)
          else early.set(payload.runId, outcome)
        })

        const { runId } = (await client.call('run.start', { agentId, input })) as { runId: string }
        mine = runId
        io.out(runId)
        // Already finished while the reply was in flight.
        const alreadyDone = early.get(runId)
        if (alreadyDone !== undefined) settle(alreadyDone)
        const outcome = await finished
        io.out(`${runId}\t${outcome.status}${outcome.reason === undefined ? '' : `\t${outcome.reason}`}`)
        return outcome.status === 'ok' ? 0 : 1
      })
    }

    case 'approve':
    case 'deny': {
      const id = positionals[0]
      if (id === undefined) return usage(io, `${command} needs an id`)
      return resolveById(command, id, values, io, config)
    }
  }
}

function usage(io: CliIo, message: string): number {
  io.err(message)
  io.err(USAGE)
  return 2
}

/**
 * Route an approve/deny by the id's PREFIX, never by guessing.
 *
 * A hold and an approval are different objects with different consequences,
 * and the prefixes exist so this dispatch cannot get it wrong.
 */
async function resolveById(
  command: 'approve' | 'deny',
  id: string,
  values: Values,
  io: CliIo,
  config: KernelConfig,
): Promise<number> {
  if (id.startsWith('hold_')) {
    if (command === 'deny') {
      // A hold is released or left held. There is no "denied" state, and
      // inventing one would suggest the output had been discarded when it is
      // still sitting in the log.
      return usage(io, 'a quarantine hold cannot be denied: release it, or leave it held')
    }
    return withClient(io, config, async (client) => {
      const result = (await client.call('quarantine.release', { holdId: id })) as { runTainted: boolean }
      io.out(`${id}\treleased\trunTainted=${String(result.runTainted)}`)
      return 0
    })
  }

  if (!id.startsWith('apr_')) {
    io.err(`not_found: ${id} is neither an approval (apr_…) nor a hold (hold_…)`)
    return 1
  }

  return withClient(io, config, async (client) => {
    const listed = (await client.call('approvals.list')) as { approvals: ApprovalItem[] }
    const item = listed.approvals.find((a) => a.approvalId === id)
    if (item === undefined) {
      io.err(`not_found: ${id} is not a pending approval`)
      return 1
    }

    if (command === 'deny') {
      // Either kind: denying a promotion needs no promotion path.
      await client.call('approval.deny', {
        approvalId: id,
        ...(typeof values['reason'] === 'string' ? { reason: values['reason'] } : {}),
      })
      io.out(`${id}\tdenied`)
      return 0
    }

    if (item.kind === 'promotion') {
      // Invariant 6: promotion has exactly one command, and this routes to it.
      const result = (await client.call('agent.promote', { approvalId: id })) as { agentId: string }
      io.out(`${id}\tpromoted\t${result.agentId}`)
      return 0
    }

    await client.call('approval.approve', { approvalId: id })
    io.out(`${id}\tapproved`)
    return 0
  })
}

// ── the daemon-less pair ───────────────────────────────────────────────────

function verifyChain(io: CliIo, config: KernelConfig): number {
  // Read-only: an investigation must not be able to become a write, and this
  // is the command an operator runs when the kernel is what is wrong.
  const store = new EventStore(dbPath(config), { readOnly: true })
  try {
    const result = store.verifyChain()
    if (result.ok) {
      io.out(`ok\t${String(result.count)} events\thead ${result.head}`)
      return 0
    }
    io.err(`broken at seq ${String(result.at)}: ${result.reason}`)
    return 1
  } finally {
    store.close()
  }
}

function search(io: CliIo, config: KernelConfig, values: Values): number {
  const store = new EventStore(dbPath(config), { readOnly: true })
  try {
    const type = typeof values['type'] === 'string' ? values['type'] : undefined
    const runId = typeof values['run'] === 'string' ? values['run'] : undefined
    const text = typeof values['text'] === 'string' ? values['text'] : undefined
    const limit = typeof values['limit'] === 'string' ? Number(values['limit']) : 50

    const rows = store
      .query({ ...(type === undefined ? {} : { type }), ...(runId === undefined ? {} : { runId }) })
      .filter((r) => text === undefined || r.payload.includes(text))
      .slice(-Math.max(1, Number.isFinite(limit) ? limit : 50))

    for (const row of rows) {
      // Redacted AGAIN on the way out. The store redacted at write time with
      // whatever the mask knew then; a value resolved later in the session is
      // known now and would otherwise be printed in full to an operator
      // grepping old events.
      io.out(`${String(row.seq)}\t${row.ts}\t${row.type}\t${row.runId ?? '-'}\t${redactString(row.payload)}`)
    }
    return 0
  } finally {
    store.close()
  }
}

// The entry point.
//
// Without this the module exported `runCli` and nothing called it: `npm run cli
// -- verify-chain` loaded the file, ran no command, printed nothing and exited
// 0. Every test drives runCli() in process, so none of them could notice — the
// same shape of bug as a router with no adapters, and found the same way, by
// running the thing for real.
//
// Compared as resolved paths rather than by suffix, so importing this module
// from a test does not execute a command.
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  runCli(process.argv.slice(2), {
    out: (line) => {
      process.stdout.write(`${line}\n`)
    },
    err: (line) => {
      process.stderr.write(`${line}\n`)
    },
    env: process.env,
    cwd: process.cwd(),
  })
    .then((code) => {
      process.exit(code)
    })
    .catch((e: unknown) => {
      // runCli already maps every expected failure to an exit code, so reaching
      // here is a bug rather than a refusal. It still must not be silent.
      process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`)
      process.exit(1)
    })
}
