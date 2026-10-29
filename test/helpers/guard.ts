// Network tripwire for the whole test suite.
//
// Contract: importing this module makes any attempt to reach a non-loopback
// host throw *before* a socket is opened. The suite's offline guarantee rests
// on it, so T01 proves the tripwire rather than assuming it. Every test file's
// first import is this module.
//
// Why patch two layers: `fetch` is patched so the failure names the URL and
// happens before undici allocates anything, and `net.Socket.prototype.connect`
// is patched so anything bypassing fetch (a provider SDK, ws, a raw socket)
// still cannot leave the machine. Unix domain sockets carry no host and are
// left alone: the Docker driver talks to a socket path.

import { existsSync, readFileSync } from 'node:fs'
import net from 'node:net'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { lockHolder } from '../../src/falsify-hold.js'

/**
 * Credentials never reach an offline test. Any name a provider key, the
 * control token or the pmmcp bearer would use is removed from this test
 * process's environment at import — so a key the operator exported in the
 * shell that runs `npm test` cannot be picked up, logged or sent by accident.
 *
 * The one exception is a test/live-*.test.ts file on the gated live run
 * (AOS_LIVE_TESTS=1). The gate alone is not enough: `AOS_LIVE_TESTS=1 npm
 * test` runs every file, and every offline one must still be scrubbed.
 * `node --test` gives each file its own process whose argv is exactly
 * [node, file]; anything else — an -e script, or --test-isolation=none, where
 * one process runs every file listed — is scrubbed.
 */
export const CREDENTIAL_NAME = /^(ANTHROPIC|OPENAI|OPENROUTER|MOONSHOT)_|_API_KEY$|^AOS_CONTROL_TOKEN$|^AOS_PMMCP_TOKEN$|^PMMCP_TOKEN$/

const LIVE_FILE = /[/\\]test[/\\]live-[^/\\]+\.test\.ts$/

/** True only in a live test file's own process on the gated run. */
export const KEEPS_CREDENTIALS =
  process.env['AOS_LIVE_TESTS'] === '1' && process.argv.length === 2 && LIVE_FILE.test(process.argv[1] ?? '')

if (!KEEPS_CREDENTIALS) {
  for (const name of Object.keys(process.env)) {
    if (CREDENTIAL_NAME.test(name)) delete process.env[name]
  }
}

/**
 * A falsify run that died (a closed terminal, a SIGKILL, a power cut) leaves a
 * source file mutated, and its journal is replayed only by the next falsify
 * start or `--recover`. Testing that tree would test a planted bug. The one
 * exception is the run that wrote the journal: it hands its id to its own test
 * processes (AOS_FALSIFY_RUN), and only they may test the tree it mutated. A
 * pid alone proves nothing — after a crash or a reboot it can name anything.
 */
function interruptedMutation(root: string): string | undefined {
  const path = join(root, '.falsify', 'journal.json')
  if (!existsSync(path)) return undefined
  let journal: { file?: unknown; runId?: unknown } = {}
  try {
    journal = JSON.parse(readFileSync(path, 'utf8')) as { file?: unknown; runId?: unknown }
  } catch {
    // Unreadable: it cannot name the file, so it must not pretend to.
  }
  if (typeof journal.runId === 'string' && journal.runId !== '' && process.env['AOS_FALSIFY_RUN'] === journal.runId) {
    return undefined
  }
  if (typeof journal.file !== 'string') {
    return (
      `${path} exists but is unreadable, so a falsify run may have left a source file mutated: ` +
      `run \`git status\`, \`git checkout\` any source file it lists that you did not change, then delete ${join(root, '.falsify')}`
    )
  }
  return (
    `a falsify run is in progress or was interrupted, and ${journal.file} may be mutated: ` +
    'run `npm run falsify -- --recover` (or git checkout the file and delete .falsify/) before testing'
  )
}

/**
 * A falsify run that holds this tree right now, and is not the one that
 * started this process. It mutates file after file while it holds the lock,
 * baselines included, so a test admitted between two mutants would load the
 * next one. Liveness is src/falsify-hold.ts's: the pid alone, since ps on every
 * test file would cost every run; a pid reused after a crash is a refusal that
 * `--recover` (which checks the start time) clears.
 */
function heldByAnotherRun(root: string): string | undefined {
  const holder = lockHolder(root)
  if (holder === undefined || (holder.runId !== undefined && holder.runId === process.env['AOS_FALSIFY_RUN'])) return undefined
  return (
    `a falsify run (pid ${String(holder.pid)}) holds this tree and mutates its files as it goes: let it finish before testing. ` +
    'If no falsify run is going, run `npm run falsify -- --recover`, which drops a stale lock'
  )
}

const root = fileURLToPath(new URL('../..', import.meta.url))
const mutated = interruptedMutation(root) ?? heldByAnotherRun(root)
if (mutated !== undefined) throw new Error(mutated)

/** Thrown instead of opening a connection the test suite must never make. */
export class NetworkBlocked extends Error {
  readonly code = 'AOS_TEST_NETWORK_BLOCKED'
  constructor(target: string, layer: string) {
    super(
      `test network guard: refused ${layer} to ${target}. ` +
        'Tests must not touch the network; use a loopback server or a test double, ' +
        'or call allowHost() if this is a gated live test.',
    )
    this.name = 'NetworkBlocked'
  }
}

const allowed = new Set<string>()

/** True for localhost, ::1 and the whole 127.0.0.0/8 range. */
export function isLoopbackHost(host: string): boolean {
  let h = host.trim().toLowerCase()
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1)
  const zone = h.indexOf('%')
  if (zone !== -1) h = h.slice(0, zone)
  if (h === 'localhost' || h === '::1' || h === '0:0:0:0:0:0:0:1') return true
  if (h === '::ffff:127.0.0.1') return true
  return /^127\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$/.test(h)
}

function permitted(host: string): boolean {
  return isLoopbackHost(host) || allowed.has(host.trim().toLowerCase())
}

/**
 * Admit exactly one non-loopback host. Used only by the gated live tests.
 * Returns a revoke function; `clearAllowedHosts()` resets every allowance.
 */
export function allowHost(host: string): () => void {
  const key = host.trim().toLowerCase()
  allowed.add(key)
  return () => {
    allowed.delete(key)
  }
}

export function clearAllowedHosts(): void {
  allowed.clear()
}

function hostOfFetchInput(input: unknown): string {
  if (typeof input === 'string') return new URL(input).hostname
  if (input instanceof URL) return input.hostname
  if (typeof input === 'object' && input !== null && 'url' in input) {
    const url = (input as { url: unknown }).url
    if (typeof url === 'string') return new URL(url).hostname
  }
  // An input shape we cannot read is treated as non-loopback: fail closed.
  return '<unparseable>'
}

type FetchArgs = Parameters<typeof globalThis.fetch>
type ConnectArgs = Parameters<net.Socket['connect']>

let installed = false

function install(): void {
  if (installed) return
  installed = true

  const realFetch = globalThis.fetch.bind(globalThis)
  globalThis.fetch = function guardedFetch(...args: FetchArgs): Promise<Response> {
    const host = hostOfFetchInput(args[0])
    if (!permitted(host)) {
      return Promise.reject(new NetworkBlocked(host, 'fetch'))
    }
    return realFetch(...args)
  } as typeof globalThis.fetch

  const realConnect = net.Socket.prototype.connect
  function guardedConnect(this: net.Socket, ...args: ConnectArgs): net.Socket {
    const first = args[0]
    let host: string | undefined
    if (typeof first === 'object' && first !== null) {
      const opts = first as { host?: unknown; path?: unknown }
      // A unix domain socket has no host and never leaves the machine.
      if (typeof opts.path === 'string') host = undefined
      else host = typeof opts.host === 'string' ? opts.host : 'localhost'
    } else if (typeof first === 'number') {
      const second = args[1]
      host = typeof second === 'string' ? second : 'localhost'
    } else {
      // net.connect(path[, listener]) — unix domain socket.
      host = undefined
    }
    if (host !== undefined && !permitted(host)) {
      throw new NetworkBlocked(host, 'socket connect')
    }
    return realConnect.apply(this, args)
  }
  net.Socket.prototype.connect = guardedConnect as net.Socket['connect']
}

install()
