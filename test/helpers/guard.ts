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

import net from 'node:net'

/**
 * Credentials never reach an offline test. Any name a provider key, the
 * control token or the pmmcp bearer would use is removed from this test
 * process's environment at import — so a key the operator exported in the
 * shell that runs `npm test` cannot be picked up, logged or sent by accident.
 *
 * The one exception is a test/live-*.test.ts file on the gated live run
 * (AOS_LIVE_TESTS=1). The gate alone is not enough: `AOS_LIVE_TESTS=1 npm
 * test` runs every file, and the sixty offline ones must still be scrubbed.
 * `node --test` gives each file its own process with the file as argv[1];
 * anything else (an -e script, --test-isolation=none) is scrubbed.
 */
export const CREDENTIAL_NAME = /^(ANTHROPIC|OPENAI|OPENROUTER|MOONSHOT)_|_API_KEY$|^AOS_CONTROL_TOKEN$|^PMMCP_TOKEN$/

const LIVE_FILE = /[/\\]test[/\\]live-[^/\\]+\.test\.ts$/

/** True only in a live test file's own process on the gated run. */
export const KEEPS_CREDENTIALS = process.env['AOS_LIVE_TESTS'] === '1' && LIVE_FILE.test(process.argv[1] ?? '')

if (!KEEPS_CREDENTIALS) {
  for (const name of Object.keys(process.env)) {
    if (CREDENTIAL_NAME.test(name)) delete process.env[name]
  }
}

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
