// T29 — control auth and the server skeleton.
//
// A real `ws` server on port 0 and a real `ws` client, because the thing being
// tested is what happens at an HTTP upgrade and a mock of an upgrade would only
// prove the mock agrees with me.
//
// The falsifiers:
//
//   Bind 0.0.0.0 instead of 127.0.0.1 and a laptop that joins a café network
//   is a kernel anyone on that network can drive. One character.
//   Honour a query-string token, or merely ignore the parameter while
//   accepting the header, and a credential travels through process lists,
//   shell history, proxy logs and crash reporters — and the client bug that
//   put it there stays invisible until it leaks.
//   Compare tokens with === and the comparison leaks length and content by
//   timing; compare raw values with timingSafeEqual and a short guess throws.
//   Admit http://tauri.localhost as loopback and a PUBLIC hostname under the
//   localhost TLD reaches the control plane.
//   Boot without a token, or with a four-character one, and every process on
//   the machine can drive the kernel.
//   Put the presented token in control.rejected and the log becomes the place
//   the credential was written down.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { connect } from 'node:net'
import { WebSocket } from 'ws'

import { withStore } from './helpers/store.js'
import { ConfigError } from '../src/errors.js'
import {
  assertTokenUsable,
  authorizeUpgrade,
  CONTROL_PATH,
  digestToken,
  FORBIDDEN_QUERY_KEYS,
  isLoopbackHttpOrigin,
  MIN_TOKEN_LENGTH,
} from '../src/control/auth.js'
import { ControlServer, CONTROL_HOST } from '../src/control/server.js'

const TOKEN = 'a'.repeat(16) + 'b'.repeat(16) // 32 chars exactly
const DIGEST = digestToken(TOKEN)

interface Served {
  readonly server: ControlServer
  readonly port: number
  readonly store: ReturnType<typeof withStore>
  readonly connections: { connectionId: string; origin: string | undefined }[]
}

async function serve(
  t: TestContext,
  options: { token?: string; allowedOrigins?: readonly string[]; maxPayloadBytes?: number } = {},
): Promise<Served> {
  const store = withStore(t)
  const connections: Served['connections'] = []
  const server = new ControlServer({
    store,
    port: 0,
    token: options.token ?? TOKEN,
    ...(options.allowedOrigins === undefined ? {} : { allowedOrigins: options.allowedOrigins }),
    maxPayloadBytes: options.maxPayloadBytes ?? 1_048_576,
    onConnection: (c) => connections.push({ connectionId: c.connectionId, origin: c.origin }),
  })
  const port = await server.listen()
  t.after(() => server.close())
  return { server, port, store, connections }
}

type Attempt = { ok: true } | { ok: false; status: number }

/**
 * Try one upgrade and report only whether it became a socket.
 *
 * The error listener is attached and never removed: `terminate()` on a
 * half-open socket emits an error of its own, and with no listener left that
 * becomes an uncaught exception that fails an unrelated test. A rejected
 * upgrade also leaves the client's HTTP request holding a socket, so it is
 * destroyed explicitly.
 */
async function tryUpgrade(
  port: number,
  options: { path?: string; headers?: Record<string, string>; origin?: string } = {},
): Promise<Attempt> {
  const url = `ws://${CONTROL_HOST}:${String(port)}${options.path ?? CONTROL_PATH}`
  const client = new WebSocket(url, {
    ...(options.headers === undefined ? {} : { headers: options.headers }),
    ...(options.origin === undefined ? {} : { origin: options.origin }),
  })

  return new Promise<Attempt>((resolve) => {
    let settled = false
    const finish = (a: Attempt): void => {
      if (settled) return
      settled = true
      resolve(a)
      setImmediate(() => {
        try {
          client.terminate()
        } catch {
          // Already gone.
        }
      })
    }
    client.on('error', () => finish({ ok: false, status: 0 }))
    client.on('unexpected-response', (req, res) => {
      res.resume()
      req.destroy()
      finish({ ok: false, status: res.statusCode ?? 0 })
    })
    client.on('open', () => finish({ ok: true }))
  })
}

const rejections = (s: Served): string[] =>
  s.store.query({ type: 'control.rejected' }).map(
    (r) => (JSON.parse(r.payload) as { reason: string }).reason,
  )

// ── binding ────────────────────────────────────────────────────────────────

test('binds 127.0.0.1 only', async (t) => {
  const s = await serve(t)

  // The literal is the contract, not a config default that happens to be right.
  assert.equal(CONTROL_HOST, '127.0.0.1')
  assert.deepEqual(await tryUpgrade(s.port, { headers: { Authorization: `Bearer ${TOKEN}` } }), {
    ok: true,
  })

  // Read back from the socket, because a loopback client reaches a 0.0.0.0
  // listener perfectly well: a successful connection proves nothing about
  // which interfaces the server is on. One character between the two, and on
  // a laptop that joins a cafe network it is the whole difference.
  assert.equal(s.server.boundAddress, '127.0.0.1')
  assert.equal(s.connections.length, 1)
})

test('the 401 body reveals nothing about which check failed', async (t) => {
  const s = await serve(t)

  // A raw socket, so the exact bytes of the rejection can be read. Telling a
  // prober whether their token was wrong or their origin was is telling them
  // which half to keep trying.
  const raw = await new Promise<string>((resolve, reject) => {
    const socket = connect({ host: CONTROL_HOST, port: s.port }, () => {
      socket.write(
        `GET ${CONTROL_PATH} HTTP/1.1\r\nHost: ${CONTROL_HOST}\r\n` +
          'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
          'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n' +
          'Authorization: Bearer definitely-not-the-token-0000000\r\n\r\n',
      )
    })
    let text = ''
    socket.setEncoding('utf8')
    socket.on('data', (chunk: string) => {
      text += chunk
    })
    socket.on('error', reject)
    socket.on('close', () => resolve(text))
  })

  assert.match(raw, /^HTTP\/1\.1 401 Unauthorized/)
  for (const leak of ['bad_token', 'missing_token', 'bad_origin', 'query_token', 'bad_upgrade', TOKEN]) {
    assert.equal(raw.includes(leak), false, `the 401 named ${leak}`)
  }
  // The reason IS in the log, where it belongs.
  assert.deepEqual(rejections(s), ['bad_token'])
})

test('plain HTTP GET is 404', async (t) => {
  const s = await serve(t)

  // There is no page to serve and nothing to discover by probing.
  for (const path of ['/', CONTROL_PATH, '/status', '/.well-known/x']) {
    const response = await fetch(`http://${CONTROL_HOST}:${String(s.port)}${path}`)
    assert.equal(response.status, 404, path)
    assert.equal((await response.text()).includes(TOKEN), false)
  }
  assert.equal(rejections(s).length, 0, 'a plain GET is not an upgrade attempt')
})

// ── the bearer ─────────────────────────────────────────────────────────────

test('accepts a valid bearer with no Origin, http://localhost, http://127.0.0.1, http://[::1]', async (t) => {
  const s = await serve(t)
  const headers = { Authorization: `Bearer ${TOKEN}` }

  // No Origin at all: a CLI, which is the only client in Phase 0.
  assert.deepEqual(await tryUpgrade(s.port, { headers }), { ok: true })
  for (const origin of ['http://localhost', 'http://127.0.0.1', 'http://[::1]', 'http://127.0.0.1:1420']) {
    assert.deepEqual(await tryUpgrade(s.port, { headers, origin }), { ok: true }, origin)
  }

  assert.equal(s.connections.length, 5)
  assert.equal(rejections(s).length, 0)
  // Every accepted connection is recorded with its origin, and none of them
  // records a token.
  const connected = s.store.query({ type: 'control.connected' })
  assert.equal(connected.length, 5)
  for (const row of connected) assert.equal(row.payload.includes(TOKEN), false)
})

test('rejects a valid token presented in the query string (token, access_token, auth) even with a valid header', async (t) => {
  const s = await serve(t)
  const headers = { Authorization: `Bearer ${TOKEN}` }

  for (const key of ['token', 'access_token', 'auth']) {
    // A VALID header alongside. The request is refused anyway: a client that
    // puts a credential in a URL has a bug the operator needs to see, and
    // quietly honouring the header would hide it until the token leaked
    // through a process list, a proxy log or a crash report.
    const attempt = await tryUpgrade(s.port, {
      path: `${CONTROL_PATH}?${key}=${TOKEN}`,
      headers,
    })
    assert.equal(attempt.ok, false, key)
    assert.equal(attempt.ok ? 0 : attempt.status, 401, key)
  }

  // Every near-miss spelling is the same failure.
  for (const key of FORBIDDEN_QUERY_KEYS) {
    const verdict = authorizeUpgrade(
      { url: `${CONTROL_PATH}?${key}=x`, headers: { authorization: `Bearer ${TOKEN}` } },
      { tokenDigest: DIGEST, allowedOrigins: [] },
    )
    assert.equal(verdict.ok, false, key)
    assert.equal(verdict.ok ? '' : verdict.reason, 'query_token', key)
  }

  // A harmless parameter is not a refusal.
  assert.equal(
    authorizeUpgrade(
      { url: `${CONTROL_PATH}?since=42`, headers: { authorization: `Bearer ${TOKEN}` } },
      { tokenDigest: DIGEST, allowedOrigins: [] },
    ).ok,
    true,
  )

  assert.deepEqual(rejections(s), ['query_token', 'query_token', 'query_token'])
  assert.equal(s.connections.length, 0)
})

test('rejects absent, wrong and equal-length-wrong tokens', async (t) => {
  const s = await serve(t)

  assert.equal((await tryUpgrade(s.port)).ok, false, 'absent')
  assert.equal((await tryUpgrade(s.port, { headers: { Authorization: 'Bearer nope' } })).ok, false, 'wrong')
  // Same length, different bytes: proves the comparison is not a length check
  // wearing a constant-time coat.
  const sameLength = 'c'.repeat(TOKEN.length)
  assert.equal(sameLength.length, TOKEN.length)
  assert.equal((await tryUpgrade(s.port, { headers: { Authorization: `Bearer ${sameLength}` } })).ok, false)

  // Malformed schemes are missing tokens, not bad ones.
  for (const header of ['', 'Bearer', 'Basic abc', `bearer ${TOKEN}`, TOKEN]) {
    const verdict = authorizeUpgrade(
      { url: CONTROL_PATH, headers: { authorization: header } },
      { tokenDigest: DIGEST, allowedOrigins: [] },
    )
    assert.equal(verdict.ok, false, JSON.stringify(header))
  }

  // A duplicated Authorization header is ambiguous, and ambiguity in an auth
  // header is a refusal rather than a guess.
  assert.equal(
    authorizeUpgrade(
      { url: CONTROL_PATH, headers: { authorization: [`Bearer ${TOKEN}`, 'Bearer other'] } },
      { tokenDigest: DIGEST, allowedOrigins: [] },
    ).ok,
    false,
  )

  assert.deepEqual(rejections(s), ['missing_token', 'bad_token', 'bad_token'])
  // And no rejection wrote down what was presented.
  for (const row of s.store.query({ type: 'control.rejected' })) {
    for (const leak of [TOKEN, 'nope', sameLength]) {
      assert.equal(row.payload.includes(leak), false)
    }
  }
})

// ── origins ────────────────────────────────────────────────────────────────

test('rejects https://evil.com, http://tauri.localhost and null Origin; admits tauri://localhost only when listed', async (t) => {
  const s = await serve(t)
  const headers = { Authorization: `Bearer ${TOKEN}` }

  for (const origin of ['https://evil.com', 'http://tauri.localhost', 'null', 'tauri://localhost']) {
    const attempt = await tryUpgrade(s.port, { headers, origin })
    assert.equal(attempt.ok, false, origin)
  }

  // `http://tauri.localhost` is the trap: a PUBLIC hostname under the
  // localhost TLD, resolvable by anyone, and not loopback at all.
  assert.equal(isLoopbackHttpOrigin('http://tauri.localhost'), false)
  assert.equal(isLoopbackHttpOrigin('http://localhost.evil.com'), false)
  assert.equal(isLoopbackHttpOrigin('http://127.0.0.1.evil.com'), false)
  assert.equal(isLoopbackHttpOrigin('tauri://localhost'), false)
  assert.equal(isLoopbackHttpOrigin('null'), false)
  assert.equal(isLoopbackHttpOrigin('http://127.0.0.1'), true)
  assert.equal(isLoopbackHttpOrigin('http://127.13.9.1:9'), true)

  // Listed explicitly, and only then (D10).
  const listed = await serve(t, { allowedOrigins: ['tauri://localhost'] })
  assert.deepEqual(await tryUpgrade(listed.port, { headers, origin: 'tauri://localhost' }), { ok: true })
  assert.equal((await tryUpgrade(listed.port, { headers, origin: 'https://evil.com' })).ok, false)

  assert.deepEqual(rejections(s), ['bad_origin', 'bad_origin', 'bad_origin', 'bad_origin'])
  // The origin IS recorded — it is not a credential and it is what an operator
  // needs to see to know who is knocking.
  assert.equal(
    (JSON.parse(s.store.query({ type: 'control.rejected' })[0]?.payload ?? '{}') as { origin?: string })
      .origin,
    'https://evil.com',
  )
})

test('a path other than /v1 is refused before any credential check', async (t) => {
  const s = await serve(t)
  const headers = { Authorization: `Bearer ${TOKEN}` }

  for (const path of ['/', '/v2', '/v1/extra', '/V1']) {
    assert.equal((await tryUpgrade(s.port, { path, headers })).ok, false, path)
  }
  assert.deepEqual(rejections(s), ['bad_upgrade', 'bad_upgrade', 'bad_upgrade', 'bad_upgrade'])
})

// ── construction ───────────────────────────────────────────────────────────

test('refuses to start without a token', (t) => {
  const store = withStore(t)
  const base = { store, port: 0, maxPayloadBytes: 1_024 }

  // A throw, not a warning. There is no useful degraded version of a control
  // plane every process on the machine can drive.
  for (const token of [undefined, '', '   ']) {
    assert.throws(
      () => new ControlServer({ ...base, token }),
      (e: unknown) => e instanceof ConfigError && /not set/.test(e.message),
      JSON.stringify(token),
    )
  }
  assert.throws(() => assertTokenUsable(undefined), ConfigError)
})

test('refuses to start with a token shorter than 32 characters (after trim)', (t) => {
  const store = withStore(t)
  const base = { store, port: 0, maxPayloadBytes: 1_024 }

  assert.equal(MIN_TOKEN_LENGTH, 32)

  const thirtyOne = 'x'.repeat(31)
  assert.throws(
    () => new ControlServer({ ...base, token: thirtyOne }),
    (e: unknown) => e instanceof ConfigError && /31 characters after trimming/.test(e.message),
  )
  // Trimmed first: whitespace is not entropy.
  assert.throws(() => assertTokenUsable(`  ${thirtyOne}  `), ConfigError)

  const thirtyTwo = 'x'.repeat(32)
  const server = new ControlServer({ ...base, token: thirtyTwo })
  assert.ok(server instanceof ControlServer)
  assert.equal(assertTokenUsable(`  ${thirtyTwo}  `), thirtyTwo)
})

test('token is digested at boot and the raw value is not retained on the server object', async (t) => {
  const s = await serve(t)

  // Walk everything reachable by ordinary means: own properties at every
  // depth, plus the JSON form. A #private field is not reachable at all,
  // which is the point — but a future edit that stored it publicly would be.
  const seen = new Set<unknown>()
  const found: string[] = []
  const walk = (value: unknown, path: string, depth: number): void => {
    if (depth > 6 || value === null || seen.has(value)) return
    if (typeof value === 'string') {
      if (value.includes(TOKEN)) found.push(path)
      return
    }
    if (typeof value !== 'object' && typeof value !== 'function') return
    seen.add(value)
    for (const key of Object.getOwnPropertyNames(value)) {
      let child: unknown
      try {
        child = (value as Record<string, unknown>)[key]
      } catch {
        continue
      }
      walk(child, `${path}.${key}`, depth + 1)
    }
  }
  walk(s.server, 'server', 0)
  assert.deepEqual(found, [], 'the raw token is reachable from the server object')

  try {
    assert.equal(JSON.stringify(s.server).includes(TOKEN), false)
  } catch {
    // A circular server object cannot be serialised, which is fine.
  }

  // It IS digested, and the digest is what a comparison uses.
  assert.equal(digestToken(TOKEN).toString('hex'), createHash('sha256').update(TOKEN).digest('hex'))
  assert.equal(digestToken(TOKEN).length, 32)
  // And the working server still authenticates, so the digest is really in use.
  assert.deepEqual(await tryUpgrade(s.port, { headers: { Authorization: `Bearer ${TOKEN}` } }), {
    ok: true,
  })
})

test('rejected upgrades append control.rejected without the presented token', async (t) => {
  const s = await serve(t)

  await tryUpgrade(s.port, { headers: { Authorization: 'Bearer wrong-but-long-enough-to-look-real-0000' } })
  await tryUpgrade(s.port, { path: `${CONTROL_PATH}?token=${TOKEN}` })
  await tryUpgrade(s.port, { headers: { Authorization: `Bearer ${TOKEN}` }, origin: 'https://evil.com' })

  const rows = s.store.query({ type: 'control.rejected' })
  assert.equal(rows.length, 3)
  assert.deepEqual(rejections(s), ['bad_token', 'query_token', 'bad_origin'])

  for (const row of rows) {
    const payload = JSON.parse(row.payload) as Record<string, unknown>
    // Exactly the reason, and an origin when there was one. No token, no
    // prefix, no length — the log must not become the place a credential was
    // written down, and it cannot be rewritten later to remove one.
    assert.deepEqual(
      Object.keys(payload).sort().filter((k) => k !== 'origin'),
      ['reason', 'schemaVersion'],
    )
    assert.equal(row.payload.includes(TOKEN), false)
    assert.equal(row.payload.includes('wrong-but-long-enough'), false)
  }
})

// ── the measured `ws` ceiling ──────────────────────────────────────────────

test('an oversized frame closes with 1009 and does not end the process', async (t) => {
  // MEASURED against ws 8.21.3: an oversized frame raises RangeError
  // 'Max payload size exceeded' (code WS_ERR_UNSUPPORTED_MESSAGE_LENGTH,
  // status 1009) on the SERVER socket, the message handler is never called,
  // and an unhandled 'error' event would end the process. One frame from any
  // client would stop the daemon.
  const s = await serve(t, { maxPayloadBytes: 64 })

  const client = new WebSocket(`ws://${CONTROL_HOST}:${String(s.port)}${CONTROL_PATH}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  })
  client.on('error', () => undefined)
  await new Promise<void>((resolve) => client.on('open', () => resolve()))

  // 2x the protocol limit is the hard ceiling, so 400 bytes clears it.
  client.send('x'.repeat(400))
  const code = await new Promise<number>((resolve) => client.on('close', (c) => resolve(c)))
  assert.equal(code, 1009)

  // Still alive and still serving: the error handler is what makes that true.
  assert.deepEqual(await tryUpgrade(s.port, { headers: { Authorization: `Bearer ${TOKEN}` } }), {
    ok: true,
  })
  client.terminate()
})

test('a frame between 1x and 2x the protocol limit reaches the server, so the polite reply stays possible', async (t) => {
  // The ws ceiling is 2x on purpose. At 1x an oversized frame would be closed
  // by the transport before any handler ran, and the protocol's
  // payload_too_large reply (T30) could never be produced at all.
  const received: number[] = []
  const store = withStore(t)
  const server = new ControlServer({
    store,
    port: 0,
    token: TOKEN,
    maxPayloadBytes: 64,
    onConnection: ({ socket }) => {
      socket.on('message', (data: Buffer) => received.push(data.length))
    },
  })
  const port = await server.listen()
  t.after(() => server.close())

  const client = new WebSocket(`ws://${CONTROL_HOST}:${String(port)}${CONTROL_PATH}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  })
  client.on('error', () => undefined)
  await new Promise<void>((resolve) => client.on('open', () => resolve()))

  let closed = false
  client.on('close', () => {
    closed = true
  })

  // 100 bytes: over the protocol's 64 but under the transport's 128.
  client.send('y'.repeat(100))
  await new Promise<void>((resolve) => setTimeout(resolve, 50))

  assert.deepEqual(received, [100], 'the frame must reach the dispatcher to be answered politely')
  assert.equal(closed, false, 'the transport must not close a frame the protocol can answer')
  client.terminate()
})
