// T31 — the CLI console.
//
// In process, no child processes, no real sockets. `runCli` takes its IO and
// its environment as arguments, so a test can watch every environment read and
// every byte written.
//
// The falsifiers:
//
//   Put the token in the URL and it lands in process lists, shell history and
//   proxy logs. The server refuses it (T29) — but the reason it cannot happen
//   is that the client has nowhere to put it.
//   Let verify-chain read AOS_CONTROL_TOKEN and a command that needs no
//   credential touches one anyway; a process that never reads a secret cannot
//   leak it.
//   Open the DB writable and an investigation into a broken chain can become a
//   write to it.
//   Guess at an id instead of dispatching on its prefix, and `approve` on a
//   hold silently approves a tool call, or a promotion is granted by the
//   command meant for tool calls (invariant 6).
//   Print a stored payload without redacting it again and a secret the mask
//   learned AFTER the event was written is shown in full.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { closeVerified, withStore, withStoreUnverified } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'
import { tamper } from './helpers/tamper.js'
import { SecretMask } from '../src/events/redact.js'
import { EventStore } from '../src/events/store.js'
import {
  CLI_COMMANDS,
  EVENTS_DB_FILE,
  runCli,
  SOCKET_COMMANDS,
  type CliIo,
} from '../src/cli/index.js'
import type { ControlClient, EventNotice } from '../src/cli/client.js'

const TOKEN = 'k'.repeat(40)

function kernelYaml(dataDir: string, mountRoot: string): string {
  return `
version: 1
dataDir: ${dataDir}
control:
  port: 7777
  allowedOrigins: []
mcp:
  servers:
    pmmcp:
      url: http://127.0.0.1:8123/mcp
sandbox:
  image: aos/worker:0.0.1
  domains:
    trusted: { dockerHost: "unix:///tmp/t.sock", network: aos-internal, mountRoot: ${mountRoot} }
    hostile: { dockerHost: "unix:///tmp/h.sock", network: aos-hostile, mountRoot: ${mountRoot} }
`
}

interface Harness {
  readonly io: CliIo
  readonly out: string[]
  readonly errs: string[]
  readonly calls: { cmd: string; params: Record<string, unknown> }[]
  readonly envReads: string[]
  readonly connects: { port: number; token: string }[]
  readonly dataDir: string
  readonly configPath: string
  emit(event: EventNotice): void
  /**
   * Emit `event` once `cmd` has been called, on the macrotask after its reply.
   *
   * Not a timer. `run` subscribes before it calls run.start and only learns
   * which runId is its own from the reply, so the event must land after that
   * continuation — a 5 ms timer is a race, and an unref'd one lets the loop
   * drain while the CLI is still waiting.
   */
  emitAfter(cmd: string, event: EventNotice): void
  /** Queue the reply for the next call to `cmd`. */
  reply(cmd: string, result: unknown): void
  fail(cmd: string, code: string, message: string): void
}

function harness(
  t: TestContext,
  options: { env?: Record<string, string | undefined>; noConnect?: boolean } = {},
): Harness {
  const root = tmpdir(t)
  const dataDir = join(root, 'data')
  const mountRoot = join(root, 'work')
  mkdirSync(dataDir, { recursive: true })
  mkdirSync(mountRoot, { recursive: true })

  const cwd = join(root, 'repo')
  mkdirSync(join(cwd, 'config'), { recursive: true })
  const configPath = join(cwd, 'config', 'kernel.yaml')
  writeFileSync(configPath, kernelYaml(dataDir, mountRoot))

  const out: string[] = []
  const errs: string[] = []
  const calls: Harness['calls'] = []
  const envReads: string[] = []
  const connects: Harness['connects'] = []
  const listeners: ((event: EventNotice) => void)[] = []
  const replies = new Map<string, unknown[]>()
  const failures = new Map<string, { code: string; message: string }>()
  const afterCall = new Map<string, EventNotice[]>()

  const fanout = (event: EventNotice): void => {
    for (const listener of listeners) listener(event)
  }

  const base: Record<string, string | undefined> = {
    AOS_CONTROL_TOKEN: TOKEN,
    ...options.env,
  }
  // A Proxy over the environment, so the test can see EVERY key the CLI reads.
  const env = new Proxy(base, {
    get(target, key) {
      if (typeof key === 'string') envReads.push(key)
      return target[key as string]
    },
    has(target, key) {
      if (typeof key === 'string') envReads.push(key)
      return key in target
    },
  }) as Record<string, string | undefined>

  const io: CliIo = {
    out: (line) => out.push(line),
    err: (line) => errs.push(line),
    env,
    cwd,
    ...(options.noConnect === true
      ? {}
      : {
          connect: (opts) => {
            connects.push({ port: opts.port, token: opts.token })
            const client: ControlClient = {
              hello: { kernel: { version: '0.0.1' }, status: {} },
              onEvent: (listener) => listeners.push(listener),
              call: (cmd, params = {}) => {
                calls.push({ cmd, params })
                const failure = failures.get(cmd)
                if (failure !== undefined) {
                  return Promise.reject(
                    Object.assign(new Error(failure.message), {
                      name: 'ControlCallError',
                      code: failure.code,
                    }),
                  )
                }
                // Scheduled, not fired: the caller's `await` continuation is
                // a microtask and must run first, so that `mine` is set before
                // any event arrives.
                for (const event of afterCall.get(cmd) ?? []) setImmediate(() => fanout(event))
                afterCall.delete(cmd)
                const queued = replies.get(cmd)
                return Promise.resolve(queued === undefined || queued.length === 0 ? {} : queued.shift())
              },
              close: () => undefined,
            }
            return Promise.resolve(client)
          },
        }),
  }

  return {
    io,
    out,
    errs,
    calls,
    envReads,
    connects,
    dataDir,
    configPath,
    emit: fanout,
    emitAfter: (cmd, event) => {
      const queued = afterCall.get(cmd) ?? []
      queued.push(event)
      afterCall.set(cmd, queued)
    },
    reply: (cmd, result) => {
      const queued = replies.get(cmd) ?? []
      queued.push(result)
      replies.set(cmd, queued)
    },
    fail: (cmd, code, message) => failures.set(cmd, { code, message }),
  }
}

/** Seed the daemon-less commands' database. */
function seedDb(t: TestContext, dataDir: string, extra?: (store: EventStore) => void): string {
  const path = join(dataDir, EVENTS_DB_FILE)
  const store = withStore(t, { path })
  store.append({ type: 'kernel.booted', payload: { schemaVersion: 1, version: '0.0.1', degraded: [] } })
  extra?.(store)
  return path
}

// ── parsing ────────────────────────────────────────────────────────────────

test('parses each of the nine commands; unknown prints usage and exits 2', async (t) => {
  assert.deepEqual([...CLI_COMMANDS], [
    'agents', 'verify-chain', 'search', 'probe', 'run', 'kill', 'approve', 'deny', 'approvals',
  ])

  const h = harness(t)
  seedDb(t, h.dataDir)
  h.reply('approvals.list', { approvals: [], holds: [] })

  // Each of the nine reaches its own handler rather than usage.
  const args: Record<string, string[]> = {
    agents: ['agents'],
    'verify-chain': ['verify-chain'],
    search: ['search'],
    probe: ['probe', 'anthropic/claude-sonnet-5'],
    run: ['run', 'ceo', 'do the thing'],
    kill: ['kill', 'run_1'],
    approve: ['approve', 'apr_nope'],
    deny: ['deny', 'apr_nope'],
    approvals: ['approvals'],
  }
  for (const [name, argv] of Object.entries(args)) {
    const fresh = harness(t)
    seedDb(t, fresh.dataDir)
    fresh.reply('approvals.list', { approvals: [], holds: [] })
    fresh.reply('run.kill', { runId: 'run_1', status: 'finished' })
    fresh.reply('model.probe', { toolCalling: true })
    fresh.reply('run.start', { runId: 'run_1' })
    if (name === 'run') {
      fresh.emitAfter('run.start', { type: 'run.finished', payload: { runId: 'run_1', status: 'ok' } })
    }
    const code = await runCli([...argv, '--config', fresh.configPath], fresh.io)
    assert.notEqual(code, 2, `${name} was treated as a usage error: ${fresh.errs.join(' | ')}`)
  }

  for (const argv of [[], ['secrets'], ['verifychain']]) {
    const fresh = harness(t)
    const code = await runCli([...argv, '--config', fresh.configPath], fresh.io)
    assert.equal(code, 2, JSON.stringify(argv))
    assert.ok(fresh.errs.join('\n').includes('aos — Agentic OS console'), 'usage was not printed')
  }

  // An unknown flag is a usage error too: a typo must not be silently ignored.
  const badFlag = harness(t)
  assert.equal(await runCli(['agents', '--includearchived'], badFlag.io), 2)
})

// ── the daemon-less pair ───────────────────────────────────────────────────

test('verify-chain runs read-only and reports ok / at+reason on a tampered copy', async (t) => {
  const h = harness(t)
  const path = join(h.dataDir, EVENTS_DB_FILE)
  const store2 = withStore(t, { path })
  store2.append({ type: 'kernel.booted', payload: { schemaVersion: 1, version: '0.0.1', degraded: [] } })
  store2.append({ type: 'kernel.shutdown', payload: { schemaVersion: 1, reason: 'requested', uptimeMs: 1 } })

  assert.equal(await runCli(['verify-chain', '--config', h.configPath], h.io), 0)
  assert.match(h.out[0] ?? '', /^ok\t2 events\thead /)

  // A tampered log reports where and why, rather than merely failing. The
  // store is closed first: the tamper helper drops the append-only triggers,
  // which is only possible with file access.
  closeVerified(store2)
  const broken = tamper(path)
  broken.setPayload(2, '{"schemaVersion":1,"reason":"edited"}')
  // Put the triggers back: a log with them MISSING is refused before
  // verifyChain runs at all, which is a different (and also correct) failure.
  // Both are asserted, because an operator will meet both.
  broken.restoreTriggers()
  broken.close()

  const b = harness(t)
  const work2 = join(tmpdir(t), 'work2')
  mkdirSync(work2, { recursive: true })
  writeFileSync(b.configPath, kernelYaml(h.dataDir, work2))
  const code = await runCli(['verify-chain', '--config', b.configPath], b.io)
  assert.equal(code, 1)
  assert.match(b.errs.join('\n'), /broken at seq 2/)

  // Read-only: the command that investigates a broken chain cannot write to it.
  const reopened = withStoreUnverified(t, { path, readOnly: true })
  assert.equal(reopened.query().length, 2, 'verify-chain changed the log')
  assert.match(JSON.parse(reopened.query()[1]?.payload ?? '{}').reason, /edited/)

  // And a log whose append-only triggers were removed is refused before the
  // chain is even walked: the triggers going missing IS the tamper signal.
  const noTriggers = tamper(path)
  noTriggers.close()
  const n = harness(t)
  const work3 = join(tmpdir(t), 'work-nt')
  mkdirSync(work3, { recursive: true })
  writeFileSync(n.configPath, kernelYaml(h.dataDir, work3))
  assert.equal(await runCli(['verify-chain', '--config', n.configPath], n.io), 1)
  assert.match(n.errs.join('\n'), /trigger .* is missing/)

  // Read-only, observed rather than asserted about: a read-only open cannot
  // run createSchema, so a data directory with NO log is a refusal. Opened
  // writable, the same command would CREATE the log it was asked to check and
  // report "ok, 0 events" — an operator pointed at the wrong dataDir would be
  // told the chain is fine. (chmod is not the test: it proves nothing when the
  // daemon runs as a user who can write the file anyway.)
  const empty = harness(t)
  assert.equal(await runCli(['verify-chain', '--config', empty.configPath], empty.io), 1)
  assert.match(empty.errs.join('\n'), /unable to open database file/)
  assert.equal(existsSync(join(empty.dataDir, EVENTS_DB_FILE)), false, 'verify-chain created a log')
})

test('verify-chain honours AOS_DATA_DIR and never reads AOS_CONTROL_TOKEN', async (t) => {
  const elsewhere = join(tmpdir(t), 'elsewhere')
  mkdirSync(elsewhere, { recursive: true })
  const store = withStore(t, { path: join(elsewhere, EVENTS_DB_FILE) })
  store.append({ type: 'kernel.booted', payload: { schemaVersion: 1, version: '0.0.1', degraded: [] } })

  const h = harness(t, { env: { AOS_DATA_DIR: elsewhere } })
  // The config's own dataDir has NO database, so finding one proves the
  // override won.
  assert.equal(await runCli(['verify-chain', '--config', h.configPath], h.io), 0)
  assert.match(h.out[0] ?? '', /^ok\t1 events/)

  // A command that needs no credential must not touch one. A process that
  // never reads a secret cannot leak it — in a log line, a crash dump or an
  // error message.
  assert.equal(h.envReads.includes('AOS_CONTROL_TOKEN'), false, `env reads: ${h.envReads.join(', ')}`)
  assert.ok(h.envReads.includes('AOS_DATA_DIR'))
  assert.deepEqual(h.connects, [], 'verify-chain opened a socket')
})

test('search --type --run --text never prints a registered mask value', async (t) => {
  SecretMask.clear()
  const h = harness(t)
  // Written BEFORE the mask knows the value, which is the realistic case: the
  // broker resolves a credential later in the session, and an operator greps
  // old events afterwards.
  const value = 'opaque-vault-value-8f3b91c07d5e'
  seedDb(t, h.dataDir, (store) => {
    store.append({
      type: 'llm.request',
      runId: 'run_1',
      payload: { schemaVersion: 1, ref: 'anthropic/x', attempt: 1, prompt: `auth ${value}`, tools: [] },
    })
    store.append({
      type: 'llm.response',
      runId: 'run_2',
      payload: {
        schemaVersion: 1, ref: 'anthropic/x', attempt: 1, content: 'fine',
        finish: 'stop', inputTokens: 1, outputTokens: 1, costMicroUsd: 1, durationMs: 1,
      },
    })
  })

  // The stored bytes really do contain it, so the assertion below is about the
  // CLI's own output-time pass and not about the store's write-time one.
  const raw = withStoreUnverified(t, { path: join(h.dataDir, EVENTS_DB_FILE), readOnly: true })
  assert.ok(JSON.stringify(raw.query()).includes(value), 'the fixture is not exercising output redaction')

  SecretMask.register(value)
  assert.equal(await runCli(['search', '--config', h.configPath], h.io), 0)
  assert.equal(h.out.join('\n').includes(value), false, 'search printed a registered secret')
  assert.ok(h.out.join('\n').includes('[REDACTED]'))

  // The filters narrow rather than widen.
  const byType = harness(t)
  writeFileSync(byType.configPath, kernelYaml(h.dataDir, join(tmpdir(t), 'work3')))
  mkdirSync(join(tmpdir(t), 'work3'), { recursive: true })
  assert.equal(await runCli(['search', '--type', 'llm.response', '--config', byType.configPath], byType.io), 0)
  assert.equal(byType.out.length, 1)
  assert.ok(byType.out[0]?.includes('llm.response'))

  const byRun = harness(t)
  writeFileSync(byRun.configPath, kernelYaml(h.dataDir, join(tmpdir(t), 'work4')))
  mkdirSync(join(tmpdir(t), 'work4'), { recursive: true })
  assert.equal(await runCli(['search', '--run', 'run_2', '--config', byRun.configPath], byRun.io), 0)
  assert.equal(byRun.out.length, 1)

  const byText = harness(t)
  writeFileSync(byText.configPath, kernelYaml(h.dataDir, join(tmpdir(t), 'work5')))
  mkdirSync(join(tmpdir(t), 'work5'), { recursive: true })
  assert.equal(await runCli(['search', '--text', 'no-such-text', '--config', byText.configPath], byText.io), 0)
  assert.deepEqual(byText.out, [])

  // Read-only, on the same terms as verify-chain: search is an investigation
  // too, and an investigation must not be able to become a write. A read-only
  // open cannot run createSchema, so a dataDir with no log is a refusal rather
  // than a freshly created empty log reported as zero results.
  const empty = harness(t)
  assert.equal(await runCli(['search', '--config', empty.configPath], empty.io), 1)
  assert.match(empty.errs.join('\n'), /unable to open database file/)
  assert.equal(existsSync(join(empty.dataDir, EVENTS_DB_FILE)), false, 'search created a log')
})

// ── socket commands ────────────────────────────────────────────────────────

test('run prints the runId and exits with the run status', async (t) => {
  const ok = harness(t)
  ok.reply('run.start', { runId: 'run_7' })
  ok.emitAfter('run.start', { type: 'run.finished', payload: { runId: 'run_7', status: 'ok' } })
  assert.equal(await runCli(['run', 'ceo', 'do', 'the', 'thing', '--config', ok.configPath], ok.io), 0)
  assert.equal(ok.out[0], 'run_7')
  assert.match(ok.out[1] ?? '', /^run_7\tok$/)
  assert.deepEqual(ok.calls[0], { cmd: 'run.start', params: { agentId: 'ceo', input: 'do the thing' } })

  // A killed run is a non-zero exit, so a script notices.
  const killed = harness(t)
  killed.reply('run.start', { runId: 'run_8' })
  killed.emitAfter('run.start', {
    type: 'run.finished',
    payload: { runId: 'run_8', status: 'killed', reason: 'wallclock' },
  })
  assert.equal(await runCli(['run', 'ceo', 'go', '--config', killed.configPath], killed.io), 1)
  assert.match(killed.out[1] ?? '', /^run_8\tkilled\twallclock$/)

  // An event for a DIFFERENT run must not settle this one.
  const other = harness(t)
  other.reply('run.start', { runId: 'run_9' })
  other.emitAfter('run.start', { type: 'run.finished', payload: { runId: 'run_other', status: 'ok' } })
  other.emitAfter('run.start', { type: 'run.finished', payload: { runId: 'run_9', status: 'error', reason: 'boom' } })
  assert.equal(await runCli(['run', 'ceo', 'go', '--config', other.configPath], other.io), 1)
  assert.match(other.out[1] ?? '', /^run_9\terror\tboom$/)
})

test('approve/deny/approvals/kill/probe round-trip', async (t) => {
  const h = harness(t)
  h.reply('approvals.list', {
    approvals: [
      { approvalId: 'apr_1', kind: 'tool', runId: 'run_1', toolRef: 'pmmcp.remember', requestedAt: 'a', expiresAt: 'b' },
    ],
    holds: [{ holdId: 'hold_1', runId: 'run_1', toolRef: 'pmmcp.recall', heldAt: 'c' }],
  })
  assert.equal(await runCli(['approvals', '--config', h.configPath], h.io), 0)
  assert.equal(h.out.length, 2)
  assert.ok(h.out[0]?.startsWith('apr_1\ttool\tpmmcp.remember'))
  assert.ok(h.out[1]?.startsWith('hold_1\thold\tpmmcp.recall'))

  const a = harness(t)
  a.reply('approvals.list', {
    approvals: [{ approvalId: 'apr_1', kind: 'tool', requestedAt: 'a', expiresAt: 'b' }],
    holds: [],
  })
  assert.equal(await runCli(['approve', 'apr_1', '--config', a.configPath], a.io), 0)
  assert.deepEqual(a.calls.map((c) => c.cmd), ['approvals.list', 'approval.approve'])

  const d = harness(t)
  d.reply('approvals.list', {
    approvals: [{ approvalId: 'apr_1', kind: 'tool', requestedAt: 'a', expiresAt: 'b' }],
    holds: [],
  })
  assert.equal(await runCli(['deny', 'apr_1', '--reason', 'no thanks', '--config', d.configPath], d.io), 0)
  assert.deepEqual(d.calls[1], { cmd: 'approval.deny', params: { approvalId: 'apr_1', reason: 'no thanks' } })

  const k = harness(t)
  k.reply('run.kill', { runId: 'run_1', status: 'finished' })
  assert.equal(await runCli(['kill', 'run_1', '--reason', 'enough', '--config', k.configPath], k.io), 0)
  assert.deepEqual(k.calls[0], { cmd: 'run.kill', params: { runId: 'run_1', reason: 'enough' } })

  const p = harness(t)
  p.reply('model.probe', { toolCalling: true })
  assert.equal(await runCli(['probe', 'anthropic/claude-sonnet-5', '--config', p.configPath], p.io), 0)
  // A model that cannot call tools is a non-zero exit: the answer is the point.
  const pf = harness(t)
  pf.reply('model.probe', { toolCalling: false, reason: 'made no tool call' })
  assert.equal(await runCli(['probe', 'x/y', '--config', pf.configPath], pf.io), 1)

  // An id that is neither shape, and one that is not pending.
  const nf = harness(t)
  assert.equal(await runCli(['approve', 'whatever', '--config', nf.configPath], nf.io), 1)
  assert.match(nf.errs.join('\n'), /not_found/)
  assert.deepEqual(nf.connects, [], 'a malformed id must not open a socket')

  const gone = harness(t)
  gone.reply('approvals.list', { approvals: [], holds: [] })
  assert.equal(await runCli(['approve', 'apr_gone', '--config', gone.configPath], gone.io), 1)
  assert.match(gone.errs.join('\n'), /not_found/)
})

test('approve on a hold id calls quarantine.release', async (t) => {
  const h = harness(t)
  h.reply('quarantine.release', { holdId: 'hold_1', released: true, runTainted: true })

  assert.equal(await runCli(['approve', 'hold_1', '--config', h.configPath], h.io), 0)
  // Dispatched on the PREFIX. Guessing would let `approve` on a hold silently
  // approve a tool call instead.
  assert.deepEqual(h.calls, [{ cmd: 'quarantine.release', params: { holdId: 'hold_1' } }])
  assert.equal(h.calls.some((c) => c.cmd === 'approval.approve'), false)
  assert.match(h.out[0] ?? '', /^hold_1\treleased\trunTainted=true$/)
})

test('approve on a promotion id calls agent.promote, never approval.approve', async (t) => {
  const h = harness(t)
  h.reply('approvals.list', {
    approvals: [{ approvalId: 'apr_p', kind: 'promotion', agentId: 'scout-1', requestedAt: 'a', expiresAt: 'b' }],
    holds: [],
  })
  h.reply('agent.promote', { agentId: 'scout-1', kind: 'standard' })

  assert.equal(await runCli(['approve', 'apr_p', '--config', h.configPath], h.io), 0)
  // Invariant 6: promotion has exactly one command, and the CLI routes to it
  // rather than to the command meant for tool calls.
  assert.deepEqual(h.calls.map((c) => c.cmd), ['approvals.list', 'agent.promote'])
  assert.equal(h.calls.some((c) => c.cmd === 'approval.approve'), false)
  assert.match(h.out[0] ?? '', /^apr_p\tpromoted\tscout-1$/)

  // Denying a promotion needs no promotion path, so it takes the ordinary one.
  const d = harness(t)
  d.reply('approvals.list', {
    approvals: [{ approvalId: 'apr_p', kind: 'promotion', agentId: 'scout-1', requestedAt: 'a', expiresAt: 'b' }],
    holds: [],
  })
  assert.equal(await runCli(['deny', 'apr_p', '--config', d.configPath], d.io), 0)
  assert.deepEqual(d.calls.map((c) => c.cmd), ['approvals.list', 'approval.deny'])
})

test('deny on a hold id is refused with usage', async (t) => {
  const h = harness(t)

  // A hold is released or left held. There is no denied state, and inventing
  // one would suggest the output had been discarded when it is still in the log.
  assert.equal(await runCli(['deny', 'hold_1', '--config', h.configPath], h.io), 2)
  assert.match(h.errs.join('\n'), /cannot be denied/)
  assert.deepEqual(h.calls, [])
  assert.deepEqual(h.connects, [], 'a refused command must not open a socket')
})

// ── the token ──────────────────────────────────────────────────────────────

test("token is sent only in the Authorization header: the server's recorded upgrade URL has no query string", async (t) => {
  // The client is asserted at its own seam: it is handed a port and a token
  // and returns a connection. There is no option, branch or fallback that
  // could put the token anywhere but the header — see src/cli/client.ts.
  const h = harness(t)
  h.reply('approvals.list', { approvals: [], holds: [] })
  assert.equal(await runCli(['approvals', '--config', h.configPath], h.io), 0)

  assert.deepEqual(h.connects, [{ port: 7777, token: TOKEN }])
  // Nothing the CLI passes to the client is a URL, so there is no place for a
  // query string to come from.
  for (const key of Object.keys(h.connects[0] ?? {})) {
    assert.equal(/url|query|search/i.test(key), false, key)
  }

  // And the client source has no query-parameter path at all. A grep is the
  // honest test here: the guarantee is structural, not behavioural.
  const { readFileSync } = await import('node:fs')
  const source = readFileSync('src/cli/client.ts', 'utf8')
  assert.equal(/searchParams|\?token=|access_token|URLSearchParams/.test(source), false)
  assert.ok(source.includes('Authorization: `Bearer ${options.token}`'))
})

test('without AOS_CONTROL_TOKEN the client never connects', async (t) => {
  for (const env of [{ AOS_CONTROL_TOKEN: undefined }, { AOS_CONTROL_TOKEN: '' }, { AOS_CONTROL_TOKEN: '   ' }]) {
    const h = harness(t, { env })
    const code = await runCli(['approvals', '--config', h.configPath], h.io)
    assert.equal(code, 1)
    assert.match(h.errs.join('\n'), /AOS_CONTROL_TOKEN is not set/)
    // No socket, no call. A missing token is a refusal before the wire.
    assert.deepEqual(h.connects, [])
    assert.deepEqual(h.calls, [])
  }

  // Every socket command needs it; neither daemon-less one does.
  assert.deepEqual([...SOCKET_COMMANDS].sort(), [
    'agents', 'approvals', 'approve', 'deny', 'kill', 'probe', 'run',
  ])
  for (const command of ['verify-chain', 'search']) {
    assert.equal(SOCKET_COMMANDS.includes(command as never), false, command)
  }
})
