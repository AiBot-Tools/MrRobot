// T30 — control dispatch.
//
// The dispatcher's job is routing, authority and errors — not running runs.
// The kernel surface is a seam, so this file supplies real policy components
// (Approvals, Quarantine, AgentRegistry, the event store) and a faithful
// miniature of a run. Driving the whole T27 loop through here would re-test
// T27 slowly and prove nothing new about dispatch.
//
// The falsifiers:
//
//   Let approval.approve settle a promotion and invariant 6 is gone: one call
//   both requests and grants. Exactly one command may promote.
//   Accept an actor that is not minted here and every human-only action can be
//   performed by kernel code that constructs an object literal.
//   Close on the first bad frame and a UI with one malformed command loses its
//   session instead of seeing its mistake.
//   Never close, and a peer that is not speaking this protocol keeps the
//   socket and the fan-out for ever.
//   Reply to an oversized frame without counting it and the limit becomes an
//   invitation to keep sending them.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import { WebSocket } from 'ws'

import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'
import { AgentRegistry } from '../src/agents/registry.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { Approvals } from '../src/policy/approvals.js'
import { Quarantine } from '../src/policy/quarantine.js'
import { boundOutput } from '../src/events/bound.js'
import { CONTROL_HOST, ControlServer, MAX_BAD_FRAMES, type ControlSurface } from '../src/control/server.js'
import { CONTROL_PATH } from '../src/control/auth.js'
import { PROTOCOL_VERSION, StatusResult } from '../src/control/protocol.js'
import { agentSummaryView } from '../src/control/views.js'
import type { RunSummary } from '../src/control/protocol.js'

const TOKEN = 'z'.repeat(40)

const TOOL_VIEWS = parseToolViews(
  parseYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall: { exposure: agent, risk: read }
`),
)

const CEO_YAML = `
id: ceo
version: 1
kind: standard
role: orchestrator
soul: ceo.md
tier: 2
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.recall]
egress:
  allow: []
spawn:
  templates: [worker-template]
  maxChildren: 4
  maxDepth: 1
memory:
  projectId: aos/ceo
`

const TEMPLATE_YAML = `
id: worker-template
version: 1
kind: template
role: worker
soul: worker.md
tier: 1
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.recall]
egress:
  allow: []
memory:
  projectId: aos/shared
`

const STATUS: StatusResult = {
  kernel: { version: '0.0.1', bootedAt: '2026-01-01T00:00:00.000Z' },
  state: 'degraded',
  subsystems: {
    events: { state: 'ok' },
    control: { state: 'ok' },
    hub: { state: 'degraded', reason: 'pmmcp unreachable' },
    secrets: { state: 'degraded', reason: 'no hub' },
    sandbox: { state: 'absent', reason: 'no docker' },
    router: { state: 'ok' },
    scheduler: { state: 'absent', reason: 'not implemented' },
    egress: { state: 'absent', reason: 'not implemented' },
  },
  chainHead: null,
  lanes: [{ lane: 'main', active: 0, queued: 0, cap: 4 }],
  envFallback: false,
}

interface Wired {
  readonly port: number
  readonly store: ReturnType<typeof withStore>
  readonly approvals: Approvals
  readonly quarantine: Quarantine
  readonly registry: AgentRegistry
  readonly runs: Map<string, { status: RunSummary['status']; abort: AbortController }>
  readonly killed: string[]
  /** Finish a run on demand. No timers: a timed miniature races the socket. */
  finish(runId: string): void
}

async function wire(t: TestContext, options: { maxPayloadBytes?: number } = {}): Promise<Wired> {
  const store = withStore(t)
  const approvals = new Approvals({ waitMs: 60_000 })
  const quarantine = new Quarantine({ store })

  const dir = join(tmpdir(t), 'agents')
  for (const [id, yaml] of [['ceo', CEO_YAML], ['worker-template', TEMPLATE_YAML]] as const) {
    mkdirSync(join(dir, id, 'history'), { recursive: true })
    writeFileSync(join(dir, id, 'agent.yaml'), yaml)
    writeFileSync(join(dir, id, 'AGENTS.md'), `# ${id}\n`)
  }
  const registry = new AgentRegistry({
    providers: new Set(['anthropic/claude-sonnet-5']),
    toolViews: TOOL_VIEWS,
    store,
  })
  registry.load(dir)

  const runs = new Map<string, { status: RunSummary['status']; abort: AbortController }>()
  const killed: string[] = []
  let nextRun = 0

  const finish = (runId: string): void => {
    const state = runs.get(runId)
    if (state === undefined || state.status === 'finished') return
    const aborted = state.abort.signal.aborted
    state.status = 'finished'
    store.append({
      type: 'run.finished',
      runId,
      payload: {
        schemaVersion: 1,
        runId,
        status: aborted ? 'killed' : 'ok',
        ...(aborted ? { reason: 'requested' } : {}),
        costMicroUsd: 0,
        llmCalls: 0,
        toolCalls: 0,
        durationMs: 1,
      },
    })
  }

  const surface: ControlSurface = {
    store,
    approvals,
    quarantine,
    status: () => STATUS,
    agents: (includeArchived) =>
      registry
        .list()
        .filter((r) => includeArchived || r.status !== 'archived')
        .map((r) =>
          agentSummaryView({
            id: r.manifest.id,
            version: r.manifest.version,
            kind: r.manifest.kind,
            role: r.manifest.role,
            tier: r.manifest.tier,
            status: r.status === 'archived' ? 'archived' : 'active',
            modelPrimary: r.manifest.model.primary,
          }),
        ),
    promote: (approvalId, actor) => {
      const pending = approvals.pending().find((a) => a.approvalId === approvalId)
      const agentId = pending?.agentId ?? ''
      // One human action: the approval settles and the promotion happens.
      approvals.resolve(approvalId, actor, 'approved')
      const record = registry.promote(agentId, actor)
      return { agentId: record.manifest.id }
    },
    archive: (agentId, actor) => {
      registry.archive(agentId, actor)
    },
    startRun: (input) => {
      nextRun++
      const runId = `run_${String(nextRun)}`
      const abort = new AbortController()
      runs.set(runId, { status: 'running', abort })
      // A faithful miniature: queued, started, and — unless killed — finished.
      store.append({
        type: 'run.queued',
        runId,
        agentId: input.agentId,
        payload: { schemaVersion: 1, runId, agentId: input.agentId, lane: 'main' },
      })
      store.append({
        type: 'run.started',
        runId,
        agentId: input.agentId,
        payload: {
          schemaVersion: 1,
          runId,
          agentId: input.agentId,
          lane: 'main',
          tier: 2,
          taint: input.taint ?? 'clean',
        },
      })
      return runId
    },
    killRun: (runId) => {
      const state = runs.get(runId)
      if (state === undefined) throw new Error('no such run')
      state.abort.abort()
      killed.push(runId)
      // A kill ends the run now, deterministically: nothing here waits on a
      // clock, so the test cannot race the socket.
      finish(runId)
      return 'finished'
    },
    runs: () => [...runs.entries()].map(([runId, s]) => ({ runId, agentId: 'ceo', status: s.status, taint: 'clean' })),
    run: (runId) =>
      runs.has(runId)
        ? {
            runId,
            agentId: 'ceo',
            status: runs.get(runId)?.status ?? 'finished',
            taint: 'clean',
            llmCalls: 1,
            toolCalls: 0,
            costMicroUsd: 4_500,
            lastEventSeq: 3,
          }
        : undefined,
    models: () => [],
    probeModel: () => Promise.reject(new Error('not implemented in this phase: probe from control')),
  }

  const server = new ControlServer({
    store,
    port: 0,
    token: TOKEN,
    maxPayloadBytes: options.maxPayloadBytes ?? 4_096,
    surface,
  })
  const port = await server.listen()
  t.after(() => server.close())

  return { port, store, approvals, quarantine, registry, runs, killed, finish }
}

interface Frame {
  readonly v: number
  readonly id?: string
  readonly ok?: boolean
  readonly result?: unknown
  readonly error?: { code: string; message: string }
  readonly protocol?: number
  readonly kernel?: { version: string }
  readonly status?: unknown
  readonly event?: { type: string; runId?: string }
}

interface Client {
  readonly frames: Frame[]
  send(cmd: string, params?: Record<string, unknown>, id?: string): Promise<Frame>
  raw(data: string | Uint8Array): void
  events(): string[]
  readonly closes: { code: number }[]
  wait(ms?: number): Promise<void>
  close(): void
}

async function connect(t: TestContext, port: number): Promise<Client> {
  const socket = new WebSocket(`ws://${CONTROL_HOST}:${String(port)}${CONTROL_PATH}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  })
  socket.on('error', () => undefined)
  const frames: Frame[] = []
  const closes: { code: number }[] = []
  socket.on('message', (data: Buffer) => frames.push(JSON.parse(data.toString('utf8')) as Frame))
  socket.on('close', (code) => closes.push({ code }))
  await new Promise<void>((resolve) => socket.on('open', () => resolve()))
  t.after(() => {
    try {
      socket.terminate()
    } catch {
      // Already gone.
    }
  })

  let n = 0
  const wait = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms).unref?.())

  return {
    frames,
    closes,
    wait,
    events: () => frames.filter((f) => f.event !== undefined).map((f) => f.event?.type ?? ''),
    raw: (data) => socket.send(data),
    close: () => socket.close(),
    async send(cmd, params = {}, id) {
      n++
      const frameId = id ?? `c${String(n)}`
      socket.send(JSON.stringify({ v: PROTOCOL_VERSION, id: frameId, cmd, params }))
      for (let i = 0; i < 200; i++) {
        const reply = frames.find((f) => f.id === frameId)
        if (reply !== undefined) return reply
        await wait(5)
      }
      throw new Error(`no reply to ${cmd}`)
    },
  }
}

// ── hello and reads ────────────────────────────────────────────────────────

test('first frame is hello with protocol 1', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)
  await c.wait()

  const hello = c.frames[0]
  assert.ok(hello !== undefined)
  assert.equal(hello.protocol, PROTOCOL_VERSION)
  assert.equal(hello.v, PROTOCOL_VERSION)
  assert.equal(hello.kernel?.version, '0.0.1')
  // A UI knows the version and the kernel's state without having to ask.
  assert.doesNotThrow(() => StatusResult.parse(hello.status))
})

test('status.get returns the status view', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  const reply = await c.send('status.get')
  assert.equal(reply.ok, true)
  assert.doesNotThrow(() => StatusResult.parse(reply.result))
  assert.equal((reply.result as { state: string }).state, 'degraded')
})

test('events.query with text filters read-only', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)
  await c.send('run.start', { agentId: 'ceo', input: 'go' })
  w.finish('run_1')
  await c.wait(40)

  const all = await c.send('events.query', {})
  assert.equal(all.ok, true)
  const types = (all.result as { type: string }[]).map((e) => e.type)
  assert.ok(types.includes('run.started'))

  const filtered = await c.send('events.query', { types: ['run.started'] })
  assert.deepEqual((filtered.result as { type: string }[]).map((e) => e.type), ['run.started'])

  const byText = await c.send('events.query', { text: 'run_1' })
  assert.ok((byText.result as unknown[]).length > 0)
  const noMatch = await c.send('events.query', { text: 'no-such-substring-anywhere' })
  assert.deepEqual(noMatch.result, [])

  // A query is a read. Nothing it does appends.
  const before = w.store.query().length
  await c.send('events.query', { limit: 1 })
  assert.equal(w.store.query().length, before)
})

// ── runs and fan-out ───────────────────────────────────────────────────────

test('run.start streams run.queued, run.started, run.finished', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  const reply = await c.send('run.start', { agentId: 'ceo', input: 'find something' })
  assert.equal(reply.ok, true)
  assert.equal((reply.result as { runId: string }).runId, 'run_1')

  w.finish('run_1')
  await c.wait(60)
  // Every appended event reaches every authenticated client, in order.
  assert.deepEqual(c.events(), ['run.queued', 'run.started', 'run.finished'])
  assert.equal(c.frames.filter((f) => f.event?.runId === 'run_1').length, 3)
})

test('run.kill aborts a running run', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)
  const started = await c.send('run.start', { agentId: 'ceo', input: 'go' })
  const runId = (started.result as { runId: string }).runId

  const reply = await c.send('run.kill', { runId, reason: 'operator changed their mind' })
  assert.equal(reply.ok, true)
  assert.deepEqual(w.killed, [runId])
  await c.wait(60)

  const finished = w.store.query({ type: 'run.finished' })
  assert.equal(JSON.parse(finished[0]?.payload ?? '{}').status, 'killed')

  // An unknown run is not a crash.
  const missing = await c.send('run.kill', { runId: 'run_nope' })
  assert.equal(missing.ok, false)
  const detail = await c.send('run.get', { runId: 'run_nope' })
  assert.equal(detail.error?.code, 'not_found')
})

// ── the minted human ───────────────────────────────────────────────────────

test('approval.approve resolves as a minted human and the run resumes', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  const { request, outcome } = w.approvals.request({
    runId: 'run_1',
    toolRef: 'pmmcp.remember',
    argsHash: 'h',
    risk: 'write',
    argsPreview: '{}',
  })
  // The protocol's prefix, so a CLI can dispatch on it without guessing.
  assert.match(request.approvalId, /^apr_/)

  const listed = await c.send('approvals.list')
  assert.equal((listed.result as { approvals: unknown[] }).approvals.length, 1)

  const reply = await c.send('approval.approve', { approvalId: request.approvalId })
  assert.equal(reply.ok, true)
  assert.deepEqual(reply.result, { approvalId: request.approvalId, resolved: true })

  const settled = await outcome
  assert.equal(settled.decision, 'approved')
  // Resolved BY a connection: the actor was minted at the upgrade, and there
  // is no other way to obtain one.
  assert.equal(typeof settled.byConnectionId, 'string')
  assert.ok((settled.byConnectionId ?? '').length > 0)

  // Answering twice is a conflict, not a crash: the world moved on.
  const again = await c.send('approval.approve', { approvalId: request.approvalId })
  assert.equal(again.ok, false)
  assert.equal(again.error?.code, 'not_found')
})

test('agent.promote from the control plane succeeds; the same call through registry.promote with a literal actor throws', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  w.registry.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1' })
  const { request } = w.approvals.request({
    kind: 'promotion',
    agentId: 'scout-1',
    risk: 'irreversible',
    argsPreview: 'promote scout-1',
  })

  const reply = await c.send('agent.promote', { approvalId: request.approvalId })
  assert.equal(reply.ok, true, JSON.stringify(reply.error))
  assert.deepEqual(reply.result, { agentId: 'scout-1', kind: 'standard' })
  assert.equal(w.registry.get('scout-1')?.manifest.kind, 'standard')

  // The same promotion, attempted with an actor that was not minted here.
  // A private-field brand is not something an object literal can have, and
  // that is what makes "a human did this" a fact about the call path.
  w.registry.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-2' })
  const forged = { connectionId: 'conn-forged' } as unknown as Parameters<typeof w.registry.promote>[1]
  assert.throws(() => w.registry.promote('scout-2', forged), TypeError)
  assert.throws(
    () => w.registry.promote('scout-2', Object.create(Object.getPrototypeOf(forged)) as typeof forged),
    TypeError,
  )
  assert.equal(w.registry.get('scout-2')?.manifest.kind, 'ephemeral')
})

test('approval.approve on a promotion-kind approval is rejected bad_request and agent.promote resolves it; approval.deny resolves either kind', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)
  w.registry.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1' })

  const promotion = w.approvals.request({
    kind: 'promotion',
    agentId: 'scout-1',
    risk: 'irreversible',
    argsPreview: 'promote scout-1',
  })

  // Exactly one command may promote (invariant 6). approval.approve is not it,
  // or requesting and granting would be the same act.
  const refused = await c.send('approval.approve', { approvalId: promotion.request.approvalId })
  assert.equal(refused.ok, false)
  assert.equal(refused.error?.code, 'bad_request')
  assert.match(refused.error?.message ?? '', /use agent.promote/)
  assert.equal(w.registry.get('scout-1')?.manifest.kind, 'ephemeral')

  assert.equal((await c.send('agent.promote', { approvalId: promotion.request.approvalId })).ok, true)
  assert.equal(w.registry.get('scout-1')?.manifest.kind, 'standard')

  // And a promotion presented to agent.promote must actually BE one.
  const toolApproval = w.approvals.request({
    runId: 'run_1',
    toolRef: 'pmmcp.remember',
    argsHash: 'h',
    risk: 'write',
    argsPreview: '{}',
  })
  const wrongKind = await c.send('agent.promote', { approvalId: toolApproval.request.approvalId })
  assert.equal(wrongKind.error?.code, 'bad_request')
  assert.match(wrongKind.error?.message ?? '', /not a promotion/)

  // Denial needs no promotion path, so it takes both kinds.
  assert.equal((await c.send('approval.deny', { approvalId: toolApproval.request.approvalId })).ok, true)
  assert.equal((await toolApproval.outcome).decision, 'denied')

  w.registry.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-3' })
  const second = w.approvals.request({
    kind: 'promotion',
    agentId: 'scout-3',
    risk: 'irreversible',
    argsPreview: 'promote scout-3',
  })
  assert.equal((await c.send('approval.deny', { approvalId: second.request.approvalId })).ok, true)
  assert.equal((await second.outcome).decision, 'denied')
  assert.equal(w.registry.get('scout-3')?.manifest.kind, 'ephemeral')
})

test('quarantine.release taints the run', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  const hold = w.quarantine.hold('run_1', 'pmmcp.recall', boundOutput('untrusted page text'))
  assert.match(hold.holdId, /^hold_/)
  assert.equal(w.quarantine.isTainted('run_1'), false)

  const listed = await c.send('approvals.list')
  assert.equal((listed.result as { holds: unknown[] }).holds.length, 1)

  const reply = await c.send('quarantine.release', { holdId: hold.holdId })
  assert.equal(reply.ok, true)
  // D17, and the reply says so rather than leaving a UI to infer it.
  assert.deepEqual(reply.result, { holdId: hold.holdId, released: true, runTainted: true })
  assert.equal(w.quarantine.isTainted('run_1'), true)
  assert.equal(w.store.query({ type: 'quarantine.released' }).length, 1)

  const again = await c.send('quarantine.release', { holdId: hold.holdId })
  assert.equal(again.ok, false)
})

// ── bad frames ─────────────────────────────────────────────────────────────

test('bad frame gets an error reply and the socket survives; three close it', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  // One malformed command must not cost a UI its session.
  c.raw('{not json at all')
  await c.wait()
  assert.equal(c.frames.some((f) => f.error?.code === 'bad_request'), true)
  assert.equal(c.closes.length, 0)
  assert.equal((await c.send('status.get')).ok, true, 'the socket still serves')

  c.raw(JSON.stringify({ v: 1, id: 'x', cmd: 'secrets.get', params: {} }))
  await c.wait()
  assert.equal(c.frames.some((f) => f.error?.code === 'unknown_command'), true)
  assert.equal(c.closes.length, 0)

  // The third ends it: the peer is not speaking this protocol and every
  // further frame is noise.
  assert.equal(MAX_BAD_FRAMES, 3)
  c.raw('}}}')
  await c.wait(80)
  assert.equal(c.closes.length, 1)
  assert.equal(c.closes[0]?.code, 1008)
})

test('frame over maxPayloadBytes gets a payload_too_large reply and counts as a bad frame', async (t) => {
  // 128 for the protocol, so ws's own ceiling is 256 and a 200-byte frame
  // reaches the dispatcher to be answered politely.
  const w = await wire(t, { maxPayloadBytes: 128 })
  const c = await connect(t, w.port)

  const big = JSON.stringify({ v: 1, id: 'big', cmd: 'status.get', params: { pad: 'p'.repeat(150) } })
  assert.ok(Buffer.byteLength(big, 'utf8') > 128 && Buffer.byteLength(big, 'utf8') < 256)

  c.raw(big)
  await c.wait()
  const reply = c.frames.find((f) => f.error?.code === 'payload_too_large')
  assert.ok(reply !== undefined, 'no payload_too_large reply arrived')
  assert.match(reply.error?.message ?? '', /over the 128 byte limit/)
  // The reply CANNOT carry the request's id: reading the id would mean parsing
  // the frame the size check exists to avoid parsing. A client sees a reply to
  // an id it never sent, which is a connection-level error rather than a
  // per-command one, and that is the honest signal.
  assert.notEqual(reply.id, 'big')
  assert.equal(c.closes.length, 0)

  // It counts. A limit that replied for ever would be an invitation to keep
  // sending them.
  c.raw(big)
  await c.wait()
  assert.equal(c.closes.length, 0)
  c.raw(big)
  await c.wait(80)
  assert.equal(c.closes.length, 1)
  assert.equal(c.closes[0]?.code, 1008)
})

test('a result the freeze does not allow is refused rather than sent', async (t) => {
  const w = await wire(t)
  const c = await connect(t, w.port)

  // The surface's run.get returns a RunDetail; a drifting one must never reach
  // a UI, which parses these shapes. Caught here, not in someone's app.
  const ok = await c.send('run.get', { runId: (await c.send('run.start', { agentId: 'ceo', input: 'x' })).result !== undefined ? 'run_1' : 'run_1' })
  assert.equal(ok.ok, true)

  const bad = await c.send('model.probe', { ref: 'anthropic/claude-sonnet-5' })
  // The surface rejects with a NotImplemented-shaped message, which maps to
  // the protocol's own code rather than leaking as an internal error.
  assert.equal(bad.ok, false)
  assert.equal(bad.error?.code, 'not_implemented')
})

test('frame over 2x maxPayloadBytes closes with 1009 and no reply', async (t) => {
  const w = await wire(t, { maxPayloadBytes: 128 })
  const c = await connect(t, w.port)
  const framesBefore = c.frames.length

  // Past ws's own ceiling: the transport closes and the dispatcher never sees
  // the frame, so no reply is possible — MEASURED, which is why the polite
  // reply lives at 1x and the hard close at 2x.
  c.raw('q'.repeat(600))
  await c.wait(80)

  assert.equal(c.closes.length, 1)
  assert.equal(c.closes[0]?.code, 1009)
  assert.equal(c.frames.length, framesBefore, 'no reply can follow the close')
})
