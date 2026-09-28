// T15 — agent manifests and the registry.
//
// Invariant 6 in code: an ephemeral agent cannot exceed its template, and
// promotion is a human action the CEO can only request. Every test here is an
// attempt to widen an agent's reach through a path that looks legitimate.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { mintHumanActor } from '../src/control/actor.js'
import { AgentRegistry } from '../src/agents/registry.js'
import { parseManifest } from '../src/agents/manifest.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import type { EventStore } from '../src/events/store.js'
import { ConfigError } from '../src/errors.js'
import { withStore } from './helpers/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const PROVIDERS = new Set(['anthropic/claude-sonnet-5', 'openrouter/moonshotai/kimi-k3'])

const TOOL_VIEWS = parseToolViews(
  parseYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall:
        exposure: agent
        namespaceArg: none
        risk: read
      remember:
        exposure: agent
        namespaceArg: none
        risk: write
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
  fallbacks: [openrouter/moonshotai/kimi-k3]
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
  allow: [docs.example.com]
memory:
  projectId: aos/shared
`

function agentsDir(t: Parameters<typeof withStore>[0], extra: Record<string, string> = {}): string {
  const dir = join(tmpdir(t), 'agents')
  const files: Record<string, string> = { ceo: CEO_YAML, 'worker-template': TEMPLATE_YAML, ...extra }
  for (const [id, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, id, 'history'), { recursive: true })
    writeFileSync(join(dir, id, 'agent.yaml'), yaml)
    writeFileSync(join(dir, id, 'AGENTS.md'), `# ${id}\n`)
  }
  return dir
}

/** The kernel ceilings a manifest may only lower. D30's defaults. */
const BUDGETS = {
  defaultRunMicroUsd: 2_000_000,
  defaultWallclockMs: 600_000,
  maxLlmCallsPerRun: 50,
  maxToolCallsPerRun: 100,
} as const

function registry(store: EventStore): AgentRegistry {
  return new AgentRegistry({ providers: PROVIDERS, toolViews: TOOL_VIEWS, store, budgets: BUDGETS })
}

test('loads ceo and worker-template fixtures and freezes records', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))

  const ceo = reg.get('ceo')
  assert.ok(ceo)
  assert.equal(ceo.manifest.role, 'orchestrator')
  assert.equal(ceo.manifest.tier, 2)
  assert.deepEqual(ceo.manifest.model.fallbacks, ['openrouter/moonshotai/kimi-k3'])
  assert.equal(reg.get('worker-template')?.manifest.kind, 'template')

  // Frozen: a run holding a record must not be able to edit its own reach.
  assert.equal(Object.isFrozen(ceo), true)
  assert.throws(() => {
    ;(ceo as { status: string }).status = 'archived'
  }, TypeError)

  assert.equal(store.query({ type: 'agent.registered' }).length, 2)
})

test('refuses an incomplete fallback entry instead of dropping it', (t) => {
  const store = withStore(t)
  const dir = agentsDir(t, {
    broken: CEO_YAML.replace('id: ceo', 'id: broken').replace(
      'fallbacks: [openrouter/moonshotai/kimi-k3]',
      'fallbacks: [openrouter/moonshotai/kimi-k3, ghost/not-configured]',
    ).replace('projectId: aos/ceo', 'projectId: aos/agent/broken'),
  })

  // Dropping the unknown ref would leave a shorter chain than the author
  // intended, with nothing anywhere saying so.
  assert.throws(() => registry(store).load(dir), /model ref ghost\/not-configured is not in providers.yaml/)
})

test('rejects a manifest whose tools.allow names a kernel-only or disabled tool', (t) => {
  const store = withStore(t)
  for (const ref of ['pmmcp.get_secret', 'pmmcp.coding_agent', 'pmmcp.brand_new_tool']) {
    const dir = agentsDir(t, {
      greedy: TEMPLATE_YAML.replace('id: worker-template', 'id: greedy')
        .replace('kind: template', 'kind: standard')
        .replace('allow: [pmmcp.recall]', `allow: [pmmcp.recall, ${ref}]`),
    })
    assert.throws(
      () => registry(store).load(dir),
      /A manifest cannot grant what the tool views withhold/,
      `${ref} must not be grantable by a manifest`,
    )
  }
})

test('accepts a runnable schedule and refuses one the scheduler could not run', () => {
  // Strictness is how a PRESENT feature stays honest. A cron expression the
  // scheduler cannot run must be refused here, at load, with the file named —
  // not accepted and then silently never fired, which is the failure an operator
  // has no way to see.
  assert.equal(
    parseManifest(parseYaml(`${TEMPLATE_YAML}\nschedule: "0 9 * * 1-5"\n`), 'agent.yaml').schedule,
    '0 9 * * 1-5',
  )
  assert.throws(
    () => parseManifest(parseYaml(`${TEMPLATE_YAML}\nschedule: "0 9 * * MON-FRI"\n`), 'agent.yaml'),
    /is a name; this parser takes numbers only/,
  )
  assert.throws(
    () => parseManifest(parseYaml(`${TEMPLATE_YAML}\nschedule: "@daily"\n`), 'agent.yaml'),
    // The quotes arrive backslash-escaped inside zod's serialised error, so the
    // pattern tolerates that. What matters is that the parser's own hint reaches
    // the manifest error: an operator is told what to write instead, in the file
    // that refused them.
    /macros like .+@daily.+ are not supported; write the five fields/,
  )
  // Any unknown key is refused too, so a typo cannot sit in the file looking
  // active.
  assert.throws(
    () => parseManifest(parseYaml(`${TEMPLATE_YAML}\ntoolz:\n  allow: []\n`), 'agent.yaml'),
    /is invalid/,
  )
})

test('spawn above template tier is rejected with agent.spawn.rejected', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))

  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1', tier: 3 }),
    /requested tier 3 exceeds template tier 1/,
  )
  // The refusal is recorded, so an attempt to widen is visible in the log.
  const rejected = store.query({ type: 'agent.spawn.rejected' })
  assert.equal(rejected.length, 1)
  assert.match(rejected[0]?.payload ?? '', /exceeds template tier/)
  assert.equal(reg.get('scout-1'), undefined)
})

test('spawn with egress outside the template is rejected', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))

  assert.throws(
    () =>
      reg.spawnEphemeral({
        templateId: 'worker-template',
        childId: 'scout-1',
        egressAllow: ['docs.example.com', 'exfil.example.net'],
      }),
    /egress exfil.example.net is not in the template's allow list/,
  )
  // Tools are clamped the same way.
  assert.throws(
    () =>
      reg.spawnEphemeral({
        templateId: 'worker-template',
        childId: 'scout-2',
        toolsAllow: ['pmmcp.recall', 'pmmcp.remember'],
      }),
    /tools pmmcp.remember are not in the template's allow list/,
  )
  assert.equal(store.query({ type: 'agent.spawn.rejected' }).length, 2)
})

test('a manifest filed under a directory that is not its id is refused, naming both', (t) => {
  // The directory is how an operator finds an agent and how history/ is kept
  // beside it. A worker-template manifest sitting in agents/scout/ would load
  // as worker-template while every edit went to the wrong folder.
  const store = withStore(t)
  const reg = registry(store)
  // `scout` sorts before `worker-template`, so the mismatch is met before the
  // real template's copy could make it a duplicate instead.
  assert.throws(
    () => reg.load(agentsDir(t, { scout: TEMPLATE_YAML })),
    /id "worker-template" does not match its directory "scout"/,
  )
  assert.equal(store.query({ type: 'agent.registered' }).length, 0, 'a refused fleet left registrations behind')
})

test('an id already registered by an earlier load is refused, not replaced', (t) => {
  // Within one load two directories cannot share a name, so the duplicate that
  // can actually happen is a second load naming an agent the first registered.
  // Replacing it would swap a live agent's manifest out from under its runs.
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))
  const before = reg.get('ceo')
  assert.throws(() => reg.load(agentsDir(t)), /duplicate agent id ceo/)
  assert.equal(reg.get('ceo'), before, 'the second load replaced the registered record')
  assert.equal(store.query({ type: 'agent.registered' }).length, 2)
})

test('an ephemeral agent may be spawned only from a template, and never over an existing id', (t) => {
  // Invariant 6 bounds an ephemeral agent by its TEMPLATE. Spawning from a
  // standing agent would copy an orchestrator's reach — kernel tools included —
  // into something the CEO minted; spawning onto an existing id would replace
  // that agent's record outright.
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))

  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'ceo', childId: 'scout-1' }),
    /spawn rejected: no template named ceo/,
  )
  assert.equal(reg.get('scout-1'), undefined)

  const ceo = reg.get('ceo')
  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'worker-template', childId: 'ceo' }),
    /spawn rejected: agent id ceo already exists/,
  )
  assert.equal(reg.get('ceo'), ceo, 'a spawn replaced the CEO')
  assert.equal(store.query({ type: 'agent.spawn.rejected' }).length, 2)
})

test('spawn within limits registers an ephemeral agent', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))

  const child = reg.spawnEphemeral({
    templateId: 'worker-template',
    childId: 'scout-1',
    parentRunId: 'run-1',
    tier: 0,
    egressAllow: [],
    toolsAllow: [],
  })

  // Narrower is allowed; the child took less than the template offered.
  assert.equal(child.manifest.kind, 'ephemeral')
  assert.equal(child.manifest.tier, 0)
  assert.deepEqual(child.manifest.egress.allow, [])
  assert.deepEqual(child.manifest.tools.allow, [])
  assert.equal(Object.isFrozen(child), true)

  // Defaulting inherits the template exactly, never more.
  const sibling = reg.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-2' })
  assert.equal(sibling.manifest.tier, 1)
  assert.deepEqual(sibling.manifest.egress.allow, ['docs.example.com'])
  assert.deepEqual(sibling.manifest.tools.allow, ['pmmcp.recall'])

  assert.equal(store.query({ type: 'agent.spawned' }).length, 2)
})

test('CEO promotion request creates a pending approval and changes nothing', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))
  const child = reg.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1' })

  reg.requestPromotion('scout-1', 'run-1', 'it did well on three tasks')

  const requests = store.query({ type: 'agent.promotion.requested' })
  assert.equal(requests.length, 1)
  assert.match(requests[0]?.payload ?? '', /"requestedByRunId":"run-1"/)

  // Asking is not receiving: the agent is exactly as it was.
  const after = reg.get('scout-1')
  assert.equal(after?.manifest.kind, 'ephemeral')
  assert.equal(after?.manifest.version, child.manifest.version)
  assert.equal(store.query({ type: 'agent.promoted' }).length, 0)
})

test('promote with a non-human or literal actor throws', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))
  reg.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1' })

  for (const forgery of [{ kind: 'human' }, { connectionId: 'conn-1' }, null, 'conn-1']) {
    assert.throws(() => reg.promote('scout-1', forgery as never), /requires a human/)
    assert.throws(() => reg.archive('scout-1', forgery as never), /requires a human/)
  }
  assert.equal(reg.get('scout-1')?.manifest.kind, 'ephemeral')
  assert.equal(store.query({ type: 'agent.promoted' }).length, 0)
})

test('promote by a minted HumanActor emits agent.promoted', (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))
  reg.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1' })

  const promoted = reg.promote('scout-1', mintHumanActor('conn-1'))
  assert.equal(promoted.manifest.kind, 'standard')
  assert.equal(promoted.manifest.version, 2)

  const events = store.query({ type: 'agent.promoted' })
  assert.equal(events.length, 1)
  assert.match(events[0]?.payload ?? '', /"fromVersion":1/)
  assert.match(events[0]?.payload ?? '', /"toVersion":2/)
  assert.match(events[0]?.payload ?? '', /"byConnectionId":"conn-1"/)
})

test('archive keeps manifest and history files', (t) => {
  const store = withStore(t)
  const dir = agentsDir(t)
  const reg = registry(store)
  reg.load(dir)

  const archived = reg.archive('ceo', mintHumanActor('conn-1'))
  assert.equal(archived.status, 'archived')
  assert.equal(store.query({ type: 'agent.archived' }).length, 1)

  // Archive never deletes: an audit of what an agent did needs the manifest
  // it acted under, and the history beside it.
  assert.ok(readFileSync(join(dir, 'ceo', 'agent.yaml'), 'utf8').includes('id: ceo'))
  assert.ok(readFileSync(join(dir, 'ceo', 'AGENTS.md'), 'utf8').includes('# ceo'))
  // Still retrievable by id, marked rather than removed.
  assert.equal(reg.get('ceo')?.status, 'archived')
  assert.equal(reg.list().length, 2)
})

test('a tier 1 manifest may not hold a write tool, and the refusal names the tier and the risk', (t) => {
  // Tier is supposed to be the gate's posture for an agent, and until this check
  // it did no work at load: a tier 1 manifest could list a `write` tool and the
  // only thing stopping it was the gate at call time. That is a refusal in the
  // right place at the wrong moment — an operator wants it when the file is read,
  // with the file named, not on the first run that happens to reach for it.
  const store = withStore(t)
  const dir = agentsDir(t, {
    'reads-only': `
id: reads-only
version: 1
kind: standard
role: worker
soul: worker.md
tier: 1
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.remember]
memory:
  projectId: aos/agent/reads-only
`,
  })
  assert.throws(
    () => registry(store).load(dir),
    (e: unknown) => {
      assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
      assert.match(e.message, /pmmcp\.remember/)
      assert.match(e.message, /write risk/)
      assert.match(e.message, /tier 1 may hold read/)
      // And it says what to do, rather than only what is wrong.
      assert.match(e.message, /Raise the tier deliberately or drop the tool/)
      return true
    },
  )
})

test('the same write tool loads at tier 2, and a read tool loads at tier 1', (t) => {
  // The other half of the claim: the check is about the tier/risk pair, not a
  // blanket refusal that would make tier 2 unusable.
  const store = withStore(t)
  const dir = agentsDir(t, {
    'can-write': `
id: can-write
version: 1
kind: standard
role: worker
soul: worker.md
tier: 2
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.remember, pmmcp.recall]
memory:
  projectId: aos/agent/can-write
`,
    'can-read': `
id: can-read
version: 1
kind: standard
role: worker
soul: worker.md
tier: 1
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.recall]
memory:
  projectId: aos/agent/can-read
`,
  })
  const reg = registry(store)
  reg.load(dir)
  assert.deepEqual(reg.get('can-write')?.manifest.tools.allow, ['pmmcp.remember', 'pmmcp.recall'])
  assert.deepEqual(reg.get('can-read')?.manifest.tools.allow, ['pmmcp.recall'])
})

test('a manifest budget above a kernel ceiling is refused at LOAD, not at the first run', (t) => {
  // resolveCaps already refused this — but only when a run started, so a bad
  // manifest loaded clean and failed later, which is the worst place to find a
  // config error. The registry now asks the same question when it reads the file.
  const store = withStore(t)
  const dir = agentsDir(t, {
    greedy: `
id: greedy
version: 1
kind: standard
role: worker
soul: worker.md
tier: 1
model:
  primary: anthropic/claude-sonnet-5
budget:
  maxLlmCalls: 500
memory:
  projectId: aos/agent/greedy
`,
  })
  assert.throws(
    () => registry(store).load(dir),
    (e: unknown) => {
      assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
      assert.match(e.message, /maxLlmCalls is 500/)
      assert.match(e.message, /A manifest may only lower a cap/)
      return true
    },
  )

  // Nothing was registered: a refused load leaves no half-loaded fleet behind.
  assert.equal(store.query({ type: 'agent.registered' }).length, 0)
})

test('a budget that lowers every cap loads and is preserved verbatim', (t) => {
  const store = withStore(t)
  const dir = agentsDir(t, {
    modest: `
id: modest
version: 1
kind: standard
role: worker
soul: worker.md
tier: 1
model:
  primary: anthropic/claude-sonnet-5
budget:
  maxCostMicroUsd: 500000
  maxLlmCalls: 12
  maxToolCalls: 40
  maxWallclockMs: 300000
memory:
  projectId: aos/agent/modest
`,
  })
  const reg = registry(store)
  reg.load(dir)
  assert.deepEqual(reg.get('modest')?.manifest.budget, {
    maxCostMicroUsd: 500_000,
    maxLlmCalls: 12,
    maxToolCalls: 40,
    maxWallclockMs: 300_000,
  })
})
