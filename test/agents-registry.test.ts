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
        risk: read
      remember:
        exposure: agent
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

function registry(store: EventStore): AgentRegistry {
  return new AgentRegistry({ providers: PROVIDERS, toolViews: TOOL_VIEWS, store })
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

test("rejects a non-null schedule with 'not implemented in Phase 0'", () => {
  // Strictness is how an absent feature stays absent. Parsed-and-ignored is
  // indistinguishable from working until the day it matters.
  assert.throws(
    () => parseManifest(parseYaml(`${TEMPLATE_YAML}\nschedule: "0 * * * *"\n`), 'agent.yaml'),
    /schedule: not implemented in Phase 0/,
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
