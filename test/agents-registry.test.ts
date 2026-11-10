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
import { AgentRegistry, type RegistryDeps } from '../src/agents/registry.js'
import { MAX_EGRESS_ALLOW, MAX_EGRESS_BIND, parseManifest, type AgentManifest } from '../src/agents/manifest.js'
import { parseKernelConfig } from '../src/config.js'
import { EgressGrant } from '../src/egress/policy.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import type { EventStore } from '../src/events/store.js'
import { ConfigError } from '../src/errors.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { closeVerified, withStore } from './helpers/store.js'
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

// Tier 2 and sandboxed in the trusted domain: the least a manifest holding an
// egress host must be (egress plan E6).
const TEMPLATE_YAML = `
id: worker-template
version: 1
kind: template
role: worker
soul: worker.md
tier: 2
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.recall]
sandbox:
  domain: trusted
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

function registry(store: EventStore, egressBindings: RegistryDeps['egressBindings'] = {}): AgentRegistry {
  return new AgentRegistry({ providers: PROVIDERS, toolViews: TOOL_VIEWS, store, budgets: BUDGETS, egressBindings })
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

  // Frozen: a run holding a record must not be able to edit its own reach
  // (to the last list in its manifest: 'every record is frozen to its last
  // list' below).
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
    /requested tier 3 exceeds template tier 2/,
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
  assert.equal(sibling.manifest.tier, 2)
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

// ── egress (egress plan E6) ─────────────────────────────────────────────────
//
// A manifest's egress names credential-free hosts (allow) and kernel.yaml
// bindings (bind). Who may hold either, which ids exist and which hosts are
// bound are the registry's questions, asked at load with the file named.

/**
 * The shipped kernel.yaml with three bindings, through the real schema, so
 * the bindings record is the shape boot hands the registry (a plain object).
 * Two share github.com, on different repositories, as kernel.yaml admits.
 */
function boundConfig(): ReturnType<typeof parseKernelConfig> {
  const raw = parseYaml(readFileSync(join(REPO_ROOT, 'config/kernel.yaml'), 'utf8')) as {
    egress: { bindings: Record<string, unknown> }
  }
  raw.egress.bindings = {
    'github-git': { host: 'github.com', scheme: 'Basic', envVar: 'AOS_GITHUB_TOKEN', profiles: ['git-fetch'], repos: ['op/fixture'] },
    'github-api': { host: 'api.github.com', scheme: 'Bearer', envVar: 'AOS_GITHUB_API_TOKEN', profiles: ['github-pulls'], repos: ['op/fixture'] },
    'github-mirror': { host: 'github.com', scheme: 'Basic', envVar: 'AOS_GITHUB_MIRROR_TOKEN', profiles: ['git-fetch'], repos: ['op/mirror'] },
  }
  return parseKernelConfig(raw, { repoRoot: REPO_ROOT })
}

/** A manifest holding `egress` (YAML lines under egress:), a tier 2 worker sandboxed in trusted unless `over` says otherwise. */
function egressAgent(
  id: string,
  egress: string,
  over: { tier?: number; role?: string; sandbox?: 'trusted' | 'hostile' | 'none'; kind?: string } = {},
): string {
  const sandbox = over.sandbox ?? 'trusted'
  return `
id: ${id}
version: 1
kind: ${over.kind ?? 'standard'}
role: ${over.role ?? 'worker'}
soul: worker.md
tier: ${String(over.tier ?? 2)}
model:
  primary: anthropic/claude-sonnet-5
${sandbox === 'none' ? '' : `sandbox:\n  domain: ${sandbox}\n`}egress:
${egress}
memory:
  projectId: aos/agent/${id}
`
}

test('egress without a trusted sandbox, below tier 2, or on an orchestrator is refused', (t) => {
  const bindings = boundConfig().egress.bindings
  // A credential-free host and a binding are each egress on their own.
  const holdings = { allow: '  allow: [docs.example.com]', bind: '  bind: [github-git]' }
  const postures = [
    { over: { sandbox: 'none' as const }, why: /it declares no sandbox\. Egress reaches only a run sandboxed in the trusted domain/ },
    { over: { sandbox: 'hostile' as const }, why: /it is sandboxed in the hostile domain\. .*the hostile domain gets no channel and no egress/ },
    { over: { tier: 1 }, why: /holds egress at tier 1, but egress needs tier 2 or more/ },
    { over: { tier: 0 }, why: /holds egress at tier 0, but egress needs tier 2 or more/ },
    // Tier 2 and trusted, so only the role is wrong.
    { over: { role: 'orchestrator' }, why: /it is role: orchestrator\. Egress is for a worker's sandboxed run/ },
  ]
  for (const [holding, egress] of Object.entries(holdings)) {
    for (const { over, why } of postures) {
      const store = withStore(t)
      const dir = agentsDir(t, { reacher: egressAgent('reacher', egress, over) })
      assert.throws(
        () => registry(store, bindings).load(dir),
        (e: unknown) => {
          assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
          // The file is named, and the agent.
          assert.match(e.message, /reacher\/agent\.yaml: reacher holds egress/)
          assert.match(e.message, why)
          return true
        },
        `${holding} at ${JSON.stringify(over)} loaded`,
      )
      assert.equal(store.query({ type: 'agent.registered' }).length, 0, 'a refused fleet left registrations behind')
    }
  }

  // The other half: each holding loads on a tier 2 or 3 worker sandboxed in
  // trusted, and a manifest holding no egress loads at every posture (the CEO
  // fixture is an orchestrator with egress.allow [], and it loads with each).
  const store = withStore(t)
  const reg = registry(store, bindings)
  reg.load(
    agentsDir(t, {
      'fetcher-a': egressAgent('fetcher-a', holdings.allow),
      'fetcher-b': egressAgent('fetcher-b', holdings.bind, { tier: 3 }),
      'no-egress-a': egressAgent('no-egress-a', '  allow: []\n  bind: []', { sandbox: 'hostile', tier: 1 }),
      'no-egress-b': egressAgent('no-egress-b', '  allow: []', { sandbox: 'none', tier: 0 }),
    }),
  )
  assert.deepEqual(reg.get('fetcher-a')?.manifest.egress, { allow: ['docs.example.com'], bind: [] })
  assert.deepEqual(reg.get('fetcher-b')?.manifest.egress, { allow: [], bind: ['github-git'] })
  assert.deepEqual(reg.get('no-egress-a')?.manifest.egress, { allow: [], bind: [] })
  assert.equal(reg.get('ceo')?.manifest.role, 'orchestrator')
})

test('egress.allow refuses 192.168.5.2 and host.lima.internal', (t) => {
  // Both are the Mac's loopback as a Colima VM sees it, where pmmcp listens.
  // A host is an EgressHost: a public DNS name in one spelling, nothing else.
  const refused = [
    '192.168.5.2',
    'host.lima.internal',
    'host.docker.internal',
    'localhost',
    '127.0.0.1',
    '2130706433',
    '[::1]',
    'docs.example.com:443',
    '*.example.com',
    'user@docs.example.com',
    'bücher.example',
    'docs',
  ]
  for (const host of refused) {
    const store = withStore(t)
    const dir = agentsDir(t, { reacher: egressAgent('reacher', `  allow: [${JSON.stringify(host)}]`) })
    assert.throws(
      () => registry(store).load(dir),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.match(e.message, /reacher\/agent\.yaml is invalid/)
        assert.match(e.message, /not an egress host: it /)
        return true
      },
      `${host} loaded as an egress host`,
    )
  }

  // One spelling: a host is stored as the kernel compares it.
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t, { reacher: egressAgent('reacher', '  allow: [Docs.Example.COM.]') }))
  assert.deepEqual(reg.get('reacher')?.manifest.egress.allow, ['docs.example.com'])

  // A valid name in a credential's shape would be stored censored in every
  // grant row naming it, so it is refused at load, and the refusal does not
  // repeat it.
  const censored = withStore(t)
  assert.throws(
    () => registry(censored).load(agentsDir(t, { reacher: egressAgent('reacher', '  allow: [docs.example.com, sk-abcdefghij.example.com]') })),
    (e: unknown) => {
      assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
      assert.match(e.message, /reacher\/agent\.yaml: egress\.allow\[1\] is a host in the shape of a credential/)
      assert.equal(e.message.includes('sk-abcdefghij'), false, e.message)
      return true
    },
  )
})

test('egress.allow may not list the host of a kernel.yaml binding, bound or not', (t) => {
  // A bound host is reached only through its binding's profiles and
  // repositories; listed credential-free as well, a request to it would not
  // say whether a credential belongs on it.
  const bindings = boundConfig().egress.bindings
  const cases: [string, RegExp][] = [
    // Every binding on the host is named, in kernel.yaml's order.
    ['  allow: [github.com]', /egress\.allow lists github\.com, the host of bindings github-git, github-mirror in kernel\.yaml/],
    // Compared in the one spelling.
    ['  allow: [GitHub.COM.]', /egress\.allow lists github\.com, the host of bindings github-git, github-mirror in kernel\.yaml/],
    // Binding another host does not make this one free.
    ['  allow: [api.github.com]\n  bind: [github-git]', /egress\.allow lists api\.github\.com, the host of binding github-api in kernel\.yaml/],
  ]
  for (const [egress, why] of cases) {
    const store = withStore(t)
    assert.throws(() => registry(store, bindings).load(agentsDir(t, { reacher: egressAgent('reacher', egress) })), why, egress)
  }

  // The rule is about the hosts kernel.yaml binds: with no binding, github.com
  // is a credential-free host like any other; and a bound worker may list
  // hosts no binding names.
  const store = withStore(t)
  const free = registry(store)
  free.load(agentsDir(t, { reacher: egressAgent('reacher', '  allow: [github.com]') }))
  assert.deepEqual(free.get('reacher')?.manifest.egress.allow, ['github.com'])
  const bound = registry(withStore(t), bindings)
  bound.load(agentsDir(t, { reacher: egressAgent('reacher', '  allow: [docs.example.com]\n  bind: [github-git, github-api]') }))
  assert.deepEqual(bound.get('reacher')?.manifest.egress, { allow: ['docs.example.com'], bind: ['github-git', 'github-api'] })
})

test('a manifest bind: [constructor] is refused as an unknown bindingId', (t) => {
  const bindings = boundConfig().egress.bindings
  // The trap: the parsed record is a plain object, so a lookup by `in` or a
  // bare index finds Object.prototype's constructor, and `constructor` is a
  // valid binding id. Only an own key is a binding.
  assert.equal('constructor' in bindings, true)
  assert.equal(Object.hasOwn(bindings, 'constructor'), false)
  for (const id of ['constructor', 'prototype', 'gitlab']) {
    const store = withStore(t)
    assert.throws(
      () => registry(store, bindings).load(agentsDir(t, { reacher: egressAgent('reacher', `  bind: [github-git, ${id}]`) })),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.match(e.message, new RegExp(`reacher/agent\\.yaml: egress\\.bind names ${id}, which is no binding in kernel\\.yaml's egress\\.bindings`))
        return true
      },
      `bind: [${id}] loaded`,
    )
    assert.equal(store.query({ type: 'agent.registered' }).length, 0)
  }
  // With no bindings at all, every id is unknown.
  assert.throws(
    () => registry(withStore(t)).load(agentsDir(t, { reacher: egressAgent('reacher', '  bind: [github-git]') })),
    /egress\.bind names github-git, which is no binding/,
  )
  // What is no binding id at all, or one named twice, is the schema's refusal.
  for (const egress of ['  bind: [__proto__]', '  bind: [GitHub]', '  bind: [github-git, github-git]']) {
    assert.throws(
      () => registry(withStore(t), bindings).load(agentsDir(t, { reacher: egressAgent('reacher', egress) })),
      /reacher\/agent\.yaml is invalid: .*(is a binding id|names a binding twice)/s,
      egress,
    )
  }
})

test('spawnEphemeral rejects a bind outside the template, and the child carries bind', (t) => {
  const store = withStore(t)
  const reg = registry(store, boundConfig().egress.bindings)
  reg.load(
    agentsDir(t, {
      'bound-template': egressAgent('bound-template', '  allow: [docs.example.com]\n  bind: [github-git]', { kind: 'template' }),
    }),
  )
  const templateId = 'bound-template'

  // github-api is a real binding, and the template does not hold it.
  assert.throws(
    () => reg.spawnEphemeral({ templateId, childId: 'scout-1', egressBind: ['github-git', 'github-api'] }),
    /spawn rejected: egress\.bind github-api is not in the template's bind list/,
  )
  assert.throws(
    () => reg.spawnEphemeral({ templateId, childId: 'scout-1', egressBind: ['constructor'] }),
    /spawn rejected: egress\.bind constructor is not in the template's bind list/,
  )
  assert.equal(reg.get('scout-1'), undefined)

  // By default the child carries the template's egress, bind included, as
  // its own arrays: the record literal names every field.
  const child = reg.spawnEphemeral({ templateId, childId: 'scout-2' })
  const template = reg.get(templateId)
  assert.ok(template)
  assert.deepEqual(child.manifest.egress, { allow: ['docs.example.com'], bind: ['github-git'] })
  assert.notEqual(child.manifest.egress.bind, template.manifest.egress.bind)
  assert.notEqual(child.manifest.egress.allow, template.manifest.egress.allow)

  // Narrower is allowed, field by field.
  const narrow = reg.spawnEphemeral({ templateId, childId: 'scout-3', egressBind: [] })
  assert.deepEqual(narrow.manifest.egress, { allow: ['docs.example.com'], bind: [] })

  // A child that lowers its tier below egress's and keeps any of the
  // template's egress holds what no loaded manifest may; with none left, it
  // spawns.
  assert.throws(
    () => reg.spawnEphemeral({ templateId, childId: 'scout-4', tier: 1 }),
    /spawn rejected: scout-4 holds egress at tier 1, but egress needs tier 2 or more/,
  )
  assert.throws(
    () => reg.spawnEphemeral({ templateId, childId: 'scout-4', tier: 1, egressAllow: [] }),
    /spawn rejected: scout-4 holds egress at tier 1/,
  )
  assert.equal(reg.get('scout-4'), undefined)
  const lowered = reg.spawnEphemeral({ templateId, childId: 'scout-5', tier: 1, egressAllow: [], egressBind: [] })
  assert.equal(lowered.manifest.tier, 1)
  assert.deepEqual(lowered.manifest.egress, { allow: [], bind: [] })

  // A request naming a template entry twice is within the template, and the
  // child holds it once: its lists are the template's entries the request
  // kept, never the request's own (a grant refuses a host or a binding
  // named twice, so a child holding one twice could never run).
  const repeated = reg.spawnEphemeral({
    templateId,
    childId: 'scout-6',
    egressAllow: ['docs.example.com', 'docs.example.com'],
    egressBind: ['github-git', 'github-git'],
  })
  assert.deepEqual(repeated.manifest.egress, { allow: ['docs.example.com'], bind: ['github-git'] })

  assert.equal(store.query({ type: 'agent.spawn.rejected' }).length, 4)
  assert.equal(store.query({ type: 'agent.spawned' }).length, 4)
})

test('a manifest egress holds at most what one grant can: 64 hosts and 16 bindings, each once', () => {
  // A manifest past the grant's bounds could never be issued a grant (egress
  // plan W1); refused when the file is read instead.
  const hosts = (n: number): string[] => Array.from({ length: n }, (_, i) => `h${String(i)}.example.com`)
  const ids = (n: number): string[] => Array.from({ length: n }, (_, i) => `b${String(i)}`)
  const manifest = (egress: string): unknown => parseYaml(egressAgent('reacher', egress))

  assert.equal(parseManifest(manifest(`  allow: [${hosts(MAX_EGRESS_ALLOW).join(', ')}]`), 'agent.yaml').egress.allow.length, MAX_EGRESS_ALLOW)
  assert.throws(() => parseManifest(manifest(`  allow: [${hosts(MAX_EGRESS_ALLOW + 1).join(', ')}]`), 'agent.yaml'), /is invalid/)
  assert.equal(parseManifest(manifest(`  bind: [${ids(MAX_EGRESS_BIND).join(', ')}]`), 'agent.yaml').egress.bind.length, MAX_EGRESS_BIND)
  assert.throws(() => parseManifest(manifest(`  bind: [${ids(MAX_EGRESS_BIND + 1).join(', ')}]`), 'agent.yaml'), /is invalid/)

  // The same bounds as the grant's own.
  const grant = (allow: number, routes: number): boolean =>
    EgressGrant.safeParse({
      runId: 'run-1',
      allow: hosts(allow),
      routes: ids(routes).map((bindingId, i) => ({ bindingId, host: `r${String(i)}.example.net`, profiles: ['git-fetch'], repos: ['op/fixture'] })),
    }).success
  assert.equal(grant(MAX_EGRESS_ALLOW, MAX_EGRESS_BIND), true)
  assert.equal(grant(MAX_EGRESS_ALLOW + 1, 0), false)
  assert.equal(grant(0, MAX_EGRESS_BIND + 1), false)

  // Each once, compared after normalisation: the grant refuses a host or a
  // binding named twice.
  assert.throws(
    () => parseManifest(manifest('  allow: [Docs.Example.com, docs.example.com.]'), 'agent.yaml'),
    /egress\.allow lists a host twice/,
  )
  assert.throws(() => parseManifest(manifest('  bind: [github-git, github-git]'), 'agent.yaml'), /egress\.bind names a binding twice/)
})

test('spawnEphemeral refuses a tier that is no integer from 0 to 3 before any other check, and registers nothing', (t) => {
  // A comparison with NaN is false whichever way it is written: unchecked,
  // NaN passed the template clamp (`tier > t.tier`) and egress's tier test,
  // and only the agent.spawned schema refused it, after the child had been
  // checked. Refused first, by name, through agent.spawn.rejected.
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))

  const given: [unknown, string][] = [
    [Number.NaN, 'NaN'],
    ['x', 'of type string'],
    [-1, '-1'],
    [1.5, '1.5'],
    [Number.POSITIVE_INFINITY, 'Infinity'],
    // Above the template too, but refused as no tier, before the clamp.
    [4, '4'],
  ]
  for (const [i, [tier, shown]] of given.entries()) {
    const childId = `scout-${String(i)}`
    assert.throws(
      () => reg.spawnEphemeral({ templateId: 'worker-template', childId, tier: tier as number }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.equal(e.message, `spawn rejected: requested tier ${shown} is not a tier: an integer from 0 to 3`)
        return true
      },
      `tier ${shown} was not refused as no tier`,
    )
    assert.equal(reg.get(childId), undefined, `tier ${shown} registered a child`)
  }
  // Before the template lookup too: from no template, or from a standing
  // agent, the tier is still what is refused, by name.
  for (const templateId of ['no-such-template', 'ceo']) {
    assert.throws(
      () => reg.spawnEphemeral({ templateId, childId: 'scout-x', tier: Number.NaN }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.equal(e.message, 'spawn rejected: requested tier NaN is not a tier: an integer from 0 to 3')
        return true
      },
      `tier NaN from ${templateId} was refused for something else`,
    )
  }
  const rejected = store.query({ type: 'agent.spawn.rejected' })
  assert.equal(rejected.length, given.length + 2)
  assert.match(rejected[0]?.payload ?? '', /requested tier NaN is not a tier/)
  assert.equal(store.query({ type: 'agent.spawned' }).length, 0)

  // Every tier the template admits still spawns; below 2, without its
  // egress, and at 0 without its tools (tier 0 holds none).
  for (const tier of [0, 1, 2]) {
    const childId = `ok-${String(tier)}`
    const child = reg.spawnEphemeral({ templateId: 'worker-template', childId, tier, ...(tier < 2 ? { egressAllow: [] } : {}), ...(tier === 0 ? { toolsAllow: [] } : {}) })
    assert.equal(child.manifest.tier, tier)
  }
  assert.equal(store.query({ type: 'agent.spawned' }).length, 3)
})

/** A template holding a read tool and a write tool, no egress: tier 2, the least that may hold the write one. */
const TOOLED_TEMPLATE_YAML = `
id: tooled-template
version: 1
kind: template
role: worker
soul: worker.md
tier: 2
model:
  primary: anthropic/claude-sonnet-5
tools:
  servers: [pmmcp]
  allow: [pmmcp.recall, pmmcp.remember]
egress:
  allow: []
memory:
  projectId: aos/shared
`

test("a child that lowers its tier is held to that tier's tool rules, as a loaded manifest is, and an archived template is no spawn source", (t) => {
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t, { 'tooled-template': TOOLED_TEMPLATE_YAML }))
  const refused: ReadonlyArray<readonly [string, Parameters<AgentRegistry['spawnEphemeral']>[0], RegExp]> = [
    // Tier 1 holds read tools only: the template's write tool, kept, is one no tier 1 manifest may load with.
    ['tier 1 keeping the write tool', { templateId: 'tooled-template', childId: 'low-1', tier: 1 }, /^spawn rejected: tools\.allow names pmmcp\.remember, which is write risk, but tier 1 may hold read\. /],
    ['tier 0 keeping a read tool', { templateId: 'tooled-template', childId: 'low-2', tier: 0, toolsAllow: ['pmmcp.recall'] }, /^spawn rejected: tools\.allow names pmmcp\.recall, which is read risk, but tier 0 may hold no tools\. /],
  ]
  for (const [what, request, why] of refused) {
    assert.throws(() => reg.spawnEphemeral(request), (e: unknown) => e instanceof ConfigError && why.test(e.message), what)
    assert.equal(reg.get(request.childId), undefined, `${what} registered a child`)
  }
  // Narrowed to what the tier holds, each spawns.
  assert.deepEqual(reg.spawnEphemeral({ templateId: 'tooled-template', childId: 'ok-1', tier: 1, toolsAllow: ['pmmcp.recall'] }).manifest.tools.allow, ['pmmcp.recall'])
  assert.deepEqual(reg.spawnEphemeral({ templateId: 'tooled-template', childId: 'ok-0', tier: 0, toolsAllow: [] }).manifest.tools.allow, [])
  assert.equal(reg.spawnEphemeral({ templateId: 'tooled-template', childId: 'ok-2' }).manifest.tier, 2)

  // Archived, a template is retired with everything it held: no child inherits from it.
  reg.archive('tooled-template', mintHumanActor('conn-1'))
  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'tooled-template', childId: 'late-1', tier: 1, toolsAllow: ['pmmcp.recall'] }),
    /spawn rejected: template tooled-template is archived: an archived template is no spawn source$/,
  )
  assert.equal(reg.get('late-1'), undefined)
  const rows = store.query({ type: 'agent.spawn.rejected' }).map((row) => JSON.parse(row.payload) as { reason: string })
  assert.deepEqual(
    rows.map((row) => row.reason.replace(/\. .*$/, '')),
    [
      'tools.allow names pmmcp.remember, which is write risk, but tier 1 may hold read',
      'tools.allow names pmmcp.recall, which is read risk, but tier 0 may hold no tools',
      'template tooled-template is archived: an archived template is no spawn source',
    ],
  )
  assert.equal(store.query({ type: 'agent.spawned' }).length, 3)
})

test('a spawn whose agent.spawned row cannot be written registers nothing', (t) => {
  // Logged, then registered: a child must never hold reach the log has no row for.
  const store = withStore(t)
  const reg = registry(store)
  reg.load(agentsDir(t))
  closeVerified(store)

  assert.throws(() => reg.spawnEphemeral({ templateId: 'worker-template', childId: 'scout-1' }), /database is not open/)
  assert.equal(reg.get('scout-1'), undefined, 'a child the log never recorded was registered')
  assert.equal(
    reg.list().some((r) => r.manifest.id === 'scout-1'),
    false,
  )
})

test('egress is strict: an unknown key is refused at parse with the file named, never stripped', (t) => {
  // Stripped, `binds:` would load as no bind at all, and an `envVar:` or a
  // `token:` under egress would vanish without the author learning that a
  // manifest never names a credential.
  const bindings = boundConfig().egress.bindings
  const cases: [string, string][] = [
    ['  allow: []\n  binds: [github-git]', 'binds'],
    ['  envVar: AOS_X', 'envVar'],
    ['  allow: [docs.example.com]\n  token: AOS_X', 'token'],
  ]
  for (const [egress, key] of cases) {
    const store = withStore(t)
    assert.throws(
      () => registry(store, bindings).load(agentsDir(t, { reacher: egressAgent('reacher', egress) })),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.match(e.message, /reacher\/agent\.yaml is invalid: /)
        // Under egress, by name: refused there, not somewhere else in the file.
        assert.match(e.message, new RegExp(`"code": "unrecognized_keys",\\s*"keys": \\[\\s*"${key}"\\s*\\],\\s*"path": \\[\\s*"egress"\\s*\\]`))
        return true
      },
      `egress ${key} loaded`,
    )
    assert.equal(store.query({ type: 'agent.registered' }).length, 0)
  }
})

test('manifests that omit egress share none of its arrays', () => {
  // zod copies an object default shallowly: with one, every manifest without
  // egress held the same allow and bind arrays, so a host pushed onto one
  // agent's would be every such agent's.
  const bare = (id: string): unknown => {
    const raw = parseYaml(egressAgent(id, '  allow: []')) as Record<string, unknown>
    delete raw['egress']
    return raw
  }
  const a = parseManifest(bare('agent-a'), 'a/agent.yaml')
  const b = parseManifest(bare('agent-b'), 'b/agent.yaml')
  assert.notEqual(a.egress.allow, b.egress.allow)
  assert.notEqual(a.egress.bind, b.egress.bind)
  const host = parseManifest(parseYaml(egressAgent('agent-c', '  allow: [docs.example.com]')), 'c/agent.yaml').egress.allow
  a.egress.allow.push(...host)
  a.egress.bind.push('github-git')
  assert.deepEqual(b.egress, { allow: [], bind: [] }, "one manifest's egress reached another")
  assert.deepEqual(parseManifest(bare('agent-d'), 'd/agent.yaml').egress, { allow: [], bind: [] }, 'the default itself was changed')
})

test('an egress.bind id in the shape of a credential is refused without being repeated', (t) => {
  // Each passes BINDING_ID, and none can be a binding: kernel.yaml refuses an
  // id redactString changes. The refusal names the index, as allow's does.
  const bindings = boundConfig().egress.bindings
  for (const id of ['sk-abcdefghij', 'xoxb-1234567890']) {
    const store = withStore(t)
    assert.throws(
      () => registry(store, bindings).load(agentsDir(t, { reacher: egressAgent('reacher', `  bind: [github-git, ${id}]`) })),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.match(e.message, /reacher\/agent\.yaml: egress\.bind\[1\] is in the shape of a credential, so it names no binding/)
        assert.equal(e.message.includes(id), false, e.message)
        return true
      },
      `bind: [${id}] loaded`,
    )
  }
})

test('manifests that omit tools share none of its arrays', () => {
  // The bug egress's default had, on an access-control list: zod copies an
  // object default shallowly, so with one every manifest without a tools
  // section held the same servers and allow arrays.
  const bare = (id: string): AgentManifest => parseManifest(parseYaml(egressAgent(id, '  allow: []')), `${id}/agent.yaml`)
  const a = bare('agent-a')
  const b = bare('agent-b')
  assert.notEqual(a.tools.allow, b.tools.allow)
  assert.notEqual(a.tools.servers, b.tools.servers)
  a.tools.allow.push('pmmcp.remember')
  a.tools.servers.push('pmmcp')
  assert.deepEqual(b.tools, { servers: [], allow: [] }, "one manifest's tools reached another")
  assert.deepEqual(bare('agent-d').tools, { servers: [], allow: [] }, 'the default itself was changed')
})

/** Every object and array reachable from `value`, each with its path, so a test can say which one is not frozen. */
function parts(value: unknown, path = 'manifest'): [string, object][] {
  if (typeof value !== 'object' || value === null) return []
  return [[path, value], ...Object.entries(value).flatMap(([key, part]) => parts(part, `${path}.${key}`))]
}

test('every record is frozen to its last list, loaded, spawned, promoted or archived', (t) => {
  // Object.freeze is shallow: a record's status was fixed while its
  // manifest's tier and every list in it stayed writable, so whatever held
  // the record could widen that agent with no event row. egress.bind is the
  // list that matters most: the grant issuer reads the credential-bearing
  // routes from the record (egress plan W1).
  const store = withStore(t)
  const reg = registry(store, boundConfig().egress.bindings)
  reg.load(
    agentsDir(t, {
      'bound-template': egressAgent('bound-template', '  allow: [docs.example.com]\n  bind: [github-git]', { kind: 'template' }),
      // Tier 1, no sandbox, no egress and no tools section: its lists are
      // the schema's defaults.
      plain: egressAgent('plain', '  allow: []', { tier: 1, sandbox: 'none' }),
    }),
  )
  reg.spawnEphemeral({ templateId: 'bound-template', childId: 'scout-1' })
  reg.spawnEphemeral({ templateId: 'bound-template', childId: 'scout-2' })
  reg.promote('scout-2', mintHumanActor('conn-1'))
  reg.archive('ceo', mintHumanActor('conn-1'))
  const ids = ['plain', 'bound-template', 'scout-1', 'scout-2', 'ceo']
  assert.deepEqual(
    ids.map((id) => [reg.get(id)?.manifest.kind, reg.get(id)?.status]),
    [['standard', 'active'], ['template', 'active'], ['ephemeral', 'active'], ['standard', 'active'], ['standard', 'archived']],
  )

  const attempts: [string, (m: AgentManifest) => unknown][] = [
    ['a push onto egress.bind', (m) => (m.egress.bind as string[]).push('github-mirror')],
    ['a push onto egress.allow', (m) => (m.egress.allow as string[]).push('exfil.example.net')],
    ['a push onto tools.allow', (m) => (m.tools.allow as string[]).push('pmmcp.remember')],
    ['a push onto tools.servers', (m) => (m.tools.servers as string[]).push('github')],
    ['a push onto model.fallbacks', (m) => (m.model.fallbacks as string[]).push('openrouter/moonshotai/kimi-k3')],
    ['an assignment to tier', (m) => ((m as { tier: number }).tier = 3)],
    ['an assignment to egress', (m) => ((m as { egress: unknown }).egress = { allow: [], bind: ['github-mirror'] })],
    ['an assignment to egress.bind', (m) => ((m.egress as { bind: string[] }).bind = ['github-mirror'])],
    ['an assignment to tools.allow', (m) => ((m.tools as { allow: string[] }).allow = ['pmmcp.remember'])],
  ]
  for (const id of ids) {
    const record = reg.get(id)
    assert.ok(record)
    const before = JSON.stringify(record)
    for (const [what, attempt] of attempts) {
      assert.throws(() => attempt(record.manifest), TypeError, `${what} on ${id} did not throw`)
    }
    // Every part, not only the ones tried above: spawn.templates, memory, budget.
    for (const [path, part] of parts(record.manifest)) assert.equal(Object.isFrozen(part), true, `${id}: ${path} is not frozen`)
    assert.equal(JSON.stringify(reg.get(id)), before, `${id} changed with no event row`)
  }
  // The template's lists, frozen, were never the child's: a child is built from copies.
  assert.notEqual(reg.get('scout-1')?.manifest.egress.bind, reg.get('bound-template')?.manifest.egress.bind)
})

test("a spawn request entry in a credential's shape, or in no egress shape at all, is refused by its index and never repeated", (t) => {
  // The load path names an entry only once it is known to be in its field's
  // shape and not a credential's; a spawn request is the caller's text, and
  // a refusal naming 'sk-...' was stored censored in agent.spawn.rejected.
  const store = withStore(t)
  const reg = registry(store, boundConfig().egress.bindings)
  reg.load(
    agentsDir(t, {
      'bound-template': egressAgent('bound-template', '  allow: [docs.example.com]\n  bind: [github-git]', { kind: 'template' }),
    }),
  )
  const BIND = /^spawn rejected: egress\.bind\[(\d)\] of the request is no binding id, or is in the shape of a credential, so it is in no template's bind list, and it is not repeated here$/
  const ALLOW = /^spawn rejected: egress\.allow\[(\d)\] of the request is no egress host in its one spelling, or is in the shape of a credential, so it is in no template's allow list, and it is not repeated here$/
  const cases: [{ egressAllow?: string[]; egressBind?: string[] }, string, RegExp, string][] = [
    // A valid binding id: only its shape says it is no binding.
    [{ egressBind: ['github-git', 'sk-abcdefghijklmnop'] }, 'sk-abcdefghijklmnop', BIND, '1'],
    [{ egressBind: ['GitHub-Git\nforged line'] }, 'forged line', BIND, '0'],
    // A valid egress host, in a credential's shape.
    [{ egressAllow: ['docs.example.com', 'sk-abcdefghij.example.com'] }, 'sk-abcdefghij', ALLOW, '1'],
    // An EgressHost, but not in the one spelling a template holds.
    [{ egressAllow: ['Docs.Example.COM'] }, 'Docs.Example', ALLOW, '0'],
    [{ egressAllow: ['192.168.5.2'] }, '192.168.5.2', ALLOW, '0'],
    // No string at all: refused by its index, never handed to the host parser
    // or the redaction pass, which would throw a TypeError and leave no row.
    [{ egressAllow: [42 as unknown as string] }, '42', ALLOW, '0'],
    [{ egressBind: ['github-git', null as unknown as string] }, 'null', BIND, '1'],
  ]
  for (const [i, [request, raw, why, index]] of cases.entries()) {
    const childId = `scout-${String(i)}`
    assert.throws(
      () => reg.spawnEphemeral({ templateId: 'bound-template', childId, ...request }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `threw ${String(e)}`)
        assert.equal(why.exec(e.message)?.[1], index, e.message)
        assert.equal(e.message.includes(raw), false, e.message)
        return true
      },
      `${JSON.stringify(request)} was not refused by its index`,
    )
    assert.equal(reg.get(childId), undefined)
  }
  const rows = store.query({ type: 'agent.spawn.rejected' })
  assert.equal(rows.length, cases.length)
  for (const row of rows) {
    // Stored as written: the redactor had nothing in the reason to censor.
    assert.equal(row.payload.includes('[REDACTED]'), false, row.payload)
    assert.match(row.payload, /\[\d\] of the request is no /)
  }

  // A well-shaped entry outside the template is still named.
  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'bound-template', childId: 'scout-9', egressAllow: ['exfil.example.net'], egressBind: ['github-api'] }),
    /spawn rejected: egress exfil\.example\.net is not in the template's allow list/,
  )
  assert.throws(
    () => reg.spawnEphemeral({ templateId: 'bound-template', childId: 'scout-9', egressBind: ['github-api'] }),
    /spawn rejected: egress\.bind github-api is not in the template's bind list/,
  )
})
