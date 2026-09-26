// T32 — the shipped config files, manifests and souls.
//
// config.test.ts asks what kernel.yaml is CAPABLE of expressing. This file
// asks a different question: is the file we actually ship correct? Those come
// apart easily — a schema with a safe default passes every schema test while
// the shipped file overrides it with something unsafe, and nothing notices.
//
// The falsifiers:
//
//   Ship a budget that relies on a schema default and an edit to the default
//   silently changes every run's cap, with the shipped file still "correct".
//   Expose one pmmcp tool to agents and invariant 7's default-deny becomes a
//   posture rather than a fact. Nothing is exposed; the test counts.
//   Clear `placeholder` on a hosted entry without filling in its price and the
//   router starts serving a model the log bills at zero.
//   Write a credential into a shipped file and the repo holds a secret. The
//   scan reads every byte under config/, agents/ and souls/.
//   Let the CEO's tools.allow name something the tool views withhold and the
//   manifest grants reach the policy denies.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, relative } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { parseProviders } from '../src/models/registry.js'
import {
  FORCED_DISABLED,
  FORCED_KERNEL_ONLY,
  parseToolViews,
  resolveView,
} from '../src/mcp/tool-views.js'
import { AgentRegistry } from '../src/agents/registry.js'
import { loadSoul } from '../src/agents/souls.js'
import { DENY_KEYS, TOKEN_PATTERNS } from '../src/events/redact.js'
import { withStore } from './helpers/store.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')

function read(rel: string): string {
  return readFileSync(join(REPO, rel), 'utf8')
}
function readYaml(rel: string): unknown {
  return parseYaml(read(rel))
}

test('config/kernel.yaml parses and its four D30 budget defaults are present and positive', () => {
  const raw = read('config/kernel.yaml')
  const config = parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO })

  // Loopback, and the token named rather than carried.
  assert.equal(config.control.host, '127.0.0.1')
  assert.equal(config.control.port, 7777)
  assert.equal(config.control.tokenEnv, 'AOS_CONTROL_TOKEN')
  assert.deepEqual(config.control.allowedOrigins, [])

  // pmmcp: the MCP endpoint on 8766, not the dashboard on 8765.
  assert.equal(config.mcp.servers['pmmcp']?.url, 'http://127.0.0.1:8766/mcp')
  assert.equal(config.mcp.servers['pmmcp']?.tokenEnv, 'PMMCP_TOKEN')
  assert.equal(config.secrets.keyArg, 'label')
  assert.equal(config.secrets.envFallback, false)

  // D30, asserted against the SHIPPED TEXT as well as the parsed value. A
  // value inherited from a schema default would pass the second check and not
  // the first, and then an edit to the default would quietly change every
  // run's cap with this file still looking correct.
  const D30: Record<string, number> = {
    defaultRunMicroUsd: 2_000_000,
    defaultWallclockMs: 600_000,
    maxLlmCallsPerRun: 50,
    maxToolCallsPerRun: 100,
  }
  for (const [key, expected] of Object.entries(D30)) {
    assert.match(raw, new RegExp(`^\\s{2}${key}: ${String(expected)}$`, 'm'), `${key} is not written out`)
    const actual = (config.budgets as unknown as Record<string, number>)[key]
    assert.equal(actual, expected, key)
    assert.ok(actual > 0, `${key} must be positive`)
  }

  // No field admits "unlimited": a budget that can be switched off is not one.
  for (const value of Object.values(config.budgets)) assert.ok(value >= 0)
  assert.equal(config.budgets.maxRetries, 2)

  // Sandbox: two domains, each on its own socket and its own internal network,
  // and ~ expanded so DOCKER_HOST is usable by a shell-less spawn.
  for (const [name, domain] of Object.entries(config.sandbox.domains)) {
    assert.match(domain.dockerHost, /^unix:\/\/\//, `${name} dockerHost is not an absolute socket`)
    assert.equal(domain.dockerHost.includes('~'), false)
    assert.equal(domain.network, `aos-${name}`)
    // Never $HOME, never inside the repo — both refused at parse; asserted
    // here because this is the shipped value, not a hypothetical one.
    assert.notEqual(domain.mountRoot, homedir())
    assert.equal(domain.mountRoot.startsWith(REPO), false)
  }
  assert.equal(config.dataDir.startsWith(REPO), false)
  assert.notEqual(config.dataDir, homedir())
})

test('scripts/colima-up.sh exists, is executable, and its header says NEEDS VALIDATION', () => {
  const path = join(REPO, 'scripts/colima-up.sh')
  const stat = statSync(path)
  // 0o111: executable by someone. A setup script that has to be discovered as
  // non-executable is one more thing to debug on first run.
  assert.ok((stat.mode & 0o111) !== 0, `mode ${stat.mode.toString(8)} is not executable`)

  const lines = read('scripts/colima-up.sh').split('\n')
  assert.equal(lines[0], '#!/usr/bin/env bash')
  // Line 2, exactly: this script was written on Linux with no Colima to run it
  // against, and it says so where the operator reads first rather than in a
  // commit message nobody opens.
  assert.equal(
    lines[1],
    '# NEEDS VALIDATION: written on Linux without Colima; run once by the operator.',
  )

  const body = read('scripts/colima-up.sh')
  assert.ok(body.includes('--vm-type vz'), 'vz backend')
  assert.ok(body.includes('--mount-type virtiofs'), 'virtiofs mounts')
  assert.ok(body.includes('network create --internal'), 'internal networks')
  // Invariant 9: the mounts are the domains' own roots, never $HOME.
  assert.equal(/--mount\s+"\$\{HOME\}:/.test(body), false, 'mounts $HOME')
  for (const domain of ['trusted', 'hostile']) {
    assert.ok(body.includes(`.aos/workspaces/${domain}`), `${domain} mountRoot`)
  }
  assert.equal(body.includes('--privileged'), false)
  assert.equal(body.includes('docker.sock:'), false, 'bind-mounts a docker socket')
})

test('config/tool-views.yaml parses and contains only the nine pinned names', () => {
  const file = parseToolViews(readYaml('config/tool-views.yaml'))
  const servers = Object.keys(file.servers)
  assert.deepEqual(servers, ['pmmcp'])

  // The nine: seven forced kernel-only plus two forced disabled. Nothing else
  // is invented here — the other 40 pmmcp tools resolve kernel-only by the
  // literal default until the operator classifies them from
  // `hub.tools.classified`.
  const nine = [...FORCED_KERNEL_ONLY, ...FORCED_DISABLED].sort()
  assert.equal(nine.length, 9)
  assert.deepEqual(Object.keys(file.servers['pmmcp']!.tools).sort(), nine)

  // Written out, not merely injected by the parser: an audit of the file has to
  // be able to see the decision.
  const raw = read('config/tool-views.yaml')
  for (const name of nine) assert.match(raw, new RegExp(`^\\s+${name}:$`, 'm'), name)

  // Nothing is exposed to agents. This is the count that makes invariant 7's
  // default-deny a fact about the shipped file rather than a posture.
  const exposures = Object.entries(file.servers['pmmcp']!.tools)
  assert.deepEqual(exposures.filter(([, v]) => v.exposure === 'agent'), [])
  for (const name of FORCED_KERNEL_ONLY) {
    assert.equal(resolveView(file, 'pmmcp', name).exposure, 'kernel-only', name)
  }
  for (const name of FORCED_DISABLED) {
    assert.equal(resolveView(file, 'pmmcp', name).exposure, 'disabled', name)
  }
  // The literal default covers everything the file does not name.
  assert.equal(file.servers['pmmcp']!.default, 'kernel-only')
  assert.equal(resolveView(file, 'pmmcp', 'recall').exposure, 'kernel-only')
  assert.equal(resolveView(file, 'unknown-server', 'anything').exposure, 'kernel-only')
})

test('config/providers.yaml parses; exactly one non-placeholder entry and it is anthropic, carrying both vaultId and envVar', () => {
  const file = parseProviders(readYaml('config/providers.yaml'))
  const real = Object.entries(file.entries).filter(([, e]) => !e.placeholder)
  assert.equal(real.length, 1, `non-placeholder entries: ${real.map(([r]) => r).join(', ')}`)

  const [ref, card] = real[0]!
  assert.equal(ref, 'anthropic/claude-sonnet-5')
  assert.equal(card.dialect, 'anthropic')
  assert.equal(card.model, 'claude-sonnet-5')
  assert.equal(card.local, false)
  assert.equal(card.baseUrl, 'https://api.anthropic.com')
  assert.equal(card.headers?.['anthropic-version'], '2023-06-01')

  // BOTH: the vault is the credential path, and the envVar exists so the
  // opt-in env-fallback path has something to resolve when the vault is down.
  // Either one alone breaks a T34 case.
  assert.equal(card.auth.header, 'x-api-key')
  assert.equal(card.auth.scheme, 'none')
  assert.equal(card.auth.vaultId, 'anthropic-api-key')
  assert.equal(card.auth.envVar, 'ANTHROPIC_API_KEY')
  assert.equal(card.auth.value, undefined, 'a literal credential on a hosted entry')

  // Published rates, integer micro-USD per million tokens.
  assert.equal(card.pricing.inMicroUsdPerMTok, 2_000_000)
  assert.equal(card.pricing.outMicroUsdPerMTok, 10_000_000)
  // Both adapters need limits: maxOutputTokens is what supplies max_tokens.
  assert.equal(card.limits?.contextTokens, 1_000_000)
  // Deliberately below the model's 128000 ceiling: this is the per-call ask,
  // and the SDK refuses a non-streaming request that large, while the number
  // also sets the worst-case turn cost the budget checks (D16).
  assert.equal(card.limits?.maxOutputTokens, 16_000)
  assert.ok(
    (card.limits?.maxOutputTokens ?? 0) < 128_000,
    'a non-streaming adapter cannot ask for the model ceiling',
  )
  // Sampling params are rejected by this model, and the schema demands none.
  assert.equal(card.caps.sampling, 'none')
  // orchestrator is set by a human after the eval harness, never by code.
  assert.equal(card.orchestrator, false)

  // Every hosted entry that is NOT a placeholder must carry a real price. This
  // is the guard on clearing the flag: a placeholder ships at zero because a
  // fabricated price is worse than an obvious one, and the router refuses
  // placeholders — but the moment an operator clears the flag, the zero
  // becomes billable and this fails.
  for (const [r, e] of Object.entries(file.entries)) {
    if (e.placeholder || e.local) continue
    assert.ok(e.pricing.inMicroUsdPerMTok > 0, `${r}: cleared placeholder with zero input price`)
    assert.ok(e.pricing.outMicroUsdPerMTok > 0, `${r}: cleared placeholder with zero output price`)
    assert.ok(e.limits !== undefined, `${r}: cleared placeholder with no limits`)
  }

  // The placeholders the plan names are all present, and all still placeholders.
  for (const r of ['openrouter/moonshotai/kimi-k3', 'moonshot/kimi-k3', 'llamacpp/local', 'ollama/qwen3:8b']) {
    assert.equal(file.entries[r]?.placeholder, true, r)
  }
  // Local entries are loopback and hold no vault id.
  for (const r of ['llamacpp/local', 'ollama/qwen3:8b']) {
    const e = file.entries[r]!
    assert.equal(e.local, true, r)
    assert.match(e.baseUrl, /^http:\/\/127\.0\.0\.1:/, r)
    assert.equal(e.auth.vaultId, undefined, r)
  }
})

test('agents/*/agent.yaml parse against the shipped providers and tool-views; ceo tools.allow is empty', (t) => {
  const store = withStore(t)
  const providers = new Set(Object.keys(parseProviders(readYaml('config/providers.yaml')).entries))
  const toolViews = parseToolViews(readYaml('config/tool-views.yaml'))

  // The real load path, against the real files. If a manifest named a tool the
  // views withhold, or a model ref providers.yaml does not carry, this throws.
  const reg = new AgentRegistry({ providers, toolViews, store })
  reg.load(join(REPO, 'agents'))

  const ceo = reg.get('ceo')
  assert.ok(ceo, 'ceo did not load')
  assert.equal(ceo.manifest.kind, 'standard')
  assert.equal(ceo.manifest.role, 'orchestrator')
  assert.equal(ceo.manifest.tier, 2)
  assert.equal(ceo.manifest.model.primary, 'anthropic/claude-sonnet-5')
  assert.equal(ceo.manifest.memory.projectId, 'aos/ceo')

  // Honestly empty. Nothing is exposed to agents, so anything here would be a
  // grant the policy denies — and the plan's own exit note says allow: [].
  assert.deepEqual(ceo.manifest.tools.allow, [])
  assert.deepEqual(ceo.manifest.tools.servers, ['pmmcp'])
  // Egress is empty too: the Phase 2 proxy does not exist, so a host here
  // would imply an allowance nothing is present to enforce.
  assert.deepEqual(ceo.manifest.egress.allow, [])
  // Every fallback must be a ref the router will actually serve. Placeholders
  // are refused (D28), so a chain naming one is decorative.
  for (const ref of ceo.manifest.model.fallbacks) {
    assert.equal(
      parseProviders(readYaml('config/providers.yaml')).entries[ref]?.placeholder,
      false,
      `${ref} is a placeholder the router refuses to serve`,
    )
  }

  const template = reg.get('worker-template')
  assert.ok(template, 'worker-template did not load')
  assert.equal(template.manifest.kind, 'template')
  assert.equal(template.manifest.tier, 1, 'the template tier is the ceiling for every child')
  assert.deepEqual(template.manifest.tools.allow, [])
  assert.equal(template.manifest.spawn, undefined, 'a template child must not itself spawn')
  assert.deepEqual(ceo.manifest.spawn?.templates, ['worker-template'])
  assert.equal(ceo.manifest.spawn?.maxDepth, 1)

  // Every soul a manifest names is actually on disk. A missing soul degrades
  // to a marker in the prompt rather than throwing, so nothing else would
  // notice a typo here.
  for (const record of reg.list()) {
    const soul = loadSoul(join(REPO, 'souls'), record.manifest.soul, { used: 0 })
    assert.equal(soul.missing, false, `${record.manifest.id} names a missing soul ${record.manifest.soul}`)
    assert.equal(soul.truncated, false, `${record.manifest.soul} exceeds the soul budget`)
  }

  // Invariant 8: AGENTS.md sits beside the manifest and no code path writes it.
  assert.ok(read('agents/ceo/AGENTS.md').length > 0)
  assert.equal(store.query({ type: 'agent.registered' }).length, 2)
})

test('no file under config/, agents/, souls/ contains a value matching TOKEN_PATTERNS or a DENY_KEYS key', () => {
  const files: string[] = []
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry)
      if (statSync(path).isDirectory()) walk(path)
      else files.push(path)
    }
  }
  for (const root of ['config', 'agents', 'souls']) walk(join(REPO, root))
  assert.ok(files.length >= 7, `only found ${String(files.length)} shipped files`)

  for (const path of files) {
    const rel = relative(REPO, path)
    const text = readFileSync(path, 'utf8')

    // Whole-file scan, not line-by-line: the bearer pattern deliberately spans
    // whitespace, and weakening the scan to make a file pass would be the
    // wrong repair.
    for (const pattern of TOKEN_PATTERNS) {
      const match = new RegExp(pattern.source, pattern.flags.replace('g', '')).exec(text)
      assert.equal(match, null, `${rel} holds a credential shape: ${String(match?.[0])}`)
    }

    // Key names, for the YAML files. kernel.yaml is walked by its own loader
    // too; this covers providers.yaml and the manifests, where a credential
    // would most plausibly be parked under a plausible-looking key.
    if (!rel.endsWith('.yaml')) continue
    const seen: string[] = []
    const keys = (value: unknown): void => {
      if (Array.isArray(value)) return value.forEach(keys)
      if (value === null || typeof value !== 'object') return
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        if (DENY_KEYS.test(key)) seen.push(key)
        keys(item)
      }
    }
    keys(parseYaml(text))
    assert.deepEqual(seen, [], `${rel} has secret-looking keys: ${seen.join(', ')}`)
  }
})
