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
import { DOCKER_NAMES } from '../scripts/install/preflight.js'
import { credentialNames, gitignoresDotenv, parseDotenv, PLACEHOLDER_PREFIX } from '../src/secrets/dotenv.js'
import { ConfigError } from '../src/errors.js'
import { CREDENTIAL_NAME } from './helpers/guard.js'
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
  // The kernel is pmmcp's client aos-kernel. Never a PMMCP_ name, which config
  // refuses (D34): that prefix is pmmcp's own, which its load_config reads.
  assert.equal(config.mcp.servers['pmmcp']?.tokenEnv, 'AOS_PMMCP_TOKEN')
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
    // Inside the program folder, under the git-ignored .aos/workspaces/, and
    // never $HOME: asserted here because this is the shipped value.
    assert.notEqual(domain.mountRoot, homedir())
    assert.equal(domain.mountRoot, join(REPO, '.aos', 'workspaces', name))
  }
  assert.equal(config.dataDir, join(REPO, '.aos'))
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
  // An EXISTING network is accepted only if it is internal: inside the VM the
  // Mac's loopback (where pmmcp listens unauthenticated) is one hop away.
  assert.ok(body.includes("network inspect --format '{{.Internal}}'"), 'checks an existing network is internal')
  assert.match(body, /if \[\[ "\$\{internal\}" != "true" \]\]; then[\s\S]*?exit 1/, 'refuses a non-internal network')
  // Invariant 9: the mounts are the domains' own roots, never $HOME.
  assert.equal(/--mount\s+"\$\{HOME\}:/.test(body), false, 'mounts $HOME')
  for (const domain of ['trusted', 'hostile']) {
    assert.ok(body.includes(`.aos/workspaces/${domain}`), `${domain} mountRoot`)
  }
  assert.equal(body.includes('--privileged'), false)
  assert.equal(body.includes('docker.sock:'), false, 'bind-mounts a docker socket')

  // Everything it writes stays in the program folder or ~/.colima (the one
  // home directory the operator allowed): not ~/.aos, not ~/.docker, not
  // ~/Library/Caches/colima.
  assert.ok(body.includes('TRUSTED_MOUNT="${REPO_ROOT}/.aos/workspaces/trusted"'))
  assert.ok(body.includes('export DOCKER_CONFIG="${REPO_ROOT}/.aos/docker"'))
  assert.ok(body.includes('export COLIMA_CACHE_HOME="${HOME}/.colima/'))
  assert.equal(body.includes('${HOME}/.aos'), false, 'a mount still points at ~/.aos')
  assert.equal(body.includes('docker --context'), false, 'a docker context lives in ~/.docker unless DOCKER_CONFIG moved it')
})

test('.npmrc keeps npm\'s cache in the program folder', () => {
  // npm resolves a relative path config against the shell's cwd
  // (@npmcli/config parse-field.js), so the README says to run npm from the root.
  assert.match(read('.npmrc'), /^cache=\.aos\/npm-cache$/m)
})

test('config/tool-views.yaml: pmmcp pins nineteen closed, and only the two kernel tools are exposed', () => {
  const file = parseToolViews(readYaml('config/tool-views.yaml'))
  const servers = Object.keys(file.servers).sort()
  assert.deepEqual(servers, ['kernel', 'pmmcp'])

  // The kernel section: exactly the two delegation tools, both `write` so a
  // tainted orchestrator needs a human for either. Anything else appearing here
  // would be a kernel capability handed to agents without its own review.
  // (The parser injects the forced kernel-only and disabled names into every
  // server section, this one included; those are unreachable by agents, so the
  // claim is about what is EXPOSED.)
  const exposedKernel = Object.entries(file.servers['kernel']!.tools).filter(([, v]) => v.exposure === 'agent')
  assert.deepEqual(exposedKernel.map(([n]) => n).sort(), ['adopt_plan', 'delegate'])
  for (const [name, view] of exposedKernel) {
    assert.equal(view.risk, 'write', `${name} must be write risk so a tainted run needs a human`)
  }

  // The nine forced (seven kernel-only, two disabled), plus ten the operator
  // pinned kernel-only explicitly after pmmcp's source was read: destructive,
  // vault-adjacent, or (scrape_context) an egress path around the proxy. Every
  // other pmmcp tool resolves kernel-only by the literal default.
  const forced = [...FORCED_KERNEL_ONLY, ...FORCED_DISABLED].sort()
  assert.equal(forced.length, 9)
  const operatorPinned = [
    'forget',
    'delete_secret',
    'list_secrets',
    'set_secret_expiry',
    'get_audit_logs',
    'save_secret_template',
    'get_secret_template',
    'repair_and_heal',
    'index_git_history',
    'scrape_context',
  ]
  const pinned = [...forced, ...operatorPinned].sort()
  assert.deepEqual(Object.keys(file.servers['pmmcp']!.tools).sort(), pinned)
  for (const name of operatorPinned) {
    assert.equal(resolveView(file, 'pmmcp', name).exposure, 'kernel-only', name)
  }

  // Written out, not merely injected by the parser: an audit of the file has to
  // be able to see the decision.
  const raw = read('config/tool-views.yaml')
  for (const name of pinned) assert.match(raw, new RegExp(`^\\s+${name}:$`, 'm'), name)

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

test('agents/*/agent.yaml parse against the shipped providers and tool-views; the ceo holds only the two kernel tools', (t) => {
  const store = withStore(t)
  const providers = new Set(Object.keys(parseProviders(readYaml('config/providers.yaml')).entries))
  const toolViews = parseToolViews(readYaml('config/tool-views.yaml'))

  // The real load path, against the real files. If a manifest named a tool the
  // views withhold, or a model ref providers.yaml does not carry, this throws.
  const reg = new AgentRegistry({
    providers,
    toolViews,
    store,
    // The SHIPPED ceilings, so the shipped manifests are checked against the
    // numbers the operator actually runs with.
    budgets: parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }).budgets,
  })
  reg.load(join(REPO, 'agents'))

  const ceo = reg.get('ceo')
  assert.ok(ceo, 'ceo did not load')
  assert.equal(ceo.manifest.kind, 'standard')
  assert.equal(ceo.manifest.role, 'orchestrator')
  assert.equal(ceo.manifest.tier, 2)
  assert.equal(ceo.manifest.model.primary, 'anthropic/claude-sonnet-5')
  assert.equal(ceo.manifest.memory.projectId, 'aos/ceo')

  // The two kernel tools and nothing else. No pmmcp tool is exposed to agents,
  // so the CEO can plan and delegate but not read memory; a pmmcp entry here would
  // be a grant the policy denies, refused at load.
  assert.deepEqual([...ceo.manifest.tools.allow].sort(), ['kernel.adopt_plan', 'kernel.delegate'])
  assert.equal(ceo.manifest.version, 2, 'adding tools is a version bump, with v1 frozen in history/')
  assert.ok(read('agents/ceo/history/agent.v1.yaml').includes('version: 1'))
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

  // ── the researcher/writer pair ──────────────────────────────────────────
  //
  // The fleet design's first rule is that an agent earns its manifest through a
  // distinct tool surface, taint posture, model binding, context boundary or gate
  // posture — otherwise it is a template or a tool view wearing a persona. With
  // nothing exposed to agents these two have the same (empty) tool surface, so the
  // distinctness has to come from somewhere the kernel enforces, and this asserts
  // it does.
  const researcher = reg.get('researcher')
  const writer = reg.get('writer')
  assert.ok(researcher, 'researcher did not load')
  assert.ok(writer, 'writer did not load')
  for (const record of [researcher, writer]) {
    assert.equal(record.manifest.kind, 'standard')
    assert.equal(record.manifest.role, 'worker', 'only the CEO is an orchestrator')
    assert.equal(record.manifest.model.primary, 'anthropic/claude-sonnet-5')
    assert.deepEqual(record.manifest.tools.allow, [])
    assert.deepEqual(record.manifest.egress.allow, [])
    assert.equal(record.manifest.spawn, undefined, 'a worker must not spawn')
    // No sandbox: the loop runs in process in this phase, so a domain here would
    // claim an isolation that does not happen.
    assert.equal(record.manifest.sandbox, undefined)
    // No schedule: the only routable model is a frontier one, and an unattended
    // run that can reach it is an unattended run that can empty an envelope.
    assert.equal(record.manifest.schedule, undefined)
  }

  // GATE POSTURE: read-only versus may-hold-write. Enforced by the gate at call
  // time and by the registry at load.
  assert.equal(researcher.manifest.tier, 1)
  assert.equal(writer.manifest.tier, 2)
  assert.notEqual(researcher.manifest.tier, writer.manifest.tier)

  // CONTEXT BOUNDARY: disjoint memory namespaces, and neither is the CEO's.
  assert.equal(researcher.manifest.memory.projectId, 'aos/agent/researcher')
  assert.equal(writer.manifest.memory.projectId, 'aos/agent/writer')
  const namespaces = reg.list().map((r) => r.manifest.memory.projectId)
  assert.equal(new Set(namespaces).size, namespaces.length, 'two agents share a memory namespace')

  // BUDGET: both lower the kernel ceilings, and differently. A pair with
  // identical caps would be one agent with two souls.
  const ceilings = parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }).budgets
  for (const record of [researcher, writer]) {
    const budget = record.manifest.budget
    assert.ok(budget, `${record.manifest.id} declares no budget`)
    assert.ok((budget.maxCostMicroUsd ?? 0) > 0)
    assert.ok(
      (budget.maxCostMicroUsd ?? Infinity) < ceilings.defaultRunMicroUsd,
      `${record.manifest.id} does not lower the cost ceiling`,
    )
    assert.ok((budget.maxLlmCalls ?? Infinity) < ceilings.maxLlmCallsPerRun)
  }
  assert.notDeepEqual(researcher.manifest.budget, writer.manifest.budget)

  // Invariant 8: AGENTS.md sits beside the manifest and no code path writes it.
  for (const id of ['ceo', 'researcher', 'writer']) {
    assert.ok(read(`agents/${id}/AGENTS.md`).length > 0, `${id} has no AGENTS.md`)
  }
  assert.equal(store.query({ type: 'agent.registered' }).length, 4)
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

test('.env.example is the placeholder-only template: exactly the accepted names, every value a placeholder the loader refuses', () => {
  // Committed to a PUBLIC repository and never filled in place: the operator's
  // real values live in the git-ignored .env, and nothing here may resemble one.
  const text = read('.env.example')
  const names = credentialNames(
    parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }),
    parseProviders(readYaml('config/providers.yaml')),
  )
  const lines = text.split('\n')
  assert.match(lines[0] ?? '', /^#/, 'the template must open with a comment')
  const assignments = lines
    .map((line, i) => ({ line, n: i + 1 }))
    .filter(({ line }) => line.trim() !== '' && !line.trim().startsWith('#'))
  const seen = assignments.map(({ line, n }) => {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line)
    assert.ok(m, `.env.example:${String(n)} is not NAME=value`)
    const value = m[2] ?? ''
    assert.ok(value.startsWith(`${PLACEHOLDER_PREFIX}-`), `.env.example:${String(n)} is not a ${PLACEHOLDER_PREFIX}- placeholder`)
    for (const pattern of TOKEN_PATTERNS) assert.equal(pattern.test(value), false, `.env.example:${String(n)} looks like a credential`)
    // The line above each assignment says what it is.
    assert.match(lines[n - 2] ?? '', /^# /, `.env.example:${String(n)} has no comment above it`)
    return m[1]
  })
  assert.deepEqual([...seen].sort(), [...names].sort(), 'the template and the accepted credential names have diverged')

  // Copied but not filled in: the loader refuses every line, by name.
  try {
    parseDotenv(text, names)
    assert.fail('the loader accepted the unfilled template')
  } catch (e) {
    assert.ok(e instanceof ConfigError)
    for (const name of names) assert.match(e.message, new RegExp(`${name} still holds the \\.env\\.example placeholder`))
  }
})

test('every credential name the shipped config declares is one test/helpers/guard.ts scrubs', () => {
  // A declared name the guard misses survives into every offline test process,
  // so a token the operator exported in the shell that runs npm test could be
  // read, logged or sent by any test. The falsify runner's copy of the pattern
  // is held equal to the guard's (falsify.test.ts), so this covers it too.
  const names = [
    ...credentialNames(
      parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }),
      parseProviders(readYaml('config/providers.yaml')),
    ),
  ].sort()
  // The declared bearer is among them, so this is not a check over a list that lost it.
  assert.ok(names.includes('AOS_PMMCP_TOKEN'), names.join(', '))
  for (const name of names) {
    assert.match(name, CREDENTIAL_NAME, `${name} is declared, and test/helpers/guard.ts does not scrub it`)
    // This file is no live test, so the guard has already removed each from
    // its environment. Checked by presence, never by value: node:test prints
    // what a failed assertion compared, and a value found here is a token the
    // operator exported (env.test.ts runs this check with a guard that
    // deletes nothing, and holds its output to the name).
    assert.ok(!Object.hasOwn(process.env, name), `${name} is still in an offline test's environment`)
  }
})

test('package.json passes --dotenv .env to dev, cli and eval and to nothing else; no script or .npmrc uses Node --env-file', () => {
  const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts
  for (const name of ['dev', 'cli', 'eval']) {
    assert.match(scripts[name] ?? '', / --dotenv \.env$/, `${name} does not pass --dotenv .env`)
  }
  // npm test above all: no test may open the operator's real .env.
  for (const [name, command] of Object.entries(scripts)) {
    if (['dev', 'cli', 'eval'].includes(name)) continue
    assert.equal(command.includes('--dotenv'), false, `${name} passes --dotenv`)
  }
  for (const command of Object.values(scripts)) assert.equal(command.includes('--env-file'), false)
  assert.equal(read('.npmrc').includes('env-file'), false)
})

test('package.json names the installer aos-install, never install/preinstall/postinstall, and it passes no --dotenv', () => {
  // npm runs a script named install (and its pre/post, and prepare) on every
  // `npm install`, which would start the installer, and its probes of pmmcp,
  // whenever dependencies are installed. So it is reached only by the name the
  // operator types, and runs the entry point and nothing else.
  const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts
  // A pattern, not a string: the entry-point rule (hygiene.test.ts) holds every string naming one to runEntry.
  assert.match(scripts['aos-install'] ?? '', /^node --import tsx scripts\/install\.ts$/)
  // `dependencies` too: npm runs it after any command that changes node_modules.
  for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare', 'dependencies']) {
    assert.equal(lifecycle in scripts, false, `package.json has a ${lifecycle} script, which npm install runs`)
  }
  // It reads .env only through the writer's inspection, never the loader's --dotenv.
  assert.equal((scripts['aos-install'] ?? '').includes('--dotenv'), false)
  // No other script runs it, by its file or by its name (`npm run aos-install` from a script npm runs on its own).
  const runners = Object.entries(scripts).filter(([, command]) => /\bscripts\/install(?:\.ts|\/)/.test(command) || /\baos-install\b/.test(command))
  assert.deepEqual(runners.map(([name]) => name), ['aos-install'], 'another script runs the installer')
})

test("README's installer section and D35 say what the installer does: the exports it names, the dry run's writes, the declared bearer's digest alone, flags after --, and the fresh install's one typed word", () => {
  const readme = read('README.md')
  const start = readme.indexOf('### Install with npm run aos-install')
  assert.notEqual(start, -1, 'README has no installer section')
  const section = readme.slice(start, readme.indexOf('### The `.env` file', start)).replace(/\s+/g, ' ')
  // The preflight names exactly these and PMMCP_*; the runner drops every other DOCKER_* without a word.
  for (const name of DOCKER_NAMES) assert.ok(section.includes(`\`${name}\``), `README does not name ${name}`)
  assert.match(section, /`DOCKER_CONTEXT` or `PMMCP_\*` your shell exports/)
  assert.doesNotMatch(section, /any `DOCKER_\*` or `PMMCP_\*` your shell exports/)
  assert.match(section, /`active\.json` too, while a `--jobs` count runs/)
  assert.match(section, /`kernel\.yaml` declares `AOS_PMMCP_TOKEN`, and pmmcp is given only the `sha256:` digest of that `aos-kernel` token, never the token/)
  assert.match(section, /The flags go after `--`: npm takes `npm run aos-install --dry-run` as its own `--dry-run`/)
  // 130 for any handled signal at a question or during the jobs count (the gate aborts the count), and 129 or 143 only before the window.
  assert.match(section, /130 interrupted before the stopped window opened \(129 and 143 for SIGHUP and SIGTERM; 130 for the input ending, or for any of those signals, at a question, which it answers, or during the jobs count, which it ends\)/)
  // After the window opened, a signal waits for the end report.
  assert.match(section, /From the window's first opening until the end report is printed, a signal outside the window \(at no question\) is held as well/)
  const row = readme.split('\n').find((l) => l.startsWith('| `npm run aos-install` |')) ?? ''
  assert.match(row, /stage pmmcp's `aos-kernel` digest of `AOS_PMMCP_TOKEN`; `npm run aos-install -- --dry-run` changes nothing/)
  // CLAUDE.md's Commands line names the dry run as npm must be given it.
  assert.match(read('CLAUDE.md'), /^npm run aos-install +# .*npm run aos-install -- --dry-run changes nothing/m)
  // D35's two typed confirmations, and the one exception the plan's Q24 makes.
  const d35 = read('docs/DECISIONS.md').split('\n').find((l) => l.startsWith('| D35 |')) ?? ''
  assert.match(d35, /a second typed `Persistent-Memory-MCP` \(one exception, the plan's Q24: on a fresh install the one typed `install` also covers the first stop and start/)
})

/** README's one-command capture: pmmcp's bearer from .env into that command's environment alone. */
const CAPTURE_COMMAND = `AOS_PMMCP_TOKEN="$(sed -n 's/^AOS_PMMCP_TOKEN=//p' .env)" npm run capture:pmmcp`

test('DECISIONS.md records D34 for the bearer kernel.yaml declares and keeps D37 open while capture:pmmcp reads no .env, README gives that capture a command that exports nothing, and the totals count the rows', () => {
  const decisions = read('docs/DECISIONS.md')
  const rows = decisions.split('\n')
  const row = (id: string): string => rows.find((l) => l.startsWith(`| ${id} |`)) ?? ''
  const tokenEnv = parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }).mcp.servers['pmmcp']?.tokenEnv
  assert.equal(tokenEnv, 'AOS_PMMCP_TOKEN')

  // D34: the name kernel.yaml declares, and why no PMMCP_ name, with what is still to come.
  const d34 = row('D34')
  assert.notEqual(d34, '', 'kernel.yaml declares pmmcp\'s bearer and DECISIONS.md has no D34 row for it')
  for (const fact of [`\`${String(tokenEnv)}\``, '`aos-kernel`', 'warn mode', '`load_config`', 'installer task A9', 'Q19']) {
    assert.ok(d34.includes(fact), `D34 does not say ${fact}`)
  }
  // A9's refusal is in src/config.ts (config.test.ts holds it), so D34 says it
  // is built, and leaves only the K3 amendment to come.
  assert.ok(d34.includes("A9's refusal built"), 'D34 still says A9\'s refusal is to come')
  assert.doesNotMatch(d34, /not built yet/)
  assert.doesNotMatch(decisions, /is recorded when/, 'DECISIONS.md still names a row it has not written')
  // The rule README states, with the row behind it.
  const readme = read('README.md')
  assert.match(readme, /No AOS credential name starts with `PMMCP_` \(decision D34\)/)

  // D37: open for as long as the capture takes no --dotenv, and meanwhile
  // README and the row give the same one-command form, which exports nothing.
  const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts
  assert.doesNotMatch(scripts['capture:pmmcp'] ?? '', /--dotenv/, 'capture:pmmcp reads .env now: answer D37 and drop CAPTURE_COMMAND')
  const d37 = row('D37')
  assert.match(d37, /\| open \|$/, 'D37 is no longer open while capture:pmmcp still reads no .env')
  assert.ok(d37.includes(`\`${CAPTURE_COMMAND}\``), 'D37 does not give README\'s command')
  const blocks = [...readme.matchAll(/^```(?:bash|sh|zsh|shell)\n([\s\S]*?)^```/gm)].map((m) => (m[1] ?? '').trim())
  assert.ok(blocks.includes(CAPTURE_COMMAND), 'README has no shell block that is exactly the one-command capture')
  for (const body of blocks) assert.doesNotMatch(body, /\bexport\b[^\n]*AOS_PMMCP_TOKEN/, `README exports pmmcp's bearer: ${body}`)

  // The totals are the rows this file holds.
  const totals = /\*\*Totals\.\*\* (\d+) Phase 0 decisions \(30 from the plan, D31 to D(\d+) added later\), (\d+) fleet\s+design decisions, (\d+) of them blocking\./.exec(decisions)
  assert.ok(totals, 'DECISIONS.md states its totals in another form')
  const ds = rows.filter((l) => /^\| D\d+ /.test(l)).length
  assert.equal(Number(totals[1]), ds, 'the Phase 0 total is not the number of D rows')
  assert.equal(Number(totals[2]), ds, 'the last D row added is not the total')
  assert.equal(Number(totals[3]), rows.filter((l) => /^\| Q\d+ /.test(l)).length, 'the fleet total is not the number of Q rows')
  assert.equal(Number(totals[4]), rows.filter((l) => /^\| \*\*[DQ]\d+\*\* /.test(l)).length, 'the blocking total is not the number of blocking rows')
})

test("no credential name the shipped config declares is in pmmcp's PMMCP_ prefix, and D34 claims config's refusal for a tokenEnv alone", () => {
  // src/config.ts refuses the prefix only as an MCP server's tokenEnv
  // (config.test.ts). A provider's auth.envVar is read from a shell export at
  // boot as well, and one in pmmcp's prefix would set a pmmcp setting, or stop
  // pmmcp, in any shell that starts it. The provider schema does not refuse
  // one (that change awaits the operator), so the shipped files are held here,
  // in any case, as pmmcp reads them.
  const names = [
    ...credentialNames(
      parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }),
      parseProviders(readYaml('config/providers.yaml')),
    ),
  ].sort()
  // A provider's key among them, so this is not a check over a list that lost them.
  assert.ok(names.includes('AOS_PMMCP_TOKEN') && names.some((n) => n.endsWith('_API_KEY')), names.join(', '))
  for (const name of names) assert.doesNotMatch(name, /^pmmcp_/i, `${name} is declared in pmmcp's PMMCP_ prefix (D34)`)

  // And D34 does not claim more than the code enforces.
  const d34 = read('docs/DECISIONS.md').split('\n').find((l) => l.startsWith('| D34 |')) ?? ''
  assert.doesNotMatch(d34, /no AOS credential name may start/, 'D34 claims a refusal for every credential name')
  assert.match(d34, /so no kernel `tokenEnv` may start with `PMMCP_`/)
  assert.match(d34, /A provider's `auth\.envVar` is not held to the prefix by `src\/models\/registry\.ts`/)
})

/** `text` in paragraphs, a list item or a table row each counted as one. */
function paragraphs(text: string): string[] {
  return text
    .split(/\n[ \t]*\n/)
    .flatMap((block) => block.split(/\n(?=[ \t]*(?:[-*] |\| ))/))
    .filter((p) => p.trim() !== '')
}

test("every place that says pmmcp's load_config refuses a PMMCP_ name says it is a checkout up to 53ea308 that refuses every one (D34)", () => {
  // pmmcp's 235992d narrowed the refusal: it reads PMMCP_<SECTION>__<KEY> as a
  // setting, stops on a bare section name or one that does not exist, and
  // leaves PMMCP_TOKEN alone. A sentence that says it refuses every PMMCP_
  // name is true only of a checkout up to 53ea308, and must say so.
  for (const rel of ['README.md', 'CLAUDE.md', 'config/kernel.yaml', 'scripts/install/run.ts', 'src/config.ts', 'docs/DECISIONS.md']) {
    const saying = paragraphs(read(rel)).filter((p) => p.includes('load_config') && p.includes('PMMCP_') && /refus/.test(p))
    assert.ok(saying.length > 0, `${rel} no longer says what pmmcp's load_config refuses: drop it from this list`)
    for (const p of saying) {
      assert.ok(p.includes('53ea308'), `${rel} says pmmcp's load_config refuses a PMMCP_ name and not which pmmcp: ${p.trim().slice(0, 160)}`)
    }
  }
})

test('every README shell block pastes cleanly into stock macOS zsh: no # comments', () => {
  // zsh does not set INTERACTIVE_COMMENTS, so a pasted `cmd  # note` passes
  // "#" and "note" to cmd (`npm run typecheck # must be clean` fails a clean
  // repo; `npm run falsify -- --list # ...` is refused as unknown suites), and
  // an apostrophe in the note opens a quote that swallows the lines after it.
  // So no block an operator copies carries one, whole-line or trailing.
  const readme = read('README.md')
  const blocks = [...readme.matchAll(/^```(?:bash|sh|zsh|shell)\n([\s\S]*?)^```/gm)].map((m) => m[1] ?? '')
  assert.ok(blocks.length >= 8, `only ${String(blocks.length)} shell blocks found in README; the matcher no longer sees them`)
  assert.ok(blocks.some((b) => b.includes('.env.example')), 'README has no shell block that creates .env')
  for (const body of blocks) {
    for (const line of body.split('\n')) assert.equal(line.includes('#'), false, `README shell line carries a comment: ${line}`)
  }
  // The same commands, quoted inside .env.example's own comments.
  const commands = read('.env.example')
    .split('\n')
    .filter((l) => l.startsWith('#   '))
    .map((l) => l.slice(4))
  assert.ok(commands.length >= 2, '.env.example no longer shows how to create .env')
  for (const command of commands) assert.equal(command.includes('#'), false, `.env.example command carries a comment: ${command}`)
})

test('.gitignore ignores .env*, editor copies, and un-ignores only .env.example', () => {
  assert.equal(gitignoresDotenv(REPO), true)
  const lines = read('.gitignore').split('\n').map((l) => l.trim())
  const ignore = lines.indexOf('.env*')
  assert.ok(ignore !== -1, '.gitignore has no .env* line')
  assert.ok(lines.indexOf('!.env.example') > ignore, '!.env.example must follow .env*')
  // Every negation, not only those that spell .env: `!*` or `!.en?` would
  // re-include the live file just the same.
  const negations = lines.filter((l) => l.startsWith('!'))
  assert.deepEqual(negations, ['!.env.example'], 'a negation re-includes more than the template')
  for (const editor of ['*~', '*.swp', '*.swo']) assert.ok(lines.includes(editor), `.gitignore misses ${editor}`)
})

test('.dockerignore keeps credentials, the event log and git history out of any build context', () => {
  const lines = read('.dockerignore').split('\n').map((l) => l.trim())
  for (const entry of ['.env*', '.aos/', '.git/']) assert.ok(lines.includes(entry), `.dockerignore misses ${entry}`)
  assert.equal(lines.some((l) => l.startsWith('!') && l.includes('.env')), false)
})
