// T17 — kernel.yaml schema.
//
// Config is where a security property is easiest to lose by accident: one
// edited string and the control plane listens to the world, or the event log
// moves somewhere an agent can reach. These tests are about which mistakes
// the file is CAPABLE of expressing, not about whether the shipped file is
// currently correct.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { assertNoSecretKeys, expandHome, parseKernelConfig } from '../src/config.js'

const REPO_ROOT = '/home/user/MrRobot'
const FIXTURES = new URL('./fixtures/config/', import.meta.url)

function fixture(name: string): unknown {
  return parseYaml(readFileSync(new URL(name, FIXTURES), 'utf8'))
}

function parse(doc: unknown, repoRoot = REPO_ROOT): ReturnType<typeof parseKernelConfig> {
  return parseKernelConfig(doc, { repoRoot })
}

test('parses a valid fixture', () => {
  const config = parse(fixture('valid.yaml'))

  assert.equal(config.version, 1)
  assert.equal(config.control.host, '127.0.0.1')
  assert.equal(config.control.port, 7777)
  assert.equal(config.dataDir, '/var/lib/aos')
  assert.equal(config.mcp.servers['pmmcp']?.url, 'http://127.0.0.1:8766/mcp')
  assert.equal(config.secrets.keyArg, 'label')
  assert.equal(config.sandbox.domains.hostile.network, 'aos-hostile')
  assert.equal(config.budgets.maxRetries, 2)

  // The minimal fixture proves the defaults are usable: everything a safe
  // default exists for is omitted, and the result is still complete.
  const minimal = parse(fixture('minimal.yaml'))
  assert.equal(minimal.control.host, '127.0.0.1')
  assert.equal(minimal.control.port, 7777)
  assert.equal(minimal.events.anchorEvery, 100)
  assert.equal(minimal.lanes.main, 4)
  assert.equal(minimal.budgets.approvalWaitMs, 300_000)
  assert.equal(minimal.sandbox.defaults.user, '65534:65534')
  assert.deepEqual(minimal.control.allowedOrigins, [])
})

test('rejects control.host other than 127.0.0.1', () => {
  // There is no spelling of this file that binds the control plane to a
  // public interface. Not a validated string; a literal.
  for (const host of ['0.0.0.0', '::', 'localhost', '192.168.1.10', '127.0.0.2']) {
    const doc = fixture('valid.yaml') as { control: { host: string } }
    doc.control.host = host
    assert.throws(() => parse(doc), /invalid/, `control.host: ${host} must be refused`)
  }
})

test('rejects unknown keys', () => {
  // A typo that parses is a setting the operator believes is active.
  const doc = fixture('valid.yaml') as Record<string, unknown>
  assert.throws(() => parse({ ...doc, budgts: { maxRetries: 0 } }), /invalid/)

  const nested = fixture('valid.yaml') as { control: Record<string, unknown> }
  nested.control['allowOrigins'] = []
  assert.throws(() => parse(nested), /invalid/)

  const sandbox = fixture('valid.yaml') as { sandbox: Record<string, unknown> }
  sandbox.sandbox['privileged'] = true
  assert.throws(() => parse(sandbox), /invalid/)
})

test('rejects a secret-looking key anywhere and names the path', () => {
  // The walk runs on the RAW document, before parsing drops unknown keys, so
  // a secret hiding under a key the schema never reads is still caught.
  const cases: [Record<string, unknown>, RegExp][] = [
    [{ version: 1, apiKey: 'sk-FAKE' }, /apiKey/],
    [{ version: 1, control: { token: 'FAKE' } }, /control\.token/],
    [{ version: 1, mcp: { servers: { pmmcp: { password: 'FAKE' } } } }, /mcp\.servers\.pmmcp\.password/],
    [{ version: 1, sandbox: { domains: { trusted: { client_secret: 'FAKE' } } } }, /client_secret/],
    [{ version: 1, list: [{ authorization: 'Bearer FAKE' }] }, /list\.0\.authorization/],
  ]
  for (const [doc, path] of cases) {
    assert.throws(() => parse(doc), /holds no secrets/, `${JSON.stringify(doc)} must be refused`)
    // The path is named: "there is a secret somewhere in your config" is not
    // an actionable error.
    assert.throws(() => parse(doc), path)
  }

  // Referencing a secret by environment variable NAME is the supported way,
  // and must keep working.
  assert.doesNotThrow(() => assertNoSecretKeys({ tokenEnv: 'PMMCP_TOKEN', vaultId: 'anthropic-api-key' }))
})

test('rejects a non-loopback pmmcp url', () => {
  for (const url of [
    'https://pmmcp.example.com/mcp',
    'http://10.0.0.5:8766/mcp',
    'http://0.0.0.0:8766/mcp',
    'not-a-url',
  ]) {
    const doc = fixture('valid.yaml') as { mcp: { servers: Record<string, { url: string }> } }
    const server = doc.mcp.servers['pmmcp']
    if (server !== undefined) server.url = url
    assert.throws(() => parse(doc), /invalid/, `${url} must be refused`)
  }

  // pmmcp is mandatory: a config without it would boot a kernel with no
  // memory and no vault, which is a silent degradation.
  const noPmmcp = fixture('valid.yaml') as { mcp: { servers: Record<string, unknown> } }
  delete noPmmcp.mcp.servers['pmmcp']
  assert.throws(() => parse(noPmmcp), /must include pmmcp/)
})

test('rejects a mountRoot or dataDir under the repo root or equal to $HOME', () => {
  const inRepo = fixture('valid.yaml') as { dataDir: string }
  inRepo.dataDir = join(REPO_ROOT, '.aos')
  assert.throws(() => parse(inRepo), /inside the repository/)

  const mountInRepo = fixture('valid.yaml') as {
    sandbox: { domains: { hostile: { mountRoot: string } } }
  }
  mountInRepo.sandbox.domains.hostile.mountRoot = join(REPO_ROOT, 'workspaces')
  assert.throws(() => parse(mountInRepo), /inside the repository/)

  // $HOME itself as a mount root would hand a container everything.
  const home = fixture('valid.yaml') as { dataDir: string }
  home.dataDir = homedir()
  assert.throws(() => parse(home), /must not be \$HOME itself/)

  // A directory UNDER home is fine, and ~ expands.
  const under = fixture('valid.yaml') as { dataDir: string }
  under.dataDir = '~/.aos'
  assert.equal(parse(under).dataDir, join(homedir(), '.aos'))
  assert.equal(expandHome('~'), homedir())
  assert.equal(expandHome('/absolute/path'), '/absolute/path')
})

test('rejects an allowedOrigins entry that is not tauri://localhost or loopback http(s)', () => {
  const withOrigins = (origins: string[]): unknown => {
    const doc = fixture('valid.yaml') as { control: { allowedOrigins: string[] } }
    doc.control.allowedOrigins = origins
    return doc
  }

  // The Tauri webview origin and loopback pages are the only callers that
  // can legitimately exist (D10).
  assert.doesNotThrow(() => parse(withOrigins(['tauri://localhost'])))
  assert.doesNotThrow(() => parse(withOrigins(['http://127.0.0.1:1420', 'http://localhost:5173'])))

  for (const origin of [
    'https://app.example.com',
    'http://evil.example.com',
    'file://',
    'tauri://evil',
    '*',
  ]) {
    assert.throws(() => parse(withOrigins([origin])), /invalid/, `${origin} must be refused`)
  }
})

test('budgets cannot be zero or negative', () => {
  // A budget that can be switched off is not a budget. No field admits
  // "unlimited", including by spelling it 0.
  const fields = [
    'defaultRunMicroUsd',
    'defaultWallclockMs',
    'maxLlmCallsPerRun',
    'maxToolCallsPerRun',
    'approvalWaitMs',
  ] as const

  for (const field of fields) {
    for (const value of [0, -1]) {
      const doc = fixture('valid.yaml') as { budgets: Record<string, number> }
      doc.budgets[field] = value
      assert.throws(() => parse(doc), /invalid/, `budgets.${field} = ${String(value)} must be refused`)
    }
  }

  // maxRetries is the one field allowed to be 0 — no retries is a valid
  // policy — but it is capped, so a typo cannot mean "retry forever".
  const noRetries = fixture('valid.yaml') as { budgets: Record<string, number> }
  noRetries.budgets['maxRetries'] = 0
  assert.equal(parse(noRetries).budgets.maxRetries, 0)

  const tooMany = fixture('valid.yaml') as { budgets: Record<string, number> }
  tooMany.budgets['maxRetries'] = 99
  assert.throws(() => parse(tooMany), /invalid/)

  // Lane caps and payload size are positive too.
  const lanes = fixture('valid.yaml') as { lanes: Record<string, number> }
  lanes.lanes['main'] = 0
  assert.throws(() => parse(lanes), /invalid/)
})

test('envFallback defaults to false', () => {
  // Reading a credential from the environment widens what the kernel trusts,
  // so it is opt-in, never the default.
  assert.equal(parse(fixture('minimal.yaml')).secrets.envFallback, false)
  assert.equal(parse(fixture('valid.yaml')).secrets.envFallback, false)

  const on = fixture('valid.yaml') as { secrets: { envFallback: boolean } }
  on.secrets.envFallback = true
  assert.equal(parse(on).secrets.envFallback, true, 'it can be turned on deliberately')

  // keyArg carries the operator-confirmed argument name.
  assert.equal(parse(fixture('minimal.yaml')).secrets.keyArg, 'label')
})

test('a ~ in sandbox dockerHost is expanded; a relative socket path is refused', () => {
  // DOCKER_HOST goes to the docker CLI, which the driver spawns without a
  // shell. Nothing downstream expands ~, so an unexpanded value is a config
  // that reads correctly and cannot connect — the exact failure this repo
  // refuses to ship. Colima keeps its sockets under $HOME, so ~ is the form an
  // operator writes.
  const doc = fixture('valid.yaml') as {
    sandbox: { domains: Record<string, { dockerHost: string }> }
  }
  doc.sandbox.domains['trusted']!.dockerHost = 'unix://~/.colima/trusted/docker.sock'
  doc.sandbox.domains['hostile']!.dockerHost = 'unix://~/.colima/hostile/docker.sock'

  const config = parse(doc)
  assert.equal(config.sandbox.domains.trusted.dockerHost, `unix://${join(homedir(), '.colima/trusted/docker.sock')}`)
  assert.equal(config.sandbox.domains.hostile.dockerHost, `unix://${join(homedir(), '.colima/hostile/docker.sock')}`)
  // Three slashes, not two: the expanded form is an absolute path.
  assert.match(config.sandbox.domains.trusted.dockerHost, /^unix:\/\/\//)
  assert.equal(config.sandbox.domains.trusted.dockerHost.includes('~'), false)

  // An absolute socket is passed through unchanged.
  const plain = fixture('valid.yaml')
  assert.equal(parse(plain).sandbox.domains.trusted.dockerHost, 'unix:///var/run/colima-trusted.sock')

  // A relative path would never resolve, so it is refused rather than handed
  // to docker to fail on.
  for (const bad of ['unix://relative/docker.sock', 'unix://./docker.sock', 'unix://']) {
    const broken = fixture('valid.yaml') as { sandbox: { domains: Record<string, { dockerHost: string }> } }
    broken.sandbox.domains['trusted']!.dockerHost = bad
    assert.throws(() => parse(broken), /must resolve to an absolute socket path/, bad)
  }
})

test('a ~ mountRoot resolves; a relative one is still refused', () => {
  // The check exists to refuse a RELATIVE mountRoot — one that resolves
  // against whatever directory the daemon started in, putting a container's
  // mount somewhere nobody chose. A ~ path is anchored, and the loader expands
  // it, so rejecting the raw string refused the one form an operator writes.
  const doc = fixture('valid.yaml') as { sandbox: { domains: Record<string, { mountRoot: string }> } }
  doc.sandbox.domains['trusted']!.mountRoot = '~/.aos/workspaces/trusted'
  doc.sandbox.domains['hostile']!.mountRoot = '~/.aos/workspaces/hostile'

  const config = parse(doc)
  assert.equal(config.sandbox.domains.trusted.mountRoot, join(homedir(), '.aos/workspaces/trusted'))
  assert.equal(config.sandbox.domains.hostile.mountRoot, join(homedir(), '.aos/workspaces/hostile'))

  for (const bad of ['workspaces/trusted', './trusted', '../outside']) {
    const broken = fixture('valid.yaml') as { sandbox: { domains: Record<string, { mountRoot: string }> } }
    broken.sandbox.domains['trusted']!.mountRoot = bad
    assert.throws(() => parse(broken), /mountRoot must be absolute/, bad)
  }

  // And ~ itself is still $HOME, which is refused for the usual reason: it
  // would hand a container everything.
  const home = fixture('valid.yaml') as { sandbox: { domains: Record<string, { mountRoot: string }> } }
  home.sandbox.domains['trusted']!.mountRoot = '~'
  assert.throws(() => parse(home), /must not be \$HOME itself/)
})
