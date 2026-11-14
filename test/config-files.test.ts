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
//   Merge an older package-lock.json and `npm ci` installs a release an
//   advisory was fixed after; range-pin a dependency and `npm install` moves it
//   on its own. The lockfile tests read every copy, nested ones included.
//   Lose sandbox.imageId between kernel.yaml and the driver boot builds and a
//   pinned kernel.yaml boots with its sandbox degraded for an unset id.
//   Let the worker Dockerfile's FROM fall back to a tag or a placeholder
//   digest, its proxy ENV drift off the mux's port, a RUN do more than its
//   pinned text, or its gitconfig take a credential helper, and every image
//   built from it says so nowhere; let the build script's code change by a
//   line, call docker before its plan is checked, or under any environment
//   but the kernel's own, or its plan take another spelling of the default
//   Colima profile's socket, and it builds on a socket nobody chose.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { linkSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { parse as parseYaml } from 'yaml'

import { EGRESS_MUX_PORT, parseKernelConfig, type KernelConfig } from '../src/config.js'
import { defaultDriver } from '../src/kernel.js'
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
import { APPROVAL_PREVIEW_BYTES } from '../src/policy/engine.js'
import { CAPTURE_EDGE_BYTES, DOCKER_CLI_FAILED, JWT_RUN_STARTS_MAX, KILL_WAIT_MS, RESULT_GRACE_MS, STREAM_WINDOW_BYTES } from '../src/runtime/sandbox-tools.js'
import { CAPTURE_MAX_BYTES } from '../src/sandbox/driver.js'
import { STOP_REQUESTED } from '../src/runtime/loop.js'
import { CATALOG } from '../scripts/falsify/catalog.js'
import { WORKSPACE_TARGET } from '../src/sandbox/docker.js'
import { FORCE_QUIT_LOG, PMMCP_OLLAMA_NAMES } from '../scripts/install/force-quit.js'
import { DOCKER_NAMES } from '../scripts/install/preflight.js'
import {
  baseProblem,
  macSockets,
  namesDefaultColima,
  notPlainAscii,
  parserDirectives,
  planFrom,
  planText,
  readDockerfile,
  WORKER_BASE,
  workerImagePlan,
  type DockerInstruction,
} from '../scripts/worker-image.js'
import { credentialNames, gitignoresDotenv, parseDotenv, PLACEHOLDER_PREFIX } from '../src/secrets/dotenv.js'
import { ConfigError } from '../src/errors.js'
import { EGRESS_CHECKS } from '../src/events/types.js'
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

test('config/kernel.yaml pins no sandbox.imageId, so the driver boot builds from it is degraded, naming the key, and asks docker nothing; pinned, it asks the daemons', async () => {
  // Egress plan P4: no worker image is built yet, so the shipped file pins no
  // id, and the tag beside it is a name no run executes. The driver is the one
  // boot builds (defaultDriver), with only the docker CLI's two process
  // functions swapped for ones that answer as a healthy daemon would: what
  // kernel.yaml holds is what decides.
  const raw = read('config/kernel.yaml')
  assert.match(raw, /^ {2}image: aos-worker:0\.0\.1$/m)
  assert.doesNotMatch(raw, /^ {2}imageId:/m)
  const probeOf = async (text: string): Promise<{ why: string; calls: string[][] }> => {
    const calls: string[][] = []
    const driver = defaultDriver(parseKernelConfig(parseYaml(text), { repoRoot: REPO }), REPO, {
      spawn: (_command, args) => {
        calls.push([...args])
        throw new Error('a probe starts no run')
      },
      execFile: (_command, args) => {
        calls.push([...args])
        return Promise.resolve({
          stdout: args[0] === 'network' ? 'true\n' : args[0] === 'image' ? `${args[args.length - 1] ?? ''}\n` : '29.5.2\n',
          stderr: '',
        })
      },
    })
    const probe = await driver.probe()
    return { why: probe.ok ? '' : probe.why, calls }
  }

  const shipped = await probeOf(raw)
  assert.match(shipped.why, /^sandbox\.imageId is not set in config\/kernel\.yaml/)
  assert.deepEqual(shipped.calls, [], 'the shipped config had docker asked something')

  const id = `sha256:${'0123456789abcdef'.repeat(4)}`
  const pinned = await probeOf(raw.replace('  image: aos-worker:0.0.1\n', `  image: aos-worker:0.0.1\n  imageId: ${id}\n`))
  assert.equal(pinned.why, '')
  assert.deepEqual(pinned.calls.map((args) => args.slice(0, 2)), [
    ['version', '--format'],
    ['network', 'inspect'],
    ['image', 'inspect'],
    ['network', 'inspect'],
    ['image', 'inspect'],
  ])
  // The image each VM is asked for is the id kernel.yaml pins, by that id.
  assert.deepEqual(pinned.calls.filter((args) => args[0] === 'image').map((args) => args[args.length - 1]), [id, id])
})

test('defaultDriver takes only spawn and execFile from the processes a test hands it: an imageId, domains or dockerConfig beside them never overrides kernel.yaml', async () => {
  // TypeScript checks no excess property on an argument that is not a
  // literal, so a DockerProcesses value may carry more than its two
  // functions. Spread over what kernel.yaml produced, those keys would decide
  // the driver, and the tests above, meant to prove that kernel.yaml decides,
  // would prove something else. Here each extra key names something
  // kernel.yaml does not: a pinned id while kernel.yaml pins none, and
  // another socket and DOCKER_CONFIG.
  const raw = read('config/kernel.yaml')
  const config = parseKernelConfig(parseYaml(raw), { repoRoot: REPO })
  assert.equal(config.sandbox.imageId, undefined)
  const calls: { args: readonly string[]; env: Record<string, string> }[] = []
  const elsewhere = { dockerHost: 'unix:///tmp/elsewhere.sock', mountRoot: '/tmp/elsewhere', network: 'aos-elsewhere' }
  const processes = {
    spawn: () => {
      throw new Error('a probe starts no run')
    },
    execFile: (_command: string, args: readonly string[], options: { env: Record<string, string> }) => {
      calls.push({ args, env: options.env })
      return Promise.resolve({
        stdout: args[0] === 'network' ? 'true\n' : args[0] === 'image' ? `${args[args.length - 1] ?? ''}\n` : '29.5.2\n',
        stderr: '',
      })
    },
    imageId: `sha256:${'0123456789abcdef'.repeat(4)}`,
    domains: { trusted: elsewhere, hostile: elsewhere },
    dockerConfig: '/tmp/elsewhere-docker',
  }
  const unpinned = await defaultDriver(config, REPO, processes).probe()
  assert.match(unpinned.ok ? '' : unpinned.why, /^sandbox\.imageId is not set in config\/kernel\.yaml/, 'an imageId beside the processes was pinned')
  assert.equal(calls.length, 0, 'the shipped config had docker asked something')

  // Pinned in kernel.yaml, the daemons are asked, through kernel.yaml's
  // sockets and DOCKER_CONFIG, for kernel.yaml's id.
  const id = `sha256:${'f'.repeat(64)}`
  const pinned = parseKernelConfig(parseYaml(raw.replace('  image: aos-worker:0.0.1\n', `  image: aos-worker:0.0.1\n  imageId: ${id}\n`)), { repoRoot: REPO })
  assert.deepEqual(await defaultDriver(pinned, REPO, processes).probe(), { ok: true, version: '29.5.2' })
  assert.deepEqual(calls.filter((c) => c.args[0] === 'image').map((c) => c.args[c.args.length - 1]), [id, id])
  assert.deepEqual(
    calls.map((c) => c.env['DOCKER_HOST']),
    [
      pinned.sandbox.domains.trusted.dockerHost,
      pinned.sandbox.domains.trusted.dockerHost,
      pinned.sandbox.domains.trusted.dockerHost,
      pinned.sandbox.domains.hostile.dockerHost,
      pinned.sandbox.domains.hostile.dockerHost,
    ],
  )
  for (const call of calls) assert.equal(call.env['DOCKER_CONFIG'], join(pinned.dataDir, 'docker'))
  // And each VM was asked about kernel.yaml's own network, not the extra one.
  assert.deepEqual(
    calls.filter((c) => c.args[0] === 'network').map((c) => c.args[c.args.length - 1]),
    [pinned.sandbox.domains.trusted.network, pinned.sandbox.domains.hostile.network],
  )
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

/**
 * readDockerfile's instructions (scripts/worker-image.ts, the reading the
 * build's plan checks the base with), for a Dockerfile whose reading is
 * certain: no empty line inside a continued instruction, no `\\` with a space
 * or tab after it, and none left open at the end.
 */
function dockerInstructions(text: string): readonly DockerInstruction[] {
  const { steps, emptyContinued, spacedContinued, unterminated } = readDockerfile(text)
  assert.equal(unterminated, false, 'the Dockerfile ends inside a continued line')
  assert.deepEqual(emptyContinued, [], `an empty line inside a continued instruction, on line ${emptyContinued.join(', ')}: BuildKit joins the line after it on, with a warning`)
  assert.deepEqual(spacedContinued, [], `a \\ with a space or tab after it, on line ${spacedContinued.join(', ')}`)
  return steps
}

/** An ENV instruction's pairs, in the KEY=value and KEY="value" forms only: the legacy `ENV KEY value` form, or anything else, fails. */
function envPairs(args: string): [string, string][] {
  const out: [string, string][] = []
  const pair = /([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"\\]*)"|([^\s"\\]*))(?:\s+|$)/y
  for (let at = 0; at < args.length; at = pair.lastIndex) {
    pair.lastIndex = at
    const m = pair.exec(args)
    assert.ok(m !== null, `ENV ${args.slice(at)} is not KEY=value or KEY="value"`)
    out.push([m[1] ?? '', m[2] ?? m[3] ?? ''])
  }
  return out
}

/** A git config file's entries, `section[.subsection].key` (section and key lower-cased, as git reads them) to every value given. A line git would read any other way fails. */
function gitConfigEntries(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>()
  let section: string | undefined
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue
    const header = /^\[([A-Za-z0-9.-]+)(?:\s+"([^"\\]*)")?\]$/.exec(line)
    if (header !== null) {
      const name = (header[1] ?? '').toLowerCase()
      section = header[2] === undefined ? name : `${name}.${header[2]}`
      continue
    }
    const entry = /^([A-Za-z][A-Za-z0-9-]*)\s*=\s*([^#;"\\]*)$/.exec(line)
    assert.ok(entry !== null && section !== undefined, `a gitconfig line this test does not read as git would: ${line}`)
    const key = `${section}.${(entry[1] ?? '').toLowerCase()}`
    out.set(key, [...(out.get(key) ?? []), (entry[2] ?? '').trim()])
  }
  return out
}

/** The environment of every docker call boot's driver makes for kernel.yaml as shipped, pinned to an id so that it asks the daemons. */
async function driverDockerEnvs(): Promise<Record<string, string>[]> {
  const envs: Record<string, string>[] = []
  const id = `sha256:${'0123456789abcdef'.repeat(4)}`
  const pinned = parseKernelConfig(parseYaml(read('config/kernel.yaml').replace('  image: aos-worker:0.0.1\n', `  image: aos-worker:0.0.1\n  imageId: ${id}\n`)), { repoRoot: REPO })
  const probe = await defaultDriver(pinned, REPO, {
    spawn: () => {
      throw new Error('a probe starts no run')
    },
    execFile: (_command: string, args: readonly string[], options: { env: Record<string, string> }) => {
      envs.push(options.env)
      return Promise.resolve({
        stdout: args[0] === 'network' ? 'true\n' : args[0] === 'image' ? `${args[args.length - 1] ?? ''}\n` : '29.5.2\n',
        stderr: '',
      })
    },
  }).probe()
  assert.deepEqual(probe, { ok: true, version: '29.5.2' })
  assert.ok(envs.length > 0, 'the driver asked docker nothing')
  return envs
}

test('the worker Dockerfile FROM is pinned by digest, USER is 65534:65534, the proxy ENV is 127.0.0.1:3128 with NO_PROXY empty, and it sets no credential or credential helper', () => {
  // Egress plan I1. The image is what every sandboxed run executes, by the id
  // scripts/build-worker-image.sh prints. Nothing in it is a boundary (the
  // agent's uid can override all of it), but each line here is something an
  // honest worker relies on to send its requests where the kernel's egress
  // engine judges them, and something a later edit could quietly undo.
  const text = read('images/worker/Dockerfile')
  // Every file BuildKit or git reads as configuration (the Dockerfile,
  // gitconfig and .dockerignore) is printable ASCII, tabs and newlines (the
  // mux the image copies is code Node reads, and holds box-drawing rules in
  // its comments), so this test's readers and BuildKit's (Go's
  // unicode.IsSpace, its trimNewline) cannot differ on a character: U+FEFF
  // between two ENV pairs is white space to JavaScript's \s and part of a
  // word to BuildKit, and a CRLF ending is one \r to drop here and every \r
  // to it.
  for (const rel of ['images/worker/Dockerfile', 'images/worker/gitconfig', 'images/worker/.dockerignore']) {
    assert.deepEqual(notPlainAscii(read(rel)), [], `${rel} holds a character that is not printable ASCII, a tab or a newline`)
  }
  assert.deepEqual(notPlainAscii(text.replace('    NO_PROXY="" \\\n    no_proxy="" \\\n', '    NO_PROXY=""\uFEFFno_proxy="" \\\n')), ['U+FEFF'])
  assert.deepEqual(notPlainAscii(text.replaceAll('\n', '\r\n')), ['U+000D'])
  assert.deepEqual(notPlainAscii('\u00a0\u0085\u00a0\u{1F600}\t \n~'), ['U+00A0', 'U+0085', 'U+1F600'])
  // The controls beside the printable range, DEL and VT among them: bash's
  // blanks are space and tab alone, so \v starts a word to it.
  assert.deepEqual(notPlainAscii('\x7f\v\f\x1f'), ['U+007F', 'U+000B', 'U+000C', 'U+001F'])
  const steps = dockerInstructions(text)
  const of = (keyword: string): string[] => steps.filter((s) => s.keyword === keyword).map((s) => s.args)
  const config = parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO })

  // The operator's base, by the digest of its index, and only it: a second
  // FROM would be a stage built from a base nobody pinned. The build script
  // reads the same line, through baseProblem (the next test but one).
  // No parser directive: escape would change how this test's reading joins
  // lines (and a RUN's text with it), and syntax has BuildKit pull a frontend
  // by its tag. A directive is read only before any other line, a comment
  // included, so line 1 is the only place one can start; BuildKit reads it
  // there past a byte-order mark or leading white space, and past a shebang
  // for syntax (parserDirectives). The rows below are each such a line 1.
  assert.deepEqual(parserDirectives(text), [], 'the Dockerfile starts with a parser directive')
  const rest = text.slice(text.indexOf('\n'))
  for (const first of [' # escape=`', '\uFEFF# escape=`', '\t# syntax=docker/dockerfile:1', '\u0085#escape=`', '\u3000# check=skip=all', '// syntax=docker/dockerfile:1', '#!/usr/bin/env docker\n# syntax=docker/dockerfile:1']) {
    assert.notDeepEqual(parserDirectives(`${first}${rest}`), [], `${JSON.stringify(first)} is not read as a directive`)
  }
  // An empty line inside a continued instruction is skipped, and the line
  // after it joined on: a `\` left after ENTRYPOINT [] would make the image's
  // entrypoint the shell form `[] USER 65534:65534`, with no USER. Refused.
  const r5 = text.replace('ENTRYPOINT []\n', 'ENTRYPOINT [] \\\n')
  assert.notEqual(r5, text)
  const read5 = readDockerfile(r5)
  assert.deepEqual(read5.steps.slice(-1), [{ keyword: 'ENTRYPOINT', args: '[] USER 65534:65534', text: 'ENTRYPOINT [] USER 65534:65534' }])
  assert.equal(read5.emptyContinued.length, 1)
  assert.throws(() => dockerInstructions(r5), /an empty line inside a continued instruction, on line \d+: BuildKit joins the line after it on/)
  assert.throws(() => dockerInstructions(text.replace(/\nUSER 65534:65534\n?$/, '\nUSER 65534:65534 \\\n')), /ends inside a continued line/)
  // An instruction the file ends inside BuildKit reads as it stands, and so
  // does readDockerfile: a FROM left open at the end is a second stage.
  assert.deepEqual(readDockerfile('FROM a\nFROM b \\').steps.map((s) => s.text), ['FROM a', 'FROM b'])
  // A last \n ends the last line and starts none (BuildKit's scanner), so a
  // file that ends inside a continued line has no empty line inside it.
  assert.deepEqual(readDockerfile('FROM a \\\n'), { steps: [{ keyword: 'FROM', args: 'a', text: 'FROM a' }], emptyContinued: [], spacedContinued: [], unterminated: true })
  assert.deepEqual(readDockerfile('FROM a \\\n\n').emptyContinued, [2])
  // Every \r at a line's end is dropped, as BuildKit's trimNewline drops
  // them, so `FR\` before two of them still continues; and a `\` with a space
  // or tab after it is reported: whether BuildKit's join keeps that space is
  // not checked here, and FROM\ then debian:latest is FROM debian:latest
  // if it does and FROMdebian:latest if not.
  assert.deepEqual(readDockerfile('FR\\\r\r\nOM a\n').steps.map((s) => s.text), ['FROM a'])
  assert.deepEqual(readDockerfile('FROM a\nRUN b \\ \nc\nRUN d\\\t\ne\n'), {
    steps: [
      { keyword: 'FROM', args: 'a', text: 'FROM a' },
      { keyword: 'RUN', args: 'b c', text: 'RUN b c' },
      { keyword: 'RUN', args: 'de', text: 'RUN de' },
    ],
    emptyContinued: [],
    spacedContinued: [2, 4],
    unterminated: false,
  })
  const spaced = text.replace('RUN apt-get update \\\n', 'RUN apt-get update \\ \n')
  assert.notEqual(spaced, text)
  assert.throws(() => dockerInstructions(spaced), /a \\ with a space or tab after it, on line \d+/)
  assert.equal(steps[0]?.keyword, 'FROM', 'the first instruction is not FROM')
  assert.equal(of('FROM').length, 1, 'a second FROM is a second stage, from a base nobody pinned')
  const base = of('FROM')[0] ?? ''
  assert.match(base, /^node:24-bookworm-slim@sha256:[0-9a-f]{64}$/)
  assert.doesNotMatch(base, /@sha256:([0-9a-f])\1{63}$/, 'the base digest is a placeholder')
  assert.ok(base.startsWith(`${WORKER_BASE}@`), base)
  assert.equal(baseProblem(text), undefined)

  // Only these instructions. No ARG: a build argument is how a credential
  // reaches a build, and it stays in the image's history. No ADD: it fetches
  // URLs and unpacks archives. No CMD, SHELL, VOLUME or ONBUILD either.
  assert.deepEqual([...new Set(steps.map((s) => s.keyword))].sort(), ['COPY', 'ENTRYPOINT', 'ENV', 'FROM', 'RUN', 'USER'])

  // One USER, the driver's own --user (kernel.yaml's sandbox.defaults.user),
  // and last: every build step runs as root, nothing after it changes whose
  // image it is.
  assert.deepEqual(of('USER'), ['65534:65534'])
  assert.equal(config.sandbox.defaults.user, '65534:65534')
  assert.equal(steps.at(-1)?.keyword, 'USER', 'an instruction follows USER')

  // The proxy is the mux, on the port kernel.yaml's egress.muxPort names
  // (config.ts holds it to EGRESS_MUX_PORT); both spellings, because libcurl,
  // which git uses, reads only the lower-case http_proxy. NO_PROXY empty in
  // both: no host is meant to be reached any other way. And nothing else: no
  // GIT_ASKPASS, no token, no credential of any name, set once each.
  const pairs = of('ENV').flatMap(envPairs)
  const env = new Map(pairs)
  assert.equal(env.size, pairs.length, 'an ENV name is set twice')
  assert.equal(config.egress.muxPort, EGRESS_MUX_PORT)
  const proxy = `http://127.0.0.1:${String(EGRESS_MUX_PORT)}`
  assert.deepEqual(Object.fromEntries(env), {
    HTTP_PROXY: proxy,
    HTTPS_PROXY: proxy,
    http_proxy: proxy,
    https_proxy: proxy,
    NO_PROXY: '',
    no_proxy: '',
    NODE_USE_ENV_PROXY: '1',
    GIT_TERMINAL_PROMPT: '0',
    HOME: '/tmp',
  })
  for (const name of env.keys()) assert.doesNotMatch(name, DENY_KEYS, `ENV ${name} is a name the log censors as a credential`)
  // What reads them: git's libcurl and Node. The image has no curl, so the
  // Dockerfile names it once, to say so.
  assert.deepEqual(
    [...text.matchAll(/^.*\bcurl\b.*$/gm)].map((m) => m[0]),
    ['# no curl (the slim base purges it, and apt adds only git and a CA store). The'],
  )
  // NODE_USE_ENV_PROXY=1 has two effects on Node 22.22 that its README row
  // has the operator check on the image's Node: a warning on every node
  // process's stderr, and loopback HTTP sent to the mux (NO_PROXY is empty),
  // which the Phase 2 exit's fixture repository keeps its tests off.
  const row = read('README.md').split('\n').find((l) => l.startsWith('| `scripts/build-worker-image.sh` and `images/worker/Dockerfile`, each marked NEEDS VALIDATION')) ?? ''
  // And, since the build's plan refuses a socket that is the same file as
  // ~/.colima/docker.sock, what that name is on the Mac before the first build.
  for (const words of [
    "what the image's `NODE_USE_ENV_PROXY=1` does on its Node (24.22.2)",
    '`[UNDICI-EHPA] Warning: EnvHttpProxyAgent is experimental`',
    'so check whether 24.22.2 still does',
    'keeps its tests off loopback HTTP',
    'before the first build, what `ls -l ~/.colima/docker.sock` shows: nothing there, or a link to `~/.colima/default/docker.sock`, is expected',
    'not checked against Colima 0.10.3',
  ]) {
    assert.ok(row.includes(words), `README's NEEDS VALIDATION row for the image does not say ${words}`)
  }
  // No RUN after the proxy is set: apt, or anything else at build time, would
  // be sent to a port nothing listens on during a build.
  const firstEnv = steps.findIndex((s) => s.keyword === 'ENV')
  assert.deepEqual(steps.slice(firstEnv).filter((s) => s.keyword === 'RUN'), [], 'a RUN follows the proxy ENV')

  // No entrypoint: a run's argv is exactly what the kernel passed, which a
  // human approving a sandbox.exec is shown, not `node <argv>` by way of the
  // base's docker-entrypoint.sh, which runs a shell first.
  assert.deepEqual(of('ENTRYPOINT'), ['[]'])

  // The image's own files are every file in its build context but the
  // Dockerfile and the context's .dockerignore, each copied once: git's
  // config to /etc/gitconfig, the rest (the mux, and the publisher
  // sandbox.publish runs, egress plan S4) to /opt/aos, where each one's
  // header says it runs from. The .dockerignore admits exactly those, so
  // nothing else that lands in images/worker reaches a build. Read from the
  // directory rather than named here: only test/egress-mux.test.ts spells the
  // mux's file name (test/hygiene.test.ts).
  const context = readdirSync(join(REPO, 'images/worker')).filter((f) => f !== 'Dockerfile' && f !== '.dockerignore').sort()
  assert.ok(context.length === 3 && context.includes('gitconfig') && context.includes('publish.mjs'), context.join(', '))
  assert.deepEqual([...of('COPY')].sort(), context.map((f) => `${f} ${f === 'gitconfig' ? '/etc/gitconfig' : `/opt/aos/${f}`}`))
  const ignore = read('images/worker/.dockerignore').split('\n').map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'))
  assert.deepEqual(ignore, ['*', ...context.map((f) => `!${f}`)])

  // Two RUNs, each whole. apt installs git and a CA store, nothing they
  // recommend (git recommends an ssh client) and nothing else, and keeps no
  // package lists; then the copied files are made root's and read-only to
  // everyone else (moot under --read-only, but what the comment says). Pinned
  // exactly, so no RUN appends to /etc/gitconfig (held whole below), installs
  // another package, loosens a mode, or mounts a build secret. As the shell
  // is handed each: the space before each `\` and the next line's one-space
  // indent are both kept.
  const copied = context.filter((f) => f !== 'gitconfig').map((f) => `/opt/aos/${f}`)
  assert.deepEqual(of('RUN'), [
    'apt-get update  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git ca-certificates  && rm -rf /var/lib/apt/lists/*',
    `chmod 0755 /opt/aos  && chmod 0444 /etc/gitconfig ${copied.join(' ')}`,
  ])

  // /etc/gitconfig: https remotes fetched as http (an absolute-form request to
  // the mux, which the kernel judges and dials over TLS), no credential helper
  // and no other credential key, neither file:// nor ext:: as a transport, and
  // the workspace as the one safe directory. The whole file, so an
  // http.extraHeader, an [include] or a second insteadOf fails too.
  const git = gitConfigEntries(read('images/worker/gitconfig'))
  assert.deepEqual(Object.fromEntries(git), {
    'url.http://.insteadof': ['https://'],
    'credential.helper': [''],
    'protocol.file.allow': ['never'],
    'protocol.ext.allow': ['never'],
    'safe.directory': [WORKSPACE_TARGET],
  })

  // No credential shape, key block or certificate in anything the image or its
  // build is made from (the repository is public: no TLS key or certificate is
  // ever committed).
  const sources = [
    ...readdirSync(join(REPO, 'images/worker')).map((f) => `images/worker/${f}`),
    'scripts/build-worker-image.sh',
    'scripts/worker-image.ts',
  ]
  assert.ok(sources.length >= 6 && sources.includes('images/worker/Dockerfile'), sources.join(', '))
  for (const rel of sources) {
    const body = read(rel)
    for (const pattern of [...TOKEN_PATTERNS, /-----BEGIN [A-Z0-9 ]*(?:CERTIFICATE|PRIVATE KEY)[A-Z ]*-----/]) {
      const match = new RegExp(pattern.source, pattern.flags.replace('g', '')).exec(body)
      assert.equal(match, null, `${rel} holds a credential shape: ${String(match?.[0])}`)
    }
  }
})

test('the Dockerfile reader is plain ASCII, and this file writes every invisible character it tests as an escape', () => {
  // A byte-order mark, U+3000 or U+00A0 written as itself in a pattern or a
  // row is invisible in most editors and diffs, and an editor that drops it
  // turns the reader's /^\uFEFF/ into /^/, or a row into another row, with
  // nothing failing. scripts/worker-image.ts is plain ASCII; this file holds
  // visible characters beyond ASCII (dashes, rules), but nothing that is
  // white space other than space, tab and newline, a format character, or
  // one Unicode says may be ignored.
  assert.deepEqual(notPlainAscii(read('scripts/worker-image.ts')), [])
  const invisible = (text: string): string[] =>
    notPlainAscii([...text.matchAll(/[\p{White_Space}\p{Cf}\p{Default_Ignorable_Code_Point}]/gu)].map((m) => m[0]).filter((c) => c !== ' ' && c !== '\t' && c !== '\n').join(''))
  assert.deepEqual(invisible(read('test/config-files.test.ts')), [])
  assert.deepEqual(invisible('a\uFEFFb\u3000c\u00a0d\u200be\u0085f\u00adg \u2014 \u2500 h\ti\nj'), ['U+FEFF', 'U+3000', 'U+00A0', 'U+200B', 'U+0085', 'U+00AD'])
})

/**
 * A line with bash's blanks trimmed from its ends: spaces and tabs, and
 * nothing else. JavaScript's trim() also strips \f, \v, \r, U+00A0, U+3000
 * and more, which bash reads as part of a word: a line led by \f and then #
 * would be a comment to trim() and a command named \f# to bash.
 */
function bashTrim(line: string): string {
  return line.replace(/^[ \t]+|[ \t]+$/g, '')
}

/** The build script's code: each line with bash's blanks trimmed, blank lines and whole-line comments dropped. */
function scriptCode(text: string): string[] {
  return text.split('\n').map(bashTrim).filter((l) => l !== '' && !l.startsWith('#'))
}

/**
 * scripts/build-worker-image.sh's code, whole (scriptCode). Its every
 * command line is held here exactly, so any edit to what it runs edits this
 * test too (the script is printable ASCII, tabs and newlines, which
 * buildScriptProblems holds it to, so a line bash runs is a line here), and
 * buildScriptProblems below says what such an edit must still keep: no
 * lexical check can refuse a command name assembled from pieces at run
 * time, and this list can.
 */
const BUILD_SCRIPT_CODE: readonly string[] = [
  'set -euo pipefail',
  'if [[ $# -ne 0 ]]; then',
  'echo "error: scripts/build-worker-image.sh takes no arguments" >&2',
  'exit 2',
  'fi',
  'REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"',
  'CONTEXT="${REPO_ROOT}/images/worker"',
  'need() {',
  'command -v "$1" >/dev/null 2>&1 || {',
  'echo "error: $1 is not installed" >&2',
  'exit 1',
  '}',
  '}',
  'need node',
  'need docker',
  'if ! plan="$(cd "${REPO_ROOT}" && node --import tsx scripts/worker-image.ts)"; then',
  'echo "error: nothing was built (scripts/worker-image.ts refused, above)" >&2',
  'exit 1',
  'fi',
  "BASE=''",
  "IMAGE=''",
  "TRUSTED_HOST=''",
  "HOSTILE_HOST=''",
  "AOS_DOCKER_CONFIG=''",
  'while IFS= read -r line; do',
  'case "${line%%=*}" in',
  'BASE) BASE="${line#*=}" ;;',
  'IMAGE) IMAGE="${line#*=}" ;;',
  'TRUSTED_DOCKER_HOST) TRUSTED_HOST="${line#*=}" ;;',
  'HOSTILE_DOCKER_HOST) HOSTILE_HOST="${line#*=}" ;;',
  'DOCKER_CONFIG) AOS_DOCKER_CONFIG="${line#*=}" ;;',
  '*)',
  'echo "error: scripts/worker-image.ts printed a line this script does not read: ${line}" >&2',
  'exit 1',
  ';;',
  'esac',
  'done <<<"${plan}"',
  'if [[ -z "${BASE}" || -z "${IMAGE}" || -z "${TRUSTED_HOST}" || -z "${HOSTILE_HOST}" || -z "${AOS_DOCKER_CONFIG}" ]]; then',
  'echo "error: scripts/worker-image.ts left a value out; nothing was built" >&2',
  'exit 1',
  'fi',
  'mkdir -p "${AOS_DOCKER_CONFIG}"',
  'dk() {',
  'local host="$1"',
  'shift',
  'env -i DOCKER_CONFIG="${AOS_DOCKER_CONFIG}" DOCKER_HOST="${host}" PATH="${PATH}" docker "$@"',
  '}',
  'answers() {',
  'local domain="$1" host="$2" out',
  'if ! out="$(dk "${host}" version --format \'{{.Server.Version}}\' 2>&1)"; then',
  'echo "error: the ${domain} VM\'s docker daemon (${host}) does not answer: ${out}" >&2',
  'echo "fix: start both VMs with scripts/colima-up.sh, then run this again" >&2',
  'exit 1',
  'fi',
  '}',
  'answers trusted "${TRUSTED_HOST}"',
  'answers hostile "${HOSTILE_HOST}"',
  'echo "building ${IMAGE} from ${BASE} on the trusted VM (${TRUSTED_HOST})" >&2',
  'dk "${TRUSTED_HOST}" build --tag "${IMAGE}" --file "${CONTEXT}/Dockerfile" "${CONTEXT}" >&2',
  'id="$(dk "${TRUSTED_HOST}" image inspect --format \'{{.Id}}\' "${IMAGE}")"',
  'if [[ ! "${id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then',
  'echo "error: the trusted VM gives ${IMAGE} the id \'${id}\', not sha256:<64 hex>" >&2',
  'exit 1',
  'fi',
  'runs="$(dk "${TRUSTED_HOST}" image inspect --format \'{{.Config.User}} {{json .Config.Entrypoint}}\' "${id}")"',
  'case "${runs}" in',
  "'65534:65534 null' | '65534:65534 []') ;;",
  '*)',
  'echo "error: ${IMAGE} (${id}) has user and entrypoint \'${runs}\', not 65534:65534 and none; do not pin it" >&2',
  'exit 1',
  ';;',
  'esac',
  'echo "loading ${IMAGE} (${id}) into the hostile VM (${HOSTILE_HOST})" >&2',
  'dk "${TRUSTED_HOST}" save "${IMAGE}" | dk "${HOSTILE_HOST}" load >&2',
  'holds() {',
  'local domain="$1" host="$2" got',
  'if ! got="$(dk "${host}" image inspect --format \'{{.Id}}\' "${id}" 2>&1)" || [[ "${got}" != "${id}" ]]; then',
  'echo "error: the ${domain} VM does not hold ${id} under that id (it answered: ${got})." >&2',
  'echo "docker save and docker load did not keep the id, so no one sandbox.imageId names the image on both VMs; do not pin it" >&2',
  'exit 1',
  'fi',
  '}',
  'holds trusted "${TRUSTED_HOST}"',
  'holds hostile "${HOSTILE_HOST}"',
  'echo "" >&2',
  'echo "Both VMs hold ${IMAGE} as ${id}. Pin it in config/kernel.yaml, under sandbox:" >&2',
  'echo "  imageId: ${id}" >&2',
  'printf \'%s\\n\' "${id}"',
]

/**
 * An echo of one double-quoted string to stderr that expands only plain
 * variables (`${name}` or `$name`): no command substitution, backtick,
 * arithmetic or other expansion, so it runs nothing but echo.
 */
const PLAIN_ECHO = /^echo "(?:[^"\\$`]|\$(?:\{\w+\}|\w+))*" >&2$/

/**
 * A code line as buildScriptProblems scans it for command words, names and
 * paths. A PLAIN_ECHO's text is data, and is dropped. Every other line loses
 * its quote characters and backslashes, rather than having its quoted text
 * replaced: bash runs "docker", 'docker', d""ocker and d\ocker all as
 * docker, and a path in quotes is that path.
 */
function scanned(line: string): string {
  return PLAIN_ECHO.test(line) ? 'echo "" >&2' : line.replace(/["'\\]/g, '')
}

/** A name assigned, in any of bash's forms but a builtin's (BINDS): `name=`, `name+=`, `name[i]=`, and `${name=}` or `${name:=}`. */
const assigns = (names: string): RegExp => new RegExp(`(?:^|[\\s;&|(!])(?:${names})(?:\\[[^\\]]*\\])?\\+?=|\\$\\{(?:${names}):?=`)

/**
 * Words that run another command, a string or a file as code: an interpreter,
 * eval, a trap, the `.` builtin. A variable's value run as code by
 * arithmetic or by prompt expansion is no word, and is bashCommands' to name.
 */
const INDIRECT =
  /\b(?:eval|exec|source|xargs|bash|sh|zsh|dash|ksh|node|npx|npm|tsx|python3?|perl|ruby|osascript|nohup|sudo|command|builtin|env|trap|alias|enable|coproc)\b|(?:^|[;&|({!]\s*|\b(?:then|do|else|elif|if|while|until|time)\s+)\.\s/

/** Builtins and syntax that set, export or unset a variable otherwise than by `name=`. */
const BINDS = /\b(?:export|typeset|declare|readonly|local|read|mapfile|readarray|getopts|let|unset|select|for|set|shopt)\b|\bprintf\s+-v\b|\(\(/

/** Reserved words after which bash reads the next word as a command name as well. */
const LEADING_WORDS = new Set(['if', 'then', 'else', 'elif', 'while', 'until', 'do', '!', '{'])

/** The comparisons inside [[ ]] that read both operands as arithmetic. */
const ARITHMETIC_TEST = new Set(['-eq', '-ne', '-lt', '-le', '-gt', '-ge'])

/** A case arm's patterns, its `)` included, at the start of a line inside a case: plain or single-quoted words, a `|` between each two. */
const CASE_PATTERN = /^(?:'[^']*'|[^ \t()'"|$`\\;&<>]+)(?:[ \t]*\|[ \t]*(?:'[^']*'|[^ \t()'"|$`\\;&<>]+))*\)/

/** A word bash runs as a command name, the code line it is on (0-based, in scriptCode), and whether any of it was quoted. */
interface CommandWord {
  readonly word: string
  readonly line: number
  readonly quoted: boolean
}

/**
 * Every word bash runs as a command name in the build script's code
 * (scriptCode), with the reserved words that stand where one does. Read with
 * bash's quoting (single and double quotes, a backslash, `${...}`), every
 * `$(...)` and `( ... )` read as a command list of its own, `[[ ... ]]` as a
 * condition, a case arm's pattern and a redirection's target as no command,
 * an assignment before a command as no command, a function's definition as
 * no call, and the command env -i, or command without -v, runs as a command
 * name too. Only space and tab are blanks, as they are to bash. Each line is
 * read on its own: none of this script's continues onto the next, and one
 * that tried would leave a quote, a `(` or a `\` open, which is named. So is
 * anything this reading does not follow (a backtick, arithmetic, a
 * here-document, process substitution, inside [[ ]] too, ANSI-C quoting, an
 * option of env but -i or of command but -v or -V), in unread, so that it is
 * refused rather than read past; and so is anything that runs a variable's
 * value as code, which no reading of the text can see: a ${...@...}
 * transformation (@P expands a prompt string, a $(...) in it included),
 * indirection, an offset or a default, a subscript other than digits (a
 * length's, ${#name[...]}, and an array element's assignment's, name[...]=,
 * included), an arithmetic comparison inside [[ ]] (-eq, -ne, -lt, -le, -gt,
 * -ge) of an operand other than digits or $#, and a -v inside [[ ]] of an
 * operand other than a plain name: bash evaluates an offset, a subscript and
 * those operands as arithmetic, and -v's operand as a name whose subscript
 * it evaluates so, and a value a[$(...)] runs the substitution. No other
 * operator of [[ ]] evaluates its operand so (bash 5.2.21, each tried on
 * that value: -t reads a number, -R and -o a name, the rest a string or a
 * path). A builtin that takes a name with a subscript (local, read, unset,
 * printf -v) is held by the pin on BINDS's lines, and test and [, whose -v
 * reads one too, are no commands the script may run.
 */
function bashCommands(code: readonly string[]): { readonly words: readonly CommandWord[]; readonly unread: readonly string[] } {
  const words: CommandWord[] = []
  const unread: string[] = []
  const META = ';&|()<>'
  const isBlank = (c: string): boolean => c === ' ' || c === '\t'
  let caseDepth = 0
  for (const [n, whole] of code.entries()) {
    const line = caseDepth > 0 ? whole.replace(CASE_PATTERN, '') : whole
    let i = 0
    const at = (k = 0): string => line[i + k] ?? ''
    const note = (what: string): void => {
      unread.push(`${what}: ${whole}`)
    }
    const dollar = (): string => {
      const next = at(1)
      if ((next === '(' && at(2) === '(') || next === '[') {
        note('arithmetic')
        i = line.length
        return ''
      }
      if (next === "'" || next === '"') {
        note('ANSI-C or locale quoting')
        i++
        return '$'
      }
      if (next === '(') {
        i += 2
        list(true)
        return '$(...)'
      }
      if (next === '{') {
        const start = i
        i += 2
        // What follows the name may run a value as code: a transformation
        // (${name@P} expands a prompt string, $(...) in it included), an
        // offset (${name:offset} evaluates offset as arithmetic, and a value
        // a[$(...)] runs the substitution), indirection (${!name}), and a
        // subscript other than digits (arithmetic too), a length's
        // (${#name[...]}) as well: a `#` before a name is a length, not the
        // special parameter. The script uses none of them but
        // ${BASH_SOURCE[0]}, and trims (%%, #) and plain names, which run
        // nothing.
        const param = /^(!?)(?:#(?=[A-Za-z_\d]))?([A-Za-z_]\w*|\d+|[#?$*@-])(\[[^\]]*\])?(.?)/.exec(line.slice(i))
        const [, bang = '', , subscript, after = ''] = param ?? []
        if (param === null) note('a ${...} this reading does not follow')
        else if (bang !== '') note('indirect expansion')
        else if (subscript !== undefined && !/^\[\d+\]$/.test(subscript)) note('a subscript, which bash reads as arithmetic')
        else if (after === '@') note('a ${...@...} transformation')
        else if (after === ':') note('an offset or a default (${...:...})')
        for (let depth = 1; depth > 0; ) {
          const c = at()
          if (c === '') {
            note('a ${ left open')
            return line.slice(start)
          }
          if (c === '$' && at(1) === '(') {
            dollar()
            continue
          }
          if (c === "'" || c === '"' || c === '`' || c === '\\') note('a quote or a backslash inside ${...}')
          if (c === '{') depth++
          if (c === '}') depth--
          i++
        }
        return line.slice(start, i)
      }
      i++
      return '$'
    }
    const dquoted = (): string => {
      let text = ''
      for (;;) {
        const c = at()
        if (c === '') {
          note('a double quote left open')
          return text
        }
        if (c === '"') {
          i++
          return text
        }
        if (c === '\\') {
          text += at(1)
          i += 2
          continue
        }
        if (c === '$') {
          text += dollar()
          continue
        }
        if (c === '`') note('a backtick')
        text += c
        i++
      }
    }
    // One word from i, its quotes removed: what bash runs, if it is a command name.
    const word = (): string => {
      let text = ''
      for (;;) {
        const c = at()
        if (c === '' || isBlank(c) || META.includes(c)) return text
        if (c === '\\') {
          if (at(1) === '') note('a \\ that continues the line')
          text += at(1)
          i += 2
          continue
        }
        if (c === "'") {
          const end = line.indexOf("'", i + 1)
          if (end === -1) {
            note('a quote left open')
            i = line.length
            return text
          }
          text += line.slice(i + 1, end)
          i = end + 1
          continue
        }
        if (c === '"') {
          i++
          text += dquoted()
          continue
        }
        if (c === '$') {
          text += dollar()
          continue
        }
        if (c === '`') note('a backtick')
        text += c
        i++
      }
    }
    // A command list from i to the end of the line, or, nested, to the `)` that closes it.
    const list = (nested: boolean): void => {
      let position = true
      let cond = false
      let skip = 0
      let envOptions = false
      let lookup = false
      let operands: string[] = []
      let named: number | undefined
      for (;;) {
        while (isBlank(at())) i++
        const c = at()
        if (c === '') {
          if (nested) note('a ( left open')
          return
        }
        if (cond && (c === '<' || c === '>') && at(1) === '(') {
          // bash runs process substitution inside [[ ]] too.
          note('process substitution')
          i = line.length
          continue
        }
        if (cond && (META.includes(c) || c === '!')) {
          i++
          continue
        }
        if (c === '#') {
          i = line.length
          continue
        }
        if (META.includes(c)) {
          const defined = named
          named = undefined
          if (c === ')') {
            i++
            if (nested) return
            note('a ) that closes nothing')
            position = false
          } else if (c === '(') {
            const definition = /^\([ \t]*\)/.exec(line.slice(i))
            if (at(1) === '(') {
              note('arithmetic')
              i = line.length
            } else if (definition !== null && defined !== undefined) {
              // name() { ... }: a definition, which runs nothing; its body does, when called.
              words.splice(defined, 1)
              i += definition[0].length
              position = true
            } else {
              i++
              list(true)
              position = false
            }
          } else if (c === '<' || c === '>' || (c === '&' && at(1) === '>')) {
            const op = /^(?:&>>?|<<<|<<-?|<>|<&|>&|>>|>\||<|>)/.exec(line.slice(i))?.[0] ?? c
            i += op.length
            if (op === '<<' || op === '<<-') {
              note('a here-document')
              i = line.length
            } else if (at() === '(') {
              note('process substitution')
              i = line.length
            } else {
              while (isBlank(at())) i++
              word()
            }
          } else {
            i += (c === ';' && at(1) === ';') || (c === '&' && at(1) === '&') || (c === '|' && (at(1) === '|' || at(1) === '&')) ? 2 : 1
            position = true
          }
          continue
        }
        const start = i
        const w = word()
        const raw = line.slice(start, i)
        named = undefined
        if (raw === '') {
          note(`a character this reading does not follow (${c})`)
          i++
          continue
        }
        if (cond) {
          if (raw === ']]') {
            // -eq and its kin evaluate both operands as arithmetic, which
            // runs a value a[$(...)] as code: only digits and $# are read.
            for (const [k, op] of operands.entries()) {
              // -v reads its operand as a name, and a subscript in it, or in
              // the value it expands to, as arithmetic: only a plain name is
              // read, with no $ or subscript.
              if (op === '-v' && !/^[A-Za-z_]\w*$/.test(operands[k + 1] ?? '')) note('-v of an operand that is not a plain name')
              if (!ARITHMETIC_TEST.has(op)) continue
              const plain = [operands[k - 1], operands[k + 1]].every((o) => o !== undefined && /^(?:\d+|\$#)$/.test(o))
              if (!plain) note(`an arithmetic comparison (${op}) of an operand that is not digits or $#`)
            }
            operands = []
            cond = false
            position = false
          } else {
            operands.push(raw)
          }
          continue
        }
        if (skip > 0) {
          skip--
          continue
        }
        if (!position) continue
        if (/^\d+$/.test(raw) && (at() === '<' || at() === '>')) continue
        const assignment = /^[A-Za-z_]\w*(\[[^\]]*\])?\+?=/.exec(raw)
        if (assignment !== null) {
          // name[subscript]=: bash reads an array element's subscript as
          // arithmetic, which runs a value a[$(...)] as code.
          if (assignment[1] !== undefined && !/^\[\d+\]$/.test(assignment[1])) note("an array element's assignment, whose subscript bash reads as arithmetic")
          continue
        }
        if (envOptions && w === '-i') continue
        if ((envOptions || lookup) && w.startsWith('-')) {
          if (lookup && (w === '-v' || w === '-V')) {
            lookup = false
            position = false
          } else {
            note(`an option this reading does not follow (${w})`)
          }
          continue
        }
        envOptions = false
        lookup = false
        const quoted = raw !== w
        words.push({ word: w, line: n, quoted })
        named = words.length - 1
        if (quoted) {
          position = false
        } else if (LEADING_WORDS.has(w)) {
          position = true
        } else if (w === '[[') {
          cond = true
          position = false
        } else if (w === 'case') {
          skip = 2
          position = false
        } else if (w === 'env') {
          envOptions = true
        } else if (w === 'command') {
          lookup = true
        } else {
          position = false
        }
      }
    }
    list(false)
    for (const { word: w } of words.filter((cw) => cw.line === n && !cw.quoted)) {
      if (w === 'case') caseDepth++
      if (w === 'esac') caseDepth--
    }
  }
  return { words, unread }
}

/** What the build script may run, by name: docker only as dk's, env -i's command. */
const BUILD_SCRIPT_COMMANDS = new Set(['set', 'echo', 'exit', 'command', 'need', 'node', 'cd', 'dirname', 'pwd', 'mkdir', 'local', 'shift', 'env', 'docker', 'dk', 'answers', 'holds', 'printf', 'read'])

/** The reserved words it may use where a command name stands, each unquoted (quoted, bash runs it as a command of that name). */
const BUILD_SCRIPT_RESERVED = new Set(['if', 'then', 'else', 'elif', 'fi', 'while', 'until', 'do', 'done', 'case', 'esac', '{', '}', '!', '[['])

const PLAN_LINE = 'if ! plan="$(cd "${REPO_ROOT}" && node --import tsx scripts/worker-image.ts)"; then'
const DK_LINE = 'env -i DOCKER_CONFIG="${AOS_DOCKER_CONFIG}" DOCKER_HOST="${host}" PATH="${PATH}" docker "$@"'
const BUILD_LINE = 'dk "${TRUSTED_HOST}" build --tag "${IMAGE}" --file "${CONTEXT}/Dockerfile" "${CONTEXT}" >&2'
const ID_LINE = 'printf \'%s\\n\' "${id}"'

/**
 * What the build script must do, read from its text: every problem found,
 * each led by its label and a colon, or none. These say why each line of
 * BUILD_SCRIPT_CODE is as it is, and what an edit to it must still keep.
 * driverEnv is the names boot's own driver gives its docker calls, planKeys
 * the keys scripts/worker-image.ts prints, in order.
 */
function buildScriptProblems(text: string, driverEnv: readonly string[], planKeys: readonly string[]): string[] {
  const problems: string[] = []
  const expect = (label: string, actual: unknown, expected: unknown): void => {
    if (!isDeepStrictEqual(actual, expected)) problems.push(`${label}: ${JSON.stringify(actual)}`)
  }
  const code = scriptCode(text)
  const scan = code.map(scanned)
  const where = (pattern: RegExp): string[] => code.filter((_, i) => pattern.test(scan[i] ?? ''))
  // Printable ASCII, tabs and newlines only, comments included: bash's blanks
  // are space and tab alone, so a line this test reads as indented, blank or
  // a comment is one to bash too, and no character reads one way here and
  // another there (\f# is a command name to bash, \f* a pattern no word
  // matches).
  expect('a character bash does not read as this test does', notPlainAscii(text), [])
  expect('set -euo pipefail', code.includes('set -euo pipefail'), true)
  expect('arguments refused', code.includes('if [[ $# -ne 0 ]]; then'), true)

  // Every command it runs is one of these, by name, wherever on a line it
  // stands (bashCommands): no cp, git, rm, sed, curl or tee can change the
  // Dockerfile or the build context between the plan's check and the build,
  // whatever path it is given, and docker runs from dk alone. A construct
  // the reading does not follow is refused, not read past.
  const commands = bashCommands(code)
  expect('a construct the command reading does not follow', commands.unread, [])
  expect(
    'a command the script may not run',
    commands.words
      .filter((w) => !(BUILD_SCRIPT_COMMANDS.has(w.word) || (BUILD_SCRIPT_RESERVED.has(w.word) && !w.quoted)) || (w.word === 'docker' && code[w.line] !== DK_LINE))
      .map((w) => `${w.word} in ${code[w.line] ?? ''}`),
    [],
  )
  const seen = new Set(commands.words.map((w) => w.word))
  expect('a command the reading does not see', ['cd', 'dirname', 'pwd', 'node', 'read', 'docker', 'dk', 'answers', 'holds', 'printf'].filter((w) => !seen.has(w)), [])

  // Every echo is one plain string, to stderr, wherever on a line it is: its
  // text is then data, and stdout carries the id alone.
  expect('an echo that runs more than echo or writes to stdout', where(/\becho\b/).filter((l) => !PLAIN_ECHO.test(l)), [])

  // docker is run in one place, dk, whose environment is exactly the names
  // DockerDriver gives its own calls: no docker context, ~/.docker or
  // exported DOCKER_* variable can point it at another daemon. Nothing runs a
  // command or a string another way (eval, an interpreter, `.`), no quoting
  // hides a name from the scans, and no name the docker CLI or env -i reads
  // is set anywhere else.
  expect('docker outside dk', where(/\bdocker\b/), ['need docker', DK_LINE])
  expect("dk's environment", [...DK_LINE.matchAll(/\b([A-Z_]+)="/g)].map((m) => m[1]).sort(), [...driverEnv])
  expect('a command run indirectly', where(INDIRECT), ['command -v "$1" >/dev/null 2>&1 || {', 'need node', PLAN_LINE, DK_LINE])
  expect('ANSI-C or locale quoting', code.filter((l) => /\$['"]/.test(l)), [])
  expect('a backslash', code.filter((l) => l.includes('\\')), [ID_LINE])
  expect('PATH or a DOCKER_ name set outside dk', where(assigns('PATH|DOCKER_\\w*')), [DK_LINE])
  expect('a function', where(/^(?:function\b|[\w-]+\s*\(\s*\))/), ['need() {', 'dk() {', 'answers() {', 'holds() {'])

  // Nothing reaches dk, and nothing is made on the Mac, before the plan:
  // scripts/worker-image.ts refuses a placeholder digest, any other base, the
  // default Colima profile and one socket for both domains first. dk is
  // defined once, after the plan line: bash cannot run a function before its
  // definition has run, so no call above the plan, however it is written,
  // reaches docker through it. The scan below says the same of the calls
  // themselves, a call of any function that reaches dk (answers, holds)
  // counting as a call of dk, after a command separator or a shell keyword.
  const reaching = new Set(['dk'])
  const bodies = [...text.matchAll(/^(\w+)\(\) \{\n([\s\S]*?)^\}$/gm)].map((m) => [m[1] ?? '', (m[2] ?? '').split('\n').map((l) => scanned(bashTrim(l))).join('\n')] as const)
  for (let grew = true; grew; ) {
    grew = false
    for (const [name, body] of bodies) {
      if (!reaching.has(name) && [...reaching].some((r) => new RegExp(`(?:^|[\\s$(|;&!])${r}\\s`, 'm').test(body))) {
        reaching.add(name)
        grew = true
      }
    }
  }
  expect('the functions that reach docker', [...reaching].sort(), ['answers', 'dk', 'holds'])
  const invokes = new RegExp(`(?:^|\\$\\(|[|;&!({]\\s*|\\b(?:if|then|else|elif|do|while|until|time)\\s+)(?:${[...reaching].join('|')})\\s`)
  const calls = scan.map((l, i) => ({ l, i })).filter(({ l }) => invokes.test(l))
  const plan = code.indexOf(PLAN_LINE)
  expect('the plan line', plan > 0, true)
  const defines = code.map((l, i) => ({ l, i })).filter(({ i }) => /^(?:function\s+)?dk\b\s*(?:\(\s*\)|\{|$)|^function\s+dk\b/.test(scan[i] ?? ''))
  expect('dk is defined once, as dk() {', defines.map(({ l }) => l), ['dk() {'])
  expect('dk is defined after the plan', (defines[0]?.i ?? -1) > plan, true)
  expect('the calls reaching docker the scan sees', calls.length >= 10, true)
  expect('docker asked something before the plan', calls.filter(({ i }) => i < plan).map(({ i }) => code[i]), [])
  expect('a directory made before the plan', code.findIndex((l) => l.startsWith('mkdir')) > plan, true)
  // And made as pinned: an option such as -v would print to stdout, which
  // carries the id alone.
  expect('mkdir, exactly as pinned', where(/\bmkdir\b/), ['mkdir -p "${AOS_DOCKER_CONFIG}"'])

  // Every socket and the DOCKER_CONFIG come from the plan, which reads
  // kernel.yaml: the script names no socket, no Colima path, no home or
  // docker config of its own, and runs no colima command (never the default
  // profile, which shares $HOME).
  expect('a Colima path, socket, home or docker config of its own', where(/\.colima|docker\.sock|unix:\/\/|\bcolima\b|\bHOME\b|~\/|\.docker\b|\/Users\//), [])
  // What each VM is asked, in order: both answer version and are asked for
  // the image by its id, trusted builds, is asked the id and the image's user
  // and entrypoint, and saves; hostile only loads. Nothing is pulled, pushed
  // or run, and every dk the script holds is one of these.
  const asked = code.flatMap((l) => [...l.matchAll(/\bdk "\$\{(\w+)\}" ((?:(?!\s\d*>)[^|)])*)/g)].map((m) => `${m[1] ?? ''} ${(m[2] ?? '').trim()}`))
  expect('what each VM is asked', asked, [
    "host version --format '{{.Server.Version}}'",
    'TRUSTED_HOST build --tag "${IMAGE}" --file "${CONTEXT}/Dockerfile" "${CONTEXT}"',
    'TRUSTED_HOST image inspect --format \'{{.Id}}\' "${IMAGE}"',
    'TRUSTED_HOST image inspect --format \'{{.Config.User}} {{json .Config.Entrypoint}}\' "${id}"',
    'TRUSTED_HOST save "${IMAGE}"',
    'HOSTILE_HOST load',
    'host image inspect --format \'{{.Id}}\' "${id}"',
  ])
  expect('a dk this scan does not read', scan.reduce((n, l) => n + (l.match(/\bdk\b/g)?.length ?? 0), 0), asked.length + 1)
  expect('the hostile VM loads what the trusted VM saved', code.includes('dk "${TRUSTED_HOST}" save "${IMAGE}" | dk "${HOSTILE_HOST}" load >&2'), true)
  expect('answers and holds', where(/\b(?:answers|holds)\b/), [
    'answers() {',
    'answers trusted "${TRUSTED_HOST}"',
    'answers hostile "${HOSTILE_HOST}"',
    'holds() {',
    'holds trusted "${TRUSTED_HOST}"',
    'holds hostile "${HOSTILE_HOST}"',
  ])

  // The build, exactly. Its context is images/worker, whose .dockerignore
  // admits only the two files the Dockerfile copies, never the repository;
  // it takes no option but the tag and the file: no --build-arg (which this
  // shell would expand before env -i, handing the VM's daemon whatever the
  // operator's shell holds), no --platform (the VMs are arm64, and an image
  // they cannot run natively would be found out only once pinned), no --pull.
  // REPO_ROOT is set once and used for two things, the context and the
  // plan: nothing else is done to the repository, so the Dockerfile and the
  // context the build reads are the ones scripts/worker-image.ts checked.
  expect('REPO_ROOT beyond its assignment, CONTEXT and the plan', where(/\bREPO_ROOT\b/), [
    'REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"',
    'CONTEXT="${REPO_ROOT}/images/worker"',
    PLAN_LINE,
  ])
  expect('CONTEXT', where(/\bCONTEXT\b/), ['CONTEXT="${REPO_ROOT}/images/worker"', BUILD_LINE])
  expect('the build', where(/\bbuild\b/), [BUILD_LINE])
  // What the build made, checked before it is loaded anywhere, exactly: an id
  // of sha256:<64 hex>, and the image's user and entrypoint 65534:65534 and
  // none, anything else refused. id and runs are set there and nowhere else,
  // in no form, and the only other case statement reads the plan.
  const check = [
    'id="$(dk "${TRUSTED_HOST}" image inspect --format \'{{.Id}}\' "${IMAGE}")"',
    'if [[ ! "${id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then',
    `echo "error: the trusted VM gives \${IMAGE} the id '\${id}', not sha256:<64 hex>" >&2`,
    'exit 1',
    'fi',
    'runs="$(dk "${TRUSTED_HOST}" image inspect --format \'{{.Config.User}} {{json .Config.Entrypoint}}\' "${id}")"',
    'case "${runs}" in',
    "'65534:65534 null' | '65534:65534 []') ;;",
    '*)',
    `echo "error: \${IMAGE} (\${id}) has user and entrypoint '\${runs}', not 65534:65534 and none; do not pin it" >&2`,
    'exit 1',
    ';;',
    'esac',
  ]
  const at = code.indexOf(check[0] ?? '')
  expect('the id asked for after the plan', at > plan, true)
  expect('the check of what the build made', code.slice(at, at + check.length), check)
  expect('id or runs set', where(assigns('id|runs')), [check[0], check[5]])
  expect('a builtin that sets, exports or unsets a variable', where(BINDS), [
    'set -euo pipefail',
    'while IFS= read -r line; do',
    'local host="$1"',
    'local domain="$1" host="$2" out',
    'local domain="$1" host="$2" got',
  ])
  expect('case', where(/^case\b/), ['case "${line%%=*}" in', 'case "${runs}" in'])

  // It reads exactly the lines the plan prints, each under its own name, and
  // sets the plan's values nowhere else: each is empty until the plan reader
  // sets it, and the base is only named, never handed to docker.
  const arms = code.filter((l) => /^[A-Z_]+\) [A-Z_]+="\$\{line#\*=\}" ;;$/.test(l))
  expect('the keys the plan reader reads', arms.map((l) => l.slice(0, l.indexOf(')'))), [...planKeys])
  const values = 'BASE|IMAGE|TRUSTED_HOST|HOSTILE_HOST|AOS_DOCKER_CONFIG'
  expect('a plan value set outside the plan reader', where(assigns(values)), [...values.split('|').map((v) => `${v}=''`), ...arms])
  expect('BASE beyond the plan reader', where(/\bBASE\b/), [
    "BASE=''",
    'BASE) BASE="${line#*=}" ;;',
    'if [[ -z "${BASE}" || -z "${IMAGE}" || -z "${TRUSTED_HOST}" || -z "${HOSTILE_HOST}" || -z "${AOS_DOCKER_CONFIG}" ]]; then',
  ])
  expect('the names the script assigns', [...new Set(scan.flatMap((l) => [...l.matchAll(/(?:^|[\s;&|(!])([A-Za-z_]\w*)(?:\[[^\]]*\])?\+?=/g)].map((m) => m[1])))].sort(), [
    'AOS_DOCKER_CONFIG',
    'BASE',
    'CONTEXT',
    'DOCKER_CONFIG',
    'DOCKER_HOST',
    'HOSTILE_HOST',
    'IFS',
    'IMAGE',
    'PATH',
    'REPO_ROOT',
    'TRUSTED_HOST',
    'domain',
    'got',
    'host',
    'id',
    'out',
    'plan',
    'runs',
  ])

  // Its stdout is the id alone: every echo goes to stderr (above), docker's
  // build and load output too, and the one printf, last, prints the id.
  expect("docker build's output to stderr", code.some((l) => l.startsWith('dk "${TRUSTED_HOST}" build ') && l.endsWith(' >&2')), true)
  expect('printf', where(/\bprintf\b/), [ID_LINE])
  expect('the last line', code.at(-1), ID_LINE)
  return problems
}

test("scripts/build-worker-image.sh is executable and NEEDS VALIDATION, asks docker nothing before scripts/worker-image.ts has checked the base, and runs docker only as the kernel does: on kernel.yaml's sockets, building on trusted and loading into hostile, with the id alone on stdout", async () => {
  const path = join(REPO, 'scripts/build-worker-image.sh')
  assert.ok((statSync(path).mode & 0o111) !== 0, `mode ${statSync(path).mode.toString(8)} is not executable`)
  const text = read('scripts/build-worker-image.sh')
  const lines = text.split('\n')
  assert.equal(lines[0], '#!/usr/bin/env bash')
  // Line 2 of each, exactly: neither has met Docker, and each says so where
  // the operator reads first.
  assert.equal(lines[1], '# NEEDS VALIDATION: written on Linux without Docker or Colima; run once by the operator.')
  assert.equal(read('images/worker/Dockerfile').split('\n')[1], '# NEEDS VALIDATION: written on Linux without Docker; built once by the operator.')

  // Its code, whole, and then what that code must keep.
  assert.deepEqual(scriptCode(text), BUILD_SCRIPT_CODE)
  const names = [...new Set((await driverDockerEnvs()).map((env) => Object.keys(env).sort().join(' ')))]
  assert.deepEqual(names, ['DOCKER_CONFIG DOCKER_HOST PATH'])
  const driverEnv = (names[0] ?? '').split(' ')
  const keys = planText(workerImagePlan(REPO, {})).trimEnd().split('\n').map((l) => l.slice(0, l.indexOf('=')))
  assert.deepEqual(buildScriptProblems(text, driverEnv, keys), [])

  // One-line edits, each of which bash -n accepts, that run docker other
  // than through dk, on a socket nobody chose, print an id nobody checked,
  // or build from a Dockerfile or context other than the one the plan read:
  // each changes the pinned code (scriptCode trims only bash's blanks, so
  // no line hides as a comment or as white space), and each is refused, by
  // the label given, by what the code must keep.
  const holdsHostile = 'holds hostile "${HOSTILE_HOST}"\n'
  const mutants: [string, string, string, string[]][] = [
    ['R1, a quoted docker word pushes', holdsHostile, `${holdsHostile}"docker" push "\${IMAGE}" >&2\n`, ['docker outside dk']],
    ['R7, docker runs before the plan', 'need docker\n', "need docker\n'docker' version >&2\n", ['docker outside dk']],
    ['R9, eval runs a pushed string', holdsHostile, `${holdsHostile}eval "$(printf 'dock%s push %s' er "\${IMAGE}")"\n`, ['a command run indirectly', 'printf']],
    ['R2, the default profile by path', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nTRUSTED_HOST="unix://${HOME}/.colima/default/docker.sock"\n', ['a Colima path, socket, home or docker config of its own', 'a plan value set outside the plan reader']],
    ['R3, a docker config of its own', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nAOS_DOCKER_CONFIG="${HOME}/.docker"\n', ['a Colima path, socket, home or docker config of its own', 'a plan value set outside the plan reader']],
    [
      "R4b, the base's id exported and the base loaded",
      '# 4. Into the hostile VM',
      `export id="$(dk "\${TRUSTED_HOST}" image inspect --format '{{.Id}}' "\${BASE}")"\ndk "\${TRUSTED_HOST}" save "\${BASE}" | dk "\${HOSTILE_HOST}" load >&2\n# 4. Into the hostile VM`,
      ['id or runs set', 'a builtin that sets, exports or unsets a variable', 'what each VM is asked', 'BASE beyond the plan reader'],
    ],
    ['R8, id read again', holdsHostile, `${holdsHostile}read -r id <<<"$(dk "\${TRUSTED_HOST}" image inspect --format '{{.Id}}' "\${BASE}")"\n`, ['a builtin that sets, exports or unsets a variable', 'what each VM is asked', 'BASE beyond the plan reader']],
    ['a backslashed docker word', holdsHostile, `${holdsHostile}d\\ocker push "\${IMAGE}" >&2\n`, ['docker outside dk', 'a backslash']],
    ['an ANSI-C quoted docker word', holdsHostile, `${holdsHostile}$'\\x64ocker' push "\${IMAGE}" >&2\n`, ['ANSI-C or locale quoting', 'a backslash']],
    ['a docker of its own on PATH', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nPATH="${REPO_ROOT}/.aos/bin:${PATH}"\n', ['PATH or a DOCKER_ name set outside dk']],
    ['an echo that runs a command', 'echo "" >&2\n', 'echo "$(dk "${TRUSTED_HOST}" push "${IMAGE}")" >&2\n', ['an echo that runs more than echo or writes to stdout', 'what each VM is asked']],
    // A line led by \f or U+00A0 and then #: a comment to JavaScript's
    // trim(), a command named \f# or U+00A0# to bash, which fails (127,
    // which set -e lets pass left of ||) and runs what follows the ||.
    ['U1, a \\f-led # line pushes', holdsHostile, `${holdsHostile}\f# || dk "\${TRUSTED_HOST}" push "\${IMAGE}" >&2\n`, ['a character bash does not read as this test does', 'a command the script may not run', 'what each VM is asked']],
    // bash's blanks are space and tab: \v starts a word, as \f does.
    ['U1, a \\v-led # line pushes', holdsHostile, `${holdsHostile}\v# || dk "\${TRUSTED_HOST}" push "\${IMAGE}" >&2\n`, ['a character bash does not read as this test does', 'a command the script may not run', 'what each VM is asked']],
    [
      'U1, a U+00A0-led # line loads into the default profile',
      holdsHostile,
      `${holdsHostile}\u00a0# || docker --host "unix://\${HOME}/.colima/default/docker.sock" load <"\${CONTEXT}/../x.tar" >&2\n`,
      ['a character bash does not read as this test does', 'a command the script may not run', 'docker outside dk', 'a Colima path, socket, home or docker config of its own'],
    ],
    // \f* as the runs case's catch-all: a pattern no word matches, to bash,
    // so an image with any other user or entrypoint falls through to be pinned.
    ['U1, a \\f-led catch-all', '  *)\n    echo "error: ${IMAGE} (${id})', '  \f*)\n    echo "error: ${IMAGE} (${id})', ['a character bash does not read as this test does', 'the check of what the build made']],
    // Between the plan's check and the build, a Dockerfile or a context other
    // than the one scripts/worker-image.ts read.
    ['P1, a Dockerfile copied in', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\ncp "${REPO_ROOT}/../evil/Dockerfile" "${REPO_ROOT}/images/worker/Dockerfile"\n', ['REPO_ROOT beyond its assignment, CONTEXT and the plan', 'a command the script may not run']],
    ['P2, the context checked out from a branch', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\ngit -C "${REPO_ROOT}" checkout origin/evil -- images/worker\n', ['REPO_ROOT beyond its assignment, CONTEXT and the plan', 'a command the script may not run']],
    ['P3, the base edited in place', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', "mkdir -p \"${AOS_DOCKER_CONFIG}\"\nsed -i '' 's/@sha256:[0-9a-f]*//' \"${REPO_ROOT}/images/worker/Dockerfile\"\n", ['REPO_ROOT beyond its assignment, CONTEXT and the plan', 'a command the script may not run']],
    ['P4, a Dockerfile fetched', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\ncurl -fsS https://example.invalid/Dockerfile | tee "${REPO_ROOT}/images/worker/Dockerfile" >&2\n', ['REPO_ROOT beyond its assignment, CONTEXT and the plan', 'a command the script may not run']],
    ['P5, the context unfenced', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nrm -rf "${REPO_ROOT}/images/worker/.dockerignore"\n', ['REPO_ROOT beyond its assignment, CONTEXT and the plan', 'a command the script may not run']],
    // The same, with no REPO_ROOT to see: the command alone is refused.
    ['P6, the Dockerfile copied in by a path of its own', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n{ cp "$(dirname "$0")/../../evil/Dockerfile" "$(dirname "$0")/../images/worker/Dockerfile"; }\n', ['a command the script may not run']],
    // Arithmetic, which the command reading does not follow, ends its reading
    // of the line, and the cp after it is seen only as what was not read.
    ['P7, arithmetic before a cp', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}" "$((1))"; cp /tmp/evil/Dockerfile "$(dirname "$0")/../images/worker/Dockerfile"\n', ['a construct the command reading does not follow']],
    // bash runs process substitution inside [[ ]], where the reading skips
    // the operators a condition holds.
    ['P8, process substitution inside a condition copies a Dockerfile in', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n[[ -n <(cp "$(dirname "$0")/../../evil/Dockerfile" "$(dirname "$0")/../images/worker/Dockerfile") ]]\n', ['a construct the command reading does not follow']],
    // A value run as code, by prompt expansion or as arithmetic: no command
    // word is in the text to see, and out is a name the script assigns
    // already. A single-quoted value is no command substitution until bash
    // expands it so.
    ['P9, a prompt expansion runs a value', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)\'\nmkdir -p "${out@P}"\n', ['a construct the command reading does not follow']],
    ['P10, an offset runs a value as arithmetic', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\nmkdir -p "${id:out}"\n', ['a construct the command reading does not follow']],
    ['P11, a comparison runs a value as arithmetic', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\n[[ $out -eq 0 ]] || exit 1\n', ['a construct the command reading does not follow']],
    ['P12, a subscript runs a value as arithmetic', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\nmkdir -p "${BASH_SOURCE[$out]}"\n', ['a construct the command reading does not follow']],
    ['P13, an indirection runs a value as arithmetic', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\nmkdir -p "${!out}"\n', ['a construct the command reading does not follow']],
    // A length's subscript, after the `#` the reading once took for the
    // special parameter, and an array element's, in an assignment the
    // reading once skipped whole: both are arithmetic to bash.
    ['P14, a length of a subscript runs a value', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\nout="${#BASH_SOURCE[$out]}"\n', ['a construct the command reading does not follow']],
    ["P15, an array element's assignment runs a value", 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\nout[$out]=1\n', ['a construct the command reading does not follow']],
    // -v inside [[ ]] reads its operand as a name, a subscript evaluated as
    // arithmetic among it: a value a[$(...)] runs the substitution.
    ['P16, -v in a condition runs a value', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -p "${AOS_DOCKER_CONFIG}"\nout=\'a[$(cp /tmp/evil/Dockerfile images/worker/Dockerfile)]\'\n[[ ! -v $out ]] || exit 1\n', ['a construct the command reading does not follow']],
    // mkdir -v prints to stdout, which carries the id alone.
    ['M1, mkdir -pv', 'mkdir -p "${AOS_DOCKER_CONFIG}"\n', 'mkdir -pv "${AOS_DOCKER_CONFIG}"\n', ['mkdir, exactly as pinned']],
  ]
  for (const [name, from, to, labels] of mutants) {
    assert.equal(text.split(from).length, 2, `${name}: its anchor is not in the script exactly once`)
    const mutant = text.replace(from, () => to)
    assert.notDeepEqual(scriptCode(mutant), BUILD_SCRIPT_CODE, name)
    const found = buildScriptProblems(mutant, driverEnv, keys).map((p) => p.slice(0, p.indexOf(': ')))
    for (const label of labels) assert.ok(found.includes(label), `${name} is not refused as '${label}': ${found.join('; ')}`)
  }
})

test("the build's plan refuses a placeholder digest and any base but node:24-bookworm-slim by digest, the default Colima profile and one socket for both domains; its sockets and DOCKER_CONFIG are those boot's driver hands docker", async () => {
  // scripts/worker-image.ts, which scripts/build-worker-image.sh runs before
  // any docker command and stops on: what it refuses here, the build never
  // starts on.
  const shipped = read('images/worker/Dockerfile')
  const from = /^FROM \S+$/m.exec(shipped)?.[0] ?? ''
  assert.ok(from !== '', 'the Dockerfile has no FROM line')
  const digest = from.slice(from.indexOf('@') + 1)
  const swap = (line: string): string => shipped.replace(from, () => line)
  const config = parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO })
  assert.equal(baseProblem(shipped), undefined)

  // A placeholder digest, as a FROM is left when its digest is not known yet:
  // refused, naming it and where the real one comes from.
  for (const placeholder of [`sha256:${'0'.repeat(64)}`, `sha256:${'f'.repeat(64)}`]) {
    const text = swap(`FROM ${WORKER_BASE}@${placeholder}`)
    assert.match(baseProblem(text) ?? '', new RegExp(`base digest ${placeholder} is a placeholder, not a digest any registry serves`))
    assert.throws(() => planFrom(text, config), (e: unknown) => e instanceof ConfigError && e.message.includes('is a placeholder'))
  }
  // Every other way the base is not the operator's, by a digest, alone.
  const refused: [string, RegExp][] = [
    [`FROM ${WORKER_BASE}`, /must be exactly FROM node:24-bookworm-slim@sha256:<64 lower-case hex>/],
    [`FROM ${WORKER_BASE}@sha256:<digest>`, /must be exactly FROM/],
    [`FROM node:22-bookworm-slim@${digest}`, /must be exactly FROM/],
    [`FROM node:24-bookworm@${digest}`, /must be exactly FROM/],
    [`FROM --platform=linux/amd64 ${WORKER_BASE}@${digest}`, /must be exactly FROM/],
    [`FROM ${WORKER_BASE}@${digest} AS worker`, /must be exactly FROM/],
    [`FROM ${WORKER_BASE}@${digest.toUpperCase().replace('SHA256', 'sha256')}`, /must be exactly FROM/],
    [`FROM \\\n  ${WORKER_BASE}@${digest}`, /must be exactly FROM/],
    [`${from}\nFROM alpine:3.20`, /has 2 FROM lines; it must have exactly one/],
    [`${from}\n  from ${WORKER_BASE}@${digest}`, /has 2 FROM lines/],
    [`# syntax=docker/dockerfile:1\n${from}`, /has a syntax directive/],
    [`// syntax=docker/dockerfile:1\n${from}`, /has a syntax directive/],
    [`\u0085# syntax=docker/dockerfile:1\n${from}`, /has a syntax directive/],
    [`${from}\n\u0085FROM alpine:3.20`, /has 2 FROM lines/],
    // Read as BuildKit reads the file, continued lines joined: a FROM split
    // across lines is a FROM, and a FROM continued into a RUN is not one. So
    // a second stage spelled FR\ then OM is refused, and so is a base by tag
    // spelled that way while the pinned FROM below it is a RUN's text.
    [`${from}\nFR\\\nOM debian:latest`, /has 2 FROM lines/],
    [`FR\\\nOM debian:latest\nRUN true \\\n${from}`, /base is "FROM debian:latest": it must be exactly FROM/],
    // Every \r at a line's end is dropped before the `\` is looked for, as
    // BuildKit's trimNewline drops them all.
    [`${from}\nFR\\\r\r\nOM debian:latest`, /has 2 FROM lines/],
    // What BuildKit joins after a `\` with a space after it is not checked
    // here (FROM debian:latest, or FROMdebian:latest): refused.
    [`${from}\nFROM\\ \ndebian:latest`, /has a `\\` with a space or tab after it, on line \d+/],
    // The keyword ends at a tab as at a space, and a comment line is dropped
    // inside a continued instruction too, so the `\` that ends one continues
    // nothing.
    [`${from}\nFROM\tdebian:latest`, /has 2 FROM lines/],
    [`${from}\n# a comment \\\nFROM debian:latest`, /has 2 FROM lines/],
    // A line BuildKit strips of its leading white space, a VT among it,
    // before it reads the keyword.
    [`${from}\n\vFROM alpine:3.20`, /has 2 FROM lines/],
    // Files from an image other than the base, by whatever name BuildKit is
    // given (a tag among them), or from anywhere but the context: refused,
    // naming the instruction, whatever else the file holds.
    [`${from}\nCOPY --from=debian:latest /bin/sh /opt/aos/sh`, /'s COPY takes files from another image \(--from, or a mount's from=\), which BuildKit pulls/],
    [`${from}\ncopy --FROM=debian:latest /bin/sh /opt/aos/sh`, /'s COPY takes files from another image/],
    [`${from}\nRUN --mount=type=bind,from=alpine:latest,target=/x cp /x/bin/busybox /opt/aos/`, /'s RUN takes files from another image/],
    [`${from}\nRUN --mount=from=alpine:latest,target=/x true`, /'s RUN takes files from another image/],
    [`${from}\nRUN --mount=type=bind,FROM=alpine:latest,target=/x true`, /'s RUN takes files from another image/],
    // Spelled with quotes or a backslash, which BuildKit's flag reader takes
    // off a `--` word before BFlags or the mount's CSV reads it.
    [`${from}\nCOPY --"from"=debian:latest /bin/sh /opt/aos/sh`, /'s COPY takes files from another image/],
    [`${from}\nCOPY --fr\\om=debian:latest /bin/sh /opt/aos/sh`, /'s COPY takes files from another image/],
    [`${from}\nRUN --mount=type=bind,"from=alpine:latest",target=/x cp /x/bin/busybox /opt/aos/`, /'s RUN takes files from another image/],
    [`${from}\nRUN --mount=type=bind,fr''om=alpine:latest,target=/x cp /x/bin/busybox /opt/aos/`, /'s RUN takes files from another image/],
    [`${from}\nADD https://example.invalid/busybox /opt/aos/busybox`, /has ADD: ADD fetches what a URL or a git ref names, and ONBUILD runs an instruction in another build/],
    [`${from}\nADD gitconfig /etc/gitconfig`, /has ADD: /],
    [`${from}\nONBUILD RUN true`, /has ONBUILD: /],
  ]
  for (const [line, why] of refused) {
    assert.match(baseProblem(swap(line)) ?? '', why, line)
    assert.throws(() => planFrom(swap(line), config), (e: unknown) => e instanceof ConfigError && why.test(e.message), line)
  }
  // A FROM spelled on two lines that joins to exactly the pinned one is the
  // pinned base, as BuildKit reads it.
  assert.equal(baseProblem(swap(`FROM\\\n ${WORKER_BASE}@${digest}`)), undefined)
  assert.match(baseProblem(shipped.replace(/^FROM .*$/m, '')) ?? '', /has 0 FROM lines/)
  // Where the reading is not certain, refused, though the base is pinned: an
  // empty line inside a continued instruction (BuildKit joins the line after
  // it on, warning that it will become an error), and a last line that
  // continues an instruction the file never ends.
  assert.match(baseProblem(shipped.replace('ENTRYPOINT []\n', 'ENTRYPOINT [] \\\n')) ?? '', /has an empty line inside a continued instruction, on line \d+: BuildKit joins the line after it on/)
  assert.match(baseProblem(shipped.replace(/\nUSER 65534:65534\n?$/, '\nUSER 65534:65534 \\\n')) ?? '', /ends inside a continued line/)
  // A heredoc, whose body BuildKit reads as text and readDockerfile as
  // instructions: after the shipped USER line, a RUN heredoc whose quoted
  // terminator keeps its backslash. BuildKit reads `true` as its body and
  // the line `EOF\` as its end, then FROM debian:latest as a second stage,
  // the last, which `docker build` builds; readDockerfile joins `EOF\` to
  // the FROM after it, and sees one FROM, the pinned one. Refused, as a plain
  // COPY heredoc is, and one whose `<<` its lines join.
  const terminator = `${shipped}RUN <<'EOF\\'\ntrue\nEOF\\\nFROM debian:latest\nUSER 65534:65534\nENTRYPOINT []\n`
  assert.deepEqual(
    readDockerfile(terminator).steps.filter((step) => step.keyword === 'FROM').map((step) => step.text),
    [from],
    'readDockerfile reads the heredoc as instructions, and one FROM',
  )
  const heredocs: [string, RegExp][] = [
    [terminator, /has a heredoc \(`<<`\) on line \d+: BuildKit reads a heredoc's body as text, not instructions/],
    [`${shipped}COPY <<EOF /x\nhello\nEOF\n`, /has a heredoc \(`<<`\) on line \d+: BuildKit reads a heredoc's body as text, not instructions/],
    [`${shipped}COPY <\\\n<EOF /x\nhello\nEOF\n`, /has a heredoc \(`<<`\) in its COPY, as its lines join: BuildKit reads a heredoc's body as text, not instructions/],
  ]
  for (const [text, why] of heredocs) {
    assert.match(baseProblem(text) ?? '', why, text.slice(shipped.length))
    assert.throws(() => planFrom(text, config), (e: unknown) => e instanceof ConfigError && why.test(e.message), text.slice(shipped.length))
  }
  // `<<` in a comment is no heredoc: BuildKit drops the line.
  assert.equal(baseProblem(shipped.replace('# The aos worker image', '# The aos worker image, no <<EOF heredoc,')), undefined)
  // A parser directive on line 1, before the header: escape would make a
  // backtick the continuation, so FR` then OM debian:latest, which the
  // reading here takes as two instructions, is BuildKit's second stage.
  for (const first of ['# escape=`', '\uFEFF# escape=`', ' # check=skip=all', '# syntax=docker/dockerfile:1']) {
    const text = `${first}\n${swap(`${from}\nFR\`\nOM debian:latest`)}`
    assert.match(baseProblem(text) ?? '', /starts with a parser directive, ".*": escape changes which lines BuildKit joins/, first)
    assert.throws(() => planFrom(text, config), (e: unknown) => e instanceof ConfigError && e.message.includes('starts with a parser directive'), first)
  }
  // And, once all else is read, any character that is not printable ASCII, a
  // tab or a newline, a comment's included: how BuildKit's Go reads it never
  // decides what is built.
  for (const [stray, named] of [['\u00a0', 'U+00A0'], ['\uFEFF', 'U+FEFF'], ['\r', 'U+000D'], ['\u3000', 'U+3000'], ['\v', 'U+000B'], ['\x7f', 'U+007F']] as const) {
    const text = shipped.replace('# The aos worker image', `#${stray}The aos worker image`)
    assert.notEqual(text, shipped)
    assert.equal(baseProblem(text), `images/worker/Dockerfile holds ${named}: it may hold only printable ASCII, tabs and newlines, so that no other character's reading decides what is built`)
  }

  // As shipped, the plan is the Dockerfile's base, kernel.yaml's tag, and the
  // sockets and DOCKER_CONFIG boot's own driver hands docker: the build talks
  // to the daemons the kernel does, under the kernel's docker config.
  const plan = workerImagePlan(REPO, {})
  assert.deepEqual(plan, {
    base: from.slice('FROM '.length),
    image: config.sandbox.image,
    trusted: config.sandbox.domains.trusted.dockerHost,
    hostile: config.sandbox.domains.hostile.dockerHost,
    dockerConfig: join(config.dataDir, 'docker'),
  })
  const envs = await driverDockerEnvs()
  assert.deepEqual([...new Set(envs.map((env) => env['DOCKER_HOST']))], [plan.trusted, plan.hostile])
  assert.deepEqual([...new Set(envs.map((env) => env['DOCKER_CONFIG']))], [plan.dockerConfig])
  assert.match(plan.trusted, /^unix:\/\/\/.+\/\.colima\/trusted\/docker\.sock$/)
  // AOS_DATA_DIR moves the kernel's DOCKER_CONFIG, as it moves the daemon's (src/main.ts).
  const elsewhere = join(REPO, '.aos', 'elsewhere')
  assert.equal(workerImagePlan(REPO, { AOS_DATA_DIR: elsewhere }).dockerConfig, join(elsewhere, 'docker'))

  // Never the default Colima profile, in either of its sockets' places, any
  // case (APFS) and any spelling the kernel's docker calls would connect
  // through all the same (`//`, `.`, `..`), and never one socket for both
  // domains. Spelled outright (expandDockerHost resolves only the `~/` form),
  // under a home no machine has, so that no socket is there to resolve:
  // what is refused here is refused by spelling alone. The next test follows
  // symlinks and links on a real filesystem.
  const raw = read('config/kernel.yaml')
  const hosts = (trusted: string, hostile: string): KernelConfig =>
    parseKernelConfig(
      parseYaml(raw.replace('unix://~/.colima/trusted/docker.sock', trusted).replace('unix://~/.colima/hostile/docker.sock', hostile)),
      { repoRoot: REPO },
    )
  const ownHostile = 'unix://~/.colima/hostile/docker.sock'
  const nowhere = '/nonexistent-aos-home/op'
  for (const [trusted, hostile, domain] of [
    ['unix://~/.colima/default/docker.sock', ownHostile, 'trusted'],
    ['unix://~/.colima/trusted/docker.sock', 'unix://~/.colima/docker.sock', 'hostile'],
    ['unix://~/.colima/Default/docker.sock', ownHostile, 'trusted'],
    [`unix://${nowhere}/.colima//default/docker.sock`, ownHostile, 'trusted'],
    [`unix://${nowhere}/.colima/./default/docker.sock`, ownHostile, 'trusted'],
    [`unix://${nowhere}/.colima/trusted/../default/docker.sock`, ownHostile, 'trusted'],
    ['unix://~/.colima/trusted/docker.sock', `unix://${nowhere}/.colima/default/./docker.sock`, 'hostile'],
    ['unix://~/.colima/trusted/docker.sock', `unix://${nowhere}/.colima/hostile/../docker.sock`, 'hostile'],
  ] as const) {
    assert.throws(
      () => planFrom(shipped, hosts(trusted, hostile)),
      (e: unknown) => e instanceof ConfigError && e.message.startsWith(`sandbox.domains.${domain}.dockerHost`) && e.message.includes("is the default Colima profile's socket, which shares $HOME writable"),
      `${trusted} ${hostile}`,
    )
  }
  const ownTrusted = `unix://${nowhere}/.colima/trusted/docker.sock`
  for (const [trusted, hostile] of [
    ['unix://~/.colima/trusted/docker.sock', 'unix://~/.colima/trusted/docker.sock'],
    ['unix://~/.colima/trusted/docker.sock', 'unix://~/.colima/TRUSTED/docker.sock'],
    [ownTrusted, `unix://${nowhere}/.colima/./trusted/docker.sock`],
    [ownTrusted, `unix://${nowhere}/.colima/trusted//docker.sock`],
    [ownTrusted, `unix://${nowhere}//.colima/hostile/../trusted/docker.sock`],
    [`unix://${nowhere}/.colima/Trusted/./docker.sock`, ownTrusted],
  ] as const) {
    assert.throws(() => planFrom(shipped, hosts(trusted, hostile)), /are one socket/, `${trusted} ${hostile}`)
  }
  // Two sockets of their own, spelled outright, are two VMs.
  assert.equal(planFrom(shipped, hosts(ownTrusted, `unix://${nowhere}/.colima/hostile/docker.sock`)).hostile, `unix://${nowhere}/.colima/hostile/docker.sock`)

  // A path with a space or a character outside printable ASCII in it, here at
  // its end, which a YAML double-quoted scalar carries and `read -r` keeps:
  // the docker CLI may trim white space from DOCKER_HOST (Go's
  // strings.TrimSpace trims U+0085, U+00A0, U+2028 and U+3000 as well as
  // ASCII space and tab), so the default profile's socket, or trusted's named
  // again for hostile, would be judged as a socket that is not there and
  // connected to as the one it is. Refused before either check, naming the
  // key, and anywhere in the path.
  const quoted = (host: string): string => JSON.stringify(host).replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
  const unprintable = (domain: string) => (e: unknown): boolean =>
    e instanceof ConfigError &&
    e.message.startsWith(`sandbox.domains.${domain}.dockerHost "unix://`) &&
    e.message.includes('has a space or a character that is not printable ASCII in its path') &&
    !/[^\x20-\x7e]/.test(e.message)
  // A case APFS folds outside ASCII (U+017F, long s, folds to s) is judged
  // the default profile's by its spelling, and refused before that as
  // unprintable.
  const longS = `unix://${nowhere}/.colima/default/docker.\u017fock`
  assert.match(namesDefaultColima(longS, macSockets(nowhere)) ?? '', /^it reaches .*\/\.colima\/default\/docker\.sock$/)
  assert.throws(() => planFrom(shipped, hosts('unix://~/.colima/trusted/docker.sock', longS)), unprintable('hostile'))
  for (const space of [' ', '\t', '\u00a0', '\u0085', '\u2028', '\u3000']) {
    for (const [trusted, hostile, domain] of [
      [`unix://~/.colima/default/docker.sock${space}`, ownHostile, 'trusted'],
      [`unix://${nowhere}/.colima/default/docker.sock${space}`, ownHostile, 'trusted'],
      ['unix://~/.colima/trusted/docker.sock', `unix://~/.colima/docker.sock${space}`, 'hostile'],
      ['unix://~/.colima/trusted/docker.sock', `unix://~/.colima/trusted/docker.sock${space}`, 'hostile'],
      [`unix://${nowhere}/.colima/hostile/docker.sock${space}`, `unix://${nowhere}/.colima/hostile/docker.sock`, 'trusted'],
      [`unix://${nowhere}/.colima/trusted${space}/docker.sock`, ownHostile, 'trusted'],
    ] as const) {
      const config = hosts(quoted(trusted), quoted(hostile))
      assert.equal(config.sandbox.domains[domain].dockerHost.endsWith(space) || config.sandbox.domains[domain].dockerHost.includes(`${space}/`), true, 'the YAML did not carry the character')
      assert.throws(() => planFrom(shipped, config), unprintable(domain), `${JSON.stringify(trusted)} ${JSON.stringify(hostile)}`)
    }
  }

  // The tag is a name:tag docker cannot read as an option or as an image id.
  for (const image of ['aos-worker', '-aos-worker:0.0.1', 'Aos-Worker:0.0.1', 'aos worker:0.0.1', `sha256:${'a'.repeat(64)}`]) {
    assert.throws(() => planFrom(shipped, { ...config, sandbox: { ...config.sandbox, image } }), /is not a name:tag the build can give the image/, image)
  }

  // One KEY=value line each, in order, and a value one line cannot carry is
  // refused rather than read by the script as a second key.
  assert.equal(
    planText(plan),
    `BASE=${plan.base}\nIMAGE=${plan.image}\nTRUSTED_DOCKER_HOST=${plan.trusted}\nHOSTILE_DOCKER_HOST=${plan.hostile}\nDOCKER_CONFIG=${plan.dockerConfig}\n`,
  )
  assert.throws(() => planText({ ...plan, dockerConfig: `${plan.dockerConfig}\nTRUSTED_DOCKER_HOST=unix:///elsewhere.sock` }), /DOCKER_CONFIG is empty or holds a control character/)
  assert.throws(() => planText({ ...plan, image: '' }), /IMAGE is empty/)
})

test("the build's plan follows each socket on the Mac: a symlink or a second link to the default profile's socket is refused, and so are two names for one socket", () => {
  // macSockets is what scripts/worker-image.ts asks the Mac when the build
  // script runs: realpath(3) of each socket path, and its device and inode.
  // Regular files stand in for sockets here (realpath and stat do not care),
  // in a temporary home and a .colima of its own.
  const shipped = read('images/worker/Dockerfile')
  const raw = read('config/kernel.yaml')
  const root = mkdtempSync(join(tmpdir(), 'aos-sockets-'))
  try {
    const home = join(root, 'home')
    const colima = join(home, '.colima')
    for (const profile of ['default', 'trusted', 'hostile']) {
      mkdirSync(join(colima, profile), { recursive: true })
      writeFileSync(join(colima, profile, 'docker.sock'), '')
    }
    const sock = (profile: string): string => join(colima, profile, 'docker.sock')
    const fs = macSockets(home)
    const plan = (trusted: string, hostile: string): unknown =>
      planFrom(
        shipped,
        parseKernelConfig(
          parseYaml(raw.replace('unix://~/.colima/trusted/docker.sock', `unix://${trusted}`).replace('unix://~/.colima/hostile/docker.sock', `unix://${hostile}`)),
          { repoRoot: REPO },
        ),
        fs,
      )
    const isDefault = (domain: string, how: RegExp) => (e: unknown): boolean =>
      e instanceof ConfigError &&
      e.message.startsWith(`sandbox.domains.${domain}.dockerHost`) &&
      e.message.includes("is the default Colima profile's socket, which shares $HOME writable") &&
      how.test(e.message)

    // Each domain's own socket, as the shipped kernel.yaml names them.
    assert.deepEqual(plan(sock('trusted'), sock('hostile')), {
      base: shipped.match(/^FROM (\S+)$/m)?.[1],
      image: 'aos-worker:0.0.1',
      trusted: `unix://${sock('trusted')}`,
      hostile: `unix://${sock('hostile')}`,
      dockerConfig: join(REPO, '.aos', 'docker'),
    })

    // A symlink, spelled any way, to a default profile's socket wherever its
    // .colima is: refused by where it leads, not by its name.
    const elsewhere = join(root, 'Volumes', 'x', '.colima', 'default')
    mkdirSync(elsewhere, { recursive: true })
    writeFileSync(join(elsewhere, 'docker.sock'), '')
    symlinkSync(join(elsewhere, 'docker.sock'), join(root, 'vm.sock'))
    assert.throws(() => plan(join(root, 'vm.sock'), sock('hostile')), isDefault('trusted', /it reaches .*\/volumes\/x\/\.colima\/default\/docker\.sock\)/))
    // A symlinked directory before a `..`, followed as the OS opens it
    // (realpath(3)): jump/.. is deep, whose profile is the default's. Read
    // lexically, as Node's own realpath and path.join would, it is
    // <root>/profile, which is not there. Spelled with a string, not join.
    mkdirSync(join(root, 'deep', 'er'), { recursive: true })
    symlinkSync(join(root, 'deep', 'er'), join(root, 'jump'))
    symlinkSync(elsewhere, join(root, 'deep', 'profile'))
    const viaDotDot = `${root}/jump/../profile/docker.sock`
    assert.throws(() => plan(sock('trusted'), viaDotDot), isDefault('hostile', /it reaches .*\/volumes\/x\/\.colima\/default\/docker\.sock\)/))

    // A hard link to the default profile's socket under the home directory,
    // and the default profile's socket kept somewhere else behind a symlink:
    // no spelling says default, but it is the same file.
    linkSync(sock('default'), join(root, 'hard.sock'))
    assert.throws(() => plan(join(root, 'hard.sock'), sock('hostile')), isDefault('trusted', /it is the same file as .*\/\.colima\/default\/docker\.sock\)/))
    const lima = join(root, 'lima', 'colima', 'sock')
    mkdirSync(lima, { recursive: true })
    writeFileSync(join(lima, 'docker.sock'), '')
    rmSync(join(colima, 'docker.sock'), { force: true })
    symlinkSync(join(lima, 'docker.sock'), join(colima, 'docker.sock'))
    assert.throws(() => plan(sock('trusted'), join(lima, 'docker.sock')), isDefault('hostile', /it is the same file as .*\/\.colima\/docker\.sock\)/))

    // Two names for one socket: a symlink to trusted's, and a hard link.
    symlinkSync(sock('trusted'), join(root, 'trusted-again.sock'))
    linkSync(sock('trusted'), join(root, 'trusted-hard.sock'))
    for (const hostile of [join(root, 'trusted-again.sock'), join(root, 'trusted-hard.sock')]) {
      assert.throws(() => plan(sock('trusted'), hostile), /are one socket/, hostile)
    }

    // A path that is not there is judged by its spelling (no daemon answers on
    // it); one that cannot be resolved for any other reason is refused.
    assert.equal(fs.realpath(join(root, 'absent', 'docker.sock')), undefined)
    assert.equal(fs.realpath(join(sock('trusted'), 'below')), undefined)
    symlinkSync(join(root, 'loop-b'), join(root, 'loop-a'))
    symlinkSync(join(root, 'loop-a'), join(root, 'loop-b'))
    assert.throws(() => plan(join(root, 'loop-a'), sock('hostile')), (e: unknown) => e instanceof ConfigError && /the docker socket .*loop-a cannot be resolved/.test(e.message))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test("README and CLAUDE.md give one reason containers cannot reach pmmcp: --network none, with each domain's internal network probed as defence in depth, and the kernel's egress engine, not a proxy, denying the Mac's loopback", () => {
  // The egress plan's S1 (the operator, 2026-11-09): every run is --network
  // none, so no container has a route anywhere. The aos-<domain> networks and
  // the probe's Internal=true check stay, but only as defence in depth: no
  // run is put on them, so they are no longer why a container cannot reach
  // pmmcp, and the old design's egress proxy does not exist.
  const flat = (text: string): string => text.replace(/\s+/g, ' ')
  const readme = read('README.md')
  const start = readme.indexOf('Until then, access rests on the two conditions the operator set')
  const end = readme.indexOf("pmmcp's other keys", start)
  assert.ok(start > 0 && end > start, "README has no pmmcp access section ending at pmmcp's other keys")
  const section = flat(readme.slice(start, end))
  const [contained = '', denied = ''] = section.split('- **').slice(1)
  assert.ok(contained.startsWith('Containers stay off it.** '), section)
  for (const fact of ['Every container runs with `--network none`', 'no route at all, so no container has a route there', 'the sandbox probe still refuses a domain whose docker network is not `--internal`, as defence in depth: no run is put on it']) {
    assert.ok(contained.includes(fact), `README's containers bullet does not say: ${fact}`)
  }
  assert.ok(denied.startsWith("The kernel's egress engine denies it** (`src/egress`, wired since egress plan W1, never yet run live)"), section)
  assert.ok(denied.includes("a worker's one way out is that engine, over its run's `docker -i` channel"), denied)
  for (const name of ['`192.168.5.2`', '`host.lima.internal`', '`host.docker.internal`']) assert.ok(denied.includes(name), `README's egress bullet does not name ${name}`)
  assert.doesNotMatch(section, /egress proxy|proxy sidecar|not `--internal`, so no container/, 'README still gives the old design as the reason')

  // CLAUDE.md's paired fact gives the same reason.
  const claude = flat(read('CLAUDE.md'))
  assert.ok(
    claude.includes('Containers are kept off it by `--network none` (the `aos-<domain>` internal networks and their probe stay as defence in depth)'),
    "CLAUDE.md's pmmcp fact does not keep containers off it by --network none",
  )
  assert.doesNotMatch(claude, /Containers are kept off it by internal networks/)

  // And what both say stays is what kernel.yaml ships: each domain names its
  // own internal network, which no run is put on.
  const config = parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO })
  assert.deepEqual([config.sandbox.domains.trusted.network, config.sandbox.domains.hostile.network], ['aos-trusted', 'aos-hostile'])
})

test("README names no egress proxy, and its sandbox record says the internal network kept containers off pmmcp only until 2026-11-09", () => {
  // The accepted design (the operator, 2026-11-09) has no proxy at all: the
  // kernel's egress engine, over each run's docker -i channel, with every run
  // on --network none. A README line that names a proxy, or says in the
  // present tense that a domain's internal network is what stands between a
  // container and pmmcp, tells the next reader to build or trust the old
  // design. The stub's id, `egress-proxy`, went with the stub (egress plan
  // W1), so no name of the old design is left.
  const flat = (text: string): string => text.replace(/\s+/g, ' ')
  const readme = flat(read('README.md'))
  assert.doesNotMatch(readme, /egress proxy|egress-proxy|proxy sidecar|Phase 2 proxy|no proxy/i)
  assert.ok(
    readme.includes("pmmcp fetch URLs itself and so would route around the kernel's egress engine)"),
    "README's scrape_context pin does not say it would route around the kernel's egress engine",
  )

  // The dated record of 2026-10-21 ran its container on the domain's internal
  // network, which was every run's network then; it says that it no longer is.
  assert.ok(
    readme.includes("uid 65534, on the domain's internal network (every run's network until 2026-11-09; since then every run is `--network none`)"),
    "README's sandbox record does not date the internal network it ran on",
  )
  const start = readme.indexOf('- **The VMs themselves reach pmmcp.**')
  const end = readme.indexOf('- **', start + 1)
  assert.ok(start > 0 && end > start, "README's sandbox record has no 'The VMs themselves reach pmmcp' bullet")
  const bullet = readme.slice(start, end)
  for (const fact of [
    'Until 2026-11-09 the internal network was the only thing between a container and pmmcp',
    "since then every run is `--network none`, and a worker's one way out is the kernel's egress engine, over its run's `docker -i` channel",
    "The egress engine runs on the Mac itself, so its refusal of the Mac's loopback is what keeps a worker's flows off pmmcp",
  ]) {
    assert.ok(bullet.includes(fact), `README's 'The VMs themselves reach pmmcp' bullet does not say: ${fact}\n${bullet}`)
  }
  assert.doesNotMatch(bullet, /Today the internal network is/, bullet)
})

test("README's console table says what a kill does to a run, in the reason the run loop records", () => {
  const row = read('README.md').split('\n').find((line) => line.startsWith('| `kill <runId>'))
  assert.equal(
    row,
    `| \`kill <runId> [--reason R]\` | yes | abort a run, queued or started: it makes no further model or tool call, and ends \`killed\`, reason \`${STOP_REQUESTED}\` (or a budget cap's, if one ran out before the stop, or the wallclock's, if it has run out by the time the stop is read); one parked on an approval ends once that approval is answered or expires |`,
  )
})

test("README's agents section: 'Both carry' follows the paragraph on the two shipped agents, and sandbox.exec's paragraph says how it ends a container and what a human approving one is shown", () => {
  // 'Both' means researcher and writer: a paragraph set between it and the
  // one that names them makes it read as the two of something else.
  const paragraphs = read('README.md').split(/\n\s*\n/).map((p) => p.replace(/\s+/g, ' ').trim())
  const neither = paragraphs.findIndex((p) => p.includes('Neither agent declares a `sandbox:`'))
  assert.ok(neither > 0, "README has no 'Neither agent declares a `sandbox:`' paragraph")
  assert.match(paragraphs[neither + 1] ?? '', /^Both carry `tools\.allow: \[\]`/, "the paragraph after 'Neither agent declares' is not 'Both carry'")
  const sandbox = paragraphs.find((p) => p.startsWith('Sandbox tools are checked at load as egress is (egress plan S3).'))
  assert.ok(sandbox !== undefined, "README has no sandbox.exec paragraph")
  assert.ok(paragraphs.indexOf(sandbox) > neither + 1, "the sandbox.exec paragraph sits before 'Both carry'")
  for (const fact of [
    `kills the container by name before that end when the docker client ended with no exit status or with ${String(DOCKER_CLI_FAILED)} (its own failure`,
    `it waits ${String(KILL_WAIT_MS / 1_000)} s at most for that kill, so that kill never holds the run.`,
    // The driver's result is bounded too (egress plan W1a), past the
    // container's wallclock, and past a stop, and a run given up is ended as
    // an error.
    `The driver's own result is awaited for the container's wallclock and ${String(RESULT_GRACE_MS / 1_000)} s more at most,`,
    `and once the run is stopped (\`aos kill\`, or a shutdown), whose kill by name goes out then, for ${String(RESULT_GRACE_MS / 1_000)} s from the stop at most:`,
    'so a daemon that accepts and never answers (a paused Colima VM) would hold the call, and the run, for good.',
    'Past that bound the runner gives the container up: the driver ends the docker client it spawned (SIGKILL, the one process it signals) and kills the container by name on its own domain,',
    `waited on for ${String(KILL_WAIT_MS / 1_000)} s at most, and \`sandbox.killed\` records \`error\`, the result saying the driver never answered.`,
    `An exec whose arguments the approval preview would cut (${String(APPROVAL_PREVIEW_BYTES)} bytes of their canonical JSON), would redact`,
    // Refused before the gate files an approval (W1a): no human approves a
    // command the runner then refuses, the driver's audit's refusals among
    // them.
    "or whose command the driver's own audit refuses (a `-v`, `--volume`, `--mount` or `--device` anywhere in it, the docker socket, or an argument that is the operator's home or a path under it, in either spelling)",
    "never runs, and no human is asked to approve it: the run loop asks the runner's own check of the arguments before the gate, and the gate denies the call, its `tool.gate` row giving the runner's refusal as the reason.",
    // And one the kernel's own config refuses, whatever its arguments.
    'The same holds for every exec on a kernel whose `sandbox.imageId` is unset or is no image id, which can build no container, or whose `sandbox.driver` is `apple-container`, a stub that runs nothing: no run on it is offered the tool, and the gate denies a call of it before any human is asked.',
    // Wired, and offered only to what the registry admits.
    'The runner (`src/runtime/sandbox-tools.ts`) is wired into the daemon (egress plan W1a): every `sandbox.*` call goes to it, never to the hub,',
    // Denied before the gate to a caller the registry does not admit, and
    // after it only when the registry changes while a human is asked.
    'Any other run that names it is denied it before the gate asks anyone, its `tool.gate` row giving the reason,',
    'is denied it once approved, with a `tool.result` saying so.',
    'No shipped manifest lists it, so no shipped agent is offered it.',
    '`npm run cli -- search --type approval.requested --run <runId> --limit 1`',
    "Each output stream keeps its own share of the result, counted in the bytes it takes in the log's JSON.",
    `Of each stream the runner reads and redacts at most ${String(STREAM_WINDOW_BYTES / 1_024)} KiB (the largest share and ${String(CAPTURE_EDGE_BYTES / 1_024)} KiB more):`,
    `all of a shorter one, the end of a longer one, and the start of one the driver capped at ${String(CAPTURE_MAX_BYTES / 1_048_576)} MiB,`,
    `not the ${String(CAPTURE_EDGE_BYTES / 1_024)} KiB there, nor anything past a private key block's marker whose other marker the cut left out.`,
    // Read from inside a token's match, a window's redaction can start a
    // token the stream's does not, one that breaks a BEGIN the stream's
    // keeps: past a word character, or inside a token that crosses the cut.
    "An end window is read from its cut, or, when a token's match may hold the character before it, from the first character past it that none may hold, none of what that skips shown: no token pattern's match runs across where it is read from, so its redaction matches each token the stream's matches there and no other, and breaks no marker the stream's keeps, nor keeps one it breaks.",
    'So an end window shows an end of what a redaction of the whole stream shows, and no more.',
    // What the windows do not follow, said rather than claimed away.
    `None of this follows a value the kernel's own mask holds, which no worker holds, nor, at a start window's cut, a token of a shape with an unbounded part that crosses it and runs on more than ${String(CAPTURE_EDGE_BYTES / 1_024)} KiB before it.`,
    "A window whose start a key block may hold, however the stream's redaction pairs its markers, is shown from where the blocks that may hold it end instead, and not at all when none ends: all before that may be a block's body.",
    // A union, not one chain: a chain that an END the walk refuses and
    // redact.ts keeps leaves open closes on an END inside the next BEGIN.
    'Those blocks are read as a union, not as one pairing: every BEGIN, one inside another marker included, held open to the first END after it that no token pattern, run first, can break (one holding an AWS key id, or one a token runs into), and the blocks that overlap taken as one.',
    // The window bounds the PEM pattern's cost alone; the JWT pattern's is
    // held by withholding.
    'The window bounds that pattern\'s cost and no other\'s:',
    `in which it starts at more than ${String(JWT_RUN_STARTS_MAX)} places is withheld before any redaction reads it, the stream's byte count (what its capture kept, for one the driver capped) said in its place.`,
    "A result that shows a stream by its window, or withholds one, is marked `truncated`, and `tool.result`'s `bytes` and `sha256` are of what it shows before a stream is cut to its share, redacted: the windows short of their cut sides, not the streams.",
  ]) {
    assert.ok(sandbox.includes(fact), `README's sandbox.exec paragraph does not say: ${fact}`)
  }
  // Not what it said before W1a: that the human is asked first and the
  // runner refuses after, that the driver's result has no bound, or that the
  // runner is not wired.
  assert.doesNotMatch(sandbox, /the human is still asked first|the runner refuses the call after/)
  assert.doesNotMatch(sandbox, /with no such bound|until the wiring task/)
  assert.doesNotMatch(sandbox, /not yet wired/)
  // Nor that every denial of an unadmitted caller comes after the gate.
  assert.doesNotMatch(sandbox, /and denies it, with a `tool\.result` saying so, to any other run/)
  // And the agents paragraph gives the reason that holds since W1a, not that
  // the loop runs in process.
  assert.doesNotMatch(paragraphs[neither] ?? '', /the loop runs in process in this phase/)
  assert.ok(
    (paragraphs[neither] ?? '').includes('has its commands run in containers since egress plan W1a, and a shipped manifest that does waits on the Phase 2 exit, as egress does'),
    paragraphs[neither] ?? '',
  )
  // Nor that skipping the word characters a window starts with is enough: a
  // token that crosses the cut can still start one inside its run.
  assert.doesNotMatch(sandbox, /past the word characters/)
})

/**
 * The sentence README's mutation catalog section says the run edits with:
 * every file a mutant or a control in `catalog` names, those under src/ as one
 * directory and those under test/helpers/ by their count.
 */
function falsifyEditsSentence(catalog: typeof CATALOG): string {
  const files = [...new Set(catalog.flatMap((suite) => [...suite.mutants, suite.control].map((mutant) => mutant.file)))].sort()
  const helpers = files.filter((file) => file.startsWith('test/helpers/')).length
  const named = files.filter((file) => !file.startsWith('src/') && !file.startsWith('test/helpers/')).map((file) => `\`${file}\``)
  const counts = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve']
  const last = named.pop()
  const rest = last === undefined ? '' : `, and ${named.length === 0 ? last : `${named.join(', ')} and ${last}`}`
  return `It edits the working tree, in the files its mutants name: those under \`src/\`, ${counts[helpers] ?? String(helpers)} helpers under \`test/helpers/\`${rest}. So:`
}

test("README's mutation catalog section names every file the catalog's mutants edit", () => {
  const text = read('README.md').replace(/\s+/g, ' ')
  const sentence = falsifyEditsSentence(CATALOG)
  assert.ok(text.includes(sentence), `README does not say: ${sentence}`)
  // Two files outside src/ and test/ that the catalog mutates by the score.
  // (The mux's own file name is held to one test file by hygiene.test.ts.)
  assert.ok(sentence.includes('`scripts/worker-image.ts`') && sentence.includes('`images/worker/'), sentence)
  // The check reads the catalog: a mutant of a file README does not name is
  // caught, as is the sentence README held before, which named two helpers.
  const [first, ...others] = CATALOG
  assert.ok(first !== undefined)
  const more = [{ ...first, mutants: [...first.mutants, { ...first.control, id: 'X', file: 'scripts/elsewhere.ts' }] }, ...others]
  assert.ok(!text.includes(falsifyEditsSentence(more)), 'a file README does not name is caught')
  assert.doesNotMatch(text, /src\/ and two test helpers/)
})

test('.npmrc keeps npm\'s cache in the program folder', () => {
  // npm resolves a relative path config against the shell's cwd
  // (@npmcli/config parse-field.js), so the README says to run npm from the root.
  assert.match(read('.npmrc'), /^cache=\.aos\/npm-cache$/m)
})

test('config/tool-views.yaml: pmmcp pins nineteen closed, and only the two kernel tools, sandbox.exec and sandbox.publish are exposed', () => {
  const file = parseToolViews(readYaml('config/tool-views.yaml'))
  const servers = Object.keys(file.servers).sort()
  assert.deepEqual(servers, ['kernel', 'pmmcp', 'sandbox'])

  // The sandbox section (egress plan S3 and S4, the operator's acceptance of
  // 2026-11-09): exec and publish and nothing else. exec is write risk so a
  // tainted run needs a human for it, and taints: true, so the first exec of
  // a run makes every later write in it, the next exec among them, wait for a
  // human. publish is irreversible, so a human approves every call of it,
  // whatever the run's taint (gate rule 4, invariant 3).
  const exposedSandbox = Object.entries(file.servers['sandbox']!.tools).filter(([, v]) => v.exposure === 'agent')
  assert.deepEqual(exposedSandbox.map(([n]) => n), ['exec', 'publish'])
  const exec = resolveView(file, 'sandbox', 'exec')
  assert.deepEqual(
    { exposure: exec.exposure, risk: exec.risk, taints: exec.taints, quarantine: exec.quarantine },
    { exposure: 'agent', risk: 'write', taints: true, quarantine: false },
  )
  const publish = resolveView(file, 'sandbox', 'publish')
  assert.deepEqual(
    { exposure: publish.exposure, risk: publish.risk, quarantine: publish.quarantine },
    { exposure: 'agent', risk: 'irreversible', quarantine: false },
  )
  assert.equal(file.servers['sandbox']!.default, 'kernel-only')
  assert.equal(resolveView(file, 'sandbox', 'shell').exposure, 'kernel-only', 'a sandbox tool nobody classified')

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
    // And the shipped bindings (none), as the kernel passes them.
    egressBindings: parseKernelConfig(readYaml('config/kernel.yaml'), { repoRoot: REPO }).egress.bindings,
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
  // Egress is empty too: the kernel's egress engine (src/egress) is not wired
  // yet (egress plan W1), so a host here would imply an allowance nothing is
  // present to enforce.
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
    // No shipped manifest holds egress: no host, no binding. One that does
    // widens what an agent reaches, which waits on the Phase 2 exit (the
    // egress plan's operator decision on shipping a coder manifest).
    assert.deepEqual(record.manifest.egress, { allow: [], bind: [] }, `${record.manifest.id} ships with egress`)
    // Nor a sandbox: block or a sandbox tool (egress plan S3): sandbox.exec
    // is wired into the daemon (W1a), egress with it (W1), and a manifest
    // that lists it waits on the Phase 2 exit, as egress does.
    assert.equal(record.manifest.sandbox, undefined, `${record.manifest.id} ships with a sandbox: block`)
    assert.deepEqual(
      record.manifest.tools.allow.filter((ref) => ref.startsWith('sandbox.')),
      [],
      `${record.manifest.id} ships with a sandbox tool`,
    )
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
    // No sandbox: a worker with one that lists sandbox.exec has its commands
    // run in containers (egress plan W1a), and a shipped manifest that does
    // waits on the Phase 2 exit, as egress does.
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

interface Lockfile {
  readonly lockfileVersion: number
  readonly packages: Record<string, { readonly version?: string; readonly dev?: boolean; readonly dependencies?: Record<string, string>; readonly devDependencies?: Record<string, string> }>
}
interface PackageJson {
  readonly dependencies: Record<string, string>
  readonly devDependencies: Record<string, string>
}
const lockfile = (): Lockfile => JSON.parse(read('package-lock.json')) as Lockfile
const packageJson = (): PackageJson => JSON.parse(read('package.json')) as PackageJson
/** Every installed copy in the lockfile, the root excluded: hoisted or nested. */
const lockEntries = (lock: Lockfile): [string, Lockfile['packages'][string]][] =>
  Object.entries(lock.packages).filter(([path]) => path !== '')

/** x.y.z only: a prerelease or a range here is something to compare by hand, not by this test. */
function plainVersion(version: string | undefined, where: string): [number, number, number] {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(version ?? '')
  assert.ok(m, `${where} is at ${String(version)}, which is not a plain x.y.z`)
  return [Number(m[1]), Number(m[2]), Number(m[3])]
}
function atLeast(a: readonly number[], b: readonly number[]): boolean {
  for (let i = 0; i < 3; i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0)
  return true
}

// The advisories `npm audit` reported on 3c6b430, each with the first release
// that fixed it. Every one but zod's sits in the MCP SDK's server tree, which is
// installed and never loaded; the lockfile is still what `npm ci` installs, so a
// merge that brings an older lockfile back brings the advisory back with it.
const ADVISORY_FLOORS: readonly { readonly name: string; readonly fixedIn: string; readonly advisories: readonly string[] }[] = [
  { name: 'zod', fixedIn: '4.6.6', advisories: ['GHSA-mrhx-c7xc-m3w5'] },
  { name: '@hono/node-server', fixedIn: '2.1.3', advisories: ['GHSA-rmxm-3fg6-px4f'] },
  { name: 'body-parser', fixedIn: '2.4.0', advisories: ['GHSA-27r3-jxmh-p828'] },
  { name: 'fast-uri', fixedIn: '3.1.9', advisories: ['GHSA-w74x-v6f9-j3xg', 'GHSA-xhq7-xmqj-769h', 'GHSA-wjr9-j795-jxcr', 'GHSA-333x-w4r6-6crp'] },
  { name: 'ip-address', fixedIn: '10.7.4', advisories: ['GHSA-rxp7-6hxx-x8q5'] },
  { name: 'qs', fixedIn: '6.16.1', advisories: ['GHSA-6pq8-jhm2-2vcw'] },
]

test('the lockfile resolves every copy of each package an advisory named at or above the release that fixed it', () => {
  const lock = lockfile()
  assert.equal(lock.lockfileVersion, 3)
  const entries = lockEntries(lock)
  for (const { name, fixedIn, advisories } of ADVISORY_FLOORS) {
    const copies = entries.filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`))
    // A row whose package left the tree guards nothing: drop it rather than let it pass by finding no copy.
    assert.ok(copies.length > 0, `${name} is no longer in the lockfile: remove its row from ADVISORY_FLOORS`)
    for (const [path, entry] of copies) {
      assert.ok(
        atLeast(plainVersion(entry.version, path), plainVersion(fixedIn, `${name}'s floor`)),
        `${path} is at ${String(entry.version)}, below ${fixedIn}, the release that fixed ${advisories.join(', ')}`,
      )
    }
  }
})

test('package.json pins every dependency exactly, and the lockfile root and its installed copy hold the same versions', () => {
  // A range would let `npm install` move a dependency on its own, and the
  // lockfile's root records are what `npm ci` checks package.json against.
  const pkg = packageJson()
  const lock = lockfile()
  const root = lock.packages['']
  for (const kind of ['dependencies', 'devDependencies'] as const) {
    assert.deepEqual(root?.[kind], pkg[kind], `the lockfile's root ${kind} are not package.json's`)
    for (const [name, pin] of Object.entries(pkg[kind])) {
      plainVersion(pin, `package.json's ${name}`)
      assert.equal(lock.packages[`node_modules/${name}`]?.version, pin, `the lockfile installs ${name} at another version than the pin ${pin}`)
    }
  }
})

test("README's dependency footprint is the lockfile's: the runtime dependencies by name and number, and the installed, dev-only and total counts", () => {
  const readme = read('README.md')
  const start = readme.indexOf('### Dependency footprint')
  assert.notEqual(start, -1, 'README has no Dependency footprint section')
  const section = readme.slice(start, readme.indexOf('\n#', start + 1)).replace(/\s+/g, ' ')
  const m = /(\w+) runtime dependencies \(([^)]*)\) expand to \*\*(\d+) installed packages\*\*, plus (\d+) dev-only, (\d+) in the lockfile\./.exec(section)
  assert.ok(m, `README's footprint sentence no longer reads as this test expects: ${section}`)
  const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve']
  const named = [...(m[2] ?? '').matchAll(/`([^`]+)`/g)].map((n) => n[1] ?? '')
  const runtime = Object.keys(packageJson().dependencies)
  assert.deepEqual([...named].sort(), [...runtime].sort(), "README's runtime dependencies are not package.json's")
  assert.equal(WORDS.indexOf((m[1] ?? '').toLowerCase()), runtime.length, `README says ${String(m[1])} runtime dependencies`)
  const entries = lockEntries(lockfile())
  assert.equal(Number(m[3]), entries.filter(([, e]) => e.dev !== true).length, 'the installed (runtime) count is not the lockfile\'s')
  assert.equal(Number(m[4]), entries.filter(([, e]) => e.dev === true).length, 'the dev-only count is not the lockfile\'s')
  assert.equal(Number(m[5]), entries.length, 'the lockfile total is not the lockfile\'s')
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

test("README and D35 say what the typed force-quit is, that pmmcp's own named Ollama instances can be force-quit and `ollama serve` and Ollama.app's or Homebrew's server cannot; CLAUDE.md \"Never\" carries the force-quit clause and D35 says so", () => {
  const readme = read('README.md')
  const start = readme.indexOf('### Install with npm run aos-install')
  assert.notEqual(start, -1, 'README has no installer section')
  const section = readme.slice(start, readme.indexOf('### The `.env` file', start)).replace(/\s+/g, ' ')
  assert.match(section, /only the typed word `force-quit` sends that one process SIGKILL, after `ps` shows it is still the same process/)
  // force-quit.ts's identity rule takes pmmcp's named Ollama instances (pmmcpOllama, the stop's _is_pmmcp_ollama) and refuses
  // the rest (install-force-quit.test.ts holds both): README names each name it takes, and what it refuses.
  const named = /pmmcp's own named Ollama instances \(exactly ([^)]*)\) can be force-quit the same way/.exec(section)
  assert.ok(named, "README does not say pmmcp's own named Ollama instances can be force-quit")
  assert.deepEqual([...(named[1] ?? '').matchAll(/`([^`]+) serve`/g)].map((m) => m[1]), [...PMMCP_OLLAMA_NAMES], 'README names other Ollama instances than force-quit.ts takes')
  assert.match(named[1] ?? '', /^the one the stop is draining, `PMMCP-TextQuery serve`, .* or `PMMCP-Ollama serve` for any of the four, yours, with no path before the name$/)
  assert.match(section, /`ollama serve` and Ollama\.app's or Homebrew's server \(`\/Applications\/Ollama\.app\/Contents\/Resources\/ollama serve`, `<prefix>\/bin\/ollama serve`\) cannot: only a PID file of the start script vouches for an `ollama serve`, the installer reads none/)
  assert.match(section, /says why and how to end it yourself \(check it with `ps` in another terminal, and end it there if it is pmmcp's\), and the stop goes on waiting on it/)
  assert.doesNotMatch(section, /are not force-quit/, 'README still says the Ollama instances are not force-quit')
  const d35 = read('docs/DECISIONS.md').split('\n').find((l) => l.startsWith('| D35 |')) ?? ''
  assert.ok(d35.includes('amended 2026-11-04, the operator: "yes, add the typed force-quit"'), 'D35 does not record the operator\'s word for the force-quit')
  const d35Named = /pmmcp's own named Ollama instances, which the stop vouches for by `_is_pmmcp_ollama`[^|]*can be force-quit too[^|]*\(a command line of exactly two words, ([^)]*), case exact and with no path before it, then `serve`; none while the stop drains a service that is no Ollama instance\)/.exec(d35)
  assert.ok(d35Named, "D35 does not say pmmcp's own named Ollama instances can be force-quit")
  // As force-quit.ts takes them (pmmcpOllama): only for the role the stop is draining, or PMMCP-Ollama for any.
  assert.match(d35Named[1] ?? '', /^the name of the role the stop is draining, one of `PMMCP-TextQuery`, .* or `PMMCP-CodeIndex`, or `PMMCP-Ollama` whatever the role$/)
  assert.deepEqual([...(d35Named[1] ?? '').matchAll(/`([^`]+)`/g)].map((m) => m[1]), [...PMMCP_OLLAMA_NAMES], 'D35 names other Ollama instances than force-quit.ts takes')
  assert.match(d35, /while `ollama serve` \(which only a PID file of the start script vouches for, and the installer reads none\) and Ollama\.app's or Homebrew's server \([^)]*\) cannot: the installer says why and how to end it from another terminal after checking it with `ps`/)
  assert.doesNotMatch(d35, /is not force-quit|widening the rule to them/, 'D35 still says the Ollama instances are not force-quit')
  // The clause F1 gives CLAUDE.md "Never", inside its parentheses right after the stop script's rule, and D35 saying, word for
  // word, that CLAUDE.md carries it. D35 may not say the clause awaits the operator, nor that it is the operator's to add.
  const clause = ', and no SIGKILL to a pmmcp service but the one the operator types `force-quit` for while the stop waits on it'
  const claude = read('CLAUDE.md').replace(/\s+/g, ' ')
  assert.ok(
    claude.includes(`(never \`launchctl kickstart -k\`, never a timeout or signal sent to the stop script${clause});`),
    'CLAUDE.md "Never" does not carry the force-quit clause inside its parentheses after the stop script\'s rule',
  )
  assert.ok(d35.includes(`CLAUDE.md "Never" carries the rule and its force-quit clause ("${clause}")`), 'D35 does not say, with the clause word for word, that CLAUDE.md "Never" carries it')
  assert.doesNotMatch(d35, /awaits the operator/, 'D35 says something of the force-quit still awaits the operator')
  assert.doesNotMatch(d35, /the operator's to add/, 'D35 says the force-quit clause is the operator\'s to add')
})

test("README's stopped-window paragraph, from its force-quit exception to the end of the bullet, is wrapped at 78 columns with no line broken early; \"Where things live\" names the run folder's force-quit.log", () => {
  const lines = read('README.md').split('\n')
  const from = lines.findIndex((l) => l.includes('One exception, typed'))
  const to = lines.findIndex((l, i) => i > from && l.endsWith('There is no `--yes` and no `--force`.'))
  assert.ok(from > 0 && to > from, 'README has no stopped-window paragraph with the force-quit exception')
  for (let i = from; i <= to; i += 1) {
    const line = lines[i] ?? ''
    assert.ok(line.startsWith('  ') && line.length <= 78, `README.md:${String(i + 1)} is ${String(line.length)} columns, or not indented as the bullet: ${line}`)
    // Reflowed: the next line's first word would not have fit on this one.
    const next = lines[i + 1]
    if (i < to && next !== undefined) {
      const word = next.trim().split(' ')[0] ?? ''
      assert.ok(line.length + 1 + word.length > 78, `README.md:${String(i + 1)} is broken early (${String(line.length)} columns, and \`${word}\` would fit): ${line}`)
    }
  }
  const row = lines.find((l) => l.startsWith('| `.aos/install/`, `.aos/install.lock` |')) ?? ''
  assert.ok(row.includes(`\`${FORCE_QUIT_LOG}\` (0600, a typed force-quit's record)`), `the .aos/install/ row does not name ${FORCE_QUIT_LOG}: ${row}`)
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

test("no credential name the shipped config declares is in pmmcp's PMMCP_ prefix, and D34 claims config's refusal only for a tokenEnv and a binding envVar", () => {
  // src/config.ts refuses the prefix only as an MCP server's tokenEnv or an
  // egress binding's envVar (config.test.ts). A provider's auth.envVar is
  // read from a shell export at boot as well, and one in pmmcp's prefix
  // would set a pmmcp setting, or stop pmmcp, in any shell that starts it.
  // The provider schema does not refuse one (that change awaits the
  // operator), so the shipped files are held here, in any case, as pmmcp
  // reads them.
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
  assert.match(d34, /holds an egress binding's `envVar` \(`egress\.bindings`, egress plan E5, 2026-11-10\) to the same two rules/)
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

test("README's live sandbox and egress section names every gated test of the two files, says what the token needs and where each container and its workspace go, and .env.example and the files' headers say the same", () => {
  const flat = (text: string): string => text.replace(/^[ \t]*(?:#|\/\/) ?/gm, '').replace(/\s+/g, ' ')
  const readme = read('README.md')
  const start = readme.indexOf('## Live sandbox and egress tests\n')
  assert.notEqual(start, -1, 'README has no live sandbox and egress section')
  const section = readme.slice(start, readme.indexOf('\n## ', start + 1))
  // Every gated test has a row, its first cell the test's name or the start of it.
  const rowsNamed = [...section.matchAll(/^\| (?:`test\/live-[a-z]+\.test\.ts`: )?([^|]+?) \| /gm)].map((m) => m[1] ?? '').filter((n) => n !== 'Test' && !n.startsWith('---'))
  for (const file of ['test/live-sandbox.test.ts', 'test/live-egress.test.ts']) {
    const names = [...read(file).matchAll(/^test\(\n {2}(['"])(.+)\1,\n/gm)].map((m) => (m[2] ?? '').replace(/\\'/g, "'"))
    assert.ok(names.length > 0, `${file} holds no test this scan reads`)
    for (const name of names) assert.ok(rowsNamed.some((row) => name.startsWith(row)), `README's live section has no row for ${file}: ${name}`)
  }
  const text = flat(section)
  // The token: the organization owns it, and GitHub's Metadata read comes with it.
  for (const says of [
    'whose resource owner is the `AiBot-Tools` organization (which may have to approve it before it works)',
    'and Metadata read-only, which GitHub adds to every fine-grained token, and nothing else',
  ]) assert.ok(text.includes(says), `README's live section does not say: ${says}`)
  const example = flat(read('.env.example'))
  for (const says of ['with the AiBot-Tools organization as its resource owner (the organization may have to approve it)', 'and the Metadata read-only GitHub adds to every fine-grained token, nothing else']) {
    assert.ok(example.includes(says), `.env.example does not say: ${says}`)
  }
  // The containers and workspaces: a test's own, removed; the canaries', named as boot names them, in boot's canary workspace, which stays.
  for (const says of [
    'A test\'s own containers are named `aos-run-live_...`',
    'the canary test\'s two are named as boot names its canaries (`aos-run-canary-1-<nonce>-<domain>`), and share the canary workspace boot uses, `.aos/workspaces/<domain>/aos_canary`, which stays',
    'in the canary workspace under each domain\'s mountRoot, which stays',
    'no workspace entry\'s name or file (`.git` included, each git object inflated: a loose object whole, a pack\'s streams each)',
  ]) assert.ok(text.includes(says), `README's live section does not say: ${says}`)
  assert.ok(flat(read('test/live-sandbox.test.ts')).includes("are named as boot names its canaries, aos-run-canary-1-<nonce>-<domain>, and share boot's canary workspace, <mountRoot>/aos_canary, which stays"), "live-sandbox's header does not name the canaries and their workspace")
  assert.ok(flat(read('test/live-egress.test.ts')).includes('in the canary workspace under each domain\'s mountRoot (<mountRoot>/aos_canary), which stays'), "live-egress's header does not say where its canaries' workspace is")
  // Which the bodies and boot hold to: the canary body names its canaries as boot's first boot would, in boot's own workspace.
  const bodies = read('test/helpers/sandbox-bodies.ts')
  assert.ok(bodies.includes('    const workspace = makeWorkspace(domain, ctx.mountRoots[domain], CANARY_WORKSPACE)\n'))
  assert.ok(bodies.includes('      name: canaryName(1, canaryNonce(), domain),\n'))
  assert.match(read('src/runtime/canary.ts'), /^export const CANARY_WORKSPACE = 'aos_canary'$/m)
})

test("README says which live tests AOS_LIVE_TESTS=1 alone runs, and which checks of the live bodies are seen offline only to pass; live-egress says its guard admits what the kernel then judges", () => {
  const flat = (text: string): string => text.replace(/^[ \t]*(?:#|\/\/|\*) ?/gm, '').replace(/\s+/g, ' ')
  const readme = flat(read('README.md'))
  // AOS_LIVE_TESTS=1 alone runs no Phase 2 file: each skips without AOS_LIVE_DOCKER=1.
  for (const says of [
    'Every Phase 0 and Phase 1 live test, including pmmcp writes to `aos/agent/aos-live-test` (the Phase 2 files below also need `AOS_LIVE_DOCKER=1`):',
    '`AOS_LIVE_TESTS=1 npm test` runs the same test plus every other Phase 0 and Phase 1 live test, at roughly twice the cost (the Phase 2 files skip without `AOS_LIVE_DOCKER=1`).',
  ]) assert.ok(readme.includes(says), `README does not say: ${says}`)
  assert.equal(/\bEverything, including pmmcp writes\b|plus every other live test\b/.test(readme), false, 'README says AOS_LIVE_TESTS=1 runs every live test')
  // The bodies: what is seen to fail, and what only to pass, named.
  for (const says of [
    'Every check a container or a VM can make fail is seen there to fail on what it is there to catch',
    'Seen only to pass are the checks of what the kernel or the driver alone decides, which no container can make fail',
    'No failure of the exit quotes the token',
    'each check a container or a VM can make fail seen offline to fail on what it catches (`liveBodies`)',
  ]) assert.ok(readme.includes(says), `README does not say: ${says}`)
  assert.equal(/Each check is seen there to fail|Two are seen only to pass|each check of which is seen offline to fail/.test(readme), false, 'README still says every check of the live bodies is seen to fail')
  assert.equal(/each check of which/.test(read('scripts/falsify/catalog.ts')), false, "the liveBodies comment still says every check is seen to fail")
  // A request that failed upstream is one a container can cause (a request
  // cut short of its Content-Length, exitActor's clone-cut): seen to fail,
  // never listed among the checks seen only to pass.
  assert.ok(readme.includes('a request cut short of its Content-Length, which fails upstream;'), 'README does not list a request cut short among the checks seen to fail')
  const passOnly = readme.slice(readme.indexOf('Seen only to pass are the checks'))
  assert.equal(/failed upstream|upstream row/.test(passOnly.slice(0, passOnly.indexOf('the chain verifying'))), false, 'README lists the upstream check among the checks seen only to pass')
  const catalog = flat(read('scripts/falsify/catalog.ts'))
  assert.ok(catalog.includes("Among them, no request failed upstream: a container makes one fail by cutting a request short of its Content-Length (exitActor's clone-cut, LB75)"), "the liveBodies comment does not say a container can make the upstream check fail")
  assert.equal(/no upstream row/.test(catalog), false, 'the liveBodies comment lists the upstream check among the checks seen only to pass')
  // live-egress's guard: it admits each answer as it arrives, before the kernel judges it.
  const egress = flat(read('test/live-egress.test.ts'))
  assert.ok(egress.includes('The kernel\'s checkAnswers (src/egress/upstream.ts, over src/egress/addr.ts) then judges each answer unchanged, so an address it refuses is admitted to the guard but never dialled.'), "live-egress's admitting() comment does not say the guard admits first")
  assert.equal(egress.includes('run first, unchanged'), false, "live-egress's admitting() comment says the kernel's checks run first")
})

test("README's Phase 2 exit checklist names test/live-egress.test.ts's exit test by its exact title, unchecked, and says what that run is: a scripted model and the test's approvals, never a coding agent or a human approval", () => {
  // The egress plan's Operator decisions entry on the Phase 2 exit's live run:
  // a scripted model is no agent and a test's approval is no person's, so the
  // line its pass fills says what ran, and the exit's own line stays apart,
  // waiting on a run no test drives. A title edited on one side only would
  // leave the operator recording a pass of a test the line does not name.
  const readme = read('README.md')
  const titles = [...read('test/live-egress.test.ts').matchAll(/^test\(\n {2}(['"])(.+)\1,\n/gm)].map((m) => (m[2] ?? '').replace(/\\'/g, "'"))
  assert.equal(titles.length, 1, 'test/live-egress.test.ts holds other than one test this scan reads')
  const title = titles[0] ?? ''
  assert.equal(title, 'Phase 2 exit: clone, change, test, push aos/<runId>/<branch>, PR opened')

  const start = readme.indexOf('## Phase 2 exit-criterion checklist\n')
  assert.notEqual(start, -1, 'README has no Phase 2 exit-criterion checklist')
  const end = readme.indexOf('\n## ', start + 1)
  const section = readme.slice(start, end === -1 ? undefined : end)
  const one = section.indexOf('**1. ')
  const two = section.indexOf('**2. ')
  assert.ok(one !== -1 && two > one, 'the Phase 2 checklist has no line 1 before a line 2')
  const line1 = section.slice(one, two)
  const line2 = section.slice(two)

  // Line 1 names the file and the test's title exactly, and runs that file with its three gates.
  assert.ok(line1.startsWith("**1. The isolation check: scripted model, the test's approvals.**\n"), line1.slice(0, 200))
  assert.ok(line1.includes(`\`test/live-egress.test.ts\`, '${title}'`), `line 1 does not name test/live-egress.test.ts's test as '${title}'`)
  assert.ok(
    line1.includes('```bash\nAOS_LIVE_TESTS=1 AOS_LIVE_DOCKER=1 AOS_LIVE_GITHUB=1 node --expose-gc --import tsx --test test/live-egress.test.ts\n```'),
    'line 1 does not give the command that runs the file with its three gates',
  )
  assert.doesNotMatch(line1, /coding agent|human approval|a person approv/i, 'line 1 calls the scripted run an agent, or its approvals a person\'s')

  // Unchecked, both lines, every field empty: nothing is recorded before the Mac runs it.
  const record = /\n- Result: (.*)\n- Date:(.*)\n- Commit:(.*)\n- `runId`:(.*)\n- `pullRequest`:(.*)\n/
  for (const [label, line] of [['line 1', line1], ['line 2', line2]] as const) {
    const fields = record.exec(line)
    assert.ok(fields, `${label} of the Phase 2 checklist has no Result, Date, Commit, runId and pullRequest fields`)
    assert.equal(fields[1], '_not yet run_', `${label} is checked`)
    assert.deepEqual(fields.slice(2).map((f) => f.trim()), ['', '', '', ''], `${label} is unrun but carries a value`)
  }
  // Line 2 is the exit itself: a real, probed model and the operator's own approvals.
  assert.ok(line2.startsWith('**2. The exit itself.**'), line2.slice(0, 200))
  for (const says of ['`npm run cli -- approve`', 'No test drives it yet']) {
    assert.ok(line2.replace(/\s+/g, ' ').includes(says), `line 2 does not say: ${says}`)
  }
  // And nothing claims the exit while both lines are unrun.
  for (const [file, text] of [['README.md', readme], ['CLAUDE.md', read('CLAUDE.md')]] as const) {
    assert.doesNotMatch(text, /Phase 2(?:'s exit(?: criterion)?)? (?:is |has )?(?:complete|exited|met|passed)\b/i, `${file} claims Phase 2 is exited before its checklist records it`)
  }
})

test("README's Egress section names every check boot's egress probe runs, each in a row of its own that names its fix, and the boot failures that refuse rather than degrade", () => {
  // egress.degraded's `check` is the closed list EGRESS_CHECKS: a check
  // added to it that README's table does not name is a degraded reason an
  // operator meets with no fix written down, and a row for a check the
  // kernel no longer runs sends them after one that cannot fail.
  const readme = read('README.md')
  const start = readme.indexOf('\n## Egress\n')
  assert.notEqual(start, -1, 'README has no Egress section')
  const section = readme.slice(start, readme.indexOf('\n## ', start + 1))
  const boot = section.slice(section.indexOf('\n### Boot states\n'), section.indexOf('\n### ', section.indexOf('\n### Boot states\n') + 1))
  assert.ok(boot.length > 200, 'the Egress section has no Boot states subsection')
  const rows = [...boot.matchAll(/^\| `([a-z]+)`(?:, naming the (?:domain|binding))? \| ([^|]+) \| ([^|]+) \|$/gm)]
  // In the order boot runs them, which EGRESS_CHECKS does not keep: each
  // once, as src/kernel.ts's egress block pushes its failures (each check a
  // `check: '<name>'` literal there), read from the source, so a reordering
  // of the checks there leaves README out of order here.
  const kernel = read('src/kernel.ts')
  const blockAt = kernel.indexOf('\n    // ── egress (degradable)')
  const blockEnd = kernel.indexOf('\n    // ── lanes', blockAt)
  assert.ok(blockAt !== -1 && blockEnd > blockAt, "src/kernel.ts has no egress block between its '// ── egress' and '// ── lanes' markers")
  const order = [...kernel.slice(blockAt, blockEnd).matchAll(/\bcheck: '([a-z]+)'/g)].map((m) => m[1] ?? '')
  assert.deepEqual([...order].sort(), [...EGRESS_CHECKS].sort(), "src/kernel.ts's egress block does not push each check egress.degraded can carry, once")
  const named = rows.map((r) => r[1] ?? '')
  assert.deepEqual(named, order, 'the Boot states table does not name the checks in the order boot runs them')
  assert.deepEqual([...named].sort(), [...EGRESS_CHECKS].sort(), 'the Boot states table does not name each check egress.degraded can carry, once')
  for (const row of rows) assert.match(row[3] ?? '', /restart the kernel/, `the ${row[1] ?? ''} row names no fix that ends in a restart`)
  const flat = boot.replace(/\s+/g, ' ')
  for (const says of [
    'Boot reports egress `ok` or `degraded`, never absent.',
    'Two failures refuse the boot instead of degrading it: a binding whose envVar is a provider\'s key',
    'A run whose manifest names no egress is not affected',
  ]) assert.ok(flat.includes(says), `README's Boot states does not say: ${says}`)
  // The section's other parts are there, in order.
  const parts = ['### Topology', '### Grants, and how each ends', '### Boot states', '### Setting it up', '### What the log records', '### What an agent can and cannot reach', '### Open decisions the code is built on']
  const at = parts.map((part) => section.indexOf(`\n${part}\n`))
  assert.ok(at.every((i) => i !== -1), `the Egress section lacks: ${parts.filter((_, i) => at[i] === -1).join(', ')}`)
  assert.deepEqual([...at].sort((a, b) => a - b), at, 'the Egress section\'s parts are out of order')
})
