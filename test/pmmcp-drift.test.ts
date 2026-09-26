// Drift guard: the pmmcp double against the real server's schemas.
//
// test/helpers/mock-pmmcp.ts models pmmcp from docs and CLAUDE.md's environment
// notes. Exactly one thing in it is confirmed — `get_secret` takes `label`
// (DECISIONS Q24) — and every other name and argument is a guess, recorded as
// `provenance: 'modelled'`. This file is how those guesses stop being guesses.
//
// The capture can only be taken on the operator's machine:
//
//   PMMCP_TOKEN=... npm run capture:pmmcp
//
// NOTHING HERE SKIPS. A gated skip would mean the comparison sits unexercised
// until the day it matters most, and a hygiene rule in this suite forbids new
// skips outside the live tests for exactly that reason. So the comparison is a
// pure function (helpers/pmmcp-capture.ts) and this file exercises it three
// ways: against the real capture when there is one, against a synthetic capture
// that is wrong in every way the guard is supposed to notice, and against one
// that agrees. With no capture on disk, the first of those instead asserts the
// thing that must still be true in its absence — that the repository has not
// started claiming these facts are settled.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { PMMCP_TOOLS, PMMCP_TOOL_COUNT } from './helpers/mock-pmmcp.js'
import {
  agreeingCapture,
  compareCapture,
  type PmmcpCapture,
} from './helpers/pmmcp-capture.js'

const CAPTURE = join(REPO_ROOT, 'test/fixtures/pmmcp-listtools.json')

function keyArg(): string {
  const config = parseKernelConfig(
    parseYaml(readFileSync(join(REPO_ROOT, 'config/kernel.yaml'), 'utf8')),
    { repoRoot: REPO_ROOT },
  )
  return config.secrets.keyArg
}

function pinned(): string[] {
  const views = parseToolViews(
    parseYaml(readFileSync(join(REPO_ROOT, 'config/tool-views.yaml'), 'utf8')),
  )
  return Object.keys(views.servers['pmmcp']?.tools ?? {})
}

test('the live capture agrees with the double, or its absence is still recorded', () => {
  if (existsSync(CAPTURE)) {
    const capture = JSON.parse(readFileSync(CAPTURE, 'utf8')) as PmmcpCapture
    const findings = compareCapture({ capture, keyArg: keyArg(), pinned: pinned() })
    assert.deepEqual(
      findings,
      [],
      `the live pmmcp disagrees with this repo:\n  ${findings.join('\n  ')}\n` +
        'Each line is an assumption Phase 1 may have been built on.',
    )
    return
  }

  // No capture. What must still hold is that nothing here has quietly started
  // treating the guesses as settled — the claim, not the check, is what goes
  // stale first.
  const confirmed = PMMCP_TOOLS.filter((s) => s.provenance === 'confirmed').map((s) => s.name)
  assert.deepEqual(
    confirmed,
    ['get_secret'],
    'a tool claims confirmation from a live listTools, but no capture exists to have read it off',
  )
  const readme = readFileSync(join(REPO_ROOT, 'README.md'), 'utf8')
  const table = readme.slice(readme.indexOf('## Still needs validation'))
  assert.match(
    table,
    /the 49 tool names/,
    'README stopped listing pmmcp\'s tool names as needing validation while no capture exists',
  )
})

test('the comparison catches a capture that is wrong in every way it checks', () => {
  // The falsifier, kept in the suite rather than run once by hand: a guard whose
  // own failure path is never exercised is a guard nobody has seen work.
  const wrong: PmmcpCapture = {
    toolCount: 50,
    tools: [
      // The confirmed argument, contradicted.
      { name: 'get_secret', inputSchema: { properties: { name: {} } } },
      // A modelled tool present but with an argument the server does not have.
      { name: 'recall', inputSchema: { properties: { project_id: {} } } },
      // A tool with no schema at all.
      { name: 'create_goal' },
      // A pinned tool is absent: `admin` is classified but not served.
    ],
  }
  const findings = compareCapture({ capture: wrong, keyArg: 'label', pinned: pinned() })

  const says = (pattern: RegExp): boolean => findings.some((f) => pattern.test(f))
  assert.equal(says(/modelled tool absent from the live server: remember/), true, 'missing tools')
  assert.equal(says(/recall: models limit, query; live declares project_id/), true, 'an argument the server does not accept')
  assert.equal(says(/create_goal: the live tool declares no inputSchema.properties/), true, 'no schema')
  assert.equal(says(/secrets.keyArg is "label" but the live get_secret declares name/), true, 'the keyArg')
  assert.equal(says(/pins a tool the live server does not expose: admin/), true, 'a pinned tool absent')
  assert.equal(says(/exposes 50 tools; this repo says 49/), true, 'the tool count')

  // An empty capture is its own finding: a file that parsed but holds nothing
  // must not read as "no disagreements".
  assert.deepEqual(compareCapture({ capture: { tools: [] }, keyArg: 'label', pinned: [] }), [
    'the capture holds no tools; re-run `npm run capture:pmmcp`',
  ])
})

test('the comparison passes on a capture that agrees, so it is not merely always red', () => {
  const findings = compareCapture({ capture: agreeingCapture(), keyArg: 'label', pinned: pinned() })
  assert.deepEqual(findings, [], findings.join('\n'))
  // And the agreeing capture is the real cardinality, so a passing comparison
  // is a comparison that saw 49 tools.
  assert.equal(agreeingCapture().toolCount, PMMCP_TOOL_COUNT)
})

test('a captured keyArg other than the configured one is the only thing that settles it', () => {
  // kernel.yaml currently says `label`, from Q24. If someone changes that line,
  // this reads it from the file rather than from a constant — the point of the
  // check is that the two agree, and hard-coding one of them defeats it.
  const configured = keyArg()
  const findings = compareCapture({
    capture: agreeingCapture(),
    keyArg: configured,
    pinned: pinned(),
  })
  assert.deepEqual(findings, [], `config/kernel.yaml secrets.keyArg is "${configured}"`)
  const mismatch = compareCapture({
    capture: agreeingCapture(),
    keyArg: 'something-else',
    pinned: pinned(),
  })
  assert.equal(mismatch.length, 1)
  assert.match(mismatch[0] ?? '', /something-else/)
})
