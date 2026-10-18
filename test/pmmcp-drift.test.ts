// Drift guard: what this repository believes about pmmcp against the live
// server's schemas.
//
// The operator's capture (test/fixtures/pmmcp-listtools.json, 2026-10-18)
// is the reference. Against it this file checks: the double's argument names
// for every tool it declares; the kernel's typed transcript of the goal and
// vault tools (src/mcp/pmmcp-schemas.ts) by type, nullability, default and
// requiredness; the keyArg the broker sends; every pin in tool-views.yaml;
// and the tool count three files repeat. The capture is re-taken on the
// operator's machine (pmmcp needs no token):
//
//   npm run capture:pmmcp
//
// NOTHING HERE SKIPS, and the capture must exist: the `confirmed` provenance
// in the double is earned against it, so a repository without it would be
// claiming facts it cannot show. The comparison is a pure function
// (helpers/pmmcp-capture.ts) exercised three ways: against the real capture,
// against a synthetic one that is wrong in every way the guard is supposed to
// notice, and against one that agrees.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig } from '../src/config.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { GOAL_STATUSES, GOAL_TRANSITIONS, PMMCP_TOOL_COUNT } from './helpers/mock-pmmcp.js'
import {
  ABSENT_BY_INVARIANT,
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

test('the live capture agrees with the double and with the kernel\'s typed schemas', () => {
  // Approved by the operator on 2026-10-18 in place of the no-capture branch,
  // which could no longer run and asserted a README line that was gone.
  assert.ok(
    existsSync(CAPTURE),
    'test/fixtures/pmmcp-listtools.json is gone, but the double\'s `confirmed` tools are earned against it; ' +
      're-run `npm run capture:pmmcp` on the operator\'s machine',
  )
  const capture = JSON.parse(readFileSync(CAPTURE, 'utf8')) as PmmcpCapture
  const findings = compareCapture({ capture, keyArg: keyArg(), pinned: pinned() })
  assert.deepEqual(
    findings,
    [],
    `the live pmmcp disagrees with this repo:\n  ${findings.join('\n  ')}\n` +
      'Each line is an assumption Phase 1 may have been built on.',
  )
})

test("the double's status vocabulary and transition table are the ones the live update_goal describes", () => {
  // pmmcp states both in prose (its tool description and the status
  // argument's), not in the schema; the double enforces them hard, so a pmmcp
  // that changed them would leave the kernel tested against rules it no
  // longer has.
  const capture = JSON.parse(readFileSync(CAPTURE, 'utf8')) as PmmcpCapture
  const tool = capture.tools?.find((t) => t.name === 'update_goal')
  const prose = tool?.description ?? ''
  const described: Record<string, string[]> = {}
  for (const m of prose.matchAll(/^\s*(\w+) → (.+)$/gmu)) {
    const from = m[1]
    const to = m[2]
    if (from === undefined || to === undefined) continue
    described[from] = to
      .replace(/\s*\([^)]*\)\s*$/u, '')
      .split(',')
      .map((s) => s.trim())
  }
  assert.deepEqual(described, GOAL_TRANSITIONS, `update_goal describes: ${prose}`)

  const status = tool?.inputSchema?.properties?.['status'] as { description?: string } | undefined
  assert.deepEqual(
    (status?.description ?? '').split(',').map((s) => s.trim()).sort(),
    [...GOAL_STATUSES].sort(),
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
      // A typed tool whose live argument changed type.
      {
        name: 'update_goal',
        inputSchema: {
          type: 'object',
          properties: { goal_id: { type: 'string' }, progress_pct: { type: 'string' } },
          required: ['goal_id', 'progress_pct'],
        },
      },
      // A pinned tool is absent: `admin` is classified but not served.
    ],
  }
  const findings = compareCapture({ capture: wrong, keyArg: 'label', pinned: pinned() })

  const says = (pattern: RegExp): boolean => findings.some((f) => pattern.test(f))
  assert.equal(says(/modelled tool absent from the live server: remember/), true, 'missing tools')
  assert.equal(says(/recall: models limit, query; live declares project_id/), true, 'an argument the server does not accept')
  assert.equal(says(/create_goal: the live tool declares no inputSchema.properties/), true, 'no schema')
  assert.equal(says(/update_goal\.progress_pct: typed null\|number; live declares string/), true, 'a type the transcript disagrees with')
  assert.equal(says(/update_goal\.progress_pct: typed default null; live no default/), true, 'a default')
  assert.equal(says(/update_goal\.status: src\/mcp\/pmmcp-schemas\.ts declares it; live does not/), true, 'a property')
  assert.equal(says(/update_goal: typed required \[goal_id\]; live requires \[goal_id, progress_pct\]/), true, 'required')
  assert.equal(says(/secrets.keyArg is "label" but the live get_secret declares name/), true, 'the keyArg')
  assert.equal(says(/pins a tool the live server does not expose: admin/), true, 'a pinned tool absent')
  assert.equal(
    says(new RegExp(`exposes 50 tools; this repo says ${String(PMMCP_TOOL_COUNT)}`)),
    true,
    'the tool count',
  )

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
  // is a comparison that saw as many tools as the live server has.
  assert.equal(agreeingCapture().toolCount, PMMCP_TOOL_COUNT)
})

test('only a tool invariant 7 forces may be missing from the live server, and only while it is', () => {
  // The excuse that clears restore_backup must not become a way to excuse
  // anything else, nor outlive the absence it records.
  const agreeing = agreeingCapture()
  assert.equal(
    agreeing.tools?.some((t) => ABSENT_BY_INVARIANT.includes(t.name)),
    false,
    'the agreeing capture lacks the excused tools, as the live one does',
  )
  assert.deepEqual(compareCapture({ capture: agreeing, keyArg: 'label', pinned: pinned() }), [])

  // An operator pin is not forced: a missing `forget` is a rule guarding nothing.
  const operatorPin = compareCapture({
    capture: { ...agreeing, tools: agreeing.tools?.filter((t) => t.name !== 'forget') ?? [] },
    keyArg: 'label',
    pinned: pinned(),
    absentByInvariant: ['restore_backup', 'forget'],
  })
  assert.equal(operatorPin.some((f) => /forget is excused as absent, but invariant 7 does not force it/.test(f)), true)
  assert.equal(operatorPin.some((f) => /pins a tool the live server does not expose: forget/.test(f)), true)

  // pmmcp adds it back: the excuse is now stale and says so.
  const returned = compareCapture({
    capture: {
      ...agreeing,
      tools: [...(agreeing.tools ?? []), { name: 'restore_backup', inputSchema: { properties: { backup_id: {} } } }],
    },
    keyArg: 'label',
    pinned: pinned(),
  })
  assert.equal(
    returned.some((f) => /the live server now registers restore_backup; remove it from ABSENT_BY_INVARIANT/.test(f)),
    true,
  )

  // Without the excuse, the absence is reported both ways, as before.
  const unexcused = compareCapture({ capture: agreeing, keyArg: 'label', pinned: pinned(), absentByInvariant: [] })
  assert.deepEqual(unexcused, [
    'modelled tool absent from the live server: restore_backup',
    'tool-views.yaml pins a tool the live server does not expose: restore_backup',
  ])
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
