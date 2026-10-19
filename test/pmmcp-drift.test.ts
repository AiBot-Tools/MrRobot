// Drift guard: what this repository believes about pmmcp against the live
// server's schemas.
//
// The operator's capture (test/fixtures/pmmcp-listtools.json, first taken
// 2026-10-18, re-taken with output schemas 2026-10-19) is the reference.
// Against it this file checks: the double's argument names for every tool it
// declares; the kernel's typed transcript of the goal and vault tools
// (src/mcp/pmmcp-schemas.ts) by type, nullability, default and requiredness;
// the double's default output for every tool, and the live create and update
// outputs against what the boot check accepts; the keyArg the broker sends;
// every pin in tool-views.yaml; and the tool count three files repeat. The capture is re-taken on the
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

import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { GOAL_RESULT_OUTPUT, GOAL_STATUSES, GOAL_TRANSITIONS, PMMCP_TOOL_COUNT } from './helpers/mock-pmmcp.js'
import {
  ABSENT_BY_INVARIANT,
  agreeingCapture,
  compareCapture,
  type PmmcpCapture,
} from './helpers/pmmcp-capture.js'

const CAPTURE = join(REPO_ROOT, 'test/fixtures/pmmcp-listtools.json')

function kernelConfig(): KernelConfig {
  return parseKernelConfig(parseYaml(readFileSync(join(REPO_ROOT, 'config/kernel.yaml'), 'utf8')), { repoRoot: REPO_ROOT })
}

function keyArg(): string {
  return kernelConfig().secrets.keyArg
}

const goals = (): KernelConfig['goals'] => kernelConfig().goals

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
  const findings = compareCapture({ capture, keyArg: keyArg(), pinned: pinned(), goals: goals() })
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
  const findings = compareCapture({ capture: wrong, keyArg: 'label', pinned: pinned(), goals: goals() })

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
  assert.equal(says(/the capture does not record output schemas/), true, 'a capture from before step 2.1.3')
  assert.equal(
    says(new RegExp(`exposes 50 tools; this repo says ${String(PMMCP_TOOL_COUNT)}`)),
    true,
    'the tool count',
  )

  // An empty capture is its own finding: a file that parsed but holds nothing
  // must not read as "no disagreements".
  assert.deepEqual(compareCapture({ capture: { tools: [] }, keyArg: 'label', pinned: [], goals: goals() }), [
    'the capture holds no tools; re-run `npm run capture:pmmcp`',
  ])
})

test('the comparison passes on a capture that agrees, so it is not merely always red', () => {
  const findings = compareCapture({ capture: agreeingCapture(), keyArg: 'label', pinned: pinned(), goals: goals() })
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
  assert.deepEqual(compareCapture({ capture: agreeing, keyArg: 'label', pinned: pinned(), goals: goals() }), [])

  // An operator pin is not forced: a missing `forget` is a rule guarding nothing.
  const operatorPin = compareCapture({
    capture: { ...agreeing, tools: agreeing.tools?.filter((t) => t.name !== 'forget') ?? [] },
    keyArg: 'label',
    pinned: pinned(), goals: goals(),
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
    pinned: pinned(), goals: goals(),
  })
  assert.equal(
    returned.some((f) => /the live server now registers restore_backup; remove it from ABSENT_BY_INVARIANT/.test(f)),
    true,
  )

  // Without the excuse, the absence is reported both ways, as before.
  const unexcused = compareCapture({ capture: agreeing, keyArg: 'label', pinned: pinned(), goals: goals(), absentByInvariant: [] })
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
    pinned: pinned(), goals: goals(),
  })
  assert.deepEqual(findings, [], `config/kernel.yaml secrets.keyArg is "${configured}"`)
  const mismatch = compareCapture({
    capture: agreeingCapture(),
    keyArg: 'something-else',
    pinned: pinned(), goals: goals(),
  })
  assert.equal(mismatch.length, 1)
  assert.match(mismatch[0] ?? '', /something-else/)
})

test('output schemas are compared only in a capture that records them, and then a P6 result that disagrees with the kernel\'s, or a double that does not serve the live form, is named', () => {
  const agreeing = agreeingCapture()
  const P = GOAL_RESULT_OUTPUT['properties'] as Record<string, unknown>
  const withOutputs = (outputs: Record<string, unknown>, records = true): PmmcpCapture => ({
    ...agreeing,
    recordsOutputSchema: records,
    tools: (agreeing.tools ?? []).map((t) => {
      if (!(t.name in outputs)) return t
      const { outputSchema: _dropped, ...rest } = t
      const next = outputs[t.name]
      return next === undefined ? rest : { ...rest, outputSchema: next }
    }),
  })
  const compare = (capture: PmmcpCapture): string[] => compareCapture({ capture, keyArg: 'label', pinned: pinned(), goals: goals() })

  // An older capture: its outputs are unknown, so nothing about them is judged,
  // and the one finding is that it should be re-taken.
  assert.deepEqual(compare(withOutputs({ recall: { type: 'object', properties: { items: { type: 'array' } } } }, false)), [
    'the capture does not record output schemas; re-run `npm run capture:pmmcp` (step 2.1.3 or later)',
  ])

  // The double must serve the live form: another shape, or none at all, is named.
  const recall = compare(withOutputs({ recall: { type: 'object', properties: { items: { type: 'array' } } }, forget: undefined }))
  assert.deepEqual([...recall].sort(), [
    'forget: the double serves {result: string} by default; live declares no output schema',
    'recall: the double serves {result: string} by default; live declares {items?: array<>}',
  ])

  // Every live tool, not only those the double models: a stand-in serves the default too.
  const unmodelled = compare(withOutputs({ live_tool_60: { type: 'object', properties: { rows: { type: 'array' } } } }))
  assert.deepEqual(unmodelled, ['live_tool_60: the double serves {result: string} by default; live declares {rows?: array<>}'])

  // P6 as the kernel reads it: the double is behind (named), the boot check serves.
  const p6 = compare(withOutputs({ create_goal: GOAL_RESULT_OUTPUT, update_goal: GOAL_RESULT_OUTPUT }))
  assert.deepEqual([...p6].sort(), [
    'create_goal: the double serves {result: string} by default; live declares {goal_id: string, progress_pct: number, project_id: string, status: string}',
    'update_goal: the double serves {result: string} by default; live declares {goal_id: string, progress_pct: number, project_id: string, status: string}',
  ])

  // A P6 result the kernel would not read: the boot check would degrade goals, and says why.
  const short = { ...GOAL_RESULT_OUTPUT, properties: { goal_id: P['goal_id'], project_id: P['project_id'], status: P['status'] }, required: ['goal_id', 'project_id', 'status'] }
  const degraded = compare(withOutputs({ update_goal: short }))
  assert.ok(degraded.includes('the boot check would degrade goals on this capture: pmmcp.update_goal does not return progress_pct'), degraded.join('\n'))

  // And the agreeing capture, which records them, has nothing to say.
  assert.deepEqual(compare(agreeing), [])
})
