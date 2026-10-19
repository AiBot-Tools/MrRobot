// The typed pmmcp goal and vault arguments against the operator's live capture.
//
// src/mcp/pmmcp-schemas.ts is a hand transcript of six tools' inputSchemas. A
// transcript is only as good as the check that holds it to the source, so this
// file reads test/fixtures/pmmcp-listtools.json unconditionally and compares
// every property, then proves the comparison itself notices each kind of
// difference it claims to.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { z } from 'zod'

import {
  CreateGoalLive,
  CreateGoalSent,
  GetGoalTreeLive,
  GetGoalTreeSent,
  GetSecretLive,
  GetSecretSent,
  GoalResult,
  inputShape,
  liveJsonSchema,
  PMMCP_LIVE,
  PMMCP_STATUSES,
  SENDABLE_STATUSES,
  UpdateGoalLive,
  UpdateGoalSent,
  type PmmcpLiveTool,
} from '../src/mcp/pmmcp-schemas.js'
import { REPO_ROOT } from './helpers/kernel.js'
import { GOAL_RESULT_OUTPUT, GOAL_STATUSES } from './helpers/mock-pmmcp.js'

interface Captured {
  readonly name: string
  readonly inputSchema?: unknown
}

const CAPTURE = JSON.parse(
  readFileSync(join(REPO_ROOT, 'test/fixtures/pmmcp-listtools.json'), 'utf8'),
) as { tools: Captured[] }

function captured(name: string): unknown {
  const tool = CAPTURE.tools.find((t) => t.name === name)
  assert.ok(tool !== undefined, `the capture has no ${name}`)
  return tool.inputSchema
}

const shapeOf = (schema: z.ZodType): ReturnType<typeof inputShape> =>
  inputShape(z.toJSONSchema(schema, { io: 'input' }))

test("each typed pmmcp schema is the live capture's inputSchema, field for field", () => {
  for (const name of Object.keys(PMMCP_LIVE) as PmmcpLiveTool[]) {
    assert.deepEqual(inputShape(liveJsonSchema(name)), inputShape(captured(name)), name)
  }
})

test('the shape comparison notices a type, a nullability, an item type, a default and a required difference', () => {
  const live = shapeOf(CreateGoalLive)
  const variants: [string, z.ZodType][] = [
    ['priority as a number', CreateGoalLive.extend({ priority: z.number().default(3) })],
    ['parent_goal_id not nullable', CreateGoalLive.extend({ parent_goal_id: z.string().optional() })],
    ['tags of numbers', CreateGoalLive.extend({ tags: z.array(z.number()).nullable().default(null) })],
    ['goal_type defaulting to task', CreateGoalLive.extend({ goal_type: z.string().default('task') })],
    ['title optional', CreateGoalLive.extend({ title: z.string().optional() })],
  ]
  for (const [why, schema] of variants) {
    assert.notDeepEqual(shapeOf(schema), live, why)
  }
  // And the two notations for "nullable" read the same, or every comparison
  // between zod's output and pydantic's would differ on form alone.
  assert.deepEqual(
    inputShape({ type: 'object', properties: { a: { type: ['string', 'null'] } } }),
    inputShape({ type: 'object', properties: { a: { anyOf: [{ type: 'string' }, { type: 'null' }] } } }),
  )
})

test('the shape reader refuses a keyword it does not compare, so a narrower schema cannot pass as equal', () => {
  assert.throws(
    () => shapeOf(CreateGoalLive.extend({ goal_type: z.enum(['objective', 'milestone', 'task']).default('objective') })),
    /keyword "enum"/,
  )
  assert.throws(() => shapeOf(CreateGoalLive.extend({ title: z.string().min(1) })), /keyword "minLength"/)
  assert.throws(() => shapeOf(CreateGoalLive.extend({ priority: z.int().min(1).default(3) })), /minimum 1/)
  // z.int()'s own safe-integer bounds are not a narrowing.
  assert.doesNotThrow(() => shapeOf(CreateGoalLive))
})

test('the sent subsets are inside the live schemas, send what the live server requires, and carry no defaults', () => {
  const pairs: [string, z.ZodObject, z.ZodObject, Record<string, unknown>][] = [
    ['create_goal', CreateGoalLive, CreateGoalSent, { project_id: 'aos/ceo', goal_type: 'task', title: 't', parent_goal_id: 'g1' }],
    ['update_goal', UpdateGoalLive, UpdateGoalSent, { goal_id: 'g1', status: 'in_progress', progress_pct: 100 }],
    ['get_goal_tree', GetGoalTreeLive, GetGoalTreeSent, { goal_id: 'g1' }],
    ['get_secret', GetSecretLive, GetSecretSent, { label: 'k' }],
  ]
  for (const [name, live, sent, sample] of pairs) {
    const liveKeys = Object.keys(live.shape)
    for (const key of Object.keys(sent.shape)) assert.ok(liveKeys.includes(key), `${name} sends ${key}, which it does not declare`)
    for (const key of inputShape(captured(name)).required) {
      assert.ok(Object.keys(sent.shape).includes(key), `${name} requires ${key}, which the kernel does not send`)
    }
    // Parse output is the input: nothing is added on the way to the wire.
    assert.deepEqual(sent.parse(sample), sample, name)
    assert.doesNotThrow(() => live.parse(sample), `${name}: the live schema refuses what the kernel sends`)
  }
})

test('update_goal and get_goal_tree are sent no project_id, and create_goal is never sent a missing or null one', () => {
  assert.equal(UpdateGoalSent.safeParse({ goal_id: 'g', status: 'blocked', project_id: 'aos/ceo' }).success, false)
  assert.equal(GetGoalTreeSent.safeParse({ goal_id: 'g', project_id: 'aos/ceo' }).success, false)
  assert.equal(CreateGoalSent.safeParse({ goal_type: 'objective', title: 't' }).success, false)
  assert.equal(CreateGoalSent.safeParse({ project_id: '', goal_type: 'objective', title: 't' }).success, false)
  assert.equal(CreateGoalSent.safeParse({ project_id: 'p', goal_type: 'objective', title: 't', parent_goal_id: null }).success, false)
  // Decisions are not sent, and a kind pmmcp does not have is not sent.
  for (const status of ['completed', 'abandoned', 'review', 'pending']) {
    assert.equal(UpdateGoalSent.safeParse({ goal_id: 'g', status }).success, false, status)
  }
  assert.equal(CreateGoalSent.safeParse({ project_id: 'p', goal_type: 'epic', title: 't' }).success, false)
  assert.equal(GetSecretSent.safeParse({ label: 'k', project_id: 'aos/ceo' }).success, false)
})

test("the P6 goal result is strict: an unknown key, a missing key, a status outside pmmcp's five, or progress outside 0-100 is refused", () => {
  const good = { goal_id: 'goal_000000000001', project_id: 'aos/ceo', status: 'in_progress', progress_pct: 100 }
  assert.deepEqual(GoalResult.parse(good), good)
  for (const [why, bad] of [
    ['an unknown key (a timestamp, say)', { ...good, created_at: '2026-10-19T00:00:00Z' }],
    ['a missing key', { goal_id: good.goal_id, project_id: good.project_id, status: good.status }],
    ['a status pmmcp does not have', { ...good, status: 'review' }],
    ['progress above 100', { ...good, progress_pct: 101 }],
    ['progress below 0', { ...good, progress_pct: -1 }],
    ['an empty id', { ...good, goal_id: '' }],
    ['a null project', { ...good, project_id: null }],
  ] as const) {
    assert.equal(GoalResult.safeParse(bad).success, false, why)
  }
  // The kernel's vocabulary sits inside pmmcp's, and the double's is pmmcp's.
  for (const s of SENDABLE_STATUSES) assert.ok((PMMCP_STATUSES as readonly string[]).includes(s))
  assert.deepEqual([...GOAL_STATUSES], [...PMMCP_STATUSES])
  // And it is the shape the double declares as P6, by names, types and required.
  assert.deepEqual(
    inputShape(z.toJSONSchema(GoalResult), { strict: false }).required,
    inputShape(GOAL_RESULT_OUTPUT, { strict: false }).required,
  )
  const kernel = inputShape(z.toJSONSchema(GoalResult), { strict: false }).properties
  const declared = inputShape(GOAL_RESULT_OUTPUT, { strict: false }).properties
  assert.deepEqual(Object.keys(kernel).sort(), Object.keys(declared).sort())
  for (const name of Object.keys(declared)) {
    assert.deepEqual(kernel[name]?.types, declared[name]?.types, name)
  }
})
