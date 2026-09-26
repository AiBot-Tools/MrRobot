// Tests of the pmmcp double itself.
//
// A double is test infrastructure, which is exactly why it gets tested: every
// later assertion about the CEO's goal planning is an assertion about this file
// behaving the way pmmcp is documented to. A double that quietly allows an
// illegal transition turns a red test green, and nothing else in the suite
// would notice.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { parse as parseYaml } from 'yaml'

import type { Client } from '@modelcontextprotocol/sdk/client/index.js'

import {
  GOAL_STATUSES,
  GOAL_TRANSITIONS,
  PARENT_KIND,
  PMMCP_TOOLS,
  PMMCP_TOOL_COUNT,
  pmmcpMock,
  type GoalStatus,
  type PmmcpMock,
} from './helpers/mock-pmmcp.js'
import { parseToolViews } from '../src/mcp/tool-views.js'
import { REPO_ROOT } from './helpers/kernel.js'

interface TextBlock {
  readonly type: string
  readonly text?: unknown
}

/** The text of a tool result, with whether the server flagged it an error. */
async function call(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ text: string; isError: boolean }> {
  const result = await client.callTool({ name, arguments: args })
  const content = result.content
  const blocks: TextBlock[] = Array.isArray(content) ? (content as TextBlock[]) : []
  const text = blocks
    .map((b) => (typeof b.text === 'string' ? b.text : ''))
    .join('')
  return { text, isError: result.isError === true }
}

async function json(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const { text, isError } = await call(client, name, args)
  assert.equal(isError, false, `${name} failed: ${text}`)
  const parsed: unknown = JSON.parse(text)
  assert.equal(typeof parsed, 'object')
  return parsed as Record<string, unknown>
}

async function open(
  t: { after: (fn: () => Promise<void> | void) => void },
  options: Parameters<typeof pmmcpMock>[0] = {},
): Promise<{ mock: PmmcpMock; client: Client }> {
  const mock = pmmcpMock(options)
  const client = await mock.connect()
  t.after(async () => {
    await mock.close()
  })
  return { mock, client }
}

test('every tool config/tool-views.yaml pins is declared by the double', () => {
  // The double exists to test policy against a server. If the policy file names
  // a tool the double does not serve, the forced classifications are asserted
  // against nothing — which is the failure mode this test exists to catch.
  const views = parseToolViews(parseYaml(readFileSync(`${REPO_ROOT}/config/tool-views.yaml`, 'utf8')))
  const pinned = Object.keys(views.servers['pmmcp']?.tools ?? {}).sort()
  const declared = new Set(PMMCP_TOOLS.map((s) => s.name))
  assert.equal(pinned.length, 9, 'tool-views pins nine pmmcp tools')
  for (const name of pinned) {
    assert.equal(declared.has(name), true, `the double does not declare the pinned tool ${name}`)
  }
})

test('exactly one declared tool is confirmed, and it is get_secret taking label', () => {
  // The honesty invariant. Q24 confirmed one argument name off a live listTools
  // and nothing else; a second `confirmed` here would be a guess wearing the
  // word, and every later decision built on it would look grounded.
  const confirmed = PMMCP_TOOLS.filter((s) => s.provenance === 'confirmed')
  assert.deepEqual(
    confirmed.map((s) => s.name),
    ['get_secret'],
  )
  assert.deepEqual(Object.keys(confirmed[0]?.inputSchema.properties ?? {}), ['label'])
  // And the rest say so, each with where the guess came from.
  for (const spec of PMMCP_TOOLS) {
    if (spec.provenance === 'modelled') {
      assert.notEqual(spec.source.trim(), '', `${spec.name} is modelled with no source`)
    }
  }
})

test('the hierarchy is objective → milestone → task and nothing else', async (t) => {
  const { client } = await open(t)
  const objective = (await json(client, 'create_goal', {
    project_id: 'aos/ceo',
    kind: 'objective',
    title: 'ship phase 1',
  }))['id']
  assert.equal(typeof objective, 'string')

  // An objective is a root.
  const rooted = await call(client, 'create_goal', {
    project_id: 'aos/ceo',
    kind: 'objective',
    title: 'nested objective',
    parent_id: objective,
  })
  assert.equal(rooted.isError, true)
  assert.match(rooted.text, /takes no parent_id/)

  // A task may not skip the milestone level: depth is three by construction,
  // which is what lets a projection walk a tree of known shape.
  const skipped = await call(client, 'create_goal', {
    project_id: 'aos/ceo',
    kind: 'task',
    title: 'orphan task',
    parent_id: objective,
  })
  assert.equal(skipped.isError, true)
  assert.match(skipped.text, /hangs from a milestone, not a objective/)

  const parentless = await call(client, 'create_goal', {
    project_id: 'aos/ceo',
    kind: 'milestone',
    title: 'floating',
  })
  assert.equal(parentless.isError, true)
  assert.match(parentless.text, /requires a parent_id/)

  // And the legal shape works.
  const milestone = (await json(client, 'create_goal', {
    project_id: 'aos/ceo',
    kind: 'milestone',
    title: 'projections',
    parent_id: objective,
  }))['id']
  const task = await json(client, 'create_goal', {
    project_id: 'aos/ceo',
    kind: 'task',
    title: 'cron',
    parent_id: milestone,
  })
  assert.equal(task['status'], 'pending')
  assert.deepEqual(Object.keys(PARENT_KIND).sort(), ['milestone', 'objective', 'task'])
})

test('project_id namespaces goals and memories, and a foreign id reads as not found', async (t) => {
  const { mock, client } = await open(t)
  const ceo = mock.seedTree('aos/ceo')
  mock.seedTree('aos/agent/researcher')

  // Not "forbidden": the answer must not confirm that the id exists elsewhere.
  const foreign = await call(client, 'get_goal', {
    project_id: 'aos/agent/researcher',
    goal_id: ceo.objective,
  })
  assert.equal(foreign.isError, true)
  assert.match(foreign.text, /no goal .* in aos\/agent\/researcher/)

  const listed = await json(client, 'list_goals', { project_id: 'aos/ceo' })
  const goals = listed['goals']
  assert.equal(Array.isArray(goals) && goals.length, 3, 'only this project\'s three goals')

  await json(client, 'remember', { project_id: 'aos/ceo', content: 'the operator prefers terse' })
  const crossed = await json(client, 'recall', { project_id: 'aos/shared', query: 'operator' })
  assert.deepEqual(crossed['hits'], [], 'a memory never crosses a namespace')
  const own = await json(client, 'recall', { project_id: 'aos/ceo', query: 'operator' })
  assert.equal(Array.isArray(own['hits']) && own['hits'].length, 1)
})

test('status transitions are validated, review is not done, and done is terminal', async (t) => {
  const { mock, client } = await open(t)
  const { task } = mock.seedTree('aos/ceo')
  const move = (status: GoalStatus): Promise<{ text: string; isError: boolean }> =>
    call(client, 'update_goal_status', { project_id: 'aos/ceo', goal_id: task, status })

  // The shortcut a self-marking worker would want, refused.
  const shortcut = await move('done')
  assert.equal(shortcut.isError, true)
  assert.match(shortcut.text, /pending → done/)

  assert.equal((await move('in_progress')).isError, false)
  // in_progress → done is refused too: review is a real state on the path, not
  // a label a projection may collapse.
  assert.equal((await move('done')).isError, true)
  assert.equal((await move('review')).isError, false)
  assert.equal((await move('done')).isError, false)

  const reopened = await move('in_progress')
  assert.equal(reopened.isError, true)
  assert.match(reopened.text, /terminal/)

  // The table itself: every terminal status has no exits, and every status is
  // reachable as a target from somewhere, or the vocabulary has a dead entry.
  assert.deepEqual(GOAL_TRANSITIONS.done, [])
  assert.deepEqual(GOAL_TRANSITIONS.abandoned, [])
  const targets = new Set(Object.values(GOAL_TRANSITIONS).flat())
  for (const status of GOAL_STATUSES) {
    if (status === 'pending') continue // the initial state, never a target
    assert.equal(targets.has(status), true, `${status} is in the vocabulary but unreachable`)
  }
})

test('auto_resume is off: nothing but an explicit update moves a status', async (t) => {
  const { mock, client } = await open(t)
  const { objective, milestone, task } = mock.seedTree('aos/ceo')
  await json(client, 'update_goal_status', {
    project_id: 'aos/ceo',
    goal_id: task,
    status: 'in_progress',
  })
  await json(client, 'update_goal_status', { project_id: 'aos/ceo', goal_id: task, status: 'review' })
  await json(client, 'update_goal_status', { project_id: 'aos/ceo', goal_id: task, status: 'done' })

  // Finishing every task must not finish the milestone or the objective. If the
  // server advanced them, the kernel's own goal projection would be racing a
  // second writer it cannot see.
  const tree = await json(client, 'list_goals', { project_id: 'aos/ceo' })
  const byId = new Map(
    (tree['goals'] as { id: string; status: string }[]).map((g) => [g.id, g.status]),
  )
  assert.equal(byId.get(task), 'done')
  assert.equal(byId.get(milestone), 'pending')
  assert.equal(byId.get(objective), 'pending')
  assert.deepEqual(mock.state.autoTransitions, [])
})

test('parent rollup is off by default and refuses a live child when switched on', async (t) => {
  // Off by default deliberately: nothing has confirmed pmmcp enforces this, and
  // a double that invents a rule makes the kernel depend on a phantom.
  const loose = await open(t)
  const l = loose.mock.seedTree('aos/ceo')
  for (const status of ['in_progress', 'review', 'done'] as const) {
    await json(loose.client, 'update_goal_status', {
      project_id: 'aos/ceo',
      goal_id: l.milestone,
      status,
    })
  }
  assert.equal(loose.mock.state.goals.get(l.milestone)?.status, 'done', 'default allows it')
  assert.equal(loose.mock.state.goals.get(l.task)?.status, 'pending', 'with the task still open')

  const strict = await open(t, { strictRollup: true })
  const s = strict.mock.seedTree('aos/ceo')
  await json(strict.client, 'update_goal_status', {
    project_id: 'aos/ceo',
    goal_id: s.milestone,
    status: 'in_progress',
  })
  await json(strict.client, 'update_goal_status', {
    project_id: 'aos/ceo',
    goal_id: s.milestone,
    status: 'review',
  })
  const blocked = await call(strict.client, 'update_goal_status', {
    project_id: 'aos/ceo',
    goal_id: s.milestone,
    status: 'done',
  })
  assert.equal(blocked.isError, true)
  assert.match(blocked.text, /not yet at rest/)
})

test('the vault answers on the confirmed argument and its audit log holds no value', async (t) => {
  const { mock, client } = await open(t, { secrets: { 'anthropic-api-key': 'sk-ant-fixture' } })
  const got = await call(client, 'get_secret', { label: 'anthropic-api-key' })
  assert.equal(got.isError, false)
  assert.equal(got.text, 'sk-ant-fixture')

  const missing = await call(client, 'get_secret', { label: 'nothing-here' })
  assert.equal(missing.isError, true)

  await json(client, 'set_secret', { label: 'written', value: 'v' })
  const audit = await call(client, 'audit_secrets', {})
  assert.equal(audit.isError, false)
  // The audit of a vault is a place a secret must not appear — in the double as
  // much as in the real one, because this text lands in test output.
  assert.equal(audit.text.includes('sk-ant-fixture'), false)
  assert.equal(audit.text.includes('anthropic-api-key'), true)
  assert.deepEqual(
    mock.state.audit.map((e) => `${e.action}:${e.label}:${String(e.ok)}`),
    ['get_secret:anthropic-api-key:true', 'get_secret:nothing-here:false', 'set_secret:written:true'],
  )
})

test('a wrong secretArg makes get_secret unanswerable and stops claiming confirmation', async (t) => {
  const { client } = await open(t, { secretArg: 'name', secrets: { k: 'v' } })
  const wrong = await call(client, 'get_secret', { label: 'k' })
  assert.equal(wrong.isError, true, 'the server wants `name`, so `label` resolves nothing')
  const right = await call(client, 'get_secret', { name: 'k' })
  assert.equal(right.text, 'v')
})

test('a forced kernel-only or disabled tool throws rather than answering plausibly', async (t) => {
  const { client } = await open(t)
  for (const name of [
    'admin',
    'restore_backup',
    'delete_context_source',
    'index_project',
    'coding_agent',
    'session_insight_agent',
  ]) {
    await assert.rejects(
      () => client.callTool({ name, arguments: {} }),
      /refuses to model/,
      `${name} must not return something a test could mistake for success`,
    )
  }
})

test('an undeclared tool is a protocol error, not an invented answer', async (t) => {
  const { client } = await open(t)
  await assert.rejects(() => client.callTool({ name: 'no_such_tool', arguments: {} }), /no tool no_such_tool/)
})

test('a session idle-expires, and a fresh session finds the state intact', async (t) => {
  let clock = 1_000
  const { mock, client } = await open(t, { idleMs: 60_000, now: () => clock })
  const { task } = mock.seedTree('aos/ceo')
  assert.equal((await call(client, 'get_goal', { project_id: 'aos/ceo', goal_id: task })).isError, false)

  clock += 60_001
  // Both doors: a call and a ping. A session that still answers ping is one the
  // hub's heartbeat can never notice has gone.
  await assert.rejects(() => client.callTool({ name: 'recall', arguments: {} }), /session expired/)
  await assert.rejects(() => client.ping(), /session expired/)

  const second = await mock.connect()
  const goal = await json(second, 'get_goal', { project_id: 'aos/ceo', goal_id: task })
  assert.equal(goal['id'], task, 'the goals outlive the session that created them')
  assert.equal(mock.sessions.length, 2)
  assert.equal(mock.sessions[0]?.expired, true)
  assert.equal(mock.sessions[1]?.expired, false)
})

test('padTo reaches pmmcp\'s real cardinality with visibly fake placeholders', async (t) => {
  const { mock, client } = await open(t, { padTo: PMMCP_TOOL_COUNT })
  const listed = await client.listTools()
  assert.equal(listed.tools.length, PMMCP_TOOL_COUNT)
  assert.equal(mock.toolNames.length, PMMCP_TOOL_COUNT)
  const padded = mock.toolNames.filter((n) => n.startsWith('unmodelled_placeholder_'))
  assert.equal(padded.length, PMMCP_TOOL_COUNT - PMMCP_TOOLS.length)
  // Named so nobody can mistake one for a real pmmcp tool. The 34 real names
  // have not been read on this machine and are not invented here.
  assert.equal(
    padded.every((n) => /^unmodelled_placeholder_\d+$/.test(n)),
    true,
  )
  await assert.rejects(
    () => client.callTool({ name: 'unmodelled_placeholder_1', arguments: {} }),
    /no tool unmodelled_placeholder_1/,
  )
})
