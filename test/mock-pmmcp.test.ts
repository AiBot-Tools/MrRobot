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
  assert.equal(pinned.length, 19, 'tool-views pins nineteen pmmcp tools')
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

/** The goal id out of pmmcp's create reply: "✅ Goal created: goal_<hex>". */
async function created(client: Client, args: Record<string, unknown>): Promise<string> {
  const { text, isError } = await call(client, 'create_goal', args)
  assert.equal(isError, false, text)
  const id = /^✅ Goal created: (goal_[0-9a-f]{12})\n/u.exec(text)?.[1]
  assert.ok(id !== undefined, `not a pmmcp create reply: ${text}`)
  return id
}

test('create_goal replies as pmmcp does, and refuses as SUCCESSFUL text', async (t) => {
  const { client } = await open(t)
  const objective = await created(client, { project_id: 'aos/ceo', goal_type: 'objective', title: 'ship phase 1' })

  // pmmcp reports a refusal as text with no error flag; only a missing
  // required argument is a transport-level error (FastMCP's own validation).
  const badType = await call(client, 'create_goal', { project_id: 'aos/ceo', goal_type: 'epic', title: 'x' })
  assert.equal(badType.isError, false)
  assert.match(badType.text, /^Error: Invalid goal_type: epic/)
  const noParent = await call(client, 'create_goal', {
    project_id: 'aos/ceo',
    goal_type: 'milestone',
    title: 'x',
    parent_goal_id: 'goal_000000000999',
  })
  assert.equal(noParent.isError, false)
  assert.match(noParent.text, /^Error: Parent goal not found: goal_000000000999/)
  assert.equal((await call(client, 'create_goal', { project_id: 'aos/ceo' })).isError, true)

  // Stricter than pmmcp, and labelled so: depth is three by construction.
  const skipped = await call(client, 'create_goal', {
    project_id: 'aos/ceo',
    goal_type: 'task',
    title: 'orphan task',
    parent_goal_id: objective,
  })
  assert.match(skipped.text, /^Error: a task hangs from a milestone .*stricter than pmmcp/)

  const milestone = await created(client, {
    project_id: 'aos/ceo',
    goal_type: 'milestone',
    title: 'projections',
    parent_goal_id: objective,
  })
  await created(client, { project_id: 'aos/ceo', goal_type: 'task', title: 'cron', parent_goal_id: milestone })
  assert.deepEqual(Object.keys(PARENT_KIND).sort(), ['milestone', 'objective', 'task'])
})

test('update_goal and get_goal_tree take no project_id; listings carry titles and no ids', async (t) => {
  const { mock, client } = await open(t)
  const ceo = mock.seedTree('aos/ceo')
  mock.seedTree('aos/agent/researcher')

  // No project on either tool: pmmcp moves and shows ANY goal by id. This is
  // why the kernel checks a goal's namespace against its own goal.created log.
  const spec = (name: string): string[] =>
    Object.keys(PMMCP_TOOLS.find((s) => s.name === name)?.inputSchema.properties ?? {})
  assert.equal(spec('update_goal').includes('project_id'), false)
  assert.equal(spec('get_goal_tree').includes('project_id'), false)
  const moved = await call(client, 'update_goal', { goal_id: ceo.task, status: 'in_progress' })
  assert.match(moved.text, new RegExp(`^✅ Goal updated: ${ceo.task}\\n`, 'u'))

  const tree = await call(client, 'get_goal_tree', { goal_id: ceo.objective })
  assert.equal(
    tree.text,
    // Progress rolls up ONE level, as pmmcp's _update_parent_progress does.
    ['⬜ [O] seeded objective', '  ⬜ [M] seeded milestone (50%)', '    🔵 [T] seeded task'].join('\n'),
  )
  assert.equal(tree.text.includes(ceo.task), false, 'pmmcp listings carry no ids')

  const listed = await call(client, 'list_goals', { project_id: 'aos/ceo' })
  assert.equal(listed.text, '## Goals for aos/ceo (1)\n⬜ [O] seeded objective')
  const none = await call(client, 'list_goals', { project_id: 'aos/nobody' })
  assert.equal(none.text, "No goals found for project 'aos/nobody'.")
  assert.equal((await call(client, 'get_goal_tree', { goal_id: 'goal_x' })).text, 'Goal goal_x not found.')

  await json(client, 'remember', { project_id: 'aos/ceo', content: 'the operator prefers terse' })
  const crossed = await json(client, 'recall', { project_id: 'aos/shared', query: 'operator' })
  assert.deepEqual(crossed['hits'], [], 'a memory never crosses a namespace')
})

test('status transitions are pmmcp\'s table, a same-status update is a no-op, and refusals are text', async (t) => {
  const { mock, client } = await open(t)
  const { task } = mock.seedTree('aos/ceo')
  const move = (status: string): Promise<{ text: string; isError: boolean }> =>
    call(client, 'update_goal', { goal_id: task, status })

  const shortcut = await move('completed')
  assert.equal(shortcut.isError, false)
  assert.match(shortcut.text, /^Error: Cannot transition from 'pending' to 'completed'/)
  assert.match((await move('review')).text, /^Error: Invalid status: review/)

  assert.match((await move('in_progress')).text, /^✅ Goal updated/)
  // The kernel sends `review` as in_progress after the run already set it.
  assert.match((await move('in_progress')).text, /^✅ Goal updated/)
  assert.match((await move('completed')).text, /^✅ Goal updated/)
  assert.match((await move('in_progress')).text, /^✅ Goal updated/, 'completed reopens')
  assert.equal((await call(client, 'update_goal', { goal_id: 'goal_nope', status: 'blocked' })).text, 'Goal goal_nope not found.')

  assert.deepEqual(GOAL_TRANSITIONS.completed, ['in_progress'])
  assert.deepEqual(GOAL_TRANSITIONS.abandoned, ['pending'])
  assert.deepEqual([...GOAL_STATUSES].sort(), ['abandoned', 'blocked', 'completed', 'in_progress', 'pending'])
})

test('auto_resume is off: a child\'s status moves its parent\'s progress, never its status', async (t) => {
  const { mock, client } = await open(t)
  const { objective, milestone, task } = mock.seedTree('aos/ceo')
  await call(client, 'update_goal', { goal_id: task, status: 'in_progress' })
  await call(client, 'complete_goal', { goal_id: task })

  assert.equal(mock.state.goals.get(task)?.status, 'completed')
  assert.equal(mock.state.goals.get(milestone)?.status, 'pending')
  assert.equal(mock.state.goals.get(milestone)?.progressPct, 100, 'pmmcp rolls up progress one level')
  assert.equal(mock.state.goals.get(objective)?.status, 'pending')
  assert.deepEqual(mock.state.autoTransitions, [])
})

test('parent rollup is off by default and refuses a live child when switched on', async (t) => {
  // Off by default: pmmcp does not do this (src/storage/goal_store.py), and a
  // double that invents a rule makes the kernel depend on a phantom.
  const loose = await open(t)
  const l = loose.mock.seedTree('aos/ceo')
  await call(loose.client, 'update_goal', { goal_id: l.milestone, status: 'in_progress' })
  assert.match((await call(loose.client, 'complete_goal', { goal_id: l.milestone })).text, /^✅ Completed/)
  assert.equal(loose.mock.state.goals.get(l.task)?.status, 'pending', 'with the task still open')

  const strict = await open(t, { strictRollup: true })
  const s = strict.mock.seedTree('aos/ceo')
  await call(strict.client, 'update_goal', { goal_id: s.milestone, status: 'in_progress' })
  const blocked = await call(strict.client, 'complete_goal', { goal_id: s.milestone })
  assert.match(blocked.text, /not yet at rest/)
})

test('get_secret answers as the real pmmcp does: a masked sentence, never the value, and success either way', async (t) => {
  // src/tools/security.py in pmmcp: found → `Secret '<label>' exists (masked):
  // ****<last 4>`; missing → `Secret '<label>' not found.`; neither is isError.
  const { client } = await open(t, { secrets: { 'anthropic-api-key': 'sk-ant-fixture-wxyz' } })
  const got = await call(client, 'get_secret', { label: 'anthropic-api-key' })
  assert.equal(got.isError, false)
  assert.equal(got.text, "Secret 'anthropic-api-key' exists (masked): ***************wxyz")
  assert.equal(got.text.includes('sk-ant'), false)

  const missing = await call(client, 'get_secret', { label: 'nothing-here' })
  assert.equal(missing.isError, false)
  assert.equal(missing.text, "Secret 'nothing-here' not found.")
})

test('the vault answers on the confirmed argument and its audit log holds no value', async (t) => {
  const { mock, client } = await open(t, { secrets: { 'anthropic-api-key': 'sk-ant-fixture' }, revealSecrets: true })
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
  const { client } = await open(t, { secretArg: 'name', secrets: { k: 'v' }, revealSecrets: true })
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
  assert.equal((await call(client, 'get_goal_tree', { goal_id: task })).text, '⬜ [T] seeded task')

  clock += 60_001
  // Both doors: a call and a ping. A session that still answers ping is one the
  // hub's heartbeat can never notice has gone.
  await assert.rejects(() => client.callTool({ name: 'recall', arguments: {} }), /session expired/)
  await assert.rejects(() => client.ping(), /session expired/)

  const second = await mock.connect()
  const goal = await call(second, 'get_goal_tree', { goal_id: task })
  assert.equal(goal.text, '⬜ [T] seeded task', 'the goals outlive the session that created them')
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
