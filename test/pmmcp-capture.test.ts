// The capture builder (src/mcp/capture.ts) against a double that declares
// output schemas: what the operator's next `npm run capture:pmmcp` will write.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test from 'node:test'

import { captureOf } from '../src/mcp/capture.js'
import { listToolPages } from '../src/mcp/hub.js'
import { GOAL_RESULT_OUTPUT, pmmcpMock } from './helpers/mock-pmmcp.js'

test('a capture keeps every tool\'s outputSchema verbatim and says that it records them', async (t) => {
  const mock = pmmcpMock({ refusals: 'p5', outputs: { create_goal: 'structured', get_secret: 'wrapped' } })
  t.after(async () => {
    await mock.close()
  })
  const client = await mock.connect()
  const { tools, pages } = await listToolPages(client)
  const capture = captureOf(tools, { capturedAt: '2026-10-19T00:00:00.000Z', server: 'pmmcp', url: 'http://127.0.0.1:8766/mcp', pages })

  assert.equal(capture.recordsOutputSchema, true)
  assert.equal(capture.pages, 1)
  assert.equal(capture.toolCount, tools.length)
  const byName = new Map(capture.tools.map((x) => [x.name, x]))
  assert.deepEqual(byName.get('create_goal')?.outputSchema, GOAL_RESULT_OUTPUT)
  assert.deepEqual(
    (byName.get('get_secret')?.outputSchema as { properties?: Record<string, unknown> } | undefined)?.properties,
    { result: { type: 'string', title: 'Result' } },
  )
  // A tool that declares none carries no key at all, so "declares none" and
  // "was captured before outputs were recorded" stay different facts.
  assert.equal('outputSchema' in (byName.get('remember') ?? {}), false)
  const names = capture.tools.map((x) => x.name)
  assert.deepEqual(names, [...names].sort())
})
