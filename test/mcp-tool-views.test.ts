// T12 — tool-view policy.
//
// The theme is that unsafe configurations are refused at parse, not corrected
// at call time. A silent downgrade would leave a file on disk that reads as
// though an agent has a tool it does not have, and the next person to edit it
// would be working from a lie.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parse as parseYaml } from 'yaml'

import {
  classify,
  DEFAULT_VIEW,
  FORCED_DISABLED,
  FORCED_KERNEL_ONLY,
  parseToolViews,
  resolveView,
} from '../src/mcp/tool-views.js'

/** Parse a YAML document the way the daemon will, from text. */
function fromYaml(yaml: string): ReturnType<typeof parseToolViews> {
  return parseToolViews(parseYaml(yaml))
}

const MINIMAL = `
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall:
        exposure: agent
        risk: read
`

test('unclassified tool resolves to kernel-only', () => {
  const file = fromYaml(MINIMAL)

  // A tool the file never mentions. New tools appear on upstream servers
  // without warning, and this is what stops one becoming agent-reachable the
  // moment it ships.
  const view = resolveView(file, 'pmmcp', 'brand_new_tool')
  assert.equal(view.exposure, 'kernel-only')
  assert.deepEqual(view, DEFAULT_VIEW)

  // An entire server nobody has classified behaves the same way.
  assert.equal(resolveView(file, 'never-seen-server', 'anything').exposure, 'kernel-only')

  // What IS classified keeps its exposure.
  assert.equal(resolveView(file, 'pmmcp', 'recall').exposure, 'agent')
})

test('yaml exposing get_secret (and each pinned name, and my_secret_thing) to agents is refused at parse', () => {
  // Each pinned name individually, so a refusal that covered only the first
  // would fail here rather than pass on a sample.
  for (const name of FORCED_KERNEL_ONLY) {
    assert.throws(
      () =>
        fromYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      ${name}:
        exposure: agent
`),
      new RegExp(`${name} must be kernel-only`),
      `${name} must not be exposable to agents`,
    )
  }

  // The name-based rule catches tools the pinned list never anticipated.
  assert.throws(
    () =>
      fromYaml(`
version: 1
servers:
  vault:
    default: kernel-only
    tools:
      my_secret_thing:
        exposure: agent
`),
    /my_secret_thing must be kernel-only/,
  )

  // "disabled" is not a way around it either: these must be kernel-only
  // exactly, because the kernel itself needs them.
  assert.throws(
    () =>
      fromYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      get_secret:
        exposure: disabled
`),
    /get_secret must be kernel-only/,
  )
})

test('yaml giving coding_agent or session_insight_agent anything but disabled is refused', () => {
  for (const name of FORCED_DISABLED) {
    for (const exposure of ['agent', 'kernel-only']) {
      assert.throws(
        () =>
          fromYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      ${name}:
        exposure: ${exposure}
`),
        new RegExp(`${name} must be disabled`),
        `${name} must not be ${exposure}`,
      )
    }
  }

  // Even the kernel may not call them: a nested model call inside another
  // server spends money and takes actions with none of it in our log.
  const file = fromYaml(MINIMAL)
  assert.equal(resolveView(file, 'pmmcp', 'coding_agent').exposure, 'disabled')
  assert.equal(resolveView(file, 'pmmcp', 'session_insight_agent').exposure, 'disabled')
})

test('a server default other than kernel-only is refused', () => {
  for (const bad of ['agent', 'disabled', 'read']) {
    assert.throws(
      () =>
        fromYaml(`
version: 1
servers:
  pmmcp:
    default: ${bad}
    tools: {}
`),
      /tool-views.yaml is invalid/,
      `default: ${bad} must be refused`,
    )
  }
  // Omitting it is refused too: the safe value is stated, never assumed.
  assert.throws(() => fromYaml('version: 1\nservers:\n  pmmcp:\n    tools: {}\n'), /invalid/)
})

test('an agent-exposed name that fails the provider regex after mapping is refused', () => {
  // Fine as an MCP name (128 chars allowed), too long once mapped and checked
  // against the stricter provider rule.
  const long = 't'.repeat(62)
  assert.throws(
    () =>
      fromYaml(`
version: 1
servers:
  server:
    default: kernel-only
    tools:
      ${long}:
        exposure: agent
`),
    /fails the provider tool-name rule/,
  )

  // The same tool kept kernel-only is fine: the kernel calls it by its MCP
  // name and never puts it in a provider tool array.
  const ok = fromYaml(`
version: 1
servers:
  server:
    default: kernel-only
    tools:
      ${long}:
        exposure: kernel-only
`)
  assert.equal(resolveView(ok, 'server', long).exposure, 'kernel-only')
})

test('classify separates listed tools into classified and unclassified', () => {
  const file = fromYaml(MINIMAL)
  const listed = ['recall', 'brand_new_tool', 'get_secret', 'coding_agent', 'another_new_one']
  const result = classify(file, 'pmmcp', listed)

  // Declared and forced tools are classified; genuinely unknown ones are not.
  assert.deepEqual([...result.classified.keys()].sort(), ['coding_agent', 'get_secret', 'recall'])
  assert.deepEqual(result.unclassified, ['brand_new_tool', 'another_new_one'])

  assert.equal(result.classified.get('recall')?.exposure, 'agent')
  assert.equal(result.classified.get('get_secret')?.exposure, 'kernel-only')
  assert.equal(result.classified.get('coding_agent')?.exposure, 'disabled')

  // Unclassified is a report for a human, not a blocker: those tools still
  // resolve, to kernel-only, so the kernel keeps working while they are
  // triaged.
  for (const tool of result.unclassified) {
    assert.equal(resolveView(file, 'pmmcp', tool).exposure, 'kernel-only')
  }
})

test('taints and quarantine default to false; exposure spelled agent', () => {
  const file = fromYaml(`
version: 1
servers:
  pmmcp:
    default: kernel-only
    tools:
      recall:
        exposure: agent
        risk: read
      remember:
        exposure: agent
        risk: write
        taints: true
        quarantine: true
        note: writes to shared memory
`)

  const recall = resolveView(file, 'pmmcp', 'recall')
  assert.equal(recall.taints, false)
  assert.equal(recall.quarantine, false)
  assert.equal(recall.risk, 'read')

  const remember = resolveView(file, 'pmmcp', 'remember')
  assert.equal(remember.taints, true)
  assert.equal(remember.quarantine, true)
  assert.equal(remember.note, 'writes to shared memory')

  // risk defaults to write, the cautious middle, not read.
  const file2 = fromYaml(`
version: 1
servers:
  s:
    default: kernel-only
    tools:
      t:
        exposure: agent
`)
  assert.equal(resolveView(file2, 's', 't').risk, 'write')

  // The spelling is exactly "agent". Near-misses are refused, not guessed.
  for (const bad of ['agents', 'Agent', 'allow', 'exposed']) {
    assert.throws(
      () => fromYaml(`version: 1\nservers:\n  s:\n    default: kernel-only\n    tools:\n      t:\n        exposure: ${bad}\n`),
      /invalid/,
      `exposure: ${bad} must be refused`,
    )
  }
  // Unknown keys are refused: a typo must not sit in the file looking active.
  assert.throws(
    () =>
      fromYaml(
        'version: 1\nservers:\n  s:\n    default: kernel-only\n    tools:\n      t:\n        exposure: agent\n        quarentine: true\n',
      ),
    /invalid/,
  )
})
