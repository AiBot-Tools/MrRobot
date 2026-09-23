// T13 — the policy gate.
//
// The gate is where "the model never makes an access-control decision" stops
// being a sentence in a contract and becomes a function signature. Every test
// here is an attempt to get a yes that the rules do not permit.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { assertHumanActor, HumanActor, mintHumanActor } from '../src/control/actor.js'
import { decide, GateInput, mentionsProtectedPath } from '../src/policy/gate.js'

function input(overrides: Partial<GateInput> = {}): GateInput {
  return {
    view: { exposure: 'agent', risk: 'read', taints: false, quarantine: false },
    scope: { runId: 'run-1', agentId: 'researcher', taint: 'clean' },
    manifestAllows: true,
    toolRef: 'pmmcp.recall',
    args: { query: 'goals' },
    ...overrides,
  }
}

test('unknown tool is denied', () => {
  // An unclassified tool resolves to kernel-only, so it arrives here as
  // not-agent and is denied. The default is refusal, not an error path.
  const verdict = decide(input({ view: { exposure: 'kernel-only', risk: 'write', taints: false, quarantine: false } }))
  assert.equal(verdict.decision, 'deny')
  assert.match(verdict.reason, /not exposed to agents/)
})

test('kernel-only and disabled are denied even for kernel callers through the gate', () => {
  // The gate answers for AGENT calls. Kernel-only tools are reached by the
  // kernel through a separate path that never consults this function, so
  // anything arriving here with those exposures is denied regardless of who
  // is asking — there is no "but I am the kernel" branch to exploit.
  for (const exposure of ['kernel-only', 'disabled'] as const) {
    const verdict = decide(input({ view: { exposure, risk: 'read', taints: false, quarantine: false } }))
    assert.equal(verdict.decision, 'deny', `${exposure} must be denied`)
  }
})

test('manifest deny wins over agent exposure', () => {
  // A tool being generally available to agents says nothing about THIS agent.
  const verdict = decide(input({ manifestAllows: false }))
  assert.equal(verdict.decision, 'deny')
  assert.match(verdict.reason, /not in agent researcher's manifest \(default deny\)/)
})

test('irreversible needs a human even when allowed and clean', () => {
  // Nothing downgrades this: the agent is permitted, the run is clean, the
  // manifest lists the tool, and it still stops for a person.
  const verdict = decide(
    input({
      view: { exposure: 'agent', risk: 'irreversible', taints: false, quarantine: false },
      toolRef: 'github.merge_pull_request',
    }),
  )
  assert.equal(verdict.decision, 'needs-human')
  assert.match(verdict.reason, /irreversible and always needs a human/)
})

test('tainted run cannot use a write tool without a human; read is allowed', () => {
  const tainted = { runId: 'run-1', agentId: 'researcher', taint: 'tainted' } as const

  const write = decide(
    input({ scope: tainted, view: { exposure: 'agent', risk: 'write', taints: false, quarantine: false } }),
  )
  assert.equal(write.decision, 'needs-human')
  assert.match(write.reason, /tainted/)

  // Reading is how a tainted run does anything useful at all, so it proceeds.
  const read = decide(
    input({ scope: tainted, view: { exposure: 'agent', risk: 'read', taints: false, quarantine: false } }),
  )
  assert.equal(read.decision, 'allow')

  // Irreversible stays irreversible; taint does not change which rule fires
  // first, only that more things need a human.
  const irreversible = decide(
    input({ scope: tainted, view: { exposure: 'agent', risk: 'irreversible', taints: false, quarantine: false } }),
  )
  assert.equal(irreversible.decision, 'needs-human')
})

test('quarantine flag yields quarantine', () => {
  const verdict = decide(
    input({ view: { exposure: 'agent', risk: 'read', taints: false, quarantine: true } }),
  )
  assert.equal(verdict.decision, 'quarantine')
  assert.match(verdict.reason, /quarantined/)
})

test('args pointing at souls or AGENTS.md are denied protected-path', () => {
  // Invariant 8: personas are read-only to agents, and the gate refuses
  // before the call rather than trusting a later filesystem check.
  const cases = [
    { path: 'souls/ceo.md' },
    { path: '/home/op/aos/souls/researcher.md' },
    { path: 'agents/ceo/AGENTS.md' },
    { file: './AGENTS.md' },
    { nested: { deep: ['notes.txt', 'souls/writer.md'] } },
    { path: 'SOULS/CEO.MD' },
  ]
  for (const args of cases) {
    const verdict = decide(input({ args, toolRef: 'fs.write' }))
    assert.equal(verdict.decision, 'deny', `${JSON.stringify(args)} must be denied`)
    assert.match(verdict.reason, /protected-path/)
  }

  // Innocent lookalikes are not denied: the rule is about paths, not words.
  assert.equal(decide(input({ args: { note: 'my soul is weary' } })).decision, 'allow')
  assert.equal(decide(input({ args: { path: 'docs/agents-guide.md' } })).decision, 'allow')
  assert.equal(mentionsProtectedPath({ a: { b: 'souls/x.md' } }), true)
  assert.equal(mentionsProtectedPath({ a: 1, b: null, c: [2, 'ok'] }), false)
})

test('gate input is strict and rejects a modelDecision field', () => {
  // The headline: a model that persuades kernel code to pass an extra field
  // gains nothing, because the input schema refuses it outright rather than
  // ignoring it. An ignored field is one refactor away from being read.
  assert.throws(
    () => decide({ ...input(), modelDecision: 'allow' } as unknown as GateInput),
    /unrecognized|unknown/i,
  )
  assert.throws(
    () => decide({ ...input(), allow: true } as unknown as GateInput),
    /unrecognized|unknown/i,
  )
  // The nested objects are strict too, so the smuggling cannot move one level
  // down.
  assert.throws(
    () =>
      decide({
        ...input(),
        scope: { runId: 'r', agentId: 'a', taint: 'clean', override: true },
      } as unknown as GateInput),
    /unrecognized|unknown/i,
  )
  assert.throws(
    () =>
      decide({
        ...input(),
        view: { exposure: 'agent', risk: 'read', taints: false, quarantine: false, bypass: true },
      } as unknown as GateInput),
    /unrecognized|unknown/i,
  )
  // Nor can taint be spelled into something the enum does not know.
  assert.throws(
    () => decide(input({ scope: { runId: 'r', agentId: 'a', taint: 'mostly-clean' } as never })),
  )
})

test('decide is pure (same frozen input twice → same output)', () => {
  // Purity is what makes a logged decision auditable: replaying it must give
  // the same answer, and calling it must not change anything.
  const frozen = Object.freeze({
    ...input({ view: { exposure: 'agent', risk: 'write', taints: false, quarantine: false } }),
    args: Object.freeze({ query: 'goals' }),
  }) as GateInput

  const first = decide(frozen)
  const second = decide(frozen)
  assert.deepEqual(first, second)
  assert.equal(first.decision, 'allow')

  // The input is untouched: no normalisation written back, no memo stashed.
  assert.deepEqual(frozen.args, { query: 'goals' })
  assert.equal(frozen.manifestAllows, true)
})

test('HumanActor cannot be forged by an object literal or a structural clone (brand check)', () => {
  const real = mintHumanActor('conn-1')
  assert.equal(HumanActor.is(real), true)
  assert.equal(real.connectionId, 'conn-1')
  assertHumanActor(real, 'approve')

  // Everything a model could talk kernel code into constructing.
  const forgeries: unknown[] = [
    { kind: 'human', connectionId: 'conn-1' },
    { connectionId: 'conn-1', brand: true },
    { ...real },
    JSON.parse(JSON.stringify(real)),
    structuredClone({ connectionId: 'conn-1' }),
    Object.create(HumanActor.prototype) as unknown,
    Object.assign(Object.create(HumanActor.prototype) as object, { connectionId: 'conn-1' }),
    null,
    undefined,
    'human',
  ]
  for (const forgery of forgeries) {
    assert.equal(HumanActor.is(forgery), false, `${JSON.stringify(forgery)} must not pass as human`)
    assert.throws(() => assertHumanActor(forgery, 'approve'), /requires a human/)
  }

  // The constructor itself is closed: the mint symbol is module-private.
  assert.throws(
    () => new HumanActor('conn-2', Symbol('not-the-mint')),
    /cannot be constructed directly/,
  )
})
