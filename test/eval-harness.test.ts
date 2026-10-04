// The harness end to end, against a real kernel.
//
// eval-checks.test.ts scores synthetic logs, which proves the scorers and nothing
// about what the kernel actually writes. This file runs cases through a real
// boot — the pmmcp double for the hub and vault, a scripted provider for the
// model, the real gate, the real budget, the real event log — and then scores the
// log the kernel produced.
//
// That is where the harness's assumptions get tested rather than asserted: that
// run.finished's cost is the sum of the logged calls, that every response has a
// request before it, that a run's slice is reachable read-only while the daemon
// still holds the database. Each of those is a claim about the kernel that only a
// real run can settle.
//
// It also records the CURRENT BASELINE honestly: a case demanding two child runs
// fails, because delegation is a stub. That failure is the deliverable, not a
// defect in the test.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import test from 'node:test'

import { CEO_CHECKS } from '../src/eval/checks.js'
import { runCase, startAndWait, type EvalTarget } from '../src/eval/harness.js'
import { observe, readRunRows, readWholeLog } from '../src/eval/observe.js'
import { renderCase, exitCode } from '../src/eval/report.js'
import { summarise } from '../src/eval/harness.js'
import { CEO_SUITE } from '../src/eval/suite.js'
import type { EvalCase } from '../src/eval/types.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { anthropicEndTurn, fakeProvider, type ScriptedResponse } from './helpers/fake-provider.js'
import { TEST_TOKEN, withKernel } from './helpers/kernel.js'
import { pmmcpMock } from './helpers/mock-pmmcp.js'
import { freshProbe } from './helpers/probe.js'

const REAL_REF = 'anthropic/claude-sonnet-5'
const VAULT_ID = 'anthropic-api-key'

/** A kernel with pmmcp connected, a vault credential and a scripted provider. */
async function kernelWith(
  t: Parameters<typeof withKernel>[0],
  script: readonly ScriptedResponse[],
): Promise<{ target: EvalTarget; provider: ReturnType<typeof fakeProvider> }> {
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider(script)
  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-eval' },
    fetch: provider.fetch,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })
  assert.equal(
    kernel.status().subsystems.router.state,
    'ok',
    kernel.status().subsystems.router.reason ?? '',
  )
  return {
    target: { port: kernel.port, token: TEST_TOKEN, dbPath: fx.dbPath, timeoutMs: 20_000 },
    provider,
  }
}

const smallCase: EvalCase = {
  id: 'e2e-small',
  title: 'a one-turn objective',
  agentId: 'ceo',
  input: 'State one risk in a single sentence.',
  expect: { maxCostMicroUsd: 1_000_000, maxLlmCalls: 4, status: ['ok'] },
}

test('a real run scores clean, and the harness reads it from the log', async (t) => {
  const { target, provider } = await kernelWith(t, [
    anthropicEndTurn({ text: 'A shared vault is the single point of compromise.', inputTokens: 900, outputTokens: 60 }),
  ])

  const result = await runCase(target, smallCase, CEO_CHECKS)
  assert.deepEqual(
    result.gatesFailed,
    [],
    renderCase(result),
  )

  // The assumptions the scorers are built on, settled against a real log rather
  // than asserted in a comment.
  const byId = new Map(result.checks.map((c) => [c.id, c]))
  assert.equal(byId.get('cost-reconciles-with-log')?.verdict, 'pass', 'run.finished cost is not the sum of the logged calls')
  assert.equal(byId.get('llm-events-paired')?.verdict, 'pass')
  assert.equal(byId.get('status-as-expected')?.verdict, 'pass')
  assert.equal(byId.get('run-reached-terminal')?.verdict, 'pass')

  // And it really came from the log: the model's text is the claims field.
  const rows = readRunRows(target.dbPath, result.runId)
  const observation = observe({ runId: result.runId, agentId: 'ceo', rows, expect: {} })
  assert.match(observation.claims, /single point of compromise/)
  assert.equal(provider.requests.length, 1)
})

test('CHEAT on a real run: a fabricated summary is caught by the log, not by reading it', async (t) => {
  // The provider is scripted to do what a plausible cheating model does: report
  // delegation that never happened, with kernel-shaped ids. Nothing else about
  // the run is unusual — the gate, the budget and the events are all real — so
  // the only thing that catches this is resolving the ids against what the kernel
  // minted.
  const { target } = await kernelWith(t, [
    anthropicEndTurn({
      text:
        'Objective complete. Delegated to run_1700000000_c0ffee and run_1700000000_facade; ' +
        'both returned successfully and I have merged their findings.',
      inputTokens: 900,
      outputTokens: 80,
    }),
  ])

  const result = await runCase(target, smallCase, CEO_CHECKS)
  assert.deepEqual(result.gatesFailed, ['evidence-refs-resolve'])
  const detail = result.checks.find((c) => c.id === 'evidence-refs-resolve')?.detail ?? ''
  assert.match(detail, /run_1700000000_c0ffee/)
  assert.match(detail, /never minted/)
  assert.equal(exitCode(summarise([result])), 1)
})

test('a CEO that answers the fan-out case alone fails it, and the harness says it never tried', async (t) => {
  // The no-spawn cheat, through the real kernel. The CEO has kernel.delegate now,
  // so answering an objective alone is the model's choice, and the harness must
  // report it as a failed gate that says no delegation was attempted — not pass
  // it on the strength of a plausible answer.
  const { target } = await kernelWith(t, [
    anthropicEndTurn({ text: 'Here is my comparison of both options.', inputTokens: 900, outputTokens: 120 }),
  ])

  const fanout = CEO_SUITE.find((c) => c.id === 'ceo-objective-fanout')
  assert.ok(fanout, 'the shipped suite has no fan-out case')
  const result = await runCase(target, fanout, CEO_CHECKS)

  assert.deepEqual(result.gatesFailed, ['child-runs'])
  const detail = result.checks.find((c) => c.id === 'child-runs')?.detail ?? ''
  assert.match(detail, /0 child run/)
  assert.match(detail, /No delegation was attempted/)

  // Everything else about the run is admissible, which is the point: the failure
  // is specific to the missing fan-out and not a smear across the scorecard.
  assert.equal(result.checks.filter((c) => c.verdict === 'fail').length, 1)
})

test('a run slower than the case ceiling fails by name rather than hanging', async (t) => {
  // A harness that hangs on a stuck run is a harness nobody will leave running.
  // The provider answers, but late: the wait ceiling must fire first and say which
  // case and which run it gave up on. The connect timeout is deliberately NOT the
  // same number — a short run ceiling must not make the harness unable to connect.
  const mock = pmmcpMock()
  t.after(async () => {
    await mock.close()
  })
  const provider = fakeProvider([anthropicEndTurn({ text: 'late', inputTokens: 10, outputTokens: 10 })])
  const slow: typeof provider.fetch = (...args) =>
    new Promise((resolve) => {
      setTimeout(() => resolve(provider.fetch(...args)), 750)
    })

  const { kernel, fx } = await withKernel(t, {
    clientFactory: mock.connect,
    env: { ANTHROPIC_API_KEY: 'env-fixture-credential-eval' },
    fetch: slow,
    beforeBoot: (f) => {
      writeProbeRecord(f.dataDir, freshProbe(REAL_REF))
    },
  })

  await assert.rejects(
    () =>
      startAndWait(
        { port: kernel.port, token: TEST_TOKEN, dbPath: fx.dbPath, timeoutMs: 50 },
        { ...smallCase, id: 'e2e-timeout' },
      ),
    (e: unknown) => {
      assert.match(String(e), /e2e-timeout/, 'the error must name the case')
      assert.match(String(e), /did not finish/)
      return true
    },
  )
  // The run itself is left to complete, so teardown is not racing a live run.
  await new Promise((resolve) => {
    setTimeout(resolve, 900)
  })
})

test('an unknown agent fails the case loudly instead of scoring an empty log', async (t) => {
  // The failure mode worth guarding: a typo'd agentId yields no run, no rows and
  // therefore no failing checks, which would score as a clean case.
  const { target } = await kernelWith(t, [
    anthropicEndTurn({ text: 'ok', inputTokens: 10, outputTokens: 10 }),
  ])
  await assert.rejects(
    () => runCase(target, { ...smallCase, id: 'e2e-no-agent', agentId: 'no-such-agent' }, CEO_CHECKS),
    /no active agent/,
  )
})

test('the shipped suite is well-formed: unique ids, real agents, ceilings inside D30', () => {
  // The suite is data an operator runs on their own machine and money. A case with
  // a ceiling above the kernel's own budget could not fail its budget gate, and a
  // case naming an agent that does not exist would fail for the wrong reason.
  const ids = CEO_SUITE.map((c) => c.id)
  assert.equal(new Set(ids).size, ids.length)
  for (const c of CEO_SUITE) {
    assert.ok(c.input.trim().length > 40, `${c.id} has no real objective text`)
    assert.equal(c.agentId, 'ceo')
    assert.ok((c.expect.maxCostMicroUsd ?? 0) > 0, `${c.id} sets no cost ceiling`)
    assert.ok((c.expect.maxCostMicroUsd ?? 0) <= 2_000_000, `${c.id} exceeds D30's per-run cost cap`)
  }
  // Every case must be admissible to the registry: an agent that does not exist
  // would fail for the wrong reason and read as a model failure.
  for (const c of CEO_SUITE) {
    assert.ok((c.expect.status ?? ['ok']).length > 0, `${c.id} allows no ending`)
  }
})
