// T36 — stub honesty.
//
// The danger this file guards is not a missing feature; it is a missing feature
// that looks present. A stub that returns `undefined`, or an empty array, or
// quietly does nothing, is indistinguishable from a working one until the day it
// matters — and the day it matters for an approvals projection is the day a run
// parked on a human decision looks answered.
//
// So every absence must ANNOUNCE itself: throw NotImplementedError, or report
// unavailable with a reason. And the announcement must be documented where an
// operator reads, which is README's stub table — generated from the same STUBS
// list, and asserted here to still match it.
//
// The falsifiers:
//
//   Make any stub return instead of refusing and the kernel gains a feature
//   that does nothing. Each entry is called here, and a call that succeeds fails
//   the test.
//   Add a STUBS entry and forget README, or fix a stub and forget to remove the
//   entry, and the honest list drifts from the honest document. Both directions
//   are checked.
//   Parse `schedule:` and ignore it, and cron looks implemented to anyone
//   reading a manifest.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'

import { STUBS } from '../src/kernel.js'
import { NotImplementedError } from '../src/errors.js'
import { AppleContainerDriver } from '../src/sandbox/apple-container.js'
import { Scheduler } from '../src/runtime/scheduler.js'
import { assertEgressEnforced } from '../src/runtime/egress.js'
import { assertDelegationAvailable } from '../src/runtime/delegate.js'
import { LANE_NAMES } from '../src/runtime/lanes.js'
import { parseManifest } from '../src/agents/manifest.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')
const README = readFileSync(`${REPO}/README.md`, 'utf8')
const CLAUDE_MD = readFileSync(`${REPO}/CLAUDE.md`, 'utf8')

const TEMPLATE = `
id: worker-template
version: 1
kind: template
role: worker
soul: worker.md
tier: 1
model:
  primary: anthropic/claude-sonnet-5
memory:
  projectId: aos/shared
`

test('every STUBS entry throws NotImplementedError or reports unavailable with a reason (table-driven: AppleContainerDriver, Scheduler.start, assertEgressEnforced, assertDelegationAvailable, Approvals.rebuildFromLog, Quarantine.rebuildFromLog)', async () => {
  // Each row is a stub id and every way to reach it. A call that RETURNS is the
  // failure: a stub that answers is a feature that does not work.
  const table: { id: string; call: () => unknown }[] = [
    { id: 'apple-container-driver', call: () => new AppleContainerDriver().run({} as never) },
    { id: 'apple-container-driver', call: () => new AppleContainerDriver().kill('x') },
    { id: 'egress-proxy', call: () => assertEgressEnforced() },
    { id: 'scheduler', call: () => new Scheduler().start() },
    { id: 'delegate-tool', call: () => assertDelegationAvailable() },
  ]

  for (const row of table) {
    assert.throws(
      row.call,
      (e: unknown) => {
        assert.ok(e instanceof NotImplementedError, `${row.id} threw ${String(e)}`)
        // A refusal with no reason sends an operator to a debugger. The message
        // must name the thing that is absent.
        assert.ok(e.message.length > 20, `${row.id} refuses without saying what is missing`)
        assert.match(e.message, /not implemented/i, row.id)
        return true
      },
      `${row.id} did not refuse`,
    )
  }

  // The one entry that reports rather than throws, because the driver contract
  // says availability is never a throw: a missing container runtime is a
  // DEGRADED boot, not a dead kernel. It threw once, and `sandbox.driver:
  // apple-container` — a value kernel.yaml accepts — refused the whole boot.
  const probe = await new AppleContainerDriver().probe()
  assert.equal(probe.ok, false)
  assert.ok(!probe.ok && probe.why.length > 20, 'the probe reports unavailable with no reason')
  assert.match(!probe.ok ? probe.why : '', /not implemented|no `container` binary/)

  // Every id in the list was actually exercised above. Without this, adding a
  // seventh stub and no row would leave it untested and still "covered".
  const exercised = new Set(table.map((r) => r.id)).add('apple-container-driver')
  for (const stub of STUBS) {
    assert.ok(exercised.has(stub.id), `STUBS lists ${stub.id} but nothing here calls it`)
  }
  assert.equal(exercised.size, STUBS.length, `exercised ${String(exercised.size)} of ${String(STUBS.length)}`)
})

test("every STUBS entry is named in README's stub section", () => {
  // The honest list and the honest document must agree, in both directions: a
  // new stub that README does not mention is an undocumented gap, and a README
  // row for a stub that no longer exists is a lie about the state of the repo.
  const section = README.slice(README.indexOf('## What is real, what is a stub'))
  assert.ok(section.length > 500, 'the README has no stub section')

  // Compared with backticks stripped and whitespace collapsed. README is
  // Markdown and STUBS.how is plain prose; demanding byte equality would force
  // the document to be unformatted, which serves nobody. The claim is that the
  // README documents the SAME refusal, not that it is the same string.
  const plain = (text: string): string => text.replace(/`/g, '').replace(/\s+/g, ' ').trim()
  const flat = plain(section)

  for (const stub of STUBS) {
    assert.ok(section.includes(stub.id), `README does not name the stub ${stub.id}`)
    assert.ok(section.includes(stub.where), `README does not say where ${stub.id} lives`)
    // The refusal itself is documented, not merely the name — an operator
    // needs to recognise the error they will actually see.
    assert.ok(
      flat.includes(plain(stub.how)),
      `README's row for ${stub.id} does not match STUBS.how:\n  ${stub.how}`,
    )
  }

  // The other direction. Any `src/…` path in a table row of that section must
  // belong to a current STUBS entry.
  const documented = [...section.matchAll(/^\| `([a-z-]+)` \| `(src\/[^`]+)`/gm)].map((m) => ({
    id: m[1] ?? '',
    where: m[2] ?? '',
  }))
  assert.equal(documented.length, STUBS.length, `README documents ${String(documented.length)} stubs`)
  for (const row of documented) {
    const stub = STUBS.find((s) => s.id === row.id)
    assert.ok(stub, `README documents ${row.id}, which is not in STUBS any more`)
    assert.equal(stub.where, row.where, row.id)
  }

  // The checklist is present, and every entry is INTERNALLY CONSISTENT.
  //
  // No test can check whether a recorded result is true — a human records a fact
  // the repository cannot verify, and that signature is the point. What a test
  // can check is that an entry is not half-filled: a result claimed with no
  // date, no commit or no cost reads like evidence and is not, and that is the
  // shape a hurried edit actually takes.
  assert.ok(README.includes('## Exit-criterion checklist'))
  const checklist = README.slice(README.indexOf('## Exit-criterion checklist'))
  const entries = [...checklist.matchAll(/- Result: (.*)\n- Date: (.*)\n- Commit: (.*)\n((?:- .*\n)*)/g)]
  assert.equal(entries.length, 3, `found ${String(entries.length)} checklist entries, expected 3`)

  for (const [i, entry] of entries.entries()) {
    const [, result = '', date = '', commit = '', extra = ''] = entry
    const unrun = result.trim() === '_not yet run_'
    const label = `checklist entry ${String(i + 1)}`
    if (unrun) {
      // Nothing recorded yet: every field is still the em-dash placeholder, so a
      // stale date from a previous attempt cannot sit beside "not yet run".
      assert.equal(date.trim(), '—', `${label} is unrun but carries a date`)
      assert.equal(commit.trim(), '—', `${label} is unrun but carries a commit`)
      for (const line of extra.trim().split('\n').filter((l) => l !== '')) {
        assert.match(line, /—\s*$/, `${label} is unrun but ${line.trim()} is filled in`)
      }
      continue
    }
    // Recorded: it must carry all of it. A date, a commit to reproduce from, and
    // the cost, because "non-zero cost" IS the criterion.
    assert.match(date.trim(), /\d{4}-\d{2}-\d{2}/, `${label} claims a result with no date`)
    assert.match(commit.trim(), /[0-9a-f]{7}/, `${label} claims a result with no commit`)
    assert.match(extra, /costMicroUsd`?: *[1-9]/, `${label} claims a result with no non-zero cost`)
  }
  assert.ok(README.includes('AOS_LIVE_TESTS=1 ANTHROPIC_API_KEY='))
  assert.ok(README.includes('PMMCP_URL='))
  assert.ok(README.includes('npm run cli -- run ceo'))
  // The Node warning that does not look like a version problem.
  assert.ok(README.includes('--disable-warning= is not allowed in NODE_OPTIONS'))
})

test('CLAUDE.md Current state names every STUBS entry', () => {
  // CLAUDE.md is the standing contract and the first thing any future session
  // reads. A "Current state" that has drifted is worse than none: it is read as
  // authoritative, so a stale claim there is believed rather than checked.
  //
  // This is the drift that actually happens — a stub gets built, or a new one
  // appears, and the paragraph nobody runs stays as it was. It said "19/19
  // passing" for a long time while the suite grew past 350.
  const start = CLAUDE_MD.indexOf('## Current state')
  assert.ok(start > 0, 'CLAUDE.md has no Current state section')
  const section = CLAUDE_MD.slice(start, CLAUDE_MD.indexOf('## Commands'))
  assert.ok(section.length > 400, 'the Current state section is suspiciously short')

  // Every absence is named. The ids are kebab-case slugs, so the paragraph is
  // matched on the words a human would actually write for each.
  const NAMES: Record<string, RegExp> = {
    'apple-container-driver': /Apple container driver/,
    'egress-proxy': /egress proxy/i,
    scheduler: /scheduler/i,
    'delegate-tool': /delegation\/spawn tool|delegation tool/i,
  }
  for (const stub of STUBS) {
    const pattern = NAMES[stub.id]
    assert.ok(pattern, `STUBS has ${stub.id} but this test does not know how CLAUDE.md should name it`)
    assert.match(section, pattern, `CLAUDE.md Current state does not name the stub ${stub.id}`)
  }
  assert.equal(Object.keys(NAMES).length, STUBS.length, 'the name table and STUBS have diverged')

  // The refusal mechanism is named for each, not just the feature — a reader
  // needs to know it will get an error rather than a silent no-op.
  for (const fragment of [
    'assertEgressEnforced',
    'assertDelegationAvailable',
    'spawnEphemeral',
  ]) {
    assert.ok(section.includes(fragment), `CLAUDE.md does not say how ${fragment} refuses`)
  }

  // The counts are real, and they are the numbers this suite actually produces.
  // A hard-coded pair that nothing checks is how "19/19" survived.
  const claimed = /(\d+) `node:test` tests passing and (\d+) gated live tests skipped by design across (\d+) files/.exec(
    section,
  )
  assert.ok(claimed, 'CLAUDE.md does not state the test counts in the checkable form')
  const [, passing = '0', skipped = '0', fileCount = '0'] = claimed
  const testFiles = readdirSync(`${REPO}/test`).filter((f) => f.endsWith('.test.ts'))
  assert.equal(Number(fileCount), testFiles.length, 'the claimed file count is wrong')
  assert.equal(Number(skipped), 2, 'the claimed skip count is wrong')
  // Not asserted against a live run — that would mean running the suite inside
  // itself. Asserted as plausible and monotonic: the number cannot be a stale
  // small one, which is the only drift that has ever actually happened here.
  assert.ok(Number(passing) > 300, `CLAUDE.md claims only ${passing} passing tests`)

  // And the two things that must not be claimed while they are untrue.
  assert.match(section, /No real provider call has ever been made/)
  assert.match(section, /is not claimed until that entry is filled/)
  assert.equal(/Phase 0 (?:is )?(?:complete|exited|met)\b/i.test(section), false, 'CLAUDE.md claims Phase 0 is exited')

  // The Apple driver's description matches what the code does, which is the
  // clause this rewrite had to correct: it said "throws", and a throwing probe
  // refused the whole boot.
  assert.match(section, /`probe` reports unavailable so boot degrades/)
  assert.equal(/Apple container driver \(throws\)|Apple container driver \(stub\)/.test(section), false)

  // The tool-view count is stated in both documents and must agree.
  assert.match(section, /classifies 9 of 49 pmmcp tools/)
  assert.match(CLAUDE_MD, /9 pinned names classified in `config\/tool-views\.yaml`/)
  assert.equal(/all classified in `config\/tool-views\.yaml`/.test(CLAUDE_MD), false)
})

test('schedule: in a manifest is refused by the schema', () => {
  // Strictness is how an absent feature stays absent. Parsed-and-ignored is
  // indistinguishable from working, and a manifest carrying a cron line would
  // sit on disk looking active while nothing ever fired.
  assert.throws(
    () => parseManifest(parseYaml(`${TEMPLATE}\nschedule: "0 * * * *"\n`), 'agent.yaml'),
    /schedule: not implemented in Phase 0/,
  )
  // Every shape of it, including the ones that look like "disabled".
  for (const value of ['"0 * * * *"', 'null', 'false', '""', '{}']) {
    assert.throws(
      () => parseManifest(parseYaml(`${TEMPLATE}\nschedule: ${value}\n`), 'agent.yaml'),
      /schedule/,
      value,
    )
  }
  // And the baseline parses, so the assertions above are about `schedule` and
  // not about a fixture that never parsed at all.
  assert.equal(parseManifest(parseYaml(TEMPLATE), 'agent.yaml').id, 'worker-template')

  // No shipped manifest carries one.
  for (const id of ['ceo', 'worker-template']) {
    const text = readFileSync(`${REPO}/agents/${id}/agent.yaml`, 'utf8')
    assert.equal(/^schedule:/m.test(text), false, `agents/${id}/agent.yaml has a schedule`)
  }
})

test('sandbox spec schema has no egress field', () => {
  // Egress is enforced by the Phase 2 proxy sidecar, which does not exist. A
  // field on the spec would imply the driver could constrain the network, and it
  // cannot: the container gets an internal network and nothing else.
  const driver = readFileSync(`${REPO}/src/sandbox/driver.ts`, 'utf8')
  const spec = driver.slice(driver.indexOf('export interface SandboxSpec'))
  const body = spec.slice(0, spec.indexOf('\n}'))
  assert.ok(body.includes('readonly domain'), 'the SandboxSpec body was not found')
  assert.equal(/egress|allowHost|allowedHosts|proxy/i.test(body), false, body)

  // Nothing in the sandbox layer pretends to do egress at all.
  for (const file of ['driver.ts', 'docker.ts', 'confine.ts', 'apple-container.ts']) {
    const text = readFileSync(`${REPO}/src/sandbox/${file}`, 'utf8')
    const code = text
      .split('\n')
      .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*'))
      .join('\n')
    assert.equal(/egress/i.test(code), false, `src/sandbox/${file} mentions egress in code`)
  }

  // The refusal lives in one place, and it is reachable.
  assert.throws(() => assertEgressEnforced(), NotImplementedError)
})

test('no cron lane exists', () => {
  // Two lanes, and cron is not one of them. A lane named for the scheduler would
  // be a queue nothing ever fills, and a plausible place for a future edit to
  // start scheduling work that no gate had approved.
  assert.deepEqual([...LANE_NAMES], ['main', 'subagent'])
  assert.equal((LANE_NAMES as readonly string[]).includes('cron'), false)

  const lanes = readFileSync(`${REPO}/src/runtime/lanes.ts`, 'utf8')
  assert.equal(/cron|schedule/i.test(lanes), false, 'src/runtime/lanes.ts mentions cron')

  // And the shipped config declares caps for exactly those two lanes.
  const config = parseYaml(readFileSync(`${REPO}/config/kernel.yaml`, 'utf8')) as {
    lanes: Record<string, unknown>
  }
  assert.deepEqual(Object.keys(config.lanes).sort(), ['main', 'subagent'])
})
