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
import { assertEgressEnforced } from '../src/runtime/egress.js'
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

test('every STUBS entry throws NotImplementedError or reports unavailable with a reason (table-driven: AppleContainerDriver, assertEgressEnforced)', async () => {
  // Each row is a stub id and every way to reach it. A call that RETURNS is the
  // failure: a stub that answers is a feature that does not work.
  const table: { id: string; call: () => unknown }[] = [
    { id: 'apple-container-driver', call: () => new AppleContainerDriver().run({} as never) },
    { id: 'apple-container-driver', call: () => new AppleContainerDriver().kill('x') },
    { id: 'egress-proxy', call: () => assertEgressEnforced() },
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
  // To the next heading only: the Phase 1 record below has the same shape.
  const checklistStart = README.indexOf('## Exit-criterion checklist')
  const checklistEnd = README.indexOf('\n## ', checklistStart + 1)
  const checklist = README.slice(checklistStart, checklistEnd === -1 ? undefined : checklistEnd)
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
  assert.ok(README.includes('AOS_LIVE_TESTS=1 npm test'))
  // The key comes from .env or an export, never typed into a command line,
  // where zsh writes it to ~/.zsh_history.
  assert.equal(/ANTHROPIC_API_KEY=\S*\s+npm\b/.test(README), false, 'README puts a key on a command line')
  assert.ok(README.includes('AOS_LIVE_PMMCP_URL='))
  // And no command README gives sets a PMMCP_ name (D34): that prefix is pmmcp's
  // own, which its load_config reads as settings.
  assert.doesNotMatch(README, /(?<![A-Z0-9_])PMMCP_[A-Z0-9_]*=/, 'README gives a command that sets a PMMCP_ name')
  assert.ok(README.includes('npm run cli -- run ceo'))
  // The Node warning that does not look like a version problem.
  assert.ok(README.includes('--disable-warning= is not allowed in NODE_OPTIONS'))
})

/**
 * Every name `source` reads from process.env by spelling: `process.env['X']`
 * (any quote, optional chaining), `process.env.X`, and `{ X } = process.env`.
 */
function envReads(source: string): string[] {
  const names: string[] = []
  for (const m of source.matchAll(/process\.env\s*(?:(?:\?\.)?\s*\[\s*(['"`])([^'"`]*)\1\s*\]|(?:\?\.|\.)\s*([A-Za-z_$][\w$]*))/g)) {
    names.push(m[2] ?? m[3] ?? '')
  }
  for (const m of source.matchAll(/\{([^{}]*)\}\s*=\s*process\.env\b/g)) {
    for (const part of (m[1] ?? '').split(',')) {
      const name = (part.split(':')[0] ?? '').trim()
      if (name !== '') names.push(name)
    }
  }
  return names
}

test("the live tests read pmmcp's URL as AOS_LIVE_PMMCP_URL, the name README's commands set, and no file reads a PMMCP_ name from its environment (D34)", () => {
  // A gated run's skips read as "by design". A live file that went back to the
  // old name would skip every pmmcp-connected test on the Mac, where README's
  // commands set only the new one, with a skip reason naming a variable that is
  // set, and the README checklist could record a pass that never ran.
  const LIVE_FILES = ['live-anthropic.test.ts', 'live-runtime.test.ts']
  const gated = readdirSync(`${REPO}/test`).filter((f) => /^live-.*\.test\.ts$/.test(f)).sort()
  assert.deepEqual(gated, LIVE_FILES, 'a live file was added or renamed: say here which pmmcp URL it reads')
  const blocks = [...README.matchAll(/^```(?:bash|sh|zsh|shell)\n([\s\S]*?)^```/gm)].map((m) => m[1] ?? '')
  const liveCommands = blocks.filter((b) => /(?:^|\s)AOS_LIVE_TESTS=1\s/.test(b))
  assert.ok(liveCommands.length >= 3, `README gives ${String(liveCommands.length)} live-test commands`)
  const set = (block: string): string[] => [...block.matchAll(/(?:^|\s)([A-Z][A-Z0-9_]*)=/g)].map((m) => m[1] ?? '')

  const readByLive = new Set<string>()
  for (const file of LIVE_FILES) {
    const source = readFileSync(`${REPO}/test/${file}`, 'utf8')
    const reads = envReads(source)
    for (const name of reads) readByLive.add(name)
    // The URL it dials is read under one name, the new one, at every read.
    const urls = [...new Set(reads.filter((n) => /pmmcp/i.test(n) && /url/i.test(n)))].sort()
    assert.deepEqual(urls, ['AOS_LIVE_PMMCP_URL'], `${file} reads pmmcp's URL as ${urls.join(', ')}`)
    // Each variable a skip reason tells the operator to set is one the file reads.
    for (const m of source.matchAll(/'set ([A-Z][A-Z0-9_]*)/g)) {
      assert.ok(reads.includes(m[1] ?? ''), `${file} says "set ${m[1] ?? ''}" and never reads it`)
    }
    // README runs the file, with the URL set on the same command.
    const runs = liveCommands.filter((b) => b.includes(`test/${file}`) || /\bnpm test\b/.test(b))
    assert.ok(
      runs.some((b) => set(b).includes('AOS_LIVE_PMMCP_URL')),
      `no README command runs ${file} with AOS_LIVE_PMMCP_URL set`,
    )
  }
  // And every name a README live command sets is one a live file reads: a
  // name README sets that nothing reads is a rename done on one side only.
  for (const block of liveCommands) {
    for (const name of set(block)) assert.ok(readByLive.has(name), `README sets ${name} for a live run and no live file reads it`)
  }

  // No AOS file reads a PMMCP_ name, in any case (pmmcp reads its prefix
  // without regard to case): that prefix is pmmcp's own (D34).
  const sources = ['src', 'scripts', 'test'].flatMap((dir) =>
    readdirSync(`${REPO}/${dir}`, { recursive: true, encoding: 'utf8' })
      .filter((f) => f.endsWith('.ts'))
      .map((f) => `${dir}/${f}`),
  )
  assert.ok(sources.length > 100, `only ${String(sources.length)} sources found`)
  for (const file of sources) {
    for (const name of envReads(readFileSync(`${REPO}/${file}`, 'utf8'))) {
      assert.doesNotMatch(name, /^pmmcp_/i, `${file} reads ${name} from its environment`)
    }
  }
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
  }
  for (const stub of STUBS) {
    const pattern = NAMES[stub.id]
    assert.ok(pattern, `STUBS has ${stub.id} but this test does not know how CLAUDE.md should name it`)
    assert.match(section, pattern, `CLAUDE.md Current state does not name the stub ${stub.id}`)
  }
  assert.equal(Object.keys(NAMES).length, STUBS.length, 'the name table and STUBS have diverged')

  // The refusal mechanism is named for each, not just the feature — a reader
  // needs to know it will get an error rather than a silent no-op.
  // Delegation left this list when it was built; ephemeral spawning stays named
  // because it is still registry-only, and a reader must not infer from
  // "delegation exists" that an agent can mint a new one.
  for (const fragment of [
    'assertEgressEnforced',
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
  // Derived from the gated files rather than written down as a literal: every
  // test in a `test/live-*.test.ts` file skips in a default run, so that count IS
  // the number this sentence must claim. A literal here went stale the moment a
  // second live file appeared, which is the drift this test exists to catch.
  const gated = readdirSync(`${REPO}/test`)
    .filter((f) => /^live-.*\.test\.ts$/.test(f))
    .reduce((n, f) => n + (readFileSync(`${REPO}/test/${f}`, 'utf8').match(/\bskip\s*:/g) ?? []).length, 0)
  assert.ok(gated >= 2, 'the gated live files hold fewer tests than they did in Phase 0')
  assert.equal(Number(skipped), gated, 'the claimed skip count is not the number of gated live tests')
  // Not asserted against a live run — that would mean running the suite inside
  // itself. Asserted as plausible and monotonic: the number cannot be a stale
  // small one, which is the only drift that has ever actually happened here.
  assert.ok(Number(passing) > 300, `CLAUDE.md claims only ${passing} passing tests`)

  // And the claims tied to README's exit-criterion record, in both directions.
  // While line 2 or 3 is unrun, Phase 0 must not be claimed and no real provider
  // call may be. Once both are recorded the contract must say so, because a
  // CLAUDE.md that trails the record is read as authoritative too.
  const sectionOf = (heading: string): string => {
    const start = README.indexOf(heading)
    assert.notEqual(start, -1, `README has no ${heading}`)
    const end = README.indexOf('\n## ', start + heading.length)
    return README.slice(start, end === -1 ? undefined : end)
  }
  const record = sectionOf('## Exit-criterion checklist')
  const results = [...record.matchAll(/- Result: (.*)\n/g)].map((m) => (m[1] ?? '').trim())
  assert.equal(results.length, 3, 'README has no three-line exit-criterion record')
  const exited = results[1] !== '_not yet run_' && results[2] !== '_not yet run_'
  if (exited) {
    assert.match(section, /Phase 0 exited on \d{4}-\d{2}-\d{2}/, 'README records the exit; CLAUDE.md does not say so')
    assert.equal(/No real provider call has ever been made/.test(section), false, 'CLAUDE.md denies the recorded run')
    assert.equal(/is not claimed until that entry is filled/.test(section), false, 'CLAUDE.md still waits on a filled entry')
  } else {
    assert.match(section, /No real provider call has ever been made/)
    assert.match(section, /is not claimed until that entry is filled/)
    assert.equal(/Phase 0 (?:is )?(?:complete|exited|met)\b/i.test(section), false, 'CLAUDE.md claims Phase 0 is exited')
  }

  // Phase 1 the same way: exited only once lines 1 and 2 of its record pass,
  // and then the contract must say so.
  const phaseOne = [...sectionOf('## Phase 1 exit-criterion checklist').matchAll(/- Result: (.*)\n/g)].map((m) => (m[1] ?? '').trim())
  assert.equal(phaseOne.length, 3, 'README has no three-line Phase 1 exit record')
  // Not half-filled, as for Phase 0: a recorded line carries a date and a
  // commit, lines 1 and 2 their logged cost, and an unrun line carries nothing.
  const phaseOneEntries = [
    ...sectionOf('## Phase 1 exit-criterion checklist').matchAll(/- Result: (.*)\n- Date:(.*)\n- Commit:(.*)\n((?:- .*\n)*)/g),
  ]
  assert.equal(phaseOneEntries.length, 3, 'a Phase 1 record line lacks its Date or Commit field')
  for (const [i, [, result = '', date = '', commit = '', extra = '']] of phaseOneEntries.entries()) {
    const label = `Phase 1 record line ${String(i + 1)}`
    if (result.trim() === '_not yet run_') {
      assert.equal(`${date}${commit}`.trim(), '', `${label} is unrun but carries a date or commit`)
      for (const line of extra.trim().split('\n').filter((l) => l !== '')) {
        assert.match(line, /:\s*$/, `${label} is unrun but ${line.trim()} is filled in`)
      }
      continue
    }
    assert.match(date.trim(), /^\d{4}-\d{2}-\d{2}\b/, `${label} claims a result with no date`)
    assert.match(commit.trim(), /^[0-9a-f]{7,40}$/, `${label} claims a result with no commit`)
    if (i < 2) assert.match(extra, /costMicroUsd`?: *[1-9]/, `${label} claims a result with no non-zero cost`)
  }
  const phaseOneExited = phaseOne.slice(0, 2).every((r) => r.startsWith('pass'))
  if (phaseOneExited) {
    assert.match(section, /Phase 1 exited on \d{4}-\d{2}-\d{2}/, 'README records the Phase 1 exit; CLAUDE.md does not say so')
    // And the sentences that contradict it are gone.
    assert.equal(/runtime checks have not run/.test(section), false, 'CLAUDE.md still says the runtime checks have not run')
    assert.equal(/Phase 1 mostly built/.test(section), false, 'CLAUDE.md still calls Phase 1 mostly built')
  } else {
    assert.equal(
      /Phase 1(?:'s exit(?: criterion)?)? (?:is |has )?(?:complete|exited|met|passed)\b/i.test(section),
      false,
      'CLAUDE.md claims Phase 1 is exited before README records it',
    )
  }

  // The Apple driver's description matches what the code does, which is the
  // clause this rewrite had to correct: it said "throws", and a throwing probe
  // refused the whole boot.
  assert.match(section, /`probe` reports unavailable so boot degrades/)
  assert.equal(/Apple container driver \(throws\)|Apple container driver \(stub\)/.test(section), false)

  // The tool-view count is stated in both documents and must agree.
  assert.match(section, /pins 19 pmmcp tools closed/)
  assert.match(section, /exposes none/)
  assert.match(CLAUDE_MD, /19 pinned closed in `config\/tool-views\.yaml`, none exposed/)
  assert.equal(/all classified in `config\/tool-views\.yaml`/.test(CLAUDE_MD), false)
})

test('a manifest schedule must be a cron expression the scheduler can run', () => {
  // Strictness is how an absent feature stays absent. Parsed-and-ignored is
  // indistinguishable from working, and a manifest carrying a cron line would
  // sit on disk looking active while nothing ever fired.
  // A valid expression is now ACCEPTED and run — the scheduler exists.
  assert.equal(
    parseManifest(parseYaml(`${TEMPLATE}\nschedule: "0 * * * *"\n`), 'agent.yaml').schedule,
    '0 * * * *',
  )
  // What must still be refused is anything the scheduler cannot actually run,
  // and every shape that looks like "disabled" — a field the schema tolerates but
  // the scheduler ignores is the failure this test exists for.
  for (const value of ['"0 9 * * MON-FRI"', '"@daily"', '"* * * *"', 'null', 'false', '""', '{}', '5']) {
    assert.throws(
      () => parseManifest(parseYaml(`${TEMPLATE}\nschedule: ${value}\n`), 'agent.yaml'),
      /is invalid/,
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
