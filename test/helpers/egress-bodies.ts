// The Phase 2 exit (egress plan L2), written once and run against two targets.
//
//   test/sandbox-bodies.test.ts   every `npm test`: a booted kernel over the
//                                 fake driver, each container played as the
//                                 worker image and its mux would act
//                                 (exitActor), the upstream the real
//                                 createUpstream over an in-process host
//                                 (test/helpers/fake-egress.ts).
//   test/live-egress.test.ts      gated (AOS_LIVE_TESTS=1, AOS_LIVE_DOCKER=1,
//                                 AOS_LIVE_GITHUB=1): the same kernel over
//                                 the real DockerDriver, the worker image on
//                                 the trusted VM, and GitHub, under the
//                                 fixture repository's own token.
//
// The run is one coder's, from a test-only agents dir (exitFleet: no shipped
// manifest holds a sandbox tool or egress): tier 3, on the trusted domain,
// binding kernel.yaml's github-git and github-api, as the plan's L2 note
// says (sandbox.publish is irreversible, which only tier 3 may hold). Its
// model is scripted (test/helpers/fake-provider.ts), so the run spends
// nothing and takes exactly the exit's steps; every step is still a tool
// call through the gate, an approval on the control plane wherever the gate
// asks a human for one (the test's, in a person's place: the plan's
// Operator decisions entry on the exit's live run), a container, and the
// kernel's egress engine.
//
// The steps (exitScript): a direct connect to 192.168.5.2 and two git
// requests for 192.168.5.2 and host.lima.internal through the proxy, which
// must find no route and be denied; then exec clone, exec edit (a second
// test file), git add and commit, exec node --test, a look at what PID 1's
// environment and command line hold (what `docker inspect` reports as Env
// and Cmd), and the mux's and the command's own environment, and
// sandbox.publish, which pushes HEAD to aos/<runId>/<branch> and opens the
// pull request.
//
// The test approves on the control plane, as a human does, only the calls
// the exit makes, each in its turn: every request the gate makes is held to
// the next expected call, its tool and its whole preview (the publish's
// branch, title and body among them), and one that is not that call is
// denied there, before it runs, and fails the body.
//
// What the body holds the run to (phase2Exit): it finished ok; each call but
// the two git requests for the loopback exited 0 and the kernel reports it
// ok, those two it reports failed; every grant of the run was revoked at its
// container's exit (`exited`), never for a violation, a limit, a kill or an
// error; the tests passed; the publish says it pushed the branch and opened
// the pull request; every proxy.decision is the run's, every flow of each of
// its grants is a decision, every allow is for the bound repository on
// github.com or api.github.com, and the clone's and the publish's are those
// requests (a push, a pull request); the direct probe found no route (its
// stdout the one line ENETUNREACH), and each git request for the Mac's
// loopback is its grant's one decision, a deny at the policy (not-a-host)
// that was never resolved or sent; no other request was denied; and the
// binding's value, and its Basic form (built from the github-git binding's
// basicUser, as the kernel builds it), are in no row, no spec the driver was
// handed, no workspace entry's name, link's target or file's contents (a git
// object inflated), and nothing PID 1, the mux or the command holds, where
// the kernel's mask showing anything at all is a value found there, as it is
// in any row of the run (a value a container printed, which the mask kept
// from the log). The caller is told the run's workspace as soon as run.start
// names the run, so it is removed however the body ends. No failure it
// reports quotes the value or its Basic form (scrubbed): node:test prints a
// failure's message and values where the operator copies them.

import './guard.js'

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, symlinkSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { constants as zlib, deflateSync, inflateSync } from 'node:zlib'
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml'

import { connectControl } from '../../src/cli/client.js'
import { CENSOR, SecretMask } from '../../src/events/redact.js'
import type { Kernel } from '../../src/kernel.js'
import { approvalPreview } from '../../src/policy/engine.js'
import { MUX_ARGV, PUBLISH_ARGV, STREAM_WINDOW_BYTES } from '../../src/runtime/sandbox-tools.js'
import { CANARY_PREFIX } from '../../src/runtime/canary.js'
import { readSpecOnce, type SandboxDriver, type SandboxSpec } from '../../src/sandbox/driver.js'
import { canaryPlayer, FakeMux } from './fake-egress.js'
import type { FakeChannel, ScriptedExit } from './fake-sandbox.js'
import { anthropicEndTurn, anthropicToolUse, type ScriptedResponse } from './fake-provider.js'
import { EventStore } from '../../src/events/store.js'
import { REPO_ROOT, TEST_TOKEN, type KernelFixture } from './kernel.js'
import { CREDENTIAL_NAME } from './guard.js'

/** The model ref the coder runs on: the shipped Claude entry, served here by the scripted provider. */
export const EXIT_REF = 'anthropic/claude-sonnet-5'

/** The branch the publish pushes, under aos/<runId>/, and the pull request it opens. */
export const EXIT_PUBLISH = Object.freeze({
  branch: 'phase2-exit',
  title: 'Phase 2 exit: a second test of sum()',
  body: 'Opened by the gated live test test/live-egress.test.ts of aos-kernel, through sandbox.publish. Safe to close.',
})

/** The second test the run's edit adds to the fixture (README: the fixture repository). */
export const SECOND_TEST = "import test from 'node:test'\nimport assert from 'node:assert/strict'\nimport { sum } from './sum.js'\n\ntest('sum(-2, 2) is 0', () => {\n  assert.equal(sum(-2, 2), 0)\n})\n"
export const SECOND_TEST_FILE = 'sum-negative.test.js'

/** A direct connect to pmmcp as a VM reaches it: --network none has no route, and prints the code it met. */
export const DIRECT_PROBE = "require('node:net').connect(8766, '192.168.5.2').on('connect', () => { console.log('connected'); process.exit(0) }).on('error', (e) => console.log(e.code))"

/**
 * What PID 1 holds, its environment and command line (what `docker inspect`
 * reports as Env and Cmd), then the same of the probe's parent, the mux that
 * spawned it (process.ppid, marked /proc/ppid/), and the probe's own
 * environment: each one marked line of JSON. The mux spawns a command with
 * no environment of its own, so today all three environments are PID 1's;
 * a mux or a publisher that gave the command a credential would show only
 * in the last two.
 */
export const PID1_PROBE =
  "const f = require('node:fs'); const at = '/proc/' + process.ppid + '/'; " +
  "for (const [mark, p] of [['/proc/1/environ', '/proc/1/environ'], ['/proc/1/cmdline', '/proc/1/cmdline'], ['/proc/ppid/environ', at + 'environ'], ['/proc/ppid/cmdline', at + 'cmdline'], ['/proc/self/environ', '/proc/self/environ']]) " +
  "console.log('@' + mark + ' ' + JSON.stringify(f.readFileSync(p, 'utf8').split(String.fromCharCode(0)).filter(Boolean)))"

/** The exit's exec commands, in order, for the bound repository `repo` (owner/name). */
export function exitCommands(repo: string): readonly (readonly string[])[] {
  return [
    ['node', '-e', DIRECT_PROBE],
    ['git', 'ls-remote', 'http://192.168.5.2:8766/mcp'],
    ['git', 'ls-remote', 'http://host.lima.internal:8766/'],
    ['git', 'clone', '--quiet', `https://github.com/${repo}.git`, '.'],
    ['node', '-e', `require('node:fs').writeFileSync(${JSON.stringify(SECOND_TEST_FILE)}, ${JSON.stringify(SECOND_TEST)})`],
    ['git', 'add', SECOND_TEST_FILE],
    ['git', '-c', 'user.name=aos-live-test', '-c', 'user.email=aos-live-test@users.noreply.github.com', 'commit', '--quiet', '-m', 'Add a second test of sum()'],
    ['node', '--test', '--test-reporter=tap'],
    ['node', '-e', PID1_PROBE],
  ]
}

/** The scripted model's turns: each exec, the publish, then its answer. */
export function exitScript(repo: string): ScriptedResponse[] {
  return [
    ...exitCommands(repo).map((command) => anthropicToolUse({ name: 'sandbox__exec', input: { command: [...command] } })),
    anthropicToolUse({ name: 'sandbox__publish', input: { ...EXIT_PUBLISH } }),
    anthropicEndTurn({ text: 'Cloned, added a test, the tests pass, and the pull request is open.' }),
  ]
}

/** The coder's manifest: tier 3, trusted, both sandbox tools, kernel.yaml's two GitHub bindings and no other host. */
export const CODER_MANIFEST = [
  'id: coder',
  'version: 1',
  'kind: standard',
  'role: worker',
  'soul: worker.md',
  'tier: 3',
  'model:',
  `  primary: ${EXIT_REF}`,
  'tools:',
  '  allow: [sandbox.exec, sandbox.publish]',
  'sandbox:',
  '  domain: trusted',
  'egress:',
  '  bind: [github-git, github-api]',
  'memory:',
  '  projectId: aos/agent/coder',
  '',
].join('\n')

/** A test-only agents dir at `dir`: the coder, and the shipped ceo and worker-template the kernel loads beside it. */
export function exitFleet(dir: string): string {
  const files: Record<string, string> = { coder: CODER_MANIFEST }
  for (const shipped of ['ceo', 'worker-template']) files[shipped] = readFileSync(join(REPO_ROOT, 'agents', shipped, 'agent.yaml'), 'utf8')
  for (const [name, yaml] of Object.entries(files)) {
    mkdirSync(join(dir, name, 'history'), { recursive: true })
    writeFileSync(join(dir, name, 'agent.yaml'), yaml)
    writeFileSync(join(dir, name, 'AGENTS.md'), `# ${name}\n`)
  }
  return dir
}

/** The shipped kernel.yaml as written: its sandbox and egress sections are what the exit runs under. */
function shippedRaw(): { sandbox: Record<string, unknown>; egress: Record<string, unknown> } {
  return parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')) as { sandbox: Record<string, unknown>; egress: Record<string, unknown> }
}

/** The fixture's kernel.yaml with the shipped sandbox section in place of its own: the operator's sockets, mountRoots and pinned image. */
export function liveSandbox(base: string): string {
  const at = base.indexOf('\nsandbox:\n')
  assert.notEqual(at, -1, "the fixture's kernel.yaml has no sandbox section")
  return `${base.slice(0, at)}\n${stringifyYaml({ sandbox: shippedRaw().sandbox })}`
}

/** The fixture's own sandbox section, `imageId` pinned. */
export const pinnedSandbox = (imageId: string) => (base: string): string => base.replace('  image: aos-worker:test\n', `  image: aos-worker:test\n  imageId: "${imageId}"\n`)

/** `sandbox`'s kernel.yaml, then the shipped egress section enabled: its limits and its two GitHub bindings. */
export const exitKernelYaml = (sandbox: (base: string) => string) => (base: string): string =>
  `${sandbox(base)}\n${stringifyYaml({ egress: { ...shippedRaw().egress, enabled: true } })}`

/** The one repository the two bindings name, as config reads it (owner/name, read without case). */
export function boundRepo(fx: KernelFixture): string {
  const git = fx.config.egress.bindings['github-git']
  const api = fx.config.egress.bindings['github-api']
  assert.ok(git !== undefined && api !== undefined, 'kernel.yaml no longer declares github-git and github-api')
  assert.equal(git.repos.length, 1)
  assert.deepEqual(api.repos, git.repos, 'the two bindings name different repositories')
  return git.repos[0]!
}

/**
 * The Basic form of `value` the kernel sends for the github-git binding, and
 * masks: base64 of `<basicUser>:<value>` (src/kernel.ts basicValue), the
 * binding's own basicUser, x-access-token unless kernel.yaml names another.
 */
export function basicOf(fx: KernelFixture, value: string): string {
  const git = fx.config.egress.bindings['github-git']
  assert.ok(git !== undefined && git.scheme === 'Basic', 'kernel.yaml no longer declares github-git as a Basic binding')
  return Buffer.from(`${git.basicUser}:${value}`, 'utf8').toString('base64')
}

/** A driver that hands every spec on as given, keeping a copy: what the driver built each container's argv from. */
export function recording(driver: SandboxDriver): { readonly driver: SandboxDriver; readonly specs: SandboxSpec[] } {
  const specs: SandboxSpec[] = []
  return {
    specs,
    driver: {
      name: driver.name,
      probe: (signal) => driver.probe(signal),
      run: (spec) => {
        specs.push(readSpecOnce(spec))
        return driver.run(spec)
      },
      commandRefusal: (command) => driver.commandRefusal(command),
      everyRunRefusal: () => driver.everyRunRefusal(),
      kill: (name) => driver.kill(name),
      abandon: (name) => driver.abandon(name),
      sweepOrphans: (request) => driver.sweepOrphans(request),
    },
  }
}

export interface ExitInputs {
  readonly kernel: Kernel
  readonly fx: KernelFixture
  /** Every spec the kernel's driver was handed (recording). */
  readonly specs: readonly SandboxSpec[]
  /** The binding's value, looked for everywhere it must not be. */
  readonly value: string
  /** How long the run may take, approvals included. */
  readonly timeoutMs: number
  /** Told the run's workspace as soon as run.start names the run, before it has run a call, so the caller removes it however the body ends. */
  readonly made?: (workspace: string) => void
}

export interface ExitRecord {
  readonly runId: string
  readonly pullRequest: string
  readonly approvals: readonly string[]
  readonly decisions: number
}

interface Row {
  readonly seq: number
  readonly type: string
  readonly runId: string | null
  readonly payload: Record<string, unknown>
}

/** The kernel's rows, parsed, each with the run id the kernel recorded it under. */
function logged(dbPath: string): Row[] {
  const store = new EventStore(dbPath, { readOnly: true })
  try {
    return store.query().map((r) => ({ seq: r.seq, type: r.type, runId: r.runId, payload: JSON.parse(r.payload) as Record<string, unknown> }))
  } finally {
    store.close()
  }
}

/** A call the gate may ask a human about: its tool, and the arguments the human sees whole in its preview. */
export interface ExpectedApproval {
  readonly toolRef: string
  readonly args: Record<string, unknown>
}

/**
 * The calls of the exit the gate asks a human about, in order: every exec
 * after the first (which taints the run), then the publish, which is
 * irreversible, with the branch, title and body the human approves.
 */
export function exitApprovals(repo: string): readonly ExpectedApproval[] {
  return [
    ...exitCommands(repo).slice(1).map((command) => ({ toolRef: 'sandbox.exec', args: { command: [...command] } })),
    { toolRef: 'sandbox.publish', args: { ...EXIT_PUBLISH } },
  ]
}

/**
 * The run started over the control plane, and its run.finished. Each
 * approval it asks for is approved there, as a human approves one, only if it
 * is the next of `expected`: the same tool, and a preview that is exactly
 * what the gate shows of that call's arguments (approvalPreview). Any other
 * is denied there before it runs, recorded, and fails the body once the run
 * has finished. `started` is told the run's id as soon as run.start answers,
 * before anything is awaited of the run, so a body that then fails (a call
 * denied, an approval refused, the timeout) still knows the run it made.
 */
async function runApproving(
  kernel: Kernel,
  prompt: string,
  timeoutMs: number,
  expected: readonly ExpectedApproval[],
  quote: (text: string) => string,
  started: (runId: string) => void,
): Promise<{ readonly finished: Record<string, unknown>; readonly approvals: string[] }> {
  const client = await connectControl({ port: kernel.port, token: TEST_TOKEN, timeoutMs: 60_000 })
  const approvals: string[] = []
  const unexpected: string[] = []
  const failures: unknown[] = []
  let next = 0
  const stop = kernel.store.subscribe((row) => {
    if (row.type !== 'approval.requested') return
    const asked = JSON.parse(row.payload) as { approvalId: string; toolRef: string; argsPreview: string }
    const want = expected[next]
    if (want !== undefined && asked.toolRef === want.toolRef && asked.argsPreview === approvalPreview(want.args).text) {
      next++
      approvals.push(asked.toolRef)
      void client.call('approval.approve', { approvalId: asked.approvalId }).catch((e: unknown) => failures.push(e))
      return
    }
    unexpected.push(quote(`${asked.toolRef} ${asked.argsPreview}`))
    void client
      .call('approval.deny', { approvalId: asked.approvalId, reason: 'not the next call of the Phase 2 exit (test/helpers/egress-bodies.ts exitApprovals)' })
      .catch((e: unknown) => failures.push(e))
  })
  try {
    const early = new Map<string, Record<string, unknown>>()
    let mine: string | undefined
    let settle: (payload: Record<string, unknown>) => void = () => undefined
    const finished = new Promise<Record<string, unknown>>((resolve) => {
      settle = resolve
    })
    client.onEvent((event) => {
      if (event.type !== 'run.finished') return
      const payload = event.payload as Record<string, unknown> | null
      if (payload === null || typeof payload['runId'] !== 'string') return
      if (payload['runId'] === mine) settle(payload)
      else early.set(payload['runId'], payload)
    })
    const begun = (await client.call('run.start', { agentId: 'coder', input: prompt })) as { runId: string }
    mine = begun.runId
    started(begun.runId)
    const done = early.get(begun.runId)
    if (done !== undefined) settle(done)
    let timer: NodeJS.Timeout | undefined
    const late = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`run ${begun.runId} did not finish within ${String(timeoutMs)} ms`)), timeoutMs)
    })
    try {
      const payload = await Promise.race([finished, late])
      assert.equal(failures.length, 0, `an approval could not be given or refused on the control plane: ${quote(failures.map(String).join('; '))}`)
      assert.deepEqual(unexpected, [], 'the gate asked a human about a call that is not the next of the exit, which was denied')
      return { finished: payload, approvals }
    } finally {
      clearTimeout(timer)
    }
  } finally {
    stop()
    client.close()
  }
}

/** Every entry under `dir`, links not followed, each with its kind: a regular file, a symbolic link, a directory, or anything else. */
function entriesUnder(dir: string): { readonly path: string; readonly kind: 'file' | 'link' | 'directory' | 'other' }[] {
  const out: { readonly path: string; readonly kind: 'file' | 'link' | 'directory' | 'other' }[] = []
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    const stat = lstatSync(path)
    out.push({ path, kind: stat.isFile() ? 'file' : stat.isSymbolicLink() ? 'link' : stat.isDirectory() ? 'directory' : 'other' })
    if (stat.isDirectory()) out.push(...entriesUnder(path))
  }
  return out
}

/** The most of a pack the scan inflates stream by stream: the fixture's are a few KiB. */
const PACK_SCAN_MAX_BYTES = 16 * 1024 * 1024

/**
 * What a workspace file holds, as text to search for the binding's value:
 * its bytes as they are, and for a git object what git deflated, since a
 * value inside one is invisible to a search of its bytes. A loose object
 * (.git/objects/xx/<rest of its id>) is one zlib stream, inflated whole; a
 * pack (.git/objects/pack/*.pack) is a run of them, each object's after its
 * header, so every place a zlib header could start is inflated as far as it
 * goes. What is not reassembled: an object a delta makes, so a value split
 * between bytes a delta copies from its base and bytes it inserts is not
 * found. A failure names the file as `quote` gives it: a path is container
 * output too, and may hold the value.
 */
export function searchable(file: string, quote: (text: string) => string): string[] {
  const bytes = readFileSync(file)
  const texts = [bytes.toString('latin1')]
  if (/[/\\]\.git[/\\]objects[/\\][0-9a-f]{2}[/\\][0-9a-f]{38}(?:[0-9a-f]{24})?$/.test(file)) {
    let inflated: Buffer
    try {
      inflated = inflateSync(bytes)
    } catch (e) {
      assert.fail(`${quote(file)} is a loose git object that does not inflate (${e instanceof Error ? e.message : String(e)}), so what it holds is unread`)
    }
    texts.push(inflated.toString('latin1'))
  } else if (/[/\\]\.git[/\\]objects[/\\]pack[/\\][^/\\]+\.pack$/.test(file)) {
    assert.ok(bytes.length <= PACK_SCAN_MAX_BYTES, `${quote(file)} is ${String(bytes.length)} bytes, more than the scan inflates`)
    for (let at = 0; at + 1 < bytes.length; at++) {
      // A zlib header: deflate (8) in the low nibble, its check bits making the pair a multiple of 31.
      if (((bytes[at] ?? 0) & 0x0f) !== 8 || (((bytes[at] ?? 0) << 8) | (bytes[at + 1] ?? 0)) % 31 !== 0) continue
      try {
        const out = inflateSync(bytes.subarray(at), { finishFlush: zlib.Z_SYNC_FLUSH })
        if (out.length > 0) texts.push(out.toString('latin1'))
      } catch {
        // Not a stream that starts here.
      }
    }
  }
  return texts
}

/** A tool.result's text, by its position among the run's results. */
function resultText(results: readonly Row[], i: number): string {
  const row = results[i]
  assert.ok(row !== undefined, `the run has no tool.result ${String(i + 1)}`)
  return String(row.payload['text'] ?? '')
}

/**
 * The stdout a call's result shows whole: the text under its `--- stdout (N
 * bytes) ---` heading, N bytes of it, read from the result as the kernel
 * wrote it (a scrub changes the count). The heading is the kernel's, the
 * first after the result's head lines, which the kernel writes above both
 * streams: a later one is a container's, printed on its stdout or its
 * stderr, and is never read. The text under it is the container's, so it is
 * read by the heading's count, never up to a line the container could print
 * (a `--- stderr` heading of its own). A stream the kernel shows by a window
 * or cut, or withholds, is no whole stdout: its first line may be the end of
 * a line, so none of it is read as whole lines. A failure shows the heading
 * as `quote` gives it.
 */
export function stdoutOf(text: string, quote: (text: string) => string): string {
  const at = text.indexOf('\n--- stdout (')
  const heading = at === -1 ? null : /^\n--- stdout \((\d+) bytes\) ---\n/.exec(text.slice(at))
  const shown = at === -1 ? 'none' : (text.slice(at + 1).split('\n')[0] ?? '')
  assert.ok(heading !== null, `the result does not show its stdout whole, so no line of it is read: ${quote(shown).slice(0, 300)}`)
  const from = Buffer.byteLength(text.slice(0, at + heading[0].length))
  return Buffer.from(text, 'utf8').subarray(from, from + Number(heading[1])).toString('utf8')
}

/**
 * The JSON on the line of `text` that starts with `marker`; a failure shows
 * `text` as `quote` gives it. A line that is not JSON fails with the line
 * scrubbed, never with JSON.parse's own error, which quotes the raw text
 * around where it stopped reading (V8: ten characters past it), a value the
 * mask let through among them.
 */
export function marked(text: string, marker: string, quote: (text: string) => string): unknown {
  const line = text.split('\n').find((l) => l.startsWith(marker))
  assert.ok(line !== undefined, `no ${marker} line in:\n${quote(text).slice(0, 2_000)}`)
  try {
    return JSON.parse(line.slice(marker.length)) as unknown
  } catch {
    assert.fail(`the ${marker.trim()} line is not JSON: ${quote(line).slice(0, 2_000)}`)
  }
}

/**
 * The head of each text, for a failure to show: each scrubbed whole, then
 * cut to `max` characters, so a value the cut would split is replaced before
 * the cut, never left half in the message.
 */
export function quotedHeads(texts: readonly string[], quote: (text: string) => string, max = 200): string {
  return texts.map((text) => quote(text).slice(0, max)).join('\n---\n')
}

/**
 * `text` as a failure message may show it: the binding's value and its Basic
 * form replaced by their names. node:test's reporters print a failed
 * assertion's message, and its actual and expected values, to the terminal
 * and the TAP output the operator copies, so no text quoted from the log, a
 * file or a container's output reaches one unscrubbed: the log's mask holds
 * them only while the kernel's mask holds, and a check that the mask failed
 * is no place to print what it let through.
 */
export function scrubbed(value: string, basic: string): (text: string) => string {
  return (text) => text.split(value).join('<the binding value>').split(basic).join('<its Basic form>')
}

/**
 * 'Phase 2 exit: clone, change, test, push aos/<runId>/<branch>, PR opened'.
 * Runs the coder's exit on a booted kernel and holds the log, the specs and
 * the workspace to everything the plan's L2 asks; the kernel is shut down
 * before the log is read, and its chain verified. No failure it reports
 * quotes the binding's value or its Basic form (scrubbed).
 */
export async function phase2Exit(inputs: ExitInputs): Promise<ExitRecord> {
  const { kernel, fx, value } = inputs
  const basic = basicOf(fx, value)
  const quote = scrubbed(value, basic)
  assert.equal(kernel.status().subsystems.egress.state, 'ok', quote(kernel.status().subsystems.egress.reason ?? ''))
  const repo = boundRepo(fx)

  const mountRoot = fx.config.sandbox.domains.trusted.mountRoot
  const prompt = `clone ${repo}, add a test, run the tests, and open a pull request`
  const { finished, approvals } = await runApproving(kernel, prompt, inputs.timeoutMs, exitApprovals(repo), quote, (started) => inputs.made?.(join(mountRoot, started)))
  const runId = String(finished['runId'])
  const workspace = join(mountRoot, runId)
  assert.equal(finished['status'], 'ok', quote(String(finished['reason'] ?? '')))
  await kernel.shutdown()
  const all = logged(fx.dbPath)
  const verified = new EventStore(fx.dbPath, { readOnly: true })
  try {
    assert.equal(verified.verifyChain(verified.readAnchor()).ok, true, 'the chain does not verify')
  } finally {
    verified.close()
  }

  // Every call the gate asked a human about was approved: each exec after
  // the first (which tainted the run) and the publish, which is irreversible.
  const commands = exitCommands(repo)
  assert.deepEqual(approvals, [...commands.slice(1).map(() => 'sandbox.exec'), 'sandbox.publish'])

  // The calls ran in order, each to its end. Each result's text is read
  // scrubbed: no check below looks for the value in it, and a failed match
  // prints the text it was handed.
  const results = all.filter((r) => r.type === 'tool.result')
  assert.equal(results.length, commands.length + 1, quotedHeads(results.map((r) => String(r.payload['text'])), quote))
  const said = (i: number): string => quote(resultText(results, i))
  // How a call ended, read from its head line alone: the result's first
  // line, the kernel's (`<name> on the trusted domain, <network>, exited N
  // after M ms`). What the container printed follows it, and may say
  // anything, `exited 0` or a whole line of a head's shape included.
  const exited = (i: number, code: number): void => {
    const head = said(i).split('\n')[0] ?? ''
    assert.match(head, new RegExp(`^aos-run-\\S+ on the trusted domain, [^\\n]*, exited ${String(code)} after \\d+ ms$`), `call ${String(i + 1)} did not exit ${String(code)}: ${head.slice(0, 300)}`)
  }
  // No route to the Mac's loopback as a VM sees it, and the proxy denies both names.
  exited(0, 0)
  // What the direct probe met, read as its whole stdout, where DIRECT_PROBE
  // prints the one code it met (console.log): ENETUNREACH alone. A line on
  // stderr is none of its report, and a `connected` beside it is a route.
  const direct = quote(stdoutOf(resultText(results, 0), quote))
  assert.ok(direct === 'ENETUNREACH\n', `a direct connect to 192.168.5.2:8766 met something other than no route: its stdout is ${JSON.stringify(direct.slice(0, 200))}`)
  for (const i of [1, 2]) assert.match(said(i), /returned error: 403/, `git ls-remote through the proxy was not denied (call ${String(i + 1)})`)
  for (const i of [3, 4, 5, 6, 7, 8, 9]) exited(i, 0)
  // How the kernel says each call ended, which its head line alone does not
  // say: the kernel marks a call ok (tool.result's ok) only when its command
  // exited 0 and its grant ended with its container's exit. A mux that sends
  // its exit frame and then tears a frame has its grant revoked for a
  // violation, and its call marked failed, with `exited 0` still on the
  // head's first line and the revocation on its second. So every call is
  // held to ok but the two git requests for the loopback, which the proxy
  // denies and git ends not ok; and every grant of the run to the revocation
  // its normal end gives (`exited`), never a violation, a limit, a kill or an
  // error: the two requests' grants included, whose calls end not ok
  // whatever their grants met. A failure names the call and the first two
  // lines of its result, scrubbed.
  const headOf = (i: number): string => said(i).split('\n').slice(0, 2).join('\n').slice(0, 600)
  for (const [i, row] of results.entries()) {
    const ok = row.payload['ok'] === true
    if (i === 1 || i === 2) assert.ok(!ok, `the kernel reports call ${String(i + 1)} ok, though the proxy denied its one request: ${headOf(i)}`)
    else assert.ok(ok, `the kernel reports call ${String(i + 1)} failed: ${headOf(i)}`)
  }
  const runGrants = all.filter((r) => r.type === 'proxy.grant.issued' && r.payload['purpose'] !== 'canary').map((r) => String(r.payload['grantId']))
  for (const r of all.filter((each) => each.type === 'proxy.grant.revoked')) {
    const i = runGrants.indexOf(String(r.payload['grantId']))
    if (i === -1) continue
    const reason = String(r.payload['reason'])
    assert.ok(reason === 'exited', `call ${String(i + 1)}'s grant was revoked (${quote(reason)}), not at its command's exit: ${i < results.length ? headOf(i) : 'the call has no result'}`)
  }
  // node --test's summary, read from its stdout alone (the reporter writes
  // its whole stream there, so a line on stderr is none of it) and from the
  // block after its top-level plan, the last `1..N` line, unindented. It prints
  // all a test writes, to its stdout or its stderr, above that plan as whole
  // `# <line>` lines, a subtest's plan indented, and a test's name escaped
  // (`\#`), so no test's name or output can make a line of the block (Node
  // 22.22.0, checked 2026-11-14). A line is what ends at a \n: never a /m
  // regex, which also ends a line at a \r, U+2028 or U+2029, the last two of
  // which the reporter passes through raw (a \r it escapes, or splits at).
  const tap = quote(stdoutOf(resultText(results, 7), quote)).split('\n')
  const plan = tap.map((line) => /^1\.\.\d+$/.test(line)).lastIndexOf(true)
  const summary = plan === -1 ? [] : tap.slice(plan + 1)
  const count = (what: string): string | undefined => summary.find((line) => line.startsWith(`# ${what} `))
  assert.equal(count('pass'), '# pass 2', 'node --test did not pass both tests')
  assert.equal(count('fail'), '# fail 0', 'node --test reported a failed test')
  assert.ok(tap[plan] === '1..2' && count('tests') === '# tests 2', 'node --test did not run exactly the two tests')
  // What the publisher says it did, as whole lines of its stdout, where
  // publish.mjs writes both (a line on stderr, or one that starts with words
  // of its own, `not pushed`, is not it saying so), each held whole to what
  // was approved: the pushed line to its end (a host that only starts
  // github.com is another host), the opened line's address to the bound
  // repository, on github.com, under the number it says it opened.
  const publish = said(9)
  const publishLines = quote(stdoutOf(resultText(results, 9), quote)).split('\n')
  const pushedLine = new RegExp(`^pushed [0-9a-f]{40} to refs/heads/aos/${runId}/${EXIT_PUBLISH.branch} of ${repo} on github\\.com$`)
  assert.ok(publishLines.some((line) => pushedLine.test(line)), 'the publish does not say it pushed the approved branch')
  const openedLine = new RegExp(`^opened pull request #(\\d+): (https://github\\.com/([^/\\s]+/[^/\\s]+)/pull/(\\d+)) \\(from aos/${runId}/${EXIT_PUBLISH.branch} into main\\)$`)
  const opened = publishLines.map((line) => openedLine.exec(line)).find((m) => m !== null) ?? null
  assert.ok(opened, `the publish opened no pull request:\n${publish.slice(0, 2_000)}`)
  // GitHub spells the repository in its own case (AiBot-Tools); config reads it without case.
  assert.equal(opened[3]?.toLowerCase(), repo, `the publish says it opened its pull request in ${String(opened[3])}, not ${repo}`)
  assert.equal(opened[4], opened[1], `the publish says it opened pull request #${String(opened[1])} at the address of #${String(opened[4])}`)

  // What PID 1 holds, as `docker inspect` reports Env and Cmd, and what the
  // mux and the command run with: no credential in any. Read from the log,
  // where the kernel's mask stands in for a registered value (the binding's,
  // its Basic form) or a credential shape: the mask showing in any list is
  // such a value found there. A failure names the variable, or the
  // argument's place, and what it holds, never the entry. Each marked line
  // is read from the probe's whole stdout, where PID1_PROBE prints all five
  // (console.log): a line on stderr is none of its report.
  const probed = stdoutOf(resultText(results, 8), quote)
  const environ = marked(probed, '@/proc/1/environ ', quote) as string[]
  const cmdline = marked(probed, '@/proc/1/cmdline ', quote) as string[]
  const muxEnviron = marked(probed, '@/proc/ppid/environ ', quote) as string[]
  const muxCmdline = marked(probed, '@/proc/ppid/cmdline ', quote) as string[]
  const ownEnviron = marked(probed, '@/proc/self/environ ', quote) as string[]
  // docker-init, then the mux around the command: the run's own argv, nothing added.
  assert.ok(cmdline.includes(MUX_ARGV[1] ?? ''), `PID 1's command line holds no ${MUX_ARGV[1] ?? ''}: ${quote(cmdline.join(' '))}`)
  // The probe's parent is the mux (its argv starts as the mux's does), so the environment read as the mux's is.
  assert.ok(same(muxCmdline.slice(0, MUX_ARGV.length), MUX_ARGV), `the probe's parent is not the mux: it runs ${quote(muxCmdline.join(' ')).slice(0, 200)}`)
  const entryHolds = (entry: string): string | undefined =>
    entry.includes(value) ? 'the binding value' : entry.includes(basic) ? 'its Basic form' : entry.includes(CENSOR) ? `the kernel's mask (${CENSOR}: a credential the log masked)` : undefined
  const environments: readonly (readonly [string, readonly string[]])[] = [["PID 1's", environ], ["the mux's", muxEnviron], ["the command's", ownEnviron]]
  for (const [whose, list] of environments) {
    for (const [i, entry] of list.entries()) {
      const name = entry.split('=')[0] ?? ''
      const held = entryHolds(entry)
      assert.equal(held, undefined, `${whose} environment holds ${String(held)} in ${quote(name)} (entry ${String(i)})`)
      assert.equal(CREDENTIAL_NAME.test(name) || /TOKEN|SECRET|PASSWORD/i.test(name), false, `${whose} environment holds ${quote(name)}`)
    }
  }
  for (const [i, arg] of cmdline.entries()) {
    const held = entryHolds(arg)
    assert.equal(held, undefined, `PID 1's command line holds ${String(held)} in argument ${String(i)}`)
  }

  // The workspace: the fixture, the second test, and no credential anywhere
  // in it, .git included: in no entry's name (a ref git named by a branch, a
  // file, directory or link the container made), in no link's target (read,
  // never followed: it may name anything on the Mac, and over virtiofs the
  // link is the Mac's), and in no file's contents, each git object searched
  // as git deflated it too. Every path a failure names is scrubbed.
  const edited = join(workspace, SECOND_TEST_FILE)
  assert.ok(existsSync(edited), `the edit wrote no ${SECOND_TEST_FILE}`)
  assert.equal(quote(readFileSync(edited, 'utf8')), SECOND_TEST, `${SECOND_TEST_FILE} is not the second test the edit writes`)
  for (const { path: file, kind } of entriesUnder(workspace)) {
    const name = relative(workspace, file)
    const nameHolds = name.includes(value) ? 'the binding value' : name.includes(basic) ? 'its Basic form' : undefined
    assert.equal(nameHolds, undefined, `the workspace entry ${quote(name)} is named with ${String(nameHolds)}`)
    if (kind === 'link') {
      const target = readlinkSync(file)
      const targetHolds = target.includes(value) ? 'the binding value' : target.includes(basic) ? 'its Basic form' : undefined
      assert.equal(targetHolds, undefined, `the workspace link ${quote(name)} has a target holding ${String(targetHolds)}`)
    }
    if (kind !== 'file') continue
    for (const text of searchable(file, quote)) {
      const fileHolds = text.includes(value) ? 'the binding value' : text.includes(basic) ? 'its Basic form' : undefined
      assert.equal(fileHolds, undefined, `${quote(file)} holds ${String(fileHolds)}`)
    }
  }
  // The specs every container was built from: no credential in any.
  for (const spec of inputs.specs) assert.equal(JSON.stringify(spec).includes(value) || JSON.stringify(spec).includes(basic), false, `the spec of ${spec.name} holds the binding value`)
  // And none in the log.
  for (const row of all) {
    const text = JSON.stringify(row.payload)
    const rowHolds = text.includes(value) ? 'the binding value' : text.includes(basic) ? 'its Basic form' : undefined
    assert.equal(rowHolds, undefined, `${row.type} (seq ${String(row.seq)}) holds ${String(rowHolds)}`)
  }
  // Nor its mask, in any row of the run: the mask in a row is a registered
  // value (the binding's, its Basic form) or a credential shape that reached
  // it, a container's output above all, which the mask kept from the log and
  // which no check of the log's bytes alone can see.
  for (const row of all.filter((r) => r.runId === runId)) {
    assert.equal(JSON.stringify(row.payload).includes(CENSOR), false, `${row.type} (seq ${String(row.seq)}) of the run holds the kernel's mask (${CENSOR}): a registered value or a credential shape reached it`)
  }

  // The run's grants: every flow a decision, every decision this run's.
  const issued = all.filter((r) => r.type === 'proxy.grant.issued' && r.payload['purpose'] !== 'canary')
  const grants = new Set(issued.map((r) => String(r.payload['grantId'])))
  assert.equal(grants.size, commands.length + 1, 'every exec and the publish is issued a grant of its own')
  for (const r of issued) assert.equal(r.runId, runId, "a grant of the run's containers recorded under another run")
  const decisions = all.filter((r) => r.type === 'proxy.decision' && grants.has(String(r.payload['grantId'])))
  for (const d of decisions) assert.equal(d.runId, runId, 'a decision of the run recorded under another run')
  const canaryGrants = new Set(all.filter((r) => r.type === 'proxy.grant.issued' && r.payload['purpose'] === 'canary').map((r) => String(r.payload['grantId'])))
  const unowned = all.filter((r) => r.type === 'proxy.decision' && !grants.has(String(r.payload['grantId'])) && !canaryGrants.has(String(r.payload['grantId'])))
  assert.equal(unowned.length, 0, `a decision under no grant of the run: ${quote(unowned.map((d) => JSON.stringify(d.payload)).join('\n'))}`)
  for (const r of all.filter((each) => each.type === 'proxy.grant.revoked' && grants.has(String(each.payload['grantId'])))) {
    const grantId = String(r.payload['grantId'])
    const totals = r.payload['totals'] as { flows: number; requests: number }
    const judged = decisions.filter((d) => d.payload['grantId'] === grantId && d.payload['stage'] === 'policy').reduce((n, d) => n + Number(d.payload['count']), 0)
    assert.equal(totals.flows, totals.requests, `grant ${grantId}: a flow carried no judged request`)
    assert.equal(judged, totals.requests, `grant ${grantId}: ${String(totals.requests)} requests and ${String(judged)} decisions`)
  }
  assert.equal(all.filter((r) => r.type === 'proxy.grant.revoked' && grants.has(String(r.payload['grantId']))).length, grants.size, 'a grant of the run was never revoked')
  // Every allow is the bound repository's, on its two hosts; nothing failed upstream.
  const allows = decisions.filter((d) => d.payload['verdict'] === 'allow')
  for (const d of allows) {
    assert.ok(['github.com', 'api.github.com'].includes(String(d.payload['host'])), `an allow for ${quote(String(d.payload['host']))}`)
    assert.equal(d.payload['repo'] === repo, true, `an allow for ${quote(String(d.payload['repo']))}, not ${repo}`)
  }
  const failedUpstream = decisions.filter((d) => d.payload['stage'] === 'upstream')
  assert.equal(failedUpstream.length, 0, `a request the kernel allowed failed upstream: ${quote(failedUpstream.map((d) => JSON.stringify(d.payload)).join('\n'))}`)

  // Each call's grant, in the order the calls ran, and what was decided under it.
  const grantOf = (i: number): string => String(issued[i]?.payload['grantId'])
  const under = (i: number): Row[] => decisions.filter((d) => d.payload['grantId'] === grantOf(i))
  const shown = (rows: readonly Row[]): string => quote(rows.map((d) => JSON.stringify(d.payload)).join('\n'))
  // The two git requests for the Mac's loopback as a VM sees it: each its
  // grant's one decision, a deny at the policy that read the target's host
  // as none (an address literal, a special-use name), so nothing was
  // resolved or sent; a not-a-host deny names why in hostRefusal, never the
  // host (src/events/types.ts ProxyDecisionPayload).
  for (const [i, hostRefusal, target] of [
    [1, 'ip-literal', '192.168.5.2'],
    [2, 'special-use', 'host.lima.internal'],
  ] as const) {
    const rows = under(i)
    const read = JSON.stringify(rows.map((d) => [d.payload['stage'], d.payload['verdict'], d.payload['reason'], d.payload['hostRefusal'], d.payload['host'] ?? null, d.payload['count']]))
    assert.ok(read === JSON.stringify([['policy', 'deny', 'not-a-host', hostRefusal, null, 1]]), `the git request for ${target} (call ${String(i + 1)}) was not its grant's one deny at the policy, as no host:\n${shown(rows)}`)
  }
  // No other request of the run was denied.
  const denied = decisions.filter((d) => d.payload['verdict'] === 'deny' && d.payload['grantId'] !== grantOf(1) && d.payload['grantId'] !== grantOf(2))
  assert.equal(denied.length, 0, `a request of the run besides the two for the loopback was denied:\n${shown(denied)}`)
  // The clone was allowed to fetch the bound repository from github.com,
  // and the publish to push to it there and to open its pull request on
  // api.github.com: what each says it did, the log shows it asked for.
  const sent = (i: number): string[] => under(i).filter((d) => d.payload['verdict'] === 'allow').map((d) => `${String(d.payload['reason'])} ${String(d.payload['method'])} ${String(d.payload['host'])}${String(d.payload['path'])}`)
  assert.ok(sent(3).includes(`git-fetch POST github.com/${repo}.git/git-upload-pack`), `the clone asked for no pack of ${repo}:\n${shown(under(3))}`)
  assert.ok(sent(9).includes(`git-push POST github.com/${repo}.git/git-receive-pack`), `the publish pushed nothing:\n${shown(under(9))}`)
  assert.ok(sent(9).includes(`github-pulls POST api.github.com/repos/${repo}/pulls`), `the publish opened no pull request:\n${shown(under(9))}`)

  return { runId, pullRequest: opened[2] ?? '', approvals, decisions: decisions.length }
}

// ── offline: the containers as the image and its mux act ──────────────────

/** The fixture repository's files, as the operator creates it (README "Live sandbox and egress tests"). */
export const FIXTURE_FILES: Readonly<Record<string, string>> = Object.freeze({
  'package.json': '{"name": "aos-fixture", "version": "0.0.0", "private": true, "type": "module", "scripts": {"test": "node --test"}}\n',
  'sum.js': 'export function sum(a, b) {\n  return a + b\n}\n',
  'sum.test.js': "import test from 'node:test'\nimport assert from 'node:assert/strict'\nimport { sum } from './sum.js'\n\ntest('sum(2, 3) is 5', () => {\n  assert.equal(sum(2, 3), 5)\n})\n",
})

const same = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i])

/** One git request through the mux, as git sends it to its http_proxy: absolute form, plain HTTP. */
const gitGet = (url: string): string => `GET ${url} HTTP/1.1\r\nHost: ${new URL(url).host}\r\nUser-Agent: git/2.39.5\r\n\r\n`

function gitPost(url: string, service: string, body: string): string {
  return (
    `POST ${url} HTTP/1.1\r\nHost: ${new URL(url).host}\r\nContent-Type: application/x-${service}-request\r\n` +
    `Content-Length: ${String(Buffer.byteLength(body, 'latin1'))}\r\n\r\n${body}`
  )
}

const pkt = (payload: string): string => (payload.length + 4).toString(16).padStart(4, '0') + payload
const OID = 'c'.repeat(40)

/** A test of a node --test run: its name, whether it passed or was skipped, and its subtests. */
interface TapTest {
  readonly name: string
  readonly ok: boolean
  readonly skipped?: boolean
  readonly subtests?: readonly TapTest[]
}

/** The fixture's two tests, and the second test's, as node --test names them. */
const FIRST: TapTest = { name: 'sum(2, 3) is 5', ok: true }
const SECOND: TapTest = { name: 'sum(-2, 2) is 0', ok: true }

/**
 * node --test's TAP stream as its reporter writes it to stdout (Node
 * 22.22.0, checked 2026-11-14): `printed`, the lines the tests wrote to
 * their stdout or stderr, each as `# <line>`, above the first test; each
 * test's `# Subtest:` line, its subtests four spaces in under a plan of
 * their own, its `ok` or `not ok` line and YAML block; then the top-level
 * plan, unindented, and the summary. A name is escaped as the reporter
 * escapes it (`#` as `\#`).
 */
function tapStream(tests: readonly TapTest[], printed: readonly string[] = []): string {
  const lines = ['TAP version 13', ...printed.map((line) => `# ${line}`)]
  const write = (list: readonly TapTest[], indent: string): void => {
    for (const [i, test] of list.entries()) {
      const name = test.name.replace(/\\/g, '\\\\').replace(/#/g, '\\#')
      lines.push(`${indent}# Subtest: ${name}`)
      if (test.subtests !== undefined) write(test.subtests, `${indent}    `)
      lines.push(`${indent}${test.ok ? 'ok' : 'not ok'} ${String(i + 1)} - ${name}${test.skipped === true ? ' # SKIP' : ''}`)
      lines.push(`${indent}  ---`, `${indent}  duration_ms: 0.5`, `${indent}  type: 'test'`, `${indent}  ...`)
    }
    lines.push(`${indent}1..${String(list.length)}`)
  }
  write(tests, '')
  const every = (list: readonly TapTest[]): TapTest[] => list.flatMap((test) => [test, ...every(test.subtests ?? [])])
  const all = every(tests)
  const n = (keep: (test: TapTest) => boolean): string => String(all.filter(keep).length)
  lines.push(`# tests ${String(all.length)}`, '# suites 0', `# pass ${n((t) => t.ok && t.skipped !== true)}`, `# fail ${n((t) => !t.ok)}`)
  lines.push('# cancelled 0', `# skipped ${n((t) => t.skipped === true)}`, '# todo 0', '# duration_ms 76.8')
  return `${lines.join('\n')}\n`
}

/**
 * What a container of the exit does wrong, offline, so that each check of
 * phase2Exit a container can make fail is seen to fail on what it is there
 * to catch. Each is one container acting as a broken VM, image or kernel
 * would have it act:
 *
 *   direct-connects    the direct probe of 192.168.5.2:8766 connects.
 *   direct-said-on-stderr
 *                      the direct probe connects, prints `connected` on its
 *                      stdout, and ENETUNREACH on its stderr.
 *   direct-said-both   the direct probe prints ENETUNREACH, then
 *                      `connected`, both on its stdout.
 *   direct-fails       the direct probe prints ENETUNREACH and exits 1.
 *   ls-remote-silent-ip, ls-remote-silent-name
 *                      git ls-remote for 192.168.5.2 (ip) or for
 *                      host.lima.internal (name) prints the 403 it would
 *                      get, but sends no request through the mux, so
 *                      nothing was denied.
 *   ls-remote-other-ip, ls-remote-other-name
 *                      git ls-remote for 192.168.5.2 (ip) or for
 *                      host.lima.internal (name) sends its request, which
 *                      the kernel denies, and prints a 502.
 *   ls-remote-exits-0  git ls-remote for host.lima.internal sends its
 *                      request, which the kernel denies, prints the 403,
 *                      and exits 0.
 *   ls-remote-then-torn
 *                      git ls-remote for 192.168.5.2 sends its request,
 *                      which the kernel denies, prints the 403 and exits
 *                      128, and its mux then sends three bytes of a frame's
 *                      header and ends its stream: its grant is revoked for
 *                      a violation, its call not ok as it would be anyway.
 *   ls-remote-client-lost
 *                      git ls-remote for 192.168.5.2 sends its request,
 *                      which the kernel denies, prints the 403 and exits
 *                      128, and its docker client then ends with no exit
 *                      status (SIGKILL, as the OOM killer ends one): the
 *                      kernel kills the container by name and revokes its
 *                      grant `error`, its call not ok as it would be anyway.
 *   ls-remote-lingers  git ls-remote for 192.168.5.2 sends its request,
 *                      which the kernel denies, prints the 403 and exits
 *                      128, and its container then never ends, as one a
 *                      process the command left behind keeps running: the
 *                      kernel kills it by name EXIT_KILL_GRACE_MS after the
 *                      exit frame and revokes its grant `requested`, its
 *                      call not ok as it would be anyway.
 *   clone-offline      the clone writes the fixture's files but fetches
 *                      nothing, as a workspace seeded some other way.
 *   clone-refs-only    the clone asks for the bound repository's refs (GET
 *                      info/refs), never for a pack, then writes the
 *                      fixture's files.
 *   clone-cut          the clone's upload-pack POST ends before its
 *                      Content-Length (git killed mid-request), so the
 *                      allowed request fails upstream ('aborted').
 *   clone-fails        the clone fetches and writes the fixture, then exits
 *                      128.
 *   extra-request      the clone also asks for another repository, as a
 *                      submodule would, which the kernel denies.
 *   flow-silent        the clone also opens a flow through the mux and hangs
 *                      it up with no request on it.
 *   edit-fails         the edit writes the second test, then exits 1.
 *   edit-prints-exited the edit writes the second test, prints `exited 0`
 *                      and a whole line of a result head's shape saying it
 *                      exited 0, then exits 1.
 *   exit-then-torn     the edit writes the second test and exits 0, and its
 *                      mux then sends three bytes of a frame's header and
 *                      ends its stream: its grant is revoked for a
 *                      violation and the kernel reports the call failed,
 *                      though its head line says it exited 0.
 *   edit-unwritten     the edit writes nothing, and exits 0.
 *   edit-other         the edit writes another file than the second test.
 *   add-fails          git add exits 128.
 *   commit-fails       git commit exits 1.
 *   tests-fail         node --test runs both tests, one fails, and exits 1.
 *   one-test           node --test passes, but ran one test: the edit added none.
 *   fail-reported      node --test reports two passed and one failed, and
 *                      exits 0.
 *   pass-named         node --test passes, but ran one test, whose name is
 *                      `# pass 2` (its line `ok 1 - \# pass 2`).
 *   fail-named         node --test reports two passed and one failed, the
 *                      failed one named `# fail 0`, and exits 0.
 *   tests-extra        node --test reports two passed, none failed, and a
 *                      third test, a subtest of the first, skipped: its plan
 *                      says two, but three ran.
 *   tests-nested       node --test passes two tests, one of them a subtest
 *                      of the other: its plan says one, the second file ran
 *                      nothing.
 *   summary-printed    node --test passes, but ran one test, which printed
 *                      `pass 2` and `tests 2`: the reporter writes them as
 *                      whole lines `# pass 2` and `# tests 2` above its plan.
 *   tap-unplanned      node --test prints a two-test summary with no plan
 *                      line above it, as no TAP reporter writes one.
 *   summary-on-stderr  node --test passes, but ran one test, and its stderr
 *                      holds a two-test plan and summary.
 *   tap-heading-on-stderr
 *                      node --test passes, but ran one test, and its stderr
 *                      prints a stdout heading of its own, `--- stdout (N
 *                      bytes) ---`, over a two-test stream of N bytes.
 *   tap-windowed       node --test passes both tests, after more output than
 *                      the kernel shows whole, so its stdout is shown by its
 *                      end.
 *   quoted-unmasked    the kernel's mask forgets the value (SecretMask.clear)
 *                      before node --test, which prints it and passes one
 *                      test: the check that fails quotes what it printed.
 *   pid1-fails         the look at PID 1 prints what it read, then exits 1.
 *   pid1-silent        the look at PID 1 prints nothing.
 *   pid1-on-stderr     the look at PID 1 prints its five lines on its stderr,
 *                      nothing on its stdout.
 *   pid1-garbled       the kernel's mask forgets the value (SecretMask.clear)
 *                      before the look at PID 1, which prints its environment
 *                      line with the value in it bare, not JSON.
 *   cmdline-bare       PID 1's command line is the command alone, with no
 *                      mux around it.
 *   cmdline-value      PID 1's command line holds the value as an argument
 *                      of its own.
 *   cmdline-unmasked   the kernel's mask forgets the value (SecretMask.clear)
 *                      before the look at PID 1, whose command line holds it.
 *   environ-value      PID 1's environment holds the value, under a name no
 *                      credential pattern reads.
 *   mux-environ-value, command-environ-value
 *                      the same in the mux's environment, or in the
 *                      command's own, PID 1's clean: a mux that gave itself or
 *                      the command a credential.
 *   mux-not-parent     the probe's parent runs docker-init's command line,
 *                      not the mux's: what is read as the mux's environment
 *                      is not.
 *   mux-parent-other-node
 *                      the probe's parent is another node program (the
 *                      publisher's argv), not the mux, its argv[0] the
 *                      mux's own.
 *   mux-environ-token-name, command-environ-token-name
 *                      the mux's environment, or the command's own, holds
 *                      GH_TOKEN, empty, PID 1's and the other clean.
 *   mux-environ-unmasked, command-environ-unmasked,
 *   mux-environ-basic-unmasked, command-environ-basic-unmasked
 *                      the kernel's mask forgets the value (SecretMask.clear)
 *                      before the look at PID 1; the mux's environment, or
 *                      the command's own, holds the value, or its Basic
 *                      form, PID 1's and the other clean.
 *   environ-unmasked   the kernel's mask forgets the value (SecretMask.clear)
 *                      before the look at PID 1, whose environment holds it
 *                      under a name no credential pattern reads.
 *   environ-basic-unmasked
 *                      the same, its environment holding the Basic form.
 *   environ-token-name PID 1's environment holds GH_TOKEN, empty.
 *   environ-key-name   PID 1's environment holds ANTHROPIC_API_KEY, empty:
 *                      a credential name that says no TOKEN, SECRET or
 *                      PASSWORD.
 *   environ-password-name, environ-secret-name
 *                      PID 1's environment holds GIT_PASSWORD, or
 *                      AWS_SECRET, empty: a name no credential pattern of
 *                      the guard's reads, and that says no TOKEN.
 *   push-elsewhere     the publisher pushes refs/heads/main, not the approved
 *                      branch, and says it pushed the approved one.
 *   push-skipped       the publisher pushes nothing, and says it pushed.
 *   pr-skipped         the publisher opens no pull request, and says it did.
 *   pr-into-other      the publisher opens the pull request into dev, not
 *                      main, and says so.
 *   publish-unsaid     the publisher pushes and opens the pull request, and
 *                      says only that it opened it.
 *   publish-said-elsewhere, publish-said-other-run, publish-said-other-repo,
 *   publish-said-other-host
 *                      the publisher pushes the approved branch and opens
 *                      the pull request, and says it pushed another branch
 *                      (aos/<runId>/other), the approved branch of another
 *                      run (aos/<another run>/<branch>), to another
 *                      repository, or to another host, each alone.
 *   publish-said-host-suffix
 *                      the same, and it says it pushed to a host whose name
 *                      only starts as github.com's (github.com.example).
 *   publish-said-prefixed, publish-said-separated
 *                      the same, and its pushed line starts with words of
 *                      its own (`not pushed ...`), or follows them after a
 *                      U+2028 on one line (`nothing pushed<U+2028>pushed
 *                      ...`).
 *   publish-said-on-stderr
 *                      the same, and it says both lines on stderr, nothing
 *                      on stdout.
 *   pr-said-elsewhere, pr-said-other-run
 *                      the same, and it says it opened the pull request
 *                      from another branch, or from the approved branch of
 *                      another run.
 *   pr-said-other-repo, pr-said-other-host, pr-said-other-number
 *                      the same, and the address it says it opened names
 *                      another repository, another host (gitlab.com), or
 *                      another number than the one it says it opened.
 *   pr-said-prefixed, pr-said-suffixed
 *                      the same, and its opened line starts with words of
 *                      its own (`never opened ...`), or goes on past what
 *                      was approved (`..., then closed it`).
 *   pr-unsaid          the publisher pushes and opens the pull request, and
 *                      says only that it pushed.
 *   publish-fails      the publisher pushes, opens the pull request, says
 *                      so, and exits 1.
 *   workspace-file     the clone writes the value into .git/config.
 *   workspace-name     the clone writes a ref named by the value
 *                      (.git/refs/heads/<value>), holding a commit id only.
 *   workspace-name-basic
 *                      the same, a tag named by its Basic form
 *                      (.git/refs/tags/<Basic form>).
 *   workspace-basic    the clone writes its Basic form into .git/config.
 *   workspace-link, workspace-link-basic
 *                      the clone makes a link, `notes`, whose target names
 *                      the value, or its Basic form (../<value>), and writes
 *                      no file that holds either.
 *   workspace-object   the commit writes it into a loose object, deflated.
 *   workspace-pack     the clone writes it into a pack, deflated.
 *   object-corrupt     the commit writes a loose object that does not inflate.
 *   pack-huge          the clone writes a pack larger than the scan reads.
 *   printed-masked     the edit prints the value, which the kernel's mask
 *                      keeps from the log as [REDACTED].
 *   mask-lost          the kernel's mask forgets the value (SecretMask.clear)
 *                      before the edit prints it, so the log holds it.
 *   mask-lost-basic    the same, and the edit prints its Basic form.
 */
export type ExitFault =
  | 'direct-connects'
  | 'direct-said-on-stderr'
  | 'direct-said-both'
  | 'direct-fails'
  | 'ls-remote-silent-ip'
  | 'ls-remote-silent-name'
  | 'ls-remote-other-ip'
  | 'ls-remote-other-name'
  | 'ls-remote-exits-0'
  | 'ls-remote-then-torn'
  | 'ls-remote-client-lost'
  | 'ls-remote-lingers'
  | 'clone-offline'
  | 'clone-refs-only'
  | 'clone-cut'
  | 'clone-fails'
  | 'extra-request'
  | 'flow-silent'
  | 'edit-fails'
  | 'edit-prints-exited'
  | 'exit-then-torn'
  | 'edit-unwritten'
  | 'edit-other'
  | 'add-fails'
  | 'commit-fails'
  | 'tests-fail'
  | 'one-test'
  | 'fail-reported'
  | 'pass-named'
  | 'fail-named'
  | 'tests-extra'
  | 'summary-on-stderr'
  | 'tap-heading-on-stderr'
  | 'tap-windowed'
  | 'tests-nested'
  | 'summary-printed'
  | 'tap-unplanned'
  | 'quoted-unmasked'
  | 'pid1-fails'
  | 'pid1-silent'
  | 'pid1-on-stderr'
  | 'pid1-garbled'
  | 'cmdline-bare'
  | 'cmdline-value'
  | 'cmdline-unmasked'
  | 'environ-value'
  | 'mux-environ-value'
  | 'command-environ-value'
  | 'mux-not-parent'
  | 'mux-parent-other-node'
  | 'mux-environ-token-name'
  | 'command-environ-token-name'
  | 'mux-environ-unmasked'
  | 'command-environ-basic-unmasked'
  | 'command-environ-unmasked'
  | 'mux-environ-basic-unmasked'
  | 'environ-unmasked'
  | 'environ-basic-unmasked'
  | 'environ-token-name'
  | 'environ-key-name'
  | 'environ-password-name'
  | 'environ-secret-name'
  | 'push-elsewhere'
  | 'push-skipped'
  | 'pr-skipped'
  | 'pr-into-other'
  | 'publish-unsaid'
  | 'publish-said-elsewhere'
  | 'publish-said-other-run'
  | 'publish-said-other-repo'
  | 'publish-said-other-host'
  | 'publish-said-host-suffix'
  | 'publish-said-prefixed'
  | 'publish-said-separated'
  | 'publish-said-on-stderr'
  | 'pr-said-elsewhere'
  | 'pr-said-other-run'
  | 'pr-said-other-repo'
  | 'pr-said-other-host'
  | 'pr-said-other-number'
  | 'pr-said-prefixed'
  | 'pr-said-suffixed'
  | 'pr-unsaid'
  | 'publish-fails'
  | 'workspace-file'
  | 'workspace-name'
  | 'workspace-name-basic'
  | 'workspace-basic'
  | 'workspace-link'
  | 'workspace-link-basic'
  | 'workspace-object'
  | 'workspace-pack'
  | 'object-corrupt'
  | 'pack-huge'
  | 'printed-masked'
  | 'mask-lost'
  | 'mask-lost-basic'

/** The faults that change only a call's exit status: the call (its place in exitCommands, or the publish) and the status it exits with. */
const EXIT_STATUS_FAULTS: Readonly<Partial<Record<ExitFault, readonly [number | 'publish', number]>>> = Object.freeze({
  'direct-fails': [0, 1],
  'clone-fails': [3, 128],
  'edit-fails': [4, 1],
  'edit-prints-exited': [4, 1],
  'add-fails': [5, 128],
  'commit-fails': [6, 1],
  'pid1-fails': [8, 1],
  'publish-fails': ['publish', 1],
  'ls-remote-exits-0': [2, 0],
})

/** The faults whose container tears a frame after its exit frame: the call, by its place in exitCommands. */
const TORN_AFTER_EXIT: Readonly<Partial<Record<ExitFault, number>>> = Object.freeze({
  'exit-then-torn': 4,
  'ls-remote-then-torn': 1,
})

/**
 * The faults whose docker client ends with no exit status after the mux's
 * exit frame, as the real driver reports a client killed by a signal: the
 * call, by its place in exitCommands.
 */
const CLIENT_LOST_AFTER_EXIT: Readonly<Partial<Record<ExitFault, number>>> = Object.freeze({
  'ls-remote-client-lost': 1,
})

/**
 * The faults whose container never ends after the mux's exit frame, as one
 * a process the command left behind keeps running: the call, by its place in
 * exitCommands. Only the kernel's kill by name ends it.
 */
const LINGERS_AFTER_EXIT: Readonly<Partial<Record<ExitFault, number>>> = Object.freeze({
  'ls-remote-lingers': 1,
})

/**
 * FakeSandboxOptions.play for the exit: boot's canaries as boot's tests play
 * them, and each of the coder's containers as the worker image acts, over its
 * channel through a FakeMux: its ready report, then the requests the real
 * program sends (git's, and the publisher's in its order: the default branch,
 * the push, the pull request), its output and its exit status. The clone and
 * the edit write the files they would into the workspace. With a `fault`,
 * one container does what that fault names (ExitFault), with `value` the
 * binding's where it leaks one and `basic` its Basic form (basicOf).
 */
export function exitActor(repo: string, fault?: ExitFaulted): (spec: SandboxSpec, container: FakeChannel | undefined) => Promise<ScriptedExit> | undefined {
  const canaries = canaryPlayer()
  return (spec, container) => {
    if (spec.name.startsWith(CANARY_PREFIX)) return canaries(spec, container)
    if (container === undefined) return undefined
    const argv = spec.command.slice(MUX_ARGV.length + 1)
    return playWorker(repo, spec, container, argv, fault)
  }
}

/** A fault exitActor plays, the binding's value, and its Basic form as the kernel builds it (basicOf). */
export interface ExitFaulted {
  readonly fault: ExitFault
  readonly value: string
  readonly basic: string
}

/** A loose object's path under .git/objects and its deflated bytes: what git writes for a blob holding `text`. */
function looseBlob(text: string): { readonly path: string; readonly bytes: Buffer } {
  const raw = Buffer.from(`blob ${String(Buffer.byteLength(text))}\0${text}`)
  const id = createHash('sha1').update(raw).digest('hex')
  return { path: join(id.slice(0, 2), id.slice(2)), bytes: deflateSync(raw) }
}

/** A one-object pack holding a blob of `text`, deflated as git deflates a pack's objects. */
function packOf(text: string): Buffer {
  const body = Buffer.from(text)
  // Type 3 (blob) and the size's low four bits, then the rest seven bits a byte.
  const header: number[] = [0x30 | (body.length & 0x0f)]
  for (let rest = body.length >> 4; rest > 0; rest >>= 7) {
    header[header.length - 1] = (header[header.length - 1] ?? 0) | 0x80
    header.push(rest & 0x7f)
  }
  const pack = Buffer.concat([Buffer.from('PACK'), Buffer.from([0, 0, 0, 2, 0, 0, 0, 1]), Buffer.from(header), deflateSync(body)])
  return Buffer.concat([pack, createHash('sha1').update(pack).digest()])
}

async function playWorker(repo: string, spec: SandboxSpec, container: FakeChannel, argv: readonly string[], fault?: ExitFaulted): Promise<ScriptedExit> {
  const mux = new FakeMux(container)
  await mux.ready()
  const commands = exitCommands(repo)
  const git = `http://github.com/${repo}.git`
  const is = (name: ExitFault): boolean => fault?.fault === name
  const value = fault?.value ?? ''
  const basic = fault?.basic ?? ''
  const call = argv[1] === PUBLISH_ARGV[1] ? 'publish' : commands.findIndex((c) => same(argv, c))
  let status = 0
  if (call === 0) {
    // What DIRECT_PROBE prints on its stdout; a line on its stderr is none of what it met.
    mux.stdout(is('direct-connects') || is('direct-said-on-stderr') ? 'connected\n' : is('direct-said-both') ? 'ENETUNREACH\nconnected\n' : 'ENETUNREACH\n')
    if (is('direct-said-on-stderr')) mux.stderr('ENETUNREACH\n')
  } else if (argv[0] === 'git' && argv[1] === 'ls-remote') {
    const url = argv[2] ?? ''
    const target = call === 1 ? 'ip' : 'name'
    const answered = is(`ls-remote-silent-${target}`)
      ? '403'
      : (/^HTTP\/1\.1 (\d{3})/.exec(await mux.request(gitGet(`${url.replace(/\/$/, '')}/info/refs?service=git-upload-pack`)))?.[1] ?? '000')
    const code = is(`ls-remote-other-${target}`) ? '502' : answered
    mux.stderr(`fatal: unable to access '${url.endsWith('/') ? url : `${url}/`}': The requested URL returned error: ${code}\n`)
    status = 128
  } else if (call === 3) {
    if (!is('clone-offline')) await mux.request(gitGet(`${git}/info/refs?service=git-upload-pack`))
    if (!is('clone-offline') && !is('clone-refs-only')) {
      const post = gitPost(`${git}/git-upload-pack`, 'git-upload-pack', `${pkt(`want ${OID}\n`)}00000009done\n`)
      // Cut short: the head, and the body but its last five bytes, then the worker's end.
      if (is('clone-cut')) await mux.cutShort(post.slice(0, -5))
      else await mux.request(post)
    }
    if (is('extra-request')) await mux.request(gitGet('http://github.com/aibot-tools/aos-other.git/info/refs?service=git-upload-pack'))
    if (is('flow-silent')) await mux.silentFlow()
    for (const [name, text] of Object.entries(FIXTURE_FILES)) writeFileSync(join(spec.workspace, name), text)
    mkdirSync(join(spec.workspace, '.git', 'objects', 'pack'), { recursive: true })
    writeFileSync(join(spec.workspace, '.git', 'HEAD'), 'ref: refs/heads/main\n')
    if (is('workspace-name') || is('workspace-name-basic')) {
      const [kind, name] = is('workspace-name') ? ['heads', value] : ['tags', basic]
      mkdirSync(join(spec.workspace, '.git', 'refs', kind), { recursive: true })
      writeFileSync(join(spec.workspace, '.git', 'refs', kind, name), `${OID}\n`)
    }
    if (is('workspace-link') || is('workspace-link-basic')) symlinkSync(`../${is('workspace-link') ? value : basic}`, join(spec.workspace, 'notes'))
    const header = is('workspace-file') ? `[http]\n\textraHeader = Authorization: Bearer ${value}\n` : is('workspace-basic') ? `[http]\n\textraHeader = Authorization: Basic ${basic}\n` : ''
    writeFileSync(join(spec.workspace, '.git', 'config'), `${header}[remote "origin"]\n\turl = https://github.com/${repo}.git\n`)
    if (is('workspace-pack')) writeFileSync(join(spec.workspace, '.git', 'objects', 'pack', `pack-${OID}.pack`), packOf(`token=${value}\n`))
    if (is('pack-huge')) writeFileSync(join(spec.workspace, '.git', 'objects', 'pack', `pack-${OID}.pack`), Buffer.alloc(PACK_SCAN_MAX_BYTES + 1))
  } else if (call === 4) {
    if (is('mask-lost') || is('mask-lost-basic')) SecretMask.clear()
    if (is('mask-lost') || is('printed-masked')) mux.stdout(`${value}\n`)
    if (is('mask-lost-basic')) mux.stdout(`${basic}\n`)
    // Its own exit status said, then a whole line of a head's shape: neither is the head the kernel writes.
    if (is('edit-prints-exited')) {
      mux.stdout(`exited 0\n${spec.name} on the trusted domain, no network but the kernel's egress engine (grant g: 0 request(s), 0 allowed, 0 denied), exited 0 after 1 ms\n`)
    }
    if (!is('edit-unwritten')) writeFileSync(join(spec.workspace, SECOND_TEST_FILE), is('edit-other') ? '// a second test, to come\n' : SECOND_TEST)
  } else if (call === 5 || call === 6) {
    // git add and commit print nothing with --quiet; the commit writes its objects.
    if (is('object-corrupt') && call === 6) {
      mkdirSync(join(spec.workspace, '.git', 'objects', 'ab'), { recursive: true })
      writeFileSync(join(spec.workspace, '.git', 'objects', 'ab', 'c'.repeat(38)), 'not a zlib stream')
    }
    if (is('workspace-object') && call === 6) {
      const blob = looseBlob(`const token = '${value}'\n`)
      mkdirSync(join(spec.workspace, '.git', 'objects', blob.path, '..'), { recursive: true })
      writeFileSync(join(spec.workspace, '.git', 'objects', blob.path), blob.bytes)
    }
  } else if (call === 7) {
    // node --test as its TAP reporter writes it, under each fault.
    if (is('tests-fail')) {
      mux.stdout(tapStream([FIRST, { ...SECOND, ok: false }]))
      status = 1
    } else if (is('fail-reported')) mux.stdout(tapStream([FIRST, SECOND, { name: 'sum(1, 1) is 3', ok: false }]))
    else if (is('quoted-unmasked')) {
      SecretMask.clear()
      mux.stdout(tapStream([FIRST], [`token ${value}`]))
    } else if (is('pass-named')) mux.stdout(tapStream([{ name: '# pass 2', ok: true }]))
    else if (is('fail-named')) mux.stdout(tapStream([FIRST, SECOND, { name: '# fail 0', ok: false }]))
    // Three tests, the third a skipped subtest of the first: the plan says two.
    else if (is('tests-extra')) mux.stdout(tapStream([{ ...FIRST, subtests: [{ name: 'a third test', ok: true, skipped: true }] }, SECOND]))
    // One top-level test, two in all: its subtest passed, the second file ran nothing.
    else if (is('tests-nested')) mux.stdout(tapStream([{ ...FIRST, subtests: [{ name: 'a subtest', ok: true }] }]))
    // A one-test run whose test printed `pass 2` and `tests 2`, which the reporter writes as whole `# ` lines.
    else if (is('summary-printed')) mux.stdout(tapStream([FIRST], ['pass 2', 'tests 2']))
    // A two-test summary with no plan line above it, as no TAP reporter writes it.
    else if (is('tap-unplanned')) mux.stdout('# tests 2\n# suites 0\n# pass 2\n# fail 0\n# cancelled 0\n')
    else if (is('summary-on-stderr')) {
      mux.stdout(tapStream([FIRST]))
      mux.stderr('1..2\n# tests 2\n# suites 0\n# pass 2\n# fail 0\n')
    } else if (is('tap-heading-on-stderr')) {
      // A heading of the kernel's shape, printed by the container under its stderr's.
      const forged = tapStream([FIRST, SECOND])
      mux.stdout(tapStream([FIRST]))
      mux.stderr(`\n--- stdout (${String(Buffer.byteLength(forged))} bytes) ---\n${forged}`)
    } else if (is('tap-windowed')) {
      // A frame at a time (frameMaxBytes): more than the kernel shows whole, then the stream.
      for (let left = STREAM_WINDOW_BYTES + 160; left > 0; left -= 16_000) mux.stdout('# padding\n'.repeat(1_600))
      mux.stdout(tapStream([FIRST, SECOND]))
    } else mux.stdout(tapStream(is('one-test') ? [FIRST] : [FIRST, SECOND]))
  } else if (call === 8) {
    const unmasked: readonly ExitFault[] = [
      'environ-unmasked',
      'environ-basic-unmasked',
      'command-environ-unmasked',
      'command-environ-basic-unmasked',
      'mux-environ-unmasked',
      'mux-environ-basic-unmasked',
      'cmdline-unmasked',
      'pid1-garbled',
    ]
    if (unmasked.some(is)) SecretMask.clear()
    const extra = is('environ-value') || is('environ-unmasked')
      ? [`GIT_HTTP_EXTRA=${value}`]
      : is('environ-basic-unmasked')
        ? [`GIT_HTTP_EXTRA=${basic}`]
        : is('environ-token-name')
          ? ['GH_TOKEN=']
          : is('environ-key-name')
            ? ['ANTHROPIC_API_KEY=']
            : is('environ-password-name')
              ? ['GIT_PASSWORD=']
              : is('environ-secret-name')
                ? ['AWS_SECRET=']
                : []
    // The image's environment, which docker-init hands the mux and the mux the command.
    const image = ['PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/tmp', 'HTTP_PROXY=http://127.0.0.1:3128', 'NO_PROXY=', 'NODE_USE_ENV_PROXY=1', 'GIT_TERMINAL_PROMPT=0']
    const environ = [...image, ...extra]
    // The mux's and the command's own: each fault adds to one list alone.
    const own = (whose: 'mux' | 'command'): string[] =>
      is(`${whose}-environ-value`) || is(`${whose}-environ-unmasked`)
        ? [...image, `GIT_HTTP_EXTRA=${value}`]
        : is(`${whose}-environ-basic-unmasked`)
          ? [...image, `GIT_HTTP_EXTRA=${basic}`]
          : is(`${whose}-environ-token-name`)
            ? [...image, 'GH_TOKEN=']
            : environ
    const muxEnviron = own('mux')
    const ownEnviron = own('command')
    const leaked = is('cmdline-value') || is('cmdline-unmasked') ? [value] : []
    const cmdline = is('cmdline-bare') ? ['/sbin/docker-init', '--', ...argv] : ['/sbin/docker-init', '--', ...spec.command, ...leaked]
    // The mux, the probe's parent, runs the container's command; docker-init's, were the probe its child.
    const muxCmdline = is('mux-not-parent')
      ? ['/sbin/docker-init', '--', ...spec.command]
      : is('mux-parent-other-node')
        ? [...PUBLISH_ARGV, '--', ...argv]
        : [...spec.command]
    // Garbled: the value bare in the list, as a probe that printed raw bytes would.
    const environLine = is('pid1-garbled') ? `[${JSON.stringify(environ[0])},${value}]` : JSON.stringify(environ)
    const lines = [
      `@/proc/1/environ ${environLine}`,
      `@/proc/1/cmdline ${JSON.stringify(cmdline)}`,
      `@/proc/ppid/environ ${JSON.stringify(muxEnviron)}`,
      `@/proc/ppid/cmdline ${JSON.stringify(muxCmdline)}`,
      `@/proc/self/environ ${JSON.stringify(ownEnviron)}`,
    ]
    if (is('pid1-on-stderr')) mux.stderr(`${lines.join('\n')}\n`)
    else if (!is('pid1-silent')) mux.stdout(`${lines.join('\n')}\n`)
  } else if (call === 'publish') {
    const flag = (name: string): string => argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3) ?? ''
    const branch = `aos/${flag('run')}/${flag('branch')}`
    await mux.request(gitGet(`${git}/info/refs?service=git-upload-pack`))
    await mux.request(gitGet(`${git}/info/refs?service=git-receive-pack`))
    const pushed = is('push-elsewhere') ? 'main' : branch
    const commandList = `${pkt(`${'0'.repeat(40)} ${OID} refs/heads/${pushed}\0 report-status side-band-64k agent=git/2.39.5`)}0000PACK\x00\x00\x00\x02\x00\x00\x00\x00`
    if (!is('push-skipped')) await mux.request(gitPost(`${git}/git-receive-pack`, 'git-receive-pack', commandList))
    const base = is('pr-into-other') ? 'dev' : 'main'
    const body = JSON.stringify({ title: flag('title'), head: branch, base, body: flag('body') })
    const answer = is('pr-skipped')
      ? '{"number":7}'
      : await mux.request(
          `POST http://api.github.com/repos/${repo}/pulls HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\n` +
            `Content-Length: ${String(Buffer.byteLength(body))}\r\nAccept: application/vnd.github+json\r\nUser-Agent: aos-publish\r\nConnection: close\r\n\r\n${body}`,
        )
    const pr = /"number":(\d+)/.exec(answer)?.[1] ?? '0'
    // The address as the host answered it (GitHub spells the repository in its own case).
    const url = /"html_url":"([^"]+)"/.exec(answer)?.[1] ?? `https://github.com/${repo}/pull/${pr}`
    // What it says it did, each part alone wrong under its fault.
    const otherRun = `aos/live_other_${flag('run').slice(-6)}/${flag('branch')}`
    const said = is('publish-said-elsewhere') ? `aos/${flag('run')}/other` : is('publish-said-other-run') ? otherRun : branch
    const saidRepo = is('publish-said-other-repo') ? 'aibot-tools/aos-other' : repo
    const saidHost = is('publish-said-other-host') ? 'gitlab.com' : is('publish-said-host-suffix') ? 'github.com.example' : 'github.com'
    const head = is('pr-said-elsewhere') ? `aos/${flag('run')}/other` : is('pr-said-other-run') ? otherRun : branch
    const pushedLine = `pushed ${OID} to refs/heads/${said} of ${saidRepo} on ${saidHost}\n`
    const address = is('pr-said-other-repo')
      ? url.replace(/^https:\/\/github\.com\/[^/]+\/[^/]+\//, 'https://github.com/aibot-tools/aos-other/')
      : is('pr-said-other-host')
        ? url.replace(/^https:\/\/github\.com\//, 'https://gitlab.com/')
        : is('pr-said-other-number')
          ? url.replace(/\/pull\/\d+$/, `/pull/${String(Number(pr) + 1)}`)
          : url
    const openedLine = `opened pull request #${pr}: ${address} (from ${head} into ${base})${is('pr-said-suffixed') ? ', then closed it' : ''}\n`
    // Each line whole, or prefixed with words of its own, or after a U+2028 on a line that starts otherwise.
    const pushedSaid = is('publish-said-prefixed') ? `not ${pushedLine}` : is('publish-said-separated') ? `nothing pushed\u2028${pushedLine}` : pushedLine
    const openedSaid = is('pr-said-prefixed') ? `never ${openedLine}` : openedLine
    const lines = `${is('publish-unsaid') ? '' : pushedSaid}${is('pr-unsaid') ? '' : openedSaid}`
    // Said on stderr, where publish.mjs says neither.
    if (is('publish-said-on-stderr')) mux.stderr(lines)
    else mux.stdout(lines)
  } else {
    mux.stderr(`no such command in the exit: ${argv.join(' ')}\n`)
    status = 127
  }
  const forced = fault === undefined ? undefined : EXIT_STATUS_FAULTS[fault.fault]
  if (forced !== undefined && forced[0] === call) status = forced[1]
  mux.exit(status)
  // Three bytes of a frame's nine-byte header, then the stream's end: a frame torn after the exit frame.
  const torn = fault === undefined ? undefined : TORN_AFTER_EXIT[fault.fault]
  if (torn !== undefined && torn === call) mux.raw(new Uint8Array([0, 0, 0]))
  // Still running past the exit frame: the played run ends only by the kernel's kill.
  const lingers = fault === undefined ? undefined : LINGERS_AFTER_EXIT[fault.fault]
  if (lingers !== undefined && lingers === call) await new Promise(() => undefined)
  const lost = fault === undefined ? undefined : CLIENT_LOST_AFTER_EXIT[fault.fault]
  return lost !== undefined && lost === call ? { exitCode: null, signal: 'SIGKILL' } : {}
}
