// Phase 2 live sandbox tests (egress plan L1): gated, and run against the
// operator's two Colima VMs.
//
// Everything the sandbox and egress plans built was proven against the fake
// driver and a fake docker CLI. These tests take the bodies that
// test/sandbox-bodies.test.ts runs offline on every `npm test`
// (test/helpers/sandbox-bodies.ts) and run them through the real
// DockerDriver, as boot builds it from config/kernel.yaml (defaultDriver), on
// both VMs, with the worker image scripts/build-worker-image.sh built and
// loaded on each, pinned as sandbox.imageId.
//
// TWO GATES, EACH NAMED IN ITS SKIP REASON:
//
//   AOS_LIVE_TESTS=1    the live run at all (D29), as in the other live files.
//   AOS_LIVE_DOCKER=1   a second, separate opt-in for anything that runs
//                       containers on the operator's VMs: each test starts
//                       containers there and kills them by name. A test's
//                       own are named aos-run-live_..., each with its
//                       workspace under <repo>/.aos/workspaces/<domain>,
//                       removed when the test ends; the canary test's two
//                       are named as boot names its canaries,
//                       aos-run-canary-1-<nonce>-<domain>, and share boot's
//                       canary workspace, <mountRoot>/aos_canary, which
//                       stays, as boot's does.
//
// Nothing here reaches GitHub, a model or pmmcp, and no credential is read:
// the containers run --network none, and the one channel carries random bytes.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'

import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { defaultDriver } from '../src/kernel.js'
import { memoryBytes } from '../src/sandbox/limits.js'
import { REPO_ROOT } from './helpers/kernel.js'
import {
  canariesPass,
  channelInputDestroyed,
  channelRoundTrip,
  clientKilledThenKillByName,
  DOMAINS,
  hostileWallclock,
  initReaps,
  killedByName,
  networkLine,
  networkNone,
  nodeProxyWarning,
  type SandboxBodyContext,
} from './helpers/sandbox-bodies.js'
import { withStore } from './helpers/store.js'


const LIVE = process.env['AOS_LIVE_TESTS'] === '1'
const DOCKER = process.env['AOS_LIVE_DOCKER'] === '1'

/** The shipped kernel.yaml, as the daemon reads it: the operator's sandbox.imageId, sockets and mountRoots. */
function shipped(): KernelConfig {
  return parseKernelConfig(parseYaml(readFileSync(join(REPO_ROOT, 'config', 'kernel.yaml'), 'utf8')), { repoRoot: REPO_ROOT })
}

/**
 * The real driver over the shipped config, its probe passed: both VMs answer
 * and each holds the pinned image by its id. Each workspace a body makes is
 * removed when the test ends; what a container wrote there is the
 * operator's own files (virtiofs writes as the operator).
 */
async function liveContext(t: TestContext, config: KernelConfig = shipped()): Promise<SandboxBodyContext> {
  const imageId = config.sandbox.imageId
  assert.ok(imageId !== undefined, 'config/kernel.yaml pins no sandbox.imageId: build the worker image with scripts/build-worker-image.sh and set the id it prints (README "Live sandbox and egress tests")')
  const driver = defaultDriver(config, REPO_ROOT)
  const probe = await driver.probe(AbortSignal.timeout(60_000))
  assert.ok(probe.ok, probe.ok ? '' : `the sandbox probe did not pass: ${probe.why}`)
  const defaults = config.sandbox.defaults
  return {
    driver,
    imageId,
    mountRoots: { trusted: config.sandbox.domains.trusted.mountRoot, hostile: config.sandbox.domains.hostile.mountRoot },
    caps: { memoryMb: Math.ceil((memoryBytes(defaults.memory) ?? 0) / (1024 * 1024)), cpus: defaults.cpus, pids: defaults.pidsLimit },
    pauseMs: 3_000,
    waitMs: 180_000,
    made: (workspace) => {
      t.after(() => rmSync(workspace, { recursive: true, force: true }))
    },
  }
}

// ── 1. no route out ────────────────────────────────────────────────────────

test(
  'network none has no route to 192.168.5.2, host.lima.internal, the other VM or the internet in either VM',
  {
    timeout: 600_000,
    // Reasons inline, where the hygiene rule reads them: each names what to set.
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const reports = await networkNone(await liveContext(t))
    // Each interface with its operstate and addresses (sit0 down []): README's row records them.
    for (const domain of DOMAINS) t.diagnostic(networkLine(domain, reports[domain]))
  },
)

// ── 2. the channel ─────────────────────────────────────────────────────────

test(
  'the -i channel is binary-safe for 64 MiB',
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    // And its stdin's end ends the container: cat exits 0 on EOF.
    const record = await channelRoundTrip(await liveContext(t), 64 * 1024 * 1024)
    // README's NEEDS VALIDATION row and the plan's risk: the wallclock must cover a clone at this rate.
    t.diagnostic(`round trip of ${String(record.bytes)} bytes each way in ${String(record.ms)} ms, about ${String(record.mibPerSecond)} MiB/s through docker -i`)
  },
)

// ── 3. the docker client killed ────────────────────────────────────────────

test(
  'killing the docker client then kill-by-name leaves no aos-run- container',
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const ends = await clientKilledThenKillByName(await liveContext(t))
    for (const [domain, { abandoned, swept }] of Object.entries(ends)) {
      t.diagnostic(`${domain}: the SIGKILLed client ended with exit ${String(abandoned.exitCode)}, signal ${String(abandoned.signal)}, after ${String(abandoned.durationMs)} ms`)
      t.diagnostic(`${domain}: the swept container's client ended with exit ${String(swept.exitCode)}, signal ${String(swept.signal)}, killedBy ${String(swept.killedBy)}`)
    }
  },
)

// ── 3a. a kill by name, and a channel's reader gone ─────────────────────────

test(
  'a kill by name ends a running container with the docker CLI\'s 137, credited to the kill, in either VM',
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const ends = await killedByName(await liveContext(t))
    for (const [domain, end] of Object.entries(ends)) {
      t.diagnostic(`${domain}: killed by name after ${String(end.durationMs)} ms, exit ${String(end.exitCode)}, signal ${String(end.signal)}, killedBy ${String(end.killedBy)}`)
    }
  },
)

test(
  "a channel run whose input is destroyed: whether its docker CLI ends and its container outlives it is recorded, and a kill by name then a sweep leave nothing",
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const record = await channelInputDestroyed(await liveContext(t))
    // README's NEEDS VALIDATION row for `docker run -i` asks exactly these.
    t.diagnostic(
      `with its stdout's reader gone, the docker CLI ${record.cliEndedFirst ? 'ended before any kill' : 'ran on until the kill'}, and the container ${record.containerRanOn ? 'ran on' : 'had stopped'}; ` +
        `the run ended with exit ${String(record.end.exitCode)}, signal ${String(record.end.signal)}, killedBy ${String(record.end.killedBy)}, after ${String(record.end.durationMs)} ms`,
    )
  },
)

// ── 4. the hostile wallclock ───────────────────────────────────────────────

test(
  'a hostile wallclock kills on the hostile socket',
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const end = await hostileWallclock(await liveContext(t), 5_000)
    t.diagnostic(`the hostile run was killed at its 5000 ms wallclock after ${String(end.durationMs)} ms, exit ${String(end.exitCode)}`)
  },
)

// ── 5. PID 1 ───────────────────────────────────────────────────────────────

test(
  "a run's PID 1 is docker-init, which reaps what its command orphans, in either VM",
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const reports = await initReaps(await liveContext(t))
    for (const [domain, report] of Object.entries(reports)) {
      t.diagnostic(`${domain}: PID 1 ${report.pid1}, the command pid ${String(report.self)}, ${String(report.processes.length)} processes, none a zombie`)
    }
  },
)

// ── 6. the canaries ────────────────────────────────────────────────────────

test(
  "both canaries pass, and each VM's self-test meets only the codes the judge accepts",
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const config = shipped()
    const record = await canariesPass(await liveContext(t, config), withStore(t), config.egress.limits)
    // The plan's E9 note: L1 records what each VM gave.
    for (const [domain, codes] of Object.entries(record.codes)) {
      t.diagnostic(`${domain}: ${codes.map(([target, code]) => `${target} ${String(code)}`).join('; ')}`)
    }
  },
)

// ── 7. the image's node ────────────────────────────────────────────────────

test(
  "the image's node reaches nothing through its proxy settings with no channel, and whether it warns that EnvHttpProxyAgent is experimental, and whether a request to its own loopback server goes to the proxy, are recorded",
  {
    timeout: 600_000,
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : false,
  },
  async (t) => {
    const record = await nodeProxyWarning(await liveContext(t))
    // I1's review: L2 must not expect a run's stderr to be empty if it does.
    t.diagnostic(`node ${record.warned ? 'prints' : 'does not print'} the EnvHttpProxyAgent warning; a fetch of its own 127.0.0.1 server was ${record.loopback === 'answered' ? 'answered by it: NO_PROXY empty, Node bypassed the proxy for loopback' : 'refused: it went to the proxy'}`)
    t.diagnostic(`the probe: ${record.stdout.replace(/\n/g, ' | ')}; stderr: ${record.stderr}`)
  },
)
