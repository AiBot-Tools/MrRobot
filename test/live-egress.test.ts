// The Phase 2 exit, live (egress plan L2): gated, and run against the
// operator's trusted Colima VM and GitHub.
//
// The body is test/helpers/egress-bodies.ts phase2Exit, which
// test/sandbox-bodies.test.ts runs offline on every `npm test` against the
// fake driver and an in-process host. Here the kernel boots with egress
// enabled over the real DockerDriver (defaultDriver, from the shipped
// sandbox section: the operator's sockets, mountRoots and pinned
// sandbox.imageId) and the real upstream (systemUpstreamDeps: node:dns and
// tls.connect to the checked address), and the coder of a test-only agents
// dir (exitFleet) clones the fixture repository the shipped github-git and
// github-api bindings name, adds a test, runs the tests, and publishes: a
// push to refs/heads/aos/<runId>/phase2-exit and a pull request into main,
// each approved on the control plane as a human approves one, and only
// while it is the exit's next call, its preview exactly the exit's
// (exitApprovals); any other the gate asks about is denied there first.
//
// THREE GATES, EACH NAMED IN ITS SKIP REASON, and the token:
//
//   AOS_LIVE_TESTS=1    the live run at all (D29).
//   AOS_LIVE_DOCKER=1   it runs containers on the operator's VMs: its boot's
//                       two canaries, named aos-run-canary-<seq>-<nonce>-
//                       <domain> (<seq> the boot's kernel.booted row), in
//                       the canary workspace under each domain's mountRoot
//                       (<mountRoot>/aos_canary), which stays, as boot's
//                       does; and the run's ten containers, named
//                       aos-run-<runId>-<n>, in the run's workspace under
//                       <repo>/.aos/workspaces/trusted, removed when the
//                       test ends, however it ends once run.start has
//                       named the run (phase2Exit's made is told it then).
//   AOS_LIVE_GITHUB=1   it writes to GitHub: a branch under aos/<runId>/ of
//                       the fixture repository and a pull request from it,
//                       which nothing here deletes or closes (the kernel has
//                       no tool that does), so the operator closes them.
//   AOS_GITHUB_TOKEN    the bindings' value, from the shell or the operator's
//                       <repo>/.env through the kernel's own .env loader
//                       (test/helpers/live-env.ts), read only when all three
//                       gates are set (never on `AOS_LIVE_TESTS=1 npm test`
//                       alone, where this file skips) and never printed: a
//                       fine-grained token for the fixture repository alone
//                       (README).
//
// The coder's model is scripted (exitScript): no provider is called, and the
// key the kernel boots with is a stand-in. Nothing reaches pmmcp. A scripted
// model, and the test's approval in place of a person's, are the egress
// plan's Operator decisions entry on the Phase 2 exit's run: until the
// operator accepts them, a pass here is the isolation's, not the exit's.

import { allowHost } from './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { rmSync } from 'node:fs'
import { join } from 'node:path'

import { systemUpstreamDeps, type UpstreamDeps, type UpstreamLimits } from '../src/egress/upstream.js'
import { defaultDriver } from '../src/kernel.js'
import { writeProbeRecord } from '../src/models/probe.js'
import { boundRepo, EXIT_REF, exitFleet, exitKernelYaml, exitScript, liveSandbox, phase2Exit, recording } from './helpers/egress-bodies.js'
import { fakeProvider } from './helpers/fake-provider.js'
import { bootOn, fixture, REPO_ROOT } from './helpers/kernel.js'
import { liveCredential } from './helpers/live-env.js'
import { freshProbe } from './helpers/probe.js'
import { tmpdir } from './helpers/tmpdir.js'

const LIVE = process.env['AOS_LIVE_TESTS'] === '1'
const DOCKER = process.env['AOS_LIVE_DOCKER'] === '1'
const GITHUB = process.env['AOS_LIVE_GITHUB'] === '1'
// From the shell, else <repo>/.env, and only when all three gates are set:
// a Phase 0 or 1 live run (AOS_LIVE_TESTS=1 alone) skips this file and never
// opens .env for it.
const TOKEN = LIVE && DOCKER && GITHUB ? liveCredential('AOS_GITHUB_TOKEN') : undefined

/** The two hosts the bindings name: the only names the kernel's upstream resolves here, and the only ones this process may reach. */
const GITHUB_HOSTS = ['github.com', 'api.github.com']

/**
 * The real upstream's dependencies (systemUpstreamDeps), every answer its
 * resolver gives for the two hosts admitted by the test's network guard as
 * it arrives, inside resolve4 and resolve6: the kernel dials the exact
 * address it checked, which the guard would otherwise refuse as a host it
 * was never told of. The kernel's checkAnswers (src/egress/upstream.ts, over
 * src/egress/addr.ts) then judges each answer unchanged, so an address it
 * refuses is admitted to the guard but never dialled. This widens only what
 * the test process's guard lets through, never what the kernel accepts.
 */
function admitting(revokes: (() => void)[]): (limits: UpstreamLimits) => UpstreamDeps {
  return (limits) => {
    const real = systemUpstreamDeps(limits)
    return {
      ...real,
      resolver: () => {
        const resolver = real.resolver()
        const admit = async (name: string, answer: Promise<string[]>): Promise<string[]> => {
          const addresses = await answer
          if (GITHUB_HOSTS.includes(name)) for (const address of addresses) revokes.push(allowHost(address))
          return addresses
        }
        return {
          resolve4: (name) => admit(name, resolver.resolve4(name)),
          resolve6: (name) => admit(name, resolver.resolve6(name)),
          cancel: () => resolver.cancel(),
        }
      },
    }
  }
}

test(
  'Phase 2 exit: clone, change, test, push aos/<runId>/<branch>, PR opened',
  {
    timeout: 900_000,
    // Reasons inline, where the hygiene rule reads them: each names what to set.
    skip: !LIVE
      ? 'set AOS_LIVE_TESTS=1 to run the live tests (D29)'
      : !DOCKER
        ? 'set AOS_LIVE_DOCKER=1 as well: this runs containers on both Colima VMs, from the worker image pinned as sandbox.imageId'
        : !GITHUB
          ? 'set AOS_LIVE_GITHUB=1 as well: this pushes a branch under aos/<runId>/ to the fixture repository and opens a pull request there, which are not deleted afterwards'
          : TOKEN === undefined
            ? 'AOS_GITHUB_TOKEN is in neither the shell nor .env: add the fixture repository token README names'
            : false,
  },
  async (t) => {
    const value = TOKEN ?? ''
    const revokes: (() => void)[] = []
    for (const host of GITHUB_HOSTS) revokes.push(allowHost(host))
    t.after(() => {
      for (const revoke of revokes) revoke()
    })

    const fx = fixture(t, { kernelYaml: exitKernelYaml(liveSandbox) })
    assert.ok(fx.config.sandbox.imageId !== undefined, 'config/kernel.yaml pins no sandbox.imageId: build the worker image with scripts/build-worker-image.sh and set the id it prints')
    writeProbeRecord(fx.dataDir, freshProbe(EXIT_REF))
    const repo = boundRepo(fx)
    const rec = recording(defaultDriver(fx.config, REPO_ROOT))
    const kernel = await bootOn(t, fx, {
      sandboxDriver: rec.driver,
      // A stand-in key for the scripted model, and the bindings' token.
      env: { ANTHROPIC_API_KEY: 'live-egress-scripted-model-0c4e1a', AOS_GITHUB_TOKEN: value },
      fetch: fakeProvider(exitScript(repo)).fetch,
      agentsDir: exitFleet(join(tmpdir(t), 'agents')),
      egressUpstreamDeps: admitting(revokes),
    })
    const record = await phase2Exit({
      kernel,
      fx,
      specs: rec.specs,
      value,
      timeoutMs: 600_000,
      made: (workspace) => {
        t.after(() => rmSync(workspace, { recursive: true, force: true }))
      },
    })
    // README's checklist records these: the branch and the pull request are the operator's to close.
    t.diagnostic(`runId=${record.runId} branch=aos/${record.runId}/phase2-exit pullRequest=${record.pullRequest} decisions=${String(record.decisions)} approvals=${String(record.approvals.length)}`)
  },
)
