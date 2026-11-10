// T25 — the Docker driver, mount confinement, and the Apple stub.
//
// The argv is the sandbox. Every hardening flag fails OPEN when it is
// missing: the container runs, the work succeeds, and nobody learns the root
// filesystem was writable until something uses it. So each flag is asserted
// on its own rather than as a set — a single assertion over a joined string
// would pass while any one of them silently disappeared.
//
// The falsifiers:
//
//   Drop --read-only, --cap-drop=ALL, --security-opt, --user, --pids-limit,
//   --memory, --cpus, --network or --init and the container is a normal
//   container with a normal attack surface.
//   Pass the REQUEST path to docker instead of the resolved one and the whole
//   confinement check validates one directory and mounts another — a symlink
//   inside the allowed tree pointing at /etc is all it takes.
//   Compare containment without a trailing separator and /data/aos-evil
//   passes as living under /data/aos.
//   Let a second --mount or a -v through and a spec field smuggles in a bind
//   the confinement never saw.
//   Pass the process environment and every provider key the operator exported
//   lands inside a worker (invariant 2), which is the failure the kernel's
//   egress engine (src/egress) exists to prevent in Phase 2, by injecting each
//   credential at the kernel's edge and never in the container, and which must
//   not be possible before it ships.
//   Send a kill to any socket but the one whose daemon holds the container
//   and the answer is "No such container", swallowed as the normal race: the
//   run outlives its hard wallclock and nobody is told. Ask the VMs one after
//   the other, to kill or to list orphans, and a daemon that never answers
//   stops the other's kill. Send a kill for a name without the kernel's
//   prefix and it reaches someone else's container, on both VMs. Report a run
//   killed because a kill was sent, rather than because its exit shows one,
//   and a run that exited 0 on its own reads as killed; credit a 137 to the
//   first kill sent rather than the last, and a run the wallclock ended reads
//   as ended by a requested kill that reached no daemon; credit a 137 when no
//   kill was sent and the OOM killer's reads as an operator kill. Resolve a
//   sweep before its kills return and the boot sweep calls containers still
//   running swept; list orphans with --quiet and docker prints IDs for names,
//   and the sweep kills none. Let the fake end a killed run before kill()
//   returns, or never end one with its own exit, and runtime code tested
//   against it meets neither the held name nor the kill that ends nothing the
//   real driver gives it; let it report a killed run with no output, a null
//   exit code, or a post-kill 137 with no killedBy, and that code meets a
//   result docker never gives.
//   Write a workspace path holding a comma into --mount, or read that value
//   other than as docker's CSV, and a second source= mounts what it names.
//   Let the image slot hold an option, in any spelling, and docker obeys it.
//   Run the image by a tag, or a repository digest, and what runs is whatever
//   image that name last had on the VM; drop --pull=never, or admit another
//   --pull, and a name the VM lacks is fetched by its daemon over the VM's own
//   route, from whatever a registry serves; probe ok with no image id pinned
//   and the kernel reports a sandbox no run can use.
//   Keep everything a container writes and one that writes without end grows
//   the kernel's memory until its wallclock, or past it; stop reading at the
//   cap instead and the container blocks on a full pipe; keep each chunk as
//   its own Buffer and one that writes a byte at a time costs the kernel a few
//   hundred bytes for every byte kept.
//   Admit --user 0:0 or a cap of 0, both well-formed to docker, and the run is
//   root or has no limit.
//   Refuse the options that widen a container (--env, -p, -t, --add-host,
//   --dns, --pid host, seccomp=unconfined, --group-add 0, --log-driver
//   syslog, --read-only=false) only because RUN_OPTIONS does not list them,
//   and the edit that lists one reaches docker with it; read docker's options
//   past the image and `grep -e` is refused as an environment; take any
//   --network value but none, the domain's internal network among them, and a
//   container sits on a network, with peers, an address on the VM and a
//   resolver; read a --network without reading it as docker does and
//   `name=host` is the VM's own network stack. Let a domain name none, host
//   or name=host without refusing it by name, or advise recreating it
//   --internal, and the operator is sent after a command docker refuses.
//   Build a hostile run against the trusted domain's config and it is
//   confined to a share its own VM never mounts.
//   Admit -i on a run that asks for no channel, or a channel on the hostile
//   domain, and a run is joined to the kernel by a way nothing asked for, or
//   the domain that must reach nothing gets a way out; read a channel run's
//   stdout into the result and the bytes meant for its caller are consumed
//   before it listens; leave a channel's 'error' unheard and a container that
//   closes its stdin throws in the kernel; let the fake settle a channel run
//   before its input has ended and runtime code tested against it awaits a
//   result the real driver holds open. Read a spec's channel or domain at
//   each decision rather than once, and a field that answers each read
//   differently gives the hostile domain a channel; stop a run's wallclock
//   at the CLI's close rather than its exit, and a caller holding a channel's
//   input past the deadline reports an overrun that never happened; let the
//   fake keep a channel's output open past its container's exit, or leave an
//   'error' on its channel unheard, and code tested against it meets on the
//   Mac what the fake never showed. Credit a kill sent after the CLI exited
//   with the CLI's 137, and a channel run the OOM killer ended, torn down
//   while its caller drains the input, reads as killed by the kernel. Leave a
//   failed spawn's timer armed and its deadline kills the retry that reused
//   the name. Read the spec again in the wallclock's timer and its kill goes
//   to the other VM. Let the fake's output acknowledge a write its container
//   never read, or keep the container's stdin open after the output ends,
//   and code tested against it never meets backpressure or the end of a
//   channel. Take a field that is not of its type, and a domain whose
//   toString answers trusted and then hostile has a run built for one VM and
//   spawned on the other; drop a field from the copy and no driver sees it.
//   Run a docker command docker.ts's header does not name, on any path, a
//   catch's as much as a healthy daemon's, and its case for a driver with no
//   HOME and no credential helper (what it runs pulls nothing) is made about
//   another driver.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { userInfo } from 'node:os'
import { join } from 'node:path'
import { PassThrough, Readable, Writable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { setFlagsFromString } from 'node:v8'
import { runInNewContext } from 'node:vm'

import ts from 'typescript'

import { tmpdir } from './helpers/tmpdir.js'
import { ConfigError, NotImplementedError } from '../src/errors.js'
import { MAX_LOGGED_OUTPUT } from '../src/events/bound.js'
import { confineWorkspace } from '../src/sandbox/confine.js'
import {
  auditRunArgs,
  buildRunArgs,
  CONTAINER_PREFIX,
  DockerDriver,
  WORKSPACE_TARGET,
  type ChildLike,
  type DockerDefaults,
  type DomainConfig,
} from '../src/sandbox/docker.js'
import { AppleContainerDriver } from '../src/sandbox/apple-container.js'
import { CAPTURE_MAX_BYTES, readSpecOnce, type SandboxDriver, type SandboxResult, type SandboxSpec } from '../src/sandbox/driver.js'
import { fakeSandbox } from './helpers/fake-sandbox.js'

const DEFAULTS: DockerDefaults = { user: '65534:65534', pidsLimit: 256, memory: '2g', cpus: 2 }

/** The pinned worker image (kernel.yaml's sandbox.imageId), as docker prints an id. */
const IMAGE_ID = `sha256:${'0123456789abcdef'.repeat(4)}`

interface Fixture {
  readonly root: string
  readonly mountRoot: string
  readonly workspace: string
  readonly realWorkspace: string
  readonly repoRoot: string
  readonly domain: DomainConfig
  /**
   * The hostile domain, with its own socket, network and mountRoot, as
   * kernel.yaml gives it: one sharing the trusted domain's would let a run
   * built against the wrong domain pass every check.
   */
  readonly hostile: DomainConfig
  readonly hostileWorkspace: string
  readonly realHostileWorkspace: string
}

/**
 * A real directory tree with real symlinks. Confinement is a filesystem
 * question, and a mocked filesystem would only prove the mock agrees with us.
 */
function fixture(t: TestContext): Fixture {
  const root = tmpdir(t)
  const mountRoot = join(root, 'work')
  const hostileRoot = join(root, 'hostile-work')
  const repoRoot = join(root, 'repo')

  mkdirSync(join(mountRoot, 'proj'), { recursive: true })
  mkdirSync(join(hostileRoot, 'proj'), { recursive: true })
  // A sibling whose name has the allowed root as a prefix.
  mkdirSync(join(root, 'work-evil'), { recursive: true })
  mkdirSync(join(root, 'outside'), { recursive: true })
  mkdirSync(join(repoRoot, 'souls'), { recursive: true })
  writeFileSync(join(repoRoot, 'souls', 'ceo.md'), '# ceo\n')

  // Links planted INSIDE the allowed tree, pointing out of it.
  symlinkSync('/etc', join(mountRoot, 'link-to-etc'))
  symlinkSync(join(root, 'outside'), join(mountRoot, 'link-outside'))
  symlinkSync(join(repoRoot, 'souls'), join(mountRoot, 'link-to-souls'))

  return {
    root,
    mountRoot,
    workspace: join(mountRoot, 'proj'),
    // What confinement hands docker: the workspace with every symlink resolved.
    // Requests stay unresolved, as they are in real use; on macOS the temp root
    // itself sits under /var -> /private/var, so the two differ there.
    realWorkspace: realpathSync(join(mountRoot, 'proj')),
    repoRoot,
    domain: { dockerHost: 'unix:///tmp/colima-trusted.sock', network: 'aos-internal', mountRoot },
    hostile: { dockerHost: 'unix:///tmp/colima-hostile.sock', network: 'aos-hostile', mountRoot: hostileRoot },
    hostileWorkspace: join(hostileRoot, 'proj'),
    realHostileWorkspace: realpathSync(join(hostileRoot, 'proj')),
  }
}

function spec(f: Fixture, over: Partial<SandboxSpec> = {}): SandboxSpec {
  return {
    name: `${CONTAINER_PREFIX}abc123`,
    runId: 'run_abc123',
    agentId: 'researcher',
    domain: 'trusted',
    image: IMAGE_ID,
    command: ['node', '--version'],
    // Each domain's own: a workspace is confined to its domain's mountRoot.
    workspace: over.domain === 'hostile' ? f.hostileWorkspace : f.workspace,
    limits: { memoryMb: 2_048, cpus: 2, pids: 256, wallclockMs: 600_000 },
    ...over,
  }
}

function argsFor(f: Fixture, over: Partial<SandboxSpec> = {}, home = join(f.root, 'home')): string[] {
  return buildRunArgs({
    spec: spec(f, over),
    domain: f.domain,
    defaults: DEFAULTS,
    repoRoot: f.repoRoot,
    imageId: IMAGE_ID,
    home,
  })
}

/** The value docker would see for `--flag value`. */
function valueOf(args: readonly string[], flag: string): string | undefined {
  const at = args.indexOf(flag)
  return at === -1 ? undefined : args[at + 1]
}

// ── the flag set ───────────────────────────────────────────────────────────

test('run args contain --read-only, --cap-drop=ALL, --security-opt=no-new-privileges, --user, --pids-limit, --memory, --cpus, --network none, --tmpfs, --init, --rm, --name', (t) => {
  const f = fixture(t)
  const args = argsFor(f)

  // One assertion each. A single check over a joined string would stay green
  // while any one of these quietly disappeared.
  assert.ok(args.includes('--read-only'), '--read-only')
  assert.ok(args.includes('--cap-drop=ALL'), '--cap-drop=ALL')
  assert.ok(args.includes('--security-opt=no-new-privileges'), '--security-opt=no-new-privileges')
  assert.equal(valueOf(args, '--user'), '65534:65534')
  assert.equal(valueOf(args, '--pids-limit'), '256')
  assert.equal(valueOf(args, '--memory'), '2g')
  assert.equal(valueOf(args, '--cpus'), '2')
  assert.equal(valueOf(args, '--network'), 'none')
  assert.equal(valueOf(args, '--tmpfs'), '/tmp:rw,noexec,nosuid,nodev,size=64m')
  assert.ok(args.includes('--init'), '--init')
  assert.ok(args.includes('--rm'), '--rm')
  assert.equal(valueOf(args, '--name'), `${CONTAINER_PREFIX}abc123`)

  // The command runs last, after the image.
  assert.deepEqual(args.slice(-3), [IMAGE_ID, 'node', '--version'])
  assert.equal(valueOf(args, '--workdir'), WORKSPACE_TARGET)
})

test('never --privileged, never docker.sock, never $HOME', (t) => {
  const f = fixture(t)
  const home = join(f.root, 'home')
  mkdirSync(home, { recursive: true })

  assert.equal(argsFor(f).includes('--privileged'), false)

  // Each of these is a way a future edit, or a crafted spec, widens the
  // container. The audit pass runs over the FINISHED argv, so it catches a
  // widening introduced anywhere — including inside spec.command.
  // An empty HOME SKIPS the home check rather than comparing against '',
  // because `arg.startsWith('/')` would otherwise match every absolute path
  // and refuse every container. Confinement to mountRoot is the real
  // protection here; the home check is belt-and-braces on top of it.
  assert.doesNotThrow(() => argsFor(f, {}, ''))

  for (const bad of ['--privileged', '--cap-add=SYS_ADMIN', '--pid=host', '--userns=host']) {
    assert.throws(() => argsFor(f, { command: [bad] }), ConfigError, bad)
  }
  for (const bad of ['/var/run/docker.sock', 'type=bind,source=/var/run/docker.sock,target=/x']) {
    assert.throws(() => argsFor(f, { command: [bad] }), ConfigError, bad)
  }
  // The home directory, as a command argument and as the workspace itself.
  assert.throws(() => argsFor(f, { command: [join(home, 'creds')] }), ConfigError)
  assert.throws(() => argsFor(f, {}, f.workspace), ConfigError, 'workspace === home')
})

test('a HOME reached through a symlink is still refused, under either spelling', (t) => {
  // Found on the operator's Mac: the audit compared the RESOLVED workspace with
  // an UNRESOLVED HOME, so "the workspace is home" went unnoticed whenever a
  // component of HOME was a symlink (on macOS, /var -> /private/var). Built with
  // an explicit link here so it fails on every OS, not only where the temp root
  // happens to sit under one.
  const f = fixture(t)
  const linkedHome = join(f.root, 'home-link')
  symlinkSync(join(f.mountRoot, 'proj'), linkedHome)

  // The workspace resolves to proj; HOME names the same directory through a link.
  assert.throws(() => argsFor(f, {}, linkedHome), /the workspace may never be the home directory/)
  // And a command argument naming home is refused whichever way it is spelled.
  assert.throws(() => argsFor(f, { command: [join(linkedHome, 'creds')] }, linkedHome), ConfigError)
  assert.throws(() => argsFor(f, { command: [join(f.realWorkspace, 'creds')] }, linkedHome), ConfigError)
})

test('an empty HOME is treated as unset: confinement and the run-args audit still see the passwd home', (t) => {
  // os.homedir() answers '' for HOME='', which resolves to the cwd. confine
  // then guarded the cwd instead of $HOME, and the audit skipped its home check
  // entirely. Both must fall back to the passwd entry, as config.ts does.
  const f = fixture(t)
  const passwdHome = userInfo().homedir
  const saved = process.env['HOME']
  process.env['HOME'] = ''
  t.after(() => {
    if (saved === undefined) delete process.env['HOME']
    else process.env['HOME'] = saved
  })
  const named = realpathSync(passwdHome).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  assert.throws(() => confineWorkspace(passwdHome, '/', f.repoRoot), new RegExp(`is or contains \\$HOME \\(${named}\\)`))
  assert.throws(
    () =>
      buildRunArgs({
        spec: spec(f, { command: ['cat', join(passwdHome, 'creds')] }),
        domain: f.domain,
        defaults: DEFAULTS,
        repoRoot: f.repoRoot,
        imageId: IMAGE_ID,
      }),
    /docker args reference the home directory/,
  )
})

test('run args contain exactly one --mount and no -v, and it is the confined workspace', (t) => {
  const f = fixture(t)
  const args = argsFor(f)

  assert.equal(args.filter((a) => a === '--mount').length, 1)
  assert.equal(args.filter((a) => a === '-v' || a === '--volume').length, 0)
  assert.equal(valueOf(args, '--mount'), `type=bind,source=${f.realWorkspace},target=${WORKSPACE_TARGET}`)

  // A spec field cannot smuggle a second bind past the audit.
  assert.throws(
    () => argsFor(f, { command: ['--mount', 'type=bind,source=/etc,target=/etc'] }),
    ConfigError,
  )
  assert.throws(() => argsFor(f, { command: ['-v', '/etc:/etc'] }), ConfigError)
})

test('a workspace whose real path holds a comma, a double quote or a control character never reaches --mount', (t) => {
  // Found in the Phase 2 egress review. Docker reads the --mount value as CSV
  // and keeps the LAST source=, so a real directory `x,source=` under the
  // mountRoot, holding `etc`, passed every containment check and became
  // `type=bind,source=<root>/x,source=/etc,target=/workspace`: the VM's /etc,
  // read-write. The same shape names any VM path, the whole mountRoot, or a
  // named volume.
  const f = fixture(t)
  const refused = /mount confinement: the workspace .* holds a comma, a double quote or a control character/
  const attempts = [join('x,source=', 'etc'), 'x,type=volume', 'a"b', 'line\nbreak', 'tab\there']
  for (const rel of attempts) {
    const dir = join(f.mountRoot, rel)
    mkdirSync(dir, { recursive: true })
    assert.throws(() => argsFor(f, { workspace: dir }), refused, JSON.stringify(rel))
  }
  // Judged on the resolved path, so a harmless-looking link is no way round it.
  symlinkSync(join(f.mountRoot, 'x,source=', 'etc'), join(f.mountRoot, 'innocent'))
  assert.throws(() => argsFor(f, { workspace: join(f.mountRoot, 'innocent') }), refused)
  // Characters with no meaning to docker's CSV reader are paths like any other.
  mkdirSync(join(f.mountRoot, 'a=b c'))
  assert.equal(
    valueOf(argsFor(f, { workspace: join(f.mountRoot, 'a=b c') }), '--mount'),
    `type=bind,source=${realpathSync(join(f.mountRoot, 'a=b c'))},target=${WORKSPACE_TARGET}`,
  )
})

test('the audit reads the --mount value as docker does and admits only type=bind, source=<workspace>, target=/workspace', (t) => {
  // The builder refuses a workspace docker would read as structure; the audit
  // must not depend on that. It is handed the same workspace string the value
  // was built from, so comparing against a filled-in template would pass
  // `source=<ws>,source=/etc` whenever the workspace itself carried the tail.
  const f = fixture(t)
  const home = join(f.root, 'home')
  const ws = f.realWorkspace
  const args = argsFor(f)
  const at = args.indexOf('--mount') + 1
  const withMount = (value: string): string[] => args.map((a, i) => (i === at ? value : a))
  assert.doesNotThrow(() => auditRunArgs(args, home, ws, IMAGE_ID))

  const bad = [
    `type=bind,source=${ws},source=/etc,target=${WORKSPACE_TARGET}`, // docker keeps the last source
    `type=bind,source=${ws},target=${WORKSPACE_TARGET},SOURCE=/etc`, // keys in any case
    `type=bind,source=${ws},src=/etc,target=${WORKSPACE_TARGET}`, // an alias of source
    `type=bind,source=${ws},target=${WORKSPACE_TARGET},dst=/etc`, // an alias of target
    `type=volume,source=${ws},target=${WORKSPACE_TARGET}`,
    `type=bind,source=${ws},target=${WORKSPACE_TARGET},bind-create-src=true`,
    `type=bind,source=${ws},target=${WORKSPACE_TARGET},readonly=false`,
    `type=bind,source=${ws},target=${WORKSPACE_TARGET},ro`, // a field without a value
    `type=bind,source=/etc,target=${WORKSPACE_TARGET}`,
    `type=bind,source=${ws},target=/etc`,
    `type=bind,source=${ws}`,
    // A quoted field may hold a comma, and a line break ends the record. Both
    // are refused by the field checks too, as a split here leaves a field
    // that is no key=value or names no workspace; the two after this list are
    // the cases only the quoting check refuses.
    `type=bind,"source=${ws},x",target=${WORKSPACE_TARGET}`,
    `type=bind,source=${ws},target=${WORKSPACE_TARGET}\nsource=/etc`,
    '',
  ]
  for (const value of bad) {
    assert.throws(() => auditRunArgs(withMount(value), home, ws, IMAGE_ID), ConfigError, JSON.stringify(value))
  }
  // A workspace that itself holds a double quote or a line break, written into
  // the value as the builder writes it, splits at its commas into exactly the
  // three fields wanted. The builder refuses such a workspace (MOUNT_STRUCTURE);
  // the audit is handed it here directly, and refuses it on its own terms,
  // because docker's CSV reader would not read that value as this split does.
  for (const quoted of ['/w/a"b', '/w/a\nb']) {
    assert.throws(
      () => auditRunArgs(withMount(`type=bind,source=${quoted},target=${WORKSPACE_TARGET}`), home, quoted, IMAGE_ID),
      /holds a double quote or a control character, so docker would not split it at its commas/,
      JSON.stringify(quoted),
    )
  }
  // And the case a template comparison misses: the workspace carries the tail.
  const tail = `${ws},source=/etc`
  assert.throws(
    () => auditRunArgs(withMount(`type=bind,source=${tail},target=${WORKSPACE_TARGET}`), home, tail, IMAGE_ID),
    /names source twice/,
  )
})

test('the image slot cannot carry a docker option: everything before the image is exactly what the builder emits', (t) => {
  // Found in the Phase 2 egress review. Docker reads its own options up to the
  // image, so an image of `--volume=/:/host` with a command of `alpine sh` ran
  // alpine with the VM's root mounted, and the audit, which matched exact
  // spellings of a few flags anywhere, let it through. The image comes from
  // operator config today; the audit does not rely on that.
  const f = fixture(t)
  const foreign = /before the image, which the builder never emits, and docker would obey it/
  for (const image of [
    '--volume=/:/host',
    '-v/:/host',
    '--mount=type=bind,source=/,target=/host',
    '--volumes-from=other',
    '--user=0:0',
    '-u0',
    '--read-only=false',
    '--network=container:abc',
    '--network=host',
    '--security-opt=seccomp=unconfined',
    '--cap-drop=NONE',
    '--env=ANTHROPIC_API_KEY',
    '-eANTHROPIC_API_KEY',
    '--publish=8080:80',
    '--',
    '-',
  ]) {
    assert.throws(() => argsFor(f, { image, command: ['alpine', 'sh'] }), foreign, image)
  }

  // A builder option in the image slot is a second copy, and docker keeps the
  // last `--user`, `--tmpfs` over /workspace, `--workdir`: each exactly once.
  for (const [image, value] of [
    ['--user', '0:0'],
    ['--tmpfs', `${WORKSPACE_TARGET}:exec`],
    ['--workdir', '/'],
    ['--network', 'aos-internal'],
  ] as const) {
    assert.throws(
      () => argsFor(f, { image, command: [value, 'alpine', 'sh'] }),
      new RegExp(`carry ${image} 2 time\\(s\\) before the image`),
      image,
    )
  }
  assert.throws(() => argsFor(f, { image: '--rm', command: ['alpine'] }), /carry --rm 2 time\(s\)/)

  // A flag the builder stops emitting is caught by the same count, rather
  // than only by the flag-by-flag test above.
  const home = join(f.root, 'home')
  const args = argsFor(f)
  for (const dropped of ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--init']) {
    assert.throws(
      () => auditRunArgs(args.filter((a) => a !== dropped), home, f.realWorkspace, IMAGE_ID),
      new RegExp(`carry ${dropped} 0 time\\(s\\)`),
      dropped,
    )
  }
  assert.throws(() => auditRunArgs(args.slice(0, args.indexOf(IMAGE_ID)), home, f.realWorkspace, IMAGE_ID), /name no image/)
  // And the argv is a `docker run`: the walk starts after it, and `create`
  // (or any other command) would be judged as though it were run.
  assert.throws(
    () => auditRunArgs(['create', ...args.slice(1)], home, f.realWorkspace, IMAGE_ID),
    /docker args must start with run \(found "create"\)/,
  )
})

test('argv runs a sha256 image id with --pull=never; the audit refuses a tag or a missing --pull=never', (t) => {
  // Egress plan P4. A tag is whatever image was last given it on that VM, and
  // a name the VM lacks is pulled by default, by the VM's daemon over the
  // VM's own route out, which no container network covers. So the run names
  // the pinned id, exactly, and docker is told never to pull.
  const f = fixture(t)
  const home = join(f.root, 'home')
  const args = argsFor(f)
  const at = args.indexOf(IMAGE_ID)
  assert.equal(args.filter((a) => a === IMAGE_ID).length, 1)
  assert.equal(args[at - 1], '--pull=never', 'the last option before the image')
  assert.deepEqual(args.slice(at), [IMAGE_ID, 'node', '--version'])
  assert.deepEqual(args.filter((a) => a.startsWith('--pull')), ['--pull=never'])

  // The spec's image is a request, held to the pinned id: a tag, a
  // repository digest of the very same content, another id, or the pinned id
  // in another spelling is refused, never run.
  const name = (image: string) => (e: unknown): boolean =>
    e instanceof ConfigError &&
    e.message ===
      `docker args run ${JSON.stringify(image)}, which is no image id but a name the VM's daemon resolves to whatever ` +
        `image it last gave that name; the driver runs only the pinned sandbox.imageId ${IMAGE_ID}`
  for (const image of [
    'aos-worker:0.0.1',
    'aos-worker',
    'aos-worker:latest',
    `aos-worker@${IMAGE_ID}`,
    `docker.io/library/aos-worker@${IMAGE_ID}`,
    IMAGE_ID.slice('sha256:'.length),
    IMAGE_ID.toUpperCase(),
    `${IMAGE_ID.slice(0, -1)}`,
    `${IMAGE_ID}0`,
    // Lower case and the right length, but not hex: no digest to docker,
    // which reads the whole string as the tag of repository
    // docker.io/library/sha256, whatever image the VM last gave that name.
    `sha256:${'g'.repeat(64)}`,
    `${IMAGE_ID.slice(0, -1)}g`,
    // The pinned id with whitespace about it: no reference docker reads, and
    // not the pin, which is compared exactly, never trimmed.
    ` ${IMAGE_ID}`,
    `${IMAGE_ID}\n`,
    `${IMAGE_ID} `,
  ]) {
    assert.throws(() => argsFor(f, { image }), name(image), JSON.stringify(image))
  }
  const other = `sha256:${'f'.repeat(64)}`
  assert.throws(
    () => argsFor(f, { image: other }),
    (e: unknown) =>
      e instanceof ConfigError &&
      e.message === `docker args run image ${other}, which is not the pinned sandbox.imageId ${IMAGE_ID}; the driver runs no other`,
  )

  // Exactly one --pull=never: missing (an edit that drops it, or an argv the
  // builder did not make) and a second copy are both refused by the count.
  assert.throws(
    () => auditRunArgs(args.filter((a) => a !== '--pull=never'), home, f.realWorkspace, IMAGE_ID),
    /carry --pull=never 0 time\(s\) before the image; the builder emits it exactly once/,
  )
  assert.throws(
    () => argsFor(f, { image: '--pull=never', command: [IMAGE_ID, 'node'] }),
    /carry --pull=never 2 time\(s\) before the image; the builder emits it exactly once/,
  )
  // And any --pull that pulls is refused for that, by name, beside the
  // builder's or in its place: missing (docker's default) and always. Any
  // other value, an empty one or one docker itself refuses, is refused as a
  // value the builder never writes, without a claim about what docker would
  // make of it. `--pull never` in two elements pulls nothing, and is refused
  // as a spelling the builder never emits.
  const refusal = (why: string): RegExp =>
    new RegExp(
      `^docker args carry (.+) before the image, which the builder never emits, and docker would obey it: it ${why}, which invariant 9 refuses in any spelling$`,
    )
  const PULLS = refusal(
    "has the VM's daemon pull the image over the VM's own route out, when the VM lacks it \\(missing, docker's default\\) or on every run \\(always\\), so that what runs is whatever the registry serves; only never is admitted",
  )
  const UNWRITTEN = refusal(
    'sets --pull to a value the builder never writes, refused whatever docker makes of it, since a later docker may read it as a pull; only never is admitted',
  )
  const pulled = (named: string, why = PULLS) => (e: unknown): boolean =>
    e instanceof ConfigError && why.exec(e.message)?.[1] === named
  for (const [inline, why] of [
    ['--pull=always', PULLS],
    ['--pull=missing', PULLS],
    ['--pull=', UNWRITTEN],
    ['--pull=NEVER', UNWRITTEN],
    ['--pull=never ', UNWRITTEN],
    ['--pull=yes', UNWRITTEN],
  ] as const) {
    assert.throws(() => argsFor(f, { image: inline, command: [IMAGE_ID] }), pulled(JSON.stringify(inline), why), inline)
    assert.throws(
      () => auditRunArgs(args.map((a) => (a === '--pull=never' ? inline : a)), home, f.realWorkspace, IMAGE_ID),
      pulled(JSON.stringify(inline), why),
      `${inline} in place of the builder's`,
    )
  }
  assert.throws(() => argsFor(f, { image: '--pull', command: ['always', IMAGE_ID] }), pulled('--pull "always"'))
  assert.throws(() => argsFor(f, { image: '--pull', command: ['', IMAGE_ID] }), pulled('--pull ""', UNWRITTEN))
  assert.throws(
    () => argsFor(f, { image: '--pull', command: ['never', IMAGE_ID] }),
    (e: unknown) =>
      e instanceof ConfigError &&
      e.message === 'docker args carry "--pull" before the image, which the builder never emits, and docker would obey it',
  )

  // The pinned value itself must be an id, whatever path handed it to the
  // builder: a tag pinned is still a tag, even when the spec names the same.
  for (const pinned of ['aos-worker:0.0.1', `aos-worker@${IMAGE_ID}`, IMAGE_ID.toUpperCase(), `sha256:${'g'.repeat(64)}`, '']) {
    assert.throws(
      () =>
        buildRunArgs({ spec: spec(f, { image: pinned }), domain: f.domain, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: pinned, home }),
      (e: unknown) =>
        e instanceof ConfigError &&
        e.message.startsWith(`docker args cannot be built: sandbox.imageId ${JSON.stringify(pinned)} is no image id: it must be sha256:<64 lower-case hex>`),
      JSON.stringify(pinned),
    )
  }
  // And none pinned refuses every run, naming the key and the script that
  // will make its value.
  assert.throws(
    () => buildRunArgs({ spec: spec(f), domain: f.domain, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: undefined, home }),
    (e: unknown) =>
      e instanceof ConfigError &&
      e.message.startsWith('docker args cannot be built: sandbox.imageId is not set in config/kernel.yaml') &&
      e.message.includes('with --pull=never, and never pulls one') &&
      e.message.includes('scripts/build-worker-image.sh'),
  )
  assert.throws(() => auditRunArgs(args, home, f.realWorkspace, undefined), /sandbox\.imageId is not set/)
  // While the argv the builder made, against the id it was built for, passes.
  assert.doesNotThrow(() => auditRunArgs(args, home, f.realWorkspace, IMAGE_ID))
  assert.throws(() => auditRunArgs(args, home, f.realWorkspace, other), /which is not the pinned sandbox\.imageId/)
})

test('the audit refuses every env, publish, tty, extra-host, dns, namespace-widening and unconfined flag, and a second or unexpected --network', (t) => {
  // Egress plan P3. Each row is a spec field docker would read as an option
  // of its own: the image slot holds the option and, where it takes a value,
  // the command supplies the value and then an image. RUN_OPTIONS refuses all
  // of them already; each row asserts the refusal that NAMES what the option
  // widens, which is the one still standing when an edit widens RUN_OPTIONS
  // and the builder together, and the reason it gives: a refusal that named
  // the option but gave another's reason, or a wrong one, would still refuse,
  // and send the operator after the wrong widening.
  const f = fixture(t)
  const home = join(f.root, 'home')
  const named = (option: string, reason: RegExp) => (e: unknown): boolean => {
    const before = `docker args carry ${option} before the image, which the builder never emits, and docker would obey it: it `
    const after = ', which invariant 9 refuses in any spelling'
    return (
      e instanceof ConfigError &&
      e.message.startsWith(before) &&
      e.message.endsWith(after) &&
      reason.test(e.message.slice(before.length, -after.length))
    )
  }
  /** The refusal of an option the builder never emits, naming nothing it widens. */
  const unnamed =
    (arg: string) =>
    (e: unknown): boolean =>
      e instanceof ConfigError &&
      e.message === `docker args carry ${JSON.stringify(arg)} before the image, which the builder never emits, and docker would obey it`

  const ENV = /^sets variables in the container's environment, where no credential may be \(invariant 2\)/
  const PUBLISH = /^publishes a container port on the VM/
  const TTY = /^allocates a pseudo-terminal/
  const DETACH = /^returns as soon as the container starts/
  const HOSTS = /^writes a name into the container's \/etc\/hosts/
  const DNS = /^sets the container's resolver configuration/
  const HOST_NETWORK = /^puts the container on the VM's own network stack, which reaches the Mac at 192\.168\.5\.2/
  const BRIDGE = /^puts the container on docker's default bridge, which has a route off the VM/
  const NOT_PLAIN = /^names no plain network \(a letter or digit/
  const SECOND_NETWORK = /^names a network beside the builder's --network none, where a worker is on no network at all$/
  const NET = /^is --network under another name, a network beside the builder's --network none, where a worker is on no network at all$/
  const vmNamespace = (what: string): RegExp => new RegExp(`^shares the VM's ${what} namespace with the container`)
  const theirNamespace = (what: string): RegExp => new RegExp(`^shares another container's ${what} namespace with this one`)
  const SECCOMP_OFF = /^removes the seccomp filter/
  const SECCOMP_REPLACED = /^replaces the default seccomp filter/
  const SECCOMP_BUILTIN = /^replaces the daemon's own seccomp profile, if it was configured with one, with docker's built-in one/
  const APPARMOR_OFF = /^removes the AppArmor profile/
  const APPARMOR_REPLACED = /^replaces the default AppArmor profile/
  const NNP_OFF = /^turns no-new-privileges off/
  const OTHER_SECURITY = /^sets a security option the builder never sets/
  const VOLUME = /^binds a path or a volume beside the one workspace mount/
  const GROUP = /^gives the container's user a supplementary group/
  const LOG_DRIVER = /^has the VM's dockerd ship the container's output through a driver the builder never chose/
  const LOG_OPT = /^configures the container's log driver/
  const WRITABLE = /^makes the container's root filesystem writable/
  const CGROUPS = /^makes the container's cgroup filesystem writable/

  const rows: readonly (readonly [image: string, command: readonly string[], named: string, reason: RegExp])[] = [
    // The environment: no credential is ever put there (invariant 2), and
    // --env-file has the CLI read a file on the Mac, .env included.
    ['-e', ['ANTHROPIC_API_KEY', 'alpine'], '-e (--env)', ENV],
    ['-eANTHROPIC_API_KEY', ['alpine'], '-e (--env)', ENV],
    ['-e=ANTHROPIC_API_KEY', ['alpine'], '-e (--env)', ENV],
    ['-ie', ['ANTHROPIC_API_KEY', 'alpine'], '-e (--env)', ENV],
    ['--env', ['ANTHROPIC_API_KEY', 'alpine'], '--env', ENV],
    ['--env=ANTHROPIC_API_KEY', ['alpine'], '--env', ENV],
    ['--env-file', ['/Users/op/MrRobot/.env', 'alpine'], '--env-file', ENV],
    ['--env-file=.env', ['alpine'], '--env-file', ENV],
    // Published ports.
    ['-p', ['8080:80', 'alpine'], '-p (--publish)', PUBLISH],
    ['-p127.0.0.1:8080:80', ['alpine'], '-p (--publish)', PUBLISH],
    ['-P', ['alpine'], '-P (--publish-all)', PUBLISH],
    ['-iP', ['alpine'], '-P (--publish-all)', PUBLISH],
    ['--publish', ['8080:80', 'alpine'], '--publish', PUBLISH],
    ['--publish=8080:80', ['alpine'], '--publish', PUBLISH],
    ['--publish-all', ['alpine'], '--publish-all', PUBLISH],
    // A terminal.
    ['-t', ['alpine'], '-t (--tty)', TTY],
    ['-it', ['alpine'], '-t (--tty)', TTY],
    ['-ti', ['alpine'], '-t (--tty)', TTY],
    ['--tty', ['alpine'], '--tty', TTY],
    ['--tty=true', ['alpine'], '--tty', TTY],
    // A client that returns at once, and the hard wallclock, which lasts as
    // long as the client does, goes with it.
    ['-d', ['alpine'], '-d (--detach)', DETACH],
    ['-dP', ['alpine'], '-d (--detach)', DETACH],
    ['--detach', ['alpine'], '--detach', DETACH],
    ['--detach=true', ['alpine'], '--detach', DETACH],
    // Names and resolvers: host.lima.internal is the Mac, where pmmcp listens.
    ['--add-host', ['host.lima.internal:192.168.5.2', 'alpine'], '--add-host', HOSTS],
    ['--add-host=pmmcp:192.168.5.2', ['alpine'], '--add-host', HOSTS],
    ['--dns', ['192.168.5.3', 'alpine'], '--dns', DNS],
    ['--dns=1.1.1.1', ['alpine'], '--dns', DNS],
    ['--dns-search=lima.internal', ['alpine'], '--dns-search', DNS],
    ['--dns-option', ['ndots:0', 'alpine'], '--dns-option', DNS],
    ['--dns-opt=ndots:0', ['alpine'], '--dns-opt', DNS],
    ['--link', ['other:db', 'alpine'], '--link', /^joins another container's network and copies its environment into this one/],
    // A second network in another spelling, and the networks docker gives a
    // meaning of its own, in every spelling.
    ['--net', ['aos-internal', 'alpine'], '--net', NET],
    ['--net=host', ['alpine'], '--net', NET],
    ['--net=none', ['alpine'], '--net', NET],
    ['--network=aos-internal', ['alpine'], '"--network=aos-internal"', SECOND_NETWORK],
    ['--network=none', ['alpine'], '"--network=none"', SECOND_NETWORK],
    ['--network=host', ['alpine'], '"--network=host"', HOST_NETWORK],
    ['--network', ['host', 'alpine'], '--network "host"', HOST_NETWORK],
    ['--network', ['container:abc', 'alpine'], '--network "container:abc"', /^puts the container in another container's network namespace/],
    ['--network', ['bridge', 'alpine'], '--network "bridge"', BRIDGE],
    ['--network=default', ['alpine'], '"--network=default"', BRIDGE],
    ['--network', ['name=host', 'alpine'], '--network "name=host"', NOT_PLAIN],
    ['--network=NAME=HOST', ['alpine'], '"--network=NAME=HOST"', NOT_PLAIN],
    // A plain HOST is no host mode to docker, which compares mode names
    // case-sensitively, but a network named HOST: refused in any case all the
    // same, for the key=value spelling, which lower-cases (name=HOST is host).
    // A Container:<id> is no container mode either, and no plain name.
    [
      '--network',
      ['HOST', 'alpine'],
      '--network "HOST"',
      /^spells host in another case, which docker reads as a network of that name, but docker's key=value spelling lower-cases \(name=HOST is host\), so no case of host is admitted$/,
    ],
    ['--network=Bridge', ['alpine'], '"--network=Bridge"', /^spells bridge in another case, .*\(name=Bridge is bridge\)/],
    ['--network', ['DEFAULT', 'alpine'], '--network "DEFAULT"', /^spells default in another case, .*\(name=DEFAULT is default\)/],
    ['--network', ['Container:abc', 'alpine'], '--network "Container:abc"', NOT_PLAIN],
    // Namespaces shared with the VM or with another container.
    ['--pid', ['host', 'alpine'], '--pid "host"', vmNamespace('PID')],
    ['--pid=container:abc', ['alpine'], '"--pid=container:abc"', theirNamespace('PID')],
    ['--ipc=host', ['alpine'], '"--ipc=host"', vmNamespace('IPC')],
    ['--ipc', ['container:abc', 'alpine'], '--ipc "container:abc"', theirNamespace('IPC')],
    ['--uts=host', ['alpine'], '"--uts=host"', vmNamespace('UTS')],
    ['--uts', ['host', 'alpine'], '--uts "host"', vmNamespace('UTS')],
    ['--cgroupns=host', ['alpine'], '"--cgroupns=host"', vmNamespace('cgroup')],
    ['--cgroupns', ['host', 'alpine'], '--cgroupns "host"', vmNamespace('cgroup')],
    ['--userns', ['host', 'alpine'], '--userns "host"', vmNamespace('user')],
    // Confinements taken away, in docker's = and older : spellings, and a
    // seccomp file, which the CLI reads on the Mac and sends as the filter.
    ['--security-opt=seccomp=unconfined', ['alpine'], '"--security-opt=seccomp=unconfined"', SECCOMP_OFF],
    ['--security-opt', ['seccomp=unconfined', 'alpine'], '--security-opt "seccomp=unconfined"', SECCOMP_OFF],
    ['--security-opt', ['seccomp:unconfined', 'alpine'], '--security-opt "seccomp:unconfined"', SECCOMP_OFF],
    [
      '--security-opt',
      ['seccomp=/Users/op/allow-all.json', 'alpine'],
      '--security-opt "seccomp=/Users/op/allow-all.json"',
      SECCOMP_REPLACED,
    ],
    // The CLI takes only unconfined and builtin, as spelled, for profiles of
    // docker's own, and reads any other value as a file on the Mac: so
    // UNCONFINED replaces the filter with one read from a file of that name.
    ['--security-opt=seccomp=UNCONFINED', ['alpine'], '"--security-opt=seccomp=UNCONFINED"', SECCOMP_REPLACED],
    ['--security-opt', ['seccomp:Unconfined', 'alpine'], '--security-opt "seccomp:Unconfined"', SECCOMP_REPLACED],
    // And BUILTIN with one read from a file named BUILTIN.
    ['--security-opt=seccomp=BUILTIN', ['alpine'], '"--security-opt=seccomp=BUILTIN"', SECCOMP_REPLACED],
    ['--security-opt', ['seccomp:Builtin', 'alpine'], '--security-opt "seccomp:Builtin"', SECCOMP_REPLACED],
    // builtin, as spelled, is docker's built-in profile, which the daemon then
    // applies in place of any it was configured with (daemon.json's
    // seccomp-profile), a stricter one among them.
    ['--security-opt=seccomp=builtin', ['alpine'], '"--security-opt=seccomp=builtin"', SECCOMP_BUILTIN],
    ['--security-opt', ['seccomp:builtin', 'alpine'], '--security-opt "seccomp:builtin"', SECCOMP_BUILTIN],
    ['--security-opt=apparmor=unconfined', ['alpine'], '"--security-opt=apparmor=unconfined"', APPARMOR_OFF],
    ['--security-opt', ['apparmor:unconfined', 'alpine'], '--security-opt "apparmor:unconfined"', APPARMOR_OFF],
    [
      '--security-opt=systempaths=unconfined',
      ['alpine'],
      '"--security-opt=systempaths=unconfined"',
      /^unmasks the \/proc and \/sys paths docker hides/,
    ],
    ['--security-opt=label=disable', ['alpine'], '"--security-opt=label=disable"', /^changes or disables the SELinux labels/],
    ['--security-opt', ['label:disable', 'alpine'], '--security-opt "label:disable"', /^changes or disables the SELinux labels/],
    ['--security-opt', ['no-new-privileges=false', 'alpine'], '--security-opt "no-new-privileges=false"', NNP_OFF],
    ['--security-opt=no-new-privileges:false', ['alpine'], '"--security-opt=no-new-privileges:false"', NNP_OFF],
    // Docker reads the value with Go's strconv.ParseBool, for which 0 and f
    // are off as much as false is.
    ['--security-opt', ['no-new-privileges=0', 'alpine'], '--security-opt "no-new-privileges=0"', NNP_OFF],
    ['--security-opt=no-new-privileges=f', ['alpine'], '"--security-opt=no-new-privileges=f"', NNP_OFF],
    ['--security-opt=no-new-privileges=F', ['alpine'], '"--security-opt=no-new-privileges=F"', NNP_OFF],
    ['--security-opt=no-new-privileges=FALSE', ['alpine'], '"--security-opt=no-new-privileges=FALSE"', NNP_OFF],
    ['--security-opt', ['no-new-privileges=False', 'alpine'], '--security-opt "no-new-privileges=False"', NNP_OFF],
    // A custom profile replaces the default one. (docker-default, moby's own
    // default profile, replaces nothing: below.)
    ['--security-opt', ['apparmor=lax', 'alpine'], '--security-opt "apparmor=lax"', APPARMOR_REPLACED],
    ['--security-opt=apparmor:unconfined-ish', ['alpine'], '"--security-opt=apparmor:unconfined-ish"', APPARMOR_REPLACED],
    // A profile name is case-sensitive to AppArmor, so these are others:
    // neither is docker-default, nor unconfined.
    ['--security-opt=apparmor=DOCKER-DEFAULT', ['alpine'], '"--security-opt=apparmor=DOCKER-DEFAULT"', APPARMOR_REPLACED],
    ['--security-opt', ['apparmor=UNCONFINED', 'alpine'], '--security-opt "apparmor=UNCONFINED"', APPARMOR_REPLACED],
    // Writable cgroups, in every spelling ParseBool reads as true.
    ['--security-opt', ['writable-cgroups=true', 'alpine'], '--security-opt "writable-cgroups=true"', CGROUPS],
    ['--security-opt=writable-cgroups=1', ['alpine'], '"--security-opt=writable-cgroups=1"', CGROUPS],
    ['--security-opt=writable-cgroups:TRUE', ['alpine'], '"--security-opt=writable-cgroups:TRUE"', CGROUPS],
    ['--security-opt=writable-cgroups=t', ['alpine'], '"--security-opt=writable-cgroups=t"', CGROUPS],
    ['--security-opt', ['writable-cgroups=T', 'alpine'], '--security-opt "writable-cgroups=T"', CGROUPS],
    ['--security-opt=writable-cgroups=True', ['alpine'], '"--security-opt=writable-cgroups=True"', CGROUPS],
    // A key docker 29 does not read is refused by name too, over-named on
    // purpose, since a later docker may read it: seccomp-profile (a daemon
    // setting, no --security-opt key), and a bare disable, which the daemon
    // reads as label=disable though the CLI refuses an option with no value
    // but no-new-privileges.
    ['--security-opt', ['seccomp-profile=/x.json', 'alpine'], '--security-opt "seccomp-profile=/x.json"', OTHER_SECURITY],
    ['--security-opt=disable', ['alpine'], '"--security-opt=disable"', OTHER_SECURITY],
    // Devices past FORBIDDEN_FLAGS' exact --device, another runtime, kernel
    // parameters and another cgroup parent.
    ['--device-cgroup-rule', ['c 1:3 rwm', 'alpine'], '--device-cgroup-rule', /^lets the container use device nodes the default device cgroup denies/],
    ['--device-cgroup-rule=b 8:0 rwm', ['alpine'], '--device-cgroup-rule', /^lets the container use device nodes/],
    ['--gpus', ['all', 'alpine'], '--gpus', /^gives the container the VM's GPUs/],
    ['--gpus=all', ['alpine'], '--gpus', /^gives the container the VM's GPUs/],
    ['--runtime', ['runc-unconfined', 'alpine'], '--runtime', /^runs the container under an OCI runtime the builder never chose/],
    ['--runtime=io.containerd.runc.v2', ['alpine'], '--runtime', /^runs the container under an OCI runtime/],
    ['--sysctl', ['net.ipv4.ip_forward=1', 'alpine'], '--sysctl', /^sets kernel parameters in the container's namespaces/],
    ['--sysctl=kernel.shm_rmid_forced=1', ['alpine'], '--sysctl', /^sets kernel parameters/],
    ['--cgroup-parent', ['/', 'alpine'], '--cgroup-parent', /^puts the container's cgroup under a parent the builder never chose/],
    ['--cgroup-parent=/system.slice', ['alpine'], '--cgroup-parent', /^puts the container's cgroup under a parent/],
    // Mounts beside the one, and the daemon itself.
    ['--volumes-from', ['other', 'alpine'], '--volumes-from', /^mounts every volume another container has/],
    ['--volumes-from=other:ro', ['alpine'], '--volumes-from', /^mounts every volume another container has/],
    ['--volume=/:/host', ['alpine'], '--volume', VOLUME],
    ['-v/:/host', ['alpine'], '-v (--volume)', VOLUME],
    [
      '--mount=type=bind,source=/,target=/host',
      ['alpine'],
      '"--mount=type=bind,source=/,target=/host"',
      /^adds a mount beside the one workspace mount, which the builder writes as --mount <value>/,
    ],
    ['--use-api-socket', ['alpine'], '--use-api-socket', /^mounts the docker API socket, and with it the VM's daemon/],
    // Root's group by another route than --user x:0, which the audit refuses.
    ['--group-add', ['0', 'alpine'], '--group-add', GROUP],
    ['--group-add=root', ['alpine'], '--group-add', GROUP],
    // The VM's dockerd ships the container's output wherever the log options
    // say, 192.168.5.2 (the Mac) among them, over the VM's own route, which
    // the container's --network none does not cover.
    ['--log-driver', ['syslog', 'alpine'], '--log-driver', LOG_DRIVER],
    ['--log-driver=gelf', ['alpine'], '--log-driver', LOG_DRIVER],
    ['--log-opt', ['syslog-address=udp://192.168.5.2:514', 'alpine'], '--log-opt', LOG_OPT],
    ['--log-opt=gelf-address=udp://192.168.5.2:12201', ['alpine'], '--log-opt', LOG_OPT],
    // A writable root filesystem, in every spelling ParseBool reads as off.
    ['--read-only=false', ['alpine'], '"--read-only=false"', WRITABLE],
    ['--read-only=0', ['alpine'], '"--read-only=0"', WRITABLE],
    ['--read-only=F', ['alpine'], '"--read-only=F"', WRITABLE],
    ['--read-only=False', ['alpine'], '"--read-only=False"', WRITABLE],
    ['--read-only=FALSE', ['alpine'], '"--read-only=FALSE"', WRITABLE],
    ['--read-only=f', ['alpine'], '"--read-only=f"', WRITABLE],
  ]
  for (const [image, command, option, reason] of rows) {
    assert.throws(() => argsFor(f, { image, command }), named(option, reason), `${image} ${command.join(' ')}`)
  }

  // What widens nothing is refused all the same, as an option the builder
  // never emits, and is not named for a widening it does not make. A
  // no-new-privileges that ParseBool reads as on (1, t, true) keeps the option
  // on, and a value it cannot read (yes, or false in a case it does not take)
  // is refused by docker; so for writable-cgroups read as false, or not read
  // (true in a case ParseBool does not take). docker-default is docker's own
  // default AppArmor profile, which it applies anyway. A security-opt key in another case (SECCOMP) is no key
  // docker reads, which compares keys case-sensitively, and refuses; and only
  // systempaths=unconfined, as spelled, unmasks anything: the CLI sends any
  // other systempaths on to the daemon, which reads no such key. A namespace
  // mode in another case (HOST, Container:<id>) is no mode docker reads, and
  // --uts, --cgroupns and --userns have no container mode at all. And a
  // --read-only value ParseBool cannot read is refused by docker.
  for (const [image, command, arg] of [
    ['--security-opt=no-new-privileges=1', ['alpine'], '--security-opt=no-new-privileges=1'],
    ['--security-opt', ['no-new-privileges=1', 'alpine'], '--security-opt'],
    ['--security-opt=no-new-privileges=t', ['alpine'], '--security-opt=no-new-privileges=t'],
    ['--security-opt=no-new-privileges=T', ['alpine'], '--security-opt=no-new-privileges=T'],
    ['--security-opt=no-new-privileges=true', ['alpine'], '--security-opt=no-new-privileges=true'],
    ['--security-opt=no-new-privileges:TRUE', ['alpine'], '--security-opt=no-new-privileges:TRUE'],
    ['--security-opt=no-new-privileges=yes', ['alpine'], '--security-opt=no-new-privileges=yes'],
    ['--security-opt', ['no-new-privileges', 'alpine'], '--security-opt'],
    ['--security-opt=apparmor=docker-default', ['alpine'], '--security-opt=apparmor=docker-default'],
    ['--security-opt', ['apparmor:docker-default', 'alpine'], '--security-opt'],
    ['--security-opt=no-new-privileges=fALSE', ['alpine'], '--security-opt=no-new-privileges=fALSE'],
    ['--security-opt', ['no-new-privileges=fAlse', 'alpine'], '--security-opt'],
    ['--security-opt=writable-cgroups=false', ['alpine'], '--security-opt=writable-cgroups=false'],
    ['--security-opt=writable-cgroups=0', ['alpine'], '--security-opt=writable-cgroups=0'],
    ['--security-opt', ['writable-cgroups=yes', 'alpine'], '--security-opt'],
    ['--security-opt=writable-cgroups=tRUE', ['alpine'], '--security-opt=writable-cgroups=tRUE'],
    ['--security-opt=SECCOMP=unconfined', ['alpine'], '--security-opt=SECCOMP=unconfined'],
    ['--security-opt', ['Seccomp:unconfined', 'alpine'], '--security-opt'],
    ['--security-opt=AppArmor=unconfined', ['alpine'], '--security-opt=AppArmor=unconfined'],
    ['--security-opt=LABEL=disable', ['alpine'], '--security-opt=LABEL=disable'],
    ['--security-opt=No-New-Privileges=false', ['alpine'], '--security-opt=No-New-Privileges=false'],
    ['--security-opt=Writable-Cgroups=true', ['alpine'], '--security-opt=Writable-Cgroups=true'],
    ['--security-opt=SYSTEMPATHS=unconfined', ['alpine'], '--security-opt=SYSTEMPATHS=unconfined'],
    ['--security-opt', ['systempaths:unconfined', 'alpine'], '--security-opt'],
    ['--security-opt=systempaths=UNCONFINED', ['alpine'], '--security-opt=systempaths=UNCONFINED'],
    ['--security-opt=systempaths=unconfined,', ['alpine'], '--security-opt=systempaths=unconfined,'],
    ['--pid', ['HOST', 'alpine'], '--pid'],
    ['--pid=HOST', ['alpine'], '--pid=HOST'],
    ['--userns=Host', ['alpine'], '--userns=Host'],
    ['--ipc', ['Container:abc', 'alpine'], '--ipc'],
    ['--uts=HOST', ['alpine'], '--uts=HOST'],
    ['--uts=container:abc', ['alpine'], '--uts=container:abc'],
    ['--cgroupns', ['container:abc', 'alpine'], '--cgroupns'],
    ['--userns=container:abc', ['alpine'], '--userns=container:abc'],
    ['--read-only=fALSE', ['alpine'], '--read-only=fALSE'],
    ['--read-only=yes', ['alpine'], '--read-only=yes'],
  ] as const) {
    assert.throws(() => argsFor(f, { image, command }), unnamed(arg), `${image} ${command.join(' ')}`)
  }

  // An option refused whatever its value is named without it: the value of
  // --env is the one thing the refusal must not repeat.
  assert.throws(
    () => argsFor(f, { image: '--env=AOS_CONTROL_TOKEN=the-value', command: ['alpine'] }),
    (e: unknown) => named('--env', ENV)(e) && !(e as Error).message.includes('the-value'),
  )
  // A letter that takes a value ends its group, as in docker: the t in -u0t
  // is part of --user's value, not a terminal (and -u is refused anyway).
  assert.throws(
    () => argsFor(f, { image: '-u0t', command: ['alpine'] }),
    (e: unknown) => e instanceof ConfigError && !named('-t (--tty)', TTY)(e) && /carry "-u0t" before the image/.test(e.message),
  )
  // The spellings an earlier check meets first are refused there.
  for (const [image, command] of [
    ['--pid=host', ['alpine']],
    ['--userns=host', ['alpine']],
    ['-v', ['/:/host', 'alpine']],
    ['--volume', ['/:/host', 'alpine']],
  ] as const) {
    assert.throws(() => argsFor(f, { image, command }), /invariant 9 forbids|exactly one --mount and no -v/, image)
  }

  // After the image every element is the command's, and docker passes it on
  // unread: none of this is docker's -e, -t, -p or --network.
  const command = [
    'sh', '-c', 'grep -e TODO -r . && ls -t && ssh -p 22 x', '--',
    '-e', 'K=V', '--env', 'K', '-it', '-t', '--tty', '-p', '22', '-P', '--publish=1:1',
    '--add-host', 'a:1.2.3.4', '--dns', '1.1.1.1', '--link', 'y', '--net=host',
    '--network', 'host', '--network=container:abc', '--pid', 'host', '--ipc=host', '--uts=host', '--cgroupns=host',
    '--security-opt', 'seccomp=unconfined', '--volumes-from', 'x', '--env-file', 'f', '--use-api-socket',
    '-d', '--detach', '--gpus', 'all', '--runtime=x', '--sysctl', 'a=b', '--cgroup-parent', 'p',
    '--device-cgroup-rule', 'r', '--network', 'name=host', '--security-opt=disable',
    '--group-add', '0', '--log-driver', 'syslog', '--log-opt=syslog-address=udp://192.168.5.2:514', '--read-only=false',
  ]
  assert.deepEqual(argsFor(f, { command }).slice(-command.length - 1), [IMAGE_ID, ...command])
  // Except to the whole-argv scans, which still read the command: kept until
  // the operator decides, for the count and FORBIDDEN_FLAGS together
  // (docker.ts, before the option walk), so `grep -v` is refused as a second
  // mount and `--device cpu` as a device.
  assert.throws(
    () => argsFor(f, { command: ['grep', '-v', 'x'] }),
    /exactly one --mount and no -v \(found 1 and 1\)/,
  )
  assert.throws(
    () => argsFor(f, { command: ['python', 'train.py', '--device', 'cpu'] }),
    /docker args contain --device, which invariant 9 forbids/,
  )

  // Exactly one --network: a second as the builder writes its own is counted,
  // a second none among them.
  for (const second of ['aos-other', 'none']) {
    assert.throws(
      () => argsFor(f, { image: '--network', command: [second, 'alpine'] }),
      /carry --network 2 time\(s\) before the image/,
      second,
    )
  }
  // And the one there is none, as spelled (egress plan S1): not merely a
  // well-formed name, and not a domain's internal network either, which
  // probe() proves has no route off the VM but which every container on it
  // shares, with an address on the VM and a resolver. A plain NONE is a
  // network called NONE to docker, which compares a network name as spelled.
  const args = argsFor(f)
  const onNetwork = (value: string): string[] => args.map((a, i) => (args[i - 1] === '--network' ? value : a))
  assert.doesNotThrow(() => auditRunArgs(args, home, f.realWorkspace, IMAGE_ID))
  for (const value of ['aos-internal', 'aos-hostile', 'aos-trusted', 'NONE', 'None', 'nonE', 'none2', 'none-']) {
    assert.throws(
      () => auditRunArgs(onNetwork(value), home, f.realWorkspace, IMAGE_ID),
      (e: unknown) =>
        e instanceof ConfigError &&
        e.message === `docker args put the container on network ${JSON.stringify(value)}; invariant 9 needs --network none, no network at all`,
      JSON.stringify(value),
    )
  }
  // No value at all is no plain network name, and is refused as one; and a
  // mode docker gives a name of its own, in the builder's own --network, is
  // refused for what it widens, before the value is held to none.
  assert.throws(() => auditRunArgs(onNetwork(''), home, f.realWorkspace, IMAGE_ID), named('--network ""', NOT_PLAIN))
  assert.throws(() => auditRunArgs(onNetwork('host'), home, f.realWorkspace, IMAGE_ID), named('--network "host"', HOST_NETWORK))
  assert.throws(() => auditRunArgs(onNetwork('bridge'), home, f.realWorkspace, IMAGE_ID), named('--network "bridge"', BRIDGE))
  assert.throws(() => auditRunArgs(onNetwork('name=none'), home, f.realWorkspace, IMAGE_ID), named('--network "name=none"', NOT_PLAIN))
})

test('worker argv carries --network none exactly once and never the domain network', (t) => {
  // Egress plan S1 (the operator, 2026-11-09). A worker has no network at all:
  // its one way out is the kernel's egress engine, over its run's docker -i
  // channel. Each domain's internal network stays, and probe() still proves it
  // internal, as defence in depth (below), but no run is put on it: it never
  // reaches the argv, as --network or in any other element, on either domain.
  const f = fixture(t)
  const home = join(f.root, 'home')
  /** Every network docker would read before the image, in any spelling. */
  const networks = (args: readonly string[]): string[] => {
    const options = args.slice(0, args.indexOf(IMAGE_ID))
    return options.flatMap((a, i) => (a === '--network' ? [options[i + 1] ?? ''] : a.startsWith('--net') ? [a] : []))
  }
  for (const [name, domain] of [['trusted', f.domain], ['hostile', f.hostile]] as const) {
    const args = buildRunArgs({ spec: spec(f, { domain: name }), domain, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: IMAGE_ID, home })
    assert.deepEqual(networks(args), ['none'], name)
    assert.equal(args.filter((a) => a === 'none').length, 1, name)
    assert.equal(args.some((a) => a.includes(domain.network)), false, `${name}: ${domain.network} in ${JSON.stringify(args)}`)
    assert.doesNotThrow(() => auditRunArgs(args, home, name === 'trusted' ? f.realWorkspace : f.realHostileWorkspace, IMAGE_ID), name)
  }

  // The builder does not read the domain's network at all: whatever a domain
  // names, the argv is the one it builds for aos-internal. kernel.yaml and
  // probe() refuse each of these as a domain's network (test/config.test.ts
  // and the probe tests below); none of them can reach a container.
  const reference = argsFor(f)
  for (const network of [
    'aos-hostile',
    'host',
    'HOST',
    'bridge',
    'default',
    'none',
    'NONE',
    'container:abc',
    'name=host',
    'name=aos-internal,alias=x',
    'aos internal',
    '',
    '--privileged',
    '/var/run/docker.sock',
    '-v',
    '--mount',
  ]) {
    assert.deepEqual(
      buildRunArgs({ spec: spec(f), domain: { ...f.domain, network }, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: IMAGE_ID, home }),
      reference,
      JSON.stringify(network),
    )
  }
})

test('the audit refuses a root --user and a --memory, --pids-limit or --cpus that docker reads as no limit', (t) => {
  // Each is well-formed to docker, so the shape of the argv says nothing: 0:0
  // is root, 65534:0 is root's group, and 0 of any cap is no cap. The config
  // schema refuses these too (test/config.test.ts), but a driver can be handed
  // its defaults another way, and the audit is what every argv meets.
  const f = fixture(t)
  const home = join(f.root, 'home')
  const build = (defaults: Partial<DockerDefaults>): string[] =>
    buildRunArgs({ spec: spec(f), domain: f.domain, defaults: { ...DEFAULTS, ...defaults }, repoRoot: f.repoRoot, imageId: IMAGE_ID, home })

  const refused: readonly (readonly [keyof DockerDefaults, string | number])[] = [
    ['user', '0:0'],
    ['user', '0:65534'],
    ['user', '65534:0'],
    ['user', '00:00'],
    ['user', '0'],
    ['user', '65534'],
    ['user', 'root'],
    ['user', '-1:-1'],
    // Past what runc admits, and 2^32 is 0 to any reader that wraps it.
    ['user', '4294967296:4294967296'],
    ['user', '2147483648:1'],
    ['user', ''],
    ['memory', '0'],
    ['memory', '0g'],
    ['memory', '0k'],
    // A bare number is bytes to docker, and a fraction of one is 0.
    ['memory', '512'],
    ['memory', '0.5g'],
    ['memory', '-1g'],
    ['memory', '1t'],
    ['memory', '2gb'],
    ['memory', '9999999999999999g'],
    ['memory', ''],
    ['pidsLimit', 0],
    ['pidsLimit', -1],
    ['pidsLimit', 1.5],
    ['cpus', 0],
    ['cpus', -1],
  ]
  for (const [field, value] of refused) {
    const flag = { user: '--user', memory: '--memory', pidsLimit: '--pids-limit', cpus: '--cpus' }[field]
    assert.throws(
      () => build({ [field]: value }),
      (e: unknown) => e instanceof ConfigError && e.message.startsWith(`docker args carry ${flag} ${JSON.stringify(String(value))}; invariant 9 needs`),
      `${field}: ${JSON.stringify(value)}`,
    )
  }

  for (const [field, value] of [
    ['user', '1:1'],
    ['user', '501:20'],
    ['user', '2147483647:2147483647'],
    ['memory', '6m'],
    ['memory', '512M'],
    ['memory', '64k'],
    ['memory', '2G'],
    ['pidsLimit', 1],
    ['cpus', 0.5],
    ['cpus', 2],
  ] as const) {
    assert.doesNotThrow(() => build({ [field]: value }), `${field}: ${JSON.stringify(value)}`)
  }

  // And in an argv the builder did not make: the audit reads the value after
  // the flag, wherever it came from.
  const args = argsFor(f)
  const swapped = (flag: string, value: string): string[] => args.map((a, i) => (args[i - 1] === flag ? value : a))
  assert.doesNotThrow(() => auditRunArgs(swapped('--user', '1000:1000'), home, f.realWorkspace, IMAGE_ID))
  assert.throws(() => auditRunArgs(swapped('--user', '0:0'), home, f.realWorkspace, IMAGE_ID), /--user "0:0"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--memory', '0'), home, f.realWorkspace, IMAGE_ID), /--memory "0"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--pids-limit', '-1'), home, f.realWorkspace, IMAGE_ID), /--pids-limit "-1"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--cpus', '0.0'), home, f.realWorkspace, IMAGE_ID), /--cpus "0.0"; invariant 9/)
})

// ── confinement ────────────────────────────────────────────────────────────

test('symlink escaping mountRoot, sibling prefix, .. and /etc are refused; proj/../proj allowed', (t) => {
  const f = fixture(t)
  const ok = (p: string): string => confineWorkspace(p, f.mountRoot, f.repoRoot)

  // A link planted inside the allowed tree pointing out of it. A textual
  // check sees a path under mountRoot and waves it through.
  assert.throws(() => ok(join(f.mountRoot, 'link-to-etc')), ConfigError, 'symlink to /etc')
  assert.throws(() => ok(join(f.mountRoot, 'link-outside')), ConfigError, 'symlink outside')
  // The separator is what stops work-evil passing as living under work.
  assert.throws(() => ok(join(f.root, 'work-evil')), ConfigError, 'sibling prefix')
  assert.throws(() => ok(join(f.mountRoot, '..', 'outside')), ConfigError, '..')
  assert.throws(() => ok('/etc'), ConfigError, '/etc')

  // A path that merely LOOKS like an escape but resolves back inside is fine:
  // the rule is about where it lands, not how it is spelled.
  assert.equal(ok(join(f.mountRoot, 'proj', '..', 'proj')), f.realWorkspace)
  assert.equal(ok(f.workspace), f.realWorkspace)

  // A workspace that does not exist would be created by the runtime as root,
  // outside the kernel's control.
  assert.throws(() => ok(join(f.mountRoot, 'not-created-yet')), ConfigError)
})

test('a workspace resolving under a protected root is refused', (t) => {
  const f = fixture(t)

  // The dangerous configuration is a domain whose mountRoot CONTAINS the
  // repository — then confinement is satisfied and invariant 8 is the only
  // thing left standing. (A link pointing out of the mountRoot, as in the
  // previous test, is caught earlier and proves something different.)
  assert.throws(
    () => confineWorkspace(join(f.repoRoot, 'souls'), f.repoRoot, f.repoRoot),
    (e: unknown) => e instanceof ConfigError && /read-only root souls\//.test(e.message),
  )
  // Reached by symlink from inside that same mountRoot, too.
  symlinkSync(join(f.repoRoot, 'souls'), join(f.repoRoot, 'alias-to-souls'))
  assert.throws(
    () => confineWorkspace(join(f.repoRoot, 'alias-to-souls'), f.repoRoot, f.repoRoot),
    (e: unknown) => e instanceof ConfigError && /read-only root souls\//.test(e.message),
  )
  // A sibling directory in the same repo is fine: the rule names three roots,
  // it does not forbid the repository.
  mkdirSync(join(f.repoRoot, 'scratch'), { recursive: true })
  assert.equal(
    confineWorkspace(join(f.repoRoot, 'scratch'), f.repoRoot, f.repoRoot),
    realpathSync(join(f.repoRoot, 'scratch')),
  )
})

test('a workspace that is, or contains, $HOME or the repository is refused on every run, under any spelling', (t) => {
  // config.ts checks the mountRoot once, at boot. A bind mount or a link made
  // since can put $HOME under it, spelled as an innocent workspace; on APFS a
  // case variant does the same. An identity function stands in for that.
  const f = fixture(t)
  const home = join(tmpdir(t), 'op')
  mkdirSync(home)
  mkdirSync(join(f.mountRoot, 'looks-innocent'))
  mkdirSync(join(f.mountRoot, 'repo-again'))
  const aliases: Record<string, string> = {
    [realpathSync(join(f.mountRoot, 'looks-innocent'))]: home,
    [realpathSync(join(f.mountRoot, 'repo-again'))]: f.repoRoot,
  }
  // An alias covers everything beneath it, as a real one would.
  const unalias = (p: string): string => {
    for (const [alias, real] of Object.entries(aliases)) {
      if (p === alias || p.startsWith(`${alias}/`)) return real + p.slice(alias.length)
    }
    return p
  }
  const id = (p: string): string | undefined => {
    try {
      const st = statSync(unalias(p), { bigint: true })
      return `${String(st.dev)}:${String(st.ino)}`
    } catch {
      return undefined
    }
  }
  const confine = (p: string): string => confineWorkspace(p, f.mountRoot, f.repoRoot, { home, id })
  assert.throws(() => confine(join(f.mountRoot, 'looks-innocent')), /is or contains \$HOME/)
  assert.throws(() => confine(join(f.mountRoot, 'repo-again')), /is or contains the repository/)
  assert.equal(confine(f.workspace), f.realWorkspace)

  // And the allowed zone is judged by spelling: a workspace that IS the
  // mountRoot by identity but is spelled elsewhere is outside it.
  const elsewhere = join(tmpdir(t), 'elsewhere')
  mkdirSync(elsewhere)
  aliases[realpathSync(elsewhere)] = f.mountRoot
  assert.throws(() => confine(elsewhere), /outside the domain mountRoot/)
})

test('resolved real path, not the request string, is passed to docker', (t) => {
  const f = fixture(t)
  // A link that resolves back inside the allowed tree. Confinement lets it
  // through — and must hand docker what it resolved to, or the check
  // validated one directory and the container gets another.
  symlinkSync(join(f.mountRoot, 'proj'), join(f.mountRoot, 'alias'))

  const args = argsFor(f, { workspace: join(f.mountRoot, 'alias') })
  assert.equal(valueOf(args, '--mount'), `type=bind,source=${f.realWorkspace},target=${WORKSPACE_TARGET}`)
  assert.equal(args.some((a) => a.includes('alias')), false, 'the request string reached docker')
})

// ── the driver ─────────────────────────────────────────────────────────────

interface FakeChild extends ChildLike {
  close(code: number | null, signal: string | null): void
  /** As Node's child emits 'exit', before 'close', once the process has ended. */
  exit(code: number | null, signal: string | null): void
  /** As Node's child emits 'error', for a spawn that started no process. */
  fail(error: Error): void
}

/** The child's pipes; stdin is none unless a test hands one, as most runs need none. */
type ChildStreams = Pick<ChildLike, 'stdout' | 'stderr'> & Partial<Pick<ChildLike, 'stdin'>>

const SILENT: ChildStreams = { stdout: { on: () => undefined }, stderr: { on: () => undefined } }

function fakeChild(streams: ChildStreams = SILENT): FakeChild {
  const handlers: Record<string, ((...a: never[]) => void)[]> = {}
  const on = (event: string, cb: (...a: never[]) => void): FakeChild => {
    ;(handlers[event] ??= []).push(cb)
    return child
  }
  const child: FakeChild = {
    stdin: streams.stdin ?? null,
    stdout: streams.stdout,
    stderr: streams.stderr,
    on: on as ChildLike['on'],
    close(code, signal) {
      for (const cb of handlers['close'] ?? []) (cb as (c: number | null, s: string | null) => void)(code, signal)
    },
    exit(code, signal) {
      for (const cb of handlers['exit'] ?? []) (cb as (c: number | null, s: string | null) => void)(code, signal)
    },
    fail(error) {
      for (const cb of handlers['error'] ?? []) (cb as (e: Error) => void)(error)
    },
  }
  return child
}

interface Spied {
  readonly driver: DockerDriver
  readonly spawns: { args: readonly string[]; env: Record<string, string> }[]
  readonly execs: { args: readonly string[]; env: Record<string, string> }[]
  readonly child: FakeChild
  setExec(fn: ScriptedExec): void
  /** The next spawn throws this, as Node's spawn does for an argument it refuses. */
  failNextSpawn(error: Error): void
}

type ScriptedExec = (
  args: readonly string[],
  env: Record<string, string>,
) => Promise<{ stdout: string; stderr: string }>

/**
 * A daemon that answers probe() as a healthy one does: its server version,
 * every network internal, and every image asked about present, printed under
 * the id it was asked by.
 */
function healthyDaemon(version: string): ScriptedExec {
  return (args) =>
    Promise.resolve({
      stdout: args[0] === 'network' ? 'true\n' : args[0] === 'image' ? `${args[args.length - 1] ?? ''}\n` : `${version}\n`,
      stderr: '',
    })
}

const TRUSTED_HOST = 'unix:///tmp/colima-trusted.sock'
const HOSTILE_HOST = 'unix:///tmp/colima-hostile.sock'

function driverFor(f: Fixture, streams?: ChildStreams, pinned: { readonly imageId: string | undefined } = { imageId: IMAGE_ID }): Spied {
  const spawns: Spied['spawns'] = []
  const execs: Spied['execs'] = []
  const child = fakeChild(streams)
  let exec: ScriptedExec = () => Promise.resolve({ stdout: '', stderr: '' })
  let spawnFailure: Error | undefined

  const driver = new DockerDriver({
    spawn: (_cmd, args, options) => {
      const failure = spawnFailure
      spawnFailure = undefined
      if (failure !== undefined) throw failure
      spawns.push({ args, env: options.env })
      return child
    },
    execFile: (_cmd, args, options) => {
      execs.push({ args, env: options.env })
      return exec(args, options.env)
    },
    domains: { trusted: f.domain, hostile: f.hostile },
    defaults: DEFAULTS,
    repoRoot: f.repoRoot,
    imageId: pinned.imageId,
    path: '/usr/bin:/bin',
    home: join(f.root, 'home'),
    dockerConfig: join(f.root, 'data', 'docker'),
  })

  return {
    driver,
    spawns,
    execs,
    child,
    setExec(fn) {
      exec = fn
    },
    failNextSpawn(error) {
      spawnFailure = error
    },
  }
}

test('spawn env keys are exactly [DOCKER_CONFIG, DOCKER_HOST, PATH] with a poisoned ANTHROPIC_API_KEY in process.env', (t) => {
  const f = fixture(t)
  const saved = process.env['ANTHROPIC_API_KEY']
  process.env['ANTHROPIC_API_KEY'] = 'POISONED-must-never-enter-a-container'
  t.after(() => {
    if (saved === undefined) delete process.env['ANTHROPIC_API_KEY']
    else process.env['ANTHROPIC_API_KEY'] = saved
  })

  const d = driverFor(f)
  d.driver.run(spec(f))

  const env = d.spawns[0]?.env
  assert.ok(env !== undefined)
  // An EXACT sorted key list, never a subset check: a subset check passes
  // while the whole operator environment rides along beside the two keys we
  // meant to pass.
  assert.deepEqual(Object.keys(env).sort(), ['DOCKER_CONFIG', 'DOCKER_HOST', 'PATH'])
  assert.equal(env['DOCKER_HOST'], 'unix:///tmp/colima-trusted.sock')
  // The kernel's own, empty docker config dir: never the operator's ~/.docker,
  // whose contexts could redirect the CLI and whose helpers hold credentials.
  assert.equal(env['DOCKER_CONFIG'], join(f.root, 'data', 'docker'))
  assert.equal(JSON.stringify(env).includes('POISONED'), false)

  // Each domain reaches its own VM, not a shared one.
  d.driver.run(spec(f, { domain: 'hostile', name: `${CONTAINER_PREFIX}def456` }))
  assert.equal(d.spawns[1]?.env['DOCKER_HOST'], 'unix:///tmp/colima-hostile.sock')
})

test('each run is built against its own domain: a hostile run goes on --network none once, from the hostile mountRoot', (t) => {
  // Each domain's VM mounts its own mountRoot and nothing else, so a run built
  // against the other domain's config is confined to a share its own VM never
  // mounts. Either way it is on no network: never the domain's own, nor the
  // other domain's (egress plan S1).
  const f = fixture(t)
  const d = driverFor(f)
  d.driver.run(spec(f, { domain: 'hostile', name: `${CONTAINER_PREFIX}h1` }))
  d.driver.run(spec(f, { domain: 'trusted', name: `${CONTAINER_PREFIX}t1` }))
  const networks = (args: readonly string[] = []): string[] =>
    args.flatMap((a, i) => (a === '--network' ? [args[i + 1] ?? ''] : a.startsWith('--net') ? [a] : []))

  const [hostile, trusted] = d.spawns.map((s) => s.args)
  assert.deepEqual(networks(hostile), ['none'])
  assert.equal(valueOf(hostile ?? [], '--mount'), `type=bind,source=${f.realHostileWorkspace},target=${WORKSPACE_TARGET}`)
  assert.deepEqual(networks(trusted), ['none'])
  assert.equal(valueOf(trusted ?? [], '--mount'), `type=bind,source=${f.realWorkspace},target=${WORKSPACE_TARGET}`)

  // And a hostile run is confined to the hostile mountRoot: the trusted
  // domain's workspace is outside it.
  assert.throws(
    () => d.driver.run(spec(f, { domain: 'hostile', name: `${CONTAINER_PREFIX}h2`, workspace: f.workspace })),
    /outside the domain mountRoot/,
  )
  assert.equal(d.spawns.length, 2)
})

// ── the channel ────────────────────────────────────────────────────────────

/** How many times `option` stands before the image, where docker reads it. */
function optionCount(args: readonly string[], option: string): number {
  return args.slice(0, args.indexOf(IMAGE_ID)).filter((a) => a === option).length
}

/** The message a run() refusal throws, or '' when the run starts. */
function runRefusal(driver: SandboxDriver, s: SandboxSpec): string {
  try {
    driver.run(s)
  } catch (e) {
    if (e instanceof ConfigError) return e.message
    throw e
  }
  return ''
}

/** A spec whose channel is a value no caller's types admit, as one built outside the type system would carry. */
function channelValued(f: Fixture, channel: unknown): SandboxSpec {
  return Object.assign({}, spec(f), { channel })
}

test('a channel run passes -i and exposes the child stdio; a run without a channel has no -i; a hostile channel spec is refused', async (t) => {
  // Egress plan S2. The channel is the CLI's own stdin and stdout, kept open
  // to the container by docker's -i, and the one way the kernel's egress
  // engine will reach a worker on --network none (W1). A run that asks for
  // none must not carry -i, and a hostile run may not ask: the hostile
  // domain reaches nothing at all.
  const f = fixture(t)
  const home = join(f.root, 'home')

  // The argv: -i exactly once before the image on a channel run, and never on
  // a run without one, whether its spec says false or nothing. --init on
  // every run, channel or not (S2's call): what any command orphans is reaped
  // and a SIGTERM ends it, not only the mux's.
  const withChannel = argsFor(f, { channel: true })
  assert.equal(optionCount(withChannel, '-i'), 1, 'a channel run carries -i once')
  assert.equal(optionCount(withChannel, '--init'), 1, 'a channel run carries --init once')
  assert.equal(valueOf(withChannel, '--network'), 'none')
  assert.deepEqual(withChannel.slice(-3), [IMAGE_ID, 'node', '--version'])
  assert.doesNotThrow(() => auditRunArgs(withChannel, home, f.realWorkspace, IMAGE_ID, true))
  for (const [label, without] of [
    ['channel unset', argsFor(f)],
    ['channel false', argsFor(f, { channel: false })],
  ] as const) {
    assert.equal(without.includes('-i'), false, `${label}: -i`)
    assert.equal(optionCount(without, '--init'), 1, `${label}: --init once`)
    // Nothing but the -i tells the two apart.
    assert.deepEqual(without, withChannel.filter((a) => a !== '-i'), label)
  }

  // The driver: a channel run's spawn carries -i, and its result carries the
  // CLI's own stdout as the channel's input and its stdin as its output.
  const stdin = new PassThrough()
  const stdout = new PassThrough()
  const stderr = new PassThrough()
  const d = driverFor(f, { stdin, stdout, stderr })
  const running = d.driver.run(spec(f, { channel: true }))
  assert.equal(optionCount(d.spawns[0]?.args ?? [], '-i'), 1)
  assert.ok(running.channel !== undefined, 'a channel run has a channel')
  assert.equal(running.channel.input, stdout, "the channel's input is the CLI's stdout")
  assert.equal(running.channel.output, stdin, "the channel's output is the CLI's stdin")
  // The driver reads none of it: no listener, and the stream not flowing, so
  // nothing the container writes is consumed before the caller listens.
  assert.equal(stdout.listenerCount('data'), 0, "the driver listens on a channel run's stdout")
  assert.equal(stdout.readableFlowing, null, "the driver set a channel run's stdout flowing")
  assert.equal(stdin.destroyed, false, "the driver closed a channel run's stdin")
  // Bytes both ways, as given: the container's stdout reaches the reader of
  // the input, and what is written to the output reaches the container.
  stdout.write(Buffer.from([0, 1, 2, 255]))
  assert.deepEqual(running.channel.input.read(), Buffer.from([0, 1, 2, 255]))
  running.channel.output.write(Buffer.from([7, 0, 9]))
  assert.deepEqual(stdin.read(), Buffer.from([7, 0, 9]))
  // Its stderr is still the driver's to keep; its stdout is not, so the
  // result's is empty.
  stderr.write('docker: a warning\n')
  d.child.close(0, null)
  const result = await running.result
  assert.equal(result.stdout, '')
  assert.equal(result.stderr, 'docker: a warning\n')
  assert.equal(result.truncated, false)

  // A run without a channel: no channel on its result, its stdin closed at
  // once, and its stdout captured as ever.
  const plainStdin = new PassThrough()
  const plainOut = new PassThrough()
  const plain = driverFor(f, { stdin: plainStdin, stdout: plainOut, stderr: new PassThrough() })
  const ran = plain.driver.run(spec(f))
  assert.equal('channel' in ran, false, 'a run without a channel has one')
  assert.equal(plainStdin.destroyed, true, "a run without a channel left the CLI's stdin open")
  assert.equal(plain.spawns[0]?.args.includes('-i'), false)
  plainOut.end('ok\n')
  await finished(plainOut)
  plain.child.close(0, null)
  assert.equal((await ran.result).stdout, 'ok\n')

  // A hostile channel: refused by the builder and by the driver before
  // anything starts, naming the domain. The same spec without the channel
  // runs, so it is the channel that was refused.
  const hostile = driverFor(f)
  const asked = spec(f, { domain: 'hostile', channel: true })
  assert.throws(
    () => buildRunArgs({ spec: asked, domain: f.hostile, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: IMAGE_ID, home }),
    /asks for a channel on the hostile domain, whose runs reach nothing at all/,
  )
  assert.match(runRefusal(hostile.driver, asked), /^container aos-run-abc123 asks for a channel on the hostile domain/)
  assert.equal(hostile.spawns.length, 0, 'a refused hostile channel reached docker')
  assert.equal(runRefusal(hostile.driver, spec(f, { domain: 'hostile', channel: false })), '')
  assert.equal(hostile.spawns[0]?.args.includes('-i'), false)

  // And a channel that is no boolean is refused, rather than read as either.
  for (const value of ['true', 1, null, {}]) {
    assert.match(
      runRefusal(driverFor(f).driver, channelValued(f, value)),
      new RegExp(`^container aos-run-abc123: channel must be true or false, and is a value of type ${typeof value}$`),
      String(value),
    )
  }
})

test('the audit admits -i only on a run that asks for a channel, exactly once, and never in another spelling', (t) => {
  const f = fixture(t)
  const home = join(f.root, 'home')
  const ws = f.realWorkspace
  const withChannel = argsFor(f, { channel: true })
  const without = argsFor(f)
  const beforeImage = (args: readonly string[], ...extra: string[]): string[] => {
    const at = args.indexOf(IMAGE_ID)
    return [...args.slice(0, at), ...extra, ...args.slice(at)]
  }
  const noChannel = /carry -i before the image on a run that asks for no channel/

  // A channel run's argv, audited as a run without one: refused, by default
  // as when said, so that a caller that forgets to say is refused -i.
  assert.throws(() => auditRunArgs(withChannel, home, ws, IMAGE_ID), noChannel)
  assert.throws(() => auditRunArgs(withChannel, home, ws, IMAGE_ID, false), noChannel)
  // A run without one, audited as a channel run: the -i it lacks.
  assert.throws(() => auditRunArgs(without, home, ws, IMAGE_ID, true), /carry -i 0 time\(s\) before the image/)
  // Twice is refused.
  assert.throws(() => auditRunArgs(beforeImage(withChannel, '-i'), home, ws, IMAGE_ID, true), /carry -i 2 time\(s\)/)

  // Smuggled through the image slot, -i is refused on a run without a
  // channel, and is a second copy on a run with one.
  assert.throws(() => argsFor(f, { image: '-i', command: [IMAGE_ID, 'node'] }), noChannel)
  assert.throws(() => argsFor(f, { channel: true, image: '-i', command: [IMAGE_ID, 'node'] }), /carry -i 2 time\(s\)/)

  // Every other spelling of an open stdin is no option the builder emits, on
  // a channel run as on any other: only the builder's own -i is admitted.
  const foreign = /before the image, which the builder never emits, and docker would obey it/
  for (const spelling of ['--interactive', '--interactive=true', '-ii', '--attach=stdin', '-astdin']) {
    for (const [channel, args] of [[true, withChannel], [false, without]] as const) {
      assert.throws(() => auditRunArgs(beforeImage(args, spelling), home, ws, IMAGE_ID, channel), foreign, `${spelling}, channel ${String(channel)}`)
    }
  }
  // A channel run that swaps its -i for --interactive carries no -i at all.
  assert.throws(
    () => auditRunArgs(withChannel.map((a) => (a === '-i' ? '--interactive' : a)), home, ws, IMAGE_ID, true),
    foreign,
  )

  // After the image, -i is the command's (`sed -i`, `grep -i`), which docker
  // passes on unread, and the audit too, with or without a channel.
  for (const channel of [false, true]) {
    const args = argsFor(f, { channel, command: ['sed', '-i', 's/a/b/', 'file'] })
    assert.equal(optionCount(args, '-i'), channel ? 1 : 0, `channel ${String(channel)}`)
    assert.deepEqual(args.slice(-5), [IMAGE_ID, 'sed', '-i', 's/a/b/', 'file'])
  }
})

test("a channel run's pipes are its caller's: their errors are heard into stderr, never thrown, and a spawn that started nothing closes them", async (t) => {
  const f = fixture(t)

  // A container that closes its stdin makes the kernel's next write fail
  // (EPIPE). The driver hears it from the start, so a caller whose listener
  // comes late, or never, does not let it throw in the kernel: an 'error'
  // nobody hears would be an uncaught exception in this test as there.
  const stdin = new PassThrough()
  const stdout = new PassThrough()
  const d = driverFor(f, { stdin, stdout, stderr: new PassThrough() })
  const running = d.driver.run(spec(f, { channel: true }))
  stdin.destroy(new Error('write EPIPE'))
  stdout.destroy(new Error('read ECONNRESET'))
  await new Promise((resolve) => setImmediate(resolve))
  d.child.close(0, null)
  const result = await running.result
  assert.equal(result.stderr, 'channel output: write EPIPE\nchannel input: read ECONNRESET\n')
  assert.equal(result.stdout, '')

  // A spawn that started no process: Node leaves its pipes pending, never to
  // end, and the driver closes them, so the input has ended once the result
  // settles, as a started run's has.
  const failedIn = new PassThrough()
  const failedOut = new PassThrough()
  const failed = driverFor(f, { stdin: failedIn, stdout: failedOut, stderr: new PassThrough() })
  const unstarted = failed.driver.run(spec(f, { channel: true }))
  assert.equal(unstarted.channel?.input, failedOut)
  failed.child.fail(new Error('spawn docker ENOENT'))
  const why = await unstarted.result
  assert.equal(why.exitCode, null)
  assert.equal(why.stderr, 'spawn docker ENOENT')
  assert.equal(failedOut.destroyed, true, "the channel's input was left open by a spawn that started nothing")
  assert.equal(failedIn.destroyed, true, "the channel's output was left open by a spawn that started nothing")

  // And a child given no pipes at all (Node's spawn that failed for want of
  // file descriptors) has no channel to hand over; its 'error' ends the run.
  const bare = driverFor(f, { stdin: null, stdout: null, stderr: null })
  const pipeless = bare.driver.run(spec(f, { channel: true }))
  assert.equal('channel' in pipeless, false)
  bare.child.fail(new Error('spawn docker EMFILE'))
  assert.equal((await pipeless.result).exitCode, null)
})

test('the fake and the real driver agree on the channel: refused in the same words, none on a run without one, and a channel run keeps no stdout', async (t) => {
  // Runtime code (W1) is tested against the fake. Had the fake run a hostile
  // channel, or given a channel to a run that asked for none, code that
  // passed against it would meet a refusal, or no channel, on the Mac.
  const f = fixture(t)

  // Refused before anything starts, in the real driver's words, and with no
  // scripted exit spent: the fake's first exit still answers the next run.
  const real = driverFor(f)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 0 }, { hangs: true }, { hangs: true }] })
  for (const refused of [spec(f, { domain: 'hostile', channel: true }), channelValued(f, 'true'), channelValued(f, 0)]) {
    const said = runRefusal(real.driver, refused)
    assert.notEqual(said, '', `the real driver ran ${JSON.stringify(refused.channel)} on ${refused.domain}`)
    assert.equal(runRefusal(fake, refused), said)
  }
  assert.equal(real.spawns.length, 0)
  assert.equal(fake.channels.length, 0)

  // No channel on a run without one, on either.
  const plainReal = real.driver.run(spec(f))
  const plainFake = fake.run(spec(f))
  assert.equal('channel' in plainReal, false)
  assert.equal('channel' in plainFake, false)
  real.child.close(0, null)
  await Promise.all([plainReal.result, plainFake.result])

  // A channel on a channel run, on either: an input to read and an output
  // to write, and a result with no stdout, whatever the container wrote.
  const io = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() }
  const realChannel = driverFor(f, io)
  const channelReal = realChannel.driver.run(spec(f, { channel: true }))
  const channelFake = fake.run(spec(f, { channel: true, name: `${CONTAINER_PREFIX}chan` }))
  for (const running of [channelReal, channelFake]) {
    assert.ok(running.channel?.input instanceof Readable)
    assert.ok(running.channel.output instanceof Writable)
  }
  assert.equal(fake.channels.length, 1)
  const container = fake.channels[0]
  assert.ok(container !== undefined)
  assert.equal(container.name, `${CONTAINER_PREFIX}chan`)
  // The fake's container ends, both ways: what the container writes is the
  // input, and what the kernel writes to the output the container reads.
  container.stdout.write('from the container')
  assert.equal(String(channelFake.channel?.input.read()), 'from the container')
  channelFake.channel?.output.write('from the kernel')
  assert.equal(String(container.stdin.read()), 'from the kernel')
  io.stdout.end('frames, not output')
  channelReal.channel?.input.resume()
  await finished(io.stdout)
  realChannel.child.close(0, null)
  await fake.kill(`${CONTAINER_PREFIX}chan`)
  for (const result of await Promise.all([channelReal.result, channelFake.result])) assert.equal(result.stdout, '')

  // The fake settles a channel run only once its input has ended, as the
  // real driver's CLI closes only once its pipes have: a reader that pauses
  // on every chunk, with a chunk still unread, holds the result open.
  const hung = fake.run(spec(f, { channel: true, name: `${CONTAINER_PREFIX}held` }))
  const held = fake.channels[1]
  const input = hung.channel?.input
  assert.ok(held !== undefined && input !== undefined)
  held.stdout.write('one chunk')
  held.stdout.write('and another')
  const got: string[] = []
  input.on('data', (chunk) => {
    got.push(String(chunk))
    input.pause()
  })
  input.pause()
  let settled = false
  void hung.result.then(() => {
    settled = true
  })
  await fake.kill(`${CONTAINER_PREFIX}held`)
  // The kill ends the run on a later macrotask, which resumes the input, as
  // Node resumes a child's stdout when it exits; the reader pauses again.
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(got, ['one chunk'])
  assert.equal(settled, false, 'the fake settled a channel run whose input had not ended')
  input.resume()
  const result = await hung.result
  assert.deepEqual(got, ['one chunk', 'and another'])
  assert.equal(settled, true)
  assert.equal(result.killedBy, 'requested')
  assert.equal(result.stdout, '')

  // And a script may not give a channel run stdout, which the real driver
  // never keeps for one.
  const scripted = fakeSandbox({ imageId: IMAGE_ID, script: [{ stdout: 'frames' }] })
  assert.throws(() => scripted.run(spec(f, { channel: true })), /stdout on a channel run/)
})

/**
 * `base`, with `field` read through a getter that answers `first` on its
 * first read and `then` on every later one: a spec built outside the type
 * system, as a getter or a Proxy would hand a driver, that a driver reading
 * a field twice judges by one value and runs by another.
 */
function flipping(base: SandboxSpec, field: 'channel' | 'domain', first: unknown, then: unknown): SandboxSpec {
  let reads = 0
  const flipped = { ...base }
  Object.defineProperty(flipped, field, { enumerable: true, get: () => (reads++ === 0 ? first : then) })
  return flipped
}

/** `base` behind a Proxy that counts each read of each of its fields. */
function counting(base: SandboxSpec): { readonly spec: SandboxSpec; readonly reads: Map<string, number> } {
  const reads = new Map<string, number>()
  const spec = new Proxy(base, {
    get(target, key, receiver) {
      if (typeof key === 'string') reads.set(key, (reads.get(key) ?? 0) + 1)
      return Reflect.get(target, key, receiver) as unknown
    },
  })
  return { spec, reads }
}

test('a spec is read once: a channel or a domain that answers each read differently is judged and run from one reading, by the builder, the driver and the fake', async (t) => {
  // A spec the kernel builds is plain data, but a driver decides several
  // things from one field: the domain picks the VM and its mountRoot and
  // judges the channel, and the channel decides the -i and whether the
  // result hands over the CLI's pipes. Read at each decision, a field that
  // answers differently would have the hostile domain judged as having no
  // channel and then given one, or judged as the trusted domain and then
  // run on its own VM with a channel.
  // The wallclock is fired below, so that what its timer does is made from
  // the one reading too: its kill, aimed at a domain read again, would go to
  // the other VM, swallowed there as "No such container".
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const home = join(f.root, 'home')
  const hostile = spec(f, { domain: 'hostile' })

  // The builder: a hostile channel that reads false and then true is built
  // as it was judged, without -i.
  const built = buildRunArgs({
    spec: flipping(hostile, 'channel', false, true),
    domain: f.hostile,
    defaults: DEFAULTS,
    repoRoot: f.repoRoot,
    imageId: IMAGE_ID,
    home,
  })
  assert.equal(optionCount(built, '-i'), 0, 'a hostile spec judged to have no channel was built with -i')

  // The driver: the same spec runs on the hostile VM without -i, with no
  // channel on its result, and its CLI's stdin closed.
  const stdin = new PassThrough()
  const d = driverFor(f, { stdin, stdout: new PassThrough(), stderr: new PassThrough() })
  const ran = d.driver.run(flipping(hostile, 'channel', false, true))
  assert.equal(d.spawns[0]?.env['DOCKER_HOST'], HOSTILE_HOST)
  assert.equal(optionCount(d.spawns[0]?.args ?? [], '-i'), 0)
  assert.equal('channel' in ran, false, 'a hostile run judged to have no channel was handed one')
  assert.equal(stdin.destroyed, true)
  d.child.close(0, null)
  await ran.result

  // A channel spec whose domain reads hostile and then trusted is judged on
  // the hostile domain, and refused before docker is asked anything.
  const asked = spec(f, { domain: 'hostile', channel: true })
  const refusedOn = driverFor(f)
  assert.match(runRefusal(refusedOn.driver, flipping(asked, 'domain', 'hostile', 'trusted')), /asks for a channel on the hostile domain/)
  assert.equal(refusedOn.spawns.length, 0)
  // And one whose domain reads trusted and then hostile runs on the trusted
  // domain throughout: its VM, its mountRoot, its channel, and a kill aimed
  // at it alone.
  const io = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() }
  const trusted = driverFor(f, io)
  const held = trusted.driver.run(flipping(spec(f, { channel: true }), 'domain', 'trusted', 'hostile'))
  const [spawned] = trusted.spawns
  assert.ok(spawned !== undefined)
  assert.equal(spawned.env['DOCKER_HOST'], TRUSTED_HOST)
  assert.equal(valueOf(spawned.args, '--mount'), `type=bind,source=${f.realWorkspace},target=${WORKSPACE_TARGET}`)
  assert.equal(optionCount(spawned.args, '-i'), 1)
  assert.equal(held.channel?.output, io.stdin)
  await trusted.driver.kill(held.name)
  assert.deepEqual(trusted.execs.map((e) => e.env['DOCKER_HOST']), [TRUSTED_HOST])
  io.stdout.end()
  held.channel?.input.resume()
  trusted.child.close(137, null)
  assert.equal((await held.result).killedBy, 'requested')
  // Its wallclock as well: a run whose domain reads trusted and then hostile
  // is killed at its deadline on the trusted VM, and on no other.
  const timed = driverFor(f, { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() })
  const late = timed.driver.run(flipping(spec(f, { name: `${CONTAINER_PREFIX}timed` }), 'domain', 'trusted', 'hostile'))
  assert.equal(timed.spawns[0]?.env['DOCKER_HOST'], TRUSTED_HOST)
  t.mock.timers.tick(600_000)
  assert.deepEqual(killsSent(timed), [`${TRUSTED_HOST} ${CONTAINER_PREFIX}timed`], "the wallclock's kill went to a domain read again")
  timed.child.close(137, null)
  assert.equal((await late.result).killedBy, 'wallclock')

  // The fake, the same: no channel for the hostile spec read false first,
  // and a refusal for the channel spec read hostile first.
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 0 }] })
  const fakeRan = fake.run(flipping(hostile, 'channel', false, true))
  assert.equal('channel' in fakeRan, false, 'the fake handed a channel to a hostile run it judged to have none')
  assert.equal(fake.channels.length, 0)
  await fakeRan.result
  assert.match(runRefusal(fake, flipping(asked, 'domain', 'hostile', 'trusted')), /asks for a channel on the hostile domain/)

  // Each field of the spec is read once, and only once, by each of them.
  const once = (label: string, reads: ReadonlyMap<string, number>): void => {
    assert.deepEqual(
      [...reads].filter(([, n]) => n !== 1),
      [],
      `${label} read a field of the spec more than once`,
    )
    for (const field of ['name', 'domain', 'channel', 'image', 'command', 'workspace', 'limits']) {
      assert.equal(reads.get(field), 1, `${label}: ${field}`)
    }
  }
  const forBuilder = counting(spec(f, { channel: true }))
  buildRunArgs({ spec: forBuilder.spec, domain: f.domain, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: IMAGE_ID, home })
  once('buildRunArgs', forBuilder.reads)
  const forDriver = counting(spec(f, { channel: true, name: `${CONTAINER_PREFIX}counted` }))
  const driven = driverFor(f, { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() })
  const counted = driven.driver.run(forDriver.spec)
  // Its wallclock fires, and what the timer sends counts with the rest.
  t.mock.timers.tick(600_000)
  assert.deepEqual(killsSent(driven), [`${TRUSTED_HOST} ${CONTAINER_PREFIX}counted`])
  await driven.driver.kill(counted.name)
  counted.channel?.input.resume()
  driven.child.close(137, null)
  assert.equal((await counted.result).killedBy, 'wallclock')
  once('the docker driver', forDriver.reads)
  const forFake = counting(spec(f, { channel: true }))
  const fakeCounted = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 0 }] })
  await fakeCounted.run(forFake.spec).result
  once('the fake', forFake.reads)
})

test('a spec field that is not of its type is refused before anything is decided from it, by the builder, the driver and the fake, in the same words', async (t) => {
  // One reading holds only for a value that is what its type says. A domain
  // that is an object is converted at each use as a property key: one whose
  // toString answers trusted and then hostile would have the run built
  // against the trusted domain's mountRoot and workspace, and spawned and
  // killed on the hostile VM, however few times the field was read.
  const f = fixture(t)
  const home = join(f.root, 'home')
  let conversions = 0
  const shifty = { toString: () => (conversions++ === 0 ? 'trusted' : 'hostile') }
  const typed = (over: Record<string, unknown>): SandboxSpec => Object.assign({}, spec(f), over)
  const limits = spec(f).limits
  const who = `container ${CONTAINER_PREFIX}abc123`
  for (const [label, bad, said] of [
    ['a domain whose toString flips', typed({ domain: shifty }), `${who}: domain must be 'trusted' or 'hostile', and is a value of type object`],
    ['a domain in another case', typed({ domain: 'Trusted' }), `${who}: domain must be 'trusted' or 'hostile', and is another string`],
    ['no domain', typed({ domain: undefined }), `${who}: domain must be 'trusted' or 'hostile', and is a value of type undefined`],
    ['a name that is no string', typed({ name: { toString: () => `${CONTAINER_PREFIX}abc123` } }), 'a container spec: name must be a string, and is a value of type object'],
    ['a runId that is no string', typed({ runId: 7 }), `${who}: runId must be a string, and is a value of type number`],
    ['an agentId that is null', typed({ agentId: null }), `${who}: agentId must be a string, and is null`],
    ['an image that is no string', typed({ image: { toString: () => IMAGE_ID } }), `${who}: image must be a string, and is a value of type object`],
    ['a command that is a string', typed({ command: 'node --version' }), `${who}: command must be an array of strings, and is a value of type string`],
    ['a command with an argument that is no string', typed({ command: ['node', 1] }), `${who}: command[1] must be a string, and is a value of type number`],
    ['a workspace that is no string', typed({ workspace: { toString: () => f.workspace } }), `${who}: workspace must be a string, and is a value of type object`],
    ['no limits', typed({ limits: null }), `${who}: limits must be an object, and is null`],
    ['a wallclock that is a string', typed({ limits: { ...limits, wallclockMs: '5000' } }), `${who}: limits.wallclockMs must be a number, and is a value of type string`],
    ['a pids cap that is missing', typed({ limits: { memoryMb: 1, cpus: 1, wallclockMs: 5_000 } }), `${who}: limits.pids must be a number, and is a value of type undefined`],
  ] as const) {
    conversions = 0
    assert.throws(
      () => buildRunArgs({ spec: bad, domain: f.domain, defaults: DEFAULTS, repoRoot: f.repoRoot, imageId: IMAGE_ID, home }),
      (e: unknown) => e instanceof ConfigError && e.message === said,
      `buildRunArgs: ${label}`,
    )
    const real = driverFor(f)
    assert.equal(runRefusal(real.driver, bad), said, `the docker driver: ${label}`)
    assert.equal(real.spawns.length, 0, `the docker driver spawned ${label}`)
    // With no scripted exit spent: the fake's one exit still answers a run.
    const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 0 }] })
    assert.equal(runRefusal(fake, bad), said, `the fake: ${label}`)
    await fake.run(spec(f)).result
  }
  // Converted at no point: the refusal names the type and never the value.
  assert.equal(conversions, 0)
})

test('readSpecOnce copies every field of a spec, and every field of its limits, and no other', () => {
  // Required<SandboxSpec> has a test name every field, so that a field added
  // to the interface fails to compile here until it is set; and one that
  // readSpecOnce then dropped would be a field no driver ever sees, which
  // for one that restricts a run fails open.
  const full: Required<SandboxSpec> = {
    name: `${CONTAINER_PREFIX}full`,
    runId: 'run_full',
    agentId: 'researcher',
    domain: 'trusted',
    image: IMAGE_ID,
    command: ['node', '--version'],
    workspace: '/work/proj',
    limits: { memoryMb: 512, cpus: 1, pids: 64, wallclockMs: 5_000 },
    channel: true,
  }
  const copy = readSpecOnce(full)
  assert.deepEqual(Object.keys(copy).sort(), Object.keys(full).sort())
  assert.deepEqual(Object.keys(copy.limits).sort(), Object.keys(full.limits).sort())
  assert.deepEqual(copy, full)
  assert.notEqual(copy.command, full.command)
  assert.notEqual(copy.limits, full.limits)
  assert.equal(Object.isFrozen(copy) && Object.isFrozen(copy.command) && Object.isFrozen(copy.limits), true)
  // An absent channel stays absent rather than becoming an own key.
  const { channel: _channel, ...withoutChannel } = full
  assert.equal('channel' in readSpecOnce(withoutChannel), false)
  // And a field no SandboxSpec has is not carried: a spec has no seam for
  // extra arguments, mounts or environment.
  assert.equal('env' in readSpecOnce(Object.assign({}, full, { env: { A: '1' } })), false)
})

test("a run's wallclock and duration end at the CLI's exit: a channel caller that holds the input past the deadline is no overrun", async (t) => {
  // A channel run's CLI closes only once its stdout has ended, and its caller
  // decides when that is: an egress session paused on a full flow, or
  // draining, holds it. A container that exited in time is not overrun by
  // the hold, and its wallclock sends no kill to a container that is gone.
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
  const f = fixture(t)
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  for (const channel of [true, false]) {
    const stdout = new PassThrough()
    const d = driverFor(f, { stdin: new PassThrough(), stdout, stderr: new PassThrough() })
    const running = d.driver.run(spec(f, { channel, limits }))
    t.mock.timers.tick(4_000)
    // The container exits on its own, a second before its wallclock, and the
    // CLI with it; its stdout is held open past the deadline.
    d.child.exit(0, null)
    t.mock.timers.tick(10_000)
    assert.deepEqual(d.execs, [], `channel ${String(channel)}: the wallclock sent a kill after the CLI had exited`)
    stdout.end()
    if (channel) running.channel?.input.resume()
    d.child.close(0, null)
    const result = await running.result
    assert.equal(result.overran, undefined, `channel ${String(channel)}: overran`)
    assert.equal(result.killedBy, undefined, `channel ${String(channel)}: killedBy`)
    assert.equal(result.exitCode, 0)
    assert.equal(result.durationMs, 4_000, `channel ${String(channel)}: the duration counts the hold`)
  }

  // A CLI that has not exited by its deadline is still killed by it, the
  // exit coming after the kill and the close after that.
  const d = driverFor(f, { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() })
  const late = d.driver.run(spec(f, { channel: true, limits }))
  t.mock.timers.tick(5_000)
  assert.deepEqual(d.execs[0]?.args, ['kill', '--signal=KILL', `${CONTAINER_PREFIX}abc123`])
  t.mock.timers.tick(250)
  d.child.exit(137, null)
  late.channel?.input.resume()
  d.child.close(137, null)
  const killed = await late.result
  assert.equal(killed.killedBy, 'wallclock')
  assert.equal(killed.overran, true)
  assert.equal(killed.durationMs, 5_250)
})

test('a channel run on the fake that does not hang exits inside run(): its container ends are closed when run() returns, and its result settles only once its input has ended', async (t) => {
  // The fake's non-hanging script is a container that exits at once. Its
  // result must still wait for its input to end, as the real driver's waits
  // for the CLI's pipes; and what its container can no longer do (write to
  // its stdout, read the kernel's writes) is refused as the real one is.
  const f = fixture(t)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 3, stderr: 'bye\n' }] })
  const running = fake.run(spec(f, { channel: true }))
  const input = running.channel?.input
  const output = running.channel?.output
  const container = fake.channels[0]
  assert.ok(input !== undefined && output !== undefined && container !== undefined)
  const order: string[] = []
  input.on('end', () => order.push('input end'))
  void running.result.then(() => order.push('result'))

  // Its container has exited: its stdout is ended, and a write to it throws,
  // naming the run, rather than becoming an 'error' on the kernel's input.
  assert.equal(container.stdout.writableEnded, true)
  assert.throws(
    () => container.stdout.write('late'),
    /^Error: fake sandbox: a write to the container stdout of aos-run-abc123 after its container exited\. A run scripted without hangs/,
  )
  assert.throws(() => container.stdout.end('late'), /after its container exited/)
  // Its channel's output is destroyed, as Node destroys a child's stdin when
  // it exits: a write fails in its callback, and nothing throws.
  assert.equal(output.destroyed, true)
  const refused = await new Promise<Error | null | undefined>((resolve) => {
    output.write('to nobody', resolve)
  })
  assert.match(String(refused), /Cannot call write after a stream was destroyed/)

  const result = await running.result
  assert.deepEqual(order, ['input end', 'result'], 'the fake settled a channel run before its input had ended')
  assert.equal(result.exitCode, 3)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr, 'bye\n')
  assert.equal(input.destroyed || input.readableEnded, true)

  // A test that ends a running container's stdout itself, and then writes
  // to it, is told so too.
  const hung = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }] })
  const live = hung.run(spec(f, { channel: true }))
  const ends = hung.channels[0]
  assert.ok(ends !== undefined)
  ends.stdout.end('last words')
  assert.throws(() => ends.stdout.write('more'), /of aos-run-abc123 after it was ended\./)
  const got: string[] = []
  live.channel?.input.on('data', (chunk) => got.push(String(chunk)))
  await hung.kill(live.name)
  await live.result
  assert.deepEqual(got, ['last words'])

  // An input read through 'readable' stays paused when the container exits,
  // as resume() leaves such a stream (RunningSandbox.result), and holds the
  // result until it is read to its end.
  const paced = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }] })
  const reading = paced.run(spec(f, { channel: true }))
  const pacedInput = reading.channel?.input
  assert.ok(pacedInput !== undefined)
  paced.channels[0]?.stdout.write('unread')
  pacedInput.on('readable', () => undefined)
  let settled = false
  void reading.result.then(() => {
    settled = true
  })
  await paced.kill(reading.name)
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(pacedInput.readableFlowing, false)
  assert.equal(settled, false, "the fake settled a channel run whose 'readable' reader had not read its input")
  assert.equal(String(pacedInput.read()), 'unread')
  assert.equal(pacedInput.read(), null)
  await reading.result
})

test("the fake ends a channel as the real driver's child does: its output destroyed at the container's exit, what was written kept, and every error heard into stderr in the real driver's words", async (t) => {
  // Node destroys a child's stdin in its exit handler, before its stdout is
  // flushed and before 'close' (checked on Node 22: stdin.destroyed in the
  // 'exit' listener), and the docker driver hears each pipe's 'error' into
  // the run's stderr. Runtime code that ends a session on the output's
  // 'close', or meets a write that fails after the exit, meets the same on
  // the fake.
  const f = fixture(t)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }, { hangs: true }] })
  const running = fake.run(spec(f, { channel: true }))
  const output = running.channel?.output
  const container = fake.channels[0]
  assert.ok(output !== undefined && container !== undefined)
  let closed = false
  output.on('close', () => {
    closed = true
  })
  assert.equal(output.write('before the exit'), true)
  assert.equal(output.destroyed, false, "the fake destroyed a running container's output")
  await fake.kill(running.name)
  await running.result
  assert.equal(output.destroyed, true, "the channel's output outlived its container")
  assert.equal(closed, true, "the channel's output emitted no 'close'")
  const after = await new Promise<Error | null | undefined>((resolve) => {
    output.write('after the exit', resolve)
  })
  assert.match(String(after), /Cannot call write after a stream was destroyed/)
  // What the kernel wrote before the exit is what the container read, and
  // its stdin then ended.
  const read: string[] = []
  for await (const chunk of container.stdin) read.push(String(chunk))
  assert.deepEqual(read, ['before the exit'])

  // Errors on the channel: a write after the kernel ended the output, and
  // an input the kernel destroyed with an error. Neither throws, on either
  // driver, and both land in the result's stderr, in the same words.
  const real = driverFor(f, { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() })
  const onReal = real.driver.run(spec(f, { channel: true }))
  const onFake = fake.run(spec(f, { channel: true, name: `${CONTAINER_PREFIX}errors` }))
  for (const each of [onReal, onFake]) {
    each.channel?.output.end()
    each.channel?.output.write('after the end')
    each.channel?.input.destroy(new Error('read ECONNRESET'))
  }
  await new Promise((resolve) => setImmediate(resolve))
  real.child.close(0, null)
  await fake.kill(onFake.name)
  const [realResult, fakeResult] = await Promise.all([onReal.result, onFake.result])
  assert.equal(realResult.stderr, 'channel output: write after end\nchannel input: read ECONNRESET\n')
  assert.equal(fakeResult.stderr, realResult.stderr)
})

test("the fake's channel output is a pipe into its container: ending it ends the container's stdin while the run goes on, and a container that reads nothing holds the kernel's writes", async (t) => {
  // What Node's child.stdin is on the real driver: an end that the container
  // reads as the end of its stdin, while it runs on, and a write that is
  // acknowledged only once the container's side has taken it, so that one
  // that reads nothing fills the pipe and write() says so. Code tested
  // against the fake (W1's egress session) may end the output to tell the
  // mux it is done, or wait on 'drain'.
  const f = fixture(t)
  const turns = async (n: number): Promise<void> => {
    for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve))
  }
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }, { hangs: true }] })

  // The end: the container's stdin ends, while the run still hangs.
  const running = fake.run(spec(f, { channel: true }))
  const container = fake.channels[0]
  const output = running.channel?.output
  assert.ok(container !== undefined && output !== undefined)
  let settled = false
  void running.result.then(() => {
    settled = true
  })
  // By the output's 'finish' the end has reached the container, as a
  // child's stdin, a socketpair, finishes once its shutdown has been sent:
  // code that awaits finished(output) may take the mux to have its EOF. (The
  // output's auto-destroy, just after 'finish', would end the container's
  // stdin too, but only then.)
  let endedAtFinish: boolean | undefined
  output.once('finish', () => {
    // The container's stdin is a PassThrough: its writable side is the end
    // the kernel's pipe delivers into.
    const { stdin } = container
    endedAtFinish = stdin instanceof Writable && stdin.writableEnded
  })
  output.end('the last request')
  const read: string[] = []
  let ended = false
  const reading = (async () => {
    for await (const chunk of container.stdin) read.push(String(chunk))
    ended = true
  })()
  await turns(3)
  assert.equal(endedAtFinish, true, "the channel's output finished before its end had reached the container's stdin")
  assert.equal(ended, true, "ending the channel's output left the container's stdin open")
  assert.deepEqual(read, ['the last request'])
  assert.equal(settled, false, 'the run ended with its stdin')
  await fake.kill(running.name)
  await running.result
  await reading

  // The pipe: written past what the container's stdin and the output can
  // hold, with nothing read, write() says to wait, and the last write's
  // callback waits until the container reads.
  const full = fake.run(spec(f, { channel: true, name: `${CONTAINER_PREFIX}full` }))
  const ends = fake.channels[1]
  const out = full.channel?.output
  assert.ok(ends !== undefined && out !== undefined)
  const capacity = ends.stdin.readableHighWaterMark + out.writableHighWaterMark
  const chunk = Buffer.alloc(1_024, 7)
  let sent = 0
  let acknowledged = 0
  let refused = false
  while (sent < 2 * capacity) {
    if (!out.write(chunk, () => (acknowledged += chunk.length))) refused = true
    sent += chunk.length
    // Each write given its turns: what holds the rest is the container's
    // stdin, full, and not a burst written in one tick.
    await turns(2)
  }
  assert.equal(refused, true, 'the fake took every write from a container that reads nothing')
  assert.ok(acknowledged < sent, 'the fake acknowledged writes no container had read')
  const drained = new Promise((resolve) => out.once('drain', resolve))
  ends.stdin.resume()
  await drained
  await turns(2)
  assert.equal(acknowledged, sent, 'a write the container read was never acknowledged')
  await fake.kill(full.name)
  await full.result
})

test('wallclock fires docker kill by name', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const d = driverFor(f)

  const running = d.driver.run(spec(f, { limits: { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 } }))
  assert.equal(d.execs.length, 0)

  t.mock.timers.tick(5_000)
  // Straight to KILL, by name. A container that ignores SIGTERM is exactly
  // the one the kernel most needs to be able to end.
  assert.deepEqual(d.execs[0]?.args, ['kill', '--signal=KILL', `${CONTAINER_PREFIX}abc123`])

  // As the docker CLI ends when its container is killed: 137, not by signal.
  d.child.close(137, null)
  const result = await running.result
  assert.equal(result.killedBy, 'wallclock')
  assert.equal(result.signal, 'SIGKILL')
  assert.equal(result.exitCode, 137)
  assert.equal(result.overran, true)
  assert.equal(result.name, `${CONTAINER_PREFIX}abc123`)
})

test('probe reports why when docker is unreachable', async (t) => {
  const f = fixture(t)
  const d = driverFor(f)

  d.setExec(() => Promise.reject(new Error('Cannot connect to the Docker daemon at unix:///tmp/colima-trusted.sock')))
  const down = await d.driver.probe()
  // Availability, never a throw: a kernel with no container runtime must boot
  // degraded and be able to say what is wrong.
  assert.equal(down.ok, false)
  assert.match(down.ok ? '' : down.why, /Cannot connect to the Docker daemon/)

  d.setExec(healthyDaemon('27.3.1'))
  const up = await d.driver.probe()
  assert.deepEqual(up, { ok: true, version: '27.3.1' })

  // A daemon that answers with nothing is not a working daemon.
  d.setExec(() => Promise.resolve({ stdout: '  \n', stderr: '' }))
  assert.equal((await d.driver.probe()).ok, false)
})

test('probe refuses a domain whose network is not internal, and checks each domain on its own VM', async (t) => {
  // In a Colima VM the Mac's loopback is 192.168.5.2, where pmmcp listens
  // unauthenticated. A network with a route out is a path to its vault tools.
  // No run is put on a domain's network (every run is --network none, egress
  // plan S1), but the networks and this proof stay, as defence in depth.
  const f = fixture(t)
  const d = driverFor(f)
  const internalOn = new Set(['unix:///tmp/colima-trusted.sock'])
  const seen: string[] = []
  d.setExec((args, env) => {
    if (args[0] !== 'network') return healthyDaemon('27.3.1')(args, env)
    const host = d.execs[d.execs.length - 1]?.env['DOCKER_HOST'] ?? ''
    seen.push(`${host} ${args.join(' ')}`)
    return Promise.resolve({ stdout: internalOn.has(host) ? 'true\n' : 'false\n', stderr: '' })
  })

  const refused = await d.driver.probe()
  assert.equal(refused.ok, false)
  assert.match(refused.ok ? '' : refused.why, /^hostile: network aos-hostile is not internal \(Internal=false\)/)
  assert.match(refused.ok ? '' : refused.why, /docker network create --internal aos-hostile/)
  // Each domain was asked through its OWN socket, about its OWN network.
  assert.deepEqual(seen, [
    'unix:///tmp/colima-trusted.sock network inspect --format {{.Internal}} aos-internal',
    'unix:///tmp/colima-hostile.sock network inspect --format {{.Internal}} aos-hostile',
  ])

  internalOn.add('unix:///tmp/colima-hostile.sock')
  assert.deepEqual(await d.driver.probe(), { ok: true, version: '27.3.1' })

  // A network that does not exist is not internal either.
  d.setExec((args, env) =>
    args[0] === 'network'
      ? Promise.reject(new Error('Error response from daemon: network aos-internal not found'))
      : healthyDaemon('27.3.1')(args, env),
  )
  const missing = await d.driver.probe()
  assert.match(missing.ok ? '' : missing.why, /^trusted: network aos-internal could not be inspected: .*not found/)
})

test('probe refuses a domain network no domain may name without inspecting it, and never advises recreating it', async (t) => {
  // host reports Internal=false, so probe used to advise `docker network rm
  // host && docker network create --internal host`, which docker refuses for
  // a predefined network. kernel.yaml refuses these names
  // (test/config.test.ts); a driver handed its domains another way meets this.
  // HOST among them: docker reads it as a network of that name, and the
  // reason says so rather than calling it host mode. And none, in any case:
  // the one every run is on already (egress plan S1), no internal network to
  // prove, and predefined, so the advice would be a command docker refuses.
  const f = fixture(t)
  for (const network of ['host', 'HOST', 'bridge', 'default', 'container:abc', 'name=host', 'none', 'NONE', 'None']) {
    const d = driverFor({ ...f, hostile: { ...f.hostile, network } })
    const inspected: string[] = []
    d.setExec((args, env) => {
      if (args[0] !== 'network') return healthyDaemon('27.3.1')(args, env)
      const name = args[args.length - 1] ?? ''
      inspected.push(name)
      // The trusted domain's network is internal; anything else answers as
      // docker answers for host and bridge.
      return Promise.resolve({ stdout: name === 'aos-internal' ? 'true\n' : 'false\n', stderr: '' })
    })
    const result = await d.driver.probe()
    const why = result.ok ? '' : result.why
    assert.ok(why.startsWith(`hostile: network ${JSON.stringify(network)} is not one a domain may name: as --network it `), why)
    if (network === 'HOST') {
      assert.ok(why.includes('as --network it spells host in another case, which docker reads as a network of that name'), why)
      assert.equal(why.includes("VM's own network stack"), false, why)
    }
    if (network === 'none') {
      assert.ok(
        why.includes("as --network it is docker's none, no network at all, which every run is on already, and no internal network for probe() to prove."),
        why,
      )
    }
    if (network === 'NONE' || network === 'None') {
      assert.ok(
        why.includes(
          "as --network it spells none in another case, which docker reads as a network of that name, but docker's key=value " +
            `spelling lower-cases (name=${network} is none), so no case of none is admitted.`,
        ),
        why,
      )
    }
    assert.ok(why.endsWith("Name the domain's own internal network in kernel.yaml (docker network create --internal aos-hostile)"), why)
    assert.equal(why.includes('docker network rm'), false, why)
    // The trusted domain's network was inspected, and the hostile one never.
    assert.deepEqual(inspected, ['aos-internal'], network)
  }
})

test('probe asks each VM for the pinned image by id, and is degraded naming the domain when it lacks it or prints another id', async (t) => {
  // Every run names the pinned id with --pull=never, so a VM without the
  // image pulls nothing, but every run on it fails at docker. Built on the
  // trusted VM and never loaded into the hostile one, the sandbox would read
  // ok at boot and every hostile run would fail.
  const f = fixture(t)
  const d = driverFor(f)
  const other = `sha256:${'f'.repeat(64)}`
  // What each VM's daemon prints for `image inspect`, by socket; an Error is
  // docker's refusal for an image it does not hold.
  let printed: Record<string, string | Error> = {}
  const asked: string[] = []
  d.setExec((args, env) => {
    if (args[0] !== 'image') return healthyDaemon('29.5.2')(args, env)
    const host = env['DOCKER_HOST'] ?? ''
    asked.push(`${host} ${args.join(' ')}`)
    const answer = printed[host] ?? `${IMAGE_ID}\n`
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve({ stdout: answer, stderr: '' })
  })
  const why = async (): Promise<string> => {
    const probe = await d.driver.probe()
    return probe.ok ? '' : probe.why
  }

  // Held by both: ok, each VM asked through its OWN socket, by the id itself.
  assert.deepEqual(await d.driver.probe(), { ok: true, version: '29.5.2' })
  assert.deepEqual(asked, [
    `${TRUSTED_HOST} image inspect --format {{.Id}} ${IMAGE_ID}`,
    `${HOSTILE_HOST} image inspect --format {{.Id}} ${IMAGE_ID}`,
  ])

  // Never loaded into the hostile VM.
  printed = { [HOSTILE_HOST]: new Error(`Error response from daemon: No such image: ${IMAGE_ID}`) }
  const hostile = await why()
  assert.ok(hostile.startsWith(`hostile: the pinned sandbox.imageId ${IMAGE_ID} could not be inspected on this domain's VM`), hostile)
  assert.ok(hostile.includes(`which is told never to pull it: Error response from daemon: No such image: ${IMAGE_ID}`), hostile)
  assert.ok(hostile.includes('docker load on this one'), hostile)

  // Nor built on the trusted one: the first domain asked is the one named.
  printed = { [TRUSTED_HOST]: new Error(`Error response from daemon: No such image: ${IMAGE_ID}`) }
  assert.ok((await why()).startsWith(`trusted: the pinned sandbox.imageId ${IMAGE_ID} could not be inspected`))

  // Held, but printed under another id, nothing, or something that is no id,
  // whose text stays out of the reason the log keeps.
  printed = { [HOSTILE_HOST]: `${other}\n` }
  assert.equal(
    await why(),
    `hostile: docker image inspect ${IMAGE_ID} printed the id ${other} on this domain's VM, not the pinned ` +
      'sandbox.imageId: pin the id `docker image inspect --format {{.Id}}` prints for the worker image, the same on both VMs',
  )
  printed = { [HOSTILE_HOST]: '  \n' }
  assert.ok((await why()).startsWith(`hostile: docker image inspect ${IMAGE_ID} printed no id on this domain's VM`))
  printed = { [TRUSTED_HOST]: `[{"Id":"${IMAGE_ID}"}]\n` }
  const junk = await why()
  assert.ok(junk.startsWith(`trusted: docker image inspect ${IMAGE_ID} printed something that is no image id`), junk)
  assert.equal(junk.includes('"Id"'), false, junk)

  // At no point was anything pulled, or asked of docker but the probe's
  // three questions.
  for (const call of d.execs) {
    assert.ok(
      ['version', 'network inspect', 'image inspect'].some((q) => call.args.join(' ').startsWith(q)),
      call.args.join(' '),
    )
    assert.equal(call.args.some((a) => a === 'pull' || a.startsWith('--pull')), false, call.args.join(' '))
  }
  assert.deepEqual(d.spawns, [])
})

test('with sandbox.imageId unset the driver is degraded, naming the key and the build script, asks no daemon anything and starts no run', async (t) => {
  // kernel.yaml ships no id: no worker image is built yet (egress plan I1).
  // The driver must then say so rather than probe ok, and no run may reach
  // docker, where a name would be resolved, or pulled, on the VM.
  const f = fixture(t)
  const answer = healthyDaemon('29.5.2')
  const unset = driverFor(f, undefined, { imageId: undefined })
  // Every daemon would answer ok: the verdict is the id's alone.
  unset.setExec(answer)

  const probe = await unset.driver.probe()
  const why = probe.ok ? '' : probe.why
  assert.equal(probe.ok, false)
  assert.ok(why.startsWith('sandbox.imageId is not set in config/kernel.yaml'), why)
  assert.ok(why.includes('runs the worker image only by that pinned id, with --pull=never, and never pulls one'), why)
  assert.ok(why.includes('Build the image with scripts/build-worker-image.sh, which is still to be written, on the trusted VM'), why)
  assert.ok(why.endsWith('then set sandbox.imageId to the sha256:<64 hex> id it prints'), why)
  // Written into the hash-chained log for good (sandbox.degraded.reason) and
  // shown in status: it names the key and the script, in the repository, and
  // no plan that lives outside it.
  assert.doesNotMatch(why, /\bplan\b|\bI1\b/, why)
  assert.deepEqual(unset.execs, [], 'probe asked a daemon something')

  assert.throws(() => unset.driver.run(spec(f)), /docker args cannot be built: sandbox\.imageId is not set/)
  assert.deepEqual(unset.spawns, [], 'a run reached docker')
  assert.deepEqual(unset.execs, [])

  // An id handed to the driver by some path other than kernel.yaml is held
  // to the same shape, before any daemon is asked.
  for (const imageId of ['aos-worker:0.0.1', `aos-worker@${IMAGE_ID}`, IMAGE_ID.toUpperCase()]) {
    const bad = driverFor(f, undefined, { imageId })
    bad.setExec(answer)
    const result = await bad.driver.probe()
    assert.equal(result.ok ? '' : result.why.startsWith(`sandbox.imageId ${JSON.stringify(imageId)} is no image id`), true, imageId)
    assert.deepEqual(bad.execs, [], imageId)
    assert.throws(() => bad.driver.run(spec(f, { image: imageId })), /docker args cannot be built: sandbox\.imageId .* is no image id/)
    assert.deepEqual(bad.spawns, [], imageId)
  }

  // Pinned, the probe goes on to the daemons, and a run names the id and
  // --pull=never: nothing at any point asks docker to pull.
  const pinned = driverFor(f)
  pinned.setExec(answer)
  assert.deepEqual(await pinned.driver.probe(), { ok: true, version: '29.5.2' })
  pinned.driver.run(spec(f))
  const run = pinned.spawns[0]?.args ?? []
  assert.deepEqual(run.slice(run.indexOf('--pull=never')), ['--pull=never', IMAGE_ID, 'node', '--version'])
  for (const call of [...pinned.execs, ...pinned.spawns]) {
    assert.equal(call.args.some((a) => a === 'pull' || (a.startsWith('--pull') && a !== '--pull=never')), false, call.args.join(' '))
  }
})

test('the fake and the real driver agree: only the pinned image id runs, a tag or another id is refused in the same words, and with none pinned, or a value pinned that is no id, every run is refused and no probe is ok', async (t) => {
  // Runtime code is tested against the fake. Had the fake run a spec naming a
  // tag, code that built its specs from config.sandbox.image or a manifest's
  // sandbox.image (both tags) would pass every offline test, and have every
  // run refused on the Mac.
  const f = fixture(t)
  const answer = healthyDaemon('29.5.2')
  const refusal = (driver: SandboxDriver, image: string): string => {
    try {
      driver.run(spec(f, { image }))
    } catch (e) {
      if (e instanceof ConfigError) return e.message
      throw e
    }
    return ''
  }
  const names = ['aos-worker:0.0.1', 'aos-worker:test', `aos-worker@${IMAGE_ID}`, IMAGE_ID.toUpperCase(), `sha256:${'g'.repeat(64)}`]
  const other = `sha256:${'f'.repeat(64)}`

  // Pinned to the id, to nothing, and to a tag: a value kernel.yaml refuses,
  // and one a driver handed its id another way may still meet. A fake that
  // checked only for an unset id would probe ok under the tag, where the real
  // driver names it as no id.
  for (const imageId of [IMAGE_ID, undefined, 'aos-worker:0.0.1']) {
    const real = driverFor(f, undefined, { imageId })
    // Every daemon would answer ok, and the fake is scripted to say so.
    real.setExec(answer)
    const fake = fakeSandbox({ imageId, probe: { ok: true, version: '29.5.2' }, script: [{ exitCode: 0 }] })
    const label = imageId === undefined ? 'unpinned' : imageId === IMAGE_ID ? 'pinned' : `pinned ${imageId}`

    for (const image of [...names, other, ...(imageId === IMAGE_ID ? [] : [IMAGE_ID])]) {
      const said = refusal(real.driver, image)
      assert.notEqual(said, '', `${label}: the real driver ran ${image}`)
      assert.equal(refusal(fake, image), said, `${label}: ${image}`)
      if (imageId !== IMAGE_ID) assert.match(said, /^docker args cannot be built: sandbox\.imageId /, `${label}: ${image}`)
    }
    assert.deepEqual(real.spawns, [], `${label}: a refused run reached docker`)

    const [realProbe, fakeProbe] = [await real.driver.probe(), await fake.probe()]
    if (imageId !== IMAGE_ID) {
      assert.equal(realProbe.ok, false, label)
      assert.deepEqual(fakeProbe, realProbe, `${label}: the fake reports ok where the real driver cannot`)
      assert.match(
        fakeProbe.ok ? '' : fakeProbe.why,
        imageId === undefined
          ? /^sandbox\.imageId is not set in config\/kernel\.yaml/
          : /^sandbox\.imageId "aos-worker:0\.0\.1" is no image id/,
        label,
      )
      assert.deepEqual(real.execs, [], label)
    } else {
      assert.deepEqual(realProbe, { ok: true, version: '29.5.2' })
      assert.deepEqual(fakeProbe, realProbe)
      // And the pinned id itself runs on both, the fake on the scripted exit
      // no refusal spent.
      const ran = real.driver.run(spec(f))
      real.child.close(0, null)
      assert.equal((await ran.result).exitCode, 0)
      assert.equal((await fake.run(spec(f)).result).exitCode, 0)
      assert.equal(real.spawns.length, 1)
    }
  }
})

test('kill is idempotent and sweepOrphans reaps only our containers', async (t) => {
  const f = fixture(t)
  const d = driverFor(f)

  d.setExec((args) =>
    args[0] === 'kill'
      ? Promise.reject(new Error('No such container'))
      : Promise.resolve({ stdout: `${CONTAINER_PREFIX}aaa\nsomeone-elses-container\n${CONTAINER_PREFIX}bbb\n`, stderr: '' }),
  )

  // A kill that races a container's own exit is the normal case, not an error.
  await d.driver.kill(`${CONTAINER_PREFIX}gone`)

  const killed = await d.driver.sweepOrphans()
  // A --filter is a request, not a guarantee; the prefix is re-checked.
  assert.deepEqual(killed, [
    `${CONTAINER_PREFIX}aaa`,
    `${CONTAINER_PREFIX}bbb`,
    `${CONTAINER_PREFIX}aaa`,
    `${CONTAINER_PREFIX}bbb`,
  ])
  assert.equal(killed.includes('someone-elses-container'), false)
})

/**
 * A sweep's listing, known by what it asks for (the kernel's containers, by
 * name) rather than by its command word: `docker container ls` lists what
 * `docker ps` does, so a fake keyed on `ps` would fail such a sweep for what
 * it returned, and only the argv pin and docker.ts's header tests may see the
 * command it ran.
 */
function listsOrphans(args: readonly string[]): boolean {
  return args.includes('--filter') && args.includes(`name=${CONTAINER_PREFIX}`) && args.includes('--format') && args.includes('{{.Names}}')
}

test('sweepOrphans asks each VM for names, never with --quiet, under which docker prints IDs', async (t) => {
  // The docker CLI ignores a custom --format when --quiet is set: it warns on
  // stderr and prints container IDs. A sweep that asked so would drop every
  // line at the prefix check and kill nothing, and every orphan of a crashed
  // kernel would run on past its hard wallclock. The exec answers as docker
  // does, IDs under --quiet and names otherwise, and the argv is pinned
  // whole, since a fake that answered names to any argv could not see it.
  const f = fixture(t)
  const d = driverFor(f)
  d.setExec((args, env) => {
    if (!listsOrphans(args)) return Promise.resolve({ stdout: '', stderr: '' })
    const vm = env['DOCKER_HOST'] === HOSTILE_HOST ? 'h' : 't'
    if (args.includes('--quiet') || args.includes('-q')) {
      return Promise.resolve({
        stdout: `${'0'.repeat(63)}${vm === 'h' ? '1' : '2'}\n`,
        stderr: 'WARNING: Ignoring custom format, because both --format and --quiet are set.\n',
      })
    }
    return Promise.resolve({ stdout: `${CONTAINER_PREFIX}${vm}1\n`, stderr: '' })
  })

  assert.deepEqual(await d.driver.sweepOrphans(), [`${CONTAINER_PREFIX}t1`, `${CONTAINER_PREFIX}h1`])
  const listed = d.execs.filter((e) => listsOrphans(e.args))
  assert.deepEqual(
    listed.map((e) => e.env['DOCKER_HOST']),
    [TRUSTED_HOST, HOSTILE_HOST],
  )
  for (const e of listed) {
    assert.deepEqual(e.args, ['ps', '--filter', `name=${CONTAINER_PREFIX}`, '--format', '{{.Names}}'])
  }
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${CONTAINER_PREFIX}t1`, `${HOSTILE_HOST} ${CONTAINER_PREFIX}h1`])
})

/** Each `docker kill` the driver sent, as "<DOCKER_HOST> <name>". */
function killsSent(d: Spied): string[] {
  return d.execs
    .filter((e) => e.args[0] === 'kill')
    .map((e) => {
      assert.deepEqual(e.args.slice(0, 2), ['kill', '--signal=KILL'])
      return `${e.env['DOCKER_HOST'] ?? '?'} ${e.args[2] ?? '?'}`
    })
}

test('the wallclock kill of a hostile container is sent to the hostile DOCKER_HOST', async (t) => {
  // Found in the Phase 2 egress review: kill() always used the trusted VM's
  // socket, so a hostile run's wallclock kill reached a daemon that had never
  // heard of it, its "No such container" was swallowed as the normal race, and
  // the container ran on past its hard wallclock.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const d = driverFor(f)
  const limits = (wallclockMs: number): SandboxSpec['limits'] => ({ memoryMb: 1, cpus: 1, pids: 1, wallclockMs })
  const hostile = `${CONTAINER_PREFIX}hostile1`
  const trusted = `${CONTAINER_PREFIX}trusted1`

  const running = d.driver.run(spec(f, { domain: 'hostile', name: hostile, limits: limits(5_000) }))
  d.driver.run(spec(f, { domain: 'trusted', name: trusted, limits: limits(7_000) }))
  assert.deepEqual(killsSent(d), [])

  t.mock.timers.tick(5_000)
  // Once, and only on the VM that runs it.
  assert.deepEqual(killsSent(d), [`${HOSTILE_HOST} ${hostile}`])

  // And the trusted one on its own, so neither VM is a hard-coded default.
  t.mock.timers.tick(2_000)
  assert.deepEqual(killsSent(d), [`${HOSTILE_HOST} ${hostile}`, `${TRUSTED_HOST} ${trusted}`])

  // A kill asked after the wallclock fired does not rewrite why the run ended.
  await d.driver.kill(hostile)
  d.child.close(137, null)
  const result = await running.result
  assert.equal(result.killedBy, 'wallclock')
  assert.equal(result.signal, 'SIGKILL')
})

test('sweepOrphans kills each orphan on the domain that listed it', async (t) => {
  // A kernel that crashed mid-run leaves containers on both VMs. Each name is
  // known only to the daemon that holds it, so the kill goes back to the socket
  // whose `ps` reported it, never to a default one.
  const f = fixture(t)
  const d = driverFor(f)
  const listed: Record<string, string> = {
    [TRUSTED_HOST]: `${CONTAINER_PREFIX}t1\n`,
    [HOSTILE_HOST]: `${CONTAINER_PREFIX}h1\n${CONTAINER_PREFIX}h2\n`,
  }
  d.setExec((args, env) =>
    listsOrphans(args)
      ? Promise.resolve({ stdout: listed[env['DOCKER_HOST'] ?? ''] ?? '', stderr: '' })
      : Promise.resolve({ stdout: '', stderr: '' }),
  )

  const killed = await d.driver.sweepOrphans()
  assert.deepEqual(killed, [`${CONTAINER_PREFIX}t1`, `${CONTAINER_PREFIX}h1`, `${CONTAINER_PREFIX}h2`])
  // One kill per orphan, each on its own VM: none sent twice, none sent wide.
  assert.deepEqual(killsSent(d), [
    `${TRUSTED_HOST} ${CONTAINER_PREFIX}t1`,
    `${HOSTILE_HOST} ${CONTAINER_PREFIX}h1`,
    `${HOSTILE_HOST} ${CONTAINER_PREFIX}h2`,
  ])
})

test('kill(name) goes only to the domain of a container this driver is running, and to every domain for a name it does not know', async (t) => {
  // The map is in-memory: after a restart, or once a run has exited, the
  // driver cannot prove where a name lives, and a kill refused for that reason
  // is a container left running. So an unknown name is asked of each daemon,
  // which costs one "No such container" from the one that lacks it.
  const f = fixture(t)
  const d = driverFor(f)
  const hostile = `${CONTAINER_PREFIX}hostile1`
  const trusted = `${CONTAINER_PREFIX}trusted1`
  const stranger = `${CONTAINER_PREFIX}from-before-a-restart`
  d.setExec((args) =>
    args[0] === 'kill' ? Promise.reject(new Error('No such container')) : Promise.resolve({ stdout: '', stderr: '' }),
  )

  d.driver.run(spec(f, { domain: 'hostile', name: hostile }))
  d.driver.run(spec(f, { domain: 'trusted', name: trusted }))
  await d.driver.kill(hostile)
  await d.driver.kill(trusted)
  assert.deepEqual(killsSent(d), [`${HOSTILE_HOST} ${hostile}`, `${TRUSTED_HOST} ${trusted}`])

  d.execs.length = 0
  await d.driver.kill(stranger)
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${stranger}`, `${HOSTILE_HOST} ${stranger}`])

  // Once a run has exited its entry is gone: no stale record can aim a later
  // kill at one VM only, and the map does not grow for the daemon's lifetime.
  d.child.close(0, null)
  d.execs.length = 0
  await d.driver.kill(hostile)
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${hostile}`, `${HOSTILE_HOST} ${hostile}`])
})

test('run refuses a second container under a name the driver is already running, on either domain', (t) => {
  // One name on both VMs at once would leave kill(name) unable to say which
  // daemon to ask, so it would reach one of them and miss the other.
  const f = fixture(t)
  const d = driverFor(f)
  const name = `${CONTAINER_PREFIX}twice`

  d.driver.run(spec(f, { domain: 'trusted', name }))
  for (const domain of ['hostile', 'trusted'] as const) {
    assert.throws(
      () => d.driver.run(spec(f, { domain, name })),
      (e: unknown) => e instanceof ConfigError && /already running on the trusted domain/.test(e.message),
      domain,
    )
  }
  // Refused before anything was spawned.
  assert.equal(d.spawns.length, 1)

  // Free again once the first has exited.
  d.child.close(0, null)
  d.driver.run(spec(f, { domain: 'hostile', name }))
  assert.equal(d.spawns[1]?.env['DOCKER_HOST'], HOSTILE_HOST)
})

test('kill(name) of a name it does not know asks every VM at once, so a daemon that never answers holds up no other', async (t) => {
  // A socket that accepts and never replies has no execFile timeout behind
  // it. Asked one VM after the other, a hung trusted daemon would mean the
  // hostile kill was never sent. Hung on each side in turn, so the order the
  // domains are listed in decides nothing.
  for (const hung of [TRUSTED_HOST, HOSTILE_HOST]) {
    const f = fixture(t)
    const d = driverFor(f)
    const stranger = `${CONTAINER_PREFIX}from-before-a-restart`
    d.setExec((args, env) =>
      args[0] === 'kill' && env['DOCKER_HOST'] === hung
        ? new Promise<never>(() => undefined)
        : Promise.reject(new Error('No such container')),
    )
    void d.driver.kill(stranger)
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(killsSent(d).sort(), [`${HOSTILE_HOST} ${stranger}`, `${TRUSTED_HOST} ${stranger}`], hung)
  }
})

test('sweepOrphans lists every VM at once and kills each orphan at once, so a daemon that never answers holds up no other', async (t) => {
  // The boot sweep (plan W2) reaps what a crashed kernel left on both VMs.
  // Listed one VM after the other, a trusted daemon that accepts the
  // connection and never answers `ps` would leave the hostile VM unlisted and
  // its orphans running; killed one after the other, one kill that never
  // returns would leave the rest. Hung on each side in turn, so the order the
  // domains are listed in decides nothing.
  const listed: Record<string, string> = {
    [TRUSTED_HOST]: `${CONTAINER_PREFIX}t1\n${CONTAINER_PREFIX}t2\n`,
    [HOSTILE_HOST]: `${CONTAINER_PREFIX}h1\n${CONTAINER_PREFIX}h2\n`,
  }
  const hang = new Promise<never>(() => undefined)
  for (const [hung, other, first, second] of [
    [TRUSTED_HOST, HOSTILE_HOST, 'h1', 'h2'],
    [HOSTILE_HOST, TRUSTED_HOST, 't1', 't2'],
  ] as const) {
    const f = fixture(t)
    const d = driverFor(f)
    d.setExec((args, env) => {
      const host = env['DOCKER_HOST'] ?? ''
      if (listsOrphans(args)) return host === hung ? hang : Promise.resolve({ stdout: listed[host] ?? '', stderr: '' })
      // The first orphan's kill never returns either.
      return args[2] === `${CONTAINER_PREFIX}${first}` ? hang : Promise.resolve({ stdout: '', stderr: '' })
    })
    void d.driver.sweepOrphans()
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(
      d.execs.filter((e) => listsOrphans(e.args)).map((e) => e.env['DOCKER_HOST']).sort(),
      [HOSTILE_HOST, TRUSTED_HOST],
      `${hung}: both VMs were not asked for their orphans`,
    )
    assert.deepEqual(
      killsSent(d),
      [`${other} ${CONTAINER_PREFIX}${first}`, `${other} ${CONTAINER_PREFIX}${second}`],
      `${hung}: the other VM's orphans were not all killed`,
    )
  }
})

test('sweepOrphans still sweeps one VM when the other cannot be listed', async (t) => {
  // The commonest boot of all: one VM is not running, and its `ps` fails at
  // once ("Cannot connect to the Docker daemon"). Each domain catches its own
  // failure, so the other VM's orphans are still killed and returned. A sweep
  // that rejected instead would still have sent those kills, but the boot
  // sweep (plan W2) would throw and lose the list of what it reaped. Failed
  // on each side in turn, so the order the domains are listed in decides
  // nothing.
  for (const [down, up, names] of [
    [TRUSTED_HOST, HOSTILE_HOST, ['h1', 'h2']],
    [HOSTILE_HOST, TRUSTED_HOST, ['t1']],
  ] as const) {
    const f = fixture(t)
    const d = driverFor(f)
    d.setExec((args, env) => {
      const host = env['DOCKER_HOST'] ?? ''
      if (!listsOrphans(args)) return Promise.resolve({ stdout: '', stderr: '' })
      if (host === down) {
        return Promise.reject(new Error(`Cannot connect to the Docker daemon at ${host}. Is the docker daemon running?`))
      }
      return Promise.resolve({ stdout: names.map((n) => `${CONTAINER_PREFIX}${n}\n`).join(''), stderr: '' })
    })
    const killed = await d.driver.sweepOrphans()
    assert.deepEqual(killed, names.map((n) => `${CONTAINER_PREFIX}${n}`), `${down} down`)
    assert.deepEqual(killsSent(d), names.map((n) => `${up} ${CONTAINER_PREFIX}${n}`), `${down} down`)
    assert.deepEqual(
      d.execs.filter((e) => listsOrphans(e.args)).map((e) => e.env['DOCKER_HOST']).sort(),
      [HOSTILE_HOST, TRUSTED_HOST],
      `${down} down`,
    )
  }
})

test('sweepOrphans resolves only once every kill it sent has returned, and kill() once each of its own has', async (t) => {
  // The boot sweep (plan W2) reports what it swept. One that resolved with the
  // names while their kills were still in flight would say swept of
  // containers still running, and a boot that went on to reuse a name would
  // meet it. Likewise kill(), which runtime code awaits before it reports a
  // run killed.
  const f = fixture(t)
  const d = driverFor(f)
  let release: () => void = () => undefined
  const held = new Promise<{ stdout: string; stderr: string }>((resolve) => {
    release = () => {
      resolve({ stdout: '', stderr: '' })
    }
  })
  d.setExec((args, env) =>
    listsOrphans(args)
      ? Promise.resolve({ stdout: env['DOCKER_HOST'] === HOSTILE_HOST ? `${CONTAINER_PREFIX}h1\n` : '', stderr: '' })
      : held,
  )
  const settledYet = <T>(promise: Promise<T>): (() => boolean) => {
    let settled = false
    void promise.then(() => {
      settled = true
    })
    return () => settled
  }

  const sweep = d.driver.sweepOrphans()
  const swept = settledYet(sweep)
  const kill = d.driver.kill(`${CONTAINER_PREFIX}stranger`)
  const killed = settledYet(kill)
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(killsSent(d).sort(), [
    `${HOSTILE_HOST} ${CONTAINER_PREFIX}h1`,
    `${HOSTILE_HOST} ${CONTAINER_PREFIX}stranger`,
    `${TRUSTED_HOST} ${CONTAINER_PREFIX}stranger`,
  ])
  assert.equal(swept(), false, 'sweepOrphans resolved while its kill was in flight')
  assert.equal(killed(), false, 'kill() resolved while its docker kills were in flight')

  release()
  assert.deepEqual(await sweep, [`${CONTAINER_PREFIX}h1`])
  await kill
})

test('kill of a name without the kernel prefix sends nothing to either VM', async (t) => {
  // run() refuses such a name, so no container this driver started has one,
  // and sweepOrphans skips one a daemon lists: it is someone else's. Asked of
  // every domain as an unknown name, it would reach that container on both
  // VMs. A no-op, not a refusal, as kill is idempotent on both drivers.
  const f = fixture(t)
  const d = driverFor(f)
  for (const name of ['someone-elses-container', `x${CONTAINER_PREFIX}abc`, '', CONTAINER_PREFIX.slice(0, -1)]) {
    await d.driver.kill(name)
  }
  assert.deepEqual(d.execs, [])
  // A name with the prefix is still asked of every VM.
  await d.driver.kill(`${CONTAINER_PREFIX}abc`)
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${CONTAINER_PREFIX}abc`, `${HOSTILE_HOST} ${CONTAINER_PREFIX}abc`])
})

test('a kill that ends nothing leaves the run its own exit: no killedBy, and the CLI\'s code and signal', async (t) => {
  // kill(name) and the wallclock mark the run before the kill is sent, and
  // whether it ended the run is the CLI's exit to say: 137 for a killed
  // container, and nothing else. A kill that lands after the container exited
  // on its own, or never reaches the daemon, ended nothing, and a run reported
  // as {exitCode: 0, signal: SIGKILL, killedBy} would read as killed though it
  // finished. The fake, scripted with ignoresKill, shows the same: see the
  // parity test 'the fake and the real driver agree: a kill that ends nothing
  // leaves the run its own exit' below.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const name = `${CONTAINER_PREFIX}abc123`
  const ended = async (
    exec: ScriptedExec,
    end: (d: Spied) => Promise<void>,
    exit: (child: FakeChild) => void,
  ): Promise<SandboxResult> => {
    const f = fixture(t)
    const d = driverFor(f)
    d.setExec(exec)
    const running = d.driver.run(spec(f, { limits: { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 } }))
    await end(d)
    assert.equal(killsSent(d).length, 1, 'no kill was sent')
    exit(d.child)
    return running.result
  }
  const closes =
    (code: number | null, signal: string | null) =>
    (child: FakeChild): void => {
      child.close(code, signal)
    }
  const ok = (): Promise<{ stdout: string; stderr: string }> => Promise.resolve({ stdout: '', stderr: '' })
  const gone = (): Promise<never> => Promise.reject(new Error(`Error response from daemon: No such container: ${name}`))
  const unreachable = (): Promise<never> =>
    Promise.reject(new Error('Cannot connect to the Docker daemon at unix:///tmp/colima-trusted.sock'))
  const requested = (d: Spied): Promise<void> => d.driver.kill(name)
  const wallclock = (): Promise<void> => {
    t.mock.timers.tick(5_000)
    return Promise.resolve()
  }

  for (const [label, exec, end, code, signal] of [
    ['requested, after the container exited', gone, requested, 0, null],
    ['requested, with the daemon unreachable', unreachable, requested, 0, null],
    ['requested, and the container then failed on its own', gone, requested, 1, null],
    // The kernel sends only KILL, so a container that ends SIGTERMed (143)
    // was ended by something else, though the kill reached a daemon.
    ['requested, and the container then SIGTERMed', ok, requested, 143, null],
    // A CLI that dies by a signal shows nothing of its container: it forwards
    // every signal it can catch to the container and exits with the
    // container's status, so one that dies by a signal met a SIGKILL from
    // outside, or a signal that came before it had installed its handlers
    // (the SIGTERM rows), and its container is expected to run on. Its own
    // signal, and no killedBy, though a kill was sent and reached a daemon.
    ['requested, with the daemon unreachable, and the CLI then SIGKILLed', unreachable, requested, null, 'SIGKILL'],
    ['requested, and the CLI SIGKILLed', ok, requested, null, 'SIGKILL'],
    ['requested, and the CLI SIGTERMed', ok, requested, null, 'SIGTERM'],
    ['wallclock, with the daemon unreachable', unreachable, wallclock, 0, null],
    ['wallclock, after the container exited', gone, wallclock, 3, null],
    ['wallclock, and the container then SIGTERMed', ok, wallclock, 143, null],
    ['wallclock, with the daemon unreachable, and the CLI then SIGKILLed', unreachable, wallclock, null, 'SIGKILL'],
    ['wallclock, and the CLI SIGKILLed', ok, wallclock, null, 'SIGKILL'],
  ] as const) {
    const result = await ended(exec, end, closes(code, signal))
    assert.equal(result.killedBy, undefined, label)
    assert.equal(result.signal, signal, label)
    assert.equal(result.exitCode, code, label)
    // A wallclock that fired is still said, though its kill ended nothing:
    // the run outlived its hard wallclock, and this is all that shows it.
    assert.equal(result.overran, end === wallclock ? true : undefined, label)
  }

  // A spawn that started no process ('error', which Node emits after spawn
  // has returned, so after a kill sent in the same tick) was ended by no kill
  // either, though its exit code is null as a signalled CLI's is.
  for (const [label, end] of [
    ['requested, then a spawn error', requested],
    ['wallclock, then a spawn error', wallclock],
  ] as const) {
    const result = await ended(ok, end, (child) => {
      child.fail(Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' }))
    })
    assert.equal(result.killedBy, undefined, label)
    assert.equal(result.signal, null, label)
    assert.equal(result.exitCode, null, label)
    assert.equal(result.overran, end === wallclock ? true : undefined, label)
  }

  // And a kill that did end it says so: the CLI exits 137.
  for (const [label, end, by] of [
    ['requested, 137', requested, 'requested'],
    ['wallclock, 137', wallclock, 'wallclock'],
  ] as const) {
    const result = await ended(ok, end, closes(137, null))
    assert.equal(result.killedBy, by, label)
    assert.equal(result.signal, 'SIGKILL', label)
    assert.equal(result.exitCode, 137, label)
    assert.equal(result.overran, by === 'wallclock' ? true : undefined, label)
  }

  // A requested kill that reached no daemon, then the wallclock, whose kill
  // ends the run: the 137 is the wallclock's, the last kill sent before the
  // run ended, and a run reported killedBy requested with overran would say
  // the requested kill ended a run that had outlived its wallclock.
  const f = fixture(t)
  const d = driverFor(f)
  let reached = false
  d.setExec(() => {
    if (reached) return ok()
    reached = true
    return unreachable()
  })
  const running = d.driver.run(spec(f, { limits: { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 } }))
  await requested(d)
  await wallclock()
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${name}`, `${TRUSTED_HOST} ${name}`])
  d.child.close(137, null)
  const result = await running.result
  assert.equal(result.killedBy, 'wallclock')
  assert.equal(result.signal, 'SIGKILL')
  assert.equal(result.exitCode, 137)
  assert.equal(result.overran, true)
})

test("a kill sent after the CLI exited on its own ends nothing: the run reports its own 137, with no killedBy, on the real driver and the fake alike", async (t) => {
  // The container is OOM-killed and the docker CLI exits 137 on its own. A
  // channel run's CLI closes only once its caller has read the input to its
  // end, and its name is held until then, so a kill sent then (a tear-down's)
  // reaches a run that has already ended: it must not be credited with the
  // 137, which would log a kernel kill of a run that ended by itself. A run
  // without a channel has the same window, for as long as the CLI takes from
  // its exit to its close.
  const f = fixture(t)
  for (const channel of [false, true]) {
    const label = `channel ${String(channel)}`
    const io = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() }
    const d = driverFor(f, io)
    d.setExec((args) => Promise.reject(new Error(`Error response from daemon: No such container: ${args[2] ?? '?'}`)))
    const running = d.driver.run(spec(f, { channel }))
    d.child.exit(137, null)
    await d.driver.kill(running.name)
    // Sent, and to the run's own VM only: the name was still held.
    assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${running.name}`], label)
    io.stdout.end()
    if (channel) running.channel?.input.resume()
    d.child.close(137, null)
    const real = await running.result
    assert.equal(real.killedBy, undefined, `${label}: a kill sent after the exit was credited with it`)
    assert.equal(real.signal, null, label)
    assert.equal(real.exitCode, 137, label)
    assert.equal(real.overran, undefined, label)

    // The fake: a run scripted to exit 137 on its own, then killed.
    const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 137 }] })
    const onFake = fake.run(spec(f, { channel }))
    await fake.kill(onFake.name)
    const faked = await onFake.result
    const shape = (r: SandboxResult): unknown => ({ exitCode: r.exitCode, signal: r.signal, killedBy: r.killedBy, overran: r.overran })
    assert.deepEqual(shape(faked), shape(real), label)
  }

  // A kill sent before the exit is still the CLI's 137 to credit.
  const d = driverFor(f)
  const before = d.driver.run(spec(f))
  await d.driver.kill(before.name)
  d.child.exit(137, null)
  d.child.close(137, null)
  const killed = await before.result
  assert.equal(killed.killedBy, 'requested')
  assert.equal(killed.signal, 'SIGKILL')
})

test("a spawn that started nothing clears its wallclock: a retry under the same name is not killed at the first run's deadline", async (t) => {
  // A transient EAGAIN or EMFILE from spawn starts no process, so Node emits
  // 'error' and never 'exit', and finish() is then the only thing that
  // clears the run's timer. Left armed, it would fire at the first run's
  // deadline and `docker kill` by name whatever then runs under the name,
  // which the failure has freed: the retry.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const d = driverFor(f)
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  const first = d.driver.run(spec(f, { limits }))
  d.child.fail(Object.assign(new Error('spawn docker EAGAIN'), { code: 'EAGAIN' }))
  const failed = await first.result
  assert.equal(failed.exitCode, null)
  assert.equal(failed.stderr, 'spawn docker EAGAIN')

  t.mock.timers.tick(2_000)
  const retry = d.driver.run(spec(f, { limits }))
  // 6 s in: a second past the first run's deadline, a second short of the
  // retry's.
  t.mock.timers.tick(4_000)
  assert.deepEqual(killsSent(d), [], "the failed run's wallclock killed the retry under its name")
  t.mock.timers.tick(1_000)
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${retry.name}`], "the retry's own wallclock")
  d.child.close(137, null)
  const ended = await retry.result
  assert.equal(ended.killedBy, 'wallclock')
  assert.equal(ended.overran, true)
})

test('a spawn that throws leaves no record: the name runs again, and a kill of it still asks every VM', async (t) => {
  // Node's spawn refuses some arguments synchronously (a NUL byte, for one),
  // and then nothing started. A record made before that throw would refuse
  // the name for the driver's lifetime and aim every later kill of it at one
  // VM only.
  const f = fixture(t)
  const d = driverFor(f)
  const name = `${CONTAINER_PREFIX}never-started`
  const refused = new TypeError("The argument 'args[25]' must be a string without null bytes")
  d.failNextSpawn(refused)
  assert.throws(() => d.driver.run(spec(f, { domain: 'hostile', name })), (e: unknown) => e === refused)
  assert.equal(d.spawns.length, 0)

  await d.driver.kill(name)
  assert.deepEqual(killsSent(d), [`${TRUSTED_HOST} ${name}`, `${HOSTILE_HOST} ${name}`])

  d.driver.run(spec(f, { domain: 'hostile', name }))
  assert.equal(d.spawns.length, 1)
  assert.equal(d.spawns[0]?.env['DOCKER_HOST'], HOSTILE_HOST)
})

test('the fake and the real driver agree: a name is refused until its run\'s result settles, hung or not, and a requested kill reports killedBy requested with SIGKILL', async (t) => {
  // Runtime code is tested against the fake. Had the fake let a name run twice,
  // or the real driver said nothing of who ended a run, code that passed
  // against one would meet different behaviour from the other.
  const f = fixture(t)
  const real = driverFor(f)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }, { exitCode: 0 }] })
  const name = `${CONTAINER_PREFIX}parity`
  // The docker CLI exits 137 when its container is killed; the fake settles on its own.
  const drivers: readonly (readonly [string, SandboxDriver, () => void])[] = [
    ['real', real.driver, () => real.child.close(137, null)],
    ['fake', fake, () => undefined],
  ]

  for (const [label, driver, exitAfterKill] of drivers) {
    const running = driver.run(spec(f, { name }))
    assert.throws(
      () => driver.run(spec(f, { domain: 'hostile', name })),
      (e: unknown) => e instanceof ConfigError && /already running on the trusted domain/.test(e.message),
      label,
    )

    let settled = false
    void running.result.then(() => {
      settled = true
    })
    await driver.kill(name)
    // kill() resolves once the kill is sent, not once the run has ended: the
    // real driver's run ends when the docker CLI closes, after `docker kill`
    // has returned, and the fake's on a later macrotask. Had the fake ended
    // it before kill() returned, code tested against it could kill a name and
    // start it again at once, which the real driver refuses.
    assert.equal(settled, false, `${label}: the run ended before kill() returned`)
    assert.throws(
      () => driver.run(spec(f, { name })),
      (e: unknown) => e instanceof ConfigError && /already running on the trusted domain/.test(e.message),
      `${label}: the name was free when kill() returned`,
    )
    exitAfterKill()
    const result = await running.result
    assert.equal(result.killedBy, 'requested', label)
    assert.equal(result.signal, 'SIGKILL', label)
    // The docker CLI's exit for a killed container, on the fake too: code
    // that told a kill by a null exit code would pass against a fake that
    // reported one, and never see a kill on docker.
    assert.equal(result.exitCode, 137, label)

    // Free again once that run has ended.
    assert.doesNotThrow(() => driver.run(spec(f, { name })), label)
  }
  // The refused calls are recorded, as every call is, and spent no scripted
  // exit: the fourth call ran on the fake's second entry rather than finding
  // none.
  assert.equal(fake.specs.length, 4)

  // A run that does not hang holds its name as long: the real driver until
  // the CLI closes, the fake until the result it resolved at once has
  // settled. Had the fake freed the name before run() returned, code tested
  // against it could start one name twice in a tick and pass. And free on
  // both once `await result` has returned, so neither keeps it for good.
  const realQuick = driverFor(f)
  const quick = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 0 }, { exitCode: 0 }] })
  const quickly: readonly (readonly [string, SandboxDriver, () => void])[] = [
    ['real', realQuick.driver, () => realQuick.child.close(0, null)],
    ['fake', quick, () => undefined],
  ]
  for (const [label, driver, exit] of quickly) {
    const first = driver.run(spec(f, { name }))
    assert.throws(
      () => driver.run(spec(f, { name })),
      (e: unknown) => e instanceof ConfigError && /already running on the trusted domain/.test(e.message),
      label,
    )
    exit()
    const result = await first.result
    assert.equal(result.exitCode, 0, label)
    assert.equal(result.killedBy, undefined, label)
    assert.equal(result.overran, undefined, label)
    assert.doesNotThrow(() => driver.run(spec(f, { name })), label)
  }
  assert.equal(quick.specs.length, 3)

  // A name without the kernel's prefix is no container of the kernel's: both
  // refuse to run one, with the same ConfigError, before anything starts and
  // before the fake spends a scripted exit; and a kill of one ends nothing on
  // either, leaving a run under the prefix running. Had the fake run such a
  // name, a kill of it would have settled that run, though the real driver
  // sends the kill nowhere: code tested against the fake could use a name
  // the real driver refuses.
  const realBare = driverFor(f)
  const bare = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }] })
  const stranger = 'someone-elses-container'
  for (const [label, driver] of [
    ['real', realBare.driver],
    ['fake', bare],
  ] as const) {
    assert.throws(
      () => driver.run(spec(f, { name: stranger })),
      (e: unknown) => e instanceof ConfigError && e.message === `container name "${stranger}" must start with ${CONTAINER_PREFIX}`,
      label,
    )
    // On the fake, the scripted exit the refusal did not spend.
    const running = driver.run(spec(f, { name }))
    let settled = false
    void running.result.then(() => {
      settled = true
    })
    await driver.kill(stranger)
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(settled, false, `${label}: a kill of ${stranger} ended another run`)
  }
  assert.equal(realBare.spawns.length, 1)
  assert.deepEqual(realBare.execs, [])
  assert.deepEqual(bare.kills, [stranger])
  assert.deepEqual(bare.specs.map((s) => s.name), [stranger, name])
})

test('the fake and the real driver agree: an overrun reports killedBy wallclock with SIGKILL, and that it overran', async (t) => {
  // W1 logs a run that outlived its hard wallclock. Runtime code tested
  // against the fake's overrun must meet what the real driver reports for
  // one: the kill the wallclock sent, and the overrun itself, which the real
  // driver reports even when that kill ends nothing.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const real = driverFor(f)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }] })
  const name = `${CONTAINER_PREFIX}overrun`
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  const drivers: readonly (readonly [string, SandboxDriver, () => void])[] = [
    [
      'real',
      real.driver,
      () => {
        t.mock.timers.tick(5_000)
        real.child.close(137, null)
      },
    ],
    ['fake', fake, () => fake.simulateOverrun(name)],
  ]
  for (const [label, driver, overrun] of drivers) {
    const running = driver.run(spec(f, { name, limits }))
    overrun()
    const result = await running.result
    assert.equal(result.killedBy, 'wallclock', label)
    assert.equal(result.signal, 'SIGKILL', label)
    assert.equal(result.exitCode, 137, label)
    assert.equal(result.overran, true, label)
  }
})

test('the fake and the real driver agree: a kill that ends nothing leaves the run its own exit, and a wallclock that fires before a killed run ends is what ended it', async (t) => {
  // Since a kill's credit is the CLI's exit to give (finish() in docker.ts),
  // the real driver reports a kill that reached no daemon as nothing: the run
  // reports its own exit when its container does exit, with no killedBy, and
  // after an overrun says only that it overran. W1 code must handle that, so
  // the fake can be scripted to meet it (ignoresKill). And a requested kill
  // still in flight when the wallclock fires is credited to the wallclock on
  // both: the last kill sent before the run ended.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const name = `${CONTAINER_PREFIX}parity`
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  const unreachable = (): Promise<never> =>
    Promise.reject(new Error('Cannot connect to the Docker daemon at unix:///tmp/colima-trusted.sock'))

  for (const how of ['requested', 'wallclock'] as const) {
    const real = driverFor(f)
    real.setExec(unreachable)
    const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true, ignoresKill: true, exitCode: 3 }] })
    const drivers: readonly (readonly [string, SandboxDriver, () => Promise<void>, () => void])[] = [
      [
        'real',
        real.driver,
        async () => {
          if (how === 'requested') await real.driver.kill(name)
          else t.mock.timers.tick(5_000)
        },
        () => real.child.close(3, null),
      ],
      [
        'fake',
        fake,
        async () => {
          if (how === 'requested') await fake.kill(name)
          else fake.simulateOverrun(name)
        },
        () => undefined,
      ],
    ]
    for (const [label, driver, kill, exitOnItsOwn] of drivers) {
      const running = driver.run(spec(f, { name, limits }))
      await kill()
      // The kill ended nothing, and the name is still held.
      assert.throws(
        () => driver.run(spec(f, { name })),
        (e: unknown) => e instanceof ConfigError && /already running/.test(e.message),
        `${label}, ${how}`,
      )
      exitOnItsOwn()
      const result = await running.result
      assert.equal(result.killedBy, undefined, `${label}, ${how}`)
      assert.equal(result.exitCode, 3, `${label}, ${how}`)
      assert.equal(result.signal, null, `${label}, ${how}`)
      assert.equal(result.overran, how === 'wallclock' ? true : undefined, `${label}, ${how}`)
    }
    assert.deepEqual(fake.kills, how === 'requested' ? [name] : [])
  }

  // A requested kill, then the wallclock before the run ended: the
  // wallclock's kill is the one the end is credited to.
  const real = driverFor(f)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }] })
  const drivers: readonly (readonly [string, SandboxDriver, () => void, () => void])[] = [
    ['real', real.driver, () => t.mock.timers.tick(5_000), () => real.child.close(137, null)],
    ['fake', fake, () => fake.simulateOverrun(name), () => undefined],
  ]
  for (const [label, driver, wallclock, exitAfterKill] of drivers) {
    const running = driver.run(spec(f, { name, limits }))
    await driver.kill(name)
    wallclock()
    exitAfterKill()
    const result = await running.result
    assert.equal(result.killedBy, 'wallclock', label)
    assert.equal(result.signal, 'SIGKILL', label)
    assert.equal(result.exitCode, 137, label)
    assert.equal(result.overran, true, label)
  }

  // ignoresKill says something only of a run that hangs: one that does not
  // has ended before any kill reaches it.
  assert.throws(() => fakeSandbox({ imageId: IMAGE_ID, script: [{ ignoresKill: true }] }), /scripted exit 0: ignoresKill on a run that does not hang/)
})

test('the fake and the real driver agree: an exit of 137 with no kill sent is the run\'s own, with no killedBy', async (t) => {
  // Every run carries --memory, so the OOM killer's 137 is the commonest 137
  // that is not the kernel's, and a worker can `exit 137` itself. The docker
  // CLI exits the same for either as for the kernel's kill; what tells them
  // apart is that no kill was sent. Credited to a kill all the same, W1 would
  // log an OOM or a worker's own exit as an operator kill.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const real = driverFor(f)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ exitCode: 137 }] })
  const name = `${CONTAINER_PREFIX}oom`
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  const drivers: readonly (readonly [string, SandboxDriver, () => void])[] = [
    ['real', real.driver, () => real.child.close(137, null)],
    ['fake', fake, () => undefined],
  ]
  for (const [label, driver, exit] of drivers) {
    const running = driver.run(spec(f, { name, limits }))
    exit()
    const result = await running.result
    assert.equal(result.exitCode, 137, label)
    assert.equal(result.signal, null, label)
    assert.equal(result.killedBy, undefined, label)
    assert.equal(result.overran, undefined, label)
  }
  // No kill was sent, by anyone.
  assert.deepEqual(real.execs, [])
  assert.deepEqual(fake.kills, [])
})

test('the fake refuses a kill that ends nothing followed by a 137, which the real driver credits to that kill', async (t) => {
  // The docker CLI's 137 is the same for the kernel's kill as for the OOM
  // killer or a worker's own exit 137, so the real driver credits a 137 to
  // the kill sent before it, whether or not that kill reached a daemon.
  // Scripted on the fake, a kill that ends nothing and then a 137 would hand
  // runtime code a post-kill 137 with no killedBy, which docker never gives.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const name = `${CONTAINER_PREFIX}oom-after-kill`
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  for (const how of ['requested', 'wallclock'] as const) {
    const real = driverFor(f)
    real.setExec(() => Promise.reject(new Error('Cannot connect to the Docker daemon at unix:///tmp/colima-trusted.sock')))
    const running = real.driver.run(spec(f, { name, limits }))
    if (how === 'requested') await real.driver.kill(name)
    else t.mock.timers.tick(5_000)
    real.child.close(137, null)
    const result = await running.result
    assert.equal(result.killedBy, how, how)
    assert.equal(result.signal, 'SIGKILL', how)
    assert.equal(result.exitCode, 137, how)
  }

  assert.throws(
    () => fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }, { hangs: true, ignoresKill: true, exitCode: 137 }] }),
    /^Error: scripted exit 1: ignoresKill with exitCode 137, which the real driver reports as ended by the kill sent before it \(killedBy, SIGKILL\)/,
  )
  // Any other exit after a kill that ends nothing is one the real driver
  // gives (the parity test above), and so is a 137 with no ignoresKill.
  assert.doesNotThrow(() =>
    fakeSandbox({
      script: [
        { hangs: true, ignoresKill: true, exitCode: 136 },
        { hangs: true, ignoresKill: true, exitCode: 0 },
        { hangs: true, exitCode: 137 },
        { exitCode: 137 },
      ],
    }),
  )
})

test('the fake and the real driver agree: a killed run returns what it wrote before the kill, with the CLI\'s 137, and an overrun ran its whole wallclock', async (t) => {
  // W1 logs a killed run's partial output: what it had done before the kernel
  // ended it. The real driver returns whatever it captured up to the kill,
  // and the docker CLI's 137 as its exit code; a fake that reported '' would
  // let code that drops that output pass against it, and one that reported
  // a null exit code, code that told a kill by one. Date is mocked with the
  // wallclock, so the real driver's duration for an overrun is the wallclock
  // too, as the fake's must be: a run that outlived its wallclock did not end
  // sooner.
  const f = fixture(t)
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
  const name = `${CONTAINER_PREFIX}partial`
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  const wrote = { stdout: 'partial progress\n', stderr: 'warn\n' }
  for (const how of ['requested', 'wallclock'] as const) {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const real = driverFor(f, { stdout, stderr })
    const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true, ...wrote }] })
    const drivers: readonly (readonly [string, SandboxDriver, () => Promise<void>])[] = [
      [
        'real',
        real.driver,
        async () => {
          stdout.end(wrote.stdout)
          stderr.end(wrote.stderr)
          await Promise.all([finished(stdout), finished(stderr)])
          if (how === 'requested') await real.driver.kill(name)
          else t.mock.timers.tick(5_000)
          real.child.close(137, null)
        },
      ],
      [
        'fake',
        fake,
        async () => {
          if (how === 'requested') await fake.kill(name)
          else fake.simulateOverrun(name)
        },
      ],
    ]
    for (const [label, driver, kill] of drivers) {
      const running = driver.run(spec(f, { name, limits }))
      await kill()
      const result = await running.result
      assert.equal(result.stdout, wrote.stdout, `${label}, ${how}`)
      assert.equal(result.stderr, wrote.stderr, `${label}, ${how}`)
      assert.equal(result.truncated, false, `${label}, ${how}`)
      assert.equal(result.exitCode, 137, `${label}, ${how}`)
      assert.equal(result.signal, 'SIGKILL', `${label}, ${how}`)
      assert.equal(result.killedBy, how, `${label}, ${how}`)
      assert.equal(result.overran, how === 'wallclock' ? true : undefined, `${label}, ${how}`)
      if (how === 'wallclock') assert.equal(result.durationMs, 5_000, `${label}, ${how}`)
    }
  }

  // A cut is kept too, as the real driver keeps a cut it made before the kill.
  const cut = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true, stdout: 'o'.repeat(CAPTURE_MAX_BYTES), truncated: true }] })
  const running = cut.run(spec(f, { name, limits }))
  await cut.kill(name)
  const result = await running.result
  assert.equal(result.truncated, true)
  assert.equal(result.stdout.length, CAPTURE_MAX_BYTES)
  assert.equal(result.killedBy, 'requested')
})

test('the fake and the real driver agree: a kill sent after the wallclock fired, before the run ended, leaves it ended by the wallclock', async (t) => {
  // The wallclock's kill is the one that ended the run. A requested kill sent
  // after it (an operator, a shutdown) does not rewrite why the run ended: a
  // run reported killedBy requested with overran would say the operator
  // ended a run that had outlived its hard wallclock.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  const real = driverFor(f)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }] })
  const name = `${CONTAINER_PREFIX}late-kill`
  const limits = { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 }
  const drivers: readonly (readonly [string, SandboxDriver, () => void, () => void])[] = [
    ['real', real.driver, () => t.mock.timers.tick(5_000), () => real.child.close(137, null)],
    ['fake', fake, () => fake.simulateOverrun(name), () => undefined],
  ]
  for (const [label, driver, wallclock, exitAfterKill] of drivers) {
    const running = driver.run(spec(f, { name, limits }))
    wallclock()
    await driver.kill(name)
    exitAfterKill()
    const result = await running.result
    assert.equal(result.killedBy, 'wallclock', label)
    assert.equal(result.signal, 'SIGKILL', label)
    assert.equal(result.exitCode, 137, label)
    assert.equal(result.overran, true, label)
  }
  assert.deepEqual(fake.kills, [name])
})

/** `n` real macrotask turns, on setImmediate as it was before any test could mock it. */
const realImmediate = setImmediate
async function turns(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await new Promise<void>((resolve) => realImmediate(() => resolve()))
}

/** What a run's result has settled to so far, read without awaiting it. */
function soFar(running: { readonly result: Promise<SandboxResult> }): () => SandboxResult | undefined {
  let settled: SandboxResult | undefined
  void running.result.then((r) => {
    settled = r
  })
  return () => settled
}

test('a killed hung run on the fake still ends with every timer API mocked', async (t) => {
  // A test that mocks timers, to drive the real driver's wallclock or its own
  // clock, must not stop the fake's hung runs from ending: the fake queues a
  // kill's end on setImmediate as it was when the fake loaded. Queued on the
  // global one, mocked here, the run would never end and its caller would
  // wait for good.
  const f = fixture(t)
  t.mock.timers.enable()
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }, { hangs: true }] })
  for (const [how, name] of [
    ['requested', `${CONTAINER_PREFIX}mocked-kill`],
    ['wallclock', `${CONTAINER_PREFIX}mocked-overrun`],
  ] as const) {
    const result = soFar(fake.run(spec(f, { name })))
    if (how === 'requested') await fake.kill(name)
    else fake.simulateOverrun(name)
    await turns(3)
    assert.equal(result()?.killedBy, how, `${how}: the run did not end with timers mocked`)
  }
})

test('two kills of a hung run in one tick end it once, and a rerun of its name is still the kill\'s to end', async (t) => {
  // Each kill would otherwise queue an end of its own. The first frees the
  // name, and a caller that starts it again in its continuation gets a new
  // run under it, before the second end runs; that end would then forget the
  // new run, and no kill could ever end it.
  const f = fixture(t)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ hangs: true }, { hangs: true }] })
  const name = `${CONTAINER_PREFIX}twice-killed`
  const first = fake.run(spec(f, { name }))
  await Promise.all([fake.kill(name), fake.kill(name)])
  assert.equal((await first.result).killedBy, 'requested')
  // In the continuation of the first result, before the next macrotask.
  const result = soFar(fake.run(spec(f, { name })))
  await turns(3)
  assert.equal(result(), undefined, 'the rerun ended though nothing killed it')
  await fake.kill(name)
  await turns(3)
  assert.equal(result()?.killedBy, 'requested', 'a kill of the rerun did not end it')
  assert.deepEqual(fake.kills, [name, name, name])
})

/** A file's header, every line before its first import, as one line of prose. */
function headerOf(rel: string): string {
  const source = readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8')
  return source
    .slice(0, source.indexOf('\nimport '))
    .split('\n')
    .map((l) => l.replace(/^\/\/ ?/, ''))
    .join(' ')
    .replace(/\s+/g, ' ')
}

/** docker.ts's file header. */
function dockerHeader(): string {
  return headerOf('src/sandbox/docker.ts')
}

/** The docker commands docker.ts's header says the driver runs, sorted. */
function headerCommands(): string[] {
  const listed = /It runs ((?:`[^`]+`, )+`[^`]+` and `[^`]+`), and nothing else/.exec(dockerHeader())
  assert.ok(listed, `docker.ts's header no longer lists the commands it runs as this test reads them: ${dockerHeader()}`)
  return [...(listed[1] ?? '').matchAll(/`([^`]+)`/g)].map((m) => m[1] ?? '').sort()
}

/** The commands the driver runs today, as the header names them. */
const DRIVER_COMMANDS = ['image inspect', 'kill', 'network inspect', 'ps', 'run', 'version']

/**
 * docker's management commands, whose command is two words (`network
 * inspect`, `image pull`, `container ls`); any other first word is a command
 * on its own (`ps`, `kill`, `rm`).
 */
const MANAGEMENT = new Set([
  'builder', 'buildx', 'checkpoint', 'compose', 'config', 'container', 'context', 'image', 'manifest',
  'network', 'node', 'plugin', 'secret', 'service', 'stack', 'swarm', 'system', 'trust', 'volume',
])

/** The docker command an argv names, as docker reads it. */
function dockerCommand(args: readonly string[]): string {
  const [first = '', second = ''] = args
  return MANAGEMENT.has(first) ? `${first} ${second}` : first
}

/**
 * Every docker command docker.ts's source can run, read from its syntax tree
 * rather than from the paths some test happens to drive: the command words of
 * each argv literal handed to this.#options.execFile, on whatever path it
 * stands, and of the argv literal buildRunArgs returns, which is the only argv
 * this.#options.spawn may be handed. `unread` names each place the file reaches
 * a process in a way this cannot read the command of: an argv that is not a
 * literal led by its command's words, a binary other than this.#binary, a
 * spawn of anything but buildRunArgs' argv, this.#options or one of its
 * process functions taken as a value, or node:child_process called anywhere
 * but realDockerDriver's forwarding of the argv it was handed. A command this
 * cannot read is one the header's list cannot be held to.
 */
function dockerCommandsInSource(text: string): { readonly commands: readonly string[]; readonly unread: readonly string[] } {
  const source = ts.createSourceFile('docker.ts', text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const where = (node: ts.Node): string =>
    `docker.ts:${String(source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1)}: ${node.getText(source).replace(/\s+/g, ' ').slice(0, 100)}`
  const commands = new Set<string>()
  const unread: string[] = []
  const isThis = (node: ts.Node, name: string): node is ts.PropertyAccessExpression =>
    ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword && node.name.text === name
  const visit = (node: ts.Node, each: (n: ts.Node) => void): void => {
    each(node)
    ts.forEachChild(node, (child) => {
      visit(child, each)
    })
  }
  const enclosing = (node: ts.Node, is: (n: ts.Node) => boolean): ts.Node | undefined => {
    for (let n = node.parent; n !== undefined; n = n.parent) if (is(n)) return n
    return undefined
  }
  // The command an argv literal names: its leading string literals, two of
  // them for a management command.
  const commandOf = (argv: ts.Expression | undefined): string | undefined => {
    if (argv === undefined || !ts.isArrayLiteralExpression(argv)) return undefined
    const lead: string[] = []
    for (const el of argv.elements.slice(0, 2)) {
      if (!ts.isStringLiteral(el) && !ts.isNoSubstitutionTemplateLiteral(el)) break
      lead.push(el.text)
    }
    const [first] = lead
    if (first === undefined || (MANAGEMENT.has(first) && lead.length < 2)) return undefined
    return dockerCommand(lead)
  }

  // buildRunArgs' argv: its `const args = [...]`, returned as built.
  const builder = source.statements.find(
    (s): s is ts.FunctionDeclaration => ts.isFunctionDeclaration(s) && s.name?.text === 'buildRunArgs',
  )
  let runCommand: string | undefined
  if (builder?.body === undefined) unread.push('docker.ts: no function buildRunArgs')
  else {
    visit(builder.body, (n) => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === 'args') {
        runCommand = commandOf(n.initializer)
        if (runCommand === undefined) unread.push(where(n))
      }
      if (ts.isReturnStatement(n) && enclosing(n, ts.isFunctionLike) === builder) {
        if (n.expression === undefined || !ts.isIdentifier(n.expression) || n.expression.text !== 'args') unread.push(where(n))
      }
    })
    if (runCommand === undefined) unread.push('docker.ts: buildRunArgs builds no `const args = [...]`')
  }

  const PROCESS = new Set(['spawn', 'execFile', 'execFileAsync'])
  const realDriver = source.statements.find(
    (s): s is ts.FunctionDeclaration => ts.isFunctionDeclaration(s) && s.name?.text === 'realDockerDriver',
  )
  visit(source, (n) => {
    // this.#options is only ever read through, or set once in the constructor.
    if (isThis(n, '#options')) {
      const p = n.parent
      const readThrough = ts.isPropertyAccessExpression(p) && p.expression === n
      const set = ts.isBinaryExpression(p) && p.left === n && p.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        enclosing(n, ts.isFunctionLike)?.kind === ts.SyntaxKind.Constructor
      if (!readThrough && !set) unread.push(where(p))
      return
    }
    // Its process functions, only ever called, by docker, with an argv read here.
    if (ts.isPropertyAccessExpression(n) && isThis(n.expression, '#options') && (n.name.text === 'execFile' || n.name.text === 'spawn')) {
      const call = n.parent
      if (!ts.isCallExpression(call) || call.expression !== n) return void unread.push(where(call))
      const [binary, argv] = call.arguments
      if (binary === undefined || !isThis(binary, '#binary')) return void unread.push(where(call))
      if (n.name.text === 'execFile') {
        const command = commandOf(argv)
        if (command === undefined) return void unread.push(where(call))
        commands.add(command)
        return
      }
      // spawn: an argv the enclosing method took from buildRunArgs.
      const method = enclosing(call, ts.isFunctionLike)
      let fromBuilder = false
      if (argv !== undefined && ts.isIdentifier(argv) && method !== undefined) {
        visit(method, (m) => {
          if (
            ts.isVariableDeclaration(m) && ts.isIdentifier(m.name) && m.name.text === argv.text &&
            m.initializer !== undefined && ts.isCallExpression(m.initializer) &&
            ts.isIdentifier(m.initializer.expression) && m.initializer.expression.text === 'buildRunArgs'
          ) fromBuilder = true
        })
      }
      if (!fromBuilder || runCommand === undefined) return void unread.push(where(call))
      commands.add(runCommand)
      return
    }
    // node:child_process by its one import, which takes execFile and spawn by
    // those names and nothing else, and named in no other string: a third
    // function, an alias or the whole module is a way to run what no argv
    // read here names.
    if ((ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) && /^(?:node:)?child_process$/.test(n.text)) {
      const decl = n.parent
      const clause = ts.isImportDeclaration(decl) && decl.moduleSpecifier === n ? decl.importClause : undefined
      const bindings = clause?.namedBindings
      const only =
        clause !== undefined && clause.name === undefined && bindings !== undefined && ts.isNamedImports(bindings) &&
        bindings.elements.every((el) => el.propertyName === undefined && (el.name.text === 'execFile' || el.name.text === 'spawn'))
      if (!only) unread.push(where(decl))
      return
    }
    // node:child_process's functions, and the promisified one: imported,
    // promisified, declared, and called only by realDockerDriver, forwarding
    // the argv it was handed (`[...args]`), which the class above built.
    if (ts.isIdentifier(n) && PROCESS.has(n.text)) {
      const p = n.parent
      const named =
        (ts.isPropertyAccessExpression(p) && p.name === n) ||
        ((ts.isPropertyAssignment(p) || ts.isPropertySignature(p)) && p.name === n) ||
        ts.isImportSpecifier(p) ||
        (ts.isVariableDeclaration(p) && p.name === n)
      const promisified = ts.isCallExpression(p) && ts.isIdentifier(p.expression) && p.expression.text === 'promisify' && p.arguments[0] === n
      const argv = ts.isCallExpression(p) ? p.arguments[1] : undefined
      const spread = argv !== undefined && ts.isArrayLiteralExpression(argv) ? argv.elements : undefined
      const forwarded =
        ts.isCallExpression(p) && p.expression === n && p.arguments.length === 3 &&
        realDriver !== undefined && enclosing(p, (x) => x === realDriver) !== undefined &&
        spread?.length === 1 && spread[0] !== undefined && ts.isSpreadElement(spread[0])
      if (!named && !promisified && !forwarded) unread.push(where(p))
    }
  })
  return { commands: [...commands].sort(), unread }
}

const DOCKER_SOURCE = readFileSync(new URL('../src/sandbox/docker.ts', import.meta.url), 'utf8')

test("docker.ts's header names every docker command its source can run, and no other", () => {
  // The header says why the driver needs no HOME and no credential helper:
  // what it runs pulls nothing. A list that leaves a command out is that
  // argument made about another driver. So the list is held to the source,
  // every argv on every path, an error path as much as a healthy one, rather
  // than to what a test happens to reach.
  const { commands, unread } = dockerCommandsInSource(DOCKER_SOURCE)
  assert.deepEqual(unread, [], 'docker.ts reaches a process in a way this test cannot read the docker command of')
  assert.deepEqual(headerCommands(), commands, "the commands docker.ts's header names are not the ones its source can run")
  assert.deepEqual(commands, DRIVER_COMMANDS)
})

test('the source scan reads a docker command on any path, and refuses a process call it cannot read', () => {
  // The scan above is what holds the header, so it is held here to the edits
  // it exists to see: each is made to docker.ts's text in memory, never on
  // disk, and must change what the scan reports.
  const edit = (from: string, to: string): string => {
    assert.equal(DOCKER_SOURCE.split(from).length, 2, `docker.ts no longer holds, once, ${JSON.stringify(from)}`)
    return DOCKER_SOURCE.replace(from, to)
  }
  const sweepCatch = '    } catch {\n      return []\n    }\n'
  const killCatch = '    } catch {\n      // "No such container" is the normal outcome'
  const pull = "await this.#options.execFile(this.#binary, ['image', 'pull', 'alpine'], { env: this.#env(domain) })"
  // docker.ts's one process import, and the module it names, read from the
  // file rather than spelt here: test/hygiene.test.ts counts a test that
  // spells an import of that module as one that imports it.
  const processImport = DOCKER_SOURCE.split('\n').find((l) => l.startsWith('import { execFile, spawn } from ')) ?? ''
  const processModule = /from '([^']+)'/.exec(processImport)?.[1] ?? ''
  assert.ok(processModule.endsWith('child_process'), `docker.ts's process import is not the one this test reads: ${processImport}`)
  const cases: [string, string, Partial<{ commands: string[]; unread: RegExp }>][] = [
    ['a pull in the sweep\'s catch', edit(sweepCatch, `    } catch {\n      ${pull}\n      return []\n    }\n`), { commands: [...DRIVER_COMMANDS, 'image pull'].sort() }],
    ['an rm in the kill\'s catch', edit(killCatch, "    } catch {\n      await this.#options.execFile(this.#binary, ['rm', '-f', name], { env: this.#env(domain) })\n      // \"No such container\" is the normal outcome"), { commands: [...DRIVER_COMMANDS, 'rm'].sort() }],
    ['a management command with no second word', edit(sweepCatch, "    } catch {\n      await this.#options.execFile(this.#binary, ['image', name], { env: this.#env(domain) })\n      return []\n    }\n"), { unread: /\['image', name\]/ }],
    ['an argv built at run time', edit(sweepCatch, "    } catch {\n      await this.#options.execFile(this.#binary, ['image', 'pull'].slice(), { env: this.#env(domain) })\n      return []\n    }\n"), { unread: /\.slice\(\)/ }],
    ['another binary', edit(sweepCatch, "    } catch {\n      await this.#options.execFile('/bin/sh', ['ps'], { env: this.#env(domain) })\n      return []\n    }\n"), { unread: /'\/bin\/sh'/ }],
    ['execFile taken as a value', edit(sweepCatch, "    } catch {\n      const run = this.#options.execFile\n      await run(this.#binary, ['image', 'pull', 'alpine'], { env: this.#env(domain) })\n      return []\n    }\n"), { unread: /run = this\.#options\.execFile/ }],
    ['#options taken whole', edit(sweepCatch, "    } catch {\n      const { execFile } = this.#options\n      await execFile(this.#binary, ['image', 'pull', 'alpine'], { env: this.#env(domain) })\n      return []\n    }\n"), { unread: /this\.#options/ }],
    ['child_process called in the class', edit(sweepCatch, "    } catch {\n      await execFileAsync('docker', ['image', 'pull', 'alpine'])\n      return []\n    }\n"), { unread: /execFileAsync\('docker'/ }],
    ['a spawn of an argv not built by buildRunArgs', edit('    const child = this.#options.spawn(this.#binary, args, { env: this.#env(spec.domain) })', "    const child = this.#options.spawn(this.#binary, ['image', 'pull', 'alpine'], { env: this.#env(spec.domain) })"), { unread: /this\.#options\.spawn\(this\.#binary, \['image'/ }],
    ['a third child_process function imported', edit(processImport, processImport.replace('{ execFile, spawn }', '{ exec, execFile, spawn }')), { unread: /import \{ exec, execFile, spawn \}/ }],
    ['child_process imported under an alias', edit(processImport, processImport.replace('spawn }', 'spawn as start }')), { unread: /spawn as start/ }],
    ['child_process reached by name', edit(sweepCatch, `    } catch {\n      void process.getBuiltinModule('${processModule}')\n      return []\n    }\n`), { unread: /getBuiltinModule\(/ }],
    ['buildRunArgs returning another argv', edit('  auditRunArgs(args, home, workspace, input.imageId, channel)\n  return args\n', "  auditRunArgs(args, home, workspace, input.imageId, channel)\n  return ['image', 'pull', spec.image]\n"), { unread: /return \['image', 'pull'/ }],
  ]
  for (const [label, text, expect] of cases) {
    const scanned = dockerCommandsInSource(text)
    if (expect.commands !== undefined) {
      assert.deepEqual(scanned.unread, [], label)
      assert.deepEqual(scanned.commands, expect.commands, label)
    }
    if (expect.unread !== undefined) {
      assert.ok(scanned.unread.some((u) => expect.unread?.test(u) === true), `${label}: the scan read it: ${JSON.stringify(scanned)}`)
    }
  }
})

/** The kernel's orphans as the sweep below lists them, one per VM. */
const ORPHAN = `${CONTAINER_PREFIX}orphan`

/**
 * Drive every entry point of a fresh spied driver against `answer` (probe; a
 * run that exits; a run whose wallclock fires; a run whose CLI fails to start;
 * a spawn that throws; a kill of a name no run holds, which asks both VMs; the
 * orphan sweep), and return the docker command of every call that reached
 * docker. Timers must be mocked: the wallclock is ticked, not waited for.
 */
async function driveEveryEntry(
  t: TestContext,
  f: Fixture,
  answer: ScriptedExec,
): Promise<{ readonly reached: readonly string[]; readonly calls: number; readonly probe: unknown; readonly swept: readonly string[] }> {
  const d = driverFor(f)
  d.setExec(answer)
  const probe = await d.driver.probe()
  const exited = d.driver.run(spec(f))
  d.child.close(0, null)
  await exited.result
  const timed = d.driver.run(spec(f, { limits: { memoryMb: 1, cpus: 1, pids: 1, wallclockMs: 5_000 } }))
  t.mock.timers.tick(5_000)
  await turns(3)
  d.child.close(137, null)
  await timed.result
  const failed = d.driver.run(spec(f))
  d.child.fail(new Error('spawn docker ENOENT'))
  await failed.result
  d.failNextSpawn(new Error('spawn E2BIG'))
  assert.throws(() => d.driver.run(spec(f)), /E2BIG/)
  await d.driver.kill(`${CONTAINER_PREFIX}gone`)
  const swept = await d.driver.sweepOrphans()
  // Long enough for a command a catch sends after its refusal to arrive.
  await turns(3)
  return {
    reached: [...new Set([...d.spawns, ...d.execs].map((call) => dockerCommand(call.args)))],
    calls: d.execs.length,
    probe,
    swept,
  }
}

test("every docker command the driver reaches, from a healthy daemon or one that refuses any call, is one docker.ts's header names", async (t) => {
  // The source scan above holds the list to every argv in the file. This
  // holds it to what reaches docker, the paths that run when a daemon fails
  // as well as when it answers: each entry point is driven against a healthy
  // daemon, one that refuses every call, and, for each call the healthy drive
  // makes, one that refuses that call alone, so that every catch runs.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const f = fixture(t)
  // The orphans are listed for any command that asks for the kernel's
  // containers by name, whatever its command word (listsOrphans), so a sweep
  // that lists by another command still sweeps, and is caught by what it ran.
  const healthy: ScriptedExec = (args, env) =>
    listsOrphans(args) ? Promise.resolve({ stdout: `${ORPHAN}\n`, stderr: '' }) : healthyDaemon('29.5.2')(args, env)
  const refused = (): Promise<never> => Promise.reject(new Error('Cannot connect to the Docker daemon at unix:///tmp/colima-trusted.sock'))

  const first = await driveEveryEntry(t, f, healthy)
  assert.deepEqual(first.probe, { ok: true, version: '29.5.2' })
  assert.deepEqual(first.swept, [ORPHAN, ORPHAN])
  const reached = new Set(first.reached)
  const drives = [refused, ...Array.from({ length: first.calls }, (_, i): ScriptedExec => {
    let seen = 0
    return (args, env) => (++seen === i + 1 ? refused() : healthy(args, env))
  })]
  for (const answer of drives) for (const command of (await driveEveryEntry(t, f, answer)).reached) reached.add(command)

  const sorted = [...reached].sort()
  assert.deepEqual(headerCommands(), sorted, "the commands docker.ts's header names are not the ones the driver runs")
  assert.deepEqual(sorted, DRIVER_COMMANDS)
})

test("the sandbox layer's prose names the accepted egress design: the kernel's egress engine over the -i channel, no proxy, and a domain network no run is put on", () => {
  // The operator accepted the egress design on 2026-11-09: no proxy
  // container, no sidecar, no listener in any VM; the kernel's egress engine
  // (src/egress) over each run's docker -i channel, with every worker on
  // --network none. Each domain's internal network is kept and probed as
  // defence in depth, and no run is put on it. Prose that names the old
  // design tells the next reader to build it.
  const read = (rel: string): string => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8')
  const OLD_DESIGN = /egress proxy|proxy sidecar|Phase 2 proxy/i
  // Every file of the sandbox layer, as the directory holds it, so a new one
  // is read the day it lands, and the script that makes its VMs and networks.
  const layer = readdirSync(new URL('../src/sandbox/', import.meta.url))
    .filter((name) => name.endsWith('.ts'))
    .sort()
    .map((name) => `src/sandbox/${name}`)
  for (const rel of ['src/sandbox/apple-container.ts', 'src/sandbox/confine.ts', 'src/sandbox/docker.ts', 'src/sandbox/driver.ts', 'src/sandbox/limits.ts']) {
    assert.ok(layer.includes(rel), `the sandbox layer read from src/sandbox/ lacks ${rel}: ${layer.join(', ')}`)
  }
  for (const rel of [...layer, 'scripts/colima-up.sh']) assert.doesNotMatch(read(rel), OLD_DESIGN, rel)
  const credentialsOut =
    "which is the failure the kernel's egress engine (src/egress) exists to prevent in Phase 2, by injecting each credential at the kernel's edge and never in the container"
  assert.ok(dockerHeader().includes(credentialsOut), "docker.ts's header does not name the kernel's egress engine as what keeps a worker's credentials out")
  // This file's header, whose falsifiers say the same of the environment a
  // worker must never inherit.
  const ownHeader = headerOf('test/sandbox-docker.test.ts')
  assert.doesNotMatch(ownHeader, OLD_DESIGN, "test/sandbox-docker.test.ts's header names the old design")
  assert.ok(ownHeader.includes(credentialsOut), "test/sandbox-docker.test.ts's header does not name the kernel's egress engine as what keeps a worker's credentials out")

  // driver.ts's SandboxDomain: a VM of its own, and an internal network that
  // is kept and probed, not the network its runs are on.
  const driver = read('src/sandbox/driver.ts')
  const at = driver.indexOf('export type SandboxDomain')
  assert.ok(at > 0, 'driver.ts no longer declares SandboxDomain')
  const doc = driver.slice(driver.lastIndexOf('/**', at), at).replace(/^\s*\/?\*+\/?/gm, '').replace(/\s+/g, ' ').trim()
  assert.equal(doc, 'Isolation domain. Each maps to its own VM; its internal network is kept and probed as defence in depth, and no run is put on it.')

  // colima-up.sh's network comment says the same of the network it makes.
  const script = read('scripts/colima-up.sh')
  const comment = /^ {2}# --internal: [\s\S]*?(?=^ {2}local network=)/m.exec(script)?.[0].replace(/^\s*# ?/gm, '').replace(/\s+/g, ' ').trim() ?? ''
  for (const fact of ['No worker is attached to it: every run is --network none', "the kernel's egress engine, over its run's docker -i channel", 'as defence in depth']) {
    assert.ok(comment.includes(fact), `colima-up.sh's network comment does not say: ${fact}\n${comment}`)
  }
})

// ── what a run writes ──────────────────────────────────────────────────────

const MiB = 1024 * 1024

/**
 * One run whose streams are real streams: write to them, end them, and return
 * the result once both have been read to the end.
 *
 * A driver must never stop reading, or the container blocks on a full pipe. A
 * driver that pauses a stream fails here at once, by name (a Readable emits
 * 'pause' when paused); one that stops reading any other way leaves `finished`
 * waiting, and the test's timeout says so.
 */
async function capture(
  t: TestContext,
  write: (stdout: PassThrough, stderr: PassThrough) => void,
): Promise<SandboxResult> {
  const f = fixture(t)
  const stdout = new PassThrough()
  const stderr = new PassThrough()
  const d = driverFor(f, { stdout, stderr })
  const running = d.driver.run(spec(f))
  const paused = new Promise<never>((_resolve, reject) => {
    for (const [label, stream] of [['stdout', stdout], ['stderr', stderr]] as const) {
      stream.once('pause', () => {
        reject(new Error(`the driver paused ${label}: a container writing to it would block on a full pipe`))
      })
    }
  })
  try {
    write(stdout, stderr)
    stdout.end()
    stderr.end()
    await Promise.race([Promise.all([finished(stdout), finished(stderr)]), paused])
  } finally {
    d.child.close(0, null)
  }
  return running.result
}

test('run keeps at most the capture cap of stdout and stderr and reports truncation', { timeout: 30_000 }, async (t) => {
  // More than the log stores, so the log's own cut, made after redaction,
  // decides what it keeps (events/bound.ts); and far less than 10 MiB, or this
  // test would prove nothing.
  assert.ok(CAPTURE_MAX_BYTES > MAX_LOGGED_OUTPUT)
  assert.ok(10 * MiB > 2 * CAPTURE_MAX_BYTES)

  // 10 MiB on each stream, in pipe-sized chunks. The bytes past the cap differ
  // from the ones before it, so a result holding any of them shows.
  const chunk = 64 * 1024
  const result = await capture(t, (stdout, stderr) => {
    for (let at = 0; at < 10 * MiB; at += chunk) {
      const kept = at < CAPTURE_MAX_BYTES
      stdout.write(Buffer.alloc(chunk, kept ? 'o' : 'z'))
      stderr.write(Buffer.alloc(chunk, kept ? 'e' : 'z'))
    }
  })

  // Both streams were read to their end (capture() awaited it), and of each
  // only its first CAPTURE_MAX_BYTES were kept.
  assert.equal(Buffer.byteLength(result.stdout), CAPTURE_MAX_BYTES)
  assert.ok(result.stdout === 'o'.repeat(CAPTURE_MAX_BYTES), 'stdout is not its first CAPTURE_MAX_BYTES')
  assert.equal(Buffer.byteLength(result.stderr), CAPTURE_MAX_BYTES)
  assert.ok(result.stderr === 'e'.repeat(CAPTURE_MAX_BYTES), 'stderr is not its first CAPTURE_MAX_BYTES')
  assert.equal(result.truncated, true)
  assert.equal(result.exitCode, 0)
})

test('a small output is returned whole and not marked truncated, nor is a stream that fills the cap exactly', { timeout: 30_000 }, async (t) => {
  // A character split across two chunks, as a pipe may split it. Decoded a
  // chunk at a time, it would come back as two U+FFFD.
  const line = Buffer.from('ok é\n', 'utf8')
  const split = line.indexOf(0xc3) + 1
  const result = await capture(t, (stdout, stderr) => {
    stdout.write(line.subarray(0, split))
    stdout.write(line.subarray(split))
    stderr.write(Buffer.alloc(CAPTURE_MAX_BYTES, 'e'))
  })
  assert.equal(result.stdout, 'ok é\n')
  assert.ok(result.stderr === 'e'.repeat(CAPTURE_MAX_BYTES), 'a stream exactly at the cap lost bytes')
  assert.equal(result.truncated, false)

  // One byte more is a cut, and either stream's cut alone sets the flag.
  const over = await capture(t, (stdout, stderr) => {
    stdout.write('ok\n')
    stderr.write(Buffer.alloc(CAPTURE_MAX_BYTES + 1, 'e'))
  })
  assert.equal(over.stdout, 'ok\n')
  assert.ok(over.stderr === 'e'.repeat(CAPTURE_MAX_BYTES), 'stderr is not its first CAPTURE_MAX_BYTES')
  assert.equal(over.truncated, true)
})

test('the cut never splits a character, and a stream that is not UTF-8 still keeps the cap', { timeout: 30_000 }, async (t) => {
  // A two-byte character one short of the cap, and a four-byte one two short.
  const result = await capture(t, (stdout, stderr) => {
    stdout.write(Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - 1, 'a'), Buffer.from('é and more')]))
    stderr.write(Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - 2, 'a'), Buffer.from('\u{1F600} and more')]))
  })
  assert.ok(result.stdout === 'a'.repeat(CAPTURE_MAX_BYTES - 1), 'stdout was not cut before the split character')
  assert.ok(result.stderr === 'a'.repeat(CAPTURE_MAX_BYTES - 2), 'stderr was not cut before the split character')
  assert.equal(result.truncated, true)

  // A four-byte character three short of the cap: all three of its
  // continuation bytes are kept and the first one dropped is its last, so the
  // walk back goes the full three. A walk bounded at two would keep F0 9F 98,
  // and the text would end in U+FFFD.
  const longest = await capture(t, (stdout) => {
    stdout.write(Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - 3, 'a'), Buffer.from('\u{1F600} and more')]))
  })
  assert.ok(longest.stdout === 'a'.repeat(CAPTURE_MAX_BYTES - 3), 'stdout was not cut before the split character')

  // A three-byte character (€, …, a smart quote, a box-drawing bar, CJK: the
  // commonest non-ASCII in CLI output) split by the cap, its lead two short of
  // the cap and one short. A lead read as declaring two bytes keeps the first
  // case's E2 82, one read as standing alone keeps either's lead, and the text
  // ends in U+FFFD.
  const three = await capture(t, (stdout, stderr) => {
    stdout.write(Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - 2, 'a'), Buffer.from('€… and more')]))
    stderr.write(Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - 1, 'a'), Buffer.from('€… and more')]))
  })
  assert.ok(three.stdout === 'a'.repeat(CAPTURE_MAX_BYTES - 2), 'stdout was not cut before the split €')
  assert.ok(three.stderr === 'a'.repeat(CAPTURE_MAX_BYTES - 1), 'stderr was not cut before the split €')
  assert.equal(three.truncated, true)

  // Continuation bytes with no character to belong to, after one that is
  // ASCII: the cut stays at the cap, each continuation byte decodes to U+FFFD,
  // and the stream is not walked back to the last lead it can find (here to
  // its first byte, keeping one).
  const binary = await capture(t, (stdout) => {
    stdout.write(Buffer.concat([Buffer.from('x'), Buffer.alloc(CAPTURE_MAX_BYTES + 15, 0x80)]))
  })
  assert.equal(binary.stdout.length, CAPTURE_MAX_BYTES)
  assert.ok(/^x\uFFFD*$/.test(binary.stdout))
  assert.equal(binary.truncated, true)
})

test('a stray continuation byte past the cap costs no character that the cap does not split', { timeout: 30_000 }, async (t) => {
  // The first byte dropped continues nothing kept: what ends at the cap is a
  // whole character, an ASCII x or a complete é, € or 😀, and it is kept. Only
  // a lead whose character runs past the cap moves the cut, so a byte that is
  // not UTF-8 costs the text nothing before it.
  const stray = Buffer.from([0x80, 0x80, 0x41])
  const before = (n: number, text: string): Buffer =>
    Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - n, 'a'), Buffer.from(text), stray])
  const short = await capture(t, (stdout, stderr) => {
    stdout.write(before(1, 'x'))
    stderr.write(before(2, 'é'))
  })
  assert.ok(short.stdout === `${'a'.repeat(CAPTURE_MAX_BYTES - 1)}x`, 'the x before a stray continuation byte was dropped')
  assert.ok(short.stderr === `${'a'.repeat(CAPTURE_MAX_BYTES - 2)}é`, 'the é before a stray continuation byte was dropped')
  assert.equal(short.truncated, true)

  const long = await capture(t, (stdout, stderr) => {
    stdout.write(before(3, '€'))
    stderr.write(before(4, '\u{1F600}'))
  })
  assert.ok(long.stdout === `${'a'.repeat(CAPTURE_MAX_BYTES - 3)}€`, 'the € before a stray continuation byte was dropped')
  assert.ok(long.stderr === `${'a'.repeat(CAPTURE_MAX_BYTES - 4)}\u{1F600}`, 'the 😀 before a stray continuation byte was dropped')
  assert.equal(long.truncated, true)
})

/**
 * A full collection, for the one test that measures what a capture holds: the
 * process's own gc when it was started with --expose-gc, as npm test and the
 * falsify runner start every test file (test/falsify.test.ts holds both to
 * it), and otherwise, for this file run some other way, one exposed at
 * runtime through V8's flag, which Node 20 and 22 honour. Should a later V8
 * stop honouring that, this says so and fails, rather than skipping: a skip
 * passes, and this is the only check of the memory bound.
 */
function exposedGc(): () => void {
  const own: unknown = (globalThis as { gc?: unknown }).gc
  if (typeof own === 'function') return own as () => void
  setFlagsFromString('--expose-gc')
  const exposed: unknown = runInNewContext("typeof gc === 'function' ? gc : undefined")
  assert.ok(
    typeof exposed === 'function',
    `Node ${process.version} did not expose gc at runtime, so what a capture holds cannot be measured; ` +
      'run this file with node --expose-gc --import tsx --test',
  )
  return exposed as () => void
}

test('a stream that arrives a byte at a time, then far past the cap, costs the kernel about the bytes kept', { timeout: 60_000 }, async (t) => {
  // A container decides how its output is cut: one that writes a byte per
  // write, paced, reaches the kernel as one-byte pipe chunks. Kept a chunk at a
  // time, each byte would cost the kernel a Buffer, about a hundred bytes of
  // heap with pooled one-byte Buffers like these (measured: 114 MiB a stream at
  // the cap). Copied into blocks the capture owns, they cost what they hold.
  //
  // And one that writes on for its whole wallclock must cost nothing more once
  // its cap is reached, so each stream is then fed 8 MiB past the cap inside
  // the measured window. Only the kernel's memory shows that: a capture that
  // copied or kept those bytes and still returned only its first
  // CAPTURE_MAX_BYTES would pass every other test here.
  //
  // Measured across full collections, so only what is still reachable counts;
  // gc is exposed to this process for that and nothing else. Each reading
  // collects until the heap stops shrinking, and at least twice: after one,
  // Buffers already freed still count in external (measured: 16 MiB of 64 KiB
  // Buffers). Before the run those are the earlier tests' garbage, which made
  // this reading 11 MB low in file order; after it they are the 16 MiB fed
  // past the caps, which made it 7 to 11 MB high. Either way the figure
  // depended on what ran before, not on what the captures hold.
  const gc = exposedGc()
  const used = (): number => {
    const m = process.memoryUsage()
    return m.heapUsed + m.external
  }
  const settled = (): number => {
    gc()
    let last = used()
    for (let i = 0; i < 8; i++) {
      gc()
      const now = used()
      if (now >= last) return now
      last = now
    }
    return last
  }

  const f = fixture(t)
  const feeds: ((chunk: Buffer | string) => void)[] = []
  const stream = (): NonNullable<ChildLike['stdout']> => ({
    on: (_event, cb) => {
      feeds.push(cb)
    },
  })
  const d = driverFor(f, { stdout: stream(), stderr: stream() })
  const before = settled()
  const running = d.driver.run(spec(f))
  assert.equal(feeds.length, 2, 'the driver reads both streams')
  const pipe = 64 * 1024
  for (const feed of feeds) {
    for (let i = 0; i <= CAPTURE_MAX_BYTES; i++) feed(Buffer.from('a'))
    for (let fed = 0; fed < 8 * MiB; fed += pipe) feed(Buffer.alloc(pipe, 'z'))
  }
  // While the run is live, which is when a capture holds what it keeps.
  const held = settled() - before
  // In the test output, so a run on another Node can be set beside the figure
  // below.
  t.diagnostic(`held ${String(held)} bytes`)
  d.child.close(0, null)
  const result = await running.result

  // Two streams at the cap hold 2 MiB and a block each (measured: 2.4 MB,
  // alone or in this file's order, on Node 22). Twice that allows for
  // collector noise, and is a quarter of the 16 MiB fed past the caps and
  // about a fiftieth of what a Buffer per byte costs.
  assert.ok(
    held < 4 * CAPTURE_MAX_BYTES,
    `two streams of ${String(CAPTURE_MAX_BYTES + 1)} one-byte chunks and 8 MiB more held ${String(held)} bytes`,
  )
  assert.ok(result.stdout === 'a'.repeat(CAPTURE_MAX_BYTES), 'stdout is not its first CAPTURE_MAX_BYTES')
  assert.ok(result.stderr === 'a'.repeat(CAPTURE_MAX_BYTES), 'stderr is not its first CAPTURE_MAX_BYTES')
  assert.equal(result.truncated, true)
})

test('the fake and the real driver agree: a run whose output was cut reports truncated, and one whose output was not does not', async (t) => {
  // Runtime code is tested against the fake (sandbox.exec, plan S3). Had the
  // fake dropped the flag, code that passed against it would never have met a cut.
  const f = fixture(t)
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: [{ stdout: 'o'.repeat(CAPTURE_MAX_BYTES), truncated: true }, { stdout: 'ok\n' }] })
  const results: readonly (readonly [string, SandboxResult, SandboxResult])[] = [
    [
      'real',
      await capture(t, (stdout) => stdout.write(Buffer.alloc(CAPTURE_MAX_BYTES + 1, 'o'))),
      await capture(t, (stdout) => stdout.write('ok\n')),
    ],
    ['fake', await fake.run(spec(f)).result, await fake.run(spec(f)).result],
  ]
  for (const [label, cut, whole] of results) {
    assert.equal(cut.truncated, true, label)
    assert.ok(cut.stdout === 'o'.repeat(CAPTURE_MAX_BYTES), `${label}: the cut stdout is not its first CAPTURE_MAX_BYTES`)
    assert.equal(whole.truncated, false, label)
    assert.equal(whole.stdout, 'ok\n', label)
  }
})

test('the fake refuses a scripted result the real driver cannot return, and accepts each one it does', { timeout: 30_000 }, async (t) => {
  // A stream over the cap, which the real driver never returns whole, counted
  // in bytes as the driver counts it: CAPTURE_MAX_BYTES / 2 + 1 é is one
  // character past half the cap, and two bytes past the cap. And one U+FFFD
  // past the cap: each stands for at least one stream byte, a byte that is
  // not UTF-8, so a fake that counted it as none would return any number.
  const over = [
    'o'.repeat(CAPTURE_MAX_BYTES + 1),
    'o'.repeat(2 * CAPTURE_MAX_BYTES),
    'é'.repeat(CAPTURE_MAX_BYTES / 2 + 1),
    '\uFFFD'.repeat(CAPTURE_MAX_BYTES + 1),
  ]
  for (const text of over) {
    for (const scripted of [{ stdout: text }, { stderr: text }, { stdout: text, truncated: true }]) {
      assert.throws(() => fakeSandbox({ imageId: IMAGE_ID, script: [{ stdout: 'ok\n' }, scripted] }), /scripted exit 1: its std(out|err) is \d+ bytes or more/)
    }
  }
  // A cut with no stream near the cap, which the real driver never reports.
  for (const scripted of [{ truncated: true }, { stdout: 'ok\n', stderr: 'e'.repeat(CAPTURE_MAX_BYTES - 4), truncated: true }]) {
    assert.throws(() => fakeSandbox({ imageId: IMAGE_ID, script: [scripted] }), /scripted exit 0: truncated with no stream within three bytes/)
  }

  // What the real driver returns is accepted as a script, the shapes the
  // refusals sit next to among them: a stream at the cap, one cut three short
  // of it before a split character, and one that is not UTF-8, whose U+FFFD
  // each stand for one byte.
  const f = fixture(t)
  const real = [
    await capture(t, (stdout) => stdout.write(Buffer.alloc(CAPTURE_MAX_BYTES, 'o'))),
    await capture(t, (stdout) => stdout.write(Buffer.concat([Buffer.alloc(CAPTURE_MAX_BYTES - 3, 'a'), Buffer.from('\u{1F600}')]))),
    await capture(t, (stdout, stderr) => {
      stdout.write('ok\n')
      stderr.write(Buffer.concat([Buffer.from('x'), Buffer.alloc(CAPTURE_MAX_BYTES + 15, 0x80)]))
    }),
  ]
  assert.deepEqual(
    real.map((r) => r.truncated),
    [false, true, true],
  )
  const fake = fakeSandbox({ imageId: IMAGE_ID, script: real.map(({ stdout, stderr, truncated }) => ({ stdout, stderr, truncated })) })
  for (const scripted of real) {
    const result = await fake.run(spec(f)).result
    assert.ok(result.stdout === scripted.stdout && result.stderr === scripted.stderr, 'the fake did not return the scripted streams')
    assert.equal(result.truncated, scripted.truncated)
  }
})

test("a spawn error's message reaches stderr, through the same capture", async (t) => {
  const f = fixture(t)
  const d = driverFor(f)
  const running = d.driver.run(spec(f))
  // A configured docker binary under a home whose name is not ASCII: the
  // message is a string, not pipe bytes, and must be encoded as UTF-8 to come
  // back as it was.
  d.child.fail(new Error('spawn /Users/josé/bin/docker ENOENT'))
  const result = await running.result
  assert.equal(result.stderr, 'spawn /Users/josé/bin/docker ENOENT')
  assert.equal(result.exitCode, null)
  assert.equal(result.truncated, false)
})

test('a container name without the kernel prefix is refused', (t) => {
  const f = fixture(t)
  // Orphan sweeping can only find what it can name. A container outside the
  // prefix would survive a kernel restart forever.
  assert.throws(() => argsFor(f, { name: 'some-other-container' }), ConfigError)
})

// ── the stub ───────────────────────────────────────────────────────────────

test('apple-container driver reports unavailable from probe and throws from run and kill', async () => {
  const driver = new AppleContainerDriver()
  assert.equal(driver.name, 'apple-container')

  // probe() REPORTS rather than throws, and the distinction this test used to
  // make — that an absent runtime and unwritten code must not look alike — is
  // kept in the reason instead of in the control flow.
  //
  // It threw once, and that broke the driver contract ("Availability, never a
  // throw: a missing runtime is a degraded boot") with a consequence:
  // `sandbox.driver: apple-container`, a value kernel.yaml accepts, refused the
  // whole boot instead of booting degraded. A stub that can stop the kernel
  // starting is worse than the feature being absent.
  const probe = await driver.probe()
  assert.equal(probe.ok, false)
  assert.ok(!probe.ok && probe.why.includes('not implemented'), 'the reason does not say it is unwritten')
  assert.ok(!probe.ok && probe.why.includes('container'), 'the reason does not name the missing binary')
  // It points somewhere useful rather than just refusing.
  assert.ok(!probe.ok && probe.why.includes('docker'), 'the reason does not name the working driver')

  // run and kill still throw: asking an absent runtime to execute something has
  // no degraded answer, and a driver that returned a plausible result here would
  // let a run believe it had been sandboxed.
  assert.throws(
    () => driver.run({} as unknown as SandboxSpec),
    (e: unknown) => e instanceof NotImplementedError && e.feature === 'apple-container',
  )
  // Synchronously, though the signature returns a promise: the stub never gets
  // as far as doing anything asynchronous, and a throw at the call site is
  // louder than a rejection a caller might not be awaiting.
  assert.throws(() => driver.kill('x'), NotImplementedError)
})
