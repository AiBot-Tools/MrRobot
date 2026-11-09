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
//   lands inside a worker (invariant 2), which is exactly what the Phase 2
//   egress proxy exists to prevent and must not be possible before it ships.
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
//   --network value and a container sits on a network probe() never proved
//   internal; take the domain's value without reading it as docker does and
//   `name=host` is the VM's own network stack. Refuse a domain of host as an
//   option the builder never emits, or advise recreating it --internal, and
//   the operator is sent after a smuggled flag or a command docker refuses.
//   Build a hostile run against the trusted domain's config and it goes on a
//   network its own VM never checked.

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { userInfo } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { finished } from 'node:stream/promises'
import { setFlagsFromString } from 'node:v8'
import { runInNewContext } from 'node:vm'

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
import { CAPTURE_MAX_BYTES, type SandboxDriver, type SandboxResult, type SandboxSpec } from '../src/sandbox/driver.js'
import { fakeSandbox } from './helpers/fake-sandbox.js'

const DEFAULTS: DockerDefaults = { user: '65534:65534', pidsLimit: 256, memory: '2g', cpus: 2 }

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
    image: 'aos/worker:0.0.1',
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
    home,
  })
}

/** The value docker would see for `--flag value`. */
function valueOf(args: readonly string[], flag: string): string | undefined {
  const at = args.indexOf(flag)
  return at === -1 ? undefined : args[at + 1]
}

// ── the flag set ───────────────────────────────────────────────────────────

test('run args contain --read-only, --cap-drop=ALL, --security-opt=no-new-privileges, --user, --pids-limit, --memory, --cpus, --network <internal>, --tmpfs, --init, --rm, --name', (t) => {
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
  assert.equal(valueOf(args, '--network'), 'aos-internal')
  assert.equal(valueOf(args, '--tmpfs'), '/tmp:rw,noexec,nosuid,nodev,size=64m')
  assert.ok(args.includes('--init'), '--init')
  assert.ok(args.includes('--rm'), '--rm')
  assert.equal(valueOf(args, '--name'), `${CONTAINER_PREFIX}abc123`)

  // The command runs last, after the image.
  assert.deepEqual(args.slice(-3), ['aos/worker:0.0.1', 'node', '--version'])
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
  assert.doesNotThrow(() => auditRunArgs(args, home, ws, f.domain.network))

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
    assert.throws(() => auditRunArgs(withMount(value), home, ws, f.domain.network), ConfigError, JSON.stringify(value))
  }
  // A workspace that itself holds a double quote or a line break, written into
  // the value as the builder writes it, splits at its commas into exactly the
  // three fields wanted. The builder refuses such a workspace (MOUNT_STRUCTURE);
  // the audit is handed it here directly, and refuses it on its own terms,
  // because docker's CSV reader would not read that value as this split does.
  for (const quoted of ['/w/a"b', '/w/a\nb']) {
    assert.throws(
      () => auditRunArgs(withMount(`type=bind,source=${quoted},target=${WORKSPACE_TARGET}`), home, quoted, f.domain.network),
      /holds a double quote or a control character, so docker would not split it at its commas/,
      JSON.stringify(quoted),
    )
  }
  // And the case a template comparison misses: the workspace carries the tail.
  const tail = `${ws},source=/etc`
  assert.throws(
    () => auditRunArgs(withMount(`type=bind,source=${tail},target=${WORKSPACE_TARGET}`), home, tail, f.domain.network),
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
      () => auditRunArgs(args.filter((a) => a !== dropped), home, f.realWorkspace, f.domain.network),
      new RegExp(`carry ${dropped} 0 time\\(s\\)`),
      dropped,
    )
  }
  assert.throws(() => auditRunArgs(args.slice(0, args.indexOf('aos/worker:0.0.1')), home, f.realWorkspace, f.domain.network), /name no image/)
  // And the argv is a `docker run`: the walk starts after it, and `create`
  // (or any other command) would be judged as though it were run.
  assert.throws(
    () => auditRunArgs(['create', ...args.slice(1)], home, f.realWorkspace, f.domain.network),
    /docker args must start with run \(found "create"\)/,
  )
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
    ['--net', ['aos-internal', 'alpine'], '--net', /^is --network under another name/],
    ['--net=host', ['alpine'], '--net', /^is --network under another name/],
    ['--network=aos-internal', ['alpine'], '"--network=aos-internal"', /^attaches a second network/],
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
    // say, 192.168.5.2 (the Mac) among them, off the internal network.
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
  assert.deepEqual(argsFor(f, { command }).slice(-command.length - 1), ['aos/worker:0.0.1', ...command])
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

  // Exactly one --network: a second as the builder writes its own is counted.
  assert.throws(
    () => argsFor(f, { image: '--network', command: ['aos-other', 'alpine'] }),
    /carry --network 2 time\(s\) before the image/,
  )
  // And the one there is the network the builder was handed, which probe()
  // proved internal: not merely a well-formed name.
  const args = argsFor(f)
  const onNetwork = (value: string): string[] => args.map((a, i) => (args[i - 1] === '--network' ? value : a))
  assert.doesNotThrow(() => auditRunArgs(args, home, f.realWorkspace, 'aos-internal'))
  for (const value of ['aos-hostile', 'aos-internal2', 'AOS-INTERNAL', 'none']) {
    assert.throws(
      () => auditRunArgs(onNetwork(value), home, f.realWorkspace, 'aos-internal'),
      (e: unknown) =>
        e instanceof ConfigError &&
        e.message === `docker args put the container on network ${JSON.stringify(value)}; invariant 9 needs the domain's internal network "aos-internal"`,
      JSON.stringify(value),
    )
  }
  assert.throws(
    () => auditRunArgs(args, home, f.realWorkspace, 'aos-hostile'),
    /put the container on network "aos-internal"; invariant 9 needs the domain's internal network "aos-hostile"/,
  )
  // No value at all is no plain network name, and is refused as one.
  assert.throws(() => auditRunArgs(onNetwork(''), home, f.realWorkspace, 'aos-internal'), named('--network ""', NOT_PLAIN))
  // A domain that names a network docker gives a meaning of its own is
  // refused although the value matches what the builder was handed: the
  // modes, and anything but a plain name, which docker may read as its
  // key=value syntax (name=host is host, its fields lower-cased). The refusal
  // names the domain's network: the --network carrying it is the builder's
  // own, which the walk's refusal would call one the builder never emits.
  const domainNamed =
    (network: string) =>
    (e: unknown): boolean =>
      e instanceof ConfigError &&
      e.message.startsWith(`the domain network ${JSON.stringify(network)} is not one a domain may name: as --network it `) &&
      e.message.endsWith("; invariant 9 needs the domain's own internal network") &&
      !e.message.includes('never emits')
  assert.throws(
    () => auditRunArgs(onNetwork('host'), home, f.realWorkspace, 'host'),
    (e: unknown) =>
      domainNamed('host')(e) &&
      (e as Error).message.includes("it puts the container on the VM's own network stack, which reaches the Mac at 192.168.5.2;"),
  )
  // A plain HOST is a network of that name to docker, not host mode, and the
  // refusal says why it is refused anyway rather than calling it host mode.
  assert.throws(
    () => auditRunArgs(onNetwork('HOST'), home, f.realWorkspace, 'HOST'),
    (e: unknown) =>
      domainNamed('HOST')(e) &&
      (e as Error).message.includes("it spells host in another case, which docker reads as a network of that name, but docker's key=value spelling lower-cases (name=HOST is host)") &&
      !(e as Error).message.includes('own network stack'),
  )
  // Refused before every other check reads the argv, so a domain network
  // that would read there as a forbidden flag, the docker socket, a -v or a
  // second --mount is still refused as the domain's, the config to change.
  for (const network of [
    'host',
    'HOST',
    'bridge',
    'Bridge',
    'default',
    'DEFAULT',
    'container:abc',
    'name=host',
    'NAME=HOST',
    'name=bridge',
    'name=aos-internal,alias=x',
    'name=aos-internal,driver-opt=com.docker.network.x=y',
    'aos internal',
    'aos-internal,',
    '-aos-internal',
    '',
    '--privileged',
    '/var/run/docker.sock',
    '-v',
    '--mount',
  ]) {
    assert.throws(
      () => buildRunArgs({ spec: spec(f), domain: { ...f.domain, network }, defaults: DEFAULTS, repoRoot: f.repoRoot, home }),
      domainNamed(network),
      network,
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
    buildRunArgs({ spec: spec(f), domain: f.domain, defaults: { ...DEFAULTS, ...defaults }, repoRoot: f.repoRoot, home })

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
  assert.doesNotThrow(() => auditRunArgs(swapped('--user', '1000:1000'), home, f.realWorkspace, f.domain.network))
  assert.throws(() => auditRunArgs(swapped('--user', '0:0'), home, f.realWorkspace, f.domain.network), /--user "0:0"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--memory', '0'), home, f.realWorkspace, f.domain.network), /--memory "0"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--pids-limit', '-1'), home, f.realWorkspace, f.domain.network), /--pids-limit "-1"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--cpus', '0.0'), home, f.realWorkspace, f.domain.network), /--cpus "0.0"; invariant 9/)
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
  /** As Node's child emits 'error', for a spawn that started no process. */
  fail(error: Error): void
}

type ChildStreams = Pick<ChildLike, 'stdout' | 'stderr'>

const SILENT: ChildStreams = { stdout: { on: () => undefined }, stderr: { on: () => undefined } }

function fakeChild(streams: ChildStreams = SILENT): FakeChild {
  const handlers: Record<string, ((...a: never[]) => void)[]> = {}
  const on = (event: string, cb: (...a: never[]) => void): FakeChild => {
    ;(handlers[event] ??= []).push(cb)
    return child
  }
  const child: FakeChild = {
    stdout: streams.stdout,
    stderr: streams.stderr,
    on: on as ChildLike['on'],
    close(code, signal) {
      for (const cb of handlers['close'] ?? []) (cb as (c: number | null, s: string | null) => void)(code, signal)
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

const TRUSTED_HOST = 'unix:///tmp/colima-trusted.sock'
const HOSTILE_HOST = 'unix:///tmp/colima-hostile.sock'

function driverFor(f: Fixture, streams?: ChildStreams): Spied {
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

test('each run is built against its own domain: a hostile run goes on --network aos-hostile once, from the hostile mountRoot', (t) => {
  // probe() proves each domain's network internal on that domain's VM. A run
  // built against the other domain's config goes on a network its own VM
  // never had checked, and the audit cannot see it: it compares the network
  // with whatever domain the builder was handed.
  const f = fixture(t)
  const d = driverFor(f)
  d.driver.run(spec(f, { domain: 'hostile', name: `${CONTAINER_PREFIX}h1` }))
  d.driver.run(spec(f, { domain: 'trusted', name: `${CONTAINER_PREFIX}t1` }))
  const networks = (args: readonly string[] = []): string[] =>
    args.flatMap((a, i) => (a === '--network' ? [args[i + 1] ?? ''] : a.startsWith('--net') ? [a] : []))

  const [hostile, trusted] = d.spawns.map((s) => s.args)
  assert.deepEqual(networks(hostile), ['aos-hostile'])
  assert.equal(valueOf(hostile ?? [], '--mount'), `type=bind,source=${f.realHostileWorkspace},target=${WORKSPACE_TARGET}`)
  assert.deepEqual(networks(trusted), ['aos-internal'])
  assert.equal(valueOf(trusted ?? [], '--mount'), `type=bind,source=${f.realWorkspace},target=${WORKSPACE_TARGET}`)

  // And a hostile run is confined to the hostile mountRoot: the trusted
  // domain's workspace is outside it.
  assert.throws(
    () => d.driver.run(spec(f, { domain: 'hostile', name: `${CONTAINER_PREFIX}h2`, workspace: f.workspace })),
    /outside the domain mountRoot/,
  )
  assert.equal(d.spawns.length, 2)
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

  d.setExec((args) => Promise.resolve({ stdout: args[0] === 'network' ? 'true\n' : '27.3.1\n', stderr: '' }))
  const up = await d.driver.probe()
  assert.deepEqual(up, { ok: true, version: '27.3.1' })

  // A daemon that answers with nothing is not a working daemon.
  d.setExec(() => Promise.resolve({ stdout: '  \n', stderr: '' }))
  assert.equal((await d.driver.probe()).ok, false)
})

test('probe refuses a domain whose network is not internal, and checks each domain on its own VM', async (t) => {
  // In a Colima VM the Mac's loopback is 192.168.5.2, where pmmcp listens
  // unauthenticated. A network with a route out is a path to its vault tools.
  const f = fixture(t)
  const d = driverFor(f)
  const internalOn = new Set(['unix:///tmp/colima-trusted.sock'])
  const seen: string[] = []
  d.setExec((args) => {
    if (args[0] !== 'network') return Promise.resolve({ stdout: '27.3.1\n', stderr: '' })
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
  d.setExec((args) =>
    args[0] === 'network'
      ? Promise.reject(new Error('Error response from daemon: network aos-internal not found'))
      : Promise.resolve({ stdout: '27.3.1\n', stderr: '' }),
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
  // reason says so rather than calling it host mode.
  const f = fixture(t)
  for (const network of ['host', 'HOST', 'bridge', 'default', 'container:abc', 'name=host']) {
    const d = driverFor({ ...f, hostile: { ...f.hostile, network } })
    const inspected: string[] = []
    d.setExec((args) => {
      if (args[0] !== 'network') return Promise.resolve({ stdout: '27.3.1\n', stderr: '' })
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
    assert.ok(why.endsWith("Name the domain's own internal network in kernel.yaml (docker network create --internal aos-hostile)"), why)
    assert.equal(why.includes('docker network rm'), false, why)
    // The trusted domain's network was inspected, and the hostile one never.
    assert.deepEqual(inspected, ['aos-internal'], network)
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
    if (args[0] !== 'ps') return Promise.resolve({ stdout: '', stderr: '' })
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
  const listed = d.execs.filter((e) => e.args[0] === 'ps')
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
    args[0] === 'ps'
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
      if (args[0] === 'ps') return host === hung ? hang : Promise.resolve({ stdout: listed[host] ?? '', stderr: '' })
      // The first orphan's kill never returns either.
      return args[2] === `${CONTAINER_PREFIX}${first}` ? hang : Promise.resolve({ stdout: '', stderr: '' })
    })
    void d.driver.sweepOrphans()
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(
      d.execs.filter((e) => e.args[0] === 'ps').map((e) => e.env['DOCKER_HOST']).sort(),
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
      if (args[0] !== 'ps') return Promise.resolve({ stdout: '', stderr: '' })
      if (host === down) {
        return Promise.reject(new Error(`Cannot connect to the Docker daemon at ${host}. Is the docker daemon running?`))
      }
      return Promise.resolve({ stdout: names.map((n) => `${CONTAINER_PREFIX}${n}\n`).join(''), stderr: '' })
    })
    const killed = await d.driver.sweepOrphans()
    assert.deepEqual(killed, names.map((n) => `${CONTAINER_PREFIX}${n}`), `${down} down`)
    assert.deepEqual(killsSent(d), names.map((n) => `${up} ${CONTAINER_PREFIX}${n}`), `${down} down`)
    assert.deepEqual(
      d.execs.filter((e) => e.args[0] === 'ps').map((e) => e.env['DOCKER_HOST']).sort(),
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
    args[0] === 'ps'
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
  const fake = fakeSandbox({ script: [{ hangs: true }, { exitCode: 0 }] })
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
  const quick = fakeSandbox({ script: [{ exitCode: 0 }, { exitCode: 0 }] })
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
  const bare = fakeSandbox({ script: [{ hangs: true }] })
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
  const fake = fakeSandbox({ script: [{ hangs: true }] })
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
    const fake = fakeSandbox({ script: [{ hangs: true, ignoresKill: true, exitCode: 3 }] })
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
  const fake = fakeSandbox({ script: [{ hangs: true }] })
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
  assert.throws(() => fakeSandbox({ script: [{ ignoresKill: true }] }), /scripted exit 0: ignoresKill on a run that does not hang/)
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
  const fake = fakeSandbox({ script: [{ exitCode: 137 }] })
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
    () => fakeSandbox({ script: [{ hangs: true }, { hangs: true, ignoresKill: true, exitCode: 137 }] }),
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
    const fake = fakeSandbox({ script: [{ hangs: true, ...wrote }] })
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
  const cut = fakeSandbox({ script: [{ hangs: true, stdout: 'o'.repeat(CAPTURE_MAX_BYTES), truncated: true }] })
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
  const fake = fakeSandbox({ script: [{ hangs: true }] })
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
  const fake = fakeSandbox({ script: [{ hangs: true }, { hangs: true }] })
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
  const fake = fakeSandbox({ script: [{ hangs: true }, { hangs: true }] })
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
  const fake = fakeSandbox({ script: [{ stdout: 'o'.repeat(CAPTURE_MAX_BYTES), truncated: true }, { stdout: 'ok\n' }] })
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
      assert.throws(() => fakeSandbox({ script: [{ stdout: 'ok\n' }, scripted] }), /scripted exit 1: its std(out|err) is \d+ bytes or more/)
    }
  }
  // A cut with no stream near the cap, which the real driver never reports.
  for (const scripted of [{ truncated: true }, { stdout: 'ok\n', stderr: 'e'.repeat(CAPTURE_MAX_BYTES - 4), truncated: true }]) {
    assert.throws(() => fakeSandbox({ script: [scripted] }), /scripted exit 0: truncated with no stream within three bytes/)
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
  const fake = fakeSandbox({ script: real.map(({ stdout, stderr, truncated }) => ({ stdout, stderr, truncated })) })
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
