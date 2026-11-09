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
//   the other and a daemon that never answers stops the other's kill.
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
}

/**
 * A real directory tree with real symlinks. Confinement is a filesystem
 * question, and a mocked filesystem would only prove the mock agrees with us.
 */
function fixture(t: TestContext): Fixture {
  const root = tmpdir(t)
  const mountRoot = join(root, 'work')
  const repoRoot = join(root, 'repo')

  mkdirSync(join(mountRoot, 'proj'), { recursive: true })
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
    workspace: f.workspace,
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
  assert.doesNotThrow(() => auditRunArgs(args, home, ws))

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
    `type=bind,"source=${ws},x",target=${WORKSPACE_TARGET}`, // a quoted field may hold a comma
    `type=bind,source=${ws},target=${WORKSPACE_TARGET}\nsource=/etc`, // a line break ends the record
    '',
  ]
  for (const value of bad) {
    assert.throws(() => auditRunArgs(withMount(value), home, ws), ConfigError, JSON.stringify(value))
  }
  // And the case a template comparison misses: the workspace carries the tail.
  const tail = `${ws},source=/etc`
  assert.throws(
    () => auditRunArgs(withMount(`type=bind,source=${tail},target=${WORKSPACE_TARGET}`), home, tail),
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
      () => auditRunArgs(args.filter((a) => a !== dropped), home, f.realWorkspace),
      new RegExp(`carry ${dropped} 0 time\\(s\\)`),
      dropped,
    )
  }
  assert.throws(() => auditRunArgs(args.slice(0, args.indexOf('aos/worker:0.0.1')), home, f.realWorkspace), /name no image/)
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
  assert.doesNotThrow(() => auditRunArgs(swapped('--user', '1000:1000'), home, f.realWorkspace))
  assert.throws(() => auditRunArgs(swapped('--user', '0:0'), home, f.realWorkspace), /--user "0:0"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--memory', '0'), home, f.realWorkspace), /--memory "0"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--pids-limit', '-1'), home, f.realWorkspace), /--pids-limit "-1"; invariant 9/)
  assert.throws(() => auditRunArgs(swapped('--cpus', '0.0'), home, f.realWorkspace), /--cpus "0.0"; invariant 9/)
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
    domains: { trusted: f.domain, hostile: { ...f.domain, dockerHost: HOSTILE_HOST } },
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

  d.child.close(null, 'SIGKILL')
  const result = await running.result
  assert.equal(result.killedBy, 'wallclock')
  assert.equal(result.signal, 'SIGKILL')
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
  assert.match(refused.ok ? '' : refused.why, /^hostile: network aos-internal is not internal \(Internal=false\)/)
  assert.match(refused.ok ? '' : refused.why, /docker network create --internal aos-internal/)
  // Each domain was asked through its OWN socket.
  assert.deepEqual(seen, [
    'unix:///tmp/colima-trusted.sock network inspect --format {{.Internal}} aos-internal',
    'unix:///tmp/colima-hostile.sock network inspect --format {{.Internal}} aos-internal',
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

test('the fake and the real driver agree: a name still running is refused, and a requested kill reports killedBy requested with SIGKILL', async (t) => {
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

    await driver.kill(name)
    exitAfterKill()
    const result = await running.result
    assert.equal(result.killedBy, 'requested', label)
    assert.equal(result.signal, 'SIGKILL', label)

    // Free again once that run has ended.
    assert.doesNotThrow(() => driver.run(spec(f, { name })), label)
  }
  // The refused call is recorded, as every call is, and spent no scripted exit:
  // the third call ran on the fake's second entry rather than finding none.
  assert.equal(fake.specs.length, 3)
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
 * process's own gc when it was started with --expose-gc, and otherwise one
 * exposed at runtime through V8's flag, which Node 20 and 22 honour. Should a
 * later V8 stop honouring it, this says so and fails, rather than skipping:
 * a skip passes npm test, and this is the only check of the memory bound.
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
  // character past half the cap, and two bytes past the cap.
  const over = ['o'.repeat(CAPTURE_MAX_BYTES + 1), 'o'.repeat(2 * CAPTURE_MAX_BYTES), 'é'.repeat(CAPTURE_MAX_BYTES / 2 + 1)]
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
