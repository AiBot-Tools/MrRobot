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

import './helpers/guard.js'

import { test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { tmpdir } from './helpers/tmpdir.js'
import { ConfigError, NotImplementedError } from '../src/errors.js'
import { confineWorkspace } from '../src/sandbox/confine.js'
import {
  buildRunArgs,
  CONTAINER_PREFIX,
  DockerDriver,
  WORKSPACE_TARGET,
  type ChildLike,
  type DockerDefaults,
  type DomainConfig,
} from '../src/sandbox/docker.js'
import { AppleContainerDriver } from '../src/sandbox/apple-container.js'
import type { SandboxSpec } from '../src/sandbox/driver.js'

const DEFAULTS: DockerDefaults = { user: '65534:65534', pidsLimit: 256, memory: '2g', cpus: 2 }

interface Fixture {
  readonly root: string
  readonly mountRoot: string
  readonly workspace: string
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

test('run args contain exactly one --mount and no -v, and it is the confined workspace', (t) => {
  const f = fixture(t)
  const args = argsFor(f)

  assert.equal(args.filter((a) => a === '--mount').length, 1)
  assert.equal(args.filter((a) => a === '-v' || a === '--volume').length, 0)
  assert.equal(valueOf(args, '--mount'), `type=bind,source=${f.workspace},target=${WORKSPACE_TARGET}`)

  // A spec field cannot smuggle a second bind past the audit.
  assert.throws(
    () => argsFor(f, { command: ['--mount', 'type=bind,source=/etc,target=/etc'] }),
    ConfigError,
  )
  assert.throws(() => argsFor(f, { command: ['-v', '/etc:/etc'] }), ConfigError)
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
  assert.equal(ok(join(f.mountRoot, 'proj', '..', 'proj')), f.workspace)
  assert.equal(ok(f.workspace), f.workspace)

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
    join(f.repoRoot, 'scratch'),
  )
})

test('resolved real path, not the request string, is passed to docker', (t) => {
  const f = fixture(t)
  // A link that resolves back inside the allowed tree. Confinement lets it
  // through — and must hand docker what it resolved to, or the check
  // validated one directory and the container gets another.
  symlinkSync(join(f.mountRoot, 'proj'), join(f.mountRoot, 'alias'))

  const args = argsFor(f, { workspace: join(f.mountRoot, 'alias') })
  assert.equal(valueOf(args, '--mount'), `type=bind,source=${f.workspace},target=${WORKSPACE_TARGET}`)
  assert.equal(args.some((a) => a.includes('alias')), false, 'the request string reached docker')
})

// ── the driver ─────────────────────────────────────────────────────────────

interface FakeChild extends ChildLike {
  close(code: number | null, signal: string | null): void
}

function fakeChild(): FakeChild {
  const handlers: Record<string, ((...a: never[]) => void)[]> = {}
  const on = (event: string, cb: (...a: never[]) => void): FakeChild => {
    ;(handlers[event] ??= []).push(cb)
    return child
  }
  const child: FakeChild = {
    stdout: { on: () => undefined },
    stderr: { on: () => undefined },
    on: on as ChildLike['on'],
    close(code, signal) {
      for (const cb of handlers['close'] ?? []) (cb as (c: number | null, s: string | null) => void)(code, signal)
    },
  }
  return child
}

interface Spied {
  readonly driver: DockerDriver
  readonly spawns: { args: readonly string[]; env: Record<string, string> }[]
  readonly execs: { args: readonly string[]; env: Record<string, string> }[]
  readonly child: FakeChild
  setExec(fn: (args: readonly string[]) => Promise<{ stdout: string; stderr: string }>): void
}

function driverFor(f: Fixture): Spied {
  const spawns: Spied['spawns'] = []
  const execs: Spied['execs'] = []
  const child = fakeChild()
  let exec: (args: readonly string[]) => Promise<{ stdout: string; stderr: string }> = () =>
    Promise.resolve({ stdout: '', stderr: '' })

  const driver = new DockerDriver({
    spawn: (_cmd, args, options) => {
      spawns.push({ args, env: options.env })
      return child
    },
    execFile: (_cmd, args, options) => {
      execs.push({ args, env: options.env })
      return exec(args)
    },
    domains: { trusted: f.domain, hostile: { ...f.domain, dockerHost: 'unix:///tmp/colima-hostile.sock' } },
    defaults: DEFAULTS,
    repoRoot: f.repoRoot,
    path: '/usr/bin:/bin',
    home: join(f.root, 'home'),
  })

  return {
    driver,
    spawns,
    execs,
    child,
    setExec(fn) {
      exec = fn
    },
  }
}

test('spawn env keys are exactly [DOCKER_HOST, PATH] with a poisoned ANTHROPIC_API_KEY in process.env', (t) => {
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
  assert.deepEqual(Object.keys(env).sort(), ['DOCKER_HOST', 'PATH'])
  assert.equal(env['DOCKER_HOST'], 'unix:///tmp/colima-trusted.sock')
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

  d.setExec(() => Promise.resolve({ stdout: '27.3.1\n', stderr: '' }))
  const up = await d.driver.probe()
  assert.deepEqual(up, { ok: true, version: '27.3.1' })

  // A daemon that answers with nothing is not a working daemon.
  d.setExec(() => Promise.resolve({ stdout: '  \n', stderr: '' }))
  assert.equal((await d.driver.probe()).ok, false)
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

test('a container name without the kernel prefix is refused', (t) => {
  const f = fixture(t)
  // Orphan sweeping can only find what it can name. A container outside the
  // prefix would survive a kernel restart forever.
  assert.throws(() => argsFor(f, { name: 'some-other-container' }), ConfigError)
})

// ── the stub ───────────────────────────────────────────────────────────────

test('apple-container driver throws NotImplemented on every method', () => {
  const driver = new AppleContainerDriver()
  assert.equal(driver.name, 'apple-container')

  // probe() throws rather than reporting unavailable: an absent runtime and
  // unwritten code must not look alike in a degraded-subsystem view.
  assert.throws(() => driver.probe(), NotImplementedError)
  assert.throws(
    () => driver.run({} as unknown as SandboxSpec),
    (e: unknown) => e instanceof NotImplementedError && e.feature === 'apple-container',
  )
  assert.throws(() => driver.kill('x'), NotImplementedError)
})
