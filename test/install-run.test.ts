// The installer's process runner (scripts/install/run.ts).
//
// Every program the installer runs goes through it, the stop and start
// scripts included, so these tests are about what a child can never get: the
// installer's environment, a secret in its argv, env or stdin, a merged or
// piped capture, a timeout or a signal on the stop and start scripts, and an
// unscrubbed line on the operator's screen. Every repository and HOME here is
// a mkdtemp directory. Most children are fakes that record what spawn was
// handed; the few real ones are /bin/sh scripts, /usr/bin/env and /bin/cat in
// those directories, never pmmcp, docker, launchctl, lsof or ps.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { PassThrough } from 'node:stream'
import test, { type TestContext } from 'node:test'

import { SecretMask } from '../src/events/redact.js'
import {
  GIT_ONLY_NAMES,
  InstallRunError,
  KILL_GRACE_MS,
  MAX_MACHINE_OUTPUT,
  PASSED_NAMES,
  Runner,
  SCAN_CHUNK,
  START_SCRIPT,
  STOP_SCRIPT,
  activePath,
  childEnv,
  childPath,
  clearActive,
  installDir,
  readActive,
  readAt,
  readJobs,
  readOut,
  spawnWith,
  tail,
  type ChildOptions,
  type ReadFn,
  type SpawnFn,
} from '../scripts/install/run.js'
import { CREDENTIAL_NAME } from './helpers/guard.js'
import { tmpdir } from './helpers/tmpdir.js'

const NOW = new Date('2026-10-29T05:45:06.123Z')
const STAMP = '20261029T054506Z'

/** A repository the runner may log under: .gitignore ignores /.aos/. */
function repo(t: TestContext): string {
  const root = tmpdir(t)
  writeFileSync(join(root, '.gitignore'), '/.aos/\n.env\n')
  return root
}

/** The installer's environment as a shell on the Mac would hand it over, every name a child must never get included. */
function installerEnv(home: string): Record<string, string> {
  return {
    HOME: home,
    USER: 'op',
    LOGNAME: 'op',
    TMPDIR: '/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/',
    LANG: 'en_US.UTF-8',
    LC_ALL: 'en_US.UTF-8',
    TERM: 'xterm-256color',
    SHELL: '/bin/zsh',
    PATH: '/Users/op/evil/bin:/usr/bin',
    SSH_AUTH_SOCK: '/private/tmp/com.apple.launchd.x/Listeners',
    DOCKER_CONFIG: '/Users/op/MrRobot/.aos/docker',
    DOCKER_HOST: 'unix:///Users/op/.colima/hostile/docker.sock',
    DOCKER_CONTEXT: 'colima-hostile',
    PMMCP_CONFIG_PATH: '/Users/op/elsewhere.yaml',
    PMMCP_TOKEN: 'pmmcp-bearer',
    PMMCP_SECRET_PASSPHRASE: 'pass',
    AOS_CONTROL_TOKEN: 'control',
    AOS_PMMCP_TOKEN: 'bearer',
    AOS_LIVE_TESTS: '1',
    ANTHROPIC_API_KEY: 'k',
    OPENAI_API_KEY: 'k',
    OPENROUTER_API_KEY: 'k',
    MOONSHOT_API_KEY: 'k',
    NODE_OPTIONS: '--require=/tmp/x.js',
    PYTHONPATH: '/Users/op/py',
    VIRTUAL_ENV: '/Users/op/venv',
    DYLD_INSERT_LIBRARIES: '/tmp/x.dylib',
    LD_PRELOAD: '/tmp/x.so',
    HTTPS_PROXY: 'http://127.0.0.1:9',
    GIT_DIR: '/tmp/elsewhere',
  }
}

/** A child that does only what the test makes it do. */
class FakeChild extends EventEmitter {
  readonly pid: number | undefined
  readonly stdin: PassThrough | null
  readonly signals: NodeJS.Signals[] = []

  constructor(pid: number | undefined, piped: boolean) {
    super()
    this.pid = pid
    this.stdin = piped ? new PassThrough() : null
  }

  kill(signal: NodeJS.Signals): boolean {
    this.signals.push(signal)
    return true
  }
}

interface Call {
  readonly command: string
  readonly args: readonly string[]
  readonly options: ChildOptions
  readonly child: FakeChild
}

/** A spawn that records each call; `behave` writes the child's output through the descriptors it was handed. */
function recorder(behave: (call: Call) => void = () => undefined, pid: number | undefined = 4242): { spawn: SpawnFn; calls: Call[] } {
  const calls: Call[] = []
  const spawn: SpawnFn = (command, args, options) => {
    const call = { command, args, options, child: new FakeChild(pid, options.stdio[0] === 'pipe') }
    calls.push(call)
    behave(call)
    return call.child
  }
  return { spawn, calls }
}

const write = (fd: number, text: string): void => {
  writeSync(fd, text)
}

/** Whether a promise has settled by the next turn of the event loop. */
async function settled(p: Promise<unknown>): Promise<boolean> {
  return Promise.race([
    p.then(
      () => true,
      () => true,
    ),
    new Promise<boolean>((resolve) => setImmediate(() => resolve(false))),
  ])
}

const mode = (path: string): number => statSync(path).mode & 0o777

/** A pmmcp checkout's folder, with real scripts in it when a test runs them. */
function checkout(t: TestContext, scripts: Readonly<Record<string, string>> = {}): string {
  const dir = join(tmpdir(t), 'Persistent-Memory-MCP')
  mkdirSync(dir)
  for (const [name, body] of Object.entries(scripts)) {
    writeFileSync(join(dir, name), body)
    chmodSync(join(dir, name), 0o755)
  }
  return dir
}

const refusedCode = (e: unknown): boolean => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_REFUSED'
const busyCode = (e: unknown): boolean => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_BUSY'
const haltedCode = (e: unknown): boolean => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_HALTED'
const outputCode = (e: unknown): boolean => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_OUTPUT'

/**
 * Printed by a real child: whether it leads a process group of its own, which
 * only a detached spawn gives it (and with it a session of its own), so a
 * Ctrl-C or a hangup at the installer's terminal cannot reach it.
 */
const GROUP_CHECK = "kill -0 -$$ 2>/dev/null && echo 'own group' || echo 'not own group'"

test('a child env holds only the allowlisted names', async (t) => {
  const home = tmpdir(t)
  const parent = installerEnv(home)
  // Docker Desktop's per-user CLI and the older uv installer's directory come last: they only supply what nothing before them has.
  const PATH = `${home}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${home}/.docker/bin:${home}/.cargo/bin`
  assert.equal(childPath(home), PATH)

  // The allowlist itself never names what a child must not get, whatever it comes to hold.
  for (const name of [...PASSED_NAMES, ...GIT_ONLY_NAMES, 'PATH']) {
    assert.equal(CREDENTIAL_NAME.test(name), false, `${name} is a credential name`)
    assert.doesNotMatch(name, /^(?:DOCKER|PMMCP|AOS)_/)
  }

  const expected = {
    HOME: home,
    USER: 'op',
    LOGNAME: 'op',
    TMPDIR: parent.TMPDIR,
    LANG: 'en_US.UTF-8',
    LC_ALL: 'en_US.UTF-8',
    TERM: 'xterm-256color',
    SHELL: '/bin/zsh',
    PATH,
  }
  assert.deepEqual(childEnv(parent, 'docker'), expected)
  assert.deepEqual(childEnv(parent, '/Users/op/Github/Persistent-Memory-MCP/.venv/bin/python'), expected)
  assert.deepEqual(childEnv(parent, '/Users/op/Github/Persistent-Memory-MCP/stop-pmmcp-server.sh'), expected)
  // The SSH agent is git's alone, by whatever path git is run.
  for (const git of ['git', '/usr/bin/git', '/opt/homebrew/bin/git']) {
    assert.deepEqual(childEnv(parent, git), { ...expected, SSH_AUTH_SOCK: parent.SSH_AUTH_SOCK })
  }
  // A name set but empty is not passed, and one unset is not invented.
  const { LC_ALL: _lcAll, USER: _user, ...withoutBoth } = expected
  assert.deepEqual(childEnv({ ...parent, LC_ALL: '', USER: undefined }, 'docker'), withoutBoth)
  // No PATH can be built without an absolute HOME, so nothing runs.
  for (const HOME of [undefined, '', 'relative/home', '/Users/o:p']) {
    assert.throws(() => childEnv({ ...parent, HOME }, 'docker'), refusedCode)
  }

  // What spawn is handed is exactly that, and the installer's own PATH is not consulted.
  const root = repo(t)
  const fake = recorder((c) => setImmediate(() => c.child.emit('exit', 0, null)))
  const runner = new Runner({ repoRoot: root, env: parent, spawn: fake.spawn, now: () => NOW })
  await runner.run({ step: 'docker-context', command: 'docker', args: ['context', 'show'], cwd: root })
  await runner.run({ step: 'git-head', command: '/usr/bin/git', args: ['rev-parse', 'HEAD'], cwd: root })
  assert.deepEqual(fake.calls[0]?.options.env, expected)
  assert.deepEqual(fake.calls[1]?.options.env, { ...expected, SSH_AUTH_SOCK: parent.SSH_AUTH_SOCK })

  // And a real child sees nothing else: /usr/bin/env prints the environment it was given.
  const real = new Runner({ repoRoot: root, env: parent, now: () => NOW })
  const printed = await real.run({ step: 'env', command: '/usr/bin/env', args: [], cwd: root })
  assert.equal(printed.code, 0)
  const names = readOut(printed)
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => l.slice(0, l.indexOf('=')))
  assert.deepEqual(names.sort(), Object.keys(expected).sort())
  assert.match(readOut(printed), new RegExp(`^PATH=${PATH.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`, 'm'))
})

test('a registered secret in argv, env or stdin is refused before anything is spawned', async (t) => {
  const TOKEN = randomBytes(32).toString('hex')
  const OTHER = randomBytes(32).toString('hex')
  SecretMask.register(TOKEN)
  t.after(() => SecretMask.clear())
  const digestOf = (v: string): string => `sha256:${createHash('sha256').update(v, 'utf8').digest('hex')}`
  const registeredDigest = digestOf('a value whose digest was registered')
  SecretMask.register(registeredDigest)

  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const python = join(pmmcp, '.venv', 'bin', 'python')
  const rotate = { step: 'rotate', command: python, args: ['scripts/rotate_http_auth_token.py', 'aos-kernel', '--create', '--digest-stdin'], cwd: pmmcp }

  const cases: { readonly why: string; readonly env?: Record<string, string | undefined>; readonly spec: Parameters<Runner['start']>[0] }[] = [
    { why: 'an argument that is the token', spec: { ...rotate, args: [...rotate.args, TOKEN] } },
    { why: 'an argument that holds it', spec: { ...rotate, args: ['--token=' + TOKEN] } },
    { why: 'a credential shape in an argument', spec: { ...rotate, args: ['sk-ant-api03-abcdefghijklmnopqrstuvwx'] } },
    { why: 'the command', spec: { ...rotate, command: `/opt/${TOKEN}/bin/python` } },
    { why: 'the working directory', spec: { ...rotate, cwd: `/tmp/${TOKEN}` } },
    { why: 'an allowlisted environment value', env: { LANG: TOKEN }, spec: rotate },
    { why: 'an allowlisted environment value that holds it', env: { TERM: `xterm-${TOKEN}` }, spec: rotate },
    { why: 'HOME, which PATH is built from', env: { HOME: join(home, TOKEN) }, spec: rotate },
    { why: 'stdin that is the token', spec: { ...rotate, digest: TOKEN } },
    { why: 'stdin that is a registered value in a digest\'s form', spec: { ...rotate, digest: registeredDigest } },
    { why: 'stdin that is not a digest', spec: { ...rotate, digest: 'aos-kernel' } },
    { why: 'stdin in upper case', spec: { ...rotate, digest: digestOf(OTHER).toUpperCase().replace('SHA256', 'sha256') } },
    { why: 'stdin with its own newline', spec: { ...rotate, digest: `${digestOf(OTHER)}\n` } },
    { why: 'stdin with a second line', spec: { ...rotate, digest: `${digestOf(OTHER)}\n${digestOf(OTHER)}` } },
    { why: 'a relative working directory', spec: { ...rotate, cwd: 'Persistent-Memory-MCP' } },
    { why: 'a relative command', spec: { ...rotate, command: '.venv/bin/python' } },
  ]
  for (const c of cases) {
    const root = repo(t)
    const fake = recorder()
    const runner = new Runner({ repoRoot: root, env: { ...installerEnv(home), ...c.env }, spawn: fake.spawn, now: () => NOW })
    assert.throws(
      () => runner.start(c.spec),
      (e: unknown) => {
        assert.ok(refusedCode(e), `${c.why}: ${String(e)}`)
        assert.ok(e instanceof Error && !e.message.includes(TOKEN), `${c.why}: the refusal quotes the token`)
        return true
      },
      c.why,
    )
    assert.equal(fake.calls.length, 0, `${c.why}: something was spawned`)
    assert.equal(existsSync(join(root, '.aos')), false, `${c.why}: something was created`)
  }

  // A value the child never gets is not its business: an unlisted name holding the token is dropped, not refused.
  const root = repo(t)
  const fake = recorder((c) => setImmediate(() => c.child.emit('exit', 0, null)))
  const runner = new Runner({ repoRoot: root, env: { ...installerEnv(home), AOS_PMMCP_TOKEN: TOKEN, ANYTHING: TOKEN }, spawn: fake.spawn, now: () => NOW })
  const digest = digestOf(OTHER)
  const run = runner.start({ ...rotate, digest })
  // The one stdin there is: the digest, one line, through a pipe.
  assert.equal(fake.calls[0]?.options.stdio[0], 'pipe')
  assert.equal(String(fake.calls[0]?.child.stdin?.read()), `${digest}\n`)
  assert.equal(Object.values(fake.calls[0]?.options.env ?? {}).some((v) => v.includes(TOKEN)), false)
  const result = await run.done
  assert.equal(result.code, 0)
  assert.equal(result.stdinError, undefined)
})

test('stop and start run detached, stdin /dev/null, stdout and stderr to separate 0600 files, with no timeout and no signal', async (t) => {
  const root = repo(t)
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const STOP = join(pmmcp, 'stop-pmmcp-server.sh')
  const START = join(pmmcp, 'start-pmmcp-server.sh')
  const fake = recorder((c) => {
    write(c.options.stdio[1], `${basename(c.command)}: stopping services\n`)
    write(c.options.stdio[2], `${basename(c.command)}: [WARN] something\n`)
  })
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] })

  const stop = runner.start({ step: 'stop', command: STOP, args: [], cwd: pmmcp })
  const call = fake.calls[0]
  assert.ok(call)
  assert.equal(call.command, STOP)
  assert.equal(call.options.detached, true)
  assert.equal(call.options.stdio[0], 'ignore', 'stdin is not /dev/null')
  assert.notEqual(call.options.stdio[1], call.options.stdio[2], 'stdout and stderr share a descriptor')
  // Nothing but these goes to spawn: no timeout, no kill signal, no shell.
  assert.deepEqual(Object.keys(call.options).sort(), ['cwd', 'detached', 'env', 'stdio'])
  // And nothing but these goes on to Node's spawn, which is where a timeout or kill signal would take effect.
  const handed: { readonly command: string; readonly args: readonly string[]; readonly options: unknown }[] = []
  const throughNode = spawnWith((command, args, options) => {
    handed.push({ command, args, options })
    return new FakeChild(7, false)
  })
  throughNode(STOP, ['--jobs'], { cwd: pmmcp, env: { HOME: home }, stdio: ['ignore', 5, 6], detached: true })
  throughNode('lsof', ['-nP'], { cwd: pmmcp, env: { HOME: home }, stdio: ['pipe', 7, 8], detached: false })
  assert.deepEqual(handed, [
    { command: STOP, args: ['--jobs'], options: { cwd: pmmcp, env: { HOME: home }, stdio: ['ignore', 5, 6], detached: true } },
    { command: 'lsof', args: ['-nP'], options: { cwd: pmmcp, env: { HOME: home }, stdio: ['pipe', 7, 8], detached: false } },
  ])

  // Two files, 0600, in this run's own 0700 folder under .aos/install.
  const dir = join(installDir(root), STAMP)
  assert.equal(runner.dir, dir)
  assert.equal(stop.out, join(dir, 'stop.out'))
  assert.equal(stop.err, join(dir, 'stop.err'))
  assert.equal(mode(dir), 0o700)
  assert.equal(mode(stop.out), 0o600)
  assert.equal(mode(stop.err), 0o600)
  assert.equal(readFileSync(stop.out, 'utf8'), 'stop-pmmcp-server.sh: stopping services\n')
  assert.equal(readFileSync(stop.err, 'utf8'), 'stop-pmmcp-server.sh: [WARN] something\n')

  // While it runs, active.json says so, and no second stop or start begins.
  const active = readActive(root)
  assert.equal(active.state, 'recorded')
  if (active.state === 'recorded') {
    assert.deepEqual(active.record, { step: 'stop', pid: 4242, started: NOW.toISOString(), out: stop.out, err: stop.err })
  }
  assert.equal(mode(activePath(root)), 0o600)
  assert.throws(
    () => runner.start({ step: 'start', command: START, args: [], cwd: pmmcp }),
    (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_BUSY' && /pid 4242/.test(e.message),
  )
  assert.equal(fake.calls.length, 1)

  // A week passes: nothing times it out, nothing signals it.
  t.mock.timers.tick(7 * 24 * 60 * 60 * 1000)
  assert.deepEqual(call.child.signals, [])
  assert.equal(await settled(stop.done), false, 'the stop was given up on')
  call.child.emit('exit', 0, null)
  const stopped = await stop.done
  assert.equal(stopped.code, 0)
  assert.equal(stopped.timedOut, false)
  assert.equal(readActive(root).state, 'none', 'active.json outlived the stop')

  const start = runner.start({ step: 'start', command: START, args: [], cwd: pmmcp })
  const startCall = fake.calls[1]
  assert.ok(startCall)
  assert.equal(startCall.options.detached, true)
  assert.equal(startCall.options.stdio[0], 'ignore')
  assert.deepEqual(Object.keys(startCall.options).sort(), ['cwd', 'detached', 'env', 'stdio'])
  assert.equal(start.out, join(dir, 'start.out'))
  t.mock.timers.tick(7 * 24 * 60 * 60 * 1000)
  assert.deepEqual(startCall.child.signals, [])
  startCall.child.emit('exit', 1, null)
  assert.equal((await start.done).code, 1)
  assert.equal(readActive(root).state, 'none')

  // Every other way of running them is refused before anything is spawned.
  const linked = checkout(t, { 'stop-pmmcp-server.sh': '#!/bin/sh\nexit 0\n' })
  const HALT = join(linked, 'halt')
  symlinkSync(join(linked, 'stop-pmmcp-server.sh'), HALT)
  const refusals: Parameters<Runner['start']>[0][] = [
    { step: 'stop', command: STOP, args: ['--force'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--quiet', '-f'], cwd: pmmcp },
    { step: 'start', command: START, args: ['--force'], cwd: pmmcp },
    { step: 'start', command: START, args: ['--tail'], cwd: pmmcp },
    { step: 'start', command: START, args: ['--only'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: [], cwd: pmmcp, timeoutMs: 600_000 },
    { step: 'stop', command: STOP, args: ['--jobs'], cwd: pmmcp, digest: `sha256:${'a'.repeat(64)}` },
    { step: 'stop', command: 'stop-pmmcp-server.sh', args: [], cwd: pmmcp },
    { step: 'stop', command: '/bin/bash', args: [STOP], cwd: pmmcp },
    { step: 'stop', command: '/bin/sh', args: ['-c', `cd ${pmmcp} && ./stop-pmmcp-server.sh`], cwd: pmmcp },
    { step: 'stop', command: '/usr/bin/env', args: [START], cwd: pmmcp },
    // Arguments come from an allowlist: a wait that ends at once is --force by another name.
    { step: 'stop', command: STOP, args: ['--wait-timeout', '0'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout=0'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout=600'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout', '299'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout', '0300'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout', '600', '--wait-timeout', '0'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--quiet', '--quiet'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--jobs', '--force'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--jobs', '--quiet'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['-q'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--dry-run'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--multi-session'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--help'], cwd: pmmcp },
    { step: 'start', command: START, args: ['--check', '--force'], cwd: pmmcp },
    { step: 'start', command: START, args: ['-t'], cwd: pmmcp },
    { step: 'start', command: START, args: ['-f'], cwd: pmmcp },
    { step: 'start', command: START, args: ['--jobs'], cwd: pmmcp },
    // In any case: APFS runs each of these as the same file.
    { step: 'stop', command: join(pmmcp, 'Stop-PMMCP-Server.sh'), args: ['--force'], cwd: pmmcp },
    { step: 'stop', command: join(pmmcp, 'STOP-PMMCP-SERVER.SH'), args: [], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'start', command: join(pmmcp, 'Start-Pmmcp-Server.sh'), args: ['--tail'], cwd: pmmcp },
    { step: 'stop', command: 'Stop-PMMCP-Server.sh', args: [], cwd: pmmcp },
    { step: 'stop', command: '/bin/bash', args: [join(pmmcp, 'STOP-pmmcp-server.sh'), '-f'], cwd: pmmcp },
    // Through a link of another name, as the command or as a shell's operand, absolute or from the working directory.
    { step: 'stop', command: HALT, args: ['--force'], cwd: linked },
    { step: 'stop', command: HALT, args: [], cwd: linked, timeoutMs: 5000 },
    { step: 'stop', command: '/bin/bash', args: [HALT], cwd: linked },
    { step: 'stop', command: '/bin/sh', args: ['halt'], cwd: linked },
  ]
  for (const spec of refusals) {
    assert.throws(() => runner.start(spec), refusedCode, JSON.stringify(spec))
  }
  assert.equal(fake.calls.length, 2)

  // What the allowlist does let through runs by the same rules: detached, stdin /dev/null, recorded.
  const allowed: Parameters<Runner['start']>[0][] = [
    { step: 'stop', command: STOP, args: [], cwd: pmmcp },
    { step: 'jobs', command: STOP, args: ['--jobs'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--quiet'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout', '300'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--quiet', '--wait-timeout', '600'], cwd: pmmcp },
    { step: 'stop', command: STOP, args: ['--wait-timeout', '86400', '--quiet'], cwd: pmmcp },
    { step: 'start', command: START, args: [], cwd: pmmcp },
    { step: 'check', command: START, args: ['--check'], cwd: pmmcp },
    { step: 'stop', command: join(pmmcp, 'Stop-PMMCP-Server.sh'), args: [], cwd: pmmcp },
    { step: 'stop', command: HALT, args: [], cwd: linked },
  ]
  for (const spec of allowed) {
    const running = runner.start(spec)
    const c = fake.calls.at(-1)
    assert.ok(c && c.command === spec.command, JSON.stringify(spec))
    assert.equal(c.options.detached, true, JSON.stringify(spec))
    assert.equal(c.options.stdio[0], 'ignore', JSON.stringify(spec))
    assert.equal(readActive(root).state, 'recorded', JSON.stringify(spec))
    c.child.emit('exit', 0, null)
    await running.done
  }
  assert.equal(fake.calls.length, 2 + allowed.length)

  // Any other program is the installer's own child: not detached, and stdin is /dev/null without a digest.
  const probe = runner.start({ step: 'facts', command: join(pmmcp, '.venv', 'bin', 'python'), args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  const probeCall = fake.calls.at(-1)
  assert.ok(probeCall)
  assert.equal(probeCall.options.detached, false)
  assert.equal(probeCall.options.stdio[0], 'ignore', 'a probe without a digest has a stdin pipe')
  assert.equal(readActive(root).state, 'none', 'a probe was recorded as a window')
  probeCall.child.emit('exit', 0, null)
  await probe.done
  t.mock.timers.reset()

  // A real one: stdin is /dev/null, not a terminal, the two streams land apart, and it leads its own process group.
  const real = checkout(t, {
    'stop-pmmcp-server.sh': [
      '#!/bin/sh',
      'if [ -t 0 ]; then echo "stdin: a terminal"; else echo "stdin: not a terminal"; fi',
      'printf "stdin bytes: %s\\n" "$(wc -c | tr -d " ")"',
      GROUP_CHECK,
      'echo "to stderr" >&2',
      '',
    ].join('\n'),
  })
  const runs = new Runner({ repoRoot: repo(t), env: installerEnv(home), now: () => NOW })
  const ran = await runs.run({ step: 'stop', command: join(real, 'stop-pmmcp-server.sh'), args: [], cwd: real })
  assert.equal(ran.code, 0)
  assert.equal(readOut(ran), 'stdin: not a terminal\nstdin bytes: 0\nown group\n')
  assert.equal(readFileSync(ran.err, 'utf8'), 'to stderr\n')
  assert.equal(mode(ran.out), 0o600)
  assert.equal(mode(ran.err), 0o600)
  assert.equal(readActive(runs.repoRoot).state, 'none')
  // A real probe is in the installer's group, and one that reads stdin sees its end at once rather than waiting on a pipe.
  const grouped = await runs.run({ step: 'group', command: '/bin/sh', args: ['-c', GROUP_CHECK], cwd: real })
  assert.equal(readOut(grouped), 'not own group\n')
  const cat = await runs.run({ step: 'cat', command: '/bin/cat', args: [], cwd: real, timeoutMs: 10_000 })
  assert.equal(cat.timedOut, false, 'cat waited on a stdin that never ended')
  assert.equal(cat.code, 0)
  assert.equal(readOut(cat), '')
})

test('--jobs is read from stdout alone: a stderr warning written first never becomes the count', async (t) => {
  const home = tmpdir(t)
  const WARNING = "[WARN] the listener on 8765 is not this checkout's dashboard, so nothing was sent"
  const pmmcp = checkout(t, {
    'stop-pmmcp-server.sh': [
      '#!/bin/sh',
      '[ "$1" = "--jobs" ] || exit 2',
      `echo "${WARNING}" >&2`,
      'echo "running jobs: 9" >&2',
      'echo "running jobs: 2"',
      'printf "  j-1  scrape  my project  40%%\\n"',
      'printf "  j-2  index  \\033[31mred\\033[0m  10%%\\n"',
      '',
    ].join('\n'),
  })
  const STOP = join(pmmcp, 'stop-pmmcp-server.sh')
  const root = repo(t)
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), now: () => NOW })
  const result = await runner.run({ step: 'jobs', command: STOP, args: ['--jobs'], cwd: pmmcp })
  // The warning really was written first, where a merged capture would have put it on line 1.
  assert.equal(readFileSync(result.err, 'utf8').split('\n')[0], WARNING)
  assert.deepEqual(readJobs(result), { running: 2, display: ['  j-1  scrape  my project  40%', '  j-2  index  red  10%'] })

  // Fakes for the rest of the contract: stdout's first line with the exit that goes with it, and nothing else.
  const cases: { readonly out: string; readonly err?: string; readonly code: number | null; readonly signal?: NodeJS.Signals; readonly jobs: ReturnType<typeof readJobs> }[] = [
    { out: 'running jobs: 0\n', err: `${WARNING}\n`, code: 0, jobs: { running: 0, display: [] } },
    { out: 'running jobs: unknown\n', err: '[WARN] registry.db: the config cannot be read\n', code: 1, jobs: { running: 'unknown' } },
    // The count on stderr, however well formed, is never read.
    { out: '', err: 'running jobs: 3\n', code: 0, jobs: undefined },
    { out: '', err: 'running jobs: 0\n', code: 1, jobs: undefined },
    // A warning on stdout's first line is not the count.
    { out: `${WARNING}\nrunning jobs: 1\n`, code: 0, jobs: undefined },
    // The exit must agree with the line.
    { out: 'running jobs: unknown\n', code: 0, jobs: undefined },
    { out: 'running jobs: 2\n', code: 1, jobs: undefined },
    { out: 'running jobs: 2\n', code: 2, jobs: undefined },
    { out: 'running jobs: 2\n', code: null, signal: 'SIGTERM', jobs: undefined },
    { out: 'running jobs: 02\n', code: 0, jobs: undefined },
    { out: 'running jobs: 2 \n', code: 0, jobs: undefined },
  ]
  for (const c of cases) {
    const fake = recorder((call) => {
      write(call.options.stdio[2], c.err ?? '')
      write(call.options.stdio[1], c.out)
      setImmediate(() => call.child.emit('exit', c.code, c.signal ?? null))
    })
    const r = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
    const got = await r.run({ step: 'jobs', command: STOP, args: ['--jobs'], cwd: pmmcp })
    assert.deepEqual(readJobs(got), c.jobs, JSON.stringify(c))
  }
})

test('child output is shown scrubbed, and a registered value in it fails the step', async (t) => {
  const TOKEN = randomBytes(32).toString('hex')
  SecretMask.register(TOKEN)
  t.after(() => SecretMask.clear())
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const python = join(pmmcp, '.venv', 'bin', 'python')

  // A credential shape no one registered, and terminal control, are shown censored and stripped; the step passes.
  const root = repo(t)
  const fake = recorder((c) => {
    write(c.options.stdio[1], '{"facts": 1}\n')
    write(c.options.stdio[2], '\x1b[33m[WARN]\x1b[0m sent Bearer abcdefghijklmnop to the dashboard\r\nkey sk-ant-api03-abcdefghijklmnopqrstuvwx\x07\nlast line')
    setImmediate(() => c.child.emit('exit', 0, null))
  })
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  const ok = await runner.run({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  assert.deepEqual(tail(ok.err), ['[WARN] sent [REDACTED] to the dashboard', 'key [REDACTED]', 'last line'])
  assert.deepEqual(tail(ok.err, 1), ['last line'])
  assert.equal(readOut(ok), '{"facts": 1}\n')
  // A registered value is censored in a tail taken while a child still runs, before any scan.
  const live = join(dirname(ok.err), 'live.err')
  writeFileSync(live, `progress ${TOKEN} 40%\n`, { mode: 0o600 })
  assert.deepEqual(tail(live), ['progress [REDACTED] 40%'])
  // C1 controls too: U+009B is a CSI to a terminal that reads 8-bit controls, U+0090 a DCS, U+009D an OSC.
  const c1 = join(dirname(ok.err), 'c1.err')
  writeFileSync(c1, 'a\u009b31mred\u0085b\u0090c\u009cd\u009d0;title\u0007\n', { mode: 0o600 })
  assert.deepEqual(tail(c1), ['a31mredbcd0;title'])

  // The registered token on stdout: the step fails, the file is emptied, and nothing more is run.
  const leaky = recorder((c) => {
    write(c.options.stdio[1], `token=${TOKEN}\n`)
    write(c.options.stdio[2], 'a clean warning\n')
    setImmediate(() => c.child.emit('exit', 0, null))
  })
  const halted = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: leaky.spawn, now: () => NOW })
  const started = halted.start({ step: 'check-expect', command: python, args: ['-m', 'src.transport.http_auth', 'check', '--expect', 'aos-kernel'], cwd: pmmcp })
  await assert.rejects(started.done, (e: unknown) => {
    assert.ok(e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK', String(e))
    assert.equal(e.message.includes(TOKEN), false)
    assert.match(e.message, /check-expect\.out/)
    assert.equal(e.result?.code, 0)
    return true
  })
  assert.equal(statSync(started.out).size, 0, 'the leaked value is still on disk')
  assert.equal(readFileSync(started.err, 'utf8'), 'a clean warning\n')
  assert.match(halted.halted ?? '', /defect/)
  assert.throws(
    () => halted.start({ step: 'stop', command: join(pmmcp, 'stop-pmmcp-server.sh'), args: [], cwd: pmmcp }),
    (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_HALTED' && !e.message.includes(TOKEN),
  )
  // Nothing at all: a read-only probe and the start are refused too (A6's end report names the manual start instead).
  assert.throws(() => halted.start({ step: 'lsof', command: 'lsof', args: ['-nP', '-iTCP:8766', '-sTCP:LISTEN'], cwd: pmmcp }), haltedCode)
  assert.throws(() => halted.start({ step: 'start', command: join(pmmcp, 'start-pmmcp-server.sh'), args: [], cwd: pmmcp }), haltedCode)
  assert.equal(leaky.calls.length, 1)

  // The token on stderr alone: the same, with stdout left as it was written.
  const errLeak = recorder((c) => {
    write(c.options.stdio[1], '{"facts": 1}\n')
    write(c.options.stdio[2], `[WARN] sent ${TOKEN} to the dashboard\n`)
    setImmediate(() => c.child.emit('exit', 0, null))
  })
  const errHalted = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: errLeak.spawn, now: () => NOW })
  const errRun = errHalted.start({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  await assert.rejects(errRun.done, (e: unknown) => {
    assert.ok(e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK', String(e))
    assert.equal(e.message.includes(TOKEN), false)
    assert.match(e.message, /facts\.err/)
    assert.doesNotMatch(e.message, /facts\.out/)
    return true
  })
  assert.equal(statSync(errRun.err).size, 0, 'the leaked value is still on disk in the .err file')
  assert.equal(readFileSync(errRun.out, 'utf8'), '{"facts": 1}\n')
  assert.ok(errHalted.halted !== undefined)
  assert.throws(() => errHalted.start({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp }), haltedCode)
  assert.equal(errLeak.calls.length, 1)

  // While a value is registered, a file the scan cannot open counts as a hit: here the child left a link where its .err was.
  const elsewhere = join(tmpdir(t), 'elsewhere.txt')
  writeFileSync(elsewhere, 'kept\n')
  const swapping = recorder()
  const swapped = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: swapping.spawn, now: () => NOW })
  const swap = swapped.start({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  unlinkSync(swap.err)
  symlinkSync(elsewhere, swap.err)
  swapping.calls[0]?.child.emit('exit', 0, null)
  await assert.rejects(swap.done, (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK' && /facts\.err/.test(e.message))
  assert.equal(readFileSync(elsewhere, 'utf8'), 'kept\n', 'the link was followed')
  assert.ok(swapped.halted !== undefined)

  // A value across the scan's 1 MiB reads is still found whole: each read keeps the end of the one before.
  const straddling = recorder((c) => {
    write(c.options.stdio[1], `${'x'.repeat(SCAN_CHUNK - 10)}${TOKEN}\n`)
    setImmediate(() => c.child.emit('exit', 0, null))
  })
  const large = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: straddling.spawn, now: () => NOW })
  const across = large.start({ step: 'scrape', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  await assert.rejects(across.done, (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK' && /scrape\.out/.test(e.message))
  assert.equal(statSync(across.out).size, 0)

  // A real child that prints the value it found in a file: the same.
  const holder = join(tmpdir(t), 'holder.txt')
  writeFileSync(holder, `the value: ${TOKEN}\n`)
  const real = new Runner({ repoRoot: repo(t), env: installerEnv(home), now: () => NOW })
  const cat = real.start({ step: 'cat', command: '/bin/cat', args: [holder], cwd: dirname(holder) })
  await assert.rejects(cat.done, (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK' && !e.message.includes(TOKEN))
  assert.equal(statSync(cat.out).size, 0)
  assert.ok(real.halted !== undefined)
})

test('a probe given a timeout is sent SIGKILL at its deadline and reported timed out; a bad timeout is refused', async (t) => {
  const home = tmpdir(t)
  const root = repo(t)
  const fake = recorder()
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const probe = runner.start({ step: 'docker-info', command: 'docker', args: ['info'], cwd: root, timeoutMs: 5000 })
  const child = fake.calls[0]?.child
  assert.ok(child)
  t.mock.timers.tick(4999)
  assert.deepEqual(child.signals, [])
  t.mock.timers.tick(1)
  assert.deepEqual(child.signals, ['SIGKILL'])
  child.emit('exit', null, 'SIGKILL')
  const result = await probe.done
  assert.equal(result.timedOut, true)
  assert.equal(result.signal, 'SIGKILL')
  assert.equal(result.exited, true)

  // One that exits in time is not killed later.
  const quick = runner.start({ step: 'docker-info', command: 'docker', args: ['info'], cwd: root, timeoutMs: 5000 })
  assert.equal(quick.step, 'docker-info-2')
  fake.calls[1]?.child.emit('exit', 0, null)
  assert.equal((await quick.done).timedOut, false)
  t.mock.timers.tick(10_000)
  assert.deepEqual(fake.calls[1]?.child.signals, [])

  // One SIGKILL does not end (uninterruptible sleep, say lsof on a hung mount): reported unreaped after a grace period, not waited on for ever.
  const stuck = runner.start({ step: 'lsof', command: 'lsof', args: ['-nP', '-iTCP:8766', '-sTCP:LISTEN'], cwd: root, timeoutMs: 1000 })
  const stuckChild = fake.calls[2]?.child
  assert.ok(stuckChild)
  t.mock.timers.tick(1000)
  assert.deepEqual(stuckChild.signals, ['SIGKILL'])
  t.mock.timers.tick(KILL_GRACE_MS - 1)
  assert.equal(await settled(stuck.done), false, 'given up on before the grace period')
  t.mock.timers.tick(1)
  assert.equal(await settled(stuck.done), true, 'still waited on after the grace period')
  const unreaped = await stuck.done
  assert.equal(unreaped.timedOut, true)
  assert.equal(unreaped.exited, false)
  assert.equal(unreaped.code, null)
  assert.equal(unreaped.signal, null)
  // Its exit, when it comes at last, changes nothing.
  stuckChild.emit('exit', null, 'SIGKILL')
  assert.deepEqual(stuckChild.signals, ['SIGKILL'])
  t.mock.timers.reset()

  for (const timeoutMs of [0, -1, 1.5, Number.NaN, 25 * 60 * 60 * 1000]) {
    assert.throws(() => runner.start({ step: 'x', command: 'docker', args: [], cwd: root, timeoutMs }), refusedCode, String(timeoutMs))
  }
  assert.equal(fake.calls.length, 3)
})

test('the logs go under .aos/install only while .gitignore ignores /.aos/, never through a link, one 0700 folder per run', async (t) => {
  const home = tmpdir(t)
  const exits = (): ReturnType<typeof recorder> => recorder((c) => setImmediate(() => c.child.emit('exit', 0, null)))
  const spec = (root: string): Parameters<Runner['start']>[0] => ({ step: 'lsof', command: 'lsof', args: ['-nP', '-iTCP:8766', '-sTCP:LISTEN'], cwd: root })

  // Not ignored: nothing is made, nothing is run.
  const bare = tmpdir(t)
  const f1 = exits()
  assert.throws(() => new Runner({ repoRoot: bare, env: installerEnv(home), spawn: f1.spawn }).start(spec(bare)), refusedCode)
  writeFileSync(join(bare, '.gitignore'), '/.aos/\n!/.aos/\n')
  assert.throws(() => new Runner({ repoRoot: bare, env: installerEnv(home), spawn: f1.spawn }).start(spec(bare)), refusedCode)
  assert.equal(existsSync(join(bare, '.aos')), false)
  assert.equal(f1.calls.length, 0)

  // A linked .aos, or a linked .aos/install, would put the logs wherever it points.
  for (const link of ['.aos', join('.aos', 'install')]) {
    const root = repo(t)
    const elsewhere = tmpdir(t)
    mkdirSync(dirname(join(root, link)), { recursive: true })
    symlinkSync(elsewhere, join(root, link))
    const f = exits()
    assert.throws(() => new Runner({ repoRoot: root, env: installerEnv(home), spawn: f.spawn }).start(spec(root)), refusedCode, link)
    assert.deepEqual(readdirSync(elsewhere), [])
    assert.equal(f.calls.length, 0)
  }
  // One group or others may write into is refused too.
  const loose = repo(t)
  mkdirSync(join(loose, '.aos', 'install'), { recursive: true })
  chmodSync(join(loose, '.aos', 'install'), 0o777)
  assert.throws(() => new Runner({ repoRoot: loose, env: installerEnv(home), spawn: exits().spawn }).start(spec(loose)), refusedCode)

  // A .aos spelled otherwise on disk is not what /.aos/ covers under core.ignorecase=false (and on APFS it is where ./.aos writes go).
  const upper = repo(t)
  mkdirSync(join(upper, '.AOS'), { mode: 0o700 })
  const fu = exits()
  assert.throws(() => new Runner({ repoRoot: upper, env: installerEnv(home), spawn: fu.spawn }).start(spec(upper)), refusedCode)
  assert.deepEqual(readdirSync(join(upper, '.AOS')), [])
  assert.equal(fu.calls.length, 0)

  // A <step>.out or .err that is already there, a link to elsewhere included, is never opened: O_EXCL, refused, nothing run.
  const pre = repo(t)
  const fp = exits()
  const runner = new Runner({ repoRoot: pre, env: installerEnv(home), spawn: fp.spawn, now: () => NOW })
  await runner.run(spec(pre))
  const dir = runner.dir
  assert.ok(dir)
  const target = join(tmpdir(t), 'elsewhere.txt')
  writeFileSync(target, 'kept\n')
  writeFileSync(join(dir, 'facts.out'), 'planted\n', { mode: 0o600 })
  symlinkSync(target, join(dir, 'linked.out'))
  writeFileSync(join(dir, 'errs.err'), 'planted\n', { mode: 0o600 })
  for (const step of ['facts', 'linked', 'errs']) {
    assert.throws(() => runner.start({ ...spec(pre), step }), refusedCode, step)
  }
  assert.equal(fp.calls.length, 1)
  assert.equal(readFileSync(target, 'utf8'), 'kept\n')
  assert.equal(readFileSync(join(dir, 'facts.out'), 'utf8'), 'planted\n')
  assert.equal(readFileSync(join(dir, 'errs.err'), 'utf8'), 'planted\n')

  // Two runs stamped the same second get a folder each; a step run twice gets a second pair of files.
  const root = repo(t)
  const a = new Runner({ repoRoot: root, env: installerEnv(home), spawn: exits().spawn, now: () => NOW })
  const b = new Runner({ repoRoot: root, env: installerEnv(home), spawn: exits().spawn, now: () => NOW })
  const first = await a.run(spec(root))
  const again = await a.run(spec(root))
  const other = await b.run(spec(root))
  assert.equal(first.out, join(installDir(root), STAMP, 'lsof.out'))
  assert.equal(again.out, join(installDir(root), STAMP, 'lsof-2.out'))
  assert.equal(other.out, join(installDir(root), `${STAMP}-2`, 'lsof.out'))
  for (const dir of [join(root, '.aos'), installDir(root), join(installDir(root), STAMP), join(installDir(root), `${STAMP}-2`)]) {
    assert.equal(mode(dir), 0o700, dir)
    assert.equal(lstatSync(dir).isDirectory(), true)
  }
})

test('a stop or start is refused while active.json records one, until the caller clears it; a spawn that fails leaves no record', async (t) => {
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const STOP = join(pmmcp, 'stop-pmmcp-server.sh')
  const root = repo(t)
  mkdirSync(installDir(root), { recursive: true, mode: 0o700 })

  // An earlier installer died mid-window: its record stands, readable or not.
  const earlier = { step: 'stop', pid: 812, started: '2026-10-29T04:00:00.000Z', out: '/x/stop.out', err: '/x/stop.err' }
  for (const body of [JSON.stringify(earlier), '', '{"step":"stop"}']) {
    writeFileSync(activePath(root), body, { mode: 0o600 })
    const fake = recorder()
    const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
    assert.throws(
      () => runner.start({ step: 'stop', command: STOP, args: [], cwd: pmmcp }),
      (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_BUSY',
      body,
    )
    assert.equal(fake.calls.length, 0)
  }
  writeFileSync(activePath(root), JSON.stringify(earlier), { mode: 0o600 })
  assert.deepEqual(readActive(root), { state: 'recorded', record: earlier })
  // What the caller reads (A6's stale-record check): only a whole record is one; anything else there is unreadable, never none.
  for (const body of ['', '{"step":"stop"}', 'not json', JSON.stringify({ ...earlier, pid: 0 }), JSON.stringify(earlier).padEnd(5000)]) {
    writeFileSync(activePath(root), body, { mode: 0o600 })
    assert.equal(readActive(root).state, 'unreadable', body.slice(0, 40))
  }
  clearActive(root)
  assert.deepEqual(readActive(root), { state: 'none' })
  clearActive(root)

  // A record that appears between the check and the claim (another installer's) is still refused: the claim is O_EXCL.
  // The runner reads the clock a second time just before it claims, which is where this one plants the record.
  let reads = 0
  const racing = recorder()
  const raced = new Runner({
    repoRoot: root,
    env: installerEnv(home),
    spawn: racing.spawn,
    now: () => {
      reads += 1
      if (reads === 2) writeFileSync(activePath(root), JSON.stringify(earlier), { mode: 0o600 })
      return NOW
    },
  })
  assert.throws(
    () => raced.start({ step: 'stop', command: STOP, args: [], cwd: pmmcp }),
    (e: unknown) => busyCode(e) && e instanceof Error && /pid 812/.test(e.message),
  )
  assert.equal(reads, 2)
  assert.equal(racing.calls.length, 0)
  assert.deepEqual(readActive(root), { state: 'recorded', record: earlier }, 'the other record was written over')
  clearActive(root)

  // A record that cannot be removed when the child exits is reported in the result, never thrown from the exit, and the scan still runs.
  const exiting = recorder()
  const clearing = new Runner({ repoRoot: root, env: installerEnv(home), spawn: exiting.spawn, now: () => NOW })
  const stuck = clearing.start({ step: 'stop', command: STOP, args: [], cwd: pmmcp })
  // unlink cannot remove what it has become (EISDIR on Linux, EPERM on macOS), as it cannot after the operator changes the folder's mode.
  unlinkSync(activePath(root))
  mkdirSync(activePath(root))
  writeFileSync(join(activePath(root), 'x'), '')
  assert.doesNotThrow(() => exiting.calls[0]?.child.emit('exit', 0, null))
  const ended = await stuck.done
  assert.equal(ended.code, 0)
  assert.match(ended.activeError ?? '', /cannot remove .*active\.json \((?:EISDIR|EPERM)\)/)
  assert.equal(readActive(root).state, 'unreadable', 'a record that stays keeps a re-run waiting')
  rmSync(activePath(root), { recursive: true })

  // A script that cannot be started: the claim is given back, and the error says why.
  const failing: SpawnFn = (command, args, options) => {
    const child = new FakeChild(undefined, options.stdio[0] === 'pipe')
    setImmediate(() => child.emit('error', Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' })))
    return child
  }
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: failing, now: () => NOW })
  const missing = runner.start({ step: 'stop', command: STOP, args: [], cwd: pmmcp })
  assert.equal(missing.pid, undefined)
  await assert.rejects(missing.done, (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_SPAWN' && /ENOENT/.test(e.message))
  assert.deepEqual(readActive(root), { state: 'none' })

  // A real one that is not there: the same, through Node's own spawn.
  const real = new Runner({ repoRoot: root, env: installerEnv(home), now: () => NOW })
  const absent = real.start({ step: 'stop', command: join(pmmcp, 'no-such-dir', 'stop-pmmcp-server.sh'), args: [], cwd: pmmcp })
  await assert.rejects(absent.done, (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_SPAWN')
  assert.deepEqual(readActive(root), { state: 'none' })
})

test('a step inside the stopped window can run in its own session: detached, recorded in active.json, never timed out', async (t) => {
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const root = repo(t)
  const python = join(pmmcp, '.venv', 'bin', 'python')
  const fake = recorder()
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] })

  // L2's fast-forward: a Ctrl-C at the installer's terminal must not leave a half-updated tree and an index.lock while pmmcp is stopped.
  const merge = runner.start({ step: 'merge', command: 'git', args: ['merge', '--ff-only', 'origin/main'], cwd: pmmcp, ownSession: true })
  const call = fake.calls[0]
  assert.ok(call)
  assert.equal(call.options.detached, true)
  assert.equal(call.options.stdio[0], 'ignore')
  assert.equal(call.options.env['SSH_AUTH_SOCK'], installerEnv(home).SSH_AUTH_SOCK, 'git still gets the agent')
  assert.deepEqual(readActive(root), { state: 'recorded', record: { step: 'merge', pid: 4242, started: NOW.toISOString(), out: merge.out, err: merge.err } })
  // While it runs, no stop, start or other step in its own session begins; a probe may still look.
  assert.throws(() => runner.start({ step: 'start', command: join(pmmcp, START_SCRIPT), args: [], cwd: pmmcp }), busyCode)
  assert.throws(() => runner.start({ step: 'qdrant', command: python, args: ['scripts/qdrant_api_key.py', 'enable'], cwd: pmmcp, ownSession: true }), busyCode)
  const look = runner.start({ step: 'lsof', command: 'lsof', args: ['-nP', '-iTCP:8766', '-sTCP:LISTEN'], cwd: pmmcp, timeoutMs: 5000 })
  assert.equal(fake.calls[1]?.options.detached, false)
  fake.calls[1]?.child.emit('exit', 1, null)
  await look.done
  // A week passes: nothing times it out, nothing signals it.
  t.mock.timers.tick(7 * 24 * 60 * 60 * 1000)
  assert.deepEqual(call.child.signals, [])
  assert.equal(await settled(merge.done), false)
  call.child.emit('exit', 0, null)
  assert.equal((await merge.done).code, 0)
  assert.equal(readActive(root).state, 'none')

  // It is given no timeout: refused before anything exists.
  assert.throws(() => runner.start({ step: 'auth', command: python, args: ['-m', 'src.dashboard.auth', 'init'], cwd: pmmcp, ownSession: true, timeoutMs: 60_000 }), refusedCode)
  // Without the option the same program is the installer's own child, and nothing is recorded.
  const plain = runner.start({ step: 'auth', command: python, args: ['-m', 'src.dashboard.auth', 'status', '--json'], cwd: pmmcp })
  assert.equal(fake.calls.at(-1)?.options.detached, false)
  assert.equal(readActive(root).state, 'none')
  fake.calls.at(-1)?.child.emit('exit', 0, null)
  await plain.done
  assert.equal(fake.calls.length, 3)
  t.mock.timers.reset()

  // A real one leads a process group of its own.
  const real = new Runner({ repoRoot: repo(t), env: installerEnv(home), now: () => NOW })
  const own = await real.run({ step: 'own', command: '/bin/sh', args: ['-c', GROUP_CHECK], cwd: pmmcp, ownSession: true })
  assert.equal(own.code, 0)
  assert.equal(readOut(own), 'own group\n')
  assert.equal(readActive(real.repoRoot).state, 'none')
})

test('machine output is read whole, as valid UTF-8 and within its cap, over as many reads as it takes', (t) => {
  const dir = tmpdir(t)
  const file = (step: string, data: string | Buffer): { readonly step: string; readonly out: string } => {
    const out = join(dir, `${step}.out`)
    writeFileSync(out, data, { mode: 0o600 })
    return { step, out }
  }
  assert.equal(readOut(file('facts', '{"facts": 1}\n')), '{"facts": 1}\n')
  assert.equal(readOut(file('empty', '')), '')

  // Bytes that are not UTF-8 are no answer, whatever a lenient decoder would make of them.
  for (const bytes of [[0xff], [0x7b, 0xc3], [0xed, 0xa0, 0x80], [0xc0, 0xaf], [0x72, 0x75, 0x6e, 0x80]]) {
    assert.throws(() => readOut(file('bad', Buffer.from(bytes))), (e: unknown) => outputCode(e) && /not valid UTF-8/.test(String(e)), JSON.stringify(bytes))
  }
  // More than the cap is no answer either; the cap itself is.
  assert.equal(readOut(file('four', 'abcd'), 4), 'abcd')
  assert.throws(() => readOut(file('five', 'abcde'), 4), (e: unknown) => outputCode(e) && /over the 4/.test(String(e)))
  assert.equal(readOut(file('max', Buffer.alloc(MAX_MACHINE_OUTPUT, 0x20))).length, MAX_MACHINE_OUTPUT)
  assert.throws(() => readOut(file('big', Buffer.alloc(MAX_MACHINE_OUTPUT + 1, 0x20))), outputCode)
  assert.throws(() => readOut({ step: 'gone', out: join(dir, 'gone.out') }), (e: unknown) => outputCode(e) && /ENOENT/.test(String(e)))

  // A short read is read on from, and only the end of the file returns fewer bytes: never a NUL nothing was read into.
  const source = Buffer.from('running jobs: 2\n  j-1  scrape  40%\n')
  const oneByte: ReadFn = (_fd, buffer, offset, length, position) => {
    const n = Math.min(1, length, source.length - position)
    if (n <= 0) return 0
    source.copy(buffer, offset, position, position + n)
    return n
  }
  assert.deepEqual(readAt(-1, source.length, 0, oneByte), source)
  assert.deepEqual(readAt(-1, source.length + 16, 0, oneByte), source)
  assert.deepEqual(readAt(-1, 7, 8, oneByte), source.subarray(8, 15))
  assert.deepEqual(readAt(-1, 0, 0, oneByte), Buffer.alloc(0))
  const real = file('real', 'abc')
  const fd = openSync(real.out, 'r')
  try {
    assert.equal(readAt(fd, 3, 0).toString('utf8'), 'abc')
    assert.equal(readAt(fd, 10, 1).toString('utf8'), 'bc')
  } finally {
    closeSync(fd)
  }
})
