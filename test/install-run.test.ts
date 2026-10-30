// The installer's process runner (scripts/install/run.ts).
//
// Every program the installer runs goes through it, the stop and start
// scripts included, so these tests are about what a child can never get: the
// installer's environment, a secret in its argv, env or stdin, a merged or
// piped capture, a timeout or a signal on the stop and start scripts, and an
// unscrubbed line on the operator's screen. Every repository and HOME here is
// a mkdtemp directory. Most children are fakes that record what spawn was
// handed. The few real ones are what the runner lets run: the stop and start
// scripts as /bin/sh files in a mkdtemp checkout, and a stand-in
// .venv/bin/python run on `scripts/pmmcp_facts.py --json`
// (helpers/python-stand-in.ts), a /bin/sh or node script whose body does what
// the test needs (cat, mkfifo, env and sleep run only inside it); never
// pmmcp, docker, launchctl, lsof or ps.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  chownSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
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
import ts from 'typescript'

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
  TAIL_BYTES,
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
  type NodeSpawnFn,
  type ReadFn,
  type RunResult,
  type RunSpec,
  type SpawnFn,
} from '../scripts/install/run.js'
import { CREDENTIAL_NAME } from './helpers/guard.js'
import { pythonStandIn, shWord } from './helpers/python-stand-in.js'
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

/** A digest for a spec that reads one. */
const DIGEST = `sha256:${'c'.repeat(64)}`

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

  // And a real child sees nothing else: a stand-in python that prints the environment it was given (in node, which adds no name of its own).
  const real = new Runner({ repoRoot: root, env: parent, now: () => NOW })
  const printer = pythonStandIn(t, 'for (const [k, v] of Object.entries(process.env)) console.log(`${k}=${v}`)', process.execPath)
  const printed = await real.run({ step: 'env', ...printer })
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
    const recorded = readActive(root)
    assert.equal(recorded.state, 'recorded', JSON.stringify(spec))
    // Only the jobs count, which changes nothing, is recorded as read-only: a re-run may clear it once its pid has ended, and never reads it as a window.
    const jobsCount = spec.command === STOP && spec.args.length === 1 && spec.args[0] === '--jobs'
    assert.equal(recorded.state === 'recorded' && recorded.record.readOnly === true, jobsCount, JSON.stringify(spec))
    if (jobsCount) {
      assert.throws(
        () => runner.start({ step: 'stop', command: STOP, args: [], cwd: pmmcp }),
        (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_BUSY' && /an earlier read-only count of pmmcp's jobs/.test(e.message) && !/inside the stopped window/.test(e.message),
      )
    }
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
  const grouped = await runs.run({ step: 'group', ...pythonStandIn(t, GROUP_CHECK) })
  assert.equal(readOut(grouped), 'not own group\n')
  const cat = await runs.run({ step: 'cat', ...pythonStandIn(t, 'exec cat'), timeoutMs: 10_000 })
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

  // A child that never exited (a probe the SIGKILL did not end) is no answer, whatever its stdout and exit code say.
  const dir = tmpdir(t)
  const counted = join(dir, 'jobs.out')
  const unknown = join(dir, 'unknown.out')
  writeFileSync(counted, 'running jobs: 0\n', { mode: 0o600 })
  writeFileSync(unknown, 'running jobs: unknown\n', { mode: 0o600 })
  const unreaped: RunResult = {
    step: 'jobs',
    pid: 7,
    out: counted,
    err: join(dir, 'jobs.err'),
    started: NOW,
    elapsedMs: 0,
    code: 0,
    signal: null,
    timedOut: true,
    exited: false,
    stdinError: undefined,
    childError: undefined,
    activeError: undefined,
  }
  assert.equal(readJobs(unreaped), undefined)
  assert.equal(readJobs({ ...unreaped, out: unknown, code: 1 }), undefined)
  // The same, exited, is the answer it looks like.
  assert.deepEqual(readJobs({ ...unreaped, exited: true, timedOut: false }), { running: 0, display: [] })
  assert.deepEqual(readJobs({ ...unreaped, out: unknown, code: 1, exited: true, timedOut: false }), { running: 'unknown' })
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
  // The bidi controls, which reorder what the operator reads, and the line and paragraph separators, which start a line of their own.
  const bidi = join(dirname(ok.err), 'bidi.err')
  writeFileSync(bidi, 'a‪b‫c‬d‭e‮f⁦g⁧h⁨i⁩j‎k‏l؜m n o\n', { mode: 0o600 })
  assert.deepEqual(tail(bidi), ['abcdefghijklmno'])
  // A registered value the 64 KiB cut lands inside: the cut line is dropped whole, so not even its end is shown.
  const cut = join(dirname(ok.err), 'cut.err')
  const after = TAIL_BYTES - 32
  writeFileSync(cut, `${'p'.repeat(100)}${TOKEN}\n${'z'.repeat(after - 2)}\n`, { mode: 0o600 })
  const fromCut = tail(cut)
  assert.deepEqual(fromCut, ['z'.repeat(after - 2)])
  assert.equal(fromCut.some((l) => l.includes(TOKEN.slice(32))), false, 'the end of a value cut at 64 KiB was shown')

  // The registered token on stdout: the step fails, the file is emptied, and nothing more is run.
  const leaky = recorder((c) => {
    write(c.options.stdio[1], `token=${TOKEN}\n`)
    write(c.options.stdio[2], 'a clean warning\n')
    setImmediate(() => c.child.emit('exit', 0, null))
  })
  const halted = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: leaky.spawn, now: () => NOW })
  const started = halted.start({ step: 'check-expect', command: python, args: ['-m', 'src.transport.http_auth', 'check', '--expect', 'aos-kernel'], cwd: pmmcp, digest: DIGEST })
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
  const cat = real.start({ step: 'cat', ...pythonStandIn(t, `exec cat ${shWord(holder)}`) })
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
    assert.throws(() => runner.start({ step: 'x', command: 'docker', args: ['info'], cwd: root, timeoutMs }), (e: unknown) => refusedCode(e) && /timeoutMs must be a whole number of milliseconds from 1 to a day/.test(String(e)), String(timeoutMs))
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
  // One group or others may write into is refused too: group write alone, others' alone, or both, at either level.
  for (const [level, bits] of [
    [join('.aos', 'install'), 0o777],
    [join('.aos', 'install'), 0o770],
    [join('.aos', 'install'), 0o775],
    [join('.aos', 'install'), 0o720],
    [join('.aos', 'install'), 0o702],
    [join('.aos', 'install'), 0o757],
    ['.aos', 0o770],
    ['.aos', 0o702],
  ] as const) {
    const loose = repo(t)
    mkdirSync(join(loose, '.aos', 'install'), { recursive: true, mode: 0o700 })
    chmodSync(join(loose, level), bits)
    const f = exits()
    assert.throws(
      () => new Runner({ repoRoot: loose, env: installerEnv(home), spawn: f.spawn }).start(spec(loose)),
      (e: unknown) => refusedCode(e) && e instanceof Error && /is writable by group or others/.test(e.message),
      `${level} ${bits.toString(8)}`,
    )
    assert.equal(f.calls.length, 0)
    assert.deepEqual(readdirSync(join(loose, '.aos', 'install')), [], `${level} ${bits.toString(8)}: a run folder was made`)
  }
  // One that only its owner writes in, read and search for the rest, is the runner's.
  const readable = repo(t)
  mkdirSync(join(readable, '.aos', 'install'), { recursive: true, mode: 0o700 })
  chmodSync(join(readable, '.aos', 'install'), 0o755)
  assert.equal((await new Runner({ repoRoot: readable, env: installerEnv(home), spawn: exits().spawn, now: () => NOW }).run(spec(readable))).code, 0)

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

  // A spawn that throws before it returns (Node does, for an argument it will not hand on): the claim is given back there too.
  const throwing: SpawnFn = () => {
    throw Object.assign(new Error('spawn EAGAIN'), { code: 'EAGAIN' })
  }
  const python = join(pmmcp, '.venv', 'bin', 'python')
  for (const spec of [
    { step: 'stop', command: STOP, args: [], cwd: pmmcp },
    { step: 'qdrant', command: python, args: ['scripts/qdrant_api_key.py', 'enable'], cwd: pmmcp, ownSession: true },
  ]) {
    const thrown = new Runner({ repoRoot: root, env: installerEnv(home), spawn: throwing, now: () => NOW })
    assert.throws(() => thrown.start(spec), (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_SPAWN' && /EAGAIN/.test(e.message), spec.step)
    assert.deepEqual(readActive(root), { state: 'none' }, `${spec.step}: the claim outlived a spawn that threw`)
  }
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

  // A child's exit removes only its own record: if the caller cleared one whose child still ran and started
  // another, the first child's exit leaves the second's record standing.
  const children: FakeChild[] = []
  const numbered: SpawnFn = (_command, _args, options) => {
    const child = new FakeChild(500 + children.length, options.stdio[0] === 'pipe')
    children.push(child)
    return child
  }
  const two = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: numbered, now: () => NOW })
  const first = two.start({ step: 'merge', command: 'git', args: ['merge', '--ff-only', 'origin/main'], cwd: pmmcp, ownSession: true })
  clearActive(two.repoRoot)
  const second = two.start({ step: 'qdrant', command: python, args: ['scripts/qdrant_api_key.py', 'enable'], cwd: pmmcp, ownSession: true })
  children[0]?.emit('exit', 0, null)
  assert.equal((await first.done).activeError, undefined)
  assert.deepEqual(readActive(two.repoRoot), { state: 'recorded', record: { step: 'qdrant', pid: 501, started: NOW.toISOString(), out: second.out, err: second.err } })
  children[1]?.emit('exit', 0, null)
  await second.done
  assert.equal(readActive(two.repoRoot).state, 'none')

  // A real one leads a process group of its own.
  const real = new Runner({ repoRoot: repo(t), env: installerEnv(home), now: () => NOW })
  const own = await real.run({ step: 'own', ...pythonStandIn(t, GROUP_CHECK), ownSession: true })
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

test("a step's two files can be emptied once read, and only a step this runner ran", async (t) => {
  // A probe's output may hold another process's command line (ps) or launchd's
  // copy of a service's environment: once read, the logs need not keep it.
  const root = repo(t)
  const home = tmpdir(t)
  const fake = recorder((c) => {
    write(c.options.stdio[1], '  501 /usr/bin/ssh -N -L 8766:127.0.0.1:8766 -o IdentityFile=/Users/op/.ssh/vm vm\n')
    write(c.options.stdio[2], 'a warning\n')
    setImmediate(() => c.child.emit('exit', 0, null))
  })
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  const result = await runner.run({ step: 'ps-812', command: 'ps', args: ['-ww', '-o', 'uid=,args=', '-p', '812'], cwd: root, timeoutMs: 5000 })
  assert.match(readOut(result), /ssh -N -L/)
  assert.equal(runner.discard(result), undefined)
  assert.equal(readFileSync(result.out, 'utf8'), '')
  assert.equal(readFileSync(result.err, 'utf8'), '')
  // Still this run's 0600 files, now empty.
  assert.equal(mode(result.out), 0o600)
  assert.equal(mode(result.err), 0o600)
  // A file already gone is no error.
  unlinkSync(result.err)
  assert.equal(runner.discard(result), undefined)

  // Nothing but a step this runner ran, by the names it gave its files.
  const keep = join(dirname(result.out), 'notes.txt')
  writeFileSync(keep, 'kept\n', { mode: 0o600 })
  const outside = join(root, 'kept.txt')
  writeFileSync(outside, 'kept\n', { mode: 0o600 })
  assert.throws(() => runner.discard({ step: 'ps-812', out: keep, err: result.err }), refusedCode)
  assert.throws(() => runner.discard({ step: 'ps-812', out: result.out, err: outside }), refusedCode)
  assert.throws(() => runner.discard({ step: 'never', out: join(dirname(result.out), 'never.out'), err: join(dirname(result.out), 'never.err') }), refusedCode)
  const other = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => new Date(NOW.getTime() + 1000) })
  assert.throws(() => other.discard(result), refusedCode)
  const theirs = await other.run({ step: 'ps-812', command: 'ps', args: ['-ww', '-o', 'uid=,args=', '-p', '812'], cwd: root, timeoutMs: 5000 })
  assert.throws(() => runner.discard(theirs), refusedCode)
  assert.match(readFileSync(theirs.out, 'utf8'), /ssh -N -L/)
  assert.equal(readFileSync(keep, 'utf8'), 'kept\n')
  assert.equal(readFileSync(outside, 'utf8'), 'kept\n')
})

test('nothing that signals, restarts or shells around these rules runs: launchctl kickstart, kill, pkill, killall, a shell command string, a stop or start with --force, a timeout or a kill signal', (t) => {
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const STOP = join(pmmcp, STOP_SCRIPT)
  const START = join(pmmcp, START_SCRIPT)
  const LABEL = 'gui/501/com.aibot.pmmcp'
  const python = join(pmmcp, '.venv', 'bin', 'python')
  // A program reached through a link of another name, as the command or as a bare name on the child's PATH, is known by what the link resolves to.
  const bin = tmpdir(t)
  for (const name of ['kill', 'killall', 'launchctl', 'bash', 'perl', 'python3', 'nohup', 'find']) {
    writeFileSync(join(bin, name), '#!/bin/sh\nexit 0\n')
    chmodSync(join(bin, name), 0o755)
  }
  symlinkSync(join(bin, 'kill'), join(bin, 'k'))
  symlinkSync(join(bin, 'bash'), join(bin, 'shell'))
  mkdirSync(join(home, '.local', 'bin'), { recursive: true })
  symlinkSync(join(bin, 'killall'), join(home, '.local', 'bin', 'zap'))
  symlinkSync(join(bin, 'launchctl'), join(home, '.local', 'bin', 'lc'))
  // An allowlisted name that is a link to something else is held to what it resolves to.
  const linked = tmpdir(t)
  for (const [name, to] of [['ls', 'perl'], ['ps', 'python3'], ['pgrep', 'nohup'], ['lsof', 'find'], ['git', 'bash']] as const) symlinkSync(join(bin, to), join(linked, name))
  // A real stop, and links to it on the child's PATH, where bash looks for a script name it does not find in the working directory.
  const install = checkout(t, { [STOP_SCRIPT]: '#!/bin/sh\necho "STOP RAN WITH: $*"\n' })
  linkSync(join(install, STOP_SCRIPT), join(home, '.local', 'bin', 'halt'))
  symlinkSync(join(install, STOP_SCRIPT), join(home, '.local', 'bin', 'stopper'))
  const bare = tmpdir(t)
  const toStdin = join(bare, 'stdin-link')
  symlinkSync('/dev/stdin', toStdin)
  const toDev = join(bare, 'dev-link')
  symlinkSync('/dev', toDev)
  // A regular file this process holds open, reached through /dev/fd: a stat sees the file, a child opening the path gets its own descriptor of that number.
  const held = join(bare, 'held.sh')
  writeFileSync(held, '#!/bin/sh\nexit 0\n')
  const heldFd = openSync(held, 'r')
  t.after(() => closeSync(heldFd))
  const toFd = join(bare, 'fd-link')
  symlinkSync(`/dev/fd/${String(heldFd)}`, toFd)
  // A renamed copy of a shell is no program the installer runs, whatever it could do.
  const mysh = join(tmpdir(t), 'mysh')
  copyFileSync('/bin/sh', mysh)
  chmodSync(mysh, 0o755)
  // A script file of the checkout's, and pmmcp's own uninstaller, which runs launchctl bootout and kill: no shell runs either, by any name.
  const script = join(pmmcp, 'x.sh')
  writeFileSync(script, '#!/bin/sh\nexit 0\n')
  const UNINSTALL = join(pmmcp, 'uninstall-pmmcp-service.sh')
  writeFileSync(UNINSTALL, '#!/bin/sh\nlaunchctl bootout gui/501/com.aibot.pmmcp\nkill -TERM 812\n')
  chmodSync(UNINSTALL, 0o755)
  // A link to itself, as a shell's script, the command or an argument: realpath(3) ends it (ELOOP), so nothing here loops on it.
  const loop = join(bare, 'loop')
  symlinkSync('loop', loop)
  // A command or working directory spelled with .. after a link: <dots>/a/link/.. is <dots>/b to the kernel, and <dots>/a to the spelling.
  const dots = tmpdir(t)
  mkdirSync(join(dots, 'a'))
  mkdirSync(join(dots, 'b', 'c'), { recursive: true })
  symlinkSync(join(dots, 'b', 'c'), join(dots, 'a', 'link'))
  symlinkSync('/bin/kill', join(dots, 'b', 'ps'))
  symlinkSync('/bin/bash', join(dots, 'b', 'ls'))
  // And an allowlisted name linked through such a spelling: the kernel reaches b/ps (kill), the spelling a/ps (a harmless file of that name).
  writeFileSync(join(dots, 'a', 'ps'), '#!/bin/sh\nexit 0\n')
  chmodSync(join(dots, 'a', 'ps'), 0o755)
  mkdirSync(join(dots, 'x'))
  symlinkSync('../a/link/../ps', join(dots, 'x', 'ps'))
  // An allowlisted name that is a link to a program on no list (tar runs a command at a checkpoint, flock and make run one), or to another on the list.
  for (const name of ['tar', 'flock', 'make', 'docker', 'python3.12']) {
    writeFileSync(join(bin, name), '#!/bin/sh\nexit 0\n')
    chmodSync(join(bin, name), 0o755)
  }
  const linkAs = (target: string, name: string): string => {
    const at = join(tmpdir(t), name)
    symlinkSync(target, at)
    return at
  }
  // The same through the child's PATH: ~/.local/bin comes first on it.
  const tarHome = tmpdir(t)
  mkdirSync(join(tarHome, '.local', 'bin'), { recursive: true })
  symlinkSync(join(bin, 'tar'), join(tarHome, '.local', 'bin', 'ls'))
  // A venv's python as uv makes it, a link to the interpreter it was made from.
  const venvBin = join(tmpdir(t), 'Persistent-Memory-MCP', '.venv', 'bin')
  mkdirSync(venvBin, { recursive: true })
  symlinkSync(join(bin, 'python3.12'), join(venvBin, 'python'))
  // A folder no program is in.
  const nowhere = tmpdir(t)
  // A link to a folder named as the stop script.
  const peeks = tmpdir(t)
  mkdirSync(join(nowhere, STOP_SCRIPT))
  symlinkSync(join(nowhere, STOP_SCRIPT), join(peeks, 'peek'))
  const SHELL = /a shell \((?:sh|bash|zsh|dash)\) runs nothing here, whatever it is given: a -c command string, a script file \(pmmcp's uninstall-pmmcp-service\.sh runs launchctl bootout and kill\) and commands read from stdin/
  const NOT_LISTED = /is not a program the installer runs: only ps, pgrep, lsof, ls, plutil, launchctl, docker, git, setup\.sh, a checkout's \.venv\/bin\/python, and the stop and start scripts/
  const DOCKER = /docker is run here only to read, with ps, info or context show, and no option before them: never kill, stop, restart, rm or compose/
  const PYTHON = /python runs here only as a checkout's \.venv\/bin\/python, by absolute path, after -B at most, in a form the installer runs \(scripts\/pmmcp_facts\.py --json; .*\): never -c, another module or script, another argument, or commands read from stdin/
  const GIT_GLOBAL = /git is given here no option before its command but --no-optional-locks: never -c, --config-env/
  const PLUTIL = /plutil is run here only as -extract <key> <format> -o - <file>, which reads/
  const NOT_THE_COMMAND = /the stop and start scripts run only as the command itself, by absolute path/
  const DOTTED = (what: string): RegExp => new RegExp(`${what} has a \\. or \\.\\. component, which after a link is another folder than its spelling says`)

  const cases: { readonly spec: RunSpec; readonly why: RegExp; readonly env?: Record<string, string> }[] = [
    // launchctl only reads: kickstart, with -k or without, in any case, and every other change to a service is refused.
    { spec: { step: 'kick', command: 'launchctl', args: ['kickstart', '-k', LABEL], cwd: pmmcp }, why: /launchctl is run here only to read, with print or list: kickstart restarts a service/ },
    { spec: { step: 'kick', command: '/bin/launchctl', args: ['kickstart', LABEL], cwd: pmmcp }, why: /kickstart restarts a service/ },
    { spec: { step: 'kick', command: 'LaunchCtl', args: ['KICKSTART', '-kp', LABEL], cwd: pmmcp }, why: /kickstart restarts a service/ },
    { spec: { step: 'kick', command: 'lc', args: ['kickstart', '-k', LABEL], cwd: pmmcp }, why: /kickstart restarts a service/ },
    { spec: { step: 'lkill', command: 'launchctl', args: ['kill', 'SIGTERM', LABEL], cwd: pmmcp }, why: /launchctl is run here only to read, with print or list/ },
    { spec: { step: 'lstop', command: 'launchctl', args: ['stop', 'com.aibot.pmmcp'], cwd: pmmcp }, why: /launchctl is run here only to read/ },
    { spec: { step: 'bootout', command: 'launchctl', args: ['bootout', LABEL], cwd: pmmcp }, why: /launchctl is run here only to read/ },
    { spec: { step: 'bare', command: 'launchctl', args: [], cwd: pmmcp }, why: /launchctl is run here only to read/ },
    // Nothing that signals a process: by pid, by name, or at a deadline.
    { spec: { step: 'kill', command: 'kill', args: ['-TERM', '812'], cwd: pmmcp }, why: /kill signals the processes it names or runs, and nothing here signals a process/ },
    { spec: { step: 'kill', command: '/bin/kill', args: ['-9', '812'], cwd: pmmcp }, why: /kill signals/ },
    { spec: { step: 'kill', command: 'kill', args: ['-0', '812'], cwd: pmmcp }, why: /kill signals/ },
    { spec: { step: 'kill', command: 'KILL', args: ['812'], cwd: pmmcp }, why: /kill signals/ },
    { spec: { step: 'kill', command: join(bin, 'k'), args: ['812'], cwd: pmmcp }, why: /kill signals/ },
    { spec: { step: 'pkill', command: 'pkill', args: ['-f', 'Persistent-Memory-MCP'], cwd: pmmcp }, why: /pkill signals/ },
    { spec: { step: 'pkill', command: '/usr/bin/pkill', args: ['-f', STOP_SCRIPT], cwd: pmmcp }, why: /pkill signals/ },
    { spec: { step: 'killall', command: 'killall', args: ['python3'], cwd: pmmcp }, why: /killall signals/ },
    { spec: { step: 'killall', command: 'KillAll', args: ['-9', 'pmmcp'], cwd: pmmcp }, why: /killall signals/ },
    { spec: { step: 'killall', command: 'zap', args: ['pmmcp'], cwd: pmmcp }, why: /killall signals/ },
    { spec: { step: 'timeout', command: 'timeout', args: ['10', STOP], cwd: pmmcp }, why: /timeout signals/ },
    { spec: { step: 'timeout', command: '/opt/homebrew/bin/gtimeout', args: ['-s', 'KILL', '10', 'docker', 'info'], cwd: pmmcp }, why: /gtimeout signals/ },
    // No shell runs, by any name, whatever it is given: a command string, an option, commands from stdin or a script file.
    { spec: { step: 'sh', command: '/bin/sh', args: ['-c', `cd ${pmmcp} && ./stop-pmmcp-server.sh --force`], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/bash', args: ['-c', 'kill -TERM 812'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/zsh', args: ['-c', 'launchctl kickstart -k gui/501/com.aibot.pmmcp'], cwd: pmmcp }, why: /a shell \(zsh\)/ },
    { spec: { step: 'sh', command: 'dash', args: ['-c', 'true'], cwd: pmmcp }, why: /a shell \(dash\)/ },
    { spec: { step: 'sh', command: '/bin/sh', args: ['-ec', 'true'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/bash', args: ['-lc', 'true'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/bash', args: ['--norc', '-c', 'true'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['+x', '-c', 'true'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['-s'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: [], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: [''], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/BIN/SH', args: ['-c', 'true'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: join(bin, 'shell'), args: ['-c', 'true'], cwd: pmmcp }, why: /a shell \(bash\)/ },
    // A name that is no file in the working directory: bash (macOS's /bin/sh too) would find halt, the stop by another name, on its PATH, and run it with --force.
    { spec: { step: 'sh', command: '/bin/bash', args: ['halt', '--force'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['halt', '--force'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/bash', args: ['stopper', '-f'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['nonexistent'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: [bare], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['.'], cwd: bare }, why: SHELL },
    // A device, or a link to one, which a child reads as its own stdin (or its own log).
    { spec: { step: 'sh', command: '/bin/sh', args: ['/dev/stdin'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['/dev/fd/0'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['/proc/self/fd/0'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['stdin-link'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['dev-link/stdin'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['/dev/null'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: [`/dev/fd/${String(heldFd)}`], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['fd-link'], cwd: bare }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['/proc/self/exe'], cwd: bare }, why: SHELL },
    // A script file, a regular one in the working directory or by absolute path: pmmcp's uninstaller (launchctl bootout, kill) first of all.
    { spec: { step: 'sh', command: '/bin/sh', args: ['uninstall-pmmcp-service.sh'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/bash', args: [UNINSTALL], cwd: home }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: [script, '-c', 'an argument of the script'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/bash', args: ['x.sh'], cwd: pmmcp }, why: SHELL },
    { spec: { step: 'sh', command: '/bin/sh', args: ['./x.sh'], cwd: pmmcp }, why: SHELL },
    // A link to itself: refused at once, never followed for ever.
    { spec: { step: 'sh', command: '/bin/sh', args: ['loop'], cwd: bare }, why: SHELL },
    // A shell reached only through an allowlisted name's link is a shell: ls linked to bash, given a name bash would look for on its PATH.
    { spec: { step: 'ls', command: linkAs('/bin/bash', 'ls'), args: ['halt', '--force'], cwd: bare }, why: /a shell \(bash\) runs nothing here/ },
    // Nor through a program that runs the one its arguments name, by any name it runs as; and env alone is no program the installer runs.
    { spec: { step: 'env', command: '/usr/bin/env', args: [], cwd: pmmcp }, why: NOT_LISTED },
    { spec: { step: 'ps', command: linkAs('/usr/bin/env', 'ps'), args: ['kill', '812'], cwd: pmmcp }, why: /env given an argument runs a program/ },
    { spec: { step: 'env', command: '/usr/bin/env', args: ['sh', '-c', 'true'], cwd: pmmcp }, why: /env given an argument runs a program/ },
    { spec: { step: 'env', command: 'env', args: ['-i', '/bin/sh', '-c', 'true'], cwd: pmmcp }, why: /env given an argument/ },
    { spec: { step: 'env', command: 'env', args: ['PATH=/tmp', 'sh', '-c', 'true'], cwd: pmmcp }, why: /env given an argument/ },
    { spec: { step: 'env', command: 'env', args: ['-S', 'sh -c true'], cwd: pmmcp }, why: /env given an argument/ },
    // One argument is enough: env halt runs the stop it finds on its PATH, env kill a signal.
    { spec: { step: 'env', command: 'env', args: ['halt'], cwd: bare }, why: /env given an argument runs a program/ },
    { spec: { step: 'env', command: '/usr/bin/env', args: ['kill'], cwd: bare }, why: /env given an argument runs a program/ },
    { spec: { step: 'nohup', command: 'nohup', args: ['/bin/sh', 'x.sh'], cwd: pmmcp }, why: /nohup runs a program its arguments name/ },
    { spec: { step: 'xargs', command: 'xargs', args: ['kill'], cwd: pmmcp }, why: /xargs runs a program/ },
    { spec: { step: 'sudo', command: 'sudo', args: ['launchctl', 'print', LABEL], cwd: pmmcp }, why: /sudo runs a program/ },
    { spec: { step: 'find', command: 'find', args: ['.', '-name', '*.pid', '-exec', 'kill', '{}', ';'], cwd: pmmcp }, why: /find -exec \(or -execdir, -ok, -okdir\) runs a program/ },
    // Nor through program text an interpreter is handed, by any name: the installer runs none of them.
    { spec: { step: 'perl', command: 'perl', args: ['-e', 'kill 15, 812'], cwd: pmmcp }, why: /perl runs program text its arguments carry/ },
    { spec: { step: 'awk', command: 'awk', args: ['BEGIN{system("kill -TERM 812")}'], cwd: pmmcp }, why: /awk runs program text/ },
    { spec: { step: 'osa', command: 'osascript', args: ['-e', 'do shell script "launchctl kickstart -k gui/501/com.aibot.pmmcp"'], cwd: pmmcp }, why: /osascript runs program text/ },
    { spec: { step: 'ls', command: join(linked, 'ls'), args: ['-e', 'kill 15, 812'], cwd: pmmcp }, why: /perl runs program text/ },
    { spec: { step: 'ps', command: join(linked, 'ps'), args: ['-c', 'import os; os.kill(812, 15)'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'pgrep', command: join(linked, 'pgrep'), args: ['/bin/sh', 'x.sh'], cwd: pmmcp }, why: /nohup runs a program/ },
    { spec: { step: 'lsof', command: join(linked, 'lsof'), args: ['.', '-exec', 'kill', '{}', ';'], cwd: pmmcp }, why: /find -exec/ },
    { spec: { step: 'git', command: join(linked, 'git'), args: ['-c', 'kill 812'], cwd: pmmcp }, why: /a shell \(bash\)/ },
    { spec: { step: 'mysh', command: mysh, args: ['-c', 'kill -TERM 812'], cwd: pmmcp }, why: NOT_LISTED },
    // Python runs only as the venv's, on pmmcp's own modules and scripts.
    { spec: { step: 'py', command: python, args: ['-c', 'import os, signal; os.kill(812, signal.SIGTERM)'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-B', '-c', 'import os'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-i'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: [], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-E', '-m', 'src.dashboard.auth', 'status'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-B', '-B', '-m', 'src.dashboard.auth', 'status'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-m', 'timeit', '-s', 'import os', 'os.kill(812, 15)'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-m'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-m', 'src'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['x.py'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/../x.py'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/x.sh'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: 'python3', args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: '/usr/bin/python3', args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: join(pmmcp, 'venv', 'bin', 'python'), args: ['scripts/pmmcp_facts.py'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: join(pmmcp, '.venv', 'python'), args: ['scripts/pmmcp_facts.py'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: 'python3.12', args: ['-c', 'pass'], cwd: pmmcp }, why: PYTHON },
    // Only the forms the installer runs, with nothing added: none of pmmcp's own CLIs that restart (rotate's --restart runs launchctl
    // kickstart -k), stop or unload (supervisor.py), mint a token into a log (http_auth new-token), restore or roll back.
    { spec: { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', 'aos-kernel', '--restart'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', 'aos-kernel', '--create', '--digest-stdin', '--restart'], cwd: pmmcp, digest: DIGEST }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', 'antigravity', '--print-token', '--restart'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', '--restart', '--create', '--digest-stdin'], cwd: pmmcp, digest: DIGEST }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', 'AOS-KERNEL', '--create', '--digest-stdin'], cwd: pmmcp, digest: DIGEST }, why: PYTHON },
    ...[['stop'], ['restart'], ['uninstall'], ['start']].map((sub) => ({ spec: { step: 'py', command: python, args: ['scripts/supervisor.py', ...sub], cwd: pmmcp }, why: PYTHON })),
    { spec: { step: 'py', command: python, args: ['-m', 'src.transport.http_auth', 'new-token', 'aos-kernel'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-B', '-m', 'src.transport.http_auth', 'check', '--expect', '--print'], cwd: pmmcp, digest: DIGEST }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-m', 'src.transport.http_auth', 'check', 'extra'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/restore_pmmcp_backup.py', 'x.zip', '--force'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'rollback'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'enable', '--force'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'status'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-m', 'src.dashboard.auth', 'init', '--only', 'all'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['-m', 'src.dashboard.auth', 'init', '--force'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/pmmcp_facts.py', '--json', '-B'], cwd: pmmcp }, why: PYTHON },
    { spec: { step: 'py', command: python, args: ['scripts/pmmcp_facts.py'], cwd: pmmcp }, why: PYTHON },
    // A digest goes to the two forms that read one, and each of them gets one.
    { spec: { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', 'aos-kernel', '--create', '--digest-stdin'], cwd: pmmcp }, why: /this python form reads its digest on stdin, and none was given/ },
    { spec: { step: 'py', command: python, args: ['-B', '-m', 'src.transport.http_auth', 'check', '--expect', 'aos-kernel'], cwd: pmmcp }, why: /this python form reads its digest on stdin, and none was given/ },
    { spec: { step: 'py', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp, digest: DIGEST }, why: /this python form takes no stdin, and a digest was given/ },
    { spec: { step: 'py', command: python, args: ['-B', '-m', 'src.transport.http_auth', 'check'], cwd: pmmcp, digest: DIGEST }, why: /this python form takes no stdin/ },
    // Every name a command runs as is on the allowlist: an allowlisted name linked to a program on no list runs nothing (tar runs a
    // command at a checkpoint, flock and make run one), and one linked to another on the list is held to both rules.
    { spec: { step: 'ls', command: linkAs(join(bin, 'tar'), 'ls'), args: ['--checkpoint=1', '--checkpoint-action=exec=kill -TERM 812', '-cf', '/dev/null', '/etc/hostname'], cwd: pmmcp }, why: /"ls" resolves to "tar", which is not a program the installer runs: only ps, pgrep/ },
    { spec: { step: 'pgrep', command: linkAs(join(bin, 'flock'), 'pgrep'), args: ['/tmp/lock', 'kill', '-TERM', '812'], cwd: pmmcp }, why: /"pgrep" resolves to "flock", which is not a program the installer runs/ },
    { spec: { step: 'ps', command: linkAs(join(bin, 'make'), 'ps'), args: ['-f', 'x'], cwd: pmmcp }, why: /"ps" resolves to "make", which is not a program the installer runs/ },
    { spec: { step: 'ls', command: 'ls', args: ['--checkpoint=1', '--checkpoint-action=exec=kill -TERM 812', '-cf', '/dev/null', '/etc/hostname'], cwd: pmmcp }, env: { HOME: tarHome }, why: /"ls" resolves to "tar"/ },
    { spec: { step: 'git', command: linkAs(join(bin, 'docker'), 'git'), args: ['status'], cwd: pmmcp }, why: DOCKER },
    // A command or working directory with a . or .. component: after a link the kernel takes .. from where the link leads (dots/a/link/.. is dots/b).
    { spec: { step: 'ps', command: `${dots}/a/link/../ps`, args: ['-TERM', '812'], cwd: pmmcp }, why: DOTTED('the command') },
    { spec: { step: 'ls', command: `${dots}/a/link/../ls`, args: ['-c', 'kill -TERM 812'], cwd: pmmcp }, why: DOTTED('the command') },
    { spec: { step: 'ps', command: `${dots}/b/./ps`, args: ['-TERM', '812'], cwd: pmmcp }, why: DOTTED('the command') },
    { spec: { step: 'stop', command: `${pmmcp}/./${STOP_SCRIPT}`, args: [], cwd: pmmcp }, why: DOTTED('the command') },
    { spec: { step: 'ls', command: 'ls', args: ['-l'], cwd: `${dots}/a/link/..` }, why: DOTTED('the working directory') },
    { spec: { step: 'ls', command: 'ls', args: ['-l'], cwd: `${pmmcp}/.` }, why: DOTTED('the working directory') },
    // A link whose target is so spelled is resolved as the kernel resolves it: x/ps is b/ps, which is kill, not the a/ps its spelling names.
    { spec: { step: 'ps', command: join(dots, 'x', 'ps'), args: ['-TERM', '812'], cwd: pmmcp }, why: /kill signals the processes it names/ },
    // A command whose text names a script, wherever it is, and an argument with a script's name anywhere in it, in any case.
    { spec: { step: 'ls', command: join(nowhere, `${STOP_SCRIPT}.d`, 'ls'), args: ['-l'], cwd: pmmcp }, why: NOT_THE_COMMAND },
    { spec: { step: 'pgrep', command: 'pgrep', args: ['-f', `bash .*${STOP_SCRIPT}`], cwd: pmmcp }, why: NOT_THE_COMMAND },
    { spec: { step: 'pgrep', command: 'pgrep', args: ['-f', 'START-PMMCP-SERVER.SH --check'], cwd: pmmcp }, why: NOT_THE_COMMAND },
    // An argument that is a link to a path named as a script, even one that is no file to compare (a folder): known by the name it resolves to.
    { spec: { step: 'ls', command: 'ls', args: ['-l', 'peek'], cwd: peeks }, why: NOT_THE_COMMAND },
    // A link to itself as the command is no program, and nothing loops on it.
    { spec: { step: 'loop', command: loop, args: [], cwd: bare }, why: /"loop" is not a program the installer runs/ },
    // docker only reads: pmmcp-qdrant is stopped and started by pmmcp alone.
    ...[['kill', 'pmmcp-qdrant'], ['stop', 'pmmcp-qdrant'], ['restart', 'pmmcp-qdrant'], ['rm', '-f', 'pmmcp-qdrant'], ['compose', 'down'], ['container', 'stop', 'pmmcp-qdrant'], ['context', 'use', 'colima-hostile'], ['context', 'show', 'x'], ['--context', 'colima-hostile', 'ps'], ['-H', 'unix:///x.sock', 'info'], ['exec', 'pmmcp-qdrant', 'kill', '1'], ['PS'], []].map(
      (args) => ({ spec: { step: 'docker', command: 'docker', args, cwd: pmmcp }, why: DOCKER }),
    ),
    // git: no option before the command but --no-optional-locks, the read-only commands, and merge, reset and clone in one form each.
    { spec: { step: 'git', command: 'git', args: ['-c', 'alias.x=!kill -TERM 812', 'x'], cwd: pmmcp }, why: GIT_GLOBAL },
    { spec: { step: 'git', command: 'git', args: ['--config-env=core.pager=X', 'status'], cwd: pmmcp }, why: GIT_GLOBAL },
    { spec: { step: 'git', command: 'git', args: ['-C', '/tmp', 'status'], cwd: pmmcp }, why: GIT_GLOBAL },
    { spec: { step: 'git', command: 'git', args: ['--exec-path=/tmp', 'status'], cwd: pmmcp }, why: GIT_GLOBAL },
    { spec: { step: 'git', command: 'git', args: ['--no-optional-locks', '-c', 'core.fsmonitor=kill', 'status'], cwd: pmmcp }, why: GIT_GLOBAL },
    { spec: { step: 'git', command: 'git', args: [], cwd: pmmcp }, why: GIT_GLOBAL },
    { spec: { step: 'git', command: 'git', args: ['x'], cwd: pmmcp }, why: /git x is not a command run here: only status, diff, rev-parse, merge-base, merge --ff-only, reset --keep and clone/ },
    { spec: { step: 'git', command: 'git', args: ['push', 'origin', 'main'], cwd: pmmcp }, why: /git push is not a command run here/ },
    { spec: { step: 'git', command: 'git', args: ['config', 'core.fsmonitor', 'kill'], cwd: pmmcp }, why: /git config is not a command run here/ },
    { spec: { step: 'git', command: 'git', args: ['merge', 'origin/main'], cwd: pmmcp }, why: /git merge is run here only as merge --ff-only <commit>/ },
    { spec: { step: 'git', command: 'git', args: ['merge', '--ff-only', '-s', 'x', 'origin/main'], cwd: pmmcp }, why: /git merge is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['merge', '--ff-only', '--strategy=x'], cwd: pmmcp }, why: /git merge is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['reset', '--hard', 'HEAD'], cwd: pmmcp }, why: /git reset is run here only as reset --keep <commit>/ },
    { spec: { step: 'git', command: 'git', args: ['reset', '--keep', '--hard'], cwd: pmmcp }, why: /git reset is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['clone', '--upload-pack=kill', 'https://github.com/x/y.git', join(home, 'y')], cwd: home }, why: /git clone is run here only as clone https:\/\/\.\.\. <absolute folder>, with no option/ },
    { spec: { step: 'git', command: 'git', args: ['clone', '-u', 'kill', 'https://github.com/x/y.git', join(home, 'y')], cwd: home }, why: /git clone is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['clone', 'https://github.com/x/y.git', '-c', 'core.sshCommand=kill'], cwd: home }, why: /git clone is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['clone', 'ext::sh -c kill% 812', join(home, 'y')], cwd: home }, why: /git clone is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['clone', 'http://github.com/x/y.git', join(home, 'y')], cwd: home }, why: /git clone is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['clone', 'https://github.com/x/y.git', 'y'], cwd: home }, why: /git clone is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['clone', 'https://github.com/x/y.git'], cwd: home }, why: /git clone is run here only/ },
    { spec: { step: 'git', command: 'git', args: ['diff', '--output=/tmp/x', 'HEAD'], cwd: pmmcp }, why: /git diff is given here only --quiet, --exit-code, --name-only, --no-ext-diff, --no-textconv and --: never --output/ },
    { spec: { step: 'git', command: 'git', args: ['diff', '--ext-diff', 'HEAD'], cwd: pmmcp }, why: /git diff is given here only/ },
    { spec: { step: 'git', command: 'git', args: ['--no-optional-locks', 'diff', '--outp=/tmp/x', 'HEAD', '--', 'uv.lock'], cwd: pmmcp }, why: /git diff is given here only/ },
    // plutil reads: any other form writes the plist in place.
    { spec: { step: 'plutil', command: 'plutil', args: ['-replace', 'ProgramArguments', '-json', '[]', 'x.plist'], cwd: pmmcp }, why: PLUTIL },
    { spec: { step: 'plutil', command: 'plutil', args: ['-convert', 'xml1', 'x.plist'], cwd: pmmcp }, why: PLUTIL },
    { spec: { step: 'plutil', command: 'plutil', args: ['-extract', 'Label', 'raw', 'x.plist'], cwd: pmmcp }, why: PLUTIL },
    { spec: { step: 'plutil', command: 'plutil', args: ['-extract', 'Label', 'raw', '-o', 'out.plist', 'x.plist'], cwd: pmmcp }, why: PLUTIL },
    { spec: { step: 'plutil', command: 'plutil', args: ['-extract', 'Label', 'raw', '-o', '-', 'x.plist', 'y.plist'], cwd: pmmcp }, why: PLUTIL },
    // setup.sh: by absolute path, --non-interactive alone.
    { spec: { step: 'setup', command: join(pmmcp, 'setup.sh'), args: [], cwd: pmmcp }, why: /setup\.sh is run here only by absolute path, with --non-interactive alone/ },
    { spec: { step: 'setup', command: join(pmmcp, 'setup.sh'), args: ['--non-interactive', '--force'], cwd: pmmcp }, why: /setup\.sh is run here only/ },
    { spec: { step: 'setup', command: 'setup.sh', args: ['--non-interactive'], cwd: pmmcp }, why: /setup\.sh is run here only/ },
    // Anything else is no program the installer runs.
    ...['cat', 'mkfifo', 'curl', 'open', 'make', 'npm', 'rm', 'uv', 'brew', 'colima'].map((command) => ({ spec: { step: 'other', command, args: ['x'], cwd: pmmcp }, why: NOT_LISTED })),
    { spec: { step: 'find', command: 'find', args: ['.', '-name', '*.pid'], cwd: pmmcp }, why: NOT_LISTED },
    { spec: { step: 'other', command: join(pmmcp, 'other.sh'), args: [], cwd: pmmcp }, why: /"other\.sh" is not a program the installer runs/ },
    // The stop and start themselves: never --force, a timeout or a kill signal.
    { spec: { step: 'stop', command: STOP, args: ['--force'], cwd: pmmcp }, why: /stop-pmmcp-server\.sh is run here only with no argument, --jobs alone/ },
    { spec: { step: 'stop', command: STOP, args: ['-f'], cwd: pmmcp }, why: /stop-pmmcp-server\.sh is run here only with/ },
    { spec: { step: 'start', command: START, args: ['--force'], cwd: pmmcp }, why: /start-pmmcp-server\.sh is run here only with no argument or --check/ },
    { spec: { step: 'stop', command: STOP, args: [], cwd: pmmcp, timeoutMs: 600_000 }, why: /stop-pmmcp-server\.sh is given no timeout/ },
    { spec: { step: 'start', command: START, args: [], cwd: pmmcp, timeoutMs: 60_000 }, why: /start-pmmcp-server\.sh is given no timeout/ },
    // A field no spec has (a cast, or a caller in plain JavaScript) is refused, never dropped on the way to spawn.
    { spec: { step: 'stop', command: STOP, args: [], cwd: pmmcp, killSignal: 'SIGKILL' } as RunSpec, why: /a spec carries only step, command, args, cwd, digest, timeoutMs, ownSession, never "killSignal"/ },
    { spec: { step: 'start', command: START, args: [], cwd: pmmcp, timeout: 5000 } as RunSpec, why: /never "timeout"/ },
    { spec: { step: 'facts', command: 'docker', args: ['info'], cwd: pmmcp, shell: true, signal: 'x' } as RunSpec, why: /never "shell", "signal"/ },
    // A NUL no program can be handed: refused here, before Node's spawn would throw over it.
    { spec: { step: 'git', command: 'git', args: ['merge', 'a\u0000b'], cwd: pmmcp, ownSession: true }, why: /argument 2 holds a NUL byte/ },
    { spec: { step: 'git', command: '/usr/bin/git\u0000x', args: [], cwd: pmmcp }, why: /the command holds a NUL byte/ },
    { spec: { step: 'git', command: 'git', args: ['status'], cwd: `${pmmcp}\u0000` }, why: /the working directory holds a NUL byte/ },
    { spec: { step: 'git', command: 'git', args: ['status'], cwd: pmmcp }, env: { LANG: 'en_US\u0000.UTF-8' }, why: /the environment's LANG holds a NUL byte/ },
  ]
  // Every shell, every program that runs the one its arguments name, every find action that runs one, and every interpreter, each by its own
  // name alone: a path where nothing is, so no link on this machine (nawk to mawk, sh to dash) adds a name of its own.
  for (const shell of ['sh', 'bash', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'csh', 'tcsh', 'fish']) {
    cases.push({ spec: { step: 'sh', command: join(nowhere, shell), args: ['-c', 'kill -TERM 812'], cwd: pmmcp }, why: new RegExp(`a shell \\(${shell}\\) runs nothing here, whatever it is given`) })
    cases.push({ spec: { step: 'sh', command: join(nowhere, shell), args: [script], cwd: pmmcp }, why: new RegExp(`a shell \\(${shell}\\) runs nothing here, whatever it is given`) })
  }
  for (const launcher of ['nohup', 'xargs', 'nice', 'sudo', 'doas', 'su', 'setsid', 'caffeinate', 'arch', 'stdbuf', 'time', 'exec', 'command', 'chroot', 'script', 'watch']) {
    cases.push({ spec: { step: 'launcher', command: join(nowhere, launcher), args: ['kill', '-TERM', '812'], cwd: pmmcp }, why: new RegExp(`^launcher: ${launcher} runs a program its arguments name`) })
  }
  for (const action of ['-exec', '-execdir', '-ok', '-okdir', '-EXEC', '-OkDir']) {
    cases.push({ spec: { step: 'find', command: join(nowhere, 'find'), args: ['.', '-name', '*.pid', action, 'kill', '{}', ';'], cwd: pmmcp }, why: /find -exec \(or -execdir, -ok, -okdir\) runs a program/ })
  }
  for (const interpreter of ['perl', 'ruby', 'node', 'nodejs', 'deno', 'bun', 'osascript', 'awk', 'gawk', 'mawk', 'nawk', 'tclsh', 'wish', 'expect', 'php', 'lua', 'swift']) {
    cases.push({ spec: { step: 'interp', command: join(nowhere, interpreter), args: ['-e', 'kill 15, 812'], cwd: pmmcp }, why: new RegExp(`^interp: ${interpreter} runs program text its arguments carry`) })
  }
  for (const c of cases) {
    const root = repo(t)
    const fake = recorder()
    const runner = new Runner({ repoRoot: root, env: { ...installerEnv(home), ...c.env }, spawn: fake.spawn, now: () => NOW })
    const what = JSON.stringify([c.spec.command, ...c.spec.args])
    assert.throws(
      () => runner.start(c.spec),
      (e: unknown) => {
        assert.ok(refusedCode(e), `${what}: ${String(e)}`)
        assert.match(e instanceof Error ? e.message : '', c.why, what)
        assert.match(e instanceof Error ? e.message : '', /nothing was run/, what)
        return true
      },
      what,
    )
    assert.equal(fake.calls.length, 0, `${what}: something was spawned`)
    assert.equal(existsSync(join(root, '.aos')), false, `${what}: something was created`)
  }

  // What the installer runs, each form it runs, is still run.
  const plist = join(home, 'Library', 'LaunchAgents', 'com.aibot.pmmcp.plist')
  const allowed: RunSpec[] = [
    { step: 'print', command: 'launchctl', args: ['print', LABEL], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'list', command: '/bin/launchctl', args: ['list', 'com.aibot.pmmcp'], cwd: pmmcp, timeoutMs: 5000 },
    // A print of a target named kickstart only reads.
    { step: 'print', command: 'launchctl', args: ['print', 'kickstart'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'pgrep-tui', command: 'pgrep', args: ['-f', 'scripts/monitor_tui\\.py'], cwd: pmmcp, timeoutMs: 5000 },
    // A link to itself as an argument is a name that resolves to nothing.
    { step: 'ls', command: 'ls', args: ['-l', loop], cwd: bare, timeoutMs: 5000 },
    // A link whose name is the program's own (Homebrew's docker and git are), and a venv's python linked to the interpreter uv made it from.
    { step: 'docker', command: linkAs(join(bin, 'docker'), 'docker'), args: ['info', '--format', '{{.ServerVersion}}'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'py', command: join(venvBin, 'python'), args: ['-B', 'scripts/qdrant_api_key.py', 'status', '--json'], cwd: dirname(dirname(venvBin)), timeoutMs: 5000 },
    { step: 'ps', command: 'ps', args: ['-o', 'etime=', '-p', '812'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'ps', command: 'PS', args: ['-ww', '-o', 'uid=,args=', '-p', '812'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'lsof', command: 'lsof', args: ['-nP', '-iTCP:8766', '-sTCP:LISTEN', '-Fpu'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'ls', command: 'ls', args: ['-lde', join(home, 'notes.txt')], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'plutil', command: 'plutil', args: ['-extract', 'Label', 'raw', '-o', '-', plist], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'docker', command: 'docker', args: ['context', 'show'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'docker', command: 'docker', args: ['info', '--format', '{{.ServerVersion}}'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'docker', command: 'docker', args: ['ps', '--all', '--filter', 'name=pmmcp-qdrant', '--format', '{{.Names}} {{.State}}'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'git', command: 'git', args: ['--no-optional-locks', 'status', '--porcelain'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'git', command: 'git', args: ['--no-optional-locks', 'rev-parse', '--verify', '-q', 'refs/remotes/origin/main^{commit}'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'git', command: 'git', args: ['--no-optional-locks', 'merge-base', '--is-ancestor', 'HEAD', 'a'.repeat(40)], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'git', command: 'git', args: ['--no-optional-locks', 'diff', '--quiet', 'HEAD', 'a'.repeat(40), '--', 'uv.lock', 'pyproject.toml'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'git', command: '/usr/bin/git', args: ['merge', '--ff-only', 'a'.repeat(40)], cwd: pmmcp, ownSession: true },
    { step: 'git', command: 'git', args: ['reset', '--keep', 'b'.repeat(40)], cwd: pmmcp, ownSession: true },
    { step: 'git', command: 'git', args: ['clone', 'https://github.com/AiBot-Tools/persistent-memory-mcp.git', join(home, 'Github', 'Persistent-Memory-MCP')], cwd: home },
    // Every python form the installer runs (apply.ts, discover.ts), each as it is run there.
    { step: 'py', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'py', command: python, args: ['-B', 'scripts/qdrant_api_key.py', 'status', '--json'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'cleanup'], cwd: pmmcp },
    { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'init'], cwd: pmmcp, ownSession: true },
    { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'enable', '--dry-run'], cwd: pmmcp, ownSession: true },
    { step: 'py', command: python, args: ['scripts/qdrant_api_key.py', 'enable'], cwd: pmmcp, ownSession: true },
    { step: 'py', command: python, args: ['-B', '-m', 'src.transport.http_auth', 'check', '--expect', 'aos-kernel'], cwd: pmmcp, digest: DIGEST, timeoutMs: 5000 },
    { step: 'py', command: python, args: ['-B', '-m', 'src.transport.http_auth', 'check'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'py', command: python, args: ['-m', 'src.dashboard.auth', 'init'], cwd: pmmcp, ownSession: true },
    { step: 'py', command: python, args: ['-m', 'src.dashboard.auth', 'init', '--only', 'dashboard'], cwd: pmmcp, ownSession: true },
    { step: 'py', command: python, args: ['-m', 'src.dashboard.auth', 'init', '--only', 'curator'], cwd: pmmcp, ownSession: true },
    { step: 'py', command: python, args: ['-B', '-m', 'src.dashboard.auth', 'status', '--json'], cwd: pmmcp, timeoutMs: 5000 },
    { step: 'py', command: join(pmmcp, '.venv', 'bin', 'python3'), args: ['scripts/rotate_http_auth_token.py', 'aos-kernel', '--create', '--digest-stdin'], cwd: pmmcp, digest: DIGEST },
    { step: 'py', command: python, args: ['scripts/rotate_http_auth_token.py', 'aos-kernel', '--create', '--digest-stdin'], cwd: pmmcp, digest: DIGEST, ownSession: true },
    { step: 'setup', command: join(pmmcp, 'setup.sh'), args: ['--non-interactive'], cwd: pmmcp, ownSession: true },
  ]
  const fake = recorder((c) => setImmediate(() => c.child.emit('exit', 0, null)))
  const runner = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  for (const spec of allowed) {
    assert.doesNotThrow(() => runner.start(spec), JSON.stringify(spec))
    // Each to its end, so a step in its own session does not hold the next one up.
    fake.calls.at(-1)?.child.emit('exit', 0, null)
  }
  assert.equal(fake.calls.length, allowed.length)
})

test('the stop and start scripts are known by identity: a hard link of another name or a renamed copy runs by their rules, and is refused anywhere else', async (t) => {
  const home = tmpdir(t)
  const pmmcp = checkout(t, { [STOP_SCRIPT]: `#!/bin/sh\n${GROUP_CHECK}\n`, [START_SCRIPT]: '#!/bin/sh\necho started\n' })
  const STOP = join(pmmcp, STOP_SCRIPT)
  const START = join(pmmcp, START_SCRIPT)
  // In the checkout: a hard link of another name, a renamed copy, and the start's hard link.
  const HALT = join(pmmcp, 'halt')
  linkSync(STOP, HALT)
  const COPY = join(pmmcp, 'halt-copy.sh')
  copyFileSync(STOP, COPY)
  chmodSync(COPY, 0o755)
  const GO = join(pmmcp, 'go')
  linkSync(START, GO)
  // Outside it: the same, run from the checkout's folder, where the installer runs pmmcp's commands.
  const away = tmpdir(t)
  const FAR_LINK = join(away, 'halt')
  linkSync(STOP, FAR_LINK)
  const FAR_COPY = join(away, 'copy.sh')
  copyFileSync(STOP, FAR_COPY)
  chmodSync(FAR_COPY, 0o755)
  // A file of the stop's size with other bytes is not the stop.
  const SAME_SIZE = join(pmmcp, 'same-size.sh')
  const body = readFileSync(STOP, 'utf8')
  writeFileSync(SAME_SIZE, body.replace('own group', 'OWN GROUP'))
  chmodSync(SAME_SIZE, 0o755)
  assert.equal(statSync(SAME_SIZE).size, statSync(STOP).size)

  const ONLY = /stop-pmmcp-server\.sh is run here only with no argument, --jobs alone/
  // Links of other names away from the checkout: to the hard link in it, to the renamed copy in it.
  const hops = tmpdir(t)
  const HOP = join(hops, 'hop')
  symlinkSync(HALT, HOP)
  const HOP_COPY = join(hops, 'hop-copy')
  symlinkSync(COPY, HOP_COPY)
  // A working directory that holds no script, so only the command names the install.
  const neither = tmpdir(t)
  // A link in it to a folder inside the checkout: into/../halt is the checkout's halt to the kernel (and to a shell), and neither/halt spelled.
  mkdirSync(join(pmmcp, 'inner'))
  symlinkSync(join(pmmcp, 'inner'), join(neither, 'into'))
  for (const [command, cwd] of [
    [HALT, pmmcp],
    [COPY, pmmcp],
    [FAR_LINK, pmmcp],
    [FAR_COPY, pmmcp],
    // Only the command's own folder holds the install.
    [HALT, neither],
    [COPY, neither],
    // Only the folder the command resolves to holds it: a link elsewhere to the hard link, or to the copy.
    [HOP, neither],
    [HOP_COPY, neither],
  ] as const) {
    // A runner of its own each time, which has run nothing from the checkout: what it knows comes from this spec alone.
    const fake = recorder()
    const runner = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
    const what = `${basename(command)} in ${dirname(command) === pmmcp ? 'the checkout' : 'another folder'}, run from ${cwd === pmmcp ? 'the checkout' : 'elsewhere'}`
    for (const [extra, why] of [
      [{ args: ['--force'] }, ONLY],
      [{ args: ['-f'] }, ONLY],
      [{ args: ['--wait-timeout', '0'] }, ONLY],
      [{ args: [], timeoutMs: 5000 }, /stop-pmmcp-server\.sh is given no timeout/],
      [{ args: ['--jobs'], digest: `sha256:${'a'.repeat(64)}` }, /stop-pmmcp-server\.sh takes no stdin/],
    ] as const) {
      assert.throws(() => runner.start({ step: 'stop', command, cwd, ...extra }), (e: unknown) => refusedCode(e) && e instanceof Error && why.test(e.message), `${what} ${JSON.stringify(extra)}`)
    }
    // Given what the stop may be given, it runs as the stop does: detached, stdin /dev/null, recorded in active.json.
    const running = runner.start({ step: 'stop', command, args: [], cwd })
    const c = fake.calls.at(-1)
    assert.ok(c && c.command === command, what)
    assert.equal(c.options.detached, true, what)
    assert.equal(c.options.stdio[0], 'ignore', what)
    assert.equal(readActive(runner.repoRoot).state, 'recorded', what)
    c.child.emit('exit', 0, null)
    await running.done
  }
  // The rest on one runner that has run nothing yet.
  const fake = recorder()
  const runner = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  assert.throws(() => runner.start({ step: 'start', command: GO, args: ['--tail'], cwd: pmmcp }), (e: unknown) => refusedCode(e) && /start-pmmcp-server\.sh is run here only with no argument or --check/.test(String(e)))
  // A link of either found on the child's PATH by a bare name: the scripts run only by absolute path.
  mkdirSync(join(home, '.local', 'bin'), { recursive: true })
  linkSync(STOP, join(home, '.local', 'bin', 'halt'))
  assert.throws(() => runner.start({ step: 'stop', command: 'halt', args: [], cwd: pmmcp }), (e: unknown) => refusedCode(e) && /stop-pmmcp-server\.sh runs only by absolute path/.test(String(e)))
  // As another program's argument: refused (a shell runs nothing here, so no copy is ever run as one's script).
  const NOT_THE_COMMAND = /the stop and start scripts run only as the command itself/
  for (const spec of [
    { step: 'ls', command: 'ls', args: ['-l', 'halt'], cwd: pmmcp },
    { step: 'ls', command: 'ls', args: ['-l', './go'], cwd: pmmcp },
    { step: 'cat', command: '/bin/cat', args: ['halt'], cwd: pmmcp },
    { step: 'git', command: 'git', args: ['diff', '--no-index', FAR_LINK, '/dev/null'], cwd: pmmcp },
    // Only an argument's folder holds the install, and not the first argument's: every argument that is a file is looked beside.
    { step: 'ls', command: 'ls', args: ['-lde', HALT], cwd: neither },
    // A link to the hard link, whose own folder holds none: the folder it resolves to does.
    { step: 'ls', command: 'ls', args: ['-l', 'hop'], cwd: hops },
    // The file a child opens, `..` taken from where the link leads (the checkout), not from its spelling (neither/halt, which is not there).
    { step: 'ls', command: 'ls', args: ['-l', 'into/../halt'], cwd: neither },
    { step: 'ls', command: 'ls', args: ['-l', `${neither}/into/../halt`], cwd: away },
  ]) {
    assert.throws(() => runner.start(spec), (e: unknown) => refusedCode(e) && NOT_THE_COMMAND.test(String(e)), JSON.stringify(spec.args))
  }
  assert.equal(fake.calls.length, 0)
  // A renamed copy as an argument is a file like any other: nothing given one runs it.
  const listed = runner.start({ step: 'ls', command: 'ls', args: ['-l', COPY, FAR_COPY], cwd: neither })
  assert.equal(fake.calls.at(-1)?.options.detached, false)
  fake.calls.at(-1)?.child.emit('exit', 0, null)
  await listed.done

  // A command taken for both scripts is neither: a hard link of the start named as the stop (or the reverse), found in either order,
  // a link of the stop's name to the start, and a copy of a stop and start that are byte for byte the same.
  const BOTH = /the command is taken for both the stop and the start script/
  const swapped = tmpdir(t)
  linkSync(START, join(swapped, STOP_SCRIPT))
  linkSync(STOP, join(swapped, START_SCRIPT))
  const relinked = tmpdir(t)
  symlinkSync(START, join(relinked, STOP_SCRIPT))
  // A link of the stop's name to the start's hard link of another name: the folder the link is in is looked in before the checkout.
  const viaGo = tmpdir(t)
  symlinkSync(GO, join(viaGo, STOP_SCRIPT))
  const twins = checkout(t, { [STOP_SCRIPT]: '#!/bin/sh\necho twin\n', [START_SCRIPT]: '#!/bin/sh\necho twin\n' })
  const TWIN = join(twins, 'twin.sh')
  copyFileSync(join(twins, STOP_SCRIPT), TWIN)
  chmodSync(TWIN, 0o755)
  for (const [command, cwd, args] of [
    [join(swapped, STOP_SCRIPT), pmmcp, ['--quiet', '--wait-timeout', '300']],
    [join(swapped, START_SCRIPT), pmmcp, []],
    [join(relinked, STOP_SCRIPT), relinked, ['--jobs']],
    [join(viaGo, STOP_SCRIPT), neither, ['--quiet', '--wait-timeout', '300']],
    [TWIN, twins, []],
  ] as const) {
    const quiet = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
    assert.throws(() => quiet.start({ step: 'stop', command, args, cwd }), (e: unknown) => refusedCode(e) && BOTH.test(String(e)), `${command} from ${cwd}`)
  }
  assert.equal(fake.calls.length, 1)
  // A copy is the script whoever owns it (only root can give one away here).
  if (process.geteuid?.() === 0) {
    const theirs = join(away, 'theirs.sh')
    copyFileSync(STOP, theirs)
    chmodSync(theirs, 0o755)
    chownSync(theirs, 65534, 65534)
    assert.throws(() => runner.start({ step: 'stop', command: theirs, args: ['--force'], cwd: pmmcp }), (e: unknown) => refusedCode(e) && ONLY.test(String(e)))
  }
  // The same size with other bytes is not the stop: as the command it is an ordinary file, no program the installer runs.
  assert.throws(() => runner.start({ step: 'same-size', command: SAME_SIZE, args: ['--force'], cwd: pmmcp }), (e: unknown) => refusedCode(e) && /"same-size\.sh" is not a program the installer runs/.test(String(e)))

  // Away from the checkout, a link is known once the runner has run a script from the install, and from the start at ~/Github/Persistent-Memory-MCP.
  const fresh = recorder((c) => setImmediate(() => c.child.emit('exit', 0, null)))
  const first = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: fresh.spawn, now: () => NOW })
  await first.run({ step: 'not-yet', command: 'ls', args: ['-l', FAR_LINK], cwd: away })
  assert.equal(fresh.calls.length, 1, 'known before the runner could know it')
  // As the command, unknown, it is no program the installer runs.
  assert.throws(() => first.start({ step: 'not-yet', command: FAR_LINK, args: ['--force'], cwd: away }), (e: unknown) => refusedCode(e) && /"halt" is not a program the installer runs/.test(String(e)))
  await first.run({ step: 'stop', command: STOP, args: [], cwd: pmmcp })
  for (const command of [FAR_LINK, FAR_COPY]) {
    assert.throws(() => first.start({ step: 'stop', command, args: ['--force'], cwd: away }), (e: unknown) => refusedCode(e) && ONLY.test(String(e)), command)
  }
  assert.throws(() => first.start({ step: 'ls', command: 'ls', args: ['-l', 'halt'], cwd: away }), (e: unknown) => refusedCode(e) && NOT_THE_COMMAND.test(String(e)))
  const opHome = tmpdir(t)
  const installed = join(opHome, 'Github', 'Persistent-Memory-MCP')
  mkdirSync(installed, { recursive: true })
  writeFileSync(join(installed, STOP_SCRIPT), `#!/bin/sh\n${GROUP_CHECK}\necho installed\n`)
  chmodSync(join(installed, STOP_SCRIPT), 0o755)
  const elsewhere = tmpdir(t)
  linkSync(join(installed, STOP_SCRIPT), join(elsewhere, 'halt'))
  const atDefault = new Runner({ repoRoot: repo(t), env: installerEnv(opHome), spawn: recorder().spawn, now: () => NOW })
  assert.throws(() => atDefault.start({ step: 'stop', command: join(elsewhere, 'halt'), args: ['--force'], cwd: elsewhere }), (e: unknown) => refusedCode(e) && ONLY.test(String(e)))

  // What a run teaches the runner is the install it ran from, wherever the command was: a third folder's copy is then known.
  const third = tmpdir(t)
  const THIRD_COPY = join(third, 'third.sh')
  copyFileSync(STOP, THIRD_COPY)
  linkSync(STOP, join(third, 'third-link'))
  const learn = async (command: string, cwd: string): Promise<Runner> => {
    const taughtSpawn = recorder((c) => setImmediate(() => c.child.emit('exit', 0, null)))
    const taught = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: taughtSpawn.spawn, now: () => NOW })
    // Before: the copy is an ordinary file, as the command no program the installer runs, and the hard link a file ls may list.
    assert.throws(() => taught.start({ step: 'third', command: THIRD_COPY, args: ['--force'], cwd: third }), (e: unknown) => refusedCode(e) && /is not a program the installer runs/.test(String(e)))
    await taught.run({ step: 'ls', command: 'ls', args: ['-l', 'third-link'], cwd: third })
    assert.equal(taughtSpawn.calls.length, 1)
    await taught.run({ step: 'stop', command, args: [], cwd })
    return taught
  }
  // A hard link away from the checkout, known by the checkout's working directory: the checkout is learned, not the link's folder.
  const byLink = await learn(FAR_LINK, pmmcp)
  // A link of the script's own name away from it, run from elsewhere: the folder it resolves to is learned.
  const named = join(tmpdir(t), STOP_SCRIPT)
  symlinkSync(STOP, named)
  const byName = await learn(named, neither)
  for (const taught of [byLink, byName]) {
    assert.throws(() => taught.start({ step: 'third', command: THIRD_COPY, args: ['--force'], cwd: third }), (e: unknown) => refusedCode(e) && ONLY.test(String(e)))
    assert.throws(() => taught.start({ step: 'ls', command: 'ls', args: ['-l', 'third-link'], cwd: third }), (e: unknown) => refusedCode(e) && NOT_THE_COMMAND.test(String(e)))
  }

  // A real one: the hard link runs as the stop does, in a process group of its own.
  const real = new Runner({ repoRoot: repo(t), env: installerEnv(home), now: () => NOW })
  const ran = await real.run({ step: 'stop', command: HALT, args: [], cwd: pmmcp })
  assert.equal(ran.code, 0)
  assert.equal(readOut(ran), 'own group\n')
  assert.equal(readActive(real.repoRoot).state, 'none')
})

/** A FIFO at `path`, made through the runner by a stand-in python (mkfifo is no program the installer runs); no test here imports child_process. */
async function mkfifo(t: TestContext, path: string): Promise<void> {
  const runner = new Runner({ repoRoot: repo(t), env: { HOME: tmpdir(t) }, now: () => NOW })
  const made = await runner.run({ step: 'mkfifo', ...pythonStandIn(t, `exec mkfifo ${shWord(path)}`), timeoutMs: 10_000 })
  assert.equal(made.code, 0, `mkfifo ${path} failed`)
}

/**
 * A process that, `seconds` from now, opens `fifo` at both ends: to write a
 * line and to read it. Whichever end this module might block on is then met,
 * so code that blocks shows as slow (and, without the regular-file check, as
 * a wrong answer) instead of a test that hangs; as the code is, the two ends
 * meet each other and the process exits on its own.
 */
function fifoPeer(t: TestContext, fifo: string, seconds = 3): Promise<RunResult> {
  const peer = pythonStandIn(t, `sleep ${String(seconds)}\ncat ${shWord(fifo)} >/dev/null &\nprintf 'late\\n' > ${shWord(fifo)}\nwait`)
  const runner = new Runner({ repoRoot: repo(t), env: { HOME: tmpdir(t) }, now: () => NOW })
  return runner.run({ step: 'peer', ...peer, timeoutMs: (seconds + 30) * 1000 })
}

test('a FIFO where active.json or a log should be blocks nothing: it reads as unreadable, an error or a hit at once', async (t) => {
  const TOKEN = randomBytes(32).toString('hex')
  t.after(() => SecretMask.clear())
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const python = join(pmmcp, '.venv', 'bin', 'python')
  const peers: Promise<RunResult>[] = []
  const atOnce = (since: number, what: string): void => {
    assert.ok(Date.now() - since < 1500, `${what} waited on the FIFO`)
  }

  // active.json: unreadable, so a stop or start is refused as busy, and nothing is spawned.
  const root = repo(t)
  mkdirSync(installDir(root), { recursive: true, mode: 0o700 })
  await mkfifo(t, activePath(root))
  peers.push(fifoPeer(t, activePath(root)))
  let since = Date.now()
  const active = readActive(root)
  atOnce(since, 'readActive')
  assert.deepEqual(active, { state: 'unreadable', reason: `${activePath(root)} cannot be read (not a regular file)` })
  const fake = recorder()
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  since = Date.now()
  assert.throws(() => runner.start({ step: 'stop', command: join(pmmcp, STOP_SCRIPT), args: [], cwd: pmmcp }), (e: unknown) => busyCode(e) && /not a regular file/.test(String(e)))
  atOnce(since, 'a stop')
  assert.equal(fake.calls.length, 0)

  // A step's .out left as a FIFO, with no value registered: the step ends, and its stdout is no answer; tail and discard say so too.
  const plain = recorder()
  const unscanned = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: plain.spawn, now: () => NOW })
  const probe = unscanned.start({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  const fifo = join(tmpdir(t), 'fifo')
  await mkfifo(t, fifo)
  unlinkSync(probe.out)
  renameSync(fifo, probe.out)
  peers.push(fifoPeer(t, probe.out))
  plain.calls[0]?.child.emit('exit', 0, null)
  const ended = await probe.done
  since = Date.now()
  assert.throws(() => readOut(ended), (e: unknown) => outputCode(e) && /facts: stdout cannot be read \(not a regular file\)/.test(String(e)))
  assert.throws(() => tail(ended.out), (e: unknown) => outputCode(e) && /cannot read .*facts\.out \(not a regular file\)/.test(String(e)))
  assert.equal(tail(ended.err).length, 0)
  assert.match(unscanned.discard(ended) ?? '', /could not empty .*facts\.out \(ENXIO\)/)
  atOnce(since, 'readOut, tail and discard')

  // The exit-time scan, with a value registered: a FIFO is a hit, reported as one that could not be emptied, and nothing more runs.
  SecretMask.register(TOKEN)
  const leaving = recorder()
  const scanned = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: leaving.spawn, now: () => NOW })
  const run = scanned.start({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
  const fifo2 = join(tmpdir(t), 'fifo')
  await mkfifo(t, fifo2)
  unlinkSync(run.out)
  renameSync(fifo2, run.out)
  peers.push(fifoPeer(t, run.out))
  since = Date.now()
  leaving.calls[0]?.child.emit('exit', 0, null)
  await assert.rejects(run.done, (e: unknown) => {
    assert.ok(e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK', String(e))
    assert.match(e.message, /facts\.out \(could not be emptied: ENXIO; delete it\)/)
    assert.doesNotMatch(e.message, /facts\.err/)
    return true
  })
  atOnce(since, 'the leak scan')
  assert.ok(scanned.halted !== undefined)

  // Another account's regular file is not the runner's either (only root can make one here).
  if (process.geteuid?.() === 0) {
    const NOBODY = 65534
    const theirs = repo(t)
    mkdirSync(installDir(theirs), { recursive: true, mode: 0o700 })
    writeFileSync(activePath(theirs), JSON.stringify({ step: 'stop', pid: 812, started: NOW.toISOString(), out: '/x/stop.out', err: '/x/stop.err' }), { mode: 0o600 })
    chownSync(activePath(theirs), NOBODY, NOBODY)
    assert.deepEqual(readActive(theirs), { state: 'unreadable', reason: `${activePath(theirs)} cannot be read (not this account's)` })
    const file = join(tmpdir(t), 'theirs.out')
    writeFileSync(file, 'running jobs: 0\n', { mode: 0o600 })
    chownSync(file, NOBODY, NOBODY)
    assert.throws(() => readOut({ step: 'jobs', out: file }), (e: unknown) => outputCode(e) && /not this account's/.test(String(e)))
    assert.throws(() => tail(file), (e: unknown) => outputCode(e) && /not this account's/.test(String(e)))
    const chowning = recorder((c) => {
      write(c.options.stdio[1], '{"facts": 1}\n')
      setImmediate(() => c.child.emit('exit', 0, null))
    })
    const handed = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: chowning.spawn, now: () => NOW })
    const given = handed.start({ step: 'facts', command: python, args: ['scripts/pmmcp_facts.py', '--json'], cwd: pmmcp })
    chownSync(given.out, NOBODY, NOBODY)
    await assert.rejects(given.done, (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_LEAK' && /facts\.out \(could not be emptied: not this account's/.test(e.message))
  }

  // Each peer met itself and ended.
  for (const peer of await Promise.all(peers)) assert.equal(peer.timedOut, false)
})

test("a step name that could leave the run's folder, or name no file, is refused before anything exists", async (t) => {
  const home = tmpdir(t)
  for (const step of ['../x', '../../x', 'a/b', '/abs', '.x', '..', 'X', 'Stop', '', ' ', 'a b', '-x', '_x', 'x'.repeat(49), 'a\u0000b', 'a\nb']) {
    const root = repo(t)
    const fake = recorder()
    const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
    assert.throws(() => runner.start({ step, command: 'lsof', args: ['-nP'], cwd: root }), (e: unknown) => refusedCode(e) && /a step is named \[a-z0-9\]\[a-z0-9\._-\]\*, at most 48 characters/.test(String(e)), JSON.stringify(step))
    assert.equal(fake.calls.length, 0, JSON.stringify(step))
    assert.deepEqual(readdirSync(root), ['.gitignore'], `${JSON.stringify(step)}: something was created`)
    assert.equal(existsSync(join(dirname(root), 'x.out')), false)
  }
  // 48 characters, and the characters a name may hold, are a name: its files are in the run's folder.
  const root = repo(t)
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: recorder((c) => setImmediate(() => c.child.emit('exit', 0, null))).spawn, now: () => NOW })
  for (const step of ['x'.repeat(48), 'a.b_c-9']) {
    const ran = await runner.run({ step, command: 'lsof', args: ['-nP'], cwd: root })
    assert.equal(ran.out, join(installDir(root), STAMP, `${step}.out`))
  }
})

test("the stop and start scripts' children reach Node's spawn only through spawnWith, so no timeout or kill signal can be added on the way", () => {
  // spawnWith hands Node exactly cwd, env, stdio and detached (test 3), but that holds only while
  // nothing else calls Node's spawn: a direct call with a timeout and killSignal would end a stop
  // mid-stop and pass every test that injects a spawn. So the source is held to that shape.
  const path = new URL('../scripts/install/run.ts', import.meta.url).pathname
  const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const nodes: ts.Node[] = []
  const visit = (node: ts.Node): void => {
    nodes.push(node)
    ts.forEachChild(node, visit)
  }
  visit(source)

  // child_process gives this module spawn alone, as nodeSpawn (and the SpawnOptions type).
  const fromChildProcess = nodes.filter((n): n is ts.ImportDeclaration => ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier) && /child_process$/.test(n.moduleSpecifier.text))
  assert.equal(fromChildProcess.length, 1)
  const bindings = fromChildProcess[0]?.importClause?.namedBindings
  assert.ok(bindings !== undefined && ts.isNamedImports(bindings) && fromChildProcess[0]?.importClause?.name === undefined)
  const values = bindings.elements.filter((e) => !e.isTypeOnly).map((e) => `${e.propertyName?.text ?? e.name.text} as ${e.name.text}`)
  assert.deepEqual(values, ['spawn as nodeSpawn'])

  // nodeSpawn is used once: as spawnWith's argument, building realSpawn.
  const uses = nodes.filter((n): n is ts.Identifier => ts.isIdentifier(n) && n.text === 'nodeSpawn' && !ts.isImportSpecifier(n.parent))
  assert.equal(uses.length, 1, 'nodeSpawn is used somewhere else')
  const call = uses[0]?.parent
  assert.ok(call !== undefined && ts.isCallExpression(call) && ts.isIdentifier(call.expression) && call.expression.text === 'spawnWith' && call.arguments.length === 1)
  const declaration = call.parent
  assert.ok(ts.isVariableDeclaration(declaration) && ts.isIdentifier(declaration.name) && declaration.name.text === 'realSpawn')

  // realSpawn is the runner's default spawn, and nothing else.
  const defaults = nodes.filter((n): n is ts.Identifier => ts.isIdentifier(n) && n.text === 'realSpawn' && n.parent !== declaration)
  assert.equal(defaults.length, 1)
  const fallback = defaults[0]?.parent
  assert.ok(fallback !== undefined && ts.isBinaryExpression(fallback) && fallback.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken && fallback.right === defaults[0])
  assert.equal(fallback.left.getText(source), 'options.spawn')

  // And spawnWith hands on an object of exactly those four, with nothing spread into it.
  const spawnWith = nodes.find((n): n is ts.FunctionDeclaration => ts.isFunctionDeclaration(n) && n.name?.text === 'spawnWith')
  assert.ok(spawnWith !== undefined)
  const handed: ts.ObjectLiteralExpression[] = []
  const collect = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'impl') {
      const options = node.arguments[2]
      if (options !== undefined && ts.isObjectLiteralExpression(options)) handed.push(options)
      assert.equal(node.arguments.length, 3)
    }
    ts.forEachChild(node, collect)
  }
  collect(spawnWith)
  assert.equal(handed.length, 1)
  const props = handed[0]?.properties ?? ts.factory.createNodeArray()
  assert.equal(props.some((p) => !ts.isPropertyAssignment(p)), false, 'something is spread or shorthanded into the options')
  assert.deepEqual(props.map((p) => p.name?.getText(source)).sort(), ['cwd', 'detached', 'env', 'stdio'])

  // spawnWith calls nothing but impl, and constructs nothing: no timer armed beside the spawn (setTimeout(() => child.kill(...))),
  // no listener that signals the child, no wrapper object handed back in place of what impl returned.
  const inside: ts.Node[] = []
  const all = (node: ts.Node): void => {
    inside.push(node)
    ts.forEachChild(node, all)
  }
  all(spawnWith)
  const calls = inside.filter((n): n is ts.CallExpression => ts.isCallExpression(n))
  assert.deepEqual(calls.map((c) => c.expression.getText(source)), ['impl'])
  assert.equal(inside.some((n) => ts.isNewExpression(n) || ts.isTaggedTemplateExpression(n) || ts.isAwaitExpression(n) || ts.isDecorator(n)), false)
  // And what it returns is impl's own child: the arrow's body is that one call.
  const arrow = inside.find((n): n is ts.ArrowFunction => ts.isArrowFunction(n))
  assert.ok(arrow !== undefined && ts.isCallExpression(arrow.body) && arrow.body === calls[0])
})

test('a stop or start spawned through spawnWith is never killed or signalled, however long it runs', async (t) => {
  // The behaviour behind the source check above: a spawnWith that armed a timer to kill its child (after ten
  // minutes, say) would pass every test that injects a spawn of its own. Here Node's spawn is a stand-in and
  // spawnWith is the runner's spawn, so whatever it arms runs under the mocked clock.
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const children: FakeChild[] = []
  // Node's spawn options, by the type spawnWith hands them on as (this file does not import child_process, as hygiene.test holds).
  const handed: Parameters<NodeSpawnFn>[2][] = []
  const standIn: NodeSpawnFn = (_command, _args, options) => {
    handed.push(options)
    const child = new FakeChild(700 + children.length, false)
    children.push(child)
    return child
  }
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] })
  const runner = new Runner({ repoRoot: repo(t), env: installerEnv(home), spawn: spawnWith(standIn), now: () => NOW })
  const DAY = 24 * 60 * 60 * 1000
  for (const [step, script, args] of [
    ['stop', STOP_SCRIPT, []],
    ['jobs', STOP_SCRIPT, ['--jobs']],
    ['start', START_SCRIPT, []],
  ] as const) {
    const running = runner.start({ step, command: join(pmmcp, script), args, cwd: pmmcp })
    const child = children.at(-1)
    assert.ok(child)
    // Two days, in steps a timer of any period would fire within.
    for (let i = 0; i < 48; i += 1) t.mock.timers.tick(DAY / 24)
    assert.deepEqual(child.signals, [], `${step} was signalled`)
    assert.equal(await settled(running.done), false, `${step} was given up on`)
    child.emit('exit', 0, null)
    assert.equal((await running.done).code, 0)
    assert.deepEqual(child.signals, [], `${step} was signalled at its exit`)
  }
  // And Node's spawn was handed neither a timeout nor a kill signal for any of them.
  assert.deepEqual(handed.map((o) => Object.keys(o).sort()), [0, 1, 2].map(() => ['cwd', 'detached', 'env', 'stdio']))
  assert.deepEqual(handed.map((o) => o.detached), [true, true, true])
  t.mock.timers.reset()
})

test("active.json's record is held to its shape: a field that is not a step, a pid, an ISO time or a log path reads as unreadable, and nothing of it is shown", (t) => {
  const home = tmpdir(t)
  const pmmcp = checkout(t)
  const STOP = join(pmmcp, STOP_SCRIPT)
  const root = repo(t)
  mkdirSync(installDir(root), { recursive: true, mode: 0o700 })
  const fake = recorder()
  const runner = new Runner({ repoRoot: root, env: installerEnv(home), spawn: fake.spawn, now: () => NOW })
  const stop = { step: 'stop', command: STOP, args: [], cwd: pmmcp }

  // A record as the runner writes it, a repeated step's name included, is read and shown whole.
  const good = { step: 'stop-2', pid: 812, started: '2026-10-29T04:00:00.000Z', out: '/x/stop-2.out', err: '/x/stop-2.err' }
  writeFileSync(activePath(root), JSON.stringify(good), { mode: 0o600 })
  assert.deepEqual(readActive(root), { state: 'recorded', record: good })
  assert.throws(
    () => runner.start(stop),
    (e: unknown) => busyCode(e) && e instanceof Error && e.message.includes('stop-2 (pid 812, since 2026-10-29T04:00:00.000Z, output in /x/stop-2.out and /x/stop-2.err)'),
  )

  const bad: readonly (readonly [string, Record<string, unknown>, string])[] = [
    ['a step with a terminal escape', { step: '\u001b[2Jstop' }, '\u001b'],
    ['a step in upper case', { step: 'STOP' }, 'STOP'],
    ['a step that is a path', { step: '../stop' }, '../stop'],
    ['a step longer than any given', { step: `${'q'.repeat(48)}-x` }, 'q'.repeat(48)],
    ['a pid that is no whole number', { pid: 812.5 }, '812.5'],
    ['a pid as text', { pid: '812q' }, '812q'],
    ['a pid past any pid', { pid: 2 ** 31 }, String(2 ** 31)],
    ['a start that is no ISO time', { started: 'yesterday' }, 'yesterday'],
    ['a start in local time', { started: '2026-10-29 04:00:00' }, '04:00:00'],
    ['a start with an offset', { started: '2026-10-29T06:00:00+02:00' }, '+02:00'],
    ['a start with a bell after it', { started: '2026-10-29T04:00:00.000Z\u0007' }, '\u0007'],
    ['a relative log', { out: 'stop-2.out' }, 'stop-2.out'],
    ['a log of another kind', { err: '/x/stop-2.log' }, 'stop-2.log'],
    ['a log with a title escape', { out: '/x/\u001b]0;pwned\u0007stop-2.out' }, 'pwned'],
    ['a log with a bidi override', { err: '/x/‮stop-2.err' }, '‮'],
    ['a log holding a credential shape', { out: '/x/sk-ant-api03-abcdefghijklmnopqrstuvwx/stop-2.out' }, 'sk-ant'],
    ['a field missing', { err: undefined }, 'stop-2.out'],
  ]
  for (const [why, change, text] of bad) {
    writeFileSync(activePath(root), JSON.stringify({ ...good, ...change }), { mode: 0o600 })
    assert.deepEqual(readActive(root), { state: 'unreadable', reason: `${activePath(root)} is not a record of a running step` }, why)
    assert.throws(
      () => runner.start(stop),
      (e: unknown) => busyCode(e) && e instanceof Error && !e.message.includes(text) && /is not a record of a running step/.test(e.message),
      why,
    )
  }
  assert.equal(fake.calls.length, 0)
})
