// Entry points, exercised as processes.
//
// Every other test drives this code in process: `runCli(argv, io)` with a fake
// IO, `bootKernel(options)` with injected doubles. That is the right way to test
// dispatch and boot, and it is structurally blind to one thing — whether the
// files are WIRED as programs at all.
//
// They were not. `src/cli/index.ts` exported runCli and nothing called it, so
// `npm run cli -- verify-chain` loaded the module, ran no command, printed
// nothing and exited 0. Three hundred and sixty tests passed over it, and the
// Phase 0 exit criterion runs exactly that command.
//
// So these spawn real processes and read real stdout. They are slower than
// everything else here and there are deliberately few of them: the claim is
// only "this file is a program that does the thing", not any detail of what it
// does. Everything finer belongs in the in-process tests.
//
// The child does not inherit the network guard, so only commands that touch
// nothing are used: verify-chain and search read a local database, and the
// daemon binds loopback with no pmmcp token so its hub never dials out.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync, spawn } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { closeVerified, withStore } from './helpers/store.js'
import { EventStore } from '../src/events/store.js'
import { tmpdir } from './helpers/tmpdir.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')
const BOOT = { schemaVersion: 1 as const, version: '0.0.1', configHash: 'h', degraded: [] }

/** Run one CLI invocation as a child process. */
function cli(args: readonly string[], env: Record<string, string>): {
  status: number | null
  stdout: string
  stderr: string
} {
  const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', ...args], {
    cwd: REPO,
    encoding: 'utf8',
    timeout: 60_000,
    // A clean environment plus exactly what the command needs: inheriting the
    // test runner's env would let a stray AOS_DATA_DIR or token decide the result.
    env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', ...env },
  })
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

/** A data directory with a real, verifiable log in it. */
function seeded(t: Parameters<typeof withStore>[0]): string {
  const dataDir = join(tmpdir(t), 'data')
  mkdirSync(dataDir, { recursive: true })
  const store = withStore(t, { path: join(dataDir, 'events.db') })
  store.append({ type: 'kernel.booted', payload: BOOT })
  store.append({ type: 'kernel.shutdown', payload: { schemaVersion: 1, reason: 'requested', uptimeMs: 1 } })
  closeVerified(store)
  return dataDir
}

test('npm run cli -- verify-chain is a program that prints and exits 0', (t) => {
  const dataDir = seeded(t)
  const run = cli(['verify-chain'], { AOS_DATA_DIR: dataDir })

  // The bug this test exists for: exit 0 with empty stdout. Both halves are
  // asserted, because the status alone was already 0 when nothing ran.
  assert.equal(run.status, 0, run.stderr)
  assert.match(run.stdout, /^ok\t2 events\thead [0-9a-f]{64}\n$/, JSON.stringify(run.stdout))
})

test('npm run cli -- search is a program that prints its rows', (t) => {
  const dataDir = seeded(t)
  const run = cli(['search', '--type', 'kernel.shutdown'], { AOS_DATA_DIR: dataDir })

  assert.equal(run.status, 0, run.stderr)
  const lines = run.stdout.trim().split('\n')
  assert.equal(lines.length, 1, run.stdout)
  assert.match(lines[0] ?? '', /kernel\.shutdown/)
  // The filter narrowed: the boot row is in the log and not in this output.
  assert.equal(run.stdout.includes('kernel.booted'), false)
})

test('the CLI maps its exit codes on a real process: 0 ok, 1 refusal, 2 usage', (t) => {
  const dataDir = seeded(t)

  // 2 — usage. An unknown command and an unknown flag both print usage.
  for (const args of [['nonsense'], [], ['agents', '--nope']]) {
    const run = cli(args, { AOS_DATA_DIR: dataDir })
    assert.equal(run.status, 2, `${JSON.stringify(args)}: ${run.stderr}`)
    assert.match(run.stderr, /aos — Agentic OS console/, JSON.stringify(args))
  }

  // 1 — a refusal. No token, so a socket command stops before the wire.
  const noToken = cli(['agents'], { AOS_DATA_DIR: dataDir })
  assert.equal(noToken.status, 1, noToken.stderr)
  assert.match(noToken.stderr, /AOS_CONTROL_TOKEN is not set/)
  assert.equal(noToken.stdout, '', 'a refused command printed to stdout')

  // 1 — a broken log, read-only and reported with a reason.
  const empty = join(tmpdir(t), 'nothing-here')
  mkdirSync(empty, { recursive: true })
  const noLog = cli(['verify-chain'], { AOS_DATA_DIR: empty })
  assert.equal(noLog.status, 1, noLog.stdout)
  assert.match(noLog.stderr, /unable to open database file/)
})

test('npm run dev boots the daemon, serves the CLI over the socket, and shuts down on SIGTERM', async (t) => {
  // The exit criterion's third line is `npm run dev` in one shell and
  // `npm run cli -- …` in another. Nothing else in the suite runs that pair.
  const dataDir = join(tmpdir(t), 'daemon')
  mkdirSync(dataDir, { recursive: true })
  const token = 'e2e-entrypoint-token-'.padEnd(40, 'x')
  // A high fixed port in the ephemeral range, from this file only, so it cannot
  // collide with the port-0 fixtures every other kernel test uses.
  const port = 7791
  const configPath = join(dataDir, 'kernel.yaml')
  const shipped = readFileSync(join(REPO, 'config', 'kernel.yaml'), 'utf8')
  const config = shipped
    .replace(/^dataDir: .*$/m, `dataDir: ${dataDir}`)
    .replace(/^  port: \d+$/m, `  port: ${String(port)}`)
    .replace(/mountRoot: [^\n}]*/g, `mountRoot: ${dataDir}/work `)
  mkdirSync(join(dataDir, 'work'), { recursive: true })
  const { writeFileSync } = await import('node:fs')
  writeFileSync(configPath, config)

  const env = {
    PATH: process.env['PATH'] ?? '',
    HOME: process.env['HOME'] ?? '',
    AOS_CONTROL_TOKEN: token,
    AOS_DATA_DIR: dataDir,
  }
  const daemon = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts', '--config', configPath], {
    cwd: REPO,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let log = ''
  daemon.stdout.on('data', (d: Buffer) => {
    log += d.toString('utf8')
  })
  daemon.stderr.on('data', (d: Buffer) => {
    log += d.toString('utf8')
  })
  t.after(() => {
    if (daemon.exitCode === null) daemon.kill('SIGKILL')
  })

  // Wait for the line that says it is listening, rather than sleeping a guess.
  const listening = await new Promise<boolean>((resolve) => {
    const deadline = setTimeout(() => resolve(false), 45_000)
    const poll = setInterval(() => {
      if (log.includes('listening on 127.0.0.1')) {
        clearInterval(poll)
        clearTimeout(deadline)
        resolve(true)
      }
      if (daemon.exitCode !== null) {
        clearInterval(poll)
        clearTimeout(deadline)
        resolve(false)
      }
    }, 250)
    poll.unref?.()
    deadline.unref?.()
  })
  assert.ok(listening, `the daemon never listened:\n${log}`)
  // Degraded, with the six subsystems this machine cannot supply.
  assert.match(log, /booted degraded/)

  // Now the other shell: a real CLI process talking to a real daemon. This is
  // the round trip nothing else in the suite makes.
  const agents = cli(['agents', '--config', configPath], { ...env })
  assert.equal(agents.status, 0, agents.stderr)
  const listed = agents.stdout.trim().split('\n').map((l) => l.split('\t')[0])
  assert.deepEqual(listed.sort(), ['ceo', 'worker-template'], agents.stdout)
  assert.match(agents.stdout, /ceo\tstandard\tT2\tactive\tanthropic\/claude-sonnet-5/)

  // SIGTERM must run the clean shutdown, not just die: the anchor and the
  // kernel.shutdown row depend on it.
  daemon.kill('SIGTERM')
  const exited = await new Promise<number | null>((resolve) => {
    const deadline = setTimeout(() => resolve(null), 30_000)
    deadline.unref?.()
    daemon.once('exit', (code) => {
      clearTimeout(deadline)
      resolve(code ?? 0)
    })
  })
  assert.equal(exited, 0, `the daemon did not exit cleanly:\n${log}`)

  // The log it left behind verifies, and records both ends of the run.
  const store = new EventStore(join(dataDir, 'events.db'), { readOnly: true })
  try {
    const types = store.query().map((r) => r.type)
    assert.equal(types[0], 'kernel.booted')
    assert.equal(types[types.length - 1], 'kernel.shutdown')
    assert.equal(types.filter((t2) => t2 === 'subsystem.state').length, 8)
    assert.equal(store.verifyChain(store.readAnchor()).ok, true)
  } finally {
    store.close()
  }

  // And the daemon-less command agrees, from a third process.
  const verify = cli(['verify-chain', '--config', configPath], { ...env })
  assert.equal(verify.status, 0, verify.stderr)
  assert.match(verify.stdout, /^ok\t\d+ events\thead [0-9a-f]{64}\n$/)
})
