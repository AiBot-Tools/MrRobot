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

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync, spawn } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { closeVerified, withStore } from './helpers/store.js'
import { EventStore } from '../src/events/store.js'
import { tmpdir } from './helpers/tmpdir.js'
import { shadowCheckout } from './helpers/checkout.js'

// Every program here runs from a copy of the checkout holding a trap .env,
// never from the checkout itself, where the operator keeps the real one (see
// helpers/checkout.ts). hygiene.test.ts refuses a spawn from the real tree.
const CHECKOUT = shadowCheckout()
after(() => CHECKOUT.dispose())
const ROOT = CHECKOUT.root

// The shipped config names the operator's REAL pmmcp and, since pmmcp takes no
// bearer, nothing short of the address keeps an offline test from reaching it.
// Port 9 (discard) on loopback: nothing listens, so a connect fails at once.
const SHIPPED_PMMCP_URL = 'url: http://127.0.0.1:8766/mcp'
const CLOSED_PMMCP_URL = 'url: http://127.0.0.1:9/mcp'

/** The shipped kernel.yaml with pmmcp pointed at a closed port, or a throw. */
function offlinePmmcp(shipped: string): string {
  assert.ok(shipped.includes(SHIPPED_PMMCP_URL), 'the shipped pmmcp url moved; update SHIPPED_PMMCP_URL')
  return shipped.replace(SHIPPED_PMMCP_URL, CLOSED_PMMCP_URL)
}
const BOOT = { schemaVersion: 1 as const, version: '0.0.1', configHash: 'h', degraded: [] }

/** Run one CLI invocation as a child process. */
function cli(args: readonly string[], env: Record<string, string>): {
  status: number | null
  stdout: string
  stderr: string
} {
  const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', ...args], {
    cwd: ROOT,
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
  const shipped = readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8')
  const config = offlinePmmcp(shipped)
    .replace(/^dataDir: .*$/m, `dataDir: ${dataDir}`)
    .replace(/^  port: \d+$/m, `  port: ${String(port)}`)
    .replace(/mountRoot: [^\n}]*/g, `mountRoot: ${dataDir}/work `)
  mkdirSync(join(dataDir, 'work'), { recursive: true })
  writeFileSync(configPath, config)

  const env = {
    PATH: process.env['PATH'] ?? '',
    HOME: process.env['HOME'] ?? '',
    AOS_CONTROL_TOKEN: token,
    AOS_DATA_DIR: dataDir,
  }
  const daemon = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts', '--config', configPath], {
    cwd: ROOT,
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
  // Started without --dotenv (as every test is): no .env was opened, not even
  // the operator's real one in this repository's root.
  assert.match(log, /credentials: shell only \(no --dotenv\)/)

  // Now the other shell: a real CLI process talking to a real daemon. This is
  // the round trip nothing else in the suite makes.
  const agents = cli(['agents', '--config', configPath], { ...env })
  assert.equal(agents.status, 0, agents.stderr)
  const listed = agents.stdout.trim().split('\n').map((l) => l.split('\t')[0])
  // The whole shipped fleet, over a real socket. Listed explicitly rather than by
  // count: an agent that silently stopped loading is the failure this catches.
  assert.deepEqual(listed.sort(), ['ceo', 'researcher', 'worker-template', 'writer'], agents.stdout)
  assert.match(agents.stdout, /ceo\tstandard\tT2\tactive\tanthropic\/claude-sonnet-5/)
  // The pair's tiers survive the round trip, which is where the gate reads them.
  assert.match(agents.stdout, /researcher\tstandard\tT1\tactive\t/)
  assert.match(agents.stdout, /writer\tstandard\tT2\tactive\t/)

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

test('the checkout these programs run from holds an armed trap .env, so a default-path regression reads nothing real', () => {
  // Pointed at it on purpose, the daemon must refuse it: that refusal is what a
  // regression or mutant that defaults to <repo>/.env would hit here, instead
  // of the operator's real file.
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/main.ts', '--dotenv', '.env'], {
    cwd: ROOT,
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '' },
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.notEqual(run.status, 0)
  assert.match(`${run.stdout}${run.stderr}`, /\.env has mode 0644/)
  assert.notEqual(ROOT, fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, ''))
})

test('the daemon will not start on a tree a falsify run has mutated, live or interrupted', () => {
  const dir = join(ROOT, '.falsify')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'journal.json'), JSON.stringify({ file: 'src/policy/gate.ts', original: '', pid: 1 }))
  try {
    const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
      cwd: ROOT,
      env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '' },
      encoding: 'utf8',
      timeout: 60_000,
    })
    assert.equal(run.status, 1)
    assert.match(`${run.stdout}${run.stderr}`, /a falsify run is in progress or was interrupted/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the operator scripts are programs: each refuses with usage rather than doing nothing', (t) => {
  // The same blindness this file exists for. `scripts/eval.ts` and
  // `scripts/capture-pmmcp.ts` are only ever reached through npm, so nothing in
  // the suite would notice an entry guard that never fires — the module would
  // load, define main, and exit 0 having run no eval and captured nothing.
  //
  // eval.ts is driven with its credential ABSENT. capture-pmmcp.ts needs no
  // credential for pmmcp, so it is driven twice against a CLOSED loopback port:
  // once as shipped (it must try, fail, and write nothing) and once with a
  // declared-but-unset tokenEnv (it must refuse before connecting). Neither
  // touches the operator's pmmcp or any daemon.
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin' }

  const evalRun = spawnSync('npx', ['tsx', 'scripts/eval.ts'], {
    cwd: ROOT,
    env,
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.equal(evalRun.status, 2, `eval.ts exited ${String(evalRun.status)}: ${evalRun.stderr}`)
  assert.match(evalRun.stderr, /AOS_CONTROL_TOKEN is not set/)

  const dir = tmpdir(t)
  const shipped = offlinePmmcp(readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8'))
  const capture = (yaml: string, name: string): { status: number | null; stderr: string; out: string } => {
    const configPath = join(dir, `${name}.yaml`)
    const out = join(dir, `${name}.json`)
    writeFileSync(configPath, yaml)
    const run = spawnSync('npx', ['tsx', 'scripts/capture-pmmcp.ts', out, '--config', configPath], {
      cwd: ROOT,
      env,
      encoding: 'utf8',
      timeout: 60_000,
    })
    return { status: run.status, stderr: run.stderr, out }
  }

  // No tokenEnv, as shipped: it must attempt the connection, fail, and write nothing.
  const tokenless = capture(shipped, 'tokenless')
  assert.equal(tokenless.status, 1, `capture-pmmcp.ts exited ${String(tokenless.status)}: ${tokenless.stderr}`)
  assert.doesNotMatch(tokenless.stderr, /is not set/)
  assert.ok(tokenless.stderr.trim().length > 0, 'a failed capture said nothing')
  assert.equal(existsSync(tokenless.out), false, 'a failed capture wrote a fixture')

  // A declared tokenEnv that is unset refuses before any connection.
  const declared = capture(
    shipped.replace(CLOSED_PMMCP_URL, `${CLOSED_PMMCP_URL}\n      tokenEnv: PMMCP_TOKEN`),
    'declared',
  )
  assert.equal(declared.status, 1, `capture-pmmcp.ts exited ${String(declared.status)}: ${declared.stderr}`)
  assert.match(declared.stderr, /PMMCP_TOKEN is not set/)
  assert.equal(existsSync(declared.out), false)
  t.diagnostic('both scripts refused as programs rather than exiting 0 silently')
})

/** A kernel.yaml for a spawned daemon: its own data dir and port, pmmcp offline. */
function daemonConfig(dataDir: string, port: number): string {
  const path = join(dataDir, 'kernel.yaml')
  const shipped = readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8')
  writeFileSync(
    path,
    offlinePmmcp(shipped)
      .replace(/^dataDir: .*$/m, `dataDir: ${dataDir}`)
      .replace(/^  port: \d+$/m, `  port: ${String(port)}`)
      .replace(/mountRoot: [^\n}]*/g, `mountRoot: ${dataDir}/work `),
  )
  mkdirSync(join(dataDir, 'work'), { recursive: true })
  return path
}

/** A credentials file OUTSIDE the repository, so the in-repo fence does not apply. */
function credsFile(dir: string, text: string, mode = 0o600): string {
  const path = join(dir, 'creds.env')
  writeFileSync(path, text, { mode })
  chmodSync(path, mode)
  return path
}

// Opaque on purpose: nothing like a real key shape, so the pattern redactor
// cannot be what keeps them out of the log. On this path nothing writes them
// at all (the broker logs ids, the token is only compared), so their absence
// is a check that nothing starts to; the exact-value mask itself is proven in
// dotenv.test.ts ("every returned value is registered with SecretMask…").
const FILE_TOKEN = 'qFileOnlyControlToken0123456789abcdefgh'
const FILE_KEY = 'qFileOnlyProviderKeyZYXWVUTSRQ987654321'

test('the daemon and the CLI read AOS_CONTROL_TOKEN and a provider key that exist only in a --dotenv file, and neither reaches the log or the output', async (t) => {
  const dataDir = join(tmpdir(t), 'daemon-dotenv')
  mkdirSync(dataDir, { recursive: true })
  const configPath = daemonConfig(dataDir, 7792)
  const creds = credsFile(tmpdir(t), `# test credentials\nAOS_CONTROL_TOKEN=${FILE_TOKEN}\nANTHROPIC_API_KEY=${FILE_KEY}\n`)

  // No credential in the environment at all: only the file can supply them.
  const env = { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', AOS_DATA_DIR: dataDir }
  const daemon = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts', '--config', configPath, '--dotenv', creds], {
    cwd: ROOT,
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
  const listening = await new Promise<boolean>((resolve) => {
    const deadline = setTimeout(() => resolve(false), 45_000)
    const poll = setInterval(() => {
      if (log.includes('listening on 127.0.0.1') || daemon.exitCode !== null) {
        clearInterval(poll)
        clearTimeout(deadline)
        resolve(daemon.exitCode === null)
      }
    }, 250)
    poll.unref?.()
    deadline.unref?.()
  })
  // Booting at all proves the token came from the file: without one the
  // control plane refuses to start.
  assert.ok(listening, `the daemon never listened:\n${log}`)
  assert.match(log, /credentials: \.env \(AOS_CONTROL_TOKEN, ANTHROPIC_API_KEY\)/)

  // The other shell, as `npm run cli` runs it: the token only in the file.
  const agents = cli(['agents', '--config', configPath, '--dotenv', creds], { AOS_DATA_DIR: dataDir })
  assert.equal(agents.status, 0, agents.stderr)
  assert.match(agents.stdout, /^ceo\t/m)
  for (const secret of [FILE_TOKEN, FILE_KEY]) {
    assert.equal(`${agents.stdout}${agents.stderr}`.includes(secret), false, 'the CLI printed a credential')
  }

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

  const store = new EventStore(join(dataDir, 'events.db'), { readOnly: true })
  try {
    const rows = store.query()
    const accessed = rows.filter((r) => r.type === 'secret.accessed').map((r) => JSON.parse(r.payload) as Record<string, unknown>)
    assert.deepEqual(
      accessed.map((a) => `${String(a['id'])}:${String(a['source'])}`),
      ['anthropic-api-key:env'],
      'the file-sourced key was not resolved through the env source',
    )
    const everything = JSON.stringify(rows)
    for (const secret of [FILE_TOKEN, FILE_KEY]) {
      assert.equal(everything.includes(secret), false, 'a file-sourced value reached the event log')
      assert.equal(log.includes(secret), false, 'a file-sourced value reached the daemon output')
    }
    assert.equal(store.verifyChain(store.readAnchor()).ok, true)
  } finally {
    store.close()
  }
})

test('the daemon refuses a group-readable or non-regular --dotenv before it boots, naming the fix, and creates no log', (t) => {
  const run = (creds: string, dataDir: string): { status: number | null; out: string } => {
    const configPath = daemonConfig(dataDir, 7793)
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/main.ts', '--config', configPath, '--dotenv', creds], {
      cwd: ROOT,
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', AOS_DATA_DIR: dataDir },
      encoding: 'utf8',
      timeout: 30_000,
    })
    return { status: result.status, out: `${result.stdout ?? ''}${result.stderr ?? ''}` }
  }

  const readable = credsFile(tmpdir(t), `AOS_CONTROL_TOKEN=${FILE_TOKEN}\n`, 0o644)
  const dataA = join(tmpdir(t), 'a')
  mkdirSync(dataA, { recursive: true })
  const a = run(readable, dataA)
  assert.equal(a.status, 1, a.out)
  assert.ok(a.out.includes(`chmod 600 ${readable}`), a.out)
  assert.equal(existsSync(join(dataA, 'events.db')), false, 'the daemon wrote a log before refusing')
  assert.equal(a.out.includes(FILE_TOKEN), false)

  // A FIFO: opened non-blocking, so the refusal cannot hang waiting for a writer.
  const fifo = join(tmpdir(t), 'fifo.env')
  const made = spawnSync('mkfifo', ['-m', '600', fifo])
  if (made.status === 0) {
    const dataB = join(tmpdir(t), 'b')
    mkdirSync(dataB, { recursive: true })
    const b = run(fifo, dataB)
    assert.equal(b.status, 1, b.out)
    assert.match(b.out, /is not a regular file/)
    assert.equal(existsSync(join(dataB, 'events.db')), false)
  } else {
    t.diagnostic('mkfifo is unavailable here; the FIFO case is covered by the unit test for /dev/null')
  }
})

test('eval.ts takes AOS_CONTROL_TOKEN from --dotenv in either form, refuses a second, and without it still names what is missing', (t) => {
  const creds = credsFile(tmpdir(t), `AOS_CONTROL_TOKEN=${FILE_TOKEN}\nANTHROPIC_API_KEY=${FILE_KEY}\n`)
  // An unknown case stops eval right after the token check, before any socket.
  const run = spawnSync('npx', ['tsx', 'scripts/eval.ts', '--dotenv', creds, '--case', 'nope'], {
    cwd: ROOT,
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.equal(run.status, 2, run.stderr)
  assert.match(run.stderr, /no case nope/, 'the token was not taken from the file')
  assert.equal(`${run.stdout}${run.stderr}`.includes(FILE_TOKEN), false)

  // The --dotenv=path form is read, as the daemon reads it.
  const eqForm = spawnSync('npx', ['tsx', 'scripts/eval.ts', `--dotenv=${creds}`, '--case', 'nope'], {
    cwd: ROOT,
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.equal(eqForm.status, 2, eqForm.stderr)
  assert.match(eqForm.stderr, /no case nope/, 'the --dotenv=path form was ignored')

  // `npm run eval -- --dotenv other` puts a second flag after package.json's:
  // refused, as by the daemon and the CLI, rather than one silently ignored.
  const twice = spawnSync('npx', ['tsx', 'scripts/eval.ts', '--dotenv', creds, '--dotenv', creds, '--case', 'nope'], {
    cwd: ROOT,
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.equal(twice.status, 2, twice.stderr)
  assert.match(twice.stderr, /--dotenv may be given once/)
})
