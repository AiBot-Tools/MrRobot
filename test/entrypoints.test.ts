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
// daemon binds loopback with its pmmcp url pointed at a closed loopback port
// or at a stand-in this process serves on one, so its hub never dials out.

import './helpers/guard.js'

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, lchownSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { createServer, type IncomingHttpHeaders } from 'node:http'
import type { AddressInfo } from 'node:net'
import { fileURLToPath } from 'node:url'

import { PassThrough, Writable } from 'node:stream'

import { closeVerified, withStore } from './helpers/store.js'
import { EventStore } from '../src/events/store.js'
import { tmpdir } from './helpers/tmpdir.js'
import { runEntry, shadowCheckout, spawnEntry, terminalAvailable, TRAP_DOTENV, type ShadowCheckout } from './helpers/checkout.js'
import { CEO_SUITE } from '../src/eval/suite.js'
import { BOOT_SLACK_MS, lockPath, takeLock, type LockOptions } from '../scripts/install/lock.js'
import { defectEnding, exitLine, outcomeEnding, refusedEnding, signalEnding, stoppedEnding } from '../scripts/install/ending.js'
import { Output, TRANSCRIPT_FILE } from '../scripts/install/output.js'
import { bashVersion, npmTookFlags, preflight, productVersion, stubRefusals } from '../scripts/install/preflight.js'
import { HANDLED_SIGNALS, REPEAT_MS, SIGNAL_EXIT, defectExit, handleSignal, onSignal, windowChanged, type HandledSignal, type SignalState, type SignalView, type WindowMarks } from '../scripts/install/signals.js'
import { afterRecheck, ranAPhase, stoppedBy } from '../scripts/install.js'
import { DiscoverError } from '../scripts/install/discover.js'
import { InstallRunError } from '../scripts/install/run.js'
import { TYPE_AHEAD_MS, Terminal } from '../scripts/install/terminal.js'

// The gate's outcome as main hands it on, named without importing src/install, which only the installer and its own tests import (hygiene.test.ts).
type GateOutcome = Parameters<typeof afterRecheck>[0]

// Every program here runs from a copy of the checkout holding a trap .env,
// never from the checkout itself, where the operator keeps the real one (see
// helpers/checkout.ts). hygiene.test.ts refuses a spawn from the real tree.
const CHECKOUT = shadowCheckout()
after(() => CHECKOUT.dispose())
const ROOT = CHECKOUT.root

// The shipped config names the operator's REAL pmmcp and, since pmmcp's gate
// runs in warn mode (it serves a request with no bearer or an unknown one),
// nothing short of the address keeps an offline test from reaching it.
// Port 9 (discard) on loopback: nothing listens, so a connect fails at once.
const SHIPPED_PMMCP_URL = 'url: http://127.0.0.1:8766/mcp'
const CLOSED_PMMCP_URL = 'url: http://127.0.0.1:9/mcp'
/** The shipped pmmcp bearer declaration, the line after the url. */
const SHIPPED_PMMCP_TOKEN = '\n      tokenEnv: AOS_PMMCP_TOKEN'

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
  const result = runEntry(CHECKOUT, 'src/cli/index.ts', [...args], {
    timeout: 60_000,
    // A clean environment plus exactly what the command needs: inheriting the
    // test runner's env would let a stray AOS_DATA_DIR or token decide the result.
    env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', ...env },
  })
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

test('runEntry and spawnEntry run from the shadow copy only: a cwd passed in is refused, not honoured', () => {
  // The cwd is the one thing that decides which .env an entry point can find;
  // the helpers own it so that no call site can move it.
  const anywhere = { cwd: '/' } as unknown as Parameters<typeof runEntry>[3]
  assert.throws(() => runEntry(CHECKOUT, 'src/main.ts', [], anywhere), /shadow checkout only/)
  assert.throws(() => spawnEntry(CHECKOUT, 'src/main.ts', [], anywhere as Parameters<typeof spawnEntry>[3]), /shadow checkout only/)
})

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
  const daemon = spawnEntry(CHECKOUT, 'src/main.ts', ['--config', configPath], {
    env,
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
  const run = runEntry(CHECKOUT, 'src/main.ts', ['--dotenv', '.env'], {
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '' },
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
    const run = runEntry(CHECKOUT, 'src/main.ts', [], {
      env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '' },
      timeout: 60_000,
    })
    assert.equal(run.status, 1)
    assert.match(`${run.stdout}${run.stderr}`, /a falsify run is in progress or was interrupted/)
    // Between mutants (a baseline) a live run holds only its lock: refused
    // too, naming the run. A lock whose pid is gone is a dead run's, and the
    // tree is clean once no journal is left.
    rmSync(join(dir, 'journal.json'))
    const lock = (pid: number): void => writeFileSync(join(dir, 'lock.json'), JSON.stringify({ pid, started: 'x', runId: 'other-run' }))
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '' }
    lock(process.pid)
    const held = runEntry(CHECKOUT, 'src/main.ts', [], { env, timeout: 60_000 })
    assert.equal(held.status, 1)
    assert.match(`${held.stdout}${held.stderr}`, new RegExp(`a falsify run \\(pid ${String(process.pid)}\\) holds this tree`))
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
  // eval.ts is driven with its credential ABSENT. capture-pmmcp.ts is driven
  // against a CLOSED loopback port: as shipped, with its declared bearer unset
  // (it must refuse before connecting), and with a config that declares no
  // tokenEnv (it must try, fail, and write nothing). Neither touches the
  // operator's pmmcp or any daemon.
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin' }

  const evalRun = runEntry(CHECKOUT, 'scripts/eval.ts', [], {
    env,
    timeout: 60_000,
  })
  assert.equal(evalRun.status, 2, `eval.ts exited ${String(evalRun.status)}: ${evalRun.stderr}`)
  assert.match(evalRun.stderr, /AOS_CONTROL_TOKEN is not set/)

  // A token the daemon would refuse is refused here too, by name, before eval
  // prints that it is about to spend money and before anything is sent.
  const canary = 'qEvalTokenCanary0123456789abcdefghijkl'
  for (const [token, why] of [
    [`\u201C${canary}\u201D`, /outside printable ASCII/],
    [canary.slice(0, 31), /31 characters after trimming/],
    [`${canary.slice(0, 20)} ${canary.slice(20)}`, /contains whitespace/],
  ] as const) {
    const refused = runEntry(CHECKOUT, 'scripts/eval.ts', ['--case', 'nope'], {
      env: { ...env, AOS_CONTROL_TOKEN: token },
      timeout: 60_000,
    })
    assert.equal(refused.status, 2, refused.stderr)
    assert.match(refused.stderr, why)
    assert.doesNotMatch(`${refused.stdout}${refused.stderr}`, /spends real money/)
    assert.equal(`${refused.stdout}${refused.stderr}`.includes(canary.slice(0, 12)), false)
  }

  // A token that passes those rules with a trailing CR or newline
  // (`$(cat token.txt)` on a CRLF file) must be SENT trimmed too: otherwise
  // Node refuses the Authorization header after eval has said it is spending.
  // Port 9 is closed, so the run ends at the connect, having sent nothing.
  const firstCase = CEO_SUITE[0]?.id ?? ''
  for (const end of ['\r', '\n']) {
    const padded = runEntry(CHECKOUT, 'scripts/eval.ts', ['--case', firstCase, '--port', '9'], {
      env: { ...env, AOS_CONTROL_TOKEN: `${canary}${canary}${end}` },
      timeout: 60_000,
    })
    const printed = `${padded.stdout}${padded.stderr}`
    assert.match(printed, /ECONNREFUSED/, printed)
    assert.doesNotMatch(printed, /Invalid character in header content/)
    assert.equal(printed.includes(canary.slice(0, 12)), false)
  }

  const dir = tmpdir(t)
  const shipped = offlinePmmcp(readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8'))
  const capture = (
    yaml: string,
    name: string,
    extra: Record<string, string> = {},
  ): { status: number | null; stderr: string; printed: string; out: string } => {
    const configPath = join(dir, `${name}.yaml`)
    const out = join(dir, `${name}.json`)
    writeFileSync(configPath, yaml)
    const run = runEntry(CHECKOUT, 'scripts/capture-pmmcp.ts', [out, '--config', configPath], {
      env: { ...env, ...extra },
      timeout: 60_000,
    })
    return { status: run.status, stderr: run.stderr, printed: `${run.stdout}${run.stderr}`, out }
  }

  // A config without the declared line: it must attempt the connection, fail, and write nothing.
  assert.ok(shipped.includes(SHIPPED_PMMCP_TOKEN), 'the shipped pmmcp tokenEnv moved; update SHIPPED_PMMCP_TOKEN')
  const tokenless = capture(shipped.replace(SHIPPED_PMMCP_TOKEN, ''), 'tokenless')
  assert.equal(tokenless.status, 1, `capture-pmmcp.ts exited ${String(tokenless.status)}: ${tokenless.stderr}`)
  assert.doesNotMatch(tokenless.stderr, /is not set/)
  assert.ok(tokenless.stderr.trim().length > 0, 'a failed capture said nothing')
  assert.equal(existsSync(tokenless.out), false, 'a failed capture wrote a fixture')

  // As shipped, with the declared tokenEnv unset: refused before any connection.
  const declared = capture(shipped, 'declared')
  assert.equal(declared.status, 1, `capture-pmmcp.ts exited ${String(declared.status)}: ${declared.stderr}`)
  assert.match(declared.stderr, /AOS_PMMCP_TOKEN is not set/)
  assert.equal(existsSync(declared.out), false)

  // A declared bearer that cannot be a header (openssl rand -base64 64 wraps
  // mid-token), or that is too short to mask, is refused by name before any
  // connection, and no piece of it is printed.
  const head = 'qCaptureHeadCanary0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ'
  const tail = 'qCaptureTailCanaryZYXWVU98765=='
  for (const [token, why, name] of [
    [`${head}\n${tail}`, /AOS_PMMCP_TOKEN contains whitespace, so it is not a bearer/, 'wrapped'],
    ['Qz7#kd!', /AOS_PMMCP_TOKEN is under 8 characters/, 'short'],
  ] as const) {
    const refused = capture(shipped, name, { AOS_PMMCP_TOKEN: token })
    assert.equal(refused.status, 1, refused.printed)
    assert.match(refused.stderr, why)
    assert.equal(existsSync(refused.out), false)
    for (const piece of token.length < 16 ? [token] : [head, tail]) {
      for (let i = 0; i + Math.min(8, piece.length) <= piece.length; i += 1) {
        assert.equal(refused.printed.includes(piece.slice(i, i + 8)), false, `capture printed part of the bearer: ${refused.printed}`)
      }
    }
  }
  t.diagnostic('both scripts refused as programs rather than exiting 0 silently')
})

test('eval --json and capture-pmmcp OUT refuse a path that is the checkout\'s .env, in another case or through a link, before anything else, and leave it byte for byte', (t) => {
  // `npm run eval -- --json .env` would otherwise replace the operator's keys
  // with the report. The shadow checkout's trap stands in for them.
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin' }
  const trap = join(ROOT, '.env')
  const before = readFileSync(trap)
  const dir = tmpdir(t)
  symlinkSync(trap, join(dir, 'report.json'))
  symlinkSync(ROOT, join(dir, 'checkout'))
  const configPath = join(dir, 'closed.yaml')
  writeFileSync(configPath, offlinePmmcp(readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8')))
  const refused = /names this checkout's credentials file, which holds your keys/

  for (const target of ['.ENV', join(dir, 'report.json'), join(dir, 'checkout', '.env')]) {
    const evalRun = runEntry(CHECKOUT, 'scripts/eval.ts', ['--json', target], { env, timeout: 60_000 })
    assert.equal(evalRun.status, 2, evalRun.stderr)
    assert.match(evalRun.stderr, refused, target)
    // Before the token: nothing else was looked at, let alone spent.
    assert.doesNotMatch(evalRun.stderr, /AOS_CONTROL_TOKEN/, target)
    assert.deepEqual(readFileSync(trap), before, target)
  }
  const captured = runEntry(CHECKOUT, 'scripts/capture-pmmcp.ts', ['.env', '--config', configPath], { env, timeout: 60_000 })
  assert.equal(captured.status, 1, captured.stderr)
  assert.match(captured.stderr, refused)
  assert.deepEqual(readFileSync(trap), before)

  // Any other path is the operator's: eval goes on to its token, capture to its declared bearer.
  const report = runEntry(CHECKOUT, 'scripts/eval.ts', ['--json', join(dir, 'report.out.json')], { env, timeout: 60_000 })
  assert.equal(report.status, 2, report.stderr)
  assert.match(report.stderr, /AOS_CONTROL_TOKEN is not set/)
  const elsewhere = runEntry(CHECKOUT, 'scripts/capture-pmmcp.ts', [join(dir, 'capture.json'), '--config', configPath], { env, timeout: 60_000 })
  assert.equal(elsewhere.status, 1, elsewhere.stderr)
  assert.doesNotMatch(elsewhere.stderr, refused)
  assert.match(elsewhere.stderr, /AOS_PMMCP_TOKEN is not set/)
  assert.equal(existsSync(join(dir, 'capture.json')), false)
})

test('capture-pmmcp masks its bearer: a server that echoes it into a refusal prints none of it', async (t) => {
  // The SDK puts a refusal's body in its error, and capture prints that error.
  // An opaque bearer, so only the exact-value mask can be what hides it.
  const bearer = 'qCaptureEchoCanary0123456789abcdefghij'
  const server = createServer((req, res) => {
    req.resume()
    res.writeHead(401, { 'content-type': 'text/plain' }).end(`unauthorized: ${String(req.headers.authorization).replace(/^Bearer /, '')}`)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
  const url = `url: http://127.0.0.1:${String((server.address() as AddressInfo).port)}/mcp`
  const dir = tmpdir(t)
  const configPath = join(dir, 'echo.yaml')
  const out = join(dir, 'echo.json')
  writeFileSync(
    configPath,
    offlinePmmcp(readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8')).replace(CLOSED_PMMCP_URL, url),
  )
  // Async: the echoing server lives in this process and must keep answering.
  const child = spawnEntry(CHECKOUT, 'scripts/capture-pmmcp.ts', [out, '--config', configPath], {
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', AOS_PMMCP_TOKEN: bearer },
  })
  let printed = ''
  child.stdout.on('data', (c: Buffer) => (printed += c.toString('utf8')))
  child.stderr.on('data', (c: Buffer) => (printed += c.toString('utf8')))
  const code = await new Promise<number | null>((resolve) => child.on('close', resolve))
  assert.equal(code, 1, printed)
  assert.match(printed, /unauthorized: \[REDACTED\]/, 'the echo never arrived, so this proves nothing')
  for (let i = 0; i + 8 <= bearer.length; i += 1) {
    assert.equal(printed.includes(bearer.slice(i, i + 8)), false, `capture printed part of the bearer: ${printed}`)
  }
  assert.equal(existsSync(out), false)
})

/** A kernel.yaml for a spawned daemon: its own data dir and port, pmmcp offline or at `pmmcpUrl` (a loopback stand-in). */
function daemonConfig(dataDir: string, port: number, pmmcpUrl?: string): string {
  const path = join(dataDir, 'kernel.yaml')
  const shipped = readFileSync(join(ROOT, 'config', 'kernel.yaml'), 'utf8')
  const offline = offlinePmmcp(shipped)
  writeFileSync(
    path,
    (pmmcpUrl === undefined ? offline : offline.replace(CLOSED_PMMCP_URL, `url: ${pmmcpUrl}`))
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
const FILE_BEARER = 'qFileOnlyPmmcpBearerKJIHGFEDCBA13579ace'

test("the daemon and the CLI read AOS_CONTROL_TOKEN, pmmcp's bearer and a provider key that exist only in a --dotenv file, the bearer reaches pmmcp as sent, and none reaches the log or the output", async (t) => {
  // A stand-in for pmmcp on a loopback port: it records each request's
  // Authorization header and refuses, echoing the bearer back, as a server
  // that quotes a refused token would. The SDK puts that body in its error,
  // and the hub's degraded reason carries the error, so only the mask can
  // keep the bearer out of the log and the event log.
  const seen: (string | undefined)[] = []
  const pmmcp = createServer((req, res) => {
    req.resume()
    seen.push(req.headers.authorization)
    res.writeHead(401, { 'content-type': 'text/plain' }).end(`unauthorized: ${String(req.headers.authorization).replace(/^Bearer /, '')}`)
  })
  await new Promise<void>((resolve) => pmmcp.listen(0, '127.0.0.1', resolve))
  t.after(() => {
    pmmcp.closeAllConnections()
    return new Promise<void>((resolve) => pmmcp.close(() => resolve()))
  })
  const dataDir = join(tmpdir(t), 'daemon-dotenv')
  mkdirSync(dataDir, { recursive: true })
  const configPath = daemonConfig(dataDir, 7792, `http://127.0.0.1:${String((pmmcp.address() as AddressInfo).port)}/mcp`)
  // In .env.example's order, as `cp .env.example .env` leaves them: the log line lists the file's names in its order.
  const creds = credsFile(
    tmpdir(t),
    `# test credentials\nAOS_CONTROL_TOKEN=${FILE_TOKEN}\nAOS_PMMCP_TOKEN=${FILE_BEARER}\nANTHROPIC_API_KEY=${FILE_KEY}\n`,
  )

  // No credential in the environment at all: only the file can supply them.
  const env = { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', AOS_DATA_DIR: dataDir }
  const daemon = spawnEntry(CHECKOUT, 'src/main.ts', ['--config', configPath, '--dotenv', creds], {
    env,
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
  // README's line for a .env made from the template (plan A10's on the Mac).
  assert.match(log, /credentials: \.env \(AOS_CONTROL_TOKEN, AOS_PMMCP_TOKEN, ANTHROPIC_API_KEY\)/)
  // The bearer pmmcp was dialled with is the file's, under the name kernel.yaml declares, on the first request.
  assert.ok(seen.length >= 1, `the daemon never dialled pmmcp:\n${log}`)
  assert.equal(seen[0], `Bearer ${FILE_BEARER}`)

  // The other shell, as `npm run cli` runs it: the token only in the file.
  const agents = cli(['agents', '--config', configPath, '--dotenv', creds], { AOS_DATA_DIR: dataDir })
  assert.equal(agents.status, 0, agents.stderr)
  assert.match(agents.stdout, /^ceo\t/m)
  for (const secret of [FILE_TOKEN, FILE_BEARER, FILE_KEY]) {
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
    // The echo arrived and was recorded, masked: otherwise the bearer's absence below proves nothing.
    assert.match(everything, /unauthorized: \[REDACTED\]/, 'the refusal pmmcp echoed is not in the log, so this proves nothing')
    for (const secret of [FILE_TOKEN, FILE_BEARER, FILE_KEY]) {
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
    const result = runEntry(CHECKOUT, 'src/main.ts', ['--config', configPath, '--dotenv', creds], {
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', AOS_DATA_DIR: dataDir },
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
  const run = runEntry(CHECKOUT, 'scripts/eval.ts', ['--dotenv', creds, '--case', 'nope'], {
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
    timeout: 60_000,
  })
  assert.equal(run.status, 2, run.stderr)
  assert.match(run.stderr, /no case nope/, 'the token was not taken from the file')
  assert.equal(`${run.stdout}${run.stderr}`.includes(FILE_TOKEN), false)

  // The --dotenv=path form is read, as the daemon reads it.
  const eqForm = runEntry(CHECKOUT, 'scripts/eval.ts', [`--dotenv=${creds}`, '--case', 'nope'], {
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
    timeout: 60_000,
  })
  assert.equal(eqForm.status, 2, eqForm.stderr)
  assert.match(eqForm.stderr, /no case nope/, 'the --dotenv=path form was ignored')

  // `npm run eval -- --dotenv other` puts a second flag after package.json's:
  // refused, as by the daemon and the CLI, rather than one silently ignored.
  const twice = runEntry(CHECKOUT, 'scripts/eval.ts', ['--dotenv', creds, '--dotenv', creds, '--case', 'nope'], {
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
    timeout: 60_000,
  })
  assert.equal(twice.status, 2, twice.stderr)
  assert.match(twice.stderr, /--dotenv may be given once/)
})

// ── npm run aos-install ─────────────────────────────────────────────────────
//
// The installer as a program: what the operator's `npm run aos-install` runs.
// Its steps are tested in process (test/install-*.test.ts); here only that the
// file is a program that refuses, plans and stops where it must. Every run has
// a shadow checkout of its own and a HOME made here, never the real one. Every
// program the installer could start is a fake in that HOME's ~/.local/bin,
// which the runner puts first on a child's PATH (scripts/install/run.ts), so
// no real lsof, ps, docker, launchctl or git runs; each fake logs its argv and
// its environment's names to a file outside the HOME, and one that is not
// expected exits 97. The AOS daemon the installer looks for is a fake HTTP
// server on an ephemeral loopback port. The installer refuses root, so a
// suite run as root (a container) runs it as nobody, who then owns its
// checkout and HOME.

/** Who the installer runs as here: the suite's own user, or nobody when that is root. */
const INSTALLER_AS: { readonly uid: number; readonly gid: number } | undefined = process.getuid?.() === 0 ? { uid: 65534, gid: 65534 } : undefined

/** Hand a tree to the installer's user, links themselves and never what they lead to (node_modules). */
function handOver(path: string): void {
  if (INSTALLER_AS === undefined) return
  lchownSync(path, INSTALLER_AS.uid, INSTALLER_AS.gid)
  const st = lstatSync(path)
  if (st.isDirectory() && !st.isSymbolicLink()) for (const entry of readdirSync(path)) handOver(join(path, entry))
}

/** Every program the installer starts, or checks for on a child's PATH (its preflight). */
const FAKED = ['git', 'curl', 'uv', 'ollama', 'python3', 'bash', 'docker', 'lsof', 'ps', 'pgrep', 'launchctl', 'plutil'] as const

/**
 * A fake: logs `<name> <args>` and `env <names>`, answers the three probes an
 * empty HOME gets (and `ps -o etime=` with what a file beside the log holds,
 * when there is one), refuses anything else.
 */
function fakeProgram(log: string): string {
  const q = `'${log.replace(/'/g, "'\\''")}'`
  return [
    '#!/bin/sh',
    `{ printf '%s' "\${0##*/}"; for a in "$@"; do printf ' %s' "$a"; done; printf '\\n'; } >> ${q}`,
    `printf 'env %s\\n' "$(env | cut -d= -f1 | sort | tr '\\n' ' ')" >> ${q}`,
    'case "${0##*/} $*" in',
    "  'lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu') exit 1 ;;",
    `  'ps -o etime= -p '*) if [ -e ${q}.etime ]; then cat ${q}.etime; exit 0; fi ;;`,
    // A release file beside the log holds this probe until the test removes it (the Ctrl-C test's slow discovery).
    `  'docker context show') i=0; while [ -e ${q}.hold ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; echo desktop-linux; exit 0 ;;`,
    "  'docker info --format {{.ServerVersion}}') echo 29.5.2; exit 0 ;;",
    'esac',
    'echo "fake ${0##*/}: not expected in this test" >&2',
    'exit 97',
    '',
  ].join('\n')
}

interface InstallerMachine {
  readonly checkout: ShadowCheckout
  readonly home: string
  /** What the fakes logged. */
  calls(): string[]
  /** Hold `docker context show` until release() (at most 10 s). */
  hold(): void
  release(): void
  /** What the fake `ps -o etime= -p <pid>` prints (exit 0); undefined: it refuses, as an unexpected call. */
  etime(text: string | undefined): void
  /** The fake daemon's requests. */
  readonly requests: { method: string | undefined; url: string | undefined; headers: IncomingHttpHeaders }[]
}

/**
 * A shadow checkout (its trap .env kept or removed), a HOME holding nothing
 * but the fakes, and the fake daemon on the port kernel.yaml names.
 */
async function installerMachine(t: Parameters<typeof tmpdir>[0], opts: { readonly trap: boolean }): Promise<InstallerMachine> {
  const checkout = shadowCheckout()
  t.after(() => checkout.dispose())
  if (!opts.trap) rmSync(join(checkout.root, '.env'))
  const base = tmpdir(t)
  const home = join(base, 'home')
  const bin = join(home, '.local', 'bin')
  mkdirSync(bin, { recursive: true })
  const logs = join(base, 'calls')
  mkdirSync(logs)
  const log = join(logs, 'calls.log')
  for (const name of FAKED) writeFileSync(join(bin, name), fakeProgram(log), { mode: 0o755 })

  const requests: InstallerMachine['requests'] = []
  const daemon = createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, headers: req.headers })
    req.resume()
    res.writeHead(404).end()
  })
  await new Promise<void>((resolve) => daemon.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>((resolve) => daemon.close(() => resolve())))
  const kernelYaml = join(checkout.root, 'config', 'kernel.yaml')
  const shipped = readFileSync(kernelYaml, 'utf8')
  assert.match(shipped, /^ {2}port: 7777$/m, 'the shipped control port moved; update this test')
  writeFileSync(kernelYaml, shipped.replace(/^ {2}port: 7777$/m, `  port: ${String((daemon.address() as AddressInfo).port)}`))

  handOver(checkout.root)
  handOver(base)
  return {
    checkout,
    home,
    calls: () => (existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter((l) => l !== '') : []),
    hold: () => writeFileSync(`${log}.hold`, ''),
    release: () => rmSync(`${log}.hold`, { force: true }),
    etime: (text) => (text === undefined ? rmSync(`${log}.etime`, { force: true }) : writeFileSync(`${log}.etime`, text)),
    requests,
  }
}

/** The environment the installer gets: PATH, the HOME made here, and `extra`. Nothing of the test runner's. */
const installerEnv = (m: InstallerMachine, extra: Record<string, string> = {}): Record<string, string> => ({
  PATH: process.env['PATH'] ?? '/usr/bin:/bin',
  HOME: m.home,
  ...extra,
})

/** Run the installer to its exit. Blocks: for runs that reach no in-process fake. */
function installer(m: InstallerMachine, args: readonly string[], extra: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const run = runEntry(m.checkout, 'scripts/install.ts', args, { env: installerEnv(m, extra), timeout: 90_000, ...INSTALLER_AS })
  return { status: run.status, stdout: run.stdout ?? '', stderr: run.stderr ?? '' }
}

/** Run the installer while this process serves the fake daemon. stdin is /dev/null: not a terminal. */
async function installerAsync(m: InstallerMachine, args: readonly string[], extra: Record<string, string> = {}): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const child = spawnEntry(m.checkout, 'scripts/install.ts', args, { env: installerEnv(m, extra), ...INSTALLER_AS })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
  child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')))
  const timer = setTimeout(() => child.kill('SIGKILL'), 90_000)
  const status = await new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)))
  clearTimeout(timer)
  return { status, stdout, stderr }
}

/** Every path under `root` (links not followed) with its kind, mode and content digest: what "nothing changed" compares. */
function snapshot(root: string): Map<string, string> {
  const out = new Map<string, string>()
  const walk = (rel: string): void => {
    const path = rel === '' ? root : join(root, rel)
    const st = lstatSync(path)
    const mode = (st.mode & 0o7777).toString(8)
    if (st.isSymbolicLink()) out.set(rel, `link ${readlinkSync(path)}`)
    else if (st.isDirectory()) {
      out.set(rel, `dir ${mode}`)
      for (const entry of readdirSync(path)) walk(rel === '' ? entry : `${rel}/${entry}`)
    } else out.set(rel, `file ${mode} ${createHash('sha256').update(readFileSync(path)).digest('hex')}`)
  }
  walk('')
  return out
}

/** What changed between two snapshots, by path. */
function changed(before: Map<string, string>, after: Map<string, string>): string[] {
  const paths = new Set([...before.keys(), ...after.keys()])
  return [...paths].filter((p) => before.get(p) !== after.get(p)).sort()
}

/** The run folders the runner made under .aos/install, by name. */
const runFolders = (root: string): string[] => {
  const dir = join(root, '.aos', 'install')
  return existsSync(dir) ? readdirSync(dir).filter((n) => /^\d{8}T\d{6}Z(?:-\d+)?$/.test(n)) : []
}

test("aos-install refuses the shadow checkout's trap .env, exits 2 and leaves it byte for byte", async (t) => {
  // The trap stands in for the operator's real .env: mode 0644 and a name no
  // config declares. The writer's inspection refuses it at S2, so nothing is
  // planned, discovered or run: no child, no log, and no lock left.
  for (const args of [[], ['--aos-only'], ['--dry-run']]) {
    const m = await installerMachine(t, { trap: true })
    const trap = join(m.checkout.root, '.env')
    const before = readFileSync(trap)
    assert.equal(before.toString('utf8'), TRAP_DOTENV)
    const run = installer(m, args)
    const printed = `${run.stdout}${run.stderr}`
    assert.equal(run.status, 2, `${JSON.stringify(args)}: ${printed}`)
    assert.match(printed, /refused before any change: .*\.env has mode 0644/, JSON.stringify(args))
    assert.deepEqual(readFileSync(trap), before, `${JSON.stringify(args)}: the trap changed`)
    assert.equal(lstatSync(trap).mode & 0o777, 0o644)
    assert.deepEqual(m.calls(), [], `${JSON.stringify(args)}: a program ran before the .env refusal`)
    assert.deepEqual(runFolders(m.checkout.root), [], `${JSON.stringify(args)}: the runner made a log folder`)
    assert.equal(existsSync(join(m.checkout.root, '.aos', 'install.lock')), false, 'the lock was left behind')
    assert.equal(printed.includes('aos-dotenv-trap'), false, 'a byte of the trap was printed')
  }
})

test("aos-install refuses a token an earlier run's write cut short, by its line, exits 2 and leaves .env byte for byte", async (t) => {
  // `writing .env failed after 23 of 81 bytes (EFBIG)`: the last line is AOS_PMMCP_TOKEN and 7 hex characters, no newline. The
  // installer judges the tokens it mints at S2, so this is a refusal, never a token whose digest is staged as pmmcp's bearer.
  for (const args of [['--aos-only'], ['--aos-only', '--dry-run'], ['--dry-run']]) {
    const m = await installerMachine(t, { trap: false })
    const env = join(m.checkout.root, '.env')
    writeFileSync(env, `# Created by npm run aos-install\nAOS_CONTROL_TOKEN=${'c'.repeat(64)}\nAOS_PMMCP_TOKEN=5b8bca5`, { mode: 0o600 })
    chmodSync(env, 0o600)
    handOver(env)
    const before = readFileSync(env)
    const run = installer(m, args)
    const printed = `${run.stdout}${run.stderr}`
    assert.equal(run.status, 2, `${JSON.stringify(args)}: ${printed}`)
    assert.match(run.stdout, /^ {2}AOS_PMMCP_TOKEN +cut short \(line 3\) -> delete that line and re-run/m, JSON.stringify(args))
    assert.match(run.stdout, /^ {2}- .*\.env line 3: AOS_PMMCP_TOKEN looks cut short \(a write that did not finish\): delete that line and re-run\./m, JSON.stringify(args))
    assert.equal(run.stdout.trimEnd().split('\n').at(-1), 'aos-install: exit 2: refused before any change: see above', JSON.stringify(args))
    assert.deepEqual(readFileSync(env), before, `${JSON.stringify(args)}: .env changed`)
    // No digest of it was handed to anything: no python ran at all.
    assert.equal(m.calls().some((l) => /python|rotate|http_auth/.test(l)), false, m.calls().join('\n'))
    assert.equal(printed.includes('5b8bca5'), false, 'a byte of the value was printed')
  }
})

test("aos-install refuses, before any change and with exit 2, a program on the child's PATH that is pmmcp's stop script by identity, naming the file and the fix", async (t) => {
  // ~/.local/bin/lsof a hard link of the stop script where discovery looks first (~/Github/Persistent-Memory-MCP): the runner refuses the
  // first lsof discovery runs. That is the machine's state, not a defect of the installer's (scenario 12's ps and start cases).
  const m = await installerMachine(t, { trap: false })
  const install = join(m.home, 'Github', 'Persistent-Memory-MCP')
  mkdirSync(install, { recursive: true })
  const stop = join(install, 'stop-pmmcp-server.sh')
  writeFileSync(stop, '#!/bin/sh\necho "the stop ran" >&2\nexit 99\n', { mode: 0o755 })
  const lsof = join(m.home, '.local', 'bin', 'lsof')
  rmSync(lsof)
  linkSync(stop, lsof)
  handOver(m.home)
  for (const args of [['--dry-run'], []]) {
    const run = installer(m, args)
    const printed = `${run.stdout}${run.stderr}`
    assert.equal(run.status, 2, `${JSON.stringify(args)}: ${printed}`)
    assert.ok(
      run.stdout.includes(
        `refused before any change: lsof-8766: stop-pmmcp-server.sh runs only by absolute path, and lsof on the child's PATH is ${lsof}, which is the same file as ${realpathSync(stop)} (a hard link): ` +
          'remove or rename that file, then re-run; nothing was run',
      ),
      printed,
    )
    assert.equal(run.stdout.trimEnd().split('\n').at(-1), 'aos-install: exit 2: refused before any change: see above', JSON.stringify(args))
    assert.doesNotMatch(printed, /a defect|the stop ran/)
    assert.equal(existsSync(join(m.checkout.root, '.env')), false)
  }
})

test('aos-install --dry-run with an empty HOME finds no pmmcp, prints the plan and writes nothing', async (t) => {
  const m = await installerMachine(t, { trap: false })
  const root = m.checkout.root
  const checkoutBefore = snapshot(root)
  const homeBefore = snapshot(m.home)
  // Names the installer's children must never see: a Colima DOCKER_CONFIG and a name in pmmcp's PMMCP_ prefix (a checkout up to 53ea308 refuses to start under it).
  const run = await installerAsync(m, ['--dry-run'], { DOCKER_CONFIG: '/nonexistent/colima-docker', PMMCP_DEBUG: '1' })
  const printed = `${run.stdout}${run.stderr}`
  assert.equal(run.status, 0, printed)

  // S1, by name only, then discovery's finding: no pmmcp anywhere it looked.
  assert.match(run.stdout, /exports {5}DOCKER_CONFIG and PMMCP_DEBUG: pmmcp's commands run without them/)
  assert.match(run.stdout, /pmmcp {6}not found \(looked at .*com\.aibot\.pmmcp\.plist.*the listener on 127\.0\.0\.1:8766.*Github\/Persistent-Memory-MCP\)/)
  assert.match(run.stdout, /^kernel {5}kernel\.yaml url matches; pmmcp tokenEnv AOS_PMMCP_TOKEN; AOS daemon listening on \d+$/m)
  // That it listens, and no restart: nothing it reads changes in a dry run (the end report asks one only when something did).
  assert.match(run.stdout, /^ {2}- the AOS daemon listens on \d+: it reads \.env when it starts, and the end report's next steps say whether this run needs it restarted$/m)
  assert.doesNotMatch(run.stdout, /restart it after this run|^ {2}restart npm run dev \(it reads \.env when it starts\)/m)
  // The plan: .env by name, the fresh install it would make, every step as would-do, and the typed word it would ask.
  assert.match(run.stdout, /^\.env {2}.*\.env {2}absent \(created at 0600 when something is appended\)$/m)
  assert.match(run.stdout, /^ {2}AOS_CONTROL_TOKEN +missing {2}-> will be generated \(64 hex\)$/m)
  assert.match(run.stdout, /^ {2}AOS_PMMCP_TOKEN +missing {2}-> will be generated \(64 hex\)$/m)
  assert.match(run.stdout, /^ {2}ANTHROPIC_API_KEY +missing {2}-> add it yourself; the installer never writes it$/m)
  assert.match(run.stdout, /pmmcp {2}not installed: a fresh install at .*\/Github\/Persistent-Memory-MCP/)
  assert.match(run.stdout, /^would 1\. \[AOS file\] create .*\.env at 0600 with AOS_CONTROL_TOKEN and AOS_PMMCP_TOKEN \(/m)
  // The declared bearer reaches pmmcp as its digest alone, staged by the fresh install.
  assert.match(run.stdout, /^would \d+\. \[fresh install\] stage the aos-kernel digest of AOS_PMMCP_TOKEN in /m)
  assert.match(run.stdout, /^would \d+\. \[fresh install\] clone pmmcp to /m)
  assert.match(run.stdout, /would ask you to type `install` before anything is installed/)
  assert.match(run.stdout, /dry run: nothing was changed, nothing was stopped or started \(probe output in .*\.aos\/install\/\d{8}T\d{6}Z\)/)
  // Its last line is its own exit code, the run's word whatever npm's own status says after a Ctrl-C it forwarded.
  assert.equal(run.stdout.trimEnd().split('\n').at(-1), 'aos-install: exit 0: a dry run: nothing was changed, stopped or started')
  // In plan §5's order: S1, S2 (.env), S3 (what discovery found), then the plan.
  const lines = run.stdout.split('\n')
  const order = [/^preflight:$/, /^\.env {2}/, /^pmmcp {6}not found/, /^discovery notes:$/, /^plan:$/].map((re) => lines.findIndex((l) => re.test(l)))
  assert.ok(order.every((n, i) => n >= 0 && (i === 0 || n > (order[i - 1] ?? 0))), `out of order (${order.join(', ')}):\n${run.stdout}`)

  // Only the probes an empty HOME gets ran, and none of them saw a DOCKER_*, PMMCP_* or AOS_* name.
  const calls = m.calls()
  assert.deepEqual(
    calls.filter((l) => !l.startsWith('env ')),
    ['lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', 'docker context show', 'docker info --format {{.ServerVersion}}'],
    calls.join('\n'),
  )
  for (const line of calls.filter((l) => l.startsWith('env '))) assert.doesNotMatch(line, /\b(?:DOCKER|PMMCP|AOS)_/, line)
  // The daemon probe was a bare GET on loopback: no credential, nothing else asked.
  assert.deepEqual(m.requests.map((r) => `${r.method ?? ''} ${r.url ?? ''}`), ['GET /'])
  assert.equal(m.requests[0]?.headers.authorization, undefined)

  // Nothing changed but the probes' logs: no .env, no lock, no active.json, nothing in HOME.
  const stamps = runFolders(root)
  assert.equal(stamps.length, 1, JSON.stringify(stamps))
  const logs = `.aos/install/${stamps[0] ?? ''}`
  const diff = changed(checkoutBefore, snapshot(root)).filter((p) => p !== logs && !p.startsWith(`${logs}/`))
  assert.deepEqual(diff, ['.aos', '.aos/install'], `the dry run changed the checkout: ${diff.join(', ')}`)
  assert.deepEqual(readdirSync(join(root, logs)).sort(), ['docker-context.err', 'docker-context.out', 'docker-info.err', 'docker-info.out', 'lsof-8766.err', 'lsof-8766.out'])
  assert.equal(existsSync(join(root, '.env')), false, 'the dry run created .env')
  assert.equal(existsSync(join(root, '.aos', 'install.lock')), false, 'the lock was left behind')
  assert.equal(existsSync(join(root, '.aos', 'install', 'active.json')), false)
  assert.deepEqual(changed(homeBefore, snapshot(m.home)), [], 'the dry run changed HOME')
})

test('aos-install with stdin not a terminal prints the plan and exits 3', async (t) => {
  // Changes are needed (no .env; no pmmcp), and a pipe of "y" lines is no
  // operator: the gate ends the run before its first prompt.
  const m = await installerMachine(t, { trap: false })
  const run = await installerAsync(m, [])
  assert.equal(run.status, 3, `${run.stdout}${run.stderr}`)
  assert.match(run.stdout, /pmmcp {2}not installed: a fresh install at /)
  assert.match(run.stdout, /^ {2}\d+\. \[fresh install\] clone pmmcp to /m)
  assert.match(run.stdout, /stdin is not a terminal: changes are needed, and only an operator at a terminal may confirm them, so nothing was changed/)
  // Its hint names the dry run as npm must be given it: after --.
  assert.match(run.stdout, /\(or npm run aos-install -- --dry-run /)
  assert.doesNotMatch(run.stdout, /\[y\/N\]|Type `install`/, 'a question was asked of a pipe')
  assert.equal(run.stdout.trimEnd().split('\n').at(-1), 'aos-install: exit 3: changes are needed, but stdin is not a terminal: nothing was changed')
  assert.equal(existsSync(join(m.checkout.root, '.env')), false, '.env was written')
  assert.deepEqual(m.calls().filter((l) => !l.startsWith('env ')), ['lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', 'docker context show', 'docker info --format {{.ServerVersion}}'])

  // --aos-only: the .env screen alone, no probe at all, and the same refusal to act.
  const aos = await installerMachine(t, { trap: false })
  const only = installer(aos, ['--aos-only'])
  assert.equal(only.status, 3, `${only.stdout}${only.stderr}`)
  assert.match(only.stdout, /pmmcp {2}not touched \(--aos-only\)/)
  assert.match(only.stdout, /^ {2}1\. \[AOS file\] create .*\.env at 0600 with AOS_CONTROL_TOKEN/m)
  assert.match(only.stdout, /stdin is not a terminal/)
  assert.equal(existsSync(join(aos.checkout.root, '.env')), false)
  assert.deepEqual(aos.calls(), [])
  assert.deepEqual(runFolders(aos.checkout.root), [], 'a program ran for --aos-only')
})

test('aos-install at a terminal: the input ending at its question aborts with exit 130, nothing changed, and its last line says the input ended', async (t) => {
  // The one prompt an empty HOME gets is the fresh install's typed word. The
  // end of the input there is no "no" to a question the installer can go on
  // past: the run ends, and its last line, the run's word, says how.
  if (!terminalAvailable()) {
    t.diagnostic('no python3 with its pty module here, so no terminal can be given to the installer: the exit line is held in process only')
    return
  }
  const m = await installerMachine(t, { trap: false })
  const child = spawnEntry(m.checkout, 'scripts/install.ts', [], { env: installerEnv(m), eofAfter: 'Type `install` to begin', ...INSTALLER_AS })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
  child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')))
  const timer = setTimeout(() => child.kill('SIGKILL'), 90_000)
  const status = await new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)))
  clearTimeout(timer)
  const text = stdout.replace(/\r\n/g, '\n')
  assert.equal(status, 130, `${text}${stderr}`)
  assert.match(text, /^ {2}\d+\. \[fresh install\] clone pmmcp to /m)
  assert.match(text, /^aborted \(the input ended\): nothing live was done, nothing was installed, and nothing was changed$/m)
  assert.equal(text.trimEnd().split('\n').at(-1), 'aos-install: exit 130: aborted, the input ended at a question: nothing was changed')
  assert.doesNotMatch(text, /Ctrl-C/)
  assert.equal(existsSync(join(m.checkout.root, '.env')), false, '.env was written')
  assert.equal(existsSync(join(m.checkout.root, '.aos', 'install.lock')), false, 'the lock was left behind')
  assert.deepEqual(m.calls().filter((l) => !l.startsWith('env ')), ['lsof -nP -iTCP:8766 -sTCP:LISTEN -Fpu', 'docker context show', 'docker info --format {{.ServerVersion}}'])
})

/** A /bin/sh stand-in for one of a fresh checkout's programs: it logs its name and arguments, then runs `body`. */
const standIn = (log: string, name: string, body: string): string =>
  ['#!/bin/sh', `# a stand-in for pmmcp's ${name}`, `{ printf '%s' ${shQuote(name)}; for a in "$@"; do printf ' %s' "$a"; done; printf '\\n'; } >> ${shQuote(log)}`, body, ''].join('\n')

const shQuote = (s: string): string => `'${s.replace(/'/g, "'\\''")}'`

/** The facts document of the checkout a fresh install cloned to `at`: every feature, pmmcp's own ports on loopback, http_auth holding `tokens`. */
const freshFacts = (home: string, at: string, tokens: readonly string[]): string =>
  JSON.stringify({
    facts: 1,
    dir: at,
    git: { head: 'e6516d5'.padEnd(40, '0'), branch: 'main', dirty: false, origin: 'https://github.com/AiBot-Tools/persistent-memory-mcp.git' },
    features: { bearer_gate: true, rotate_digest_stdin: true, check_expect: true, qdrant_key_script: true, qdrant_init: true, qdrant_status_json: true, dashboard_auth: true, curator_secret: true, stop_jobs_flag: true, stop_engine_guard: true, curator_proof: true, stop_listener_check: true },
    config: {
      source: join(home, '.persistent-memory-mcp', 'config.yaml'),
      server: { host: '127.0.0.1', port: 8766, enabled: true },
      dashboard: { host: '127.0.0.1', port: 8765, enabled: true, legacy_token_key: false },
      curator: { host: '127.0.0.1', port: 8767, enabled: true },
    },
    env_overrides: [],
    http_auth: { state: tokens.length === 0 ? 'absent' : 'present', mode: tokens.length === 0 ? null : 'warn', tokens, reason: null, links: tokens.length === 0 ? null : 1 },
    qdrant_key_file: { state: 'absent' },
    dashboard_token: { state: 'absent' },
    curator_secret: { state: 'absent' },
    launchd: { plist: join(home, 'Library', 'LaunchAgents', 'com.aibot.pmmcp.plist'), exists: true, working_directory: at, legacy_plists: [] },
  })

test('aos-install at a terminal: a Ctrl-C after the stopped window is held until the end report, the probe it reached is asked again, and the run ends with the gate\'s code', async (t) => {
  // A fresh install whose stop does not stop, with "start pmmcp again?" answered n: the window opened (setup) and closed (the
  // question), and the run owes its report. The facts are read again for it, and the Ctrl-C typed while that probe runs reaches the
  // probe (the terminal signals its whole foreground group), which dies by SIGINT. The installer holds the signal (main wires the
  // applier's window to it), asks the probe again, prints the report with what the second answer said, says why it went on, and ends
  // with exit 4, the live step's code, never 130.
  if (!terminalAvailable()) {
    t.diagnostic('no python3 with its pty module here, so no terminal can be given to the installer')
    return
  }
  const m = await installerMachine(t, { trap: false })
  const base = dirname(m.home)
  const log = join(base, 'calls', 'fresh.log')
  const marks = join(base, 'marks')
  mkdirSync(marks)
  const at = join(m.home, 'Github', 'Persistent-Memory-MCP')
  const factsDoc = (tokens: readonly string[]): string => freshFacts(m.home, at, tokens)
  // What the clone copies: setup, the stop (which does not stop), the start, and the venv's python, whose facts are read three times:
  // after setup; for the report, held until the test's Ctrl-C ends it (its start leaves a mark); and again, as the second answer.
  const template = join(base, 'template')
  mkdirSync(join(template, '.venv', 'bin'), { recursive: true })
  writeFileSync(join(base, 'facts-1.json'), `${factsDoc([])}\n`)
  writeFileSync(join(base, 'facts-2.json'), `${factsDoc(['aos-kernel'])}\n`)
  const count = join(base, 'facts.count')
  const reading = join(marks, 'facts-after-started')
  const files: [string, string][] = [
    ['setup.sh', standIn(log, 'setup.sh', 'exit 0')],
    ['stop-pmmcp-server.sh', standIn(log, 'stop-pmmcp-server.sh', "echo 'pmmcp-worker FAILED TO STOP' >&2\nexit 1")],
    ['start-pmmcp-server.sh', standIn(log, 'start-pmmcp-server.sh', 'exit 0')],
    [
      join('.venv', 'bin', 'python'),
      standIn(
        log,
        'python',
        [
          'case "$*" in',
          "  'scripts/pmmcp_facts.py --json')",
          `    n=$(cat ${shQuote(count)} 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > ${shQuote(count)}`,
          `    if [ "$n" = 1 ]; then cat ${shQuote(join(base, 'facts-1.json'))}; exit 0; fi`,
          `    if [ "$n" = 2 ]; then : > ${shQuote(reading)}; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; cat ${shQuote(join(base, 'facts-1.json'))}; exit 0; fi`,
          `    cat ${shQuote(join(base, 'facts-2.json'))}; exit 0 ;;`,
          'esac',
          'exit 97',
        ].join('\n'),
      ),
    ],
  ]
  for (const [rel, body] of files) writeFileSync(join(template, rel), body, { mode: 0o755 })
  writeFileSync(join(m.home, '.local', 'bin', 'git'), standIn(log, 'git', `if [ "$1" = clone ] && [ "$#" = 3 ]; then mkdir -p "$(dirname "$3")" && cp -Rp ${shQuote(template)} "$3"; exit $?; fi\nexit 97`), { mode: 0o755 })
  handOver(base)

  const child = spawnEntry(m.checkout, 'scripts/install.ts', [], {
    env: installerEnv(m),
    typed: [
      { cue: 'Type `install` to begin', send: 'install\r', delayMs: 300 },
      { cue: 'start pmmcp again to restore service?', send: 'n\r', delayMs: 300 },
      { file: reading, send: '\x03', delayMs: 100 },
    ],
    ...INSTALLER_AS,
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
  child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')))
  const timer = setTimeout(() => child.kill('SIGKILL'), 120_000)
  const status = await new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)))
  clearTimeout(timer)
  const text = stdout.replace(/\r\n/g, '\n')
  const lines = text.trimEnd().split('\n')
  const calls = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter((l) => l !== '') : []
  const said = `${text}${stderr}\n${calls.join('\n')}`

  assert.equal(status, 4, said)
  assert.ok(existsSync(reading), `the facts were never read for the report:\n${said}`)
  // The window ran: setup, the stop that did not stop, and no start (the question was answered n).
  assert.deepEqual(calls.filter((c) => !c.startsWith('python')), [`git clone https://github.com/AiBot-Tools/persistent-memory-mcp.git ${at}`, 'setup.sh --non-interactive', 'stop-pmmcp-server.sh'], said)
  // The Ctrl-C was held: said at once, and the run went on to its report.
  assert.ok(
    text.includes('Ctrl-C does not end the run yet: the stopped window opened in this run, so the installer finishes its last checks and prints the end report (what was done, and what is left to do) first.'),
    said,
  )
  // The probe it reached was asked again, and the report says what that answer said: the facts after this run's changes.
  assert.equal(calls.filter((c) => c === 'python scripts/pmmcp_facts.py --json').length, 3, said)
  assert.ok(text.includes('facts-after: ended by Ctrl-C, which does not end the run before its end report: asked again'), said)
  assert.ok(lines.includes('pmmcp bearer: http_auth.yaml present, mode warn, tokens [aos-kernel]'), said)
  assert.equal(text.includes('could not check'), false, said)
  assert.ok(lines.includes('end report:'), said)
  // Its last two lines: what the held signal waited for, and the gate's own code with the report named.
  assert.equal(lines.at(-2), 'Ctrl-C came after the stopped window; the installer finished its checks and printed the end report above first', said)
  assert.equal(lines.at(-1), 'aos-install: exit 4: a live step failed, and pmmcp is not in its intended state: see the end report above', said)
  assert.equal(existsSync(join(m.checkout.root, '.aos', 'install.lock')), false, 'the lock was left behind')
})

test("aos-install at a terminal: a registered value in what is read again for the end report stops the run there, and the report is still printed, with the defect, the emptied file and the manual start (exit 4)", async (t) => {
  // A fresh install whose stop refuses its arguments (exit 2: nothing more of the window runs, exit 1 so far). The facts are read
  // again for the report, and that read echoes the AOS_PMMCP_TOKEN this run appended to the shadow checkout's .env. main's recheck
  // reports it as a leak inside the window is reported: its report is printed, its last line is exit 4 (setup ran, so pmmcp may be
  // up or half up), never "failed (a defect, report it)" with no report, and the value is never printed.
  if (!terminalAvailable()) {
    t.diagnostic('no python3 with its pty module here, so no terminal can be given to the installer')
    return
  }
  const m = await installerMachine(t, { trap: false })
  const base = dirname(m.home)
  const log = join(base, 'calls', 'fresh.log')
  const at = join(m.home, 'Github', 'Persistent-Memory-MCP')
  const env = join(m.checkout.root, '.env')
  const template = join(base, 'template')
  mkdirSync(join(template, '.venv', 'bin'), { recursive: true })
  writeFileSync(join(base, 'facts-1.json'), `${freshFacts(m.home, at, [])}\n`)
  const count = join(base, 'facts.count')
  const files: [string, string][] = [
    ['setup.sh', standIn(log, 'setup.sh', 'exit 0')],
    ['stop-pmmcp-server.sh', standIn(log, 'stop-pmmcp-server.sh', "echo 'unknown argument' >&2\nexit 2")],
    ['start-pmmcp-server.sh', standIn(log, 'start-pmmcp-server.sh', 'exit 0')],
    [
      join('.venv', 'bin', 'python'),
      standIn(
        log,
        'python',
        [
          'case "$*" in',
          "  'scripts/pmmcp_facts.py --json')",
          `    n=$(cat ${shQuote(count)} 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > ${shQuote(count)}`,
          `    if [ "$n" = 1 ]; then cat ${shQuote(join(base, 'facts-1.json'))}; exit 0; fi`,
          // The second read, for the report: a defect of pmmcp's that prints the bearer it was handed.
          `    printf '{"echo": "%s"}\\n' "$(sed -n 's/^AOS_PMMCP_TOKEN=//p' ${shQuote(env)})"; exit 0 ;;`,
          'esac',
          'exit 97',
        ].join('\n'),
      ),
    ],
  ]
  for (const [rel, body] of files) writeFileSync(join(template, rel), body, { mode: 0o755 })
  writeFileSync(join(m.home, '.local', 'bin', 'git'), standIn(log, 'git', `if [ "$1" = clone ] && [ "$#" = 3 ]; then mkdir -p "$(dirname "$3")" && cp -Rp ${shQuote(template)} "$3"; exit $?; fi\nexit 97`), { mode: 0o755 })
  handOver(base)

  const child = spawnEntry(m.checkout, 'scripts/install.ts', [], {
    env: installerEnv(m),
    typed: [{ cue: 'Type `install` to begin', send: 'install\r', delayMs: 300 }],
    ...INSTALLER_AS,
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
  child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')))
  const timer = setTimeout(() => child.kill('SIGKILL'), 120_000)
  const status = await new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)))
  clearTimeout(timer)
  const text = stdout.replace(/\r\n/g, '\n')
  const lines = text.trimEnd().split('\n')
  const calls = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter((l) => l !== '') : []
  const said = `${text}${stderr}\n${calls.join('\n')}`

  assert.equal(status, 4, said)
  // The window ran setup and the stop, which refused its arguments: nothing after it, and the facts were read twice.
  assert.deepEqual(calls.filter((c) => !c.startsWith('python')), [`git clone https://github.com/AiBot-Tools/persistent-memory-mcp.git ${at}`, 'setup.sh --non-interactive', 'stop-pmmcp-server.sh'], said)
  assert.equal(calls.filter((c) => c === 'python scripts/pmmcp_facts.py --json').length, 2, said)
  // The report came, with the leak as its defect, the file it emptied, and the manual start.
  assert.ok(lines.includes('end report:'), said)
  const defect = lines.find((l) => l.startsWith('stopped by a defect: '))
  assert.ok(defect !== undefined, said)
  const emptied = /: (\/\S+\/facts-after(?:-\d+)?\.out)$/.exec(defect)?.[1]
  assert.ok(emptied !== undefined, defect)
  assert.equal(readFileSync(emptied, 'utf8'), '', 'the file that held the value was not emptied')
  assert.ok(lines.includes(`  pmmcp may be stopped: start it with cd ${at} && ./start-pmmcp-server.sh`), said)
  assert.ok(lines.includes('next steps:'), said)
  assert.doesNotMatch(said, /failed \(a defect, report it\)/)
  assert.equal(lines.at(-1), 'aos-install: exit 4: a live step failed, and pmmcp is not in its intended state: see the end report above', said)
  // The value reached no line the installer printed.
  const token = /^AOS_PMMCP_TOKEN=([0-9a-f]{64})$/m.exec(readFileSync(env, 'utf8'))?.[1]
  assert.ok(token !== undefined, 'the run appended no AOS_PMMCP_TOKEN')
  assert.equal(`${stdout}${stderr}`.includes(token), false, 'the token was printed')
  assert.equal(existsSync(join(m.checkout.root, '.aos', 'install.lock')), false, 'the lock was left behind')
})

/**
 * An install found where discovery looks first (~/Github/Persistent-Memory-MCP), its programs /bin/sh stand-ins that log to `log`:
 * stopped (nothing listens on 8766), every feature but Qdrant's status document (so none is read), the aos-kernel digest on file and
 * matching the AOS_PMMCP_TOKEN of a .env that holds both tokens, no dashboard token or curator secret yet, and no job running.
 */
function foundInstall(m: InstallerMachine): { readonly at: string; readonly log: string } {
  const base = dirname(m.home)
  const log = join(base, 'calls', 'found.log')
  const at = join(m.home, 'Github', 'Persistent-Memory-MCP')
  mkdirSync(join(at, '.venv', 'bin'), { recursive: true })
  mkdirSync(join(at, '.git'))
  mkdirSync(join(at, 'scripts'))
  writeFileSync(join(at, 'scripts', 'pmmcp_facts.py'), '# read by the python stand-in\n')
  writeFileSync(join(at, 'pyproject.toml'), '[project]\nname = "persistent-memory-mcp"\n')
  writeFileSync(join(at, '.git', 'config'), '[remote "origin"]\n\turl = https://github.com/AiBot-Tools/persistent-memory-mcp.git\n')
  writeFileSync(join(at, '.venv', 'bin', 'pmmcp'), standIn(log, 'pmmcp', 'exit 97'), { mode: 0o755 })
  const facts = JSON.parse(freshFacts(m.home, at, ['aos-kernel'])) as { features: Record<string, boolean> }
  facts.features['qdrant_status_json'] = false
  writeFileSync(join(base, 'facts.json'), `${JSON.stringify(facts)}\n`)
  writeFileSync(
    join(at, '.venv', 'bin', 'python'),
    standIn(
      log,
      'python',
      [
        'case "$*" in',
        `  'scripts/pmmcp_facts.py --json') cat ${shQuote(join(base, 'facts.json'))}; exit 0 ;;`,
        "  '-B -m src.transport.http_auth check --expect aos-kernel') read -r digest; echo 'aos-kernel: matches'; exit 0 ;;",
        'esac',
        'exit 97',
      ].join('\n'),
    ),
    { mode: 0o755 },
  )
  writeFileSync(join(at, 'stop-pmmcp-server.sh'), standIn(log, 'stop-pmmcp-server.sh', 'if [ "$*" = --jobs ]; then echo "running jobs: 0"; exit 0; fi\nexit 97'), { mode: 0o755 })
  writeFileSync(join(at, 'start-pmmcp-server.sh'), standIn(log, 'start-pmmcp-server.sh', 'exit 97'), { mode: 0o755 })
  const env = join(m.checkout.root, '.env')
  writeFileSync(env, `AOS_CONTROL_TOKEN=${'c'.repeat(64)}\nAOS_PMMCP_TOKEN=${'d'.repeat(64)}\n`, { mode: 0o600 })
  chmodSync(env, 0o600)
  handOver(env)
  return { at, log }
}

test("aos-install at a terminal: for a found pmmcp whose ~/.local/bin/pgrep gives no answer, the warning says whether a TUI runs cannot be told, never that none runs", async (t) => {
  // main hands the planner what the TUI check said as it is: undefined when pgrep gave no answer (here it exits 3), never [], which
  // the warning would read as "none runs now" of a scripts/monitor_tui.py that may be running. A found install, stopped, with both
  // tokens in .env and the aos-kernel digest on file: the one offer is the dashboard token and curator secret (live), so the window's
  // warning is printed, and the first typed confirmation is answered with another word, so nothing is stopped or changed.
  if (!terminalAvailable()) {
    t.diagnostic('no python3 with its pty module here, so no terminal can be given to the installer')
    return
  }
  const m = await installerMachine(t, { trap: false })
  const { at, log } = foundInstall(m)
  // pgrep gives no answer: neither its pids (exit 0) nor "none" (exit 1 with nothing printed).
  writeFileSync(join(m.home, '.local', 'bin', 'pgrep'), standIn(log, 'pgrep', 'exit 3'), { mode: 0o755 })
  handOver(dirname(m.home))

  const child = spawnEntry(m.checkout, 'scripts/install.ts', [], {
    env: installerEnv(m),
    typed: [
      { cue: 'Create the dashboard token and curator secret (live)? [y/N]', send: 'y\r', delayMs: 300 },
      { cue: 'Type `stop pmmcp` to continue', send: 'not now\r', delayMs: 300 },
    ],
    ...INSTALLER_AS,
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
  child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')))
  const timer = setTimeout(() => child.kill('SIGKILL'), 120_000)
  const status = await new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)))
  clearTimeout(timer)
  const text = stdout.replace(/\r\n/g, '\n')
  const lines = text.trimEnd().split('\n')
  const calls = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter((l) => l !== '') : []
  const said = `${text}${stderr}\n${calls.join('\n')}`

  assert.equal(status, 0, said)
  assert.ok(calls.includes('pgrep -f scripts/monitor_tui\\.py'), said)
  assert.ok(lines.some((l) => l.startsWith('  - whether a scripts/monitor_tui.py runs cannot be told (pgrep gave no answer)')), said)
  // The warning, twice over (what does not stop, and the curator secret's quit-first line), says it cannot be told; never that none runs.
  const blind = 'whether one runs cannot be told: pgrep gave no answer'
  assert.ok(lines.includes(`What does not stop: a scripts/monitor_tui.py of ${at} (${blind}).`), said)
  assert.ok(lines.some((l) => l.startsWith(`Quit any scripts/monitor_tui.py of ${at} first (${blind}), and start none until this run ends`)), said)
  assert.doesNotMatch(text, /none runs now/)
  // Nothing was stopped or changed: the stop ran only to count jobs, the start never, and the run ended at the first typed word.
  assert.deepEqual(calls.filter((c) => /-pmmcp-server\.sh/.test(c)), ['stop-pmmcp-server.sh --jobs'], said)
  assert.equal(lines.at(-1), 'aos-install: exit 0: declined: nothing was changed', said)
  assert.equal(existsSync(join(m.checkout.root, '.aos', 'install.lock')), false, 'the lock was left behind')
})

test("aos-install refuses, before any change and with exit 2, a ~/.local/bin/pgrep that is the found pmmcp's stop script by hard link: the TUI check names the file and the fix, never 'cannot be told'", async (t) => {
  // Discovery's probes pass (none of them is pgrep); the TUI check after it is the first to run pgrep, which the runner refuses for
  // the machine's state. That is a refusal with its fix (exit 2), as discovery's own would be, never read as pgrep giving no answer.
  const m = await installerMachine(t, { trap: false })
  const { at, log } = foundInstall(m)
  const stop = join(at, 'stop-pmmcp-server.sh')
  const pgrep = join(m.home, '.local', 'bin', 'pgrep')
  rmSync(pgrep)
  linkSync(stop, pgrep)
  handOver(dirname(m.home))
  for (const args of [['--dry-run'], []]) {
    rmSync(log, { force: true })
    const run = await installerAsync(m, args)
    const printed = `${run.stdout}${run.stderr}`
    assert.equal(run.status, 2, `${JSON.stringify(args)}: ${printed}`)
    assert.ok(
      run.stdout.includes(
        `refused before any change: pgrep-tui: stop-pmmcp-server.sh runs only by absolute path, and pgrep on the child's PATH is ${pgrep}, which is the same file as ${realpathSync(stop)} (a hard link): ` +
          'remove or rename that file, then re-run; nothing was run',
      ),
      printed,
    )
    assert.equal(run.stdout.trimEnd().split('\n').at(-1), 'aos-install: exit 2: refused before any change: see above', JSON.stringify(args))
    assert.doesNotMatch(printed, /a defect|cannot be told|plan:/)
    // The stop script ran only as discovery's jobs count, by its own path: never as pgrep.
    const calls = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter((l) => l !== '') : []
    assert.deepEqual(calls.filter((c) => c.startsWith('stop-pmmcp-server.sh')), ['stop-pmmcp-server.sh --jobs'], printed)
  }
})

test('aos-install rejects an unknown flag with usage and exit 2', async (t) => {
  const m = await installerMachine(t, { trap: true })
  const before = snapshot(m.checkout.root)
  // Neither --yes nor --force exists; a repeat, a flag without its value, and --aos-only beside a pmmcp flag are refused too.
  for (const args of [
    ['--yes'],
    ['--force'],
    ['-y'],
    ['install'],
    ['--dry-run', '--dry-run'],
    ['--pmmcp-dir'],
    ['--pmmcp-dir', '--dry-run'],
    ['--pmmcp-dir=-x'],
    ['--help', '-h'],
    ['--aos-only', '--pmmcp-dir', '/tmp'],
    ['--aos-only', '--no-install'],
  ]) {
    const run = installer(m, args)
    assert.equal(run.status, 2, `${JSON.stringify(args)}: ${run.stdout}${run.stderr}`)
    assert.match(run.stderr, /usage: npm run aos-install/, JSON.stringify(args))
    assert.match(run.stderr, /There is no --yes and no --force/)
    assert.match(run.stderr, /130 for\nany of them at a question or during the jobs count\)\. Once the window opened, a signal waits for the end report\./)
    assert.equal(run.stdout, '', `${JSON.stringify(args)}: printed more than usage`)
  }
  // Refused before anything was looked at: not even the lock's folder was made.
  assert.deepEqual(changed(before, snapshot(m.checkout.root)), [])
  assert.deepEqual(m.calls(), [])
  // A flag's value that starts with - is a flag, not a path.
  assert.match(installer(m, ['--pmmcp-dir', '--dry-run']).stderr, /^--pmmcp-dir needs a path$/m)
  for (const flag of ['--help', '-h']) {
    const help = installer(m, [flag])
    assert.equal(help.status, 0, `${flag}: ${help.stderr}`)
    assert.match(help.stdout, /--dry-run {10}discover and plan only/, flag)
    assert.match(help.stdout, /The flags go after --, as in npm run aos-install -- --dry-run/, flag)
    // Usage is no run: it has no exit line.
    assert.doesNotMatch(help.stdout, /^aos-install: exit/m, flag)
  }
  assert.deepEqual(changed(before, snapshot(m.checkout.root)), [])
})

test('aos-install refuses a flag npm took as its own (a flag before --): usage, exit 2, nothing looked at', async (t) => {
  // npm 10 reads `npm run aos-install --dry-run` as its own --dry-run: the
  // script gets no argument and npm_config_dry_run=true, so without this the
  // "dry run" is a real run, and `--aos-only` so given touches pmmcp. npm
  // leaves these names (`--no-install` sets npm_config_install to '';
  // `--pmmcp-dir PATH` sets npm_config_pmmcp_dir and hands PATH on as an
  // argument).
  const m = await installerMachine(t, { trap: false })
  const before = snapshot(m.checkout.root)
  const homeBefore = snapshot(m.home)
  const cases: readonly (readonly [Record<string, string>, readonly string[], string])[] = [
    [{ npm_config_dry_run: 'true' }, [], '--dry-run'],
    [{ npm_config_aos_only: 'true' }, [], '--aos-only'],
    [{ npm_config_pmmcp_dir: 'true' }, ['/tmp/x'], '--pmmcp-dir'],
    [{ npm_config_help: 'true' }, [], '--help'],
    [{ npm_config_install: '' }, [], '--no-install'],
    [{ npm_config_dry_run: 'true', npm_config_aos_only: 'true' }, ['--dry-run'], '--dry-run and --aos-only'],
  ]
  for (const [env, args, named] of cases) {
    const run = installer(m, args, env)
    const what = JSON.stringify(env)
    assert.equal(run.status, 2, `${what}: ${run.stdout}${run.stderr}`)
    assert.equal(run.stdout, '', `${what}: it went on to the preflight`)
    assert.ok(run.stderr.startsWith(`npm took ${named} as its own option`), `${what}: ${run.stderr}`)
    assert.match(run.stderr, /put the installer's flags after --, as in npm run aos-install -- --dry-run/)
    assert.match(run.stderr, /usage: npm run aos-install/)
  }
  assert.deepEqual(changed(before, snapshot(m.checkout.root)), [], 'a refused run wrote in the checkout')
  assert.deepEqual(changed(homeBefore, snapshot(m.home)), [])
  assert.deepEqual(m.calls(), [])
})

test('aos-install refuses at the preflight, before the lock or any program: root, a HOME with a colon, a .gitignore that ignores neither .env nor /.aos/, Node outside engines, a missing credential helper', async (t) => {
  // Each refusal is printed with its fix, and nothing is made: no .aos (the
  // lock's folder), no log folder, no program run.
  const refusedAt = (m: InstallerMachine, run: { status: number | null; stdout: string; stderr: string }, why: RegExp): void => {
    assert.equal(run.status, 2, `${run.stdout}${run.stderr}`)
    assert.match(run.stdout, /^refused before any change:$/m)
    assert.match(run.stdout, why)
    assert.equal(existsSync(join(m.checkout.root, '.aos')), false, 'the lock was taken before the preflight passed')
    assert.equal(existsSync(join(m.checkout.root, '.env')), false)
    assert.deepEqual(m.calls(), [], 'a program ran before the preflight passed')
  }

  // Root: `sudo npm run aos-install` would make a root-owned .aos and lock in the checkout.
  if (INSTALLER_AS !== undefined) {
    const root = await installerMachine(t, { trap: false })
    const run = runEntry(root.checkout, 'scripts/install.ts', ['--dry-run'], { env: installerEnv(root), timeout: 90_000 })
    refusedAt(root, { status: run.status, stdout: run.stdout, stderr: run.stderr }, /^ {2}- the installer does not run as root: run it as your own account, without sudo/m)
  } else {
    t.diagnostic('the suite does not run as root, so the root refusal is covered in process only')
  }

  // A HOME with a colon in it: it would split the PATH a child is given.
  const colon = await installerMachine(t, { trap: false })
  const odd = join(colon.home, '..', 'ho:me')
  mkdirSync(join(odd, '.local'), { recursive: true })
  symlinkSync(join(colon.home, '.local', 'bin'), join(odd, '.local', 'bin'))
  handOver(odd)
  refusedAt(colon, installer(colon, ['--dry-run'], { HOME: odd }), /^ {2}- HOME is not set to an absolute path without a colon/m)

  // A .gitignore that ignores neither .env* nor /.aos/: the installer would create both where git can commit them.
  const ignores = await installerMachine(t, { trap: false })
  const gitignore = join(ignores.checkout.root, '.gitignore')
  writeFileSync(gitignore, readFileSync(gitignore, 'utf8').split('\n').filter((l) => l.trim() !== '.env*' && l.trim() !== '/.aos/').join('\n'))
  handOver(gitignore)
  const unignored = installer(ignores, ['--dry-run'])
  refusedAt(ignores, unignored, /\.gitignore does not ignore \.env, which the installer may create: restore the \.env\* line, then re-run/)
  assert.match(unignored.stdout, /\.gitignore does not ignore \/\.aos\/, where the installer keeps its lock and logs: add the line \/\.aos\/, then re-run/)

  // A Node outside package.json's engines.
  const engines = await installerMachine(t, { trap: false })
  const pkgPath = join(engines.checkout.root, 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as Record<string, unknown>
  writeFileSync(pkgPath, `${JSON.stringify({ ...pkg, engines: { node: '>=999.0.0' } }, null, 2)}\n`)
  handOver(pkgPath)
  refusedAt(engines, installer(engines, ['--dry-run']), /^ {2}- Node v[\d.]+ is outside package\.json's engines \(>=999\.0\.0\): install a Node that meets them, then re-run$/m)

  // ~/.docker/config.json names Docker Desktop's helper and no docker-credential-desktop is on the child's PATH.
  const helper = await installerMachine(t, { trap: false })
  mkdirSync(join(helper.home, '.docker'))
  writeFileSync(join(helper.home, '.docker', 'config.json'), JSON.stringify({ auths: {}, credsStore: 'desktop' }))
  handOver(join(helper.home, '.docker'))
  const missing = installer(helper, ['--dry-run'])
  refusedAt(helper, missing, /^ {2}- docker-credential-desktop is not on the PATH pmmcp's commands get \(above\): it ships with Docker Desktop .*remove credsStore from ~\/\.docker\/config\.json$/m)
  // With the helper there, the same HOME passes the preflight (and --aos-only never looks).
  writeFileSync(join(helper.home, '.local', 'bin', 'docker-credential-desktop'), '#!/bin/sh\nexit 97\n', { mode: 0o755 })
  handOver(join(helper.home, '.local', 'bin', 'docker-credential-desktop'))
  const present = await installerAsync(helper, ['--dry-run'])
  assert.equal(present.status, 0, `${present.stdout}${present.stderr}`)
  assert.match(present.stdout, /programs {4}.*docker-credential-desktop on the PATH pmmcp's commands get/)
})

test('aos-install --dry-run in an empty HOME hands discovery and the planner what it was given: --no-install, --pmmcp-dir, the default folder in another case, a shell export', async (t) => {
  // --no-install: no fresh install is offered, and the plan says why pmmcp is left out.
  const none = await installerMachine(t, { trap: false })
  const noInstall = await installerAsync(none, ['--dry-run', '--no-install'])
  assert.equal(noInstall.status, 0, `${noInstall.stdout}${noInstall.stderr}`)
  assert.match(noInstall.stdout, /^pmmcp {2}not installed \(--no-install\)$/m)
  assert.match(noInstall.stdout, /--no-install offers no setup: install it, or give --pmmcp-dir, then re-run/)
  assert.match(noInstall.stdout, /^would 1\. \[AOS file\] create .*\.env at 0600 with AOS_CONTROL_TOKEN/m)
  assert.doesNotMatch(noInstall.stdout, /\[fresh install\]|type `install`/)

  // --pmmcp-dir naming a folder that is no install: discovery stops on it, named as given, exit 2.
  const dirMachine = await installerMachine(t, { trap: false })
  const empty = join(dirMachine.home, '..', 'elsewhere', 'Persistent-Memory-MCP')
  mkdirSync(empty, { recursive: true })
  handOver(join(dirMachine.home, '..', 'elsewhere'))
  const given = await installerAsync(dirMachine, ['--dry-run', '--pmmcp-dir', empty])
  assert.equal(given.status, 2, `${given.stdout}${given.stderr}`)
  assert.match(given.stdout, /^refused before any change:$/m)
  assert.match(given.stdout, /Persistent-Memory-MCP \(--pmmcp-dir\) is not a pmmcp install: /)
  assert.doesNotMatch(given.stdout, /^plan:|fresh install/m)

  // The default folder stored in another case (APFS finds ~/github/persistent-memory-mcp at ~/Github/Persistent-Memory-MCP):
  // the stop script and the second confirmation know it by its name, so discovery stops, exit 2.
  const lower = await installerMachine(t, { trap: false })
  const stored = join(lower.home, 'github', 'persistent-memory-mcp')
  mkdirSync(stored, { recursive: true })
  const typed = join(lower.home, 'Github', 'Persistent-Memory-MCP')
  if (!existsSync(typed)) {
    // A filesystem that tells case apart: the typed path leads to the stored one, as APFS's lookup would.
    mkdirSync(join(lower.home, 'Github'))
    symlinkSync(join('..', 'github', 'persistent-memory-mcp'), typed)
  }
  handOver(lower.home)
  const variant = await installerAsync(lower, ['--dry-run'])
  assert.equal(variant.status, 2, `${variant.stdout}${variant.stderr}`)
  assert.match(variant.stdout, /\(the default place\) is stored as "persistent-memory-mcp", not Persistent-Memory-MCP/)
  assert.doesNotMatch(variant.stdout, /^plan:|fresh install at/m)

  // AOS_CONTROL_TOKEN exported by the shell: S2 names it among the exports and nothing is generated for it;
  // only the declared pmmcp bearer, which the shell does not export, would be.
  const shell = await installerMachine(t, { trap: false })
  const value = createHash('sha256').update(`export ${String(Date.now())}`).digest('hex')
  const exported = await installerAsync(shell, ['--dry-run'], { AOS_CONTROL_TOKEN: value })
  const printed = `${exported.stdout}${exported.stderr}`
  assert.equal(exported.status, 2, printed)
  assert.match(exported.stdout, /^ {2}shell exports {8}AOS_CONTROL_TOKEN$/m)
  assert.match(exported.stdout, /^ {2}AOS_CONTROL_TOKEN +missing, and exported by this shell -> not appended; unset it and re-run$/m)
  assert.doesNotMatch(exported.stdout, /AOS_CONTROL_TOKEN +missing {2}-> will be generated|\.env at 0600 with AOS_CONTROL_TOKEN|append AOS_CONTROL_TOKEN/)
  assert.match(exported.stdout, /^ {2}1\. \[AOS file\] create .*\.env at 0600 with AOS_PMMCP_TOKEN \(/m)
  assert.equal(printed.includes(value), false, 'the exported value was printed')
  assert.equal(existsSync(join(shell.checkout.root, '.env')), false)
})

test('aos-install --aos-only --dry-run asks whether only the tokens it generates fit in .env, never the names you add yourself', async (t) => {
  // `fits` counts every missing name it is given: asked over the screen's
  // names, a .env with room for the two tokens it generates but not for every
  // provider key beside them would be refused as over 64 KiB, though the
  // installer never writes those keys.
  const m = await installerMachine(t, { trap: false })
  const path = join(m.checkout.root, '.env')
  const line = `# ${'x'.repeat(96)}\n`
  const room = 65_536 - `AOS_CONTROL_TOKEN=${'0'.repeat(64)}\n`.length - `AOS_PMMCP_TOKEN=${'0'.repeat(64)}\n`.length - 20
  const body = line.repeat(Math.floor(room / line.length)) + '#'.repeat(room % line.length - 1) + '\n'
  assert.equal(Buffer.byteLength(body), room)
  writeFileSync(path, body, { mode: 0o600 })
  chmodSync(path, 0o600)
  handOver(path)
  const run = installer(m, ['--aos-only', '--dry-run'])
  assert.equal(run.status, 0, `${run.stdout}${run.stderr}`)
  assert.match(run.stdout, /^would 1\. \[AOS file\] append AOS_CONTROL_TOKEN and AOS_PMMCP_TOKEN to /m)
  assert.doesNotMatch(run.stdout, /over 64 KiB/)
  assert.equal(readFileSync(path, 'utf8'), body, 'a dry run changed .env')
})

test('aos-install refuses while a falsify run holds the tree', async (t) => {
  // src/ may hold a planted bug while a falsify run is going or was cut off
  // (src/falsify-hold.ts): the installer, which writes .env and stops pmmcp,
  // must not run it. Refused at S1, before the lock or any probe.
  const m = await installerMachine(t, { trap: false })
  const root = m.checkout.root
  const dir = join(root, '.falsify')
  mkdirSync(dir)
  writeFileSync(join(dir, 'journal.json'), JSON.stringify({ file: 'src/install/gate.ts', original: '', pid: 1 }))
  handOver(dir)
  const journal = installer(m, ['--dry-run'])
  assert.equal(journal.status, 2, `${journal.stdout}${journal.stderr}`)
  assert.match(journal.stdout, /refused before any change:\n {2}- .*a falsify run is in progress or was interrupted/)
  assert.equal(existsSync(join(root, '.aos')), false, 'the lock was taken under a falsify hold')
  assert.deepEqual(m.calls(), [])

  // Between mutants a live run holds only its lock, naming its pid: refused too.
  rmSync(join(dir, 'journal.json'))
  writeFileSync(join(dir, 'lock.json'), JSON.stringify({ pid: process.pid, started: 'x', runId: 'other-run' }))
  handOver(dir)
  const held = installer(m, ['--dry-run'])
  assert.equal(held.status, 2, `${held.stdout}${held.stderr}`)
  assert.match(held.stdout, new RegExp(`a falsify run \\(pid ${String(process.pid)}\\) holds this tree`))
  assert.equal(existsSync(join(root, '.aos')), false)
  assert.equal(existsSync(join(root, '.env')), false)
  assert.deepEqual(m.calls(), [])
})

test('aos-install takes over a stale lock (its pid gone, the machine booted since, or the pid given out again), and refuses a live one or anything else at its path, naming the removal', async (t) => {
  // One installer at a time: .aos/install.lock, O_EXCL with the pid. A run
  // killed outright (a SIGKILL, a crash, a reboot) leaves its lock behind,
  // and the next run must not need a hand to remove it, even once macOS has
  // given that pid to a process of its own.
  const m = await installerMachine(t, { trap: false })
  const root = m.checkout.root
  const lockPath = join(root, '.aos', 'install.lock')
  mkdirSync(join(root, '.aos'), { mode: 0o700 })
  chmodSync(join(root, '.aos'), 0o700)
  const lockWith = (text: string): void => {
    writeFileSync(lockPath, text, { mode: 0o600 })
    handOver(join(root, '.aos'))
  }
  const takenOver = (pid: number, why: RegExp): void => {
    const taken = installer(m, ['--aos-only', '--dry-run'])
    assert.equal(taken.status, 0, `${taken.stdout}${taken.stderr}`)
    assert.match(taken.stdout, new RegExp(`took over .*install\\.lock: it named pid ${String(pid)}, ${why.source}`))
    assert.match(taken.stdout, /dry run: nothing was changed/)
    assert.equal(existsSync(lockPath), false, 'the lock taken over was left behind')
  }
  // A pid that ran and has exited.
  const gone = spawnSync('true').pid
  assert.ok(gone !== undefined && gone > 0)
  lockWith(JSON.stringify({ pid: gone, started: new Date().toISOString() }))
  takenOver(gone, /which no longer runs/)
  assert.deepEqual(m.calls(), [], 'ps was asked about a pid that no longer runs')

  // A live pid (this test's own) in a lock older than the machine's boot: whatever runs it now is not the installer.
  lockWith(JSON.stringify({ pid: process.pid, started: '2000-01-01T00:00:00.000Z' }))
  takenOver(process.pid, /from before the machine last started/)
  assert.deepEqual(m.calls(), [], 'ps was asked though the boot already told')

  // A live pid whose process started after the lock was taken (ps etime): the pid was given out again.
  const recent = new Date(Date.now() - 30_000).toISOString()
  m.etime('00:02\n')
  lockWith(JSON.stringify({ pid: process.pid, started: recent }))
  takenOver(process.pid, /which now belongs to a process that started after the lock was taken/)
  assert.deepEqual(m.calls().filter((l) => !l.startsWith('env ')), [`ps -o etime= -p ${String(process.pid)}`])

  // A live pid that started before its lock (a day ago), or one ps cannot describe: the installer's, refused and left as it was.
  const remove = new RegExp(`remove it \\(rm ${lockPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\), then re-run`)
  for (const answer of ['1-00:00:00\n', undefined]) {
    m.etime(answer)
    const text = JSON.stringify({ pid: process.pid, started: recent })
    lockWith(text)
    const refused = installer(m, ['--aos-only', '--dry-run'])
    assert.equal(refused.status, 2, `${refused.stdout}${refused.stderr}`)
    assert.match(refused.stdout, new RegExp(`another npm run aos-install \\(pid ${String(process.pid)}, since ${recent.replace(/\./g, '\\.')}\\) holds`))
    assert.match(refused.stdout, remove)
    assert.equal(readFileSync(lockPath, 'utf8'), text, 'a lock the installer does not hold was changed')
  }

  // A lock that names no pid: refused, left as it was, its removal named.
  lockWith('')
  const blank = installer(m, ['--aos-only', '--dry-run'])
  assert.equal(blank.status, 2, `${blank.stdout}${blank.stderr}`)
  assert.match(blank.stdout, /names no installer's pid: if no npm run aos-install is running, remove it \(rm /)
  assert.equal(readFileSync(lockPath, 'utf8'), '')

  // A link or a directory at the path is no lock, and re-running never helps: each names its removal.
  rmSync(lockPath)
  symlinkSync(join(m.home, 'elsewhere'), lockPath)
  const link = installer(m, ['--aos-only', '--dry-run'])
  assert.equal(link.status, 2, `${link.stdout}${link.stderr}`)
  assert.match(link.stdout, /install\.lock is a symbolic link, not the installer's lock: remove the link \(rm .*install\.lock\), then re-run/)
  assert.doesNotMatch(link.stdout, /at the same moment/)
  assert.equal(existsSync(join(m.home, 'elsewhere')), false, 'the link was followed')
  rmSync(lockPath)
  mkdirSync(lockPath)
  handOver(lockPath)
  const dir = installer(m, ['--aos-only', '--dry-run'])
  assert.equal(dir.status, 2, `${dir.stdout}${dir.stderr}`)
  assert.match(dir.stdout, /install\.lock is a directory, not the installer's lock: .*\(rmdir .*install\.lock\), then re-run/)
  assert.ok(lstatSync(lockPath).isDirectory())
})

test('aos-install ends at once on Ctrl-C, a hangup or SIGTERM outside the stopped window: exit 130, 129 or 143, nothing changed, no lock left', async (t) => {
  // Outside the window nothing is half done that a re-run does not pick up
  // from the state on disk, so a signal ends the run (plan A7), with the
  // status its default would give, and the lock is released (a default
  // SIGHUP or SIGTERM would leave it behind). Here it comes while discovery
  // waits on docker.
  for (const [signal, code, last] of [
    ['SIGINT', 130, 'SIGINT (Ctrl-C)'],
    ['SIGHUP', 129, 'SIGHUP (the terminal closed)'],
    ['SIGTERM', 143, 'SIGTERM'],
  ] as const) {
    const m = await installerMachine(t, { trap: false })
    m.hold()
    t.after(() => m.release())
    const child = spawnEntry(m.checkout, 'scripts/install.ts', [], { env: installerEnv(m), ...INSTALLER_AS })
    let stdout = ''
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
    child.stderr.on('data', (d: Buffer) => (stdout += d.toString('utf8')))
    const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.on('close', (c, s) => resolve({ code: c, signal: s })))
    const deadline = Date.now() + 45_000
    while (!m.calls().includes('docker context show') && Date.now() < deadline && child.exitCode === null) {
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    assert.ok(m.calls().includes('docker context show'), `${signal}: discovery never reached docker:\n${stdout}`)
    child.kill(signal)
    const ended = await closed
    m.release()
    assert.deepEqual(ended, { code, signal: null }, `${signal}: ${stdout}`)
    // Said as it came, and as the last line, in the same words: where it came (before the window ever opened) and what was done.
    const words = `ended by ${last} before the stopped window opened: nothing more was done`
    const lines = stdout.trimEnd().split('\n')
    assert.equal(lines.at(-1), `aos-install: exit ${String(code)}: ${words}`, signal)
    assert.equal(lines.at(-2), words, `${signal}: what was said as it came differs from the last line:\n${stdout}`)
    assert.doesNotMatch(stdout, /^plan:/m, `${signal}: it went on to plan`)
    assert.equal(existsSync(join(m.checkout.root, '.env')), false)
    assert.equal(existsSync(join(m.checkout.root, '.aos', 'install.lock')), false, `${signal}: the lock was left behind`)
  }
})

test('aos-install goes on when its stdout reader is gone: no EPIPE crash, its lines on stderr, and what it said kept in installer.out', async (t) => {
  // `npm run aos-install 2>&1 | tee log` with tee gone: every write to stdout
  // fails with EPIPE. Unheard, that 'error' ends Node with exit 1, which inside
  // the stopped window leaves pmmcp stopped. A dry run shows it outside one.
  const m = await installerMachine(t, { trap: false })
  const child = spawnEntry(m.checkout, 'scripts/install.ts', ['--dry-run'], { env: installerEnv(m), ...INSTALLER_AS })
  child.stdout.destroy()
  let stderr = ''
  child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')))
  const timer = setTimeout(() => child.kill('SIGKILL'), 90_000)
  const code = await new Promise<number | null>((resolve) => child.on('close', (c) => resolve(c)))
  clearTimeout(timer)
  assert.equal(code, 0, stderr)
  assert.doesNotMatch(stderr, /EPIPE\n\s+at |Unhandled 'error' event/)
  assert.match(stderr, /dry run: nothing was changed, nothing was stopped or started/)
  const stamps = runFolders(m.checkout.root)
  assert.equal(stamps.length, 1)
  const kept = join(m.checkout.root, '.aos', 'install', stamps[0] ?? '', TRANSCRIPT_FILE)
  assert.match(stderr, new RegExp(`the installer's output went away \\(EPIPE\\) during the run; what it said is in ${kept.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
  const text = readFileSync(kept, 'utf8')
  assert.match(text, /^stdout went away \(EPIPE\) during this run; the installer went on\. What it said:\npreflight:\n/)
  assert.match(text, /dry run: nothing was changed.*\nexit 0\n$/s)
  assert.equal(lstatSync(kept).mode & 0o777, 0o600)
})

// ── the installer's entry point, in process ────────────────────────────────
//
// What the program does with a signal, a lost stdout, a typed-ahead line, a
// lock left behind and the preflight's refusals, without a terminal, a
// found install or a real signal: each piece is a module of its own
// (scripts/install/*.ts) that install.ts only wires.

test("the installer's last line says how this run ended: the input ending or an interrupt (never named Ctrl-C), a decline that changed nothing, and the end report only when one was printed", () => {
  const line = (...a: Parameters<typeof outcomeEnding>): string => exitLine(outcomeEnding(...a))
  // EOF and an interrupt at a question, before anything was applied: no end report is printed then.
  assert.equal(line({ kind: 'aborted', at: 'offer', by: 'eof', applied: [], exitCode: 130 }, false), 'aos-install: exit 130: aborted, the input ended at a question: nothing was changed')
  assert.equal(
    line({ kind: 'aborted', at: 'second-confirmation', by: 'interrupt', applied: [], exitCode: 130 }, false),
    'aos-install: exit 130: aborted, interrupted at a question: nothing was changed',
  )
  assert.equal(line({ kind: 'aborted', at: 'jobs', by: 'interrupt', applied: [], exitCode: 130 }, false), 'aos-install: exit 130: aborted, interrupted at the jobs check: nothing was changed')
  // The input ending during the jobs wait (or at its question) is the check's, not "a question".
  assert.equal(line({ kind: 'aborted', at: 'jobs', by: 'eof', applied: [], exitCode: 130 }, false), 'aos-install: exit 130: aborted, the input ended at the jobs check: nothing was changed')
  // After the non-live steps: their end report was printed.
  assert.equal(
    line({ kind: 'aborted', at: 'first-confirmation', by: 'eof', applied: ['non-live'], exitCode: 130 }, true),
    'aos-install: exit 130: aborted, the input ended at a question: nothing live was done (the non-live steps were applied: see the end report above)',
  )
  // A jobs count that is unknown, with nothing applied: exit 1, and no end report to point at.
  assert.equal(line({ kind: 'aborted', at: 'jobs', by: 'jobs', applied: [], exitCode: 1 }, false), "aos-install: exit 1: pmmcp's jobs could not be counted, so nothing was stopped: see above")
  assert.equal(line({ kind: 'aborted', at: 'jobs', by: 'jobs', applied: ['non-live'], exitCode: 1 }, true), "aos-install: exit 1: pmmcp's jobs could not be counted, so nothing was stopped: see the end report above")
  assert.equal(line({ kind: 'aborted', at: 'jobs', by: 'quit', applied: [], exitCode: 0 }, false), 'aos-install: exit 0: aborted at the jobs wait (q): nothing was changed')
  // Declined: exit 0, and never "done".
  assert.equal(line({ kind: 'declined', at: 'offer', applied: [], exitCode: 0 }, false), 'aos-install: exit 0: declined: nothing was changed')
  assert.equal(
    line({ kind: 'declined', at: 'second-confirmation', applied: ['non-live'], exitCode: 0 }, true),
    'aos-install: exit 0: declined: nothing live was done (the non-live steps were applied: see the end report above)',
  )
  // A failed phase always has its end report.
  assert.equal(line({ kind: 'failed', phase: 'non-live', applied: [], exitCode: 1 }, true), 'aos-install: exit 1: a step failed, and the state is as the end report above says')
  assert.equal(line({ kind: 'failed', phase: 'non-live', applied: [], exitCode: 2 }, true), 'aos-install: exit 2: refused before any change: see the end report above')
  assert.equal(line({ kind: 'failed', phase: 'live', applied: ['non-live'], exitCode: 4 }, true), 'aos-install: exit 4: a live step failed, and pmmcp is not in its intended state: see the end report above')
  assert.equal(line({ kind: 'done', applied: ['non-live'], exitCode: 0 }, true), 'aos-install: exit 0: done: see the end report above')
  assert.equal(line({ kind: 'dry-run', exitCode: 0 }, false), 'aos-install: exit 0: a dry run: nothing was changed, stopped or started')
  assert.equal(line({ kind: 'refused', exitCode: 2 }, false), 'aos-install: exit 2: refused before any change: see above')
  // Before the gate: a refusal, a stop by a defect (a leak, a halt, discovery's own), a defect anywhere, a signal: none has an end report.
  assert.equal(exitLine(refusedEnding()), 'aos-install: exit 2: refused before any change: see above')
  assert.equal(exitLine(stoppedEnding()), 'aos-install: exit 1: stopped before any change: see above')
  assert.equal(exitLine(defectEnding(1)), 'aos-install: exit 1: a defect (report it) before the stopped window: see above')
  assert.equal(exitLine(defectEnding(4)), 'aos-install: exit 4: a defect (report it) once the stopped window had opened: pmmcp may be stopped, see above')
  assert.equal(exitLine(signalEnding(143, 'SIGTERM')), 'aos-install: exit 143: ended by SIGTERM before the stopped window opened: nothing more was done')
  // No line points at an end report that was not printed, and none names Ctrl-C for an interrupt at a prompt.
  for (const reported of [false, true]) {
    for (const by of ['eof', 'interrupt', 'quit', 'jobs'] as const) {
      const text = line({ kind: 'aborted', at: 'offer', by, applied: [], exitCode: by === 'quit' ? 0 : by === 'jobs' ? 1 : 130 }, reported)
      assert.doesNotMatch(text, /Ctrl-C/, text)
      if (!reported) assert.doesNotMatch(text, /end report/, text)
    }
  }
})

test('a signal answers an open prompt, is trapped inside the window, ends a jobs count, or ends the run with 128 + its number; the same one again within REPEAT_MS is one delivery; a defect exits 4 once the window opened', () => {
  const view = (o: Partial<SignalView> = {}): SignalView => ({ promptOpen: false, windowOpen: false, reporting: false, counting: false, last: undefined, ...o })
  assert.deepEqual(HANDLED_SIGNALS, ['SIGINT', 'SIGHUP', 'SIGTERM'])
  assert.deepEqual(SIGNAL_EXIT, { SIGINT: 130, SIGHUP: 129, SIGTERM: 143 })
  for (const signal of HANDLED_SIGNALS) {
    // In this order: a prompt's answer first, then the window, then the count.
    assert.deepEqual(onSignal(view({ promptOpen: true, windowOpen: true, counting: true }), signal, 1000), { kind: 'answered' }, signal)
    assert.deepEqual(onSignal(view({ windowOpen: true, reporting: true, counting: true }), signal, 1000), { kind: 'trapped' }, signal)
    // After the window, once it had opened, until the end report: held, whatever the signal, so the run ends with its report and its own code.
    assert.deepEqual(onSignal(view({ reporting: true, counting: true }), signal, 1000), { kind: 'held' }, signal)
    assert.deepEqual(onSignal(view({ promptOpen: true, reporting: true }), signal, 1000), { kind: 'answered' }, `${signal}: "start pmmcp again?" after the window takes it as its answer`)
    assert.deepEqual(onSignal(view({ counting: true }), signal, 1000), { kind: 'count-aborted' }, signal)
    assert.deepEqual(onSignal(view(), signal, 1000), { kind: 'exit', code: SIGNAL_EXIT[signal] }, signal)
  }
  // npm forwards the terminal's Ctrl-C to a child that already got it: a millisecond later it is the same one.
  const last = { signal: 'SIGINT' as const, at: 1000 }
  assert.deepEqual(onSignal(view({ last }), 'SIGINT', 1001), { kind: 'repeat' })
  assert.deepEqual(onSignal(view({ last, windowOpen: true }), 'SIGINT', 1000 + REPEAT_MS - 1), { kind: 'repeat' })
  assert.deepEqual(onSignal(view({ last }), 'SIGINT', 1000 + REPEAT_MS), { kind: 'exit', code: 130 })
  assert.deepEqual(onSignal(view({ last }), 'SIGHUP', 1001), { kind: 'exit', code: 129 }, 'another signal is no repeat')
  assert.deepEqual(onSignal(view({ last }), 'SIGINT', 999), { kind: 'exit', code: 130 }, 'a clock that stepped back is no repeat')
  assert.equal(defectExit(true), 4)
  assert.equal(defectExit(false), 1)
})

test('handleSignal carries out the decision: a Ctrl-C delivered twice at "start pmmcp again?" answers it once and ends nothing; SIGHUP and SIGTERM inside the window are trapped and kept for the end', () => {
  const done: string[] = []
  let prompt = true
  const effects = {
    promptOpen: (): boolean => prompt,
    answer: (): void => {
      done.push('answer')
      prompt = false
    },
    trapped: (s: HandledSignal): void => void done.push(`trapped ${s}`),
    held: (s: HandledSignal): void => void done.push(`held ${s}`),
    abortCount: (): void => void done.push('abort'),
    exit: (code: number, s: HandledSignal): void => void done.push(`exit ${String(code)} ${s}`),
  }
  const state: SignalState & WindowMarks & { counting: boolean } = {
    windowOpen: false,
    windowOpened: false,
    reporting: false,
    counting: false,
    last: undefined,
    trapped: new Set(),
    held: new Set(),
  }
  // The window is closed while the question is asked (A6); the second delivery finds it answered.
  assert.equal(handleSignal(state, 'SIGINT', 5000, effects).kind, 'answered')
  assert.equal(handleSignal(state, 'SIGINT', 5001, effects).kind, 'repeat')
  assert.deepEqual(done, ['answer'])
  assert.deepEqual(state.last, { signal: 'SIGINT', at: 5000 }, 'a repeat moved the mark')
  // A real second Ctrl-C, later, with no prompt open, ends the run.
  assert.equal(handleSignal(state, 'SIGINT', 5000 + REPEAT_MS + 1, effects).kind, 'exit')
  assert.deepEqual(done, ['answer', 'exit 130 SIGINT'])

  // While pmmcp's jobs are counted, before any window: the count ends.
  state.counting = true
  done.length = 0
  handleSignal(state, 'SIGTERM', 20_000, effects)
  assert.deepEqual(done, ['abort'])
  state.counting = false

  done.length = 0
  windowChanged(state, true)
  assert.deepEqual([state.windowOpen, state.windowOpened, state.reporting], [true, true, true], 'the first opening marks the run')
  for (const [signal, at] of [['SIGHUP', 9000], ['SIGTERM', 9001], ['SIGINT', 9002], ['SIGINT', 9003]] as const) handleSignal(state, signal, at, effects)
  assert.deepEqual(done, ['trapped SIGHUP', 'trapped SIGTERM', 'trapped SIGINT'])
  assert.deepEqual([...state.trapped].sort(), ['SIGHUP', 'SIGINT', 'SIGTERM'])

  // The window closed (L5 ended, or "start the old revision?" was answered n), and the run's last checks and its report are still to
  // come: a Ctrl-C or SIGTERM there is held, never the end of a run that stopped pmmcp with no report and 130 for its 4.
  done.length = 0
  windowChanged(state, false)
  assert.deepEqual([state.windowOpen, state.windowOpened, state.reporting], [false, true, true], 'a close keeps the run owing its report')
  assert.equal(handleSignal(state, 'SIGINT', 30_000, effects).kind, 'held')
  assert.equal(handleSignal(state, 'SIGTERM', 30_001, effects).kind, 'held')
  assert.deepEqual(done, ['held SIGINT', 'held SIGTERM'])
  assert.deepEqual([...state.held].sort(), ['SIGINT', 'SIGTERM'])
  // Opened again for a start, the window traps as before; closed, it holds.
  windowChanged(state, true)
  assert.equal(handleSignal(state, 'SIGHUP', 31_000, effects).kind, 'trapped')
  windowChanged(state, false)
  assert.equal(handleSignal(state, 'SIGHUP', 32_000, effects).kind, 'held')
  // Once the report is printed (main clears the mark), a signal ends the run as before the window.
  state.reporting = false
  done.length = 0
  assert.equal(handleSignal(state, 'SIGINT', 40_000, effects).kind, 'exit')
  assert.deepEqual(done, ['exit 130 SIGINT'])
})

test("main's ends that are not the gate's: the end report only after a phase ran, a probe the runner's rules refused for the machine's state is a refusal (exit 2), and any other refusal, or discovery's or the TUI check's defect, is exit 1, never a refusal", () => {
  // The end report is printed after a phase ran or failed, and not for a jobs count that failed (or anything else) with nothing applied.
  for (const [outcome, reported] of [
    [{ kind: 'aborted', at: 'jobs', by: 'jobs', applied: [], exitCode: 1 }, false],
    [{ kind: 'aborted', at: 'jobs', by: 'jobs', applied: ['non-live'], exitCode: 1 }, true],
    [{ kind: 'aborted', at: 'first-confirmation', by: 'eof', applied: [], exitCode: 130 }, false],
    [{ kind: 'declined', at: 'offer', applied: [], exitCode: 0 }, false],
    [{ kind: 'declined', at: 'second-confirmation', applied: ['non-live'], exitCode: 0 }, true],
    [{ kind: 'failed', phase: 'non-live', applied: [], exitCode: 2 }, true],
    [{ kind: 'done', applied: ['live'], exitCode: 0 }, true],
    [{ kind: 'nothing-to-do', exitCode: 0 }, false],
    [{ kind: 'dry-run', exitCode: 0 }, false],
    [{ kind: 'refused', exitCode: 2 }, false],
    [{ kind: 'not-a-terminal', exitCode: 3 }, false],
  ] as const) {
    assert.equal(ranAPhase(outcome), reported, JSON.stringify(outcome))
  }
  // A leak in the recheck before the report makes a failed phase's code the worse of the two (4 while pmmcp may be stopped), and
  // changes nothing else: no leak, a code no worse, or an outcome that is not a failed phase.
  const failed = (exitCode: 1 | 2 | 4): GateOutcome => ({ kind: 'failed', phase: 'live', applied: ['non-live'], exitCode })
  assert.deepEqual(afterRecheck(failed(1), 4), failed(4))
  assert.deepEqual(afterRecheck(failed(2), 1), failed(2))
  assert.deepEqual(afterRecheck(failed(4), 1), failed(4))
  assert.deepEqual(afterRecheck(failed(1), undefined), failed(1))
  assert.deepEqual(afterRecheck(failed(1), 1), failed(1))
  const done: GateOutcome = { kind: 'done', applied: ['live'], exitCode: 0 }
  assert.equal(afterRecheck(done, 4), done)
  assert.equal(exitLine(outcomeEnding(afterRecheck(failed(1), 4), true)), 'aos-install: exit 4: a live step failed, and pmmcp is not in its intended state: see the end report above')
  // A leak or a halted runner, or discovery's own defect: stopped before any change, exit 1 (nothing was refused), with the line that says why.
  for (const [e, said] of [
    [new InstallRunError('AOS_INSTALL_RUN_LEAK', 'lsof-8766: a registered secret value reached its output', 'lsof-8766'), 'stopped: lsof-8766: a registered secret value reached its output'],
    [new InstallRunError('AOS_INSTALL_RUN_HALTED', 'facts: not run: a defect', 'facts'), 'stopped: facts: not run: a defect'],
    [new DiscoverError('no candidate'), 'discovery failed (a defect, report it): no candidate'],
  ] as const) {
    const stopped = stoppedBy(e)
    assert.ok(stopped !== undefined, said)
    assert.equal(stopped.line, said)
    assert.equal(stopped.ending.code, 1, said)
    assert.equal(exitLine(stopped.ending), 'aos-install: exit 1: stopped before any change: see above')
  }
  // A probe the runner's rules refused for the machine's state (a file on the child's PATH that is the stop script by identity): a refusal
  // before any change, exit 2, the runner's message, which names the file and its fix, said as it is (plan §5's failure table: discovery
  // refusals are exit 2).
  const MACHINE = "ps-40001: stop-pmmcp-server.sh runs only by absolute path, and ps on the child's PATH is /Users/op/.local/bin/ps"
  const refusedProbe = stoppedBy(new InstallRunError('AOS_INSTALL_RUN_REFUSED', MACHINE, 'ps-40001', undefined, true))
  assert.ok(refusedProbe !== undefined)
  assert.equal(refusedProbe.line, `refused before any change: ${MACHINE}`)
  assert.equal(refusedProbe.ending.code, 2)
  assert.equal(exitLine(refusedProbe.ending), 'aos-install: exit 2: refused before any change: see above')
  // Any other refusal of the runner's only an installer defect makes (a bad step name, arguments off the allowlist, a timeout on a step in
  // its own session): never read as the machine's fault with no fix, but stopped as a defect, exit 1.
  for (const message of [
    'a step is named [a-z0-9][a-z0-9._-]*, at most 48 characters; got "Bad Step"; nothing was run',
    'pgrep-tui: "pgrep" is given what its entry does not allow; nothing was run',
    'auth-init: a step in its own session is given no timeout; nothing was run',
  ]) {
    const defect = stoppedBy(new InstallRunError('AOS_INSTALL_RUN_REFUSED', message, 'pgrep-tui'))
    assert.ok(defect !== undefined, message)
    assert.equal(defect.line, `stopped by a defect (report it): the runner refused a probe the installer asked for: ${message}`)
    assert.equal(defect.ending.code, 1, message)
    assert.equal(exitLine(defect.ending), 'aos-install: exit 1: stopped before any change: see above')
  }
  // Anything else is main's own defect, thrown on: a probe that could not be started, or an error of no kind it knows.
  assert.equal(stoppedBy(new InstallRunError('AOS_INSTALL_RUN_SPAWN', 'lsof-8766: lsof could not be started (EACCES)')), undefined)
  assert.equal(stoppedBy(new Error('boom')), undefined)
})

/** A stream whose every write fails as a pipe with no reader does. */
class BrokenPipe extends Writable {
  override _write(_chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    callback(Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }))
  }
}

const drained = (stream: PassThrough): string => {
  const chunks: Buffer[] = []
  let chunk: unknown
  while ((chunk = stream.read()) !== null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)))
  return Buffer.concat(chunks).toString('utf8')
}

test('a write error on stdout never ends the installer: stdout is read as lost, its lines go to stderr, and at the end what it said goes to installer.out in the log folder', async (t) => {
  // `npm run aos-install 2>&1 | tee log` and a Ctrl-C during L1: the same
  // signal ends tee, and the next line raises EPIPE. Unheard, that 'error'
  // ends Node mid-window with pmmcp stopped and nothing to start it again.
  const stdout = new BrokenPipe()
  const stderr = new PassThrough()
  const out = new Output(stdout, stderr)
  out.say('L1 stop-pmmcp-server.sh: exit 0 after 41 s')
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(out.lost, { stream: 'stdout', code: 'EPIPE' })
  assert.equal(out.stdoutWorks, false)
  // Another 'error' from the stream is heard too: without a listener this throws.
  stdout.emit('error', Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }))
  out.say('pmmcp is left as the stop left it: start it with cd /Users/op/Github/Persistent-Memory-MCP && ./start-pmmcp-server.sh')
  out.warn('a defect line')
  assert.equal(drained(stderr), 'pmmcp is left as the stop left it: start it with cd /Users/op/Github/Persistent-Memory-MCP && ./start-pmmcp-server.sh\na defect line\n')
  // A question nobody can see is not asked: answered as the input ending, not waited on for good.
  const term = new Terminal({ input: new PassThrough(), output: new PassThrough(), interactive: true, raw: false, outputWorks: () => out.stdoutWorks, print: (l) => out.say(l) })
  const waited = new Promise<'waited'>((resolve) => setTimeout(() => resolve('waited'), 2000).unref())
  assert.deepEqual(await Promise.race([term.ask('start pmmcp again to restore service? [Y/n]'), waited]), { kind: 'eof' })
  assert.equal(term.promptOpen, false)

  const dir = tmpdir(t)
  const kept = out.keep(dir, 4)
  assert.equal(kept, join(dir, TRANSCRIPT_FILE))
  assert.equal(lstatSync(kept).mode & 0o777, 0o600)
  const text = readFileSync(kept, 'utf8')
  assert.match(text, /^stdout went away \(EPIPE\) during this run; the installer went on\. What it said:\n/)
  assert.match(text, /L1 stop-pmmcp-server\.sh: exit 0 after 41 s\n.*start it with cd \/Users\/op\/Github\/Persistent-Memory-MCP && \.\/start-pmmcp-server\.sh\n! a defect line\nexit 4\n$/s)
  // Exclusive: a second keep never writes over the first.
  assert.match(out.keep(dir, 4) ?? '', /could not be created \(EEXIST\)/)
  // Both streams gone: nothing is written, nothing throws, and flush still calls back.
  const both = new Output(new BrokenPipe(), new BrokenPipe())
  both.say('x')
  both.warn('y')
  await new Promise((resolve) => setImmediate(resolve))
  both.say('z')
  await new Promise<void>((resolve) => both.flush(resolve))
  assert.deepEqual(both.transcript, ['x', '! y', 'z'])

  // While output works, nothing is kept.
  const fine = new Output(new PassThrough(), new PassThrough())
  fine.say('fine')
  const quiet = tmpdir(t)
  assert.equal(fine.keep(quiet, 0), undefined)
  assert.deepEqual(readdirSync(quiet), [])
})

test("a line typed before a question was shown is dropped, not taken as its answer; a stdin that is not a terminal is never asked", async () => {
  let clock = 0
  const input = new PassThrough()
  const output = new PassThrough()
  const printed: string[] = []
  const term = new Terminal({ input, output, interactive: true, raw: false, outputWorks: () => true, print: (l) => printed.push(l), now: () => clock })
  // Typed while the jobs were counted, before the second confirmation was shown.
  input.write('Persistent-Memory-MCP\n')
  const answer = term.ask('Second confirmation: type the folder name `Persistent-Memory-MCP` to stop it now')
  assert.equal(term.promptOpen, true)
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(printed, ['(dropped what was typed before the question was shown: answer it now)'])
  clock += TYPE_AHEAD_MS
  input.write('no\n')
  assert.deepEqual(await answer, { kind: 'line', text: 'no' })
  assert.equal(term.promptOpen, false)
  assert.match(drained(output), /Second confirmation: type the folder name `Persistent-Memory-MCP` to stop it now /)

  // A Ctrl-C delivered as a signal answers the open question.
  const asked = term.ask('Apply the non-live steps 1-2 now? [y/N]')
  assert.equal(term.interrupt(), true)
  assert.deepEqual(await asked, { kind: 'interrupt' })
  assert.equal(term.interrupt(), false, 'with no question open a signal is no answer')

  const pipe = new Terminal({ input: new PassThrough(), output: new PassThrough(), interactive: false, raw: false, outputWorks: () => true, print: () => undefined })
  assert.deepEqual(await pipe.ask('Type `stop pmmcp` to continue'), { kind: 'eof' })
})

test('the lock: a stale one is taken over (its pid gone, a boot since, a pid given out again), a live one refused; every refusal names its fix with the path shell-quoted', async (t) => {
  // A checkout under a folder with a space: each command printed must paste back as one path.
  const root = join(tmpdir(t), 'My Projects', 'MrRobot')
  mkdirSync(root, { recursive: true })
  const path = lockPath(root)
  const quoted = `'${path}'`
  const printed: string[] = []
  const at = Date.parse('2026-10-29T10:00:00.000Z')
  const asked: number[] = []
  const options = (o: Partial<LockOptions> = {}): LockOptions => ({
    root,
    print: (l) => printed.push(l),
    alive: () => true,
    bootedAt: () => at - 3_600_000,
    startOf: async (pid) => {
      asked.push(pid)
      return at - 60_000
    },
    ...o,
  })
  const holder = (pid: number): void => writeFileSync(path, JSON.stringify({ pid, started: new Date(at).toISOString() }), { mode: 0o600 })

  const lock = await takeLock(options())
  assert.ok(typeof lock !== 'string', String(lock))
  assert.equal(lstatSync(path).mode & 0o777, 0o600)
  assert.equal(lstatSync(join(root, '.aos')).mode & 0o777, 0o700)
  lock.release()
  assert.equal(existsSync(path), false)

  // A live holder that started before its lock: refused, and the removal pastes back as one path.
  holder(4242)
  assert.equal(
    await takeLock(options()),
    `another npm run aos-install (pid 4242, since 2026-10-29T10:00:00.000Z) holds ${path}: let it finish; if no npm run aos-install is running, remove it (rm ${quoted}), then re-run`,
  )
  assert.deepEqual(asked, [4242])
  // One whose start ps cannot tell: refused the same way.
  assert.match(String(await takeLock(options({ startOf: async () => undefined }))), /^another npm run aos-install \(pid 4242/)
  // Its pid gone (kill 0), or ps finding none: taken over.
  for (const o of [{ alive: () => false }, { startOf: async (): Promise<'gone'> => 'gone' }]) {
    holder(4242)
    const taken = await takeLock(options(o))
    assert.ok(typeof taken !== 'string', String(taken))
    taken.release()
    assert.equal(printed.pop(), `took over ${path}: it named pid 4242, which no longer runs`)
  }
  // The machine booted after the lock was taken: whatever has pid 4242 now is not that installer. ps is not asked.
  holder(4242)
  asked.length = 0
  const rebooted = await takeLock(options({ bootedAt: () => at + BOOT_SLACK_MS + 1000 }))
  assert.ok(typeof rebooted !== 'string', String(rebooted))
  rebooted.release()
  assert.match(printed.pop() ?? '', /it named pid 4242, from before the machine last started/)
  assert.deepEqual(asked, [])
  // A boot within the slack is the same moment: not stale by it.
  holder(4242)
  assert.match(String(await takeLock(options({ bootedAt: () => at + BOOT_SLACK_MS }))), /^another npm run aos-install/)
  // The process with that pid started after the lock was taken: the pid was given out again.
  const reused = await takeLock(options({ startOf: async () => at + 5000 }))
  assert.ok(typeof reused !== 'string', String(reused))
  reused.release()
  assert.match(printed.pop() ?? '', /it named pid 4242, which now belongs to a process that started after the lock was taken/)

  // No pid in it, a link, a directory, a FIFO: each refused with its own removal, never "re-run".
  writeFileSync(path, '{"pid":"x"}')
  assert.equal(await takeLock(options()), `${path} is there but names no installer's pid: if no npm run aos-install is running, remove it (rm ${quoted}), then re-run`)
  rmSync(path)
  symlinkSync(join(root, 'nowhere'), path)
  assert.equal(await takeLock(options()), `${path} is a symbolic link, not the installer's lock: remove the link (rm ${quoted}), then re-run`)
  rmSync(path)
  mkdirSync(path)
  assert.equal(await takeLock(options()), `${path} is a directory, not the installer's lock: move what you keep in it elsewhere and remove it (rmdir ${quoted}), then re-run`)
  rmSync(path, { recursive: true })
  if (spawnSync('mkfifo', [path]).status === 0) {
    assert.equal(await takeLock(options()), `${path} is not a regular file, not the installer's lock: remove it (rm ${quoted}), then re-run`)
    rmSync(path)
  } else {
    t.diagnostic('mkfifo is unavailable here; the FIFO case is not run')
  }

  // A .aos others may write in: refused, the chmod pasting back as one path.
  chmodSync(join(root, '.aos'), 0o770)
  assert.equal(await takeLock(options()), `${join(root, '.aos')} is writable by group or others: chmod go-w '${join(root, '.aos')}', then re-run`)
})

test("the preflight refuses root and a current directory that is not the checkout's root (its cd quoted), reads macOS's version, and on macOS holds /usr/bin's git and python3 stubs to the Command Line Tools", (t) => {
  const base = tmpdir(t)
  const root = join(base, 'My Projects', 'MrRobot')
  mkdirSync(join(root, 'node_modules'), { recursive: true })
  writeFileSync(join(root, 'package.json'), '{"engines":{"node":">=20.0.0"}}\n')
  writeFileSync(join(root, '.gitignore'), '.env*\n!.env.example\n/.aos/\n')
  const home = join(base, 'home')
  mkdirSync(home)
  const input = { aosOnly: true, root, home, env: {}, cwd: root, euid: 501, uid: 501, user: 'op' } as const
  assert.deepEqual(preflight(input).refusals, [])
  assert.deepEqual(preflight({ ...input, euid: 0, uid: 0, user: 'root' }).refusals, [
    "the installer does not run as root: run it as your own account, without sudo (the .env it writes and pmmcp's files must be yours)",
  ])
  assert.deepEqual(preflight({ ...input, cwd: home }).refusals, [`the current directory is not this checkout's root (${root}): run it from there, cd '${root}' && npm run aos-install`])
  // npm run typed in a subfolder hands the installer the root as its cwd, but npm keeps its cache and logs under the folder it was typed in: refused, with the cd.
  assert.deepEqual(preflight({ ...input, env: { INIT_CWD: root } }).refusals, [])
  const sub = join(root, 'src')
  mkdirSync(sub)
  const typedIn = `npm run was typed in ${sub}, not in this checkout's root (${root}), and npm keeps its cache and logs under the folder it was typed in (.npmrc's cache=.aos/npm-cache): run it from the root, cd '${root}' && npm run aos-install`
  assert.deepEqual(preflight({ ...input, env: { INIT_CWD: sub } }).refusals, [typedIn])
  // What npm already wrote there is named for removal, never removed.
  mkdirSync(join(sub, '.aos', 'npm-cache', '_logs'), { recursive: true })
  assert.deepEqual(preflight({ ...input, env: { INIT_CWD: sub } }).refusals, [
    `${typedIn}; ${join(sub, '.aos')} holds what npm wrote there, which git does not ignore: remove it once you have checked it holds only npm's cache and logs`,
  ])
  assert.ok(existsSync(join(sub, '.aos', 'npm-cache', '_logs')))
  assert.equal(preflight({ ...input, env: { INIT_CWD: 'relative/dir' } }).refusals.length, 1, 'an INIT_CWD that is no folder of this checkout is refused too')
  assert.match(preflight({ ...input, platform: 'linux' }).lines[1] ?? '', /^ {2}system {6}Linux \S+ \S+, user op \(uid 501\)$/)

  assert.equal(productVersion('<plist><dict>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t<key>ProductVersion</key>\n\t<string>15.6.1</string>\n</dict></plist>'), '15.6.1')
  assert.equal(productVersion('<key>ProductVersion</key><string>$(rm -rf ~)</string>'), undefined)

  const stubs = new Map([['git', '/usr/bin/git'], ['python3', '/usr/bin/python3'], ['curl', '/usr/bin/curl']])
  const clt = '/Library/Developer/CommandLineTools'
  assert.deepEqual(stubRefusals(stubs, 'linux', [clt], () => false), [], 'only macOS puts a stub in /usr/bin')
  const without = stubRefusals(stubs, 'darwin', [clt], () => false)
  assert.equal(without.length, 2)
  assert.match(without[0] ?? '', /^git on the PATH pmmcp's commands get is \/usr\/bin\/git, the stub that asks to install the Command Line Tools, .*xcode-select --install/)
  assert.match(without[1] ?? '', /^python3 on the PATH/)
  assert.deepEqual(stubRefusals(stubs, 'darwin', ['/Applications/Xcode.app/Contents/Developer', clt], (p) => p.startsWith(`${clt}/usr/bin/`)), [])
  assert.deepEqual(stubRefusals(new Map([['git', '/opt/homebrew/bin/git']]), 'darwin', [clt], () => false), [], 'a git of its own needs no developer folder')

  assert.deepEqual(npmTookFlags({ PATH: '/usr/bin', npm_config_cache: '/x', npm_config_local_prefix: '/r' }), [], "npm's own settings are no trace")
  assert.deepEqual(npmTookFlags({ npm_config_install: '', npm_config_dry_run: 'true' }), ['--dry-run', '--no-install'])

  // S1 names the bash pmmcp's scripts run (#!/usr/bin/env bash: the first on the child's PATH) and its version, read from the file's own
  // version string and never by running it. A stand-in carries macOS's, amid bytes that are not UTF-8, as in a binary.
  const bin = join(home, '.local', 'bin')
  mkdirSync(bin, { recursive: true })
  const bash = join(bin, 'bash')
  writeFileSync(bash, Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x00, 0xff]), Buffer.from('\0@(#)Bash version 3.2.57(1) release GNU\0'), Buffer.from([0xfe, 0x00])]), { mode: 0o755 })
  chmodSync(bash, 0o755)
  assert.equal(bashVersion(bash), '3.2.57(1)')
  const checked = preflight({ ...input, aosOnly: false })
  assert.ok(checked.lines.includes(`  bash        ${bash}, version 3.2.57(1) (the one pmmcp's scripts run)`), checked.lines.join('\n'))
  // A bash whose file holds no version string, or that cannot be read: said so, and nothing is run to find out.
  writeFileSync(bash, '#!/bin/sh\nexit 0\n')
  assert.equal(bashVersion(bash), undefined)
  assert.ok(preflight({ ...input, aosOnly: false }).lines.includes(`  bash        ${bash}, version not readable from the file (the one pmmcp's scripts run)`))
  assert.equal(bashVersion(join(bin, 'nowhere')), undefined)
})
