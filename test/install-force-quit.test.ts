// The typed force-quit of the one pmmcp service the stop waits on (F1):
// scripts/install/drain.ts (what the stop drains, read from its stdout),
// scripts/install/force-quit.ts (the identity check, the question, the one
// SIGKILL) and the SIGINT branch in scripts/install/signals.ts.
//
// Everything here is in process: ps is a fake runner whose answers are
// files in a mkdtemp folder, the question a fake terminal, and the kill a
// recorder (offerForceQuitWith). No process is signalled, and no real ps
// runs. The real SIGKILL, through real ps, of a child the test itself spawns
// is test/entrypoints.test.ts's, as is the installer's whole run.

import './helpers/guard.js'

import assert from 'node:assert/strict'
import { appendFileSync, chmodSync, chownSync, linkSync, mkdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'

import { DrainReader, DrainWatch, MAX_LINE, READ_BYTES, forceQuitLine, type DrainTarget } from '../scripts/install/drain.js'
import {
  CMD_SHOWN,
  FORCE_QUIT_LOG,
  NO_TARGET,
  PMMCP_OLLAMA_NAMES,
  PMMCP_OLLAMA_RELAUNCHED,
  PMMCP_OLLAMA_ROLES,
  PS_TRIES,
  forceQuitQuestion,
  offerForceQuitWith,
  ollamaRefusal,
  ollamaRole,
  pmmcpCommand,
  pmmcpOllama,
  targetRefusal,
  type ForceQuitOptions,
  type Guard,
  type Kill,
  type Snapshot,
} from '../scripts/install/force-quit.js'
import { InstallRunError, readLogFrom, type RunResult, type RunSpec } from '../scripts/install/run.js'
import { HANDLED_SIGNALS, handleSignal, onSignal, type HandledSignal, type SignalState, type SignalView } from '../scripts/install/signals.js'
import type { Answer } from '../src/install/gate.js'
import { tmpdir } from './helpers/tmpdir.js'

const enc = (s: string): Buffer => Buffer.from(s, 'utf8')

/** The stop's lines as its graceful_kill logs them (`log`: three spaces first). */
const sent = (pid: number, label: string, upTo = 300): string => `   Sent SIGTERM to PID ${String(pid)} (${label}) — waiting for clean drain (up to ${String(upTo)}s)\n`
const drained = (pid: number, label: string): string => `   PID ${String(pid)} (${label}) drained and exited cleanly after 3s ✓\n`
const exitedTotal = (pid: number, label: string): string => `   PID ${String(pid)} (${label}) exited cleanly after 412s total ✓\n`
/** What the stop draws while it waits: a carriage return, the spinner line, and the erase before its next line. */
const spinner = (label: string, n: number): string => `\r  ⠋ [██░░░░] ${String(n)}% — waiting for ${label} to drain... ${String(n)}s  (Ctrl+C to force-quit)`
const erase = '\r\x1b[2K'
/** The reader's target, read through a call so an assertion before it does not narrow it. */
const targetOf = (r: DrainReader): DrainTarget | undefined => r.target

// ── the target reader ──

test('the drain reader: no target before a "Sent SIGTERM" line, one after it, none once that pid and label drained or exited', () => {
  const r = new DrainReader()
  r.feed(enc('   Stopping pmmcp services...\n   running jobs: 0\n'), 1000)
  assert.equal(r.target, undefined, 'no line yet')
  r.feed(enc(sent(4242, 'Worker', 30)), 2000)
  assert.deepEqual(r.target, { pid: 4242, label: 'Worker', upTo: 30, seenAt: 2000 })
  // The spinner the stop draws meanwhile is no line of its own, and changes nothing; seenAt stays the first read's.
  r.feed(enc(`${spinner('Worker', 3)}${spinner('Worker', 4)}`), 3000)
  assert.deepEqual(r.target, { pid: 4242, label: 'Worker', upTo: 30, seenAt: 2000 })
  // A done line for another pid or label is not this target's.
  r.feed(enc(`${erase}${drained(4243, 'Worker')}`), 3500)
  r.feed(enc(drained(4242, 'Scraper Worker')), 3600)
  assert.equal(targetOf(r)?.pid, 4242)
  // The exited target: after the erase sequence the stop draws, its own line.
  r.feed(enc(`${spinner('Worker', 9)}${erase}${drained(4242, 'Worker')}`), 4000)
  assert.equal(r.target, undefined)

  // The second form, after the recheck boxes: "exited cleanly after <s>s total".
  const total = new DrainReader()
  total.feed(enc(`${sent(77, 'MCP Server')}\n╔════╗\n║  WAITING FOR CLEAN SHUTDOWN -- check #1  (Ctrl+C to force-quit)║\n╚════╝\n${spinner('MCP Server', 1)}`), 10)
  assert.equal(total.target?.pid, 77)
  total.feed(enc(`${erase}${exitedTotal(77, 'MCP Server')}`), 20)
  assert.equal(total.target, undefined)

  // Qdrant's docker stop -t 60 logs no such line: between services there is nothing to force-quit.
  const qdrant = new DrainReader()
  qdrant.feed(enc(`${sent(10, 'Backup Daemon', 45)}${drained(10, 'Backup Daemon')}   Stopping Qdrant (docker stop -t 60 pmmcp-qdrant)...\n`), 5)
  assert.equal(qdrant.target, undefined)
})

test('the drain reader follows two services in turn: the last "Sent SIGTERM" line is the target, a label with parentheses included', () => {
  const r = new DrainReader()
  r.feed(enc(sent(500, 'Dashboard (port 8765)')), 1)
  assert.deepEqual(r.target, { pid: 500, label: 'Dashboard (port 8765)', upTo: 300, seenAt: 1 })
  r.feed(enc(`${erase}${drained(500, 'Dashboard (port 8765)')}`), 2)
  assert.equal(r.target, undefined)
  r.feed(enc(sent(501, 'MCP Server (legacy PID)')), 3)
  assert.deepEqual(r.target, { pid: 501, label: 'MCP Server (legacy PID)', upTo: 300, seenAt: 3 })
  // A later service's line replaces an earlier one's, whatever became of it.
  r.feed(enc(sent(502, 'Worker', 30)), 4)
  assert.deepEqual(r.target, { pid: 502, label: 'Worker', upTo: 30, seenAt: 4 })
  // The earlier one's done line now changes nothing.
  r.feed(enc(drained(501, 'MCP Server (legacy PID)')), 5)
  assert.equal(targetOf(r)?.pid, 502)
})

test('the drain reader reads a line split across reads once it is whole, the dash split between its bytes included, and never a part of one', () => {
  const whole = enc(sent(123456, 'Scraper Worker', 15))
  // Every split point: the pid cut short, the label, the three bytes of the dash, the newline.
  for (let cut = 1; cut < whole.length; cut += 1) {
    const r = new DrainReader()
    r.feed(whole.subarray(0, cut), 100)
    assert.equal(r.target, undefined, `a part of the line (${String(cut)} bytes) was read as one`)
    r.feed(whole.subarray(cut), 200)
    assert.deepEqual(r.target, { pid: 123456, label: 'Scraper Worker', upTo: 15, seenAt: 200 }, `cut at ${String(cut)}`)
  }
  // Byte by byte, with a carriage-return progress line before it.
  const r = new DrainReader()
  for (const b of enc(`${spinner('X', 1)}${erase}${sent(9, 'Curator')}`)) r.feed(Uint8Array.of(b), 1)
  assert.equal(r.target?.pid, 9)
})

test('the drain reader takes no line that is not the stop\'s: pid 0 or 1, a pid past 2^31 - 1, a run with no break past MAX_LINE, another wording', () => {
  for (const line of [sent(1, 'X'), sent(0, 'X'), sent(2 ** 31, 'X'), sent(4242, ''), `${sent(4242, 'X').trimEnd()} extra\n`, 'Sent SIGTERM to PID 4242 (X) - waiting for clean drain (up to 300s)\n']) {
    const r = new DrainReader()
    r.feed(enc(line), 1)
    assert.equal(r.target, undefined, JSON.stringify(line))
  }
  // A run of more than MAX_LINE characters with no break is dropped up to its break, and the reader goes on after it.
  const r = new DrainReader()
  r.feed(enc('y'.repeat(MAX_LINE + 1)), 1)
  r.feed(enc(`${'y'.repeat(10)}${sent(4242, 'Worker').trim()}`), 2)
  r.feed(enc(`\n${sent(4343, 'Worker')}`), 3)
  assert.deepEqual(r.target, { pid: 4343, label: 'Worker', upTo: 300, seenAt: 3 })
})

test('the drain watch follows a growing file from where it last read, and a file that is not there changes nothing', (t) => {
  const dir = tmpdir(t)
  const out = join(dir, 'stop.out')
  const w = new DrainWatch(out)
  w.poll(1)
  assert.equal(w.target, undefined)
  writeFileSync(out, '   Stopping...\n   Sent SIGTERM to PID 31 (Wor', { mode: 0o600 })
  w.poll(2)
  assert.equal(w.target, undefined)
  appendFileSync(out, 'ker) — waiting for clean drain (up to 30s)\n')
  w.poll(3)
  assert.deepEqual(w.target, { pid: 31, label: 'Worker', upTo: 30, seenAt: 3 })
  appendFileSync(out, `${spinner('Worker', 1)}${erase}${drained(31, 'Worker')}`)
  w.poll(4)
  assert.equal(w.target, undefined)
  // What it read is never read twice: the earlier Sent line does not come back.
  w.poll(5)
  assert.equal(w.target, undefined)

  // The runner's read it follows the file with: from an offset, at most `max`, nothing past the end, and never through a link.
  assert.equal(readLogFrom(out, 3, 8).toString('utf8'), 'Stopping')
  assert.equal(readLogFrom(out, statSync(out).size, 8).length, 0)
  const link = join(dir, 'link.out')
  symlinkSync(out, link)
  assert.throws(() => readLogFrom(link, 0, 8), (e: unknown) => e instanceof InstallRunError && e.code === 'AOS_INSTALL_RUN_OUTPUT')
  const linked = new DrainWatch(link)
  linked.poll(6)
  assert.equal(linked.target, undefined, 'a link was followed')
})

test("the drain watch reads each byte once: a second service's wait counts from its own first read, every read starts where the last ended, and a stdout past one read's most is read on, never from the start again", (t) => {
  const dir = tmpdir(t)
  const out = join(dir, 'stop.out')
  writeFileSync(out, sent(500, 'Dashboard (port 8765)'), { mode: 0o600 })
  /** Each read the watch makes: [offset, bytes it got]. */
  const reads: [number, number][] = []
  const w = new DrainWatch(out, (path, offset, max) => {
    const chunk = readLogFrom(path, offset, max)
    reads.push([offset, chunk.length])
    return chunk
  })
  w.poll(1)
  assert.equal(w.target?.pid, 500)
  appendFileSync(out, `${erase}${drained(500, 'Dashboard (port 8765)')}${sent(501, 'Worker', 30)}`)
  w.poll(2)
  assert.deepEqual(w.target, { pid: 501, label: 'Worker', upTo: 30, seenAt: 2 })
  appendFileSync(out, `${spinner('Worker', 1)}${spinner('Worker', 2)}`)
  w.poll(3)
  w.poll(4)
  // Read again from the start, the first service's lines would replace the second's target, and its wait would count from the latest poll.
  assert.deepEqual(w.target, { pid: 501, label: 'Worker', upTo: 30, seenAt: 2 }, "the second service's wait was counted afresh")
  let at = 0
  for (const [offset, got] of reads) {
    assert.equal(offset, at, `a read started at ${String(offset)}, not where the last ended (${String(at)})`)
    at += got
  }
  assert.equal(at, statSync(out).size, 'the whole file was read, once')

  // A stdout past READ_BYTES: read on from where the full read ended, and the line after it is read.
  const big = Buffer.concat([enc(`${'x'.repeat(READ_BYTES - 1)}\n`), enc(sent(502, 'Curator'))])
  const offsets: number[] = []
  const bw = new DrainWatch(join(dir, 'big.out'), (_path, offset, max) => {
    offsets.push(offset)
    // A watch that never moved on would read the first READ_BYTES for ever, inside the entry point's timer.
    if (offsets.length > 8) return Buffer.alloc(0)
    return big.subarray(offset, offset + max)
  })
  bw.poll(7)
  assert.deepEqual(offsets, [0, READ_BYTES])
  assert.deepEqual(bw.target, { pid: 502, label: 'Curator', upTo: 300, seenAt: 7 })
})

// ── the identity check ──

const ME = 501
const INSTALLER = 7000
const STOP = 7100
const DIR = '/Users/op/Github/Persistent-Memory-MCP'
const guard = (o: Partial<Guard> = {}): Guard => ({ uid: ME, installerPid: INSTALLER, stopPid: STOP, dirs: [DIR, '/Volumes/Data/pmmcp'], darwin: false, ...o })
const PMMCP_ARGS = `${DIR}/.venv/bin/python ${DIR}/scripts/run_worker.py`
/** The drain a check is for: the Worker's, unless a label is given. */
const W = (pid: number, label = 'Worker'): DrainTarget => ({ pid, label, upTo: 30, seenAt: 0 })
/** The stop's label for pmmcp's TextQuery instance, from its PID file: graceful_kill "$pid" "${_ol_name} (port ${_ol_port})" 10. */
const TQ = 'PMMCP-TextQuery (port 11435)'
const snap = (o: { pid?: number; start?: string; startAfter?: string; uid?: number; pgid?: number; args?: string; installerPgid?: number | undefined; stopPgid?: number | undefined } = {}): Snapshot => ({
  start: o.start ?? 'Wed Nov  4 09:00:00 2026',
  startAfter: o.startAfter ?? o.start ?? 'Wed Nov  4 09:00:00 2026',
  target: { pid: o.pid ?? 4242, uid: o.uid ?? ME, pgid: o.pgid ?? 4000, args: o.args ?? PMMCP_ARGS },
  installerPgid: 'installerPgid' in o ? o.installerPgid : 6900,
  stopPgid: 'stopPgid' in o ? o.stopPgid : STOP,
})

test("a command line is pmmcp's by the stop script's rule: Persistent-Memory-MCP anywhere, or a word that is the install's folder or starts with it; case folded on macOS only", () => {
  assert.equal(pmmcpCommand('/opt/x/bin/python -m Persistent-Memory-MCP.worker', [], false), true)
  assert.equal(pmmcpCommand('uv run --directory /Volumes/Data/pmmcp pmmcp', ['/Volumes/Data/pmmcp'], false), true)
  assert.equal(pmmcpCommand('/Volumes/Data/pmmcp/.venv/bin/python run.py', ['/Volumes/Data/pmmcp'], false), true)
  // A folder that only begins with the install's name is another folder.
  assert.equal(pmmcpCommand('/Volumes/Data/pmmcp2/.venv/bin/python run.py', ['/Volumes/Data/pmmcp'], false), false)
  assert.equal(pmmcpCommand('/usr/bin/python3 -m http.server 8766', [DIR], false), false)
  // APFS: ~/github/persistent-memory-mcp is the same folder; elsewhere case is kept.
  assert.equal(pmmcpCommand('/users/op/github/persistent-memory-mcp/.venv/bin/python w.py', [], true), true)
  assert.equal(pmmcpCommand('/users/op/github/persistent-memory-mcp/.venv/bin/python w.py', [], false), false)
  assert.equal(pmmcpCommand('/VOLUMES/DATA/PMMCP/.venv/bin/python w.py', ['/Volumes/Data/pmmcp'], true), true)
  // pmmcp's Ollama instances name neither: they are pmmcp's by the stop's other rule, _is_pmmcp_ollama (pmmcpOllama, below).
  for (const ollama of ['PMMCP-TextQuery serve', 'PMMCP-CodeIndex serve', 'PMMCP-Ollama serve', 'ollama serve']) {
    assert.equal(pmmcpCommand(ollama, [DIR, '/Volumes/Data/pmmcp'], true), false, ollama)
  }
})

/** The way out every refusal of an Ollama-shaped command line ends with. */
const WAY_OUT = /\(to end it, check it with `ps -ww -o pid,uid,lstart,args -p 4242` in another terminal, and end it there if it is pmmcp's\)$/

/** Under the TextQuery drain (TQ): its own name, and the health monitor's for any role. */
const OLLAMA_ACCEPTED = ['PMMCP-TextQuery serve', 'PMMCP-Ollama serve'] as const

/** Ollama-shaped command lines that are refused under the TextQuery drain (TQ), each with the start of its reason. */
const OLLAMA_REFUSED: readonly (readonly [string, RegExp])[] = [
  // Only a PID file of the start script vouches for it, and Ollama.app's and Homebrew's servers are the same with the path dropped.
  ['ollama serve', /^it is `ollama serve`, which only a PID file of pmmcp's start script vouches for \(the installer reads none\), and which Ollama\.app's or Homebrew's server also is once its path is dropped /],
  ['/Applications/Ollama.app/Contents/Resources/ollama serve', /^it is run by a path \(`\/Applications\/Ollama\.app\/Contents\/Resources\/ollama`\), as Ollama\.app's and Homebrew's servers are /],
  ['/opt/homebrew/bin/ollama serve', /^it is run by a path \(`\/opt\/homebrew\/bin\/ollama`\)/],
  ['/usr/local/bin/PMMCP-TextQuery serve', /^it is run by a path \(`\/usr\/local\/bin\/PMMCP-TextQuery`\)/],
  ['./PMMCP-Ollama serve', /^it is run by a path \(`\.\/PMMCP-Ollama`\)/],
  // ollama in another case: told the way out as well, never taken (the stop compares it case exact).
  ['OLLAMA serve', /^`OLLAMA` is neither `ollama` nor one of pmmcp's named Ollama instances \(PMMCP-TextQuery, PMMCP-CodeQuery, PMMCP-TextIndex, PMMCP-CodeIndex, PMMCP-Ollama, case as written\) /],
  ['Ollama serve', /^`Ollama` is neither `ollama` nor one of pmmcp's named Ollama instances /],
  ['/opt/x/Ollama serve', /^it is run by a path \(`\/opt\/x\/Ollama`\)/],
  ['PMMCP-TextQuery serve --verbose', /^its command line has a word after `PMMCP-TextQuery serve` /],
  ['PMMCP-Ollama serve serve', /^its command line has a word after `PMMCP-Ollama serve` /],
  ['ollama serve 11434', /^its command line has a word after `ollama serve` /],
  ['PMMCP-TextQuery run', /^its command line is not `PMMCP-TextQuery serve` /],
  ['PMMCP-CodeQuery', /^its command line is not `PMMCP-CodeQuery serve` /],
  ['PMMCP-TextQuery Serve', /^its command line is not `PMMCP-TextQuery serve` /],
  ['pmmcp-textquery serve', /^`pmmcp-textquery` is none of pmmcp's named Ollama instances \(PMMCP-TextQuery, PMMCP-CodeQuery, PMMCP-TextIndex, PMMCP-CodeIndex, PMMCP-Ollama, case as written\) /],
  ['PMMCP-TEXTQUERY serve', /^`PMMCP-TEXTQUERY` is none of pmmcp's named Ollama instances /],
  ['PMMCP-Embedder serve', /^`PMMCP-Embedder` is none of pmmcp's named Ollama instances /],
  ['PMMCP- serve', /^`PMMCP-` is none of pmmcp's named Ollama instances /],
  // Another role's instance: the stop takes it only while it drains that role, so the pid is no longer the one it named.
  ['PMMCP-CodeIndex serve', /^its command line is `PMMCP-CodeIndex serve`, but the stop is draining PMMCP-TextQuery, and takes only `PMMCP-TextQuery serve` or `PMMCP-Ollama serve` for it \(the pid may have been given to another process since the stop's line\) /],
  ['PMMCP-CodeQuery serve', /^its command line is `PMMCP-CodeQuery serve`, but the stop is draining PMMCP-TextQuery/],
]

test("pmmcp's named Ollama instances are pmmcp's by the stop's _is_pmmcp_ollama for the role it drains: exactly `<role> serve` or `PMMCP-Ollama serve`, case exact, no path; `ollama serve`, a path, a third word, another name or role are refused with why and the way out", () => {
  assert.deepEqual(PMMCP_OLLAMA_ROLES, ['PMMCP-TextQuery', 'PMMCP-CodeQuery', 'PMMCP-TextIndex', 'PMMCP-CodeIndex'])
  assert.equal(PMMCP_OLLAMA_RELAUNCHED, 'PMMCP-Ollama')
  assert.deepEqual(PMMCP_OLLAMA_NAMES, ['PMMCP-TextQuery', 'PMMCP-CodeQuery', 'PMMCP-TextIndex', 'PMMCP-CodeIndex', 'PMMCP-Ollama'])
  for (const darwin of [false, true]) {
    for (const args of OLLAMA_ACCEPTED) {
      assert.equal(pmmcpOllama(args, TQ), true, args)
      assert.equal(targetRefusal(W(4242, TQ), snap({ args }), guard({ darwin })), undefined, `${args} (darwin ${String(darwin)})`)
    }
    // As the stop's `read -r` splits a ps row: more than one space between the words is still two words.
    assert.equal(targetRefusal(W(4242, TQ), snap({ args: 'PMMCP-Ollama  serve' }), guard({ darwin })), undefined)
    for (const [args, why] of OLLAMA_REFUSED) {
      assert.equal(pmmcpOllama(args, TQ), false, args)
      const refused = targetRefusal(W(4242, TQ), snap({ args }), guard({ darwin })) ?? ''
      assert.match(refused, why, `${args} (darwin ${String(darwin)}): ${refused}`)
      assert.match(refused, WAY_OUT, `${args} (darwin ${String(darwin)}): ${refused}`)
      assert.equal(ollamaRefusal(args, 4242, TQ), refused, args)
    }
  }
  // Each role, under both of the stop's labels for it: its own name and PMMCP-Ollama are taken, every other role's name is refused.
  for (const role of PMMCP_OLLAMA_ROLES) {
    for (const label of [`${role} (port 11436)`, `${role} port-scan (port 11436)`]) {
      assert.equal(ollamaRole(label), role, label)
      for (const name of PMMCP_OLLAMA_NAMES) {
        const args: string = `${name} serve`
        const taken: boolean = name === role || name === 'PMMCP-Ollama'
        assert.equal(pmmcpOllama(args, label), taken, `${args} under ${label}`)
        const refused = targetRefusal(W(4242, label), snap({ args }), guard())
        if (taken) assert.equal(refused, undefined, `${args} under ${label}`)
        else {
          assert.match(refused ?? '', new RegExp(`^its command line is \`${name} serve\`, but the stop is draining ${role}, and takes only \`${role} serve\` or \`PMMCP-Ollama serve\` for it `), `${args} under ${label}`)
          assert.match(refused ?? '', WAY_OUT)
        }
      }
    }
  }
  // A drain that is no Ollama instance's (a Worker, the MCP Server, or a label not in the stop's two forms): no Ollama form is taken.
  for (const label of ['Worker', 'MCP Server', 'Dashboard (port 8765)', 'PMMCP-TextQuery', 'PMMCP-TextQuery (port x)', 'PMMCP-TextQuery port-scan', 'pmmcp-textquery (port 11435)', 'PMMCP-Ollama (port 11434)', 'PMMCP-TextQuery (port 11435) extra']) {
    assert.equal(ollamaRole(label), undefined, label)
    for (const name of PMMCP_OLLAMA_NAMES) {
      const args: string = `${name} serve`
      assert.equal(pmmcpOllama(args, label), false, `${args} under ${label}`)
      const refused = targetRefusal(W(4242, label), snap({ args }), guard()) ?? ''
      assert.ok(refused.startsWith(`its command line is \`${name} serve\`, one of pmmcp's Ollama instances, but the stop is draining ${label}, which is none (the pid may have been given to another process since the stop's line) `), `${args} under ${label}: ${refused}`)
      assert.match(refused, WAY_OUT)
    }
  }
  // Not shaped like an Ollama server: the stop's other rule's reason, which offers no way out (Lima's hostagent is a VM).
  assert.equal(ollamaRefusal('/opt/homebrew/bin/limactl hostagent --pidfile x colima', 4242, TQ), undefined)
  assert.equal(ollamaRefusal('', 4242, TQ), undefined)
  assert.equal(ollamaRefusal('PMMCP-TextQuery serve', 4242, TQ), undefined)
  assert.equal(ollamaRefusal('/opt/homebrew/bin/ollamad serve', 4242, TQ), undefined)
  const foreign = targetRefusal(W(4242, TQ), snap({ args: '/opt/homebrew/bin/limactl hostagent --pidfile x colima' }), guard()) ?? ''
  assert.match(foreign, /^its command line names neither Persistent-Memory-MCP nor \/Users\/op\/Github\/Persistent-Memory-MCP, and is no named Ollama instance of pmmcp's \(`PMMCP-TextQuery serve` and the like\)$/)
  // What a terminal would act on is stripped from the words a refusal shows, a label's included.
  assert.doesNotMatch(ollamaRefusal('PMMCP-\x1b]0;x\x07Text serve', 4242, TQ) ?? '', /\x1b|\x07/)
  assert.doesNotMatch(ollamaRefusal('PMMCP-Ollama serve', 4242, 'Wor\x1b[2Jker') ?? '', /\x1b/)
  // The rest of the identity check holds for them as for any target: the uid, pid 1, the installer's and the stop's pids and groups, the start time.
  const args = 'PMMCP-TextQuery serve'
  assert.equal(targetRefusal(W(4242, TQ), snap({ args, uid: 502 }), guard()), "it is not this account's (uid 502)")
  assert.equal(targetRefusal(W(1, TQ), snap({ args }), guard()), 'it is pid 1')
  assert.equal(targetRefusal(W(INSTALLER, TQ), snap({ args }), guard()), "it is the installer's own process")
  assert.equal(targetRefusal(W(STOP, TQ), snap({ args }), guard()), 'it is the stop script itself')
  assert.equal(targetRefusal(W(4242, TQ), snap({ args, pgid: 6900 }), guard()), "it is in the installer's own process group")
  assert.equal(targetRefusal(W(4242, TQ), snap({ args, pgid: STOP }), guard()), "it is in the stop script's own process group")
  assert.match(targetRefusal(W(4242, TQ), snap({ args, startAfter: 'Wed Nov  4 09:00:07 2026' }), guard()) ?? '', /its start time changed while ps read it/)
  const kept = snap({ args })
  assert.match(targetRefusal(W(4242, TQ), snap({ args, start: 'Wed Nov  4 09:00:07 2026' }), guard(), kept) ?? '', /its start time changed: the pid was given to another process/)
  assert.match(targetRefusal(W(4242, TQ), snap({ args: 'PMMCP-Ollama serve' }), guard(), kept) ?? '', /its owner or command line changed/)
})

test('the identity check: only this account\'s pmmcp process outside the installer\'s and the stop\'s groups, never pid 1, and at the kill the very process the question named', () => {
  assert.equal(targetRefusal(W(4242), snap(), guard()), undefined)
  // Another uid.
  assert.equal(targetRefusal(W(4242), snap({ uid: 502 }), guard()), "it is not this account's (uid 502)")
  assert.match(targetRefusal(W(4242), snap(), guard({ uid: undefined })) ?? '', /not this account's/)
  // A foreign command line: a port's listener that is not pmmcp's, Lima's hostagent, an Ollama.app.
  assert.match(targetRefusal(W(4242), snap({ args: '/opt/homebrew/bin/limactl hostagent --pidfile x colima' }), guard()) ?? '', /^its command line names neither Persistent-Memory-MCP nor /)
  // The installer's own pid or group, the stop's own pid or group, pid 1.
  assert.equal(targetRefusal(W(INSTALLER), snap(), guard()), "it is the installer's own process")
  assert.equal(targetRefusal(W(4242), snap({ pgid: 6900 }), guard()), "it is in the installer's own process group")
  assert.equal(targetRefusal(W(STOP), snap(), guard()), 'it is the stop script itself')
  assert.equal(targetRefusal(W(4242), snap({ pgid: STOP }), guard()), "it is in the stop script's own process group")
  assert.equal(targetRefusal(W(4242), snap({ pgid: 7200, stopPgid: 7200 }), guard()), "it is in the stop script's own process group")
  assert.equal(targetRefusal(W(1), snap(), guard()), 'it is pid 1')
  // pid 0 and a negative pid, which process.kill would send to a process group (its own, or -pid's): never, even when ps shows a row for them.
  for (const pid of [0, -1, -4242]) assert.equal(targetRefusal(W(pid), snap({ pid }), guard()), `it is pid ${String(pid)}`)
  // Groups ps could not show: never taken as "not in them".
  assert.equal(targetRefusal(W(4242), snap({ installerPgid: undefined }), guard()), "the installer's own process group cannot be read")
  assert.equal(targetRefusal(W(4242), snap({ stopPgid: undefined }), guard()), 'the stop script is no longer running')
  // At the kill: a reused pid (another start time), or another owner or command line, is not the process asked about.
  const kept = snap()
  assert.equal(targetRefusal(W(4242), snap(), guard(), kept), undefined)
  assert.match(targetRefusal(W(4242), snap({ start: 'Wed Nov  4 09:00:07 2026' }), guard(), kept) ?? '', /its start time changed: the pid was given to another process/)
  assert.match(targetRefusal(W(4242), snap({ args: `${PMMCP_ARGS} --again` }), guard(), kept) ?? '', /its owner or command line changed/)
  // Within one snapshot: a start time read after the row that is not the one read before it.
  assert.match(targetRefusal(W(4242), snap({ startAfter: 'Wed Nov  4 09:00:07 2026' }), guard()) ?? '', /its start time changed while ps read it/)
  assert.match(targetRefusal(W(4242), snap({ startAfter: 'Wed Nov  4 09:00:07 2026' }), guard(), kept) ?? '', /its start time changed while ps read it/)
})

// ── the question and the kill ──

/** ps as a fake runner answers it: each call's stdout in a file of its own, read by readOut as the real one's is. */
class FakePs {
  readonly dir: string
  readonly specs: RunSpec[] = []
  readonly discarded: string[] = []
  /** What `ps -o lstart= -p <pid>` prints, by call (the last repeats); undefined: the pid is gone (exit 1, nothing). */
  starts: (string | undefined)[] = ['Wed Nov  4 09:00:00 2026']
  /** The rows `ps -o pid=,uid=,pgid=,args=` prints, by call (the last repeats). */
  rows: string[][] = [[`4242 ${String(ME)} 4000 ${PMMCP_ARGS}`, `${String(INSTALLER)} ${String(ME)} 6900 node (the installer)`, `${String(STOP)} ${String(ME)} ${String(STOP)} /bin/bash ${DIR}/stop-pmmcp-server.sh`]]
  /** Ends of a call, in order, before its answer: a Ctrl-C reached that ps. */
  interrupted = 0
  /** How such a ps ended: by the signal, or as a shell reports one (130 for SIGINT, 129 for SIGHUP). */
  interruptedAs: { readonly code: number | null; readonly signal: NodeJS.Signals | null } = { code: null, signal: 'SIGINT' }
  /** Runs as call n (from 1) begins, before it is answered. */
  onCall: (n: number) => void = () => undefined
  #n = 0
  #lstart = 0
  #listed = 0

  constructor(t: TestContext) {
    this.dir = tmpdir(t)
  }

  run = (spec: RunSpec): Promise<RunResult> => {
    this.specs.push(spec)
    this.#n += 1
    this.onCall(this.#n)
    const out = join(this.dir, `${spec.step}-${String(this.#n)}.out`)
    const base = { step: spec.step, pid: 90000 + this.#n, out, err: `${out}.err`, started: new Date(0), elapsedMs: 1, timedOut: false, exited: true, stdinError: undefined, childError: undefined, activeError: undefined }
    if (this.interrupted > 0) {
      this.interrupted -= 1
      writeFileSync(out, '', { mode: 0o600 })
      return Promise.resolve({ ...base, ...this.interruptedAs })
    }
    if (spec.args[1] === 'lstart=') {
      const start = this.starts[Math.min(this.#lstart, this.starts.length - 1)]
      this.#lstart += 1
      writeFileSync(out, start === undefined ? '' : `${start}\n`, { mode: 0o600 })
      return Promise.resolve({ ...base, code: start === undefined ? 1 : 0, signal: null })
    }
    const rows = this.rows[Math.min(this.#listed, this.rows.length - 1)] ?? []
    this.#listed += 1
    writeFileSync(out, rows.map((r) => `  ${r}\n`).join(''), { mode: 0o600 })
    return Promise.resolve({ ...base, code: 0, signal: null })
  }

  discard = (result: Pick<RunResult, 'step' | 'out' | 'err'>): string | undefined => {
    this.discarded.push(result.out)
    return undefined
  }
}

interface Offer {
  readonly ps: FakePs
  readonly asked: string[]
  readonly printed: string[]
  readonly kills: number[]
  readonly logDir: string
  options: Omit<ForceQuitOptions, 'ask'>
  answers: Answer[]
  kill: (pid: number) => Kill
  /** Runs while the question is open, before its answer comes back. */
  whileAsked: () => void
}

const TARGET: DrainTarget = { pid: 4242, label: 'Worker', upTo: 30, seenAt: 1_000_000 }

function offer(t: TestContext): Offer {
  const ps = new FakePs(t)
  const logDir = tmpdir(t)
  const o: Offer = {
    ps,
    asked: [],
    printed: [],
    kills: [],
    logDir,
    answers: [{ kind: 'line', text: 'force-quit' }],
    kill: (pid) => {
      o.kills.push(pid)
      return { sent: true }
    },
    whileAsked: () => undefined,
    options: {
      runner: ps,
      cwd: '/Users/op/MrRobot',
      stopPid: STOP,
      target: () => TARGET,
      running: () => true,
      dir: DIR,
      print: (line) => o.printed.push(line),
      logDir,
      uid: ME,
      installerPid: INSTALLER,
      darwin: false,
      now: () => 1_042_400,
    },
  }
  return o
}

async function run(o: Offer): Promise<Awaited<ReturnType<typeof offerForceQuitWith>>> {
  return offerForceQuitWith(
    {
      ...o.options,
      ask: (question) => {
        o.asked.push(question)
        o.whileAsked()
        return Promise.resolve(o.answers.shift() ?? { kind: 'eof' })
      },
    },
    (pid) => o.kill(pid),
  )
}

test('the force-quit asks about the target ps confirmed, by its label, pid, command line and wait, and only the typed word force-quit SIGKILLs it, once, and only it', async (t) => {
  const o = offer(t)
  const outcome = await run(o)
  assert.deepEqual(outcome, { kind: 'killed', record: { label: 'Worker', pid: 4242, seconds: 42 } })
  assert.deepEqual(o.asked, [
    `pmmcp's stop is waiting on Worker (PID 4242: ${PMMCP_ARGS}) for 42s. Type force-quit to SIGKILL that one process (the stop then goes on); anything else keeps waiting:`,
  ])
  assert.deepEqual(o.kills, [4242], 'only the target, once')
  // ps through the runner, read-only, with a timeout: the start time, the row and the start time again to confirm, the same three just before the kill; its files emptied once read.
  const lstart = 'ps -o lstart= -p 4242'
  const row = `ps -ww -o pid=,uid=,pgid=,args= -p 4242,${String(INSTALLER)},${String(STOP)}`
  assert.deepEqual(
    o.ps.specs.map((s) => [s.command, ...s.args].join(' ')),
    [lstart, row, lstart, lstart, row, lstart],
  )
  assert.ok(o.ps.specs.every((s) => s.timeoutMs !== undefined && s.ownSession === undefined && s.digest === undefined))
  assert.equal(o.ps.discarded.length, 6)
  assert.ok(o.printed.includes('SIGKILL sent to Worker (PID 4242) at your typed force-quit: the stop sees it gone and goes on'), o.printed.join('\n'))
  // The run folder's record: 0600, the end report's line, the command line and the start time.
  const log = join(o.logDir, FORCE_QUIT_LOG)
  assert.equal(statSync(log).mode & 0o777, 0o600)
  const text = readFileSync(log, 'utf8')
  assert.match(text, /^\d{4}-\d\d-\d\dT[\d:.]+Z force-quit: Worker \(PID 4242\) SIGKILLed at your typed force-quit after 42s\n {2}command line: .*run_worker\.py\n {2}started \(ps lstart\): Wed Nov {2}4 09:00:00 2026\n$/)
  assert.equal(forceQuitLine({ label: 'Worker', pid: 4242, seconds: 42 }), 'force-quit: Worker (PID 4242) SIGKILLed at your typed force-quit after 42s')
})

test('anything but force-quit keeps waiting: another word, the input ending, a second Ctrl-C at the question; nothing is signalled', async (t) => {
  for (const answer of [{ kind: 'line', text: 'force quit' }, { kind: 'line', text: 'FORCE-QUIT' }, { kind: 'line', text: 'y' }, { kind: 'line', text: '' }, { kind: 'eof' }, { kind: 'interrupt' }] as const) {
    const o = offer(t)
    o.answers = [answer]
    assert.deepEqual(await run(o), { kind: 'kept-waiting' }, JSON.stringify(answer))
    assert.deepEqual(o.kills, [], JSON.stringify(answer))
    assert.equal(o.asked.length, 1)
    assert.match(o.printed.at(-1) ?? '', /: nothing was signalled, and the stop goes on waiting on Worker \(PID 4242\)$/, JSON.stringify(answer))
    // Confirmed once, never checked again for a kill that is not coming.
    assert.equal(o.ps.specs.length, 3)
  }
  // The word is read as the gate reads every typed word: trimmed.
  const o = offer(t)
  o.answers = [{ kind: 'line', text: '  force-quit ' }]
  assert.equal((await run(o)).kind, 'killed')
})

test('no target, or one ps does not confirm, is said in one line, and nothing is asked or signalled', async (t) => {
  // The stop counts jobs, stops Qdrant or is between services.
  const none = offer(t)
  none.options = { ...none.options, target: () => undefined }
  assert.deepEqual(await run(none), { kind: 'no-target' })
  assert.deepEqual(none.printed, [NO_TARGET])
  assert.deepEqual([none.asked, none.kills, none.ps.specs], [[], [], []])

  const cases: [string, (o: Offer) => void, RegExp][] = [
    ['another uid', (o) => (o.ps.rows = [[`4242 502 4000 ${PMMCP_ARGS}`, `${String(INSTALLER)} ${String(ME)} 6900 node`, `${String(STOP)} ${String(ME)} ${String(STOP)} bash`]]), /it is not this account's \(uid 502\)/],
    ['a foreign command line', (o) => (o.ps.rows = [['4242 501 4000 /usr/libexec/sshd-session', `${String(INSTALLER)} 501 6900 node`, `${String(STOP)} 501 ${String(STOP)} bash`]]), /its command line names neither/],
    ["the stop's own group", (o) => (o.ps.rows = [[`4242 501 ${String(STOP)} ${PMMCP_ARGS}`, `${String(INSTALLER)} 501 6900 node`, `${String(STOP)} 501 ${String(STOP)} bash`]]), /the stop script's own process group/],
    ["the installer's own group", (o) => (o.ps.rows = [[`4242 501 6900 ${PMMCP_ARGS}`, `${String(INSTALLER)} 501 6900 node`, `${String(STOP)} 501 ${String(STOP)} bash`]]), /the installer's own process group/],
    ['an exited target', (o) => (o.ps.starts = [undefined]), /it has exited/],
    ['a ps the Ctrl-C ended every time', (o) => (o.ps.interrupted = PS_TRIES), /cannot be checked \(ps was interrupted 3 times\)/],
  ]
  for (const [what, set, why] of cases) {
    const o = offer(t)
    set(o)
    const outcome = await run(o)
    assert.equal(outcome.kind, 'refused', what)
    assert.deepEqual([o.asked, o.kills], [[], []], what)
    assert.equal(o.printed.length, 1, what)
    assert.match(o.printed[0] ?? '', /^pmmcp's stop is waiting on Worker \(PID 4242\), but .*: nothing is force-quit, and the stop goes on$/, what)
    assert.match(o.printed[0] ?? '', why, what)
  }
  // A ps the Ctrl-C ended once is asked again, and the offer goes on: ended by SIGINT, or by SIGHUP (a closed terminal's, which
  // reaches the installer's group too), or exiting as a shell reports either.
  for (const as of [{ code: null, signal: 'SIGINT' }, { code: null, signal: 'SIGHUP' }, { code: 130, signal: null }, { code: 129, signal: null }] as const) {
    const again = offer(t)
    again.ps.interrupted = 1
    again.ps.interruptedAs = as
    assert.equal((await run(again)).kind, 'killed', JSON.stringify(as))
    assert.equal(again.ps.specs.length, 7, JSON.stringify(as))
  }
  // Ended by any other signal: no answer, not asked again.
  const termed = offer(t)
  termed.ps.interrupted = 1
  termed.ps.interruptedAs = { code: null, signal: 'SIGTERM' }
  assert.equal((await run(termed)).kind, 'refused')
  assert.equal(termed.ps.specs.length, 1)
  assert.match(termed.printed[0] ?? '', /cannot be checked \(ps ended by SIGTERM\)/)
})

test("a Ctrl-C while the stop drains one of pmmcp's named Ollama instances asks, and force-quit SIGKILLs it; `ollama serve`, a path, a third word, another name or role, or an Ollama form under another service's drain is not asked about or signalled, and the line says why and the way out", async (t) => {
  const rowsOf = (args: string): string[] => [`4242 ${String(ME)} 4000 ${args}`, `${String(INSTALLER)} ${String(ME)} 6900 node (the installer)`, `${String(STOP)} ${String(ME)} ${String(STOP)} /bin/bash ${DIR}/stop-pmmcp-server.sh`]
  // The stop's own label for an Ollama drain: graceful_kill "$pid" "${_ol_name} (port ${_ol_port})" 10.
  const drain: DrainTarget = { pid: 4242, label: 'PMMCP-TextQuery (port 11435)', upTo: 10, seenAt: 1_000_000 }
  const ollamaOffer = (args: string, darwin: boolean): Offer => {
    const o = offer(t)
    o.ps.rows = [rowsOf(args)]
    o.options = { ...o.options, target: () => drain, darwin }
    return o
  }
  for (const darwin of [false, true]) {
    for (const args of OLLAMA_ACCEPTED) {
      const o = ollamaOffer(args, darwin)
      assert.deepEqual(await run(o), { kind: 'killed', record: { label: drain.label, pid: 4242, seconds: 42 } }, args)
      assert.deepEqual(o.kills, [4242], args)
      assert.deepEqual(o.asked, [
        `pmmcp's stop is waiting on PMMCP-TextQuery (port 11435) (PID 4242: ${args}) for 42s. Type force-quit to SIGKILL that one process (the stop then goes on); anything else keeps waiting:`,
      ])
      assert.match(readFileSync(join(o.logDir, FORCE_QUIT_LOG), 'utf8'), new RegExp(`force-quit: PMMCP-TextQuery \\(port 11435\\) \\(PID 4242\\) SIGKILLed at your typed force-quit after 42s\\n {2}command line: ${args}\\n`))
      // Another word keeps waiting for these too.
      const no = ollamaOffer(args, darwin)
      no.answers = [{ kind: 'line', text: 'y' }]
      assert.deepEqual(await run(no), { kind: 'kept-waiting' }, args)
      assert.deepEqual(no.kills, [], args)
    }
    for (const [args, why] of OLLAMA_REFUSED) {
      const o = ollamaOffer(args, darwin)
      assert.equal((await run(o)).kind, 'refused', args)
      assert.deepEqual([o.asked, o.kills], [[], []], args)
      assert.equal(o.printed.length, 1, args)
      const line = o.printed[0] ?? ''
      assert.match(line, /^pmmcp's stop is waiting on PMMCP-TextQuery \(port 11435\) \(PID 4242\), but .* \(to end it, check it with `ps -ww -o pid,uid,lstart,args -p 4242` in another terminal, and end it there if it is pmmcp's\): nothing is force-quit, and the stop goes on$/, args)
      assert.match(line, new RegExp(why.source.slice(1)), args)
    }
  }
  // A Worker's drain whose pid ps shows as one of pmmcp's Ollama instances (the pid given to it since the stop's line): the stop
  // would not take it for the Worker, and nor does the installer.
  for (const args of PMMCP_OLLAMA_NAMES.map((n) => `${n} serve`)) {
    const o = ollamaOffer(args, true)
    o.options = { ...o.options, target: () => TARGET }
    assert.equal((await run(o)).kind, 'refused', args)
    assert.deepEqual([o.asked, o.kills], [[], []], args)
    assert.match(o.printed[0] ?? '', new RegExp(`^pmmcp's stop is waiting on Worker \\(PID 4242\\), but its command line is \`${args}\`, one of pmmcp's Ollama instances, but the stop is draining Worker, which is none `), args)
  }
  // Under the CodeIndex drain, the TextQuery instance's command line is refused; the CodeIndex one's and PMMCP-Ollama's are asked about.
  for (const [args, kind] of [['PMMCP-TextQuery serve', 'refused'], ['PMMCP-CodeIndex serve', 'killed'], ['PMMCP-Ollama serve', 'killed']] as const) {
    const o = ollamaOffer(args, false)
    o.options = { ...o.options, target: () => ({ ...drain, label: 'PMMCP-CodeIndex port-scan (port 11437)' }) }
    assert.equal((await run(o)).kind, kind, args)
    assert.deepEqual(o.kills, kind === 'killed' ? [4242] : [], args)
  }
  // The pid given to Ollama.app's server between the question and the kill (another start time, its command line a path): not signalled.
  const reused = ollamaOffer('PMMCP-TextQuery serve', true)
  reused.ps.rows = [rowsOf('PMMCP-TextQuery serve'), rowsOf('/Applications/Ollama.app/Contents/Resources/ollama serve')]
  reused.ps.starts = ['Wed Nov  4 09:00:00 2026', 'Wed Nov  4 09:00:00 2026', 'Wed Nov  4 09:00:07 2026']
  assert.equal((await run(reused)).kind, 'refused')
  assert.equal(reused.asked.length, 1)
  assert.deepEqual(reused.kills, [])
  assert.match(reused.printed.at(-1) ?? '', /but it is run by a path \(`\/Applications\/Ollama\.app\/Contents\/Resources\/ollama`\)/)
})

test('a pid given to another process, a drain that moved on, the stop ending or the offer withdrawn between the question and the kill: nothing is signalled', async (t) => {
  // A reused pid: another start time just before the kill.
  const reused = offer(t)
  reused.ps.starts = ['Wed Nov  4 09:00:00 2026', 'Wed Nov  4 09:00:00 2026', 'Wed Nov  4 09:00:41 2026']
  assert.equal((await run(reused)).kind, 'refused')
  assert.deepEqual(reused.kills, [])
  assert.match(reused.printed.at(-1) ?? '', /its start time changed: the pid was given to another process/)
  // Another command line on the same pid.
  const changed = offer(t)
  changed.ps.rows = [changed.ps.rows[0] ?? [], [`4242 501 4000 ${DIR}/.venv/bin/python other.py`, `${String(INSTALLER)} 501 6900 node`, `${String(STOP)} 501 ${String(STOP)} bash`]]
  assert.equal((await run(changed)).kind, 'refused')
  assert.deepEqual(changed.kills, [])
  // The drain moved on to another service while the question was open.
  const moved = offer(t)
  let target: DrainTarget | undefined = TARGET
  moved.options = { ...moved.options, target: () => target }
  moved.whileAsked = () => (target = { pid: 4300, label: 'Scraper Worker', upTo: 15, seenAt: 1_040_000 })
  assert.deepEqual(await run(moved), { kind: 'kept-waiting' })
  assert.deepEqual(moved.kills, [])
  assert.match(moved.printed.at(-1) ?? '', /the stop is no longer waiting on Worker \(PID 4242\): nothing was signalled/)
  // The same pid under another label while the question was open: the stop is draining something else by its own account.
  const relabelled = offer(t)
  let current: DrainTarget | undefined = TARGET
  relabelled.options = { ...relabelled.options, target: () => current }
  relabelled.whileAsked = () => (current = { ...TARGET, label: 'Scraper Worker' })
  assert.deepEqual(await run(relabelled), { kind: 'kept-waiting' })
  assert.deepEqual(relabelled.kills, [])
  assert.equal(relabelled.ps.specs.length, 3, 'checked again for a kill that is not coming')
  assert.match(relabelled.printed.at(-1) ?? '', /the stop is no longer waiting on Worker \(PID 4242\): nothing was signalled/)
  // The target exited while the question was open.
  const gone = offer(t)
  gone.ps.starts = ['Wed Nov  4 09:00:00 2026', 'Wed Nov  4 09:00:00 2026', undefined]
  assert.deepEqual(await run(gone), { kind: 'kept-waiting' })
  assert.deepEqual(gone.kills, [])
  // The stop finished while the question was open (the entry point answers it then).
  const ended = offer(t)
  let running = true
  ended.options = { ...ended.options, running: () => running }
  ended.whileAsked = () => (running = false)
  assert.deepEqual(await run(ended), { kind: 'kept-waiting' })
  assert.deepEqual(ended.kills, [])
  assert.deepEqual(ended.printed, ['the stop has finished meanwhile: nothing was signalled'])
  // Withdrawn (a second Ctrl-C) before the question: never asked.
  const withdrawn = offer(t)
  const c = new AbortController()
  c.abort()
  withdrawn.options = { ...withdrawn.options, cancelled: c.signal }
  assert.deepEqual(await run(withdrawn), { kind: 'kept-waiting' })
  assert.deepEqual([withdrawn.asked, withdrawn.kills], [[], []])
  // A kill that finds the pid gone (ESRCH) is no kill, and no record.
  const raced = offer(t)
  raced.kill = (pid) => {
    raced.kills.push(pid)
    return { sent: false, why: 'ESRCH' }
  }
  assert.deepEqual(await run(raced), { kind: 'kept-waiting' })
  assert.equal(raced.printed.at(-1), 'Worker (PID 4242) has exited meanwhile: nothing was signalled, and the stop goes on waiting on Worker (PID 4242)')
  assert.throws(() => statSync(join(raced.logDir, FORCE_QUIT_LOG)), /ENOENT/)
  // A kill the system refuses (EPERM) is no kill either, and is said as a refusal, not as an exit.
  const denied = offer(t)
  denied.kill = (pid) => {
    denied.kills.push(pid)
    return { sent: false, why: 'EPERM' }
  }
  assert.deepEqual(await run(denied), { kind: 'refused', why: 'SIGKILL could not be sent (EPERM)' })
  assert.deepEqual(denied.kills, [4242])
  assert.equal(denied.printed.at(-1), "pmmcp's stop is waiting on Worker (PID 4242), but SIGKILL could not be sent (EPERM): nothing is force-quit, and the stop goes on")
  assert.throws(() => statSync(join(denied.logDir, FORCE_QUIT_LOG)), /ENOENT/)
})

test("the install's folder is compared as typed and as resolved, as the stop compares both: through a symlink to it, a command line naming either is asked about", async (t) => {
  const real = join(realpathSync(tmpdir(t)), 'pmmcp-real')
  mkdirSync(real)
  const link = join(tmpdir(t), 'pmmcp-link')
  symlinkSync(real, link)
  const rowsOf = (args: string): string[] => [`4242 ${String(ME)} 4000 ${args}`, `${String(INSTALLER)} ${String(ME)} 6900 node`, `${String(STOP)} ${String(ME)} ${String(STOP)} bash`]
  for (const folder of [real, link]) {
    const args = `${folder}/.venv/bin/python ${folder}/scripts/run_worker.py`
    const o = offer(t)
    o.ps.rows = [rowsOf(args)]
    o.options = { ...o.options, dir: link }
    assert.equal((await run(o)).kind, 'killed', folder)
    assert.deepEqual(o.kills, [4242], folder)
    assert.match(o.asked[0] ?? '', new RegExp(`\\(PID 4242: ${args.replace(/[.]/g, '\\.')}\\)`), folder)
  }
  // A folder that is not there to resolve is compared as typed only: the real folder's command line is no longer pmmcp's by it.
  const missing = offer(t)
  missing.ps.rows = [rowsOf(`${real}/.venv/bin/python ${real}/scripts/run_worker.py`)]
  missing.options = { ...missing.options, dir: join(tmpdir(t), 'gone') }
  assert.equal((await run(missing)).kind, 'refused')
  assert.deepEqual([missing.asked, missing.kills], [[], []])
  assert.match(missing.printed[0] ?? '', /its command line names neither Persistent-Memory-MCP nor /)
})

test('a pid given to a copy of the same service while ps reads it is caught by the start time read after the row: nothing is asked or signalled', async (t) => {
  const A = 'Wed Nov  4 09:00:00 2026'
  const B = 'Wed Nov  4 09:00:43 2026'
  // Just before the kill: the re-check's first start time is the one asked about and its row is the same uid and command line (a respawned
  // copy, outside both groups); only the start time read after the row tells the processes apart.
  const respawned = offer(t)
  respawned.ps.starts = [A, A, A, B]
  assert.equal((await run(respawned)).kind, 'refused')
  assert.deepEqual(respawned.kills, [])
  assert.equal(respawned.asked.length, 1)
  assert.equal(respawned.ps.specs.length, 6)
  assert.match(respawned.printed.at(-1) ?? '', /^pmmcp's stop is waiting on Worker \(PID 4242\), but its start time changed while ps read it \(the pid was given to another process\): nothing is force-quit, and the stop goes on$/)
  // At the first look: never asked.
  const first = offer(t)
  first.ps.starts = [A, B]
  assert.equal((await run(first)).kind, 'refused')
  assert.deepEqual([first.asked, first.kills], [[], []])
  assert.match(first.printed.at(-1) ?? '', /its start time changed while ps read it/)
})

test('a second Ctrl-C, or the stop ending, while the re-check before the kill runs: nothing is signalled, and nothing recorded', async (t) => {
  // The Ctrl-C withdraws the offer (forceQuitOffered aborts `cancelled`) and ends the re-check's first ps, which is asked again.
  const o = offer(t)
  const c = new AbortController()
  o.options = { ...o.options, cancelled: c.signal }
  o.ps.onCall = (n) => {
    if (n !== 4) return
    c.abort()
    o.ps.interrupted = 1
  }
  assert.deepEqual(await run(o), { kind: 'kept-waiting' })
  assert.deepEqual(o.kills, [])
  assert.equal(o.asked.length, 1)
  assert.equal(o.ps.specs.length, 7, 'the interrupted ps was asked again, and the re-check finished')
  assert.deepEqual(o.printed, ['the force-quit was withdrawn (Ctrl-C again): nothing was signalled, and the stop goes on waiting on Worker (PID 4242)'])
  assert.throws(() => statSync(join(o.logDir, FORCE_QUIT_LOG)), /ENOENT/)
  // The stop finished during the re-check's last ps.
  const ended = offer(t)
  let running = true
  ended.options = { ...ended.options, running: () => running }
  ended.ps.onCall = (n) => {
    if (n === 6) running = false
  }
  assert.deepEqual(await run(ended), { kind: 'kept-waiting' })
  assert.deepEqual(ended.kills, [])
  assert.deepEqual(ended.printed, ['the stop has finished meanwhile: nothing was signalled'])
})

test("force-quit.log is appended only as this account's own regular file in the run's log folder: never through a symlink or a second hard link, and a wider mode is made 0600", async (t) => {
  const killed = { kind: 'killed', record: { label: 'Worker', pid: 4242, seconds: 42 } }
  const elsewhere = tmpdir(t)
  // A symlink there to a file outside the log folder: the kill stands, the record is not written, and the file it names is untouched.
  const target = join(elsewhere, 'symlinked.txt')
  writeFileSync(target, 'untouched\n', { mode: 0o600 })
  const linked = offer(t)
  symlinkSync(target, join(linked.logDir, FORCE_QUIT_LOG))
  assert.deepEqual(await run(linked), killed)
  assert.deepEqual(linked.kills, [4242])
  assert.match(linked.printed.at(-1) ?? '', /^the force-quit is not recorded in the run's log folder: .*force-quit\.log could not be opened \(ELOOP\)$/)
  assert.equal(readFileSync(target, 'utf8'), 'untouched\n')
  assert.equal(statSync(target).mode & 0o777, 0o600)
  // A second hard link of a file outside it.
  const other = join(elsewhere, 'hardlinked.txt')
  writeFileSync(other, 'untouched\n', { mode: 0o644 })
  const hard = offer(t)
  linkSync(other, join(hard.logDir, FORCE_QUIT_LOG))
  assert.deepEqual(await run(hard), killed)
  assert.deepEqual(hard.kills, [4242])
  assert.match(hard.printed.at(-1) ?? '', /^the force-quit is not recorded in the run's log folder: .*force-quit\.log is not this account's regular file$/)
  assert.equal(readFileSync(other, 'utf8'), 'untouched\n')
  assert.equal(statSync(other).mode & 0o777, 0o644, 'the linked file was made 0600')
  // A 0644 force-quit.log of its own already there: appended to, and made 0600.
  const wide = offer(t)
  const log = join(wide.logDir, FORCE_QUIT_LOG)
  writeFileSync(log, 'an earlier record\n')
  chmodSync(log, 0o644)
  assert.deepEqual(await run(wide), killed)
  assert.equal(statSync(log).mode & 0o777, 0o600)
  assert.match(readFileSync(log, 'utf8'), /^an earlier record\n\S+ force-quit: Worker \(PID 4242\) SIGKILLed at your typed force-quit after 42s\n/)
  assert.equal(wide.printed.some((l) => l.includes('not recorded')), false, wide.printed.join('\n'))
  // A file there that is not the installer's own (owned by another uid than the one that creates it): not written, its mode kept.
  const notMine = /^the force-quit is not recorded in the run's log folder: .*force-quit\.log is not this account's regular file$/
  const foreign = offer(t)
  const foreignLog = join(foreign.logDir, FORCE_QUIT_LOG)
  writeFileSync(foreignLog, 'theirs\n')
  chmodSync(foreignLog, 0o644)
  foreign.options = { ...foreign.options, euid: (process.geteuid?.() ?? 0) + 1 }
  assert.deepEqual(await run(foreign), killed)
  assert.match(foreign.printed.at(-1) ?? '', notMine)
  assert.equal(readFileSync(foreignLog, 'utf8'), 'theirs\n')
  assert.equal(statSync(foreignLog).mode & 0o777, 0o644)
  // As root, a real file of nobody's, the installer's own uid the default.
  if (process.geteuid?.() === 0) {
    const nobody = offer(t)
    const nobodyLog = join(nobody.logDir, FORCE_QUIT_LOG)
    writeFileSync(nobodyLog, 'nobody\n', { mode: 0o600 })
    chownSync(nobodyLog, 65534, 65534)
    assert.deepEqual(await run(nobody), killed)
    assert.match(nobody.printed.at(-1) ?? '', notMine)
    assert.equal(readFileSync(nobodyLog, 'utf8'), 'nobody\n')
    assert.equal(statSync(nobodyLog).uid, 65534)
  }
})

test('the question cuts a long command line and strips what a terminal would act on', () => {
  const long = `${DIR}/.venv/bin/python \x1b[31m${'x'.repeat(300)}`
  const q = forceQuitQuestion({ pid: 9, label: 'MCP\x1b[2J Server' }, long, 5)
  assert.equal(q.includes('\x1b'), false)
  const shown = /\(PID 9: (.*)\) for 5s\. /.exec(q)?.[1] ?? ''
  assert.equal(shown.length, CMD_SHOWN)
  assert.ok(shown.endsWith('...'))
  assert.ok(q.startsWith("pmmcp's stop is waiting on MCP Server (PID 9: "), q)
})

// ── the SIGINT branch ──

test("a Ctrl-C while L1's stop runs offers the force-quit; SIGHUP and SIGTERM there, and a Ctrl-C anywhere else in the window, are trapped as before; a question open still takes it", () => {
  const view = (o: Partial<SignalView> = {}): SignalView => ({ promptOpen: false, windowOpen: true, stopping: true, reporting: true, counting: false, last: undefined, ...o })
  assert.deepEqual(onSignal(view(), 'SIGINT', 1000), { kind: 'force-quit' })
  assert.deepEqual(onSignal(view(), 'SIGHUP', 1000), { kind: 'trapped' }, 'a closed terminal cannot answer a question')
  assert.deepEqual(onSignal(view(), 'SIGTERM', 1000), { kind: 'trapped' })
  // The force-quit's own question open (or any other): the Ctrl-C answers it, which keeps waiting.
  assert.deepEqual(onSignal(view({ promptOpen: true }), 'SIGINT', 1000), { kind: 'answered' })
  // npm's second delivery of the same Ctrl-C is no second offer.
  assert.deepEqual(onSignal(view({ last: { signal: 'SIGINT', at: 1000 } }), 'SIGINT', 1001), { kind: 'repeat' })
  // Outside L1 (the start, the cutover, the update, auth init), inside the window: trapped, whatever the signal.
  for (const signal of HANDLED_SIGNALS) assert.deepEqual(onSignal(view({ stopping: false }), signal, 1000), { kind: 'trapped' }, signal)
  // Outside the window nothing of it applies, whatever `stopping` says.
  assert.deepEqual(onSignal(view({ windowOpen: false }), 'SIGINT', 1000), { kind: 'held' })
  assert.deepEqual(onSignal(view({ windowOpen: false, reporting: false }), 'SIGINT', 1000), { kind: 'exit', code: 130 })

  // handleSignal hands it to the effect, and keeps it out of what the window trapped.
  const done: string[] = []
  const state: SignalState = { windowOpen: true, stopping: true, reporting: true, counting: false, last: undefined, trapped: new Set(), held: new Set() }
  const effects = {
    promptOpen: (): boolean => false,
    answer: (): void => void done.push('answer'),
    forceQuit: (): void => void done.push('force-quit'),
    trapped: (s: HandledSignal): void => void done.push(`trapped ${s}`),
    held: (s: HandledSignal): void => void done.push(`held ${s}`),
    abortCount: (): void => void done.push('abort'),
    exit: (code: number): void => void done.push(`exit ${String(code)}`),
  }
  handleSignal(state, 'SIGINT', 5000, effects)
  handleSignal(state, 'SIGINT', 5001, effects)
  handleSignal(state, 'SIGHUP', 6000, effects)
  handleSignal(state, 'SIGINT', 7000, effects)
  assert.deepEqual(done, ['force-quit', 'trapped SIGHUP', 'force-quit'])
  assert.deepEqual([...state.trapped], ['SIGHUP'])
})
