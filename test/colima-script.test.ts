import './helpers/guard.js'

// scripts/colima-up.sh (egress plan C1), run as a program against fake colima,
// limactl and docker, never the real ones: each run's PATH is one directory
// holding the three fakes and links to the four system tools the script needs
// (dirname, mkdir, awk, cat), so no other program on this machine, a real
// docker or colima included, can be reached by name. The script runs from a
// copy in a temporary repository, with HOME a temporary directory, so it makes
// nothing in this checkout or in a real home.
//
// The fakes log every call, one line each (an argument holding a newline
// carries a call onto the next line, which run() does not count as a call),
// tab-separated: the tool, docker's
// DOCKER_HOST, then the arguments; and, in a second log (NUL-separated), the
// DOCKER_CONFIG and COLIMA_CACHE_HOME each call ran with, which every run
// holds to the program folder and ~/.colima. A fake colima answers `status <profile>`
// with the exit codes its state file lists for that profile, one a call (the
// last repeated), `start` with the exit code its state file names for that
// profile, 0 unless one is named (as Colima 0.10.3 answers "already running,
// ignoring" with 0 on a VM whose first start never finished), and
// `ssh --profile <profile> -- cat /proc/mounts` with the mount table its state
// file holds for that profile; it refuses status and ssh unless their stdin is
// /dev/null, and the script runs with stdin a pipe, so a redirect dropped
// shows. A fake docker keeps each network's Internal flag in a file, prints
// it for `network inspect --format`, fails that inspect for a network its
// state file names, and fails `network create` for a network its state file
// names. Anything else is refused with 64, so a call the script was not
// expected to make fails the run.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { test, type TestContext } from 'node:test'

import { REPO_ROOT } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'

const SCRIPT = 'scripts/colima-up.sh'
const DOMAINS = ['trusted', 'hostile'] as const
type Domain = (typeof DOMAINS)[number]

/** The first of these that exists: system tools only, never /usr/local/bin or /opt/homebrew/bin, where a real colima or docker lives. */
function systemTool(name: string): string {
  for (const dir of ['/bin', '/usr/bin']) {
    const path = join(dir, name)
    if (existsSync(path)) return path
  }
  throw new Error(`no ${name} in /bin or /usr/bin`)
}

const BASH = systemTool('bash')

const FAKE_COLIMA = `#!${BASH}
state="\${FAKE_STATE:?}"
{ printf 'colima'; printf '\\t%s' "$@"; printf '\\n'; } >> "\${state}/calls"
printf 'colima\\0%s\\0%s\\0' "\${DOCKER_CONFIG-<unset>}" "\${COLIMA_CACHE_HOME-<unset>}" >> "\${state}/env"
stdin_null() { [ /dev/stdin -ef /dev/null ] || { echo "fake colima: $1 with stdin not /dev/null" >&2; exit 64; }; }
case "\${1:-}" in
  status)
    stdin_null status
    [ "$#" -eq 2 ] || { echo "fake colima: status takes one profile" >&2; exit 64; }
    f="\${state}/status-$2"
    n=0
    if [ -f "\${f}.n" ]; then read -r n < "\${f}.n"; fi
    codes=()
    if [ -f "\${f}" ]; then read -r -a codes < "\${f}"; fi
    if [ "\${#codes[@]}" -eq 0 ]; then code=1
    elif [ "\${n}" -lt "\${#codes[@]}" ]; then code="\${codes[\${n}]}"
    else code="\${codes[\${#codes[@]}-1]}"; fi
    printf '%s\\n' "$((n + 1))" > "\${f}.n"
    if [ "\${code}" -eq 0 ]; then echo "colima [profile=$2] is running" >&2; else echo "colima [profile=$2] is not running" >&2; fi
    exit "\${code}"
    ;;
  start)
    code=0
    if [ -f "\${state}/start-$2" ]; then read -r code < "\${state}/start-$2"; fi
    if [ "\${code}" -eq 0 ]; then echo "colima [profile=$2] already running, ignoring" >&2; else echo "colima [profile=$2] error starting vm: fake failure" >&2; fi
    exit "\${code}"
    ;;
  ssh)
    if [ "$#" -ne 6 ] || [ "$2" != --profile ] || [ "$4" != -- ] || [ "$5" != cat ] || [ "$6" != /proc/mounts ]; then
      echo "fake colima: unexpected ssh" >&2; exit 64
    fi
    stdin_null ssh
    if [ -f "\${state}/ssh-fails-$3" ]; then echo "fake colima: ssh failed" >&2; exit 255; fi
    cat "\${state}/mounts-$3"
    ;;
  *)
    echo "fake colima: unexpected command" >&2; exit 64
    ;;
esac
`

const FAKE_DOCKER = `#!${BASH}
state="\${FAKE_STATE:?}"
{ printf 'docker\\t%s' "\${DOCKER_HOST:-}"; printf '\\t%s' "$@"; printf '\\n'; } >> "\${state}/calls"
printf 'docker\\0%s\\0%s\\0' "\${DOCKER_CONFIG-<unset>}" "\${COLIMA_CACHE_HOME-<unset>}" >> "\${state}/env"
last=""
for a in "$@"; do last="\${a}"; done
f="\${state}/network-\${last}"
case "\${1:-} \${2:-}" in
  "network inspect")
    [ -f "\${f}" ] || { echo "Error: No such network: \${last}" >&2; exit 1; }
    if [ "\${3:-}" = --format ]; then
      if [ -f "\${state}/format-fails-\${last}" ]; then echo "Error response from daemon: fake inspect failure" >&2; exit 1; fi
      cat "\${f}"
    fi
    ;;
  "network create")
    [ "\${3:-}" = --internal ] || { echo "fake docker: a network that is not internal" >&2; exit 64; }
    if [ -f "\${state}/create-fails-\${last}" ]; then echo "Error response from daemon: fake failure" >&2; exit 1; fi
    printf 'true\\n' > "\${f}"
    echo "0123abcd"
    ;;
  *)
    echo "fake docker: unexpected command" >&2; exit 64
    ;;
esac
`

const FAKE_LIMACTL = `#!${BASH}
{ printf 'limactl'; printf '\\t%s' "$@"; printf '\\n'; } >> "\${FAKE_STATE:?}/calls"
echo "fake limactl: unexpected command" >&2
exit 64
`

interface Fixture {
  /** The temporary repository, as `pwd -P` gives it. */
  readonly repo: string
  readonly home: string
  readonly state: string
  readonly bin: string
  /** Each domain's mountRoot as the script computes it. */
  readonly root: Readonly<Record<Domain, string>>
}

function fixture(t: TestContext, repoName = 'repo'): Fixture {
  const base = tmpdir(t)
  mkdirSync(join(base, repoName, 'scripts'), { recursive: true })
  const repo = realpathSync(join(base, repoName))
  copyFileSync(join(REPO_ROOT, SCRIPT), join(repo, SCRIPT))
  const home = join(base, 'home')
  const state = join(base, 'state')
  const bin = join(base, 'bin')
  for (const dir of [home, state, bin]) mkdirSync(dir)
  writeFileSync(join(state, 'calls'), '')
  writeFileSync(join(state, 'env'), '')
  for (const [name, body] of [['colima', FAKE_COLIMA], ['docker', FAKE_DOCKER], ['limactl', FAKE_LIMACTL]] as const) {
    writeFileSync(join(bin, name), body)
    chmodSync(join(bin, name), 0o755)
  }
  for (const name of ['dirname', 'mkdir', 'awk', 'cat']) symlinkSync(systemTool(name), join(bin, name))
  return { repo, home, state, bin, root: { trusted: `${repo}/.aos/workspaces/trusted`, hostile: `${repo}/.aos/workspaces/hostile` } }
}

/** /proc/mounts' spelling of a path: a space, tab, newline or backslash as an octal escape. */
function mangle(path: string): string {
  return path.replace(/[ \t\n\\]/g, (c) => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`)
}

/** A VM's mount table: the system's own mounts, then the shares given, each `[fstype, path]`. */
function mountTable(shares: readonly (readonly [string, string])[], eol = '\n'): string {
  const system = [
    '/dev/vda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0',
    'proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0',
    'sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0',
    'tmpfs /run tmpfs rw,nosuid,nodev,size=402432k,mode=755 0 0',
    '/dev/vdb /mnt/lima-cidata iso9660 ro,relatime,nojoliet,check=s,map=n,blocksize=2048 0 0',
  ]
  const lines = [...system, ...shares.map(([type, path], i) => `mount${String(i)} ${mangle(path)} ${type} rw,relatime 0 0`)]
  return lines.map((l) => l + eol).join('')
}

interface Scene {
  /** Exit codes of successive `colima status <profile>` calls, the last repeated. */
  readonly status?: Partial<Record<Domain, readonly number[]>>
  /** Each profile's /proc/mounts; by default its mountRoot over virtiofs alone. */
  readonly mounts?: Partial<Record<Domain, string>>
  readonly sshFails?: readonly Domain[]
  /** Exit code of `colima start <profile>`; 0 for a profile not named. */
  readonly start?: Partial<Record<Domain, number>>
  /** Networks that exist already, with their Internal flag as `docker network inspect --format` prints it. */
  readonly networks?: Partial<Record<Domain, boolean | string>>
  /** Profiles whose `docker network inspect --format` fails. */
  readonly formatFails?: readonly Domain[]
  /** Profiles whose `docker network create` fails. */
  readonly createFails?: readonly Domain[]
  readonly env?: Readonly<Record<string, string>>
}

interface Ran {
  readonly status: number | null
  readonly stdout: string
  readonly stderr: string
  readonly calls: readonly (readonly string[])[]
  /** Each colima and docker call's DOCKER_CONFIG and COLIMA_CACHE_HOME (`<unset>` when not exported): `[tool, DOCKER_CONFIG, COLIMA_CACHE_HOME]`. */
  readonly footprint: readonly (readonly string[])[]
}

function run(fx: Fixture, scene: Scene = {}): Ran {
  for (const domain of DOMAINS) {
    writeFileSync(join(fx.state, `status-${domain}`), (scene.status?.[domain] ?? [1, 0]).join(' ') + '\n')
    writeFileSync(join(fx.state, `mounts-${domain}`), scene.mounts?.[domain] ?? mountTable([['virtiofs', fx.root[domain]]]))
    if (scene.sshFails?.includes(domain) === true) writeFileSync(join(fx.state, `ssh-fails-${domain}`), '')
    const start = scene.start?.[domain]
    if (start !== undefined) writeFileSync(join(fx.state, `start-${domain}`), `${String(start)}\n`)
    const internal = scene.networks?.[domain]
    if (internal !== undefined) writeFileSync(join(fx.state, `network-aos-${domain}`), `${String(internal)}\n`)
    if (scene.createFails?.includes(domain) === true) writeFileSync(join(fx.state, `create-fails-aos-${domain}`), '')
    if (scene.formatFails?.includes(domain) === true) writeFileSync(join(fx.state, `format-fails-aos-${domain}`), '')
  }
  // Only these: no AOS_COLIMA_* from the shell that runs the suite, and a
  // PATH where every name the script runs is a fake or a linked system tool.
  const env = { PATH: fx.bin, HOME: fx.home, FAKE_STATE: fx.state, ...scene.env }
  // Stdin a pipe, as when the operator pipes to the script or runs it from a
  // terminal: the fake colima refuses status and ssh unless the script gives
  // them /dev/null.
  const r = spawnSync(BASH, [join(fx.repo, SCRIPT)], { env, encoding: 'utf8', timeout: 30_000, input: '', stdio: ['pipe', 'pipe', 'pipe'] })
  assert.equal(r.error, undefined, String(r.error))
  const calls = readFileSync(join(fx.state, 'calls'), 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => l.split('\t'))
  // NUL-separated, three fields a call: a mountRoot may hold a tab or a
  // newline, and a path no NUL.
  const fields = readFileSync(join(fx.state, 'env'), 'utf8').split('\0').slice(0, -1)
  const footprint = Array.from({ length: Math.ceil(fields.length / 3) }, (_, i) => fields.slice(i * 3, i * 3 + 3))
  // Every colima and docker call, in every run, ran with the two the script
  // exports: what docker and Colima write goes to the program folder and
  // ~/.colima, never ~/.docker or ~/Library/Caches/colima.
  assert.deepEqual(
    footprint,
    // A line that only continues an argument holding a newline is no call.
    calls.filter((c) => c[0] === 'colima' || c[0] === 'docker').map((c) => [c[0], `${fx.repo}/.aos/docker`, `${fx.home}/.colima/_cache`]),
    'a colima or docker call ran with DOCKER_CONFIG or COLIMA_CACHE_HOME other than <repo>/.aos/docker and ~/.colima/_cache',
  )
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls, footprint }
}

/** A scene value for one domain alone. */
function only<T>(domain: Domain, value: T): Partial<Record<Domain, T>> {
  return domain === 'trusted' ? { trusted: value } : { hostile: value }
}

const sock = (fx: Fixture, domain: Domain): string => `unix://${fx.home}/.colima/${domain}/docker.sock`

/** The calls one domain's healthy pass makes once its start has been asked for: status, shares, network. */
function healthyAfterStart(fx: Fixture, domain: Domain, network: 'create' | 'exists'): string[][] {
  return [
    ['colima', 'status', domain],
    ['colima', 'ssh', '--profile', domain, '--', 'cat', '/proc/mounts'],
    ['docker', sock(fx, domain), 'network', 'inspect', `aos-${domain}`],
    ...(network === 'create'
      ? [['docker', sock(fx, domain), 'network', 'create', '--internal', `aos-${domain}`]]
      : [['docker', sock(fx, domain), 'network', 'inspect', '--format', '{{.Internal}}', `aos-${domain}`]]),
  ]
}

/**
 * The trusted VM's whole healthy pass from a stopped VM, network made: what
 * runs before the hostile VM is asked about at all, which a failure there
 * must follow, not replace.
 */
function trustedPass(fx: Fixture): string[][] {
  return [['colima', 'status', 'trusted'], startCall(fx, 'trusted', recordedSizes()), ...healthyAfterStart(fx, 'trusted', 'create')]
}

function startCall(fx: Fixture, domain: Domain, sizes: { cpu: string; memory: string; disk: string }): string[] {
  return [
    'colima', 'start', domain,
    '--vm-type', 'vz', '--mount-type', 'virtiofs',
    '--cpu', sizes.cpu, '--memory', sizes.memory, '--disk', sizes.disk,
    '--mount', `${fx.root[domain]}:w`,
  ]
}

/** The VM sizes README "Sandbox checks on the Mac" and CLAUDE.md record: CPUs, GiB of memory, GiB of disk. */
function recordedSizes(): { cpu: string; memory: string; disk: string } {
  const flat = (text: string): string => text.replace(/\s+/g, ' ')
  const readme = /and (\d+) CPUs, (\d+) GiB and (\d+) GiB each, all from one uninterrupted `scripts\/colima-up\.sh` run/.exec(
    flat(readFileSync(join(REPO_ROOT, 'README.md'), 'utf8')),
  )
  assert.ok(readme, 'README no longer records the VM sizes as "<n> CPUs, <n> GiB and <n> GiB each, all from one uninterrupted `scripts/colima-up.sh` run"')
  const claude = /(\d+) CPU \/ (\d+) GiB \/ (\d+) GiB each/.exec(flat(readFileSync(join(REPO_ROOT, 'CLAUDE.md'), 'utf8')))
  assert.ok(claude, 'CLAUDE.md no longer records the VM sizes as "<n> CPU / <n> GiB / <n> GiB each"')
  assert.deepEqual(claude.slice(1), readme.slice(1), 'README and CLAUDE.md record different VM sizes')
  return { cpu: readme[1] ?? '', memory: readme[2] ?? '', disk: readme[3] ?? '' }
}

/** The script's default for one size variable, as `NAME="${AOS_COLIMA_X:-<n>}"` sets it. */
function scriptDefault(body: string, name: string, variable: string): string {
  const all = [...body.matchAll(new RegExp(`^${name}="\\$\\{${variable}:-(\\d+)\\}"$`, 'gm'))]
  assert.equal(all.length, 1, `${SCRIPT} sets ${name} from ${variable} ${String(all.length)} times, not once`)
  return all[0]?.[1] ?? ''
}

test('the script exits non-zero when colima status fails after start, and its MEMORY default equals the recorded VM size', (t) => {
  const recorded = recordedSizes()
  assert.equal(recorded.memory, '4', 'the recorded VMs have 4 GiB each (README, CLAUDE.md)')
  const body = readFileSync(join(REPO_ROOT, SCRIPT), 'utf8')
  assert.equal(scriptDefault(body, 'MEMORY', 'AOS_COLIMA_MEMORY'), recorded.memory, "the script's MEMORY default is not the recorded VMs' memory")
  assert.equal(scriptDefault(body, 'CPUS', 'AOS_COLIMA_CPUS'), recorded.cpu)
  assert.equal(scriptDefault(body, 'DISK', 'AOS_COLIMA_DISK'), recorded.disk)

  // The defect README recorded on 2026-10-21: a VM running but whose first
  // start never finished. `colima status` fails, `colima start` answers
  // "already running, ignoring" with 0, and status still fails. The script
  // stops there: no share read, no network touched, no other VM, no Done.
  // The same if the VM was running at the first ask and is not at the second.
  for (const codes of [[1, 1], [0, 1], [1, 3]] as const) {
    const fx = fixture(t)
    const r = run(fx, { status: { trusted: codes } })
    const why = `status ${codes.join(' then ')}`
    assert.notEqual(r.status, 0, `${why}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, why)
    assert.match(r.stderr, /error: colima profile trusted is not running after the start: colima status trusted failed:\ncolima \[profile=trusted\] is not running\n/, why)
    assert.match(r.stderr, /fix: colima stop trusted, then re-run this script; if colima status trusted still fails, colima delete trusted and re-run/, why)
    const start = codes[0] === 0 ? [] : [startCall(fx, 'trusted', recorded)]
    assert.deepEqual(r.calls, [['colima', 'status', 'trusted'], ...start, ['colima', 'status', 'trusted']], why)
  }

  // The hostile VM's verdict is acted on as the trusted one's is: with the
  // trusted VM healthy, a hostile VM whose status fails after the start
  // stops the script there, after the trusted VM's whole pass and before
  // the hostile VM's share is read or its network touched. Not best effort:
  // the hostile VM is the one whose share matters most.
  for (const codes of [[1, 1], [0, 1]] as const) {
    const fx = fixture(t)
    const r = run(fx, { status: { hostile: codes } })
    const why = `hostile status ${codes.join(' then ')}`
    assert.notEqual(r.status, 0, `${why}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, why)
    assert.ok(r.stdout.includes(`colima profile trusted has one host share, mounted at ${fx.root.trusted} (virtiofs)\n`), `${why}: ${r.stdout}`)
    assert.match(r.stderr, /error: colima profile hostile is not running after the start: colima status hostile failed:\ncolima \[profile=hostile\] is not running\n/, why)
    assert.match(r.stderr, /fix: colima stop hostile, then re-run this script; if colima status hostile still fails, colima delete hostile and re-run/, why)
    assert.doesNotMatch(r.stderr, /profile trusted/, why)
    const start = codes[0] === 0 ? [] : [startCall(fx, 'hostile', recorded)]
    assert.deepEqual(r.calls, [...trustedPass(fx), ['colima', 'status', 'hostile'], ...start, ['colima', 'status', 'hostile']], why)
  }

  // And a first start, with no AOS_COLIMA_* set, makes each VM at the
  // recorded sizes: --memory is the recorded GiB.
  const fx = fixture(t)
  const r = run(fx)
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /\nDone\. Sockets the kernel expects/)
  assert.deepEqual(r.calls, [
    ['colima', 'status', 'trusted'],
    startCall(fx, 'trusted', recorded),
    ...healthyAfterStart(fx, 'trusted', 'create'),
    ['colima', 'status', 'hostile'],
    startCall(fx, 'hostile', recorded),
    ...healthyAfterStart(fx, 'hostile', 'create'),
  ])
  for (const call of r.calls.filter((c) => c[1] === 'start')) assert.equal(call[call.indexOf('--memory') + 1], '4')

  // The variable still sets it.
  const sized = fixture(t)
  const s = run(sized, { env: { AOS_COLIMA_MEMORY: '6' } })
  assert.equal(s.status, 0, s.stderr)
  assert.deepEqual(s.calls.filter((c) => c[1] === 'start'), [startCall(sized, 'trusted', { ...recorded, memory: '6' }), startCall(sized, 'hostile', { ...recorded, memory: '6' })])
})

test("the script fails unless the VM has one host share, mounted over virtiofs at its mountRoot, before its network is touched, naming where each share is mounted", (t) => {
  const passes: readonly { readonly why: string; readonly table: (fx: Fixture) => string }[] = [
    { why: 'its mountRoot over virtiofs, beside the system mounts', table: (fx) => mountTable([['virtiofs', fx.root.trusted]]) },
    { why: 'the same, read with CRLF line ends', table: (fx) => mountTable([['virtiofs', fx.root.trusted]], '\r\n') },
    { why: 'with a bind mount of no share type beside it', table: (fx) => mountTable([['virtiofs', fx.root.trusted], ['ext4', '/var/lib/docker']]) },
  ]
  for (const { why, table } of passes) {
    const fx = fixture(t)
    // Already running, so this shows the check on a VM the script did not start.
    const r = run(fx, { status: { trusted: [0], hostile: [0] }, mounts: { trusted: table(fx) }, networks: { trusted: true, hostile: true } })
    assert.equal(r.status, 0, `${why}: ${r.stderr}`)
    assert.ok(r.stdout.includes(`colima profile trusted has one host share, mounted at ${fx.root.trusted} (virtiofs)\n`), `${why}: ${r.stdout}`)
    assert.deepEqual(r.calls, [
      ['colima', 'status', 'trusted'],
      ...healthyAfterStart(fx, 'trusted', 'exists'),
      ['colima', 'status', 'hostile'],
      ...healthyAfterStart(fx, 'hostile', 'exists'),
    ], why)
  }

  const fails: readonly { readonly why: string; readonly table: (fx: Fixture) => string; readonly names: (fx: Fixture) => string }[] = [
    { why: 'no share at all', table: () => mountTable([]), names: () => '  nothing' },
    { why: 'nothing read', table: () => '', names: () => '  nothing' },
    { why: '$HOME beside its mountRoot', table: (fx) => mountTable([['virtiofs', fx.root.trusted], ['virtiofs', fx.home]]), names: (fx) => `  virtiofs ${fx.home}` },
    { why: 'the old ~/.aos mount in its place', table: (fx) => mountTable([['virtiofs', `${fx.home}/.aos/workspaces/trusted`]]), names: (fx) => `  virtiofs ${fx.home}/.aos/workspaces/trusted` },
    { why: 'its mountRoot twice', table: (fx) => mountTable([['virtiofs', fx.root.trusted], ['virtiofs', fx.root.trusted]]), names: (fx) => `  virtiofs ${fx.root.trusted}\n  virtiofs ${fx.root.trusted}` },
    { why: "the hostile domain's mountRoot", table: (fx) => mountTable([['virtiofs', fx.root.hostile]]), names: (fx) => `  virtiofs ${fx.root.hostile}` },
    { why: 'the directory above its mountRoot', table: (fx) => mountTable([['virtiofs', `${fx.repo}/.aos/workspaces`]]), names: (fx) => `  virtiofs ${fx.repo}/.aos/workspaces` },
    { why: 'a directory under its mountRoot', table: (fx) => mountTable([['virtiofs', `${fx.root.trusted}/run`]]), names: (fx) => `  virtiofs ${fx.root.trusted}/run` },
    { why: 'its mountRoot with a trailing slash', table: (fx) => mountTable([['virtiofs', `${fx.root.trusted}/`]]), names: (fx) => `  virtiofs ${fx.root.trusted}/` },
    { why: 'a path that only starts with its mountRoot', table: (fx) => mountTable([['virtiofs', `${fx.root.trusted}-old`]]), names: (fx) => `  virtiofs ${fx.root.trusted}-old` },
    { why: 'its mountRoot over 9p', table: (fx) => mountTable([['9p', fx.root.trusted]]), names: (fx) => `  9p ${fx.root.trusted}` },
    { why: 'its mountRoot over sshfs', table: (fx) => mountTable([['fuse.sshfs', fx.root.trusted]]), names: (fx) => `  fuse.sshfs ${fx.root.trusted}` },
    { why: '$HOME over sshfs beside its mountRoot', table: (fx) => mountTable([['virtiofs', fx.root.trusted], ['fuse.sshfs', fx.home]]), names: (fx) => `  fuse.sshfs ${fx.home}` },
  ]
  for (const { why, table, names } of fails) {
    const fx = fixture(t)
    const r = run(fx, { mounts: { trusted: table(fx) } })
    assert.notEqual(r.status, 0, `${why}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, why)
    assert.ok(
      r.stderr.includes(`error: colima profile trusted must have one host share, mounted over virtiofs at its mountRoot, ${fx.root.trusted}; its host shares are mounted at:\n`),
      `${why}: ${r.stderr}`,
    )
    assert.ok(r.stderr.includes(names(fx)), `${why}: the refusal does not name ${JSON.stringify(names(fx))}\n${r.stderr}`)
    assert.match(r.stderr, /fix: colima stop trusted, then re-run this script so its --mount applies; if the shares stay wrong, colima delete trusted and re-run/, why)
    // Nothing after the shares: no network, no other VM.
    assert.deepEqual(r.calls, [['colima', 'status', 'trusted'], startCall(fx, 'trusted', recordedSizes()), ...healthyAfterStart(fx, 'trusted', 'create').slice(0, 2)], why)
  }

  // The hostile VM's shares are held to the same check, after the trusted
  // VM's whole pass: a hostile VM that shares $HOME, or the trusted domain's
  // mountRoot, stops the script before its own network is touched. A process
  // that escapes there writes its share as the operator.
  const hostileFails: readonly { readonly why: string; readonly table: (fx: Fixture) => string; readonly names: (fx: Fixture) => string }[] = [
    { why: '$HOME beside its mountRoot', table: (fx) => mountTable([['virtiofs', fx.root.hostile], ['virtiofs', fx.home]]), names: (fx) => `  virtiofs ${fx.root.hostile}\n  virtiofs ${fx.home}\n` },
    { why: "the trusted domain's mountRoot in its place", table: (fx) => mountTable([['virtiofs', fx.root.trusted]]), names: (fx) => `  virtiofs ${fx.root.trusted}\n` },
  ]
  for (const { why, table, names } of hostileFails) {
    const fx = fixture(t)
    const r = run(fx, { mounts: { hostile: table(fx) } })
    const at = `hostile, ${why}`
    assert.notEqual(r.status, 0, `${at}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, at)
    assert.ok(r.stdout.includes(`colima profile trusted has one host share, mounted at ${fx.root.trusted} (virtiofs)\n`), `${at}: ${r.stdout}`)
    assert.ok(
      r.stderr.includes(`error: colima profile hostile must have one host share, mounted over virtiofs at its mountRoot, ${fx.root.hostile}; its host shares are mounted at:\n${names(fx)}`),
      `${at}: ${r.stderr}`,
    )
    assert.match(r.stderr, /fix: colima stop hostile, then re-run this script so its --mount applies; if the shares stay wrong, colima delete hostile and re-run/, at)
    assert.doesNotMatch(r.stdout, /colima profile hostile has one host share/, at)
    assert.deepEqual(
      r.calls,
      [...trustedPass(fx), ['colima', 'status', 'hostile'], startCall(fx, 'hostile', recordedSizes()), ...healthyAfterStart(fx, 'hostile', 'create').slice(0, 2)],
      at,
    )
  }

  // A VM whose mount table cannot be read is refused as well, the hostile
  // one after the trusted VM's whole pass.
  for (const domain of DOMAINS) {
    const fx = fixture(t)
    const r = run(fx, { sshFails: [domain] })
    assert.notEqual(r.status, 0, `${domain}: ${r.stdout}`)
    assert.ok(r.stderr.includes(`error: could not read /proc/mounts in colima profile ${domain}: colima ssh --profile ${domain} failed\n`), `${domain}: ${r.stderr}`)
    assert.doesNotMatch(r.stdout, /Done\./, domain)
    // It stops at the failure: an unread table is not read on as an empty one.
    assert.doesNotMatch(r.stderr, /must have one host share/, domain)
    const own = [['colima', 'status', domain], startCall(fx, domain, recordedSizes()), ...healthyAfterStart(fx, domain, 'create').slice(0, 2)]
    assert.deepEqual(r.calls, domain === 'trusted' ? own : [...trustedPass(fx), ...own], domain)
  }

  // What the check reads is where each share is mounted ($2 of /proc/mounts),
  // never which directory of the Mac it is: a virtiofs entry's source is
  // Lima's tag (mount0). Neither the script nor README's row claims more.
  const body = readFileSync(join(REPO_ROOT, SCRIPT), 'utf8')
  assert.equal(/shares (?:exactly|only)\b/.test(body), false, 'the script claims to know which directory of the Mac a VM shares')
  assert.ok(body.includes('/proc/mounts names a\n# virtiofs share by Lima\'s tag (mount0), not by its Mac path.'), "the script's header no longer says the share's Mac path is not read")
  const readme = readFileSync(join(REPO_ROOT, 'README.md'), 'utf8')
  assert.ok(
    readme.includes("Not read at all: which directory of the Mac the share mounted there is. /proc/mounts names a virtiofs share by Lima's tag (`mount0`), not by its Mac path"),
    "README's NEEDS VALIDATION row no longer says the share's Mac path is not read",
  )
  // The share check's awk has run here only under the awk this test links
  // from /bin or /usr/bin, which on Linux is mawk; on the Mac /usr/bin/awk is
  // BWK's awk. README's row says so, and what of the program a dialect could
  // read otherwise.
  const row = readme.split('\n').find((l) => l.startsWith('| `scripts/colima-up.sh`, still marked NEEDS VALIDATION'))
  assert.ok(row, "README's NEEDS VALIDATION row for scripts/colima-up.sh is gone")
  for (const claim of [
    "Nor has the share check's awk program run under macOS's `/usr/bin/awk` (BWK's awk): here it has run only under Linux's awk (mawk, which the test links in as `awk`)",
    'It uses `ENVIRON`, string compares against `"\\\\040"`, `"\\\\011"`, `"\\\\012"` and `"\\\\134"`, and `exit (expr)`',
    'the operator runs `npm test` on the Mac first, which runs the share check under `/usr/bin/awk` against the fakes',
  ]) {
    assert.ok(row.includes(claim), `README's colima-up.sh row no longer says: ${claim}`)
  }
  for (const used of ['ENVIRON["MOUNT_ROOT"]', '"\\\\040"', '"\\\\011"', '"\\\\012"', '"\\\\134"', 'exit (']) {
    assert.ok(body.includes(used), `the share check no longer uses ${used}, which README's row names as what a dialect could read otherwise`)
  }
})

test('a mountRoot whose path holds a space, a tab, a newline or a backslash is matched as /proc/mounts escapes it, and only so', (t) => {
  // Each of the four characters /proc/mounts escapes, each in a repository
  // of its own and then all four in one.
  const names = ['my aos', 'my\taos', 'my\naos', 'my\\aos', 'my aos\t\n\\checkout']
  for (const name of names) {
    const fx = fixture(t, name)
    const ok = run(fx)
    assert.equal(ok.status, 0, `${JSON.stringify(name)}: ${ok.stderr}`)
    // The share is read as the path it is: the mount table spells it with
    // octal escapes (\040, \011, \012, \134), and the script reads them back.
    assert.ok(readFileSync(join(fx.state, 'mounts-trusted'), 'utf8').includes(`/${mangle(name)}/.aos/workspaces/trusted virtiofs `), JSON.stringify(name))
    assert.notEqual(mangle(name), name, `${JSON.stringify(name)} holds nothing /proc/mounts escapes`)
  }

  // Escaped otherwise (as another tool might print it), it is another path.
  const other = fixture(t, 'my aos\\checkout')
  const bad = mountTable([['virtiofs', other.root.trusted]]).replace('my\\040aos\\134checkout', 'my\\x20aos\\134checkout')
  const r = run(other, { mounts: { trusted: bad } })
  assert.notEqual(r.status, 0, r.stdout)
  assert.ok(r.stderr.includes(`its host shares are mounted at:\n  virtiofs ${other.repo.replace('my aos\\checkout', 'my\\x20aos\\checkout')}/.aos/workspaces/trusted\n`), r.stderr)
})

test('a colima start that fails stops the script there, passing on what colima said, before status is asked again, any share read or network touched, or Done. printed', (t) => {
  // The trusted VM's start, and then the hostile VM's after the trusted VM's
  // whole pass. Status would succeed if asked again: only the start's own
  // failure stops the script (set -e), not the re-ask.
  for (const domain of DOMAINS) {
    const fx = fixture(t)
    const r = run(fx, { start: domain === 'trusted' ? { trusted: 1 } : { hostile: 1 } })
    assert.notEqual(r.status, 0, `${domain}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, domain)
    assert.ok(r.stdout.includes(`starting colima profile ${domain} (mount: ${fx.root[domain]})\n`), `${domain}: ${r.stdout}`)
    assert.ok(r.stderr.includes(`colima [profile=${domain}] error starting vm: fake failure\n`), `${domain}: ${r.stderr}`)
    assert.doesNotMatch(r.stderr, /not running after the start/, domain)
    assert.doesNotMatch(r.stdout, new RegExp(`colima profile ${domain} has one host share`), domain)
    const own = [['colima', 'status', domain], startCall(fx, domain, recordedSizes())]
    assert.deepEqual(r.calls, domain === 'trusted' ? own : [...trustedPass(fx), ...own], domain)
  }
})

test('an aos-<domain> network that exists and is not internal, or that cannot be made, stops the script before Done., the first naming docker network rm as its fix, with no network made in its place', (t) => {
  // Inside the VM the Mac's loopback is 192.168.5.2, where pmmcp listens
  // unauthenticated: a network with a route out reaches it. The script
  // neither accepts nor deletes such a network, and makes none beside it.
  // The trusted VM's, and then the hostile VM's after the trusted VM's whole
  // pass, its network made.
  for (const domain of DOMAINS) {
    const fx = fixture(t)
    const r = run(fx, { networks: domain === 'trusted' ? { trusted: false } : { hostile: false } })
    assert.notEqual(r.status, 0, `${domain}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, domain)
    assert.doesNotMatch(r.stdout, new RegExp(`network aos-${domain} already exists and is internal`), domain)
    assert.ok(r.stderr.includes(`network aos-${domain} exists but is NOT internal (Internal=false).\n`), `${domain}: ${r.stderr}`)
    assert.ok(
      r.stderr.includes(`fix: DOCKER_HOST=unix://${fx.home}/.colima/${domain}/docker.sock docker network rm aos-${domain}  # then re-run this script\n`),
      `${domain}: ${r.stderr}`,
    )
    assert.equal(r.calls.some((c) => c[0] === 'docker' && c[1] === sock(fx, domain) && c[3] === 'create'), false, `${domain}: a network was made`)
    assert.equal(readFileSync(join(fx.state, `network-aos-${domain}`), 'utf8'), 'false\n', `${domain}: the network was changed`)
    const own = [['colima', 'status', domain], startCall(fx, domain, recordedSizes()), ...healthyAfterStart(fx, domain, 'exists')]
    assert.deepEqual(r.calls, domain === 'trusted' ? own : [...trustedPass(fx), ...own], domain)
  }

  // An internal network that docker refuses to make stops the script as well.
  for (const domain of DOMAINS) {
    const fx = fixture(t)
    const r = run(fx, { createFails: [domain] })
    assert.notEqual(r.status, 0, `${domain}, create refused: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, `${domain}, create refused`)
    assert.ok(r.stderr.includes('Error response from daemon: fake failure\n'), `${domain}, create refused: ${r.stderr}`)
    const own = [['colima', 'status', domain], startCall(fx, domain, recordedSizes()), ...healthyAfterStart(fx, domain, 'create')]
    assert.deepEqual(r.calls, domain === 'trusted' ? own : [...trustedPass(fx), ...own], `${domain}, create refused`)
  }
})

test('a VM that is already running is held to the checks a VM the script starts is: one with other shares, or whose network is not internal, is refused, and is not started', (t) => {
  // The script's header: a VM created earlier with other mounts (the old
  // ~/.aos ones) keeps them while it runs, and this script refuses it. No
  // start is asked for, so nothing the script passes to colima could have
  // put the shares right; the refusal is what stands between that VM and
  // Done. The trusted VM, and then the hostile VM after the trusted VM's
  // whole pass from a stopped VM.
  const shares: readonly { readonly why: string; readonly table: (fx: Fixture, domain: Domain) => string; readonly names: (fx: Fixture, domain: Domain) => string }[] = [
    { why: 'the old ~/.aos mount in its place', table: (fx, d) => mountTable([['virtiofs', `${fx.home}/.aos/workspaces/${d}`]]), names: (fx, d) => `  virtiofs ${fx.home}/.aos/workspaces/${d}\n` },
    { why: '$HOME beside its mountRoot', table: (fx, d) => mountTable([['virtiofs', fx.root[d]], ['virtiofs', fx.home]]), names: (fx, d) => `  virtiofs ${fx.root[d]}\n  virtiofs ${fx.home}\n` },
  ]
  const before = (fx: Fixture, domain: Domain): string[][] => (domain === 'trusted' ? [] : trustedPass(fx))
  const notStarted = (r: Ran, domain: Domain, at: string): void => {
    assert.notEqual(r.status, 0, `${at}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, at)
    assert.ok(r.stdout.includes(`colima profile ${domain} is already running\n`), `${at}: ${r.stdout}`)
    assert.equal(r.stdout.includes(`starting colima profile ${domain}`), false, at)
    assert.equal(r.calls.some((c) => c[0] === 'colima' && c[1] === 'start' && c[2] === domain), false, `${at}: the running VM was started`)
  }
  for (const domain of DOMAINS) {
    for (const { why, table, names } of shares) {
      const fx = fixture(t)
      const r = run(fx, { status: only(domain, [0]), mounts: only(domain, table(fx, domain)) })
      const at = `${domain} already running, ${why}`
      notStarted(r, domain, at)
      assert.ok(
        r.stderr.includes(`error: colima profile ${domain} must have one host share, mounted over virtiofs at its mountRoot, ${fx.root[domain]}; its host shares are mounted at:\n${names(fx, domain)}`),
        `${at}: ${r.stderr}`,
      )
      assert.ok(r.stderr.includes(`fix: colima stop ${domain}, then re-run this script so its --mount applies; if the shares stay wrong, colima delete ${domain} and re-run\n`), `${at}: ${r.stderr}`)
      assert.doesNotMatch(r.stdout, new RegExp(`colima profile ${domain} has one host share`), at)
      // Status, status again, the shares, and nothing after them.
      assert.deepEqual(r.calls, [...before(fx, domain), ['colima', 'status', domain], ...healthyAfterStart(fx, domain, 'create').slice(0, 2)], at)
    }

    const fx = fixture(t)
    const r = run(fx, { status: only(domain, [0]), networks: only(domain, false) })
    const at = `${domain} already running, its network not internal`
    notStarted(r, domain, at)
    assert.ok(r.stdout.includes(`colima profile ${domain} has one host share, mounted at ${fx.root[domain]} (virtiofs)\n`), `${at}: ${r.stdout}`)
    assert.ok(r.stderr.includes(`network aos-${domain} exists but is NOT internal (Internal=false).\n`), `${at}: ${r.stderr}`)
    assert.ok(r.stderr.includes(`fix: DOCKER_HOST=unix://${fx.home}/.colima/${domain}/docker.sock docker network rm aos-${domain}  # then re-run this script\n`), `${at}: ${r.stderr}`)
    assert.equal(readFileSync(join(fx.state, `network-aos-${domain}`), 'utf8'), 'false\n', `${at}: the network was changed`)
    assert.deepEqual(r.calls, [...before(fx, domain), ['colima', 'status', domain], ...healthyAfterStart(fx, domain, 'exists')], at)
  }
})

test('an existing aos-<domain> network is accepted only when docker reads its Internal flag as true: a flag read as anything else, or not read at all, stops the script before Done., with no network made', (t) => {
  // Fail closed: what is not `true` is not internal, an empty or unknown
  // answer included, and an inspect that fails is no answer at all. The
  // trusted VM's network, and then the hostile VM's after the trusted VM's
  // whole pass.
  for (const domain of DOMAINS) {
    const own = (fx: Fixture): string[][] => [['colima', 'status', domain], startCall(fx, domain, recordedSizes()), ...healthyAfterStart(fx, domain, 'exists')]
    for (const flag of ['', '<no value>', 'false ']) {
      const fx = fixture(t)
      const r = run(fx, { networks: only(domain, flag) })
      const at = `${domain}, Internal ${JSON.stringify(flag)}`
      assert.notEqual(r.status, 0, `${at}: the script passed\n${r.stdout}`)
      assert.doesNotMatch(r.stdout, /Done\./, at)
      assert.doesNotMatch(r.stdout, new RegExp(`network aos-${domain} already exists and is internal`), at)
      assert.ok(r.stderr.includes(`network aos-${domain} exists but is NOT internal (Internal=${flag}).\n`), `${at}: ${r.stderr}`)
      assert.ok(r.stderr.includes(`docker network rm aos-${domain}  # then re-run this script\n`), `${at}: ${r.stderr}`)
      assert.equal(r.calls.some((c) => c[0] === 'docker' && c[3] === 'create' && c.at(-1) === `aos-${domain}`), false, `${at}: a network was made`)
      assert.deepEqual(r.calls, domain === 'trusted' ? own(fx) : [...trustedPass(fx), ...own(fx)], at)
    }

    const fx = fixture(t)
    const r = run(fx, { networks: only(domain, true), formatFails: [domain] })
    const at = `${domain}, the flag's inspect failing`
    assert.notEqual(r.status, 0, `${at}: the script passed\n${r.stdout}`)
    assert.doesNotMatch(r.stdout, /Done\./, at)
    assert.doesNotMatch(r.stdout, new RegExp(`network aos-${domain} already exists and is internal`), at)
    assert.ok(r.stderr.includes('Error response from daemon: fake inspect failure\n'), `${at}: ${r.stderr}`)
    assert.equal(r.calls.some((c) => c[0] === 'docker' && c[3] === 'create' && c.at(-1) === `aos-${domain}`), false, `${at}: a network was made`)
    assert.deepEqual(r.calls, domain === 'trusted' ? own(fx) : [...trustedPass(fx), ...own(fx)], at)
  }
})

test('the script keeps what it writes in the program folder and ~/.colima: docker and colima run with DOCKER_CONFIG <repo>/.aos/docker and COLIMA_CACHE_HOME ~/.colima/_cache, whatever the shell had, and each mountRoot is made', (t) => {
  // CLAUDE.md's install footprint: everything under <repo>/.aos but
  // ~/.colima. Unset, DOCKER_CONFIG is ~/.docker and COLIMA_CACHE_HOME
  // ~/Library/Caches/colima (the script's header); a shell that exports
  // either elsewhere is overridden, not followed.
  const shells: readonly { readonly why: string; readonly env: (fx: Fixture) => Readonly<Record<string, string>> }[] = [
    { why: 'neither set', env: () => ({}) },
    { why: 'both set elsewhere in the shell', env: (fx) => ({ DOCKER_CONFIG: `${fx.home}/.docker`, COLIMA_CACHE_HOME: `${fx.home}/Library/Caches/colima` }) },
  ]
  for (const { why, env } of shells) {
    const fx = fixture(t)
    const r = run(fx, { env: env(fx) })
    assert.equal(r.status, 0, `${why}: ${r.stderr}`)
    // run() holds every call to the two; here, that there were calls of both
    // tools to hold.
    assert.ok(r.footprint.some((f) => f[0] === 'colima') && r.footprint.some((f) => f[0] === 'docker'), `${why}: ${JSON.stringify(r.footprint)}`)
    assert.equal(r.footprint.length, r.calls.length, why)
    for (const dir of [fx.root.trusted, fx.root.hostile, `${fx.repo}/.aos/docker`, `${fx.home}/.colima/_cache`]) assert.ok(existsSync(dir), `${why}: ${dir} was not made`)
    // And nothing beside them: no ~/.docker, no ~/Library, nothing else in
    // the program folder.
    assert.deepEqual(readdirSync(fx.home), ['.colima'], why)
    assert.deepEqual(readdirSync(join(fx.home, '.colima')), ['_cache'], why)
    assert.deepEqual(readdirSync(join(fx.repo, '.aos')).sort(), ['docker', 'workspaces'], why)
    assert.deepEqual(readdirSync(join(fx.repo, '.aos', 'workspaces')).sort(), ['hostile', 'trusted'], why)
  }

  // On VMs already running, too: each mountRoot is made before the VM is
  // asked about.
  const fx = fixture(t)
  const r = run(fx, { status: { trusted: [0], hostile: [0] } })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.calls.some((c) => c[1] === 'start'), false)
  for (const domain of DOMAINS) assert.ok(existsSync(fx.root[domain]), `${domain}: its mountRoot was not made`)
})

test('colima status and colima ssh run with stdin /dev/null, so neither takes the terminal or what was piped to the script: the fake colima refuses either on any other stdin, and the script, run with stdin a pipe, passes', (t) => {
  // The fake's check is real here: with stdin a pipe, status and ssh are
  // refused with 64; with /dev/null they answer from their state.
  const fx = fixture(t)
  writeFileSync(join(fx.state, 'status-trusted'), '3\n')
  writeFileSync(join(fx.state, 'mounts-trusted'), 'mount0 /x virtiofs rw 0 0\n')
  const fake = (args: readonly string[], stdin: 'pipe' | 'ignore'): ReturnType<typeof spawnSync> =>
    spawnSync(join(fx.bin, 'colima'), args, { env: { PATH: fx.bin, FAKE_STATE: fx.state }, encoding: 'utf8', timeout: 10_000, stdio: [stdin, 'pipe', 'pipe'], ...(stdin === 'pipe' ? { input: '' } : {}) })
  for (const [args, answer] of [[['status', 'trusted'], 3], [['ssh', '--profile', 'trusted', '--', 'cat', '/proc/mounts'], 0]] as const) {
    const piped = fake(args, 'pipe')
    assert.equal(piped.status, 64, `${args[0]} on a pipe: ${String(piped.stderr)}`)
    assert.match(String(piped.stderr), new RegExp(`fake colima: ${args[0]} with stdin not /dev/null`))
    const nulled = fake(args, 'ignore')
    assert.equal(nulled.status, answer, `${args[0]} on /dev/null: ${String(nulled.stderr)}`)
  }

  // Run with stdin a pipe (as run() always does), the script passes, from
  // stopped VMs and from running ones: every status and ssh it ran had
  // /dev/null.
  for (const status of [{}, { trusted: [0], hostile: [0] }] as const) {
    const ran = run(fixture(t), { status })
    assert.equal(ran.status, 0, ran.stderr)
    assert.doesNotMatch(ran.stderr, /stdin not \/dev\/null/)
  }
  // And in the source, every colima status and ssh the script runs (not the
  // ones its messages quote) reads /dev/null.
  const code = readFileSync(join(REPO_ROOT, SCRIPT), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l) && !/^\s*echo /.test(l))
  const asks = code.filter((l) => /\bcolima (?:status|ssh)\b/.test(l))
  assert.equal(asks.length, 3, asks.join('\n'))
  for (const ask of asks) assert.ok(ask.includes('</dev/null'), `a colima status or ssh that reads the script's stdin: ${ask.trim()}`)
})

test("every colima command the script runs names a profile, never Colima's default, and it adds no iptables rule and no network but each domain's internal one", (t) => {
  const body = readFileSync(join(REPO_ROOT, SCRIPT), 'utf8')
  const code = body.split('\n').filter((l) => !/^\s*#/.test(l))
  // Every colima command in the code, run or quoted in a fix line, takes the
  // profile it is about.
  // A command runs to the first ;, ), > or , after it: an argument list, or
  // a fix line's clause.
  const commands = code.flatMap((l) => [...l.matchAll(/\bcolima (?:start|stop|status|ssh|delete|restart|ssh-config|kubernetes|prune)\b[^;)>,\n]*/g)].map((m) => m[0]))
  assert.ok(commands.length >= 8, `only ${String(commands.length)} colima commands were found: ${commands.join(' | ')}`)
  for (const command of commands) assert.match(command, /\$\{profile\}/, `a colima command that names no profile: ${command}`)
  assert.equal(/iptables/i.test(body), false, 'the script touches iptables')
  assert.deepEqual(code.filter((l) => /network create/.test(l)).map((l) => l.trim()), ['DOCKER_HOST="unix://${HOME}/.colima/${profile}/docker.sock" docker network create --internal "${network}"'])

  // Run, it asked about the two profiles it makes and no other, and the
  // fakes were all it ran: limactl not at all.
  const fx = fixture(t)
  const r = run(fx)
  assert.equal(r.status, 0, r.stderr)
  const profiles = new Set(r.calls.filter((c) => c[0] === 'colima').map((c) => (c[1] === 'ssh' ? c[3] : c[2])))
  assert.deepEqual([...profiles], ['trusted', 'hostile'])
  assert.equal(r.calls.some((c) => c[0] === 'limactl'), false)
  assert.deepEqual([...new Set(r.calls.filter((c) => c[0] === 'docker').map((c) => c[1]))], [sock(fx, 'trusted'), sock(fx, 'hostile')])
})
