// The installer's preflight (plan §5 S1): read-only and in-process, before
// the lock or any child.
//
// CONTRACT
//
//   Who calls it: the installer's entry point (scripts/install.ts), after its
//   flags were read and before anything is written or run. Nothing here
//   starts a program or writes a file. What it is handed (the current
//   directory, the effective uid, the platform, the developer folders) is
//   the process's own unless a test says otherwise.
//
//   npmTookFlags, first of all: the flags npm took as its own. `npm run
//   aos-install --dry-run` hands the script no argument and sets
//   npm_config_dry_run instead (npm 10 reads a flag before `--` as its
//   config), so the installer would make a real run of what was asked to be
//   a dry one, and `--aos-only` swallowed so would touch pmmcp. Any of
//   npm_config_dry_run, _aos_only, _pmmcp_dir, _help or _install (which
//   `--no-install` sets to '') is refused with usage, before anything is
//   looked at.
//
//   preflight, in order, collecting every refusal with its fix (the caller
//   prints them all and exits 2): not root; HOME an absolute path without a
//   colon; the current directory this checkout's root (by spelling once
//   links are resolved, and by device and inode), and so INIT_CWD when npm
//   set it (npm run moves the cwd to the root, but npm writes its cache and
//   logs under the folder the command was typed in, as .npmrc's relative
//   cache names it, and git ignores only the root's /.aos/); no falsify run
//   holds the tree (src/falsify-hold.ts); Node within package.json's engines;
//   node_modules there; .gitignore ignoring .env and /.aos/ (git's rules,
//   src/gitignore.ts), and .aos spelled so and not a link. Then, names only,
//   which of DOCKER_CONFIG, DOCKER_HOST, DOCKER_CONTEXT and PMMCP_* the
//   shell exports (pmmcp's commands run without them). Unless --aos-only,
//   the programs pmmcp and its scripts call, found on the PATH the runner
//   gives a child as `command -v` would, without a shell (PROGRAMS), and
//   docker-credential-desktop when ~/.docker/config.json names credsStore
//   "desktop" (read in-process for that one key; nothing of it is kept or
//   shown). On macOS a git or python3 found as /usr/bin's stub needs the
//   Command Line Tools (or Xcode) behind it: without them the stub opens an
//   install dialog and the probe that ran it fails, so that is a refusal
//   too. The system line names the macOS version (SystemVersion.plist) and
//   the Darwin release. Every command or path in a fix is shell-quoted.

import { accessSync, constants, lstatSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { arch, release, type, userInfo } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { z } from 'zod'

import { assertAosEntry, gitignoresAos } from '../../src/config.js'
import { ConfigError } from '../../src/errors.js'
import { falsifyRefusal } from '../../src/falsify-hold.js'
import { rootGitignoreIgnores } from '../../src/gitignore.js'
import { shellWord } from '../../src/install/plan.js'
import { readRegular } from './discover.js'
import { childPath } from './run.js'

/** The names a shell may export that would point pmmcp's commands elsewhere: shown, never passed on (the runner's allowlist). */
export const DOCKER_NAMES: readonly string[] = ['DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_CONTEXT']

/** What pmmcp's scripts and the installer's probes and steps run, with the fix for one that is missing. */
export const PROGRAMS: readonly (readonly [string, string])[] = [
  ['git', 'install the Command Line Tools (xcode-select --install) or brew install git'],
  ['curl', 'it ships with macOS as /usr/bin/curl'],
  ['uv', 'brew install uv (pmmcp builds its virtualenv with it)'],
  ['ollama', 'install Ollama.app and open it once (it links /usr/local/bin/ollama), or brew install ollama'],
  ['python3', 'install the Command Line Tools (xcode-select --install)'],
  ['bash', 'it ships with macOS as /bin/bash'],
  ['docker', "install Docker Desktop (pmmcp's Qdrant runs in it)"],
  ['lsof', 'it ships with macOS as /usr/sbin/lsof'],
  ['ps', 'it ships with macOS as /bin/ps'],
  ['pgrep', 'it ships with macOS as /usr/bin/pgrep'],
  ['launchctl', 'it ships with macOS: pmmcp runs as a launchd service, so the installer changes pmmcp on macOS only (--aos-only works anywhere)'],
  ['plutil', 'it ships with macOS: the installer reads pmmcp\'s launchd plist with it (--aos-only works anywhere)'],
]

/** Docker Desktop's credential helper: the start script's Qdrant image pull needs it when ~/.docker/config.json names it. */
export const CREDENTIAL_HELPER = 'docker-credential-desktop'

/** The fix for a missing credential helper. */
export const CREDENTIAL_HELPER_FIX = 'it ships with Docker Desktop (in ~/.docker/bin or /usr/local/bin): reinstall Docker Desktop, or remove credsStore from ~/.docker/config.json'

/** The largest ~/.docker/config.json read for its credsStore. */
const DOCKER_CONFIG_CAP = 1024 * 1024

/** ~/.docker/config.json, as far as the preflight reads it: its credsStore, if it names one. */
const DockerConfig = z.object({ credsStore: z.unknown().optional() }).loose()

/** package.json, as far as the preflight reads it. */
const PackageJson = z.object({ engines: z.object({ node: z.string() }).loose().optional() }).loose()

/** The npm config names a flag of the installer's becomes when npm takes it before `--`, with that flag. */
export const NPM_TRACES: readonly (readonly [string, string])[] = [
  ['npm_config_dry_run', '--dry-run'],
  ['npm_config_aos_only', '--aos-only'],
  ['npm_config_pmmcp_dir', '--pmmcp-dir'],
  ['npm_config_help', '--help'],
  ['npm_config_install', '--no-install'],
]

/** The installer's flags npm took as its own, by the npm_config_* names it left; [] when there are none. */
export function npmTookFlags(env: Readonly<Record<string, string | undefined>>): string[] {
  return NPM_TRACES.filter(([name]) => env[name] !== undefined).map(([, flag]) => flag)
}

const list = (names: readonly string[]): string => (names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names.at(-1) ?? ''}`)

/** Where `name` is on `path` as `command -v` finds it: an executable file in one of its directories, links followed. */
export function onPath(name: string, path: string): string | undefined {
  for (const dir of path.split(':')) {
    if (dir === '') continue
    const candidate = join(dir, name)
    try {
      if (!statSync(candidate).isFile()) continue
      accessSync(candidate, constants.X_OK)
      return candidate
    } catch {
      // Not here.
    }
  }
  return undefined
}

/** Whether ~/.docker/config.json names Docker Desktop's credential helper. Undefined when it cannot be read: nothing of it is shown. */
function namesDesktopHelper(home: string): boolean | undefined {
  const read = readRegular(join(home, '.docker', 'config.json'), DOCKER_CONFIG_CAP)
  if ('problem' in read) return /ENOENT/.test(read.problem) ? false : undefined
  try {
    const doc = DockerConfig.safeParse(JSON.parse(read.text))
    return doc.success ? doc.data.credsStore === 'desktop' : undefined
  } catch {
    // A parse error quotes the text, which may hold a registry credential: never shown.
    return undefined
  }
}

/** Does `version` (x.y.z) meet an engines range of `^a.b.c` and `>=a.b.c` alternatives? Undefined for a range this does not read. */
export function meetsEngines(version: string, range: string): boolean | undefined {
  const triple = (s: string): readonly [number, number, number] | undefined => {
    const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(s)
    return m === null ? undefined : [Number(m[1]), Number(m[2]), Number(m[3])]
  }
  const atLeast = (a: readonly number[], b: readonly number[]): boolean => {
    for (let i = 0; i < 3; i += 1) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0)
    return true
  }
  const v = triple(version.replace(/^v/, ''))
  if (v === undefined) return undefined
  let met = false
  for (const alt of range.split('||').map((s) => s.trim())) {
    const m = /^(\^|>=)(\d+\.\d+\.\d+)$/.exec(alt)
    const floor = m === null ? undefined : triple(m[2] ?? '')
    if (m === null || floor === undefined) return undefined
    if (m[1] === '^' ? v[0] === floor[0] && atLeast(v, floor) : atLeast(v, floor)) met = true
  }
  return met
}

/** True when two paths are the same directory: by spelling once links are resolved, and by device and inode. */
function sameDirectory(a: string, b: string): boolean {
  try {
    if (realpathSync(a) !== realpathSync(b)) return false
    const sa = statSync(a)
    const sb = statSync(b)
    return sa.dev === sb.dev && sa.ino === sb.ino
  } catch {
    return false
  }
}

/** macOS's version from SystemVersion.plist's text: its ProductVersion, or undefined. */
export function productVersion(plist: string): string | undefined {
  const m = /<key>ProductVersion<\/key>\s*<string>([0-9][0-9.]{0,15})<\/string>/.exec(plist)
  return m?.[1]
}

/** Where macOS keeps its version. */
const SYSTEM_VERSION = '/System/Library/CoreServices/SystemVersion.plist'

/** The S1 system line's start: `macOS 15.6.1 (Darwin 24.6.0) arm64`, or the kernel's name and release elsewhere. */
function systemName(platform: NodeJS.Platform): string {
  if (platform === 'darwin') {
    const read = readRegular(SYSTEM_VERSION, 64 * 1024)
    const version = 'text' in read ? productVersion(read.text) : undefined
    return `macOS ${version ?? '(version not readable)'} (Darwin ${release()}) ${arch()}`
  }
  return `${type()} ${release()} ${arch()}`
}

/** The developer folders /usr/bin's git and python3 stubs run from: xcode-select's choice, the Command Line Tools, Xcode. */
export function developerDirs(): string[] {
  const dirs: string[] = []
  try {
    dirs.push(realpathSync('/var/db/xcode_select_link'))
  } catch {
    // Never chosen with xcode-select -s: the stubs try the next two.
  }
  dirs.push('/Library/Developer/CommandLineTools', '/Applications/Xcode.app/Contents/Developer')
  return dirs
}

/** The stubs macOS puts in /usr/bin, which run the developer folder's program or open an install dialog. */
const STUBS: ReadonlySet<string> = new Set(['git', 'python3'])

/**
 * On macOS, a git or python3 found as /usr/bin's stub with no developer
 * folder that has the program behind it: each is a refusal with its fix.
 */
export function stubRefusals(found: ReadonlyMap<string, string>, platform: NodeJS.Platform, dirs: readonly string[], executable: (path: string) => boolean): string[] {
  if (platform !== 'darwin') return []
  const out: string[] = []
  for (const [name, path] of found) {
    if (!STUBS.has(name) || path !== `/usr/bin/${name}`) continue
    if (dirs.some((d) => executable(join(d, 'usr', 'bin', name)))) continue
    out.push(
      `${name} on the PATH pmmcp's commands get is /usr/bin/${name}, the stub that asks to install the Command Line Tools, and neither they nor Xcode are installed: ` +
        'run xcode-select --install and finish its dialog, then re-run',
    )
  }
  return out
}

const isExecutable = (path: string): boolean => {
  try {
    if (!statSync(path).isFile()) return false
    accessSync(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}

export interface PreflightInput {
  readonly aosOnly: boolean
  /** This checkout's root. */
  readonly root: string
  readonly home: string | undefined
  readonly env: Readonly<Record<string, string | undefined>>
  /** Default: process.cwd(). */
  readonly cwd?: string
  /** Default: process.geteuid(). */
  readonly euid?: number | undefined
  /** Default: process.getuid(). */
  readonly uid?: number | undefined
  /** Default: the login name of the uid, or unknown. */
  readonly user?: string
  /** Default: process.platform. */
  readonly platform?: NodeJS.Platform
  /** Default: developerDirs(). */
  readonly developer?: readonly string[]
}

export interface Preflight {
  readonly lines: readonly string[]
  readonly refusals: readonly string[]
}

/** The login name of this process's uid, or unknown when it has no passwd entry. */
function loginName(): string {
  try {
    return userInfo().username
  } catch {
    return 'unknown'
  }
}

export function preflight(input: PreflightInput): Preflight {
  const { root, home, env } = input
  const platform = input.platform ?? process.platform
  const lines: string[] = ['preflight:']
  const refusals: string[] = []
  const euid = 'euid' in input ? input.euid : process.geteuid?.()
  const uid = 'uid' in input ? input.uid : process.getuid?.()
  const user = input.user ?? loginName()
  lines.push(`  system      ${systemName(platform)}, user ${user} (uid ${uid === undefined ? 'unknown' : String(uid)})`)
  if (euid === 0) {
    refusals.push('the installer does not run as root: run it as your own account, without sudo (the .env it writes and pmmcp\'s files must be yours)')
  }
  const homeOk = home !== undefined && isAbsolute(home) && !home.includes(':')
  if (!homeOk) refusals.push('HOME is not set to an absolute path without a colon: run the installer from your own login shell')
  if (!sameDirectory(input.cwd ?? process.cwd(), root)) {
    refusals.push(`the current directory is not this checkout's root (${root}): run it from there, cd ${shellWord(root)} && npm run aos-install`)
  }
  // npm run sets the script's cwd to the package root whatever folder it was typed in, and says where in INIT_CWD. npm itself
  // resolves .npmrc's cache=.aos/npm-cache against that folder, so its cache and logs land in <there>/.aos, which git does not ignore.
  const init = env['INIT_CWD']
  if (init !== undefined && init !== '' && !sameDirectory(init, root)) {
    const stray = join(init, '.aos')
    let made = false
    try {
      made = isAbsolute(init) && lstatSync(stray).isDirectory()
    } catch {
      made = false
    }
    refusals.push(
      `npm run was typed in ${init}, not in this checkout's root (${root}), and npm keeps its cache and logs under the folder it was typed in (.npmrc's cache=.aos/npm-cache): ` +
        `run it from the root, cd ${shellWord(root)} && npm run aos-install` +
        (made ? `; ${stray} holds what npm wrote there, which git does not ignore: remove it once you have checked it holds only npm's cache and logs` : ''),
    )
  }
  lines.push(`  checkout    ${root}`)
  const held = falsifyRefusal(root)
  if (held !== undefined) refusals.push(held)

  let engines: string | undefined
  try {
    const pkg = PackageJson.safeParse(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')))
    engines = pkg.success ? pkg.data.engines?.node : undefined
  } catch {
    engines = undefined
  }
  const meets = engines === undefined ? undefined : meetsEngines(process.version, engines)
  lines.push(`  node        ${process.version}${engines === undefined ? '' : ` (package.json engines: ${engines})`}`)
  if (meets === false) refusals.push(`Node ${process.version} is outside package.json's engines (${engines ?? ''}): install a Node that meets them, then re-run`)
  let modules = false
  try {
    modules = statSync(join(root, 'node_modules')).isDirectory()
  } catch {
    modules = false
  }
  if (!modules) refusals.push(`${join(root, 'node_modules')} is missing: run npm install in the repository root, then re-run`)
  if (!rootGitignoreIgnores(root, '.env', 'file')) {
    refusals.push(`${join(root, '.gitignore')} does not ignore .env, which the installer may create: restore the .env* line, then re-run`)
  }
  if (!gitignoresAos(root)) {
    refusals.push(`${join(root, '.gitignore')} does not ignore /.aos/, where the installer keeps its lock and logs: add the line /.aos/, then re-run`)
  } else {
    try {
      assertAosEntry(root)
    } catch (e) {
      if (!(e instanceof ConfigError)) throw e
      refusals.push(e.message)
    }
  }

  const pointed = [...DOCKER_NAMES.filter((n) => env[n] !== undefined), ...Object.keys(env).filter((n) => n.startsWith('PMMCP_')).sort()]
  lines.push(
    `  exports     ${pointed.length === 0 ? `none of ${DOCKER_NAMES.join(', ')} or PMMCP_*` : `${list(pointed)}: pmmcp's commands run without ${pointed.length === 1 ? 'it' : 'them'}`}`,
  )

  if (input.aosOnly) {
    lines.push('  programs    not checked (--aos-only: pmmcp is not touched)')
  } else if (homeOk) {
    const path = childPath(home)
    const wanted: (readonly [string, string])[] = [...PROGRAMS]
    const helper = namesDesktopHelper(home)
    if (helper === true) wanted.push([CREDENTIAL_HELPER, CREDENTIAL_HELPER_FIX])
    const at = new Map<string, string>()
    for (const [name] of wanted) {
      const where = onPath(name, path)
      if (where !== undefined) at.set(name, where)
    }
    const missing = wanted.filter(([name]) => !at.has(name))
    const found = wanted.filter(([name]) => at.has(name)).map(([name]) => name)
    lines.push(`  programs    ${found.length === 0 ? 'none found' : list(found)} on the PATH pmmcp's commands get`)
    if (helper === undefined) lines.push(`  docker      ~/.docker/config.json cannot be read, so whether it names ${CREDENTIAL_HELPER} is not known`)
    if (missing.length > 0) {
      lines.push(`  PATH        ${path}`)
      for (const [name, fix] of missing) refusals.push(`${name} is not on the PATH pmmcp's commands get (above): ${fix}`)
    }
    refusals.push(...stubRefusals(at, platform, input.developer ?? developerDirs(), isExecutable))
  }
  return { lines, refusals }
}
