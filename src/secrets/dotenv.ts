// The operator's credentials file: <repo>/.env, read by entry points only.
//
// CONTRACT
//
//   Who reads it: src/main.ts (npm run dev), src/cli/index.ts and scripts/eval.ts,
//   and only when their argv carries `--dotenv <path>`. package.json passes
//   `--dotenv .env` to those three scripts and to nothing else, and nothing here
//   has a default path, so an entry point started without the flag opens no
//   file. Tests that start one WITH it (entrypoints.test.ts) run from
//   shadowCheckout()'s temporary copy, whose .env is a trap, and hygiene.test.ts
//   holds every such spawn to that copy's cwd. The one test reader of the real
//   file is test/helpers/live-env.ts: with no path it opens <repo>/.env only on
//   the operator's gated live run (AOS_LIVE_TESTS=1, one test/live-*.test.ts
//   file in its process), and only when the shell lacks the key. Its other
//   callers (dotenv.test.ts) hand it explicit trap paths; hygiene.test.ts
//   admits a pathless call there only as a thunk proving liveCredential's own
//   refusal.
//
//   Who writes it: the operator. No code path writes it, or .env.example, which
//   is the committed, placeholder-only template and never holds a real value.
//
//   Where the values go: into a plain object the caller hands to bootKernel as
//   its env. NEVER into process.env, so child processes, the Anthropic SDK's own
//   ambient reads (ANTHROPIC_CUSTOM_HEADERS, ANTHROPIC_LOG) and diagnostic
//   reports never see a file-sourced value, and no line in the file can set
//   NODE_OPTIONS or turn on a paid test gate.
//
//   What it admits: only names the config declares as credentials
//   (credentialNames). Everything else is refused, not ignored.
//
//   What it refuses, before reading a byte: a symlink, anything that is not a
//   regular file, a file owned by another user, a file whose mode lets group or
//   others read or write it (the mode bits only: a macOS ACL is not read, so
//   README says to clear one with chmod -N), a second hard link, more than
//   64 KiB, and — inside the repository — any path but <repo>/.env, a .env
//   stored on disk under another case (.Env), or a .gitignore that no longer
//   ignores it.
//
//   Why not util.parseEnv: Node's parser (shared with --env-file) gives a
//   whitespace-only value the WHOLE NEXT LINE — `ANTHROPIC_API_KEY= ` followed by
//   `AOS_CONTROL_TOKEN=x` sets the key to `AOS_CONTROL_TOKEN=x` — resolves a
//   repeated name silently, and glues a UTF-8 BOM onto the first name. The
//   grammar below is per line, strict, and refuses rather than guesses.
//
//   What it never says: a value, a line's text, or a name it does not accept.
//   Messages carry the path, line numbers and accepted names only, because the
//   daemon's catch logs e.message and pino has no value mask of its own.

import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'

import { entryProblem, identify, isUnder, type Identify } from '../agents/protected.js'
import type { KernelConfig } from '../config.js'
import { ConfigError } from '../errors.js'
import { SecretMask } from '../events/redact.js'
import { rootGitignoreIgnores } from '../gitignore.js'
import { ENV_LINE } from './broker.js'
import type { ProvidersFile } from '../models/registry.js'

export const DOTENV_FLAG = '--dotenv'
export const DOTENV_FILE = '.env'
export const DOTENV_MAX_BYTES = 65_536

/**
 * The placeholder prefix every .env.example value carries. A live file still
 * holding one is refused: copying the template and forgetting a line must not
 * send `replace-me-…` to a provider as a key.
 */
export const PLACEHOLDER_PREFIX = 'replace-me'

const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/
const LINE = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(.*)$/

export interface DotenvOptions {
  /** The repository root, for the in-repo fence and the .gitignore check. */
  readonly repoRoot: string
  /** Every name the file may contain (credentialNames). */
  readonly accepted: ReadonlySet<string>
  /** The names this caller actually wants back; a subset of `accepted`. */
  readonly wanted: readonly string[]
  /** The process's own environment. A value here that is not blank wins over the file. */
  readonly shell: Readonly<Record<string, string | undefined>>
  /** Injected so a test can stand in for another user; defaults to process.getuid(). */
  readonly uid?: number
}

export interface DotenvResult {
  readonly path: string
  readonly found: boolean
  /** Wanted names taken from the file. Never holds an empty string. */
  readonly values: Readonly<Record<string, string>>
  /** Wanted names set in BOTH the shell (not blank) and the file: the shell won. */
  readonly shadowed: readonly string[]
}

interface Parsed {
  readonly value: string
  readonly line: number
}

/**
 * The credential names the config declares: the control token, any declared
 * MCP bearer, and every provider entry's auth.envVar (placeholders included, so
 * clearing a placeholder needs no code change here).
 */
export function credentialNames(config: KernelConfig, providers: ProvidersFile): ReadonlySet<string> {
  const names = new Set<string>([config.control.tokenEnv])
  for (const server of Object.values(config.mcp.servers)) {
    if (server.tokenEnv !== undefined) names.add(server.tokenEnv)
  }
  for (const entry of Object.values(providers.entries)) {
    if (entry.auth.envVar !== undefined) names.add(entry.auth.envVar)
  }
  return names
}

/**
 * The path named by `--dotenv`, resolved against `base`, or undefined without
 * the flag. A repeated flag, a missing value, or a value that is itself an
 * option is refused rather than guessed at.
 */
export function dotenvPathFrom(argv: readonly string[], base: string): string | undefined {
  let found: string | undefined
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    let value: string | undefined
    if (arg === DOTENV_FLAG) {
      value = argv[i + 1]
      if (value === undefined || value === '' || value.startsWith('--')) {
        throw new ConfigError(`${DOTENV_FLAG} needs a path`)
      }
      i += 1
    } else if (arg !== undefined && arg.startsWith(`${DOTENV_FLAG}=`)) {
      value = arg.slice(DOTENV_FLAG.length + 1)
      if (value === '') throw new ConfigError(`${DOTENV_FLAG} needs a path`)
    } else {
      continue
    }
    if (found !== undefined) throw new ConfigError(`${DOTENV_FLAG} may be given once`)
    found = resolve(base, value)
  }
  return found
}

/**
 * True when <repoRoot>/.gitignore ignores the file `.env`, read with git's
 * rules and failing closed (src/gitignore.ts): `.env*` then `!.env.example`
 * ignores it; a later negation that could match `.env` — `!*`, `!.en?` — does not.
 */
export function gitignoresDotenv(repoRoot: string): boolean {
  return rootGitignoreIgnores(repoRoot, DOTENV_FILE, 'file')
}

/**
 * The env a kernel boots with: exactly `names`. Per name, a shell value that
 * is not blank wins, then the file's, then unset. An exported empty or
 * whitespace-only string is unset — it must not hide a value the operator put
 * in the file.
 */
export function credentialEnv(
  names: Iterable<string>,
  shell: Readonly<Record<string, string | undefined>>,
  loaded: DotenvResult | undefined,
): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = {}
  for (const name of names) env[name] = shellValue(shell, name) ?? loaded?.values[name]
  return env
}

/**
 * A shell value that counts as set: anything but unset, empty or only
 * whitespace. One definition for the daemon, the CLI, eval and the shadow
 * report, so `export AOS_CONTROL_TOKEN=" "` cannot be "set" to one of them and
 * "unset" to another while the real value sits in the file.
 */
function shellValue(shell: Readonly<Record<string, string | undefined>>, name: string): string | undefined {
  const value = shell[name]
  return value !== undefined && value.trim() !== '' ? value : undefined
}

function realpathOrSelf(p: string): string {
  try {
    return realpathSync(p)
  } catch {
    return resolve(p)
  }
}

/**
 * Where `dir` sits relative to the repository, decided by identity as well as
 * spelling (isUnder): Node's JS realpath keeps every non-symlink component as
 * typed, so on case-insensitive APFS `/users/op/mrrobot` and `/Users/op/MrRobot`
 * are one directory and two strings — as are a firmlinked
 * `/System/Volumes/Data/...` path and a bind mount. A string comparison alone
 * would call the first spelling "outside" and skip the fence.
 */
export function placeInRepo(dir: string, repoRoot: string, id: Identify = identify): 'root' | 'inside' | 'outside' {
  const repo = realpathOrSelf(repoRoot)
  const d = realpathOrSelf(dir)
  if (!isUnder(repo, d, id)) return 'outside'
  return isUnder(d, repo, id) ? 'root' : 'inside'
}

/**
 * Parse a credentials file. Pure: no I/O, no process.env, no mask.
 *
 * Throws ONE ConfigError listing every bad line, by number, with the accepted
 * names — never a value, a line's text, or a name it does not accept.
 */
export function parseDotenv(text: string, accepted: ReadonlySet<string>, label = '.env'): ReadonlyMap<string, Parsed> {
  const out = new Map<string, Parsed>()
  const problems: string[] = []
  const lines = text.split('\n')
  for (let i = 0; i < lines.length; i += 1) {
    const n = i + 1
    let line = lines[i] ?? ''
    if (line.endsWith('\r')) line = line.slice(0, -1)
    if (line.includes('\r')) {
      problems.push(`line ${String(n)}: a stray carriage return`)
      continue
    }
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue

    const m = LINE.exec(line)
    const name = m?.[1]
    if (m === null || name === undefined || !NAME.test(name)) {
      problems.push(`line ${String(n)}: not NAME=value`)
      continue
    }
    if (!accepted.has(name)) {
      // Not quoted: a pasted key can land where a name belongs.
      problems.push(`line ${String(n)}: a name this kernel does not read: delete the line`)
      continue
    }

    let value = (m[2] ?? '').replace(/^[ \t]+|[ \t]+$/g, '')
    const q = value[0]
    if (q === '"' || q === "'") {
      if (value.length < 2 || value[value.length - 1] !== q) {
        problems.push(`line ${String(n)}: ${name} has an unmatched quote`)
        continue
      }
      value = value.slice(1, -1)
    }
    if (/[\s#'"`]/.test(value)) {
      problems.push(`line ${String(n)}: ${name} holds whitespace, a quote, a backtick or '#': a key is one unbroken token`)
      continue
    }
    // A TextEdit smart quote or a zero-width space pasted from a web page is
    // none of the above, and no provider key or token holds one.
    if (/[^\x21-\x7e]/.test(value)) {
      problems.push(`line ${String(n)}: ${name} holds a character outside printable ASCII (a smart quote, a zero-width space): retype it`)
      continue
    }
    if (ENV_LINE.test(value)) {
      problems.push(`line ${String(n)}: ${name} holds a whole NAME=value line: two lines were joined`)
      continue
    }
    if (value.toLowerCase().startsWith(PLACEHOLDER_PREFIX)) {
      problems.push(`line ${String(n)}: ${name} still holds the .env.example placeholder: put the real value there`)
      continue
    }

    const earlier = out.get(name)
    if (earlier !== undefined) {
      problems.push(`line ${String(n)}: ${name} is already set on line ${String(earlier.line)}`)
      continue
    }
    // A blank value means unset, never ''. It is still recorded as a line so a
    // later duplicate is caught.
    out.set(name, { value, line: n })
  }

  if (problems.length > 0) {
    throw new ConfigError(`${label}: ${problems.join('; ')} (accepted: ${[...accepted].sort().join(', ')})`)
  }
  for (const [name, parsed] of out) {
    if (parsed.value === '') out.delete(name)
  }
  return out
}

/**
 * Every name that holds a line in a credentials file, with the first line it
 * is on. Pure: names and line numbers only, never a value.
 *
 * parseDotenv drops a blank value as unset; this keeps it, with `export`
 * prefixes and quoted values alike, because the .env writer must never append
 * a name the operator already gave a line, even an empty one: the file would
 * then hold it twice and the loader would refuse it. A comment is not a line
 * for a name. It judges nothing, so call it on text parseDotenv accepted.
 */
export function occupiedLines(text: string): ReadonlyMap<string, number> {
  const out = new Map<string, number>()
  const lines = text.split('\n')
  for (let i = 0; i < lines.length; i += 1) {
    let line = lines[i] ?? ''
    if (line.endsWith('\r')) line = line.slice(0, -1)
    const name = LINE.exec(line)?.[1]
    if (name !== undefined && !out.has(name)) out.set(name, i + 1)
  }
  return out
}

/** Read the file through one descriptor that refused to follow a symlink. */
function readGuarded(path: string, uid: number | undefined): Buffer | undefined {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return undefined
    if (code === 'ELOOP') throw new ConfigError(`${path} is a symbolic link; replace it with a regular file and chmod 600 it`)
    throw new ConfigError(`cannot open ${path}: ${code ?? 'unknown error'}`)
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw new ConfigError(`${path} is not a regular file`)
    if (uid === undefined) throw new ConfigError(`cannot verify the owner of ${path}`)
    if (st.uid !== uid) throw new ConfigError(`${path} is owned by uid ${String(st.uid)}, not you (uid ${String(uid)})`)
    if ((st.mode & 0o077) !== 0) {
      const mode = (st.mode & 0o777).toString(8).padStart(4, '0')
      throw new ConfigError(`${path} has mode ${mode}: its mode lets group or others read or write it. Run: chmod 600 ${path}`)
    }
    if (st.nlink !== 1) throw new ConfigError(`${path} has another hard link, which exposes it elsewhere`)
    if (st.size > DOTENV_MAX_BYTES) {
      throw new ConfigError(`${path} is ${String(st.size)} bytes; a credentials file is at most ${String(DOTENV_MAX_BYTES)}`)
    }
    const buf = Buffer.alloc(st.size)
    let read = 0
    while (read < st.size) {
      const got = readSync(fd, buf, read, st.size - read, read)
      if (got === 0) break
      read += got
    }
    if (read !== st.size) throw new ConfigError(`${path} changed while it was being read`)
    return buf
  } finally {
    closeSync(fd)
  }
}

/**
 * Load the wanted credentials from a .env.
 *
 * A missing file is not an error: `found` is false and nothing is returned.
 * Every returned value is registered with SecretMask BEFORE this returns, so a
 * file-sourced value is censored from the very first event that could carry it.
 *
 * @throws {ConfigError} for anything in the contract above it cannot verify.
 */
export function loadDotenv(path: string, options: DotenvOptions): DotenvResult {
  const abs = resolve(path)
  const repo = realpathOrSelf(options.repoRoot)
  const place = placeInRepo(dirname(abs), options.repoRoot)
  if (place !== 'outside') {
    if (place !== 'root' || basename(abs) !== DOTENV_FILE) {
      throw new ConfigError(`the only credentials file read inside the repository is ${join(repo, DOTENV_FILE)}; got ${abs}`)
    }
    const spelled = entryProblem(dirname(abs), DOTENV_FILE)
    if (spelled?.kind === 'spelling') {
      throw new ConfigError(
        `${join(dirname(abs), spelled.actual)} is spelled ${spelled.actual} on disk, not ${DOTENV_FILE}: git judges the name as stored, ` +
          `and .gitignore's .env* does not cover it under core.ignorecase=false. Rename it to ${DOTENV_FILE}`,
      )
    }
    if (!gitignoresDotenv(options.repoRoot)) {
      throw new ConfigError(`${abs} is not ignored by ${join(repo, '.gitignore')}: add the line /.env before putting a key in it`)
    }
  }

  const buf = readGuarded(abs, options.uid ?? process.getuid?.())
  if (buf === undefined) return { path: abs, found: false, values: {}, shadowed: [] }

  let text: string
  try {
    // ignoreBOM is false: the decoder consumes a leading UTF-8 BOM itself.
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf)
  } catch {
    throw new ConfigError(`${abs} is not valid UTF-8`)
  }
  if (text.includes('\0')) throw new ConfigError(`${abs} contains a NUL byte`)

  const parsed = parseDotenv(text, options.accepted, abs)
  const values: Record<string, string> = {}
  const shadowed: string[] = []
  for (const name of options.wanted) {
    const fromFile = parsed.get(name)
    if (fromFile === undefined) continue
    if (shellValue(options.shell, name) !== undefined) {
      shadowed.push(name)
      continue
    }
    SecretMask.register(fromFile.value)
    values[name] = fromFile.value
  }
  return { path: abs, found: true, values, shadowed }
}

/**
 * One credential, for a client that needs only that one (the CLI and eval need
 * the control token, never a provider key): a shell value that is not blank,
 * else the file at `path`, else undefined. Without a path no file is opened.
 *
 * `accepted` must still be every credential name, so the operator's file —
 * which holds provider keys too — is not refused for containing them.
 */
export function oneCredential(
  name: string,
  path: string | undefined,
  options: Omit<DotenvOptions, 'wanted'>,
): string | undefined {
  // As set, not trimmed: the daemon's env carries the shell value as set, and a
  // caller that reports it (liveCredential) must see what the broker will.
  const fromShell = shellValue(options.shell, name)
  if (fromShell !== undefined) return fromShell
  if (path === undefined) return undefined
  return loadDotenv(path, { ...options, wanted: [name] }).values[name]
}
