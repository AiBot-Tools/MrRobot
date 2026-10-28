// The one writer of the operator's credentials file, <repo>/.env.
//
// CONTRACT
//
//   Who calls it: the installer (npm run aos-install: scripts/install.ts and
//   scripts/install/*) and its tests, which hand it temp directories only. The
//   kernel, the daemon, the CLI and eval never reach it, and no other module in
//   src/ or scripts/ opens .env for writing (hygiene.test.ts holds all three).
//
//   What it writes: only <repoRoot>/.env, and only names the config declares
//   (`accepted`) that hold no line in the file yet. A missing file is created at
//   0600 with O_EXCL, so a file that appears meanwhile is never written over,
//   and starts with two comment lines that hold no value. An existing file is
//   appended to, never rewritten: no line is changed, removed or reordered; a
//   name the operator left blank keeps its blank line and is never appended a
//   second time; no backup copy is made anywhere. An existing file is read
//   through a descriptor that cannot write, and opened for writing only once
//   something is missing, so a 0400 file the loader accepts is accepted here
//   while nothing is missing. Nothing to append means nothing is opened for
//   writing, and a missing file stays missing.
//
//   What it reports: each name it was asked for, by line number, as appended,
//   present (set to a value) or blank (on a line with no value, which the
//   loader reads as unset: not done, and for the operator to fill in or
//   delete, since appending it again would make the file a duplicate the
//   loader refuses). inspectCredentials reports the same, and what is missing,
//   before anything is written: it is the installer's plan and its dry run,
//   read through the same refusals and never opened for writing.
//
//   What it refuses, changing nothing: running as root (the file would be
//   root's, and the daemon run as the operator refuses it); a .gitignore that
//   does not ignore .env; a .env that is a symlink or is stored under another
//   case; every file the loader (dotenv.ts) refuses: not a regular file,
//   another owner, group or other mode bits, a second hard link, over 64 KiB
//   (after the append, too), invalid UTF-8, a NUL byte, any line parseDotenv
//   refuses (a placeholder, an undeclared name, a duplicate); a file it must
//   append to whose mode bits deny its owner writing; a file it created whose
//   filesystem does not keep mode 0600; a file that changed between the read
//   and the write; and a generated value shorter than the control token's
//   floor or one the loader would not read back exactly as written. Every
//   refusal happens before a byte is written. A file this call created and
//   then refused, before its first byte, is removed again.
//
//   How a failure says what it changed: every error appendCredentials throws
//   is a DotenvWriteError, whose `written` is false for a refusal (the file is
//   as it was) and true once the file may have changed (created and not
//   removed, or bytes appended, then something failed). The installer reads
//   that field, never the message, to tell "refused, nothing changed" from "a
//   step failed".
//
//   What it never says: a value. It prints nothing. Its result and its errors
//   carry the path, names and line numbers only, and every generated value is
//   registered with SecretMask before it is written, so anything that quotes
//   one later is censored.
//
//   How it knows it worked: the descriptor it appends through must name the
//   inode it read, at the size and mtime it read, so an editor's save between
//   the read and the write is refused with nothing written. After the write and
//   fsync it lstats the path again: another inode means the file was replaced
//   during the write itself and the new lines went with the old one; that is
//   reported, never lost silently. Then loadDotenv must read every written name
//   back as generated.

import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  unlinkSync,
  writeSync,
  type Stats,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'

import { entryProblem } from '../agents/protected.js'
import { MIN_TOKEN_LENGTH } from '../control/auth.js'
import { ConfigError } from '../errors.js'
import { SecretMask } from '../events/redact.js'
import { DOTENV_FILE, DOTENV_MAX_BYTES, gitignoresDotenv, loadDotenv, occupiedLines, parseDotenv } from './dotenv.js'

/** The two lines a created file starts with: comments, no value, no placeholder. */
export const CREATED_HEADER = '# Created by npm run aos-install, which only ever appends the names it lacks.\n# Add ANTHROPIC_API_KEY yourself.\n'

/**
 * The shortest value this writes. The control token's floor
 * (control/auth.ts) is the strictest any credential here has, so one floor
 * serves every name: a value under it would be refused at boot, or by the
 * mask, wherever it went.
 */
export const MIN_GENERATED_LENGTH = MIN_TOKEN_LENGTH

const NEWLINE = 0x0a

/** Who runs, and which file and names: what both calls check before opening anything. */
interface Where {
  /** The repository root: the file is <repoRoot>/.env and nothing else. */
  readonly repoRoot: string
  /** Every name the file may contain (credentialNames). */
  readonly accepted: ReadonlySet<string>
  /** The owner the file must have, as the loader checks it; defaults to process.getuid(). */
  readonly uid?: number
  /** Who is running, for the root refusal; defaults to process.geteuid(). Injected so a test run as root can stand for the operator. */
  readonly euid?: number
}

export interface AppendOptions extends Where {
  /** The names to add when the file holds no line for them, in order, each with what makes its value. */
  readonly generate: ReadonlyMap<string, () => string>
}

export interface InspectOptions extends Where {
  /** The names to report, in order. Each must be one `accepted` holds. */
  readonly names: Iterable<string>
}

/** A name and the line it is on, numbered as the loader numbers them (from 1). */
export interface NameLine {
  readonly name: string
  readonly line: number
}

export interface AppendResult {
  readonly path: string
  /** True when this call created the file. */
  readonly created: boolean
  /** Names written by this call, in the order written, each with the line it now holds. */
  readonly appended: readonly NameLine[]
  /** Names in `generate` already set to a value, left alone. */
  readonly present: readonly NameLine[]
  /**
   * Names in `generate` on a line with a blank value, left alone. The loader
   * reads each as unset, so none is done: the caller reports the line for the
   * operator to fill in or delete. Appending it would make a duplicate.
   */
  readonly blank: readonly NameLine[]
}

export interface InspectResult {
  readonly path: string
  /** True when the file exists. */
  readonly found: boolean
  /** Names set to a value, by line. */
  readonly present: readonly NameLine[]
  /** Names on a line with a blank value, by line: the loader reads each as unset, and none is ever appended. */
  readonly blank: readonly NameLine[]
  /** Names that hold no line at all, in the order asked: the ones appendCredentials would add, given a value. */
  readonly missing: readonly string[]
  /**
   * Whether its owner may write the file, by its mode bits, as an append
   * needs: false for a 0400 file, which appendCredentials refuses to add a
   * missing name to. True with no file, which would be created.
   */
  readonly writable: boolean
}

/**
 * What appendCredentials throws: a ConfigError naming the path, names and
 * line numbers only, and whether the file may have changed. `written` is
 * false when <repoRoot>/.env is exactly as it was before the call (every
 * refusal, and a file it created and removed again), and true when this call
 * may have written it: created it and could not remove it, or put bytes in it
 * before something failed. The message says what to check by hand.
 */
export class DotenvWriteError extends ConfigError {
  readonly written: boolean

  constructor(message: string, written: boolean, options?: ErrorOptions) {
    super(message, options)
    this.written = written
  }
}

/**
 * What <repoRoot>/.env holds of `names`, by line, through every refusal
 * appendCredentials makes before it generates a value. Opens nothing for
 * writing and creates nothing: a missing file is reported missing.
 *
 * @throws {ConfigError} naming the path, names and line numbers only, for any
 *   refusal in the contract above that comes before a value is made.
 */
export function inspectCredentials(options: InspectOptions): InspectResult {
  const names = [...new Set(options.names)]
  const path = dotenvPathIn(options.repoRoot)
  const uid = preflight(options, names, path)
  const fd = openToRead(path)
  if (fd === undefined) return { path, found: false, present: [], blank: [], missing: names, writable: true }
  try {
    const held = readHeld(fd, path, names, options.accepted, uid)
    return { path, found: true, present: held.present, blank: held.blank, missing: held.missing, writable: (held.before.mode & 0o200) !== 0 }
  } finally {
    closeSync(fd)
  }
}

/**
 * Create <repoRoot>/.env at 0600, or append to it the `generate` names it
 * holds no line for. Never changes, removes or reorders a line.
 *
 * @throws {DotenvWriteError} (a ConfigError) for anything in the contract
 *   above: `written` false for a refusal, the file as it was; true once the
 *   file may have changed, with what to check in the message.
 */
export function appendCredentials(options: AppendOptions): AppendResult {
  const path = dotenvPathIn(options.repoRoot)
  const progress: Progress = { written: false }
  try {
    return append(path, options, progress)
  } catch (e) {
    throw failure(path, e, progress.written)
  }
}

/** Whether the file may have changed yet: set once it exists by this call's hand, or once bytes go into it. */
interface Progress {
  written: boolean
}

function append(path: string, options: AppendOptions, progress: Progress): AppendResult {
  const uid = preflight(options, options.generate.keys(), path)
  const fd = openToRead(path)
  if (fd === undefined) return create(path, options, uid, progress)

  // Held open to the end, so the inode read cannot be freed and its number
  // handed to a new file that would then pass for it.
  try {
    const held = readHeld(fd, path, options.generate.keys(), options.accepted, uid)
    const { buf, text, present, blank, missing } = held
    if (missing.length === 0) return { path, created: false, appended: [], present, blank }

    if ((held.before.mode & 0o200) === 0) {
      const mode = (held.before.mode & 0o777).toString(8).padStart(4, '0')
      throw new ConfigError(
        `${path} has mode ${mode}: its owner cannot write it, so ${missing.join(', ')} cannot be added. ` +
          `Run: chmod 600 ${path}, then re-run npm run aos-install`,
      )
    }
    const values = generated(missing, options)
    // Without it the first new line would join the file's last key.
    const lead = buf.length > 0 && buf[buf.length - 1] !== NEWLINE ? '\n' : ''
    const chunk = Buffer.from(lead + assignments(values), 'utf8')
    if (held.before.size + chunk.length > DOTENV_MAX_BYTES) {
      throw new ConfigError(
        `${path} would be ${String(held.before.size + chunk.length)} bytes after the append; a credentials file is at most ` +
          `${String(DOTENV_MAX_BYTES)}. Nothing was written`,
      )
    }
    const appended = readsBack(text + chunk.toString('utf8'), values, options.accepted, path)
    appendTo(path, held.before, chunk, uid, progress)
    sameFile(path, held.before)
    verify(path, values, options, uid)
    return { path, created: false, appended, present, blank }
  } finally {
    closeSync(fd)
  }
}

/** <repoRoot>/.env: the one path this module opens. */
function dotenvPathIn(repoRoot: string): string {
  return join(resolve(repoRoot), DOTENV_FILE)
}

/**
 * The refusals before the file is opened: root, a link or a case variant at
 * the path, a .gitignore that does not ignore it, a name the config does not
 * declare. Returns the owner the file must have.
 */
function preflight(where: Where, names: Iterable<string>, path: string): number {
  const euid = where.euid ?? process.geteuid?.()
  if (euid === undefined) throw new ConfigError('cannot tell which user is running, so .env is not written')
  if (euid === 0) {
    throw new ConfigError(
      'refusing to write .env as root: the file would be owned by root, and the daemon you run refuses it. ' +
        'Run npm run aos-install as yourself, without sudo',
    )
  }
  const uid = where.uid ?? process.getuid?.()
  if (uid === undefined) throw new ConfigError('cannot verify who would own .env, so it is not written')

  const repo = dirname(path)
  const entry = entryProblem(repo, DOTENV_FILE)
  if (entry?.kind === 'link') throw new ConfigError(`${path} is a symbolic link; replace it with a regular file and chmod 600 it`)
  if (entry?.kind === 'spelling') {
    throw new ConfigError(
      `${join(repo, entry.actual)} is spelled ${entry.actual} on disk, not ${DOTENV_FILE}: git judges the name as stored, ` +
        `and .gitignore's .env* does not cover it under core.ignorecase=false. Rename it to ${DOTENV_FILE}`,
    )
  }
  if (!gitignoresDotenv(repo)) {
    throw new ConfigError(`${path} is not ignored by ${join(repo, '.gitignore')}: add the line /.env before a key goes in it`)
  }
  for (const name of names) {
    if (!where.accepted.has(name)) throw new ConfigError(`${name} is not a credential name the config declares, so it is not written to .env`)
  }
  return uid
}

/**
 * A descriptor that cannot write, or undefined when there is no file. A file
 * with nothing missing is never opened for writing, so a 0400 .env the loader
 * accepts is not refused for want of a permission nothing needs.
 */
function openToRead(path: string): number | undefined {
  try {
    return openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return undefined
    if (code === 'ELOOP') throw new ConfigError(`${path} is a symbolic link; replace it with a regular file and chmod 600 it`)
    throw new ConfigError(`cannot open ${path}: ${code ?? 'unknown error'}`)
  }
}

/** The file as `fd` reads it, judged as the loader judges it, and where each of `names` stands in it. */
interface Held {
  readonly before: Stats
  readonly buf: Buffer
  readonly text: string
  readonly present: NameLine[]
  readonly blank: NameLine[]
  readonly missing: string[]
}

function readHeld(fd: number, path: string, names: Iterable<string>, accepted: ReadonlySet<string>, uid: number): Held {
  const before = fstatSync(fd)
  // A FIFO, a directory or a device is refused here, before anything is
  // opened for writing: a FIFO's reader would receive the new token.
  refuseLikeTheLoader(before, path, uid)
  const buf = readAll(fd, before.size, path)
  const text = decode(buf, path)
  // Any line the loader refuses stops here: its message names line numbers
  // only, and the operator fixes the file by hand.
  const parsed = parseDotenv(text, accepted, path)
  const occupied = occupiedLines(text)
  const present: NameLine[] = []
  const blank: NameLine[] = []
  const missing: string[] = []
  for (const name of names) {
    const line = occupied.get(name)
    if (line === undefined) missing.push(name)
    // parseDotenv keeps only names with a value; a line it dropped is blank.
    else (parsed.has(name) ? present : blank).push({ name, line })
  }
  return { before, buf, text, present, blank, missing }
}

/**
 * Open the file read as `read` for appending, and append `chunk`. The new
 * descriptor must name that inode at that size and mtime: anything else is a
 * file saved or edited since the read, and nothing is written to it.
 */
function appendTo(path: string, read: Stats, chunk: Buffer, uid: number, progress: Progress): void {
  let fd: number
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ELOOP') throw new ConfigError(`${path} was replaced by a symbolic link while the installer read it; nothing was written`)
    throw new ConfigError(`cannot open ${path} to append to it: ${code ?? 'unknown error'}; nothing was written`)
  }
  try {
    const now = fstatSync(fd)
    if (now.dev !== read.dev || now.ino !== read.ino || now.size !== read.size || now.mtimeMs !== read.mtimeMs) {
      throw new ConfigError(
        `${path} changed while the installer read it (an editor saving it?); nothing was written. Re-run npm run aos-install`,
      )
    }
    refuseLikeTheLoader(now, path, uid)
    progress.written = true
    writeAll(fd, chunk, path)
    syncFile(fd, path)
  } finally {
    closeSync(fd)
  }
}

/** A missing file: generate every value first, then create it with O_EXCL. */
function create(path: string, options: AppendOptions, uid: number, progress: Progress): AppendResult {
  const names = [...options.generate.keys()]
  if (names.length === 0) return { path, created: false, appended: [], present: [], blank: [] }
  const values = generated(names, options)
  const chunk = Buffer.from(CREATED_HEADER + assignments(values), 'utf8')
  const appended = readsBack(chunk.toString('utf8'), values, options.accepted, path)

  let fd: number
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'EEXIST') throw new ConfigError(`${path} appeared while the installer was preparing it; nothing was written. Re-run npm run aos-install`)
    throw new ConfigError(`cannot create ${path}: ${code ?? 'unknown error'}`)
  }
  // The file exists now, by this call's hand: until it is removed again, a
  // failure has changed what is there.
  progress.written = true
  let made: Stats
  // What the operator can do about a file left behind.
  let fix = 'delete it, then re-run npm run aos-install'
  try {
    // The umask can only narrow the open mode; fchmod makes it exact.
    fchmodSync(fd, 0o600)
    made = fstatSync(fd)
    // On a filesystem that ignores chmod no command makes the file private,
    // and the file is removed below, so the loader's "Run: chmod 600" would
    // name a fix for a file that is gone, and a re-run would fail the same way.
    if ((made.mode & 0o077) !== 0) {
      fix = 'delete it; this filesystem cannot hold a credentials file'
      const mode = (made.mode & 0o777).toString(8).padStart(4, '0')
      throw new ConfigError(`${path} was created, but its filesystem did not keep mode 0600 (it shows ${mode}), so a credentials file cannot be private there`)
    }
    refuseLikeTheLoader(made, path, uid)
  } catch (e) {
    // Before the close: see removeCreated.
    const refused = removeCreated(path, fd, e, fix)
    closeSync(fd)
    throw refused
  }
  try {
    writeAll(fd, chunk, path)
    syncFile(fd, path)
  } finally {
    closeSync(fd)
  }
  syncDirectory(path)
  sameFile(path, made)
  verify(path, values, options, uid)
  return { path, created: true, appended, present: [], blank: [] }
}

/**
 * A file this call created and then refused before writing a byte: remove
 * it, so a refusal leaves a missing file missing. Only while the path still
 * names the empty inode `fd` holds; anything else there is not this call's to
 * remove. Called before `fd` is closed: an open descriptor keeps its inode
 * from being freed and its number handed to a new file that would pass for
 * it, and a closed one cannot be checked at all, so the file is left, the
 * message says so with `fix`, and the error says the file may have changed.
 */
function removeCreated(path: string, fd: number, why: unknown, fix: string): DotenvWriteError {
  const reason = why instanceof ConfigError ? why.message : `${path} could not be prepared (${(why as NodeJS.ErrnoException).code ?? 'unknown error'})`
  try {
    const held = fstatSync(fd)
    const now = lstatSync(path)
    if (now.dev === held.dev && now.ino === held.ino && held.size === 0) {
      unlinkSync(path)
      return new DotenvWriteError(`${reason}. Nothing was written, and the empty file this created was removed`, false, { cause: why })
    }
  } catch {
    // Reported below: the file may be left, and the message says so.
  }
  return new DotenvWriteError(`${reason}. Nothing was written to it, but ${path} may be left empty: ${fix}`, true, { cause: why })
}

/**
 * Every failure as a DotenvWriteError: a refusal or a failure from below
 * keeps its message; anything else (a generator's own error, an errno no
 * branch above names) is reported by its code, never its text, which may
 * quote what it was given.
 */
function failure(path: string, e: unknown, written: boolean): DotenvWriteError {
  if (e instanceof DotenvWriteError) return e
  if (e instanceof ConfigError) return new DotenvWriteError(e.message, written, { cause: e })
  const what = (e as NodeJS.ErrnoException).code ?? (e instanceof Error ? e.name : 'an unknown error')
  return new DotenvWriteError(written ? `${path} may have been changed before ${what}: check it by hand` : `${path} was not written: ${what}`, written, { cause: e })
}

/** What the loader refuses before reading a byte (dotenv.ts readGuarded), refused here before writing one. */
function refuseLikeTheLoader(st: Stats, path: string, uid: number): void {
  if (!st.isFile()) throw new ConfigError(`${path} is not a regular file`)
  if (st.uid !== uid) throw new ConfigError(`${path} is owned by uid ${String(st.uid)}, not you (uid ${String(uid)})`)
  if ((st.mode & 0o077) !== 0) {
    const mode = (st.mode & 0o777).toString(8).padStart(4, '0')
    throw new ConfigError(`${path} has mode ${mode}: its mode lets group or others read or write it. Run: chmod 600 ${path}`)
  }
  if (st.nlink !== 1) throw new ConfigError(`${path} has another hard link, which exposes it elsewhere`)
  if (st.size > DOTENV_MAX_BYTES) {
    throw new ConfigError(`${path} is ${String(st.size)} bytes; a credentials file is at most ${String(DOTENV_MAX_BYTES)}`)
  }
}

function readAll(fd: number, size: number, path: string): Buffer {
  const buf = Buffer.alloc(size)
  let read = 0
  while (read < size) {
    const got = readSync(fd, buf, read, size - read, read)
    if (got === 0) break
    read += got
  }
  if (read !== size) throw new ConfigError(`${path} changed while it was being read; nothing was written`)
  return buf
}

function decode(buf: Buffer, path: string): string {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf)
  } catch {
    throw new ConfigError(`${path} is not valid UTF-8`)
  }
  if (text.includes('\0')) throw new ConfigError(`${path} contains a NUL byte`)
  return text
}

/** One value per name, each checked and masked before anything is written. */
function generated(names: readonly string[], options: AppendOptions): ReadonlyMap<string, string> {
  const out = new Map<string, string>()
  for (const name of names) {
    const make = options.generate.get(name)
    if (make === undefined) continue
    const value = make()
    const problem = valueProblem(name, value, options.accepted)
    if (problem !== undefined) throw new ConfigError(`the value generated for ${name} ${problem}; nothing was written`)
    if (!SecretMask.register(value)) throw new ConfigError(`the value generated for ${name} cannot be masked; nothing was written`)
    out.set(name, value)
  }
  return out
}

/**
 * Why `value` must not be written as `name`, as a phrase that never quotes
 * it. The loader is the judge: the line must parse, and parse back to exactly
 * the value, so a newline, a quote pair the loader would strip or a
 * placeholder is refused here rather than at the next boot.
 */
function valueProblem(name: string, value: string, accepted: ReadonlySet<string>): string | undefined {
  if (typeof value !== 'string') return 'is not a string'
  if (value.length < MIN_GENERATED_LENGTH) {
    return `is ${String(value.length)} characters; a generated value has at least ${String(MIN_GENERATED_LENGTH)}`
  }
  let parsed: ReturnType<typeof parseDotenv>
  try {
    parsed = parseDotenv(`${name}=${value}\n`, accepted, `the line generated for ${name}`)
  } catch (e) {
    // parseDotenv's message names line numbers and accepted names, never a value.
    return `would be refused by the .env loader (${(e as Error).message})`
  }
  if (parsed.size !== 1 || parsed.get(name)?.value !== value) return 'would not read back from .env as written'
  return undefined
}

function assignments(values: ReadonlyMap<string, string>): string {
  return [...values].map(([name, value]) => `${name}=${value}\n`).join('')
}

/**
 * The whole file as it will be, read by the loader's grammar before a byte is
 * written: each value must come back exactly, and the line the loader finds
 * it on is the line reported.
 */
function readsBack(text: string, values: ReadonlyMap<string, string>, accepted: ReadonlySet<string>, path: string): NameLine[] {
  const parsed = parseDotenv(text, accepted, path)
  const lines: NameLine[] = []
  for (const [name, value] of values) {
    const got = parsed.get(name)
    if (got?.value !== value) throw new ConfigError(`${path} would not hold ${name} after the append; nothing was written`)
    lines.push({ name, line: got.line })
  }
  return lines
}

function writeAll(fd: number, chunk: Buffer, path: string): void {
  let written = 0
  try {
    while (written < chunk.length) written += writeSync(fd, chunk, written, chunk.length - written)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? 'unknown error'
    throw new ConfigError(
      `writing ${path} failed after ${String(written)} of ${String(chunk.length)} bytes (${code}): check its last line by hand before re-running`,
    )
  }
}

/** The bytes are durable only once the file is synced. */
function syncFile(fd: number, path: string): void {
  try {
    fsyncSync(fd)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? 'unknown error'
    throw new ConfigError(`${path} was written but could not be synced (${code}): check its last line by hand before re-running`)
  }
}

/** A created entry is durable only once its directory is. */
function syncDirectory(path: string): void {
  let fd: number | undefined
  try {
    fd = openSync(dirname(path), constants.O_RDONLY)
    fsyncSync(fd)
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? 'unknown error'
    throw new ConfigError(`${path} was written but its directory could not be synced (${code}): check the file is there, then re-run`)
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

/** The path must still name the inode written: an editor's save-by-rename would carry the new lines away. */
function sameFile(path: string, written: Stats): void {
  let now: Stats
  try {
    now = lstatSync(path)
  } catch {
    throw new ConfigError(`${path} disappeared while the installer wrote it: the new lines are not in your file. Re-run npm run aos-install`)
  }
  if (now.dev !== written.dev || now.ino !== written.ino) {
    throw new ConfigError(
      `${path} was replaced while the installer wrote it (an editor saving it?): the new lines are not in your file. Re-run npm run aos-install`,
    )
  }
}

/** The loader, the one reader that matters, must return every written name exactly. */
function verify(path: string, values: ReadonlyMap<string, string>, options: AppendOptions, uid: number): void {
  const loaded = loadDotenv(path, { repoRoot: options.repoRoot, accepted: options.accepted, wanted: [...values.keys()], shell: {}, uid })
  for (const [name, value] of values) {
    if (loaded.values[name] !== value) throw new ConfigError(`${path} does not read back ${name} as written: check the file by hand`)
  }
}
