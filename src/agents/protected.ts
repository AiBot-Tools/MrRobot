// Protected roots (invariant 8).
//
// Souls, agent manifests and config are read-only to agents. No code path
// lets a run write them, and this is the check that makes that true rather
// than merely intended.
//
// The check resolves symlinks before deciding. A string comparison alone is
// defeated by the oldest trick there is: put a link outside the protected
// tree that points into it, hand the kernel the link's path, and a textual
// test sees an innocent path while the write lands on a persona. Because the
// target of a write usually does not exist yet, resolution walks up to the
// nearest ancestor that does and resolves that — the parent directory is
// where a malicious link would have to be.
//
// Containment is compared with a separator appended, so `/data/aos-evil`
// cannot pass as living under `/data/aos`. And it is also decided by identity
// (device and inode), because resolution keeps every non-symlink component as
// typed: on case-insensitive APFS `/users/op/mrrobot/SOULS` is the souls
// directory under a spelling no string test recognises, as is a firmlinked
// `/System/Volumes/Data/...` path or a bind mount.

import { lstatSync, readdirSync, realpathSync, statSync } from 'node:fs'
import { homedir, userInfo } from 'node:os'
import { dirname, isAbsolute, join, resolve, sep } from 'node:path'

import { ConfigError } from '../errors.js'

/**
 * The operator's home directory, for the never-$HOME checks. os.homedir()
 * answers '' when HOME is set but empty, and '' resolves to the cwd — which
 * would quietly turn every "not $HOME" check into "not the repository". So an
 * empty or relative HOME falls back to the passwd entry, and with no usable
 * answer the caller is refused rather than compared against nothing.
 */
export function homeDirectory(): string {
  const fromEnv = homedir()
  if (isAbsolute(fromEnv)) return fromEnv
  let fromPasswd = ''
  try {
    fromPasswd = userInfo().homedir
  } catch {
    // No passwd entry for this uid.
  }
  if (isAbsolute(fromPasswd)) return fromPasswd
  throw new ConfigError('cannot tell the home directory: HOME is empty or relative and the passwd entry has none')
}

/** A name folded past any filesystem's case folding: compatibility forms, then upper, then lower. */
function foldName(s: string): string {
  return s.normalize('NFKC').toUpperCase().toLowerCase().normalize('NFKC')
}

/**
 * What is wrong with `<parent>/<name>` as git will see it, or undefined when it
 * is absent or a plain entry spelled exactly `name`. git judges the name as it
 * is on disk (readdir), not as a path was typed: on case-insensitive APFS
 * `<repo>/.env` opens a file stored as `.Env`, which `.env*` does not cover
 * under core.ignorecase=false; and a symlink is a file to git, so `/.aos/`
 * does not cover a linked `.aos`, which `git add -A` would commit.
 */
export function entryProblem(
  parent: string,
  name: string,
  readdir: (dir: string) => readonly string[] = (dir) => readdirSync(dir),
): { readonly kind: 'link' } | { readonly kind: 'spelling'; readonly actual: string } | undefined {
  let entries: readonly string[]
  try {
    entries = readdir(parent)
  } catch {
    return undefined
  }
  if (!entries.includes(name)) {
    // Absent as spelled. A variant beside it is the same entry on APFS, and a
    // trap on a case-sensitive disk: either way, say so. APFS folds with
    // Unicode's case folding, not JS's toLowerCase ('ſ' folds to 's'), so this
    // folds more widely than either: a false match costs a rename, a missed one
    // a committed log.
    const actual = entries.find((e) => foldName(e) === foldName(name))
    return actual === undefined ? undefined : { kind: 'spelling', actual }
  }
  try {
    return lstatSync(join(parent, name)).isSymbolicLink() ? { kind: 'link' } : undefined
  } catch {
    return undefined
  }
}

/** Directories, relative to the repository root, that agents may never write. */
export const PROTECTED_ROOTS: readonly string[] = ['souls', 'agents', 'config']

/**
 * Resolve the real path of `p`, or of its nearest existing ancestor when `p`
 * itself does not exist yet. A create is as dangerous as an overwrite, so an
 * absent target still has to be located truthfully.
 */
export function realpathNearest(p: string): string {
  let current = resolve(p)
  const seen = new Set<string>()
  for (;;) {
    try {
      const real = realpathSync(current)
      // Re-attach the part we walked past, so the answer describes `p`.
      const suffix = resolve(p).slice(current.length)
      return suffix === '' ? real : real + suffix
    } catch {
      const parent = dirname(current)
      // At the filesystem root, or looping: give up and use the lexical form.
      if (parent === current || seen.has(parent)) return resolve(p)
      seen.add(current)
      current = parent
    }
  }
}

/** What two spellings of one directory share: device and inode. */
export type Identify = (path: string) => string | undefined

export const identify: Identify = (path) => {
  try {
    const st = statSync(path, { bigint: true })
    return `${String(st.dev)}:${String(st.ino)}`
  } catch {
    return undefined
  }
}

/**
 * True when `child` is `parent` itself or lies beneath it AS SPELLED. The test
 * for an ALLOWED zone — a workspace under its mountRoot, the event log under
 * <repo>/.aos — where identity would let a link or a bind mount that shares
 * the zone's dev:ino vouch for a path that physically lives elsewhere.
 */
export function isSpelledUnder(parent: string, child: string): boolean {
  const p = resolve(parent)
  const c = resolve(child)
  // The separator is what stops /data/aos-evil matching /data/aos.
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep)
}

/**
 * True when `child` is `parent` itself or lies beneath it: by spelling, or by
 * identity — some ancestor of `child` (itself included) IS `parent`. The test
 * for a FORBIDDEN zone (a protected root, $HOME, the repository): the
 * spelling test is its floor, so it can only find more containment than a
 * string comparison, never less, and refuses aliases a string would miss.
 */
export function isUnder(parent: string, child: string, id: Identify = identify): boolean {
  if (isSpelledUnder(parent, child)) return true
  const p = resolve(parent)
  const target = id(p)
  if (target === undefined) return false
  for (let d = resolve(child); ; d = dirname(d)) {
    if (id(d) === target) return true
    if (dirname(d) === d) return false
  }
}

/**
 * Throw if `target` resolves inside a protected root.
 *
 * @param target absolute path a run wants to write
 * @param repoRoot the root the protected directories are relative to
 */
export function assertNotProtected(target: string, repoRoot: string): void {
  if (!isAbsolute(target)) {
    throw new ConfigError(`protected-path check needs an absolute path, got "${target}"`)
  }
  const realTarget = realpathNearest(target)
  const realRoot = realpathNearest(repoRoot)

  for (const name of PROTECTED_ROOTS) {
    const root = resolve(realRoot, name)
    if (isUnder(root, realTarget)) {
      throw new ConfigError(
        `protected-path: ${target} resolves to ${realTarget}, inside the read-only root ${name}/`,
      )
    }
  }
}
