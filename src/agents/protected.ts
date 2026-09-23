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
// cannot pass as living under `/data/aos`.

import { realpathSync } from 'node:fs'
import { dirname, isAbsolute, resolve, sep } from 'node:path'

import { ConfigError } from '../errors.js'

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

/** True when `child` is `parent` itself or lies beneath it. */
export function isUnder(parent: string, child: string): boolean {
  const p = resolve(parent)
  const c = resolve(child)
  if (c === p) return true
  // The separator is what stops /data/aos-evil matching /data/aos.
  return c.startsWith(p.endsWith(sep) ? p : p + sep)
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
