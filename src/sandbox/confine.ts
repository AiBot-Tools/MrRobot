// Mount confinement (invariants 9 and 8).
//
// A bind mount is the one thing that reaches out of a container, so the host
// path is never trusted as written. Both sides are resolved through symlinks
// first, because a textual check is defeated by the oldest trick there is:
// leave a link inside the allowed tree pointing at /etc, hand over the link's
// path, and a string comparison sees something harmless while the container
// gets the real directory read-write.
//
// Containment compares with a separator appended, so `/data/aos-evil` cannot
// pass as living under `/data/aos`.
//
// The resolved path is what goes to docker. Passing the request string would
// undo the whole check at the last moment: the kernel would have validated one
// path and mounted another.

import { statSync } from 'node:fs'
import { homedir } from 'node:os'

import { ConfigError } from '../errors.js'
import { assertNotProtected, identify, isSpelledUnder, isUnder, realpathNearest, type Identify } from '../agents/protected.js'

/**
 * Resolve a workspace path and prove it is allowed.
 *
 * @returns the REAL path, which is what the caller must hand to the runtime.
 * @throws {ConfigError} when it escapes the domain's mountRoot or lands in a
 *   protected root.
 */
export function confineWorkspace(
  workspace: string,
  mountRoot: string,
  repoRoot: string,
  // Seams for tests: an alias of $HOME cannot be made without root.
  opts: { readonly home?: string; readonly id?: Identify } = {},
): string {
  const id = opts.id ?? identify
  const realWorkspace = realpathNearest(workspace)
  const realRoot = realpathNearest(mountRoot)

  // The allowed zone by spelling only: identity would let a bind mount under
  // the mountRoot vouch for whatever it mounts.
  if (!isSpelledUnder(realRoot, realWorkspace)) {
    throw new ConfigError(
      `mount confinement: ${workspace} resolves to ${realWorkspace}, which is outside ` +
        `the domain mountRoot ${mountRoot} (${realRoot})`,
    )
  }

  // Invariant 9 on every run, by identity: config.ts checked the mountRoot at
  // boot, and a link or mount made since can put $HOME or the repository
  // under it under a spelling no string comparison recognises.
  const home = realpathNearest(opts.home ?? homedir())
  if (isUnder(realWorkspace, home, id)) {
    throw new ConfigError(`mount confinement: ${realWorkspace} is or contains $HOME (${home})`)
  }
  const repo = realpathNearest(repoRoot)
  if (isUnder(realWorkspace, repo, id)) {
    throw new ConfigError(`mount confinement: ${realWorkspace} is or contains the repository (${repo})`)
  }

  // Invariant 8 still applies inside the mountRoot: a domain configured to
  // point at the repository must not hand an agent its own souls.
  assertNotProtected(realWorkspace, repoRoot)

  // A workspace that does not exist would be created by the runtime as root,
  // outside the kernel's control. Refusing is the fail-closed answer.
  let ok = false
  try {
    ok = statSync(realWorkspace).isDirectory()
  } catch {
    ok = false
  }
  if (!ok) {
    throw new ConfigError(`mount confinement: ${realWorkspace} is not an existing directory`)
  }

  return realWorkspace
}
