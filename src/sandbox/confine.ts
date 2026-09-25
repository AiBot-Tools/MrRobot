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

import { ConfigError } from '../errors.js'
import { assertNotProtected, isUnder, realpathNearest } from '../agents/protected.js'

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
): string {
  const realWorkspace = realpathNearest(workspace)
  const realRoot = realpathNearest(mountRoot)

  if (!isUnder(realRoot, realWorkspace)) {
    throw new ConfigError(
      `mount confinement: ${workspace} resolves to ${realWorkspace}, which is outside ` +
        `the domain mountRoot ${mountRoot} (${realRoot})`,
    )
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
