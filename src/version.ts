// Single source of truth for the kernel's version string.
// Kept in its own module so test/env.test.ts can prove that tsx resolves a
// ".js" specifier to this ".ts" source: the import suffix convention that
// CLAUDE.md mandates is load-bearing for every other file in the project.

export const VERSION = '0.0.1'

/** Protocol version served on the control plane. Frozen for the UI. */
export const PROTOCOL_VERSION = 1 as const
