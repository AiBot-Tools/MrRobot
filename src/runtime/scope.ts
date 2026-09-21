// Ambient run scope.
//
// Carries the identity of the run currently executing across await
// boundaries, so kernel code deep in a call stack can ask "whose run is
// this?" without every function threading the answer through its signature.
//
// What it carries is deliberately tiny and strictly typed: ids, a taint mark,
// a tier and a lane. It never carries a token, a key, a vault handle or an
// MCP connection (invariant 2). The schema is strict, so a caller cannot
// smuggle an extra field into the ambient context and have some later
// function find it there, and the object is frozen, so nothing can raise its
// own tier or clear its own taint mid-run.

import { AsyncLocalStorage } from 'node:async_hooks'
import { z } from 'zod'

export const RunScope = z
  .object({
    runId: z.string().min(1),
    agentId: z.string().min(1),
    taint: z.enum(['clean', 'tainted']),
    tier: z.number().int().nonnegative(),
    lane: z.string().min(1),
  })
  .strict()

export type RunScope = z.infer<typeof RunScope>

const storage = new AsyncLocalStorage<RunScope>()

/**
 * Run `fn` with `scope` as the ambient run identity.
 *
 * The scope is parsed (not cast) and frozen before it is installed: a run
 * must not be able to edit the record that describes its own privileges.
 */
export function withRunScope<T>(scope: RunScope, fn: () => T): T {
  const parsed = Object.freeze(RunScope.parse(scope))
  return storage.run(parsed, fn)
}

/** The current run's scope, or undefined when called outside any run. */
export function runScope(): RunScope | undefined {
  return storage.getStore()
}
