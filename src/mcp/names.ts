// Tool name mapping (invariant 10).
//
// A tool has two spellings and they must never be confused:
//
//   ref   `pmmcp.recall`   dotted. What the kernel uses everywhere — in
//                          manifests, tool-views, the gate, tickets, and the
//                          event log.
//   name  `pmmcp__recall`  underscored. Only ever what goes into a provider's
//                          tool array and comes back on a tool call.
//
// The mapping exists because provider tool names cannot contain a dot.
// Anthropic accepts ^[a-zA-Z0-9_-]{1,128}$ and OpenAI-compatible endpoints
// document a-z A-Z 0-9 underscore dash with a 64-character limit, so the
// kernel validates against the STRICTER of the two: a name that works on one
// provider and not another would turn a routing decision into a silent
// capability difference.
//
// This module is the only place the mapping happens. Two rules follow, and
// both are enforced by buildNameTable rather than left to discipline:
//
//   * The mapping must be injective. `a.b` and `a__b` both map to `a__b`, so
//     a tool call coming back from the model would be ambiguous — and
//     resolving it the wrong way means the gate authorised one tool and the
//     hub ran another. That is refused at load, naming both refs.
//   * A ref whose mapped name fails the provider regex is refused at load,
//     not silently dropped at request time, so the failure surfaces where a
//     human is reading config rather than mid-run.

import { ConfigError } from '../errors.js'

/** Strictest provider rule: OpenAI's 64-char limit over the shared alphabet. */
export const PROVIDER_TOOL_NAME = /^[a-zA-Z0-9_-]{1,64}$/

/** A dotted ref: at least two segments, each non-empty. */
export const TOOL_REF = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$/

/** Map a dotted ref to its provider-facing name. */
export function toolName(ref: string): string {
  return ref.split('.').join('__')
}

/**
 * Map a provider-facing name back to its ref, using a table built by
 * buildNameTable. There is no string-level inverse — `a__b` could have come
 * from `a.b` or from a tool genuinely named `a__b` — so the table is the only
 * correct way back, and an unknown name is an error rather than a guess.
 */
export function toolRef(name: string, table: NameTable): string {
  const ref = table.refByName.get(name)
  if (ref === undefined) {
    throw new ConfigError(`unknown provider tool name: ${name}`)
  }
  return ref
}

export interface NameTable {
  readonly nameByRef: ReadonlyMap<string, string>
  readonly refByName: ReadonlyMap<string, string>
}

/**
 * Build the mapping for a set of refs, refusing anything ambiguous or
 * unusable. Called once when tool views are loaded, so every failure is a
 * startup failure with both offending refs named.
 */
export function buildNameTable(refs: Iterable<string>): NameTable {
  const nameByRef = new Map<string, string>()
  const refByName = new Map<string, string>()

  for (const ref of refs) {
    if (!TOOL_REF.test(ref)) {
      throw new ConfigError(
        `tool ref "${ref}" is not a dotted reference (expected <server>.<tool>)`,
      )
    }
    if (nameByRef.has(ref)) continue // the same ref listed twice is harmless

    const name = toolName(ref)
    if (!PROVIDER_TOOL_NAME.test(name)) {
      throw new ConfigError(
        `tool ref "${ref}" maps to "${name}", which fails the provider tool-name rule ` +
          `${String(PROVIDER_TOOL_NAME)}. Rename the tool or keep it kernel-only.`,
      )
    }

    const collidesWith = refByName.get(name)
    if (collidesWith !== undefined) {
      throw new ConfigError(
        `tool name collision: "${collidesWith}" and "${ref}" both map to "${name}". ` +
          'A tool call could not be resolved unambiguously, so the gate could authorise one ' +
          'tool and the hub run the other.',
      )
    }

    nameByRef.set(ref, name)
    refByName.set(name, ref)
  }

  return { nameByRef, refByName }
}
