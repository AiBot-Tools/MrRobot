// The capture file's shape, built from a server's tool list.
//
// Pure, apart from the entry point that calls it (scripts/capture-pmmcp.ts), so
// a test can hold it to what it claims without running the operator's script.
//
// Output schemas are kept verbatim. Contract P6 gives pmmcp's goal tools typed
// results, and FastMCP already publishes `{result: string}` for a tool
// annotated `-> str`; a capture that dropped them could show neither. The file
// says it records them (`recordsOutputSchema`), because a capture taken before
// it did reads exactly like a server that declares none.

import type { ListedTool } from './hub.js'

export interface CapturedToolRecord {
  readonly name: string
  readonly description?: string
  readonly inputSchema: unknown
  readonly outputSchema?: unknown
}

export interface CaptureRecord {
  readonly capturedAt: string
  readonly server: string
  readonly url: string
  readonly toolCount: number
  /** tools/list pages the server answered with; contract P6 wants one. */
  readonly pages: number
  readonly recordsOutputSchema: true
  readonly tools: readonly CapturedToolRecord[]
}

export function captureOf(
  tools: readonly ListedTool[],
  meta: { readonly capturedAt: string; readonly server: string; readonly url: string; readonly pages: number },
): CaptureRecord {
  return {
    ...meta,
    toolCount: tools.length,
    recordsOutputSchema: true,
    tools: tools
      .map((t) => ({
        name: t.name,
        ...(t.description === undefined ? {} : { description: t.description }),
        inputSchema: t.inputSchema,
        ...(t.outputSchema === undefined ? {} : { outputSchema: t.outputSchema }),
      }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
  }
}
