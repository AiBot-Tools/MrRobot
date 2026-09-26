// Comparing a live pmmcp `listTools` capture against what this repo believes.
//
// A pure function, deliberately: the comparison is the load-bearing part of the
// drift guard, and it cannot be allowed to rot while the capture that would
// exercise it does not exist. Separated out, it is tested TODAY against
// synthetic captures — one correct, one wrong in every way that matters — so the
// day the operator drops a real capture in, the thing doing the checking has
// already been checked.
//
// Every disagreement is collected rather than thrown at the first one. Finding
// drift means finding the set of assumptions Phase 1 was built on; reporting one
// of them would hide the rest.

import './guard.js'

import { PMMCP_TOOLS, PMMCP_TOOL_COUNT } from './mock-pmmcp.js'

export interface CapturedTool {
  readonly name: string
  readonly description?: string
  readonly inputSchema?: { readonly properties?: Record<string, unknown> } | undefined
}

export interface PmmcpCapture {
  readonly capturedAt?: string
  readonly toolCount?: number
  readonly tools?: readonly CapturedTool[]
}

export interface CompareInput {
  readonly capture: PmmcpCapture
  /** config/kernel.yaml secrets.keyArg — the argument the broker will send. */
  readonly keyArg: string
  /** The tool names config/tool-views.yaml pins. */
  readonly pinned: readonly string[]
}

/** The property names a captured tool declares, or undefined if it declares none. */
function properties(tool: CapturedTool | undefined): string[] | undefined {
  const props = tool?.inputSchema?.properties
  if (props === undefined) return undefined
  return Object.keys(props).sort()
}

/**
 * Every way the capture disagrees with this repo, as one-line findings. Empty
 * means the guesses in mock-pmmcp.ts were right.
 */
export function compareCapture(input: CompareInput): string[] {
  const findings: string[] = []
  const tools = input.capture.tools ?? []
  if (tools.length === 0) {
    return ['the capture holds no tools; re-run `npm run capture:pmmcp`']
  }
  const live = new Map(tools.map((t) => [t.name, t]))

  for (const spec of PMMCP_TOOLS) {
    const tool = live.get(spec.name)
    if (tool === undefined) {
      // A modelled tool the server does not have is a guess that was wrong, and
      // anything in the kernel built on it needs revisiting.
      findings.push(`modelled tool absent from the live server: ${spec.name}`)
      continue
    }
    const actual = properties(tool)
    if (actual === undefined) {
      findings.push(`${spec.name}: the live tool declares no inputSchema.properties`)
      continue
    }
    // Subset, not equality: the double models the arguments the kernel uses, and
    // a server with extra optional ones is not drift. A declared argument the
    // server does not have IS — every call the kernel makes would carry it.
    const unknown = Object.keys(spec.inputSchema.properties)
      .sort()
      .filter((k) => !actual.includes(k))
    if (unknown.length > 0) {
      findings.push(`${spec.name}: models ${unknown.join(', ')}; live declares ${actual.join(', ')}`)
    }
  }

  // The stub that fails closed until this passes. kernel.yaml names the argument
  // the broker sends; a server wanting a different one makes every credential
  // fetch fail, and this names it before boot ever tries.
  const secretArgs = properties(live.get('get_secret'))
  if (secretArgs === undefined) {
    findings.push('the live get_secret declares no properties, so secrets.keyArg cannot be confirmed')
  } else if (!secretArgs.includes(input.keyArg)) {
    findings.push(
      `config/kernel.yaml secrets.keyArg is "${input.keyArg}" but the live get_secret declares ` +
        secretArgs.join(', '),
    )
  }

  // A pinned classification for a tool that does not exist is a rule guarding
  // nothing, and in an audit it reads exactly like a rule that works.
  for (const name of input.pinned) {
    if (!live.has(name)) findings.push(`tool-views.yaml pins a tool the live server does not expose: ${name}`)
  }

  // 49 appears in CLAUDE.md, in config/tool-views.yaml's header and in the
  // double. If the server has gained tools, the number in three files is stale
  // and so is "forty are unclassified".
  const count = input.capture.toolCount ?? tools.length
  if (count !== PMMCP_TOOL_COUNT) {
    findings.push(
      `the live server exposes ${String(count)} tools; this repo says ${String(PMMCP_TOOL_COUNT)} in ` +
        'CLAUDE.md, config/tool-views.yaml and test/helpers/mock-pmmcp.ts',
    )
  }

  return findings
}

/**
 * A capture that agrees with this repo, for proving the comparison can pass.
 * Built from the same table it is compared against, so it says nothing about
 * pmmcp — only that `compareCapture` is not a function that always complains.
 */
export function agreeingCapture(): PmmcpCapture {
  const tools: CapturedTool[] = PMMCP_TOOLS.map((spec) => ({
    name: spec.name,
    inputSchema: { properties: { ...spec.inputSchema.properties } },
  }))
  for (let i = tools.length; i < PMMCP_TOOL_COUNT; i += 1) {
    tools.push({ name: `live_tool_${String(i)}`, inputSchema: { properties: {} } })
  }
  return { toolCount: PMMCP_TOOL_COUNT, tools }
}
