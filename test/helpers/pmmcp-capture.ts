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

import {
  inputShape,
  liveJsonSchema,
  PMMCP_LIVE,
  type InputShape,
  type PmmcpLiveTool,
  type PropertyShape,
} from '../../src/mcp/pmmcp-schemas.js'
import { FORCED_DISABLED, FORCED_KERNEL_ONLY } from '../../src/mcp/tool-views.js'
import { PMMCP_TOOLS, PMMCP_TOOL_COUNT } from './mock-pmmcp.js'

/**
 * Tools invariant 7 forces closed that the live server does not register.
 *
 * Their pins stay in config/tool-views.yaml and their entries stay in the
 * double, because the rule is about the day pmmcp adds them, not about today:
 * the hub tests prove such a tool arrives kernel-only. The drift guard would
 * otherwise read each one as a pin guarding nothing. Only a forced name may sit
 * here (an operator's own pin for a missing tool IS a rule guarding nothing),
 * and a name the live server registers again is a finding, so the list can
 * neither grow past invariant 7 nor outlive the absence it records.
 */
export const ABSENT_BY_INVARIANT: readonly string[] = ['restore_backup']

export interface CapturedTool {
  readonly name: string
  readonly description?: string
  readonly inputSchema?:
    | { readonly type?: unknown; readonly properties?: Record<string, unknown>; readonly required?: readonly string[] }
    | undefined
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
  /** Defaults to ABSENT_BY_INVARIANT; the tests pass a wrong one. */
  readonly absentByInvariant?: readonly string[]
}

function defaultOf(p: PropertyShape): string {
  return 'default' in p ? `default ${JSON.stringify(p.default)}` : 'no default'
}

/**
 * Where the kernel's typed transcript (src/mcp/pmmcp-schemas.ts) and the live
 * tool part ways: a property either side lacks, its types, its default, and
 * the required set. Exact, not a subset: the transcript claims to BE the live
 * schema, so a property it lacks is a property nothing has typed.
 */
function shapeFindings(tool: string, typed: InputShape, live: InputShape): string[] {
  const out: string[] = []
  const names = [...new Set([...Object.keys(typed.properties), ...Object.keys(live.properties)])].sort()
  for (const name of names) {
    const t = typed.properties[name]
    const l = live.properties[name]
    if (t === undefined) {
      out.push(`${tool}.${name}: live declares it; src/mcp/pmmcp-schemas.ts does not`)
    } else if (l === undefined) {
      out.push(`${tool}.${name}: src/mcp/pmmcp-schemas.ts declares it; live does not`)
    } else {
      if (t.types.join('|') !== l.types.join('|')) {
        out.push(`${tool}.${name}: typed ${t.types.join('|')}; live declares ${l.types.join('|')}`)
      }
      if (defaultOf(t) !== defaultOf(l)) out.push(`${tool}.${name}: typed ${defaultOf(t)}; live ${defaultOf(l)}`)
    }
  }
  if (typed.required.join(',') !== live.required.join(',')) {
    out.push(`${tool}: typed required [${typed.required.join(', ')}]; live requires [${live.required.join(', ')}]`)
  }
  return out
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

  const forced = new Set([...FORCED_KERNEL_ONLY, ...FORCED_DISABLED])
  const absent = new Set<string>()
  for (const name of input.absentByInvariant ?? ABSENT_BY_INVARIANT) {
    if (!forced.has(name)) {
      findings.push(`${name} is excused as absent, but invariant 7 does not force it; only a forced pin may be absent`)
    } else if (live.has(name)) {
      findings.push(`the live server now registers ${name}; remove it from ABSENT_BY_INVARIANT so its schema is checked`)
    } else {
      absent.add(name)
    }
  }

  for (const spec of PMMCP_TOOLS) {
    const tool = live.get(spec.name)
    if (tool === undefined && absent.has(spec.name)) continue
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

  // The kernel's typed transcript, held to the capture by type, nullability,
  // item type, default and requiredness. A tool missing from the capture, or
  // with no properties, is already a finding above.
  for (const name of Object.keys(PMMCP_LIVE) as PmmcpLiveTool[]) {
    const tool = live.get(name)
    if (tool?.inputSchema?.properties === undefined) continue
    try {
      findings.push(...shapeFindings(name, inputShape(liveJsonSchema(name)), inputShape(tool.inputSchema)))
    } catch (e) {
      findings.push(`${name}: the live schema cannot be compared: ${e instanceof Error ? e.message : String(e)}`)
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
    if (!live.has(name) && !absent.has(name)) findings.push(`tool-views.yaml pins a tool the live server does not expose: ${name}`)
  }

  // The count appears in CLAUDE.md, in config/tool-views.yaml's header and in
  // the double. If the server has gained tools, the number in three files is
  // stale and so is the count of unclassified tools.
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
 * Agreeing includes the belief that the excused tools are absent.
 */
export function agreeingCapture(): PmmcpCapture {
  const tools: CapturedTool[] = PMMCP_TOOLS.filter((spec) => !ABSENT_BY_INVARIANT.includes(spec.name)).map((spec) => ({
    name: spec.name,
    inputSchema: {
      type: 'object',
      properties: { ...spec.inputSchema.properties },
      ...(spec.inputSchema.required === undefined ? {} : { required: [...spec.inputSchema.required] }),
    },
  }))
  for (let i = tools.length; i < PMMCP_TOOL_COUNT; i += 1) {
    tools.push({ name: `live_tool_${String(i)}`, inputSchema: { properties: {} } })
  }
  return { toolCount: PMMCP_TOOL_COUNT, tools }
}
