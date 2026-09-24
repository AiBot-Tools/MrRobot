// aos probe — does this model actually call tools?
//
// A manifest may name any model reference; the router refuses to route to one
// until a probe has SEEN it call a tool (D28). This is the file that produces
// that evidence, so its definition of success is deliberately narrow:
//
//   exactly one tool call, to the tool we offered, carrying the nonce we sent,
//   AND a successful round trip when the result is handed back.
//
// Every looser definition passes a model that cannot actually be driven. A
// model that emits two calls when asked for one, or invents a tool name, or
// echoes a nonce it made up, or takes a tool result and falls over, will fail
// a real agent loop on its first turn — quietly, mid-run, having already spent
// money. The probe is the cheap place to find that out.
//
// The probe deliberately bypasses the router: the router refuses an unprobed
// ref, and this is what makes a ref probed. It still goes through the same
// transport, so invariant 4 holds — a probe is two event pairs like any other
// spend, not a special case that escapes the log.
//
// Pre-checks can only ever say NO. A local server that reports its chat
// template cannot call tools saves us a request; a server that reports
// nothing, or a key we cannot find, means the real probe runs. Absence of
// evidence is never evidence of absence here, because a wrong guess about a
// JSON key name would otherwise mark a perfectly good model unroutable.

import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'

import { ConfigError } from '../errors.js'
import type { EventStore } from '../events/store.js'
import { AnthropicAdapter } from './anthropic.js'
import { OpenAiChatAdapter } from './openai-chat.js'
import { ProbeRecord, type ModelCard } from './registry.js'
import { withCallEvents, type CallOutcome, type Dialect, type ModelAdapter, type ToolSchema } from './transport.js'

/** How long a probe's verdict stands before the router calls it stale. */
export const DEFAULT_PROBE_TTL_HOURS = 24

/**
 * The tool the probe offers.
 *
 * Dotted, like every ref in the kernel, so it maps to `probe__echo` on the
 * wire through the one mapping invariant 10 allows. The plan calls it
 * `probe_echo` in prose; inventing a second naming path for one internal tool
 * would be the beginning of the end of that invariant.
 */
export const PROBE_TOOL_REF = 'probe.echo'

const PROBE_TOOL: ToolSchema = {
  ref: PROBE_TOOL_REF,
  description: 'Echo the nonce back. Call this exactly once, with the nonce you were given.',
  inputSchema: {
    type: 'object',
    properties: { nonce: { type: 'string', description: 'The nonce from the user message.' } },
    required: ['nonce'],
    additionalProperties: false,
  },
}

/**
 * Local servers with a capability endpoint worth asking first, keyed by the
 * provider segment of the ref. An unrecognised provider simply skips the
 * pre-check and runs the real probe.
 */
export const LOCAL_SERVER_KINDS: Readonly<Record<string, 'llama-cpp' | 'ollama'>> = {
  llama: 'llama-cpp',
  ollama: 'ollama',
}

const DEFAULT_ADAPTERS: Readonly<Record<Dialect, ModelAdapter>> = {
  anthropic: new AnthropicAdapter(),
  'openai-chat': new OpenAiChatAdapter(),
}

/**
 * Where a probe record lives.
 *
 * The ref regex admits `/`, `:` and `..`, so the name is percent-encoded: every
 * record is then a flat file directly under `probes/`, and a config-supplied
 * `anthropic/../../x` cannot write outside it.
 */
export function probeFile(dataDir: string, ref: string): string {
  return join(dataDir, 'probes', `${encodeURIComponent(ref)}.json`)
}

export function writeProbeRecord(dataDir: string, record: ProbeRecord): string {
  const path = probeFile(dataDir, record.ref)
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = join(dir, `.${encodeURIComponent(record.ref)}.${String(process.pid)}.tmp`)
  writeFileSync(tmp, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 })
  try {
    renameSync(tmp, path)
  } catch (e) {
    try {
      unlinkSync(tmp)
    } catch {
      // A stray temp file must not mask the rename failure.
    }
    throw e
  }
  return path
}

export function readProbeRecord(dataDir: string, ref: string): ProbeRecord | undefined {
  const path = probeFile(dataDir, ref)
  if (!existsSync(path)) return undefined
  let json: unknown
  try {
    json = JSON.parse(readFileSync(path, 'utf8'))
  } catch (e) {
    throw new ConfigError(`probe record ${path} is not valid JSON`, { cause: e })
  }
  const parsed = ProbeRecord.safeParse(json)
  if (!parsed.success) {
    throw new ConfigError(`probe record ${path} is malformed: ${parsed.error.message}`)
  }
  return parsed.data
}

// ── pre-checks ─────────────────────────────────────────────────────────────

interface Precheck {
  /** Set only when the server said, unambiguously, that it cannot call tools. */
  readonly refuse?: string
  readonly serverVersion?: string
}

async function readJson(
  fetchImpl: typeof globalThis.fetch,
  url: string,
  init?: RequestInit,
): Promise<Record<string, unknown> | undefined> {
  try {
    const response = await fetchImpl(url, init)
    if (!response.ok) return undefined
    const value: unknown = await response.json()
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined
  } catch {
    // An endpoint that is absent, unreachable or not JSON tells us nothing.
    return undefined
  }
}

/**
 * llama.cpp `/props`.
 *
 * NEEDS VALIDATION: the `chat_template_caps.supports_tool_calls` key name is
 * inferred from llama.cpp's own caps struct, not observed on a live server,
 * and `build_info` is read best-effort. Both are why this short-circuits ONLY
 * on a key that is present and exactly `false`: if the guess is wrong the cost
 * is one wasted chat probe, never a good model marked unroutable.
 */
async function precheckLlamaCpp(fetchImpl: typeof globalThis.fetch, baseUrl: string): Promise<Precheck> {
  const props = await readJson(fetchImpl, `${baseUrl}/props`)
  if (props === undefined) return {}

  const version = typeof props['build_info'] === 'string' ? props['build_info'] : undefined
  const caps = props['chat_template_caps']
  const out: Precheck = version === undefined ? {} : { serverVersion: version }

  if (typeof caps !== 'object' || caps === null) return out
  if ((caps as Record<string, unknown>)['supports_tool_calls'] !== false) return out

  return { ...out, refuse: 'llama.cpp /props reports chat_template_caps.supports_tool_calls: false' }
}

/** Ollama `/api/show`: `capabilities` lists `tools` when the model has them. */
async function precheckOllama(
  fetchImpl: typeof globalThis.fetch,
  baseUrl: string,
  model: string,
): Promise<Precheck> {
  const shown = await readJson(fetchImpl, `${baseUrl}/api/show`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model }),
  })
  if (shown === undefined) return {}

  const capabilities = shown['capabilities']
  if (!Array.isArray(capabilities)) return {}
  if (capabilities.includes('tools')) return {}

  return { refuse: `ollama /api/show lists capabilities [${capabilities.map(String).join(', ')}] without tools` }
}

async function precheck(
  fetchImpl: typeof globalThis.fetch,
  ref: string,
  card: ModelCard,
): Promise<Precheck> {
  const provider = ref.split('/')[0] ?? ''
  const kind = LOCAL_SERVER_KINDS[provider]
  if (kind === 'llama-cpp') return precheckLlamaCpp(fetchImpl, card.baseUrl)
  if (kind === 'ollama') return precheckOllama(fetchImpl, card.baseUrl, card.model)
  return {}
}

// ── the probe ──────────────────────────────────────────────────────────────

export interface ProbeOptions {
  readonly store: EventStore
  readonly dataDir: string
  readonly ref: string
  readonly card: ModelCard
  /** Resolved by the secrets broker. The probe never reads a vault itself. */
  readonly credential?: string
  readonly adapters?: Partial<Record<Dialect, ModelAdapter>>
  readonly fetch?: typeof globalThis.fetch
  readonly ttlHours?: number
  readonly now?: () => number
  /** Injected only by tests that need a predictable nonce. */
  readonly nonce?: string
}

export interface ProbeResult {
  readonly record: ProbeRecord
  readonly path: string
}

function sum(outcomes: readonly CallOutcome[]): { input: number; output: number; cost: number } {
  return outcomes.reduce(
    (acc, o) => ({
      input: acc.input + o.inputTokens,
      output: acc.output + o.outputTokens,
      cost: acc.cost + o.costMicroUsd,
    }),
    { input: 0, output: 0, cost: 0 },
  )
}

/**
 * Probe one model reference and persist the verdict.
 *
 * Always writes a record and always appends `probe.recorded` — a probe that
 * failed is exactly as much of a result as one that passed, and leaving no
 * trace would mean the operator re-runs it to find out what happened.
 */
export async function probe(options: ProbeOptions): Promise<ProbeResult> {
  const { store, ref, card, dataDir } = options
  const now = options.now ?? Date.now
  const fetchImpl = options.fetch ?? globalThis.fetch
  const ttlHours = options.ttlHours ?? DEFAULT_PROBE_TTL_HOURS
  const nonce = options.nonce ?? randomUUID()
  const adapter = { ...DEFAULT_ADAPTERS, ...options.adapters }[card.dialect]

  const probedAt = now()
  const startedAt = Date.now()
  const outcomes: CallOutcome[] = []

  const finish = (fields: {
    toolCalling: boolean
    modelIdSeen?: string
    finishSeen?: string
    roundTrip?: boolean
    serverVersion?: string
    reason?: string
  }): ProbeResult => {
    const totals = sum(outcomes)
    const record: ProbeRecord = {
      schemaVersion: 1,
      ref,
      probedAt,
      modelIdSeen: fields.modelIdSeen ?? card.model,
      ...(fields.serverVersion === undefined ? {} : { serverVersion: fields.serverVersion }),
      toolCalling: fields.toolCalling,
      // Phase 0 sends no forced pass, so this is never observed either way.
      toolChoiceForced: null,
      finishSeen: fields.finishSeen ?? 'none',
      roundTrip: fields.roundTrip ?? false,
      usage: { input: totals.input, output: totals.output },
      costMicroUsd: totals.cost,
      latencyMs: Math.max(0, Date.now() - startedAt),
      ttlHours,
      ...(fields.reason === undefined ? {} : { reason: fields.reason }),
    }

    const path = writeProbeRecord(dataDir, record)
    store.append({
      type: 'probe.recorded',
      payload: {
        schemaVersion: 1,
        ref,
        toolCalling: record.toolCalling,
        toolChoiceForced: null,
        latencyMs: record.latencyMs,
        ...(record.reason === undefined ? {} : { reason: record.reason }),
      },
    })
    return { record, path }
  }

  // Step 0 — ask the server before spending a token.
  const pre = await precheck(fetchImpl, ref, card)
  if (pre.refuse !== undefined) {
    return finish({
      toolCalling: false,
      reason: pre.refuse,
      ...(pre.serverVersion === undefined ? {} : { serverVersion: pre.serverVersion }),
    })
  }

  const transport = {
    store,
    scope: {},
    ref,
    card,
    ...(options.credential === undefined ? {} : { key: options.credential }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
  }

  const system =
    'You are being probed for tool-calling support. Call the probe__echo tool exactly once, ' +
    'passing back the nonce you are given. Do not call any other tool and do not call it twice.'

  // Step 1 — ask for exactly one tool call.
  let first: CallOutcome
  try {
    const prepared = adapter.prepare({
      ref,
      card,
      system,
      messages: [{ role: 'user', content: `The nonce is ${nonce}. Call probe__echo with it now.` }],
      tools: [PROBE_TOOL],
    })
    first = await withCallEvents({ ...transport, attempt: 1 }, prepared.context, prepared.perform)
  } catch (e) {
    return finish({
      toolCalling: false,
      reason: `the first probe request failed: ${e instanceof Error ? e.message : String(e)}`,
    })
  }
  outcomes.push(first)

  const seen = {
    ...(first.modelSeen === undefined ? {} : { modelIdSeen: first.modelSeen }),
    finishSeen: first.finish,
    ...(pre.serverVersion === undefined ? {} : { serverVersion: pre.serverVersion }),
  }

  // Step 2 — judge the call, strictly.
  const calls = first.toolCalls ?? []
  const errors = first.toolCallErrors ?? []

  if (calls.length === 0) {
    const named = errors.map((e) => e.name).join(', ')
    return finish({
      ...seen,
      toolCalling: false,
      reason:
        errors.length === 0
          ? 'the model made no tool call'
          : `the model made no usable tool call (rejected: ${named})`,
    })
  }
  if (calls.length + errors.length > 1) {
    // A model that cannot be asked for one call cannot be driven a turn at a
    // time, which is the only way the gate can authorise anything.
    return finish({
      ...seen,
      toolCalling: false,
      reason: `the model made ${String(calls.length + errors.length)} tool calls when asked for one`,
    })
  }

  const call = calls[0]
  if (call === undefined || call.ref !== PROBE_TOOL_REF) {
    return finish({ ...seen, toolCalling: false, reason: `the model called ${String(call?.ref)}, not ${PROBE_TOOL_REF}` })
  }

  const args = call.args
  const echoed = typeof args === 'object' && args !== null ? (args as Record<string, unknown>)['nonce'] : undefined
  if (echoed !== nonce) {
    // An echoed nonce proves the model read the request. A model that invents
    // one is producing tool-shaped text, not following the conversation.
    return finish({
      ...seen,
      toolCalling: false,
      reason: `the tool call echoed ${JSON.stringify(echoed)} instead of the nonce it was given`,
    })
  }

  // Step 3 — hand the result back and require a completion.
  try {
    const prepared = adapter.prepare({
      ref,
      card,
      system,
      messages: [
        { role: 'user', content: `The nonce is ${nonce}. Call probe__echo with it now.` },
        {
          role: 'assistant',
          content: first.content,
          toolCalls: calls,
          ...(first.raw === undefined ? {} : { raw: first.raw }),
        },
        { role: 'tool', callId: call.id, ref: PROBE_TOOL_REF, content: nonce },
      ],
      tools: [PROBE_TOOL],
    })
    const second = await withCallEvents({ ...transport, attempt: 2 }, prepared.context, prepared.perform)
    outcomes.push(second)

    if (second.finish === 'error') {
      return finish({ ...seen, toolCalling: false, reason: 'the round trip returned an error finish' })
    }

    // Step 4 — the verdict.
    return finish({ ...seen, toolCalling: true, roundTrip: true })
  } catch (e) {
    return finish({
      ...seen,
      toolCalling: false,
      reason: `the round trip failed: ${e instanceof Error ? e.message : String(e)}`,
    })
  }
}
