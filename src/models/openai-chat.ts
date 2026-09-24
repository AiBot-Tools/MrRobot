// OpenAI-compatible Chat Completions adapter (raw fetch).
//
// The endpoints this speaks to are not OpenAI. They are llama.cpp, Ollama,
// OpenRouter and Moonshot, each implementing a subset of the same shape, and
// the failure mode that matters is a field one of them does not know: llama.cpp
// rejects `best_of` and `suffix` outright. That is why the `openai` SDK is not
// installed (D6) — it is Responses-first and emits fields these servers throw
// on — and why every optional field below is omitted rather than sent with a
// default. The body carries what the call needs and nothing else.
//
// Three shapes of this dialect are genuinely different from Anthropic's, and
// each one is a bug if copied across:
//
//   `function.arguments` is a JSON STRING, not an object, and the providers
//   document that models do not always produce valid JSON. A parse failure is
//   therefore expected traffic, not an exception: it becomes a ToolCallError
//   the model is told about, never a crash and never an executable call.
//
//   Cached tokens are reported INSIDE `prompt_tokens` and broken out under
//   `prompt_tokens_details.cached_tokens`, the mirror image of Anthropic where
//   they sit beside it. `normaliseChatUsage` owns that arithmetic.
//
//   Tool results are one `role: 'tool'` message EACH. Grouping them the way
//   the Anthropic adapter must would be malformed here.
//
// `max_tokens` rather than `max_completion_tokens`: every server in the target
// set accepts the former, and OpenAI proper is not among them. Revisit only if
// a card ever points at api.openai.com.

import { z } from 'zod'

import { ConfigError } from '../errors.js'
import { toolName } from '../mcp/names.js'
import { costForCard } from './cost.js'
import { classifyProviderFailure, ProviderError } from './router.js'
import { normaliseChatUsage } from './usage.js'
import type {
  AdapterRequest,
  CallOutcome,
  ModelAdapter,
  PreparedCall,
  ToolCall,
  ToolCallError,
  TurnMessage,
} from './transport.js'

/** Parameters that must never reach a request body in Phase 0. */
export const FORBIDDEN_PARAMS = ['temperature', 'top_p', 'top_k', 'best_of', 'suffix'] as const

/** The only three `tool_choice` values this phase will send. */
export const TOOL_CHOICE_VALUES = ['auto', 'none', 'required'] as const
export type ToolChoiceValue = (typeof TOOL_CHOICE_VALUES)[number]

// ── response schema ────────────────────────────────────────────────────────
//
// zod at the boundary (CLAUDE.md). `.loose()` throughout: a compat server adds
// fields freely, and dropping them would break `preserveAssistantMessage`
// replay. The raw JSON, not this parse, is what gets replayed.

const ChatToolCall = z
  .object({
    id: z.string(),
    type: z.string().optional(),
    function: z.object({ name: z.string(), arguments: z.string() }).loose(),
  })
  .loose()

const ChatMessage = z
  .object({
    role: z.string().optional(),
    content: z.string().nullish(),
    tool_calls: z.array(ChatToolCall).nullish(),
  })
  .loose()

const ChatChoice = z
  .object({ index: z.number().optional(), message: ChatMessage, finish_reason: z.string().nullish() })
  .loose()

const ChatCompletion = z
  .object({ choices: z.array(ChatChoice).min(1), usage: z.unknown().optional() })
  .loose()

// ── request building ───────────────────────────────────────────────────────

/**
 * What to send as `tool_choice`, or undefined to omit the field.
 *
 * `none` means the endpoint rejects the field, so it is left out entirely
 * rather than sent as the string "none" — the two are not the same thing to a
 * server that does not know the parameter.
 *
 * `forced` is downgraded to `auto`. A named tool choice is the kernel telling
 * the model which tool to call, and in Phase 0 nothing forces a call: the
 * probe sends none and the gate, not the router, is where tool authority
 * lives. The capability stays recorded on the card for the Phase 1 forced
 * pass.
 */
export function toolChoiceFor(
  caps: AdapterRequest['card']['caps'],
  toolCount: number,
): ToolChoiceValue | undefined {
  if (toolCount === 0) return undefined
  if (caps.toolChoice === 'none') return undefined
  if (caps.toolChoice === 'forced') return 'auto'
  return caps.toolChoice
}

interface WireToolCall {
  readonly id: string
  readonly type: 'function'
  readonly function: { readonly name: string; readonly arguments: string }
}

interface WireMessage {
  readonly role: string
  readonly content?: string | null
  readonly tool_calls?: readonly WireToolCall[]
  readonly tool_call_id?: string
}

/**
 * Translate kernel turns into chat messages.
 *
 * Unlike the Anthropic dialect, each tool result is its own message. The
 * system prompt is a message here too, not a separate top-level field.
 */
function toMessages(
  system: string,
  messages: readonly TurnMessage[],
  preserveAssistantMessage: boolean,
): unknown[] {
  const out: unknown[] = []
  if (system !== '') out.push({ role: 'system', content: system })

  for (const message of messages) {
    if (message.role === 'user') {
      out.push({ role: 'user', content: message.content } satisfies WireMessage)
      continue
    }

    if (message.role === 'tool') {
      // The dialect has no is_error flag; the failure is described by the
      // content the caller already wrote.
      out.push({
        role: 'tool',
        tool_call_id: message.callId,
        content: message.content,
      } satisfies WireMessage)
      continue
    }

    // A server that returns reasoning traces (llama.cpp's reasoning_content,
    // and the R1-family servers behind it) requires them back untouched. A
    // reconstructed message drops them and the next turn is rejected or, worse,
    // silently reasons from nothing.
    if (preserveAssistantMessage && message.raw !== undefined) {
      out.push(message.raw)
      continue
    }

    const calls = message.toolCalls ?? []
    out.push({
      role: 'assistant',
      content: message.content === '' ? null : message.content,
      ...(calls.length === 0
        ? {}
        : {
            tool_calls: calls.map((call) => ({
              id: call.id,
              type: 'function' as const,
              function: { name: toolName(call.ref), arguments: JSON.stringify(call.args ?? {}) },
            })),
          }),
    } satisfies WireMessage)
  }

  return out
}

function toProviderError(ref: string, status: number | undefined, message: string, cause?: unknown): ProviderError {
  return new ProviderError(ref, classifyProviderFailure(status, message), message, {
    ...(status === undefined ? {} : { status }),
    ...(cause === undefined ? {} : { cause }),
  })
}

export class OpenAiChatAdapter implements ModelAdapter {
  readonly dialect = 'openai-chat' as const

  prepare(request: AdapterRequest): PreparedCall {
    const { card, ref } = request

    const maxTokens = request.maxOutputTokens ?? card.limits?.maxOutputTokens
    if (maxTokens === undefined) {
      throw new ConfigError(
        `${ref}: a generation must be bounded and neither the request nor the card’s ` +
          'limits.maxOutputTokens supplies a max_tokens',
      )
    }

    // Offered names, so an inbound tool call maps back to a dotted ref
    // (invariant 10) and a name we never offered cannot be run.
    const offered = new Map(request.tools.map((t) => [toolName(t.ref), t.ref]))

    const tools = request.tools.map((t) => ({
      type: 'function' as const,
      function: {
        name: toolName(t.ref),
        description: t.description,
        parameters: t.inputSchema,
        // Only when the endpoint advertises it: an unknown field is what
        // llama.cpp throws on.
        ...(card.caps.strictSchema === true ? { strict: true } : {}),
      },
    }))

    const choice = toolChoiceFor(card.caps, tools.length)

    const body: Record<string, unknown> = {
      model: card.model,
      messages: toMessages(request.system, request.messages, card.caps.preserveAssistantMessage),
      max_tokens: maxTokens,
      ...(tools.length === 0 ? {} : { tools }),
      ...(choice === undefined ? {} : { tool_choice: choice }),
      // Sent only to turn parallel calls OFF. `true` is the default
      // everywhere, so sending it is a field for a server to reject.
      ...(card.caps.parallelToolCalls === false ? { parallel_tool_calls: false } : {}),
    }

    // Structural, not aspirational: a future edit that adds a sampling knob or
    // a field the target servers throw on never leaves this function.
    for (const key of FORBIDDEN_PARAMS) {
      if (key in body) throw new ConfigError(`${ref}: ${key} must never be sent to a compat endpoint`)
    }
    if (choice !== undefined && !TOOL_CHOICE_VALUES.includes(choice)) {
      throw new ConfigError(`${ref}: tool_choice must be one of ${TOOL_CHOICE_VALUES.join(', ')}`)
    }

    const url = `${card.baseUrl}${card.path}`

    return {
      context: {
        prompt: JSON.stringify(body),
        tools: request.tools.map((t) => t.ref),
        maxOutputTokens: maxTokens,
      },

      async perform(fetchImpl): Promise<CallOutcome> {
        // No credential here by construction: the transport owns the auth
        // header (invariant 2), so this adapter cannot leak what it never has.
        const response = await fetchImpl(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        })

        const text = await response.text()

        if (!response.ok) {
          const header = response.headers.get('retry-after')
          const seconds = header === null ? Number.NaN : Number(header)
          const error = toProviderError(ref, response.status, `HTTP ${String(response.status)}: ${text.slice(0, 500)}`)
          if (!Number.isFinite(seconds) || seconds < 0) throw error
          throw new ProviderError(ref, error.kind, error.message, {
            status: response.status,
            retryAfterMs: Math.ceil(seconds * 1_000),
          })
        }

        let json: unknown
        try {
          json = JSON.parse(text)
        } catch (e) {
          // A 200 whose body does not parse is a truncated transfer: the
          // request was accepted, so it is worth one more attempt.
          throw new ProviderError(ref, 'retryable', 'the response body is not valid JSON', { cause: e })
        }

        const parsed = ChatCompletion.safeParse(json)
        if (!parsed.success) {
          // Valid JSON of the wrong shape means this is not a Chat Completions
          // endpoint. Retrying cannot fix a misconfigured baseUrl or path.
          throw toProviderError(
            ref,
            undefined,
            `the response is not a Chat Completions body: ${parsed.error.message}`,
          )
        }

        const choiceOut = parsed.data.choices[0]
        if (choiceOut === undefined) {
          throw toProviderError(ref, undefined, 'the response carried no choices')
        }

        const toolCalls: ToolCall[] = []
        const toolCallErrors: ToolCallError[] = []

        for (const call of choiceOut.message.tool_calls ?? []) {
          const dotted = offered.get(call.function.name)
          if (dotted === undefined) {
            toolCallErrors.push({
              id: call.id,
              name: call.function.name,
              reason: 'the model named a tool that was not offered on this call',
            })
            continue
          }

          // Documented as not always valid. Expected traffic, not a crash.
          let args: unknown
          try {
            args = JSON.parse(call.function.arguments)
          } catch (e) {
            toolCallErrors.push({
              id: call.id,
              name: call.function.name,
              reason: `arguments are not valid JSON: ${e instanceof Error ? e.message : String(e)}`,
            })
            continue
          }

          toolCalls.push({ id: call.id, ref: dotted, args })
        }

        const usage = normaliseChatUsage(parsed.data.usage ?? {})
        const { costMicroUsd } = costForCard(usage, card)

        // The RAW message, not the zod output: replay must be byte-faithful,
        // including fields this schema never named.
        const raw = (json as { choices?: { message?: unknown }[] }).choices?.[0]?.message

        return {
          content: choiceOut.message.content ?? '',
          // Verbatim: compat servers invent their own finish reasons.
          finish: choiceOut.finish_reason ?? 'unknown',
          inputTokens: usage.inputTokens,
          outputTokens: usage.outputTokens,
          cacheReadTokens: usage.cacheReadTokens,
          costMicroUsd,
          ...(toolCalls.length === 0 ? {} : { toolCalls }),
          ...(toolCallErrors.length === 0 ? {} : { toolCallErrors }),
          ...(raw === undefined ? {} : { raw }),
        }
      },
    }
  }
}
