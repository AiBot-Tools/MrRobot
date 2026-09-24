// Anthropic Messages adapter.
//
// Credentials are the whole reason this file is shaped the way it is.
//
// The pinned SDK (0.127.0) substitutes an environment variable per credential
// field, and ONLY when that field is `undefined` (client.mjs l.70, 76-81):
//
//   if (apiKey === undefined)    apiKey    = readEnv('ANTHROPIC_API_KEY')    ?? null
//   if (authToken === undefined) authToken = readEnv('ANTHROPIC_AUTH_TOKEN') ?? null
//
// and `authHeaders()` returns `buildHeaders([apiKeyAuth, bearerAuth])`
// (l.363) — BOTH headers go on the wire when both fields are non-null. So
// spreading only the field we mean to set would leave the other `undefined`,
// let a stray or poisoned env var fill it in, and send a second, unintended
// credential on every request. Every credential field is therefore passed
// explicitly, the unused ones as `null`.
//
// The same `null` does one more thing: the SDK falls back to an OAuth
// profile, stored credentials or a config file only when apiKey AND authToken
// are both null (l.147). One non-null field means no profile on this machine
// can ever authenticate a kernel request.
//
// `baseURL` is passed for the same reason — it defaults from
// ANTHROPIC_BASE_URL (l.70), so leaving it out would let an environment
// variable redirect every model call to a host nobody configured.
//
// `maxRetries: 0` because the router owns retries. An SDK retry would be a
// provider call with no llm.request/llm.response pair, which is invariant 4
// broken silently — a spend the log cannot account for.
//
// Sampling parameters are never sent: the card's caps say `sampling: none`
// for every Anthropic entry, and the current models reject temperature /
// top_p / top_k outright. `tool_choice` is `auto` and nothing else, for the
// same reason plus a kernel one — a forced tool call is the model being told
// what to do by us rather than deciding, and the gate, not the router, is
// where tool authority lives.

import Anthropic, { APIError } from '@anthropic-ai/sdk'

import { ConfigError } from '../errors.js'
import { toolName } from '../mcp/names.js'
import { costForCard } from './cost.js'
import { classifyProviderFailure, ProviderError } from './router.js'
import { normaliseAnthropicUsage } from './usage.js'
import type {
  AdapterRequest,
  CallOutcome,
  ModelAdapter,
  PreparedCall,
  ToolCall,
  ToolCallError,
  TurnMessage,
} from './transport.js'

/** Parameters that must never reach an Anthropic request body. */
export const FORBIDDEN_PARAMS = ['temperature', 'top_p', 'top_k'] as const

type Params = Anthropic.MessageCreateParamsNonStreaming

/** Outgoing name for a ref. Pure mapping, so a replayed call maps too. */
function nameOf(ref: string): string {
  return toolName(ref)
}

/**
 * Translate kernel turns into Anthropic messages.
 *
 * Consecutive tool results collapse into ONE user message. The API models a
 * turn's results as a single user message, and splitting them teaches the
 * model to stop making parallel calls — a behaviour change that would show up
 * much later as "the agent got slower" with no obvious cause.
 */
function toMessages(
  messages: readonly TurnMessage[],
  preserveAssistantMessage: boolean,
): Anthropic.MessageParam[] {
  const out: Anthropic.MessageParam[] = []
  let pending: Anthropic.ToolResultBlockParam[] = []

  const flush = (): void => {
    if (pending.length === 0) return
    out.push({ role: 'user', content: pending })
    pending = []
  }

  for (const message of messages) {
    if (message.role === 'tool') {
      pending.push({
        type: 'tool_result',
        tool_use_id: message.callId,
        content: message.content,
        ...(message.isError === true ? { is_error: true } : {}),
      })
      continue
    }

    flush()

    if (message.role === 'user') {
      out.push({ role: 'user', content: message.content })
      continue
    }

    // A provider's own assistant message replayed untouched. Reconstructing
    // one loses fields the server may require back verbatim.
    if (preserveAssistantMessage && message.raw !== undefined) {
      out.push({ role: 'assistant', content: message.raw as Anthropic.ContentBlockParam[] })
      continue
    }

    const blocks: Anthropic.ContentBlockParam[] = []
    if (message.content !== '') blocks.push({ type: 'text', text: message.content })
    for (const call of message.toolCalls ?? []) {
      blocks.push({ type: 'tool_use', id: call.id, name: nameOf(call.ref), input: call.args })
    }
    if (blocks.length === 0) {
      throw new ConfigError('an assistant turn must carry text or at least one tool call')
    }
    out.push({ role: 'assistant', content: blocks })
  }

  flush()
  return out
}

/** Map an SDK failure onto the router's error classes. */
function toProviderError(ref: string, e: unknown): ProviderError {
  if (e instanceof ProviderError) return e

  const status = e instanceof APIError ? e.status : undefined
  const message = e instanceof Error ? e.message : String(e)

  let retryAfterMs: number | undefined
  if (e instanceof APIError && e.headers !== undefined) {
    const header = e.headers.get('retry-after')
    const seconds = header === null ? Number.NaN : Number(header)
    if (Number.isFinite(seconds) && seconds >= 0) retryAfterMs = Math.ceil(seconds * 1_000)
  }

  return new ProviderError(ref, classifyProviderFailure(status, message), message, {
    ...(status === undefined ? {} : { status }),
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    cause: e,
  })
}

export class AnthropicAdapter implements ModelAdapter {
  readonly dialect = 'anthropic' as const

  prepare(request: AdapterRequest): PreparedCall {
    const { card, ref } = request

    const maxTokens = request.maxOutputTokens ?? card.limits?.maxOutputTokens
    if (maxTokens === undefined) {
      throw new ConfigError(
        `${ref}: max_tokens is required by the Messages API and neither the request nor ` +
          'the card’s limits.maxOutputTokens supplies one',
      )
    }

    // Offered names, so an inbound tool_use can be mapped back to a dotted ref
    // (invariant 10) and a name we never offered is refused rather than run.
    const offered = new Map(request.tools.map((t) => [nameOf(t.ref), t.ref]))

    const tools: Anthropic.Tool[] = request.tools.map((t) => ({
      name: nameOf(t.ref),
      description: t.description,
      input_schema: t.inputSchema as Anthropic.Tool.InputSchema,
    }))

    const params: Params = {
      model: card.model,
      max_tokens: maxTokens,
      system: request.system,
      messages: toMessages(request.messages, card.caps.preserveAssistantMessage),
      ...(tools.length === 0 ? {} : { tools, tool_choice: { type: 'auto' } }),
    }

    // Structural, not aspirational: if a future edit adds a sampling knob the
    // request never leaves this function.
    for (const key of FORBIDDEN_PARAMS) {
      if (key in params) {
        throw new ConfigError(`${ref}: ${key} must never be sent to an Anthropic model`)
      }
    }

    return {
      context: {
        prompt: JSON.stringify(params),
        tools: request.tools.map((t) => t.ref),
        maxOutputTokens: maxTokens,
      },

      async perform(fetchImpl, credential): Promise<CallOutcome> {
        if (credential === undefined) {
          throw new ConfigError(`${ref}: an Anthropic entry needs a credential`)
        }

        const usesApiKey = card.auth.header === 'x-api-key'
        const client = new Anthropic({
          fetch: fetchImpl,
          maxRetries: 0,
          baseURL: card.baseUrl,
          // Every credential field explicit. See this file's header.
          apiKey: usesApiKey ? credential : null,
          authToken: usesApiKey ? null : credential,
          webhookKey: null,
          defaultHeaders: { ...card.headers },
        })

        let message: Anthropic.Message
        try {
          message = await client.messages.create(params)
        } catch (e) {
          throw toProviderError(ref, e)
        }

        const texts: string[] = []
        const toolCalls: ToolCall[] = []
        const toolCallErrors: ToolCallError[] = []

        for (const block of message.content) {
          if (block.type === 'text') {
            texts.push(block.text)
          } else if (block.type === 'tool_use') {
            const dotted = offered.get(block.name)
            if (dotted === undefined) {
              // Data, not an exception: the model is told it named a tool that
              // was not on offer. It must never become an executable call.
              toolCallErrors.push({
                id: block.id,
                name: block.name,
                reason: 'the model named a tool that was not offered on this call',
              })
              continue
            }
            toolCalls.push({ id: block.id, ref: dotted, args: block.input })
          }
        }

        const usage = normaliseAnthropicUsage(message.usage)
        const { costMicroUsd } = costForCard(usage, card)

        return {
          content: texts.join(''),
          // Verbatim. Mapping onto a closed set would silently swallow a
          // stop_reason the API adds later.
          finish: message.stop_reason ?? 'unknown',
          inputTokens: usage.inputTokens,
          outputTokens: usage.outputTokens,
          cacheReadTokens: usage.cacheReadTokens,
          cacheWriteTokens: usage.cacheWrite5mTokens + usage.cacheWrite1hTokens,
          costMicroUsd,
          modelSeen: message.model,
          ...(toolCalls.length === 0 ? {} : { toolCalls }),
          ...(toolCallErrors.length === 0 ? {} : { toolCallErrors }),
          raw: message.content,
        }
      },
    }
  }
}
