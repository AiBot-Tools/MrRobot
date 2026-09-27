// The history rules a real provider enforces, for the fakes that do not.
//
// The fake providers answer whatever they are sent, which is how a replay that
// real APIs reject went unnoticed: a model that named an un-offered tool with no
// text produced an assistant turn with no content and an error result answering
// a call that was not in the history. These checks are the part of the real
// server a double has to reproduce for that class of bug to show up offline.
//
// Anthropic — confirmed against the Messages API docs ("Handle tool calls",
// platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls):
//   tool results must immediately follow their tool_use blocks, answer them by
//   tool_use_id, and come FIRST in the user message's content.
// Chat Completions — the conservative reading every compatible server accepts
// (the vendor page was not reachable when this was written): a `tool` message
// answers a tool_call of the assistant message before it, with only tool
// messages between, and every tool_call is answered.
// Both: an assistant turn carries text or at least one call.

import './guard.js'

import { http, type RecordedRequest, type ScriptEntry, type ScriptedResponse } from './fake-provider.js'

type Json = Record<string, unknown>

const blocksOf = (content: unknown): Json[] =>
  Array.isArray(content) ? (content.filter((b) => typeof b === 'object' && b !== null) as Json[]) : []

/** Violations of the Anthropic Messages history rules; empty when valid. */
export function anthropicHistoryViolations(body: unknown): string[] {
  const messages = blocksOf((body as Json | undefined)?.['messages'])
  const out: string[] = []
  messages.forEach((message, i) => {
    const role = message['role']
    const content = message['content']
    if (role === 'assistant') {
      const blocks = blocksOf(content)
      if (typeof content === 'string' ? content === '' : blocks.length === 0) {
        out.push(`messages[${String(i)}]: an assistant turn with no content`)
      }
      const uses = blocks.filter((b) => b['type'] === 'tool_use').map((b) => String(b['id']))
      if (uses.length === 0) return
      const next = messages[i + 1]
      const results = next?.['role'] === 'user' ? blocksOf(next['content']) : []
      const answered = new Set(results.filter((b) => b['type'] === 'tool_result').map((b) => String(b['tool_use_id'])))
      for (const id of uses) {
        if (!answered.has(id)) out.push(`messages[${String(i)}]: tool_use ${id} has no tool_result immediately after`)
      }
      return
    }
    if (role === 'user') {
      const blocks = blocksOf(content)
      const firstNonResult = blocks.findIndex((b) => b['type'] !== 'tool_result')
      const lastResult = blocks.map((b) => b['type']).lastIndexOf('tool_result')
      if (firstNonResult !== -1 && lastResult > firstNonResult) {
        out.push(`messages[${String(i)}]: text before a tool_result`)
      }
      const prev = messages[i - 1]
      const offered = new Set(
        prev?.['role'] === 'assistant'
          ? blocksOf(prev['content']).filter((b) => b['type'] === 'tool_use').map((b) => String(b['id']))
          : [],
      )
      for (const r of blocks.filter((b) => b['type'] === 'tool_result')) {
        const id = String(r['tool_use_id'])
        if (!offered.has(id)) out.push(`messages[${String(i)}]: tool_result ${id} answers no tool_use in the turn before`)
      }
    }
  })
  return out
}

/** Violations of the Chat Completions history rules; empty when valid. */
export function chatHistoryViolations(body: unknown): string[] {
  const messages = blocksOf((body as Json | undefined)?.['messages'])
  const out: string[] = []
  let open: Set<string> | undefined
  let openAt = -1
  const close = (): void => {
    if (open !== undefined && open.size > 0) {
      out.push(`messages[${String(openAt)}]: tool_calls ${[...open].join(', ')} never answered`)
    }
    open = undefined
  }
  messages.forEach((message, i) => {
    const role = message['role']
    if (role === 'tool') {
      const id = String(message['tool_call_id'])
      if (open === undefined || !open.has(id)) {
        out.push(`messages[${String(i)}]: tool message ${id} answers no tool_call in the assistant turn before`)
      } else {
        open.delete(id)
      }
      return
    }
    close()
    if (role !== 'assistant') return
    const calls = blocksOf(message['tool_calls'])
    const text = message['content']
    if (calls.length === 0 && (text === null || text === undefined || text === '')) {
      out.push(`messages[${String(i)}]: an assistant turn with no content and no tool_calls`)
    }
    if (calls.length > 0) {
      open = new Set(calls.map((c) => String(c['id'])))
      openAt = i
    }
  })
  close()
  return out
}

/**
 * A script entry that answers like the real server would: a 400 naming the
 * violations when the history breaks the rules, the scripted reply otherwise.
 * Every rejected request is also kept, so a test can say WHAT was wrong rather
 * than only that the run failed.
 */
export function strictly(
  dialect: 'anthropic' | 'openai-chat',
  reply: ScriptedResponse,
  rejected: string[][] = [],
): ScriptEntry {
  return (request: RecordedRequest) => {
    const violations =
      dialect === 'anthropic' ? anthropicHistoryViolations(request.body) : chatHistoryViolations(request.body)
    if (violations.length === 0) return reply
    rejected.push(violations)
    return http(400, { type: 'error', error: { type: 'invalid_request_error', message: violations.join('; ') } })
  }
}
