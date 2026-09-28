// A rejected tool call, replayed to the Anthropic Messages API — one body, two
// targets.
//
// When a model calls a tool the kernel will not execute, the loop replays that
// call as a tool_use block and answers it with an is_error tool_result (see
// src/runtime/loop.ts and test/wire-replay.test.ts). The Messages API docs
// confirm the pairing rules; they do NOT say whether the API accepts, in
// history, a tool_use whose name is not in the request's `tools` — or a
// tool_use at all when the request carries no `tools` field, which is exactly
// what a worker offered nothing (the shipped writer) sends. Only the real API
// can answer that, so this body is run:
//
//   test/wire-replay.test.ts     every `npm test`, against the strict fake.
//                                Proves the assertions and the request shapes.
//   test/live-anthropic.test.ts  gated, against api.anthropic.com. Settles the
//                                question. A 400 here is a kernel bug to fix,
//                                not a flaky test.

import './guard.js'

import assert from 'node:assert/strict'

import type { EventStore } from '../../src/events/store.js'
import type { Router, RouteRequest } from '../../src/models/router.js'

export interface ReplayTarget {
  readonly router: Router
  readonly store: EventStore
  readonly ref: string
}

/** The two request shapes, named for what they settle. */
export const REPLAY_CASES = ['name-not-in-tools', 'no-tools-field'] as const
export type ReplayCase = (typeof REPLAY_CASES)[number]

/** The history the loop builds after a model's only output was a rejected call. */
export function replayRequest(shape: ReplayCase): RouteRequest {
  const id = `toolu_replay_${shape.replace(/-/g, '_')}`
  const reason = 'the model named a tool that was not offered on this call'
  return {
    system: 'You are a test fixture. Answer in one short sentence and call no tools.',
    tools:
      shape === 'name-not-in-tools'
        ? [
            {
              ref: 'kernel.echo',
              description: 'Echo a string back. Offered so the request has a tools field.',
              inputSchema: { type: 'object', properties: { text: { type: 'string' } } },
            },
          ]
        : [],
    messages: [
      { role: 'user', content: 'Look something up for me, then reply with the word ok.' },
      {
        role: 'assistant',
        content: '',
        rejectedCalls: [{ id, name: 'web__search', reason, rawArgs: { query: 'anything' } }],
      },
      { role: 'tool', callId: id, ref: 'web__search', content: `[error] ${reason}`, isError: true },
    ],
  }
}

/**
 * Send each shape once. The API accepting the history is the claim; the model's
 * words are not asserted, only that a real, billed answer came back and that
 * the kernel logged it as it logs every call.
 */
export async function rejectedCallReplays(target: ReplayTarget): Promise<void> {
  for (const shape of REPLAY_CASES) {
    const runId = `run_replay_${shape.replace(/-/g, '_')}`
    // A 400 surfaces here as a thrown ProviderError whose message is the API's
    // own — which is the diagnosis, so it is not caught.
    const result = await target.router.call({
      binding: { primary: target.ref, fallbacks: [] },
      request: replayRequest(shape),
      scope: { runId, agentId: 'writer' },
      remainingMicroUsd: 1_000_000,
    })

    assert.equal(typeof result.outcome.content, 'string', `${shape}: no answer`)
    assert.ok(result.outcome.costMicroUsd > 0, `${shape}: the call cost nothing, so it never reached a provider`)
    // Invariant 4 holds on this path too: one request event, one response event.
    const logged = target.store.query({ runId }).map((r) => r.type)
    assert.deepEqual(logged, ['llm.request', 'llm.response'], `${shape}: ${logged.join(', ')}`)
  }
}
