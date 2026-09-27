// The mutation catalog: the bugs each suite has been shown to catch.
//
// Every entry was a real falsifier pass when its feature landed — each one was
// seen killed, and the ones that first SURVIVED are why some of these tests
// exist at all (D13, D15, W1, W3). Keeping them as data means the next change
// to delegation, recovery or replay can prove the suite still bites without
// anyone rebuilding the mutants from memory.
//
// Anchors are exact text and must match exactly once; test/falsify.test.ts
// checks that on every `npm test`, so a refactor that moves an anchor fails the
// suite rather than silently turning its mutant into a no-op.
//
// To add one: the smallest edit that reintroduces a specific bug, the tests
// that should catch it, and one line saying what the bug is.

import type { Suite } from './runner.js'

const DELEGATE = 'src/runtime/delegate.ts'
const KERNEL = 'src/kernel.ts'
const PROJECTIONS = 'src/events/projections.ts'
const TRANSPORT = 'src/models/transport.ts'
const CHAT = 'src/models/openai-chat.ts'

const delegation: Suite = {
  name: 'delegation',
  tests: [
    'test/delegation.test.ts',
    'test/delegation-unit.test.ts',
    'test/kernel-tools.test.ts',
    'test/runtime-loop.test.ts',
    'test/eval-checks.test.ts',
  ],
  mutants: [
    { id: 'D1', file: DELEGATE, from: '    if (state.children.has(taskId)) {', to: '    if (false) {', why: 'a task can be delegated twice in one run' },
    { id: 'D2', file: DELEGATE, from: "      if (done?.status !== 'ok') {", to: '      if (false) {', why: 'dependsOn is ignored' },
    { id: 'D3', file: DELEGATE, from: '    if (state.children.size >= maxChildren) {', to: '    if (false) {', why: 'spawn.maxChildren is ignored' },
    { id: 'D4', file: DELEGATE, from: '    if (this.#childRuns.has(runId)) {', to: '    if (false) {', why: 'a child may delegate: depth is unbounded' },
    { id: 'D5', file: DELEGATE, from: '    if (target.manifest.tier > agent.tier) {', to: '    if (false) {', why: 'a child may run above its parent’s tier' },
    { id: 'D6', file: DELEGATE, from: "    budget.charge('cost', outcome.costMicroUsd)", to: '    void budget', why: 'a child’s spend is not charged to the parent' },
    { id: 'D7', file: DELEGATE, from: "      taints: outcome.taint === 'tainted',", to: '      taints: false,', why: 'a tainted child does not taint the parent' },
    { id: 'D8', file: DELEGATE, from: "    ctx.signal?.addEventListener('abort', onAbort, { once: true })", to: '    void onAbort', why: 'killing the parent leaves the child running' },
    { id: 'D9', file: DELEGATE, from: '      ceiling: { usdMax: ceilingMicroUsd, wallclockMs: ceilingWallclockMs },', to: '      ceiling: {},', why: 'no ceiling is handed to the child' },
    { id: 'D10', file: DELEGATE, from: '    if (adopted === undefined) {', to: '    if (false) {', why: 'delegate works with no adopted plan' },
    { id: 'D11', file: 'src/runtime/loop.ts', from: "      agent.role === 'orchestrator' && this.#o.kernelTools !== undefined", to: '      this.#o.kernelTools !== undefined', why: 'a worker is offered kernel tools' },
    { id: 'D12', file: 'src/agents/registry.ts', from: "      if (serverId === KERNEL_SERVER && manifest.role !== 'orchestrator') {", to: '      if (false) {', why: 'the registry loads a worker manifest holding a kernel tool' },
    { id: 'D13', file: KERNEL, from: '            usdMax: Math.min(caps.usdMax, ceiling?.usdMax ?? caps.usdMax),', to: '            usdMax: caps.usdMax,', why: 'the kernel ignores the cost ceiling it hands a child' },
    { id: 'D14', file: 'src/eval/checks.ts', from: '    const summed = own + delegated', to: '    const summed = own', why: 'the eval’s cost check ignores delegated spend' },
    { id: 'D15', file: 'src/runtime/kernel-tools.ts', from: '    PolicyEngine.assertTicketMatches(ticket, ref, args)', to: '    void PolicyEngine', why: 'the kernel tool runner skips the ticket check' },
    { id: 'W1', file: KERNEL, from: '            wallclockMs: Math.min(caps.wallclockMs, ceiling?.wallclockMs ?? caps.wallclockMs),', to: '            wallclockMs: caps.wallclockMs,', why: 'the kernel ignores the wallclock ceiling' },
    { id: 'W2', file: DELEGATE, from: '      ceiling: { usdMax: ceilingMicroUsd, wallclockMs: ceilingWallclockMs },', to: '      ceiling: { usdMax: ceilingMicroUsd },', why: 'delegate hands down no wallclock' },
    { id: 'W3', file: DELEGATE, from: '    const ceilingWallclockMs = budget.remainingMs()', to: '    const ceilingWallclockMs = budget.caps.wallclockMs', why: 'the slice is the parent’s whole cap, not what it has left' },
  ],
  control: {
    id: 'C',
    file: DELEGATE,
    from: '// Delegation: an orchestrator adopts a plan',
    to: '// Delegation (control, unchanged behaviour): an orchestrator adopts a plan',
    why: 'comment only',
  },
}

const recovery: Suite = {
  name: 'recovery',
  tests: ['test/projections.test.ts', 'test/delegation-restart.test.ts'],
  mutants: [
    { id: 'P1', file: PROJECTIONS, from: "        if (run !== undefined) run.costMicroUsd += numberAt(payload, 'costMicroUsd')", to: '        void run', why: 'an orphaned parent’s bill omits children it already paid for' },
    { id: 'P2', file: PROJECTIONS, from: '    if (parent !== undefined) parent.costMicroUsd += costMicroUsd', to: '    void parent', why: 'an orphaned parent’s bill omits the child in flight' },
    { id: 'P3', file: PROJECTIONS, from: "      status: done === undefined ? 'error' : resultStatus(done.status),", to: "      status: 'error',", why: 'a child that finished is recorded as error' },
    { id: 'P4', file: PROJECTIONS, from: "        startedTainted.has(childRunId) || touchedUntrusted.has(childRunId) ? 'tainted' : 'clean',", to: "        'clean',", why: 'a recovered result claims clean without proof' },
    { id: 'P5', file: PROJECTIONS, from: '        if (row.runId !== null) touchedUntrusted.add(row.runId)\n        holds.delete', to: '        holds.delete', why: 'a released hold does not count against clean' },
    { id: 'P6', file: PROJECTIONS, from: "        if (stringAt(payload, 'taint') !== 'clean') startedTainted.add(runId)", to: '', why: 'a child that started tainted is recovered clean' },
    { id: 'P7', file: PROJECTIONS, from: "        admitted.delete(stringAt(payload, 'childRunId'))", to: '', why: 'a result does not close its admission, so recovery repeats' },
    { id: 'P8', file: PROJECTIONS, from: '    const costMicroUsd = done?.costMicroUsd ?? orphan?.costMicroUsd ?? 0', to: '    const costMicroUsd = orphan?.costMicroUsd ?? 0', why: 'a finished child’s cost is lost' },
    { id: 'K1', file: KERNEL, from: '    for (const d of recovered.danglingDelegations) {', to: '    for (const d of recovered.danglingDelegations.slice(0, 0)) {', why: 'boot writes no result for a dangling admission' },
    { id: 'K2', file: KERNEL, from: '    for (const run of recovered.orphanRuns) if (childIds.has(run.runId)) closeOrphan(run)', to: '    for (const run of recovered.orphanRuns) closeOrphan(run)\n    childIds.clear()', why: 'parents are closed before their children’s results' },
    { id: 'K3', file: KERNEL, from: '          status: d.status,', to: "          status: 'ok' as const,", why: 'a recovered result guesses ok' },
    { id: 'K4', file: KERNEL, from: '          taint: d.taint,', to: "          taint: 'tainted' as const,", why: 'a recovered result ignores what the log proves about taint' },
  ],
  control: {
    id: 'C',
    file: PROJECTIONS,
    from: '// Crash recovery, projected from the log.',
    to: '// Crash recovery, projected from the log. (control)',
    why: 'comment only',
  },
}

const replay: Suite = {
  name: 'replay',
  tests: [
    'test/wire-replay.test.ts',
    'test/runtime-loop.test.ts',
    'test/models-openai-chat.test.ts',
    'test/models-anthropic.test.ts',
  ],
  mutants: [
    { id: 'R1', file: 'src/runtime/loop.ts', from: '          ...(callErrors.length === 0 ? {} : { rejectedCalls: callErrors }),', to: '', why: 'the loop drops rejected calls from the replay (the original bug)' },
    { id: 'R2', file: 'src/models/anthropic.ts', from: '    for (const call of message.rejectedCalls ?? []) {', to: '    for (const call of [] as NonNullable<typeof message.rejectedCalls>) {', why: 'the Anthropic encoder skips rejected calls' },
    { id: 'R3', file: CHAT, from: '      ...(message.rejectedCalls ?? []).map((call) => ({', to: '      ...([] as NonNullable<typeof message.rejectedCalls>).map((call) => ({', why: 'the Chat encoder skips rejected calls' },
    { id: 'R4', file: TRANSPORT, from: "  return typeof rawArgs === 'string' ? rawArgs : JSON.stringify(rawArgs ?? {})", to: '  return JSON.stringify(rawArgs ?? {})', why: 'raw arguments are re-quoted instead of replayed verbatim' },
    { id: 'R5', file: TRANSPORT, from: '  if (PROVIDER_TOOL_NAME.test(name)) return name', to: '  if (PROVIDER_TOOL_NAME.test(name) || name !== "") return name', why: 'a name one dialect allows is replayed unsanitised to the other' },
    { id: 'R6', file: TRANSPORT, from: '  const direct = asObject(rawArgs)', to: "  if (typeof rawArgs === 'string') return rawArgs as unknown as Record<string, unknown>\n  const direct = asObject(rawArgs)", why: 'string arguments reach a dialect that needs an object' },
    { id: 'R7', file: CHAT, from: '              rawArgs: call.function.arguments,\n            })\n            continue\n          }\n\n          toolCalls.push', to: '              rawArgs: call.function.arguments,\n            })\n            toolCalls.push({ id: call.id, ref: dotted, args: {} })\n            toolCallErrors.pop()\n            continue\n          }\n\n          toolCalls.push', why: 'a call with unparseable arguments becomes executable' },
  ],
  control: {
    id: 'C',
    file: TRANSPORT,
    from: "/** A rejected call's arguments as a string, for a dialect that sends one. */",
    to: "/** A rejected call's arguments as a string, for a dialect that sends one (control). */",
    why: 'comment only',
  },
}

export const CATALOG: readonly Suite[] = [delegation, recovery, replay]
