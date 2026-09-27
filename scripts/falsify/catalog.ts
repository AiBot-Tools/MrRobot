// The mutation catalog: the bugs each suite has been shown to catch.
//
// Every entry was a real falsifier pass when its feature landed — each one was
// seen killed, and the ones that first SURVIVED are why some of these tests
// exist at all (D13, D15, W1, W3). Keeping them as data means the next change
// to any of these areas can prove the suite still bites without anyone
// rebuilding the mutants from memory.
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

const GATE = 'src/policy/gate.ts'
const TRACKER = 'src/goals/tracker.ts'
const WRITER = 'src/goals/writer.ts'
const STORE = 'src/events/store.ts'
const CHECKS = 'src/eval/checks.ts'

const namespace: Suite = {
  name: 'namespace',
  tests: [
    'test/policy-namespace.test.ts',
    'test/mcp-tool-views.test.ts',
    'test/runtime-loop.test.ts',
    'test/goals-tracker.test.ts',
  ],
  mutants: [
    { id: 'N1', file: GATE, from: "  if (pinned !== undefined && pinned !== 'none') {", to: '  if (false) {', why: 'the gate does not pin memory namespaces at all' },
    { id: 'N2', file: GATE, from: '    if (scope.projectId === undefined) {', to: '    if (false) {', why: 'an agent with no namespace may call a namespaced tool' },
    { id: 'N3', file: GATE, from: '    if (asked !== scope.projectId) {', to: "    if (typeof asked === 'string' && asked !== scope.projectId) {", why: 'an absent namespace argument lets the server default it' },
    { id: 'N4', file: 'src/mcp/tool-views.ts', from: '          view.namespaceArg === undefined\n', to: '          false\n', why: 'an exposed pmmcp tool loads without a namespace decision' },
    { id: 'N5', file: 'src/runtime/loop.ts', from: '        ...(view.namespaceArg === undefined ? {} : { namespaceArg: view.namespaceArg }),', to: '', why: 'the loop never tells the gate which argument to pin' },
    { id: 'N6', file: KERNEL, from: '      projectId: m.memory.projectId,', to: "      projectId: 'aos/ceo',", why: 'the kernel gives every agent the CEO’s namespace' },
    { id: 'N7', file: TRACKER, from: '    return this.#namespaceOf.get(goalId) ?? this.#o.projectIdOf(agentId)', to: '    return this.#o.projectIdOf(agentId)', why: 'a child’s goal is moved in the child’s namespace, not where it was written' },
  ],
  control: {
    id: 'C',
    file: GATE,
    from: '// The policy gate (invariant 3).',
    to: '// The policy gate (invariant 3). (control)',
    why: 'comment only',
  },
}

const goals: Suite = {
  name: 'goals',
  tests: [
    'test/goals-writer.test.ts',
    'test/goals-tracker.test.ts',
    'test/goals-plan.test.ts',
    'test/delegation.test.ts',
    'test/delegation-restart.test.ts',
  ],
  mutants: [
    { id: 'G1', file: WRITER, from: '    if (!(KERNEL_SETTABLE as readonly string[]).includes(to)) {', to: '    if (false) {', why: 'the kernel may mark a goal done' },
    { id: 'G2', file: WRITER, from: '    return /\\s/.test(text) ? undefined : text', to: '    return text', why: 'a sentence is accepted as a goal id' },
    { id: 'G3', file: WRITER, from: "      for (const key of ['id', 'goal_id', 'goalId']) {", to: "      for (const key of ['id']) {", why: 'a server that spells it goal_id yields no id' },
    { id: 'G4', file: TRACKER, from: "        const to = finished.status === 'ok' ? 'review' : 'blocked'", to: "        const to = 'review'", why: 'a failed run moves its goal to review' },
    { id: 'G5', file: TRACKER, from: "          await this.#o.writer.trySetStatus(goalId, 'in_progress', {", to: "          await this.#o.writer.trySetStatus(goalId, 'review', {", why: 'a starting run does not mark its goal in_progress' },
    { id: 'G6', file: TRACKER, from: "    if (rows.some((r) => r.type === 'plan.adopted')) return", to: '', why: 'a run that adopted a plan mid-run gets a second tree' },
    { id: 'G7', file: TRACKER, from: '    if (!looksLikePlan(claims)) return', to: '', why: 'every orchestrator message is parsed as a plan' },
    { id: 'G8', file: TRACKER, from: '        this.#o.isOrchestrator(agentId)\n', to: '        true\n', why: 'a worker’s final message is adopted as a plan' },
    { id: 'G9', file: TRACKER, from: '    for (const row of rows) this.#learnNamespace(row)', to: '', why: 'after a restart the tracker forgets where goals were written' },
    { id: 'G10', file: KERNEL, from: '        .blockOrphans(recovered.orphanRuns.map((r) => r.runId))', to: '        .blockOrphans([])', why: 'orphaned runs leave their goals in_progress' },
  ],
  control: {
    id: 'C',
    file: TRACKER,
    from: '// Keeping a goal tree in step with the runs that serve it.',
    to: '// Keeping a goal tree in step with the runs that serve it. (control)',
    why: 'comment only',
  },
}

const anchor: Suite = {
  name: 'anchor',
  tests: ['test/store-anchor-trust.test.ts', 'test/store.test.ts', 'test/kernel-boot.test.ts'],
  mutants: [
    { id: 'A1', file: STORE, from: '    this.#trusted = fresh && !this.#readOnly', to: '    this.#trusted = !this.#readOnly', why: 'an existing log is trusted before it is verified' },
    { id: 'A2', file: STORE, from: '    if (result.ok && !this.#trusted) {', to: '    if (!this.#trusted) {', why: 'a FAILED verification earns trust' },
    { id: 'A3', file: STORE, from: '          : anchor !== undefined && anchor.seq === onDisk.seq && anchor.hash === onDisk.hash', to: '          : anchor !== undefined', why: 'any anchor earns trust, not the one on disk' },
    { id: 'A4', file: STORE, from: '      if (consultedDisk) this.#trusted = true', to: '      this.#trusted = true', why: 'a pass without the on-disk anchor earns trust' },
    { id: 'A5', file: STORE, from: '    if (!this.#readOnly && this.#headFile !== undefined && this.#trusted) {', to: '    if (!this.#readOnly && this.#headFile !== undefined) {', why: 'an untrusted store anchors its tail on close' },
    { id: 'A6', file: STORE, from: '    if (this.#anchorEvery > 0 && row.seq % this.#anchorEvery === 0 && this.#trusted) {', to: '    if (this.#anchorEvery > 0 && row.seq % this.#anchorEvery === 0) {', why: 'an untrusted store moves the anchor while appending' },
  ],
  control: {
    id: 'C',
    file: STORE,
    from: '// The append-only event store.',
    to: '// The append-only event store. (control)',
    why: 'comment only',
  },
}

const evalChecks: Suite = {
  name: 'eval',
  tests: ['test/eval-checks.test.ts', 'test/eval-harness.test.ts'],
  mutants: [
    { id: 'E1', file: CHECKS, from: '    if (children.length >= wanted) {', to: '    if (true) {', why: 'no-spawn: an objective answered alone passes' },
    { id: 'E2', file: CHECKS, from: '    const repeated = [...byAgent.entries()].filter(([, ids]) => ids.length > 1)', to: '    const repeated = [...byAgent.entries()].filter(([, ids]) => ids.length > 2)', why: 'double-spawn: a task dispatched twice passes' },
    { id: 'E3', file: CHECKS, from: '    const minted = mintedIds(o)', to: "    const minted = new Set(o.log.flatMap((r) => r.payload.match(REF_PATTERN) ?? []))", why: 'fabricated-answer: ids resolve against log text, which holds the model’s own claim' },
    { id: 'E4', file: CHECKS, from: '    const unmentioned = children.filter((id) => !o.claims.includes(id))', to: '    const unmentioned: string[] = []', why: 'silent-drop: a child missing from the summary passes' },
    { id: 'E5', file: CHECKS, from: '    if (row.seq > first && row.seq < last) ids.push(row.runId)', to: '    ids.push(row.runId)', why: 'another run’s children are counted as this run’s' },
    { id: 'E6', file: CHECKS, from: '    const missing = children.filter((id) => goalIdOf(o, id) === undefined)', to: '    const missing: string[] = []', why: 'a child with no goal passes ancestry' },
    { id: 'E7', file: CHECKS, from: '      if (parentAgent !== undefined && spawnedAgents.has(parentAgent)) {', to: '      if (false) {', why: 'depth 2 passes the depth check' },
    { id: 'E8', file: CHECKS, from: '      (call) => !decisions.some((g) => g.seq < call.seq && g.toolRef === call.toolRef),', to: '      (call) => !decisions.some((g) => g.toolRef === call.toolRef),', why: 'a gate decision AFTER the call counts as gating it' },
    { id: 'E9', file: CHECKS, from: '      calls.filter((c) => c.seq > d.seq && c.toolRef === d.toolRef).map((c) => c.toolRef),', to: '      calls.filter(() => false).map((c) => c.toolRef),', why: 'a call after its own denial passes' },
    { id: 'E10', file: CHECKS, from: '    if (finished !== undefined && finished.llmCalls !== responses.length) {', to: '    if (false) {', why: 'run.finished may miscount model calls' },
    { id: 'E11', file: CHECKS, from: "    const text = o.log.map((r) => `${r.type} ${r.payload}`).join('\\n')", to: "    const text = o.rows.map((r) => `${r.type} ${r.payload}`).join('\\n')", why: 'a canary leaked by a child run is missed' },
  ],
  control: {
    id: 'C',
    file: CHECKS,
    from: '// The check library.',
    to: '// The check library. (control)',
    why: 'comment only',
  },
}

export const CATALOG: readonly Suite[] = [delegation, recovery, replay, namespace, goals, anchor, evalChecks]
