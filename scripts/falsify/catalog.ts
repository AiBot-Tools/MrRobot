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
    { id: 'R8', file: 'src/models/anthropic.ts', from: "      ...(tools.length === 0 ? {} : { tools, tool_choice: { type: 'auto' } }),", to: "      ...{ tools, tool_choice: { type: 'auto' } },", why: 'a worker offered nothing still sends tools and tool_choice' },
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
    { id: 'N7', file: TRACKER, from: '  #projectFor(goalId: string): string | undefined {\n    return this.#namespaceOf.get(goalId)', to: "  #projectFor(goalId: string): string | undefined {\n    return this.#namespaceOf.has(goalId) ? 'aos/agent/researcher' : undefined", why: 'a child’s goal is moved in the child’s namespace, not where it was written' },
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
    { id: 'G11', file: WRITER, from: '    if (owner === undefined) {', to: '    if (false) {', why: 'a goal the kernel never created is moved (pmmcp moves any goal by id)' },
    { id: 'G12', file: WRITER, from: '    if (owner !== context.projectId) {', to: '    if (false) {', why: 'a goal created in one namespace is moved on behalf of another' },
    { id: 'G13', file: WRITER, from: '    if (confirmed?.[1] !== goalId) {', to: '    if (false) {', why: 'pmmcp’s refusal, sent as success text, is recorded as a move' },
    { id: 'G14', file: WRITER, from: '        ...(to === \'review\' ? { [a.progress]: 100 } : {}),', to: '', why: 'review reaches pmmcp indistinguishable from a task still running' },
    { id: 'G15', file: WRITER, from: '  if (created?.[1] !== undefined) return created[1]', to: '', why: 'pmmcp’s own create reply yields no id, so no tree is ever written' },
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
    { id: 'A7', file: 'src/kernel.ts', from: '  keepPrivate(config.dataDir, 0o700)\n', to: '', why: 'the event log sits in a .aos npm created at 0755, readable by every local account' },
    { id: 'A8', file: 'src/kernel.ts', from: '  for (const file of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) keepPrivate(file, 0o600)\n', to: '', why: 'events.db and its WAL stay at the umask\'s 0644' },
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

// Invariant 5. These edit the chain, the canonicalizer, the triggers and the
// redaction pass — the change-controlled core — and restore them; the operator
// approved keeping them in the catalog on that basis. The worst silent failure
// this kernel could have is a log that is tampered with, or holds a credential,
// while verifyChain still says ok.
const CHAIN = 'src/events/chain.ts'
const CANONICAL = 'src/events/canonical.ts'
const SCHEMA = 'src/events/schema.ts'
const REDACT = 'src/events/redact.ts'

const integrity: Suite = {
  name: 'integrity',
  tests: [
    'test/chain.test.ts',
    'test/canonical.test.ts',
    'test/store.test.ts',
    'test/store-anchor-trust.test.ts',
    'test/kernel-boot.test.ts',
    'test/cli.test.ts',
  ],
  mutants: [
    { id: 'H1', file: CHAIN, from: '    if (row.seq !== expectedSeq) {', to: '    if (false) {', why: 'a gap in seq is not reported as a gap' },
    { id: 'H2', file: CHAIN, from: '    if (row.prevHash !== prev) {', to: '    if (false) {', why: 'a broken prev_hash link passes' },
    { id: 'H3', file: CHAIN, from: '    if (recomputed !== row.hash) {', to: '    if (false) {', why: 'a row whose content was edited passes' },
    { id: 'H4', file: CHAIN, from: '  if (counter > tail) {', to: '  if (false) {', why: 'a deleted-and-refilled tail passes' },
    { id: 'H5', file: CHAIN, from: '    if (anchor.genesis !== GENESIS) {', to: '    if (false) {', why: 'an anchor from another chain is accepted' },
    { id: 'H6', file: CHAIN, from: '    if (tail < anchor.seq) {', to: '    if (false) {', why: 'a log behind its anchor (truncated) passes' },
    { id: 'H7', file: CHAIN, from: '      if (anchored === undefined || anchored.hash !== anchor.hash) {', to: '      if (false) {', why: 'a rewritten row at the anchored position passes' },
    { id: 'H8', file: CHAIN, from: '      type: row.type,\n    }),', to: '    }),', why: 'the event type is not hashed, so it can be changed silently' },
    { id: 'H9', file: CHAIN, from: "export const GENESIS: string = sha256Hex('aos-kernel:events:v1')", to: "export const GENESIS: string = '0'.repeat(64)", why: 'the genesis loses its domain separation' },
    { id: 'J1', file: CANONICAL, from: '      const keys = Object.keys(record).sort()', to: '      const keys = Object.keys(record)', why: 'key order changes the hash' },
    { id: 'J2', file: CANONICAL, from: '      if (!Number.isSafeInteger(v)) {', to: '      if (!Number.isFinite(v)) {', why: 'floats are hashed, so the hash depends on float formatting' },
    { id: 'J3', file: CANONICAL, from: '      if (LONE_SURROGATE.test(v)) {', to: '      if (false) {', why: 'a lone surrogate is hashed rather than refused' },
    { id: 'J4', file: CANONICAL, from: '      if (proto !== Object.prototype && proto !== null) {', to: '      if (false) {', why: 'a Date or class instance is canonicalized as an object' },
    { id: 'J5', file: CANONICAL, from: '      throw new TypeError(`unsupported value type ${typeof v} in event`)', to: "      return 'null'", why: 'undefined and bigint are silently written as null' },
    { id: 'T1', file: SCHEMA, from: '    if (normalize(actual) !== normalize(expected.sql)) {', to: '    if (false) {', why: 'a trigger rewritten to do nothing passes the check' },
    { id: 'T2', file: SCHEMA, from: '  if (extra.length > 0) {', to: '  if (false) {', why: 'an extra trigger on events is accepted' },
    { id: 'T3', file: SCHEMA, from: "      \"BEGIN SELECT RAISE(ABORT, 'events is append-only: UPDATE refused'); END\",", to: '      "BEGIN SELECT 1; END",', why: 'UPDATE on events is allowed' },
    { id: 'T4', file: SCHEMA, from: "      \"BEGIN SELECT RAISE(ABORT, 'events is append-only: DELETE refused'); END\",", to: '      "BEGIN SELECT 1; END",', why: 'DELETE on events is allowed' },
    { id: 'T5', file: SCHEMA, from: "      'WHEN NEW.seq IS NULL OR NEW.seq != (SELECT coalesce(max(seq), 0) + 1 FROM events) ' +", to: "      'WHEN NEW.seq IS NULL ' +", why: 'a row can be inserted out of sequence' },
    { id: 'T6', file: STORE, from: '    if (fresh && !this.#readOnly) createSchema(this.#db)', to: '    if (!this.#readOnly) createSchema(this.#db)', why: 'a dropped trigger is silently recreated instead of refused' },
    { id: 'T7', file: STORE, from: '    if (!triggers.ok) {', to: '    if (false) {', why: 'the store opens a log whose triggers fail the check' },
  ],
  control: {
    id: 'C',
    file: CHAIN,
    from: '// Hash chain over the event log.',
    to: '// Hash chain over the event log. (control)',
    why: 'comment only',
  },
}

const redaction: Suite = {
  name: 'redaction',
  tests: [
    'test/redact.test.ts',
    'test/store.test.ts',
    'test/secrets-broker.test.ts',
    'test/log.test.ts',
    'test/models-router.test.ts',
    'test/models-openai-chat.test.ts',
    'test/models-anthropic.test.ts',
    'test/cli.test.ts',
  ],
  mutants: [
    { id: 'S1', file: STORE, from: '    const payloadText = canonicalize(redactValue(stripUndefined(parsed.data)))', to: '    const payloadText = canonicalize(stripUndefined(parsed.data))', why: 'the store writes payloads unredacted' },
    { id: 'S2', file: REDACT, from: '  if (key !== undefined && DENY_KEYS.test(key)) return CENSOR', to: '', why: 'a value under a key like `password` is kept' },
    { id: 'S3', file: REDACT, from: '  let out = SecretMask.apply(s)', to: '  let out = s', why: 'a registered vault secret of no known shape is kept' },
    { id: 'S4', file: REDACT, from: '    const values = [...SecretMask.#values].sort((a, b) => b.length - a.length)', to: '    const values = [...SecretMask.#values].sort((a, b) => a.length - b.length)', why: 'a secret containing another is left half-censored' },
    { id: 'S5', file: REDACT, from: "    if (typeof value !== 'string' || value.length < MIN_MASK_LENGTH) return false", to: "    if (typeof value !== 'string') return false", why: 'a short common word can be registered and censored everywhere' },
    { id: 'S6', file: REDACT, from: '  if (Array.isArray(v)) return v.map((item) => redactValue(item))', to: '  if (Array.isArray(v)) return v', why: 'secrets inside arrays are kept' },
    { id: 'S7', file: REDACT, from: '  /\\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}/g, // OpenAI sk-…, Anthropic sk-ant-…\n', to: '', why: 'an OpenAI or Anthropic key in a string is kept' },
    { id: 'S8', file: REDACT, from: '  /\\bBearer\\s+[A-Za-z0-9._~+/-]+=*/g, // any bearer credential\n', to: '', why: 'a bearer token in a string is kept' },
    { id: 'S9', file: REDACT, from: '|credentials?)$/i', to: '|credentials?)$/', why: 'deny-keys match only in lower case (`Authorization` is kept)' },
    { id: 'S10', file: REDACT, from: '  /\\bgh[pousr]_[A-Za-z0-9]{20,}/g, // GitHub ghp_/gho_/ghu_/ghs_/ghr_\n', to: '', why: 'a GitHub token in a string is kept' },
    { id: 'S11', file: 'src/log.ts', from: "  'req.headers[\"x-api-key\"]',\n", to: '', why: 'pino logs the x-api-key header the Anthropic SDK sends' },
    { id: 'S12', file: 'src/log.ts', from: "  'req.headers.authorization',\n", to: '', why: 'pino logs a request Authorization header' },
    { id: 'S13', file: 'src/log.ts', from: '      inner.write(scrubLogLine(line))', to: '      inner.write(line)', why: 'a bearer a server echoes into an error message reaches stdout and the launchd log in clear: pino never looks at values' },
    { id: 'S14', file: 'src/log.ts', from: '    return redactString(line)\n', to: '    return line\n', why: 'a log line that is not JSON is written unscrubbed' },
  ],
  control: {
    id: 'C',
    file: REDACT,
    from: '// Value-scrubbing pass for the event log.',
    to: '// Value-scrubbing pass for the event log. (control)',
    why: 'comment only',
  },
}

const SCHEDULER = 'src/runtime/scheduler.ts'
const CRON = 'src/runtime/cron.ts'
const REGISTRY = 'src/agents/registry.ts'

const schedule: Suite = {
  name: 'schedule',
  tests: ['test/runtime-scheduler.test.ts', 'test/cron.test.ts', 'test/kernel-boot.test.ts', 'test/stubs.test.ts'],
  mutants: [
    { id: 'Q1', file: SCHEDULER, from: '      if (this.#fired.get(agent.agentId) === key) continue', to: '', why: 'a minute fires twice' },
    { id: 'Q2', file: SCHEDULER, from: '      this.#fired.set(agent.agentId, key)', to: '', why: 'the minute is not claimed in memory before the run starts' },
    { id: 'Q3', file: SCHEDULER, from: "    for (const row of this.#o.store.query({ type: 'run.scheduled' })) {", to: "    for (const row of this.#o.store.query({ type: 'run.scheduled' }).slice(0, 0)) {", why: 'a restart inside a fired minute fires it again' },
    { id: 'Q4', file: SCHEDULER, from: '      if (this.#o.isBusy(agent.agentId)) {', to: '      if (false) {', why: 'a run is started while the agent’s last one is still going' },
    { id: 'Q5', file: SCHEDULER, from: '          \'scheduler: unusable expression, skipping this agent\',\n        )\n        continue', to: '          \'scheduler: unusable expression, skipping this agent\',\n        )\n        throw e', why: 'one agent’s bad expression stops every other schedule' },
    { id: 'Q6', file: CRON, from: '  return expr.bothDayFieldsRestricted ? domHit || dowHit : domHit && dowHit', to: '  return domHit && dowHit', why: 'cron’s day-of-month OR day-of-week rule is ANDed' },
    { id: 'Q7', file: CRON, from: '  for (const d of dowRaw) dayOfWeek.add(d === 7 ? 0 : d)', to: '  for (const d of dowRaw) dayOfWeek.add(d)', why: 'day 7 is not Sunday' },
    { id: 'Q8', file: CRON, from: '      if (lo > hi) {', to: '      if (false) {', why: 'a backwards range is accepted instead of refused' },
    { id: 'Q9', file: CRON, from: '      if (slash !== -1) {\n        // `5/10`', to: '      if (false) {\n        // `5/10`', why: 'a step on a single value is accepted with one of two readings' },
    { id: 'Q10', file: CRON, from: "  if (text.startsWith('@')) {", to: '  if (false) {', why: 'an @macro is accepted' },
    { id: 'Q11', file: KERNEL, from: "        .filter((r) => r.status === 'active' && r.manifest.schedule !== undefined)", to: '        .filter((r) => r.manifest.schedule !== undefined)', why: 'an archived agent keeps firing' },
    { id: 'Q12', file: KERNEL, from: "        [...runs.values()].some((r) => r.state.agentId === agentId && r.state.status !== 'finished'),", to: '        false,', why: 'the kernel never reports an agent busy, so runs overlap' },
    { id: 'Q13', file: KERNEL, from: '    scheduler.start()', to: '    void scheduler', why: 'the kernel builds the scheduler and never starts it' },
  ],
  control: { id: 'C', file: SCHEDULER, from: '// Cron scheduler.', to: '// Cron scheduler. (control)', why: 'comment only' },
}

const registry: Suite = {
  name: 'registry',
  tests: ['test/agents-registry.test.ts', 'test/config-files.test.ts', 'test/delegation-unit.test.ts', 'test/kernel-boot.test.ts'],
  mutants: [
    { id: 'Y1', file: REGISTRY, from: '      pending.push({ manifest, dir })', to: "      this.#register({ manifest, status: 'active', dir })", why: 'a fleet with one bad manifest leaves the earlier ones registered' },
    { id: 'Y2', file: REGISTRY, from: '      if (already !== undefined) {', to: '      if (false) {', why: 'a duplicate agent id loads' },
    { id: 'Y3', file: REGISTRY, from: '      if (manifest.id !== entry) {', to: '      if (false) {', why: 'a manifest whose id does not match its directory loads' },
    { id: 'Y4', file: REGISTRY, from: '      if (!this.#deps.providers.has(ref)) {', to: '      if (false) {', why: 'a model ref missing from providers.yaml loads' },
    { id: 'Y5', file: REGISTRY, from: "      if (view.exposure !== 'agent') {", to: '      if (false) {', why: 'a manifest grants a tool the tool views withhold' },
    { id: 'Y6', file: REGISTRY, from: '      if (!allowed.includes(view.risk)) {', to: '      if (false) {', why: 'a tier holds a tool above its risk ceiling' },
    { id: 'Y7', file: REGISTRY, from: '    resolveCaps(this.#deps.budgets, manifest.budget ?? {})', to: '', why: 'a manifest may RAISE a budget cap' },
    { id: 'Y8', file: REGISTRY, from: '    this.#agents.set(record.manifest.id, Object.freeze(record))', to: '    this.#agents.set(record.manifest.id, record)', why: 'a registered record can be edited by what holds it' },
    { id: 'Y9', file: REGISTRY, from: "    if (template === undefined || template.manifest.kind !== 'template') {", to: '    if (template === undefined) {', why: 'an ephemeral agent can be spawned from a standing agent' },
    { id: 'Y10', file: REGISTRY, from: '    if (tier > t.tier) {', to: '    if (false) {', why: 'a spawned agent exceeds its template’s tier (invariant 6)' },
    { id: 'Y11', file: REGISTRY, from: '    if (outsideEgress.length > 0) {', to: '    if (false) {', why: 'a spawned agent exceeds its template’s egress (invariant 6)' },
    { id: 'Y12', file: REGISTRY, from: '    if (outsideTools.length > 0) {', to: '    if (false) {', why: 'a spawned agent holds tools its template does not' },
    { id: 'Y13', file: REGISTRY, from: '    if (this.#agents.has(input.childId)) {', to: '    if (false) {', why: 'a spawn overwrites an existing agent' },
  ],
  control: {
    id: 'C',
    file: REGISTRY,
    from: '  // Tier 3 may REQUEST an irreversible tool. It is still human-gated, always.',
    to: '  // Tier 3 may REQUEST an irreversible tool. It is still human-gated, always. (control)',
    why: 'comment only',
  },
}

const restart: Suite = {
  name: 'restart',
  tests: ['test/projections.test.ts', 'test/kernel-boot.test.ts', 'test/policy-approvals.test.ts', 'test/policy-quarantine.test.ts'],
  mutants: [
    { id: 'V1', file: PROJECTIONS, from: "        if (approvalId === '') break", to: '        break', why: 'an unanswered approval is not seen after a restart' },
    { id: 'V2', file: PROJECTIONS, from: "        approvals.delete(stringAt(payload, 'approvalId'))", to: '', why: 'a decided approval is expired again on every restart' },
    { id: 'V3', file: PROJECTIONS, from: "        if (holdId === '') break", to: '        break', why: 'an unreleased hold is not seen after a restart' },
    { id: 'V4', file: PROJECTIONS, from: "        if (row.runId !== null) touchedUntrusted.add(row.runId)\n        holds.delete(stringAt(payload, 'holdId'))", to: '        if (row.runId !== null) touchedUntrusted.add(row.runId)', why: 'a released hold is abandoned again on restart' },
    { id: 'V5', file: PROJECTIONS, from: "      case 'quarantine.abandoned': {\n        holds.delete(stringAt(payload, 'holdId'))", to: "      case 'quarantine.abandoned': {\n        void 0", why: 'recovery’s own abandon row does not close the hold, so recovery repeats' },
    { id: 'V6', file: KERNEL, from: "decision: 'expired' },", to: "decision: 'denied' },", why: 'an unanswered approval is recorded as a person saying no' },
    { id: 'V7', file: KERNEL, from: '    for (const approval of recovered.unresolvedApprovals) {', to: '    for (const approval of recovered.unresolvedApprovals.slice(0, 0)) {', why: 'boot leaves unanswered approvals open' },
    { id: 'V8', file: KERNEL, from: '    for (const hold of recovered.unreleasedHolds) {', to: '    for (const hold of recovered.unreleasedHolds.slice(0, 0)) {', why: 'boot leaves unreleased holds open' },
  ],
  control: {
    id: 'C',
    file: PROJECTIONS,
    from: '// So recovery TERMINATES what it finds.',
    to: '// So recovery TERMINATES what it finds. (control)',
    why: 'comment only',
  },
}

const DOCKER = 'src/sandbox/docker.ts'

const sandbox: Suite = {
  name: 'sandbox',
  tests: ['test/sandbox-docker.test.ts', 'test/config.test.ts', 'test/config-files.test.ts', 'test/agents-souls.test.ts'],
  mutants: [
    { id: 'Z1', file: DOCKER, from: '    const spellings = [...new Set([home, realpathNearest(home)])]', to: '    const spellings = [home]', why: 'a HOME reached through a symlink passes the never-$HOME check (found on macOS)' },
    { id: 'Z2', file: DOCKER, from: '  if (mounts !== 1 || volumes !== 0) {', to: '  if (false) {', why: 'a second bind mount or a -v reaches docker' },
    { id: 'Z3', file: DOCKER, from: '      if (arg === bad || arg.startsWith(`${bad}=`)) {', to: '      if (false) {', why: '--privileged and friends reach docker' },
    { id: 'Z4', file: DOCKER, from: '      if (arg.includes(bad)) {', to: '      if (false) {', why: 'the docker socket can be mounted into a container' },
    { id: 'Z5', file: DOCKER, from: "      if (internal !== 'true') {", to: '      if (false) {', why: 'a domain whose network has a route out (to pmmcp on 192.168.5.2) is reported available' },
    { id: 'Z6', file: 'src/config.ts', from: '    if (!isSpelledUnder(fence, real)) {', to: '    if (false) {', why: 'the event log or a mount root may live anywhere in the repo, beside the source' },
    { id: 'Z7', file: 'src/config.ts', from: '    if (!gitignoresAos(repoRoot)) {', to: '    if (false) {', why: 'an in-repo event log is admitted while git would commit it' },
    { id: 'Z8', file: 'src/config.ts', from: '  if (isUnder(real, home, id)) {', to: '  if (false) {', why: 'a mount root above $HOME hands a container the home directory' },
    { id: 'Z9', file: 'src/config.ts', from: '  if (isUnder(real, repo, id)) {', to: '  if (false) {', why: 'a data dir or mount root above the repository contains it' },
    { id: 'Z10', file: 'src/agents/protected.ts', from: '    if (id(d) === target) return true', to: '    if (false) return true', why: 'a case-variant or firmlinked spelling of souls/, $HOME or the repo passes every containment check (APFS)' },
    { id: 'Z11', file: 'src/config.ts', from: '  const id = opts.id ?? identify\n', to: '  const id: Identify = () => undefined\n', why: 'config compares paths by spelling only: an APFS case variant of $HOME or the repo passes as a data dir or mount root' },
    { id: 'Z12', file: 'src/config.ts', from: '    if (!isSpelledUnder(fence, real)) {', to: '    if (!isUnder(fence, real, id)) {', why: 'an alias that shares .aos\'s identity vouches for a data dir git does not ignore' },
    { id: 'Z13', file: 'src/sandbox/confine.ts', from: '  if (!isSpelledUnder(realRoot, realWorkspace)) {', to: '  if (!isUnder(realRoot, realWorkspace, id)) {', why: 'a bind mount sharing the mountRoot\'s identity vouches for a workspace anywhere' },
    { id: 'Z14', file: 'src/sandbox/confine.ts', from: '  if (isUnder(realWorkspace, home, id)) {', to: '  if (false) {', why: 'a link or mount made after boot puts $HOME under the mountRoot and into a container' },
    { id: 'Z15', file: 'src/sandbox/confine.ts', from: '  if (isUnder(realWorkspace, repo, id)) {', to: '  if (false) {', why: 'a link or mount made after boot puts the repository (souls, .env) into a container' },
    { id: 'Z16', file: 'src/config.ts', from: "      if (problem?.kind === 'link') {", to: '      if (false) {', why: 'a linked .aos or .aos/workspaces, which git does not ignore and would commit, is admitted' },
    { id: 'Z17', file: 'src/config.ts', from: "      if (problem?.kind === 'spelling') {", to: '      if (false) {', why: 'a .aos stored as .AOS, which /.aos/ does not cover under core.ignorecase=false, is admitted' },
    { id: 'Z18', file: 'src/agents/protected.ts', from: "    return actual === undefined ? undefined : { kind: 'spelling', actual }", to: '    return undefined', why: 'an entry stored under another case than the one git is told to ignore passes as spelled right' },
  ],
  control: { id: 'C', file: DOCKER, from: '    // Invariant 9, one flag at a time.', to: '    // Invariant 9, one flag at a time. (control)', why: 'comment only' },
}

const DOTENV = 'src/secrets/dotenv.ts'

const dotenv: Suite = {
  name: 'dotenv',
  tests: [
    'test/dotenv.test.ts',
    'test/cli.test.ts',
    'test/entrypoints.test.ts',
    'test/secrets-broker.test.ts',
    'test/control-auth.test.ts',
    'test/kernel-boot.test.ts',
    'test/env.test.ts',
    'test/hygiene.test.ts',
    'test/config-files.test.ts',
  ],
  mutants: [
    { id: 'X1', file: DOTENV, from: '    if ((st.mode & 0o077) !== 0) {', to: '    if (false) {', why: 'a .env whose mode lets group or others read or write it is loaded' },
    { id: 'X2', file: DOTENV, from: 'constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', to: 'constants.O_RDONLY | constants.O_NONBLOCK', why: 'a symlinked .env is followed to wherever it points' },
    { id: 'X3', file: DOTENV, from: '    if (!st.isFile()) throw', to: '    if (false) throw', why: 'a directory, device or FIFO is read as a .env' },
    { id: 'X4', file: DOTENV, from: '    if (st.uid !== uid) throw', to: '    if (false) throw', why: 'a .env owned by another user is trusted' },
    { id: 'X5', file: DOTENV, from: '    if (st.nlink !== 1) throw', to: '    if (false) throw', why: 'a .env hard-linked elsewhere is read' },
    { id: 'X6', file: DOTENV, from: '    if (st.size > DOTENV_MAX_BYTES) {', to: '    if (false) {', why: 'an arbitrarily large file is read and parsed' },
    { id: 'X7', file: DOTENV, from: '    if (!accepted.has(name)) {', to: '    if (false) {', why: 'any name in the file is admitted, NODE_OPTIONS and AOS_LIVE_TESTS included' },
    { id: 'X8', file: DOTENV, from: '  for (const name of options.wanted) {', to: '  for (const name of options.accepted) {', why: 'the CLI and eval receive provider keys they never asked for' },
    { id: 'X9', file: DOTENV, from: '  for (const name of names) env[name] = shellValue(shell, name) ?? loaded?.values[name]', to: '  for (const name of names) env[name] = loaded?.values[name] ?? shellValue(shell, name)', why: 'the file silently beats a value the operator exported' },
    { id: 'X10', file: DOTENV, from: '  return value !== undefined && value.trim() !== \'\' ? value : undefined', to: '  return value !== undefined ? value : undefined', why: 'an exported empty or blank string hides the key in the file (and is "set" to one reader, "unset" to another)' },
    { id: 'X11', file: DOTENV, from: '    if (earlier !== undefined) {', to: '    if (false) {', why: 'a name set twice resolves silently to one of them' },
    { id: 'X12', file: DOTENV, from: '    if (ENV_LINE.test(value)) {', to: '    if (false) {', why: 'a value that is a joined NAME=value line is loaded as a key' },
    { id: 'X13', file: DOTENV, from: '    SecretMask.register(fromFile.value)', to: '    void fromFile.value', why: 'a file-sourced value is not masked before anything can log it' },
    { id: 'X14', file: DOTENV, from: '    if (!gitignoresDotenv(options.repoRoot)) {', to: '    if (false) {', why: 'an in-repo .env git would commit is read anyway' },
    { id: 'X15', file: DOTENV, from: '    if (place !== \'root\' || basename(abs) !== DOTENV_FILE) {', to: '    if (false) {', why: 'any file inside the repo, the template included, is read as credentials' },
    { id: 'X28', file: DOTENV, from: '  if (!isUnder(repo, d, id)) return \'outside\'', to: '  if (!(d === repo || d.startsWith(repo + \'/\'))) return \'outside\'', why: 'a differently spelled path to the repo (APFS case, a firmlink) skips the in-repo fence' },
    { id: 'X16', file: DOTENV, from: '  return { path: abs, found: true, values, shadowed }', to: '  Object.assign(process.env, values)\n  return { path: abs, found: true, values, shadowed }', why: 'file-sourced values are written into process.env, where every child inherits them' },
    { id: 'X17', file: DOTENV, from: '      problems.push(`line ${String(n)}: not NAME=value`)', to: '      problems.push(`line ${String(n)}: not NAME=value: ${line}`)', why: 'a refusal quotes the offending line, which may be a pasted key' },
    { id: 'X18', file: DOTENV, from: '      problems.push(`line ${String(n)}: a name this kernel does not read: delete the line`)', to: '      problems.push(`line ${String(n)}: ${name} is a name this kernel does not read: delete the line`)', why: 'a refusal quotes an unaccepted name, which may be a pasted key' },
    { id: 'X19', file: DOTENV, from: '    if (parsed.value === \'\') out.delete(name)', to: '', why: 'a blank value is returned as the empty string instead of unset' },
    { id: 'X20', file: DOTENV, from: '    if (value.toLowerCase().startsWith(PLACEHOLDER_PREFIX)) {', to: '    if (false) {', why: 'an unfilled copy of .env.example sends its placeholder as a key' },
    { id: 'X21', file: DOTENV, from: '  if (fromShell !== undefined) return fromShell\n', to: '', why: 'the CLI opens the file even when the shell already has the token' },
    { id: 'X32', file: DOTENV, from: '  if (fromShell !== undefined) return fromShell\n', to: '  if (fromShell !== undefined) return fromShell.trim()\n', why: 'the live tests pass on a trimmed key the daemon\'s broker refuses as it is set' },
    { id: 'X33', file: 'src/control/auth.ts', from: '  if (/[^\\x21-\\x7e]/.test(token)) {', to: '  if (false) {', why: 'a smart-quoted control token boots the daemon and fails every client with an unreadable header error' },
    { id: 'X36', file: 'src/control/auth.ts', from: '  if (/\\s/.test(token)) {', to: '  if (false) {', why: 'a passphrase token is refused as holding a non-ASCII character, sending the operator after one that is not there' },
    { id: 'X37', file: 'src/secrets/broker.ts', from: '  if (problem !== undefined) return `${name} ${problem}, so it is not a bearer`', to: '  void problem', why: 'a pmmcp bearer with a newline is sent, and the HTTP error quoting it lands in the chained log and on capture-pmmcp\'s terminal' },
    { id: 'X38', file: 'src/secrets/broker.ts', from: '  if (!SecretMask.register(token)) return', to: '  if (token.length < MIN_MASK_LENGTH) return', why: 'a valid pmmcp bearer is never masked, so a server that echoes it puts it in the chained log and on capture-pmmcp\'s terminal' },
    { id: 'X40', file: 'src/secrets/broker.ts', from: '  if (!SecretMask.register(token)) return', to: '  if (!SecretMask.register(token) && false) return', why: 'a pmmcp bearer too short for the mask is sent unmasked, and an echo of it is chained into the log for good' },
    { id: 'X39', file: DOTENV, from: "    if (spelled?.kind === 'spelling') {", to: '    if (false) {', why: 'a .env stored as .Env, which .env* does not cover under core.ignorecase=false, is opened on the Mac and pushed by git add -A' },
    { id: 'X29', file: DOTENV, from: '    if (/[^\\x21-\\x7e]/.test(value)) {', to: '    if (false) {', why: 'a smart-quoted or zero-width-spaced key in .env is loaded and fails at the first request, naming nothing' },
    { id: 'X23', file: 'src/secrets/broker.ts', from: "  if (looksLikeEnvLine(value)) return 'holds a whole NAME=value line'", to: "  if (false) return 'holds a whole NAME=value line'", why: 'a shell value that is a joined NAME=value line is minted as a key' },
    { id: 'X26', file: 'src/secrets/broker.ts', from: '    return this.#mintFromEnv(id, envVar, fromEnv, purpose)\n  }\n\n  /** Both env paths', to: '    return this.#mint(id, \'env\', fromEnv, purpose)\n  }\n\n  /** Both env paths', why: 'the D8 env fallback mints a value source env would refuse' },
    { id: 'X27', file: 'src/secrets/broker.ts', from: '  if (/[^\\x21-\\x7e]/.test(value)) return', to: '  if (false) return', why: 'a smart-quoted or zero-width-spaced key is minted and fails far away, naming nothing' },
    { id: 'X24', file: 'test/helpers/live-env.ts', from: '  if (env[\'AOS_LIVE_TESTS\'] !== \'1\') throw new Error', to: '  if (false) throw new Error', why: 'an offline test can open the repo\'s real .env' },
    { id: 'X25', file: 'test/helpers/guard.ts', from: 'if (!KEEPS_CREDENTIALS) {', to: 'if (false) {', why: 'a key exported in the shell running npm test reaches every offline test' },
    { id: 'X31', file: 'test/helpers/guard.ts', from: "  process.env['AOS_LIVE_TESTS'] === '1' && process.argv.length === 2 && LIVE_FILE.test(process.argv[1] ?? '')", to: "  process.env['AOS_LIVE_TESTS'] === '1'", why: 'on the live run every offline test file keeps the shell\'s keys, not just the two live ones' },
    { id: 'X35', file: 'test/helpers/guard.ts', from: "  process.env['AOS_LIVE_TESTS'] === '1' && process.argv.length === 2 && LIVE_FILE.test(process.argv[1] ?? '')", to: "  process.env['AOS_LIVE_TESTS'] === '1' && LIVE_FILE.test(process.argv[1] ?? '')", why: 'one process running several files (--test-isolation=none) keeps the keys for all of them when a live file comes first' },
    // Deliberately NOT here: a mutant disabling liveCredential's no-path gate.
    // Its killing test would call liveCredential in-process with the default
    // path, which under that mutant IS the operator's real <repo>/.env.
  ],
  control: {
    id: 'C',
    file: DOTENV,
    from: "// The operator's credentials file: <repo>/.env, read by entry points only.",
    to: "// The operator's credentials file: <repo>/.env, read by entry points only. (control)",
    why: 'comment only',
  },
}

// Mutants on how an entry point picks its credentials file live apart from the
// dotenv suite on purpose. That suite runs test/entrypoints.test.ts, which
// spawns the daemon, the CLI and eval with cwd = this checkout — where the
// operator keeps the real <repo>/.env. X22 (default the daemon to <repo>/.env),
// run there, would have a test-spawned daemon read the real keys before any
// assertion killed it. Here the tests are in-process and their repos are temp
// directories: dotenv.test.ts points daemonEnv at a trap repo, and cli.test.ts
// runs the CLI with a temp cwd. falsify.test.ts keeps it that way.
const dotenvDefault: Suite = {
  name: 'dotenvDefault',
  tests: ['test/dotenv.test.ts', 'test/cli.test.ts'],
  mutants: [
    { id: 'X22', file: 'src/main.ts', from: '  const path = dotenvPathFrom(argv, ctx.repoRoot)', to: '  const path = dotenvPathFrom(argv, ctx.repoRoot) ?? join(ctx.repoRoot, \'.env\')', why: 'a daemon started without --dotenv opens <repo>/.env anyway' },
    { id: 'X30', file: 'src/cli/index.ts', from: '    dotenvPathFrom(end === -1 ? argv : argv.slice(0, end), io.cwd)\n', to: '', why: 'npm run cli -- --dotenv other silently replaces the .env package.json names' },
    { id: 'X34', file: 'src/cli/index.ts', from: '    dotenvPathFrom(end === -1 ? argv : argv.slice(0, end), io.cwd)', to: '    dotenvPathFrom(argv, io.cwd)', why: 'run input after -- that mentions --dotenv is refused as a second --dotenv' },
  ],
  control: {
    id: 'C',
    file: 'src/main.ts',
    from: '// Daemon entry point: `npm run dev`.',
    to: '// Daemon entry point: `npm run dev`. (control)',
    why: 'comment only',
  },
}

const GITIGNORE = 'src/gitignore.ts'

const gitignore: Suite = {
  name: 'gitignore',
  tests: ['test/gitignore.test.ts', 'test/dotenv.test.ts', 'test/config.test.ts', 'test/config-files.test.ts'],
  mutants: [
    { id: 'I1', file: GITIGNORE, from: '      if (couldMatch) ignored = false', to: '      if (false) ignored = false', why: 'a later `!*` or `!.en?` re-includes .env and the check still says ignored' },
    { id: 'I2', file: GITIGNORE, from: '  let pattern = trimTrailingSpaces(line)', to: '  let pattern = trimTrailingSpaces(line.trim())', why: 'a line git reads as \' .env\' or \'.env<TAB>\' is credited as ignoring .env' },
    { id: 'I3', file: GITIGNORE, from: '  if (dirOnly && kind !== \'dir\') return false', to: '', why: 'a directory-only `.env/` is credited as ignoring the file' },
    { id: 'I4', file: GITIGNORE, from: '      if (matches(line, entry, kind, false) === true && matches(line, entry, kind, true) === true) ignored = true', to: '      if (matches(line, entry, kind, false) === true) ignored = true', why: 'a line git applies only without core.ignorecase (`.e[!A-Z]v`) is credited on the Mac, where it is not' },
    { id: 'I5', file: GITIGNORE, from: '  return /\\*{2,}/.test(anchored) ? undefined : false', to: '  return false', why: 'git\'s literal-prefix rule (`!.**/*`, `!.e**/nv`) re-includes .env unseen' },
    { id: 'I6', file: GITIGNORE, from: '    if (!st.isFile() || st.size >= GIT_PATTERN_FILE_LIMIT) return false', to: '    if (st.size >= GIT_PATTERN_FILE_LIMIT) return false', why: 'a symlinked .gitignore, which git does not read, is trusted' },
    { id: 'I7', file: GITIGNORE, from: '  if (text.startsWith(\'\\xEF\\xBB\\xBF\')) text = text.slice(3)', to: '', why: 'a BOM-prefixed .gitignore is read unlike git, which skips the BOM: a first-line `!.env` goes unseen' },
    { id: 'I8', file: GITIGNORE, from: '  if (anchored.includes(\'[\')) return undefined', to: '', why: 'a negation with `/` inside a bracket (`![!/]env`) re-includes .env unseen' },
    { id: 'I9', file: GITIGNORE, from: "  while (segments.length > 1 && /^\\*{2,}$/.test(segments[0] ?? '')) segments.shift()", to: "  while (segments.length > 1 && segments[0] === '**') segments.shift()", why: '`***/.env`, which git reads as `**/.env`, stops being credited: the matcher and git disagree on a plain line' },
    { id: 'I10', file: GITIGNORE, from: '  return nul === -1 ? line : line.slice(0, nul)', to: '  return line', why: 'a negation cut short by a NUL, as git reads it, re-includes .env unseen' },
    { id: 'I11', file: GITIGNORE, from: '      if (!lstatSync(join(repoRoot, entry)).isDirectory()) return false', to: '      if (false) return false', why: 'a .aos symlink, which `/.aos/` does not cover, is credited as ignored' },
    { id: 'I12', file: GITIGNORE, from: '    if (!st.isFile() || st.size >= GIT_PATTERN_FILE_LIMIT) return false', to: '    if (!st.isFile()) return false', why: 'a .gitignore git 2.50 skips as too large is credited' },
    { id: 'I13', file: GITIGNORE, from: '      if (up >= lo && up <= hi) matched = true', to: '      if (false) matched = true', why: 'git\'s folded range test is modelled wrongly, so `[!A-Z]` is credited where macOS git refuses it' },
    { id: 'I14', file: GITIGNORE, from: '    if (!st.isFile() || st.size >= GIT_PATTERN_FILE_LIMIT) return false', to: '    if (!st.isFile() || st.size >= GIT_PATTERN_FILE_LIMIT - 1) return false', why: 'a .gitignore one byte under 100 MiB, which git 2.50 reads, is judged to ignore nothing: the model drifts from git' },
    { id: 'I15', file: GITIGNORE, from: '  if (line.length > MAX_MODELLED_LINE) return undefined\n', to: '', why: 'a pattern line of any length is matched as written: a huge one exhausts the heap at boot, and a long ignoring line is credited unmodelled' },
  ],
  control: {
    id: 'C',
    file: GITIGNORE,
    from: '// Does <repo>/.gitignore ignore one entry directly under the repository root?',
    to: '// Does <repo>/.gitignore ignore one entry directly under the repository root? (control)',
    why: 'comment only',
  },
}

export const CATALOG: readonly Suite[] = [
  delegation,
  recovery,
  replay,
  namespace,
  goals,
  anchor,
  evalChecks,
  integrity,
  redaction,
  schedule,
  registry,
  restart,
  sandbox,
  dotenv,
  dotenvDefault,
  gitignore,
]
