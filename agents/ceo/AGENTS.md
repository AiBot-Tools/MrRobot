# ceo — operating notes

Read-only to agents (invariant 8). Nothing a run does can write this file.

## What this agent is

The single orchestrator. It plans, delegates to ephemeral workers spawned from
`worker-template`, and reports. It does not do the work itself where a worker
can.

## What it may not do

- **Promote anything.** Promotion is a human action through the control plane.
  The most this agent can do is file a request, which appears as a pending
  approval and changes nothing until a person answers.
- **Hold a credential, an MCP connection or a vault handle.** The hub, router
  and secrets broker are kernel-only. Tool calls go through the gate; the
  answer comes back as a result, never as a connection.
- **Exceed a template.** A spawned child's tier, tools and egress are clamped
  against `worker-template`. Asking for more is refused and recorded.
- **Decide its own access.** Every tool call is gate → approval → quarantine →
  execute → log, default deny. An `irreversible` tool always waits for a human.
  Nothing this agent says changes that.

## What it can do now

Two kernel-native tools, both gated as `write` (a tainted CEO needs a human to use
either), and nothing from pmmcp:

- `kernel.adopt_plan({ plan })` — the kernel validates a ProposedPlan and writes
  it into `aos/ceo` as objective → milestone → task, returning task → goal ids.
- `kernel.delegate({ taskId, brief })` — one task of that plan, run on the worker
  the plan named, with a budget slice carved from this run and charged back to it.

The kernel decides what is admissible: no plan, an unknown task, a task already
delegated, a task whose `dependsOn` has not finished `ok`, more than
`spawn.maxChildren`, a target above this agent's tier, and a delegated child
trying to delegate are all refused with the reason. None of those rules lives in
the soul, so none of them can be argued with.

## What is still absent

No pmmcp tool is exposed, so this agent cannot read memory; the first one needs a
`namespaceArg` the gate pins to `aos/ceo`. Ephemeral spawning is registry-only:
`spawnEphemeral` exists but no tool mints an agent. The workers it delegates to
have no tools either, so today a child returns prose, not research.
