# CLAUDE.md — aos-kernel

Read this file completely before touching anything. It is the standing contract for every session.

## What this is

The kernel (control plane) of a local-first Agentic OS for a single operator on one Mac. A CEO agent orchestrates a fleet of standard agents and spawns ephemeral ones; every action lands in a hash-chained event log; pmmcp (the operator's Persistent Memory MCP server) is shared long-term memory and the secrets vault; models are bound per agent across Anthropic, OpenAI, OpenRouter, and any OpenAI-compatible endpoint (local llama.cpp/Bonsai, Ollama, Moonshot/Kimi). A native macOS app comes later and renders the WebSocket protocol this kernel serves; a Tauri/React prototype comes first.

Reference points, not code to copy: OpenClaw (gateway/lane-queue/agent-workspace shape; its security posture is the anti-pattern) and Hermes Agent (delegate_task isolated-context delegation, per-task model priority chain).

## Current state

Phase 0 scaffold, delivered as a repo: `tsc --noEmit` clean, 366 `node:test` tests passing and 2 gated live tests skipped by design across 40 files, kernel boots DEGRADED with no pmmcp and no Docker. See README.md "What is real, what is a stub". Stubs and gaps: Apple container driver (`probe` reports unavailable so boot degrades, `run`/`kill` throw), egress proxy sidecar (absent; `assertEgressEnforced` throws), cron scheduler (absent; `schedule:` refused at parse), restart-safe projections for approvals/quarantine (absent; `rebuildFromLog` throws), live tests behind `AOS_LIVE_TESTS=1` (one file, two tests: the LLM half and the pmmcp-connected exit criterion; neither has run), `SecretsBroker.keyArg` unverified (fails closed) until the pmmcp-connected live test passes, CEO delegation/spawn tool (absent; `spawnEphemeral` is registry-only, `assertDelegationAvailable` throws), `tool-views.yaml` classifies 9 of 49 pmmcp tools (remainder kernel-only by default). No real provider call has ever been made: the run path is proven offline against a doubled provider, with a credential resolved at boot and non-zero cost. Phase 0 exit (pmmcp-connected `aos run ceo` with non-zero cost) is recorded in README's exit-criterion checklist and is not claimed until that entry is filled.

## Commands

```
npm run typecheck        # tsc --noEmit, must be clean before any claim of done
npm test                 # node --import tsx --test test/*.test.ts
npm run dev              # daemon on 127.0.0.1:7777 (needs .env sourced)
npm run cli -- <cmd>     # agents | verify-chain | search | probe | run | kill | approve | deny | approvals
npm run build            # emits dist/
```

## Architecture

Three planes. Shell (UI, holds no secrets, executes nothing) → Kernel (this repo: event log, registry, lanes, CEO loop, model router, MCP hub, policy gate, secrets broker, sandbox manager, budgets) → Workers (one process or container per run; scoped tools, no raw credentials, own workspace).

Source map: `src/events` log + chain + redaction · `src/agents` manifests + registry · `src/policy` gate + approvals · `src/mcp` hub + tool-view policy · `src/models` registry + router + probe · `src/runtime` lanes + run loop + AsyncLocalStorage run scope · `src/sandbox` driver interface + docker + apple-container stub · `src/secrets` broker over pmmcp vault · `src/control` protocol + views + WebSocket server · `src/cli` console.

Config is data: `config/kernel.yaml` (no secrets), `config/tool-views.yaml` (per-server tool exposure/risk/taint/quarantine), `config/providers.yaml` (providers + model cards + pricing), `agents/<id>/agent.yaml` (versioned manifests, `history/` holds frozen prior versions), `souls/*.md` (personas).

## Non-negotiable invariants

These are enforced in code. Do not weaken them for convenience, tests, or speed. If a task appears to require weakening one, stop and ask.

1. Control plane binds loopback only; bearer token in the `Authorization` header only; query-string tokens rejected; `Origin`, if present, must be loopback.
2. Agents never hold an MCP connection, a provider key, or a vault handle. The hub, router, and broker are kernel-only. Workers get credentials injected at the egress proxy edge, never in env or files.
3. Every agent tool call: policy gate → (human approval) → (quarantine) → execute → log. Default deny. `irreversible` risk always requires a human. Tainted runs cannot use `write` tools without a human. The model never makes an access-control decision.
4. Every LLM call is two events (`llm.request`, `llm.response`) with prompt, content, tokens, cost.
5. Every event is redacted, canonicalized, hashed, chained. SQLite triggers refuse UPDATE/DELETE on `events`. `verifyChain` must pass after every test run that writes events.
6. Ephemeral agents cannot exceed the template's tier or egress. Promotion is a human action via the control plane; the CEO can only file a request. Archive never deletes.
7. Unknown tools on any MCP server default to `kernel-only` until classified in `tool-views.yaml`. Secret tools, `admin`, `restore_backup`, `delete_context_source`, `index_project` stay `kernel-only`. `coding_agent` and `session_insight_agent` stay `disabled` for agents (nested LLM calls bypass router, budgets, taint, log).
8. `souls/*.md` and `agents/*/AGENTS.md` are read-only to agents. No code path lets a run write them.
9. Containers: `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, non-root, pids/memory/cpu caps, internal network, mounts confined to the domain's `mountRoot` after symlink resolution, hard wallclock. Never `--privileged`, never `docker.sock`, never `$HOME`.
10. Provider tool names use `__` in place of `.` (`pmmcp__recall`); refs stay dotted everywhere else. Keep `toolName`/`toolRef` as the only mapping.

## Coding standards

* TypeScript strict with `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess` on. ESM (`"type": "module"`, `.js` import suffixes). No `require`.
* zod at every boundary: config, manifests, protocol commands, tool-view policy, provider config. Parse, don't cast, except at documented third-party type seams (the MCP `Transport` cast in `hub.ts` is the one allowed example).
* Errors: throw with context at the source; log with `pino` (`src/log.ts`, redaction paths configured); never swallow silently except listener fan-out in the event store, which is documented.
* Tests: `node:test` + `node:assert/strict`, files in `test/*.test.ts`. Every behavior change ships with a test. Use `EventStore(":memory:")` for unit tests. For hub tests, build an in-process MCP server with the SDK's `InMemoryTransport` rather than requiring a live pmmcp.
* No new dependencies without asking. If you must propose one, name the package, version, why the standard library or an existing dep is insufficient, and its transitive footprint.
* Comments explain why, not what. Keep file headers that state a component's contract.
* Commit per completed task with a message that names the phase item and the test that proves it.

## Change control

Ask before: adding a dependency; changing `src/control/protocol.ts` (v1 is frozen for the UI; a change means a version bump and a migration note); changing any tool's `exposure` in `tool-views.yaml`; touching redaction, chain hashing, or the immutability triggers; deleting or skipping a test; anything that widens what an agent can reach.

Never: write a secret into any file under the repo; log a secret value; auto-promote an agent; add a bypass of the gate "for testing"; disable the wallclock, budget, or retry caps; store raw tool output larger than `MAX_LOGGED_OUTPUT` in the log.

Decide alone: internal refactors that keep tests green; new tests; new kernel-only helpers; documentation.

## Environment facts (the operator's machine)

* macOS 15.6.1 on M1 Max, 64 GB unified memory, 2 TB SSD. Not macOS 26: Apple `container` is unavailable; the `apple-container` driver stays a stub. Sandboxes are Docker via two Colima VMs (`trusted`, `hostile`), see `scripts/colima-up.sh`. Qdrant runs in Docker. Ollama should run natively for Metal.
* pmmcp: Streamable HTTP, 49 exposed tools (9 pinned names classified in `config/tool-views.yaml`; the remaining names are kernel-only until classified from `hub.tools.classified`). Namespacing is by `project_id`; the kernel uses `aos/ceo`, `aos/agent/<id>`, `aos/shared`. Goals are hierarchical (objective → milestone → task) with validated status transitions and `auto_resume` off. Sessions idle-expire; the hub heartbeats every 240 s. The vault (`get_secret`/`set_secret`, Fernet + keyring, audit logs, `audit_secrets`) is the secrets store; the kernel is its only caller.
* Local models: budget ≤ ~40 GB for weights + KV. Bonsai (PrismML, ~1.1 bits/weight) runs behind llama.cpp's OpenAI-compatible server at `localhost:8080/v1`. Kimi K2-class is hosted (Moonshot), not local.
* Model ids in `config/providers.yaml` are placeholders except the Claude entry. A model is bound to an agent only after `aos probe <ref>` reports `toolCalling: true`. `orchestrator: true` is set by the human after the eval harness, never by code.

## Phase map and exit criteria

* Phase 0 (remainder, needs the operator): pmmcp loopback + bearer confirmed; `get_secret` arg name confirmed and set; FSEvents-through-virtiofs check passes; probes run; providers.yaml real. Exit: daemon boots with pmmcp connected and `aos run ceo "..."` produces `run.finished` with non-zero cost.
* Phase 1, first real loop: restart-safe projections (approvals + quarantine rebuilt from the log); CEO plans into pmmcp goals and delegated runs carry `goalId`, kernel updates task goal status on run start/finish; cron scheduler for `schedule:`; in-process mock MCP server for hub tests; typed wrappers for pmmcp goal + secret tools generated from live `listTools` schemas; two standard agents (`researcher`, `writer`); eval harness scoring orchestration tasks against the mock hub; live runtime tests behind `AOS_LIVE_TESTS=1`. Exit: one objective → goal tree + ≥2 child runs + trustworthy summary; kernel restart mid-run orphans nothing.
* Phase 2, sandboxes and the wire: egress proxy sidecar (per-agent hostname allowlist, credential injection at the edge, every decision logged); Colima domains live with the worker image; live Docker driver tests; pack manifests + tool-view classification for GitHub, Vercel, Supabase MCP servers with schema-hash pinning and drift alerts; first critical-fixes audit pass. Exit: a T2 coding agent clones a repo, changes it, runs tests, opens a PR, with every network call visible as a proxy decision and zero credentials in the container.
* Phase 3, Tauri prototype: React over protocol v1: Ops Deck, Run Inspector, Approvals, Agent Forge, Router, Memory Browser, History; daemon as a launchd user agent. Exit: a full day without the CLI and zero protocol changes.
* Phase 4, reach: Twilio voice/SMS behind hard gate preconditions; media pipeline (ffmpeg in T2, TTS/image/video APIs, review queue); social adapters as swappable MCP servers; Telegram as tainted ingress with pairing. Exit: clip → scheduled post with a human approval in between; inbound SMS → tainted run that cannot reply without a human.
* Phase 5, hardening + native: signed skills repo; Tailscale remote access; per-agent eval suites gating manifest changes; SwiftUI port; Apple container driver when the OS allows. Exit: the Tauri app is deleted.

Order is deliberate: Phase 2 before Phase 4 (dangerous integrations only after proxy, taint, sandboxes); Phase 3 before Phase 5 (prove the protocol before paying for native).

## Session protocol

Start: read this file; run `npm run typecheck && npm test`; report the baseline in one line. If red, fix the baseline before new work.

Plan: write a numbered task list for the session scoped to one phase item or a small set of them. Each task names its acceptance test. Get it acknowledged before implementing anything larger than a bug fix.

Work: smallest correct change; test; typecheck; commit. Never batch three features into one commit.

End: report exactly this: tasks done (with test names), tasks not done and why, baseline state (typecheck, test count pass/fail, chain verified), decisions that need the operator, and the next three tasks. No summaries of what you would have done.
