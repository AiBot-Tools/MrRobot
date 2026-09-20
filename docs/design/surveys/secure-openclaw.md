# Survey: secure-openclaw

Clone: `refs/secure-openclaw` (paths below are relative to it; openclaw comparisons are relative to `../openclaw`). CONFIRMED = read in the clone; INFERRED = derived.

## Identity

- Commit: `70806a72a064c0dc868cfc351a92d91bf375ff03` (2026-02-11), single squashed commit by `Prathit-tech`, no history (CONFIRMED `git log`).
- Remote of this clone: `AiBot-Tools/secure-openclaw`. Upstream: `ComposioHQ/secure-openclaw` (CONFIRMED: README "Community" links issues/discussions to ComposioHQ/secure-openclaw; LICENSE.md "Copyright (c) 2025 Composio").
- Relation to openclaw/openclaw: name and gateway/adapter/session-key vocabulary only. No shared source, different stack and dependencies (INFERRED: no openclaw code, config, or package appears in the tree; session key `agent:<agentId>:<platform>:<dm|group>:<chatId>` in `adapters/base.js:98-101` echoes openclaw's `agent:<agentId>:main` convention in `../openclaw/docs/gateway/sandboxing/modes-scope-and-backend.md`).
- License: MIT (`LICENSE.md`).
- Stack: Node 18+, plain ESM JavaScript (no TypeScript, no tests, no CI), 32 files, ~5.5k LOC. Deps (`package.json`): `@anthropic-ai/claude-agent-sdk ^0.1.0`, `@composio/core latest`, `@opencode-ai/sdk latest`, `@whiskeysockets/baileys`, `node-telegram-bot-api`, `zod`, `pino` (declared, unused: all logging is `console.log`), `dotenv`, `qrcode`. Two `latest` pins = unpinned supply chain (CONFIRMED).

## What it is

A single-agent "personal 24x7 assistant" gateway: WhatsApp/Telegram/Signal/iMessage adapters feed a per-chat FIFO queue that drives one Claude Agent SDK `query()` per message, with Claude Code's built-in tools (`Read, Write, Edit, Bash, Glob, Grep`, `config.js:41`), three in-process MCP servers (cron, gateway messaging, AppleScript), and Composio's remote MCP "Tool Router" for 500+ SaaS apps (`gateway.js:38-53`). Memory is markdown files in `~/secure-openclaw/`; reminders are a JSON job file. Docker/Compose is for VPS deployment, not for sandboxing (`Dockerfile`, `docker-compose.yml`, README "Deploying Remotely"). "Secure" in the name refers to per-platform sender allowlists and Composio-managed OAuth (INFERRED from README "Security" and "App Integrations" sections; nothing else in the tree is security-specific).

## Orchestration model

None. One agent identity (`agentId: 'secure-openclaw'`, `config.js:4`), one SDK session per chat resumed by session id (`providers/claude-provider.js:87-92`, `sessions/manager.js`), one FIFO queue per session key with position/wait feedback (`agent/runner.js:80-179`). No delegation, no sub-agents, no roles, no planner. Cron jobs may re-enter the agent with `invoke_agent: true` (`tools/cron.js:57-111`; executed in `gateway.js:83-119`). Provider abstraction (`providers/base-provider.js`) lets the chat switch `/model` and `/provider` (claude vs opencode) at runtime from any allowed chat (`commands/handler.js:232-346`).

## Agent roster / roles found

- Exactly one: "You are Secure OpenClaw, a personal AI assistant" system prompt built per run in `agent/claude-agent.js:11-165`. The prompt embeds the whole memory context, the cron job list, tool-selection rules ("Use Composio tools for everything"), and instructions to start the gateway itself via `npm start &` (`claude-agent.js:131-138`).
- No manifests, no tiers, no per-role tool scoping. `allowedTools` is one flat list plus hard-coded MCP tool names (`claude-agent.js:194-225, 327`).

## Memory model

- `memory/manager.js`: `MEMORY.md` (curated long-term) + `memory/YYYY-MM-DD.md` (append-only daily) + optional topic files. `getMemoryContext()` (lines 142-161) concatenates long-term + yesterday + today and the agent code injects it wholesale into the system prompt (`claude-agent.js:57-58`). No size cap, no summarisation, no embeddings; search is substring grep over the last 30 daily files (lines 180-205).
- The agent writes memory with its own `Write`/`Edit`/`Bash` tools; the prompt asks it to do so only when the user says "remember" (`claude-agent.js:37-55`).
- Transcripts: JSONL per session under the repo's `transcripts/` (`sessions/manager.js:6, 58-72`), gitignored, plain appendable text, not hashed.

## Tool / plugin / MCP model

- Built-in Claude Code tools by name list; in-process MCP servers built with `createSdkMcpServer` + zod (`tools/cron.js`, `tools/gateway.js`, `tools/applescript.js`); remote Composio MCP over HTTP with per-session headers handed straight to the SDK (`gateway.js:42-47`) so the agent process holds the Composio session credential.
- Tool naming follows the SDK's `mcp__<server>__<tool>` convention (`claude-agent.js:200-225`), compatible with our invariant 10.
- No tool classification, no risk levels, no allow/deny per tool beyond the flat list; under the gateway's `bypassPermissions` every Composio tool is callable (see below).

## Sandbox & security posture

Isolation
- No sandbox. Agent `Bash` runs on the gateway host as the gateway user. Docker image is deployment packaging: non-root user `claw` exists because "Claude Code refuses bypassPermissions as root" (`Dockerfile:24-25`), not as hardening. No `--read-only`, no `cap-drop`, no network policy, volume-mounted memory (`docker-compose.yml`).
- Compare openclaw: sandbox modes `off|non-main|all`, scope `agent|session|shared`, docker defaults `network: "none"`, `readOnlyRoot: true`, `capDrop: ["ALL"]`, `no-new-privileges` (`../openclaw/docs/gateway/sandboxing/modes-scope-and-backend.md`, `docker-backend.md:13,41`).

Credential handling
- `ANTHROPIC_API_KEY`, `COMPOSIO_API_KEY`, `TELEGRAM_BOT_TOKEN`, Signal number in process env of the same process that runs the agent with Bash (`config.js`, `.env.example`); `setup.sh:23-29` writes keys into `.env` with `sed`. WhatsApp session keys persist in `auth_whatsapp/` (volume). No vault, no broker, no rotation.
- Third-party SaaS OAuth (Gmail, GitHub, ...) is held by Composio; the agent receives a session-scoped MCP URL + headers (`gateway.js:42-47`; token custody server-side is INFERRED from README "On first use of an app, Composio provides an auth link").

Gates / human-in-the-loop
- README "Tool Approvals" claims permission mode `default` with Y/N approvals over chat. Code: `gateway.js:24` hard-codes `permissionMode: 'bypassPermissions'` for the messaging gateway. The approval callback is wired (`runner.js:185-263`) but under `bypassPermissions` the SDK auto-allows and does not consult `canUseTool` (INFERRED from Agent SDK permission-mode semantics), so on the messaging path the gate is dead code. Terminal chat (`cli.js:313-318, 392-470`) keeps `default`, so approvals work only there. Cron-triggered agent runs pass no `canUseTool` at all (`gateway.js:98-104`).
- Approval resolution: a pending approval is keyed by `chatId` and the next message from anyone in that chat resolves it (`gateway.js:267-275`); no approver identity, no logging of the decision. Timeout 120 s resolves to deny with `interrupt: true` (`gateway.js:125-150`, `runner.js:253-255`).
- Compare openclaw: exec approvals with `deny|allowlist|ask|auto|full`, stricter-of policy composition, executable identity binding and re-check before launch (`../openclaw/docs/tools/exec-approvals.md`); DM pairing codes with expiry and per-channel caps (`../openclaw/docs/channels/pairing.md`); a written threat model (`../openclaw/docs/security/THREAT-MODEL-ATLAS.md`). secure-openclaw has none of these.

Ingress control
- Per-platform `allowedDMs` / `allowedGroups`, empty list = all blocked, `*` must be explicit, `respondToMentionsOnly` in groups, blocked senders logged (`adapters/base.js:62-89`, `config.js:1`), effective policy printed at startup (`gateway.js:160-167`). WhatsApp auto-allows self-DM and maps phone JIDs to LIDs (`adapters/whatsapp.js:84-97, 218-234`). Images are downloaded only after allowlist and mention gating pass (`adapters/whatsapp.js:289-318`).
- No prompt-injection handling: any allowed sender (or any member of a `*` group) drives an agent with host Bash, 500+ SaaS tools, `broadcast_message` to any chat, and arbitrary AppleScript.

Other defects found while reading
- `tools/applescript.js:81, 103-106` interpolate unescaped user strings into AppleScript (`tell application "${args.app_name}"`), an injection on top of `run_script` which already executes arbitrary AppleScript (lines 37-52).
- Module-global mutable "current context" for cron and gateway tools (`tools/cron.js:226-233`, `tools/gateway.js:7-16`) is overwritten per run; concurrent sessions race and scheduled messages can be bound to another chat's `chatId`/`platform` (CONFIRMED code shape; race is INFERRED).
- Cron expression parser honours only minute and hour; day/month/weekday are ignored (`tools/cron.js:174-193`) while the tool advertises full 5-field cron (line 310).
- HTTP status/QR server on `0.0.0.0:4096` with no auth (`gateway.js:345-381`, `docker-compose.yml:6-7`, README "ufw allow 4096"): anyone reaching the port can scan the QR and link the operator's WhatsApp.
- The model can create persistent, self-re-invoking cron jobs with no human step (`tools/cron.js`, `gateway.js:95-109`).

## BEST PARTS

1. Chat-native approval protocol shape. Evidence: `agent/runner.js:185-263`, `gateway.js:125-150`. Sector: ops-security (comms/tainted ingress), executive (approvals UX). Why: shows the minimum viable remote approval: tool name + reason + input (only if < 500 chars) + "Reply Y/N", separate numbered-option handling for clarifying questions vs permission requests, timeout resolves to deny and interrupts the run. Our Phase 4 comms agent needs exactly this envelope, but issued by the kernel gate, bound to a verified approver, and logged as an event.
2. Fail-closed ingress allowlist with explicit wildcard and a startup policy banner. Evidence: `adapters/base.js:62-89`, `config.js:1`, `gateway.js:160-167`. Sector: ops-security. Why: empty list blocks everything, `*` must be typed, every blocked sender is logged, the effective policy is printed on boot so misconfiguration is visible. Cheap and correct; pair it with openclaw-style pairing codes for our tainted Telegram/SMS ingress.
3. Security checks before attachment download. Evidence: `adapters/whatsapp.js:289-318` (allowlist, group, mention gating, then "Check for image (only after passing security checks)"). Sector: ops-security. Why: untrusted media is never fetched or parsed for a sender who would be dropped anyway; our comms adapters should keep this ordering.
4. Two-mode scheduler: "send canned message" vs "wake the agent with a task", persisted across restarts. Evidence: `tools/cron.js:57-111, 195-211`, `gateway.js:83-119`. Sector: executive (Phase 1 cron for `schedule:`), kernel. Why: notification jobs should not cost an LLM run; the distinction belongs in our manifest `schedule:` entries. We keep the split but not the model-created jobs (see bad parts).
5. Two-layer memory: curated long-term file plus dated append-only journal, with a "yesterday + today" context window and a "write only when asked" rule. Evidence: `memory/manager.js:142-161`, `agent/claude-agent.js:37-55`. Sector: kernel (memory model), executive. Why: a sane default shape for each agent's pmmcp namespace (`aos/agent/<id>`): curated facts vs daily log, small recent window in context, explicit write triggers. In ours the store is pmmcp behind tool views, never agent-writable files.
6. Broker holds third-party OAuth; agent gets a session-scoped MCP endpoint. Evidence: `gateway.js:38-53`, README "App Integrations". Sector: growth (marketing/sales/social need Gmail, HubSpot, LinkedIn, X), ops-security. Why: confirms our "credentials injected at the edge" design for SaaS reach. We would mount a Composio-like router as one MCP server behind the hub, classify its tools in `tool-views.yaml` (unknown = kernel-only), and route the MCP headers through the broker, not the agent.
7. Per-session AbortController map and normalized streaming chunk protocol across providers. Evidence: `providers/claude-provider.js:31-39, 94-104`, `providers/base-provider.js`. Sector: kernel. Why: small but clean: kill-by-session and a single chunk vocabulary (`text`, `tool_use`, `tool_result`, `done`, `aborted`, `error`) regardless of provider; our router's stream surface should be that small.

## BAD PARTS / anti-patterns

1. Gate bypassed in production while documented as on. Evidence: `gateway.js:24` (`permissionMode: 'bypassPermissions'`) vs README "Tool Approvals" and `cli.js:313-318` (default mode only in terminal). Why out: this is literally the "bypass of the gate for testing" CLAUDE.md forbids; the approval code exists but never runs on the messaging path. Cron-invoked runs (`gateway.js:98-104`) pass no approval callback at all.
2. Approval resolved by whoever speaks next in the chat. Evidence: `gateway.js:267-275`, keyed by `chatId`, groups allowed with `*`. Why out: the approver is not an identity; in a group any member (or an injected reply) approves. Our approvals are control-plane human actions with an authenticated operator and an `approval.*` event.
3. Unauthenticated HTTP server on all interfaces publishing the WhatsApp login QR. Evidence: `gateway.js:345-381`, `docker-compose.yml:6-7`, README "ufw allow 4096". Why out: violates invariant 1 outright and hands the operator's WhatsApp session to anyone on the network.
4. Agent process holds every credential and runs host Bash. Evidence: `config.js`, `.env.example`, `setup.sh:23-29`, `Dockerfile` (`npm install -g @anthropic-ai/claude-code`, agent Bash in the same container), Composio headers passed to the SDK at `gateway.js:42-47`. Why out: invariant 2; a single prompt injection exfiltrates provider, Composio, and bot tokens.
5. Arbitrary host automation tools, with an injection bug. Evidence: `tools/applescript.js:37-52` (`run_script` executes any AppleScript), lines 81 and 103-106 (unescaped interpolation into AppleScript strings); `tools/gateway.js:141-176` (`broadcast_message` to any chat). Why out: irreversible, unbounded, ungated; the injection shows why unknown tools default to `kernel-only` and why `irreversible` always needs a human.
6. Model-created persistent cron jobs that re-invoke the agent, with a broken parser and global mutable context. Evidence: `tools/cron.js:174-193` (only minute/hour honoured), `tools/cron.js:226-233` and `tools/gateway.js:7-16` (module-global context overwritten per run). Why out: self-scheduling without a human is a persistence vector; the parser silently does the wrong thing; the global context races between concurrent sessions. We use `AsyncLocalStorage` run scope and manifest-declared schedules.
7. Agent-writable memory injected wholesale into the system prompt. Evidence: `agent/claude-agent.js:57-58`, `memory/manager.js:142-161`, memory edited via the agent's own `Write`/`Edit`. Why out: a persistent prompt-injection channel with no size cap and no provenance; it is the spirit of invariant 8 (persona/instructions read-only to agents).
8. Docker as deployment, not isolation; hardening by accident. Evidence: `Dockerfile:24-25` comment, no read-only/cap-drop/network settings, `env_file: .env`. Why out: invariant 9 lists the required flags; "non-root because the SDK refuses root" is not a threat model.

## Conflicts with CLAUDE.md invariants

1. Inv 1 (loopback + bearer): HTTP server binds all interfaces, no auth (`gateway.js:378`, compose port publish).
2. Inv 2 (agents never hold credentials): provider key, Composio key/MCP headers, bot tokens all in the agent process env; Bash on the host.
3. Inv 3 (gate on every call, default deny, irreversible needs human, taint): `bypassPermissions` on the gateway path; no policy gate, no risk classes, no taint; cron runs without any approval callback; approvals resolvable by any chat member.
4. Inv 4 (two events per LLM call with tokens/cost): no LLM request/response records, no token or cost accounting; only user/assistant text in transcripts.
5. Inv 5 (redacted, hashed, chained, immutable log): no event log; `console.log` only; `pino` declared but unused; transcripts are plain appendable JSONL.
6. Inv 6 (ephemeral bounded, promotion human-only): no ephemeral agents, but the model can create indefinitely self-re-invoking cron jobs, an unbounded self-persistence path.
7. Inv 7 (unknown tools kernel-only; nested-LLM tools disabled): all 500+ Composio tools exposed with no classification; `run_script` (AppleScript) and `Bash` exposed by default.
8. Inv 8 (souls/AGENTS read-only to agents): the system prompt is partly built from files the agent writes with its own tools.
9. Inv 9 (container flags, no docker.sock/$HOME): none of the required flags; `$HOME`-equivalent workspace volume; secrets via `env_file`.
10. Inv 10 (`__` tool naming): compatible, no conflict.

## Verdict

Take the chat-approval envelope (tool + reason + truncated input + Y/N, numbered clarifying questions, timeout = deny + interrupt), the fail-closed ingress allowlist with explicit wildcard and boot-time policy banner, the check-before-download ordering, the notify-vs-invoke scheduler split, the curated-plus-journal memory shape, and the broker-holds-OAuth pattern as one classified MCP server behind our hub. Leave its entire trust model: gate bypassed in production, approvals resolved by whoever speaks next, an unauthenticated public QR endpoint, credentials in the agent's env, arbitrary AppleScript with an injection bug, model-created self-invoking cron jobs, agent-writable memory in the system prompt, and Docker used as packaging rather than isolation. Against both our invariants and openclaw's own current controls (pairing codes, exec approvals with binary binding, sandbox defaults of no egress/read-only/cap-drop, a written threat model), this project is strictly weaker on every axis; it earns "secure" only through sender allowlists.
