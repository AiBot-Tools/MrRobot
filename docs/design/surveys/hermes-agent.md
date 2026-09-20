# Survey: hermes-agent (Nous Research)

Clone: `refs/hermes-agent`
All paths below are relative to that clone. CONFIRMED = read in the clone; INFERRED = deduced from what was read.

## Identity

| Field | Value | Evidence |
|---|---|---|
| Repo (clone remote) | `AiBot-Tools/hermes-agent` (a fork clone) | `git remote -v` |
| Upstream | `NousResearch/hermes-agent` | `README.md` badge links, `SECURITY.md` §1 advisory URL |
| License | MIT, (c) 2025 Nous Research | `LICENSE` |
| Commit | `6621e8aa98c0aa90bd20fe4b86c3bbc764b5dffb` 2026-09-19 | `git log -1` |
| Version | 0.21.3 | `pyproject.toml` |
| Stack | Python >=3.11,<3.14; OpenAI SDK as the wire (`openai==2.24.0`), native Anthropic/Bedrock/Gemini/Vertex adapters in `agent/*_adapter.py`; every direct dep exact-pinned (supply-chain rationale in `pyproject.toml` comments); Node for TUI (`ui-tui/`), Electron desktop (`apps/`), Docusaurus docs (`website/`) | `pyproject.toml`, `AGENTS.md` |
| Size | `agent/` alone ~109k lines across ~350 modules; `tools/` similar | `wc -l agent/*.py` |

## What it is

CONFIRMED (`AGENTS.md`, `README.md`): a single-tenant *personal* agent. One `AIAgent` core (`run_agent.py`, turn loop in `agent/turn_*.py`) reused by CLI, a messaging gateway (~20 platforms as `plugins/platforms/*`), a TUI, and a desktop app. Selling points: a "learning loop" (agent-curated `MEMORY.md`/`USER.md`, autonomous skill creation, skills that self-patch, FTS5 session search, Honcho user modeling), `delegate_task` subagents, a cron scheduler, a durable Kanban board for multi-profile collaboration, seven terminal backends (local/Docker/SSH/Singularity/Modal/Daytona/Vercel), and an egress credential-injection proxy for the Docker backend. Trajectories are saved in ShareGPT JSONL for training data (`website/docs/developer-guide/trajectory-format.md`).

Two governing design invariants (`AGENTS.md`): **prompt-cache is sacred** (system prompt byte-stable for a conversation; memory is a frozen snapshot; toolsets never swap mid-conversation) and **narrow-waist core, capability at the edges** (the "Footprint Ladder": extend existing → CLI+skill → `check_fn`-gated tool → plugin → MCP server → new core tool last).

## Orchestration model

Three distinct primitives, deliberately separated (CONFIRMED `website/docs/user-guide/features/kanban.md` "Kanban vs delegate_task" table):

1. **`delegate_task` — fork/join subagents** (`tools/delegate_tool.py` + `delegate_tool_*.py` siblings).
   - Child = fresh `AIAgent`, fresh conversation, own `task_id` (own terminal session and file-ops cache), a system prompt built from `goal` + `context`, and the parent's toolsets **minus** a blocked set. "The parent only ever sees the delegation call and the summary result."
   - Model-facing schema (`DELEGATE_TASK_SCHEMA`, `tools/delegate_tool.py:631`): `tasks[]` of `{goal, context, output_schema, images, group}` plus live-control `action: spawn|list|steer|stop`. **No model-facing `toolsets` or `model` parameter** — "Nested delegation is granted by depth/role in `_build_child_agent`, never by the model naming toolsets" (`tools/delegate_tool.py:56`). Model/provider pinning is config-only (`delegation.model/provider/base_url`, `_DESCRIPTION_TAIL`).
   - Roles `leaf | orchestrator` (`_ROLES`); orchestrator re-gains `delegate_task` only when `delegation.max_spawn_depth` > 1 (default 1 = flat). Kill switch `delegation.orchestrator_enabled`.
   - `DELEGATE_BLOCKED_TOOLS = {delegate_task, clarify, memory, send_message, cronjob_manage}` (`tools/delegate_tool_toolsets.py:14`); children "never gain a tool the parent lacks" (`_resolve_child_toolsets`, intersection against parent's composite-expanded set).
   - Limits: `max_concurrent_children` default 10, **floor 1, no ceiling**; `max_spawn_depth` floor 1, **no ceiling**; child iteration budget default 50 (`agent/iteration_budget.py`); **no default child wall-clock** (`DEFAULT_CHILD_TIMEOUT = None`, `tools/delegate_tool_config.py:25`) — stuck children caught by a heartbeat staleness monitor (450 s idle / 1200 s in-tool, `tools/delegate_tool.py:76-81`).
   - Top-level delegations always run in the background; results re-enter as a new user turn between the parent's turns. Process-local: "/stop, /new, or process exit halts running subagents (whole tree)".
   - Tool description literally tells the parent: "Child summaries are SELF-REPORTS, not verified facts ... require a verifiable handle (URL, ID, absolute path) and verify it yourself" and "Children cannot close tracked work" (`_DESCRIPTION_HEAD`).
   - `output_schema`: child told up front, parent validates with one bounded correction retry, raw text never discarded.
   - Public plugin-facing lifecycle API (`agent/subagent_lifecycle`, doc `website/docs/developer-guide/subagent-lifecycle-api.md`): serializable capability handle, states PENDING..CANCELLED/UNKNOWN, cooperative cancel, results bounded to 32k chars with a stable hash, "fail-closed: unknown or parent-broadening toolsets are rejected", no reconnect after process restart.
   - Subagent worker threads get a **non-interactive approval callback: deny by default**, `delegation.subagent_auto_approve: true` flips to auto-approve (`tools/delegate_tool_config.py:37-59`).

2. **Kanban — durable work queue + state machine** (`plugins/kanban/`, `hermes_cli/kanban*.py`, docs `kanban.md`, `kanban-worker-lanes.md`).
   - SQLite board; task statuses `triage|todo|ready|running|blocked|review|done|archived`; links = parent→child dependencies promoted by a dispatcher loop (default 60 s) that reclaims stale/crashed workers, reaps workers that outlive their run (PID + spawn-time fingerprint), and auto-blocks a task after `kanban.failure_limit` (default 2) consecutive spawn failures.
   - Worker = a named **profile** spawned as a full OS process (`hermes -p <assignee> chat -q <prompt>`) in a pinned workspace (`scratch` | `dir:<abs path>` | `worktree`), with `HERMES_KANBAN_*` env. Board isolation is absolute (separate DB/workspaces/logs per board; `HERMES_KANBAN_BOARD` pinned).
   - **Lane contract**: assignee string + spawn mechanism + *exactly one lifecycle terminator* per run (`kanban_complete` | `kanban_request_review` | `kanban_block` | crash/gave_up/timed_out). "Worker lanes execute work but never own that truth." Reviewer (bundled `sdlc-review` skill, or human) gates `review → done`; `unblock` is orchestrator-only.
   - **PR completion contract**: `--completion-contract OWNER/REPO`; `complete_task` reads branch protection + rulesets, paginates exact-head check runs, re-reads PR head/base; missing/pending/failed *required* evidence cannot complete the card; first matching PR URL binds permanently. Durable `pr_acceptance` events.
   - Completion checkpoint at ~90% of iteration budget; "a commit or diff alone never automatically completes a task."
   - **ESTOP** (`agent/estop.py`, ported from gastown): `hermes pause` writes `$HERMES_HOME/ESTOP`; cron, dispatcher and new gateway turns skip work; in-flight never killed; corrupt sentinel still counts as engaged (fail safe).
   - Descendant fence: `agent/delegation_context.py` ContextVars make identity gates fail closed for in-process children/cron; docs are explicit this is "cooperative runtime scoping, **not OS confinement**".

3. **Cron** (`cron/`): job store + tick loop; per-job `model/provider` override, pre-run `script`, `context_from` chaining, `workdir`. Hardening invariants in `cron/AGENTS.md`: inactivity watchdog (600 s idle), at-most-once occurrence accounting (`next_run_at` advanced *before* dispatch, `pending_slot` stamped in the same save), per-home tick lock, `skip_memory=True` for cron sessions.

Also present: **MoA** (`agent/moa_loop.py`, per-turn mixture-of-agents with a PII/secret redactor on advisor outputs), a **background review fork** after each turn that decides whether to save memory/skills (`agent/background_review.py`; inherits the parent's live credentials and prefix cache), and a **curator** for skill lifecycle (`agent/curator.py`, "never delete, only archive").

## Agent roster / roles found

There is **no fixed roster**; roles are structural, and specialists are operator-defined profiles + skills.

| Role | Where | Notes |
|---|---|---|
| Parent agent / orchestrator (depth 0) | `run_agent.py`, `tools/delegate_tool.py` | Any session |
| `leaf` / `orchestrator` subagent | `tools/delegate_tool.py:52` `_ROLES` | Capability derived from depth, not model input |
| Kanban worker profile (named, persistent memory) | `plugins/kanban`, `kanban-worker-lanes.md` | Assignee = profile name or plugin lane (Codex/Claude Code/OpenCode wrappers mentioned as lane shapes) |
| Reviewer | `kanban_request_review` + bundled `sdlc-review` skill | Human or human-proxy gates `done` |
| Guardian ("smart approvals") LLM | `tools/approval_smart.py` | Auxiliary LLM returns APPROVE/DENY/ESCALATE on flagged shell commands |
| Auxiliary task models | `agent/auxiliary_client.py`, `hermes_cli/config_defaults.py:703` | Per-task `auxiliary.<task>` provider/model/reasoning_effort for compression, vision, approval, ... |
| Background review fork / curator fork | `agent/background_review.py`, `agent/curator.py` | Self-improvement writers |
| MoA advisors | `agent/moa_loop.py` | Reference models per turn |
| Skills (bundled categories) | `skills/`: `social-media`, `software-development`, `research`, `creative`, `devops`, `email`, `autonomous-ai-agents`, `productivity`, `web`, `media`, `note-taking`, `apple`; `optional-skills/`: adds `blockchain`, `security`, `mlops`, `communication`, ... (58 `SKILL.md` in `skills/`) | `skills/AGENTS.md`; contents of `blockchain`/`social-media` skills NOT read (INFERRED to be procedure docs, not agents) |
| Personas | `SOUL.md` (single default persona; users add their own) | Loaded through the injection scan in `agent/prompt_builder.py:82` |

## Memory model

CONFIRMED:
- Builtin: `MEMORY.md` (agent notes, default cap 2200 chars) + `USER.md` (user profile, 1375 chars), one `memory` tool with `add/replace/remove` + batch. Both enter the system prompt as a **frozen snapshot at session start**; mid-session writes hit disk but never change the prompt (`tools/memory_tool.py:1-6`).
- **Write-approval gate** (`tools/write_approval.py`): per-subsystem boolean for `memory` and `skills`; **default `false` = writes freely**; `true` stages writes under `<HERMES_HOME>/pending/{memory,skills}/<id>.json` for out-of-band review.
- Provenance ContextVar separates `foreground` vs `background_review` writes (`tools/skill_provenance.py`), so curator/ledger/approval guards can key on origin; `is_unattended_review()` gates memory deletes.
- `session_search` tool: FTS5 over past sessions with LLM summarization (`hermes_state_fts.py`, `hermes_state_search.py`).
- Pluggable `MemoryProvider` ABC (`agent/memory_provider.py`): builtin always on, **exactly one** external plugin at a time (`plugins/memory/{honcho,mem0,supermemory,hindsight,byterover,holographic,openviking,retaindb}`); lifecycle initialize → `system_prompt_block`/`prefetch`/`sync_turn` per turn → tool dispatch → shutdown; v2 fail-closed pre-compress checkpoint. Trivial-prompt gate skips recall for greetings.
- Honcho plugin filters machine-generated gateway/delegation notifications out of durable memory (`plugins/memory/honcho/__init__.py:37`).
- Children are blocked from `memory` ("no writes to shared MEMORY.md"); cron runs `skip_memory=True`.
- Skills = the second memory: agent-created skills tracked by `tools/skill_usage.py`, curated/archived by `agent/curator.py` (only `created_by: "agent"` skills; pinned exempt; never deletes). `agent/learning_graph.py` renders memory+skills as a graph for the desktop.

## Tool / plugin / MCP model

CONFIRMED:
- **Toolsets** (`toolsets.py`): named groups over a flat `_HERMES_CORE_TOOLS` list (terminal, file, web, browser, vision, image/video gen, tts, todo, memory, session_search, clarify, execute_code, delegate_task, cronjob_manage, HA, kanban, computer_use, ...). Platform bundles `hermes-*`; `_HERMES_WEBHOOK_SAFE_TOOLS = [web_search, web_extract, vision_analyze, clarify]` for untrusted webhook payloads; `disabled_toolsets` is a strict end-of-pipeline subtraction. "Surface capability is a property of the SESSION, never of the process env" (`AGENTS.md`).
- **`check_fn` service gating**: a tool appears only when its prerequisite is configured; results TTL-cached process-wide (`tools/registry.py`).
- **`execute_code`**: Python scripts that call tools via RPC "collapsing multi-step pipelines into zero-context-cost turns"; iterations refunded from the budget (`agent/iteration_budget.py`); has its own guard entry `check_execute_code_guard` (`tools/approval.py` header).
- **Plugins** (`plugins/`, `hermes_cli` loader): load **into the agent process with full agent privileges** (`SECURITY.md` §2.5). Categories: platforms, memory, model-providers, browser, context_engine, cron_providers, image/video gen, kanban, dashboard_auth, observability, security-guidance.
- **Skills**: `SKILL.md` + `scripts/ references/ templates/`, agentskills.io-compatible; hardline authoring standards enforced by tests (`skills/AGENTS.md`). Hub install from GitHub/ClawHub/skills.sh/official (`tools/skills_hub_*.py`). **Skills Guard** (`tools/skills_guard.py`): regex static scan, trust tiers `builtin/trusted/community/agent-created` with an `INSTALL_POLICY` matrix (community: any finding blocks unless `--force`; `TRUSTED_REPOS = {openai/skills, anthropics/skills, huggingface/skills, NVIDIA/skills}`). Explicitly "a review aid", not a boundary.
- **MCP client** (`tools/mcp_tool*.py`, 20+ modules): stdio/HTTP transports, OAuth incl. device flow, schema cache, "death supervisor", circuit breaker/cooldowns, per-profile connection keys (`tools/mcp_tool_scope.py`), **sampling handler** (`tools/mcp_tool_sampling.py`: servers may issue `sampling/createMessage` and the agent answers with its own LLM client, including tool-use blocks) and elicitation. Children inherit parent MCP toolsets by default (`delegation.inherit_mcp_toolsets`, default true).
- Supply chain: exact pins, `<next_major` upper bounds required, SHA-pinned actions, `supply-chain-audit.yml` CI (`CONTRIBUTING.md:888-927`).

## Sandbox & security posture

CONFIRMED from `SECURITY.md` (unusually candid) and code:

- **Trust model statement**: "The only security boundary against an adversarial LLM is the operating system. Nothing inside the agent process constitutes containment — not the approval gate, not output redaction, not any pattern scanner, not any tool allowlist." Two postures: *terminal-backend isolation* (shell + file tools in a container; **does not** confine `execute_code`, MCP subprocesses, plugins, hooks, skill loading) and *whole-process wrapping* (their Docker image, or NVIDIA OpenShell with L7 egress + provider-store credential injection). Running the default local backend with untrusted input is "outside the supported security posture."
- **Approvals** (`tools/approval*.py`, `website/docs/user-guide/security.md`): order is *floors first* — hardline blocklist (`rm -rf /`, fork bomb, `mkfs`, `dd` to block device, curl|sh at rootfs), `sudo -S` stdin guard, and user `approvals.deny` fnmatch globs (matched over de-obfuscated command variants) fire **before** yolo/`mode: off`/cron approve; then `approvals.mode: smart|manual|off`. `smart` is the **default**: an auxiliary LLM auto-approves "clearly safe", auto-denies "genuinely dangerous", escalates uncertain (`tools/approval_smart.py`; comments stripped, `<command>` delimiters, operator policy only in system prompt). Consecutive-denial circuit breaker (default 3). Timeout 300 s → deny. Unattended surfaces (`cron_mode`, `single_query_mode`, `unattended_mode`) default **deny**. `HERMES_YOLO_MODE` frozen at import so a skill can't flip it at runtime (`tools/approval.py:45`). A separate non-overridable guard stops the agent killing its own supervised gateway.
- **Docker backend** (`tools/environments/docker.py`): `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`, `--cpus/--memory` (probed, skipped where cgroups unavailable), `--user uid:gid`, optional `--network=none` (`docker_network: true` by default). `--read-only` **not found** by grep (INFERRED absent). `docker_volumes`, `docker_extra_args`, `docker_run_as_host_user` are operator knobs; the egress module guards `docker_forward_env/docker_env/docker_extra_args` from overriding proxy env.
- **Egress proxy (iron-proxy)** (`tools/environments/docker_egress.py`, `agent/proxy_sources/iron_proxy.py`, docs `egress/iron-proxy.md`, `egress-internals.md`): Go MITM proxy on the host; sandbox holds **opaque proxy tokens under the real env names** (`OPENROUTER_API_KEY=<token>`), CA mounted read-only, `HTTPS_PROXY/HTTP_PROXY` + every CA-bundle var set, `NO_PROXY` loopback only; proxy swaps token→real secret; default upstream host allowlist (provider APIs) + `extra_allowed_hosts` wildcards; **SSRF deny CIDRs by default** (loopback, link-local incl. metadata IP, RFC1918, ULA, CGNAT); `enforce_on_docker: true` = sandbox **refuses to start** if proxy enabled but not running/misconfigured; credential source `env` or Bitwarden Secrets Manager. Docker backend only; explicitly does not cover host-process LLM calls.
- **Credential scoping**: subprocess env stripped of provider keys/gateway tokens (`tools/environments/local_env_policy.py` `_HERMES_PROVIDER_ENV_BLOCKLIST`, `_ALWAYS_STRIP_KEYS`), MCP subprocesses and cron scripts too; declared pass-throughs allowed. Under gateway multiplexing, `agent/secret_scope.py` installs a **ContextVar secret scope that raises rather than fall back to `os.environ`** (`UnscopedSecretError`); `tools/terminal_scope.py` does the same for `TERMINAL_*` policy with a refusal scope (`TerminalPolicyUnavailable`). `agent/credential_pool.py`: multi-credential same-provider failover with cooldowns. `agent/vault_store.py`: Fernet-encrypted browser-autofill vault, **model sees opaque handles only**; fill resolved server-side (design ported from OpenInstinct).
- **Model fallback** (`hermes_cli/fallback_config.py`, `agent/fallback_cooldown.py`): ordered `fallback_providers` chain deduped by (provider, model, base_url); primary rate-limit cooldown 60 s → 4 h exponential on consecutive 429s; per-session dead (provider, model) marking to stop oscillation. Children: pinned children **never borrow the parent's chain**; endpoint-trust `capabilities` inherited only on the exact same route, else default-deny (`_inherit_parent_capabilities`, `tools/delegate_tool_config.py`).
- **Inbound**: gateway platform allowlists + DM pairing (`gateway/platforms/base.py`, `hermes pairing approve`); "an allowlist is required for every enabled network-exposed adapter"; local surfaces loopback-bound; `--host 0.0.0.0` is documented break-glass. "Within the authorized set, all callers are equally trusted" — no per-caller capabilities.
- **Prompt-injection scan** of context files (AGENTS.md, .cursorrules, SOUL.md): matches are BLOCKED from loading (`agent/prompt_builder.py:82-108`).
- **File safety** (`agent/file_safety.py`): denylist for credential stores; header says "defense-in-depth, NOT a security boundary".
- **Evals** (`evals/`, 69 entries): mostly regression probes per issue; `evals/postmortem/` is a forensics + live A/B harness built after a **1,393-agent, $19.3k run** (`evals/postmortem/README.md`): observed cost buckets (cache writes $11.2k of $19.3k; depth-2 subagents 65% of cost; 332 nested `delegate_task` timeouts; 579 hardline false blocks), labeled OBSERVED vs MODELED.

## BEST PARTS

1. **Delegation contract that assumes the child lies and cannot broaden itself.**
   Evidence: `tools/delegate_tool.py:560-590` (`_DESCRIPTION_HEAD`: "Child summaries are SELF-REPORTS ... require a verifiable handle ... verify it yourself"; "Children cannot close tracked work"), `tools/delegate_tool_toolsets.py` (`DELEGATE_BLOCKED_TOOLS`, intersection-only child toolsets), `tools/delegate_tool.py:56` (capability by depth/role, never by model-named toolsets), `subagent-lifecycle-api.md` (parent-broadening toolsets rejected, bounded immutable results with hash). CONFIRMED.
   Sector: **kernel** (ephemeral templates, invariant 6) and **engineering** (coding fleet fan-out).
   Why: this is exactly invariant 6 expressed as tool schema + resolver: the model never chooses its own capabilities, and the parent is told in-band to distrust the summary. Our `scout/checker/worker` templates should copy the "no model-facing toolsets/model params", the `output_schema` + one-bounded-retry validation, and the "verifiable handle" rule for any side-effecting child.

2. **Per-child model routing as one immutable bundle, with fallback chains that do not leak across trust routes.**
   Evidence: `tools/delegate_tool_config.py` `_resolve_child_runtime` ("provider/base_url are one bundle: all from the override, or all from the parent"; api_mode re-derived per provider; pinned transport must exist on PATH or spawn fails loudly), `_resolve_child_fallback_chain` (pinned children never borrow the parent chain; `[]` disables), `_inherit_parent_capabilities` (endpoint trust is per provider+endpoint, default-deny on any override), `hermes_cli/fallback_config.py` (chain dedup), `agent/fallback_cooldown.py` (60 s→4 h exponential cooldown, per-session dead-model marking). CONFIRMED.
   Sector: **kernel** (`src/models/router`), all fleet sectors.
   Why: our per-agent model binding needs the same rules: a bound model carries its own chain; a chain is a property of the manifest, not inherited from the spawner; "trust" of an endpoint is a kernel decision keyed on (provider, base_url), never a model input. The cooldown/dead-marking logic prevents the 429 oscillation we will hit with local llama.cpp + hosted mixes.

3. **Cheap auxiliary model lanes per side-task.**
   Evidence: `agent/auxiliary_client.py` header (text auto chain main → OpenRouter → Nous → custom → native Anthropic → direct; `free_only`), `hermes_cli/config_defaults.py:696-726` (`auxiliary.<task>` blocks: provider/base_url/api_key/reasoning_effort/extra_body per task: compression, vision, approval, ...; "Each task is independent — main-agent provider_routing ... do NOT propagate to aux calls by design"), `delegation.reasoning_effort` override. CONFIRMED.
   Sector: **kernel** router, **ops-security** (cost control).
   Why: our router should expose named lanes (`summarize`, `classify`, `vision`, `embed`) bound to cheap/local models (Bonsai on llama.cpp) independent of the agent's primary binding, each still emitting `llm.request/response` events with cost.

4. **Kanban worker-lane contract: the kernel owns lifecycle truth, workers only execute, one terminator per run, reviewer gates done, PR completion verified against required checks.**
   Evidence: `website/docs/user-guide/features/kanban-worker-lanes.md` ("Worker lanes execute work but never own that truth"; assignee + spawn + exactly one of complete/request_review/block; crash/gave_up/timed_out are kernel-emitted), `kanban.md` (PR completion contract reads branch protection + rulesets, required-check evidence, first PR URL binds permanently; `failure_limit` auto-block; dispatcher reclaims crashed workers by PID + spawn fingerprint; tenants soft / boards hard isolation), `agent/estop.py` (fail-safe global pause). CONFIRMED.
   Sector: **executive** (CEO → pmmcp goal tree), **engineering** (coding fleet with reviewer/QA lanes).
   Why: this is the missing "restart-safe projections" and "kernel updates task goal status on run start/finish" from our Phase 1, plus a concrete shape for the coding fleet: implementer lane → `review` → reviewer (auditor) approves/requests changes → `done` only with external evidence. The PR-acceptance gate is the model for our Phase 2 exit criterion ("opens a PR"). ESTOP is a one-file idea worth copying for the control plane.

5. **Egress credential-injection proxy with fail-closed enforcement and SSRF defaults.**
   Evidence: `tools/environments/docker_egress.py` (opaque tokens under real env names; `_PROXY_CONTROL_ENV` override guard; `enforce_on_docker` raises on any half-configured state; CA mounted `:ro`; `NO_PROXY` loopback only), `website/docs/user-guide/egress/iron-proxy.md` (default host allowlist, `upstream_deny_cidrs` incl. 169.254.169.254, Bitwarden source, `allow_env_fallback: false`), `egress-internals.md` (module layout, ~70 hermetic tests + gated live E2E). CONFIRMED.
   Sector: **ops-security** (Phase 2 egress sidecar), **engineering** (T2 coding agents), **trading** (any exchange key must go through this, never into a container).
   Why: it is a working reference implementation of invariant 2's "credentials injected at the egress proxy edge, never in env or files", including the two things easy to forget: refuse to start the sandbox when the proxy is down, and deny RFC1918/metadata upstreams so a proxied worker cannot pivot to the host network.

6. **Policy floors run before any bypass, and unattended surfaces default to deny.**
   Evidence: `tools/approval_floors.py` (hardline, sudo-stdin, user deny globs "BEFORE the yolo / mode=off bypass", matched over de-obfuscated variants), `tools/approval.py:45` (`_YOLO_MODE_FROZEN` at import "so a skill running in the process can't set this and bypass every approval check"), `security.md` (`cron_mode/single_query_mode/unattended_mode` default `deny`; timeout → deny; expired prompt cannot be reopened), `tools/delegate_tool_config.py:37-59` (subagent approval callback deny-by-default). CONFIRMED.
   Sector: **kernel** policy gate, **ops-security**.
   Why: our gate ordering should be the same: static denies (irreversible risk, tainted+write, kernel-only tools) are evaluated before approvals and can never be approved away; runs with no human attached (cron, tainted ingress) resolve "needs human" to deny + `approval.requested` event, never block indefinitely.

7. **Self-modification is provenance-tagged, stageable, and never destructive.**
   Evidence: `tools/write_approval.py` (per-subsystem gate that stages memory/skill writes to `pending/` for out-of-band review), `tools/skill_provenance.py` (`foreground` vs `background_review` ContextVar; attended vs unattended), `agent/curator.py` ("never delete, only archive"; pinned skills exempt), `tools/skills_guard.py` (trust-tier install matrix, `agent-created` tier can be forced to "ask"), `tools/skill_manager_guards.py`. CONFIRMED.
   Sector: **kernel** memory/skills, **executive** (CEO learning loop).
   Why: matches invariant 8's spirit and "archive never deletes" (invariant 6). For our fleet, any agent-proposed change to a manifest, soul, or shared pmmcp memory should be a staged proposal with origin metadata that a human promotes, which is exactly this design with `write_approval: true` as the only allowed setting.

8. **Post-mortem forensics harness on a real fleet-scale run.**
   Evidence: `evals/postmortem/README.md` (recomputes from a copied `state.db`: cost buckets, per-call cache behaviour, nested-delegate timeouts, batch-join delay, tool friction, rework inventory; OBSERVED vs MODELED labeling; live A/B probes against fake providers; reference numbers: $19.3k, depth-2 = 65% of cost, 332 nested timeouts, 579 hardline false blocks). CONFIRMED.
   Sector: **executive** / **kernel** (eval harness, budgets).
   Why: our Phase 1 eval harness should be able to answer the same questions from the hash-chained event log alone (which is a better substrate than their session DB). The findings themselves are design input: nested delegation depth and cache-write churn dominate cost, so the fleet should default to depth 1 and short-lived children with the 5 m cache tier (`_apply_child_cache_ttl`).

## BAD PARTS / anti-patterns

1. **A guardian LLM makes the access-control decision by default.**
   Evidence: `tools/approval_smart.py` (auxiliary LLM answers APPROVE/DENY/ESCALATE; APPROVE executes the command with no human), `security.md` ("smart (default) ... Low-risk commands are auto-approved"). The file itself says the command text is untrusted and may be prompt-injected. CONFIRMED.
   Why we leave it out: invariant 3 — "The model never makes an access-control decision." An LLM classifier can be a *hint* attached to the approval request for the human, never a decider. Their own SECURITY.md §2.4 concedes the gate "catches cooperative-mode mistakes, not adversarial output."

2. **Plugins, skills and hooks execute inside the agent process with full credentials; default backend is the host shell.**
   Evidence: `SECURITY.md` §2.2-2.5 ("everything the agent does in its own Python process" is unconfined under terminal-backend isolation; "Any component running inside the agent process ... can read whatever the agent itself can read, including in-memory credentials"; env scrubbing "is not containment"), `tools/environments/local.py` default. CONFIRMED.
   Why we leave it out: invariant 2. Our extension points are MCP servers behind the hub with tool-view classification and packs, never in-process code. Their own footprint ladder already prefers "MCP server in the catalog" over plugins; we take that rung only.

3. **Configurable total bypasses: YOLO, `approvals.mode: off`, `subagent_auto_approve`, `cron_mode: approve`.**
   Evidence: `security.md` YOLO section, `tools/delegate_tool_config.py:37-59`, `approvals` config table. CONFIRMED.
   Why we leave it out: CLAUDE.md "Never: add a bypass of the gate"; irreversible always requires a human. The only Hermes bits that survive are the *floors* (item 6 above), which exist precisely because the bypasses do.

4. **Unbounded fan-out and no default child wall-clock.**
   Evidence: `tools/delegate_tool_config.py` (`max_concurrent_children` "no ceiling", `max_spawn_depth` "no ceiling", `DEFAULT_CHILD_TIMEOUT = None`: "No default wall-clock cap on children"), and their own post-mortem (`evals/postmortem/README.md`: 332 nested timeouts, 242.6 h of sleep after first timeout, depth-2 = 65% of $19.3k). CONFIRMED.
   Why we leave it out: invariant 9 (hard wallclock) and "never disable the wallclock, budget, or retry caps". Templates carry hard caps; lanes cap concurrency; depth is a manifest field with a kernel ceiling.

5. **Self-improving writes default to unattended; community skills install with a regex scan as the gate.**
   Evidence: `tools/write_approval.py` (`write_approval` default `false` "writes freely"), `agent/background_review.py` (fork after every turn writes memory + skills, inherits live credentials), `tools/skills_guard.py` header ("Known gap: language write APIs ... static regexes cannot tie the call to a dynamic destination"), `SECURITY.md` §2.4 ("skills execute arbitrary Python at import time"). CONFIRMED.
   Why we leave it out: a prompt-injected run could persist instructions into shared memory or a skill that every future run loads; with invariant 8 (souls/AGENTS.md read-only to agents) we extend read-only to skills and make memory writes to `aos/shared` a staged proposal. We keep the staging mechanism (item 7), not the default.

6. **MCP servers may drive the agent's LLM (sampling) and `execute_code` batches tool calls outside the per-call loop.**
   Evidence: `tools/mcp_tool_sampling.py` (handles `sampling/createMessage` with tool-use results via the agent's client), `toolsets.py` `code_execution` ("Run Python scripts that call tools programmatically (reduces LLM round trips)"), `SECURITY.md` §2.2 (code-execution runs as a host subprocess outside terminal-backend isolation). CONFIRMED; whether every RPC'd tool call passes the approval gate individually is INFERRED-partial (a `check_execute_code_guard` exists in `tools/approval.py` but was not traced).
   Why we leave it out: invariant 7's rationale ("nested LLM calls bypass router, budgets, taint, log") applies to MCP sampling; invariant 3 requires the gate on *every* tool call, so a scripted RPC path must still go through hub → gate → log per call or not exist.

7. **Flat trust inside an authorized set; kanban workspaces and fences are cooperative.**
   Evidence: `SECURITY.md` §2.6 rule 4 ("all callers are equally trusted ... run separate agent instances" for capability separation), `kanban.md` (`dir:<path>` "trusted — it's your box"; descendant fence "cooperative runtime scoping, not OS confinement"). CONFIRMED.
   Why we leave it out: our taint model (Telegram/SMS as tainted ingress that cannot write without a human) is per-run, per-source, and enforced by the kernel, not by which profile a message reached.

## Conflicts with CLAUDE.md invariants

Numbered by the CLAUDE.md invariant they touch.

1. **Inv 1 (loopback + bearer)** — Compatible: local surfaces loopback-bound, `--host 0.0.0.0` is documented break-glass (`SECURITY.md` §2.6 rule 5). No conflict to import.
2. **Inv 2 (agents never hold keys)** — CONFLICT: plugins/skills/hooks in-process with credentials (§2.5); default local terminal has host env minus a blocklist; sandboxes hold real keys unless iron-proxy is enabled. Only the iron-proxy posture is compatible.
3. **Inv 3 (gate → human → quarantine → execute → log; model never decides access)** — CONFLICT: `approvals.mode: smart` default lets an LLM approve; YOLO/off/auto-approve bypasses exist; no taint concept (webhook payloads get a reduced toolset, `_HERMES_WEBHOOK_SAFE_TOOLS`, which is a static allowlist, not run-level taint).
4. **Inv 4 (two events per LLM call with cost)** — Partial: usage/cost rows in `hermes_state_usage.py` and trajectories exist; aux calls (`call_llm`) and MCP sampling calls are accounted separately or not at all (INFERRED). Not a hash-chained event log.
5. **Inv 5 (redacted, canonicalized, hashed, chained; immutable)** — CONFLICT by absence: session DB is mutable SQLite with rewind/repair modules (`hermes_state_rewind.py`, `hermes_state_repair.py`); `kanban.md` itself notes delegate_task audit trail is "lost on context compression".
6. **Inv 6 (ephemeral bounded by template; promotion human-only; archive never deletes)** — Mostly compatible: children intersect the parent's toolsets and cannot broaden; curator archives never deletes. Gap: no template/tier concept; `orchestrator` role re-adds delegation to a child.
7. **Inv 7 (unknown tools kernel-only; nested-LLM tools disabled)** — CONFLICT: MCP sampling honoured; `execute_code` RPC path; child MCP toolsets inherited by default.
8. **Inv 8 (souls/AGENTS.md read-only to agents)** — CONFLICT: `memory` tool writes `MEMORY.md/USER.md`, `skill_manage` writes skills, background review writes both; `file_safety` is declared "NOT a security boundary"; Skills Guard has patterns for skills that try to modify `SOUL.md`/`AGENTS.md`, which means the write path exists.
9. **Inv 9 (container hardening + hard wallclock)** — Partial: `--cap-drop ALL`, `no-new-privileges`, pids/cpu/memory, non-root `--user` match; `--read-only` not present (INFERRED), network on by default, arbitrary `docker_volumes`, no default child wallclock, `docker_run_as_host_user` knob.
10. **Inv 10 (`__` tool naming)** — n/a; they use `mcp-<server>` toolset prefixes (`tools/delegate_tool_toolsets.py:_is_mcp_toolset_name`).

## Verdict

Take the delegation *contract* (no model-facing capability or model parameters, child = intersection of parent minus blocked, output-schema validation, "summaries are self-reports, demand a verifiable handle"), the per-child model bundle and non-leaking fallback chains with cooldowns, the auxiliary per-task model lanes, the Kanban lane/terminator/reviewer/PR-acceptance contract as the shape of our coding fleet and goal-status projection, the iron-proxy egress design (fail-closed enforcement, SSRF deny CIDRs, tokens under real env names) as the Phase 2 sidecar blueprint, floors-before-gates with unattended-defaults-to-deny, staged provenance-tagged self-modification, ESTOP, and the post-mortem forensics questions as our eval harness's required outputs. Leave the guardian-LLM approver, every bypass mode, in-process plugins/skills, default-unattended memory/skill writes, uncapped fan-out/depth/wallclock, MCP sampling and scripted tool RPC, and flat trust within an authorized set. Net: Hermes is a strong reference for *how a subagent is shaped and routed* and for *what a coding-fleet work queue must guarantee*, and an explicit counter-example (by its own SECURITY.md) for where the security boundary must live.
