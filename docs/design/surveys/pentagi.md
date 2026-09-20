# Survey: PentAGI

## Identity
- **Upstream**: PentAGI (vxcontrol/pentagi), "Penetration testing Artificial General Intelligence". CONFIRMED (README.md, trendshift badge repo 15161).
- **License**: MIT (LICENSE, "PentAGI Development Team 2025") plus a separate EULA.md and NOTICE. CONFIRMED.
- **Commit**: ea665308baaff015b226f308438a68d929d0f29b, 2026-08-06. CONFIRMED.
- **Stack**: Go 1.26.5 backend (REST+GraphQL/gqlgen, Gin), React+TS frontend (Apollo, Radix), PostgreSQL+pgvector (required), optional Neo4j via Graphiti; OTEL→VictoriaMetrics/Loki/Jaeger/Grafana, Langfuse+ClickHouse analytics. Docker SDK for sandboxes. CONFIRMED (backend/go.mod, CLAUDE.md, README.md).

## What it is
Autonomous + assistant-guided penetration-testing platform. A user creates a "flow" (a pentest engagement); the backend queues it and spawns a multi-agent goroutine system that plans, researches, and executes security tools inside Docker sandboxes, storing outputs/reasoning in a pgvector memory store and streaming progress to the UI over GraphQL subscriptions. CONFIRMED (README Data Flow, CLAUDE.md Project Overview).

## Orchestration model
- **Hierarchy**: Flow -> Task -> SubTask -> Action -> Artifact/Memory (ER diagram, README). Each SubTask carries an `agent_type`. CONFIRMED.
- **Agents-as-tools delegation**: the primary agent (and others) delegate by *calling a tool named after a specialist* (`coder`, `pentester`, `memorist`, `search`, `advice`, `maintenance`). In `registry.go` these map to `AgentToolType`; each has a paired result tool (`code_result`, `hack_result`, `memorist_result`, `search_result`, `enricher_result`) of `StoreAgentResultToolType` that writes the sub-agent's isolated-context output back. Barrier tools `done`/`ask` (`BarrierToolType`) end or pause a chain. CONFIRMED (backend/pkg/tools/registry.go:12-122).
- **Generator/refiner** decompose a goal into a subtask list when the flow is waiting with no active subtask (`subtask_list`, `subtask_patch`). CONFIRMED (registry.go:434, tools/args.go:300).
- **Supervision layers** (README "Advanced Agent Supervision"): (1) Execution Monitor — adviser("mentor") auto-intervenes when identical tool calls (>5) or total tool calls (>10) indicate a loop, injecting `<mentor_analysis>` into results; (2) Planning step — adviser("planner") emits a 3-7 step plan wrapped in `<task_assignment>` before specialists run; (3) Reflector — invoked when the LLM fails to emit tool calls 3x, steers back to real tools or barriers; (4) `tool_call_fixer` / `summarizer` housekeeping agents. Two-tier **hard tool-call caps**: general agents (assistant/primary/pentester/coder/installer) 100, limited agents (searcher/enricher/memorist/generator/reporter/adviser/reflector/planner) 20. CONFIRMED (README.md:462-560, database/models.go:194-211).

## Agent roster / roles found
`MsgchainType` enum (backend/pkg/database/models.go:194-211), all CONFIRMED:
- `primary_agent` — top orchestrator of a task.
- `pentester` — runs security tooling (general agent, 100-call cap).
- `coder` — exploit/tool development; the reason SYS_PTRACE is granted (gdb/strace).
- `installer` — on-the-fly package installs in the sandbox (needs SETFCAP/SETPCAP).
- `searcher` + `web_search` orchestrator — external search (limited agent).
- `memorist` — long-term memory recall agent.
- `enricher` — pulls execution context to inform plans.
- `adviser` — doubles as mentor (execution monitor) and planner.
- `reflector` — failure recovery / graceful termination near limits.
- `generator` + `refiner` — goal -> subtask-list decomposition.
- `reporter` — vulnerability report generation.
- `assistant` — interactive chat mode (with optional "Use Agents" delegation toggle).
- `summarizer`, `tool_call_fixer` — infrastructure agents.
Per-agent context inheritance is validated against the set `agent adviser coder searcher generator memorist enricher reporter assistant` (tools/tools.go:59).

## Memory model
- **Long-term**: pgvector store split by kind with dedicated tool pairs — `search_guide`/`store_guide`, `search_answer`/`store_answer`, `search_code`/`store_code`, plus `search_in_memory`. The `memorist` agent is the recall specialist. CONFIRMED (registry.go:36-43).
- **Optional knowledge graph**: Graphiti over Neo4j (`graphiti_search`), flow-scoped, auto-captures agent responses and tool executions. CONFIRMED (README, pkg/graphiti).
- **Working/episodic**: task state + action history in PostgreSQL (Flow/Task/SubTask/Action/Memory tables).
- **Chain summarization** (`pkg/csum`): a ChainAST-based selective summarizer keeps context under token limits (env-tunable: preserve-last, QA-pairs, byte caps). CONFIRMED (README Chain Summarization).

## Tool / plugin / MCP model
- No MCP. Tools are Go functions in `pkg/tools`, dispatched through a central `registry.go` that types each tool (agent / store-agent-result / barrier / search / terminal / file). CONFIRMED.
- **Search abstraction**: agents never call a search engine directly; they call one `web_search` tool with an intent `mode`, and an internal `fallbackStrategy` chain picks engines (Tavily/Google/DuckDuckGo/Firecrawl/Perplexity/Traversaal/Searxng/Sploitus). Engine API keys live in server config, never in the agent. CONFIRMED (CLAUDE.md "Adding a New Search Engine", web_search.go:301).
- **Execution surface**: `terminal` and `file` tools run commands / manipulate files inside the flow's Docker container.
- **Per-agent-type model routing**: `ProviderConfig` holds a separate `AgentConfig` (model, temperature, reasoning effort/budget) for each role — `primary_agent`, `adviser`, `reflector`, `searcher`, `pentester`, `coder`, ... — so a weak base model can pair with a strong adviser. CONFIRMED (pkg/providers/pconfig/config.go:141-296). Mirrors Hermes' per-task model priority chain.

## Sandbox & security posture
- **Isolation**: one primary Docker container per flow (Docker SDK, `pkg/docker/client.go`). Per-flow work directory bind-mounted at `/work`; per-flow named volume if no host dir; tenant labels for multi-instance sweeps. CONFIRMED.
- **Capabilities** (GOOD discipline): `CapDrop: ["ALL"]` then an explicit `CapAdd` allowlist = Docker's default 14 minus `MKNOD`, plus `SYS_PTRACE`, plus `NET_ADMIN` only when `DOCKER_NET_ADMIN=true`. `MKNOD` is deliberately omitted because block-device mknod+debugfs is the "primary confirmed escape vector"; `SYS_ADMIN/SYS_MODULE/SYS_RAWIO/SYS_BOOT` never granted. The set is kept consistent with a vetted `authz.rego` for nested dind. Documented per-capability rationale. CONFIRMED (tools/tools.go:509-535, docs/docker.md:474-514).
- **PidsLimit** default 2048 (fork-bomb guard). Memory/CPU only if caller sets them. CONFIRMED (client.go:363).
- **Credential handling**: search/LLM keys are server-side config; the agent invokes `web_search` and provider calls are made by the kernel/provider layer, not injected into the worker. GOOD, and consistent with our invariant 2. CONFIRMED.
- **Human-in-the-loop**: only the `ask` barrier tool, invoked *at the model's discretion* when it wants user input; no mandatory approval gate, no default-deny, no per-tool-call authorization. The system is "Fully Autonomous" by design. CONFIRMED (registry.go:401, README Features).
- **Authorization / scope**: there is **no kernel-enforced target scope allowlist**. Authorization is the human's flow prompt; the model chooses targets and tools. grep for scope/rules-of-engagement/authorized-target in tools/templates found nothing. CONFIRMED (negative result).
- **Anti-patterns baked in**: `NetworkMode("host")` is a selectable network mode giving the container the host network stack (client.go:382); `DOCKER_INSIDE` bind-mounts the host `docker.sock` (and TLS certs) into workers for DinD (client.go:341); `no-new-privileges` was *deliberately removed* (client.go:355, docker.md:514) to allow SUID/privesc testing; containers run as **root**; and despite docs claiming "Read-Only Root", `ReadonlyRootfs` is **not set anywhere in code** (grep empty) — a doc/code drift, the worker rootfs is writable. CONFIRMED.

## BEST PARTS
1. **Agents-as-tools delegation with paired result-store tools and isolated context.** Evidence: backend/pkg/tools/registry.go:99-122 (`AgentToolType`/`StoreAgentResultToolType`). Serves: kernel + engineering (coding fleet). Why: clean way to expose each specialist to the orchestrator as a typed tool call while keeping the sub-agent's context isolated and its output an explicit logged artifact — maps directly onto our delegate_task + goalId model and per-run event pair.
2. **Per-agent-type model routing (model/temperature/reasoning per role).** Evidence: backend/pkg/providers/pconfig/config.go:141-296 (`ProviderConfig` with one `AgentConfig` per role). Serves: kernel (router). Why: proves the "strong adviser + cheap workers" pattern in production; lets our router bind a frontier model to ceo/auditor and Bonsai/local to scouts, per agent, without code changes.
3. **Two-tier hard tool-call caps + reflector graceful termination.** Evidence: README.md:508-527 (general 100 / limited 20; reflector guides to `done`/`ask` near the cap). Serves: ops-security (budgets/runaway control). Why: a cheap, always-on runaway guard differentiated by agent role — a concrete default for our wallclock/budget caps and for ending stuck runs cleanly instead of killing them.
4. **Execution-monitor "mentor" + planning step for loop detection.** Evidence: README.md:466-486 (adviser auto-invoked on repeated/total tool-call thresholds; 3-7 step plans). Serves: ops-security + kernel. Why: a supervisor that watches tool-call *patterns* (identical-call and total-call thresholds) is a logged, deterministic loop-breaker we can run as a kernel-side monitor without letting the model self-police.
5. **Explicit capability allowlist: CapDrop ALL + minimal CapAdd, MKNOD omitted, per-cap rationale, kept in sync with a dind authz.rego.** Evidence: backend/pkg/tools/tools.go:509-535, docs/docker.md:474-514. Serves: ops-security (sandbox). Why: exactly the discipline our invariant 9 wants (cap-drop=ALL, no SYS_ADMIN/MODULE/RAWIO/BOOT, documented why each cap exists) — adopt the allowlist method and the MKNOD-is-the-escape-vector reasoning; we go further by keeping read-only, non-root, no-new-privileges that they dropped.
6. **Kind-split vector memory + recall agent + optional knowledge graph + chain summarization.** Evidence: registry.go:36-43 (`store_guide/answer/code`), pkg/csum, pkg/graphiti. Serves: kernel + engineering (memory). Why: splitting long-term memory by artifact kind (reusable guides vs answers vs code) with a dedicated recall agent and a context-compaction pass is a mature memory design that maps onto our pmmcp namespaces (aos/shared vs aos/agent/<id>).
7. **Single search facade with server-side keys and engine fallback chain.** Evidence: web_search.go:301, CLAUDE.md "Adding a New Search Engine" (agents call `web_search` mode, never an engine; keys in server config). Serves: growth/research. Why: agents get a capability without ever holding a credential and without knowing which provider served it — the exact shape of our invariant 2 (credentials at the kernel edge) applied to research tooling.

## BAD PARTS / anti-patterns
1. **Selectable host networking (`NetworkMode("host")`).** Evidence: backend/pkg/docker/client.go:382. Why leave out: gives the sandbox the host network stack (and loopback services like our pmmcp/control plane); our invariant 9 mandates an internal network only.
2. **DinD via host docker.sock bind-mount into workers (`DOCKER_INSIDE`).** Evidence: client.go:341 (`dc.socket:/var/run/docker.sock`), the startup warning at client.go:151. Why leave out: mounting the daemon socket is a full host-takeover primitive and hands a worker daemon-level control; invariant 9 forbids docker.sock, invariant 2 forbids credential-adjacent handles in the worker.
3. **`no-new-privileges` deliberately removed, containers run as root, rootfs not actually read-only.** Evidence: client.go:355 + docs/docker.md:514 (removed on purpose); grep for `ReadonlyRootfs` returns nothing despite docs/docker.md:474 claiming "Read-Only Root". Why leave out: invariant 9 requires `--read-only`, non-root, and `--security-opt=no-new-privileges`; their pentest use-case justifies dropping them, ours does not, and the doc/code drift means the security claim is unenforced.
4. **No kernel-enforced scope/authorization; the model chooses targets, human input is a discretionary `ask`.** Evidence: registry.go:401-404 (`ask` is model-invoked), negative grep for any scope/allowlist gate. Why leave out: violates our invariant 3 (default-deny, policy gate on every tool call, the model never makes an access-control decision) and the operator's explicit requirement for a kernel-enforced scope allowlist over their own assets.
5. **Mutable observability instead of an immutable audit trail.** Evidence: README/CLAUDE.md — reasoning/outputs land in PostgreSQL, Loki, Langfuse; no hash-chaining or append-only immutability. Why leave out: our invariants 4-5 require every LLM call and event to be redacted, canonicalized, hashed and chained with UPDATE/DELETE refused; PentAGI's logs are editable operational telemetry, not a tamper-evident log.

## Conflicts with CLAUDE.md invariants
1. **Invariant 9** (containers `--read-only`, `--cap-drop=ALL` [OK], `no-new-privileges`, non-root, internal network, never docker.sock, never host net): PentAGI offers host networking, mounts docker.sock for DinD, removed no-new-privileges, runs root, and does not set read-only rootfs. Only CapDrop=ALL+allowlist aligns.
2. **Invariant 3** (policy gate -> approval -> quarantine -> execute -> log, default deny, model never makes access-control decisions): PentAGI has no gate; the model selects targets/tools and only optionally calls `ask`.
3. **Invariant 2** (agents never hold a credential/vault handle; injection at the egress edge): partially aligned for search/LLM keys (server-side, GOOD), but DinD injects a daemon socket/TLS into the worker — a credential-adjacent handle.
4. **Invariants 4 & 5** (every LLM call is two hashed events; every event redacted/canonicalized/hash-chained, UPDATE/DELETE refused): PentAGI persists to mutable PG/Loki/Langfuse with no chain or immutability triggers.
5. **Invariant 6** (ephemeral agents bounded by template tier/egress; promotion is human via control plane): no tier ladder or template-bounded egress; every agent shares the one flow container's capabilities.

## Verdict
Take PentAGI's orchestration and routing brain: agents-as-tools delegation with paired result-store tools, per-agent-type model binding, two-tier tool-call caps with a reflector, an execution-monitor mentor + planning step for loop control, kind-split vector memory with a recall agent, and the single-facade/server-side-keys search pattern. Take its capability-allowlist *method* (CapDrop ALL + documented minimal CapAdd, MKNOD-as-escape-vector reasoning) but not its choices — we keep read-only, non-root, no-new-privileges, internal network, and no docker.sock, all of which it drops for pentest convenience. Leave out entirely its autonomy-without-a-gate posture (no default-deny, no scope allowlist, model-chosen targets) and its mutable telemetry, replacing both with our policy gate, kernel-enforced scope allowlist, and hash-chained event log.
