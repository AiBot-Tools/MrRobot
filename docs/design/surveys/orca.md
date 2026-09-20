# Survey: orca (stablyai/orca)

All paths are relative to `refs/orca`.
Evidence tags: CONFIRMED = read in the clone; INFERRED = derived from structure/absence.

## Identity

- Upstream: `https://github.com/stablyai/orca` (package.json `homepage`, author `stablyai`); not a fork. CONFIRMED.
- License: MIT, copyright 2026 Lovecast Inc. (`LICENSE`). CONFIRMED.
- Commit surveyed: `b5b727bddbdd34c31801fb125d43eb818cf84a76` 2026-09-19. CONFIRMED.
- Version: 1.4.197, description "Next-gen IDE for parallel agentic development" (`package.json`). CONFIRMED.
- Stack: Electron + electron-vite + React renderer (`src/renderer`), Node main process (`src/main`), a standalone CLI (`src/cli`, bin `orca`), a headless daemon `orcad` (`src/main/orcad`, `docs/reference/orcad-operations.md`), a relay for mobile (`src/relay`, `cloud/apps/relay`), Swift native computer-use sidecar (`native/computer-use-macos`), browser automation via the `agent-browser` npm package `~0.27.0` (`package.json:182`, `src/main/browser/agent-browser-bridge.ts`). pnpm workspace; oxlint/vitest/Playwright. ~22,400 TS/TSX files, 187 MB of `src`. CONFIRMED.

## What it is

Orca is a desktop **orchestrator IDE for parallel CLI coding agents**, not an AI browser and not itself an LLM agent. It spawns third-party agent CLIs (Claude Code, Codex, Cursor, Gemini, Hermes, Devin, Goose, 25+ listed in `README.md`) as PTY processes, each in its own git worktree, and adds: a supervised orchestration layer (Run/Task/Dispatch with a SQLite inbox), an embedded Chromium browser that agents drive through the `orca` CLI (`snapshot`/`click`/`fill`), "Design Mode" (click a DOM element to push HTML+CSS+screenshot into the agent prompt), native desktop "Computer Use" via macOS accessibility, scheduled "Automations" (cron/RRULE prompts), a session-transcript index across all agents ("AI Vault"), GitHub/Linear/Jira panes, SSH/WSL/ephemeral-VM worktree placement, and a mobile companion over an E2EE relay. CONFIRMED (`README.md`, `skill-guides/*.md`, `src/main` layout).

For our purposes it is a **QA / prototyper / growth-browser-automation harness and a coordinator-worker protocol**, not a security reference.

## Orchestration model

CONFIRMED from `skill-guides/orchestration.md` and `src/main/runtime/orchestration/`:

- Nouns: **Run** (durable namespace + coordinator inbox), **Task** (unit of work, optional DAG deps), **Dispatch** (one authoritative attempt of a Task bound to a worker terminal). "Lifecycle authority comes from the active Dispatch, not a terminal title, copied ID, old database row, provider transcript, or visible pane."
- Roles are classified from context: Coordinator, Dispatched worker (has an injected preamble carrying Task ID, Dispatch ID and a capability), Handoff owner, Compatibility operator, Ordinary terminal agent. Model/effort selection "does not make a handoff supervised".
- Coordinator loop: `run-create` -> N x `worker-start --spec` (fan out the whole independent wave before waiting) -> `check --wait --types worker_done,escalation,question` -> `reply` / `worker-release` -> `check --ack`. FIFO Delivery batches (up to 50) are replayed until acked; type filters decide when to wake but never permit skipping older mail (`skill-guides/orchestration/references/messaging-and-gates.md`).
- Worker obligations: do only the Task; blocking `ask` (durable, resumable by message ID after timeout); heartbeats at preamble cadence ("proves liveness, not completion"); read follow-ups at checkpoints; `worker_done` exactly once with `--outcome succeeded|failed` ("Never encode failure only in prose"), then idle.
- Task-spec contract: Target, Change, Constraints, Ownership, Observable acceptance.
- Decision gates: `gate-create --task --question --options`, `gate-resolve`; "Do not create a gate merely to answer a worker's ask."
- Liveness verdicts are three-valued: `live` / `unverifiable` / `exited`; "contact loss is not process death"; "Absence never authorizes stop, abandon, retry, or release." `worker-list` gives the fleet verdict, `worker-show` gives PTY liveness only.
- Completion accounting: after settlement exactly one of reuse / `worker-retain` / `worker-release`; a review-only `worker_done` "authorizes synthesis of findings, not coordinator file edits".
- Nesting: `NESTED_WORKER_MAX_DEPTH_DEFAULT = 1`, error `nested_worker_depth_exceeded`; a malformed setting falls back to the default "rather than disabling the fence" (`src/shared/nested-worker-depth.ts`).
- Persistence: SQLite tables `runs`, `messages`, `deliveries`, `mutation_receipts` (idempotency keyed by caller fingerprint + request id), `attempt_observation_facts` (append-only evidence with authority id/clock), `worker_dispatches` (state enum incl. `start_unknown`, `stop_unknown`, `abandoned`), `worker_terminal_resources` (owner chain) (`src/main/runtime/orchestration/db/schema/create-core-tables-sql.ts`).
- Dispatch capability: `dcap_` + 32 random bytes, stored hashed, revocable, with `consumer_generation`; re-pointing a Dispatch fences the prior consumer's unacked Deliveries in the same transaction; a worker that gets `consumer_fenced` must stop and not send `worker_done` (`src/main/runtime/orchestration/db/dispatch-context/dispatch-capability.ts`, `references/worker-contract.md`).
- Federation: remote dispatch authority and relay acks exist (`db/federation/*`), execution host owns process/filesystem/stop facts (`docs/reference/ssh-execution-boundary.md`).

## Agent roster / roles found

Orca has no fixed roster; agents are user-chosen CLIs. Role concepts with paths:

- Coordinator / dispatched worker / handoff owner: `skill-guides/orchestration.md` ("Classify the role" table). CONFIRMED.
- Group addresses `@all`, `@idle`, `@claude`, `@codex`, `@opencode`, `@gemini`, `@droid`, `@grok`, `@cursor`, `@worktree:<id>` = live Dispatches of the sender's Run (`references/messaging-and-gates.md`). CONFIRMED.
- Supported agent CLIs and their launch/permission profiles: `src/shared/tui-agent-permissions.ts`, `src/shared/tui-agent-config.ts`, per-agent dirs `src/main/{claude,codex,cursor,gemini,hermes,devin,...}`. CONFIRMED.
- Automations (scheduled prompt runs with a chosen provider, fresh or reused worktree, prechecks): `src/main/automations/`, `skill-guides/orca-cli/references/automations.md`. CONFIRMED.
- Bundled skills shipped to agents: `computer-use`, `linear-tickets`, `orca-cli`, `orca-emulator`, `orca-emulator-android`, `orca-linear`, `orca-per-workspace-env`, `orchestration` (`skills/`, `skill-guides/`, `skill-stubs/`). CONFIRMED.

## Memory model

- No agent long-term memory. `src/main/memory/` is process RAM telemetry (`process-memory-metric.ts`, `host-memory.ts`). CONFIRMED.
- "AI Vault" (`src/main/ai-vault/`) is a read-only **cross-agent session transcript index**: parsers for Claude, Codex, Cursor, Gemini, Hermes, Devin, OpenCode, Kimi, Antigravity, Cline, Droid, Grok, Copilot, plus subagent transcripts, first-user-prompt capture, title resolution, search (`agent-session-search-contract.md`). CONFIRMED.
- Orchestration state (Runs/Tasks/messages) is durable SQLite, used as the coordinator's external memory ("use the ready view as external memory", `references/coordinator-loop.md`). CONFIRMED.
- Terminal scrollback survives restart (`src/main/terminal-history*.ts`). CONFIRMED.

## Tool / plugin / MCP model

- No MCP hub. Tools reach agents as **CLI verbs** (`orca ...`) documented in agent-readable skill guides that the CLI serves (`orca skills get <name> --reference <file>`), with a compact kernel plus conditional references loaded "at an action gate" (`skill-guides/orchestration.md` "Conditional references"). CONFIRMED.
- Browser automation verbs: `goto back reload snapshot screenshot full-screenshot pdf click fill type select check scroll hover focus keypress upload wait(--text|--url|--selector|--load) eval tab list/create/switch/close cookie get capture start console network exec`; refs `@eN` are per-snapshot, per-tab, invalidated by navigation; page affinity via `--page <browserPageId>` (`skill-guides/orca-cli/references/browser.md`). Backed by `agent-browser` (`src/main/browser/agent-browser-bridge*.ts`). CONFIRMED.
- Computer use verbs: `list-apps list-windows get-app-state click set-value type-text press-key hotkey paste-text scroll drag perform-secondary-action`, element indexes from an accessibility tree; every action returns a **verification status** (`verified` / `unverified (accessibility action unasserted)` / `unverified (synthetic input)`) and the guide says "Never report an unverified action as success" (`skill-guides/computer-use.md`, `src/main/computer/computer-action-verification-normalization.ts`). CONFIRMED.
- Skill sharing via Orca Cloud with a written threat model (`docs/reference/agent-skill-sharing-threat-model.md`): manifest+`skill/` envelope only, archive validation before mutation, "installer never executes package content", immutable generation-fenced objects, independent kill switches. CONFIRMED.
- Hooks: Orca installs managed hooks into agent CLIs (Claude/Codex/Grok etc.) to receive status (`src/main/agent-hooks/`, `src/shared/agent-hook-listener.ts`); hooks are the single agent-status producer (`docs/reference/agent-status-store.md`). CONFIRMED.

## Sandbox & security posture

- Isolation: **none by default**. Agents run as host PTY processes in git worktrees or folder workspaces; `README.md`: "if it runs in a terminal, it runs in Orca". No sandbox subsystem exists (`grep -rli sandbox src/main` hits only SSH/startup files). INFERRED from absence, consistent with all launch code read. Optional placement on SSH hosts or "ephemeral VMs" defined by user shell recipes `create/suspend/resume/destroy` in `orca.yaml` (`src/shared/orca-yaml-hook-types.ts` `OrcaVmRecipe`, `src/main/ephemeral-vm-runtime-service.ts`); isolation is whatever the recipe provides. CONFIRMED.
- Permission bypass by default: `DEFAULT_TUI_AGENT_ARGS = YOLO_TUI_AGENT_ARGS` (`src/shared/tui-agent-launch-defaults.ts:17`), where `YOLO_TUI_AGENT_ARGS` maps claude -> `--dangerously-skip-permissions`, codex -> `--dangerously-bypass-approvals-and-sandbox`, gemini/cursor/kimi/hermes/copilot -> `--yolo`, grok -> `--permission-mode bypassPermissions`, goose -> `GOOSE_MODE=auto`, etc. (`src/shared/tui-agent-permissions.ts`). Modes `yolo | manual | mixed` exist but yolo is the default. CONFIRMED.
- Trust-prompt bypass: Orca pre-writes Cursor/Copilot/Codex "trust this folder" artifacts so the agent's trust menu never fires, locally and over SSH (`src/main/agent-trust-presets.ts`, `src/main/remote-agent-trust-presets.ts`). CONFIRMED.
- Credentials: integration tokens (Linear/Jira/GitHub) sealed with Electron `safeStorage`, **falling back to 0600 plaintext when no keyring** (`src/main/integration-credential-file.ts`, `src/shared/secret-store.ts` `describeProtectionGap`). Browser cookie import decrypts the user's Chrome/Edge/Firefox/Safari cookie stores (OS keychain key, HMAC stripping, v20 app-bound detection) into the embedded browser so agents browse as the logged-in user (`src/main/browser/browser-cookie-*.ts`, `browser-cookie-decryption.ts`). Automations use 30-minute single-use dispatch tokens (`src/main/automations/dispatch-tokens.ts`). CONFIRMED.
- Gates: the only hard gates found are (a) orchestration decision gates, which are coordinator-owned choices not access-control; (b) nested-worker depth; (c) a computer-use bundle-ID blocklist of password managers (1Password, Bitwarden, Dashlane, LastPass, NordPass, Proton Pass) returning `app_blocked` (`native/computer-use-macos/Sources/OrcaComputerUseMacOS/main.swift:964`); (d) prose rules in `skill-guides/computer-use.md` ("Do not push, submit forms, send messages, buy items, delete data ... unless the user explicitly asked"). Human-in-the-loop is otherwise the agent CLI's own prompt, which Orca disables by default. CONFIRMED.
- Worktree removal has a home-directory guard scoped to the executing host (`src/main/worktree-removal-home-guard.ts`). Mobile relay is an opaque E2EE splice; phones never hold an Orca credential (`cloud/README.md`, `cloud/packages/relay-contract/src/splice-state-machine.ts`). CONFIRMED.
- Evals: none for agent quality. `tests/e2e` is Playwright UI/regression; `config/vitest.performance.config.ts` is perf contracts. CONFIRMED.

## BEST PARTS

1. **Run/Task/Dispatch with a bearer Dispatch capability** — idea: one authoritative attempt per task, capability hashed at rest, revocable, generation-fenced so a re-pointed worker learns `consumer_fenced` and must not report done. Evidence: `src/main/runtime/orchestration/db/dispatch-context/dispatch-capability.ts`, `create-core-tables-sql.ts`, `references/worker-contract.md`. Sector: kernel + engineering (coding fleet). Why: our `delegate`-style child runs need exactly this to make `run.finished` trustworthy when a kernel restart or retry produces two workers for one task (Phase 1 exit "kernel restart mid-run orphans nothing").
2. **Three-valued liveness (`live`/`unverifiable`/`exited`) and "absence never authorizes stop/retry/release"** — Evidence: `skill-guides/orchestration.md` "Authority and safety floor", `src/shared/agent-session-lease-adjudication.ts` ("fails closed: expiry alone never grants a second owner"). Sector: kernel, ops-security. Why: lane/run reconciliation after a crash should distinguish lost contact from proven exit before the CEO relaunches, or we get duplicate side effects.
3. **Typed `worker_done` with explicit `--outcome succeeded|failed`, heartbeat != completion, review-only done grants no edit authority** — Evidence: `skill-guides/orchestration.md` "Worker obligations", `references/coordinator-loop.md` "Review ownership". Sector: engineering, executive (CEO summaries). Why: forces the model to declare outcome as data, not prose, so the kernel and the CEO's summary rely on a field rather than parsing text; auditor/checker verdicts should be typed the same way.
4. **Task-spec contract (Target, Change, Constraints, Ownership, Observable acceptance)** — Evidence: `skill-guides/orchestration.md` "Task-spec contract". Sector: executive, engineering. Why: a schema for CEO -> worker delegation payloads and for pmmcp task goals; "Ownership" maps directly to our per-run mountRoot and tool scope.
5. **Snapshot -> ref -> act -> re-snapshot browser loop with typed recoveries** — Evidence: `skill-guides/orca-cli/references/browser.md` (`@eN` refs scoped per tab, `browser_stale_ref`, `browser_no_tab`, `wait --text/--url/--selector/--load` instead of sleeps, `--page` affinity for concurrency). Sector: growth (marketing/social browser automation) and prototyper/QA. Why: it is the cleanest agent-facing browser tool contract in the reference set; our `browser` MCP pack for T2 should expose these verbs and error codes, with `eval`/`cookie`/`upload` classified `write`/`kernel-only`.
6. **Action verification status on every GUI action** — Evidence: `skill-guides/computer-use.md` ("verified" / "unverified (synthetic input)"; "Never report an unverified action as success"), `src/main/computer/computer-action-verification-normalization.ts`. Sector: prototyper/QA, growth. Why: a QA agent's pass/fail must carry evidence class; we should log `verification` on every browser/computer tool result event and make the checker template refuse to score unverified actions as passes.
7. **Design Mode: element -> HTML + computed CSS + cropped screenshot + source map location as one prompt attachment** — Evidence: `docs/site/content/docs/browser/design-mode.mdx`, `README.md`. Sector: prototyper. Why: gives the prototyper agent a precise, cheap UI-defect payload and closes the edit -> hot reload -> re-click loop the operator asked for.
8. **Skill-package threat model and install invariants** — Evidence: `docs/reference/agent-skill-sharing-threat-model.md` (TM-01..TM-20; manifest-only envelope, never execute on install, generation-fenced immutability, kill switches). Sector: ops-security, kernel (Phase 5 signed skills repo). Why: a ready-made checklist for our signed-skills design and for pack manifests with schema-hash pinning.

Also worth noting: scheduled Automations with prechecks and fixed-sentence dispatch refusals (`src/main/automations/precheck-runner.ts`, `dispatch-refusal.ts`) as a shape for our cron scheduler; compact skill kernel + on-demand references (`orca skills get --reference`) as a prompt-budget pattern for `souls/*.md`.

## BAD PARTS / anti-patterns

1. **Permission bypass is the default launch profile** — `DEFAULT_TUI_AGENT_ARGS = YOLO_TUI_AGENT_ARGS` (`src/shared/tui-agent-launch-defaults.ts:17`, `src/shared/tui-agent-permissions.ts`). Every supported agent starts with `--dangerously-skip-permissions`/`--yolo`/`--bypass-approvals-and-sandbox`. Why out: violates invariant 3 (default deny, human for irreversible); the human-in-the-loop is exactly what gets switched off.
2. **Trust-prompt pre-marking** — Orca writes `.workspace-trusted`, `trustedFolders`, `trust_level = "trusted"` on the agent's behalf so no trust menu appears (`src/main/agent-trust-presets.ts`). Why out: a safety prompt bypassed for paste ergonomics; our promotion/trust is a human control-plane action (invariant 6).
3. **No isolation** — agents are host PTY processes with the user's full environment; "ephemeral VM" is a user shell recipe with no enforced properties (`src/shared/orca-yaml-hook-types.ts`, README). Why out: invariant 9 requires Docker with read-only/cap-drop/no-new-privileges/internal network; Orca's model gives workers `$HOME`.
4. **Browser cookie import from the user's real browsers** — decrypts Chrome/Edge/Firefox/Safari cookie stores using the OS keychain and loads them into the agent-driven browser (`src/main/browser/browser-cookie-decryption.ts`, `browser-cookie-chromium-import.ts`, `browser-cookie-safari-import.ts`). Why out: hands live session credentials to an agent-controlled surface, violating invariant 2 (credentials injected only at the egress proxy edge, never held by the agent's process/profile). A social/growth agent that needs a logged-in session must get it via the proxy with per-hostname scoping and logging.
5. **Plaintext 0600 fallback for integration tokens when no keyring** (`src/main/integration-credential-file.ts`, `src/shared/secret-store.ts` `describeProtectionGap`). Why out: our vault is pmmcp only; the kernel never writes a secret to a file.
6. **Prose-only safety for computer use** — the only hard block is a password-manager bundle-ID list (`native/computer-use-macos/.../main.swift:964`); "do not buy/delete/send unless asked" lives in the skill text (`skill-guides/computer-use.md`). Why out: the model is making the access-control decision; our gate must classify `computer.*` actions as `write`/`irreversible` by verb and require a human, with the blocklist kept as defense in depth.
7. **Every agent has an egress-unrestricted browser and `eval --expression <js>`** (`references/browser.md`). Why out: arbitrary JS in a logged-in browser is a `write` tool with taint implications; must sit behind the gate and the egress proxy allowlist.

## Conflicts with CLAUDE.md invariants

1. Invariant 3 (gate, default deny, human for irreversible): default `--dangerously-skip-permissions`-class flags remove every approval step (`tui-agent-launch-defaults.ts`).
2. Invariant 2 (agents never hold credentials): cookie import places the user's browser sessions in an agent-driven Chromium profile; integration tokens are readable by the same process that runs agents.
3. Invariant 9 (container hardening): no sandbox; workers get host `$HOME`, host network, host keychain.
4. Invariant 6 (promotion is human): trust presets auto-trust workspaces on behalf of the human.
5. Invariant 4/5 (every LLM call logged, hash chain): Orca observes agents via hooks and transcript scanning after the fact; it does not sit on the LLM call path, so cost/tokens are not first-class events (usage is scraped from provider JSONL, `src/main/usage/`).
6. Invariant 7 (unknown tools kernel-only): Orca's `exec --command "<agent-browser command>"` passes through any unlisted verb ("Anything not listed above goes through `exec`"), the opposite of default-deny.
7. Invariant 8 (souls read-only): not applicable directly, but Orca's model of writing into agent config homes (`CODEX_HOME`, `~/.cursor`, `~/.copilot`) is the pattern we must not copy for agent manifests.

## Verdict

Take the orchestration protocol shapes (Run/Task/Dispatch with hashed revocable capabilities, three-valued liveness with fail-closed reconciliation, typed `worker_done` outcomes, the task-spec contract, nested-depth fence) as the design for CEO-to-worker delegation and restart-safe projections, and take the browser/computer tool contracts (snapshot-ref loop, typed recovery codes, per-action verification status, Design Mode payload) as the surface for our prototyper, QA checker, and growth/social browser agents. Leave the entire security posture: yolo-by-default launches, trust pre-marking, no sandbox, cookie import, plaintext token fallback, and prose-only guardrails all contradict invariants 2, 3, 6 and 9. Orca is a strong reference for coordination semantics and agent-facing tool ergonomics and a clear anti-pattern for credential handling and gating.
