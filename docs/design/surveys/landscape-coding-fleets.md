# Landscape survey: how the strongest systems compose a fleet of coding agents

Purpose: inform the ENGINEERING sector of the aos-kernel agent fleet (coder fleet, prototyper, reviewer/tester/verifier roles) without violating CLAUDE.md invariants (policy gate on every tool call, default deny, `irreversible` => human, tainted runs cannot write without a human, agents never hold credentials, ephemeral agents bounded by their template, the model never makes an access-control decision).

Date: 2026-09-20. Scope: web survey plus two local reference clones (`refs/OpenHands`, `refs/ruflo`).

## Provenance legend and reachability

* **CONFIRMED** = I fetched and read the cited page or file.
* **INFERRED (snippet)** = the primary page was egress-blocked from this session; the fact comes from a web-search result snippet that quotes or paraphrases the primary source. Treat numbers as "as reported", re-verify before quoting in operator-facing docs.
* Egress-blocked from this session: `anthropic.com`, `claude.com`, `cognition.ai`/`cognition.com`, `devin.ai`, `openai.com`, `developers.openai.com`, `aider.chat`, `block.github.io`, `docs.cline.bot`, `docs.all-hands.dev`, `arxiv.org`, `huggingface.co`, `alphaxiv.org`, `research.google`, `simonwillison.net`, `medium.com`, `dev.to`, `news.ycombinator.com`, `wikipedia.org`. Reachable: `code.claude.com`, `github.com`.
* Local clones cited by path are relative to `refs/`.

Per-project entries use one fixed grid: **Role split · Isolation · Verification gates · Context management · Parallelism & merge · Cost control · Evidence**.

---

## 1. Claude Code: subagents, worktrees, agent teams, dynamic workflows

**What it is.** Anthropic's CLI coding agent. Five parallelism surfaces: subagents (in-session delegated workers), agent view (background sessions), agent teams (experimental, lead + teammates with shared task list and mailboxes), dynamic workflows (a script orchestrates many subagents), projects (cloud threads). CONFIRMED https://code.claude.com/docs/en/agents

**Role split.** Roles are data: Markdown files with YAML frontmatter (`name`, `description`, `tools`, `disallowedTools`, `model`, `permissionMode`, `skills`, `memory`, `isolation`, `maxTurns`, `mcpServers`, `hooks`). Built-ins: `Explore` (read-only, fast), `Plan` (read-only research during plan mode), `general-purpose` (all tools). Recommended workflow is explore -> plan -> implement -> commit, with a **Writer/Reviewer** split across sessions: "A fresh context improves code review since Claude won't be biased toward code it just wrote." CONFIRMED https://code.claude.com/docs/en/sub-agents ; https://code.claude.com/docs/en/best-practices

**Isolation.** Each subagent has "its own context window with a custom system prompt, specific tool access, and independent permissions" and does not inherit the parent's conversation history. `isolation: worktree` gives a subagent "an isolated copy of the repository branched by default from your default branch"; `claude --worktree <name>` does the same for sessions; `/batch` splits "one large change into 5 to 30 worktree-isolated subagents that each open a pull request". Worktree enforcement is mechanical, not advisory: Claude Code blocks Edit/Write to the main checkout, blocks commands whose cwd resolves to the main checkout, blocks `git -C`/`GIT_DIR`/`cd` redirects into it, and refuses any command whose shape it cannot verify ("You can't turn this check off"). Agent teams do **not** isolate teammates in worktrees: "partition the work so each teammate owns a different set of files". CONFIRMED https://code.claude.com/docs/en/worktrees ; https://code.claude.com/docs/en/agent-teams

**Verification gates.** "Give Claude a check it can run: tests, a build, a screenshot to compare." Four escalating gate strengths: in-prompt check; `/goal` with a separate evaluator re-checking after every turn; a `Stop` hook that blocks the turn until a script passes ("Claude Code overrides the hook and ends the turn after 8 consecutive blocks"); and an adversarial reviewer subagent in a fresh context that "sees only the diff and the criteria you give it, not the reasoning that produced the change". Hooks are "deterministic and guarantee the action happens", CLAUDE.md is "advisory". Team hooks `TeammateIdle`, `TaskCreated`, `TaskCompleted` exit 2 to block. Warning about reviewer bias: "A reviewer prompted to find gaps will usually report some, even when the work is sound." CONFIRMED https://code.claude.com/docs/en/best-practices ; https://code.claude.com/docs/en/agent-teams

**Context management.** "Claude's context window fills up fast, and performance degrades as it fills." Tools: `/clear` between tasks, auto-compaction, `/compact <instructions>`, partial summarize-from/up-to a checkpoint, `/btw` side questions that never enter history, subagents so "only the findings come back". Subagent results: "Only the summary returns to you and the intermediate output stays out of your main conversation." Subagent final messages are scanned for control-tag imitation and turn markers before the parent reads them (v2.1.210+). CONFIRMED https://code.claude.com/docs/en/best-practices ; https://code.claude.com/docs/en/agent-sdk/subagents

**Parallelism & merge.** Subagents: default concurrency cap 20 (`CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`), nesting depth 3 (`CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH`), background by default. Teams: "Start with 3-5 teammates", "Three focused teammates often outperform five scattered ones", tasks with dependencies, self-claim with file locking, "No nested teams", "Lead is fixed". Merge is via git: each worktree subagent opens its own PR (`/batch`); the doc explicitly says agent teams "add coordination overhead and use significantly more tokens than a single session". Inter-agent messages are marked as coming from another Claude session; "A teammate can't approve a permission prompt or supply consent on your behalf, and a teammate that was denied an action can't relay it to another teammate to bypass the check." CONFIRMED https://code.claude.com/docs/en/agent-teams ; https://code.claude.com/docs/en/agent-sdk/subagents

**Cost control.** Per-agent `model` (haiku/sonnet/opus), `maxTurns` (returns partial output, resumable), `maxBudgetUsd` in the SDK compared against `total_cost_usd` including subagent requests: at the cap it "refuses to spawn more subagents ... stops background subagents that are still running, and ends the query with the `error_max_budget_usd` result subtype". Subagent prompt-cache TTL is separate from the main conversation. A public issue notes fan-out skills inheriting the session's premium model for all subagents with no tiering (INFERRED (snippet), https://github.com/anthropics/claude-code/issues/74171). CONFIRMED https://code.claude.com/docs/en/agent-sdk/subagents

---

## 2. Claude Agent SDK

**Role split.** `agents: { name: AgentDefinition }` with `description`, `prompt`, `tools`, `disallowedTools` (accepts `mcp__server__*` patterns), `model`, `skills`, `memory`, `mcpServers`, `maxTurns`, `background`, `omitClaudeMd`, `effort`, `permissionMode`. Canonical example: a read-only `code-reviewer` (`Read, Grep, Glob`) and a `test-runner` (`Bash, Read, Grep`). CONFIRMED https://code.claude.com/docs/en/agent-sdk/subagents

**Isolation.** "Each subagent runs in its own conversation, which starts fresh unless the subagent is a fork ... only its final message returns to the parent." A tool left out "isn't in the subagent's session at all: Claude works without it, with no permission prompt or error." CONFIRMED same page.

**Verification gates.** SDK inherits Claude Code hooks/permissions; recommended pattern is a verification subagent so "the agent doing the work isn't the one grading it" (best-practices). Subagent output scanning neutralizes `<system-reminder>`-style tags and `Human:`/`Assistant:` turn markers. CONFIRMED same page + best-practices.

**Context management.** Subagents "isolate context"; a `research-assistant` "can explore dozens of files without any of that content accumulating in the main conversation." CONFIRMED.

**Parallelism & merge.** "multiple subagents can run concurrently, so independent subtasks finish in the time of the slowest one"; for "dozens to hundreds of agents, use the `Workflow` tool, which moves the orchestration into a script the runtime executes outside the conversation context." CONFIRMED.

**Cost control.** Depth / concurrency / spend caps (table in the doc: defaults 3 / 20 / no limit). Note "Claude Opus 5 delegates to subagents more readily than earlier models, so the depth, concurrency, and spend limits matter most". CONFIRMED.

---

## 3. OpenAI Codex (cloud agent + CLI)

**Role split.** Single agent per task; no built-in planner/implementer split. Separate **code review** surface: "@codex review" on a PR triggers a cloud review that "reads the entire PR including dependencies and tests"; on GitHub findings are limited to P0/P1; custom rules via a `## Code Review Rules` section in the nearest `AGENTS.md`. INFERRED (snippet) https://developers.openai.com/codex/use-cases/github-code-reviews ; https://developers.openai.com/blog/custom-code-review-rules-for-codex

**Isolation.** Cloud: "Codex provisions an isolated container in the cloud and clones your repository into it, along with the dependencies you configured. Once the task starts, that container has no internet access"; setup scripts run with internet, the agent phase does not by default. INFERRED (snippet) https://developers.openai.com/codex/cloud ; https://developers.openai.com/codex/cloud/internet-access . CLI: `SandboxMode` enum in source is exactly `read-only` (default) | `workspace-write` | `danger-full-access` (CONFIRMED https://github.com/openai/codex/blob/main/codex-rs/protocol/src/config_types.rs). Approval policy `on-request` "allows the agent to work inside the sandbox by default and ask when it needs to go beyond that boundary"; `untrusted` no longer selectable. macOS uses Seatbelt (`sandbox-exec`), Linux uses Landlock; "In workspace-write mode, network is disabled by default unless enabled in config". INFERRED (snippet) https://developers.openai.com/codex/concepts/sandboxing ; https://developers.openai.com/codex/agent-approvals-security

**Verification gates.** Cloud tasks return "verifiable evidence" (terminal logs, test output, citations) with the PR; `AGENTS.md` carries test commands and conventions. INFERRED (snippet) https://openai.com/index/introducing-codex/

**Context management.** Layered `AGENTS.md` (nearest file wins); no documented condenser. INFERRED (snippet).

**Parallelism & merge.** "Codex works in parallel, so you can queue multiple changes"; cloud subagent workflows spawn "specialized agents in parallel and then collecting their results in one response". **Best-of-N**: `codex cloud exec --env ENV_ID --attempts 3 "..."` "allows submitting multiple candidates for a hard problem and choosing the best". Merge is one PR per task. INFERRED (snippet) https://developers.openai.com/codex/subagents ; https://codex.danielvaughan.com/2026/03/27/codex-cloud-vs-local-when-to-run-in-cloud/

**Cost control.** Not documented beyond per-task container and the attempts count. INFERRED.

---

## 4. Devin (Cognition): single-threaded agent, Multi-Devin, "Don't Build Multi-Agents"

**Role split.** Cognition's stated position (June 2025): "Share context, and share full agent traces, not just individual messages" and "Actions carry implicit decisions, and conflicting decisions carry bad results"; the Flappy Bird example (two subagents produce a Super Mario-style background and a mismatched sprite because neither saw the other's implicit style decision); prescription "default to single-threaded linear agents" with a fine-tuned **context-compression model** that distills history into "key details, events, and decisions". INFERRED (snippet) https://cognition.com/blog/dont-build-multi-agents . Follow-up (2026, "Multi-Agents: What's Actually Working"): "a single orchestrator owns the full conversation context and spawns ephemeral isolated subagents that return only a compressed summary ... There is no peer-to-peer channel and no shared mutable state ... Multi-agent systems work best today when writes stay single-threaded and the additional agents contribute intelligence rather than actions ... map-reduce-and-manage"; "The unstructured-swarm approach ... is mostly a distraction." INFERRED (snippet) https://cognition.com/blog/multi-agents-working

**Isolation.** "Each session spins up a fresh, dedicated containerized VM bundling shell, a full or headless browser, and a VS Code-style editor" (Devbox); "Devin Fusion" pairs a frontier reasoning model with small helper models for "linting, file reading, and syntax checks". INFERRED (snippet, third-party writeup) https://fast.io/resources/cognition-devin-ai-architecture/

**Verification gates.** Browser-based verification: starts dev servers, navigates localhost, captures screenshots "to verify CSS layouts or check for console errors". 2025 performance review: "When outcomes aren't straightforwardly verifiable, additional human review is necessary", humans "check unit testing logic after Devin takes the first pass, and check its code reviews". PR merge rate 67% (up from 34%). INFERRED (snippet) https://cognition.com/blog/devin-annual-performance-review-2025

**Context management.** Dedicated compression model (above). INFERRED.

**Parallelism & merge.** Guidance: "treat Devin as a parallelizable junior engineer — assign it tasks a junior developer would complete in four to eight hours, verify the pull request, and scale the workload horizontally". Stacked PRs: "breaks large tasks into stacks of small, independently reviewable PRs — handling rebasing, conflict resolution, and CI verification". Multi-Devin manager/worker exists (docs blocked; not verified here). INFERRED (snippet) https://devin.ai/blog/introducing-pr-stacks

**Cost control.** ACU-based billing (not verified here). Design-level cost control is "no parallel writers": one linear agent per task avoids reconciliation cost.

---

## 5. SWE-agent and mini-SWE-agent (Princeton/Stanford)

**Role split.** One agent. The contribution is the **Agent-Computer Interface (ACI)**: "a set of tools and interaction format that allows an agent to interact with a computer-based environment"; "good ACI design leads to much better results". CONFIRMED https://github.com/SWE-agent/SWE-agent/blob/main/docs/background/aci.md

**Isolation.** Docker per instance via SWE-ReX (CONFIRMED referenced on README; details not fetched). mini-SWE-agent: "Executes actions with `subprocess.run` — every action is completely independent (as opposed to keeping a stateful shell session running)"; supports "local, Docker, Singularity, bubblewrap". CONFIRMED https://github.com/SWE-agent/mini-swe-agent/blob/main/README.md

**Verification gates.** Guardrails inside the tool, not a separate agent: "a linter that runs when an edit command is issued" rejects syntactically invalid edits; file viewer shows ~100 lines with scroll/search; search returns only filenames; empty output is replaced by "Your command ran successfully and did not produce any output." Ablations (paper): linting guardrail +3.0 points; removing the dedicated editor -7.7 points; 100-line window best. INFERRED (snippet) https://arxiv.org/abs/2405.15793 ; CONFIRMED tool descriptions in aci.md.

**Context management.** History processors (e.g. collapse old observations, image parsing) are config; mini-SWE-agent deliberately keeps "a completely linear history — every step of the agent just appends to the messages". CONFIRMED https://github.com/SWE-agent/SWE-agent/blob/main/docs/config/config.md ; mini README.

**Parallelism & merge.** Batch mode across instances; no in-task multi-agent. INFERRED.

**Cost control.** Per-instance cost/call limits are config (referenced in docs; exact keys not fetched). Scores as reported: SWE-agent 12.47% full SWE-bench (GPT-4 Turbo, 2024); mini-SWE-agent ">74% on SWE-bench verified" in ~100 lines of Python with bash only. CONFIRMED mini README; INFERRED (snippet) paper numbers.

**Note for us.** The single strongest lesson is that the *tool surface* (ACI) moves the score more than agent count: bounded viewers, lint-on-edit, filename-only search, explicit empty-output messages.

---

## 6. Aider

**Role split.** Four chat modes: `code`, `ask` (never changes files), `architect`, `help`. Architect mode: "An architect model will propose changes and an editor model will translate that proposal into specific file edits" — a two-model reasoning/editing split, "especially useful with OpenAI's o1 models, which are strong at reasoning but less capable at editing files". CONFIRMED https://github.com/Aider-AI/aider/blob/main/aider/website/docs/usage/modes.md

**Verification gates.** Benchmark on the architect split: "Using o1-preview as the Architect with either DeepSeek or o1-mini as the Editor produced the SOTA score of 85%" vs previous 79.7%; "Sonnet, GPT-4o and GPT-4o-mini all scored higher when used as an Architect/Editor pair"; caveat: the top pair "is quite slow, so probably not practical for interactive use". Rationale: the architect can "focus on solving the coding problem" while the editor handles "properly formatting the edits". CONFIRMED https://github.com/Aider-AI/aider/blob/main/aider/website/_posts/2024-09-26-architect.md

**Context management.** Repo map: "a concise map of your whole git repository" ranked by "a graph ranking algorithm, computed on a graph where each source file is a node and edges connect files which have dependencies"; token budget `--map-tokens` "defaults to 1k tokens", expands when no files are in chat; "only includes the most important identifiers, the ones which are most often referenced". CONFIRMED https://github.com/Aider-AI/aider/blob/main/aider/website/docs/repomap.md

**Isolation / Parallelism / Cost.** Single process in the user's checkout; no sandbox, no parallelism. Cost control is via model pairing (cheap editor). CONFIRMED (absence in docs read).

---

## 7. Goose (Block)

**Role split.** Recipes (YAML/JSON) "package up instructions and settings"; fields: `instructions`/`prompt`, `extensions` (which MCP servers/tools), `parameters`, `settings` (provider, model, temperature, `max_turns`), `retry` ("automated validation loops with shell command checks and failure handlers"), `response` (JSON schema enforced), `sub_recipes`. CONFIRMED https://github.com/block/goose/blob/main/documentation/docs/guides/recipes/recipe-reference.md

**Isolation.** Subagents are "independent instances that execute tasks while keeping your main conversation clean"; they inherit parent extensions but "maintain separate execution contexts"; subrecipes/subagents "do not share state with one another" (INFERRED (snippet) https://block.github.io/goose/blog/2025/09/26/subagents-vs-subrecipes/). CONFIRMED https://github.com/block/goose/blob/main/documentation/docs/guides/context-engineering/subagents.mdx

**Verification gates.** Recipe `retry` checks (shell commands) gate completion; `response` schema validates output. CONFIRMED recipe-reference.

**Context management.** Offload to subagents; results appear as expandable sections tagged `[subagent:16] text_editor | developer`. CONFIRMED subagents.mdx.

**Parallelism & merge.** Parallel when prompted ("parallel", "simultaneously"); subrecipes can run "concurrently using isolated worker processes". Hard limits: default **25 max turns** (`GOOSE_SUBAGENT_MAX_TURNS`), **5-minute timeout**, and subagents "Cannot create additional subagents to prevent infinite recursion"; blocked operations: "Subagent spawning, Extension management, Schedule management". CONFIRMED subagents.mdx.

**Cost control.** `max_turns`, timeout, per-recipe model override. CONFIRMED.

---

## 8. Cline

**Role split.** Plan/Act: "Plan mode lets you explore and strategize without changing files ... cannot modify any files or execute commands"; "Act mode ... retains the full context from your planning session and can now modify files, run commands"; "configure separate models for Plan and Act modes". CONFIRMED https://github.com/cline/cline/blob/main/docs/core-workflows/plan-and-act.mdx

**Isolation.** Runs in the user's workspace; no sandbox. Human-in-the-loop by default: "Every file edit and terminal command requires your approval"; optional auto-approve. CONFIRMED https://github.com/cline/cline/blob/main/README.md

**Verification gates.** Checkpoints: "Cline maintains a shadow Git repository separate from your project's actual Git history ... After each tool use, Cline commits the current state of your files to this shadow repo"; restore modes Restore Files / Restore Task Only / Restore Files & Task; Compare opens a diff. Limitation: on large codebases checkpoints "may use significant storage and slow down Cline". CONFIRMED https://github.com/cline/cline/blob/main/docs/core-workflows/checkpoints.mdx

**Context / Parallelism / Cost.** Single agent; cost lever is cheaper Plan model vs Act model. CONFIRMED (docs read).

---

## 9. OpenHands (upstream `OpenHands/software-agent-sdk` + the Agent Canvas clone)

**Role split.** One agent per conversation; delegation = "Sub-agents operate as independent conversations that inherit the parent's model configuration and workspace context" (INFERRED (snippet) https://arxiv.org/html/2511.03690v2). In the canvas clone the `launch_child_conversation` client tool spells the contract out: child "cannot see the parent's history", brief "must be self-contained", one call per task, `isolation=worktree|shared` with worktree default ("gives the child its own git worktree and branch"), result arrives as an async follow-up message. CONFIRMED `OpenHands/src/api/launch-child-conversation-client-tool.ts` lines 48, 98.

**Isolation.** SDK: agents "run inside ephemeral workspaces (e.g. in Docker or Kubernetes) using the Agent Server" (CONFIRMED https://github.com/OpenHands/software-agent-sdk/blob/main/README.md). Canvas default dev mode runs the agent-server on the host with full filesystem access (CONFIRMED `OpenHands/README.md`, `docs/architecture.md`; see `survey/OpenHands.md`).

**Verification gates.** `confirmation_policy` = `NeverConfirm` | `AlwaysConfirm` | `ConfirmRisky{threshold:"HIGH"}` where the risk label can be **predicted by the acting LLM** (`LLMSecurityAnalyzer`); default `confirmation_mode: false`. Hooks (`PreToolUse`, `PostToolUse`, `Stop`...) run as shell and every execution is an event with `blocked`, `exit_code`, `reason`. `/goal` judge loop with `GoalVerdict{score, complete, missing}` capped by `max_iterations`; per-action `critic_result`. CONFIRMED `OpenHands/src/api/agent-server-adapter.ts` ~680-706, `src/types/agent-server/core/events/hook-execution-event.ts`, `conversation-state-event.ts`, `core/base/critic.ts`.

**Context management.** Condensers are first-class and event-sourced: the log is append-only; a `Condensation` event (tombstone-like) records `forgotten_event_ids` and a `summary` inserted at `summary_offset`; a `View` applies condensations; `LLMSummarizingCondenser` triggers on REQUEST / TOKENS / EVENTS (`len(view) > max_size`), preserves `keep_first` events, respects atomic action/observation boundaries, "summaries are also summarized in future condensations", and falls back to a "hard context reset" if message structure is violated. Reported effect: "reduce API costs by up to 2x with no degradation in agent performance" across 14 models and five benchmark categories. CONFIRMED https://github.com/OpenHands/software-agent-sdk/tree/main/openhands-sdk/openhands/sdk/context/condenser and `llm_summarizing_condenser.py` ; INFERRED (snippet) the 2x claim from the SDK paper.

**Parallelism & merge.** Worktree per child conversation; merge left to the human/PR flow. Automations carry `timeout` (600 s default), typed finish status `success|partial_success|blocked|failed`, and are auto-disabled after consecutive failures. CONFIRMED `OpenHands/src/types/automation.ts`.

**Cost control.** `max_iterations`, `max_budget_per_task`, `stuck_detection`, per-usage-id metrics including a separate `"condenser"` line. CONFIRMED `OpenHands/src/types/settings.ts`, `conversation-state-event.ts`.

---

## 10. MetaGPT

**Role split.** "Code = SOP(Team)": Product Manager -> Architect -> Project Manager -> Engineer (-> QA), each producing structured artifacts (PRD, competitive analysis, data structures, APIs, tasks) rather than free chat; an assembly-line of SOP-encoded roles. CONFIRMED https://github.com/FoundationAgents/MetaGPT/blob/main/README.md . Paper numbers as reported: 85.9% HumanEval, 87.7% MBPP pass@1 (GPT-4); on SoftwareDev executability 3.75 vs ChatDev 2.25 (1-4 scale), 0.83 human revisions vs 2.5; **executable feedback** adds +4.2% HumanEval / +5.4% MBPP and moves revisions 2.25 -> 0.83. INFERRED (snippet) https://arxiv.org/abs/2308.00352 ; https://proceedings.iclr.cc/paper_files/paper/2024/file/6507b115562bb0a305f1958ccc87355a-Paper-Conference.pdf

**Isolation / Verification / Context / Parallelism / Cost.** Runs as one Python process; verification is "executable feedback" (run the code, feed errors back); message pool with publish-subscribe so roles read only what they subscribe to (INFERRED (snippet)). No sandbox, no per-role budget in the docs read.

**Note for us.** The reusable idea is *structured intermediate artifacts as the interface between roles*, not the roster of job titles.

---

## 11. ChatDev

**Role split.** A "virtual software company" following a waterfall of "designing, coding, testing, and documenting"; the **chat chain** "breaking down each stage into atomic subtasks", each subtask a two-role dialogue (instructor/assistant: CEO/CTO, CTO/Programmer, Programmer/Reviewer, Programmer/Tester) "allowing for proposing and validating solutions". **Communicative dehallucination**: agents "actively request more specific details before giving direct responses". Extensions: Experiential Co-Learning, Iterative Experience Refinement, MacNet (DAG topologies, "more than a thousand agents"). CONFIRMED https://github.com/OpenBMB/ChatDev/blob/main/README.md ; INFERRED (snippet) https://arxiv.org/abs/2307.07924

**Cost.** "completion of the entire software development process in under seven minutes at a cost of less than one dollar" (paper, as reported). INFERRED (snippet).

**Note for us.** Cheap toy-app demos; MetaGPT's own comparison reports ChatDev at lower executability with more human revisions. The transferable bit is the *pairwise propose/validate* turn shape and the "ask before answering" dehallucination rule for the planner.

---

## 12. Agentless

**Role split.** No agent loop. Three phases: "Localization, Repair, and Patch Validation". Localization is hierarchical: "first localize the fault to specific files, then to relevant classes or functions, and finally to fine-grained edit locations". Repair "samples multiple candidate patches per bug in a simple diff format". Validation "selects the regression tests to run and generates additional reproduction test to reproduce the original error. Using the test results, Agentless re-ranks all remaining patches to selects one to submit." CONFIRMED https://github.com/OpenAutoCoder/Agentless/blob/main/README.md

**Cost / results.** v1.0: 27.3% SWE-bench Lite at ~$0.34/issue (README); paper: 32.00% Lite at $0.70 (INFERRED (snippet) https://arxiv.org/abs/2407.01489); with Claude 3.5 Sonnet 40.7% Lite / 50.8% Verified (README). CONFIRMED / INFERRED as marked.

**Note for us.** Reproduction test + regression selection + rerank is the cheapest verified-selection loop in the literature; it needs no second LLM "reviewer".

---

## 13. ruflo / claude-flow (upstream; local clone surveyed in `survey/ruflo.md`)

**Role split.** "Anti-Drift Coding Swarm (PREFERRED DEFAULT)": "ALWAYS use hierarchical topology for coding swarms", "Keep maxAgents at 6-8", "specialized strategy", `raft` consensus ("leader maintains authoritative state"), "Keep task cycles short with verification gates". Fixed pipeline `researcher -> architect -> coder -> tester -> reviewer`; dependency levels L0 architect, L1 coder+tester, L2 reviewer, L3 optimizer. CONFIRMED `ruflo/CLAUDE.md` lines 110-126 and the sections cited in `survey/ruflo.md`.

**Isolation.** None of its own; "never two writers in one worktree", writers get an isolated worktree with explicit file ownership, "only the integration owner edits manifests/lockfiles". Generated Codex profile `dev` uses `approval_policy="never"` + `sandbox_mode="danger-full-access"`. CONFIRMED `ruflo/CLAUDE.md` §"Concurrent Automated Development"; `ruflo/v3/@claude-flow/codex/src/generators/config-toml.ts` 570-700.

**Verification gates.** Capability envelopes that may only shrink on delegation (`delegateEnvelope`, `capability-envelope-cannot-grow`); hash-chained policy receipts; `production-validator` agent greps for mock/stub/TODO; Ed25519 witness manifests that assert each fix's load-bearing line still exists. CONFIRMED `ruflo/v3/@claude-flow/security/src/policy/envelope.ts`, `engine.ts`, `ruflo/verification/README.md`.

**Context management.** AgentDB + HNSW "ReasoningBank"; three memory scopes; retrieval guard off by default. CONFIRMED `ruflo/v3/@claude-flow/memory/src/agentdb-retrieval-guard.ts`.

**Parallelism & merge.** Claude Code `Task` subagents; work claims/leases; "A lease or work claim coordinates ownership; it never grants authority". CONFIRMED `ruflo/CLAUDE.md`.

**Cost control.** 3-tier routing: Tier 1 deterministic codemod ($0), Tier 2 Haiku for complexity <30%, Tier 3 Sonnet/Opus; budget ladder 50/75/90/100% with hard stop. CONFIRMED `ruflo/CLAUDE.md` §"3-Tier Model Routing"; `ruflo/plugins/ruflo-cost-tracker/README.md`.

**Caveat.** Marketing claims ("84.8% SWE-bench", "75% cost savings") appear in search snippets and third-party posts; `grep -i swe-bench` over `ruflo/README.md`, `docs/ruflo-explained.md`, `CLAUDE.md` in the clone found **no** SWE-bench figure, and the docs themselves warn tool counts "describe the available interface, not ... capabilities proven in your environment". Treat all ruflo performance numbers as unverified. CONFIRMED (grep) ; INFERRED (snippet) for the claims.

---

## 14. Anthropic, "How we built our multi-agent research system" (June 2025)

Primary page egress-blocked; facts below are INFERRED (snippet) from https://www.anthropic.com/engineering/multi-agent-research-system via search summaries and secondary writeups (bytebytego, zenml, fountaincity.tech).

* Orchestrator-worker: "a lead agent coordinates the overall process while delegating specialized tasks to subagents operating in parallel"; production used an Opus lead with Sonnet subagents; "outperformed single-agent Claude Opus 4 by 90.2%" on their internal research eval.
* Cost: "Multi-agent systems use ~15x more tokens than chat"; "token usage alone explains 80% of performance variance" on BrowseComp.
* Explicit scaling rules in the prompt: "simple fact-finding requires one agent with 3-10 tool calls, direct comparisons need 2-4 subagents with 10-15 calls each, while complex research might deploy more than 10 subagents".
* On coding: "Most coding tasks involve fewer truly parallelizable subtasks than research" — the pattern is presented as a fit for read-heavy, independent-direction research, not for concurrent writes.

---

## 15. Published evaluations 2025-2026: what moves SWE-bench-style outcomes, what is theater

All INFERRED (snippet) unless noted; arXiv/HF/alphaXiv were egress-blocked.

* **Dissecting the SWE-Bench Leaderboards** (arXiv 2506.17208, July 2025 snapshot: 79 Lite / 99 Verified entries): "a mix of both agentic and non-agentic designs", "clear dominance of proprietary LLMs, especially Claude 3.5"; the authors "cannot determine that one architecture achieves better results than the other" from the leaderboards. Closed-model group median 28% Lite / 49% Verified. https://arxiv.org/abs/2506.17208
* **Towards a Science of Scaling Agent Systems** (arXiv 2512.08296, Google/MIT): on parallelizable tasks centralized coordination improved "by 80.9% over a single agent"; on strictly sequential tasks (PlanCraft) "every multi-agent variant tested degraded performance by 39-70%"; as tasks need more tools ("a coding agent with access to 16+ tools") the coordination "tax" grows disproportionately; a predictive model picks the right architecture for 87% of unseen configurations; "Coordination benefits arise from matching communication topology to task structure not from scaling the number of agents". https://arxiv.org/abs/2512.08296
* **Single-Agent LLMs Outperform Multi-Agent Systems on Multi-Hop Reasoning Under Equal Thinking Token Budgets** (arXiv 2604.02460, Apr 2026): once thinking tokens are matched, the multi-agent advantage disappears on multi-hop reasoning; "many elaborate prompting or search strategies fail to outperform simpler baselines once token or compute budgets are matched". https://arxiv.org/html/2604.02460v1
* **R2E-Gym** (arXiv 2504.07164, COLM 2025): "Test-based verifiers suffer from low distinguishability, while execution-free verifiers are biased and often rely on stylistic features"; each saturates around 42-43%, the **hybrid** verifier with best-of-k selection reaches 51% pass@1 on SWE-bench Verified for a 32B open model (from 34.4% pass@1). https://arxiv.org/abs/2504.07164
* **Agentless** (FSE 2025): three-phase non-agent pipeline beat the open-source agents of its time at $0.70/issue (see §12). https://arxiv.org/abs/2407.01489
* **The Complexity Trap** (arXiv 2508.21433, JetBrains, NeurIPS DL4Code 2025): in SWE-agent on SWE-bench Verified, "simple environment observation masking strategy halves cost relative to the raw agent while matching, and sometimes slightly exceeding, the solve rate of LLM summarization" (Qwen3-Coder 480B: 53.8% raw -> 54.8% masked); a hybrid cuts cost a further 7-11%; "Without any context management strategy, agent costs can more than double". https://arxiv.org/abs/2508.21433
* **icat-agent** (arXiv 2606.25514, June 2026): a decentralized multi-agent scaffold that "replaces shared context with synchronous, event-based message passing" and uses "a rubric-based quality checker" so "well-specified issues proceed directly to parallel repair and validation, while ambiguous issues first invoke repository exploration"; reported to beat SWE-agent and mini-SWE-agent on SWE-bench Verified and Pro under the same backbones. https://arxiv.org/abs/2606.25514
* **SWE-agent ACI ablations** (NeurIPS 2024): lint guardrail +3.0 points; dedicated editor +7.7 points; 100-line viewer optimal. https://arxiv.org/abs/2405.15793
* **Aider architect/editor** (Sept 2024): two-model split raised the benchmark from 79.7% to 85% for the best pair; also lifted single models paired with themselves. CONFIRMED (§6).
* **MetaGPT executable feedback**: +4.2% HumanEval / +5.4% MBPP; human revisions 2.25 -> 0.83. INFERRED (snippet) (§10).
* **OpenHands condenser**: up to 2x cost reduction with no degradation (14 models, 5 benchmark categories). INFERRED (snippet) (§9).

**Reading across them.** The things that reliably move outcomes are: (a) execution-grounded verification (tests, reproduction tests, lint-on-edit, hybrid verifiers), (b) best-of-k sampling *with* a verifier, (c) a reasoning/editing split, (d) bounded, well-designed tool interfaces, (e) cheap context management (masking is as good as summarization). Things that look like progress but are not: more agents per se (no leaderboard signal; sequential tasks get 39-70% worse), peer-to-peer swarms, LLM "reviewers" with no execution, and unmatched token budgets in comparisons.

---

# Transferable patterns (for the aos-kernel engineering sector)

Each item: the pattern, where it is proven, and how it lands inside our invariants.

1. **One writer per checkout, worktree per writing run, PR per run.** Claude Code refuses edits/commands that reach the main checkout from a worktree session and cannot be turned off (CONFIRMED §1); `/batch` = 5-30 worktree subagents each opening a PR; OpenHands child conversations default to `isolation=worktree` (CONFIRMED §9); ruflo "never two writers in one worktree" (CONFIRMED §13); Cognition "writes stay single-threaded" (INFERRED §4). For us: the `coder` template's sandbox spec mounts a fresh worktree under the domain `mountRoot`; the kernel, not the agent, creates and removes it, and the only merge path is a PR the human approves (fits invariants 3, 9).

2. **Fresh-context adversarial reviewer that sees only the diff and the acceptance criteria.** Claude Code best-practices ("the agent doing the work isn't the one grading it"; reviewer bias warning) (CONFIRMED §1); Writer/Reviewer session pattern (CONFIRMED). For us: `auditor`/`reviewer` runs are separate runs with read-only tool views on the PR diff; their verdict is advisory input to the human gate, never the gate itself (invariant 3).

3. **Execution-grounded verification before any model-graded verification.** Agentless reproduction + regression rerank (CONFIRMED §12); R2E-Gym hybrid verifier beats either alone (INFERRED §15); MetaGPT executable feedback (INFERRED §10); SWE-agent lint-on-edit (CONFIRMED §5); Claude Code Stop hook with 8-block cap (CONFIRMED §1). For us: a `tester` template whose only job is to run the repo's checks in T3 (no egress) and emit a typed `verify.result` event; the reviewer LLM only runs after tests pass.

4. **Best-of-k candidates selected by a verifier, not by the generator.** Codex `--attempts N` (INFERRED §3); Agentless multi-patch sampling + test rerank (CONFIRMED §12); R2E-Gym best-of-k to 51% (INFERRED §15). For us: the CEO may spawn k ephemeral `worker` runs on the same brief in k worktrees; the kernel's tester picks by test outcome; cost ceiling per objective bounds k.

5. **Reasoning/editing model split.** Aider architect/editor 79.7% -> 85%, and self-pairing helps (CONFIRMED §6); Cline separate Plan/Act models (CONFIRMED §8); Devin Fusion helper models (INFERRED §4). For us: per-agent model binding already exists; add a second binding slot `editorModel` on coder manifests so a local/cheap model applies diffs proposed by the frontier model; both calls still logged as `llm.request`/`llm.response` pairs (invariant 4).

6. **Plan mode as a read-only tool view, then implement.** Claude Code plan mode and Explore/Plan built-ins are read-only tool sets (CONFIRMED §1); Cline Plan "cannot modify any files or execute commands" (CONFIRMED §8). For us: `prototyper`/`architect` templates get a read-only tool view (no `write` risk tools); the plan is a pmmcp goal tree, and implementation is a separate run with `goalId`.

7. **Self-contained delegation brief, summary-only return, no shared mutable state.** Claude Code subagents receive only the Agent prompt string and return only the final message (CONFIRMED §1-2); OpenHands child brief "must be self-contained" (CONFIRMED §9); Cognition 2026 "no peer-to-peer channel and no shared mutable state" (INFERRED §4). For us: the CEO's `delegate` tool schema requires a full brief (paths, acceptance test, out-of-scope), and the run result envelope is typed; inter-agent mail is not a feature in Phase 1.

8. **Hard mechanical caps on fan-out: depth, concurrency, turns, wallclock, spend.** Claude Code depth 3 / concurrency 20 / `maxTurns` partial-and-resumable / `maxBudgetUsd` that kills running background subagents (CONFIRMED §1-2); Goose 25 turns, 5 min, no recursive spawning (CONFIRMED §7); Anthropic's explicit scaling rules by task class (INFERRED §14); ruflo maxAgents 6-8 (CONFIRMED §13). For us: `agents/<id>/agent.yaml` carries `maxTurns`, `wallclock`, `budgetUsd`, `maxChildren`, `maxDepth`; ephemeral templates cannot raise them (invariant 6); the CEO's spawn call is refused by the kernel when a cap would be exceeded.

9. **Condense the view, never the log; bill the condenser.** OpenHands `Condensation` events with `forgotten_event_ids` + `summary_offset` over an append-only log, separate `"condenser"` usage line, up to 2x savings (CONFIRMED source, INFERRED number, §9); Complexity Trap shows plain observation masking matches summarization at half the cost (INFERRED §15). For us: add a `context.condensed` event type; default strategy is observation masking (no LLM), LLM summarization opt-in per agent; chain and redaction untouched (invariant 5).

10. **Design the tool interface, not the org chart.** SWE-agent ACI ablations: editor +7.7, lint +3.0, 100-line window (INFERRED §15, CONFIRMED tool list §5); Aider 1k-token ranked repo map (CONFIRMED §6). For us: the coder's tool view gets a bounded `view_file` (window + scroll), `search` returning filenames only, `edit` with lint-on-edit rejection, and a kernel-generated repo map capped by tokens; each is a tool-view entry with risk/taint classification (invariant 7).

11. **Deterministic hooks as gates, prompts as advice.** Claude Code: hooks "deterministic and guarantee the action happens", CLAUDE.md "advisory" (CONFIRMED §1); OpenHands hook executions logged with `blocked`/`reason` (CONFIRMED §9); Goose recipe `retry` checks (CONFIRMED §7). For us: kernel-side pre/post tool hooks (lint, secret scan, path-confinement) emit events and can deny; they live in the kernel config, never in the workspace the run edits (invariant 8).

12. **Structured artifacts between roles.** MetaGPT PRD/design/task docs (CONFIRMED §10); Goose `response` JSON schema (CONFIRMED §7); OpenHands typed finish status `success|partial_success|blocked|failed` (CONFIRMED §9). For us: every run ends with a zod-validated `run.finished` payload (status, changed files, tests run, evidence pointers); the CEO plans against pmmcp goals, not free text.

13. **Small, verifiable task sizing; stacked small PRs.** Devin 2025 review: 4-8 hour junior-sized tasks, verify the PR, scale horizontally; stacked PRs with CI verification (INFERRED §4); Claude Code teams "5-6 tasks per teammate", "Three focused teammates often outperform five scattered ones" (CONFIRMED §1). For us: the CEO's decomposition rubric caps a coder task at one PR touching one owned file set with a named acceptance test; anything larger becomes a milestone with children.

14. **Capability envelopes that only shrink on delegation, checked before rules.** ruflo `delegateEnvelope` / `capability-envelope-cannot-grow` (CONFIRMED §13); Claude Code teammates inherit the lead's permission mode and cannot escalate via relayed messages (CONFIRMED §1). For us: literally invariant 6 as data: the spawn request carries the child's tools/servers/namespaces/egress/budget and the kernel refuses any field not a subset of the template.

15. **Rerank verifiers are hybrid: execution + execution-free, because each alone saturates.** R2E-Gym (INFERRED §15). For us: tester (execution) plus reviewer (execution-free rubric) both feed the human gate with independent evidence; neither alone marks a PR mergeable.

---

# Anti-patterns (leave out, with the evidence)

1. **The acting model rates its own risk and that rating gates approval.** OpenHands `LLMSecurityAnalyzer` + `ConfirmRisky` (CONFIRMED `OpenHands/src/api/agent-server-adapter.ts` 680-706); ruflo `claims-authorizer` LLM agent and queen-override votes (CONFIRMED `ruflo/.claude/agents/v3/claims-authorizer.md`, `swarm/src/queen-coordinator.ts`). Violates invariant 3: a prompt-injected coder labels everything LOW.

2. **Confirmation off / sandbox off by default for a shell-capable agent.** OpenHands `confirmation_mode: false` -> `NeverConfirm` (CONFIRMED); ruflo-generated Codex `dev` profile `approval_policy="never"` + `danger-full-access` (CONFIRMED `ruflo/v3/@claude-flow/codex/src/generators/config-toml.ts` 670-700); Codex `danger-full-access` and the "bypass the sandbox" folklore (INFERRED §3). We are default deny.

3. **Peer-to-peer swarms and agent "consensus" as coordination.** Cognition: "The unstructured-swarm approach ... is mostly a distraction" (INFERRED §4); scaling paper: sequential tasks degrade 39-70% under every multi-agent variant, coordination tax grows with tool count (INFERRED §15); Claude Code teams are experimental, no worktree isolation, "significantly more tokens", task status lags, no resume (CONFIRMED §1); ruflo raft/byzantine/gossip agents (CONFIRMED §13). For coding, a single orchestrator with stateless workers is the only shape with evidence behind it.

4. **Parallel writers on one tree, or shared mutable memory any agent can write.** Claude Code: "Two teammates editing the same file leads to overwrites" (CONFIRMED §1); Cognition Flappy Bird (INFERRED §4); ruflo AgentDB "accepts writes from any swarm agent with no anomaly detection layer" (CONFIRMED `ruflo/v3/@claude-flow/hooks/src/workers/memory-poison-forensics.ts` header). Our pmmcp writes go through the hub with per-agent `project_id` and a quarantine step.

5. **Credentials in the agent's process or prompt.** OpenHands ACP agents get provider keys as env vars named after the secret and reuse host Keychain logins (CONFIRMED `OpenHands/docs/ACP_AGENTS.md`); ruflo `agentic-payments.md` passes `private_key_hex` through tool args and `code-review-swarm.md` runs `gh auth status` in-agent (CONFIRMED). Invariant 2: injection at the egress proxy only.

6. **Agent-writable policy: hooks, skills, agent definitions inside the workspace the agent edits.** OpenHands `.openhands/hooks.json` and project skills (CONFIRMED `OpenHands/src/api/hooks-service.ts`); ruflo `.claude/agents/*.md` with `hooks.pre/post` shell snippets and self-scored "reward" (CONFIRMED `ruflo/v3/@claude-flow/cli/.claude/agents/core/planner.md`); Claude Code itself skips repo-defined git filter drivers when creating worktrees precisely because "anything that can write to the repository, including Claude, could have put one there" (CONFIRMED §1). Invariant 8.

7. **Multi-agent gains claimed without matched token budgets or execution-grounded verification.** Equal-budget study: advantage vanishes (INFERRED §15); leaderboard profiling finds no architecture signal (INFERRED §15); ruflo "84.8% SWE-bench" not present anywhere in the clone's own docs (CONFIRMED grep §13); "LLM-as-reviewer" without tests is biased toward stylistic features (R2E-Gym, INFERRED). Our eval harness compares against a single-agent baseline at equal spend before any fleet shape is adopted.

8. **Roster sprawl and role theater.** ruflo 89 agent prompt files, 300+ MCP tools, "three separate, non-interoperating things called workers" (CONFIRMED `survey/ruflo.md`); ChatDev/MetaGPT job-title casts (CEO/CTO/PM/QA) whose measured benefit comes from executable feedback and structured artifacts, not the titles (INFERRED §10-11). Every agent we ship needs a manifest, a soul, a tier, an eval, and a budget; if it cannot have all five it is a tool view, not an agent.

9. **LLM summarization as the default condenser when masking is as good.** Complexity Trap: masking halves cost and matches or beats summarization (INFERRED §15). Default to masking; summarize only where an agent's eval shows it helps.

10. **Letting the orchestrator "wait" become "do it itself" or stop early.** Claude Code teams troubleshooting: "the lead starts implementing tasks itself instead of waiting", "The lead can stop early too" (CONFIRMED §1). The CEO's tool view should not include write tools on code; its only outputs are goals, delegations, requests to the human, and summaries.

---

# Recommended engineering-sector shape (derived, for the fleet designer)

* **CEO** (T0, read-only on code): plans into pmmcp goals; `delegate` requires a self-contained brief with acceptance test and owned file set; spawn refused by the kernel above `maxChildren`/`maxDepth`/budget.
* **architect / prototyper** (T1 or T2 read-only tool view): explore + plan + spike in a throwaway worktree; output is a plan artifact and, for prototyper, a demo PR marked non-mergeable.
* **coder** (T2, egress via proxy allowlist): one worktree, one PR, `editorModel` slot for the diff-applier, lint-on-edit tool, `maxTurns` + wallclock; may run k-way best-of-k as ephemeral `worker`s on the same brief.
* **tester** (T3, no egress): runs the repo's checks and reproduction tests, emits typed `verify.result`; the only path to "tests passed" in the log.
* **reviewer / auditor** (T1 read-only on the diff): fresh context, rubric-scoped findings, advisory only.
* **Human gate**: merge is `irreversible`; CI + tester + reviewer evidence are attached to the approval request; the model never decides.
* **Context**: observation masking by default, condensation recorded as events, condenser cost attributed.
* **Eval**: every fleet change measured against single-coder-at-equal-spend on the mock hub before adoption.
