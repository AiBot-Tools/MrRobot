# Landscape survey: Agentic OS / orchestration projects (web)

Purpose: mine other agent operating systems and orchestration frameworks for patterns worth
adopting in the aos-kernel fleet design, and name the patterns to avoid. Scope is the web (not
the reference clones under `scratchpad/refs/`, which have their own per-project files in this
directory). Date: 2026-09-20.

Evidence tags: **CONFIRMED** = I read the cited page during this survey. **INFERRED** = a
reasonable reading of a listing, a search snippet, or a secondary source; not verified in the
primary source. Where a documentation site was blocked by the egress proxy (arxiv.org,
docs.letta.com, microsoft.github.io, docs.ag2.ai, langchain-ai.github.io, docs.langchain.com,
openai.github.io, google.github.io, learn.microsoft.com, open-jarvis.github.io,
techcommunity.microsoft.com) I fell back to the same content in the project's GitHub source or
docs tree, and I say so.

Dimensions per project: orchestration topology · scheduling/lanes · memory tiers · tool
permissioning · human-in-the-loop (HITL) · budgets/cost · evals · audit logging · security
posture.

---

## 1. AIOS (agiresearch, "LLM Agent Operating System")

- Repo: https://github.com/agiresearch/AIOS (CONFIRMED). Paper arxiv 2403.16971 (blocked; not read).
- **Topology**: two layers, "AIOS Kernel" + "AIOS SDK (Cerebrum)"; agents call the kernel
  through "a chain of syscalls that are scheduled and dispatched to run in different modules"
  (README, CONFIRMED). Source tree `aios/`: `config, context, hooks, llm_core, memory,
  scheduler, storage, syscall, terminal, tool, utils` (CONFIRMED via
  https://github.com/agiresearch/AIOS/tree/main/aios). There is **no `access` directory** even
  though the README's architecture figure lists an "Access Manager" (CONFIRMED absence; the
  access manager appears to be a paper-level concept, INFERRED).
- **Scheduling/lanes**: `aios/scheduler/{base.py, fifo_scheduler.py, rr_scheduler.py}`
  (CONFIRMED). `RRScheduler` keeps **separate queues per module** (LLM, memory, storage, tool),
  one processor thread each, a `time_slice` (default 1 s) applied with
  `syscall.set_time_limit(self.time_slice)`; LLM syscalls are batched
  (`_execute_batch_syscalls`), others run one at a time (CONFIRMED via
  raw `aios/scheduler/rr_scheduler.py`).
- **Memory tiers**: "Memory Manager" + "Storage Manager" as separate modules (short-term vs
  persistent) (CONFIRMED module names; tier semantics INFERRED).
- **Tool permissioning**: none described. Tool manager was "redesigned for computer-use agents
  to incorporate VM Controller and MCP Server" (CONFIRMED README).
- **HITL**: none described (CONFIRMED absence in README).
- **Budgets/cost**: none described (CONFIRMED absence).
- **Evals**: none in README (CONFIRMED absence).
- **Audit**: none (CONFIRMED absence).
- **Security posture**: not addressed. LICENSE file is 1 byte / empty and no license badge is
  shown (CONFIRMED via https://github.com/agiresearch/AIOS/blob/main/LICENSE) — treat the
  license as **unknown**; do not copy code.
- Takeaway: the per-resource-queue scheduler with a per-syscall time limit is the one idea worth
  keeping; everything the kernel needs for safety is absent.

## 2. Letta (formerly MemGPT) and Letta Code

- Repos: https://github.com/letta-ai/letta (legacy V1 server on `archive` branch, Apache-2.0),
  https://github.com/letta-ai/letta-code (active, Apache-2.0) (CONFIRMED both). docs.letta.com blocked.
- **Topology**: single stateful agent with optional multi-agent; Letta Code adds built-in
  subagents "general-purpose, forked, recall, history-analyzer" and "Agents can call any other
  agent (including themselves) as subagents" (CONFIRMED letta-code README).
- **Memory tiers** (the reason to study it): base tool set in
  `letta/functions/function_sets/base.py` (archive): `send_message`, `conversation_search`
  ("hybrid search (text + semantic similarity)" over prior history), `archival_memory_insert` /
  `archival_memory_search` ("long-term archival memory"), `core_memory_append` /
  `core_memory_replace`, plus line-level editors `memory_replace`, `memory_insert`,
  `memory_rethink` ("Completely rewrite the contents of a memory block") (CONFIRMED). So three
  tiers: in-context **core memory blocks** the agent edits itself, **recall** (message history
  search), **archival** (vector store). Letta Code moves all context into **MemFS**, "tracked
  via git", syncable to a user repo via `/memory-repository set git@github.com:...`
  (CONFIRMED). Skills are three-tiered: global `~/.letta`, project `.agents/skills`, agent-scoped
  in MemFS (CONFIRMED). A `voice_sleeptime_agent.py` exists in `letta/agents/` (CONFIRMED file
  name; "sleep-time" background memory consolidation INFERRED from name only).
- **Tool permissioning**: `letta/schemas/tool_rule.py` defines a discriminated union of
  **tool rules**: `InitToolRule`, `TerminalToolRule`, `ContinueToolRule`,
  `RequiredBeforeExitToolRule`, `MaxCountPerStepToolRule`, `ChildToolRule`, `ParentToolRule`
  ("only allows a child tool to be called if the parent has been called"),
  `ConditionalToolRule`, and `RequiresApprovalToolRule` ("requires approval before the tool
  can be invoked") (CONFIRMED). Letta Code: "Set permission modes and customize what actions
  are auto-approved or auto-denied" (CONFIRMED).
- **HITL**: `RequiresApprovalToolRule` (CONFIRMED) — approval is a property of the tool, not a
  decision the model makes.
- **Sandboxing**: `letta/services/tool_sandbox/{local_sandbox.py, e2b_sandbox.py,
  modal_sandbox.py, modal_sandbox_v2.py, ...}` (CONFIRMED file names).
- **Budgets/cost, audit, evals**: nothing surfaced in either README (CONFIRMED absence in what I read).
- Takeaway: the **tool-rule grammar** (init/terminal/parent-child/max-per-step/requires-approval)
  is a declarative, model-independent way to constrain a run's tool graph; the three-tier memory
  with agent-editable core blocks maps cleanly onto pmmcp (core = per-agent block in
  `aos/agent/<id>`, archival = pmmcp search, recall = event log search).

## 3. Microsoft AutoGen (0.4+) and AG2

- AutoGen: https://github.com/microsoft/autogen (MIT code / CC-BY-4.0 docs). **"AutoGen is now
  in maintenance mode. It will not receive new features or enhancements and is community
  managed going forward."** Successor: Microsoft Agent Framework (CONFIRMED README).
- **Topology**: Core = "event-driven actor runtime", "single-threaded and distributed gRPC
  runtime"; AgentChat teams `RoundRobinGroupChat`, `SelectorGroupChat`, `Swarm`, `MagenticOne`
  (CONFIRMED README).
- **HITL**: `UserProxyAgent` docstring: "Using UserProxyAgent puts a running team in a
  temporary blocked state until the user responds"; "It is recommended to use termination
  conditions such as HandoffTermination or SourceMatchTermination to stop the running team and
  return control to the application" (CONFIRMED via
  `python/packages/autogen-agentchat/src/autogen_agentchat/agents/_user_proxy_agent.py`).
  The `input_func` may take a `CancellationToken` for timeouts (CONFIRMED).
- **Tool permissioning**: none beyond which tools you register (CONFIRMED absence in README).
- **Sandboxing**: Docker code executor extension; MCP extension (CONFIRMED README).
- **Observability**: OpenTelemetry (CONFIRMED README). Budgets/audit/evals: not in README.
- AG2: https://github.com/ag2ai/ag2 (Apache-2.0). v1.0+ replaced `ConversableAgent`/`GroupChat`
  with an `Agent` + "network hub-and-channels" model; the classic API moved to
  https://github.com/ag2ai/ag2-classic where `human_input_mode` (`ALWAYS`/`TERMINATE`/`NEVER`),
  `DockerCommandLineCodeExecutor`, `LocalCommandLineCodeExecutor`, and cost tracking via
  `gather_usage_summary` live (CONFIRMED both READMEs). Classic is dual MIT (original) +
  Apache-2.0 (modifications) (CONFIRMED).
- Takeaway: the useful lesson is negative — a blocking HITL agent inside the team is an
  anti-pattern; the framework itself tells you to *stop the team and return control to the
  application*. That is exactly the kernel's approvals-as-events model.

## 4. LangGraph

- Repo: https://github.com/langchain-ai/langgraph (MIT). Docs sites blocked; read source.
- **Topology**: graph of nodes with a shared state; subgraphs (general knowledge, INFERRED here).
- **HITL / durability**: `interrupt()` in `libs/langgraph/langgraph/types.py`: "In a given node,
  the first invocation of this function raises a `GraphInterrupt` exception, halting
  execution"; "To use an `interrupt`, you must enable a checkpointer, as the feature relies on
  persisting the graph state"; resume with `Command(resume=...)` where resume is "Mapping of
  interrupt ids to resume values [or] A single value with which to resume the next interrupt";
  caveat: "The graph resumes from the start of the node, **re-executing** all logic"
  (CONFIRMED).
- **Persistence**: `langgraph-checkpoint` defines `BaseCheckpointSaver` (`put`, `get_tuple`,
  `list`, `delete_thread` + async variants), `InMemorySaver`; threads "enable the checkpointing
  of multiple different runs"; separate `SqliteSaver`/`PostgresSaver` packages (CONFIRMED
  README of `libs/checkpoint`). Security note in the same README: set
  `LANGGRAPH_STRICT_MSGPACK=true` or pass `allowed_msgpack_modules` "to restrict deserialization
  to known-safe types" (CONFIRMED).
- **Memory tiers**: thread-scoped checkpoints vs cross-thread `BaseStore` (INFERRED; the store
  page was blocked).
- **Permissioning, budgets, audit, evals**: not part of the library; LangSmith is the external
  tracing/eval product (INFERRED).
- Takeaway: the **interrupt-with-checkpoint** model (pause is a persisted state, resume is a
  typed command keyed by interrupt id) is the right shape for restart-safe approvals; the
  re-execution caveat is a warning to make everything before an approval idempotent, or to
  place the gate *before* side effects, which the kernel already does.

## 5. OpenAI Agents SDK

- Repo: https://github.com/openai/openai-agents-python (MIT). Docs site blocked; read `docs/*.md`
  in the repo.
- **Topology / handoffs**: handoffs "function as tools with names following the pattern
  `transfer_to_<agent_name>`"; `handoff(agent, tool_name_override, tool_description_override,
  on_handoff, input_type, input_filter, is_enabled)`; `handoff_filters.remove_all_tools` strips
  tool items from history on transfer; `RECOMMENDED_PROMPT_PREFIX` /
  `prompt_with_handoff_instructions` (CONFIRMED `docs/handoffs.md`).
- **Guardrails**: input guardrails "run only for the first agent in the chain"; output
  guardrails "run only for the agent that produces the final output"; **tool guardrails** "run
  on every guarded function-tool invocation" with input checks before and output checks after;
  tripwires raise `InputGuardrailTripwireTriggered`, `OutputGuardrailTripwireTriggered`,
  `ToolInputGuardrailTripwireTriggered`, `ToolOutputGuardrailTripwireTriggered`; input
  guardrails default to `run_in_parallel=True`, and `run_in_parallel=False` "prevent[s] token
  consumption if blocked" (CONFIRMED `docs/guardrails.md`).
- **Tracing**: spans `agent_span`, `generation_span`, `function_span`, `guardrail_span`,
  `handoff_span`, `mcp_tools_span` (listed in the doc), `transcription_span`, `speech_span`;
  `RunConfig.trace_include_sensitive_data` (default True) controls whether "LLM generation
  inputs/outputs and function call data" are captured; `add_trace_processor` vs
  `set_trace_processors`; the doc advises keeping "redaction and delivery inside the same
  application-owned exporter" (CONFIRMED `docs/tracing.md`).
- **Usage**: `result.context_wrapper.usage` has `requests`, `input_tokens`, `output_tokens`,
  `total_tokens`, "aggregated across all model calls during the run, including model calls
  that produce tool calls or handoffs"; **no dollar cost is computed** (CONFIRMED `docs/usage.md`).
- **Memory**: `Session` protocol (`get_items`, `add_items`, `pop_item`, `clear_session`),
  `SQLiteSession`, `SQLAlchemySession`, `OpenAIConversationsSession`, `EncryptedSession`
  (encryption + TTL), `SessionSettings(limit=N)`, `RunConfig.session_input_callback` for
  trimming (CONFIRMED `docs/sessions/index.md`).
- **Permissioning / HITL / budgets / audit**: no permission model; HITL is "raise a tripwire"
  or your own tool guardrail; no budgets; tracing is not tamper-evident (CONFIRMED absence).
- Takeaway: **tool guardrails as a per-invocation pre/post hook** and **handoff input filters**
  (strip history on delegation) are directly transferable; the `trace_include_sensitive_data`
  switch is a reminder that the kernel's redaction must be *in* the logger, not in an exporter.

## 6. Google ADK

- Repo: https://github.com/google/adk-python (Apache-2.0, INFERRED license from org norms —
  not read). Docs site blocked; read source and `google/adk-docs` raw where paths existed.
- **Topology**: `LlmAgent` with `sub_agents`; LLM-driven transfer can be disabled per agent:
  `disallow_transfer_to_parent` ("Disallows LLM-controlled transferring to the parent agent")
  and `disallow_transfer_to_peers` (CONFIRMED `src/google/adk/agents/llm_agent.py`). Workflow
  agents `SequentialAgent`/`ParallelAgent`/`LoopAgent` (INFERRED; page 404'd at guessed path).
  `output_key` writes an agent's output into shared session state (CONFIRMED docstring).
- **Callbacks (policy hooks)**: `before_agent_callback`, `after_agent_callback`,
  `before_model_callback`, `after_model_callback`, `before_tool_callback` ("Can modify tool
  arguments, perform authorization checks, or skip tool execution entirely by returning a
  dictionary, which becomes the tool result"), `after_tool_callback` (CONFIRMED
  `docs/callbacks/types-of-callbacks.md`). Callback lists short-circuit on first non-None
  (CONFIRMED llm_agent.py docstrings).
- **HITL**: `FunctionTool(require_confirmation: Union[bool, Callable[..., bool]] = False)`;
  when required and not yet supplied, the tool calls `tool_context.request_confirmation(...)`
  and returns `"This tool call requires confirmation, please approve or reject."`; the answer
  arrives as `tool_context.tool_confirmation` (a `ToolConfirmation` with `.confirmed`); a
  rejection returns `{"error": "This tool call is rejected."}` (CONFIRMED
  `src/google/adk/tools/function_tool.py`). The predicate is **developer code over the
  arguments**, never the model.
- **Memory tiers**: session `state` (short-term) vs `BaseMemoryService` implementations
  `InMemoryMemoryService`, `VertexAiMemoryBankService`, `VertexAiRagMemoryService`
  (CONFIRMED file names under `src/google/adk/memory/`).
- **Evals**: `.test.json` unit files and evalset files; `adk eval` CLI; `adk conformance`
  regression "comparing live agent behavior against recorded baseline interactions in Replay
  or Live modes"; metrics `tool_trajectory_avg_score` (exact tool-call match),
  `response_match_score` (ROUGE-1), `final_response_match_v2` (LLM-judged) (CONFIRMED
  `docs/evaluate/index.md`).
- **Budgets, audit, security**: no budget or tamper-evident log in what I read (CONFIRMED absence).
- Takeaway: **trajectory evals with a recorded-baseline conformance mode** is the closest
  published match to the Phase 1 "eval harness scoring orchestration tasks against the mock
  hub"; `require_confirmation` as a callable over args is a nice refinement of "irreversible
  ⇒ human" (e.g. `amount > threshold`).

## 7. Anthropic Claude Agent SDK

- Docs: https://code.claude.com/docs/en/agent-sdk/overview and
  https://code.claude.com/docs/en/agent-sdk/permissions (CONFIRMED). Governed by Anthropic's
  Commercial Terms, not an OSS license (CONFIRMED overview).
- **Permission evaluation order** (verbatim structure): 1 **Hooks** (`PreToolUse` can deny;
  "A hook that returns `allow` does not skip the deny and ask rules") → 2 **Deny rules**
  (`disallowed_tools`; bare-name deny removes the tool from the model's context; scoped deny
  like `Bash(rm *)` "blocked, even in `bypassPermissions` mode") → 3 **Ask rules** (fall
  through to `canUseTool`; MCP tools with `_meta["anthropic/requiresUserInteraction"]` always
  reach the callback) → 4 **Permission mode** (`default`, `dontAsk`, `acceptEdits`,
  `bypassPermissions`, `plan`, `auto`) → 5 **Allow rules** (`allowed_tools`; globs only after a
  literal `mcp__<server>__` prefix) → 6 **`canUseTool` callback** (skipped and denied in
  `dontAsk`) (CONFIRMED).
- Explicit warnings worth quoting: "**Auto-approved tools never reach `canUseTool`**"; "For
  checks that must run on every tool call, use a `PreToolUse` hook: hooks run before every
  other step, and a hook deny applies even in `bypassPermissions` mode";
  "**`allowed_tools` does not constrain `bypassPermissions`**"; subagents inherit the parent's
  mode and "Claude Code never applies a `"bypassPermissions"` value" from an
  `AgentDefinition` (CONFIRMED).
- `auto` mode = "A model classifier approves or denies permission prompts" (CONFIRMED) — this
  is a model making an access-control decision, which the kernel forbids (see anti-patterns).
- Sessions (resume/fork), subagents, hooks, MCP, plugins, skills all present (CONFIRMED overview table).
- Budgets/audit: not in the two pages read (absence CONFIRMED for those pages only).
- Takeaway: the **six-step, deny-first evaluation order with hooks that cannot be bypassed by
  any mode** is the best-documented permission pipeline in the survey and matches invariant 3;
  copy the ordering and the "bare deny removes the tool from context" trick.

## 8. Anthropic Claude Managed Agents (beta `managed-agents-2026-04-01`)

- Docs: overview, tools, permission-policies, sessions, budgets, vaults under
  https://platform.claude.com/docs/en/managed-agents/ (all CONFIRMED).
- **Topology**: Agent (model, system prompt, tools, MCP servers, skills) / Environment (cloud or
  self-hosted sandbox) / Session / Events; multiagent sessions with a coordinator and a roster
  (CONFIRMED overview + tools page).
- **Scheduling**: "Scheduled execution: Recurring agent runs on a cron schedule through
  scheduled deployments" (CONFIRMED overview).
- **Tool permissioning**: `permission_policy` per toolset (`default_config`) or per tool
  (`configs[]`): `always_allow`, `always_ask`, `auto`. Defaults: agent toolset
  `always_allow`, **MCP toolsets `always_ask`** ("This ensures that new tools added to an MCP
  server do not execute in your application without approval") (CONFIRMED). Every
  `agent.tool_use` / `agent.mcp_tool_use` event carries `evaluated_permission`
  (`allow|ask|deny`) and an `evaluation` object with `type` and, under `auto`, a `reason_code`
  ("a value for your client to branch on and keep in audit records") (CONFIRMED).
- **HITL**: on `ask` the session emits `session.status_idle` with
  `stop_reason.type = requires_action` and `stop_reason.event_ids`; the client answers with
  `user.tool_confirmation {tool_use_id, result: allow|deny, deny_message}`; "The session waits
  indefinitely"; a client "cannot override" an `auto` deny (CONFIRMED). Warning verbatim:
  "**`auto` is not a human checkpoint.** If the server determines that a call is safe, the
  call runs before anyone sees it, and its effects might not be reversible" (CONFIRMED).
- **Egress control**: per-tool `allowed_domains` / `blocked_domains` for `web_search` and
  `web_fetch`; in multiagent sessions "a roster agent can narrow what a tool reaches but never
  widen it" (allowlists intersect, blocklists union) (CONFIRMED tools page).
- **Budgets**: `budget: {type: "limit", max_list_cost: {amount: "<cents as string>", currency:
  "USD"}}`; "The cap is enforced between model requests, not mid-request"; overshoot "bounded
  by one model request per thread"; session goes idle with `stop_reason = budget_reached`
  and emits a `session.usage` event first; at the cap only settle events
  (`user.tool_confirmation`, `user.tool_result`, `user.custom_tool_result`, `user.interrupt`)
  are accepted; multiagent sessions share one budget; deployments copy the cap onto each run;
  budgets are rejected for models "with no public list price" (CONFIRMED budgets page).
- **Secrets**: Vaults hold `mcp_oauth`, `static_bearer`, and `environment_variable`
  credentials. For env vars the secret is "stored in the sandbox as an opaque placeholder.
  When the agent initiates an outbound request, the opaque placeholder is substituted with the
  real secret at egress. The agent never sees the secret value"; `networking.allowed_hosts`
  scopes which hosts get substitution; `injection_location {header, body}`; "Substitution is
  outbound only" so exchange flows leak the returned token (CONFIRMED vaults page).
- **Audit**: server-side persisted event history with `evaluated_permission` on each tool event
  (CONFIRMED); not described as hash-chained (absence CONFIRMED for pages read).
- **Evals**: "outcome-driven sessions" with a grader that "runs without `web_search` and
  `web_fetch`" (CONFIRMED mention on tools page; details not read).
- Takeaway: this is the closest commercial analogue to the kernel: **placeholder-at-rest,
  substitute-at-egress credentials** = invariant 2; **narrow-only inheritance of egress lists
  in a roster** = invariant 6; **hard budget enforced between requests with explicit
  `budget_reached` stop reason and a usage snapshot** = the shape for `run.finished` cost
  accounting. Note the pattern it declines to give you: a tamper-evident log.

## 9. Semantic Kernel and Microsoft Agent Framework (MAF)

- Semantic Kernel: https://github.com/microsoft/semantic-kernel (MIT). "Semantic Kernel is now
  Microsoft Agent Framework!"; planners deprecated; filters = function invocation, prompt
  render, auto function invocation (CONFIRMED README + `python/semantic_kernel/filters/`
  directory names `auto_function_invocation`, `functions`, `prompts`, `filter_types.py`).
- MAF: https://github.com/microsoft/agent-framework (MIT). "Graph-Based Workflows" with
  "checkpointing, streaming, human-in-the-loop, and time-travel"; middleware system;
  OpenTelemetry (CONFIRMED README). Source: `ApprovalMode: TypeAlias = Literal["always_require",
  "never_require"]`; `FunctionTool` default "approval is NOT required (`"never_require"`)";
  `_ensure_approved_arguments_unchanged()` "detects when middleware modifies approved
  arguments and raises `_FunctionArgumentsChangedAfterApproval`" (CONFIRMED
  `python/packages/core/agent_framework/_tools.py`). Workflows dir has `_checkpoint.py`,
  `_checkpoint_encoding.py`, `_request_info_mixin.py` (CONFIRMED file names). Search snippets
  (INFERRED, Learn pages blocked): `ctx.request_info()` emits a `RequestInfoEvent`, the workflow
  enters `IDLE_WITH_PENDING_REQUESTS`, and "pending requests are also saved as part of the
  checkpoint state" so a restore re-emits them.
- Budgets/audit/taint: none seen (absence CONFIRMED for README/source read).
- Takeaway: **bind the approval to the exact argument bytes** (`_FunctionArgumentsChangedAfterApproval`)
  and **persist pending requests inside the checkpoint** so a restart re-raises them — both
  belong in the Phase 1 restart-safe approvals projection.

## 10. CAMEL and OWL

- CAMEL: https://github.com/camel-ai/camel (Apache-2.0). Principles "Evolvability, Scalability
  (millions of agents), Statefulness, Code-as-Prompt" (CONFIRMED README).
- **Topology**: `RolePlaying` (AI user ↔ AI assistant) and `Workforce`. `Workforce`
  (`camel/societies/workforce/workforce.py`, CONFIRMED): a **coordinator agent** ("assigning
  tasks to a existing worker, creating a new worker for a task"), a **task agent** (planner:
  decompose/compose), worker nodes ("a group of agents or a single agent"), a `TaskChannel`,
  `WorkforceMode.AUTO_DECOMPOSE` vs `PIPELINE`, `RecoveryStrategy` enum `RETRY | REPLAN |
  REASSIGN | DECOMPOSE | CREATE_WORKER`, `FailureHandlingConfig(max_retries,
  enabled_strategies)`, `MAX_PENDING_TASKS_LIMIT = 20`, `TASK_TIMEOUT_SECONDS = 600.0`, and
  operator controls `pause()/resume()`, `stop_gracefully()/stop_immediately()`,
  `modify_task_content()`, `reorder_tasks()`, `save_snapshot()` (CONFIRMED). Supporting files
  `workforce_logger.py`, `workforce_metrics.py`, `workflow_memory_manager.py` (CONFIRMED names).
- **Memory**: `ChatHistoryMemory`, `VectorDBMemory`, `LongtermAgentMemory` (CONFIRMED README).
- **Sandboxing**: `DockerInterpreter`, E2B, subprocess interpreters (CONFIRMED README).
- **HITL**: README links a cookbook "agents_with_human_in_loop_and_tool_approval"
  (CONFIRMED link text); `HumanToolkit` itself only has `ask_human_via_console` and
  `send_message_to_user` — no gating (CONFIRMED source). Tool approval lives in the cookbook
  (INFERRED, not read).
- OWL: https://github.com/camel-ai/owl (Apache-2.0); "69.09 average score on GAIA benchmark";
  role-playing user/assistant with MCP (CONFIRMED README).
- Budgets/audit: none (absence CONFIRMED in README).
- Takeaway: the **explicit recovery-strategy enum with a max-retry config and a hard pending
  limit** is the cleanest published spec for what the CEO loop should do when a child run
  fails; `CREATE_WORKER` maps to spawning an ephemeral agent from a template (bounded by
  invariant 6).

## 11. smolagents (Hugging Face)

- Repo: https://github.com/huggingface/smolagents (Apache-2.0) (CONFIRMED).
- **Topology**: `CodeAgent` (actions as Python code; "uses 30% fewer steps") vs
  `ToolCallingAgent`; `managed_agents` for hierarchy; `max_steps`, `planning_interval`
  (CONFIRMED README).
- **Security posture (the key content)**: `LocalPythonExecutor`: "imports are disallowed unless
  they have been explicitly added to an authorization list by the user"; "access to submodules
  is disabled by default"; operation cap "to prevent infinite loops"; "Any operation that has
  not been explicitly defined in our custom interpreter will raise an error". But: "no local
  python sandbox can ever be completely secure" and "the only way to run LLM-generated code
  with truly robust security isolation is to use remote execution options";
  `executor_type` ∈ {blaxel, e2b, modal, docker} (CONFIRMED
  `docs/source/en/tutorials/secure_code_execution.md`). README: "`LocalPythonExecutor`
  provides best-effort mitigations only and is not a security boundary" (CONFIRMED).
- Memory, permissioning, HITL, budgets, audit: `memory`/`steps` logging and OpenTelemetry only
  (CONFIRMED README); nothing else.
- Takeaway: adopt the honesty, not the executor: an in-process interpreter with an import
  allowlist is a **T1 convenience**, never a tier boundary. The kernel's T1 "process sandbox"
  should be described the same way.

## 12. Agent Zero

- Repo: https://github.com/agent0ai/agent-zero (MIT, © Agent Zero s.r.o.) (CONFIRMED LICENSE).
- **Topology**: "Every agent can create subordinate agents to break down work. The superior
  gives tasks and receives reports; subagents keep their own contexts focused and return their
  findings when done" (CONFIRMED README).
- **Memory**: projects "isolate workspaces, instructions, memory, secrets, knowledge,
  repositories, and model-preset choices"; auto-memorization (CONFIRMED README).
- **Scheduling**: scheduler for "recurring checks and monitoring tasks" with "project-scoped
  context and credentials" (CONFIRMED).
- **Security posture**: full Dockerized Linux desktop (XFCE, Blender, LibreOffice, browser);
  "Keep it running inside Docker or another isolated environment. Do not mount your entire home
  directory unless you understand the risk" (CONFIRMED README). Behavior is prompts in
  `prompts/`, tools in `tools/`, MCP + A2A (CONFIRMED).
- Permissioning, HITL gate, budgets, audit, evals: none (absence CONFIRMED in README).
- Takeaway: the "secrets scoped to a project" idea is fine; the rest is the anti-pattern the
  CLAUDE.md already names (agent holds credentials, isolation is advice not enforcement).

## 13. OpenManus (and Manus)

- Repo: https://github.com/FoundationAgents/OpenManus (MIT); "No fortress, purely open ground"
  (CONFIRMED README). Manus itself is a closed product; not surveyed (no primary source read).
- **Topology**: `Manus` agent over a `ToolCallAgent` loop; `PlanningFlow` for multi-agent;
  optional DataAnalysis agent (CONFIRMED README).
- **Sandboxing**: Docker sandbox configured in `config.toml`; browser via "Browser Use CLI 3.0
  as default MCP server"; python execute tool (CONFIRMED README).
- Permissioning, HITL, budgets, audit, evals: "does not specify explicit permissions models,
  token budgets, or audit logging" (CONFIRMED absence in README). OpenManus-RL exists for RL
  tuning (CONFIRMED mention).
- Takeaway: nothing to adopt beyond confirming that "sandbox = a Docker flag in config" is the
  common floor; the kernel's container flags (invariant 9) are already stricter.

## 14. Suna / Kortix

- Repo: https://github.com/kortix-ai/suna. **License: Elastic License 2.0** (CONFIRMED
  `LICENSE`) — not OSI open source; do not vendor code.
- **Topology**: "Org-scale specialist agents that run in parallel" with "a scoped reach into
  tools"; "Every session gets its own cloud computer — a disposable, isolated Linux sandbox on
  its own branch" (CONFIRMED README).
- **Scheduling**: "Cron and signed webhooks that spawn sessions automatically" (CONFIRMED).
- **Memory**: skills and memory "versioned, diffable, and shared by the whole company" in "a
  git repository" (CONFIRMED).
- **Secrets**: "Credentials are brokered server-side through one scoped token and never enter
  the machine" (CONFIRMED).
- **HITL**: "Approval gates you switch on for the actions that matter" — opt-in, not default
  (CONFIRMED). Budgets/audit/taint: not in README (CONFIRMED absence).
- Takeaway: confirms the industry direction on credential brokering; its opt-in approval
  default is the opposite of invariant 3.

## 15. Paperclip (paperclipai) — verified: it exists

- Repo: https://github.com/paperclipai/paperclip (MIT) (CONFIRMED). Tagline: "If OpenClaw is
  an _employee_, Paperclip is the _company_" (CONFIRMED README).
- **Topology**: companies → org chart with roles/titles/reporting lines; CEO agent; issues with
  "full goal ancestry so agents consistently see the 'why'"; "Every task exists in service of
  a parent task, all the way up to the company goal" (CONFIRMED README + `doc/PRODUCT.md`).
  Adapters: OpenClaw, Claude Code, Codex, Cursor, Bash, HTTP — "If it can receive a heartbeat,
  it's hired" (CONFIRMED).
- **Scheduling/lanes**: **heartbeats** — "Agents wake on a schedule, check work, and act";
  "DB-backed wakeup queue with coalescing, budget checks, workspace resolution, secret
  injection"; "Task checkout and budget enforcement are atomic" (CONFIRMED README/search
  snippet of README). `doc/TASK-WATCHDOG.md`: reconciliation "at server startup, at the end of
  each heartbeat cycle, and on demand after any mutation"; fires only when "every leaf in that
  subtree comes to rest ... and there is no live continuation path"; explicitly "not an
  output-silence monitor for active runs" (CONFIRMED).
- **Budgets/cost**: "Monthly budgets per agent. When they hit the limit, they stop. No runaway
  costs."; "Token and cost tracking by company, agent, project, goal, issue, provider, and
  model"; PRODUCT.md: "Auto mode is allowed; hidden token burn is not" (CONFIRMED).
- **HITL / governance**: "Board approval workflows, execution policies with review/approval
  stages, decision tracking, budget hard-stops, agent pause/resume/terminate"; board approval
  required to hire (add to org chart); config changes "revisioned" with rollback (CONFIRMED).
- **Tool permissioning (MCP)**: `doc/MCP-ACCESS-GOVERNANCE.md`: Applications / Connections /
  Catalog entries / Profiles; "profile says *can this agent see the tool*; policy says *is this
  exact call allowed right now*"; policy types `allow`, `block` (overrides allow),
  `require_approval`, `rate_limit`, `trust_rule`; an approval opens an **Action Request**
  carrying "a canonical hash of the arguments" and can be promoted to a `trust_rule` that
  "match[es] exact argument shapes only" and is invalidated if the catalog schema changes
  (CONFIRMED). Local stdio MCP requires explicit trust and "Never set
  `PAPERCLIP_TRUSTED_MCP_RUNTIME_HOST` on the same worker that serves public HTTP traffic"
  (CONFIRMED).
- **Trust tiers**: `doc/LOW-TRUST-PRESETS.md`: `low_trust_review` preset; "Low-trust agents
  cannot read or mutate agent configuration, instruction bundles, or company skill
  configuration"; prevents "raw untrusted output from being automatically promoted into
  higher-trust agent context"; requires "the `sandbox` driver" and `isolated_workspace`;
  "Inline sensitive environment values such as API keys and tokens are rejected"; presets
  intersect agent/project/issue scope, "Narrower wins"; containment "fails closed" (CONFIRMED).
  Caveat: PRODUCT.md says "Skill permissions are opt-in restrictions, not opt-in capabilities"
  — default-open for skills (CONFIRMED).
- **Audit**: "Mutating actions, heartbeat state changes, cost events, approvals, comments, and
  work products are recorded as durable activity"; the MCP call event log records "decision,
  matched policies, reason codes, redaction applied, and outcomes" and is "intentionally
  append-only — there is no edit or delete route" (CONFIRMED). **Not hash-chained** (absence
  CONFIRMED in the docs read).
- **Identity/secrets**: "Agent API keys, short-lived run JWTs, company memberships"; "Instance
  and company secrets, encrypted local storage ... Sensitive values stay out of prompts unless
  a scoped run explicitly needs them" (CONFIRMED README).
- **Evals**: none seen (absence CONFIRMED for pages read).
- Takeaway: the single richest source for the *organizational* layer: goal ancestry on every
  task, heartbeat wake-ups with atomic checkout+budget check, per-agent monthly budgets with
  hard stops, board-gated hiring, argument-hash-bound approvals promotable to trust rules,
  and low-trust presets that fail closed. Its default-open skills and non-chained log are the
  two places the kernel is already stricter.

## 16. Archon (coleam00)

- Repo: https://github.com/coleam00/Archon (MIT) (CONFIRMED). Now "The first open-source
  harness builder for AI coding" — YAML workflow DAGs (planning, implementation, validation,
  review, PR), "Git worktree isolation for concurrent workflow execution", SQLite/Postgres
  backend, platform adapters (Web, CLI, Telegram, Slack, Discord, GitHub), 19 bundled
  workflows; the old task-management + RAG Archon is on branch `archive/v1-task-management-rag`
  (CONFIRMED README).
- Permissioning, budgets, audit, HITL: "no explicit mention" (CONFIRMED absence).
- Takeaway: **workflows as data (YAML DAG of deterministic bash/git nodes interleaved with AI
  nodes) plus per-run git worktrees** is the right shape for the coding-fleet lane; the kernel
  would run each node as a gated run rather than as an unmediated step.

## 17. Dify and Flowise (briefly)

- Dify: https://github.com/langgenius/dify; "Dify Open Source License, based on Apache 2.0
  with additional conditions" (CONFIRMED README). Visual workflow/agent builder, RAG, LLMOps
  logs, MCP tools. Release 1.13.0 added a **Human Input node**: "suspend workflow execution at
  critical decision points", forms delivered "via Webapp or Email", custom buttons
  ("Approve," "Reject," "Escalate") route the graph, `HUMAN_INPUT_GLOBAL_TIMEOUT_SECONDS`
  default 604800 (7 days) (CONFIRMED release page).
- Flowise: https://github.com/FlowiseAI/Flowise (Apache-2.0); **archived August 13, 2026**,
  read-only (CONFIRMED README banner).
- Takeaway: Dify's approval **timeout with a defined expiry** is a detail the kernel's
  approvals projection needs (an approval that never expires is an orphan).

## 18. OpenJarvis (Stanford Hazy Research / Scaling Intelligence Lab)

- Repo: https://github.com/open-jarvis/OpenJarvis (Apache-2.0) (CONFIRMED). Docs site blocked.
- **Topology / scheduling**: eight built-in agents in three modes — scheduled
  (`morning_digest`), on-demand (`deep_research`, `orchestrator`, `native_react`,
  `native_openhands`, `simple`), continuous (`monitor_operative`, `operative`) (CONFIRMED README).
- **Evals**: "energy, FLOPs, latency, and dollar cost as first-class constraints alongside
  accuracy"; claim that local models handle "88.7% of single-turn queries" (CONFIRMED README;
  the number is the project's own claim).
- **Learning loop**: "improves models using local trace data" (CONFIRMED).
- **Skills**: agentskills.io standard; imports from Hermes Agent (~150) and OpenClaw
  (~13,700) skill catalogs (CONFIRMED README).
- Permissioning, sandboxing, budgets, audit: "No explicit sandboxing details" (CONFIRMED absence).
- Takeaway: the **local-first routing eval** (accuracy × energy × latency × cost) is the right
  frame for `aos probe` and for deciding when Bonsai/Ollama is enough; nothing else to take.

## 19. Extra data points found while searching (not in the assigned list)

- **OpenFang** (https://github.com/RightNow-AI/openfang, Rust, MIT/Apache-2.0): "Merkle
  Hash-Chain Audit Trail — Every action is cryptographically linked to the previous one"
  (SHA-256, `verify_integrity()`), "Taint Tracking — information flow labeled from source to
  sink", "WASM Dual-Metered Sandbox ... fuel metering + epoch interruption", "Ed25519 Signed
  Manifests", "Capability Gates, RBAC", 27 providers with cost tracking; "Browser (web
  automation with mandatory purchase approval)" (CONFIRMED README). Budget *enforcement*
  formulas not documented (CONFIRMED absence). This is the only surveyed project that claims
  all four of: hash-chained log, taint tracking, capability gates, per-action cost tracking.
- **CaMeL** (Google DeepMind, "Defeating Prompt Injections by Design", arxiv 2503.18813 —
  blocked; summary via https://simonwillison.net/2025/Apr/11/camel/ and search snippets,
  INFERRED): a Privileged LLM plans in a locked-down Python subset and "never sees raw user
  data"; a Quarantined LLM reads untrusted content; **capabilities** on values enforce security
  policies at tool-call time so untrusted data "can never impact the program flow"; 77% of
  AgentDojo tasks solved with provable security vs 84% undefended.
- Hash-chained audit ecosystem (INFERRED from search snippets, not read): halo-record
  (https://github.com/bkuan001/halo-record), Asqav (signed + chained trail for LangChain,
  CrewAI, LiteLLM, Haystack, OpenAI Agents SDK), enclawed (arxiv 2604.16838: "every record is
  canonicalized as JSON and hashed"), and a Hermes Agent feature request #487 for a
  "SHA-256 Hash-Chained Action Log ... inspired by OpenFang".

---

## Feature matrix: who actually implements the kernel's hard requirements

| Project | Hash-chained / immutable audit log | Per-agent or per-run budget with hard stop | Taint tracking | Capability / trust tiers |
|---|---|---|---|---|
| AIOS | no | no | no | no |
| Letta | no | no | no | tool rules (per-tool, not tiers) |
| AutoGen / AG2 | no (OTel traces; classic has usage summary) | no | no | no |
| LangGraph | no (checkpoints are mutable state) | no | no | no |
| OpenAI Agents SDK | no (traces; sensitive-data switch) | no (usage counts only, no $) | no | no |
| Google ADK | no | no | no | no (callbacks only) |
| Claude Agent SDK | no | no (in pages read) | no | permission modes + deny/ask/allow rules |
| Claude Managed Agents | append-only server event history, **not chained** | **yes**: session `max_list_cost`, `budget_reached`, settle-only at cap | no | policy per tool (`always_allow/always_ask/auto`); roster egress narrow-only |
| Semantic Kernel / MAF | no | no | no | approval bound to argument bytes |
| CAMEL / OWL | no (workforce logger) | no | no | no |
| smolagents | no | no | no | executor types (not a boundary, by their own admission) |
| Agent Zero | no | no | no | no |
| OpenManus | no | no | no | no |
| Suna / Kortix | no | credits/billing (INFERRED) | no | scoped tool reach (INFERRED) |
| Paperclip | **append-only, no edit/delete route; not hash-chained** | **yes**: monthly per-agent, atomic with task checkout | no (but "raw untrusted output" containment) | **yes**: `low_trust_review` preset, fails closed |
| Archon | no | no | no | no |
| Dify / Flowise | run logs | no | no | no |
| OpenJarvis | no | no (cost is an eval axis) | no | no |
| OpenFang (extra) | **yes** (SHA-256 chain, `verify_integrity`) | cost tracking; enforcement undocumented | **yes** (claimed) | **yes** (capability gates, RBAC, signed manifests) |
| CaMeL (paper, extra) | n/a | n/a | **yes** (capabilities on data) | dual-LLM privilege split |

Conclusion: **none of the assigned mainstream frameworks ships a hash-chained log or taint
tracking.** aos-kernel's invariants 3, 5 and 9 are ahead of the field; the field is ahead of the
kernel on budgets (Managed Agents, Paperclip), approvals ergonomics (argument-hash binding,
trust-rule promotion, expiry), and evals (ADK).

---

## Transferable patterns (each fits inside the CLAUDE.md invariants)

1. **Deny-first, hook-first permission pipeline that no mode can bypass.** Order: hooks → deny
   rules → ask rules → mode → allow rules → callback; bare-name deny removes the tool from the
   model's context entirely; "hooks run before every other step, and a hook deny applies even
   in `bypassPermissions`" (Claude Agent SDK permissions page, CONFIRMED). Map: `policy gate`
   is the hook; `tool-views.yaml exposure` is the deny/allow list; `kernel-only` = removed from
   context, not merely refused.
2. **Bind an approval to the canonical hash of the exact arguments; promote to a scoped trust
   rule; invalidate on schema drift.** Paperclip MCP-ACCESS-GOVERNANCE (CONFIRMED) and MAF's
   `_FunctionArgumentsChangedAfterApproval` (CONFIRMED). Map: `approval.granted` event carries
   `argsHash`; execution re-hashes and refuses on mismatch; a human may file a `trust_rule`
   that only auto-allows identical shapes; Phase 2 schema-hash pinning invalidates them.
3. **Approvals are persisted, resumable interrupts with an expiry.** LangGraph `interrupt()` +
   checkpointer + `Command(resume=…)` keyed by interrupt id (CONFIRMED); MAF saves pending
   requests inside the checkpoint so a restore re-emits them (INFERRED); Dify's
   `HUMAN_INPUT_GLOBAL_TIMEOUT_SECONDS` (CONFIRMED). Map: Phase 1 "restart-safe projections"
   rebuild pending approvals from the log and expire them; LangGraph's re-execution caveat says
   the gate must sit *before* side effects (it does).
4. **Hard dollar budget enforced between model requests, with a named stop reason and a usage
   snapshot.** Managed Agents `max_list_cost` / `budget_reached` / `session.usage`; overshoot
   bounded by one request; only settle events accepted at the cap; refuse budgets on models
   without a list price (CONFIRMED). Map: `budgets` component emits `run.budget_reached`, then
   `run.finished` with cost; `providers.yaml` pricing is mandatory for any bound model.
5. **Per-agent recurring budget with atomic checkout.** Paperclip "Monthly budgets per agent.
   When they hit the limit, they stop"; "Task checkout and budget enforcement are atomic"
   (CONFIRMED). Map: the lane queue checks the agent's remaining monthly budget in the same
   transaction that claims the run.
6. **Credentials as opaque placeholders substituted at egress, scoped to hosts and to
   header/body.** Managed Agents vaults: "The agent never sees the secret value";
   `networking.allowed_hosts`; `injection_location {header, body}`; warning that exchange
   flows leak tokens (CONFIRMED). Suna: "brokered server-side through one scoped token"
   (CONFIRMED). Map: Phase 2 egress proxy sidecar — this is the spec; forbid OAuth
   client-credential exchanges from inside the container.
7. **Delegated agents can narrow but never widen the parent's egress and tool surface.**
   Managed Agents multiagent: allowlists intersect, blocklists union (CONFIRMED). Map:
   invariant 6 generalised — ephemeral template ⊆ parent's tier, egress, tool view.
8. **Declarative tool rules per run.** Letta `InitToolRule`, `TerminalToolRule`,
   `ParentToolRule`, `MaxCountPerStepToolRule`, `RequiredBeforeExitToolRule`,
   `RequiresApprovalToolRule` (CONFIRMED). Map: add an optional `toolRules:` block to
   `agent.yaml` evaluated by the gate (e.g. `writer` must call `pmmcp.recall` before any
   write; `publisher` cannot call `post` more than once per step).
9. **Tool guardrails as pre/post hooks per invocation, and handoff input filters.** OpenAI
   Agents SDK tool guardrails "run on every guarded function-tool invocation";
   `handoff_filters.remove_all_tools` (CONFIRMED). Map: the quarantine step is a post-hook;
   the delegate call strips the parent's tool results from the child's context (Hermes
   isolated-context delegation, already a reference point).
10. **Explicit recovery strategies with caps.** CAMEL `RecoveryStrategy {RETRY, REPLAN,
    REASSIGN, DECOMPOSE, CREATE_WORKER}`, `FailureHandlingConfig(max_retries)`,
    `MAX_PENDING_TASKS_LIMIT = 20`, `TASK_TIMEOUT_SECONDS = 600` (CONFIRMED). Map: the CEO loop
    chooses from a closed enum logged as an event; `CREATE_WORKER` = spawn ephemeral from
    template; caps are kernel config, not prompt.
11. **Goal ancestry on every task and heartbeat wake-ups with a watchdog.** Paperclip "Every
    task exists in service of a parent task, all the way up to the company goal"; heartbeats
    with coalescing; watchdog reconciles "at server startup, at the end of each heartbeat
    cycle" and only when a subtree "comes to rest" with "no live continuation path"
    (CONFIRMED). Map: Phase 1 `goalId` on delegated runs; the cron scheduler is a heartbeat;
    the Phase 1 exit test "kernel restart mid-run orphans nothing" is exactly the watchdog tick.
12. **Trust presets that fail closed and forbid promotion of raw untrusted output.** Paperclip
    `low_trust_review`: cannot touch agent config/instructions/skills, requires sandbox driver
    + isolated workspace, rejects inline secrets, "fails closed" (CONFIRMED). Map: the T3
    "hostile" tier and the `comms` tainted-ingress agent are this preset; tainted output must
    pass quarantine before reaching a higher-tier agent (invariant 3).
13. **Trajectory evals with recorded-baseline conformance.** ADK `adk eval` over evalsets,
    `tool_trajectory_avg_score`, `adk conformance` Replay/Live (CONFIRMED). Map: Phase 1 eval
    harness scores the CEO's tool trajectory against the mock hub; replay the event log as the
    baseline.
14. **Every logged tool event carries the gate's verdict and a machine-readable reason code.**
    Managed Agents `evaluated_permission` + `evaluation.reason_code` ("keep in audit records")
    (CONFIRMED); Paperclip call log records "decision, matched policies, reason codes,
    redaction applied" (CONFIRMED). Map: `tool.gate` event fields: `decision`, `matchedRule`,
    `reasonCode`, `redactionApplied`.
15. **Memory: agent-editable core blocks + searchable recall + archival; skills in three
    scopes.** Letta base functions and MemFS git-tracking; skills global/project/agent
    (CONFIRMED). Map: core block = pmmcp context in `aos/agent/<id>`; recall = event-log
    search; archival = pmmcp semantic search; `souls/` stays read-only (invariant 8), the
    editable part is the pmmcp block, not the soul.
16. **Workflows as data for the coding fleet; one git worktree per run.** Archon YAML DAGs of
    deterministic + AI nodes, "Git worktree isolation for concurrent workflow execution"
    (CONFIRMED). Map: each T2 coder run gets its own worktree under the domain `mountRoot`; the
    DAG's AI nodes are gated runs.
17. **Per-resource scheduling queues with a per-call time slice.** AIOS `RRScheduler` queues
    per LLM/memory/storage/tool with `set_time_limit` (CONFIRMED). Map: lanes per provider
    and per MCP server, each with its own concurrency and wallclock.
18. **Local-first routing judged on accuracy × energy × latency × cost.** OpenJarvis
    (CONFIRMED). Map: `aos probe` records latency and tokens/s alongside `toolCalling`, so the
    router can prefer Bonsai/Ollama for lanes where they pass the eval.

## Anti-patterns (leave out)

1. **A model classifier as the access-control decision.** Claude Agent SDK `auto` mode ("A
   model classifier approves or denies permission prompts") and Managed Agents `auto`
   ("`auto` is not a human checkpoint ... the call runs before anyone sees it, and its effects
   might not be reversible") (both CONFIRMED). Violates invariant 3 ("The model never makes an
   access-control decision"). The kernel may use a model to *rank* or *summarise* a pending
   approval for the human, never to decide it.
2. **Opt-in approvals / default-open capabilities.** Suna "Approval gates you switch on";
   Paperclip "Skill permissions are opt-in restrictions, not opt-in capabilities"; MAF
   `approval_mode` default `"never_require"`; Managed Agents agent-toolset default
   `always_allow` (all CONFIRMED). Violates default deny. The one good default in the set is
   Managed Agents' MCP toolset default `always_ask` — keep that one.
3. **In-process "sandboxes" presented as boundaries.** smolagents `LocalPythonExecutor`
   ("best-effort mitigations only and is not a security boundary") and AG2
   `LocalCommandLineCodeExecutor` (CONFIRMED). Agent Zero's "Keep it running inside Docker"
   is advice, not enforcement (CONFIRMED). The kernel's T1 must be documented as a convenience
   tier; anything touching untrusted input is T2+ with invariant 9 flags.
4. **Blocking the orchestrator on a human.** AutoGen `UserProxyAgent` "puts a running team in a
   temporary blocked state until the user responds" — the project itself recommends stopping
   the team and returning control to the application (CONFIRMED). Approvals are events with an
   expiry; the lane moves on.
5. **Agents that hold credentials or can edit their own instructions.** Agent Zero projects
   bundle "secrets" with the agent's workspace (CONFIRMED); Letta Code lets the agent
   "programmatically rewrite their context" including memory blocks that act as system-prompt
   learning (CONFIRMED). Invariant 2 and invariant 8: secrets stay in the broker, `souls/` and
   `AGENTS.md` are read-only; self-editing is confined to the pmmcp core block, and even that
   is a `write` tool that a tainted run cannot use without a human.
6. **Mutable or exporter-dependent audit.** LangGraph checkpoints are editable state (that is
   their purpose); OpenAI Agents SDK tracing defaults to capturing all sensitive data and
   leaves redaction to an exporter ("keep redaction and delivery inside the same
   application-owned exporter") (CONFIRMED); Paperclip's log is append-only by *route* not by
   cryptography (CONFIRMED). Invariant 5: redact before hashing, chain, SQLite triggers.
7. **Budgets that stop after the money is spent, or none at all.** Most frameworks count
   tokens and compute no dollars (OpenAI Agents SDK usage: "actual cost calculation remains
   the application's responsibility", CONFIRMED). Even the good implementations admit
   one-request overshoot (Managed Agents, CONFIRMED). The kernel should pre-reserve the
   estimated cost of the next request (max output × price) so the ceiling is never crossed.
8. **Unbounded self-delegation and worker creation.** Letta Code "Agents can call any other
   agent (including themselves) as subagents"; CAMEL `CREATE_WORKER` is capped only by
   `MAX_PENDING_TASKS_LIMIT` (CONFIRMED). Invariant 6: spawn only from templates, never above
   the parent's tier; add a per-run spawn depth and count cap.
9. **Unknown or restrictive licenses on "reference" code.** AIOS ships an empty LICENSE
   (CONFIRMED); Suna is Elastic License 2.0 (CONFIRMED); Dify adds conditions to Apache-2.0
   (CONFIRMED). Read patterns, do not copy code.
10. **Unbounded approval waits.** Managed Agents "The session waits indefinitely" for a
    `user.tool_confirmation` (CONFIRMED). Give every approval an expiry (Dify does) and make
    expiry a logged deny.

## Invariant conflicts to flag

- Any adoption of Claude Agent SDK `auto` mode, Managed Agents `auto` policy, or a
  "classifier approves prompts" design conflicts with invariant 3.
- Letta-style agent-editable memory blocks conflict with invariant 8 unless confined to the
  pmmcp block (not `souls/`), and with invariant 3's taint rule unless the block write is a
  gated `write` tool.
- Paperclip's default-open skill permissions and Suna's opt-in approval gates conflict with
  default deny; adopt their governance objects, not their defaults.
- Managed Agents' `environment_variable` credentials are placeholders substituted at egress —
  compatible with invariant 2 — but its `mcp_oauth` refresh-on-your-behalf and "substitution
  is outbound only" caveat mean any token-exchange flow must run in the kernel, not the worker.
