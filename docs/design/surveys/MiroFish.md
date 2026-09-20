# MiroFish — reference survey for the aos-kernel fleet design

Paths below are relative to `refs/MiroFish`. Every claim is tagged CONFIRMED (read in the clone) or INFERRED.

## Identity

* **Repo surveyed:** `AiBot-Tools/MiroFish` (fork). **Upstream:** `666ghj/MiroFish` (README badges, star-history, `docker-compose.yml` image `ghcr.io/666ghj/mirofish`). CONFIRMED (`README.md`, `docker-compose.yml`, `git remote -v`).
* **Commit:** `39d849138ef254f6c737ab4c4705e5545dbe31d4`, 2026-09-03. CONFIRMED.
* **License:** AGPL-3.0 (`LICENSE`, `package.json`, `backend/pyproject.toml`). CONFIRMED. Copyleft over the network: anything we lift must be re-implemented from the idea, not copied, or the kernel inherits AGPL.
* **Stack:** Python 3.11–3.12 Flask backend (`backend/app`), `camel-oasis==0.2.5` + `camel-ai==0.2.78` (the simulation engine is CAMEL-AI's OASIS; MiroFish is the wrapper), `zep-cloud==3.25.0` (mandatory SaaS graph memory), `openai` SDK against any OpenAI-compatible endpoint, `PyMuPDF` for seed docs; Vue 3 + Vite + d3 frontend (`frontend/package.json`); Docker image runs `npm run dev` on `python:3.11`. CONFIRMED (`backend/pyproject.toml`, `Dockerfile`).
* **Backing:** incubated by Shanda Group (README). CONFIRMED.
* **Tests:** 110 pytest functions in `backend/tests/*.py`, mostly Zep contract/lifecycle barriers and JSON-robustness of LLM output. CONFIRMED (grep count). Not run here (needs camel/zep deps).

## What it is

A "swarm intelligence prediction engine": you upload seed documents (news, a policy draft, a report, a novel) plus a natural-language "simulation requirement"; it builds a typed knowledge graph, turns every real-world entity in that graph into an LLM persona, runs hundreds of those personas on two simulated social platforms (Twitter-like and Reddit-like) for a simulated 24–168 hours, streams their actions back into the graph as temporal memory, and then a ReAct "ReportAgent" writes a "future prediction report" by querying the graph and interviewing the still-running agents. CONFIRMED (`README.md` Workflow; `backend/app/services/simulation_manager.py:128-478`; `backend/scripts/run_parallel_simulation.py`).

Pipeline (CONFIRMED, `backend/app/api/graph.py`, `simulation.py`, `report.py`):

1. `OntologyGenerator` — LLM designs exactly 10 entity types (8 specific + `Person`/`Organization` fallbacks) and edge types, constrained to "entities that can speak on social media" (`backend/app/services/ontology_generator.py:40-120`).
2. `GraphBuilderService` — chunks text (500/50) and batch-ingests into a Zep Cloud graph with that ontology (`graph_builder.py:75-220, 407-570`).
3. `ZepEntityReader.filter_defined_entities` — keeps only nodes with a label beyond `Entity`/`Node` (`zep_entity_reader.py:221-262`).
4. `OasisProfileGenerator` — one LLM call per entity (parallel N=3), retrieving Zep context, producing a 2000-char persona with stance, "personal memory", MBTI, activity habits; institutional entities get a distinct prompt (`oasis_profile_generator.py:716-818`).
5. `SimulationConfigGenerator` — stepwise LLM generation of time config (hours, minutes/round, peak/off-peak), event config (hot topics, narrative direction, initial posts assigned by `poster_type`), per-agent activity configs; rule-based fallbacks on failure (`simulation_config_generator.py:244-380, 537-730`).
6. `SimulationRunner.start_simulation` — spawns `scripts/run_parallel_simulation.py` as a subprocess (`subprocess.Popen`, `start_new_session=True`, cwd = the simulation dir, `env=os.environ.copy()`), monitors `twitter/actions.jsonl` and `reddit/actions.jsonl` (`simulation_runner.py:371-620`).
7. Optional `ZepGraphMemoryUpdater` — tails the action logs and writes batched "episodes" back into the same graph so later rounds and the report see the evolved world (`zep_graph_memory_updater.py:213-560`).
8. `ReportAgent` — plan outline (2–5 sections) → per-section ReAct loop with 4 read-only tools → assemble Markdown; `chat()` answers follow-ups with the same tools (`report_agent.py:871-1930`).
9. After the loop the simulation process stays alive in a "wait for commands" mode so the UI or ReportAgent can interview agents via file-based IPC (`run_parallel_simulation.py:1560-1610`).

## Orchestration model

* **Not an agent-orchestrated system.** It is a fixed, code-driven pipeline; the LLM fills parameters at each stage. There is no planner agent, no delegation, no CEO. CONFIRMED (`simulation_manager.py:244-478` is a straight-line function with progress callbacks).
* **Process topology:** Flask (threaded) → one long-lived Python subprocess per simulation running two `asyncio` coroutines (`asyncio.gather(run_twitter_simulation, run_reddit_simulation)`) sharing one process. CONFIRMED (`run_parallel_simulation.py:1553-1558`).
* **Round loop:** for each round, compute simulated hour; `get_active_agents_for_round` picks a stochastic subset (peak/off-peak multiplier × per-agent `active_hours` and `activity_level`, then `random.sample` to a target count); `env.step({agent: LLMAction()})`; then **read the actions that actually happened from OASIS's SQLite** (`fetch_new_actions_from_db`) rather than trusting the model's stated intent; log round start/end markers. CONFIRMED (`run_parallel_simulation.py:1040-1091, 1225-1275`).
* **Concurrency caps:** `oasis.make(..., semaphore=30)` limits in-flight LLM calls per platform; optional second "boost" provider so the two platforms hit different API vendors. CONFIRMED (`run_parallel_simulation.py:984-1037, 1159`).
* **Control channel:** file-based IPC. Flask writes `ipc_commands/<uuid>.json`, the sim process polls, writes `ipc_responses/<uuid>.json`; commands are `interview`, `batch_interview`, `close_env`; an `env_status` file says alive/stopped. CONFIRMED (`backend/app/services/simulation_ipc.py:95-290`, `run_parallel_simulation.py:205-600`).
* **Lifecycle discipline (good):** start atomically claims the simulation id under a per-id lock and persists `STARTING` so concurrent starts fail closed; the monitor thread is registered before start; on any start failure the child is terminated and the memory updater stopped; `register_cleanup` kills all children on server exit. CONFIRMED (`simulation_runner.py:418-436, 555-618, 1554`).
* **Barriers (good):** a simulation cannot be reported as finished, and a report cannot be generated, while Zep ingestion is pending or failed; report readers hold a lease that blocks graph start/delete. CONFIRMED by test names and `report.py:98-211` (`tests/test_zep_simulation_barrier.py`, `tests/test_zep_report_barrier.py`).
* **Dynamic injection claim:** README promises "inject variables dynamically from a God's-eye view". In code the only injection points are the round-0 `initial_posts` and post-run interviews; `scheduled_events` is always `[]` and has no consumer in any script. CONFIRMED (`simulation_config_generator.py:121, 725`; grep over `backend/scripts` finds no reader).

## Agent roster / roles found

There is no fixed roster. Simulated agents are generated per entity from the seed graph. The meta-roles are code classes, each a prompt + parser:

| Role | Path | Notes |
|---|---|---|
| Ontology designer | `backend/app/services/ontology_generator.py` | LLM → 10 entity types, must be real speaking actors, not concepts |
| Persona generator | `backend/app/services/oasis_profile_generator.py:540-818` | individual vs institution prompts; rule-based fallback |
| Config generator | `backend/app/services/simulation_config_generator.py` | time / event / per-agent activity; China-timezone defaults |
| Simulated social agents | `backend/scripts/run_parallel_simulation.py:158-204` (OASIS `LLMAction`) | Twitter actions: CREATE_POST, LIKE, REPOST, FOLLOW, QUOTE, DO_NOTHING; Reddit adds comments, dislikes, search, trend, mute |
| Initial-poster assignment | `simulation_config_generator.py:730-815` | initial posts mapped to agents by `poster_type` |
| ReportAgent (planner + section writer + chat) | `backend/app/services/report_agent.py:871-1930` | ReAct, 4 tools, min 3 / max 5 tool calls per section |
| Interview planner | `backend/app/services/zep_tools.py:1270-1690` | LLM picks ≤10 diverse interviewees, generates questions, summarises |
| Memory updater (daemon thread) | `backend/app/services/zep_graph_memory_updater.py` | batches actions into Zep episodes |

Frontend steps mirror the pipeline: `frontend/src/components/Step1GraphBuild.vue` … `Step5Interaction.vue` (chat with any agent = `/api/simulation/interview/batch`; chat with report = `/api/report/chat`). CONFIRMED (`frontend/src/api/simulation.js:175-179`, `report.js:47-51`).

## Memory model

* **Long-term / shared:** a Zep Cloud graph per project, typed by the generated ontology. Nodes carry summaries and labels; edges carry `fact`, `valid_at`, `invalid_at`, `expired_at`; `EdgeInfo.is_expired/is_invalid` and `panorama_search(include_expired=...)` split "current" from "historical" facts so the report can describe evolution. CONFIRMED (`zep_tools.py:87-142, 1143-1235`).
* **Write-back:** every non-`DO_NOTHING` action is rendered to a natural-language episode line with full context (the liked post's text, the quoted post, the followed user), batched 5 at a time under a 9,500-char cap, tagged with `simulation_id`, platform, rounds, agent ids, action types. `graph.add` has no idempotency key, so a failed batch is **not** replayed; it is kept in `_failed_batches` and surfaced to the runner as a failure. CONFIRMED (`zep_graph_memory_updater.py:26-205, 444-550`).
* **Per-agent working memory:** inside OASIS/CAMEL (SQLite `*_simulation.db`, `trace` table); MiroFish only reads it (`_get_interview_result` reads the latest `INTERVIEW` trace row). CONFIRMED (`run_parallel_simulation.py:517-556`).
* **Local-first?** No. `ZEP_API_URL` is explicitly rejected: "MiroFish only connects to Zep Cloud". All seed documents and every simulated utterance leave the machine. CONFIRMED (`backend/app/config.py:60-64`).

## Tool / plugin / MCP model

* No MCP, no plugin system. ReportAgent has a home-grown text protocol: the model emits `<tool_call>{"name":..,"parameters":..}</tool_call>`; a regex extracts it, with a bare-JSON fallback validated against `VALID_TOOL_NAMES`. CONFIRMED (`report_agent.py:1073-1131`).
* Four tools, all read-only over the graph or the interview channel: `insight_forge` (LLM decomposes the question into ≤5 sub-queries, searches edges for each, expands touched entities, builds relation chains), `panorama_search` (all nodes/edges, temporal split), `quick_search`, `interview_agents`. Legacy names (`search_graph`, `get_entity_summary`, ...) are still executed if wrapped in `<tool_call>` because format-1 parsing does not check the allowlist. CONFIRMED (`report_agent.py:925-1070`; `zep_tools.py:943-1235`).
* **Anti-fabrication guards (good):** `_strip_fake_tool_results` removes model-fabricated `<tool_result>` blocks (nested, unclosed, malformed) before they enter history, with a parametrised test; a `Final Answer` before 3 tool calls is rejected and the model is told which tools it has not used; a response containing both a tool call and a Final Answer is bounced twice then truncated to the first tool call; the section prompt forbids own-knowledge and invented usernames/statistics. CONFIRMED (`report_agent.py:1144-1176, 1330-1420, 615-700`; `backend/tests/test_report_tool_result_sanitizer.py`).
* **Observability:** `ReportLogger` writes a JSONL trace per report (planning context, each thought, tool call, tool result, LLM response, section content); `ReportConsoleLogger` mirrors console output; both are streamable from the API. CONFIRMED (`report_agent.py:36-390`, `report.py:877-1052`).
* Caps: `REPORT_AGENT_MAX_TOOL_CALLS=5`, `MAX_REFLECTION_ROUNDS=2`, chat ≤2 tool calls, tool results in chat truncated to 1,500 chars. CONFIRMED (`config.py:50-52`, `report_agent.py:881-887, 1880-1895`).

## Sandbox and security posture

* **Network:** Flask binds `0.0.0.0:5001` by default, `CORS(origins="*")` on `/api/*`, no authentication anywhere, default `SECRET_KEY='mirofish-secret-key'`, request bodies logged at DEBUG. CONFIRMED (`backend/run.py:43`, `backend/app/__init__.py:44-57`, `backend/app/config.py:21`).
* **Credentials:** LLM and Zep keys come from `.env` into process env; the simulation subprocess receives `os.environ.copy()` and then **sets `OPENAI_API_KEY`/`OPENAI_API_BASE_URL` itself** for CAMEL. The simulated agents therefore run in a process that holds the provider key. CONFIRMED (`simulation_runner.py:531-548`; `run_parallel_simulation.py:1020-1030`).
* **Isolation:** none. Sim process is a plain child with the server's privileges, cwd under `backend/uploads/simulations/<id>`; Docker image runs both dev servers as root with `npm run dev`. CONFIRMED (`Dockerfile`, `simulation_runner.py:539-549`).
* **Human-in-the-loop:** none. No approval step anywhere in the pipeline; the frontend "steps" are UI staging, not gates. CONFIRMED (no approval code in `backend/app/api/*`).
* **Budgets:** no token or cost accounting at all (grep for `usage`, `total_tokens`, `cost`, `budget` finds only prompt-size budgeting in `ontology_generator.py`). Only `max_rounds` truncation and `semaphore=30`. README itself warns "High consumption, try simulations with fewer than 40 rounds first". CONFIRMED.
* **Evaluation:** none. No ground truth, calibration, backtest, or scoring; the report prompts assert "the simulation's evolution *is* the prediction of the future". CONFIRMED (`report_agent.py:560-600`; grep for brier/calibration/backtest finds nothing).
* **Input handling that is fine:** script download is allowlisted; simulation ids are server-generated `sim_<hex12>`; `force` must be a JSON boolean. CONFIRMED (`simulation.py:1373-1425`, `simulation_manager.py:227-228`, `graph.py:520-527`).
* **Data residency:** all content to Zep Cloud and to whichever OpenAI-compatible vendor is configured (default recommendation: Alibaba DashScope). CONFIRMED (`.env.example`).

## BEST PARTS

1. **Graph-to-persona pipeline (ontology → typed entities → grounded personas with stance and memory).**
   Evidence: `backend/app/services/ontology_generator.py:40-120`; `backend/app/services/oasis_profile_generator.py:274-340, 716-818`; `backend/app/services/zep_entity_reader.py:221-262`. CONFIRMED.
   Sector: **growth** (marketing/social pre-testing: build an audience from real customer research, competitor threads, a subreddit dump) and **trading** (build a "market participant" cast from filings, analyst notes, CT/Reddit sentiment).
   Why: it is the one reusable mechanism here. Personas are derived from evidence, typed, and forced to be actors that can speak, which is what makes the later reactions interpretable. We would implement it as a kernel-hosted `simulate.cast` tool that reads pmmcp/Qdrant instead of Zep.

2. **Time-structured stochastic activation.**
   Evidence: `backend/scripts/run_parallel_simulation.py:1040-1091`; `backend/app/services/simulation_config_generator.py:29-50, 537-640`. CONFIRMED.
   Sector: **growth**, **trading**.
   Why: reaction curves depend on who is awake and how loud they are; per-agent `active_hours`/`activity_level` plus population-level peak multipliers give a cheap, explainable diffusion model and a natural knob for cost (fewer active agents per round). Trivial to port; keep the LLM-generated config but validate it with zod.

3. **Two parallel worlds with different interaction physics (broadcast vs threaded), separate logs, optional separate providers.**
   Evidence: `backend/scripts/run_parallel_simulation.py:158-204, 984-1037, 1553-1558`. CONFIRMED.
   Sector: **growth** (same message on X-like vs Reddit-like dynamics), **trading** (news shock under "fast broadcast" vs "slow deliberation").
   Why: a built-in A/B over channel dynamics for one seed; a template for our ephemeral `scout`/`worker` pattern where one run spawns N bounded sub-simulations under one budget.

4. **Temporal memory with expiry, and fail-closed write-back.**
   Evidence: `backend/app/services/zep_tools.py:87-142, 1143-1235`; `backend/app/services/zep_graph_memory_updater.py:444-550`. CONFIRMED.
   Sector: **kernel** (memory model), **trading** (regime change: which "facts" are still valid).
   Why: facts carry `valid_at/invalid_at`, the report tool separates current from historical, and the updater refuses to replay a non-idempotent write on ambiguous failure, keeping the failed batch for a human. That is the correct posture for a shared memory that agents write into; pmmcp goal/episode writes from runs should follow the same rule.

5. **Report ReAct discipline: allowlisted tools, fabricated-result stripping, minimum-evidence gate, conflict handling, full JSONL trace.**
   Evidence: `backend/app/services/report_agent.py:36-300, 615-700, 1073-1176, 1260-1420`; `backend/tests/test_report_tool_result_sanitizer.py`. CONFIRMED.
   Sector: **engineering** (auditor, researcher, writer agents), **trading** (research memos must cite retrieved evidence).
   Why: these are cheap, tested guards against a model narrating tool results it never received and against "Final Answer" without retrieval. In our kernel the equivalents are: native tool calling only, `llm.response` content scanned for `tool_result`-like blocks, and a per-manifest `minEvidenceCalls` for research roles.

6. **Interview primitive: ask specific simulated agents a question after the run, via a narrow control channel, reading the answer from the engine's own trace rather than a fresh LLM guess.**
   Evidence: `backend/scripts/run_parallel_simulation.py:317-345, 517-556`; `backend/app/services/zep_tools.py:1270-1330, 1549-1690`; `backend/app/services/simulation_ipc.py:95-190`. CONFIRMED.
   Sector: **growth** (focus-group on a draft post), **trading** (ask the "retail" cluster why they sold).
   Why: it turns a simulation into a queryable artifact. The LLM chooses *whom* to interview for diversity, which is fine because it is not an access-control decision; the kernel still gates the tool.

7. **Log what actually happened, append-only, with round markers; read actions back from the engine DB.**
   Evidence: `backend/scripts/action_logger.py:1-120`; `backend/scripts/run_parallel_simulation.py:657-750, 1253-1275`. CONFIRMED.
   Sector: **kernel**, **ops-security**.
   Why: matches our event-log philosophy (the record is the DB row, not the model's claim). Ours must additionally hash-chain it and never expose a `cleanup_simulation_logs` path.

8. **Fail-closed start claim and ingestion barriers.**
   Evidence: `backend/app/services/simulation_runner.py:418-436, 555-618`; `backend/app/api/report.py:98-211`; `backend/tests/test_zep_simulation_barrier.py`, `test_zep_report_barrier.py`. CONFIRMED.
   Sector: **kernel** (Phase 1 restart-safe projections).
   Why: persisted `STARTING` state, lock-ordered publication of process/monitor, "no terminal success until memory writes are confirmed", reader leases blocking destructive ops. Directly applicable to `run.finished` semantics when a run's pmmcp writes are still pending.

## BAD PARTS / anti-patterns

1. **Wide-open control surface.** `0.0.0.0`, CORS `*`, no auth, default secret, request bodies in logs. Evidence: `backend/run.py:43`, `backend/app/__init__.py:44-57`, `backend/app/config.py:21`. Leave out: violates invariant 1 outright; nothing to salvage.

2. **Provider key handed to the worker process.** The simulation child inherits the full environment and writes `OPENAI_API_KEY` into `os.environ` for CAMEL. Evidence: `backend/app/services/simulation_runner.py:531-548`; `backend/scripts/run_parallel_simulation.py:1020-1030`. Leave out: violates invariant 2; in our design the OASIS worker calls the kernel router or the egress proxy, never a vendor.

3. **Mandatory cloud memory; local-first impossible.** `ZEP_API_URL` is rejected by design; every seed document and simulated utterance goes to Zep Cloud. Evidence: `backend/app/config.py:60-64`, `.env.example`. Leave out: replace with pmmcp (`aos/shared` project) + Qdrant; keep only the temporal-fact and fail-closed-write ideas.

4. **No cost accounting, unbounded spend.** Hundreds of agents × up to 168 h / 30 min rounds × two platforms, capped only by `max_rounds` and a concurrency semaphore; the README warns about cost instead of enforcing it. Evidence: grep (no `usage`/`cost`/`budget` tracking); `README.md` Quick Start note; `run_parallel_simulation.py:1159`. Leave out: violates invariant 4; every simulated agent turn must be an `llm.request/llm.response` pair charged to the run budget, and the scheduler must degrade active-agent counts when the budget nears its cap.

5. **"Prediction" with zero evaluation, framed as fact.** Prompts tell the writer that "the simulation's evolution is the prediction of the future" and to treat agent speech as future crowd behaviour; there is no ground truth, calibration, or backtest. Evidence: `backend/app/services/report_agent.py:560-600, 615-660`; no eval code anywhere. Leave out for trading: outputs must be labelled scenario analysis, run under a documented seed/config, and scored against outcomes by the eval harness before any trading agent may cite them. The model never gets to decide a trade on their basis.

6. **Home-grown regex tool protocol with a leaky allowlist.** Tool calls are parsed from free text; format-1 parsing skips `VALID_TOOL_NAMES`, so legacy tool names remain callable; "conflict" handling is prompt-level. Evidence: `backend/app/services/report_agent.py:1073-1131, 1040-1070`. Leave out: use native tool calling through the router and enforce the tool-view policy in the gate, not the parser.

7. **README overclaims dynamic intervention.** `scheduled_events` is always empty and unread; only round-0 posts and post-hoc interviews exist. Evidence: `backend/app/services/simulation_config_generator.py:121, 725` and absence of consumers in `backend/scripts`. Leave out the claim; if we want mid-run injection it must be a gated `ManualAction` command over the control channel, logged like any other tool call.

8. **Unsandboxed long-lived worker, dev-mode container, deletable logs.** Plain subprocess with server privileges; Docker `CMD npm run dev` as root; `cleanup_simulation_logs`, `delete_report`, `delete_graph` remove history. Evidence: `Dockerfile`; `backend/app/services/simulation_runner.py:1365-1450`; `backend/app/api/report.py:563`; `backend/app/api/graph.py:907`. Leave out: violates invariants 5, 6 (archive never deletes) and 9.

## Conflicts with CLAUDE.md invariants

1. **Inv. 1 (loopback + bearer):** binds all interfaces, no token, CORS wildcard (`run.py:43`, `app/__init__.py:44`).
2. **Inv. 2 (agents never hold keys):** worker process holds `LLM_API_KEY` and sets `OPENAI_API_KEY` (`simulation_runner.py:544`, `run_parallel_simulation.py:1025`).
3. **Inv. 3 (gate → approval → execute → log, default deny):** no policy gate; ReportAgent executes any parsed tool immediately; interviews and full simulations start from an unauthenticated POST.
4. **Inv. 4 (two events per LLM call with cost):** OASIS/CAMEL calls are invisible to MiroFish; ReportLogger records responses but no tokens or cost.
5. **Inv. 5 (redacted, hashed, chained, immutable log):** JSONL is append-only but unhashed and deletable via cleanup endpoints; Zep episodes are mutable/deletable (`delete_graph`).
6. **Inv. 6 (archive never deletes):** `delete_report`, `delete_graph`, `cleanup_simulation_logs` destroy records.
7. **Inv. 7 (unknown tools kernel-only):** legacy tool names reachable through the parser without allowlisting.
8. **Inv. 9 (container hardening):** no containerisation; root dev container; child process with server privileges and full env.
9. **Local-first premise:** Zep Cloud mandatory; all seed content exfiltrated by design.
10. **"The model never makes an access-control decision":** not violated in spirit (the LLM only picks interviewees and config values), but nothing else makes one either, because there is no gate.

## Verdict

Take the mechanism, not the software: a kernel-hosted `simulate` capability (T3 "hostile" Docker worker running an OASIS-class engine with no egress, all LLM calls proxied through the router and metered per round) that builds a typed cast from pmmcp/Qdrant evidence, activates agents on a time-of-day schedule, runs two channel-physics worlds in parallel, writes temporal facts back fail-closed, exposes an `interview` tool, and feeds a researcher/writer agent whose report loop enforces minimum evidence and strips fabricated tool results. Leave the Flask surface, the env-passed keys, Zep Cloud, the regex tool protocol, the deletable logs, and above all the "this is the future" framing: for the trading sector every output is a labelled scenario with a seed, a config hash, and a later outcome score, and it can inform a human or a research memo but never a trade. AGPL means we re-implement from these notes; nothing is copied.
