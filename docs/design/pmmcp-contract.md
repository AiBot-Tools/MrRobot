# pmmcp ↔ kernel contract: sector compartments

Status: **draft, proposed** (2026-10-17). Not implemented on either side.
Decisions D1–D7 (§7) are written on their recommended defaults; each is the
operator's to change.

## 0. What this is for

The operator's rule: every sector of the agent OS keeps its pmmcp data apart
from every other sector, and **coding data is readable only by agents that do
coding**.

Two halves, and neither one isolates anything alone:

- **pmmcp changes (P1–P8, §3)**, for the pmmcp project (Python, outside this
  repository). pmmcp must enforce the compartments itself. Today it
  authenticates nobody, so any process on the Mac can read any `project_id`.
  And several tools ignore `project_id` or treat its absence as "everything".
- **Kernel changes (K1–K10, §4)**, for this repository. The kernel must put
  every agent in exactly one sector, address only that sector's namespaces,
  and hold one pmmcp credential per sector, so that a kernel bug cannot cross
  a compartment pmmcp enforces.

Out of scope, and **not isolated by this contract**: data that lives outside
pmmcp (§8).

## 1. Facts this rests on

C = read in a primary source; I = inference.

**MCP specification**

- The latest revision is **2026-07-28** (C: spec repo `docs/docs.json:33`,
  changelog). It removes protocol sessions, `initialize` and `ping`.
- The kernel's TypeScript SDK 1.30.0 speaks **2025-11-25** at most (C:
  `node_modules/@modelcontextprotocol/sdk/dist/esm/types.js:2-4`).
- Python `mcp` 2.x serves both eras; `mcp` 1.30.0 serves 2025-11-25 (C).
- So this contract targets 2025-11-25 Streamable HTTP, and **no isolation may
  depend on sessions** (I). 2026-07-28 drops them, and the spec already says
  servers "MUST NOT use sessions for authentication" (C: 2025-11-25 security
  best practices).

**Authorization**

- Authorization is OPTIONAL in MCP (C: `basic/authorization`). A static bearer
  per client is therefore a permitted deviation from the OAuth flow, not a
  violation (I).
- The spec's local-server guidance says to require a token, because "binding
  to 127.0.0.1 is not an authentication boundary" (C: local-server-security,
  security best practices).
- Invalid or missing tokens MUST get HTTP 401 (C).
- The Python SDK's bearer middleware answers 401 `invalid_token` without
  echoing the token (C: `auth/middleware/bearer_auth.py`).
- **The Python SDK binds a session to the `(client_id, iss, subject)` of the
  token that opened it** (C: `streamable_http_manager.py`). So each sector's
  token must map to a distinct `client_id`, or a session opened with one
  sector's token would accept another's (I).
- On 2026-07-28, `tools/list` "MAY vary by the authorization presented on the
  request" (C: `server/tools.mdx:61-68`). Per-sector tool sets are within the
  spec.

**Tool results**

- A tool's own failure SHOULD be a result with `isError: true` (C).
- Python v1 `raise ToolError(...)` produces that (C).
- A returned string is `isError: false`. That is what pmmcp does today for
  every refusal (C: Python SDK `handling-errors.md`; kernel
  `test/helpers/mock-pmmcp.ts` `said`).
- **Structured output**: `outputSchema` plus `structuredContent`, with the
  JSON also returned as a text block for compatibility (C).
- TS SDK 1.30.0 requires an **object-rooted** `outputSchema`.
- It **throws** when a tool declares one and returns no `structuredContent`
  without `isError`.
- It validates only the last page of a paginated `tools/list` (C:
  `client/index.js:479-557`).
- Tool annotations (`readOnlyHint`, …) are hints the client "MUST consider
  untrusted" (C). `config/tool-views.yaml` stays the authority.

**pmmcp today (from this repository)**

- `recall`/`remember` take an optional `project_id`, and leaving it out means
  global scope (pmmcp `src/tools/primary.py`, per `config/tool-views.yaml`).
- `update_goal`, `get_goal_tree` and `complete_goal` take only `goal_id` (C:
  `mock-pmmcp.ts:218-268`, read from pmmcp's source).
- `forget` is global when `project_id` is absent.
- `scrape_context` takes no `project_id`.
- Refusals arrive as success text. The kernel parses prose:
  `✅ Goal created: <id>` and `✅ Goal updated: <id>`
  (`src/goals/writer.ts:119, 335`).
- pmmcp publishes RFC 9728 metadata that lists no authorization server, which
  the spec's "at least one" MUST forbids (`README.md`, `kernel.yaml`).
- `docs/DECISIONS.md:136` says pmmcp needs a bearer. The operator-confirmed
  fact (CLAUDE.md) is that it authenticates nobody. That wins until P1 ships.

**The kernel today**

- One memory namespace per agent, from a fixed shape:
  `aos/ceo | aos/shared | aos/agent/<id>` (`src/agents/manifest.ts:28`).
- No sector concept anywhere in `src/`.
- No pmmcp tool is exposed to any agent (`config/tool-views.yaml`).
- The gate **checks** the `project_id` the model sends and never **sets** it
  (`src/policy/gate.ts:127-144`), although the docs say it sets it.
- One pmmcp client, one session and at most one bearer (`src/mcp/hub.ts`).

## 2. The compartment model

### 2.1 Sectors (D1)

| Sector | Holds | Agents (from docs/design; the media/marketing split is D1) |
|---|---|---|
| `executive` | goal tree, adopted plans, mandates, CEO memory | ceo, planner, judge¹, curator¹, assistant |
| `engineering` | **all coding data**: code knowledge, ADRs, module maps, design system, incident notes, indexed repos and git history | eng-lead, prototyper, sre, architect, implementer, tester, reviewer, release, scout¹ |
| `media` | clipping and production: captions, renders, clip plans, media checks | producer, checker{media}, publisher² |
| `marketing` | marketing, social, community, sales: brand kit, ICP, drafts, CRM-adjacent notes | marketer, writer, community, sales, checker{brand,policy,facts}, reporter, focus-group, scout¹ |
| `trading` | theses, signals, strategy cards, backtests, journals | quant, executor, bookkeeper, market-scout, critic¹ |
| `security` | warden reports, review and pentest findings | warden, security-reviewer, evaluator, pentester, comms-triage |

¹ A template that serves several sectors (scout, judge/critic, curator) gets a
sector **bound at spawn or delegation** (§2.4). It has none of its own.

² The publisher posts both clips and marketing copy. D1 puts it in `media`;
marketing hands it copy through a handoff (§2.6).

### 2.2 Namespaces

The grammar replaces `MEMORY_PROJECT`:

```
aos/<sector>/agent/<id>     an agent's own memory (episodic)
aos/<sector>/shared         the sector's curated knowledge (human-promoted)
aos/<sector>/inbox          handoffs the operator approved into this sector (§2.6)
aos/executive/goals         the goal tree (§2.5)
aos/fleet/shared            operator-level knowledge every sector may read (D3)
```

- `<sector>` is one of the six names above. `<id>` is `[a-z0-9-]+`.
- Nothing outside `aos/` is ever an agent's namespace. In particular, whatever
  `project_id`s the operator's own tools (Claude Code, pmmcp's CLI) already
  use stay unreachable from every agent.
- The old names (`aos/ceo`, `aos/shared`, `aos/agent/<id>`) are retired, not
  aliased (§6, K10).

### 2.3 Who may read and write what

| Namespace | Read | Write |
|---|---|---|
| `aos/<s>/agent/<id>` | that agent; that sector's curator instance | that agent (gated `remember`); the kernel on `run.finished` |
| `aos/<s>/shared` | every agent of sector `s` | **only** a human `memory-promote` (proposed by that sector's curator) |
| `aos/<s>/inbox` | every agent of sector `s` | **only** the kernel, executing an operator-approved handoff (§2.6) |
| `aos/executive/goals` | the kernel; ceo, planner | the kernel only (from CEO plans; status from the run lifecycle) |
| `aos/fleet/shared` | every agent | **only** a human `memory-promote` |

- **Cross-sector reads exist only as explicit grants in config**, each one
  read-only and each one the operator's decision. The one default grant is D5:
  `security` → `engineering`, for code review and pentest only.
- **Coding data never leaves `engineering`** except through a grant or a
  handoff the operator approves.

### 2.4 Templates, ephemeral children and delegation

- A template manifest declares no sector.
- When the kernel spawns or delegates to one, it binds the sector of the
  objective's task (D1 table). The child's namespace becomes
  `aos/<that sector>/agent/<template>-<runId>`. This replaces today's
  inheritance of the template's `aos/shared` (`registry.ts:246-255`).
- A child's sector can only narrow, never widen, its parent's grants.
- **The CEO delegates across sectors but reads none of them** (D2). What comes
  back is the kernel's typed `RunResult`: status, cost, taint, evidence refs,
  and a summary capped at 2,000 characters. Raw memory never comes back.
  Whether a coding summary may name files is D6.
- Taint passes from parent to child. Today it does not
  (`kernel.ts:612-613`); K5 fixes that.

### 2.5 Goals

- The goal tree lives in `aos/executive/goals`. It is written only by the
  kernel, with the executive token, as it is today in `aos/ceo`.
- Goal titles are CEO-authored planning text, never sector data: a task title
  says what to do, not what the sector knows.
- Sector agents never touch goals. The kernel moves task status from the run
  lifecycle, as it does today.
- P4 makes pmmcp enforce the namespace on every goal call. The tree can then
  no longer be moved or read by id alone.

### 2.6 Handoffs (D4)

A handoff is the one way data moves between sectors, for example engineering
release notes to marketing. It works like this:

1. An agent in sector A proposes it, as a typed artifact. The proposal holds
   the text, ≤ 8 KiB, bound by hash, plus the target sector B.
2. The operator approves it through the control plane, as a `HumanActor`.
3. The kernel writes it into `aos/B/inbox`, with provenance
   `{origin: operator, fromSector: A, approvedBy, artifactHash}`.
4. Nothing else crosses: no raw recall and no shared namespace.

This reuses the quarantine-release machinery (`EX:196-216` in the executive
design); it is not a second declassification path.

## 3. pmmcp changes

Each item has: the change, why, an acceptance test, and the kernel impact.
They are numbered in the order they should ship (§6).

### P1. One bearer token per sector principal

**Change**

- pmmcp reads a principals file, outside any repository, mode 0600:

  ```yaml
  principals:
    - id: aos-executive        # becomes the token's client_id
      token_sha256: "<hex>"    # sha256 of the token; the token itself is never stored
      prefixes: ["aos/executive/", "aos/fleet/shared"]
      profile: kernel-goals    # §P3
    - id: aos-engineering
      token_sha256: "<hex>"
      prefixes: ["aos/engineering/", "aos/fleet/shared"]
      profile: sector-memory
    # ... one per sector ...
    - id: operator             # the operator's own tools; never given to the kernel
      token_sha256: "<hex>"
      prefixes: ["*"]
      profile: all
  ```

- A `TokenVerifier` hashes the presented token and compares it in constant
  time (`hmac.compare_digest`) against each entry. It returns an `AccessToken`
  whose `client_id` is the principal id, distinct per sector, because the SDK
  binds sessions to it.
- No match, or no token: HTTP 401 `invalid_token`. The body never echoes the
  token, and the server never logs it.
- Remove the RFC 9728 metadata document that lists no authorization server, or
  stop publishing it.
- Keep binding to 127.0.0.1 and keep the SDK's DNS-rebinding protection on.

**Why.** Without a credential, every compartment below is advisory: any local
process, any future container that escapes the Phase 2 proxy, or any kernel
bug can read anything.

**Acceptance**

- No token → 401.
- A wrong token → 401, with the token absent from the body and the logs.
- Each sector token opens a session.
- A session opened with the engineering token, then used with the marketing
  token, gets 404 "Session not found" (the SDK's principal binding).

**Kernel impact.** K3 (one client per sector). The token names enter `.env`
through `credentialNames`.

### P2. Server-side namespace enforcement

**Change**

- Every tool that reads or writes memory, goals or indexes resolves the
  `project_id` it will touch and refuses unless that id matches one of the
  principal's `prefixes`:
  - a prefix ending in `/` matches the namespace and everything under it;
  - any other prefix must match exactly.
- For any principal other than `operator`, **a missing `project_id` is a
  refusal, never global scope.** That covers `recall`, `remember`, `forget`,
  `list_secrets`, `get_audit_logs` and every index tool.
- **Search filters inside the vector query**, as a Qdrant payload filter on
  `project_id`, never by filtering hits afterwards. A query must not be able to
  rank, count or time results from another compartment.

**Why.** The kernel can be wrong; pmmcp is the last wall.

**Acceptance**

- With the marketing token:
  - `recall(project_id: "aos/engineering/shared", …)` is refused;
  - `recall(query: "…")` with no `project_id` is refused;
  - `recall(project_id: "aos/marketing/shared", query: <a phrase only stored
    in engineering>)` returns zero hits.
- The engineering token can recall its own memory.
- A seeded engineering memory never appears in any other principal's results,
  under any query, in a sweep test.

### P3. A tool profile per principal

**Change.** `tools/list` returns only the tools the principal may call; calling
any other tool is refused. Profiles:

| Profile | Tools |
|---|---|
| `kernel-goals` (executive) | `create_goal`, `update_goal`, `get_goal_tree`, `list_goals`, `recall`, `remember` |
| `sector-memory` (every other sector) | `recall`, `remember`, `search` (if it exists) |
| `engineering` adds | `index_project`, `index_git_history` (writing only under `aos/engineering/`) |
| `all` (operator only) | everything |

Every profile except `all` excludes:

- the secret and vault tools;
- `admin`, `restore_backup`, `delete_context_source` and `repair_and_heal`;
- `scrape_context`, which is pmmcp fetching the web around the Phase 2 proxy;
- `forget` (deletion is the operator's);
- `coding_agent` and `session_insight_agent` (nested LLM calls).

**Why**

- It removes whole classes of tools from what a kernel bug can reach. The
  kernel's `tool-views.yaml` stays the authority on what agents see; P3 is the
  server's floor under it.
- It shrinks the capture, the double and the drift surface per sector.

**Acceptance**

- `tools/list` per token matches its profile exactly.
- Calling an unlisted tool is refused.
- The operator token lists all tools (49–53 today).

### P4. Goal tools take and enforce `project_id`

**Change**

- `update_goal`, `get_goal_tree` and `complete_goal` gain a **required**
  `project_id`. Each is refused unless the goal is stored in that project and
  the project passes P2.
- `create_goal` refuses a `parent_goal_id` stored outside the given project.

**Why.** Today any caller holding a goal id can read or move any project's
goal; the kernel guards this only with its own `goal.created` log.

**Acceptance.** `update_goal(goal_id: <an aos/executive/goals goal>,
project_id: "aos/marketing/…")` is refused, and so is the same call under the
marketing token.

**Kernel impact.** K6. `GoalArgs`, the writer, the double and its tests gain
the argument. The kernel's owner check stays, as defence in depth.

### P5. Real errors

**Change**

- Every refusal is `raise ToolError(f"{code}: {message}")`, which gives
  `isError: true` and one text block. Codes are stable snake_case:
  - `goal_not_found`, `invalid_transition`, `invalid_status`,
    `parent_not_found`, `invalid_goal_type`, `progress_out_of_range`;
  - `namespace_denied`, `project_id_required`, `tool_not_in_profile`.
- The message never quotes a secret, and never quotes another compartment's
  data.
- Do not return `CallToolResult(isError=True)` from a tool that declares an
  output schema on `mcp` v1. v1 validates `structuredContent` even on errors,
  and the validator's text replaces the message (C: `func_metadata.py:133-136`).

**Why.** Today a refusal is a success; the kernel must parse prose to notice,
and a one-word reply like `Unauthorized` would be read as a goal id
(`writer.ts:134`).

**Acceptance.** Every refusal string in `mock-pmmcp.ts` (`said`) has a P5 code
and arrives with `isError: true`.

### P6. Structured output for the goal and memory tools

**Change**

- `create_goal`, `update_goal`, `get_goal_tree`, `list_goals`, `recall` and
  `remember` return typed Pydantic models, so the SDK publishes an
  `outputSchema` and `structuredContent`:
  - `create_goal` and `update_goal` → `{goal_id, project_id, status,
    progress_pct}`;
  - `get_goal_tree` → `{goal_id, children: [...]}` with ids;
  - `recall` → `{hits: [{id, project_id, content, provenance}]}`.
- Every root is an **object**, which TS 1.30 requires (wrap lists).
- The serialized JSON is also returned as a text block.
- `tools/list` is one page.

**Why.** It replaces the kernel's prose parsing with validated data.

**Acceptance.**

- Each listed `outputSchema` has `type: object`.
- The TS 1.30 client validates every one of these results without throwing.

**Kernel impact.** K8.

- The hub reads `structuredContent`, which it drops today.
- The writer reads `goal_id` from it rather than matching `✅ Goal created:`.

### P7. Provenance on every memory write

**Change.** `remember` stores
`provenance {runId, agentId, sector, taint, origin: operator|agent|untrusted|system, observedAt}`.

- Only the kernel supplies it; pmmcp refuses a `remember` without it from a
  sector principal.
- `recall` accepts `exclude_origin: ["untrusted"]` and returns provenance with
  each hit.

**Why.** The designs' rule that a clean run never recalls untrusted text
(agent-fleet.md:486-491) needs a field pmmcp can filter on. Today this is
NEEDS VALIDATION (DECISIONS Q24).

**Acceptance.** A memory written with `origin: untrusted` never appears in a
recall that excludes it, under any query.

### P8. Protocol era

- pmmcp keeps serving 2025-11-25 Streamable HTTP while the kernel is on TS SDK
  1.30.
- Moving the kernel to a 2026-07-28 client is a new dependency
  (`@modelcontextprotocol/client`) and needs the operator's approval.
- Nothing in P1–P7 relies on sessions. On 2026-07-28 the same token checks run
  on every request.

## 4. Kernel changes

Each item has its acceptance test. These follow the session protocol: one
task, one test, one commit.

| # | Change | Acceptance test |
|---|---|---|
| K1 | Manifest gains `sector` (one of the six; absent on templates). `MEMORY_PROJECT` becomes the §2.2 grammar. The registry refuses a namespace outside the agent's sector, a duplicate namespace, and a template with a sector. | `agents-registry.test.ts`: a marketing agent declaring `aos/engineering/agent/x` fails to load. |
| K2 | **The kernel sets `project_id`.** `project_id` is stripped from the schema the model sees. The kernel fills it from the agent's sector and namespace before the gate hashes the arguments: reads may use the agent's read set, writes only its own namespace. `namespaceArg: none` is refused for any tool whose live schema declares `project_id`. | `policy-namespace.test.ts`: a model call carrying `project_id: aos/engineering/...` from a marketing agent is denied; a call with none is filled with the agent's own namespace. |
| K3 | **One pmmcp client per sector**, each with that sector's token (`mcp.servers.pmmcp.sectors.<s>.tokenEnv`). Every call is routed by the calling run's sector; kernel-only goal calls use the executive client. A 401 degrades that sector by name and never retries the same token. Fix the stuck-degraded hub, and retry when pmmcp is down at boot. | `mcp-hub.test.ts`: a marketing run's call reaches the double under the marketing principal; the double refuses it an engineering namespace. |
| K4 | `tool-views.yaml` gains `sectors: [...]` per tool, and `tools.servers` is enforced. Engineering-only tools (code packs; later GitHub, Vercel, Supabase) never reach another sector's agent. **Changing any exposure is ask-before.** | `config-files.test.ts`: an engineering-only tool in a marketing agent's `allow` fails to load. |
| K5 | Delegation binds the child's sector, inherits taint, and returns a typed `RunResult` (summary ≤ 2,000 chars) instead of the child's `finalText`. | `delegation.test.ts`: a tainted parent's child starts tainted; the CEO sees the summary, not the full text. |
| K6 | The goal writer uses the executive client, adds `project_id` to update and tree calls (after P4), and keeps the owner check. | `goals-writer.test.ts` against the P4 double. |
| K7 | `run.queued`, `run.started`, `tool.gate` and `agent.registered` events carry `sector`. The control protocol stays v1; a sector filter in the UI is a v2 change and ask-before. | `events-types.test.ts`. |
| K8 | The double (`mock-pmmcp.ts`) models principals, profiles, prefix enforcement, `isError` codes and structured output. The drift test also compares `required` lists, `project_id` optionality and `outputSchema`. The hub reads `structuredContent`. | `mcp-pmmcp-double.test.ts`, `pmmcp-drift.test.ts`. |
| K9 | The handoff (§2.6): a proposal tool for sector agents, an operator approval card, and the kernel write into `aos/<B>/inbox`. | `handoff.test.ts`: without approval nothing is written; with it, exactly the hashed bytes land in B's inbox with provenance. |
| K10 | Migration: retire `aos/ceo`, `aos/shared` and `aos/agent/<id>` **before the Phase 0 exit run writes real data**. If pmmcp already holds anything under `aos/`, the operator moves or deletes it with the operator token. | Boot refuses a manifest using an old namespace; README gives the one-time check `list_goals`/`recall` under `aos/`. |

## 5. End-to-end acceptance: the leak matrix

The release test for this contract. It runs against the double offline, and
against live pmmcp under `AOS_LIVE_TESTS=1`.

1. Seed one distinctive memory into each sector's agent namespace and shared
   namespace.
2. For every (caller sector, target sector) pair with no grant:
   - recall, search and list of the target are refused;
   - a recall within the caller's own namespaces with the target's
     distinctive phrase returns nothing.
3. A call with no `project_id` is refused for every sector principal.
4. `security` can read `engineering` (the D5 grant) and cannot write it.
5. The CEO's tools reach only `aos/executive/*` and `aos/fleet/shared`.
6. A goal created under the executive token cannot be moved or read with any
   sector token.
7. A handoff without approval moves nothing.
8. The operator token sees everything; it is never in the kernel's `.env`.

## 6. Order of work

1. **Operator:** commit the current pmmcp capture (`npm run capture:pmmcp`).
   It is the "before" picture for the drift test.
2. pmmcp **P5 + P6** (errors, structured output), with kernel **K8**. No
   behaviour change, just honest results.
3. pmmcp **P1 + P2 + P3** (tokens, enforcement, profiles), with kernel
   **K1 + K2 + K3 + K4**. This is the compartment itself, so the leak matrix
   (§5) must pass before step 4.
4. pmmcp **P4**, with kernel **K6**.
5. Kernel **K5, K7, K9**.
6. pmmcp **P7** (provenance), before any recall is exposed to an agent.
7. **K10** must happen before the Phase 0 exit run writes real data, wherever
   the rest stands.

After each pmmcp change: re-capture, update the double, let the drift test show
exactly what moved.

## 7. Decisions for the operator

| # | Decision | Default (written into this spec) | Alternative |
|---|---|---|---|
| D1 | Sector list | Six sectors: growth splits into `media` (clipping, production, publishing) and `marketing` (marketing, social, community, sales) | the design's five, with growth as one sector |
| D2 | What the CEO sees | Typed results only: status, cost, taint, evidence refs, a ≤2,000-char summary. **No recall into any sector.** | the design's recall over every agent's namespace (executive.md:410), provenance-filtered |
| D3 | Shared knowledge | One shared namespace per sector, plus `aos/fleet/shared` for operator-level knowledge only (preferences, voice), human-promoted | one flat `aos/shared` read by every clean run (agent-fleet.md:489) |
| D4 | Moving data between sectors | Only as an operator-approved handoff into the target's inbox (§2.6) | sector leads read each other's shared namespaces |
| D5 | Security agents and code | A read-only grant: `security` → `engineering`, for security-reviewer and pentester runs | no grant (code review moves into engineering's own reviewer) |
| D6 | May an engineering summary to the CEO name files, functions or errors? | Yes, up to 2,000 chars, since the CEO must judge the result; no file contents | names only of deliverables, no technical detail |
| D7 | The event log | Stays one log for the operator. warden's `events.search` over engineering runs is metadata only; payload reads need a human | warden unscoped, as designed (ops-security.md:74) |

Design-doc conflicts these defaults resolve, kept so the next design pass can
amend the docs:

- the flat `aos/shared` (agent-fleet.md:483, 489);
- CEO recall over `aos/agent/*` (executive.md:410);
- the curator reading every sector (executive.md:453); under D2 and D3 it runs
  as one instance per sector;
- pentest findings mirrored fleet-wide (ops-security.md:225, 515), which now go
  to `aos/security/shared`;
- implementer#docs writing to `aos/shared` (engineering.md:247);
- shared templates recalling "the spawner's namespace" (engineering.md:180,
  growth.md:239, trading.md:405).

## 8. What this does not isolate

- **The event log**: one SQLite file. It holds tool results, prompts and
  responses for every sector, and the operator's UI and CLI read it whole.
  That is by design, because the operator sees everything. Agents cannot read
  it today. Any future `events.search` tool must be sector-scoped (D7).
- **Domain stores outside pmmcp**: the CRM, the trading ledger, the publishing
  edge and the artifact store. Each needs its own sector check where it is
  built.
- **Kernel memory**: a single process holds every sector's tokens.
  Compartments protect against a wrong call, not against code execution
  inside the kernel. Invariant 2 keeps agents out of the kernel.
- **pmmcp's own storage**: SQLite and Qdrant on disk, and backups. Anything
  that reads them directly bypasses P1–P3. They stay operator-only files.

## 9. Needs validation before implementing

- pmmcp's `mcp` version: v1 FastMCP or v2 MCPServer (`ToolError` and the
  error quirk differ).
- Whether pmmcp's recall filters `project_id` inside the Qdrant query today.
- The real name and arguments of `search`, if it exists.
- Whether anything is already stored under `aos/` (K10).
- Whether `get_secret` takes `project_id` live.
