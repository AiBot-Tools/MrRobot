# pmmcp ↔ kernel contract: compartments

Status: **draft, revision 5** (2026-10-17). Not implemented on either side.

- **Revision 1** wrote decisions D1–D7 on recommended defaults.
- **Revision 2** encoded the operator's answers (2026-10-17) and fixed an
  adversarial review of revision 1.
- **Revision 3** rebuilt lineage, copies and briefs after a second review.
- **Revision 4** answers a third review (61 of 68 findings survived their
  skeptics), whose critical findings all came from exceptions revision 3 had
  added. It replaces them with one smaller core (§2.4), built on three
  relations:
  - **hold**: what a run may have in its context;
  - **receive**: what a child may be started with;
  - **store**: what may be written where. Foreign data is stored only where
    the operator approved its exact bytes, or where an open set the operator
    approved covers it.

  It also drops the CEO's blanket clearance, the executive-child exemption,
  and every way a release could become storage. Typed results are now strictly
  kernel-derived, and grant data stays in the grantee's run.
- **Revision 5** answers a fourth review (61 of 69 findings survived). It
  fixes three holes in the core:
  - an effort release now records its member set when it is granted, so
    adding a member never reopens earlier copies;
  - effort ids are never reused;
  - the D6 channel never changes the source run's logged lineage, so it never
    unlocks a deliverable.

  It also:
  - marks D5 data with a standing mark, so `security/code` holds natively only
    what its own D5 reads delivered;
  - covers copies only through an open set;
  - makes reading a tainted result taint the reader;
  - names two readings for the operator: the CEO keeps what it holds in its
    own memory and goals (R13), and open-set briefs carry data without a copy
    (R14);
  - fixes the leak matrix so a correct implementation can pass it, the order
    of work, and many details.

Short names for the design documents: AF = `docs/design/agent-fleet.md`;
EX, EN, GR, OS, TR = `docs/design/sectors/` executive, engineering, growth,
ops-security, trading.

## 0. What this is for

The operator's rule: every part of the agent OS keeps its pmmcp data apart
from every other part, and **coding data is readable only by agents that do
coding**. Marketing (clipping included), trading, security and the rest are
kept apart from engineering and from each other.

The unit of separation is a **compartment**: each sector is one, and a sector
may contain sub-sections (§2.1).

Two halves, and neither one isolates anything alone:

- **pmmcp changes (P1–P9, §3)**, for the pmmcp project (Python, outside this
  repository). pmmcp must enforce the compartments itself. Today it
  authenticates nobody, so any process on the Mac can read any `project_id`.
  Several tools also ignore `project_id` or treat its absence as "everything".
- **Kernel changes (K1–K13, §4)**, for this repository. The kernel puts every
  agent in exactly one compartment, addresses only the namespaces that
  compartment may reach, holds one pmmcp credential per principal, and tracks
  where the data inside every run came from (lineage, §2.4).

What each wall can and cannot catch:

- pmmcp catches a kernel that addresses the wrong namespace with a correctly
  chosen principal. It cannot catch a kernel that picks the wrong principal
  for a run. K3's binding and cross-check are the guard for that.
- Once data is inside a run's context, only the kernel's lineage rules stop it
  moving on (§2.4). pmmcp stores lineage, filters on it, and never sees a
  prompt.
- The kernel-only principals reach only their fixed namespaces. `aos-promote`,
  `aos-collab` and `aos-brief` read nothing; `aos-goals` and `aos-goals-live`
  read only their goal namespaces. A kernel bug can still misuse them by
  writing: wrong bytes, wrong members or a wrong target land where other
  compartments read. pmmcp cannot verify that a human approved a write (§8).

Out of scope, and **not isolated by this contract**: data outside pmmcp (§8).

## 1. Facts this rests on

C = read in a primary source; I = inference.

**MCP specification**

- The latest revision is **2026-07-28** (C: spec repo `docs/docs.json:33`,
  changelog). It removes protocol sessions, `initialize` and `ping`.
- The kernel's TypeScript SDK 1.30.0 speaks **2025-11-25** at most (C:
  `node_modules/@modelcontextprotocol/sdk/dist/esm/types.js:2-4`).
- Python `mcp` 2.x serves both eras; `mcp` 1.30.0 serves 2025-11-25 (C).
- This contract targets 2025-11-25 Streamable HTTP. On that revision a
  per-tool principal check in the Python SDK depends on its session-owner
  binding (below), so P1 pins a version that has it. 2026-07-28 removes the
  dependency (I).

**Authorization**

- Authorization is OPTIONAL in 2025-11-25 (C: `basic/authorization.mdx:16`).
  A static bearer per client is therefore a permitted deviation from the
  OAuth flow, not a violation (I).
- 2025-11-25's security best practices say a local HTTP server SHOULD
  restrict access, for example by requiring an authorization token (C:
  `security_best_practices.mdx:678-686`). The 2026-07-28 local-server page
  adds that "binding to 127.0.0.1 is not an authentication boundary" (C:
  `local-server-security.mdx:320-327`).
- Invalid or missing tokens MUST get HTTP 401 (C: `authorization.mdx:475,
  491`).
- The Python SDK's bearer middleware answers 401
  `{"error":"invalid_token","error_description":"Authentication required"}`
  and never echoes the token (C: `auth/middleware/bearer_auth.py:120-170`).
- `RequireAuthMiddleware` with no `required_scopes` admits every verified
  principal (C: `bearer_auth.py:123-141`).
- **From `mcp` 1.27.2, and in 2.x, the SDK binds a session to the
  `(client_id, claims["iss"], subject)` of the token that opened it**, and
  answers any other principal with 404 "Session not found" (C: 1.30.0
  `streamable_http_manager.py:274-288`; 2.3.0 `:267-279`). **1.27.1 and
  earlier have no such check** (C). Each principal must therefore map to its
  own `client_id` (I).
- In `mcp` v1 stateful mode, `get_access_token()` inside a tool returns the
  token of the request that **opened the session**. The session's server task
  is started inside that request and inherits its context (C:
  `auth_context.py:41-43`, `streamable_http_manager.py:385`,
  `lowlevel/server.py:679-684`). A per-tool check is sound only with the
  owner binding above (I).
- In `mcp` v1, `Context.client_id` returns the **client-supplied**
  `_meta.client_id`, not the token's (C: 1.30.0 `fastmcp/server.py:1321-1331`;
  `types.py:61-71`, where `Meta` allows extra fields).
- From 2.0, `mcp.server.fastmcp` no longer imports (C: 2.3.0
  `server/fastmcp.py:1-16`).
- 2025-11-25 neither allows nor forbids a `tools/list` that varies by caller
  (C: `server/tools.mdx:36-70`). 2026-07-28 allows one that varies "by the
  authorization presented on the request" (C: `server/tools.mdx:62-68`). P3
  therefore refuses the call as well, and never relies on the listing alone.

**Tool results**

- A tool's own failure SHOULD be a result with `isError: true` (C).
- `raise ToolError("x")` in a tool body reaches the client as one text block,
  **`Error executing tool <name>: x`**, with `isError: true`, in v1 and v2 (C:
  v1 `fastmcp/tools/base.py:116-117`, `lowlevel/server.py:589-590`; v2
  `mcpserver/tools/base.py:208-210`). In v1, any other exception's text
  reaches the client the same way (C).
- On v2, `_handle_call_tool` turns an exception raised by `call_tool()` into an
  `is_error` result (C: `mcpserver/server.py:437-456`). A `ToolError` raised
  in an override of `_handle_call_tool` itself escapes to the dispatcher and
  reaches the client as a JSON-RPC error with code 0 (C:
  `shared/jsonrpc_dispatcher.py:771-777`).
- A missing or malformed required argument is refused by the SDK's pydantic
  validation before the tool body runs. The text is pydantic's, and it
  carries no code of pmmcp's (C: v1 `func_metadata.py:107`; v2
  `tools/base.py:153-156`).
- A returned string is `isError: false`. That is what pmmcp does today for
  every refusal (C: Python SDK `handling-errors.md`; kernel
  `test/helpers/mock-pmmcp.ts` `said`).
- **Structured output**: `outputSchema` plus `structuredContent`, with the
  JSON also returned as a text block for compatibility (C).
- TS SDK 1.30.0 (C: `types.js:1252-1259`; `client/index.js:479-557`;
  `validation/ajv-provider.js:4-15`; `ajv-formats/dist/formats.js:12,
  99-111`):
  - it requires an **object-rooted** `outputSchema`, and refuses the whole
    `tools/list` otherwise;
  - it **throws** when a tool declares one and returns no `structuredContent`
    without `isError`;
  - it validates only the last page of a paginated `tools/list`;
  - it validates `format: date-time` strictly, so a timestamp without an
    offset fails.
- pydantic emits a self-referential model as `{"$defs": {...}, "$ref":
  "#/$defs/<Model>"}`, with no root `type`. `mcp` 1.29.1 and later, and 2.x,
  copy the referenced definition onto the root. 1.27.2 to 1.29.0 publish the
  schema unchanged (C: 1.30.0 `fastmcp/utilities/func_metadata.py:51-64, 450`;
  2.3.0 `mcpserver/utilities/func_metadata.py:131`; 1.27.2
  `func_metadata.py:410-430`).
- Do not return `CallToolResult(isError=True)` from a v1 tool that declares an
  output schema. v1 validates `structuredContent` even on errors, and the
  validator's text replaces the message (C: `func_metadata.py:133-137`). v2
  skips the check when `is_error` is set (C).
- Tool annotations (`readOnlyHint`, …) are hints the client "MUST consider
  untrusted" (C). `config/tool-views.yaml` stays the authority.
- FastMCP v1 always registers resource and prompt handlers, so it advertises
  those capabilities whether or not pmmcp defines any (C:
  `fastmcp/server.py:318-329`).
- With `AuthSettings.resource_server_url` set, the SDK publishes RFC 9728
  metadata naming `issuer_url` as the authorization server; with `None` it
  adds no metadata route (C: v1 `fastmcp/server.py:1056-1066`). Custom routes
  are added outside the auth middleware (C: `:736`, `:1068`).

**pmmcp today (from this repository)**

- `recall`/`remember` take an optional `project_id`, and leaving it out means
  global scope (pmmcp `src/tools/primary.py`, per
  `config/tool-views.yaml:15-18`).
- `update_goal`, `get_goal_tree` and `complete_goal` take no `project_id`;
  `goal_id` is their only locator (C: `mock-pmmcp.ts:217-268`, read from
  pmmcp's source). `update_goal` takes ten arguments, among them
  `description`, `blockers`, `tags`, `acceptance_criteria` and
  `related_files`.
- `list_goals` requires one exact `project_id`, so it cannot enumerate a
  prefix (C: `mock-pmmcp.ts:239-254`).
- `forget` is global when `project_id` is absent. `scrape_context` takes no
  `project_id`. `index_git_history` takes only `project_id` (C:
  `mock-pmmcp.ts:381-386`).
- Refusals arrive as success text. The kernel parses prose:
  `✅ Goal created: <id>` and `✅ Goal updated: <id>`
  (`src/goals/writer.ts:119, 335`).
- pmmcp publishes RFC 9728 metadata that lists no authorization server, which
  the spec's "at least one" MUST forbids (`README.md`, `kernel.yaml`).
- The pmmcp dashboard is a separate HTTP server on 127.0.0.1:8765
  (`config/kernel.yaml:35`). Qdrant runs in Docker.
- `docs/DECISIONS.md:136` says pmmcp needs a bearer. The operator-confirmed
  fact (CLAUDE.md) is that it authenticates nobody. That wins until P1 ships.

**The kernel today**

- **Namespaces and goals.**
  - One memory namespace per agent, from a fixed shape:
    `aos/ceo | aos/shared | aos/agent/<id>` (`src/agents/manifest.ts:28`).
  - Goals are written into the adopting agent's namespace
    (`src/runtime/delegate.ts:185, 203`; `src/kernel.ts:476`;
    `src/goals/tracker.ts:203`).
  - No compartment concept exists anywhere in `src/`.
  - No pmmcp tool is exposed to any agent (`config/tool-views.yaml`).
- **The gate.**
  - It **checks** the `project_id` the model sends against exactly one
    namespace, and never **sets** it (`src/policy/gate.ts:122-145`).
    CLAUDE.md, README.md:389-390 and tool-views.yaml:15-18 require it to set
    the id before `recall` or `remember` is exposed. K2 meets that
    requirement.
  - Its only `needs-human` rules are irreversible risk and a tainted run
    calling a non-read tool (`gate.ts:146-155`).
  - Kernel tools are `risk: write` (`tool-views.yaml:136-142`). The CEO is
    tier 2, which may hold only read and write tools (`agents/ceo/agent.yaml`;
    `src/agents/registry.ts:67-73`).
- **The hub.**
  - One pmmcp client, one session, at most one bearer (`src/mcp/hub.ts`).
  - On the agent path it renders a tool result to text and drops
    `structuredContent` (`hub.ts:424-428, 514-524`).
- **Kernel tools and delegation.**
  - Kernel tools are offered to, and run for, orchestrators only
    (`registry.ts:150`, `src/runtime/loop.ts:437`).
  - A kernel tool runs only after the gate's ticket (`kernel-tools.ts:96,
    121`), and the execute step runs outside the run scope (`loop.ts:440-448`).
  - A plan may name any active standard worker (`delegate.ts:172-176`). No
    assistant manifest ships yet (`agents/` holds ceo, researcher,
    worker-template and writer). Once one ships as an active standard worker,
    the CEO can delegate to it with no further check.
  - A plan's task and milestone ids are free model text, up to 64 characters
    (`src/goals/plan.ts:44, 70`). `kernel.delegate` takes `taskId` from the
    model (`delegate.ts:127`).
  - A delegation brief (≤ 8,000 characters) becomes part of the child's
    prompt, after a task header and the acceptance list
    (`delegate.ts:51, 300-302`).
  - The child's `finalText` comes back to the parent, and so does its error
    or stop `reason` (`delegate.ts:368-370`).
    - That `reason` is an exception's `message` (`src/runtime/loop.ts:292`),
      with no cap of its own.
    - A refused delegation returns `[refused]` plus the whole reason
      (`delegate.ts:168`). Only the logged copy is cut to 500 UTF-16 code
      units (`delegate.ts:165`).
    - A provider error's text holds up to 500 UTF-16 code units of the
      response body (`src/models/openai-chat.ts:270`).
  - A delegated child does not inherit its parent's taint (`kernel.ts:613`).
  - There is no `RunResult`, no deliverable and no `inputRefs` in code. These
    exist only in EX §3, where every model-written field is self-reported
    (EX:139-152).
- **The log.**
  - `run.finished` records status, reason, cost and counts, and no output text
    (`src/events/types.ts:325-336`). The run's final taint is in no event
    today. The loop derives it on its last turn (`loop.ts:162-166`).
  - `llm.response` logs only the model's text, never its tool-call input
    (`src/models/anthropic.ts:224-252`). A tool call's arguments first reach
    the log in the next `llm.request`.
  - A `needs-human` card carries a 500-byte preview of the canonical
    arguments (`src/policy/engine.ts:81`).
  - The event store refuses any payload whose canonical JSON exceeds
    `MAX_LOGGED_OUTPUT` (65,536 bytes) (`src/events/store.ts:147-159`).
    Strings are JSON-escaped (`src/events/canonical.ts:46`).
    `PAYLOAD_TEXT_BUDGET` (63,488 bytes) is the text budget a producer bounds
    to (`src/events/bound.ts:40`).
  - Boot re-parses stored `goal.created` rows and open `run.queued` rows with
    strict schemas (`kernel.ts:301, 482`; `tracker.ts:93, 135`).
- **Approvals and protocol v1.**
  - An approval is tied to a parked run and expires with it, and restart
    settles every pending one (`src/policy/approvals.ts:115-132`).
  - Protocol v1's approval kinds are `tool` and `promotion` (agent promotion)
    only (`src/control/protocol.ts:123`).
  - `approval.approve` takes only `{approvalId}` (`protocol.ts:307-310`).
  - v1 has no revoke, suspend, close or override command (`protocol.ts:44-61`).
- **Live tests.** The live tests take one `PMMCP_TOKEN`.
  - `test/live-runtime.test.ts` builds its own hub with it (`:111-124`).
  - The kernel-boot tests pass it in the boot env (`live-runtime.test.ts:162`;
    `test/live-anthropic.test.ts:230`). Nothing reads it there, because
    `config/kernel.yaml` declares no pmmcp `tokenEnv`.
  - The test guard and the falsify child scrubber strip credential names by
    pattern, and today's pattern matches only `PMMCP_TOKEN` among pmmcp names
    (`test/helpers/guard.ts`, `scripts/falsify/runner.ts`, pinned equal by
    `test/falsify.test.ts:481`).

## 2. The compartment model

### 2.1 Compartments (D1)

Five sectors, two of which contain a sub-section:

| Compartment | Holds | Agents (from docs/design) |
|---|---|---|
| `executive` | goal tree, adopted plans, mandates, CEO memory | ceo, planner², assistant, judge#exec², curator-executive |
| `engineering` | **all coding data**: code knowledge, ADRs, module maps, design system, incident notes, indexed repositories and git history | eng-lead, prototyper, sre, architect, implementer, tester, reviewer, release, scout#eng², judge#eng² |
| `marketing` | marketing, social, community, sales: brand kit, ICP, drafts, CRM-adjacent notes | marketer, writer, community, sales, publisher, researcher, checker{brand,policy,facts}, reporter, focus-group, scout#growth², curator-marketing |
| `marketing/clipping` | clipping and production: captions, renders, clip plans, media checks | producer, checker{media} |
| `trading` | theses, signals, strategy cards, backtests, journals | quant, executor, bookkeeper, market-scout (scout#market²), critic (judge#critic²), curator-trading |
| `security` | warden reports and fleet security findings that cite no code | warden, evaluator, comms-triage, curator-security |
| `security/code` | code review and pentest work under the D5 grant | security-reviewer, pentester |

There are two kinds of sub-section:

- **Open** (`marketing/clipping`). It is part of marketing. Every marketing
  agent reads it, and clipping agents read marketing. Both run under the
  marketing principal (P1), and for lineage a clipping run counts as
  `marketing` everywhere: in the kernel and on the wire (§2.4, P7). Its own
  namespaces keep clipping work organised, and an edit to the principals file
  would seal it later.
- **Sealed** (`security/code`). Only its own agents read it, and the CEO reads
  its kernel-filed, capped brief (§2.5). They hold the D5 read grant into
  engineering, so what they find stays away from warden, evaluator and
  comms-triage. comms-triage is always tainted and will take inbound SMS and
  Telegram.

² **Template profiles** (§2.5). planner, scout and judge are templates; scout
and judge have one profile per compartment. A profile serves `engineering`
only if its manifest, which the operator edits, gives it that compartment.
That entry is the operator's statement that the profile does coding work.

**Curators** are standard, scheduled agents, one per compartment they curate.
There is none for `engineering` or `security/code`. Engineering memory is
curated by promotions of eng-lead's deliverables (§2.8), or by the operator
(R7).

**The shipped fleet**:

- ceo → `executive`. It is the agent with id `ceo`, and the only one bound to
  `aos-ceo` (K3).
- writer → `marketing`.
- researcher → `marketing`. It is a web researcher, and GR:110 folds the
  standing researcher into growth.
- worker-template → a template with one profile, in `executive`.

**The eval cases** (`src/eval/suite.ts`):

- `ceo-objective-fanout` researches the kernel's own event log, which is
  engineering material, and requires two child runs. K1 rewrites its objective
  in marketing terms, so both children stay in one compartment.
- `ceo-inline-small-objective` delegates nothing. `ceo-honest-about-missing-tools`
  is scored on ending honestly, not on delegating. Both keep their objectives.
- The live `PLAN_REQUEST` (`test/helpers/runtime-bodies.ts`) adopts a plan into
  goals and starts no child run, so it is unchanged.

### 2.2 Namespaces

This grammar replaces `MEMORY_PROJECT`. `<c>` is a compartment from §2.1.

```
aos/<c>/agent/<id>             an agent's own memory (episodic)
aos/<c>/shared                 the compartment's curated knowledge (promotion, §2.8)
aos/<c>/brief                  decision-grade reports for the CEO (D2); every <c> except executive
aos/engineering/index/<repo>   an indexed repository and its git history (P9)
aos/executive/ceo              the CEO's own memory (the CEO only)
aos/executive/goals            the goal tree (kernel only, §2.6)
aos/executive/live-test        goals written by the gated live tests
aos/collab/<effort>            one collaboration effort's space (§2.7)
aos/fleet/shared               knowledge every compartment reads (promotion, §2.8)
```

- `<id>`, `<repo>` and `<effort>` are `[a-z0-9][a-z0-9-]{0,63}`.
- pmmcp checks this grammar exactly (P2). Nothing normalises a `project_id`
  anywhere.
- Nothing outside `aos/` is ever an agent's namespace. Whatever `project_id`s
  the operator's own tools (Claude Code, pmmcp's CLI) use stay unreachable
  from every agent.
- The old names (`aos/ceo`, `aos/shared`, `aos/agent/<id>`) are retired, not
  aliased (K12).

### 2.3 Who may read and write what

"Read" means recall (and `search`, if pmmcp serves it) and list. Writes into
`shared`, `collab`, `fleet`, the engineering and `security/code` briefs, and
the goal namespaces are made by the kernel with a kernel-only principal (P1),
and every write obeys the store rule (§2.4).

| Namespace | Read | Write |
|---|---|---|
| `aos/<c>/agent/<id>` | that agent, and `c`'s curator¹ | that agent, by a gated `remember` |
| `aos/<c>/shared` | agents of `c`; `security/code` for `aos/engineering/shared` (D5); the CEO, except for `engineering` and `security/code` | **only** the kernel, for an operator-approved promotion (§2.8) |
| `aos/<c>/brief` (every `c` except `executive`) | agents of `c`; the CEO | agents of `c`, by a gated `remember`; for `engineering` and `security/code`, **only** the kernel, from a finished run's capped summary (§2.5) |
| `aos/engineering/index/<repo>` | `engineering`; `security/code` (D5) | **only** the operator's indexing (P9) |
| `aos/executive/ceo` | the CEO | the CEO, by a gated `remember` |
| `aos/executive/goals` | the kernel; the CEO through `kernel.read_goals` | the kernel only (§2.6) |
| `aos/collab/<effort>` | agents of the effort's member compartments while it is live; the CEO, under its hold rule (§2.4), while it is live | **only** the kernel, for an approved or open-set-covered copy (§2.7) |
| `aos/fleet/shared` | every agent | **only** the kernel, for an operator-approved promotion (§2.8) |

"Agents of `c`" includes the parent sector's agents when `c` is the open
sub-section, and the sub-section's agents when `c` is `marketing`.

¹ pmmcp's wall is the compartment: any agent of `c` holds the principal that
could read every `aos/<c>/agent/*`. Keeping an agent to its own namespace is
the kernel's read set (K2). A curator reads its compartment's agent
namespaces through `agent:<id>` labels (K2). The CEO's memory is curated by
the operator.

**Readers.** Wherever this contract speaks of the readers of a namespace (the
store rule, copies, promotions, cards), they are the compartments in this
table, plus every standing grant that reads the namespace, plus the CEO
where the table lists it.

Rules that apply across the table:

- **Cross-compartment reads exist only by the operator's decision**, and each
  is read-only:
  - standing grants in config; there is one today, D5;
  - runtime grants the operator approves (§2.9);
  - collaboration memberships the operator approves (§2.7);
  - every agent's read of `aos/fleet/shared`, which holds only promoted
    records;
  - the CEO's reads in this table (D2).
- **The CEO's wider reach belongs to the CEO alone.** Every other executive
  agent, whether a standard agent such as assistant or a template child such
  as planner, holds executive data only (§2.4).
- **Coding data leaves engineering only in ways the operator chose:**
  - the D5 grant;
  - the capped D6 channel to the CEO: summaries it asks for, and
    kernel-filed briefs (§2.5);
  - an operator grant;
  - a copy or promotion the operator approved on its exact bytes;
  - a parked delegation or parked result read the operator approved.

  Lineage (§2.4) keeps it from moving any further without the operator.
- **Approval cards.** A card, its preview and any held output carry the
  compartment and the lineage of the run that asked (K7). No agent-facing
  bundle (the assistant's digest, warden, a CEO continuation) carries any
  card's preview or held output, with one exception: the CEO's continuation
  receives its own cards. Everywhere else a bundle shows counts per
  compartment and class, nothing more.

### 2.4 Lineage

D2 gives the CEO as much visibility as it needs to decide, and D6 lets the
operator show it file contents. Efforts let compartments work together. All
three put one compartment's data into another's runs. A model can repeat
anything in its context into anything it writes. Lineage keeps that data
where the operator put it.

**Elements**

- A run's lineage is a set of elements `(c, R)`.
  - `c` is the compartment the data came from: `executive`, `engineering`,
    `marketing`, `trading`, `security` or `security/code`. The open
    sub-section counts as `marketing`.
  - `R` is the set of release entries that operator decisions attached to
    that data. It is empty unless an approval says otherwise. An entry is one
    of:
    - a compartment name;
    - `ceo`, which names the agent `ceo` alone;
    - `effort(<id>, {members})`. This names the effort, and the member set it
      had when the release was made. Adding a member later never widens an
      entry already made.
- **Marks.** An element may carry one of two marks:
  - a **grant mark**: the id of the grant that delivered it (§2.9);
  - a **standing mark**, `standing:d5`. The kernel adds it to an engineering
    element only when the element came from a read under the D5 grant
    (`aos/engineering/shared`, `aos/engineering/index/*`). That covers the
    hit's own lineage and what the kernel logged for its id.

  A copy (§2.7), a promotion (§2.8) and an approved parked delegation
  (rule 1) drop both marks from the copy they write.
- Elements with `c = executive` never restrict anything. Executive data may go
  to every compartment.
- The kernel computes lineage for **every** run. The model never sets or sees
  it.
- A run starts with `{(its compartment, ∅)}`, plus what its start admitted
  (receive, below).
- **No rule ever changes a lineage the kernel has already logged.** Every
  release, D6 entry and approval is added to the copy of an element that
  joins the run receiving it, or to the record being written.

**Hold: what a run may have in its context.** A run of compartment B holds an
element when its `c` is `executive`, or when any of these is true:

- `c` is B;
- B is in `R`;
- `R` holds `effort(e, M)`, e is live, and B is in M;
- the element carries `standing:d5`, and B is `security/code`.

Two rules override that list:

- **The CEO** holds every element whose `c` is not `engineering` or
  `security/code`. It holds a coding element only when `ceo` is in `R`.
- **A grant-marked element** is held only by the grantee run (§2.9).

Every other executive agent, whether standard or template child, holds by the
list above. So it holds executive data only.

**Receive: what a child may be started with.** This covers a child the CEO
delegates to, and any run the kernel starts. A child of compartment B, under
objective O, receives an element when its `c` is `executive`, or when any of
these is true:

- `c` is B, or B is in `R`;
- `R` holds `effort(e, M)`, e is live, e is bound to O, and B is in M;
- `c` is not a coding compartment, O's effort e is live, B is one of e's
  members, and `c` is in e's open set. The child's copy of the element then
  gains `effort(e, <e's members now>)`.

A child never receives a grant-marked element, except through a parked
delegation the operator approved (rule 1). Standing marks and standing grants
never admit a brief, because a grant names namespaces while lineage records
only a compartment.

**Store: what may be written where.** A write into namespace N is allowed
only when every reader of N (§2.3) holds every element natively. That covers
an agent's `remember`, a brief the kernel files, a goal, and any record the
kernel writes. A reader X holds an element natively when its `c` is
`executive`, or when any of these is true:

- `c` is X;
- X is `security/code`, and the element carries `standing:d5`;
- X is the CEO, and `c` is not a coding compartment, or `ceo` is in `R`.

Under this rule:

- release entries other than `ceo` never count for storage;
- a grant-marked element is never stored.

The approved writes are the exception: a copy (§2.7) and a promotion (§2.8)
store exactly the bytes their approval or open set covers.

**So foreign data rests in only three kinds of place:**

1. where the operator approved its exact bytes;
2. under an open set the operator approved;
3. in the two namespaces only the CEO reads, its own memory and the goal tree,
   as D2 allows (R13).

Coding data rests in the CEO's namespaces only with `ceo` in `R`.

**What adds to a run's lineage**

- **Recall hits.** A recall hit adds the lineage in its provenance (P7). It
  also adds every lineage the kernel logged for that record id, and for each
  id in its `mergedFrom` (K11).
- **Reading another run's text.** `kernel.read_result` of a run adds that
  run's logged lineage, after the D6 channel below. So does the CEO's own
  card, shown in its continuation.
- **The D6 channel.** It covers exactly two byte strings, both capped:
  - an engineering or `security/code` run's summary, when the CEO reads it
    with `kernel.read_result {part: summary}`;
  - the brief the kernel files from that summary.

  For the read, `ceo` is added to the run's natively held elements in the
  copy of its lineage that joins the CEO's run. For the brief, the brief
  record's provenance gets the same entries. Natively held means the run's
  own compartment, plus, for `security/code`, the elements marked
  `standing:d5`. Neither step changes the run's logged lineage. A
  `part: deliverable` read never uses the D6 channel.
- **Grants.** A granted read adds `(owner, ∅)` and the lineage of every record
  or deliverable it delivered, all grant-marked (§2.9).
- **The goal tree.** `kernel.read_goals {objectiveId}` adds the lineage of the
  goals it returns. It returns one objective's subtree, never the whole tree.
  A goal whose `goal.created` row has no lineage (a v1 row, §4) comes back as
  id, kind, parent and status only, with no title, and adds nothing.
- **Other inputs.** Bytes the kernel hands a run outside a brief add the
  lineage of every run they came from. That includes a deliverable, an
  evidence item and an event-log slice.

**What does not add to a run's lineage:** values the kernel derived itself,
and nothing else. These are:

- run and goal ids;
- a task's kernel-minted handle (`<plan.adopted seq>:<n>`);
- the status and stop-reason enums;
- cost and call counts;
- taint;
- gate counts;
- the kernel's own acceptance and sha256 checks, as enums and counts;
- deliverable refs the kernel minted (`<kind>:<runId>:<n>` with a sha256).

Every string a model wrote is that run's text. That includes:

- a plan's task and milestone ids and titles;
- a summary, deliverable text, and any URL or ref the model chose;
- `failureHistory`, `proposedPlan`, `proposals` and evidence text;
- any error or provider message.

It reaches another run through:

- `kernel.read_result`;
- a brief or a plan's task text, which carry the plan's lineage (rule 5);
- `kernel.read_goals`;
- a copy, a promotion or a grant;
- a stored memory recalled later.

Each of these carries the writing run's lineage.

**Taint travels with text.** A read that hands a run another run's text taints
the reader when that text was tainted. This covers:

- `kernel.read_result` of a run whose `run.result` records `taint: tainted`;
- `kernel.read_grant` of an untrusted or tainted record, or of a tainted run's
  deliverable;
- `kernel.read_goals` of goals that a tainted run adopted.

`goals.adoptFromRuns` skips a run that finished tainted, so a tainted plan
reaches goals only through `kernel.adopt_plan`, which the taint rule parks for
a human.

**The rules**

1. **Delegation and kernel-started runs.** A child starts without a human
   only when it receives every element of:
   - its brief;
   - its plan's task text;
   - every input the kernel hands it.

   Otherwise:
   - **A CEO delegation parks** as `needs-human`. The kernel first logs
     `delegation.parked`, with the child's full input, before the card (K5).
     If the operator approves, the child's copy of each failing element gains
     B in `R` and loses any grant mark: the operator read and released that
     exact input to that compartment. The parent's lineage is unchanged, so a
     grantee parent stays grant-marked. This is the only way a child receives
     data a grant delivered.
   - **A run the kernel itself would start** (a ready plan node, a milestone
     judge) is not started. The kernel logs `start.withheld`, and the CEO may
     delegate it instead.
2. **Reading a result.** `kernel.read_result` hands the CEO a run's text only
   when the CEO holds every element of that run's logged lineage, after the
   D6 channel, which applies only to `part: summary`.
   - Otherwise it parks as `needs-human`. The kernel first logs
     `result.read.parked`, with the run, the part and the failing elements.
   - If the operator approves, `ceo` is added to those elements in the copy
     that joins the CEO's run, for that read only.
3. **Storing.** Every write obeys the store rule.
   - A `remember` that fails it, or that comes from a run holding a
     grant-marked element, is denied.
   - A brief the kernel would file is withheld (`brief.withheld`).
   - A plan adoption from a run holding a grant-marked element is refused.
4. **Copies and promotions** are judged on the source's lineage, never on the
   source run's compartment alone (§2.7, §2.8).
5. **Plans and goals.** An adopted plan carries the adopting run's lineage
   and taint, and so does each goal written from it.

**Where decisions are recorded.**

- Every check on a tool call is computed by the kernel before the gate, and
  reaches the pure gate as a fact. So every refusal of a tool call, and every
  park, is a `tool.gate` row (K2, K5, K9, K11).
- A decision the kernel makes outside a tool call logs its own event:
  `brief.withheld`, `start.withheld` or `judge.skipped`.

**The CEO's own memory.** A recall of `aos/executive/ceo` offers kernel
labels that bound the lineage of the hits (K11; P7's `lineage_within`):

- `own` returns records whose lineage is executive only (`lineage_within:
  [executive]`);
- `own:<c>` returns records whose lineage stays within executive and `c`;
- `own:all` returns everything.

The CEO chooses how much to read. Reading less never widens anything.

**In practice**

- **Typed results.** The CEO reads them freely, and can still delegate
  anywhere.
- **A single-compartment objective.** The CEO reads that compartment's brief,
  and delegates into it without the operator.
- **A cross-compartment objective.** The CEO opens an effort (§2.7) with those
  compartments as members, and the non-coding ones in its open set. The
  operator approves that once. Delegations under the objective then carry
  those compartments' data between members with no further approval. A member
  never stores such data outside the collaboration space.
- **Coding data never moves through an open set.** Outside the D6 summary
  channel, each crossing out of engineering is an operator approval of exact
  bytes: a copy, a promotion, a parked brief or a parked result read.
- **Reading has a cost (R9).** If the CEO reads marketing's and trading's
  briefs with no effort open, every brief it then writes to either
  compartment parks.

### 2.5 Templates, children and results

**A child's compartment**

- A standard agent's compartment is the one in its manifest.
- A template declares one or more **profiles**. Each profile has exactly one
  compartment and its own `tools.allow`, and the operator edits both. Examples
  are `scout#eng` → engineering, `scout#growth` → marketing, `scout#market` →
  trading, `judge#exec` → executive, `judge#eng` → engineering, and
  `judge#critic` → trading.
- A plan task names a profile, as it names a standard agent. A template with
  one profile may be named bare. A plan that names a multi-profile template
  without a profile is refused.
- No plan field sets a compartment. Which data the child receives is still
  decided by the receive rule (§2.4).
- The registry refuses `schedule:` on a template, so every scheduled run
  belongs to a standard agent.

**What a child can reach**

- A child gets its compartment's read set plus that compartment's config
  grants, intersected with what its profile declares. It inherits nothing
  from its parent's reach.
- Tier, egress, tools and budget follow the parent ∩ template rule (EX:130).
- Taint passes from parent to child (K5). Today it does not (`kernel.ts:613`).

**Results (K5)**

- **The result record.** When any run finishes, child or not (a scheduled
  curator included), the kernel logs two events.
  - **`run.deliverable {runId, n, sha256, text, truncated}`.** The text is the
    run's final text, bounded by `PAYLOAD_TEXT_BUDGET` minus 4,096 bytes for
    the other fields. `truncated` says whether it was cut. A truncated
    deliverable can be read, but never copied or promoted.
  - **`run.result`**, which carries:
    - the typed fields (§2.4);
    - the run's final taint;
    - its logged lineage;
    - kernel-minted refs to its deliverables;
    - its summary: the first 2,000 code points of the final text, with
      `summaryCut: true` when cut. No marker is added to the text.
- **What `kernel.delegate` returns.**
  - It returns only the typed fields, with the task named by its kernel
    handle.
  - A stop reason is an enum: `usdMax`, `maxLlmCalls`, `maxToolCalls`,
    `wallclock`, `approval`, `killed` or `error`. Its text stays in the log.
  - It keeps returning the child's taint, so a tainted child taints its
    parent (`delegate.ts:362`).
- **Reading the summary or deliverable.** The CEO reads either with
  `kernel.read_result {runId, part}`, under §2.4 rule 2. That read taints the
  CEO when the run finished tainted.
- **Raw memory** never comes back.

**Engineering text and D6**

- Engineering and `security/code` text reaches the CEO, outside an operator
  release, in only two shapes, the D6 channel (§2.4). The kernel caps both at
  2,000 code points.
  - **A summary** the CEO reads with `kernel.read_result {part: summary}`. A
    `part: deliverable` read of such a run always needs the operator.
  - **A brief** the kernel files from a finished run's summary into
    `aos/<c>/brief`, with the write-only `aos-brief` principal. It does so
    only for agents whose manifest sets `filesBrief: true`, which the operator
    edits, and only when the store rule passes. There is at most one per run,
    and P2 caps it at pmmcp too.
- Engineering and `security/code` agents never write their brief themselves,
  because K2 offers them no `brief` scope.
- A summary or brief may name files, functions and errors. No artifact body is
  handed over.
- **What stays possible (R8).** A model can quote up to 2,000 code points of
  code in one summary or brief, and many briefs together can quote more.
  Lineage keeps such a quote from going any further.
- File contents otherwise reach the CEO only through an operator grant (§2.9),
  or a copy or promotion the operator released to the CEO.

**Milestone judges.** The kernel judges a milestone only through a judge
profile whose compartment natively holds every element of the evidence's
lineage. An engineering milestone needs `judge#eng`, and `judge#exec` judges
no coding milestone. Otherwise the kernel logs `judge.skipped`, and the
milestone waits for a human (EX:276).

**Delegating to a template** is ephemeral spawning, which no tool does yet
(CLAUDE.md). Building it widens what agents can reach, so it is ask-before.

### 2.6 Goals

- **Where goals live.** The goal tree lives in `goals.projectId`,
  `aos/executive/goals`. K6a lands together with K1, so no goal is ever
  written into an agent's namespace, the CEO's included.
- **Who writes them.** The goal writer uses the `aos-goals` principal. The
  gated live tests use `aos-goals-live`, which reaches only
  `aos/executive/live-test`, so pmmcp refuses a live-test goal aimed at the
  real tree. `aos-goals-live` is declared only in the live tests' config
  (`liveKernelYaml`), never in the shipped `kernel.yaml`.
- **What the kernel sends.**
  - To `create_goal`: only `project_id`, `goal_type`, `title` (≤ 200
    characters) and `parent_goal_id`.
  - To `update_goal`: only `goal_id`, `project_id`, `status` and
    `progress_pct`.
  - Never description, acceptance criteria, related files, blockers or tags.
- **Lineage and taint.** A goal carries its plan's lineage and taint in the
  kernel's `goal.created` record, from K11 on (schema version 2). When the CEO
  adopts a plan it read from a child's result, the plan carries that child's
  lineage too, because reading it added that lineage to the CEO's run.
- **Plans from tainted runs.** `goals.adoptFromRuns` skips a run that finished
  tainted.
- **How the CEO sees them.**
  - The CEO sees one objective's subtree at a time, through
    `kernel.read_goals {objectiveId}`, and those goals' lineage and taint join
    its run.
  - A goal recorded before lineage existed (a v1 row) comes back without its
    title (§2.4).
- Sector agents never touch goals. The kernel moves task status from the run
  lifecycle, as it does today.
- P4 makes pmmcp enforce the namespace on every goal call, so no goal can be
  read or moved by id alone.

### 2.7 Collaboration efforts and copies (D3, D4)

Data never moves between compartments. When agents of different compartments
work together, whatever must persist is **copied** into a collaboration space,
and the original stays where it is. Within a live effort, a CEO delegation
brief may also carry one open-set member's non-coding data into another
member's run (receive, §2.4). That data lives only in that run's context.
Members store neither kind in their own namespaces (store rule, §2.4). R14
names this reading of D4.

**Efforts**

- An effort is bound to one objective. It has:
  - an id, never reused: `kernel.open_effort` refuses an id that any earlier
    `effort.opened` row used, so an ended effort's releases can never come
    back;
  - a title;
  - **members**: compartments with a principal of their own, never
    `executive`; the open sub-section joins as `marketing`;
  - an **open set**: the members whose non-coding data may flow within the
    effort without an approval each time (`engineering` and `security/code`
    can never be in it);
  - an expiry;
  - the space `aos/collab/<effort>`.
- The CEO proposes an effort with `kernel.open_effort {effort, objectiveId,
  title, members, open, expiresAt}`. The operator approves it, because the
  members and the open set are access decisions.
- `kernel.add_member` adds a member under the same approval. Every release
  already made records the member set it was made for (§2.4), so a new member
  holds and receives only data copied or released after it joined. In
  protocol v1 nothing else changes an effort before it expires (§2.10).
- An objective has at most one effort.
- An effort ends at its expiry. The kernel cannot see an objective close in
  pmmcp; closing early is protocol v2. When an effort ends:
  - the kernel stops offering its `effort:<id>` label to every agent, the
    CEO included, and refuses new copies;
  - its `effort(…)` releases stop counting for hold and receive;
  - the space stays in pmmcp, and nothing is deleted.
- Efforts are logged (`effort.opened`, `effort.member.added`, `effort.ended`)
  and projected from the log.
- **Why `executive` is never a member.** Every executive agent other than the
  CEO holds executive data only (§2.3). A member set naming `executive` would
  give the assistant and the planner effort data. The CEO reads efforts under
  its own hold rule instead.

**Size**

- There is no cap on a space.
- A single copy must fit in one event with its proposal. Its JSON-escaped
  length (`canonicalize`) is at most `PAYLOAD_TEXT_BUDGET` minus 8,192 bytes
  (55,296 bytes), which leaves room for its lineage, readers and other fields.
  The kernel refuses a copy whose `kernel.proposed` row would still exceed
  `MAX_LOGGED_OUTPUT`. Larger material goes in as several copies.
- The kernel never truncates a copy. It refuses a source the log holds
  truncated.

**A copy**

The CEO files `kernel.copy_to_collab {effort, source, ceoRelease}`.

- **The source** is a deliverable ref the kernel minted for a finished run
  (§2.5): bytes the log already holds. To copy a stored memory, a run of the
  source compartment first recalls it into its deliverable.
- **`ceoRelease`** asks that the CEO may read a coding copy too. The CEO reads
  a non-coding copy anyway.
- **Who may file.** Workers do not file copies. Letting them is a widening,
  and ask-before.

1. **Preparing.** The kernel's prepare step (K5) runs only after the gate's
   deny rules have passed for this call. It then:
   - resolves the bytes;
   - refuses bytes the log's redactor would change, so the bytes the operator
     reads are exactly the bytes that get written;
   - logs `kernel.proposed`. That row carries the full arguments, the full
     bytes and their sha256, the source compartment, run, taint and lineage,
     and every reader of the copy: the members, plus the CEO for a non-coding
     copy or when `ceoRelease` is set;
   - adds the sha256 to the arguments the gate hashes, so an approval binds
     those exact bytes.

   A denied call resolves nothing, and logs only its `tool.gate` row.
2. **Coverage.** A copy needs no fresh approval only when all of these hold:
   - the calling run is clean;
   - `ceoRelease` is not set;
   - no element of the source lineage is grant-marked;
   - no element has `c` = `engineering` or `security/code`, whatever its `R`;
   - every member receives every other element: its `c` is `executive`, or is
     that member's own compartment, or is in the effort's open set, or its
     `R` holds an `effort(<this effort>, M)` entry with that member in M.

   A compartment-name or `ceo` entry in `R` never makes a copy covered. So
   every copy whose source holds coding data is approved one at a time. So is
   every copy of data that reached the source only through a compartment or
   `ceo` release.
3. **Approval.** Otherwise the operator approves this copy, having read the
   `kernel.proposed` row. The operator can approve or deny it as filed: in v1,
   a different `ceoRelease` means the CEO files again.
4. **Writing.** The kernel writes the bytes into `aos/collab/<effort>` with the
   `aos-collab` principal (P1). The provenance is P7's, filled for the source
   run:
   - its `runId`, `agentId` and `taint`;
   - `origin`: `untrusted` if that run was tainted, else `agent`;
   - `lineage`: the source lineage, with `effort(<id>, <members now>)` added
     to each element's `R`, plus `ceo` when `ceoRelease` was approved. This
     is the release. Grant and standing marks are dropped, because the
     operator approved these bytes or an approved open set covers them;
   - `observedAt`;
   - `source {compartment, runId, sha256}`, `members`, `copiedBy` and
     `approvedBy`.

**Reading**

- **Members** read the space while it is live. pmmcp returns a record only to
  a principal whose compartment is among that record's `members` (P2).
- **The CEO** reads, while the effort is live, every record its hold rule
  allows: every record whose coding elements, if any, all carry `ceo`. pmmcp
  enforces that per element (P2).
- **Lineage.** Reading adds the record's lineage (§2.4). A member holds it
  while the effort is live, may pass it within the effort, and stores none of
  it.
- **A new member** sees only later copies, because both the record's
  `members` and each release's member set were fixed when it was written. To
  give a new member an earlier copy, the CEO files it again.

**The fleet space.** `aos/fleet/shared` is written only by promotion (§2.8).

### 2.8 Promotion

A promotion puts approved bytes into a curated namespace: a compartment's
`shared`, or `aos/fleet/shared`.

- **Who files.** In v1, the CEO files `kernel.promote {source, target}`. The
  source is a deliverable ref the kernel minted.
- **Candidates.** A curator's or eng-lead's deliverables are candidates;
  every finished run has them (§2.5).
  - The kernel lists them in the CEO's continuation as typed refs only: ref,
    source compartment and sha256. They carry no text and no target. The CEO
    names the target when it files `kernel.promote`.
  - A promotion approved without a CEO run needs a run-independent approval,
    which is protocol v2 (§2.10).
- **The target** is relative to the source run's compartment:
  - `own`: `aos/<c>/shared`, which is `aos/security/code/shared` for a
    `security/code` source;
  - `parent`: `aos/security/shared` for a `security/code` source, or
    `aos/marketing/shared` for a clipping source;
  - `fleet`: `aos/fleet/shared`.

  The kernel refuses anything else.
- **The source.** The kernel takes the source bytes as it does for a copy
  (§2.7: size, redaction, truncation, `kernel.proposed`, sha256 hashed). It
  refuses a source from a tainted run.
- **The card names every reader of the target** (§2.3), the CEO and
  standing-grant readers included. Approving a coding-lineage promotion into a
  namespace the CEO reads is a D6 release.
- **Approval** is always per item, by the operator. No open set covers a
  promotion.
- **The write** uses `aos-promote`. The provenance lineage is the source
  lineage, with each element released to the target's reader compartments,
  plus `ceo` when the CEO reads the target. Grant and standing marks are
  dropped. It also carries `promotedFrom {runId, sha256}` and `approvedBy`.
- **Effect.** The target's readers hold the promoted data. They store none of
  its released elements, though their own compartment's elements stay
  storable as usual (store rule). A `security/code` finding promoted into
  `aos/security/shared` is released to warden, evaluator and comms-triage,
  and to the CEO, approved on its exact bytes.

### 2.9 Grants and overrides (D5, D6)

**Grants**

A grant lets one run read something its compartment cannot.

- **Requesting.** In v1, the CEO requests one with `kernel.request_access
  {compartment, what, reason}`.
  - The kernel logs `kernel.proposed` with the full arguments, and with the
    lineage of every deliverable or record `what` names, so the operator sees
    every compartment the bytes hold.
  - The operator approves it as a `HumanActor`.
  - The grantee is the requesting run, and the grant ends with that run.
  - Grants the operator issues to a named agent or objective, and
    revocation, are protocol v2 (§2.10).
- **What `what` may name.**
  - Deliverables of that compartment, delivered from the bytes the log holds.
  - Its pmmcp records.
  - Engineering files only as indexed records with `source_paths` (P9). The
    kernel fills `source_paths` from the grant, and pmmcp filters on it
    inside the query. Until P9 ships that, a file grant is refused, and only
    deliverables can carry file contents.
- **Reading.** The grantee reads with `kernel.read_grant {grantId, query?}`.
  The kernel performs the read with `callKernelOnly` under the owning
  compartment's principal. It renders the hits without provenance, as K11
  does. It adds `(owner, ∅)` and the delivered data's own lineage to the
  run, all grant-marked. It taints the run when any delivered hit is
  untrusted or tainted, or when a delivered deliverable's run finished
  tainted.
- **Nothing a grant delivers moves or is stored without a per-item approval.**
  - Only the grantee run holds a grant-marked element.
  - No child receives one, except through a parked delegation the operator
    approves on its full `delegation.parked` input. The child's copy then
    carries no mark, and the grantee keeps its own (§2.4, rule 1).
  - No open set covers one.
  - The store rule never passes one, so the grantee run cannot `remember`,
    and cannot adopt a plan.
  - Its outputs reach anyone else only through a parked delegation, a copy or
    a promotion the operator approves on its exact bytes.
- **D6's override** is this grant to the CEO, or a copy or promotion released
  to the CEO. In v1 the operator starts a grant by telling the CEO, in
  `run.start`'s input, to request it, and then approving.

**The standing D5 grant**

- `security/code` (security-reviewer, pentester) reads
  `aos/engineering/shared` and `aos/engineering/index/*`, read-only, through
  `aos-security-code` (P1), with `index:<repo>` labels (K2).
- Its findings stay in `aos/security/code/*`, and its briefs are kernel-filed
  and capped (§2.5).
- A finding reaches `aos/security/shared` only by promotion (§2.8). It reaches
  anyone else only by promotion or an approved copy.
- **The standing mark.** `security/code` holds natively, and may store, only
  the engineering elements its own D5 reads delivered (`standing:d5`, §2.4).
  An engineering element that reached it through a copy or an approved brief
  is held under that release and stored nowhere.
- D5 is about what `security/code` may hold, not what it may receive. A CEO
  brief that carries engineering lineage to a `security/code` child parks like
  any other (§2.4).

**Overrides (D5)**

The operator can overrule every security agent. No security agent can overrule
the operator.

- **In v1.** Security agents' blocks and vetoes do not exist in code yet. When
  they are built, each block on a tool call is a pending card. The operator
  resolves it with `approval.approve`, which logs `approval.resolved` and
  carries no reason. That is the whole v1 override.
  - `quarantine.release` is not an override of a security agent. Today it
    hands held output to the operator only (`src/policy/quarantine.ts:94-117`),
    and lets no held run continue.
- **From v2 (ask-before):**
  - `override.applied {by, target, reason}`, logged as its own event;
  - a fleet halt and resume;
  - an override of a security veto;
  - the rule that a security agent cannot raise the same block again on an
    action whose block the operator overrode.
- **Cutting the D5 grant.**
  - In v1, the operator kills any `security/code` run with `run.kill`, removes
    the grant from `kernel.yaml`, and restarts the daemon. The daemon reads its
    config only at boot.
  - At pmmcp, the operator removes `aos/engineering/shared` and
    `aos/engineering/index/` from `aos-security-code`'s read list and restarts
    pmmcp. Rotating that token instead would also cut `security/code` off from
    its own namespaces.
  - **What D5 already stored.** While D5 is off, the kernel stops treating
    `standing:d5` as native. It also fills `lineage_within` for every
    `security/code` read with every compartment except `engineering`, so
    the engineering data `security/code` stored under D5 stays unread.
  - From v2, one suspend command takes effect on the next call.
- **Widening a security run.** In v1 the operator edits the standing config
  grant, and the change stands until edited back. Widening one run needs an
  operator-issued grant, which is v2.

### 2.10 What protocol v1 covers

**Covered.** In each case the CEO files a kernel tool, which parks for a human
through a gate fact (§4).
- Before the card, the kernel logs a row holding the full bytes the approval
  binds: `kernel.proposed`, `delegation.parked` or `result.read.parked`.
- The card's argsHash binds that row's sha256.
- The operator reads the row with `events.query`, then answers with
  `approval.approve` or `approval.deny`.

The covered cases:

- opening an effort, with its members, open set and expiry;
- adding a member;
- a copy, with or without `ceoRelease`;
- a promotion;
- a grant request;
- a parked delegation;
- a parked result read.

**Not covered.** Each of these needs a protocol v2 command, which is
ask-before, with a version bump and a migration note:

- revoking a grant, an open set or an effort before its expiry;
- suspending D5 live;
- a grant the operator issues;
- an approval tied to no live run, such as a curator's promotion with no CEO
  run;
- choosing a different `ceoRelease` from the one the CEO filed;
- an override that records a reason;
- a fleet halt and resume;
- an override of a security veto;
- a UI filter by compartment.

**Until v2:**

- open sets and efforts expire;
- grants end with their run;
- D5 is cut by a config edit and a restart;
- an override is an approval with no reason recorded.

## 3. pmmcp changes

Each item has the change, why, an acceptance test, and the kernel impact. §6
gives the order they ship in.

### P1. One bearer token per principal

**Change**

pmmcp reads a principals file outside any repository, owned by the operator,
mode 0600. The real file spells out every compartment; `…` marks repetition
here.

```yaml
operator_token_file: "/Users/<op>/.config/pmmcp/operator.token"   # absolute; outside every repo and index root
index_roots:                                    # P9; the operator edits these
  aos/engineering/index/aos-kernel: {path: "/Users/<op>/src/MrRobot", trust: operator}
  aos/engineering/index/somelib:    {path: "/Users/<op>/src/vendor/somelib", trust: untrusted}
principals:
  # one per compartment, except: executive has two (aos-ceo for the agent
  # `ceo` alone, aos-executive for the rest), and marketing/clipping uses
  # aos-marketing. aos-trading reads aos/trading/, collab and fleet, and
  # writes aos/trading/agent/ and aos/trading/brief.
  - id: aos-engineering                 # becomes the token's client_id
    token_sha256: "<hex>"               # sha256 of the token; the token is never stored
    compartment: engineering
    read:  ["aos/engineering/", "aos/collab/", "aos/fleet/shared"]
    write: ["aos/engineering/agent/"]   # its brief is kernel-written (aos-brief)
    profile: sector-memory
  - id: aos-marketing                   # the open sub-section sits inside the prefix
    compartment: marketing
    read:  ["aos/marketing/", "aos/collab/", "aos/fleet/shared"]
    write: ["aos/marketing/agent/", "aos/marketing/brief",
            "aos/marketing/clipping/agent/", "aos/marketing/clipping/brief"]
    profile: sector-memory
  - id: aos-security                    # the sealed sub-section is NOT in its read list
    compartment: security
    read:  ["aos/security/agent/", "aos/security/shared", "aos/security/brief",
            "aos/collab/", "aos/fleet/shared"]
    write: ["aos/security/agent/", "aos/security/brief"]
    profile: sector-memory
  - id: aos-security-code               # D5: read-only into engineering
    compartment: security/code
    read:  ["aos/security/code/", "aos/engineering/shared", "aos/engineering/index/",
            "aos/collab/", "aos/fleet/shared"]
    write: ["aos/security/code/agent/"] # its brief is kernel-written (aos-brief)
    profile: sector-memory
  - id: aos-executive                   # every executive agent except `ceo`
    compartment: executive
    read:  ["aos/executive/agent/", "aos/executive/shared", "aos/fleet/shared"]
    write: ["aos/executive/agent/"]
    profile: sector-memory
  - id: aos-ceo                         # the agent `ceo` only
    compartment: executive
    collab_all: true                    # every effort, under the CEO hold rule (P2)
    read:  ["aos/executive/ceo", "aos/executive/shared",
            "aos/engineering/brief", "aos/marketing/brief", "aos/marketing/clipping/brief",
            "aos/trading/brief", "aos/security/brief", "aos/security/code/brief",
            "aos/marketing/shared", "aos/marketing/clipping/shared",
            "aos/trading/shared", "aos/security/shared",
            "aos/collab/", "aos/fleet/shared"]
    write: ["aos/executive/ceo"]
    profile: sector-memory
  # kernel-only principals
  - id: aos-goals
    read:  ["aos/executive/goals"]
    write: ["aos/executive/goals"]
    profile: goals
  - id: aos-goals-live                  # the gated live tests only
    read:  ["aos/executive/live-test"]
    write: ["aos/executive/live-test"]
    profile: goals
  - id: aos-promote                     # write-only
    read:  []
    write: ["aos/engineering/shared", "aos/marketing/shared", …every shared…, "aos/fleet/shared"]
    profile: write-only
  - id: aos-collab                      # write-only
    read:  []
    write: ["aos/collab/"]
    profile: write-only
  - id: aos-brief                       # write-only
    read:  []
    write: ["aos/engineering/brief", "aos/security/code/brief"]
    profile: write-only
  # the operator's own MCP clients (recommended, §8): never aos/
  - id: operator-clients
    token_sha256: "<hex>"
    own_projects: true
    profile: sector-memory
  # the operator's pmmcp CLI; never configured in any MCP client the kernel runs
  - id: operator
    token_sha256: "<hex>"
    all: true
    profile: all
```

**Startup checks.** pmmcp refuses to start when any of these holds:

- **The file itself.**
  - It lacks `operator_token_file`, or that value is not an absolute path.
  - An `index_roots` entry lacks `path` or `trust`.
- **Fields every entry must carry.**
  - An entry lacks `token_sha256` or `profile`.
  - An entry other than `operator` and `operator-clients` lacks `read` and
    `write`.
  - An entry names a profile not in P3's table.
- **Duplicates.** Two entries share an `id` or a `token_sha256`.
- **The operator.** An entry other than `operator` has `all: true` or
  `profile: all`, or `operator` lacks either.
- **`collab_all`.** More than one entry has it, or the one that has it is not
  `aos-ceo`.
- **Prefixes.** An entry other than `operator` and `operator-clients` has a
  prefix that does not start with `aos/`.
- **`operator-clients`.** It has `all`, `collab_all`, `compartment`, any
  prefix, or a profile other than `sector-memory`.

**Token check**

- A `TokenVerifier` hashes the presented token and compares it in constant
  time (`hmac.compare_digest`) with each entry.
- It returns `AccessToken(token=<the principal id, never the presented
  bearer>, client_id=<principal id>, scopes=[])`. `AccessToken.token` is a
  required field, and a tool can read it, so it must not hold the bearer.
- No match, or no token: HTTP 401 `invalid_token`. The body never echoes the
  token, and the server never logs it.
- The operator token's plaintext lives only in `operator_token_file`, owned by
  the operator, mode 0600. pmmcp's CLI reads it there. The server reads only
  the path, so that P9 can refuse a root that contains it.

**SDK configuration**

- Construct FastMCP (or MCPServer) with `token_verifier=<verifier>` and
  `auth=AuthSettings(issuer_url="http://127.0.0.1:8766",
  resource_server_url=None)`, with no `required_scopes`.
- `resource_server_url=None` is what stops the SDK publishing a metadata
  document. Also remove pmmcp's hand-built RFC 9728 document.
- **Other routes.** Remove every other custom route on 8766. P2 and P3 govern
  only `/mcp`. A route that must stay serves the `operator` principal only.
  Either:
  - wrap it in `RequireAuthMiddleware`, and answer 403 to any
    `request.user.access_token.client_id` other than `operator`; or
  - give only the operator's `AccessToken` the scope `operator`, and wrap the
    route in `RequireAuthMiddleware(app, required_scopes=["operator"])`.

  `RequireAuthMiddleware` with no scopes admits every principal (§1), so a
  route wrapped only in it would bypass P2 and P3.
- **Version pin.** Pin `mcp>=1.29.1,<2` while pmmcp imports
  `mcp.server.fastmcp`, or port it to `MCPServer` and pin `mcp>=2.3,<3`.
  - 1.27.2 adds the session-owner binding.
  - 1.29.1 adds the inlining of a root `$ref`, which P6 needs (§1).

**The other network surfaces**

- The dashboard on 127.0.0.1:8765 requires the operator token, or is
  disabled.
- Qdrant runs with `service.api_key` set and its ports published on 127.0.0.1
  only. Only pmmcp holds the key.
- Keep binding to 127.0.0.1, and keep the SDK's DNS-rebinding protection,
  which turns on by itself for a loopback host. It refuses a `Host:
  192.168.5.2` request with 421, but a client can forge `Host`, so the token
  is the wall.

**Why.** Without a credential, every compartment below is advisory. Any local
process, any future container that slips past the Phase 2 proxy, or any
kernel bug could read anything.

**Acceptance**

- **Tokens.**
  - No token gets 401.
  - A wrong token gets 401, and the token appears in neither the body nor the
    logs.
- **Routes.**
  - `/mcp` answers 401 without a token.
  - Every other route answers 401 without a token, and 403 with each
    kernel-held principal's token.
  - `GET /.well-known/oauth-protected-resource` answers 404.
- **Sessions.**
  - Each principal opens a session.
  - A session opened with one principal's token, then used with another's,
    gets 404 "Session not found".
- **Spoofing.** A call under the marketing token that carries
  `_meta.client_id: "operator"` or `"aos-engineering"` is still refused
  `aos/engineering/*`.
- **Other surfaces.** Requests without a token to 8765, and to Qdrant's REST
  and gRPC ports, are refused.
- **Startup.** pmmcp refuses to start on each of the startup checks above,
  including an `operator` entry without `token_sha256`.

**Kernel impact.** K3. The token name of each kernel-held principal enters
`.env` through `credentialNames`. The operator token's name appears nowhere in
this repository.

### P2. Server-side namespace enforcement

**Change**

- **Where the principal comes from.** It is the verified token of the
  current request: `get_access_token().client_id` (sound under P1's version
  pin), or the authenticated user on the current Starlette request. It is
  never `Context.client_id`, and never anything else in `_meta`.
- **Grammar first.** For every principal except `operator` and
  `operator-clients`, `project_id` must fullmatch one of these, or the call is
  refused with `namespace_denied`:

  ```
  ^aos/(executive|engineering|marketing|marketing/clipping|trading|security|security/code)/(agent/[a-z0-9][a-z0-9-]{0,63}|shared)$
  ^aos/(engineering|marketing|marketing/clipping|trading|security|security/code)/brief$
  ^aos/engineering/index/[a-z0-9][a-z0-9-]{0,63}$
  ^aos/executive/(ceo|goals|live-test)$
  ^aos/collab/[a-z0-9][a-z0-9-]{0,63}$
  ^aos/fleet/shared$
  ```

  - The id must be ASCII and is compared exactly as received.
  - The string that passed validation is used unchanged for the check, for
    storage, for the Qdrant filter and in SQL.
  - Match with Python's `re.fullmatch`, or end the pattern with `\Z`. Under
    `re.match`, `$` also matches before a final newline.
- **`operator-clients`.** For it, `project_id` must fullmatch
  `^[a-z0-9][a-z0-9/-]{0,127}$`, must not be `aos` or begin with `aos/`, and
  must contain no `//` and no trailing `/`. `own_projects: true` matches every
  such id, for reads and writes.
- **Read or write.** pmmcp classifies every tool as read or write. A read must
  match one of the principal's `read` prefixes, and a write one of its `write`
  prefixes.
  - A prefix ending in `/` matches everything under it.
  - Any other prefix must match exactly.
  - `all: true` matches everything, including an absent `project_id`.
- **A missing `project_id` is refused, never treated as global scope.** This
  holds for every principal except `operator`, on every tool that declares
  the argument.
- **Goal tools.** The project a goal tool touches is the project stored on the
  goal, and for `create_goal` also on its parent, whether or not the call
  names one. P2 can ship before P4 without refusing the kernel's goal moves,
  because K6a has already put every kernel goal into the goal namespaces.
- **The provenance argument.** P2 adds `provenance` to `remember`, with P7's
  model, and stores it with the record. Until P7 ships it is optional, and
  only the members and CEO rules below read it. P7 makes it required and adds
  its own checks. Until then, a record under `aos/collab/` with no
  `provenance.lineage` is never returned to `aos-ceo`.
- **Collaboration members.**
  - A read under `aos/collab/` returns a record only when the record's
    `provenance.members` include the principal's `compartment`.
  - `operator` gets every record.
  - A write under `aos/collab/` must carry `provenance.members` (non-empty,
    each a compartment that some principal in the principals file holds, never
    `executive`) and `provenance.source`. Otherwise it is refused with
    `invalid_provenance`.
- **The CEO's hold rule** (`collab_all`, §2.4). In every namespace it reads,
  `aos-ceo` gets no record that holds a lineage element whose `c` is
  `engineering` or `security/code` and whose `R` lacks `ceo`. Under
  `aos/collab/` it gets every other record, whatever its members.
  - The test is per element: one element's `ceo` never excuses another's.
  - In Qdrant this is a `must_not` holding a `nested` condition on
    `provenance.lineage`. Inside the nested condition, `must` matches `c` in
    `[engineering, security/code]`, and `must_not` matches `R` containing
    `ceo`.
  - A flattened filter over `lineage[].c` and `lineage[].R` is wrong, because
    Qdrant would match its conditions across different elements.
- **Operator writes into `aos/collab/`.** They obey the members rule like any
  other write. The operator copies through the kernel, or writes with explicit
  `members` and `source`.
- **Brief cap.** A write into `aos/engineering/brief` or
  `aos/security/code/brief` whose content exceeds 2,000 code points is refused
  with `content_too_long`.
- **Search filters inside the query.** It is a Qdrant `must` exact match on
  the validated `project_id`, plus the members and CEO rules above, plus P7's
  and P9's filters. Records whose `project_id` is null or different are never
  candidates. A query must not be able to rank or count results from another
  compartment. Timing is covered in §8.
- **Similarity work never mixes records.**
  - Deduplication on `remember`, related-memory links, consolidation and
    `repair_and_heal` compare records of one `project_id` only. Within that,
    they compare only records whose provenance is equal in every field except
    `runId`, `agentId` and `observedAt`, and whose `source_paths` and `commit`
    are equal or absent on both (P9).
  - Records whose `source_paths` differ are never merged, rewritten into one,
    or folded together. This holds for every principal, the operator included.
    A re-index replaces only the records of the same `source_paths`.
  - For every principal except `operator`, pmmcp never changes a stored
    record's `project_id`, content or provenance after the write.
  - Writes by `aos-promote`, `aos-collab` and `aos-brief` are never
    deduplicated, merged or rewritten. They stay the bytes the operator
    approved.
  - A hand merge by the operator follows P7's merge rule.
  - A recall hit's content is the text of one record only.
- **Order of checks.** Principal, then namespace, then existence, then
  everything else. An id-addressed object outside the principal's read set
  gets exactly the answer a nonexistent one gets (`goal_not_found`,
  `not_found`), and that answer does not repeat the id.
- **Record ids are random** (uuid4), never a global sequence.

**Why.** The kernel can be wrong, and pmmcp is the last wall.

**Acceptance**

With the marketing token:

- `recall(project_id: "aos/engineering/shared", …)` is refused.
- `recall` with no `project_id` is refused.
- `recall(project_id: "aos/marketing/shared", query: <a phrase stored only in
  engineering>)` returns zero hits.

For every sector principal:

- `remember` is refused into `aos/fleet/shared`, into any `shared`, under
  `aos/collab/`, into the engineering and `security/code` briefs, and into
  another compartment.
- With `aos-security-code`, `remember` into `aos/engineering/*` is refused.
- A `project_id` holding `..`, `//`, a trailing `/`, uppercase, U+0456, `%2F`,
  whitespace, NUL or a final newline is refused, each case on its own.

Isolation and answers:

- **Seeded memories reach only their readers**, under any query, in a sweep
  test:
  - one seeded in `aos/engineering/agent/<id>` appears only to
    `aos-engineering` and `operator`;
  - one seeded in `aos/engineering/shared` or `aos/engineering/index/x`
    appears only to `aos-engineering`, `aos-security-code` and `operator`;
  - one seeded in `aos/engineering/brief` with `ceo` in its `R` appears only
    to `aos-engineering`, `aos-ceo` and `operator`.
- **Collaboration records.**
  - One with members `[engineering, marketing]` and no coding lineage is
    returned to `aos-marketing` and `aos-ceo`, never to `aos-trading`.
  - One with engineering lineage and no `ceo` in `R` is never returned to
    `aos-ceo`. With `ceo` in `R` it is.
  - The CEO gets no mixed record:
    - one with lineage `[(engineering, {effort(e, M)}), (marketing, {ceo,
      effort(e, M)})]` is never returned to `aos-ceo`;
    - neither is one with `[(engineering, ∅), (engineering, {ceo})]`;
    - one with `[(engineering, {ceo, effort(e, M)}), (marketing,
      {effort(e, M)})]` is returned.
  - No collaboration record is returned to `aos-executive`.
  - An `aos-collab` write whose `members` include `executive` is refused.
- **Brief cap.** A 2,001-code-point `remember` into `aos/engineering/brief`
  from `aos-brief` is refused.
- **Similarity.**
  - Near-duplicate records whose provenance differs stay two records.
  - Two index records of different files with near-identical content stay
    two records after indexing, consolidation and `repair_and_heal`.
- **Not found.** An existing goal id in another project and a nonexistent goal
  id get byte-identical answers.

### P3. A tool profile per principal

**Change**

`tools/list` returns only the tools in the principal's profile, and **the call
path refuses every other tool**. Filtering the listing is not enough, because
FastMCP dispatches any registered tool by name (`lowlevel/server.py:482-496,
531-541`).

- **On v1**, a FastMCP subclass overrides `list_tools()` and `call_tool()`.
  Both are registered as bound methods (`fastmcp/server.py:318-329`). Each
  resolves the principal as P2 says.
- **On v2**, an MCPServer subclass overrides `list_tools()` and `call_tool()`,
  which `_handle_list_tools` and `_handle_call_tool` call. Do not raise a
  refusal from an override of `_handle_call_tool` itself, because it arrives as
  a JSON-RPC error with code 0 (§1).
- **No per-profile servers.** Do not serve one server per profile. The kernel
  has one URL per server, and a tool missing from a profile's server answers
  `Unknown tool`, not `tool_not_in_profile`.

| Profile | Tools |
|---|---|
| `goals` | `create_goal`, `update_goal`, `get_goal_tree`, `list_goals` |
| `sector-memory` | `recall`, `remember`; and `search` once it meets P6, P7 and P9 exactly as `recall` does |
| `write-only` | `remember` |
| `all` (operator only) | everything |

Every profile except `all` excludes:

- the secret and vault tools;
- `admin`, `restore_backup`, `delete_context_source` and `repair_and_heal`;
- `scrape_context`, which is pmmcp fetching the web around the Phase 2 proxy;
- `forget` (deletion is the operator's);
- `coding_agent` and `session_insight_agent` (nested LLM calls);
- `index_project` and `index_git_history` (P9).

**Resources and prompts.** For every principal except `operator`:

- `resources/list`, `resources/templates/list` and `prompts/list` return empty
  lists;
- `resources/read`, `prompts/get` and `completion/complete` are refused with
  `tool_not_in_profile`.

pmmcp may instead register no resources or prompts at all.

**Why**

- It removes whole classes of tools from what a kernel bug can reach. The
  kernel's `tool-views.yaml` stays the authority on what agents see; P3 is
  the server's floor under it.
- It shrinks the capture, the double and the drift surface for each principal.

**Acceptance**

- `tools/list` for each token matches its profile exactly.
- Each tool absent from a principal's listing, called by name with valid
  arguments, returns `tool_not_in_profile` and changes nothing.
- Resources and prompts behave as above.
- The operator token lists every tool (49–53 today). That check runs in
  pmmcp's own suite, not from this repository (§5).

**Kernel impact.** P3 permanently retires the kernel's dormant vault path
(`secrets.source: vault`), because no kernel principal can call `get_secret`.
Removing that path from `config.ts`, the broker and their tests deletes tests,
so it is ask-before. Until then `kernel.yaml` keeps `source: env`.

### P4. Goal tools take and enforce `project_id`

**Change**

- `update_goal`, `get_goal_tree` and `complete_goal` gain a **required**
  `project_id`. Each is refused with `goal_not_found`, exactly the answer a
  nonexistent goal id gets, unless the goal is stored in that project and the
  project passes P2.
- `create_goal` refuses a `parent_goal_id` stored outside the given project.

**Why.** Today any caller holding a goal id can read or move any project's
goal. The kernel guards against this only with its own `goal.created` log.

**Acceptance**

- Under `aos-goals`, `update_goal` on a goal stored in
  `aos/executive/live-test`, with `project_id: "aos/executive/goals"`, is
  refused and leaves the goal unchanged. Its answer is byte-identical to the
  one a nonexistent goal id with the same `project_id` gets. The same holds
  for `get_goal_tree`.
- Under `aos-goals`, the same calls on a goal outside its read set (created
  with the operator token in pmmcp's own suite) get that same answer.
- Under any sector token, every goal tool gets `tool_not_in_profile`. That is
  P3's check, not P4's.

**Kernel impact.** K6b, in three commits around this one (§6).

### P5. Real errors

**Change**

- **How a refusal is raised.** Every refusal is
  `raise ToolError(f"{code}: {message}")`.
- **What the client receives.**
  - Raised in a tool body, it reaches the client as one text block,
    `Error executing tool <tool>: <code>: <message>`, with `isError: true`.
  - Raised in an overridden `call_tool` before dispatch (v1
    `FastMCP.call_tool`, v2 `MCPServer.call_tool`), it arrives as
    `<code>: <message>`.
  - It is never raised from v2's `_handle_call_tool` (P3).
  - The kernel and the double both match
    `^(?:Error executing tool [a-z_]+: )?([a-z_]+): `.
- **Codes** are stable snake_case:
  - `goal_not_found`, `not_found`, `invalid_transition`, `invalid_status`,
    `parent_not_found`, `invalid_goal_type`, `progress_out_of_range`;
  - `namespace_denied`, `project_id_required`, `tool_not_in_profile`,
    `provenance_required`, `invalid_provenance`, `content_too_long`;
  - `internal_error`.
- **Argument errors.** A required argument that is missing or malformed is
  refused by the SDK, with pydantic's text and no code. The kernel treats an
  `isError` result without a code as `invalid_arguments`.
- **Unexpected exceptions.** Every tool body catches any exception other than
  `ToolError` and raises `ToolError("internal_error: see server log")`,
  because v1 forwards an exception's text to the client.
- **What a message may say.** A message never quotes a secret, another
  compartment's data, or the id a not-found call sent. Checks run in P2's
  order, so a refusal never reveals, for example, the status of another
  compartment's goal.
- **One v1 trap.** Do not return `CallToolResult(isError=True)` from a v1
  tool that declares an output schema (§1).

**Why.** Today a refusal is a success, so the kernel must parse prose to
notice it. A one-word reply such as `Unauthorized` would be read as a goal id
(`writer.ts:134`).

**Acceptance.** Every refusal string in `mock-pmmcp.ts` (`said`) has a P5 code,
arrives with `isError: true`, and matches the kernel's pattern in both wire
forms.

### P6. Structured output for the goal and memory tools

**Change**

- **The goal tools ship first** (§6 step 2): `create_goal`, `update_goal`,
  `get_goal_tree` and `list_goals` return typed Pydantic models.
  - `create_goal` and `update_goal` → `{goal_id, project_id, status,
    progress_pct}`.
  - `get_goal_tree` → `{goal_id, title, goal_type, status, progress_pct,
    children: [GoalNode]}`. `GoalNode` carries the same fields. The root is a
    separate, non-recursive model, and only `GoalNode` refers to itself.
- **The memory tools ship with P7** (§6 step 5): `recall`, `search` (if it
  exists) and `remember`.
  - `recall` and `search` → `{hits: [{id, project_id, content, provenance,
    source_paths?, commit?}]}`.
  - `remember` → `{id, project_id}` and nothing else. `id` names the record
    that holds the content after the call: the new record, or the existing
    record pmmcp deduplicated the write into under P2's rule. The reply
    carries no other record's id, and no content, provenance or count.
    `aos-promote`, `aos-collab` and `aos-brief` are never deduplicated, so a
    write-only principal's reply always names a new record and carries
    nothing read from storage.
- **The provenance model.**
  - Required on every hit: `writer`, `taint`, `origin`, `lineage` and
    `observedAt`.
  - Nullable: `runId`, `agentId` and `compartment`. `compartment` is null for a
    principal that has none.
  - Optional, present only when the record was written with them: `source`,
    `members`, `copiedBy`, `approvedBy`, `promotedFrom`, `briefOf` and
    `mergedFrom` (a list of ids, default `[]`).
  - A hit may have `provenance: null` for a record stored before P7. That
    happens only for `operator`, and for `operator-clients` within its own
    `project_id`s (P7).
- Every root is an **object**, which TS 1.30 requires. Wrap lists, and never
  make a self-referential model the root.
- Every datetime is timezone-aware (Pydantic `AwareDatetime`) and serializes
  with `Z` or an offset. `observedAt` is UTC.
- The serialized JSON is also returned as a text block.
- `tools/list` is one page. Neither FastMCP v1 nor v2 paginates it today (C:
  v1 `server.py:331-346`; v2 `server.py:427-430`).

**Why.** It replaces the kernel's prose parsing with validated data, and it
carries the provenance lineage needs (K11).

**Acceptance**

- **Schemas.** Each listed `outputSchema` has `type: object` at the root, not
  only a `$ref`. That includes `get_goal_tree`'s.
- **Validation.** The kernel's default `Client` (Ajv with ajv-formats)
  validates every result without throwing:
  - a goal carrying timestamps;
  - recall hits on an agent record, a filed brief, a collaboration copy, a
    promoted fleet record and an indexed record.
- **`remember`.**
  - A `remember` that pmmcp deduplicates returns exactly `{id, project_id}`
    with the existing record's id.
  - The same `remember` under a write-only principal returns a new id, and
    leaves the existing record unchanged.

**Kernel impact.** K8, K11.

- The hub keeps `structuredContent` on both paths.
- The writer reads `goal_id` from it rather than matching `✅ Goal created:`
  or `✅ Goal updated:`.

### P7. Provenance on every memory write

**Change**

- **Required provenance.** From every principal except `operator` and
  `operator-clients`, `remember` requires `provenance {runId, agentId, taint,
  origin: operator|agent|untrusted|system, lineage: [{c, R, mark?}],
  observedAt}`. Without it, the call is refused with `provenance_required`.
  - `R` holds three kinds of entry: compartment names, `ceo`, and
    `{effort, members}` entries.
  - `mark` is `standing:d5` or absent. Grant marks are never stored (§2.4).
  - pmmcp stores these as given, and filters on them as P2 and the read
    filters below say.
- **Extra fields for kernel writes.**
  - `aos-collab` writes add `source`, `members`, `copiedBy` and `approvedBy`
    (§2.7).
  - `aos-promote` writes add `promotedFrom` and `approvedBy` (§2.8).
  - `aos-brief` writes add `briefOf {runId}`.
- **Server stamps.** pmmcp stamps `writer` (the principal id) and
  `compartment` itself, server side, and ignores any value a call sends for
  them. For a principal with no compartment, `compartment` is null.
- **Lineage check.** pmmcp refuses with `invalid_provenance`:
  - an empty `lineage`;
  - an element whose `c` is not one of `executive`, `engineering`,
    `marketing`, `trading`, `security` and `security/code`. The kernel always
    sends the open sub-section as `marketing`;
  - when the writer has a compartment, a `lineage` that does not name it
    (`marketing` for `aos-marketing`);
  - for `aos-collab`, a `lineage` that does not name `source.compartment`;
  - a `standing:d5` mark from any writer but `aos-security-code`, or on an
    element whose `c` is not `engineering`.
- **Records no agent wrote.** pmmcp stamps the provenance itself, and ignores
  any value sent, on every record the `operator` or `operator-clients`
  principal stores, except a merge. That includes everything `index_project`
  and `index_git_history` store. The stamp is `{runId: null, agentId: null,
  origin, taint, lineage: [{c, R: []}], observedAt}`:
  - **origin and taint.** `origin: operator, taint: false`, except a record
    indexed from a root whose `trust` is `untrusted` (P9). That record is
    `origin: untrusted, taint: true`.
  - **`c`** is the compartment the namespace names, folded as the kernel
    folds it.
    - `aos/engineering/index/…` names `engineering`.
    - `aos/marketing/clipping/…` names `marketing`.
    - For `aos/fleet/shared`, which names none, `c` is `executive`, because
      the operator chose to put the record there.
    - An operator write under `aos/collab/` carries explicit provenance
      instead (P2).
    - For an `operator-clients` project, the lineage is `[]`, and no kernel
      principal can read it.
- **Hand merges.** A merge the operator runs is a pmmcp operation that names
  the ids of the records it replaces, all in one `project_id`. It is never a
  `remember` of combined text. Its provenance is:
  - the union of the inputs' lineages;
  - `taint: true` and `origin: untrusted` if any input has them;
  - the intersection of the inputs' `members`;
  - `mergedFrom`: every input id, plus every id in the inputs' own
    `mergedFrom`;
  - the inputs' `source_paths`, which P2 requires to be equal.

  pmmcp cannot tell where an operator's own `remember` text came from. Text
  the operator copies by hand, outside the merge operation, is stamped as
  fresh operator data. That is the operator's own act (§8).
- **No provenance, no hit.** A record with no provenance, such as one stored
  before P7, is never returned to a principal other than `operator`. The
  exception is `operator-clients`, for a `project_id` that passes its grammar.
- **Untrusted text is excluded by default.** For every principal except
  `operator`, a memory read leaves out hits whose origin is `untrusted` or
  whose taint is `true` (`must_not`), unless the call passes
  `include_untrusted: true`.
- **`lineage_within: [compartments]`.** When given, a memory read returns only
  hits whose every lineage element has its `c` in the list.
- **Filters are part of the query.** All of these filters are part of P2's
  query filter, never applied to hits afterwards.
- **What a hit returns.** Each hit returns its provenance.
- **Who fills what.** The kernel fills every provenance field,
  `include_untrusted`, `lineage_within` and `source_paths`. The model sees none
  of them, neither in its tool schema (K2) nor in a result (K11).

**Why**

- The designs' rule is that a clean run never recalls untrusted text
  (AF:486-491). That rule needs a field pmmcp can filter on, and today it is
  NEEDS VALIDATION (DECISIONS Q24).
- Lineage (§2.4) needs a carrier that survives between runs.

**Acceptance**

- **Untrusted text.**
  - An untrusted or tainted memory never appears in a read without
    `include_untrusted`, under any query.
  - A clean record and a tainted near-duplicate in one project stay two
    records.
  - An index record from a `trust: untrusted` root never appears without
    `include_untrusted`. One from a `trust: operator` root does.
- **Lineage.**
  - Near-duplicates with lineage `[executive, engineering]` and `[executive]`
    never come back as one hit carrying `[executive]`.
  - An operator hand merge of such records stores the union and a
    `mergedFrom` holding both ids. A read with `lineage_within: [executive]`
    does not return it.
  - A read with `lineage_within: [executive]` returns no record whose lineage
    names another compartment.
- **Server stamps.**
  - A call under the marketing token that claims `compartment: engineering` is
    stored as marketing.
  - Under the marketing token, a `remember` into
    `aos/marketing/clipping/agent/producer` with lineage `[{c: marketing}]` is
    stored. With lineage `[{c: engineering}]`, or with an empty lineage, it is
    refused.
- **Missing provenance.**
  - A record stored without provenance never appears in a non-operator read.
  - An index record recalled under `aos-security-code` carries lineage
    `[{c: engineering}]`.
- **`search`.** Each check above is repeated with `search` when pmmcp serves
  it.

### P8. Protocol era

- pmmcp keeps serving 2025-11-25 Streamable HTTP while the kernel is on TS SDK
  1.30.
- **On 2025-11-25**, P2's principal relies on the SDK's session-owner binding
  (`mcp>=1.27.2`; P1 pins 1.29.1 for P6). P1's cross-token 404 test is what
  keeps that safe, so it stays in pmmcp's suite. The alternative is
  `stateless_http=True`, which checks the token on every request.
- **On 2026-07-28** there are no sessions, and the token is checked on every
  request.
- Moving the kernel to a 2026-07-28 client is a new dependency
  (`@modelcontextprotocol/client`) and needs the operator's approval.

### P9. Indexing is the operator's

**Change**

- `index_project` and `index_git_history` are operator-only (profile `all`).
- **Roots.** Sources come from the principals file's `index_roots` map,
  `aos/engineering/index/<repo>` → `{path, trust}`, and never from a tool
  argument.
  - `trust` is required: `operator` only for a root whose files and commits
    the operator wrote or merged, and `untrusted` for a third-party repository,
    a vendored dependency or a fork.
  - An untrusted root's records are stamped untrusted (P7), so only an
    already-tainted run reads them.
- **Resolving a root.** pmmcp resolves each root once with `realpath`. It
  refuses a root in any of these cases:
  - it is `$HOME` or an ancestor of `$HOME`;
  - it is, contains or lies inside pmmcp's own storage, the principals file's
    directory, or `operator_token_file`;
  - it is, or lies inside, a `.aos/` directory, matched case-insensitively.

  A root that *contains* a `.aos/` directory, such as the kernel's own
  checkout, is accepted, and the walk skips that directory. Every other root
  is accepted, whether or not it lies under `$HOME`.
- **The walk.**
  - It uses `os.fwalk(root, follow_symlinks=False)`, and enters a subdirectory
    only after `samestat` confirms that the opened directory is the one it
    `lstat`ed. A directory swapped for a symlink during the walk is not
    entered.
  - Each file is opened relative to its directory's descriptor, with
    `os.open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, dir_fd=<fd>)`.
  - After opening, `fstat` must show a regular file with `st_nlink == 1`,
    whose `(st_dev, st_ino)` is not a forbidden file's; otherwise the file is
    skipped. A hard link can name a file outside the root without being a
    symlink.
- **Forbidden within an accepted root.** The walk skips each of these and
  never reads one. They are compared by device and inode as well as by
  spelling, because APFS is case-insensitive:
  - any `.aos/` directory;
  - any `.env*` file, matched case-insensitively;
  - the principals file's directory and `operator_token_file`;
  - pmmcp's own storage: its SQLite files with their `-wal` and `-shm`,
    Qdrant's storage and snapshot directories, and every backup directory;
  - files matching credential patterns.

  Today's default ignore list skips only an exact `.env` (README.md:142-145).
- **History obeys the same exclusions.** `index_git_history` applies the
  forbidden list to every path a commit touches. It compares each path
  relative to the root, case-insensitively, as the commit records it.
  - It stores no record for a path the walk would skip, nor for a rename or
    copy whose source or destination is such a path.
  - It applies the walk's credential patterns to each hunk and to the commit
    message, and stores no record that matches one.
  - Deleted files and removed lines count. History keeps what the working tree
    no longer shows.
- **`source_paths`.** Every index record stores `source_paths`, a non-empty
  list of paths relative to its root.
  - A file record stores its one path.
  - A git-history record also stores `commit`, and pmmcp splits a commit into
    one record per touched file: that file's hunks plus the commit message,
    with that one path.
  - A memory read returns `source_paths`, and `commit` when it is set, in each
    hit.
  - It accepts `source_paths: [...]`. When that is given, it returns only
    records that store at least one path and whose every stored path is in
    the list, filtered inside the query. In Qdrant that is `must_not:
    is_empty(source_paths)` plus `must_not` on any stored path outside the
    list.

**Why**

- An index tool reads the disk, and P2 constrains only where the index lands.
  If the kernel could call one, it could pull any directory, another
  compartment's export or a credential into engineering.
- The content of a root comes from more people than the operator: an agent's
  merged change, or a third-party repository. A committed symlink, a hard
  link or a swapped directory must not pull in a file outside the root, and
  third-party text must stay untrusted.

**Acceptance**

- **Links and swaps.** A root holding any of the following indexes none of
  them, and the walk terminates:
  - a symlink named `notes.md` that points to a `.env` file;
  - a relative symlink to a file outside the root;
  - a symlinked directory that points to the root's own parent;
  - a directory replaced by a symlink after the walk lists it;
  - a hard link to a file outside the root;
  - a symlink to pmmcp's database.
- **Roots.**
  - A root that is `$HOME` or its parent is refused.
  - A root that contains pmmcp's storage, the principals file or the operator
    token file is refused. A root that lies inside a `.aos/` directory is
    refused. The kernel's checkout, which contains `.aos/`, is accepted, and
    nothing under its `.aos/` is indexed.
  - A repository whose history once added `.env.local` holding a value, and
    later deleted it, indexes no record naming `.env.local` and no record
    holding that value.
  - A root outside `$HOME` that commits `.env.example` is accepted, and that
    file is not indexed.
- **`source_paths`.**
  - A read with `source_paths: [a]` returns no hit from any other file.
  - It returns no git-history record carrying a change to another file.

**Kernel impact.** The kernel never calls these tools, and `tool-views.yaml`
keeps them kernel-only (invariant 7 names `index_project`). File grants
(§2.9) depend on `source_paths`.

## 4. Kernel changes

Each item has its acceptance test. Rules that apply to all of them:

- **Session protocol.** One task, one test, one commit.
- **Gate facts.** Every access decision the kernel makes on a tool call is
  computed before `decide()` and reaches the pure gate as a fact. The model
  never sets one.
  - **The decisions:** reserved arguments, delegation and result-read fits,
    copy coverage, the store rule, `human: always`.
  - **The inputs:** the log, the run scope and, for a kernel tool, the
    kernel's own state for that run (such as the adopted plan) in the tool's
    prepare step (K5).
  - **Order.** A fact that denies is checked before the needs-human rules
    (4 and 5). A fact that parks is checked after rule 5, so a tainted run
    always needs a human.
  - **Logging.** Every outcome is a `tool.gate` row.
  - **Change control.** Each new fact is a gate change, so it is ask-before,
    and ships with a falsify mutant.
- **Mutation coverage.** Each K commit updates `scripts/falsify/catalog.ts` in
  the same commit, with at least one mutant per new refusal or fact. Several
  items touch anchored lines:
  - K1: `kernel.ts` (N6);
  - K2: `gate.ts` (N1–N3);
  - K6b and K8: `writer.ts:119, 335` (G13, G15).
- **Changed or deleted tests (ask-before).** Each K commit lists every test
  assertion it changes or deletes. Known now:
  - K1 and K2 change `policy-namespace.test.ts`. A model-sent `project_id`
    becomes a denial, and an absent one becomes a fill.
  - K1 and K2 change the registry tests that pin `MEMORY_PROJECT`.
  - K3 changes the credential-name patterns in `test/helpers/guard.ts` and
    `scripts/falsify/runner.ts`, which `falsify.test.ts:481` pins equal.
  - K8 deletes from `pmmcp-drift.test.ts`:
    - the keyArg test (`:128-146`);
    - the keyArg, pinned-name and tool-count assertions (`:109-111`, `:125`);
    - the no-capture block's `get_secret` and 49-tool claims (`:73-85`).
  - K8 changes the tests and headers that list `.env` readers and `--dotenv`
    scripts (`hygiene.test.ts`, `entrypoints.test.ts`).
- **Old rows.** The operator's log is permanent, every payload schema is
  strict, and boot re-parses stored rows (§1).
  - **Versioning.** A field that a K item adds to an existing payload is added
    by a new schema version (`schemaVersion: 2`), never by editing v1. The
    kernel appends only v2.
  - **Re-parsing.** Code that re-parses stored rows parses the union of v1 and
    v2. That code is the tracker, `eval/observe.ts` and `eval/checks.ts`.
  - **What a v1 row means.**
    - It has no compartment. Its lineage is unknown, and every lineage check
      treats unknown as failing.
    - The one exception is a v1 `goal.created` row. `kernel.read_goals`
      returns that goal without its title, adding nothing (§2.4).
  - **Optional v1 fields** need no new version: `principal` on `hub.*`, and
    `projectId` on `tool.gate` and `tool.call`.
  - **Approvals.** Pending approvals do not survive a restart (§1), so no
    approval field needs restoring.
  - **Acceptance.** Each such item boots once over a fixture log written by
    the commit before it, then passes `verifyChain`.
- **Ask-before for reach and approvals.** Each of these is ask-before:
  - widenings: delegation to templates, and any kernel tool offered to
    workers;
  - each new gate fact;
  - a path that lets a call proceed without a human because of an earlier
    decision, such as an open set (K9).
- **Exposure.** Exposing any pmmcp tool to an agent, or a new kernel tool to
  the CEO, is a `tool-views.yaml` exposure change, so it is ask-before. This
  contract is what makes such changes safe to propose.

| # | Change | Acceptance test |
|---|---|---|
| K1 | **Compartments, profiles and derived namespaces.** **Manifests:** a standard agent declares `compartment`. A template declares `profiles` (each with exactly one `compartment` and its own `tools.allow`) and has no memory block. A manifest may set `filesBrief` (§2.5). **Namespaces:** `memory.projectId` is derived, never declared: `aos/<c>/agent/<id>`, or `aos/executive/ceo` for the agent whose id is `ceo`. `MEMORY_PROJECT` becomes the §2.2 grammar. **The registry refuses:** a template without profiles; a profile without exactly one compartment; `schedule:` on a template; a child whose profile is not in its template; a manifest with id `ceo` that is not an `executive` orchestrator; and `filesBrief` outside engineering and `security/code`. **Fleet and eval:** curators become standard agents per compartment. The shipped fleet takes its §2.1 places, with manifest version bumps and history frozen. liveFleet's live-ceo declares `compartment: executive`. `ceo-objective-fanout` is rewritten in marketing terms. | `agents-registry.test.ts`: a manifest that declares `memory.projectId` fails to load; a template without profiles fails; a plan naming bare `scout` with two profiles is refused; a scheduled template fails; the four shipped manifests load with their compartments; derived namespaces are unique. |
| K2 | **The kernel sets `project_id`.** **Schema:** the model's schema for a pmmcp memory tool loses the reserved arguments: `project_id`, `provenance`, `include_untrusted`, `lineage_within` and `source_paths`. **Scope labels:** in their place a read gets a kernel enum, `scope`. The loop computes it on every turn from the run's scope, and each label maps to exactly one `project_id`. This commit builds the mechanism with these labels: `own`; `shared:<c>` and `brief:<c>` for each such namespace in the agent's read set; `index:<repo>` for engineering and `security/code`, for each repo in `mcp.servers.pmmcp.indexRepos` (kernel.yaml, kept by the operator in step with pmmcp's `index_roots`); `agent:<id>` for a curator's compartment; and `fleet`. K9 adds `effort:<id>`, and K11 adds the CEO's `own:<c>` and `own:all`. A write takes `scope: own`, or `brief:<own compartment>` for marketing, trading and security agents. **Filling:** in `RunLoop.#handleToolCall`, before the gate input is built, the kernel records which reserved names the model sent (`reservedArgs`, a deny fact). It then maps the label and fills every reserved argument into the arguments the gate hashes and the hub sends. `include_untrusted` is true only for a run that is already tainted. **Gate:** rule 3b checks the filled `project_id` against `ScopeInput.projectIds`, the set the label map allows for this call, rather than the one `projectId`. The hub never adds or rewrites an argument. `namespaceArg: none` is refused for any tool whose live schema declares `project_id`. **`human: always`:** this commit adds it as a view fact. It is used by K9 (`open_effort`, `add_member`), K10 (`request_access`) and K13 (`promote`). K5's delegation and result reads park through their own facts. | `policy-namespace.test.ts`: a model-sent `project_id` writes a `tool.gate` deny row, even the agent's own, and even in a tainted run; `scope: shared:marketing` reaches the double as `aos/marketing/shared`; the CEO's `brief:trading` reaches it as `aos/trading/brief`; a reviewer's `index:aos-kernel` reaches `aos/engineering/index/aos-kernel`; an engineering agent has no `brief` scope; a write naming a read scope is denied; the hub refuses when `project_id` changed after the ticket; a clean run's recall never carries `include_untrusted`. |
| K3 | **One pmmcp client per principal.** **Binding:** `kernel.yaml` binds each kernel-held principal to what may use it (`mcp.servers.pmmcp.principals.<id>: {tokenEnv, compartments, agents?}`). An entry that names an agent wins over one that names its compartment: `aos-ceo` serves the agent `ceo` alone, and `aos-executive` every other executive agent. `aos-marketing` serves both `marketing` and `marketing/clipping`, and each other sector principal its own compartment. The kernel-only principals serve no agent. Boot refuses a config in which a registered agent or a profile resolves to zero principals or to more than one. `aos-goals-live` is declared only in the live tests' config. `RunAgent` and `RunScope` gain `compartment` and `principal`, and K7 adds the event fields they need. **Token names:** every principal's `tokenEnv` matches `^PMMCP_TOKEN_[A-Z0-9_]+$`, and config refuses one that does not. The same commit widens the credential-name patterns in `test/helpers/guard.ts` and `scripts/falsify/runner.ts` to `^PMMCP_TOKEN(_[A-Z0-9_]+)?$`, keeping them equal. It also adds the names to README's credential list. **Calls:** the hub keys clients by (serverId, principal). The loop runs the hub branch of the execute step inside `#inScope`. The kernel-tool branch stays outside, because `kernel.delegate` appends the child's `run.queued`. The hub refuses an agent call when `runScope()` is undefined, when `ticket.runId` differs from the scope's, when the principal is not bound to the scope's agent and compartment, or when the principal is kernel-only. `callKernelOnly`, `describe` and `status` take an explicit principal: the goal writer uses `aos-goals`, and grant reads the owning principal. **Profiles:** at connect, each client's `tools/list` is compared with its P3 profile, and any difference is recorded in `hub.tools.classified{principal}`. The check that degrades lands in its own commit, with P3 (§6). **Failures:** a declared `tokenEnv` that is unset degrades that principal by name, and boot goes on. A 401 degrades it by name and never retries the same token. Fix the stuck-degraded hub, and retry when pmmcp is down at boot. **Live tests:** `test/helpers/live-env.ts` and the live tests move from `PMMCP_TOKEN` to per-principal token names, and their hand-built hubs get the binding. | `mcp-hub.test.ts`: two runs of different compartments in parallel each reach the double under their own principal; the CEO resolves to `aos-ceo` only, and the planner's recall goes out under `aos-executive` and is refused `aos/marketing/brief`; an agent call outside a run scope, or with another run's ticket, is refused; `kernel.delegate` still starts its child; a boot with one principal's token unset degrades only that principal; an offline test process started with every principal's token in its environment has none after the guard loads, and `childEnv` drops each; a config whose `tokenEnv` is `AOS_PMMCP_CEO` is refused. |
| K4 | **Compartments per tool.** `tool-views.yaml` gains `compartments: [...]` on every agent-exposed tool. It is required: an exposed tool without it fails to parse, and there is no default. `tools.servers` is enforced for MCP servers, and the `kernel` server is exempt. The CEO's kernel tools get `compartments: [executive]`: `adopt_plan`, `delegate`, `read_result`, `read_goals`, `open_effort`, `add_member`, `copy_to_collab`, `promote`, `request_access` and `read_grant`. A template profile whose `allow` holds a tool not permitted in its compartment fails to load, and the check runs again when a child is bound. Changing any exposure is ask-before. | `config-files.test.ts`: an engineering-only tool in a marketing agent's `allow` fails to load; an exposed tool without `compartments` fails to parse; the shipped CEO loads; a marketing profile with an engineering tool fails. |
| K5 | **Delegation, results and the prepare step.** **Prepare step:** `KernelToolHandler` gains an optional `prepare(args, ctx)`. `RunLoop.#handleToolCall` first calls the pure `decide()` on the model's arguments. If that denies, or the agent is not an orchestrator, the call is denied with its `tool.gate` row, and `prepare` never runs. Otherwise `prepare` runs. Its returned arguments replace `context.args`, the gate input is built from them, and the runner re-checks the ticket against them. **Delegation:** `Delegation.prepare` first applies every refusal `#delegate` makes (`delegate.ts:229-297`). A refused call logs `delegation.refused` and reaches the gate as a deny fact, so no card is raised for a delegation that cannot run. It then resolves the task (by its kernel handle), the target and the target's compartment from the adopted plan, and builds the child's input as `#delegate` does. It computes `delegationFits` (§2.4 rule 1). When that fact fails, it logs `delegation.parked {parentRunId, taskHandle, target, targetCompartment, lineage, childInput}` before the card. The handler launches the child with the input `prepare` built. Approval releases the failing elements to the child's copy only, and drops grant marks there. **Child compartment and taint:** a child's compartment comes from its manifest or its profile (§2.5). Taint is inherited, and a tainted child taints its parent through `kernel.delegate`. **Results:** every finished run logs `run.deliverable` and `run.result` (§2.5), the latter with its final taint and lineage. `kernel.delegate` returns the typed fields only. `kernel.read_result {runId, part: summary\|deliverable}` computes `resultReadFits` in its prepare step from the run's logged lineage. It applies the D6 channel only to `part: summary` of an engineering or `security/code` run, and only to the copy that joins the CEO's run. When the fact fails it logs `result.read.parked {runId, part, failing}` before the card. It taints the CEO when the run finished tainted. **Briefs:** at `run.finished` of an engineering or `security/code` run whose manifest sets `filesBrief: true`, the kernel files the summary with `aos-brief`, adding `ceo` to the brief record's natively held elements, then applying the store rule. Otherwise it logs `brief.withheld`. **Plans:** `goals.adoptFromRuns` skips a run that finished tainted. **Kernel-started runs** follow the same receive rule, and are withheld with `start.withheld` (§2.4). Milestone judges follow §2.5. Delegating to templates is ask-before. | `delegation.test.ts`: a tainted parent's child starts tainted; a tainted child taints its parent; `kernel.delegate`'s result holds no model-written string, not even a provider error's text; a refused delegation raises no card; an engineering child whose deliverable, failureHistory or error text holds a seeded phrase leaves no trace of it in the CEO's context until `read_result {part: summary}`, which adds engineering with `ceo` for a phrase in the first 2,000 code points; `read_result {part: deliverable}` of that child parks before the summary read, after it, and after its brief is filed, and the child's logged lineage never gains `ceo`; a CEO run that read typed results only delegates to marketing with no human; one that read a marketing brief and a trading brief parks a brief to either; after an engineering summary read, a brief to a marketing child, a `security/code` child or the assistant parks (template children are tested when template delegation ships); `delegation.parked` precedes `approval.requested`, and its `childInput` is byte-identical to the child's input, with a seeded phrase in the last 100 characters included; approving it leaves the parent's lineage unchanged; a CEO `read_result` of a tainted researcher's deliverable taints the CEO; an eng-lead summary lands in `aos/engineering/brief` through `aos-brief`, with `ceo` in its record's `R`. |
| K6a | **The goals' namespace**, with K1. `goals.projectId` in `kernel.yaml` (default `aos/executive/goals`). `delegate.ts:185, 203`, `kernel.ts:476` and `tracker.ts:203` use it, never an agent's namespace. The writer sends only the §2.6 fields. Until K3 it uses today's single client. `test/helpers/runtime-bodies.ts` exports `liveKernelYaml(base)`, which sets `goals.projectId: aos/executive/live-test`, and splits its constant into `LIVE_TEST_GOALS` (`aos/executive/live-test`) and `liveTestMemory(c)` (`aos/<c>/agent/aos-live-test`). `runtime-bodies.test.ts` and `live-runtime.test.ts` build their config through `liveKernelYaml`. K3 binds the live writer to `aos-goals-live`. | `goals-writer.test.ts`: every `goal.created` row from a CEO plan carries `aos/executive/goals`; no adoption path passes an agent's namespace to `materialise`; a `runtime-bodies.test.ts` boot through `liveKernelYaml` writes every goal to `aos/executive/live-test`. |
| K6b | **Goals under P4**, in three commits around P4 (§6). **(1)** The writer sends `project_id` to update and tree calls when the tool's live schema declares it, and keeps the owner check either way. **(2)** P4 ships in pmmcp. **(3)** `requiredArgs` adds `projectId` to `updateStatus` and `get`, so a pmmcp without P4 degrades goals at boot, by name. Goal lineage is K11's. | `goals-writer.test.ts` against the pre-P4 and the P4 double after commit (1); after commit (3), a pre-P4 double degrades goals with a reason naming `update_goal`'s missing `project_id`. |
| K7 | **Events.** All of these follow the old-rows rule. **Run and gate events:** `compartment` and `principal` on `run.queued`, `run.started`, `tool.gate`, `agent.registered` and `delegation.admitted`. `tool.gate` and `tool.call` carry the `projectId` the kernel filled. `run.finished` (v2) carries the final taint. **Hub events:** an optional `principal` on `hub.connected`, `hub.degraded` and `hub.tools.classified`. **Lineage:** `run.result`, `goal.created` (v2), the delegation events, `approval.requested` and the hold event carry it, and `tool.result` carries `lineageAdded`. **New events:** `run.result`, `run.deliverable`, `kernel.proposed`, `delegation.parked`, `delegation.refused`, `result.read.parked`, `start.withheld`, `brief.withheld`, `judge.skipped`, `effort.opened`, `effort.member.added` and `effort.ended`. Each is bounded under `MAX_LOGGED_OUTPUT`: a brief is at most 8,000 characters, a copy as §2.7 says, and a lineage holds at most one element per compartment and release entry. **Status:** `status.get` keeps its one `hub` key. It is degraded when any principal is, with a reason that names them, so protocol v1 holds. | `events-types.test.ts`; a booted kernel whose marketing token is refused emits `hub.degraded{principal: aos-marketing}`, and `status.get` names it; an allowed recall's `tool.gate` row names `aos/marketing/agent/writer`; a boot over a pre-K7 log succeeds. |
| K8 | **The double and the drift guard.** **The double** models: principals (read, write, compartment, members, `collab_all`, and the CEO's hold filter per lineage element); profiles enforced at dispatch; the grammar; the brief cap; `isError` codes in both wire forms; structured output; provenance stamping; the operator stamp with index `trust`; hand merges; standing marks; the untrusted default; `lineage_within`; and `source_paths`. **Capture:** `capture:pmmcp` passes `--dotenv .env` and reads each kernel-held principal's token with `oneCredential`, as `scripts/eval.ts` does. It writes one fixture per principal (`test/fixtures/pmmcp-listtools.<principal>.json`), with `outputSchema` and the resource and prompt lists. `compareCapture` checks each fixture against its P3 profile. The deleted drift assertions (§4 rules) move to a capture the operator takes with pmmcp's own tooling. No script here reads the operator token. CLAUDE.md, README, `hygiene.test.ts`, `entrypoints.test.ts` and the contract headers that list `.env` readers and `--dotenv` scripts add the capture script. **Structured content:** `callKernelOnly` returns `structuredContent`, and `McpHub.call` keeps it for K11. **Writer:** it first accepts both the P6 result and today's prose, for create and for update; a later commit removes the prose. | `mcp-pmmcp-double.test.ts`, `pmmcp-drift.test.ts`, `hygiene.test.ts`, `entrypoints.test.ts`. |
| K9 | **Collaboration efforts and copies** (§2.7). **Tools:** `kernel.open_effort`, `kernel.add_member` and `kernel.copy_to_collab` are CEO kernel tools; the first two carry `human: always`. `kernel.open_effort` refuses an effort id that any `effort.opened` row has used. **Prepare:** K9's tools use K5's prepare step. A model-supplied `sha256` is also denied. For a copy, `prepare` resolves the source and refuses what §2.7 refuses. It then logs `kernel.proposed` with the full arguments, bytes and readers, and returns the arguments with `sha256` added. The same step logs `kernel.proposed` for every `human: always` kernel tool. **Coverage:** whether a copy needs a fresh approval is the `copyCovered` fact (§2.7, Coverage). **Write:** it uses `aos-collab` with the §2.7 provenance. Each release entry records the member set at the time of the copy. The kernel keeps only `{id, project_id}` from the reply. **Projection:** efforts (members, open set, expiry) are projected from the `effort.*` events. Their `effort:` labels join K2's scope, and they feed the effort clauses of hold, receive and coverage. Before K9, no effort is live, so those clauses never hold. | `collab.test.ts`: without approval nothing is written; a copy at the §2.7 size limit, holding newlines and quotes and ending in a seeded phrase, is in `kernel.proposed` in full before approval and lands byte-identical; one escaped byte more is refused, logging only its `tool.gate` row; a worker's or an unlisted caller's call resolves nothing; a copy from a tainted run lands `untrusted`; a CEO copy whose lineage holds engineering, released or not, is approved per copy, even with marketing in the open set; a copy whose source holds `(trading, {marketing})`, into an effort with only marketing open, parks; a copy of `(executive)` and `(marketing)` data into an effort with marketing open is covered; a tainted CEO run's otherwise covered copy parks; a member that recalled a copy has its `remember` denied; after `add_member` the new member neither holds nor receives an earlier copy; reopening an ended effort's id is refused; after expiry the copy no longer counts for hold. |
| K10 | **Grants and overrides** (§2.9). `kernel.request_access` carries `human: always`. Its `kernel.proposed` row shows the lineage of what `what` names. The grantee is the requesting run, for that run. `kernel.read_grant` reads with `callKernelOnly` under the owning principal and renders hits without provenance. It adds `(owner, ∅)` and the delivered data's own lineage, all grant-marked, and taints the run when delivered data is untrusted or tainted. Grant-marked elements are held by the grantee run only. No child receives one except through an approved parked delegation, which drops the mark on the child's copy. No open set covers one, and no store rule passes one. A plan adoption from a run holding one is refused. A file grant is refused until P9's `source_paths` ships, and then the kernel fills `source_paths`. The D5 grant lives in config (`grants: [{compartment: security/code, reads: [aos/engineering/shared, aos/engineering/index/*]}]`), read at boot. While it is off, the kernel fills `lineage_within` without `engineering` for every `security/code` read. In v1, overrides are approvals (§2.9). The v2 commands (§2.10) are ask-before, and ship after the operator approves the bump. | `grants.test.ts`: a grant read happens only after approval, only for the requesting run, and never after it ends; a grant on a marketing deliverable whose run held a released engineering element adds that element, marked, and the card shows it; that run's `remember` and `adopt_plan` are refused; its brief to a child parks, and approving it starts the child with an unmarked copy while the grantee stays marked; a clean CEO copy of its output into an effort with the owner in the open set parks; a grant read of an untrusted record taints the reader; a file grant before P9 is refused, and with P9 a grant on one indexed file returns no hit from another; with D5 off, a `security/code` recall returns none of the engineering data it stored under D5; comms-triage's run never reaches `aos-security-code`'s client. |
| K11 | **Lineage** (§2.4). **Run state:** `RunScope` gains `lineage`, a set of `(c, R)` elements with their marks, which the kernel computes for every run. Kernel tools that add lineage (`read_result`, `read_grant`, `read_goals`) return it in their result, and the loop applies it. **Reading recall hits:** on the agent path, `McpHub.call` keeps `structuredContent`. For a pmmcp memory read, the hub renders the model's text from it as each hit's `id`, `project_id` and `content`, with no provenance, and `tool.result.text` logs the same bytes (`docs/DECISIONS.md` D18). The hub returns the union of the hits' lineage, computed before any truncation, and logs it on `tool.result` as `lineageAdded`. It adds `standing:d5` to engineering elements of hits from a D5 namespace. A hit whose lineage holds an element the run may not hold is withheld, with `withheld: {count}` on `tool.result`. That is a second wall behind P2. A memory read with missing or invalid `structuredContent`, or with a hit lacking lineage, fails closed: it is an error to the model and passes no content. **Stamping:** every `remember` stamps the provenance (runId, agentId, taint, `origin` `untrusted` if tainted else `agent`, lineage with marks, `observedAt`). The kernel logs each `remember`'s returned id with the lineage it stamped. On recall it unions into the hit's lineage what it logged for the hit's id and for each id in its `mergedFrom`. **The store rule** is the `memoryFits` deny fact, for every `remember`. **Goals:** `goal.created` (v2) carries the adopting run's lineage and taint. `kernel.read_goals {objectiveId}` returns that objective's subtree, adds its lineage and taint, and returns v1 goals without titles. **Labels:** the CEO's `own` fills `lineage_within: [executive]`, and `own:<c>` and `own:all` fill theirs. | `lineage.test.ts`: a marketing run that recalled a record whose stamped lineage holds `(engineering, {marketing})` has its `remember` denied with a `tool.gate` row; a recall hit's `tool.result.text` holds no `provenance` key; a double that returns a mixed-lineage collaboration record to the CEO's recall passes no content to the model; a double that answers `remember` with an existing id still makes a later recall add the remembered lineage; a recall without `structuredContent` reaches the model as an error; a `goal.created` row from a CEO run that recalled a marketing brief carries `(marketing, ∅)`, and a later `read_goals` of that objective adds it; over a fixture log with v1 goal rows, `read_goals` returns them without titles and the CEO then delegates to marketing with no card; a `security/code` run stores engineering data its D5 read delivered, and has its `remember` denied after recalling a record whose stamped lineage holds `(engineering, {security/code})` with no standing mark. |
| K12 | **Migration.** Retire `aos/ceo`, `aos/shared`, `aos/agent/researcher`, `aos/agent/writer` and `aos/agent/aos-live-test` together with K1 and K6a, **before the first pmmcp write**. The first write can be any of these: the first `npm run eval`; any `AOS_LIVE_PMMCP_WRITES=1` run; or any pmmcp-connected orchestrator run. An orchestrator writes goals mid-run through `kernel.adopt_plan` (`risk: write`, so a clean run needs no human), and at `run.finished` when `goals.adoptFromRuns` is true. Both Phase 0 exit runs are such runs. If either comes before K1 and K12, the operator records in README's exit checklist whether its log holds a `plan.adopted` or `goal.created` row. If one does, the operator removes those goals with pmmcp's own CLI before K12's check. README gives the check as `list_goals` on each retired id, plus pmmcp's own CLI for memories; the operator runs it outside the kernel. | Boot refuses a manifest with an old namespace; `runtime-bodies.ts` holds no namespace outside the §2.2 grammar; a boot with the live config writes no goal outside `aos/executive/live-test` and no memory outside `aos/<c>/agent/aos-live-test`. |
| K13 | **Memory promotion** (§2.8). `kernel.promote {source, target}` is a CEO kernel tool with `human: always`, filed per item. The kernel resolves `own`, `parent` or `fleet` relative to the source run's compartment, and refuses any other target. It applies §2.7's size, redaction and truncation rules, refuses a tainted source, and logs `kernel.proposed` with the bytes and every reader of the target, the CEO and standing-grant readers included. The write uses `aos-promote` with the §2.8 provenance. The kernel lists finished runs' deliverables to the CEO as typed candidate refs, with no text and no target. A run-independent approval kind is v2. | `promote.test.ts`: nothing is written without approval; `target: own` for a marketing source lands in `aos/marketing/shared`, and no target reaches another compartment's `shared`; a tainted source is refused; a `security/code` finding reaches `aos/security/shared` only after its own approval, with `security` and `ceo` in its `R`; a reader of a promoted record cannot store its released elements; the bytes written equal the bytes logged. |

## 5. End-to-end acceptance: the leak matrix

The release test for this contract.

- **Offline**, every item runs against the double.
- **Live** (`AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_WRITES=1`):
  - it uses only the kernel-held principals' tokens;
  - it seeds only `aos/<c>/agent/aos-live-test` in each compartment, and goals
    only in `aos/executive/live-test`, through `aos-goals-live`;
  - it never seeds a `shared`, `brief`, `collab` or `fleet` namespace;
  - it runs items 2, 4, 7 and 9 over the namespaces it seeded;
  - it runs the refusals of items 2–6 over the rest. Each write refusal is
    sent without `provenance`, and passes only on `namespace_denied` or
    `project_id_required`.
    - **From P7 on**, P2 checks the namespace first, so a regressed pmmcp
      answers `provenance_required` and stores nothing.
    - **Before P7** the only such backstop is P2's `invalid_provenance` under
      `aos/collab/`. So until §6 step 5, the live run sends write refusals only
      into other compartments' `aos/<c>/agent/aos-live-test` and under
      `aos/collab/`. The write refusals into `shared`, `brief` and `fleet` run
      offline only;
  - it checks the positive reads of items 5 and 6 only as recalls that are not
    refused, never printing hits. That each read returns the seeded record is
    checked offline.
- **Outside this repository.** The operator checks item 11, and clears the
  live-test namespaces, with pmmcp's own CLI.
- No file in this repository names the operator token.

The items:

1. **Seed.**
   - One distinctive memory into each compartment's agent and shared
     namespaces.
   - One into every brief except executive's, with the engineering and
     `security/code` briefs carrying `ceo` in `R`.
   - One collaboration record per member pair, with and without coding
     lineage, and with and without `ceo` in `R`.
   - One **mixed** collaboration record whose lineage holds `(marketing, ∅)`
     and an engineering element without `ceo`.
   - One record each in `aos/engineering/index/x` (trusted) and
     `aos/engineering/index/y` (untrusted).
2. **Cross reads.** For every (principal, namespace) pair outside that
   principal's read list:
   - recall, search and list are refused;
   - a recall within the principal's own namespaces using the target's
     phrase returns nothing.
3. **Cross writes.** Every sector principal's `remember` is refused into
   `aos/fleet/shared`, any `shared`, `aos/collab/`, the engineering and
   `security/code` briefs, and any other compartment. For `aos-security-code`,
   `remember` into engineering is refused too.
4. **Malformed calls.** Each of these is refused for every principal except
   `operator`:
   - a call with no `project_id`;
   - each grammar edge case from P2;
   - a call with a spoofed `_meta.client_id`.
5. **D5 and the sealed sub-section.**
   - `aos-security-code` reads engineering's shared and index namespaces, and
     writes neither.
   - `aos-security` reads nothing of `security/code` or `engineering`.
6. **The CEO's reach** is exactly the `aos-ceo` read list in P1, under its hold
   rule:
   - every brief;
   - the shared namespaces of compartments other than engineering and
     `security/code`;
   - non-coding collaboration records, and coding ones only with `ceo` in
     `R` on every coding element;
   - fleet;
   - its own namespace.

   It never reaches any compartment's `agent` namespaces,
   `aos/engineering/shared`, `aos/security/code/shared` or any
   `aos/engineering/index/*`. No record carrying a coding element without
   `ceo` in `R` reaches it, in any namespace. The mixed record from item 1 is
   never returned to it, by any query.
7. **Goals.**
   - A goal can be read and moved only with `aos-goals` (or, for
     `aos/executive/live-test`, `aos-goals-live`).
   - An existing goal id in another project and a nonexistent id give
     identical answers.
8. **Copies and promotions.**
   - A copy or promotion without approval writes nothing.
   - A collaboration record reaches only member principals, `aos-ceo` under
     its rule, and `operator`.
   - A copy whose source lineage holds engineering is never written under an
     open set.
   - A member stores nothing it read from a copy.
   - A compartment added to an effort after a copy is written never reads
     that copy.
9. **Untrusted text.** Untrusted hits, including index records from an
   untrusted root, never come back without `include_untrusted`.
10. **Lineage, results, grants and approvals.**
    - **Seeded engineering phrases.** A run whose compartment is not
      `engineering` receives a seeded phrase in its input, memory or
      `llm.request` only where this list says, or through an operator
      approval of exact bytes that hold it: a parked delegation's
      `childInput`, a parked result read, a copy or a promotion.
      - **In an engineering child's summary** (its first 2,000 code points),
        and **in a kernel-filed `aos/engineering/brief` record**: the CEO's
        runs, `aos/executive/ceo` and the goals the CEO adopts, through the
        D6 channel. No other run: not a `security/code` child, the planner,
        the assistant or a marketing child.
      - **In that child's final text past its first 2,000 code points**, its
        failureHistory or its error text: no run, the CEO's included, before
        an approved parked result read. That holds after the child's summary
        was read and after its brief was filed, and the child's logged
        lineage never gains `ceo`.
      - **In `aos/engineering/shared` or an index**: `security/code` runs
        (D5). They may store it in their own agent namespaces. No other
        run receives it from them without an approval of those bytes, and
        none does once the D5 grant is off.
      - **In a granted read**: the grantee run only, never its memory or a
        child.
      - **In a collaboration copy**: member runs while the effort is live,
        and the CEO only when `ceoRelease` was approved. A member never stores
        it.
    - **The CEO without a release.** A seeded engineering phrase that reaches
      a marketing run through an approved copy never reaches the CEO without a
      release to it.
    - **Parked delegations.** A seeded phrase in the input of a parked CEO
      delegation never appears in the `llm.request` of the assistant, warden
      or any run other than the CEO's own and, after approval, the approved
      child's.
    - **Grants.** A run that used a grant stores nothing and adopts no plan.
    - **Taint.** A CEO run that read a tainted run's result is tainted, and
      its next write needs a human.
11. **Operator-only checks** (run outside this repository).
    - The operator token sees everything.
    - Requests without a token to 8765 and to Qdrant are refused.

When warden's `events.search` is built, its acceptance carries the D7 check:
- a `text` search for a seeded engineering phrase matches nothing over a run
  whose lineage holds engineering;
- `includePayload` over any run returns nothing until a human approves it.

## 6. Order of work

1. **Operator:** commit the current pmmcp capture (`npm run capture:pmmcp`).
   It is the "before" picture for the drift test.
2. **Honest results, kernel first.**
   1. The hub and writer part of K8: `callKernelOnly` returns
      `structuredContent`, and the writer accepts both the structured and the
      prose form, for create and for update.
   2. pmmcp **P5**, and **P6 for the goal tools** only.
   3. A kernel commit that removes the prose path and replaces falsify G13 and
      G15.

   P6 removes the `✅ Goal updated:` text the writer confirms against, so the
   order matters. pmmcp and the kernel live in separate repositories, so
   shipping them "together" does not set the order.
3. **The compartment itself.**
   1. Kernel **K1, K6a, K12, K2, K4**, landing together.
      - Without K6a, once K1 ships every adopted plan writes its goals into
        `aos/executive/ceo`, which `aos-goals` cannot write once P2 ships.
      - K12 needs K1's grammar.
      - K2 lands with its first labels; the effort and `own:*` labels come
        later.
      - These must land before the first pmmcp write (K12's row), even if
        nothing else in this list has started.
   2. Kernel **K3**, with the event fields it needs from K7, and with profile
      differences only recorded.
      - It declares each principal's `tokenEnv` in `kernel.yaml`, and adds one
        placeholder line per name to `.env.example`.
      - The loader refuses a `.env` line for a name `kernel.yaml` does not
        declare, and refuses the whole file over one placeholder. So the
        operator adds the real lines right after pulling this commit, not
        before.
      - Until then, `status.get` names those principals degraded.
      - pmmcp still ignores bearers at this point.
   3. pmmcp **P1**, with the principals file.
   4. pmmcp **P2 + P3 + P9**, then the kernel commit that turns on K3's
      exact-profile check. Before P3, a wider listing is only recorded, so
      goals and delegation keep working.

   **Gate:** leak-matrix items 1–7 and 11 pass before step 4, with §5's
   pre-P7 limit on live write refusals.
4. **Goals under P4.** Kernel **K6b (1)**, then pmmcp **P4**, then kernel
   **K6b (3)**.
5. **Provenance and lineage.** pmmcp **P7**, with P6's memory models. Then
   kernel **K11**, then **K5** with the rest of **K7**. K5's tests read the
   lineage K11 computes, so K11 comes first. P7 ships before any recall is
   exposed to an agent. **Gate:** leak-matrix item 9, and item 10's checks on
   summaries, briefs, D5, parked delegations and taint.
6. **Efforts, grants and promotion.** Kernel **K9**, then **K10** and **K13**.
   K10's tests file copies, so K9 comes first. **Gate:** leak-matrix items 8
   and 10 in full.
7. **Protocol v2** (§2.10), after the operator approves the bump.

After each pmmcp change: re-capture per principal, update the double, and let
the drift test show exactly what moved.

## 7. Decisions

### 7.1 The operator's answers (2026-10-17)

| # | Question | Operator's answer | How this spec encodes it |
|---|---|---|---|
| D1 | Sector list | "marketing should have clipping as a sub-section" | Five sectors. `marketing/clipping` is an open sub-section of marketing (§2.1). `security/code` is a sealed one: the standing rule requires it once D5 lets those two agents read code. |
| D2 | What the CEO sees | "as much visibility as the ceo needs to make the informed decisions" | **Always:** typed, kernel-derived results. **Directly:** every brief; the shared namespaces of compartments other than engineering and `security/code`; and, while an effort is live, every collaboration record its hold rule allows. **On request:** summaries and deliverables through `kernel.read_result`, and one objective's goals through `kernel.read_goals`. **Coding data:** only with `ceo` in `R`, given by the capped D6 channel or an operator release. **Anything more:** grants. **Kept:** it may store what it holds in its own memory and the goal tree, which no other agent reads (R13). Lineage keeps it from passing any of this to another compartment without the operator, and efforts let cross-compartment objectives run without an approval each time (§2.4, §2.7). |
| D3 | Shared knowledge | "as big as it needs for agents to collaborate" | No cap on any shared or collaboration space. The one cap is one event's worth per copy: 55,296 bytes after JSON escaping (`PAYLOAD_TEXT_BUDGET` minus 8,192, about 54 KiB), so the operator can read each copy whole in its `kernel.proposed` row. `aos/fleet/shared` holds whatever every compartment needs, by promotion (§2.7, §2.8). |
| D4 | Data between sectors | "it shouldn't 'move', it should be copied to the collaboration space … when needed" | Copies into per-effort collaboration spaces. The original stays put, and the copy carries provenance and lineage. Members use a copy in context and store none of it in their own namespaces. Within a live effort, a CEO brief may also carry one open-set member's non-coding data to another member's run without a copy; that data lives only in that run's context (R14). Foreign data rests only where the operator approved its exact bytes, under an open set the operator approved, or, for what the CEO holds, in the CEO's own memory and the goal tree (§2.4, §2.7, R13). |
| D5 | Security agents and code | "sounds about right, but we want to be able to override the security agents if necessary" | A read-only standing grant for `security/code` only, under its own principal. It holds and stores natively only what its own D5 reads delivered (`standing:d5`). Its findings stay sealed and reach others only by promotion or copy. In v1 the operator resolves a security block as a card, and cuts or widens the grant by a config edit and a restart. `quarantine.release` is not an override. The rest of the override set is protocol v2 (§2.9, §2.10). |
| D6 | Engineering summaries to the CEO | "unless we override it and need the CEO to know the file contents" | Summaries and kernel-filed briefs may name files, functions and errors. Both are capped at 2,000 code points, and these two byte strings are the whole D6 channel: a deliverable read never uses it, and it never changes the source run's logged lineage. File contents reach the CEO only through an operator grant, an approved parked result read, or a copy or promotion the operator released to it (§2.4, §2.5, §2.9). R8 names the residual. |
| D7 | The event log | "Leave as is" | One log for the operator. When warden's `events.search` is built, the following holds over every run whose compartment is `engineering` or `security/code`, or whose lineage holds either: it returns metadata only, and takes no `text` filter there, because a match over those payloads tells a non-coding agent what coding data says. That covers the CEO's runs and grant-holding runs. A run whose lineage the kernel cannot establish counts as engineering. Over other runs the `text` filter works with no human, as designed (OS:74; R6). A payload body (`includePayload: true`) of any run is returned only with a human: warden-forensics, on operator request (OS:189, 473). |

### 7.2 Readings the operator may want to change

The rest of the spec is written on these readings. None blocks work.

- **R1. Clipping is open both ways within marketing.** The alternative is to
  seal it like `security/code`.
- **R2. Copies.** Engineering and `security/code` copies are approved one at a
  time. Within an effort, the members in its open set exchange non-coding data
  without an approval each time. The alternatives are per copy everywhere, or
  an open set that can include engineering.
- **R3. "Override the security agents".** This is read as four powers:
  - overrule any block, halt or veto;
  - release held output so that the held run goes on;
  - cut the D5 grant;
  - widen a security run.

  In v1, a block resolves as a card, and the standing grant is cut or widened
  by a config edit and a restart. `quarantine.release` is not an override: it
  shows held output to the operator and lets no held run go on. Overrides
  that record a reason, halts, vetoes, releases that resume a run, and
  per-run widening are v2.
- **R4. The CEO's direct reads.** The CEO reads the shared namespaces of
  compartments other than engineering and `security/code` directly. It reads
  those two only through capped briefs and summaries, grants, approved parked
  result reads, and released copies and promotions.
- **R5. The shipped researcher** is placed in marketing, and
  `ceo-objective-fanout` is rewritten to match. The other two eval cases are
  unchanged.
- **R6. What D7 leaves open.**
  - warden's metadata (event types, run and agent ids, counts, cost) still
    covers every compartment.
  - Its `text` filter still works, with no human, over runs that are not in
    engineering or `security/code` and whose lineage holds neither. Over
    marketing, trading and executive runs, that filter is a cross-compartment
    read under the "all sectors separate" rule. Refusing `text` over every run
    is the stricter alternative.
  - Closing it would make every agent's `events.search` compartment-scoped,
    with warden getting kernel-computed aggregates elsewhere.
- **R7. Who curates engineering memory.** Promotions of eng-lead's
  deliverables, filed by the CEO, or the operator. A `curator-engineering`
  agent exists only if the operator adds its manifest.
- **R8. What D6 still allows.** Summaries and briefs are model-written, so one
  can quote up to 2,000 code points of code, and many together can quote more.
  The stricter alternatives are briefs the kernel renders from typed fields
  only, or an operator approval per engineering brief and summary read.
- **R9. Visibility costs unattended delegation.** Lineage is per run, and the
  CEO's memory and goals carry it into later runs.
  - A CEO run that reads several compartments' briefs, with no effort open,
    parks every brief it writes to them. The planner and the assistant are
    included.
  - Efforts with an open set, the CEO's `own:*` recall labels, and reading
    goals one objective at a time are the tools for keeping delegation
    unattended. `kernel.read_goals` takes one objective, so it adds only that
    objective's lineage.
  - Tracking lineage per brief rather than per run is not an alternative,
    because the kernel cannot tell which part of a context a brief came from.
- **R10. Who starts an override.** In v1 the operator can only approve what
  the CEO requests. To start a D6 override, the operator tells the CEO to ask.
  Grants the operator issues directly are v2.
- **R11. Foreign data at rest.** An agent other than the CEO that read
  released data cannot store anything in its own namespaces for the rest of
  that run. Neither can an agent that holds open-set data from an effort, or a
  grantee run.
  - What should outlive the run goes into a collaboration space, as a copy
    approved on its exact bytes or covered by the effort's open set (§2.7).
    Members read it until the effort ends.
  - What should outlive the effort goes into a promotion, approved on its
    exact bytes (§2.8).
  - The CEO is R13.

  The alternative, letting released data be stored where its release reaches,
  was revision 3's, and it let released data outlive its effort.
- **R12. Grants are per run.** A grant serves only the run that asked, and
  nothing derived from it is stored or delegated without a per-item approval.
  That run also cannot adopt a plan. The alternative is objective-scoped
  grants, which need protocol v2 for revocation.
- **R13. The CEO keeps what it holds.** No agent but the CEO reads its own
  memory or the goal tree. So the CEO may store there what it holds natively,
  labelled by lineage (§2.4):
  - non-coding data from every compartment;
  - coding data with `ceo` in `R`: D6 summaries and briefs, approved parked
    result reads, and copies and promotions released to it.

  Its `own` label leaves those records out, and `own:<c>` and `own:all` bring
  them back. This reads D2 as visibility that outlasts one run. The stricter
  reading counts only `executive` as native for the CEO's store rule. A CEO
  run that read any brief or result could then neither `remember` nor adopt a
  plan.
- **R14. Data between members without a copy.** D4 says data is copied, not
  moved. Two paths carry data into another compartment's run without writing
  a copy:
  - within a live effort, a CEO brief may carry one open-set member's
    non-coding data into another member's run;
  - a parked delegation the operator approves may carry any data into its
    child.

  That data lives only in the receiving run's context, and lineage keeps it
  from being stored outside a copy (§2.4). This reads D4 as a rule about what
  persists. The stricter reading sends every crossing through a copy: the CEO
  files the copy and the member recalls it. That costs a
  `kernel.copy_to_collab` call per crossing, but no extra approval under an
  open set.

### 7.3 Design-doc conflicts these decisions resolve

Kept so the next design pass can amend the docs:

- **Shared memory.**
  - The flat `aos/shared` (AF:483, 489) becomes per-compartment `shared`
    plus `aos/fleet/shared`.
  - implementer#docs writing to `aos/shared` (EN:247).
  - The kernel's per-run and handoff records into agent namespaces (EX:281)
    are dropped. §2.3 admits only the agent's own gated `remember` there.
- **The CEO's reads.**
  - CEO recall over `aos/agent/*` (EX:410) becomes briefs, results, grants,
    copies and promotions, under lineage.
- **Curation and promotion.**
  - The curator reading every sector (EX:453) becomes standard curators per
    compartment, and none for engineering (R7).
  - Promotion as the curator's own `remember` into `shared` (EX:343, AF:175)
    becomes a CEO-filed `kernel.promote`, approved per item (K13).
  - Pentest findings mirrored fleet-wide by the projection writer with no
    approval (OS:191, 225, 515) stay in `security/code`, and reach
    `security/shared` only by promotion.
- **Results and templates.**
  - The self-reported `RunResult` fields (EX:139-152) are model text: they
    reach the CEO only through `kernel.read_result`.
  - Shared templates recalling "the spawner's namespace" (EN:180, GR:239,
    TR:405) get their profile's compartment read set.
  - The delegation envelope that intersects `memory.projectId` (EX:130) is
    replaced: children get their compartment's read set.
  - scout and judge "spanning sectors" (AF:240, AF:542, TR:87) become profiles
    with one compartment each.
- **Plans and kernel-started runs.**
  - `inputRefs` injected into later children (EX:122, 166) are inputs under
    the receive rule.
  - A lead's `ProposedPlan` adopted into goals (EX:59, 243) is model text:
    it is read through `read_result`, which adds the lead's lineage.
  - Kernel-started plan nodes (EX:45) and milestone judges (EX:497) follow
    the receive rule and §2.5.
- **Approvals.**
  - Tainted-write and promotion cards deferred into the assistant's digest,
    and the kernel bundle's pending approvals (EX:363, 510), become counts
    only.
  - A declassification scoped by objective only (EX:205) is now a release per
    compartment, through lineage.
- **The event log.**
  - `events.search` with `text` over every payload (OS:74, 473) is governed by
    D7 as encoded.

## 8. What this does not isolate

- **The event log.** It is one SQLite file holding tool results, prompts and
  responses for every compartment. The operator's UI and CLI read it whole, by
  design. Agents cannot read it today. warden's future `events.search` is
  governed by D7.
- **Domain stores outside pmmcp**: the CRM, the trading ledger, the publishing
  edge and the artifact store. Each needs its own compartment check where it
  is built.
- **Kernel memory.** A single process holds every principal's token.
  Compartments protect against a wrong call, not against code execution inside
  the kernel. Invariant 2 keeps agents out of the kernel.
- **Lineage is kernel-only.** pmmcp stores it, filters on it, and never sees a
  prompt.
- **Non-pmmcp tools.** Their results enter a run as that run's own data. Web
  pages and other untrusted inputs are handled by taint, not lineage.
- **The kernel-only principals.**
  - What protects: they reach only their own namespaces, and `aos-promote`,
    `aos-collab` and `aos-brief` read nothing. So a kernel bug cannot read
    another compartment's data through them.
  - What does not: a kernel bug can still leak by writing through them.
    Wrong bytes or wrong `members` through `aos-collab`, or a promotion into
    the wrong `shared` or into `aos/fleet/shared`, put data where other
    compartments read it. pmmcp accepts the write: it checks the shape, and
    does not know efforts or approvals.
  - A signed approval the kernel cannot forge, binding the bytes, the target
    and the members, belongs to Phase 5.
- **pmmcp's storage**: SQLite and Qdrant's files on disk, and backups. These
  are operator-only files. Their network surfaces (the dashboard and Qdrant's
  API) are covered by P1.
- **Typed results as a channel.** Values the kernel derives add no lineage
  (§2.4), but a child's model steers some of them: how many calls it makes,
  whether it stops on an error, whether an acceptance check passes. An
  engineering child could signal a few bits per run to the CEO that way.
  Closing it would mean treating every typed result of a coding run as coding
  data, which costs D2 the cheapest signal it has. This revision accepts the
  channel.
- **Withheld hits.** A recall hit the kernel withholds (K11) is counted on
  `tool.result`, which only the operator reads. The model sees fewer hits and
  nothing else. P2 should never return such a hit, so a count above zero is a
  pmmcp defect for the operator to chase.
- **The operator's own copying.** Text the operator copies by hand, through
  pmmcp's CLI or the `operator` principal, is stamped as fresh operator data
  (P7). It carries no lineage from where the operator read it. That is the
  operator's own act, and no wall here second-guesses it.
- **Timing.** In one shared Qdrant collection, a compartment can time its own
  recalls to estimate how much the others store. Closing that means one
  collection per principal, a change to pmmcp's storage. This revision
  accepts the channel.
- **The operator's own tools.**
  - The `operator` principal sees everything, by design. A Claude Code session
    on an untrusted repository could be prompt-injected into reading trading
    or CRM data through it.
  - Recommended: give the operator's MCP clients the `operator-clients`
    principal, limited to the operator's own `project_id`s outside `aos/`, and
    keep `all` for pmmcp's CLI.
  - `operator-clients` cannot reach global (null-project) records, or an
    existing `project_id` outside its grammar (uppercase, `_` or `.`). Check
    §9 before switching.

## 9. Needs validation before implementing

- **pmmcp's SDK.** Its `mcp` version: v1 FastMCP or v2 MCPServer, and whether
  it is at least 1.29.1 (P1).
- **Search and storage.**
  - Whether pmmcp's recall filters `project_id` inside the Qdrant query
    today, and whether a project-scoped recall also returns global
    (null-project) records.
  - Whether `remember` deduplicates, links or consolidates records, and how.
  - Whether the Qdrant server and client that pmmcp pins support the `nested`
    filter condition that P2's CEO hold rule needs, and whether P7's
    `lineage_within` (every element of an array of objects in a set) can be
    written without a precomputed field.
- **Tools.**
  - The real name and arguments of `search`, if it exists.
  - The real arguments of `index_project`.
  - How `index_git_history` divides a commit into records.
  - Whether pmmcp registers resources, resource templates or prompts, and
    what other routes it serves on 8766.
  - How the kernel's `indexRepos` (K2) stays in step with pmmcp's
    `index_roots` (P9). A repo in one list and not the other gives a label
    that reaches nothing, or an index no label reaches. Both fail closed, but
    a boot check that compares them needs pmmcp to report its roots to
    `aos-engineering`.
- **The operator's surfaces.**
  - What the dashboard on 8765 shows.
  - Which `project_id`s the operator's own clients use today, and how many
    global records exist.
- **Existing data.** Whether anything is already stored under `aos/` (K12),
  including goals from any Phase 0 exit run.
- **The vault.** Whether `get_secret` takes `project_id` live. After P3 this
  matters only to the operator.
