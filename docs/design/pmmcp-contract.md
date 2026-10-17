# pmmcp ↔ kernel contract: compartments

Status: **draft, revision 3** (2026-10-17). Not implemented on either side.

- **Revision 1** wrote decisions D1–D7 on recommended defaults.
- **Revision 2** encoded the operator's answers (2026-10-17) and fixed an
  adversarial review of revision 1.
- **Revision 3** fixes a second review, of revision 2, by the same four
  lenses (isolation red-team, pmmcp on the Python SDK, kernel fit, coherence
  and intent), with a skeptic on every finding; 60 of 74 findings survived,
  9 of them critical. The main changes:
  - lineage is tracked for every run, and records operator releases (§2.4);
  - copies, promotions, memory writes and briefs are judged on lineage;
  - engineering briefs are written by the kernel and capped (§2.5);
  - data delivered by a grant is never stored (§2.9);
  - what protocol v1 can and cannot do is stated (§2.10).

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
  moving on (§2.4). pmmcp stores lineage and never sees a prompt.
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
  - it requires an **object-rooted** `outputSchema`;
  - it **throws** when a tool declares one and returns no `structuredContent`
    without `isError`;
  - it validates only the last page of a paginated `tools/list`;
  - it validates `format: date-time` strictly, so a timestamp without an
    offset fails.
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

- **Namespaces.**
  - One memory namespace per agent, from a fixed shape:
    `aos/ceo | aos/shared | aos/agent/<id>` (`src/agents/manifest.ts:28`).
  - Goals are written into the adopting agent's namespace
    (`src/runtime/delegate.ts:185, 203`; `src/kernel.ts:476`;
    `src/goals/tracker.ts:203`).
  - No compartment concept exists anywhere in `src/`.
  - No pmmcp tool is exposed to any agent (`config/tool-views.yaml`).
- **The gate.**
  - It **checks** the `project_id` the model sends and never **sets** it
    (`src/policy/gate.ts:122-145`). CLAUDE.md, README.md:389-390 and
    tool-views.yaml:15-18 require it to set the id before `recall` or
    `remember` is exposed. K2 meets that requirement.
  - Its only `needs-human` rules are irreversible risk, and a tainted run
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
  - Delegation is depth 1, and the CEO is the only orchestrator (AF:18,
    AF:107).
  - A delegation brief (≤ 8,000 characters) becomes the child's prompt
    verbatim (`delegate.ts:51, 300-302`). The child's `finalText` comes back
    to the parent (`:370`).
  - A delegated child does not inherit its parent's taint (`kernel.ts:613`).
- **The log.**
  - `llm.response` logs only the model's text, never its tool-call input
    (`src/models/anthropic.ts:224-252`). A tool call's arguments first reach
    the log in the next `llm.request`.
  - A `needs-human` card carries a 500-byte preview of the canonical
    arguments (`src/policy/engine.ts:81`).
  - The event store refuses any payload whose canonical JSON exceeds
    `MAX_LOGGED_OUTPUT` (65,536 bytes) (`src/events/store.ts:147-159`).
    Strings are JSON-escaped (`src/events/canonical.ts:46`), and
    `PAYLOAD_TEXT_BUDGET` (63,488 bytes) is the text budget a producer bounds
    to (`src/events/bound.ts:40`).
  - Boot re-parses stored `goal.created` rows and open `run.queued` rows with
    strict schemas (`kernel.ts:301, 482`; `tracker.ts:93, 135`).
- **Protocol v1.**
  - Its approval kinds are `tool` and `promotion` only
    (`src/control/protocol.ts:123`).
  - `approval.approve` takes only `{approvalId}` (`protocol.ts:307-310`).
  - v1 has no revoke, suspend, close or override command (`protocol.ts:44-61`).

## 2. The compartment model

### 2.1 Compartments (D1)

Five sectors, two of which contain a sub-section:

| Compartment | Holds | Agents (from docs/design) |
|---|---|---|
| `executive` | goal tree, adopted plans, mandates, CEO memory | ceo, planner, assistant, judge#exec², curator-executive |
| `engineering` | **all coding data**: code knowledge, ADRs, module maps, design system, incident notes, indexed repositories and git history | eng-lead, prototyper, sre, architect, implementer, tester, reviewer, release, scout#eng² |
| `marketing` | marketing, social, community, sales: brand kit, ICP, drafts, CRM-adjacent notes | marketer, writer, community, sales, publisher, researcher, checker{brand,policy,facts}, reporter, focus-group, scout#growth², curator-marketing |
| `marketing/clipping` | clipping and production: captions, renders, clip plans, media checks | producer, checker{media} |
| `trading` | theses, signals, strategy cards, backtests, journals | quant, executor, bookkeeper, market-scout (scout#market²), critic (judge#critic²), curator-trading |
| `security` | warden reports and fleet security findings that cite no code | warden, evaluator, comms-triage, curator-security |
| `security/code` | code review and pentest work under the D5 grant | security-reviewer, pentester |

There are two kinds of sub-section:

- **Open** (`marketing/clipping`). It is part of marketing. Every marketing
  agent reads it, and clipping agents read marketing. Both run under the
  marketing principal (P1), and for lineage a clipping run counts as
  marketing (§2.4). Its own namespaces keep clipping work organised, and an
  edit to the principals file would seal it later.
- **Sealed** (`security/code`). Only its own agents read it, and the CEO reads
  its kernel-filed, capped brief (§2.5). They hold the D5 read grant into
  engineering, so what they find stays away from warden, evaluator and
  comms-triage. comms-triage is always tainted and will take inbound SMS and
  Telegram.

² **Template profiles** (§2.5). scout and judge are templates with one
profile per compartment. A profile serves `engineering` only if its manifest,
which the operator edits, gives it that compartment. That entry is the
operator's statement that the profile does coding work.

**Curators** are standard, scheduled agents, one per compartment they curate.
There is none for `engineering` or `security/code`. Engineering memory is
curated by eng-lead, through promotion proposals (§2.8), or by the operator
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

"Read" means recall, search and list. Writes into `shared`, `collab`, `fleet`,
the engineering and `security/code` briefs, and the goal namespaces are made
by the kernel with a kernel-only principal (P1).

| Namespace | Read | Write |
|---|---|---|
| `aos/<c>/agent/<id>` | that agent, and `c`'s curator¹ | that agent, by a gated `remember` (§2.4, rule 2) |
| `aos/<c>/shared` | agents of `c`; the CEO, except for `engineering` and `security/code` | **only** the kernel, for an operator-approved promotion (§2.8) |
| `aos/<c>/brief` (every `c` except `executive`) | agents of `c`; the CEO | agents of `c`, by a gated `remember`; for `engineering` and `security/code`, **only** the kernel, from a finished run's summary (§2.5) |
| `aos/engineering/index/<repo>` | `engineering`; `security/code` (D5) | **only** the operator's indexing (P9) |
| `aos/executive/ceo` | the CEO | the CEO, by a gated `remember` |
| `aos/executive/goals` | the kernel; the CEO through `kernel.read_goals` | the kernel only (§2.6) |
| `aos/collab/<effort>` | agents of the effort's member compartments; the CEO, except coding-lineage records not released to it (§2.7) | **only** the kernel, for an approved copy (§2.7) |
| `aos/fleet/shared` | every agent | **only** the kernel, for an operator-approved promotion (§2.8) |

"Agents of `c`" includes the parent sector's agents when `c` is the open
sub-section, and the sub-section's agents when `c` is `marketing`.

¹ pmmcp's wall is the compartment: any agent of `c` holds the principal that
could read every `aos/<c>/agent/*`. Keeping an agent to its own namespace is
the kernel's read set (K2). The CEO's memory is curated by the operator.

Rules that apply across the table:

- **Cross-compartment reads exist only by the operator's decision**, and each
  is read-only:
  - standing grants in config; there is one today, D5;
  - runtime grants the operator approves (§2.9);
  - collaboration memberships the operator approves (§2.7);
  - every agent's read of `aos/fleet/shared`, which holds only promoted
    records;
  - the CEO's reads in this table (D2).
- **The CEO's wider reach belongs to the CEO alone.** assistant and
  curator-executive read no brief, no other compartment and no collaboration
  space. A child the CEO delegates to in executive (planner, judge#exec,
  worker-template) sees only what the CEO's brief carries (§2.4).
- **Coding data leaves engineering only in ways the operator chose**. The
  ways out are:
  - the D5 grant;
  - the CEO's reads of capped engineering briefs and summaries (D2, D6);
  - an operator grant;
  - an approved copy or promotion;
  - an approved parked delegation.

  Lineage (§2.4) keeps it from moving further without the operator.
- **Approval cards.** A card, its preview and any held output carry the
  compartment and the lineage of the run that asked (K7). No agent-facing
  bundle (the assistant's digest, warden, a CEO continuation) carries any
  card's preview or held output, with one exception: the CEO's continuation
  receives its own cards, and their lineage joins its run. Everywhere else a
  bundle shows counts per compartment and class, nothing more.

### 2.4 Lineage

D2 gives the CEO as much visibility as it needs to decide, and D6 lets the
operator show it file contents. The CEO then holds other compartments' data in
its context. A model can repeat anything in its context into anything it
writes. Lineage is the rule that keeps such data where the operator put it.

**What lineage is**

- A run's lineage is a set of elements `(c, R)`.
  - `c` is a compartment whose data entered the run's context. The open
    sub-section counts as its sector.
  - `R` is the set of compartments that an operator approval released that
    data to. It is empty unless an approval says otherwise.
- Elements with `c = executive` are recorded and never restrict anything.
  Executive data may go to every compartment.
- The kernel computes lineage for **every** run. The model never sets or sees
  it.
- A run starts with `{(its compartment, ∅)}`, plus the lineage that its brief,
  plan and `inputRefs` carried (after any release, rule 1).

**What a compartment may hold.** A run of compartment B may hold `(c, R)`
when any of these is true:

- `c` is B;
- B is in `R`;
- `c` is covered by one of B's standing grants. Under D5, `security/code`
  holds engineering.

Three kinds of agent are special:

- **The CEO** may hold every element (D2).
- **A child the CEO delegates to in executive** (planner, judge#exec,
  worker-template) may hold every non-coding element for that run. It may not
  hold an engineering or `security/code` element.
- **Every other executive agent** holds executive data only.

**What adds to it**

- A recall hit adds the lineage in its provenance (P7). The kernel also adds
  every lineage it logged for that record id (K11).
- A child's summary adds the child's lineage.
- A brief, a shared record or a collaboration record adds the lineage in its
  provenance.
- A granted read adds `(owning compartment, ∅)`, marked with the grant's id.
- An approval card shown to the CEO adds the card's lineage.

What does not add to it: the kernel's typed fields. These are status, cost,
taint, the acceptance results and evidence verdicts the kernel computed, and
deliverable kinds and refs. The kernel renders them, and no model wrote them.

**The CEO's own memory.** A recall of `aos/executive/ceo` offers kernel
labels that bound the lineage of the hits (K2; P7's `lineage_within`):

- `own` returns records whose lineage is executive only;
- `own:<c>` returns records whose lineage stays within executive and `c`;
- `own:all` returns everything.

The CEO chooses how much to read. Reading less never widens anything.

**What it constrains.** Each check is computed by the kernel before the gate,
from the log and the run scope, and reaches the pure gate as a fact (K9a).

1. **Delegation.** The brief, the plan's task text and its `inputRefs` carry
   the lineage of the run and of the plan they came from.
   - **When a child may start.** A child in B starts without a human only when
     B may *receive* every element:
     - `c` is B, or B is in `R`;
     - for an executive child of the CEO, any non-coding element;
     - under the effort its objective is bound to (§2.7), an element whose
       `c` is in the effort's open set, when B is a member.
   - **Standing grants never admit a brief.** A grant names namespaces, while
     lineage records only a compartment.
   - **Parking.** Otherwise the delegation parks as `needs-human`. The kernel
     logs `delegation.parked`, with the full brief, before the card (K5). If
     the operator approves, the brief is released to B: each element becomes
     `(c, R ∪ {B})`.
   - **`inputRefs`.** An `inputRef` whose elements B may not receive is
     refused, not parked, unless its exact bytes are an approved copy in an
     effort with B as a member.
2. **Memory.** A `remember` into namespace N is refused unless every element
   of the run's lineage is held by every compartment that reads N (§2.3). For
   example:
   - a marketing run that read engineering data cannot store it in marketing
     memory;
   - a planner holding marketing data cannot store it in executive memory;
   - the CEO can store anything in `aos/executive/ceo`.
3. **Grants.** A run whose lineage holds a grant-marked element cannot
   `remember` at all (§2.9). That covers the grantee, and any run that read
   its summary. Grant elements pass on only through a per-item approval.
4. **Copies and promotions.** §2.7 and §2.8 judge them on the source's
   lineage, never on the source run's compartment alone.
5. **Plans and goals.** An adopted plan carries the adopting run's lineage,
   and so does each goal written from it. Showing the CEO the goal tree adds
   that lineage to its run.

**In practice**

- The CEO reads typed results freely and can delegate anywhere.
- **A single-compartment objective.** The CEO reads that compartment's brief
  and delegates into it without the operator.
- **A cross-compartment objective.** The CEO opens an effort (§2.7) with
  those compartments as members and the non-coding ones in its open set. The
  operator approves that once. Delegations under the objective then carry
  those compartments' data between members with no further approval.
- **Coding data never moves through an open set.** Each crossing out of
  engineering is an operator approval of exact bytes: a copy, a promotion or a
  parked brief.
- **Reading has a cost (R9).** If the CEO reads marketing's and trading's
  briefs with no effort open, every brief it then writes to either
  compartment parks.

### 2.5 Templates, children and delegation

**A child's compartment**

- A standard agent's compartment is the one in its manifest.
- A template declares one or more **profiles**. Each profile has exactly one
  compartment and its own `tools.allow`, and the operator edits both. Examples
  are `scout#eng` → engineering, `scout#growth` → marketing, `scout#market` →
  trading, `judge#exec` → executive, and `judge#critic` → trading.
- A plan task names a profile, as it names a standard agent. A template with
  one profile may be named bare. A plan that names a multi-profile template
  without a profile is refused.
- No plan field sets a compartment. Which data the child may receive is still
  decided by the lineage check (§2.4), never by the plan.
- The registry refuses `schedule:` on a template, so every scheduled run
  belongs to a standard agent.

**What a child can reach**

- A child gets its compartment's read set plus that compartment's config
  grants, intersected with what its profile declares. It inherits nothing
  from its parent's reach.
- Tier, egress, tools and budget follow the parent ∩ template rule (EX:130).
- Taint passes from parent to child (K5). Today it does not (`kernel.ts:613`).

**What comes back to the CEO**

- **Typed fields.** The kernel's typed `RunResult`: status, cost, taint, the
  kernel's acceptance results, and evidence and deliverable refs.
- **The summary.** It is at most 2,000 characters and is written by the
  child's model. The CEO gets it only by asking, with `kernel.read_result`, and
  asking adds the child's lineage to the CEO's run (§2.4).
- **Raw memory** never comes back.

**Engineering text and D6**

- Engineering and `security/code` text reaches the CEO in only two shapes, and
  the kernel caps both at 2,000 characters:
  - a summary the CEO asks for;
  - a brief the kernel files from a finished run's summary into
    `aos/<c>/brief`, with the write-only `aos-brief` principal. It does so
    only for agents whose manifest sets `filesBrief: true`, which the operator
    edits: eng-lead and security-reviewer by default. There is at most one
    per run, and P2 caps it at pmmcp too.
- Both caps count Unicode code points, in the kernel and in pmmcp alike.
- Engineering and `security/code` agents never write their brief themselves,
  because K2 offers them no `brief` scope.
- A summary or brief may name files, functions and errors. No artifact body is
  handed over.
- **What stays possible (R8).** A model can quote up to 2,000 characters of
  code in one summary or brief, and many briefs together can quote more.
  Lineage keeps such a quote from going further. The stricter alternatives are
  briefs the kernel renders from typed fields only, or an operator approval
  for each engineering brief.
- Otherwise, file contents reach the CEO only through an operator grant
  (§2.9), or a copy the operator released to the CEO (§2.7).

**Delegating to a template** is ephemeral spawning, which no tool does yet
(CLAUDE.md). Building it widens what agents can reach, so it is ask-before.

### 2.6 Goals

- **Where goals live.** The goal tree lives in `goals.projectId`,
  `aos/executive/goals`. K6a lands together with K1, so no goal is ever
  written into an agent's namespace, the CEO's included.
- **Who writes them.** The goal writer uses the `aos-goals` principal. The
  gated live tests use `aos-goals-live`, which reaches only
  `aos/executive/live-test`, so pmmcp refuses a live-test goal aimed at the
  real tree.
- **What the kernel sends.**
  - To `create_goal`: only `project_id`, `goal_type`, `title` (≤ 200
    characters) and `parent_goal_id`.
  - To `update_goal`: only `goal_id`, `project_id`, `status` and
    `progress_pct`.
  - Never description, acceptance criteria, related files, blockers or tags.
- **Lineage.** A goal carries its plan's lineage in the kernel's
  `goal.created` record. When a plan comes from a sector lead's `ProposedPlan`
  (EX:59), its titles are that compartment's data and carry its lineage.
- **How the CEO sees them.** The CEO sees the tree through `kernel.read_goals`,
  and the goals' lineage joins its run.
- Sector agents never touch goals. The kernel moves task status from the run
  lifecycle, as it does today.
- P4 makes pmmcp enforce the namespace on every goal call, so no goal can be
  read or moved by id alone.

### 2.7 Collaboration efforts and copies (D3, D4)

Data never moves between compartments. When agents of different compartments
work together, the data they need is **copied** into a collaboration space,
and the original stays where it is.

**Efforts**

- An effort is bound to one objective. It has:
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
- `kernel.add_member` adds a member under the same approval. In protocol v1
  nothing else changes an effort before it expires (§2.10).
- An objective has at most one effort.
- An effort ends at its expiry or when its objective closes. The kernel then
  stops offering it and refuses new copies. The space stays in pmmcp, and
  nothing is deleted.
- **Why `executive` is never a member.** Executive data goes to every
  compartment, so a copy released to executive would be released to all. The
  CEO reads efforts under its own rule (Reading, below).

**Size**

- There is no cap on a space.
- A single copy must fit in one event. Its JSON-escaped length (`canonicalize`)
  is at most `PAYLOAD_TEXT_BUDGET` (63,488 bytes), so `collab.copy.proposed`
  fits under `MAX_LOGGED_OUTPUT` with its other fields and the operator can
  read every byte. Larger material goes in as several copies.
- The kernel never truncates a copy. It refuses a source the log holds
  truncated: a `tool.result` with `truncated: true`, or an `llm.response` cut
  at the budget.

**A copy**

An orchestrator files `kernel.copy_to_collab {effort, source}`. The source is
bytes the kernel already holds: a finished run's deliverable or summary, as
logged. To copy a stored memory, a run of the source compartment first
recalls it into its deliverable. Workers do not file copies; letting them is a
widening, and ask-before.

1. **Resolving the source.** The kernel resolves the source (K9's prepare
   step) only after the gate's deny rules have passed for this call: the tool
   is exposed, it is in the caller's manifest, and the caller is an
   orchestrator. A denied call resolves nothing and logs nothing. The kernel
   refuses bytes the log's redactor would change, so the bytes the operator
   reads are exactly the bytes that get written.
2. **Logging.** The kernel logs `collab.copy.proposed`. It carries the full
   bytes and their sha256; the source compartment, run, taint and lineage; and
   the effort. The kernel then adds the sha256 to the call's arguments before
   the gate hashes them, so an approval binds those exact bytes.
3. **Approval** follows the source's lineage, as its `run.finished` recorded
   it.
   - **When no fresh approval is needed.** The calling run is clean, and every
     element `(c, R)` is either already released to every member (each member
     is `c` or is in `R`) or has its `c` in the effort's open set.
   - **Otherwise** the operator approves this copy. An element whose `c` is
     `engineering` or `security/code` is never covered by an open set, so every
     coding copy is approved one at a time.
   - **The card names every reader.** Those are the members, and the CEO if
     the operator also releases the copy to it (`ceoRelease`). For a coding
     copy, `ceoRelease` is the D6 override. The CEO reads a non-coding copy
     anyway.
4. **Writing.** The kernel writes the bytes into `aos/collab/<effort>` with the
   `aos-collab` principal (P1). The provenance is P7's, filled for the source
   run, and every field below sits inside `provenance`:
   - `runId`, `agentId` and `taint` of the source run;
   - `origin`: `untrusted` if that run was tainted, else `agent`;
   - `lineage`: the source lineage, with each element's `R` extended by the
     members. This is the release;
   - `observedAt`;
   - `source {compartment, runId, sha256}`, `members`, `copiedBy`,
     `approvedBy` and `ceoRelease`.

**Reading**

- **Members.** Agents of a member compartment read the space. pmmcp returns a
  record only to a principal whose compartment is among that record's
  `members` (P2).
- **The CEO** reads every record without coding lineage, and a coding-lineage
  record only when `ceoRelease` is true. pmmcp enforces both.
- **Lineage.** Reading adds the record's lineage (§2.4). A member may hold it,
  because the copy released it to members. Passing it any further needs
  another approval.
- **A new member** sees only later copies. Members are stamped on each record,
  and no tool rewrites a record. To give a new member an earlier copy, the CEO
  files it again, under a new approval.

**The fleet space.** `aos/fleet/shared` is written only by promotion (§2.8).
A promotion releases to every compartment, and is always approved per item.

### 2.8 Promotion

A promotion puts approved bytes into a curated namespace: a compartment's
`shared`, or `aos/fleet/shared`.

- **Who proposes.** A worker proposes a promotion only as a typed
  `RunResult.proposals[]` entry: `{kind: promote, target: shared | fleet,
  deliverableRef}`. The model never names a namespace. Letting a worker's
  output start an approval is ask-before (K13).
- **The target.** The kernel resolves it to one of three: the proposer's own
  compartment's `shared`, `aos/security/shared` for a `security/code` proposer,
  or `aos/fleet/shared`. It refuses anything else.
- **The source.** The kernel takes the source bytes as it does for a copy
  (§2.7: size, redaction, truncation), logs `promote.proposed`, and hashes the
  sha256. It refuses a source from a tainted run.
- **Approval** is always per item, by the operator. No open set covers a
  promotion.
- **The write** uses `aos-promote`. The provenance lineage is the source
  lineage, with each element released to the target's readers. It also
  carries `promotedFrom {runId, sha256}` and `approvedBy`.
- **Effect.** The target's readers hold the promoted data because the
  promotion released it. A `security/code` finding promoted into
  `aos/security/shared`, for example, is released to warden, evaluator and
  comms-triage, approved on its exact bytes.

### 2.9 Grants and overrides (D5, D6)

**Grants**

A grant lets a run read something its compartment cannot.

- **In v1.** The CEO requests one with `kernel.request_access {compartment,
  what, reason}`. The grantee is the requesting run, and the grant ends with
  that run. The operator approves it as a `HumanActor`. Grants the operator
  issues to a named agent or objective, and revocation, are protocol v2
  (§2.10).
- **What `what` may name.**
  - Deliverables of that compartment, delivered from the bytes the log holds.
  - Its pmmcp records.
  - Engineering files only as indexed records with a `source_path` (P9). The
    kernel fills `source_paths` from the grant, and pmmcp filters on it
    inside the query. Until P9 ships that, a file grant is refused, and only
    deliverables can carry file contents.
- **Execution.** The kernel performs the read through the owning
  compartment's principal and delivers the result to the run. The run's
  lineage gains `(c, ∅)`, marked with the grant's id.
- **Nothing a grant delivers is stored.** A run whose lineage holds a
  grant-marked element cannot `remember` (§2.4, rule 3). The grantee's summary
  carries those elements, so a run that reads it cannot `remember` either, and
  whatever comes from the grant reaches anyone else only through the operator.
- **D6's override** is this grant to the CEO, or a copy with `ceoRelease`. In
  v1 the operator starts it by telling the CEO, in `run.start`'s input, to
  request it, and then approving.

**The standing D5 grant**

- `security/code` (security-reviewer, pentester) reads
  `aos/engineering/shared` and `aos/engineering/index/*`, read-only, through
  `aos-security-code` (P1).
- Its findings stay in `aos/security/code/*`, and its briefs are kernel-filed
  and capped (§2.5).
- A finding reaches `aos/security/shared` only by promotion (§2.8). It reaches
  anyone else only by promotion or an approved copy.
- D5 is about what `security/code` may hold, not what it may receive. A CEO
  brief that carries engineering lineage to a `security/code` child parks like
  any other (§2.4).

**Overrides (D5)**

The operator can overrule every security agent. No security agent can overrule
the operator.

- **In v1.**
  - A security agent's block on a tool call is a pending card. The operator
    resolves it with `approval.approve`, which logs `approval.resolved` and
    carries no reason.
  - A held output is released with `quarantine.release`.
- **From v2 (ask-before):**
  - `override.applied {by, target, reason}`, logged as its own event;
  - a fleet halt and resume;
  - an override of a security veto;
  - the rule that a security agent cannot raise the same block again on an
    action whose block the operator overrode.

  Neither the halt nor the veto exists in code yet.
- **Cutting the D5 grant.**
  - In v1, the operator kills any `security/code` run with `run.kill`, removes
    the grant from `kernel.yaml`, and restarts the daemon. The daemon reads its
    config only at boot.
  - At pmmcp, the operator removes `aos/engineering/shared` and
    `aos/engineering/index/` from `aos-security-code`'s read list and restarts
    pmmcp. Rotating that token instead would also cut `security/code` off from
    its own namespaces.
  - From v2, one suspend command takes effect on the next call.
- **Widening a security run.** In v1 the operator edits the standing config
  grant, and the change stands until edited back. Widening one run needs an
  operator-issued grant, which is v2.

### 2.10 What protocol v1 covers

**Covered.** In each case below, the CEO files a kernel tool and the operator
answers with `approval.approve` or `approval.deny`, after reading the logged
bytes with `events.query`:

- opening an effort, with its members, open set and expiry;
- adding a member;
- a copy, with or without `ceoRelease`;
- a promotion;
- a grant request;
- a parked delegation.

**Not covered.** Each of these needs a protocol v2 command, which is
ask-before, with a version bump and a migration note:

- revoking a grant, an open set or an effort before its expiry;
- suspending D5 live;
- a grant the operator issues;
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
  - id: aos-executive                   # assistant, curator-executive, and the CEO's executive children
    compartment: executive
    read:  ["aos/executive/agent/", "aos/executive/shared", "aos/fleet/shared"]
    write: ["aos/executive/agent/"]
    profile: sector-memory
  - id: aos-ceo                         # the agent `ceo` only
    compartment: executive
    collab_all: true                    # every effort; coding-lineage records only with ceo_release (P2)
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
  # the operator's own clients (recommended, §8): never aos/
  - id: operator-clients
    own_projects: true
    profile: sector-memory
  # the operator's pmmcp CLI; never configured in any MCP client the kernel runs
  - id: operator
    all: true
    profile: all
```

**Startup checks.** pmmcp refuses to start when any of these holds:

- an entry other than `operator` has `all: true` or `profile: all`, or
  `operator` lacks either;
- an entry other than `operator` lacks `token_sha256`, `profile`, or (except
  `operator-clients`) `read` and `write`;
- an entry names a profile not in P3's table;
- two entries share an `id` or a `token_sha256`;
- more than one entry has `collab_all`, or the one that has it is not
  `aos-ceo`;
- an entry other than `operator` and `operator-clients` has a prefix that does
  not start with `aos/`;
- `operator-clients` has `all`, `collab_all`, `compartment`, any prefix, or a
  profile other than `sector-memory`.

**Token check**

- A `TokenVerifier` hashes the presented token and compares it in constant
  time (`hmac.compare_digest`) with each entry.
- It returns `AccessToken(token=<the principal id, never the presented
  bearer>, client_id=<principal id>, scopes=[])`. `AccessToken.token` is a
  required field, and a tool can read it, so it must not hold the bearer.
- No match, or no token: HTTP 401 `invalid_token`. The body never echoes the
  token, and the server never logs it.
- The operator token lives in a named location outside every repository and
  every index root (P9 refuses a root containing it).

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
- **Version pin.** Pin `mcp>=1.27.2,<2` while pmmcp imports
  `mcp.server.fastmcp`, or port it to `MCPServer` and pin `mcp>=2.3,<3` (§1).

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
- **Startup.** pmmcp refuses to start on each of the startup checks above.

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

  The id must be ASCII and is compared exactly as received. The string that
  passed validation is used unchanged for the check, for storage, for the
  Qdrant filter and in SQL. Match with Python's `re.fullmatch`, or end the
  pattern with `\Z`: under `re.match`, `$` also matches before a final
  newline.
- **`operator-clients`.** For it, `project_id` must fullmatch
  `^[a-z0-9][a-z0-9/-]{0,127}$`, must not begin with `aos`, and must contain
  no `//` and no trailing `/`.
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
- **Collaboration members.**
  - A read under `aos/collab/` returns a record only when the record's
    `provenance.members` include the principal's `compartment`.
  - The `collab_all` principal gets every record, except one whose lineage
    names `engineering` or `security/code` and whose `ceo_release` is not true.
  - `operator` gets every record.
  - A write under `aos/collab/` must carry `provenance.members` (non-empty,
    each a compartment that some principal in the principals file holds, never
    `executive`) and `provenance.source`. Otherwise it is refused with
    `invalid_provenance`.
- **Brief cap.** A write into `aos/engineering/brief` or
  `aos/security/code/brief` whose content exceeds 2,000 code points is refused
  with `content_too_long`.
- **Search filters inside the query.** It is a Qdrant `must` exact match on
  the validated `project_id`, plus the members and lineage rules above under
  `aos/collab/`, and P7's filters. Records whose `project_id` is null or
  different are never candidates. A query must not be able to rank or count
  results from another compartment. Timing is covered in §8.
- **Similarity work never mixes records.**
  - Deduplication on `remember`, related-memory links, consolidation and
    `repair_and_heal` compare records of one `project_id` only, and only
    records whose provenance is equal in every field except `runId`,
    `agentId` and `observedAt`.
  - For every principal except `operator`, pmmcp never changes a stored
    record's `project_id`, content or provenance after the write.
  - Writes by `aos-promote`, `aos-collab` and `aos-brief` are never
    deduplicated, merged or rewritten. They stay the bytes the operator
    approved.
  - A merge the operator runs by hand records the union of the lineages,
    `taint: true` and `origin: untrusted` if either record has them, and the
    intersection of the `members`.
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
  whitespace or NUL is refused, each case on its own.

Isolation and answers:

- A memory seeded in `aos/engineering/agent/<id>` appears, under any query in
  a sweep test, only to `aos-engineering` and `operator`.
- One seeded in `aos/engineering/shared` or `aos/engineering/index/x` appears
  only to `aos-engineering`, `aos-security-code` and `operator`.
- One seeded in `aos/engineering/brief` appears only to `aos-engineering`,
  `aos-ceo` and `operator`.
- Collaboration records:
  - one with members `[engineering, marketing]` and no coding lineage is
    returned to `aos-marketing` and `aos-ceo`, never to `aos-trading`;
  - one with engineering lineage and no `ceo_release` is never returned to
    `aos-ceo`;
  - no collaboration record is returned to `aos-executive`.
- An `aos-collab` write whose `members` include `executive` is refused.
- A 2,001-character `remember` into `aos/engineering/brief` from `aos-brief`
  is refused.
- Near-duplicate records whose provenance differs stay two records.
- An existing goal id in another project and a nonexistent goal id get
  byte-identical answers.

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
| `sector-memory` | `recall`, `remember`, `search` (if it exists) |
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

**Kernel impact.** K6b. `GoalArgs`, the writer, the double and its tests gain
the argument. The kernel's owner check stays, as defence in depth.

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

- `create_goal`, `update_goal`, `get_goal_tree`, `list_goals`, `recall` and
  `remember` return typed Pydantic models, so the SDK publishes an
  `outputSchema` and `structuredContent`:
  - `create_goal` and `update_goal` → `{goal_id, project_id, status,
    progress_pct}`;
  - `get_goal_tree` → `{goal_id, children: [...]}`, with ids;
  - `recall` → `{hits: [{id, project_id, content, provenance,
    source_path?}]}`. In the provenance model `runId` and `agentId` are
    `str | None`, and every other field is required;
  - `remember` → `{id, project_id}` and nothing else: no duplicate, related or
    merged record's id, content, provenance or count. A write-only principal's
    reply therefore carries nothing read from storage, which §0 and §8 rely
    on.
- Every root is an **object**, which TS 1.30 requires (wrap lists).
- Every datetime is timezone-aware (Pydantic `AwareDatetime`) and serializes
  with `Z` or an offset. `observedAt` is UTC.
- The serialized JSON is also returned as a text block.
- `tools/list` is one page. Neither FastMCP v1 nor v2 paginates it today (C:
  v1 `server.py:331-346`; v2 `server.py:427-430`).

**Why.** It replaces the kernel's prose parsing with validated data, and it
carries the provenance lineage needs (K11).

**Acceptance**

- Each listed `outputSchema` has `type: object`.
- The kernel's default `Client` (Ajv with ajv-formats) validates every one of
  these results without throwing. That includes:
  - a recall hit carrying provenance;
  - a hit on an indexed record;
  - a goal carrying timestamps.
- A `remember` that duplicates an existing record returns exactly
  `{id, project_id}`.

**Kernel impact.** K8, K11.

- The hub keeps `structuredContent` on both paths.
- The writer reads `goal_id` from it rather than matching `✅ Goal created:`
  or `✅ Goal updated:`.

### P7. Provenance on every memory write

**Change**

- **Required provenance.** From every principal except `operator` and
  `operator-clients`, `remember` requires `provenance {runId, agentId, taint,
  origin: operator|agent|untrusted|system, lineage: [{c, R}], observedAt}`.
  Without it, the call is refused with `provenance_required`.
- **Extra fields for kernel writes.**
  - `aos-collab` writes add `source`, `members`, `copiedBy`, `approvedBy` and
    `ceo_release` (§2.7).
  - `aos-promote` writes add `promotedFrom` and `approvedBy` (§2.8).
  - `aos-brief` writes add `briefOf {runId}`.
- **Server stamps.** pmmcp stamps `writer` (the principal id) and
  `compartment` itself, server side, and ignores any value a call sends for
  them.
- **Lineage check.** pmmcp refuses with `invalid_provenance` a `lineage`
  element whose `c` is not a compartment of P2's grammar. When the writer has
  a compartment, it also refuses a `lineage` that names neither that
  compartment nor an open sub-section of it.
  - An open sub-section is a grammar compartment `<c>/<x>` that no principal
    has as its `compartment`. Here it counts as `<c>`: today
    `marketing/clipping` counts as `marketing`.
  - Once a principal names the sub-section, it is sealed and stops counting
    as its sector.
- **Records no agent wrote.** pmmcp stamps the provenance itself, and ignores
  any value sent, on every record the `operator` or `operator-clients`
  principal stores. That includes everything `index_project` and
  `index_git_history` store. The stamp is `{runId: null, agentId: null,
  origin: operator, taint: false, lineage: [{c: <the namespace's compartment>,
  R: []}], observedAt}`.
- **No provenance, no hit.** A record with no provenance, such as one stored
  before P7, is never returned to a principal other than `operator`.
- **Untrusted text is excluded by default.** For every principal except
  `operator`, `recall` leaves out hits whose origin is `untrusted` or whose
  taint is `true` (`must_not`), unless the call passes `include_untrusted:
  true`.
- **`lineage_within: [compartments]`.** When given, `recall` returns only
  hits whose every lineage element has its `c` in the list.
- **Filters are part of the query.** Both filters are part of P2's query
  filter, never applied to hits afterwards.
- **What a hit returns.** Each hit returns its provenance.
- **Who fills what.** The kernel fills every provenance field,
  `include_untrusted`, `lineage_within` and `source_paths` (P9). The model
  sees none of them, neither in its tool schema (K2) nor in a result (K11).

**Why**

- The designs' rule is that a clean run never recalls untrusted text
  (AF:486-491). That rule needs a field pmmcp can filter on, and today it is
  NEEDS VALIDATION (DECISIONS Q24).
- Lineage (§2.4) needs a carrier that survives between runs.

**Acceptance**

- **Untrusted text.**
  - An untrusted or tainted memory never appears in a recall without
    `include_untrusted`, under any query.
  - A clean record and a tainted near-duplicate in one project stay two
    records.
- **Lineage.**
  - Near-duplicates with lineage `[executive, engineering]` and `[executive]`
    never come back as one hit carrying `[executive]`.
  - A recall with `lineage_within: [executive]` returns no record whose
    lineage names another compartment.
- **Server stamps.**
  - A call under the marketing token that claims `compartment: engineering` is
    stored as marketing.
  - Under the marketing token, a `remember` into
    `aos/marketing/clipping/agent/producer` with lineage `[{c:
    marketing/clipping}]` is stored. With lineage `[{c: engineering}]` it is
    refused.
- **Missing provenance.**
  - A record stored without provenance never appears in a non-operator
    recall.
  - An index record recalled under `aos-security-code` carries lineage
    `[{c: engineering}]`.

### P8. Protocol era

- pmmcp keeps serving 2025-11-25 Streamable HTTP while the kernel is on TS SDK
  1.30.
- **On 2025-11-25**, P2's principal relies on the SDK's session-owner binding
  (`mcp>=1.27.2`). P1's cross-token 404 test is what keeps that safe, so it
  stays in pmmcp's suite. The alternative is `stateless_http=True`, which
  checks the token on every request.
- **On 2026-07-28** there are no sessions, and the token is checked on every
  request.
- Moving the kernel to a 2026-07-28 client is a new dependency
  (`@modelcontextprotocol/client`) and needs the operator's approval.

### P9. Indexing is the operator's

**Change**

- `index_project` and `index_git_history` are operator-only (profile `all`).
- **Roots.** Sources come from an operator-owned `index_roots` map in the
  principals file, `aos/engineering/index/<repo>` → absolute path, and never
  from a tool argument.
- **Resolving a root.** pmmcp resolves each root once with `realpath`. It
  refuses a root that is, contains, or lies inside a forbidden zone below. The
  exception: a root may lie under `$HOME`.
- **Symlinks.** Within a root, pmmcp never follows a symlink. A symlinked file
  or directory is skipped, not read:
  - the walk uses `os.walk(followlinks=False)`;
  - each file is opened with `O_NOFOLLOW` and checked with `fstat` after it is
    opened, so a link swapped in after the walk is not read either.
- **Comparison.** Forbidden zones and files are compared by device and inode
  as well as by spelling, because APFS is case-insensitive.
- **Forbidden.** Each of these is refused as a root and skipped within one:
  - `$HOME` and every ancestor of it;
  - any `.aos/` directory;
  - any `.env*` file, matched case-insensitively;
  - the principals file's directory;
  - the file or keychain item from which pmmcp's CLI reads the operator token
    (P1 names its location);
  - pmmcp's own storage: its SQLite files with their `-wal` and `-shm`,
    Qdrant's storage and snapshot directories, and every backup directory;
  - files matching credential patterns.

  Today's default ignore list skips only an exact `.env` (README.md:142-145).
- **`source_path`.** Every index record stores it: the path relative to its
  root, plus the commit id for git history. `recall` returns it in each hit,
  and accepts `source_paths: [...]`. When that is given, `recall` returns only
  records whose `source_path` is in the list, filtered inside the query.

**Why**

- An index tool reads the disk, and P2 constrains only where the index lands.
  If the kernel could call one, it could pull any directory, another
  compartment's export or a credential into engineering.
- The content of a root comes from more people than the operator: an agent's
  merged change, or a third-party repository. A committed symlink must not
  pull in a file outside the root.

**Acceptance**

- A root holding any of the following indexes none of them, and the walk
  terminates:
  - a symlink named `notes.md` that points to a `.env` file;
  - a relative symlink to a file outside the root;
  - a symlinked directory that points to the root's own parent;
  - a symlink to pmmcp's database.
- A root that is `$HOME` or its parent, or that contains pmmcp's storage or
  the principals file, is refused.
- A recall with `source_paths: [a]` returns no hit from any other file.

**Kernel impact.** The kernel never calls these tools, and `tool-views.yaml`
keeps them kernel-only (invariant 7 names `index_project`). File grants
(§2.9) depend on `source_path`.

## 4. Kernel changes

Each item has its acceptance test. Rules that apply to all of them:

- **Session protocol.** One task, one test, one commit.
- **Mutation coverage.** Each K commit updates `scripts/falsify/catalog.ts` in
  the same commit, with at least one mutant per new refusal or gate rule.
  Several items touch anchored lines:
  - K1: `kernel.ts` (N6);
  - K2: `gate.ts` (N1–N3);
  - K6b and K8: `writer.ts:119, 335` (G13, G15).
- **Changed or deleted tests (ask-before).**
  - K2 changes what `policy-namespace.test.ts:71-92` asserts. A model-sent
    `project_id` becomes a denial, and an absent one becomes a fill.
  - K8 deletes from `pmmcp-drift.test.ts`:
    - the keyArg test (`:128-146`);
    - the keyArg, pinned-name and tool-count assertions (`:109-111`, `:125`);
    - the no-capture block's `get_secret` and 49-tool claims (`:73-85`).

    After P3, no kernel principal's listing shows those tools.
- **Old rows.** The operator's log is permanent, every payload schema is
  strict, and boot re-parses stored rows (§1).
  - A field that K6a, K6b, K7 or K11 adds to an existing payload is added by a
    new schema version (`schemaVersion: 2`), never by editing v1. The kernel
    appends only v2.
  - Code that re-parses stored rows (the tracker, `eval/observe.ts`,
    `eval/checks.ts`) parses the union of v1 and v2.
  - A v1 row has no compartment. Its lineage is unknown, and every lineage
    check treats unknown as failing.
  - `principal` on `hub.*`, and `projectId` on `tool.gate` and `tool.call`,
    are optional v1 fields. A non-pmmcp tool has no `projectId`.
  - The acceptance of each of these items boots once over a fixture log
    written by the commit before it, then passes `verifyChain`.
- **Ask-before for reach and approvals.** Each of these is ask-before, and is
  flagged where it occurs:
  - widenings: delegation to templates (K5), and any kernel tool offered to
    workers;
  - gate changes that compute new facts (K9a);
  - a path that settles an approval from a standing decision (K9);
  - worker output that starts an approval (K13).
- **Exposure.** Exposing any pmmcp tool to an agent, or a new kernel tool to
  the CEO, is a `tool-views.yaml` exposure change, so it is ask-before. This
  contract is what makes such changes safe to propose.

| # | Change | Acceptance test |
|---|---|---|
| K1 | **Compartments, profiles and derived namespaces.** **Manifests:** a standard agent declares `compartment`. A template declares `profiles` (each with exactly one `compartment` and its own `tools.allow`) and has no memory block. **Namespaces:** `memory.projectId` is derived, never declared: `aos/<c>/agent/<id>`, or `aos/executive/ceo` for the agent whose id is `ceo`. `MEMORY_PROJECT` becomes the §2.2 grammar. **The registry refuses:** a template without profiles; a profile without exactly one compartment; `schedule:` on a template; a child whose profile is not in its template; and a manifest with id `ceo` that is not an `executive` orchestrator. **Fleet and eval:** curators become standard agents per compartment. The shipped fleet takes its §2.1 places, with manifest version bumps and history frozen. `ceo-objective-fanout` is rewritten in marketing terms. | `agents-registry.test.ts`: a manifest that declares `memory.projectId` fails to load; a template without profiles fails; a plan naming bare `scout` with two profiles is refused; a scheduled template fails; the four shipped manifests load with their compartments; derived namespaces are unique. |
| K2 | **The kernel sets `project_id`.** The model's schema for a pmmcp memory tool loses the reserved arguments: `project_id`, `provenance`, `include_untrusted`, `lineage_within` and `source_paths`. In their place a read gets a kernel enum, `scope`, which the loop computes on every turn from the run's compartment, efforts and live grants: `own`; `shared:<c>` and `brief:<c>` for each such namespace in the agent's read set; `fleet`; `effort:<id>`; `grant:<id>`; and for the CEO `own:<c>` and `own:all` (§2.4). Each label maps to exactly one `project_id`. A write takes `scope: own`, or `brief:<own compartment>` outside executive, engineering and `security/code`. In `RunLoop.#handleToolCall`, before the gate input is built, the kernel records which reserved names the model sent as a scope fact, `reservedArgs`, and the gate denies when it is not empty. This is the first gate fact (K9a adds the rest). The kernel then maps the label, and fills every reserved argument into the arguments the gate hashes and the hub sends. `include_untrusted` is true only for a run that is already tainted. The hub never adds or rewrites an argument. `namespaceArg: none` is refused for any tool whose live schema declares `project_id`. | `policy-namespace.test.ts`: a model-sent `project_id` writes a `tool.gate` deny row, even the agent's own; `scope: shared:marketing` reaches the double as `aos/marketing/shared`; the CEO's `brief:trading` reaches it as `aos/trading/brief`; an engineering agent has no `brief` scope; a write naming a read scope is denied; the hub refuses when `project_id` changed after the ticket; a clean run's recall never carries `include_untrusted`; a revoked grant's label is gone from the next turn's schema. |
| K3 | **One pmmcp client per principal.** **Binding:** `kernel.yaml` binds each kernel-held principal to what may use it (`mcp.servers.pmmcp.principals.<id>: {tokenEnv, compartments, agents?}`). `aos-ceo` serves the agent `ceo` alone; `aos-executive` every other executive agent; `aos-marketing` both `marketing` and `marketing/clipping`; each other sector principal its own compartment. The kernel-only principals serve no agent. Boot refuses a config in which a registered agent or a profile resolves to zero principals or to more than one. `RunAgent` and `RunScope` gain `compartment` and `principal`. **Calls:** the hub keys clients by (serverId, principal). The loop runs the hub branch of the execute step inside `#inScope`; the kernel-tool branch stays outside, because `kernel.delegate` appends the child's `run.queued`. The hub refuses an agent call when `runScope()` is undefined, when `ticket.runId` differs from the scope's, when the principal is not bound to the scope's agent and compartment, or when the principal is kernel-only. `callKernelOnly`, `describe` and `status` take an explicit principal. **Profiles:** at connect, each client's `tools/list` is compared with its P3 profile and any difference is recorded in `hub.tools.classified{principal}`; the check that degrades lands in its own commit with P3 (§6). **Failures:** a declared `tokenEnv` that is unset degrades that principal by name and boot goes on; a 401 degrades it by name and never retries the same token. Fix the stuck-degraded hub, and retry when pmmcp is down at boot. | `mcp-hub.test.ts`: two runs of different compartments in parallel each reach the double under their own principal; the planner's recall goes out under `aos-executive` and is refused `aos/marketing/brief`; an agent call outside a run scope, or with another run's ticket, is refused; `kernel.delegate` still starts its child; a config in which the assistant resolves to both `aos-ceo` and `aos-executive` fails to boot; a boot with one principal's token unset degrades only that principal. |
| K4 | **Compartments per tool.** `tool-views.yaml` gains `compartments: [...]` on every agent-exposed tool. It is required: an exposed tool without it fails to parse, and there is no default. `tools.servers` is enforced for MCP servers, and the `kernel` server is exempt. The CEO's kernel tools get `compartments: [executive]`: `adopt_plan`, `delegate`, `read_result`, `read_goals`, `open_effort`, `add_member`, `copy_to_collab` and `request_access`. A template profile whose `allow` holds a tool not permitted in its compartment fails to load, and the check runs again when a child is bound. Changing any exposure is ask-before. | `config-files.test.ts`: an engineering-only tool in a marketing agent's `allow` fails to load; an exposed tool without `compartments` fails to parse; the shipped CEO loads; a marketing profile with an engineering tool fails. |
| K5 | **Delegation.** A child's compartment comes from its manifest or its profile (§2.5). Taint is inherited. The result is a typed `RunResult`, and `kernel.read_result` returns the summary and adds the child's lineage. The lineage check (§2.4, rule 1) covers the brief, the plan and `inputRefs`. A failing brief parks through K9a, after the kernel logs `delegation.parked {parentRunId, taskId, target, targetCompartment, lineage, brief, taskText, inputRefs}`. The kernel refuses a brief the redactor would change. A failing `inputRef` is refused, never parked, unless its exact bytes are an approved copy in an effort with the child's compartment as a member. Approval releases the brief to the child (§2.4). At `run.finished` of an engineering or `security/code` run whose manifest sets `filesBrief: true`, the kernel files the run's summary (≤ 2,000 code points) as its brief with `aos-brief`. Delegating to templates is ask-before. | `delegation.test.ts`: a tainted parent's child starts tainted; the CEO's tool result holds no summary until `read_result`; after the CEO reads an engineering summary, a brief to a marketing child, to a `security/code` child and to the planner each park; `delegation.parked` precedes `approval.requested` and its brief is byte-identical to the child's input, a seeded phrase in the last 100 characters included; a clean CEO run reaches `approval.requested` for such a brief; an engineering resultRef as an `inputRef` to a marketing child is refused with no card, and accepted after an approved copy into an effort with both as members; no plan field changes a child's compartment; an eng-lead run's summary lands in `aos/engineering/brief` through `aos-brief`, and one over 2,000 code points is not filed. |
| K6a | **The goals' namespace**, with K1. `goals.projectId` in `kernel.yaml` (default `aos/executive/goals`). `delegate.ts:185, 203`, `kernel.ts:476` and `tracker.ts:203` use it, never an agent's namespace. The writer uses `aos-goals` and sends only the §2.6 fields. `test/helpers/runtime-bodies.ts` exports `liveKernelYaml(base)`, which sets `goals.projectId: aos/executive/live-test` and binds the writer to `aos-goals-live`. `runtime-bodies.test.ts` and `live-runtime.test.ts` build their config through it. liveFleet declares `compartment: executive` for live-ceo. | `goals-writer.test.ts`: every `goal.created` row from a CEO plan carries `aos/executive/goals`; no adoption path passes an agent's namespace to `materialise`; a `runtime-bodies.test.ts` boot through `liveKernelYaml` writes every goal to `aos/executive/live-test`. |
| K6b | **Goals under P4.** The writer adds `project_id` to update and tree calls and keeps the owner check. `requiredArgs` adds `projectId` to `updateStatus` and `get`, so a pre-P4 pmmcp degrades goals at boot, by name. `goal.created` carries the plan's lineage. `kernel.read_goals` returns the tree and adds its lineage. | `goals-writer.test.ts` against the P4 double; a pre-P4 double degrades goals, with a reason naming `update_goal`'s missing `project_id`. |
| K7 | **Events.** `compartment` (and `principal`, where a client is used) on `run.queued`, `run.started`, `tool.gate`, `agent.registered` and `delegation.admitted`. An optional `principal` on `hub.connected`, `hub.degraded` and `hub.tools.classified`. `tool.gate` and `tool.call` carry the `projectId` the kernel filled. Lineage is carried by `run.finished`, the delegation events, `approval.requested` and the hold event, and the approval projection keeps it across a restart. All of this follows the old-rows rule. `status.get` keeps its one `hub` key: it is degraded when any principal is, with a reason that names them, so protocol v1 holds. | `events-types.test.ts`; a booted kernel whose marketing token is refused emits `hub.degraded{principal: aos-marketing}`, and `status.get` names it; an allowed recall's `tool.gate` row names `aos/marketing/agent/writer`; a boot over a pre-K7 log succeeds. |
| K8 | **The double and the drift guard.** **The double** models principals (read, write, compartment, members, `collab_all`, `ceo_release`), profiles enforced at dispatch, the grammar, the brief cap, `isError` codes in both wire forms, structured output, provenance stamping, the operator stamp, the untrusted default and `lineage_within`. **Capture:** `capture:pmmcp` passes `--dotenv .env` and reads each kernel-held principal's token with `oneCredential`, as `scripts/eval.ts` does. It writes one fixture per principal (`test/fixtures/pmmcp-listtools.<principal>.json`), with `outputSchema` and the resource and prompt lists. CLAUDE.md's and README's lists of `.env` readers add it. `compareCapture` checks each fixture against its P3 profile. The deleted drift assertions (§4 rules) move to a capture the operator takes with pmmcp's own tooling. No script here reads the operator token. **Structured content:** `callKernelOnly` returns `structuredContent`, and `McpHub.call` keeps it for K11. **Writer:** it first accepts both the P6 result and today's prose, for create and for update; a later commit removes the prose. | `mcp-pmmcp-double.test.ts`, `pmmcp-drift.test.ts`. |
| K9 | **Collaboration efforts and copies** (§2.7). `kernel.open_effort`, `kernel.add_member` and `kernel.copy_to_collab` are orchestrator kernel tools. **Prepare step:** `KernelToolHandler` gains an optional `prepare(args, ctx)`. `RunLoop.#handleToolCall` calls the pure `decide()` on the model's arguments first. If that denies, or the agent is not an orchestrator, or the model supplied a `sha256`, the call is denied and `prepare` never runs. Otherwise `prepare` resolves the source, refuses what §2.7 refuses, logs `collab.copy.proposed`, and returns the arguments with `sha256` added. The gate input is built from those. **Coverage:** whether a copy needs a fresh approval is the kernel-computed fact `copyCovered` (K9a). It is true only for a clean run whose source lineage is fully released to the members or in the open set. **Write:** it uses `aos-collab` with the §2.7 provenance, and the kernel keeps only `{id, project_id}` from the reply. **Projection:** effort records (members, open set, expiry, status) are projected from the log, so they survive a restart. | `collab.test.ts`: without approval nothing is written; a copy whose escaped length is exactly `PAYLOAD_TEXT_BUDGET`, holding newlines and quotes and ending in a seeded phrase, is in the log in full before approval and lands byte-identical; one escaped byte more is refused with nothing logged; a truncated source is refused; a worker's or an unlisted caller's call resolves nothing and logs no `collab.copy.proposed`; a copy from a tainted run lands `untrusted`; a CEO copy whose lineage holds engineering is approved per copy, even with marketing in the open set; a tainted CEO run's covered copy still parks; a non-member's recall returns nothing; a new member sees only later copies. |
| K9a | **Gate facts.** The gate stays pure. Every fact is computed by the kernel before `decide()` runs, and the model never sets one. The facts: `human: always` on a tool view (`open_effort`, `add_member`, `request_access`, with `risk: write`, so the tier-2 CEO still loads); `delegationFits` for `kernel.delegate`; and `copyCovered` for `kernel.copy_to_collab`. `reservedArgs` came with K2. The rules run after rule 5, the taint rule, so a tainted run always needs a human. Changing the gate, and settling a call from a standing decision, are ask-before, with a falsify mutant per rule, one of which moves `copyCovered` ahead of the taint rule. | `policy-gate.test.ts`: each fact's verdict; a clean CEO's `open_effort` and `add_member` park; a lineage-failing delegation from a clean CEO parks; the shipped CEO loads with all eight kernel tools. |
| K10 | **Grants and overrides** (§2.9). `kernel.request_access` grants to the requesting run, for that run. A grant read goes through the owning principal and adds `(c, ∅)` marked with the grant's id. A run whose lineage holds a grant-marked element has every `remember` denied before the gate. A file grant is refused until P9's `source_path` ships; then the kernel fills `source_paths`. The D5 grant lives in config (`grants: [{compartment: security/code, reads: [aos/engineering/shared, aos/engineering/index/*]}]`), read at boot. In v1, overrides are approvals (§2.9). The v2 commands (§2.10) are ask-before and ship after the operator approves the bump. | `grants.test.ts`: a grant read happens only after approval, only for the requesting run, and never after it ends; the CEO's lineage gains the compartment; that run's `remember` is denied in every scope; a file grant before P9 is refused; with P9, a grant on one indexed file returns no hit from another; comms-triage's run never reaches `aos-security-code`'s client. |
| K11 | **Lineage** (§2.4). **Run state:** `RunScope` gains `lineage`, a set of `(c, R)` elements the kernel computes for every run. **Reading recall hits:** on the agent path, `McpHub.call` keeps `structuredContent`. For a pmmcp memory read, the hub renders the model's text from it as each hit's `id`, `project_id` and `content`, with no provenance, and `tool.result.text` logs the same bytes (D18). The hub returns the union of the hits' lineage, computed before any truncation, and logs it on `tool.result` as `lineageAdded`. A memory read with missing or invalid `structuredContent`, or with a hit lacking lineage, fails closed: it is an error to the model and passes no content. **Stamping:** the kernel logs each `remember`'s returned id with the lineage it stamped, and on recall unions that into the hit's lineage (defence against a server-side merge). Every `remember` stamps the provenance (runId, agentId, taint, `origin` `untrusted` if tainted else `agent`, lineage, `observedAt`). **Rules:** the write rule (§2.4, rule 2) is a denial before the gate. Summaries, grants, briefs, collaboration records, cards and goals add lineage as §2.4 says. The CEO's `own:*` labels fill `lineage_within`. | `lineage.test.ts`: a CEO run that read typed results only delegates to marketing with no human; one that read a marketing brief and a trading brief parks a brief to either with no effort, and passes one under an effort with both in its open set; a marketing run that recalled an engineering-sourced copy has its `remember` into marketing memory denied; a recall hit's `tool.result.text` holds no `provenance` key; a double that answers `remember` with an existing id still makes a later recall add the remembered lineage; a recall without `structuredContent` reaches the model as an error. |
| K12 | **Migration.** Retire `aos/ceo`, `aos/shared`, `aos/agent/researcher`, `aos/agent/writer` and `aos/agent/aos-live-test` together with K1 and K6a, **before the first pmmcp write**. The first write can be any of these: the first `npm run eval`; any `AOS_LIVE_PMMCP_WRITES=1` run; or any pmmcp-connected orchestrator run. An orchestrator writes goals mid-run through `kernel.adopt_plan` (`risk: write`, so a clean run needs no human), and at `run.finished` when `goals.adoptFromRuns` is true. Both Phase 0 exit runs are such runs. If either comes before K1 and K12, the operator records in README's exit checklist whether its log holds a `plan.adopted` or `goal.created` row. If one does, the operator removes those goals with pmmcp's own CLI before K12's check. `LIVE_TEST_PROJECT` becomes `aos/<c>/agent/aos-live-test` for memory. README gives the check as `list_goals` on each retired id, plus pmmcp's own CLI for memories; the operator runs it outside the kernel. | Boot refuses a manifest with an old namespace; `runtime-bodies.ts` holds no namespace outside the §2.2 grammar; a boot with the live config writes no goal outside `aos/executive/live-test`. |
| K13 | **Memory promotion** (§2.8), ask-before. A worker proposes only through typed `RunResult.proposals[]` entries. The kernel resolves the target (own `shared`; `aos/security/shared` for `security/code`; or `aos/fleet/shared`) and refuses any other. It applies §2.7's size, redaction and truncation rules, refuses a tainted source, and logs `promote.proposed` with the bytes. It then files a `kind: tool` approval of `kernel.promote`, a tool never offered to a model, with the sha256 hashed. Every promotion is approved per item. The write uses `aos-promote` with the §2.8 provenance. | `promote.test.ts`: nothing is written without approval; a marketing proposal targeting `aos/engineering/shared` is refused; a tainted source is refused; a `security/code` finding reaches `aos/security/shared` only after its own approval; the bytes written equal the bytes logged. |

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
    sent without `provenance` and passes only on `namespace_denied` or
    `project_id_required`. P2 checks the namespace first, so a regressed pmmcp
    answers `provenance_required` and stores nothing;
  - it checks the positive reads of items 5 and 6 only as recalls that are not
    refused, never printing hits. That each read returns the seeded record is
    checked offline.
- **Outside this repository.** The operator checks item 12, and clears the
  live-test namespaces, with pmmcp's own CLI.
- No file in this repository names the operator token.

The items:

1. **Seed.**
   - One distinctive memory into each compartment's agent and shared
     namespaces.
   - One into every brief except executive's.
   - One collaboration record per member pair, with and without coding
     lineage.
   - One record in `aos/engineering/index/x`.
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
6. **The CEO's reach** is exactly the `aos-ceo` read list in P1:
   - every brief;
   - the shared namespaces of compartments other than engineering and
     `security/code`;
   - collaboration records without coding lineage, plus coding ones with
     `ceo_release`;
   - fleet;
   - its own namespace.

   It never reaches any compartment's `agent` namespaces,
   `aos/engineering/shared`, `aos/security/code/shared` or any
   `aos/engineering/index/*`.
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
9. **Untrusted text.** Untrusted hits never come back without
   `include_untrusted`.
10. **Lineage, grants and approvals.** Each of these seeded engineering
    phrases never reaches a non-engineering run's input, memory or
    `llm.request` without an operator approval of those bytes:
    - one in an engineering child's summary;
    - one in an engineering brief;
    - one in a granted read;
    - one in a collaboration copy.

    Also:
    - a seeded phrase in the brief of a parked CEO delegation never appears in
      the `llm.request` of the assistant, warden or any run other than the
      CEO's own and, after approval, the approved child's;
    - a run that used a grant stores nothing.
11. **Event log (D7).** warden's `events.search` with `text` set to a seeded
    engineering phrase matches nothing over:
    - a CEO run that read it through a summary or a grant;
    - a `security/code` run that recalled it under D5.
12. **Operator-only checks** (run outside this repository).
    - The operator token sees everything.
    - Requests without a token to 8765 and to Qdrant are refused.

## 6. Order of work

1. **Operator:** commit the current pmmcp capture (`npm run capture:pmmcp`).
   It is the "before" picture for the drift test.
2. **Honest results, kernel first.**
   1. The hub and writer part of K8: `callKernelOnly` returns
      `structuredContent`, and the writer accepts both the structured and the
      prose form, for create and for update.
   2. pmmcp **P5 + P6**.
   3. A kernel commit that removes the prose path and replaces falsify G13 and
      G15.

   P6 removes the `✅ Goal updated:` text the writer confirms against, so the
   order matters. pmmcp and the kernel live in separate repositories, so
   shipping them "together" does not set the order.
3. **The compartment itself.**
   1. Kernel **K1, K6a, K2, K4, K12**, landing together.
      - Without K6a, once K1 ships every adopted plan writes its goals into
        `aos/executive/ceo`, which `aos-goals` cannot write once P2 ships.
      - K12 needs K1's grammar.
      - These must land before the first pmmcp write (K12's row), even if
        nothing else in this list has started.
   2. Kernel **K3**, with the profile difference only recorded.
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

   **Gate:** leak-matrix items 1–7 and 12 pass before step 4.
4. pmmcp **P4**, with kernel **K6b**.
5. pmmcp **P7**. Then kernel **K11, K9a, K5, K7**. P7 ships before any recall
   is exposed to an agent.
6. Kernel **K9, K10, K13**. **Gate:** leak-matrix items 8–11.
7. The protocol v2 commands (§2.10), after the operator approves the bump.

After each pmmcp change: re-capture per principal, update the double, and let
the drift test show exactly what moved.

## 7. Decisions

### 7.1 The operator's answers (2026-10-17)

| # | Question | Operator's answer | How this spec encodes it |
|---|---|---|---|
| D1 | Sector list | "marketing should have clipping as a sub-section" | Five sectors. `marketing/clipping` is an open sub-section of marketing (§2.1). `security/code` is a sealed one: the standing rule requires it once D5 lets those two agents read code. |
| D2 | What the CEO sees | "as much visibility as the ceo needs to make the informed decisions" | Typed results always. Summaries on request. Every brief, the shared namespaces of compartments other than engineering and `security/code`, and every collaboration record except unreleased coding ones. Grants cover anything more (§2.3, §2.9). Lineage keeps it from passing any of this on without the operator, and efforts let cross-compartment objectives run without an approval each time (§2.4, §2.7). |
| D3 | Shared knowledge | "as big as it needs for agents to collaborate" | No cap on any shared or collaboration space. The one cap is one event's worth per copy (`PAYLOAD_TEXT_BUDGET`, about 62 KiB after JSON escaping), so the operator can read each copy whole. `aos/fleet/shared` holds whatever every compartment needs, by promotion (§2.7, §2.8). |
| D4 | Data between sectors | "it shouldn't 'move', it should be copied to the collaboration space … when needed" | Copies into per-effort collaboration spaces. The original stays put, the copy carries provenance and lineage, and approvals follow §2.7. A copy is judged on what its source holds, not on where it ran. |
| D5 | Security agents and code | "sounds about right, but we want to be able to override the security agents if necessary" | A read-only grant for `security/code` only, under its own principal. Its findings stay sealed and reach others only by promotion or copy. The operator can resolve every security block, can release a held output, and can cut the grant. The rest of the override set is protocol v2 (§2.9, §2.10). |
| D6 | Engineering summaries to the CEO | "unless we override it and need the CEO to know the file contents" | Summaries and kernel-filed briefs may name files, functions and errors. Both are capped at 2,000 characters, and no artifact body is handed over. File contents reach the CEO only through an operator grant, or a copy the operator released to it (§2.5, §2.9). R8 names the residual. |
| D7 | The event log | "Leave as is" | One log for the operator. Over every run whose compartment is `engineering` or `security/code`, or whose lineage holds either, warden's `events.search` returns metadata only. It takes no `text` filter there, because a substring match over payloads is a payload read. That covers the CEO's runs and grant-holding runs. A run whose lineage the kernel cannot establish counts as engineering. A payload read of any run needs a human: warden-forensics, on operator request (OS:189). |

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
  - release held output;
  - cut the D5 grant;
  - widen a security run.

  In v1, resolving a block, releasing output, and cutting or widening the
  standing grant by a config edit all work. Overrides that record a reason,
  halts, vetoes and per-run widening are v2.
- **R4. The CEO's direct reads.** The CEO reads the shared namespaces of
  compartments other than engineering and `security/code` directly. It reads
  those two only through capped briefs, summaries, grants and released copies.
- **R5. The shipped researcher** is placed in marketing, and
  `ceo-objective-fanout` is rewritten to match. The other two eval cases are
  unchanged.
- **R6. What D7 leaves open.**
  - warden's metadata (event types, run and agent ids, counts, cost) still
    covers every compartment.
  - Its `text` filter still works over runs that are not in engineering or
    `security/code` and whose lineage holds neither. Over marketing, trading
    and executive runs, that filter is a cross-compartment read under the "all
    sectors separate" rule.
  - Closing it would make every agent's `events.search` compartment-scoped,
    with warden getting kernel-computed aggregates elsewhere.
- **R7. Who curates engineering memory.** eng-lead, through promotion
  proposals, or the operator. A `curator-engineering` agent exists only if the
  operator adds its manifest.
- **R8. What D6 still allows.** Summaries and briefs are model-written, so one
  can quote up to 2,000 characters of code, and many together can quote more.
  The stricter alternatives are briefs the kernel renders from typed fields
  only, or an operator approval per engineering brief.
- **R9. Visibility costs unattended delegation.** Lineage is per run, and the
  CEO's memory and goals carry it into later runs.
  - A CEO run that reads several compartments' briefs, with no effort open,
    parks every brief it writes to them. The planner is included.
  - Efforts with an open set, and the CEO's `own:*` recall labels, are the
    tools for keeping delegation unattended.
  - Tracking lineage per brief rather than per run is not an alternative,
    because the kernel cannot tell which part of a context a brief came from.
- **R10. Who starts an override.** In v1 the operator can only approve what
  the CEO requests. To start a D6 override, the operator tells the CEO to ask.
  Grants the operator issues directly are v2.
- **R11. The CEO's executive children** (planner, judge#exec,
  worker-template) may hold non-coding data for the run they are delegated,
  never coding data. They cannot store foreign data (§2.4, rule 2). The
  alternative is to treat them like the assistant, which parks every brief
  that carries another compartment's data.

### 7.3 Design-doc conflicts these decisions resolve

Kept so the next design pass can amend the docs:

- **Shared memory.**
  - The flat `aos/shared` (AF:483, 489) becomes per-compartment `shared`
    plus `aos/fleet/shared`.
  - implementer#docs writing to `aos/shared` (EN:247).
- **The CEO's reads.**
  - CEO recall over `aos/agent/*` (EX:410) becomes briefs, summaries,
    grants and copies, under lineage.
- **Curation and promotion.**
  - The curator reading every sector (EX:453) becomes standard curators per
    compartment, and none for engineering (R7).
  - Promotion as the curator's own `remember` into `shared` (EX:343, AF:175)
    becomes a typed proposal and the kernel's write after approval (K13).
  - Pentest findings mirrored fleet-wide by the projection writer with no
    approval (OS:191, 225, 515) stay in `security/code`, and reach
    `security/shared` only by promotion.
- **Templates and children.**
  - Shared templates recalling "the spawner's namespace" (EN:180, GR:239,
    TR:405) get their profile's compartment read set.
  - The delegation envelope that intersects `memory.projectId` (EX:130) is
    replaced: children get their compartment's read set.
  - scout and judge "spanning sectors" (AF:240, AF:542, TR:87) become profiles
    with one compartment each.
- **Plans and delegation.**
  - `inputRefs` injected into later children (EX:122, 166) are checked
    against lineage, and refused unless released.
  - A lead's `ProposedPlan` adopted into goals (EX:59, 243) carries the
    lead's lineage.
- **Approvals.**
  - Tainted-write and promotion cards deferred into the assistant's digest,
    and the kernel bundle's pending approvals (EX:363, 510), become counts
    only.
  - A declassification scoped by objective only (EX:205) is now released per
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
- **Timing.** In one shared Qdrant collection, a compartment can time its own
  recalls to estimate how much the others store. Closing that means one
  collection per principal, a change to pmmcp's storage. This revision
  accepts the channel.
- **The operator's own tools.** The `operator` principal sees everything, by
  design. A Claude Code session on an untrusted repository could be
  prompt-injected into reading trading or CRM data through it. Recommended:
  give the operator's MCP clients the `operator-clients` principal, limited to
  the operator's own `project_id`s outside `aos/`, and keep `all` for pmmcp's
  CLI.

## 9. Needs validation before implementing

- pmmcp's `mcp` version: v1 FastMCP or v2 MCPServer, and whether it is at
  least 1.27.2.
- Whether pmmcp's recall filters `project_id` inside the Qdrant query today,
  and whether a project-scoped recall also returns global (null-project)
  records.
- Whether `remember` deduplicates, links or consolidates records, and how.
- Whether Qdrant's payload filter can express P7's `lineage_within` (every
  element of an array in a set) without a precomputed field.
- The real name and arguments of `search`, if it exists, and the real
  arguments of `index_project`.
- Whether index records can carry `source_path` (P9).
- Whether pmmcp registers resources, resource templates or prompts, and what
  other routes it serves on 8766.
- What the dashboard on 8765 shows.
- Whether anything is already stored under `aos/` (K12), including goals from
  any Phase 0 exit run.
- Whether `get_secret` takes `project_id` live. After P3 this matters only to
  the operator.
