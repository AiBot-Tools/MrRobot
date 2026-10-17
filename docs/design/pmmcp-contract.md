# pmmcp ↔ kernel contract: compartments

Status: **draft, revision 2** (2026-10-17). Not implemented on either side.

- Revision 1 wrote decisions D1–D7 on recommended defaults. The operator
  answered them on 2026-10-17. §7 records each answer and how this text
  encodes it, and lists the readings the operator may want to change.
- Revision 2 also folds in an adversarial review of revision 1 by four lenses
  (isolation red-team, pmmcp on the Python SDK, kernel fit, facts), each
  finding checked by a skeptic. What it found is fixed in the text below.

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
- **Kernel changes (K1–K12, §4)**, for this repository. The kernel puts every
  agent in exactly one compartment, addresses only the namespaces that
  compartment may reach, holds one pmmcp credential per principal, and tracks
  where the data inside a run came from (lineage, §2.4).

What each wall can and cannot catch:

- pmmcp catches a kernel that addresses the wrong namespace with a correctly
  chosen principal. It cannot catch a kernel that picks the wrong principal
  for a run; K3's cross-check is the guard for that.
- Once data is inside a run's context, only the kernel's lineage rules stop it
  moving on (§2.4). pmmcp never sees a prompt.
- The kernel's write-only principals (promotion, collaboration copies, goals)
  reach only their fixed namespaces and read nothing. pmmcp still cannot
  verify that a human approved a given write (§8).

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

- One memory namespace per agent, from a fixed shape:
  `aos/ceo | aos/shared | aos/agent/<id>` (`src/agents/manifest.ts:28`).
- No compartment concept anywhere in `src/`.
- No pmmcp tool is exposed to any agent (`config/tool-views.yaml`).
- The gate **checks** the `project_id` the model sends and never **sets** it
  (`src/policy/gate.ts:122-145`). CLAUDE.md, README.md:389-390 and
  tool-views.yaml:15-18 require it to set the id before `recall` or
  `remember` is exposed. K2 meets that requirement.
- One pmmcp client, one session, at most one bearer (`src/mcp/hub.ts`).
- Kernel tools are offered to, and run for, orchestrators only
  (`src/agents/registry.ts:150`, `src/runtime/loop.ts:437`).
- A delegation brief (≤ 8,000 characters) becomes the child's prompt verbatim
  (`src/runtime/delegate.ts:51, 300-302`). The child's `finalText` comes back
  to the parent (`:370`). A delegated child does not inherit its parent's
  taint (`src/kernel.ts:613`).
- A `needs-human` card carries a 500-character preview of the canonical
  arguments (`src/policy/engine.ts:81`). Protocol v1's approval kinds are
  `tool` and `promotion` only (`src/control/protocol.ts:123`).
- `MAX_LOGGED_OUTPUT` is 65,536 bytes (`src/events/bound.ts:23`).

## 2. The compartment model

### 2.1 Compartments (D1)

Five sectors, two of which contain a sub-section:

| Compartment | Holds | Agents (from docs/design) |
|---|---|---|
| `executive` | goal tree, adopted plans, mandates, CEO memory | ceo, planner, assistant, judge¹, curator¹ |
| `engineering` | **all coding data**: code knowledge, ADRs, module maps, design system, incident notes, indexed repositories and git history | eng-lead, prototyper, sre, architect, implementer, tester, reviewer, release, scout¹ |
| `marketing` | marketing, social, community, sales: brand kit, ICP, drafts, CRM-adjacent notes | marketer, writer, community, sales, publisher, researcher, checker{brand,policy,facts}, reporter, focus-group, scout¹ |
| `marketing/clipping` | clipping and production: captions, renders, clip plans, media checks | producer, checker{media} |
| `trading` | theses, signals, strategy cards, backtests, journals | quant, executor, bookkeeper, market-scout, critic¹ |
| `security` | warden reports and fleet security findings that cite no code | warden, evaluator, comms-triage |
| `security/code` | code review and pentest work under the D5 grant | security-reviewer, pentester |

There are two kinds of sub-section:

- **Open** (`marketing/clipping`). It is part of marketing. Every marketing
  agent reads it, and clipping agents read marketing. Both run under the
  marketing principal (P1). Its own namespaces keep clipping work organised,
  and an edit to the principals file would seal it later.
- **Sealed** (`security/code`). Only its own agents read it. They hold the D5
  read grant into engineering, so what they find stays away from warden,
  evaluator and comms-triage. comms-triage is always tainted and will take
  inbound SMS and Telegram.

¹ A template that serves several compartments (scout, judge/critic, curator)
declares which ones in its manifest (`compartments: [...]`, edited by the
operator). §2.5 says how a child gets one. A template serves `engineering` only
if its manifest lists it. That entry is the operator's statement that the
template does coding work.

**The shipped fleet**:

- ceo → `executive`.
- writer → `marketing`.
- researcher → `marketing`. It is a web researcher, and GR:110 folds the
  standing researcher into growth.
- worker-template → a template with `compartments: [executive]`.

The one eval case (`src/eval/suite.ts`) researches the kernel's own event log,
which is engineering material. K1 rewrites its objective in marketing terms,
so both children stay in one compartment.

### 2.2 Namespaces

This grammar replaces `MEMORY_PROJECT`. `<c>` is a compartment from §2.1.

```
aos/<c>/agent/<id>             an agent's own memory (episodic)
aos/<c>/shared                 the compartment's curated knowledge (promoted by a human)
aos/<c>/brief                  decision-grade reports the compartment writes for the CEO (D2)
aos/engineering/index/<repo>   an indexed repository and its git history (P9)
aos/executive/ceo              the CEO's own memory (sealed: the CEO only)
aos/executive/goals            the goal tree (kernel only, §2.6)
aos/executive/live-test        goals written by the gated live tests
aos/collab/<effort>            one collaboration effort's space (D3, D4; §2.7)
aos/fleet/shared               knowledge every compartment may read (promoted by a human)
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

"Read" means recall, search and list. Writes into `shared`, `collab` and
`fleet` are made by the kernel with a write-only principal (P1), and only
after the approval the row names.

| Namespace | Read | Write |
|---|---|---|
| `aos/<c>/agent/<id>` | that agent, and `c`'s curator² | that agent, by a gated `remember` |
| `aos/<c>/shared` | agents of `c`; the CEO, except for `engineering` and `security/code` | **only** the kernel, for an operator-approved promotion |
| `aos/<c>/brief` | agents of `c`; the CEO | agents of `c`, by a gated `remember` |
| `aos/engineering/index/<repo>` | `engineering`; `security/code` (D5) | **only** the operator's indexing (P9) |
| `aos/executive/ceo` | the CEO | the CEO, by a gated `remember` |
| `aos/executive/goals` | the kernel only; the CEO sees the tree through kernel tools | the kernel only (§2.6) |
| `aos/collab/<effort>` | agents of the effort's member compartments; the CEO | **only** the kernel, for an approved copy (§2.7) |
| `aos/fleet/shared` | every agent | **only** the kernel, for an operator-approved promotion |

"Agents of `c`" includes the parent sector's agents when `c` is the open
sub-section, and the sub-section's agents when `c` is `marketing`.

² pmmcp's wall is the compartment: any agent of `c` holds the principal that
could read every `aos/<c>/agent/*`. Keeping an agent to its own namespace is
the kernel's read set (K2). The CEO's memory is curated by the operator.
Engineering's promotions are proposed by eng-lead or the operator. The shared
curator template proposes them only if its manifest lists `engineering` (§2.1
footnote ¹).

Rules that apply across the table:

- **Cross-compartment reads exist only as grants in config.** Each one is
  read-only and the operator's decision. The one standing grant is D5:
  `security/code` reads `aos/engineering/shared` and `aos/engineering/index/*`.
- **The CEO's wider reach (D2) belongs to the CEO alone.** planner, assistant,
  judge and curator in executive read no brief and no other compartment.
- **Coding data leaves engineering only five ways**: the D5 grant, an approved
  copy into a collaboration space (§2.7), an operator grant (§2.8), the CEO's
  own reads under D2 and D6, and a parked delegation the operator approves.
  Lineage (§2.4) keeps whatever reaches the CEO, or a run holding a grant,
  from going any further without the operator.
- **Approval cards stay with the compartment that asked.** An approval card,
  its preview and any held output belong to the compartment of the run that
  asked. No agent-facing bundle (the assistant's digest, a CEO continuation,
  warden) carries another compartment's previews or held outputs. Such a
  bundle shows counts per compartment and class, nothing more.

### 2.4 Lineage: the CEO sees what it needs and passes none of it on

D2 gives the CEO as much visibility as it needs to decide, and D6 lets the
operator show it file contents. The CEO then holds other compartments' data in
its context. A model can repeat anything in its context into anything it
writes. Without a rule, the CEO would be an unguarded hub between
compartments. Lineage is that rule.

- **Definition.** A run's lineage is the set of compartments whose data has
  entered its context. It starts as `{own compartment}`.
- **Who it grows for.** It grows only for runs that read beyond their own
  compartment:
  - the CEO, through briefs, other compartments' shared namespaces,
    collaboration spaces, summaries and grants;
  - `security/code`, through the D5 grant;
  - any run that holds an operator grant.
- **Who computes it.** The kernel. The model never sets it and never sees it.
- **What adds to it:**
  - a recall hit adds the lineage in the hit's provenance (P7);
  - a child's summary text adds the child's lineage (§2.5);
  - a brief, a shared or collaboration record, or a granted read adds the
    compartment it came from.
- **What does not add to it:** the kernel's typed fields. These are status,
  cost, taint, the acceptance results and evidence verdicts the kernel
  computed, and deliverable kinds and refs. The kernel renders them, and no
  model wrote them.
- **What it constrains:**
  - **Delegation.** A brief, a plan's task text and its `inputRefs` carry the
    lineage of the run and of the plan they came from. The kernel starts a
    child in compartment B only when that lineage, minus `executive`, lies
    within B and B's grants (an open sub-section and its sector count as
    one). Otherwise it parks the delegation as
    `needs-human`. The full brief is already in the log, so the operator
    reads it before deciding. If approved, the child starts with lineage
    `{executive, B}`: the operator has released that brief.
  - **Memory.** Every `remember` carries the run's lineage in its provenance,
    so a later recall brings the lineage back.
  - **Plans and goals.** An adopted plan carries the adopting run's lineage,
    and so does each goal written from it.
- **`executive` is not a restriction.** A CEO brief to any child is executive
  data, and every compartment may receive it.

In practice, the CEO reads typed results freely and can delegate anywhere. If
it asks for an engineering summary or file contents, its run gains
`engineering`. Any brief it then writes for a marketing child waits for the
operator.

### 2.5 Templates, children and delegation

**A child's compartment**

- A standard agent's compartment is the one in its manifest.
- A template declares `compartments: [...]`. A child's compartment comes from
  kernel config keyed by (parent, template), never from any field of a plan.
  Under invariant 3, the model never makes an access-control decision. When a
  template lists one compartment, the child gets that one. A plan naming a
  template that lists several compartments, with no configured choice, is
  refused.

**What a child can reach**

- A child gets its own compartment's read set plus that compartment's config
  grants, intersected with what the template declares. It inherits nothing
  from its parent's reach.
- Tier, egress, tools and budget follow the parent ∩ template rule (EX:130).
- Taint passes from parent to child (K5). Today it does not
  (`kernel.ts:613`).

**What comes back to the CEO**

- The kernel's typed `RunResult`: status, cost, taint, the kernel's
  acceptance results, and evidence and deliverable refs.
- The child's summary is at most 2,000 characters and is written by the
  child's model. It comes back only when the CEO asks for it, and asking adds
  the child's lineage to the CEO's run (§2.4).
- Raw memory never comes back.

**Engineering summaries (D6)**

- An engineering summary may name files, functions and errors. It carries no
  file contents.
- The kernel enforces what it hands over: no recall into engineering's own
  namespaces, no artifact bodies, and the 2,000-character cap.
- It cannot stop a child's model from quoting a few lines. Lineage keeps such
  a quote from going any further.
- File contents reach the CEO only through an operator grant (§2.8).

**Delegating to a template** is ephemeral spawning, which no tool does yet
(CLAUDE.md). Building it widens what agents can reach, so it is ask-before.

### 2.6 Goals

- The goal tree lives in `aos/executive/goals`. Only the kernel writes it,
  with the `aos-goals` principal (P1). No agent's principal can read or move a
  goal.
- **What the kernel sends.**
  - To `create_goal`: only `project_id`, `goal_type`, `title` (≤ 200
    characters) and `parent_goal_id`.
  - To `update_goal`: only `goal_id`, `project_id`, `status` and
    `progress_pct`.
  - Never description, acceptance criteria, related files, blockers or tags.
- **Lineage.** A goal carries its plan's lineage in the kernel's
  `goal.created` record. When a plan comes from a sector lead's `ProposedPlan`
  (EX:59), its titles are that compartment's data and carry its lineage. When
  the kernel shows the CEO the tree, the goals' lineage joins the CEO's run.
- Sector agents never touch goals. The kernel moves task status from the run
  lifecycle, as it does today.
- P4 makes pmmcp enforce the namespace on every goal call, so no goal can be
  read or moved by id alone.

### 2.7 Collaboration efforts and copies (D3, D4)

Data never moves between compartments. When agents of different compartments
work together, the data they need is **copied** into a collaboration space,
and the original stays where it is.

**Efforts**

- An effort has a title, an objective, a set of **member compartments**, and
  the space `aos/collab/<effort>`.
- The CEO proposes an effort with `kernel.open_effort`. The operator approves
  it, because the member set is an access decision.
- Adding a member later takes the same approval.
- Members are compartments with a principal of their own. The open
  sub-section joins as `marketing`.

**Size**

- An effort's space is as large as the collaboration needs. There is no cap on
  the space.
- A single copy is at most `MAX_LOGGED_OUTPUT` (64 KiB), because the operator
  must be able to read every byte before approving it.
- Larger material goes in as several copies.

**A copy**

An orchestrator files it with `kernel.copy_to_collab {effort, source}`. The
source is bytes the kernel already holds: a run's deliverable or summary, as
logged. To copy a stored memory, a run of the source compartment first recalls
it into its deliverable. Workers do not file copies; letting them would widen
what agents can reach, so it is ask-before.

1. The kernel resolves the source bytes. It refuses any byte string the log's
   redactor would change (a registered secret or a credential shape), so the
   bytes the operator reads are exactly the bytes that get written.
2. The kernel logs `collab.copy.proposed`, carrying:
   - the full bytes and their sha256;
   - the source compartment, run and taint;
   - the effort.

   It then adds the sha256 to the call's arguments before the gate hashes
   them, so an approval binds those exact bytes.
3. Approval follows the source compartment's copy policy:
   - for `engineering` and `security/code`, **the operator approves each
     copy** (`perCopy`);
   - for every other compartment, the operator approves either each copy, or
     once with a **standing approval** for that compartment in that effort
     (`perEffort`). A standing approval is logged, scoped to one effort, and
     revocable.
4. The kernel writes the bytes into `aos/collab/<effort>` with the
   `aos-collab` principal (P1). The provenance is `{source: {compartment, runId,
   sha256}, sourceTaint, copiedBy, approvedBy, members}`. A copy from a tainted
   run is stored as `origin: untrusted` (P7).

**Reading, release and closing**

- **Reading.** The CEO and agents of a member compartment read the space.
  pmmcp returns a record only to a principal whose compartment is in that
  record's `members` (P2).
- **Release.** An approved copy is released to the member compartments.
  - If a member derives memory from it, that memory stays in the member's own
    compartment.
  - Only another approved copy carries it further.
- **Close.** The kernel stops offering the effort to any run and refuses new
  copies. The space stays in pmmcp; nothing is deleted.

**The fleet space**

`aos/fleet/shared` behaves as an effort whose members are every compartment. A
promotion into it follows the strictest copy policy of the compartments its
source came from.

**Protocol v1 is enough.** Opening an effort, copying and requesting a grant
are all `kind: tool` approvals of kernel tools. The operator reads the full
bytes with `events.query` before `approval.approve`.

### 2.8 Operator grants and overrides (D5, D6)

**Grants**

A grant lets one run, or one agent for one objective, read something its
compartment cannot.

- The CEO requests one with `kernel.request_access {compartment, what,
  objectiveId, reason}`. `what` names deliverables or pmmcp records of that
  compartment. For engineering files, that means files a run returned as
  deliverables, or the indexed copy in `aos/engineering/index/*`. The operator
  approves it as a `HumanActor`.
- **Limits.** A grant is scoped to one objective or one run, time-boxed and
  revocable. Granting, each use, and revoking are logged.
- **Execution.** The kernel performs the read through the owning
  compartment's principal and delivers the result to the run. The run's
  lineage gains that compartment. Agents never hold a grant's credential.
- D6's "the CEO knows the file contents" is exactly this: an operator-approved
  grant to the CEO on named engineering files.

**The standing D5 grant**

- `security/code` (security-reviewer, pentester) reads
  `aos/engineering/shared` and `aos/engineering/index/*`. The grant is
  read-only and uses its own principal, `aos-security-code` (P1).
- Its findings stay in `aos/security/code/*`.
- A finding reaches `aos/security/shared`, warden or anyone else only through
  an approved copy, under engineering's `perCopy` policy.

**Overrides (D5)**

The operator can overrule every security agent. No security agent can overrule
the operator.

- **Resolving a block.** Every block, veto, halt or quarantine a security
  agent raises can be resolved by an explicit `HumanActor` override that
  carries a reason.
- **Its own event.** The override is logged as its own event
  (`override.applied {by, target, reason}`), never as a side effect of
  approving something else.
- **No re-raise.** Once the operator overrides a block on an action, no
  security agent can raise the same block on that same action again.
- **Cutting the grant.** The operator can suspend or revoke the D5 grant at
  once. The kernel stops routing `security/code` reads into engineering on the
  next call. Rotating the `aos-security-code` token cuts it off at pmmcp too.
- **Widening.** The operator can widen a security run for one task with an
  ordinary grant.
- **What exists today.** A held tool call is overridden with today's
  `approval.approve`. A fleet halt or a security veto needs a new control
  command, and that is protocol v2 (ask-before). Neither the halt nor the veto
  exists in code yet.

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
  # one per compartment (trading is shaped like engineering)
  - id: aos-engineering                 # becomes the token's client_id
    token_sha256: "<hex>"               # sha256 of the token; the token is never stored
    compartment: engineering
    read:  ["aos/engineering/", "aos/collab/", "aos/fleet/shared"]
    write: ["aos/engineering/agent/", "aos/engineering/brief"]
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
    write: ["aos/security/code/agent/", "aos/security/code/brief"]
    profile: sector-memory
  - id: aos-executive                   # planner, assistant, judge, curator
    compartment: executive
    read:  ["aos/executive/agent/", "aos/executive/shared", "aos/collab/", "aos/fleet/shared"]
    write: ["aos/executive/agent/"]
    profile: sector-memory
  - id: aos-ceo
    compartment: executive
    collab_all: true                    # reads every effort, whatever its members
    read:  ["aos/executive/ceo", "aos/executive/shared",
            "aos/engineering/brief", "aos/marketing/brief", …every brief…,
            "aos/marketing/shared", "aos/marketing/clipping/shared",
            "aos/trading/shared", "aos/security/shared",
            "aos/collab/", "aos/fleet/shared"]
    write: ["aos/executive/ceo"]
    profile: sector-memory
  # kernel-only principals
  - id: aos-goals
    read:  ["aos/executive/goals", "aos/executive/live-test"]
    write: ["aos/executive/goals", "aos/executive/live-test"]
    profile: goals
  - id: aos-promote                     # write-only
    read:  []
    write: ["aos/engineering/shared", "aos/marketing/shared", …every shared…, "aos/fleet/shared"]
    profile: write-only
  - id: aos-collab                      # write-only
    read:  []
    write: ["aos/collab/"]
    profile: write-only
  # the operator's pmmcp CLI; never configured in any MCP client the kernel runs
  - id: operator
    all: true
    profile: all
```

**Startup checks.** pmmcp refuses to start when:

- an entry other than `operator` has `all`;
- more than one entry has `collab_all`;
- two entries share a hash;
- an entry other than `operator` has a prefix that does not start with
  `aos/`.

**Token check**

- A `TokenVerifier` hashes the presented token and compares it in constant
  time (`hmac.compare_digest`) with each entry.
- It returns `AccessToken(token=<the principal id, never the presented
  bearer>, client_id=<principal id>, scopes=[])`. `AccessToken.token` is a
  required field, and a tool can read it, so it must not hold the bearer.
- No match, or no token: HTTP 401 `invalid_token`. The body never echoes the
  token, and the server never logs it.

**SDK configuration**

- Construct FastMCP (or MCPServer) with `token_verifier=<verifier>` and
  `auth=AuthSettings(issuer_url="http://127.0.0.1:8766",
  resource_server_url=None)`, with no `required_scopes`.
- `resource_server_url=None` is what stops the SDK publishing a metadata
  document. Also remove pmmcp's hand-built RFC 9728 document.
- Remove every other custom route on 8766, or wrap each in
  `RequireAuthMiddleware`.
- Pin `mcp>=1.27.2` on v1, or use 2.x (§1, the session-owner binding).

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

- No token → 401. A wrong token → 401, and the token is absent from the body
  and from the logs.
- Every route of the served Starlette app answers 401 without a token.
  `GET /.well-known/oauth-protected-resource` answers 404.
- Each principal opens a session. A session opened with one principal's token
  and then used with another's gets 404 "Session not found".
- A call under the marketing token that carries `_meta.client_id: "operator"`
  or `"aos-engineering"` is still refused `aos/engineering/*`.
- Requests without a token to 8765 and to Qdrant's REST and gRPC ports are
  refused.
- pmmcp refuses to start on each of the startup checks above.

**Kernel impact.** K3. The token name of each kernel-held principal enters
`.env` through `credentialNames`. The operator token's name appears nowhere in
this repository.

### P2. Server-side namespace enforcement

**Change**

- **Where the principal comes from.** It is the verified token of the
  current request: `get_access_token().client_id` (sound under P1's version
  pin), or the authenticated user on the current Starlette request. It is
  never `Context.client_id`, and never anything else in `_meta`.
- **Grammar first.** For any principal other than `operator`, `project_id`
  must fullmatch one of these, or the call is refused with
  `namespace_denied`:

  ```
  ^aos/(executive|engineering|marketing|marketing/clipping|trading|security|security/code)/(agent/[a-z0-9][a-z0-9-]{0,63}|shared|brief)$
  ^aos/engineering/index/[a-z0-9][a-z0-9-]{0,63}$
  ^aos/executive/(ceo|goals|live-test)$
  ^aos/collab/[a-z0-9][a-z0-9-]{0,63}$
  ^aos/fleet/shared$
  ```

  The id must be ASCII and is compared exactly as received. The string that
  passed validation is used unchanged for the check, for storage, for the
  Qdrant filter and in SQL.
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
  names one. P2 can therefore ship before P4 without refusing the kernel's
  goal moves.
- **Collaboration members.**
  - A read under `aos/collab/` returns only records whose `members` include
    the principal's `compartment`; a `collab_all` principal gets every record.
  - A write under `aos/collab/` must carry `members` (non-empty, valid
    compartment names) and `source`.
- **Search filters inside the query.** It is a Qdrant `must` exact match on
  the validated `project_id`, and on `members` under `aos/collab/`. Records
  whose `project_id` is null or different are never candidates. A query must
  not be able to rank or count results from another compartment. Timing is
  covered in §8.
- **Similarity work stays inside one project.** Deduplication on `remember`,
  related-memory links, consolidation and `repair_and_heal` compare records of
  one `project_id` only. No merge changes a record's `project_id`.
- **Order of checks.** Principal, then namespace, then existence, then
  everything else. An id-addressed object outside the principal's read set
  gets exactly the answer a nonexistent one gets (`goal_not_found`,
  `not_found`).
- **Record ids are random** (uuid4), never a global sequence.

**Why.** The kernel can be wrong, and pmmcp is the last wall.

**Acceptance**

With the marketing token:

- `recall(project_id: "aos/engineering/shared", …)` is refused.
- `recall` with no `project_id` is refused.
- `recall(project_id: "aos/marketing/shared", query: <a phrase stored only in
  engineering>)` returns zero hits.

For every sector principal:

- `remember` into `aos/fleet/shared`, into any `shared`, under `aos/collab/`,
  or into another compartment is refused.
- With `aos-security-code`, `remember` into `aos/engineering/*` is refused.
- A `project_id` holding `..`, `//`, a trailing `/`, uppercase, U+0456, `%2F`,
  whitespace or NUL is refused, each case on its own.

Isolation and answers:

- The engineering token recalls its own memory.
- A seeded engineering memory never appears in any other principal's results,
  under any query, in a sweep test.
- A collaboration record with members `[engineering, marketing]` is returned to
  `aos-marketing` and `aos-ceo`, never to `aos-trading`.
- An existing goal id in another project and a nonexistent goal id get
  byte-identical answers.

### P3. A tool profile per principal

**Change**

`tools/list` returns only the tools in the principal's profile, and **the call
path refuses every other tool**. Filtering the listing is not enough, because
FastMCP dispatches any registered tool by name (`lowlevel/server.py:482-496,
531-541`).

- On v1, a FastMCP subclass overrides `list_tools()` and `call_tool()`. Both
  are registered as bound methods (`fastmcp/server.py:318-329`). Each
  resolves the principal as P2 says.
- On v2, override `_handle_list_tools`/`_handle_call_tool`, or mount one
  server per profile behind a verifier that accepts only that profile's
  principals.

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

Resources and prompts, for every principal except `operator`:

- `resources/list`, `resources/templates/list` and `prompts/list` return
  empty lists;
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
  `project_id`. Each is refused unless the goal is stored in that project and
  the project passes P2.
- `create_goal` refuses a `parent_goal_id` stored outside the given project.

**Why.** Today any caller holding a goal id can read or move any project's
goal. The kernel guards against this only with its own `goal.created` log.

**Acceptance**

- `update_goal(goal_id: <a goal in aos/executive/goals>, project_id:
  "aos/marketing/…")` is refused.
- The same call under the marketing token is refused with exactly the answer a
  nonexistent goal gets.

**Kernel impact.** K6. `GoalArgs`, the writer, the double and its tests gain
the argument. The kernel's owner check stays, as defence in depth.

### P5. Real errors

**Change**

- **How a refusal is raised.** Every refusal is
  `raise ToolError(f"{code}: {message}")`.
- **What the client receives.** Raised in a tool body, it reaches the client
  as one text block, `Error executing tool <tool>: <code>: <message>`, with
  `isError: true`. Raised before dispatch (for example `tool_not_in_profile`
  from an overridden `call_tool`), it arrives as `<code>: <message>`. The
  kernel and the double both match
  `^(?:Error executing tool [a-z_]+: )?([a-z_]+): `.
- **Codes** are stable snake_case:
  - `goal_not_found`, `not_found`, `invalid_transition`, `invalid_status`,
    `parent_not_found`, `invalid_goal_type`, `progress_out_of_range`;
  - `namespace_denied`, `project_id_required`, `tool_not_in_profile`,
    `provenance_required`;
  - `internal_error`.
- **Argument errors.** A required argument that is missing or malformed is
  refused by the SDK, with pydantic's text and no code. The kernel treats an
  `isError` result without a code as `invalid_arguments`.
- **Unexpected exceptions.** Every tool body catches any exception other than
  `ToolError` and raises `ToolError("internal_error: see server log")`,
  because v1 forwards an exception's text to the client.
- **What a message may say.** A message never quotes a secret or another
  compartment's data. Checks run in P2's order, so a refusal never reveals,
  for example, the status of another compartment's goal.
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
  - `recall` → `{hits: [{id, project_id, content, provenance}]}`.
- Every root is an **object**, which TS 1.30 requires (wrap lists).
- Every datetime is timezone-aware (Pydantic `AwareDatetime`) and serializes
  with `Z` or an offset. `observedAt` is UTC.
- The serialized JSON is also returned as a text block.
- `tools/list` is one page. Neither FastMCP v1 nor v2 paginates it today (C:
  v1 `server.py:331-346`; v2 `server.py:427-430`).

**Why.** It replaces the kernel's prose parsing with validated data.

**Acceptance**

- Each listed `outputSchema` has `type: object`.
- The kernel's default `Client` (Ajv with ajv-formats) validates every one of
  these results without throwing. That includes a recall hit carrying
  provenance and a goal carrying timestamps.

**Kernel impact.** K8.

- The hub reads `structuredContent`, which it drops today.
- The writer reads `goal_id` from it rather than matching `✅ Goal created:`
  or `✅ Goal updated:`.

### P7. Provenance on every memory write

**Change**

- From every principal except `operator`, `remember` requires
  `provenance {runId, agentId, taint, origin: operator|agent|untrusted|system,
  lineage: [compartments], observedAt}`. Without it, the call is refused with
  `provenance_required`.
- pmmcp stamps `writer` (the principal id) and `compartment` itself, server
  side, and ignores any value a call sends for them. It refuses a `lineage`
  that names an unknown compartment, or that leaves out the writer's own
  compartment when the writer has one.
- **`recall` excludes untrusted text by default.** For any principal except
  `operator`, hits whose origin is `untrusted` or whose taint is `true` are
  left out unless the call passes `include_untrusted: true`. The exclusion is
  part of P2's query filter, not a filter applied to hits afterwards.
- Each hit returns its provenance.
- The kernel fills every provenance field and `include_untrusted`. The model
  never sees them (K2, K11).

**Why**

- The designs' rule is that a clean run never recalls untrusted text
  (AF:486-491). That rule needs a field pmmcp can filter on, and today it is
  NEEDS VALIDATION (DECISIONS Q24).
- Lineage (§2.4) needs a carrier that survives between runs.

**Acceptance**

- An untrusted or tainted memory never appears in a recall without
  `include_untrusted`, under any query.
- A call under the marketing token that claims `compartment: engineering` is
  stored as marketing.

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
- Their sources come from an operator-owned `index_roots` map in the
  principals file, `aos/engineering/index/<repo>` → absolute path, and never
  from a tool argument.
- pmmcp refuses as a source, or skips within a root:
  - `$HOME` itself;
  - any `.aos/` directory;
  - any `.env*` file;
  - the principals file's directory;
  - files matching credential patterns.

  Today's default ignore list skips only an exact `.env` (README.md:142-145).

**Why.** An index tool reads the disk, and P2 constrains only where the index
lands. If the kernel could call one, it could pull any directory, another
compartment's export, or a credential into engineering.

**Kernel impact.** None. The kernel never calls these tools, and
`tool-views.yaml` keeps them kernel-only (invariant 7 names `index_project`).

## 4. Kernel changes

Each item has its acceptance test. Rules that apply to all of them:

- **Session protocol.** One task, one test, one commit.
- **Mutation coverage.** Each K commit updates `scripts/falsify/catalog.ts` in
  the same commit, with at least one mutant per new refusal. Several items
  touch anchored lines:
  - K1: `kernel.ts` (N6);
  - K2: `gate.ts` (N1–N3);
  - K6 and K8: `writer.ts:119, 335` (G13, G15).
- **Changed test guarantees.** K2 changes what `policy-namespace.test.ts:71-92`
  asserts: a model-sent `project_id` becomes a denial, and an absent one
  becomes a fill. Changing a test's guarantee is ask-before.
- **Widenings** are ask-before, and are flagged where they occur: delegation
  to templates (K5), and any kernel tool offered to workers.
- **Exposure.** Exposing any pmmcp tool to an agent is a `tool-views.yaml`
  exposure change, so it is ask-before. This contract is what makes such a
  change safe to propose.

| # | Change | Acceptance test |
|---|---|---|
| K1 | **Compartments in manifests.** A standard agent declares `compartment`; a template declares `compartments: [...]` and has no memory block. `memory.projectId` is derived, never declared: `aos/<c>/agent/<id>`, or `aos/executive/ceo` for the CEO. So no agent can claim a `shared`, `brief`, `collab` or `goals` namespace as its own. `MEMORY_PROJECT` becomes the §2.2 grammar. The registry refuses a template without compartments, and a child whose compartment is not in its template's list. The shipped fleet takes its §2.1 places (manifest version bumps, with history frozen), and the eval case is rewritten in marketing terms. | `agents-registry.test.ts`: a manifest that declares `memory.projectId` fails to load; a template without `compartments` fails; the four shipped manifests load with their compartments; derived namespaces are unique. |
| K2 | **The kernel sets `project_id`.** The model's schema for a pmmcp memory tool loses `project_id`, `provenance` and `include_untrusted`, from both `properties` and `required`. In their place a read gets a kernel enum, `scope`, whose values label the agent's read set: `own`, `shared`, `brief`, `fleet`, one label per effort it belongs to, and one per grant. A write takes `scope: own` or `brief`. In `RunLoop.#handleToolCall`, before the gate input is built, the kernel maps the label to a `project_id` and writes it into the arguments the gate hashes and the hub sends. In the same place it writes provenance (K11) and `include_untrusted`, which is true only for a run that is already tainted. The hub never adds or rewrites an argument. Any `project_id`, `provenance` or `include_untrusted` the model supplies is denied, whatever its value. `namespaceArg: none` is refused for any tool whose live schema declares `project_id`. | `policy-namespace.test.ts`: a model-sent `project_id` is denied, even the agent's own; `scope: shared` reaches the double as `aos/marketing/shared`; a write naming a read scope is denied; the hub refuses when `project_id` changed after the ticket; a clean run's recall never carries `include_untrusted`. |
| K3 | **One pmmcp client per principal** (`mcp.servers.pmmcp.principals.<id>.tokenEnv`). The hub keys clients by (serverId, principal). `RunAgent` and `RunScope` gain `compartment`, set from the registry. The client comes from the compartment in the agent's manifest, looked up by agentId at call time, and the hub refuses the call when that disagrees with the `RunScope`. It never takes a principal from a ticket, an argument or ambient state. `LoopOptions.agentView` takes the compartment. `callKernelOnly`, `describe` and `status` take an explicit principal: the goal writer and its boot check use `aos-goals`, promotions `aos-promote`, copies `aos-collab`, and grant reads the owning compartment's principal. At connect, each client's `tools/list` must equal its profile exactly, or that principal is degraded by name. A 401 degrades that principal by name and never retries the same token. Fix the stuck-degraded hub, and retry when pmmcp is down at boot. | `mcp-hub.test.ts`: two runs of different compartments, in parallel, each reach the double under their own principal; the double refuses a marketing run an engineering namespace; a client listing a tool outside its profile is degraded. |
| K4 | **Compartments per tool.** `tool-views.yaml` gains `compartments: [...]` on every agent-exposed tool. It is required: an exposed tool without it fails to parse, and there is no default. `tools.servers` is enforced for MCP servers, and the `kernel` server is exempt. `kernel.adopt_plan`, `kernel.delegate`, `kernel.open_effort`, `kernel.copy_to_collab` and `kernel.request_access` get `compartments: [executive]`. A template whose `allow` holds a tool not permitted in every compartment it declares fails to load, and the check runs again when a child is bound. Changing any exposure is ask-before. | `config-files.test.ts`: an engineering-only tool in a marketing agent's `allow` fails to load; an exposed tool without `compartments` fails to parse; the shipped CEO loads; a template bound to marketing with an engineering tool fails. |
| K5 | **Delegation.** The child's compartment comes from its manifest or from kernel config (§2.5), and delegation to a multi-compartment template with no configured choice is refused. Taint is inherited. The result is a typed `RunResult`; the summary is included only on request, and including it adds lineage. The lineage check (§2.4) covers the brief, the plan and `inputRefs`, and parks a failing delegation as `needs-human`. `inputRefs` from another compartment's run are refused unless a copy exists. Delegating to templates is ask-before. | `delegation.test.ts`: a tainted parent's child starts tainted; the CEO's tool result holds no summary unless asked for; after the CEO reads an engineering child's summary, a brief to a marketing child is parked, and a seeded engineering phrase from that summary reaches no marketing run's input until the operator approves; no plan field changes a child's compartment. |
| K6 | **Goals.** Add `goals.projectId` to `kernel.yaml`, default `aos/executive/goals`. `delegate.ts:185, 203`, `kernel.ts:476` and `tracker.ts:203` use it, never an agent's namespace. The writer uses `aos-goals`, sends only the §2.6 fields, adds `project_id` to update and tree calls once P4 ships, and keeps the owner check. `requiredArgs` adds `projectId` to `updateStatus` and `get`, so a pre-P4 pmmcp degrades goals at boot, by name. `goal.created` carries the plan's lineage. Live-test goals go to `aos/executive/live-test`. | `goals-writer.test.ts` against the P4 double; every `goal.created` row from a CEO plan carries `aos/executive/goals`; a pre-P4 double degrades goals, with a reason naming `update_goal`'s missing `project_id`. |
| K7 | **Events.** `compartment` on `run.queued`, `run.started`, `tool.gate`, `agent.registered` and `delegation.admitted`. An optional `principal` on `hub.connected`, `hub.degraded` and `hub.tools.classified`, so old rows still parse. `tool.gate` and `tool.call` carry the `projectId` the kernel filled. `run.finished` and the delegation events carry lineage. `status.get` keeps its one `hub` key: it is degraded when any principal is, with a reason that names them, so protocol v1 holds. A UI filter by compartment is a v2 change and ask-before. | `events-types.test.ts`; a booted kernel whose marketing token is refused emits `hub.degraded{principal: aos-marketing}`, and `status.get` names it; an allowed recall's `tool.gate` row names `aos/marketing/agent/writer`. |
| K8 | **The double and the drift guard.** The double models principals (read, write, compartment, members), profiles enforced at dispatch, the grammar, `isError` codes in both wire forms, structured output, provenance stamping and the untrusted default. `capture:pmmcp` reads each kernel-held principal's token through `--dotenv` and writes one fixture per principal (`test/fixtures/pmmcp-listtools.<principal>.json`). Each fixture includes `outputSchema` and the resource and prompt lists. `compareCapture` checks each fixture against its P3 profile. The `get_secret`, pinned-name and tool-count checks move to a capture the operator takes with pmmcp's own tooling, outside this repository. No script here reads the operator token. `callKernelOnly` returns `structuredContent`. The writer first accepts both the P6 result and today's prose, for create and for update; a later commit removes the prose. | `mcp-pmmcp-double.test.ts`, `pmmcp-drift.test.ts`. |
| K9 | **Collaboration efforts and copies** (§2.7). `kernel.open_effort` and `kernel.copy_to_collab` are orchestrator kernel tools. Opening an effort always needs a human. A copy needs one unless a standing approval covers it, and the gate checks that the standing approval is logged, unexpired and from a `HumanActor`. `collab.copy.proposed` logs the full bytes (≤ `MAX_LOGGED_OUTPUT`) and their sha256, and the sha256 joins the hashed arguments. Bytes the redactor would change are refused. The write uses `aos-collab`, with provenance, and a tainted source lands as `origin: untrusted`. Effort records (members, standing approvals, status) are projected from the log, so they survive a restart. | `collab.test.ts`: without approval nothing is written; a 64 KiB copy whose last 100 bytes are a seeded phrase is in the log in full before approval and lands byte-identical after; a copy from a tainted run lands `untrusted`; bytes holding a credential shape are refused; a non-member compartment's recall of the effort returns nothing. |
| K10 | **Grants and overrides** (§2.8). `kernel.request_access`, from the CEO, needs a human. Grant records (scope, expiry, revocation) are projected from the log. A grant read goes through the owning principal and adds lineage. The D5 grant lives in config (`grants: [{compartment: security/code, reads: [aos/engineering/shared, aos/engineering/index/*]}]`) and can be suspended and revoked. The `override.applied` event type, plus the rule that a security agent cannot re-raise a block the operator overrode. The control command for halts and vetoes is v2 (ask-before) and ships with those features. | `grants.test.ts`: a grant read happens only after approval, only in scope, and never after revocation or expiry; the CEO's lineage gains the compartment; suspending the D5 grant stops `security/code`'s next engineering read; comms-triage's run never reaches `aos-security-code`'s client. |
| K11 | **Lineage** (§2.4). `RunScope` gains `lineage`, which the kernel computes. Recall hits add their provenance lineage, summaries add the child's, and grants and briefs add their compartment. Every `remember` stamps it, with the rest of the provenance: runId, agentId, taint, `origin` (`untrusted` if tainted, else `agent`) and `observedAt`. `plan.adopted` and `goal.created` carry it, and K5 checks it at delegation. | `lineage.test.ts`: a CEO run that read typed results only delegates to marketing with no human; one that read an engineering summary is parked; a phrase recalled from a record with engineering lineage parks the next marketing brief; model-supplied provenance is denied (K2). |
| K12 | **Migration.** Retire `aos/ceo`, `aos/shared`, `aos/agent/researcher`, `aos/agent/writer` and `aos/agent/aos-live-test` **before the first pmmcp write**: the first `npm run eval`, any pmmcp-connected CEO run that can adopt a plan (`goals.adoptFromRuns: true`), or any `AOS_LIVE_PMMCP_WRITES=1` run. The Phase 0 exit run (`run ceo "reply with the word pong"`) writes nothing to pmmcp. `LIVE_TEST_PROJECT` becomes `aos/<c>/agent/aos-live-test` for memory and `aos/executive/live-test` for goals. README gives the check as `list_goals` on each of those exact ids, plus pmmcp's own CLI for memories. The operator runs it, outside the kernel: before P1 no token is needed; after P1, with the operator's CLI. | Boot refuses a manifest with an old namespace; `runtime-bodies.ts` holds no namespace outside the §2.2 grammar. |

## 5. End-to-end acceptance: the leak matrix

The release test for this contract.

- **Offline**, every item runs against the double.
- **Live** (`AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_WRITES=1`):
  - it uses only the kernel-held principals' tokens;
  - it seeds only `aos/<c>/agent/aos-live-test` in each compartment, and goals
    only in `aos/executive/live-test`;
  - it never writes a `shared`, `brief`, `collab` or `fleet` namespace;
  - it runs items 2–7 and 9 over the namespaces it seeded, and the refusals
    over the rest.
- **Outside this repository.** The operator checks item 11, and clears the
  live-test namespaces, with pmmcp's own CLI.
- No file in this repository names the operator token.

The items:

1. **Seed.** Seed one distinctive memory into each compartment's agent,
   shared and brief namespaces. Add one collaboration record per member pair,
   and one record in `aos/engineering/index/x`.
2. **Cross reads.** For every (principal, namespace) pair outside that
   principal's read list:
   - recall, search and list are refused;
   - a recall within the principal's own namespaces using the target's
     phrase returns nothing.
3. **Cross writes.** Every sector principal's `remember` is refused into
   `aos/fleet/shared`, any `shared`, `aos/collab/` and any other compartment.
   For `aos-security-code`, `remember` into engineering is refused too.
4. **Malformed calls.** Each of these is refused for every principal except
   `operator`:
   - a call with no `project_id`;
   - each grammar edge case from P2;
   - a call with a spoofed `_meta.client_id`.
5. **D5 and the sealed sub-section.**
   - `aos-security-code` reads engineering's shared and index namespaces, and
     writes neither.
   - `aos-security` reads nothing of `security/code` or `engineering`.
6. **The CEO's reach** is exactly its read list: briefs, the shared
   namespaces of compartments other than engineering, collaboration spaces,
   fleet, and its own namespace. It never reaches engineering's agent, shared
   or index namespaces.
7. **Goals.**
   - A goal can be read and moved only with `aos-goals`.
   - An existing goal id in another project and a nonexistent id give
     identical answers.
8. **Copies.**
   - A copy without approval writes nothing.
   - A collaboration record reaches only member principals.
9. **Untrusted text.** Untrusted hits never come back without
   `include_untrusted`.
10. **Lineage and approvals.**
    - A seeded engineering phrase in an engineering child's summary never
      reaches a non-engineering child's input or memory without an operator
      approval.
    - A seeded phrase in a pending engineering approval never appears in any
      executive run's `llm.request`.
11. **Operator-only checks** (run outside this repository).
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
   1. Kernel **K1, K2, K4, K12**. K12 comes forward because it needs K1's
      grammar. K1 and K12 must land before the first pmmcp write (K12's row),
      even if nothing else in this list has started.
   2. Kernel **K3**. `kernel.yaml` names the principals' `tokenEnv`s only in
      the change where the operator's `.env` holds every token. The loader
      refuses the whole file over one placeholder line, and a declared but
      unset `tokenEnv` refuses boot. pmmcp still ignores bearers at this
      point.
   3. pmmcp **P1**, with the principals file.
   4. pmmcp **P2 + P3 + P9**.

   **Gate:** leak-matrix items 1–7 and 11 pass before step 4.
4. pmmcp **P4**, with kernel **K6**.
5. pmmcp **P7**. Then kernel **K11, K5, K7**. P7 ships before any recall is
   exposed to an agent.
6. Kernel **K9, K10**. **Gate:** leak-matrix items 8–10.

After each pmmcp change: re-capture per principal, update the double, and let
the drift test show exactly what moved.

## 7. Decisions

### 7.1 The operator's answers (2026-10-17)

| # | Question | Operator's answer | How this spec encodes it |
|---|---|---|---|
| D1 | Sector list | "marketing should have clipping as a sub-section" | Five sectors. `marketing/clipping` is an open sub-section of marketing (§2.1). `security/code` is a sealed one, which D5 requires. |
| D2 | What the CEO sees | "as much visibility as the ceo needs to make the informed decisions" | The CEO always gets typed results. It gets summaries when it asks, plus every brief, the shared namespaces of compartments other than engineering, and every collaboration space. Grants cover anything more (§2.3, §2.8). Lineage keeps it from passing any of this on (§2.4). |
| D3 | Shared knowledge | "as big as it needs for agents to collaborate" | No cap on any shared or collaboration space. The one cap is 64 KiB per copy, so the operator can read each copy whole. `aos/fleet/shared` holds whatever every compartment needs, promoted by a human (§2.7). |
| D4 | Data between sectors | "it shouldn't 'move', it should be copied to the collaboration space … when needed" | Copies into per-effort collaboration spaces. The original stays put, the copy carries provenance, and approvals follow §2.7. The inbox and handoff of revision 1 are gone. |
| D5 | Security agents and code | "sounds about right, but we want to be able to override the security agents if necessary" | A read-only grant for `security/code` only, under its own principal; its findings stay sealed. The operator can override every security block, halt or veto, and can suspend or revoke the grant (§2.8). |
| D6 | Engineering summaries to the CEO | "unless we override it and need the CEO to know the file contents" | Summaries may name files, functions and errors. File contents reach the CEO only through an operator grant (§2.5, §2.8). |
| D7 | The event log | "Leave as is" | One log for the operator. warden's `events.search` over engineering runs is metadata only, and that rules out the `text` filter as well, because a substring match over payloads is a payload read. Payload reads need a human. |

### 7.2 Readings the operator may want to change

The rest of the spec is written on these readings. None blocks work.

- **R1. Clipping is open both ways within marketing.** The alternative is to
  seal it like `security/code`.
- **R2. Copy approval.** Engineering and `security/code` copies need an
  approval each time. Copies from other compartments can be approved one at a
  time or by a standing approval per effort. The alternatives are per copy
  everywhere, or standing approvals for engineering too.
- **R3. "Override the security agents".** This is read as three powers: the
  operator can overrule any block, halt or veto; suspend or revoke the D5
  grant; and widen one security run with a grant.
- **R4. The CEO's direct reads.** The CEO reads non-engineering shared
  namespaces directly. It reads engineering only through briefs, summaries and
  grants.
- **R5. The shipped researcher.** It is placed in marketing, and the eval case
  is rewritten to match.
- **R6. What D7 leaves open.** D7 restricted warden only over engineering
  runs. warden therefore still reads the payloads of marketing and trading
  runs, which is a cross-compartment read under the "all sectors separate"
  rule. Closing it would make every agent's `events.search` compartment-scoped,
  with warden getting kernel-computed aggregates elsewhere.
- **R7. Who curates engineering memory.** Engineering memory is curated by
  eng-lead or the operator. The shared curator template does it only if its
  manifest lists `engineering`.

### 7.3 Design-doc conflicts these decisions resolve

Kept so the next design pass can amend the docs:

- The flat `aos/shared` (AF:483, 489) becomes per-compartment `shared` plus
  `aos/fleet/shared`.
- CEO recall over `aos/agent/*` (EX:410) becomes briefs, summaries and grants,
  under lineage.
- The curator reading every sector (EX:453) runs per compartment; engineering
  per R7.
- Promotion as the curator's own `remember` into `shared` (EX:343) becomes a
  proposal; the kernel writes after approval, with `aos-promote`.
- Pentest findings mirrored fleet-wide by the projection writer with no
  approval (OS:191, 225, 515) stay in `security/code`. They reach
  `security/shared` only by an approved copy.
- implementer#docs writing to `aos/shared` (EN:247).
- Shared templates recalling "the spawner's namespace" (EN:180, GR:239,
  TR:405) get their bound compartment's read set.
- `inputRefs` injected into later children (EX:122, 166) are checked against
  lineage.
- A lead's `ProposedPlan` adopted into goals (EX:59, 243) carries the lead's
  lineage.
- Tainted-write and promotion cards deferred into the assistant's digest, and
  the kernel bundle's pending approvals (EX:363, 510), are shown across
  compartments as counts only.
- `events.search` with `text` over every payload (OS:74, 473) is governed by
  D7 as encoded.
- A declassification scoped by objective only (EX:205) is now also scoped by
  compartment.
- The delegation envelope that intersects `memory.projectId` (EX:130) is
  replaced: children get their compartment's read set.

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
- **Lineage is kernel-only.** pmmcp stores it and never sees a prompt.
- **The write-only kernel principals** (`aos-promote`, `aos-collab`,
  `aos-goals`) reach only their own namespaces, and the first two read
  nothing, so a kernel bug cannot exfiltrate through them. pmmcp cannot verify
  that a human approved a given write. A signed approval the kernel cannot
  forge belongs to Phase 5.
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
  give the operator's MCP clients a principal limited to the operator's own
  `project_id`s outside `aos/`, and keep `all` for pmmcp's CLI.

## 9. Needs validation before implementing

- pmmcp's `mcp` version: v1 FastMCP or v2 MCPServer, and whether it is at
  least 1.27.2.
- Whether pmmcp's recall filters `project_id` inside the Qdrant query today,
  and whether a project-scoped recall also returns global (null-project)
  records.
- Whether `remember` deduplicates across projects.
- The real name and arguments of `search`, if it exists, and the real
  arguments of `index_project`.
- Whether pmmcp registers resources, resource templates or prompts, and what
  other routes it serves on 8766.
- What the dashboard on 8765 shows.
- Whether anything is already stored under `aos/` (K12).
- Whether `get_secret` takes `project_id` live. After P3 this matters only to
  the operator.
