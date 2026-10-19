# pmmcp contract §6 step 2: honest results, kernel first

Status: **proposed, awaiting the operator's approval** (2026-10-19). Nothing here
is implemented. Planned against `c0bf08f`; baseline there: typecheck clean, 701
tests, 695 pass, 0 fail, 6 skipped.

## What step 2 is

Today pmmcp answers every goal call as prose, refusals included ("Error: Cannot
transition…" arrives as *success* text), and the kernel trusts a move only when
the reply starts `✅ Goal updated: <id>`. Step 2 makes results something the
kernel can check:

- **2.1 (kernel, now):** read pmmcp's structured result (`structuredContent`)
  when there is one and today's prose when there is not, for `create_goal` and
  `update_goal`, and refuse when the two disagree.
- **2.2 (pmmcp, the operator's repository):** P5 real errors on every tool, and
  P6 typed results for the goal tools, in one release.
- **2.3 (kernel, after 2.2):** remove the prose path and replace falsify G13 and
  G15.

Order matters. P6 removes the `✅ Goal updated:` line that today's writer
confirms against, so a P6 pmmcp with a pre-2.1 kernel would leave every status
move unconfirmed. Goals would silently go stale, with only a warning in the log.

## 2.1: kernel commits that can ship now

Each commit has its own test, and each test fails on today's code. Change
control: none of these deletes or skips a test, changes `protocol.ts`, changes
a tool's exposure, touches redaction, chain or triggers, or widens agent reach.

| # | Commit | Acceptance test |
|---|---|---|
| 2.1.1 | **Double: opt-in P5 refusals and P6 goal results.** New `PmmcpMockOptions`, set per tool. `refusals: 'text' \| 'p5'`: P5 sends `isError` with `<code>: <message>` in both wire forms, and a not-found message never quotes the id the call sent. `outputs: 'prose' \| 'wrapped' \| 'structured'`: `wrapped` is FastMCP's automatic `{result: string}`, `structured` is P6's `{goal_id, project_id, status, progress_pct}`, with a non-recursive `get_goal_tree` root. `text: 'json' \| 'prose' \| 'none'` (what text block accompanies a structured reply), plus a skew that changes both forms or one. The default is the form the live capture records; until 2.1.O1 that is today's prose. Every refusal site gets a code, strictRollup and `complete_goal` included. | `test/mcp-pmmcp-double.test.ts`: "in structured mode the goal tools declare object-rooted output schemas, answer with structuredContent and the same JSON as text, and refuse with isError and a P5 code; by default they answer as the capture records" |
| 2.1.2 | **Hub: `callKernelOnly` returns `structuredContent`; `describe()` carries `outputSchema`.** Additive. The broker, the wrappers and every test read only `.ok`/`.content` today (full caller list in the commit). Still appends nothing; the agent path (`McpHub.call`) is untouched. | same file: "callKernelOnly hands back structuredContent and still appends nothing, and describe() carries the live outputSchema" |
| 2.1.3 | **Capture keeps `outputSchema`** (it strips it today), records `recordsOutputSchema: true` and the page count, through a new pure `src/mcp/capture.ts`. | `test/pmmcp-capture.test.ts` (new): "a capture keeps every tool's outputSchema verbatim and says that it records them" |
| 2.1.O1 | **Operator: re-capture pmmcp** (`npm run capture:pmmcp`, read-only, no writes), then commit. Settles what the live goal tools return today: no output schema, or FastMCP's `{result: string}` wrapper. Whether pmmcp's SDK wraps is an inference; §9 still lists its version as open. Must land before 2.1.5. | 2.1.5's test, which also requires the committed fixture to carry `recordsOutputSchema: true` |
| 2.1.4 | **The kernel's P6 result schema, strict.** `GoalResult = {goal_id, project_id, status ∈ pmmcp's five, progress_pct 0–100}`. Strict, so an unreviewed extra field is refused. Written so that falsify anchor G17 still matches exactly once. | `test/pmmcp-schemas.test.ts`: "the P6 goal result is strict: an unknown key, a missing key, a status outside pmmcp's five, or progress outside 0–100 is refused" |
| 2.1.5 | **Drift guard reads output schemas**, only from a capture that records them. It compares property names, types and the required set, read leniently. min, max, enum and strictness are the kernel's own and are not expected in the live schema. The double's default output form must match the live one. | `test/pmmcp-drift.test.ts`: "output schemas are compared only in a capture that records them, and then a P6 result that disagrees with the kernel's, or a double that does not serve the live form, is named" |
| 2.1.6 | **Writer: a create reads `structuredContent` or prose, and refuses when they disagree.** Also refused: another `project_id`, a non-P6 structure, and a `{result}` whose text differs. Any transport error other than `GoalWriteFailed` or `PolicyDenied` becomes `GoalWriteFailed`, so `kernel.adopt_plan` refuses cleanly. Each check has its own mutant, and each test case triggers exactly one check. | `test/goals-writer.test.ts`: "a create is read from structuredContent when there is one: another project, two forms that disagree, or a non-P6 structure is refused with no goal.created row" |
| 2.1.7 | **Writer: a status move is confirmed from `structuredContent` or prose.** With P6: same goal, same status, same project as the kernel's own record, and 100 % for review. The prose confirm stays byte-identical (falsify G13). **This is the commit pmmcp 2.2 must not ship before.** | same file: "a move is confirmed from structuredContent: P6's JSON-only reply is a move, and a reply naming another status, goal or project, or a review below 100 %, is not recorded" |
| 2.1.8 | **Boot check: an output schema the writer cannot read degrades goals** before any write, instead of leaving one orphan goal per run. Also re-run when the hub reconnects, so a pmmcp redeployed under a running kernel is caught. | same file: "a live goal tool whose outputSchema returns a field the kernel does not read degrades goals at boot and on reconnect, by name; no schema, FastMCP's {result} and the P6 schema all serve" |

New falsify mutants go into the goals suite with each commit, and each is seen
killed before it is catalogued. `test/falsify.test.ts` ("every catalog anchor
still matches exactly once") runs in every commit, because these files hold the
anchors G1–G3 and G11–G23.

## 2.2: pmmcp (the operator's repository)

The brief for whoever changes pmmcp. Every quote is from §3 P5 and P6.

- **Ship P5 and P6 (goal tools) in one release.** Deploy it only once the
  daemon runs kernel 2.1.7 or later, then **restart the daemon** (or rely on
  2.1.8's reconnect check).
- **P5, every tool:** "Every refusal is `raise ToolError(f"{code}: {message}")`",
  and it reaches the client as `Error executing tool <tool>: <code>: <message>`
  with `isError: true`. The codes:
  - `goal_not_found`, `not_found`, `invalid_transition`, `invalid_status`,
    `parent_not_found`, `invalid_goal_type`, `progress_out_of_range`;
  - `internal_error` for anything else.

  A message never quotes a secret, another compartment's data, **or the id or
  label a not-found call sent**.
- **P6, goal tools:** `create_goal` and `update_goal` return
  `{goal_id, project_id, status, progress_pct}`. `get_goal_tree` returns
  `{goal_id, title, goal_type, status, progress_pct, children: [GoalNode]}`,
  with a non-recursive root. Every root is an object, every datetime is
  timezone-aware, the JSON is also returned as a text block, and `tools/list`
  is one page.
- **Also state:** pmmcp's `mcp` SDK version, pinned per P1 (`mcp>=1.29.1,<2`, or
  MCPServer on 2.3+).
- **Then the operator:** restart the daemon, re-capture (2.2.O2) and commit.

## 2.3: after 2.2 ships and is captured

Split into four commits, each with its own test. The first gates the rest.

| # | Commit | Change control |
|---|---|---|
| 2.3.1 | **The capture proves P6 by machine:** a drift test that fails unless the committed fixture records outputs and `create_goal`/`update_goal` declare `goal_id`. The boot check then requires P6 output schemas, so a pre-P6 pmmcp degrades goals by name. | none |
| 2.3.2 | **The double's default becomes P6 + P5.** Every test assertion that pinned prose or success-text refusals changes; each is listed in the commit. Covers `mock-pmmcp.test.ts`, `runtime-bodies.ts`, `mcp-pmmcp-double.test.ts` and `goals-writer.test.ts`. | **ask-before** (assertions changed) |
| 2.3.3 | **Remove the prose path.** `goalIdOf`, the prose confirm and the `{result}` branch go. Falsify G13 and G15 are replaced, on the structured confirm and the structured id, and G2/G3 are retired with `goalIdOf`. The kernel reads P5 codes from an `isError` reply (an `isError` without one reads as `invalid_arguments`). | **ask-before** (tests deleted: the bare-id and `goalIdOf` tests) |
| 2.3.4 | **Docs:** README, CLAUDE.md, and the contract's status for step 2. | none |

## Decisions the operator owns

1. **Approve 2.1** (eight kernel commits plus the 2.1.O1 re-capture) as written.
2. **`list_goals`:** P6 names it among the typed tools but gives no shape. The
   kernel does not read it. Proposal: leave it untyped until pmmcp defines one.
3. **Extra fields in a P6 result** (timestamps, say). P6's acceptance mentions
   "a goal carrying timestamps", but the create/update shape has none.
   Proposal: strict, so an extra field is refused, and 2.1.8 catches it at boot
   before any write.
4. **An orphan record.** When pmmcp has created a goal but the kernel refuses
   to confirm it, append a new `goal.unconfirmed {goalId, projectId, reason}`
   event, so the orphan is in the chain rather than only in a warn line.
   Proposal: yes. It is a new event type, so it is not ask-before.
5. **Is a capture plus offline tests enough for 2.3?** A live structured goal
   write is not allowed before step 3.1 (K12). Proposal: yes, as the spec
   orders it, with the risk that the structured path meets real pmmcp for the
   first time after the prose path is gone.

## Risks

- **pmmcp's SDK may already wrap today's replies** as `{result: string}`. A
  writer that parsed every structured reply as P6 would refuse every live
  create. Covered by the `{result}` branch, the `wrapped` double and 2.1.O1.
- **Orphan goals.** Any refusal after pmmcp has written a goal leaves one that
  no `goal.created` row claims. 2.1.8 moves schema-level drift to boot.
  Value-level failures still orphan one goal per attempt (decision 4).
- **Deploy order is enforced only by the operator.** The two repositories ship
  separately.
- **The double's structured forms are modelled, not captured.** They stay out
  of `confirmed` until 2.2.O2's capture holds them.
- **`get_secret`'s structured form**, if pmmcp wraps it, now reaches the broker.
  The broker stays unread and unlogged on that path; 2.1.2's test asserts that
  `callKernelOnly` appends nothing.
