# Decisions that need the operator

One index over every open question in this repository. Nothing in `docs/plan/` or
`docs/design/` gets implemented until the blocking ones are answered, per the CLAUDE.md
session protocol and its change-control rule on dependencies.

**Sources of truth.** This file is an index; the full reasoning lives in the section each
row cites. `D*` rows come from `docs/plan/phase-0-bootstrap.md` §6. `Q*` rows come from
`docs/design/agent-fleet.md` §13. Where a row is clipped here, the source is complete.

**How to answer.** Every row carries a conservatively chosen default. Reply "accept all
defaults" and name only what you want changed, for example `D3: better-sqlite3` or
`Q2: per-order approval only, no mandate`. Answers get recorded here and in the source.

**Totals.** 30 Phase 0 plan decisions, 29 fleet design decisions, 16 of them blocking.

**Status.** All 59 decisions answered on 2026-09-21. All defaults accepted except D13.

## 1. Blocking — answer before any code is written

| # | Question | Default if you say nothing | Answer |
|---|---|---|---|
| **D1** | What is `node --version` on the Mac, and is the `engines` floor `^22.21.0 \|\| >=24.15.0` acceptable (recommend Node 24 LTS)? | that floor; `@types/node 22.20.4`; switch types to 24.x if the Mac has 24 | ✅ **v24.9.0**. Floor accepted. Switch `@types/node` to 24.x. |
| **D2** | Keep the `.js` import-suffix mandate (⇒ `tsx` required) or switch to `.ts` suffixes + native stripping (a CLAUDE.md standards change)? | keep `.js` + tsx; `erasableSyntaxOnly` keeps the door open | ✅ default (`.js`) |
| **D3** | `node:sqlite` (stdlib, RC API) vs `better-sqlite3@13.0.3` (native N-API addon, +27 MB)? | `node:sqlite` behind `src/events/db.ts` | ✅ default — kernel needs its own SQLite for the hash-chained event log (invariant 5), separate from pmmcp's SQLite |
| **D5** | Accept the MCP SDK's 94-package footprint (express/hono/jose installed, never loaded)? | accept; recorded in README | ✅ default |
| **D6** | Raw-fetch Chat Completions adapter vs adding `openai@7.20.0` (0 transitive deps, Node ≥ 22)? | raw fetch; `openai` not installed | ✅ default |
| **D8** | Allow the opt-in `secrets.envFallback` at all (widens what the kernel reads from env; default OFF, DEGRADED when ON)? The env name is a **per-entry secondary** (`auth.envVar` beside a mandatory `auth.vaultId`, §3.4), consulted only after that entry's vault path failed — never a substitute for `vaul… | allowed, default off; `vaultId` stays mandatory on every non-local entry | ✅ default — pmmcp vault (`get_secret`/`set_secret`) is the primary store; env fallback is only for when pmmcp is unreachable |
| **D10** | Origin policy: `allowedOrigins` default `[]` (Tauri origin admitted only when listed) and bind `127.0.0.1` only; Phase 3 must open the socket from Rust or amend invariant 1 via a v2 connect ticket? | `[]`, IPv4 only, no ticket in v1 | ✅ default |
| **D27** | Acknowledge the T37 rewrite of CLAUDE.md "Current state" with the text in T37? | as written | ✅ default |
| **D29** | Ship a test that is skipped by default (`test/live-anthropic.test.ts`, gated by `AOS_LIVE_TESTS=1`, and T35's hygiene rule whitelisting `test/live-*.test.ts`)? CLAUDE.md lists "skipping a test" as ask-before, so this cannot be decided silently. Alternative: keep the live tests in a separate script… | gated skip inside the suite, whitelisted by name only | ✅ default |
| **Q1** | **Trading taint boundary.** Is the human's approval of a signal batch the only laundering point — declassifying the *decision* (a numeric `SignalExecView`), never the prose — or should a kernel rule treat a scout's zod-validated `numbers[]` as clean so the quant stays clean on numbers? | approval is the only laundering point. A schema is not a security boundary when the attacker chooses the numbers. | ✅ default |
| **Q2** | **Live orders under a mandate.** Does a human-signed mandate with `maxUses` and ≤ 30 d expiry ever satisfy "irreversible always requires a human" for `venue.live.submit`? | no. It is a CLAUDE.md amendment, not a kernel toggle; it would additionally require 60 paper days, a passed reconcile drill and the Phase 3 trust-rule machinery. | ✅ default |
| **Q6** | **Scoped trust rules (Phase 3).** Restrict them to `write`-class approvals from clean runs only, exact shape, `maxUses`, TTL, void while tainted — never tainted-write, memory-promote, declassify, plan, promotion, escalation or irreversible? | yes, Phase 3 only. | ✅ default |
| **Q12** | **Pentest capabilities.** Keep `--cap-drop=ALL` with **no** `CapAdd` (TCP-connect scanning, HTTP probing, dependency analysis), or amend invariant 9 to allow `NET_RAW` for SYN scanning? | no CapAdd. `SYS_PTRACE` is refused outright. | ✅ default |
| **Q16** | **Facts that must come from primary sources before they become config.** Platform limits (X, LinkedIn, Instagram, TikTok, Reddit), FTC/CAN-SPAM and the Google/Yahoo bulk-sender requirements, FINRA Notice 26-10 (PDT), day-trade buying power, IRS Pub. 550 wash sales and the crypto exclusion, venue ToS on automated trading, Hyperliquid US eligibility. | nothing goes live until the operator has re-read each and confirmed the block. Every number currently in these designs is INFERRED from search snippets. | ✅ default |
| **Q26** | **Fail-safe writes on tainted runs.** Does `failSafe: true` (currently proposed for exactly one tool, `suppress.add`) amend invariant 3, or should an opt-out write on a tainted run instead be executed by a deterministic kernel reader with no agent in the path, as §6.3 already does for inbound opt-out replies? | kernel-side executor, no invariant amendment — the `community` agent files an `inbox`/`suppress` record and the kernel's deterministic opt-out reader performs the write,… | ✅ default |
| **Q27** | **Amended phase map.** The fleet adds two sectors CLAUDE.md's phase map does not contain — trading and offensive security. Accept the amended map as written (trading research in Phase 1, trading kernel and `pentester` in Phase 2a/2b), or hold both behind CLAUDE.md's existing exits and land them as Phase 2c and Phase 6? | hold trading *execution* and the pentest sector to a Phase 2c that starts only after CLAUDE.md's own Phase 2 exit is met, and keep trading *research* (`quant` research-o… | ✅ default |

Two of these would narrow a non-negotiable invariant, so nobody but you can decide them:
**Q26** (a fail-safe write on a tainted run, invariant 3) and **Q12** (a network capability
inside a pentest container, invariant 9). Both default to no amendment. **Q27** amends the
CLAUDE.md phase map, which does not currently contain the trading or offensive sectors.

## 2. Phase 0 bootstrap plan — `docs/plan/phase-0-bootstrap.md` §6

D3, D5 and D6 are the dependency acknowledgement CLAUDE.md requires before a single
package is installed.

| # | Question | Default | Answer |
|---|---|---|---|
| D1 ★ | What is `node --version` on the Mac, and is the `engines` floor `^22.21.0 \|\| >=24.15.0` acceptable (recommend Node 24 LTS)? | that floor; `@types/node 22.20.4`; switch types to 24.x if the Mac has 24 | ✅ **v24.9.0**; switch `@types/node` to 24.x |
| D2 ★ | Keep the `.js` import-suffix mandate (⇒ `tsx` required) or switch to `.ts` suffixes + native stripping (a CLAUDE.md standards change)? | keep `.js` + tsx; `erasableSyntaxOnly` keeps the door open | ✅ default |
| D3 ★ | `node:sqlite` (stdlib, RC API) vs `better-sqlite3@13.0.3` (native N-API addon, +27 MB)? | `node:sqlite` behind `src/events/db.ts` | ✅ default |
| D4 | Money encoding in events: integer micro-USD vs decimal string? | integer micro-USD (`costMicroUsd`) | ✅ default |
| D5 ★ | Accept the MCP SDK's 94-package footprint (express/hono/jose installed, never loaded)? | accept; recorded in README | ✅ default |
| D6 ★ | Raw-fetch Chat Completions adapter vs adding `openai@7.20.0` (0 transitive deps, Node ≥ 22)? | raw fetch; `openai` not installed | ✅ default |
| D7 | Add `--env-file-if-exists=.env` to `dev`/`cli` (deviates from "needs .env sourced")? | not added; operator sources `.env` | ✅ default |
| D8 ★ | Allow the opt-in `secrets.envFallback` at all (widens what the kernel reads from env; default OFF, DEGRADED when ON)? The env name is a **per-entry secondary** (`auth.envVar` beside a mandatory `auth.vaultId`, §3.4), consulted only after t… | allowed, default off; `vaultId` stays mandatory on every non-local entry | ✅ default |
| D9 | Tool names > 64 chars after `__` mapping on OpenAI-compatible routes: fail closed at load vs deterministic shortening? | fail closed | ✅ default |
| D10 ★ | Origin policy: `allowedOrigins` default `[]` (Tauri origin admitted only when listed) and bind `127.0.0.1` only; Phase 3 must open the socket from Rust or amend invariant 1 via a v2 connect ticket? | `[]`, IPv4 only, no ticket in v1 | ✅ default |
| D11 | Genesis constant `sha256('aos-kernel:events:v1')` vs 64 zeros (frozen forever)? | domain-separated | ✅ default |
| D12 | Chain anchoring: head file only (Phase 0) vs also pmmcp record / HMAC with a vault key? | head file; pmmcp anchor in Phase 1 | ✅ default |
| D13 | The single real Claude entry: `claude-opus-5` vs `claude-sonnet-5` vs `claude-haiku-4-5` (not `claude-fable-5-1` for a forced-tool probe)? | `claude-opus-5` | ⚡ **`claude-sonnet-5`** — better cost/intelligence ratio for orchestration |
| D14 | Incomplete `model.fallbacks` entries: refuse at parse vs drop with a warning? | refuse | ✅ default |
| D15 | Tier semantics 0–3 (§3.4), `kind: standard \| template \| ephemeral`, CEO tier 2? | as §3.4 | ✅ default |
| D16 | May a fallback move to a pricier model within the run budget? | only if the remaining budget covers one worst-case turn | ✅ default |
| D17 | Quarantine semantic: execute-then-hold output until a human releases; release taints the run? | yes | ✅ default |
| D18 | Does the model receive exactly the bounded, redacted tool output the log stores (one truth), or the full text up to a separate model cap? | one truth | ✅ default |
| D19 | Does the wallclock keep running while a run is parked for approval, and is a late approval refused? | keeps running; late approval → `conflict` | ✅ default |
| D20 | Anthropic auth mechanism: `x-api-key` via SDK `apiKey` (CONFIRMED SDK path) vs `Authorization: Bearer` via `authToken` (documented primary; NEEDS VALIDATION that an API key is accepted as a bearer)? | `x-api-key`; `Authorization` selectable per entry | ✅ default |
| D21 | `aos search` = event-log search (`events.query text`) vs pmmcp memory search (tool name unknown)? | event log | ✅ default |
| D22 | Sandbox caps (`256 pids / 2g / 2 cpus / 65534:65534`), Colima VM sizes vs the ~40 GB model budget? | placeholders as written | ✅ default |
| D23 | Lane caps `main: 4`, `subagent: 8`? | as written | ✅ default |
| D24 | TypeScript 5.9.3 vs 6.0.3 vs 7.0.2? | 5.9.3 | ✅ default |
| D25 | `AOS_DATA_DIR` default `~/.aos` (outside the repo) vs `./data`? | `~/.aos` | ✅ default |
| D26 | Approval wait 300 s → deny? | 300 s | ✅ default |
| D27 ★ | Acknowledge the T37 rewrite of CLAUDE.md "Current state" with the text in T37? | as written | ✅ default |
| D28 | Reading of "a model is bound to an agent only after `aos probe` reports `toolCalling: true`": **registry** accepts a manifest naming an unprobed ref (so the CEO manifest can ship before the operator has run a probe); the **router** refuses… | registry accepts, router refuses (T18 `routable`, T19, T34) | ✅ default |
| D29 ★ | Ship a test that is skipped by default (`test/live-anthropic.test.ts`, gated by `AOS_LIVE_TESTS=1`, and T35's hygiene rule whitelisting `test/live-*.test.ts`)? CLAUDE.md lists "skipping a test" as ask-before, so this cannot be decided sile… | gated skip inside the suite, whitelisted by name only | ✅ default |
| D30 | Kernel run-cap defaults shipped in `config/kernel.yaml` (T32): `defaultRunMicroUsd: 2000000` ($2 per run), `defaultWallclockMs: 600000` (10 min), `maxLlmCallsPerRun: 50`, `maxToolCallsPerRun: 100`? A manifest may only lower them (T27b). | as written | ✅ default |

## 3. Agent fleet design — `docs/design/agent-fleet.md` §13

| # | Question | Default | Answer |
|---|---|---|---|
| Q1 ★ | **Trading taint boundary.** Is the human's approval of a signal batch the only laundering point — declassifying the *decision* (a numeric `SignalExecView`), never the prose — or should a kernel rule treat a scout's zod-validated `numbers[]` as clean so the quant stay… | approval is the only laundering point. A schema is not a security boundary when the attacker chooses the numbers. | ✅ default |
| Q2 ★ | **Live orders under a mandate.** Does a human-signed mandate with `maxUses` and ≤ 30 d expiry ever satisfy "irreversible always requires a human" for `venue.live.submit`? | no. It is a CLAUDE.md amendment, not a kernel toggle; it would additionally require 60 paper days, a passed reconcile drill and the Phase 3 trust-rul… | ✅ default |
| Q3 | **Depth.** Keep depth 1 with sector leads as non-delegating planner-workers, or grant one expiring `depth-raise` mandate to `eng-lead` after a harness win at equal spend? | depth 1 for Phase 1, revisited only on measured evidence. | ✅ default |
| Q4 | **Approval wait semantics.** Keep the Phase 0 park-then-deny, or adopt suspend-then-continue with class-specific expiry? | suspend-then-continue in Phase 1, now safe because of the exactly-once receipts (KC9). | ✅ default |
| Q5 | **Plan auto-accept.** Auto-accept a plan when the irreversible inventory is empty, the budget fits the envelope and no hostile-domain template is used; otherwise one mandate. | yes (engineering adds a $10 threshold plus protected-area triggers; refactors and `class: self` repos are always human). | ✅ default |
| Q6 ★ | **Scoped trust rules (Phase 3).** Restrict them to `write`-class approvals from clean runs only, exact shape, `maxUses`, TTL, void while tainted — never tainted-write, memory-promote, declassify, plan, promotion, escalation or irreversible? | yes, Phase 3 only. | ✅ default |
| Q7 | **Budget numbers.** The §12 table is now complete — per-sector objective defaults, the **$100 per-objective** ceiling, a **$700 kernel-enforced fleet-month ceiling** that refuses new unattended runs above it, per-agent monthlies for all five sectors (growth r… | the completed table as tabulated, with trading at $10 until Phase 2a and $40 thereafter if the operator agrees; the four engineering monthlies and th… | ✅ default |
| Q8 | **Approvals daily budget.** 20/day with per-class sub-budgets and scheduler back-pressure on card-producing unattended runs. | yes, back-pressure only; nothing auto-approves. | ✅ default |
| Q9 | **Local concurrency.** `models.localConcurrency: 1` with off-peak pinning. | yes; raise to 2 only if a probe shows weights plus two KV caches fit 40 GB. | ✅ default |
| Q10 | **Manifest complexity.** Are `profiles:` on one template acceptable, or would the operator rather have three manifests and three eval suites (`implementer` code/docs/refactor)? | profiles. | ✅ default |
| Q11 | **Declassification granularity.** Per-extract with a content hash, a ≤ 8 KiB human-read preview, 30 d expiry and a `revokedAt` that blocks new reuse; bulk release is a batch of hashes; no "mark this run clean". | as stated. | ✅ default |
| Q12 ★ | **Pentest capabilities.** Keep `--cap-drop=ALL` with **no** `CapAdd` (TCP-connect scanning, HTTP probing, dependency analysis), or amend invariant 9 to allow `NET_RAW` for SYN scanning? | no CapAdd. `SYS_PTRACE` is refused outright. | ✅ default |
| Q13 | **Publishing edge as a second credential store.** Accept it (self-hosted Mixpost Lite or Postiz on loopback, admin credential in the vault, never over Tailscale, in the backup set, treated as a credential holder in the threat model), or hold audience reach until the vault can hold refresh… | accept with those five conditions; Mixpost Lite. | ✅ default |
| Q14 | **Automatic fail-closed halt.** Halting admission automatically on chain-verify failure or a missing witness marker risks the operator finding a stopped fleet. | halt automatically — a control plane that cannot prove its log is intact must stop authorizing; `fleet.resume` stays available on the loopback contro… | ✅ default |
| Q15 | **Evaluator strictness.** Advisory in Phase 1, hard gate at Phase 5? | yes, so early manifests are not stuck behind an incomplete harness. | ✅ default |
| Q16 ★ | **Facts that must come from primary sources before they become config.** Platform limits (X, LinkedIn, Instagram, TikTok, Reddit), FTC/CAN-SPAM and the Google/Yahoo bulk-sender requirements, FINRA Notice 26-10 (PDT), day-trade buying power, IRS Pub. 550 wash sales and the crypto exclusion, venue ToS on automate… | nothing goes live until the operator has re-read each and confirmed the block. Every number currently in these designs is INFERRED from search snippe… | ✅ default |
| Q17 | **Venues and asset classes.** Alpaca paper first, one crypto testnet second, IBKR and Coinbase deferred; long-only equities in the first cut; crypto perps only with an operator-signed reduce-only-close pre-authorisation. | as stated — if the operator will not pre-authorise the unwind, perps stay out. | ✅ default |
| Q18 | **Executor mode.** Deterministic for the first 60 paper days, `llm` mode only after an equal-spend fill-quality comparison. | deterministic. | ✅ default |
| Q19 | **Email sending identity.** A dedicated domain with SPF/DKIM/DMARC and a warmup ramp starting at 20/day, separate from the operator's mailbox. | dedicated domain. | ✅ default |
| Q20 | **`delegateTier` promotions.** Which agents reach tier 3, when, and for how long (every promotion is a Mandate expiring within 30 days)? | `reporter` immediately; `community` and `sales` after two weeks of tier-2 cards above 80% acceptance, re-issued monthly; `publisher` never above tier… | ✅ default |
| Q21 | **`focus-group` at all.** Ship disabled and enable only if the cheap proxy metric (does it surface objections the operator's own edits and the `checker` also raised, below the `checker-brand` baseline cost) beats the baseline twice. | ship disabled; drop it if the proxy fails. | ✅ default |
| Q22 | **Presenter engine.** Validate LiveTalking wav2lip256 on MPS at ≥ 25 fps and patch the burned-in watermark, or evaluate another engine? The tool view is engine-agnostic. | validate LiveTalking. Live Q&A answered by a model is never shipped. | ✅ default |
| Q23 | **Reviewer/checker model diversity.** Fund a second provider probe so verifier and writer do not share a model family. | yes at Phase 2; until then the seeded-violation gate at 1.0 is the only defence against a correlated false pass. | ✅ default |
| Q24 | **pmmcp validation before Phase 1 wrappers.** Goal-status vocabulary, metadata support for provenance, and the `get_secret` argument name, all confirmed from live `listTools`; fall back to a kernel SQLite projection for provenance if absent. | validate first. | ✅ default — `get_secret` arg is `label` (confirmed from live schema) |
| Q25 | **Souls originality lint.** WARN at 20% / FAIL at 40% shingle overlap as a repo test once more than five souls exist. | yes. | ✅ default |
| Q26 ★ | **Fail-safe writes on tainted runs.** Does `failSafe: true` (currently proposed for exactly one tool, `suppress.add`) amend invariant 3, or should an opt-out write on a tainted run instead be executed by a deterministic kernel reader with no agent in the path, as §6.3 already… | kernel-side executor, no invariant amendment — the `community` agent files an `inbox`/`suppress` record and the kernel's deterministic opt-out reader… | ✅ default |
| Q27 ★ | **Amended phase map.** The fleet adds two sectors CLAUDE.md's phase map does not contain — trading and offensive security. Accept the amended map as written (trading research in Phase 1, trading kernel and `pentester` in Phase 2a/2b), or hold both behind CLAUDE.… | hold trading *execution* and the pentest sector to a Phase 2c that starts only after CLAUDE.md's own Phase 2 exit is met, and keep trading *research*… | ✅ default |
| Q28 | **Paid media at all.** Marketing's only irreversible money-movement surface. Enable paid-media spend verbs (shape in §5.6 `marketer`: `irreversible`, carded per campaign, kernel-computed spend ceiling, kernel daily cap, confidence-gated, credit cost in the tool… | no — audience reach stays organic until after Phase 4's exit, and the Phase 5 clause is conditional on this answer, not a plan. | ✅ default |
| Q29 | **Disk budget and the free-space floor.** The §12 per-consumer table (weights 40 GB · Colima trusted 120 GB · hostile 60 GB · Qdrant/pmmcp 40 GB · artifact store 300 GB with intermediate media renders evicted at objective close + 30 days · worktrees and shadow refs 60 GB with chec… | as tabulated. The artifact-store number and the media-render eviction rule are the two most likely to need changing once real renders exist. | ✅ default |

## 4. Facts only your machine can settle

Not judgement calls, measurements. Listed as NEEDS VALIDATION in the plan, §7.

### Resolved ✅

- **`node --version`**: **v24.9.0**. Drives D1: floor accepted, `@types/node` switches to 24.x.
- **pmmcp endpoint**: **`http://127.0.0.1:8766/mcp`**, Streamable HTTP, port 8766 (dashboard on 8765), loopback confirmed, bearer token required.
- **`get_secret` argument name**: **`label`** (not `key`). Set `kernel.yaml secrets.keyArg` to `'label'`, or update `SecretsBroker` code. Resolves the "unverified" status in CLAUDE.md.

### Pending 🔧

- Whether FSEvents survives virtiofs in the Colima VMs. Test: host-side `fs.watch` + VM-side file write. Phase 2 concern, not Phase 0 blocker.
- The llama.cpp build, whether it runs with `--jinja`, and the chat template in use. Validate when local model setup begins.
- Live model ids for Moonshot and OpenRouter; auto-detect via `GET /v1/models` on each provider's API. Run after API keys are stored in vault.
