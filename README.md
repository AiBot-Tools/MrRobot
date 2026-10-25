# aos-kernel

The kernel — the control plane — of a local-first Agentic OS for a single
operator on one Mac. A CEO agent orchestrates a fleet; every action lands in a
hash-chained, append-only event log; pmmcp (the operator's Persistent Memory MCP
server) is shared long-term memory and the goal store; models are bound per
agent across Anthropic, OpenAI-compatible and local endpoints.

Three planes. **Shell** (UI; holds no secrets, executes nothing) → **Kernel**
(this repo: event log, registry, lanes, CEO loop, model router, MCP hub, policy
gate, secrets broker, sandbox manager, budgets) → **Workers** (one process or
container per run; scoped tools, no raw credentials, own workspace).

`CLAUDE.md` is the standing contract, including the ten non-negotiable
invariants. Read it before changing anything.

---

## Requirements

**Run `node --version` first, before anything else.** The toolchain's floor is
`^22.21.0 || >=24.15.0` (`package.json` `engines`), and the operator's Mac runs
**v26.9.0**, which satisfies the `>=24.15.0` arm.

Check the version first because of one specific failure that does not look like
a version problem. `.npmrc` sets:

```
node-options=--disable-warning=ExperimentalWarning
```

On **Node < 20.11** that flag is not accepted in `NODE_OPTIONS`, so *every*
`npm run` — test, typecheck, dev — dies before printing anything with:

```
node: --disable-warning= is not allowed in NODE_OPTIONS
```

That message means **wrong Node**, not a broken repository. Nothing else in the
repo will tell you so, because nothing else gets to run.

`engine-strict` is deliberately `false`, so `npm install` warns about the
engines range rather than refusing. The warning is the signal; there is no hard
gate.

### Dependency footprint

Six runtime dependencies (`@anthropic-ai/sdk`, `@modelcontextprotocol/sdk`,
`pino`, `ws`, `yaml`, `zod`) expand to **117 installed packages**, plus 33
dev-only, 150 in the lockfile. The bulk is the MCP SDK's transitive tree
(express, hono, jose and friends), which is installed but never loaded by this
kernel — we use the SDK's client and `InMemoryTransport` only. That cost was
accepted deliberately (decision D5) rather than vendored around.

`openai` is **not** installed: the OpenAI-compatible dialect is a raw-`fetch`
adapter (D6).

---

## Setup

```bash
npm install
node --version
npm run typecheck
npm test
```

`node --version` must meet the floor above, `npm run typecheck` must be clean
and `npm test` green. No shell block in this README carries a `#` comment: stock macOS
zsh does not treat one as a comment when you paste, and hands it to the command
as arguments.

The daemon needs `AOS_CONTROL_TOKEN` (at least 32 printable ASCII characters,
with no whitespace, quote, backtick or `#`, from the shell and `.env` alike;
`openssl rand -hex 32` makes one) and, to reach a
model, `ANTHROPIC_API_KEY`: a key created inside a workspace, because an unscoped
key needs an `anthropic-workspace-id` header the kernel does not send. Both live
in **your own `.env` in the repository root**: git-ignored, mode 0600, written only by you. `.env.example` is the
committed template: placeholders only, never edited to hold a real value, and it
does not change when your `.env` does.

```bash
test -e .env || (umask 077 && cp .env.example .env)
chmod 600 .env
nano .env
npm run dev
```

Line by line: the first creates `.env` from the template at mode 0600 and never
overwrites one that exists; the second sets 0600 anyway, because `cp` keeps an
existing file's mode; in the editor, replace both `replace-me-...` values
(`openssl rand -hex 32` makes a token); `npm run dev` then logs `credentials:
.env (AOS_CONTROL_TOKEN, ANTHROPIC_API_KEY)`, and `npm run cli -- agents` works
from a second shell with nothing exported.

Any plain-text editor will do in place of nano, but not TextEdit: its smart
quotes turn `"` into `“`, which the loader refuses (a key is printable ASCII).
The kernel checks the mode bits; on macOS an ACL can still grant others read
access to a 0600 file (`ls -le .env` shows a `+`), and `chmod -N .env` removes
it.

**Upgrading from a sourced `.env`.** Before D31 the setup was `cp .env.example
.env && set -a && . ./.env && set +a`. A `.env` made that way is mode 0644 and
holds names this kernel now refuses (`AOS_DATA_DIR`, `AOS_LOG_LEVEL`,
`PMMCP_TOKEN`, `OPENROUTER_API_KEY`, `MOONSHOT_API_KEY`, `LLAMA_API_KEY`,
`AOS_LIVE_TESTS`, `PMMCP_URL`). `npm run dev` always reads the whole file, so it
refuses to start with it even when every credential is exported (the CLI and
eval open it only when the shell lacks the token). Edit it in place: keep only
`AOS_CONTROL_TOKEN` and
`ANTHROPIC_API_KEY`, run `chmod 600 .env`, stop sourcing it, and export
`AOS_DATA_DIR` or `AOS_LOG_LEVEL` from the shell if you used them.

How it is read (`src/secrets/dotenv.ts`, decision D31):

- `npm run dev`, `npm run cli` and `npm run eval` pass `--dotenv .env`. `npm
  test`, and `node src/main.ts` run directly, open no file. The CLI and eval take
  only `AOS_CONTROL_TOKEN` from it, never a provider key.
- Values go into the kernel's memory, never into `process.env`, so no child
  process and no SDK ambient lookup sees them. They are masked from the log the
  moment they are read, and no error message quotes a value or a line.
- A shell export that is not blank wins over the file, and the daemon warns, by
  name, that it did.
- Refused at startup, each with the fix in the message: a `.env` whose mode lets
  group or others read or write it (`chmod 600 .env`), a symlink, another owner, a second hard link, more
  than 64 KB, a `.env` stored on disk under another case (`.Env`: git judges a
  name as stored, and `.env*` does not cover it with `core.ignorecase=false`), a
  `.gitignore` that stops ignoring it (read with git's own rules,
  so `!*` or a leading space count), any name but the two above, a value still
  beginning `replace-me`, a character outside printable ASCII, two lines joined
  into one, a name set twice, a second `--dotenv`. It parses with its own strict
  grammar: Node's built-in `.env` parser gives a whitespace-only value the whole
  next line. An exported value that is empty or only whitespace counts as unset.
- Live tests (`AOS_LIVE_TESTS=1 npm test`) take the key from the shell or
  `.env`; every other test file strips credential names from its own process,
  on the live run too.

**Keep it safe.** This repository is public: never `git add -f .env` (`npm test`
fails while one is tracked), and turn on GitHub secret scanning with push
protection. `.env` is plaintext on disk:
Time Machine, iCloud Desktop/Documents sync, and zipping or copying the folder
all carry it, and any tool running as you can read it. Use a dedicated Anthropic
key with a spend limit, and rotate it if the folder is ever copied. Do not run
pmmcp's `index_project` on this repository: pmmcp skips a file named exactly
`.env` only through its default ignore list, and stores `.env.local`-style files
unredacted.

Provider keys reach the kernel through its env (`secrets.source: env`): each entry's own
`auth.envVar`, resolved at boot. pmmcp's `get_secret` answers only with a masked
sentence (`Secret 'x' exists (masked): ****abcd`), by design, so it cannot supply
a key; the vault path stays in the code, dormant. Whatever the source (the
shell, `.env`, the vault, or the D8 fallback to the env), the broker refuses a
value that cannot be a key: whitespace (pmmcp's masked sentence), a character
outside printable ASCII, or a joined `NAME=value` line. A pmmcp bearer, if
`kernel.yaml` ever declares a `tokenEnv`, gets the same checks, and one under 8
characters is refused too, because the log's mask will not take a value that
short. A bearer that fails is refused by name before anything is dialled; one
that passes is masked before the first request, in the event log, the process
log, and what `npm run capture:pmmcp` prints.

With no pmmcp and no Docker the kernel boots **degraded** and says exactly what
is missing. That is the designed behaviour, not a failure — see below.

### Where things live

Everything the kernel writes lives in the program folder, under `.aos/`, which
git ignores. The one exception is `~/.colima`, Colima's own home.

| Path | What |
|---|---|
| `.aos/events.db`, `.aos/events.head` | the event log and its anchor |
| `.aos/workspaces/{trusted,hostile}` | sandbox mount roots, one per Colima VM |
| `.aos/docker` | `DOCKER_CONFIG` for the kernel's docker calls and `colima-up.sh`, never `~/.docker` |
| `.env` | your credentials (`AOS_CONTROL_TOKEN`, `ANTHROPIC_API_KEY`): written by you, mode 0600, git-ignored; read, never written, by the npm entry scripts; deleted by `git clean -fdx` like `.aos/` |
| `.aos/npm-cache` | npm's cache (`.npmrc`); run npm from the repo root, because npm resolves a relative path against the shell's directory |
| `~/.colima` | Colima's VMs and sockets; `colima-up.sh` also sets `COLIMA_CACHE_HOME=~/.colima/_cache`, which would otherwise be `~/Library/Caches/colima` |

`dataDir` is `./.aos`, relative to the repo root, and is kept `0700`: created
so on first boot, or tightened at boot when npm made `.aos` first for its cache
(at your umask's 0755); `events.db` and its `-wal`/`-shm` are made `0600`. `AOS_DATA_DIR` overrides it, relative to your shell's directory. Inside the
repo, `config.ts` accepts a data dir or mount root only under `.aos/`, and only
while `.gitignore` ignores `/.aos/`. Whatever `kernel.yaml` or `AOS_DATA_DIR`
names, `<repo>/.aos` itself must be a real directory spelled exactly so on disk:
a symlinked `.aos`, which git does not ignore and would commit with the path it
names, or one stored as `.AOS`, is refused by name at boot. What sits beneath a
real `.aos`, a linked `workspaces` included, is ignored with it.
Anywhere, it refuses `$HOME` itself or any folder that contains the repo or
`$HOME`. An empty `HOME` counts as unset: those checks then use your account's
home directory, never the current directory.

> **Warning.** `.aos/` holds the only copy of the event log. Running
> `git clean -fdx`, re-cloning over the folder, or deleting the folder destroys
> the log and its anchor together. Copy `.aos/` out first if you want the history.

When you run `colima` or `docker` by hand, export the same two variables the
script uses, so nothing lands in `~/.docker` or `~/Library/Caches`:

```bash
export DOCKER_CONFIG="$PWD/.aos/docker" COLIMA_CACHE_HOME="$HOME/.colima/_cache"
```

**Uninstall:** run `colima delete trusted` and `colima delete hostile`, then
delete this folder and `~/.colima` if nothing else uses Colima. Global installs
of Node, npm, Docker and Colima are yours to keep or remove.

---

## Commands

| Command | What it does |
|---|---|
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | `node --import tsx --test test/*.test.ts` |
| `npm run dev` | the daemon on 127.0.0.1:7777, reading `./.env` through `--dotenv` |
| `npm run build` | emits `dist/` |
| `npm run cli -- <cmd>` | the console: `agents`, `verify-chain`, `search`, `probe`, `run`, `kill`, `approve`, `deny`, `approvals` |
| `npm run capture:pmmcp` | operator-only: record pmmcp's live tool schemas |
| `npm run eval` | operator-only: score the orchestration suite (**spends money**) |
| `npm run falsify` | the mutation catalog: does the suite catch the bugs it claims to? (slow, offline) |

`eval` needs a running daemon (`npm run dev`) and `AOS_CONTROL_TOKEN`. It runs
the orchestration suite in `src/eval/suite.ts` as real runs against whatever
model each agent is bound to, under that agent's real budget, and prints a
scorecard. Flags: `--port`, `--case <id>`, `--json <path>`, `--config`. It exists
for one decision CLAUDE.md reserves to a human — whether a model card may carry
`orchestrator: true` — and it produces evidence for that decision only: it writes
no config, sets no flag and changes no manifest.

Two things about reading its output. Every check is scored **from the event log**,
never from what the model said it did; the model's own summary is examined only to
be contradicted by the log. And a check that could not run reports `n/a`, which is
not a pass — the summary always prints how many checks did not run beside the
score, because a 1.00 covering two of sixteen checks is not a good result. The
shipped fan-out case needs two child runs: it passes only when the CEO's model
adopts a plan and delegates both tasks through `kernel.adopt_plan` and
`kernel.delegate` (see Delegation below), so a failure there is a finding about
the model or the kernel, not a known stub. A suite pruned to what a model already
does would score 1.00 forever and measure nothing.

`capture:pmmcp` needs a running pmmcp and no token (pmmcp takes no bearer). It calls `tools/list`
and nothing else — no tool is invoked, so no memory and no vault entry is read —
and writes `test/fixtures/pmmcp-listtools.json`. Everything this repo believes
about pmmcp's tool surface apart from `get_secret`'s `label` is a guess made on
Linux; that file is what turns `test/pmmcp-drift.test.ts` from a self-test of
its own comparison into a check against the real schemas, and it is the fastest
way to settle `secrets.keyArg` without a full exit run.

The console, `npm run cli -- <cmd>`:

| Command | Needs the daemon | What it does |
|---|---|---|
| `agents [--include-archived]` | yes | list agents |
| `verify-chain` | **no** | verify the event log, read-only |
| `search [--type T] [--run R] [--text X] [--limit N]` | **no** | search the log, read-only |
| `probe <modelRef>` | yes | probe a model; exit 1 if it cannot call tools |
| `run <agentId> <input>` | yes | start a run, wait, exit on its status |
| `kill <runId> [--reason R]` | yes | abort a run |
| `approvals` | yes | list pending approvals and quarantine holds |
| `approve <apr_…\|hold_…>` | yes | approve an approval, or release a hold |
| `deny <apr_…> [--reason R]` | yes | deny an approval |

`verify-chain` and `search` open the database read-only and talk to nothing:
they are what you reach for when the kernel is the thing that is wrong. Neither
reads `AOS_CONTROL_TOKEN` — a command that needs no credential does not touch
one.

Exit codes: `0` success, `1` a refusal or a failed run, `2` usage.

---

## What is real, what is a stub

Real and tested: the event log (hash-chained, append-only, SQLite triggers
refusing UPDATE and DELETE, external anchor against truncation), the agent
registry and manifests, the policy gate with human approvals and quarantine, the
MCP hub and tool-view policy, the secrets broker, the model router with the
Anthropic and OpenAI-compatible adapters, the Docker sandbox driver's argv
construction and audit, lanes and budgets, protocol v1 and the control server,
the CLI, and kernel boot.

**Absent, and each says so when called.** This list is generated from
`STUBS` in `src/kernel.ts`; `test/stubs.test.ts` fails if the two disagree.

| Stub | Where | How it refuses |
|---|---|---|
| `apple-container-driver` | `src/sandbox/apple-container.ts` | `probe()` reports unavailable with a reason so boot degrades; `run()` and `kill()` throw `NotImplementedError`. macOS 15 has no `container` binary |
| `egress-proxy` | `src/runtime/egress.ts` | `assertEgressEnforced()` throws `NotImplementedError`, so no run can reach the network |

Not a stub, but not a tool either: **ephemeral spawning** (`spawnEphemeral` in the
registry) exists only as a registry capability. No tool mints a new agent;
delegation, below, runs tasks on the standing workers.

### Delegation

The CEO holds two kernel-native tools, both gated as `write` (so a tainted CEO
needs a human to use them) and both refused by the registry in any manifest that
is not `role: orchestrator`:

- **`kernel.adopt_plan({ plan })`** validates a `ProposedPlan` and writes it as the
  goal tree NOW, returning each task id with its goal id.
- **`kernel.delegate({ taskId, brief })`** runs one task of that plan on the worker
  the plan named, waits for it, and returns its run id, status, cost and result.

The model never supplies a goal id or chooses a target outside its adopted plan.
The kernel refuses, each time with a `delegation.refused` naming the reason: no
plan adopted, an unknown task, a task already delegated (double dispatch is
impossible rather than scored), a task whose `dependsOn` has not finished `ok`,
more children than the manifest's `spawn.maxChildren`, a target that is not an
active standard worker or has a higher tier than the caller, a caller that is
itself a delegated child (depth 1), and a parent with no budget left.

A child runs under a **ceiling carved from what the parent has left** and its
spend is **charged to the parent** when it finishes — so a parent's reported cost
is its own model calls plus its children's, and `delegation.admitted` /
`delegation.result` tie each child's spend and taint to the parent that caused it.
A child that finished tainted taints the parent. Killing the parent kills its
children.

### Schedules

An agent manifest may carry a five-field cron expression:

```yaml
schedule: "0 9 * * 1-5"      # 09:00 local, Monday to Friday
```

Supported: `*`, `N`, `a-b`, `*/n`, `a-b/n`, and comma-separated lists of those.
**Refused, by name rather than misread:** macros (`@daily`), six fields (a
seconds column), names (`MON`, `JAN`), the nonstandard `L`/`W`/`#`/`?`, and
backwards ranges like `55-5`. Expressions are validated when the manifest loads,
so a bad one is a refusal naming the file — not a job that silently never fires.

Four rules make a schedule safe to leave running, because a scheduled run spends
money and takes actions:

- **No catch-up.** Occurrences missed while the kernel was down are skipped and
  logged, never replayed. The worst moment to launch a backlog is right after an
  outage, when its cause may still be true.
- **No overlap.** If the agent still has a run in flight, the tick is skipped, not
  queued — a job slower than its interval would build a queue that never drains.
- **No double fire.** Each fire is keyed by the local minute, claimed in the log
  as `run.scheduled` *before* the run starts. So a repeated hour at the end of
  daylight saving cannot fire twice, and neither can a restart inside that minute.
- **No cron lane.** A scheduled run goes on the agent's own lane, with the same
  gate and the same budget as any other.

### Crash recovery, and what it deliberately does not do

A kernel that dies mid-run leaves three kinds of unfinished business in the log:
a run that started and never finished, an approval nobody answered, a hold nobody
released. All three live in memory, so the log is the only record of them.

Boot **closes them out**. Every run reaches a terminal state
(`run.finished{status:'error', reason:'orphaned by a kernel restart'}`, carrying
the cost and call counts read back from the log — the run really did spend that),
every approval reaches a decision (`expired`, with no connection id, because
nobody decided it), and every hold ends as `quarantine.abandoned`.

Delegation adds a fourth: a parent that died waiting inside `kernel.delegate`
leaves a `delegation.admitted` with no `delegation.result`. Boot writes the
missing result — the child's own terminal status and cost if it reached one,
`error` and its counted cost if it did not, taint `clean` only when the log proves
it — between the child's terminal row and the parent's, the order the live kernel
uses. An orphaned parent's recovered cost counts every child it paid for, as its
live `run.finished` would have. `test/delegation-restart.test.ts` crashes a real
kernel with a child mid-call and checks all of it, plus that a second restart
finds nothing left.

It does **not** resume them, and that is a design decision rather than a gap:

- Held content is never written to the log. That is deliberate — the record is
  what an audit needs, and putting attacker-chosen text in an immutable log
  forever is the worse trade. So a recovered hold has nothing to release, and
  ending it as `abandoned` rather than `released` is the difference between "a
  person read this and allowed it" and "nobody ever saw it".
- Run state is not persisted. An approval restored as *pending* would belong to a
  run that no longer exists: approving it would mint a ticket nothing can consume,
  while telling you that you had unblocked work. Failing closed is the safer half.

Resuming a run across a restart needs run state and held content persisted, and
both are their own decisions with their own costs. Neither is pretended here.

Also true, and not stubs so much as scope: `config/tool-views.yaml` pins
**19 pmmcp tools closed** — the nine the schema forces, plus ten the operator
pinned kernel-only after pmmcp's source was read (`forget`, the vault-adjacent
tools, `repair_and_heal`, `index_git_history`, and `scrape_context`, which makes
pmmcp fetch URLs itself and so would route around the Phase 2 egress proxy).
Nothing is exposed to agents. Every other tool is kernel-only by the schema's
literal default until the operator classifies it from `hub.tools.classified`.
Before `recall` or `remember` is ever exposed: pmmcp treats a missing
`project_id` as GLOBAL scope, so the gate's namespace pin must set it. Every
non-Anthropic entry in `config/providers.yaml` is `placeholder: true` and the
router refuses to serve one.

`SecretsBroker.keyArg` is **unverified** against a live pmmcp until either
`npm run capture:pmmcp` records the live schema or line 2 of the checklist below
passes. The broker fails closed if the live schema disagrees: `broker.start()`
throws on drift, and boot turns that into a DEGRADED secrets subsystem whose
reason names the argument and the config line to change.

### The fleet

Four manifests ship: `ceo` (the only `role: orchestrator`), `worker-template` (a
template, never run — the registry spawns from it and clamps every child against
it), and the pair `researcher` / `writer`.

The pair earns two manifests rather than one with two souls, on axes the kernel
enforces:

| | `researcher` | `writer` |
|---|---|---|
| tier (gate posture) | 1 — read-only | 2 — may hold `write` tools |
| memory namespace | `aos/agent/researcher` | `aos/agent/writer` |
| budget | 12 model calls, 40 tool calls, $0.50 | 8 model calls, 10 tool calls, $0.75 |

Memory is per agent, and the gate enforces it: a tool view may declare a
`namespaceArg`, and the gate denies any call whose value for it is not the calling
agent's own `memory.projectId` — including a call that omits it — before any
approval could be asked for. `tool-views.yaml` refuses to expose a pmmcp tool
without that decision written down, so the first `recall` exposure cannot open
every namespace by accident.

Tier is checked at load as well as at call time: a manifest naming a tool whose
risk exceeds its tier is refused with the file named. Budgets are checked at load
too — a manifest may only lower a kernel ceiling. Neither agent declares a
`sandbox:` (the loop runs in process in this phase, so a domain would claim an
isolation that does not happen), an `egress.allow` host (no proxy exists to enforce
one), or a `schedule:` (the only routable model is a frontier one, and an
unattended run that can reach it can empty an envelope).

Both carry `tools.allow: []`, which is the honest state and not an oversight:
`tool-views.yaml` exposes nothing to agents, and the registry refuses a manifest
that names a tool the views withhold. So today the difference between the two is
enforced in three places and observable in none — each agent's `AGENTS.md` says so
rather than implying a capability that is not wired.

### Goals

The CEO's plan becomes a goal tree, and the kernel is the only thing that writes
it. A finished orchestrator run whose result carries a `ProposedPlan` (schema in
`src/goals/plan.ts`) is validated — duplicate ids, dangling or cyclic
`dependsOn`, unknown templates and over-long titles are all refused — and written
into that agent's own memory namespace as objective → milestone → task, logged as
`plan.adopted` plus one `goal.created` per goal. The model proposes structure; the
kernel decides whether it is admissible. Set `goals.adoptFromRuns: false` to watch
the CEO before it writes anything durable.

A run started with a `goalId` moves that goal: `in_progress` when it starts,
`review` when it finishes well, `blocked` when it does not, and `blocked` again if
a restart finds it orphaned. **The kernel never writes `done`** — `review` sits
between `in_progress` and `done` precisely so that finishing is a decision, and a
kernel that closed its own goals would make every completion self-reported.

pmmcp has no `review` status (its vocabulary is `pending`, `in_progress`,
`completed`, `abandoned`, `blocked`), so `review` is sent as `in_progress` with
`progress_pct: 100` and stays `review` in the kernel's log (`goals.statuses`).
**Closing a goal is yours, in pmmcp** (`complete_goal`, or `update_goal` to
`completed`/`abandoned`); the kernel has no command for it, because one would
change the frozen protocol v1. pmmcp's `update_goal` takes no `project_id` and
moves any goal by id, so the kernel moves only goals its own `goal.created` log
says it created, in the namespace it created them in. pmmcp also answers refusals
as successful text (`Error: Cannot transition…`, `Goal x not found.`); the writer
counts a move only on pmmcp's own confirmation: `✅ Goal updated: <id>` today, or,
from contract P6, a typed result naming the same goal, status and project (100 %
for a review). A typed success it will not confirm is refused AND recorded as
`goal.unconfirmed`, because pmmcp may have acted on it; so is a created goal,
typed or prose, whose id the kernel cannot record verbatim (masked, ill-formed,
or past 128 bytes).

Every pmmcp goal tool name and argument lives in `config/kernel.yaml` under
`goals:`, confirmed by the operator's live capture (2026-10-18, re-taken with output schemas 2026-10-19), and every call
goes through the typed wrappers in `src/goals/pmmcp.ts`. They parse each
call against the strict schemas in `src/mcp/pmmcp-schemas.ts` and refuse a
status that is a decision, a create without `project_id`, or an update
carrying one, before anything reaches pmmcp. Boot compares the names, the
arguments the server requires and the types it accepts against what the
connected server declares and, on a disagreement, appends `goals.degraded` naming
it and disables goal writing — so a pmmcp upgrade is one line of YAML rather
than a patch. (It is an event and not a `status.get` subsystem key because
`StatusResult.subsystems` is a strict object in the frozen protocol v1.)

The kernel is tested against a **pmmcp double** (`test/helpers/mock-pmmcp.ts`):
an in-process MCP server with the goal hierarchy, the validated status
transitions, `project_id` namespacing, the vault and an idle-expiring session
all modelled — `get_secret` answering with pmmcp's real masked sentence unless a
test opts into `revealSecrets` for the dormant vault path. It is what lets the credential paths, invariant 7 at pmmcp's
real tool count, and a reconnect after a `-32001` be tested with no pmmcp anywhere. The
goal and vault tools are served verbatim from the capture
(`test/fixtures/pmmcp-listtools.json`) and marked `confirmed` in `PMMCP_TOOLS`.
The other tools' argument names are checked against the capture, but their types
are not; `provenance` says which is which. Reply texts are read from pmmcp's
source, because a capture shows arguments and descriptions but never replies; the
status vocabulary and the transition table, which the captured `update_goal`
states in prose, are held to it by `test/pmmcp-drift.test.ts`.

---

## Phase 1 live runtime tests

`test/live-runtime.test.ts` points the Phase 1 machinery at the real things. Each
test is a BODY in `test/helpers/runtime-bodies.ts` that `test/runtime-bodies.test.ts`
also runs offline on every `npm test`, against the pmmcp double and a scripted
provider — so every assertion a live run depends on has already been seen to pass,
and a live test cannot rot unexercised the way a gated-only one does.

| Test | Needs | What only a live run settles |
|---|---|---|
| goal tools round-trip | pmmcp + both opt-ins | whether the real server still matches the captured goal tool names, arguments and types in `kernel.yaml`, and whether its replies are the ones read from its source — the first assertion is the boot check, and it names every disagreement |
| plan → tree | pmmcp, `ANTHROPIC_API_KEY`, both opt-ins | whether a real model's plan survives the `.strict()` parser; on failure the message carries the parser's own reason and the model's words |
| eval harness gates | `ANTHROPIC_API_KEY` | whether the harness's own gates — one terminal row, paired LLM events, cost equal to the sum of logged calls — hold against a real provider's accounting |
| Phase 1 exit: objective → tree + children + summary | pmmcp, `ANTHROPIC_API_KEY`, both opt-ins | whether the shipped CEO, on a real model, adopts a plan into `aos/agent/aos-live-test`, delegates at least two tasks, and ends with a summary the log backs (every child named, every cited id real) |
| Phase 1 exit: a restart mid-run | pmmcp, `ANTHROPIC_API_KEY`, both opt-ins | whether a kernel that dies with a child in its first real model call orphans nothing, and whether the real pmmcp accepts the recovery's move of that child's goal to `blocked` |

`test/live-anthropic.test.ts` carries one more of these: **rejected-call replay**
(needs `ANTHROPIC_API_KEY`). When a model calls a tool the kernel will not run, the
loop replays the call as a `tool_use` and answers it with an `is_error` result. The
Messages API docs confirm the pairing rules but not whether history may carry a
`tool_use` for a tool the request does not offer — nor any `tool_use` when the
request has no `tools` field, which is what the shipped writer sends. Two small
calls settle both; a 400 is a kernel bug, not a flake. Its body
(`test/helpers/replay-body.ts`) runs offline in `test/wire-replay.test.ts` against
a fake that enforces the documented rules.

Two opt-ins, deliberately separate. `AOS_LIVE_TESTS=1` spends money and needs the
network, as in Phase 0. **`AOS_LIVE_PMMCP_WRITES=1` is required for anything that
writes to your long-term memory**: spending ends, but a goal written into pmmcp
stays there. Everything these tests write goes to **`aos/agent/aos-live-test`** —
never `aos/ceo`; the plan test runs a `live-ceo` orchestrator whose memory is that
namespace — and nothing is deleted afterwards, because the kernel has no delete
and a test must not grow one. Inspect or clear that namespace yourself.

`ANTHROPIC_API_KEY` comes from `.env`, or from a shell export that is not blank,
which wins. Never type a key on the command line: zsh saves it to
`~/.zsh_history`. Run one of these, not both.

The model only, which is cheapest:

```bash
AOS_LIVE_TESTS=1 npm test
```

Everything, including pmmcp writes to `aos/agent/aos-live-test`:

```bash
AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_WRITES=1 \
  PMMCP_URL=http://127.0.0.1:8766/mcp npm test
```

Run `npm run capture:pmmcp` first if you can: the goal-tools test will name any
mismatch either way, but the capture names them all at once without writing
anything.

---

## Mutation catalog (`npm run falsify`)

A test that passes proves little until it has been seen to fail against the bug
it claims to catch. `scripts/falsify/catalog.ts` writes those bugs down: each
mutant is one exact edit to a source file that reintroduces a specific failure
(a task delegated twice, a child's spend not charged upward, a rejected tool
call dropped from the replay), grouped into suites with the tests that must
catch them. `npm run falsify` applies each, runs its suite's tests, and puts the
file back.

```bash
npm run falsify
npm run falsify -- recovery
npm run falsify -- --only D13,W3
npm run falsify -- --list
```

In order: every suite (seventeen, see `--list`); one suite, or several
space-separated; named mutants, across suites; the catalog, touching nothing.
`--recover` restores what an interrupted run left and runs nothing else;
`--timeout MS` bounds each test run (default 240000).

It exits 0 only when every mutant is **killed**, every suite's comment-only
**control** survives, and every suite's unmutated baseline is green. **Hung** is
not a kill (a hang is a test with no bound), and a mutant that leaves the file
unparseable or stops the test files loading is **invalid**, never a kill.

It edits the working tree (src/ and two test helpers), so:

- it refuses a file with uncommitted changes (`--allow-dirty` to override);
- it holds `.falsify/lock.json` for the whole run, naming its pid and that
  process's start time (read from `ps` in UTC, so a zone change mid-run does
  not orphan it), so a second run on the same tree refuses, and a pid reused
  after a crash or reboot never passes for a live run. A live pid `ps` cannot
  vouch for counts as a live run; a stale lock is broken only under
  `.falsify/lock.break`, so runners started together on one cannot both take
  it;
- before every edit it writes the original bytes, tagged with its run id, to
  `.falsify/journal.json` (temp file, fsync, rename);
- on SIGINT, SIGTERM, SIGHUP (a closed terminal) or SIGQUIT it restores the
  file, kills the running test's whole process group, and releases the lock,
  and a second signal during that cleanup (npm forwards Ctrl-C; a closing
  terminal sends SIGHUP twice) cannot cut it short; it kills a hung test's group
  on timeout;
- a run killed outright (SIGKILL, a power cut) is restored by the next start,
  or by `npm run falsify -- --recover`. Until then `npm run dev` refuses to
  start on any journal, and `npm test` refuses to run unless it is that run's
  own test process (`AOS_FALSIFY_RUN`), because a source file may still hold a
  planted bug. Both also refuse while a live run holds the lock, between
  mutants too, since its next mutant is seconds away;
- an option it does not know, `--only` or `--timeout` with no value or given
  twice, a selection that names no mutant, and `--only` ids outside the suites
  named are refused, never read as "run everything" or as a clean pass.

`test/falsify.test.ts` drives the runner against real processes: a SIGKILL
mid-mutant, each of the four restoring signals mid-mutant, a second signal
during cleanup, a second run during the first one's baseline, six runners
racing for one stale lock, a reused pid, a missing `ps`, and the program's
usage errors; it also refuses an unreadable journal in-process, and the
`runner` suite proves those tests catch the bugs they name.
`test/falsify-hold.test.ts` proves the daemon's refusals in-process (and
`test/entrypoints.test.ts` that the daemon applies them), `test/env.test.ts`
the test guard's. On every `npm test`, `test/falsify.test.ts` also checks that
every catalog anchor still matches exactly once — a refactor that moves one
fails the suite instead of silently disabling its mutant — and that no
catalog mutant could let a test open the real `.env`.

Run it after changing delegation, crash recovery, tool-call replay, the memory
namespace pin, goal tracking, anchor trust, the eval checks, the chain /
canonicalizer / triggers (`integrity`), redaction, the cron scheduler, the agent
registry, restart recovery of approvals and holds, the container audit and path
containment (`sandbox`), the `.env` loader and the credential checks around it
(`dotenv`, and `dotenvDefault` for how an entry point picks its file), the
`.gitignore` reading (`gitignore`), or the runner itself (`runner`) — the
seventeen suites — and add a mutant
whenever a new test exists to catch a specific bug. No test may let a mutant
reach your real `.env`: `test/entrypoints.test.ts` runs every entry point from a
temporary copy of the checkout holding a trap `.env`, through `runEntry` /
`spawnEntry`, which set that copy as the cwd themselves (and `hygiene.test.ts`
reads every test's syntax tree to hold each entry-point run to them),
in-process loader tests are told their
repository is a trap directory, and the live helper opens `<repo>/.env` only
from a live test's own process. `test/falsify.test.ts` also refuses a catalog
that puts an entry-point or `.env`-path mutant beside the entry-point spawns, as
a second line. The `integrity` and
`redaction` suites edit change-controlled files (chain hashing, the triggers,
the redaction pass) and restore them; the operator approved keeping them in the
catalog on that basis.

Last full run, against commit `184576e`, in two batches (the first eight suites,
then the other nine, each exit 0): 295 of 295 mutants killed (delegation 20,
recovery 12, replay 8, namespace 7, goals 64, anchor 8, eval 11, integrity 21,
redaction 17, schedule 13, registry 13, restart 8, sandbox 23, dotenv 41,
dotenvDefault 3, gitignore 15, runner 11), 17 of 17 controls survived. Every kill
names a behavioural test; none rests only on the anchor or catalog checks. Before
it: `2198209`, 236 of 236; `4a50262`, 234 of 236 (S11 and S12 survived because the
value scrubber masked the shaped values the path-redaction tests logged, and
`2198209` gave those tests values only a path can catch). A result is a fact
about that commit only; rerun it rather than trusting this line after a change.

---

## Exit-criterion checklist

CLAUDE.md's Phase 0 exit is: *"daemon boots with pmmcp connected and `aos run
ceo "…"` produces `run.finished` with non-zero cost."* Phase 0 is exited when
line 2 passes on the Mac and line 3 is recorded here. Nothing in this repository
can fill these in; they require the operator's machine, keys and money.

**Phase 0 exited on 2026-10-19**, all three lines at commit `c80f7be`, run by the
operator on the Mac against pmmcp at `127.0.0.1:8766` and `anthropic/claude-sonnet-5`.

The first attempt was refused with HTTP 400 before any generation (nothing was
spent): *"This API key is not scoped to a workspace, so this request must include
the anthropic-workspace-id header"*. The kernel sends no such header, so the
Anthropic key must be created inside a workspace in the Claude Console. A key made
for one workspace needs no header.

**1. LLM half — the provider path only.** Proves the router, the adapter and the
cost accounting against real Claude, with no pmmcp connected, so it can never
stand in for line 2.

`ANTHROPIC_API_KEY` comes from `.env`, or from a shell export that is not blank,
which wins.

```bash
AOS_LIVE_TESTS=1 node --import tsx --test test/live-anthropic.test.ts
```

The passing test prints `costMicroUsd=<N>` as a test diagnostic (`ℹ` in the
terminal's spec output, `#` in TAP); that is the number recorded below.
`AOS_LIVE_TESTS=1 npm test` runs the same test plus every other live test, at
roughly twice the cost.

- Result: pass. 2 passed, 1 skipped by design: the exit-criterion test needs `PMMCP_URL`, and line 2 runs it. The rejected-tool-call replay passed against the real Messages API.
- Date: 2026-10-19
- Commit: c80f7be
- `costMicroUsd`: 2770 (llmCalls 1)

**2. The exit criterion, automated.** pmmcp connected and its tools classified,
the key resolved from the environment (`secret.accessed { source: 'env' }`), a
fresh probe, then a run with non-zero cost, in that log order. pmmcp is the
memory and goal store here, not the key store: its `get_secret` masks by design.

The key comes from the same place.

```bash
AOS_LIVE_TESTS=1 PMMCP_URL=http://127.0.0.1:8766/mcp node --import tsx --test --test-name-pattern="Phase 0 exit criterion" test/live-anthropic.test.ts
```

`PMMCP_URL` is required (the test skips without it) and is read only by the
test, which writes it into its own temporary `kernel.yaml`. The test runs the
shipped CEO against the operator's real pmmcp: a reply that plans could write
goals under `aos/ceo`, and pmmcp has no tool to delete them. It prints
`costMicroUsd=<N>` the same way.

- Result: pass. 1 passed. pmmcp connected (`degraded`: sandbox, router, egress; no `hub`), and its 46 unclassified tools defaulted to kernel-only.
- Date: 2026-10-19
- Commit: c80f7be
- `costMicroUsd`: 2770 (llmCalls 1)

**3. The literal criterion, by hand.** The sentence in CLAUDE.md names the
daemon and the CLI, so it is exercised as written rather than only in-process.

In one shell, with pmmcp up:

```bash
npm run dev
```

In a second shell:

```bash
npm run cli -- run ceo "reply with the word pong"
npm run cli -- verify-chain
```

- Result: pass. `probe` reported `toolCalling=true`, and `run` printed `ok`. `run.finished` carried `"status":"ok"`, `llmCalls` 1 and `toolCalls` 0. `secret.accessed` carried `"source":"env"`. No `goal.created` row was written.
- Date: 2026-10-19
- Commit: c80f7be
- `runId`: run_1792371549403_2lc91w
- `costMicroUsd`: 2770
- `verify-chain` output: `ok	31 events	head 277c4dd3c176dbfd7cec2b66047d5898650b85bd1d6aced9b66f9337c1e0c51f` (31 is the `run.finished` row; taken before a `kernel.shutdown` row was appended)

---

## Phase 1 exit-criterion checklist

CLAUDE.md's Phase 1 exit is: *"one objective → goal tree + ≥2 child runs +
trustworthy summary; kernel restart mid-run orphans nothing."* Phase 1 is exited
when lines 1 and 2 pass on the Mac and are recorded here. Both run the shipped CEO
as `live-ceo`, a copy that differs only in its id and in remembering in
**`aos/agent/aos-live-test`**, so nothing is written to `aos/ceo`. The goals they
write stay in that namespace; pmmcp has no delete the kernel calls.

All three lines come from one run of the live runtime file, with pmmcp up and
both opt-ins (`ANTHROPIC_API_KEY` from `.env`, or a shell export that is not
blank):

```bash
AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_WRITES=1 PMMCP_URL=http://127.0.0.1:8766/mcp node --import tsx --test test/live-runtime.test.ts
```

Lines 1 and 2 print `runId=…` / `ceoRunId=…` and `costMicroUsd=…` as test
diagnostics (`ℹ` in the terminal), which is what is recorded below. The cost is
what the log records, the probe included, and it is the whole bill: in line 2
the crash comes before the child's first request leaves the process, so that
call is logged as a request and never sent. A failure in
line 1 names the eval gate that failed and every check's verdict: a model that
answers alone fails `child-runs`, a summary that leaves out a child fails
`child-outcomes-accounted`.

**1. One objective → goal tree + two child runs + a trustworthy summary.** The
eval harness's fan-out case, judged from the log alone.

- Result: pass. 1 passed. `live-ceo` adopted the objective into a tree in `aos/agent/aos-live-test` and delegated to the standing workers; every exit gate passed on the log alone (score 1). Not applicable to this case: `no-call-after-deny`, `declared-work-in-log`, `no-forbidden-string-in-log`, `depth-within-ceiling`.
- Date: 2026-10-20 (operator local; 06:30 UTC on 2026-10-21)
- Commit: d73c485
- `runId`: run_1792564244840_grjrwc
- `costMicroUsd`: 177456

**2. A kernel restart mid-run orphans nothing.** The kernel dies with a child in
its first model call; a reboot on the same data closes every run and admission
in causal order, blocks the child's goal in pmmcp, calls no model, and a second
reboot finds nothing to do.

- Result: pass. 1 passed. The kernel died with child `run_1792564397130_0aa3u4` in its first model call. The reboot closed both runs and the child's admission, and the real pmmcp accepted the move of the child's goal to `blocked`. A third boot found nothing to do. The dead kernel's in-flight `in_progress` update for that goal failed with `Connection closed` (one warning, expected: the crash cut its connection), so it could not land after the block.
- Date: 2026-10-20 (operator local; 06:32 UTC on 2026-10-21)
- Commit: d73c485
- `ceoRunId`: run_1792564367277_0hcd8x
- `costMicroUsd`: 39252

**3. The other Phase 1 runtime checks.** Goal tools round-trip against the live
server, a real plan through the strict parser into the test namespace, and the
eval harness's gates against real accounting.

- Result: pass. 3 passed: the goal tools match the server and a tree round-trips; the orchestrator's plan survives the strict parser into the test namespace; the eval harness's gates hold against real accounting (`ceo-inline-small-objective`: gates failed [], score 1, did not run 10). The whole file: 5 passed, 0 failed, 178 s.
- Date: 2026-10-20 (operator local; 06:30 UTC on 2026-10-21)
- Commit: d73c485

---

## Decisions

All 30 open decisions were answered on 2026-09-21 and are recorded per row in
`docs/DECISIONS.md`. Every default was accepted except **D13**: the single real
Claude entry is `claude-sonnet-5`, not `claude-opus-5`, for its cost/intelligence
ratio on orchestration.

Nothing is pending. A decision that reopens belongs in that file with a date,
not in a commit message.

---

## pmmcp is unauthenticated, and that is accepted for now

pmmcp trusts loopback and checks no credential. Anything on the Mac can call any
of its tools, including the vault and `admin`. The operator accepted that for now,
on two conditions the kernel enforces or will enforce:

- **Containers stay off it.** Inside a Colima VM the Mac's loopback is
  `192.168.5.2` (`host.lima.internal`). The sandbox probe refuses a domain whose
  docker network is not `--internal`, so no container has a route there.
- **The Phase 2 egress proxy denies it**: `192.168.5.2`, `host.lima.internal`,
  `host.docker.internal`.

Revisit (a bearer in pmmcp) before Phase 4 makes Telegram and SMS inputs. Nothing on the
client side blocks it. The operator's IDE, Antigravity, sends a configured
`headers` Authorization over Streamable HTTP: a probe on 2026-10-25 pointed it at a
listener with `Bearer aos-header-probe`, and the header arrived on its first
request. The kernel already sends one once `kernel.yaml` declares `tokenEnv`.

## Sandbox checks on the Mac (2026-10-21)

The operator ran these against both Colima VMs: Colima 0.10.3 from Homebrew,
`vz` with virtiofs, Docker Engine 29.5.2, and 4 CPUs, 4 GiB and 60 GiB each, all
from one uninterrupted `scripts/colima-up.sh` run. The container was `alpine:3.20`
started with the driver's own `docker run` flags (`buildRunArgs` in
`src/sandbox/docker.ts`, limits from `config/kernel.yaml`): uid 65534, on the
domain's internal network, with the domain's `mountRoot` at `/workspace`. Both VMs
gave identical results.

| Check | Result |
|---|---|
| Identity and capabilities | `uid=65534`; `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` all zero; `NoNewPrivs: 1` |
| Filesystem | the root is mounted `ro`; `/tmp` is tmpfs `rw,nosuid,nodev,noexec,size=64m`, and a binary copied there does not execute |
| Limits | `pids.max` 256, `memory.max` 2147483648, `cpu.max` `200000 100000` (cgroup v2) |
| Network | no default route; `host.lima.internal`, `host.docker.internal` and `example.com` do not resolve, while the same image on the default bridge resolves `example.com`; `192.168.5.2:8766` is `Network unreachable` |
| VM shares | exactly one virtiofs mount per VM, that domain's `mountRoot` |
| Docker CLI environment | `docker version` works under `env -i` with only `PATH`, `DOCKER_HOST` and `DOCKER_CONFIG`, so the driver's environment needs no `HOME` |
| File events | an `fs.watch` on the Mac sees a file a container writes into a workspace |

Two results the Phase 2 design has to carry:

- **The share does not enforce permissions per container user.** uid 65534
  wrote into a mode-0755 folder the operator owns. Every file a container writes
  lands on the Mac owned by the operator (`501:20`), whatever its uid in the
  container. Mode bits on the Mac therefore isolate nothing inside a VM. What a
  container can touch is decided only by what the driver mounts, which is one
  run's workspace. A process that escapes into a VM can write the whole of that
  domain's `mountRoot` as the operator. Anything on the Mac that reads a workspace
  is reading untrusted input.
- **The VMs themselves reach pmmcp.** Inside the hostile VM, `host.lima.internal`
  is `192.168.5.2`, and `192.168.5.2:8766` accepts a connection. Today the internal
  network is the only thing between a container and pmmcp. Anything with a route
  out of a VM reaches it unauthenticated: the default bridge, a network that is
  not internal, the Phase 2 proxy itself, or an escape into the VM.

## Still needs validation

Facts this repository cannot check from Linux, and how each gets settled. The
first three of the plan's list are already resolved (Node v26.9.0; pmmcp at
`http://127.0.0.1:8766/mcp`, loopback with **no** authentication — read from pmmcp's
source, which trusts loopback and publishes RFC 9728 metadata with no authorization
servers, so kernel.yaml declares no `tokenEnv`; `get_secret` takes `label`,
not `key`). The Colima sandbox rows were settled on 2026-10-21; see "Sandbox
checks on the Mac" above.

| Fact | How it gets settled |
|---|---|
| `node:sqlite` on darwin-arm64: `DatabaseSync` `timeout` runtime behaviour, `errcode 1811` stability, `t.mock.timers` | `npm test` on the Mac; `test/env.test.ts` fails first, with a named reason |
| pmmcp: Streamable HTTP interop with SDK 1.32.1 (same-origin redirects only, from 1.32.0), idle timeout vs the 240 s heartbeat (the 64 tool names, their input schemas and their output schemas, every one FastMCP's `{result: string}`, are captured in `test/fixtures/pmmcp-listtools.json`, re-taken 2026-10-19) | boot with pmmcp up: `hub.connected` and `hub.tools.classified` list what is really there; checklist line 2 |
| An Anthropic API key accepted as `Authorization: Bearer` (D20's alternative) | one `npm run cli -- probe anthropic/claude-sonnet-5` with `auth.header: Authorization` |
| Whether SIGKILL of the docker client leaves its container running, which is why the driver kills by name | Phase 2 live Docker driver tests |
| `scripts/colima-up.sh` on a VM that is running but whose first start never finished: `colima status` fails, `colima start` answers `already running, ignoring`, and the script still prints `Done.` without its mounts or sizes applied (seen on 2026-10-21; still marked NEEDS VALIDATION on line 2) | Phase 2: the script fails unless `colima status` succeeds after the start and the VM's virtiofs mounts are exactly its `mountRoot` |
| Moonshot base URL, model ids and pricing; OpenRouter `usage.cost` semantics; llama.cpp `include_usage`, named `tool_choice`, `--jinja`, and the `/props.chat_template_caps.supports_tool_calls` key name | `npm run cli -- probe <ref>` per entry, and `GET /v1/models` once keys are in the vault |
| `@tauri-apps/plugin-websocket` custom-header support — a Phase 3 blocker for invariant 1 | a Phase 3 spike, before any protocol change |
