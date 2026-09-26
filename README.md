# aos-kernel

The kernel — the control plane — of a local-first Agentic OS for a single
operator on one Mac. A CEO agent orchestrates a fleet; every action lands in a
hash-chained, append-only event log; pmmcp (the operator's Persistent Memory MCP
server) is shared long-term memory and the secrets vault; models are bound per
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
node --version                 # confirm the floor above
npm run typecheck              # must be clean
npm test                       # must be green
```

The daemon needs `AOS_CONTROL_TOKEN` (at least 32 characters) in the
environment, and refuses to start without it. There is no `--env-file` flag on
`dev` or `cli` by design (D7): source your `.env` yourself.

```bash
export AOS_CONTROL_TOKEN="$(openssl rand -hex 32)"
export PMMCP_TOKEN=…           # optional; without it the kernel boots with no vault
npm run dev
```

With no pmmcp and no Docker the kernel boots **degraded** and says exactly what
is missing. That is the designed behaviour, not a failure — see below.

`dataDir` defaults to `~/.aos`, outside the repository (D25), and is created
`0700` on first boot. `AOS_DATA_DIR` overrides it.

---

## Commands

```bash
npm run typecheck        # tsc --noEmit
npm test                 # node --import tsx --test test/*.test.ts
npm run dev              # daemon on 127.0.0.1:7777
npm run build            # emits dist/
npm run cli -- <cmd>
```

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
| `scheduler` | `src/runtime/scheduler.ts` | `Scheduler.start()` throws `NotImplementedError`; a manifest carrying `schedule:` is refused at parse |
| `delegate-tool` | `src/runtime/delegate.ts` | `assertDelegationAvailable()` throws `NotImplementedError`; no delegation tool is offered to any model |
| `approvals-projection` | `src/policy/approvals.ts` | `rebuildFromLog()` throws `NotImplementedError` rather than returning an empty set after a restart |
| `quarantine-projection` | `src/policy/quarantine.ts` | `rebuildFromLog()` throws `NotImplementedError` rather than returning an empty set after a restart |

Two of these deserve spelling out. **Restart-safe projections are absent**: after
a restart the kernel does not know which approvals were pending, and
`rebuildFromLog()` throws rather than answering "none" — because "nothing is
pending" is a dangerous lie that would make a run parked on a human decision
look answered. And **no delegation tool is offered to any model**: the CEO can
plan, but in Phase 0 it cannot actually spawn or delegate, so the fleet it
describes does not exist yet.

Also true, and not stubs so much as scope: `config/tool-views.yaml` classifies
**9 of pmmcp's 49 tools**, and all nine are pinned closed — nothing is exposed
to agents. The remaining 40 are kernel-only by the schema's literal default
until the operator classifies them from the `hub.tools.classified` event. Every
non-Anthropic entry in `config/providers.yaml` is `placeholder: true` and the
router refuses to serve one.

`SecretsBroker.keyArg` is **unverified** against a live pmmcp until line 2 of
the checklist below passes. The broker fails closed if the live schema
disagrees.

---

## Exit-criterion checklist

CLAUDE.md's Phase 0 exit is: *"daemon boots with pmmcp connected and `aos run
ceo "…"` produces `run.finished` with non-zero cost."* Phase 0 is **not**
exited until line 2 passes on the Mac and line 3 is recorded here. Nothing in
this repository can fill these in; they require the operator's machine, keys and
money.

**1. LLM half — the provider path only.** Proves the router, the adapter and the
cost accounting against real Claude. Uses the env fallback (D8), so it can never
stand in for line 2.

```bash
AOS_LIVE_TESTS=1 ANTHROPIC_API_KEY=… npm test
```

- Result: _not yet run_
- Date: —
- Commit: —
- `costMicroUsd`: —

**2. The exit criterion, automated.** Requires the Anthropic key already stored
in the pmmcp vault under the `vaultId` that `config/providers.yaml` names
(`anthropic-api-key`) — a one-time manual step outside the kernel. `envFallback`
is off and `ANTHROPIC_API_KEY` is poisoned by the test, so the vault is the only
working credential path. This is also the first time `secrets.keyArg` is
confirmed against the live `get_secret` schema.

```bash
AOS_LIVE_TESTS=1 PMMCP_URL=http://127.0.0.1:8766/mcp PMMCP_TOKEN=… npm test
```

- Result: _not yet run_
- Date: —
- Commit: —
- `costMicroUsd`: —

**3. The literal criterion, by hand.** The sentence in CLAUDE.md names the
daemon and the CLI, so it is exercised as written rather than only in-process.

```bash
# shell 1, with pmmcp up
npm run dev

# shell 2
npm run cli -- run ceo "reply with the word pong"
npm run cli -- verify-chain
```

- Result: _not yet run_
- Date: —
- Commit: —
- `runId`: —
- `costMicroUsd`: —
- `verify-chain` output: —

---

## Decisions

All 30 open decisions were answered on 2026-09-21 and are recorded per row in
`docs/DECISIONS.md`. Every default was accepted except **D13**: the single real
Claude entry is `claude-sonnet-5`, not `claude-opus-5`, for its cost/intelligence
ratio on orchestration.

Nothing is pending. A decision that reopens belongs in that file with a date,
not in a commit message.

---

## Still needs validation

Facts this repository cannot check from Linux, and how each gets settled. The
first three of the plan's list are already resolved (Node v26.9.0; pmmcp at
`http://127.0.0.1:8766/mcp`, loopback with a bearer; `get_secret` takes `label`,
not `key`).

| Fact | How it gets settled |
|---|---|
| `node:sqlite` on darwin-arm64: `DatabaseSync` `timeout` runtime behaviour, `errcode 1811` stability, `t.mock.timers` | `npm test` on the Mac; `test/env.test.ts` fails first, with a named reason |
| pmmcp: bearer acceptance, Streamable HTTP interop with SDK 1.30.0, idle timeout vs the 240 s heartbeat, the 49 tool names, `get_secret`/`set_secret` schemas | boot with pmmcp up: `hub.connected` and `hub.tools.classified` list what is really there; checklist line 2 |
| An Anthropic API key accepted as `Authorization: Bearer` (D20's alternative) | one `npm run cli -- probe anthropic/claude-sonnet-5` with `auth.header: Authorization` |
| Docker on Colima: `--cap-drop=ALL` → empty `CapEff`; `--read-only` plus a `/workspace` writable by `65534` through virtiofs; `~/.colima/<profile>/docker.sock` paths; FSEvents through virtiofs | `scripts/colima-up.sh` (itself marked NEEDS VALIDATION on line 2) then the security check commands; Phase 2 live tests |
| Whether the docker CLI works with a spawn env of only `PATH` + `DOCKER_HOST`, or needs `HOME` for `~/.docker/config.json` | `env -i PATH="$PATH" DOCKER_HOST=unix://$HOME/.colima/trusted/docker.sock docker version`. If it needs `HOME`, the driver adds `HOME` **only** — never the full environment |
| Moonshot base URL, model ids and pricing; OpenRouter `usage.cost` semantics; llama.cpp `include_usage`, named `tool_choice`, `--jinja`, and the `/props.chat_template_caps.supports_tool_calls` key name | `npm run cli -- probe <ref>` per entry, and `GET /v1/models` once keys are in the vault |
| `@tauri-apps/plugin-websocket` custom-header support — a Phase 3 blocker for invariant 1 | a Phase 3 spike, before any protocol change |
