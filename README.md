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

### Install with npm run aos-install

```bash
npm run aos-install -- --dry-run
```

```bash
npm run aos-install
```

The first only looks: it finds pmmcp, reads what `.env` holds by name, and
prints the plan, every step as "would" and every question and word it would ask
you, then `dry run: nothing was changed`. The second does it, asking first. Run
it from the repository root, and in a terminal. npm moves the script to the root
whatever folder you type it in, but keeps its own cache and logs under that
folder (`.npmrc`'s `cache=.aos/npm-cache`, where git does not ignore them), so a
run typed anywhere else is refused with the `cd` to make. With stdin not a
terminal it prints the plan and exits 3, because only you, at a terminal, may
confirm a change. What it does, in order (`scripts/install.ts`; decisions
D33, D35 and D36):

- **Preflight**, read-only. It refuses root, a tree a falsify run holds, a Node
  outside `engines`, a `.gitignore` that stops ignoring `.env` or `/.aos/`, a
  `.aos` or `.aos/install` that is not yours to write in ("belongs to uid N,
  not you: fix its owner (chown) and re-run"), and
  a missing program that pmmcp or the installer runs (git, curl, uv, ollama,
  python3, bash, docker, lsof, ps, pgrep, launchctl, plutil, and Docker
  Desktop's credential helper when `~/.docker/config.json` names it; not
  checked with `--aos-only`). Every program the run will start (ls, ps, pgrep,
  lsof, plutil, launchctl, docker, git; ls and ps alone with `--aos-only`,
  whose programs line says so) and, unless `--aos-only`, every one pmmcp's
  scripts run by name (bash, curl, uv, python3, ollama) is
  looked up on the PATH a child gets and held to the installer's rules then,
  without running it (below), so a file there that the rules refuse stops the
  run before the lock, `.env` or any program. Its `pmmcp's scripts` line names
  the bash their `#!/usr/bin/env bash` finds on that PATH and its version when
  the file's bytes spell it out (read, never run: bash composes the version it
  prints when it runs, so a build may hold none, and the line then says the
  version is not readable), and says your login shell (`$SHELL`, zsh on a Mac)
  is not used, because the installer runs every program itself.
  It names any of `DOCKER_CONFIG`, `DOCKER_HOST`,
  `DOCKER_CONTEXT` or `PMMCP_*` your shell exports: no program it starts sees
  them, nor any other `DOCKER_*`, `AOS_*` or credential name.
- **`.env`**: created at mode 0600 when it is missing, or appended with the
  token names it lacks (64 random hex each). It never changes or removes a
  line, never writes a placeholder or a blank value, and never prints a value.
  It never writes `ANTHROPIC_API_KEY`: add that yourself. A `.env` the loader
  would refuse is refused with its fix, and nothing is written. So is a token
  an earlier write cut short (one that stopped part way, on a full disk or
  past a file size limit, leaves `NAME=` and the first characters of its 64
  hex): a value of either
  token that is lowercase hex shorter than 64 characters is refused by its
  line, "looks cut short (a write that did not finish): delete that line and
  re-run", before pmmcp is looked at, and no digest of it is ever staged; so
  is a last line, with no newline, that a write stopped inside the name
  (`AOS_PMMCP_TOK`). The screen gives `.env`'s mode,
  link count and owner.
- **pmmcp**: found from its launchd plist, the process on 8766, or
  `~/Github/Persistent-Memory-MCP`, with every fact read from pmmcp's own
  interfaces. With none, it offers to install it there, after one typed
  `install` (what pmmcp's `setup.sh` then writes outside this folder is in
  "Where things live"). `kernel.yaml` declares `AOS_PMMCP_TOKEN`, and pmmcp is
  given only the `sha256:` digest of that `aos-kernel` token, never the token
  (a `kernel.yaml` that declares no pmmcp `tokenEnv` stages none). pmmcp's own
  keys (the Qdrant key, the dashboard token, the curator secret) are made by
  pmmcp's CLIs in its 0600 files under `~/.persistent-memory-mcp`, and never go
  into `.env`. Its bearer gate stays in warn mode: switching it to enforce is
  your later step. Every program it starts runs by the path its rules
  checked, never by a name looked up again; a file on that PATH that is
  pmmcp's stop or start script by a link, by identity (a hard link, a copy)
  or by its `#!` header (each of pmmcp's two names itself on its second line,
  so a link or copy of one is known wherever its install is), or a link there
  to a program it never runs, is refused before any change, exit 2, naming
  the file to remove or rename: at the preflight (by its header, or by
  identity with the default install's and `--pmmcp-dir`'s scripts), and again,
  by identity, as discovery reads an install's folder from its launchd plist
  or from the server on 8766, before its next probe. A file refused only then
  that one of discovery's read-only probes had already run (a changed copy of
  that install's script linked as plutil, say) is said to have run, with
  what to check, and the first and last lines say so too: never that nothing
  ran. One that appears later, during the run, is still named with its fix,
  and the run ends as a step that failed. A program that cannot be started is named with that file and why: a `#!` line
  naming an interpreter that is not there (in discovery's notes), a file that
  lost its execute bit (with the `chmod u+x`), or one that is gone. A refusal of its own rules
  that nothing on the machine causes is its defect: exit 1, said as one.
- **Live pmmcp changes** (a restart to load the digest, the Qdrant key
  cutover, the dashboard token and curator secret, a fast-forward of its code,
  the start of a pmmcp an earlier run left stopped) are each offered with a default of no, and run only after a warning that
  says what stops and for how long, a first typed confirmation, `stop pmmcp`,
  pmmcp's job count, and a second, the folder name `Persistent-Memory-MCP`.
  pmmcp is stopped only by `stop-pmmcp-server.sh` without `--force`, and
  nothing ever sends it or the start script a signal or a timeout: inside that
  window neither Ctrl-C nor a closed terminal (SIGHUP) nor a SIGTERM ends the
  installer, which goes on to the start and its checks, and its steps run in
  sessions of their own. One exception, typed (the operator's, 2026-11-04):
  the stop's drain waits on a service with no upper bound and offers only a
  Ctrl-C, which cannot reach it there, so a Ctrl-C while the stop runs names
  the service it is waiting on (read from the stop's own output, then
  confirmed with `ps`: alive, yours, a command line holding
  `Persistent-Memory-MCP` or the install's folder, or one of pmmcp's own named
  Ollama instances, outside the installer's and the stop's process groups) and
  asks; only the typed word `force-quit` sends that one process SIGKILL, after
  `ps` shows it is still the same process (start time, owner, command line).
  The stop then sees it gone and goes on, and the installer goes on to the
  start and its checks. Anything else typed, the input ending or a second
  Ctrl-C keeps waiting; a stop that is not waiting on a service (counting
  jobs, stopping Qdrant with `docker stop -t 60`, between services) has
  nothing to force-quit, and says so. pmmcp's own named Ollama instances
  (exactly the one the stop is draining, `PMMCP-TextQuery serve`,
  `PMMCP-CodeQuery serve`, `PMMCP-TextIndex serve` or `PMMCP-CodeIndex serve`,
  or `PMMCP-Ollama serve` for any of the four, yours, with no path before the
  name) can be force-quit the same way; `ollama serve` and Ollama.app's or
  Homebrew's server (`/Applications/Ollama.app/Contents/Resources/ollama
  serve`, `<prefix>/bin/ollama serve`) cannot: only a PID file of the start
  script vouches for an `ollama serve`, the installer reads none, and the
  three look alike once a path is dropped. A Ctrl-C while the stop drains one
  of those says why and how to end it yourself (check it with `ps` in another
  terminal, and end it there if it is pmmcp's), and the stop goes on waiting
  on it. A SIGHUP or SIGTERM then, and a Ctrl-C anywhere else in the window
  (the start, the Qdrant cutover, the fast-forward, `auth init`), are trapped
  as before. A force-quit is in the end report and in the run folder's
  `force-quit.log`; a SIGKILL gives the service no drain, so a job the worker
  was running is marked failed and re-run by pmmcp (check
  `~/.persistent-memory-mcp/logs/server.log`). From the window's first opening
  until the end report is printed, a signal outside the window (at no
  question) is held as well: the run finishes its last checks and prints the
  report (whether pmmcp is left stopped, and what is left to do) first, and
  ends with its own code. There is no `--yes` and no `--force`.

Flags: `--dry-run`; `--aos-only` (`.env` only, pmmcp is never touched);
`--pmmcp-dir PATH` (use this install, still validated); `--no-install` (never
offer the clone and `setup.sh`); `--help`. Exit codes: 0 done, nothing to do,
a dry run, or declined, 1 a step failed (the end report says what state it left), 2 refused before any
change, 3 changes are needed but stdin is not a terminal, 4 a live step failed
and pmmcp is not in its intended state, 130 interrupted before the stopped
window opened (129 and 143 for SIGHUP and SIGTERM; 130 for the input ending,
or for any of those signals, at a question, which it answers, or during the
jobs count, which it ends). The flags go after `--`: npm
takes `npm run aos-install --dry-run` as its own `--dry-run` and hands the
installer nothing, so the installer refuses any flag npm took that way. The
installer's last line, `aos-install: exit N: …`, is its own code and how this
run ended (a dry run, done, declined with nothing changed, the input ended or
an interrupt at a question, a step that failed, a signal, a defect; it points
at the end report only when one was printed above it), and is the run's word:
npm 10 re-raises a Ctrl-C it forwarded, so after
one (inside the stopped window, say, where the installer goes on to the start)
`npm run aos-install` can end with status 130 for a run the installer finished
with 0 or 4. Read that line, not `$?`; or run `node --import tsx
scripts/install.ts` from the repository root, with the same flags and no `--`
before them (`node --import tsx scripts/install.ts --dry-run`): its status is
the installer's own. A dry run writes only the installer's probe
logs under `.aos/install/<stamp>/` (`active.json` too, while a `--jobs` count
runs: the count runs on if a Ctrl-C or a signal ends the installer, and its
record, marked read-only, is waited for up to 15 s by the next run, or removed
by it once the count has ended) and its lock while it runs. If its output goes
away mid-run (a `| tee` the same Ctrl-C ended, a closed terminal), it goes on,
and what it said lands in `installer.out` beside those logs. After a failure, run it again: it picks up from the state on disk,
including a pmmcp that is stopped while the last run that stopped it ran no
start after it (it was killed or crashed inside the stopped window, or a stop
did not stop and no start followed; its run folder shows it, and what you ran
by hand since is not known to it): it then offers the start, behind the same
warning and two typed confirmations. The end report's next steps say "run npm
run aos-install again and accept the restart" exactly when the `aos-kernel`
digest is on file but not known to be loaded by the running MCP server and
this run neither stopped nor started pmmcp (you declined the restart, typed
another word, or stopped at a question): pmmcp loads the digest only when it
starts. Where the jobs check cannot run (an older stop script), no restart
could be offered, and the line says pmmcp loads it at its next restart; for a
pmmcp that is not running, its next start loads it. After a stop that refused
its arguments or never ran, it never says to accept the restart: a stop that
refused its arguments (exit 2: the installer gives it none, so pmmcp's stop
script may have changed) and a refusal of the installer's own rules are to
report, and when a file, a step still running, or a stop that cannot be
started (its execute bit lost: the line names the `chmod u+x`) kept it from
running, it says to fix what that line names and run the installer again. After a stop that did not stop and a start you accepted to
restore service, it says to run the installer again, once the stop's problem
is fixed, to finish what was not reached. When nothing was applied, no end
report is printed: the plan's notes say the running server may not have
loaded the digest, and each such run offers the restart again.
After the stopped window the end report reads pmmcp's facts and Qdrant's
`status --json` again, so what it shows is what holds after the start, never
what discovery read while pmmcp was stopped; a read it cannot make (a Ctrl-C
there reaches the probe, which it then asks again) is said as a check it could
not make. A `pmmcp-qdrant` that holds its key and is only stopped, as it is
while pmmcp is, is no failure: the start runs it again. The start's own check
of a key this run made asks `status --json` once more before one failed read
fails the start, and gives the cutover's `rollback` only for a verdict read and
not `enforced`; a fresh install's key, which `init` made, has no rollback, and
the advice is what to check and that its key file goes only with pmmcp
stopped. Once everything is in place it says so and asks nothing. A
`pmmcp-qdrant-prekey` kept from a Qdrant cutover counts as in place: it is not
asked about on its own (the notes give its `qdrant_api_key.py cleanup` command,
which also ends the cutover's rollback), and is offered, default no, only in a
run that asks something else anyway.

When you pull the commit that makes `kernel.yaml` declare `AOS_PMMCP_TOKEN`,
run `npm run aos-install` before you restart `npm run dev`: a daemon restarted
first boots with its hub degraded, because the token it then needs is not set.

### The `.env` file

The daemon needs `AOS_CONTROL_TOKEN` (at least 32 printable ASCII characters,
with no whitespace, quote, backtick or `#`, from the shell and `.env` alike;
`openssl rand -hex 32` makes one; lowercase hex shorter than 64 characters is
what a write the installer did not finish leaves, so `npm run aos-install`
refuses such a value as cut short), to reach pmmcp, `AOS_PMMCP_TOKEN` (its bearer
as client `aos-kernel`, which `npm run aos-install` generates), and, to reach a
model, `ANTHROPIC_API_KEY`: a key created inside a workspace, because an unscoped
key needs an `anthropic-workspace-id` header the kernel does not send. All three live
in **your own `.env` in the repository root**: git-ignored, mode 0600, written by you, or appended by `npm run aos-install`. `.env.example` is the
committed template: placeholders only, never edited to hold a real value, and it
does not change when your `.env` does. To make it by hand rather than with the
installer:

```bash
test -e .env || (umask 077 && cp .env.example .env)
chmod 600 .env
nano .env
npm run dev
```

Line by line: the first creates `.env` from the template at mode 0600 and never
overwrites one that exists; the second sets 0600 anyway, because `cp` keeps an
existing file's mode; in the editor, replace every `replace-me-...` value
(`openssl rand -hex 32` makes a token); `npm run dev` then logs
`credentials: .env (AOS_CONTROL_TOKEN, AOS_PMMCP_TOKEN, ANTHROPIC_API_KEY)` (the
names in the order the file holds them), and `npm run cli -- agents` works from
a second shell with nothing exported.

`npm run aos-install` never changes a line, so it refuses a `.env` that still
holds a placeholder, `AOS_PMMCP_TOKEN`'s included, naming the line. For that
name, either delete its line, and the installer then appends it (run it before
`npm run dev`, which boots with its hub degraded while the name is unset), or
put in a value of your own (`openssl rand -hex 32`), whose digest the installer
then stages. Until it has, pmmcp holds no digest of your value, and in warn mode
logs the token as unknown and serves the request.

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
`AOS_DATA_DIR` or `AOS_LOG_LEVEL` from the shell if you used them. Then
`npm run aos-install` appends `AOS_PMMCP_TOKEN`.

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
  so `!*` or a leading space count), any name but the three above, a value still
  beginning `replace-me`, a character outside printable ASCII, two lines joined
  into one, a name set twice, a second `--dotenv`. It parses with its own strict
  grammar: Node's built-in `.env` parser gives a whitespace-only value the whole
  next line. An exported value that is empty or only whitespace counts as unset.
- The installer (`npm run aos-install`, through `src/secrets/dotenv-append.ts`,
  decision D33) is the only program that writes `.env`: it creates it at 0600
  (exclusively, never through a link) only when it is missing and `.gitignore`
  ignores it, and appends only names no line holds, after a newline when the
  last line lacks one. It never changes, removes or reorders a line, makes no
  backup, refuses whatever the loader refuses before it writes, and reads every
  name it appended back through the loader before it returns. It is given no
  value to write: it generates the tokens itself, and hands pmmcp only their
  digest. Every other program only reads `.env`.
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
outside printable ASCII, or a joined `NAME=value` line. The pmmcp bearer
`AOS_PMMCP_TOKEN` gets the same checks, and one under 8
characters is refused too, because the log's mask will not take a value that
short. A bearer that fails is refused by name before anything is dialled; one
that passes is masked before the first request, in the event log, the process
log, and what `npm run capture:pmmcp` prints.

With no pmmcp and no Docker the kernel boots **degraded** and says exactly what
is missing. That is the designed behaviour, not a failure — see below.

### Where things live

Everything the kernel and the installer write lives in the program folder, under
`.aos/`, which git ignores. The one exception is `~/.colima`, Colima's own home.
pmmcp, which the installer installs when it finds none, is a product of its own
and outside this rule (decision D36, the last row).

| Path | What |
|---|---|
| `.aos/events.db`, `.aos/events.head` | the event log and its anchor |
| `.aos/kernel.lock`, `.aos/kernel.lock-journal` | the running kernel's hold on its data directory (an empty SQLite file, locked while a kernel runs, its lock dropped by the OS when that kernel ends), and the rollback journal SQLite keeps beside it while the hold lasts, holding only SQLite's journal header, and removes when the hold is released (one a killed kernel left stays until the next kernel's hold takes it over and removes it in turn); both 0600, the lock made so before SQLite opens it, so the journal takes its mode: one kernel per event log |
| `.aos/workspaces/{trusted,hostile}` | sandbox mount roots, one per Colima VM |
| `.aos/docker` | `DOCKER_CONFIG` for the kernel's docker calls, `colima-up.sh` and `build-worker-image.sh`, never `~/.docker` |
| `.env` | your credentials (`AOS_CONTROL_TOKEN`, `AOS_PMMCP_TOKEN`, `ANTHROPIC_API_KEY`): written by you, or created at 0600 and appended to by `npm run aos-install`, which generates the two tokens, never writes `ANTHROPIC_API_KEY` and never changes a line; mode 0600, git-ignored; read, never written, by the other npm entry scripts; deleted by `git clean -fdx` like `.aos/` |
| `.aos/install/`, `.aos/install.lock` | the installer's logs: a 0700 folder per run, `<UTC stamp>/`, holding each program's `<step>.out` and `<step>.err` (0600), `installer.out` (what it said, when its own output went away mid-run), `force-quit.log` (0600, a typed force-quit's record), and `active.json` while a step it started in a session of its own runs; its lock, held while it runs and removed at its exit (one left by a killed run is taken over, even after a reboot gave its pid to another process) |
| `.aos/npm-cache` | npm's cache (`.npmrc`); run npm from the repo root, because npm resolves a relative path against the shell's directory |
| `~/.colima` | Colima's VMs and sockets; `colima-up.sh` also sets `COLIMA_CACHE_HOME=~/.colima/_cache`, which would otherwise be `~/Library/Caches/colima` |
| pmmcp (D36) | outside the rule: `~/Github/Persistent-Memory-MCP`, where `npm run aos-install` clones it when there is none, and what its `setup.sh` writes: `~/.persistent-memory-mcp`, `~/.ollama/models`, `~/.gemini/config/plugins/pmmcp-plugin`, `~/Library/LaunchAgents/com.aibot.pmmcp.plist`, uv and Python under `~/.local`, uv's cache `~/.cache/uv` (several GB), a macOS Keychain item (service `persistent-memory-mcp`, user `master_key`), and Docker Desktop's volume `pmmcp-qdrant-data` |

`dataDir` is `./.aos`, relative to the repo root, and is kept `0700`: created
so on first boot, or tightened at boot when npm made `.aos` first for its cache
(at your umask's 0755); `events.db` and its `-wal`/`-shm`, and `kernel.lock`
and its `-journal`, are made `0600`. `AOS_DATA_DIR` overrides it, relative to
your shell's directory. Inside the repo, `config.ts` accepts a data dir or
mount root only under `.aos/`, and only while `.gitignore` ignores `/.aos/`.
Whatever `kernel.yaml` or `AOS_DATA_DIR` names, `<repo>/.aos` itself must be a
real directory spelled exactly so on disk:
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

That export also decides which engine every later `docker` in the shell talks
to. `colima start` makes the VM it started the current context in
`.aos/docker`, so in that shell a bare `docker` reaches a Colima VM, not Docker
Desktop or any other engine you use. Another tool's script run there would not
find its containers, and might create fresh ones inside the VM. Keep the export
to a shell you use for AOS only, or `unset DOCKER_CONFIG` before managing other
containers.

**Uninstall:** run `colima delete trusted` and `colima delete hostile`, then
delete this folder and `~/.colima` if nothing else uses Colima. Global installs
of Node, npm, Docker and Colima are yours to keep or remove.

---

## Commands

| Command | What it does |
|---|---|
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | `node --expose-gc --import tsx --test test/*.test.ts` |
| `npm run dev` | the daemon on 127.0.0.1:7777, reading `./.env` through `--dotenv` |
| `npm run build` | emits `dist/` |
| `npm run cli -- <cmd>` | the console: `agents`, `verify-chain`, `search`, `probe`, `run`, `kill`, `approve`, `deny`, `approvals` |
| `npm run capture:pmmcp` | operator-only: record pmmcp's live tool schemas |
| `npm run eval` | operator-only: score the orchestration suite (**spends money**) |
| `npm run falsify` | the mutation catalog: does the suite catch the bugs it claims to? (slow, offline) |
| `npm run aos-install` | operator-only: find or install pmmcp, append the tokens `.env` lacks, and stage pmmcp's `aos-kernel` digest of `AOS_PMMCP_TOKEN`; `npm run aos-install -- --dry-run` changes nothing (its flags go after `--`), and live pmmcp changes need two typed confirmations (see Setup) |

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

`capture:pmmcp` needs a running pmmcp and `AOS_PMMCP_TOKEN` in its own
environment: `kernel.yaml` declares it, the capture reads no `.env` (whether it
should is decision D37, open), and it refuses a declared name left unset before
dialling. Until D37 is answered, hand it the value for that one command, from
the repository root:

```bash
AOS_PMMCP_TOKEN="$(sed -n 's/^AOS_PMMCP_TOKEN=//p' .env)" npm run capture:pmmcp
```

The value goes into that one command's environment and nowhere else: your
shell's history keeps the line as typed, never the value, and the shell does
not export it. Never `export AOS_PMMCP_TOKEN=...`: zsh saves a value typed that
way to `~/.zsh_history`, and while your shell exports `AOS_PMMCP_TOKEN`,
`npm run aos-install` stops and asks you to unset it, because the kernel
started from that shell would send the export, not the value whose digest pmmcp
is given. The `sed` reads the line as the installer writes it,
`AOS_PMMCP_TOKEN=` and the value; with no such line it gives nothing, and the
capture refuses the name as unset. It calls `tools/list`
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
| `kill <runId> [--reason R]` | yes | abort a run, queued or started: it makes no further model or tool call, and ends `killed`, reason `requested` (or a budget cap's, if one ran out before the stop, or the wallclock's, if it has run out by the time the stop is read); one parked on an approval ends once that approval is answered or expires |
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
| `apple-container-driver` | `src/sandbox/apple-container.ts` | `probe()` reports unavailable with a reason so boot degrades; `run()`, `kill()`, `abandon()` and `sweepOrphans()` throw `NotImplementedError`. macOS 15 has no `container` binary |

**Egress: built, and never yet run live.** The kernel's own egress engine
(`src/egress/`) is the one way a container reaches anything (egress plan W1,
the operator's design of 2026-11-09). It runs in the kernel's process: nothing
listens for it, nothing stands between a worker and the kernel but the run's
own `docker -i` channel and the image's mux, and no credential is in any VM.
A run on the trusted domain whose manifest names egress (`egress.allow`,
`egress.bind`) is issued a grant before its container starts
(`proxy.grant.issued`, naming the run, the agent, the container, its
credential-free hosts and, of each binding, git-fetch alone: an exec grant
never holds `git-push` or `github-pulls`), and every request its container
sends is a `proxy.decision` row of that run before anything is resolved or
dialled. The grant is revoked (`proxy.grant.revoked`, with its totals) when the
container exits, meets its wallclock, breaks the channel's protocol or a
per-grant limit, or the run is stopped; the kernel ends a container only by
killing it by name on its own domain, never by closing its stdin. A container
still running 10 s after its command's exit status arrived (a flow held open
by what the command left behind, a `setsid` child say) is killed by name, and
its grant revoked `requested`, saying so; one whose docker client ended with
no exit status or 125, its own failure, is killed by name and its grant
revoked `error`, the kernel's verdict, never read as the container breaking
the protocol. A grant whose host, repository, binding id, run id or agent id
the event log would store censored is not issued, and the exec is refused
naming the field; so is one naming more repositories across its bindings
than one `proxy.grant.issued` row records (128), which the registry refuses
in a manifest at load. Each refusal is made when the run is offered tools and
again before the gate, so no human is asked to approve an exec that would be
refused, but the run id's, which is judged before the gate only: the offer
is judged without a run, so a run whose id the event log would store
censored is shown the tool, and its exec is denied at the gate, with no
human asked and nothing run. The hostile domain gets no channel and no
grant, whatever its manifest says.

Boot reports egress `ok` or `degraded`, never absent: degraded appends one
`egress.degraded` row per failed check, naming what failed and the key or
command that fixes it (`egress.enabled: false`, which kernel.yaml ships; a
sandbox that cannot run a container; a binding whose value did not resolve,
named with its envVar, never its value). While it is degraded no run is offered
`sandbox.exec` for a manifest with egress, and a call of it is refused with the
egress reason before any human is asked. That reason, which `status` shows and
each refusal quotes, names the failed checks while they fit 2 KiB and counts the
rest, each named in its own row. Each binding's value is resolved once,
at boot, outside any run, through the broker (`secret.accessed` with purpose
`egress credential for <host>`), checked as a bearer, and, for a Basic
binding, its derived value (base64 of `<basicUser>:<value>`) masked before
anything can quote it; a binding whose envVar is a provider's key refuses the
boot. Of `egress.limits`, `maxRequests` counts the flows a container opens, not
only the requests judged (a flow carries at most one request, and one whose
head never completes costs one too). An upstream 401 or 403 (`challenged`), and
an answer whose head the kernel will not write to the worker
(`response-head`), are recorded as upstream `proxy.decision` rows, sent, and
answered 502, so git never prompts.

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

Egress adds a fifth (egress plan W2): a `proxy.grant.issued` with no
`proxy.grant.revoked`, a grant whose kernel died while its container ran (or,
rarely, one whose live revocation the store refused to append, which a boot
cannot tell apart; its detail names both).
Nothing can be served under it any more (the egress engine and the container's
one channel were in the dead process), so boot writes the revocation, reason
`recovered`, under the grant's run and agent (none, for a canary's), before
that run's terminal row, and with no totals: the counts died with the kernel
that kept them, and zeros would claim nothing crossed. Then, before it marks
the sandbox subsystem, boot kills by name, on both VMs, the containers its log
names that a VM still runs (the orphan sweep: `docker ps` for the `aos-run-`
prefix, then `docker kill` on the VM that listed each), whatever the sandbox
probe said, since a dead kernel's wallclock timers died with it. Only those
the log names: a container of every run that called a sandbox tool, started a
container or was issued a grant (a finished run's included, so a container a
live kernel's kill missed is reaped at the next boot), and each open grant's
container. A VM is shared by every kernel on the Mac, and a container with the
prefix that this log does not name may be another data directory's live
kernel's. A log with no sandbox run asks no VM anything. The sandbox's reason
names what the sweep killed. Boot waits 30 s for it at most, then tells it to
stop, so a listing a VM answers late kills nothing. A sweep that did not
finish, that could not list a VM, or whose kill a daemon refused degrades the
sandbox (and so egress), naming each, saying a container a previous kernel
left may still be running, and the boot completes; the next boot sweeps for
the same runs again. The sweep runs beside the sandbox probe, which boot also
waits 30 s for at most (`PROBE_WAIT_MS` in `src/kernel.ts`), so a paused VM
holds the boot one bound and degrades the sandbox rather than holding it for
good; once boot stops waiting, the docker CLI of each probe call and each
sweep listing still held is ended by SIGKILL, while a `docker kill` the sweep
already sent is left to finish on its own. When both fail, the sandbox's
reason names the probe's failure and then the sweep's, each also in a
`sandbox.degraded` row of its own.

All of that assumes the log has no live kernel, so boot first takes
`<dataDir>/kernel.lock` (`src/data-lock.ts`), before it opens the log: SQLite's
own exclusive lock on an empty file, held until shutdown has closed the log,
and dropped by the OS when the process ends however it ends, so no stale lock
is ever left to judge. A second kernel on the same data directory is refused
there, before it writes anything, instead of closing the live kernel's runs as
orphans, revoking their grants and killing their containers, and only then
failing on the control port.

`test/projections.test.ts` boots on such a log twice and checks that the first
boot closes each grant once, a canary's under no run and no agent, and the
second appends nothing; `test/kernel-boot.test.ts` checks the sweep reaches
both VMs before the mark and kills only what the log names, and that a second
kernel on the same data directory is refused; `test/entrypoints.test.ts`
checks the same of a second `npm run dev`.

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
pmmcp fetch URLs itself and so would route around the kernel's egress engine).
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
risk exceeds its tier is refused with the file named. Budgets are checked at
load too — a manifest may only lower a kernel ceiling. So is egress, which the
kernel's egress engine serves to a trusted run (above): an `egress.allow` host
must be a DNS name, kept in one spelling (never an IP literal, a port, a
wildcard or a special-use name like `host.lima.internal`), an `egress.bind` id
must name a binding in kernel.yaml's `egress.bindings`, no allow host may be a
binding's host, and only a tier 2 or higher worker sandboxed in the trusted
domain may hold either; a spawned child keeps a subset of its template's hosts
and bindings, and only at tier 2 or more. No shipped manifest holds egress.
Neither agent declares a `sandbox:` (a worker with one at tier 2 or more that
lists `sandbox.exec` has its commands run in containers since egress plan W1a,
and a shipped manifest that does waits on the Phase 2 exit, as egress does), an
`egress.allow` host (egress has never yet run live), or a `schedule:` (the only
routable model is a frontier one, and an unattended run that can reach it can
empty an envelope).

Both carry `tools.allow: []`, which is the honest state and not an oversight:
`tool-views.yaml` exposes no pmmcp tool to agents, `sandbox.exec` needs the
`sandbox:` block neither declares, and the registry refuses a manifest that
names a tool the views withhold. So today the difference between the two is
enforced in three places and observable in none — each agent's `AGENTS.md` says so
rather than implying a capability that is not wired.

Sandbox tools are checked at load as egress is (egress plan S3). `sandbox.exec`, on
`tool-views.yaml`'s `sandbox` server as `write` with `taints: true`, runs one
command in one container of the caller's own sandbox domain: the pinned image by
id, `--network none`, with a channel to the kernel's egress engine only for a
run on the trusted domain whose manifest has egress, served under a grant
issued before its container starts (above), and none on the hostile domain,
the run's own workspace `<mountRoot>/<runId>` at `/workspace`, and a hard
wallclock of what is left of the run's budget, at most
`sandbox.defaults.wallclockMs` (itself at most 2^31 - 1 ms, a timer's limit).
It logs `sandbox.started` and `sandbox.killed` between `tool.call` and
`tool.result`, and kills the container by name before that end when the docker
client ended with no exit status or with 125 (its own failure, a lost daemon
connection among them), since such a client may leave its container running;
it waits 10 s at most for that kill, so that kill never holds the run. The
driver's own result is awaited for the container's wallclock and 30 s more at
most, and once the run is stopped (`aos kill`, or a shutdown), whose kill by
name goes out then, for 30 s from the stop at most: the docker CLI holds it
until it closes, and the container's wallclock is a kill by name through the
same daemon, so a daemon that accepts and never answers (a paused Colima VM)
would hold the call, and the run, for good. Past that bound the runner gives
the container up: the driver ends the docker
client it spawned (SIGKILL, the one process it signals) and kills the
container by name on its own domain, waited on for 10 s at most, and
`sandbox.killed` records `error`, the result saying the driver never
answered. Its output taints the run, so every exec after the first in a run,
and every other write, waits for a human. An exec
whose arguments the approval preview would cut (500 bytes of their canonical
JSON), would redact (a span shaped like a credential is shown as
`[REDACTED]`, and the PEM pattern hides everything between its markers), or
would show with a character a screen hides or reorders text by (a bidi, format
or C1 control, a line separator, or another default-ignorable code point: a
Hangul filler, a variation selector, so an emoji written with VS16 too), or
whose command the driver's own audit refuses (a `-v`, `--volume`, `--mount` or
`--device` anywhere in it, the docker socket, or an argument that is the
operator's home or a path under it, in either spelling) never
runs, and no human is asked to approve it: the run loop asks the runner's own
check of the arguments before the gate, and the gate denies the call, its
`tool.gate` row giving the runner's refusal as the reason. The same holds
for every exec on a kernel whose `sandbox.imageId` is unset or is no image id,
which can build no container, or whose `sandbox.driver` is `apple-container`,
a stub that runs nothing: no run on it is offered the tool, and the gate
denies a call of it before any human is asked. `aos approvals`
does not show what an approval would run (protocol v1's `ApprovalItem` carries
no preview, and adding one is a protocol version bump for the operator), so
before `aos approve` on an exec, read the command it was shown in its
`approval.requested` row: `npm run cli -- search --type approval.requested
--run <runId> --limit 1`. Each output stream keeps its own share of the
result, counted in the bytes it takes in the log's JSON. Of each stream the
runner reads and redacts at most 74 KiB (the largest share and 16 KiB more):
all of a shorter one, the end of a longer one, and the start of one the driver
capped at 1 MiB, since `redact.ts`'s PEM pattern takes time quadratic in BEGIN
lines with no END (a MiB of them would hold the daemon's event loop some 11 s;
a window of them, some 60 ms). The window bounds that pattern's cost and no
other's: the JWT pattern's is quadratic in a run of `-ey`, some 2 s over one
window, so a window holding a run of letters, digits, `-` and `_` in which it
starts at more than 16 places is withheld before any redaction reads it, the
stream's byte count (what its capture kept, for one the driver capped) said in
its place. A window is never shown on the side its cut is on, as that cut, like
the driver's, is made before redaction and may split a credential: not the 16
KiB there, nor anything past a private key block's marker whose other marker the
cut left out. An end window is read from its cut, or, when a token's match may
hold the character before it, from the first character past it that none may
hold, none of what that skips shown: no token pattern's match runs across where
it is read from, so its redaction matches each token the stream's matches there
and no other, and breaks no marker the stream's keeps, nor keeps one it breaks.
A window whose start a key block may hold, however the stream's redaction pairs
its markers, is shown from where the blocks that may hold it end instead, and
not at all when none ends: all before that may be a block's body. Those blocks
are read as a union, not as one pairing: every BEGIN, one inside another marker
included, held open to the first END after it that no token pattern, run first,
can break (one holding an AWS key id, or one a token runs into), and the blocks
that overlap taken as one. So an end window shows an end of what a redaction of
the whole stream shows, and no more. None of this follows a value the kernel's
own mask holds, which no worker holds, nor, at a start window's cut, a token of
a shape with an unbounded part that crosses it and runs on more than 16 KiB
before it. A window that redaction shrinks is shown less of, never more. A
result that shows a stream by its window, or withholds one, is marked
`truncated`, and `tool.result`'s `bytes` and `sha256` are of what it shows
before a stream is cut to its share, redacted: the windows short of their cut
sides, not the streams. Only a worker with a `sandbox:` block at tier 2 or more
may list it; the registry refuses it in any other manifest, at load and in a
spawned child, and no MCP server may be named `sandbox` or `kernel`. The runner
(`src/runtime/sandbox-tools.ts`) is wired into the daemon (egress plan W1a):
every `sandbox.*` call goes to it, never to the hub, and the run loop offers
`sandbox.exec` only to a run whose agent's manifest, read from the registry,
may hold it and lists it, on a kernel that pins an image id and names a
driver that runs one. Any other run that names it is denied it before the
gate asks anyone, its `tool.gate` row giving the reason, and one whose agent
the registry stops admitting while a human is asked (archived, say) is denied
it once approved, with a `tool.result` saying so. No shipped manifest lists it,
so no shipped agent is offered it.

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
`~/.zsh_history`. `AOS_LIVE_PMMCP_URL` goes inline, as below: inline only; never
export a `PMMCP_` name in a shell that starts pmmcp, whose `load_config` reads that
prefix as its own settings (a checkout up to 53ea308 refuses to start under one it
does not know). pmmcp's bearer, `AOS_PMMCP_TOKEN`, is optional while pmmcp's gate is in
warn mode; the tests send it only when the shell's environment holds it (they
read no `.env` for it). Run one of these, not both.

The model only, which is cheapest:

```bash
AOS_LIVE_TESTS=1 npm test
```

Everything, including pmmcp writes to `aos/agent/aos-live-test`:

```bash
AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_WRITES=1 \
  AOS_LIVE_PMMCP_URL=http://127.0.0.1:8766/mcp npm test
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

In order: every suite (twenty, see `--list`); one suite, or several
space-separated; named mutants, across suites; the catalog, touching nothing.
`--recover` restores what an interrupted run left and runs nothing else;
`--timeout MS` bounds each test run (default 240000).

It exits 0 only when every mutant is **killed**, every suite's comment-only
**control** survives, and every suite's unmutated baseline is green. **Hung** is
not a kill (a hang is a test with no bound), and a mutant that leaves the file
unparseable or stops the test files loading is **invalid**, never a kill.

It edits the working tree, in the files its mutants name: those under `src/`,
six helpers under `test/helpers/`, and `images/worker/mux.mjs`,
`scripts/falsify.ts`, `scripts/falsify/runner.ts`, `scripts/worker-image.ts`,
`test/config-files.test.ts`, `test/egress-address.test.ts`,
`test/egress-frame.test.ts` and `test/hygiene.test.ts`. So:

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
containment (`sandbox`), the egress host normaliser, address classifier,
upstream, binding routes, decide() and the channel frame codec (`egress`), the
`.env` loader and the credential checks around it (`dotenv`, and
`dotenvDefault` for how an entry point picks its file), the `.env` writer
(`dotenvAppend`), the installer's plan and confirmation gate (`installPlan`),
the `.gitignore` reading (`gitignore`), or the runner itself (`runner`) — the
twenty suites — and add a mutant whenever a new test exists to catch a specific
bug. No test may let a mutant reach your real `.env`: `test/entrypoints.test.ts`
runs every entry point from a temporary copy of the checkout holding a trap
`.env`, through `runEntry` / `spawnEntry`, which set that copy as the cwd
themselves (and `hygiene.test.ts` reads every test's syntax tree to hold each
entry-point run to them), in-process loader tests are told their repository is
a trap directory, and the live helper opens `<repo>/.env` only from a live
test's own process. `test/falsify.test.ts` also refuses a catalog that puts an
entry-point or `.env`-path mutant beside the entry-point spawns, as a second
line. The `integrity` and `redaction` suites edit change-controlled files
(chain hashing, the triggers, the redaction pass) and restore them; the
operator approved keeping them in the catalog on that basis.

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

- Result: pass. 2 passed, 1 skipped by design: the exit-criterion test needs `PMMCP_URL` (since renamed `AOS_LIVE_PMMCP_URL`), and line 2 runs it. The rejected-tool-call replay passed against the real Messages API.
- Date: 2026-10-19
- Commit: c80f7be
- `costMicroUsd`: 2770 (llmCalls 1)

**2. The exit criterion, automated.** pmmcp connected and its tools classified,
the key resolved from the environment (`secret.accessed { source: 'env' }`), a
fresh probe, then a run with non-zero cost, in that log order. pmmcp is the
memory and goal store here, not the key store: its `get_secret` masks by design.

The key comes from the same place.

```bash
AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_URL=http://127.0.0.1:8766/mcp node --import tsx --test --test-name-pattern="Phase 0 exit criterion" test/live-anthropic.test.ts
```

`AOS_LIVE_PMMCP_URL` is required (the test skips without it) and is read only by
the test, which writes it into its own temporary `kernel.yaml`. Give it inline, as
here. It was `PMMCP_URL` until the rename that keeps every AOS name out of pmmcp's
`PMMCP_` prefix (decision D34). The test runs the
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
AOS_LIVE_TESTS=1 AOS_LIVE_PMMCP_WRITES=1 AOS_LIVE_PMMCP_URL=http://127.0.0.1:8766/mcp node --import tsx --test test/live-runtime.test.ts
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

Open since 2026-10-29: D37, how `npm run capture:pmmcp` gets pmmcp's bearer,
and D34's amendment of contract K3's token names. A decision that reopens
belongs in that file with a date, not in a commit message.

---

## pmmcp's bearer runs in warn mode

pmmcp has a bearer gate (`src/transport/http_auth.py` in pmmcp;
`~/.persistent-memory-mcp/http_auth.yaml`, which holds digests only and is read
once at server start), and it runs in **warn** mode: a request with a missing or
unknown token is logged and still served. So loopback trust still decides
access, and anything on the Mac can call any of pmmcp's tools, including the
vault and `admin`, until the operator switches the gate to enforce, before
Phase 4 makes Telegram and SMS inputs. The installer does not switch it.

The kernel sends `AOS_PMMCP_TOKEN` as pmmcp's client `aos-kernel`
(`mcp.servers.pmmcp.tokenEnv` in `kernel.yaml`), and refuses to dial while it is
unset. In warn mode nothing on the kernel side shows a wrong token, so
`npm run aos-install` checks the digest offline (`http_auth check --expect`).
No AOS credential name starts with `PMMCP_` (decision D34), and `kernel.yaml`
refuses one as a `tokenEnv`: that prefix is pmmcp's own. pmmcp's `load_config`
reads an exported `PMMCP_<SECTION>__<KEY>` as a setting, in any case
(`pmmcp_server__port` sets the port), and refuses to start under a bare section
name such as `PMMCP_SERVER` or a section that does not exist
(`PMMCP_DASHBORD__PORT`); a pmmcp checkout up to 53ea308 refuses to start under
any `PMMCP_` name that is no setting (pydantic `extra_forbidden`, checked
2026-10-28). So a `PMMCP_*` value goes inline on one command, never `export`.

Until then, access rests on the two conditions the operator set, which the
kernel enforces or will enforce:

- **Containers stay off it.** Inside a Colima VM the Mac's loopback is
  `192.168.5.2` (`host.lima.internal`). Every container runs with
  `--network none` (the operator, 2026-11-09): a loopback of its own and no
  route at all, so no container has a route there. Each domain's internal
  network stays, and the sandbox probe still refuses a domain whose docker
  network is not `--internal`, as defence in depth: no run is put on it.
- **The kernel's egress engine denies it** (`src/egress`, wired since egress
  plan W1, never yet run live): a worker's one way out is that engine, over
  its run's `docker -i` channel, and it refuses `192.168.5.2`,
  `host.lima.internal` and `host.docker.internal`.

pmmcp's other keys (Qdrant's `service.api_key`, the dashboard token, the curator
secret) live in 0600 files under `~/.persistent-memory-mcp`, made by pmmcp's own
CLIs. The kernel never calls 8765, 8767 or 6333, holds none of them, and none
goes in `<repo>/.env`.

Nothing on the client side blocks enforce. The operator's IDE, Antigravity,
sends a configured `headers` Authorization over Streamable HTTP: a probe on
2026-10-25 pointed it at a listener with `Bearer aos-header-probe`, and the
header arrived on its first request.

## Sandbox checks on the Mac (2026-10-21)

The operator ran these against both Colima VMs: Colima 0.10.3 from Homebrew,
`vz` with virtiofs, Docker Engine 29.5.2, and 4 CPUs, 4 GiB and 60 GiB each, all
from one uninterrupted `scripts/colima-up.sh` run. The container was `alpine:3.20`
started with the driver's own `docker run` flags (`buildRunArgs` in
`src/sandbox/docker.ts`, limits from `config/kernel.yaml`): uid 65534, on the
domain's internal network (every run's network until 2026-11-09; since then every
run is `--network none`), with the domain's `mountRoot` at `/workspace`. Both VMs
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
| Docker firewall backend (2026-10-25) | `iptables`, so rules in `DOCKER-USER` apply to container traffic |
| VM network (2026-10-25) | both VMs attach to one shared `limactl usernet` process (Lima 2.2.1) on `192.168.5.0/24`; each VM resolves through its own dnsmasq at its `eth0` address, which forwards to `192.168.5.2`; the hostile VM opens a TCP connection to the trusted VM's sshd |
| Gateway NAT (2026-10-25) | a VM's connection to `192.168.5.2:8766` arrives at pmmcp from `127.0.0.1`, opened by that `limactl` process (`lsof` on the Mac), the same as a local client |

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
  is `192.168.5.2`, and `192.168.5.2:8766` accepts a connection. Until 2026-11-09
  the internal network was the only thing between a container and pmmcp; since
  then every run is `--network none`, and a worker's one way out is the kernel's
  egress engine, over its run's `docker -i` channel. Anything with a route out of
  a VM reaches pmmcp unauthenticated: the default bridge, a network that is not
  internal, or an escape into the VM. The egress engine runs on the Mac itself,
  so its refusal of the Mac's loopback is what keeps a worker's flows off pmmcp.
- **The gateway is the Mac's whole loopback, and the VMs share a network.**
  Lima's user-v2 network rewrites `192.168.5.2` to `127.0.0.1` on every port
  (`pkg/networks/usernet/gvproxy.go` at Lima v2.2.1). Every service listening on
  the Mac's loopback or on all interfaces is therefore reachable from both VMs,
  and a service cannot tell a VM's connection from a local one by its address.
  Only a credential distinguishes them. The two VMs are separate kernels on one
  switch, so the hostile VM can reach the trusted one. Neither Lima 2.2.1 nor
  Colima 0.10.3 has a setting that turns the gateway rewrite off.

## Installer checks on the Mac (2026-11-05)

The operator ran `npm run aos-install` twice from a fresh clone on the Mac (macOS
15.6.1, arm64, Node v26.9.0), the first time at `3c6b430` and the second at
`b91482c`. Both ran against a configured pmmcp at `e646096`, with local changes to
five tracked files. That pmmcp was loaded by launchd, its bearer gate in warn mode,
and its Qdrant key enforced. `.env` already held `AOS_CONTROL_TOKEN`,
`AOS_PMMCP_TOKEN` and `ANTHROPIC_API_KEY`. Both runs ended `aos-install: exit 0:
done`.

| Check | Result |
|---|---|
| Preflight | every program found on the PATH a child gets, and an exported `DOCKER_CONFIG` named and withheld from pmmcp's commands. At `b91482c` the bash line reads `pmmcp's scripts  /bin/bash (their #!/usr/bin/env bash), version not readable from the file (it is read, never run); your login shell (zsh) is not used`: Apple's bash 3.2 composes its version string when it runs, so its bytes hold none |
| `.env` | 0600, one link, the operator's, and not written by either run (every name was present). It has no ACL: `ls -le` lists none, and its `@` is an extended attribute, which the loader does not read |
| Discovery | pmmcp was found from its launchd plist, the `aos-kernel` digest matched `.env`, and the jobs were counted with `stop-pmmcp-server.sh --jobs` |
| Run 1 (`3c6b430`): the dashboard token | the graceful stop exited 0 after 9 s. `auth init --only dashboard` made `dashboard_token` (0600), and the start exited 0 after 24 s. The start's checks passed: `/health` 200, a new MCP server started after `http_auth.yaml` last changed, Qdrant, the worker and the scraper running, and the dashboard refusing a request without its token (401). The curator secret was skipped, as designed, because a `monitor_tui.py` was running |
| Run 2 (`b91482c`): the curator secret | the TUI was quit first. The stop waited for one running `curator_health` job and exited 0 after 154 s. `auth init --only curator` made `curator_secret` (0600), and the start exited 0 after 20 s. The same checks passed, and the curator refused a request without a proof (401) |
| Bearer | in both runs the running server had loaded the `aos-kernel` digest. After `npm run dev`, pmmcp's `server.log` holds `http auth: first request with token` for `aos-kernel`, mode `warn` |
| Event log | `npm run cli -- verify-chain`: `ok`, 117 events |

No drain hung, so the typed force-quit was not exercised. Both runs left the
`pmmcp-qdrant-prekey` the cutover kept, by the operator's choice. The operator
removed it afterwards, with pmmcp running. First, `qdrant_api_key.py status`
gave the verdict "Qdrant enforces the key, and the key file holds it" (401 without
the key, 200 with it, published on `127.0.0.1:6333` only), and pmmcp's logs held no
refused Qdrant request. Then `qdrant_api_key.py cleanup` reported "removed
pmmcp-qdrant-prekey; its volumes are untouched". A second `status` showed
`pmmcp-qdrant-prekey: none` with the same verdict, and `docker volume ls` still
listed `pmmcp-qdrant-data`. The cutover can no longer be rolled back, and Qdrant's
snapshots under `~/.persistent-memory-mcp/backups` are its safety net. Warn mode
stays as it was (switching to enforce is the operator's later step). Findings to
carry forward:

- At run 2's discovery, the MCP server run 1 had started did not answer
  `/health`. Run 2's restart cleared it, and the cause is not known.
- The installer's warning still says the stop signals a port's listener
  without checking its command line. pmmcp's stop script stopped doing that at
  `0a452c6`, so the warning overstates what the stop can reach.
- The AOS provider `ollama/qwen3:8b` points at 11434, one of pmmcp's four Ollama
  instances, which every pmmcp stop stops. Both end reports say to move it to a
  port of its own.

## Still needs validation

Facts this repository cannot check from Linux, and how each gets settled. The
first three of the plan's list are already resolved (Node v26.9.0; pmmcp at
`http://127.0.0.1:8766/mcp`, loopback; since 2026-10-28 a bearer gate in warn mode,
and kernel.yaml declares `AOS_PMMCP_TOKEN`; `get_secret` takes `label`,
not `key`). The Colima sandbox rows were settled on 2026-10-21; see "Sandbox
checks on the Mac" above.

| Fact | How it gets settled |
|---|---|
| `node:sqlite` on darwin-arm64: `DatabaseSync` `timeout` runtime behaviour, `errcode 1811` stability, `t.mock.timers` | `npm test` on the Mac; `test/env.test.ts` fails first, with a named reason |
| pmmcp: Streamable HTTP interop with SDK 1.32.1 (same-origin redirects only, from 1.32.0), idle timeout vs the 240 s heartbeat (the 64 tool names, their input schemas and their output schemas, every one FastMCP's `{result: string}`, are captured in `test/fixtures/pmmcp-listtools.json`, re-taken 2026-10-19) | boot with pmmcp up: `hub.connected` and `hub.tools.classified` list what is really there; checklist line 2 |
| An Anthropic API key accepted as `Authorization: Bearer` (D20's alternative) | one `npm run cli -- probe anthropic/claude-sonnet-5` with `auth.header: Authorization` |
| Whether SIGKILL of the docker client leaves its container running, which is why the driver kills by name | Phase 2 live Docker driver tests |
| What `docker run -i` gives a channel run through Colima's forwarded socket (a spec's `channel`, on the trusted domain only: `buildRunArgs` and `DockerDriver.run` in `src/sandbox/docker.ts`, which add `-i` beside `--init`, never `-t`, and hand the CLI's own stdin and stdout to the caller unread): the bytes carried both ways as they are, the CLI's stdin ending as the container's end of file, and the CLI exiting once its container has, its stdin still open; and what the CLI does when the reader of its stdout goes away (the kernel destroys the channel's input): its next copy of container output is expected to fail with EPIPE rather than kill it by SIGPIPE, as it catches every signal to relay it, and it is expected to exit while its `--rm` container runs on unattached, past its wallclock, which the CLI's exit clears. Check whether the container outlives the CLI, and for how long. Whatever it shows, a caller ends a channel run with `kill(name)`, never by destroying its input (`SandboxChannel` in `src/sandbox/driver.ts`), and the deadline is to stay armed until a kill by name succeeds (the wallclock note in `DockerDriver.run`: open, and owned by no plan task yet; until it is, only the next boot's orphan sweep, plan W2, reaps a container such a kill missed) | Phase 2 live Docker driver tests (egress plan L1), on each VM |
| That docker 29.5.2 runs `docker run --pull=never sha256:<64 hex>` from the image of that id on the VM, under whichever image store the VM uses, and fails with no such image rather than pulling when the VM lacks it; and that `docker save` on the trusted VM and `docker load` on the hostile one keep the id the same, so one `sandbox.imageId` names the image on both; and that `docker image inspect --format {{.Id}} sha256:<64 hex>` prints that same id on a VM that holds the image and fails on one that lacks it, which the probe asks of each VM (`buildRunArgs`, `assertTheImage` and `#imageMissingOn` in `src/sandbox/docker.ts`; kernel.yaml ships no id, so the sandbox is degraded until the image is built, pinned and held by both VMs) | Phase 2 live Docker driver tests (egress plan L1), on each VM, once `scripts/build-worker-image.sh` (plan I1) has built the image |
| `scripts/build-worker-image.sh` and `images/worker/Dockerfile`, each marked NEEDS VALIDATION on its line 2: that the docker CLI, given only `DOCKER_CONFIG`, `DOCKER_HOST` and `PATH` as the kernel's own calls are, builds through the trusted VM's daemon with whichever builder it finds (the Dockerfile keeps to the classic builder's syntax: no syntax directive, heredoc or `--chmod`); that the base, `node:24-bookworm-slim` by the digest of its index, gives the VMs its arm64 image; that `ENTRYPOINT []` leaves the image with no entrypoint, which the script checks as `{{json .Config.Entrypoint}}` printing `null` or `[]`; and that bookworm's git (2.39), matching `safe.directory = /workspace` exactly, admits a repository cloned into `/workspace` itself and refuses one in a directory under it, which virtiofs shows as the operator's `501:20`; and what the image's `NODE_USE_ENV_PROXY=1` does on its Node (24.22.2): on Node 22.22 every node process started with it, the mux included, every `node --test` child and any Node command an agent runs, prints `[UNDICI-EHPA] Warning: EnvHttpProxyAgent is experimental` to stderr, so check whether 24.22.2 still does; and, with `NO_PROXY` empty, a request to a server the run itself listens on at `127.0.0.1` goes to the mux like any other (seen on Node 22.22, on loopback), which the kernel denies, so the Phase 2 exit's fixture repository (egress plan L2) keeps its tests off loopback HTTP; and, before the first build, what `ls -l ~/.colima/docker.sock` shows: nothing there, or a link to `~/.colima/default/docker.sock`, is expected. The build's plan refuses a `dockerHost` that is the same file as that name (`defaultSockets` in `scripts/worker-image.ts`), on the understanding, not checked against Colima 0.10.3, that Colima keeps it for the default profile alone; if it links to the trusted or hostile VM's socket instead, the plan refuses the shipped kernel.yaml as the default profile's, and that check needs changing before the image can be built | the operator runs the script once on the Mac and pins the id it prints as `sandbox.imageId`; then the Phase 2 live Docker driver tests (egress plan L1) |
| The docker CLI's exit code once its container is killed by name from another client (`docker kill --signal=KILL aos-run-<id>`), with the driver's `--init` and `--rm`: 137 is expected, and the driver credits a kill (`killedBy`, SIGKILL) only on a 137 (`finish()` in `DockerDriver.run`). Any other code would make every kernel kill read as a run that ended on its own, leaving only `overran` to show a wallclock breach | Phase 2 live Docker driver tests, on each VM |
| `docker ps --filter name=aos-run- --format {{.Names}}` prints one container name per line, which the orphan sweep reads (`#sweepOn` in `src/sandbox/docker.ts`; with `--quiet` the CLI would ignore the format and print IDs, which the sweep would drop) | Phase 2 live Docker driver tests, on each VM, with a container of that prefix running |
| How docker 29 reads the namespace and network modes the run-args audit refuses, all case-sensitively: `--pid HOST` and `--network HOST` no mode (a plain `HOST` names a network called HOST), `--uts`, `--cgroupns` and `--userns container:<id>` refused as no mode they have, and only the key=value `--network name=HOST` lower-cased to host (`sharesNamespace` and `networkMode` in `src/sandbox/docker.ts`; the builder emits none of them, and the audit refuses each whatever docker makes of it) | Phase 2 live Docker driver tests, on each VM |
| How docker 29's CLI and daemon read the `--security-opt` spellings the run-args audit names by what they widen (`auditRunArgs` in `src/sandbox/docker.ts`; the builder emits none of them): `seccomp=UNCONFINED` and `seccomp=BUILTIN` each read as a profile file of that name on the Mac, `seccomp=builtin` putting docker's built-in profile in place of one set by the daemon's `seccomp-profile`, `no-new-privileges` and `writable-cgroups` values read with Go's `strconv.ParseBool`, and a key in another case (`SECCOMP=unconfined`) refused | Phase 2 live Docker driver tests, on each VM and on a daemon configured with a `seccomp-profile` of its own |
| `scripts/colima-up.sh` on a VM that is running but whose first start never finished: `colima status` fails, `colima start` answers `already running, ignoring`, and the script still prints `Done.` without its mounts or sizes applied (seen on 2026-10-21; still marked NEEDS VALIDATION on line 2) | Phase 2: the script fails unless `colima status` succeeds after the start and the VM's virtiofs mounts are exactly its `mountRoot` |
| Moonshot base URL, model ids and pricing; OpenRouter `usage.cost` semantics; llama.cpp `include_usage`, named `tool_choice`, `--jinja`, and the `/props.chat_template_caps.supports_tool_calls` key name | `npm run cli -- probe <ref>` per entry, and `GET /v1/models` once keys are in the vault |
| `@tauri-apps/plugin-websocket` custom-header support — a Phase 3 blocker for invariant 1 | a Phase 3 spike, before any protocol change |
