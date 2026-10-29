// The installer's process runner: the one place npm run aos-install starts a
// program.
//
// CONTRACT
//
//   Who calls it: the installer's probes and steps (scripts/install.ts and
//   scripts/install/*). In scripts/, node:child_process is imported only here
//   and by the mutation runner (hygiene.test.ts), so every program the
//   installer runs goes through the rules below.
//
//   What a child gets:
//     - An environment built from an allowlist, never the installer's own:
//       HOME, USER, LOGNAME, TMPDIR, LANG, LC_ALL, TERM and SHELL as the
//       installer has them, PATH fixed to ~/.local/bin, Homebrew's and the
//       system's directories, then ~/.docker/bin and ~/.cargo/bin (Docker
//       Desktop's per-user CLI and the older uv installer, found only when
//       nothing before them has the program), and SSH_AUTH_SOCK for git
//       alone. So no DOCKER_* (a DOCKER_CONFIG export points docker at a
//       Colima VM, which holds no pmmcp-qdrant), no PMMCP_* (pmmcp's
//       load_config reads PMMCP_<SECTION>__<KEY> as a setting and
//       PMMCP_CONFIG_PATH as its config's path, and a checkout up to 53ea308
//       refuses to start under any PMMCP_ name that is no setting,
//       PMMCP_CONFIG_PATH included), no AOS_* and no credential name ever
//       reaches a child.
//     - stdin from /dev/null, or one `sha256:<64 lowercase hex>` line: a
//       digest is the only thing the installer ever hands a child.
//     - stdout and stderr in two files, <step>.out and <step>.err, created
//       0600 with O_EXCL under <repo>/.aos/install/<UTC stamp>/ (0700; the
//       logs are written only while .gitignore ignores /.aos/ and .aos is
//       spelled .aos on disk, and never through a link). Never one merged
//       capture: the stop script writes its --jobs warnings to stderr before
//       stdout's first line, so a merge would put a warning where the count
//       belongs. Never a pipe: if the installer died, a child writing to a
//       pipe nobody reads would end on SIGPIPE, and a stop script ended
//       mid-stop leaves pmmcp half stopped.
//     - Exactly cwd, env, stdio and detached from Node's spawn: no timeout,
//       no kill signal, no shell (spawnWith, the one way Node's spawn is
//       reached here).
//
//   What a dry run writes through this module, as a real run does: .aos and
//   .aos/install when missing (0700), the run's folder with each probe's
//   .out and .err (0600), and active.json while discovery's `--jobs` runs
//   (removed at its exit). The only other files the installer writes in a
//   dry run are the entry point's .aos/install.lock while it runs (lock.ts)
//   and <run folder>/installer.out, only when the installer's stdout or
//   stderr went away during the run (EPIPE, EIO: Output.keep, at its end);
//   npm, which starts it, keeps its own cache in .aos/npm-cache (.npmrc).
//
//   What runs: an allowlist of what the installer runs and nothing more (no
//   program is on it for its tests' sake: a test's real child is a stand-in
//   .venv/bin/python run in one of the forms below). Every name a command
//   runs as is held to it, in any case (APFS runs PS as ps): the name typed,
//   and the name of the file a link resolves it to (a bare name looked up on
//   the child's PATH first), links resolved as the kernel resolves them
//   (realpath(3): a `..` after a link leaves the folder the link leads to).
//   A name that resolves to another is run only when that one is on the
//   allowlist too, and each name's rule holds (~/.local/bin/ls linked to
//   tar, or pgrep to flock, is refused: neither is a program the installer
//   runs). The programs: ps, pgrep, lsof and ls, which only read; plutil as
//   `-extract <key> <format> -o - <file>` (any other form writes the plist);
//   launchctl `print` or `list`; docker `ps`, `info` or `context show`, with
//   no option before them; git with `--no-optional-locks` at most before the
//   command, and only status, rev-parse, merge-base, diff (with --quiet,
//   --exit-code, --name-only, --no-ext-diff, --no-textconv and --; never
//   --output or --ext-diff), `merge --ff-only <commit>`, `reset --keep
//   <commit>` and `clone https://... <absolute folder>` (no option: never -u,
//   --upload-pack, -c or --template); a checkout's .venv/bin/python by
//   absolute path, after -B at most, in exactly the forms the installer runs
//   (PYTHON_FORMS): `scripts/pmmcp_facts.py --json`;
//   `scripts/qdrant_api_key.py` with `status --json`, `cleanup`, `init`,
//   `enable` or `enable --dry-run`; `scripts/rotate_http_auth_token.py NAME
//   --create --digest-stdin` and `-m src.transport.http_auth check --expect
//   NAME`, each with a digest on stdin (and only they); `-m
//   src.transport.http_auth check`; `-m src.dashboard.auth` with `init`,
//   `init --only dashboard`, `init --only curator` or `status --json`. So
//   none of pmmcp's own CLIs that restart, stop, mint, restore or roll back
//   runs here (rotate's --restart, which runs launchctl kickstart -k;
//   supervisor.py; http_auth new-token, which prints a token the leak scan
//   cannot know; restore_pmmcp_backup.py; qdrant_api_key.py rollback). Then
//   setup.sh by absolute path with --non-interactive alone, and the stop and
//   start scripts (below). Anything else is refused: a shell by any name, env,
//   and a renamed copy of a shell or an interpreter (mysh -c, perl -e,
//   osascript -e, awk, python -c, python -m timeit) included. A copy of a
//   program given an allowlisted name (bash copied to ~/.local/bin/ps) is
//   not told from that program and runs by its rules, as does a hard link of
//   the stop or start given one outside every folder the scripts are looked
//   for in (below); and a script file's own body (the python stand-in's,
//   setup.sh's, the stop's) is beyond these rules' sight: they hold what the
//   installer's code asks to run, by name and arguments.
//
//   What it refuses, before anything is created or spawned:
//     - a spec with any field but step, command, args, cwd, digest,
//       timeoutMs and ownSession (a killSignal or a timeout under another
//       name included), or a step not named [a-z0-9][a-z0-9._-]*, at most 48
//       characters, so no step's files are written outside the run's folder;
//     - a command, cwd, argument, environment value or stdin that holds a
//       NUL, a value registered with SecretMask or a credential shape
//       redactString knows; stdin that is not one digest; a relative cwd, or
//       a command that is neither absolute nor a bare program name; a
//       command or cwd with a `.` or `..` component (after a link, `..` is
//       not the folder its spelling names, so the rules would look at
//       another file than the kernel runs; the installer joins every path it
//       hands over, which leaves none);
//     - by any name the program runs as (above), so an allowlisted name that
//       is a link to one of these is refused too: kill, pkill, killall,
//       timeout and gtimeout, which signal what they name or run (CLAUDE.md:
//       never a signal or a timeout sent to the stop or start script);
//       launchctl but `print` or `list` (never kickstart, with -k or
//       without, nor kill, stop, bootout or any other change to a service);
//       a shell (sh, bash, zsh, dash, ksh, mksh, ash, csh, tcsh, fish),
//       whatever it is given (a -c command string, a script file such as
//       uninstall-pmmcp-service.sh, which runs launchctl bootout and kill, or
//       commands read from stdin); env given any argument, and nohup, xargs,
//       nice, sudo, doas, su, setsid, caffeinate, arch, stdbuf, time, exec,
//       command, chroot, script and watch, and find with -exec, -execdir, -ok
//       or -okdir, each of which runs a program its arguments name, out of
//       these rules' sight; perl, ruby, node, nodejs, deno, bun, osascript,
//       awk, gawk, mawk, nawk, tclsh, wish, expect, php, lua and swift, which
//       run program text their arguments carry; python but as the allowlist
//       has it;
//     - anything not on the allowlist, by the name typed or the name it
//       resolves to, or given what its entry does not allow (above);
//     - once a child's output held a registered value, every further run
//       (below).
//
//   The stop and start scripts (stop-pmmcp-server.sh, start-pmmcp-server.sh)
//   are recognised by name in any case (APFS runs Stop-PMMCP-Server.sh as the
//   same file), by the name a symbolic link resolves to, and by identity: a
//   file with the same dev:ino as either script (a hard link of any name),
//   or, for the command, the same bytes (a renamed copy), where "either
//   script" is the stop-pmmcp-server.sh or start-pmmcp-server.sh in the
//   command's folder (as typed and as resolved), the working directory, the
//   folder of each argument that is a file (as typed and as resolved),
//   ~/Github/Persistent-Memory-MCP, and every install this runner has run
//   one of them from (the folder of the command, as typed and as resolved,
//   and of the script a link or copy of another name was found to be), each
//   file under every name it is found by. A command taken for both (named or
//   linked as one and the other by identity, as a hard link of the start
//   named stop-pmmcp-server.sh is, in whichever folder it is found first, or
//   a copy of both) is refused. A changed copy, or a link or copy outside
//   all of those folders, is not recognised: as the command it is then
//   refused as no program the installer runs unless it has an allowlisted
//   name (a hard link of the stop named ps, in a folder not yet learned,
//   runs as ps does, with what ps may be given: --force, or a timeout), and
//   as an argument it is a file like any other. Recognised, they run only as
//   the command itself, by absolute path; any other run whose command or
//   arguments name either (as text in any case, through a link, or by
//   dev:ino, an argument taken as the file it names from the working
//   directory, links resolved as the kernel resolves them) is refused. That
//   includes read-only commands that only mention one (`git show
//   HEAD:stop-pmmcp-server.sh`, `pgrep -f start-pmmcp-server.sh`): A4 and A6
//   learn what they need from the facts' feature flags, whole-tree git
//   commands and the pid active.json records. Their arguments come from an
//   allowlist: the stop gets none, `--jobs` alone, or `--quiet` and
//   `--wait-timeout N` with N at least 300 (the script's own default), so
//   never --force or -f (CLAUDE.md) nor a wait that ends at once; the start
//   gets none or `--check` (never --force, nor --tail or --only: a start that
//   follows its logs never exits, and nothing here would end it). They are
//   given no timeout and no stdin.
//
//   A step in its own session: the stop and start scripts always, and any
//   other step the caller marks ownSession (a step inside the stopped window,
//   L2 to L4, which a Ctrl-C at the installer's terminal must not interrupt
//   mid-change). It runs detached, in a session and process group of its own,
//   so a Ctrl-C or a hangup at the installer's terminal never reaches it; with
//   no timeout, and never signalled by this module, whatever happens. A stop
//   killed part way leaves services half stopped and the drain lock behind.
//   While one runs, <repo>/.aos/install/active.json records {step, pid,
//   started, out, err}; it is created with O_EXCL before the spawn and
//   removed when the child exits, so a re-run after the installer died finds
//   the window still open. A second one is refused while the record exists:
//   only the caller, having seen the recorded child gone, clears it
//   (clearActive). A record that cannot be removed after the exit is reported
//   in the result (activeError), never thrown from the exit.
//
//   active.json's record is held to a schema before any of it is read or
//   shown: a step name, a whole pid, an ISO time, and absolute .out and .err
//   paths with no control character or credential shape; anything else reads
//   as unreadable, which keeps a re-run waiting.
//
//   What it reads and shows: machine output from the .out file only
//   (readOut, readJobs); the .err file is shown, never parsed (one caller's
//   exception, stated in its contract: A6 reads an `invalid:` line from
//   `http_auth check`'s stderr, where pmmcp's interface puts its refusal and
//   prints nothing on stdout; nothing here parses it). Either is shown
//   through tail(), which strips terminal control sequences, the bidi
//   controls and the line and paragraph separators, and then applies
//   redactString. Every file read here (active.json, a log for the scan,
//   tail or readOut, a log being emptied) is opened non-blocking, never
//   through a link, and used only when fstat says it is a regular file of
//   this account: a FIFO left where a log was would otherwise block the
//   installer for ever, in the exit-time scan beyond the reach of a signal.
//   One that is not is unreadable to readActive, a hit to the scan, an error
//   to tail and readOut, and one discard or the scan reports it could not
//   empty. A caller that has read a probe whose output may hold another
//   process's command line or environment (ps, launchctl print) has the
//   runner empty that step's two files (discard): the leak scan knows only
//   the values registered with SecretMask, never someone else's.
//
//   After a child exits, both files are scanned for every value registered
//   with SecretMask. A hit empties that file, fails the step with a defect
//   that names the file and never the value, and halts the runner: nothing
//   more is run, a read-only probe or the start script included, so the
//   installer stops before its next live step (A6's end report then names the
//   manual start and the checks it could not make). While any value is
//   registered, a file that cannot be scanned counts as a hit.
//
//   A read-only probe may be given timeoutMs, after which it is sent SIGKILL
//   and reported timedOut; one the kill does not end (a process in
//   uninterruptible sleep) is reported unreaped (exited false) after a grace
//   period. Only a probe: a step that writes (rotate, qdrant, auth init, git)
//   must be left to finish or fail on its own, and a step in its own session
//   refuses a timeout outright.

import { spawn as nodeSpawn, type SpawnOptions } from 'node:child_process'
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { basename, dirname, isAbsolute, join } from 'node:path'
import type { Writable } from 'node:stream'
import { z } from 'zod'

import { assertAosEntry, gitignoresAos } from '../../src/config.js'
import { ConfigError, KernelError } from '../../src/errors.js'
import { SecretMask, redactString } from '../../src/events/redact.js'

/** The names a child is given from the installer's environment, when set and not empty. */
export const PASSED_NAMES: readonly string[] = ['HOME', 'USER', 'LOGNAME', 'TMPDIR', 'LANG', 'LC_ALL', 'TERM', 'SHELL']

/** Given to git alone: a clone over SSH needs the operator's agent, and nothing else does. */
export const GIT_ONLY_NAMES: readonly string[] = ['SSH_AUTH_SOCK']

/** After ~/.local/bin (uv): Homebrew on Apple silicon, then on Intel, then the system's. */
const SYSTEM_PATH: readonly string[] = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']

/**
 * Last, so they only supply what nothing earlier has: Docker Desktop's
 * per-user CLI (docker, docker-credential-desktop) and the older uv
 * installer's directory. Unverified on the operator's Mac (plan §7).
 */
const HOME_FALLBACK_PATH: readonly (readonly string[])[] = [
  ['.docker', 'bin'],
  ['.cargo', 'bin'],
]

/** The child's PATH, whatever the installer's own holds. */
export function childPath(home: string): string {
  return [join(home, '.local', 'bin'), ...SYSTEM_PATH, ...HOME_FALLBACK_PATH.map((p) => join(home, ...p))].join(':')
}

/** The one thing stdin may carry: pmmcp's digest_of form. */
export const DIGEST_LINE = /^sha256:[0-9a-f]{64}$/

/** The scripts that stop and start pmmcp, by file name. */
export const STOP_SCRIPT = 'stop-pmmcp-server.sh'
export const START_SCRIPT = 'start-pmmcp-server.sh'
const SERVICE_SCRIPTS: readonly string[] = [STOP_SCRIPT, START_SCRIPT]

/** Where an install's scripts are compared from even before the runner has run one: discovery's default folder, ~/Github/Persistent-Memory-MCP. */
const DEFAULT_INSTALL: readonly string[] = ['Github', 'Persistent-Memory-MCP']

/** The largest file compared byte for byte with the stop and start scripts (each is a few tens of KiB). */
const MAX_SCRIPT_BYTES = 1024 * 1024

/** The shortest job wait the stop may be given: its own default. A shorter one ends the wait early, as --force does. */
export const MIN_WAIT_TIMEOUT_S = 300

/** A step's name: its files are <step>.out and <step>.err. */
const STEP_NAME = /^[a-z0-9][a-z0-9._-]{0,47}$/

/** A step's name as active.json records it: the name given, with the -2, -3, ... a repeated one gets. */
const RECORDED_STEP = /^[a-z0-9][a-z0-9._-]{0,47}(?:-[1-9][0-9]{0,8})?$/

/** The fields a spec may carry: a killSignal, a shell or a timeout under any other name is refused, never ignored. */
const SPEC_FIELDS: readonly string[] = ['step', 'command', 'args', 'cwd', 'digest', 'timeoutMs', 'ownSession']

/** Programs that signal what they name (a pid, a process name) or what they run at a deadline. */
const SIGNAL_SENDERS: readonly string[] = ['kill', 'pkill', 'killall', 'timeout', 'gtimeout']

/** Shells: none runs here, by any name, whatever it is given (the installer runs none). */
const SHELLS: readonly string[] = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'csh', 'tcsh', 'fish']

/** Programs that run another program their arguments name, which these rules would then never see. env is one given any argument. */
const LAUNCHERS: readonly string[] = ['nohup', 'xargs', 'nice', 'sudo', 'doas', 'su', 'setsid', 'caffeinate', 'arch', 'stdbuf', 'time', 'exec', 'command', 'chroot', 'script', 'watch']

/**
 * Programs that run program text their arguments carry (perl -e, ruby -e,
 * node -e, osascript -e, awk 'BEGIN{system(...)}', a tclsh or expect script
 * on stdin): none runs here, by any name. Python is held to its own rule
 * (pythonRefusal).
 */
const INTERPRETERS: readonly string[] = ['perl', 'ruby', 'node', 'nodejs', 'deno', 'bun', 'osascript', 'awk', 'gawk', 'mawk', 'nawk', 'tclsh', 'wish', 'expect', 'php', 'lua', 'swift']

/** Python by any name it runs as: python, python3, python3.12 (a venv's python is a link to one of those). */
const PYTHON = /^python[0-9]*(?:\.[0-9]+)*$/

/** launchctl's subcommands that only read: every other one changes a service (kickstart, kill, stop, bootout, ...). */
const LAUNCHCTL_READS: readonly string[] = ['print', 'list']

/** find's actions that run a program. */
const FIND_RUNS = /^-(?:exec|execdir|ok|okdir)$/i

/** The git commands that only read; merge, reset and clone are held to the one form each the installer runs (gitRefusal). */
const GIT_READS: readonly string[] = ['status', 'diff', 'rev-parse', 'merge-base']

/** The options git diff is given here: none writes a file (--output) or runs a program (--ext-diff). */
const GIT_DIFF_OPTIONS: readonly string[] = ['--quiet', '--exit-code', '--name-only', '--no-ext-diff', '--no-textconv']

/** docker's commands that only read (pmmcp-qdrant's state and the engine's): never kill, stop, restart, rm or compose. */
const DOCKER_READS: readonly string[] = ['ps', 'info']

/** A client name as pmmcp's http_auth takes one (its _NAME): the rotate's and check --expect's NAME. */
const CLIENT_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/

/** One way the venv's python is run here: its arguments after -B at most, and whether stdin carries a digest (only the two that read one). */
interface PythonForm {
  readonly args: readonly (string | RegExp)[]
  readonly digest: boolean
}

/**
 * The forms the installer runs pmmcp's python in, and nothing added: never
 * another of pmmcp's modules or scripts, nor another argument (rotate's
 * --restart runs launchctl kickstart -k; supervisor.py stops and unloads;
 * http_auth new-token prints a token the leak scan cannot know;
 * restore_pmmcp_backup.py and qdrant_api_key.py rollback write pmmcp's
 * state back), nor the standard library's (-m timeit runs the text it is
 * given).
 */
const PYTHON_FORMS: readonly PythonForm[] = [
  { args: ['scripts/pmmcp_facts.py', '--json'], digest: false },
  { args: ['scripts/qdrant_api_key.py', 'status', '--json'], digest: false },
  { args: ['scripts/qdrant_api_key.py', 'cleanup'], digest: false },
  { args: ['scripts/qdrant_api_key.py', 'init'], digest: false },
  { args: ['scripts/qdrant_api_key.py', 'enable'], digest: false },
  { args: ['scripts/qdrant_api_key.py', 'enable', '--dry-run'], digest: false },
  { args: ['scripts/rotate_http_auth_token.py', CLIENT_NAME, '--create', '--digest-stdin'], digest: true },
  { args: ['-m', 'src.transport.http_auth', 'check'], digest: false },
  { args: ['-m', 'src.transport.http_auth', 'check', '--expect', CLIENT_NAME], digest: true },
  { args: ['-m', 'src.dashboard.auth', 'init'], digest: false },
  { args: ['-m', 'src.dashboard.auth', 'init', '--only', 'dashboard'], digest: false },
  { args: ['-m', 'src.dashboard.auth', 'init', '--only', 'curator'], digest: false },
  { args: ['-m', 'src.dashboard.auth', 'status', '--json'], digest: false },
]

/** The forms as a refusal names them. */
const PYTHON_FORMS_SHOWN =
  'scripts/pmmcp_facts.py --json; scripts/qdrant_api_key.py status --json, cleanup, init, enable or enable --dry-run; scripts/rotate_http_auth_token.py NAME --create --digest-stdin and -m src.transport.http_auth check --expect NAME, each with a digest on stdin; -m src.transport.http_auth check; -m src.dashboard.auth init, init --only dashboard, init --only curator or status --json'

/** A program looked up on the child's PATH. */
const BARE_PROGRAM = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/

/** The longest timeout a probe may be given: a day is no longer a probe. */
const MAX_TIMEOUT_MS = 24 * 60 * 60 * 1000

/** How long a probe sent SIGKILL at its deadline is waited for before it is reported unreaped. */
export const KILL_GRACE_MS = 5000

/** Machine output larger than this is not what any interface the installer reads prints. */
export const MAX_MACHINE_OUTPUT = 1024 * 1024

/** How much of a file tail() reads from its end. */
export const TAIL_BYTES = 64 * 1024

/** How much the leak scan reads at a time, and how much of the last read it keeps, so a value across two reads is still whole in one window. */
export const SCAN_CHUNK = 1024 * 1024
const SCAN_OVERLAP = 64 * 1024

export type RunErrorCode =
  | 'AOS_INSTALL_RUN_REFUSED'
  | 'AOS_INSTALL_RUN_BUSY'
  | 'AOS_INSTALL_RUN_SPAWN'
  | 'AOS_INSTALL_RUN_LEAK'
  | 'AOS_INSTALL_RUN_HALTED'
  | 'AOS_INSTALL_RUN_OUTPUT'

/** What went wrong, by code; the message names steps, paths and names, never a value. */
export class InstallRunError extends KernelError {
  readonly step: string | undefined
  /** For a leak: how the child ended. Its output is gone. */
  readonly result: RunResult | undefined

  constructor(code: RunErrorCode, message: string, step?: string, result?: RunResult) {
    super(code, message)
    this.step = step
    this.result = result
  }
}

export interface RunSpec {
  /** The step's name: its output goes to <step>.out and <step>.err (a repeated name gets -2, -3, ...). */
  readonly step: string
  /** An absolute path, or a bare program name looked up on the child's PATH. */
  readonly command: string
  readonly args: readonly string[]
  /** An absolute directory. */
  readonly cwd: string
  /** One `sha256:<64 lowercase hex>` digest, sent as one line on stdin; without it stdin is /dev/null. */
  readonly digest?: string
  /** A read-only probe only: SIGKILL after this many milliseconds. */
  readonly timeoutMs?: number
  /**
   * Run in a session of its own, recorded in active.json, with no timeout:
   * for a step inside the stopped window. The stop and start scripts always
   * run so, whatever this says.
   */
  readonly ownSession?: boolean
}

/** What spawn is handed: no timeout and no kill signal, by construction. */
export interface ChildOptions {
  readonly cwd: string
  readonly env: Readonly<Record<string, string>>
  /** stdin ('ignore' is /dev/null), then the .out and .err descriptors. */
  readonly stdio: readonly ['ignore' | 'pipe', number, number]
  readonly detached: boolean
}

/** The part of a ChildProcess the runner uses. */
export interface ChildLike {
  readonly pid?: number | undefined
  readonly stdin: Writable | null
  kill(signal: NodeJS.Signals): boolean
  once(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown
  once(event: 'error', listener: (error: Error) => void): unknown
}

export type SpawnFn = (command: string, args: readonly string[], options: ChildOptions) => ChildLike

/** Node's spawn, as spawnWith calls it. */
export type NodeSpawnFn = (command: string, args: readonly string[], options: SpawnOptions) => ChildLike

/**
 * A SpawnFn over Node's spawn (or a stand-in for it): the options it hands
 * on are exactly cwd, env, stdio and detached, so no timeout, kill signal or
 * shell can be added on the way.
 */
export function spawnWith(impl: NodeSpawnFn): SpawnFn {
  return (command, args, o) => impl(command, [...args], { cwd: o.cwd, env: { ...o.env }, stdio: [o.stdio[0], o.stdio[1], o.stdio[2]], detached: o.detached })
}

const realSpawn: SpawnFn = spawnWith(nodeSpawn)

export interface RunResult {
  readonly step: string
  readonly pid: number | undefined
  readonly out: string
  readonly err: string
  readonly started: Date
  readonly elapsedMs: number
  readonly code: number | null
  readonly signal: NodeJS.Signals | null
  readonly timedOut: boolean
  /**
   * False only for a probe that was sent SIGKILL at its deadline and had not
   * exited a grace period later: it may still run and write to its files,
   * and code and signal are null.
   */
  readonly exited: boolean
  /** The stdin pipe's error code, when the digest could not be delivered. */
  readonly stdinError: string | undefined
  /** An error the child emitted after it was spawned: only a failed kill can be one. */
  readonly childError: string | undefined
  /** For a step in its own session: why active.json could not be removed after the exit. The record stays, and a re-run waits on it. */
  readonly activeError: string | undefined
}

export interface Started {
  readonly step: string
  readonly pid: number | undefined
  readonly out: string
  readonly err: string
  readonly started: Date
  /** For a step in its own session: why active.json could not be filled in. It then reads as unreadable, which keeps a re-run waiting. */
  readonly activeError: string | undefined
  readonly done: Promise<RunResult>
}

export interface RunnerOptions {
  /** The repository root: the logs go under <repoRoot>/.aos/install. */
  readonly repoRoot: string
  /** The installer's environment, which the child's is picked from (default: process.env). */
  readonly env?: Readonly<Record<string, string | undefined>>
  readonly spawn?: SpawnFn
  readonly now?: () => Date
}

const refused = (message: string, step?: string): InstallRunError => new InstallRunError('AOS_INSTALL_RUN_REFUSED', message, step)

/** An error by its errno or Node code, else its class: never its message, which may quote what it was handed. */
const errnoOf = (e: unknown): string => {
  if (!(e instanceof Error)) return 'unknown'
  return 'code' in e && typeof e.code === 'string' ? e.code : e.name
}

/**
 * The environment a child runs with: the allowlisted names the installer has,
 * PATH fixed, and SSH_AUTH_SOCK only when the program is git.
 */
export function childEnv(parent: Readonly<Record<string, string | undefined>>, command: string): Record<string, string> {
  const home = parent['HOME']
  if (home === undefined || !isAbsolute(home) || home.includes(':')) {
    throw refused('HOME is not set to an absolute path without a colon, so no PATH can be built for a child')
  }
  const env: Record<string, string> = {}
  const names = basename(command) === 'git' ? [...PASSED_NAMES, ...GIT_ONLY_NAMES] : PASSED_NAMES
  for (const name of names) {
    const value = parent[name]
    if (value !== undefined && value !== '') env[name] = value
  }
  env['PATH'] = childPath(home)
  return env
}

/** True when a string holds a registered secret or a credential shape. */
const holdsCredential = (s: string): boolean => redactString(s) !== s

/** The service script a file name is, in any case. */
const scriptNamed = (name: string): string | undefined => {
  const lower = name.toLowerCase()
  return SERVICE_SCRIPTS.find((s) => s === lower)
}

/**
 * What a path resolves to, links followed as the kernel follows them, when
 * it resolves: realpath(3), which takes a `..` from the folder a link led
 * to. Never Node's own realpathSync, which first collapses `..` by spelling
 * (a/link/../ps would be a/ps to it while exec runs the ps beside the
 * link's target), nor path.resolve, which does the same.
 */
function realOf(path: string): string | undefined {
  try {
    return realpathSync.native(path)
  } catch {
    return undefined
  }
}

/** The service script a path is by the name of what it resolves to (a symbolic link of another name). */
const scriptLinkedAt = (path: string): string | undefined => {
  const real = realOf(path)
  return real === undefined ? undefined : scriptNamed(basename(real))
}

/** Where the child finds a bare program: the first executable file of that name on its PATH, links followed, as execvp does. */
function onChildPath(name: string, env: Readonly<Record<string, string>>): string | undefined {
  for (const dir of (env['PATH'] ?? '').split(':')) {
    if (dir === '') continue
    const candidate = join(dir, name)
    try {
      if (!statSync(candidate).isFile()) continue
      accessSync(candidate, constants.X_OK)
      return candidate
    } catch {
      // Not here.
    }
  }
  return undefined
}

/** A regular file by identity, links followed. */
interface FileId {
  readonly dev: bigint
  readonly ino: bigint
  readonly size: bigint
}

/** A path's identity; undefined when nothing is there or it is not a regular file. */
function fileId(path: string): FileId | undefined {
  try {
    const st = statSync(path, { bigint: true })
    return st.isFile() ? { dev: st.dev, ino: st.ino, size: st.size } : undefined
  } catch {
    return undefined
  }
}

/** One of an install's two scripts, as found on disk. */
interface ScriptFile extends FileId {
  readonly script: string
  /** Where it is, links resolved: what its bytes are read from, and the install a run of it teaches the runner. */
  readonly path: string
}

/**
 * The stop and start scripts in each folder that has them, by the path each
 * resolves to (a folder or script reached through a link included): each
 * file once under each name it was found by, so a hard link of the start
 * named stop-pmmcp-server.sh is both, whichever folder is looked in first.
 */
function scriptsIn(dirs: Iterable<string>): ScriptFile[] {
  const found: ScriptFile[] = []
  for (const dir of dirs) {
    for (const script of SERVICE_SCRIPTS) {
      const path = realOf(join(dir, script))
      const id = path === undefined ? undefined : fileId(path)
      if (path !== undefined && id !== undefined && !found.some((f) => f.dev === id.dev && f.ino === id.ino && f.script === script)) found.push({ ...id, script, path })
    }
  }
  return found
}

/** A file's bytes, when it is a regular file of exactly `size` bytes that opens without blocking; undefined otherwise. */
function bytesOf(path: string, size: number): Buffer | undefined {
  let fd: number
  try {
    fd = openRegular(path, true)
  } catch {
    return undefined
  }
  try {
    const buf = readAt(fd, size + 1, 0)
    return buf.length === size ? buf : undefined
  } catch {
    return undefined
  } finally {
    closeSync(fd)
  }
}

/**
 * The install scripts a file is by identity: each found with the same
 * dev:ino (a hard link of any name, or a symbolic link to one), or, with
 * `copies` and none of those, each with the same bytes (a renamed copy).
 * Empty when it is none of them.
 */
function scriptsByIdentity(path: string, scripts: readonly ScriptFile[], copies: boolean): ScriptFile[] {
  const id = fileId(path)
  if (id === undefined) return []
  const linked = scripts.filter((s) => s.dev === id.dev && s.ino === id.ino)
  if (linked.length > 0) return linked
  const sized = scripts.filter((s) => s.size === id.size)
  if (!copies || sized.length === 0 || id.size > BigInt(MAX_SCRIPT_BYTES)) return []
  // Read where a link leads (bytesOf opens nothing through one), as exec runs what it leads to.
  const real = realOf(path)
  const mine = real === undefined ? undefined : bytesOf(real, Number(id.size))
  if (mine === undefined) return []
  return sized.filter((s) => bytesOf(s.path, Number(s.size))?.equals(mine) === true)
}

/**
 * True when an argument names a service script: as text in any case, as a
 * path that resolves to one by name, or as one by dev:ino (a hard link, or a
 * link to one). A renamed copy is only a file here: no program the
 * installer runs is given a file to run.
 */
function namesScript(arg: string, path: string | undefined, scripts: readonly ScriptFile[]): boolean {
  const lower = arg.toLowerCase()
  if (SERVICE_SCRIPTS.some((s) => lower.includes(s))) return true
  if (path === undefined) return false
  return scriptLinkedAt(path) !== undefined || scriptsByIdentity(path, scripts, false).length > 0
}

/** True when a path has a `.` or `..` component: after a link, `..` is not the folder its spelling names. */
const dotted = (path: string): boolean => path.split('/').some((c) => c === '.' || c === '..')

/**
 * The file an argument names, as a child opening it from the working
 * directory gets it: the path left as spelled for the kernel (and realOf) to
 * resolve, never collapsed by path.resolve, which takes `..` by spelling.
 */
const argPath = (cwd: string, arg: string): string | undefined => (arg === '' ? undefined : isAbsolute(arg) ? arg : `${cwd}/${arg}`)

/** The arguments the stop or start script may be given here (the contract); anything else is refused. */
function scriptArgsAllowed(script: string, args: readonly string[]): boolean {
  if (script === START_SCRIPT) return args.length === 0 || (args.length === 1 && args[0] === '--check')
  if (args.length === 1 && args[0] === '--jobs') return true
  let quiet = false
  let wait = false
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]
    if (arg === '--quiet' && !quiet) {
      quiet = true
    } else if (arg === '--wait-timeout' && !wait) {
      // Whole seconds as the script reads them: no sign, no leading 0, no more digits than bash arithmetic holds.
      const n = args[i + 1]
      if (n === undefined || !/^[1-9][0-9]{0,8}$/.test(n) || Number(n) < MIN_WAIT_TIMEOUT_S) return false
      wait = true
      i += 1
    } else {
      return false
    }
  }
  return true
}

/** The names a program runs as, lower case (APFS runs KILL as kill): as typed, then the file a link to it resolves to when that is another name. */
function programNames(command: string, located: string | undefined): string[] {
  const typed = basename(command).toLowerCase()
  const real = located === undefined ? undefined : realOf(located)
  const resolved = real === undefined ? typed : basename(real).toLowerCase()
  return resolved === typed ? [typed] : [typed, resolved]
}

/** The form of PYTHON_FORMS these arguments are, after -B at most; undefined when they are none. */
function pythonForm(args: readonly string[]): PythonForm | undefined {
  const rest = args[0] === '-B' ? args.slice(1) : args
  return PYTHON_FORMS.find((f) => f.args.length === rest.length && f.args.every((a, i) => (typeof a === 'string' ? rest[i] === a : a.test(rest[i] ?? ''))))
}

/** How the venv's python may be run: a checkout's .venv/bin/python by absolute path, in one of PYTHON_FORMS, with a digest on stdin exactly when that form reads one. */
function pythonRefusal(command: string, args: readonly string[], digest: boolean): string | undefined {
  const venv = isAbsolute(command) && basename(dirname(command)) === 'bin' && basename(dirname(dirname(command))) === '.venv'
  const form = pythonForm(args)
  if (venv && form !== undefined) {
    if (form.digest === digest) return undefined
    return form.digest ? 'this python form reads its digest on stdin, and none was given' : 'this python form takes no stdin, and a digest was given'
  }
  return `python runs here only as a checkout's .venv/bin/python, by absolute path, after -B at most, in a form the installer runs (${PYTHON_FORMS_SHOWN}): never -c, another module or script, another argument, or commands read from stdin`
}

/** Why a program is never run here with these arguments, by any name it runs as (typed or resolved), or undefined. */
function programRefusal(names: ReadonlySet<string>, command: string, args: readonly string[], digest: boolean): string | undefined {
  const named = (list: readonly string[]): string | undefined => list.find((p) => names.has(p))
  const sender = named(SIGNAL_SENDERS)
  if (sender !== undefined) return `${sender} signals the processes it names or runs, and nothing here signals a process (never the stop or start script)`
  if (names.has('launchctl')) {
    const sub = (args[0] ?? '').toLowerCase()
    if (!LAUNCHCTL_READS.includes(sub)) {
      const kickstart = sub === 'kickstart' ? ': kickstart restarts a service (with -k it kills it first), and pmmcp is stopped and started only by its own scripts' : ''
      return `launchctl is run here only to read, with print or list${kickstart}`
    }
  }
  const shell = named(SHELLS)
  if (shell !== undefined) {
    return `a shell (${shell}) runs nothing here, whatever it is given: a -c command string, a script file (pmmcp's uninstall-pmmcp-service.sh runs launchctl bootout and kill) and commands read from stdin are all beyond these rules' sight, and the installer runs no shell`
  }
  if (names.has('env') && args.length > 0) return "env given an argument runs a program (or changes the environment) out of these rules' sight: run the program itself"
  const launcher = named(LAUNCHERS)
  if (launcher !== undefined) return `${launcher} runs a program its arguments name, out of these rules' sight: run the program itself`
  if (names.has('find') && args.some((a) => FIND_RUNS.test(a))) return "find -exec (or -execdir, -ok, -okdir) runs a program out of these rules' sight"
  const interpreter = named(INTERPRETERS)
  if (interpreter !== undefined) return `${interpreter} runs program text its arguments carry, out of these rules' sight, and the installer runs none`
  if ([...names].some((n) => PYTHON.test(n))) return pythonRefusal(command, args, digest)
  return undefined
}

/** What one program on the allowlist may be given; undefined when these arguments may run. */
type ArgRule = (args: readonly string[], command: string) => string | undefined

/** For a program whose arguments read and nothing more, or whose rule programRefusal holds by any name (launchctl). */
const ANY_ARGS: ArgRule = () => undefined

/** docker reads here: pmmcp-qdrant's state (ps), the engine's (info) and the context (context show). */
const dockerRule: ArgRule = (args) => {
  const sub = args[0] ?? ''
  if (DOCKER_READS.includes(sub) || (sub === 'context' && args[1] === 'show' && args.length === 2)) return undefined
  return 'docker is run here only to read, with ps, info or context show, and no option before them: never kill, stop, restart, rm or compose, and pmmcp-qdrant is stopped and started only by pmmcp'
}

/** git: --no-optional-locks at most before the command; the read-only commands, and merge, reset and clone in the one form each the installer runs. */
const gitRule: ArgRule = (args) => {
  const i = args[0] === '--no-optional-locks' ? 1 : 0
  const sub = args[i] ?? ''
  const rest = args.slice(i + 1)
  const operand = (a: string | undefined): boolean => a !== undefined && a !== '' && !a.startsWith('-')
  if (sub.startsWith('-') || sub === '') return 'git is given here no option before its command but --no-optional-locks: never -c, --config-env, -C, --exec-path, --git-dir or --work-tree'
  if (sub === 'diff') {
    const end = rest.indexOf('--')
    const options = (end === -1 ? rest : rest.slice(0, end)).filter((a) => a.startsWith('-'))
    return options.every((o) => GIT_DIFF_OPTIONS.includes(o)) ? undefined : `git diff is given here only ${GIT_DIFF_OPTIONS.join(', ')} and --: never --output, which writes a file, or --ext-diff, which runs a program`
  }
  if (GIT_READS.includes(sub)) return undefined
  if (sub === 'merge') return rest.length === 2 && rest[0] === '--ff-only' && operand(rest[1]) ? undefined : 'git merge is run here only as merge --ff-only <commit>'
  if (sub === 'reset') return rest.length === 2 && rest[0] === '--keep' && operand(rest[1]) ? undefined : 'git reset is run here only as reset --keep <commit>'
  if (sub === 'clone') {
    const [url, into] = rest
    return rest.length === 2 && url !== undefined && /^https:\/\/[^\s]+$/.test(url) && operand(into) && isAbsolute(into ?? '') ? undefined : 'git clone is run here only as clone https://... <absolute folder>, with no option (never -u, --upload-pack, -c or --template, each of which runs or configures a program)'
  }
  return `git ${shownLine(sub).slice(0, 32)} is not a command run here: only ${GIT_READS.join(', ')}, merge --ff-only, reset --keep and clone`
}

/** plutil reads one key to stdout: -extract <key> <format> -o - <file>. Without -o - it writes the plist in place, as -convert, -replace, -insert and -remove do. */
const plutilRule: ArgRule = (args) => (args.length === 6 && args[0] === '-extract' && args[3] === '-o' && args[4] === '-' ? undefined : 'plutil is run here only as -extract <key> <format> -o - <file>, which reads; every other form writes the plist')

/** pmmcp's setup.sh, which the clone step runs: by absolute path, --non-interactive alone. */
const setupRule: ArgRule = (args, command) => (isAbsolute(command) && args.length === 1 && args[0] === '--non-interactive' ? undefined : 'setup.sh is run here only by absolute path, with --non-interactive alone')

/**
 * What runs here, by name (lower case), and what each is given: the
 * programs the installer runs, and nothing for its tests' sake. The venv's
 * python (by PYTHON, held by pythonRefusal) and the stop and start scripts
 * (by identity, held by scriptArgsAllowed) are the rest. A program by any
 * other name is refused, whatever it is: a shell, env, and a copy of a shell
 * or an interpreter under a name of its own included.
 */
const PROGRAMS: ReadonlyMap<string, ArgRule> = new Map<string, ArgRule>([
  ['ps', ANY_ARGS],
  ['pgrep', ANY_ARGS],
  ['lsof', ANY_ARGS],
  ['ls', ANY_ARGS],
  ['plutil', plutilRule],
  ['launchctl', ANY_ARGS],
  ['docker', dockerRule],
  ['git', gitRule],
  ['setup.sh', setupRule],
])

const ALLOWLIST_SHOWN = `only ${[...PROGRAMS.keys()].join(', ')}, a checkout's .venv/bin/python, and the stop and start scripts`

/**
 * Why a program that is neither the stop nor the start script is not run
 * here, or undefined when it may run with these arguments: every name it
 * runs as (`names`: typed, then the one a link resolves it to) must be on
 * the allowlist, and each name's rule must let these arguments through, so
 * an allowlisted name linked to a program on no list (ls to tar, pgrep to
 * flock) is refused, and one linked to another on the list is held to both.
 */
function notOnAllowlist(command: string, names: readonly string[], args: readonly string[]): string | undefined {
  const [typed] = names
  for (const name of names) {
    if (PYTHON.test(name)) continue
    const rule = PROGRAMS.get(name)
    if (rule === undefined) {
      const shown = (n: string): string => JSON.stringify(shownLine(n).slice(0, 64))
      return name === typed
        ? `${shown(basename(command))} is not a program the installer runs: ${ALLOWLIST_SHOWN}`
        : `${shown(basename(command))} resolves to ${shown(name)}, which is not a program the installer runs: ${ALLOWLIST_SHOWN}`
    }
    const why = rule(args, command)
    if (why !== undefined) return why
  }
  return undefined
}

/** What checkSpec found: the service script the spec runs, if any, whether it runs in its own session, and the folders a script runs from. */
interface Checked {
  readonly script: string | undefined
  readonly ownSession: boolean
  /** For a service script: the folders it ran from (the command's, as typed and as resolved, and the script's it was found to be), where later commands are compared with the install's scripts. */
  readonly installs: readonly string[]
}

/** Check a spec without changing anything: `installs` are the folders this runner has run a service script from. */
function checkSpec(spec: RunSpec, env: Readonly<Record<string, string>>, installs: ReadonlySet<string>): Checked {
  const { step } = spec
  if (typeof step !== 'string' || !STEP_NAME.test(step)) {
    throw refused(`a step is named [a-z0-9][a-z0-9._-]*, at most 48 characters; got ${JSON.stringify(redactString(String(step)).replace(CONTROL, ''))}; nothing was run`)
  }
  const extra = Object.keys(spec).filter((k) => !SPEC_FIELDS.includes(k))
  if (extra.length > 0) {
    throw refused(`${step}: a spec carries only ${SPEC_FIELDS.join(', ')}, never ${extra.map((k) => JSON.stringify(shownLine(k).slice(0, 32))).join(', ')} (no kill signal, no other timeout); nothing was run`, step)
  }
  if (!isAbsolute(spec.cwd)) throw refused(`${step}: the working directory must be absolute`, step)
  if (!isAbsolute(spec.command) && !BARE_PROGRAM.test(spec.command)) {
    throw refused(`${step}: the command must be an absolute path or a bare program name`, step)
  }
  // After a link, `..` leaves the folder the link leads to, not the one its spelling names: what these rules look at would not be what runs.
  for (const [what, path] of [
    ['the command', spec.command],
    ['the working directory', spec.cwd],
  ] as const) {
    if (dotted(path)) throw refused(`${step}: ${what} has a . or .. component, which after a link is another folder than its spelling says; nothing was run`, step)
  }
  // Every byte that leaves for the child, before anything is created.
  const where: [string, string][] = [
    ['the command', spec.command],
    ['the working directory', spec.cwd],
    ...spec.args.map((a, i): [string, string] => [`argument ${String(i + 1)}`, a]),
    ...Object.entries(env).map(([k, v]): [string, string] => [`the environment's ${k}`, v]),
  ]
  if (spec.digest !== undefined) where.push(['stdin', spec.digest])
  for (const [what, text] of where) {
    if (text.includes('\0')) throw refused(`${step}: ${what} holds a NUL byte, which no program can be handed; nothing was run`, step)
    if (holdsCredential(text)) throw refused(`${step}: ${what} holds a registered secret or a credential shape; nothing was run`, step)
  }
  if (spec.digest !== undefined && !DIGEST_LINE.test(spec.digest)) {
    throw refused(`${step}: stdin carries one sha256:<64 lowercase hex> digest or nothing; nothing was run`, step)
  }

  // The program by its names, as typed and as a link (or the child's PATH) resolves it.
  const located = isAbsolute(spec.command) ? spec.command : onChildPath(spec.command, env)
  const names = programNames(spec.command, located)
  const why = programRefusal(new Set(names), spec.command, spec.args, spec.digest !== undefined)
  if (why !== undefined) throw refused(`${step}: ${why}; nothing was run`, step)

  // Each argument as the file a child opening it would get, `..` left for the kernel (and realOf) to resolve.
  const argPaths = spec.args.map((a) => argPath(spec.cwd, a))

  // The install scripts this spec is compared with: wherever it could reach one.
  const dirs = new Set(installs)
  const home = env['HOME']
  if (home !== undefined) dirs.add(join(home, ...DEFAULT_INSTALL))
  const dirsOf = (path: string): string[] => {
    const real = realOf(path)
    return real === undefined ? [dirname(path)] : [dirname(path), dirname(real)]
  }
  // The working directory as given: it has no `..`, and each script in it is resolved as the kernel resolves it (scriptsIn).
  dirs.add(spec.cwd)
  if (located !== undefined) for (const d of dirsOf(located)) dirs.add(d)
  for (const p of argPaths) if (p !== undefined && fileId(p) !== undefined) for (const d of dirsOf(p)) dirs.add(d)
  const scripts = scriptsIn(dirs)

  // Which script the command is: by its name, by the name a link gives it, and by identity (dev:ino, or the bytes of a renamed copy). All that say must agree.
  const named = scriptNamed(basename(spec.command))
  const linkedAs = located === undefined ? undefined : scriptLinkedAt(located)
  const matched = located === undefined ? [] : scriptsByIdentity(located, scripts, true)
  const taken = new Set([named, linkedAs, ...matched.map((m) => m.script)].filter((s): s is string => s !== undefined))
  if (taken.size > 1) {
    throw refused(`${step}: the command is taken for both the stop and the start script (named or linked as one, the same file or bytes as the other, or a copy of both); nothing was run`, step)
  }
  const [script] = taken
  if (script === undefined) {
    if (spec.args.some((a, i) => namesScript(a, argPaths[i], scripts)) || SERVICE_SCRIPTS.some((s) => spec.command.toLowerCase().includes(s))) {
      throw refused(`${step}: the stop and start scripts run only as the command itself, by absolute path; nothing was run`, step)
    }
    const unlisted = notOnAllowlist(spec.command, names, spec.args)
    if (unlisted !== undefined) throw refused(`${step}: ${unlisted}; nothing was run`, step)
    const ownSession = spec.ownSession === true
    if (spec.timeoutMs !== undefined) {
      if (ownSession) throw refused(`${step}: a step in its own session is given no timeout; nothing was run`, step)
      if (!Number.isInteger(spec.timeoutMs) || spec.timeoutMs <= 0 || spec.timeoutMs > MAX_TIMEOUT_MS) {
        throw refused(`${step}: timeoutMs must be a whole number of milliseconds from 1 to a day`, step)
      }
    }
    return { script: undefined, ownSession, installs: [] }
  }
  if (!isAbsolute(spec.command)) throw refused(`${step}: ${script} runs only by absolute path; nothing was run`, step)
  if (!scriptArgsAllowed(script, spec.args)) {
    const allowed = script === START_SCRIPT ? 'no argument or --check' : `no argument, --jobs alone, or --quiet and --wait-timeout N (N at least ${String(MIN_WAIT_TIMEOUT_S)})`
    throw refused(`${step}: ${script} is run here only with ${allowed}; nothing was run`, step)
  }
  if (spec.timeoutMs !== undefined) throw refused(`${step}: ${script} is given no timeout; nothing was run`, step)
  if (spec.digest !== undefined) throw refused(`${step}: ${script} takes no stdin; nothing was run`, step)
  // The install it ran from: the command's folder as typed and as resolved, and that of the script a link or copy of another name is.
  return { script, ownSession: true, installs: [...dirsOf(spec.command), ...matched.flatMap((m) => dirsOf(m.path))] }
}

/** The UTC stamp a run's folder is named by: 20261029T054506Z. */
export function stampOf(at: Date): string {
  return at.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')
}

/** <repoRoot>/.aos/install: the runs' folders and active.json. */
export function installDir(repoRoot: string): string {
  return join(repoRoot, '.aos', 'install')
}

export function activePath(repoRoot: string): string {
  return join(installDir(repoRoot), 'active.json')
}

const euid = (): number | undefined => process.geteuid?.()

/**
 * Make a directory 0700. False when it was there already. umask only clears
 * bits, and one of 0700 would leave none, hence the chmod.
 */
function makeDirectory(path: string): boolean {
  try {
    mkdirSync(path, { mode: 0o700 })
  } catch (e) {
    if (errnoOf(e) === 'EEXIST') return false
    throw refused(`cannot make ${path} (${errnoOf(e)})`)
  }
  chmodSync(path, 0o700)
  return true
}

/** A directory the logs may go beneath: one, not a link, this account's, and no one else's to write in. */
function checkDirectory(path: string): void {
  const st = lstatSync(path)
  if (st.isSymbolicLink() || !st.isDirectory()) throw refused(`${path} is not a directory (a link is not one): the installer writes its logs only beneath a real one`)
  const me = euid()
  if (me !== undefined && st.uid !== me) throw refused(`${path} belongs to uid ${String(st.uid)}, not this account`)
  if ((st.mode & 0o022) !== 0) throw refused(`${path} is writable by group or others: chmod go-w ${path}, then re-run`)
}

/** Create a log file: 0600, exclusive, never through a link, appended to by the child. */
function createLog(path: string): number {
  let fd: number
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_APPEND, 0o600)
  } catch (e) {
    throw refused(`cannot create ${path} (${errnoOf(e)}); nothing was run`)
  }
  try {
    fchmodSync(fd, 0o600)
    if ((fstatSync(fd).mode & 0o777) !== 0o600) throw refused(`${path} does not keep mode 0600 on this filesystem`)
  } catch (e) {
    closeSync(fd)
    throw e
  }
  return fd
}

/** readSync's shape, as readAt calls it. */
export type ReadFn = (fd: number, buffer: Buffer, offset: number, length: number, position: number) => number

/**
 * Up to `length` bytes of a file from `position`, over as many reads as it
 * takes: a short read is read on from, and only the end of the file returns
 * fewer, so the buffer never carries bytes nothing was read into.
 */
export function readAt(fd: number, length: number, position: number, read: ReadFn = readSync): Buffer {
  const buf = Buffer.alloc(length)
  let got = 0
  while (got < length) {
    const n = read(fd, buf, got, length - got, position + got)
    if (n <= 0) break
    got += n
  }
  return buf.subarray(0, got)
}

/** A file this module reads that is not one it may: a FIFO or a device blocks or misleads a read, and another account's file is not the runner's. */
const notReadable = (why: string): Error => Object.assign(new Error(why), { code: why })

/**
 * A descriptor just opened, kept only when fstat says it is a regular file
 * and, unless `anyOwner`, this account's; anything else is closed again and
 * thrown, with `not a regular file` or `not this account's` as its code.
 */
function regularOrClose(fd: number, anyOwner: boolean): number {
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw notReadable('not a regular file')
    const me = euid()
    if (!anyOwner && me !== undefined && st.uid !== me) throw notReadable("not this account's")
  } catch (e) {
    closeSync(fd)
    throw e
  }
  return fd
}

/**
 * Open a file this module reads: never through a link, never blocking on the
 * open (O_NONBLOCK: a FIFO with no writer opens at once), and kept only as
 * regularOrClose says. The flags are written out read-only, as hygiene.test's
 * .env scan reads them.
 */
function openRegular(path: string, anyOwner = false): number {
  return regularOrClose(openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK), anyOwner)
}

/** Open a log to empty it, as openRegular opens one to read: a FIFO with no reader refuses at once (ENXIO) rather than wait for one. */
function openRegularToEmpty(path: string): number {
  return regularOrClose(openSync(path, constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK), false)
}

/** A log path as active.json records it: absolute, the step's .out or .err, nothing a terminal would act on and no credential shape. */
const recordedLog = (suffix: string): z.ZodType<string> =>
  z
    .string()
    .max(4096)
    .refine((p) => isAbsolute(p) && p.endsWith(suffix) && shownLine(p) === p)

/**
 * active.json's record, every field held to its shape: what a BUSY refusal
 * and discovery show of it comes from here, so a record written by anything
 * else cannot put a control sequence on the operator's screen.
 */
const ActiveRecord = z.object({
  step: z.string().regex(RECORDED_STEP),
  pid: z.number().int().positive().max(2 ** 31 - 1),
  started: z.iso.datetime(),
  out: recordedLog('.out'),
  err: recordedLog('.err'),
})
export type ActiveRecord = z.infer<typeof ActiveRecord>

export type Active =
  | { readonly state: 'none' }
  | { readonly state: 'recorded'; readonly record: ActiveRecord }
  /** A record that cannot be read: one being written when the installer died counts, and is no proof the child is gone. */
  | { readonly state: 'unreadable'; readonly reason: string }

/** What active.json says: a step in its own session that this installer started may still run. */
export function readActive(repoRoot: string): Active {
  const path = activePath(repoRoot)
  let text: string
  try {
    const fd = openRegular(path)
    try {
      const size = fstatSync(fd).size
      if (size > 4096) return { state: 'unreadable', reason: `${path} is ${String(size)} bytes` }
      text = readAt(fd, size, 0).toString('utf8')
    } finally {
      closeSync(fd)
    }
  } catch (e) {
    if (errnoOf(e) === 'ENOENT') return { state: 'none' }
    return { state: 'unreadable', reason: `${path} cannot be read (${errnoOf(e)})` }
  }
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    return { state: 'unreadable', reason: `${path} is not JSON` }
  }
  const parsed = ActiveRecord.safeParse(json)
  if (!parsed.success) return { state: 'unreadable', reason: `${path} is not a record of a running step` }
  return { state: 'recorded', record: parsed.data }
}

/** Remove active.json, once the caller has seen the child it records gone. */
export function clearActive(repoRoot: string): void {
  try {
    unlinkSync(activePath(repoRoot))
  } catch (e) {
    if (errnoOf(e) !== 'ENOENT') throw refused(`cannot remove ${activePath(repoRoot)} (${errnoOf(e)})`)
  }
}

/** True when the file holds a value registered with SecretMask; a file that cannot be read, or is not this account's regular file, counts. */
function holdsRegistered(path: string): boolean {
  if (SecretMask.size === 0) return false
  let fd: number
  try {
    fd = openRegular(path)
  } catch {
    return true
  }
  try {
    let carry = Buffer.alloc(0)
    const chunk = Buffer.alloc(SCAN_CHUNK)
    for (;;) {
      const n = readSync(fd, chunk, 0, SCAN_CHUNK, null)
      if (n === 0) return false
      const window = Buffer.concat([carry, chunk.subarray(0, n)])
      const text = window.toString('utf8')
      if (SecretMask.apply(text) !== text) return true
      carry = window.subarray(Math.max(0, window.length - SCAN_OVERLAP))
    }
  } catch {
    return true
  } finally {
    closeSync(fd)
  }
}

/** Empty a log file that held a registered value: only this account's regular file, opened as readActive opens one. */
function empty(path: string): void {
  const fd = openRegularToEmpty(path)
  try {
    ftruncateSync(fd, 0)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/**
 * What tail strips before a line is shown: CSI and other escape sequences,
 * every C0 and C1 control but tab, the bidi controls (U+061C, U+200E-F,
 * U+202A-E, U+2066-9), which can reorder what the operator reads, and the
 * line and paragraph separators (U+2028-9), which can start a line that
 * looks like the installer's own.
 */
const CONTROL = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|[\x00-\x08\x0a-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g

/** One line of child output as it may be shown: no terminal control, scrubbed. */
export function shownLine(line: string): string {
  return redactString(line.replace(CONTROL, ''))
}

/** The last `lines` lines of a log file, as they may be shown. A file that is not there shows nothing; one that is not this account's regular file is an error. */
export function tail(path: string, lines = 20): string[] {
  let fd: number
  try {
    fd = openRegular(path)
  } catch (e) {
    if (errnoOf(e) === 'ENOENT') return []
    throw new InstallRunError('AOS_INSTALL_RUN_OUTPUT', `cannot read ${path} (${errnoOf(e)})`)
  }
  try {
    const size = fstatSync(fd).size
    const from = Math.max(0, size - TAIL_BYTES)
    const all = readAt(fd, size - from, from).toString('utf8').split('\n')
    // Read from the middle of a line: drop its end, and the empty piece after a final newline.
    if (from > 0) all.shift()
    if (all.at(-1) === '') all.pop()
    return all.slice(-lines).map(shownLine)
  } finally {
    closeSync(fd)
  }
}

/** A child's stdout, for parsing: this account's regular file, whole, valid UTF-8, and at most `maxBytes`. */
export function readOut(result: Pick<RunResult, 'step' | 'out'>, maxBytes = MAX_MACHINE_OUTPUT): string {
  const fail = (why: string): InstallRunError => new InstallRunError('AOS_INSTALL_RUN_OUTPUT', `${result.step}: stdout ${why}`, result.step)
  let fd: number
  try {
    fd = openRegular(result.out)
  } catch (e) {
    throw fail(`cannot be read (${errnoOf(e)})`)
  }
  try {
    const size = fstatSync(fd).size
    if (size > maxBytes) throw fail(`is ${String(size)} bytes, over the ${String(maxBytes)} machine output may be`)
    const buf = readAt(fd, size, 0)
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(buf)
    } catch {
      throw fail('is not valid UTF-8')
    }
  } finally {
    closeSync(fd)
  }
}

export type Jobs =
  | { readonly running: number; readonly display: readonly string[] }
  | { readonly running: 'unknown' }

/** The longest job listing shown. */
const MAX_JOB_LINES = 50

/**
 * `stop-pmmcp-server.sh --jobs`, as its contract has it: stdout's first line
 * alone, `running jobs: N` with exit 0 or `running jobs: unknown` with exit 1.
 * Anything else, a line on stderr included however much it looks like a
 * count, is no answer (undefined). The job lines after the first are display
 * text, returned as they may be shown, never parsed.
 */
export function readJobs(result: RunResult): Jobs | undefined {
  const text = readOut(result)
  const lines = text.split('\n')
  const first = /^running jobs: (0|[1-9][0-9]{0,8}|unknown)$/.exec(lines[0] ?? '')
  if (first === null || result.signal !== null || !result.exited) return undefined
  if (first[1] === 'unknown') return result.code === 1 ? { running: 'unknown' } : undefined
  if (result.code !== 0) return undefined
  const display = lines.slice(1).filter((l) => l.trim() !== '').slice(0, MAX_JOB_LINES).map(shownLine)
  return { running: Number(first[1]), display }
}

/**
 * Runs the installer's children by the rules in the contract. One per
 * installer run: its first child makes <repo>/.aos/install/<UTC stamp>/.
 */
export class Runner {
  readonly repoRoot: string
  readonly #env: Readonly<Record<string, string | undefined>>
  readonly #spawn: SpawnFn
  readonly #now: () => Date
  #dir: string | undefined
  readonly #steps = new Set<string>()
  /** Every folder this runner has run the stop or start script from: later commands are compared with the scripts there. */
  readonly #installs = new Set<string>()
  #halted: string | undefined

  constructor(options: RunnerOptions) {
    if (!isAbsolute(options.repoRoot)) throw refused('the repository root must be an absolute path')
    this.repoRoot = options.repoRoot
    this.#env = options.env ?? process.env
    this.#spawn = options.spawn ?? realSpawn
    this.#now = options.now ?? ((): Date => new Date())
  }

  /** This run's log folder, once a child has made it. */
  get dir(): string | undefined {
    return this.#dir
  }

  /** Why nothing more is run, once a child's output held a registered value. */
  get halted(): string | undefined {
    return this.#halted
  }

  /**
   * Empty a step's two files once the caller has read what it needs from
   * them: for a probe whose output may hold another process's command line
   * (ps) or launchd's copy of a service's environment (launchctl print),
   * which the logs need not keep and the leak scan cannot judge. Only a step
   * this runner ran, in this run's folder, by the names it gave them. A file
   * already gone is no error; one that cannot be emptied is returned, never
   * thrown, so the caller can report it.
   */
  discard(result: Pick<RunResult, 'step' | 'out' | 'err'>): string | undefined {
    const dir = this.#dir
    const out = dir === undefined ? undefined : join(dir, `${result.step}.out`)
    const err = dir === undefined ? undefined : join(dir, `${result.step}.err`)
    if (out === undefined || err === undefined || !this.#steps.has(result.step) || result.out !== out || result.err !== err) {
      throw refused(`${result.step}: not a step of this run, so its files are not this runner's to empty`, result.step)
    }
    const failed: string[] = []
    for (const path of [out, err]) {
      try {
        empty(path)
      } catch (e) {
        if (errnoOf(e) !== 'ENOENT') failed.push(`${path} (${errnoOf(e)})`)
      }
    }
    return failed.length === 0 ? undefined : `could not empty ${failed.join(', ')}: delete ${failed.length > 1 ? 'them' : 'it'}`
  }

  /** Run a child to its exit. */
  run(spec: RunSpec): Promise<RunResult> {
    return this.start(spec).done
  }

  /** Start a child; `done` settles when it exits. Every refusal is thrown here, before anything exists. */
  start(spec: RunSpec): Started {
    if (this.#halted !== undefined) {
      throw new InstallRunError('AOS_INSTALL_RUN_HALTED', `${spec.step}: not run: ${this.#halted}`, spec.step)
    }
    const env = childEnv(this.#env, spec.command)
    const { ownSession, installs } = checkSpec(spec, env, this.#installs)
    for (const dir of installs) this.#installs.add(dir)
    if (ownSession) {
      const active = readActive(this.repoRoot)
      if (active.state !== 'none') throw this.#busy(spec.step, active)
    }

    const dir = this.#logDir()
    const step = this.#uniqueStep(spec.step)
    const out = join(dir, `${step}.out`)
    const err = join(dir, `${step}.err`)
    const outFd = createLog(out)
    let errFd: number
    try {
      errFd = createLog(err)
    } catch (e) {
      closeSync(outFd)
      throw e
    }
    const started = this.#now()

    let child: ChildLike
    let claim: number | undefined
    try {
      if (ownSession) claim = this.#claim(spec.step)
      child = this.#spawn(spec.command, spec.args, {
        cwd: spec.cwd,
        env,
        stdio: [spec.digest === undefined ? 'ignore' : 'pipe', outFd, errFd],
        detached: ownSession,
      })
    } catch (e) {
      const left = claim === undefined ? undefined : this.#release(claim)
      if (e instanceof InstallRunError && left === undefined) throw e
      throw new InstallRunError('AOS_INSTALL_RUN_SPAWN', `${step}: ${spec.command} could not be started (${errnoOf(e)})${left === undefined ? '' : `; ${left}`}`, step)
    } finally {
      // The child holds its own copies.
      closeSync(outFd)
      closeSync(errFd)
    }
    const pid = child.pid
    let activeError: string | undefined
    if (claim !== undefined) {
      // No pid: the spawn failed, and its 'error' comes next, so nothing here may throw past the listeners below.
      activeError = pid === undefined ? this.#release(claim) : this.#record(claim, { step, pid, started: started.toISOString(), out, err })
    }

    let stdinError: string | undefined
    if (spec.digest !== undefined) {
      if (child.stdin === null) stdinError = 'no stdin'
      else {
        // A child that ends without reading its stdin closes the pipe; its exit code says what it made of that.
        child.stdin.on('error', (e: Error) => {
          stdinError = errnoOf(e)
        })
        child.stdin.end(`${spec.digest}\n`)
      }
    }

    const done = new Promise<RunResult>((resolveRun, reject) => {
      let settled = false
      let timedOut = false
      let childError: string | undefined
      let timer: NodeJS.Timeout | undefined
      let grace: NodeJS.Timeout | undefined
      const stopTimers = (): void => {
        if (timer !== undefined) clearTimeout(timer)
        if (grace !== undefined) clearTimeout(grace)
      }
      const finish = (code: number | null, signal: NodeJS.Signals | null, exited: boolean): void => {
        if (settled) return
        settled = true
        stopTimers()
        const cleared = ownSession && exited ? this.#clearOwn(pid) : undefined
        const result: RunResult = {
          step,
          pid,
          out,
          err,
          started,
          elapsedMs: this.#now().getTime() - started.getTime(),
          code,
          signal,
          timedOut,
          exited,
          stdinError,
          childError,
          activeError: cleared,
        }
        const leaked = [out, err].filter(holdsRegistered)
        if (leaked.length === 0) {
          resolveRun(result)
          return
        }
        const emptied: string[] = []
        for (const path of leaked) {
          try {
            empty(path)
            emptied.push(path)
          } catch (e) {
            emptied.push(`${path} (could not be emptied: ${errnoOf(e)}; delete it)`)
          }
        }
        this.#halted = `a registered secret value reached ${step}'s output, a defect; the file was emptied: ${emptied.join(', ')}`
        reject(new InstallRunError('AOS_INSTALL_RUN_LEAK', `${step}: ${this.#halted}. Nothing more is run.`, step, result))
      }
      if (spec.timeoutMs !== undefined && !ownSession) {
        const { timeoutMs } = spec
        timer = setTimeout(() => {
          timedOut = true
          child.kill('SIGKILL')
          // A process in uninterruptible sleep dies only when its syscall returns: report it rather than wait on it for ever.
          grace = setTimeout(() => finish(null, null, false), KILL_GRACE_MS)
        }, timeoutMs)
      }
      child.once('error', (e) => {
        // Spawned: the only error left is a failed kill. It is reported with the exit, which still comes and decides.
        if (pid !== undefined) {
          childError = errnoOf(e)
          return
        }
        if (settled) return
        settled = true
        stopTimers()
        reject(new InstallRunError('AOS_INSTALL_RUN_SPAWN', `${step}: ${spec.command} could not be started (${errnoOf(e)})`, step))
      })
      child.once('exit', (code, signal) => {
        finish(code, signal, true)
      })
    })
    return { step, pid, out, err, started, activeError, done }
  }

  /** The refusal while active.json stands. A record's fields are shown only as readActive's schema let them through; an unreadable one by its reason, which names the path and an errno, never the file's text. */
  #busy(step: string, active: Active): InstallRunError {
    const what =
      active.state === 'recorded'
        ? `${active.record.step} (pid ${String(active.record.pid)}, since ${active.record.started}, output in ${active.record.out} and ${active.record.err})`
        : active.state === 'unreadable'
          ? `a step whose record cannot be read (${active.reason})`
          : 'a step whose record was there a moment ago'
    return new InstallRunError(
      'AOS_INSTALL_RUN_BUSY',
      `${step}: not run: ${activePath(this.repoRoot)} says an earlier step in its own session (a stop, a start, or a step inside the stopped window) may still be running: ${what}. ` +
        'Wait for it to end; nothing is stopped or started meanwhile.',
      step,
    )
  }

  /** The run's log folder, made on first use, under a .aos git ignores. */
  #logDir(): string {
    if (this.#dir !== undefined) return this.#dir
    if (!gitignoresAos(this.repoRoot)) {
      throw refused('.gitignore does not ignore /.aos/, where the installer keeps its logs: add the line /.aos/, then re-run')
    }
    try {
      assertAosEntry(this.repoRoot)
    } catch (e) {
      throw e instanceof ConfigError ? refused(e.message) : e
    }
    for (const dir of [join(this.repoRoot, '.aos'), installDir(this.repoRoot)]) {
      makeDirectory(dir)
      checkDirectory(dir)
    }
    const stamp = stampOf(this.#now())
    for (let n = 1; n <= 100; n += 1) {
      const dir = join(installDir(this.repoRoot), n === 1 ? stamp : `${stamp}-${String(n)}`)
      if (!makeDirectory(dir)) continue
      checkDirectory(dir)
      this.#dir = dir
      return dir
    }
    throw refused(`${installDir(this.repoRoot)} already holds 100 runs stamped ${stamp}`)
  }

  #uniqueStep(step: string): string {
    let name = step
    for (let n = 2; this.#steps.has(name); n += 1) name = `${step}-${String(n)}`
    this.#steps.add(name)
    return name
  }

  /** Claim active.json before the spawn, exclusively: a second claim fails while the first stands. */
  #claim(step: string): number {
    try {
      const fd = openSync(activePath(this.repoRoot), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
      fchmodSync(fd, 0o600)
      return fd
    } catch (e) {
      if (errnoOf(e) === 'EEXIST') throw this.#busy(step, readActive(this.repoRoot))
      throw refused(`${step}: cannot create ${activePath(this.repoRoot)} (${errnoOf(e)}); nothing was run`, step)
    }
  }

  /**
   * Fill the claim once the pid is known. The child runs by now, so a write
   * that fails is returned rather than thrown: it leaves the record
   * unreadable, which a re-run reads as a window that may be open.
   */
  #record(fd: number, record: ActiveRecord): string | undefined {
    try {
      writeSync(fd, `${JSON.stringify(record)}\n`)
      fsyncSync(fd)
      return undefined
    } catch (e) {
      return `${activePath(this.repoRoot)} could not be filled in (${errnoOf(e)})`
    } finally {
      closeSync(fd)
    }
  }

  /** Give a claim back: no child was started. Returns why the record stays, rather than throwing over the error that brought it here. */
  #release(fd: number): string | undefined {
    closeSync(fd)
    return this.#removeRecord()
  }

  /**
   * Remove active.json when it records this child, which has exited. Called
   * from the child's exit, so an error is returned, never thrown: thrown
   * there it would escape as an uncaught exception, and the step's leak scan
   * would never run.
   */
  #clearOwn(pid: number | undefined): string | undefined {
    const active = readActive(this.repoRoot)
    if (active.state === 'recorded' && active.record.pid !== pid) return undefined
    return this.#removeRecord()
  }

  #removeRecord(): string | undefined {
    try {
      clearActive(this.repoRoot)
      return undefined
    } catch (e) {
      return `${e instanceof Error ? e.message : 'active.json could not be removed'}: remove it once nothing it names runs`
    }
  }
}
