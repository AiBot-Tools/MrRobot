// @ts-check
// The in-image publisher (egress plan S4): /opt/aos/publish.mjs in the worker image.
//
// Contract: sandbox.publish's container, once a human has approved the call, is
// started as
//
//   docker run --init -i --network none ... <image id> node /opt/aos/mux.mjs -- \
//     node /opt/aos/publish.mjs --git-host=<host> --api-host=<host> --repo=<owner/name> \
//       --run=<runId> --branch=<branch> --title=<title> --body=<body>
//
// every argument the kernel's (src/runtime/sandbox-tools.ts publishCommand,
// which test/egress-publish.test.ts holds this file's parseArgs to): the two
// hosts and the repository from the one bound repository the agent's manifest
// may publish to, the run's id from the kernel, and the branch, title and body
// a human approved. The mux runs it as it runs any command, so its stdout and
// stderr reach the kernel as the call's result, and every request it sends goes
// to the mux on 127.0.0.1:3128 and so to the kernel's egress engine, which
// judges and records each one under the run's publish grant (git-fetch and
// git-push on the push host, github-pulls on the API host, for that one
// repository) before anything is dialled.
//
// What it does, in order, stopping at the first step that fails (exit 1) and
// sending nothing after it:
//
//   1. Reads the commit the workspace's HEAD names, itself, from the files of
//      /workspace/.git (workspaceHead): HEAD, then the branch's loose ref or
//      packed-refs. A plain repository at /workspace only, as the image's
//      gitconfig admits one (clone into it with `git clone <url> .`).
//   2. Makes a bare repository of its own under /tmp whose object store
//      borrows the workspace's (objects/info/alternates), and the workspace's
//      shallow list when it has one. No git process this file starts ever
//      reads the workspace's config, hooks or index: those are a run's writing,
//      and git runs what a repository's config names (core.fsmonitor, a hook,
//      a credential helper, an ext:: url). Only its objects are read, as data.
//   3. Reads the repository's default branch (git ls-remote --symref, HEAD):
//      the base of the pull request. A git-fetch request.
//   4. Pushes the commit to refs/heads/aos/<runId>/<branch>: a git-push
//      request, whose command list the kernel holds under aos/<runId>/.
//   5. Opens the pull request: POST /repos/<owner/name>/pulls on the API host,
//      its JSON in the one spelling the kernel's github-pulls route reads, its
//      head aos/<runId>/<branch> and its base the default branch.
//
// Every git it starts is /usr/bin/git, through no shell, with no stdin, in
// /tmp, with an environment of its own (GIT_ENV: no system or global config,
// http the only transport, no prompt) and the command-line config PROTECTED
// (no hook, no credential helper, no askpass, no signing, no submodule, the
// mux as the proxy, no redirect followed). The pull request is sent by this
// file itself, over node:http, to the mux, in absolute form, on an agent of
// its own, so no environment variable decides where it goes.
//
// It is NOT a boundary. It runs under the agent's uid, beside whatever an
// earlier exec left in the workspace, and the kernel judges every request it
// sends as it judges a worker's: only the publish grant's routes, on its one
// repository, refs and pull requests under aos/<runId>/ alone. It holds no
// credential: the kernel injects one, at its own edge, into a request it
// allowed. Node builtins only, and no build step: the image copies this file as
// it stands (images/worker/Dockerfile; test/hygiene.test.ts).

import { spawn as spawnChild } from 'node:child_process'
import { lstatSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'

/** @import { ChildProcess, SpawnOptions } from 'node:child_process' */
/** @import { ClientRequest, IncomingMessage, RequestOptions } from 'node:http' */

/** The mux, inside the container: the image's HTTP(S)_PROXY (images/worker/mux.mjs MUX_HOST, MUX_PORT). */
export const MUX_HOST = '127.0.0.1'
export const MUX_PORT = 3128
const PROXY = `http://${MUX_HOST}:${String(MUX_PORT)}`

/** The workspace, as the driver mounts it. */
export const WORKSPACE = '/workspace'

/** The image's git (Debian bookworm's), by its path: no PATH lookup decides which program runs. */
export const GIT = '/usr/bin/git'

/** How publish ends: done, a step failed, or arguments it does not read. */
export const PUBLISH_EXIT = Object.freeze({ ok: 0, failed: 1, usage: 2 })

/**
 * Every git's environment, whole: nothing of the container's own is passed
 * on. No system or global config (the image's /etc/gitconfig is an honest
 * worker's, and PROTECTED below says all this file needs), http the one
 * transport whatever any config says (GIT_ALLOW_PROTOCOL overrides every
 * protocol.*.allow), no prompt, and no pager.
 */
export const GIT_ENV = Object.freeze({
  PATH: '/usr/bin:/bin',
  HOME: '/tmp',
  LC_ALL: 'C',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_ALLOW_PROTOCOL: 'http',
  GIT_TERMINAL_PROMPT: '0',
  GIT_PAGER: 'cat',
})

/**
 * The command-line config every git is started with: the highest-priority
 * config git reads, so nothing else can set these. The repository it runs in
 * is this file's own (step 2), so they are a second wall, not the first.
 */
export const PROTECTED = Object.freeze([
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.fsmonitor=false',
  '-c', 'credential.helper=',
  '-c', 'core.askPass=',
  '-c', `http.proxy=${PROXY}`,
  '-c', 'http.followRedirects=false',
  '-c', 'protocol.version=0',
  '-c', 'push.gpgSign=false',
  '-c', 'push.recurseSubmodules=no',
  '-c', 'submodule.recurse=false',
])

/** The most of a git's stdout or stderr kept, and of a pull request's answer read. */
export const OUTPUT_MAX_BYTES = 65_536
/** The most of a failure's own text a line quotes. */
export const QUOTE_MAX_CHARS = 512

// ── the arguments ───────────────────────────────────────────────────────────

/**
 * @typedef {object} PublishArgs
 * @property {string} gitHost the push host: git-fetch and git-push
 * @property {string} apiHost the API host: github-pulls
 * @property {string} repo owner/name, in the kernel's one (lower-case) spelling
 * @property {string} run the run's id
 * @property {string} branch the branch under aos/<run>/
 * @property {string} title
 * @property {string} body
 */

/** The flags, in the order the kernel writes them. */
export const FLAGS = Object.freeze(['git-host', 'api-host', 'repo', 'run', 'branch', 'title', 'body'])

/** A lower-case DNS name with a dot in it, as the kernel's EgressHost spells one: no port, no address. */
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
const OWNER = /^[a-z0-9][a-z0-9-]{0,38}$/
const REPO_NAME = /^[a-z0-9._-]{1,100}$/
/** A run's id as the kernel mints one and a workspace directory admits it (sandbox-tools.ts WORKSPACE_RUN_ID). */
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_]{0,63}$/
/** A full object name, SHA-1 or SHA-256, as git writes it. */
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/

/**
 * A branch name as the kernel reads one (src/egress/routes.ts isBranchName):
 * components of letters, digits, dot, underscore and hyphen, none starting
 * with a dot or a hyphen, none ending with a dot or `.lock`, no `..`, at most
 * 200 characters.
 * @param {string} text
 */
export function isBranchName(text) {
  if (text.length === 0 || text.length > 200 || text.includes('..')) return false
  return text.split('/').every((part) => /^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(part) && !part.endsWith('.') && !part.endsWith('.lock'))
}

/** A host as HOST reads it, whose last label is no number: an address is never a host here, as it is none to the kernel. @param {string} host */
function isHost(host) {
  return HOST.test(host) && /[a-z]/.test(host.slice(host.lastIndexOf('.') + 1))
}

/** @param {string} repo */
function isRepo(repo) {
  const [owner = '', name = '', ...rest] = repo.split('/')
  return rest.length === 0 && OWNER.test(owner) && REPO_NAME.test(name) && name !== '.' && name !== '..' && !name.endsWith('.git')
}

/**
 * The arguments, exactly FLAGS in order, each `--<flag>=<value>` once, or
 * undefined: anything else is not the kernel's command. Each value is held to
 * what the kernel would have written, never narrower: a host, a repository, a
 * run id and a branch in their one spelling, a title of 1 to 1024 characters.
 * @param {readonly string[]} argv
 * @returns {PublishArgs | undefined}
 */
export function parseArgs(argv) {
  if (argv.length !== FLAGS.length) return undefined
  /** @type {string[]} */
  const values = []
  for (const [i, flag] of FLAGS.entries()) {
    const arg = argv[i] ?? ''
    const prefix = `--${flag}=`
    if (!arg.startsWith(prefix)) return undefined
    values.push(arg.slice(prefix.length))
  }
  const [gitHost = '', apiHost = '', repo = '', run = '', branch = '', title = '', body = ''] = values
  if (!isHost(gitHost) || !isHost(apiHost) || !isRepo(repo) || !RUN_ID.test(run) || !isBranchName(branch)) return undefined
  if (title.length === 0 || title.length > 1024) return undefined
  return Object.freeze({ gitHost, apiHost, repo, run, branch, title, body })
}

export const USAGE =
  'usage: node publish.mjs --git-host=<host> --api-host=<host> --repo=<owner/name> --run=<runId> --branch=<branch> --title=<title> --body=<body>\n'

/** @param {PublishArgs} args */
export function remoteOf(args) {
  return `http://${args.gitHost}/${args.repo}.git`
}

/** The branch the push lands on and the pull request is opened from: aos/<run>/<branch>. @param {PublishArgs} args */
export function headOf(args) {
  return `aos/${args.run}/${args.branch}`
}

// ── the workspace's HEAD, read as files ─────────────────────────────────────

/**
 * @typedef {object} Files
 * @property {(path: string) => string | undefined} readFile a regular file's text, never through a link; undefined when there is none
 * @property {(path: string) => boolean} isDirectory a directory, never through a link
 */

/**
 * The commit /workspace's HEAD names, read from its files and no git: HEAD as
 * an object name, or `ref: refs/heads/<branch>` and that branch's loose ref,
 * else its line in packed-refs. Anything else (a worktree's or submodule's
 * .git file, a link, a reftable, a ref outside refs/heads) is refused, named.
 * @param {Files} files
 * @returns {{ readonly oid: string } | { readonly refusal: string }}
 */
export function workspaceHead(files) {
  const git = `${WORKSPACE}/.git`
  if (!files.isDirectory(git) || !files.isDirectory(`${git}/objects`)) {
    return { refusal: `${WORKSPACE} is no plain git repository (its .git is no directory of its own): clone into it with git clone <url> .` }
  }
  const head = files.readFile(`${git}/HEAD`)?.replace(/\n$/, '')
  if (head === undefined) return { refusal: `${git}/HEAD is no file of its own` }
  if (OID.test(head)) return { oid: head }
  const named = /^ref: (refs\/heads\/[^\s]+)$/.exec(head)?.[1]
  if (named === undefined || !isBranchName(named.slice('refs/heads/'.length))) {
    return { refusal: "HEAD names neither a commit nor a branch under refs/heads in the kernel's spelling" }
  }
  const loose = files.readFile(`${git}/${named}`)?.replace(/\n$/, '')
  if (loose !== undefined) return OID.test(loose) ? { oid: loose } : { refusal: `${named} holds no object name` }
  for (const line of (files.readFile(`${git}/packed-refs`) ?? '').split('\n')) {
    const [oid = '', ref = '', ...rest] = line.split(' ')
    if (rest.length === 0 && ref === named && OID.test(oid)) return { oid }
  }
  return { refusal: `HEAD names ${named}, which has no commit` }
}

/**
 * The workspace's shallow list, each line an object name, or undefined when
 * it has none; a list holding anything else is refused.
 * @param {Files} files
 * @returns {{ readonly shallow: string | undefined } | { readonly refusal: string }}
 */
export function workspaceShallow(files) {
  const text = files.readFile(`${WORKSPACE}/.git/shallow`)
  if (text === undefined) return { shallow: undefined }
  const lines = text.split('\n').filter((line) => line !== '')
  if (!lines.every((line) => OID.test(line))) return { refusal: `${WORKSPACE}/.git/shallow holds a line that is no object name` }
  return { shallow: `${lines.join('\n')}\n` }
}

/**
 * The default branch an `ls-remote --symref <remote> HEAD` names, or
 * undefined when it names none in the kernel's spelling.
 * @param {string} listed
 */
export function defaultBranch(listed) {
  for (const line of listed.split('\n')) {
    const branch = /^ref: refs\/heads\/(\S+)\tHEAD$/.exec(line)?.[1]
    if (branch !== undefined) return isBranchName(branch) ? branch : undefined
  }
  return undefined
}

// ── the pull request ────────────────────────────────────────────────────────

/**
 * @typedef {object} PullRequest
 * @property {string} target the absolute-form target the mux is sent
 * @property {Readonly<Record<string, string>>} headers
 * @property {string} body
 */

/**
 * The pull request's request: POST to the mux in absolute form, its body the
 * JSON JSON.stringify writes (the one spelling the kernel's github-pulls route
 * reads), its head aos/<run>/<branch> and its base `base`.
 * @param {PublishArgs} args
 * @param {string} base
 * @returns {PullRequest}
 */
export function pullRequest(args, base) {
  const body = JSON.stringify({ title: args.title, head: headOf(args), base, body: args.body })
  return Object.freeze({
    target: `http://${args.apiHost}/repos/${args.repo}/pulls`,
    headers: Object.freeze({
      host: args.apiHost,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
      accept: 'application/vnd.github+json',
      'user-agent': 'aos-publish',
      'x-github-api-version': '2022-11-28',
      connection: 'close',
    }),
    body,
  })
}

/** @param {unknown} text */
function quoted(text) {
  const plain = String(text).replace(/[^\x20-\x7e]/g, ' ')
  return plain.length <= QUOTE_MAX_CHARS ? plain : `${plain.slice(0, QUOTE_MAX_CHARS)}...`
}

/**
 * What a pull request's answer says, as one line: its number and address on
 * 201, and otherwise its status and the host's own message, quoted printable
 * and cut.
 * @param {number} status
 * @param {string} text
 * @returns {{ readonly ok: boolean, readonly line: string }}
 */
export function pullAnswer(status, text) {
  /** @type {unknown} */
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    parsed = undefined
  }
  const field = (/** @type {string} */ name) => (typeof parsed === 'object' && parsed !== null ? Reflect.get(parsed, name) : undefined)
  if (status === 201) {
    const number = field('number')
    const url = field('html_url')
    if (Number.isSafeInteger(number) && typeof url === 'string' && /^https:\/\/[\x21-\x7e]{1,2048}$/.test(url)) {
      return { ok: true, line: `opened pull request #${String(number)}: ${url}` }
    }
    return { ok: true, line: 'opened the pull request (HTTP 201); its answer named no number and address' }
  }
  const message = field('message')
  return { ok: false, line: `the pull request was not opened: HTTP ${String(status)}${typeof message === 'string' ? `: ${quoted(message)}` : ''}` }
}

// ── git, and the mux ────────────────────────────────────────────────────────

/**
 * @typedef {object} GitResult
 * @property {number | null} code
 * @property {string} stdout
 * @property {string} stderr
 */

/**
 * @typedef {(command: string, args: readonly string[], options: SpawnOptions) => ChildProcess} SpawnProcess
 */

/** @type {SpawnProcess} */
const spawnProcess = (command, args, options) => spawnChild(command, [...args], options)

/** A stream's first OUTPUT_MAX_BYTES, kept as they come, and the rest dropped. */
function capture() {
  /** @type {Buffer[]} */
  const chunks = []
  let bytes = 0
  return {
    keep: (/** @type {Buffer} */ chunk) => {
      const room = OUTPUT_MAX_BYTES - bytes
      if (room <= 0) return
      const part = chunk.subarray(0, room)
      chunks.push(part)
      bytes += part.length
    },
    text: () => Buffer.concat(chunks).toString('utf8'),
  }
}

/** The options every git is spawned with: no stdin, no shell, in /tmp, GIT_ENV whole. */
export const GIT_SPAWN_OPTIONS = Object.freeze({ cwd: '/tmp', env: GIT_ENV, stdio: /** @type {const} */ (['ignore', 'pipe', 'pipe']), shell: false })

/**
 * Run the image's git with `args`, and what it said, each stream cut to
 * OUTPUT_MAX_BYTES. Never rejects: a git that could not start ends with no
 * code and says why on stderr. `spawn` is node's spawn but for a test.
 * @param {readonly string[]} args
 * @param {SpawnProcess} [spawn]
 * @returns {Promise<GitResult>}
 */
export function runGit(args, spawn = spawnProcess) {
  return new Promise((resolve) => {
    /** @type {ChildProcess} */
    let child
    try {
      child = spawn(GIT, [...args], { ...GIT_SPAWN_OPTIONS, env: { ...GIT_ENV }, stdio: [...GIT_SPAWN_OPTIONS.stdio] })
    } catch (error) {
      resolve({ code: null, stdout: '', stderr: `git did not start: ${quoted(error instanceof Error ? error.message : error)}` })
      return
    }
    const out = capture()
    const err = capture()
    child.stdout?.on('data', out.keep)
    child.stderr?.on('data', err.keep)
    let settled = false
    child.once('error', (error) => {
      if (settled) return
      settled = true
      resolve({ code: null, stdout: out.text(), stderr: `${err.text()}git did not start: ${quoted(error.message)}` })
    })
    child.once('close', (code) => {
      if (settled) return
      settled = true
      resolve({ code, stdout: out.text(), stderr: err.text() })
    })
  })
}

/**
 * @typedef {object} Answer
 * @property {number} status
 * @property {string} text
 */

/**
 * @typedef {(options: RequestOptions, callback: (res: IncomingMessage) => void) => ClientRequest} HttpRequest
 */

/** @type {HttpRequest} */
const requestProcess = (options, callback) => httpRequest(options, callback)

/**
 * The options the pull request is sent to the mux with: the mux's address,
 * the absolute-form target as the path, its own Host header (setHost false),
 * and an agent of its own (agent false), never the global one that
 * NODE_USE_ENV_PROXY configures.
 * @param {PullRequest} request
 * @returns {RequestOptions}
 */
export function muxRequestOptions(request) {
  return { host: MUX_HOST, port: MUX_PORT, method: 'POST', path: request.target, headers: { ...request.headers }, setHost: false, agent: false }
}

/**
 * Send `request` to the mux and read its answer, at most OUTPUT_MAX_BYTES of
 * it. Rejects when no answer comes. `send` is node's http.request but for a
 * test.
 * @param {PullRequest} request
 * @param {HttpRequest} [send]
 * @returns {Promise<Answer>}
 */
export function postThroughMux(request, send = requestProcess) {
  return new Promise((resolve, reject) => {
    const req = send(muxRequestOptions(request), (res) => {
      const kept = capture()
      res.on('data', kept.keep)
      res.once('end', () => resolve({ status: res.statusCode ?? 0, text: kept.text() }))
      res.once('error', reject)
    })
    req.once('error', reject)
    req.end(request.body)
  })
}

// ── publish ─────────────────────────────────────────────────────────────────

/**
 * @typedef {object} PublishDeps
 * @property {(args: readonly string[]) => Promise<GitResult>} git
 * @property {(request: PullRequest) => Promise<Answer>} post
 * @property {Files['readFile']} readFile
 * @property {Files['isDirectory']} isDirectory
 * @property {() => string} scratch a new, empty directory of this run's own under /tmp
 * @property {(path: string, text: string) => void} writeFile a file that is not there yet
 * @property {(text: string) => void} out
 * @property {(text: string) => void} err
 */

/**
 * Publish: steps 1 to 5 of the header, each only once the one before it
 * succeeded. Resolves with the exit code (PUBLISH_EXIT); never rejects.
 * @param {PublishArgs} args
 * @param {PublishDeps} deps
 * @returns {Promise<number>}
 */
export async function publish(args, deps) {
  const fail = (/** @type {string} */ line) => {
    deps.err(`publish: ${line}\n`)
    return PUBLISH_EXIT.failed
  }
  /** @param {string} what @param {readonly string[]} argv */
  const git = async (what, argv) => {
    const result = await deps.git(argv)
    if (result.code === 0) return { ok: /** @type {const} */ (true), stdout: result.stdout }
    return { ok: /** @type {const} */ (false), line: `${what} failed (git exited ${String(result.code)}): ${quoted(result.stderr.trim())}` }
  }
  try {
    const head = workspaceHead(deps)
    if ('refusal' in head) return fail(head.refusal)
    const shallow = workspaceShallow(deps)
    if ('refusal' in shallow) return fail(shallow.refusal)

    const dir = deps.scratch()
    const init = await git('making the publisher\'s own repository', [...PROTECTED, 'init', '--bare', '--quiet', '--template=', dir])
    if (!init.ok) return fail(init.line)
    deps.writeFile(`${dir}/objects/info/alternates`, `${WORKSPACE}/.git/objects\n`)
    if (shallow.shallow !== undefined) deps.writeFile(`${dir}/shallow`, shallow.shallow)

    const remote = remoteOf(args)
    const listed = await git('reading the default branch', [...PROTECTED, `--git-dir=${dir}`, 'ls-remote', '--symref', remote, 'HEAD'])
    if (!listed.ok) return fail(listed.line)
    const base = defaultBranch(listed.stdout)
    if (base === undefined) return fail(`${args.repo} names no default branch in the kernel's spelling`)

    const ref = `refs/heads/${headOf(args)}`
    const pushed = await git('the push', [...PROTECTED, `--git-dir=${dir}`, 'push', '--porcelain', '--no-verify', '--no-recurse-submodules', remote, `${head.oid}:${ref}`])
    if (!pushed.ok) return fail(pushed.line)
    deps.out(`pushed ${head.oid} to ${ref} of ${args.repo} on ${args.gitHost}\n`)

    const answer = await deps.post(pullRequest(args, base))
    const said = pullAnswer(answer.status, answer.text)
    if (!said.ok) return fail(said.line)
    deps.out(`${said.line} (from ${headOf(args)} into ${base})\n`)
    return PUBLISH_EXIT.ok
  } catch (error) {
    return fail(quoted(error instanceof Error ? error.message : error))
  }
}

/** @param {string} path */
function readOwnFile(path) {
  try {
    return lstatSync(path).isFile() ? readFileSync(path, 'utf8') : undefined
  } catch {
    return undefined
  }
}

/** @param {string} path */
function isOwnDirectory(path) {
  try {
    return lstatSync(path).isDirectory()
  } catch {
    return false
  }
}

/** The deps main() runs publish() with: the real git, the mux, the container's own files. @type {PublishDeps} */
export const SYSTEM_DEPS = Object.freeze({
  git: (/** @type {readonly string[]} */ args) => runGit(args),
  post: (/** @type {PullRequest} */ request) => postThroughMux(request),
  readFile: readOwnFile,
  isDirectory: isOwnDirectory,
  scratch: () => mkdtempSync('/tmp/aos-publish-'),
  writeFile: (/** @type {string} */ path, /** @type {string} */ text) => writeFileSync(path, text, { flag: 'wx', mode: 0o600 }),
  out: (/** @type {string} */ text) => void process.stdout.write(text),
  err: (/** @type {string} */ text) => void process.stderr.write(text),
})

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args === undefined) {
    process.stderr.write(USAGE)
    process.exit(PUBLISH_EXIT.usage)
  }
  process.exit(await publish(args, SYSTEM_DEPS))
}

// Run only as the program node was started with, never when a test imports
// the module (as the mux does).
if (import.meta.main) await main()
