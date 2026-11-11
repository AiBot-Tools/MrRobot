// What scripts/build-worker-image.sh reads before it asks docker anything
// (egress plan I1). Operator-only, run by that script from the repository
// root:
//
//   node --import tsx scripts/worker-image.ts
//
// It reads two files and writes none. images/worker/Dockerfile must have one
// FROM, the base the operator chose (WORKER_BASE) pinned by a real digest:
// a tag alone is whatever the registry serves that day, and a placeholder
// digest (one hex digit 64 times, as a FROM is left when its digest is not
// known yet) would fail the pull only after the operator had started. The
// file is read as BuildKit reads it, continued lines joined (readDockerfile,
// which test/config-files.test.ts reads it with as well), so the FROM checked
// is the one the build uses; a parser directive, a reading that is not
// certain, and any character but printable ASCII, tab and newline are
// refused (readBase). And
// config/kernel.yaml, through the kernel's own parser and AOS_DATA_DIR as the
// daemon reads it (src/main.ts), for what the kernel's docker calls use:
// each domain's dockerHost and the DOCKER_CONFIG beside them (defaultDriver
// in src/kernel.ts), and the tag to give the image (sandbox.image). A
// dockerHost that is the default Colima profile's socket is refused, since
// that profile shares $HOME writable, and so is one socket for both domains,
// which would build and load in one VM: each socket is judged as every way
// the Mac reaches it, its path normalized (`//`, `.` and `..`) and
// lower-cased (APFS), the path a symlink leads to, and the file itself by
// device and inode, so another spelling of one socket, or a link to it, is
// that socket (socketsAreOne, namesDefaultColima). A path holding a space or
// anything but printable ASCII is refused before that (PRINTABLE_PATH): the
// docker CLI may trim white space from DOCKER_HOST, and the socket judged
// would then not be the one it connects to. Any other socket is used as
// kernel.yaml names it, as the kernel uses it for every run. It prints them
// as KEY=value lines (planText), or names what is wrong on stderr and exits
// 1, and the build script stops there, before any docker command.
//
// It reads no .env and no credential: the build needs none. The base is
// pulled anonymously, by digest, by the trusted VM's daemon. Like the daemon,
// it refuses a tree a falsify run holds.

import { readFileSync, realpathSync } from 'node:fs'
import { join, posix, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

import { foldName, homeDirectory, identify, type Identify } from '../src/agents/protected.js'
import { parseKernelConfig, type KernelConfig } from '../src/config.js'
import { ConfigError } from '../src/errors.js'
import { falsifyRefusal } from '../src/falsify-hold.js'
import { isImageId } from '../src/sandbox/limits.js'

/** The base the operator chose on 2026-11-09, by name: the FROM pins it by digest. */
export const WORKER_BASE = 'node:24-bookworm-slim'

/** Where the worker image's build context and Dockerfile live, from the repository root. */
export const WORKER_CONTEXT = 'images/worker'

/** The one FROM a worker Dockerfile may have: WORKER_BASE by a sha256 digest, and nothing beside it. */
const PINNED_FROM = /^FROM node:24-bookworm-slim@(sha256:[0-9a-f]{64})$/

/** A digest that is one hex digit 64 times: a placeholder, not one any registry serves. */
const PLACEHOLDER = /^sha256:([0-9a-f])\1{63}$/

/**
 * Go's unicode.IsSpace, which BuildKit's Dockerfile parser strips and trims
 * by: ASCII's six, U+0085, U+00A0 and the rest of Unicode's White_Space.
 * JavaScript's \s less U+FEFF (which Go keeps) and plus U+0085 (which \s
 * lacks). A character class, to build patterns from.
 */
export const GO_SPACE = '[\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]'

/**
 * A syntax directive, in either comment style BuildKit's DetectSyntax reads:
 * `# syntax=` and the C-style `// syntax=`, case-insensitively.
 */
const SYNTAX_DIRECTIVE = /^(?:#|\/\/)\s*syntax\s*=/i

/**
 * A Dockerfile's lines as BuildKit's parser reads them: split at \n by its
 * scanner, which gives no empty line after a last \n, every \r at a line's
 * end dropped (trimNewline trims them all, not only the one a CRLF ends
 * with), and one byte-order mark off line 1.
 */
export function dockerfileLines(text: string): string[] {
  const lines = text.split('\n')
  if (lines.length > 1 && lines.at(-1) === '') lines.pop()
  return lines.map((l, n) => (n === 0 ? l.replace(/^\uFEFF/, '') : l).replace(/\r+$/, ''))
}

/** One instruction as BuildKit's parser reads it: its keyword upper-cased, its arguments, and the whole of it, continuations joined. */
export interface DockerInstruction {
  readonly keyword: string
  readonly args: string
  /** The instruction as one line, its continuations joined and its edges trimmed: what PINNED_FROM reads. */
  readonly text: string
}

/** What readDockerfile reads, and the places where how BuildKit reads it is not certain enough to build on. */
export interface DockerfileReading {
  readonly steps: readonly DockerInstruction[]
  /** The lines (1-based) that are empty inside a continued instruction, which BuildKit skips, warning that it will become an error. */
  readonly emptyContinued: readonly number[]
  /** The lines (1-based) whose continuing `\` has a space or tab after it: which of them the join keeps is not checked against BuildKit here. */
  readonly spacedContinued: readonly number[]
  /** The last line continues an instruction the file never ends (BuildKit reads what it has, as one instruction, as does this). */
  readonly unterminated: boolean
}

/**
 * A Dockerfile as BuildKit's parser reads it (the classic builder uses the
 * same parser), with `\` as the escape, which a parser directive could change
 * and readBase refuses one for: a line's leading white space (GO_SPACE) is
 * stripped when it starts an instruction, a comment line is dropped, inside a
 * continued instruction too, and a line ending in `\` is joined to the next
 * as it stands, the white space before the `\` and the next line's indent
 * kept and nothing put between them. The keyword ends at the first ASCII
 * space, tab, VT, FF or CR, and is upper-cased; its arguments are trimmed. An
 * empty line inside a continued instruction BuildKit skips, warning that it
 * will become an error, and joins the line after it on: so does this, saying
 * on which lines it did. An instruction the file ends inside is read as it
 * stands, as BuildKit reads it.
 */
export function readDockerfile(text: string): DockerfileReading {
  const steps: DockerInstruction[] = []
  const emptyContinued: number[] = []
  const spacedContinued: number[] = []
  const lead = new RegExp(`^${GO_SPACE}+`)
  const edges = new RegExp(`^${GO_SPACE}+|${GO_SPACE}+$`, 'g')
  const push = (whole: string): void => {
    const joined = whole.replace(edges, '')
    if (joined === '') return
    const at = joined.search(/[\t\v\f\r ]/)
    steps.push({ keyword: (at === -1 ? joined : joined.slice(0, at)).toUpperCase(), args: at === -1 ? '' : joined.slice(at).replace(edges, ''), text: joined })
  }
  let pending: string | undefined
  for (const [n, raw] of dockerfileLines(text).entries()) {
    const stripped = raw.replace(lead, '')
    if (stripped.startsWith('#')) continue
    if (stripped === '') {
      if (pending !== undefined) emptyContinued.push(n + 1)
      continue
    }
    const line = pending === undefined ? stripped : raw
    const continued = /\\[ \t]*$/.exec(line)
    if (continued !== null) {
      if (continued[0].length > 1) spacedContinued.push(n + 1)
      pending = (pending ?? '') + line.slice(0, continued.index)
      continue
    }
    push((pending ?? '') + line)
    pending = undefined
  }
  if (pending !== undefined) push(pending)
  return { steps, emptyContinued, spacedContinued, unterminated: pending !== undefined }
}

/**
 * Every line BuildKit could read as a parser directive (`escape`, `syntax`,
 * `check`), counted generously. Its parser reads them from line 1, after one
 * byte-order mark and any leading white space, and stops at the first line
 * that is not one; its syntax detection (DetectSyntax) first skips a shebang
 * on line 1, and also reads `// key=value`. Any key counts, valid or not, and
 * reading goes on past one that is not: one more refusal costs nothing.
 */
export function parserDirectives(text: string): string[] {
  const lines = dockerfileLines(text).map((l) => l.replace(new RegExp(`^${GO_SPACE}+`), ''))
  const out: string[] = []
  for (const line of lines.slice(lines[0]?.startsWith('#!') === true ? 1 : 0)) {
    if (!/^(?:#|\/\/)\s*[A-Za-z][A-Za-z0-9]*\s*=/.test(line)) break
    out.push(line)
  }
  return out
}

/** Each character of a text that is not printable ASCII, a tab or a newline, once, in order, as U+XXXX. */
export function notPlainAscii(text: string): string[] {
  const found = [...text.matchAll(/[^\t\n\x20-\x7e]/gu)].map((m) => `U+${(m[0].codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`)
  return [...new Set(found)]
}

/**
 * A docker socket path the plan can judge: absolute, every character
 * printable ASCII, no space. The docker CLI is understood to trim white space
 * from DOCKER_HOST before it parses it (opts.ParseHost, with Go's
 * strings.TrimSpace, which trims U+0085, U+00A0, U+2028 and U+3000 as well as
 * ASCII space and tab; not checked against its source here), so a path with
 * a space or such a character at its end would be judged here as a socket
 * that is not there while docker connected to the one without it, the
 * default profile's included. Any character outside printable ASCII is
 * refused rather than reasoned about one at a time.
 */
const PRINTABLE_PATH = /^\/[\x21-\x7e]+$/

/** What the build script needs, every value one a shell line can carry. */
export interface WorkerImagePlan {
  /** The worker Dockerfile's base, as its FROM names it: WORKER_BASE@sha256:<digest>. */
  readonly base: string
  /** sandbox.image: the tag the build gives the image. A name only: no run executes it. */
  readonly image: string
  /** The trusted domain's DOCKER_HOST, where the image is built. */
  readonly trusted: string
  /** The hostile domain's DOCKER_HOST, which only loads what trusted built. */
  readonly hostile: string
  /** The DOCKER_CONFIG the kernel's docker calls use: <dataDir>/docker. */
  readonly dockerConfig: string
}

/**
 * A worker Dockerfile's base, or why it cannot be built from, read as
 * BuildKit reads the file (readDockerfile), so that the FROM checked here is
 * the one the build uses: exactly one FROM instruction, continuations joined,
 * which is WORKER_BASE pinned by a real digest. Refused before that: a parser
 * directive (escape would change which lines join, syntax has BuildKit pull a
 * frontend image by its tag), a syntax directive on any line, not only where
 * BuildKit reads one, and a file whose reading is not certain: an empty line
 * inside a continued instruction, a `\` with a space or tab after it, or a
 * last instruction left open. And after it, any character that is not
 * printable ASCII, a tab or a newline, so that how BuildKit's Go reads any
 * other never decides what is built.
 */
function readBase(dockerfile: string): { readonly base: string } | { readonly why: string } {
  const file = `${WORKER_CONTEXT}/Dockerfile`
  const directive = parserDirectives(dockerfile)[0]
  if (directive !== undefined) {
    return { why: `${file} starts with a parser directive, ${escaped(directive)}: escape changes which lines BuildKit joins, and syntax has it pull a frontend image by its tag; remove it` }
  }
  const lead = new RegExp(`^${GO_SPACE}+`)
  const lines = dockerfileLines(dockerfile).map((line) => line.replace(lead, ''))
  if (lines.some((line) => SYNTAX_DIRECTIVE.test(line))) {
    return { why: `${file} has a syntax directive, which has BuildKit pull a frontend image by its tag: remove it` }
  }
  const { steps, emptyContinued, spacedContinued, unterminated } = readDockerfile(dockerfile)
  if (emptyContinued.length > 0) {
    return { why: `${file} has an empty line inside a continued instruction, on line ${emptyContinued.join(', ')}: BuildKit joins the line after it on, with a warning that this will become an error; end the instruction or remove the line` }
  }
  if (spacedContinued.length > 0) {
    return { why: `${file} has a \`\\\` with a space or tab after it, on line ${spacedContinued.join(', ')}: what BuildKit joins there is not certain; remove what follows the \`\\\`` }
  }
  if (unterminated) {
    return { why: `${file} ends inside a continued line: its last line ends in \`\\\`` }
  }
  const froms = steps.filter((step) => step.keyword === 'FROM')
  if (froms.length !== 1) {
    return {
      why: `${file} has ${String(froms.length)} FROM lines; it must have exactly one, FROM ${WORKER_BASE}@sha256:<digest>`,
    }
  }
  const from = froms[0]?.text ?? ''
  const pinned = PINNED_FROM.exec(from)
  if (pinned === null) {
    return {
      why:
        `${file}'s base is ${escaped(from)}: it must be exactly FROM ${WORKER_BASE}@sha256:<64 lower-case hex>, ` +
        'the base the operator chose pinned by its digest, with no tag-only name, --platform or stage name',
    }
  }
  const digest = pinned[1] ?? ''
  if (PLACEHOLDER.test(digest)) {
    return {
      why:
        `${file}'s base digest ${digest} is a placeholder, not a digest any registry serves: put in the ` +
        `digest of ${WORKER_BASE}'s index (docker buildx imagetools inspect ${WORKER_BASE} prints it as Digest)`,
    }
  }
  const stray = notPlainAscii(dockerfile)
  if (stray.length > 0) {
    return { why: `${file} holds ${stray.join(', ')}: it may hold only printable ASCII, tabs and newlines, so that no other character's reading decides what is built` }
  }
  return { base: `${WORKER_BASE}@${digest}` }
}

/** Why a worker Dockerfile's base cannot be built from (readBase), or undefined when it can. */
export function baseProblem(dockerfile: string): string | undefined {
  const read = readBase(dockerfile)
  return 'why' in read ? read.why : undefined
}

/**
 * The sandbox.image tag, or why it cannot be one: a docker name with an
 * explicit tag, lower-case path components, and nothing that docker could
 * read as an option or as an image id.
 */
function imageProblem(image: string): string | undefined {
  const name = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/
  if (!name.test(image) || isImageId(image) || image.startsWith('sha256:')) {
    return `sandbox.image ${JSON.stringify(image)} is not a name:tag the build can give the image (as shipped, aos-worker:0.0.1)`
  }
  return undefined
}

/** What the plan asks the Mac's filesystem about a socket path. */
export interface SocketFs {
  /** The path every symlink in it leads to, as the OS resolves it, or undefined when nothing is there. */
  readonly realpath: (path: string) => string | undefined
  /** The file's device and inode, through symlinks, or undefined when nothing is there. */
  readonly identify: Identify
  /** The home directory whose .colima holds the default profile's sockets: the one `~` in a dockerHost expands to. */
  readonly home: string
}

/**
 * The Mac's own answers, where the build script runs beside the sockets.
 * realpath(3) rather than Node's realpath, which reads a `..` before the
 * symlink it follows. A path that is not there is undefined: no daemon
 * answers on it, so no docker call reaches one through it. Any other failure
 * (a symlink loop, a directory it may not search) is refused rather than
 * guessed past.
 */
export function macSockets(home: string = homeDirectory()): SocketFs {
  return {
    realpath: (path) => {
      try {
        return realpathSync.native(path)
      } catch (e: unknown) {
        const code = (e as NodeJS.ErrnoException).code
        if (code === 'ENOENT' || code === 'ENOTDIR') return undefined
        throw new ConfigError(`the docker socket ${path} cannot be resolved (${e instanceof Error ? e.message : String(e)}), so it cannot be told from the default Colima profile's`)
      }
    },
    identify,
    home,
  }
}

/**
 * Every spelling by which the Mac reaches a socket path: the path as written
 * and the one its symlinks lead to, each normalized (`//`, `.` and `..`, read
 * as written: refusing one more spelling costs a rename) and case-folded, as
 * APFS opens every case of a name and realpath may keep the case typed.
 */
function spellings(path: string, fs: SocketFs): string[] {
  const real = fs.realpath(path)
  return [...new Set([path, ...(real === undefined ? [] : [real])].map((p) => foldName(posix.normalize(p))))]
}

/**
 * The default Colima profile's sockets, in both of their places under the
 * home directory. That Colima makes the second, ~/.colima/docker.sock, for
 * the default profile alone (as a socket or a link to the first) is not
 * checked against Colima 0.10.3: README's NEEDS VALIDATION row for the image
 * has the operator look before the first build, since a link there to the
 * trusted or hostile socket would refuse the shipped kernel.yaml.
 */
function defaultSockets(fs: SocketFs): string[] {
  return [join(fs.home, '.colima', 'default', 'docker.sock'), join(fs.home, '.colima', 'docker.sock')]
}

/**
 * How a unix:// docker host is the default Colima profile's socket, or
 * undefined when it is not: by a spelling of it, wherever its .colima is, or
 * as the same file as one of the default profile's sockets under the home
 * directory (a hard link, or the target of a symlink spelled otherwise).
 */
export function namesDefaultColima(dockerHost: string, fs: SocketFs): string | undefined {
  const path = dockerHost.slice('unix://'.length)
  for (const spelling of spellings(path, fs)) {
    if (spelling.endsWith('/.colima/default/docker.sock') || spelling.endsWith('/.colima/docker.sock')) return `it reaches ${spelling}`
  }
  const own = fs.identify(path)
  if (own === undefined) return undefined
  for (const socket of defaultSockets(fs)) {
    if (fs.identify(socket) === own) return `it is the same file as ${socket}`
  }
  return undefined
}

/** True when two unix:// docker hosts reach one socket: a spelling in common, or the same file by device and inode. */
export function socketsAreOne(a: string, b: string, fs: SocketFs): boolean {
  const [pathA, pathB] = [a.slice('unix://'.length), b.slice('unix://'.length)]
  const ofB = spellings(pathB, fs)
  if (spellings(pathA, fs).some((s) => ofB.includes(s))) return true
  const idA = fs.identify(pathA)
  return idA !== undefined && idA === fs.identify(pathB)
}

/** A string as JSON, every character outside printable ASCII escaped, so that an error shows what it names. */
function escaped(value: string): string {
  return JSON.stringify(value).replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
}

/**
 * The build's plan from a Dockerfile's text and a parsed kernel.yaml.
 * @throws {ConfigError} naming the first thing the build cannot proceed past.
 */
export function planFrom(dockerfile: string, config: KernelConfig, fs: SocketFs = macSockets()): WorkerImagePlan {
  const base = readBase(dockerfile)
  if ('why' in base) throw new ConfigError(base.why)
  const image = imageProblem(config.sandbox.image)
  if (image !== undefined) throw new ConfigError(image)
  const { trusted, hostile } = config.sandbox.domains
  for (const [domain, host] of [['trusted', trusted.dockerHost], ['hostile', hostile.dockerHost]] as const) {
    if (!PRINTABLE_PATH.test(host.slice('unix://'.length))) {
      throw new ConfigError(
        `sandbox.domains.${domain}.dockerHost ${escaped(host)} has a space or a character that is not printable ASCII in its path: ` +
          'the docker CLI may trim white space from DOCKER_HOST, so the socket it connects to may not be the one judged here; spell the path in printable ASCII, with no space',
      )
    }
    const how = namesDefaultColima(host, fs)
    if (how !== undefined) {
      throw new ConfigError(
        `sandbox.domains.${domain}.dockerHost ${host} is the default Colima profile's socket, which shares $HOME writable (${how}): ` +
          'name that domain\'s own profile (scripts/colima-up.sh starts trusted and hostile)',
      )
    }
  }
  if (socketsAreOne(trusted.dockerHost, hostile.dockerHost, fs)) {
    throw new ConfigError(
      `sandbox.domains.trusted.dockerHost ${trusted.dockerHost} and sandbox.domains.hostile.dockerHost ${hostile.dockerHost} are one socket: ` +
        'each domain is its own VM, and the image is built in trusted and loaded into hostile',
    )
  }
  return {
    base: base.base,
    image: config.sandbox.image,
    trusted: trusted.dockerHost,
    hostile: hostile.dockerHost,
    dockerConfig: join(config.dataDir, 'docker'),
  }
}

/** The plan as the build script reads it: one KEY=value line each, in this order. */
export function planText(plan: WorkerImagePlan): string {
  const lines: [string, string][] = [
    ['BASE', plan.base],
    ['IMAGE', plan.image],
    ['TRUSTED_DOCKER_HOST', plan.trusted],
    ['HOSTILE_DOCKER_HOST', plan.hostile],
    ['DOCKER_CONFIG', plan.dockerConfig],
  ]
  for (const [key, value] of lines) {
    if (value === '' || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new ConfigError(`${key} is empty or holds a control character, which one line cannot carry: ${JSON.stringify(value)}`)
    }
  }
  return lines.map(([key, value]) => `${key}=${value}\n`).join('')
}

/** Read the repository's worker Dockerfile and kernel.yaml as the daemon would, and plan the build. */
export function workerImagePlan(repoRoot: string, env: Readonly<Record<string, string | undefined>>): WorkerImagePlan {
  const dockerfile = readFileSync(join(repoRoot, WORKER_CONTEXT, 'Dockerfile'), 'utf8')
  const dataDir = env['AOS_DATA_DIR']
  const config = parseKernelConfig(parseYaml(readFileSync(join(repoRoot, 'config', 'kernel.yaml'), 'utf8')), {
    repoRoot,
    ...(dataDir === undefined ? {} : { dataDirOverride: dataDir }),
  })
  return planFrom(dockerfile, config)
}

// Only when run as the entry point. Compared as resolved paths rather than by
// suffix: a suffix test matches any file whose name happens to end the same way.
const entry = process.argv[1]
if (entry !== undefined && fileURLToPath(import.meta.url) === resolve(entry)) {
  try {
    if (process.argv.length > 2) throw new ConfigError('scripts/worker-image.ts takes no arguments')
    const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
    // A falsify run's tree may hold a planted bug in src/, config.ts's
    // parsing included (src/falsify-hold.ts), as the daemon refuses it.
    const held = falsifyRefusal(repoRoot)
    if (held !== undefined) throw new ConfigError(held)
    process.stdout.write(planText(workerImagePlan(repoRoot, process.env)))
  } catch (e: unknown) {
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`)
    process.exitCode = 1
  }
}
