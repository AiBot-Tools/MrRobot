// The egress binding profiles (egress plan E3): what a request to a bound
// host may be, read from the request alone.
//
// Contract: a worker's request reaches a host that holds a credential binding
// only through one of three route profiles, each a closed set of request
// shapes on a bound repository (RepoSlug), and nothing a profile does not name
// is a route at all. Token-returning paths, the web UI, every other API
// endpoint and every other repository's paths are denied because nothing
// names them:
//
//   git-fetch     GET  /<owner>/<repo>[.git]/info/refs?service=git-upload-pack
//                 POST /<owner>/<repo>[.git]/git-upload-pack
//   git-push      GET  /<owner>/<repo>[.git]/info/refs?service=git-receive-pack
//                 POST /<owner>/<repo>[.git]/git-receive-pack, whose pkt-line
//                 command list (at most MAX_COMMAND_LIST bytes, read before the
//                 pack) only creates or updates refs under
//                 refs/heads/aos/<runId>/: no delete, no signed push, no
//                 capability but the few a push needs (PUSH_CAPABILITIES, read
//                 as name[=value], so push-options=1 is push options), and no
//                 Content-Encoding, so the bytes judged are the bytes the host
//                 reads
//   github-pulls  POST /repos/<owner>/<repo>/pulls, a JSON body of at most
//                 MAX_PULLS_BODY bytes in its one canonical spelling, whose
//                 head is a branch under aos/<runId>/ of the same repository
//                 (never a cross-repository owner:branch)
//
// The request target is read here too, and refused rather than normalised:
// whatever a peer might read another way is not sent at all. Only absolute
// form (http:// or https://, lower-case) is a target; userinfo is a second
// host, refused with the host a URL parser reads past its last `@` (or why it
// is none, namedHost), so a log row says where such a request was headed; the
// host is read before the rest of the target (its length, its characters, a
// fragment, the port and the path), so a target naming an address or a
// special-use name (192.168.5.2:8766, host.lima.internal:8766) is refused for
// its host whatever port it names and whatever follows it, and only an egress
// host on a port other than 443 is refused for the port, which names another
// service than the one dialled; and the path may hold no backslash, no empty
// segment (a double slash), no dot segment, no percent-encoded slash, dot,
// backslash, percent or control character, and nothing that does not decode
// to UTF-8 (an overlong encoding is one more spelling of a dot or a slash).
// The query is carried as it came, and a route admits only the one it names.
//
// A refusal carries a reason from ROUTE_REFUSALS and a clause that never
// holds the input: a worker's request is attacker-chosen text.
//
// Pure: no I/O and no imports but zod and host.ts. decide() (policy.ts)
// composes these with the grant; nothing here knows which profiles a run was
// granted.

import { z } from 'zod'

import { parseEgressHost, type EgressHost, type HostRefusal } from './host.js'

/** The binding profiles. Stable: grants, config and decisions name these. */
export const EGRESS_PROFILES = Object.freeze(['git-fetch', 'git-push', 'github-pulls'] as const)
export type EgressProfile = (typeof EGRESS_PROFILES)[number]
export const EgressProfileName = z.enum(EGRESS_PROFILES)

/** Why a request matches no route, or a route refuses it. Stable: decisions and their log rows name these. */
export const ROUTE_REFUSALS = Object.freeze([
  'target',
  'not-a-host',
  'port',
  'second-host',
  'path',
  'no-route',
  'method',
  'query',
  'push-commands',
  'push-ref',
  'push-delete',
  'pulls-body',
  'pulls-head',
] as const)
export type RouteRefusal = (typeof ROUTE_REFUSALS)[number]

export interface RouteRefused {
  readonly ok: false
  readonly reason: RouteRefusal
  /** A clause; never holds the input. */
  readonly why: string
  /** host.ts's reason, when the target's host (past any userinfo) is no EgressHost. */
  readonly hostRefusal?: HostRefusal
  /** The target's host (past any userinfo), when parseTarget read one before it refused the userinfo, the port or the path. */
  readonly host?: EgressHost
}

/** What a refusal knows of the target beyond its reason: why its host was none, or the host it read. */
type RefusedAt = { readonly hostRefusal: HostRefusal } | { readonly host: EgressHost }

function refused(reason: RouteRefusal, why: string, at?: RefusedAt): RouteRefused {
  return Object.freeze(at === undefined ? { ok: false as const, reason, why } : { ok: false as const, reason, why, ...at })
}

/** Where a refused request was headed: the host its authority names, or host.ts's reason it names none. */
export type NamedHost = { readonly host: EgressHost } | { readonly hostRefusal: HostRefusal }

/**
 * An authority (`host[:port]`) split as parseTarget reads one: brackets or a
 * second colon are an IPv6 literal, which host.ts refuses whole, so the port
 * is split off only after the one colon of a name or an IPv4 address.
 */
function splitAuthority(authority: string): { readonly hostText: string; readonly port: string | undefined } {
  if (authority.includes('[') || authority.split(':').length !== 2) return { hostText: authority, port: undefined }
  const colon = authority.indexOf(':')
  return { hostText: authority.slice(0, colon), port: authority.slice(colon + 1) }
}

/**
 * The host an authority names, for a refusal to record where the request was
 * headed, never to admit one: a CONNECT's authority (policy.ts), or a
 * target's whose userinfo is refused. Read as a URL parser reads it, past the
 * last `@`, without its port, and judged by host.ts: its EgressHost, or the
 * reason it is none (ip-literal for 192.168.5.2:8766, special-use for
 * host.lima.internal:8766), so a probe of the Mac's loopback in either
 * spelling is recorded as one. Text that is no authority (a slash, a `?`, a
 * `#`: an absolute-form CONNECT, say) names nothing.
 */
export function namedHost(authority: string): NamedHost | undefined {
  if (/[/?#]/.test(authority)) return undefined
  const { hostText } = splitAuthority(authority.slice(authority.lastIndexOf('@') + 1))
  const parsed = parseEgressHost(hostText)
  return parsed.ok ? { host: parsed.host } : { hostRefusal: parsed.reason }
}

/** The one port egress dials (upstream.ts); a target naming any other names another service. */
export const ROUTE_PORT = '443'

/** The upstream's bound on an origin-form path and query (upstream.ts MAX_PATH). */
export const MAX_PATH = 8192

/** A target longer than this is no request a route has a use for: a path at MAX_PATH and the longest DNS name, with room for the scheme and a port. */
export const MAX_TARGET = MAX_PATH + 300

/** The most a push's command list may take, flush included: the bytes the session reads and decide() judges before the pack. */
export const MAX_COMMAND_LIST = 65_536

/** The most a pull request's JSON body may take: the whole of it is read and judged. */
export const MAX_PULLS_BODY = 65_536

/** git's own bound on one pkt-line, its four length digits included. */
const MAX_PKT = 65_520

/** The branch every push lands under, with the run's id after it: refs/heads/aos/<runId>/<branch>. */
export const PUSH_ROOT = 'aos'

/**
 * A run's id as it may stand in a ref: the kernel's `run_<ms>_<base36>`, and
 * nothing git would read as two components, a dot rule or an option.
 */
export const RUN_REF = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/

/** The branch prefix a run's pushes and pull requests stay under: `aos/<runId>/`. */
export function pushBranchPrefix(runId: string): string {
  return `${PUSH_ROOT}/${runId}/`
}

/** The ref prefix a run's pushes stay under: `refs/heads/aos/<runId>/`. */
export function pushRefPrefix(runId: string): string {
  return `refs/heads/${pushBranchPrefix(runId)}`
}

/**
 * A branch name in a spelling git, a shell and a URL all read the same way:
 * components of letters, digits, dot, underscore and hyphen, none starting
 * with a dot or a hyphen (an option to the script that pushes it), none
 * ending with a dot or `.lock`, no `..`, at most 200 characters. Narrower than
 * git's check_refname_format, never wider.
 */
export function isBranchName(text: string): boolean {
  if (text.length === 0 || text.length > 200 || text.includes('..')) return false
  return text
    .split('/')
    .every((part) => /^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(part) && !part.endsWith('.') && !part.endsWith('.lock'))
}

/** A GitHub owner: a login or organisation, letters, digits and hyphens. */
const OWNER = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/
/** A repository name; `.` and `..` are dot segments, and a name ending in `.git` reads two ways in a git URL. */
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/

function isRepoName(name: string): boolean {
  return REPO_NAME.test(name) && name !== '.' && name !== '..' && !name.toLowerCase().endsWith('.git')
}

/**
 * A bound repository, `owner/name`, in its one spelling: lower-case, because
 * GitHub reads owners and names without case, so `Op/Fixture` and
 * `op/fixture` must never compare unequal. Branded: a grant names only
 * repositories this schema read.
 */
export const RepoSlug = z
  .string()
  .transform((raw, ctx) => {
    const [owner = '', name = '', ...rest] = raw.split('/')
    if (rest.length === 0 && OWNER.test(owner) && isRepoName(name)) return `${owner}/${name}`.toLowerCase()
    ctx.addIssue({ code: 'custom', message: 'not a repository: owner/name, letters, digits, dot, underscore and hyphen, the name not ending in .git' })
    return z.NEVER
  })
  .brand<'RepoSlug'>()
export type RepoSlug = z.output<typeof RepoSlug>

function repoOf(owner: string, name: string): RepoSlug | undefined {
  const parsed = RepoSlug.safeParse(`${owner}/${name}`)
  return parsed.success ? parsed.data : undefined
}

// ── the request target ──────────────────────────────────────────────────────

/** A request target as decide() reads it: absolute form, its host one EgressHost, its path checked. */
export interface ParsedTarget {
  readonly ok: true
  readonly host: EgressHost
  /** As written: none, or ROUTE_PORT. */
  readonly port: string | undefined
  /** Starts with one slash; no query. */
  readonly path: string
  /** After the `?`, as it came; none when the target has no `?`. */
  readonly query: string | undefined
  /** What the upstream sends on its request line: the path, then `?` and the query when there is one. */
  readonly originForm: string
}

const HEX_DIGITS = /^[0-9A-Fa-f]{2}$/

/**
 * The path's percent-encodings, judged by the byte each decodes to: never a
 * slash, a dot, a backslash, a percent (a second decoding) or a control
 * character, and the whole path, decoded, valid UTF-8, which refuses the
 * overlong spellings of all of those.
 */
function checkEncodings(path: string): boolean {
  const bytes: number[] = []
  for (let i = 0; i < path.length; i++) {
    const code = path.charCodeAt(i)
    if (code !== 0x25) {
      bytes.push(code)
      continue
    }
    const hex = path.slice(i + 1, i + 3)
    if (!HEX_DIGITS.test(hex)) return false
    const byte = Number.parseInt(hex, 16)
    if (byte === 0x2f || byte === 0x2e || byte === 0x5c || byte === 0x25 || byte < 0x20 || byte === 0x7f) return false
    bytes.push(byte)
    i += 2
  }
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))
    return true
  } catch {
    return false
  }
}

/**
 * Read a request target, refusing what a peer could read another way. The
 * host is normalised (host.ts); everything else is refused, never rewritten,
 * so the request sent is the request the worker wrote.
 *
 * In absolute form the authority is read first, its userinfo and host before
 * anything after them: where the request was headed is known before its
 * length, its characters, a fragment, its port or its path is judged, so a
 * probe of the Mac's loopback is refused for its host (or its userinfo, with
 * the host past it) whatever else the target holds, and a target in absolute
 * form is refused as `target`, which names no host, only when its host is an
 * egress host. The authority ends at the first `/`, `?` or `#`, so
 * http://github.com#x has the host github.com, as a URL parser reads it.
 */
export function parseTarget(target: string): ParsedTarget | RouteRefused {
  const form = /^(?:http|https):\/\/([^/?#]*)([\s\S]*)$/.exec(target)
  if (form === null) {
    return refused('target', 'the target is not absolute-form http:// or https://: egress routes only a request that names its host')
  }
  const [, authority = '', rest = ''] = form
  if (authority.includes('@')) return refused('second-host', 'the target carries userinfo, a second host a peer may read', namedHost(authority))
  const { hostText, port } = splitAuthority(authority)
  // The host before the port: 192.168.5.2:8766 is refused for its host, as
  // 192.168.5.2 is, not as a typo of a port, so the log tells a probe of the
  // Mac's loopback from a wrong-port request to a real host.
  const parsed = parseEgressHost(hostText)
  if (!parsed.ok) return refused('not-a-host', `the target's host is not an egress host: it ${parsed.why}`, { hostRefusal: parsed.reason })
  const host = parsed.host
  if (target.length > MAX_TARGET || !/^[\x21-\x7e]+$/.test(target) || target.includes('#')) {
    return refused('target', 'the target is too long, holds a fragment or a character no request line has')
  }
  if (port !== undefined && port !== ROUTE_PORT) {
    return refused('port', `the target names a port other than ${ROUTE_PORT}, the only one egress dials, so it names another service`, { host })
  }
  // The authority ends at a `/` or a `?` (a `#` was refused above), so the
  // path is empty or starts with a slash, and an empty one is `/`.
  const queryAt = rest.indexOf('?')
  const path = (queryAt === -1 ? rest : rest.slice(0, queryAt)) || '/'
  const query = queryAt === -1 ? undefined : rest.slice(queryAt + 1)
  const originForm = query === undefined ? path : `${path}?${query}`
  if (originForm.length > MAX_PATH) return refused('path', `the path and query are longer than the ${String(MAX_PATH)} characters the upstream sends`, { host })
  if (path.includes('\\')) return refused('path', 'the path holds a backslash, which some servers read as a slash', { host })
  if (path.includes('//')) return refused('path', 'the path holds an empty segment (a double slash), which servers collapse differently', { host })
  if (path.split('/').some((segment) => segment === '.' || segment === '..')) {
    return refused('path', 'the path holds a dot segment, which a peer resolves to another path', { host })
  }
  if (!checkEncodings(path)) {
    return refused(
      'path',
      'the path percent-encodes a slash, a dot, a backslash, a percent or a control character, or does not decode to UTF-8: a second spelling of another path',
      { host },
    )
  }
  return Object.freeze({ ok: true as const, host, port, path, query, originForm })
}

// ── route shapes ────────────────────────────────────────────────────────────

/** Which request of its profile a route is. */
export type RouteKind = 'info-refs' | 'upload-pack' | 'receive-pack' | 'pulls'

export interface RouteMatch {
  readonly ok: true
  readonly profile: EgressProfile
  readonly kind: RouteKind
  readonly repo: RepoSlug
}

/**
 * The query each info/refs route names, and the only one it admits. A Map,
 * not a record: a query of `constructor` or `__proto__` must find nothing,
 * not what an object inherits.
 */
const SERVICE_QUERY: ReadonlyMap<string, EgressProfile> = new Map([
  ['service=git-upload-pack', 'git-fetch'],
  ['service=git-receive-pack', 'git-push'],
])

/** A git URL's repository: the name with at most one `.git` after it, which GitHub reads as the same repository. */
function gitRepo(owner: string, segment: string): RepoSlug | undefined {
  return repoOf(owner, segment.toLowerCase().endsWith('.git') ? segment.slice(0, -4) : segment)
}

/**
 * Which route a request is, by its path, method and query, on whatever host
 * holds the binding. The repository is read, not yet compared: policy.ts
 * compares it with the grant's.
 */
export function matchRoute(method: string, path: string, query: string | undefined): RouteMatch | RouteRefused {
  const segments = path.slice(1).split('/')
  const [first = '', second = '', third = '', fourth = ''] = segments
  // Each shape, its kind, and the profile it belongs to; info/refs belongs to
  // the profile its service query names.
  let shape: { readonly kind: RouteKind; readonly profile: EgressProfile | undefined; readonly repo: RepoSlug | undefined } | undefined
  if (segments.length === 4 && first === 'repos' && fourth === 'pulls') {
    shape = { kind: 'pulls', profile: 'github-pulls', repo: repoOf(second, third) }
  } else if (segments.length === 4 && third === 'info' && fourth === 'refs') {
    shape = { kind: 'info-refs', profile: undefined, repo: gitRepo(first, second) }
  } else if (segments.length === 3 && third === 'git-upload-pack') {
    shape = { kind: 'upload-pack', profile: 'git-fetch', repo: gitRepo(first, second) }
  } else if (segments.length === 3 && third === 'git-receive-pack') {
    shape = { kind: 'receive-pack', profile: 'git-push', repo: gitRepo(first, second) }
  }
  if (shape?.repo === undefined) {
    return refused('no-route', 'the path is none a binding profile names, so the request reaches nothing bound')
  }
  const { kind, repo } = shape
  if (method !== (kind === 'info-refs' ? 'GET' : 'POST')) return refused('method', 'the method is not the one this route takes')
  let { profile } = shape
  if (kind === 'info-refs') {
    profile = query === undefined ? undefined : SERVICE_QUERY.get(query)
    if (profile === undefined) return refused('query', 'info/refs names no service, or one other than git-upload-pack or git-receive-pack')
  } else if (query !== undefined) {
    return refused('query', 'this route takes no query')
  }
  if (profile === undefined) return refused('no-route', 'the path is none a binding profile names')
  return Object.freeze({ ok: true as const, profile, kind, repo })
}

// ── git-push: the pkt-line command list ─────────────────────────────────────

export interface PushCommand {
  readonly old: string
  readonly new: string
  readonly ref: string
}

export type CommandListScan =
  | { readonly status: 'incomplete' }
  | { readonly status: 'invalid'; readonly why: string }
  | {
      readonly status: 'complete'
      /** Where the command list ends, its flush-pkt included: the bytes decide() judged. */
      readonly end: number
      readonly commands: readonly PushCommand[]
      readonly capabilities: readonly string[]
    }

const INCOMPLETE = Object.freeze({ status: 'incomplete' as const })

function invalid(why: string): CommandListScan {
  return Object.freeze({ status: 'invalid' as const, why })
}

/** A full object name, SHA-1 or SHA-256, as git writes it: lower-case hex. */
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/

/** ASCII text of bytes[from, to), or none when any byte is outside ASCII. */
function asciiOf(bytes: Uint8Array, from: number, to: number): string | undefined {
  let text = ''
  for (let i = from; i < to; i++) {
    const byte = bytes[i] ?? 0x80
    if (byte > 0x7f) return undefined
    text += String.fromCharCode(byte)
  }
  return text
}

/**
 * The capabilities a push may ask for, by name, each with whether git writes
 * it with a value (`agent=git/2.47.1`) or bare (`quiet`). receive-pack finds
 * a capability with parse_feature_request(), which reads `name` and
 * `name=value` alike: `push-options=1`, and `push-options=` too, ask for push
 * options as surely as `push-options` does. So a capability is judged by its
 * name before any `=`, and only a name listed here is admitted: push-options
 * (option lines after the list, which nothing here reads, handed to the
 * host's hooks), a capability a later git adds, and anything else are
 * refused, never passed for the host to read its own way. A Map, not a
 * record: a capability named `constructor` must find nothing.
 */
const PUSH_CAPABILITIES: ReadonlyMap<string, 'bare' | 'valued'> = new Map([
  ['report-status', 'bare'],
  ['report-status-v2', 'bare'],
  ['side-band-64k', 'bare'],
  ['quiet', 'bare'],
  ['atomic', 'bare'],
  ['ofs-delta', 'bare'],
  ['object-format', 'valued'],
  ['agent', 'valued'],
  ['session-id', 'valued'],
])

/**
 * Why a first command's capabilities are refused, or none. Each is a word of
 * printable ASCII: receive-pack splits the list on git's isspace, which
 * counts HT, LF and CR as well as SP, so agent=git/2.47.1<HT>push-options,
 * split here on SP alone, is one valued capability here and asks for push
 * options there. Each is `name` or `name=value` as PUSH_CAPABILITIES says,
 * with a value that is not empty, and asked for once.
 */
function capabilityRefusal(listed: readonly string[]): string | undefined {
  const named = new Set<string>()
  for (const cap of listed) {
    if (!/^[\x21-\x7e]+$/.test(cap)) return 'a capability holds a control character'
    const eq = cap.indexOf('=')
    const name = eq === -1 ? cap : cap.slice(0, eq)
    const shape = PUSH_CAPABILITIES.get(name)
    if (shape === undefined) {
      return 'the push asks for a capability a run\'s push never needs (push options among them: lines after the list that nothing here reads, handed to the host)'
    }
    if ((shape === 'valued') !== (eq !== -1) || eq === cap.length - 1) {
      return 'a capability is written with a value it takes none of, or without the value it takes'
    }
    if (named.has(name)) return 'a capability is asked for twice'
    named.add(name)
  }
  return undefined
}

/**
 * Read a receive-pack request's update requests, as receive-pack reads them
 * (gitprotocol-pack: `*shallow command-list`), up to the flush-pkt that ends
 * them, in at most MAX_COMMAND_LIST bytes. Narrower than receive-pack, never
 * wider, so a list read here is read the same way there: lengths are four
 * lower-case hex digits, as git writes them; a line is ASCII, with one
 * trailing LF dropped; capabilities ride the first command only, and only
 * those PUSH_CAPABILITIES names, so push options are refused in every
 * spelling receive-pack reads as them; and a signed push (push-cert) and
 * anything else are invalid. Incomplete means more bytes are needed: the
 * session reads on until the scan is complete or invalid, the body ends, or
 * MAX_COMMAND_LIST.
 */
export function scanCommandList(bytes: Uint8Array): CommandListScan {
  const commands: PushCommand[] = []
  let capabilities: readonly string[] = []
  let shallow = 0
  let at = 0
  for (;;) {
    if (at + 4 > MAX_COMMAND_LIST) return invalid(`the command list runs past ${String(MAX_COMMAND_LIST)} bytes`)
    if (at + 4 > bytes.length) return INCOMPLETE
    const lengthText = asciiOf(bytes, at, at + 4)
    if (lengthText === undefined || !/^[0-9a-f]{4}$/.test(lengthText)) return invalid('a pkt-line length is not four lower-case hex digits')
    const length = Number.parseInt(lengthText, 16)
    if (length === 0) {
      if (shallow > 0 && commands.length === 0) return invalid('the list holds shallow lines and no command')
      return Object.freeze({ status: 'complete' as const, end: at + 4, commands: Object.freeze(commands), capabilities })
    }
    if (length <= 4) return invalid('a pkt-line is empty or a special packet, which a command list never holds')
    if (length > MAX_PKT) return invalid('a pkt-line is longer than git writes one')
    const end = at + length
    if (end > MAX_COMMAND_LIST) return invalid(`the command list runs past ${String(MAX_COMMAND_LIST)} bytes`)
    if (end > bytes.length) return INCOMPLETE
    const read = asciiOf(bytes, at + 4, end)
    if (read === undefined) return invalid('a pkt-line holds a byte outside ASCII')
    const payload = read.endsWith('\n') ? read.slice(0, -1) : read
    const nul = payload.indexOf('\0')
    const line = nul === -1 ? payload : payload.slice(0, nul)
    const caps = nul === -1 ? undefined : payload.slice(nul + 1)
    at = end
    if (line.startsWith('shallow ')) {
      if (commands.length > 0 || caps !== undefined || !OID.test(line.slice('shallow '.length))) {
        return invalid('a shallow line is malformed, carries capabilities, or follows a command')
      }
      shallow++
      continue
    }
    if (line === 'push-cert') return invalid('the push is signed (push-cert), whose certificate nothing here reads')
    if (caps !== undefined && commands.length > 0) return invalid('a command after the first carries capabilities')
    const [old = '', next = '', ref = '', ...more] = line.split(' ')
    if (more.length > 0 || ref.length === 0 || !OID.test(old) || !OID.test(next) || old.length !== next.length) {
      return invalid('a command is not old-id SP new-id SP ref')
    }
    if (caps !== undefined) {
      const listed = caps.split(' ').filter((cap) => cap.length > 0)
      const refusal = capabilityRefusal(listed)
      if (refusal !== undefined) return invalid(refusal)
      capabilities = Object.freeze(listed)
    }
    commands.push(Object.freeze({ old, new: next, ref }))
  }
}

export type CommandsJudged = { readonly ok: true; readonly count: number } | RouteRefused

/**
 * A complete command list is admitted only when every command creates or
 * updates a ref under refs/heads/aos/<runId>/, with a branch after it. A
 * delete is refused under the prefix too: a run's push never removes a ref.
 * An empty list is the caller's to judge (git's probe before a large push).
 */
export function judgeCommands(commands: readonly PushCommand[], runId: string): CommandsJudged {
  const prefix = pushRefPrefix(runId)
  for (const command of commands) {
    if (!command.ref.startsWith(prefix) || !isBranchName(command.ref.slice(prefix.length))) {
      return refused('push-ref', "a command names a ref outside refs/heads/aos/<runId>/ of this run, or one that is no branch")
    }
    if (/^0+$/.test(command.new)) return refused('push-delete', 'a command deletes a ref, which a run never does')
  }
  return { ok: true, count: commands.length }
}

// ── github-pulls: the JSON body ─────────────────────────────────────────────

/**
 * The fields a pull request is opened with, and no other: `head_repo` (a
 * pull from another repository) and `issue` (an existing issue turned into
 * a pull) are refused by being unnamed.
 */
const PullsBody = z
  .object({
    title: z.string().min(1).max(1024),
    head: z.string(),
    base: z.string(),
    body: z.string().optional(),
    draft: z.boolean().optional(),
    maintainer_can_modify: z.boolean().optional(),
  })
  .strict()

export type PullsJudged = { readonly ok: true; readonly head: string; readonly base: string } | RouteRefused

/**
 * A pull request's body, read whole: UTF-8 JSON in its one canonical
 * spelling (what JSON.stringify writes of what it parses to, so no
 * duplicate key a host may resolve the other way, no escape it may read
 * differently, no byte-order mark), the fields PullsBody names, a head under
 * aos/<runId>/ in this repository, and a base that is a branch.
 */
export function judgePullsBody(bytes: Uint8Array, runId: string): PullsJudged {
  if (bytes.length > MAX_PULLS_BODY) return refused('pulls-body', `the body is longer than ${String(MAX_PULLS_BODY)} bytes`)
  let parsed: unknown
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
    parsed = JSON.parse(text)
    if (JSON.stringify(parsed) !== text) return refused('pulls-body', 'the body is not JSON in its one canonical spelling')
  } catch {
    return refused('pulls-body', 'the body is not UTF-8 JSON')
  }
  const fields = PullsBody.safeParse(parsed)
  if (!fields.success) return refused('pulls-body', 'the body is not a title, head, base and the optional fields a pull request is opened with, and nothing else')
  const { head, base } = fields.data
  if (head.includes(':')) return refused('pulls-head', 'the head names an owner (owner:branch), a pull from another repository')
  const prefix = pushBranchPrefix(runId)
  if (!head.startsWith(prefix) || !isBranchName(head.slice(prefix.length))) {
    return refused('pulls-head', 'the head is not a branch under aos/<runId>/ of this run')
  }
  if (!isBranchName(base)) return refused('pulls-body', 'the base is not a branch name')
  return { ok: true, head, base }
}
