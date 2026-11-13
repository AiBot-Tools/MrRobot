// The egress decision (egress plan E3): decide(grant, request), pure and
// model-blind.
//
// Contract: every request a worker's container sends is judged here, and
// only an allow from here reaches the upstream (upstream.ts), because only
// here is an EgressAllow minted (decision.ts; a hygiene test pins who names
// mintEgressAllow and who imports decision.ts). decide() reads nothing but
// its arguments: no clock, no environment, no log, no model output, no
// network. The grant is the kernel's (which hosts this run may reach, which
// bound routes and profiles it holds, and for a publish what a human
// approved), and so is what the grant has spent (the session's count); the
// request is the worker's, and every field of it is attacker-chosen text,
// read once and parsed, never trusted:
//
//   * A CONNECT is denied 'use-route', whatever it names: egress has no
//     tunnel mode, and a tunnel's bytes are opaque to every check below. The
//     deny names the host its authority names, or host.ts's reason it is none
//     (routes.ts namedHost), so a CONNECT to 192.168.5.2:8766, the spelling an
//     HTTPS client under HTTPS_PROXY uses, is recorded as a probe of an
//     address, apart from a CONNECT to a real host.
//   * The target must be absolute-form, its host an EgressHost, its text what
//     a request line holds, its port none or 443, its path one spelling
//     (routes.ts parseTarget), judged in that order: a target whose host is
//     none is 'not-a-host' whatever port it names and whatever follows its
//     host (a fragment, a character no request line has, a length past
//     MAX_TARGET), and a deny for the port or the path names the host it
//     read. A Host header naming another host, or userinfo, is a second host;
//     a userinfo deny names the host past the userinfo, or why it is none, as
//     a CONNECT's does. Only then is the method read, a token of upper-case
//     letters, so a deny for it names the host too. A target that is not
//     absolute-form (origin-form, an upper-case scheme) is 'target', and names
//     no host: nothing in it is read as one. So is one whose host is an
//     egress host and whose text holds a fragment, a character no request
//     line has or more than MAX_TARGET: a 'target' row names no host, and is
//     never a probe of a host that is none.
//   * Every header is read under one name however it is spelt
//     (canonicalHeaderName: `Content_Encoding` and `content.encoding` are
//     Content-Encoding), as a backend that folds names reads it. The body's
//     framing is read from the headers as node:http read it: one
//     Content-Length, or Transfer-Encoding: chunked, never both, never two.
//     Content-Type and Content-Encoding are each sent once or not at all.
//   * A header that asks a host to act on another method or path than the
//     request line's (X-HTTP-Method-Override, X-HTTP-Method,
//     X-Method-Override, X-Original-URL, X-Rewrite-URL) is denied
//     'override-header', on every host the grant reaches: decide() judges the
//     request line, and a host that honours one (Rack::MethodOverride turns
//     a POST into the header's method) acts on a request nobody judged, with
//     the binding's credential on it. Any other header is the session's to
//     strip or forward (E8).
//   * A host in the grant's allow list (credential-free) admits GET and HEAD
//     with no body, on any path parseTarget admits: no credential is injected
//     there, and it is read-only, as built for E3 while the plan's Operator
//     decisions hold that question open (its E3 entry on credential-free
//     hosts, which is change-controlled: it decides what an agent reaches).
//   * A host one of the grant's routes binds admits only the route shapes of
//     the profiles that route was granted, on its bound repositories
//     (routes.ts): the shape first ('no-route', 'method', 'query'), then the
//     repository ('repo'), then the profile ('not-granted'), then what the
//     profile asks of the body.
//   * Any other host is 'not-allowed'.
//
// Two profiles judge the start of the body as well as the head: git-push its
// pkt-line command list, github-pulls its whole JSON. leadingNeed() says what
// to read; the session reads it and calls decide() with those bytes as
// `leading`. The allow then carries the bytes judged (decision.ts), and the
// upstream sends only a body that begins with exactly them.
//
// How the host decodes those bytes is in the head: Content-Encoding (a push
// or a pull request judged plain and sent gzip would be decoded into bytes
// nobody judged) and Content-Type. So the allow carries both as decide() read
// them, one value each or none (EgressAllow.content), and the upstream
// refuses a head that names another value, adds one or drops one. The session
// (E8) forwards these two exactly as it handed them to decide(), from the one
// header record it judged; one that judged one record and built the upstream
// head from another is refused there, not sent.
//
// One request, one decision, one allow: decide() mints a fresh EgressAllow
// for each request it allows, over the method, path, content headers and
// body declaration it judged, and caches none; the upstream spends it on the
// first request it carries. decide() never throws: a grant that does not
// parse, a request that is no record, a field that throws when read, a
// leading that is not what leadingNeed() asked for, a count of what the grant
// spent that is no count, and anything else unforeseen are denied
// 'malformed'. A decision is frozen, and its `why` never holds the input.
//
// A grant serving one human-approved sandbox.publish names what the human
// approved (EgressGrant.publish, routes.ts ApprovedPublish), and is held to
// it: its push to that branch alone, its pull request from that branch with
// that title and body alone (routes.ts judgeCommands, judgePullsBody), and
// one pull request: decide() reads what the grant has spent (`spent`, the
// pull requests the caller has had allowed under it, which the session
// counts) and denies a second 'not-granted', before its body is read. That
// count is the only state decide() is handed; it keeps none.

import { z } from 'zod'

import { mintEgressAllow, type EgressAllow, type JudgedBody } from './decision.js'
import { EgressHost, type HostRefusal } from './host.js'
import {
  ApprovedPublish,
  EGRESS_PROFILES,
  EgressProfileName,
  judgeCommands,
  judgePullsBody,
  matchRoute,
  MAX_COMMAND_LIST,
  MAX_PULLS_BODY,
  namedHost,
  parseTarget,
  RepoSlug,
  ROUTE_REFUSALS,
  RUN_REF,
  scanCommandList,
  type EgressProfile,
  type ParsedTarget,
} from './routes.js'

/** The one port egress dials (upstream.ts UPSTREAM_PORT); routes.ts admits a target naming none or this one. */
const DIAL_PORT = 443

/** Why decide() allowed a request: the credential-free allow list, or the profile whose route it is. Stable. */
export const ALLOW_REASONS = Object.freeze(['allow-host', 'git-fetch', 'git-push', 'github-pulls'] as const)
export type AllowReason = (typeof ALLOW_REASONS)[number]

/** Why decide() denied a request. Stable: proxy.decision rows name these. */
export const DENY_REASONS = Object.freeze([
  'malformed',
  'use-route',
  'not-allowed',
  'repo',
  'not-granted',
  'body',
  'content-type',
  'content-encoding',
  'override-header',
  ...ROUTE_REFUSALS,
] as const)
export type DenyReason = (typeof DENY_REASONS)[number]

/** A binding's id, as kernel.yaml keys it and decisions name it. */
export const BINDING_ID = /^[a-z][a-z0-9-]{0,62}$/

/** A bound host, the binding whose credential is injected there, the profiles this grant holds of it, and its repositories. */
export const EgressRoute = z
  .object({
    bindingId: z.string().regex(BINDING_ID),
    host: EgressHost,
    profiles: z.array(EgressProfileName).min(1).max(EGRESS_PROFILES.length),
    repos: z.array(RepoSlug).min(1).max(64),
  })
  .strict()

/**
 * What one run may reach: credential-free hosts and bound routes. A host is
 * one or the other, never both (a request to it would not say whether a
 * credential belongs on it), and a repository on a host is in one route only
 * (it would not say whose). A grant serving one human-approved
 * sandbox.publish names what the human approved (`publish`), and decide()
 * holds its push and its one pull request to that.
 */
export const EgressGrant = z
  .object({
    runId: z.string().regex(RUN_REF),
    allow: z.array(EgressHost).max(64),
    routes: z.array(EgressRoute).max(16),
    publish: ApprovedPublish.optional(),
  })
  .strict()
  .superRefine((grant, ctx) => {
    const issue = (message: string): void => ctx.addIssue({ code: 'custom', message })
    if (new Set(grant.allow).size !== grant.allow.length) issue('a host is listed twice in allow')
    if (new Set(grant.routes.map((r) => r.bindingId)).size !== grant.routes.length) issue('a binding is routed twice')
    const bound = new Set<string>()
    for (const route of grant.routes) {
      if (grant.allow.includes(route.host)) issue('a host is both credential-free and bound')
      if (new Set(route.profiles).size !== route.profiles.length) issue('a route lists a profile twice')
      for (const repo of route.repos) {
        const key = `${route.host} ${repo}`
        if (bound.has(key)) issue('a repository on a host is in two routes')
        bound.add(key)
      }
    }
  })
export type EgressGrant = z.output<typeof EgressGrant>

/**
 * The worker's headers, by lower-case name: the session (session.ts
 * headerRecord) builds one null-prototype record from IncomingMessage's
 * rawHeaders, every value kept in order, and hands decide() and the upstream
 * head that record alone. Not headersDistinct, which throws on a header named
 * `constructor` or `__proto__`, nor headers, which keeps only the first of two
 * Content-Types.
 */
export type EgressHeaders = Readonly<Record<string, string | readonly string[] | undefined>>

/** The worker's request as the session read it. Every field is untrusted. */
export interface EgressRequest {
  /** As the request line had it. */
  readonly method: string
  /** The request-target as the request line had it (IncomingMessage.url). */
  readonly target: string
  readonly headers: EgressHeaders
  /** The bytes of the body the session read for decide(), as leadingNeed() asked; none when it asked for none. */
  readonly leading?: Uint8Array | undefined
}

export interface EgressAllowed {
  readonly verdict: 'allow'
  readonly reason: AllowReason
  /** A clause; never holds the input. */
  readonly why: string
  readonly host: EgressHost
  /** The binding whose credential the session injects; none on a credential-free host. */
  readonly bindingId: string | undefined
  readonly repo: RepoSlug | undefined
  /** The proof the upstream takes: minted over this request as judged, good for one. */
  readonly allow: EgressAllow
}

export interface EgressDenied {
  readonly verdict: 'deny'
  readonly reason: DenyReason
  /** A clause; never holds the input. */
  readonly why: string
  /** The target's host, once it read as one (never on a 'target' deny); a CONNECT's, or a userinfo target's past the userinfo (routes.ts namedHost). */
  readonly host: EgressHost | undefined
  /** The route the request reached, once one did. */
  readonly bindingId: string | undefined
  /** host.ts's reason the host was none: always for 'not-a-host', and for a 'use-route' or 'second-host' whose host namedHost refused. Never beside a host. */
  readonly hostRefusal: HostRefusal | undefined
}

export type EgressDecision = EgressAllowed | EgressDenied

/** What decide() needs read of the body before it can judge a request. */
export type LeadingNeed =
  | { readonly kind: 'none' }
  /** git-push: read until routes.ts scanCommandList is complete or invalid, the body ends, or `max` bytes. */
  | { readonly kind: 'command-list'; readonly max: number }
  /** github-pulls: read the whole body, exactly `length` bytes. */
  | { readonly kind: 'whole-body'; readonly length: number }

const NO_LEADING: LeadingNeed = Object.freeze({ kind: 'none' as const })

/**
 * What the caller has had allowed under the grant so far that decide() must
 * know: the pull requests (allows whose reason is github-pulls). A grant that
 * names its publish (EgressGrant.publish) opens one. The session counts it,
 * at each allow, before it awaits anything, so two pull requests judged on
 * two flows at once are never both allowed.
 */
export interface GrantSpent {
  readonly pullRequests: number
}

const NOTHING_SPENT: GrantSpent = Object.freeze({ pullRequests: 0 })

/** The pull requests a grant has spent, read once, or undefined when `spent` is no count. */
function readSpent(spent: unknown): number | undefined {
  if (typeof spent !== 'object' || spent === null) return undefined
  const count: unknown = Reflect.get(spent, 'pullRequests')
  return typeof count === 'number' && Number.isSafeInteger(count) && count >= 0 ? count : undefined
}

interface Where {
  readonly host?: EgressHost | undefined
  readonly bindingId?: string | undefined
  readonly hostRefusal?: HostRefusal | undefined
}

function deny(reason: DenyReason, why: string, where: Where = {}): EgressDenied {
  return Object.freeze({
    verdict: 'deny' as const,
    reason,
    why,
    host: where.host,
    bindingId: where.bindingId,
    hostRefusal: where.hostRefusal,
  })
}

/** How far the head took a request: decided, ready to allow on the head alone, or waiting on the body's leading bytes. */
type HeadVerdict =
  | { readonly kind: 'decided'; readonly decision: EgressDenied }
  | { readonly kind: 'ready'; readonly allow: () => EgressAllowed }
  | { readonly kind: 'read'; readonly need: LeadingNeed; readonly finish: (leading: Uint8Array) => EgressDecision }

const denied = (decision: EgressDenied): HeadVerdict => ({ kind: 'decided', decision })

/**
 * A header's name as a host may read it: lower case, and every character but
 * a letter or a digit a hyphen. node:http's parser keeps any token as a name,
 * and many backends fold names into one variable (Rack's and Puma's HTTP_*,
 * which read `X_HTTP_Method_Override` as the override header,
 * CVE-2024-45614's class; a CGI gateway, whose git-http-backend reads
 * HTTP_CONTENT_ENCODING for `Content_Encoding` or `Content.Encoding`), so a
 * name decide() did not read as one header is one there. decide() reads every
 * header under this name, so an alias is the same header to the override
 * check, to the framing, to the content headers and to sending one twice;
 * the session strips by it too (session.ts). An alias that reaches an allow
 * (a lone `Content_Type`) is refused by the upstream, which compares the
 * content headers by their own names and so finds the judged one missing.
 */
export function canonicalHeaderName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '-')
}

/** The worker's headers, by canonical name (canonicalHeaderName), each with every value sent under any spelling of it; none when the record is no headers. */
function readHeaders(given: unknown): ReadonlyMap<string, readonly string[]> | undefined {
  // An array is rawHeaders' shape, name and value in turn: no record of names.
  if (typeof given !== 'object' || given === null || Array.isArray(given)) return undefined
  const headers = new Map<string, string[]>()
  for (const [name, value] of Object.entries(given)) {
    let values: string[]
    if (typeof value === 'string') values = [value]
    else if (value === undefined) continue
    else if (Array.isArray(value) && value.every((v): v is string => typeof v === 'string')) values = [...value]
    else return undefined
    const canonical = canonicalHeaderName(name)
    headers.set(canonical, [...(headers.get(canonical) ?? []), ...values])
  }
  return headers
}

/** One header's one value: none when absent, `many` when sent more than once, which a judged header may never be. */
function single(headers: ReadonlyMap<string, readonly string[]>, name: string): string | undefined | typeof MANY {
  const values = headers.get(name)
  if (values === undefined || values.length === 0) return undefined
  if (values.length > 1) return MANY
  return values[0]
}
const MANY = Symbol('many')

/**
 * The body as the head declares it: none, one Content-Length (a whole number
 * of bytes), or Transfer-Encoding: chunked alone. Both, either twice, or a
 * coding beside chunked is framing two parsers may read two ways.
 */
function declaredBody(headers: ReadonlyMap<string, readonly string[]>): { readonly ok: true; readonly body: JudgedBody | undefined } | { readonly ok: false } {
  const te = single(headers, 'transfer-encoding')
  const cl = single(headers, 'content-length')
  if (te === MANY || cl === MANY || (te !== undefined && cl !== undefined)) return { ok: false }
  if (te !== undefined) return te.trim().toLowerCase() === 'chunked' ? { ok: true, body: Object.freeze({}) } : { ok: false }
  if (cl !== undefined) {
    if (!/^[0-9]{1,15}$/.test(cl.trim())) return { ok: false }
    return { ok: true, body: Object.freeze({ length: Number(cl.trim()) }) }
  }
  return { ok: true, body: undefined }
}

/** A Host header, when sent, names the target's host and port, in any spelling host.ts reads as the same. */
function sameHost(headers: ReadonlyMap<string, readonly string[]>, target: ParsedTarget): boolean {
  const value = single(headers, 'host')
  if (value === undefined) return true
  if (value === MANY || value.includes('[') || value.split(':').length > 2) return false
  const colon = value.indexOf(':')
  const port = colon === -1 ? undefined : value.slice(colon + 1)
  if (port !== target.port) return false
  const named = EgressHost.safeParse(colon === -1 ? value : value.slice(0, colon))
  return named.success && named.data === target.host
}

/**
 * Headers some hosts read as the method or the path in place of the request
 * line's, by lower-case name. decide() judges the request line, so a request
 * that sends one, with any value, is denied: a route judged as a POST to
 * /pulls is not one a host may act on as another method or another path.
 */
const OVERRIDE_HEADERS: readonly string[] = Object.freeze([
  'x-http-method-override',
  'x-http-method',
  'x-method-override',
  'x-original-url',
  'x-rewrite-url',
])

const UPLOAD_PACK_TYPE = 'application/x-git-upload-pack-request'
const RECEIVE_PACK_TYPE = 'application/x-git-receive-pack-request'
const JSON_TYPE = /^application\/json(?:\s*;\s*charset=utf-8)?$/

interface Judging {
  readonly grant: EgressGrant
  /** The pull requests the grant has spent (GrantSpent). */
  readonly pullRequests: number
  readonly method: string
  readonly target: ParsedTarget
  /** Content-Type and Content-Encoding as sent, one value each or none: what the allow holds the upstream's head to. */
  readonly content: { readonly type: string | undefined; readonly encoding: string | undefined }
  readonly body: JudgedBody | undefined
}

function allowed(j: Judging, reason: AllowReason, why: string, route: { readonly bindingId: string; readonly repo: RepoSlug } | undefined, leading?: Uint8Array): EgressAllowed {
  const body: JudgedBody | undefined =
    j.body === undefined ? undefined : leading === undefined ? j.body : Object.freeze({ length: j.body.length, leading })
  return Object.freeze({
    verdict: 'allow' as const,
    reason,
    why,
    host: j.target.host,
    bindingId: route?.bindingId,
    repo: route?.repo,
    allow: mintEgressAllow({ host: j.target.host, port: DIAL_PORT, method: j.method, path: j.target.originForm, content: j.content, body }),
  })
}

/** A credential-free host: read-only, no body, on any path parseTarget admitted. */
function judgeFree(j: Judging): HeadVerdict {
  const where = { host: j.target.host }
  if (j.method !== 'GET' && j.method !== 'HEAD') {
    return denied(deny('method', 'a credential-free host admits GET and HEAD only', where))
  }
  if (j.body !== undefined) return denied(deny('body', 'a request to a credential-free host carries no body', where))
  return { kind: 'ready', allow: () => allowed(j, 'allow-host', 'a credential-free host this grant allows, read-only', undefined) }
}

/** A bound host: a route shape of a profile its route was granted, on a bound repository, and what that profile asks of the body. */
function judgeRoute(j: Judging, routes: EgressGrant['routes']): HeadVerdict {
  const host = j.target.host
  const match = matchRoute(j.method, j.target.path, j.target.query)
  if (!match.ok) return denied(deny(match.reason, match.why, { host }))
  const route = routes.find((r) => r.repos.includes(match.repo))
  if (route === undefined) return denied(deny('repo', 'the repository is none this host binds for the run', { host }))
  const where = { host, bindingId: route.bindingId }
  if (!route.profiles.includes(match.profile)) {
    return denied(deny('not-granted', "the route's profile is not one this grant holds for the binding", where))
  }
  const bound = { bindingId: route.bindingId, repo: match.repo }
  const profile: EgressProfile = match.profile
  // Judged from the values the allow is minted with, so what was judged is what the upstream holds the head to.
  const contentType = j.content.type?.trim().toLowerCase()
  const encoding = j.content.encoding?.trim().toLowerCase()
  switch (match.kind) {
    case 'info-refs':
      if (j.body !== undefined) return denied(deny('body', 'info/refs carries no body', where))
      return { kind: 'ready', allow: () => allowed(j, profile, "the ref advertisement of a bound repository's granted service", bound) }
    case 'upload-pack':
      if (j.body === undefined) return denied(deny('body', 'git-upload-pack carries a body', where))
      if (contentType !== UPLOAD_PACK_TYPE) return denied(deny('content-type', 'git-upload-pack takes its own content type', where))
      // Read-only, and nothing here reads its body: git compresses a large negotiation.
      if (encoding !== undefined && encoding !== 'gzip') return denied(deny('content-encoding', 'git-upload-pack is sent plain or gzip', where))
      return { kind: 'ready', allow: () => allowed(j, profile, 'a fetch from a bound repository', bound) }
    case 'receive-pack': {
      const body = j.body
      if (body === undefined) return denied(deny('body', 'git-receive-pack carries a body', where))
      if (contentType !== RECEIVE_PACK_TYPE) return denied(deny('content-type', 'git-receive-pack takes its own content type', where))
      // The command list judged must be the bytes the host reads.
      if (encoding !== undefined) return denied(deny('content-encoding', 'a push body is never encoded: the command list judged must be the bytes the host reads', where))
      return {
        kind: 'read',
        need: Object.freeze({ kind: 'command-list' as const, max: MAX_COMMAND_LIST }),
        finish: (leading) => {
          if (leading.length > MAX_COMMAND_LIST || (body.length !== undefined && leading.length > body.length)) {
            return deny('malformed', 'more was read of the body than leadingNeed() asked for, or than it declares', where)
          }
          const scan = scanCommandList(leading)
          if (scan.status === 'incomplete') return deny('push-commands', 'the command list does not end where the bytes read do', where)
          if (scan.status === 'invalid') return deny('push-commands', `the command list is refused: ${scan.why}`, where)
          // git's probe before a large push: a flush and nothing else, which updates nothing.
          if (scan.commands.length === 0 && body.length !== scan.end) {
            return deny('push-commands', 'an empty command list is admitted only as the whole body, as git probes', where)
          }
          const judged = judgeCommands(scan.commands, j.grant.runId, j.grant.publish?.branch)
          if (!judged.ok) return deny(judged.reason, judged.why, where)
          return allowed(j, profile, "a push of this run's branches to a bound repository", bound, leading.slice(0, scan.end))
        },
      }
    }
    case 'pulls': {
      // A publish opens one pull request: a second is refused before its body is read.
      if (j.grant.publish !== undefined && j.pullRequests > 0) {
        return denied(deny('not-granted', "this publish grant's one pull request was allowed already", where))
      }
      const length = j.body?.length
      if (length === undefined) return denied(deny('body', 'a pull request is opened with a body of declared length', where))
      if (length > MAX_PULLS_BODY) return denied(deny('body', `a pull request's body is at most ${String(MAX_PULLS_BODY)} bytes`, where))
      if (contentType === undefined || !JSON_TYPE.test(contentType)) {
        return denied(deny('content-type', 'a pull request is opened with application/json', where))
      }
      if (encoding !== undefined) return denied(deny('content-encoding', 'a pull request body is never encoded: the JSON judged must be the bytes the host reads', where))
      return {
        kind: 'read',
        need: Object.freeze({ kind: 'whole-body' as const, length }),
        finish: (leading) => {
          if (leading.length !== length) return deny('malformed', 'the bytes read are not the whole body leadingNeed() asked for', where)
          const judged = judgePullsBody(leading, j.grant.runId, j.grant.publish)
          if (!judged.ok) return deny(judged.reason, judged.why, where)
          return allowed(j, profile, "a pull request from this run's branch, in a bound repository", bound, leading.slice())
        },
      }
    }
  }
}

/** Judge a request on its head: everything but the leading bytes of a body. */
function judgeHead(grant: unknown, method: unknown, target: unknown, headersGiven: unknown, spent: unknown): HeadVerdict {
  const parsedGrant = EgressGrant.safeParse(grant)
  if (!parsedGrant.success) return denied(deny('malformed', 'the grant is not one EgressGrant reads'))
  const pullRequests = readSpent(spent)
  if (pullRequests === undefined) return denied(deny('malformed', 'what the grant has spent is not a count'))
  if (typeof method !== 'string' || typeof target !== 'string') return denied(deny('malformed', 'the method or the target is not text'))
  if (method.toUpperCase() === 'CONNECT') {
    // Where it was headed, for the row: a probe of the Mac's loopback is told from a tunnel to a real host.
    return denied(deny('use-route', 'egress opens no tunnel: a request is sent in absolute form and routed', namedHost(target)))
  }
  const parsed = parseTarget(target)
  if (!parsed.ok) return denied(deny(parsed.reason, parsed.why, { host: parsed.host, hostRefusal: parsed.hostRefusal }))
  const host = parsed.host
  // After the target, so a deny for the method names where the request was headed.
  if (!/^[A-Z]{1,16}$/.test(method)) return denied(deny('method', 'the method is not an upper-case token', { host }))
  const headers = readHeaders(headersGiven)
  if (headers === undefined) return denied(deny('malformed', 'the headers are not a record of text', { host }))
  if (!sameHost(headers, parsed)) return denied(deny('second-host', 'the Host header names another host or port than the target', { host }))
  const declared = declaredBody(headers)
  if (!declared.ok) {
    return denied(deny('body', "the body's framing is ambiguous: Content-Length and Transfer-Encoding, either twice, or a coding beside chunked", { host }))
  }
  // Sent once or not at all, on every route: the allow holds the upstream's
  // head to the one value read, and two would leave which one that is to the
  // order a record kept them in.
  const type = single(headers, 'content-type')
  if (type === MANY) return denied(deny('content-type', 'the request sends Content-Type twice', { host }))
  const encoding = single(headers, 'content-encoding')
  if (encoding === MANY) return denied(deny('content-encoding', 'the request sends Content-Encoding twice', { host }))
  const content = Object.freeze({ type, encoding })
  const j: Judging = { grant: parsedGrant.data, pullRequests, method, target: parsed, content, body: declared.body }
  const free = j.grant.allow.includes(host)
  const routes = j.grant.routes.filter((r) => r.host === host)
  if (!free && routes.length === 0) {
    return denied(deny('not-allowed', 'the host is neither credential-free nor bound for this run', { host }))
  }
  if (OVERRIDE_HEADERS.some((name) => headers.has(name))) {
    return denied(deny('override-header', 'a header asks the host to act on another method or path than the request line judged', { host }))
  }
  return free ? judgeFree(j) : judgeRoute(j, routes)
}

/** Read the request's fields once, so a getter runs once and what is judged is what was read. */
function readRequest(request: unknown): { readonly method: unknown; readonly target: unknown; readonly headers: unknown; readonly leading: unknown } | undefined {
  if (typeof request !== 'object' || request === null) return undefined
  const field = (name: string): unknown => Reflect.get(request, name)
  return { method: field('method'), target: field('target'), headers: field('headers'), leading: field('leading') }
}

/**
 * Judge one request against one grant, and what the grant has spent
 * (GrantSpent: none when unset): allow, with the EgressAllow the upstream
 * takes, or deny, with a reason from DENY_REASONS. Pure and model-blind;
 * never throws.
 */
export function decide(grant: EgressGrant, request: EgressRequest, spent: GrantSpent = NOTHING_SPENT): EgressDecision {
  try {
    const read = readRequest(request)
    if (read === undefined) return deny('malformed', 'the request is not a record')
    const { leading } = read
    if (leading !== undefined && !(leading instanceof Uint8Array)) return deny('malformed', 'the leading bytes are not bytes')
    // A copy: the bytes judged stay the bytes judged, whatever the caller later writes into its buffer.
    const bytes = leading === undefined ? undefined : new Uint8Array(leading)
    const verdict = judgeHead(grant, read.method, read.target, read.headers, spent)
    switch (verdict.kind) {
      case 'decided':
        return verdict.decision
      case 'ready':
        if (bytes !== undefined) return deny('malformed', 'bytes of the body were read that this route does not judge')
        return verdict.allow()
      case 'read':
        if (bytes === undefined) return deny('malformed', "the body's leading bytes this route judges were not read")
        return verdict.finish(bytes)
    }
  } catch {
    return deny('malformed', 'judging the request threw')
  }
}

/**
 * What the session must read of the body before decide() can judge the
 * request: nothing, unless the head alone admits a route that judges its
 * body. Pure; never throws.
 */
export function leadingNeed(grant: EgressGrant, request: Omit<EgressRequest, 'leading'>, spent: GrantSpent = NOTHING_SPENT): LeadingNeed {
  try {
    const read = readRequest(request)
    if (read === undefined) return NO_LEADING
    const verdict = judgeHead(grant, read.method, read.target, read.headers, spent)
    return verdict.kind === 'read' ? verdict.need : NO_LEADING
  } catch {
    return NO_LEADING
  }
}
