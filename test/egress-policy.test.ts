// Egress plan E3 — the binding profiles (src/egress/routes.ts) and the pure
// decide() (src/egress/policy.ts).
//
// decide() is the allowlist. It fails OPEN when it is wrong: the upstream
// sends whatever it allowed, with the binding's credential injected, and the
// host answers as it would answer the operator. So every way a worker could
// reach past what a grant names is driven here, from the request a container
// would write:
//
//   Admit any path on a bound host and the worker reads a token endpoint, or
//   the web UI, with the operator's credential on the request.
//   Read the push command list loosely, or skip one command of it, and a run
//   pushes to main, or deletes a branch, in a bound repository.
//   Admit an encoded push body and the command list judged is not the one the
//   host reads.
//   Admit owner:branch as a pull request's head, or an unnamed field, and a
//   run opens a pull from another repository, or converts an issue.
//   Normalise a path rather than refuse it and the path judged is not the
//   path a peer resolves (%2e%2e, //, a backslash, an overlong dot).
//   Compare hosts by suffix or by spelling and an allowlist entry admits a
//   name nobody listed, or misses one it did.
//
// Every request here is a value; nothing resolves, dials or reads a file but
// the purity scan of the two modules' own source.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { Readable } from 'node:stream'
import ts from 'typescript'

import { EgressAllow } from '../src/egress/decision.js'
import { EgressHost } from '../src/egress/host.js'
import {
  ALLOW_REASONS,
  canonicalHeaderName,
  decide,
  DENY_REASONS,
  EgressGrant,
  leadingNeed,
  type EgressDecision,
  type EgressHeaders,
  type EgressRequest,
} from '../src/egress/policy.js'
import {
  EGRESS_PROFILES,
  isBranchName,
  MAX_COMMAND_LIST,
  MAX_PULLS_BODY,
  MAX_TARGET,
  namedHost,
  parseTarget,
  RepoSlug,
  ROUTE_REFUSALS,
  scanCommandList,
} from '../src/egress/routes.js'
import { createUpstream, type UpstreamDeps, type UpstreamResolver } from '../src/egress/upstream.js'
import { recordable } from '../src/events/bound.js'
import {
  EGRESS_PATH_BYTES,
  EGRESS_WHY_BYTES,
  METHOD_SHAPE,
  PAYLOAD_SCHEMAS,
  PROXY_DENIES_BEFORE_HOST,
  PROXY_DENIES_BEFORE_PATH,
  PROXY_DENIES_BY_HOST_REFUSAL,
  PROXY_DENIES_ON_A_ROUTE,
  PROXY_DENY_REASONS,
} from '../src/events/types.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')

const RUN = 'run_1762700000000_k3x9q2'
const OTHER_RUN = 'run_1762700000001_zz0000'

/** What sandbox.exec's grant holds: a credential-free host, and git-fetch of the bound repository. */
const EXEC = EgressGrant.parse({
  runId: RUN,
  allow: ['registry.npmjs.org'],
  routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['Op/Fixture'] }],
})

/** What sandbox.publish's grant holds: fetch and push on github.com, pulls on the API host. */
const PUBLISH = EgressGrant.parse({
  runId: RUN,
  allow: [],
  routes: [
    { bindingId: 'github', host: 'github.com', profiles: ['git-fetch', 'git-push'], repos: ['op/fixture'] },
    { bindingId: 'github-api', host: 'api.github.com', profiles: ['github-pulls'], repos: ['op/fixture'] },
  ],
})

const OLD = 'a'.repeat(40)
const NEW = 'b'.repeat(40)
const ZERO = '0'.repeat(40)
const CAPS = ' report-status side-band-64k quiet object-format=sha1 agent=git/2.47.1'

/** One pkt-line: four lower-case hex digits of length, the payload, as git writes it. */
function pkt(payload: string): string {
  return (payload.length + 4).toString(16).padStart(4, '0') + payload
}

/** A receive-pack request's command list, as send-pack writes it: capabilities on the first, then a flush. */
function commandList(refs: readonly (readonly [old: string, next: string, ref: string])[], caps = CAPS): string {
  return refs.map(([old, next, ref], i) => pkt(`${old} ${next} ${ref}${i === 0 ? `\0${caps}` : ''}`)).join('') + '0000'
}

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text)

/** A pack after the list: what decide() never reads. */
const PACK = 'PACK\x00\x00\x00\x02\x00\x00\x00\x00'

function request(method: string, target: string, headers: EgressHeaders = {}, leading?: Uint8Array): EgressRequest {
  return leading === undefined ? { method, target, headers } : { method, target, headers, leading }
}

const UPLOAD_HEADERS = { 'content-type': 'application/x-git-upload-pack-request', 'transfer-encoding': 'chunked' }

/** A push, its body declared at the length of the list and a pack, and the list read as leading. */
function push(list: string, extra: EgressHeaders = {}, grant: EgressGrant = PUBLISH): EgressDecision {
  const body = list + PACK
  return decide(
    grant,
    request(
      'POST',
      'http://github.com/op/fixture.git/git-receive-pack',
      { 'content-type': 'application/x-git-receive-pack-request', 'content-length': String(body.length), ...extra },
      bytes(list),
    ),
  )
}

/** A pull request, its whole body read as leading. */
function pulls(body: string, extra: EgressHeaders = {}, target = 'http://api.github.com/repos/op/fixture/pulls'): EgressDecision {
  const raw = bytes(body)
  return decide(PUBLISH, request('POST', target, { 'content-type': 'application/json', 'content-length': String(raw.length), ...extra }, raw))
}

const PR = { title: 'Add the fixture change', head: `aos/${RUN}/feature`, base: 'main', body: 'Opened by sandbox.publish.' }

function allows(decision: EgressDecision, reason: string, label: string): EgressAllow {
  assert.equal(decision.verdict, 'allow', `${label}: ${decision.verdict === 'deny' ? `${decision.reason} (${decision.why})` : ''}`)
  assert.equal(decision.reason, reason, label)
  if (decision.verdict !== 'allow') throw new Error('unreachable')
  assert.equal(EgressAllow.is(decision.allow), true, label)
  return decision.allow
}

function denies(decision: EgressDecision, reason: string, label: string): void {
  assert.equal(decision.verdict, 'deny', `${label}: allowed as ${decision.reason}`)
  assert.equal(decision.reason, reason, `${label}: ${decision.why}`)
  assert.equal('allow' in decision, false, `${label}: a deny carries an allow`)
}

// ── the acceptance tests ─────────────────────────────────────────────────────

test('git-fetch admits only info/refs?service=git-upload-pack and git-upload-pack of a bound repo', () => {
  for (const repo of ['op/fixture.git', 'op/fixture', 'Op/Fixture.git', 'OP/FIXTURE']) {
    const refs = allows(
      decide(EXEC, request('GET', `http://github.com/${repo}/info/refs?service=git-upload-pack`, { host: 'github.com' })),
      'git-fetch',
      `info/refs of ${repo}`,
    )
    // Sent as written: the allow is minted over the worker's own path.
    assert.equal(refs.path, `/${repo}/info/refs?service=git-upload-pack`)
    assert.equal(refs.method, 'GET')
    assert.equal(refs.host, 'github.com')
    assert.equal(refs.port, 443)
    assert.equal(refs.body, undefined)
  }
  const decision = decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', UPLOAD_HEADERS))
  const rpc = allows(decision, 'git-fetch', 'upload-pack, chunked')
  assert.equal(decision.verdict === 'allow' ? decision.bindingId : undefined, 'github')
  assert.equal(decision.verdict === 'allow' ? decision.repo : undefined, 'op/fixture')
  assert.deepEqual(rpc.body, { length: undefined, leadingBytes: 0 })
  const sized = allows(
    decide(EXEC, request('POST', 'http://github.com/op/fixture/git-upload-pack', { 'content-type': 'application/x-git-upload-pack-request', 'content-length': '312', 'content-encoding': 'gzip' })),
    'git-fetch',
    'upload-pack, gzip, sized',
  )
  assert.deepEqual(sized.body, { length: 312, leadingBytes: 0 })

  // Push is another profile, which an exec grant does not hold.
  denies(decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-receive-pack')), 'not-granted', 'receive-pack refs on exec')
  denies(
    decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'content-length': '4' }, bytes('0000'))),
    'not-granted',
    'receive-pack on exec',
  )
  // Another repository on the bound host, under any owner.
  for (const repo of ['op/other', 'someone/fixture', 'op/fixture-2']) {
    denies(decide(EXEC, request('GET', `http://github.com/${repo}/info/refs?service=git-upload-pack`)), 'repo', repo)
    denies(decide(EXEC, request('POST', `http://github.com/${repo}/git-upload-pack`, UPLOAD_HEADERS)), 'repo', repo)
  }
  // Only the one query, the one method.
  for (const query of ['', '?', '?service=git-upload-pack&x=1', '?x=1&service=git-upload-pack', '?service=git-upload-pack-x', '?Service=git-upload-pack', '?constructor', '?__proto__']) {
    denies(decide(EXEC, request('GET', `http://github.com/op/fixture.git/info/refs${query}`)), 'query', `info/refs${query}`)
  }
  denies(decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack?x=1', UPLOAD_HEADERS)), 'query', 'upload-pack with a query')
  denies(decide(EXEC, request('POST', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', UPLOAD_HEADERS)), 'method', 'POST info/refs')
  denies(decide(EXEC, request('GET', 'http://github.com/op/fixture.git/git-upload-pack')), 'method', 'GET upload-pack')
  denies(decide(EXEC, request('PUT', 'http://github.com/op/fixture.git/git-upload-pack', UPLOAD_HEADERS)), 'method', 'PUT upload-pack')
  // Everything else on the bound host is no route: the web UI, archives,
  // token endpoints, the API shapes of another profile, a trailing slash.
  for (const path of [
    '/',
    '/op/fixture',
    '/op/fixture.git',
    '/op/fixture/archive/refs/heads/main.zip',
    '/login/oauth/access_token',
    '/settings/tokens',
    '/op/fixture.git/info/refs/',
    '/op/fixture.git/info/lfs/objects/batch',
    '/op/fixture.git/objects/info/packs',
    '/op/fixture.git/HEAD',
    '/op/fixture/git-upload-pack/x',
  ]) {
    denies(decide(EXEC, request('GET', `http://github.com${path}`)), 'no-route', path)
  }
  // The upload-pack body: its own content type, plain or gzip, and a body.
  denies(decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { ...UPLOAD_HEADERS, 'content-type': 'application/x-git-receive-pack-request' })), 'content-type', 'upload-pack typed as receive-pack')
  denies(decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { 'transfer-encoding': 'chunked' })), 'content-type', 'upload-pack untyped')
  denies(decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { ...UPLOAD_HEADERS, 'content-encoding': 'br' })), 'content-encoding', 'upload-pack in br')
  denies(decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { 'content-type': 'application/x-git-upload-pack-request' })), 'body', 'upload-pack with no body')
  denies(decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', { 'content-length': '0' })), 'body', 'info/refs with a body')
})

test('git-push refuses a ref outside aos/<runId>/, a delete and an encoded body', () => {
  const prefix = `refs/heads/aos/${RUN}/`
  const list = commandList([[ZERO, NEW, `${prefix}feature`], [OLD, NEW, `${prefix}feature/two`]])
  const allow = allows(push(list), 'git-push', 'a create and an update under the prefix')
  // The bytes judged are exactly the command list, flush included: the pack after it is the host's.
  assert.deepEqual(allow.body, { length: list.length + PACK.length, leadingBytes: list.length })
  assert.deepEqual(EgressAllow.leadingOf(allow), bytes(list))
  allows(decide(PUBLISH, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-receive-pack')), 'git-push', 'the receive-pack advertisement')
  // Chunked, as git sends a push larger than its post buffer.
  allows(
    decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'transfer-encoding': 'chunked' }, bytes(list))),
    'git-push',
    'a chunked push',
  )

  // A ref outside aos/<runId>/ of this run, in any command of the list.
  for (const ref of [
    'refs/heads/main',
    'refs/heads/aos',
    `refs/heads/aos/${RUN}`,
    `refs/heads/aos/${RUN}/`,
    `refs/heads/aos/${OTHER_RUN}/feature`,
    `refs/heads/aos/${RUN}x/feature`,
    `refs/heads/aos/${RUN.toUpperCase()}/feature`,
    `refs/tags/aos/${RUN}/feature`,
    `refs/aos/${RUN}/feature`,
    `refs/heads/aos/${RUN}/../../main`,
    `refs/heads/aos/${RUN}/feature.lock`,
    `refs/heads/aos/${RUN}/.hidden`,
    `refs/heads/aos/${RUN}/-option`,
    `refs/heads/aos/${RUN}/feature//two`,
    `refs/heads/aos/${RUN}/feature/`,
    `refs/heads/aos/${RUN}/feature\nrefs/heads/main`,
    `refs/heads/aos/${RUN}/fea ture`,
    'HEAD',
  ]) {
    denies(push(commandList([[OLD, NEW, ref]])), ref.includes(' ') ? 'push-commands' : 'push-ref', `alone: ${JSON.stringify(ref)}`)
    denies(push(commandList([[OLD, NEW, `${prefix}ok`], [OLD, NEW, ref]])), ref.includes(' ') ? 'push-commands' : 'push-ref', `second: ${JSON.stringify(ref)}`)
  }
  // A delete, under the prefix as anywhere, alone or beside an update.
  denies(push(commandList([[OLD, ZERO, `${prefix}feature`]])), 'push-delete', 'a delete under the prefix')
  denies(push(commandList([[OLD, NEW, `${prefix}feature`], [OLD, ZERO, `${prefix}old`]])), 'push-delete', 'a delete after an update')
  denies(push(commandList([[ZERO, ZERO, `${prefix}feature`]])), 'push-delete', 'a zero-to-zero command')
  // In a SHA-256 repository too, whose null id is 64 zeros, not 40.
  denies(push(commandList([['c'.repeat(64), '0'.repeat(64), `${prefix}f`]])), 'push-delete', 'a SHA-256 delete')
  allows(push(commandList([['0'.repeat(64), 'd'.repeat(64), `${prefix}f`]])), 'git-push', 'a SHA-256 create')
  // An encoded body: the list judged would not be the list the host reads.
  for (const coding of ['gzip', 'identity', 'deflate', 'br', 'GZIP']) {
    denies(push(list, { 'content-encoding': coding }), 'content-encoding', `push in ${coding}`)
  }
  denies(push(list, { 'content-encoding': ['gzip', 'identity'] }), 'content-encoding', 'push with two codings')
  // Its own content type, and no other.
  denies(push(list, { 'content-type': 'application/x-git-upload-pack-request' }), 'content-type', 'push typed as fetch')
  // Another repository's receive-pack.
  denies(
    decide(PUBLISH, request('POST', 'http://github.com/op/other.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'content-length': '4' }, bytes('0000'))),
    'repo',
    "another repository's receive-pack",
  )
})

test('github-pulls admits only POST /repos/<bound>/pulls with a prefixed head', () => {
  const body = JSON.stringify(PR)
  const decision = pulls(body)
  const allow = allows(decision, 'github-pulls', 'a pull request from the run branch')
  assert.equal(decision.verdict === 'allow' ? decision.bindingId : undefined, 'github-api')
  assert.equal(allow.path, '/repos/op/fixture/pulls')
  assert.equal(allow.host, 'api.github.com')
  // The whole body is judged, and the upstream holds the body to it.
  assert.deepEqual(allow.body, { length: bytes(body).length, leadingBytes: bytes(body).length })
  assert.deepEqual(EgressAllow.leadingOf(allow), bytes(body))
  allows(pulls(JSON.stringify({ ...PR, draft: true, maintainer_can_modify: false })), 'github-pulls', 'with draft and maintainer_can_modify')
  allows(pulls(JSON.stringify({ title: 'Löschen ✓', head: `aos/${RUN}/f`, base: 'release/1.x' })), 'github-pulls', 'non-ASCII title, a nested base')
  allows(pulls(body, { 'content-type': 'application/json; charset=utf-8' }), 'github-pulls', 'json with charset')
  allows(pulls(body, {}, 'http://api.github.com/repos/Op/Fixture/pulls'), 'github-pulls', 'the repository in another case')

  // The head: under aos/<runId>/ of this run, in this repository.
  for (const head of ['main', `aos/${OTHER_RUN}/feature`, `aos/${RUN}`, `aos/${RUN}/`, `aos/${RUN}/../main`, `aos/${RUN}/f.lock`, `refs/heads/aos/${RUN}/f`]) {
    denies(pulls(JSON.stringify({ ...PR, head })), 'pulls-head', `head ${head}`)
  }
  // Cross-repository: owner:branch, even with the prefix after it, and head_repo.
  for (const head of [`someone:aos/${RUN}/feature`, `op:aos/${RUN}/feature`, `aos/${RUN}/feat:ure`]) {
    denies(pulls(JSON.stringify({ ...PR, head })), 'pulls-head', `cross-repo head ${head}`)
  }
  denies(pulls(JSON.stringify({ ...PR, head_repo: 'someone/fixture' })), 'pulls-body', 'head_repo')
  denies(pulls(JSON.stringify({ ...PR, issue: 7 })), 'pulls-body', 'an issue turned into a pull')
  denies(pulls(JSON.stringify({ ...PR, base: 'main..x' })), 'pulls-body', 'a base that is no branch')
  denies(pulls(JSON.stringify({ head: PR.head, base: 'main' })), 'pulls-body', 'no title')
  // One spelling of the JSON: a duplicate key a host may read the other way, whitespace, an escape.
  denies(pulls(`{"title":"t","head":"aos/${RUN}/feature","base":"main","head":"main"}`), 'pulls-body', 'a duplicate head')
  denies(pulls(`{"title":"t","head":"main","base":"main","head":"aos/${RUN}/feature"}`), 'pulls-body', 'a duplicate head, the other order')
  denies(pulls(JSON.stringify(PR, null, 2)), 'pulls-body', 'pretty-printed')
  denies(pulls(`{"title":"t","head":"\\u0061os/${RUN}/feature","base":"main"}`), 'pulls-body', 'an escape stringify would not write')
  denies(pulls(`\ufeff${body}`), 'pulls-body', 'a byte-order mark')
  denies(pulls('[]'), 'pulls-body', 'an array')
  denies(pulls('not json'), 'pulls-body', 'not json')
  const invalidUtf8 = new Uint8Array([...bytes(body.slice(0, -2)), 0xc0, 0xae, 0x22, 0x7d])
  denies(decide(PUBLISH, request('POST', 'http://api.github.com/repos/op/fixture/pulls', { 'content-type': 'application/json', 'content-length': String(invalidUtf8.length) }, invalidUtf8)), 'pulls-body', 'not UTF-8')
  // Its size, its framing, its type, no encoding.
  const big = JSON.stringify({ ...PR, body: 'x'.repeat(MAX_PULLS_BODY) })
  denies(pulls(big), 'body', 'over 64 KiB')
  const atLimit = JSON.stringify({ ...PR, body: 'x'.repeat(MAX_PULLS_BODY - JSON.stringify({ ...PR, body: '' }).length) })
  assert.equal(bytes(atLimit).length, MAX_PULLS_BODY)
  allows(pulls(atLimit), 'github-pulls', 'exactly 64 KiB')
  denies(decide(PUBLISH, request('POST', 'http://api.github.com/repos/op/fixture/pulls', { 'content-type': 'application/json', 'transfer-encoding': 'chunked' }, bytes(body))), 'body', 'chunked')
  denies(pulls(body, { 'content-type': 'text/plain' }), 'content-type', 'text/plain')
  denies(pulls(body, { 'content-type': 'application/json; charset=latin1' }), 'content-type', 'another charset')
  denies(pulls(body, { 'content-encoding': 'gzip' }), 'content-encoding', 'gzip')
  // Only POST, only /pulls of the bound repository.
  denies(decide(PUBLISH, request('GET', 'http://api.github.com/repos/op/fixture/pulls')), 'method', 'GET pulls')
  denies(pulls(body, {}, 'http://api.github.com/repos/op/other/pulls'), 'repo', "another repository's pulls")
  denies(pulls(body, {}, 'http://api.github.com/repos/op/fixture/pulls?state=open'), 'query', 'pulls with a query')
  for (const path of [
    '/repos/op/fixture/pulls/1/merge',
    '/repos/op/fixture/pulls/1',
    '/repos/op/fixture/issues',
    '/repos/op/fixture.git/pulls',
    // Four segments ending in pulls, the bound repository in the middle two: only /repos/ is the route.
    '/orgs/op/fixture/pulls',
    '/op/op/fixture/pulls',
    '/user',
    '/installation/token',
    '/repos/op/fixture/actions/secrets',
    '/graphql',
  ]) {
    denies(pulls(body, {}, `http://api.github.com${path}`), 'no-route', path)
  }
  // The pulls profile is publish's: git-fetch on the API host is no grant of it.
  denies(decide(PUBLISH, request('GET', 'http://api.github.com/op/fixture/info/refs?service=git-upload-pack')), 'not-granted', 'fetch on the API host')
  // And the exec grant never reaches it.
  denies(decide(EXEC, request('POST', 'http://api.github.com/repos/op/fixture/pulls', { 'content-type': 'application/json', 'content-length': '2' }, bytes('{}'))), 'not-allowed', 'pulls on exec')
})

test('a host not in allow, a non-443 upstream and CONNECT are denied', () => {
  for (const host of ['example.com', 'github.com.evil.example', 'evilgithub.com', 'api.github.com', 'npmjs.org', 'sub.registry.npmjs.org', 'registry.npmjs.org.example']) {
    denies(decide(EXEC, request('GET', `http://${host}/`)), 'not-allowed', host)
  }
  // The allow list is compared in the one spelling host.ts gives a name.
  allows(decide(EXEC, request('GET', 'http://Registry.NPMJS.org./react')), 'allow-host', 'another spelling of an allowed host')
  // Ports: none or 443, as the image's insteadOf leaves an https URL's.
  allows(decide(EXEC, request('GET', 'http://registry.npmjs.org:443/react', { host: 'registry.npmjs.org:443' })), 'allow-host', 'an explicit 443')
  allows(decide(EXEC, request('GET', 'https://registry.npmjs.org/react')), 'allow-host', 'https in absolute form')
  for (const port of ['80', '8443', '22', '0443', '443 ', '', '65536', '-1', '4430']) {
    denies(decide(EXEC, request('GET', `http://registry.npmjs.org:${port}/react`)), port.includes(' ') ? 'target' : 'port', `port ${JSON.stringify(port)}`)
  }
  denies(decide(EXEC, request('GET', 'http://github.com:8443/op/fixture.git/info/refs?service=git-upload-pack')), 'port', 'a bound host on another port')
  // CONNECT, whatever it names: an allowed host, a bound one, in any case.
  for (const [method, target] of [
    ['CONNECT', 'registry.npmjs.org:443'],
    ['CONNECT', 'github.com:443'],
    ['CONNECT', '192.168.5.2:8766'],
    ['CONNECT', 'http://github.com/'],
    ['connect', 'github.com:443'],
    ['Connect', 'github.com:443'],
  ] as const) {
    denies(decide(PUBLISH, request(method, target)), 'use-route', `${method} ${target}`)
    denies(decide(EXEC, request(method, target)), 'use-route', `${method} ${target}`)
  }
  // Names that are no egress host, and addresses, are refused by host.ts's reason.
  for (const [host, refusal] of [
    ['192.168.5.2', 'ip-literal'],
    ['127.0.0.1', 'ip-literal'],
    ['[::1]', 'ip-literal'],
    ['2130706433', 'ip-literal'],
    ['0x7f.1', 'ip-literal'],
    ['host.lima.internal', 'special-use'],
    ['host.docker.internal', 'special-use'],
    ['localhost', 'special-use'],
    ['printer', 'single-label'],
    ['nas.home', 'special-use'],
    ['', 'empty'],
  ] as const) {
    const decision = decide(EXEC, request('GET', `http://${host}/`))
    denies(decision, 'not-a-host', host)
    assert.equal(decision.verdict === 'deny' ? decision.hostRefusal : undefined, refusal, host)
  }
  denies(decide(EXEC, request('GET', 'http://[::1]:443/')), 'not-a-host', '[::1]:443')
})

test('the host is judged before the port: a probe of the Mac\'s loopback is not-a-host whatever port it names, a wrong port names its host, and a CONNECT or userinfo names where it was headed', () => {
  // The targets the image's self-test and the Phase 2 exit name (E9, L2): pmmcp and the control plane, by address and by name.
  for (const [target, refusal] of [
    ['http://192.168.5.2:8766/mcp', 'ip-literal'],
    // With no path after the host: the host is read first, so it is not-a-host, never a target deny that names nothing.
    ['http://192.168.5.2:8766', 'ip-literal'],
    ['http://192.168.5.2:8766?x', 'ip-literal'],
    ['http://host.lima.internal:8766', 'special-use'],
    ['https://192.168.5.2:7777/', 'ip-literal'],
    ['http://192.168.5.2:443/', 'ip-literal'],
    ['http://127.0.0.1:7777/', 'ip-literal'],
    ['http://host.lima.internal:8766/mcp', 'special-use'],
    ['http://host.docker.internal:8766/mcp', 'special-use'],
    ['http://localhost:3128/', 'special-use'],
    ['http://printer:8080/', 'single-label'],
    ['http://router.lan:80/', 'special-use'],
  ] as const) {
    for (const grant of [EXEC, PUBLISH]) {
      const decision = decide(grant, request('GET', target))
      denies(decision, 'not-a-host', target)
      assert.equal(decision.verdict === 'deny' ? decision.hostRefusal : undefined, refusal, target)
      assert.equal(decision.host, undefined, target)
    }
  }
  // An egress host on another port: refused for the port, with the host it named, bound or not, and no binding.
  for (const [target, host] of [
    ['https://example.com:8080/', 'example.com'],
    ['http://registry.npmjs.org:80/react', 'registry.npmjs.org'],
    ['http://GitHub.com:8443/op/fixture.git/info/refs?service=git-upload-pack', 'github.com'],
  ] as const) {
    const decision = decide(EXEC, request('GET', target))
    denies(decision, 'port', target)
    assert.equal(decision.host, host, target)
    assert.equal(decision.bindingId, undefined, target)
    assert.equal(decision.verdict === 'deny' ? decision.hostRefusal : 'x', undefined, target)
    const parsed = parseTarget(target)
    assert.equal(!parsed.ok && parsed.reason === 'port' ? parsed.host : undefined, host, target)
  }
  // A CONNECT's authority and a userinfo target's host past the userinfo are
  // read the same way, for the row alone: the host, or why it is none.
  for (const [authority, named] of [
    ['192.168.5.2:8766', { hostRefusal: 'ip-literal' }],
    ['192.168.5.2', { hostRefusal: 'ip-literal' }],
    ['[::1]:8766', { hostRefusal: 'ip-literal' }],
    ['host.docker.internal:8766', { hostRefusal: 'special-use' }],
    ['GitHub.com.:443', { host: 'github.com' }],
    ['user:pw@github.com:443', { host: 'github.com' }],
    ['github.com@192.168.5.2:8766', { hostRefusal: 'ip-literal' }],
    ['192.168.5.2:8766@github.com', { host: 'github.com' }],
    // Past the last `@`, as a URL parser reads it, not the first.
    ['x@github.com@192.168.5.2:8766', { hostRefusal: 'ip-literal' }],
    ['github.com:443:443', { hostRefusal: 'port' }],
    ['', { hostRefusal: 'empty' }],
    ['user@', { hostRefusal: 'empty' }],
  ] as const) {
    assert.deepEqual(namedHost(authority), named, authority)
    const decision = decide(EXEC, request('CONNECT', authority))
    denies(decision, 'use-route', `CONNECT ${authority}`)
    const expected: { readonly host?: string; readonly hostRefusal?: string } = named
    assert.deepEqual(
      { host: decision.host, hostRefusal: decision.verdict === 'deny' ? decision.hostRefusal : 'allowed' },
      { host: expected.host, hostRefusal: expected.hostRefusal },
      authority,
    )
  }
  // Text that is no authority names nothing.
  for (const text of ['http://192.168.5.2:8766/', '192.168.5.2:8766/', '192.168.5.2:8766/mcp', 'github.com?x', 'github.com#x']) {
    assert.equal(namedHost(text), undefined, text)
    // So a CONNECT to it is a use-route deny that names no destination, neither a host nor a host refusal.
    const decision = decide(EXEC, request('CONNECT', text))
    denies(decision, 'use-route', `CONNECT ${text}`)
    assert.deepEqual({ host: decision.host, hostRefusal: decision.verdict === 'deny' ? decision.hostRefusal : 'allowed' }, { host: undefined, hostRefusal: undefined }, text)
  }
  // A target with no path after its host is read with path /, never refused for the path it lacks.
  for (const target of ['http://github.com', 'http://github.com?x', 'http://registry.npmjs.org']) {
    const parsed = parseTarget(target)
    assert.equal(parsed.ok ? parsed.path : parsed.reason, '/', target)
  }
  // The host before the target's length, its characters and a fragment: a
  // probe that also holds a fragment (node:http delivers `#x` as written), a
  // character no request line has, or more than MAX_TARGET is refused for its
  // host or its userinfo, never as a target deny that a typo of a real host
  // shares. The authority ends at a `#`, as a URL parser reads it.
  const long = 'a'.repeat(MAX_TARGET)
  for (const [target, reason, named] of [
    ['http://192.168.5.2:8766/mcp#x', 'not-a-host', { hostRefusal: 'ip-literal' }],
    ['http://192.168.5.2:8766#x', 'not-a-host', { hostRefusal: 'ip-literal' }],
    ['http://host.lima.internal:8766/mcp#x', 'not-a-host', { hostRefusal: 'special-use' }],
    [`http://192.168.5.2:8766/${long}`, 'not-a-host', { hostRefusal: 'ip-literal' }],
    [`http://host.docker.internal:8766/mcp?${long}#x`, 'not-a-host', { hostRefusal: 'special-use' }],
    ['http://192.168.5.2:8766/m\ncp', 'not-a-host', { hostRefusal: 'ip-literal' }],
    ['http://192.168.5.2:8766/m cp', 'not-a-host', { hostRefusal: 'ip-literal' }],
    ['http://x@192.168.5.2:8766/mcp#x', 'second-host', { hostRefusal: 'ip-literal' }],
    [`http://x@github.com/${long}`, 'second-host', { host: 'github.com' }],
  ] as const) {
    for (const grant of [EXEC, PUBLISH]) {
      const decision = decide(grant, request('GET', target))
      denies(decision, reason, JSON.stringify(target.slice(0, 64)))
      const expected: { readonly host?: string; readonly hostRefusal?: string } = named
      assert.deepEqual(
        { host: decision.host, hostRefusal: decision.verdict === 'deny' ? decision.hostRefusal : 'allowed' },
        { host: expected.host, hostRefusal: expected.hostRefusal },
        target.slice(0, 64),
      )
    }
  }
  // An egress host's target that no request line holds is a target deny,
  // and names no host: a typo of a real host, never a probe.
  for (const target of ['http://registry.npmjs.org/react#readme', 'http://github.com#x', 'http://github.com:8766#x', `http://registry.npmjs.org/${long}`, 'http://registry.npmjs.org/re\tact']) {
    const decision = decide(EXEC, request('GET', target))
    denies(decision, 'target', JSON.stringify(target.slice(0, 64)))
    assert.deepEqual({ host: decision.host, hostRefusal: decision.verdict === 'deny' ? decision.hostRefusal : 'allowed' }, { host: undefined, hostRefusal: undefined }, target.slice(0, 64))
  }
  // The port before the path: a wrong port with a dot segment is a port deny, and nothing of its path was read.
  denies(decide(EXEC, request('GET', 'http://registry.npmjs.org:8080/a/../b')), 'port', 'a wrong port and a dot segment')
  // And a path deny names the host whose path it refused.
  for (const target of ['http://registry.npmjs.org/a/../b', 'http://github.com/op/fixture.git%2finfo/refs', 'http://github.com//op', 'http://github.com/a\\b', `http://github.com/${'a'.repeat(8192)}`]) {
    const decision = decide(EXEC, request('GET', target))
    denies(decision, 'path', target)
    assert.equal(decision.host, new URL(target).hostname, target)
    assert.equal(decision.bindingId, undefined, target)
  }
})

test('every deny decide() gives is a proxy.decision row with exactly the host, binding and host refusal it names, and a path only where it read one', () => {
  const prefix = `refs/heads/aos/${RUN}/`
  const RECEIVE = { 'content-type': 'application/x-git-receive-pack-request' }
  const PUSH_TARGET = 'http://github.com/op/fixture.git/git-receive-pack'
  const PULLS_TARGET = 'http://api.github.com/repos/op/fixture/pulls'
  /** What a deny names, exactly: each case's own, not a union over the cases of its reason. */
  interface Named { readonly host?: string; readonly bindingId?: string; readonly hostRefusal?: string }
  const registry = { host: 'registry.npmjs.org' }
  const github = { host: 'github.com' }
  const routed = { host: 'github.com', bindingId: 'github' }
  const api = { host: 'api.github.com', bindingId: 'github-api' }
  // Each case: its label (its reason first), the decision, the request's method and target as the session read them, and what the deny names.
  const cases: ReadonlyArray<readonly [string, EgressDecision, string | undefined, string | undefined, Named]> = [
    ['malformed, a method that is no text', decide(EXEC, { method: 1, target: 'http://registry.npmjs.org/', headers: {} } as unknown as EgressRequest), undefined, undefined, {}],
    ['malformed, headers that are no record', decide(EXEC, request('GET', 'http://registry.npmjs.org/', ['host', 'x'] as unknown as EgressHeaders)), 'GET', 'http://registry.npmjs.org/', registry],
    ['malformed, more read than the push declares', decide(PUBLISH, request('POST', PUSH_TARGET, { ...RECEIVE, 'content-length': '4' }, bytes(commandList([[OLD, NEW, `${prefix}f`]])))), 'POST', PUSH_TARGET, routed],
    // A CONNECT names where it was headed: a probe of pmmcp is told from a tunnel to a real host.
    ['use-route, pmmcp by address', decide(EXEC, request('CONNECT', '192.168.5.2:8766')), 'CONNECT', '192.168.5.2:8766', { hostRefusal: 'ip-literal' }],
    ['use-route, the control plane by address', decide(EXEC, request('CONNECT', '192.168.5.2:7777')), 'CONNECT', '192.168.5.2:7777', { hostRefusal: 'ip-literal' }],
    ['use-route, pmmcp by name', decide(EXEC, request('CONNECT', 'host.lima.internal:8766')), 'CONNECT', 'host.lima.internal:8766', { hostRefusal: 'special-use' }],
    ['use-route, the loopback in IPv6', decide(EXEC, request('CONNECT', '[::1]:8766')), 'CONNECT', '[::1]:8766', { hostRefusal: 'ip-literal' }],
    ['use-route, a real host', decide(EXEC, request('CONNECT', 'GitHub.com:443')), 'CONNECT', 'GitHub.com:443', github],
    ['use-route, a host not in the grant', decide(EXEC, request('CONNECT', 'example.com:443')), 'CONNECT', 'example.com:443', { host: 'example.com' }],
    ['use-route, in lower case', decide(EXEC, request('connect', '192.168.5.2:8766')), 'connect', '192.168.5.2:8766', { hostRefusal: 'ip-literal' }],
    ['use-route, a target that is no authority', decide(EXEC, request('CONNECT', 'http://192.168.5.2:8766/')), 'CONNECT', 'http://192.168.5.2:8766/', {}],
    ['not-allowed', decide(EXEC, request('GET', 'http://example.com/')), 'GET', 'http://example.com/', { host: 'example.com' }],
    ['repo', decide(EXEC, request('GET', 'http://github.com/evil/other.git/info/refs?service=git-upload-pack')), 'GET', 'http://github.com/evil/other.git/info/refs?service=git-upload-pack', github],
    ['not-granted', decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-receive-pack')), 'GET', 'http://github.com/op/fixture.git/info/refs?service=git-receive-pack', routed],
    ['body, on a credential-free host', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-length': '0' })), 'GET', 'http://registry.npmjs.org/react', registry],
    ['body, on a route', decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', { 'content-length': '2' })), 'GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', routed],
    ['body, framed two ways', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-length': '2', 'transfer-encoding': 'chunked' })), 'GET', 'http://registry.npmjs.org/react', registry],
    ['content-type, sent twice', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-type': ['a/b', 'c/d'] })), 'GET', 'http://registry.npmjs.org/react', registry],
    ['content-type, on a route', decide(EXEC, request('POST', 'http://github.com/op/fixture/git-upload-pack', { ...UPLOAD_HEADERS, 'content-type': 'text/plain' })), 'POST', 'http://github.com/op/fixture/git-upload-pack', routed],
    ['content-encoding, sent twice', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-encoding': ['gzip', 'br'] })), 'GET', 'http://registry.npmjs.org/react', registry],
    ['content-encoding, on a route', push(commandList([[OLD, NEW, `${prefix}f`]]), { 'content-encoding': 'gzip' }), 'POST', PUSH_TARGET, routed],
    ['override-header', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'x-http-method-override': 'DELETE' })), 'GET', 'http://registry.npmjs.org/react', registry],
    ['override-header, on a route', decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', { 'x-original-url': '/x' })), 'GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', github],
    // A target decide() cannot read names no destination at all.
    ['target, origin-form', decide(EXEC, request('GET', '/react', { host: '192.168.5.2:8766' })), 'GET', '/react', {}],
    ['target, an upper-case scheme', decide(EXEC, request('GET', 'HTTP://192.168.5.2:8766/')), 'GET', 'HTTP://192.168.5.2:8766/', {}],
    ['not-a-host, pmmcp by address', decide(EXEC, request('GET', 'http://192.168.5.2:8766/mcp')), 'GET', 'http://192.168.5.2:8766/mcp', { hostRefusal: 'ip-literal' }],
    ['not-a-host, the control plane by address', decide(EXEC, request('GET', 'https://192.168.5.2:7777/')), 'GET', 'https://192.168.5.2:7777/', { hostRefusal: 'ip-literal' }],
    ['not-a-host, pmmcp by name', decide(EXEC, request('GET', 'http://host.lima.internal:8766/mcp')), 'GET', 'http://host.lima.internal:8766/mcp', { hostRefusal: 'special-use' }],
    ['port', decide(EXEC, request('GET', 'https://example.com:8080/')), 'GET', 'https://example.com:8080/', { host: 'example.com' }],
    ['port, on a bound host', decide(EXEC, request('GET', 'http://github.com:8443/op/fixture.git/info/refs?service=git-upload-pack')), 'GET', 'http://github.com:8443/op/fixture.git/info/refs?service=git-upload-pack', github],
    // Userinfo names the host past it, as a URL parser reads it, or why it is none.
    ['second-host, userinfo', decide(EXEC, request('GET', 'http://user@registry.npmjs.org/')), 'GET', 'http://user@registry.npmjs.org/', registry],
    ['second-host, userinfo before pmmcp', decide(EXEC, request('GET', 'http://registry.npmjs.org@192.168.5.2:8766/mcp')), 'GET', 'http://registry.npmjs.org@192.168.5.2:8766/mcp', { hostRefusal: 'ip-literal' }],
    ['second-host, userinfo before pmmcp by name', decide(EXEC, request('GET', 'http://x:y@host.lima.internal:8766/')), 'GET', 'http://x:y@host.lima.internal:8766/', { hostRefusal: 'special-use' }],
    ['second-host, the Host header', decide(EXEC, request('GET', 'http://registry.npmjs.org/', { host: 'example.com' })), 'GET', 'http://registry.npmjs.org/', registry],
    ['path', decide(EXEC, request('GET', 'http://registry.npmjs.org/a/../b')), 'GET', 'http://registry.npmjs.org/a/../b', registry],
    ['path, on a bound host', decide(EXEC, request('GET', 'http://github.com/op/%2e%2e/x')), 'GET', 'http://github.com/op/%2e%2e/x', github],
    ['no-route', decide(EXEC, request('GET', 'http://github.com/user/keys')), 'GET', 'http://github.com/user/keys', github],
    // The method is read once the target is, so a deny for it names where the request was headed.
    ['method, no token', decide(EXEC, request('get', 'http://registry.npmjs.org/')), 'get', 'http://registry.npmjs.org/', registry],
    ['method, a token with a hyphen', decide(EXEC, request('M-SEARCH', 'http://example.com/')), 'M-SEARCH', 'http://example.com/', { host: 'example.com' }],
    ['method, on a credential-free host', decide(EXEC, request('POST', 'http://registry.npmjs.org/react', { 'content-length': '2' })), 'POST', 'http://registry.npmjs.org/react', registry],
    ['method, on a route', decide(EXEC, request('POST', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack')), 'POST', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', github],
    ['query', decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-archive')), 'GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-archive', github],
    ['push-commands', push(pkt('not a command') + '0000'), 'POST', PUSH_TARGET, routed],
    ['push-ref', push(commandList([[OLD, NEW, 'refs/heads/main']])), 'POST', PUSH_TARGET, routed],
    ['push-delete', push(commandList([[OLD, ZERO, `${prefix}f`]])), 'POST', PUSH_TARGET, routed],
    ['pulls-body', pulls(JSON.stringify({ ...PR, draft: 'yes', extra: 1 })), 'POST', PULLS_TARGET, api],
    ['pulls-head', pulls(JSON.stringify({ ...PR, head: 'evil:x' })), 'POST', PULLS_TARGET, api],
  ]
  const SERVICES = new Map([
    ['service=git-upload-pack', 'git-upload-pack'],
    ['service=git-receive-pack', 'git-receive-pack'],
  ])
  const hosted = new Set<string>()
  const bound = new Set<string>()
  const refusing = new Set<string>()
  const pathed = new Set<string>()
  for (const [label, decision, method, target, named] of cases) {
    assert.equal(decision.verdict, 'deny', label)
    if (decision.verdict !== 'deny') continue
    assert.ok(label.startsWith(decision.reason), `${label} was denied ${decision.reason}`)
    assert.deepEqual(
      { host: decision.host, bindingId: decision.bindingId, hostRefusal: decision.hostRefusal },
      { host: named.host, bindingId: named.bindingId, hostRefusal: named.hostRefusal },
      label,
    )
    // The path the session keeps: the one parseTarget read, when it read one
    // (session.ts pathFields), and none for a reason PROXY_DENIES_BEFORE_PATH
    // names, which must therefore never be given with one read.
    const parsed = target === undefined ? undefined : parseTarget(target)
    const path =
      parsed?.ok === true
        ? {
            path: recordable(parsed.path, EGRESS_PATH_BYTES),
            pathBytes: parsed.path.length,
            queryBytes: parsed.query === undefined ? 0 : parsed.query.length + 1,
            ...(decision.reason !== 'query' && parsed.query !== undefined && parsed.path.endsWith('/info/refs') ? { service: SERVICES.get(parsed.query) } : {}),
          }
        : {}
    // The row the session (E8) writes from the decision, naming exactly what it named.
    const row = Object.fromEntries(
      Object.entries({
        schemaVersion: 1,
        grantId: 'grant_1',
        stage: 'policy',
        verdict: 'deny',
        reason: decision.reason,
        count: 1,
        method: method !== undefined && METHOD_SHAPE.test(method) ? method : undefined,
        host: decision.host,
        bindingId: decision.bindingId,
        hostRefusal: decision.hostRefusal,
        ...path,
        why: recordable(decision.why, EGRESS_WHY_BYTES),
      }).filter(([, value]) => value !== undefined),
    )
    const accepted = PAYLOAD_SCHEMAS['proxy.decision'].safeParse(row)
    assert.equal(accepted.success, true, `${label}: ${accepted.success ? '' : accepted.error.issues.map((i) => i.message).join('; ')}`)
    if (decision.host !== undefined) hosted.add(decision.reason)
    if (decision.bindingId !== undefined) bound.add(decision.reason)
    if (decision.hostRefusal !== undefined) refusing.add(decision.reason)
    if ('path' in path) pathed.add(decision.reason)
  }
  // Every deny reason was given, and the rows' tables are exactly decide()'s:
  // every reason not before the host was given with a host, every reason the
  // rows let name a binding was given with one, every reason the rows let say
  // why a host was none was given with one, and every reason not before the
  // path was given with a path read, but `path`, whose path parseTarget
  // refused and the session therefore keeps none of.
  const outside = (table: readonly string[]): string[] => PROXY_DENY_REASONS.filter((r) => !table.includes(r)).sort()
  assert.deepEqual(new Set(cases.map(([, d]) => d.reason)), new Set(PROXY_DENY_REASONS))
  assert.deepEqual([...hosted].sort(), outside(PROXY_DENIES_BEFORE_HOST))
  assert.deepEqual([...bound].sort(), [...PROXY_DENIES_ON_A_ROUTE].sort())
  assert.deepEqual([...refusing].sort(), [...PROXY_DENIES_BY_HOST_REFUSAL].sort())
  assert.deepEqual([...pathed, 'path'].sort(), outside(PROXY_DENIES_BEFORE_PATH))
  for (const reason of PROXY_DENIES_BEFORE_PATH) assert.equal(pathed.has(reason), false, `${reason} was given with a path read`)
})

test('path normalisation refuses %2f, %2e, .., a double slash and a second host, and never rewrites a path it admits', () => {
  for (const path of [
    '/op/fixture.git%2finfo/refs',
    '/a%2Fb',
    '/a/%2e%2e/b',
    '/a/%2E/b',
    '/a/.%2e/b',
    '/a/../b',
    '/a/./b',
    '/..',
    '/a/..',
    '//a',
    '/a//b',
    '/a/b//',
    '/a\\b',
    '/a%5cb',
    '/a%5Cb',
    '/a%252e%252e/b',
    '/a%00b',
    '/a%0ab',
    '/a%7fb',
    '/a%c0%ae%c0%ae/b',
    '/a%e0%80%ae/b',
    '/a%ffb',
    '/a%2',
    '/a%zzb',
    '/a%',
    `/${'a'.repeat(8192)}`,
  ]) {
    denies(decide(EXEC, request('GET', `http://registry.npmjs.org${path}`)), 'path', path)
    // A bound host's request is refused for its path before any route reads it.
    denies(decide(EXEC, request('GET', `http://github.com${path}`)), 'path', `github.com${path}`)
  }
  // A second host: userinfo, in any form, and a Host header naming another host or port.
  for (const authority of ['user@registry.npmjs.org', 'registry.npmjs.org@example.com', 'registry.npmjs.org:443@example.com', ':@registry.npmjs.org', '@registry.npmjs.org']) {
    denies(decide(EXEC, request('GET', `http://${authority}/react`)), 'second-host', authority)
  }
  for (const host of ['example.com', 'github.com', 'registry.npmjs.org:443', 'registry.npmjs.org:80', '192.168.5.2', '[::1]', 'registry.npmjs.org:443:443', '']) {
    denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { host })), 'second-host', `Host: ${host}`)
  }
  denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { host: ['registry.npmjs.org', 'example.com'] })), 'second-host', 'two Host headers')
  allows(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { Host: 'REGISTRY.npmjs.org.' })), 'allow-host', 'Host in another spelling and case of name')
  // Only absolute form: origin form, authority form, another scheme, a fragment, a space.
  for (const target of ['/react', 'registry.npmjs.org/react', 'registry.npmjs.org:443', 'ftp://registry.npmjs.org/', 'HTTP://registry.npmjs.org/', 'ws://registry.npmjs.org/', 'http:/registry.npmjs.org/', 'http://registry.npmjs.org/react#x', 'http://registry.npmjs.org/re act', '*', '', 'http://registry.npmjs.org/\u00e9']) {
    denies(decide(EXEC, request('GET', target)), 'target', JSON.stringify(target))
  }
  // Admitted paths are sent as written, percent-encodings and all; an empty path is '/'.
  for (const [target, originForm] of [
    ['http://registry.npmjs.org/react', '/react'],
    ['http://registry.npmjs.org', '/'],
    ['http://registry.npmjs.org?x=1', '/?x=1'],
    ['http://registry.npmjs.org/%40scope/pkg', '/%40scope/pkg'],
    ['http://registry.npmjs.org/caf%C3%A9', '/caf%C3%A9'],
    ['http://registry.npmjs.org/a.b/c..d/.e', '/a.b/c..d/.e'],
    ['http://registry.npmjs.org/-/v1/search?text=a%2Fb&size=2', '/-/v1/search?text=a%2Fb&size=2'],
  ] as const) {
    assert.equal(allows(decide(EXEC, request('GET', target)), 'allow-host', target).path, originForm, target)
    const parsed = parseTarget(target)
    assert.equal(parsed.ok && parsed.originForm, originForm)
  }
})

// ── around them ──────────────────────────────────────────────────────────────

test('a credential-free host admits GET and HEAD with no body, on any path the normaliser admits, and nothing else', () => {
  allows(decide(EXEC, request('GET', 'http://registry.npmjs.org/react/-/react-19.0.0.tgz')), 'allow-host', 'GET')
  const head = allows(decide(EXEC, request('HEAD', 'http://registry.npmjs.org/react')), 'allow-host', 'HEAD')
  assert.equal(head.method, 'HEAD')
  const decision = decide(EXEC, request('GET', 'http://registry.npmjs.org/react'))
  assert.equal(decision.verdict === 'allow' ? decision.bindingId : 'x', undefined, 'no credential on a free host')
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE']) {
    denies(decide(EXEC, request(method, 'http://registry.npmjs.org/react', { 'content-length': '2' })), 'method', method)
  }
  for (const method of ['get', 'G E T', 'GET\r\n', '', 'AVERYLONGMETHODNAME']) {
    denies(decide(EXEC, request(method, 'http://registry.npmjs.org/react')), 'method', JSON.stringify(method))
  }
  denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-length': '0' })), 'body', 'GET with a Content-Length')
  denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'transfer-encoding': 'chunked' })), 'body', 'GET chunked')
  // A free host is free on every path, git's included, but read-only: a POST to upload-pack is a method it does not take.
  allows(decide(EXEC, request('GET', 'http://registry.npmjs.org/op/fixture.git/info/refs?service=git-receive-pack')), 'allow-host', 'git shape on a free host')
  denies(decide(EXEC, request('POST', 'http://registry.npmjs.org/op/fixture.git/git-upload-pack', UPLOAD_HEADERS)), 'method', 'upload-pack on a free host')
})

test('the command list is read as receive-pack reads it, narrower and never wider: lengths, flush, shallow lines, capabilities, push-cert, push-options and the 64 KiB bound', () => {
  const prefix = `refs/heads/aos/${RUN}/`
  const one = commandList([[OLD, NEW, `${prefix}f`]])
  const scan = scanCommandList(bytes(one))
  assert.equal(scan.status, 'complete')
  if (scan.status !== 'complete') throw new Error('unreachable')
  assert.equal(scan.end, one.length)
  assert.deepEqual(scan.commands, [{ old: OLD, new: NEW, ref: `${prefix}f` }])
  assert.deepEqual(scan.capabilities, ['report-status', 'side-band-64k', 'quiet', 'object-format=sha1', 'agent=git/2.47.1'])
  // Bytes after the flush are not read: the pack is the host's.
  const followed = scanCommandList(bytes(one + PACK))
  assert.equal(followed.status === 'complete' && followed.end, one.length)
  // A trailing LF per line, as some clients write it, and SHA-256 names.
  const lf = pkt(`${OLD} ${NEW} ${prefix}f\0 report-status\n`) + pkt(`${OLD} ${NEW} ${prefix}g\n`) + '0000'
  const lfScan = scanCommandList(bytes(lf))
  assert.deepEqual(lfScan.status === 'complete' && lfScan.commands.map((c) => c.ref), [`${prefix}f`, `${prefix}g`])
  assert.equal(scanCommandList(bytes(commandList([['c'.repeat(64), 'd'.repeat(64), `${prefix}f`]]))).status, 'complete')
  // Shallow lines before the commands, as a shallow clone pushes.
  allows(push(pkt(`shallow ${'e'.repeat(40)}`) + one), 'git-push', 'a push from a shallow clone')
  // Every capability a push may ask for, as git and its peers write them.
  for (const caps of [
    ' report-status-v2 side-band-64k quiet object-format=sha1 agent=git/2.47.1',
    ' report-status atomic ofs-delta session-id=a1b2c3 object-format=sha256 agent=JGit/7.1',
    '',
    ' ',
  ]) {
    allows(push(commandList([[OLD, NEW, `${prefix}f`]], caps)), 'git-push', `capabilities ${JSON.stringify(caps)}`)
  }
  // The push the review probed: push-options=1 on the first command, then,
  // after the flush, an option line receive-pack would hand to the host's
  // hooks. Refused on the list alone; nothing past the flush is read.
  const optioned = commandList([[OLD, NEW, `${prefix}f`]], ' report-status side-band-64k push-options=1')
  const optionedBody = optioned + pkt('ci.variable=DEPLOY=1') + '0000' + PACK
  denies(
    decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'content-length': String(optionedBody.length) }, bytes(optioned))),
    'push-commands',
    'push-options=1, then an option line',
  )
  // The same push with push-options inside agent's value, after a tab, an LF
  // in the middle of the line, or a CR. Split on SP alone it is one valued
  // capability; receive-pack splits on git's isspace, which counts all
  // three, and reads push options. Only the control character refuses it.
  for (const [separator, label] of [
    ['\t', 'a tab'],
    ['\n', 'an LF before the end of the pkt-line'],
    ['\r', 'a CR'],
  ] as const) {
    const list = commandList([[OLD, NEW, `${prefix}f`]], ` report-status agent=git/2.47.1${separator}push-options`)
    assert.ok(!list.slice(0, -4).endsWith('\n'), 'the separator is inside the line, not the trailing LF dropped')
    const body = list + pkt('ci.variable=DEPLOY=1') + '0000' + PACK
    assert.equal(scanCommandList(bytes(list)).status, 'invalid', label)
    denies(
      decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'content-length': String(body.length) }, bytes(list))),
      'push-commands',
      `push-options after ${label} in agent's value, then an option line`,
    )
  }

  // Every prefix of a list is incomplete, never complete or wrong.
  for (let cut = 0; cut < one.length; cut++) assert.equal(scanCommandList(bytes(one.slice(0, cut))).status, 'incomplete', `cut at ${String(cut)}`)
  for (const [list, label] of [
    [`00A9${one.slice(4)}`, 'an upper-case hex length'],
    [`0001${one}`, 'a delim-pkt'],
    [`0002${one}`, 'a response-end-pkt'],
    [`0003${one}`, 'a length of three'],
    [`0004${one}`, 'an empty pkt-line'],
    [`zzzz${one.slice(4)}`, 'a length that is no hex'],
    [pkt(`${OLD} ${NEW}`) + '0000', 'a command with no ref'],
    [pkt(`${OLD}  ${NEW} ${prefix}f`) + '0000', 'two spaces'],
    [pkt(`${OLD} ${NEW} ${prefix}f extra`) + '0000', 'a fourth field'],
    [pkt(`${OLD.toUpperCase()} ${NEW} ${prefix}f`) + '0000', 'an upper-case object name'],
    [pkt(`${OLD.slice(1)} ${NEW} ${prefix}f`) + '0000', 'a short object name'],
    [pkt(`${OLD} ${'d'.repeat(64)} ${prefix}f`) + '0000', 'mixed hash lengths'],
    [pkt('push-cert\0 report-status') + '0000', 'a signed push'],
    [pkt('push-cert') + '0000', 'a signed push, no capabilities'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status push-options'), 'push options'],
    // receive-pack reads `name=value` as `name` (parse_feature_request), so these ask for push options too.
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status side-band-64k push-options=1'), 'push-options=1'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status push-options='), 'push-options='],
    [commandList([[OLD, NEW, `${prefix}f`]], ' push-options=1 report-status'), 'push-options=1 first'],
    // Only the capabilities a push needs: a server's own, a signed push's, a later git's, a record's.
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status delete-refs'), 'a capability only a server advertises'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status push-cert=1762700000-abc'), 'push-cert as a capability'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status x-future-capability'), 'an unknown capability'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status constructor'), 'a capability named constructor'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status =1'), 'a value with no name'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' Report-Status'), 'a capability in another case'],
    // Each in the one shape git writes it: bare, or with a value that is not empty; and once.
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status quiet=1'), 'a bare capability with a value'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status agent'), 'a valued capability bare'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status agent='), 'a valued capability with an empty value'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status report-status'), 'a capability asked for twice'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' object-format=sha1 object-format=sha256'), 'a valued capability asked for twice'],
    [commandList([[OLD, NEW, `${prefix}f`]], ' report-status\tquiet'), 'a control character in a capability'],
    [one.slice(0, -4) + pkt(`${OLD} ${NEW} ${prefix}g\0 quiet`) + '0000', 'capabilities on a second command'],
    [one.slice(0, -4) + pkt(`shallow ${'e'.repeat(40)}`) + '0000', 'a shallow line after a command'],
    [pkt(`shallow ${'e'.repeat(40)}`) + '0000', 'shallow lines and no command'],
    [pkt(`shallow ${'e'.repeat(39)}`) + one, 'a short shallow line'],
    [pkt(`${OLD} ${NEW} ${prefix}\u00e9`) + '0000', 'a byte outside ASCII'],
  ] as const) {
    const result = scanCommandList(new TextEncoder().encode(list))
    assert.equal(result.status, 'invalid', label)
    denies(push(list), 'push-commands', label)
  }
  // The 64 KiB bound: a list that runs past it is invalid however its bytes are cut.
  const filler = Array.from({ length: 1000 }, (_, i) => [OLD, NEW, `${prefix}${'x'.repeat(80)}${String(i)}`] as const)
  const long = commandList(filler)
  assert.ok(long.length > MAX_COMMAND_LIST)
  assert.equal(scanCommandList(bytes(long)).status, 'invalid')
  assert.equal(scanCommandList(bytes(long.slice(0, MAX_COMMAND_LIST + 10))).status, 'invalid')
  assert.equal(scanCommandList(bytes(long.slice(0, MAX_COMMAND_LIST))).status, 'invalid')
  // Short of the line that crosses the bound it is still incomplete; once that
  // line's length is read it is invalid, before its bytes arrive.
  assert.equal(scanCommandList(bytes(long.slice(0, 1000))).status, 'incomplete')
  denies(push(long.slice(0, MAX_COMMAND_LIST)), 'push-commands', 'a list that does not end within 64 KiB')
  // A list that ends exactly at the bound is read whole.
  const fitting: (readonly [string, string, string])[] = []
  let text = ''
  for (let i = 0; ; i++) {
    const next = commandList([...fitting, [OLD, NEW, `${prefix}b${String(i)}`]])
    if (next.length > MAX_COMMAND_LIST) break
    fitting.push([OLD, NEW, `${prefix}b${String(i)}`])
    text = next
  }
  const [, , lastRef = ''] = fitting.at(-1) ?? []
  const exact = commandList([...fitting.slice(0, -1), [OLD, NEW, `${lastRef}${'y'.repeat(MAX_COMMAND_LIST - text.length)}`]])
  assert.equal(exact.length, MAX_COMMAND_LIST)
  allows(push(exact), 'git-push', 'a list of exactly 64 KiB')
  // An incomplete list is refused, not judged on what arrived.
  denies(push(one.slice(0, -4)), 'push-commands', 'a list with no flush')
})

test('git probes a large push with a flush alone: admitted only as the whole body', () => {
  const probe = { 'content-type': 'application/x-git-receive-pack-request', 'content-length': '4' }
  const decision = decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', probe, bytes('0000')))
  const allow = allows(decision, 'git-push', 'the probe')
  assert.deepEqual(allow.body, { length: 4, leadingBytes: 4 })
  denies(push('0000'), 'push-commands', 'a flush followed by a pack')
  denies(
    decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': probe['content-type'], 'transfer-encoding': 'chunked' }, bytes('0000'))),
    'push-commands',
    'a chunked flush, whose end nobody declared',
  )
})

test('leadingNeed asks for the command list of a push and the whole body of a pull request, and for nothing else; decide() refuses leading bytes it did not ask for, or none where it did', () => {
  const pushHead = request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'transfer-encoding': 'chunked' })
  assert.deepEqual(leadingNeed(PUBLISH, pushHead), { kind: 'command-list', max: MAX_COMMAND_LIST })
  const pr = bytes(JSON.stringify(PR))
  const prHead = request('POST', 'http://api.github.com/repos/op/fixture/pulls', { 'content-type': 'application/json', 'content-length': String(pr.length) })
  assert.deepEqual(leadingNeed(PUBLISH, prHead), { kind: 'whole-body', length: pr.length })
  // Nothing for a request decided on its head, allowed or denied.
  for (const [grant, head] of [
    [EXEC, pushHead],
    [PUBLISH, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-receive-pack')],
    [PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', UPLOAD_HEADERS)],
    [PUBLISH, { ...pushHead, headers: { ...pushHead.headers, 'content-encoding': 'gzip' } }],
    [PUBLISH, { ...prHead, headers: { ...prHead.headers, 'content-length': String(MAX_PULLS_BODY + 1) } }],
    [PUBLISH, request('CONNECT', 'github.com:443')],
    [EXEC, request('GET', 'http://registry.npmjs.org/react')],
  ] as const) {
    assert.deepEqual(leadingNeed(grant, head), { kind: 'none' }, `${head.method} ${head.target}`)
  }
  assert.deepEqual(leadingNeed(PUBLISH, null as unknown as EgressRequest), { kind: 'none' })
  // decide() wants exactly what leadingNeed() asked for.
  denies(decide(PUBLISH, pushHead), 'malformed', 'a push with nothing read')
  denies(decide(PUBLISH, prHead), 'malformed', 'a pull request with nothing read')
  denies(decide(PUBLISH, { ...prHead, leading: pr.subarray(0, -1) }), 'malformed', 'a pull request read short')
  denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', {}, bytes('x'))), 'malformed', 'bytes read for a GET')
  denies(decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', UPLOAD_HEADERS, bytes('0000'))), 'malformed', 'bytes read for a fetch')
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])
  denies(decide(PUBLISH, { ...pushHead, leading: new Uint8Array(MAX_COMMAND_LIST + 1) }), 'malformed', 'more than 64 KiB read')
  denies(
    decide(PUBLISH, request('POST', 'http://github.com/op/fixture.git/git-receive-pack', { 'content-type': 'application/x-git-receive-pack-request', 'content-length': String(list.length - 1) }, bytes(list))),
    'malformed',
    'more read than the body declares',
  )
})

test('an allow carries Content-Type and Content-Encoding as decide() read them, each sent once or not at all, on every route', () => {
  // How the host decodes the body is in these two, so the upstream holds the
  // head it sends to them (test/egress-upstream.test.ts): decide() mints the
  // values it judged, as the worker sent them, and none where it sent none.
  const cases: ReadonlyArray<readonly [string, EgressDecision, { readonly type: string | undefined; readonly encoding: string | undefined }]> = [
    ['info/refs, none sent', decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack')), { type: undefined, encoding: undefined }],
    ['upload-pack, plain', decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', UPLOAD_HEADERS)), { type: UPLOAD_HEADERS['content-type'], encoding: undefined }],
    [
      'upload-pack, gzip, as the worker spelled them',
      decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { 'Content-Type': 'Application/X-Git-Upload-Pack-Request', 'Content-Encoding': 'GZIP', 'transfer-encoding': 'chunked' })),
      { type: 'Application/X-Git-Upload-Pack-Request', encoding: 'GZIP' },
    ],
    ['a push', push(commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])), { type: 'application/x-git-receive-pack-request', encoding: undefined }],
    ['a pull request', pulls(JSON.stringify(PR), { 'content-type': 'application/json; charset=utf-8' }), { type: 'application/json; charset=utf-8', encoding: undefined }],
    ['a free host, none sent', decide(EXEC, request('GET', 'http://registry.npmjs.org/react')), { type: undefined, encoding: undefined }],
    ['a free host, a type sent with no body', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-type': 'text/plain' })), { type: 'text/plain', encoding: undefined }],
  ]
  for (const [label, decision, content] of cases) {
    const allow = allows(decision, decision.reason, label)
    assert.deepEqual(allow.content, content, label)
    assert.equal(Object.isFrozen(allow.content), true, label)
  }
  // Two of either, in one case or two, on a free host or a bound one: which
  // one the upstream's head should carry would be the order a record kept.
  for (const [label, decision, reason] of [
    ['two Content-Types, free', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-type': ['text/plain', 'text/html'] })), 'content-type'],
    ['two Content-Types, two cases', decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { ...UPLOAD_HEADERS, 'Content-Type': UPLOAD_HEADERS['content-type'] })), 'content-type'],
    ['two Content-Encodings, free', decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-encoding': ['gzip', 'gzip'] })), 'content-encoding'],
    ['two Content-Encodings, upload-pack', decide(EXEC, request('POST', 'http://github.com/op/fixture.git/git-upload-pack', { ...UPLOAD_HEADERS, 'content-encoding': ['gzip', 'gzip'] })), 'content-encoding'],
    ['two Content-Encodings, info/refs', decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack', { 'Content-Encoding': 'gzip', 'content-encoding': 'br' })), 'content-encoding'],
  ] as const) {
    denies(decision, reason, label)
  }
})

test('the body framing is one Content-Length or chunked alone: both, either twice or another coding is denied', () => {
  const target = 'http://github.com/op/fixture.git/git-upload-pack'
  const type = { 'content-type': 'application/x-git-upload-pack-request' }
  for (const headers of [
    { ...type, 'content-length': '10', 'transfer-encoding': 'chunked' },
    { ...type, 'content-length': ['10', '10'] },
    { ...type, 'content-length': ['10', '11'] },
    { ...type, 'Content-Length': '10', 'content-length': '10' },
    { ...type, 'transfer-encoding': ['chunked', 'chunked'] },
    { ...type, 'transfer-encoding': 'gzip, chunked' },
    { ...type, 'transfer-encoding': 'identity' },
    { ...type, 'content-length': '-1' },
    { ...type, 'content-length': '1e3' },
    { ...type, 'content-length': '0x10' },
    { ...type, 'content-length': '9'.repeat(16) },
    { ...type, 'content-length': '' },
  ]) {
    denies(decide(EXEC, request('POST', target, headers)), 'body', JSON.stringify(headers))
  }
  denies(decide(EXEC, request('POST', target, { 'content-type': ['application/x-git-upload-pack-request', 'text/plain'], 'transfer-encoding': 'chunked' })), 'content-type', 'two content types')
  allows(decide(EXEC, request('POST', target, { ...type, 'transfer-encoding': 'Chunked' })), 'git-fetch', 'chunked in another case')
})

test('a header that names another method or path than the request line is denied override-header on every host the grant reaches, in any case and with any value', () => {
  // decide() judges the request line. A host that honours one of these acts on
  // a method or a path nobody judged, with the binding's credential on it:
  // Rack::MethodOverride turns a POST into the header's method, and IIS and
  // Symfony read X-Original-URL and X-Rewrite-URL as the path.
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])
  const pr = JSON.stringify(PR)
  const free = 'http://registry.npmjs.org/react'
  const infoRefs = 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack'
  const uploadPack = 'http://github.com/op/fixture/git-upload-pack'
  // Each request is admitted without the header, so the header alone denies it.
  allows(push(list), 'git-push', 'the push, no override')
  allows(pulls(pr), 'github-pulls', 'the pull request, no override')
  allows(decide(EXEC, request('GET', infoRefs, { 'x-request-id': 'r1', accept: '*/*' })), 'git-fetch', 'info/refs with headers decide() does not judge')
  allows(decide(EXEC, request('GET', free, { 'user-agent': 'npm/11' })), 'allow-host', 'a credential-free GET')
  for (const name of [
    'X-HTTP-Method-Override', 'x-http-method', 'X-Method-Override', 'X-Original-URL', 'x-rewrite-url', 'X-HTTP-METHOD-OVERRIDE',
    // Aliases a backend that folds names reads as the same header (Rack's HTTP_*, CVE-2024-45614's class).
    'X_HTTP_Method_Override', 'x_original_url', 'X.HTTP.Method', 'x-method_override',
  ]) {
    // Sent twice too, as headersDistinct and a raw record hold a repeated header.
    for (const value of ['DELETE', 'GET', '/op/fixture/settings', '', ['PUT'], ['DELETE', 'PUT']] as const) {
      const extra: EgressHeaders = { [name]: value }
      const label = `${name}: ${JSON.stringify(value)}`
      denies(push(list, extra), 'override-header', `a push, ${label}`)
      denies(pulls(pr, extra), 'override-header', `a pull request, ${label}`)
      denies(decide(EXEC, request('GET', infoRefs, extra)), 'override-header', `info/refs, ${label}`)
      denies(decide(EXEC, request('POST', uploadPack, { ...UPLOAD_HEADERS, ...extra })), 'override-header', `upload-pack, ${label}`)
      denies(decide(EXEC, request('GET', free, extra)), 'override-header', `a credential-free GET, ${label}`)
    }
  }
  // Decided on its head: nothing of the body is read for one.
  const pushHead = request('POST', 'http://github.com/op/fixture.git/git-receive-pack', {
    'content-type': 'application/x-git-receive-pack-request',
    'content-length': String(list.length + PACK.length),
    'x-http-method-override': 'DELETE',
  })
  assert.deepEqual(leadingNeed(PUBLISH, pushHead), { kind: 'none' })
  // A host the grant does not reach is still not-allowed: the header says nothing of where a request may go.
  denies(decide(EXEC, request('GET', 'http://example.com/', { 'x-original-url': '/admin' })), 'not-allowed', 'an unlisted host')
})

test('every header is read under the one name a backend that folds names reads, so an alias is the header it aliases: to the framing, the content headers and sending one twice', () => {
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])
  const pr = JSON.stringify(PR)
  // A push judged plain and sent gzip under another spelling: a CGI gateway
  // hands git-http-backend HTTP_CONTENT_ENCODING for any of them.
  for (const name of ['Content_Encoding', 'content.encoding', 'CONTENT~ENCODING', 'content_encoding']) {
    denies(push(list, { [name]: 'gzip' }), 'content-encoding', `a push with ${name}`)
    denies(pulls(pr, { [name]: 'gzip' }), 'content-encoding', `a pull request with ${name}`)
    // Beside the real one, it is the header sent twice.
    denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-encoding': 'gzip', [name]: 'br' })), 'content-encoding', `Content-Encoding and ${name}`)
  }
  // Framing under another spelling, beside the real one: never both.
  for (const name of ['Transfer_Encoding', 'transfer.encoding']) {
    denies(push(list, { [name]: 'chunked' }), 'body', `a push with Content-Length and ${name}`)
  }
  denies(decide(EXEC, request('GET', 'http://registry.npmjs.org/react', { 'content-length': '0', content_length: '5' })), 'body', 'Content-Length twice, in two spellings')
  // A second Content-Type in another spelling is a Content-Type sent twice.
  denies(push(list, { Content_Type: 'text/plain' }), 'content-type', 'a push with a second Content-Type alias')
  // A lone alias of a header decide() reads is read as that header, and the
  // allow holds the upstream to it under its own name, which the head that
  // carries only the alias does not have: refused there, not sent.
  const aliased = decide(EXEC, request('POST', 'http://github.com/op/fixture/git-upload-pack', { Content_Type: 'application/x-git-upload-pack-request', 'transfer-encoding': 'chunked' }))
  assert.equal(allows(aliased, 'git-fetch', 'upload-pack under an alias of Content-Type').content.type, 'application/x-git-upload-pack-request')
  // The fold itself: lower case, every character but a letter or a digit a hyphen.
  for (const [name, canonical] of [
    ['Content-Type', 'content-type'],
    ['X_HTTP_Method_Override', 'x-http-method-override'],
    ['content.encoding', 'content-encoding'],
    ["a!#$%&'*+.^_`|~z", `a${'-'.repeat(14)}z`],
    ['ETag', 'etag'],
  ] as const) {
    assert.equal(canonicalHeaderName(name), canonical, name)
  }
})

test('the grant is strict: a host both free and bound, a repository in two routes, an unknown profile, a run id no ref holds, a non-EgressHost or a non-repo is refused; decide() denies malformed on a grant that does not parse', () => {
  const base = { runId: RUN, allow: ['registry.npmjs.org'], routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }] }
  assert.equal(EgressGrant.safeParse(base).success, true)
  const route = base.routes[0] ?? assert.fail()
  for (const [label, grant] of [
    ['a host both free and bound', { ...base, allow: ['github.com'] }],
    ['a host free twice', { ...base, allow: ['registry.npmjs.org', 'Registry.npmjs.org.'] }],
    ['a repository in two routes', { ...base, routes: [route, { ...route, bindingId: 'github-2' }] }],
    ['a repository in two routes, in two cases', { ...base, routes: [route, { ...route, bindingId: 'github-2', repos: ['Op/Fixture'] }] }],
    ['a binding routed twice', { ...base, routes: [route, { ...route, repos: ['op/other'] }] }],
    ['an unknown profile', { ...base, routes: [{ ...route, profiles: ['git-admin'] }] }],
    ['a profile twice', { ...base, routes: [{ ...route, profiles: ['git-fetch', 'git-fetch'] }] }],
    ['no profile', { ...base, routes: [{ ...route, profiles: [] }] }],
    ['no repository', { ...base, routes: [{ ...route, repos: [] }] }],
    ['a run id with a slash', { ...base, runId: 'run/1' }],
    ['a run id with dots', { ...base, runId: 'run..1' }],
    ['an empty run id', { ...base, runId: '' }],
    ['a run id that is an option', { ...base, runId: '-run' }],
    ['an address host', { ...base, allow: ['192.168.5.2'] }],
    ['a special-use host', { ...base, routes: [{ ...route, host: 'host.lima.internal' }] }],
    ['a repository ending in .git', { ...base, routes: [{ ...route, repos: ['op/fixture.git'] }] }],
    ['a repository with three parts', { ...base, routes: [{ ...route, repos: ['op/fixture/x'] }] }],
    ['a repository that is a dot segment', { ...base, routes: [{ ...route, repos: ['op/..'] }] }],
    ['a binding id in upper case', { ...base, routes: [{ ...route, bindingId: 'GitHub' }] }],
    ['an unknown field', { ...base, credential: 'x' }],
    ['an unknown route field', { ...base, routes: [{ ...route, header: 'authorization' }] }],
  ] as const) {
    assert.equal(EgressGrant.safeParse(grant).success, false, label)
    denies(decide(grant as unknown as EgressGrant, request('GET', 'http://registry.npmjs.org/react')), 'malformed', label)
  }
  for (const grant of [null, undefined, 'grant', 7, {}, [], { runId: RUN }]) {
    denies(decide(grant as unknown as EgressGrant, request('GET', 'http://registry.npmjs.org/react')), 'malformed', String(grant))
  }
  // A repository is held in its one spelling: lower-case.
  assert.equal(RepoSlug.parse('Op/Fixture'), 'op/fixture')
  assert.deepEqual(EgressGrant.parse({ ...base, routes: [{ ...route, repos: ['OP/Fixture'] }] }).routes[0]?.repos, ['op/fixture'])
})

test('decide() is pure and model-blind: the same request gives the same decision, the request is never written, every decision is frozen, and each allow is a fresh one, minted over the request it judged', () => {
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])
  const leading = bytes(list + PACK)
  const headers = Object.freeze({ 'content-type': 'application/x-git-receive-pack-request', 'content-length': String(leading.length) })
  const req = Object.freeze({ method: 'POST', target: 'http://github.com/op/fixture.git/git-receive-pack', headers, leading })
  const grant = structuredClone(PUBLISH)
  const first = decide(grant, req)
  const second = decide(grant, req)
  assert.equal(first.verdict, 'allow')
  assert.equal(second.verdict, 'allow')
  if (first.verdict !== 'allow' || second.verdict !== 'allow') throw new Error('unreachable')
  // Equal decisions, distinct allows: one request, one allow, never a cached one.
  const { allow: a, ...restA } = first
  const { allow: b, ...restB } = second
  assert.deepEqual(restA, restB)
  assert.notEqual(a, b)
  assert.equal(EgressAllow.spend(a), true)
  assert.equal(EgressAllow.spend(a), false)
  assert.equal(EgressAllow.spend(b), true, 'spending one allow spends no other')
  // Nothing of the request or the grant was written, and the bytes judged are a copy.
  assert.deepEqual(grant, structuredClone(PUBLISH))
  assert.deepEqual(leading, bytes(list + PACK))
  leading.fill(0x30, 0, 4)
  assert.deepEqual(EgressAllow.leadingOf(b), bytes(list), "the caller's buffer, written later, is not the bytes judged")
  // Frozen, allow and deny alike.
  assert.equal(Object.isFrozen(first), true)
  const denied = decide(PUBLISH, request('GET', 'http://example.com/'))
  assert.equal(Object.isFrozen(denied), true)
  assert.throws(() => {
    ;(denied as { reason: string }).reason = 'git-fetch'
  }, TypeError)
  // What the decision reads is the request: a field the model might set elsewhere (a tool argument, a prompt) has no slot.
  const extra = { ...request('GET', 'http://example.com/'), approved: true, reason: 'allow-host', verdict: 'allow' }
  denies(decide(PUBLISH, extra as EgressRequest), 'not-allowed', 'fields decide() does not read')
})

test('decide() never throws: a request that is no record, fields that throw, headers that are not text, and leading that is not bytes are denied malformed', () => {
  const throwing = Object.defineProperty({ target: 'http://registry.npmjs.org/', headers: {} }, 'method', {
    get() {
      throw new Error('a getter that throws')
    },
  })
  const throwingHeaders = { method: 'GET', target: 'http://registry.npmjs.org/', headers: new Proxy({}, { ownKeys: () => { throw new Error('trap') } }) }
  for (const [label, req] of [
    ['null', null],
    ['a string', 'GET / HTTP/1.1'],
    ['a getter that throws', throwing],
    ['headers whose keys throw', throwingHeaders],
    ['a method that is no text', { method: 7, target: 'http://registry.npmjs.org/', headers: {} }],
    ['a target that is no text', { method: 'GET', target: new URL('http://registry.npmjs.org/'), headers: {} }],
    ['headers that are no record', { method: 'GET', target: 'http://registry.npmjs.org/', headers: 'host: x' }],
    ['headers in rawHeaders form', { method: 'GET', target: 'http://registry.npmjs.org/', headers: ['Host', 'example.com'] }],
    ['a header that is a number', { method: 'GET', target: 'http://registry.npmjs.org/', headers: { 'content-length': 4 } }],
    ['a header list holding a number', { method: 'GET', target: 'http://registry.npmjs.org/', headers: { accept: ['a', 1] } }],
    ['leading that is a string', { method: 'GET', target: 'http://registry.npmjs.org/', headers: {}, leading: '0000' }],
    ['leading that is an array', { method: 'GET', target: 'http://registry.npmjs.org/', headers: {}, leading: [48, 48, 48, 48] }],
  ] as const) {
    let decision: EgressDecision | undefined
    assert.doesNotThrow(() => {
      decision = decide(EXEC, req as unknown as EgressRequest)
    }, label)
    assert.ok(decision !== undefined)
    denies(decision, 'malformed', label)
    assert.doesNotThrow(() => leadingNeed(EXEC, req as unknown as EgressRequest), label)
  }
  // A header named __proto__ is a header, not a prototype.
  const proto = JSON.parse('{"__proto__": "x", "host": "registry.npmjs.org"}') as EgressHeaders
  allows(decide(EXEC, request('GET', 'http://registry.npmjs.org/', proto)), 'allow-host', '__proto__ header')
})

test('no why holds the input: a marker in the target, the headers or the body appears in a decision only as its normalised host', () => {
  const MARK = 'zqmarkqz'
  const prefix = `refs/heads/aos/${RUN}/`
  const decisions: EgressDecision[] = [
    decide(EXEC, request('GET', `http://${MARK}.example/`)),
    decide(EXEC, request('GET', `http://${MARK}/`)),
    decide(EXEC, request('GET', `http://${MARK}.internal/`)),
    decide(EXEC, request('GET', `http://registry.npmjs.org:${MARK}/`)),
    decide(EXEC, request('GET', `http://${MARK}@registry.npmjs.org/`)),
    decide(EXEC, request('GET', `http://registry.npmjs.org/${MARK}/../x`)),
    decide(EXEC, request('GET', `/${MARK}`)),
    decide(EXEC, request(`${MARK.toUpperCase()}X`, 'http://registry.npmjs.org/')),
    decide(EXEC, request('GET', 'http://registry.npmjs.org/', { host: `${MARK}.example` })),
    decide(EXEC, request('GET', `http://github.com/op/${MARK}/info/refs?service=git-upload-pack`)),
    decide(EXEC, request('GET', `http://github.com/op/fixture/info/refs?${MARK}`)),
    decide(EXEC, request('GET', `http://github.com/${MARK}`)),
    decide(EXEC, request('POST', 'http://github.com/op/fixture/git-upload-pack', { 'content-type': MARK, 'content-length': '1' })),
    push(commandList([[OLD, NEW, `refs/heads/${MARK}`]])),
    push(commandList([[OLD, NEW, `${prefix}f`]], ` ${MARK} push-options`)),
    push(pkt(`${MARK}`) + '0000'),
    pulls(JSON.stringify({ ...PR, head: `${MARK}:x` })),
    pulls(JSON.stringify({ ...PR, head: MARK })),
    pulls(JSON.stringify({ ...PR, [MARK]: 1 })),
    pulls(`{"${MARK}":`),
  ]
  for (const decision of decisions) {
    assert.equal(decision.verdict, 'deny')
    // The host is the one field that is the input's, in its one spelling, for the row to bound and log.
    if (decision.host !== undefined) assert.equal(EgressHost.parse(decision.host), decision.host)
    assert.equal(JSON.stringify({ ...decision, host: undefined }).includes(MARK), false, JSON.stringify(decision))
    assert.ok((DENY_REASONS as readonly string[]).includes(decision.reason), decision.reason)
  }
})

test('an allow decide() minted is the one the upstream takes for the request it judged, and for no other', async () => {
  // A resolver with no records: an allow the upstream takes gets as far as
  // resolving and is refused there, 'no-address'; one it does not is refused
  // before, 'not-decided'. Nothing is dialled either way.
  const resolver = (): UpstreamResolver => {
    const none = async (): Promise<string[]> => {
      throw Object.assign(new Error('no record'), { code: 'ENOTFOUND' })
    }
    return { resolve4: none, resolve6: none, cancel: () => undefined }
  }
  const deps: UpstreamDeps = {
    resolver,
    dial: () => assert.fail('nothing is dialled'),
    interfaces: () => ({ lo0: [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' }] }),
    connectTimeoutMs: 1000,
    idleTimeoutMs: 1000,
  }
  const upstream = createUpstream(deps)
  const list = commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])
  const pushBody = list + PACK
  const cases = [
    {
      decision: decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack')),
      head: { method: 'GET', path: '/op/fixture.git/info/refs?service=git-upload-pack', headers: {} },
      body: undefined,
    },
    {
      decision: decide(EXEC, request('POST', 'http://github.com/op/fixture/git-upload-pack', UPLOAD_HEADERS)),
      head: { method: 'POST', path: '/op/fixture/git-upload-pack', headers: { 'content-type': UPLOAD_HEADERS['content-type'] } },
      body: { length: undefined, text: '0032want x\n0000' },
    },
    {
      decision: push(list),
      head: { method: 'POST', path: '/op/fixture.git/git-receive-pack', headers: { 'content-type': 'application/x-git-receive-pack-request' } },
      body: { length: pushBody.length, text: pushBody },
    },
    {
      decision: pulls(JSON.stringify(PR)),
      head: { method: 'POST', path: '/repos/op/fixture/pulls', headers: { 'content-type': 'application/json' } },
      body: { length: bytes(JSON.stringify(PR)).length, text: JSON.stringify(PR) },
    },
    {
      decision: decide(EXEC, request('GET', 'http://registry.npmjs.org/react')),
      head: { method: 'GET', path: '/react', headers: {} },
      body: undefined,
    },
  ]
  const send = async (allow: EgressAllow, head: { method: string; path: string; headers: Record<string, string> }, body: { length: number | undefined; text: string } | undefined) => {
    const stream = body === undefined ? undefined : Readable.from([Buffer.from(body.text)])
    const options = stream === undefined || body === undefined ? {} : { body: body.length === undefined ? { stream } : { stream, length: body.length } }
    return upstream.request(allow, head, options)
  }
  for (const { decision, head, body } of cases) {
    const label = `${head.method} ${head.path}`
    assert.equal(decision.verdict, 'allow', label)
    if (decision.verdict !== 'allow') continue
    const taken = await send(decision.allow, head, body)
    assert.equal(taken.ok === false && taken.reason, 'no-address', label)
    // The same allow again, or a fresh one for this request sent with another path, is not decided.
    const again = await send(decision.allow, head, body)
    assert.equal(again.ok === false && again.reason, 'not-decided', `${label}, again`)
  }
  const fresh = decide(EXEC, request('GET', 'http://github.com/op/fixture.git/info/refs?service=git-upload-pack'))
  assert.equal(fresh.verdict, 'allow')
  if (fresh.verdict !== 'allow') return
  const elsewhere = await send(fresh.allow, { method: 'POST', path: '/op/other.git/git-receive-pack', headers: {} }, { length: 4, text: '0000' })
  assert.equal(elsewhere.ok === false && elsewhere.reason, 'not-decided')
  // A session that judged one header record and built the upstream's head
  // from another: a push decide() judged plain, sent gzip-encoded, would
  // have the host gunzip it into a command list nobody read. Each is refused.
  const pushHead = { method: 'POST', path: '/op/fixture.git/git-receive-pack', headers: { 'content-type': 'application/x-git-receive-pack-request' } }
  for (const [label, headers] of [
    ['Content-Encoding: gzip added', { ...pushHead.headers, 'content-encoding': 'gzip' }],
    ['Content-Encoding: identity added', { ...pushHead.headers, 'Content-Encoding': 'identity' }],
    ['Content-Type dropped', {}],
    ['another Content-Type', { 'content-type': 'application/x-git-upload-pack-request' }],
  ] as const) {
    const judged = push(list)
    assert.equal(judged.verdict, 'allow', label)
    if (judged.verdict !== 'allow') continue
    const sent = await send(judged.allow, { ...pushHead, headers }, { length: pushBody.length, text: pushBody })
    assert.equal(sent.ok === false && sent.reason, 'not-decided', label)
  }
  // And an upload-pack judged gzip, sent with the encoding dropped.
  const gzip = decide(EXEC, request('POST', 'http://github.com/op/fixture/git-upload-pack', { ...UPLOAD_HEADERS, 'content-encoding': 'gzip' }))
  assert.equal(gzip.verdict, 'allow')
  if (gzip.verdict !== 'allow') return
  const dropped = await send(gzip.allow, { method: 'POST', path: '/op/fixture/git-upload-pack', headers: { 'content-type': UPLOAD_HEADERS['content-type'] } }, { length: undefined, text: 'x' })
  assert.equal(dropped.ok === false && dropped.reason, 'not-decided')
})

test('a repository is read without case and with or without .git; a name ending in .git or a non-repo segment is no route', () => {
  const grant = EgressGrant.parse({ runId: RUN, allow: [], routes: [{ bindingId: 'github', host: 'github.com', profiles: ['git-fetch'], repos: ['op/fixture'] }] })
  for (const repo of ['op/fixture', 'OP/FIXTURE', 'op/fixture.git', 'op/fixture.GIT']) {
    allows(decide(grant, request('GET', `http://github.com/${repo}/info/refs?service=git-upload-pack`)), 'git-fetch', repo)
  }
  denies(decide(grant, request('GET', 'http://github.com/op/fixture.git.git/info/refs?service=git-upload-pack')), 'no-route', 'fixture.git.git')
  for (const repo of ['op/.git', 'op/fix%74ure', 'op/fix;ure', '-op/fixture', 'op/fix~ture', `op/${'a'.repeat(101)}`]) {
    denies(decide(grant, request('GET', `http://github.com/${repo}/info/refs?service=git-upload-pack`)), 'no-route', repo)
  }
})

test('a ref or a head names a branch in one spelling: .lock, .., a leading dot or hyphen, a control character or an empty branch is refused', () => {
  for (const name of ['feature', 'feature/two', 'f.x', 'v1.2.3', 'a_b-c', 'x'.repeat(200)]) assert.equal(isBranchName(name), true, name)
  for (const name of ['', 'a..b', '.a', 'a/.b', '-a', 'a/-b', 'a.', 'a.lock', 'a/b.lock', 'a//b', 'a/', '/a', 'a b', 'a~b', 'a^b', 'a:b', 'a?b', 'a*b', 'a[b', 'a\\b', 'a@{b', '@', 'a\u0000b', 'a\nb', 'é', 'x'.repeat(201)]) {
    assert.equal(isBranchName(name), false, JSON.stringify(name))
  }
})

test('the reasons and profiles are the stable lists decisions name', () => {
  assert.deepEqual([...ALLOW_REASONS], ['allow-host', 'git-fetch', 'git-push', 'github-pulls'])
  assert.deepEqual([...EGRESS_PROFILES], ['git-fetch', 'git-push', 'github-pulls'])
  assert.deepEqual([...DENY_REASONS], [
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
  ])
  assert.deepEqual([...ROUTE_REFUSALS], [
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
  ])
  assert.equal(new Set([...ALLOW_REASONS, ...DENY_REASONS]).size, ALLOW_REASONS.length + DENY_REASONS.length, 'no reason is both')
  for (const table of [ALLOW_REASONS, DENY_REASONS, ROUTE_REFUSALS, EGRESS_PROFILES]) {
    assert.equal(Object.isFrozen(table), true)
    assert.throws(() => (table as unknown as string[]).push('allow-everything'), TypeError)
  }
  // A profile allow names its profile: the reason a row logs is the route that admitted it.
  for (const profile of EGRESS_PROFILES) assert.ok((ALLOW_REASONS as readonly string[]).includes(profile))
  assert.equal(EgressHost.parse('github.com'), PUBLISH.routes[0]?.host)
})

/** What policy.ts and routes.ts may import, by module and by name: nothing with a socket, a resolver, a file or a clock. */
const PURE_IMPORTS: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>> = {
  'src/egress/routes.ts': {
    zod: ['z'],
    './host.js': ['parseEgressHost', 'EgressHost', 'HostRefusal'],
  },
  'src/egress/policy.ts': {
    zod: ['z'],
    './decision.js': ['mintEgressAllow', 'EgressAllow', 'JudgedBody'],
    './host.js': ['EgressHost', 'HostRefusal'],
    './routes.js': [
      'EGRESS_PROFILES', 'EgressProfileName', 'judgeCommands', 'judgePullsBody', 'matchRoute', 'MAX_COMMAND_LIST', 'MAX_PULLS_BODY',
      'namedHost', 'parseTarget', 'RepoSlug', 'ROUTE_REFUSALS', 'RUN_REF', 'scanCommandList', 'EgressProfile', 'ParsedTarget',
    ],
  },
}

/** Names a pure module has no use for: each a way to I/O, the clock, chance or a loader with no import at all. */
const IMPURE_NAMES: ReadonlySet<string> = new Set([
  'process', 'globalThis', 'global', 'fetch', 'require', 'eval', 'Function', 'WebSocket', 'XMLHttpRequest', 'constructor', 'Date', 'performance', 'Math', 'crypto', 'setTimeout', 'setImmediate', 'queueMicrotask',
])

test('policy.ts and routes.ts are pure: they import only zod, host.ts, routes.ts and the mint by name, re-export nothing, and name no process, global object, clock, chance, fetch, require, eval or Function', () => {
  for (const [path, allowed] of Object.entries(PURE_IMPORTS)) {
    const source = ts.createSourceFile(path, readFileSync(`${REPO}/${path}`, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
    const imported: string[] = []
    const offences: string[] = []
    const visit = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node)) {
        const spec = ts.isStringLiteral(node.moduleSpecifier) ? node.moduleSpecifier.text : '<computed>'
        const bindings = node.importClause?.namedBindings
        if (node.importClause?.name !== undefined || bindings === undefined || !ts.isNamedImports(bindings)) offences.push(`${spec}: not a named import`)
        else for (const el of bindings.elements) imported.push(`${spec} ${(el.propertyName ?? el.name).text}`)
        return
      }
      if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) offences.push('a re-export')
      if (ts.isImportEqualsDeclaration(node) || ts.isImportTypeNode(node)) offences.push('an import in another form')
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) offences.push('import()')
      if (ts.isMetaProperty(node)) offences.push('import.meta')
      if (ts.isIdentifier(node) && IMPURE_NAMES.has(node.text)) offences.push(`names ${node.text}`)
      if (ts.isStringLiteralLike(node) && (IMPURE_NAMES.has(node.text) || node.text.startsWith('node:'))) offences.push(`spells ${node.text}`)
      ts.forEachChild(node, visit)
    }
    visit(source)
    assert.deepEqual(offences, [], path)
    const expected = Object.entries(allowed).flatMap(([spec, names]) => names.map((name) => `${spec} ${name}`))
    assert.deepEqual(imported.sort(), expected.sort(), path)
  }
})

test('every table routes.ts and policy.ts export is frozen, and so is every decision and scan', () => {
  const decisions = [
    decide(EXEC, request('GET', 'http://registry.npmjs.org/react')),
    decide(EXEC, request('GET', 'http://example.com/')),
    decide(EXEC, request('GET', 'http://host.lima.internal/')),
    push(commandList([[OLD, NEW, 'refs/heads/main']])),
  ]
  for (const decision of decisions) assert.equal(Object.isFrozen(decision), true, decision.reason)
  const scan = scanCommandList(bytes(commandList([[OLD, NEW, `refs/heads/aos/${RUN}/f`]])))
  assert.equal(Object.isFrozen(scan), true)
  if (scan.status === 'complete') {
    assert.equal(Object.isFrozen(scan.commands), true)
    assert.equal(Object.isFrozen(scan.capabilities), true)
    for (const command of scan.commands) assert.equal(Object.isFrozen(command), true)
  }
  const parsed = parseTarget('http://registry.npmjs.org/react')
  assert.equal(Object.isFrozen(parsed), true)
})
