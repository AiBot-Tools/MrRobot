// Egress plan S4: the in-image publisher, images/worker/publish.mjs, which
// sandbox.publish's container runs under the mux.
//
// Nothing here spawns a process, dials or listens: the publisher's git and
// its request to the mux are handed in, and the kernel's own policy
// (src/egress/policy.ts, routes.ts) judges what it would send.
//
// The falsifiers:
//
//   Read an argument the kernel does not write, or miss one it does
//   (publishCommand), and a publish pushes where nobody approved, or not at
//   all. Run git in the workspace, or with the container's environment, a
//   shell, a stdin, or without the protected config, and a hook or a config a
//   run wrote runs with the publish grant live. Open the pull request in a
//   spelling the github-pulls route refuses, or push a ref outside
//   aos/<runId>/, and every publish fails at the kernel. Go on past a failed
//   step, and a pull request is opened for a push that never landed. Send the
//   request anywhere but the mux, in absolute form, on an agent of its own,
//   and an environment variable decides where it goes.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { PassThrough, Writable } from 'node:stream'

import { EGRESS_MUX_PORT } from '../src/config.js'
import { decide, EgressGrant } from '../src/egress/policy.js'
import { isBranchName as kernelBranchName, judgeCommands, judgePullsBody, matchRoute, parseTarget } from '../src/egress/routes.js'
import { PUBLISH_ARGV, publishCommand, type PublishFields, type PublishTarget } from '../src/runtime/sandbox-tools.js'
import {
  defaultBranch,
  FLAGS,
  GIT,
  GIT_ENV,
  GIT_SPAWN_OPTIONS,
  headOf,
  isBranchName,
  MUX_HOST,
  MUX_PORT,
  muxRequestOptions,
  OUTPUT_MAX_BYTES,
  parseArgs,
  postThroughMux,
  PROTECTED,
  publish,
  PUBLISH_EXIT,
  pullAnswer,
  pullRequest,
  remoteOf,
  runGit,
  SYSTEM_DEPS,
  workspaceHead,
  workspaceShallow,
} from '../images/worker/publish.mjs'
import { REPO_ROOT } from './helpers/kernel.js'
import { tmpdir } from './helpers/tmpdir.js'

const RUN = 'run_1758000000000_abc123'
const TARGET: PublishTarget = { gitHost: 'github.com', apiHost: 'api.github.com', repo: 'op/fixture' }
const FIELDS: PublishFields = { branch: 'fix/readme', title: 'Fix the README', body: 'One line.\nAnd "another", for the café.' }
const OID = 'c0ffee'.repeat(6) + 'c0de'
const ZERO = '0'.repeat(40)

/** The grant sandbox.publish's container runs under, as #planPublish builds it for TARGET. */
const GRANT = EgressGrant.parse({
  runId: RUN,
  allow: [],
  routes: [
    { bindingId: 'github', host: 'github.com', profiles: ['git-fetch', 'git-push'], repos: ['op/fixture'] },
    { bindingId: 'github-api', host: 'api.github.com', profiles: ['github-pulls'], repos: ['op/fixture'] },
  ],
})

const ARGS = (() => {
  const parsed = parseArgs(publishCommand(TARGET, RUN, FIELDS).slice(PUBLISH_ARGV.length))
  assert.ok(parsed !== undefined)
  return parsed
})()

test("the publisher reads exactly the command the kernel builds, every value whole, and nothing else", () => {
  const command = publishCommand(TARGET, RUN, FIELDS)
  assert.deepEqual(command.slice(0, PUBLISH_ARGV.length), ['node', '/opt/aos/publish.mjs'])
  const argv = command.slice(PUBLISH_ARGV.length)
  // One element per flag, in the publisher's order.
  assert.deepEqual(argv.map((arg) => arg.slice(2, arg.indexOf('='))), [...FLAGS])
  assert.deepEqual(parseArgs(argv), {
    gitHost: 'github.com',
    apiHost: 'api.github.com',
    repo: 'op/fixture',
    run: RUN,
    branch: 'fix/readme',
    title: 'Fix the README',
    body: 'One line.\nAnd "another", for the café.',
  })
  // A value that reads as a flag, or holds `=`, is a value: each is joined to
  // its own flag, so nothing a human approved stands as an argument of its own.
  const tricky = { branch: 'b', title: '--body=x', body: '--title=y = z\n--repo=other/repo' }
  assert.deepEqual(parseArgs(publishCommand(TARGET, RUN, tricky).slice(2)), { ...ARGS, branch: 'b', title: '--body=x', body: '--title=y = z\n--repo=other/repo' })
  assert.deepEqual(parseArgs(publishCommand(TARGET, RUN, { ...FIELDS, body: '' }).slice(2))?.body, '')

  const ok = [...argv]
  const refused: readonly (readonly [string, readonly string[]])[] = [
    ['nothing', []],
    ['a flag missing', ok.slice(0, -1)],
    ['a flag more', [...ok, '--draft=true']],
    ['two flags swapped', [ok[1] ?? '', ok[0] ?? '', ...ok.slice(2)]],
    ['a flag twice, in place of another', [ok[0] ?? '', ok[0] ?? '', ...ok.slice(2)]],
    ['a value as its own argument', ['--git-host', 'github.com', ...ok.slice(1, -1)]],
    ['a host with a port', ['--git-host=github.com:443', ...ok.slice(1)]],
    ['a host that is an address', ['--git-host=192.168.5.2', ...ok.slice(1)]],
    ['a host whose last label is a number', ['--git-host=github.123', ...ok.slice(1)]],
    ['a host in upper case', ['--git-host=GitHub.com', ...ok.slice(1)]],
    ['a host with no dot', [ok[0] ?? '', '--api-host=localhost', ...ok.slice(2)]],
    ['a repository with .git', [...ok.slice(0, 2), '--repo=op/fixture.git', ...ok.slice(3)]],
    ['a repository in upper case', [...ok.slice(0, 2), '--repo=Op/fixture', ...ok.slice(3)]],
    ['a repository with a third part', [...ok.slice(0, 2), '--repo=op/fixture/x', ...ok.slice(3)]],
    ['a run id with a hyphen', [...ok.slice(0, 3), '--run=run-1', ...ok.slice(4)]],
    ['a branch with ..', [...ok.slice(0, 4), '--branch=a..b', ...ok.slice(5)]],
    ['a branch starting with -', [...ok.slice(0, 4), '--branch=-x', ...ok.slice(5)]],
    ['a branch ending in .lock', [...ok.slice(0, 4), '--branch=x.lock', ...ok.slice(5)]],
    ['an empty title', [...ok.slice(0, 5), '--title=', ok[6] ?? '']],
    ['a title past 1024 characters', [...ok.slice(0, 5), `--title=${'t'.repeat(1025)}`, ok[6] ?? '']],
  ]
  for (const [what, given] of refused) assert.equal(parseArgs(given), undefined, what)
  assert.equal(parseArgs([...ok.slice(0, 5), `--title=${'t'.repeat(1024)}`, ok[6] ?? ''])?.title.length, 1024)
})

test("the publisher's branch names are the kernel's, both ways", () => {
  const names = ['main', 'fix/readme', 'a_b-c.d', '_x', 'x/y/z', '..', 'a..b', '-x', 'x/-y', '.x', 'x.', 'x.lock', 'x/', '/x', 'x//y', 'a b', 'ä', '', 'x'.repeat(200), 'x'.repeat(201)]
  for (const name of names) assert.equal(isBranchName(name), kernelBranchName(name), name)
})

/** A container's files, as the publisher reads them: regular files and directories, none through a link. */
function files(given: Readonly<Record<string, string>>, dirs: readonly string[] = ['/workspace/.git', '/workspace/.git/objects']) {
  return {
    readFile: (path: string): string | undefined => (Object.hasOwn(given, path) ? given[path] : undefined),
    isDirectory: (path: string): boolean => dirs.includes(path),
  }
}

test("what the publisher reads of the workspace is HEAD and the ref it names, as files, and it publishes only from a plain repository", () => {
  const head = (text: string, more: Record<string, string> = {}) => workspaceHead(files({ '/workspace/.git/HEAD': text, ...more }))
  assert.deepEqual(head(`${OID}\n`), { oid: OID })
  assert.deepEqual(head('ref: refs/heads/main\n', { '/workspace/.git/refs/heads/main': `${OID}\n` }), { oid: OID })
  assert.deepEqual(head('ref: refs/heads/fix/readme', { '/workspace/.git/packed-refs': `# pack-refs with: peeled fully-peeled sorted\n${ZERO} refs/heads/other\n${OID} refs/heads/fix/readme\n^${ZERO}\n` }), { oid: OID })
  // A loose ref is read before packed-refs, as git reads it.
  assert.deepEqual(head('ref: refs/heads/main', { '/workspace/.git/refs/heads/main': OID, '/workspace/.git/packed-refs': `${ZERO} refs/heads/main\n` }), { oid: OID })
  const refusals: readonly (readonly [string, ReturnType<typeof workspaceHead>, RegExp])[] = [
    ['no .git directory (a worktree or a submodule, whose .git is a file)', workspaceHead(files({ '/workspace/.git/HEAD': OID }, [])), /\/workspace is no plain git repository/],
    ['no objects directory', workspaceHead(files({ '/workspace/.git/HEAD': OID }, ['/workspace/.git'])), /\/workspace is no plain git repository/],
    ['no HEAD', workspaceHead(files({})), /\.git\/HEAD is no file of its own/],
    ['a ref outside refs/heads', head('ref: refs/tags/v1'), /HEAD names neither a commit nor a branch/],
    ['a ref that walks out of refs/heads', head('ref: refs/heads/../../config'), /HEAD names neither a commit nor a branch/],
    ['a short object name', head(OID.slice(0, 12)), /HEAD names neither a commit nor a branch/],
    ['a branch with no commit', head('ref: refs/heads/main'), /HEAD names refs\/heads\/main, which has no commit/],
    ['a loose ref holding no object name', head('ref: refs/heads/main', { '/workspace/.git/refs/heads/main': 'ref: refs/heads/other\n' }), /refs\/heads\/main holds no object name/],
  ]
  for (const [what, got, why] of refusals) {
    assert.ok('refusal' in got, what)
    assert.match(got.refusal, why, what)
  }

  assert.deepEqual(workspaceShallow(files({})), { shallow: undefined })
  assert.deepEqual(workspaceShallow(files({ '/workspace/.git/shallow': `${OID}\n${ZERO}\n` })), { shallow: `${OID}\n${ZERO}\n` })
  const shallow = workspaceShallow(files({ '/workspace/.git/shallow': `${OID}\n[include]\n` }))
  assert.ok('refusal' in shallow && /holds a line that is no object name/.test(shallow.refusal))

  assert.equal(defaultBranch(`ref: refs/heads/main\tHEAD\n${OID}\tHEAD\n`), 'main')
  assert.equal(defaultBranch(`${OID}\tHEAD\n`), undefined)
  assert.equal(defaultBranch('ref: refs/heads/a..b\tHEAD\n'), undefined)
  assert.equal(defaultBranch('ref: refs/tags/v1\tHEAD\n'), undefined)
})

test("the files main() hands publish() read no link, in any component of a path, and its writes make a new file at 0600 and never replace one", (t) => {
  // Every other test hands in fake files, which hold no link by
  // construction: this one holds SYSTEM_DEPS itself, the readers and the
  // writer the publisher runs with in the container, on a real directory.
  // Its real path: the readers refuse a path any directory of which is a
  // link, and the system's temporary directory may sit under one (macOS's
  // /var is /private/var).
  const root = realpathSync(tmpdir(t))
  const file = join(root, 'HEAD')
  const dir = join(root, 'objects')
  writeFileSync(file, `${OID}\n`)
  mkdirSync(dir)
  symlinkSync(file, join(root, 'file-link'))
  symlinkSync(dir, join(root, 'dir-link'))

  assert.equal(SYSTEM_DEPS.readFile(file), `${OID}\n`, 'a regular file reads')
  assert.equal(SYSTEM_DEPS.readFile(join(root, 'file-link')), undefined, 'a link to a file reads as no file')
  assert.equal(SYSTEM_DEPS.readFile(dir), undefined, 'a directory reads as no file')
  assert.equal(SYSTEM_DEPS.readFile(join(root, 'missing')), undefined, 'a missing path reads as no file')
  assert.equal(SYSTEM_DEPS.isDirectory(dir), true, 'a directory is one')
  assert.equal(SYSTEM_DEPS.isDirectory(join(root, 'dir-link')), false, 'a link to a directory is none')
  assert.equal(SYSTEM_DEPS.isDirectory(file), false, 'a file is no directory')
  assert.equal(SYSTEM_DEPS.isDirectory(join(root, 'missing')), false, 'a missing path is no directory')

  // A link above the last component: a workspace whose .git and objects are
  // directories of its own, and whose .git/refs is a link to ../elsewhere, a
  // directory of the workspace outside .git. lstat on the last component
  // alone sees a regular file and a directory there, so a ref would read from
  // outside .git (the commit the publisher pushes named by a file the run
  // wrote there): no component of a path read may be a link.
  const ws = join(root, 'ws')
  const elsewhere = join(ws, 'elsewhere')
  mkdirSync(join(ws, '.git', 'objects'), { recursive: true })
  mkdirSync(join(elsewhere, 'heads', 'deeper'), { recursive: true })
  writeFileSync(join(elsewhere, 'heads', 'main'), `${OID}\n`)
  symlinkSync('../elsewhere', join(ws, '.git', 'refs'))
  assert.equal(SYSTEM_DEPS.isDirectory(join(ws, '.git')), true, '.git is a directory of its own')
  assert.equal(SYSTEM_DEPS.isDirectory(join(ws, '.git', 'objects')), true, 'objects is a directory of its own')
  assert.equal(lstatSync(join(ws, '.git', 'refs', 'heads', 'main')).isFile(), true, 'lstat alone reads the ref as a regular file')
  assert.equal(SYSTEM_DEPS.readFile(join(ws, '.git', 'refs', 'heads', 'main')), undefined, 'a ref under a linked refs directory reads as no file')
  assert.equal(SYSTEM_DEPS.isDirectory(join(ws, '.git', 'refs', 'heads', 'deeper')), false, 'a directory under a linked one is none')
  // The same files reached by their own path read as they are.
  assert.equal(SYSTEM_DEPS.readFile(join(elsewhere, 'heads', 'main')), `${OID}\n`)
  assert.equal(SYSTEM_DEPS.isDirectory(join(elsewhere, 'heads', 'deeper')), true)

  const made = join(root, 'alternates')
  SYSTEM_DEPS.writeFile(made, '/workspace/.git/objects\n')
  assert.equal(readFileSync(made, 'utf8'), '/workspace/.git/objects\n')
  assert.equal(statSync(made).mode & 0o777, 0o600, 'a new file is the publisher\'s alone')
  // A path that is there already, as a file or as a link (one whose target
  // is not there included), is never written: the write fails EEXIST.
  const linkTarget = join(root, 'target')
  symlinkSync(linkTarget, join(root, 'dangling'))
  for (const [what, path] of [['a file', file], ['a link', join(root, 'file-link')], ['a link to nothing', join(root, 'dangling')]] as const) {
    assert.throws(() => SYSTEM_DEPS.writeFile(path, 'replaced\n'), (e: unknown) => e instanceof Error && (e as NodeJS.ErrnoException).code === 'EEXIST', what)
  }
  assert.equal(readFileSync(file, 'utf8'), `${OID}\n`, 'the file is as it was')
  assert.equal(lstatSync(join(root, 'dangling')).isSymbolicLink(), true)
  assert.throws(() => lstatSync(linkTarget), /ENOENT/, 'nothing was made through the link')
})

test('every git the publisher runs is /usr/bin/git, through no shell, with no stdin, in /tmp, with an environment of its own and the protected config', async () => {
  assert.equal(GIT, '/usr/bin/git')
  assert.deepEqual(
    { ...GIT_ENV },
    {
      PATH: '/usr/bin:/bin',
      HOME: '/tmp',
      LC_ALL: 'C',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_ALLOW_PROTOCOL: 'http',
      GIT_TERMINAL_PROMPT: '0',
      GIT_PAGER: 'cat',
    },
  )
  assert.deepEqual(
    [...PROTECTED],
    [
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'credential.helper=',
      '-c', 'core.askPass=',
      '-c', `http.proxy=http://127.0.0.1:${String(EGRESS_MUX_PORT)}`,
      '-c', 'http.followRedirects=false',
      '-c', 'protocol.version=0',
      '-c', 'push.gpgSign=false',
      '-c', 'push.recurseSubmodules=no',
      '-c', 'submodule.recurse=false',
    ],
  )

  const calls: { command: string; args: readonly string[]; options: unknown }[] = []
  const child = (code: number | null, out = '', err = ''): EventEmitter & { stdout: PassThrough; stderr: PassThrough } => {
    const c = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough() })
    setImmediate(() => {
      c.stdout.end(out)
      c.stderr.end(err)
      setImmediate(() => c.emit('close', code))
    })
    return c
  }
  const spawning = (make: () => unknown) => (command: string, args: readonly string[], options: unknown) => {
    calls.push({ command, args, options })
    return make() as never
  }
  const ran = await runGit(['version'], spawning(() => child(0, 'git version 2.39.5\n', '')))
  assert.deepEqual(ran, { code: 0, stdout: 'git version 2.39.5\n', stderr: '' })
  assert.deepEqual(calls[0], {
    command: '/usr/bin/git',
    args: ['version'],
    options: { cwd: '/tmp', env: { ...GIT_ENV }, stdio: ['ignore', 'pipe', 'pipe'], shell: false },
  })
  assert.deepEqual(calls[0]?.options, { ...GIT_SPAWN_OPTIONS, env: { ...GIT_ENV }, stdio: [...GIT_SPAWN_OPTIONS.stdio] })
  // Its own copy of the environment, never the frozen constant itself, and never the container's.
  assert.notEqual((calls[0]?.options as { env: unknown }).env, GIT_ENV)
  assert.equal(Object.hasOwn((calls[0]?.options as { env: object }).env, 'HTTP_PROXY'), false)

  // Each stream is kept to its first OUTPUT_MAX_BYTES.
  const long = await runGit(['x'], spawning(() => child(1, 'o'.repeat(OUTPUT_MAX_BYTES + 10), 'e'.repeat(OUTPUT_MAX_BYTES * 2))))
  assert.deepEqual([long.code, long.stdout.length, long.stderr.length], [1, OUTPUT_MAX_BYTES, OUTPUT_MAX_BYTES])
  // A git that could not start ends with no code, and says why, never rejects.
  const thrown = await runGit(['x'], () => {
    throw new Error('spawn EACCES')
  })
  assert.deepEqual(thrown, { code: null, stdout: '', stderr: 'git did not start: spawn EACCES' })
  const failing = await runGit(['x'], spawning(() => {
    const c = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough() })
    setImmediate(() => c.emit('error', new Error('spawn /usr/bin/git ENOENT')))
    return c
  }))
  assert.deepEqual(failing, { code: null, stdout: '', stderr: 'git did not start: spawn /usr/bin/git ENOENT' })
})

interface Played {
  readonly gits: (readonly string[])[]
  readonly posts: ReturnType<typeof pullRequest>[]
  readonly writes: [string, string][]
  readonly out: string[]
  readonly err: string[]
}

/**
 * The publisher's deps over a workspace whose HEAD is OID: each git is
 * answered by `answer` (by its subcommand), and the pull request by `post`.
 */
function played(
  over: {
    answer?: (sub: string, argv: readonly string[]) => { code: number | null; stdout?: string; stderr?: string }
    post?: (request: ReturnType<typeof pullRequest>) => Promise<{ status: number; text: string }>
    workspace?: Readonly<Record<string, string>>
  } = {},
): { readonly deps: Parameters<typeof publish>[1]; readonly seen: Played } {
  const seen: Played = { gits: [], posts: [], writes: [], out: [], err: [] }
  const answer =
    over.answer ??
    ((sub: string): { code: number | null; stdout?: string; stderr?: string } =>
      sub === 'ls-remote' ? { code: 0, stdout: `ref: refs/heads/main\tHEAD\n${OID}\tHEAD\n` } : { code: 0, stdout: '' })
  const deps: Parameters<typeof publish>[1] = {
    git: async (argv) => {
      seen.gits.push(argv)
      const sub = argv.slice(PROTECTED.length).find((arg) => !arg.startsWith('--')) ?? ''
      const a = answer(sub, argv)
      return { code: a.code, stdout: a.stdout ?? '', stderr: a.stderr ?? '' }
    },
    post: (request) => {
      seen.posts.push(request)
      return over.post?.(request) ?? Promise.resolve({ status: 201, text: JSON.stringify({ number: 7, html_url: 'https://github.com/op/fixture/pull/7' }) })
    },
    ...files(over.workspace ?? { '/workspace/.git/HEAD': 'ref: refs/heads/work\n', '/workspace/.git/refs/heads/work': `${OID}\n` }),
    scratch: () => '/tmp/aos-publish-Ab12Cd',
    writeFile: (path, text) => {
      seen.writes.push([path, text])
    },
    out: (text) => {
      seen.out.push(text)
    },
    err: (text) => {
      seen.err.push(text)
    },
  }
  return { deps, seen }
}

test("publish reads HEAD and the default branch, pushes HEAD to aos/<runId>/<branch>, opens the pull request the kernel's route admits under the grant that names what the human approved, and says where", async () => {
  const { deps, seen } = played()
  assert.equal(await publish(ARGS, deps), PUBLISH_EXIT.ok)
  const dir = '/tmp/aos-publish-Ab12Cd'
  const remote = 'http://github.com/op/fixture.git'
  assert.equal(remoteOf(ARGS), remote)
  const ref = `refs/heads/aos/${RUN}/fix/readme`
  assert.deepEqual(seen.gits, [
    [...PROTECTED, 'init', '--bare', '--quiet', '--template=', dir],
    [...PROTECTED, `--git-dir=${dir}`, 'ls-remote', '--symref', remote, 'HEAD'],
    [...PROTECTED, `--git-dir=${dir}`, 'push', '--porcelain', '--no-verify', '--no-recurse-submodules', remote, `${OID}:${ref}`],
  ])
  // No git it runs is pointed at the workspace: it reads only its objects,
  // through the alternates file, as data.
  for (const argv of seen.gits) {
    assert.equal(argv.some((arg) => arg.includes('/workspace')), false, argv.join(' '))
    assert.deepEqual(argv.slice(0, PROTECTED.length), [...PROTECTED])
  }
  assert.deepEqual(seen.writes, [[`${dir}/objects/info/alternates`, '/workspace/.git/objects\n']])

  // The push is one the kernel's push check admits: the one ref it names is under aos/<runId>/.
  assert.deepEqual(judgeCommands([{ old: ZERO, new: OID, ref }], RUN), { ok: true, count: 1 })
  assert.equal(headOf(ARGS), `aos/${RUN}/fix/readme`)

  // The pull request is one the kernel allows under the publish grant: its
  // target, its headers and its body judged as the session would hand them.
  const [request] = seen.posts
  assert.ok(request !== undefined)
  assert.deepEqual(request, pullRequest(ARGS, 'main'))
  assert.equal(request.body, JSON.stringify({ title: 'Fix the README', head: `aos/${RUN}/fix/readme`, base: 'main', body: 'One line.\nAnd "another", for the café.' }))
  assert.notEqual(Buffer.byteLength(request.body), request.body.length, 'the body holds a character of more than one byte')
  const body = new TextEncoder().encode(request.body)
  assert.deepEqual(judgePullsBody(body, RUN), { ok: true, head: `aos/${RUN}/fix/readme`, base: 'main' })
  const target = parseTarget(request.target)
  assert.ok(target.ok)
  assert.equal(target.host, 'api.github.com')
  assert.deepEqual(matchRoute('POST', target.path, target.query), { ok: true, profile: 'github-pulls', kind: 'pulls', repo: 'op/fixture' })
  const decision = decide(GRANT, { method: 'POST', target: request.target, headers: request.headers, leading: body })
  assert.equal(decision.verdict, 'allow', decision.verdict === 'deny' ? `${decision.reason}: ${decision.why}` : '')
  assert.equal(decision.reason, 'github-pulls')
  assert.equal(request.headers['content-length'], String(body.length))
  // And under the grant #publish issues, which names the branch, title and
  // body the human approved: the push is that branch, and the pull request
  // is from it, with exactly that title and body and no other field, an
  // empty body sent as the empty string it was approved as.
  const bound = EgressGrant.parse({ ...GRANT, publish: FIELDS })
  assert.deepEqual(judgeCommands([{ old: ZERO, new: OID, ref }], RUN, FIELDS.branch), { ok: true, count: 1 })
  assert.deepEqual(judgePullsBody(body, RUN, FIELDS), { ok: true, head: `aos/${RUN}/fix/readme`, base: 'main' })
  const held = decide(bound, { method: 'POST', target: request.target, headers: request.headers, leading: body })
  assert.equal(held.verdict, 'allow', held.verdict === 'deny' ? `${held.reason}: ${held.why}` : '')
  const quiet = { ...FIELDS, body: '' }
  const quietArgs = parseArgs(publishCommand(TARGET, RUN, quiet).slice(PUBLISH_ARGV.length))
  assert.ok(quietArgs !== undefined)
  const quietBody = new TextEncoder().encode(pullRequest(quietArgs, 'main').body)
  assert.deepEqual(judgePullsBody(quietBody, RUN, quiet), { ok: true, head: `aos/${RUN}/fix/readme`, base: 'main' })

  assert.deepEqual(seen.out, [
    `pushed ${OID} to ${ref} of op/fixture on github.com\n`,
    `opened pull request #7: https://github.com/op/fixture/pull/7 (from aos/${RUN}/fix/readme into main)\n`,
  ])
  assert.deepEqual(seen.err, [])

  // A shallow workspace's list goes with its objects.
  const shallow = played({ workspace: { '/workspace/.git/HEAD': OID, '/workspace/.git/shallow': `${ZERO}\n` } })
  assert.equal(await publish(ARGS, shallow.deps), PUBLISH_EXIT.ok)
  assert.deepEqual(shallow.seen.writes.map(([path]) => path), [`${dir}/objects/info/alternates`, `${dir}/shallow`])
})

test("README tells the publisher's steps in the order it takes them: HEAD, the default branch, the push, the pull request", () => {
  const readme = readFileSync(join(REPO_ROOT, 'README.md'), 'utf8')
  const start = readme.indexOf('`sandbox.publish` (egress plan S4)')
  assert.ok(start > 0, 'README has no sandbox.publish paragraph')
  const paragraph = readme.slice(start, readme.indexOf('\n\n', start)).replace(/\s+/g, ' ')
  const steps = [
    "reads the commit the workspace's `HEAD` names",
    "reads the repository's default branch",
    'pushes the commit to `refs/heads/aos/<runId>/<branch>`',
    'opens a pull request from that branch into the default branch',
  ]
  const at = steps.map((step) => paragraph.indexOf(step))
  assert.ok(at.every((i) => i >= 0), `README's paragraph does not say: ${steps.filter((_, i) => (at[i] ?? -1) < 0).join('; ')}`)
  assert.deepEqual([...at].sort((a, b) => a - b), at, "README's paragraph tells the steps out of order")
  // As publish.mjs's header numbers them, and publish() runs them.
  const source = readFileSync(join(REPO_ROOT, 'images', 'worker', 'publish.mjs'), 'utf8')
  const header = ['1. Reads the commit the workspace', "3. Reads the repository's default branch", '4. Pushes the commit to', '5. Opens the pull request'].map((line) => source.indexOf(line))
  assert.ok(header.every((i) => i >= 0) && [...header].sort((a, b) => a - b).every((v, i) => v === header[i]), 'publish.mjs header steps')
  const body = ['workspaceHead(deps)', "git('reading the default branch'", "git('the push'", 'deps.post(pullRequest('].map((call) => source.indexOf(call))
  assert.ok(body.every((i) => i >= 0) && [...body].sort((a, b) => a - b).every((v, i) => v === body[i]), 'publish() steps')
})

test("README tells the human approving a publish to read its binding as the running kernel booted with it, not as the manifest or kernel.yaml reads now", () => {
  // The approval names no repository, and the kernel publishes to the
  // bindings it booted with: bootKernel hands config.egress.bindings to the
  // runner once, and loads the agents' manifests (their egress.bind) once
  // (agents.load, its only caller). A manifest or a kernel.yaml edited since
  // the last boot names a repository the publish will not go to, and a human
  // reading the file as it is now approves an irreversible push and pull
  // request against the wrong text.
  const readme = readFileSync(join(REPO_ROOT, 'README.md'), 'utf8')
  const start = readme.indexOf('`sandbox.publish` (egress plan S4)')
  assert.ok(start > 0, 'README has no sandbox.publish paragraph')
  const paragraph = readme.slice(start, readme.indexOf('\n\n', start)).replace(/\s+/g, ' ')
  for (const fact of [
    "so read that binding before approving, in the agent's manifest (`agents/<id>/agent.yaml`, its `egress.bind`) and in kernel.yaml, each as of the kernel's last boot:",
    'the running kernel reads both only at boot and publishes to the bindings it booted with,',
    'so an edit to either takes effect only at the next boot, and a file edited since shows a repository this publish will not go to.',
  ]) {
    assert.ok(paragraph.includes(fact), `README's sandbox.publish paragraph does not say: ${fact}`)
  }
  assert.doesNotMatch(paragraph, /read that binding in kernel\.yaml before approving/, 'README still sends the human to kernel.yaml as it reads now')
  assert.doesNotMatch(paragraph, /in kernel\.yaml as of the kernel's last boot/, 'README names kernel.yaml alone as read at boot, not the manifest beside it')
})

test('publish stops at the first step that fails, and sends nothing after it', async () => {
  const failAt = (step: string) => (sub: string): { code: number | null; stdout?: string; stderr?: string } =>
    sub === step ? { code: 128, stderr: `fatal: ${step} went wrong\n` } : sub === 'ls-remote' ? { code: 0, stdout: `ref: refs/heads/main\tHEAD\n` } : { code: 0 }
  const cases: readonly {
    readonly what: string
    readonly over: Parameters<typeof played>[0]
    readonly gits: readonly string[]
    readonly posts: number
    readonly err: RegExp
  }[] = [
    { what: 'no HEAD in the workspace', over: { workspace: {} }, gits: [], posts: 0, err: /\/workspace\/\.git\/HEAD is no file of its own/ },
    { what: 'its own repository not made', over: { answer: failAt('init') }, gits: ['init'], posts: 0, err: /making the publisher's own repository failed \(git exited 128\): fatal: init went wrong/ },
    { what: 'no default branch read', over: { answer: failAt('ls-remote') }, gits: ['init', 'ls-remote'], posts: 0, err: /reading the default branch failed/ },
    {
      what: 'a default branch that is none',
      over: { answer: (sub) => (sub === 'ls-remote' ? { code: 0, stdout: `${OID}\tHEAD\n` } : { code: 0 }) },
      gits: ['init', 'ls-remote'],
      posts: 0,
      err: /op\/fixture names no default branch/,
    },
    { what: 'the push refused', over: { answer: failAt('push') }, gits: ['init', 'ls-remote', 'push'], posts: 0, err: /the push failed \(git exited 128\): fatal: push went wrong/ },
    {
      what: 'the pull request refused',
      over: { post: () => Promise.resolve({ status: 422, text: JSON.stringify({ message: 'A pull request already exists for op:aos/x.' }) }) },
      gits: ['init', 'ls-remote', 'push'],
      posts: 1,
      err: /the pull request was not opened: HTTP 422: A pull request already exists/,
    },
    {
      what: 'no answer from the mux',
      over: { post: () => Promise.reject(new Error('connect ECONNREFUSED 127.0.0.1:3128')) },
      gits: ['init', 'ls-remote', 'push'],
      posts: 1,
      err: /connect ECONNREFUSED 127\.0\.0\.1:3128/,
    },
  ]
  for (const c of cases) {
    const { deps, seen } = played(c.over)
    assert.equal(await publish(ARGS, deps), PUBLISH_EXIT.failed, c.what)
    assert.deepEqual(seen.gits.map((argv) => argv.slice(PROTECTED.length).find((arg) => !arg.startsWith('--'))), c.gits, c.what)
    assert.equal(seen.posts.length, c.posts, c.what)
    assert.match(seen.err.join(''), c.err, c.what)
    assert.equal(seen.out.some((line) => line.startsWith('opened')), false, c.what)
  }
  // A host's answer is quoted printable and cut.
  assert.deepEqual(pullAnswer(502, JSON.stringify({ message: `bad\u001b[2Jgate${'x'.repeat(600)}` })).ok, false)
  assert.match(pullAnswer(502, JSON.stringify({ message: `bad\u001b[2Jgate${'x'.repeat(600)}` })).line, /^the pull request was not opened: HTTP 502: bad \[2Jgatex+\.\.\.$/)
  assert.equal(pullAnswer(403, 'not json').line, 'the pull request was not opened: HTTP 403')
  assert.deepEqual(pullAnswer(201, '{}'), { ok: true, line: 'opened the pull request (HTTP 201); its answer named no number and address' })
  assert.equal(pullAnswer(201, JSON.stringify({ number: 3, html_url: 'javascript:alert(1)' })).line, 'opened the pull request (HTTP 201); its answer named no number and address')
})

test('the pull request goes to the mux, in absolute form, with its own Host, on an agent of its own', async () => {
  assert.deepEqual([MUX_HOST, MUX_PORT], ['127.0.0.1', EGRESS_MUX_PORT])
  const request = pullRequest(ARGS, 'main')
  assert.deepEqual(muxRequestOptions(request), {
    host: '127.0.0.1',
    port: 3128,
    method: 'POST',
    path: 'http://api.github.com/repos/op/fixture/pulls',
    headers: { ...request.headers },
    setHost: false,
    agent: false,
  })
  assert.equal(request.headers.host, 'api.github.com')

  const sent: { options: unknown; body: string }[] = []
  const answer = (status: number, chunks: readonly string[]) => (options: unknown, callback: (res: never) => void) => {
    let body = ''
    const req = new Writable({
      write(chunk: Buffer, _encoding, done) {
        body += chunk.toString('utf8')
        done()
      },
      final(done) {
        sent.push({ options, body })
        const res = Object.assign(new PassThrough(), { statusCode: status })
        callback(res as never)
        for (const chunk of chunks) res.write(chunk)
        res.end()
        done()
      },
    })
    return req as never
  }
  const got = await postThroughMux(request, answer(201, ['{"number":', '7}']))
  assert.deepEqual(got, { status: 201, text: '{"number":7}' })
  assert.deepEqual(sent, [{ options: muxRequestOptions(request), body: request.body }])
  const long = await postThroughMux(request, answer(200, ['a'.repeat(OUTPUT_MAX_BYTES), 'b'.repeat(10)]))
  assert.equal(long.text.length, OUTPUT_MAX_BYTES)
  await assert.rejects(
    postThroughMux(request, () => {
      const req = new Writable({
        write(_c, _e, done) {
          done()
        },
        final(done) {
          done(new Error('connect ECONNREFUSED 127.0.0.1:3128'))
        },
      })
      return req as never
    }),
    /ECONNREFUSED/,
  )
})

test('the publisher imports only what it uses, runs only as the program, and is what the image copies to the path the kernel names', () => {
  const source = readFileSync(join(REPO_ROOT, 'images', 'worker', 'publish.mjs'), 'utf8')
  assert.deepEqual(
    source.split('\n').filter((line) => /^\s*import\b/.test(line)),
    [
      "import { spawn as spawnChild } from 'node:child_process'",
      "import { lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'",
      "import { request as httpRequest } from 'node:http'",
    ],
  )
  // No other spawn, no environment read but where main() writes its streams.
  assert.equal(source.match(/spawnChild\(/g)?.length, 1)
  assert.equal(source.match(/process\.env/g), null)
  assert.equal(source.trimEnd().split('\n').at(-1), 'if (import.meta.main) await main()')
  const dockerfile = readFileSync(join(REPO_ROOT, 'images', 'worker', 'Dockerfile'), 'utf8')
  assert.ok(dockerfile.includes(`\nCOPY publish.mjs ${PUBLISH_ARGV[1] ?? ''}\n`), 'the Dockerfile copies the publisher to the path the kernel runs')
  assert.equal(PUBLISH_ARGV[0], 'node')
})
