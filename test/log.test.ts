// T02 — the logger's redaction is a backstop with known, tested limits.
//
// The point of these tests is not that pino works; it is that our path list
// covers the fields a credential actually arrives in, and that the one place
// it does not cover is documented rather than assumed.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Writable } from 'node:stream'

import { CENSOR, createLogger, REDACT_PATHS, resolveLevel, scrubLogLine } from '../src/log.js'
import { SecretMask } from '../src/events/redact.js'
import {
  BudgetExceeded,
  ChainBroken,
  ConfigError,
  KernelError,
  NotImplementedError,
  PolicyDenied,
  SecretsSchemaMismatch,
} from '../src/errors.js'

/** Collect one log line as a parsed object. */
function capture(): { lines: string[]; stream: Writable } {
  const lines: string[] = []
  const stream = new Writable({
    write(chunk: Buffer | string, _enc, cb): void {
      lines.push(String(chunk))
      cb()
    },
  })
  return { lines, stream }
}

function logOne(payload: Record<string, unknown>): Record<string, unknown> {
  const { lines, stream } = capture()
  const logger = createLogger({ level: 'info', destination: stream })
  logger.info(payload, 'probe')
  assert.equal(lines.length, 1, 'expected exactly one log line')
  return JSON.parse(lines[0] as string) as Record<string, unknown>
}

const FAKE = 'sk-ant-api03-NOT-A-REAL-KEY'

test('redacts authorization, x-api-key, apiKey, token, secret, password and env.* paths', () => {
  // An opaque value the value pass cannot recognise and no one registered, so
  // only the path list can be what censors it: each assertion here holds the
  // path layer on its own, beneath the value scrubber.
  const OPAQUE = 'opaque-credential-value-0123'
  const out = logOne({
    authorization: OPAQUE,
    headers: { authorization: OPAQUE, 'x-api-key': OPAQUE },
    req: { headers: { authorization: OPAQUE, cookie: 'session=abc', 'x-api-key': OPAQUE } },
    apiKey: OPAQUE,
    api_key: OPAQUE,
    token: OPAQUE,
    secret: OPAQUE,
    password: 'hunter2',
    env: { ANTHROPIC_API_KEY: OPAQUE, PATH: '/usr/bin' },
  })

  const headers = out['headers'] as Record<string, unknown>
  const req = out['req'] as { headers: Record<string, unknown> }
  const env = out['env'] as Record<string, unknown>

  assert.equal(out['authorization'], CENSOR)
  assert.equal(headers['authorization'], CENSOR)
  // The falsifier: drop the x-api-key paths and this line leaks the exact
  // header the pinned Anthropic SDK puts on every request.
  assert.equal(headers['x-api-key'], CENSOR)
  assert.equal(req.headers['authorization'], CENSOR)
  assert.equal(req.headers['cookie'], CENSOR)
  assert.equal(req.headers['x-api-key'], CENSOR)
  assert.equal(out['apiKey'], CENSOR)
  assert.equal(out['api_key'], CENSOR)
  assert.equal(out['token'], CENSOR)
  assert.equal(out['secret'], CENSOR)
  assert.equal(out['password'], CENSOR)
  assert.equal(env['ANTHROPIC_API_KEY'], CENSOR)
  // env.* is a wildcard over every variable, so even innocuous ones go.
  assert.equal(env['PATH'], CENSOR)

  // Nothing resembling the key survives anywhere in the serialized line.
  const { lines, stream } = capture()
  const logger = createLogger({ level: 'info', destination: stream })
  logger.info({ authorization: `Bearer ${FAKE}`, apiKey: FAKE }, 'probe')
  assert.ok(!(lines[0] as string).includes(FAKE), 'the fake credential reached the log line')
})

test('top-level x-api-key is redacted via bracket path', () => {
  // Hyphenated keys need bracket notation. A bare `x-api-key` path happens to
  // work at top level on this pino build but is undocumented, so the config
  // uses the bracket form and this test pins that behaviour.
  const out = logOne({ 'x-api-key': 'opaque-header-value-0123' })
  assert.equal(out['x-api-key'], CENSOR)
  assert.ok(REDACT_PATHS.includes('["x-api-key"]'))
})

test('wildcard covers one level only (documented limit)', () => {
  // This asserts a LIMITATION, deliberately. pino's `*` matches exactly one
  // level, so a value the scrubber cannot recognise, nested two deep under a
  // credential-looking key, is NOT redacted. That is why no module may log raw
  // payloads. A recognisable one is caught by the value pass instead (below).
  const OPAQUE = 'opaque-unregistered-value'
  const out = logOne({ nested: { apiKey: OPAQUE }, deep: { deeper: { apiKey: OPAQUE, shaped: FAKE } } })
  const nested = out['nested'] as Record<string, unknown>
  const deep = out['deep'] as { deeper: Record<string, unknown> }
  assert.equal(nested['apiKey'], CENSOR, 'one level deep must be redacted')
  assert.equal(deep.deeper['apiKey'], OPAQUE, 'two levels deep is NOT covered by path — documented limit')
  assert.equal(deep.deeper['shaped'], CENSOR, 'a credential shape is censored by value at any depth')
})

test('a registered secret never reaches the process log: msg, error text, bindings, any depth', (t) => {
  // A server that echoes a bearer in its 401 body makes the SDK throw with the
  // bearer in e.message, and callers log e.message. pino's paths never look at
  // values, so the value pass is what keeps it out of stdout.
  t.after(() => SecretMask.clear())
  const BEARER = 'qOpaqueBearerCanary0123456789abcdefghij'
  assert.equal(SecretMask.register(BEARER), true)
  const { lines, stream } = capture()
  const logger = createLogger({ level: 'info', destination: stream }).child({ server: `pmmcp ${BEARER}` })
  logger.warn({ err: `Streamable HTTP error: unauthorized: ${BEARER}`, deep: { a: { b: [BEARER] } } }, `connect failed: ${BEARER}`)
  logger.error({ err: new Error(`unauthorized: ${BEARER}`) }, 'failed')
  assert.equal(lines.length, 2)
  for (const line of lines) {
    for (let i = 0; i + 8 <= BEARER.length; i++) {
      assert.equal(line.includes(BEARER.slice(i, i + 8)), false, `a piece of the bearer reached the log: ${line}`)
    }
    assert.ok(line.includes(CENSOR), line)
    JSON.parse(line) // still one JSON record per line
  }
  const out = JSON.parse(lines[0] as string) as Record<string, unknown>
  assert.equal(out['msg'], `connect failed: ${CENSOR}`)
  assert.equal(out['server'], `pmmcp ${CENSOR}`)
})

test('the line scrubber finds a secret JSON escaping respelled, and scrubs a line it cannot parse', (t) => {
  t.after(() => SecretMask.clear())
  const QUOTED = 'a"b\\c-opaque-1234'
  assert.equal(SecretMask.register(QUOTED), true)
  const line = `${JSON.stringify({ level: 30, msg: `x ${QUOTED} y` })}\n`
  assert.equal(line.includes(QUOTED), false, 'JSON escaping changed the spelling, as the test needs')
  const scrubbed = scrubLogLine(line)
  assert.deepEqual(JSON.parse(scrubbed), { level: 30, msg: `x ${CENSOR} y` })
  assert.ok(scrubbed.endsWith('\n'))
  assert.equal(scrubLogLine(`not json ${QUOTED}\n`), `not json ${CENSOR}\n`)
})

test('level from AOS_LOG_LEVEL defaults to info', () => {
  assert.equal(resolveLevel({}), 'info')
  assert.equal(resolveLevel({ AOS_LOG_LEVEL: '' }), 'info')
  assert.equal(resolveLevel({ AOS_LOG_LEVEL: 'debug' }), 'debug')
  const { stream } = capture()
  assert.equal(createLogger({ destination: stream }).level, resolveLevel())
})

test('child logger inherits redaction', () => {
  const { lines, stream } = capture()
  const child = createLogger({ level: 'info', destination: stream }).child({ runId: 'run-1' })
  // Opaque values, so the child's PATH redaction is what is shown, not the value pass.
  child.info({ authorization: 'opaque-credential-value-0123', headers: { 'x-api-key': 'opaque-header-value-0123' } }, 'probe')
  const out = JSON.parse(lines[0] as string) as Record<string, unknown>
  assert.equal(out['runId'], 'run-1')
  assert.equal(out['authorization'], CENSOR)
  assert.equal((out['headers'] as Record<string, unknown>)['x-api-key'], CENSOR)
})

test('every error class carries a code', () => {
  const cases: ReadonlyArray<readonly [KernelError, string]> = [
    [new NotImplementedError('apple-container driver'), 'AOS_NOT_IMPLEMENTED'],
    [new ConfigError('kernel.yaml: dataDir must be outside the repo'), 'AOS_CONFIG'],
    [new PolicyDenied('pmmcp.remember', 'tool is kernel-only'), 'AOS_POLICY_DENIED'],
    [new ChainBroken(42, 'prevHash mismatch'), 'AOS_CHAIN_BROKEN'],
    [new SecretsSchemaMismatch('get_secret does not accept `label`'), 'AOS_SECRETS_SCHEMA_MISMATCH'],
    [new BudgetExceeded('run:run-1', 'wallclock'), 'AOS_BUDGET_EXCEEDED'],
  ]
  for (const [err, code] of cases) {
    assert.ok(err instanceof KernelError, `${err.name} must extend KernelError`)
    assert.ok(err instanceof Error)
    assert.equal(err.code, code)
    assert.notEqual(err.name, 'Error', 'name must identify the class')
    assert.ok(err.message.length > 0)
    assert.ok(err.stack !== undefined)
  }
  // Codes are unique: the control plane and CLI match on them.
  const codes = cases.map(([, c]) => c)
  assert.equal(new Set(codes).size, codes.length)
})
