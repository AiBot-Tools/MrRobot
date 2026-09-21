// T04 — the value-scrubbing pass that runs before anything is hashed.
//
// Every credential in this file is fabricated. The shapes are real, the
// values are not, and none of them is valid anywhere.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { sha256Hex } from '../src/events/canonical.js'
import { boundOutput, MAX_LOGGED_OUTPUT } from '../src/events/bound.js'
import { CENSOR, MIN_MASK_LENGTH, redactString, redactValue, SecretMask } from '../src/events/redact.js'

test('deny-listed keys censored at any depth, case-insensitive (Authorization, x-api-key, client_secret)', () => {
  // A deny-listed key censors whatever it holds, even a value no pattern
  // would recognise — which is the case that matters for an opaque vault
  // entry that happens to be logged under a known name.
  const out = redactValue({
    Authorization: 'anything at all',
    'X-API-Key': 'opaque-nothing-matches-this',
    nested: { deep: { client_secret: 'plain words here', keep: 'visible' } },
    list: [{ token: 'abc' }, { PASSWORD: 'x' }],
    credentials: { whatever: 1 },
  }) as Record<string, unknown>

  assert.equal(out['Authorization'], CENSOR)
  assert.equal(out['X-API-Key'], CENSOR)
  const nested = out['nested'] as { deep: Record<string, unknown> }
  assert.equal(nested.deep['client_secret'], CENSOR)
  assert.equal(nested.deep['keep'], 'visible', 'non-secret keys must survive')
  const list = out['list'] as Record<string, unknown>[]
  assert.equal(list[0]?.['token'], CENSOR)
  assert.equal(list[1]?.['PASSWORD'], CENSOR)
  // A deny-listed key censors the whole subtree, object value included.
  assert.equal(out['credentials'], CENSOR)
})

test('bearer, sk-/sk-ant-, ghp_/github_pat_, xoxb-, AKIA, JWT, PEM censored inside strings', () => {
  // One assertion per credential family. These are values under innocuous
  // keys, so only the pattern pass can catch them.
  assert.equal(redactString('curl -H "Authorization: Bearer abc.def-ghi_jkl"'), 'curl -H "Authorization: [REDACTED]"')
  assert.match(redactString('key=sk-FAKEFAKEFAKE1234'), /key=\[REDACTED\]$/)
  assert.match(redactString('key=sk-ant-api03-FAKEFAKEFAKE1234'), /key=\[REDACTED\]$/)
  assert.match(redactString('ghp_FAKEfakeFAKEfake0123456789 trailing'), /^\[REDACTED\] trailing$/)
  assert.match(redactString('github_pat_FAKEfake_0123456789abcdef'), /^\[REDACTED\]$/)
  assert.match(redactString('xoxb-000000-000000-FAKEfakeFAKE'), /^\[REDACTED\]$/)
  assert.match(redactString('AKIAFAKEFAKEFAKE2345'), /^\[REDACTED\]$/)
  assert.match(
    redactString('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.FAKEsignature_value'),
    /^\[REDACTED\]$/,
  )
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\nmore\n-----END RSA PRIVATE KEY-----'
  assert.equal(redactString(`before ${pem} after`), `before ${CENSOR} after`)
})

test('registered mask values are censored before regexes and short values are not registered', (t) => {
  t.after(() => {
    SecretMask.clear()
  })
  SecretMask.clear()

  // An opaque vault value of no recognisable shape: patterns cannot help, the
  // mask can. This is why the broker registers what it resolves.
  const opaque = 'correct-horse-battery-staple-42'
  assert.equal(SecretMask.register(opaque), true)
  assert.equal(redactString(`token is ${opaque} here`), `token is ${CENSOR} here`)

  // Too short to register: a 7-character value could be a common word, and
  // masking it would censor unrelated text across the whole log.
  const short = 'abc1234'
  assert.equal(short.length, MIN_MASK_LENGTH - 1)
  assert.equal(SecretMask.register(short), false)
  assert.equal(redactString(`value ${short} stays`), `value ${short} stays`)

  // Mask runs first: a registered value that also matches a pattern is
  // censored once, not censored twice or partially.
  const patterned = 'sk-ant-api03-REGISTERED-value'
  assert.equal(SecretMask.register(patterned), true)
  assert.equal(redactString(`x ${patterned} y`), `x ${CENSOR} y`)

  // Longest-first: one secret containing another must not be left in pieces.
  SecretMask.clear()
  SecretMask.register('inner-secret-value')
  SecretMask.register('prefix-inner-secret-value-suffix')
  assert.equal(redactString('see prefix-inner-secret-value-suffix here'), `see ${CENSOR} here`)
})

test('redacts inside JSON-that-is-a-string', () => {
  // Tool output frequently arrives as a JSON string rather than a structure.
  // The key-based pass cannot see into it, so the pattern pass must.
  const blob = JSON.stringify({
    headers: { authorization: 'Bearer FAKEfake.token-value' },
    body: { apiKey: 'sk-FAKEFAKEFAKE9876' },
  })
  const out = redactString(blob)
  assert.ok(!out.includes('FAKEfake.token-value'), 'bearer token survived inside a JSON string')
  assert.ok(!out.includes('sk-FAKEFAKEFAKE9876'), 'api key survived inside a JSON string')
  assert.ok(out.includes(CENSOR))
  // Still parses: we replaced values, not structure.
  const parsed = JSON.parse(out) as { headers: { authorization: string } }
  assert.equal(parsed.headers.authorization, CENSOR)
})

test('boundOutput redacts first, truncates on a UTF-8 boundary, hashes the redacted text (sha256 != sha256(raw))', () => {
  // A multi-byte character straddling the cut must not be split into a
  // replacement character, and the secret must be gone before any of this.
  const secret = 'sk-FAKEFAKEFAKE5555'
  const raw = `${secret} ` + '\u{1F600}'.repeat(50) // each emoji is 4 bytes
  const max = 21 // lands mid-emoji: '[REDACTED] ' is 11 bytes, then 2.5 emoji
  const out = boundOutput(raw, max)

  assert.equal(out.truncated, true)
  assert.ok(!out.text.includes(secret), 'the secret must be removed before truncation')
  assert.ok(out.text.startsWith(`${CENSOR} `))
  // Boundary-safe: no replacement character, and the byte length is <= max.
  assert.ok(!out.text.includes('�'), 'truncation split a code point')
  assert.ok(Buffer.byteLength(out.text, 'utf8') <= max)
  assert.equal(out.text, `${CENSOR} \u{1F600}\u{1F600}`)

  // bytes is the length of the redacted whole, not of the stored prefix.
  const redactedWhole = `${CENSOR} ` + '\u{1F600}'.repeat(50)
  assert.equal(out.bytes, Buffer.byteLength(redactedWhole, 'utf8'))

  // The digest commits to the redacted text, never the raw text. Storing
  // sha256(raw) would let anyone with a candidate secret confirm it offline.
  assert.equal(out.sha256, sha256Hex(redactedWhole))
  assert.notEqual(out.sha256, sha256Hex(raw))
})

test('below the limit: truncated:false and no hash', () => {
  const out = boundOutput('short and clean')
  assert.equal(out.truncated, false)
  assert.equal(out.text, 'short and clean')
  assert.equal(out.bytes, 15)
  assert.equal(out.sha256, undefined)
  // Exactly at the limit is still not truncated.
  const exact = boundOutput('a'.repeat(MAX_LOGGED_OUTPUT))
  assert.equal(exact.truncated, false)
  assert.equal(exact.bytes, MAX_LOGGED_OUTPUT)
  assert.equal(exact.sha256, undefined)
  // One byte over is.
  const over = boundOutput('a'.repeat(MAX_LOGGED_OUTPUT + 1))
  assert.equal(over.truncated, true)
  assert.equal(over.bytes, MAX_LOGGED_OUTPUT + 1)
  assert.equal(over.text.length, MAX_LOGGED_OUTPUT)
})
