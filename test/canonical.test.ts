// T03 — canonical JSON, the input to every chain hash.
//
// Two properties matter. First, byte-identity with RFC 8785 on the accepted
// domain, so an outside auditor with any JCS library recomputes our hashes.
// Second, refusal everywhere JCS would silently convert, because a silent
// conversion in an append-only log is a hash that cannot be reproduced.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { canonicalHash, canonicalize, sha256Hex } from '../src/events/canonical.js'

test('sorts keys by UTF-16 code units (emoji before U+FF01)', () => {
  // U+1F600 is the surrogate pair D83D DE00, so its first code unit (0xD83D)
  // sorts BEFORE U+FF01 (0xFF01). Under code-point order it would sort after.
  // This is the one case where the two orderings disagree, which is why it is
  // the named test: it pins that we implement RFC 8785's order and not the
  // intuitive one. The expected bytes match the reference implementation
  // canonicalize@5.1.0 (security report section 2.1).
  const input = { '\u{1F600}': 3, a: 2, '': 0, '！': 4, B: 1 }
  assert.equal(canonicalize(input), '{"":0,"B":1,"a":2,"\u{1F600}":3,"！":4}')

  // Spelled out as code units, so a reviewer can check the claim by eye.
  const keys = Object.keys(JSON.parse(canonicalize(input)) as Record<string, unknown>)
  assert.deepEqual(keys, ['', 'B', 'a', '\u{1F600}', '！'])
  assert.ok('\u{1F600}'.charCodeAt(0) < '！'.charCodeAt(0))
})

test('byte-stable across insertion order', () => {
  const a = { z: 1, nested: { b: [1, 2, { y: 'y', x: 'x' }], a: true }, m: null }
  const b = { m: null, nested: { a: true, b: [1, 2, { x: 'x', y: 'y' }] }, z: 1 }
  assert.equal(canonicalize(a), canonicalize(b))
  assert.equal(canonicalize(a), '{"m":null,"nested":{"a":true,"b":[1,2,{"x":"x","y":"y"}]},"z":1}')
  // Array order is data and must NOT be normalized away.
  assert.notEqual(canonicalize([1, 2]), canonicalize([2, 1]))
  // Empty containers survive.
  assert.equal(canonicalize({ a: {}, b: [] }), '{"a":{},"b":[]}')
})

test('rejects 0.1, 2**53, 1e21, NaN, Infinity', () => {
  // Any of these would make a hash depend on float formatting. 2**53 is the
  // sharpest case: JSON.stringify(2**53 + 1) silently yields 9007199254740992,
  // so a value round-trips to a different number and the chain breaks later,
  // far from the cause.
  for (const bad of [0.1, 1e-7, 2 ** 53, 2 ** 53 + 1, 1e21, NaN, Infinity, -Infinity]) {
    assert.throws(
      () => canonicalize({ v: bad }),
      TypeError,
      `canonicalize must reject ${String(bad)}`,
    )
  }
  // The safe-integer boundary itself is accepted, and -0 normalizes to 0
  // exactly as RFC 8785 requires.
  assert.equal(canonicalize({ v: Number.MAX_SAFE_INTEGER }), '{"v":9007199254740991}')
  assert.equal(canonicalize({ v: Number.MIN_SAFE_INTEGER }), '{"v":-9007199254740991}')
  assert.equal(canonicalize({ v: -0 }), '{"v":0}')
})

test('rejects undefined, Date, class instances, bigint instead of silently converting', () => {
  class Point {
    x = 1
  }
  // JCS drops an undefined property and turns a Date into its ISO string. Both
  // are conversions the log must not make on the author's behalf.
  assert.throws(() => canonicalize({ a: undefined, b: 1 }), TypeError)
  assert.throws(() => canonicalize(undefined), TypeError)
  assert.throws(() => canonicalize({ d: new Date(0) }), TypeError)
  assert.throws(() => canonicalize({ p: new Point() }), TypeError)
  assert.throws(() => canonicalize({ n: 1n }), TypeError)
  assert.throws(() => canonicalize({ f: () => 0 }), TypeError)
  assert.throws(() => canonicalize({ s: Symbol('s') }), TypeError)
  assert.throws(() => canonicalize({ m: new Map() }), TypeError)
  assert.throws(() => canonicalize([undefined]), TypeError)
  // A null-prototype object is still a plain record and is accepted.
  const bare = Object.create(null) as Record<string, unknown>
  bare['k'] = 1
  assert.equal(canonicalize(bare), '{"k":1}')
})

test('escapes control characters like JSON.stringify', () => {
  const s = 'quote " backslash \\ newline \n tab \t nul \u0000 unit \u001f del \u007f'
  assert.equal(canonicalize(s), JSON.stringify(s))
  assert.equal(canonicalize({ s }), `{"s":${JSON.stringify(s)}}`)
  // Non-ASCII is emitted literally, not escaped — same as JSON.stringify.
  assert.equal(canonicalize('café'), '"café"')
})

test('rejects lone surrogates (JCS refuses them too)', () => {
  // JSON.stringify would emit "\ud800" here, which is well-formed output for
  // input that is not well-formed text. JCS refuses; so do we, or two
  // implementations would disagree on the bytes.
  assert.throws(() => canonicalize('\uD800'), TypeError)
  assert.throws(() => canonicalize('\uDC00'), TypeError)
  assert.throws(() => canonicalize({ k: 'a\uD800b' }), TypeError)
  // A proper pair is fine.
  assert.equal(canonicalize('😀'), '"\u{1F600}"')
})

test('sha256Hex is stable', () => {
  // Fixed vectors: the empty string and "abc" are the standard NIST cases, so
  // a wrong digest algorithm or encoding is caught without trusting our own
  // helper to define correctness.
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  // UTF-8 encoding, not UTF-16: verified against an independent hash call.
  const s = 'café \u{1F600}'
  assert.equal(sha256Hex(s), createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex'))
  // canonicalHash is exactly sha256Hex ∘ canonicalize, and is order-stable.
  assert.equal(canonicalHash({ b: 2, a: 1 }), sha256Hex('{"a":1,"b":2}'))
  assert.equal(canonicalHash({ a: 1, b: 2 }), canonicalHash({ b: 2, a: 1 }))
})
