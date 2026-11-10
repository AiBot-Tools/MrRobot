// Egress plan E1 — the host normaliser (src/egress/host.ts) and the address
// classifier (src/egress/addr.ts).
//
// These two decide what the egress engine may resolve and what it may dial,
// and both fail OPEN when they are wrong: the request goes out, it succeeds,
// and nobody learns it reached the Mac's loopback. From a Colima VM,
// 192.168.5.2 IS the Mac's 127.0.0.1 on every port, and host.lima.internal is
// its name; pmmcp listens there in warn mode. So every range is checked at its
// edges and its neighbours rather than at one sample, and every spelling of an
// address is tried, because a deny list matched against text it cannot read
// answers "not listed":
//
//   Read `127.1` or `0x7f.1` with BlockList and it is in no range, so a deny
//   list consulted with unchecked text lets every legacy IPv4 notation
//   through. The address classifier must refuse what it cannot read.
//   Drop one of the four unwraps and an IPv6 answer that carries 127.0.0.1
//   (::ffff:127.0.0.1, 64:ff9b::7f00:1, 2002:7f00:1::, a Teredo address) is
//   dialled, or a public one carried the same way is refused for a reason
//   that is not true. Node's BlockList happens to match IPv4-mapped
//   addresses against IPv4 rules; nothing here relies on it.
//   Admit a host whose last label is a number and `0x7f.1` is an allowlist
//   entry a URL parser reads as 127.0.0.1.
//   Admit *.internal and host.lima.internal can be named at all.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

import {
  ADDRESS_DENIALS,
  addressDenial,
  IPV4_DENIED,
  IPV6_DENIED,
  IPV6_GLOBAL_UNICAST,
  isDeniedAddress,
  UNWRAPS,
  type AddressDenialReason,
  type DeniedRanges,
  type Unwrap,
} from '../src/egress/addr.js'
import { EgressHost, HOST_REFUSALS, parseEgressHost, SPECIAL_USE, type HostRefusal } from '../src/egress/host.js'

const REPO = new URL('..', import.meta.url).pathname.replace(/\/$/, '')

// ── address arithmetic, written independently of addr.ts ─────────────────────

function v4Text(value: number): string {
  return [value >>> 24, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.')
}

function v4Value(text: string): number {
  return text.split('.').reduce((n, part) => n * 256 + Number(part), 0)
}

/** First and last address of an IPv4 CIDR. */
function v4Span(cidr: string): readonly [number, number] {
  const [network = '', bits = ''] = cidr.split('/')
  const size = 2 ** (32 - Number(bits))
  const first = v4Value(network)
  return [first, first + size - 1]
}

/** Full eight-group text of a 128-bit value. */
function v6Text(value: bigint): string {
  const groups: string[] = []
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(((value >> shift) & 0xffffn).toString(16))
  return groups.join(':')
}

function v6Value(text: string): bigint {
  const [front = '', back] = text.split('::')
  const head = front === '' ? [] : front.split(':')
  const rest = back === undefined || back === '' ? [] : back.split(':')
  const groups = [...head, ...Array<string>(8 - head.length - rest.length).fill('0'), ...rest]
  return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n)
}

function v6Span(cidr: string): readonly [bigint, bigint] {
  const [network = '', bits = ''] = cidr.split('/')
  const hostBits = BigInt(128 - Number(bits))
  const first = (v6Value(network) >> hostBits) << hostBits
  return [first, first + (1n << hostBits) - 1n]
}

/** Every address in an IPv4 CIDR at `stride`, plus its last one. */
function v4Sweep(cidr: string, stride: number): string[] {
  const [first, last] = v4Span(cidr)
  const out: string[] = []
  for (let a = first; a <= last; a += stride) out.push(v4Text(a))
  out.push(v4Text(last))
  return out
}

function deniedAs(address: string, reason: AddressDenialReason, via?: Unwrap, embedded?: string): void {
  const denial = addressDenial(address)
  assert.ok(denial !== undefined, `${address} must be denied (${reason})`)
  assert.equal(denial.reason, reason, `${address} is denied as ${denial.reason}, not ${reason}`)
  assert.equal(denial.via, via, `${address} was unwrapped via ${String(denial.via)}, not ${String(via)}`)
  assert.equal(denial.embedded, embedded, `${address} carries ${String(denial.embedded)}, not ${String(embedded)}`)
  assert.equal(isDeniedAddress(address), true, address)
}

function allowed(address: string): void {
  assert.equal(addressDenial(address), undefined, `${address} must be allowed, got ${JSON.stringify(addressDenial(address))}`)
  assert.equal(isDeniedAddress(address), false, address)
}

// ── addr.ts ──────────────────────────────────────────────────────────────────

test('denies 192.168.5.2, all of 192.168.5.0/24, 127/8, 10/8, 172.16/12, 100.64/10, 169.254/16, ::1, fe80::/10, fc00::/7, ::ffff:127.0.0.1, 64:ff9b::7f00:1, 2002:7f00:1::; allows a public v4 and v6', () => {
  // The address a Colima VM reaches the Mac's loopback by, and its whole subnet.
  deniedAs('192.168.5.2', 'private')
  for (const a of v4Sweep('192.168.5.0/24', 1)) deniedAs(a, 'private')

  const ranges: ReadonlyArray<readonly [string, AddressDenialReason, number]> = [
    ['127.0.0.0/8', 'loopback', 4093],
    ['10.0.0.0/8', 'private', 4093],
    ['172.16.0.0/12', 'private', 1021],
    ['192.168.0.0/16', 'private', 253],
    ['100.64.0.0/10', 'shared', 1021],
    ['169.254.0.0/16', 'link-local', 253],
  ]
  for (const [cidr, reason, stride] of ranges) for (const a of v4Sweep(cidr, stride)) deniedAs(a, reason)

  // One past each edge is a public address: the ranges are no wider than they say.
  for (const a of [
    '9.255.255.255', '11.0.0.0',
    '126.255.255.255', '128.0.0.0',
    '172.15.255.255', '172.32.0.0',
    '192.167.255.255', '192.169.0.0',
    '100.63.255.255', '100.128.0.0',
    '169.253.255.255', '169.255.0.0',
  ]) {
    allowed(a)
  }

  deniedAs('::1', 'loopback')
  deniedAs('0:0:0:0:0:0:0:1', 'loopback')
  for (const a of ['fe80::', 'fe80::1', 'fe80::1:2:3:4', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'FE80::ABCD']) deniedAs(a, 'link-local')
  for (const a of ['fc00::', 'fc00::1', 'fd00:aaaa::1', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']) deniedAs(a, 'unique-local')

  deniedAs('::ffff:127.0.0.1', 'loopback', 'ipv4-mapped', '127.0.0.1')
  deniedAs('64:ff9b::7f00:1', 'loopback', 'nat64', '127.0.0.1')
  deniedAs('2002:7f00:1::', 'loopback', '6to4', '127.0.0.1')

  // GitHub, Cloudflare and Google: public v4 and v6.
  for (const a of ['140.82.112.3', '1.1.1.1', '8.8.8.8', '93.184.215.14', '223.255.255.255', '1.0.0.0']) allowed(a)
  for (const a of ['2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450:4001:82a::200e', '2000::', '3fff:1000::1']) allowed(a)
})

test('denies 0.0.0.0/8, multicast, broadcast, 240/4 and every documentation and benchmarking range, in both families, each with its reason', () => {
  // 0.0.0.0 reaches the Mac's own listeners on macOS and Linux.
  for (const a of v4Sweep('0.0.0.0/8', 65_521)) deniedAs(a, 'this-network')
  for (const a of ['224.0.0.1', '224.0.0.251', '239.255.255.250', '233.252.0.1', '239.255.255.255']) deniedAs(a, 'multicast')
  for (const a of ['ff02::1', 'ff02::fb', 'ff05::1:3', 'ff0e::1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']) deniedAs(a, 'multicast')
  deniedAs('255.255.255.255', 'broadcast')
  for (const a of ['240.0.0.0', '240.0.0.1', '250.1.2.3', '255.255.255.254']) deniedAs(a, 'reserved')
  for (const cidr of ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']) for (const a of v4Sweep(cidr, 17)) deniedAs(a, 'documentation')
  for (const a of ['2001:db8::', '2001:db8::1', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '3fff::', '3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff']) {
    deniedAs(a, 'documentation')
  }
  for (const a of v4Sweep('198.18.0.0/15', 4099)) deniedAs(a, 'benchmarking')
  deniedAs('2001:2::1', 'benchmarking')
  for (const a of ['192.0.0.1', '192.0.0.8', '192.0.0.170', '192.0.0.255']) deniedAs(a, 'ietf-protocol')
  for (const a of ['2001:1::1', '2001:3::1', '2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff']) deniedAs(a, 'ietf-protocol')
  for (const a of ['192.88.99.1', '192.31.196.1', '192.52.193.1', '192.175.48.1', '100::1', '64:ff9b:1::7f00:1', '2620:4f:8000::1', '5f00::1']) {
    deniedAs(a, 'special-purpose')
  }
  deniedAs('::', 'unspecified')
  deniedAs('::127.0.0.1', 'ipv4-compatible')
  deniedAs('::8.8.8.8', 'ipv4-compatible')
  // Outside 2000::/3 and in no named range: deprecated site-local, the unassigned rest.
  for (const a of ['fec0::1', '4000::1', '1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'e000::1', '::ffff:0:7f00:1']) deniedAs(a, 'not-global-unicast')
})

test('every range in the deny tables is denied at its first and last address, and 2000::/3 bounds what IPv6 may be', () => {
  // The tables are data; this holds each entry to what it says, so a range
  // mistyped narrower than its CIDR would fail here as well as above.
  for (const [reason, cidrs] of IPV4_DENIED) {
    assert.ok(ADDRESS_DENIALS.includes(reason))
    for (const cidr of cidrs) {
      const [first, last] = v4Span(cidr)
      for (const a of [first, last]) assert.equal(isDeniedAddress(v4Text(a)), true, `${v4Text(a)} in ${cidr} (${reason})`)
    }
  }
  for (const [reason, cidrs] of IPV6_DENIED) {
    assert.ok(ADDRESS_DENIALS.includes(reason))
    for (const cidr of cidrs) {
      const [first, last] = v6Span(cidr)
      for (const a of [first, last]) assert.equal(isDeniedAddress(v6Text(a)), true, `${v6Text(a)} in ${cidr} (${reason})`)
    }
  }
  const [first, last] = v6Span(IPV6_GLOBAL_UNICAST)
  deniedAs(v6Text(first - 1n), 'not-global-unicast')
  deniedAs(v6Text(last + 1n), 'not-global-unicast')
  allowed(v6Text(first))
  allowed('2a01:111:f400::1')
})

test('IPv4-mapped, NAT64, 6to4 and Teredo are unwrapped explicitly: denied in every spelling when what they carry is denied, allowed when it is public', () => {
  // IPv4-mapped: every way RFC 4291 lets it be written.
  for (const a of ['::ffff:127.0.0.1', '::ffff:7f00:1', '::FFFF:7F00:0001', '0:0:0:0:0:ffff:7f00:1', '0000:0000:0000:0000:0000:ffff:127.0.0.1']) {
    deniedAs(a, 'loopback', 'ipv4-mapped', '127.0.0.1')
  }
  deniedAs('::ffff:192.168.5.2', 'private', 'ipv4-mapped', '192.168.5.2')
  deniedAs('::ffff:c0a8:502', 'private', 'ipv4-mapped', '192.168.5.2')
  deniedAs('::ffff:10.0.0.1', 'private', 'ipv4-mapped', '10.0.0.1')
  deniedAs('::ffff:0.0.0.0', 'this-network', 'ipv4-mapped', '0.0.0.0')
  deniedAs('::ffff:169.254.169.254', 'link-local', 'ipv4-mapped', '169.254.169.254')
  allowed('::ffff:8.8.8.8')
  allowed('::ffff:140.82.112.3')

  // NAT64's well-known prefix: what a DNS64 resolver answers for a v4-only name.
  for (const a of ['64:ff9b::7f00:1', '64:ff9b::127.0.0.1', '64:FF9B:0:0:0:0:7F00:1']) deniedAs(a, 'loopback', 'nat64', '127.0.0.1')
  deniedAs('64:ff9b::192.168.5.2', 'private', 'nat64', '192.168.5.2')
  deniedAs('64:ff9b::a9fe:a9fe', 'link-local', 'nat64', '169.254.169.254')
  allowed('64:ff9b::808:808')
  allowed('64:ff9b::140.82.112.3')

  // 6to4: bits 16-47.
  for (const a of ['2002:7f00:1::', '2002:7f00:0001::1', '2002:7f00:1:ffff:ffff:ffff:ffff:ffff']) deniedAs(a, 'loopback', '6to4', '127.0.0.1')
  deniedAs('2002:c0a8:502::1', 'private', '6to4', '192.168.5.2')
  deniedAs('2002:a00:1::', 'private', '6to4', '10.0.0.1')
  allowed('2002:808:808::1')

  // Teredo: server at bits 32-63, client inverted at bits 96-127. The client
  // 127.0.0.1 is 0x7f000001 ^ 0xffffffff = 0x80fffffe, and 8.8.8.8 is f7f7:f7f7.
  deniedAs('2001:0:808:808:0:0:80ff:fffe', 'loopback', 'teredo-client', '127.0.0.1')
  deniedAs('2001::808:808:8000:ffff:3f57:fafd', 'private', 'teredo-client', '192.168.5.2')
  deniedAs('2001:0:7f00:1::f7f7:f7f7', 'loopback', 'teredo-server', '127.0.0.1')
  deniedAs('2001:0:c0a8:502::f7f7:f7f7', 'private', 'teredo-server', '192.168.5.2')
  // An uninverted 127.0.0.1 in the client field is the client 128.255.255.254, public.
  allowed('2001:0:808:808::f7f7:f7f7')
  allowed('2001:0:808:808::7f00:1')
})

test('IPv4 in any legacy notation, a zone, brackets and any other text are no address, and are denied, public-looking or not', () => {
  // Each of these is an address to inet_aton or a URL parser, and to BlockList
  // none is in any range. Public-looking ones are denied too: the classifier
  // reads one spelling, and the rest are refused, not guessed at.
  for (const a of [
    '2130706433', '0x7f000001', '0X7F000001', '017700000001',
    '0x7f.1', '0x7f.0.0.1', '0x7f.0x0.0x0.0x1', '0177.0.0.1', '0177.0.0.01', '127.1', '127.0.1', '127.000.000.001',
    '134744072', '0x08080808', '010.010.010.010', '8.8.8.010', '8.8.2056', '0x8.0x8.0x8.0x8',
    '127.0.0.1.', '8.8.8.8.', ' 8.8.8.8', '8.8.8.8 ', '8.8.8.8\n', '1.2.3.4/32', '1.2.3.4:443', '256.1.1.1', '1.2.3',
    '[::1]', '[2606:4700:4700::1111]', 'fe80::1%en0', 'fe80::1%1', '2606:4700:4700::1111%en0', '::ffff:127.0.0.1%lo0',
    '::ffff:127.000.000.001', '::ffff:0x7f.0.0.1', '::ffff:127.1', ':::1', '1::2::3', '12345::1', 'g::1',
    '', 'localhost', 'github.com', '1', 'null',
  ]) {
    deniedAs(a, 'not-an-address')
  }
})

// ── host.ts ──────────────────────────────────────────────────────────────────

function refusedAs(input: string, reason: HostRefusal): void {
  const verdict = parseEgressHost(input)
  assert.equal(verdict.ok, false, `${JSON.stringify(input)} must be refused (${reason}), got ${JSON.stringify(verdict)}`)
  if (verdict.ok) return
  assert.equal(verdict.reason, reason, `${JSON.stringify(input)} is refused as ${verdict.reason}, not ${reason}`)
  assert.equal(EgressHost.safeParse(input).success, false, `the schema admits ${JSON.stringify(input)}`)
}

function admittedAs(input: string, host: string): void {
  const verdict = parseEgressHost(input)
  assert.deepEqual(verdict, { ok: true, host }, `${JSON.stringify(input)} must be admitted as ${host}`)
  assert.equal(EgressHost.parse(input), host)
}

test('EgressHost refuses host.lima.internal, host.docker.internal, gateway.docker.internal, localhost, 2130706433, 0x7f.1, 0177.0.0.1, [::1], a port, a wildcard and non-ASCII', () => {
  refusedAs('host.lima.internal', 'special-use')
  refusedAs('host.docker.internal', 'special-use')
  refusedAs('gateway.docker.internal', 'special-use')
  refusedAs('localhost', 'special-use')
  refusedAs('2130706433', 'ip-literal')
  refusedAs('0x7f.1', 'ip-literal')
  refusedAs('0177.0.0.1', 'ip-literal')
  refusedAs('[::1]', 'ip-literal')
  refusedAs('github.com:443', 'port')
  refusedAs('*.github.com', 'wildcard')
  refusedAs('gíthub.com', 'non-ascii')
})

test('EgressHost refuses an IP literal in every notation: dotted, whole, octal, hex, mixed, short, trailing-dot, bracketed, bare and zoned', () => {
  for (const input of [
    // Dotted decimal, public or not.
    '127.0.0.1', '192.168.5.2', '8.8.8.8', '0.0.0.0', '255.255.255.255',
    // One number: decimal, hex, octal.
    '2130706433', '3232236802', '0x7f000001', '0X7F000001', '0x', '0', '017700000001',
    // In parts, each decimal, octal or hex; short forms fill the last part.
    '0x7f.1', '0x7f.0.0.1', '0x7f.0x0.0x0.0x1', '0177.0.0.1', '0177.0.0.01', '127.1', '127.0.1', '127.0x0.1', '0300.0250.5.2',
    // The fully-qualified spelling of each.
    '127.0.0.1.', '2130706433.', '0x7f.1.', '127.1.',
    // A name that ends in a number is an IPv4 address to a URL parser, or no host.
    'example.0', 'example.123', 'example.0x7f', 'example.0x',
    // IPv6: bracketed, bare, mapped, zoned, with and without a port.
    '[::1]', '::1', '[::ffff:127.0.0.1]', '::ffff:127.0.0.1', '[64:ff9b::7f00:1]', '0:0:0:0:0:0:0:1',
    '[fe80::1%25en0]', 'fe80::1%en0', '[::1]:443', '[2606:4700:4700::1111]', '2606:4700:4700::1111', '[v1.fe]',
    // A zone net.isIP will not read is still a zone on an address.
    'fe80::1%', 'fe80::1%en 0', 'fe80::1%en0/64',
  ]) {
    refusedAs(input, 'ip-literal')
  }
})

test('EgressHost refuses every special-use name and every name beneath one', () => {
  for (const suffix of SPECIAL_USE) {
    refusedAs(suffix, 'special-use')
    refusedAs(`${suffix}.`, 'special-use')
    refusedAs(`a.${suffix}`, 'special-use')
    refusedAs(`deep.er.${suffix.toUpperCase()}`, 'special-use')
  }
  for (const input of [
    'LOCALHOST', 'localhost.', 'api.localhost', 'mac.local', 'Operators-MacBook.local.',
    'host.lima.internal', 'host.docker.internal', 'gateway.docker.internal', 'kubernetes.docker.internal', 'x.internal',
    'localhost.localdomain', 'router.home.arpa', '1.0.0.127.in-addr.arpa', 'b.a.ip6.arpa',
    'x.invalid', 'x.test', 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion', 'x.alt',
    // The router and private-network conventions, whose names a home router answers with LAN addresses.
    'router.lan', 'nas.home', 'x.corp', 'wiki.intranet', 'db.private', 'localhost6.localdomain6', 'intranet', 'HOME.',
  ]) {
    refusedAs(input, 'special-use')
  }
  for (const suffix of ['lan', 'home', 'corp', 'intranet', 'private', 'localdomain6']) assert.ok(SPECIAL_USE.includes(suffix), suffix)
  // A special-use word inside a public name is just a label.
  for (const host of ['localhost.example.com', 'local.example.com', 'internal.github.com', 'test.github.com', 'internalx.com', 'xlocal.com', 'home.example.com', 'lan.example', 'homes.example', 'private.example.org']) {
    admittedAs(host, host)
  }
})

test('EgressHost refuses userinfo, URL syntax, bad labels, single labels, over-long names and non-canonical punycode, and admits the edges of what DNS allows', () => {
  for (const input of ['user@github.com', 'user:pw@github.com', '@github.com', 'github.com@evil.example']) refusedAs(input, 'userinfo')
  for (const input of ['https://github.com', 'github.com/owner/repo', 'github.com?x=1', 'github.com#x', 'github.com\\evil.example', '//github.com']) {
    refusedAs(input, 'syntax')
  }
  for (const input of ['github.com:', 'github.com:443', 'github.com:80', 'evil.example:22']) refusedAs(input, 'port')
  for (const input of ['*', '*.github.com', 'git*hub.com', 'github.*']) refusedAs(input, 'wildcard')
  for (const input of ['git hub.com', ' github.com', 'github.com ', 'github.com\n', 'github.com\0', 'git_hub.com', '%67ithub.com', 'github.com,evil.example', 'github!.com']) {
    refusedAs(input, 'syntax')
  }
  // Fullwidth letters and the ideographic full stop are letters and a dot to a URL parser.
  for (const input of ['gíthub.com', 'ｇｉｔｈｕｂ.com', 'github。com', 'bücher.de', '１２７.0.0.1', 'github.com​']) refusedAs(input, 'non-ascii')
  for (const input of ['.github.com', 'github..com', 'github.com..', '-github.com', 'github-.com', 'github.-com', `${'a'.repeat(64)}.com`]) {
    refusedAs(input, 'label')
  }
  refusedAs('', 'empty')
  refusedAs('.', 'empty')
  for (const input of ['github', 'GITHUB', 'github.', 'com']) refusedAs(input, 'single-label')
  // No valid punycode, two labels raw punycode decodes but UTS 46 refuses
  // (xn--wca is an upper-case Ü, xn--ab-r13a is 'a。b', with an ideographic
  // full stop), for all of which Node 22's domainToUnicode answers '', and
  // two it decodes that are a second spelling of 汘 and 公司 (xn--2sw and
  // xn--55qx5d), with a delimiter before an empty basic part. Those two
  // decode to non-ASCII, so only isCanonicalLabel's round trip refuses them;
  // its non-ASCII and no-dot tests are defence in depth (host.ts says why).
  for (const input of ['xn--zz.com', 'xn--a.com', 'xn--wca.com', 'xn--ab-r13a.com', 'www.xn--zz', 'xn---2sw.com', 'xn---55qx5d.cn']) {
    refusedAs(input, 'punycode')
  }
  // A label that punycode decodes to plain ASCII (localhost, xn--abc) ends in
  // its delimiter, as every such label must, so it never reaches the
  // punycode test: a label that ends in a hyphen is refused first.
  for (const input of ['xn--localhost-.com', 'xn--xn--abc-.com', 'xn--com-.com', 'www.xn--localhost-']) refusedAs(input, 'label')
  admittedAs('xn--2sw.com', 'xn--2sw.com')

  // The longest name DNS allows, and one past it.
  const label63 = 'a'.repeat(63)
  const longest = `${label63}.${label63}.${label63}.${'b'.repeat(61)}`
  assert.equal(longest.length, 253)
  admittedAs(longest, longest)
  admittedAs(`${longest}.`, longest)
  refusedAs(`${longest}b`, 'too-long')
  refusedAs(`${'a.'.repeat(130)}com`, 'too-long')
  refusedAs('a'.repeat(10_000), 'too-long')
  admittedAs(`${label63}.com`, `${label63}.com`)
  admittedAs('xn--bcher-kva.de', 'xn--bcher-kva.de')
  admittedAs('XN--BCHER-KVA.DE', 'xn--bcher-kva.de')
  admittedAs('xn--55qx5d.cn', 'xn--55qx5d.cn')
  for (const host of ['ab--cd.com', '123.example.com', '0x7f.example.com', 'a.b', 'a-b.c-d.e0', 'api.github.com']) admittedAs(host, host)
})

test('EgressHost normalises case and one trailing dot, and its one spelling is a fixed point', () => {
  admittedAs('GitHub.COM.', 'github.com')
  admittedAs('API.GitHub.com', 'api.github.com')
  admittedAs('github.com.', 'github.com')
  admittedAs('github.com', 'github.com')
  // Two spellings of a name normalise to one, so an allowlist compares by equality.
  assert.equal(EgressHost.parse('Codeload.GitHub.com.'), EgressHost.parse('codeload.github.com'))
  for (const input of ['GitHub.COM.', 'xn--bcher-kva.DE.', 'a.B', `${'A'.repeat(63)}.com.`]) {
    const once = EgressHost.parse(input)
    assert.equal(EgressHost.parse(once), once, `${input} normalises to ${once}, which normalises again`)
  }
})

test('the EgressHost schema refuses what parseEgressHost refuses, in zod, and no refusal sentence echoes its input', () => {
  const inputs = [
    'host.lima.internal', '127.0.0.1', '0x7f.1', '[::1]', 'user@github.com', 'github.com:443', '*.github.com',
    'gíthub.com', 'github', 'xn--zz.com', '-github.com', 'a'.repeat(300), 'https://github.com', '',
    // Attacker-chosen text, as a worker's request host is.
    'ghp_0123456789abcdefghijklmnopqrstuvwxyz@github.com', 'Bearer.sk-live-ABCDEFGH12345678:1', 'xn--secretvalue.internal',
  ]
  const reasons = new Set<HostRefusal>()
  for (const input of inputs) {
    const verdict = parseEgressHost(input)
    assert.equal(verdict.ok, false, JSON.stringify(input))
    if (verdict.ok) continue
    reasons.add(verdict.reason)
    assert.ok(HOST_REFUSALS.includes(verdict.reason))
    const parsed = EgressHost.safeParse(input)
    assert.equal(parsed.success, false)
    const message = parsed.error?.issues.map((i) => i.message).join('\n') ?? ''
    assert.equal(message, `not an egress host: it ${verdict.why}`)
    for (const text of [verdict.why, message]) {
      if (input.length >= 4) assert.equal(text.includes(input), false, `the refusal of ${JSON.stringify(input)} echoes it`)
      for (const fragment of ['ghp_', 'sk-live', 'secretvalue', 'lima']) {
        if (input.includes(fragment)) assert.equal(text.includes(fragment), false, `the refusal echoes ${fragment}`)
      }
    }
  }
  assert.ok(reasons.size >= 10, `the inputs exercise only ${String(reasons.size)} reasons`)
  // A config value that is a name comes back branded and normalised.
  const Binding = EgressHost.array()
  assert.deepEqual(Binding.parse(['GitHub.com', 'api.github.com.']), ['github.com', 'api.github.com'])
  assert.equal(Binding.safeParse(['github.com', 'host.docker.internal']).success, false)
})

/** What host.ts and addr.ts may import, by module and by name: no socket, resolver or file API is among them. */
const PURE_IMPORTS: Readonly<Record<string, readonly string[]>> = {
  'node:net': ['BlockList', 'isIP', 'isIPv4', 'isIPv6'],
  'node:url': ['domainToASCII', 'domainToUnicode'],
  zod: ['z'],
}

/**
 * Names a pure module has no use for, each a way to I/O, or to code that does
 * it, with no import at all: the process object (env, getBuiltinModule,
 * binding), the global object under both its names, fetch, WebSocket and
 * XMLHttpRequest, require, and eval, Function and `constructor`, which reaches
 * Function from any value (`[].constructor.constructor('return process')`);
 * and Reflect and the prototype accessors (getPrototypeOf, `__proto__`,
 * getOwnPropertyDescriptor(s), getOwnPropertyNames), which reach it from any
 * function without naming `constructor` as a word.
 */
const IMPURE_NAMES: ReadonlySet<string> = new Set([
  'process', 'globalThis', 'global', 'fetch', 'require', 'eval', 'Function', 'WebSocket', 'XMLHttpRequest', 'constructor',
  'Reflect', 'getPrototypeOf', '__proto__', 'getOwnPropertyDescriptor', 'getOwnPropertyDescriptors', 'getOwnPropertyNames',
])

/** An impure name as a word of a string: not inside a longer name, nor a hyphenated one ('not-global-unicast' is clean). */
const IMPURE_WORDS: readonly RegExp[] = [...IMPURE_NAMES].map((name) => new RegExp(`(?<![\\w$-])${name}(?![\\w$-])`))

/**
 * What a file does that a pure module may not, read from its syntax tree
 * rather than matched as text, and the names it imports that it may. Every
 * import must take allowlisted names from an allowlisted module by named
 * import: a module outside PURE_IMPORTS, a name outside its list (`connect`,
 * however it is renamed), a namespace or default import (`net['connect']`
 * needs no name), a bare `import 'x'`, any re-export, `import x = require()`,
 * `import()` and `import('x')` in a type are all offences. So is any
 * identifier in IMPURE_NAMES wherever it stands (a destructuring of process,
 * `fetch ('...')` with a space, a property named `constructor`), import.meta,
 * and any string in code that spells one of those names or a `node:` module,
 * or holds one as a word ('return process'), the way `x['constructor']`
 * reaches one with no identifier. A property looked up by a name built at run
 * time (`isIP['constr' + 'uctor']`) and a computed key are offences too:
 * every way to a loader or the global object by name is refused, but Function
 * stays reachable from any function value a pure module holds (isIP,
 * BlockList, z) through its prototype chain, and a name built from parts
 * looks it up with no name at all. A tripwire for natural code, not a proof:
 * a reviewer reads by eye what no static scan can.
 */
function impurities(path: string, text: string): { readonly offences: string[]; readonly imported: string[] } {
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const offences: string[] = []
  const imported: string[] = []
  const offence = (node: ts.Node, what: string): void => {
    const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1
    offences.push(`${path}:${String(line)} ${what}: ${node.getText(source)}`)
  }
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      const spec = ts.isStringLiteral(node.moduleSpecifier) ? node.moduleSpecifier.text : undefined
      const allowed = spec === undefined ? undefined : PURE_IMPORTS[spec]
      const clause = node.importClause
      if (spec === undefined || allowed === undefined) offence(node, 'imports a module outside the allowlist')
      else if (clause === undefined) offence(node, 'imports a module for its side effects')
      else if (clause.name !== undefined) offence(node, 'takes a default import')
      else if (clause.namedBindings === undefined || !ts.isNamedImports(clause.namedBindings)) offence(node, 'takes a namespace import')
      else {
        for (const el of clause.namedBindings.elements) {
          const name = (el.propertyName ?? el.name).text
          if (allowed.includes(name)) imported.push(`${spec} ${name}`)
          else offence(el, `imports ${name} from ${spec}`)
        }
      }
      // The local names are identifiers like any other; the specifier is the module, judged above.
      if (clause !== undefined) visit(clause)
      return
    }
    if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) return offence(node, 're-exports a module')
    if (ts.isImportEqualsDeclaration(node)) return offence(node, 'imports a module with import = require()')
    if (ts.isImportTypeNode(node)) return offence(node, 'names a module in a type')
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) offence(node, 'imports a module at run time')
    if (ts.isMetaProperty(node)) offence(node, 'reads import.meta')
    if (ts.isIdentifier(node) && IMPURE_NAMES.has(node.text)) offence(node, `names ${node.text}`)
    if (ts.isElementAccessExpression(node) && !ts.isStringLiteralLike(node.argumentExpression) && !ts.isNumericLiteral(node.argumentExpression)) {
      offence(node, 'looks a property up by a name built at run time')
    }
    if (ts.isComputedPropertyName(node)) offence(node, 'names a property by a computed key')
    const spelled = ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)
    if (spelled && (IMPURE_WORDS.some((word) => word.test(node.text)) || node.text.startsWith('node:'))) offence(node, `spells ${node.text}`)
    ts.forEachChild(node, visit)
  }
  visit(source)
  return { offences, imported }
}

test('the purity scan finds every way a module reaches I/O: another module or name, a namespace or default import, a re-export, require, import(), process, the global object, fetch, eval and Function', () => {
  // The scan below is only as good as this reader. Each form here is one a
  // pure module could use to reach a file, a socket, a resolver or the
  // environment; the first group pulls in node:fs every way a module can name
  // another, the second reaches I/O through a module the allowlist admits or
  // through no import at all.
  const reaches = [
    "import { readFileSync } from 'node:fs'",
    "import 'node:fs'",
    "import type { Stats } from 'node:fs'",
    "import * as fs from 'node:fs'",
    "export * from 'node:fs'",
    "export * as fs from 'node:fs'",
    "export { readFileSync } from 'node:fs'",
    "export type { Stats } from 'node:fs'",
    "import fs = require('node:fs')",
    "const fs = await import('node:fs')",
    "const fs = require('node:fs')",
    "type F = typeof import('node:fs')",
    "const x = 1; export * from 'node:fs'",
    "export {\n  readFileSync,\n} from\n  'node:fs'",
    "import { lookup } from 'node:dns'",
    "import { createRequire } from 'node:module'\nconst fs = createRequire(import.meta.url)('node:fs')",

    // A socket to the Mac's loopback as a VM sees it, by a renamed import, a
    // namespace import, a default import and a re-export of node:net.
    "import { isIP, connect as dial } from 'node:net'\nexport const probe = () => dial(443, '192.168.5.2')",
    "import * as net from 'node:net'\nnet['connect'](443, '192.168.5.2')",
    "import net from 'node:net'\nnet.connect(443, '192.168.5.2')",
    "import { default as net } from 'node:net'",
    "import { createConnection, Socket } from 'node:net'",
    "import 'node:net'",
    "export { isIP } from 'node:net'",
    "export * from 'zod'",
    // No import at all: process destructured, fetch with a space, the global
    // object, eval, Function and the constructor chain that reaches it.
    "const { getBuiltinModule: gbm } = process; gbm('node:child_process')",
    "const { env } = process; env['AOS_PMMCP_TOKEN']",
    "fetch ('http://192.168.5.2:8766/mcp')",
    "globalThis.fetch('http://192.168.5.2:8766/mcp')",
    "const g = global; g['process']",
    "(0, eval)('1')",
    "new Function('return 1')()",
    "[].constructor.constructor('return 1')()",
    "const o = {}; o['constructor']['constructor']('return 1')()",
    "new WebSocket('ws://192.168.5.2:8766/mcp')",
    "new XMLHttpRequest()",
    "export const here = import.meta.url",
    'const m = `node:${"fs"}`',
    // A builtin by its bare name, which only the import() and import-type
    // branches catch: no string here spells node: or an impure name.
    "const fs = await import('fs')",
    "type F = typeof import('fs')",
    // Function, reached from an allowlisted import through its prototype chain
    // by a name built at run time: each form is caught by one rule alone.
    "import { isIP } from 'node:net'\nReflect.get(Object.getPrototypeOf(isIP), 'constr' + 'uctor')('return process')()",
    "import { isIP } from 'node:net'\nconst F = isIP['constr' + 'uctor']",
    "import { isIP } from 'node:net'\nconst keys = Reflect.ownKeys(isIP)",
    "import { isIP } from 'node:net'\nconst p = Object.getPrototypeOf(isIP)",
    "import { isIP } from 'node:net'\nconst p = isIP.__proto__",
    "import { isIP } from 'node:net'\nconst d = Object.getOwnPropertyDescriptors(isIP)",
    "const o = { ['constr' + 'uctor']: 1 }",
    "const code = 'return process.versions.node'",
    "const code = 'return globalThis'",
  ]
  for (const form of reaches) assert.notDeepEqual(impurities('probe.ts', form).offences, [], form)

  // And what host.ts and addr.ts write is not an offence: allowlisted names,
  // renamed or type-only, and the words in comments, strings and longer names.
  const clean = [
    "import { BlockList, isIPv4, isIPv6 } from 'node:net'",
    "import { isIP as isAddress } from 'node:net'",
    "import { domainToASCII, domainToUnicode } from 'node:url'\nimport { z } from 'zod'",
    "import type { z } from 'zod'",
    "const reason = 'not-global-unicast' // process.env, fetch(), require('node:fs')\n/* globalThis, import('node:fs') */",
    "export const GLOBAL_UNICAST = '2000::/3'\nconst processed = 1, fetched = 2, globals = [processed, fetched]",
    'const why = `holds a character no ${"hostname"} has`',
    // A word inside a hyphenated reason or a longer word, and an index or a key by literal.
    "const why = 'a not-global-unicast answer, processed as required'",
    "const parts = ['a', 'b']\nconst first = parts[0]\nconst o = { 'k': 1 }\nconst v = o['k']",
  ]
  for (const form of clean) assert.deepEqual(impurities('probe.ts', form).offences, [], form)
  assert.deepEqual(impurities('probe.ts', clean[0] ?? '').imported, ['node:net BlockList', 'node:net isIPv4', 'node:net isIPv6'])
  assert.deepEqual(impurities('probe.ts', clean[1] ?? '').imported, ['node:net isIP'])
})

test('host.ts and addr.ts are pure: they import only BlockList, isIP, isIPv4 and isIPv6 from node:net, domainToASCII and domainToUnicode from node:url and z from zod, re-export nothing, and name no process, global object, fetch, require, eval or Function', () => {
  for (const file of ['src/egress/host.ts', 'src/egress/addr.ts']) {
    const { offences, imported } = impurities(file, readFileSync(`${REPO}/${file}`, 'utf8'))
    assert.deepEqual(offences, [], `${file} is not pure`)
    assert.ok(imported.length > 0, `${file} has no imports to check`)
  }
})

test('every table host.ts and addr.ts export is frozen to its leaves, and so is every denial, so no importer can empty a deny list or the special-use names or write into a later decision', () => {
  // SPECIAL_USE is read on every inspect(): emptied, it admits
  // host.lima.internal. The address tables are compiled at load, but they are
  // what tests and decisions read as the deny list, and are frozen alike.
  const tables: Record<string, unknown> = { HOST_REFUSALS, SPECIAL_USE, ADDRESS_DENIALS, UNWRAPS, IPV4_DENIED, IPV6_DENIED }
  const frozenThrough = (value: unknown, path: string): number => {
    if (typeof value !== 'object' || value === null) return 0
    assert.equal(Object.isFrozen(value), true, `${path} is not frozen`)
    return 1 + Object.entries(value).reduce((n, [key, inner]) => n + frozenThrough(inner, `${path}[${key}]`), 0)
  }
  let objects = 0
  for (const [name, table] of Object.entries(tables)) objects += frozenThrough(table, name)
  // Six tables, and in the two deny tables every entry and its CIDR list.
  assert.equal(objects, 6 + 2 * (IPV4_DENIED.length + IPV6_DENIED.length))

  // What an importer that casts the type away would try. Modules are strict,
  // so a write to a frozen array throws rather than being dropped.
  const specialUse = SPECIAL_USE as string[]
  assert.throws(() => { specialUse.length = 0 }, TypeError)
  assert.throws(() => specialUse.splice(0), TypeError)
  assert.throws(() => { specialUse[2] = 'example.com' }, TypeError)
  const privateRanges = IPV4_DENIED.find(([reason]) => reason === 'private')
  assert.ok(privateRanges !== undefined)
  assert.throws(() => (privateRanges[1] as string[]).splice(0), TypeError)
  assert.throws(() => (IPV4_DENIED as DeniedRanges[]).pop(), TypeError)
  assert.throws(() => (HOST_REFUSALS as unknown as string[]).push('ok'), TypeError)
  refusedAs('host.lima.internal', 'special-use')
  refusedAs('host.docker.internal', 'special-use')
  deniedAs('192.168.5.2', 'private')

  // Every denial is frozen too. One object stands for every unreadable
  // answer, so a caller that enriched one for its log row would put this
  // request's data into every later decision; Object.assign checks no
  // readonly, so only the freeze stops it.
  for (const a of ['127.1', '0x7f.1', '', '127.0.0.1', '192.168.5.2', 'fe80::1', 'fec0::1', '::ffff:127.0.0.1', '2001:0:808:808:0:0:80ff:fffe']) {
    assert.equal(Object.isFrozen(addressDenial(a)), true, `the denial of ${JSON.stringify(a)} is not frozen`)
  }
  const unreadable = addressDenial('127.1')
  assert.ok(unreadable !== undefined)
  assert.throws(() => Object.assign(unreadable, { via: 'teredo-client', embedded: '9.9.9.9' }), TypeError)
  const loopback = addressDenial('::ffff:127.0.0.1')
  assert.ok(loopback !== undefined)
  assert.throws(() => Object.assign(loopback, { embedded: '8.8.8.8' }), TypeError)
  for (const a of ['0x7f.1', '01.2.3.4', '2000::/3']) assert.deepEqual(addressDenial(a), { reason: 'not-an-address' }, a)
  deniedAs('::ffff:127.0.0.1', 'loopback', 'ipv4-mapped', '127.0.0.1')
})
