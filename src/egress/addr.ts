// The egress address classifier (egress plan E1).
//
// Contract: an allowed name is dialled only when every address it resolves to
// is global unicast, and isDeniedAddress is the one test of that. It judges an
// address by its prefix alone, and denies every address in a range that is
// not global unicast: loopback (127/8, ::1), "this network" (0.0.0.0/8, which
// reaches the Mac's own listeners on macOS and Linux), RFC 1918 private (and
// with it 192.168.5.0/24, the Colima VMs' network, where 192.168.5.2 is
// rewritten to the Mac's 127.0.0.1 on every port), CGNAT (100.64/10),
// link-local, unique-local, multicast, broadcast, the documentation and
// benchmarking ranges, and the rest of IANA's IPv4 and IPv6 special-purpose
// registries (IPV4_DENIED, IPV6_DENIED). An IPv6 address outside 2000::/3,
// the global unicast space, is denied unless it carries an IPv4 address as
// below.
//
// What a prefix cannot show is not denied here, and all of it is global
// unicast and allowed:
//
//   * every address in an on-link prefix of the Mac's interfaces: the Mac's
//     own global addresses (a SLAAC or DHCPv6 IPv6 address, a public IPv4 on
//     an interface) and, on an IPv6 network, every LAN peer's global address
//     in the same /64, the router's LAN side (which often serves its admin
//     UI), a NAS, a printer, the operator's other machines;
//   * the router's WAN address, a NAT hairpin to its port-forwards;
//   * a network-specific NAT64 prefix (RFC 6052) that a DNS64 resolver
//     synthesises for a private A record, and an RFC 5969 6rd prefix, which
//     carries an IPv4 address as 6to4 does but under a prefix only the ISP
//     knows.
//
// A name that resolves to one of them reaches whatever listens there. That
// residual is E2's. As the plan stands, its upstream denies the host's own
// interface addresses when it dials and states the rest as not detected;
// whether it should deny every on-link prefix instead, LAN peers included, is
// open with the operator. Either way E2 dials TLS only, with certificate
// verification on, so a dial to any of them delivers at most a TCP connect
// and a ClientHello naming the allowed host before it is torn down.
//
// Four IPv6 forms carry an IPv4 address, and each is judged by the IPv4
// address its packets end up at, unwrapped here explicitly:
//
//   ::ffff:0:0/96   IPv4-mapped: a dual-stack socket sends to it over IPv4
//   64:ff9b::/96    NAT64's well-known prefix: the gateway translates to it
//   2002::/16       6to4: bits 16-47 are the IPv4 address of the site's
//                   router, which a relay delivers to
//   2001::/32       Teredo: bits 32-63 are the server's IPv4 address, and
//                   the last 32, inverted, the client's; both are judged
//
// Each is denied when an IPv4 address it carries is denied, and otherwise
// allowed: IANA's registry gives 6to4 and Teredo no reachability of their own
// ("N/A"), only that of what they carry, and a DNS64 network answers a v4-only
// name (github.com has no AAAA) with NAT64 addresses. Node's BlockList
// matches an IPv4-mapped address against IPv4 rules on its own, but that is
// not relied on: the unwrap is done here, before any BlockList sees the
// address, and each family is checked only against its own lists.
//
// Fail closed: anything that is not one address in a standard text form is
// denied as not-an-address. BlockList.check answers false, in no range, for
// text it cannot read (`127.1`), so a deny list consulted with an unchecked
// string would let every legacy IPv4 notation through; only dotted-quad
// decimal IPv4 and RFC 4291 IPv6 text are read at all, and a zone index
// (`fe80::1%en0`), which names one of the Mac's own links and which no DNS
// answer carries, is refused.
//
// Every table exported here is frozen to its leaves. The deny lists are
// compiled into BlockLists at load, so a later change to the arrays would not
// reach a decision, but they are still what tests and log rows read as the
// truth, and no importer may rewrite them. So is every denial addressDenial
// returns: one object stands for every unreadable answer, and a caller that
// enriched a denial for its log row (Object.assign checks no readonly) would
// otherwise write one request's data into another request's decision. The
// lists carriedAddresses returns are frozen for the same reason: one empty
// list stands for every address that carries none.
//
// Pure: no I/O. Nothing is resolved here; E2's upstream resolves and asks this
// of every answer.

import { BlockList, isIPv4, isIPv6 } from 'node:net'

/** Why an address is denied. Stable: decisions and their log rows name these. */
export const ADDRESS_DENIALS = Object.freeze([
  'not-an-address',
  'this-network',
  'unspecified',
  'loopback',
  'private',
  'shared',
  'link-local',
  'unique-local',
  'ipv4-compatible',
  'ietf-protocol',
  'documentation',
  'benchmarking',
  'special-purpose',
  'multicast',
  'broadcast',
  'reserved',
  'not-global-unicast',
] as const)
export type AddressDenialReason = (typeof ADDRESS_DENIALS)[number]

/** The IPv6 form an IPv4 address was unwrapped from. */
export const UNWRAPS = Object.freeze(['ipv4-mapped', 'nat64', '6to4', 'teredo-server', 'teredo-client'] as const)
export type Unwrap = (typeof UNWRAPS)[number]

export interface AddressDenial {
  readonly reason: AddressDenialReason
  /** Set when the denied address is an IPv4 address carried in an IPv6 one. */
  readonly via?: Unwrap
  /** That IPv4 address, dotted-quad. */
  readonly embedded?: string
}

/** A reason and the CIDR ranges it covers. Order matters: the first match names the reason. */
export type DeniedRanges = readonly [reason: AddressDenialReason, cidrs: readonly string[]]

/** A deny table frozen to its leaves: each entry, and each entry's CIDR list. */
function frozenTable(table: readonly DeniedRanges[]): readonly DeniedRanges[] {
  for (const entry of table) {
    Object.freeze(entry[1])
    Object.freeze(entry)
  }
  return Object.freeze(table)
}

/** IANA's IPv4 special-purpose registry, all of it, plus multicast and 240/4. */
export const IPV4_DENIED: readonly DeniedRanges[] = frozenTable([
  ['this-network', ['0.0.0.0/8']],
  ['loopback', ['127.0.0.0/8']],
  ['private', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']],
  ['shared', ['100.64.0.0/10']],
  ['link-local', ['169.254.0.0/16']],
  // DS-Lite, PCP and TURN anycast, NAT64 discovery (ipv4only.arpa).
  ['ietf-protocol', ['192.0.0.0/24']],
  ['documentation', ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']],
  ['benchmarking', ['198.18.0.0/15']],
  // AS112, AMT, the deprecated 6to4 relay anycast, AS112 direct delegation.
  ['special-purpose', ['192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24', '192.175.48.0/24']],
  ['multicast', ['224.0.0.0/4']],
  ['broadcast', ['255.255.255.255/32']],
  ['reserved', ['240.0.0.0/4']],
])

/**
 * IANA's IPv6 special-purpose registry, less the four forms unwrapped before
 * these are read, plus multicast. Ranges outside 2000::/3 are named here only
 * for a clearer reason: anything there is denied regardless.
 */
export const IPV6_DENIED: readonly DeniedRanges[] = frozenTable([
  ['unspecified', ['::/128']],
  ['loopback', ['::1/128']],
  // Deprecated IPv4-compatible addresses (RFC 4291 2.5.5.1): never an answer.
  ['ipv4-compatible', ['::/96']],
  // Local-use NAT64 (RFC 8215), discard-only, AS112-v6, SRv6 SIDs.
  ['special-purpose', ['64:ff9b:1::/48', '100::/64', '2620:4f:8000::/48', '5f00::/16']],
  ['link-local', ['fe80::/10']],
  ['unique-local', ['fc00::/7']],
  ['multicast', ['ff00::/8']],
  ['documentation', ['2001:db8::/32', '3fff::/20']],
  ['benchmarking', ['2001:2::/48']],
  // The rest of 2001::/23 once Teredo (2001::/32) has been unwrapped.
  ['ietf-protocol', ['2001::/23']],
])

/** The global unicast space (RFC 4291 2.4): an IPv6 address outside it is denied. */
export const IPV6_GLOBAL_UNICAST = '2000::/3'

type Family = 'ipv4' | 'ipv6'

function blockList(family: Family, cidrs: readonly string[]): BlockList {
  const list = new BlockList()
  for (const cidr of cidrs) {
    const [network = '', prefix = ''] = cidr.split('/')
    list.addSubnet(network, Number(prefix), family)
  }
  return list
}

function compile(family: Family, table: readonly DeniedRanges[]): ReadonlyArray<{ reason: AddressDenialReason; list: BlockList }> {
  return table.map(([reason, cidrs]) => ({ reason, list: blockList(family, cidrs) }))
}

const V4 = compile('ipv4', IPV4_DENIED)
const V6 = compile('ipv6', IPV6_DENIED)
const GLOBAL_UNICAST = blockList('ipv6', [IPV6_GLOBAL_UNICAST])

/** A denial, frozen: a caller holds it as a decision, never as a record to enrich. */
function denial(reason: AddressDenialReason, carried?: { readonly via: Unwrap; readonly embedded: string }): AddressDenial {
  return Object.freeze(carried === undefined ? { reason } : { reason, via: carried.via, embedded: carried.embedded })
}

/** Shared by every answer that is not one address in a standard text form. */
const NOT_AN_ADDRESS = denial('not-an-address')

/** Dotted-quad decimal IPv4 as a 32-bit unsigned value, or undefined for anything else. */
function ipv4Value(text: string): number | undefined {
  if (!isIPv4(text)) return undefined
  return [...text.matchAll(/[0-9]+/g)].reduce((value, [part]) => value * 256 + Number(part), 0)
}

function ipv4Text(value: number): string {
  return [value >>> 24, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.')
}

/**
 * RFC 4291 text as a 128-bit value, or undefined. Only called on text
 * isIPv6 accepted, so undefined means the two readers disagree, and the
 * address is then denied.
 */
function ipv6Value(text: string): bigint | undefined {
  let hex = text
  const tail = hex.slice(hex.lastIndexOf(':') + 1)
  if (tail.includes('.')) {
    const v4 = ipv4Value(tail)
    if (v4 === undefined) return undefined
    hex = `${hex.slice(0, hex.length - tail.length)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`
  }
  const [front = '', back, ...more] = hex.split('::')
  if (more.length > 0) return undefined
  const head = front === '' ? [] : front.split(':')
  const rest = back === undefined || back === '' ? [] : back.split(':')
  const missing = 8 - head.length - rest.length
  if (back === undefined ? missing !== 0 : missing < 1) return undefined
  let value = 0n
  for (const group of [...head, ...Array<string>(missing).fill('0'), ...rest]) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return undefined
    value = (value << 16n) | BigInt(parseInt(group, 16))
  }
  return value
}

const LOW_32 = 0xffffffffn

/** The IPv4 addresses an IPv6 address carries, by form, or undefined when it is none of the four. */
function carriedIpv4(value: bigint): ReadonlyArray<readonly [Unwrap, number]> | undefined {
  if (value >> 32n === 0xffffn) return [['ipv4-mapped', Number(value & LOW_32)]]
  if (value >> 32n === 0x0064ff9b_0000_0000_0000_0000n) return [['nat64', Number(value & LOW_32)]]
  if (value >> 112n === 0x2002n) return [['6to4', Number((value >> 80n) & LOW_32)]]
  if (value >> 96n === 0x2001_0000n) {
    return [
      ['teredo-server', Number((value >> 64n) & LOW_32)],
      ['teredo-client', Number((value & LOW_32) ^ LOW_32)],
    ]
  }
  return undefined
}

function v4Denial(address: string): AddressDenial | undefined {
  for (const { reason, list } of V4) if (list.check(address, 'ipv4')) return denial(reason)
  return undefined
}

function v6Denial(address: string): AddressDenial | undefined {
  for (const { reason, list } of V6) if (list.check(address, 'ipv6')) return denial(reason)
  return GLOBAL_UNICAST.check(address, 'ipv6') ? undefined : denial('not-global-unicast')
}

/** Why `address` must not be dialled, or undefined when it is a global unicast address. */
export function addressDenial(address: string): AddressDenial | undefined {
  if (address.includes('%')) return NOT_AN_ADDRESS
  if (isIPv4(address)) return v4Denial(address)
  if (!isIPv6(address)) return NOT_AN_ADDRESS
  const value = ipv6Value(address)
  if (value === undefined) return NOT_AN_ADDRESS
  const carried = carriedIpv4(value)
  if (carried === undefined) return v6Denial(address)
  for (const [via, v4] of carried) {
    const embedded = ipv4Text(v4)
    const denied = v4Denial(embedded)
    if (denied !== undefined) return denial(denied.reason, { via, embedded })
  }
  return undefined
}

/** True unless `address` is one global unicast address, judged as addressDenial judges it. */
export function isDeniedAddress(address: string): boolean {
  return addressDenial(address) !== undefined
}

/** An IPv4 address an IPv6 one carries, and the form it is carried in. */
export interface CarriedAddress {
  readonly via: Unwrap
  /** Dotted-quad. */
  readonly address: string
}

const CARRIES_NOTHING: readonly CarriedAddress[] = Object.freeze([])

/**
 * The IPv4 addresses `address` carries in one of the four forms above, the
 * ones addressDenial judges it by, frozen; none for an IPv4 address, an IPv6
 * address of no such form, or text that is no address. addressDenial already
 * checks them against the deny ranges. This is for a check that compares an
 * answer with addresses rather than ranges (E2's test of the Mac's own
 * interface addresses), which must see the IPv4 address a packet ends up at
 * just as addressDenial does: ::ffff:a.b.c.d is a.b.c.d to a dual-stack
 * socket.
 */
export function carriedAddresses(address: string): readonly CarriedAddress[] {
  if (address.includes('%') || !isIPv6(address)) return CARRIES_NOTHING
  const value = ipv6Value(address)
  const carried = value === undefined ? undefined : carriedIpv4(value)
  if (carried === undefined) return CARRIES_NOTHING
  return Object.freeze(carried.map(([via, v4]) => Object.freeze({ via, address: ipv4Text(v4) })))
}
