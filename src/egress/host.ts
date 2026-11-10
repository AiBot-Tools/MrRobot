// The egress host normaliser (egress plan E1).
//
// Contract: every host the egress engine compares, resolves or names in a TLS
// handshake is an EgressHost, a DNS name in the one spelling the kernel
// compares by: lower-case letter-digit-hyphen labels (an internationalised
// name only as its valid punycode A-labels), at least two of them, at most 253
// characters, one trailing dot stripped. Two spellings of one name must never
// compare unequal (an allowlist holding `github.com` must not miss
// `GitHub.com.`), and nothing that is not a public DNS name may pass for one:
//
//   * IP literals, in every notation. A URL parser (WHATWG's "ends in a
//     number") and inet_aton read a host whose last label is a number as an
//     IPv4 address, whole or in parts, each part decimal, octal (`0177`) or
//     hex (`0x7f`): `2130706433`, `0x7f000001`, `0x7f.1`, `0177.0.0.1` and
//     `127.1` are all 127.0.0.1. IPv6 likewise, bracketed or bare, with or
//     without a zone. A host that is an address would skip the step that
//     makes resolving safe: only a name is resolved, and every answer it gets
//     is checked by addr.ts before anything is dialled.
//   * Userinfo, ports and wildcards. A host is a name alone, not an
//     authority, and an allowlist names exact hosts.
//   * Special-use names (SPECIAL_USE): names that by standard or convention
//     never denote a public host and are answered, if at all, by something on
//     the Mac, a VM or the local network. `host.lima.internal` and
//     `host.docker.internal` are the Mac's own loopback as a VM sees it, and
//     pmmcp listens there.
//   * A single label, which a resolver may complete with a search domain into
//     a name nobody listed.
//
// A refusal carries a reason from HOST_REFUSALS and a sentence that never
// echoes the input: a worker's request host is attacker-chosen text, so the
// reason and the sentence are safe to log as they stand, and a caller that
// wants the input in a row bounds it itself.
//
// Pure: no I/O and no resolver. Whether a name is safe to dial is decided only
// after it resolves, by addr.ts, for every answer it gets.

import { isIP } from 'node:net'
import { domainToASCII, domainToUnicode } from 'node:url'
import { z } from 'zod'

/** Why a string is not an EgressHost. Stable: decisions and their log rows name these. */
export const HOST_REFUSALS = Object.freeze([
  'empty',
  'too-long',
  'non-ascii',
  'userinfo',
  'ip-literal',
  'syntax',
  'port',
  'wildcard',
  'label',
  'special-use',
  'single-label',
  'punycode',
] as const)
export type HostRefusal = (typeof HOST_REFUSALS)[number]

/**
 * Names refused with every name beneath them: each is answered, if at all,
 * by something on the Mac, a VM or the local network, never by public DNS. A
 * home router's resolver answers the router conventions with LAN addresses,
 * which on an IPv6 LAN are global unicast, the residual E1 leaves to E2:
 * refused here by name, before anything resolves.
 *
 *   localhost    the loopback name (RFC 6761); resolvers may answer any
 *                *.localhost with 127.0.0.1 without asking anyone
 *   local        multicast DNS (RFC 6762): Bonjour names on the Mac's LAN
 *   internal     ICANN's private-use TLD (2024): host.lima.internal and
 *                host.docker.internal (the Mac's loopback as a VM sees it),
 *                gateway.docker.internal, kubernetes.docker.internal
 *   localdomain  the /etc/hosts and router convention for the local network
 *   localdomain6 its IPv6 twin (localhost6.localdomain6 in /etc/hosts)
 *   lan          a router's default local domain (OpenWrt's, among others)
 *   home         a home router's local domain, and a TLD ICANN will not
 *                delegate for the name collisions that makes
 *   corp         a corporate network's, which ICANN will not delegate either
 *   intranet     a private network's (RFC 6762 Appendix G)
 *   private      likewise (RFC 6762 Appendix G)
 *   arpa         infrastructure: home.arpa is residential networks (RFC
 *                8375), and the reverse-DNS names (in-addr.arpa, ip6.arpa)
 *                name addresses, which egress never names
 *   invalid      guaranteed never to resolve (RFC 6761)
 *   test         reserved for testing (RFC 6761) and never delegated, so
 *                whatever answers it is local
 *   onion        Tor (RFC 7686), resolved only by a local Tor proxy
 *   alt          non-DNS namespaces (RFC 9476)
 *
 * Frozen: inspect() reads it on every call, so an importer that emptied it
 * would admit host.lima.internal.
 */
export const SPECIAL_USE: readonly string[] = Object.freeze([
  'localhost',
  'local',
  'internal',
  'localdomain',
  'localdomain6',
  'lan',
  'home',
  'corp',
  'intranet',
  'private',
  'arpa',
  'invalid',
  'test',
  'onion',
  'alt',
])

/** RFC 1035's limit on a name in text form, without its trailing dot. */
const MAX_NAME = 253

/**
 * Dot-separated LDH labels, each 1 to 63 characters, lower-case, with no
 * hyphen at either end. Matched whole, so a name it admits has no empty label,
 * and its labels are exactly the runs between dots.
 */
const LDH_NAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * A label a URL parser reads as an IPv4 number: all decimal digits, or `0x`
 * and hex digits (`0x` alone is 0). A host that ends in one is an IPv4 address
 * to WHATWG's parser, in whole or in parts, or no valid host at all, and never
 * a name: no top-level domain is numeric.
 */
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/

export interface HostRefused {
  readonly ok: false
  readonly reason: HostRefusal
  /** Completes "not an egress host: it ...". Never holds any of the input. */
  readonly why: string
}

type Inspected = { readonly ok: true; readonly host: string } | HostRefused

function refused(reason: HostRefusal, why: string): HostRefused {
  return { ok: false, reason, why }
}

/** Bracketed (`[::1]`, `[::1]:443`), or an address net.isIP reads, with or without a zone. */
function isIpLiteral(input: string): boolean {
  if (input.includes('[') || input.includes(']')) return true
  const [unzoned = ''] = input.split('%')
  return isIP(input) !== 0 || isIP(unzoned) !== 0
}

/**
 * A label is either plain LDH or a punycode A-label that decodes to a name
 * with something outside ASCII in it and encodes back to exactly itself: the
 * one spelling of an internationalised label, and never a second spelling of
 * a name an allowlist holds another way.
 *
 * On Node 22 (Ada) domainToUnicode answers '' for a label it cannot decode or
 * whose decoding UTS 46 refuses (`xn--zz`; `xn--wca`, an upper-case Ü;
 * `xn--ab-r13a`, which would hold an ideographic full stop), and those fail
 * the non-ASCII test and the round trip alike. It does decode some labels to
 * a name they are not the A-label of. A decoding that is all ASCII (`xn--localhost-` is `localhost`,
 * `xn--xn--abc-` is `xn--abc`) comes only from a label that ends in its
 * delimiter, since punycode inserts only code points above ASCII, and
 * LDH_NAME refuses a label that ends in a hyphen before this runs. So a label
 * that reaches here and decodes at all decodes to something outside ASCII,
 * and the round trip is the test that decides: `xn---2sw`, its delimiter
 * before an empty basic part, decodes to the 汘 that `xn--2sw` spells, and
 * only the round trip refuses it. The non-ASCII and no-dot tests are defence
 * in depth, for a runtime whose toUnicode hands back a label it cannot decode
 * or decodes one to a dot, neither of which Ada does.
 */
function isCanonicalLabel(label: string): boolean {
  if (!label.startsWith('xn--')) return true
  const unicode = domainToUnicode(label)
  return /[^\x00-\x7f]/.test(unicode) && !unicode.includes('.') && domainToASCII(unicode) === label
}

function inspect(input: string): Inspected {
  if (input.length === 0) return refused('empty', 'is empty')
  if (input.length > MAX_NAME + 1) {
    return refused('too-long', `is longer than the ${String(MAX_NAME)} characters a DNS name may hold`)
  }
  // Before anything reads the text as a name: a fullwidth digit or an
  // ideographic full stop (U+3002) is a digit or a dot to a URL parser.
  if (/[^\x00-\x7f]/.test(input)) {
    return refused('non-ascii', 'holds a character outside ASCII; an internationalised name is written as its punycode A-labels (xn--)')
  }
  if (input.includes('@')) return refused('userinfo', 'holds userinfo (@): a host is a name alone, never an authority')
  if (isIpLiteral(input)) {
    return refused('ip-literal', 'is an IP address literal: egress names hosts, and only a name is resolved and its every answer checked')
  }
  if (/[/\\?#]/.test(input)) return refused('syntax', 'is a URL or a path, not a host')
  if (input.includes(':')) return refused('port', 'carries a port: a host is a name alone')
  if (input.includes('*')) return refused('wildcard', 'holds a wildcard: an egress allowlist names exact hosts')
  if (/[^A-Za-z0-9.-]/.test(input)) return refused('syntax', 'holds a character no hostname has: a label is letters, digits and hyphens')

  // One trailing dot is the fully-qualified spelling of the same name. Case is
  // not significant in DNS, so the one spelling is lower-case.
  const name = (input.endsWith('.') ? input.slice(0, -1) : input).toLowerCase()
  if (name.length === 0) return refused('empty', 'is only a dot')
  if (NUMERIC_LABEL.test(name.slice(name.lastIndexOf('.') + 1))) {
    return refused(
      'ip-literal',
      'ends in a number, which a URL parser and inet_aton read as an IPv4 address written in parts, in decimal, octal or hex',
    )
  }
  if (!LDH_NAME.test(name)) {
    return refused('label', 'has a label that is empty, longer than 63 characters, or starts or ends with a hyphen')
  }
  if (name.length > MAX_NAME) {
    return refused('too-long', `is longer than the ${String(MAX_NAME)} characters a DNS name may hold`)
  }
  if (SPECIAL_USE.some((suffix) => name === suffix || name.endsWith(`.${suffix}`))) {
    return refused(
      'special-use',
      'is a special-use name (localhost, .local, .internal and the like), answered if at all on the Mac, a VM or the local network, never a public host',
    )
  }
  if (!name.includes('.')) {
    return refused('single-label', 'is a single label, which a resolver may complete with a search domain into a name nobody listed')
  }
  if (![...name.matchAll(/[^.]+/g)].every(([label]) => isCanonicalLabel(label))) {
    return refused('punycode', 'has an xn-- label that is not the canonical punycode A-label of an internationalised name')
  }
  return { ok: true, host: name }
}

/**
 * The schema for an egress host at a boundary (kernel.yaml bindings, manifest
 * allowlists): it normalises a name to its one spelling and refuses anything
 * else, and its output is branded, so code that takes an EgressHost cannot be
 * handed a string nothing normalised. It is the only place one is made.
 */
export const EgressHost = z
  .string()
  .transform((raw, ctx) => {
    const seen = inspect(raw)
    if (seen.ok) return seen.host
    ctx.addIssue({ code: 'custom', message: `not an egress host: it ${seen.why}` })
    return z.NEVER
  })
  .brand<'EgressHost'>()
export type EgressHost = z.output<typeof EgressHost>

export type HostVerdict = { readonly ok: true; readonly host: EgressHost } | HostRefused

/**
 * Normalise `input` to an EgressHost, or say why it is none. For a request's
 * host, where the reason is what a decision logs; the schema is for config.
 */
export function parseEgressHost(input: string): HostVerdict {
  const seen = inspect(input)
  if (!seen.ok) return seen
  // The one spelling is its own spelling, so the schema cannot refuse it; it
  // runs again only because it alone brands a host.
  return { ok: true, host: EgressHost.parse(seen.host) }
}
