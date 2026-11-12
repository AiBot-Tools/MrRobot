// The kernel's judge of the mux's ready report (images/worker/mux.mjs).
//
// Before the mux listens or runs its command, it tries to reach what a run
// must never reach and reports what it met: the Mac's loopback as a Colima VM
// reaches it (192.168.5.2 on pmmcp's 8766 and the control plane's 7777, and
// host.lima.internal and host.docker.internal on 8766), the internet by
// address (1.1.1.1:443) and any resolver at all (a lookup of example.com).
// With --network none the container has a loopback of its own and nothing
// else, so each probe must fail, and fail in the way that says there is no
// route: ENETUNREACH for a connect by address; ENETUNREACH, EAI_AGAIN or
// ENOTFOUND for a connect by name; EAI_AGAIN or ENOTFOUND for the lookup.
// Anything else is refused, ETIMEDOUT above all: a SYN that went unanswered
// went somewhere, so there is a route.
//
// The session (session.ts) sends go only to a ready this accepts, so a
// container whose network is not what the kernel asked for never runs its
// command. The report is the container's text and attacker-chosen: it is
// parsed strictly and never echoed, and a clause here names a probe by the
// target the kernel itself holds, never by what the report says.
//
// SELF_TEST here is the kernel's copy of the mux's list, which the image
// carries; test/egress-mux.test.ts holds the two equal, probe for probe, and
// the mux's report format to this reading. The boot canary (egress plan W3)
// will run the same judge on a container of its own.

import { isIP } from 'node:net'
import { z } from 'zod'

/** One self-test probe, as the mux runs it and its report names it. */
export interface ReadyProbe {
  readonly probe: 'connect' | 'lookup'
  readonly host: string
  readonly port?: number
}

/** What a run must never reach, in the order the mux's ready report names it (mux.mjs SELF_TEST). */
export const SELF_TEST: readonly ReadyProbe[] = Object.freeze([
  Object.freeze({ probe: 'connect', host: '192.168.5.2', port: 8766 }),
  Object.freeze({ probe: 'connect', host: '192.168.5.2', port: 7777 }),
  Object.freeze({ probe: 'connect', host: 'host.lima.internal', port: 8766 }),
  Object.freeze({ probe: 'connect', host: 'host.docker.internal', port: 8766 }),
  Object.freeze({ probe: 'connect', host: '1.1.1.1', port: 443 }),
  Object.freeze({ probe: 'lookup', host: 'example.com' }),
] as const)

/** The longest ready payload the mux sends (mux.mjs READY_MAX_BYTES). */
export const READY_MAX_BYTES = 4_096

/** The error codes that say there is no route, by the kind of probe. */
export const NO_ROUTE_CODES: Readonly<Record<'address' | 'name' | 'lookup', ReadonlySet<string>>> = Object.freeze({
  address: new Set(['ENETUNREACH']),
  name: new Set(['ENETUNREACH', 'EAI_AGAIN', 'ENOTFOUND']),
  lookup: new Set(['EAI_AGAIN', 'ENOTFOUND']),
})

/** How the report names a probe: host:port for a connect, the host for a lookup. */
export function probeTarget(probe: ReadyProbe): string {
  return probe.probe === 'connect' ? `${probe.host}:${String(probe.port)}` : probe.host
}

const Report = z.strictObject({
  mux: z.literal(1),
  probes: z.array(
    z.strictObject({
      probe: z.enum(['connect', 'lookup']),
      target: z.string().max(300),
      reached: z.boolean(),
      error: z.string().max(64).nullable(),
    }),
  ),
  reached: z.number().int().min(0),
})

/**
 * Undefined to accept `report`, or a clause saying why not, which names a
 * probe by the kernel's own target, never by the report's text. Accepts only
 * ASCII JSON in the mux's shape naming every SELF_TEST probe in order, none
 * reached, the top-level count zero, and each error a code that says there
 * is no route for that kind of probe.
 */
export function acceptReady(report: Uint8Array): string | undefined {
  if (report.length === 0 || report.length > READY_MAX_BYTES) return 'the report is empty or longer than a ready report is'
  // ASCII only: anything else is not what the mux writes.
  for (const byte of report) if (byte < 0x20 || byte > 0x7e) return 'the report holds a byte that is not printable ASCII'
  let json: unknown
  try {
    json = JSON.parse(Buffer.from(report).toString('ascii'))
  } catch {
    return 'the report is not JSON'
  }
  const parsed = Report.safeParse(json)
  if (!parsed.success) return 'the report is not one the judge reads'
  const { probes } = parsed.data
  if (probes.length !== SELF_TEST.length || probes.some((p, i) => p.target !== probeTarget(SELF_TEST[i] ?? { probe: 'lookup', host: '' }))) {
    return 'the report does not name every self-test probe, in order'
  }
  const reached = probes.filter((p) => p.reached).length
  if (reached !== 0 || parsed.data.reached !== 0) {
    return `the self-test reached ${String(Math.max(reached, parsed.data.reached))} of what it must not`
  }
  for (const [i, p] of probes.entries()) {
    const probe = SELF_TEST[i]
    if (probe === undefined) return 'the report names a probe the kernel does not run'
    const codes = probe.probe === 'lookup' ? NO_ROUTE_CODES.lookup : isIP(probe.host) === 0 ? NO_ROUTE_CODES.name : NO_ROUTE_CODES.address
    if (p.probe !== probe.probe || p.error === null || !codes.has(p.error)) {
      return `the self-test's probe of ${probeTarget(probe)} met no error that says there is no route`
    }
  }
  return undefined
}
