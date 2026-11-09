// Proof that decide() allowed one request (egress plan E2, for E3).
//
// The upstream (upstream.ts) resolves and dials only for a request decide()
// allowed. A plain object cannot carry that: any kernel code could build
// `{ verdict: 'allow', host, port: 443 }` for a host no allowlist judged, and
// the upstream could not tell it from the real one. So an allow is an
// EgressAllow, minted over the request decide() judged.
//
// What an EgressAllow proves:
//
//   * That this module made it. The brand is a private class field, as
//     HumanActor's is (src/control/actor.ts), so an object literal, a spread
//     copy, a structural clone, a JSON round-trip, a Proxy and
//     Object.create(EgressAllow.prototype) all fail EgressAllow.is. The
//     instance, the class and its prototype are frozen, so neither the fields
//     the upstream checks nor `is` itself can be replaced after the fact.
//   * Which request it is for: the host and port, the method and path, and
//     the body as decide() saw it (none, a declared length or chunked, and the
//     leading bytes it read and judged, such as git-push's command list, held
//     as a private copy). The upstream sends only that request: a head with
//     another method or path, a body declared otherwise, or a body that does
//     not begin with the bytes judged is refused as not decided.
//   * That it is spent once used. The upstream spends an allow when request()
//     is called, before it checks or awaits anything, and refuses a spent one,
//     so an allow the session keeps cannot carry a second request, to the
//     same path or to another, whatever became of the first.
//
// What it does not prove:
//
//   * That decide() was right. Minting records that decide() allowed this
//     request; it does not judge it again. The upstream still checks what an
//     allow says (an EgressHost in its one spelling, port 443, a head and a
//     body it will send), so a decide() that minted a malformed one is
//     refused, not dialled, but a request decide()'s policy wrongly admitted
//     is sent, and E3's tests are where that is caught.
//   * Anything about the bytes past the leading ones decide() judged (a
//     push's pack), which nothing read.
//   * Who called mintEgressAllow. Nothing at run time can say; a hygiene
//     test pins the files that name mintEgressAllow and the files that import
//     this module, because the guarantee is only as good as that list. Until
//     E3 lands it is this file for the name, and upstream.ts, for the check,
//     as the one importer.
//
// Pure: no I/O, no imports but a type.

import type { EgressHost } from './host.js'

/** The body of a request as decide() judged it. */
export interface JudgedBody {
  /** The length the request declared, in bytes. None: the body is sent chunked. */
  readonly length?: number | undefined
  /** The leading bytes decide() read and judged (git-push's command list), if it read any. Copied when minted. */
  readonly leading?: Uint8Array | undefined
}

/** The request decide() judged, as it mints the allow for it. */
export interface JudgedRequest {
  readonly host: EgressHost
  readonly port: number
  readonly method: string
  readonly path: string
  /** None: decide() judged a request with no body. */
  readonly body?: JudgedBody | undefined
}

/** What anyone may read of the judged body. The leading bytes themselves stay private (EgressAllow.leadingOf). */
export interface AllowedBody {
  readonly length: number | undefined
  /** How many leading bytes decide() judged; 0 when it read none. */
  readonly leadingBytes: number
}

/** A request decide() allowed: the only thing the upstream resolves, dials and sends, once. */
export class EgressAllow {
  readonly #brand = true
  /** Private, so freezing the instance leaves it writable: set by spend(), never cleared. */
  #spent = false
  readonly #leading: Uint8Array | undefined
  readonly verdict = 'allow' as const
  readonly host: EgressHost
  readonly port: number
  readonly method: string
  readonly path: string
  /** None: decide() judged a request with no body, and the upstream sends one with none. */
  readonly body: AllowedBody | undefined

  /** @internal — reachable only through mintEgressAllow. */
  constructor(key: symbol, judged: JudgedRequest) {
    if (key !== MINT) {
      throw new TypeError('EgressAllow cannot be constructed directly; decide() mints it')
    }
    const { host, port, method, path, body } = judged
    let leading: Uint8Array | undefined
    if (body !== undefined) {
      const given: unknown = body.leading
      if (given !== undefined && !(given instanceof Uint8Array)) {
        throw new TypeError('EgressAllow: the judged leading bytes must be a Uint8Array')
      }
      // A copy: the bytes the caller judged stay the bytes judged, whatever
      // it later writes into its own buffer.
      leading = given === undefined || given.length === 0 ? undefined : new Uint8Array(given)
    }
    this.#leading = leading
    this.host = host
    this.port = port
    this.method = method
    this.path = path
    this.body = body === undefined ? undefined : Object.freeze({ length: body.length, leadingBytes: leading?.length ?? 0 })
    Object.freeze(this)
  }

  /**
   * True only for an instance this module made. The `in` check on a private
   * field is the one test outside code cannot arrange: a literal, a copy, a
   * clone, a Proxy and Object.create(prototype) all lack the field, and the
   * check reads nothing of the value, so no getter or trap of a caller's runs.
   */
  static is(value: unknown): value is EgressAllow {
    return typeof value === 'object' && value !== null && #brand in value
  }

  /** Spend an allow: true the first time, false ever after. The upstream calls it once per request(), before anything else. */
  static spend(allow: EgressAllow): boolean {
    if (allow.#spent) return false
    allow.#spent = true
    return true
  }

  /** A copy of the leading bytes decide() judged, or none. */
  static leadingOf(allow: EgressAllow): Uint8Array | undefined {
    return allow.#leading === undefined ? undefined : new Uint8Array(allow.#leading)
  }
}
// Frozen with its prototype: `EgressAllow.is = () => true` would otherwise
// pass any literal as decided, and the upstream reads the class every time.
Object.freeze(EgressAllow)
Object.freeze(EgressAllow.prototype)

const MINT = Symbol('aos.egressAllow.mint')

/** Mint the allow for the request decide() allowed, as it judged it. For decide() alone. */
export function mintEgressAllow(judged: JudgedRequest): EgressAllow {
  return new EgressAllow(MINT, judged)
}
