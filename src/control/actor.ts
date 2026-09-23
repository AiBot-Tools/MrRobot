// Proof that a human decided something.
//
// Several kernel operations are reserved for a person: approving an
// irreversible tool call, promoting an agent, archiving one, releasing a
// quarantine. Those functions take a HumanActor, and the type is the proof.
//
// The brand is a private class field. Nothing outside this module can create
// one, so an object literal, a structural clone, a JSON round-trip and
// Object.create(HumanActor.prototype) all fail the check — and a model that
// talks kernel code into passing `{ kind: 'human' }` achieves nothing.
//
// mintHumanActor is imported by exactly one file, src/control/server.ts,
// where a real authenticated connection exists. A hygiene test enforces that
// dependency direction, because the guarantee is only as good as the list of
// callers.

/** Evidence that a request came from an authenticated human connection. */
export class HumanActor {
  readonly #brand = true
  readonly connectionId: string

  /** @internal — reachable only through mintHumanActor. */
  constructor(connectionId: string, key: symbol) {
    if (key !== MINT) {
      throw new TypeError('HumanActor cannot be constructed directly; it is minted by the control plane')
    }
    this.connectionId = connectionId
  }

  /**
   * True only for an instance this module made. The `in` check on a private
   * field is the one test that cannot be faked: an object literal, a
   * structural clone, a JSON round-trip and Object.create(prototype) all lack
   * the field, and reading it is not something outside code can arrange.
   */
  static is(value: unknown): value is HumanActor {
    return typeof value === 'object' && value !== null && #brand in value
  }
}

const MINT = Symbol('aos.humanActor.mint')

/** Mint an actor for an authenticated control-plane connection. */
export function mintHumanActor(connectionId: string): HumanActor {
  return new HumanActor(connectionId, MINT)
}

/** Throw unless `value` is a genuine HumanActor. */
export function assertHumanActor(value: unknown, action: string): asserts value is HumanActor {
  if (!HumanActor.is(value)) {
    throw new TypeError(`${action} requires a human: no valid HumanActor was supplied`)
  }
}
