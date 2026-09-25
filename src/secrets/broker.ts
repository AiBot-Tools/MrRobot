// Secrets broker — the kernel's only caller of the pmmcp vault (invariant 2).
//
// Agents never hold a vault handle, and neither does most of the kernel. What
// circulates is a SecretRef: an opaque handle whose value lives in a WeakMap
// keyed by the handle itself, so there is no property, no getter and no
// enumeration order that yields the credential. `use(ref, fn)` hands the value
// to a callback and nothing else; a ref that is logged, serialised or attached
// to an event carries an id and a source, never a secret.
//
// Two rules about WHEN, which matter as much as the shape:
//
//   `ref()` is refused inside an agent run scope. Credentials are resolved at
//   boot, on the kernel's own behalf. A run that could reach the vault — even
//   through kernel code it does not control — would make the vault reachable
//   by anything an agent can steer into calling it, and "resolve me the
//   anthropic key" is a sentence a model can produce.
//
//   `use()` is permitted anywhere, because the router must attach a provider
//   credential during a run, inside that run's scope. It never returns the
//   value, so permitting it widens nothing.
//
// The mask is registered the instant a value is fetched and before the
// function returns. Everything downstream — every event payload, every error
// message, every bounded tool output — is censored by exact substring from
// that moment on. A vault entry can be an opaque string of no recognisable
// shape, so the regex pass alone would not catch it; ordering is the whole
// defence.
//
// D8: `envFallback` exists, defaults OFF, and keeps the kernel DEGRADED while
// it is on. It is a per-entry secondary consulted only after that entry's own
// vault fetch failed, and only through that entry's own `auth.envVar`. It is
// never a substitute for a vaultId, which stays mandatory on every non-local
// provider entry.

import { PolicyDenied, SecretsSchemaMismatch } from '../errors.js'
import { SecretMask } from '../events/redact.js'
import type { EventStore } from '../events/store.js'
import { runScope } from '../runtime/scope.js'
import type { McpHub } from '../mcp/hub.js'

export const VAULT_TOOL = 'get_secret'

export type SecretSource = 'vault' | 'env'

/**
 * The value store.
 *
 * A module-level WeakMap keyed by the handle: the value is not a field, so it
 * cannot be read, spread, enumerated, JSON-serialised or reached by a
 * debugger inspecting the object. Dropping the last reference to a ref drops
 * the value with it.
 */
const VALUES = new WeakMap<SecretRef, string>()

/** An opaque handle to a resolved credential. Carries no value. */
export class SecretRef {
  readonly id: string
  readonly source: SecretSource

  /** @internal Constructed only by the broker. */
  constructor(id: string, source: SecretSource, value: string, brand: symbol) {
    if (brand !== MINT) {
      throw new PolicyDenied(id, 'a SecretRef may only be minted by the secrets broker')
    }
    this.id = id
    this.source = source
    VALUES.set(this, value)
    Object.freeze(this)
  }

  /** Never the value: a ref that lands in a log or an error says only this. */
  toJSON(): { id: string; source: SecretSource } {
    return { id: this.id, source: this.source }
  }

  toString(): string {
    return `SecretRef(${this.id})`
  }
}

const MINT = Symbol('aos.secrets.mint')

/**
 * Fail closed unless the LIVE schema has the argument we intend to send.
 *
 * pmmcp's `get_secret` takes `label` (confirmed against the live schema). If a
 * server upgrade renames it, sending the old name would return nothing, the
 * broker would fall through to whatever comes next, and the failure would look
 * like a missing secret rather than a protocol drift. Better to refuse at boot
 * and say exactly which argument is missing.
 */
export function assertSecretSchema(inputSchema: unknown, keyArg: string, toolRef: string): void {
  if (typeof inputSchema !== 'object' || inputSchema === null) {
    throw new SecretsSchemaMismatch(`${toolRef} reports no input schema, so ${keyArg} cannot be confirmed`)
  }
  const properties = (inputSchema as Record<string, unknown>)['properties']
  if (typeof properties !== 'object' || properties === null) {
    throw new SecretsSchemaMismatch(`${toolRef} reports no inputSchema.properties, so ${keyArg} cannot be confirmed`)
  }
  if (!Object.prototype.hasOwnProperty.call(properties, keyArg)) {
    throw new SecretsSchemaMismatch(
      `${toolRef}.inputSchema.properties has no "${keyArg}" ` +
        `(it has ${Object.keys(properties as Record<string, unknown>).join(', ') || 'nothing'}). ` +
        'Set kernel.yaml secrets.keyArg to the live argument name.',
    )
  }
}

export interface BrokerOptions {
  readonly store: EventStore
  /** Absent means no vault: the broker is degraded and ref() throws. */
  readonly hub?: McpHub | undefined
  readonly serverId?: string
  readonly keyArg: string
  readonly envFallback: boolean
  /** Injected so a test never needs to mutate the real environment. */
  readonly env?: NodeJS.ProcessEnv
}

export interface RefOptions {
  /**
   * The entry's own `auth.envVar`. Without one there is no fallback for this
   * entry, whatever `envFallback` says.
   */
  readonly envVar?: string | undefined
}

export class SecretsBroker {
  readonly #store: EventStore
  readonly #hub: McpHub | undefined
  readonly #serverId: string
  readonly #keyArg: string
  readonly #envFallback: boolean
  readonly #env: NodeJS.ProcessEnv
  #degraded: string | undefined

  constructor(options: BrokerOptions) {
    this.#store = options.store
    this.#hub = options.hub
    this.#serverId = options.serverId ?? 'pmmcp'
    this.#keyArg = options.keyArg
    this.#envFallback = options.envFallback
    this.#env = options.env ?? process.env
    this.#degraded = options.hub === undefined ? 'no MCP hub: the pmmcp vault is unreachable' : undefined
  }

  get keyArg(): string {
    return this.#keyArg
  }

  status(): 'ready' | 'degraded' {
    return this.#degraded === undefined ? 'ready' : 'degraded'
  }

  /** Why the broker is degraded, or undefined when it is not. */
  get degradedReason(): string | undefined {
    return this.#degraded
  }

  #degrade(reason: string): void {
    this.#degraded = reason
    this.#store.append({ type: 'secrets.degraded', payload: { schemaVersion: 1, reason } })
  }

  /**
   * The boot step: confirm the live schema, and declare any standing
   * degradation. Does NOT throw when the vault is simply absent — the kernel
   * is specified to boot degraded — but DOES throw when the vault is present
   * and disagrees about its own arguments.
   */
  async start(): Promise<'ready' | 'degraded'> {
    if (this.#hub === undefined) {
      this.#degrade('no MCP hub: the pmmcp vault is unreachable')
    } else {
      const described = this.#hub.describe(this.#serverId, VAULT_TOOL)
      if (described === undefined) {
        this.#degrade(`${this.#serverId} does not offer ${VAULT_TOOL}`)
      } else {
        // Throws: a live server that disagrees about its arguments is a
        // protocol drift, not a missing optional dependency.
        assertSecretSchema(described.inputSchema, this.#keyArg, `${this.#serverId}.${VAULT_TOOL}`)
      }
    }

    if (this.#envFallback) {
      // Standing, not incidental. Reading credentials from the environment is
      // a weaker posture than the vault, and the operator should see it in the
      // subsystem view for as long as it is true.
      this.#degrade('secrets.envFallback is ON: credentials may be read from the environment (D8)')
    }

    await Promise.resolve()
    return this.status()
  }

  /**
   * Resolve a credential at boot.
   *
   * @throws {PolicyDenied} inside an agent run scope, or when nothing supplies
   *   the value.
   */
  async ref(id: string, purpose: string, options: RefOptions = {}): Promise<SecretRef> {
    const scope = runScope()
    if (scope !== undefined) {
      throw new PolicyDenied(
        id,
        `a run may not resolve a secret (run ${scope.runId}); credentials are resolved at boot`,
      )
    }
    if (purpose.trim() === '') {
      throw new PolicyDenied(id, 'a secret may not be resolved without a stated purpose')
    }

    let vaultError: string | undefined
    if (this.#hub === undefined) {
      vaultError = this.#degraded ?? 'no MCP hub'
    } else {
      try {
        const result = await this.#hub.callKernelOnly(
          this.#serverId,
          VAULT_TOOL,
          { [this.#keyArg]: id },
          purpose,
        )
        const value = result.ok ? extractText(result.content) : undefined
        if (value !== undefined && value !== '') return this.#mint(id, 'vault', value, purpose)
        vaultError = result.ok ? 'the vault returned no value' : 'the vault reported an error'
      } catch (e) {
        vaultError = e instanceof Error ? e.message : String(e)
      }
    }

    // D8. Only now, only for this entry, only through this entry's own name.
    if (!this.#envFallback) {
      throw new PolicyDenied(id, `${vaultError ?? 'the vault failed'} and secrets.envFallback is off`)
    }
    const envVar = options.envVar
    if (envVar === undefined) {
      throw new PolicyDenied(
        id,
        `${vaultError ?? 'the vault failed'} and this entry declares no auth.envVar to fall back to`,
      )
    }
    const fromEnv = this.#env[envVar]
    if (fromEnv === undefined || fromEnv === '') {
      throw new PolicyDenied(id, `${vaultError ?? 'the vault failed'} and ${envVar} is not set`)
    }

    return this.#mint(id, 'env', fromEnv, purpose)
  }

  #mint(id: string, source: SecretSource, value: string, purpose: string): SecretRef {
    // Registered BEFORE the event that records the access, and therefore
    // before anything else in the process can append a payload containing it.
    SecretMask.register(value)
    const ref = new SecretRef(id, source, value, MINT)
    this.#store.append({
      type: 'secret.accessed',
      payload: { schemaVersion: 1, id, purpose, source },
    })
    return ref
  }

  /**
   * Hand a resolved value to a callback.
   *
   * Permitted inside a run scope, because the router attaches the provider
   * credential during a run. It never returns the value, so a run gains the
   * ability to USE a credential the kernel already resolved, never to obtain
   * one. No event is appended: the access was accounted for when the ref was
   * minted, and logging every use would add a row per provider call saying
   * nothing new.
   */
  use<T>(ref: SecretRef, fn: (value: string) => T): T {
    const value = VALUES.get(ref)
    if (value === undefined) {
      throw new PolicyDenied(String(ref), 'this SecretRef was not minted by this broker')
    }
    return fn(value)
  }
}

/** Pull the text out of MCP content blocks. */
function extractText(content: unknown): string | undefined {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return undefined
  const parts: string[] = []
  for (const block of content) {
    if (typeof block !== 'object' || block === null) continue
    const b = block as Record<string, unknown>
    if (b['type'] === 'text' && typeof b['text'] === 'string') parts.push(b['text'])
  }
  return parts.length === 0 ? undefined : parts.join('')
}
