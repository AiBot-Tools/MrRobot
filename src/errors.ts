// Kernel error types.
//
// Contract: every error the kernel throws on purpose carries a stable `code`.
// Codes are what the control plane, the CLI and the tests match on; messages
// are for humans and may be reworded freely. Nothing here ever carries a
// secret value — an error message names the key, the id or the path, never the
// credential.

/** Base class: a deliberate, identifiable kernel failure. */
export class KernelError extends Error {
  readonly code: string

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options)
    this.code = code
    this.name = new.target.name
  }
}

/** A Phase 0 stub was reached. Stubs throw; they are never silent no-ops. */
export class NotImplementedError extends KernelError {
  readonly feature: string

  constructor(feature: string, options?: ErrorOptions) {
    super('AOS_NOT_IMPLEMENTED', `not implemented in this phase: ${feature}`, options)
    this.feature = feature
  }
}

/** Configuration is missing, malformed, or refused by a schema refinement. */
export class ConfigError extends KernelError {
  constructor(message: string, options?: ErrorOptions) {
    super('AOS_CONFIG', message, options)
  }
}

/** The policy gate refused a tool call. Default deny: this is the normal path. */
export class PolicyDenied extends KernelError {
  readonly toolRef: string
  readonly reason: string

  constructor(toolRef: string, reason: string, options?: ErrorOptions) {
    super('AOS_POLICY_DENIED', `policy denied ${toolRef}: ${reason}`, options)
    this.toolRef = toolRef
    this.reason = reason
  }
}

/** The event chain failed verification: a gap, a mismatch, or a truncation. */
export class ChainBroken extends KernelError {
  readonly seq: number

  constructor(seq: number, detail: string, options?: ErrorOptions) {
    super('AOS_CHAIN_BROKEN', `event chain broken at seq ${seq}: ${detail}`, options)
    this.seq = seq
  }
}

/** A live MCP tool schema disagrees with what the secrets broker requires. */
export class SecretsSchemaMismatch extends KernelError {
  constructor(message: string, options?: ErrorOptions) {
    super('AOS_SECRETS_SCHEMA_MISMATCH', message, options)
  }
}

/** A run, agent or objective hit a spend or step ceiling. */
export class BudgetExceeded extends KernelError {
  readonly scope: string

  constructor(scope: string, detail: string, options?: ErrorOptions) {
    super('AOS_BUDGET_EXCEEDED', `budget exceeded for ${scope}: ${detail}`, options)
    this.scope = scope
  }
}
