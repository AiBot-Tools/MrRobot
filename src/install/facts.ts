// pmmcp's machine documents, as the installer reads them: the facts
// (`scripts/pmmcp_facts.py --json`, schema `facts: 1`) and Qdrant's status
// (`scripts/qdrant_api_key.py status --json`).
//
// CONTRACT
//
//   Who reads them: the installer's discovery (scripts/install/discover.ts)
//   and its planner. Pure: no I/O, no process, nothing kept. The kernel never
//   imports src/install.
//
//   How leniently: both documents may gain keys without a new number (pmmcp's
//   docs/installer_interfaces.md: "Read it leniently"), so every object here
//   is loose, never strict: a key this schema does not name passes and is
//   kept. What is named must have the type the shipped interface gives it, or
//   the document is refused with the field's path, never its value.
//
//   What `facts: 1` documents exist: every pmmcp commit from c8bae1e (the
//   one that added the facts) prints the ten feature flags this schema
//   requires. e6516d5 added three keys under the same number:
//   `features.curator_proof`, `features.stop_listener_check` and
//   `http_auth.links`. An older document lacks them, so they are optional
//   here, and an absent flag reads as false (featuresOf): the installer makes
//   a curator secret only where `curator_proof` is true and a dashboard token
//   only where `stop_listener_check` is, because older code hands either one
//   to whatever answers on its port once the service is down.
//
//   What the Qdrant document proves: only `verdict: 'enforced'` says the
//   container asks for the key file's key and is reachable on 127.0.0.1
//   alone (keyedLoopbackOnly). `published` never does: on the host network
//   it is empty while Qdrant listens on every interface. A `not_running`
//   document (container absent or stopped, both collections null) is valid
//   and means nothing was asked.

import { z } from 'zod'

import { KernelError } from '../errors.js'
import { redactString } from '../events/redact.js'

/** The facts schema number this reads. Another number is another document. */
export const FACTS_VERSION = 1

/** The flags every `facts: 1` document carries, from c8bae1e on. */
export const REQUIRED_FEATURES = [
  'bearer_gate',
  'rotate_digest_stdin',
  'check_expect',
  'qdrant_key_script',
  'qdrant_init',
  'qdrant_status_json',
  'dashboard_auth',
  'curator_secret',
  'stop_jobs_flag',
  'stop_engine_guard',
] as const

/** The flags e6516d5 added under `facts: 1`: absent from an older document, and absent reads as false. */
export const OPTIONAL_FEATURES = ['curator_proof', 'stop_listener_check'] as const

export type FeatureName = (typeof REQUIRED_FEATURES)[number] | (typeof OPTIONAL_FEATURES)[number]

export const FEATURE_NAMES: readonly FeatureName[] = [...REQUIRED_FEATURES, ...OPTIONAL_FEATURES]

/** The pmmcp commit that added the facts: a checkout before it has no document at all. */
export const FACTS_COMMIT = 'c8bae1e'

/**
 * For each feature, the pmmcp commit from which a checkout's facts report it
 * true: the commit that added its code, or, for the two flags e6516d5 added
 * to the facts, e6516d5 (fa67d43 and 0e8e4cc hold their code, but their facts
 * have no such key, which reads as false). Every one before c8bae1e is in any
 * checkout that has facts on pmmcp's main line.
 */
export const FEATURE_COMMITS: Readonly<Record<FeatureName, string>> = {
  bearer_gate: '7a33417',
  rotate_digest_stdin: 'bf63dce',
  check_expect: 'bf63dce',
  qdrant_key_script: '0b6c7e2',
  qdrant_init: 'f4c698a',
  qdrant_status_json: 'f4c698a',
  dashboard_auth: '25d4a26',
  curator_secret: '25d4a26',
  stop_jobs_flag: '540bc6b',
  stop_engine_guard: '540bc6b',
  curator_proof: 'e6516d5',
  stop_listener_check: 'e6516d5',
}

/** What each feature is, for the operator. */
export const FEATURE_LABELS: Readonly<Record<FeatureName, string>> = {
  bearer_gate: 'the MCP bearer gate',
  rotate_digest_stdin: 'rotate --digest-stdin',
  check_expect: 'http_auth check --expect',
  qdrant_key_script: 'the Qdrant API key script',
  qdrant_init: 'qdrant init',
  qdrant_status_json: 'qdrant status --json',
  dashboard_auth: 'the dashboard token',
  curator_secret: 'the curator secret',
  curator_proof: 'the curator proof (callers never send the secret)',
  stop_jobs_flag: 'stop --jobs',
  stop_engine_guard: "the stop script's docker engine guard",
  stop_listener_check: "the stop script's dashboard listener check",
}

const FileState = z.enum(['absent', 'present', 'unusable'])

const Features = z
  .object({
    bearer_gate: z.boolean(),
    rotate_digest_stdin: z.boolean(),
    check_expect: z.boolean(),
    qdrant_key_script: z.boolean(),
    qdrant_init: z.boolean(),
    qdrant_status_json: z.boolean(),
    dashboard_auth: z.boolean(),
    curator_secret: z.boolean(),
    stop_jobs_flag: z.boolean(),
    stop_engine_guard: z.boolean(),
    curator_proof: z.boolean().optional(),
    stop_listener_check: z.boolean().optional(),
  })
  .loose()

const Service = { host: z.string(), port: z.number().int() }

/** `scripts/pmmcp_facts.py --json`, schema `facts: 1`, as shipped (pmmcp docs/installer_interfaces.md). */
export const Facts = z
  .object({
    facts: z.literal(FACTS_VERSION),
    dir: z.string(),
    git: z
      .object({
        head: z.string().nullable(),
        branch: z.string().nullable(),
        origin: z.string().nullable(),
        dirty: z.boolean().nullable(),
      })
      .loose(),
    features: Features,
    config: z
      .object({
        source: z.string().nullable(),
        server: z.object({ ...Service, enabled: z.literal(true) }).loose(),
        dashboard: z.object({ ...Service, enabled: z.boolean(), legacy_token_key: z.boolean() }).loose(),
        curator: z.object({ ...Service, enabled: z.boolean() }).loose(),
      })
      .loose(),
    env_overrides: z.array(z.string()),
    http_auth: z
      .object({
        state: z.enum(['absent', 'present', 'invalid']),
        mode: z.enum(['off', 'warn', 'enforce']).nullable(),
        tokens: z.array(z.string()),
        reason: z.string().nullable(),
        // Added by e6516d5 under facts: 1, so an older document has none.
        links: z.number().int().nullable().optional(),
      })
      .loose(),
    qdrant_key_file: z.object({ state: FileState }).loose(),
    dashboard_token: z.object({ state: FileState }).loose(),
    curator_secret: z.object({ state: FileState }).loose(),
    launchd: z
      .object({
        plist: z.string(),
        exists: z.boolean(),
        working_directory: z.string().nullable(),
        legacy_plists: z.array(z.string()),
      })
      .loose(),
  })
  .loose()
export type Facts = z.output<typeof Facts>

/** `scripts/qdrant_api_key.py status --json`, as shipped. */
export const QdrantStatus = z
  .object({
    docker_context: z.string(),
    key_file: z.object({ state: FileState, reason: z.string().nullable() }).loose(),
    container: z
      .object({
        state: z.enum(['running', 'stopped', 'absent']),
        key_set: z.boolean().nullable(),
        image12: z.string().nullable(),
        published: z.array(
          z
            .object({
              host_ip: z.string(),
              host_port: z.number().int().nullable(),
              container_port: z.string(),
            })
            .loose(),
        ),
        publish_all_ports: z.boolean().nullable(),
        reachable_beyond_loopback: z.array(z.string()),
      })
      .loose(),
    prekey_kept: z.boolean(),
    collections: z
      .object({
        without_key: z.number().int().nullable(),
        with_key: z.number().int().nullable(),
      })
      .loose(),
    verdict: z.enum(['enforced', 'not_asked', 'inconsistent', 'not_running']),
  })
  .loose()
export type QdrantStatus = z.output<typeof QdrantStatus>

/** A pmmcp document that is not what its interface prints: the message names the field, never a value. */
export class PmmcpDocumentError extends KernelError {
  /** The dotted paths of the fields that failed, `(document)` for the whole of it. */
  readonly fields: readonly string[]

  constructor(message: string, fields: readonly string[]) {
    super('AOS_INSTALL_PMMCP_DOCUMENT', message)
    this.fields = fields
  }
}

/** The most fields a refusal names. */
const MAX_NAMED = 5

function parseDocument<T>(schema: z.ZodType<T>, what: string, text: string): T {
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    throw new PmmcpDocumentError(`${what} is not JSON`, ['(document)'])
  }
  const result = schema.safeParse(json)
  if (result.success) return result.data
  // A path and the rule it broke; zod's messages name the expected type or values, never the input.
  const issues = result.error.issues.map((issue) => {
    const path = issue.path.length === 0 ? '(document)' : issue.path.map(String).join('.')
    return { path, text: `${path}: ${redactString(issue.message)}` }
  })
  const more = issues.length > MAX_NAMED ? ` and ${String(issues.length - MAX_NAMED)} more` : ''
  const named = issues.slice(0, MAX_NAMED).map((i) => i.text).join('; ')
  throw new PmmcpDocumentError(`${what} does not fit the shipped schema: ${named}${more}`, issues.map((i) => i.path))
}

/**
 * The facts document from its stdout, through the `facts: 1` schema.
 *
 * @throws {PmmcpDocumentError} naming the fields that do not fit (or that it is not JSON).
 */
export function parseFacts(text: string): Facts {
  return parseDocument(Facts, `the facts document (facts: ${String(FACTS_VERSION)})`, text)
}

/**
 * The Qdrant status document from its stdout.
 *
 * @throws {PmmcpDocumentError} naming the fields that do not fit (or that it is not JSON).
 */
export function parseQdrantStatus(text: string): QdrantStatus {
  return parseDocument(QdrantStatus, 'the Qdrant status document (status --json)', text)
}

/** Every feature as a boolean: a flag an older document lacks is false. */
export function featuresOf(facts: Facts): Readonly<Record<FeatureName, boolean>> {
  const out = {} as Record<FeatureName, boolean>
  for (const name of FEATURE_NAMES) out[name] = facts.features[name] ?? false
  return out
}

/** A feature the checkout's facts say it lacks (or the facts themselves), and the commit that brings it. */
export interface MissingFeature {
  readonly feature: FeatureName | 'facts'
  readonly label: string
  readonly commit: string
}

/** What a checkout older than the facts lacks first: with no document, no other feature can be read. */
export const FACTS_MISSING: MissingFeature = { feature: 'facts', label: 'the facts (scripts/pmmcp_facts.py --json)', commit: FACTS_COMMIT }

/** The features `facts` reads as false, in FEATURE_NAMES order, each with the commit that adds it. */
export function missingFeatures(facts: Facts): readonly MissingFeature[] {
  const have = featuresOf(facts)
  return FEATURE_NAMES.filter((f) => !have[f]).map((feature) => ({ feature, label: FEATURE_LABELS[feature], commit: FEATURE_COMMITS[feature] }))
}

/** Whether Qdrant asks for the key file's key and is reachable on 127.0.0.1 alone: `enforced`, and nothing else. */
export function keyedLoopbackOnly(status: QdrantStatus): boolean {
  return status.verdict === 'enforced'
}
