// Provider registry (providers.yaml).
//
// One entry per model reference, describing how to reach it, what it costs,
// and what it can do. Several refinements exist because a mistake here is a
// mistake about where credentials go:
//
//   A non-local entry must carry a vaultId. An envVar alone is not a
//   credential path — it is a per-entry SECONDARY consulted only when the
//   vault failed and the operator has opted into env fallback. Accepting
//   envVar alone would let a config silently move a production key out of
//   the vault and into the process environment.
//
//   A local entry may carry the literal 'ollama' and nothing else. Local
//   endpoints on loopback need a placeholder token, not a secret, and any
//   other literal in this file would be a secret in a file CLAUDE.md says
//   holds none.
//
//   Literal credentials in `headers` are refused by key name and by value
//   shape, so a key cannot arrive dressed as a custom header.
//
// In Phase 0 every entry except the Anthropic one must be marked placeholder,
// which is what keeps "model ids are placeholders except the Claude entry"
// true in code rather than in a comment.

import { z } from 'zod'

import { ConfigError } from '../errors.js'
import { DENY_KEYS, TOKEN_PATTERNS } from '../events/redact.js'

export const MODEL_REF = /^[a-z0-9-]+\/[A-Za-z0-9._:/-]+$/
const ENV_VAR = /^[A-Z][A-Z0-9_]*$/

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1'])

function hostnameOf(url: string): string | undefined {
  try {
    return new URL(url).hostname.replace(/^\[|\]$/g, '')
  } catch {
    return undefined
  }
}

const Auth = z
  .object({
    header: z.enum(['Authorization', 'x-api-key']),
    scheme: z.enum(['Bearer', 'none']),
    vaultId: z.string().min(1).optional(),
    envVar: z.string().regex(ENV_VAR).optional(),
    value: z.literal('ollama').optional(),
    optional: z.boolean().optional(),
  })
  .strict()

const Pricing = z
  .object({
    inMicroUsdPerMTok: z.number().int().nonnegative(),
    outMicroUsdPerMTok: z.number().int().nonnegative(),
    cacheWrite5mMicroUsdPerMTok: z.number().int().nonnegative().optional(),
    cacheWrite1hMicroUsdPerMTok: z.number().int().nonnegative().optional(),
    cacheReadMicroUsdPerMTok: z.number().int().nonnegative().optional(),
    source: z.enum(['table', 'usage.cost']),
    asOf: z.string().optional(),
    url: z.string().optional(),
  })
  .strict()

const Caps = z
  .object({
    toolChoice: z.enum(['forced', 'required', 'auto', 'none']),
    parallelToolCalls: z.boolean().nullable(),
    strictSchema: z.boolean().nullable(),
    sampling: z.enum(['none', 'temperature']),
    streamUsage: z.boolean().nullable(),
    preserveAssistantMessage: z.boolean(),
  })
  .strict()

const Entry = z
  .object({
    dialect: z.enum(['anthropic', 'openai-chat']),
    baseUrl: z.string().url(),
    path: z.string().startsWith('/'),
    auth: Auth,
    headers: z.record(z.string(), z.string()).optional(),
    model: z.string().min(1),
    local: z.boolean(),
    placeholder: z.boolean(),
    pricing: Pricing,
    limits: z
      .object({
        contextTokens: z.number().int().positive(),
        maxOutputTokens: z.number().int().positive(),
      })
      .strict()
      .optional(),
    caps: Caps,
    // Set by a human after the eval harness, never by code.
    orchestrator: z.boolean().default(false),
  })
  .strict()

export const ProvidersFile = z
  .object({ version: z.literal(1), entries: z.record(z.string().regex(MODEL_REF), Entry) })
  .strict()
  .superRefine((file, ctx) => {
    for (const [ref, entry] of Object.entries(file.entries)) {
      const at = ['entries', ref]
      const host = hostnameOf(entry.baseUrl)

      if (entry.local) {
        if (host === undefined || !(LOOPBACK.has(host) || /^127\.\d+\.\d+\.\d+$/.test(host))) {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: local entries must use a loopback baseUrl` })
        }
      } else if (!entry.baseUrl.startsWith('https:')) {
        ctx.addIssue({ code: 'custom', path: at, message: `${ref}: non-local entries must use https` })
      }

      // Credential shape.
      const { vaultId, envVar, value } = entry.auth
      if (value !== undefined) {
        if (!entry.local) {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: a literal credential is only allowed on a local entry` })
        }
        if (vaultId !== undefined || envVar !== undefined) {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: value: ollama must stand alone, with no vaultId or envVar` })
        }
      } else if (!entry.local && vaultId === undefined) {
        ctx.addIssue({
          code: 'custom',
          path: at,
          message:
            `${ref}: a non-local entry needs auth.vaultId. envVar alone is not a credential path — ` +
            'it is a secondary consulted only when the vault fails and envFallback is on.',
        })
      } else if (envVar !== undefined && vaultId === undefined) {
        ctx.addIssue({ code: 'custom', path: at, message: `${ref}: envVar may only accompany a vaultId` })
      }

      // No credential may hide in a custom header.
      for (const [key, headerValue] of Object.entries(entry.headers ?? {})) {
        if (DENY_KEYS.test(key)) {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: header "${key}" would hold a credential` })
        }
        if (TOKEN_PATTERNS.some((re) => re.test(headerValue))) {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: header "${key}" holds a literal credential` })
        }
      }

      if (entry.dialect === 'anthropic') {
        if (entry.headers?.['anthropic-version'] !== '2023-06-01') {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: anthropic entries must set anthropic-version: 2023-06-01` })
        }
        if (entry.caps.sampling !== 'none') {
          ctx.addIssue({ code: 'custom', path: at, message: `${ref}: anthropic entries must set caps.sampling: none` })
        }
      }

      // Phase 0: only the Anthropic entry is real.
      if (!ref.startsWith('anthropic/') && !entry.placeholder) {
        ctx.addIssue({
          code: 'custom',
          path: at,
          message: `${ref}: every non-anthropic entry must be placeholder: true in Phase 0`,
        })
      }
    }
  })

export type ProvidersFile = z.output<typeof ProvidersFile>
export type ModelCard = z.output<typeof Entry>

export function parseProviders(input: unknown): ProvidersFile {
  const result = ProvidersFile.safeParse(input)
  if (!result.success) {
    throw new ConfigError(`providers.yaml is invalid: ${result.error.message}`)
  }
  return result.data
}

export interface ProbeRecord {
  readonly ref: string
  readonly toolCalling: boolean
  readonly checkedAt: number
  readonly ttlMs: number
}

/**
 * Whether a model may be bound to an agent.
 *
 * A model is routable only after a probe observed it making a tool call, and
 * only while that observation is fresh. Without this a manifest could name
 * any string and the failure would surface mid-run as a confusing provider
 * error rather than at bind time.
 */
export function routable(card: ModelCard, probe: ProbeRecord | undefined, now: number): boolean {
  if (probe === undefined) return false
  if (!probe.toolCalling) return false
  if (now - probe.checkedAt > probe.ttlMs) return false
  return card.placeholder === false
}
