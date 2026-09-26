// kernel.yaml schema and loader.
//
// Configuration is data, and this is where that data is checked before any of
// it can hurt. Three refinements do the real work:
//
//   The control host is the LITERAL '127.0.0.1'. Not a validated string, not
//   a default an operator can edit: there is no spelling of kernel.yaml that
//   binds the control plane to a public interface (invariant 1).
//
//   dataDir and every mountRoot must resolve outside the repository and must
//   not be $HOME itself. A data directory inside the repo would put the event
//   log where an agent with repo access could reach it; $HOME as a mount root
//   would hand a container everything (invariant 9).
//
//   A post-parse walk rejects any key whose name looks like a secret, naming
//   the path. CLAUDE.md says kernel.yaml holds no secrets; this makes that
//   structural rather than a habit, and the path is named because "there is a
//   secret somewhere in your config" is not an actionable error.
//
// Every numeric field is positive and no field admits "unlimited". A budget
// that can be switched off is not a budget.

import { homedir } from 'node:os'
import { isAbsolute, resolve, sep } from 'node:path'
import { z } from 'zod'

import { ConfigError } from './errors.js'
import { realpathNearest } from './agents/protected.js'
import { DENY_KEYS } from './events/redact.js'

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

const posInt = () => z.number().int().positive()

/** A URL whose hostname is loopback. */
function isLoopbackUrl(value: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(value).hostname.replace(/^\[|\]$/g, '')) ||
      /^127\.\d+\.\d+\.\d+$/.test(new URL(value).hostname)
  } catch {
    return false
  }
}

/** tauri://localhost, or an http(s) origin on a loopback hostname (D10). */
function isAllowedOrigin(value: string): boolean {
  if (value === 'tauri://localhost') return true
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    const host = url.hostname.replace(/^\[|\]$/g, '')
    return LOOPBACK_HOSTS.has(host) || /^127\.\d+\.\d+\.\d+$/.test(host)
  } catch {
    return false
  }
}

const Control = z
  .object({
    // Literal, not a choice. See the file header.
    host: z.literal('127.0.0.1').default('127.0.0.1'),
    port: z.number().int().min(1024).max(65_535).default(7777),
    tokenEnv: z.literal('AOS_CONTROL_TOKEN').default('AOS_CONTROL_TOKEN'),
    allowedOrigins: z
      .array(z.string())
      .default([])
      .refine((list) => list.every(isAllowedOrigin), {
        message: 'allowedOrigins entries must be tauri://localhost or an http(s) loopback origin',
      }),
    maxPayloadBytes: posInt().default(1_048_576),
  })
  .strict()

const Events = z.object({ anchorEvery: posInt().default(100) }).strict()

const McpServer = z
  .object({
    url: z.string().refine(isLoopbackUrl, { message: 'mcp server url must have a loopback hostname' }),
    tokenEnv: z.string().min(1).optional(),
    heartbeatMs: posInt().default(240_000),
    requestTimeoutMs: posInt().default(30_000),
    pingTimeoutMs: posInt().default(10_000),
    listToolsTimeoutMs: posInt().default(15_000),
  })
  .strict()

const Mcp = z
  .object({ servers: z.record(z.string().min(1), McpServer) })
  .strict()
  .refine((m) => 'pmmcp' in m.servers, { message: 'mcp.servers must include pmmcp' })

const Secrets = z
  .object({
    // Confirmed against the live get_secret schema; the broker still asserts
    // it at runtime and fails closed if the server disagrees.
    keyArg: z.string().min(1).default('label'),
    envFallback: z.boolean().default(false),
  })
  .strict()

const SandboxDomain = z
  .object({
    dockerHost: z.string().startsWith('unix://'),
    network: z.string().min(1),
    mountRoot: z.string().refine(isAbsolute, { message: 'mountRoot must be absolute' }),
  })
  .strict()

const Sandbox = z
  .object({
    driver: z.enum(['docker', 'apple-container']).default('docker'),
    image: z.string().min(1),
    domains: z.object({ trusted: SandboxDomain, hostile: SandboxDomain }).strict(),
    defaults: z
      .object({
        user: z.string().regex(/^\d+:\d+$/).default('65534:65534'),
        pidsLimit: posInt().default(256),
        memory: z.string().min(1).default('2g'),
        cpus: posInt().default(2),
        wallclockMs: posInt().default(600_000),
      })
      .strict()
      .prefault({}),
  })
  .strict()

const Lanes = z
  .object({ main: posInt().default(4), subagent: posInt().default(8) })
  .strict()
  .prefault({})

const Budgets = z
  .object({
    defaultRunMicroUsd: posInt().default(2_000_000),
    defaultWallclockMs: posInt().default(600_000),
    maxRetries: z.number().int().min(0).max(3).default(2),
    maxLlmCallsPerRun: posInt().default(50),
    maxToolCallsPerRun: posInt().default(100),
    approvalWaitMs: posInt().default(300_000),
  })
  .strict()
  .prefault({})

export const KernelConfig = z
  .object({
    version: z.literal(1),
    dataDir: z.string().min(1).default('~/.aos'),
    control: Control.prefault({}),
    events: Events.prefault({}),
    mcp: Mcp,
    secrets: Secrets.prefault({}),
    sandbox: Sandbox,
    lanes: Lanes,
    budgets: Budgets,
  })
  .strict()

export type KernelConfig = z.output<typeof KernelConfig>

/** Expand a leading ~ to the current user's home directory. */
export function expandHome(p: string): string {
  if (p === '~') return homedir()
  if (p.startsWith(`~${sep}`) || p.startsWith('~/')) return resolve(homedir(), p.slice(2))
  return p
}

/**
 * Expand a leading `~` inside a `unix://` docker host.
 *
 * DOCKER_HOST is handed to the docker CLI, which the driver spawns WITHOUT a
 * shell, so nothing downstream would ever expand it: a literal
 * `unix://~/.colima/...` arrives at the daemon lookup as a relative path whose
 * first segment is the character `~`, and the connection simply fails. Colima
 * keeps its sockets under $HOME, so the `~` form is the one an operator
 * actually writes — which makes expanding it here the difference between a
 * config that works and one that looks right and does not.
 */
export function expandDockerHost(value: string): string {
  const real = expandHome(value.slice('unix://'.length))
  if (!isAbsolute(real)) {
    throw new ConfigError(
      `sandbox dockerHost "${value}" must resolve to an absolute socket path, got "${real}". ` +
        'DOCKER_HOST is passed to the docker CLI without a shell, so a relative path never resolves.',
    )
  }
  return `unix://${real}`
}

/** Walk every key in the document; reject anything that looks like a secret. */
export function assertNoSecretKeys(value: unknown, path: string[] = []): void {
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoSecretKeys(item, [...path, String(i)]))
    return
  }
  if (value === null || typeof value !== 'object') return
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (DENY_KEYS.test(key)) {
      throw new ConfigError(
        `kernel.yaml holds no secrets: key "${key}" at ${[...path, key].join('.')} looks like one. ` +
          'Reference an environment variable or a vault id instead.',
      )
    }
    assertNoSecretKeys(item, [...path, key])
  }
}

export interface LoadOptions {
  /** Repository root, used for the outside-the-repo refinements. */
  readonly repoRoot: string
  /** AOS_DATA_DIR override, which wins over the file's dataDir. */
  readonly dataDirOverride?: string
}

/** Parse and refine a kernel.yaml document. */
export function parseKernelConfig(input: unknown, options: LoadOptions): KernelConfig {
  // The no-secrets walk runs on the RAW document, before parsing drops
  // unknown keys, so a secret hiding in a key the schema never reads is still
  // caught.
  assertNoSecretKeys(input)

  const result = KernelConfig.safeParse(input)
  if (!result.success) {
    throw new ConfigError(`kernel.yaml is invalid: ${result.error.message}`)
  }
  const config = result.data

  const dataDir = expandHome(options.dataDirOverride ?? config.dataDir)
  assertOutsideRepoAndHome(dataDir, 'dataDir', options.repoRoot)
  for (const [name, domain] of Object.entries(config.sandbox.domains)) {
    assertOutsideRepoAndHome(expandHome(domain.mountRoot), `sandbox.domains.${name}.mountRoot`, options.repoRoot)
  }

  return {
    ...config,
    dataDir: resolve(dataDir),
    sandbox: {
      ...config.sandbox,
      domains: {
        trusted: {
          ...config.sandbox.domains.trusted,
          dockerHost: expandDockerHost(config.sandbox.domains.trusted.dockerHost),
          mountRoot: resolve(expandHome(config.sandbox.domains.trusted.mountRoot)),
        },
        hostile: {
          ...config.sandbox.domains.hostile,
          dockerHost: expandDockerHost(config.sandbox.domains.hostile.dockerHost),
          mountRoot: resolve(expandHome(config.sandbox.domains.hostile.mountRoot)),
        },
      },
    },
  }
}

function assertOutsideRepoAndHome(target: string, field: string, repoRoot: string): void {
  const real = realpathNearest(target)
  const repo = realpathNearest(repoRoot)
  const home = realpathNearest(homedir())

  if (real === repo || real.startsWith(repo.endsWith(sep) ? repo : repo + sep)) {
    throw new ConfigError(
      `${field} resolves to ${real}, inside the repository. The event log and container ` +
        'mounts must not live where repository tooling can reach them.',
    )
  }
  if (real === home) {
    throw new ConfigError(`${field} must not be $HOME itself (${home})`)
  }
}
