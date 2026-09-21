// External chain anchor.
//
// A hash chain proves nothing about rows that were removed from its end: the
// remaining prefix is perfectly valid on its own. The anchor is the only
// defence against that — a small file outside the database recording the
// highest (seq, hash) the kernel has seen, so a shortened log can be
// recognised as shortened.
//
// It is written atomically (temp file in the same directory, then rename) so
// a crash mid-write leaves either the old anchor or the new one, never a
// half-written file that would look like corruption. Mode is 0600: the anchor
// is not secret, but it is trust-bearing, and anything that can rewrite it can
// hide a truncation.
//
// The log is EXPECTED to run ahead of the anchor between writes. Only a log
// BEHIND its anchor is evidence of truncation — see verifyChain.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { z } from 'zod'

import { ConfigError } from '../errors.js'

export const AnchorRecord = z
  .object({
    schemaVersion: z.literal(1),
    /** Genesis of the chain this anchor belongs to, so anchors cannot be
     * swapped between logs. */
    genesis: z.string(),
    seq: z.number().int().nonnegative(),
    hash: z.string(),
    writtenAt: z.string(),
  })
  .strict()

export type Anchor = z.infer<typeof AnchorRecord>

export const ANCHOR_MODE = 0o600

/** Write the anchor atomically. Creates the directory if needed. */
export function writeAnchor(path: string, anchor: Anchor): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = join(dir, `.${'events.head'}.${String(process.pid)}.tmp`)
  writeFileSync(tmp, `${JSON.stringify(anchor)}\n`, { mode: ANCHOR_MODE })
  // writeFileSync's mode is subject to umask on creation, so set it outright.
  chmodSync(tmp, ANCHOR_MODE)
  try {
    renameSync(tmp, path)
  } catch (e) {
    try {
      unlinkSync(tmp)
    } catch {
      // Leaving a temp file behind must not mask the rename failure.
    }
    throw e
  }
  chmodSync(path, ANCHOR_MODE)
}

/** Read the anchor, or undefined when there is none yet. */
export function readAnchor(path: string): Anchor | undefined {
  if (!existsSync(path)) return undefined
  const text = readFileSync(path, 'utf8')
  let parsedJson: unknown
  try {
    parsedJson = JSON.parse(text)
  } catch (e) {
    throw new ConfigError(`anchor file ${path} is not valid JSON`, { cause: e })
  }
  const result = AnchorRecord.safeParse(parsedJson)
  if (!result.success) {
    throw new ConfigError(`anchor file ${path} is malformed: ${result.error.message}`)
  }
  return result.data
}
