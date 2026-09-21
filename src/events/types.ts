// Event catalog — minimal set for T05a. T05b grows this to the frozen 36.
//
// Every event type has one strict payload schema carrying schemaVersion: 1.
// Strictness is the point: an unknown key in a payload is a caller bug or a
// drifted schema, and either way it must not reach the log, because once
// hashed it is permanent.

import { z } from 'zod'

export const KernelBootedPayload = z
  .object({
    schemaVersion: z.literal(1),
    version: z.string(),
    degraded: z.array(z.string()),
  })
  .strict()

export const ChainAnchoredPayload = z
  .object({
    schemaVersion: z.literal(1),
    seq: z.number().int().nonnegative(),
    hash: z.string(),
  })
  .strict()

/** The frozen list of event types. T05b replaces this with the full catalog. */
export const EVENT_TYPES = ['kernel.booted', 'chain.anchored'] as const

export type EventType = (typeof EVENT_TYPES)[number]

export const PAYLOAD_SCHEMAS: Readonly<Record<EventType, z.ZodType>> = {
  'kernel.booted': KernelBootedPayload,
  'chain.anchored': ChainAnchoredPayload,
}

export function isEventType(t: string): t is EventType {
  return (EVENT_TYPES as readonly string[]).includes(t)
}
