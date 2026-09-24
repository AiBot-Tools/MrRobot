// Probe fixtures.
//
// `routable()` consults the same record `aos probe` persists, so a fixture is
// a whole record. Building it here rather than in each test file means a new
// field lands in one place, and no test can accidentally exercise routing
// against a shape the probe never writes.

import './guard.js'

import type { ProbeRecord } from '../../src/models/registry.js'

/** A record fresh enough to route, unless an override says otherwise. */
export function freshProbe(ref: string, over: Partial<ProbeRecord> = {}): ProbeRecord {
  return {
    schemaVersion: 1,
    ref,
    probedAt: Date.now(),
    modelIdSeen: 'fixture-model',
    toolCalling: true,
    toolChoiceForced: null,
    finishSeen: 'tool_use',
    roundTrip: true,
    usage: { input: 10, output: 5 },
    costMicroUsd: 1,
    latencyMs: 12,
    ttlHours: 24,
    ...over,
  }
}
