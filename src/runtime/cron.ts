// Cron expressions, parsed and matched.
//
// Hand-rolled because a new dependency is an ask-before, and because the
// surface actually needed is small. What is NOT small is the number of ways a
// cron parser can be quietly wrong, so the rule here is that anything this
// module does not implement is REFUSED by name rather than accepted and
// misread. A scheduler that reads `MON-FRI` as "every minute" would fire a
// hundred runs nobody asked for, and the expression would look correct.
//
// Supported, on five space-separated fields:
//
//   *        every value
//   N        one value
//   a-b      inclusive range, a <= b
//   */n      every nth value from the field's minimum
//   a-b/n    every nth value within a range
//   a,b,c    any combination of the above
//
// Refused, each with a message naming what to write instead: macros (@daily),
// six fields (seconds), names (MON, JAN), and the nonstandard specials L, W, #
// and ?. Ranges do not wrap: `55-5` is refused rather than read as 55..59,0..5,
// because the wrapping reading is an extension and the non-wrapping one is
// silently different.
//
// The day-of-month / day-of-week rule is cron's genuinely surprising one, and it
// is implemented rather than simplified: when BOTH are restricted, the
// expression matches a day that satisfies EITHER. `0 0 1 * 1` means the first of
// the month and every Monday, not Mondays that fall on the first.

import { ConfigError } from '../errors.js'

interface FieldSpec {
  readonly name: string
  readonly min: number
  readonly max: number
}

const FIELDS: readonly FieldSpec[] = [
  { name: 'minute', min: 0, max: 59 },
  { name: 'hour', min: 0, max: 23 },
  { name: 'day-of-month', min: 1, max: 31 },
  { name: 'month', min: 1, max: 12 },
  { name: 'day-of-week', min: 0, max: 7 },
]

export interface CronExpr {
  /** The expression as written, for messages and for the log. */
  readonly source: string
  readonly minute: ReadonlySet<number>
  readonly hour: ReadonlySet<number>
  readonly dayOfMonth: ReadonlySet<number>
  readonly month: ReadonlySet<number>
  /** 0-6, Sunday is 0. A written 7 is normalised to 0. */
  readonly dayOfWeek: ReadonlySet<number>
  /**
   * True when neither day field is `*`. Cron then ORs them, which is the rule
   * most re-implementations get wrong.
   */
  readonly bothDayFieldsRestricted: boolean
}

function refuse(source: string, why: string): never {
  throw new ConfigError(`cron expression "${source}" is invalid: ${why}`)
}

/** One comma-separated term of one field. */
function parseTerm(term: string, spec: FieldSpec, source: string): number[] {
  if (term === '') refuse(source, `${spec.name} has an empty term (a stray comma?)`)

  // step
  let body = term
  let step = 1
  const slash = term.indexOf('/')
  if (slash !== -1) {
    body = term.slice(0, slash)
    const stepText = term.slice(slash + 1)
    if (!/^\d+$/.test(stepText)) {
      refuse(source, `${spec.name} step "${stepText}" is not a positive whole number`)
    }
    step = Number(stepText)
    if (step === 0) refuse(source, `${spec.name} step is 0, which selects nothing`)
  }

  let lo: number
  let hi: number
  if (body === '*') {
    lo = spec.min
    hi = spec.max
  } else {
    const dash = body.indexOf('-')
    if (dash > 0) {
      const loText = body.slice(0, dash)
      const hiText = body.slice(dash + 1)
      lo = numberIn(loText, spec, source)
      hi = numberIn(hiText, spec, source)
      if (lo > hi) {
        // Refused rather than wrapped: the wrapping reading is a nonstandard
        // extension, and guessing which one the author meant is how a job ends
        // up firing at the wrong hour for a year.
        refuse(
          source,
          `${spec.name} range ${loText}-${hiText} runs backwards; ranges do not wrap, so write two terms (${loText}-${String(spec.max)},${String(spec.min)}-${hiText})`,
        )
      }
    } else {
      lo = numberIn(body, spec, source)
      hi = lo
      if (slash !== -1) {
        // `5/10` is accepted by some implementations as 5,15,25… and rejected by
        // others. Refused, because the two readings differ and both look right.
        refuse(source, `${spec.name} "${term}" applies a step to a single value; write ${body}-${String(spec.max)}/${String(step)}`)
      }
    }
  }

  const values: number[] = []
  for (let v = lo; v <= hi; v += step) values.push(v)
  return values
}

function numberIn(text: string, spec: FieldSpec, source: string): number {
  if (!/^\d+$/.test(text)) {
    if (/^[a-z]+$/i.test(text)) {
      refuse(
        source,
        `${spec.name} "${text}" is a name; this parser takes numbers only (${String(spec.min)}-${String(spec.max)})`,
      )
    }
    refuse(source, `${spec.name} "${text}" is not a whole number`)
  }
  const value = Number(text)
  if (value < spec.min || value > spec.max) {
    refuse(source, `${spec.name} ${String(value)} is outside ${String(spec.min)}-${String(spec.max)}`)
  }
  return value
}

function parseField(text: string, spec: FieldSpec, source: string): Set<number> {
  const out = new Set<number>()
  for (const term of text.split(',')) {
    for (const value of parseTerm(term, spec, source)) out.add(value)
  }
  if (out.size === 0) refuse(source, `${spec.name} selects no values`)
  return out
}

export function parseCron(source: string): CronExpr {
  const text = source.trim()
  if (text === '') refuse(source, 'it is empty')
  if (text.startsWith('@')) {
    refuse(
      source,
      `macros like "${text}" are not supported; write the five fields (@daily is "0 0 * * *")`,
    )
  }
  for (const special of ['L', 'W', '#', '?']) {
    if (text.includes(special)) {
      refuse(source, `"${special}" is a nonstandard extension this parser does not implement`)
    }
  }

  const fields = text.split(/\s+/)
  if (fields.length !== 5) {
    const hint =
      fields.length === 6
        ? ' (six fields looks like a seconds column; this parser has minute resolution)'
        : ''
    refuse(source, `expected 5 fields, found ${String(fields.length)}${hint}`)
  }

  const [minuteText, hourText, domText, monthText, dowText] = fields as [
    string,
    string,
    string,
    string,
    string,
  ]
  const minute = parseField(minuteText, FIELDS[0]!, source)
  const hour = parseField(hourText, FIELDS[1]!, source)
  const dayOfMonth = parseField(domText, FIELDS[2]!, source)
  const month = parseField(monthText, FIELDS[3]!, source)
  const dowRaw = parseField(dowText, FIELDS[4]!, source)

  // 7 and 0 both mean Sunday. Normalised so matching compares one thing.
  const dayOfWeek = new Set<number>()
  for (const d of dowRaw) dayOfWeek.add(d === 7 ? 0 : d)

  return {
    source: text,
    minute,
    hour,
    dayOfMonth,
    month,
    dayOfWeek,
    bothDayFieldsRestricted: domText !== '*' && dowText !== '*',
  }
}

/**
 * Does this expression match the given LOCAL minute?
 *
 * Local because `0 9 * * 1-5` means nine in the morning where the operator is.
 * Seconds and milliseconds are ignored: the scheduler ticks once a minute and
 * dedupes on the minute, so matching is a property of the minute, not the instant.
 */
export function cronMatches(expr: CronExpr, at: Date): boolean {
  if (!expr.minute.has(at.getMinutes())) return false
  if (!expr.hour.has(at.getHours())) return false
  if (!expr.month.has(at.getMonth() + 1)) return false

  const domHit = expr.dayOfMonth.has(at.getDate())
  const dowHit = expr.dayOfWeek.has(at.getDay())
  // Cron's OR rule. With one field unrestricted it degenerates to AND, which is
  // what an expression like `0 9 * * 1-5` needs.
  return expr.bothDayFieldsRestricted ? domHit || dowHit : domHit && dowHit
}

/** The minute an instant belongs to, as a stable key for dedupe. */
export function minuteKey(at: Date): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, '0')
  return `${p(at.getFullYear(), 4)}-${p(at.getMonth() + 1)}-${p(at.getDate())}T${p(at.getHours())}:${p(at.getMinutes())}`
}
