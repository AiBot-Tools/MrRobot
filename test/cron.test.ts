// C.1 — cron expressions.
//
// A cron parser has a large surface for being quietly wrong, and every wrong
// reading looks correct in the file. So the tests are mostly about REFUSALS: an
// expression this parser does not implement must be rejected by name, because
// the alternative is firing a hundred runs nobody asked for from an expression
// that reads fine.
//
// The falsifiers:
//
//   Read `MON-FRI` as anything at all and a weekday job becomes an every-minute
//   job, because an unparsed name that defaulted to `*` is the widest possible
//   mistake.
//   Let `55-5` wrap and a job fires at hours the author did not write; refuse it
//   and they find out at parse time.
//   AND the two day fields when both are restricted and `0 0 1 * 1` fires only on
//   Mondays that fall on the 1st — a handful of times a year instead of monthly
//   plus weekly. This is cron's genuinely surprising rule and the one a
//   re-implementation gets wrong.

import './helpers/guard.js'

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { cronMatches, minuteKey, parseCron } from '../src/runtime/cron.js'

/** Local-time date, so matching is tested in the zone the scheduler uses. */
function at(iso: string): Date {
  return new Date(iso)
}

test('parses every supported field form and matches the minutes it should', () => {
  // A single value in each field.
  const exact = parseCron('30 9 15 6 *')
  assert.deepEqual([...exact.minute], [30])
  assert.deepEqual([...exact.hour], [9])
  assert.deepEqual([...exact.dayOfMonth], [15])
  assert.deepEqual([...exact.month], [6])
  // Seven days, not eight: `*` parses 0-7 and normalisation collapses 7 onto 0,
  // so Sunday is present once rather than twice.
  assert.deepEqual([...exact.dayOfWeek].sort((a, b) => a - b), [0, 1, 2, 3, 4, 5, 6])
  assert.equal(cronMatches(exact, at('2026-06-15T09:30:00')), true)
  assert.equal(cronMatches(exact, at('2026-06-15T09:31:00')), false)
  assert.equal(cronMatches(exact, at('2026-06-16T09:30:00')), false)
  assert.equal(cronMatches(exact, at('2026-07-15T09:30:00')), false)

  // Every minute.
  const always = parseCron('* * * * *')
  assert.equal(always.minute.size, 60)
  assert.equal(cronMatches(always, at('2026-01-01T00:00:00')), true)
  assert.equal(cronMatches(always, at('2026-12-31T23:59:00')), true)

  // Step from the field minimum.
  const quarter = parseCron('*/15 * * * *')
  assert.deepEqual([...quarter.minute].sort((a, b) => a - b), [0, 15, 30, 45])
  for (const m of [0, 15, 30, 45]) {
    assert.equal(cronMatches(quarter, at(`2026-03-04T10:${String(m).padStart(2, '0')}:00`)), true)
  }
  assert.equal(cronMatches(quarter, at('2026-03-04T10:14:00')), false)

  // Range, and a stepped range.
  assert.deepEqual([...parseCron('0 9-17 * * *').hour], [9, 10, 11, 12, 13, 14, 15, 16, 17])
  assert.deepEqual([...parseCron('0 0-12/4 * * *').hour], [0, 4, 8, 12])

  // Lists, and lists of mixed forms.
  assert.deepEqual([...parseCron('0,30 * * * *').minute].sort((a, b) => a - b), [0, 30])
  assert.deepEqual(
    [...parseCron('0 1,3-5,20-23/2 * * *').hour].sort((a, b) => a - b),
    [1, 3, 4, 5, 20, 22],
  )

  // Weekdays at nine, the expression an operator is most likely to write.
  const weekdays = parseCron('0 9 * * 1-5')
  assert.equal(cronMatches(weekdays, at('2026-09-28T09:00:00')), true, 'Monday')
  assert.equal(cronMatches(weekdays, at('2026-10-02T09:00:00')), true, 'Friday')
  assert.equal(cronMatches(weekdays, at('2026-10-03T09:00:00')), false, 'Saturday')
  assert.equal(cronMatches(weekdays, at('2026-10-04T09:00:00')), false, 'Sunday')

  // Sunday is 0 and 7 is accepted as the same day, normalised so matching has
  // one representation to compare.
  assert.deepEqual([...parseCron('0 0 * * 7').dayOfWeek], [0])
  assert.deepEqual([...parseCron('0 0 * * 0').dayOfWeek], [0])
  assert.equal(cronMatches(parseCron('0 0 * * 7'), at('2026-10-04T00:00:00')), true)

  // Surrounding whitespace and multiple spaces between fields.
  assert.equal(parseCron('  0   9  *  *  * ').source, '0   9  *  *  *')
  assert.deepEqual([...parseCron('  0   9  *  *  * ').hour], [9])
})

test("applies cron's OR rule when both day fields are restricted", () => {
  // The rule a re-implementation gets wrong. `0 0 1 * 1` is the first of the
  // month OR every Monday — not Mondays that fall on the first, which would be a
  // handful of days a year instead of roughly sixteen.
  const both = parseCron('0 0 1 * 1')
  assert.equal(both.bothDayFieldsRestricted, true)
  assert.equal(cronMatches(both, at('2026-10-01T00:00:00')), true, 'the 1st, a Thursday')
  assert.equal(cronMatches(both, at('2026-10-05T00:00:00')), true, 'a Monday, not the 1st')
  assert.equal(cronMatches(both, at('2026-10-07T00:00:00')), false, 'neither')

  // With one field unrestricted it must behave as AND, or a weekday job would
  // fire every day of the month.
  const dowOnly = parseCron('0 0 * * 1')
  assert.equal(dowOnly.bothDayFieldsRestricted, false)
  assert.equal(cronMatches(dowOnly, at('2026-10-05T00:00:00')), true)
  assert.equal(cronMatches(dowOnly, at('2026-10-06T00:00:00')), false)

  const domOnly = parseCron('0 0 1 * *')
  assert.equal(domOnly.bothDayFieldsRestricted, false)
  assert.equal(cronMatches(domOnly, at('2026-10-01T00:00:00')), true)
  assert.equal(cronMatches(domOnly, at('2026-10-02T00:00:00')), false)
})

test('refuses what it does not implement instead of guessing', () => {
  const cases: [string, RegExp][] = [
    // Names. The widest possible mistake if mis-parsed as `*`.
    ['0 9 * * MON-FRI', /is a name; this parser takes numbers only/],
    ['0 9 * JAN *', /is a name/],
    // Macros.
    ['@daily', /macros like "@daily" are not supported.*0 0 \* \* \*/s],
    ['@reboot', /macros/],
    // Field count. Six fields is a seconds column, and reading it as five would
    // shift every field by one.
    ['0 0 * * * *', /expected 5 fields, found 6.*seconds column/s],
    ['0 0 * *', /expected 5 fields, found 4/],
    ['*', /expected 5 fields, found 1/],
    // Nonstandard specials.
    ['0 0 L * *', /"L" is a nonstandard extension/],
    ['0 0 * * 5#3', /"#" is a nonstandard extension/],
    ['0 0 ? * *', /"\?" is a nonstandard extension/],
    ['0 0 15W * *', /"W" is a nonstandard extension/],
    // Out of range.
    ['60 * * * *', /minute 60 is outside 0-59/],
    ['0 24 * * *', /hour 24 is outside 0-23/],
    ['0 0 0 * *', /day-of-month 0 is outside 1-31/],
    ['0 0 32 * *', /day-of-month 32 is outside 1-31/],
    ['0 0 * 13 *', /month 13 is outside 1-12/],
    ['0 0 * * 8', /day-of-week 8 is outside 0-7/],
    // Backwards ranges, refused with the two-term form to write instead.
    ['55-5 * * * *', /runs backwards; ranges do not wrap.*55-59,0-5/s],
    ['0 17-9 * * *', /runs backwards/],
    // Steps that select nothing, or that are ambiguous.
    ['*/0 * * * *', /step is 0, which selects nothing/],
    ['*/-1 * * * *', /step "-1" is not a positive whole number/],
    ['5/10 * * * *', /applies a step to a single value; write 5-59\/10/],
    // Malformed.
    ['', /it is empty/],
    ['   ', /it is empty/],
    ['0,, * * * *', /has an empty term/],
    ['0 9 * * 1-', /is not a whole number/],
    ['x * * * *', /is a name/],
    ['0 9 * * 1.5', /is not a whole number/],
  ]

  for (const [expr, pattern] of cases) {
    assert.throws(() => parseCron(expr), pattern, `"${expr}" was accepted or misreported`)
  }

  // Every refusal quotes the expression, so an operator can find it in the file.
  for (const [expr] of cases) {
    try {
      parseCron(expr)
      assert.fail(`"${expr}" was accepted`)
    } catch (e) {
      assert.match((e as Error).message, /^cron expression ".*" is invalid: /, expr)
    }
  }
})

test('minuteKey identifies the minute and nothing finer', () => {
  // The dedupe key. Seconds must not be in it, or two ticks in the same minute
  // would look like different minutes and a job would fire twice.
  assert.equal(minuteKey(at('2026-09-26T14:05:00')), '2026-09-26T14:05')
  assert.equal(minuteKey(at('2026-09-26T14:05:59.999')), '2026-09-26T14:05')
  assert.notEqual(minuteKey(at('2026-09-26T14:05:00')), minuteKey(at('2026-09-26T14:06:00')))
  // Padded, so keys sort and compare as strings.
  assert.equal(minuteKey(at('2026-01-02T03:04:00')), '2026-01-02T03:04')
})
