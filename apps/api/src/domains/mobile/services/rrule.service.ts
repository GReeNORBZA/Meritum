// ============================================================================
// Domain 10: Mobile Companion — RRULE Expansion Service (MOB-002 §3.1.2)
// ============================================================================
//
// Expands iCal RRULE strings into concrete date instances for shift scheduling.
// Supports FREQ=WEEKLY, FREQ=MONTHLY, BYDAY, INTERVAL.
// Handles overnight shifts (end time < start time = next calendar day).

import { SHIFT_SCHEDULE_HORIZON_DAYS } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShiftInstance {
  /** Start of the shift (local date-time) */
  start: Date;
  /** End of the shift (local date-time); may be next calendar day for overnight */
  end: Date;
  /** The RRULE-expanded date (YYYY-MM-DD) */
  date: string;
}

export interface ParsedRRule {
  freq: 'WEEKLY' | 'MONTHLY';
  interval: number;
  byDay: string[];
  until?: Date;
  count?: number;
}

// ---------------------------------------------------------------------------
// Day-of-week mapping (iCal BYDAY → JS getDay())
// ---------------------------------------------------------------------------

const ICAL_DAY_MAP: Record<string, number> = {
  SU: 0,
  MO: 1,
  TU: 2,
  WE: 3,
  TH: 4,
  FR: 5,
  SA: 6,
};

const JS_DAY_TO_ICAL: Record<number, string> = {
  0: 'SU',
  1: 'MO',
  2: 'TU',
  3: 'WE',
  4: 'TH',
  5: 'FR',
  6: 'SA',
};

// ---------------------------------------------------------------------------
// RRULE Parsing
// ---------------------------------------------------------------------------

/**
 * Parse an iCal RRULE string into structured components.
 *
 * Supported properties:
 * - FREQ=WEEKLY | FREQ=MONTHLY
 * - INTERVAL=N (default 1)
 * - BYDAY=MO,TU,WE,...
 * - UNTIL=YYYYMMDD
 * - COUNT=N
 *
 * @example parseRRule('FREQ=WEEKLY;BYDAY=MO,WE,FR;INTERVAL=1')
 */
export function parseRRule(rrule: string): ParsedRRule {
  const parts = rrule.split(';');
  let freq: 'WEEKLY' | 'MONTHLY' = 'WEEKLY';
  let interval = 1;
  let byDay: string[] = [];
  let until: Date | undefined;
  let count: number | undefined;

  for (const part of parts) {
    const [key, value] = part.split('=');
    switch (key) {
      case 'FREQ':
        if (value !== 'WEEKLY' && value !== 'MONTHLY') {
          throw new Error(`Unsupported FREQ: ${value}. Only WEEKLY and MONTHLY are supported.`);
        }
        freq = value;
        break;
      case 'INTERVAL':
        interval = parseInt(value, 10);
        if (isNaN(interval) || interval < 1) {
          throw new Error(`Invalid INTERVAL: ${value}`);
        }
        break;
      case 'BYDAY':
        byDay = value.split(',').map((d) => d.trim().toUpperCase());
        for (const day of byDay) {
          if (!(day in ICAL_DAY_MAP)) {
            throw new Error(`Unknown BYDAY value: ${day}`);
          }
        }
        break;
      case 'UNTIL': {
        const y = parseInt(value.slice(0, 4), 10);
        const m = parseInt(value.slice(4, 6), 10) - 1;
        const d = parseInt(value.slice(6, 8), 10);
        until = new Date(y, m, d, 23, 59, 59, 999);
        break;
      }
      case 'COUNT':
        count = parseInt(value, 10);
        if (isNaN(count) || count < 1) {
          throw new Error(`Invalid COUNT: ${value}`);
        }
        break;
    }
  }

  return { freq, interval, byDay, until, count };
}

// ---------------------------------------------------------------------------
// Time Parsing
// ---------------------------------------------------------------------------

/**
 * Parse an HH:mm time string into hours and minutes.
 */
export function parseTime(time: string): { hours: number; minutes: number } {
  const [h, m] = time.split(':').map(Number);
  return { hours: h, minutes: m };
}

// ---------------------------------------------------------------------------
// RRULE Expansion
// ---------------------------------------------------------------------------

/**
 * Expand an iCal RRULE string into concrete shift instances.
 *
 * @param rrule - iCal RRULE string (e.g., 'FREQ=WEEKLY;BYDAY=MO,WE,FR')
 * @param shiftStartTime - Shift start time in HH:mm format
 * @param shiftDurationMinutes - Shift duration in minutes
 * @param effectiveFrom - Start of expansion window (inclusive)
 * @param effectiveUntil - End of expansion window (exclusive, defaults to effectiveFrom + windowDays)
 * @param windowDays - Default window in days when effectiveUntil not specified
 * @returns Array of concrete shift instances with start/end times
 */
export function expandRrule(
  rrule: string,
  shiftStartTime: string,
  shiftDurationMinutes: number,
  effectiveFrom: Date,
  effectiveUntil?: Date,
  windowDays: number = SHIFT_SCHEDULE_HORIZON_DAYS,
): ShiftInstance[] {
  const parsed = parseRRule(rrule);
  const { hours, minutes } = parseTime(shiftStartTime);

  const windowEnd = effectiveUntil ?? new Date(
    effectiveFrom.getFullYear(),
    effectiveFrom.getMonth(),
    effectiveFrom.getDate() + windowDays,
  );

  // Clamp by UNTIL if present
  const endDate = parsed.until && parsed.until < windowEnd
    ? parsed.until
    : windowEnd;

  const instances: ShiftInstance[] = [];
  let countRemaining = parsed.count ?? Infinity;

  if (parsed.freq === 'WEEKLY') {
    expandWeekly(parsed, effectiveFrom, endDate, hours, minutes, shiftDurationMinutes, instances, countRemaining);
  } else if (parsed.freq === 'MONTHLY') {
    expandMonthly(parsed, effectiveFrom, endDate, hours, minutes, shiftDurationMinutes, instances, countRemaining);
  }

  return instances;
}

// ---------------------------------------------------------------------------
// Weekly Expansion
// ---------------------------------------------------------------------------

function expandWeekly(
  parsed: ParsedRRule,
  from: Date,
  until: Date,
  hours: number,
  minutes: number,
  duration: number,
  out: ShiftInstance[],
  maxCount: number,
): void {
  // If no BYDAY specified, use all 7 days
  const targetDays = parsed.byDay.length > 0
    ? parsed.byDay.map((d) => ICAL_DAY_MAP[d])
    : [0, 1, 2, 3, 4, 5, 6];

  // Start from the beginning of the week containing effectiveFrom
  const cursor = new Date(from.getFullYear(), from.getMonth(), from.getDate());

  // Rewind cursor to the start of its week (Sunday)
  cursor.setDate(cursor.getDate() - cursor.getDay());

  let weekCount = 0;
  let emitted = 0;

  while (cursor <= until && emitted < maxCount) {
    // Only emit on matching interval weeks
    if (weekCount % parsed.interval === 0) {
      for (const dayNum of targetDays) {
        if (emitted >= maxCount) break;

        const instanceDate = new Date(cursor);
        instanceDate.setDate(cursor.getDate() + dayNum);

        // Skip dates before the effective window
        if (instanceDate < from) continue;
        // Skip dates at or after window end
        if (instanceDate >= until) continue;

        const start = new Date(instanceDate);
        start.setHours(hours, minutes, 0, 0);

        const end = new Date(start.getTime() + duration * 60_000);

        const dateStr = formatDate(instanceDate);
        out.push({ start, end, date: dateStr });
        emitted++;
      }
    }

    // Advance by one week
    cursor.setDate(cursor.getDate() + 7);
    weekCount++;
  }
}

// ---------------------------------------------------------------------------
// Monthly Expansion
// ---------------------------------------------------------------------------

function expandMonthly(
  parsed: ParsedRRule,
  from: Date,
  until: Date,
  hours: number,
  minutes: number,
  duration: number,
  out: ShiftInstance[],
  maxCount: number,
): void {
  // For MONTHLY with BYDAY, we need to find the matching days in each month
  // For MONTHLY without BYDAY, use the same day-of-month as from
  const targetDays = parsed.byDay.length > 0
    ? parsed.byDay.map((d) => ICAL_DAY_MAP[d])
    : null;

  let year = from.getFullYear();
  let month = from.getMonth();
  let emitted = 0;
  let monthCount = 0;

  while (emitted < maxCount) {
    if (monthCount % parsed.interval === 0) {
      if (targetDays) {
        // Find all occurrences of target days in this month
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        for (let d = 1; d <= daysInMonth; d++) {
          if (emitted >= maxCount) break;

          const candidate = new Date(year, month, d);
          if (candidate < from) continue;
          if (candidate >= until) return;

          if (targetDays.includes(candidate.getDay())) {
            const start = new Date(candidate);
            start.setHours(hours, minutes, 0, 0);
            const end = new Date(start.getTime() + duration * 60_000);
            out.push({ start, end, date: formatDate(candidate) });
            emitted++;
          }
        }
      } else {
        // Same day-of-month
        const dayOfMonth = from.getDate();
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        const actualDay = Math.min(dayOfMonth, daysInMonth);
        const candidate = new Date(year, month, actualDay);

        if (candidate >= from && candidate < until) {
          const start = new Date(candidate);
          start.setHours(hours, minutes, 0, 0);
          const end = new Date(start.getTime() + duration * 60_000);
          out.push({ start, end, date: formatDate(candidate) });
          emitted++;
        }

        if (candidate >= until) return;
      }
    }

    // Advance to next month
    month++;
    if (month > 11) {
      month = 0;
      year++;
    }
    monthCount++;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(d: Date): string {
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Check if a shift crosses midnight (overnight shift).
 * An overnight shift has end time earlier than start time on the clock.
 *
 * @example isOvernightShift('22:00', 600) // 22:00 + 10h = 08:00 next day → true
 * @example isOvernightShift('08:00', 480) // 08:00 + 8h = 16:00 same day → false
 */
export function isOvernightShift(
  shiftStartTime: string,
  durationMinutes: number,
): boolean {
  const { hours, minutes } = parseTime(shiftStartTime);
  const startMinutes = hours * 60 + minutes;
  const endMinutes = startMinutes + durationMinutes;
  return endMinutes >= 24 * 60;
}
