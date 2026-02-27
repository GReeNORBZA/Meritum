import { describe, it, expect } from 'vitest';

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  SHIFT_SCHEDULE_HORIZON_DAYS: 90,
}));

import { vi } from 'vitest';
import {
  parseRRule,
  expandRrule,
  parseTime,
  isOvernightShift,
} from './rrule.service.js';

// ---------------------------------------------------------------------------
// parseRRule
// ---------------------------------------------------------------------------

describe('parseRRule', () => {
  it('should parse FREQ=WEEKLY with BYDAY', () => {
    const result = parseRRule('FREQ=WEEKLY;BYDAY=MO,WE,FR');
    expect(result.freq).toBe('WEEKLY');
    expect(result.interval).toBe(1);
    expect(result.byDay).toEqual(['MO', 'WE', 'FR']);
  });

  it('should parse FREQ=WEEKLY with INTERVAL', () => {
    const result = parseRRule('FREQ=WEEKLY;BYDAY=TU;INTERVAL=2');
    expect(result.freq).toBe('WEEKLY');
    expect(result.interval).toBe(2);
    expect(result.byDay).toEqual(['TU']);
  });

  it('should parse FREQ=MONTHLY', () => {
    const result = parseRRule('FREQ=MONTHLY;BYDAY=MO');
    expect(result.freq).toBe('MONTHLY');
    expect(result.byDay).toEqual(['MO']);
  });

  it('should parse UNTIL', () => {
    const result = parseRRule('FREQ=WEEKLY;BYDAY=MO;UNTIL=20260401');
    expect(result.until).toBeDefined();
    expect(result.until!.getFullYear()).toBe(2026);
    expect(result.until!.getMonth()).toBe(3); // April (0-indexed)
    expect(result.until!.getDate()).toBe(1);
  });

  it('should parse COUNT', () => {
    const result = parseRRule('FREQ=WEEKLY;BYDAY=MO;COUNT=5');
    expect(result.count).toBe(5);
  });

  it('should default interval to 1', () => {
    const result = parseRRule('FREQ=WEEKLY;BYDAY=MO');
    expect(result.interval).toBe(1);
  });

  it('should throw on unsupported FREQ', () => {
    expect(() => parseRRule('FREQ=DAILY;BYDAY=MO')).toThrow('Unsupported FREQ');
  });

  it('should throw on invalid BYDAY', () => {
    expect(() => parseRRule('FREQ=WEEKLY;BYDAY=XX')).toThrow('Unknown BYDAY');
  });

  it('should throw on invalid INTERVAL', () => {
    expect(() => parseRRule('FREQ=WEEKLY;INTERVAL=0')).toThrow('Invalid INTERVAL');
  });

  it('should throw on invalid COUNT', () => {
    expect(() => parseRRule('FREQ=WEEKLY;COUNT=-1')).toThrow('Invalid COUNT');
  });
});

// ---------------------------------------------------------------------------
// parseTime
// ---------------------------------------------------------------------------

describe('parseTime', () => {
  it('should parse HH:mm', () => {
    expect(parseTime('08:30')).toEqual({ hours: 8, minutes: 30 });
    expect(parseTime('22:00')).toEqual({ hours: 22, minutes: 0 });
    expect(parseTime('00:15')).toEqual({ hours: 0, minutes: 15 });
  });
});

// ---------------------------------------------------------------------------
// expandRrule — WEEKLY
// ---------------------------------------------------------------------------

describe('expandRrule — WEEKLY', () => {
  it('should expand a weekly MO,WE,FR schedule for 2 weeks', () => {
    const from = new Date(2026, 1, 16); // Monday Feb 16 2026
    const to = new Date(2026, 2, 2);    // Monday Mar 2 2026

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO,WE,FR',
      '08:00',
      480, // 8 hours
      from,
      to,
    );

    // Feb 16 (MO), Feb 18 (WE), Feb 20 (FR), Feb 23 (MO), Feb 25 (WE), Feb 27 (FR)
    expect(instances).toHaveLength(6);
    expect(instances[0].date).toBe('2026-02-16');
    expect(instances[1].date).toBe('2026-02-18');
    expect(instances[2].date).toBe('2026-02-20');
    expect(instances[3].date).toBe('2026-02-23');
    expect(instances[4].date).toBe('2026-02-25');
    expect(instances[5].date).toBe('2026-02-27');
  });

  it('should respect INTERVAL=2 (every other week)', () => {
    const from = new Date(2026, 1, 16); // Monday
    const to = new Date(2026, 2, 16);   // 4 weeks later

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO;INTERVAL=2',
      '08:00',
      480,
      from,
      to,
    );

    // Week 1: Feb 16, Week 3: Mar 2
    expect(instances).toHaveLength(2);
    expect(instances[0].date).toBe('2026-02-16');
    expect(instances[1].date).toBe('2026-03-02');
  });

  it('should respect COUNT limit', () => {
    const from = new Date(2026, 1, 16);
    const to = new Date(2026, 11, 31);

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO;COUNT=3',
      '08:00',
      480,
      from,
      to,
    );

    expect(instances).toHaveLength(3);
  });

  it('should respect UNTIL', () => {
    const from = new Date(2026, 1, 16);
    const to = new Date(2026, 11, 31);

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO;UNTIL=20260302',
      '08:00',
      480,
      from,
      to,
    );

    // Feb 16, Feb 23, Mar 2
    expect(instances).toHaveLength(3);
    expect(instances[2].date).toBe('2026-03-02');
  });

  it('should set correct start and end times', () => {
    const from = new Date(2026, 1, 16);
    const to = new Date(2026, 1, 17);

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO',
      '08:30',
      480, // 8 hours
      from,
      to,
    );

    expect(instances).toHaveLength(1);
    expect(instances[0].start.getHours()).toBe(8);
    expect(instances[0].start.getMinutes()).toBe(30);
    expect(instances[0].end.getHours()).toBe(16);
    expect(instances[0].end.getMinutes()).toBe(30);
  });

  it('should handle overnight shifts (end crosses midnight)', () => {
    const from = new Date(2026, 1, 16);
    const to = new Date(2026, 1, 17);

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO',
      '22:00',
      600, // 10 hours → ends at 08:00 next day
      from,
      to,
    );

    expect(instances).toHaveLength(1);
    expect(instances[0].start.getHours()).toBe(22);
    // End should be next day 08:00
    expect(instances[0].end.getDate()).toBe(17);
    expect(instances[0].end.getHours()).toBe(8);
  });

  it('should use 90-day default window when effectiveUntil not specified', () => {
    const from = new Date(2026, 0, 1);

    const instances = expandRrule(
      'FREQ=WEEKLY;BYDAY=MO',
      '08:00',
      480,
      from,
    );

    // ~13 Mondays in 90 days
    expect(instances.length).toBeGreaterThanOrEqual(12);
    expect(instances.length).toBeLessThanOrEqual(14);
  });
});

// ---------------------------------------------------------------------------
// expandRrule — MONTHLY
// ---------------------------------------------------------------------------

describe('expandRrule — MONTHLY', () => {
  it('should expand monthly with BYDAY', () => {
    const from = new Date(2026, 0, 1);  // Jan 1
    const to = new Date(2026, 3, 1);    // Apr 1 (3 months)

    const instances = expandRrule(
      'FREQ=MONTHLY;BYDAY=FR',
      '08:00',
      480,
      from,
      to,
    );

    // All Fridays in Jan, Feb, Mar
    // Jan: 2,9,16,23,30 (5), Feb: 6,13,20,27 (4), Mar: 6,13,20,27 (4) = 13
    expect(instances.length).toBe(13);
  });

  it('should expand monthly without BYDAY (same day of month)', () => {
    const from = new Date(2026, 0, 15); // Jan 15
    const to = new Date(2026, 4, 1);    // May 1

    const instances = expandRrule(
      'FREQ=MONTHLY',
      '08:00',
      480,
      from,
      to,
    );

    // Jan 15, Feb 15, Mar 15, Apr 15
    expect(instances).toHaveLength(4);
    expect(instances[0].date).toBe('2026-01-15');
    expect(instances[1].date).toBe('2026-02-15');
    expect(instances[2].date).toBe('2026-03-15');
    expect(instances[3].date).toBe('2026-04-15');
  });

  it('should handle months with fewer days (e.g., Feb 30 → Feb 28)', () => {
    const from = new Date(2026, 0, 30); // Jan 30
    const to = new Date(2026, 3, 1);

    const instances = expandRrule(
      'FREQ=MONTHLY',
      '08:00',
      480,
      from,
      to,
    );

    // Jan 30, Feb 28 (no Feb 30), Mar 30
    expect(instances).toHaveLength(3);
    expect(instances[1].date).toBe('2026-02-28');
  });

  it('should respect INTERVAL for monthly', () => {
    const from = new Date(2026, 0, 15);
    const to = new Date(2026, 6, 1);

    const instances = expandRrule(
      'FREQ=MONTHLY;INTERVAL=2',
      '08:00',
      480,
      from,
      to,
    );

    // Jan 15, Mar 15, May 15
    expect(instances).toHaveLength(3);
    expect(instances[0].date).toBe('2026-01-15');
    expect(instances[1].date).toBe('2026-03-15');
    expect(instances[2].date).toBe('2026-05-15');
  });
});

// ---------------------------------------------------------------------------
// isOvernightShift
// ---------------------------------------------------------------------------

describe('isOvernightShift', () => {
  it('should return true for shifts crossing midnight', () => {
    expect(isOvernightShift('22:00', 600)).toBe(true); // 22:00 + 10h = 08:00
    expect(isOvernightShift('23:00', 540)).toBe(true); // 23:00 + 9h = 08:00
  });

  it('should return false for day shifts', () => {
    expect(isOvernightShift('08:00', 480)).toBe(false); // 08:00 + 8h = 16:00
    expect(isOvernightShift('06:00', 600)).toBe(false); // 06:00 + 10h = 16:00
  });

  it('should return true for exactly midnight ending', () => {
    expect(isOvernightShift('16:00', 480)).toBe(true); // 16:00 + 8h = 00:00
  });
});
