import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  SHIFT_REMINDER_BEFORE_MINUTES: 15,
  SHIFT_SCHEDULE_HORIZON_DAYS: 90,
}));

vi.mock('./rrule.service.js', () => ({
  expandRrule: vi.fn().mockReturnValue([]),
}));

import {
  processShiftReminders,
  processFollowupReminders,
} from './shift-reminder.service.js';
import type { ReminderDeps } from './shift-reminder.service.js';
import { expandRrule } from './rrule.service.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const SCHEDULE_ID = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();

function makeSchedule(overrides: Record<string, any> = {}) {
  return {
    scheduleId: overrides.scheduleId ?? SCHEDULE_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    locationId: overrides.locationId ?? LOCATION_ID,
    name: overrides.name ?? 'Monday ED',
    rrule: overrides.rrule ?? 'FREQ=WEEKLY;BYDAY=MO',
    shiftStartTime: overrides.shiftStartTime ?? '08:00',
    shiftDurationMinutes: overrides.shiftDurationMinutes ?? 480,
    isActive: true,
    lastExpandedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function makeDeps(overrides: Partial<ReminderDeps> = {}): ReminderDeps {
  return {
    getActiveSchedules: vi.fn().mockResolvedValue([makeSchedule()]),
    hasActiveShift: vi.fn().mockResolvedValue(false),
    emitNotification: vi.fn().mockResolvedValue(undefined),
    auditLog: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ShiftReminderService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('processShiftReminders', () => {
    it('should emit reminder for upcoming shift in window', async () => {
      const now = new Date(2026, 1, 16, 7, 50, 0); // 7:50 AM
      const shiftStart = new Date(2026, 1, 16, 8, 0, 0); // 8:00 AM (within 15min)

      vi.mocked(expandRrule).mockReturnValue([
        { start: shiftStart, end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
      ]);

      const deps = makeDeps();
      const result = await processShiftReminders(deps, now);

      expect(result.reminders).toBe(1);
      expect(deps.emitNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'SHIFT_REMINDER',
          providerId: PROVIDER_A,
        }),
      );
    });

    it('should NOT emit reminder for shift outside window', async () => {
      const now = new Date(2026, 1, 16, 7, 0, 0); // 7:00 AM
      const shiftStart = new Date(2026, 1, 16, 8, 0, 0); // 8:00 AM (60min away)

      vi.mocked(expandRrule).mockReturnValue([
        { start: shiftStart, end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
      ]);

      const deps = makeDeps();
      const result = await processShiftReminders(deps, now);

      expect(result.reminders).toBe(0);
      expect(deps.emitNotification).not.toHaveBeenCalled();
    });

    it('should handle multiple schedules', async () => {
      const now = new Date(2026, 1, 16, 7, 50, 0);
      const deps = makeDeps({
        getActiveSchedules: vi.fn().mockResolvedValue([
          makeSchedule(),
          makeSchedule({ scheduleId: crypto.randomUUID(), providerId: crypto.randomUUID() }),
        ]),
      });

      vi.mocked(expandRrule).mockReturnValue([
        { start: new Date(2026, 1, 16, 8, 0), end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
      ]);

      const result = await processShiftReminders(deps, now);
      expect(result.reminders).toBe(2);
    });

    it('should collect errors without stopping', async () => {
      vi.mocked(expandRrule).mockImplementation(() => {
        throw new Error('Invalid RRULE');
      });

      const deps = makeDeps();
      const result = await processShiftReminders(deps, new Date());

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('Invalid RRULE');
    });

    it('should log audit when auditLog is provided', async () => {
      const now = new Date(2026, 1, 16, 7, 50, 0);
      vi.mocked(expandRrule).mockReturnValue([
        { start: new Date(2026, 1, 16, 8, 0), end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
      ]);

      const deps = makeDeps();
      await processShiftReminders(deps, now);

      expect(deps.auditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'mobile.shift_reminder_sent' }),
      );
    });
  });

  describe('processFollowupReminders', () => {
    it('should emit followup when shift started but no active shift', async () => {
      const now = new Date(2026, 1, 16, 8, 20, 0); // 8:20 AM
      // Shift started at 8:00 (20min ago, within lookback 15-30min)
      const shiftStart = new Date(2026, 1, 16, 8, 0, 0);

      vi.mocked(expandRrule).mockReturnValue([
        { start: shiftStart, end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
      ]);

      const deps = makeDeps({
        hasActiveShift: vi.fn().mockResolvedValue(false),
      });
      const result = await processFollowupReminders(deps, now);

      expect(result.followups).toBe(1);
      expect(deps.emitNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'SHIFT_FOLLOWUP_REMINDER',
          providerId: PROVIDER_A,
        }),
      );
    });

    it('should NOT emit followup when physician already has active shift', async () => {
      const now = new Date(2026, 1, 16, 8, 20, 0);
      const shiftStart = new Date(2026, 1, 16, 8, 0, 0);

      vi.mocked(expandRrule).mockReturnValue([
        { start: shiftStart, end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
      ]);

      const deps = makeDeps({
        hasActiveShift: vi.fn().mockResolvedValue(true),
      });
      const result = await processFollowupReminders(deps, now);

      expect(result.followups).toBe(0);
      expect(deps.emitNotification).not.toHaveBeenCalled();
    });

    it('should collect errors without stopping', async () => {
      vi.mocked(expandRrule).mockImplementation(() => {
        throw new Error('Bad RRULE');
      });

      const deps = makeDeps();
      const result = await processFollowupReminders(deps, new Date());

      expect(result.errors).toHaveLength(1);
    });
  });
});
