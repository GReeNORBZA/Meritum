// ============================================================================
// Domain 10: Mobile Companion — Shift Reminder Service (MOB-002 §3.2)
// ============================================================================
//
// Scheduled job that checks upcoming shifts within the reminder window and
// emits SHIFT_REMINDER events. Also handles follow-up reminders for shifts
// that started but the physician hasn't manually started tracking.

import { SHIFT_REMINDER_BEFORE_MINUTES } from '@meritum/shared/constants/mobile.constants.js';
import type { SelectShiftSchedule } from '@meritum/shared/schemas/db/mobile.schema.js';
import { expandRrule, type ShiftInstance } from './rrule.service.js';

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

export interface ReminderDeps {
  /** List all active schedules for all providers */
  getActiveSchedules: () => Promise<SelectShiftSchedule[]>;

  /** Check whether the provider has an active shift right now */
  hasActiveShift: (providerId: string) => Promise<boolean>;

  /** Emit a notification event */
  emitNotification: (event: {
    type: string;
    providerId: string;
    payload: Record<string, unknown>;
  }) => Promise<void>;

  /** Audit log callback */
  auditLog?: (entry: {
    action: string;
    userId: string;
    category: string;
    detail: Record<string, unknown>;
  }) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReminderResult {
  reminders: number;
  followups: number;
  errors: string[];
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Process shift reminders for all active schedules.
 *
 * For each active schedule, expand the RRULE for the current time window
 * and check if any shift instance starts within the reminder window
 * (default: 15 minutes). If so, emit a SHIFT_REMINDER notification.
 *
 * @param deps - Injected dependencies
 * @param now - Current time (injectable for testing)
 * @returns Summary of reminders sent and errors
 */
export async function processShiftReminders(
  deps: ReminderDeps,
  now: Date = new Date(),
): Promise<ReminderResult> {
  const result: ReminderResult = { reminders: 0, followups: 0, errors: [] };
  const schedules = await deps.getActiveSchedules();

  // Define the reminder window: now to now + REMINDER_BEFORE_MINUTES
  const windowStart = now;
  const windowEnd = new Date(now.getTime() + SHIFT_REMINDER_BEFORE_MINUTES * 60_000);

  // Also need a slightly larger expansion window for RRULE
  const expansionStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const expansionEnd = new Date(expansionStart.getTime() + 2 * 24 * 60 * 60_000); // 2 days

  for (const schedule of schedules) {
    try {
      const instances = expandRrule(
        schedule.rrule,
        schedule.shiftStartTime,
        schedule.shiftDurationMinutes,
        expansionStart,
        expansionEnd,
      );

      for (const instance of instances) {
        // Check if this instance's start time falls within the reminder window
        if (instance.start >= windowStart && instance.start <= windowEnd) {
          await deps.emitNotification({
            type: 'SHIFT_REMINDER',
            providerId: schedule.providerId,
            payload: {
              scheduleId: schedule.scheduleId,
              scheduleName: schedule.name,
              locationId: schedule.locationId,
              shiftStart: instance.start.toISOString(),
              shiftEnd: instance.end.toISOString(),
              date: instance.date,
            },
          });
          result.reminders++;

          if (deps.auditLog) {
            await deps.auditLog({
              action: 'mobile.shift_reminder_sent',
              userId: schedule.providerId,
              category: 'mobile',
              detail: {
                scheduleId: schedule.scheduleId,
                shiftStart: instance.start.toISOString(),
              },
            });
          }
        }
      }
    } catch (err: any) {
      result.errors.push(
        `Schedule ${schedule.scheduleId}: ${err.message ?? 'unknown error'}`,
      );
    }
  }

  return result;
}

/**
 * Process follow-up reminders for shifts that are past their start time
 * but the physician hasn't manually started tracking.
 *
 * Checks shifts that started SHIFT_REMINDER_BEFORE_MINUTES ago. If the
 * physician doesn't have an active shift, emit SHIFT_FOLLOWUP_REMINDER.
 *
 * @param deps - Injected dependencies
 * @param now - Current time (injectable for testing)
 * @returns Summary including followup count
 */
export async function processFollowupReminders(
  deps: ReminderDeps,
  now: Date = new Date(),
): Promise<ReminderResult> {
  const result: ReminderResult = { reminders: 0, followups: 0, errors: [] };
  const schedules = await deps.getActiveSchedules();

  // Look for shifts that should have started REMINDER_BEFORE_MINUTES ago
  const lookbackStart = new Date(
    now.getTime() - SHIFT_REMINDER_BEFORE_MINUTES * 60_000 * 2,
  );
  const lookbackEnd = new Date(
    now.getTime() - SHIFT_REMINDER_BEFORE_MINUTES * 60_000,
  );

  const expansionStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const expansionEnd = new Date(expansionStart.getTime() + 2 * 24 * 60 * 60_000);

  for (const schedule of schedules) {
    try {
      const instances = expandRrule(
        schedule.rrule,
        schedule.shiftStartTime,
        schedule.shiftDurationMinutes,
        expansionStart,
        expansionEnd,
      );

      for (const instance of instances) {
        // Check if this shift should have started in the lookback window
        if (instance.start >= lookbackStart && instance.start <= lookbackEnd) {
          // Check if physician already has an active shift
          const hasActive = await deps.hasActiveShift(schedule.providerId);
          if (!hasActive) {
            await deps.emitNotification({
              type: 'SHIFT_FOLLOWUP_REMINDER',
              providerId: schedule.providerId,
              payload: {
                scheduleId: schedule.scheduleId,
                scheduleName: schedule.name,
                locationId: schedule.locationId,
                shiftStart: instance.start.toISOString(),
                shiftEnd: instance.end.toISOString(),
                date: instance.date,
                message:
                  'Your scheduled shift appears to have started. Would you like to begin tracking?',
              },
            });
            result.followups++;

            if (deps.auditLog) {
              await deps.auditLog({
                action: 'mobile.shift_followup_sent',
                userId: schedule.providerId,
                category: 'mobile',
                detail: {
                  scheduleId: schedule.scheduleId,
                  shiftStart: instance.start.toISOString(),
                },
              });
            }
          }
        }
      }
    } catch (err: any) {
      result.errors.push(
        `Schedule ${schedule.scheduleId}: ${err.message ?? 'unknown error'}`,
      );
    }
  }

  return result;
}
