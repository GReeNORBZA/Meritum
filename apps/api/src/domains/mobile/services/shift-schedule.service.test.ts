import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  ShiftSource: { MANUAL: 'MANUAL', INFERRED: 'INFERRED' },
  MobileShiftStatus: { ACTIVE: 'ACTIVE', ENDED: 'ENDED', REVIEWED: 'REVIEWED' },
  SHIFT_SCHEDULE_HORIZON_DAYS: 90,
}));

vi.mock('./rrule.service.js', () => ({
  expandRrule: vi.fn().mockReturnValue([]),
}));

import {
  createSchedule,
  updateSchedule,
  deleteSchedule,
  getSchedule,
  listSchedules,
  getCalendarInstances,
  createInferredShift,
} from './shift-schedule.service.js';
import type { ShiftScheduleServiceDeps } from './shift-schedule.service.js';
import { expandRrule } from './rrule.service.js';
import { NotFoundError, BusinessRuleError } from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();
const SCHEDULE_ID = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();

function makeSchedule(overrides: Record<string, any> = {}) {
  return {
    scheduleId: overrides.scheduleId ?? SCHEDULE_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    locationId: overrides.locationId ?? LOCATION_ID,
    name: overrides.name ?? 'Monday ED',
    rrule: overrides.rrule ?? 'FREQ=WEEKLY;BYDAY=MO',
    shiftStartTime: overrides.shiftStartTime ?? '08:00',
    shiftDurationMinutes: overrides.shiftDurationMinutes ?? 480,
    isActive: overrides.isActive ?? true,
    lastExpandedAt: overrides.lastExpandedAt ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
}

function makeShift(overrides: Record<string, any> = {}) {
  return {
    shiftId: overrides.shiftId ?? SHIFT_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    locationId: overrides.locationId ?? LOCATION_ID,
    shiftStart: new Date(),
    shiftEnd: null,
    patientCount: 0,
    estimatedValue: '0',
    status: 'ACTIVE',
    createdAt: new Date(),
  };
}

function makeDeps(overrides: Partial<ShiftScheduleServiceDeps> = {}): ShiftScheduleServiceDeps {
  return {
    scheduleRepo: {
      create: vi.fn().mockResolvedValue(makeSchedule()),
      getById: vi.fn().mockResolvedValue(makeSchedule()),
      update: vi.fn().mockResolvedValue(makeSchedule()),
      delete: vi.fn().mockResolvedValue(makeSchedule({ isActive: false })),
      list: vi.fn().mockResolvedValue([makeSchedule()]),
      updateLastExpanded: vi.fn().mockResolvedValue(undefined),
    } as any,
    shiftRepo: {
      create: vi.fn().mockResolvedValue(makeShift()),
      getActive: vi.fn().mockResolvedValue(null),
      getById: vi.fn(),
      endShift: vi.fn(),
      markReviewed: vi.fn(),
      list: vi.fn(),
      incrementPatientCount: vi.fn(),
      getSummary: vi.fn(),
    } as any,
    locationCheck: {
      belongsToPhysician: vi.fn().mockResolvedValue(true),
    },
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ShiftScheduleService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // createSchedule
  // =========================================================================

  describe('createSchedule', () => {
    it('should create a schedule when location is valid', async () => {
      const deps = makeDeps();
      const result = await createSchedule(deps, PROVIDER_A, {
        locationId: LOCATION_ID,
        name: 'Monday ED',
        rrule: 'FREQ=WEEKLY;BYDAY=MO',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      expect(result.scheduleId).toBe(SCHEDULE_ID);
      expect(deps.scheduleRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PROVIDER_A,
          name: 'Monday ED',
        }),
      );
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'mobile.schedule_created' }),
      );
    });

    it('should throw NotFoundError when location does not belong to provider', async () => {
      const deps = makeDeps({
        locationCheck: { belongsToPhysician: vi.fn().mockResolvedValue(false) },
      });

      await expect(
        createSchedule(deps, PROVIDER_A, {
          locationId: LOCATION_ID,
          name: 'Monday ED',
          rrule: 'FREQ=WEEKLY;BYDAY=MO',
          shiftStartTime: '08:00',
          shiftDurationMinutes: 480,
        }),
      ).rejects.toThrow(NotFoundError);
    });
  });

  // =========================================================================
  // updateSchedule
  // =========================================================================

  describe('updateSchedule', () => {
    it('should update and return the schedule', async () => {
      const deps = makeDeps();
      const result = await updateSchedule(deps, PROVIDER_A, SCHEDULE_ID, {
        name: 'Updated Name',
      });

      expect(result.scheduleId).toBe(SCHEDULE_ID);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'mobile.schedule_updated' }),
      );
    });

    it('should throw NotFoundError when schedule not found', async () => {
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          update: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        updateSchedule(deps, PROVIDER_A, 'non-existent', { name: 'X' }),
      ).rejects.toThrow(NotFoundError);
    });
  });

  // =========================================================================
  // deleteSchedule
  // =========================================================================

  describe('deleteSchedule', () => {
    it('should soft-delete the schedule', async () => {
      const deps = makeDeps();
      const result = await deleteSchedule(deps, PROVIDER_A, SCHEDULE_ID);

      expect(result.isActive).toBe(false);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'mobile.schedule_deleted' }),
      );
    });

    it('should throw NotFoundError when schedule not found', async () => {
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          delete: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        deleteSchedule(deps, PROVIDER_A, 'non-existent'),
      ).rejects.toThrow(NotFoundError);
    });
  });

  // =========================================================================
  // getSchedule
  // =========================================================================

  describe('getSchedule', () => {
    it('should return the schedule', async () => {
      const deps = makeDeps();
      const result = await getSchedule(deps, PROVIDER_A, SCHEDULE_ID);
      expect(result.scheduleId).toBe(SCHEDULE_ID);
    });

    it('should throw NotFoundError when not found', async () => {
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          getById: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        getSchedule(deps, PROVIDER_A, 'non-existent'),
      ).rejects.toThrow(NotFoundError);
    });
  });

  // =========================================================================
  // listSchedules
  // =========================================================================

  describe('listSchedules', () => {
    it('should return all schedules for provider', async () => {
      const deps = makeDeps();
      const result = await listSchedules(deps, PROVIDER_A);
      expect(result).toHaveLength(1);
    });

    it('should pass activeOnly filter', async () => {
      const deps = makeDeps();
      await listSchedules(deps, PROVIDER_A, true);
      expect(deps.scheduleRepo.list).toHaveBeenCalledWith(PROVIDER_A, true);
    });
  });

  // =========================================================================
  // getCalendarInstances
  // =========================================================================

  describe('getCalendarInstances', () => {
    it('should expand RRULE for all active schedules', async () => {
      const mockInstances = [
        { start: new Date(2026, 1, 16, 8, 0), end: new Date(2026, 1, 16, 16, 0), date: '2026-02-16' },
        { start: new Date(2026, 1, 23, 8, 0), end: new Date(2026, 1, 23, 16, 0), date: '2026-02-23' },
      ];
      vi.mocked(expandRrule).mockReturnValue(mockInstances);

      const deps = makeDeps();
      const from = new Date(2026, 1, 16);
      const to = new Date(2026, 2, 1);
      const result = await getCalendarInstances(deps, PROVIDER_A, from, to);

      expect(result).toHaveLength(2);
      expect(result[0].scheduleId).toBe(SCHEDULE_ID);
      expect(result[0].scheduleName).toBe('Monday ED');
      expect(expandRrule).toHaveBeenCalledWith(
        'FREQ=WEEKLY;BYDAY=MO',
        '08:00',
        480,
        from,
        to,
      );
    });

    it('should sort instances by start time', async () => {
      const schedule2 = makeSchedule({
        scheduleId: crypto.randomUUID(),
        name: 'Wednesday',
        rrule: 'FREQ=WEEKLY;BYDAY=WE',
      });
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          list: vi.fn().mockResolvedValue([makeSchedule(), schedule2]),
        } as any,
      });

      const earlyInstance = { start: new Date(2026, 1, 16, 8), end: new Date(2026, 1, 16, 16), date: '2026-02-16' };
      const lateInstance = { start: new Date(2026, 1, 18, 8), end: new Date(2026, 1, 18, 16), date: '2026-02-18' };

      vi.mocked(expandRrule)
        .mockReturnValueOnce([lateInstance])
        .mockReturnValueOnce([earlyInstance]);

      const result = await getCalendarInstances(deps, PROVIDER_A, new Date(2026, 1, 16), new Date(2026, 1, 19));

      expect(result[0].date).toBe('2026-02-16');
      expect(result[1].date).toBe('2026-02-18');
    });

    it('should return empty array when no active schedules', async () => {
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          list: vi.fn().mockResolvedValue([]),
        } as any,
      });

      const result = await getCalendarInstances(
        deps,
        PROVIDER_A,
        new Date(),
        new Date(),
      );
      expect(result).toHaveLength(0);
    });
  });

  // =========================================================================
  // createInferredShift
  // =========================================================================

  describe('createInferredShift', () => {
    it('should create an inferred shift from schedule', async () => {
      const deps = makeDeps();
      const result = await createInferredShift(deps, PROVIDER_A, SCHEDULE_ID);

      expect(result.shiftId).toBe(SHIFT_ID);
      expect(deps.shiftRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PROVIDER_A,
          locationId: LOCATION_ID,
        }),
      );
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'mobile.inferred_shift_created' }),
      );
    });

    it('should throw NotFoundError when schedule not found', async () => {
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          getById: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        createInferredShift(deps, PROVIDER_A, 'non-existent'),
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw BusinessRuleError when schedule is inactive', async () => {
      const deps = makeDeps({
        scheduleRepo: {
          ...makeDeps().scheduleRepo,
          getById: vi.fn().mockResolvedValue(makeSchedule({ isActive: false })),
        } as any,
      });

      await expect(
        createInferredShift(deps, PROVIDER_A, SCHEDULE_ID),
      ).rejects.toThrow(BusinessRuleError);
    });

    it('should throw BusinessRuleError when active shift already exists', async () => {
      const deps = makeDeps({
        shiftRepo: {
          ...makeDeps().shiftRepo,
          getActive: vi.fn().mockResolvedValue(makeShift()),
        } as any,
      });

      await expect(
        createInferredShift(deps, PROVIDER_A, SCHEDULE_ID),
      ).rejects.toThrow(BusinessRuleError);
    });
  });
});
