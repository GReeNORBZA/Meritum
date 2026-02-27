import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('drizzle-orm', () => ({
  eq: (col: any, val: any) => ({ type: 'eq', col, val }),
  and: (...args: any[]) => ({ type: 'and', args }),
  desc: (col: any) => ({ type: 'desc', col }),
}));

vi.mock('@meritum/shared/schemas/db/mobile.schema.js', () => {
  const cols = {
    scheduleId: 'scheduleId',
    providerId: 'providerId',
    locationId: 'locationId',
    name: 'name',
    rrule: 'rrule',
    shiftStartTime: 'shiftStartTime',
    shiftDurationMinutes: 'shiftDurationMinutes',
    isActive: 'isActive',
    lastExpandedAt: 'lastExpandedAt',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
  };
  return {
    shiftSchedules: cols,
  };
});

import { createShiftSchedulesRepository } from './shift-schedules.repo.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();
const SCHEDULE_ID = crypto.randomUUID();

function makeSchedule(overrides: Record<string, any> = {}) {
  return {
    scheduleId: overrides.scheduleId ?? SCHEDULE_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    locationId: overrides.locationId ?? LOCATION_ID,
    name: overrides.name ?? 'Monday ED Shift',
    rrule: overrides.rrule ?? 'FREQ=WEEKLY;BYDAY=MO',
    shiftStartTime: overrides.shiftStartTime ?? '08:00',
    shiftDurationMinutes: overrides.shiftDurationMinutes ?? 480,
    isActive: overrides.isActive ?? true,
    lastExpandedAt: overrides.lastExpandedAt ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
}

function makeDb(returnRows: any[] = [makeSchedule()]) {
  const mockChain = {
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue(returnRows),
    set: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue(returnRows),
    orderBy: vi.fn().mockResolvedValue(returnRows),
  };

  return {
    insert: vi.fn().mockReturnValue(mockChain),
    select: vi.fn().mockReturnValue(mockChain),
    update: vi.fn().mockReturnValue(mockChain),
    delete: vi.fn().mockReturnValue(mockChain),
    _chain: mockChain,
  } as any;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ShiftSchedulesRepository', () => {
  describe('create', () => {
    it('should insert a new schedule and return it', async () => {
      const expected = makeSchedule();
      const db = makeDb([expected]);
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        name: 'Monday ED Shift',
        rrule: 'FREQ=WEEKLY;BYDAY=MO',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      expect(result).toEqual(expected);
      expect(db.insert).toHaveBeenCalled();
      expect(db._chain.values).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PROVIDER_A,
          locationId: LOCATION_ID,
          name: 'Monday ED Shift',
          rrule: 'FREQ=WEEKLY;BYDAY=MO',
          shiftStartTime: '08:00',
          shiftDurationMinutes: 480,
          isActive: true,
        }),
      );
    });
  });

  describe('getById', () => {
    it('should return schedule for correct provider', async () => {
      const expected = makeSchedule();
      const db = makeDb([expected]);
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.getById(SCHEDULE_ID, PROVIDER_A);
      expect(result).toEqual(expected);
    });

    it('should return null when no rows', async () => {
      const db = makeDb([]);
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.getById(SCHEDULE_ID, PROVIDER_B);
      expect(result).toBeNull();
    });
  });

  describe('update', () => {
    it('should update schedule and return updated row', async () => {
      const updated = makeSchedule({ name: 'Updated Name' });
      const db = makeDb([updated]);
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.update(SCHEDULE_ID, PROVIDER_A, {
        name: 'Updated Name',
      });

      expect(result).toEqual(updated);
      expect(db.update).toHaveBeenCalled();
    });

    it('should return null when schedule not found', async () => {
      const db = makeDb([]);
      db.update = vi.fn().mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([]),
          }),
        }),
      });
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.update(SCHEDULE_ID, PROVIDER_B, { name: 'X' });
      expect(result).toBeNull();
    });
  });

  describe('delete (soft)', () => {
    it('should deactivate schedule', async () => {
      const deactivated = makeSchedule({ isActive: false });
      const db = makeDb([deactivated]);
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.delete(SCHEDULE_ID, PROVIDER_A);

      expect(result).toEqual(deactivated);
      expect(result!.isActive).toBe(false);
    });

    it('should return null for non-existent schedule', async () => {
      const db = makeDb([]);
      db.update = vi.fn().mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([]),
          }),
        }),
      });
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.delete('non-existent', PROVIDER_A);
      expect(result).toBeNull();
    });
  });

  describe('list', () => {
    it('should return all schedules for a provider', async () => {
      const schedules = [makeSchedule(), makeSchedule({ scheduleId: crypto.randomUUID() })];
      const db = makeDb(schedules);
      const repo = createShiftSchedulesRepository(db);

      const result = await repo.list(PROVIDER_A);
      expect(result).toHaveLength(2);
    });

    it('should filter active-only when requested', async () => {
      const db = makeDb([makeSchedule()]);
      const repo = createShiftSchedulesRepository(db);

      await repo.list(PROVIDER_A, true);
      // Verify it was called — the mock chain applies
      expect(db.select).toHaveBeenCalled();
    });
  });

  describe('updateLastExpanded', () => {
    it('should update lastExpandedAt timestamp', async () => {
      const db = makeDb([]);
      db.update = vi.fn().mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue(undefined),
        }),
      });
      const repo = createShiftSchedulesRepository(db);

      await repo.updateLastExpanded(SCHEDULE_ID, PROVIDER_A);
      expect(db.update).toHaveBeenCalled();
    });
  });
});
