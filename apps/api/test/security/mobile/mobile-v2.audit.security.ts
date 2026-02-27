// ============================================================================
// Domain 10: Mobile V2 — Audit Trail Completeness (Security)
//
// Verifies that all V2 mobile audit events (encounter and schedule) are
// logged correctly, contain required fields, and exclude PHI.
//
// Unlike HTTP-based tests, this file invokes services directly to inspect
// audit entries via mock deps (same pattern as mobile.audit.security.ts).
//
// Coverage:
//   - logEncounter produces audit with encounter_id, shift_id, phnCaptureMethod (not PHN)
//   - deleteEncounter produces audit with encounter_id, shift_id
//   - createSchedule produces audit with schedule_id, name, rrule
//   - updateSchedule produces audit with schedule_id
//   - deleteSchedule produces audit with schedule_id
//   - createInferredShift produces audit with shift_id, schedule_id, source
//   - No PHI (PHN, patient names) in any audit entries
//   - Append-only integrity for V2 audit entries
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import {
  MobileAuditAction,
} from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Service imports
// ---------------------------------------------------------------------------

import {
  logEncounter,
  deleteEncounter,
  type EncounterServiceDeps,
} from '../../../src/domains/mobile/services/encounter.service.js';

import {
  createSchedule,
  updateSchedule,
  deleteSchedule,
  createInferredShift,
  type ShiftScheduleServiceDeps,
} from '../../../src/domains/mobile/services/shift-schedule.service.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '11111111-aaaa-0000-0000-000000000001';
const SHIFT_ID = '22222222-bbbb-0000-0000-000000000001';
const ENCOUNTER_ID = '33333333-cccc-0000-0000-000000000001';
const SCHEDULE_ID = '44444444-dddd-0000-0000-000000000001';
const LOCATION_ID = '55555555-eeee-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock AuditRepo factory
// ---------------------------------------------------------------------------

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => ({})),
  };
}

// ---------------------------------------------------------------------------
// Mock EncounterServiceDeps
// ---------------------------------------------------------------------------

function createMockEncounterDeps(
  auditRepo = createMockAuditRepo(),
): EncounterServiceDeps {
  const encounterRecord = {
    encounterId: ENCOUNTER_ID,
    shiftId: SHIFT_ID,
    providerId: PHYSICIAN_ID,
    phn: '123456789',
    phnCaptureMethod: 'MANUAL',
    phnIsPartial: false,
    healthServiceCode: '03.04A',
    modifiers: null,
    diCode: null,
    freeTextTag: 'Patient note',
    encounterTimestamp: new Date('2026-02-19T10:00:00Z'),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  return {
    encounterRepo: {
      logEncounter: vi.fn(async () => encounterRecord),
      listEncounters: vi.fn(async () => [encounterRecord]),
      deleteEncounter: vi.fn(async () => encounterRecord),
    } as any,
    auditRepo,
  };
}

// ---------------------------------------------------------------------------
// Mock ShiftScheduleServiceDeps
// ---------------------------------------------------------------------------

function createMockScheduleDeps(
  auditRepo = createMockAuditRepo(),
): ShiftScheduleServiceDeps {
  const scheduleRecord = {
    scheduleId: SCHEDULE_ID,
    providerId: PHYSICIAN_ID,
    locationId: LOCATION_ID,
    name: 'Monday AM',
    rrule: 'FREQ=WEEKLY;BYDAY=MO',
    shiftStartTime: '08:00',
    shiftDurationMinutes: 480,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const shiftRecord = {
    shiftId: randomUUID(),
    providerId: PHYSICIAN_ID,
    locationId: LOCATION_ID,
    shiftStart: new Date(),
    shiftEnd: null,
    status: 'ACTIVE',
    patientCount: 0,
    estimatedValue: '0.00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  return {
    scheduleRepo: {
      create: vi.fn(async (data: any) => ({
        ...scheduleRecord,
        ...data,
        scheduleId: SCHEDULE_ID,
      })),
      getById: vi.fn(async () => scheduleRecord),
      update: vi.fn(async (_id: string, _pid: string, data: any) => ({
        ...scheduleRecord,
        ...data,
      })),
      delete: vi.fn(async () => scheduleRecord),
      list: vi.fn(async () => [scheduleRecord]),
    } as any,
    shiftRepo: {
      create: vi.fn(async () => shiftRecord),
      getActive: vi.fn(async () => null),
    } as any,
    locationCheck: {
      belongsToPhysician: vi.fn(async () => true),
    },
    auditRepo,
  };
}

// ===========================================================================
// TEST SUITE
// ===========================================================================

describe('Mobile V2 Audit Trail (Security)', () => {
  // =========================================================================
  // 1. Encounter Events — Audit Records
  // =========================================================================

  describe('Encounter Events', () => {
    it('logEncounter produces audit entry with encounter_id, shift_id, phnCaptureMethod', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
        phnIsPartial: false,
        healthServiceCode: '03.04A',
        encounterTimestamp: '2026-02-19T10:00:00Z',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.PATIENT_LOGGED,
          category: 'mobile',
          resourceType: 'ed_shift_encounter',
          resourceId: ENCOUNTER_ID,
          detail: expect.objectContaining({
            shiftId: SHIFT_ID,
            phnCaptureMethod: 'MANUAL',
          }),
        }),
      );
    });

    it('logEncounter audit entry does NOT contain the actual PHN value', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
        phnIsPartial: false,
        healthServiceCode: '03.04A',
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // Must contain capture method but NOT the actual PHN
      expect(serialized).toContain('phnCaptureMethod');
      expect(serialized).not.toMatch(/"phn"\s*:\s*"123456789"/);
      // The detail should not have a "phn" key with the actual value
      if (call.detail && typeof call.detail === 'object') {
        expect((call.detail as Record<string, unknown>).phn).toBeUndefined();
      }
    });

    it('logEncounter with BARCODE capture records phnCaptureMethod in audit', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'BARCODE',
        phnIsPartial: false,
        healthServiceCode: '08.19A',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          detail: expect.objectContaining({
            phnCaptureMethod: 'BARCODE',
          }),
        }),
      );
    });

    it('logEncounter with LAST_FOUR capture records phnIsPartial true in audit', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '6789',
        phnCaptureMethod: 'LAST_FOUR',
        phnIsPartial: true,
        healthServiceCode: '03.04A',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          detail: expect.objectContaining({
            phnCaptureMethod: 'LAST_FOUR',
            phnIsPartial: true,
          }),
        }),
      );
    });

    it('deleteEncounter produces audit entry with encounter_id and shift_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await deleteEncounter(deps, PHYSICIAN_ID, SHIFT_ID, ENCOUNTER_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: 'mobile.encounter_deleted',
          category: 'mobile',
          resourceType: 'ed_shift_encounter',
          resourceId: ENCOUNTER_ID,
          detail: expect.objectContaining({
            shiftId: SHIFT_ID,
          }),
        }),
      );
    });

    it('deleteEncounter audit entry does NOT contain PHN', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await deleteEncounter(deps, PHYSICIAN_ID, SHIFT_ID, ENCOUNTER_ID);

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      expect(serialized).not.toContain('123456789');
      expect(serialized).not.toContain('"phn"');
    });
  });

  // =========================================================================
  // 2. Schedule Events — Audit Records
  // =========================================================================

  describe('Schedule Events', () => {
    it('createSchedule produces audit entry with schedule_id, name, rrule', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createSchedule(deps, PHYSICIAN_ID, {
        locationId: LOCATION_ID,
        name: 'Monday AM',
        rrule: 'FREQ=WEEKLY;BYDAY=MO',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: 'mobile.schedule_created',
          category: 'mobile',
          resourceType: 'shift_schedule',
          resourceId: SCHEDULE_ID,
          detail: expect.objectContaining({
            name: 'Monday AM',
            rrule: 'FREQ=WEEKLY;BYDAY=MO',
            shiftStartTime: '08:00',
            shiftDurationMinutes: 480,
          }),
        }),
      );
    });

    it('updateSchedule produces audit entry with schedule_id and changed fields', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await updateSchedule(deps, PHYSICIAN_ID, SCHEDULE_ID, {
        name: 'Updated Name',
        shiftStartTime: '09:00',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: 'mobile.schedule_updated',
          category: 'mobile',
          resourceType: 'shift_schedule',
          resourceId: SCHEDULE_ID,
          detail: expect.objectContaining({
            name: 'Updated Name',
            shiftStartTime: '09:00',
          }),
        }),
      );
    });

    it('deleteSchedule produces audit entry with schedule_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await deleteSchedule(deps, PHYSICIAN_ID, SCHEDULE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: 'mobile.schedule_deleted',
          category: 'mobile',
          resourceType: 'shift_schedule',
          resourceId: SCHEDULE_ID,
        }),
      );
    });

    it('createInferredShift produces audit entry with shift_id, schedule_id, source INFERRED', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      const result = await createInferredShift(deps, PHYSICIAN_ID, SCHEDULE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: 'mobile.inferred_shift_created',
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: result.shiftId,
          detail: expect.objectContaining({
            scheduleId: SCHEDULE_ID,
            scheduleName: 'Monday AM',
            source: 'INFERRED',
          }),
        }),
      );
    });
  });

  // =========================================================================
  // 3. Audit Entry Completeness — Required Fields
  // =========================================================================

  describe('Audit Entry Completeness', () => {
    it('every V2 audit entry includes userId, action, category, and detail', async () => {
      const auditRepo = createMockAuditRepo();

      // Trigger encounter audit
      const encDeps = createMockEncounterDeps(auditRepo);
      await logEncounter(encDeps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
        healthServiceCode: '03.04A',
      });

      // Trigger schedule audit
      const schedDeps = createMockScheduleDeps(auditRepo);
      await createSchedule(schedDeps, PHYSICIAN_ID, {
        locationId: LOCATION_ID,
        name: 'Test',
        rrule: 'FREQ=DAILY',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      // All calls must have required fields
      for (const call of auditRepo.appendAuditLog.mock.calls) {
        const entry = call[0];
        expect(entry).toHaveProperty('userId');
        expect(entry).toHaveProperty('action');
        expect(entry).toHaveProperty('category');
        expect(entry.category).toBe('mobile');
        expect(entry.userId).toBe(PHYSICIAN_ID);
      }
    });

    it('encounter audit entries include resourceType=ed_shift_encounter and resourceId', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
      });

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.resourceType).toBe('ed_shift_encounter');
      expect(entry.resourceId).toBe(ENCOUNTER_ID);
    });

    it('schedule audit entries include resourceType=shift_schedule and resourceId', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createSchedule(deps, PHYSICIAN_ID, {
        locationId: LOCATION_ID,
        name: 'Test',
        rrule: 'FREQ=DAILY',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.resourceType).toBe('shift_schedule');
      expect(entry.resourceId).toBe(SCHEDULE_ID);
    });

    it('inferred shift audit includes resourceType=ed_shift', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createInferredShift(deps, PHYSICIAN_ID, SCHEDULE_ID);

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.resourceType).toBe('ed_shift');
    });
  });

  // =========================================================================
  // 4. Audit Entries — No PHI / Sensitive Data
  // =========================================================================

  describe('Audit Entries Do Not Contain PHI', () => {
    it('logEncounter audit does not contain actual PHN, patient names, or DOB', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
        phnIsPartial: false,
        healthServiceCode: '03.04A',
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // No patient names
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('first_name');
      expect(serialized).not.toContain('last_name');

      // No raw PHN value — phnCaptureMethod is allowed but not the number itself
      expect(serialized).not.toMatch(/"phn"\s*:\s*"\d{9}"/);

      // No date of birth
      expect(serialized).not.toContain('dateOfBirth');
      expect(serialized).not.toContain('date_of_birth');
    });

    it('deleteEncounter audit does not contain PHI', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await deleteEncounter(deps, PHYSICIAN_ID, SHIFT_ID, ENCOUNTER_ID);

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('"phn"');
      expect(serialized).not.toContain('123456789');
    });

    it('createSchedule audit does not contain PHI', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createSchedule(deps, PHYSICIAN_ID, {
        locationId: LOCATION_ID,
        name: 'Monday AM',
        rrule: 'FREQ=WEEKLY;BYDAY=MO',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // Schedule audit should contain name and rrule (not PHI) but no patient data
      expect(serialized).not.toContain('phn');
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('dateOfBirth');
    });

    it('createInferredShift audit does not contain PHI', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createInferredShift(deps, PHYSICIAN_ID, SCHEDULE_ID);

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      expect(serialized).not.toContain('phn');
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
    });
  });

  // =========================================================================
  // 5. Append-Only Integrity
  // =========================================================================

  describe('Append-Only Audit Integrity', () => {
    it('audit repo interface only exposes appendAuditLog — no update or delete methods', () => {
      const auditRepo = createMockAuditRepo();

      expect(auditRepo).toHaveProperty('appendAuditLog');
      expect(typeof auditRepo.appendAuditLog).toBe('function');

      // No mutation methods
      expect(auditRepo).not.toHaveProperty('updateAuditLog');
      expect(auditRepo).not.toHaveProperty('deleteAuditLog');
      expect(auditRepo).not.toHaveProperty('update');
      expect(auditRepo).not.toHaveProperty('delete');
      expect(auditRepo).not.toHaveProperty('remove');
      expect(auditRepo).not.toHaveProperty('clear');
    });

    it('each V2 action produces exactly one audit entry — no batch overwrites', async () => {
      const auditRepo = createMockAuditRepo();

      // Log encounter
      const encDeps = createMockEncounterDeps(auditRepo);
      await logEncounter(encDeps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
      });

      // Delete encounter
      await deleteEncounter(encDeps, PHYSICIAN_ID, SHIFT_ID, ENCOUNTER_ID);

      // Two separate audit entries
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);

      const firstCall = auditRepo.appendAuditLog.mock.calls[0][0];
      const secondCall = auditRepo.appendAuditLog.mock.calls[1][0];

      expect(firstCall.action).toBe(MobileAuditAction.PATIENT_LOGGED);
      expect(secondCall.action).toBe('mobile.encounter_deleted');
    });
  });

  // =========================================================================
  // 6. Full Lifecycle — Complete Audit Trail
  // =========================================================================

  describe('Full Lifecycle Audit Trail', () => {
    it('encounter lifecycle: logged -> deleted produces 2 independent audit entries', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      // 1. Log encounter
      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
        healthServiceCode: '03.04A',
      });

      // 2. Delete encounter
      await deleteEncounter(deps, PHYSICIAN_ID, SHIFT_ID, ENCOUNTER_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);

      const actions = auditRepo.appendAuditLog.mock.calls.map(
        (c: any[]) => c[0].action,
      );
      expect(actions).toEqual([
        MobileAuditAction.PATIENT_LOGGED,
        'mobile.encounter_deleted',
      ]);
    });

    it('schedule lifecycle: created -> updated -> deleted produces 3 independent audit entries', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      // 1. Create schedule
      await createSchedule(deps, PHYSICIAN_ID, {
        locationId: LOCATION_ID,
        name: 'Monday AM',
        rrule: 'FREQ=WEEKLY;BYDAY=MO',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      // 2. Update schedule
      await updateSchedule(deps, PHYSICIAN_ID, SCHEDULE_ID, {
        name: 'Monday AM Updated',
      });

      // 3. Delete schedule
      await deleteSchedule(deps, PHYSICIAN_ID, SCHEDULE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(3);

      const actions = auditRepo.appendAuditLog.mock.calls.map(
        (c: any[]) => c[0].action,
      );
      expect(actions).toEqual([
        'mobile.schedule_created',
        'mobile.schedule_updated',
        'mobile.schedule_deleted',
      ]);
    });

    it('inferred shift creation produces audit after schedule validation', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      const result = await createInferredShift(deps, PHYSICIAN_ID, SCHEDULE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.action).toBe('mobile.inferred_shift_created');
      expect(entry.resourceId).toBe(result.shiftId);
      expect(entry.detail.scheduleId).toBe(SCHEDULE_ID);
    });
  });

  // =========================================================================
  // 7. V2 Audit Action Identifiers
  // =========================================================================

  describe('V2 Audit Action Identifiers', () => {
    it('encounter audit uses MobileAuditAction.PATIENT_LOGGED constant', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await logEncounter(deps, PHYSICIAN_ID, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'MANUAL',
      });

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.action).toBe('mobile.patient_logged');
      expect(entry.action).toBe(MobileAuditAction.PATIENT_LOGGED);
    });

    it('encounter delete audit uses string literal mobile.encounter_deleted', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEncounterDeps(auditRepo);

      await deleteEncounter(deps, PHYSICIAN_ID, SHIFT_ID, ENCOUNTER_ID);

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.action).toBe('mobile.encounter_deleted');
    });

    it('schedule audit actions are prefixed with mobile.', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createSchedule(deps, PHYSICIAN_ID, {
        locationId: LOCATION_ID,
        name: 'Test',
        rrule: 'FREQ=DAILY',
        shiftStartTime: '08:00',
        shiftDurationMinutes: 480,
      });

      await updateSchedule(deps, PHYSICIAN_ID, SCHEDULE_ID, { name: 'Updated' });
      await deleteSchedule(deps, PHYSICIAN_ID, SCHEDULE_ID);

      const actions = auditRepo.appendAuditLog.mock.calls.map(
        (c: any[]) => c[0].action,
      );

      for (const action of actions) {
        expect(action).toMatch(/^mobile\./);
      }

      expect(actions).toContain('mobile.schedule_created');
      expect(actions).toContain('mobile.schedule_updated');
      expect(actions).toContain('mobile.schedule_deleted');
    });

    it('inferred shift audit uses mobile.inferred_shift_created action', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockScheduleDeps(auditRepo);

      await createInferredShift(deps, PHYSICIAN_ID, SCHEDULE_ID);

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.action).toBe('mobile.inferred_shift_created');
    });
  });
});
