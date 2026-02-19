import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  startShift,
  getActiveShift,
  logPatient,
  endShift,
  getShiftSummary,
  listShifts,
  detectAfterHoursBracket,
  getAlbertaStatutoryHolidays,
} from './ed-shift.service.js';
import type { EdShiftServiceDeps } from './ed-shift.service.js';
import { ConflictError, NotFoundError, BusinessRuleError } from '../../../lib/errors.js';
import { AfterHoursBracket } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();
const PATIENT_ID = crypto.randomUUID();
const CLAIM_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeShift(overrides: Record<string, any> = {}) {
  return {
    shiftId: overrides.shiftId ?? SHIFT_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    locationId: overrides.locationId ?? LOCATION_ID,
    shiftStart: overrides.shiftStart ?? new Date('2026-02-19T08:00:00Z'),
    shiftEnd: overrides.shiftEnd ?? null,
    patientCount: overrides.patientCount ?? 0,
    estimatedValue: overrides.estimatedValue ?? '0',
    status: overrides.status ?? 'ACTIVE',
    createdAt: overrides.createdAt ?? new Date('2026-02-19T08:00:00Z'),
  };
}

function makeSummary(overrides: Record<string, any> = {}) {
  return {
    ...makeShift(overrides),
    claims: overrides.claims ?? [],
  };
}

function makeDeps(overrides: Partial<EdShiftServiceDeps> = {}): EdShiftServiceDeps {
  return {
    repo: {
      create: vi.fn().mockResolvedValue(makeShift()),
      getActive: vi.fn().mockResolvedValue(null),
      getById: vi.fn().mockResolvedValue(makeShift()),
      endShift: vi.fn().mockResolvedValue(makeShift({ status: 'ENDED', shiftEnd: new Date() })),
      markReviewed: vi.fn().mockResolvedValue(makeShift({ status: 'REVIEWED' })),
      list: vi.fn().mockResolvedValue({ data: [makeShift()], total: 1 }),
      incrementPatientCount: vi.fn().mockResolvedValue(makeShift({ patientCount: 1 })),
      getSummary: vi.fn().mockResolvedValue(makeSummary()),
    } as any,
    locationCheck: {
      belongsToPhysician: vi.fn().mockResolvedValue(true),
    },
    claimCreator: {
      createClaimFromShift: vi.fn().mockResolvedValue({ claimId: CLAIM_ID }),
    },
    hscEligibility: {
      isEligibleForModifier: vi.fn().mockResolvedValue(true),
    },
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests: startShift
// ---------------------------------------------------------------------------

describe('EdShiftService', () => {
  describe('startShift', () => {
    it('creates a new shift when location is valid and no active shift exists', async () => {
      const deps = makeDeps();

      const result = await startShift(deps, PROVIDER_A, LOCATION_ID);

      expect(result).toBeDefined();
      expect(result.shiftId).toBe(SHIFT_ID);
      expect(result.status).toBe('ACTIVE');
      expect(deps.locationCheck.belongsToPhysician).toHaveBeenCalledWith(
        LOCATION_ID,
        PROVIDER_A,
      );
      expect(deps.repo.getActive).toHaveBeenCalledWith(PROVIDER_A);
      expect(deps.repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PROVIDER_A,
          locationId: LOCATION_ID,
        }),
      );
    });

    it('throws NotFoundError when location does not belong to physician', async () => {
      const deps = makeDeps({
        locationCheck: {
          belongsToPhysician: vi.fn().mockResolvedValue(false),
        },
      });

      await expect(
        startShift(deps, PROVIDER_A, LOCATION_ID),
      ).rejects.toThrow(NotFoundError);

      expect(deps.repo.create).not.toHaveBeenCalled();
    });

    it('throws ConflictError when physician already has an active shift', async () => {
      const deps = makeDeps();
      (deps.repo.getActive as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeShift(),
      );

      await expect(
        startShift(deps, PROVIDER_A, LOCATION_ID),
      ).rejects.toThrow(ConflictError);

      expect(deps.repo.create).not.toHaveBeenCalled();
    });

    it('logs audit event on successful start', async () => {
      const deps = makeDeps();

      await startShift(deps, PROVIDER_A, LOCATION_ID);

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.shift_started',
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: SHIFT_ID,
          detail: expect.objectContaining({
            locationId: LOCATION_ID,
          }),
        }),
      );
    });

    it('does not log audit event when start fails', async () => {
      const deps = makeDeps({
        locationCheck: {
          belongsToPhysician: vi.fn().mockResolvedValue(false),
        },
      });

      await expect(
        startShift(deps, PROVIDER_A, LOCATION_ID),
      ).rejects.toThrow();

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // getActiveShift
  // =========================================================================

  describe('getActiveShift', () => {
    it('returns the active shift when one exists', async () => {
      const deps = makeDeps();
      (deps.repo.getActive as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeShift(),
      );

      const result = await getActiveShift(deps, PROVIDER_A);

      expect(result).toBeDefined();
      expect(result!.shiftId).toBe(SHIFT_ID);
      expect(result!.status).toBe('ACTIVE');
    });

    it('returns null when no active shift exists', async () => {
      const deps = makeDeps();

      const result = await getActiveShift(deps, PROVIDER_A);

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // logPatient
  // =========================================================================

  describe('logPatient', () => {
    it('creates a draft claim linked to the shift', async () => {
      const deps = makeDeps();

      const result = await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(result.claimId).toBe(CLAIM_ID);
      expect(deps.claimCreator.createClaimFromShift).toHaveBeenCalledWith(
        PROVIDER_A,
        PROVIDER_A,
        SHIFT_ID,
        expect.objectContaining({
          patientId: PATIENT_ID,
          claimType: 'AHCIP',
        }),
      );
    });

    it('uses today as default date_of_service', async () => {
      const deps = makeDeps();
      const today = new Date().toISOString().split('T')[0];

      await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(deps.claimCreator.createClaimFromShift).toHaveBeenCalledWith(
        PROVIDER_A,
        PROVIDER_A,
        SHIFT_ID,
        expect.objectContaining({
          dateOfService: today,
        }),
      );
    });

    it('uses provided date_of_service when supplied', async () => {
      const deps = makeDeps();

      await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-18',
      });

      expect(deps.claimCreator.createClaimFromShift).toHaveBeenCalledWith(
        PROVIDER_A,
        PROVIDER_A,
        SHIFT_ID,
        expect.objectContaining({
          dateOfService: '2026-02-18',
        }),
      );
    });

    it('throws NotFoundError when shift does not exist', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        logPatient(deps, PROVIDER_A, SHIFT_ID, {
          patientId: PATIENT_ID,
          healthServiceCode: '03.04A',
        }),
      ).rejects.toThrow(NotFoundError);

      expect(deps.claimCreator.createClaimFromShift).not.toHaveBeenCalled();
    });

    it('throws BusinessRuleError when shift is not active', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeShift({ status: 'ENDED' }),
      );

      await expect(
        logPatient(deps, PROVIDER_A, SHIFT_ID, {
          patientId: PATIENT_ID,
          healthServiceCode: '03.04A',
        }),
      ).rejects.toThrow(BusinessRuleError);

      expect(deps.claimCreator.createClaimFromShift).not.toHaveBeenCalled();
    });

    it('increments shift patient count after logging', async () => {
      const deps = makeDeps();

      await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(deps.repo.incrementPatientCount).toHaveBeenCalledWith(
        SHIFT_ID,
        PROVIDER_A,
        '0',
      );
    });

    it('returns after-hours result with modifier and eligibility', async () => {
      const deps = makeDeps();

      const result = await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(result.afterHours).toBeDefined();
      expect(result.afterHours).toHaveProperty('modifier');
      expect(result.afterHours).toHaveProperty('eligible');
    });

    it('checks HSC eligibility for detected modifier', async () => {
      const deps = makeDeps();
      // The modifier detected depends on test runtime; we just verify the
      // eligibility check is called when a modifier is detected
      const { modifier } = detectAfterHoursBracket(new Date());

      await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      if (modifier) {
        expect(deps.hscEligibility!.isEligibleForModifier).toHaveBeenCalledWith(
          '03.04A',
          modifier,
        );
      }
    });

    it('logs audit event with claim and after-hours details', async () => {
      const deps = makeDeps();

      await logPatient(deps, PROVIDER_A, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.patient_logged',
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: SHIFT_ID,
          detail: expect.objectContaining({
            claimId: CLAIM_ID,
            patientId: PATIENT_ID,
            healthServiceCode: '03.04A',
          }),
        }),
      );
    });
  });

  // =========================================================================
  // endShift
  // =========================================================================

  describe('endShift', () => {
    it('ends an active shift and returns summary', async () => {
      const deps = makeDeps();
      const endedShift = makeShift({
        status: 'ENDED',
        shiftEnd: new Date(),
        patientCount: 3,
        estimatedValue: '150.00',
      });
      (deps.repo.endShift as ReturnType<typeof vi.fn>).mockResolvedValue(endedShift);
      const summary = makeSummary({
        status: 'ENDED',
        patientCount: 3,
        estimatedValue: '150.00',
        claims: [
          {
            claimId: CLAIM_ID,
            patientFirstName: 'Jane',
            patientLastName: 'Smith',
            healthServiceCode: '03.04A',
            fee: '50.00',
          },
        ],
      });
      (deps.repo.getSummary as ReturnType<typeof vi.fn>).mockResolvedValue(summary);

      const result = await endShift(deps, PROVIDER_A, SHIFT_ID);

      expect(result.shift.status).toBe('ENDED');
      expect(result.shift.patientCount).toBe(3);
      expect(result.shift.estimatedValue).toBe('150.00');
      expect(result.summary.claims).toHaveLength(1);
    });

    it('throws NotFoundError when shift does not exist', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        endShift(deps, PROVIDER_A, SHIFT_ID),
      ).rejects.toThrow(NotFoundError);

      expect(deps.repo.endShift).not.toHaveBeenCalled();
    });

    it('throws BusinessRuleError when shift is not active', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeShift({ status: 'ENDED' }),
      );

      await expect(
        endShift(deps, PROVIDER_A, SHIFT_ID),
      ).rejects.toThrow(BusinessRuleError);

      expect(deps.repo.endShift).not.toHaveBeenCalled();
    });

    it('logs audit event with shift end details', async () => {
      const deps = makeDeps();
      const endedShift = makeShift({
        status: 'ENDED',
        shiftEnd: new Date('2026-02-19T16:00:00Z'),
        patientCount: 5,
        estimatedValue: '275.00',
      });
      (deps.repo.endShift as ReturnType<typeof vi.fn>).mockResolvedValue(endedShift);

      await endShift(deps, PROVIDER_A, SHIFT_ID);

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.shift_ended',
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: SHIFT_ID,
          detail: expect.objectContaining({
            patientCount: 5,
            estimatedValue: '275.00',
          }),
        }),
      );
    });

    it('does not log audit event when end fails', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        endShift(deps, PROVIDER_A, SHIFT_ID),
      ).rejects.toThrow();

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // getShiftSummary
  // =========================================================================

  describe('getShiftSummary', () => {
    it('returns the shift summary with linked claims', async () => {
      const deps = makeDeps();
      const summary = makeSummary({
        claims: [
          {
            claimId: CLAIM_ID,
            patientFirstName: 'Jane',
            patientLastName: 'Smith',
            healthServiceCode: '03.04A',
            fee: '38.50',
          },
        ],
      });
      (deps.repo.getSummary as ReturnType<typeof vi.fn>).mockResolvedValue(summary);

      const result = await getShiftSummary(deps, PROVIDER_A, SHIFT_ID);

      expect(result.shiftId).toBe(SHIFT_ID);
      expect(result.claims).toHaveLength(1);
      expect(result.claims[0].patientFirstName).toBe('Jane');
    });

    it('throws NotFoundError when shift does not exist', async () => {
      const deps = makeDeps();
      (deps.repo.getSummary as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        getShiftSummary(deps, PROVIDER_A, SHIFT_ID),
      ).rejects.toThrow(NotFoundError);
    });
  });

  // =========================================================================
  // listShifts
  // =========================================================================

  describe('listShifts', () => {
    it('returns shifts for the provider', async () => {
      const deps = makeDeps();

      const result = await listShifts(deps, PROVIDER_A);

      expect(result.data).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(deps.repo.list).toHaveBeenCalledWith(PROVIDER_A, undefined);
    });

    it('passes filters to repository', async () => {
      const deps = makeDeps();
      const filters = { status: 'ENDED', limit: 5 };

      await listShifts(deps, PROVIDER_A, filters);

      expect(deps.repo.list).toHaveBeenCalledWith(PROVIDER_A, filters);
    });
  });

  // =========================================================================
  // detectAfterHoursBracket (pure function)
  // =========================================================================

  describe('detectAfterHoursBracket', () => {
    // Use a fixed timezone for deterministic tests
    const tz = 'America/Edmonton';

    describe('weekday standard hours (08:00–16:59)', () => {
      it('returns null modifier for 10:00 on a Wednesday', () => {
        // Feb 18, 2026 is a Wednesday
        // 10:00 MST = 17:00 UTC (MST = UTC-7)
        const timestamp = new Date('2026-02-18T17:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBeNull();
      });

      it('returns null modifier for 08:00 on a Monday', () => {
        // Feb 23, 2026 is a Monday (not a holiday)
        // 08:00 MST = 15:00 UTC
        const timestamp = new Date('2026-02-23T15:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBeNull();
      });

      it('returns null modifier for 16:59 on a Thursday', () => {
        // Feb 19, 2026 is a Thursday
        // 16:59 MST = 23:59 UTC
        const timestamp = new Date('2026-02-19T23:59:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBeNull();
      });
    });

    describe('weekday evening AFHR (17:00–22:59)', () => {
      it('returns AFHR for 17:00 on a Tuesday', () => {
        // Feb 17, 2026 is a Tuesday
        // 17:00 MST = 00:00 UTC next day
        const timestamp = new Date('2026-02-18T00:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.AFHR);
      });

      it('returns AFHR for 20:00 on a Wednesday', () => {
        // Feb 18, 2026 is a Wednesday
        // 20:00 MST = 03:00 UTC next day
        const timestamp = new Date('2026-02-19T03:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.AFHR);
      });

      it('returns AFHR for 22:59 on a Thursday', () => {
        // Feb 19, 2026 is a Thursday
        // 22:59 MST = 05:59 UTC next day
        const timestamp = new Date('2026-02-20T05:59:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.AFHR);
      });
    });

    describe('weekday night NGHR (23:00–07:59)', () => {
      it('returns NGHR for 23:00 on a Monday', () => {
        // Feb 23, 2026 is a Monday (not a holiday)
        // 23:00 MST = 06:00 UTC next day
        const timestamp = new Date('2026-02-24T06:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.NGHR);
      });

      it('returns NGHR for 02:00 on a Wednesday', () => {
        // Feb 18, 2026 is a Wednesday
        // 02:00 MST = 09:00 UTC same day
        const timestamp = new Date('2026-02-18T09:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.NGHR);
      });

      it('returns NGHR for 07:59 on a Thursday', () => {
        // Feb 19, 2026 is a Thursday
        // 07:59 MST = 14:59 UTC same day
        const timestamp = new Date('2026-02-19T14:59:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.NGHR);
      });
    });

    describe('weekends (WKND)', () => {
      it('returns WKND for Saturday any time', () => {
        // Feb 21, 2026 is a Saturday
        // 10:00 MST = 17:00 UTC
        const timestamp = new Date('2026-02-21T17:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Sunday any time', () => {
        // Feb 22, 2026 is a Sunday
        // 14:00 MST = 21:00 UTC
        const timestamp = new Date('2026-02-22T21:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Saturday night', () => {
        // Feb 21, 2026 is a Saturday
        // 23:30 MST = 06:30 UTC next day
        const timestamp = new Date('2026-02-22T06:30:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        // Sunday at 23:30 is still WKND
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });
    });

    describe('statutory holidays (WKND)', () => {
      it('returns WKND for New Year\'s Day on a weekday', () => {
        // Jan 1, 2026 is a Thursday
        // 10:00 MST = 17:00 UTC
        const timestamp = new Date('2026-01-01T17:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Canada Day on a weekday', () => {
        // Jul 1, 2026 is a Wednesday
        // 12:00 MDT = 18:00 UTC (MDT = UTC-6 in summer)
        const timestamp = new Date('2026-07-01T18:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Christmas Day on a weekday', () => {
        // Dec 25, 2026 is a Friday
        // 09:00 MST = 16:00 UTC
        const timestamp = new Date('2026-12-25T16:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Family Day (3rd Monday of February)', () => {
        // Family Day 2026: Feb 16 (3rd Monday)
        // 10:00 MST = 17:00 UTC
        const timestamp = new Date('2026-02-16T17:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Truth and Reconciliation Day (Sept 30)', () => {
        // Sept 30, 2026 is a Wednesday
        // 10:00 MDT = 16:00 UTC
        const timestamp = new Date('2026-09-30T16:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Remembrance Day (Nov 11)', () => {
        // Nov 11, 2026 is a Wednesday
        // 10:00 MST = 17:00 UTC
        const timestamp = new Date('2026-11-11T17:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });

      it('returns WKND for Labour Day (1st Monday of September)', () => {
        // Labour Day 2026: Sept 7 (1st Monday)
        // 10:00 MDT = 16:00 UTC
        const timestamp = new Date('2026-09-07T16:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.WKND);
      });
    });

    describe('boundary cases', () => {
      it('08:00 is standard hours (not NGHR)', () => {
        // Feb 19, 2026 is a Thursday
        // 08:00 MST = 15:00 UTC
        const timestamp = new Date('2026-02-19T15:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBeNull();
      });

      it('17:00 is AFHR (not standard)', () => {
        // Feb 19, 2026 is a Thursday
        // 17:00 MST = 00:00 UTC next day
        const timestamp = new Date('2026-02-20T00:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.AFHR);
      });

      it('23:00 is NGHR (not AFHR)', () => {
        // Feb 19, 2026 is a Thursday
        // 23:00 MST = 06:00 UTC next day
        const timestamp = new Date('2026-02-20T06:00:00Z');
        const result = detectAfterHoursBracket(timestamp, tz);
        expect(result.modifier).toBe(AfterHoursBracket.NGHR);
      });
    });
  });

  // =========================================================================
  // getAlbertaStatutoryHolidays
  // =========================================================================

  describe('getAlbertaStatutoryHolidays', () => {
    it('returns the correct number of holidays', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays).toHaveLength(11);
    });

    it('includes New Year\'s Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.some((d) => d.getMonth() === 0 && d.getDate() === 1)).toBe(true);
    });

    it('includes Christmas Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.some((d) => d.getMonth() === 11 && d.getDate() === 25)).toBe(true);
    });

    it('includes Canada Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.some((d) => d.getMonth() === 6 && d.getDate() === 1)).toBe(true);
    });

    it('includes Truth and Reconciliation Day (Sept 30)', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.some((d) => d.getMonth() === 8 && d.getDate() === 30)).toBe(true);
    });

    it('includes Remembrance Day (Nov 11)', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.some((d) => d.getMonth() === 10 && d.getDate() === 11)).toBe(true);
    });

    it('includes Family Day (3rd Monday of February)', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      // Family Day 2026: Feb 16
      expect(holidays.some((d) => d.getMonth() === 1 && d.getDate() === 16)).toBe(true);
    });

    it('includes Good Friday', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      // Good Friday 2026: April 3
      expect(holidays.some((d) => d.getMonth() === 3 && d.getDate() === 3)).toBe(true);
    });

    it('includes Heritage Day (1st Monday of August)', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      // Heritage Day 2026: Aug 3
      expect(holidays.some((d) => d.getMonth() === 7 && d.getDate() === 3)).toBe(true);
    });

    it('includes Labour Day (1st Monday of September)', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      // Labour Day 2026: Sept 7
      expect(holidays.some((d) => d.getMonth() === 8 && d.getDate() === 7)).toBe(true);
    });

    it('includes Thanksgiving (2nd Monday of October)', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      // Thanksgiving 2026: Oct 12
      expect(holidays.some((d) => d.getMonth() === 9 && d.getDate() === 12)).toBe(true);
    });

    it('computes correct holidays for different years', () => {
      const holidays2027 = getAlbertaStatutoryHolidays(2027);
      expect(holidays2027).toHaveLength(11);
      // Family Day 2027: Feb 15
      expect(holidays2027.some((d) => d.getMonth() === 1 && d.getDate() === 15)).toBe(true);
    });
  });

  // =========================================================================
  // Security: location validation
  // =========================================================================

  describe('Security: location validation', () => {
    it('cannot start shift at another physician\'s location', async () => {
      const deps = makeDeps({
        locationCheck: {
          belongsToPhysician: vi.fn().mockResolvedValue(false),
        },
      });

      await expect(
        startShift(deps, PROVIDER_B, LOCATION_ID),
      ).rejects.toThrow(NotFoundError);
    });

    it('shift ownership is validated before logging patient', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        logPatient(deps, PROVIDER_B, SHIFT_ID, {
          patientId: PATIENT_ID,
          healthServiceCode: '03.04A',
        }),
      ).rejects.toThrow(NotFoundError);

      expect(deps.claimCreator.createClaimFromShift).not.toHaveBeenCalled();
    });

    it('shift ownership is validated before ending shift', async () => {
      const deps = makeDeps();
      (deps.repo.getById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        endShift(deps, PROVIDER_B, SHIFT_ID),
      ).rejects.toThrow(NotFoundError);

      expect(deps.repo.endShift).not.toHaveBeenCalled();
    });
  });
});
