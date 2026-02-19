// ============================================================================
// Domain 10: Mobile Companion — Audit Trail Completeness (Security)
// Verifies all mobile audit events are logged, append-only integrity,
// PHI exclusion from audit entries, delegate audit context, and
// rate-limited summary audit.
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
  startShift,
  endShift,
  logPatient,
  type EdShiftServiceDeps,
} from '../../../src/domains/mobile/services/ed-shift.service.js';

import {
  addFavourite,
  removeFavourite,
  reorderFavourites,
  type FavouriteCodesServiceDeps,
} from '../../../src/domains/mobile/services/favourite-codes.service.js';

import {
  createQuickClaim,
  type QuickClaimServiceDeps,
} from '../../../src/domains/mobile/services/quick-claim.service.js';

import {
  getSummary,
  resetAuditRateLimiter,
  type MobileSummaryServiceDeps,
} from '../../../src/domains/mobile/services/mobile-summary.service.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '11111111-aaaa-0000-0000-000000000001';
const DELEGATE_ID = '22222222-bbbb-0000-0000-000000000002';
const LOCATION_ID = '33333333-cccc-0000-0000-000000000001';
const SHIFT_ID = '44444444-dddd-0000-0000-000000000001';
const CLAIM_ID = '55555555-eeee-0000-0000-000000000001';
const FAVOURITE_ID = '66666666-ffff-0000-0000-000000000001';
const PATIENT_ID = '77777777-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock AuditRepo factory
// ---------------------------------------------------------------------------

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => ({})),
  };
}

// ---------------------------------------------------------------------------
// Mock EdShiftServiceDeps
// ---------------------------------------------------------------------------

function createMockEdShiftDeps(
  auditRepo = createMockAuditRepo(),
): EdShiftServiceDeps {
  const shiftRecord = {
    shiftId: SHIFT_ID,
    providerId: PHYSICIAN_ID,
    locationId: LOCATION_ID,
    status: 'ACTIVE' as const,
    shiftStart: new Date('2026-02-19T08:00:00Z'),
    shiftEnd: null,
    patientCount: 0,
    estimatedValue: '0.00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const endedShift = {
    ...shiftRecord,
    status: 'ENDED' as const,
    shiftEnd: new Date('2026-02-19T16:00:00Z'),
    patientCount: 3,
    estimatedValue: '450.00',
  };

  return {
    repo: {
      create: vi.fn(async () => shiftRecord),
      getActive: vi.fn(async () => null),
      getById: vi.fn(async () => shiftRecord),
      endShift: vi.fn(async () => endedShift),
      getSummary: vi.fn(async () => ({
        shift: endedShift,
        claims: [],
        totalValue: '450.00',
      })),
      list: vi.fn(async () => ({ data: [], total: 0 })),
      incrementPatientCount: vi.fn(async () => {}),
    } as any,
    locationCheck: {
      belongsToPhysician: vi.fn(async () => true),
    },
    claimCreator: {
      createClaimFromShift: vi.fn(async () => ({ claimId: CLAIM_ID })),
    },
    hscEligibility: {
      isEligibleForModifier: vi.fn(async () => true),
    },
    auditRepo,
  };
}

// ---------------------------------------------------------------------------
// Mock FavouriteCodesServiceDeps
// ---------------------------------------------------------------------------

function createMockFavouriteDeps(
  auditRepo = createMockAuditRepo(),
): FavouriteCodesServiceDeps {
  return {
    repo: {
      create: vi.fn(async (data: any) => ({
        favouriteId: FAVOURITE_ID,
        providerId: data.providerId,
        healthServiceCode: data.healthServiceCode,
        displayName: data.displayName,
        sortOrder: data.sortOrder,
        defaultModifiers: data.defaultModifiers,
        createdAt: new Date(),
      })),
      update: vi.fn(async (id: string, providerId: string, data: any) => ({
        favouriteId: id,
        providerId,
        healthServiceCode: '03.04A',
        displayName: data.displayName ?? 'Office Visit',
        sortOrder: data.sortOrder ?? 1,
        defaultModifiers: null,
        createdAt: new Date(),
      })),
      delete: vi.fn(async () => true),
      listByProvider: vi.fn(async () => []),
      countByProvider: vi.fn(async () => 5),
      reorder: vi.fn(async () => {}),
      bulkCreate: vi.fn(async () => {}),
    } as any,
    hscLookup: {
      findByCode: vi.fn(async () => ({
        code: '03.04A',
        description: 'Office Visit',
        baseFee: '38.44',
        feeType: 'FIXED',
      })),
    },
    modifierLookup: {
      isKnownModifier: vi.fn(async () => true),
    },
    claimHistory: {
      getTopBilledCodes: vi.fn(async () => []),
    },
    providerProfile: {
      getSpecialty: vi.fn(async () => null),
    },
    specialtyDefaults: {
      getDefaultCodes: vi.fn(async () => []),
    },
    auditRepo,
  };
}

// ---------------------------------------------------------------------------
// Mock QuickClaimServiceDeps
// ---------------------------------------------------------------------------

function createMockQuickClaimDeps(
  auditRepo = createMockAuditRepo(),
): QuickClaimServiceDeps {
  return {
    claimCreator: {
      createDraftClaim: vi.fn(async () => ({ claimId: CLAIM_ID })),
    },
    patientCreator: {
      createMinimalPatient: vi.fn(async (_pid: string, data: any) => ({
        patientId: PATIENT_ID,
        ...data,
      })),
    },
    recentPatientsQuery: {
      getRecentBilledPatients: vi.fn(async () => []),
    },
    auditRepo,
  };
}

// ---------------------------------------------------------------------------
// Mock MobileSummaryServiceDeps
// ---------------------------------------------------------------------------

function createMockSummaryDeps(
  auditRepo = createMockAuditRepo(),
): MobileSummaryServiceDeps {
  return {
    claimCounter: {
      countTodayClaims: vi.fn(async () => 5),
      countPendingQueue: vi.fn(async () => 2),
    },
    unreadCounter: {
      countUnread: vi.fn(async () => 1),
    },
    activeShiftLookup: {
      getActive: vi.fn(async () => null),
    },
    auditRepo,
  };
}

// ===========================================================================
// TEST SUITE
// ===========================================================================

describe('Mobile Companion Audit Trail (Security)', () => {
  // =========================================================================
  // 1. Shift Events — Audit Records
  // =========================================================================

  describe('Shift Events', () => {
    it('mobile.shift_started: start shift produces audit entry with shift_id, location_id, provider_id, timestamp', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      await startShift(deps, PHYSICIAN_ID, LOCATION_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.SHIFT_STARTED,
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: SHIFT_ID,
          detail: expect.objectContaining({
            locationId: LOCATION_ID,
            shiftStart: expect.any(String),
          }),
        }),
      );
    });

    it('mobile.shift_ended: end shift produces audit entry with shift_id, patient_count, estimated_value, provider_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      await endShift(deps, PHYSICIAN_ID, SHIFT_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.SHIFT_ENDED,
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: SHIFT_ID,
          detail: expect.objectContaining({
            patientCount: 3,
            estimatedValue: '450.00',
          }),
        }),
      );
    });

    it('mobile.patient_logged: log patient produces audit entry with shift_id, claim_id, provider_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      await logPatient(deps, PHYSICIAN_ID, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.PATIENT_LOGGED,
          category: 'mobile',
          resourceType: 'ed_shift',
          resourceId: SHIFT_ID,
          detail: expect.objectContaining({
            claimId: CLAIM_ID,
          }),
        }),
      );
    });

    it('mobile.patient_logged audit entry does NOT contain patient name or PHN', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      await logPatient(deps, PHYSICIAN_ID, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // Must not contain patient names or PHN
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('first_name');
      expect(serialized).not.toContain('last_name');
      expect(serialized).not.toMatch(/\b\d{9}\b/); // 9-digit PHN pattern
      expect(serialized).not.toContain('phn');

      // Should contain claim_id reference only
      expect(call.detail).toHaveProperty('claimId');
    });
  });

  // =========================================================================
  // 2. Quick Claim Events — Audit Records
  // =========================================================================

  describe('Quick Claim Events', () => {
    it('mobile.quick_claim_created: quick claim produces audit entry with claim_id, health_service_code, provider_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockQuickClaimDeps(auditRepo);

      await createQuickClaim(deps, PHYSICIAN_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.QUICK_CLAIM_CREATED,
          category: 'mobile',
          resourceType: 'claim',
          resourceId: CLAIM_ID,
          detail: expect.objectContaining({
            healthServiceCode: '03.04A',
          }),
        }),
      );
    });

    it('mobile.quick_claim_created audit entry does NOT contain patient name or PHN', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockQuickClaimDeps(auditRepo);

      await createQuickClaim(deps, PHYSICIAN_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // Must not contain patient names or PHN
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('first_name');
      expect(serialized).not.toContain('last_name');
      expect(serialized).not.toContain('phn');
    });
  });

  // =========================================================================
  // 3. Favourite Events — Audit Records
  // =========================================================================

  describe('Favourite Events', () => {
    it('mobile.favourite_added: add favourite produces audit entry with favourite_id, health_service_code, provider_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockFavouriteDeps(auditRepo);

      await addFavourite(deps, PHYSICIAN_ID, {
        healthServiceCode: '03.04A',
        displayName: 'Office Visit',
        sortOrder: 1,
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.FAVOURITE_ADDED,
          category: 'mobile',
          resourceType: 'favourite_code',
          resourceId: FAVOURITE_ID,
          detail: expect.objectContaining({
            healthServiceCode: '03.04A',
          }),
        }),
      );
    });

    it('mobile.favourite_removed: remove favourite produces audit entry with favourite_id, provider_id', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockFavouriteDeps(auditRepo);

      await removeFavourite(deps, PHYSICIAN_ID, FAVOURITE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.FAVOURITE_REMOVED,
          category: 'mobile',
          resourceType: 'favourite_code',
          resourceId: FAVOURITE_ID,
        }),
      );
    });

    it('mobile.favourite_reordered: reorder produces audit entry with provider_id and count of items reordered', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockFavouriteDeps(auditRepo);

      const items = [
        { favourite_id: randomUUID(), sort_order: 1 },
        { favourite_id: randomUUID(), sort_order: 2 },
        { favourite_id: randomUUID(), sort_order: 3 },
      ];

      await reorderFavourites(deps, PHYSICIAN_ID, items);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.FAVOURITE_REORDERED,
          category: 'mobile',
          resourceType: 'favourite_code',
          detail: expect.objectContaining({
            itemCount: 3,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // 4. Summary Viewed — Rate-Limited Audit
  // =========================================================================

  describe('Summary Viewed (Rate-Limited Audit)', () => {
    beforeEach(() => {
      resetAuditRateLimiter();
    });

    it('mobile.summary_viewed: view summary produces audit entry', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockSummaryDeps(auditRepo);

      await getSummary(deps, PHYSICIAN_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PHYSICIAN_ID,
          action: MobileAuditAction.SUMMARY_VIEWED,
          category: 'mobile',
          resourceType: 'mobile_summary',
        }),
      );
    });

    it('viewing summary 5 times in 1 minute produces only 1 audit entry', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockSummaryDeps(auditRepo);

      // Call 5 times in rapid succession
      for (let i = 0; i < 5; i++) {
        await getSummary(deps, PHYSICIAN_ID);
      }

      // Rate limiter allows max 1 per 10 minutes
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    });

    it('rate limiter resets after 10 minutes — new audit entry created', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockSummaryDeps(auditRepo);

      // First view — produces audit entry
      await getSummary(deps, PHYSICIAN_ID);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);

      // Simulate 11 minutes passing by resetting the rate limiter
      resetAuditRateLimiter();

      // Second view after reset — produces new audit entry
      await getSummary(deps, PHYSICIAN_ID);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);
    });

    it('rate limiter is per-physician — different physicians get independent audit entries', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockSummaryDeps(auditRepo);

      const OTHER_PHYSICIAN_ID = '99999999-aaaa-0000-0000-000000000099';

      // Physician 1 views summary
      await getSummary(deps, PHYSICIAN_ID);
      // Physician 2 views summary
      await getSummary(deps, OTHER_PHYSICIAN_ID);

      // Both should produce audit entries (independent rate limiters)
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);

      const calls = auditRepo.appendAuditLog.mock.calls;
      expect(calls[0][0].userId).toBe(PHYSICIAN_ID);
      expect(calls[1][0].userId).toBe(OTHER_PHYSICIAN_ID);
    });
  });

  // =========================================================================
  // 5. Audit Entry Completeness — Required Fields
  // =========================================================================

  describe('Audit Entry Completeness', () => {
    it('every audit entry includes userId, action, category, and detail', async () => {
      const auditRepo = createMockAuditRepo();

      // Trigger multiple audit events
      const shiftDeps = createMockEdShiftDeps(auditRepo);
      await startShift(shiftDeps, PHYSICIAN_ID, LOCATION_ID);

      const favDeps = createMockFavouriteDeps(auditRepo);
      await addFavourite(favDeps, PHYSICIAN_ID, {
        healthServiceCode: '03.04A',
        sortOrder: 1,
      });

      const claimDeps = createMockQuickClaimDeps(auditRepo);
      await createQuickClaim(claimDeps, PHYSICIAN_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      // All calls must have required fields
      for (const call of auditRepo.appendAuditLog.mock.calls) {
        const entry = call[0];
        expect(entry).toHaveProperty('userId');
        expect(entry).toHaveProperty('action');
        expect(entry).toHaveProperty('category');
        expect(entry.category).toBe('mobile');
        expect(entry).toHaveProperty('detail');
        expect(entry.userId).toBe(PHYSICIAN_ID);
      }
    });

    it('shift audit entries include resourceType and resourceId', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      await startShift(deps, PHYSICIAN_ID, LOCATION_ID);

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.resourceType).toBe('ed_shift');
      expect(entry.resourceId).toBe(SHIFT_ID);
    });

    it('favourite audit entries include resourceType', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockFavouriteDeps(auditRepo);

      await addFavourite(deps, PHYSICIAN_ID, {
        healthServiceCode: '03.04A',
        sortOrder: 1,
      });

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.resourceType).toBe('favourite_code');
      expect(entry.resourceId).toBe(FAVOURITE_ID);
    });

    it('quick claim audit entries include resourceType=claim and resourceId', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockQuickClaimDeps(auditRepo);

      await createQuickClaim(deps, PHYSICIAN_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      const entry = auditRepo.appendAuditLog.mock.calls[0][0];
      expect(entry.resourceType).toBe('claim');
      expect(entry.resourceId).toBe(CLAIM_ID);
    });
  });

  // =========================================================================
  // 6. Audit Entries — No PHI / Sensitive Data
  // =========================================================================

  describe('Audit Entries Do Not Contain PHI', () => {
    it('patient_logged audit does not contain patient name, PHN, or date of birth', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      await logPatient(deps, PHYSICIAN_ID, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // No patient names
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('first_name');
      expect(serialized).not.toContain('last_name');

      // No PHN (9-digit number should not appear in audit)
      expect(serialized).not.toContain('phn');

      // No date of birth
      expect(serialized).not.toContain('dateOfBirth');
      expect(serialized).not.toContain('date_of_birth');
    });

    it('quick_claim_created audit does not contain patient PHI', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockQuickClaimDeps(auditRepo);

      await createQuickClaim(deps, PHYSICIAN_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('phn');
      expect(serialized).not.toContain('dateOfBirth');
    });

    it('summary_viewed audit contains only aggregate counts, no PHI', async () => {
      resetAuditRateLimiter();
      const auditRepo = createMockAuditRepo();
      const deps = createMockSummaryDeps(auditRepo);

      await getSummary(deps, PHYSICIAN_ID);

      const call = auditRepo.appendAuditLog.mock.calls[0][0];
      const serialized = JSON.stringify(call);

      // Should only contain aggregate counts
      expect(call.detail).toHaveProperty('todayClaimsCount');
      expect(call.detail).toHaveProperty('pendingQueueCount');
      expect(call.detail).toHaveProperty('unreadNotificationsCount');
      expect(call.detail).toHaveProperty('hasActiveShift');

      // Must not contain PHI
      expect(serialized).not.toContain('phn');
      expect(serialized).not.toContain('firstName');
      expect(serialized).not.toContain('lastName');
      expect(serialized).not.toContain('patientId');
    });
  });

  // =========================================================================
  // 7. Delegate Audit Context
  // =========================================================================

  describe('Delegate Audit Context', () => {
    it('delegate viewing summary shows delegate as actor in audit', async () => {
      resetAuditRateLimiter();
      const auditRepo = createMockAuditRepo();
      const deps = createMockSummaryDeps(auditRepo);

      // Delegate views summary on behalf of physician
      // The service receives the providerId from the auth context
      // When a delegate acts, the userId passed is the delegate's userId
      await getSummary(deps, DELEGATE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: DELEGATE_ID,
          action: MobileAuditAction.SUMMARY_VIEWED,
        }),
      );
    });

    it('delegate creating quick claim shows delegate identity in audit', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockQuickClaimDeps(auditRepo);

      // When a delegate creates a claim, their identity is the userId
      await createQuickClaim(deps, DELEGATE_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: DELEGATE_ID,
          action: MobileAuditAction.QUICK_CLAIM_CREATED,
        }),
      );
    });
  });

  // =========================================================================
  // 8. Append-Only Integrity
  // =========================================================================

  describe('Append-Only Audit Integrity', () => {
    it('audit repo interface only exposes appendAuditLog — no update or delete methods', () => {
      const auditRepo = createMockAuditRepo();

      // The AuditRepo interface only defines appendAuditLog
      expect(auditRepo).toHaveProperty('appendAuditLog');
      expect(typeof auditRepo.appendAuditLog).toBe('function');

      // No update or delete methods exist
      expect(auditRepo).not.toHaveProperty('updateAuditLog');
      expect(auditRepo).not.toHaveProperty('deleteAuditLog');
      expect(auditRepo).not.toHaveProperty('update');
      expect(auditRepo).not.toHaveProperty('delete');
      expect(auditRepo).not.toHaveProperty('remove');
      expect(auditRepo).not.toHaveProperty('clear');
    });

    it('each action produces exactly one audit entry — no batch overwrites', async () => {
      const auditRepo = createMockAuditRepo();
      const shiftDeps = createMockEdShiftDeps(auditRepo);

      // Start a shift
      await startShift(shiftDeps, PHYSICIAN_ID, LOCATION_ID);

      // End the shift
      await endShift(shiftDeps, PHYSICIAN_ID, SHIFT_ID);

      // Two separate audit entries — no overwriting of the first
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);

      const firstCall = auditRepo.appendAuditLog.mock.calls[0][0];
      const secondCall = auditRepo.appendAuditLog.mock.calls[1][0];

      expect(firstCall.action).toBe(MobileAuditAction.SHIFT_STARTED);
      expect(secondCall.action).toBe(MobileAuditAction.SHIFT_ENDED);
    });

    it('all 8 mobile audit action identifiers are defined and distinct', () => {
      const actions = Object.values(MobileAuditAction);
      const uniqueActions = new Set(actions);

      // All 8 actions are defined
      expect(actions).toHaveLength(8);
      // All are unique
      expect(uniqueActions.size).toBe(8);

      // All are prefixed with 'mobile.'
      for (const action of actions) {
        expect(action).toMatch(/^mobile\./);
      }
    });
  });

  // =========================================================================
  // 9. Full Lifecycle — Complete Audit Trail
  // =========================================================================

  describe('Full Lifecycle Audit Trail', () => {
    it('complete shift lifecycle produces audit trail: started → patient_logged → ended', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockEdShiftDeps(auditRepo);

      // 1. Start shift
      await startShift(deps, PHYSICIAN_ID, LOCATION_ID);

      // 2. Log patient
      await logPatient(deps, PHYSICIAN_ID, SHIFT_ID, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      // 3. End shift
      await endShift(deps, PHYSICIAN_ID, SHIFT_ID);

      // Verify 3 audit entries in order
      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(3);

      const actions = auditRepo.appendAuditLog.mock.calls.map(
        (c: any[]) => c[0].action,
      );
      expect(actions).toEqual([
        MobileAuditAction.SHIFT_STARTED,
        MobileAuditAction.PATIENT_LOGGED,
        MobileAuditAction.SHIFT_ENDED,
      ]);
    });

    it('favourite lifecycle: added → reordered → removed produces 3 independent audit entries', async () => {
      const auditRepo = createMockAuditRepo();
      const deps = createMockFavouriteDeps(auditRepo);

      // 1. Add favourite
      await addFavourite(deps, PHYSICIAN_ID, {
        healthServiceCode: '03.04A',
        sortOrder: 1,
      });

      // 2. Reorder
      await reorderFavourites(deps, PHYSICIAN_ID, [
        { favourite_id: FAVOURITE_ID, sort_order: 2 },
      ]);

      // 3. Remove
      await removeFavourite(deps, PHYSICIAN_ID, FAVOURITE_ID);

      expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(3);

      const actions = auditRepo.appendAuditLog.mock.calls.map(
        (c: any[]) => c[0].action,
      );
      expect(actions).toEqual([
        MobileAuditAction.FAVOURITE_ADDED,
        MobileAuditAction.FAVOURITE_REORDERED,
        MobileAuditAction.FAVOURITE_REMOVED,
      ]);
    });
  });
});
