import { describe, it, expect, vi } from 'vitest';
import {
  createQuickClaim,
  createMinimalPatient,
  getRecentPatients,
} from './quick-claim.service.js';
import type { QuickClaimServiceDeps } from './quick-claim.service.js';
import { RECENT_PATIENTS_COUNT } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PATIENT_ID = crypto.randomUUID();
const CLAIM_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeDeps(
  overrides: Partial<QuickClaimServiceDeps> = {},
): QuickClaimServiceDeps {
  return {
    claimCreator: {
      createDraftClaim: vi.fn().mockResolvedValue({ claimId: CLAIM_ID }),
    },
    patientCreator: {
      createMinimalPatient: vi.fn().mockResolvedValue({
        patientId: PATIENT_ID,
        firstName: 'Jane',
        lastName: 'Doe',
        phn: '123456789',
        dateOfBirth: '1990-05-15',
        gender: 'FEMALE',
      }),
    },
    recentPatientsQuery: {
      getRecentBilledPatients: vi.fn().mockResolvedValue([
        {
          patientId: PATIENT_ID,
          firstName: 'Jane',
          lastName: 'Doe',
          phn: '123456789',
        },
      ]),
    },
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests: createQuickClaim
// ---------------------------------------------------------------------------

describe('QuickClaimService', () => {
  describe('createQuickClaim', () => {
    it('creates a draft AHCIP claim with source=mobile_quick_entry', async () => {
      const deps = makeDeps();

      const result = await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(result.claimId).toBe(CLAIM_ID);
      expect(deps.claimCreator.createDraftClaim).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.objectContaining({
          patientId: PATIENT_ID,
          healthServiceCode: '03.04A',
          dateOfService: '2026-02-19',
          claimType: 'AHCIP',
          state: 'DRAFT',
          source: 'mobile_quick_entry',
        }),
      );
    });

    it('defaults dateOfService to today when not provided', async () => {
      const deps = makeDeps();
      const today = new Date().toISOString().split('T')[0];

      await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
      });

      expect(deps.claimCreator.createDraftClaim).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.objectContaining({
          dateOfService: today,
        }),
      );
    });

    it('passes modifiers to claim creator when provided', async () => {
      const deps = makeDeps();

      await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        modifiers: ['CMGP', 'AFHR'],
        dateOfService: '2026-02-19',
      });

      expect(deps.claimCreator.createDraftClaim).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.objectContaining({
          modifiers: ['CMGP', 'AFHR'],
        }),
      );
    });

    it('passes undefined modifiers as undefined when not provided', async () => {
      const deps = makeDeps();

      await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(deps.claimCreator.createDraftClaim).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.objectContaining({
          modifiers: undefined,
        }),
      );
    });

    it('always creates claims as AHCIP type', async () => {
      const deps = makeDeps();

      await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(deps.claimCreator.createDraftClaim).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.objectContaining({
          claimType: 'AHCIP',
        }),
      );
    });

    it('always creates claims in DRAFT state', async () => {
      const deps = makeDeps();

      await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(deps.claimCreator.createDraftClaim).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.objectContaining({
          state: 'DRAFT',
        }),
      );
    });

    it('logs audit event mobile.quick_claim_created on success', async () => {
      const deps = makeDeps();

      await createQuickClaim(deps, PROVIDER_A, {
        patientId: PATIENT_ID,
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-19',
      });

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.quick_claim_created',
          category: 'mobile',
          resourceType: 'claim',
          resourceId: CLAIM_ID,
          detail: expect.objectContaining({
            patientId: PATIENT_ID,
            healthServiceCode: '03.04A',
            source: 'mobile_quick_entry',
          }),
        }),
      );
    });

    it('does not log audit event when claim creation fails', async () => {
      const deps = makeDeps({
        claimCreator: {
          createDraftClaim: vi
            .fn()
            .mockRejectedValue(new Error('DB error')),
        },
      });

      await expect(
        createQuickClaim(deps, PROVIDER_A, {
          patientId: PATIENT_ID,
          healthServiceCode: '03.04A',
          dateOfService: '2026-02-19',
        }),
      ).rejects.toThrow('DB error');

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // createMinimalPatient
  // =========================================================================

  describe('createMinimalPatient', () => {
    it('creates a patient with minimal fields via patient creator', async () => {
      const deps = makeDeps();

      const result = await createMinimalPatient(deps, PROVIDER_A, {
        firstName: 'Jane',
        lastName: 'Doe',
        phn: '123456789',
        dateOfBirth: '1990-05-15',
        gender: 'FEMALE',
      });

      expect(result.patientId).toBe(PATIENT_ID);
      expect(result.firstName).toBe('Jane');
      expect(result.lastName).toBe('Doe');
      expect(result.phn).toBe('123456789');
      expect(result.dateOfBirth).toBe('1990-05-15');
      expect(result.gender).toBe('FEMALE');
    });

    it('passes all fields to patient creator dependency', async () => {
      const deps = makeDeps();

      await createMinimalPatient(deps, PROVIDER_A, {
        firstName: 'John',
        lastName: 'Smith',
        phn: '987654321',
        dateOfBirth: '1985-12-25',
        gender: 'MALE',
      });

      expect(deps.patientCreator.createMinimalPatient).toHaveBeenCalledWith(
        PROVIDER_A,
        {
          firstName: 'John',
          lastName: 'Smith',
          phn: '987654321',
          dateOfBirth: '1985-12-25',
          gender: 'MALE',
        },
      );
    });

    it('propagates errors from patient creator', async () => {
      const deps = makeDeps({
        patientCreator: {
          createMinimalPatient: vi
            .fn()
            .mockRejectedValue(new Error('Duplicate PHN')),
        },
      });

      await expect(
        createMinimalPatient(deps, PROVIDER_A, {
          firstName: 'Jane',
          lastName: 'Doe',
          phn: '123456789',
          dateOfBirth: '1990-05-15',
          gender: 'FEMALE',
        }),
      ).rejects.toThrow('Duplicate PHN');
    });
  });

  // =========================================================================
  // getRecentPatients
  // =========================================================================

  describe('getRecentPatients', () => {
    it('returns recent patients ordered by recency', async () => {
      const patient1 = {
        patientId: crypto.randomUUID(),
        firstName: 'Jane',
        lastName: 'Doe',
        phn: '123456789',
      };
      const patient2 = {
        patientId: crypto.randomUUID(),
        firstName: 'John',
        lastName: 'Smith',
        phn: '987654321',
      };
      const deps = makeDeps({
        recentPatientsQuery: {
          getRecentBilledPatients: vi
            .fn()
            .mockResolvedValue([patient1, patient2]),
        },
      });

      const result = await getRecentPatients(deps, PROVIDER_A);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual(patient1);
      expect(result[1]).toEqual(patient2);
    });

    it('defaults limit to RECENT_PATIENTS_COUNT (20) when not specified', async () => {
      const deps = makeDeps();

      await getRecentPatients(deps, PROVIDER_A);

      expect(
        deps.recentPatientsQuery.getRecentBilledPatients,
      ).toHaveBeenCalledWith(PROVIDER_A, RECENT_PATIENTS_COUNT);
    });

    it('uses custom limit when provided', async () => {
      const deps = makeDeps();

      await getRecentPatients(deps, PROVIDER_A, 5);

      expect(
        deps.recentPatientsQuery.getRecentBilledPatients,
      ).toHaveBeenCalledWith(PROVIDER_A, 5);
    });

    it('returns empty array when physician has no recent claims', async () => {
      const deps = makeDeps({
        recentPatientsQuery: {
          getRecentBilledPatients: vi.fn().mockResolvedValue([]),
        },
      });

      const result = await getRecentPatients(deps, PROVIDER_A);

      expect(result).toEqual([]);
    });

    it('returns patient_id, first_name, last_name, phn fields', async () => {
      const deps = makeDeps();

      const result = await getRecentPatients(deps, PROVIDER_A);

      expect(result).toHaveLength(1);
      expect(result[0]).toHaveProperty('patientId');
      expect(result[0]).toHaveProperty('firstName');
      expect(result[0]).toHaveProperty('lastName');
      expect(result[0]).toHaveProperty('phn');
    });
  });
});
