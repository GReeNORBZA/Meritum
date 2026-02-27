/**
 * Cross-Domain Integration Tests — Patient + Claim
 *
 * Validates workflows that span the Patient (Domain 3) and Claim (Domain 4)
 * repositories against a real PostgreSQL database. Each test runs inside a
 * rolled-back transaction for full isolation.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';

import { getTestDb, setupTestDb, teardownTestDb } from '../../fixtures/db.js';
import { withTestTransaction } from '../../fixtures/helpers.js';
import {
  createTestUser,
  createTestProvider,
  createTestPatient,
  createTestClaim,
} from '../../fixtures/factories.js';
import { createClaimRepository } from '../../../src/domains/claim/claim.repository.js';
import { createPatientRepository } from '../../../src/domains/patient/patient.repository.js';

let db: NodePgDatabase;

beforeAll(async () => {
  await setupTestDb();
  db = getTestDb();
});

afterAll(async () => {
  await teardownTestDb();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Reusable scaffold: provider + patient ready for claim creation. */
async function scaffold(tx: NodePgDatabase) {
  const provider = await createTestProvider(tx);
  const patient = await createTestPatient(tx, { providerId: provider.userId });
  return { provider, patient };
}

// ===========================================================================
// Patient-Claim Cross-Domain Tests
// ===========================================================================

describe('Cross-Domain: Patient + Claim', () => {
  // -------------------------------------------------------------------------
  // 1. Create patient then create claim referencing patient
  // -------------------------------------------------------------------------
  it('creates a claim referencing an existing patient — claim.patientId matches', () =>
    withTestTransaction(db, async (tx) => {
      const { provider, patient } = await scaffold(tx);
      const claimRepo = createClaimRepository(tx);

      const claim = await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patient.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-01-15',
        importSource: 'MANUAL',
      });

      expect(claim.patientId).toBe(patient.patientId);
      expect(claim.physicianId).toBe(provider.userId);
      expect(claim.state).toBe('DRAFT');
    }));

  // -------------------------------------------------------------------------
  // 2. findClaimById returns claim with correct patientId
  // -------------------------------------------------------------------------
  it('findClaimById returns the claim with correct patientId', () =>
    withTestTransaction(db, async (tx) => {
      const { provider, patient } = await scaffold(tx);
      const claimRepo = createClaimRepository(tx);

      const created = await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patient.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-02-01',
        importSource: 'MANUAL',
      });

      const found = await claimRepo.findClaimById(
        created.claimId,
        provider.userId,
      );

      expect(found).toBeDefined();
      expect(found!.claimId).toBe(created.claimId);
      expect(found!.patientId).toBe(patient.patientId);
    }));

  // -------------------------------------------------------------------------
  // 3. List claims filtered by patientId
  // -------------------------------------------------------------------------
  it('listClaims filtered by patientId returns only that patient\'s claims', () =>
    withTestTransaction(db, async (tx) => {
      const provider = await createTestProvider(tx);
      const patientA = await createTestPatient(tx, {
        providerId: provider.userId,
        firstName: 'Alice',
      });
      const patientB = await createTestPatient(tx, {
        providerId: provider.userId,
        firstName: 'Bob',
      });

      const claimRepo = createClaimRepository(tx);

      // Create 2 claims for patient A and 1 for patient B
      await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patientA.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-01-10',
        importSource: 'MANUAL',
      });
      await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patientA.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-01-11',
        importSource: 'MANUAL',
      });
      await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patientB.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-01-12',
        importSource: 'MANUAL',
      });

      const result = await claimRepo.listClaims(provider.userId, {
        patientId: patientA.patientId,
        page: 1,
        pageSize: 50,
      });

      expect(result.data).toHaveLength(2);
      expect(result.pagination.total).toBe(2);
      for (const claim of result.data) {
        expect(claim.patientId).toBe(patientA.patientId);
      }
    }));

  // -------------------------------------------------------------------------
  // 4. Two patients, claims for each — filter by patient A returns only A's
  // -------------------------------------------------------------------------
  it('filtering by patient A excludes patient B claims', () =>
    withTestTransaction(db, async (tx) => {
      const provider = await createTestProvider(tx);
      const patientA = await createTestPatient(tx, {
        providerId: provider.userId,
        firstName: 'PatientA',
      });
      const patientB = await createTestPatient(tx, {
        providerId: provider.userId,
        firstName: 'PatientB',
      });

      const claimRepo = createClaimRepository(tx);

      await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patientA.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-03-01',
        importSource: 'MANUAL',
      });
      await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patientB.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-03-02',
        importSource: 'MANUAL',
      });

      const resultA = await claimRepo.listClaims(provider.userId, {
        patientId: patientA.patientId,
        page: 1,
        pageSize: 50,
      });

      const resultB = await claimRepo.listClaims(provider.userId, {
        patientId: patientB.patientId,
        page: 1,
        pageSize: 50,
      });

      expect(resultA.data).toHaveLength(1);
      expect(resultA.data[0].patientId).toBe(patientA.patientId);

      expect(resultB.data).toHaveLength(1);
      expect(resultB.data[0].patientId).toBe(patientB.patientId);
    }));

  // -------------------------------------------------------------------------
  // 5. Create claim with non-existent patientId — still inserts
  // -------------------------------------------------------------------------
  it('creates a claim with non-existent patientId (no FK enforcement at repo level)', () =>
    withTestTransaction(db, async (tx) => {
      const provider = await createTestProvider(tx);
      const claimRepo = createClaimRepository(tx);

      const fakePatientId = '00000000-0000-0000-0000-000000000999';

      const claim = await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: fakePatientId,
        claimType: 'AHCIP',
        dateOfService: '2026-01-15',
        importSource: 'MANUAL',
      });

      expect(claim.claimId).toBeDefined();
      expect(claim.patientId).toBe(fakePatientId);
    }));

  // -------------------------------------------------------------------------
  // 6. Deactivate patient — claims still accessible
  // -------------------------------------------------------------------------
  it('deactivating a patient does not cascade to claims — claims remain accessible', () =>
    withTestTransaction(db, async (tx) => {
      const { provider, patient } = await scaffold(tx);
      const claimRepo = createClaimRepository(tx);
      const patientRepo = createPatientRepository(tx);

      const claim = await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patient.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-01-20',
        importSource: 'MANUAL',
      });

      // Deactivate the patient (soft-delete)
      const deactivated = await patientRepo.deactivatePatient(
        patient.patientId,
        provider.userId,
      );
      expect(deactivated).toBeDefined();
      expect(deactivated!.isActive).toBe(false);

      // Claim should still be accessible
      const found = await claimRepo.findClaimById(
        claim.claimId,
        provider.userId,
      );
      expect(found).toBeDefined();
      expect(found!.claimId).toBe(claim.claimId);
      expect(found!.patientId).toBe(patient.patientId);
    }));

  // -------------------------------------------------------------------------
  // 7. Multiple claims for same patient — all have correct patientId
  // -------------------------------------------------------------------------
  it('creates multiple claims for the same patient — all reference the correct patientId', () =>
    withTestTransaction(db, async (tx) => {
      const { provider, patient } = await scaffold(tx);
      const claimRepo = createClaimRepository(tx);

      const claims = await Promise.all([
        claimRepo.createClaim({
          physicianId: provider.userId,
          patientId: patient.patientId,
          claimType: 'AHCIP',
          dateOfService: '2026-02-01',
          importSource: 'MANUAL',
        }),
        claimRepo.createClaim({
          physicianId: provider.userId,
          patientId: patient.patientId,
          claimType: 'AHCIP',
          dateOfService: '2026-02-02',
          importSource: 'MANUAL',
        }),
        claimRepo.createClaim({
          physicianId: provider.userId,
          patientId: patient.patientId,
          claimType: 'AHCIP',
          dateOfService: '2026-02-03',
          importSource: 'MANUAL',
        }),
      ]);

      expect(claims).toHaveLength(3);
      for (const claim of claims) {
        expect(claim.patientId).toBe(patient.patientId);
        expect(claim.physicianId).toBe(provider.userId);
      }

      // Verify via listClaims
      const result = await claimRepo.listClaims(provider.userId, {
        patientId: patient.patientId,
        page: 1,
        pageSize: 50,
      });
      expect(result.data).toHaveLength(3);
    }));

  // -------------------------------------------------------------------------
  // 8. List claims with multiple filters (patientId + state)
  // -------------------------------------------------------------------------
  it('listClaims with patientId + state filter returns correct subset', () =>
    withTestTransaction(db, async (tx) => {
      const { provider, patient } = await scaffold(tx);
      const claimRepo = createClaimRepository(tx);

      // Create two DRAFT claims
      const draft1 = await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patient.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-03-01',
        importSource: 'MANUAL',
      });
      await claimRepo.createClaim({
        physicianId: provider.userId,
        patientId: patient.patientId,
        claimType: 'AHCIP',
        dateOfService: '2026-03-02',
        importSource: 'MANUAL',
      });

      // Transition one claim to VALIDATED
      await claimRepo.transitionState(
        draft1.claimId,
        provider.userId,
        'DRAFT',
        'VALIDATED',
      );

      // Filter by patientId + state=DRAFT — should return only 1
      const draftResult = await claimRepo.listClaims(provider.userId, {
        patientId: patient.patientId,
        state: 'DRAFT',
        page: 1,
        pageSize: 50,
      });
      expect(draftResult.data).toHaveLength(1);
      expect(draftResult.data[0].state).toBe('DRAFT');

      // Filter by patientId + state=VALIDATED — should return only 1
      const validatedResult = await claimRepo.listClaims(provider.userId, {
        patientId: patient.patientId,
        state: 'VALIDATED',
        page: 1,
        pageSize: 50,
      });
      expect(validatedResult.data).toHaveLength(1);
      expect(validatedResult.data[0].state).toBe('VALIDATED');
      expect(validatedResult.data[0].claimId).toBe(draft1.claimId);

      // Filter by patientId alone — should return both
      const allResult = await claimRepo.listClaims(provider.userId, {
        patientId: patient.patientId,
        page: 1,
        pageSize: 50,
      });
      expect(allResult.data).toHaveLength(2);
    }));
});
