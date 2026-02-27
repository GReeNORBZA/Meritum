/**
 * Cross-Domain Integration Tests — Registration + Onboarding
 *
 * Validates workflows that span the IAM (Domain 1), Provider (Domain 2),
 * and Onboarding (Domain 11) repositories against a real PostgreSQL database.
 * Each test runs inside a rolled-back transaction for full isolation.
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
  createTestNotification,
} from '../../fixtures/factories.js';
import { createUserRepository } from '../../../src/domains/iam/iam.repository.js';
import { createOnboardingRepository } from '../../../src/domains/onboarding/onboarding.repository.js';
import { createProviderRepository } from '../../../src/domains/provider/provider.repository.js';
import { BusinessRuleError } from '../../../src/lib/errors.js';

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

/** Reusable scaffold: user + provider for onboarding tests. */
async function scaffold(tx: NodePgDatabase) {
  const user = await createTestUser(tx);
  const providerRepo = createProviderRepository(tx);
  const provider = await providerRepo.createProvider({
    providerId: user.userId,
    billingNumber: 'BN12345',
    cpsaRegistrationNumber: 'CPSA12345',
    firstName: 'Test',
    lastName: 'Provider',
    specialtyCode: '00',
    physicianType: 'GP',
  });
  return { user, provider, providerRepo };
}

// ===========================================================================
// Registration-Onboarding Cross-Domain Tests
// ===========================================================================

describe('Cross-Domain: Registration + Onboarding', () => {
  // -------------------------------------------------------------------------
  // 1. Create user -> provider -> onboarding progress -> verify exists
  // -------------------------------------------------------------------------
  it('creates user, provider, and onboarding progress — progress record exists', () =>
    withTestTransaction(db, async (tx) => {
      const { user, provider } = await scaffold(tx);
      const onboardingRepo = createOnboardingRepository(tx);

      const progress = await onboardingRepo.createProgress(provider.providerId);

      expect(progress).toBeDefined();
      expect(progress.providerId).toBe(provider.providerId);
      expect(progress.step1Completed).toBe(false);
      expect(progress.step2Completed).toBe(false);
      expect(progress.step3Completed).toBe(false);
      expect(progress.step4Completed).toBe(false);
      expect(progress.step7Completed).toBe(false);
      expect(progress.completedAt).toBeNull();

      // Verify it can be found
      const found = await onboardingRepo.findProgressByProviderId(
        provider.providerId,
      );
      expect(found).not.toBeNull();
      expect(found!.providerId).toBe(provider.providerId);
    }));

  // -------------------------------------------------------------------------
  // 2. Mark step 1 completed -> verify step1Completed = true
  // -------------------------------------------------------------------------
  it('marks step 1 completed — step1Completed is true', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const onboardingRepo = createOnboardingRepository(tx);

      await onboardingRepo.createProgress(provider.providerId);

      const updated = await onboardingRepo.markStepCompleted(
        provider.providerId,
        1,
      );

      expect(updated.step1Completed).toBe(true);
      expect(updated.step2Completed).toBe(false);
      expect(updated.completedAt).toBeNull();
    }));

  // -------------------------------------------------------------------------
  // 3. Mark steps 1,2,3,4,7 -> markOnboardingCompleted -> completedAt is set
  // -------------------------------------------------------------------------
  it('marks required steps then completes onboarding — completedAt is set', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const onboardingRepo = createOnboardingRepository(tx);

      await onboardingRepo.createProgress(provider.providerId);

      // Mark all required steps (1, 2, 3, 4, 7)
      await onboardingRepo.markStepCompleted(provider.providerId, 1);
      await onboardingRepo.markStepCompleted(provider.providerId, 2);
      await onboardingRepo.markStepCompleted(provider.providerId, 3);
      await onboardingRepo.markStepCompleted(provider.providerId, 4);
      await onboardingRepo.markStepCompleted(provider.providerId, 7);

      const completed = await onboardingRepo.markOnboardingCompleted(
        provider.providerId,
      );

      expect(completed.completedAt).not.toBeNull();
      expect(completed.completedAt).toBeInstanceOf(Date);
      expect(completed.step1Completed).toBe(true);
      expect(completed.step2Completed).toBe(true);
      expect(completed.step3Completed).toBe(true);
      expect(completed.step4Completed).toBe(true);
      expect(completed.step7Completed).toBe(true);
    }));

  // -------------------------------------------------------------------------
  // 4. Try markOnboardingCompleted with incomplete steps -> throws BusinessRuleError
  // -------------------------------------------------------------------------
  it('throws BusinessRuleError when trying to complete onboarding with incomplete steps', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const onboardingRepo = createOnboardingRepository(tx);

      await onboardingRepo.createProgress(provider.providerId);

      // Only complete steps 1 and 2 — missing 3, 4, 7
      await onboardingRepo.markStepCompleted(provider.providerId, 1);
      await onboardingRepo.markStepCompleted(provider.providerId, 2);

      await expect(
        onboardingRepo.markOnboardingCompleted(provider.providerId),
      ).rejects.toThrow(BusinessRuleError);

      // Verify the error message mentions incomplete steps
      try {
        await onboardingRepo.markOnboardingCompleted(provider.providerId);
      } catch (err) {
        expect(err).toBeInstanceOf(BusinessRuleError);
        expect((err as BusinessRuleError).message).toContain(
          'required steps incomplete',
        );
      }
    }));

  // -------------------------------------------------------------------------
  // 5. Create IMA record -> findLatestImaRecord returns it
  // -------------------------------------------------------------------------
  it('creates an IMA record and retrieves it via findLatestImaRecord', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const onboardingRepo = createOnboardingRepository(tx);

      const ima = await onboardingRepo.createImaRecord({
        providerId: provider.providerId,
        templateVersion: '1.0.0',
        documentHash: 'abc123def456',
        ipAddress: '127.0.0.1',
        userAgent: 'vitest-integration',
      });

      expect(ima).toBeDefined();
      expect(ima.providerId).toBe(provider.providerId);
      expect(ima.templateVersion).toBe('1.0.0');
      expect(ima.documentHash).toBe('abc123def456');
      expect(ima.acknowledgedAt).toBeInstanceOf(Date);

      // Verify findLatestImaRecord returns it
      const latest = await onboardingRepo.findLatestImaRecord(
        provider.providerId,
      );
      expect(latest).not.toBeNull();
      expect(latest!.templateVersion).toBe('1.0.0');
      expect(latest!.documentHash).toBe('abc123def456');
    }));

  // -------------------------------------------------------------------------
  // 6. Full flow: user -> provider -> onboarding -> steps -> IMA -> complete
  // -------------------------------------------------------------------------
  it('full onboarding flow: user -> provider -> steps 1-4,7 -> IMA -> mark completed -> all fields correct', () =>
    withTestTransaction(db, async (tx) => {
      // Step A: Create user
      const userRepo = createUserRepository(tx);
      const user = await createTestUser(tx);

      // Verify user exists
      const foundUser = await userRepo.findUserById(user.userId);
      expect(foundUser).toBeDefined();
      expect(foundUser!.userId).toBe(user.userId);

      // Step B: Create provider profile
      const providerRepo = createProviderRepository(tx);
      const provider = await providerRepo.createProvider({
        providerId: user.userId,
        billingNumber: 'BN99999',
        cpsaRegistrationNumber: 'CPSA99999',
        firstName: 'Integration',
        lastName: 'TestDoc',
        specialtyCode: '01',
        physicianType: 'SP',
      });
      expect(provider.providerId).toBe(user.userId);
      expect(provider.billingNumber).toBe('BN99999');

      // Step C: Create onboarding progress
      const onboardingRepo = createOnboardingRepository(tx);
      const progress = await onboardingRepo.createProgress(
        provider.providerId,
      );
      expect(progress.step1Completed).toBe(false);

      // Step D: Complete all required onboarding steps
      await onboardingRepo.markStepCompleted(provider.providerId, 1);
      await onboardingRepo.markStepCompleted(provider.providerId, 2);
      await onboardingRepo.markStepCompleted(provider.providerId, 3);
      await onboardingRepo.markStepCompleted(provider.providerId, 4);
      await onboardingRepo.markStepCompleted(provider.providerId, 7);

      // Step E: Create IMA acknowledgement record
      const ima = await onboardingRepo.createImaRecord({
        providerId: provider.providerId,
        templateVersion: '1.0.0',
        documentHash: 'sha256-full-flow-test',
        ipAddress: '10.0.0.1',
        userAgent: 'vitest-full-flow',
      });
      expect(ima.templateVersion).toBe('1.0.0');

      // Step F: Mark onboarding completed
      const completed = await onboardingRepo.markOnboardingCompleted(
        provider.providerId,
      );
      expect(completed.completedAt).not.toBeNull();
      expect(completed.completedAt).toBeInstanceOf(Date);
      expect(completed.step1Completed).toBe(true);
      expect(completed.step2Completed).toBe(true);
      expect(completed.step3Completed).toBe(true);
      expect(completed.step4Completed).toBe(true);
      expect(completed.step7Completed).toBe(true);

      // Step G: Verify the full state via findProgressByProviderId
      const finalProgress = await onboardingRepo.findProgressByProviderId(
        provider.providerId,
      );
      expect(finalProgress).not.toBeNull();
      expect(finalProgress!.completedAt).not.toBeNull();
      expect(finalProgress!.step1Completed).toBe(true);
      expect(finalProgress!.step2Completed).toBe(true);
      expect(finalProgress!.step3Completed).toBe(true);
      expect(finalProgress!.step4Completed).toBe(true);
      expect(finalProgress!.step7Completed).toBe(true);

      // Step H: Verify IMA record via findLatestImaRecord
      const latestIma = await onboardingRepo.findLatestImaRecord(
        provider.providerId,
      );
      expect(latestIma).not.toBeNull();
      expect(latestIma!.templateVersion).toBe('1.0.0');

      // Step I: Verify provider record is still intact
      const finalProvider = await providerRepo.findProviderById(
        provider.providerId,
      );
      expect(finalProvider).toBeDefined();
      expect(finalProvider!.firstName).toBe('Integration');
      expect(finalProvider!.lastName).toBe('TestDoc');
      expect(finalProvider!.specialtyCode).toBe('01');
    }));
});
