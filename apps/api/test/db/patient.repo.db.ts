import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import crypto from 'node:crypto';

import { setupTestDb, teardownTestDb, getTestDb } from '../fixtures/db.js';
import { withTestTransaction } from '../fixtures/helpers.js';
import { createTestProvider, createTestPatient } from '../fixtures/factories.js';
import { createPatientRepository } from '../../src/domains/patient/patient.repository.js';

// ---------------------------------------------------------------------------
// Lifecycle: create disposable test database, run migrations, tear down after
// ---------------------------------------------------------------------------

let db: NodePgDatabase;

beforeAll(async () => {
  await setupTestDb();
  db = getTestDb();
}, 30_000);

afterAll(async () => {
  await teardownTestDb();
}, 30_000);

// ---------------------------------------------------------------------------
// Patient CRUD
// ---------------------------------------------------------------------------

describe('PatientRepository — CRUD', () => {
  it('creates a patient and returns generated fields', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);

      const patient = await repo.createPatient({
        providerId: provider.userId,
        firstName: 'Jane',
        lastName: 'Doe',
        dateOfBirth: '1990-01-15',
        gender: 'F',
        createdBy: provider.userId,
      });

      expect(patient.patientId).toBeDefined();
      expect(patient.firstName).toBe('Jane');
      expect(patient.lastName).toBe('Doe');
      expect(patient.dateOfBirth).toBe('1990-01-15');
      expect(patient.gender).toBe('F');
      expect(patient.isActive).toBe(true);
      expect(patient.createdAt).toBeDefined();
    }));

  it('findPatientById returns patient scoped to physician', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const patient = await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
      });

      const found = await repo.findPatientById(patient.patientId, provider.userId);
      expect(found).toBeDefined();
      expect(found!.patientId).toBe(patient.patientId);
    }));

  it('findPatientById returns undefined for another physician', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const providerA = await createTestProvider(tx);
      const providerB = await createTestProvider(tx);
      const patient = await createTestPatient(tx, {
        providerId: providerA.userId,
        createdBy: providerA.userId,
      });

      const found = await repo.findPatientById(patient.patientId, providerB.userId);
      expect(found).toBeUndefined();
    }));

  it('findPatientByPhn returns exact match on provider + phn', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const phn = '123456789';
      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        phn,
      });

      const found = await repo.findPatientByPhn(provider.userId, phn);
      expect(found).toBeDefined();
      expect(found!.phn).toBe(phn);
    }));

  it('updatePatient modifies fields and sets updatedAt', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const patient = await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
      });

      const updated = await repo.updatePatient(patient.patientId, provider.userId, {
        firstName: 'Updated',
        phone: '403-555-1234',
      });

      expect(updated).toBeDefined();
      expect(updated!.firstName).toBe('Updated');
      expect(updated!.phone).toBe('403-555-1234');
      expect(updated!.updatedAt.getTime()).toBeGreaterThanOrEqual(
        patient.updatedAt.getTime(),
      );
    }));

  it('deactivatePatient sets isActive to false', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const patient = await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
      });

      const deactivated = await repo.deactivatePatient(patient.patientId, provider.userId);
      expect(deactivated).toBeDefined();
      expect(deactivated!.isActive).toBe(false);
    }));

  it('reactivatePatient sets isActive back to true', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const patient = await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
      });

      await repo.deactivatePatient(patient.patientId, provider.userId);
      const reactivated = await repo.reactivatePatient(patient.patientId, provider.userId);
      expect(reactivated).toBeDefined();
      expect(reactivated!.isActive).toBe(true);
    }));
});

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

describe('PatientRepository — Search', () => {
  it('searchByPhn returns active patient with matching PHN', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const phn = '987654321';
      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        phn,
      });

      const result = await repo.searchByPhn(provider.userId, phn);
      expect(result).toBeDefined();
      expect(result!.phn).toBe(phn);
    }));

  it('searchByPhn returns undefined for deactivated patient', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const phn = '111222333';
      const patient = await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        phn,
      });

      await repo.deactivatePatient(patient.patientId, provider.userId);

      const result = await repo.searchByPhn(provider.userId, phn);
      expect(result).toBeUndefined();
    }));

  it('searchByName returns paginated results with case-insensitive match', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);

      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        firstName: 'Alice',
        lastName: 'Smith',
      });
      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        firstName: 'Bob',
        lastName: 'Smithson',
      });
      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        firstName: 'Carol',
        lastName: 'Jones',
      });

      const result = await repo.searchByName(provider.userId, 'smith', 1, 10);
      expect(result.data.length).toBe(2);
      expect(result.pagination.total).toBe(2);
      expect(result.pagination.page).toBe(1);
      expect(result.pagination.hasMore).toBe(false);
    }));

  it('searchByDob returns patients matching date of birth', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);

      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        firstName: 'Dave',
        lastName: 'Lee',
        dateOfBirth: '1985-06-20',
      });
      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        firstName: 'Eve',
        lastName: 'Kim',
        dateOfBirth: '1985-06-20',
      });
      await createTestPatient(tx, {
        providerId: provider.userId,
        createdBy: provider.userId,
        firstName: 'Frank',
        lastName: 'Ng',
        dateOfBirth: '2000-12-01',
      });

      const result = await repo.searchByDob(
        provider.userId,
        new Date('1985-06-20'),
        1,
        10,
      );
      expect(result.data.length).toBe(2);
      expect(result.pagination.total).toBe(2);
      expect(result.data.every((p) => p.dateOfBirth === '1985-06-20')).toBe(true);
    }));
});

// ---------------------------------------------------------------------------
// Import Batches
// ---------------------------------------------------------------------------

describe('PatientRepository — Import Batches', () => {
  it('createImportBatch inserts a batch record', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const fileHash = crypto.randomBytes(32).toString('hex');

      const batch = await repo.createImportBatch({
        physicianId: provider.userId,
        fileName: 'patients.csv',
        fileHash,
        totalRows: 50,
        createdBy: provider.userId,
      });

      expect(batch.importId).toBeDefined();
      expect(batch.fileName).toBe('patients.csv');
      expect(batch.fileHash).toBe(fileHash);
      expect(batch.totalRows).toBe(50);
      expect(batch.status).toBe('PENDING');
    }));

  it('findImportByFileHash detects duplicate file upload', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const fileHash = crypto.randomBytes(32).toString('hex');

      await repo.createImportBatch({
        physicianId: provider.userId,
        fileName: 'patients.csv',
        fileHash,
        createdBy: provider.userId,
      });

      const duplicate = await repo.findImportByFileHash(provider.userId, fileHash);
      expect(duplicate).toBeDefined();
      expect(duplicate!.fileHash).toBe(fileHash);
    }));

  it('findImportByFileHash returns undefined for unknown hash', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);

      const result = await repo.findImportByFileHash(
        provider.userId,
        'nonexistent_hash',
      );
      expect(result).toBeUndefined();
    }));
});

// ---------------------------------------------------------------------------
// Eligibility Cache
// ---------------------------------------------------------------------------

describe('PatientRepository — Eligibility Cache', () => {
  it('setCachedEligibility inserts and getCachedEligibility retrieves non-expired entry', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const phnHash = crypto.createHash('sha256').update('123456789').digest('hex');
      const futureExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // +24 hours

      const cached = await repo.setCachedEligibility({
        providerId: provider.userId,
        phnHash,
        isEligible: true,
        verifiedAt: new Date(),
        expiresAt: futureExpiry,
      });

      expect(cached.cacheId).toBeDefined();
      expect(cached.isEligible).toBe(true);

      const retrieved = await repo.getCachedEligibility(provider.userId, phnHash);
      expect(retrieved).toBeDefined();
      expect(retrieved!.cacheId).toBe(cached.cacheId);
      expect(retrieved!.isEligible).toBe(true);
    }));

  it('getCachedEligibility returns undefined for expired entry', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const phnHash = crypto.createHash('sha256').update('expired_phn').digest('hex');
      const pastExpiry = new Date(Date.now() - 60 * 1000); // 1 minute ago

      await repo.setCachedEligibility({
        providerId: provider.userId,
        phnHash,
        isEligible: false,
        verifiedAt: new Date(Date.now() - 2 * 60 * 1000),
        expiresAt: pastExpiry,
      });

      const result = await repo.getCachedEligibility(provider.userId, phnHash);
      expect(result).toBeUndefined();
    }));

  it('setCachedEligibility upserts on conflict (provider + phnHash)', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createPatientRepository(tx);
      const provider = await createTestProvider(tx);
      const phnHash = crypto.createHash('sha256').update('upsert_phn').digest('hex');
      const futureExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

      // First insert: not eligible
      await repo.setCachedEligibility({
        providerId: provider.userId,
        phnHash,
        isEligible: false,
        verifiedAt: new Date(),
        expiresAt: futureExpiry,
      });

      // Upsert: now eligible
      const upserted = await repo.setCachedEligibility({
        providerId: provider.userId,
        phnHash,
        isEligible: true,
        verifiedAt: new Date(),
        expiresAt: futureExpiry,
      });

      expect(upserted.isEligible).toBe(true);

      // Only one row should exist
      const retrieved = await repo.getCachedEligibility(provider.userId, phnHash);
      expect(retrieved).toBeDefined();
      expect(retrieved!.isEligible).toBe(true);
    }));
});
