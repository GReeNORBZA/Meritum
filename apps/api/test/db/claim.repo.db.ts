/**
 * Database Integration Tests — Claim Repository
 *
 * Validates every public method of createClaimRepository against a real
 * PostgreSQL database. Each test runs inside a rolled-back transaction
 * for full isolation.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import crypto from 'node:crypto';

import { getTestDb, setupTestDb, teardownTestDb } from '../fixtures/db.js';
import { withTestTransaction } from '../fixtures/helpers.js';
import {
  createTestProvider,
  createTestPatient,
} from '../fixtures/factories.js';
import { createClaimRepository } from '../../src/domains/claim/claim.repository.js';
import { ConflictError } from '../../src/lib/errors.js';

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

/** Provider + patient scaffold ready for claim creation. */
async function scaffold(tx: NodePgDatabase) {
  const provider = await createTestProvider(tx);
  const patient = await createTestPatient(tx, { providerId: provider.userId });
  return { provider, patient };
}

/** Minimal valid InsertClaim data. */
function claimData(physicianId: string, patientId: string, overrides: Record<string, unknown> = {}) {
  return {
    physicianId,
    patientId,
    claimType: 'AHCIP' as const,
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    importSource: 'MANUAL' as const,
    createdBy: physicianId,
    updatedBy: physicianId,
    ...overrides,
  };
}

// ===========================================================================
// Tests
// ===========================================================================

describe('Claim Repository', () => {
  // -------------------------------------------------------------------------
  // createClaim
  // -------------------------------------------------------------------------
  describe('createClaim', () => {
    it('creates a claim with state=DRAFT and returns all fields', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const claim = await repo.createClaim(
          claimData(provider.userId, patient.patientId),
        );

        expect(claim.claimId).toBeDefined();
        expect(claim.state).toBe('DRAFT');
        expect(claim.physicianId).toBe(provider.userId);
        expect(claim.patientId).toBe(patient.patientId);
        expect(claim.claimType).toBe('AHCIP');
        expect(claim.dateOfService).toBe('2026-01-15');
        expect(claim.importSource).toBe('MANUAL');
      }));

    it('forces state=DRAFT even when caller passes a different state', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const claim = await repo.createClaim(
          claimData(provider.userId, patient.patientId, { state: 'SUBMITTED' }),
        );
        expect(claim.state).toBe('DRAFT');
      }));
  });

  // -------------------------------------------------------------------------
  // findClaimById
  // -------------------------------------------------------------------------
  describe('findClaimById', () => {
    it('returns the claim for the owning physician and undefined otherwise', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);
        const other = await createTestProvider(tx);

        const created = await repo.createClaim(claimData(provider.userId, patient.patientId));

        // Owner can find it
        const found = await repo.findClaimById(created.claimId, provider.userId);
        expect(found).toBeDefined();
        expect(found!.claimId).toBe(created.claimId);

        // Non-existent, wrong physician, and soft-deleted all return undefined
        expect(await repo.findClaimById(crypto.randomUUID(), provider.userId)).toBeUndefined();
        expect(await repo.findClaimById(created.claimId, other.userId)).toBeUndefined();

        await repo.softDeleteClaim(created.claimId, provider.userId);
        expect(await repo.findClaimById(created.claimId, provider.userId)).toBeUndefined();
      }));
  });

  // -------------------------------------------------------------------------
  // updateClaim
  // -------------------------------------------------------------------------
  describe('updateClaim', () => {
    it('updates claim fields; returns undefined for another physician', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);
        const other = await createTestProvider(tx);

        const created = await repo.createClaim(claimData(provider.userId, patient.patientId));

        const updated = await repo.updateClaim(created.claimId, provider.userId, {
          dateOfService: '2026-02-20',
        });
        expect(updated).toBeDefined();
        expect(updated!.dateOfService).toBe('2026-02-20');

        // Wrong physician
        expect(
          await repo.updateClaim(created.claimId, other.userId, { dateOfService: '2026-03-01' }),
        ).toBeUndefined();
      }));
  });

  // -------------------------------------------------------------------------
  // softDeleteClaim
  // -------------------------------------------------------------------------
  describe('softDeleteClaim', () => {
    it('soft-deletes DRAFT claims and rejects non-DRAFT claims', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const draft = await repo.createClaim(claimData(provider.userId, patient.patientId));
        expect(await repo.softDeleteClaim(draft.claimId, provider.userId)).toBe(true);

        const validated = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.transitionState(validated.claimId, provider.userId, 'DRAFT', 'VALIDATED');
        expect(await repo.softDeleteClaim(validated.claimId, provider.userId)).toBe(false);
      }));
  });

  // -------------------------------------------------------------------------
  // listClaims
  // -------------------------------------------------------------------------
  describe('listClaims', () => {
    it('returns paginated results and supports state/patientId filters', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);
        const patient2 = await createTestPatient(tx, { providerId: provider.userId, firstName: 'Bob' });

        const c1 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.createClaim(claimData(provider.userId, patient2.patientId));
        await repo.transitionState(c1.claimId, provider.userId, 'DRAFT', 'VALIDATED');

        // Pagination
        const all = await repo.listClaims(provider.userId, { page: 1, pageSize: 2 });
        expect(all.data).toHaveLength(2);
        expect(all.pagination.total).toBe(3);
        expect(all.pagination.hasMore).toBe(true);

        // Filter by state
        const byState = await repo.listClaims(provider.userId, { state: 'VALIDATED', page: 1, pageSize: 10 });
        expect(byState.data).toHaveLength(1);

        // Filter by patientId
        const byPatient = await repo.listClaims(provider.userId, { patientId: patient2.patientId, page: 1, pageSize: 10 });
        expect(byPatient.data).toHaveLength(1);
        expect(byPatient.data[0].patientId).toBe(patient2.patientId);
      }));

    it('excludes soft-deleted claims', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const c1 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.softDeleteClaim(c1.claimId, provider.userId);

        const result = await repo.listClaims(provider.userId, { page: 1, pageSize: 10 });
        expect(result.pagination.total).toBe(1);
      }));
  });

  // -------------------------------------------------------------------------
  // countClaimsByState
  // -------------------------------------------------------------------------
  describe('countClaimsByState', () => {
    it('groups claims by state and returns counts', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        await repo.createClaim(claimData(provider.userId, patient.patientId));
        const c2 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.transitionState(c2.claimId, provider.userId, 'DRAFT', 'VALIDATED');

        const counts = await repo.countClaimsByState(provider.userId);
        expect(counts.find((c) => c.state === 'DRAFT')?.count).toBe(1);
        expect(counts.find((c) => c.state === 'VALIDATED')?.count).toBe(1);
      }));
  });

  // -------------------------------------------------------------------------
  // transitionState
  // -------------------------------------------------------------------------
  describe('transitionState', () => {
    it('transitions state atomically and returns the updated claim', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const created = await repo.createClaim(claimData(provider.userId, patient.patientId));
        const transitioned = await repo.transitionState(
          created.claimId, provider.userId, 'DRAFT', 'VALIDATED',
        );
        expect(transitioned.state).toBe('VALIDATED');
        expect(transitioned.claimId).toBe(created.claimId);
      }));

    it('throws ConflictError when fromState does not match current state', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const created = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await expect(
          repo.transitionState(created.claimId, provider.userId, 'VALIDATED', 'QUEUED'),
        ).rejects.toThrow(ConflictError);
      }));
  });

  // -------------------------------------------------------------------------
  // bulkTransitionState
  // -------------------------------------------------------------------------
  describe('bulkTransitionState', () => {
    it('transitions all claims and sets submittedBatchId', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const c1 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        const c2 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.transitionState(c1.claimId, provider.userId, 'DRAFT', 'VALIDATED');
        await repo.transitionState(c2.claimId, provider.userId, 'DRAFT', 'VALIDATED');
        await repo.transitionState(c1.claimId, provider.userId, 'VALIDATED', 'QUEUED');
        await repo.transitionState(c2.claimId, provider.userId, 'VALIDATED', 'QUEUED');

        const batchId = crypto.randomUUID();
        const results = await repo.bulkTransitionState(
          [c1.claimId, c2.claimId], provider.userId, 'QUEUED', 'SUBMITTED', batchId,
        );

        expect(results).toHaveLength(2);
        expect(results.every((r) => r.state === 'SUBMITTED')).toBe(true);
        expect(results.every((r) => r.submittedBatchId === batchId)).toBe(true);
      }));

    it('throws ConflictError when not all claims match the expected state', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const c1 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        const c2 = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.transitionState(c1.claimId, provider.userId, 'DRAFT', 'VALIDATED');
        await repo.transitionState(c1.claimId, provider.userId, 'VALIDATED', 'QUEUED');
        // c2 stays DRAFT

        await expect(
          repo.bulkTransitionState(
            [c1.claimId, c2.claimId], provider.userId, 'QUEUED', 'SUBMITTED', crypto.randomUUID(),
          ),
        ).rejects.toThrow(ConflictError);
      }));
  });

  // -------------------------------------------------------------------------
  // findClaimsApproachingDeadline
  // -------------------------------------------------------------------------
  describe('findClaimsApproachingDeadline', () => {
    it('returns only claims whose deadline falls within the threshold', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const soon = new Date();
        soon.setDate(soon.getDate() + 5);
        const soonStr = soon.toISOString().split('T')[0];

        const far = new Date();
        far.setDate(far.getDate() + 60);
        const farStr = far.toISOString().split('T')[0];

        await repo.createClaim(claimData(provider.userId, patient.patientId, { submissionDeadline: soonStr }));
        await repo.createClaim(claimData(provider.userId, patient.patientId, { submissionDeadline: farStr }));

        const approaching = await repo.findClaimsApproachingDeadline(provider.userId, 10);
        expect(approaching).toHaveLength(1);
        expect(approaching[0].submissionDeadline).toBe(soonStr);
      }));
  });

  // -------------------------------------------------------------------------
  // Import Batches
  // -------------------------------------------------------------------------
  describe('Import Batches', () => {
    it('creates a batch and retrieves it by id', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const batch = await repo.createImportBatch({
          physicianId: provider.userId,
          fileName: 'claims-2026.csv',
          fileHash: crypto.randomBytes(32).toString('hex'),
          totalRows: 50,
          successCount: 0,
          errorCount: 0,
          status: 'PENDING',
          createdBy: provider.userId,
        });

        expect(batch.importBatchId).toBeDefined();
        expect(batch.status).toBe('PENDING');

        const found = await repo.findImportBatchById(batch.importBatchId, provider.userId);
        expect(found).toBeDefined();
        expect(found!.importBatchId).toBe(batch.importBatchId);
      }));

    it('updates batch status and counts', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const batch = await repo.createImportBatch({
          physicianId: provider.userId,
          fileName: 'import.csv',
          fileHash: crypto.randomBytes(32).toString('hex'),
          totalRows: 100,
          successCount: 0,
          errorCount: 0,
          status: 'PENDING',
          createdBy: provider.userId,
        });

        const updated = await repo.updateImportBatchStatus(
          batch.importBatchId, provider.userId, 'COMPLETED',
          { successCount: 95, errorCount: 5 },
        );

        expect(updated).toBeDefined();
        expect(updated!.status).toBe('COMPLETED');
        expect(updated!.successCount).toBe(95);
        expect(updated!.errorCount).toBe(5);
      }));

    it('detects duplicate imports by file hash', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);
        const hash = crypto.randomBytes(32).toString('hex');

        expect(
          await repo.findDuplicateImportByHash(provider.userId, crypto.randomBytes(32).toString('hex')),
        ).toBeUndefined();

        await repo.createImportBatch({
          physicianId: provider.userId,
          fileName: 'first-upload.csv',
          fileHash: hash,
          totalRows: 10,
          successCount: 0,
          errorCount: 0,
          status: 'COMPLETED',
          createdBy: provider.userId,
        });

        const dup = await repo.findDuplicateImportByHash(provider.userId, hash);
        expect(dup).toBeDefined();
        expect(dup!.fileName).toBe('first-upload.csv');
      }));
  });

  // -------------------------------------------------------------------------
  // Shifts
  // -------------------------------------------------------------------------
  describe('Shifts', () => {
    const facilityId = crypto.randomUUID();

    it('creates a shift with IN_PROGRESS status and retrieves it', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const shift = await repo.createShift({
          physicianId: provider.userId, facilityId,
          shiftDate: '2026-02-01', startTime: '08:00', endTime: '16:00',
          status: 'IN_PROGRESS',
        });

        expect(shift.shiftId).toBeDefined();
        expect(shift.status).toBe('IN_PROGRESS');
        expect(shift.encounterCount).toBe(0);

        const found = await repo.findShiftById(shift.shiftId, provider.userId);
        expect(found!.shiftId).toBe(shift.shiftId);
      }));

    it('updates shift status', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const shift = await repo.createShift({
          physicianId: provider.userId, facilityId,
          shiftDate: '2026-02-01', startTime: '08:00', endTime: '16:00',
          status: 'IN_PROGRESS',
        });

        const updated = await repo.updateShiftStatus(shift.shiftId, provider.userId, 'COMPLETED');
        expect(updated!.status).toBe('COMPLETED');
      }));

    it('atomically increments the encounter counter', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const shift = await repo.createShift({
          physicianId: provider.userId, facilityId,
          shiftDate: '2026-02-01', startTime: '08:00', endTime: '16:00',
          status: 'IN_PROGRESS',
        });

        await repo.incrementEncounterCount(shift.shiftId, provider.userId);
        await repo.incrementEncounterCount(shift.shiftId, provider.userId);
        const after = await repo.incrementEncounterCount(shift.shiftId, provider.userId);
        expect(after!.encounterCount).toBe(3);
      }));

    it('returns paginated shift list', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        for (let d = 1; d <= 3; d++) {
          await repo.createShift({
            physicianId: provider.userId, facilityId,
            shiftDate: `2026-01-0${d}`, startTime: '08:00', endTime: '16:00',
            status: 'IN_PROGRESS',
          });
        }

        const page1 = await repo.listShifts(provider.userId, 1, 2);
        expect(page1.data).toHaveLength(2);
        expect(page1.pagination.total).toBe(3);
        expect(page1.pagination.hasMore).toBe(true);
      }));
  });

  // -------------------------------------------------------------------------
  // Claim Templates
  // -------------------------------------------------------------------------
  describe('Claim Templates', () => {
    it('creates a template with defaults and retrieves it by id', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const template = await repo.createClaimTemplate({
          physicianId: provider.userId,
          name: 'Office Visit',
          claimType: 'AHCIP',
          templateType: 'CUSTOM',
          lineItems: [{ hscCode: '03.04A', modifiers: [] }],
        });

        expect(template.templateId).toBeDefined();
        expect(template.usageCount).toBe(0);
        expect(template.isActive).toBe(true);

        const found = await repo.findClaimTemplateById(template.templateId, provider.userId);
        expect(found!.name).toBe('Office Visit');
      }));

    it('increments usageCount and enforces physician scoping', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);
        const other = await createTestProvider(tx);

        const template = await repo.createClaimTemplate({
          physicianId: provider.userId,
          name: 'Scoped Template',
          claimType: 'AHCIP',
          templateType: 'CUSTOM',
          lineItems: [],
        });

        await repo.incrementClaimTemplateUsage(template.templateId, provider.userId);
        const after = await repo.incrementClaimTemplateUsage(template.templateId, provider.userId);
        expect(after!.usageCount).toBe(2);

        // Another physician cannot see it
        expect(await repo.findClaimTemplateById(template.templateId, other.userId)).toBeUndefined();
      }));
  });

  // -------------------------------------------------------------------------
  // Recent Referrers
  // -------------------------------------------------------------------------
  describe('Recent Referrers', () => {
    it('inserts a new referrer and increments on duplicate', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        const first = await repo.upsertRecentReferrer(provider.userId, 'CPSA12345', 'Dr. Alice');
        expect(first.useCount).toBe(1);

        const second = await repo.upsertRecentReferrer(provider.userId, 'CPSA12345', 'Dr. Alice Updated');
        expect(second.useCount).toBe(2);
        expect(second.referrerName).toBe('Dr. Alice Updated');
      }));

    it('returns referrers ordered by most recently used', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider } = await scaffold(tx);

        await repo.upsertRecentReferrer(provider.userId, 'CPSA00001', 'Dr. First');
        await repo.upsertRecentReferrer(provider.userId, 'CPSA00002', 'Dr. Second');
        await repo.upsertRecentReferrer(provider.userId, 'CPSA00001', 'Dr. First');

        const referrers = await repo.getRecentReferrers(provider.userId);
        expect(referrers).toHaveLength(2);
        expect(referrers[0].referrerCpsa).toBe('CPSA00001');
      }));
  });

  // -------------------------------------------------------------------------
  // Claim Audit History
  // -------------------------------------------------------------------------
  describe('Claim Audit History', () => {
    it('appends audit entries and returns paginated history', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);

        const claim = await repo.createClaim(claimData(provider.userId, patient.patientId));

        const audit = await repo.appendClaimAudit({
          claimId: claim.claimId,
          actorId: provider.userId,
          action: 'claim.created',
          previousState: null,
          newState: 'DRAFT',
          actorContext: 'PHYSICIAN',
        });
        expect(audit.auditId).toBeDefined();
        expect(audit.action).toBe('claim.created');

        await repo.appendClaimAudit({ claimId: claim.claimId, actorId: provider.userId, action: 'claim.validated', previousState: 'DRAFT', newState: 'VALIDATED', actorContext: 'PHYSICIAN' });
        await repo.appendClaimAudit({ claimId: claim.claimId, actorId: provider.userId, action: 'claim.queued', previousState: 'VALIDATED', newState: 'QUEUED', actorContext: 'PHYSICIAN' });

        const page = await repo.getClaimAuditHistoryPaginated(claim.claimId, provider.userId, 1, 2);
        expect(page.data).toHaveLength(2);
        expect(page.pagination.total).toBe(3);
        expect(page.pagination.hasMore).toBe(true);
      }));

    it('returns empty audit history when queried by another physician', () =>
      withTestTransaction(db, async (tx) => {
        const repo = createClaimRepository(tx);
        const { provider, patient } = await scaffold(tx);
        const other = await createTestProvider(tx);

        const claim = await repo.createClaim(claimData(provider.userId, patient.patientId));
        await repo.appendClaimAudit({ claimId: claim.claimId, actorId: provider.userId, action: 'claim.created', previousState: null, newState: 'DRAFT', actorContext: 'PHYSICIAN' });

        const page = await repo.getClaimAuditHistoryPaginated(claim.claimId, other.userId, 1, 10);
        expect(page.data).toHaveLength(0);
        expect(page.pagination.total).toBe(0);
      }));
  });
});
