import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { setupTestDb, teardownTestDb, getTestDb } from '../fixtures/db.js';
import { createTestProvider, createTestPatient } from '../fixtures/factories.js';
import { createClaimRepository } from '../../src/domains/claim/claim.repository.js';
import {
  claims,
  importBatches,
  claimAuditHistory,
} from '@meritum/shared/schemas/db/claim.schema.js';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Seed helper — bulk-insert claims using Drizzle for speed
// ---------------------------------------------------------------------------

async function seedClaims(
  db: NodePgDatabase,
  physicianId: string,
  patientId: string,
  count: number,
) {
  const CHUNK_SIZE = 500;
  for (let i = 0; i < count; i += CHUNK_SIZE) {
    const batch = [];
    for (let j = 0; j < Math.min(CHUNK_SIZE, count - i); j++) {
      batch.push({
        physicianId,
        patientId,
        claimType: 'AHCIP',
        dateOfService: `2026-01-${String((j % 28) + 1).padStart(2, '0')}`,
        importSource: 'MANUAL',
        state: ['DRAFT', 'VALIDATED', 'QUEUED', 'SUBMITTED'][j % 4],
        submissionDeadline: `2026-06-${String((j % 28) + 1).padStart(2, '0')}`,
        createdBy: physicianId,
        updatedBy: physicianId,
      });
    }
    await db.insert(claims).values(batch);
  }
}

// ---------------------------------------------------------------------------
// Seed helper — bulk-insert import batches
// ---------------------------------------------------------------------------

async function seedImportBatches(
  db: NodePgDatabase,
  physicianId: string,
  count: number,
) {
  const CHUNK_SIZE = 50;
  for (let i = 0; i < count; i += CHUNK_SIZE) {
    const batch = [];
    for (let j = 0; j < Math.min(CHUNK_SIZE, count - i); j++) {
      const idx = i + j;
      batch.push({
        physicianId,
        fileName: `import-${idx}.csv`,
        fileHash: `hash${String(idx).padStart(8, '0')}`,
        totalRows: 100,
        successCount: 95,
        errorCount: 5,
        status: 'COMPLETED',
        createdBy: physicianId,
      });
    }
    await db.insert(importBatches).values(batch);
  }
}

// ---------------------------------------------------------------------------
// Seed helper — bulk-insert audit history entries
// ---------------------------------------------------------------------------

async function seedAuditHistory(
  db: NodePgDatabase,
  claimId: string,
  actorId: string,
  count: number,
) {
  const CHUNK_SIZE = 100;
  const actions = [
    'claim.created',
    'claim.validated',
    'claim.queued',
    'claim.submitted',
    'claim.updated',
  ];
  for (let i = 0; i < count; i += CHUNK_SIZE) {
    const batch = [];
    for (let j = 0; j < Math.min(CHUNK_SIZE, count - i); j++) {
      batch.push({
        claimId,
        actorId,
        action: actions[j % actions.length],
        previousState: 'DRAFT',
        newState: 'VALIDATED',
        actorContext: 'PHYSICIAN',
      });
    }
    await db.insert(claimAuditHistory).values(batch);
  }
}

// ---------------------------------------------------------------------------
// Performance Tests
// ---------------------------------------------------------------------------

describe('Claim Query Performance', { timeout: 120_000 }, () => {
  let db: NodePgDatabase;
  let repo: ReturnType<typeof createClaimRepository>;
  let physicianId: string;
  let patientId: string;

  // A single claim used for audit-history seeding
  let auditTargetClaimId: string;

  // Claim IDs used for the bulk-transition test (seeded separately as DRAFT)
  let bulkTransitionClaimIds: string[] = [];

  afterAll(async () => {
    await teardownTestDb();
  });

  beforeAll(async () => {
    await setupTestDb();
    db = getTestDb();
    repo = createClaimRepository(db);

    // Create provider + patient
    const provider = await createTestProvider(db);
    physicianId = provider.providerId;

    const patient = await createTestPatient(db, { providerId: physicianId });
    patientId = patient.patientId;

    // -----------------------------------------------------------------------
    // Seed 10,000 claims (mixed states) for list / count / deadline / read tests
    // -----------------------------------------------------------------------
    await seedClaims(db, physicianId, patientId, 10_000);

    // -----------------------------------------------------------------------
    // Seed 500 DRAFT claims for the bulk state-transition test
    // -----------------------------------------------------------------------
    const BULK_COUNT = 500;
    const bulkBatch = [];
    for (let i = 0; i < BULK_COUNT; i++) {
      bulkBatch.push({
        physicianId,
        patientId,
        claimType: 'AHCIP',
        dateOfService: `2026-02-${String((i % 28) + 1).padStart(2, '0')}`,
        importSource: 'MANUAL',
        state: 'DRAFT',
        submissionDeadline: `2026-07-${String((i % 28) + 1).padStart(2, '0')}`,
        createdBy: physicianId,
        updatedBy: physicianId,
      });
    }
    const bulkRows = await db.insert(claims).values(bulkBatch).returning();
    bulkTransitionClaimIds = bulkRows.map((r) => r.claimId);

    // -----------------------------------------------------------------------
    // Pick one claim from the 10k set to use as audit-history target
    // -----------------------------------------------------------------------
    const [sampleClaim] = await db.select().from(claims).limit(1);
    auditTargetClaimId = sampleClaim.claimId;

    // -----------------------------------------------------------------------
    // Seed 500 audit-history entries for the audit target claim
    // -----------------------------------------------------------------------
    await seedAuditHistory(db, auditTargetClaimId, physicianId, 500);

    // -----------------------------------------------------------------------
    // Seed 100 import batches
    // -----------------------------------------------------------------------
    await seedImportBatches(db, physicianId, 100);
  }, 120_000);

  // =========================================================================
  // 1. List claims with 10,000 rows — pagination within 500ms
  // =========================================================================

  it('list claims with 10k rows returns within 500ms', async () => {
    const start = performance.now();
    const result = await repo.listClaims(physicianId, {
      page: 1,
      pageSize: 50,
      state: 'DRAFT',
    });
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500);
    expect(result.data.length).toBeLessThanOrEqual(50);
    expect(result.pagination.total).toBeGreaterThan(0);
  });

  // =========================================================================
  // 2. Count by state with 10,000 rows — within 300ms
  // =========================================================================

  it('count claims by state with 10k rows returns within 300ms', async () => {
    const start = performance.now();
    const counts = await repo.countClaimsByState(physicianId);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(300);
    expect(counts.length).toBeGreaterThan(0);

    const totalCounted = counts.reduce((sum, c) => sum + c.count, 0);
    // We seeded 10,000 + 500 bulk-transition claims
    expect(totalCounted).toBeGreaterThanOrEqual(10_000);
  });

  // =========================================================================
  // 3. Deadline query with 10,000 rows — within 500ms
  // =========================================================================

  it('deadline query with 10k rows returns within 500ms', async () => {
    const start = performance.now();
    // Use a large threshold so it actually scans data
    const approaching = await repo.findClaimsApproachingDeadline(
      physicianId,
      365,
    );
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500);
    // The result set depends on dates vs "now"; just ensure it ran
    expect(approaching).toBeDefined();
    expect(Array.isArray(approaching)).toBe(true);
  });

  // =========================================================================
  // 4. Bulk state transition (500 claims) — within 5s
  // =========================================================================

  it('bulk state transition of 500 claims completes within 5s', async () => {
    expect(bulkTransitionClaimIds.length).toBe(500);

    const batchId = crypto.randomUUID();
    const start = performance.now();
    const transitioned = await repo.bulkTransitionState(
      bulkTransitionClaimIds,
      physicianId,
      'DRAFT',
      'SUBMITTED',
      batchId,
    );
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(5000);
    expect(transitioned.length).toBe(500);
  });

  // =========================================================================
  // 5. Import batch listing (100 batches) — pagination within 300ms
  // =========================================================================

  it('import batch listing with 100 batches returns within 300ms', async () => {
    const start = performance.now();
    const result = await repo.listImportBatches(physicianId, 1, 25);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(300);
    expect(result.data.length).toBeLessThanOrEqual(25);
    expect(result.pagination.total).toBe(100);
  });

  // =========================================================================
  // 6. Claim audit history (500 entries) — paginated query within 300ms
  // =========================================================================

  it('claim audit history with 500 entries paginates within 300ms', async () => {
    const start = performance.now();
    const result = await repo.getClaimAuditHistoryPaginated(
      auditTargetClaimId,
      physicianId,
      1,
      25,
    );
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(300);
    expect(result.data.length).toBeLessThanOrEqual(25);
    expect(result.pagination.total).toBe(500);
  });

  // =========================================================================
  // 7. Concurrent read load (20 parallel list queries) — no timeouts
  // =========================================================================

  it('handles 20 concurrent reads without timeout', async () => {
    const start = performance.now();
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        repo.listClaims(physicianId, { page: i + 1, pageSize: 50 }),
      ),
    );
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(5000);
    results.forEach((r) => {
      expect(r.data).toBeDefined();
      expect(Array.isArray(r.data)).toBe(true);
    });
  });

  // =========================================================================
  // 8. Paginated deep offset (page 100 of 10,000) — within 500ms
  // =========================================================================

  it('deep pagination (page 100) with 10k rows returns within 500ms', async () => {
    const start = performance.now();
    const result = await repo.listClaims(physicianId, {
      page: 100,
      pageSize: 50,
    });
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500);
    expect(result.data.length).toBeLessThanOrEqual(50);
    expect(result.pagination.page).toBe(100);
    // With 10,500 total claims, page 100 at pageSize 50 => offset 4950, still has data
    expect(result.pagination.total).toBeGreaterThan(0);
  });
});
