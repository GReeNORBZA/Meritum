/**
 * Concurrent Access Tests
 *
 * Verifies optimistic concurrency control and race condition handling against
 * real PostgreSQL using Promise.all() / Promise.allSettled().
 *
 * IMPORTANT: These tests do NOT use withTestTransaction because concurrent
 * operations need separate transactions to actually race. The test DB is
 * disposable (created per test run via global-setup), so leftover rows are
 * acceptable. Where practical, tests clean up after themselves.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import crypto from 'node:crypto';

import { setupTestDb, teardownTestDb, getTestDb } from '../fixtures/db.js';
import {
  createTestProvider,
  createTestPatient,
  createTestNotification,
} from '../fixtures/factories.js';
import { createClaimRepository } from '../../src/domains/claim/claim.repository.js';
import { createNotificationRepository } from '../../src/domains/notification/notification.repository.js';
import { createSessionRepository } from '../../src/domains/iam/iam.repository.js';
import { ConflictError } from '../../src/lib/errors.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid InsertClaim payload. */
function claimData(
  physicianId: string,
  patientId: string,
  overrides: Record<string, unknown> = {},
) {
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

/** Reusable scaffold: provider + patient ready for claim creation. */
async function scaffold(db: NodePgDatabase) {
  const provider = await createTestProvider(db);
  const patient = await createTestPatient(db, { providerId: provider.userId });
  return { provider, patient };
}

// ===========================================================================
// Test Suite
// ===========================================================================

describe('Concurrent Access Tests', () => {
  let db: NodePgDatabase;

  beforeAll(async () => {
    await setupTestDb();
    db = getTestDb();
  });

  afterAll(async () => {
    await teardownTestDb();
  });

  // -------------------------------------------------------------------------
  // 1. Optimistic concurrency on state transition
  // -------------------------------------------------------------------------
  it('rejects concurrent state transitions on the same claim', async () => {
    const { provider, patient } = await scaffold(db);
    const repo = createClaimRepository(db);

    const claim = await repo.createClaim(
      claimData(provider.userId, patient.patientId),
    );

    // Fire two identical DRAFT -> VALIDATED transitions concurrently.
    // The first UPDATE to match state=DRAFT wins; the second finds no rows.
    const results = await Promise.allSettled([
      repo.transitionState(claim.claimId, provider.userId, 'DRAFT', 'VALIDATED'),
      repo.transitionState(claim.claimId, provider.userId, 'DRAFT', 'VALIDATED'),
    ]);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      ConflictError,
    );
  });

  // -------------------------------------------------------------------------
  // 2. Bulk transition atomicity — partial state mismatch
  // -------------------------------------------------------------------------
  it('rejects bulk transition when some claims have already moved state', async () => {
    const { provider, patient } = await scaffold(db);
    const repo = createClaimRepository(db);

    // Create 3 DRAFT claims
    const [c1, c2, c3] = await Promise.all([
      repo.createClaim(claimData(provider.userId, patient.patientId)),
      repo.createClaim(claimData(provider.userId, patient.patientId)),
      repo.createClaim(claimData(provider.userId, patient.patientId)),
    ]);

    // Transition c1 and c2 to VALIDATED — they leave DRAFT state
    await repo.transitionState(c1.claimId, provider.userId, 'DRAFT', 'VALIDATED');
    await repo.transitionState(c2.claimId, provider.userId, 'DRAFT', 'VALIDATED');

    // Attempt bulk DRAFT -> SUBMITTED on all 3 — should fail because c1 & c2
    // are no longer in DRAFT
    const batchId = crypto.randomUUID();
    await expect(
      repo.bulkTransitionState(
        [c1.claimId, c2.claimId, c3.claimId],
        provider.userId,
        'DRAFT',
        'SUBMITTED',
        batchId,
      ),
    ).rejects.toThrow(ConflictError);
  });

  // -------------------------------------------------------------------------
  // 3. Soft-delete race — two concurrent deletes on the same claim
  // -------------------------------------------------------------------------
  it('allows only one soft-delete to succeed when raced', async () => {
    const { provider, patient } = await scaffold(db);
    const repo = createClaimRepository(db);

    const claim = await repo.createClaim(
      claimData(provider.userId, patient.patientId),
    );

    // Fire two concurrent soft-deletes. The WHERE clause matches
    // state=DRAFT AND deleted_at IS NULL, so only the first UPDATE
    // can match; the second finds zero rows.
    const results = await Promise.all([
      repo.softDeleteClaim(claim.claimId, provider.userId),
      repo.softDeleteClaim(claim.claimId, provider.userId),
    ]);

    const trueResults = results.filter((r) => r === true);
    const falseResults = results.filter((r) => r === false);

    expect(trueResults).toHaveLength(1);
    expect(falseResults).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // 4. Concurrent claim creation — 10 claims at once
  // -------------------------------------------------------------------------
  it('creates 10 claims concurrently with unique IDs', async () => {
    const { provider, patient } = await scaffold(db);
    const repo = createClaimRepository(db);

    const promises = Array.from({ length: 10 }, (_, i) =>
      repo.createClaim(
        claimData(provider.userId, patient.patientId, {
          dateOfService: `2026-02-${String(i + 1).padStart(2, '0')}`,
        }),
      ),
    );

    const claims = await Promise.all(promises);

    expect(claims).toHaveLength(10);

    // All claim IDs must be unique
    const ids = new Set(claims.map((c) => c.claimId));
    expect(ids.size).toBe(10);

    // All claims should belong to the same physician
    for (const c of claims) {
      expect(c.physicianId).toBe(provider.userId);
      expect(c.state).toBe('DRAFT');
    }
  });

  // -------------------------------------------------------------------------
  // 5. Import batch duplicate detection via unique constraint
  // -------------------------------------------------------------------------
  it('rejects duplicate import batch with same physician + fileHash', async () => {
    const { provider } = await scaffold(db);
    const repo = createClaimRepository(db);

    const fileHash = crypto.randomBytes(32).toString('hex');
    const batchData = {
      physicianId: provider.userId,
      fileName: 'duplicate-test.csv',
      fileHash,
      totalRows: 10,
      successCount: 0,
      errorCount: 0,
      status: 'PENDING' as const,
      createdBy: provider.userId,
    };

    // First insert succeeds
    const batch1 = await repo.createImportBatch(batchData);
    expect(batch1.importBatchId).toBeDefined();

    // Second insert with same physician + fileHash should violate the
    // unique index (import_batches_physician_file_hash_idx)
    await expect(
      repo.createImportBatch({ ...batchData, fileName: 'duplicate-test-2.csv' }),
    ).rejects.toThrow(); // DB unique constraint violation
  });

  // -------------------------------------------------------------------------
  // 6. Notification mark-all-read race — two concurrent calls
  // -------------------------------------------------------------------------
  it('handles concurrent markAllRead calls gracefully', async () => {
    const { provider } = await scaffold(db);
    const notifRepo = createNotificationRepository(db);

    // Create 5 unread notifications
    const notifs = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        createTestNotification(db, {
          recipientId: provider.userId,
          title: `Concurrent Notif ${i}`,
        }),
      ),
    );
    expect(notifs).toHaveLength(5);

    // Fire two concurrent markAllRead calls
    const results = await Promise.all([
      notifRepo.markAllRead(provider.userId),
      notifRepo.markAllRead(provider.userId),
    ]);

    // Both calls succeed. The combined count should be exactly 5
    // (one call marks some/all, the other marks the remainder or zero).
    const totalMarked = results[0] + results[1];
    expect(totalMarked).toBe(5);

    // Final state: all notifications should be read
    const unread = await notifRepo.countUnread(provider.userId);
    expect(unread).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 7. Session creation race — two sessions for same user
  // -------------------------------------------------------------------------
  it('allows concurrent session creation for the same user', async () => {
    const { provider } = await scaffold(db);
    const sessionRepo = createSessionRepository(db);

    const sessionData = (index: number) => ({
      userId: provider.userId,
      tokenHash: crypto
        .createHash('sha256')
        .update(`session-token-${index}-${crypto.randomUUID()}`)
        .digest('hex'),
      ipAddress: '127.0.0.1',
      userAgent: `vitest-concurrent-${index}`,
    });

    // Create two sessions concurrently — multiple active sessions are allowed
    const [s1, s2] = await Promise.all([
      sessionRepo.createSession(sessionData(1)),
      sessionRepo.createSession(sessionData(2)),
    ]);

    expect(s1.sessionId).toBeDefined();
    expect(s2.sessionId).toBeDefined();
    expect(s1.sessionId).not.toBe(s2.sessionId);
    expect(s1.userId).toBe(provider.userId);
    expect(s2.userId).toBe(provider.userId);
  });

  // -------------------------------------------------------------------------
  // 8. Concurrent notification creation — 20 at once
  // -------------------------------------------------------------------------
  it('creates 20 notifications concurrently without errors', async () => {
    const { provider } = await scaffold(db);

    const promises = Array.from({ length: 20 }, (_, i) =>
      createTestNotification(db, {
        recipientId: provider.userId,
        title: `Bulk Notif ${i}`,
        body: `Concurrent notification body ${i}`,
      }),
    );

    const notifications = await Promise.all(promises);

    expect(notifications).toHaveLength(20);

    // All notification IDs should be unique
    const ids = new Set(notifications.map((n) => n.notificationId));
    expect(ids.size).toBe(20);

    // All should belong to the same recipient
    for (const n of notifications) {
      expect(n.recipientId).toBe(provider.userId);
    }
  });

  // -------------------------------------------------------------------------
  // 9. Concurrent countUnread — consistent read under no writes
  // -------------------------------------------------------------------------
  it('returns consistent countUnread across 5 concurrent calls', async () => {
    const { provider } = await scaffold(db);
    const notifRepo = createNotificationRepository(db);

    // Create exactly 7 unread notifications
    await Promise.all(
      Array.from({ length: 7 }, (_, i) =>
        createTestNotification(db, {
          recipientId: provider.userId,
          title: `Count Notif ${i}`,
        }),
      ),
    );

    // Fire 5 concurrent countUnread calls — no writes happening, so all
    // should return the same number
    const counts = await Promise.all(
      Array.from({ length: 5 }, () =>
        notifRepo.countUnread(provider.userId),
      ),
    );

    // All counts should be identical
    for (const c of counts) {
      expect(c).toBe(7);
    }
  });

  // -------------------------------------------------------------------------
  // 10. Concurrent list operations under write load
  // -------------------------------------------------------------------------
  it('lists claims without errors while concurrent inserts are running', async () => {
    const { provider, patient } = await scaffold(db);
    const repo = createClaimRepository(db);

    // Seed a few initial claims so listClaims has something to return
    await Promise.all(
      Array.from({ length: 3 }, () =>
        repo.createClaim(claimData(provider.userId, patient.patientId)),
      ),
    );

    // Fire a mix of writes and reads concurrently
    const writes = Array.from({ length: 5 }, (_, i) =>
      repo.createClaim(
        claimData(provider.userId, patient.patientId, {
          dateOfService: `2026-03-${String(i + 10).padStart(2, '0')}`,
        }),
      ),
    );

    const reads = Array.from({ length: 5 }, () =>
      repo.listClaims(provider.userId, {
        page: 1,
        pageSize: 50,
      }),
    );

    const results = await Promise.allSettled([...writes, ...reads]);

    // No operation should have failed
    const rejected = results.filter((r) => r.status === 'rejected');
    expect(rejected).toHaveLength(0);

    // All writes should have produced claims
    const writeResults = results.slice(0, 5) as PromiseFulfilledResult<any>[];
    for (const wr of writeResults) {
      expect(wr.value.claimId).toBeDefined();
    }

    // All reads should have returned paginated results with at least 3 items
    // (the initial seed, possibly more if some writes completed first)
    const readResults = results.slice(5) as PromiseFulfilledResult<any>[];
    for (const rr of readResults) {
      expect(rr.value.data.length).toBeGreaterThanOrEqual(3);
      expect(rr.value.pagination).toBeDefined();
      expect(rr.value.pagination.total).toBeGreaterThanOrEqual(3);
    }
  });
});
