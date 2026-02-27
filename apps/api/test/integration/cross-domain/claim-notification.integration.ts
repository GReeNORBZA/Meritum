/**
 * Cross-Domain Integration Tests — Claim + Notification
 *
 * Validates workflows that span the Claim (Domain 4), Notification (Domain 9),
 * and IAM (Domain 1) repositories/services against a real PostgreSQL database.
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
import { createClaimRepository } from '../../../src/domains/claim/claim.repository.js';
import { createNotificationRepository } from '../../../src/domains/notification/notification.repository.js';
import {
  processEvent,
  resolveRecipients,
  type NotificationServiceDeps,
  type EmitEvent,
} from '../../../src/domains/notification/notification.service.js';
import {
  createDelegateLinkageRepository,
  createAuditLogRepository,
} from '../../../src/domains/iam/iam.repository.js';
import { delegateLinkages } from '@meritum/shared/schemas/db/iam.schema.js';

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

/** Build the real NotificationServiceDeps using real repos inside a tx. */
function buildDeps(tx: NodePgDatabase): NotificationServiceDeps {
  return {
    notificationRepo: createNotificationRepository(tx),
    delegateLinkageRepo: createDelegateLinkageRepository(tx),
    auditRepo: createAuditLogRepository(tx),
  };
}

/** Reusable scaffold: user + provider + patient + claim. */
async function scaffold(tx: NodePgDatabase) {
  const provider = await createTestProvider(tx);
  const patient = await createTestPatient(tx, { providerId: provider.userId });
  const claimRepo = createClaimRepository(tx);
  const claim = await claimRepo.createClaim({
    physicianId: provider.userId,
    patientId: patient.patientId,
    claimType: 'AHCIP',
    dateOfService: '2026-01-15',
    importSource: 'MANUAL',
  });
  return { provider, patient, claim };
}

// ===========================================================================
// Claim-Notification Cross-Domain Tests
// ===========================================================================

describe('Cross-Domain: Claim + Notification', () => {
  // -------------------------------------------------------------------------
  // 1. CLAIM_VALIDATED -> notification created for physician
  // -------------------------------------------------------------------------
  it('processEvent with CLAIM_VALIDATED creates notification for the physician', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const deps = buildDeps(tx);

      const event: EmitEvent = {
        eventType: 'CLAIM_VALIDATED',
        physicianId: provider.userId,
        metadata: { claimId: 'test-claim-001' },
      };

      const notifications = await processEvent(deps, event);

      expect(notifications).toHaveLength(1);
      expect(notifications[0].recipientId).toBe(provider.userId);
      expect(notifications[0].eventType).toBe('CLAIM_VALIDATED');
    }));

  // -------------------------------------------------------------------------
  // 2. CLAIM_REJECTED -> notification with HIGH priority
  // -------------------------------------------------------------------------
  it('processEvent with CLAIM_REJECTED creates notification with HIGH priority', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const deps = buildDeps(tx);

      const event: EmitEvent = {
        eventType: 'CLAIM_REJECTED',
        physicianId: provider.userId,
        metadata: { claimId: 'test-claim-002', reason: 'Invalid HSC code' },
      };

      const notifications = await processEvent(deps, event);

      expect(notifications).toHaveLength(1);
      expect(notifications[0].priority).toBe('HIGH');
      expect(notifications[0].eventType).toBe('CLAIM_REJECTED');
    }));

  // -------------------------------------------------------------------------
  // 3. BATCH_ASSEMBLED -> notification created with metadata
  // -------------------------------------------------------------------------
  it('processEvent with BATCH_ASSEMBLED creates notification with metadata', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const deps = buildDeps(tx);

      const metadata = { batchId: 'batch-001', claimCount: 5 };
      const event: EmitEvent = {
        eventType: 'BATCH_ASSEMBLED',
        physicianId: provider.userId,
        metadata,
      };

      const notifications = await processEvent(deps, event);

      expect(notifications).toHaveLength(1);
      expect(notifications[0].eventType).toBe('BATCH_ASSEMBLED');
      expect(notifications[0].metadata).toEqual(metadata);
    }));

  // -------------------------------------------------------------------------
  // 4. DEADLINE_7_DAY -> notification created for physician
  // -------------------------------------------------------------------------
  it('processEvent with DEADLINE_7_DAY creates notification for physician', () =>
    withTestTransaction(db, async (tx) => {
      const { provider } = await scaffold(tx);
      const deps = buildDeps(tx);

      const event: EmitEvent = {
        eventType: 'DEADLINE_7_DAY',
        physicianId: provider.userId,
        metadata: { claimCount: 3 },
      };

      const notifications = await processEvent(deps, event);

      expect(notifications).toHaveLength(1);
      expect(notifications[0].recipientId).toBe(provider.userId);
      expect(notifications[0].eventType).toBe('DEADLINE_7_DAY');
      expect(notifications[0].priority).toBe('MEDIUM');
    }));

  // -------------------------------------------------------------------------
  // 5. resolveRecipients with delegate having CLAIM_VIEW permission
  // -------------------------------------------------------------------------
  it('resolveRecipients includes delegate with CLAIM_VIEW permission for CLAIM_VALIDATED', () =>
    withTestTransaction(db, async (tx) => {
      const physician = await createTestUser(tx, { role: 'PHYSICIAN' });
      const delegate = await createTestUser(tx, {
        role: 'DELEGATE',
        email: `delegate-${Date.now()}@meritum.test`,
      });
      const deps = buildDeps(tx);

      // Insert delegate linkage with CLAIM_VIEW permission
      await tx.insert(delegateLinkages).values({
        physicianUserId: physician.userId,
        delegateUserId: delegate.userId,
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
      });

      const recipients = await resolveRecipients(
        deps,
        physician.userId,
        'CLAIM_VALIDATED',
      );

      expect(recipients).toHaveLength(2);
      expect(recipients[0].userId).toBe(physician.userId);
      expect(recipients[0].isDelegate).toBe(false);
      expect(recipients[1].userId).toBe(delegate.userId);
      expect(recipients[1].isDelegate).toBe(true);
    }));

  // -------------------------------------------------------------------------
  // 6. resolveRecipients with delegate lacking CLAIM_VIEW permission
  // -------------------------------------------------------------------------
  it('resolveRecipients excludes delegate without CLAIM_VIEW permission for CLAIM_VALIDATED', () =>
    withTestTransaction(db, async (tx) => {
      const physician = await createTestUser(tx, { role: 'PHYSICIAN' });
      const delegate = await createTestUser(tx, {
        role: 'DELEGATE',
        email: `delegate-no-perm-${Date.now()}@meritum.test`,
      });
      const deps = buildDeps(tx);

      // Insert delegate linkage with only ANALYTICS_VIEW permission (no CLAIM_VIEW)
      await tx.insert(delegateLinkages).values({
        physicianUserId: physician.userId,
        delegateUserId: delegate.userId,
        permissions: ['ANALYTICS_VIEW'],
        canApproveBatches: false,
      });

      const recipients = await resolveRecipients(
        deps,
        physician.userId,
        'CLAIM_VALIDATED',
      );

      // Should only include the physician, not the delegate
      expect(recipients).toHaveLength(1);
      expect(recipients[0].userId).toBe(physician.userId);
      expect(recipients[0].isDelegate).toBe(false);
    }));

  // -------------------------------------------------------------------------
  // 7. processEvent creates notification for each recipient (physician + delegate)
  // -------------------------------------------------------------------------
  it('processEvent creates a notification for physician and qualifying delegate', () =>
    withTestTransaction(db, async (tx) => {
      const physician = await createTestUser(tx, { role: 'PHYSICIAN' });
      const delegate = await createTestUser(tx, {
        role: 'DELEGATE',
        email: `delegate-multi-${Date.now()}@meritum.test`,
      });
      const deps = buildDeps(tx);

      // Insert delegate linkage with CLAIM_VIEW permission
      await tx.insert(delegateLinkages).values({
        physicianUserId: physician.userId,
        delegateUserId: delegate.userId,
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
      });

      const event: EmitEvent = {
        eventType: 'CLAIM_VALIDATED',
        physicianId: physician.userId,
        metadata: { claimId: 'claim-multi-001' },
      };

      const notifications = await processEvent(deps, event);

      expect(notifications).toHaveLength(2);

      // Find physician's notification
      const physicianNotif = notifications.find(
        (n) => n.recipientId === physician.userId,
      );
      expect(physicianNotif).toBeDefined();
      expect(physicianNotif!.eventType).toBe('CLAIM_VALIDATED');

      // Find delegate's notification
      const delegateNotif = notifications.find(
        (n) => n.recipientId === delegate.userId,
      );
      expect(delegateNotif).toBeDefined();
      expect(delegateNotif!.eventType).toBe('CLAIM_VALIDATED');
      expect(delegateNotif!.recipientId).toBe(delegate.userId);
    }));

  // -------------------------------------------------------------------------
  // 8. processEvent with unknown event type -> still creates notification (fallback)
  // -------------------------------------------------------------------------
  it('processEvent with unknown event type creates notification using fallback content', () =>
    withTestTransaction(db, async (tx) => {
      const physician = await createTestUser(tx, { role: 'PHYSICIAN' });
      const deps = buildDeps(tx);

      const event: EmitEvent = {
        eventType: 'COMPLETELY_UNKNOWN_EVENT',
        physicianId: physician.userId,
        metadata: { foo: 'bar' },
      };

      const notifications = await processEvent(deps, event);

      expect(notifications).toHaveLength(1);
      expect(notifications[0].recipientId).toBe(physician.userId);
      expect(notifications[0].eventType).toBe('COMPLETELY_UNKNOWN_EVENT');
      // Fallback content uses eventType as the title
      expect(notifications[0].title).toBe('COMPLETELY_UNKNOWN_EVENT');
      expect(notifications[0].body).toBe('Event: COMPLETELY_UNKNOWN_EVENT');
    }));
});
