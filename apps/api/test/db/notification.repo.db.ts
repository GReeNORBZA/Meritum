import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';

import { setupTestDb, teardownTestDb, getTestDb } from '../fixtures/db.js';
import { withTestTransaction } from '../fixtures/helpers.js';
import { createTestUser, createTestNotification } from '../fixtures/factories.js';
import { createNotificationRepository } from '../../src/domains/notification/notification.repository.js';

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
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_CHANNELS = { in_app: true, email: false, push: false };

// ---------------------------------------------------------------------------
// Core Notification CRUD
// ---------------------------------------------------------------------------

describe('NotificationRepository — Core CRUD', () => {
  it('creates a notification and returns generated fields', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      const notif = await repo.createNotification({
        recipientId: user.userId,
        eventType: 'CLAIM_VALIDATED',
        priority: 'MEDIUM',
        title: 'Claim validated',
        body: 'Your claim has been validated.',
        channelsDelivered: DEFAULT_CHANNELS,
      });

      expect(notif.notificationId).toBeDefined();
      expect(notif.recipientId).toBe(user.userId);
      expect(notif.eventType).toBe('CLAIM_VALIDATED');
      expect(notif.priority).toBe('MEDIUM');
      expect(notif.title).toBe('Claim validated');
      expect(notif.body).toBe('Your claim has been validated.');
      expect(notif.readAt).toBeNull();
      expect(notif.dismissedAt).toBeNull();
      expect(notif.createdAt).toBeDefined();
    }));

  it('createNotificationsBatch inserts multiple notifications and returns count', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      const count = await repo.createNotificationsBatch([
        {
          recipientId: user.userId,
          eventType: 'CLAIM_VALIDATED',
          priority: 'LOW',
          title: 'Batch 1',
          body: 'Body 1',
          channelsDelivered: DEFAULT_CHANNELS,
        },
        {
          recipientId: user.userId,
          eventType: 'CLAIM_REJECTED',
          priority: 'HIGH',
          title: 'Batch 2',
          body: 'Body 2',
          channelsDelivered: DEFAULT_CHANNELS,
        },
        {
          recipientId: user.userId,
          eventType: 'CLAIM_VALIDATED',
          priority: 'MEDIUM',
          title: 'Batch 3',
          body: 'Body 3',
          channelsDelivered: DEFAULT_CHANNELS,
        },
      ]);

      expect(count).toBe(3);
    }));

  it('createNotificationsBatch returns 0 for empty array', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);

      const count = await repo.createNotificationsBatch([]);
      expect(count).toBe(0);
    }));

  it('findNotificationById returns notification scoped to recipient', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);
      const notif = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });

      const found = await repo.findNotificationById(notif.notificationId, user.userId);
      expect(found).toBeDefined();
      expect(found!.notificationId).toBe(notif.notificationId);
    }));

  it('findNotificationById returns undefined for another recipient', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const userA = await createTestUser(tx);
      const userB = await createTestUser(tx);
      const notif = await createTestNotification(tx, {
        recipientId: userA.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });

      const found = await repo.findNotificationById(notif.notificationId, userB.userId);
      expect(found).toBeUndefined();
    }));
});

// ---------------------------------------------------------------------------
// Listing, Counting, Read/Dismiss
// ---------------------------------------------------------------------------

describe('NotificationRepository — List, Count, Read & Dismiss', () => {
  it('listNotifications returns paginated results excluding dismissed', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      // Create 3 notifications, dismiss one
      await createTestNotification(tx, {
        recipientId: user.userId,
        title: 'N1',
        channelsDelivered: DEFAULT_CHANNELS,
      });
      const dismissed = await createTestNotification(tx, {
        recipientId: user.userId,
        title: 'N2',
        channelsDelivered: DEFAULT_CHANNELS,
      });
      await createTestNotification(tx, {
        recipientId: user.userId,
        title: 'N3',
        channelsDelivered: DEFAULT_CHANNELS,
      });

      await repo.dismiss(dismissed.notificationId, user.userId);

      const list = await repo.listNotifications(user.userId, {
        limit: 10,
        offset: 0,
      });

      expect(list.length).toBe(2);
      expect(list.every((n) => n.dismissedAt === null)).toBe(true);
    }));

  it('listNotifications with unreadOnly filters out read notifications', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      const read = await createTestNotification(tx, {
        recipientId: user.userId,
        title: 'Read',
        channelsDelivered: DEFAULT_CHANNELS,
      });
      await createTestNotification(tx, {
        recipientId: user.userId,
        title: 'Unread',
        channelsDelivered: DEFAULT_CHANNELS,
      });

      await repo.markRead(read.notificationId, user.userId);

      const list = await repo.listNotifications(user.userId, {
        unreadOnly: true,
        limit: 10,
        offset: 0,
      });

      expect(list.length).toBe(1);
      expect(list[0].title).toBe('Unread');
    }));

  it('countUnread returns count of unread, undismissed notifications', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      const toRead = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      const toDismiss = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });

      await repo.markRead(toRead.notificationId, user.userId);
      await repo.dismiss(toDismiss.notificationId, user.userId);

      const count = await repo.countUnread(user.userId);
      expect(count).toBe(2);
    }));

  it('markRead sets readAt timestamp', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);
      const notif = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });

      const updated = await repo.markRead(notif.notificationId, user.userId);
      expect(updated).toBeDefined();
      expect(updated!.readAt).toBeInstanceOf(Date);
    }));

  it('markAllRead marks all unread notifications as read and returns count', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      const alreadyRead = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      await repo.markRead(alreadyRead.notificationId, user.userId);

      const count = await repo.markAllRead(user.userId);
      expect(count).toBe(2);

      // Verify all are now read
      const unread = await repo.countUnread(user.userId);
      expect(unread).toBe(0);
    }));

  it('dismiss sets dismissedAt timestamp', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);
      const notif = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });

      const dismissed = await repo.dismiss(notif.notificationId, user.userId);
      expect(dismissed).toBeDefined();
      expect(dismissed!.dismissedAt).toBeInstanceOf(Date);
    }));
});

// ---------------------------------------------------------------------------
// Email Delivery Log
// ---------------------------------------------------------------------------

describe('NotificationRepository — Delivery Log', () => {
  it('createDeliveryLog and updateDeliveryStatus', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);
      const notif = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: { in_app: true, email: true, push: false },
      });

      const log = await repo.createDeliveryLog({
        notificationId: notif.notificationId,
        recipientEmail: 'test@meritum.test',
        templateId: 'claim_validated_v1',
        status: 'QUEUED',
      });

      expect(log.deliveryId).toBeDefined();
      expect(log.status).toBe('QUEUED');
      expect(log.retryCount).toBe(0);

      const sentAt = new Date();
      const updated = await repo.updateDeliveryStatus(log.deliveryId, 'SENT', {
        providerMessageId: 'ses-msg-123',
        sentAt,
      });

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('SENT');
      expect(updated!.providerMessageId).toBe('ses-msg-123');
    }));

  it('findPendingRetries returns QUEUED/FAILED entries with retryCount < 4', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);
      const notif = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: { in_app: true, email: true, push: false },
      });

      // QUEUED with no nextRetryAt (should be found)
      await repo.createDeliveryLog({
        notificationId: notif.notificationId,
        recipientEmail: 'a@meritum.test',
        templateId: 'tpl_a',
        status: 'QUEUED',
      });

      // SENT (should NOT be found)
      await repo.createDeliveryLog({
        notificationId: notif.notificationId,
        recipientEmail: 'b@meritum.test',
        templateId: 'tpl_b',
        status: 'SENT',
      });

      const pending = await repo.findPendingRetries();
      expect(pending.length).toBeGreaterThanOrEqual(1);
      expect(pending.every((p) => ['QUEUED', 'FAILED'].includes(p.status))).toBe(true);
    }));
});

// ---------------------------------------------------------------------------
// Digest Queue
// ---------------------------------------------------------------------------

describe('NotificationRepository — Digest Queue', () => {
  it('addToDigestQueue, findPendingDigestItems, and markDigestItemsSent', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);
      const notifA = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });
      const notifB = await createTestNotification(tx, {
        recipientId: user.userId,
        channelsDelivered: DEFAULT_CHANNELS,
      });

      const itemA = await repo.addToDigestQueue({
        recipientId: user.userId,
        notificationId: notifA.notificationId,
        digestType: 'DAILY',
      });
      const itemB = await repo.addToDigestQueue({
        recipientId: user.userId,
        notificationId: notifB.notificationId,
        digestType: 'DAILY',
      });

      expect(itemA.queueId).toBeDefined();
      expect(itemA.digestSent).toBe(false);

      // Find pending
      const pending = await repo.findPendingDigestItems(user.userId, 'DAILY');
      expect(pending.length).toBe(2);

      // Mark sent
      const sentCount = await repo.markDigestItemsSent([itemA.queueId, itemB.queueId]);
      expect(sentCount).toBe(2);

      // Verify no longer pending
      const afterSent = await repo.findPendingDigestItems(user.userId, 'DAILY');
      expect(afterSent.length).toBe(0);
    }));
});

// ---------------------------------------------------------------------------
// Notification Preferences
// ---------------------------------------------------------------------------

describe('NotificationRepository — Preferences', () => {
  it('upsertPreference inserts and updates, findPreferencesByProvider lists them', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      // Insert
      const pref = await repo.upsertPreference(user.userId, 'BILLING', {
        inAppEnabled: true,
        emailEnabled: false,
        digestMode: 'DAILY_DIGEST',
      });

      expect(pref.preferenceId).toBeDefined();
      expect(pref.eventCategory).toBe('BILLING');
      expect(pref.emailEnabled).toBe(false);
      expect(pref.digestMode).toBe('DAILY_DIGEST');

      // Update via upsert
      const updated = await repo.upsertPreference(user.userId, 'BILLING', {
        emailEnabled: true,
      });

      expect(updated.preferenceId).toBe(pref.preferenceId);
      expect(updated.emailEnabled).toBe(true);

      // List all
      const all = await repo.findPreferencesByProvider(user.userId);
      expect(all.length).toBe(1);
      expect(all[0].eventCategory).toBe('BILLING');
    }));

  it('updateQuietHours sets quiet hours across all provider preferences', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);
      const user = await createTestUser(tx);

      await repo.upsertPreference(user.userId, 'BILLING', {
        emailEnabled: true,
      });
      await repo.upsertPreference(user.userId, 'CLAIMS', {
        emailEnabled: true,
      });

      const count = await repo.updateQuietHours(user.userId, '22:00', '07:00');
      expect(count).toBe(2);

      const prefs = await repo.findPreferencesByProvider(user.userId);
      expect(prefs.every((p) => p.quietHoursStart === '22:00:00')).toBe(true);
      expect(prefs.every((p) => p.quietHoursEnd === '07:00:00')).toBe(true);
    }));
});

// ---------------------------------------------------------------------------
// Notification Templates
// ---------------------------------------------------------------------------

describe('NotificationRepository — Templates', () => {
  it('upsertTemplate inserts and updates, findTemplateById retrieves', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);

      // Insert
      const tpl = await repo.upsertTemplate({
        templateId: 'claim_validated_v1',
        inAppTitle: 'Claim {{claimId}} validated',
        inAppBody: 'Your claim {{claimId}} has been validated successfully.',
        variables: ['claimId'],
      });

      expect(tpl.templateId).toBe('claim_validated_v1');
      expect(tpl.inAppTitle).toBe('Claim {{claimId}} validated');
      expect(tpl.variables).toEqual(['claimId']);

      // Update via upsert
      const updated = await repo.upsertTemplate({
        templateId: 'claim_validated_v1',
        inAppTitle: 'Claim {{claimId}} approved',
        inAppBody: 'Your claim {{claimId}} was approved.',
        variables: ['claimId', 'amount'],
      });

      expect(updated.templateId).toBe('claim_validated_v1');
      expect(updated.inAppTitle).toBe('Claim {{claimId}} approved');
      expect(updated.variables).toEqual(['claimId', 'amount']);

      // Find by ID
      const found = await repo.findTemplateById('claim_validated_v1');
      expect(found).toBeDefined();
      expect(found!.inAppTitle).toBe('Claim {{claimId}} approved');
    }));

  it('findTemplateById returns undefined for unknown template', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createNotificationRepository(tx);

      const found = await repo.findTemplateById('nonexistent_template');
      expect(found).toBeUndefined();
    }));
});
