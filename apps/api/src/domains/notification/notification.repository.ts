import { eq, and, or, isNull, lte, lt, desc, asc, sql, inArray } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  notifications,
  emailDeliveryLog,
  notificationTemplates,
  digestQueue,
  notificationPreferences,
  type InsertNotification,
  type SelectNotification,
  type InsertEmailDeliveryLog,
  type SelectEmailDeliveryLog,
  type InsertNotificationTemplate,
  type SelectNotificationTemplate,
  type InsertDigestQueueItem,
  type SelectDigestQueueItem,
  type InsertNotificationPreference,
  type SelectNotificationPreference,
} from '@meritum/shared/schemas/db/notification.schema.js';
import {
  EVENT_CATALOGUE,
  NotificationPriority,
} from '@meritum/shared/constants/notification.constants.js';

interface ListNotificationsOpts {
  unreadOnly?: boolean;
  limit: number;
  offset: number;
}

export function createNotificationRepository(db: NodePgDatabase) {
  return {
    async createNotification(
      data: InsertNotification,
    ): Promise<SelectNotification> {
      const rows = await db
        .insert(notifications)
        .values(data)
        .returning();
      return rows[0];
    },

    async createNotificationsBatch(
      data: InsertNotification[],
    ): Promise<number> {
      if (data.length === 0) return 0;
      const rows = await db
        .insert(notifications)
        .values(data)
        .returning();
      return rows.length;
    },

    async findNotificationById(
      notificationId: string,
      recipientId: string,
    ): Promise<SelectNotification | undefined> {
      const rows = await db
        .select()
        .from(notifications)
        .where(
          and(
            eq(notifications.notificationId, notificationId),
            eq(notifications.recipientId, recipientId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async findNotificationByIdInternal(
      notificationId: string,
    ): Promise<SelectNotification | undefined> {
      const rows = await db
        .select()
        .from(notifications)
        .where(eq(notifications.notificationId, notificationId))
        .limit(1);
      return rows[0];
    },

    async listNotifications(
      recipientId: string,
      opts: ListNotificationsOpts,
    ): Promise<SelectNotification[]> {
      const conditions = [
        eq(notifications.recipientId, recipientId),
        isNull(notifications.dismissedAt),
      ];

      if (opts.unreadOnly) {
        conditions.push(isNull(notifications.readAt));
      }

      return db
        .select()
        .from(notifications)
        .where(and(...conditions))
        .orderBy(desc(notifications.createdAt))
        .limit(opts.limit)
        .offset(opts.offset);
    },

    async countUnread(recipientId: string): Promise<number> {
      const rows = await db
        .select()
        .from(notifications)
        .where(
          and(
            eq(notifications.recipientId, recipientId),
            isNull(notifications.readAt),
            isNull(notifications.dismissedAt),
          ),
        );
      return rows.length;
    },

    async markRead(
      notificationId: string,
      recipientId: string,
    ): Promise<SelectNotification | undefined> {
      const rows = await db
        .update(notifications)
        .set({ readAt: new Date() })
        .where(
          and(
            eq(notifications.notificationId, notificationId),
            eq(notifications.recipientId, recipientId),
          ),
        )
        .returning();
      return rows[0];
    },

    async markAllRead(recipientId: string): Promise<number> {
      const rows = await db
        .update(notifications)
        .set({ readAt: new Date() })
        .where(
          and(
            eq(notifications.recipientId, recipientId),
            isNull(notifications.readAt),
          ),
        )
        .returning();
      return rows.length;
    },

    async dismiss(
      notificationId: string,
      recipientId: string,
    ): Promise<SelectNotification | undefined> {
      const rows = await db
        .update(notifications)
        .set({ dismissedAt: new Date() })
        .where(
          and(
            eq(notifications.notificationId, notificationId),
            eq(notifications.recipientId, recipientId),
          ),
        )
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------
    // Email Delivery Log
    // -----------------------------------------------------------------

    async createDeliveryLog(
      data: InsertEmailDeliveryLog,
    ): Promise<SelectEmailDeliveryLog> {
      const rows = await db
        .insert(emailDeliveryLog)
        .values(data)
        .returning();
      return rows[0];
    },

    async updateDeliveryStatus(
      deliveryId: string,
      status: string,
      details?: {
        providerMessageId?: string;
        sentAt?: Date;
        deliveredAt?: Date;
        bouncedAt?: Date;
        bounceReason?: string;
      },
    ): Promise<SelectEmailDeliveryLog | undefined> {
      const setClauses: Record<string, unknown> = { status };

      if (details) {
        if (details.providerMessageId !== undefined) {
          setClauses.providerMessageId = details.providerMessageId;
        }
        if (status === 'SENT' && details.sentAt) {
          setClauses.sentAt = details.sentAt;
        }
        if (status === 'DELIVERED' && details.deliveredAt) {
          setClauses.deliveredAt = details.deliveredAt;
        }
        if (status === 'BOUNCED') {
          if (details.bouncedAt) setClauses.bouncedAt = details.bouncedAt;
          if (details.bounceReason) setClauses.bounceReason = details.bounceReason;
        }
      }

      const rows = await db
        .update(emailDeliveryLog)
        .set(setClauses)
        .where(eq(emailDeliveryLog.deliveryId, deliveryId))
        .returning();
      return rows[0];
    },

    async findPendingRetries(): Promise<SelectEmailDeliveryLog[]> {
      const now = new Date();
      return db
        .select()
        .from(emailDeliveryLog)
        .where(
          and(
            inArray(emailDeliveryLog.status, ['QUEUED', 'FAILED']),
            or(
              lte(emailDeliveryLog.nextRetryAt, now),
              isNull(emailDeliveryLog.nextRetryAt),
            ),
            lt(emailDeliveryLog.retryCount, 4),
          ),
        )
        .orderBy(asc(emailDeliveryLog.nextRetryAt));
    },

    async incrementRetry(
      deliveryId: string,
      nextRetryAt: Date,
    ): Promise<SelectEmailDeliveryLog | undefined> {
      const rows = await db
        .update(emailDeliveryLog)
        .set({
          retryCount: sql`${emailDeliveryLog.retryCount} + 1`,
          nextRetryAt,
        })
        .where(eq(emailDeliveryLog.deliveryId, deliveryId))
        .returning();
      return rows[0];
    },

    async findDeliveryLogByProviderMessageId(
      providerMessageId: string,
    ): Promise<SelectEmailDeliveryLog | undefined> {
      const rows = await db
        .select()
        .from(emailDeliveryLog)
        .where(eq(emailDeliveryLog.providerMessageId, providerMessageId))
        .limit(1);
      return rows[0];
    },

    async listDeliveryLogByNotification(
      notificationId: string,
    ): Promise<SelectEmailDeliveryLog[]> {
      return db
        .select()
        .from(emailDeliveryLog)
        .where(eq(emailDeliveryLog.notificationId, notificationId));
    },

    // -----------------------------------------------------------------
    // Notification Templates
    // -----------------------------------------------------------------

    async findTemplateById(
      templateId: string,
    ): Promise<SelectNotificationTemplate | undefined> {
      const rows = await db
        .select()
        .from(notificationTemplates)
        .where(eq(notificationTemplates.templateId, templateId))
        .limit(1);
      return rows[0];
    },

    async listAllTemplates(): Promise<SelectNotificationTemplate[]> {
      return db.select().from(notificationTemplates);
    },

    async upsertTemplate(
      data: InsertNotificationTemplate,
    ): Promise<SelectNotificationTemplate> {
      const rows = await db
        .insert(notificationTemplates)
        .values(data)
        .onConflictDoUpdate({
          target: notificationTemplates.templateId,
          set: {
            inAppTitle: data.inAppTitle,
            inAppBody: data.inAppBody,
            emailSubject: data.emailSubject ?? null,
            emailHtmlBody: data.emailHtmlBody ?? null,
            emailTextBody: data.emailTextBody ?? null,
            actionUrlTemplate: data.actionUrlTemplate ?? null,
            actionLabel: data.actionLabel ?? null,
            variables: data.variables,
            updatedAt: new Date(),
          },
        })
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------
    // Digest Queue
    // -----------------------------------------------------------------

    async addToDigestQueue(data: {
      recipientId: string;
      notificationId: string;
      digestType: string;
    }): Promise<SelectDigestQueueItem> {
      const rows = await db
        .insert(digestQueue)
        .values({
          recipientId: data.recipientId,
          notificationId: data.notificationId,
          digestType: data.digestType,
        })
        .returning();
      return rows[0];
    },

    async findPendingDigestItems(
      recipientId: string,
      digestType: string,
    ): Promise<SelectDigestQueueItem[]> {
      return db
        .select()
        .from(digestQueue)
        .where(
          and(
            eq(digestQueue.recipientId, recipientId),
            eq(digestQueue.digestType, digestType),
            eq(digestQueue.digestSent, false),
          ),
        );
    },

    async findAllPendingDigestItems(
      digestType: string,
    ): Promise<Map<string, SelectDigestQueueItem[]>> {
      const rows = await db
        .select()
        .from(digestQueue)
        .where(
          and(
            eq(digestQueue.digestType, digestType),
            eq(digestQueue.digestSent, false),
          ),
        );

      const grouped = new Map<string, SelectDigestQueueItem[]>();
      for (const row of rows) {
        const existing = grouped.get(row.recipientId);
        if (existing) {
          existing.push(row);
        } else {
          grouped.set(row.recipientId, [row]);
        }
      }
      return grouped;
    },

    async markDigestItemsSent(queueIds: string[]): Promise<number> {
      if (queueIds.length === 0) return 0;
      const rows = await db
        .update(digestQueue)
        .set({ digestSent: true })
        .where(inArray(digestQueue.queueId, queueIds))
        .returning();
      return rows.length;
    },

    // -----------------------------------------------------------------
    // Notification Preferences
    // -----------------------------------------------------------------

    async findPreferencesByProvider(
      providerId: string,
    ): Promise<SelectNotificationPreference[]> {
      return db
        .select()
        .from(notificationPreferences)
        .where(eq(notificationPreferences.providerId, providerId));
    },

    async findPreference(
      providerId: string,
      eventCategory: string,
    ): Promise<SelectNotificationPreference | undefined> {
      const rows = await db
        .select()
        .from(notificationPreferences)
        .where(
          and(
            eq(notificationPreferences.providerId, providerId),
            eq(notificationPreferences.eventCategory, eventCategory),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async upsertPreference(
      providerId: string,
      eventCategory: string,
      data: Partial<InsertNotificationPreference>,
    ): Promise<SelectNotificationPreference> {
      const rows = await db
        .insert(notificationPreferences)
        .values({
          providerId,
          eventCategory,
          inAppEnabled: data.inAppEnabled ?? true,
          emailEnabled: data.emailEnabled ?? true,
          digestMode: data.digestMode ?? 'IMMEDIATE',
          quietHoursStart: data.quietHoursStart ?? null,
          quietHoursEnd: data.quietHoursEnd ?? null,
        })
        .onConflictDoUpdate({
          target: [
            notificationPreferences.providerId,
            notificationPreferences.eventCategory,
          ],
          set: {
            ...(data.inAppEnabled !== undefined && { inAppEnabled: data.inAppEnabled }),
            ...(data.emailEnabled !== undefined && { emailEnabled: data.emailEnabled }),
            ...(data.digestMode !== undefined && { digestMode: data.digestMode }),
            ...(data.quietHoursStart !== undefined && { quietHoursStart: data.quietHoursStart }),
            ...(data.quietHoursEnd !== undefined && { quietHoursEnd: data.quietHoursEnd }),
            updatedAt: new Date(),
          },
        })
        .returning();
      return rows[0];
    },

    async createDefaultPreferences(
      providerId: string,
    ): Promise<SelectNotificationPreference[]> {
      const categories = new Set<string>();
      const categoryDefaults = new Map<string, { defaultEmail: boolean; hasUrgent: boolean }>();

      for (const [, entry] of Object.entries(EVENT_CATALOGUE)) {
        if (!categories.has(entry.category)) {
          categories.add(entry.category);
          categoryDefaults.set(entry.category, {
            defaultEmail: entry.defaultEmail,
            hasUrgent: entry.priority === NotificationPriority.URGENT,
          });
        } else {
          const existing = categoryDefaults.get(entry.category)!;
          if (entry.defaultEmail) {
            existing.defaultEmail = true;
          }
          if (entry.priority === NotificationPriority.URGENT) {
            existing.hasUrgent = true;
          }
        }
      }

      const values: InsertNotificationPreference[] = [];
      for (const [category, defaults] of categoryDefaults) {
        values.push({
          providerId,
          eventCategory: category,
          inAppEnabled: true,
          emailEnabled: defaults.defaultEmail,
          digestMode: 'IMMEDIATE',
        });
      }

      if (values.length === 0) return [];

      const rows = await db
        .insert(notificationPreferences)
        .values(values)
        .returning();
      return rows;
    },

    async updateQuietHours(
      providerId: string,
      start: string | null,
      end: string | null,
    ): Promise<number> {
      const rows = await db
        .update(notificationPreferences)
        .set({
          quietHoursStart: start,
          quietHoursEnd: end,
          updatedAt: new Date(),
        })
        .where(eq(notificationPreferences.providerId, providerId))
        .returning();
      return rows.length;
    },
  };
}

export type NotificationRepository = ReturnType<typeof createNotificationRepository>;
