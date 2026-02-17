// ============================================================================
// Domain 9: Notification Service — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  time,
  jsonb,
  integer,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

import { users } from './iam.schema.js';

// --- Channels Delivered JSONB Type ---

interface ChannelsDelivered {
  in_app: boolean;
  email: boolean;
  push: boolean;
}

// --- Notifications Table ---
// Stores all rendered notifications. Scoped by recipient_id.
// Dismissed notifications retained for audit trail (soft-hide via dismissed_at).
// 90-day primary retention, 365-day archive retention.

export const notifications = pgTable(
  'notifications',
  {
    notificationId: uuid('notification_id').primaryKey().defaultRandom(),
    recipientId: uuid('recipient_id')
      .notNull()
      .references(() => users.userId),
    physicianContextId: uuid('physician_context_id'),
    eventType: varchar('event_type', { length: 50 }).notNull(),
    priority: varchar('priority', { length: 10 }).notNull(),
    title: varchar('title', { length: 200 }).notNull(),
    body: text('body').notNull(),
    actionUrl: varchar('action_url', { length: 500 }),
    actionLabel: varchar('action_label', { length: 50 }),
    metadata: jsonb('metadata').$type<Record<string, unknown>>(),
    channelsDelivered: jsonb('channels_delivered')
      .notNull()
      .$type<ChannelsDelivered>(),
    readAt: timestamp('read_at', { withTimezone: true }),
    dismissedAt: timestamp('dismissed_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('notifications_recipient_read_at_idx').on(
      table.recipientId,
      table.readAt,
    ),
    index('notifications_recipient_created_at_idx').on(
      table.recipientId,
      table.createdAt,
    ),
    index('notifications_event_type_created_at_idx').on(
      table.eventType,
      table.createdAt,
    ),
  ],
);

// --- Email Delivery Log Table ---
// Tracks email delivery status, retries, and bounces.
// Access restricted to internal services and admin only (contains recipient_email).

export const emailDeliveryLog = pgTable(
  'email_delivery_log',
  {
    deliveryId: uuid('delivery_id').primaryKey().defaultRandom(),
    notificationId: uuid('notification_id')
      .notNull()
      .references(() => notifications.notificationId),
    recipientEmail: varchar('recipient_email', { length: 100 }).notNull(),
    templateId: varchar('template_id', { length: 50 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('QUEUED'),
    providerMessageId: varchar('provider_message_id', { length: 100 }),
    sentAt: timestamp('sent_at', { withTimezone: true }),
    deliveredAt: timestamp('delivered_at', { withTimezone: true }),
    bouncedAt: timestamp('bounced_at', { withTimezone: true }),
    bounceReason: text('bounce_reason'),
    retryCount: integer('retry_count').notNull().default(0),
    nextRetryAt: timestamp('next_retry_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('email_delivery_log_notification_id_idx').on(table.notificationId),
    index('email_delivery_log_status_next_retry_at_idx').on(
      table.status,
      table.nextRetryAt,
    ),
    index('email_delivery_log_recipient_email_created_at_idx').on(
      table.recipientEmail,
      table.createdAt,
    ),
  ],
);

// --- Notification Templates Table ---
// Managed by the dev team only. No physician-facing mutation endpoints.
// Templates contain {{variable}} placeholders — never actual PHI.

export const notificationTemplates = pgTable('notification_templates', {
  templateId: varchar('template_id', { length: 50 }).primaryKey(),
  inAppTitle: varchar('in_app_title', { length: 200 }).notNull(),
  inAppBody: text('in_app_body').notNull(),
  emailSubject: varchar('email_subject', { length: 200 }),
  emailHtmlBody: text('email_html_body'),
  emailTextBody: text('email_text_body'),
  actionUrlTemplate: varchar('action_url_template', { length: 500 }),
  actionLabel: varchar('action_label', { length: 50 }),
  variables: jsonb('variables').notNull().$type<string[]>(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// --- Digest Queue Table ---
// Holds notifications awaiting digest assembly (DAILY or WEEKLY).
// Hard-deleted after digest is sent — no PHI retention beyond delivery.

export const digestQueue = pgTable(
  'digest_queue',
  {
    queueId: uuid('queue_id').primaryKey().defaultRandom(),
    recipientId: uuid('recipient_id')
      .notNull()
      .references(() => users.userId),
    notificationId: uuid('notification_id')
      .notNull()
      .references(() => notifications.notificationId),
    digestType: varchar('digest_type', { length: 20 }).notNull(),
    digestSent: boolean('digest_sent').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('digest_queue_recipient_sent_type_idx').on(
      table.recipientId,
      table.digestSent,
      table.digestType,
    ),
    index('digest_queue_created_at_idx').on(table.createdAt),
  ],
);

// --- Notification Preferences Table ---
// Per-provider, per-event-category channel and frequency config.
// Scoped to provider_id — no cross-physician preference access.
// URGENT in-app cannot be disabled (enforced at service layer).

export const notificationPreferences = pgTable(
  'notification_preferences',
  {
    preferenceId: uuid('preference_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => users.userId),
    eventCategory: varchar('event_category', { length: 50 }).notNull(),
    inAppEnabled: boolean('in_app_enabled').notNull().default(true),
    emailEnabled: boolean('email_enabled').notNull(),
    digestMode: varchar('digest_mode', { length: 20 })
      .notNull()
      .default('IMMEDIATE'),
    quietHoursStart: time('quiet_hours_start'),
    quietHoursEnd: time('quiet_hours_end'),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('notification_preferences_provider_category_idx').on(
      table.providerId,
      table.eventCategory,
    ),
    index('notification_preferences_provider_id_idx').on(table.providerId),
  ],
);

// --- Inferred Types ---

export type InsertNotification = typeof notifications.$inferInsert;
export type SelectNotification = typeof notifications.$inferSelect;

export type InsertEmailDeliveryLog = typeof emailDeliveryLog.$inferInsert;
export type SelectEmailDeliveryLog = typeof emailDeliveryLog.$inferSelect;

export type InsertNotificationTemplate =
  typeof notificationTemplates.$inferInsert;
export type SelectNotificationTemplate =
  typeof notificationTemplates.$inferSelect;

export type InsertDigestQueueItem = typeof digestQueue.$inferInsert;
export type SelectDigestQueueItem = typeof digestQueue.$inferSelect;

export type InsertNotificationPreference =
  typeof notificationPreferences.$inferInsert;
export type SelectNotificationPreference =
  typeof notificationPreferences.$inferSelect;
