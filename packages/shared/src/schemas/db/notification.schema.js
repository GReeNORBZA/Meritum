"use strict";
// ============================================================================
// Domain 9: Notification Service — Drizzle DB Schema
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.notificationPreferences = exports.digestQueue = exports.notificationTemplates = exports.emailDeliveryLog = exports.notifications = void 0;
const pg_core_1 = require("drizzle-orm/pg-core");
const iam_schema_js_1 = require("./iam.schema.js");
// --- Notifications Table ---
// Stores all rendered notifications. Scoped by recipient_id.
// Dismissed notifications retained for audit trail (soft-hide via dismissed_at).
// 90-day primary retention, 365-day archive retention.
exports.notifications = (0, pg_core_1.pgTable)('notifications', {
    notificationId: (0, pg_core_1.uuid)('notification_id').primaryKey().defaultRandom(),
    recipientId: (0, pg_core_1.uuid)('recipient_id')
        .notNull()
        .references(() => iam_schema_js_1.users.userId),
    physicianContextId: (0, pg_core_1.uuid)('physician_context_id'),
    eventType: (0, pg_core_1.varchar)('event_type', { length: 50 }).notNull(),
    priority: (0, pg_core_1.varchar)('priority', { length: 10 }).notNull(),
    title: (0, pg_core_1.varchar)('title', { length: 200 }).notNull(),
    body: (0, pg_core_1.text)('body').notNull(),
    actionUrl: (0, pg_core_1.varchar)('action_url', { length: 500 }),
    actionLabel: (0, pg_core_1.varchar)('action_label', { length: 50 }),
    metadata: (0, pg_core_1.jsonb)('metadata').$type(),
    channelsDelivered: (0, pg_core_1.jsonb)('channels_delivered')
        .notNull()
        .$type(),
    readAt: (0, pg_core_1.timestamp)('read_at', { withTimezone: true }),
    dismissedAt: (0, pg_core_1.timestamp)('dismissed_at', { withTimezone: true }),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('notifications_recipient_read_at_idx').on(table.recipientId, table.readAt),
    (0, pg_core_1.index)('notifications_recipient_created_at_idx').on(table.recipientId, table.createdAt),
    (0, pg_core_1.index)('notifications_event_type_created_at_idx').on(table.eventType, table.createdAt),
]);
// --- Email Delivery Log Table ---
// Tracks email delivery status, retries, and bounces.
// Access restricted to internal services and admin only (contains recipient_email).
exports.emailDeliveryLog = (0, pg_core_1.pgTable)('email_delivery_log', {
    deliveryId: (0, pg_core_1.uuid)('delivery_id').primaryKey().defaultRandom(),
    notificationId: (0, pg_core_1.uuid)('notification_id')
        .notNull()
        .references(() => exports.notifications.notificationId),
    recipientEmail: (0, pg_core_1.varchar)('recipient_email', { length: 100 }).notNull(),
    templateId: (0, pg_core_1.varchar)('template_id', { length: 50 }).notNull(),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull().default('QUEUED'),
    providerMessageId: (0, pg_core_1.varchar)('provider_message_id', { length: 100 }),
    sentAt: (0, pg_core_1.timestamp)('sent_at', { withTimezone: true }),
    deliveredAt: (0, pg_core_1.timestamp)('delivered_at', { withTimezone: true }),
    bouncedAt: (0, pg_core_1.timestamp)('bounced_at', { withTimezone: true }),
    bounceReason: (0, pg_core_1.text)('bounce_reason'),
    retryCount: (0, pg_core_1.integer)('retry_count').notNull().default(0),
    nextRetryAt: (0, pg_core_1.timestamp)('next_retry_at', { withTimezone: true }),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('email_delivery_log_notification_id_idx').on(table.notificationId),
    (0, pg_core_1.index)('email_delivery_log_status_next_retry_at_idx').on(table.status, table.nextRetryAt),
    (0, pg_core_1.index)('email_delivery_log_recipient_email_created_at_idx').on(table.recipientEmail, table.createdAt),
]);
// --- Notification Templates Table ---
// Managed by the dev team only. No physician-facing mutation endpoints.
// Templates contain {{variable}} placeholders — never actual PHI.
exports.notificationTemplates = (0, pg_core_1.pgTable)('notification_templates', {
    templateId: (0, pg_core_1.varchar)('template_id', { length: 50 }).primaryKey(),
    inAppTitle: (0, pg_core_1.varchar)('in_app_title', { length: 200 }).notNull(),
    inAppBody: (0, pg_core_1.text)('in_app_body').notNull(),
    emailSubject: (0, pg_core_1.varchar)('email_subject', { length: 200 }),
    emailHtmlBody: (0, pg_core_1.text)('email_html_body'),
    emailTextBody: (0, pg_core_1.text)('email_text_body'),
    actionUrlTemplate: (0, pg_core_1.varchar)('action_url_template', { length: 500 }),
    actionLabel: (0, pg_core_1.varchar)('action_label', { length: 50 }),
    variables: (0, pg_core_1.jsonb)('variables').notNull().$type(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
});
// --- Digest Queue Table ---
// Holds notifications awaiting digest assembly (DAILY or WEEKLY).
// Hard-deleted after digest is sent — no PHI retention beyond delivery.
exports.digestQueue = (0, pg_core_1.pgTable)('digest_queue', {
    queueId: (0, pg_core_1.uuid)('queue_id').primaryKey().defaultRandom(),
    recipientId: (0, pg_core_1.uuid)('recipient_id')
        .notNull()
        .references(() => iam_schema_js_1.users.userId),
    notificationId: (0, pg_core_1.uuid)('notification_id')
        .notNull()
        .references(() => exports.notifications.notificationId),
    digestType: (0, pg_core_1.varchar)('digest_type', { length: 20 }).notNull(),
    digestSent: (0, pg_core_1.boolean)('digest_sent').notNull().default(false),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('digest_queue_recipient_sent_type_idx').on(table.recipientId, table.digestSent, table.digestType),
    (0, pg_core_1.index)('digest_queue_created_at_idx').on(table.createdAt),
]);
// --- Notification Preferences Table ---
// Per-provider, per-event-category channel and frequency config.
// Scoped to provider_id — no cross-physician preference access.
// URGENT in-app cannot be disabled (enforced at service layer).
exports.notificationPreferences = (0, pg_core_1.pgTable)('notification_preferences', {
    preferenceId: (0, pg_core_1.uuid)('preference_id').primaryKey().defaultRandom(),
    providerId: (0, pg_core_1.uuid)('provider_id')
        .notNull()
        .references(() => iam_schema_js_1.users.userId),
    eventCategory: (0, pg_core_1.varchar)('event_category', { length: 50 }).notNull(),
    inAppEnabled: (0, pg_core_1.boolean)('in_app_enabled').notNull().default(true),
    emailEnabled: (0, pg_core_1.boolean)('email_enabled').notNull(),
    digestMode: (0, pg_core_1.varchar)('digest_mode', { length: 20 })
        .notNull()
        .default('IMMEDIATE'),
    quietHoursStart: (0, pg_core_1.time)('quiet_hours_start'),
    quietHoursEnd: (0, pg_core_1.time)('quiet_hours_end'),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('notification_preferences_provider_category_idx').on(table.providerId, table.eventCategory),
    (0, pg_core_1.index)('notification_preferences_provider_id_idx').on(table.providerId),
]);
//# sourceMappingURL=notification.schema.js.map