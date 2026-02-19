// ============================================================================
// Domain 8: Analytics & Reporting — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  date,
  timestamp,
  jsonb,
  bigint,
  boolean,
  text,
  index,
  unique,
} from 'drizzle-orm/pg-core';

import { providers } from './provider.schema.js';

// --- Analytics Cache Table ---
// Pre-computed metric aggregates refreshed via nightly batch, event-driven
// incremental updates, and stale-cache detection on dashboard open.
// Physician-scoped: every query MUST filter by provider_id from auth context.
// Hard deletes allowed (cache data, not PHI source of truth).

export const analyticsCache = pgTable(
  'analytics_cache',
  {
    cacheId: uuid('cache_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    metricKey: varchar('metric_key', { length: 50 }).notNull(),
    periodStart: date('period_start', { mode: 'string' }).notNull(),
    periodEnd: date('period_end', { mode: 'string' }).notNull(),
    dimensions: jsonb('dimensions').$type<{
      ba_number?: string;
      location_id?: string;
      claim_type?: string;
      hsc_code?: string;
    } | null>(),
    value: jsonb('value').notNull(),
    computedAt: timestamp('computed_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Upsert target: one cache entry per provider + metric + period + dimensions
    unique('analytics_cache_provider_metric_period_dims_uniq').on(
      table.providerId,
      table.metricKey,
      table.periodStart,
      table.periodEnd,
      table.dimensions,
    ),

    // Dashboard queries: lookup by provider + metric
    index('analytics_cache_provider_metric_idx').on(
      table.providerId,
      table.metricKey,
    ),

    // Stale cache detection: find entries older than threshold
    index('analytics_cache_computed_at_idx').on(table.computedAt),
  ],
);

// --- Generated Reports Table ---
// Tracks asynchronous report generation lifecycle: pending -> generating -> ready | failed.
// Physician-scoped: every query MUST filter by provider_id from auth context.
// Contains PHI (patient data in CSV exports). file_path must NEVER be exposed in API responses.
// Retention: 90 days (scheduled), 30 days (on-demand), 72 hours (data portability).

export const generatedReports = pgTable(
  'generated_reports',
  {
    reportId: uuid('report_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    reportType: varchar('report_type', { length: 50 }).notNull(),
    format: varchar('format', { length: 10 }).notNull(),
    periodStart: date('period_start', { mode: 'string' }),
    periodEnd: date('period_end', { mode: 'string' }),
    filePath: varchar('file_path', { length: 255 }).notNull(),
    fileSizeBytes: bigint('file_size_bytes', { mode: 'number' }).notNull(),
    downloadLinkExpiresAt: timestamp('download_link_expires_at', {
      withTimezone: true,
    }).notNull(),
    downloaded: boolean('downloaded').notNull().default(false),
    scheduled: boolean('scheduled').notNull().default(false),
    status: varchar('status', { length: 20 }).notNull().default('pending'),
    errorMessage: text('error_message'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Listing reports by type for a physician
    index('generated_reports_provider_type_idx').on(
      table.providerId,
      table.reportType,
    ),

    // Recent reports listing (descending by creation)
    index('generated_reports_provider_created_idx').on(
      table.providerId,
      table.createdAt,
    ),

    // Cleanup job: find expired download links
    index('generated_reports_expires_at_idx').on(
      table.downloadLinkExpiresAt,
    ),

    // Processing queue: find reports by status
    index('generated_reports_status_idx').on(table.status),
  ],
);

// --- Report Subscriptions Table ---
// Physician opt-in to scheduled report generation (weekly summary, monthly
// performance, etc.). One subscription per report_type per physician (UNIQUE).
// Physician-scoped: every query MUST filter by provider_id from auth context.
// Soft-deletable via is_active flag.

export const reportSubscriptions = pgTable(
  'report_subscriptions',
  {
    subscriptionId: uuid('subscription_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    reportType: varchar('report_type', { length: 50 }).notNull(),
    frequency: varchar('frequency', { length: 20 }).notNull(),
    deliveryMethod: varchar('delivery_method', { length: 20 })
      .notNull()
      .default('IN_APP'),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // One subscription per report type per physician
    unique('report_subscriptions_provider_report_type_uniq').on(
      table.providerId,
      table.reportType,
    ),

    // Scheduled job queries: find active subscriptions by frequency
    index('report_subscriptions_active_frequency_idx').on(
      table.isActive,
      table.frequency,
    ),
  ],
);

// --- Inferred Types ---

export type InsertAnalyticsCache = typeof analyticsCache.$inferInsert;
export type SelectAnalyticsCache = typeof analyticsCache.$inferSelect;

export type InsertGeneratedReport = typeof generatedReports.$inferInsert;
export type SelectGeneratedReport = typeof generatedReports.$inferSelect;

export type InsertReportSubscription = typeof reportSubscriptions.$inferInsert;
export type SelectReportSubscription = typeof reportSubscriptions.$inferSelect;
