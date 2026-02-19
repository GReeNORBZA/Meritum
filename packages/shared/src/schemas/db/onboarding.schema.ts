// ============================================================================
// Domain 11: Onboarding — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  timestamp,
  uniqueIndex,
  index,
} from 'drizzle-orm/pg-core';
import { providers } from './provider.schema.js';

// --- Onboarding Progress Table ---
// One row per provider. Tracks per-step completion through the onboarding wizard.
// Steps 1–4 and 7 are required; steps 5–6 are optional.
// completed_at is set when all required steps are done.

export const onboardingProgress = pgTable(
  'onboarding_progress',
  {
    progressId: uuid('progress_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .unique()
      .references(() => providers.providerId),
    step1Completed: boolean('step_1_completed').notNull().default(false),
    step2Completed: boolean('step_2_completed').notNull().default(false),
    step3Completed: boolean('step_3_completed').notNull().default(false),
    step4Completed: boolean('step_4_completed').notNull().default(false),
    step5Completed: boolean('step_5_completed').notNull().default(false),
    step6Completed: boolean('step_6_completed').notNull().default(false),
    step7Completed: boolean('step_7_completed').notNull().default(false),
    patientImportCompleted: boolean('patient_import_completed').notNull().default(false),
    guidedTourCompleted: boolean('guided_tour_completed').notNull().default(false),
    guidedTourDismissed: boolean('guided_tour_dismissed').notNull().default(false),
    startedAt: timestamp('started_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('onboarding_progress_provider_id_idx').on(table.providerId),
  ],
);

export type InsertOnboardingProgress = typeof onboardingProgress.$inferInsert;
export type SelectOnboardingProgress = typeof onboardingProgress.$inferSelect;

// --- IMA Records Table ---
// One row per IMA acknowledgement. A provider can have multiple rows if they
// re-acknowledge after a template version update. Rows are immutable once written.
// Captures IP + user agent for regulatory audit trail.

export const imaRecords = pgTable(
  'ima_records',
  {
    imaId: uuid('ima_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    templateVersion: varchar('template_version', { length: 20 }).notNull(),
    documentHash: varchar('document_hash', { length: 64 }).notNull(),
    acknowledgedAt: timestamp('acknowledged_at', { withTimezone: true }).notNull(),
    ipAddress: varchar('ip_address', { length: 45 }).notNull(),
    userAgent: varchar('user_agent', { length: 500 }).notNull(),
  },
  (table) => [
    // Find the latest acknowledgement for a provider
    index('ima_records_provider_acknowledged_idx').on(
      table.providerId,
      table.acknowledgedAt,
    ),
  ],
);

export type InsertImaRecord = typeof imaRecords.$inferInsert;
export type SelectImaRecord = typeof imaRecords.$inferSelect;
