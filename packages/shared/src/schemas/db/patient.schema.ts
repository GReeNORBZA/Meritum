// ============================================================================
// Domain 6: Patient Registry — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  timestamp,
  date,
  text,
  integer,
  jsonb,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { users } from './iam.schema.js';
import { providers } from './provider.schema.js';

// --- Patients Table ---
// One row per patient per physician. Physician-scoped via provider_id (HIA custodian boundary).
// PHN is nullable (newborns, out-of-province, WCB no-PHN cases).
// Partial unique index on (provider_id, phn) WHERE phn IS NOT NULL prevents duplicate PHNs per physician.
// pg_trgm GIN index on (last_name, first_name) enables efficient prefix/fuzzy name search.

export const patients = pgTable(
  'patients',
  {
    patientId: uuid('patient_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    phn: varchar('phn', { length: 9 }),
    phnProvince: varchar('phn_province', { length: 2 }).default('AB'),
    firstName: varchar('first_name', { length: 50 }).notNull(),
    middleName: varchar('middle_name', { length: 50 }),
    lastName: varchar('last_name', { length: 50 }).notNull(),
    dateOfBirth: date('date_of_birth', { mode: 'string' }).notNull(),
    gender: varchar('gender', { length: 1 }).notNull(),
    phone: varchar('phone', { length: 24 }),
    email: varchar('email', { length: 100 }),
    addressLine1: varchar('address_line_1', { length: 100 }),
    addressLine2: varchar('address_line_2', { length: 100 }),
    city: varchar('city', { length: 50 }),
    province: varchar('province', { length: 2 }),
    postalCode: varchar('postal_code', { length: 7 }),
    notes: text('notes'),
    isActive: boolean('is_active').notNull().default(true),
    lastVisitDate: date('last_visit_date', { mode: 'string' }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    // Partial unique: one PHN per physician (allows multiple null-PHN patients)
    uniqueIndex('patients_provider_phn_unique_idx')
      .on(table.providerId, table.phn)
      .where(sql`phn IS NOT NULL`),

    // Name search (physician-scoped)
    index('patients_provider_name_idx').on(
      table.providerId,
      table.lastName,
      table.firstName,
    ),

    // DOB search (physician-scoped)
    index('patients_provider_dob_idx').on(
      table.providerId,
      table.dateOfBirth,
    ),

    // Recent patients sort (physician-scoped, descending last visit)
    index('patients_provider_last_visit_idx').on(
      table.providerId,
      table.lastVisitDate,
    ),

    // Active filter (physician-scoped)
    index('patients_provider_is_active_idx').on(
      table.providerId,
      table.isActive,
    ),

    // pg_trgm GIN trigram index for fuzzy/prefix name matching
    // Requires: CREATE EXTENSION IF NOT EXISTS pg_trgm;
    index('patients_name_trgm_idx').using(
      'gin',
      sql`(last_name || ' ' || first_name) gin_trgm_ops`,
    ),
  ],
);

// --- Patient Import Batches Table ---
// Tracks CSV import operations with row-level result counts and error details.
// Physician-scoped via provider_id (HIA custodian boundary).

export const patientImportBatches = pgTable(
  'patient_import_batches',
  {
    importId: uuid('import_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    fileName: varchar('file_name', { length: 255 }).notNull(),
    fileHash: varchar('file_hash', { length: 64 }).notNull(),
    totalRows: integer('total_rows').notNull().default(0),
    createdCount: integer('created_count').notNull().default(0),
    updatedCount: integer('updated_count').notNull().default(0),
    skippedCount: integer('skipped_count').notNull().default(0),
    errorCount: integer('error_count').notNull().default(0),
    errorDetails: jsonb('error_details'),
    status: varchar('status', { length: 20 }).notNull().default('PENDING'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    index('patient_import_batches_physician_created_idx').on(
      table.physicianId,
      table.createdAt,
    ),
    index('patient_import_batches_physician_hash_idx').on(
      table.physicianId,
      table.fileHash,
    ),
  ],
);

// --- Patient Merge History Table ---
// Records merge operations with claim transfer count and field conflicts.
// Physician-scoped via provider_id (HIA custodian boundary).

export const patientMergeHistory = pgTable(
  'patient_merge_history',
  {
    mergeId: uuid('merge_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    survivingPatientId: uuid('surviving_patient_id')
      .notNull()
      .references(() => patients.patientId),
    mergedPatientId: uuid('merged_patient_id')
      .notNull()
      .references(() => patients.patientId),
    claimsTransferred: integer('claims_transferred').notNull(),
    fieldConflicts: jsonb('field_conflicts'),
    mergedAt: timestamp('merged_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    mergedBy: uuid('merged_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    index('patient_merge_history_physician_merged_at_idx').on(
      table.physicianId,
      table.mergedAt,
    ),
    index('patient_merge_history_surviving_idx').on(
      table.survivingPatientId,
    ),
    index('patient_merge_history_merged_idx').on(
      table.mergedPatientId,
    ),
  ],
);

// --- Inferred Types ---

export type InsertPatient = typeof patients.$inferInsert;
export type SelectPatient = typeof patients.$inferSelect;

export type InsertPatientImportBatch = typeof patientImportBatches.$inferInsert;
export type SelectPatientImportBatch = typeof patientImportBatches.$inferSelect;

export type InsertPatientMergeHistory = typeof patientMergeHistory.$inferInsert;
export type SelectPatientMergeHistory = typeof patientMergeHistory.$inferSelect;
