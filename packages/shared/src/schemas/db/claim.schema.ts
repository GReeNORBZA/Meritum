// ============================================================================
// Domain 4.0: Claim Lifecycle Core — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  integer,
  timestamp,
  date,
  time,
  text,
  jsonb,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { users } from './iam.schema.js';
import { providers } from './provider.schema.js';
import { patients } from './patient.schema.js';

// --- Claims Table ---
// One row per claim regardless of pathway (AHCIP or WCB).
// claim_type determines which extension tables apply.
// Physician-scoped via physician_id (HIA custodian boundary).
// Soft-deleted via deleted_at (only from DRAFT state). Retained for audit.

export const claims = pgTable(
  'claims',
  {
    claimId: uuid('claim_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    patientId: uuid('patient_id')
      .notNull()
      .references(() => patients.patientId),
    claimType: varchar('claim_type', { length: 10 }).notNull(),
    state: varchar('state', { length: 20 }).notNull().default('DRAFT'),
    isClean: boolean('is_clean'),
    importSource: varchar('import_source', { length: 20 }).notNull(),
    importBatchId: uuid('import_batch_id'),
    shiftId: uuid('shift_id'),
    dateOfService: date('date_of_service', { mode: 'string' }).notNull(),
    submissionDeadline: date('submission_deadline', { mode: 'string' }).notNull(),
    submittedBatchId: uuid('submitted_batch_id'),
    validationResult: jsonb('validation_result'),
    validationTimestamp: timestamp('validation_timestamp', {
      withTimezone: true,
    }),
    referenceDataVersion: varchar('reference_data_version', { length: 20 }),
    aiCoachSuggestions: jsonb('ai_coach_suggestions'),
    duplicateAlert: jsonb('duplicate_alert'),
    flags: jsonb('flags'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedBy: uuid('updated_by')
      .notNull()
      .references(() => users.userId),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
  },
  (table) => [
    // Dashboard queries: list claims by state for a physician
    index('claims_physician_state_idx').on(table.physicianId, table.state),

    // Duplicate detection: same patient + same DOS
    index('claims_patient_dos_idx').on(
      table.patientId,
      table.dateOfService,
    ),

    // Batch assembly: find claims ready for submission
    index('claims_state_type_clean_idx').on(
      table.state,
      table.claimType,
      table.isClean,
    ),

    // Expiry monitoring: find claims approaching submission deadline
    index('claims_submission_deadline_idx').on(table.submissionDeadline),
  ],
);

// --- Field Mapping Templates Table ---
// Per-physician reusable column-to-field mappings for EMR CSV imports.
// Physician-scoped via physician_id (HIA custodian boundary).

export const fieldMappingTemplates = pgTable(
  'field_mapping_templates',
  {
    templateId: uuid('template_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    name: varchar('name', { length: 100 }).notNull(),
    emrType: varchar('emr_type', { length: 50 }),
    mappings: jsonb('mappings').notNull(),
    delimiter: varchar('delimiter', { length: 5 }),
    hasHeaderRow: boolean('has_header_row').notNull(),
    dateFormat: varchar('date_format', { length: 20 }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Listing templates for a physician
    index('field_mapping_templates_physician_idx').on(table.physicianId),
  ],
);

// --- Import Batches Table ---
// Tracks EMR file imports with SHA-256 deduplication per physician.
// Physician-scoped via physician_id (HIA custodian boundary).

export const importBatches = pgTable(
  'import_batches',
  {
    importBatchId: uuid('import_batch_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    fileName: varchar('file_name', { length: 255 }).notNull(),
    fileHash: varchar('file_hash', { length: 64 }).notNull(),
    fieldMappingTemplateId: uuid('field_mapping_template_id').references(
      () => fieldMappingTemplates.templateId,
    ),
    totalRows: integer('total_rows').notNull(),
    successCount: integer('success_count').notNull(),
    errorCount: integer('error_count').notNull(),
    errorDetails: jsonb('error_details'),
    status: varchar('status', { length: 20 }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    // Listing import batches for a physician, newest first
    index('import_batches_physician_created_idx').on(
      table.physicianId,
      table.createdAt,
    ),

    // Deduplication: same physician cannot re-import the same file
    uniqueIndex('import_batches_physician_file_hash_idx').on(
      table.physicianId,
      table.fileHash,
    ),
  ],
);

// --- Shifts Table ---
// ED shift tracking for encounter-based claim entry.
// Physician-scoped via physician_id (HIA custodian boundary).
// Claims with import_source = ED_SHIFT reference shift_id.

export const shifts = pgTable(
  'shifts',
  {
    shiftId: uuid('shift_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    facilityId: uuid('facility_id').notNull(),
    shiftDate: date('shift_date', { mode: 'string' }).notNull(),
    startTime: time('start_time'),
    endTime: time('end_time'),
    status: varchar('status', { length: 20 }).notNull(),
    encounterCount: integer('encounter_count').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Dashboard queries: list shifts for a physician by date
    index('shifts_physician_shift_date_idx').on(
      table.physicianId,
      table.shiftDate,
    ),
  ],
);

// --- Claim Exports Table ---
// Tracks data export requests and their generated files.
// Physician-scoped via physician_id (HIA custodian boundary).
// Export files stored in DigitalOcean Spaces; file_path references the object key.

export const claimExports = pgTable(
  'claim_exports',
  {
    exportId: uuid('export_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    dateFrom: date('date_from', { mode: 'string' }).notNull(),
    dateTo: date('date_to', { mode: 'string' }).notNull(),
    claimType: varchar('claim_type', { length: 10 }),
    format: varchar('format', { length: 10 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('PENDING'),
    filePath: varchar('file_path', { length: 500 }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('claim_exports_physician_created_idx').on(
      table.physicianId,
      table.createdAt,
    ),
  ],
);

// --- Claim Audit History Table ---
// Append-only audit trail for every claim state change and significant edit.
// Separate from the system-wide audit log (iam.schema.ts auditLog).
// Retention: claim lifetime + 10 years (HIA custodian requirement).
// CRITICAL: No UPDATE or DELETE operations. Repository must only expose insert.

export const claimAuditHistory = pgTable(
  'claim_audit_history',
  {
    auditId: uuid('audit_id').primaryKey().defaultRandom(),
    claimId: uuid('claim_id')
      .notNull()
      .references(() => claims.claimId),
    action: varchar('action', { length: 30 }).notNull(),
    previousState: varchar('previous_state', { length: 20 }),
    newState: varchar('new_state', { length: 20 }),
    changes: jsonb('changes'),
    actorId: uuid('actor_id')
      .notNull()
      .references(() => users.userId),
    actorContext: varchar('actor_context', { length: 20 }).notNull(),
    reason: text('reason'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Timeline view: all audit entries for a claim, newest first
    index('claim_audit_history_claim_created_idx').on(
      table.claimId,
      table.createdAt,
    ),

    // Actor activity log: all actions by a specific user
    index('claim_audit_history_actor_created_idx').on(
      table.actorId,
      table.createdAt,
    ),
  ],
);

// --- Inferred Types ---

export type InsertClaim = typeof claims.$inferInsert;
export type SelectClaim = typeof claims.$inferSelect;

export type InsertFieldMappingTemplate =
  typeof fieldMappingTemplates.$inferInsert;
export type SelectFieldMappingTemplate =
  typeof fieldMappingTemplates.$inferSelect;

export type InsertImportBatch = typeof importBatches.$inferInsert;
export type SelectImportBatch = typeof importBatches.$inferSelect;

export type InsertShift = typeof shifts.$inferInsert;
export type SelectShift = typeof shifts.$inferSelect;

export type InsertClaimExport = typeof claimExports.$inferInsert;
export type SelectClaimExport = typeof claimExports.$inferSelect;

export type InsertClaimAuditHistory = typeof claimAuditHistory.$inferInsert;
export type SelectClaimAuditHistory = typeof claimAuditHistory.$inferSelect;
