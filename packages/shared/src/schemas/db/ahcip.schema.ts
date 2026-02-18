// ============================================================================
// Domain 4.1: AHCIP Pathway — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  smallint,
  integer,
  decimal,
  date,
  timestamp,
  jsonb,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { claims } from './claim.schema.js';
import { providers } from './provider.schema.js';
import { users } from './iam.schema.js';

// --- AHCIP Claim Details Table ---
// One row per AHCIP claim, linked 1:1 to base claims table.
// Contains all H-Link file fields: HSC, modifiers, facility, diagnostic, fees.
// PHI (diagnostic codes, service details) — encrypted at rest via DO Managed DB.
// No direct physician_id column; physician scoping enforced via JOIN to claims.

export const ahcipClaimDetails = pgTable(
  'ahcip_claim_details',
  {
    ahcipDetailId: uuid('ahcip_detail_id').primaryKey().defaultRandom(),
    claimId: uuid('claim_id')
      .notNull()
      .unique()
      .references(() => claims.claimId),
    baNumber: varchar('ba_number', { length: 10 }).notNull(),
    functionalCentre: varchar('functional_centre', { length: 10 }).notNull(),
    healthServiceCode: varchar('health_service_code', { length: 10 }).notNull(),
    modifier1: varchar('modifier_1', { length: 6 }),
    modifier2: varchar('modifier_2', { length: 6 }),
    modifier3: varchar('modifier_3', { length: 6 }),
    diagnosticCode: varchar('diagnostic_code', { length: 8 }),
    facilityNumber: varchar('facility_number', { length: 10 }),
    referralPractitioner: varchar('referral_practitioner', { length: 10 }),
    encounterType: varchar('encounter_type', { length: 10 }).notNull(),
    calls: smallint('calls').notNull().default(1),
    timeSpent: smallint('time_spent'),
    patientLocation: varchar('patient_location', { length: 10 }),
    shadowBillingFlag: boolean('shadow_billing_flag').notNull().default(false),
    pcpcmBasketFlag: boolean('pcpcm_basket_flag').notNull().default(false),
    afterHoursFlag: boolean('after_hours_flag').notNull().default(false),
    afterHoursType: varchar('after_hours_type', { length: 20 }),
    submittedFee: decimal('submitted_fee', { precision: 10, scale: 2 }),
    assessedFee: decimal('assessed_fee', { precision: 10, scale: 2 }),
    assessmentExplanatoryCodes: jsonb('assessment_explanatory_codes'),
  },
  (table) => [
    // 1:1 lookup by claim_id (unique constraint above covers this as a unique index)
    // Composite index for batch assembly and reporting queries by BA + HSC
    index('ahcip_claim_details_ba_hsc_idx').on(
      table.baNumber,
      table.healthServiceCode,
    ),

    // PCPCM routing queries: find all PCPCM vs FFS claims
    index('ahcip_claim_details_pcpcm_flag_idx').on(table.pcpcmBasketFlag),
  ],
);

// --- Inferred Types ---

export type InsertAhcipClaimDetail = typeof ahcipClaimDetails.$inferInsert;
export type SelectAhcipClaimDetail = typeof ahcipClaimDetails.$inferSelect;

// --- AHCIP Batches Table ---
// One row per H-Link submission batch.
// Batches grouped by physician_id + ba_number per weekly cycle (Thursday).
// PCPCM dual-BA physicians generate two batches per week (one per BA).
// file_path points to AES-256 encrypted H-Link file — never serve raw content.
// submission_reference is H-Link tracking ID — do not expose in logs.

export const ahcipBatches = pgTable(
  'ahcip_batches',
  {
    ahcipBatchId: uuid('ahcip_batch_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    baNumber: varchar('ba_number', { length: 10 }).notNull(),
    batchWeek: date('batch_week', { mode: 'string' }).notNull(),
    status: varchar('status', { length: 20 }).notNull(),
    claimCount: integer('claim_count').notNull(),
    totalSubmittedValue: decimal('total_submitted_value', {
      precision: 12,
      scale: 2,
    }).notNull(),
    filePath: varchar('file_path', { length: 255 }),
    fileHash: varchar('file_hash', { length: 64 }),
    submissionReference: varchar('submission_reference', { length: 50 }),
    submittedAt: timestamp('submitted_at', { withTimezone: true }),
    responseReceivedAt: timestamp('response_received_at', {
      withTimezone: true,
    }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    // Dashboard / batch history: list batches by physician ordered by week
    index('ahcip_batches_physician_week_idx').on(
      table.physicianId,
      table.batchWeek,
    ),

    // Batch lifecycle queries: find batches in a given status
    index('ahcip_batches_status_idx').on(table.status),

    // Prevent duplicate batches: one batch per physician + BA + week
    uniqueIndex('ahcip_batches_physician_ba_week_uniq').on(
      table.physicianId,
      table.baNumber,
      table.batchWeek,
    ),
  ],
);

// --- Inferred Types ---

export type InsertAhcipBatch = typeof ahcipBatches.$inferInsert;
export type SelectAhcipBatch = typeof ahcipBatches.$inferSelect;
