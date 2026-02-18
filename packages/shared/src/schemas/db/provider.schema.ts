// ============================================================================
// Domain 5: Provider Management — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  integer,
  decimal,
  timestamp,
  date,
  jsonb,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { users } from './iam.schema.js';

// --- Providers Table ---
// One row per physician. Linked 1:1 to users table (provider_id = user_id).
// provider_id is the physician tenant isolation key for all downstream queries.

export const providers = pgTable(
  'providers',
  {
    providerId: uuid('provider_id')
      .primaryKey()
      .references(() => users.userId),
    billingNumber: varchar('billing_number', { length: 10 }).notNull(),
    cpsaRegistrationNumber: varchar('cpsa_registration_number', { length: 10 }).notNull(),
    firstName: varchar('first_name', { length: 50 }).notNull(),
    middleName: varchar('middle_name', { length: 50 }),
    lastName: varchar('last_name', { length: 50 }).notNull(),
    specialtyCode: varchar('specialty_code', { length: 10 }).notNull(),
    specialtyDescription: varchar('specialty_description', { length: 100 }),
    subSpecialtyCode: varchar('sub_specialty_code', { length: 10 }),
    physicianType: varchar('physician_type', { length: 20 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('ACTIVE'),
    onboardingCompleted: boolean('onboarding_completed').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('providers_billing_number_idx').on(table.billingNumber),
    uniqueIndex('providers_cpsa_registration_number_idx').on(table.cpsaRegistrationNumber),
    index('providers_specialty_code_idx').on(table.specialtyCode),
    index('providers_status_idx').on(table.status),
  ],
);

// --- Business Arrangements Table ---
// Tracks Alberta Health business arrangements (FFS, PCPCM, ARP) per physician.
// Max 2 active BAs per provider (enforced at service layer).
// If ba_type = PCPCM, a paired FFS BA must also exist.
// ba_number is unique across active (non-INACTIVE) records via partial unique index.

export const businessArrangements = pgTable(
  'business_arrangements',
  {
    baId: uuid('ba_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    baNumber: varchar('ba_number', { length: 10 }).notNull(),
    baType: varchar('ba_type', { length: 10 }).notNull(),
    isPrimary: boolean('is_primary').notNull(),
    status: varchar('status', { length: 20 }).notNull().default('PENDING'),
    effectiveDate: date('effective_date', { mode: 'string' }),
    endDate: date('end_date', { mode: 'string' }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('ba_provider_id_status_idx').on(table.providerId, table.status),
    uniqueIndex('ba_number_active_unique_idx')
      .on(table.baNumber)
      .where(sql`status != 'INACTIVE'`),
  ],
);

// --- PCPCM Enrolments Table ---
// Tracks PCPCM dual-BA enrolment linking the PCPCM BA and its paired FFS BA.
// One active enrolment per provider (enforced via partial unique index).

export const pcpcmEnrolments = pgTable(
  'pcpcm_enrolments',
  {
    enrolmentId: uuid('enrolment_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    pcpcmBaId: uuid('pcpcm_ba_id')
      .notNull()
      .references(() => businessArrangements.baId),
    ffsBaId: uuid('ffs_ba_id')
      .notNull()
      .references(() => businessArrangements.baId),
    panelSize: integer('panel_size'),
    enrolmentDate: date('enrolment_date', { mode: 'string' }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('PENDING'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('pcpcm_enrolments_provider_id_status_idx').on(
      table.providerId,
      table.status,
    ),
    uniqueIndex('pcpcm_enrolments_one_active_per_provider_idx')
      .on(table.providerId)
      .where(sql`status != 'WITHDRAWN'`),
  ],
);

// --- Practice Locations Table ---
// Multi-site support: each physician can have multiple practice locations.
// Each location maps to an AHCIP functional centre code.
// RRNP eligibility is derived from community_code via Reference Data.
// Exactly one is_default = true per provider where is_active = true (enforced at service layer).

export const practiceLocations = pgTable(
  'practice_locations',
  {
    locationId: uuid('location_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    name: varchar('name', { length: 100 }).notNull(),
    functionalCentre: varchar('functional_centre', { length: 10 }).notNull(),
    facilityNumber: varchar('facility_number', { length: 10 }),
    addressLine1: varchar('address_line_1', { length: 100 }),
    addressLine2: varchar('address_line_2', { length: 100 }),
    city: varchar('city', { length: 50 }),
    province: varchar('province', { length: 2 }).default('AB'),
    postalCode: varchar('postal_code', { length: 7 }),
    communityCode: varchar('community_code', { length: 10 }),
    rrnpEligible: boolean('rrnp_eligible').notNull().default(false),
    rrnpRate: decimal('rrnp_rate', { precision: 8, scale: 2 }),
    isDefault: boolean('is_default').notNull().default(false),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('practice_locations_provider_id_is_active_idx').on(
      table.providerId,
      table.isActive,
    ),
    index('practice_locations_provider_id_is_default_idx').on(
      table.providerId,
      table.isDefault,
    ),
  ],
);

// --- WCB Configurations Table ---
// Tracks WCB Alberta contract configurations per physician.
// Each provider can have multiple Contract IDs, each mapping to a Role code
// and set of permitted form types derived from the WCB matrix.
// At most one is_default = true per provider (enforced at service layer).

export const wcbConfigurations = pgTable(
  'wcb_configurations',
  {
    wcbConfigId: uuid('wcb_config_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    contractId: varchar('contract_id', { length: 10 }).notNull(),
    roleCode: varchar('role_code', { length: 10 }).notNull(),
    skillCode: varchar('skill_code', { length: 10 }),
    permittedFormTypes: jsonb('permitted_form_types').notNull(),
    isDefault: boolean('is_default').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('wcb_configurations_provider_id_idx').on(table.providerId),
    uniqueIndex('wcb_configurations_provider_contract_idx').on(
      table.providerId,
      table.contractId,
    ),
  ],
);

// --- Delegate Relationships Table ---
// Tracks physician-delegate linkage with JSONB permissions array.
// A physician grants a delegate user a subset of the 24 delegate permission keys.
// Statuses: INVITED (pending acceptance), ACTIVE, REVOKED.
// Unique constraint on (physician_id, delegate_user_id) for active/invited relationships.

export const delegateRelationships = pgTable(
  'delegate_relationships',
  {
    relationshipId: uuid('relationship_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    delegateUserId: uuid('delegate_user_id')
      .notNull()
      .references(() => users.userId),
    permissions: jsonb('permissions').notNull(),
    status: varchar('status', { length: 20 }).notNull().default('INVITED'),
    invitedAt: timestamp('invited_at', { withTimezone: true }).notNull(),
    acceptedAt: timestamp('accepted_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedBy: uuid('revoked_by').references(() => users.userId),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('delegate_relationships_physician_status_idx').on(
      table.physicianId,
      table.status,
    ),
    index('delegate_relationships_delegate_status_idx').on(
      table.delegateUserId,
      table.status,
    ),
    uniqueIndex('delegate_relationships_active_unique_idx')
      .on(table.physicianId, table.delegateUserId)
      .where(sql`status != 'REVOKED'`),
  ],
);

// --- Submission Preferences Table ---
// One row per physician. Controls AHCIP and WCB auto-submission behaviour
// and reminder settings. Defaults: AUTO_CLEAN for AHCIP, REQUIRE_APPROVAL for WCB.

export const submissionPreferences = pgTable(
  'submission_preferences',
  {
    preferenceId: uuid('preference_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .unique()
      .references(() => providers.providerId),
    ahcipSubmissionMode: varchar('ahcip_submission_mode', { length: 20 })
      .notNull()
      .default('AUTO_CLEAN'),
    wcbSubmissionMode: varchar('wcb_submission_mode', { length: 20 })
      .notNull()
      .default('REQUIRE_APPROVAL'),
    batchReviewReminder: boolean('batch_review_reminder').notNull().default(true),
    deadlineReminderDays: integer('deadline_reminder_days').notNull().default(7),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedBy: uuid('updated_by')
      .notNull()
      .references(() => users.userId),
  },
);

// --- H-Link Configurations Table ---
// One row per physician. Stores H-Link accreditation details.
// credential_secret_ref is a REFERENCE to secrets management only —
// actual H-Link transmission credentials are NEVER stored in the database.

export const hlinkConfigurations = pgTable(
  'hlink_configurations',
  {
    hlinkConfigId: uuid('hlink_config_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .unique()
      .references(() => providers.providerId),
    submitterPrefix: varchar('submitter_prefix', { length: 10 }).notNull(),
    credentialSecretRef: varchar('credential_secret_ref', { length: 100 }).notNull(),
    accreditationStatus: varchar('accreditation_status', { length: 20 })
      .notNull()
      .default('PENDING'),
    accreditationDate: date('accreditation_date', { mode: 'string' }),
    lastSuccessfulTransmission: timestamp('last_successful_transmission', {
      withTimezone: true,
    }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
);

// --- Inferred Types ---

export type InsertProvider = typeof providers.$inferInsert;
export type SelectProvider = typeof providers.$inferSelect;

export type InsertBa = typeof businessArrangements.$inferInsert;
export type SelectBa = typeof businessArrangements.$inferSelect;

export type InsertPcpcmEnrolment = typeof pcpcmEnrolments.$inferInsert;
export type SelectPcpcmEnrolment = typeof pcpcmEnrolments.$inferSelect;

export type InsertLocation = typeof practiceLocations.$inferInsert;
export type SelectLocation = typeof practiceLocations.$inferSelect;

export type InsertWcbConfig = typeof wcbConfigurations.$inferInsert;
export type SelectWcbConfig = typeof wcbConfigurations.$inferSelect;

export type InsertDelegateRelationship = typeof delegateRelationships.$inferInsert;
export type SelectDelegateRelationship = typeof delegateRelationships.$inferSelect;

export type InsertSubmissionPreferences = typeof submissionPreferences.$inferInsert;
export type SelectSubmissionPreferences = typeof submissionPreferences.$inferSelect;

export type InsertHlinkConfig = typeof hlinkConfigurations.$inferInsert;
export type SelectHlinkConfig = typeof hlinkConfigurations.$inferSelect;
