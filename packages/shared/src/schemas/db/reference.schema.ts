// ============================================================================
// Domain 2: Reference Data — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  text,
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

// --- Reference Data Versions Table ---
// Tracks versioned snapshots of each reference data set (SOMB, WCB, etc.).
// At most one version per data_set may be active at a time (enforced by partial unique index).
// Published versions are immutable — corrections require a new version.

export const referenceDataVersions = pgTable(
  'reference_data_versions',
  {
    versionId: uuid('version_id').primaryKey().defaultRandom(),
    dataSet: varchar('data_set', { length: 30 }).notNull(),
    versionLabel: varchar('version_label', { length: 50 }).notNull(),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
    publishedBy: uuid('published_by')
      .notNull()
      .references(() => users.userId),
    publishedAt: timestamp('published_at', { withTimezone: true }).notNull(),
    sourceDocument: text('source_document'),
    changeSummary: text('change_summary'),
    recordsAdded: integer('records_added').notNull().default(0),
    recordsModified: integer('records_modified').notNull().default(0),
    recordsDeprecated: integer('records_deprecated').notNull().default(0),
    isActive: boolean('is_active').notNull().default(false),
  },
  (table) => [
    index('ref_versions_data_set_is_active_idx').on(
      table.dataSet,
      table.isActive,
    ),
    index('ref_versions_data_set_effective_from_idx').on(table.dataSet),
    // Partial unique index: at most one active version per data_set
    uniqueIndex('ref_versions_one_active_per_dataset_idx')
      .on(table.dataSet)
      .where(sql`is_active = true`),
  ],
);

// --- HSC Codes Table ---
// Schedule of Medical Benefits (SOMB) health service codes (~6,000+ records).
// Each record belongs to a specific version of the SOMB data set.
// No PHI — these are public reference data.

export const hscCodes = pgTable(
  'hsc_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    hscCode: varchar('hsc_code', { length: 10 }).notNull(),
    description: text('description').notNull(),
    baseFee: decimal('base_fee', { precision: 10, scale: 2 }),
    feeType: varchar('fee_type', { length: 20 }).notNull(),
    specialtyRestrictions: jsonb('specialty_restrictions')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    facilityRestrictions: jsonb('facility_restrictions')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    maxPerDay: integer('max_per_day'),
    maxPerVisit: integer('max_per_visit'),
    requiresReferral: boolean('requires_referral').notNull().default(false),
    referralValidityDays: integer('referral_validity_days'),
    combinationGroup: varchar('combination_group', { length: 20 }),
    modifierEligibility: jsonb('modifier_eligibility')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    surchargeEligible: boolean('surcharge_eligible').notNull().default(false),
    pcpcmBasket: varchar('pcpcm_basket', { length: 20 })
      .notNull()
      .default('not_applicable'),
    shadowBillingEligible: boolean('shadow_billing_eligible')
      .notNull()
      .default(false),
    notes: text('notes'),
    helpText: text('help_text'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('hsc_codes_hsc_code_version_id_idx').on(
      table.hscCode,
      table.versionId,
    ),
    index('hsc_codes_version_id_idx').on(table.versionId),
    // GIN index on description for full-text search
    index('hsc_codes_description_gin_idx').using(
      'gin',
      sql`to_tsvector('english', ${table.description})`,
    ),
    // pg_trgm indexes for fuzzy search on hsc_code and description
    index('hsc_codes_hsc_code_trgm_idx').using(
      'gin',
      sql`${table.hscCode} gin_trgm_ops`,
    ),
    index('hsc_codes_description_trgm_idx').using(
      'gin',
      sql`${table.description} gin_trgm_ops`,
    ),
  ],
);

// --- WCB Codes Table ---
// Workers' Compensation Board fee schedule (~500-1,000 records).
// Each record belongs to a specific version of the WCB data set.
// No PHI — these are public reference data.

export const wcbCodes = pgTable(
  'wcb_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    wcbCode: varchar('wcb_code', { length: 10 }).notNull(),
    description: text('description').notNull(),
    baseFee: decimal('base_fee', { precision: 10, scale: 2 }).notNull(),
    feeType: varchar('fee_type', { length: 20 }).notNull(),
    requiresClaimNumber: boolean('requires_claim_number').notNull().default(true),
    requiresEmployer: boolean('requires_employer').notNull().default(false),
    documentationRequirements: text('documentation_requirements'),
    helpText: text('help_text'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('wcb_codes_wcb_code_version_id_idx').on(
      table.wcbCode,
      table.versionId,
    ),
    index('wcb_codes_version_id_idx').on(table.versionId),
    // pg_trgm indexes for fuzzy search on wcb_code and description
    index('wcb_codes_wcb_code_trgm_idx').using(
      'gin',
      sql`${table.wcbCode} gin_trgm_ops`,
    ),
    index('wcb_codes_description_trgm_idx').using(
      'gin',
      sql`${table.description} gin_trgm_ops`,
    ),
  ],
);

// --- Modifier Definitions Table ---
// AHCIP modifier definitions (~15-20 modifiers: CMGP, LSCD, AFHR, BCP, RRNP, TM, ANE, AST, etc.).
// Each record belongs to a specific version of the modifiers data set.
// No PHI — these are public reference data.

export const modifierDefinitions = pgTable(
  'modifier_definitions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    modifierCode: varchar('modifier_code', { length: 10 }).notNull(),
    name: varchar('name', { length: 100 }).notNull(),
    description: text('description').notNull(),
    type: varchar('type', { length: 20 }).notNull(),
    calculationMethod: varchar('calculation_method', { length: 20 }).notNull(),
    calculationParams: jsonb('calculation_params')
      .notNull()
      .default(sql`'{}'::jsonb`)
      .$type<Record<string, unknown>>(),
    applicableHscFilter: jsonb('applicable_hsc_filter')
      .notNull()
      .default(sql`'{}'::jsonb`)
      .$type<Record<string, unknown>>(),
    requiresTimeDocumentation: boolean('requires_time_documentation')
      .notNull()
      .default(false),
    requiresFacility: boolean('requires_facility').notNull().default(false),
    combinableWith: jsonb('combinable_with')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    exclusiveWith: jsonb('exclusive_with')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    governingRuleReference: varchar('governing_rule_reference', { length: 20 }),
    helpText: text('help_text'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('modifier_definitions_code_version_id_idx').on(
      table.modifierCode,
      table.versionId,
    ),
    index('modifier_definitions_version_id_idx').on(table.versionId),
  ],
);

// --- Governing Rules Table ---
// AHCIP governing rules (~50-80 rules across GR 1-13 + surcharge rules).
// Each record belongs to a specific version of the governing_rules data set.
// rule_logic JSONB follows strict schema per rule_category.
// No PHI — these are public reference data.

export const governingRules = pgTable(
  'governing_rules',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    ruleId: varchar('rule_id', { length: 20 }).notNull(),
    ruleName: varchar('rule_name', { length: 200 }).notNull(),
    ruleCategory: varchar('rule_category', { length: 30 }).notNull(),
    description: text('description').notNull(),
    ruleLogic: jsonb('rule_logic')
      .notNull()
      .$type<Record<string, unknown>>(),
    severity: varchar('severity', { length: 10 }).notNull(),
    errorMessage: text('error_message').notNull(),
    helpText: text('help_text'),
    sourceReference: varchar('source_reference', { length: 100 }),
    sourceUrl: text('source_url'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('governing_rules_rule_id_version_id_idx').on(
      table.ruleId,
      table.versionId,
    ),
    index('governing_rules_rule_category_version_id_idx').on(
      table.ruleCategory,
      table.versionId,
    ),
  ],
);

// --- Functional Centres Table ---
// AHCIP functional centre codes (~2,000-3,000 records).
// Each record belongs to a specific version of the functional_centres data set.
// rrnp_community_id FK references rrnp_communities (defined in D02-005).
// No PHI — these are public reference data.

export const functionalCentres = pgTable(
  'functional_centres',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    code: varchar('code', { length: 10 }).notNull(),
    name: varchar('name', { length: 200 }).notNull(),
    facilityType: varchar('facility_type', { length: 30 }).notNull(),
    locationCity: varchar('location_city', { length: 100 }),
    locationRegion: varchar('location_region', { length: 50 }),
    rrnpCommunityId: uuid('rrnp_community_id').references(
      () => rrnpCommunities.communityId,
    ),
    active: boolean('active').notNull().default(true),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('functional_centres_code_version_id_idx').on(
      table.code,
      table.versionId,
    ),
    index('functional_centres_facility_type_version_id_idx').on(
      table.facilityType,
      table.versionId,
    ),
  ],
);

// --- DI Codes Table ---
// Diagnostic codes (~14,000 records).
// Each record belongs to a specific version of the DI data set.
// Includes surcharge/BCP qualifier flags (Attachment G).
// No PHI — these are public reference data.

export const diCodes = pgTable(
  'di_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    diCode: varchar('di_code', { length: 10 }).notNull(),
    description: text('description').notNull(),
    category: varchar('category', { length: 100 }).notNull(),
    subcategory: varchar('subcategory', { length: 100 }),
    qualifiesSurcharge: boolean('qualifies_surcharge').notNull().default(false),
    qualifiesBcp: boolean('qualifies_bcp').notNull().default(false),
    commonInSpecialty: jsonb('common_in_specialty')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    helpText: text('help_text'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('di_codes_di_code_version_id_idx').on(
      table.diCode,
      table.versionId,
    ),
    // pg_trgm indexes for fuzzy search on di_code and description
    index('di_codes_di_code_trgm_idx').using(
      'gin',
      sql`${table.diCode} gin_trgm_ops`,
    ),
    index('di_codes_description_trgm_idx').using(
      'gin',
      sql`${table.description} gin_trgm_ops`,
    ),
    // GIN index on description for full-text search
    index('di_codes_description_gin_idx').using(
      'gin',
      sql`to_tsvector('english', ${table.description})`,
    ),
  ],
);

// --- RRNP Communities Table ---
// Rural/Remote Northern Program communities (~100-200 records).
// Each record belongs to a specific version of the RRNP data set.
// No PHI — these are public reference data.

export const rrnpCommunities = pgTable(
  'rrnp_communities',
  {
    communityId: uuid('community_id').primaryKey().defaultRandom(),
    communityName: varchar('community_name', { length: 200 }).notNull(),
    rrnpPercentage: decimal('rrnp_percentage', { precision: 5, scale: 2 }).notNull(),
    rrnpTier: varchar('rrnp_tier', { length: 20 }),
    region: varchar('region', { length: 100 }),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('rrnp_communities_name_version_id_idx').on(
      table.communityName,
      table.versionId,
    ),
  ],
);

// --- PCPCM Baskets Table ---
// Primary Care Panel Comprehensive Management HSC classifications (~3,000-4,000 records).
// Each record belongs to a specific version of the PCPCM data set.
// No PHI — these are public reference data.

export const pcpcmBaskets = pgTable(
  'pcpcm_baskets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    hscCode: varchar('hsc_code', { length: 10 }).notNull(),
    basket: varchar('basket', { length: 20 }).notNull(),
    notes: text('notes'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('pcpcm_baskets_hsc_code_version_id_idx').on(
      table.hscCode,
      table.versionId,
    ),
  ],
);

// --- Statutory Holidays Table ---
// Alberta statutory holidays (~11 per year). NOT versioned — date-specific.
// Used for billing premium calculations (e.g., surcharges for services on holidays).
// No PHI — these are public reference data.

export const statutoryHolidays = pgTable(
  'statutory_holidays',
  {
    holidayId: uuid('holiday_id').primaryKey().defaultRandom(),
    date: date('date', { mode: 'string' }).notNull(),
    name: varchar('name', { length: 100 }).notNull(),
    jurisdiction: varchar('jurisdiction', { length: 20 }).notNull(),
    affectsBillingPremiums: boolean('affects_billing_premiums')
      .notNull()
      .default(true),
    year: integer('year').notNull(),
  },
  (table) => [
    uniqueIndex('statutory_holidays_date_idx').on(table.date),
    index('statutory_holidays_year_idx').on(table.year),
  ],
);

// --- Explanatory Codes Table ---
// AHCIP explanatory codes (~100-200 records) returned on claim assessments.
// Each record belongs to a specific version of the explanatory_codes data set.
// Includes Meritum-authored guidance (common_cause, suggested_action, help_text).
// No PHI — these are public reference data.

export const explanatoryCodes = pgTable(
  'explanatory_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    explCode: varchar('expl_code', { length: 10 }).notNull(),
    description: text('description').notNull(),
    severity: varchar('severity', { length: 10 }).notNull(),
    commonCause: text('common_cause'),
    suggestedAction: text('suggested_action'),
    helpText: text('help_text'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('explanatory_codes_expl_code_version_id_idx').on(
      table.explCode,
      table.versionId,
    ),
  ],
);

// --- Reference Data Staging Table ---
// Staging area for reference data uploads before validation and publishing.
// Supports the admin workflow: upload → validate → diff → publish/discard.
// staged_data JSONB holds the full parsed records from the uploaded file.
// No PHI — these are internal admin records for reference data management.

export const referenceDataStaging = pgTable(
  'reference_data_staging',
  {
    stagingId: uuid('staging_id').primaryKey().defaultRandom(),
    dataSet: varchar('data_set', { length: 30 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('uploaded'),
    uploadedBy: uuid('uploaded_by')
      .notNull()
      .references(() => users.userId),
    uploadedAt: timestamp('uploaded_at', { withTimezone: true }).notNull(),
    fileHash: varchar('file_hash', { length: 64 }).notNull(),
    recordCount: integer('record_count').notNull(),
    validationResult: jsonb('validation_result').$type<Record<string, unknown>>(),
    diffResult: jsonb('diff_result').$type<Record<string, unknown>>(),
    stagedData: jsonb('staged_data').notNull().$type<Record<string, unknown>[]>(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('reference_data_staging_data_set_status_idx').on(
      table.dataSet,
      table.status,
    ),
  ],
);

// --- Inferred Types ---

export type InsertVersion = typeof referenceDataVersions.$inferInsert;
export type SelectVersion = typeof referenceDataVersions.$inferSelect;

export type InsertHscCode = typeof hscCodes.$inferInsert;
export type SelectHscCode = typeof hscCodes.$inferSelect;

export type InsertWcbCode = typeof wcbCodes.$inferInsert;
export type SelectWcbCode = typeof wcbCodes.$inferSelect;

export type InsertModifierDefinition = typeof modifierDefinitions.$inferInsert;
export type SelectModifierDefinition = typeof modifierDefinitions.$inferSelect;

export type InsertGoverningRule = typeof governingRules.$inferInsert;
export type SelectGoverningRule = typeof governingRules.$inferSelect;

export type InsertFunctionalCentre = typeof functionalCentres.$inferInsert;
export type SelectFunctionalCentre = typeof functionalCentres.$inferSelect;

export type InsertDiCode = typeof diCodes.$inferInsert;
export type SelectDiCode = typeof diCodes.$inferSelect;

export type InsertRrnpCommunity = typeof rrnpCommunities.$inferInsert;
export type SelectRrnpCommunity = typeof rrnpCommunities.$inferSelect;

export type InsertPcpcmBasket = typeof pcpcmBaskets.$inferInsert;
export type SelectPcpcmBasket = typeof pcpcmBaskets.$inferSelect;

export type InsertStatutoryHoliday = typeof statutoryHolidays.$inferInsert;
export type SelectStatutoryHoliday = typeof statutoryHolidays.$inferSelect;

export type InsertExplanatoryCode = typeof explanatoryCodes.$inferInsert;
export type SelectExplanatoryCode = typeof explanatoryCodes.$inferSelect;

export type InsertReferenceDataStaging = typeof referenceDataStaging.$inferInsert;
export type SelectReferenceDataStaging = typeof referenceDataStaging.$inferSelect;
