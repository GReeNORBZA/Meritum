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
  foreignKey,
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
    category: varchar('category', { length: 100 }),
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
    governingRuleReferences: jsonb('governing_rule_references')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    selfReferralBlocked: boolean('self_referral_blocked')
      .notNull()
      .default(false),
    ageRestriction: jsonb('age_restriction').$type<{
      text: string;
      minYears?: number;
      maxYears?: number;
      minMonths?: number;
      maxMonths?: number;
    } | null>(),
    frequencyRestriction: jsonb('frequency_restriction').$type<{
      text: string;
      count: number;
      period: string;
    } | null>(),
    requiresAnesthesia: boolean('requires_anesthesia')
      .notNull()
      .default(false),
    pcpcmBasket: varchar('pcpcm_basket', { length: 20 })
      .notNull()
      .default('not_applicable'),
    shadowBillingEligible: boolean('shadow_billing_eligible')
      .notNull()
      .default(false),
    facilityDesignation: varchar('facility_designation', { length: 20 }),
    notes: text('notes'),
    helpText: text('help_text'),
    billingTips: text('billing_tips'),
    commonTerms: jsonb('common_terms')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    uniqueIndex('hsc_codes_hsc_code_version_id_unique_idx').on(
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

// --- HSC Modifier Eligibility Table ---
// Per-code modifier eligibility rows (~41,000 records from Fee Navigator).
// Each row specifies how a particular modifier sub-code applies to an HSC code:
// the action (Replace Base, Increase By, etc.) and the amount ($40.23, 25%).
// No PHI — these are public reference data.

export const hscModifierEligibility = pgTable(
  'hsc_modifier_eligibility',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    hscCode: varchar('hsc_code', { length: 10 }).notNull(),
    modifierType: varchar('modifier_type', { length: 10 }).notNull(),
    subCode: varchar('sub_code', { length: 20 }).notNull(),
    calls: varchar('calls', { length: 20 }),
    explicit: boolean('explicit').notNull().default(false),
    action: varchar('action', { length: 50 }).notNull(),
    amount: varchar('amount', { length: 20 }).notNull(),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('hsc_modifier_elig_hsc_code_version_id_idx').on(
      table.hscCode,
      table.versionId,
    ),
    index('hsc_modifier_elig_type_version_id_idx').on(
      table.modifierType,
      table.versionId,
    ),
    uniqueIndex('hsc_modifier_elig_code_type_sub_calls_version_idx').on(
      table.hscCode,
      table.modifierType,
      table.subCode,
      table.calls,
      table.versionId,
    ),
    // FK to hsc_codes on (hsc_code, version_id)
    foreignKey({
      columns: [table.hscCode, table.versionId],
      foreignColumns: [hscCodes.hscCode, hscCodes.versionId],
    }),
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
    descriptionHtml: text('description_html'),
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

// --- ICD Crosswalk Table (FRD CC-001 §A4) ---
// Maps ICD-10-CA codes to ICD-9-CM equivalents for AHCIP claims.
// Each row belongs to a versioned data set. Multiple ICD-9 mappings
// per ICD-10 code are possible (one preferred per ICD-10 code).

export const icdCrosswalk = pgTable(
  'icd_crosswalk',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    icd10Code: varchar('icd10_code', { length: 10 }).notNull(),
    icd10Description: text('icd10_description').notNull(),
    icd9Code: varchar('icd9_code', { length: 10 }).notNull(),
    icd9Description: text('icd9_description').notNull(),
    matchQuality: varchar('match_quality', { length: 20 }).notNull(),
    isPreferred: boolean('is_preferred').notNull().default(false),
    notes: text('notes'),
    versionId: uuid('version_id')
      .notNull()
      .references(() => referenceDataVersions.versionId),
    effectiveFrom: date('effective_from', { mode: 'string' }).notNull(),
    effectiveTo: date('effective_to', { mode: 'string' }),
  },
  (table) => [
    index('icd_crosswalk_icd10_code_version_idx').on(
      table.icd10Code,
      table.versionId,
    ),
    index('icd_crosswalk_icd9_code_version_idx').on(
      table.icd9Code,
      table.versionId,
    ),
    index('icd_crosswalk_version_id_idx').on(table.versionId),
  ],
);

// --- Provider Registry Table (FRD MVPADD-001 §B1) ---
// Public directory of Alberta physicians for referral lookups.
// NOT physician-scoped — system-wide reference data.
// pg_trgm index on name for fuzzy/prefix search.

export const providerRegistry = pgTable(
  'provider_registry',
  {
    registryId: uuid('registry_id').primaryKey().defaultRandom(),
    cpsa: varchar('cpsa', { length: 10 }).notNull(),
    firstName: varchar('first_name', { length: 50 }).notNull(),
    lastName: varchar('last_name', { length: 50 }).notNull(),
    specialtyCode: varchar('specialty_code', { length: 10 }).notNull(),
    specialtyDescription: varchar('specialty_description', { length: 100 }),
    city: varchar('city', { length: 100 }),
    facilityName: varchar('facility_name', { length: 200 }),
    phone: varchar('phone', { length: 24 }),
    fax: varchar('fax', { length: 24 }),
    isActive: boolean('is_active').notNull().default(true),
    lastSyncedAt: timestamp('last_synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('provider_registry_cpsa_unique_idx').on(table.cpsa),
    index('provider_registry_specialty_idx').on(table.specialtyCode),
    index('provider_registry_city_idx').on(table.city),
    index('provider_registry_name_trgm_idx').using(
      'gin',
      sql`(last_name || ' ' || first_name) gin_trgm_ops`,
    ),
  ],
);

// --- Billing Guidance Table (FRD MVPADD-001 §B6) ---
// Curated billing guidance entries organized by category.
// NOT physician-scoped — system-wide reference data.

export const billingGuidance = pgTable(
  'billing_guidance',
  {
    guidanceId: uuid('guidance_id').primaryKey().defaultRandom(),
    category: varchar('category', { length: 30 }).notNull(),
    title: varchar('title', { length: 200 }).notNull(),
    content: text('content').notNull(),
    applicableSpecialties: jsonb('applicable_specialties')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    applicableHscCodes: jsonb('applicable_hsc_codes')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    sourceReference: varchar('source_reference', { length: 200 }),
    sourceUrl: text('source_url'),
    sortOrder: integer('sort_order').notNull().default(0),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('billing_guidance_category_active_idx').on(
      table.category,
      table.isActive,
    ),
    index('billing_guidance_content_gin_idx').using(
      'gin',
      sql`to_tsvector('english', ${table.content})`,
    ),
  ],
);

// --- Provincial PHN Formats Table (FRD MVPADD-001 §B8) ---
// PHN format definitions for all 11 Canadian province/territory codes.
// Used for reciprocal billing province detection.

export const provincialPhnFormats = pgTable(
  'provincial_phn_formats',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    provinceCode: varchar('province_code', { length: 2 }).notNull(),
    provinceName: varchar('province_name', { length: 50 }).notNull(),
    phnLength: integer('phn_length').notNull(),
    phnRegex: varchar('phn_regex', { length: 100 }).notNull(),
    validationAlgorithm: varchar('validation_algorithm', { length: 30 }),
    notes: text('notes'),
  },
  (table) => [
    uniqueIndex('provincial_phn_formats_province_unique_idx').on(
      table.provinceCode,
    ),
  ],
);

// --- Reciprocal Billing Rules Table (FRD MVPADD-001 §B8) ---
// Province-specific reciprocal billing rules, fees, and submission requirements.

export const reciprocalBillingRules = pgTable(
  'reciprocal_billing_rules',
  {
    ruleId: uuid('rule_id').primaryKey().defaultRandom(),
    sourceProvince: varchar('source_province', { length: 2 }).notNull(),
    claimType: varchar('claim_type', { length: 10 }).notNull(),
    submissionMethod: varchar('submission_method', { length: 30 }).notNull(),
    feeScheduleSource: varchar('fee_schedule_source', { length: 30 }).notNull(),
    deadlineDays: integer('deadline_days').notNull(),
    notes: text('notes'),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('reciprocal_billing_rules_province_type_idx').on(
      table.sourceProvince,
      table.claimType,
    ),
  ],
);

// --- Anesthesia Rules Table (FRD MVPADD-001 §B7) ---
// Anesthesia calculation rules (GR 12), 10 scenarios.
// NOT physician-scoped — system-wide reference data.

export const anesthesiaRules = pgTable(
  'anesthesia_rules',
  {
    ruleId: uuid('rule_id').primaryKey().defaultRandom(),
    scenarioCode: varchar('scenario_code', { length: 30 }).notNull(),
    scenarioLabel: varchar('scenario_label', { length: 100 }).notNull(),
    description: text('description').notNull(),
    baseUnits: integer('base_units'),
    timeUnitMinutes: integer('time_unit_minutes'),
    calculationFormula: text('calculation_formula').notNull(),
    applicableModifiers: jsonb('applicable_modifiers')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    sourceReference: varchar('source_reference', { length: 100 }),
    sortOrder: integer('sort_order').notNull().default(0),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('anesthesia_rules_scenario_unique_idx').on(table.scenarioCode),
    index('anesthesia_rules_active_sort_idx').on(
      table.isActive,
      table.sortOrder,
    ),
  ],
);

// --- Bundling Rules Table (FRD MVPADD-001 §B9) ---
// Defines code-pair bundling relationships for AHCIP claims.
// Constraint: code_a < code_b (canonical ordering, avoids duplicate pairs).

export const bundlingRules = pgTable(
  'bundling_rules',
  {
    ruleId: uuid('rule_id').primaryKey().defaultRandom(),
    codeA: varchar('code_a', { length: 10 }).notNull(),
    codeB: varchar('code_b', { length: 10 }).notNull(),
    relationship: varchar('relationship', { length: 30 }).notNull(),
    description: text('description'),
    overrideAllowed: boolean('override_allowed').notNull().default(false),
    sourceReference: varchar('source_reference', { length: 100 }),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Canonical pair constraint: code_a < code_b
    uniqueIndex('bundling_rules_code_pair_unique_idx').on(
      table.codeA,
      table.codeB,
    ),
    index('bundling_rules_code_a_active_idx').on(table.codeA, table.isActive),
    index('bundling_rules_code_b_active_idx').on(table.codeB, table.isActive),
  ],
);

// --- Justification Templates Table (FRD MVPADD-001 §B11) ---
// Reusable justification text templates for specific scenarios.
// NOT physician-scoped — system-wide reference data.

export const justificationTemplates = pgTable(
  'justification_templates',
  {
    templateId: uuid('template_id').primaryKey().defaultRandom(),
    scenario: varchar('scenario', { length: 40 }).notNull(),
    name: varchar('name', { length: 200 }).notNull(),
    templateText: text('template_text').notNull(),
    placeholders: jsonb('placeholders')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    applicableSpecialties: jsonb('applicable_specialties')
      .notNull()
      .default(sql`'[]'::jsonb`)
      .$type<string[]>(),
    sortOrder: integer('sort_order').notNull().default(0),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('justification_templates_scenario_active_idx').on(
      table.scenario,
      table.isActive,
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

export type InsertHscModifierEligibility = typeof hscModifierEligibility.$inferInsert;
export type SelectHscModifierEligibility = typeof hscModifierEligibility.$inferSelect;

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

export type InsertIcdCrosswalk = typeof icdCrosswalk.$inferInsert;
export type SelectIcdCrosswalk = typeof icdCrosswalk.$inferSelect;

export type InsertProviderRegistry = typeof providerRegistry.$inferInsert;
export type SelectProviderRegistry = typeof providerRegistry.$inferSelect;

export type InsertBillingGuidance = typeof billingGuidance.$inferInsert;
export type SelectBillingGuidance = typeof billingGuidance.$inferSelect;

export type InsertProvincialPhnFormat = typeof provincialPhnFormats.$inferInsert;
export type SelectProvincialPhnFormat = typeof provincialPhnFormats.$inferSelect;

export type InsertReciprocalBillingRule = typeof reciprocalBillingRules.$inferInsert;
export type SelectReciprocalBillingRule = typeof reciprocalBillingRules.$inferSelect;

export type InsertAnesthesiaRule = typeof anesthesiaRules.$inferInsert;
export type SelectAnesthesiaRule = typeof anesthesiaRules.$inferSelect;

export type InsertBundlingRule = typeof bundlingRules.$inferInsert;
export type SelectBundlingRule = typeof bundlingRules.$inferSelect;

export type InsertJustificationTemplate = typeof justificationTemplates.$inferInsert;
export type SelectJustificationTemplate = typeof justificationTemplates.$inferSelect;
