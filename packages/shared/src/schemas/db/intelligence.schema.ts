// ============================================================================
// Domain 7: Intelligence Engine — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  timestamp,
  jsonb,
  integer,
  decimal,
  text,
  index,
  unique,
} from 'drizzle-orm/pg-core';

import { claims } from './claim.schema.js';
import { providers } from './provider.schema.js';

// --- Condition Tree JSONB Structure ---
// Structured condition tree evaluated against claim context.
// Combinators (and/or/not) use children; leaf nodes use field + operator + value.

export interface CrossClaimQuery {
  /** Time window in days to look back */
  lookbackDays: number;
  /** Field to aggregate or check across claims */
  field: string;
  /** Aggregation function: count, sum, exists */
  aggregation: 'count' | 'sum' | 'exists';
  /** Filter conditions applied to the cross-claim lookup */
  filter?: Condition;
}

export type Condition = {
  type:
    | 'field_compare'
    | 'existence'
    | 'set_membership'
    | 'temporal'
    | 'cross_claim'
    | 'and'
    | 'or'
    | 'not';
  /** Dot-notation path into claim context (e.g., 'claim.healthServiceCode') */
  field?: string;
  operator?:
    | '=='
    | '!='
    | '>'
    | '<'
    | '>='
    | '<='
    | 'IS NULL'
    | 'IS NOT NULL'
    | 'IN'
    | 'NOT IN';
  /** Literal value or ref.{reference_data_key} for dynamic lookup */
  value?: unknown;
  /** Child conditions for and/or/not combinators */
  children?: Condition[];
  /** Cross-claim query definition for cross_claim type */
  query?: CrossClaimQuery;
};

// --- Suggestion Template JSONB Structure ---
// Template used to generate user-facing suggestion content.

export interface SuggestionTemplate {
  /** Title with {{field}} placeholders (e.g., 'Add {{modifier}} to {{hsc}}') */
  title: string;
  /** Description with {{field}} placeholders */
  description: string;
  /** Expression or fixed value for revenue impact calculation */
  revenue_impact_formula?: string;
  /** SOMB or regulatory reference (e.g., 'SOMB 2026 Section 3.2.1') */
  source_reference: string;
  /** URL to authoritative source */
  source_url?: string;
  /** Suggested field changes to apply if the physician accepts */
  suggested_changes?: { field: string; value_formula: string }[];
}

// --- AI Rules Table ---
// Deterministic rules evaluated by the Tier 1 rules engine.
// Each rule defines conditions under which a suggestion should be generated,
// the suggestion template to render, and priority/filtering metadata.
// Not physician-scoped — rules are system-wide reference data.

export const aiRules = pgTable(
  'ai_rules',
  {
    ruleId: uuid('rule_id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 100 }).notNull(),
    category: varchar('category', { length: 30 }).notNull(),
    claimType: varchar('claim_type', { length: 10 }).notNull(),
    conditions: jsonb('conditions').$type<Condition>().notNull(),
    suggestionTemplate: jsonb('suggestion_template')
      .$type<SuggestionTemplate>()
      .notNull(),
    specialtyFilter: jsonb('specialty_filter').$type<string[] | null>(),
    priorityFormula: varchar('priority_formula', { length: 100 }).notNull(),
    isActive: boolean('is_active').notNull().default(true),
    sombVersion: varchar('somb_version', { length: 20 }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Rule lookup by category for active rules
    index('ai_rules_category_active_idx').on(table.category, table.isActive),

    // Rule lookup by claim type for active rules
    index('ai_rules_claim_type_active_idx').on(
      table.claimType,
      table.isActive,
    ),

    // Filter rules by SOMB version
    index('ai_rules_somb_version_idx').on(table.sombVersion),
  ],
);

// --- AI Provider Learning Table ---
// Per-physician per-rule learning state. Created lazily on first suggestion.
// Tracks acceptance/dismissal rates and suppression.

export const aiProviderLearning = pgTable(
  'ai_provider_learning',
  {
    learningId: uuid('learning_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id').notNull(),
    ruleId: uuid('rule_id')
      .notNull()
      .references(() => aiRules.ruleId),
    timesShown: integer('times_shown').notNull().default(0),
    timesAccepted: integer('times_accepted').notNull().default(0),
    timesDismissed: integer('times_dismissed').notNull().default(0),
    consecutiveDismissals: integer('consecutive_dismissals').notNull().default(0),
    isSuppressed: boolean('is_suppressed').notNull().default(false),
    priorityAdjustment: integer('priority_adjustment').notNull().default(0),
    lastShownAt: timestamp('last_shown_at', { withTimezone: true }),
    lastFeedbackAt: timestamp('last_feedback_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique('ai_provider_learning_provider_rule_uniq').on(
      table.providerId,
      table.ruleId,
    ),
    index('ai_provider_learning_provider_suppressed_idx').on(
      table.providerId,
      table.isSuppressed,
    ),
    index('ai_provider_learning_rule_idx').on(table.ruleId),
  ],
);

// --- AI Specialty Cohorts Table ---
// Aggregate acceptance rates per specialty per rule. Updated nightly.
// Minimum 10 physicians per cohort for statistical validity.

export const aiSpecialtyCohorts = pgTable(
  'ai_specialty_cohorts',
  {
    cohortId: uuid('cohort_id').primaryKey().defaultRandom(),
    specialtyCode: varchar('specialty_code', { length: 10 }).notNull(),
    ruleId: uuid('rule_id')
      .notNull()
      .references(() => aiRules.ruleId),
    physicianCount: integer('physician_count').notNull(),
    acceptanceRate: decimal('acceptance_rate', {
      precision: 5,
      scale: 4,
    }).notNull(),
    medianRevenueImpact: decimal('median_revenue_impact', {
      precision: 10,
      scale: 2,
    }),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique('ai_specialty_cohorts_specialty_rule_uniq').on(
      table.specialtyCode,
      table.ruleId,
    ),
    index('ai_specialty_cohorts_specialty_idx').on(table.specialtyCode),
  ],
);

// --- AI Suggestion Events Table (Append-Only Audit Log) ---
// Records every suggestion lifecycle event: generated, accepted, dismissed, suppressed, unsuppressed.
// CRITICAL: Append-only. No UPDATE or DELETE operations. Same pattern as Domain 1 audit_log.
// No PHI stored — only billing metadata (suggestion IDs, categories, revenue impacts).

export const aiSuggestionEvents = pgTable(
  'ai_suggestion_events',
  {
    eventId: uuid('event_id').primaryKey().defaultRandom(),
    claimId: uuid('claim_id')
      .notNull()
      .references(() => claims.claimId),
    suggestionId: uuid('suggestion_id').notNull(),
    ruleId: uuid('rule_id').references(() => aiRules.ruleId),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    eventType: varchar('event_type', { length: 20 }).notNull(),
    tier: integer('tier').notNull(),
    category: varchar('category', { length: 30 }).notNull(),
    revenueImpact: decimal('revenue_impact', { precision: 10, scale: 2 }),
    dismissedReason: text('dismissed_reason'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('ai_suggestion_events_claim_idx').on(table.claimId),
    index('ai_suggestion_events_provider_created_idx').on(
      table.providerId,
      table.createdAt,
    ),
    index('ai_suggestion_events_rule_event_idx').on(
      table.ruleId,
      table.eventType,
    ),
    index('ai_suggestion_events_category_created_idx').on(
      table.category,
      table.createdAt,
    ),
  ],
);

// --- Inferred Types ---

export type InsertAiRule = typeof aiRules.$inferInsert;
export type SelectAiRule = typeof aiRules.$inferSelect;

export type InsertAiProviderLearning = typeof aiProviderLearning.$inferInsert;
export type SelectAiProviderLearning = typeof aiProviderLearning.$inferSelect;

export type InsertAiSpecialtyCohort = typeof aiSpecialtyCohorts.$inferInsert;
export type SelectAiSpecialtyCohort = typeof aiSpecialtyCohorts.$inferSelect;

export type InsertAiSuggestionEvent = typeof aiSuggestionEvents.$inferInsert;
export type SelectAiSuggestionEvent = typeof aiSuggestionEvents.$inferSelect;
