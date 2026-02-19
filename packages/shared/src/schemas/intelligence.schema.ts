// ============================================================================
// Domain 7: Intelligence Engine — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  SuggestionCategory,
  SuggestionPriority,
  SuggestionStatus,
  RuleClaimType,
} from '../constants/intelligence.constants.js';

// --- Enum Value Arrays ---

const SUGGESTION_CATEGORIES = [
  SuggestionCategory.MODIFIER_ADD,
  SuggestionCategory.MODIFIER_REMOVE,
  SuggestionCategory.CODE_ALTERNATIVE,
  SuggestionCategory.CODE_ADDITION,
  SuggestionCategory.MISSED_BILLING,
  SuggestionCategory.REJECTION_RISK,
  SuggestionCategory.DOCUMENTATION_GAP,
  SuggestionCategory.FEE_OPTIMISATION,
  SuggestionCategory.WCB_TIMING,
  SuggestionCategory.WCB_COMPLETENESS,
  SuggestionCategory.REVIEW_RECOMMENDED,
] as const;

const SUGGESTION_PRIORITIES = [
  SuggestionPriority.HIGH,
  SuggestionPriority.MEDIUM,
  SuggestionPriority.LOW,
] as const;

const SUGGESTION_STATUSES = [
  SuggestionStatus.PENDING,
  SuggestionStatus.ACCEPTED,
  SuggestionStatus.DISMISSED,
] as const;

const RULE_CLAIM_TYPES = [
  RuleClaimType.AHCIP,
  RuleClaimType.WCB,
  RuleClaimType.BOTH,
] as const;

// ============================================================================
// Suggestion Endpoints (consumed by Domain 4)
// ============================================================================

// --- Claim Context (anonymised billing metadata for analysis) ---

const claimContextSchema = z.object({
  claim_type: z.enum(['AHCIP', 'WCB']),
  health_service_code: z.string().min(1).max(10),
  modifiers: z.array(z.string().max(4)).default([]),
  date_of_service: z.string().date(),
  provider_specialty: z.string().max(10),
  patient_demographics_anonymised: z.object({
    age_range: z.string().max(20).optional(),
    gender: z.string().max(10).optional(),
  }),
  diagnostic_codes: z.array(z.string().max(10)).default([]),
  encounter_type: z.string().max(20).optional(),
  facility_type: z.string().max(30).optional(),
  text_amount: z.string().regex(/^\d+\.\d{2}$/).optional(),
  time_spent: z.number().int().positive().optional(),
  referring_provider: z.boolean().optional(),
});

// --- Analyse Claim ---

export const analyseClaimSchema = z.object({
  claim_id: z.string().uuid(),
  claim_context: claimContextSchema,
});

export type AnalyseClaim = z.infer<typeof analyseClaimSchema>;

// --- Claim Suggestions Param (path: /claims/:claim_id/suggestions) ---

export const claimSuggestionsParamSchema = z.object({
  claim_id: z.string().uuid(),
});

export type ClaimSuggestionsParam = z.infer<typeof claimSuggestionsParamSchema>;

// --- Suggestion ID Param ---

export const intelSuggestionIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type IntelSuggestionIdParam = z.infer<typeof intelSuggestionIdParamSchema>;

// --- Accept Suggestion (no body, suggestion ID in URL) ---

export const acceptSuggestionSchema = z.object({});

export type AcceptSuggestion = z.infer<typeof acceptSuggestionSchema>;

// --- Dismiss Suggestion ---

export const intelDismissSuggestionSchema = z.object({
  reason: z.string().max(500).optional(),
});

export type IntelDismissSuggestion = z.infer<typeof intelDismissSuggestionSchema>;

// ============================================================================
// Suggestion Response Schema (JSONB validation)
// ============================================================================

const suggestedChangeSchema = z.object({
  field: z.string(),
  current_value: z.string().nullable(),
  suggested_value: z.string(),
});

export const suggestionResponseSchema = z.object({
  suggestion_id: z.string().uuid(),
  tier: z.number().int().min(1).max(3),
  category: z.enum(SUGGESTION_CATEGORIES),
  priority: z.enum(SUGGESTION_PRIORITIES),
  title: z.string().max(200),
  description: z.string(),
  revenue_impact: z.number().nullable(),
  confidence: z.number().min(0).max(1).nullable(),
  source_reference: z.string().max(200),
  source_url: z.string().url().max(500).optional(),
  suggested_changes: z.array(suggestedChangeSchema).nullable(),
  status: z.enum(SUGGESTION_STATUSES),
  dismissed_reason: z.string().nullable(),
  created_at: z.string().datetime(),
  resolved_at: z.string().datetime().nullable(),
  resolved_by: z.string().uuid().nullable(),
});

export type SuggestionResponse = z.infer<typeof suggestionResponseSchema>;

// ============================================================================
// Learning & Preferences
// ============================================================================

// --- Unsuppress Rule Param ---

export const unsuppressRuleParamSchema = z.object({
  rule_id: z.string().uuid(),
});

export type UnsuppressRuleParam = z.infer<typeof unsuppressRuleParamSchema>;

// --- Update Preferences ---

const priorityThresholdsSchema = z.object({
  high_revenue: z.string().regex(/^\d+\.\d{2}$/),
  medium_revenue: z.string().regex(/^\d+\.\d{2}$/),
});

export const updateIntelPreferencesSchema = z.object({
  enabled_categories: z.array(z.enum(SUGGESTION_CATEGORIES)).optional(),
  disabled_categories: z.array(z.enum(SUGGESTION_CATEGORIES)).optional(),
  priority_thresholds: priorityThresholdsSchema.optional(),
});

export type UpdateIntelPreferences = z.infer<typeof updateIntelPreferencesSchema>;

// ============================================================================
// Rule Management (Admin)
// ============================================================================

// --- Condition Tree (JSONB — validated as opaque object at API boundary) ---

const conditionSchema: z.ZodType = z.lazy(() =>
  z.object({
    type: z.enum([
      'field_compare',
      'existence',
      'set_membership',
      'temporal',
      'cross_claim',
      'and',
      'or',
      'not',
    ]),
    field: z.string().optional(),
    operator: z.enum([
      '==', '!=', '>', '<', '>=', '<=',
      'IS NULL', 'IS NOT NULL', 'IN', 'NOT IN',
    ]).optional(),
    value: z.unknown().optional(),
    children: z.array(z.lazy(() => conditionSchema)).optional(),
    query: z.object({
      lookbackDays: z.number().int().positive(),
      field: z.string(),
      aggregation: z.enum(['count', 'sum', 'exists']),
      filter: z.lazy(() => conditionSchema).optional(),
    }).optional(),
  }),
);

// --- Suggestion Template (JSONB) ---

const suggestionTemplateSchema = z.object({
  title: z.string().max(200),
  description: z.string(),
  revenue_impact_formula: z.string().max(200).optional(),
  source_reference: z.string().max(200),
  source_url: z.string().url().max(500).optional(),
  suggested_changes: z.array(z.object({
    field: z.string(),
    value_formula: z.string(),
  })).optional(),
});

// --- Create Rule ---

export const createRuleSchema = z.object({
  name: z.string().min(1).max(100),
  category: z.enum(SUGGESTION_CATEGORIES),
  claim_type: z.enum(RULE_CLAIM_TYPES),
  conditions: conditionSchema,
  suggestion_template: suggestionTemplateSchema,
  specialty_filter: z.array(z.string().max(10)).nullable().default(null),
  priority_formula: z.string().min(1).max(100),
  somb_version: z.string().max(20).optional(),
});

export type CreateRule = z.infer<typeof createRuleSchema>;

// --- Update Rule (partial of create) ---

export const updateRuleSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  category: z.enum(SUGGESTION_CATEGORIES).optional(),
  claim_type: z.enum(RULE_CLAIM_TYPES).optional(),
  conditions: conditionSchema.optional(),
  suggestion_template: suggestionTemplateSchema.optional(),
  specialty_filter: z.array(z.string().max(10)).nullable().optional(),
  priority_formula: z.string().min(1).max(100).optional(),
  somb_version: z.string().max(20).optional(),
});

export type UpdateRule = z.infer<typeof updateRuleSchema>;

// --- Rule ID Param ---

export const ruleIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type RuleIdParam = z.infer<typeof ruleIdParamSchema>;

// --- Activate Rule ---

export const activateRuleSchema = z.object({
  is_active: z.boolean(),
});

export type ActivateRule = z.infer<typeof activateRuleSchema>;

// --- Rule List Query ---

export const ruleListQuerySchema = z.object({
  category: z.enum(SUGGESTION_CATEGORIES).optional(),
  claim_type: z.enum(RULE_CLAIM_TYPES).optional(),
  is_active: z.coerce.boolean().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(50),
});

export type RuleListQuery = z.infer<typeof ruleListQuerySchema>;

// ============================================================================
// SOMB Change Analysis
// ============================================================================

export const sombChangeAnalysisSchema = z.object({
  old_version: z.string().min(1).max(20),
  new_version: z.string().min(1).max(20),
});

export type SombChangeAnalysis = z.infer<typeof sombChangeAnalysisSchema>;
