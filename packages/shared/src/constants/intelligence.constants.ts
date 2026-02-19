// ============================================================================
// Domain 7: Intelligence Engine — Constants
// ============================================================================

// --- Processing Tiers (3 tiers) ---

export const IntelTier = {
  /** Deterministic Rules Engine — zero LLM cost, ~80% of suggestions */
  TIER_1: 'TIER_1',
  /** Self-Hosted LLM — low cost, ~15% of suggestions */
  TIER_2: 'TIER_2',
  /** Review Recommended — human review, ~5% of cases */
  TIER_3: 'TIER_3',
} as const;

export type IntelTier = (typeof IntelTier)[keyof typeof IntelTier];

// --- Suggestion Categories (11 total) ---

export const SuggestionCategory = {
  /** Suggest adding a modifier (Tier 1, 2) */
  MODIFIER_ADD: 'MODIFIER_ADD',
  /** Modifier is invalid or suboptimal (Tier 1) */
  MODIFIER_REMOVE: 'MODIFIER_REMOVE',
  /** Different HSC code more appropriate (Tier 1, 2) */
  CODE_ALTERNATIVE: 'CODE_ALTERNATIVE',
  /** Additional code billable for same encounter (Tier 1, 2) */
  CODE_ADDITION: 'CODE_ADDITION',
  /** Billable service performed but not claimed (Tier 1, 2) */
  MISSED_BILLING: 'MISSED_BILLING',
  /** Claim likely to be rejected (Tier 1) */
  REJECTION_RISK: 'REJECTION_RISK',
  /** Required documentation missing (Tier 1) */
  DOCUMENTATION_GAP: 'DOCUMENTATION_GAP',
  /** Different billing approach yields more revenue (Tier 1, 2) */
  FEE_OPTIMISATION: 'FEE_OPTIMISATION',
  /** WCB tier will downgrade if not submitted sooner (Tier 1) */
  WCB_TIMING: 'WCB_TIMING',
  /** WCB form has fields that improve acceptance (Tier 1) */
  WCB_COMPLETENESS: 'WCB_COMPLETENESS',
  /** Case too complex for automated analysis (Tier 3) */
  REVIEW_RECOMMENDED: 'REVIEW_RECOMMENDED',
} as const;

export type SuggestionCategory =
  (typeof SuggestionCategory)[keyof typeof SuggestionCategory];

// --- Suggestion Category Tier Applicability ---

interface SuggestionCategoryConfig {
  readonly category: SuggestionCategory;
  readonly description: string;
  readonly applicableTiers: readonly IntelTier[];
}

export const SUGGESTION_CATEGORY_CONFIGS: Readonly<
  Record<SuggestionCategory, SuggestionCategoryConfig>
> = Object.freeze({
  [SuggestionCategory.MODIFIER_ADD]: {
    category: SuggestionCategory.MODIFIER_ADD,
    description: 'Suggest adding a modifier',
    applicableTiers: Object.freeze([IntelTier.TIER_1, IntelTier.TIER_2]),
  },
  [SuggestionCategory.MODIFIER_REMOVE]: {
    category: SuggestionCategory.MODIFIER_REMOVE,
    description: 'Modifier is invalid or suboptimal',
    applicableTiers: Object.freeze([IntelTier.TIER_1]),
  },
  [SuggestionCategory.CODE_ALTERNATIVE]: {
    category: SuggestionCategory.CODE_ALTERNATIVE,
    description: 'Different HSC code more appropriate',
    applicableTiers: Object.freeze([IntelTier.TIER_1, IntelTier.TIER_2]),
  },
  [SuggestionCategory.CODE_ADDITION]: {
    category: SuggestionCategory.CODE_ADDITION,
    description: 'Additional code billable for same encounter',
    applicableTiers: Object.freeze([IntelTier.TIER_1, IntelTier.TIER_2]),
  },
  [SuggestionCategory.MISSED_BILLING]: {
    category: SuggestionCategory.MISSED_BILLING,
    description: 'Billable service performed but not claimed',
    applicableTiers: Object.freeze([IntelTier.TIER_1, IntelTier.TIER_2]),
  },
  [SuggestionCategory.REJECTION_RISK]: {
    category: SuggestionCategory.REJECTION_RISK,
    description: 'Claim likely to be rejected',
    applicableTiers: Object.freeze([IntelTier.TIER_1]),
  },
  [SuggestionCategory.DOCUMENTATION_GAP]: {
    category: SuggestionCategory.DOCUMENTATION_GAP,
    description: 'Required documentation missing',
    applicableTiers: Object.freeze([IntelTier.TIER_1]),
  },
  [SuggestionCategory.FEE_OPTIMISATION]: {
    category: SuggestionCategory.FEE_OPTIMISATION,
    description: 'Different billing approach yields more revenue',
    applicableTiers: Object.freeze([IntelTier.TIER_1, IntelTier.TIER_2]),
  },
  [SuggestionCategory.WCB_TIMING]: {
    category: SuggestionCategory.WCB_TIMING,
    description: 'WCB tier will downgrade if not submitted sooner',
    applicableTiers: Object.freeze([IntelTier.TIER_1]),
  },
  [SuggestionCategory.WCB_COMPLETENESS]: {
    category: SuggestionCategory.WCB_COMPLETENESS,
    description: 'WCB form has fields that improve acceptance',
    applicableTiers: Object.freeze([IntelTier.TIER_1]),
  },
  [SuggestionCategory.REVIEW_RECOMMENDED]: {
    category: SuggestionCategory.REVIEW_RECOMMENDED,
    description: 'Case too complex for automated analysis',
    applicableTiers: Object.freeze([IntelTier.TIER_3]),
  },
});

// --- Suggestion Priorities ---

export const SuggestionPriority = {
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
} as const;

export type SuggestionPriority =
  (typeof SuggestionPriority)[keyof typeof SuggestionPriority];

// --- Priority Threshold Defaults (configurable per specialty) ---

interface PriorityThresholdConfig {
  readonly priority: SuggestionPriority;
  readonly revenueImpactMin: string;
  readonly revenueImpactMax: string | null;
  readonly rejectionRiskMin: number;
  readonly rejectionRiskMax: number | null;
  readonly description: string;
}

export const PRIORITY_THRESHOLD_DEFAULTS: Readonly<
  Record<SuggestionPriority, PriorityThresholdConfig>
> = Object.freeze({
  [SuggestionPriority.HIGH]: {
    priority: SuggestionPriority.HIGH,
    revenueImpactMin: '20.01',
    revenueImpactMax: null,
    rejectionRiskMin: 0.80,
    rejectionRiskMax: null,
    description: 'Revenue impact > $20 OR rejection risk confidence > 0.80',
  },
  [SuggestionPriority.MEDIUM]: {
    priority: SuggestionPriority.MEDIUM,
    revenueImpactMin: '5.00',
    revenueImpactMax: '20.00',
    rejectionRiskMin: 0.50,
    rejectionRiskMax: 0.80,
    description: 'Revenue impact $5–$20 OR rejection risk 0.50–0.80',
  },
  [SuggestionPriority.LOW]: {
    priority: SuggestionPriority.LOW,
    revenueImpactMin: '0.00',
    revenueImpactMax: '5.00',
    rejectionRiskMin: 0,
    rejectionRiskMax: 0.50,
    description: 'Revenue impact < $5, informational, or documentation',
  },
});

// --- Suggestion Statuses ---

export const SuggestionStatus = {
  PENDING: 'PENDING',
  ACCEPTED: 'ACCEPTED',
  DISMISSED: 'DISMISSED',
} as const;

export type SuggestionStatus =
  (typeof SuggestionStatus)[keyof typeof SuggestionStatus];

// --- Suggestion Event Types ---

export const SuggestionEventType = {
  GENERATED: 'GENERATED',
  ACCEPTED: 'ACCEPTED',
  DISMISSED: 'DISMISSED',
  SUPPRESSED: 'SUPPRESSED',
  UNSUPPRESSED: 'UNSUPPRESSED',
} as const;

export type SuggestionEventType =
  (typeof SuggestionEventType)[keyof typeof SuggestionEventType];

// --- Rule Claim Types ---

export const RuleClaimType = {
  AHCIP: 'AHCIP',
  WCB: 'WCB',
  BOTH: 'BOTH',
} as const;

export type RuleClaimType =
  (typeof RuleClaimType)[keyof typeof RuleClaimType];

// --- Learning Loop Constants ---

/** Consecutive dismissals before a rule is suppressed for a physician */
export const SUPPRESSION_THRESHOLD = 5;

/** Minimum physicians per specialty cohort before aggregate data is used */
export const MIN_COHORT_SIZE = 10;

/** Claims processed before personalisation overrides specialty defaults */
export const CALIBRATION_CLAIMS = 50;

/** Rolling window in days for seasonal pattern detection */
export const ROLLING_WINDOW_DAYS = 90;

/** Tier 2 LLM latency budget in milliseconds */
export const LLM_TIMEOUT_MS = 3000;

/** Below this confidence, Tier 2 escalates to Tier 3 (human review) */
export const LLM_CONFIDENCE_THRESHOLD = 0.60;

// --- MVP Rule Categories ---

interface RuleCategoryCount {
  readonly category: string;
  readonly approximateCount: number;
  readonly description: string;
}

export const MVP_RULE_CATEGORIES: readonly RuleCategoryCount[] = Object.freeze([
  {
    category: 'MODIFIER_ELIGIBILITY',
    approximateCount: 30,
    description: 'Rules for modifier applicability and eligibility',
  },
  {
    category: 'REJECTION_PREVENTION',
    approximateCount: 40,
    description: 'Rules to prevent claim rejection based on known patterns',
  },
  {
    category: 'WCB_SPECIFIC',
    approximateCount: 20,
    description: 'WCB-specific billing rules and timing optimisation',
  },
  {
    category: 'PATTERN_BASED',
    approximateCount: 15,
    description: 'Rules derived from billing patterns and specialty norms',
  },
] as const);

/** Total approximate number of rules at MVP launch */
export const MVP_TOTAL_RULE_COUNT = 105;

// --- Intelligence Engine Audit Actions ---

export const IntelAuditAction = {
  SUGGESTION_GENERATED: 'intel.suggestion_generated',
  SUGGESTION_ACCEPTED: 'intel.suggestion_accepted',
  SUGGESTION_DISMISSED: 'intel.suggestion_dismissed',
  RULE_SUPPRESSED: 'intel.rule_suppressed',
  RULE_UNSUPPRESSED: 'intel.rule_unsuppressed',
  LLM_ESCALATION: 'intel.llm_escalation',
  PREFERENCES_UPDATED: 'intel.preferences_updated',
  CLAIM_ANALYSED: 'intel.claim_analysed',
} as const;

export type IntelAuditAction =
  (typeof IntelAuditAction)[keyof typeof IntelAuditAction];
