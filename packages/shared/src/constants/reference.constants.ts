// ============================================================================
// Domain 2: Reference Data — Constants
// ============================================================================

// --- Data Set Identifiers ---

export const ReferenceDataSet = {
  SOMB: 'SOMB',
  WCB: 'WCB',
  MODIFIERS: 'MODIFIERS',
  GOVERNING_RULES: 'GOVERNING_RULES',
  FUNCTIONAL_CENTRES: 'FUNCTIONAL_CENTRES',
  DI_CODES: 'DI_CODES',
  RRNP: 'RRNP',
  PCPCM: 'PCPCM',
  EXPLANATORY_CODES: 'EXPLANATORY_CODES',
} as const;

export type ReferenceDataSet =
  (typeof ReferenceDataSet)[keyof typeof ReferenceDataSet];

// --- Fee Types ---

export const FeeType = {
  FIXED: 'fixed',
  CALCULATED: 'calculated',
  TIME_BASED: 'time_based',
  UNIT_BASED: 'unit_based',
  REPORT_BASED: 'report_based',
} as const;

export type FeeType = (typeof FeeType)[keyof typeof FeeType];

// --- Modifier Types ---

export const ModifierType = {
  EXPLICIT: 'explicit',
  IMPLICIT: 'implicit',
  SEMI_IMPLICIT: 'semi_implicit',
} as const;

export type ModifierType = (typeof ModifierType)[keyof typeof ModifierType];

// --- Modifier Calculation Methods ---

export const ModifierCalculationMethod = {
  PERCENTAGE: 'percentage',
  FIXED_AMOUNT: 'fixed_amount',
  TIME_BASED_UNITS: 'time_based_units',
  MULTIPLIER: 'multiplier',
  NONE: 'none',
} as const;

export type ModifierCalculationMethod =
  (typeof ModifierCalculationMethod)[keyof typeof ModifierCalculationMethod];

// --- Rule Categories ---

export const RuleCategory = {
  VISIT_LIMITS: 'visit_limits',
  CODE_COMBINATIONS: 'code_combinations',
  MODIFIER_RULES: 'modifier_rules',
  REFERRAL_RULES: 'referral_rules',
  FACILITY_RULES: 'facility_rules',
  SURCHARGE_RULES: 'surcharge_rules',
  TIME_RULES: 'time_rules',
  GENERAL: 'general',
} as const;

export type RuleCategory = (typeof RuleCategory)[keyof typeof RuleCategory];

// --- Rule Severities ---

export const RuleSeverity = {
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
} as const;

export type RuleSeverity = (typeof RuleSeverity)[keyof typeof RuleSeverity];

// --- Facility Types ---

export const FacilityType = {
  OFFICE: 'office',
  HOSPITAL_INPATIENT: 'hospital_inpatient',
  HOSPITAL_OUTPATIENT: 'hospital_outpatient',
  EMERGENCY: 'emergency',
  AUXILIARY_HOSPITAL: 'auxiliary_hospital',
  NURSING_HOME: 'nursing_home',
  TELEHEALTH: 'telehealth',
  COMMUNITY_HEALTH: 'community_health',
  OTHER: 'other',
} as const;

export type FacilityType = (typeof FacilityType)[keyof typeof FacilityType];

// --- PCPCM Basket Types ---

export const PcpcmBasketType = {
  IN_BASKET: 'in_basket',
  OUT_OF_BASKET: 'out_of_basket',
  FACILITY: 'facility',
  NOT_APPLICABLE: 'not_applicable',
} as const;

export type PcpcmBasketType =
  (typeof PcpcmBasketType)[keyof typeof PcpcmBasketType];

// --- Holiday Jurisdictions ---

export const HolidayJurisdiction = {
  PROVINCIAL: 'provincial',
  FEDERAL: 'federal',
  BOTH: 'both',
} as const;

export type HolidayJurisdiction =
  (typeof HolidayJurisdiction)[keyof typeof HolidayJurisdiction];

// --- Explanatory Code Severities ---

export const ExplanatoryCodeSeverity = {
  PAID: 'paid',
  ADJUSTED: 'adjusted',
  REJECTED: 'rejected',
} as const;

export type ExplanatoryCodeSeverity =
  (typeof ExplanatoryCodeSeverity)[keyof typeof ExplanatoryCodeSeverity];

// --- Staging Statuses ---

export const StagingStatus = {
  UPLOADED: 'UPLOADED',
  VALIDATED: 'VALIDATED',
  DIFF_GENERATED: 'DIFF_GENERATED',
  PUBLISHED: 'PUBLISHED',
  DISCARDED: 'DISCARDED',
} as const;

export type StagingStatus =
  (typeof StagingStatus)[keyof typeof StagingStatus];

// --- Version Event Types ---

export const VersionEventType = {
  VERSION_PUBLISHED: 'VERSION_PUBLISHED',
  CODE_DEPRECATED: 'CODE_DEPRECATED',
  HOLIDAY_CALENDAR_REMINDER: 'HOLIDAY_CALENDAR_REMINDER',
} as const;

export type VersionEventType =
  (typeof VersionEventType)[keyof typeof VersionEventType];

// --- Reference Data Audit Actions ---

export const ReferenceAuditAction = {
  VERSION_STAGED: 'ref.version_staged',
  VERSION_DIFF_REVIEWED: 'ref.version_diff_reviewed',
  VERSION_PUBLISHED: 'ref.version_published',
  VERSION_ROLLED_BACK: 'ref.version_rolled_back',
  STAGING_DISCARDED: 'ref.staging_discarded',
  RULE_DRY_RUN: 'ref.rule_dry_run',
  HOLIDAY_CREATED: 'ref.holiday_created',
  HOLIDAY_UPDATED: 'ref.holiday_updated',
  HOLIDAY_DELETED: 'ref.holiday_deleted',
} as const;

export type ReferenceAuditAction =
  (typeof ReferenceAuditAction)[keyof typeof ReferenceAuditAction];
