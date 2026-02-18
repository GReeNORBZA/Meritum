// ============================================================================
// Domain 4.1: AHCIP Pathway — Constants
// ============================================================================

import { ValidationSeverity } from './claim.constants.js';

// --- AHCIP Batch Status ---

export const AhcipBatchStatus = {
  ASSEMBLING: 'ASSEMBLING',
  GENERATED: 'GENERATED',
  SUBMITTED: 'SUBMITTED',
  RESPONSE_RECEIVED: 'RESPONSE_RECEIVED',
  RECONCILED: 'RECONCILED',
  ERROR: 'ERROR',
} as const;

export type AhcipBatchStatus =
  (typeof AhcipBatchStatus)[keyof typeof AhcipBatchStatus];

// --- AHCIP Validation Check IDs (A1–A19) ---

export const AhcipValidationCheckId = {
  A1_HSC_CODE_VALID: 'A1_HSC_CODE_VALID',
  A2_HSC_ACTIVE_ON_DOS: 'A2_HSC_ACTIVE_ON_DOS',
  A3_BA_NUMBER_VALID: 'A3_BA_NUMBER_VALID',
  A4_GOVERNING_RULES: 'A4_GOVERNING_RULES',
  A5_MODIFIER_ELIGIBILITY: 'A5_MODIFIER_ELIGIBILITY',
  A6_MODIFIER_COMBINATION: 'A6_MODIFIER_COMBINATION',
  A7_DIAGNOSTIC_CODE_REQUIRED: 'A7_DIAGNOSTIC_CODE_REQUIRED',
  A8_FACILITY_REQUIRED: 'A8_FACILITY_REQUIRED',
  A9_REFERRAL_REQUIRED: 'A9_REFERRAL_REQUIRED',
  A10_DI_SURCHARGE_ELIGIBILITY: 'A10_DI_SURCHARGE_ELIGIBILITY',
  A11_PCPCM_ROUTING: 'A11_PCPCM_ROUTING',
  A12_AFTER_HOURS_ELIGIBILITY: 'A12_AFTER_HOURS_ELIGIBILITY',
  A13_90_DAY_WINDOW: 'A13_90_DAY_WINDOW',
  A14_TIME_BASED_DURATION: 'A14_TIME_BASED_DURATION',
  A15_CALL_COUNT_VALID: 'A15_CALL_COUNT_VALID',
  A16_SHADOW_BILLING_CONSISTENCY: 'A16_SHADOW_BILLING_CONSISTENCY',
  A17_RRNP_ELIGIBILITY: 'A17_RRNP_ELIGIBILITY',
  A18_PREMIUM_ELIGIBILITY_351: 'A18_PREMIUM_ELIGIBILITY_351',
  A19_BUNDLING_CHECK: 'A19_BUNDLING_CHECK',
} as const;

export type AhcipValidationCheckId =
  (typeof AhcipValidationCheckId)[keyof typeof AhcipValidationCheckId];

// --- AHCIP Validation Check Configuration ---

interface AhcipValidationCheckConfig {
  readonly id: AhcipValidationCheckId;
  readonly defaultSeverity: ValidationSeverity;
  readonly description: string;
}

/**
 * A13 has dual severity: ERROR when the 90-day window has expired,
 * WARNING when within 7 days of expiry. The default severity here
 * reflects the expired (error) case; the validation engine overrides
 * to WARNING for the approaching-deadline case.
 */
export const AHCIP_VALIDATION_CHECKS: Readonly<
  Record<AhcipValidationCheckId, AhcipValidationCheckConfig>
> = Object.freeze({
  [AhcipValidationCheckId.A1_HSC_CODE_VALID]: {
    id: AhcipValidationCheckId.A1_HSC_CODE_VALID,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'health_service_code exists in current SOMB schedule (version-aware by DOS)',
  },
  [AhcipValidationCheckId.A2_HSC_ACTIVE_ON_DOS]: {
    id: AhcipValidationCheckId.A2_HSC_ACTIVE_ON_DOS,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'HSC was active (not retired/added-after) on the date_of_service',
  },
  [AhcipValidationCheckId.A3_BA_NUMBER_VALID]: {
    id: AhcipValidationCheckId.A3_BA_NUMBER_VALID,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'ba_number is a valid, active BA for this physician',
  },
  [AhcipValidationCheckId.A4_GOVERNING_RULES]: {
    id: AhcipValidationCheckId.A4_GOVERNING_RULES,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Claim satisfies all applicable governing rules for the HSC code',
  },
  [AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY]: {
    id: AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Each modifier is valid for the HSC code and encounter context',
  },
  [AhcipValidationCheckId.A6_MODIFIER_COMBINATION]: {
    id: AhcipValidationCheckId.A6_MODIFIER_COMBINATION,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Modifier combinations are valid (no mutually exclusive pairs)',
  },
  [AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED]: {
    id: AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Diagnostic code present and valid in ICD-9 when required by HSC category',
  },
  [AhcipValidationCheckId.A8_FACILITY_REQUIRED]: {
    id: AhcipValidationCheckId.A8_FACILITY_REQUIRED,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'facility_number present and valid for hospital-based encounters',
  },
  [AhcipValidationCheckId.A9_REFERRAL_REQUIRED]: {
    id: AhcipValidationCheckId.A9_REFERRAL_REQUIRED,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Referring practitioner billing number present for specialist consultations (GR 8)',
  },
  [AhcipValidationCheckId.A10_DI_SURCHARGE_ELIGIBILITY]: {
    id: AhcipValidationCheckId.A10_DI_SURCHARGE_ELIGIBILITY,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'DI surcharge conditions validated (equipment type, certification) for eligible DI codes',
  },
  [AhcipValidationCheckId.A11_PCPCM_ROUTING]: {
    id: AhcipValidationCheckId.A11_PCPCM_ROUTING,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'PCPCM basket classification validated; in-basket to PCPCM BA, out-of-basket to FFS BA',
  },
  [AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY]: {
    id: AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'After-hours flag validated: HSC permits after-hours premium and time qualifies',
  },
  [AhcipValidationCheckId.A13_90_DAY_WINDOW]: {
    id: AhcipValidationCheckId.A13_90_DAY_WINDOW,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'DOS within 90 calendar days. Error if expired; warning if within 7 days of deadline',
  },
  [AhcipValidationCheckId.A14_TIME_BASED_DURATION]: {
    id: AhcipValidationCheckId.A14_TIME_BASED_DURATION,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'time_spent present and within valid range for time-based HSC codes',
  },
  [AhcipValidationCheckId.A15_CALL_COUNT_VALID]: {
    id: AhcipValidationCheckId.A15_CALL_COUNT_VALID,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'calls value within valid range for the HSC code (typically 1 unless multiple-call code)',
  },
  [AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY]: {
    id: AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'shadow_billing_flag=true requires modifier TM and fee=$0',
  },
  [AhcipValidationCheckId.A17_RRNP_ELIGIBILITY]: {
    id: AhcipValidationCheckId.A17_RRNP_ELIGIBILITY,
    defaultSeverity: ValidationSeverity.INFO,
    description:
      'Physician qualifies for RRNP; calculates and notes RRNP premium amount',
  },
  [AhcipValidationCheckId.A18_PREMIUM_ELIGIBILITY_351]: {
    id: AhcipValidationCheckId.A18_PREMIUM_ELIGIBILITY_351,
    defaultSeverity: ValidationSeverity.INFO,
    description:
      'HSC in 351 premium code list; notes any premium conditions',
  },
  [AhcipValidationCheckId.A19_BUNDLING_CHECK]: {
    id: AhcipValidationCheckId.A19_BUNDLING_CHECK,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'Checks for potential bundling with other claims for same patient on same DOS per governing rules',
  },
});

// --- After-Hours Type ---

export const AfterHoursType = {
  EVENING: 'EVENING',
  WEEKEND: 'WEEKEND',
  NIGHT: 'NIGHT',
  STAT_HOLIDAY: 'STAT_HOLIDAY',
} as const;

export type AfterHoursType =
  (typeof AfterHoursType)[keyof typeof AfterHoursType];

// --- After-Hours Time Slot Definitions ---
// Hours are in 24h format, Mountain Time (MT).

interface TimeSlotDefinition {
  readonly type: AfterHoursType | null;
  readonly label: string;
  readonly description: string;
}

export const AFTER_HOURS_TIME_SLOTS: readonly TimeSlotDefinition[] =
  Object.freeze([
    {
      type: null,
      label: 'Standard Hours',
      description: 'Monday–Friday, 08:00–17:00 (excl. statutory holidays)',
    },
    {
      type: AfterHoursType.EVENING,
      label: 'Evening',
      description: 'Monday–Friday, 17:00–23:00',
    },
    {
      type: AfterHoursType.NIGHT,
      label: 'Night',
      description: '23:00–08:00 any day',
    },
    {
      type: AfterHoursType.WEEKEND,
      label: 'Weekend',
      description: 'Saturday/Sunday full day',
    },
    {
      type: AfterHoursType.STAT_HOLIDAY,
      label: 'Statutory Holiday',
      description: '10 named Alberta statutory holidays, full day',
    },
  ] as const);

// --- Standard Hours Boundaries ---

export const STANDARD_HOURS_START = 8; // 08:00 MT
export const STANDARD_HOURS_END = 17; // 17:00 MT
export const EVENING_HOURS_END = 23; // 23:00 MT

// --- Alberta Statutory Holidays (10 named) ---
// Day-of-year varies; the application resolves actual dates per calendar year
// from the Reference Data holiday calendar.

export const ALBERTA_STATUTORY_HOLIDAYS = Object.freeze([
  'New Year\'s Day',
  'Family Day',
  'Good Friday',
  'Victoria Day',
  'Canada Day',
  'Heritage Day',
  'Labour Day',
  'Thanksgiving Day',
  'Remembrance Day',
  'Christmas Day',
] as const);

export type AlbertaStatutoryHoliday =
  (typeof ALBERTA_STATUTORY_HOLIDAYS)[number];

// --- AHCIP Encounter Type ---

export const AhcipEncounterType = {
  CONSULTATION: 'CONSULTATION',
  FOLLOW_UP: 'FOLLOW_UP',
  PROCEDURE: 'PROCEDURE',
  SURGICAL: 'SURGICAL',
  DIAGNOSTIC_IMAGING: 'DIAGNOSTIC_IMAGING',
  OBSTETRIC: 'OBSTETRIC',
  CDM: 'CDM',
  VIRTUAL: 'VIRTUAL',
  OTHER: 'OTHER',
} as const;

export type AhcipEncounterType =
  (typeof AhcipEncounterType)[keyof typeof AhcipEncounterType];

// --- Well-Known Modifier Codes ---

export const AhcipModifierCode = {
  TM: 'TM',
  AFHR: 'AFHR',
  CMGP: 'CMGP',
  LOCI: 'LOCI',
  ED_SURCHARGE: '13.99H',
  BMI: 'BMI',
} as const;

export type AhcipModifierCode =
  (typeof AhcipModifierCode)[keyof typeof AhcipModifierCode];

interface ModifierCodeConfig {
  readonly code: AhcipModifierCode;
  readonly name: string;
  readonly feeImpact: string;
}

export const AHCIP_MODIFIER_CONFIGS: Readonly<
  Record<AhcipModifierCode, ModifierCodeConfig>
> = Object.freeze({
  [AhcipModifierCode.TM]: {
    code: AhcipModifierCode.TM,
    name: 'Shadow Billing (ARP)',
    feeImpact: 'Fee = $0.00. Claim recorded for panel tracking, no payment.',
  },
  [AhcipModifierCode.AFHR]: {
    code: AhcipModifierCode.AFHR,
    name: 'After-Hours',
    feeImpact:
      'Adds after-hours premium. Amount varies by HSC category and time slot.',
  },
  [AhcipModifierCode.CMGP]: {
    code: AhcipModifierCode.CMGP,
    name: 'Comprehensive Care',
    feeImpact: 'Adds CMGP premium to qualifying office visit codes.',
  },
  [AhcipModifierCode.LOCI]: {
    code: AhcipModifierCode.LOCI,
    name: 'Locum',
    feeImpact:
      'No fee impact. Identifies claim as billed by a locum on behalf of the regular physician.',
  },
  [AhcipModifierCode.ED_SURCHARGE]: {
    code: AhcipModifierCode.ED_SURCHARGE,
    name: 'ED Surcharge',
    feeImpact:
      'Adds emergency department surcharge for qualifying ED visits.',
  },
  [AhcipModifierCode.BMI]: {
    code: AhcipModifierCode.BMI,
    name: 'Body Mass Index',
    feeImpact:
      'Percentage modifier for certain procedural codes based on patient BMI category.',
  },
});

// --- Governing Rule (representative set) ---

export const GoverningRule = {
  GR_1: 'GR_1',
  GR_3: 'GR_3',
  GR_5: 'GR_5',
  GR_8: 'GR_8',
  GR_10: 'GR_10',
  GR_14: 'GR_14',
  GR_18: 'GR_18',
} as const;

export type GoverningRule =
  (typeof GoverningRule)[keyof typeof GoverningRule];

interface GoverningRuleConfig {
  readonly id: GoverningRule;
  readonly name: string;
  readonly summary: string;
}

export const GOVERNING_RULE_CONFIGS: Readonly<
  Record<GoverningRule, GoverningRuleConfig>
> = Object.freeze({
  [GoverningRule.GR_1]: {
    id: GoverningRule.GR_1,
    name: 'General',
    summary:
      'Applies to all codes. Basic requirements: valid date, valid patient, valid provider.',
  },
  [GoverningRule.GR_3]: {
    id: GoverningRule.GR_3,
    name: 'Visit Limits',
    summary:
      'Limits on number of visits per patient per time period. Hospital: typically 1/day. Office: varies by code.',
  },
  [GoverningRule.GR_5]: {
    id: GoverningRule.GR_5,
    name: 'Diagnostic Imaging',
    summary:
      'Special rules for DI codes. Facility requirements, surcharge eligibility, BCP qualification.',
  },
  [GoverningRule.GR_8]: {
    id: GoverningRule.GR_8,
    name: 'Referrals',
    summary:
      'Specialist consultations require a valid referring practitioner within specified timeframe.',
  },
  [GoverningRule.GR_10]: {
    id: GoverningRule.GR_10,
    name: 'Surgical',
    summary:
      'Operating room codes. Anaesthesia requirements, assistant rules, post-operative visit windows.',
  },
  [GoverningRule.GR_14]: {
    id: GoverningRule.GR_14,
    name: 'Obstetric',
    summary:
      'Obstetric package rules. Global fee vs unbundled services. Gestational age requirements.',
  },
  [GoverningRule.GR_18]: {
    id: GoverningRule.GR_18,
    name: 'Chronic Disease Management',
    summary:
      'Requirements for CDM billing codes. Documentation, care plan, team-based care.',
  },
});

// --- Batch Cycle Constants ---
// Thursday 12:00 MT cutoff per FRD Section 3.1.

/** Day of week for batch cutoff: 4 = Thursday (JS Date.getDay() convention) */
export const BATCH_CUTOFF_DAY = 4;

/** Hour (MT, 24h) at which the batch cutoff occurs */
export const BATCH_CUTOFF_HOUR = 12;

/** Retry intervals in seconds for H-Link submission failures (exponential backoff) */
export const BATCH_RETRY_INTERVALS_S = Object.freeze([
  60, 300, 900, 3600,
] as const);

/** Maximum number of H-Link submission retry attempts */
export const BATCH_MAX_RETRIES = 4;

// --- Fee Formula Reference ---
// submitted_fee = base_fee × calls + modifier_adjustments + premiums
// This is documented in FRD Section 6.1. The constants below support
// the fee engine but the actual calculation lives in the service layer.

/** Default number of calls for a standard claim */
export const DEFAULT_CALL_COUNT = 1;

/** Shadow billing fee amount (always $0.00 for TM modifier) */
export const SHADOW_BILLING_FEE = '0.00';
