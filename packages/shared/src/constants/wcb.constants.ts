// ============================================================================
// Domain 4.2: WCB Pathway — Constants
// ============================================================================

import { ValidationSeverity } from './claim.constants.js';

// --- WCB Form Types (8 forms) ---

export const WcbFormType = {
  C050E: 'C050E',
  C050S: 'C050S',
  C151: 'C151',
  C151S: 'C151S',
  C568: 'C568',
  C568A: 'C568A',
  C569: 'C569',
  C570: 'C570',
} as const;

export type WcbFormType = (typeof WcbFormType)[keyof typeof WcbFormType];

// --- Form Type Metadata ---

interface WcbFormTypeConfig {
  readonly formType: WcbFormType;
  readonly name: string;
  readonly description: string;
  readonly isInitial: boolean;
  readonly fieldCount: number;
  readonly requiredFieldCount: number;
}

export const WCB_FORM_TYPE_CONFIGS: Readonly<
  Record<WcbFormType, WcbFormTypeConfig>
> = Object.freeze({
  [WcbFormType.C050E]: {
    formType: WcbFormType.C050E,
    name: 'Physician First Report',
    description: 'Initial physician report for a new WCB claim',
    isInitial: true,
    fieldCount: 111,
    requiredFieldCount: 38,
  },
  [WcbFormType.C050S]: {
    formType: WcbFormType.C050S,
    name: 'OIS Physician First Report',
    description: 'Initial physician report with OIS appendix for occupational injury service',
    isInitial: true,
    fieldCount: 171,
    requiredFieldCount: 70,
  },
  [WcbFormType.C151]: {
    formType: WcbFormType.C151,
    name: 'Physician Progress Report',
    description: 'Follow-up progress report on an existing WCB claim',
    isInitial: false,
    fieldCount: 136,
    requiredFieldCount: 39,
  },
  [WcbFormType.C151S]: {
    formType: WcbFormType.C151S,
    name: 'OIS Physician Progress Report',
    description: 'Follow-up progress report with OIS appendix',
    isInitial: false,
    fieldCount: 153,
    requiredFieldCount: 39,
  },
  [WcbFormType.C568]: {
    formType: WcbFormType.C568,
    name: 'Medical Invoice',
    description: 'Invoice for medical services rendered under a WCB claim',
    isInitial: false,
    fieldCount: 61,
    requiredFieldCount: 17,
  },
  [WcbFormType.C568A]: {
    formType: WcbFormType.C568A,
    name: 'Medical Consultation Report',
    description: 'Consultation report and invoice for specialist assessment',
    isInitial: false,
    fieldCount: 69,
    requiredFieldCount: 19,
  },
  [WcbFormType.C569]: {
    formType: WcbFormType.C569,
    name: 'Medical Supplies Invoice',
    description: 'Invoice for medical supplies provided under a WCB claim',
    isInitial: false,
    fieldCount: 37,
    requiredFieldCount: 18,
  },
  [WcbFormType.C570]: {
    formType: WcbFormType.C570,
    name: 'Medical Invoice Correction',
    description: 'Correction to a previously submitted medical invoice',
    isInitial: false,
    fieldCount: 66,
    requiredFieldCount: 18,
  },
});

// --- Form Section Matrix ---
// Defines which sections appear on each form type.

export const WcbFormSection = {
  GENERAL: 'GENERAL',
  CLAIMANT: 'CLAIMANT',
  PRACTITIONER: 'PRACTITIONER',
  EMPLOYER: 'EMPLOYER',
  ACCIDENT: 'ACCIDENT',
  INJURY: 'INJURY',
  TREATMENT_PLAN: 'TREATMENT_PLAN',
  RETURN_TO_WORK: 'RETURN_TO_WORK',
  ATTACHMENTS: 'ATTACHMENTS',
  INVOICE: 'INVOICE',
} as const;

export type WcbFormSection =
  (typeof WcbFormSection)[keyof typeof WcbFormSection];

const ALL_SECTIONS: readonly WcbFormSection[] = Object.freeze([
  WcbFormSection.GENERAL,
  WcbFormSection.CLAIMANT,
  WcbFormSection.PRACTITIONER,
  WcbFormSection.EMPLOYER,
  WcbFormSection.ACCIDENT,
  WcbFormSection.INJURY,
  WcbFormSection.TREATMENT_PLAN,
  WcbFormSection.RETURN_TO_WORK,
  WcbFormSection.ATTACHMENTS,
  WcbFormSection.INVOICE,
]);

export const WCB_FORM_SECTION_MATRIX: Readonly<
  Record<WcbFormType, readonly WcbFormSection[]>
> = Object.freeze({
  [WcbFormType.C050E]: ALL_SECTIONS,
  [WcbFormType.C050S]: ALL_SECTIONS,
  [WcbFormType.C151]: ALL_SECTIONS,
  [WcbFormType.C151S]: ALL_SECTIONS,
  [WcbFormType.C568]: Object.freeze([
    WcbFormSection.GENERAL,
    WcbFormSection.CLAIMANT,
    WcbFormSection.PRACTITIONER,
    WcbFormSection.ACCIDENT,
    WcbFormSection.INJURY,
    WcbFormSection.INVOICE,
  ]),
  [WcbFormType.C568A]: Object.freeze([
    WcbFormSection.GENERAL,
    WcbFormSection.CLAIMANT,
    WcbFormSection.PRACTITIONER,
    WcbFormSection.ACCIDENT,
    WcbFormSection.INJURY,
    WcbFormSection.TREATMENT_PLAN,
    WcbFormSection.INVOICE,
  ]),
  [WcbFormType.C569]: Object.freeze([
    WcbFormSection.GENERAL,
    WcbFormSection.CLAIMANT,
    WcbFormSection.PRACTITIONER,
    WcbFormSection.ACCIDENT,
    WcbFormSection.INVOICE,
  ]),
  [WcbFormType.C570]: Object.freeze([
    WcbFormSection.GENERAL,
    WcbFormSection.CLAIMANT,
    WcbFormSection.PRACTITIONER,
    WcbFormSection.ACCIDENT,
    WcbFormSection.INVOICE,
  ]),
});

// --- Practitioner Role Codes (10 roles) ---

export const WcbPractitionerRole = {
  GP: 'GP',
  OR: 'OR',
  SP: 'SP',
  ERS: 'ERS',
  ANE: 'ANE',
  DP: 'DP',
  VSC: 'VSC',
  VSCFAC: 'VSCFAC',
  OIS: 'OIS',
  NP: 'NP',
} as const;

export type WcbPractitionerRole =
  (typeof WcbPractitionerRole)[keyof typeof WcbPractitionerRole];

// --- Contract ID / Role / Form ID Permission Matrix (Initial Reports) ---

interface WcbContractRolePermission {
  readonly contractId: string;
  readonly role: WcbPractitionerRole;
  readonly allowedInitialForms: readonly WcbFormType[];
}

export const WCB_INITIAL_FORM_PERMISSIONS: readonly WcbContractRolePermission[] =
  Object.freeze([
    {
      contractId: '000001',
      role: WcbPractitionerRole.GP,
      allowedInitialForms: Object.freeze([WcbFormType.C050E, WcbFormType.C568]),
    },
    {
      contractId: '000004',
      role: WcbPractitionerRole.OR,
      allowedInitialForms: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000006',
      role: WcbPractitionerRole.SP,
      allowedInitialForms: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000006',
      role: WcbPractitionerRole.ERS,
      allowedInitialForms: Object.freeze([WcbFormType.C050E, WcbFormType.C568]),
    },
    {
      contractId: '000006',
      role: WcbPractitionerRole.ANE,
      allowedInitialForms: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000022',
      role: WcbPractitionerRole.DP,
      allowedInitialForms: Object.freeze([WcbFormType.C568]),
    },
    {
      contractId: '000023',
      role: WcbPractitionerRole.DP,
      allowedInitialForms: Object.freeze([WcbFormType.C568]),
    },
    {
      contractId: '000024',
      role: WcbPractitionerRole.VSC,
      allowedInitialForms: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000025',
      role: WcbPractitionerRole.VSCFAC,
      allowedInitialForms: Object.freeze([WcbFormType.C568]),
    },
    {
      contractId: '000052',
      role: WcbPractitionerRole.DP,
      allowedInitialForms: Object.freeze([WcbFormType.C568]),
    },
    {
      contractId: '000053',
      role: WcbPractitionerRole.OIS,
      allowedInitialForms: Object.freeze([WcbFormType.C050S, WcbFormType.C568]),
    },
    {
      contractId: '000065',
      role: WcbPractitionerRole.GP,
      allowedInitialForms: Object.freeze([WcbFormType.C568]),
    },
    {
      contractId: '000066',
      role: WcbPractitionerRole.SP,
      allowedInitialForms: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000084',
      role: WcbPractitionerRole.NP,
      allowedInitialForms: Object.freeze([WcbFormType.C050E, WcbFormType.C568]),
    },
  ] as const);

// --- Follow-up Form Permission Matrix ---

interface WcbFollowUpPermission {
  readonly contractId: string;
  readonly role: WcbPractitionerRole;
  readonly allowedFollowUpForms: readonly WcbFormType[];
  readonly canCreateFrom: readonly WcbFormType[];
}

export const WCB_FOLLOW_UP_FORM_PERMISSIONS: readonly WcbFollowUpPermission[] =
  Object.freeze([
    {
      contractId: '000001',
      role: WcbPractitionerRole.GP,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C151,
        WcbFormType.C568,
        WcbFormType.C569,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([
        WcbFormType.C050E,
        WcbFormType.C151,
        WcbFormType.C568,
      ]),
    },
    {
      contractId: '000006',
      role: WcbPractitionerRole.ERS,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C151,
        WcbFormType.C568,
        WcbFormType.C569,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([
        WcbFormType.C050E,
        WcbFormType.C151,
        WcbFormType.C568,
      ]),
    },
    {
      contractId: '000006',
      role: WcbPractitionerRole.SP,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C568A,
        WcbFormType.C568,
        WcbFormType.C569,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000006',
      role: WcbPractitionerRole.ANE,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C568A,
        WcbFormType.C568,
        WcbFormType.C569,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000004',
      role: WcbPractitionerRole.OR,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C568A,
        WcbFormType.C568,
        WcbFormType.C569,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([WcbFormType.C568A, WcbFormType.C568]),
    },
    {
      contractId: '000053',
      role: WcbPractitionerRole.OIS,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C151S,
        WcbFormType.C568,
        WcbFormType.C569,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([
        WcbFormType.C050S,
        WcbFormType.C151S,
        WcbFormType.C568,
      ]),
    },
    {
      contractId: '000084',
      role: WcbPractitionerRole.NP,
      allowedFollowUpForms: Object.freeze([
        WcbFormType.C151,
        WcbFormType.C568,
        WcbFormType.C570,
      ]),
      canCreateFrom: Object.freeze([
        WcbFormType.C050E,
        WcbFormType.C151,
        WcbFormType.C568,
      ]),
    },
  ] as const);

// --- Facility Types ---

export const WcbFacilityType = {
  C: 'C',
  F: 'F',
  H: 'H',
} as const;

export type WcbFacilityType =
  (typeof WcbFacilityType)[keyof typeof WcbFacilityType];

interface WcbFacilityTypeConfig {
  readonly code: WcbFacilityType;
  readonly name: string;
}

export const WCB_FACILITY_TYPE_CONFIGS: Readonly<
  Record<WcbFacilityType, WcbFacilityTypeConfig>
> = Object.freeze({
  [WcbFacilityType.C]: {
    code: WcbFacilityType.C,
    name: 'Clinic',
  },
  [WcbFacilityType.F]: {
    code: WcbFacilityType.F,
    name: 'Facility Non-Hospital',
  },
  [WcbFacilityType.H]: {
    code: WcbFacilityType.H,
    name: 'Hospital',
  },
});

// --- WCB Batch Statuses ---

export const WcbBatchStatus = {
  ASSEMBLING: 'ASSEMBLING',
  GENERATED: 'GENERATED',
  VALIDATED: 'VALIDATED',
  UPLOADED: 'UPLOADED',
  RETURN_RECEIVED: 'RETURN_RECEIVED',
  RECONCILED: 'RECONCILED',
  ERROR: 'ERROR',
} as const;

export type WcbBatchStatus =
  (typeof WcbBatchStatus)[keyof typeof WcbBatchStatus];

// --- WCB Return Report Statuses ---

export const WcbReturnReportStatus = {
  COMPLETE: 'COMPLETE',
  INVALID: 'INVALID',
} as const;

export type WcbReturnReportStatus =
  (typeof WcbReturnReportStatus)[keyof typeof WcbReturnReportStatus];

// --- WCB Payment Status Codes (7 values) ---

export const WcbPaymentStatus = {
  ISS: 'ISS',
  REQ: 'REQ',
  PAE: 'PAE',
  PGA: 'PGA',
  PGD: 'PGD',
  REJ: 'REJ',
  DEL: 'DEL',
} as const;

export type WcbPaymentStatus =
  (typeof WcbPaymentStatus)[keyof typeof WcbPaymentStatus];

interface WcbPaymentStatusConfig {
  readonly code: WcbPaymentStatus;
  readonly name: string;
}

export const WCB_PAYMENT_STATUS_CONFIGS: Readonly<
  Record<WcbPaymentStatus, WcbPaymentStatusConfig>
> = Object.freeze({
  [WcbPaymentStatus.ISS]: {
    code: WcbPaymentStatus.ISS,
    name: 'Issued',
  },
  [WcbPaymentStatus.REQ]: {
    code: WcbPaymentStatus.REQ,
    name: 'Requested',
  },
  [WcbPaymentStatus.PAE]: {
    code: WcbPaymentStatus.PAE,
    name: 'Pending Approval',
  },
  [WcbPaymentStatus.PGA]: {
    code: WcbPaymentStatus.PGA,
    name: 'Pending Approval',
  },
  [WcbPaymentStatus.PGD]: {
    code: WcbPaymentStatus.PGD,
    name: 'Pending Decision',
  },
  [WcbPaymentStatus.REJ]: {
    code: WcbPaymentStatus.REJ,
    name: 'Rejected',
  },
  [WcbPaymentStatus.DEL]: {
    code: WcbPaymentStatus.DEL,
    name: 'Deleted',
  },
});

// --- WCB Timing Tiers ---

export const WcbTimingTier = {
  SAME_DAY: 'SAME_DAY',
  ON_TIME: 'ON_TIME',
  LATE: 'LATE',
} as const;

export type WcbTimingTier =
  (typeof WcbTimingTier)[keyof typeof WcbTimingTier];

// --- WCB Fee Schedule (2025) ---

interface WcbFeeScheduleEntry {
  readonly formCode: string;
  readonly description: string;
  readonly sameDayFee: string;
  readonly onTimeFee: string;
  readonly lateFee: string;
}

export const WCB_FEE_SCHEDULE_2025: readonly WcbFeeScheduleEntry[] =
  Object.freeze([
    {
      formCode: 'C050E',
      description: 'Physician First Report',
      sameDayFee: '94.15',
      onTimeFee: '85.80',
      lateFee: '54.08',
    },
    {
      formCode: 'C151',
      description: 'Physician Progress Report',
      sameDayFee: '57.19',
      onTimeFee: '52.12',
      lateFee: '32.86',
    },
    {
      formCode: 'RF01E',
      description: 'Specialist Consultation',
      sameDayFee: '115.05',
      onTimeFee: '104.87',
      lateFee: '66.09',
    },
    {
      formCode: 'RF03E',
      description: 'Specialist Follow-up',
      sameDayFee: '57.19',
      onTimeFee: '52.12',
      lateFee: '32.86',
    },
  ] as const);

// --- Timing Deadline Rules ---

interface WcbTimingDeadlineRule {
  readonly formType: string;
  readonly sameDayDescription: string;
  readonly onTimeDescription: string;
  /** Business days after exam date to remain on-time */
  readonly onTimeBusinessDays: number;
  /** Hour (MT, 24h) by which submission must occur on the deadline day */
  readonly deadlineHourMT: number;
}

export const WCB_TIMING_DEADLINE_RULES: readonly WcbTimingDeadlineRule[] =
  Object.freeze([
    {
      formType: 'C050E',
      sameDayDescription: 'Exam day or next business day by 10:00 MT',
      onTimeDescription: 'Within 3 business days (by 10:00 MT on day 4)',
      onTimeBusinessDays: 3,
      deadlineHourMT: 10,
    },
    {
      formType: 'C151',
      sameDayDescription: 'Exam day or next business day by 10:00 MT',
      onTimeDescription: 'Within 4 business days (by 10:00 MT on day 5)',
      onTimeBusinessDays: 4,
      deadlineHourMT: 10,
    },
    {
      formType: 'C568A',
      sameDayDescription: 'Exam day or next business day by 10:00 MT',
      onTimeDescription: 'Within 4 business days (by 10:00 MT on day 5)',
      onTimeBusinessDays: 4,
      deadlineHourMT: 10,
    },
  ] as const);

// --- Alberta Statutory Holidays for WCB Business Day Calculation (10 named) ---
// Day-of-year varies; the application resolves actual dates per calendar year.

export const WCB_ALBERTA_STATUTORY_HOLIDAYS = Object.freeze([
  'New Year\'s Day',
  'Family Day',
  'Good Friday',
  'Victoria Day',
  'Canada Day',
  'Heritage Day',
  'Labour Day',
  'Truth and Reconciliation Day',
  'Thanksgiving Day',
  'Christmas Day',
] as const);

export type WcbAlbertaStatutoryHoliday =
  (typeof WCB_ALBERTA_STATUTORY_HOLIDAYS)[number];

// --- Invoice Line Types ---

export const WcbInvoiceLineType = {
  STANDARD: 'STANDARD',
  DATED: 'DATED',
  SUPPLY: 'SUPPLY',
  WAS: 'WAS',
  SHOULD_BE: 'SHOULD_BE',
} as const;

export type WcbInvoiceLineType =
  (typeof WcbInvoiceLineType)[keyof typeof WcbInvoiceLineType];

// --- Consultation Categories ---

export const WcbConsultationCategory = {
  CONREF: 'CONREF',
  INVE: 'INVE',
} as const;

export type WcbConsultationCategory =
  (typeof WcbConsultationCategory)[keyof typeof WcbConsultationCategory];

interface WcbConsultationCategoryConfig {
  readonly code: WcbConsultationCategory;
  readonly name: string;
}

export const WCB_CONSULTATION_CATEGORY_CONFIGS: Readonly<
  Record<WcbConsultationCategory, WcbConsultationCategoryConfig>
> = Object.freeze({
  [WcbConsultationCategory.CONREF]: {
    code: WcbConsultationCategory.CONREF,
    name: 'Consultation/Referral',
  },
  [WcbConsultationCategory.INVE]: {
    code: WcbConsultationCategory.INVE,
    name: 'Investigation',
  },
});

// --- WCB Validation Check IDs (16 checks from Section 4.1 pipeline) ---

export const WcbValidationCheckId = {
  FORM_ID_VALID: 'FORM_ID_VALID',
  CONTRACT_ROLE_FORM: 'CONTRACT_ROLE_FORM',
  REQUIRED_FIELDS: 'REQUIRED_FIELDS',
  CONDITIONAL_LOGIC: 'CONDITIONAL_LOGIC',
  DATA_TYPE_LENGTH: 'DATA_TYPE_LENGTH',
  DATE_VALIDATION: 'DATE_VALIDATION',
  POB_NOI_COMBINATION: 'POB_NOI_COMBINATION',
  SIDE_OF_BODY: 'SIDE_OF_BODY',
  CODE_TABLE_VALUES: 'CODE_TABLE_VALUES',
  SUBMITTER_TXN_FORMAT: 'SUBMITTER_TXN_FORMAT',
  PHN_LOGIC: 'PHN_LOGIC',
  INVOICE_LINE_INTEGRITY: 'INVOICE_LINE_INTEGRITY',
  ATTACHMENT_CONSTRAINTS: 'ATTACHMENT_CONSTRAINTS',
  TIMING_DEADLINE: 'TIMING_DEADLINE',
  EXPEDITE_ELIGIBILITY: 'EXPEDITE_ELIGIBILITY',
  DUPLICATE_DETECTION: 'DUPLICATE_DETECTION',
} as const;

export type WcbValidationCheckId =
  (typeof WcbValidationCheckId)[keyof typeof WcbValidationCheckId];

interface WcbValidationCheckConfig {
  readonly id: WcbValidationCheckId;
  readonly defaultSeverity: ValidationSeverity;
  readonly description: string;
}

export const WCB_VALIDATION_CHECKS: Readonly<
  Record<WcbValidationCheckId, WcbValidationCheckConfig>
> = Object.freeze({
  [WcbValidationCheckId.FORM_ID_VALID]: {
    id: WcbValidationCheckId.FORM_ID_VALID,
    defaultSeverity: ValidationSeverity.ERROR,
    description: 'Form ID is a recognized WCB form type (C050E, C050S, etc.)',
  },
  [WcbValidationCheckId.CONTRACT_ROLE_FORM]: {
    id: WcbValidationCheckId.CONTRACT_ROLE_FORM,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Contract ID + Role Code combination permits this form type per the permission matrix',
  },
  [WcbValidationCheckId.REQUIRED_FIELDS]: {
    id: WcbValidationCheckId.REQUIRED_FIELDS,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'All required fields for the form type are present and non-empty',
  },
  [WcbValidationCheckId.CONDITIONAL_LOGIC]: {
    id: WcbValidationCheckId.CONDITIONAL_LOGIC,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Conditionally required fields are present when their trigger conditions are met',
  },
  [WcbValidationCheckId.DATA_TYPE_LENGTH]: {
    id: WcbValidationCheckId.DATA_TYPE_LENGTH,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'All field values conform to expected data types and maximum lengths',
  },
  [WcbValidationCheckId.DATE_VALIDATION]: {
    id: WcbValidationCheckId.DATE_VALIDATION,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Date fields are valid calendar dates; logical date ordering is correct (e.g., accident date <= exam date)',
  },
  [WcbValidationCheckId.POB_NOI_COMBINATION]: {
    id: WcbValidationCheckId.POB_NOI_COMBINATION,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Part of Body (POB) and Nature of Injury (NOI) combination is valid per WCB code tables',
  },
  [WcbValidationCheckId.SIDE_OF_BODY]: {
    id: WcbValidationCheckId.SIDE_OF_BODY,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'Side of body is specified when the injury type requires laterality',
  },
  [WcbValidationCheckId.CODE_TABLE_VALUES]: {
    id: WcbValidationCheckId.CODE_TABLE_VALUES,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'All coded fields reference valid entries in WCB code tables',
  },
  [WcbValidationCheckId.SUBMITTER_TXN_FORMAT]: {
    id: WcbValidationCheckId.SUBMITTER_TXN_FORMAT,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Submitter transaction number conforms to required format (prefix + sequence)',
  },
  [WcbValidationCheckId.PHN_LOGIC]: {
    id: WcbValidationCheckId.PHN_LOGIC,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'PHN passes Alberta Luhn check digit validation',
  },
  [WcbValidationCheckId.INVOICE_LINE_INTEGRITY]: {
    id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'Invoice lines have valid service codes, amounts, and date ranges; line totals match form total',
  },
  [WcbValidationCheckId.ATTACHMENT_CONSTRAINTS]: {
    id: WcbValidationCheckId.ATTACHMENT_CONSTRAINTS,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'Attachments conform to size, type, and count constraints per form type',
  },
  [WcbValidationCheckId.TIMING_DEADLINE]: {
    id: WcbValidationCheckId.TIMING_DEADLINE,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'Submission timing tier calculated; warns if approaching or past deadline',
  },
  [WcbValidationCheckId.EXPEDITE_ELIGIBILITY]: {
    id: WcbValidationCheckId.EXPEDITE_ELIGIBILITY,
    defaultSeverity: ValidationSeverity.INFO,
    description:
      'Checks if the report qualifies for expedited processing based on injury severity',
  },
  [WcbValidationCheckId.DUPLICATE_DETECTION]: {
    id: WcbValidationCheckId.DUPLICATE_DETECTION,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'Detects potential duplicate submissions for the same claimant/accident/form combination',
  },
});

// --- OIS-Specific Codes (Appendix C) ---

// Basic Work Restriction Codes
export const OisBasicWorkRestriction = {
  ABLE: 'ABLE',
  UNABLE: 'UNABLE',
  LIMITED: 'LIMITED',
} as const;

export type OisBasicWorkRestriction =
  (typeof OisBasicWorkRestriction)[keyof typeof OisBasicWorkRestriction];

// Extended Work Restriction Codes
export const OisExtendedWorkRestriction = {
  ABLE: 'ABLE',
  UNABLE: 'UNABLE',
  LIMITEDTO: 'LIMITEDTO',
} as const;

export type OisExtendedWorkRestriction =
  (typeof OisExtendedWorkRestriction)[keyof typeof OisExtendedWorkRestriction];

// Fit For Work Codes
export const OisFitForWork = {
  FIT: 'FIT',
  NOTFIT: 'NOTFIT',
} as const;

export type OisFitForWork =
  (typeof OisFitForWork)[keyof typeof OisFitForWork];

// Restriction Codes
export const OisRestriction = {
  NORESTRICT: 'NORESTRICT',
  RESTRICTFR: 'RESTRICTFR',
} as const;

export type OisRestriction =
  (typeof OisRestriction)[keyof typeof OisRestriction];

// Work Level Codes
export const OisWorkLevel = {
  PREINJURY: 'PREINJURY',
  LIMITATION: 'LIMITATION',
} as const;

export type OisWorkLevel =
  (typeof OisWorkLevel)[keyof typeof OisWorkLevel];

// OIS Family Physician Codes
export const OisFamilyPhysician = {
  OIS: 'OIS',
  FAMILY: 'FAMILY',
} as const;

export type OisFamilyPhysician =
  (typeof OisFamilyPhysician)[keyof typeof OisFamilyPhysician];

// --- WCB Audit Actions ---

export const WcbAuditAction = {
  WCB_FORM_CREATED: 'WCB_FORM_CREATED',
  WCB_FORM_UPDATED: 'WCB_FORM_UPDATED',
  WCB_FORM_VALIDATED: 'WCB_FORM_VALIDATED',
  WCB_FORM_SUBMITTED: 'WCB_FORM_SUBMITTED',
  WCB_BATCH_ASSEMBLED: 'WCB_BATCH_ASSEMBLED',
  WCB_BATCH_VALIDATED: 'WCB_BATCH_VALIDATED',
  WCB_BATCH_DOWNLOADED: 'WCB_BATCH_DOWNLOADED',
  WCB_BATCH_UPLOADED: 'WCB_BATCH_UPLOADED',
  WCB_RETURN_RECEIVED: 'WCB_RETURN_RECEIVED',
  WCB_PAYMENT_RECEIVED: 'WCB_PAYMENT_RECEIVED',
  WCB_MVP_EXPORT_GENERATED: 'WCB_MVP_EXPORT_GENERATED',
  WCB_MANUAL_OUTCOME_RECORDED: 'WCB_MANUAL_OUTCOME_RECORDED',
} as const;

export type WcbAuditAction =
  (typeof WcbAuditAction)[keyof typeof WcbAuditAction];

// --- WCB Fee Calculation Constants (Section 8) ---

/** Premium code multiplier — 351 codes paid at 2× SOMB base rate */
export const WCB_PREMIUM_MULTIPLIER = 2;

/**
 * Premium codes are excluded when date_of_service is within 4 calendar days
 * of the date_of_injury. Days 0-4 are excluded; day 5+ is eligible.
 */
export const WCB_PREMIUM_EXCLUSION_DAYS = 4;

/** Maximum one premium code per operative encounter */
export const WCB_PREMIUM_LIMIT_PER_ENCOUNTER = 1;

/** RRNP flat fee per claim for qualifying rural/remote northern physicians */
export const WCB_RRNP_FLAT_FEE = '32.77';

/**
 * Expedited service completion tiers (business days).
 * Within 15 → full fee; 16-25 → pro-rated; >25 → no fee.
 */
export const WCB_EXPEDITED_FULL_DAYS = 15;
export const WCB_EXPEDITED_PRORATE_END_DAYS = 25;

/**
 * Default expedited consultation fee (full amount).
 * This is the base amount; pro-rating applies for 16-25 biz day completions.
 */
export const WCB_EXPEDITED_CONSULTATION_FEE = '150.00';

/**
 * Report form code mapping — maps WCB form types to fee schedule form codes.
 * C050E/C050S → C050E schedule, C151/C151S → C151 schedule,
 * C568A → RF01E (specialist consultation), C568A follow-up → RF03E.
 */
export const WCB_FORM_TO_FEE_CODE: Readonly<Record<string, string>> = Object.freeze({
  C050E: 'C050E',
  C050S: 'C050E',
  C151: 'C151',
  C151S: 'C151',
});

// --- WCB Phase Feature Flag ---
// Phase 1 (mvp): Manual portal entry with pre-filled export + manual outcome recording
// Phase 2 (vendor): Automated XML submission via vendor accreditation

export const WcbPhase = {
  MVP: 'mvp',
  VENDOR: 'vendor',
} as const;

export type WcbPhase = (typeof WcbPhase)[keyof typeof WcbPhase];
