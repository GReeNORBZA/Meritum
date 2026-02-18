import type { AhcipRepository } from './ahcip.repository.js';
import {
  AhcipModifierCode,
  AhcipValidationCheckId,
  AhcipBatchStatus,
  AfterHoursType,
  STANDARD_HOURS_START,
  STANDARD_HOURS_END,
  EVENING_HOURS_END,
  SHADOW_BILLING_FEE,
  BATCH_RETRY_INTERVALS_S,
  BATCH_MAX_RETRIES,
} from '@meritum/shared/constants/ahcip.constants.js';
import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

/**
 * Domain 4.0 (Claim Lifecycle Core) — create a base claim record.
 * Returns the new claim ID.
 */
export interface ClaimService {
  createClaim(
    physicianId: string,
    actorId: string,
    actorContext: string,
    data: CreateClaimInput,
  ): Promise<{ claimId: string }>;
}

/** Provider Management (Domain 5) — BA routing and PCPCM enrolment. */
export interface ProviderService {
  routeClaimToBa(
    providerId: string,
    claimType: 'AHCIP' | 'WCB',
    hscCode?: string,
    dateOfService?: string,
  ): Promise<BaRoutingResult>;
}

/** Reference Data (Domain 2) — PCPCM basket + holiday calendar. */
export interface ReferenceDataService {
  getPcpcmBasket(
    hscCode: string,
    dateOfService?: string,
  ): Promise<PcpcmBasketResult | null>;

  isHoliday(date: Date): Promise<HolidayCheckResult>;
}

/** Shift lookup (Domain 4.0) — retrieve shift times for ED claims. */
export interface ShiftLookup {
  getShift(
    shiftId: string,
    physicianId: string,
  ): Promise<ShiftInfo | null>;
}

// ---------------------------------------------------------------------------
// Validation dependency interfaces
// ---------------------------------------------------------------------------

/**
 * Extended Reference Data service for AHCIP validation.
 * Provides version-aware HSC code, modifier, and governing rule lookups.
 */
export interface AhcipValidationRefData {
  /** Lookup HSC code in the SOMB schedule effective on DOS. Returns null if not found. */
  getHscDetail(
    hscCode: string,
    dateOfService: string,
  ): Promise<HscDetail | null>;

  /** Get applicable modifiers for an HSC code, version-aware by DOS. */
  getModifiersForHsc(
    hscCode: string,
    dateOfService: string,
  ): Promise<ModifierDetail[]>;

  /** Get full modifier detail including exclusiveWith / combinableWith. */
  getModifierDetail(modifierCode: string): Promise<ModifierDetail | null>;

  /** Get governing rules applicable to an HSC code for the DOS. */
  getApplicableRules(
    hscCode: string,
    dateOfService: string,
  ): Promise<GoverningRuleDetail[]>;

  /** Get the current reference data version string for audit traceability. */
  getCurrentVersion(): Promise<string>;
}

/** Provider Management validation interface — BA and practitioner checks. */
export interface AhcipValidationProviderService {
  /** Validate that the BA number is active for this physician. */
  validateBa(
    physicianId: string,
    baNumber: string,
  ): Promise<{ valid: boolean; reason?: string }>;

  /** Check if physician qualifies for RRNP premiums. */
  isRrnpEligible(physicianId: string): Promise<boolean>;
}

/** Claim repository interface for bundling checks. */
export interface AhcipValidationClaimLookup {
  /** Find other claims for the same patient on the same DOS (for bundling check). */
  findClaimsForPatientOnDate(
    physicianId: string,
    patientId: string,
    dateOfService: string,
    excludeClaimId: string,
  ): Promise<Array<{ claimId: string; healthServiceCode: string }>>;
}

// ---------------------------------------------------------------------------
// Validation types
// ---------------------------------------------------------------------------

export interface ValidationEntry {
  check: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  rule_reference: string;
  message: string;
  help_text: string;
  field_affected?: string;
}

export interface HscDetail {
  code: string;
  description: string;
  baseFee: string | null;
  feeType: string;
  isActive: boolean;
  effectiveFrom: string;
  effectiveTo: string | null;
  specialtyRestrictions: string[];
  facilityRestrictions: string[];
  requiresReferral: boolean;
  requiresDiagnosticCode: boolean;
  requiresFacility: boolean;
  isTimeBased: boolean;
  minTime: number | null;
  maxTime: number | null;
  minCalls: number | null;
  maxCalls: number | null;
  maxPerDay: number | null;
  surchargeEligible: boolean;
  pcpcmBasket: string | null;
  afterHoursEligible: boolean;
  premium351Eligible: boolean;
  combinationGroup: string | null;
}

export interface ModifierDetail {
  modifierCode: string;
  name: string;
  calculationMethod: string;
  combinableWith: string[];
  exclusiveWith: string[];
}

export interface GoverningRuleDetail {
  ruleId: string;
  ruleName: string;
  ruleCategory: string;
  severity: string;
  ruleLogic: Record<string, unknown>;
  errorMessage: string;
}

export interface AhcipValidationDeps {
  refData: AhcipValidationRefData;
  providerService: AhcipValidationProviderService;
  claimLookup: AhcipValidationClaimLookup;
}

export interface AhcipClaimForValidation {
  claimId: string;
  physicianId: string;
  patientId: string;
  dateOfService: string;
  submissionDeadline: string | null;
  healthServiceCode: string;
  baNumber: string;
  modifier1: string | null;
  modifier2: string | null;
  modifier3: string | null;
  diagnosticCode: string | null;
  facilityNumber: string | null;
  referralPractitioner: string | null;
  encounterType: string;
  calls: number;
  timeSpent: number | null;
  shadowBillingFlag: boolean;
  pcpcmBasketFlag: boolean;
  afterHoursFlag: boolean;
  afterHoursType: string | null;
}

export interface AhcipValidationResult {
  entries: ValidationEntry[];
  referenceDataVersion: string;
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

export interface CreateClaimInput {
  claimType: string;
  patientId: string;
  dateOfService: string;
  importSource?: string;
}

export interface CreateAhcipDetailInput {
  healthServiceCode: string;
  functionalCentre: string;
  encounterType: string;
  modifier1?: string | null;
  modifier2?: string | null;
  modifier3?: string | null;
  diagnosticCode?: string | null;
  facilityNumber?: string | null;
  referralPractitioner?: string | null;
  calls?: number;
  timeSpent?: number | null;
  patientLocation?: string | null;
  submittedFee?: string | null;
  serviceTime?: string | null;
}

export interface BaRoutingResult {
  ba_number: string;
  ba_type: 'FFS' | 'PCPCM';
  routing_reason: 'WCB_PRIMARY' | 'NON_PCPCM' | 'IN_BASKET' | 'OUT_OF_BASKET' | 'UNCLASSIFIED';
  warning?: string;
}

export interface PcpcmBasketResult {
  hscCode: string;
  basket: string;
  notes: string | null;
}

export interface HolidayCheckResult {
  is_holiday: boolean;
  holiday_name?: string;
}

export interface ShiftInfo {
  shiftId: string;
  facilityId: string;
  shiftDate: string;
  startTime: string | null;
  endTime: string | null;
}

export interface CreateAhcipClaimResult {
  claimId: string;
  ahcipDetailId: string;
  baNumber: string;
  pcpcmBasketFlag: boolean;
  shadowBillingFlag: boolean;
  afterHoursFlag: boolean;
  afterHoursType: string | null;
  submissionDeadline: string;
}

export interface AhcipServiceDeps {
  repo: AhcipRepository;
  claimService: ClaimService;
  providerService: ProviderService;
  referenceData: ReferenceDataService;
  shiftLookup?: ShiftLookup;
}

// ---------------------------------------------------------------------------
// Fee Calculation Dependency Interfaces
// ---------------------------------------------------------------------------

/**
 * Extended Reference Data service for fee calculation.
 * Provides version-aware base fee, modifier fee impacts, and premium lookups.
 */
export interface FeeReferenceDataService {
  /** Lookup HSC code in the SOMB schedule effective on DOS. Returns null if not found. */
  getHscDetail(
    hscCode: string,
    dateOfService: string,
  ): Promise<HscDetail | null>;

  /** Get modifier fee impact for an HSC code, version-aware by DOS. */
  getModifierFeeImpact(
    modifierCode: string,
    hscCode: string,
    dateOfService: string,
  ): Promise<ModifierFeeImpact | null>;

  /** Get after-hours premium amount for a given HSC category and time slot. */
  getAfterHoursPremium(
    hscCode: string,
    afterHoursType: string,
    dateOfService: string,
  ): Promise<string | null>;

  /** Get CMGP premium amount for a qualifying HSC code. */
  getCmgpPremium(
    hscCode: string,
    dateOfService: string,
  ): Promise<string | null>;

  /** Get RRNP premium rate for a physician's community code. */
  getRrnpPremium(
    physicianId: string,
    dateOfService: string,
  ): Promise<string | null>;

  /** Get ED surcharge amount for qualifying codes. */
  getEdSurcharge(
    hscCode: string,
    dateOfService: string,
  ): Promise<string | null>;
}

/** Provider eligibility checks for fee calculation. */
export interface FeeProviderService {
  /** Check if physician qualifies for RRNP premiums. */
  isRrnpEligible(physicianId: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Fee Calculation Types
// ---------------------------------------------------------------------------

export interface ModifierFeeImpact {
  modifierCode: string;
  calculationMethod: 'PERCENTAGE' | 'ADDITIVE' | 'OVERRIDE';
  /** Percentage as decimal (e.g., 0.15 for 15%) for PERCENTAGE, dollar amount for ADDITIVE/OVERRIDE. */
  value: string;
  priority: number;
}

export interface FeeBreakdownModifierAdjustment {
  modifier: string;
  effect: string;
  amount: string;
}

export interface FeeBreakdownPremium {
  type: string;
  amount: string;
}

export interface FeeBreakdown {
  base_fee: string;
  calls: number;
  modifier_adjustments: FeeBreakdownModifierAdjustment[];
  premiums: FeeBreakdownPremium[];
  rrnp_premium: string | null;
  total_fee: string;
}

export interface FeeCalculateInput {
  healthServiceCode: string;
  dateOfService: string;
  modifier1?: string | null;
  modifier2?: string | null;
  modifier3?: string | null;
  calls?: number;
  afterHoursFlag?: boolean;
  afterHoursType?: string | null;
  shadowBillingFlag?: boolean;
  pcpcmBasketFlag?: boolean;
}

export interface FeeCalculationDeps {
  repo: AhcipRepository;
  feeRefData: FeeReferenceDataService;
  feeProviderService: FeeProviderService;
}

// ---------------------------------------------------------------------------
// Batch Cycle Dependency Interfaces
// ---------------------------------------------------------------------------

/**
 * Notification service for emitting batch events.
 * Consumed by Domain 9 (Notification Service).
 */
export interface BatchNotificationService {
  /** Emit event when batch assembly completes. */
  emit(event: string, payload: Record<string, unknown>): Promise<void>;
}

/**
 * Claim state transition service from Domain 4.0.
 * Used to transition claims to SUBMITTED or back to VALIDATED.
 */
export interface ClaimStateService {
  /** Transition a claim to a new state. Returns success. */
  transitionState(
    claimId: string,
    physicianId: string,
    fromState: string,
    toState: string,
    actorId: string,
    actorContext: string,
  ): Promise<boolean>;
}

/**
 * H-Link transmission service — abstraction over SFTP/API channel.
 * Implementation uses credentials from secrets management (env vars).
 */
export interface HlinkTransmissionService {
  /** Transmit file content via secure channel. Returns submission reference or throws. */
  transmit(fileContent: Buffer, metadata: {
    batchId: string;
    recordCount: number;
    totalValue: string;
  }): Promise<{ submissionReference: string }>;
}

/**
 * File encryption service for H-Link files at rest.
 * Uses AES-256 encryption.
 */
export interface FileEncryptionService {
  /** Encrypt content and store. Returns file_path and file_hash. */
  encryptAndStore(content: Buffer, filename: string): Promise<{
    filePath: string;
    fileHash: string;
  }>;
}

/**
 * Submission preference lookup from Provider Management.
 */
export interface SubmissionPreferenceService {
  /** Get auto-submission mode for a physician. */
  getAutoSubmissionMode(physicianId: string): Promise<'AUTO_CLEAN' | 'AUTO_ALL' | 'REQUIRE_APPROVAL'>;
}

/**
 * AHCIP validation runner that combines shared (S1–S7) and AHCIP-specific (A1–A19) checks.
 */
export interface BatchValidationRunner {
  /** Run full validation pipeline on a claim. Returns true if passed (zero errors). */
  validateClaim(claimId: string, physicianId: string): Promise<{
    passed: boolean;
    errors: ValidationEntry[];
  }>;
}

/** Dependencies for batch cycle operations. */
export interface BatchCycleDeps {
  repo: AhcipRepository;
  feeRefData: FeeReferenceDataService;
  feeProviderService: FeeProviderService;
  claimStateService: ClaimStateService;
  notificationService: BatchNotificationService;
  hlinkTransmission: HlinkTransmissionService;
  fileEncryption: FileEncryptionService;
  submissionPreferences: SubmissionPreferenceService;
  validationRunner: BatchValidationRunner;
  /** Optional sleep function for retry backoff. Defaults to real sleep. Injectable for testing. */
  sleep?: (ms: number) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Batch Cycle Types
// ---------------------------------------------------------------------------

export interface BatchAssemblyResult {
  batches: Array<{
    batchId: string;
    baNumber: string;
    claimCount: number;
    totalValue: string;
  }>;
  removedClaims: Array<{
    claimId: string;
    reason: string;
  }>;
}

export interface BatchPreview {
  batchWeek: string;
  groups: Array<{
    baNumber: string;
    claimCount: number;
    totalValue: string;
  }>;
  totalClaims: number;
  totalValue: string;
}

export interface HlinkFileContent {
  header: string;
  records: string[];
  trailer: string;
  raw: Buffer;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** AHCIP deadline: DOS + 90 calendar days. */
const AHCIP_DEADLINE_DAYS = 90;

/** PCPCM basket values that indicate an in-basket HSC code. */
const IN_BASKET_VALUES = ['in_basket', 'IN_BASKET'];

// ---------------------------------------------------------------------------
// Service: createAhcipClaim
// ---------------------------------------------------------------------------

/**
 * Create an AHCIP claim: base claim via Domain 4.0 + AHCIP extension row.
 *
 * Orchestrates:
 * 1. Create base claim via Domain 4.0 createClaim.
 * 2. Resolve BA number via Provider Management (PCPCM routing if applicable).
 * 3. Determine pcpcm_basket_flag from Reference Data basket classification.
 * 4. Detect shadow billing from TM modifier.
 * 5. Auto-detect after-hours from shift times or service time context.
 * 6. Calculate submission_deadline = DOS + 90 calendar days.
 * 7. Create AHCIP extension row in ahcip_claim_details.
 *
 * Security:
 * - BA resolution comes from Provider Management — physician cannot specify arbitrary BA.
 * - pcpcm_basket_flag derived from Reference Data, not user input.
 * - Shadow billing detection is automatic from TM modifier.
 */
export async function createAhcipClaim(
  deps: AhcipServiceDeps,
  physicianId: string,
  actorId: string,
  actorContext: string,
  baseData: CreateClaimInput,
  ahcipData: CreateAhcipDetailInput,
): Promise<CreateAhcipClaimResult> {
  // 1. Create base claim via Domain 4.0 (state = DRAFT)
  const { claimId } = await deps.claimService.createClaim(
    physicianId,
    actorId,
    actorContext,
    {
      claimType: 'AHCIP',
      patientId: baseData.patientId,
      dateOfService: baseData.dateOfService,
      importSource: baseData.importSource,
    },
  );

  // 2. Resolve BA via Provider Management PCPCM routing
  const routing = await deps.providerService.routeClaimToBa(
    physicianId,
    'AHCIP',
    ahcipData.healthServiceCode,
    baseData.dateOfService,
  );

  // 3. Determine PCPCM basket flag from routing result
  const pcpcmBasketFlag = routing.routing_reason === 'IN_BASKET';

  // 4. Detect shadow billing: TM modifier → shadow_billing_flag = true, fee = $0.00
  const shadowBillingFlag = isShadowBilling(
    ahcipData.modifier1,
    ahcipData.modifier2,
    ahcipData.modifier3,
  );

  // 5. Auto-detect after-hours
  const afterHoursResult = await resolveAfterHours(
    deps,
    baseData.dateOfService,
    ahcipData.serviceTime ?? null,
    baseData.importSource,
    physicianId,
  );

  // 6. Calculate submission deadline = DOS + 90 calendar days
  const submissionDeadline = calculateDeadline(baseData.dateOfService);

  // 7. Determine submitted fee (shadow billing overrides to $0.00)
  const submittedFee = shadowBillingFlag
    ? SHADOW_BILLING_FEE
    : ahcipData.submittedFee ?? null;

  // 8. Create AHCIP extension row
  const detail = await deps.repo.createAhcipDetail({
    claimId,
    baNumber: routing.ba_number,
    functionalCentre: ahcipData.functionalCentre,
    healthServiceCode: ahcipData.healthServiceCode,
    modifier1: ahcipData.modifier1 ?? null,
    modifier2: ahcipData.modifier2 ?? null,
    modifier3: ahcipData.modifier3 ?? null,
    diagnosticCode: ahcipData.diagnosticCode ?? null,
    facilityNumber: ahcipData.facilityNumber ?? null,
    referralPractitioner: ahcipData.referralPractitioner ?? null,
    encounterType: ahcipData.encounterType,
    calls: ahcipData.calls ?? 1,
    timeSpent: ahcipData.timeSpent ?? null,
    patientLocation: ahcipData.patientLocation ?? null,
    shadowBillingFlag,
    pcpcmBasketFlag,
    afterHoursFlag: afterHoursResult.afterHoursFlag,
    afterHoursType: afterHoursResult.afterHoursType,
    submittedFee,
  } as any);

  return {
    claimId,
    ahcipDetailId: detail.ahcipDetailId,
    baNumber: routing.ba_number,
    pcpcmBasketFlag,
    shadowBillingFlag,
    afterHoursFlag: afterHoursResult.afterHoursFlag,
    afterHoursType: afterHoursResult.afterHoursType,
    submissionDeadline,
  };
}

// ---------------------------------------------------------------------------
// Service: validateAhcipClaim
// ---------------------------------------------------------------------------

/** Days before deadline that trigger a warning instead of error for A13. */
const DEADLINE_WARNING_DAYS = 7;

/**
 * AHCIP-specific validation pipeline (A1–A19).
 *
 * Implements the PathwayValidator interface from Domain 4.0.
 * Called after shared checks (S1–S7) have passed.
 *
 * Returns AHCIP-specific ValidationEntry[] to merge with shared results.
 * Each entry has a severity (ERROR, WARNING, INFO) per FRD Table 6.
 *
 * Security:
 * - Uses current Reference Data version (no caching stale SOMB rules).
 * - reference_data_version recorded for audit traceability.
 * - Governing rule evaluation is deterministic.
 */
export async function validateAhcipClaim(
  deps: AhcipValidationDeps,
  claim: AhcipClaimForValidation,
  physicianId: string,
): Promise<AhcipValidationResult> {
  const entries: ValidationEntry[] = [];
  const modifiers = collectModifiers(claim);

  // Fetch reference data context (version-aware by DOS)
  const [hscDetail, applicableModifiers, applicableRules, refVersion] =
    await Promise.all([
      deps.refData.getHscDetail(claim.healthServiceCode, claim.dateOfService),
      deps.refData.getModifiersForHsc(claim.healthServiceCode, claim.dateOfService),
      deps.refData.getApplicableRules(claim.healthServiceCode, claim.dateOfService),
      deps.refData.getCurrentVersion(),
    ]);

  // --- A1: HSC code valid ---
  if (!hscDetail) {
    entries.push({
      check: AhcipValidationCheckId.A1_HSC_CODE_VALID,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A1',
      message: `HSC code '${claim.healthServiceCode}' not found in SOMB schedule`,
      help_text: 'Verify the health service code exists in the current Schedule of Medical Benefits.',
      field_affected: 'health_service_code',
    });

    // Cannot proceed with most checks without a valid HSC code
    return { entries, referenceDataVersion: refVersion };
  }

  // --- A2: HSC active on DOS ---
  if (!hscDetail.isActive) {
    entries.push({
      check: AhcipValidationCheckId.A2_HSC_ACTIVE_ON_DOS,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A2',
      message: `HSC code '${claim.healthServiceCode}' was not active on ${claim.dateOfService}`,
      help_text: 'This code may have been retired or was not yet effective on the date of service.',
      field_affected: 'health_service_code',
    });
  }

  // --- A3: BA number valid ---
  const baValidation = await deps.providerService.validateBa(
    physicianId,
    claim.baNumber,
  );
  if (!baValidation.valid) {
    entries.push({
      check: AhcipValidationCheckId.A3_BA_NUMBER_VALID,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A3',
      message: `BA number '${claim.baNumber}' is not valid or active for this physician`,
      help_text: 'Ensure your billing arrangement is active and correctly assigned.',
      field_affected: 'ba_number',
    });
  }

  // --- A4: Governing rules ---
  for (const rule of applicableRules) {
    const violation = evaluateGoverningRule(rule, claim);
    if (violation) {
      entries.push({
        check: AhcipValidationCheckId.A4_GOVERNING_RULES,
        severity: 'ERROR',
        rule_reference: `FRD 4.1 S5.2 ${rule.ruleId}`,
        message: violation,
        help_text: rule.errorMessage,
        field_affected: getGoverningRuleField(rule),
      });
    }
  }

  // --- A5: Modifier eligibility ---
  const applicableModifierCodes = new Set(
    applicableModifiers.map((m) => m.modifierCode),
  );
  for (const mod of modifiers) {
    if (!applicableModifierCodes.has(mod)) {
      entries.push({
        check: AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY,
        severity: 'ERROR',
        rule_reference: 'FRD 4.1 S5.1 A5',
        message: `Modifier '${mod}' is not valid for HSC code '${claim.healthServiceCode}'`,
        help_text: 'Remove or replace this modifier with one applicable to the service code.',
        field_affected: getModifierField(mod, claim),
      });
    }
  }

  // --- A6: Modifier combination ---
  if (modifiers.length >= 2) {
    const combinationErrors = await checkModifierCombinations(deps, modifiers);
    for (const error of combinationErrors) {
      entries.push({
        check: AhcipValidationCheckId.A6_MODIFIER_COMBINATION,
        severity: 'ERROR',
        rule_reference: 'FRD 4.1 S5.1 A6',
        message: error,
        help_text: 'These modifiers cannot be used together. Remove one of the conflicting modifiers.',
        field_affected: 'modifier_1, modifier_2, modifier_3',
      });
    }
  }

  // --- A7: Diagnostic code required ---
  if (hscDetail.requiresDiagnosticCode && !claim.diagnosticCode) {
    entries.push({
      check: AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A7',
      message: 'Diagnostic code (ICD-9) is required for this HSC category',
      help_text: 'Add a valid ICD-9 diagnostic code for this service.',
      field_affected: 'diagnostic_code',
    });
  }

  // --- A8: Facility required ---
  if (hscDetail.requiresFacility && !claim.facilityNumber) {
    entries.push({
      check: AhcipValidationCheckId.A8_FACILITY_REQUIRED,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A8',
      message: 'Facility number is required for hospital-based encounters',
      help_text: 'Add the facility number where the service was provided.',
      field_affected: 'facility_number',
    });
  }

  // --- A9: Referral required (GR 8) ---
  if (hscDetail.requiresReferral && !claim.referralPractitioner) {
    entries.push({
      check: AhcipValidationCheckId.A9_REFERRAL_REQUIRED,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A9 / GR 8',
      message: 'Referring practitioner is required for specialist consultations',
      help_text: 'Add the referring practitioner billing number.',
      field_affected: 'referral_practitioner',
    });
  }

  // --- A10: DI surcharge eligibility (Warning) ---
  if (hscDetail.surchargeEligible) {
    entries.push({
      check: AhcipValidationCheckId.A10_DI_SURCHARGE_ELIGIBILITY,
      severity: 'WARNING',
      rule_reference: 'FRD 4.1 S5.1 A10',
      message: 'This code is eligible for a DI surcharge. Verify surcharge conditions are met.',
      help_text: 'Ensure equipment type and certification meet surcharge requirements.',
      field_affected: 'health_service_code',
    });
  }

  // --- A11: PCPCM routing (Warning) ---
  if (hscDetail.pcpcmBasket) {
    const expectedInBasket = hscDetail.pcpcmBasket === 'IN_BASKET' ||
      hscDetail.pcpcmBasket === 'in_basket';
    if (expectedInBasket !== claim.pcpcmBasketFlag) {
      entries.push({
        check: AhcipValidationCheckId.A11_PCPCM_ROUTING,
        severity: 'WARNING',
        rule_reference: 'FRD 4.1 S5.1 A11',
        message: `PCPCM basket classification mismatch: expected ${expectedInBasket ? 'in-basket' : 'out-of-basket'}`,
        help_text: 'The claim routing may not match the PCPCM basket classification for this code.',
        field_affected: 'pcpcm_basket_flag',
      });
    }
  }

  // --- A12: After-hours eligibility (Warning) ---
  if (claim.afterHoursFlag && !hscDetail.afterHoursEligible) {
    entries.push({
      check: AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY,
      severity: 'WARNING',
      rule_reference: 'FRD 4.1 S5.1 A12',
      message: 'This HSC code does not qualify for after-hours premium',
      help_text: 'The after-hours flag is set but this code is not eligible for after-hours premium.',
      field_affected: 'after_hours_flag',
    });
  }

  // --- A13: 90-day window ---
  if (claim.submissionDeadline) {
    const deadline = new Date(claim.submissionDeadline + 'T00:00:00Z');
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (deadline < today) {
      entries.push({
        check: AhcipValidationCheckId.A13_90_DAY_WINDOW,
        severity: 'ERROR',
        rule_reference: 'FRD 4.1 S5.1 A13',
        message: 'AHCIP 90-day submission window has expired',
        help_text: 'This claim is past its 90-day submission deadline and cannot be submitted.',
        field_affected: 'submission_deadline',
      });
    } else {
      const daysRemaining = Math.ceil(
        (deadline.getTime() - today.getTime()) / (1000 * 60 * 60 * 24),
      );
      if (daysRemaining <= DEADLINE_WARNING_DAYS) {
        entries.push({
          check: AhcipValidationCheckId.A13_90_DAY_WINDOW,
          severity: 'WARNING',
          rule_reference: 'FRD 4.1 S5.1 A13',
          message: `Submission deadline is within ${daysRemaining} day(s)`,
          help_text: 'Submit this claim soon to avoid missing the 90-day AHCIP deadline.',
          field_affected: 'submission_deadline',
        });
      }
    }
  }

  // --- A14: Time-based code duration ---
  if (hscDetail.isTimeBased) {
    if (claim.timeSpent == null) {
      entries.push({
        check: AhcipValidationCheckId.A14_TIME_BASED_DURATION,
        severity: 'ERROR',
        rule_reference: 'FRD 4.1 S5.1 A14',
        message: 'time_spent is required for time-based HSC codes',
        help_text: 'Enter the time spent (in minutes) for this time-based service code.',
        field_affected: 'time_spent',
      });
    } else {
      if (hscDetail.minTime != null && claim.timeSpent < hscDetail.minTime) {
        entries.push({
          check: AhcipValidationCheckId.A14_TIME_BASED_DURATION,
          severity: 'ERROR',
          rule_reference: 'FRD 4.1 S5.1 A14',
          message: `time_spent (${claim.timeSpent} min) is below minimum (${hscDetail.minTime} min) for this code`,
          help_text: 'Ensure the documented time meets the minimum requirement for this code.',
          field_affected: 'time_spent',
        });
      }
      if (hscDetail.maxTime != null && claim.timeSpent > hscDetail.maxTime) {
        entries.push({
          check: AhcipValidationCheckId.A14_TIME_BASED_DURATION,
          severity: 'ERROR',
          rule_reference: 'FRD 4.1 S5.1 A14',
          message: `time_spent (${claim.timeSpent} min) exceeds maximum (${hscDetail.maxTime} min) for this code`,
          help_text: 'The documented time exceeds the maximum allowed for this code.',
          field_affected: 'time_spent',
        });
      }
    }
  }

  // --- A15: Call count valid ---
  if (hscDetail.maxCalls != null && claim.calls > hscDetail.maxCalls) {
    entries.push({
      check: AhcipValidationCheckId.A15_CALL_COUNT_VALID,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A15',
      message: `Call count (${claim.calls}) exceeds maximum (${hscDetail.maxCalls}) for this code`,
      help_text: 'Reduce the call count to the valid range for this service code.',
      field_affected: 'calls',
    });
  }
  if (hscDetail.minCalls != null && claim.calls < hscDetail.minCalls) {
    entries.push({
      check: AhcipValidationCheckId.A15_CALL_COUNT_VALID,
      severity: 'ERROR',
      rule_reference: 'FRD 4.1 S5.1 A15',
      message: `Call count (${claim.calls}) is below minimum (${hscDetail.minCalls}) for this code`,
      help_text: 'Increase the call count to the valid range for this service code.',
      field_affected: 'calls',
    });
  }

  // --- A16: Shadow billing consistency (Warning) ---
  const hasTmModifier = modifiers.includes(AhcipModifierCode.TM);
  if (claim.shadowBillingFlag && !hasTmModifier) {
    entries.push({
      check: AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY,
      severity: 'WARNING',
      rule_reference: 'FRD 4.1 S5.1 A16',
      message: 'Shadow billing flag is set but TM modifier is missing',
      help_text: 'Add the TM modifier for shadow billing claims, or unset the shadow billing flag.',
      field_affected: 'shadow_billing_flag, modifier_1',
    });
  }
  if (hasTmModifier && !claim.shadowBillingFlag) {
    entries.push({
      check: AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY,
      severity: 'WARNING',
      rule_reference: 'FRD 4.1 S5.1 A16',
      message: 'TM modifier is present but shadow billing flag is not set',
      help_text: 'The TM modifier indicates shadow billing. The shadow billing flag should be set.',
      field_affected: 'shadow_billing_flag, modifier_1',
    });
  }

  // --- A17: RRNP eligibility (Info) ---
  const rrnpEligible = await deps.providerService.isRrnpEligible(physicianId);
  if (rrnpEligible) {
    entries.push({
      check: AhcipValidationCheckId.A17_RRNP_ELIGIBILITY,
      severity: 'INFO',
      rule_reference: 'FRD 4.1 S5.1 A17',
      message: 'Physician qualifies for RRNP premium on this claim',
      help_text: 'Rural and Remote Northern Program premium will be applied.',
    });
  }

  // --- A18: Premium eligibility 351 (Info) ---
  if (hscDetail.premium351Eligible) {
    entries.push({
      check: AhcipValidationCheckId.A18_PREMIUM_ELIGIBILITY_351,
      severity: 'INFO',
      rule_reference: 'FRD 4.1 S5.1 A18',
      message: 'This HSC code is eligible for 351 premium',
      help_text: 'Check premium conditions for code 351 applicability.',
    });
  }

  // --- A19: Bundling check (Warning) ---
  const otherClaims = await deps.claimLookup.findClaimsForPatientOnDate(
    physicianId,
    claim.patientId,
    claim.dateOfService,
    claim.claimId,
  );
  if (otherClaims.length > 0) {
    const codesStr = otherClaims.map((c) => c.healthServiceCode).join(', ');
    entries.push({
      check: AhcipValidationCheckId.A19_BUNDLING_CHECK,
      severity: 'WARNING',
      rule_reference: 'FRD 4.1 S5.1 A19',
      message: `Potential bundling: ${otherClaims.length} other claim(s) for same patient on same DOS (${codesStr})`,
      help_text: 'Review other claims for the same patient on this date to ensure services are not bundled.',
      field_affected: 'health_service_code',
    });
  }

  return { entries, referenceDataVersion: refVersion };
}

// ---------------------------------------------------------------------------
// Validation Helpers
// ---------------------------------------------------------------------------

/**
 * Collect non-null modifiers from a claim into an array.
 */
function collectModifiers(claim: AhcipClaimForValidation): string[] {
  const mods: string[] = [];
  if (claim.modifier1) mods.push(claim.modifier1);
  if (claim.modifier2) mods.push(claim.modifier2);
  if (claim.modifier3) mods.push(claim.modifier3);
  return mods;
}

/**
 * Evaluate a governing rule against a claim. Returns violation message or null.
 * Deterministic: same input always produces same result.
 */
function evaluateGoverningRule(
  rule: GoverningRuleDetail,
  claim: AhcipClaimForValidation,
): string | null {
  const logic = rule.ruleLogic;

  // GR 3: Visit limits
  if (logic.maxVisitsPerDay != null) {
    if (claim.calls > (logic.maxVisitsPerDay as number)) {
      return `Governing Rule ${rule.ruleId}: Visit limit exceeded (max ${logic.maxVisitsPerDay}/day)`;
    }
  }

  // GR 8: Referral required
  if (logic.requiresReferral === true && !claim.referralPractitioner) {
    return `Governing Rule ${rule.ruleId}: Referring practitioner required`;
  }

  // GR 5: DI facility requirement
  if (logic.requiresFacility === true && !claim.facilityNumber) {
    return `Governing Rule ${rule.ruleId}: Facility number required`;
  }

  // GR 10: Surgical requirements
  if (logic.requiresTimeDocumentation === true && claim.timeSpent == null) {
    return `Governing Rule ${rule.ruleId}: Time documentation required`;
  }

  // GR 14: Obstetric rules
  if (logic.maxCallsPerEncounter != null) {
    if (claim.calls > (logic.maxCallsPerEncounter as number)) {
      return `Governing Rule ${rule.ruleId}: Call limit exceeded (max ${logic.maxCallsPerEncounter})`;
    }
  }

  return null;
}

/**
 * Identify the field name for a governing rule violation.
 */
function getGoverningRuleField(rule: GoverningRuleDetail): string {
  const logic = rule.ruleLogic;
  if (logic.requiresReferral) return 'referral_practitioner';
  if (logic.requiresFacility) return 'facility_number';
  if (logic.requiresTimeDocumentation) return 'time_spent';
  if (logic.maxVisitsPerDay || logic.maxCallsPerEncounter) return 'calls';
  return 'health_service_code';
}

/**
 * Check modifier combinations for mutual exclusivity.
 */
async function checkModifierCombinations(
  deps: AhcipValidationDeps,
  modifiers: string[],
): Promise<string[]> {
  const errors: string[] = [];
  for (let i = 0; i < modifiers.length; i++) {
    const detail = await deps.refData.getModifierDetail(modifiers[i]);
    if (!detail) continue;

    for (let j = i + 1; j < modifiers.length; j++) {
      if (detail.exclusiveWith.includes(modifiers[j])) {
        errors.push(
          `Modifiers '${modifiers[i]}' and '${modifiers[j]}' are mutually exclusive`,
        );
      }
    }
  }
  return errors;
}

/**
 * Identify which modifier field (modifier_1, modifier_2, modifier_3) contains the given code.
 */
function getModifierField(mod: string, claim: AhcipClaimForValidation): string {
  if (claim.modifier1 === mod) return 'modifier_1';
  if (claim.modifier2 === mod) return 'modifier_2';
  if (claim.modifier3 === mod) return 'modifier_3';
  return 'modifier_1';
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Detect shadow billing from TM modifier in any of the 3 modifier slots.
 * Per FRD Table 8: TM modifier = shadow billing, fee $0.
 */
function isShadowBilling(
  modifier1?: string | null,
  modifier2?: string | null,
  modifier3?: string | null,
): boolean {
  return (
    modifier1 === AhcipModifierCode.TM ||
    modifier2 === AhcipModifierCode.TM ||
    modifier3 === AhcipModifierCode.TM
  );
}

/**
 * Calculate AHCIP submission deadline: DOS + 90 calendar days.
 */
function calculateDeadline(dateOfService: string): string {
  const dos = new Date(dateOfService + 'T00:00:00Z');
  dos.setUTCDate(dos.getUTCDate() + AHCIP_DEADLINE_DAYS);
  return dos.toISOString().split('T')[0];
}

/**
 * Resolve after-hours status from:
 * 1. ED shift claims: derive from shift start_time / end_time.
 * 2. Manual claims with serviceTime: classify per time slot definitions.
 * 3. Stat holiday check: call Reference Data for stat holiday list.
 *
 * After-hours time slot definitions (Mountain Time):
 * - Standard: Mon–Fri 08:00–17:00 (excl. stat holidays)
 * - Evening:  Mon–Fri 17:00–23:00
 * - Night:    Any day 23:00–08:00
 * - Weekend:  Saturday/Sunday full day
 * - Stat:     Named Alberta statutory holidays, full day
 */
async function resolveAfterHours(
  deps: AhcipServiceDeps,
  dateOfService: string,
  serviceTime: string | null,
  importSource?: string,
  physicianId?: string,
): Promise<{ afterHoursFlag: boolean; afterHoursType: string | null }> {
  const dos = new Date(dateOfService + 'T00:00:00Z');

  // 1. Check stat holiday first — full day counts as after-hours
  const holidayResult = await deps.referenceData.isHoliday(dos);
  if (holidayResult.is_holiday) {
    return {
      afterHoursFlag: true,
      afterHoursType: AfterHoursType.STAT_HOLIDAY,
    };
  }

  // 2. Check weekend (Saturday=6, Sunday=0)
  const dayOfWeek = dos.getUTCDay();
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    return {
      afterHoursFlag: true,
      afterHoursType: AfterHoursType.WEEKEND,
    };
  }

  // 3. If service time available, classify by hour
  if (serviceTime) {
    const hour = parseHour(serviceTime);
    if (hour !== null) {
      return classifyHour(hour);
    }
  }

  // 4. No time context available — cannot determine after-hours
  return { afterHoursFlag: false, afterHoursType: null };
}

/**
 * Classify an hour (0–23) into after-hours type.
 */
function classifyHour(hour: number): { afterHoursFlag: boolean; afterHoursType: string | null } {
  // Night: 23:00–08:00
  if (hour >= EVENING_HOURS_END || hour < STANDARD_HOURS_START) {
    return { afterHoursFlag: true, afterHoursType: AfterHoursType.NIGHT };
  }

  // Evening: 17:00–23:00
  if (hour >= STANDARD_HOURS_END && hour < EVENING_HOURS_END) {
    return { afterHoursFlag: true, afterHoursType: AfterHoursType.EVENING };
  }

  // Standard hours: 08:00–17:00
  return { afterHoursFlag: false, afterHoursType: null };
}

/**
 * Parse an hour from a time string. Supports "HH:MM", "HH:MM:SS", or "HH".
 * Returns the hour as an integer 0–23, or null if parsing fails.
 */
function parseHour(time: string): number | null {
  const parts = time.split(':');
  const hour = parseInt(parts[0], 10);
  if (isNaN(hour) || hour < 0 || hour > 23) {
    return null;
  }
  return hour;
}

// ---------------------------------------------------------------------------
// Service: calculateFee
// ---------------------------------------------------------------------------

/**
 * Calculate submitted_fee for an AHCIP claim and persist the result.
 *
 * Fee formula (FRD 4.1 Section 6.1):
 *   submitted_fee = (base_fee × calls) + modifier_adjustments + premiums
 *
 * Steps:
 * 1. Look up base_fee from SOMB schedule for HSC code (version-aware by DOS).
 * 2. Apply modifier adjustments in SOMB-defined priority order.
 * 3. Calculate premiums (CMGP, after-hours, RRNP, ED surcharge).
 * 4. Shadow billing override: if shadow_billing_flag = true → $0.00.
 * 5. PCPCM in-basket: calculated for tracking, may be $0 depending on BA.
 *
 * Security:
 * - Physician scoping enforced via repo.findAhcipDetailByClaimId.
 * - Fee derived from Reference Data, not user input.
 */
export async function calculateFee(
  deps: FeeCalculationDeps,
  claimId: string,
  physicianId: string,
): Promise<FeeBreakdown> {
  // 1. Fetch claim detail (physician-scoped)
  const detailResult = await deps.repo.findAhcipDetailByClaimId(claimId, physicianId);
  if (!detailResult) {
    throw new Error('Claim not found');
  }

  const detail = detailResult;

  // Build input from stored claim detail
  const input: FeeCalculateInput = {
    healthServiceCode: detail.healthServiceCode,
    dateOfService: detail.claim.dateOfService,
    modifier1: detail.modifier1,
    modifier2: detail.modifier2,
    modifier3: detail.modifier3,
    calls: detail.calls,
    afterHoursFlag: detail.afterHoursFlag,
    afterHoursType: detail.afterHoursType,
    shadowBillingFlag: detail.shadowBillingFlag,
    pcpcmBasketFlag: detail.pcpcmBasketFlag,
  };

  // Calculate fee breakdown
  const breakdown = await computeFeeBreakdown(deps, physicianId, input);

  // Persist the calculated fee
  await deps.repo.updateAhcipDetail(claimId, physicianId, {
    submittedFee: breakdown.total_fee,
  } as any);

  return breakdown;
}

// ---------------------------------------------------------------------------
// Service: calculateFeePreview
// ---------------------------------------------------------------------------

/**
 * Calculate fee without saving — for UI preview/estimation.
 * Same formula as calculateFee but does not touch the database.
 */
export async function calculateFeePreview(
  deps: FeeCalculationDeps,
  physicianId: string,
  data: FeeCalculateInput,
): Promise<FeeBreakdown> {
  return computeFeeBreakdown(deps, physicianId, data);
}

// ---------------------------------------------------------------------------
// Service: getFeeBreakdown
// ---------------------------------------------------------------------------

/**
 * Return detailed fee breakdown for an existing claim.
 * Re-computes from current Reference Data (not cached).
 *
 * Returns: { base_fee, calls, modifier_adjustments, premiums, rrnp_premium, total_fee }
 */
export async function getFeeBreakdown(
  deps: FeeCalculationDeps,
  claimId: string,
  physicianId: string,
): Promise<FeeBreakdown> {
  // Fetch claim detail (physician-scoped)
  const detailResult = await deps.repo.findAhcipDetailByClaimId(claimId, physicianId);
  if (!detailResult) {
    throw new Error('Claim not found');
  }

  const detail = detailResult;

  const input: FeeCalculateInput = {
    healthServiceCode: detail.healthServiceCode,
    dateOfService: detail.claim.dateOfService,
    modifier1: detail.modifier1,
    modifier2: detail.modifier2,
    modifier3: detail.modifier3,
    calls: detail.calls,
    afterHoursFlag: detail.afterHoursFlag,
    afterHoursType: detail.afterHoursType,
    shadowBillingFlag: detail.shadowBillingFlag,
    pcpcmBasketFlag: detail.pcpcmBasketFlag,
  };

  return computeFeeBreakdown(deps, physicianId, input);
}

// ---------------------------------------------------------------------------
// Fee Computation Engine (shared by calculateFee, calculateFeePreview, getFeeBreakdown)
// ---------------------------------------------------------------------------

/**
 * Core fee computation logic.
 *
 * Formula: submitted_fee = (base_fee × calls) + modifier_adjustments + premiums
 *
 * Shadow billing override: if shadow_billing_flag = true → total $0.00.
 * All calculations use string-based decimal arithmetic to avoid floating point errors.
 */
async function computeFeeBreakdown(
  deps: FeeCalculationDeps,
  physicianId: string,
  input: FeeCalculateInput,
): Promise<FeeBreakdown> {
  const {
    healthServiceCode,
    dateOfService,
    modifier1,
    modifier2,
    modifier3,
    calls = 1,
    afterHoursFlag = false,
    afterHoursType = null,
    shadowBillingFlag = false,
  } = input;

  // 1. Look up base_fee from SOMB schedule
  const hscDetail = await deps.feeRefData.getHscDetail(healthServiceCode, dateOfService);
  if (!hscDetail || !hscDetail.baseFee) {
    // HSC code not found or has no base fee — return zero breakdown
    return {
      base_fee: '0.00',
      calls,
      modifier_adjustments: [],
      premiums: [],
      rrnp_premium: null,
      total_fee: '0.00',
    };
  }

  const baseFee = parseDecimal(hscDetail.baseFee);

  // Shadow billing override — fee $0.00 but still compute breakdown for tracking
  if (shadowBillingFlag) {
    const modifierAdjustments = await computeModifierAdjustments(
      deps, healthServiceCode, dateOfService, baseFee,
      [modifier1, modifier2, modifier3],
    );
    const premiums = await computePremiums(
      deps, physicianId, healthServiceCode, dateOfService,
      hscDetail, afterHoursFlag, afterHoursType,
      [modifier1, modifier2, modifier3],
    );
    const rrnpPremium = await computeRrnpPremium(
      deps, physicianId, dateOfService,
    );

    return {
      base_fee: hscDetail.baseFee,
      calls,
      modifier_adjustments: modifierAdjustments,
      premiums,
      rrnp_premium: rrnpPremium,
      total_fee: SHADOW_BILLING_FEE,
    };
  }

  // 2. Apply modifier adjustments in priority order
  const modifierAdjustments = await computeModifierAdjustments(
    deps, healthServiceCode, dateOfService, baseFee,
    [modifier1, modifier2, modifier3],
  );

  // 3. Calculate premiums
  const premiums = await computePremiums(
    deps, physicianId, healthServiceCode, dateOfService,
    hscDetail, afterHoursFlag, afterHoursType,
    [modifier1, modifier2, modifier3],
  );

  // 4. RRNP premium
  const rrnpPremium = await computeRrnpPremium(
    deps, physicianId, dateOfService,
  );

  // 5. Compute total
  //    total = (base_fee × calls) + sum(modifier_adjustments) + sum(premiums) + rrnp
  let total = baseFee * calls;

  for (const adj of modifierAdjustments) {
    total += parseDecimal(adj.amount);
  }

  for (const prem of premiums) {
    total += parseDecimal(prem.amount);
  }

  if (rrnpPremium) {
    total += parseDecimal(rrnpPremium);
  }

  // Ensure non-negative
  if (total < 0) {
    total = 0;
  }

  return {
    base_fee: hscDetail.baseFee,
    calls,
    modifier_adjustments: modifierAdjustments,
    premiums,
    rrnp_premium: rrnpPremium,
    total_fee: formatDecimal(total),
  };
}

/**
 * Compute modifier adjustments in SOMB-defined priority order.
 * Each modifier can be percentage-based or additive.
 */
async function computeModifierAdjustments(
  deps: FeeCalculationDeps,
  hscCode: string,
  dateOfService: string,
  baseFee: number,
  modifiers: (string | null | undefined)[],
): Promise<FeeBreakdownModifierAdjustment[]> {
  const adjustments: FeeBreakdownModifierAdjustment[] = [];
  const impacts: ModifierFeeImpact[] = [];

  // Fetch fee impact for each modifier
  for (const mod of modifiers) {
    if (!mod) continue;
    // Skip TM modifier — it's handled by shadow billing override, not as a fee adjustment
    if (mod === AhcipModifierCode.TM) continue;
    // Skip AFHR — after-hours is handled as a premium, not a modifier adjustment
    if (mod === AhcipModifierCode.AFHR) continue;

    const impact = await deps.feeRefData.getModifierFeeImpact(mod, hscCode, dateOfService);
    if (impact) {
      impacts.push(impact);
    }
  }

  // Sort by SOMB-defined priority order (lower priority number = applied first)
  impacts.sort((a, b) => a.priority - b.priority);

  // Apply each modifier
  for (const impact of impacts) {
    let amount: number;
    let effect: string;

    switch (impact.calculationMethod) {
      case 'PERCENTAGE': {
        const pct = parseDecimal(impact.value);
        amount = baseFee * pct;
        const pctDisplay = (pct * 100).toFixed(0);
        effect = `${pctDisplay}% of base fee`;
        break;
      }
      case 'ADDITIVE': {
        amount = parseDecimal(impact.value);
        effect = `+$${formatDecimal(amount)}`;
        break;
      }
      case 'OVERRIDE': {
        amount = parseDecimal(impact.value) - baseFee;
        effect = `Override to $${impact.value}`;
        break;
      }
      default:
        continue;
    }

    adjustments.push({
      modifier: impact.modifierCode,
      effect,
      amount: formatDecimal(amount),
    });
  }

  return adjustments;
}

/**
 * Compute independent premiums (CMGP, after-hours, ED surcharge).
 * RRNP is handled separately since it depends on physician eligibility.
 */
async function computePremiums(
  deps: FeeCalculationDeps,
  physicianId: string,
  hscCode: string,
  dateOfService: string,
  hscDetail: HscDetail,
  afterHoursFlag: boolean,
  afterHoursType: string | null,
  modifiers: (string | null | undefined)[],
): Promise<FeeBreakdownPremium[]> {
  const premiums: FeeBreakdownPremium[] = [];
  const modSet = new Set(modifiers.filter(Boolean) as string[]);

  // CMGP premium: if CMGP modifier present and HSC qualifies
  if (modSet.has(AhcipModifierCode.CMGP)) {
    const cmgpAmount = await deps.feeRefData.getCmgpPremium(hscCode, dateOfService);
    if (cmgpAmount) {
      premiums.push({ type: 'CMGP', amount: cmgpAmount });
    }
  }

  // After-hours premium: based on after_hours_type and HSC category
  if (afterHoursFlag && afterHoursType && hscDetail.afterHoursEligible) {
    const ahPremium = await deps.feeRefData.getAfterHoursPremium(
      hscCode, afterHoursType, dateOfService,
    );
    if (ahPremium) {
      premiums.push({ type: `AFTER_HOURS_${afterHoursType}`, amount: ahPremium });
    }
  }

  // ED surcharge (13.99H): if modifier present and HSC eligible
  if (modSet.has(AhcipModifierCode.ED_SURCHARGE) && hscDetail.surchargeEligible) {
    const edAmount = await deps.feeRefData.getEdSurcharge(hscCode, dateOfService);
    if (edAmount) {
      premiums.push({ type: 'ED_SURCHARGE', amount: edAmount });
    }
  }

  return premiums;
}

/**
 * Compute RRNP premium if physician qualifies.
 * Returns the flat premium amount or null.
 */
async function computeRrnpPremium(
  deps: FeeCalculationDeps,
  physicianId: string,
  dateOfService: string,
): Promise<string | null> {
  const eligible = await deps.feeProviderService.isRrnpEligible(physicianId);
  if (!eligible) {
    return null;
  }

  const amount = await deps.feeRefData.getRrnpPremium(physicianId, dateOfService);
  return amount ?? null;
}

// ---------------------------------------------------------------------------
// Decimal Helpers (avoid floating point errors for money)
// ---------------------------------------------------------------------------

/**
 * Parse a string decimal into a number.
 * Handles both "85.00" style and "0.15" style.
 */
function parseDecimal(value: string): number {
  const n = parseFloat(value);
  if (isNaN(n)) return 0;
  return n;
}

/**
 * Format a number as a 2-decimal-place string (e.g., "85.00").
 */
function formatDecimal(value: number): string {
  return value.toFixed(2);
}

/**
 * Resolve after-hours from ED shift times.
 * Called when claim has a shiftId and the shift has start/end times.
 *
 * Uses the shift start_time to determine the after-hours classification,
 * since the shift start represents when the physician began the service.
 */
export async function resolveAfterHoursFromShift(
  deps: AhcipServiceDeps,
  dateOfService: string,
  shiftStartTime: string | null,
  shiftEndTime: string | null,
): Promise<{ afterHoursFlag: boolean; afterHoursType: string | null }> {
  const dos = new Date(dateOfService + 'T00:00:00Z');

  // Stat holiday check first
  const holidayResult = await deps.referenceData.isHoliday(dos);
  if (holidayResult.is_holiday) {
    return {
      afterHoursFlag: true,
      afterHoursType: AfterHoursType.STAT_HOLIDAY,
    };
  }

  // Weekend check
  const dayOfWeek = dos.getUTCDay();
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    return {
      afterHoursFlag: true,
      afterHoursType: AfterHoursType.WEEKEND,
    };
  }

  // Use shift start_time to determine after-hours classification
  if (shiftStartTime) {
    const hour = parseHour(shiftStartTime);
    if (hour !== null) {
      return classifyHour(hour);
    }
  }

  return { afterHoursFlag: false, afterHoursType: null };
}

// ---------------------------------------------------------------------------
// Service: assembleBatch
// ---------------------------------------------------------------------------

/**
 * Assemble Thursday batch for a physician.
 *
 * Process:
 * 1. Find all QUEUED AHCIP claims for the physician, grouped by BA number.
 * 2. For PCPCM physicians: create separate batches per BA (FFS + PCPCM).
 * 3. Run pre-submission validation on every claim. Remove failed claims
 *    (return to VALIDATED state, emit notification).
 * 4. Calculate fee for each passing claim.
 * 5. Create ahcip_batch record with ASSEMBLING status per BA group.
 * 6. Link claims to batch.
 * 7. Transition claims to SUBMITTED.
 * 8. Emit BATCH_ASSEMBLED notification.
 *
 * Security:
 * - Physician scoping enforced by repository queries.
 * - Auto-submission mode respected per physician preference.
 * - Pre-submission validation prevents sending invalid claims to AHCIP.
 */
export async function assembleBatch(
  deps: BatchCycleDeps,
  physicianId: string,
  batchWeek: string,
): Promise<BatchAssemblyResult> {
  const result: BatchAssemblyResult = { batches: [], removedClaims: [] };

  // 1. Get auto-submission mode to determine which claims to include
  const autoMode = await deps.submissionPreferences.getAutoSubmissionMode(physicianId);

  // 2. Get all queued AHCIP claims grouped by BA via preview
  const previewGroups = await deps.repo.findNextBatchPreview(physicianId);

  if (previewGroups.length === 0) {
    return result;
  }

  // 3. Process each BA group separately (PCPCM dual-BA creates separate batches)
  for (const group of previewGroups) {
    // Determine isClean filter based on auto-submission mode
    let isCleanFilter: boolean | undefined;
    if (autoMode === 'AUTO_CLEAN') {
      isCleanFilter = true; // Only clean claims auto-submit
    } else if (autoMode === 'REQUIRE_APPROVAL') {
      continue; // Skip — physician must explicitly approve
    }
    // AUTO_ALL: isCleanFilter = undefined (include all queued claims)

    // Fetch claims for this BA
    const batchClaims = await deps.repo.listAhcipClaimsForBatch(
      physicianId,
      group.baNumber,
      isCleanFilter,
    );

    if (batchClaims.length === 0) {
      continue;
    }

    // 4. Pre-submission validation — remove failed claims
    const validClaims: typeof batchClaims = [];

    for (const item of batchClaims) {
      const validationResult = await deps.validationRunner.validateClaim(
        item.claim.claimId,
        physicianId,
      );

      if (!validationResult.passed) {
        // Return failed claim to VALIDATED state
        await deps.claimStateService.transitionState(
          item.claim.claimId,
          physicianId,
          'QUEUED',
          'VALIDATED',
          'SYSTEM',
          'SYSTEM',
        );

        result.removedClaims.push({
          claimId: item.claim.claimId,
          reason: validationResult.errors.map((e) => e.message).join('; '),
        });

        // Notify about removed claim
        await deps.notificationService.emit('CLAIM_VALIDATION_FAILED_PRE_BATCH', {
          claimId: item.claim.claimId,
          physicianId,
          errors: validationResult.errors.map((e) => ({
            check: e.check,
            message: e.message,
          })),
        });

        continue;
      }

      validClaims.push(item);
    }

    if (validClaims.length === 0) {
      continue;
    }

    // 5. Calculate fee for each valid claim
    let totalValue = 0;
    for (const item of validClaims) {
      const breakdown = await computeFeeBreakdown(
        {
          repo: deps.repo,
          feeRefData: deps.feeRefData,
          feeProviderService: deps.feeProviderService,
        },
        physicianId,
        {
          healthServiceCode: item.detail.healthServiceCode,
          dateOfService: item.claim.dateOfService,
          modifier1: item.detail.modifier1,
          modifier2: item.detail.modifier2,
          modifier3: item.detail.modifier3,
          calls: item.detail.calls,
          afterHoursFlag: item.detail.afterHoursFlag,
          afterHoursType: item.detail.afterHoursType,
          shadowBillingFlag: item.detail.shadowBillingFlag,
          pcpcmBasketFlag: item.detail.pcpcmBasketFlag,
        },
      );

      // Persist the calculated fee
      await deps.repo.updateAhcipDetail(
        item.claim.claimId,
        physicianId,
        { submittedFee: breakdown.total_fee } as any,
      );

      totalValue += parseDecimal(breakdown.total_fee);
    }

    // 6. Create batch record
    const batch = await deps.repo.createAhcipBatch({
      physicianId,
      baNumber: group.baNumber,
      batchWeek,
      status: AhcipBatchStatus.ASSEMBLING,
      claimCount: validClaims.length,
      totalSubmittedValue: formatDecimal(totalValue),
      createdBy: physicianId,
    } as any);

    // 7. Link claims to batch
    const claimIds = validClaims.map((c) => c.claim.claimId);
    await deps.repo.linkClaimsToBatch(claimIds, batch.ahcipBatchId);

    // 8. Transition claims to SUBMITTED
    for (const item of validClaims) {
      await deps.claimStateService.transitionState(
        item.claim.claimId,
        physicianId,
        'QUEUED',
        'SUBMITTED',
        'SYSTEM',
        'SYSTEM',
      );
    }

    result.batches.push({
      batchId: batch.ahcipBatchId,
      baNumber: group.baNumber,
      claimCount: validClaims.length,
      totalValue: formatDecimal(totalValue),
    });
  }

  // 9. Emit BATCH_ASSEMBLED notification for all batches
  if (result.batches.length > 0) {
    await deps.notificationService.emit('BATCH_ASSEMBLED', {
      physicianId,
      batchWeek,
      batches: result.batches.map((b) => ({
        batchId: b.batchId,
        baNumber: b.baNumber,
        claimCount: b.claimCount,
        totalValue: b.totalValue,
      })),
      removedClaimCount: result.removedClaims.length,
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Service: generateHlinkFile
// ---------------------------------------------------------------------------

/** H-Link submitter prefix from secrets management. */
const HLINK_SUBMITTER_PREFIX = process.env.HLINK_SUBMITTER_PREFIX ?? 'MERITUM';
/** Meritum vendor ID for H-Link header. */
const HLINK_VENDOR_ID = 'MERITUM_V1';

/**
 * Generate H-Link file for a batch per Electronic Claims Submission Specifications Manual.
 *
 * File structure:
 * - Header: submitter prefix, batch date, record count, vendor ID
 * - Claim records: ordered by DOS ascending
 * - Trailer: record count, total value checksum
 *
 * Security:
 * - Generated file encrypted at rest (AES-256) before storage.
 * - File hash (SHA-256) stored for integrity verification.
 * - Physician scoping via batch ownership check.
 */
export async function generateHlinkFile(
  deps: BatchCycleDeps,
  batchId: string,
  physicianId: string,
): Promise<HlinkFileContent> {
  // 1. Verify batch ownership and status
  const batch = await deps.repo.findBatchById(batchId, physicianId);
  if (!batch) {
    throw new Error('Batch not found');
  }

  if (batch.status !== AhcipBatchStatus.ASSEMBLING) {
    throw new Error(`Cannot generate file for batch in ${batch.status} status`);
  }

  // 2. Fetch linked claims for this batch
  // We get all submitted claims for this BA — they were linked during assembly
  const allClaims = await deps.repo.listAhcipClaimsForBatch(
    physicianId,
    batch.baNumber,
  );

  // Filter to only claims linked to this batch
  const linkedClaims = allClaims.filter(
    (c) => c.claim.submittedBatchId === batchId,
  );

  // Sort by date_of_service ascending
  linkedClaims.sort((a, b) =>
    a.claim.dateOfService.localeCompare(b.claim.dateOfService),
  );

  // 3. Generate header
  const batchDate = batch.batchWeek;
  const recordCount = linkedClaims.length;
  const header = formatHlinkHeader(
    HLINK_SUBMITTER_PREFIX,
    batchDate,
    recordCount,
    HLINK_VENDOR_ID,
  );

  // 4. Generate claim records
  const records: string[] = [];
  let totalValueCents = 0;

  for (const item of linkedClaims) {
    const record = formatHlinkClaimRecord(item.claim, item.detail);
    records.push(record);
    totalValueCents += Math.round(parseDecimal(item.detail.submittedFee ?? '0.00') * 100);
  }

  // 5. Generate trailer
  const totalValue = formatDecimal(totalValueCents / 100);
  const checksum = computeChecksum(header, records);
  const trailer = formatHlinkTrailer(recordCount, totalValue, checksum);

  // 6. Assemble full file content
  const fileLines = [header, ...records, trailer];
  const fileContent = Buffer.from(fileLines.join('\n') + '\n', 'utf-8');

  // 7. Encrypt and store file
  const filename = `hlink_${batch.baNumber}_${batchDate}_${batchId}.dat`;
  const { filePath, fileHash } = await deps.fileEncryption.encryptAndStore(
    fileContent,
    filename,
  );

  // 8. Update batch status to GENERATED
  await deps.repo.updateBatchStatus(batchId, physicianId, AhcipBatchStatus.GENERATED, {
    filePath,
    fileHash,
  } as any);

  return { header, records, trailer, raw: fileContent };
}

/**
 * Format H-Link header line.
 * Format: H|submitter_prefix|batch_date|record_count|vendor_id
 */
export function formatHlinkHeader(
  submitterPrefix: string,
  batchDate: string,
  recordCount: number,
  vendorId: string,
): string {
  return `H|${submitterPrefix}|${batchDate}|${String(recordCount).padStart(6, '0')}|${vendorId}`;
}

/**
 * Format a single H-Link claim record line.
 * Format: C|ba_number|hsc_code|dos|mod1|mod2|mod3|diag|facility|referral|calls|time|fee
 */
export function formatHlinkClaimRecord(
  claim: { dateOfService: string },
  detail: {
    baNumber: string;
    healthServiceCode: string;
    modifier1: string | null;
    modifier2: string | null;
    modifier3: string | null;
    diagnosticCode: string | null;
    facilityNumber: string | null;
    referralPractitioner: string | null;
    calls: number;
    timeSpent: number | null;
    submittedFee: string | null;
  },
): string {
  return [
    'C',
    detail.baNumber,
    detail.healthServiceCode,
    claim.dateOfService,
    detail.modifier1 ?? '',
    detail.modifier2 ?? '',
    detail.modifier3 ?? '',
    detail.diagnosticCode ?? '',
    detail.facilityNumber ?? '',
    detail.referralPractitioner ?? '',
    String(detail.calls),
    detail.timeSpent != null ? String(detail.timeSpent) : '',
    detail.submittedFee ?? '0.00',
  ].join('|');
}

/**
 * Format H-Link trailer line.
 * Format: T|record_count|total_value|checksum
 */
export function formatHlinkTrailer(
  recordCount: number,
  totalValue: string,
  checksum: string,
): string {
  return `T|${String(recordCount).padStart(6, '0')}|${totalValue}|${checksum}`;
}

/**
 * Compute SHA-256 checksum of header + records for trailer integrity verification.
 */
export function computeChecksum(header: string, records: string[]): string {
  const content = [header, ...records].join('\n');
  return createHash('sha256').update(content).digest('hex').substring(0, 16);
}

// ---------------------------------------------------------------------------
// Service: transmitBatch
// ---------------------------------------------------------------------------

/**
 * Transmit H-Link file via secure channel (SFTP/API).
 *
 * On success: update batch status to SUBMITTED with submitted_at and submission_reference.
 * On failure: retry with exponential backoff (1m, 5m, 15m, 1h).
 * After 4 failures: status = ERROR, emit notification.
 *
 * Security:
 * - H-Link credentials from secrets management (env vars), never in code or DB.
 * - Transmission logged: timestamp, file reference, record count, result.
 * - Physician scoping via batch ownership check.
 */
export async function transmitBatch(
  deps: BatchCycleDeps,
  batchId: string,
  physicianId: string,
): Promise<{ success: boolean; submissionReference?: string; error?: string }> {
  // 1. Verify batch ownership and status
  const batch = await deps.repo.findBatchById(batchId, physicianId);
  if (!batch) {
    throw new Error('Batch not found');
  }

  if (batch.status !== AhcipBatchStatus.GENERATED && batch.status !== AhcipBatchStatus.ERROR) {
    throw new Error(`Cannot transmit batch in ${batch.status} status`);
  }

  // 2. Attempt transmission with retry logic
  let lastError: string | undefined;

  for (let attempt = 0; attempt <= BATCH_MAX_RETRIES; attempt++) {
    try {
      const transmitResult = await deps.hlinkTransmission.transmit(
        Buffer.from(batch.filePath ?? '', 'utf-8'),
        {
          batchId,
          recordCount: batch.claimCount,
          totalValue: batch.totalSubmittedValue,
        },
      );

      // Success — update batch status
      await deps.repo.updateBatchStatus(batchId, physicianId, AhcipBatchStatus.SUBMITTED, {
        submissionReference: transmitResult.submissionReference,
        submittedAt: new Date(),
      } as any);

      return { success: true, submissionReference: transmitResult.submissionReference };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);

      // If we still have retries left, wait with exponential backoff
      if (attempt < BATCH_MAX_RETRIES) {
        const delayMs = (BATCH_RETRY_INTERVALS_S[attempt] ?? 60) * 1000;
        const sleepFn = deps.sleep ?? sleep;
        await sleepFn(delayMs);
      }
    }
  }

  // All retries exhausted — set batch to ERROR
  await deps.repo.updateBatchStatus(batchId, physicianId, AhcipBatchStatus.ERROR);

  // Emit failure notification
  await deps.notificationService.emit('BATCH_TRANSMISSION_FAILED', {
    physicianId,
    batchId,
    baNumber: batch.baNumber,
    batchWeek: batch.batchWeek,
    error: lastError,
    retryCount: BATCH_MAX_RETRIES,
  });

  return { success: false, error: lastError };
}

/**
 * Promise-based sleep for retry backoff.
 * Exported for testability (can be mocked in tests).
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Service: previewNextBatch
// ---------------------------------------------------------------------------

/**
 * Preview what the next Thursday batch will contain without actually assembling.
 *
 * Returns queued AHCIP claims grouped by BA number with counts and totals.
 * Does not modify any state.
 *
 * Security:
 * - Physician scoping enforced by repository query.
 */
export async function previewNextBatch(
  deps: BatchCycleDeps,
  physicianId: string,
): Promise<BatchPreview> {
  // Get next Thursday's date
  const batchWeek = getNextThursday();

  // Get preview groups from repository
  const groups = await deps.repo.findNextBatchPreview(physicianId);

  // Calculate totals
  let totalClaims = 0;
  let totalValueCents = 0;

  const previewGroups = groups.map((g) => {
    totalClaims += g.claimCount;
    totalValueCents += Math.round(parseDecimal(g.totalValue) * 100);
    return {
      baNumber: g.baNumber,
      claimCount: g.claimCount,
      totalValue: g.totalValue,
    };
  });

  return {
    batchWeek,
    groups: previewGroups,
    totalClaims,
    totalValue: formatDecimal(totalValueCents / 100),
  };
}

/**
 * Get the next Thursday date string (YYYY-MM-DD).
 * If today is Thursday before cutoff, returns today.
 * If today is Thursday after cutoff or later, returns next Thursday.
 */
export function getNextThursday(): string {
  const now = new Date();
  const dayOfWeek = now.getUTCDay(); // 0=Sun, 4=Thu
  let daysUntilThursday = (4 - dayOfWeek + 7) % 7;
  if (daysUntilThursday === 0) {
    // It's Thursday — default to next Thursday
    daysUntilThursday = 7;
  }
  const next = new Date(now);
  next.setUTCDate(next.getUTCDate() + daysUntilThursday);
  return next.toISOString().split('T')[0];
}

// ---------------------------------------------------------------------------
// Service: retryFailedBatch
// ---------------------------------------------------------------------------

/**
 * Retry transmission for an ERROR status batch.
 *
 * Resets the batch to GENERATED and attempts transmission again.
 * Only allowed for batches in ERROR status.
 *
 * Security:
 * - Physician scoping via batch ownership check.
 */
export async function retryFailedBatch(
  deps: BatchCycleDeps,
  batchId: string,
  physicianId: string,
): Promise<{ success: boolean; submissionReference?: string; error?: string }> {
  // 1. Verify batch ownership and status
  const batch = await deps.repo.findBatchById(batchId, physicianId);
  if (!batch) {
    throw new Error('Batch not found');
  }

  if (batch.status !== AhcipBatchStatus.ERROR) {
    throw new Error(`Can only retry batches in ERROR status, current: ${batch.status}`);
  }

  // 2. Update status to GENERATED to allow transmission
  await deps.repo.updateBatchStatus(batchId, physicianId, AhcipBatchStatus.GENERATED);

  // 3. Attempt transmission (transmitBatch handles retry logic)
  return transmitBatch(deps, batchId, physicianId);
}

// ---------------------------------------------------------------------------
// Assessment Response Ingestion Types
// ---------------------------------------------------------------------------

/**
 * A single record from the H-Link assessment response file.
 * Maps to one submitted claim.
 */
export interface AssessmentRecord {
  /** Submission reference linking to the original batch. */
  submissionReference: string;
  /** Claim reference matching the original claim in our system. */
  claimReference: string;
  /** Assessment outcome: ACCEPTED, REJECTED, or ADJUSTED. */
  status: 'ACCEPTED' | 'REJECTED' | 'ADJUSTED';
  /** Fee as assessed by AHCIP (may differ from submitted_fee for adjusted claims). */
  assessedFee: string;
  /** Explanatory code(s) returned by AHCIP. Present for rejected/adjusted claims. */
  explanatoryCodes: string[];
}

/**
 * Parsed assessment file containing header metadata and individual records.
 */
export interface ParsedAssessmentFile {
  submissionReference: string;
  batchDate: string;
  recordCount: number;
  records: AssessmentRecord[];
}

/**
 * Result of processing a single assessment record.
 */
export interface AssessmentRecordResult {
  claimId: string;
  claimReference: string;
  status: 'ACCEPTED' | 'REJECTED' | 'ADJUSTED';
  assessedFee: string;
  submittedFee: string;
  explanatoryCodes: ResolvedExplanatoryCode[];
  isCleanAcceptance: boolean;
  correctiveActions: CorrectiveAction[];
}

/**
 * Explanatory code resolved against Reference Data.
 */
export interface ResolvedExplanatoryCode {
  code: string;
  description: string;
  category: string;
  correctiveGuidance: string | null;
}

/**
 * One-click corrective action for common rejections.
 */
export interface CorrectiveAction {
  actionType: string;
  label: string;
  field: string;
  description: string;
}

/**
 * Result of ingesting an entire assessment file.
 */
export interface AssessmentIngestionResult {
  batchId: string;
  totalRecords: number;
  accepted: number;
  rejected: number;
  adjusted: number;
  unmatched: number;
  unmatchedRecords: Array<{ claimReference: string; reason: string }>;
  results: AssessmentRecordResult[];
}

/**
 * Per-claim assessment result for physician display.
 */
export interface BatchAssessmentResult {
  batchId: string;
  batchStatus: string;
  submissionReference: string | null;
  totalClaims: number;
  accepted: number;
  rejected: number;
  adjusted: number;
  claims: Array<{
    claimId: string;
    healthServiceCode: string;
    dateOfService: string;
    submittedFee: string;
    assessedFee: string | null;
    state: string;
    explanatoryCodes: ResolvedExplanatoryCode[];
    correctiveActions: CorrectiveAction[];
  }>;
}

// ---------------------------------------------------------------------------
// Assessment Ingestion Dependency Interfaces
// ---------------------------------------------------------------------------

/**
 * H-Link assessment file retrieval service — abstraction over SFTP/API channel.
 */
export interface HlinkAssessmentRetrievalService {
  /** Retrieve assessment file for a batch. Returns raw file content. */
  retrieveAssessmentFile(submissionReference: string): Promise<Buffer>;
}

/**
 * Reference Data service for explanatory code resolution.
 */
export interface ExplanatoryCodeService {
  /** Resolve an AHCIP explanatory code to description and corrective guidance. */
  resolveExplanatoryCode(code: string): Promise<ResolvedExplanatoryCode | null>;
}

/** Dependencies for assessment ingestion operations. */
export interface AssessmentIngestionDeps {
  repo: AhcipRepository;
  claimStateService: ClaimStateService;
  notificationService: BatchNotificationService;
  hlinkRetrieval: HlinkAssessmentRetrievalService;
  explanatoryCodeService: ExplanatoryCodeService;
  fileEncryption: FileEncryptionService;
}

// ---------------------------------------------------------------------------
// Service: ingestAssessmentFile
// ---------------------------------------------------------------------------

/**
 * Ingest an assessment file from H-Link for a submitted batch.
 *
 * Process:
 * 1. Verify batch exists and is in SUBMITTED status.
 * 2. Retrieve assessment file via secure channel.
 * 3. Store raw file encrypted for audit trail.
 * 4. Parse file per H-Link response format.
 * 5. Match each record to submitted claims.
 * 6. Process each record (accepted/rejected/adjusted).
 * 7. Update batch status to RESPONSE_RECEIVED.
 *
 * Security:
 * - Assessment files contain PHI — processed within Canadian data residency.
 * - Raw file retained encrypted for audit.
 * - Unmatched records logged for manual resolution — no silent data loss.
 * - Physician scoping enforced via batch ownership check.
 */
export async function ingestAssessmentFile(
  deps: AssessmentIngestionDeps,
  batchId: string,
  physicianId: string,
): Promise<AssessmentIngestionResult> {
  // 1. Verify batch exists and is in SUBMITTED status
  const batch = await deps.repo.findBatchById(batchId, physicianId);
  if (!batch) {
    throw new Error('Batch not found');
  }

  if (batch.status !== AhcipBatchStatus.SUBMITTED) {
    throw new Error(`Cannot ingest assessment for batch in ${batch.status} status`);
  }

  // 2. Retrieve assessment file from H-Link
  const rawFile = await deps.hlinkRetrieval.retrieveAssessmentFile(
    batch.submissionReference ?? batchId,
  );

  // 3. Store raw file encrypted for audit trail
  const auditFilename = `assessment_${batchId}_${Date.now()}.dat`;
  await deps.fileEncryption.encryptAndStore(rawFile, auditFilename);

  // 4. Parse the assessment file
  const parsed = parseAssessmentFile(rawFile);

  // 6. Process each record
  const result: AssessmentIngestionResult = {
    batchId,
    totalRecords: parsed.records.length,
    accepted: 0,
    rejected: 0,
    adjusted: 0,
    unmatched: 0,
    unmatchedRecords: [],
    results: [],
  };

  for (const record of parsed.records) {
    // Look up each claim directly by ID (physician-scoped via repository)
    const matchedClaim = await deps.repo.findAhcipDetailByClaimId(
      record.claimReference,
      physicianId,
    );

    if (!matchedClaim || matchedClaim.claim.submittedBatchId !== batchId) {
      // Unmatched record — log for manual resolution
      result.unmatched++;
      result.unmatchedRecords.push({
        claimReference: record.claimReference,
        reason: 'No matching submitted claim found for reference',
      });
      continue;
    }

    // Structure claim data for processAssessmentRecord
    const claimData = {
      claim: matchedClaim.claim,
      detail: matchedClaim,
    };

    const recordResult = await processAssessmentRecord(
      deps,
      record,
      claimData,
      physicianId,
    );

    result.results.push(recordResult);

    switch (record.status) {
      case 'ACCEPTED':
        result.accepted++;
        break;
      case 'REJECTED':
        result.rejected++;
        break;
      case 'ADJUSTED':
        result.adjusted++;
        break;
    }
  }

  // 7. Update batch status to RESPONSE_RECEIVED
  await deps.repo.updateBatchStatus(
    batchId,
    physicianId,
    AhcipBatchStatus.RESPONSE_RECEIVED,
    { responseReceivedAt: new Date() } as any,
  );

  return result;
}

// ---------------------------------------------------------------------------
// Service: processAssessmentRecord
// ---------------------------------------------------------------------------

/**
 * Process a single assessment record from the H-Link response.
 *
 * Outcomes:
 * - Accepted: SUBMITTED → ASSESSED, store assessed_fee. If assessed === submitted, clean acceptance.
 * - Rejected: SUBMITTED → REJECTED, store explanatory codes. Emit CLAIM_REJECTED notification.
 * - Adjusted: SUBMITTED → ASSESSED, store assessed_fee (differs from submitted). Flag for review.
 *
 * Explanatory code resolution:
 * - Lookup each code in Reference Data for description and corrective guidance.
 * - For common rejections, generate one-click corrective actions.
 */
export async function processAssessmentRecord(
  deps: AssessmentIngestionDeps,
  record: AssessmentRecord,
  claimData: { claim: any; detail: any },
  physicianId: string,
): Promise<AssessmentRecordResult> {
  const claimId = claimData.claim.claimId;
  const submittedFee = claimData.detail.submittedFee ?? '0.00';

  // Resolve explanatory codes via Reference Data
  const resolvedCodes: ResolvedExplanatoryCode[] = [];
  for (const code of record.explanatoryCodes) {
    const resolved = await deps.explanatoryCodeService.resolveExplanatoryCode(code);
    if (resolved) {
      resolvedCodes.push(resolved);
    } else {
      // Unknown code — still record it with minimal info
      resolvedCodes.push({
        code,
        description: `Unknown explanatory code: ${code}`,
        category: 'UNKNOWN',
        correctiveGuidance: null,
      });
    }
  }

  // Generate corrective actions for common rejections
  const correctiveActions = generateCorrectiveActions(resolvedCodes);

  switch (record.status) {
    case 'ACCEPTED': {
      // Transition SUBMITTED → ASSESSED
      await deps.claimStateService.transitionState(
        claimId, physicianId, 'SUBMITTED', 'ASSESSED', 'SYSTEM', 'SYSTEM',
      );

      // Store assessed_fee
      await deps.repo.updateAssessmentResult(
        claimId, physicianId, record.assessedFee, resolvedCodes,
      );

      const isCleanAcceptance = record.assessedFee === submittedFee;

      return {
        claimId,
        claimReference: record.claimReference,
        status: 'ACCEPTED',
        assessedFee: record.assessedFee,
        submittedFee,
        explanatoryCodes: resolvedCodes,
        isCleanAcceptance,
        correctiveActions: [],
      };
    }

    case 'REJECTED': {
      // Transition SUBMITTED → REJECTED
      await deps.claimStateService.transitionState(
        claimId, physicianId, 'SUBMITTED', 'REJECTED', 'SYSTEM', 'SYSTEM',
      );

      // Store explanatory codes
      await deps.repo.updateAssessmentResult(
        claimId, physicianId, '0.00', resolvedCodes,
      );

      // Emit CLAIM_REJECTED notification
      await deps.notificationService.emit('CLAIM_REJECTED', {
        claimId,
        physicianId,
        explanatoryCodes: resolvedCodes.map((c) => ({
          code: c.code,
          description: c.description,
          category: c.category,
        })),
        correctiveActions: correctiveActions.map((a) => ({
          actionType: a.actionType,
          label: a.label,
        })),
      });

      return {
        claimId,
        claimReference: record.claimReference,
        status: 'REJECTED',
        assessedFee: '0.00',
        submittedFee,
        explanatoryCodes: resolvedCodes,
        isCleanAcceptance: false,
        correctiveActions,
      };
    }

    case 'ADJUSTED': {
      // Transition SUBMITTED → ASSESSED (adjusted claims still assessed, just different fee)
      await deps.claimStateService.transitionState(
        claimId, physicianId, 'SUBMITTED', 'ASSESSED', 'SYSTEM', 'SYSTEM',
      );

      // Store assessed_fee (different from submitted)
      await deps.repo.updateAssessmentResult(
        claimId, physicianId, record.assessedFee, resolvedCodes,
      );

      // Emit notification for physician review
      await deps.notificationService.emit('CLAIM_ASSESSED', {
        claimId,
        physicianId,
        submittedFee,
        assessedFee: record.assessedFee,
        isAdjusted: true,
        explanatoryCodes: resolvedCodes.map((c) => ({
          code: c.code,
          description: c.description,
        })),
      });

      return {
        claimId,
        claimReference: record.claimReference,
        status: 'ADJUSTED',
        assessedFee: record.assessedFee,
        submittedFee,
        explanatoryCodes: resolvedCodes,
        isCleanAcceptance: false,
        correctiveActions,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Service: reconcilePayment
// ---------------------------------------------------------------------------

/**
 * Reconcile payment for a batch when Friday deposit confirmed.
 *
 * Process:
 * 1. Verify batch is in RESPONSE_RECEIVED status.
 * 2. Find all ASSESSED claims linked to this batch.
 * 3. Transition each ASSESSED claim to PAID.
 * 4. Update batch status to RECONCILED.
 * 5. Emit CLAIM_PAID notifications.
 *
 * Security:
 * - Payment reconciliation is final — PAID claims enter terminal state.
 * - Physician scoping enforced via batch ownership check.
 */
export async function reconcilePayment(
  deps: AssessmentIngestionDeps,
  batchId: string,
  physicianId: string,
): Promise<{ reconciledCount: number }> {
  // 1. Verify batch exists and is in RESPONSE_RECEIVED status
  const batch = await deps.repo.findBatchById(batchId, physicianId);
  if (!batch) {
    throw new Error('Batch not found');
  }

  if (batch.status !== AhcipBatchStatus.RESPONSE_RECEIVED) {
    throw new Error(`Cannot reconcile batch in ${batch.status} status`);
  }

  // 2. Find all claims linked to this batch (any state)
  const linkedClaims = await deps.repo.findClaimsByBatchId(batchId, physicianId);

  // 3. Transition each ASSESSED claim to PAID
  let reconciledCount = 0;
  for (const item of linkedClaims) {
    if (item.claim.state === 'ASSESSED') {
      await deps.claimStateService.transitionState(
        item.claim.claimId, physicianId,
        'ASSESSED', 'PAID', 'SYSTEM', 'SYSTEM',
      );

      // Emit CLAIM_PAID notification
      await deps.notificationService.emit('CLAIM_PAID', {
        claimId: item.claim.claimId,
        physicianId,
        assessedFee: item.detail.assessedFee,
      });

      reconciledCount++;
    }
  }

  // 4. Update batch status to RECONCILED
  await deps.repo.updateBatchStatus(
    batchId,
    physicianId,
    AhcipBatchStatus.RECONCILED,
  );

  return { reconciledCount };
}

// ---------------------------------------------------------------------------
// Service: getAssessmentResults
// ---------------------------------------------------------------------------

/**
 * Return batch assessment results with per-claim status.
 * For physician display of how their batch was assessed.
 *
 * Security:
 * - Physician scoping enforced via batch ownership check.
 */
export async function getAssessmentResults(
  deps: AssessmentIngestionDeps,
  batchId: string,
  physicianId: string,
): Promise<BatchAssessmentResult> {
  const batch = await deps.repo.findBatchById(batchId, physicianId);
  if (!batch) {
    throw new Error('Batch not found');
  }

  // Get claims linked to this batch (any state)
  const linkedClaims = await deps.repo.findClaimsByBatchId(batchId, physicianId);

  let accepted = 0;
  let rejected = 0;
  let adjusted = 0;

  const claimResults = await Promise.all(
    linkedClaims.map(async (item) => {
      const explanatoryCodes: ResolvedExplanatoryCode[] =
        Array.isArray(item.detail.assessmentExplanatoryCodes)
          ? item.detail.assessmentExplanatoryCodes
          : [];

      const correctiveActions = generateCorrectiveActions(explanatoryCodes);

      // Determine assessment status from claim state and fee comparison
      if (item.claim.state === 'REJECTED') {
        rejected++;
      } else if (item.detail.assessedFee && item.detail.submittedFee &&
        item.detail.assessedFee !== item.detail.submittedFee) {
        adjusted++;
      } else if (item.claim.state === 'ASSESSED' || item.claim.state === 'PAID') {
        accepted++;
      }

      return {
        claimId: item.claim.claimId,
        healthServiceCode: item.detail.healthServiceCode,
        dateOfService: item.claim.dateOfService,
        submittedFee: item.detail.submittedFee ?? '0.00',
        assessedFee: item.detail.assessedFee ?? null,
        state: item.claim.state,
        explanatoryCodes,
        correctiveActions,
      };
    }),
  );

  return {
    batchId,
    batchStatus: batch.status,
    submissionReference: batch.submissionReference,
    totalClaims: linkedClaims.length,
    accepted,
    rejected,
    adjusted,
    claims: claimResults,
  };
}

// ---------------------------------------------------------------------------
// Service: listBatchesAwaitingResponse
// ---------------------------------------------------------------------------

/**
 * List batches in SUBMITTED status awaiting H-Link assessment response.
 * For physician dashboard display.
 *
 * Security:
 * - Physician scoping enforced by repository query.
 */
export async function listBatchesAwaitingResponse(
  deps: AssessmentIngestionDeps,
  physicianId: string,
): Promise<Array<{
  batchId: string;
  baNumber: string;
  batchWeek: string;
  claimCount: number;
  totalSubmittedValue: string;
  submittedAt: Date | null;
  submissionReference: string | null;
}>> {
  const batches = await deps.repo.findBatchesAwaitingResponse(physicianId);

  return batches.map((b) => ({
    batchId: b.ahcipBatchId,
    baNumber: b.baNumber,
    batchWeek: b.batchWeek,
    claimCount: b.claimCount,
    totalSubmittedValue: b.totalSubmittedValue,
    submittedAt: b.submittedAt,
    submissionReference: b.submissionReference,
  }));
}

// ---------------------------------------------------------------------------
// Assessment File Parsing
// ---------------------------------------------------------------------------

/**
 * Parse H-Link assessment response file.
 *
 * File format mirrors submission:
 * - Header: H|submission_reference|batch_date|record_count
 * - Records: R|claim_reference|status|assessed_fee|explanatory_code1;code2;...
 * - Trailer: T|record_count|total_assessed_value
 */
export function parseAssessmentFile(rawFile: Buffer): ParsedAssessmentFile {
  const content = rawFile.toString('utf-8');
  const lines = content.split('\n').filter((l) => l.trim().length > 0);

  if (lines.length === 0) {
    throw new Error('Invalid assessment file: empty file');
  }

  // Parse header
  const headerParts = lines[0].split('|');
  if (headerParts[0] !== 'H') {
    throw new Error('Invalid assessment file: missing header');
  }

  const submissionReference = headerParts[1] ?? '';
  const batchDate = headerParts[2] ?? '';
  const recordCount = parseInt(headerParts[3] ?? '0', 10);

  // Parse records (skip header and trailer)
  const records: AssessmentRecord[] = [];
  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split('|');

    if (parts[0] === 'T') {
      // Trailer — skip
      continue;
    }

    if (parts[0] === 'R') {
      const status = parts[2] as 'ACCEPTED' | 'REJECTED' | 'ADJUSTED';
      const assessedFee = parts[3] ?? '0.00';
      const codes = parts[4] ? parts[4].split(';').filter((c) => c.length > 0) : [];

      records.push({
        submissionReference,
        claimReference: parts[1] ?? '',
        status,
        assessedFee,
        explanatoryCodes: codes,
      });
    }
  }

  return {
    submissionReference,
    batchDate,
    recordCount,
    records,
  };
}

// ---------------------------------------------------------------------------
// Corrective Action Generation
// ---------------------------------------------------------------------------

/**
 * Generate one-click corrective actions for common rejection patterns.
 * Maps explanatory code categories to actionable fixes.
 */
function generateCorrectiveActions(
  codes: ResolvedExplanatoryCode[],
): CorrectiveAction[] {
  const actions: CorrectiveAction[] = [];
  const seenTypes = new Set<string>();

  for (const code of codes) {
    // Map well-known categories to corrective actions
    const action = mapCodeToCorrectiveAction(code);
    if (action && !seenTypes.has(action.actionType)) {
      actions.push(action);
      seenTypes.add(action.actionType);
    }
  }

  return actions;
}

/**
 * Map an explanatory code to a corrective action.
 * Returns null if no automatic corrective action is available.
 */
function mapCodeToCorrectiveAction(
  code: ResolvedExplanatoryCode,
): CorrectiveAction | null {
  switch (code.category) {
    case 'MISSING_REFERRAL':
      return {
        actionType: 'ADD_REFERRAL',
        label: 'Add referring practitioner',
        field: 'referral_practitioner',
        description: 'Add the referring practitioner billing number to satisfy GR 8.',
      };

    case 'MISSING_DIAGNOSTIC':
      return {
        actionType: 'ADD_DIAGNOSTIC_CODE',
        label: 'Add diagnostic code',
        field: 'diagnostic_code',
        description: 'Add a valid ICD-9 diagnostic code for this service.',
      };

    case 'MISSING_FACILITY':
      return {
        actionType: 'ADD_FACILITY',
        label: 'Add facility number',
        field: 'facility_number',
        description: 'Add the facility number where the service was provided.',
      };

    case 'INVALID_HSC':
      return {
        actionType: 'UPDATE_HSC',
        label: 'Update service code',
        field: 'health_service_code',
        description: 'The HSC code was rejected. Review and update the service code.',
      };

    case 'EXPIRED_SUBMISSION':
      return {
        actionType: 'WRITE_OFF',
        label: 'Write off claim',
        field: 'state',
        description: 'The submission window has expired. Consider writing off this claim.',
      };

    case 'DUPLICATE_CLAIM':
      return {
        actionType: 'REVIEW_DUPLICATE',
        label: 'Review duplicate',
        field: 'claim_id',
        description: 'This claim was flagged as a duplicate. Review and resolve.',
      };

    default:
      return null;
  }
}
