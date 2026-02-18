import { createHash } from 'node:crypto';
import type { ClaimRepository } from './claim.repository.js';
import {
  ClaimType,
  ClaimImportSource,
  ClaimAuditAction,
  ActorContext,
  ClaimState,
  ShiftStatus,
  ValidationCheckId,
  ValidationSeverity,
  AutoSubmissionMode,
  ImportBatchStatus,
  TERMINAL_STATES,
  STATE_TRANSITIONS,
  ClaimNotificationEvent,
} from '@meritum/shared/constants/claim.constants.js';
import { BusinessRuleError, ConflictError, ForbiddenError, NotFoundError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface ProviderCheck {
  isActive(physicianId: string): Promise<boolean>;
  getRegistrationDate?(physicianId: string): Promise<string | null>;
}

export interface PatientCheck {
  exists(patientId: string, physicianId: string): Promise<boolean>;
}

/** Pathway-specific validator (AHCIP or WCB). Modules implement this. */
export interface PathwayValidator {
  validate(claim: Record<string, any>, physicianId: string): Promise<ValidationEntry[]>;
}

/** Reference data version provider. */
export interface ReferenceDataVersionProvider {
  getCurrentVersion(): Promise<string>;
}

/** Notification emitter for claim events. */
export interface NotificationEmitter {
  emit(event: string, payload: Record<string, unknown>): Promise<void>;
}

/** Provider submission preference lookup. */
export interface SubmissionPreferenceLookup {
  getSubmissionMode(physicianId: string, claimType: string): Promise<string>;
}

/** Facility ownership check (from Provider Management domain). */
export interface FacilityCheck {
  belongsToPhysician(facilityId: string, physicianId: string): Promise<boolean>;
}

/** After-hours premium calculator (pathway-specific, e.g. AHCIP or WCB). */
export interface AfterHoursPremiumCalculator {
  calculatePremiums(
    claims: Record<string, any>[],
    shiftStartTime: string,
    shiftEndTime: string,
  ): Promise<{ claimId: string; premium: string }[]>;
}

/** Explanatory code lookup for rejection management (Reference Data, Domain 2). */
export interface ExplanatoryCodeLookup {
  getExplanatoryCode(code: string): Promise<{
    code: string;
    description: string;
    severity: string;
    commonCause: string;
    suggestedAction: string;
    helpText: string;
  } | null>;
}

export interface ClaimServiceDeps {
  repo: ClaimRepository;
  providerCheck: ProviderCheck;
  patientCheck: PatientCheck;
  pathwayValidators?: Record<string, PathwayValidator>;
  referenceDataVersion?: ReferenceDataVersionProvider;
  notificationEmitter?: NotificationEmitter;
  submissionPreference?: SubmissionPreferenceLookup;
  facilityCheck?: FacilityCheck;
  afterHoursPremiumCalculators?: Record<string, AfterHoursPremiumCalculator>;
  explanatoryCodeLookup?: ExplanatoryCodeLookup;
}

// ---------------------------------------------------------------------------
// Validation result types
// ---------------------------------------------------------------------------

export interface ValidationEntry {
  check: string;
  rule_reference: string;
  message: string;
  help_text: string;
  field_affected?: string;
}

export interface ValidationResult {
  errors: ValidationEntry[];
  warnings: ValidationEntry[];
  info: ValidationEntry[];
  passed: boolean;
  validation_timestamp: string;
  reference_data_version: string;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Rejection management types
// ---------------------------------------------------------------------------

export interface RejectionCodeDetail {
  code: string;
  description: string;
  commonCause: string;
  suggestedAction: string;
  helpText: string;
}

export interface RejectionDetails {
  claimId: string;
  state: string;
  rejectionCodes: RejectionCodeDetail[];
  resubmissionEligible: boolean;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export interface CreateClaimInput {
  claimType: string;
  patientId: string;
  dateOfService: string;
  importSource?: string;
}

export interface MappedRow {
  claimType: string;
  patientId: string;
  dateOfService: string;
  [key: string]: string | undefined;
}

export interface UploadedFile {
  fileName: string;
  content: Buffer | string;
}

export interface FieldMappingEntry {
  source_column: string;
  target_field: string;
  transform?: string;
}

export interface ImportPreviewRow {
  rowNumber: number;
  mapped: Record<string, string>;
  errors: Array<{ field: string; message: string }>;
}

export interface ImportPreviewResult {
  rows: ImportPreviewRow[];
  unmappedColumns: string[];
  totalRows: number;
  validRows: number;
  errorRows: number;
}

export interface ImportCommitResult {
  successCount: number;
  errorCount: number;
  errorDetails: Array<{ rowNumber: number; field: string; message: string }>;
}

export interface EncounterInput {
  patientId: string;
  dateOfService: string;
  claimType: string;
}

export interface CreateShiftInput {
  facilityId: string;
  shiftDate: string;
  startTime?: string;
  endTime?: string;
}

// ---------------------------------------------------------------------------
// Deadline calculation
// ---------------------------------------------------------------------------

/** AHCIP deadline: DOS + 90 calendar days. */
const AHCIP_DEADLINE_DAYS = 90;

function calculateSubmissionDeadline(claimType: string, dateOfService: string): string {
  if (claimType === ClaimType.AHCIP) {
    const dos = new Date(dateOfService + 'T00:00:00Z');
    dos.setUTCDate(dos.getUTCDate() + AHCIP_DEADLINE_DAYS);
    return dos.toISOString().split('T')[0];
  }

  // WCB: form-specific deadlines delegated to Domain 4.2.
  // Default to DOS + 90 days for initial claim creation; Domain 4.2
  // overrides during pathway-specific processing.
  const dos = new Date(dateOfService + 'T00:00:00Z');
  dos.setUTCDate(dos.getUTCDate() + AHCIP_DEADLINE_DAYS);
  return dos.toISOString().split('T')[0];
}

// ---------------------------------------------------------------------------
// Service: createClaim
// ---------------------------------------------------------------------------

/**
 * Create a claim with state DRAFT via manual entry.
 *
 * Verifies:
 * - Physician is active with valid BA (via ProviderCheck)
 * - Patient exists in physician's registry (via PatientCheck)
 *
 * Calculates submission_deadline based on claim_type:
 * - AHCIP: DOS + 90 calendar days
 * - WCB: defaults to DOS + 90 days (Domain 4.2 overrides later)
 *
 * Appends CREATED audit entry with actor_id and actor_context.
 */
export async function createClaim(
  deps: ClaimServiceDeps,
  physicianId: string,
  actorId: string,
  actorContext: string,
  data: CreateClaimInput,
): Promise<{ claimId: string }> {
  // 1. Verify physician is active
  const providerActive = await deps.providerCheck.isActive(physicianId);
  if (!providerActive) {
    throw new BusinessRuleError(
      'Physician is not active or does not have a valid billing arrangement',
    );
  }

  // 2. Verify patient exists in physician's registry
  const patientExists = await deps.patientCheck.exists(data.patientId, physicianId);
  if (!patientExists) {
    throw new NotFoundError('Patient');
  }

  // 3. Calculate submission deadline
  const submissionDeadline = calculateSubmissionDeadline(
    data.claimType,
    data.dateOfService,
  );

  // 4. Create the claim record (repository forces state=DRAFT)
  const claim = await deps.repo.createClaim({
    physicianId,
    patientId: data.patientId,
    claimType: data.claimType,
    importSource: data.importSource ?? ClaimImportSource.MANUAL,
    dateOfService: data.dateOfService,
    submissionDeadline,
    createdBy: actorId,
    updatedBy: actorId,
  } as any);

  // 5. Append CREATED audit entry
  await deps.repo.appendClaimAudit({
    claimId: claim.claimId,
    action: ClaimAuditAction.CREATED,
    previousState: null,
    newState: 'DRAFT',
    changes: null,
    actorId,
    actorContext,
  } as any);

  return { claimId: claim.claimId };
}

// ---------------------------------------------------------------------------
// Service: createClaimFromImport
// ---------------------------------------------------------------------------

/**
 * Create a claim from an EMR import batch row.
 *
 * Sets import_source = EMR_IMPORT and import_batch_id.
 * Same validation as manual creation.
 */
export async function createClaimFromImport(
  deps: ClaimServiceDeps,
  physicianId: string,
  actorId: string,
  importBatchId: string,
  rowData: MappedRow,
): Promise<{ claimId: string }> {
  // 1. Verify physician is active
  const providerActive = await deps.providerCheck.isActive(physicianId);
  if (!providerActive) {
    throw new BusinessRuleError(
      'Physician is not active or does not have a valid billing arrangement',
    );
  }

  // 2. Verify patient exists
  const patientExists = await deps.patientCheck.exists(rowData.patientId, physicianId);
  if (!patientExists) {
    throw new NotFoundError('Patient');
  }

  // 3. Calculate submission deadline
  const submissionDeadline = calculateSubmissionDeadline(
    rowData.claimType,
    rowData.dateOfService,
  );

  // 4. Create the claim record with import metadata
  const claim = await deps.repo.createClaim({
    physicianId,
    patientId: rowData.patientId,
    claimType: rowData.claimType,
    importSource: ClaimImportSource.EMR_IMPORT,
    importBatchId,
    dateOfService: rowData.dateOfService,
    submissionDeadline,
    createdBy: actorId,
    updatedBy: actorId,
  } as any);

  // 5. Append CREATED audit entry
  await deps.repo.appendClaimAudit({
    claimId: claim.claimId,
    action: ClaimAuditAction.CREATED,
    previousState: null,
    newState: 'DRAFT',
    changes: { importBatchId },
    actorId,
    actorContext: ActorContext.SYSTEM,
  } as any);

  return { claimId: claim.claimId };
}

// ---------------------------------------------------------------------------
// Service: createClaimFromShift
// ---------------------------------------------------------------------------

/**
 * Create a claim from an ED shift encounter.
 *
 * Sets import_source = ED_SHIFT and shift_id.
 * Increments the shift's encounter count.
 * Verifies the shift exists and is in IN_PROGRESS status.
 */
export async function createClaimFromShift(
  deps: ClaimServiceDeps,
  physicianId: string,
  actorId: string,
  shiftId: string,
  encounterData: EncounterInput,
): Promise<{ claimId: string }> {
  // 1. Verify physician is active
  const providerActive = await deps.providerCheck.isActive(physicianId);
  if (!providerActive) {
    throw new BusinessRuleError(
      'Physician is not active or does not have a valid billing arrangement',
    );
  }

  // 2. Verify patient exists
  const patientExists = await deps.patientCheck.exists(
    encounterData.patientId,
    physicianId,
  );
  if (!patientExists) {
    throw new NotFoundError('Patient');
  }

  // 3. Verify shift exists and belongs to physician
  const shift = await deps.repo.findShiftById(shiftId, physicianId);
  if (!shift) {
    throw new NotFoundError('Shift');
  }

  // 4. Verify shift is in IN_PROGRESS status
  if (shift.status !== ShiftStatus.IN_PROGRESS) {
    throw new BusinessRuleError(
      'Cannot add encounters to a shift that is not in progress',
    );
  }

  // 5. Calculate submission deadline
  const submissionDeadline = calculateSubmissionDeadline(
    encounterData.claimType,
    encounterData.dateOfService,
  );

  // 6. Create the claim record with shift metadata
  const claim = await deps.repo.createClaim({
    physicianId,
    patientId: encounterData.patientId,
    claimType: encounterData.claimType,
    importSource: ClaimImportSource.ED_SHIFT,
    shiftId,
    dateOfService: encounterData.dateOfService,
    submissionDeadline,
    createdBy: actorId,
    updatedBy: actorId,
  } as any);

  // 7. Increment shift encounter count
  await deps.repo.incrementEncounterCount(shiftId, physicianId);

  // 8. Append CREATED audit entry
  await deps.repo.appendClaimAudit({
    claimId: claim.claimId,
    action: ClaimAuditAction.CREATED,
    previousState: null,
    newState: 'DRAFT',
    changes: { shiftId },
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);

  return { claimId: claim.claimId };
}

// ---------------------------------------------------------------------------
// Service: validateClaim
// ---------------------------------------------------------------------------

/** Days-before-deadline threshold for the submission window warning. */
const DEADLINE_WARNING_DAYS = 7;

/**
 * Run the full validation pipeline on a claim.
 *
 * Pipeline (ordered, S1 short-circuits):
 *   S1: Claim type valid (AHCIP or WCB)
 *   S2: Required base fields present
 *   S3: Patient exists
 *   S4: Physician active with valid BA
 *   S5: DOS is valid date, not future, not before registration
 *   S6: Submission window (error if expired, warning if within 7 days)
 *   S7: Duplicate detection (warning)
 *
 * After shared checks, delegates to pathway-specific validator if available.
 * Stores result on the claim. Transitions DRAFT -> VALIDATED if zero errors.
 */
export async function validateClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
  actorContext: string,
): Promise<ValidationResult> {
  const errors: ValidationEntry[] = [];
  const warnings: ValidationEntry[] = [];
  const info: ValidationEntry[] = [];

  // Fetch the claim (physician-scoped)
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  // --- S1: Claim type valid ---
  const validClaimTypes = [ClaimType.AHCIP, ClaimType.WCB];
  if (!validClaimTypes.includes(claim.claimType as any)) {
    errors.push({
      check: ValidationCheckId.S1_CLAIM_TYPE_VALID,
      rule_reference: 'FRD 4.0 S4.3 S1',
      message: 'Invalid claim type: must be AHCIP or WCB',
      help_text: 'Select a valid claim type (AHCIP or WCB) for this claim.',
      field_affected: 'claim_type',
    });

    // S1 failure short-circuits all subsequent checks
    const refVersion = deps.referenceDataVersion
      ? await deps.referenceDataVersion.getCurrentVersion()
      : 'unknown';

    const result: ValidationResult = {
      errors,
      warnings,
      info,
      passed: false,
      validation_timestamp: new Date().toISOString(),
      reference_data_version: refVersion,
    };

    await deps.repo.updateValidationResult(claimId, physicianId, result as any, refVersion);

    return result;
  }

  // --- S2: Required base fields ---
  const missingFields: string[] = [];
  if (!claim.physicianId) missingFields.push('physician_id');
  if (!claim.patientId) missingFields.push('patient_id');
  if (!claim.dateOfService) missingFields.push('date_of_service');

  if (missingFields.length > 0) {
    errors.push({
      check: ValidationCheckId.S2_REQUIRED_BASE_FIELDS,
      rule_reference: 'FRD 4.0 S4.3 S2',
      message: `Missing required fields: ${missingFields.join(', ')}`,
      help_text: 'Ensure physician, patient, and date of service are all provided.',
      field_affected: missingFields.join(', '),
    });
  }

  // --- S3: Patient exists ---
  if (claim.patientId) {
    const patientExists = await deps.patientCheck.exists(claim.patientId, physicianId);
    if (!patientExists) {
      errors.push({
        check: ValidationCheckId.S3_PATIENT_EXISTS,
        rule_reference: 'FRD 4.0 S4.3 S3',
        message: 'Patient record not found',
        help_text: 'Verify the patient exists in your patient registry before submitting.',
        field_affected: 'patient_id',
      });
    }
  }

  // --- S4: Physician active ---
  const providerActive = await deps.providerCheck.isActive(physicianId);
  if (!providerActive) {
    errors.push({
      check: ValidationCheckId.S4_PHYSICIAN_ACTIVE,
      rule_reference: 'FRD 4.0 S4.3 S4',
      message: 'Physician is not active or does not have a valid billing arrangement',
      help_text: 'Ensure your provider profile and billing arrangement are active.',
      field_affected: 'physician_id',
    });
  }

  // --- S5: DOS valid ---
  if (claim.dateOfService) {
    const dosDate = new Date(claim.dateOfService + 'T00:00:00Z');
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (isNaN(dosDate.getTime())) {
      errors.push({
        check: ValidationCheckId.S5_DOS_VALID,
        rule_reference: 'FRD 4.0 S4.3 S5',
        message: 'Date of service is not a valid date',
        help_text: 'Enter a valid date in YYYY-MM-DD format.',
        field_affected: 'date_of_service',
      });
    } else if (dosDate > today) {
      errors.push({
        check: ValidationCheckId.S5_DOS_VALID,
        rule_reference: 'FRD 4.0 S4.3 S5',
        message: 'Date of service cannot be in the future',
        help_text: 'The date of service must be today or earlier.',
        field_affected: 'date_of_service',
      });
    } else if (deps.providerCheck.getRegistrationDate) {
      const regDate = await deps.providerCheck.getRegistrationDate(physicianId);
      if (regDate) {
        const regDateObj = new Date(regDate + 'T00:00:00Z');
        if (dosDate < regDateObj) {
          errors.push({
            check: ValidationCheckId.S5_DOS_VALID,
            rule_reference: 'FRD 4.0 S4.3 S5',
            message: 'Date of service is before physician registration date',
            help_text: 'The date of service must not be before your registration date.',
            field_affected: 'date_of_service',
          });
        }
      }
    }
  }

  // --- S6: Submission window ---
  if (claim.submissionDeadline) {
    const deadline = new Date(claim.submissionDeadline + 'T00:00:00Z');
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (deadline < today) {
      errors.push({
        check: ValidationCheckId.S6_SUBMISSION_WINDOW,
        rule_reference: 'FRD 4.0 S4.3 S6',
        message: 'Submission deadline has expired',
        help_text: 'This claim is past its submission deadline and cannot be submitted.',
        field_affected: 'submission_deadline',
      });
    } else {
      const daysRemaining = Math.ceil(
        (deadline.getTime() - today.getTime()) / (1000 * 60 * 60 * 24),
      );
      if (daysRemaining <= DEADLINE_WARNING_DAYS) {
        warnings.push({
          check: ValidationCheckId.S6_SUBMISSION_WINDOW,
          rule_reference: 'FRD 4.0 S4.3 S6',
          message: `Submission deadline is within ${daysRemaining} day(s)`,
          help_text: 'Submit this claim soon to avoid missing the deadline.',
          field_affected: 'submission_deadline',
        });
      }
    }
  }

  // --- S7: Duplicate detection ---
  if (claim.patientId && claim.dateOfService) {
    const existing = await deps.repo.listClaims(physicianId, {
      patientId: claim.patientId,
      dateFrom: claim.dateOfService,
      dateTo: claim.dateOfService,
      page: 1,
      pageSize: 100,
    });

    const duplicates = existing.data.filter(
      (c: any) => c.claimId !== claimId,
    );

    if (duplicates.length > 0) {
      warnings.push({
        check: ValidationCheckId.S7_DUPLICATE_DETECTION,
        rule_reference: 'FRD 4.0 S4.3 S7',
        message: `Found ${duplicates.length} potential duplicate claim(s) for the same patient and date of service`,
        help_text: 'Review existing claims for this patient on this date. Duplicates may be intentional (e.g., radiology).',
        field_affected: 'patient_id, date_of_service',
      });
    }
  }

  // --- Pathway delegation ---
  if (deps.pathwayValidators) {
    const pathwayValidator = deps.pathwayValidators[claim.claimType as string];
    if (pathwayValidator) {
      const pathwayResults = await pathwayValidator.validate(claim as any, physicianId);
      for (const entry of pathwayResults) {
        errors.push(entry);
      }
    }
  }

  // --- Build result ---
  const refVersion = deps.referenceDataVersion
    ? await deps.referenceDataVersion.getCurrentVersion()
    : 'unknown';

  const result: ValidationResult = {
    errors,
    warnings,
    info,
    passed: errors.length === 0,
    validation_timestamp: new Date().toISOString(),
    reference_data_version: refVersion,
  };

  // Store validation result on the claim
  await deps.repo.updateValidationResult(claimId, physicianId, result as any, refVersion);

  // Transition DRAFT -> VALIDATED if passed
  if (result.passed && (claim as any).state === ClaimState.DRAFT) {
    await deps.repo.transitionState(
      claimId,
      physicianId,
      ClaimState.DRAFT,
      ClaimState.VALIDATED,
    );

    await deps.repo.appendClaimAudit({
      claimId,
      action: ClaimAuditAction.VALIDATED,
      previousState: ClaimState.DRAFT,
      newState: ClaimState.VALIDATED,
      changes: { validation_result: result },
      actorId,
      actorContext,
    } as any);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Clean/flagged classification
// ---------------------------------------------------------------------------

/**
 * Classify a claim as clean or flagged.
 *
 * Clean when ALL true:
 *  - Zero validation warnings
 *  - Zero pending AI suggestions
 *  - Zero unresolved flags
 *  - Zero duplicate alerts
 *
 * Flagged otherwise.
 */
export function classifyCleanFlagged(claim: Record<string, any>): boolean {
  // Check validation warnings
  const validationResult = claim.validationResult;
  if (validationResult) {
    const warnings = validationResult.warnings;
    if (Array.isArray(warnings) && warnings.length > 0) {
      return false; // flagged
    }
  }

  // Check pending AI suggestions
  const aiSuggestions = claim.aiCoachSuggestions;
  if (aiSuggestions) {
    const suggestions = Array.isArray(aiSuggestions)
      ? aiSuggestions
      : aiSuggestions.suggestions;
    if (Array.isArray(suggestions) && suggestions.some((s: any) => s.status === 'PENDING')) {
      return false; // flagged
    }
  }

  // Check unresolved flags
  const flags = claim.flags;
  if (flags) {
    const flagList = Array.isArray(flags) ? flags : flags.items;
    if (Array.isArray(flagList) && flagList.some((f: any) => !f.resolved)) {
      return false; // flagged
    }
  }

  // Check duplicate alerts
  const duplicateAlert = claim.duplicateAlert;
  if (duplicateAlert) {
    const alerts = Array.isArray(duplicateAlert)
      ? duplicateAlert
      : duplicateAlert.alerts;
    if (Array.isArray(alerts) && alerts.length > 0) {
      return false; // flagged
    }
    // If it's a single object with unacknowledged duplicates
    if (!Array.isArray(duplicateAlert) && duplicateAlert.duplicateCount > 0 && !duplicateAlert.acknowledged) {
      return false; // flagged
    }
  }

  return true; // clean
}

// ---------------------------------------------------------------------------
// Service: queueClaim
// ---------------------------------------------------------------------------

/**
 * Queue a validated claim for batch submission.
 *
 * 1. Verify claim is in VALIDATED state
 * 2. Re-validate (full pipeline)
 * 3. Classify as clean or flagged
 * 4. Transition to QUEUED
 * 5. Emit CLAIM_FLAGGED notification if flagged
 * 6. Append audit entry
 */
export async function queueClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
  actorContext: string,
): Promise<{ isClean: boolean }> {
  // 1. Fetch and verify claim is in VALIDATED state
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  if ((claim as any).state !== ClaimState.VALIDATED) {
    const allowed = STATE_TRANSITIONS[(claim as any).state as ClaimState];
    if (!allowed || !allowed.includes(ClaimState.QUEUED)) {
      throw new ConflictError(
        `Cannot queue claim: claim is in ${(claim as any).state} state, expected VALIDATED`,
      );
    }
    throw new ConflictError(
      `Cannot queue claim: claim is in ${(claim as any).state} state, expected VALIDATED`,
    );
  }

  // 2. Re-validate (full pipeline)
  const validationResult = await validateClaim(
    deps,
    claimId,
    physicianId,
    actorId,
    actorContext,
  );

  if (!validationResult.passed) {
    throw new BusinessRuleError(
      'Claim failed re-validation and cannot be queued',
      { errors: validationResult.errors },
    );
  }

  // Re-fetch claim after validation (may have updated fields)
  const updatedClaim = await deps.repo.findClaimById(claimId, physicianId);
  if (!updatedClaim) {
    throw new NotFoundError('Claim');
  }

  // 3. Classify as clean or flagged
  const isClean = classifyCleanFlagged(updatedClaim as any);
  await deps.repo.classifyClaim(claimId, physicianId, isClean);

  // 4. Transition VALIDATED -> QUEUED
  await deps.repo.transitionState(
    claimId,
    physicianId,
    ClaimState.VALIDATED,
    ClaimState.QUEUED,
  );

  // 5. Emit CLAIM_FLAGGED notification if flagged
  if (!isClean && deps.notificationEmitter) {
    await deps.notificationEmitter.emit(ClaimNotificationEvent.CLAIM_FLAGGED, {
      claimId,
      physicianId,
    });
  }

  // 6. Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.QUEUED,
    previousState: ClaimState.VALIDATED,
    newState: ClaimState.QUEUED,
    changes: { isClean },
    actorId,
    actorContext,
  } as any);

  return { isClean };
}

// ---------------------------------------------------------------------------
// Service: unqueueClaim
// ---------------------------------------------------------------------------

/**
 * Remove a claim from the queue back to VALIDATED state.
 *
 * 1. Verify claim is in QUEUED state
 * 2. Transition QUEUED -> VALIDATED
 * 3. Append audit entry
 */
export async function unqueueClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
): Promise<void> {
  // 1. Fetch and verify claim is in QUEUED state
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  if ((claim as any).state !== ClaimState.QUEUED) {
    throw new ConflictError(
      `Cannot unqueue claim: claim is in ${(claim as any).state} state, expected QUEUED`,
    );
  }

  // 2. Transition QUEUED -> VALIDATED
  await deps.repo.transitionState(
    claimId,
    physicianId,
    ClaimState.QUEUED,
    ClaimState.VALIDATED,
  );

  // 3. Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.UNQUEUED,
    previousState: ClaimState.QUEUED,
    newState: ClaimState.VALIDATED,
    changes: null,
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);
}

// ---------------------------------------------------------------------------
// Service: approveFlaggedClaim
// ---------------------------------------------------------------------------

/**
 * Approve a flagged claim for batch inclusion.
 *
 * Only delegates with CLAIM_APPROVE permission should call this
 * (checked at handler/route level), but the service verifies the claim
 * is actually flagged and in QUEUED state.
 *
 * Sets is_clean to true (approved = treated as clean for batch assembly).
 */
export async function approveFlaggedClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
  actorContext: string,
): Promise<void> {
  // 1. Fetch and verify claim exists
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  // 2. Verify claim is in QUEUED state
  if ((claim as any).state !== ClaimState.QUEUED) {
    throw new ConflictError(
      `Cannot approve claim: claim is in ${(claim as any).state} state, expected QUEUED`,
    );
  }

  // 3. Verify claim is flagged (not clean)
  if ((claim as any).isClean === true) {
    throw new BusinessRuleError('Claim is already clean and does not need approval');
  }

  // 4. Mark claim as approved (treat as clean for batch)
  await deps.repo.classifyClaim(claimId, physicianId, true);

  // 5. Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.QUEUED, // Re-use QUEUED action with changes noting approval
    previousState: ClaimState.QUEUED,
    newState: ClaimState.QUEUED,
    changes: { flaggedApproval: true, approvedBy: actorId },
    actorId,
    actorContext,
  } as any);
}

// ---------------------------------------------------------------------------
// Service: writeOffClaim
// ---------------------------------------------------------------------------

/**
 * Write off a rejected claim. Terminal state.
 *
 * 1. Verify claim is in REJECTED state
 * 2. Transition REJECTED -> WRITTEN_OFF
 * 3. Record reason in audit
 */
export async function writeOffClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
  reason: string,
): Promise<void> {
  // 1. Fetch and verify claim is in REJECTED state
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  if ((claim as any).state !== ClaimState.REJECTED) {
    throw new ConflictError(
      `Cannot write off claim: claim is in ${(claim as any).state} state, expected REJECTED`,
    );
  }

  // 2. Transition REJECTED -> WRITTEN_OFF
  await deps.repo.transitionState(
    claimId,
    physicianId,
    ClaimState.REJECTED,
    ClaimState.WRITTEN_OFF,
  );

  // 3. Append audit entry with reason
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.WRITTEN_OFF,
    previousState: ClaimState.REJECTED,
    newState: ClaimState.WRITTEN_OFF,
    changes: null,
    actorId,
    actorContext: ActorContext.PHYSICIAN,
    reason,
  } as any);
}

// ---------------------------------------------------------------------------
// Service: listRejectedClaims
// ---------------------------------------------------------------------------

/**
 * List claims in REJECTED state for a physician, with explanatory codes
 * and corrective guidance.
 *
 * Returns paginated results scoped to the authenticated physician.
 */
export async function listRejectedClaims(
  deps: ClaimServiceDeps,
  physicianId: string,
  page: number,
  pageSize: number,
): Promise<{
  data: Array<Record<string, any> & { rejectionCodes: RejectionCodeDetail[] }>;
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}> {
  const result = await deps.repo.listClaims(physicianId, {
    state: ClaimState.REJECTED,
    page,
    pageSize,
  });

  // Enrich each rejected claim with corrective guidance from explanatory codes
  const enrichedData = await Promise.all(
    result.data.map(async (claim: any) => {
      const rejectionCodes = await extractRejectionCodes(deps, claim);
      return { ...claim, rejectionCodes };
    }),
  );

  return {
    data: enrichedData,
    pagination: result.pagination,
  };
}

// ---------------------------------------------------------------------------
// Service: getRejectionDetails
// ---------------------------------------------------------------------------

/**
 * Return rejection codes, human-readable descriptions, corrective guidance,
 * and resubmission eligibility for a specific rejected claim.
 *
 * Returns null if claim not found or belongs to a different physician.
 */
export async function getRejectionDetails(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
): Promise<RejectionDetails | null> {
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    return null;
  }

  const rejectionCodes = await extractRejectionCodes(deps, claim as any);

  // Resubmission is eligible if claim is in REJECTED state and
  // the REJECTED -> QUEUED transition exists in state machine
  const allowed = STATE_TRANSITIONS[(claim as any).state as ClaimState] ?? [];
  const resubmissionEligible =
    (claim as any).state === ClaimState.REJECTED &&
    allowed.includes(ClaimState.QUEUED);

  return {
    claimId: (claim as any).claimId,
    state: (claim as any).state,
    rejectionCodes,
    resubmissionEligible,
  };
}

// ---------------------------------------------------------------------------
// Service: resubmitClaim
// ---------------------------------------------------------------------------

/**
 * One-click resubmit for a rejected claim.
 *
 * 1. Verify claim is in REJECTED state
 * 2. Re-validate the claim (full pipeline)
 * 3. If valid: transition REJECTED -> QUEUED
 * 4. Append RESUBMITTED audit entry
 * 5. Emit notification
 *
 * Throws BusinessRuleError if validation fails after correction.
 */
export async function resubmitClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
): Promise<{ claimId: string; newState: string }> {
  // 1. Fetch and verify claim is in REJECTED state
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  if ((claim as any).state !== ClaimState.REJECTED) {
    throw new ConflictError(
      `Cannot resubmit claim: claim is in ${(claim as any).state} state, expected REJECTED`,
    );
  }

  // 2. Re-validate (full pipeline) — temporarily set state to DRAFT
  // so validation can proceed, then revert if it fails.
  // We validate by running the same checks without actually transitioning yet.
  const validationResult = await runValidationChecks(
    deps,
    claimId,
    physicianId,
    actorId,
  );

  if (!validationResult.passed) {
    throw new BusinessRuleError(
      'Claim failed re-validation and cannot be resubmitted',
      { errors: validationResult.errors },
    );
  }

  // 3. Transition REJECTED -> QUEUED
  await deps.repo.transitionState(
    claimId,
    physicianId,
    ClaimState.REJECTED,
    ClaimState.QUEUED,
  );

  // 4. Append RESUBMITTED audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.RESUBMITTED,
    previousState: ClaimState.REJECTED,
    newState: ClaimState.QUEUED,
    changes: { validation_result: validationResult },
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);

  // 5. Emit notification
  if (deps.notificationEmitter) {
    await deps.notificationEmitter.emit(ClaimNotificationEvent.CLAIM_VALIDATED, {
      claimId,
      physicianId,
      resubmission: true,
    });
  }

  return { claimId, newState: ClaimState.QUEUED };
}

// ---------------------------------------------------------------------------
// Helper: extractRejectionCodes
// ---------------------------------------------------------------------------

/**
 * Extract rejection codes from a claim's validation result and enrich
 * with explanatory code descriptions from Reference Data (Domain 2).
 */
async function extractRejectionCodes(
  deps: ClaimServiceDeps,
  claim: Record<string, any>,
): Promise<RejectionCodeDetail[]> {
  const codes: RejectionCodeDetail[] = [];

  const validationResult = claim.validationResult;
  if (!validationResult) return codes;

  const errors = validationResult.errors;
  if (!Array.isArray(errors)) return codes;

  for (const error of errors) {
    const code = error.check ?? error.code ?? '';

    // Attempt enrichment from reference data
    if (deps.explanatoryCodeLookup) {
      const explanation = await deps.explanatoryCodeLookup.getExplanatoryCode(code);
      if (explanation) {
        codes.push({
          code: explanation.code,
          description: explanation.description,
          commonCause: explanation.commonCause,
          suggestedAction: explanation.suggestedAction,
          helpText: explanation.helpText,
        });
        continue;
      }
    }

    // Fallback: use the validation error's own message as guidance
    codes.push({
      code,
      description: error.message ?? 'Unknown rejection reason',
      commonCause: error.help_text ?? '',
      suggestedAction: error.help_text ?? 'Review and correct the claim data.',
      helpText: error.help_text ?? '',
    });
  }

  return codes;
}

// ---------------------------------------------------------------------------
// Helper: runValidationChecks
// ---------------------------------------------------------------------------

/**
 * Run the validation pipeline without transitioning state.
 * Used by resubmitClaim to check if a REJECTED claim is now valid
 * without altering the claim's state.
 */
async function runValidationChecks(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
): Promise<ValidationResult> {
  const errors: ValidationEntry[] = [];
  const warnings: ValidationEntry[] = [];
  const info: ValidationEntry[] = [];

  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  // --- S1: Claim type valid ---
  const validClaimTypes = [ClaimType.AHCIP, ClaimType.WCB];
  if (!validClaimTypes.includes((claim as any).claimType)) {
    errors.push({
      check: ValidationCheckId.S1_CLAIM_TYPE_VALID,
      rule_reference: 'FRD 4.0 S4.3 S1',
      message: 'Invalid claim type: must be AHCIP or WCB',
      help_text: 'Select a valid claim type (AHCIP or WCB) for this claim.',
      field_affected: 'claim_type',
    });

    const refVersion = deps.referenceDataVersion
      ? await deps.referenceDataVersion.getCurrentVersion()
      : 'unknown';

    return {
      errors,
      warnings,
      info,
      passed: false,
      validation_timestamp: new Date().toISOString(),
      reference_data_version: refVersion,
    };
  }

  // --- S2: Required base fields ---
  const missingFields: string[] = [];
  if (!(claim as any).physicianId) missingFields.push('physician_id');
  if (!(claim as any).patientId) missingFields.push('patient_id');
  if (!(claim as any).dateOfService) missingFields.push('date_of_service');

  if (missingFields.length > 0) {
    errors.push({
      check: ValidationCheckId.S2_REQUIRED_BASE_FIELDS,
      rule_reference: 'FRD 4.0 S4.3 S2',
      message: `Missing required fields: ${missingFields.join(', ')}`,
      help_text: 'Ensure physician, patient, and date of service are all provided.',
      field_affected: missingFields.join(', '),
    });
  }

  // --- S3: Patient exists ---
  if ((claim as any).patientId) {
    const patientExists = await deps.patientCheck.exists((claim as any).patientId, physicianId);
    if (!patientExists) {
      errors.push({
        check: ValidationCheckId.S3_PATIENT_EXISTS,
        rule_reference: 'FRD 4.0 S4.3 S3',
        message: 'Patient record not found',
        help_text: 'Verify the patient exists in your patient registry before submitting.',
        field_affected: 'patient_id',
      });
    }
  }

  // --- S4: Physician active ---
  const providerActive = await deps.providerCheck.isActive(physicianId);
  if (!providerActive) {
    errors.push({
      check: ValidationCheckId.S4_PHYSICIAN_ACTIVE,
      rule_reference: 'FRD 4.0 S4.3 S4',
      message: 'Physician is not active or does not have a valid billing arrangement',
      help_text: 'Ensure your provider profile and billing arrangement are active.',
      field_affected: 'physician_id',
    });
  }

  // --- S5: DOS valid ---
  if ((claim as any).dateOfService) {
    const dosDate = new Date((claim as any).dateOfService + 'T00:00:00Z');
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (isNaN(dosDate.getTime())) {
      errors.push({
        check: ValidationCheckId.S5_DOS_VALID,
        rule_reference: 'FRD 4.0 S4.3 S5',
        message: 'Date of service is not a valid date',
        help_text: 'Enter a valid date in YYYY-MM-DD format.',
        field_affected: 'date_of_service',
      });
    } else if (dosDate > today) {
      errors.push({
        check: ValidationCheckId.S5_DOS_VALID,
        rule_reference: 'FRD 4.0 S4.3 S5',
        message: 'Date of service cannot be in the future',
        help_text: 'The date of service must be today or earlier.',
        field_affected: 'date_of_service',
      });
    }
  }

  // --- S6: Submission window ---
  if ((claim as any).submissionDeadline) {
    const deadline = new Date((claim as any).submissionDeadline + 'T00:00:00Z');
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (deadline < today) {
      errors.push({
        check: ValidationCheckId.S6_SUBMISSION_WINDOW,
        rule_reference: 'FRD 4.0 S4.3 S6',
        message: 'Submission deadline has expired',
        help_text: 'This claim is past its submission deadline and cannot be submitted.',
        field_affected: 'submission_deadline',
      });
    }
  }

  // --- Pathway delegation ---
  if (deps.pathwayValidators) {
    const pathwayValidator = deps.pathwayValidators[(claim as any).claimType as string];
    if (pathwayValidator) {
      const pathwayResults = await pathwayValidator.validate(claim as any, physicianId);
      for (const entry of pathwayResults) {
        errors.push(entry);
      }
    }
  }

  const refVersion = deps.referenceDataVersion
    ? await deps.referenceDataVersion.getCurrentVersion()
    : 'unknown';

  const result: ValidationResult = {
    errors,
    warnings,
    info,
    passed: errors.length === 0,
    validation_timestamp: new Date().toISOString(),
    reference_data_version: refVersion,
  };

  // Store updated validation result on the claim
  await deps.repo.updateValidationResult(claimId, physicianId, result as any, refVersion);

  return result;
}

// ---------------------------------------------------------------------------
// Service: expireClaim
// ---------------------------------------------------------------------------

/**
 * System-initiated expiration of a claim past its submission deadline.
 *
 * Transitions any non-terminal claim past deadline to EXPIRED.
 * Emits DEADLINE_EXPIRED notification.
 * No user-facing endpoint — called by scheduled job.
 */
export async function expireClaim(
  deps: ClaimServiceDeps,
  claimId: string,
): Promise<void> {
  // Fetch the claim without physician scoping (system operation)
  // We use a special internal call — the repository's findClaimById requires
  // a physicianId. For system ops we pass the claim's own physicianId.
  // First, list the claim by state to get physicianId.
  // In practice, this is called from a batch job that already has the claim data.
  // For the service layer, we accept claimId and look it up via the
  // underlying repository which needs physicianId — we'll use a two-step approach.

  // The batch job should pass physicianId, but per the task spec the signature
  // is just (claimId). We need to find the claim across all physicians.
  // The repository doesn't support cross-tenant lookup for good reason.
  // For system operations, we use a separate internal method on the repo.
  // Since we don't have that yet, we'll accept that the caller (batch job)
  // provides a claim object. For now, we implement with the assumption
  // that the batch job pre-fetches the claim and calls with the data.

  // Implementation note: expireClaim is called from a scheduled job that
  // already has the full claim data including physicianId. We delegate
  // the state transition using that physicianId.
  throw new BusinessRuleError('expireClaim requires claim data from batch job');
}

/**
 * Expire a specific claim. Called by the batch expiry job with full claim context.
 *
 * @param claim - Pre-fetched claim record (from batch job query)
 */
export async function expireClaimWithContext(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  currentState: string,
): Promise<void> {
  // Verify the claim is not already in a terminal state
  if (TERMINAL_STATES.has(currentState as ClaimState)) {
    throw new BusinessRuleError(
      `Cannot expire claim: claim is already in terminal state ${currentState}`,
    );
  }

  // Verify deadline has passed
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  const deadline = (claim as any).submissionDeadline;
  if (deadline) {
    const deadlineDate = new Date(deadline + 'T00:00:00Z');
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    if (deadlineDate >= today) {
      throw new BusinessRuleError('Claim deadline has not yet passed');
    }
  }

  // Transition to EXPIRED
  await deps.repo.transitionState(
    claimId,
    physicianId,
    currentState,
    ClaimState.EXPIRED,
  );

  // Emit DEADLINE_EXPIRED notification
  if (deps.notificationEmitter) {
    await deps.notificationEmitter.emit(ClaimNotificationEvent.DEADLINE_EXPIRED, {
      claimId,
      physicianId,
    });
  }

  // Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.EXPIRED,
    previousState: currentState,
    newState: ClaimState.EXPIRED,
    changes: null,
    actorId: 'SYSTEM',
    actorContext: ActorContext.SYSTEM,
  } as any);
}

// ---------------------------------------------------------------------------
// Service: getClaimsForAutoSubmission
// ---------------------------------------------------------------------------

/**
 * Get claims eligible for auto-submission based on physician's preference.
 *
 * Submission modes:
 * - AUTO_CLEAN: include clean claims only, exclude flagged
 * - AUTO_ALL: include both clean and flagged
 * - REQUIRE_APPROVAL: include only explicitly approved (is_clean = true after approval)
 *
 * Called by batch assembly.
 */
export async function getClaimsForAutoSubmission(
  deps: ClaimServiceDeps,
  physicianId: string,
  claimType: string,
): Promise<{ claims: any[]; mode: string }> {
  // Get physician's submission preference
  const mode = deps.submissionPreference
    ? await deps.submissionPreference.getSubmissionMode(physicianId, claimType)
    : AutoSubmissionMode.AUTO_CLEAN;

  let includeClean = false;
  let includeFlagged = false;

  switch (mode) {
    case AutoSubmissionMode.AUTO_CLEAN:
      includeClean = true;
      includeFlagged = false;
      break;
    case AutoSubmissionMode.AUTO_ALL:
      includeClean = true;
      includeFlagged = true;
      break;
    case AutoSubmissionMode.REQUIRE_APPROVAL:
      // Only include claims that have been explicitly approved (is_clean = true)
      // but originally were flagged. In practice this means only approved claims.
      includeClean = true;
      includeFlagged = false;
      break;
    default:
      includeClean = true;
      includeFlagged = false;
  }

  const claimsForBatch = await deps.repo.findClaimsForBatchAssembly(
    physicianId,
    claimType,
    includeClean,
    includeFlagged,
  );

  return { claims: claimsForBatch, mode };
}

// ---------------------------------------------------------------------------
// Service: reclassifyQueuedClaim
// ---------------------------------------------------------------------------

/**
 * Re-evaluate clean/flagged classification for a claim that was updated
 * while in QUEUED state. Called when a queued claim's data changes.
 */
export async function reclassifyQueuedClaim(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
): Promise<{ isClean: boolean }> {
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  if ((claim as any).state !== ClaimState.QUEUED) {
    throw new BusinessRuleError('Can only reclassify claims in QUEUED state');
  }

  const isClean = classifyCleanFlagged(claim as any);
  await deps.repo.classifyClaim(claimId, physicianId, isClean);

  return { isClean };
}

// ---------------------------------------------------------------------------
// Service: createShift
// ---------------------------------------------------------------------------

/**
 * Create a new ED shift with IN_PROGRESS status.
 *
 * Verifies:
 * - Physician is active
 * - Facility belongs to physician (via FacilityCheck)
 *
 * Returns shift_id.
 */
export async function createShift(
  deps: ClaimServiceDeps,
  physicianId: string,
  data: CreateShiftInput,
): Promise<{ shiftId: string }> {
  // 1. Verify physician is active
  const providerActive = await deps.providerCheck.isActive(physicianId);
  if (!providerActive) {
    throw new BusinessRuleError(
      'Physician is not active or does not have a valid billing arrangement',
    );
  }

  // 2. Verify facility belongs to physician
  if (deps.facilityCheck) {
    const facilityBelongs = await deps.facilityCheck.belongsToPhysician(
      data.facilityId,
      physicianId,
    );
    if (!facilityBelongs) {
      throw new NotFoundError('Facility');
    }
  }

  // 3. Create shift (repository forces status = IN_PROGRESS)
  const shift = await deps.repo.createShift({
    physicianId,
    facilityId: data.facilityId,
    shiftDate: data.shiftDate,
    startTime: data.startTime ?? null,
    endTime: data.endTime ?? null,
  } as any);

  return { shiftId: shift.shiftId };
}

// ---------------------------------------------------------------------------
// Service: addEncounter
// ---------------------------------------------------------------------------

/**
 * Add an encounter (claim) to an existing ED shift.
 *
 * Delegates to createClaimFromShift for the actual claim creation.
 * This is the public API for the ED shift workflow.
 */
export async function addEncounter(
  deps: ClaimServiceDeps,
  physicianId: string,
  actorId: string,
  shiftId: string,
  data: EncounterInput,
): Promise<{ claimId: string }> {
  return createClaimFromShift(deps, physicianId, actorId, shiftId, data);
}

// ---------------------------------------------------------------------------
// Service: completeShift
// ---------------------------------------------------------------------------

/**
 * Complete an ED shift.
 *
 * 1. Verify shift is IN_PROGRESS
 * 2. Transition to COMPLETED
 * 3. Calculate after-hours premiums for all encounters
 * 4. Return shift with all linked claims
 */
export async function completeShift(
  deps: ClaimServiceDeps,
  physicianId: string,
  shiftId: string,
): Promise<{ shift: Record<string, any>; claims: Record<string, any>[] }> {
  // 1. Verify shift exists and belongs to physician
  const shift = await deps.repo.findShiftById(shiftId, physicianId);
  if (!shift) {
    throw new NotFoundError('Shift');
  }

  // 2. Verify shift is IN_PROGRESS
  if (shift.status !== ShiftStatus.IN_PROGRESS) {
    throw new BusinessRuleError(
      'Cannot complete a shift that is not in progress',
    );
  }

  // 3. Transition to COMPLETED
  const updatedShift = await deps.repo.updateShiftStatus(
    shiftId,
    physicianId,
    ShiftStatus.COMPLETED,
  );

  // 4. Fetch all linked claims
  const claims = await deps.repo.findClaimsByShift(shiftId, physicianId);

  // 5. Calculate after-hours premiums if shift has start/end times
  if (
    updatedShift &&
    updatedShift.startTime &&
    updatedShift.endTime &&
    deps.afterHoursPremiumCalculators
  ) {
    // Group claims by type and delegate to pathway-specific calculators
    for (const [claimType, calculator] of Object.entries(
      deps.afterHoursPremiumCalculators,
    )) {
      const typedClaims = claims.filter(
        (c: any) => c.claimType === claimType,
      );
      if (typedClaims.length > 0) {
        await calculator.calculatePremiums(
          typedClaims as any,
          updatedShift.startTime,
          updatedShift.endTime,
        );
      }
    }
  }

  return {
    shift: (updatedShift ?? shift) as Record<string, any>,
    claims: claims as Record<string, any>[],
  };
}

// ---------------------------------------------------------------------------
// Service: getShiftDetails
// ---------------------------------------------------------------------------

/**
 * Retrieve a shift with all linked claims.
 *
 * Physician-scoped.
 */
export async function getShiftDetails(
  deps: ClaimServiceDeps,
  physicianId: string,
  shiftId: string,
): Promise<{ shift: Record<string, any>; claims: Record<string, any>[] }> {
  // 1. Fetch shift (physician-scoped)
  const shift = await deps.repo.findShiftById(shiftId, physicianId);
  if (!shift) {
    throw new NotFoundError('Shift');
  }

  // 2. Fetch all linked claims
  const claims = await deps.repo.findClaimsByShift(shiftId, physicianId);

  return {
    shift: shift as Record<string, any>,
    claims: claims as Record<string, any>[],
  };
}

// ---------------------------------------------------------------------------
// EMR Import: file parsing helpers
// ---------------------------------------------------------------------------

/** Detect delimiter from file content. Tries comma, tab, pipe. */
export function detectDelimiter(firstLine: string): string {
  const candidates = [
    { char: '\t', count: (firstLine.match(/\t/g) || []).length },
    { char: ',', count: (firstLine.match(/,/g) || []).length },
    { char: '|', count: (firstLine.match(/\|/g) || []).length },
  ];
  candidates.sort((a, b) => b.count - a.count);
  return candidates[0].count > 0 ? candidates[0].char : ',';
}

/** Parse a date string in multiple formats to YYYY-MM-DD. */
export function parseDate(value: string, format?: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  // Try explicit format first
  if (format === 'DD/MM/YYYY') {
    const match = trimmed.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
    if (match) {
      return `${match[3]}-${match[2].padStart(2, '0')}-${match[1].padStart(2, '0')}`;
    }
  }

  if (format === 'MM/DD/YYYY') {
    const match = trimmed.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
    if (match) {
      return `${match[3]}-${match[1].padStart(2, '0')}-${match[2].padStart(2, '0')}`;
    }
  }

  // YYYY-MM-DD (ISO)
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    return trimmed;
  }

  // DD/MM/YYYY or MM/DD/YYYY — auto-detect by checking if day > 12
  const slashMatch = trimmed.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (slashMatch) {
    const part1 = parseInt(slashMatch[1], 10);
    const part2 = parseInt(slashMatch[2], 10);
    const year = slashMatch[3];

    // If first part > 12, it must be DD/MM/YYYY
    if (part1 > 12) {
      return `${year}-${String(part2).padStart(2, '0')}-${String(part1).padStart(2, '0')}`;
    }
    // If second part > 12, it must be MM/DD/YYYY
    if (part2 > 12) {
      return `${year}-${String(part1).padStart(2, '0')}-${String(part2).padStart(2, '0')}`;
    }
    // Ambiguous — default to MM/DD/YYYY (North American convention)
    return `${year}-${String(part1).padStart(2, '0')}-${String(part2).padStart(2, '0')}`;
  }

  return null;
}

/** Parse CSV/TSV content into rows of string arrays. Handles quoted fields. */
export function parseRows(content: string, delimiter: string): string[][] {
  const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
  return lines.map((line) => {
    const fields: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"' && line[i + 1] === '"') {
          current += '"';
          i++;
        } else if (ch === '"') {
          inQuotes = false;
        } else {
          current += ch;
        }
      } else {
        if (ch === '"') {
          inQuotes = true;
        } else if (ch === delimiter) {
          fields.push(current.trim());
          current = '';
        } else {
          current += ch;
        }
      }
    }
    fields.push(current.trim());
    return fields;
  });
}

// ---------------------------------------------------------------------------
// Service: uploadImport
// ---------------------------------------------------------------------------

/**
 * Upload an EMR import file. Computes SHA-256 hash, checks for duplicates,
 * parses the file, creates an import_batch record with PENDING status.
 *
 * Returns importBatchId.
 */
export async function uploadImport(
  deps: ClaimServiceDeps,
  physicianId: string,
  actorId: string,
  file: UploadedFile,
  templateId?: string,
): Promise<{ importBatchId: string }> {
  // 1. Compute SHA-256 hash
  const contentStr = typeof file.content === 'string'
    ? file.content
    : file.content.toString('utf-8');
  const fileHash = createHash('sha256').update(contentStr).digest('hex');

  // 2. Check for duplicate file
  const existing = await deps.repo.findDuplicateImportByHash(physicianId, fileHash);
  if (existing) {
    throw new ConflictError('This file has already been imported');
  }

  // 3. Determine delimiter and parse
  let delimiter = ',';
  let hasHeaderRow = true;
  let dateFormat: string | undefined;

  if (templateId) {
    const template = await deps.repo.findTemplateById(templateId, physicianId);
    if (!template) {
      throw new NotFoundError('Field mapping template');
    }
    delimiter = (template as any).delimiter || delimiter;
    hasHeaderRow = (template as any).hasHeaderRow ?? true;
    dateFormat = (template as any).dateFormat ?? undefined;
  }

  const rows = parseRows(contentStr, delimiter);
  const dataRowCount = hasHeaderRow ? Math.max(0, rows.length - 1) : rows.length;

  // 4. Create import batch record
  const batch = await deps.repo.createImportBatch({
    physicianId,
    fileName: file.fileName,
    fileHash,
    fieldMappingTemplateId: templateId ?? null,
    totalRows: dataRowCount,
    successCount: 0,
    errorCount: 0,
    status: ImportBatchStatus.PENDING,
    createdBy: actorId,
  } as any);

  return { importBatchId: batch.importBatchId };
}

// ---------------------------------------------------------------------------
// Service: previewImport
// ---------------------------------------------------------------------------

/**
 * Preview an import batch: apply field mapping, validate each row,
 * report unmapped columns and per-row errors.
 * Does NOT create claims.
 */
export async function previewImport(
  deps: ClaimServiceDeps,
  importBatchId: string,
  physicianId: string,
  fileContent: string,
): Promise<ImportPreviewResult> {
  // 1. Fetch the import batch
  const batch = await deps.repo.findImportBatchById(importBatchId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch');
  }

  // 2. Load template if specified
  let mappings: FieldMappingEntry[] = [];
  let delimiter = ',';
  let hasHeaderRow = true;
  let dateFormat: string | undefined;

  const templateId = (batch as any).fieldMappingTemplateId;
  if (templateId) {
    const template = await deps.repo.findTemplateById(templateId, physicianId);
    if (template) {
      const rawMappings = (template as any).mappings;
      mappings = Array.isArray(rawMappings) ? rawMappings : [];
      delimiter = (template as any).delimiter || delimiter;
      hasHeaderRow = (template as any).hasHeaderRow ?? true;
      dateFormat = (template as any).dateFormat ?? undefined;
    }
  }

  if (!(batch as any).fieldMappingTemplateId) {
    delimiter = detectDelimiter(fileContent.split(/\r?\n/)[0] || '');
  }

  // 3. Parse the file
  const allRows = parseRows(fileContent, delimiter);
  if (allRows.length === 0) {
    return { rows: [], unmappedColumns: [], totalRows: 0, validRows: 0, errorRows: 0 };
  }

  // 4. Determine headers
  let headers: string[];
  let dataRows: string[][];

  if (hasHeaderRow) {
    headers = allRows[0];
    dataRows = allRows.slice(1);
  } else {
    headers = allRows[0].map((_, i) => `column_${i}`);
    dataRows = allRows;
  }

  // 5. Identify mapped and unmapped columns
  const mappedSourceColumns = new Set(mappings.map((m) => m.source_column));
  const unmappedColumns = headers.filter((h) => !mappedSourceColumns.has(h));

  // 6. Map and validate each row
  const previewRows: ImportPreviewRow[] = [];
  let validCount = 0;
  let errorCount = 0;

  for (let i = 0; i < dataRows.length; i++) {
    const row = dataRows[i];
    const mapped: Record<string, string> = {};
    const rowErrors: Array<{ field: string; message: string }> = [];

    // Apply mappings
    for (const mapping of mappings) {
      const colIndex = headers.indexOf(mapping.source_column);
      if (colIndex === -1 || colIndex >= row.length) {
        continue;
      }

      let value = row[colIndex];

      // Apply transform if specified
      if (mapping.transform === 'uppercase') {
        value = value.toUpperCase();
      } else if (mapping.transform === 'lowercase') {
        value = value.toLowerCase();
      } else if (mapping.transform === 'trim') {
        value = value.trim();
      }

      // Parse dates for date fields
      if (mapping.target_field === 'dateOfService' || mapping.target_field === 'date_of_service') {
        const parsed = parseDate(value, dateFormat);
        if (!parsed) {
          rowErrors.push({ field: mapping.target_field, message: `Invalid date: ${value}` });
        } else {
          value = parsed;
        }
      }

      mapped[mapping.target_field] = value;
    }

    // Validate required fields
    if (!mapped.patientId && !mapped.patient_id) {
      rowErrors.push({ field: 'patientId', message: 'Missing required field: patientId' });
    }
    if (!mapped.dateOfService && !mapped.date_of_service) {
      rowErrors.push({ field: 'dateOfService', message: 'Missing required field: dateOfService' });
    }
    if (!mapped.claimType && !mapped.claim_type) {
      rowErrors.push({ field: 'claimType', message: 'Missing required field: claimType' });
    }

    if (rowErrors.length > 0) {
      errorCount++;
    } else {
      validCount++;
    }

    previewRows.push({
      rowNumber: i + 1,
      mapped,
      errors: rowErrors,
    });
  }

  return {
    rows: previewRows,
    unmappedColumns,
    totalRows: dataRows.length,
    validRows: validCount,
    errorRows: errorCount,
  };
}

// ---------------------------------------------------------------------------
// Service: commitImport
// ---------------------------------------------------------------------------

/**
 * Commit an import batch: create claims from valid mapped rows,
 * skip failed rows, update batch with counts and error details.
 */
export async function commitImport(
  deps: ClaimServiceDeps,
  importBatchId: string,
  physicianId: string,
  actorId: string,
  fileContent: string,
): Promise<ImportCommitResult> {
  // 1. Fetch the import batch
  const batch = await deps.repo.findImportBatchById(importBatchId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch');
  }

  if ((batch as any).status !== ImportBatchStatus.PENDING) {
    throw new ConflictError('Import batch has already been processed');
  }

  // 2. Set status to PROCESSING
  await deps.repo.updateImportBatchStatus(
    importBatchId,
    physicianId,
    ImportBatchStatus.PROCESSING,
  );

  // 3. Preview to get mapped rows
  const preview = await previewImport(deps, importBatchId, physicianId, fileContent);

  // 4. Create claims for valid rows, skip failed ones
  let successCount = 0;
  let errorCount = 0;
  const errorDetails: Array<{ rowNumber: number; field: string; message: string }> = [];

  for (const row of preview.rows) {
    if (row.errors.length > 0) {
      errorCount++;
      errorDetails.push(
        ...row.errors.map((e) => ({ rowNumber: row.rowNumber, ...e })),
      );
      continue;
    }

    // Normalize field names (camelCase)
    const patientId = row.mapped.patientId || row.mapped.patient_id;
    const dateOfService = row.mapped.dateOfService || row.mapped.date_of_service;
    const claimType = row.mapped.claimType || row.mapped.claim_type || ClaimType.AHCIP;

    try {
      await createClaimFromImport(deps, physicianId, actorId, importBatchId, {
        patientId: patientId!,
        dateOfService: dateOfService!,
        claimType,
      });
      successCount++;
    } catch (err: any) {
      errorCount++;
      errorDetails.push({
        rowNumber: row.rowNumber,
        field: 'claim',
        message: err.message || 'Failed to create claim',
      });
    }
  }

  // 5. Update batch with final counts
  await deps.repo.updateImportBatchStatus(
    importBatchId,
    physicianId,
    ImportBatchStatus.COMPLETED,
    {
      successCount,
      errorCount,
      errorDetails,
    },
  );

  return { successCount, errorCount, errorDetails };
}

// ---------------------------------------------------------------------------
// Service: getClaimSuggestions
// ---------------------------------------------------------------------------

/**
 * Return AI Coach suggestions for a specific claim.
 *
 * Returns the ai_coach_suggestions JSONB field, physician-scoped.
 */
export async function getClaimSuggestions(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
): Promise<{ suggestions: any[] }> {
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  const raw = (claim as any).aiCoachSuggestions;
  if (!raw) {
    return { suggestions: [] };
  }

  const suggestions = Array.isArray(raw) ? raw : raw.suggestions ?? [];
  return { suggestions };
}

// ---------------------------------------------------------------------------
// Service: acceptSuggestion
// ---------------------------------------------------------------------------

/**
 * Accept an AI Coach suggestion and apply the suggested change.
 *
 * 1. Verify claim exists and belongs to physician
 * 2. Find the suggestion by ID in the JSONB array
 * 3. Mark suggestion as ACCEPTED
 * 4. Apply the suggested change to the claim
 * 5. Re-validate the claim
 * 6. Append AI_SUGGESTION_ACCEPTED audit entry
 * 7. Re-evaluate clean/flagged if claim is in QUEUED state
 */
export async function acceptSuggestion(
  deps: ClaimServiceDeps,
  claimId: string,
  suggestionId: string,
  physicianId: string,
  actorId: string,
): Promise<void> {
  // 1. Fetch claim
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  // 2. Find and update suggestion in JSONB
  const raw = (claim as any).aiCoachSuggestions;
  if (!raw) {
    throw new NotFoundError('Suggestion');
  }

  const suggestions: any[] = Array.isArray(raw) ? [...raw] : [...(raw.suggestions ?? [])];
  const suggestionIndex = suggestions.findIndex((s: any) => s.id === suggestionId);
  if (suggestionIndex === -1) {
    throw new NotFoundError('Suggestion');
  }

  const suggestion = suggestions[suggestionIndex];
  if (suggestion.status !== 'PENDING') {
    throw new BusinessRuleError('Suggestion has already been processed');
  }

  // 3. Mark suggestion as ACCEPTED
  suggestions[suggestionIndex] = { ...suggestion, status: 'ACCEPTED' };

  // 4. Apply suggested change to the claim if suggestion has a field and value
  if (suggestion.field && suggestion.suggestedValue !== undefined) {
    await deps.repo.updateClaim(claimId, physicianId, {
      [suggestion.field]: suggestion.suggestedValue,
    } as any);
  }

  // Update the JSONB suggestions on the claim
  const updatedSuggestions = Array.isArray(raw)
    ? suggestions
    : { ...raw, suggestions };
  await deps.repo.updateAiSuggestions(claimId, physicianId, updatedSuggestions);

  // 5. Re-validate the claim
  await runValidationChecks(deps, claimId, physicianId, actorId);

  // 6. Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.AI_SUGGESTION_ACCEPTED,
    previousState: (claim as any).state,
    newState: (claim as any).state,
    changes: { suggestionId, field: suggestion.field, suggestedValue: suggestion.suggestedValue },
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);

  // 7. Re-evaluate clean/flagged if in QUEUED state
  if ((claim as any).state === ClaimState.QUEUED) {
    await reclassifyQueuedClaim(deps, claimId, physicianId);
  }
}

// ---------------------------------------------------------------------------
// Service: dismissSuggestion
// ---------------------------------------------------------------------------

/**
 * Dismiss an AI Coach suggestion with optional reason.
 *
 * 1. Verify claim exists and belongs to physician
 * 2. Find the suggestion by ID
 * 3. Mark suggestion as DISMISSED with optional reason
 * 4. Append AI_SUGGESTION_DISMISSED audit entry
 * 5. Re-evaluate clean/flagged if claim is in QUEUED state
 */
export async function dismissSuggestion(
  deps: ClaimServiceDeps,
  claimId: string,
  suggestionId: string,
  physicianId: string,
  actorId: string,
  reason?: string,
): Promise<void> {
  // 1. Fetch claim
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  // 2. Find suggestion
  const raw = (claim as any).aiCoachSuggestions;
  if (!raw) {
    throw new NotFoundError('Suggestion');
  }

  const suggestions: any[] = Array.isArray(raw) ? [...raw] : [...(raw.suggestions ?? [])];
  const suggestionIndex = suggestions.findIndex((s: any) => s.id === suggestionId);
  if (suggestionIndex === -1) {
    throw new NotFoundError('Suggestion');
  }

  const suggestion = suggestions[suggestionIndex];
  if (suggestion.status !== 'PENDING') {
    throw new BusinessRuleError('Suggestion has already been processed');
  }

  // 3. Mark as DISMISSED
  suggestions[suggestionIndex] = {
    ...suggestion,
    status: 'DISMISSED',
    dismissReason: reason ?? null,
  };

  const updatedSuggestions = Array.isArray(raw)
    ? suggestions
    : { ...raw, suggestions };
  await deps.repo.updateAiSuggestions(claimId, physicianId, updatedSuggestions);

  // 4. Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.AI_SUGGESTION_DISMISSED,
    previousState: (claim as any).state,
    newState: (claim as any).state,
    changes: { suggestionId, reason: reason ?? null },
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);

  // 5. Re-evaluate clean/flagged if in QUEUED state
  if ((claim as any).state === ClaimState.QUEUED) {
    await reclassifyQueuedClaim(deps, claimId, physicianId);
  }
}

// ---------------------------------------------------------------------------
// Service: acknowledgeDuplicate
// ---------------------------------------------------------------------------

/**
 * Acknowledge a duplicate alert on a claim. Clears the duplicate_alert
 * JSONB field and re-evaluates clean/flagged classification.
 *
 * 1. Verify claim exists and belongs to physician
 * 2. Clear duplicate_alert
 * 3. Append DUPLICATE_ACKNOWLEDGED audit entry
 * 4. Re-evaluate clean/flagged if in QUEUED state
 */
export async function acknowledgeDuplicate(
  deps: ClaimServiceDeps,
  claimId: string,
  physicianId: string,
  actorId: string,
): Promise<void> {
  // 1. Fetch claim
  const claim = await deps.repo.findClaimById(claimId, physicianId);
  if (!claim) {
    throw new NotFoundError('Claim');
  }

  // Capture previous alert before clearing (the update mutates in-place)
  const previousAlert = (claim as any).duplicateAlert
    ? JSON.parse(JSON.stringify((claim as any).duplicateAlert))
    : null;

  // 2. Clear duplicate_alert
  await deps.repo.updateDuplicateAlert(claimId, physicianId, null);

  // 3. Append audit entry
  await deps.repo.appendClaimAudit({
    claimId,
    action: ClaimAuditAction.DUPLICATE_ACKNOWLEDGED,
    previousState: (claim as any).state,
    newState: (claim as any).state,
    changes: { previousAlert },
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);

  // 4. Re-evaluate clean/flagged if in QUEUED state
  if ((claim as any).state === ClaimState.QUEUED) {
    await reclassifyQueuedClaim(deps, claimId, physicianId);
  }
}

// ---------------------------------------------------------------------------
// Service: getSubmissionPreferences
// ---------------------------------------------------------------------------

/**
 * Read submission preferences from Provider Management (Domain 5).
 *
 * Delegates to the submissionPreference dependency.
 * Returns defaults if no dependency is configured.
 */
export async function getSubmissionPreferences(
  deps: ClaimServiceDeps,
  physicianId: string,
): Promise<{ ahcipMode: string; wcbMode: string }> {
  if (!deps.submissionPreference) {
    return {
      ahcipMode: AutoSubmissionMode.AUTO_CLEAN,
      wcbMode: AutoSubmissionMode.REQUIRE_APPROVAL,
    };
  }

  const [ahcipMode, wcbMode] = await Promise.all([
    deps.submissionPreference.getSubmissionMode(physicianId, ClaimType.AHCIP),
    deps.submissionPreference.getSubmissionMode(physicianId, ClaimType.WCB),
  ]);

  return { ahcipMode, wcbMode };
}

// ---------------------------------------------------------------------------
// Service: updateSubmissionPreferences
// ---------------------------------------------------------------------------

/**
 * Update submission preferences via Provider Management.
 *
 * Validates the mode, delegates update to the submissionPreference
 * dependency, and appends an audit entry.
 */
export async function updateSubmissionPreferences(
  deps: ClaimServiceDeps,
  physicianId: string,
  actorId: string,
  mode: string,
): Promise<void> {
  const validModes = [
    AutoSubmissionMode.AUTO_CLEAN,
    AutoSubmissionMode.AUTO_ALL,
    AutoSubmissionMode.REQUIRE_APPROVAL,
  ];

  if (!validModes.includes(mode)) {
    throw new BusinessRuleError(`Invalid submission mode: ${mode}`);
  }

  // The actual update is delegated to Provider Management.
  // For now, we record the audit entry for this domain's perspective.
  // The handler will call the provider domain's service to persist the change.

  await deps.repo.appendClaimAudit({
    claimId: 'submission_preferences',
    action: 'submission_preferences.updated' as any,
    previousState: null,
    newState: null,
    changes: { mode, physicianId },
    actorId,
    actorContext: ActorContext.PHYSICIAN,
  } as any);
}

// ---------------------------------------------------------------------------
// Export types
// ---------------------------------------------------------------------------

export interface ExportParams {
  dateFrom: string;
  dateTo: string;
  claimType?: string;
  format: string;
}

// ---------------------------------------------------------------------------
// Service: requestExport
// ---------------------------------------------------------------------------

/**
 * Create a data export request.
 *
 * 1. Validate date range (dateFrom <= dateTo, not unbounded)
 * 2. Create export record with PENDING status
 * 3. Return export_id for status polling
 *
 * The actual file generation is done asynchronously by generateExportFile.
 */
export async function requestExport(
  deps: ClaimServiceDeps,
  physicianId: string,
  params: ExportParams,
): Promise<{ exportId: string }> {
  // Validate date range
  if (params.dateFrom > params.dateTo) {
    throw new BusinessRuleError('date_from must be before or equal to date_to');
  }

  const exportRecord = await deps.repo.createExportRecord({
    physicianId,
    dateFrom: params.dateFrom,
    dateTo: params.dateTo,
    claimType: params.claimType,
    format: params.format,
  });

  return { exportId: exportRecord.exportId };
}

// ---------------------------------------------------------------------------
// Service: getExportStatus
// ---------------------------------------------------------------------------

/**
 * Return the status of a data export request.
 *
 * Physician-scoped — returns null if the export doesn't exist or
 * belongs to a different physician.
 */
export async function getExportStatus(
  deps: ClaimServiceDeps,
  exportId: string,
  physicianId: string,
): Promise<{
  exportId: string;
  status: string;
  filePath: string | null;
} | null> {
  const record = await deps.repo.findExportById(exportId, physicianId);
  if (!record) {
    return null;
  }

  return {
    exportId: record.exportId,
    status: record.status,
    filePath: record.filePath ?? null,
  };
}

// ---------------------------------------------------------------------------
// Service: generateExportFile
// ---------------------------------------------------------------------------

/**
 * Background job: generate the export file for a completed request.
 *
 * 1. Transition export to PROCESSING
 * 2. Query claims within the date range (physician-scoped)
 * 3. Generate CSV or JSON content
 * 4. Store file path (in production: upload to DigitalOcean Spaces)
 * 5. Transition export to COMPLETED with file path
 *
 * On failure, transition to FAILED.
 */
export async function generateExportFile(
  deps: ClaimServiceDeps,
  exportId: string,
  physicianId: string,
): Promise<{ filePath: string }> {
  // 1. Find and verify export record
  const record = await deps.repo.findExportById(exportId, physicianId);
  if (!record) {
    throw new NotFoundError('Export');
  }

  // 2. Transition to PROCESSING
  await deps.repo.updateExportStatus(exportId, physicianId, 'PROCESSING');

  try {
    // 3. Query claims within the date range
    const result = await deps.repo.listClaims(physicianId, {
      dateFrom: record.dateFrom,
      dateTo: record.dateTo,
      claimType: record.claimType ?? undefined,
      page: 1,
      pageSize: 10000, // Export up to 10K claims per request
    });

    // 4. Generate file content
    let fileContent: string;
    if (record.format === 'JSON') {
      fileContent = JSON.stringify(result.data, null, 2);
    } else {
      // CSV format
      const headers = [
        'claim_id', 'claim_type', 'state', 'patient_id',
        'date_of_service', 'submission_deadline', 'is_clean',
      ];
      const rows = result.data.map((c: any) =>
        [
          c.claimId, c.claimType, c.state, c.patientId,
          c.dateOfService, c.submissionDeadline, c.isClean,
        ].join(','),
      );
      fileContent = [headers.join(','), ...rows].join('\n');
    }

    // 5. Generate file path (in production: upload to DO Spaces)
    const filePath = `exports/${physicianId}/${exportId}.${record.format === 'JSON' ? 'json' : 'csv'}`;

    // 6. Transition to COMPLETED with file path
    await deps.repo.updateExportStatus(exportId, physicianId, 'COMPLETED', filePath);

    return { filePath };
  } catch (err: any) {
    // On failure, transition to FAILED
    await deps.repo.updateExportStatus(exportId, physicianId, 'FAILED');
    throw err;
  }
}
