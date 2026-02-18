// ============================================================================
// Domain 4.0: Claim Lifecycle Core — Constants
// ============================================================================

// --- Claim State (11 states, 5 terminal) ---

export const ClaimState = {
  DRAFT: 'DRAFT',
  VALIDATED: 'VALIDATED',
  QUEUED: 'QUEUED',
  SUBMITTED: 'SUBMITTED',
  ASSESSED: 'ASSESSED',
  PAID: 'PAID',
  REJECTED: 'REJECTED',
  ADJUSTED: 'ADJUSTED',
  WRITTEN_OFF: 'WRITTEN_OFF',
  EXPIRED: 'EXPIRED',
  DELETED: 'DELETED',
} as const;

export type ClaimState = (typeof ClaimState)[keyof typeof ClaimState];

// --- Terminal States ---

export const TERMINAL_STATES: ReadonlySet<ClaimState> = new Set([
  ClaimState.PAID,
  ClaimState.ADJUSTED,
  ClaimState.WRITTEN_OFF,
  ClaimState.EXPIRED,
  ClaimState.DELETED,
]);

// --- State Transition Map ---
// Maps each state to the set of states it can transition to.
// The EXPIRED transition from any non-terminal state is handled separately
// (system-initiated, not user-triggered).

export const STATE_TRANSITIONS: Readonly<
  Record<ClaimState, readonly ClaimState[]>
> = Object.freeze({
  [ClaimState.DRAFT]: [ClaimState.VALIDATED, ClaimState.DELETED],
  [ClaimState.VALIDATED]: [ClaimState.DRAFT, ClaimState.QUEUED],
  [ClaimState.QUEUED]: [ClaimState.VALIDATED, ClaimState.SUBMITTED],
  [ClaimState.SUBMITTED]: [ClaimState.ASSESSED, ClaimState.REJECTED],
  [ClaimState.ASSESSED]: [ClaimState.PAID, ClaimState.ADJUSTED],
  [ClaimState.REJECTED]: [
    ClaimState.DRAFT,
    ClaimState.QUEUED,
    ClaimState.WRITTEN_OFF,
  ],
  // Terminal states have no outgoing transitions
  [ClaimState.PAID]: [],
  [ClaimState.ADJUSTED]: [],
  [ClaimState.WRITTEN_OFF]: [],
  [ClaimState.EXPIRED]: [],
  [ClaimState.DELETED]: [],
});

// --- Claim Type ---

export const ClaimType = {
  AHCIP: 'AHCIP',
  WCB: 'WCB',
} as const;

export type ClaimType = (typeof ClaimType)[keyof typeof ClaimType];

// --- Claim Import Source ---

export const ClaimImportSource = {
  MANUAL: 'MANUAL',
  EMR_IMPORT: 'EMR_IMPORT',
  ED_SHIFT: 'ED_SHIFT',
} as const;

export type ClaimImportSource =
  (typeof ClaimImportSource)[keyof typeof ClaimImportSource];

// --- Auto-Submission Mode ---
// Physician preference for how claims are included in batches.
// Re-exported from provider.constants.ts as SubmissionMode — these are
// the same concept, aliased here for domain clarity.

export { SubmissionMode as AutoSubmissionMode } from './provider.constants.js';

// --- Import Batch Status ---

export const ImportBatchStatus = {
  PENDING: 'PENDING',
  PROCESSING: 'PROCESSING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
} as const;

export type ImportBatchStatus =
  (typeof ImportBatchStatus)[keyof typeof ImportBatchStatus];

// --- ED Shift Status ---

export const ShiftStatus = {
  IN_PROGRESS: 'IN_PROGRESS',
  COMPLETED: 'COMPLETED',
  SUBMITTED: 'SUBMITTED',
} as const;

export type ShiftStatus = (typeof ShiftStatus)[keyof typeof ShiftStatus];

// --- Claim Audit Actions (17 actions) ---

export const ClaimAuditAction = {
  CREATED: 'claim.created',
  EDITED: 'claim.edited',
  VALIDATED: 'claim.validated',
  QUEUED: 'claim.queued',
  UNQUEUED: 'claim.unqueued',
  SUBMITTED: 'claim.submitted',
  ASSESSED: 'claim.assessed',
  REJECTED: 'claim.rejected',
  RESUBMITTED: 'claim.resubmitted',
  WRITTEN_OFF: 'claim.written_off',
  DELETED: 'claim.deleted',
  EXPIRED: 'claim.expired',
  AI_SUGGESTION_ACCEPTED: 'claim.ai_suggestion_accepted',
  AI_SUGGESTION_DISMISSED: 'claim.ai_suggestion_dismissed',
  DUPLICATE_ACKNOWLEDGED: 'claim.duplicate_acknowledged',
  SHIFT_CREATED: 'shift.created',
  SHIFT_COMPLETED: 'shift.completed',
} as const;

export type ClaimAuditAction =
  (typeof ClaimAuditAction)[keyof typeof ClaimAuditAction];

// --- Actor Context ---

export const ActorContext = {
  PHYSICIAN: 'PHYSICIAN',
  DELEGATE: 'DELEGATE',
  SYSTEM: 'SYSTEM',
} as const;

export type ActorContext = (typeof ActorContext)[keyof typeof ActorContext];

// --- Shared Validation Check IDs ---

export const ValidationCheckId = {
  S1_CLAIM_TYPE_VALID: 'S1_CLAIM_TYPE_VALID',
  S2_REQUIRED_BASE_FIELDS: 'S2_REQUIRED_BASE_FIELDS',
  S3_PATIENT_EXISTS: 'S3_PATIENT_EXISTS',
  S4_PHYSICIAN_ACTIVE: 'S4_PHYSICIAN_ACTIVE',
  S5_DOS_VALID: 'S5_DOS_VALID',
  S6_SUBMISSION_WINDOW: 'S6_SUBMISSION_WINDOW',
  S7_DUPLICATE_DETECTION: 'S7_DUPLICATE_DETECTION',
} as const;

export type ValidationCheckId =
  (typeof ValidationCheckId)[keyof typeof ValidationCheckId];

// --- Validation Severity ---

export const ValidationSeverity = {
  ERROR: 'ERROR',
  WARNING: 'WARNING',
  INFO: 'INFO',
} as const;

export type ValidationSeverity =
  (typeof ValidationSeverity)[keyof typeof ValidationSeverity];

// --- Shared Validation Check Configuration ---

interface ValidationCheckConfig {
  readonly id: ValidationCheckId;
  readonly defaultSeverity: ValidationSeverity;
  readonly description: string;
}

export const VALIDATION_CHECKS: Readonly<
  Record<ValidationCheckId, ValidationCheckConfig>
> = Object.freeze({
  [ValidationCheckId.S1_CLAIM_TYPE_VALID]: {
    id: ValidationCheckId.S1_CLAIM_TYPE_VALID,
    defaultSeverity: ValidationSeverity.ERROR,
    description: 'Claim type is AHCIP or WCB',
  },
  [ValidationCheckId.S2_REQUIRED_BASE_FIELDS]: {
    id: ValidationCheckId.S2_REQUIRED_BASE_FIELDS,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'physician_id, patient_id, date_of_service are present',
  },
  [ValidationCheckId.S3_PATIENT_EXISTS]: {
    id: ValidationCheckId.S3_PATIENT_EXISTS,
    defaultSeverity: ValidationSeverity.ERROR,
    description: 'patient_id resolves to a valid patient record',
  },
  [ValidationCheckId.S4_PHYSICIAN_ACTIVE]: {
    id: ValidationCheckId.S4_PHYSICIAN_ACTIVE,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'physician_id resolves to an active provider with valid BA/billing number',
  },
  [ValidationCheckId.S5_DOS_VALID]: {
    id: ValidationCheckId.S5_DOS_VALID,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'date_of_service is a valid date, not in the future, not before physician registration',
  },
  [ValidationCheckId.S6_SUBMISSION_WINDOW]: {
    id: ValidationCheckId.S6_SUBMISSION_WINDOW,
    defaultSeverity: ValidationSeverity.ERROR,
    description:
      'DOS within submission window (AHCIP: 90 days, WCB: form-specific). Warning if within 7 days of deadline.',
  },
  [ValidationCheckId.S7_DUPLICATE_DETECTION]: {
    id: ValidationCheckId.S7_DUPLICATE_DETECTION,
    defaultSeverity: ValidationSeverity.WARNING,
    description:
      'Same patient + same DOS + same primary service code found in existing non-deleted claims',
  },
});

// --- Export Status ---

export const ExportStatus = {
  PENDING: 'PENDING',
  PROCESSING: 'PROCESSING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
} as const;

export type ExportStatus = (typeof ExportStatus)[keyof typeof ExportStatus];

// --- Claim Notification Events ---
// Subset of NotificationEventType relevant to claims. These identifiers match
// the values already defined in notification.constants.ts.

export const ClaimNotificationEvent = {
  CLAIM_VALIDATED: 'CLAIM_VALIDATED',
  CLAIM_FLAGGED: 'CLAIM_FLAGGED',
  DEADLINE_APPROACHING: 'DEADLINE_APPROACHING',
  DEADLINE_EXPIRED: 'DEADLINE_EXPIRED',
  BATCH_ASSEMBLED: 'BATCH_ASSEMBLED',
  BATCH_SUBMITTED: 'BATCH_SUBMITTED',
  CLAIM_ASSESSED: 'CLAIM_ASSESSED',
  CLAIM_REJECTED: 'CLAIM_REJECTED',
  CLAIM_PAID: 'CLAIM_PAID',
  DUPLICATE_DETECTED: 'DUPLICATE_DETECTED',
  AI_SUGGESTION_READY: 'AI_SUGGESTION_READY',
} as const;

export type ClaimNotificationEvent =
  (typeof ClaimNotificationEvent)[keyof typeof ClaimNotificationEvent];
