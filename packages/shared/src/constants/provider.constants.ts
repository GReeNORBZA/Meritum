// ============================================================================
// Domain 5: Provider Management — Constants
// ============================================================================

// --- Provider Status ---

export const ProviderStatus = {
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  INACTIVE: 'INACTIVE',
} as const;

export type ProviderStatus =
  (typeof ProviderStatus)[keyof typeof ProviderStatus];

// --- Physician Type ---

export const PhysicianType = {
  GP: 'GP',
  SPECIALIST: 'SPECIALIST',
  LOCUM: 'LOCUM',
} as const;

export type PhysicianType =
  (typeof PhysicianType)[keyof typeof PhysicianType];

// --- Business Arrangement Type ---

export const BAType = {
  FFS: 'FFS',
  PCPCM: 'PCPCM',
  ARP: 'ARP',
} as const;

export type BAType = (typeof BAType)[keyof typeof BAType];

// --- Business Arrangement Status ---

export const BAStatus = {
  ACTIVE: 'ACTIVE',
  PENDING: 'PENDING',
  INACTIVE: 'INACTIVE',
} as const;

export type BAStatus = (typeof BAStatus)[keyof typeof BAStatus];

// --- PCPCM Enrolment Status ---

export const PcpcmEnrolmentStatus = {
  ACTIVE: 'ACTIVE',
  PENDING: 'PENDING',
  WITHDRAWN: 'WITHDRAWN',
} as const;

export type PcpcmEnrolmentStatus =
  (typeof PcpcmEnrolmentStatus)[keyof typeof PcpcmEnrolmentStatus];

// --- Delegate Relationship Status ---

export const DelegateRelationshipStatus = {
  ACTIVE: 'ACTIVE',
  INVITED: 'INVITED',
  REVOKED: 'REVOKED',
} as const;

export type DelegateRelationshipStatus =
  (typeof DelegateRelationshipStatus)[keyof typeof DelegateRelationshipStatus];

// --- Submission Mode ---

export const SubmissionMode = {
  AUTO_CLEAN: 'AUTO_CLEAN',
  AUTO_ALL: 'AUTO_ALL',
  REQUIRE_APPROVAL: 'REQUIRE_APPROVAL',
} as const;

export type SubmissionMode =
  (typeof SubmissionMode)[keyof typeof SubmissionMode];

// --- H-Link Accreditation Status ---

export const HLinkAccreditationStatus = {
  PENDING: 'PENDING',
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
} as const;

export type HLinkAccreditationStatus =
  (typeof HLinkAccreditationStatus)[keyof typeof HLinkAccreditationStatus];

// --- Delegate Permission Keys (24 total, across 9 categories) ---

export const DelegatePermission = {
  // Claims (8)
  CLAIM_CREATE: 'CLAIM_CREATE',
  CLAIM_EDIT: 'CLAIM_EDIT',
  CLAIM_VIEW: 'CLAIM_VIEW',
  CLAIM_DELETE: 'CLAIM_DELETE',
  CLAIM_QUEUE: 'CLAIM_QUEUE',
  CLAIM_APPROVE: 'CLAIM_APPROVE',
  CLAIM_RESUBMIT: 'CLAIM_RESUBMIT',
  CLAIM_WRITE_OFF: 'CLAIM_WRITE_OFF',

  // Batches (3)
  BATCH_VIEW: 'BATCH_VIEW',
  BATCH_DOWNLOAD: 'BATCH_DOWNLOAD',
  BATCH_CONFIRM_UPLOAD: 'BATCH_CONFIRM_UPLOAD',

  // Import (2)
  IMPORT_EMR: 'IMPORT_EMR',
  IMPORT_MANAGE_TEMPLATES: 'IMPORT_MANAGE_TEMPLATES',

  // Patients (4)
  PATIENT_VIEW: 'PATIENT_VIEW',
  PATIENT_CREATE: 'PATIENT_CREATE',
  PATIENT_EDIT: 'PATIENT_EDIT',
  PATIENT_IMPORT: 'PATIENT_IMPORT',

  // ED Shifts (1)
  SHIFT_MANAGE: 'SHIFT_MANAGE',

  // Reports (2)
  REPORT_VIEW: 'REPORT_VIEW',
  REPORT_EXPORT: 'REPORT_EXPORT',

  // AI Coach (1)
  AI_COACH_REVIEW: 'AI_COACH_REVIEW',

  // Rejections (1)
  REJECTION_MANAGE: 'REJECTION_MANAGE',

  // Settings (2)
  PREFERENCE_VIEW: 'PREFERENCE_VIEW',
  PREFERENCE_EDIT: 'PREFERENCE_EDIT',
} as const;

export type DelegatePermission =
  (typeof DelegatePermission)[keyof typeof DelegatePermission];

// --- All 24 delegate permissions ---

const ALL_DELEGATE_PERMISSIONS: readonly DelegatePermission[] =
  Object.values(DelegatePermission);

// --- Default Permission Templates ---

export const DelegatePermissionTemplate = {
  FULL_ACCESS: 'FULL_ACCESS',
  BILLING_ENTRY: 'BILLING_ENTRY',
  REVIEW_SUBMIT: 'REVIEW_SUBMIT',
  VIEW_ONLY: 'VIEW_ONLY',
  CUSTOM: 'CUSTOM',
} as const;

export type DelegatePermissionTemplate =
  (typeof DelegatePermissionTemplate)[keyof typeof DelegatePermissionTemplate];

export const DelegatePermissionTemplatePermissions: Readonly<
  Record<string, readonly DelegatePermission[]>
> = Object.freeze({
  [DelegatePermissionTemplate.FULL_ACCESS]: ALL_DELEGATE_PERMISSIONS,

  [DelegatePermissionTemplate.BILLING_ENTRY]: [
    DelegatePermission.CLAIM_CREATE,
    DelegatePermission.CLAIM_EDIT,
    DelegatePermission.CLAIM_VIEW,
    DelegatePermission.CLAIM_QUEUE,
    DelegatePermission.IMPORT_EMR,
    DelegatePermission.PATIENT_VIEW,
    DelegatePermission.PATIENT_CREATE,
    DelegatePermission.SHIFT_MANAGE,
    DelegatePermission.AI_COACH_REVIEW,
  ],

  [DelegatePermissionTemplate.REVIEW_SUBMIT]: [
    DelegatePermission.CLAIM_VIEW,
    DelegatePermission.CLAIM_APPROVE,
    DelegatePermission.BATCH_VIEW,
    DelegatePermission.BATCH_DOWNLOAD,
    DelegatePermission.BATCH_CONFIRM_UPLOAD,
    DelegatePermission.REJECTION_MANAGE,
    DelegatePermission.REPORT_VIEW,
  ],

  [DelegatePermissionTemplate.VIEW_ONLY]: [
    DelegatePermission.CLAIM_VIEW,
    DelegatePermission.BATCH_VIEW,
    DelegatePermission.PATIENT_VIEW,
    DelegatePermission.REPORT_VIEW,
  ],
});

// --- Provider Audit Action Identifiers ---

export const ProviderAuditAction = {
  // Profile (2)
  PROFILE_UPDATED: 'provider.profile_updated',
  ONBOARDING_COMPLETED: 'provider.onboarding_completed',

  // Business Arrangements (3)
  BA_ADDED: 'ba.added',
  BA_UPDATED: 'ba.updated',
  BA_DEACTIVATED: 'ba.deactivated',

  // Locations (3)
  LOCATION_ADDED: 'location.added',
  LOCATION_UPDATED: 'location.updated',
  LOCATION_DEACTIVATED: 'location.deactivated',

  // WCB Config (3)
  WCB_CONFIG_ADDED: 'wcb_config.added',
  WCB_CONFIG_UPDATED: 'wcb_config.updated',
  WCB_CONFIG_REMOVED: 'wcb_config.removed',

  // Delegates (4)
  DELEGATE_INVITED: 'delegate.invited',
  DELEGATE_ACCEPTED: 'delegate.accepted',
  DELEGATE_PERMISSIONS_CHANGED: 'delegate.permissions_changed',
  DELEGATE_REVOKED: 'delegate.revoked',

  // Submission Preferences (1)
  SUBMISSION_PREFERENCE_CHANGED: 'submission_preference.changed',

  // H-Link (1)
  HLINK_CONFIG_UPDATED: 'hlink_config.updated',
} as const;

export type ProviderAuditAction =
  (typeof ProviderAuditAction)[keyof typeof ProviderAuditAction];

// --- Default Submission Preferences ---

export const DEFAULT_SUBMISSION_PREFERENCES = Object.freeze({
  ahcip: SubmissionMode.AUTO_CLEAN,
  wcb: SubmissionMode.REQUIRE_APPROVAL,
  batchReviewReminder: true,
  deadlineReminderDays: 7,
} as const);
