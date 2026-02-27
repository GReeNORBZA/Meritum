// ============================================================================
// Connect Care / SCC Integration — Constants
// ============================================================================

// --- SCC Extract Specification Versions ---

export const SCC_SPEC_VERSIONS = {
  '2025-12': { label: 'December 2025', ahcipFields: 21, wcbFields: 13 },
} as const;

export type SccSpecVersion = keyof typeof SCC_SPEC_VERSIONS;

export const CURRENT_SCC_SPEC_VERSION: SccSpecVersion = '2025-12';

// --- SCC Extract Types ---

export const SccExtractType = {
  AHCIP: 'AHCIP',
  WCB: 'WCB',
} as const;

export type SccExtractType =
  (typeof SccExtractType)[keyof typeof SccExtractType];

// --- SCC Charge Status ---

export const SccChargeStatus = {
  ACTIVE: 'ACTIVE',
  MODIFIED: 'MODIFIED',
  DELETED: 'DELETED',
} as const;

export type SccChargeStatus =
  (typeof SccChargeStatus)[keyof typeof SccChargeStatus];

// --- SCC Row Classification ---

export const SccRowClassification = {
  VALID: 'VALID',
  WARNING: 'WARNING',
  ERROR: 'ERROR',
  DELETED: 'DELETED',
  DUPLICATE: 'DUPLICATE',
} as const;

export type SccRowClassification =
  (typeof SccRowClassification)[keyof typeof SccRowClassification];

// --- SCC Validation Severity ---

export const SccValidationSeverity = {
  BLOCKING: 'BLOCKING',
  WARNING: 'WARNING',
  INFORMATIONAL: 'INFORMATIONAL',
} as const;

export type SccValidationSeverity =
  (typeof SccValidationSeverity)[keyof typeof SccValidationSeverity];

// --- Import Source (extended from claim constants) ---

export const ConnectCareImportSource = {
  CONNECT_CARE_CSV: 'CONNECT_CARE_CSV',
  CONNECT_CARE_SFTP: 'CONNECT_CARE_SFTP',
} as const;

export type ConnectCareImportSource =
  (typeof ConnectCareImportSource)[keyof typeof ConnectCareImportSource];

// --- Import Batch Status (for CC-specific flow: PENDING → CONFIRMED / CANCELLED) ---

export const ConnectCareImportStatus = {
  PENDING: 'PENDING',
  CONFIRMED: 'CONFIRMED',
  CANCELLED: 'CANCELLED',
} as const;

export type ConnectCareImportStatus =
  (typeof ConnectCareImportStatus)[keyof typeof ConnectCareImportStatus];

// --- ICD Match Quality ---

export const IcdMatchQuality = {
  EXACT: 'EXACT',
  CLOSE: 'CLOSE',
  APPROXIMATE: 'APPROXIMATE',
  BROAD: 'BROAD',
} as const;

export type IcdMatchQuality =
  (typeof IcdMatchQuality)[keyof typeof IcdMatchQuality];

// --- WCB Column Detection Headers ---
// Used by the SCC parser to auto-detect extract type.

export const WCB_DETECTION_HEADERS = Object.freeze([
  'WCB Claim Number',
  'Employer Name',
  'Injury Date',
] as const);

// --- File Constraints ---

export const SCC_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
export const SCC_MAX_ROWS = 10_000;
export const SCC_ALLOWED_EXTENSIONS = Object.freeze([
  '.csv',
  '.CSV',
  '.xlsx',
  '.xls',
] as const);
export const SCC_RAW_FILE_RETENTION_MONTHS = 12;

// --- Duplicate Detection Composite Key Fields ---

export const SCC_DUPLICATE_KEY_FIELDS = Object.freeze([
  'patientUli',
  'encounterDate',
  'serviceCode',
  'billingProviderId',
] as const);

// --- Connect Care Audit Actions ---

export const ConnectCareAuditAction = {
  IMPORT_UPLOADED: 'connect_care.import_uploaded',
  IMPORT_CONFIRMED: 'connect_care.import_confirmed',
  IMPORT_CANCELLED: 'connect_care.import_cancelled',
  CLAIM_CORRECTION: 'connect_care.claim_correction',
  ICD_CROSSWALK_RESOLVED: 'connect_care.icd_crosswalk_resolved',
} as const;

export type ConnectCareAuditAction =
  (typeof ConnectCareAuditAction)[keyof typeof ConnectCareAuditAction];
