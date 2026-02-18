// ============================================================================
// Domain 6: Patient Registry — Constants
// ============================================================================

// --- Gender ---

export const Gender = {
  MALE: 'M',
  FEMALE: 'F',
  OTHER: 'X',
} as const;

export type Gender = (typeof Gender)[keyof typeof Gender];

// --- Import Status ---

export const ImportStatus = {
  PENDING: 'PENDING',
  PROCESSING: 'PROCESSING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
} as const;

export type ImportStatus = (typeof ImportStatus)[keyof typeof ImportStatus];

// --- Import Source ---

export const ImportSource = {
  MANUAL: 'MANUAL',
  CSV_IMPORT: 'CSV_IMPORT',
} as const;

export type ImportSource = (typeof ImportSource)[keyof typeof ImportSource];

// --- Search Mode ---

export const PatientSearchMode = {
  PHN_LOOKUP: 'PHN_LOOKUP',
  NAME_SEARCH: 'NAME_SEARCH',
  DOB_SEARCH: 'DOB_SEARCH',
  COMBINED: 'COMBINED',
  RECENT: 'RECENT',
} as const;

export type PatientSearchMode =
  (typeof PatientSearchMode)[keyof typeof PatientSearchMode];

// --- Canadian Province Codes (for reciprocal billing) ---

export const ProvinceCode = {
  AB: 'AB',
  BC: 'BC',
  SK: 'SK',
  MB: 'MB',
  ON: 'ON',
  QC: 'QC',
  NB: 'NB',
  NS: 'NS',
  PE: 'PE',
  NL: 'NL',
  YT: 'YT',
  NT: 'NT',
  NU: 'NU',
} as const;

export type ProvinceCode = (typeof ProvinceCode)[keyof typeof ProvinceCode];

export const DEFAULT_PHN_PROVINCE: ProvinceCode = ProvinceCode.AB;

// --- Patient Audit Action Identifiers ---

export const PatientAuditAction = {
  CREATED: 'patient.created',
  UPDATED: 'patient.updated',
  DEACTIVATED: 'patient.deactivated',
  REACTIVATED: 'patient.reactivated',
  MERGED: 'patient.merged',
  IMPORT_COMPLETED: 'patient.import_completed',
  EXPORT_REQUESTED: 'patient.export_requested',
  EXPORT_DOWNLOADED: 'patient.export_downloaded',
  SEARCHED: 'patient.searched',
} as const;

export type PatientAuditAction =
  (typeof PatientAuditAction)[keyof typeof PatientAuditAction];

// --- CSV Import Column Mappings ---

export const CSV_COLUMN_MAPPINGS = Object.freeze({
  phn: Object.freeze(['PHN', 'HealthNumber', 'AB_PHN'] as const),
  first_name: Object.freeze(['FirstName', 'First', 'GivenName'] as const),
  last_name: Object.freeze(['LastName', 'Last', 'Surname'] as const),
  date_of_birth: Object.freeze(['DOB', 'DateOfBirth', 'BirthDate'] as const),
  gender: Object.freeze(['Gender', 'Sex'] as const),
  phone: Object.freeze(['Phone', 'PhoneNumber', 'Tel'] as const),
  address_line_1: Object.freeze(['Address', 'Address1', 'Street'] as const),
  city: Object.freeze(['City', 'Town'] as const),
  postal_code: Object.freeze(['PostalCode', 'Postal', 'Zip'] as const),
});

// --- CSV Gender Value Mappings ---

export const CSV_GENDER_VALUE_MAPPINGS: Readonly<Record<string, Gender>> =
  Object.freeze({
    Male: Gender.MALE,
    Female: Gender.FEMALE,
    M: Gender.MALE,
    F: Gender.FEMALE,
    X: Gender.OTHER,
  });
