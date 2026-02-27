// ============================================================================
// Connect Care SCC Parser Service (FRD CC-001 §3)
// ============================================================================
//
// Stateless parser for AHS Connect Care SCC extract CSV files.
// Supports AHCIP ("My Billing Codes") and WCB ("My WCB Codes") extracts.

import {
  SccExtractType,
  SccChargeStatus,
  SccRowClassification,
  SccValidationSeverity,
  WCB_DETECTION_HEADERS,
  SCC_MAX_ROWS,
  SCC_DUPLICATE_KEY_FIELDS,
  CURRENT_SCC_SPEC_VERSION,
} from '@meritum/shared/constants/scc.constants.js';
import { BusinessRuleError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ValidationMessage {
  severity: 'BLOCKING' | 'WARNING' | 'INFORMATIONAL';
  code: string;
  message: string;
}

export interface ParsedRow {
  rowNumber: number;
  extractType: string;
  chargeStatus: string;
  classification: string;
  patientUli?: string;
  patientName?: string;
  patientDob?: string;
  patientGender?: string;
  patientInsurer?: string;
  encounterDate: string;
  serviceCode: string;
  serviceCodeDescription?: string;
  modifiers: string[];
  diagnosticCode?: string;
  icd10SourceCode?: string;
  icdConversionFlag: boolean;
  referringProviderId?: string;
  referringProviderName?: string;
  billingProviderId?: string;
  businessArrangementNumber?: string;
  facilityCode?: string;
  functionalCentre?: string;
  encounterType?: string;
  // WCB-specific
  wcbClaimNumber?: string;
  employerName?: string;
  injuryDate?: string;
  // Validation
  validationMessages: ValidationMessage[];
}

export interface ParseResult {
  extractType: string;
  specVersion: string;
  fileName: string;
  totalRows: number;
  validCount: number;
  warningCount: number;
  errorCount: number;
  duplicateCount: number;
  deletedCount: number;
  rows: ParsedRow[];
}

export interface ProviderContext {
  providerId: string;
  billingNumber: string;
  businessArrangements: Array<{ baNumber: string; baId: string }>;
}

export interface DuplicateCheckDeps {
  findExistingClaim(
    physicianId: string,
    patientUli: string,
    encounterDate: string,
    serviceCode: string,
  ): Promise<{ claimId: string; state: string } | null>;
}

// ---------------------------------------------------------------------------
// Delimiter detection (CC-001 §3.2)
// ---------------------------------------------------------------------------

/**
 * Auto-detect the CSV delimiter by examining the first line of content.
 * Supports: comma, tab, pipe.
 */
export function detectDelimiter(content: string): string {
  const firstLine = content.split(/\r?\n/)[0] ?? '';

  // Count occurrences of each candidate
  const tabCount = (firstLine.match(/\t/g) ?? []).length;
  const pipeCount = (firstLine.match(/\|/g) ?? []).length;
  const commaCount = (firstLine.match(/,/g) ?? []).length;

  // Pick the delimiter with the most occurrences (minimum 1)
  if (tabCount > commaCount && tabCount > pipeCount && tabCount > 0) {
    return '\t';
  }
  if (pipeCount > commaCount && pipeCount > tabCount && pipeCount > 0) {
    return '|';
  }
  // Default to comma
  return ',';
}

// ---------------------------------------------------------------------------
// Extract type classification (CC-001 §3.3)
// ---------------------------------------------------------------------------

/**
 * Detect extract type (AHCIP vs WCB) based on header columns.
 * WCB extracts contain WCB-specific headers like "WCB Claim Number".
 */
export function detectExtractType(headers: string[]): string {
  const normalised = headers.map((h) => h.trim().toLowerCase());
  const wcbHeaders = WCB_DETECTION_HEADERS.map((h) => h.toLowerCase());

  const hasWcbHeaders = wcbHeaders.some((wh) =>
    normalised.some((h) => h.includes(wh)),
  );

  return hasWcbHeaders ? SccExtractType.WCB : SccExtractType.AHCIP;
}

// ---------------------------------------------------------------------------
// Modifier string parsing (CC-001 §3.5)
// ---------------------------------------------------------------------------

/**
 * Parse modifier string — supports comma-delimited ("CALL,COMP")
 * and pipe-delimited ("CALL|COMP|AGE") formats.
 */
export function parseModifiers(modifierString?: string): string[] {
  if (!modifierString || modifierString.trim() === '') {
    return [];
  }

  const trimmed = modifierString.trim();

  // Determine separator: pipe takes precedence if present
  if (trimmed.includes('|')) {
    return trimmed.split('|').map((m) => m.trim()).filter(Boolean);
  }

  return trimmed.split(',').map((m) => m.trim()).filter(Boolean);
}

// ---------------------------------------------------------------------------
// Provider identity validation (CC-001 §3.4)
// ---------------------------------------------------------------------------

/**
 * Validate that the billing provider ID and BA number in the extract
 * match the authenticated provider's profile.
 */
export function validateProviderIdentity(
  row: { billingProviderId?: string; businessArrangementNumber?: string },
  ctx: ProviderContext,
): ValidationMessage[] {
  const messages: ValidationMessage[] = [];

  if (row.billingProviderId && row.billingProviderId !== ctx.billingNumber) {
    messages.push({
      severity: SccValidationSeverity.BLOCKING,
      code: 'PROVIDER_MISMATCH',
      message: `The billing provider in this file (ID: ${row.billingProviderId}) does not match your profile (ID: ${ctx.billingNumber}). This file may belong to another provider.`,
    });
  }

  if (row.businessArrangementNumber) {
    const matchesBa = ctx.businessArrangements.some(
      (ba) => ba.baNumber === row.businessArrangementNumber,
    );
    if (!matchesBa) {
      messages.push({
        severity: SccValidationSeverity.BLOCKING,
        code: 'BA_MISMATCH',
        message: `Business Arrangement ${row.businessArrangementNumber} in this file is not registered on your profile.`,
      });
    }
  }

  return messages;
}

// ---------------------------------------------------------------------------
// Row validation rules (CC-001 §3.6)
// ---------------------------------------------------------------------------

/**
 * Apply validation rules to a single parsed row.
 * Returns validation messages with severity classification.
 */
export function validateRow(
  row: Partial<ParsedRow>,
  extractType: string,
): ValidationMessage[] {
  const messages: ValidationMessage[] = [];

  // --- BLOCKING errors ---

  // Missing Patient ULI
  if (!row.patientUli || row.patientUli.trim() === '') {
    messages.push({
      severity: SccValidationSeverity.BLOCKING,
      code: 'MISSING_ULI',
      message: 'Patient ULI is required',
    });
  } else {
    // Validate Alberta PHN format (9 digits) — out-of-province accepted as-is
    const uliTrimmed = row.patientUli.trim();
    if (uliTrimmed.length === 9 && !/^\d{9}$/.test(uliTrimmed)) {
      messages.push({
        severity: SccValidationSeverity.BLOCKING,
        code: 'INVALID_ULI_FORMAT',
        message: 'Patient ULI format is invalid',
      });
    }
  }

  // Missing Service Code
  if (!row.serviceCode || row.serviceCode.trim() === '') {
    messages.push({
      severity: SccValidationSeverity.BLOCKING,
      code: 'MISSING_SERVICE_CODE',
      message: 'Service code is required',
    });
  }

  // Future encounter date
  if (row.encounterDate) {
    const encounterDateObj = new Date(row.encounterDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (encounterDateObj > today) {
      messages.push({
        severity: SccValidationSeverity.BLOCKING,
        code: 'FUTURE_ENCOUNTER_DATE',
        message: 'Encounter date cannot be in the future',
      });
    }
  }

  // --- WARNING ---

  // ICD Conversion Flag set
  if (row.icdConversionFlag) {
    messages.push({
      severity: SccValidationSeverity.WARNING,
      code: 'ICD_CONVERSION_FAILED',
      message: 'ICD-10 to ICD-9 conversion failed. ICD-9 field left blank — physician must manually select ICD-9 before submission.',
    });
  }

  // Encounter date > 90 days old (stale claim)
  if (row.encounterDate) {
    const encounterDateObj = new Date(row.encounterDate);
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    if (encounterDateObj < ninetyDaysAgo) {
      messages.push({
        severity: SccValidationSeverity.WARNING,
        code: 'STALE_ENCOUNTER_DATE',
        message: 'Encounter date is more than 90 days old. Alberta Health may reject stale claims.',
      });
    }
  }

  // Missing Referring Provider ID (specialist claims)
  if (
    extractType === SccExtractType.AHCIP &&
    !row.referringProviderId &&
    row.serviceCode
  ) {
    // Only warn — not all codes require referral
    // Full implementation would check SOMB code GR 8 rules
  }

  return messages;
}

// ---------------------------------------------------------------------------
// CSV line parser (handles quoted fields)
// ---------------------------------------------------------------------------

function splitCsvLine(line: string, delimiter: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++; // Skip escaped quote
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === delimiter && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  fields.push(current.trim());
  return fields;
}

// ---------------------------------------------------------------------------
// AHCIP header mapping
// ---------------------------------------------------------------------------

const AHCIP_HEADER_MAP: Record<string, string> = {
  'encounter date': 'encounterDate',
  'patient uli': 'patientUli',
  'patient name': 'patientName',
  'patient dob': 'patientDob',
  'patient gender': 'patientGender',
  'patient insurer': 'patientInsurer',
  'coverage status': 'coverageStatus',
  'service code': 'serviceCode',
  'service code (somb)': 'serviceCode',
  'service code description': 'serviceCodeDescription',
  'modifier(s)': 'modifiers',
  'modifiers': 'modifiers',
  'diagnostic code': 'diagnosticCode',
  'diagnostic code (icd-9)': 'diagnosticCode',
  'icd-10-ca source code': 'icd10SourceCode',
  'icd10 source code': 'icd10SourceCode',
  'icd conversion flag': 'icdConversionFlag',
  'referring provider id': 'referringProviderId',
  'referring provider name': 'referringProviderName',
  'billing provider id': 'billingProviderId',
  'business arrangement number': 'businessArrangementNumber',
  'facility code': 'facilityCode',
  'functional centre': 'functionalCentre',
  'encounter type': 'encounterType',
  'charge status': 'chargeStatus',
};

// ---------------------------------------------------------------------------
// WCB header mapping
// ---------------------------------------------------------------------------

const WCB_HEADER_MAP: Record<string, string> = {
  'wcb claim number': 'wcbClaimNumber',
  'employer name': 'employerName',
  'injury date': 'injuryDate',
  'date of service': 'encounterDate',
  'patient uli': 'patientUli',
  'patient name': 'patientName',
  'patient dob': 'patientDob',
  'patient gender': 'patientGender',
  'service code': 'serviceCode',
  'service code (somb)': 'serviceCode',
  'diagnostic code': 'diagnosticCode',
  'diagnostic code (icd-9)': 'diagnosticCode',
  'billing provider id / ba number': 'billingProviderId',
  'billing provider id': 'billingProviderId',
  'facility code': 'facilityCode',
  'charge status': 'chargeStatus',
};

// ---------------------------------------------------------------------------
// Map headers to field names
// ---------------------------------------------------------------------------

function mapHeaders(
  headers: string[],
  extractType: string,
): Map<number, string> {
  const headerMap =
    extractType === SccExtractType.WCB ? WCB_HEADER_MAP : AHCIP_HEADER_MAP;
  const mapping = new Map<number, string>();

  for (let i = 0; i < headers.length; i++) {
    const normalised = headers[i].trim().toLowerCase();
    const fieldName = headerMap[normalised];
    if (fieldName) {
      mapping.set(i, fieldName);
    }
  }

  return mapping;
}

// ---------------------------------------------------------------------------
// Parse a single row into a ParsedRow
// ---------------------------------------------------------------------------

function parseRow(
  fields: string[],
  headerMapping: Map<number, string>,
  rowNumber: number,
  extractType: string,
): ParsedRow {
  const raw: Record<string, string> = {};

  for (const [index, fieldName] of headerMapping) {
    raw[fieldName] = fields[index] ?? '';
  }

  // Parse boolean fields
  const icdConversionFlag =
    raw.icdConversionFlag?.toLowerCase() === 'true' ||
    raw.icdConversionFlag === '1';

  // Determine charge status
  const rawChargeStatus = (raw.chargeStatus ?? 'ACTIVE').toUpperCase();
  const chargeStatus =
    rawChargeStatus === 'MODIFIED'
      ? SccChargeStatus.MODIFIED
      : rawChargeStatus === 'DELETED'
        ? SccChargeStatus.DELETED
        : SccChargeStatus.ACTIVE;

  const row: ParsedRow = {
    rowNumber,
    extractType,
    chargeStatus,
    classification: SccRowClassification.VALID, // default, refined later
    patientUli: raw.patientUli || undefined,
    patientName: raw.patientName || undefined,
    patientDob: raw.patientDob || undefined,
    patientGender: raw.patientGender || undefined,
    patientInsurer: raw.patientInsurer || undefined,
    encounterDate: raw.encounterDate ?? '',
    serviceCode: raw.serviceCode ?? '',
    serviceCodeDescription: raw.serviceCodeDescription || undefined,
    modifiers: parseModifiers(raw.modifiers),
    diagnosticCode: raw.diagnosticCode || undefined,
    icd10SourceCode: raw.icd10SourceCode || undefined,
    icdConversionFlag,
    referringProviderId: raw.referringProviderId || undefined,
    referringProviderName: raw.referringProviderName || undefined,
    billingProviderId: raw.billingProviderId || undefined,
    businessArrangementNumber: raw.businessArrangementNumber || undefined,
    facilityCode: raw.facilityCode || undefined,
    functionalCentre: raw.functionalCentre || undefined,
    encounterType: raw.encounterType || undefined,
    // WCB-specific
    wcbClaimNumber: raw.wcbClaimNumber || undefined,
    employerName: raw.employerName || undefined,
    injuryDate: raw.injuryDate || undefined,
    validationMessages: [],
  };

  return row;
}

// ---------------------------------------------------------------------------
// Classify a row based on its charge status and validation messages
// ---------------------------------------------------------------------------

function classifyRow(row: ParsedRow): void {
  // DELETED rows get their own classification
  if (row.chargeStatus === SccChargeStatus.DELETED) {
    row.classification = SccRowClassification.DELETED;
    row.validationMessages.push({
      severity: SccValidationSeverity.INFORMATIONAL,
      code: 'CHARGE_DELETED',
      message: 'This charge was deleted in Connect Care',
    });
    return;
  }

  // Check for blocking errors
  const hasBlocking = row.validationMessages.some(
    (m) => m.severity === SccValidationSeverity.BLOCKING,
  );
  if (hasBlocking) {
    row.classification = SccRowClassification.ERROR;
    return;
  }

  // Check for warnings
  const hasWarning = row.validationMessages.some(
    (m) => m.severity === SccValidationSeverity.WARNING,
  );
  if (hasWarning) {
    row.classification = SccRowClassification.WARNING;
    return;
  }

  row.classification = SccRowClassification.VALID;
}

// ---------------------------------------------------------------------------
// Main parse function (CC-001 §3)
// ---------------------------------------------------------------------------

/**
 * Parse an SCC CSV extract into structured rows with validation.
 *
 * Steps:
 * 1. Detect delimiter
 * 2. Parse header row, detect extract type
 * 3. Validate provider identity (first data row)
 * 4. Parse each row, validate, classify
 * 5. Assemble ParseResult with summary statistics
 */
export function parseSccExtract(
  content: string,
  fileName: string,
  ctx: ProviderContext,
  extractTypeOverride?: string,
): ParseResult {
  if (!content || content.trim() === '') {
    return {
      extractType: extractTypeOverride ?? SccExtractType.AHCIP,
      specVersion: CURRENT_SCC_SPEC_VERSION,
      fileName,
      totalRows: 0,
      validCount: 0,
      warningCount: 0,
      errorCount: 0,
      duplicateCount: 0,
      deletedCount: 0,
      rows: [],
    };
  }

  // 1. Detect delimiter
  const delimiter = detectDelimiter(content);

  // 2. Split into lines
  const lines = content.split(/\r?\n/).filter((line) => line.trim() !== '');
  if (lines.length === 0) {
    return {
      extractType: extractTypeOverride ?? SccExtractType.AHCIP,
      specVersion: CURRENT_SCC_SPEC_VERSION,
      fileName,
      totalRows: 0,
      validCount: 0,
      warningCount: 0,
      errorCount: 0,
      duplicateCount: 0,
      deletedCount: 0,
      rows: [],
    };
  }

  // 3. Parse header row
  const headers = splitCsvLine(lines[0], delimiter);
  const extractType = extractTypeOverride ?? detectExtractType(headers);
  const headerMapping = mapHeaders(headers, extractType);

  // 4. Enforce max rows
  const dataLines = lines.slice(1);
  if (dataLines.length > SCC_MAX_ROWS) {
    throw new BusinessRuleError(
      `File exceeds maximum row limit of ${SCC_MAX_ROWS}. Found ${dataLines.length} rows.`,
    );
  }

  // 5. Provider identity validation — check first data row for billing ID / BA
  let providerValidationDone = false;
  let providerRejected = false;
  let providerRejectionMessages: ValidationMessage[] = [];

  // 6. Parse rows
  const rows: ParsedRow[] = [];

  for (let i = 0; i < dataLines.length; i++) {
    const fields = splitCsvLine(dataLines[i], delimiter);
    const row = parseRow(fields, headerMapping, i + 1, extractType);

    // Provider identity validation (first row with billing provider ID)
    if (!providerValidationDone && row.billingProviderId) {
      const providerMessages = validateProviderIdentity(row, ctx);
      if (providerMessages.length > 0) {
        const hasBlocking = providerMessages.some(
          (m) => m.severity === SccValidationSeverity.BLOCKING,
        );
        if (hasBlocking) {
          providerRejected = true;
          providerRejectionMessages = providerMessages;
        }
      }
      providerValidationDone = true;
    }

    // If provider was rejected, mark all rows as errors
    if (providerRejected) {
      row.validationMessages.push(...providerRejectionMessages);
      row.classification = SccRowClassification.ERROR;
      rows.push(row);
      continue;
    }

    // Apply row validation rules
    const validationMessages = validateRow(row, extractType);
    row.validationMessages.push(...validationMessages);

    // Classify the row
    classifyRow(row);

    rows.push(row);
  }

  // 7. Assemble summary statistics
  let validCount = 0;
  let warningCount = 0;
  let errorCount = 0;
  let deletedCount = 0;

  for (const row of rows) {
    switch (row.classification) {
      case SccRowClassification.VALID:
        validCount++;
        break;
      case SccRowClassification.WARNING:
        warningCount++;
        break;
      case SccRowClassification.ERROR:
        errorCount++;
        break;
      case SccRowClassification.DELETED:
        deletedCount++;
        break;
    }
  }

  return {
    extractType,
    specVersion: CURRENT_SCC_SPEC_VERSION,
    fileName,
    totalRows: rows.length,
    validCount,
    warningCount,
    errorCount,
    duplicateCount: 0, // Set by detectRowDuplicates
    deletedCount,
    rows,
  };
}

// ---------------------------------------------------------------------------
// Duplicate Detection (CC-001 §6)
// ---------------------------------------------------------------------------

/**
 * Detect row duplicates by querying existing claims on composite key:
 * Patient ULI + Encounter Date + Service Code + Billing Provider ID.
 * Flags matching rows as DUPLICATE.
 */
export async function detectRowDuplicates(
  rows: ParsedRow[],
  physicianId: string,
  deps: DuplicateCheckDeps,
): Promise<{ rows: ParsedRow[]; duplicateCount: number }> {
  let duplicateCount = 0;

  for (const row of rows) {
    // Skip rows already classified as ERROR or DELETED
    if (
      row.classification === SccRowClassification.ERROR ||
      row.classification === SccRowClassification.DELETED
    ) {
      continue;
    }

    if (!row.patientUli || !row.encounterDate || !row.serviceCode) {
      continue;
    }

    const existing = await deps.findExistingClaim(
      physicianId,
      row.patientUli,
      row.encounterDate,
      row.serviceCode,
    );

    if (existing) {
      row.classification = SccRowClassification.DUPLICATE;
      row.validationMessages.push({
        severity: SccValidationSeverity.INFORMATIONAL,
        code: 'DUPLICATE_DETECTED',
        message: `Potential duplicate: existing claim ${existing.claimId} (state: ${existing.state}) matches this row`,
      });
      duplicateCount++;
    }
  }

  return { rows, duplicateCount };
}

// ---------------------------------------------------------------------------
// Correction & Deletion Handler (CC-001 §7)
// ---------------------------------------------------------------------------

export interface CorrectionResult {
  deletedDraftsRemoved: string[];
  deletedSubmittedAlerts: string[];
  modifiedDraftsUpdated: string[];
  modifiedNewDrafts: string[];
}

/**
 * Handle DELETED and MODIFIED rows from SCC extract.
 *
 * DELETED: find matching draft → remove or alert
 * MODIFIED: find matching draft → replace or create new
 */
export async function handleCorrections(
  rows: ParsedRow[],
  physicianId: string,
  deps: DuplicateCheckDeps,
): Promise<CorrectionResult> {
  const result: CorrectionResult = {
    deletedDraftsRemoved: [],
    deletedSubmittedAlerts: [],
    modifiedDraftsUpdated: [],
    modifiedNewDrafts: [],
  };

  for (const row of rows) {
    if (!row.patientUli || !row.encounterDate || !row.serviceCode) {
      continue;
    }

    if (row.chargeStatus === SccChargeStatus.DELETED) {
      const existing = await deps.findExistingClaim(
        physicianId,
        row.patientUli,
        row.encounterDate,
        row.serviceCode,
      );

      if (existing) {
        if (existing.state === 'DRAFT' || existing.state === 'VALIDATED') {
          result.deletedDraftsRemoved.push(existing.claimId);
          row.validationMessages.push({
            severity: SccValidationSeverity.INFORMATIONAL,
            code: 'DRAFT_REMOVED',
            message: `Prior draft ${existing.claimId} removed due to SCC correction`,
          });
        } else {
          result.deletedSubmittedAlerts.push(existing.claimId);
          row.validationMessages.push({
            severity: SccValidationSeverity.WARNING,
            code: 'SUBMITTED_DELETION_ALERT',
            message: `A billing code you already submitted was deleted in Connect Care. Review claim ${existing.claimId}`,
          });
        }
      }
      // If not found — no action needed
    }

    if (row.chargeStatus === SccChargeStatus.MODIFIED) {
      const existing = await deps.findExistingClaim(
        physicianId,
        row.patientUli,
        row.encounterDate,
        row.serviceCode,
      );

      if (existing) {
        if (existing.state === 'DRAFT') {
          result.modifiedDraftsUpdated.push(existing.claimId);
          row.validationMessages.push({
            severity: SccValidationSeverity.INFORMATIONAL,
            code: 'DRAFT_UPDATED',
            message: `Prior draft ${existing.claimId} updated from SCC correction`,
          });
        } else {
          result.modifiedNewDrafts.push(existing.claimId);
          row.validationMessages.push({
            severity: SccValidationSeverity.WARNING,
            code: 'MODIFIED_NEW_DRAFT',
            message: `Existing claim ${existing.claimId} has advanced past DRAFT. A new draft will be created with modified data.`,
          });
        }
      }
      // If not found — create new draft normally (handled by import confirmation)
    }
  }

  return result;
}
