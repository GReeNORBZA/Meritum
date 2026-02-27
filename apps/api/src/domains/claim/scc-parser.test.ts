import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  detectDelimiter,
  detectExtractType,
  parseModifiers,
  validateProviderIdentity,
  validateRow,
  parseSccExtract,
  detectRowDuplicates,
  handleCorrections,
  type ProviderContext,
  type DuplicateCheckDeps,
  type ParsedRow,
} from './scc-parser.service.js';

// ---------------------------------------------------------------------------
// Mock modules
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/scc.constants.js', () => ({
  SccExtractType: { AHCIP: 'AHCIP', WCB: 'WCB' },
  SccChargeStatus: { ACTIVE: 'ACTIVE', MODIFIED: 'MODIFIED', DELETED: 'DELETED' },
  SccRowClassification: {
    VALID: 'VALID', WARNING: 'WARNING', ERROR: 'ERROR',
    DELETED: 'DELETED', DUPLICATE: 'DUPLICATE',
  },
  SccValidationSeverity: { BLOCKING: 'BLOCKING', WARNING: 'WARNING', INFORMATIONAL: 'INFORMATIONAL' },
  WCB_DETECTION_HEADERS: ['WCB Claim Number', 'Employer Name', 'Injury Date'],
  SCC_MAX_ROWS: 10000,
  SCC_DUPLICATE_KEY_FIELDS: ['patientUli', 'encounterDate', 'serviceCode', 'billingProviderId'],
  CURRENT_SCC_SPEC_VERSION: '2025-12',
  SCC_MAX_FILE_SIZE_BYTES: 10485760,
  SCC_ALLOWED_EXTENSIONS: ['.csv', '.CSV', '.xlsx', '.xls'],
  ConnectCareImportSource: { CONNECT_CARE_CSV: 'CONNECT_CARE_CSV', CONNECT_CARE_SFTP: 'CONNECT_CARE_SFTP' },
  ConnectCareImportStatus: { PENDING: 'PENDING', CONFIRMED: 'CONFIRMED', CANCELLED: 'CANCELLED' },
  IcdMatchQuality: { EXACT: 'EXACT', CLOSE: 'CLOSE', APPROXIMATE: 'APPROXIMATE', BROAD: 'BROAD' },
  ConnectCareAuditAction: {
    IMPORT_UPLOADED: 'connect_care.import_uploaded',
    IMPORT_CONFIRMED: 'connect_care.import_confirmed',
    IMPORT_CANCELLED: 'connect_care.import_cancelled',
    CLAIM_CORRECTION: 'connect_care.claim_correction',
    ICD_CROSSWALK_RESOLVED: 'connect_care.icd_crosswalk_resolved',
  },
  SCC_RAW_FILE_RETENTION_MONTHS: 12,
}));

vi.mock('../../lib/errors.js', () => ({
  BusinessRuleError: class BusinessRuleError extends Error {
    constructor(msg: string) { super(msg); this.name = 'BusinessRuleError'; }
  },
}));

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const PROVIDER_ID = '11111111-1111-1111-1111-111111111111';
const BILLING_NUMBER = '12345';
const BA_NUMBER = '98765';

function makeCtx(overrides: Partial<ProviderContext> = {}): ProviderContext {
  return {
    providerId: PROVIDER_ID,
    billingNumber: BILLING_NUMBER,
    businessArrangements: [{ baNumber: BA_NUMBER, baId: 'ba-uuid-1' }],
    ...overrides,
  };
}

function makeAhcipCsv(rows: string[], delimiter = ','): string {
  const headers = [
    'Encounter Date', 'Patient ULI', 'Patient Name', 'Patient DOB',
    'Patient Gender', 'Patient Insurer', 'Coverage Status',
    'Service Code (SOMB)', 'Service Code Description', 'Modifier(s)',
    'Diagnostic Code (ICD-9)', 'ICD-10-CA Source Code', 'ICD Conversion Flag',
    'Referring Provider ID', 'Referring Provider Name',
    'Billing Provider ID', 'Business Arrangement Number',
    'Facility Code', 'Functional Centre', 'Encounter Type', 'Charge Status',
  ].join(delimiter);

  return [headers, ...rows].join('\n');
}

function makeAhcipRow(overrides: Record<string, string> = {}, delimiter = ','): string {
  const defaults: Record<string, string> = {
    encounterDate: '2025-01-15',
    patientUli: '123456789',
    patientName: 'John Doe',
    patientDob: '1980-05-20',
    patientGender: 'M',
    patientInsurer: 'ALBERTA HEALTH',
    coverageStatus: 'VALID',
    serviceCode: '03.04A',
    serviceCodeDescription: 'Office Visit',
    modifiers: '',
    diagnosticCode: '250',
    icd10SourceCode: 'E11.9',
    icdConversionFlag: 'false',
    referringProviderId: '',
    referringProviderName: '',
    billingProviderId: BILLING_NUMBER,
    businessArrangementNumber: BA_NUMBER,
    facilityCode: 'FAC01',
    functionalCentre: 'FC001',
    encounterType: 'outpatient',
    chargeStatus: 'ACTIVE',
  };

  const merged = { ...defaults, ...overrides };
  return [
    merged.encounterDate, merged.patientUli, merged.patientName, merged.patientDob,
    merged.patientGender, merged.patientInsurer, merged.coverageStatus,
    merged.serviceCode, merged.serviceCodeDescription, merged.modifiers,
    merged.diagnosticCode, merged.icd10SourceCode, merged.icdConversionFlag,
    merged.referringProviderId, merged.referringProviderName,
    merged.billingProviderId, merged.businessArrangementNumber,
    merged.facilityCode, merged.functionalCentre, merged.encounterType,
    merged.chargeStatus,
  ].join(delimiter);
}

function makeWcbCsv(rows: string[], delimiter = ','): string {
  const headers = [
    'WCB Claim Number', 'Employer Name', 'Injury Date', 'Date of Service',
    'Patient ULI', 'Patient Name', 'Patient DOB', 'Patient Gender',
    'Service Code (SOMB)', 'Diagnostic Code (ICD-9)',
    'Billing Provider ID', 'Facility Code', 'Charge Status',
  ].join(delimiter);

  return [headers, ...rows].join('\n');
}

function makeWcbRow(overrides: Record<string, string> = {}, delimiter = ','): string {
  const defaults: Record<string, string> = {
    wcbClaimNumber: 'WCB-2025-001',
    employerName: 'ACME Corp',
    injuryDate: '2025-01-10',
    dateOfService: '2025-01-15',
    patientUli: '987654321',
    patientName: 'Jane Smith',
    patientDob: '1975-03-15',
    patientGender: 'F',
    serviceCode: '03.04A',
    diagnosticCode: '250',
    billingProviderId: BILLING_NUMBER,
    facilityCode: 'FAC01',
    chargeStatus: 'ACTIVE',
  };

  const merged = { ...defaults, ...overrides };
  return [
    merged.wcbClaimNumber, merged.employerName, merged.injuryDate, merged.dateOfService,
    merged.patientUli, merged.patientName, merged.patientDob, merged.patientGender,
    merged.serviceCode, merged.diagnosticCode,
    merged.billingProviderId, merged.facilityCode, merged.chargeStatus,
  ].join(delimiter);
}

// ===========================================================================
// Tests
// ===========================================================================

describe('SCC Parser Service', () => {
  // =========================================================================
  // Delimiter Detection
  // =========================================================================

  describe('detectDelimiter', () => {
    it('should detect comma delimiter', () => {
      expect(detectDelimiter('a,b,c,d')).toBe(',');
    });

    it('should detect tab delimiter', () => {
      expect(detectDelimiter('a\tb\tc\td')).toBe('\t');
    });

    it('should detect pipe delimiter', () => {
      expect(detectDelimiter('a|b|c|d')).toBe('|');
    });

    it('should default to comma for ambiguous content', () => {
      expect(detectDelimiter('abc')).toBe(',');
    });
  });

  // =========================================================================
  // Extract Type Detection
  // =========================================================================

  describe('detectExtractType', () => {
    it('should detect AHCIP extract type', () => {
      const headers = ['Encounter Date', 'Patient ULI', 'Service Code', 'Charge Status'];
      expect(detectExtractType(headers)).toBe('AHCIP');
    });

    it('should detect WCB extract type', () => {
      const headers = ['WCB Claim Number', 'Employer Name', 'Injury Date', 'Service Code'];
      expect(detectExtractType(headers)).toBe('WCB');
    });

    it('should detect WCB with partial match', () => {
      const headers = ['Date of Service', 'WCB Claim Number', 'Patient ULI'];
      expect(detectExtractType(headers)).toBe('WCB');
    });
  });

  // =========================================================================
  // Modifier Parsing
  // =========================================================================

  describe('parseModifiers', () => {
    it('should parse comma-delimited modifiers', () => {
      expect(parseModifiers('CALL,COMP')).toEqual(['CALL', 'COMP']);
    });

    it('should parse pipe-delimited modifiers', () => {
      expect(parseModifiers('CALL|COMP|AGE')).toEqual(['CALL', 'COMP', 'AGE']);
    });

    it('should handle single modifier', () => {
      expect(parseModifiers('CALL')).toEqual(['CALL']);
    });

    it('should return empty array for empty string', () => {
      expect(parseModifiers('')).toEqual([]);
    });

    it('should return empty array for undefined', () => {
      expect(parseModifiers(undefined)).toEqual([]);
    });

    it('should trim whitespace from modifiers', () => {
      expect(parseModifiers(' CALL , COMP ')).toEqual(['CALL', 'COMP']);
    });
  });

  // =========================================================================
  // Provider Identity Validation
  // =========================================================================

  describe('validateProviderIdentity', () => {
    it('should pass when billing provider ID matches', () => {
      const ctx = makeCtx();
      const messages = validateProviderIdentity(
        { billingProviderId: BILLING_NUMBER, businessArrangementNumber: BA_NUMBER },
        ctx,
      );
      expect(messages).toHaveLength(0);
    });

    it('should reject when billing provider ID does not match', () => {
      const ctx = makeCtx();
      const messages = validateProviderIdentity(
        { billingProviderId: '99999', businessArrangementNumber: BA_NUMBER },
        ctx,
      );
      expect(messages).toHaveLength(1);
      expect(messages[0].severity).toBe('BLOCKING');
      expect(messages[0].code).toBe('PROVIDER_MISMATCH');
    });

    it('should reject when BA number does not match', () => {
      const ctx = makeCtx();
      const messages = validateProviderIdentity(
        { billingProviderId: BILLING_NUMBER, businessArrangementNumber: '00000' },
        ctx,
      );
      expect(messages).toHaveLength(1);
      expect(messages[0].severity).toBe('BLOCKING');
      expect(messages[0].code).toBe('BA_MISMATCH');
    });

    it('should reject both when both mismatch', () => {
      const ctx = makeCtx();
      const messages = validateProviderIdentity(
        { billingProviderId: '99999', businessArrangementNumber: '00000' },
        ctx,
      );
      expect(messages).toHaveLength(2);
    });
  });

  // =========================================================================
  // Row Validation
  // =========================================================================

  describe('validateRow', () => {
    it('should flag missing ULI as BLOCKING', () => {
      const messages = validateRow({ serviceCode: '03.04A', encounterDate: '2025-01-15' }, 'AHCIP');
      expect(messages.some((m) => m.code === 'MISSING_ULI')).toBe(true);
    });

    it('should flag missing service code as BLOCKING', () => {
      const messages = validateRow({ patientUli: '123456789', encounterDate: '2025-01-15' }, 'AHCIP');
      expect(messages.some((m) => m.code === 'MISSING_SERVICE_CODE')).toBe(true);
    });

    it('should flag future encounter date as BLOCKING', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 30);
      const dateStr = futureDate.toISOString().split('T')[0];
      const messages = validateRow(
        { patientUli: '123456789', serviceCode: '03.04A', encounterDate: dateStr },
        'AHCIP',
      );
      expect(messages.some((m) => m.code === 'FUTURE_ENCOUNTER_DATE')).toBe(true);
    });

    it('should flag ICD conversion failure as WARNING', () => {
      const messages = validateRow(
        { patientUli: '123456789', serviceCode: '03.04A', encounterDate: '2025-01-15', icdConversionFlag: true },
        'AHCIP',
      );
      expect(messages.some((m) => m.code === 'ICD_CONVERSION_FAILED')).toBe(true);
      expect(messages.find((m) => m.code === 'ICD_CONVERSION_FAILED')?.severity).toBe('WARNING');
    });

    it('should flag stale encounter date as WARNING', () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100);
      const dateStr = oldDate.toISOString().split('T')[0];
      const messages = validateRow(
        { patientUli: '123456789', serviceCode: '03.04A', encounterDate: dateStr },
        'AHCIP',
      );
      expect(messages.some((m) => m.code === 'STALE_ENCOUNTER_DATE')).toBe(true);
    });

    it('should return no errors for a valid row', () => {
      const messages = validateRow(
        { patientUli: '123456789', serviceCode: '03.04A', encounterDate: '2025-01-15' },
        'AHCIP',
      );
      // Only stale date warning possible (depending on current date)
      const blocking = messages.filter((m) => m.severity === 'BLOCKING');
      expect(blocking).toHaveLength(0);
    });
  });

  // =========================================================================
  // Full Parse — AHCIP
  // =========================================================================

  describe('parseSccExtract — AHCIP', () => {
    it('should parse a valid AHCIP CSV', () => {
      const csv = makeAhcipCsv([makeAhcipRow()]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.extractType).toBe('AHCIP');
      expect(result.totalRows).toBe(1);
      expect(result.rows[0].patientUli).toBe('123456789');
      expect(result.rows[0].serviceCode).toBe('03.04A');
      expect(result.rows[0].billingProviderId).toBe(BILLING_NUMBER);
    });

    it('should parse multiple rows', () => {
      const csv = makeAhcipCsv([
        makeAhcipRow({ patientUli: '111111111' }),
        makeAhcipRow({ patientUli: '222222222', serviceCode: '03.05A' }),
      ]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.totalRows).toBe(2);
      expect(result.rows[0].patientUli).toBe('111111111');
      expect(result.rows[1].patientUli).toBe('222222222');
    });

    it('should handle provider ID mismatch — reject entire file', () => {
      const csv = makeAhcipCsv([makeAhcipRow({ billingProviderId: 'WRONG' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.errorCount).toBe(1);
      expect(result.rows[0].classification).toBe('ERROR');
      const providerMsg = result.rows[0].validationMessages.find(
        (m) => m.code === 'PROVIDER_MISMATCH',
      );
      expect(providerMsg).toBeDefined();
    });

    it('should handle BA mismatch — reject entire file', () => {
      const csv = makeAhcipCsv([
        makeAhcipRow({ businessArrangementNumber: 'WRONG' }),
        makeAhcipRow({ businessArrangementNumber: 'WRONG', patientUli: '222222222' }),
      ]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.errorCount).toBe(2);
      expect(result.rows[0].validationMessages.some((m) => m.code === 'BA_MISMATCH')).toBe(true);
    });

    it('should classify DELETED rows', () => {
      const csv = makeAhcipCsv([makeAhcipRow({ chargeStatus: 'DELETED' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.deletedCount).toBe(1);
      expect(result.rows[0].classification).toBe('DELETED');
      expect(result.rows[0].chargeStatus).toBe('DELETED');
    });

    it('should handle missing ULI as ERROR', () => {
      const csv = makeAhcipCsv([makeAhcipRow({ patientUli: '' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.errorCount).toBe(1);
      expect(result.rows[0].classification).toBe('ERROR');
    });

    it('should handle missing service code as ERROR', () => {
      const csv = makeAhcipCsv([makeAhcipRow({ serviceCode: '' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.errorCount).toBe(1);
    });

    it('should parse modifiers correctly', () => {
      // Quote the modifier field so the comma is not treated as a CSV delimiter
      const csv = makeAhcipCsv([makeAhcipRow({ modifiers: '"CALL,COMP"' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.rows[0].modifiers).toEqual(['CALL', 'COMP']);
    });

    it('should parse pipe-delimited modifiers', () => {
      const csv = makeAhcipCsv([makeAhcipRow({ modifiers: 'CALL|COMP|AGE' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.rows[0].modifiers).toEqual(['CALL', 'COMP', 'AGE']);
    });

    it('should handle ICD conversion flag as WARNING', () => {
      const csv = makeAhcipCsv([makeAhcipRow({ icdConversionFlag: 'true' })]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.warningCount).toBe(1);
      expect(result.rows[0].classification).toBe('WARNING');
    });
  });

  // =========================================================================
  // Full Parse — WCB
  // =========================================================================

  describe('parseSccExtract — WCB', () => {
    it('should auto-detect WCB extract type', () => {
      const csv = makeWcbCsv([makeWcbRow()]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'wcb.csv', ctx);

      expect(result.extractType).toBe('WCB');
    });

    it('should parse WCB-specific fields', () => {
      const csv = makeWcbCsv([makeWcbRow()]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'wcb.csv', ctx);

      expect(result.rows[0].wcbClaimNumber).toBe('WCB-2025-001');
      expect(result.rows[0].employerName).toBe('ACME Corp');
      expect(result.rows[0].injuryDate).toBe('2025-01-10');
    });
  });

  // =========================================================================
  // Delimiter Variants
  // =========================================================================

  describe('parseSccExtract — delimiter variants', () => {
    it('should parse tab-delimited file', () => {
      const csv = makeAhcipCsv([makeAhcipRow({}, '\t')], '\t');
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.tsv', ctx);

      expect(result.totalRows).toBe(1);
      expect(result.rows[0].serviceCode).toBe('03.04A');
    });

    it('should parse pipe-delimited file', () => {
      const csv = makeAhcipCsv([makeAhcipRow({}, '|')], '|');
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.totalRows).toBe(1);
      expect(result.rows[0].serviceCode).toBe('03.04A');
    });
  });

  // =========================================================================
  // Edge Cases
  // =========================================================================

  describe('parseSccExtract — edge cases', () => {
    it('should handle empty file', () => {
      const ctx = makeCtx();

      const result = parseSccExtract('', 'empty.csv', ctx);

      expect(result.totalRows).toBe(0);
      expect(result.validCount).toBe(0);
    });

    it('should handle header-only file', () => {
      const csv = makeAhcipCsv([]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'headers-only.csv', ctx);

      expect(result.totalRows).toBe(0);
    });

    it('should throw BusinessRuleError for >10K rows', () => {
      // Create header + 10001 rows
      const rows = Array.from({ length: 10001 }, (_, i) =>
        makeAhcipRow({ patientUli: String(i).padStart(9, '0') }),
      );
      const csv = makeAhcipCsv(rows);
      const ctx = makeCtx();

      expect(() => parseSccExtract(csv, 'big.csv', ctx)).toThrow('exceeds maximum row limit');
    });

    it('should handle extract type override', () => {
      const csv = makeAhcipCsv([makeAhcipRow()]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx, 'WCB');

      expect(result.extractType).toBe('WCB');
    });

    it('should count summary statistics correctly', () => {
      // Use a recent date to avoid stale-date warning on the ICD warning row
      const recentDate = new Date();
      recentDate.setDate(recentDate.getDate() - 5);
      const recentDateStr = recentDate.toISOString().split('T')[0];

      const csv = makeAhcipCsv([
        makeAhcipRow({ encounterDate: recentDateStr }), // valid
        makeAhcipRow({ patientUli: '', encounterDate: recentDateStr }), // error
        makeAhcipRow({ chargeStatus: 'DELETED', encounterDate: recentDateStr }), // deleted
        makeAhcipRow({ icdConversionFlag: 'true', patientUli: '333333333', encounterDate: recentDateStr }), // warning (ICD only)
      ]);
      const ctx = makeCtx();

      const result = parseSccExtract(csv, 'test.csv', ctx);

      expect(result.totalRows).toBe(4);
      expect(result.errorCount).toBe(1);
      expect(result.deletedCount).toBe(1);
      expect(result.warningCount).toBe(1);
    });
  });

  // =========================================================================
  // Duplicate Detection
  // =========================================================================

  describe('detectRowDuplicates', () => {
    it('should flag duplicate rows', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'ACTIVE',
          classification: 'VALID', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue({
          claimId: 'existing-claim-1', state: 'DRAFT',
        }),
      };

      const result = await detectRowDuplicates(rows, PROVIDER_ID, deps);

      expect(result.duplicateCount).toBe(1);
      expect(result.rows[0].classification).toBe('DUPLICATE');
    });

    it('should not flag non-duplicate rows', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'ACTIVE',
          classification: 'VALID', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue(null),
      };

      const result = await detectRowDuplicates(rows, PROVIDER_ID, deps);

      expect(result.duplicateCount).toBe(0);
      expect(result.rows[0].classification).toBe('VALID');
    });

    it('should skip ERROR rows for duplicate detection', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'ACTIVE',
          classification: 'ERROR', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn(),
      };

      const result = await detectRowDuplicates(rows, PROVIDER_ID, deps);

      expect(result.duplicateCount).toBe(0);
      expect(deps.findExistingClaim).not.toHaveBeenCalled();
    });

    it('should skip DELETED rows for duplicate detection', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'DELETED',
          classification: 'DELETED', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn(),
      };

      const result = await detectRowDuplicates(rows, PROVIDER_ID, deps);

      expect(result.duplicateCount).toBe(0);
      expect(deps.findExistingClaim).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // Correction & Deletion Handling
  // =========================================================================

  describe('handleCorrections', () => {
    it('should remove draft for DELETED row', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'DELETED',
          classification: 'DELETED', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue({
          claimId: 'draft-1', state: 'DRAFT',
        }),
      };

      const result = await handleCorrections(rows, PROVIDER_ID, deps);

      expect(result.deletedDraftsRemoved).toContain('draft-1');
    });

    it('should alert for DELETED row when claim is submitted', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'DELETED',
          classification: 'DELETED', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue({
          claimId: 'submitted-1', state: 'SUBMITTED',
        }),
      };

      const result = await handleCorrections(rows, PROVIDER_ID, deps);

      expect(result.deletedSubmittedAlerts).toContain('submitted-1');
    });

    it('should update draft for MODIFIED row', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'MODIFIED',
          classification: 'WARNING', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue({
          claimId: 'draft-2', state: 'DRAFT',
        }),
      };

      const result = await handleCorrections(rows, PROVIDER_ID, deps);

      expect(result.modifiedDraftsUpdated).toContain('draft-2');
    });

    it('should create new draft for MODIFIED row when claim advanced past DRAFT', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'MODIFIED',
          classification: 'WARNING', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue({
          claimId: 'queued-1', state: 'QUEUED',
        }),
      };

      const result = await handleCorrections(rows, PROVIDER_ID, deps);

      expect(result.modifiedNewDrafts).toContain('queued-1');
    });

    it('should handle DELETED row with no existing claim', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'DELETED',
          classification: 'DELETED', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue(null),
      };

      const result = await handleCorrections(rows, PROVIDER_ID, deps);

      expect(result.deletedDraftsRemoved).toHaveLength(0);
      expect(result.deletedSubmittedAlerts).toHaveLength(0);
    });

    it('should handle VALIDATED claim as removable for DELETED row', async () => {
      const rows: ParsedRow[] = [
        {
          rowNumber: 1, extractType: 'AHCIP', chargeStatus: 'DELETED',
          classification: 'DELETED', patientUli: '123456789',
          encounterDate: '2025-01-15', serviceCode: '03.04A',
          modifiers: [], icdConversionFlag: false, validationMessages: [],
        },
      ];

      const deps: DuplicateCheckDeps = {
        findExistingClaim: vi.fn().mockResolvedValue({
          claimId: 'validated-1', state: 'VALIDATED',
        }),
      };

      const result = await handleCorrections(rows, PROVIDER_ID, deps);

      expect(result.deletedDraftsRemoved).toContain('validated-1');
    });
  });
});
