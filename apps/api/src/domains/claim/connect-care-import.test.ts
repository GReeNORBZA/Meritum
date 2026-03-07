import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  validateFile,
  generateFilePath,
  computeFileHash,
  uploadAndParse,
  confirmImport,
  cancelImport,
  getImportHistory,
  getImportBatchDetail,
  type ConnectCareImportDeps,
  type UploadedFile,
} from './connect-care-import.service.js';

// ---------------------------------------------------------------------------
// Mock scc-parser.service — we test the parser separately
// ---------------------------------------------------------------------------

const mockParseSccExtract = vi.fn();
const mockDetectRowDuplicates = vi.fn();
const mockHandleCorrections = vi.fn();

vi.mock('./scc-parser.service.js', () => ({
  parseSccExtract: (...args: any[]) => mockParseSccExtract(...args),
  detectRowDuplicates: (...args: any[]) => mockDetectRowDuplicates(...args),
  handleCorrections: (...args: any[]) => mockHandleCorrections(...args),
}));

// ---------------------------------------------------------------------------
// Mock shared constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/scc.constants.js', () => ({
  SCC_MAX_FILE_SIZE_BYTES: 10 * 1024 * 1024,
  SCC_ALLOWED_EXTENSIONS: ['.csv', '.CSV', '.xlsx', '.xls'],
  CURRENT_SCC_SPEC_VERSION: '2025-12',
  ConnectCareImportStatus: {
    PENDING: 'PENDING',
    CONFIRMED: 'CONFIRMED',
    CANCELLED: 'CANCELLED',
  },
  ConnectCareAuditAction: {
    IMPORT_UPLOADED: 'connect_care.import_uploaded',
    IMPORT_CONFIRMED: 'connect_care.import_confirmed',
    IMPORT_CANCELLED: 'connect_care.import_cancelled',
    CLAIM_CORRECTION: 'connect_care.claim_correction',
    ICD_CROSSWALK_RESOLVED: 'connect_care.icd_crosswalk_resolved',
  },
  SccRowClassification: {
    VALID: 'VALID',
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    DELETED: 'DELETED',
    DUPLICATE: 'DUPLICATE',
  },
}));

vi.mock('@meritum/shared/constants/claim.constants.js', () => ({
  ClaimImportSource: {
    MANUAL: 'MANUAL',
    EMR_IMPORT: 'EMR_IMPORT',
    ED_SHIFT: 'ED_SHIFT',
    CONNECT_CARE_CSV: 'CONNECT_CARE_CSV',
    CONNECT_CARE_SFTP: 'CONNECT_CARE_SFTP',
    EMR_GENERIC: 'EMR_GENERIC',
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDeps(overrides?: Partial<ConnectCareImportDeps>): ConnectCareImportDeps {
  return {
    repo: {
      createImportBatch: vi.fn().mockResolvedValue({ importBatchId: 'batch-001' }),
      findImportBatchById: vi.fn().mockResolvedValue({
        importBatchId: 'batch-001',
        confirmationStatus: 'PENDING',
        fileName: 'test.csv',
      }),
      updateImportBatchStatus: vi.fn().mockResolvedValue({}),
      listImportBatches: vi.fn().mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
      }),
      createClaim: vi.fn().mockResolvedValue({ claimId: 'claim-001' }),
      appendClaimAudit: vi.fn().mockResolvedValue({}),
    },
    duplicateCheck: {
      findExistingClaim: vi.fn().mockResolvedValue(undefined),
    } as any,
    auditLog: {
      log: vi.fn().mockResolvedValue(undefined),
    },
    ...overrides,
  };
}

function makeFile(overrides?: Partial<UploadedFile>): UploadedFile {
  return {
    fileName: 'extract.csv',
    content: 'header1,header2\nval1,val2',
    size: 100,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Connect Care Import Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockParseSccExtract.mockReturnValue({
      rows: [],
      totalRows: 0,
      validCount: 0,
      warningCount: 0,
      errorCount: 0,
      duplicateCount: 0,
      deletedCount: 0,
      extractType: 'AHCIP',
    });
    mockDetectRowDuplicates.mockResolvedValue({ duplicateCount: 0 });
    mockHandleCorrections.mockResolvedValue(undefined);
  });

  // =========================================================================
  // File Validation
  // =========================================================================

  describe('validateFile', () => {
    it('accepts a valid .csv file', () => {
      expect(() => validateFile(makeFile())).not.toThrow();
    });

    it('accepts a valid .xlsx file', () => {
      expect(() => validateFile(makeFile({ fileName: 'data.xlsx' }))).not.toThrow();
    });

    it('rejects an unsupported file extension', () => {
      expect(() => validateFile(makeFile({ fileName: 'data.pdf' }))).toThrow(
        /Invalid file extension/,
      );
    });

    it('rejects a file exceeding the size limit', () => {
      const oversized = makeFile({ size: 11 * 1024 * 1024 });
      expect(() => validateFile(oversized)).toThrow(/exceeds maximum size/);
    });

    it('accepts a file exactly at the size limit', () => {
      const exact = makeFile({ size: 10 * 1024 * 1024 });
      expect(() => validateFile(exact)).not.toThrow();
    });
  });

  // =========================================================================
  // Generate File Path
  // =========================================================================

  describe('generateFilePath', () => {
    it('returns a path in the expected format', () => {
      const path = generateFilePath('phys-123', 'extract.csv');
      expect(path).toMatch(/^imports\/phys-123\/\d{4}-\d{2}\/[0-9a-f-]+\.csv$/);
    });

    it('preserves the original file extension', () => {
      const path = generateFilePath('phys-123', 'report.xlsx');
      expect(path).toMatch(/\.xlsx$/);
    });
  });

  // =========================================================================
  // Compute File Hash
  // =========================================================================

  describe('computeFileHash', () => {
    it('returns a 64-character hex string (SHA-256)', () => {
      const hash = computeFileHash('hello world');
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]+$/);
    });

    it('returns the same hash for the same content', () => {
      expect(computeFileHash('test')).toBe(computeFileHash('test'));
    });

    it('returns different hashes for different content', () => {
      expect(computeFileHash('abc')).not.toBe(computeFileHash('xyz'));
    });

    it('works with Buffer input', () => {
      const hash = computeFileHash(Buffer.from('hello'));
      expect(hash).toHaveLength(64);
    });
  });

  // =========================================================================
  // Upload & Parse
  // =========================================================================

  describe('uploadAndParse', () => {
    it('creates an import batch and returns results', async () => {
      const deps = makeDeps();
      const providerCtx = { providerId: 'PROV1', billingNumber: 'BN001', businessArrangements: [{ baNumber: 'BA1', baId: 'ba-001' }] };

      mockParseSccExtract.mockReturnValue({
        rows: [{ rowNumber: 1, classification: 'VALID' }],
        totalRows: 1,
        validCount: 1,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'AHCIP',
      });

      const result = await uploadAndParse(
        deps, 'phys-001', 'actor-001', providerCtx, makeFile(),
      );

      expect(result.importBatchId).toBe('batch-001');
      expect(result.parseResult.totalRows).toBe(1);
      expect(result.rawFilePath).toMatch(/^imports\/phys-001\//);
      expect(deps.repo.createImportBatch).toHaveBeenCalledOnce();
    });

    it('rejects an invalid file extension before parsing', async () => {
      const deps = makeDeps();
      const providerCtx = { providerId: 'PROV1', billingNumber: 'BN001', businessArrangements: [{ baNumber: 'BA1', baId: 'ba-001' }] };

      await expect(
        uploadAndParse(deps, 'phys-001', 'actor-001', providerCtx, makeFile({ fileName: 'data.json' })),
      ).rejects.toThrow(/Invalid file extension/);

      expect(mockParseSccExtract).not.toHaveBeenCalled();
    });

    it('runs duplicate detection after parsing', async () => {
      const deps = makeDeps();
      const providerCtx = { providerId: 'PROV1', billingNumber: 'BN001', businessArrangements: [{ baNumber: 'BA1', baId: 'ba-001' }] };

      mockParseSccExtract.mockReturnValue({
        rows: [{ rowNumber: 1 }],
        totalRows: 1,
        validCount: 1,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'AHCIP',
      });
      mockDetectRowDuplicates.mockResolvedValue({ duplicateCount: 1 });

      const result = await uploadAndParse(
        deps, 'phys-001', 'actor-001', providerCtx, makeFile(),
      );

      expect(mockDetectRowDuplicates).toHaveBeenCalledOnce();
      expect(result.parseResult.duplicateCount).toBe(1);
    });

    it('runs correction handling after duplicate detection', async () => {
      const deps = makeDeps();
      const providerCtx = { providerId: 'PROV1', billingNumber: 'BN001', businessArrangements: [{ baNumber: 'BA1', baId: 'ba-001' }] };

      await uploadAndParse(deps, 'phys-001', 'actor-001', providerCtx, makeFile());

      expect(mockHandleCorrections).toHaveBeenCalledOnce();
    });

    it('calls audit log when available', async () => {
      const deps = makeDeps();
      const providerCtx = { providerId: 'PROV1', billingNumber: 'BN001', businessArrangements: [{ baNumber: 'BA1', baId: 'ba-001' }] };

      await uploadAndParse(deps, 'phys-001', 'actor-001', providerCtx, makeFile());

      expect(deps.auditLog!.log).toHaveBeenCalledWith(
        'connect_care.import_uploaded',
        expect.objectContaining({ physicianId: 'phys-001' }),
      );
    });

    it('handles Buffer content correctly', async () => {
      const deps = makeDeps();
      const providerCtx = { providerId: 'PROV1', billingNumber: 'BN001', businessArrangements: [{ baNumber: 'BA1', baId: 'ba-001' }] };
      const bufferFile = makeFile({ content: Buffer.from('csv,content\na,b') });

      await uploadAndParse(deps, 'phys-001', 'actor-001', providerCtx, bufferFile);

      expect(mockParseSccExtract).toHaveBeenCalledWith(
        'csv,content\na,b',
        'extract.csv',
        providerCtx,
        undefined,
      );
    });
  });

  // =========================================================================
  // Confirm Import
  // =========================================================================

  describe('confirmImport', () => {
    it('creates claims for VALID and WARNING rows', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
          { rowNumber: 2, classification: 'WARNING', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-16' },
        ],
        totalRows: 2,
        validCount: 1,
        warningCount: 1,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'AHCIP',
      } as any;

      const result = await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(result.claimsCreated).toBe(2);
      expect(result.claimsSkipped).toBe(0);
      expect(result.status).toBe('CONFIRMED');
      expect(deps.repo.createClaim).toHaveBeenCalledTimes(2);
    });

    it('skips ERROR rows', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
          { rowNumber: 2, classification: 'ERROR', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-16' },
        ],
        totalRows: 2,
        validCount: 1,
        warningCount: 0,
        errorCount: 1,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'AHCIP',
      } as any;

      const result = await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(result.claimsCreated).toBe(1);
      expect(result.claimsSkipped).toBe(1);
    });

    it('skips DUPLICATE rows', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
          { rowNumber: 2, classification: 'DUPLICATE', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-16' },
        ],
        totalRows: 2,
        validCount: 1,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 1,
        deletedCount: 0,
        extractType: 'AHCIP',
      } as any;

      const result = await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(result.claimsCreated).toBe(1);
      expect(result.claimsSkipped).toBe(1);
    });

    it('skips DELETED rows', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
          { rowNumber: 2, classification: 'DELETED', extractType: 'AHCIP', chargeStatus: 'DELETED', encounterDate: '2026-01-16' },
        ],
        totalRows: 2,
        validCount: 1,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 1,
        extractType: 'AHCIP',
      } as any;

      const result = await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(result.claimsCreated).toBe(1);
      expect(result.claimsSkipped).toBe(1);
    });

    it('respects excluded row numbers', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
          { rowNumber: 2, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-16' },
          { rowNumber: 3, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-17' },
        ],
        totalRows: 3,
        validCount: 3,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'AHCIP',
      } as any;

      const result = await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult, [2]);

      expect(result.claimsCreated).toBe(2);
      expect(result.claimsSkipped).toBe(1);
    });

    it('throws NotFoundError when batch does not exist', async () => {
      const deps = makeDeps();
      (deps.repo.findImportBatchById as any).mockResolvedValue(undefined);

      const parseResult = { rows: [], totalRows: 0 } as any;

      await expect(
        confirmImport(deps, 'phys-001', 'actor-001', 'missing-batch', parseResult),
      ).rejects.toThrow(/not found/i);
    });

    it('throws BusinessRuleError when batch is already CONFIRMED', async () => {
      const deps = makeDeps();
      (deps.repo.findImportBatchById as any).mockResolvedValue({
        importBatchId: 'batch-001',
        confirmationStatus: 'CONFIRMED',
        fileName: 'test.csv',
      });

      const parseResult = { rows: [], totalRows: 0 } as any;

      await expect(
        confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult),
      ).rejects.toThrow(/already CONFIRMED/);
    });

    it('updates batch status to COMPLETED after confirmation', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'AHCIP', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
        ],
        totalRows: 1,
        validCount: 1,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'AHCIP',
      } as any;

      await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(deps.repo.updateImportBatchStatus).toHaveBeenCalledWith(
        'batch-001', 'phys-001', 'COMPLETED',
        expect.objectContaining({ successCount: 1 }),
      );
    });

    it('creates WCB claims with WCB claim type', async () => {
      const deps = makeDeps();
      const parseResult = {
        rows: [
          { rowNumber: 1, classification: 'VALID', extractType: 'WCB', chargeStatus: 'ACTIVE', encounterDate: '2026-01-15' },
        ],
        totalRows: 1,
        validCount: 1,
        warningCount: 0,
        errorCount: 0,
        duplicateCount: 0,
        deletedCount: 0,
        extractType: 'WCB',
      } as any;

      await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(deps.repo.createClaim).toHaveBeenCalledWith(
        expect.objectContaining({ claimType: 'WCB' }),
      );
    });

    it('calls audit log on confirmation', async () => {
      const deps = makeDeps();
      const parseResult = { rows: [], totalRows: 0, validCount: 0, warningCount: 0, errorCount: 0, duplicateCount: 0, deletedCount: 0, extractType: 'AHCIP' } as any;

      await confirmImport(deps, 'phys-001', 'actor-001', 'batch-001', parseResult);

      expect(deps.auditLog!.log).toHaveBeenCalledWith(
        'connect_care.import_confirmed',
        expect.objectContaining({ importBatchId: 'batch-001' }),
      );
    });
  });

  // =========================================================================
  // Cancel Import
  // =========================================================================

  describe('cancelImport', () => {
    it('cancels a pending import batch', async () => {
      const deps = makeDeps();

      const result = await cancelImport(deps, 'phys-001', 'batch-001');

      expect(result.status).toBe('CANCELLED');
      expect(result.importBatchId).toBe('batch-001');
      expect(deps.repo.updateImportBatchStatus).toHaveBeenCalledWith(
        'batch-001', 'phys-001', 'FAILED',
        expect.objectContaining({ successCount: 0, errorCount: 0 }),
      );
    });

    it('throws NotFoundError when batch does not exist', async () => {
      const deps = makeDeps();
      (deps.repo.findImportBatchById as any).mockResolvedValue(undefined);

      await expect(
        cancelImport(deps, 'phys-001', 'missing-batch'),
      ).rejects.toThrow(/not found/i);
    });

    it('throws BusinessRuleError when batch is already CANCELLED', async () => {
      const deps = makeDeps();
      (deps.repo.findImportBatchById as any).mockResolvedValue({
        importBatchId: 'batch-001',
        confirmationStatus: 'CANCELLED',
      });

      await expect(
        cancelImport(deps, 'phys-001', 'batch-001'),
      ).rejects.toThrow(/already CANCELLED/);
    });

    it('calls audit log on cancellation', async () => {
      const deps = makeDeps();

      await cancelImport(deps, 'phys-001', 'batch-001');

      expect(deps.auditLog!.log).toHaveBeenCalledWith(
        'connect_care.import_cancelled',
        expect.objectContaining({ importBatchId: 'batch-001', physicianId: 'phys-001' }),
      );
    });
  });

  // =========================================================================
  // Import History
  // =========================================================================

  describe('getImportHistory', () => {
    it('delegates to repo.listImportBatches with pagination', async () => {
      const deps = makeDeps();
      const expected = {
        data: [{ importBatchId: 'batch-001' }],
        pagination: { total: 1, page: 1, pageSize: 25, hasMore: false },
      };
      (deps.repo.listImportBatches as any).mockResolvedValue(expected);

      const result = await getImportHistory(deps, 'phys-001', 1, 25);

      expect(result).toEqual(expected);
      expect(deps.repo.listImportBatches).toHaveBeenCalledWith('phys-001', 1, 25);
    });
  });

  // =========================================================================
  // Import Batch Detail
  // =========================================================================

  describe('getImportBatchDetail', () => {
    it('returns the batch when found', async () => {
      const deps = makeDeps();
      const batch = { importBatchId: 'batch-001', confirmationStatus: 'PENDING' };
      (deps.repo.findImportBatchById as any).mockResolvedValue(batch);

      const result = await getImportBatchDetail(deps, 'phys-001', 'batch-001');

      expect(result).toEqual(batch);
    });

    it('throws NotFoundError when batch does not exist', async () => {
      const deps = makeDeps();
      (deps.repo.findImportBatchById as any).mockResolvedValue(undefined);

      await expect(
        getImportBatchDetail(deps, 'phys-001', 'missing-batch'),
      ).rejects.toThrow(/not found/i);
    });
  });
});
