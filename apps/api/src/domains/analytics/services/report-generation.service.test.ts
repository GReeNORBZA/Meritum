// ============================================================================
// Domain 8: Report Generation Service — Unit Tests
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createReportGenerationService,
  buildAccountantCsv,
  type AccountantClaimRow,
  type ProviderProfile,
  type RevenueSummary,
  type DataPortabilityData,
  type FileStorage,
  type PdfGenerator,
  type ZipArchiver,
  type ReportDataAccess,
} from './report-generation.service.js';
import {
  ReportType,
  ReportFormat,
} from '@meritum/shared/constants/analytics.constants.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';
import type { SelectGeneratedReport } from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROVIDER_ID = '00000000-0000-0000-0000-000000000001';
const REPORT_ID = '11111111-1111-1111-1111-111111111111';
const PERIOD_START = '2026-01-01';
const PERIOD_END = '2026-01-31';

// ---------------------------------------------------------------------------
// Sample Data Factories
// ---------------------------------------------------------------------------

function sampleClaimRow(overrides?: Partial<AccountantClaimRow>): AccountantClaimRow {
  return {
    dateOfService: '2026-01-15',
    hscCode: '03.01A',
    modifiers: 'CMGP',
    submittedFee: '85.00',
    assessedFee: '80.00',
    paymentDate: '2026-01-25',
    baNumber: 'BA12345',
    location: 'Main Clinic',
    claimType: 'AHCIP',
    ...overrides,
  };
}

function sampleProviderProfile(): ProviderProfile {
  return {
    physicianName: 'Dr. Jane Smith',
    baNumbers: ['BA12345', 'BA67890'],
  };
}

function sampleRevenueSummary(): RevenueSummary {
  return {
    totalRevenue: '15000.00',
    revenueByBa: [
      { baNumber: 'BA12345', revenue: '10000.00' },
      { baNumber: 'BA67890', revenue: '5000.00' },
    ],
    revenueByLocation: [
      { locationName: 'Main Clinic', revenue: '12000.00' },
      { locationName: 'Rural Site', revenue: '3000.00' },
    ],
    ahcipRevenue: '12000.00',
    wcbRevenue: '3000.00',
    claimCount: 150,
    rrnpPremiumTotal: '450.00',
    adjustments: '-200.00',
    writtenOff: '100.00',
  };
}

function samplePortabilityData(): DataPortabilityData {
  return {
    claims: 'claim_id,state,date_of_service\nc1,PAID,2026-01-15',
    patients: 'patient_id,first_name,last_name\np1,John,Doe',
    auditHistory: 'audit_id,action,timestamp\na1,CREATE,2026-01-10T00:00:00Z',
    aiSuggestions: 'suggestion_id,status,category\ns1,accepted,missing_modifier',
    batches: 'batch_id,type,status\nb1,AHCIP,SUBMITTED',
    providerProfile: 'provider_id,billing_number,name\nprov1,12345,Dr. Smith',
  };
}

function sampleReportRecord(
  overrides?: Partial<SelectGeneratedReport>,
): SelectGeneratedReport {
  return {
    reportId: REPORT_ID,
    providerId: PROVIDER_ID,
    reportType: ReportType.ACCOUNTANT_SUMMARY,
    format: ReportFormat.CSV,
    periodStart: PERIOD_START,
    periodEnd: PERIOD_END,
    filePath: '',
    fileSizeBytes: 0,
    downloadLinkExpiresAt: new Date('2026-03-01T00:00:00Z'),
    downloaded: false,
    scheduled: false,
    status: 'pending',
    errorMessage: null,
    createdAt: new Date('2026-01-15T00:00:00Z'),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock Factories
// ---------------------------------------------------------------------------

function createMockReportsRepo(): GeneratedReportsRepository {
  return {
    create: vi.fn(),
    getById: vi.fn().mockResolvedValue(sampleReportRecord()),
    updateStatus: vi.fn().mockResolvedValue(sampleReportRecord()),
    markDownloaded: vi.fn(),
    listByProvider: vi.fn(),
    deleteExpired: vi.fn(),
    getReadyForDownload: vi.fn(),
  };
}

function createMockDataAccess(): ReportDataAccess {
  return {
    getPaidClaims: vi.fn().mockResolvedValue([
      sampleClaimRow(),
      sampleClaimRow({
        dateOfService: '2026-01-20',
        hscCode: '08.19C',
        modifiers: '',
        submittedFee: '120.00',
        assessedFee: '115.00',
        paymentDate: '2026-01-30',
        baNumber: 'BA67890',
        location: 'Rural Site',
        claimType: 'WCB',
      }),
    ]),
    getProviderProfile: vi.fn().mockResolvedValue(sampleProviderProfile()),
    getRevenueSummary: vi.fn().mockResolvedValue(sampleRevenueSummary()),
    getPortabilityData: vi.fn().mockResolvedValue(samplePortabilityData()),
  };
}

function createMockFileStorage(): FileStorage {
  return {
    writeFile: vi.fn().mockResolvedValue(undefined),
    getFileSize: vi.fn().mockResolvedValue(4096),
  };
}

function createMockPdfGenerator(): PdfGenerator {
  return {
    generateSummaryPdf: vi.fn().mockResolvedValue(Buffer.from('PDF-SUMMARY')),
    generateDetailPdf: vi.fn().mockResolvedValue(Buffer.from('PDF-DETAIL')),
  };
}

function createMockZipArchiver(): ZipArchiver {
  return {
    createZip: vi.fn().mockResolvedValue(Buffer.from('ZIP-CONTENT')),
  };
}

function createService(overrides?: {
  reportsRepo?: GeneratedReportsRepository;
  dataAccess?: ReportDataAccess;
  fileStorage?: FileStorage;
  pdfGenerator?: PdfGenerator;
  zipArchiver?: ZipArchiver;
  getStoragePath?: (reportId: string, format: string) => string;
}) {
  const reportsRepo = overrides?.reportsRepo ?? createMockReportsRepo();
  const dataAccess = overrides?.dataAccess ?? createMockDataAccess();
  const fileStorage = overrides?.fileStorage ?? createMockFileStorage();
  const pdfGenerator = overrides?.pdfGenerator ?? createMockPdfGenerator();
  const zipArchiver = overrides?.zipArchiver ?? createMockZipArchiver();
  const getStoragePath =
    overrides?.getStoragePath ??
    ((reportId: string, format: string) => `/reports/${reportId}.${format}`);

  const service = createReportGenerationService({
    reportsRepo,
    dataAccess,
    fileStorage,
    pdfGenerator,
    zipArchiver,
    getStoragePath,
  });

  return {
    service,
    reportsRepo,
    dataAccess,
    fileStorage,
    pdfGenerator,
    zipArchiver,
  };
}

// ============================================================================
// buildAccountantCsv — CSV format validation
// ============================================================================

describe('buildAccountantCsv', () => {
  it('produces correct CSV header row', () => {
    const csv = buildAccountantCsv([]);
    const lines = csv.split('\n');
    expect(lines[0]).toBe(
      'date_of_service,hsc_code,modifiers,submitted_fee,assessed_fee,payment_date,ba_number,location,claim_type',
    );
  });

  it('produces one row per claim', () => {
    const rows = [sampleClaimRow(), sampleClaimRow(), sampleClaimRow()];
    const csv = buildAccountantCsv(rows);
    const lines = csv.split('\n');
    // 1 header + 3 data rows
    expect(lines).toHaveLength(4);
  });

  it('formats claim data correctly in CSV columns', () => {
    const row = sampleClaimRow();
    const csv = buildAccountantCsv([row]);
    const lines = csv.split('\n');
    expect(lines[1]).toBe(
      '2026-01-15,03.01A,CMGP,85.00,80.00,2026-01-25,BA12345,Main Clinic,AHCIP',
    );
  });

  it('escapes fields containing commas', () => {
    const row = sampleClaimRow({ location: 'Clinic, Downtown' });
    const csv = buildAccountantCsv([row]);
    const lines = csv.split('\n');
    expect(lines[1]).toContain('"Clinic, Downtown"');
  });

  it('escapes fields containing double quotes', () => {
    const row = sampleClaimRow({ location: 'The "Best" Clinic' });
    const csv = buildAccountantCsv([row]);
    const lines = csv.split('\n');
    expect(lines[1]).toContain('"The ""Best"" Clinic"');
  });

  it('escapes fields containing newlines', () => {
    const row = sampleClaimRow({ modifiers: 'MOD1\nMOD2' });
    const csv = buildAccountantCsv([row]);
    const lines = csv.split('\n');
    // The field should be quoted to contain the newline
    expect(csv).toContain('"MOD1\nMOD2"');
  });

  it('handles empty rows (header only)', () => {
    const csv = buildAccountantCsv([]);
    expect(csv).toBe(
      'date_of_service,hsc_code,modifiers,submitted_fee,assessed_fee,payment_date,ba_number,location,claim_type',
    );
  });

  it('handles empty modifier field', () => {
    const row = sampleClaimRow({ modifiers: '' });
    const csv = buildAccountantCsv([row]);
    const lines = csv.split('\n');
    // The modifiers column should be empty (no quotes needed)
    const columns = lines[1].split(',');
    expect(columns[2]).toBe('');
  });
});

// ============================================================================
// generateAccountantCsv
// ============================================================================

describe('generateAccountantCsv', () => {
  it('queries paid claims for the specified period', async () => {
    const { service, dataAccess } = createService();

    await service.generateAccountantCsv(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(dataAccess.getPaidClaims).toHaveBeenCalledWith(
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );
  });

  it('writes CSV to storage', async () => {
    const { service, fileStorage } = createService();

    await service.generateAccountantCsv(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(fileStorage.writeFile).toHaveBeenCalledWith(
      `/reports/${REPORT_ID}.csv`,
      expect.stringContaining('date_of_service,hsc_code'),
    );
  });

  it('updates report status to ready with file path and size', async () => {
    const fileStorage = createMockFileStorage();
    vi.mocked(fileStorage.getFileSize).mockResolvedValue(2048);
    const { service, reportsRepo } = createService({ fileStorage });

    await service.generateAccountantCsv(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(reportsRepo.updateStatus).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID,
      'ready',
      `/reports/${REPORT_ID}.csv`,
      2048,
    );
  });

  it('scopes data query to providerId', async () => {
    const otherProviderId = '00000000-0000-0000-0000-000000000002';
    const { service, dataAccess } = createService();

    await service.generateAccountantCsv(
      REPORT_ID,
      otherProviderId,
      PERIOD_START,
      PERIOD_END,
    );

    expect(dataAccess.getPaidClaims).toHaveBeenCalledWith(
      otherProviderId,
      PERIOD_START,
      PERIOD_END,
    );
  });
});

// ============================================================================
// generateAccountantPdfSummary
// ============================================================================

describe('generateAccountantPdfSummary', () => {
  it('fetches provider profile and revenue summary', async () => {
    const { service, dataAccess } = createService();

    await service.generateAccountantPdfSummary(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(dataAccess.getProviderProfile).toHaveBeenCalledWith(PROVIDER_ID);
    expect(dataAccess.getRevenueSummary).toHaveBeenCalledWith(
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );
  });

  it('generates PDF with profile, period, and summary data', async () => {
    const { service, pdfGenerator } = createService();

    await service.generateAccountantPdfSummary(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(pdfGenerator.generateSummaryPdf).toHaveBeenCalledWith(
      sampleProviderProfile(),
      { start: PERIOD_START, end: PERIOD_END },
      sampleRevenueSummary(),
    );
  });

  it('writes generated PDF to storage', async () => {
    const { service, fileStorage } = createService();

    await service.generateAccountantPdfSummary(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(fileStorage.writeFile).toHaveBeenCalledWith(
      `/reports/${REPORT_ID}.pdf`,
      Buffer.from('PDF-SUMMARY'),
    );
  });

  it('updates report status to ready', async () => {
    const { service, reportsRepo } = createService();

    await service.generateAccountantPdfSummary(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(reportsRepo.updateStatus).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID,
      'ready',
      `/reports/${REPORT_ID}.pdf`,
      4096,
    );
  });
});

// ============================================================================
// generateAccountantPdfDetail
// ============================================================================

describe('generateAccountantPdfDetail', () => {
  it('fetches provider profile and paid claims', async () => {
    const { service, dataAccess } = createService();

    await service.generateAccountantPdfDetail(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(dataAccess.getProviderProfile).toHaveBeenCalledWith(PROVIDER_ID);
    expect(dataAccess.getPaidClaims).toHaveBeenCalledWith(
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );
  });

  it('generates detail PDF with claim rows', async () => {
    const rows = [sampleClaimRow(), sampleClaimRow({ hscCode: '08.19C' })];
    const dataAccess = createMockDataAccess();
    vi.mocked(dataAccess.getPaidClaims).mockResolvedValue(rows);
    const { service, pdfGenerator } = createService({ dataAccess });

    await service.generateAccountantPdfDetail(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(pdfGenerator.generateDetailPdf).toHaveBeenCalledWith(
      sampleProviderProfile(),
      { start: PERIOD_START, end: PERIOD_END },
      rows,
    );
  });

  it('writes PDF to storage and updates status to ready', async () => {
    const { service, fileStorage, reportsRepo } = createService();

    await service.generateAccountantPdfDetail(
      REPORT_ID,
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );

    expect(fileStorage.writeFile).toHaveBeenCalledWith(
      `/reports/${REPORT_ID}.pdf`,
      Buffer.from('PDF-DETAIL'),
    );
    expect(reportsRepo.updateStatus).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID,
      'ready',
      `/reports/${REPORT_ID}.pdf`,
      4096,
    );
  });
});

// ============================================================================
// generateDataPortabilityExport
// ============================================================================

describe('generateDataPortabilityExport', () => {
  it('fetches all portability data for the provider', async () => {
    const { service, dataAccess } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    expect(dataAccess.getPortabilityData).toHaveBeenCalledWith(PROVIDER_ID);
  });

  it('creates ZIP with all expected CSV files and README', async () => {
    const { service, zipArchiver } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    expect(zipArchiver.createZip).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ name: 'claims.csv' }),
        expect.objectContaining({ name: 'patients.csv' }),
        expect.objectContaining({ name: 'audit_history.csv' }),
        expect.objectContaining({ name: 'ai_suggestions.csv' }),
        expect.objectContaining({ name: 'batches.csv' }),
        expect.objectContaining({ name: 'provider_profile.csv' }),
        expect.objectContaining({ name: 'README.txt' }),
      ]),
      undefined,
    );
  });

  it('includes exactly 7 entries in the ZIP', async () => {
    const { service, zipArchiver } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    const entries = vi.mocked(zipArchiver.createZip).mock.calls[0][0];
    expect(entries).toHaveLength(7);
  });

  it('passes password to ZIP archiver when provided', async () => {
    const { service, zipArchiver } = createService();
    const password = 'MySecurePass123!';

    await service.generateDataPortabilityExport(
      REPORT_ID,
      PROVIDER_ID,
      password,
    );

    expect(zipArchiver.createZip).toHaveBeenCalledWith(
      expect.any(Array),
      password,
    );
  });

  it('creates ZIP without password when not provided', async () => {
    const { service, zipArchiver } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    expect(zipArchiver.createZip).toHaveBeenCalledWith(
      expect.any(Array),
      undefined,
    );
  });

  it('writes ZIP to storage and updates status', async () => {
    const fileStorage = createMockFileStorage();
    vi.mocked(fileStorage.getFileSize).mockResolvedValue(65536);
    const { service, reportsRepo } = createService({ fileStorage });

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    expect(fileStorage.writeFile).toHaveBeenCalledWith(
      `/reports/${REPORT_ID}.zip`,
      Buffer.from('ZIP-CONTENT'),
    );
    expect(reportsRepo.updateStatus).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID,
      'ready',
      `/reports/${REPORT_ID}.zip`,
      65536,
    );
  });

  it('README content describes the export format', async () => {
    const { service, zipArchiver } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    const entries = vi.mocked(zipArchiver.createZip).mock.calls[0][0];
    const readme = entries.find((e) => e.name === 'README.txt');
    expect(readme).toBeDefined();
    expect(readme!.content).toContain('Data Portability Export');
    expect(readme!.content).toContain('claims.csv');
    expect(readme!.content).toContain('patients.csv');
    expect(readme!.content).toContain('audit_history.csv');
    expect(readme!.content).toContain('ai_suggestions.csv');
    expect(readme!.content).toContain('batches.csv');
    expect(readme!.content).toContain('provider_profile.csv');
    expect(readme!.content).toContain('Health Information Act');
  });

  it('portability data includes actual CSV content from data access', async () => {
    const { service, zipArchiver } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, PROVIDER_ID);

    const entries = vi.mocked(zipArchiver.createZip).mock.calls[0][0];
    const claimsCsv = entries.find((e) => e.name === 'claims.csv');
    expect(claimsCsv!.content).toContain('claim_id,state,date_of_service');
  });
});

// ============================================================================
// processReport — Dispatcher
// ============================================================================

describe('processReport', () => {
  it('fetches report record by ID and providerId', async () => {
    const { service, reportsRepo } = createService();

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(reportsRepo.getById).toHaveBeenCalledWith(REPORT_ID, PROVIDER_ID);
  });

  it('does nothing if report not found', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service, dataAccess } = createService({ reportsRepo });

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(reportsRepo.updateStatus).not.toHaveBeenCalled();
    expect(dataAccess.getPaidClaims).not.toHaveBeenCalled();
  });

  it('sets status to generating at start', async () => {
    const { service, reportsRepo } = createService();

    await service.processReport(REPORT_ID, PROVIDER_ID);

    // First updateStatus call should be 'generating'
    const calls = vi.mocked(reportsRepo.updateStatus).mock.calls;
    expect(calls[0]).toEqual([REPORT_ID, PROVIDER_ID, 'generating']);
  });

  it('dispatches ACCOUNTANT_SUMMARY CSV to generateAccountantCsv', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        reportType: ReportType.ACCOUNTANT_SUMMARY,
        format: ReportFormat.CSV,
      }),
    );
    const { service, dataAccess } = createService({ reportsRepo });

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(dataAccess.getPaidClaims).toHaveBeenCalledWith(
      PROVIDER_ID,
      PERIOD_START,
      PERIOD_END,
    );
  });

  it('dispatches ACCOUNTANT_SUMMARY PDF to generateAccountantPdfSummary', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        reportType: ReportType.ACCOUNTANT_SUMMARY,
        format: ReportFormat.PDF,
      }),
    );
    const { service, pdfGenerator } = createService({ reportsRepo });

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(pdfGenerator.generateSummaryPdf).toHaveBeenCalled();
  });

  it('dispatches ACCOUNTANT_DETAIL CSV to generateAccountantCsv', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        reportType: ReportType.ACCOUNTANT_DETAIL,
        format: ReportFormat.CSV,
      }),
    );
    const { service, dataAccess } = createService({ reportsRepo });

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(dataAccess.getPaidClaims).toHaveBeenCalled();
  });

  it('dispatches ACCOUNTANT_DETAIL PDF to generateAccountantPdfDetail', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        reportType: ReportType.ACCOUNTANT_DETAIL,
        format: ReportFormat.PDF,
      }),
    );
    const { service, pdfGenerator } = createService({ reportsRepo });

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(pdfGenerator.generateDetailPdf).toHaveBeenCalled();
  });

  it('dispatches DATA_PORTABILITY to generateDataPortabilityExport', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        reportType: ReportType.DATA_PORTABILITY,
        format: ReportFormat.ZIP,
        periodStart: null,
        periodEnd: null,
      }),
    );
    const { service, dataAccess } = createService({ reportsRepo });

    await service.processReport(REPORT_ID, PROVIDER_ID);

    expect(dataAccess.getPortabilityData).toHaveBeenCalledWith(PROVIDER_ID);
  });

  describe('error handling', () => {
    it('sets status to failed on generation error', async () => {
      const dataAccess = createMockDataAccess();
      vi.mocked(dataAccess.getPaidClaims).mockRejectedValue(
        new Error('DB connection lost'),
      );
      const { service, reportsRepo } = createService({ dataAccess });

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      const failCall = statusCalls.find((c) => c[2] === 'failed');
      expect(failCall).toBeDefined();
      expect(failCall![2]).toBe('failed');
    });

    it('does not expose internal error details in error_message', async () => {
      const dataAccess = createMockDataAccess();
      vi.mocked(dataAccess.getPaidClaims).mockRejectedValue(
        new Error('FATAL: relation "claims" does not exist'),
      );
      const { service, reportsRepo } = createService({ dataAccess });

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      const failCall = statusCalls.find((c) => c[2] === 'failed');
      expect(failCall).toBeDefined();
      // Error message must be generic — no SQL, table names, or stack traces
      const errorMessage = failCall![5];
      expect(errorMessage).toBe(
        'Report generation failed. Please try again or contact support.',
      );
      expect(errorMessage).not.toContain('relation');
      expect(errorMessage).not.toContain('claims');
      expect(errorMessage).not.toContain('FATAL');
    });

    it('sets status to failed for unsupported report type', async () => {
      const reportsRepo = createMockReportsRepo();
      vi.mocked(reportsRepo.getById).mockResolvedValue(
        sampleReportRecord({
          reportType: 'UNKNOWN_TYPE' as any,
          format: ReportFormat.CSV,
        }),
      );
      const { service } = createService({ reportsRepo });

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      const failCall = statusCalls.find((c) => c[2] === 'failed');
      expect(failCall).toBeDefined();
    });

    it('sets status to failed on file storage error', async () => {
      const fileStorage = createMockFileStorage();
      vi.mocked(fileStorage.writeFile).mockRejectedValue(
        new Error('Disk full'),
      );
      const { service, reportsRepo } = createService({ fileStorage });

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      const failCall = statusCalls.find((c) => c[2] === 'failed');
      expect(failCall).toBeDefined();
    });

    it('sets status to failed on PDF generation error', async () => {
      const reportsRepo = createMockReportsRepo();
      vi.mocked(reportsRepo.getById).mockResolvedValue(
        sampleReportRecord({
          reportType: ReportType.ACCOUNTANT_SUMMARY,
          format: ReportFormat.PDF,
        }),
      );
      const pdfGenerator = createMockPdfGenerator();
      vi.mocked(pdfGenerator.generateSummaryPdf).mockRejectedValue(
        new Error('PDF buffer overflow'),
      );
      const { service } = createService({ reportsRepo, pdfGenerator });

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      const failCall = statusCalls.find((c) => c[2] === 'failed');
      expect(failCall).toBeDefined();
      expect(failCall![5]).not.toContain('overflow');
    });
  });

  describe('status transitions', () => {
    it('transitions pending -> generating -> ready on success', async () => {
      const { service, reportsRepo } = createService();

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      // First call: 'generating'
      expect(statusCalls[0][2]).toBe('generating');
      // Last call: 'ready'
      expect(statusCalls[statusCalls.length - 1][2]).toBe('ready');
    });

    it('transitions pending -> generating -> failed on error', async () => {
      const dataAccess = createMockDataAccess();
      vi.mocked(dataAccess.getPaidClaims).mockRejectedValue(new Error('fail'));
      const { service, reportsRepo } = createService({ dataAccess });

      await service.processReport(REPORT_ID, PROVIDER_ID);

      const statusCalls = vi.mocked(reportsRepo.updateStatus).mock.calls;
      expect(statusCalls[0][2]).toBe('generating');
      expect(statusCalls[1][2]).toBe('failed');
    });
  });
});

// ============================================================================
// Provider scoping (security)
// ============================================================================

describe('provider scoping', () => {
  const OTHER_PROVIDER = '00000000-0000-0000-0000-000000000099';

  it('processReport scopes getById to provider', async () => {
    const { service, reportsRepo } = createService();

    await service.processReport(REPORT_ID, OTHER_PROVIDER);

    expect(reportsRepo.getById).toHaveBeenCalledWith(REPORT_ID, OTHER_PROVIDER);
  });

  it('generateAccountantCsv passes provider to data access', async () => {
    const { service, dataAccess } = createService();

    await service.generateAccountantCsv(
      REPORT_ID,
      OTHER_PROVIDER,
      PERIOD_START,
      PERIOD_END,
    );

    expect(dataAccess.getPaidClaims).toHaveBeenCalledWith(
      OTHER_PROVIDER,
      PERIOD_START,
      PERIOD_END,
    );
  });

  it('generateAccountantPdfSummary passes provider to data access', async () => {
    const { service, dataAccess } = createService();

    await service.generateAccountantPdfSummary(
      REPORT_ID,
      OTHER_PROVIDER,
      PERIOD_START,
      PERIOD_END,
    );

    expect(dataAccess.getProviderProfile).toHaveBeenCalledWith(OTHER_PROVIDER);
    expect(dataAccess.getRevenueSummary).toHaveBeenCalledWith(
      OTHER_PROVIDER,
      PERIOD_START,
      PERIOD_END,
    );
  });

  it('generateDataPortabilityExport passes provider to data access', async () => {
    const { service, dataAccess } = createService();

    await service.generateDataPortabilityExport(REPORT_ID, OTHER_PROVIDER);

    expect(dataAccess.getPortabilityData).toHaveBeenCalledWith(OTHER_PROVIDER);
  });

  it('updateStatus calls are scoped to provider', async () => {
    const { service, reportsRepo } = createService();

    await service.generateAccountantCsv(
      REPORT_ID,
      OTHER_PROVIDER,
      PERIOD_START,
      PERIOD_END,
    );

    expect(reportsRepo.updateStatus).toHaveBeenCalledWith(
      REPORT_ID,
      OTHER_PROVIDER,
      'ready',
      expect.any(String),
      expect.any(Number),
    );
  });
});
