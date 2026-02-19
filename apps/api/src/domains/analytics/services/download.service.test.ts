// ============================================================================
// Domain 8: Download Service — Unit Tests
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Readable } from 'node:stream';
import {
  createDownloadService,
  DownloadError,
  DownloadErrorCode,
  type DownloadFileStorage,
  type DownloadAuditLogger,
  type ExpiredReportsQuery,
} from './download.service.js';
import {
  ReportType,
  ReportFormat,
  AnalyticsAuditAction,
} from '@meritum/shared/constants/analytics.constants.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';
import type { SelectGeneratedReport } from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROVIDER_ID = '00000000-0000-0000-0000-000000000001';
const OTHER_PROVIDER_ID = '00000000-0000-0000-0000-000000000002';
const REPORT_ID = '11111111-1111-1111-1111-111111111111';
const NOW = new Date('2026-02-01T12:00:00Z');

// ---------------------------------------------------------------------------
// Sample Data Factories
// ---------------------------------------------------------------------------

function sampleReportRecord(
  overrides?: Partial<SelectGeneratedReport>,
): SelectGeneratedReport {
  return {
    reportId: REPORT_ID,
    providerId: PROVIDER_ID,
    reportType: ReportType.ACCOUNTANT_SUMMARY,
    format: ReportFormat.CSV,
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '/storage/reports/report-1.csv',
    fileSizeBytes: 4096,
    downloadLinkExpiresAt: new Date('2026-03-01T00:00:00Z'),
    downloaded: false,
    scheduled: false,
    status: 'ready',
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
    markDownloaded: vi.fn().mockResolvedValue(sampleReportRecord()),
    listByProvider: vi.fn(),
    deleteExpired: vi.fn(),
    getReadyForDownload: vi.fn(),
  };
}

function createMockFileStorage(): DownloadFileStorage {
  return {
    createReadStream: vi.fn().mockReturnValue(Readable.from(['file-content'])),
    deleteFile: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockAuditLogger(): DownloadAuditLogger {
  return {
    log: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockExpiredReportsQuery(): ExpiredReportsQuery {
  return {
    listExpired: vi.fn().mockResolvedValue([]),
  };
}

function createService(overrides?: {
  reportsRepo?: GeneratedReportsRepository;
  fileStorage?: DownloadFileStorage;
  auditLogger?: DownloadAuditLogger;
  expiredReportsQuery?: ExpiredReportsQuery;
  clock?: () => Date;
}) {
  const reportsRepo = overrides?.reportsRepo ?? createMockReportsRepo();
  const fileStorage = overrides?.fileStorage ?? createMockFileStorage();
  const auditLogger = overrides?.auditLogger ?? createMockAuditLogger();
  const expiredReportsQuery =
    overrides?.expiredReportsQuery ?? createMockExpiredReportsQuery();
  const clock = overrides?.clock ?? (() => NOW);

  const service = createDownloadService({
    reportsRepo,
    fileStorage,
    auditLogger,
    expiredReportsQuery,
    clock,
  });

  return {
    service,
    reportsRepo,
    fileStorage,
    auditLogger,
    expiredReportsQuery,
  };
}

// ============================================================================
// getDownloadStream — successful download
// ============================================================================

describe('getDownloadStream', () => {
  it('returns a readable stream for a ready report', async () => {
    const { service } = createService();

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.stream).toBeInstanceOf(Readable);
  });

  it('returns correct content-type for CSV format', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ format: ReportFormat.CSV }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.contentType).toBe('text/csv');
  });

  it('returns correct content-type for PDF format', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ format: ReportFormat.PDF }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.contentType).toBe('application/pdf');
  });

  it('returns correct content-type for ZIP format', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ format: ReportFormat.ZIP }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.contentType).toBe('application/zip');
  });

  it('returns content-disposition with attachment filename', async () => {
    const { service } = createService();

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.contentDisposition).toBe(
      `attachment; filename="report-${REPORT_ID}.csv"`,
    );
  });

  it('returns file size from the report record', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ fileSizeBytes: 8192 }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.fileSizeBytes).toBe(8192);
  });

  it('creates read stream from the correct file path', async () => {
    const filePath = '/storage/reports/custom-path.csv';
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ filePath }),
    );
    const { service, fileStorage } = createService({ reportsRepo });

    await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(fileStorage.createReadStream).toHaveBeenCalledWith(filePath);
  });

  it('marks report as downloaded', async () => {
    const { service, reportsRepo } = createService();

    await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(reportsRepo.markDownloaded).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID,
    );
  });

  it('logs audit event for regular report download', async () => {
    const { service, auditLogger } = createService();

    await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(auditLogger.log).toHaveBeenCalledWith({
      action: AnalyticsAuditAction.REPORT_DOWNLOADED,
      resourceType: 'generated_report',
      resourceId: REPORT_ID,
      providerId: PROVIDER_ID,
      metadata: {
        reportType: ReportType.ACCOUNTANT_SUMMARY,
        format: ReportFormat.CSV,
      },
    });
  });

  it('logs data portability audit action for DATA_PORTABILITY reports', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        reportType: ReportType.DATA_PORTABILITY,
        format: ReportFormat.ZIP,
      }),
    );
    const { service, auditLogger } = createService({ reportsRepo });

    await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: AnalyticsAuditAction.DATA_PORTABILITY_DOWNLOADED,
      }),
    );
  });

  // ---------------------------------------------------------------------------
  // Error cases
  // ---------------------------------------------------------------------------

  it('throws NOT_FOUND when report does not exist', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service } = createService({ reportsRepo });

    await expect(
      service.getDownloadStream(REPORT_ID, PROVIDER_ID),
    ).rejects.toThrow(DownloadError);

    try {
      await service.getDownloadStream(REPORT_ID, PROVIDER_ID);
    } catch (err) {
      expect((err as DownloadError).code).toBe(DownloadErrorCode.NOT_FOUND);
    }
  });

  it('throws NOT_FOUND when report belongs to different provider', async () => {
    const reportsRepo = createMockReportsRepo();
    // getById returns null when provider doesn't match (repo handles scoping)
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service } = createService({ reportsRepo });

    await expect(
      service.getDownloadStream(REPORT_ID, OTHER_PROVIDER_ID),
    ).rejects.toThrow(DownloadError);

    try {
      await service.getDownloadStream(REPORT_ID, OTHER_PROVIDER_ID);
    } catch (err) {
      expect((err as DownloadError).code).toBe(DownloadErrorCode.NOT_FOUND);
    }
  });

  it('throws NOT_FOUND when report status is not ready', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ status: 'pending' }),
    );
    const { service } = createService({ reportsRepo });

    await expect(
      service.getDownloadStream(REPORT_ID, PROVIDER_ID),
    ).rejects.toThrow(DownloadError);

    try {
      await service.getDownloadStream(REPORT_ID, PROVIDER_ID);
    } catch (err) {
      expect((err as DownloadError).code).toBe(DownloadErrorCode.NOT_FOUND);
    }
  });

  it('throws NOT_FOUND when report status is generating', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ status: 'generating' }),
    );
    const { service } = createService({ reportsRepo });

    await expect(
      service.getDownloadStream(REPORT_ID, PROVIDER_ID),
    ).rejects.toThrow(DownloadError);
  });

  it('throws NOT_FOUND when report status is failed', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ status: 'failed' }),
    );
    const { service } = createService({ reportsRepo });

    await expect(
      service.getDownloadStream(REPORT_ID, PROVIDER_ID),
    ).rejects.toThrow(DownloadError);
  });

  it('throws EXPIRED when download link has expired', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        // Expired: set expiry in the past relative to NOW
        downloadLinkExpiresAt: new Date('2026-01-31T00:00:00Z'),
      }),
    );
    const { service } = createService({ reportsRepo });

    await expect(
      service.getDownloadStream(REPORT_ID, PROVIDER_ID),
    ).rejects.toThrow(DownloadError);

    try {
      await service.getDownloadStream(REPORT_ID, PROVIDER_ID);
    } catch (err) {
      expect((err as DownloadError).code).toBe(DownloadErrorCode.EXPIRED);
    }
  });

  it('does not mark report as downloaded when validation fails', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service } = createService({ reportsRepo });

    try {
      await service.getDownloadStream(REPORT_ID, PROVIDER_ID);
    } catch {
      // expected
    }

    expect(reportsRepo.markDownloaded).not.toHaveBeenCalled();
  });

  it('does not log audit when validation fails', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service, auditLogger } = createService({ reportsRepo });

    try {
      await service.getDownloadStream(REPORT_ID, PROVIDER_ID);
    } catch {
      // expected
    }

    expect(auditLogger.log).not.toHaveBeenCalled();
  });

  it('returns fallback content-type for unknown format', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ format: 'UNKNOWN' as any }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(result.contentType).toBe('application/octet-stream');
  });
});

// ============================================================================
// isDownloadAvailable
// ============================================================================

describe('isDownloadAvailable', () => {
  it('returns available=true for a ready, non-expired report', async () => {
    const { service } = createService();

    const result = await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(result.available).toBe(true);
  });

  it('returns expiry date when available', async () => {
    const expiresAt = new Date('2026-03-01T00:00:00Z');
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ downloadLinkExpiresAt: expiresAt }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(result.expiresAt).toEqual(expiresAt);
  });

  it('returns file size when available', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ fileSizeBytes: 12345 }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(result.fileSizeBytes).toBe(12345);
  });

  it('returns available=false when report not found', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service } = createService({ reportsRepo });

    const result = await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(result.available).toBe(false);
    expect(result.expiresAt).toBeUndefined();
    expect(result.fileSizeBytes).toBeUndefined();
  });

  it('returns available=false when report status is not ready', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({ status: 'pending' }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(result.available).toBe(false);
  });

  it('returns available=false when download link has expired', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(
      sampleReportRecord({
        downloadLinkExpiresAt: new Date('2026-01-15T00:00:00Z'),
      }),
    );
    const { service } = createService({ reportsRepo });

    const result = await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(result.available).toBe(false);
  });

  it('returns available=false for wrong provider', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service } = createService({ reportsRepo });

    const result = await service.isDownloadAvailable(
      REPORT_ID,
      OTHER_PROVIDER_ID,
    );

    expect(result.available).toBe(false);
  });

  it('does not initiate any file operations', async () => {
    const { service, fileStorage } = createService();

    await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(fileStorage.createReadStream).not.toHaveBeenCalled();
    expect(fileStorage.deleteFile).not.toHaveBeenCalled();
  });

  it('does not log any audit events', async () => {
    const { service, auditLogger } = createService();

    await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(auditLogger.log).not.toHaveBeenCalled();
  });
});

// ============================================================================
// cleanupExpiredFiles
// ============================================================================

describe('cleanupExpiredFiles', () => {
  it('returns 0 when no expired reports exist', async () => {
    const { service } = createService();

    const count = await service.cleanupExpiredFiles();

    expect(count).toBe(0);
  });

  it('deletes physical files for expired reports', async () => {
    const expiredReportsQuery = createMockExpiredReportsQuery();
    vi.mocked(expiredReportsQuery.listExpired).mockResolvedValue([
      {
        reportId: 'r1',
        providerId: 'p1',
        filePath: '/storage/reports/r1.csv',
      },
      {
        reportId: 'r2',
        providerId: 'p2',
        filePath: '/storage/reports/r2.pdf',
      },
    ]);
    const { service, fileStorage } = createService({ expiredReportsQuery });

    await service.cleanupExpiredFiles();

    expect(fileStorage.deleteFile).toHaveBeenCalledWith(
      '/storage/reports/r1.csv',
    );
    expect(fileStorage.deleteFile).toHaveBeenCalledWith(
      '/storage/reports/r2.pdf',
    );
  });

  it('updates DB status to expired for each cleaned-up report', async () => {
    const expiredReportsQuery = createMockExpiredReportsQuery();
    vi.mocked(expiredReportsQuery.listExpired).mockResolvedValue([
      {
        reportId: 'r1',
        providerId: 'p1',
        filePath: '/storage/reports/r1.csv',
      },
    ]);
    const { service, reportsRepo } = createService({ expiredReportsQuery });

    await service.cleanupExpiredFiles();

    expect(reportsRepo.updateStatus).toHaveBeenCalledWith(
      'r1',
      'p1',
      'expired',
    );
  });

  it('returns count of cleaned-up reports', async () => {
    const expiredReportsQuery = createMockExpiredReportsQuery();
    vi.mocked(expiredReportsQuery.listExpired).mockResolvedValue([
      { reportId: 'r1', providerId: 'p1', filePath: '/storage/r1.csv' },
      { reportId: 'r2', providerId: 'p2', filePath: '/storage/r2.pdf' },
      { reportId: 'r3', providerId: 'p1', filePath: '/storage/r3.zip' },
    ]);
    const { service } = createService({ expiredReportsQuery });

    const count = await service.cleanupExpiredFiles();

    expect(count).toBe(3);
  });

  it('continues cleanup when file deletion fails', async () => {
    const expiredReportsQuery = createMockExpiredReportsQuery();
    vi.mocked(expiredReportsQuery.listExpired).mockResolvedValue([
      { reportId: 'r1', providerId: 'p1', filePath: '/storage/r1.csv' },
      { reportId: 'r2', providerId: 'p2', filePath: '/storage/r2.pdf' },
    ]);
    const fileStorage = createMockFileStorage();
    vi.mocked(fileStorage.deleteFile)
      .mockRejectedValueOnce(new Error('File not found'))
      .mockResolvedValueOnce(undefined);
    const { service, reportsRepo } = createService({
      expiredReportsQuery,
      fileStorage,
    });

    const count = await service.cleanupExpiredFiles();

    // Both records should have DB status updated despite first file delete failing
    expect(reportsRepo.updateStatus).toHaveBeenCalledTimes(2);
    expect(count).toBe(2);
  });

  it('deletes file before updating DB status', async () => {
    const expiredReportsQuery = createMockExpiredReportsQuery();
    vi.mocked(expiredReportsQuery.listExpired).mockResolvedValue([
      { reportId: 'r1', providerId: 'p1', filePath: '/storage/r1.csv' },
    ]);
    const callOrder: string[] = [];
    const fileStorage = createMockFileStorage();
    vi.mocked(fileStorage.deleteFile).mockImplementation(async () => {
      callOrder.push('deleteFile');
    });
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.updateStatus).mockImplementation(async () => {
      callOrder.push('updateStatus');
      return sampleReportRecord();
    });
    const { service } = createService({
      expiredReportsQuery,
      fileStorage,
      reportsRepo,
    });

    await service.cleanupExpiredFiles();

    expect(callOrder).toEqual(['deleteFile', 'updateStatus']);
  });
});

// ============================================================================
// Provider scoping (security)
// ============================================================================

describe('provider scoping', () => {
  it('getDownloadStream scopes getById to provider', async () => {
    const { service, reportsRepo } = createService();

    await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(reportsRepo.getById).toHaveBeenCalledWith(REPORT_ID, PROVIDER_ID);
  });

  it('getDownloadStream scopes markDownloaded to provider', async () => {
    const { service, reportsRepo } = createService();

    await service.getDownloadStream(REPORT_ID, PROVIDER_ID);

    expect(reportsRepo.markDownloaded).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID,
    );
  });

  it('isDownloadAvailable scopes getById to provider', async () => {
    const { service, reportsRepo } = createService();

    await service.isDownloadAvailable(REPORT_ID, PROVIDER_ID);

    expect(reportsRepo.getById).toHaveBeenCalledWith(REPORT_ID, PROVIDER_ID);
  });

  it('wrong provider gets NOT_FOUND not FORBIDDEN', async () => {
    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.getById).mockResolvedValue(null);
    const { service } = createService({ reportsRepo });

    try {
      await service.getDownloadStream(REPORT_ID, OTHER_PROVIDER_ID);
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(DownloadError);
      expect((err as DownloadError).code).toBe(DownloadErrorCode.NOT_FOUND);
      // Must not reveal whether the resource exists
      expect((err as DownloadError).message).toBe('Report not found');
    }
  });
});
