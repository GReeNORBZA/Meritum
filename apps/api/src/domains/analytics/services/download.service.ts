// ============================================================================
// Domain 8: Download Service
// Manages secure file downloads for generated reports. Enforces provider
// scoping, download link expiry, and audit logging.
// ============================================================================

import { Readable } from 'node:stream';
import {
  ReportFormat,
  ReportType,
  AnalyticsAuditAction,
} from '@meritum/shared/constants/analytics.constants.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';
import type { SelectGeneratedReport } from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Abstraction for file storage with streaming and deletion support. */
export interface DownloadFileStorage {
  createReadStream(filePath: string): Readable;
  deleteFile(filePath: string): Promise<void>;
}

/** Audit logger interface for recording download events. */
export interface DownloadAuditLogger {
  log(entry: {
    action: string;
    resourceType: string;
    resourceId: string;
    providerId: string;
    metadata?: Record<string, unknown>;
  }): Promise<void>;
}

/** Queries for expired reports (system-level, not provider-scoped). */
export interface ExpiredReportsQuery {
  listExpired(): Promise<
    Array<{ reportId: string; providerId: string; filePath: string }>
  >;
}

/** Result from getDownloadStream — headers + stream for the response. */
export interface DownloadStreamResult {
  stream: Readable;
  contentType: string;
  contentDisposition: string;
  fileSizeBytes: number;
}

/** Result from isDownloadAvailable — availability check without initiating download. */
export interface DownloadAvailability {
  available: boolean;
  expiresAt?: Date;
  fileSizeBytes?: number;
}

/** Error codes the download service can produce. */
export const DownloadErrorCode = {
  NOT_FOUND: 'NOT_FOUND',
  EXPIRED: 'EXPIRED',
} as const;

export type DownloadErrorCode =
  (typeof DownloadErrorCode)[keyof typeof DownloadErrorCode];

export class DownloadError extends Error {
  constructor(
    public readonly code: DownloadErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'DownloadError';
  }
}

// ---------------------------------------------------------------------------
// Content-Type Mapping
// ---------------------------------------------------------------------------

const FORMAT_CONTENT_TYPE: Record<string, string> = {
  [ReportFormat.CSV]: 'text/csv',
  [ReportFormat.PDF]: 'application/pdf',
  [ReportFormat.ZIP]: 'application/zip',
};

function getContentType(format: string): string {
  return FORMAT_CONTENT_TYPE[format] ?? 'application/octet-stream';
}

function getFileExtension(format: string): string {
  return format.toLowerCase();
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

interface DownloadServiceDeps {
  reportsRepo: GeneratedReportsRepository;
  fileStorage: DownloadFileStorage;
  auditLogger: DownloadAuditLogger;
  expiredReportsQuery: ExpiredReportsQuery;
  clock?: () => Date;
}

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createDownloadService(deps: DownloadServiceDeps) {
  const {
    reportsRepo,
    fileStorage,
    auditLogger,
    expiredReportsQuery,
    clock = () => new Date(),
  } = deps;

  /**
   * Fetch a report, verifying ownership and status, distinguishing between
   * "not found / wrong provider / wrong status" (404) and "expired" (410).
   */
  async function resolveReport(
    reportId: string,
    providerId: string,
  ): Promise<SelectGeneratedReport> {
    const report = await reportsRepo.getById(reportId, providerId);

    if (!report) {
      throw new DownloadError(DownloadErrorCode.NOT_FOUND, 'Report not found');
    }

    if (report.status !== 'ready') {
      throw new DownloadError(DownloadErrorCode.NOT_FOUND, 'Report not found');
    }

    const now = clock();
    if (report.downloadLinkExpiresAt < now) {
      throw new DownloadError(
        DownloadErrorCode.EXPIRED,
        'Download link has expired',
      );
    }

    return report;
  }

  /**
   * Get a readable stream for the report file, along with response headers.
   * Verifies: report exists, belongs to provider, status is 'ready', link not expired.
   * Marks the report as downloaded and writes an audit log entry.
   */
  async function getDownloadStream(
    reportId: string,
    providerId: string,
  ): Promise<DownloadStreamResult> {
    const report = await resolveReport(reportId, providerId);

    const stream = fileStorage.createReadStream(report.filePath);

    const contentType = getContentType(report.format);
    const ext = getFileExtension(report.format);
    const filename = `report-${reportId}.${ext}`;
    const contentDisposition = `attachment; filename="${filename}"`;

    // Mark as downloaded
    await reportsRepo.markDownloaded(reportId, providerId);

    // Audit log the download event
    const auditAction =
      report.reportType === ReportType.DATA_PORTABILITY
        ? AnalyticsAuditAction.DATA_PORTABILITY_DOWNLOADED
        : AnalyticsAuditAction.REPORT_DOWNLOADED;

    await auditLogger.log({
      action: auditAction,
      resourceType: 'generated_report',
      resourceId: reportId,
      providerId,
      metadata: {
        reportType: report.reportType,
        format: report.format,
      },
    });

    return {
      stream,
      contentType,
      contentDisposition,
      fileSizeBytes: report.fileSizeBytes,
    };
  }

  /**
   * Check download availability without initiating a download.
   * Returns availability status, expiry time, and file size.
   */
  async function isDownloadAvailable(
    reportId: string,
    providerId: string,
  ): Promise<DownloadAvailability> {
    const report = await reportsRepo.getById(reportId, providerId);

    if (!report || report.status !== 'ready') {
      return { available: false };
    }

    const now = clock();
    if (report.downloadLinkExpiresAt < now) {
      return { available: false };
    }

    return {
      available: true,
      expiresAt: report.downloadLinkExpiresAt,
      fileSizeBytes: report.fileSizeBytes,
    };
  }

  /**
   * Delete physical files for expired reports and update their DB status to 'expired'.
   * Called by the cleanup cron job. Returns the count of cleaned-up reports.
   */
  async function cleanupExpiredFiles(): Promise<number> {
    const expired = await expiredReportsQuery.listExpired();

    let cleanedCount = 0;

    for (const record of expired) {
      // Delete the physical file first
      try {
        await fileStorage.deleteFile(record.filePath);
      } catch {
        // File may already be deleted — continue with DB update
      }

      // Update status to 'expired' in the database
      await reportsRepo.updateStatus(
        record.reportId,
        record.providerId,
        'expired',
      );

      cleanedCount++;
    }

    return cleanedCount;
  }

  return {
    getDownloadStream,
    isDownloadAvailable,
    cleanupExpiredFiles,
  };
}

export type DownloadService = ReturnType<typeof createDownloadService>;
