// ============================================================================
// Domain 8: Report Routes
// 5 endpoints for report generation, status, download, and listing.
// All require authentication. Delegates need specific permissions.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  accountantReportSchema,
  dataPortabilitySchema,
  reportIdParamSchema,
  reportListQuerySchema,
  type AccountantReport,
  type DataPortability,
  type ReportIdParam,
  type ReportListQuery,
} from '@meritum/shared/schemas/validation/analytics.validation.js';
import {
  ReportType,
  ReportFormat,
  AnalyticsAuditAction,
  REPORT_DOWNLOAD_EXPIRY_DAYS,
} from '@meritum/shared/constants/analytics.constants.js';
import type { ReportGenerationService } from '../services/report-generation.service.js';
import type { DownloadService, DownloadError } from '../services/download.service.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReportRouteDeps {
  reportsRepo: GeneratedReportsRepository;
  reportGenerationService: ReportGenerationService;
  downloadService: DownloadService;
  auditLog: (entry: {
    action: string;
    providerId: string;
    details: Record<string, unknown>;
  }) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helper: extract providerId from auth context
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

// ---------------------------------------------------------------------------
// Helper: compute download link expiry date
// ---------------------------------------------------------------------------

function computeExpiryDate(reportType: string): Date {
  const now = new Date();
  const days =
    reportType === ReportType.DATA_PORTABILITY
      ? REPORT_DOWNLOAD_EXPIRY_DAYS.DATA_PORTABILITY
      : REPORT_DOWNLOAD_EXPIRY_DAYS.ON_DEMAND;
  return new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
}

// ---------------------------------------------------------------------------
// Helper: map accountant format to report type + format
// ---------------------------------------------------------------------------

function resolveAccountantFormat(format: string): {
  reportType: string;
  reportFormat: string;
} {
  switch (format) {
    case 'csv':
      return { reportType: ReportType.ACCOUNTANT_SUMMARY, reportFormat: ReportFormat.CSV };
    case 'pdf_summary':
      return { reportType: ReportType.ACCOUNTANT_SUMMARY, reportFormat: ReportFormat.PDF };
    case 'pdf_detail':
      return { reportType: ReportType.ACCOUNTANT_DETAIL, reportFormat: ReportFormat.PDF };
    default:
      return { reportType: ReportType.ACCOUNTANT_SUMMARY, reportFormat: ReportFormat.CSV };
  }
}

// ---------------------------------------------------------------------------
// Helper: sanitize report for API response (strip internal fields)
// ---------------------------------------------------------------------------

function sanitizeReport(report: Record<string, any>) {
  return {
    report_id: report.reportId,
    report_type: report.reportType,
    format: report.format,
    status: report.status,
    period_start: report.periodStart ?? null,
    period_end: report.periodEnd ?? null,
    file_size_bytes: report.status === 'ready' ? report.fileSizeBytes : null,
    download_link_expires_at:
      report.status === 'ready' && report.downloadLinkExpiresAt
        ? report.downloadLinkExpiresAt instanceof Date
          ? report.downloadLinkExpiresAt.toISOString()
          : report.downloadLinkExpiresAt
        : null,
    downloaded: report.downloaded,
    created_at:
      report.createdAt instanceof Date
        ? report.createdAt.toISOString()
        : report.createdAt,
  };
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function reportRoutes(
  app: FastifyInstance,
  opts: { deps: ReportRouteDeps },
) {
  const { reportsRepo, reportGenerationService, downloadService, auditLog } =
    opts.deps;

  // =========================================================================
  // POST /api/v1/reports/accountant
  // Generate accountant report (CSV or PDF). Async — returns report_id.
  // Permission: REPORT_EXPORT
  // =========================================================================

  app.post('/api/v1/reports/accountant', {
    schema: { body: accountantReportSchema },
    preHandler: [app.authenticate, app.authorize('REPORT_EXPORT')],
    handler: async (
      request: FastifyRequest<{ Body: AccountantReport }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      const { reportType, reportFormat } = resolveAccountantFormat(body.format);

      const report = await reportsRepo.create({
        providerId,
        reportType,
        format: reportFormat,
        periodStart: body.period_start,
        periodEnd: body.period_end,
        filePath: '',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: computeExpiryDate(reportType),
      });

      // Queue async generation
      setImmediate(() => {
        reportGenerationService
          .processReport(report.reportId, providerId)
          .catch(() => {});
      });

      auditLog({
        action: AnalyticsAuditAction.REPORT_GENERATED,
        providerId,
        details: {
          reportId: report.reportId,
          reportType,
          format: reportFormat,
          periodStart: body.period_start,
          periodEnd: body.period_end,
        },
      }).catch(() => {});

      return reply.code(201).send({
        data: {
          report_id: report.reportId,
          status: 'pending',
        },
      });
    },
  });

  // =========================================================================
  // POST /api/v1/reports/data-portability
  // Generate data portability export (ZIP). Async — returns report_id.
  // Permission: DATA_EXPORT
  // Audit: DATA_PORTABILITY_REQUESTED (sensitive action)
  // =========================================================================

  app.post('/api/v1/reports/data-portability', {
    schema: { body: dataPortabilitySchema },
    preHandler: [app.authenticate, app.authorize('DATA_EXPORT')],
    handler: async (
      request: FastifyRequest<{ Body: DataPortability }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      const report = await reportsRepo.create({
        providerId,
        reportType: ReportType.DATA_PORTABILITY,
        format: ReportFormat.ZIP,
        filePath: '',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: computeExpiryDate(ReportType.DATA_PORTABILITY),
      });

      // Queue async generation (with optional password)
      setImmediate(() => {
        reportGenerationService
          .generateDataPortabilityExport(
            report.reportId,
            providerId,
            body.password,
          )
          .catch(() => {});
      });

      auditLog({
        action: AnalyticsAuditAction.DATA_PORTABILITY_REQUESTED,
        providerId,
        details: {
          reportId: report.reportId,
          sensitive: true,
        },
      }).catch(() => {});

      return reply.code(201).send({
        data: {
          report_id: report.reportId,
          status: 'pending',
        },
      });
    },
  });

  // =========================================================================
  // GET /api/v1/reports/:id
  // Get report status. Does NOT return file_path.
  // Permission: REPORT_VIEW
  // =========================================================================

  app.get('/api/v1/reports/:id', {
    schema: { params: reportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('REPORT_VIEW')],
    handler: async (
      request: FastifyRequest<{ Params: ReportIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      const report = await reportsRepo.getById(id, providerId);

      if (!report) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      return reply.code(200).send({
        data: sanitizeReport(report),
      });
    },
  });

  // =========================================================================
  // GET /api/v1/reports/:id/download
  // Stream file download. Returns 410 for expired links.
  // Permission: REPORT_EXPORT
  // Audit: REPORT_DOWNLOADED or DATA_PORTABILITY_DOWNLOADED
  // =========================================================================

  app.get('/api/v1/reports/:id/download', {
    schema: { params: reportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('REPORT_EXPORT')],
    handler: async (
      request: FastifyRequest<{ Params: ReportIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        const result = await downloadService.getDownloadStream(id, providerId);

        return reply
          .code(200)
          .header('content-type', result.contentType)
          .header('content-disposition', result.contentDisposition)
          .header('content-length', result.fileSizeBytes)
          .send(result.stream);
      } catch (error: any) {
        if (error?.name === 'DownloadError') {
          const dlError = error as DownloadError;
          if (dlError.code === 'EXPIRED') {
            return reply.code(410).send({
              error: { code: 'GONE', message: 'Download link has expired' },
            });
          }
          return reply.code(404).send({
            error: { code: 'NOT_FOUND', message: 'Resource not found' },
          });
        }
        throw error;
      }
    },
  });

  // =========================================================================
  // GET /api/v1/reports
  // List physician's reports. Paginated.
  // Permission: REPORT_VIEW
  // =========================================================================

  app.get('/api/v1/reports', {
    schema: { querystring: reportListQuerySchema },
    preHandler: [app.authenticate, app.authorize('REPORT_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: ReportListQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await reportsRepo.listByProvider(providerId, {
        reportType: query.report_type,
        periodStart: query.start_date,
        periodEnd: query.end_date,
        limit: query.limit,
        offset: query.offset,
      });

      const page = Math.floor((query.offset ?? 0) / (query.limit ?? 20)) + 1;

      return reply.code(200).send({
        data: result.data.map(sanitizeReport),
        pagination: {
          total: result.total,
          page,
          pageSize: query.limit ?? 20,
          hasMore: (query.offset ?? 0) + (query.limit ?? 20) < result.total,
        },
      });
    },
  });
}
