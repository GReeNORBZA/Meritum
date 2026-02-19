// ============================================================================
// Domain 8: Analytics Reports — Integration Tests
// End-to-end tests for report generation, polling, download, and listing.
// Tests accountant CSV/PDF, data portability ZIP, expiry behaviour.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  reportRoutes,
  type ReportRouteDeps,
} from '../../../src/domains/analytics/routes/report.routes.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '20000000-0000-4000-8000-000000000001';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');
const REPORT_ID_1 = '20000000-0000-4000-8000-000000000010';
const REPORT_ID_2 = '20000000-0000-4000-8000-000000000020';
const REPORT_ID_3 = '20000000-0000-4000-8000-000000000030';

// ---------------------------------------------------------------------------
// Mock report fixtures
// ---------------------------------------------------------------------------

function makeReport(overrides: Record<string, any> = {}) {
  return {
    reportId: REPORT_ID_1,
    providerId: PHYSICIAN_ID,
    reportType: 'ACCOUNTANT_SUMMARY',
    format: 'CSV',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '/storage/reports/test.csv',
    fileSizeBytes: 2048,
    downloadLinkExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    downloaded: false,
    scheduled: false,
    status: 'ready',
    errorMessage: null,
    createdAt: new Date('2026-02-10T10:00:00.000Z'),
    ...overrides,
  };
}

// CSV content fixture: one row per paid claim
const CSV_CONTENT = [
  'Date of Service,HSC Code,Modifiers,Submitted Fee,Assessed Fee,Payment Date,BA Number,Location,Claim Type',
  '2026-01-05,03.04A,,85.00,80.00,2026-01-20,BA001,Clinic A,AHCIP',
  '2026-01-10,08.19A,MOD1,120.00,115.00,2026-01-25,BA001,Clinic A,AHCIP',
  '2026-01-15,03.04A,,85.00,80.00,2026-01-28,BA002,Clinic B,AHCIP',
].join('\n');

// ---------------------------------------------------------------------------
// Mock session deps for auth plugin
// ---------------------------------------------------------------------------

function makeSessionDeps(userId: string, role: string) {
  return {
    sessionRepo: {
      findSessionByTokenHash: async (hash: string) => {
        if (hash !== SESSION_HASH) return undefined;
        return {
          session: {
            sessionId: 'sess-1',
            userId,
            tokenHash: SESSION_HASH,
            ipAddress: '127.0.0.1',
            userAgent: 'test',
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
            revokedReason: null,
          },
          user: {
            userId,
            role,
            subscriptionStatus: 'ACTIVE',
          },
        };
      },
      refreshSession: async () => {},
      listActiveSessions: async () => [],
    },
    auditRepo: { appendAuditLog: async () => {} },
    events: { emit: () => true, on: () => {} },
  };
}

// ---------------------------------------------------------------------------
// Default mock deps factory
// ---------------------------------------------------------------------------

function makeMockDeps(
  overrides: Partial<{
    reportsRepo: any;
    reportGenerationService: any;
    downloadService: any;
    auditLog: any;
  }> = {},
): ReportRouteDeps {
  return {
    reportsRepo: {
      create: vi.fn().mockResolvedValue(makeReport({ status: 'pending' })),
      getById: vi.fn().mockResolvedValue(null),
      listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
      updateStatus: vi.fn().mockResolvedValue(null),
      markDownloaded: vi.fn().mockResolvedValue(null),
      ...overrides.reportsRepo,
    },
    reportGenerationService: {
      processReport: vi.fn().mockResolvedValue(undefined),
      generateDataPortabilityExport: vi.fn().mockResolvedValue(undefined),
      ...overrides.reportGenerationService,
    },
    downloadService: {
      getDownloadStream: vi.fn().mockRejectedValue(
        Object.assign(new Error('Report not found'), {
          name: 'DownloadError',
          code: 'NOT_FOUND',
        }),
      ),
      isDownloadAvailable: vi.fn().mockResolvedValue({ available: false }),
      ...overrides.downloadService,
    },
    auditLog: overrides.auditLog ?? vi.fn().mockResolvedValue(undefined),
  };
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(deps: ReportRouteDeps): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(PHYSICIAN_ID, 'physician');
  await app.register(authPluginFp, { sessionDeps } as any);

  await app.register(reportRoutes, { deps });
  await app.ready();

  return app;
}

function authedPost(app: FastifyInstance, url: string, body: any) {
  return app.inject({
    method: 'POST',
    url,
    headers: { cookie: `session=${SESSION_TOKEN}` },
    payload: body,
  });
}

function authedGet(app: FastifyInstance, url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${SESSION_TOKEN}` },
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Analytics Reports — Integration Tests', () => {
  // -------------------------------------------------------------------------
  // POST /api/v1/reports/accountant — CSV format
  // -------------------------------------------------------------------------

  describe('POST /api/v1/reports/accountant (CSV)', () => {
    it('creates report, returns pending status, triggers async generation', async () => {
      const auditLog = vi.fn().mockResolvedValue(undefined);
      const processReport = vi.fn().mockResolvedValue(undefined);
      const deps = makeMockDeps({
        auditLog,
        reportGenerationService: { processReport, generateDataPortabilityExport: vi.fn() },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBeDefined();
      expect(body.data.status).toBe('pending');

      // Repo create was called with correct params
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PHYSICIAN_ID,
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'CSV',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
        }),
      );

      // Audit log was called
      expect(auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.report_generated',
          providerId: PHYSICIAN_ID,
        }),
      );

      await app.close();
    });

    it('poll status returns report status after generation', async () => {
      const readyReport = makeReport({ status: 'ready' });
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(makeReport({ status: 'pending' })),
          getById: vi.fn().mockResolvedValue(readyReport),
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
      });
      const app = await buildTestApp(deps);

      // Poll report status
      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('ready');
      expect(body.data.report_id).toBe(REPORT_ID_1);
      expect(body.data.format).toBe('CSV');
      expect(body.data.file_size_bytes).toBe(2048);
      expect(body.data.download_link_expires_at).toBeDefined();

      // file_path NEVER exposed
      expect(body.data).not.toHaveProperty('file_path');
      expect(body.data).not.toHaveProperty('filePath');

      await app.close();
    });

    it('download returns CSV content with proper headers', async () => {
      const csvStream = Readable.from(CSV_CONTENT);
      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockResolvedValue({
            stream: csvStream,
            contentType: 'text/csv',
            contentDisposition: 'attachment; filename="accountant-report-2026-01.csv"',
            fileSizeBytes: Buffer.byteLength(CSV_CONTENT),
          }),
          isDownloadAvailable: vi.fn().mockResolvedValue({ available: true }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}/download`);

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/csv');
      expect(res.headers['content-disposition']).toContain('attachment');
      expect(res.headers['content-disposition']).toContain('.csv');

      // Verify CSV format: header + data rows
      const csvBody = res.body;
      const lines = csvBody.split('\n');
      expect(lines.length).toBeGreaterThanOrEqual(2); // header + at least 1 data row

      // Verify CSV header columns
      const header = lines[0];
      expect(header).toContain('Date of Service');
      expect(header).toContain('HSC Code');
      expect(header).toContain('Assessed Fee');
      expect(header).toContain('BA Number');
      expect(header).toContain('Claim Type');

      // Verify data row count (3 paid claims)
      const dataRows = lines.filter((l: string) => l.trim() && !l.startsWith('Date'));
      expect(dataRows).toHaveLength(3);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/reports/accountant — PDF summary format
  // -------------------------------------------------------------------------

  describe('POST /api/v1/reports/accountant (PDF summary)', () => {
    it('creates report with PDF format and returns pending status', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'pdf_summary',
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBeDefined();
      expect(body.data.status).toBe('pending');

      // Verify format mapping
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'PDF',
        }),
      );

      await app.close();
    });

    it('download returns PDF with correct content-type', async () => {
      // Minimal PDF-like content
      const pdfContent = Buffer.from('%PDF-1.4 mock content');
      const pdfStream = Readable.from(pdfContent);

      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockResolvedValue({
            stream: pdfStream,
            contentType: 'application/pdf',
            contentDisposition: 'attachment; filename="accountant-summary-2026-01.pdf"',
            fileSizeBytes: pdfContent.length,
          }),
          isDownloadAvailable: vi.fn().mockResolvedValue({ available: true }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}/download`);

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/pdf');
      expect(res.headers['content-disposition']).toContain('.pdf');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/reports/data-portability — ZIP
  // -------------------------------------------------------------------------

  describe('POST /api/v1/reports/data-portability', () => {
    it('creates data portability export and returns pending status', async () => {
      const auditLog = vi.fn().mockResolvedValue(undefined);
      const generateDataPortabilityExport = vi.fn().mockResolvedValue(undefined);
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({
              reportId: REPORT_ID_2,
              reportType: 'DATA_PORTABILITY',
              format: 'ZIP',
              status: 'pending',
            }),
          ),
          getById: vi.fn().mockResolvedValue(null),
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
        auditLog,
        reportGenerationService: {
          processReport: vi.fn(),
          generateDataPortabilityExport,
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/data-portability', {});

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBe(REPORT_ID_2);
      expect(body.data.status).toBe('pending');

      // Repo called with DATA_PORTABILITY type
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PHYSICIAN_ID,
          reportType: 'DATA_PORTABILITY',
          format: 'ZIP',
        }),
      );

      // Audit log with sensitive flag
      expect(auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.data_portability_requested',
          providerId: PHYSICIAN_ID,
          details: expect.objectContaining({ sensitive: true }),
        }),
      );

      await app.close();
    });

    it('download returns ZIP with correct content-type', async () => {
      // Minimal ZIP-like content
      const zipContent = Buffer.from('PK\x03\x04 mock zip content');
      const zipStream = Readable.from(zipContent);

      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockResolvedValue({
            stream: zipStream,
            contentType: 'application/zip',
            contentDisposition: 'attachment; filename="data-export.zip"',
            fileSizeBytes: zipContent.length,
          }),
          isDownloadAvailable: vi.fn().mockResolvedValue({ available: true }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID_2}/download`);

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/zip');
      expect(res.headers['content-disposition']).toContain('.zip');

      await app.close();
    });

    it('accepts optional password for encryption', async () => {
      const generateDataPortabilityExport = vi.fn().mockResolvedValue(undefined);
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({ reportType: 'DATA_PORTABILITY', format: 'ZIP', status: 'pending' }),
          ),
          getById: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
        reportGenerationService: {
          processReport: vi.fn(),
          generateDataPortabilityExport,
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/data-portability', {
        password: 'MySecure12CharPassword',
      });

      expect(res.statusCode).toBe(201);

      await app.close();
    });

    it('rejects password shorter than 12 characters', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/data-portability', {
        password: 'short',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // GET /api/v1/reports — list
  // -------------------------------------------------------------------------

  describe('GET /api/v1/reports — list', () => {
    it('lists generated reports with pagination', async () => {
      const reports = [
        makeReport({ reportId: REPORT_ID_1 }),
        makeReport({ reportId: REPORT_ID_2, reportType: 'DATA_PORTABILITY', format: 'ZIP' }),
      ];
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn(),
          getById: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue({ data: reports, total: 2 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(2);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(2);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.pageSize).toBe(20);
      expect(body.pagination.hasMore).toBe(false);

      // Verify sanitized output (no filePath)
      for (const report of body.data) {
        expect(report).not.toHaveProperty('filePath');
        expect(report).not.toHaveProperty('file_path');
        expect(report).toHaveProperty('report_id');
        expect(report).toHaveProperty('report_type');
        expect(report).toHaveProperty('format');
        expect(report).toHaveProperty('status');
      }

      await app.close();
    });

    it('filters by report_type', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn(),
          getById: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports?report_type=ACCOUNTANT_SUMMARY');

      expect(res.statusCode).toBe(200);
      expect(deps.reportsRepo.listByProvider).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ reportType: 'ACCOUNTANT_SUMMARY' }),
      );

      await app.close();
    });

    it('pagination with offset', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn(),
          getById: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 50 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports?limit=10&offset=20');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.pagination.page).toBe(3); // offset 20 / limit 10 + 1 = 3
      expect(body.pagination.pageSize).toBe(10);
      expect(body.pagination.hasMore).toBe(true); // 20 + 10 < 50

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Download expired report — 410 Gone
  // -------------------------------------------------------------------------

  describe('Download expired report', () => {
    it('returns 410 Gone for expired download link', async () => {
      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockRejectedValue(
            Object.assign(new Error('Download link has expired'), {
              name: 'DownloadError',
              code: 'EXPIRED',
            }),
          ),
          isDownloadAvailable: vi.fn().mockResolvedValue({ available: false }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}/download`);

      expect(res.statusCode).toBe(410);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('GONE');
      expect(body.error.message).toContain('expired');

      await app.close();
    });

    it('returns 404 for non-existent report download', async () => {
      const deps = makeMockDeps(); // default downloadService throws NOT_FOUND
      const app = await buildTestApp(deps);

      const nonExistentId = '99999999-0000-4000-8000-000000000001';
      const res = await authedGet(app, `/api/v1/reports/${nonExistentId}/download`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Report status transitions
  // -------------------------------------------------------------------------

  describe('Report status lifecycle', () => {
    it('pending -> ready -> downloaded flow', async () => {
      const pendingReport = makeReport({ status: 'pending', fileSizeBytes: 0 });
      const readyReport = makeReport({ status: 'ready' });
      const downloadedReport = makeReport({ status: 'ready', downloaded: true });

      // getById returns different states on sequential calls
      const getByIdMock = vi.fn()
        .mockResolvedValueOnce(pendingReport)
        .mockResolvedValueOnce(readyReport)
        .mockResolvedValueOnce(downloadedReport);

      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(pendingReport),
          getById: getByIdMock,
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
      });
      const app = await buildTestApp(deps);

      // Step 1: Check status — pending
      const res1 = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}`);
      expect(res1.statusCode).toBe(200);
      const body1 = JSON.parse(res1.body);
      expect(body1.data.status).toBe('pending');
      expect(body1.data.file_size_bytes).toBeNull();

      // Step 2: Check status — ready
      const res2 = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}`);
      expect(res2.statusCode).toBe(200);
      const body2 = JSON.parse(res2.body);
      expect(body2.data.status).toBe('ready');
      expect(body2.data.file_size_bytes).toBe(2048);

      // Step 3: After download — downloaded flag
      const res3 = await authedGet(app, `/api/v1/reports/${REPORT_ID_1}`);
      expect(res3.statusCode).toBe(200);
      const body3 = JSON.parse(res3.body);
      expect(body3.data.downloaded).toBe(true);

      await app.close();
    });

    it('returns 404 for report belonging to another physician', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn(),
          // getById returns null (scoped query finds nothing for this provider)
          getById: vi.fn().mockResolvedValue(null),
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
          updateStatus: vi.fn(),
          markDownloaded: vi.fn(),
        },
      });
      const app = await buildTestApp(deps);

      const otherPhysicianReport = '30000000-0000-4000-8000-000000000001';
      const res = await authedGet(app, `/api/v1/reports/${otherPhysicianReport}`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      // Generic message — don't reveal existence
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------------------

  describe('Validation', () => {
    it('rejects invalid date format in accountant report', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: 'not-a-date',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(400);
      expect(deps.reportsRepo.create).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects invalid format enum', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'xml',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-UUID report ID param', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports/not-a-uuid');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects date range exceeding 2 years', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2022-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });
});
