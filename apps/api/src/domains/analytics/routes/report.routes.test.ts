// ============================================================================
// Domain 8: Report Routes — Unit Tests
// Tests: route registration, Zod validation, permission enforcement,
// provider scoping, download streaming, 404 for wrong provider, audit logging.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';

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
import { authPluginFp } from '../../../plugins/auth.plugin.js';
import { reportRoutes, type ReportRouteDeps } from './report.routes.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const PHYSICIAN2_ID = '00000000-0000-4000-8000-000000000010';
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000002';
const DELEGATE_PHYSICIAN_ID = '00000000-0000-4000-8000-000000000003';
const REPORT_ID = '00000000-0000-4000-8000-000000000099';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');
const SESSION_TOKEN_2 = randomBytes(32).toString('hex');
const SESSION_HASH_2 = createHash('sha256').update(SESSION_TOKEN_2).digest('hex');

// ---------------------------------------------------------------------------
// Mock report record fixture
// ---------------------------------------------------------------------------

function makeReport(overrides: Record<string, any> = {}) {
  return {
    reportId: REPORT_ID,
    providerId: PHYSICIAN_ID,
    reportType: 'ACCOUNTANT_SUMMARY',
    format: 'CSV',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '/storage/reports/test.csv',
    fileSizeBytes: 1024,
    downloadLinkExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    downloaded: false,
    scheduled: false,
    status: 'ready',
    errorMessage: null,
    createdAt: new Date(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock session deps for auth plugin
// ---------------------------------------------------------------------------

function makeSessionDeps(
  userId: string,
  role: string,
  delegateContext?: Record<string, unknown>,
  sessionHash?: string,
) {
  const userObj: any = {
    userId,
    role,
    subscriptionStatus: 'ACTIVE',
  };
  if (delegateContext) {
    userObj.delegateContext = delegateContext;
  }

  const hash = sessionHash ?? SESSION_HASH;

  return {
    sessionRepo: {
      findSessionByTokenHash: async (h: string) => {
        if (h !== hash) return undefined;
        return {
          session: {
            sessionId: 'sess-1',
            userId,
            tokenHash: hash,
            ipAddress: '127.0.0.1',
            userAgent: 'test',
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
            revokedReason: null,
          },
          user: userObj,
        };
      },
      refreshSession: async () => {},
      listActiveSessions: async () => [],
    },
    auditRepo: {
      appendAuditLog: async () => {},
    },
    events: {
      emit: () => true,
      on: () => {},
    },
  };
}

// ---------------------------------------------------------------------------
// Default mock deps factory
// ---------------------------------------------------------------------------

function makeMockDeps(overrides: Partial<{
  reportsRepo: any;
  reportGenerationService: any;
  downloadService: any;
  auditLog: any;
}> = {}): ReportRouteDeps {
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

async function buildTestApp(
  deps: ReportRouteDeps,
  opts: {
    userId?: string;
    role?: string;
    delegateContext?: Record<string, unknown>;
    sessionHash?: string;
  } = {},
): Promise<FastifyInstance> {
  const userId = opts.userId ?? PHYSICIAN_ID;
  const role = opts.role ?? 'physician';

  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(userId, role, opts.delegateContext, opts.sessionHash);
  await app.register(authPluginFp, { sessionDeps } as any);

  await app.register(reportRoutes, { deps });
  await app.ready();

  return app;
}

function authedGet(app: FastifyInstance, url: string, token = SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function authedPost(
  app: FastifyInstance,
  url: string,
  body: any,
  token = SESSION_TOKEN,
) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    body,
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Report Routes', () => {
  // -----------------------------------------------------------------------
  // POST /api/v1/reports/accountant
  // -----------------------------------------------------------------------

  describe('POST /api/v1/reports/accountant', () => {
    it('creates accountant report with valid body and returns 201', { timeout: 15000 }, async () => {
      const deps = makeMockDeps();
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
      expect(deps.reportsRepo.create).toHaveBeenCalledOnce();
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PHYSICIAN_ID,
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'CSV',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
        }),
      );

      await app.close();
    });

    it('maps pdf_summary format correctly', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'pdf_summary',
      });

      expect(res.statusCode).toBe(201);
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'PDF',
        }),
      );

      await app.close();
    });

    it('maps pdf_detail format correctly', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'pdf_detail',
      });

      expect(res.statusCode).toBe(201);
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          reportType: 'ACCOUNTANT_DETAIL',
          format: 'PDF',
        }),
      );

      await app.close();
    });

    it('logs REPORT_GENERATED audit event', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      // Allow setImmediate to settle
      await new Promise((r) => setTimeout(r, 10));

      expect(deps.auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.report_generated',
          providerId: PHYSICIAN_ID,
        }),
      );

      await app.close();
    });

    it('rejects missing period_start with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(400);
      expect(deps.reportsRepo.create).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects missing format with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid format value with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'xlsx',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects end_date before start_date with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-02-15',
        period_end: '2026-01-01',
        format: 'csv',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects malformed dates with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: 'not-a-date',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(
        app,
        '/api/v1/reports/accountant',
        {
          period_start: '2026-01-01',
          period_end: '2026-01-31',
          format: 'csv',
        },
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);
      expect(deps.reportsRepo.create).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 403 for delegate without REPORT_EXPORT permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/reports/data-portability
  // -----------------------------------------------------------------------

  describe('POST /api/v1/reports/data-portability', () => {
    it('creates data portability report with 201', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({
              status: 'pending',
              reportType: 'DATA_PORTABILITY',
              format: 'ZIP',
            }),
          ),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/data-portability', {});

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBeDefined();
      expect(body.data.status).toBe('pending');
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PHYSICIAN_ID,
          reportType: 'DATA_PORTABILITY',
          format: 'ZIP',
        }),
      );

      await app.close();
    });

    it('accepts optional password for encryption', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({ status: 'pending', reportType: 'DATA_PORTABILITY' }),
          ),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/data-portability', {
        password: 'MySecurePassword123!',
      });

      expect(res.statusCode).toBe(201);

      await app.close();
    });

    it('rejects password shorter than 12 characters with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/reports/data-portability', {
        password: 'short',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('logs DATA_PORTABILITY_REQUESTED as sensitive action', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({ status: 'pending', reportType: 'DATA_PORTABILITY' }),
          ),
        },
      });
      const app = await buildTestApp(deps);

      await authedPost(app, '/api/v1/reports/data-portability', {});

      await new Promise((r) => setTimeout(r, 10));

      expect(deps.auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.data_portability_requested',
          providerId: PHYSICIAN_ID,
          details: expect.objectContaining({ sensitive: true }),
        }),
      );

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(
        app,
        '/api/v1/reports/data-portability',
        {},
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without DATA_EXPORT permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW', 'REPORT_EXPORT'],
          linkageId: 'link-1',
        },
      });

      const res = await authedPost(
        app,
        '/api/v1/reports/data-portability',
        {},
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/reports/:id
  // -----------------------------------------------------------------------

  describe('GET /api/v1/reports/:id', () => {
    it('returns report status for own report', async () => {
      const report = makeReport();
      const deps = makeMockDeps({
        reportsRepo: {
          getById: vi.fn().mockResolvedValue(report),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBe(REPORT_ID);
      expect(body.data.status).toBe('ready');
      expect(body.data.file_size_bytes).toBe(1024);
      expect(body.data.download_link_expires_at).toBeDefined();

      await app.close();
    });

    it('does NOT include file_path in response', async () => {
      const report = makeReport();
      const deps = makeMockDeps({
        reportsRepo: {
          getById: vi.fn().mockResolvedValue(report),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.file_path).toBeUndefined();
      expect(body.data.filePath).toBeUndefined();
      expect(JSON.stringify(body)).not.toContain('file_path');
      expect(JSON.stringify(body)).not.toContain('filePath');

      await app.close();
    });

    it('returns null file_size_bytes for pending reports', async () => {
      const report = makeReport({ status: 'pending', fileSizeBytes: 0 });
      const deps = makeMockDeps({
        reportsRepo: {
          getById: vi.fn().mockResolvedValue(report),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.file_size_bytes).toBeNull();
      expect(body.data.download_link_expires_at).toBeNull();

      await app.close();
    });

    it('returns 404 for report not found (or wrong provider)', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          getById: vi.fn().mockResolvedValue(null),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('rejects non-UUID id with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports/not-a-uuid');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}`, 'invalid-token');

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('scopes query to authenticated provider', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          getById: vi.fn().mockResolvedValue(null),
        },
      });
      const app = await buildTestApp(deps);

      await authedGet(app, `/api/v1/reports/${REPORT_ID}`);

      expect(deps.reportsRepo.getById).toHaveBeenCalledWith(
        REPORT_ID,
        PHYSICIAN_ID,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/reports/:id/download
  // -----------------------------------------------------------------------

  describe('GET /api/v1/reports/:id/download', () => {
    it('streams file download for ready report', async () => {
      const mockStream = new Readable({
        read() {
          this.push('csv,data,here\n');
          this.push(null);
        },
      });

      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockResolvedValue({
            stream: mockStream,
            contentType: 'text/csv',
            contentDisposition: `attachment; filename="report-${REPORT_ID}.csv"`,
            fileSizeBytes: 14,
          }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}/download`);

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('text/csv');
      expect(res.headers['content-disposition']).toContain('attachment');
      expect(res.body).toContain('csv,data,here');

      await app.close();
    });

    it('returns 410 for expired download link', async () => {
      const expiredError = Object.assign(
        new Error('Download link has expired'),
        { name: 'DownloadError', code: 'EXPIRED' },
      );
      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockRejectedValue(expiredError),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}/download`);

      expect(res.statusCode).toBe(410);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('GONE');

      await app.close();
    });

    it('returns 404 for report not found', async () => {
      const notFoundError = Object.assign(
        new Error('Report not found'),
        { name: 'DownloadError', code: 'NOT_FOUND' },
      );
      const deps = makeMockDeps({
        downloadService: {
          getDownloadStream: vi.fn().mockRejectedValue(notFoundError),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}/download`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('rejects non-UUID id with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports/not-a-uuid/download');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(
        app,
        `/api/v1/reports/${REPORT_ID}/download`,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without REPORT_EXPORT permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}/download`);

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/reports
  // -----------------------------------------------------------------------

  describe('GET /api/v1/reports', () => {
    it('returns paginated report list', async () => {
      const reports = [makeReport(), makeReport({ reportId: '00000000-0000-4000-8000-000000000098' })];
      const deps = makeMockDeps({
        reportsRepo: {
          listByProvider: vi.fn().mockResolvedValue({
            data: reports,
            total: 2,
          }),
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

      await app.close();
    });

    it('does not include file_path in listed reports', async () => {
      const reports = [makeReport()];
      const deps = makeMockDeps({
        reportsRepo: {
          listByProvider: vi.fn().mockResolvedValue({ data: reports, total: 1 }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const bodyStr = res.body;
      expect(bodyStr).not.toContain('file_path');
      expect(bodyStr).not.toContain('filePath');
      expect(bodyStr).not.toContain('/storage/reports/');

      await app.close();
    });

    it('passes filters to repository', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(
        app,
        '/api/v1/reports?report_type=ACCOUNTANT_SUMMARY&limit=10&offset=20',
      );

      expect(res.statusCode).toBe(200);
      expect(deps.reportsRepo.listByProvider).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          reportType: 'ACCOUNTANT_SUMMARY',
          limit: 10,
          offset: 20,
        }),
      );

      await app.close();
    });

    it('calculates page correctly from offset/limit', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 50 }),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports?limit=10&offset=20');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.pagination.page).toBe(3);
      expect(body.pagination.hasMore).toBe(true);

      await app.close();
    });

    it('rejects invalid report_type with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports?report_type=INVALID');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects limit > 100 with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports?limit=200');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects negative offset with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports?offset=-1');

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/reports', 'invalid-token');

      expect(res.statusCode).toBe(401);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Provider scoping — physician vs delegate
  // -----------------------------------------------------------------------

  describe('Provider scoping from session', () => {
    it('uses physician userId as providerId for physician role', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
        },
      });
      const app = await buildTestApp(deps, {
        userId: PHYSICIAN_ID,
        role: 'physician',
      });

      await authedGet(app, '/api/v1/reports');

      expect(deps.reportsRepo.listByProvider).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.any(Object),
      );

      await app.close();
    });

    it('uses delegate physicianProviderId for delegate role', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          listByProvider: vi.fn().mockResolvedValue({ data: [], total: 0 }),
        },
      });
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      await authedGet(app, '/api/v1/reports');

      expect(deps.reportsRepo.listByProvider).toHaveBeenCalledWith(
        DELEGATE_PHYSICIAN_ID,
        expect.any(Object),
      );

      await app.close();
    });

    it('POST /accountant scopes to delegate physician context', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({ status: 'pending', providerId: DELEGATE_PHYSICIAN_ID }),
          ),
        },
      });
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_EXPORT'],
          linkageId: 'link-1',
        },
      });

      const res = await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(201);
      expect(deps.reportsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: DELEGATE_PHYSICIAN_ID,
        }),
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // 404 for cross-provider access
  // -----------------------------------------------------------------------

  describe('Tenant isolation', () => {
    it('GET /reports/:id returns 404 for another physician\'s report', async () => {
      // Report belongs to PHYSICIAN2_ID, current user is PHYSICIAN_ID
      const deps = makeMockDeps({
        reportsRepo: {
          getById: vi.fn().mockImplementation(
            (reportId: string, providerId: string) => {
              // Only return report if providerId matches owner
              if (providerId === PHYSICIAN2_ID) {
                return makeReport({ providerId: PHYSICIAN2_ID });
              }
              return null;
            },
          ),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, `/api/v1/reports/${REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      expect(deps.reportsRepo.getById).toHaveBeenCalledWith(
        REPORT_ID,
        PHYSICIAN_ID,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Async generation dispatch
  // -----------------------------------------------------------------------

  describe('Async report generation', () => {
    it('POST /accountant queues processReport via setImmediate', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      await authedPost(app, '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      // Wait for setImmediate to fire
      await new Promise((r) => setTimeout(r, 50));

      expect(deps.reportGenerationService.processReport).toHaveBeenCalledWith(
        REPORT_ID,
        PHYSICIAN_ID,
      );

      await app.close();
    });

    it('POST /data-portability queues generateDataPortabilityExport', async () => {
      const deps = makeMockDeps({
        reportsRepo: {
          create: vi.fn().mockResolvedValue(
            makeReport({ status: 'pending', reportType: 'DATA_PORTABILITY' }),
          ),
        },
      });
      const app = await buildTestApp(deps);

      await authedPost(app, '/api/v1/reports/data-portability', {
        password: 'MySecurePass123',
      });

      await new Promise((r) => setTimeout(r, 50));

      expect(
        deps.reportGenerationService.generateDataPortabilityExport,
      ).toHaveBeenCalledWith(REPORT_ID, PHYSICIAN_ID, 'MySecurePass123');

      await app.close();
    });
  });
});
