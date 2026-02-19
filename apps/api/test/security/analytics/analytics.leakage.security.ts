// ============================================================================
// Domain 8: Analytics & Reporting — PHI & Data Leakage Prevention (Security)
// Verifies PHI never leaks via error responses, HTTP headers, download
// filenames, aggregate analytics data, or internal file paths.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { dashboardRoutes } from '../../../src/domains/analytics/routes/dashboard.routes.js';
import { reportRoutes } from '../../../src/domains/analytics/routes/report.routes.js';
import { subscriptionRoutes } from '../../../src/domains/analytics/routes/subscription.routes.js';
import type { DashboardRouteDeps } from '../../../src/domains/analytics/routes/dashboard.routes.js';
import type { ReportRouteDeps } from '../../../src/domains/analytics/routes/report.routes.js';
import type { SubscriptionRouteDeps } from '../../../src/domains/analytics/routes/subscription.routes.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const P1_TOKEN = randomBytes(32).toString('hex');
const P1_TOKEN_HASH = hashToken(P1_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const P2_TOKEN = randomBytes(32).toString('hex');
const P2_TOKEN_HASH = hashToken(P2_TOKEN);
const P2_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Constants — known PHI and internal paths
// ---------------------------------------------------------------------------

const TEST_PHN = '123456789';
const TEST_PATIENT_NAME = 'Jane Doe';
const TEST_PATIENT_FIRST = 'Jane';
const TEST_PATIENT_LAST = 'Doe';
const INTERNAL_FILE_PATH = '/data/reports/providers/aaaa0000/2026-01-report.csv';
const INTERNAL_FILE_PATH_2 = '/data/reports/providers/aaaa0002/2026-01-report.pdf';

const P1_REPORT_ID = 'a0a00000-0000-4000-a000-000000000001';
const P2_REPORT_ID = 'a0a00000-0000-4000-a000-000000000002';
const NONEXISTENT_UUID = '00000000-ffff-ffff-ffff-ffffffffffff';
const FAILED_REPORT_ID = 'a0a00000-0000-4000-a000-000000000099';
const EXPIRED_REPORT_ID = 'a0a00000-0000-4000-a000-000000000088';

// ---------------------------------------------------------------------------
// Mock stores for auth
// ---------------------------------------------------------------------------

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

function makeSession(id: string, userId: string, tokenHash: string): MockSession {
  return {
    sessionId: id,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  };
}

// ---------------------------------------------------------------------------
// Mock session repository
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Per-physician data stores
// ---------------------------------------------------------------------------

const reportsStore = new Map<string, any>();
const reportsListStore = new Map<string, any[]>();

/** Flag to force internal error from dashboard service */
let forceInternalError = false;

function resetDataStores() {
  reportsStore.clear();
  reportsListStore.clear();
  forceInternalError = false;

  const now = new Date();
  const futureExpiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const pastExpiry = new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000);

  // -- Physician 1: ready accountant report --
  reportsStore.set(`${P1_REPORT_ID}:${P1_USER_ID}`, {
    reportId: P1_REPORT_ID,
    providerId: P1_USER_ID,
    reportType: 'ACCOUNTANT_SUMMARY',
    format: 'CSV',
    status: 'ready',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: INTERNAL_FILE_PATH,
    fileSizeBytes: 2048,
    downloadLinkExpiresAt: futureExpiry,
    downloaded: false,
    createdAt: now,
    errorMessage: null,
  });

  reportsListStore.set(P1_USER_ID, [
    reportsStore.get(`${P1_REPORT_ID}:${P1_USER_ID}`),
  ]);

  // -- Physician 2: ready monthly report --
  reportsStore.set(`${P2_REPORT_ID}:${P2_USER_ID}`, {
    reportId: P2_REPORT_ID,
    providerId: P2_USER_ID,
    reportType: 'MONTHLY_PERFORMANCE',
    format: 'PDF',
    status: 'ready',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: INTERNAL_FILE_PATH_2,
    fileSizeBytes: 4096,
    downloadLinkExpiresAt: futureExpiry,
    downloaded: false,
    createdAt: now,
    errorMessage: null,
  });

  // -- Failed report for P1 --
  reportsStore.set(`${FAILED_REPORT_ID}:${P1_USER_ID}`, {
    reportId: FAILED_REPORT_ID,
    providerId: P1_USER_ID,
    reportType: 'ACCOUNTANT_DETAIL',
    format: 'PDF',
    status: 'failed',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '',
    fileSizeBytes: 0,
    downloadLinkExpiresAt: futureExpiry,
    downloaded: false,
    createdAt: now,
    errorMessage: 'Report generation failed',
  });

  // -- Expired report for P1 --
  reportsStore.set(`${EXPIRED_REPORT_ID}:${P1_USER_ID}`, {
    reportId: EXPIRED_REPORT_ID,
    providerId: P1_USER_ID,
    reportType: 'DATA_PORTABILITY',
    format: 'ZIP',
    status: 'ready',
    periodStart: null,
    periodEnd: null,
    filePath: '/data/exports/p1-data-export.zip',
    fileSizeBytes: 10240,
    downloadLinkExpiresAt: pastExpiry,
    downloaded: false,
    createdAt: now,
    errorMessage: null,
  });

  reportsListStore.set(P1_USER_ID, [
    reportsStore.get(`${P1_REPORT_ID}:${P1_USER_ID}`),
    reportsStore.get(`${FAILED_REPORT_ID}:${P1_USER_ID}`),
    reportsStore.get(`${EXPIRED_REPORT_ID}:${P1_USER_ID}`),
  ]);
}

// ---------------------------------------------------------------------------
// Handler deps
// ---------------------------------------------------------------------------

function createLeakageDashboardDeps(): DashboardRouteDeps {
  return {
    dashboardService: {
      getRevenueDashboard: vi.fn(async (providerId: string) => {
        if (forceInternalError) {
          throw new Error(
            `Database connection failed: pg_hba.conf reject for host 10.0.0.1, ` +
            `query: SELECT SUM(fee) FROM claims WHERE provider_id='${providerId}' ` +
            `AND patient_phn='${TEST_PHN}'`,
          );
        }
        return {
          totalRevenue: '15000.00',
          claimCount: 42,
          pendingPipeline: '3200.00',
          monthlyTrend: [{ month: '2026-01', revenue: '15000.00' }],
          byBa: [{ baNumber: 'BA-001', revenue: '15000.00' }],
          topHscCodes: [{ code: '03.04A', count: 20, revenue: '8000.00' }],
          cacheStatus: 'realtime',
          period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
        };
      }),
      getRejectionDashboard: vi.fn(async () => ({
        rejectionRate: 5.2,
        totalRejected: 3,
        byExplanatoryCode: [{ code: 'E01', count: 2 }],
        byHscCode: [{ code: '03.04A', rate: 4.5, count: 1 }],
        resolutionFunnel: { total: 3, resolved: 1, pending: 2 },
      })),
      getAgingDashboard: vi.fn(async () => ({
        brackets: [
          { label: '0-30 days', count: 5 },
          { label: '31-60 days', count: 2 },
        ],
        approachingDeadline: 1,
        expiredClaims: 0,
        avgResolutionDays: 14,
      })),
      getWcbDashboard: vi.fn(async () => null),
      getAiCoachDashboard: vi.fn(async () => ({
        acceptanceRate: 0.75,
        totalAccepted: 20,
        byCategory: [],
        topAcceptedRules: [],
        suppressedRules: [],
      })),
      getMultiSiteDashboard: vi.fn(async () => null),
      getKpis: vi.fn(async () => ({
        totalRevenue: { current: '15000.00', prior: '12000.00', delta: 25.0 },
        claimsSubmitted: { current: 42, prior: 38, delta: 10.5 },
        rejectionRate: { current: 5.2, prior: 6.0, delta: -13.3 },
        avgFeePerClaim: { current: '357.14', prior: '315.79', delta: 13.1 },
      })),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createLeakageReportDeps(): ReportRouteDeps {
  return {
    reportsRepo: {
      create: vi.fn(async (input: any) => ({
        reportId: randomBytes(16).toString('hex').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5'),
        providerId: input.providerId,
        reportType: input.reportType,
        format: input.format,
        status: 'pending',
        periodStart: input.periodStart ?? null,
        periodEnd: input.periodEnd ?? null,
        filePath: '',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: input.downloadLinkExpiresAt,
        downloaded: false,
        createdAt: new Date(),
        errorMessage: null,
      })),
      getById: vi.fn(async (reportId: string, providerId: string) => {
        return reportsStore.get(`${reportId}:${providerId}`) ?? null;
      }),
      listByProvider: vi.fn(async (providerId: string) => {
        const list = reportsListStore.get(providerId) ?? [];
        return { data: list, total: list.length };
      }),
      updateStatus: vi.fn(async () => {}),
      markDownloaded: vi.fn(async () => {}),
      deleteExpired: vi.fn(async () => {}),
    } as any,
    reportGenerationService: {
      processReport: vi.fn(async () => {}),
      generateDataPortabilityExport: vi.fn(async () => {}),
    } as any,
    downloadService: {
      getDownloadStream: vi.fn(async (reportId: string, providerId: string) => {
        const report = reportsStore.get(`${reportId}:${providerId}`);
        if (!report) {
          const err = new Error('Report not found') as any;
          err.name = 'DownloadError';
          err.code = 'NOT_FOUND';
          throw err;
        }
        if (report.status !== 'ready') {
          const err = new Error('Report not found') as any;
          err.name = 'DownloadError';
          err.code = 'NOT_FOUND';
          throw err;
        }
        const now = new Date();
        if (report.downloadLinkExpiresAt < now) {
          const err = new Error('Download link has expired') as any;
          err.name = 'DownloadError';
          err.code = 'EXPIRED';
          throw err;
        }

        // Determine content type and generic filename
        const formatMap: Record<string, { ct: string; ext: string }> = {
          CSV: { ct: 'text/csv', ext: 'csv' },
          PDF: { ct: 'application/pdf', ext: 'pdf' },
          ZIP: { ct: 'application/zip', ext: 'zip' },
        };
        const fmt = formatMap[report.format] ?? { ct: 'application/octet-stream', ext: 'bin' };

        // Filename varies by report type
        let filename: string;
        if (report.reportType === 'DATA_PORTABILITY') {
          const dateStr = new Date().toISOString().slice(0, 10);
          filename = `meritum-data-export-${dateStr}.zip`;
        } else if (report.reportType.startsWith('ACCOUNTANT')) {
          const period = report.periodStart && report.periodEnd
            ? `${report.periodStart}-to-${report.periodEnd}`
            : 'report';
          filename = `accountant-export-${period}.${fmt.ext}`;
        } else {
          filename = `report-${reportId}.${fmt.ext}`;
        }

        // Create a real Readable stream so Fastify can send it
        const stream = new Readable({
          read() {
            this.push('mock-report-content');
            this.push(null);
          },
        });

        return {
          stream,
          contentType: fmt.ct,
          contentDisposition: `attachment; filename="${filename}"`,
          fileSizeBytes: report.fileSizeBytes,
        };
      }),
      isDownloadAvailable: vi.fn(async () => ({ available: true })),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createLeakageSubscriptionDeps(): SubscriptionRouteDeps {
  return {
    subscriptionsRepo: {
      create: vi.fn(async (input: any) => ({
        subscriptionId: randomBytes(16).toString('hex').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5'),
        providerId: input.providerId,
        reportType: input.reportType,
        frequency: input.frequency,
        deliveryMethod: input.deliveryMethod,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      })),
      listByProvider: vi.fn(async () => []),
      getById: vi.fn(async () => null),
      update: vi.fn(async () => null),
      delete: vi.fn(async () => false),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    // 500 — NEVER expose internal details
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(dashboardRoutes, { deps: createLeakageDashboardDeps() });
  await testApp.register(reportRoutes, { deps: createLeakageReportDeps() });
  await testApp.register(subscriptionRoutes, { deps: createLeakageSubscriptionDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function injectAs(
  token: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: Record<string, unknown>,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${token}` },
    ...(payload ? { payload } : {}),
  });
}

function seedIdentities() {
  sessions = [];
  users = [];

  users.push({
    userId: P1_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push(makeSession(P1_SESSION_ID, P1_USER_ID, P1_TOKEN_HASH));

  users.push({
    userId: P2_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push(makeSession(P2_SESSION_ID, P2_USER_ID, P2_TOKEN_HASH));
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Analytics & Reporting PHI Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedIdentities();
    resetDataStores();
  });

  // =========================================================================
  // Error responses must not contain PHI
  // =========================================================================

  describe('Error responses do not contain PHI or internals', () => {
    it('404 on report access contains only error code and generic message', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${NONEXISTENT_UUID}`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');
      // No claim data, patient info, or file paths
      expect(body.data).toBeUndefined();
      const rawBody = res.body;
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain(TEST_PATIENT_LAST);
      expect(rawBody).not.toContain(NONEXISTENT_UUID);
    });

    it('404 on report download contains only error code and generic message', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${NONEXISTENT_UUID}/download`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');
      expect(body.data).toBeUndefined();
    });

    it('400 on invalid input contains validation error, no claim details', async () => {
      const res = await injectAs(P1_TOKEN, 'POST', '/api/v1/reports/accountant', {
        format: 'invalid_format',
        period_start: 'not-a-date',
        period_end: 'also-not-a-date',
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain('claim');
      expect(rawBody).not.toContain(INTERNAL_FILE_PATH);
    });

    it('500 error returns generic message with no stack trace, query details, or PHI', async () => {
      forceInternalError = true;

      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('details');
      expect(body).not.toHaveProperty('data');

      const rawBody = res.body;
      // No database details
      expect(rawBody).not.toMatch(/postgres/i);
      expect(rawBody).not.toMatch(/drizzle/i);
      expect(rawBody).not.toMatch(/pg_hba/i);
      expect(rawBody).not.toMatch(/sql/i);
      expect(rawBody).not.toContain('Database connection');
      expect(rawBody).not.toContain('10.0.0.1');
      // No PHI
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain(P1_USER_ID);
    });

    it('500 error has consistent {error: {code, message}} shape with no extras', async () => {
      forceInternalError = true;

      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('404 for cross-physician report does not reveal report existence', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_REPORT_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('MONTHLY_PERFORMANCE');
      expect(rawBody).not.toContain(INTERNAL_FILE_PATH_2);
    });

    it('failed report status shows generic error message, no PHI', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${FAILED_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('failed');
      // The sanitizeReport function strips file_path and errorMessage
      const responseStr = JSON.stringify(body.data);
      expect(responseStr).not.toContain(TEST_PHN);
      expect(responseStr).not.toContain(TEST_PATIENT_FIRST);
      expect(responseStr).not.toContain(INTERNAL_FILE_PATH);
    });

    it('410 for expired download link does not reveal file details', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${EXPIRED_REPORT_ID}/download`);

      expect(res.statusCode).toBe(410);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('GONE');
      expect(body.error.message).toBe('Download link has expired');
      const rawBody = res.body;
      expect(rawBody).not.toContain('/data/exports/');
      expect(rawBody).not.toContain('p1-data-export');
      expect(rawBody).not.toContain(EXPIRED_REPORT_ID);
    });
  });

  // =========================================================================
  // Response headers must not leak information
  // =========================================================================

  describe('Response headers do not leak server information', () => {
    it('responses do not contain X-Powered-By header', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('responses do not contain Server version header', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/reports');

      expect(res.headers['server']).toBeUndefined();
    });

    it('multiple endpoints consistently omit server headers', async () => {
      const endpoints = [
        '/api/v1/analytics/revenue?period=THIS_MONTH',
        '/api/v1/analytics/rejections?period=THIS_MONTH',
        '/api/v1/analytics/aging',
        '/api/v1/analytics/kpis?period=THIS_MONTH',
        '/api/v1/reports',
        '/api/v1/report-subscriptions',
      ];

      for (const url of endpoints) {
        const res = await injectAs(P1_TOKEN, 'GET', url);
        expect(res.headers['x-powered-by']).toBeUndefined();
        expect(res.headers['server']).toBeUndefined();
      }
    });

    it('error responses also omit server headers', async () => {
      // 404
      const res404 = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${NONEXISTENT_UUID}`);
      expect(res404.headers['x-powered-by']).toBeUndefined();
      expect(res404.headers['server']).toBeUndefined();

      // 500
      forceInternalError = true;
      const res500 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');
      expect(res500.headers['x-powered-by']).toBeUndefined();
      expect(res500.headers['server']).toBeUndefined();
    });
  });

  // =========================================================================
  // file_path field NEVER appears in any API response body
  // =========================================================================

  describe('file_path never appears in API responses', () => {
    it('GET /reports/:id response does not contain file_path', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('file_path');
      expect(body.data).not.toHaveProperty('filePath');
      const rawBody = res.body;
      expect(rawBody).not.toContain(INTERNAL_FILE_PATH);
      expect(rawBody).not.toContain('/data/reports/');
    });

    it('GET /reports list response does not contain file_path in any report', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const report of body.data) {
        expect(report).not.toHaveProperty('file_path');
        expect(report).not.toHaveProperty('filePath');
      }
      const rawBody = res.body;
      expect(rawBody).not.toContain(INTERNAL_FILE_PATH);
      expect(rawBody).not.toContain('/data/reports/');
      expect(rawBody).not.toContain('/data/exports/');
    });

    it('GET /reports/:id for failed report does not contain file_path or errorMessage', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${FAILED_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('file_path');
      expect(body.data).not.toHaveProperty('filePath');
      expect(body.data).not.toHaveProperty('error_message');
      expect(body.data).not.toHaveProperty('errorMessage');
    });

    it('report status response exposes only safe fields', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const allowedFields = [
        'report_id', 'report_type', 'format', 'status',
        'period_start', 'period_end', 'file_size_bytes',
        'download_link_expires_at', 'downloaded', 'created_at',
      ];
      const actualFields = Object.keys(body.data);
      for (const field of actualFields) {
        expect(allowedFields).toContain(field);
      }
    });
  });

  // =========================================================================
  // Download filenames are generic, not internal paths
  // =========================================================================

  describe('Content-Disposition uses generic filenames, not internal paths', () => {
    it('accountant CSV download uses generic filename accountant-export-{period}.csv', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}/download`);

      expect(res.statusCode).toBe(200);
      const disposition = res.headers['content-disposition'] as string;
      expect(disposition).toBeDefined();
      expect(disposition).toContain('attachment');
      expect(disposition).toContain('accountant-export-');
      expect(disposition).toContain('.csv');
      // Must NOT contain internal file path
      expect(disposition).not.toContain(INTERNAL_FILE_PATH);
      expect(disposition).not.toContain('/data/');
      expect(disposition).not.toContain('providers/');
    });

    it('accountant CSV download has Content-Type: text/csv', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}/download`);

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('text/csv');
    });

    it('data portability download uses generic filename meritum-data-export-{date}.zip', async () => {
      // Create a data portability report that is ready and not expired
      const dpReportId = 'a0a00000-0000-4000-a000-000000000077';
      const futureExpiry = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
      reportsStore.set(`${dpReportId}:${P1_USER_ID}`, {
        reportId: dpReportId,
        providerId: P1_USER_ID,
        reportType: 'DATA_PORTABILITY',
        format: 'ZIP',
        status: 'ready',
        periodStart: null,
        periodEnd: null,
        filePath: '/data/exports/secret-internal-path/physician-data.zip',
        fileSizeBytes: 51200,
        downloadLinkExpiresAt: futureExpiry,
        downloaded: false,
        createdAt: new Date(),
        errorMessage: null,
      });

      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${dpReportId}/download`);

      expect(res.statusCode).toBe(200);
      const disposition = res.headers['content-disposition'] as string;
      expect(disposition).toBeDefined();
      expect(disposition).toContain('meritum-data-export-');
      expect(disposition).toContain('.zip');
      expect(disposition).not.toContain('secret-internal-path');
      expect(disposition).not.toContain('physician-data.zip');
      expect(disposition).not.toContain('/data/exports/');
    });
  });

  // =========================================================================
  // Analytics-specific leakage vectors: aggregate-only data
  // =========================================================================

  describe('Dashboard responses contain aggregate values only, never individual patient claims', () => {
    it('GET /analytics/revenue returns aggregate totals, not individual claim rows', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const data = body.data;

      // Contains aggregate values
      expect(data).toHaveProperty('totalRevenue');
      expect(data).toHaveProperty('claimCount');
      expect(data).toHaveProperty('pendingPipeline');

      // Must NOT contain individual claim details
      const rawBody = res.body;
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain(TEST_PATIENT_LAST);
      expect(rawBody).not.toContain('patient_id');
      expect(rawBody).not.toContain('patientId');
      expect(rawBody).not.toContain('claim_id');
      expect(rawBody).not.toContain('claimId');
    });

    it('GET /analytics/rejections returns aggregate rates, not individual patient data', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body).data;
      expect(data).toHaveProperty('rejectionRate');
      expect(data).toHaveProperty('totalRejected');
      expect(typeof data.rejectionRate).toBe('number');

      const rawBody = res.body;
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
    });

    it('GET /analytics/aging returns bracket counts, not individual claims', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body).data;
      expect(data).toHaveProperty('brackets');
      expect(Array.isArray(data.brackets)).toBe(true);
      for (const bracket of data.brackets) {
        expect(bracket).toHaveProperty('label');
        expect(bracket).toHaveProperty('count');
        expect(typeof bracket.count).toBe('number');
      }

      const rawBody = res.body;
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain('patient');
    });

    it('GET /analytics/kpis returns KPI cards with delta, no individual patient data', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body).data;
      expect(data).toHaveProperty('totalRevenue');
      expect(data.totalRevenue).toHaveProperty('current');
      expect(data.totalRevenue).toHaveProperty('prior');
      expect(data.totalRevenue).toHaveProperty('delta');

      const rawBody = res.body;
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain('patient');
    });

    it('no dashboard response contains patient_id, phn, or patient names', async () => {
      const endpoints = [
        '/api/v1/analytics/revenue?period=THIS_MONTH',
        '/api/v1/analytics/rejections?period=THIS_MONTH',
        '/api/v1/analytics/aging',
        '/api/v1/analytics/ai-coach?period=THIS_MONTH',
        '/api/v1/analytics/kpis?period=THIS_MONTH',
      ];

      for (const url of endpoints) {
        const res = await injectAs(P1_TOKEN, 'GET', url);
        const rawBody = res.body;
        expect(rawBody).not.toContain(TEST_PHN);
        expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
        expect(rawBody).not.toContain(TEST_PATIENT_LAST);
        expect(rawBody).not.toContain('"phn"');
        expect(rawBody).not.toContain('"patient_name"');
      }
    });
  });

  // =========================================================================
  // Report status response: safe fields only
  // =========================================================================

  describe('Report status responses expose only safe metadata', () => {
    it('GET /reports/:id includes status, file_size, expiry — NOT file_path, NOT report content', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const data = body.data;

      // Expected fields present
      expect(data).toHaveProperty('report_id');
      expect(data).toHaveProperty('status');
      expect(data).toHaveProperty('file_size_bytes');
      expect(data.status).toBe('ready');
      expect(data.file_size_bytes).toBe(2048);

      // Internal fields NOT present
      expect(data).not.toHaveProperty('file_path');
      expect(data).not.toHaveProperty('filePath');
      expect(data).not.toHaveProperty('error_message');
      expect(data).not.toHaveProperty('errorMessage');
      expect(data).not.toHaveProperty('provider_id');
      expect(data).not.toHaveProperty('providerId');
    });

    it('file_size_bytes is null when report is not ready', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${FAILED_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('failed');
      expect(body.data.file_size_bytes).toBeNull();
    });
  });

  // =========================================================================
  // Generated report error paths
  // =========================================================================

  describe('Failed report generation shows generic error only', () => {
    it('failed report API response shows status "failed" with no PHI in response', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${FAILED_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('failed');
      const rawBody = res.body;
      // No internal error details, no PHI, no file paths
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain('Database');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain(INTERNAL_FILE_PATH);
    });

    it('failed report does not expose error_message field to API consumer', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${FAILED_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // The sanitizeReport function should strip errorMessage
      expect(body.data).not.toHaveProperty('error_message');
      expect(body.data).not.toHaveProperty('errorMessage');
    });

    it('downloading a failed report returns 404, not error details', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${FAILED_REPORT_ID}/download`);

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      expect(body.error).not.toHaveProperty('details');
    });
  });

  // =========================================================================
  // Dashboard query logs contain no PHI
  // =========================================================================

  describe('Audit log calls contain no PHI (logged fields verification)', () => {
    it('dashboard audit log contains provider_id and dashboardType but NOT patient data', async () => {
      const deps = createLeakageDashboardDeps();
      const auditLog = deps.auditLog as ReturnType<typeof vi.fn>;

      // Re-register with trackable deps (rebuild app scoped for this test)
      const testApp = Fastify({ logger: false });
      testApp.setValidatorCompiler(validatorCompiler);
      testApp.setSerializerCompiler(serializerCompiler);

      const mockSessionRepo = createMockSessionRepo();
      const sessionDeps = {
        sessionRepo: mockSessionRepo,
        auditRepo: { appendAuditLog: vi.fn(async () => {}) },
        events: { emit: vi.fn() },
      };
      await testApp.register(authPluginFp, { sessionDeps });
      testApp.setErrorHandler((error, _request, reply) => {
        if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
          return reply.code(error.statusCode).send({
            error: { code: (error as any).code ?? 'ERROR', message: error.message },
          });
        }
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });
      await testApp.register(dashboardRoutes, { deps });
      await testApp.ready();

      // Seed session for this sub-app
      seedIdentities();

      await testApp.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: { cookie: `session=${P1_TOKEN}` },
      });

      // Check audit log call if it was made
      if (auditLog.mock.calls.length > 0) {
        const logEntry = auditLog.mock.calls[0][0];
        expect(logEntry).toHaveProperty('action');
        expect(logEntry).toHaveProperty('providerId');
        expect(logEntry).toHaveProperty('details');
        const logStr = JSON.stringify(logEntry);
        expect(logStr).not.toContain(TEST_PHN);
        expect(logStr).not.toContain(TEST_PATIENT_FIRST);
        expect(logStr).not.toContain(TEST_PATIENT_LAST);
        expect(logStr).toContain('dashboardType');
      }

      await testApp.close();
    });

    it('report generation audit log contains report_id and type but NOT file contents or patient data', async () => {
      const deps = createLeakageReportDeps();
      const auditLog = deps.auditLog as ReturnType<typeof vi.fn>;

      const testApp = Fastify({ logger: false });
      testApp.setValidatorCompiler(validatorCompiler);
      testApp.setSerializerCompiler(serializerCompiler);

      const mockSessionRepo = createMockSessionRepo();
      const sessionDeps = {
        sessionRepo: mockSessionRepo,
        auditRepo: { appendAuditLog: vi.fn(async () => {}) },
        events: { emit: vi.fn() },
      };
      await testApp.register(authPluginFp, { sessionDeps });
      testApp.setErrorHandler((error, _request, reply) => {
        if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
          return reply.code(error.statusCode).send({
            error: { code: (error as any).code ?? 'ERROR', message: error.message },
          });
        }
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });
      await testApp.register(reportRoutes, { deps });
      await testApp.ready();

      seedIdentities();

      await testApp.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        headers: { cookie: `session=${P1_TOKEN}` },
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
      });

      if (auditLog.mock.calls.length > 0) {
        const logEntry = auditLog.mock.calls[0][0];
        expect(logEntry).toHaveProperty('action');
        expect(logEntry).toHaveProperty('providerId');
        const logStr = JSON.stringify(logEntry);
        expect(logStr).not.toContain(TEST_PHN);
        expect(logStr).not.toContain(TEST_PATIENT_FIRST);
        expect(logStr).not.toContain(TEST_PATIENT_LAST);
        expect(logStr).not.toContain(INTERNAL_FILE_PATH);
        // Should contain reportId and reportType (safe metadata)
        expect(logStr).toContain('reportId');
        expect(logStr).toContain('reportType');
      }

      await testApp.close();
    });
  });

  // =========================================================================
  // Internal fields never leak to responses across all endpoints
  // =========================================================================

  describe('No internal identifiers or paths leak in any response', () => {
    it('report list never contains file_path, errorMessage, or provider_id', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const report of body.data) {
        expect(report).not.toHaveProperty('file_path');
        expect(report).not.toHaveProperty('filePath');
        expect(report).not.toHaveProperty('error_message');
        expect(report).not.toHaveProperty('errorMessage');
        expect(report).not.toHaveProperty('provider_id');
        expect(report).not.toHaveProperty('providerId');
      }
    });

    it('newly created report response does not leak file_path', async () => {
      const res = await injectAs(P1_TOKEN, 'POST', '/api/v1/reports/accountant', {
        format: 'csv',
        period_start: '2026-01-01',
        period_end: '2026-01-31',
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('file_path');
      expect(body.data).not.toHaveProperty('filePath');
      // POST response is minimal: report_id + status
      expect(body.data).toHaveProperty('report_id');
      expect(body.data).toHaveProperty('status');
    });

    it('data portability creation response does not leak file_path', async () => {
      const res = await injectAs(P1_TOKEN, 'POST', '/api/v1/reports/data-portability', {});

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).not.toHaveProperty('file_path');
      expect(body.data).not.toHaveProperty('filePath');
    });
  });
});
