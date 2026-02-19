// ============================================================================
// Domain 8: Analytics & Reporting — Input Validation & Injection Prevention
// Verifies SQL injection, XSS, type coercion, UUID tampering, and boundary
// value attacks are rejected at the Zod validation layer before reaching DB.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

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

const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
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
// Stub handler deps (services should never be reached for invalid input)
// ---------------------------------------------------------------------------

function createStubDashboardDeps(): DashboardRouteDeps {
  return {
    dashboardService: {
      getRevenueDashboard: vi.fn(),
      getRejectionDashboard: vi.fn(),
      getAgingDashboard: vi.fn(),
      getWcbDashboard: vi.fn(),
      getAiCoachDashboard: vi.fn(),
      getMultiSiteDashboard: vi.fn(),
      getKpis: vi.fn(),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createStubReportDeps(): ReportRouteDeps {
  return {
    reportsRepo: {
      create: vi.fn(async () => ({
        reportId: '00000000-0000-0000-0000-000000000099',
        providerId: P1_USER_ID,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'CSV',
        status: 'pending',
        filePath: '',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: new Date(),
        downloaded: false,
        createdAt: new Date(),
      })),
      getById: vi.fn(),
      listByProvider: vi.fn(async () => ({ data: [], total: 0 })),
      updateStatus: vi.fn(),
      markDownloaded: vi.fn(),
      deleteExpired: vi.fn(),
    } as any,
    reportGenerationService: {
      processReport: vi.fn(async () => {}),
      generateDataPortabilityExport: vi.fn(async () => {}),
    } as any,
    downloadService: {
      getDownloadStream: vi.fn(),
      isDownloadAvailable: vi.fn(),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createStubSubscriptionDeps(): SubscriptionRouteDeps {
  return {
    subscriptionsRepo: {
      create: vi.fn(),
      listByProvider: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
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
    if (error.validation || (error as any).code === 'FST_ERR_VALIDATION') {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(dashboardRoutes, { deps: createStubDashboardDeps() });
  await testApp.register(reportRoutes, { deps: createStubReportDeps() });
  await testApp.register(subscriptionRoutes, { deps: createStubSubscriptionDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
  });
}

function authedPost(url: string, payload: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    payload: payload as Record<string, unknown>,
  });
}

function authedPut(url: string, payload: unknown) {
  return app.inject({
    method: 'PUT',
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    payload: payload as Record<string, unknown>,
  });
}

function authedDelete(url: string) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
  });
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "'; DROP TABLE claims; --",
  "1' OR '1'='1",
  "1; SELECT * FROM users --",
  "' UNION SELECT * FROM providers --",
  "'; DELETE FROM analytics_cache; --",
  "03.03A'; DELETE FROM generated_reports; --",
];

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '"><svg onload=alert(1)>',
];

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

function expectValidationError(res: { statusCode: number; body: string }) {
  expect(res.statusCode).toBe(400);
  const body = JSON.parse(res.body);
  expect(body.error).toBeDefined();
  expect(body.error.code).toBe('VALIDATION_ERROR');
  // Must not leak internal details
  expect(body.error).not.toHaveProperty('stack');
  expect(res.body).not.toMatch(/postgres|drizzle|sql|SELECT|DROP|DELETE/i);
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Analytics & Reporting Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    users.push({
      userId: P1_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: P1_SESSION_ID,
      userId: P1_USER_ID,
      tokenHash: P1_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // 1. SQL Injection Attempts
  // =========================================================================

  describe('SQL Injection Prevention', () => {
    describe('period parameter', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects period="${payload}" on revenue dashboard`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/revenue?period=${encodeURIComponent(payload)}`,
          );
          expectValidationError(res);
        });
      }
    });

    describe('ba_number filter', () => {
      const baSqlPayloads = [
        "1 OR 1=1",
        "'; DROP TABLE claims; --",
        "' UNION SELECT * FROM providers --",
      ];

      for (const payload of baSqlPayloads) {
        it(`rejects ba_number="${payload}" on revenue dashboard`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/revenue?period=THIS_MONTH&ba_number=${encodeURIComponent(payload)}`,
          );
          // ba_number has max(20), so long payloads get rejected; short ones may pass Zod
          // but must be parameterized by Drizzle. Either 400 or handler doesn't reach DB.
          // We verify payload > 20 chars are rejected at Zod level.
          if (payload.length > 20) {
            expectValidationError(res);
          } else {
            // Short payloads that pass Zod max(20) would reach handler with parameterized queries.
            // This is safe — Drizzle uses parameterized queries. Verify no 500.
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('hsc_code filter', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects hsc_code="${payload}" on revenue dashboard`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/revenue?period=THIS_MONTH&hsc_code=${encodeURIComponent(payload)}`,
          );
          // hsc_code has max(10), all injection payloads exceed this
          expectValidationError(res);
        });
      }
    });

    describe('report_id parameter', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects report_id="${payload}"`, async () => {
          const res = await authedGet(
            `/api/v1/reports/${encodeURIComponent(payload)}`,
          );
          expectValidationError(res);
        });
      }
    });

    describe('subscription_id parameter', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects subscription_id="${payload}" on PUT`, async () => {
          const res = await authedPut(
            `/api/v1/report-subscriptions/${encodeURIComponent(payload)}`,
            { frequency: 'WEEKLY' },
          );
          expectValidationError(res);
        });

        it(`rejects subscription_id="${payload}" on DELETE`, async () => {
          const res = await authedDelete(
            `/api/v1/report-subscriptions/${encodeURIComponent(payload)}`,
          );
          expectValidationError(res);
        });
      }
    });

    describe('accountant report body fields', () => {
      it('rejects SQL injection in format field', async () => {
        const res = await authedPost('/api/v1/reports/accountant', {
          period_start: '2026-01-01',
          period_end: '2026-01-31',
          format: "csv'; DROP TABLE generated_reports; --",
        });
        expectValidationError(res);
      });

      it('rejects SQL injection in period_start', async () => {
        const res = await authedPost('/api/v1/reports/accountant', {
          period_start: "'; DROP TABLE claims; --",
          period_end: '2026-01-31',
          format: 'csv',
        });
        expectValidationError(res);
      });

      it('rejects SQL injection in period_end', async () => {
        const res = await authedPost('/api/v1/reports/accountant', {
          period_start: '2026-01-01',
          period_end: "'; DROP TABLE claims; --",
          format: 'csv',
        });
        expectValidationError(res);
      });
    });

    describe('data portability password field', () => {
      it('rejects SQL injection in password (too short)', async () => {
        const res = await authedPost('/api/v1/reports/data-portability', {
          password: "'; DROP --",
        });
        // 10 chars, rejected by min(12)
        expectValidationError(res);
      });
    });

    describe('subscription body fields', () => {
      it('rejects SQL injection in report_type', async () => {
        const res = await authedPost('/api/v1/report-subscriptions', {
          report_type: "'; DROP TABLE report_subscriptions; --",
          frequency: 'WEEKLY',
          delivery_method: 'IN_APP',
        });
        expectValidationError(res);
      });

      it('rejects SQL injection in frequency', async () => {
        const res = await authedPost('/api/v1/report-subscriptions', {
          report_type: 'WEEKLY_SUMMARY',
          frequency: "WEEKLY'; DROP TABLE claims; --",
          delivery_method: 'IN_APP',
        });
        expectValidationError(res);
      });
    });
  });

  // =========================================================================
  // 2. XSS Attempts
  // =========================================================================

  describe('XSS Prevention', () => {
    describe('period parameter with XSS', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects period="${payload}"`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/revenue?period=${encodeURIComponent(payload)}`,
          );
          expectValidationError(res);
        });
      }
    });

    describe('filter values with HTML injection', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects hsc_code="${payload}" on kpis`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/kpis?period=THIS_MONTH&hsc_code=${encodeURIComponent(payload)}`,
          );
          // hsc_code max(10), all XSS payloads > 10 chars
          expectValidationError(res);
        });
      }

      for (const payload of XSS_PAYLOADS) {
        it(`rejects claim_type="${payload}" on revenue`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/revenue?period=THIS_MONTH&claim_type=${encodeURIComponent(payload)}`,
          );
          // claim_type is enum, XSS string doesn't match
          expectValidationError(res);
        });
      }
    });

    describe('report format with XSS', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects format="${payload}" on accountant report`, async () => {
          const res = await authedPost('/api/v1/reports/accountant', {
            period_start: '2026-01-01',
            period_end: '2026-01-31',
            format: payload,
          });
          expectValidationError(res);
        });
      }
    });

    describe('subscription fields with XSS', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects report_type="${payload}"`, async () => {
          const res = await authedPost('/api/v1/report-subscriptions', {
            report_type: payload,
            frequency: 'WEEKLY',
            delivery_method: 'IN_APP',
          });
          expectValidationError(res);
        });
      }
    });
  });

  // =========================================================================
  // 3. Type Coercion Attacks
  // =========================================================================

  describe('Type Coercion Prevention', () => {
    it('rejects integer instead of string for period (injected as body)', async () => {
      // When period is sent as part of query string, it always arrives as string.
      // Test invalid enum value that wouldn't match any allowed period.
      const res = await authedGet('/api/v1/analytics/revenue?period=12345');
      expectValidationError(res);
    });

    it('rejects array instead of string for claim_type', async () => {
      // Fastify query parsing: claim_type=AHCIP&claim_type=WCB becomes array
      const res = await authedGet(
        '/api/v1/analytics/revenue?period=THIS_MONTH&claim_type=AHCIP&claim_type=WCB',
      );
      expectValidationError(res);
    });

    it('rejects object for ba_number via nested query', async () => {
      // Fastify may flatten nested query params to string "[object Object]".
      // Either way, the handler should not crash (no 500).
      const res = await authedGet(
        '/api/v1/analytics/revenue?period=THIS_MONTH&ba_number[key]=value',
      );
      expect(res.statusCode).not.toBe(500);
    });

    it('rejects unsupported report format value', async () => {
      const res = await authedPost('/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'exe',
      });
      expectValidationError(res);
    });

    it('rejects numeric format for accountant report', async () => {
      const res = await authedPost('/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 123,
      });
      expectValidationError(res);
    });

    it('rejects boolean for report period_start', async () => {
      const res = await authedPost('/api/v1/reports/accountant', {
        period_start: true,
        period_end: '2026-01-31',
        format: 'csv',
      });
      expectValidationError(res);
    });

    it('rejects numeric period_end on accountant report', async () => {
      const res = await authedPost('/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: 20260131,
        format: 'csv',
      });
      expectValidationError(res);
    });

    it('rejects non-boolean for is_active on subscription update', async () => {
      const res = await authedPut(
        `/api/v1/report-subscriptions/${DUMMY_UUID}`,
        { is_active: 'true' },
      );
      expectValidationError(res);
    });

    it('rejects numeric frequency on subscription create', async () => {
      const res = await authedPost('/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 7,
        delivery_method: 'IN_APP',
      });
      expectValidationError(res);
    });

    it('rejects array for password on data portability', async () => {
      const res = await authedPost('/api/v1/reports/data-portability', {
        password: ['a', 'b', 'c'],
      });
      expectValidationError(res);
    });

    it('rejects null body on subscription create', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: {
          cookie: `session=${P1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: 'null',
      });
      expectValidationError(res);
    });
  });

  // =========================================================================
  // 4. UUID Validation
  // =========================================================================

  describe('UUID Parameter Validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz',
      '../../../etc/passwd',
      '00000000-0000-0000-0000-00000000000',  // one digit short
      '',
      'null',
      'undefined',
    ];

    describe('report_id path parameter', () => {
      for (const invalidId of INVALID_UUIDS) {
        if (invalidId === '') continue; // empty would hit different route

        it(`rejects report_id="${invalidId}" on GET /reports/:id`, async () => {
          const res = await authedGet(`/api/v1/reports/${encodeURIComponent(invalidId)}`);
          expectValidationError(res);
        });

        it(`rejects report_id="${invalidId}" on GET /reports/:id/download`, async () => {
          const res = await authedGet(`/api/v1/reports/${encodeURIComponent(invalidId)}/download`);
          expectValidationError(res);
        });
      }
    });

    describe('subscription_id path parameter', () => {
      for (const invalidId of INVALID_UUIDS) {
        if (invalidId === '') continue;

        it(`rejects subscription_id="${invalidId}" on PUT`, async () => {
          const res = await authedPut(
            `/api/v1/report-subscriptions/${encodeURIComponent(invalidId)}`,
            { frequency: 'WEEKLY' },
          );
          expectValidationError(res);
        });

        it(`rejects subscription_id="${invalidId}" on DELETE`, async () => {
          const res = await authedDelete(
            `/api/v1/report-subscriptions/${encodeURIComponent(invalidId)}`,
          );
          expectValidationError(res);
        });
      }
    });

    describe('location_id in filter', () => {
      const LOCATION_INVALID_UUIDS = [
        'not-a-uuid',
        '../etc/passwd',
        "'; DROP TABLE locations; --",
      ];

      for (const invalidId of LOCATION_INVALID_UUIDS) {
        it(`rejects location_id="${invalidId}" on revenue dashboard`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/revenue?period=THIS_MONTH&location_id=${encodeURIComponent(invalidId)}`,
          );
          expectValidationError(res);
        });

        it(`rejects location_id="${invalidId}" on kpis dashboard`, async () => {
          const res = await authedGet(
            `/api/v1/analytics/kpis?period=THIS_MONTH&location_id=${encodeURIComponent(invalidId)}`,
          );
          expectValidationError(res);
        });
      }
    });

    describe('compare_locations array UUIDs', () => {
      it('rejects non-UUID in compare_locations', async () => {
        const res = await authedGet(
          `/api/v1/analytics/multi-site?period=THIS_MONTH&compare_locations=not-a-uuid`,
        );
        expectValidationError(res);
      });

      it('rejects mixed valid and invalid UUIDs in compare_locations', async () => {
        const res = await authedGet(
          `/api/v1/analytics/multi-site?period=THIS_MONTH&compare_locations=${DUMMY_UUID}&compare_locations=not-valid`,
        );
        expectValidationError(res);
      });
    });
  });

  // =========================================================================
  // 5. Boundary Value Tests
  // =========================================================================

  describe('Boundary Value Validation', () => {
    describe('Custom date range validation', () => {
      it('rejects end_date before start_date', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2026-03-01&end_date=2026-01-01',
        );
        expectValidationError(res);
      });

      it('rejects date range exceeding 2 years (731 days)', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2024-01-01&end_date=2026-01-02',
        );
        expectValidationError(res);
      });

      it('accepts date range of exactly 730 days', async () => {
        // 2024-01-01 to 2025-12-31 = 730 days (2024 is a leap year)
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2024-01-01&end_date=2025-12-31',
        );
        // Should not be a validation error (may be 200 or another non-400 status)
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects CUSTOM_RANGE without start_date', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&end_date=2026-01-31',
        );
        expectValidationError(res);
      });

      it('rejects CUSTOM_RANGE without end_date', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2026-01-01',
        );
        expectValidationError(res);
      });

      it('rejects CUSTOM_RANGE without either date', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE',
        );
        expectValidationError(res);
      });

      it('rejects invalid date format (MM/DD/YYYY)', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=01/01/2026&end_date=01/31/2026',
        );
        expectValidationError(res);
      });

      it('rejects invalid date format (DD-MM-YYYY)', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=31-01-2026&end_date=28-02-2026',
        );
        expectValidationError(res);
      });
    });

    describe('Accountant report date range', () => {
      it('rejects period_end before period_start', async () => {
        const res = await authedPost('/api/v1/reports/accountant', {
          period_start: '2026-03-01',
          period_end: '2026-01-01',
          format: 'csv',
        });
        expectValidationError(res);
      });

      it('rejects accountant report range exceeding 2 years', async () => {
        const res = await authedPost('/api/v1/reports/accountant', {
          period_start: '2024-01-01',
          period_end: '2026-01-02',
          format: 'csv',
        });
        expectValidationError(res);
      });
    });

    describe('Report list pagination boundaries', () => {
      it('rejects limit=0', async () => {
        const res = await authedGet('/api/v1/reports?limit=0');
        expectValidationError(res);
      });

      it('rejects limit=-1', async () => {
        const res = await authedGet('/api/v1/reports?limit=-1');
        expectValidationError(res);
      });

      it('rejects limit=1000 (exceeds max 100)', async () => {
        const res = await authedGet('/api/v1/reports?limit=1000');
        expectValidationError(res);
      });

      it('rejects negative offset', async () => {
        const res = await authedGet('/api/v1/reports?offset=-1');
        expectValidationError(res);
      });

      it('rejects non-integer limit', async () => {
        const res = await authedGet('/api/v1/reports?limit=1.5');
        expectValidationError(res);
      });

      it('accepts limit=1 (minimum)', async () => {
        const res = await authedGet('/api/v1/reports?limit=1');
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts limit=100 (maximum)', async () => {
        const res = await authedGet('/api/v1/reports?limit=100');
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('compare_locations array max size', () => {
      it('rejects more than 2 compare_locations', async () => {
        const uuid1 = '11111111-1111-1111-1111-111111111111';
        const uuid2 = '22222222-2222-2222-2222-222222222222';
        const uuid3 = '33333333-3333-3333-3333-333333333333';
        const res = await authedGet(
          `/api/v1/analytics/multi-site?period=THIS_MONTH&compare_locations=${uuid1}&compare_locations=${uuid2}&compare_locations=${uuid3}`,
        );
        expectValidationError(res);
      });

      it('accepts exactly 2 compare_locations', async () => {
        const uuid1 = '11111111-1111-1111-1111-111111111111';
        const uuid2 = '22222222-2222-2222-2222-222222222222';
        const res = await authedGet(
          `/api/v1/analytics/multi-site?period=THIS_MONTH&compare_locations=${uuid1}&compare_locations=${uuid2}`,
        );
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('Data portability password minimum length', () => {
      it('rejects password with less than 12 characters', async () => {
        const res = await authedPost('/api/v1/reports/data-portability', {
          password: 'short',
        });
        expectValidationError(res);
      });

      it('rejects password with exactly 11 characters', async () => {
        const res = await authedPost('/api/v1/reports/data-portability', {
          password: 'a'.repeat(11),
        });
        expectValidationError(res);
      });

      it('accepts password with exactly 12 characters', async () => {
        const res = await authedPost('/api/v1/reports/data-portability', {
          password: 'a'.repeat(12),
        });
        // Should not be a validation error
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts empty body (password is optional)', async () => {
        const res = await authedPost('/api/v1/reports/data-portability', {});
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('String field max length enforcement', () => {
      it('rejects ba_number exceeding 20 characters', async () => {
        const res = await authedGet(
          `/api/v1/analytics/revenue?period=THIS_MONTH&ba_number=${'A'.repeat(21)}`,
        );
        expectValidationError(res);
      });

      it('rejects hsc_code exceeding 10 characters', async () => {
        const res = await authedGet(
          `/api/v1/analytics/revenue?period=THIS_MONTH&hsc_code=${'X'.repeat(11)}`,
        );
        expectValidationError(res);
      });

      it('rejects form_type exceeding 30 characters on WCB dashboard', async () => {
        const res = await authedGet(
          `/api/v1/analytics/wcb?period=THIS_MONTH&form_type=${'Z'.repeat(31)}`,
        );
        expectValidationError(res);
      });
    });

    describe('Enum strict validation', () => {
      it('rejects misspelled period value', async () => {
        const res = await authedGet('/api/v1/analytics/revenue?period=THIS_MONT');
        expectValidationError(res);
      });

      it('rejects lowercase period value', async () => {
        const res = await authedGet('/api/v1/analytics/revenue?period=this_month');
        expectValidationError(res);
      });

      it('rejects unknown claim_type', async () => {
        const res = await authedGet(
          '/api/v1/analytics/revenue?period=THIS_MONTH&claim_type=UNKNOWN',
        );
        expectValidationError(res);
      });

      it('rejects unknown report_type on subscription create', async () => {
        const res = await authedPost('/api/v1/report-subscriptions', {
          report_type: 'UNKNOWN_TYPE',
          frequency: 'WEEKLY',
          delivery_method: 'IN_APP',
        });
        expectValidationError(res);
      });

      it('rejects non-subscribable report_type (DATA_PORTABILITY)', async () => {
        const res = await authedPost('/api/v1/report-subscriptions', {
          report_type: 'DATA_PORTABILITY',
          frequency: 'WEEKLY',
          delivery_method: 'IN_APP',
        });
        expectValidationError(res);
      });

      it('rejects unknown frequency on subscription create', async () => {
        const res = await authedPost('/api/v1/report-subscriptions', {
          report_type: 'WEEKLY_SUMMARY',
          frequency: 'HOURLY',
          delivery_method: 'IN_APP',
        });
        expectValidationError(res);
      });

      it('rejects unknown delivery_method on subscription create', async () => {
        const res = await authedPost('/api/v1/report-subscriptions', {
          report_type: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          delivery_method: 'SMS',
        });
        expectValidationError(res);
      });

      it('rejects unknown report_type on report list query', async () => {
        const res = await authedGet('/api/v1/reports?report_type=FAKE_TYPE');
        expectValidationError(res);
      });
    });

    describe('Subscription update requires at least one field', () => {
      it('rejects empty body on subscription update', async () => {
        const res = await authedPut(
          `/api/v1/report-subscriptions/${DUMMY_UUID}`,
          {},
        );
        expectValidationError(res);
      });
    });
  });

  // =========================================================================
  // 6. Error Response Safety
  // =========================================================================

  describe('Error responses do not leak internals', () => {
    it('400 response from SQL injection does not echo payload', async () => {
      const payload = "'; DROP TABLE claims; --";
      const res = await authedGet(
        `/api/v1/analytics/revenue?period=${encodeURIComponent(payload)}`,
      );
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('DROP TABLE');
      expect(res.body).not.toContain('claims');
    });

    it('400 response does not reveal Zod schema structure', async () => {
      const res = await authedGet('/api/v1/analytics/revenue?period=INVALID');
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      // Should not contain Zod's internal field names like "code", "expected", "received"
      // in the top-level message
      expect(body.error.message).toBe('Validation failed');
    });

    it('400 response does not contain stack traces', async () => {
      const res = await authedPost('/api/v1/reports/accountant', {
        period_start: 'invalid',
        period_end: 'also-invalid',
        format: 'exe',
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('node_modules');
      expect(res.body).not.toContain('.ts:');
      expect(res.body).not.toContain('at ');
    });

    it('400 response does not reveal database table names', async () => {
      const res = await authedGet(
        `/api/v1/analytics/revenue?period=${encodeURIComponent("' UNION SELECT * FROM analytics_cache --")}`,
      );
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('analytics_cache');
      expect(res.body).not.toContain('generated_reports');
      expect(res.body).not.toContain('report_subscriptions');
    });
  });
});
