// ============================================================================
// Domain 8: Analytics & Reporting — Authentication Enforcement (Security)
// Verifies every authenticated route returns 401 without valid session.
// 16 routes x 3 auth failure modes = 48+ test cases.
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

const VALID_SESSION_TOKEN = randomBytes(32).toString('hex');
const VALID_SESSION_TOKEN_HASH = hashToken(VALID_SESSION_TOKEN);
const VALID_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const VALID_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = 'cccc0000-0000-0000-0000-000000000001';

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
// Mock session repository (consumed by auth plugin)
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
// Stub handler deps (not exercised — requests should never reach handlers)
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
      create: vi.fn(),
      getById: vi.fn(),
      listByProvider: vi.fn(),
      updateStatus: vi.fn(),
      markDownloaded: vi.fn(),
      deleteExpired: vi.fn(),
    } as any,
    reportGenerationService: {
      processReport: vi.fn(),
      generateDataPortabilityExport: vi.fn(),
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
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
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

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

// ---------------------------------------------------------------------------
// Route specs — all 17 authenticated analytics endpoints
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AUTHENTICATED_ROUTES: RouteSpec[] = [
  // ---- Dashboard routes (7 GET endpoints) ----
  // Most require `period` query param to pass Zod validation before preHandler.
  {
    method: 'GET',
    url: '/api/v1/analytics/revenue?period=THIS_MONTH',
    description: 'Revenue dashboard',
  },
  {
    method: 'GET',
    url: '/api/v1/analytics/rejections?period=THIS_MONTH',
    description: 'Rejections dashboard',
  },
  {
    method: 'GET',
    url: '/api/v1/analytics/aging',
    description: 'Aging dashboard',
  },
  {
    method: 'GET',
    url: '/api/v1/analytics/wcb?period=THIS_MONTH',
    description: 'WCB dashboard',
  },
  {
    method: 'GET',
    url: '/api/v1/analytics/ai-coach?period=THIS_MONTH',
    description: 'AI Coach dashboard',
  },
  {
    method: 'GET',
    url: '/api/v1/analytics/multi-site?period=THIS_MONTH',
    description: 'Multi-site dashboard',
  },
  {
    method: 'GET',
    url: '/api/v1/analytics/kpis?period=THIS_MONTH',
    description: 'KPI cards',
  },

  // ---- Report routes (5 endpoints) ----
  {
    method: 'POST',
    url: '/api/v1/reports/accountant',
    payload: {
      format: 'csv',
      period_start: '2026-01-01',
      period_end: '2026-01-31',
    },
    description: 'Generate accountant report',
  },
  {
    method: 'POST',
    url: '/api/v1/reports/data-portability',
    payload: {},
    description: 'Generate data portability export',
  },
  {
    method: 'GET',
    url: `/api/v1/reports/${DUMMY_UUID}`,
    description: 'Get report status',
  },
  {
    method: 'GET',
    url: `/api/v1/reports/${DUMMY_UUID}/download`,
    description: 'Download report',
  },
  {
    method: 'GET',
    url: '/api/v1/reports',
    description: 'List reports',
  },

  // ---- Subscription routes (4 endpoints) ----
  {
    method: 'GET',
    url: '/api/v1/report-subscriptions',
    description: 'List subscriptions',
  },
  {
    method: 'POST',
    url: '/api/v1/report-subscriptions',
    payload: {
      report_type: 'WEEKLY_SUMMARY',
      frequency: 'WEEKLY',
      delivery_method: 'IN_APP',
    },
    description: 'Create subscription',
  },
  {
    method: 'PUT',
    url: `/api/v1/report-subscriptions/${DUMMY_UUID}`,
    payload: {
      frequency: 'WEEKLY',
    },
    description: 'Update subscription',
  },
  {
    method: 'DELETE',
    url: `/api/v1/report-subscriptions/${DUMMY_UUID}`,
    description: 'Delete subscription',
  },
];

// ---------------------------------------------------------------------------
// Assertion: 17 routes
// ---------------------------------------------------------------------------

if (AUTHENTICATED_ROUTES.length !== 16) {
  throw new Error(
    `Expected 16 authenticated routes but found ${AUTHENTICATED_ROUTES.length}. ` +
      'Update the route specs to match the registered analytics routes.',
  );
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Analytics & Reporting Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    // Seed a valid user + active session (for sanity checks)
    users.push({
      userId: VALID_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: VALID_SESSION_ID,
      userId: VALID_USER_ID,
      tokenHash: VALID_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Seed an expired/revoked session
    sessions.push({
      sessionId: EXPIRED_SESSION_ID,
      userId: VALID_USER_ID,
      tokenHash: EXPIRED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
      lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
      revoked: true,
      revokedReason: 'expired_absolute',
    });
  });

  // =========================================================================
  // No Cookie — each route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 without session cookie`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired/Revoked Cookie — each route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with expired session`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Tampered Cookie — each route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with tampered cookie`, async () => {
        const tamperedToken = createTamperedCookie();
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${tamperedToken}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Empty cookie value — returns 401
  // =========================================================================

  describe('Requests with empty session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with empty cookie value`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: 'session=' },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Wrong cookie name — returns 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: { cookie: `token=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/reports',
        headers: { cookie: `auth=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/report-subscriptions',
        headers: { cookie: `sid=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (confirms test setup)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/analytics/revenue returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/reports returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/reports',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/report-subscriptions returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/report-subscriptions',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 response body must not leak analytics data
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response does not leak analytics or report data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/kpis?period=THIS_MONTH',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('revenue');
      expect(rawBody).not.toContain('rejection');
      expect(rawBody).not.toContain('claim');
      expect(rawBody).not.toContain('report');
      expect(rawBody).not.toContain('subscription');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/data-portability',
        payload: {},
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });
});
