// ============================================================================
// Domain 8: Analytics & Reporting — Authorization & Permission Enforcement
// Verifies role-based access, delegate permission boundaries, and the
// ANALYTICS_VIEW / REPORT_VIEW / REPORT_EXPORT / DATA_EXPORT permission
// hierarchy. Tests both positive (allowed) and negative (403) cases.
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

// Physician — full permissions (role = PHYSICIAN)
const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Delegate with NO analytics permissions at all (only CLAIM_VIEW)
const DELEGATE_NONE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_TOKEN_HASH = hashToken(DELEGATE_NONE_TOKEN);
const DELEGATE_NONE_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const DELEGATE_NONE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';

// Delegate with REPORT_VIEW only (can view dashboards/reports, cannot export)
const DELEGATE_VIEW_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_TOKEN_HASH = hashToken(DELEGATE_VIEW_TOKEN);
const DELEGATE_VIEW_USER_ID = 'aaaa0000-0000-0000-0000-000000000003';
const DELEGATE_VIEW_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000003';

// Delegate with REPORT_EXPORT (can generate/download reports, but no DATA_EXPORT)
const DELEGATE_EXPORT_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_EXPORT_TOKEN_HASH = hashToken(DELEGATE_EXPORT_TOKEN);
const DELEGATE_EXPORT_USER_ID = 'aaaa0000-0000-0000-0000-000000000004';
const DELEGATE_EXPORT_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000004';

// Delegate with full analytics permissions (ANALYTICS_VIEW + REPORT_VIEW + REPORT_EXPORT + DATA_EXPORT)
const DELEGATE_FULL_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_FULL_TOKEN_HASH = hashToken(DELEGATE_FULL_TOKEN);
const DELEGATE_FULL_USER_ID = 'aaaa0000-0000-0000-0000-000000000005';
const DELEGATE_FULL_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000005';

const PHYSICIAN_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000001';
const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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
// Stub handler deps
// ---------------------------------------------------------------------------

function createStubDashboardDeps(): DashboardRouteDeps {
  return {
    dashboardService: {
      getRevenueDashboard: vi.fn(async () => ({ revenue: [] })),
      getRejectionDashboard: vi.fn(async () => ({ rejections: [] })),
      getAgingDashboard: vi.fn(async () => ({ aging: [] })),
      getWcbDashboard: vi.fn(async () => ({ wcb: [] })),
      getAiCoachDashboard: vi.fn(async () => ({ coach: [] })),
      getMultiSiteDashboard: vi.fn(async () => ({ sites: [] })),
      getKpis: vi.fn(async () => ({ kpis: {} })),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createStubReportDeps(): ReportRouteDeps {
  return {
    reportsRepo: {
      create: vi.fn(async () => ({
        reportId: DUMMY_UUID,
        status: 'pending',
      })),
      getById: vi.fn(async () => null),
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
      create: vi.fn(async () => ({
        subscriptionId: DUMMY_UUID,
        providerId: PHYSICIAN_PROVIDER_ID,
        reportType: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
        deliveryMethod: 'IN_APP',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      })),
      listByProvider: vi.fn(async () => []),
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

// ---------------------------------------------------------------------------
// Seed data helper — populates sessions and users for each test
// ---------------------------------------------------------------------------

function seedTestIdentities() {
  sessions = [];
  users = [];

  const now = new Date();

  // Physician — full access (PHYSICIAN role has all permissions)
  users.push({
    userId: PHYSICIAN_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: now,
    lastActiveAt: now,
    revoked: false,
    revokedReason: null,
  });

  // Delegate with NO analytics permissions (only CLAIM_VIEW)
  users.push({
    userId: DELEGATE_NONE_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_NONE_USER_ID,
      physicianProviderId: PHYSICIAN_PROVIDER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: 'link-001',
    },
  });
  sessions.push({
    sessionId: DELEGATE_NONE_SESSION_ID,
    userId: DELEGATE_NONE_USER_ID,
    tokenHash: DELEGATE_NONE_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: now,
    lastActiveAt: now,
    revoked: false,
    revokedReason: null,
  });

  // Delegate with ANALYTICS_VIEW + REPORT_VIEW only (can view, cannot export)
  users.push({
    userId: DELEGATE_VIEW_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_VIEW_USER_ID,
      physicianProviderId: PHYSICIAN_PROVIDER_ID,
      permissions: ['ANALYTICS_VIEW', 'REPORT_VIEW'],
      linkageId: 'link-002',
    },
  });
  sessions.push({
    sessionId: DELEGATE_VIEW_SESSION_ID,
    userId: DELEGATE_VIEW_USER_ID,
    tokenHash: DELEGATE_VIEW_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: now,
    lastActiveAt: now,
    revoked: false,
    revokedReason: null,
  });

  // Delegate with ANALYTICS_VIEW + REPORT_VIEW + REPORT_EXPORT (no DATA_EXPORT)
  users.push({
    userId: DELEGATE_EXPORT_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_EXPORT_USER_ID,
      physicianProviderId: PHYSICIAN_PROVIDER_ID,
      permissions: ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT'],
      linkageId: 'link-003',
    },
  });
  sessions.push({
    sessionId: DELEGATE_EXPORT_SESSION_ID,
    userId: DELEGATE_EXPORT_USER_ID,
    tokenHash: DELEGATE_EXPORT_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: now,
    lastActiveAt: now,
    revoked: false,
    revokedReason: null,
  });

  // Delegate with ALL analytics permissions
  users.push({
    userId: DELEGATE_FULL_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_FULL_USER_ID,
      physicianProviderId: PHYSICIAN_PROVIDER_ID,
      permissions: ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT', 'DATA_EXPORT'],
      linkageId: 'link-004',
    },
  });
  sessions.push({
    sessionId: DELEGATE_FULL_SESSION_ID,
    userId: DELEGATE_FULL_USER_ID,
    tokenHash: DELEGATE_FULL_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: now,
    lastActiveAt: now,
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const VALID_ACCOUNTANT_PAYLOAD = {
  format: 'csv',
  period_start: '2026-01-01',
  period_end: '2026-01-31',
};

const VALID_DATA_PORTABILITY_PAYLOAD = {};

const VALID_CREATE_SUBSCRIPTION_PAYLOAD = {
  report_type: 'WEEKLY_SUMMARY',
  frequency: 'WEEKLY',
  delivery_method: 'IN_APP',
};

const VALID_UPDATE_SUBSCRIPTION_PAYLOAD = {
  frequency: 'MONTHLY',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Analytics & Reporting Authorization & Permission Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedTestIdentities();
  });

  // =========================================================================
  // ANALYTICS_VIEW — Dashboard endpoints (7 GET routes)
  // =========================================================================

  describe('ANALYTICS_VIEW permission enforcement on dashboard endpoints', () => {
    const dashboardEndpoints = [
      { url: '/api/v1/analytics/revenue?period=THIS_MONTH', description: 'Revenue dashboard' },
      { url: '/api/v1/analytics/rejections?period=THIS_MONTH', description: 'Rejections dashboard' },
      { url: '/api/v1/analytics/aging', description: 'Aging dashboard' },
      { url: '/api/v1/analytics/wcb?period=THIS_MONTH', description: 'WCB dashboard' },
      { url: '/api/v1/analytics/ai-coach?period=THIS_MONTH', description: 'AI Coach dashboard' },
      { url: '/api/v1/analytics/multi-site?period=THIS_MONTH', description: 'Multi-site dashboard' },
      { url: '/api/v1/analytics/kpis?period=THIS_MONTH', description: 'KPI cards' },
    ];

    for (const ep of dashboardEndpoints) {
      it(`GET ${ep.description} returns 403 for delegate without ANALYTICS_VIEW`, async () => {
        const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', ep.url);
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }

    for (const ep of dashboardEndpoints) {
      it(`GET ${ep.description} succeeds for delegate with ANALYTICS_VIEW`, async () => {
        const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', ep.url);
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
      });
    }
  });

  // =========================================================================
  // REPORT_VIEW — Report listing and status endpoints
  // =========================================================================

  describe('REPORT_VIEW permission enforcement on report endpoints', () => {
    it('GET /reports returns 403 for delegate without REPORT_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', '/api/v1/reports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /reports/:id returns 403 for delegate without REPORT_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', `/api/v1/reports/${DUMMY_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('GET /report-subscriptions returns 403 for delegate without REPORT_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', '/api/v1/report-subscriptions');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('GET /reports succeeds for delegate with REPORT_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', '/api/v1/reports');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /reports/:id succeeds for delegate with REPORT_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', `/api/v1/reports/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /report-subscriptions succeeds for delegate with REPORT_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', '/api/v1/report-subscriptions');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // REPORT_EXPORT — Report generation, download, subscriptions CRUD
  // =========================================================================

  describe('REPORT_EXPORT permission enforcement', () => {
    it('POST /reports/accountant returns 403 for delegate with REPORT_VIEW only', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/reports/accountant', VALID_ACCOUNTANT_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /reports/:id/download returns 403 for delegate with REPORT_VIEW only', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', `/api/v1/reports/${DUMMY_UUID}/download`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /report-subscriptions returns 403 for delegate with REPORT_VIEW only', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/report-subscriptions', VALID_CREATE_SUBSCRIPTION_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('PUT /report-subscriptions/:id returns 403 for delegate with REPORT_VIEW only', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'PUT', `/api/v1/report-subscriptions/${DUMMY_UUID}`, VALID_UPDATE_SUBSCRIPTION_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('DELETE /report-subscriptions/:id returns 403 for delegate with REPORT_VIEW only', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'DELETE', `/api/v1/report-subscriptions/${DUMMY_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    // Positive cases: delegate with REPORT_EXPORT succeeds
    it('POST /reports/accountant succeeds for delegate with REPORT_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'POST', '/api/v1/reports/accountant', VALID_ACCOUNTANT_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /reports/:id/download succeeds for delegate with REPORT_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'GET', `/api/v1/reports/${DUMMY_UUID}/download`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /report-subscriptions succeeds for delegate with REPORT_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'POST', '/api/v1/report-subscriptions', VALID_CREATE_SUBSCRIPTION_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /report-subscriptions/:id succeeds for delegate with REPORT_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'PUT', `/api/v1/report-subscriptions/${DUMMY_UUID}`, VALID_UPDATE_SUBSCRIPTION_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /report-subscriptions/:id succeeds for delegate with REPORT_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'DELETE', `/api/v1/report-subscriptions/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // DATA_EXPORT — Data portability (higher privilege, separate from REPORT_EXPORT)
  // =========================================================================

  describe('DATA_EXPORT permission enforcement', () => {
    it('POST /reports/data-portability returns 403 for delegate with REPORT_EXPORT but no DATA_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /reports/data-portability returns 403 for delegate with REPORT_VIEW only', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /reports/data-portability returns 403 for delegate with no analytics permissions', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /reports/data-portability succeeds for delegate with DATA_EXPORT', async () => {
      const res = await injectAs(DELEGATE_FULL_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /reports/data-portability succeeds for physician (has all permissions)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Physician: full access to all non-admin endpoints
  // =========================================================================

  describe('Physician has full access to all analytics endpoints', () => {
    it('GET /analytics/revenue succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /analytics/rejections succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /analytics/aging succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/aging');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /analytics/wcb succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/wcb?period=THIS_MONTH');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /analytics/ai-coach succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/ai-coach?period=THIS_MONTH');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /analytics/multi-site succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/multi-site?period=THIS_MONTH');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /analytics/kpis succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /reports/accountant succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/reports/accountant', VALID_ACCOUNTANT_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /reports succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/reports');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /reports/:id succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', `/api/v1/reports/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /reports/:id/download succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', `/api/v1/reports/${DUMMY_UUID}/download`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /report-subscriptions succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/report-subscriptions');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /report-subscriptions succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/report-subscriptions', VALID_CREATE_SUBSCRIPTION_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /report-subscriptions/:id succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', `/api/v1/report-subscriptions/${DUMMY_UUID}`, VALID_UPDATE_SUBSCRIPTION_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /report-subscriptions/:id succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'DELETE', `/api/v1/report-subscriptions/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Permission escalation prevention
  // =========================================================================

  describe('Permission escalation prevention', () => {
    it('delegate cannot access REPORT_EXPORT endpoints by only having ANALYTICS_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/reports/accountant', VALID_ACCOUNTANT_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot access DATA_EXPORT endpoints by only having REPORT_EXPORT', async () => {
      const res = await injectAs(DELEGATE_EXPORT_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot escalate to any analytics endpoint', async () => {
      const endpoints = [
        { method: 'GET' as const, url: '/api/v1/analytics/revenue?period=THIS_MONTH' },
        { method: 'GET' as const, url: '/api/v1/reports' },
        { method: 'GET' as const, url: '/api/v1/report-subscriptions' },
        { method: 'POST' as const, url: '/api/v1/reports/accountant', payload: VALID_ACCOUNTANT_PAYLOAD },
        { method: 'POST' as const, url: '/api/v1/reports/data-portability', payload: VALID_DATA_PORTABILITY_PAYLOAD },
        { method: 'POST' as const, url: '/api/v1/report-subscriptions', payload: VALID_CREATE_SUBSCRIPTION_PAYLOAD },
      ];

      for (const ep of endpoints) {
        const res = await injectAs(DELEGATE_NONE_TOKEN, ep.method, ep.url, ep.payload);
        expect(res.statusCode).toBe(403);
      }
    });
  });

  // =========================================================================
  // 403 response safety — no information leakage
  // =========================================================================

  describe('403 responses do not leak sensitive information', () => {
    it('403 does not contain stack traces', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('403 does not reveal which permission was missing', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/reports/accountant', VALID_ACCOUNTANT_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('REPORT_EXPORT');
      expect(rawBody).not.toContain('ANALYTICS_VIEW');
      expect(rawBody).not.toContain('DATA_EXPORT');
      expect(rawBody).not.toContain('REPORT_VIEW');
    });

    it('403 does not reveal endpoint internals', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Insufficient permissions');
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('details');
    });

    it('403 has consistent error shape across all permission types', async () => {
      // Test ANALYTICS_VIEW 403
      const res1 = await injectAs(DELEGATE_NONE_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');
      expect(res1.statusCode).toBe(403);
      const body1 = JSON.parse(res1.body);
      expect(Object.keys(body1)).toEqual(['error']);
      expect(body1.error).toHaveProperty('code');
      expect(body1.error).toHaveProperty('message');
      expect(body1.error.code).toBe('FORBIDDEN');

      // Test REPORT_EXPORT 403
      const res2 = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/reports/accountant', VALID_ACCOUNTANT_PAYLOAD);
      expect(res2.statusCode).toBe(403);
      const body2 = JSON.parse(res2.body);
      expect(Object.keys(body2)).toEqual(['error']);
      expect(body2.error.code).toBe('FORBIDDEN');

      // Test DATA_EXPORT 403
      const res3 = await injectAs(DELEGATE_EXPORT_TOKEN, 'POST', '/api/v1/reports/data-portability', VALID_DATA_PORTABILITY_PAYLOAD);
      expect(res3.statusCode).toBe(403);
      const body3 = JSON.parse(res3.body);
      expect(Object.keys(body3)).toEqual(['error']);
      expect(body3.error.code).toBe('FORBIDDEN');
    });
  });
});
