// ============================================================================
// Domain 8: Analytics & Reporting — Physician Tenant Isolation (Security)
// MOST CRITICAL: Verifies cross-physician data isolation across dashboards,
// reports, subscriptions, and cache. Analytics data is PHI-derived — cross-
// physician leakage would expose patient data.
// All cross-physician access returns 404, NEVER 403.
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
// Fixed test identities — two physicians + delegates
// ---------------------------------------------------------------------------

// Physician 1
const P1_TOKEN = randomBytes(32).toString('hex');
const P1_TOKEN_HASH = hashToken(P1_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';
const P1_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000001';

// Physician 2
const P2_TOKEN = randomBytes(32).toString('hex');
const P2_TOKEN_HASH = hashToken(P2_TOKEN);
const P2_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';
const P2_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000002';

// Delegate linked to Physician 1 (ANALYTICS_VIEW + REPORT_VIEW + REPORT_EXPORT + DATA_EXPORT)
const DELEGATE_P1_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_P1_TOKEN_HASH = hashToken(DELEGATE_P1_TOKEN);
const DELEGATE_P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000003';
const DELEGATE_P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000003';

// Same delegate linked to Physician 2 context
const DELEGATE_P2_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_P2_TOKEN_HASH = hashToken(DELEGATE_P2_TOKEN);
const DELEGATE_P2_USER_ID = 'aaaa0000-0000-0000-0000-000000000004';
const DELEGATE_P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000004';

// Delegate NOT linked to Physician 2 — only linked to Physician 1
const DELEGATE_P1_ONLY_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_P1_ONLY_TOKEN_HASH = hashToken(DELEGATE_P1_ONLY_TOKEN);
const DELEGATE_P1_ONLY_USER_ID = 'aaaa0000-0000-0000-0000-000000000005';
const DELEGATE_P1_ONLY_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000005';

// ---------------------------------------------------------------------------
// Test data IDs
// ---------------------------------------------------------------------------

const P1_REPORT_ID = 'a0a00000-0000-4000-a000-000000000001';
const P2_REPORT_ID = 'a0a00000-0000-4000-a000-000000000002';

const P1_SUBSCRIPTION_ID = 'b0b00000-0000-4000-a000-000000000001';
const P2_SUBSCRIPTION_ID = 'b0b00000-0000-4000-a000-000000000002';

// ---------------------------------------------------------------------------
// Per-physician data stores (simulate DB scoping)
// ---------------------------------------------------------------------------

/** Revenue data keyed by providerId */
const revenueStore = new Map<string, any>();

/** Rejection data keyed by providerId */
const rejectionStore = new Map<string, any>();

/** Aging data keyed by providerId */
const agingStore = new Map<string, any>();

/** WCB data keyed by providerId */
const wcbStore = new Map<string, any>();

/** AI Coach data keyed by providerId */
const aiCoachStore = new Map<string, any>();

/** Multi-site data keyed by providerId */
const multiSiteStore = new Map<string, any>();

/** KPI data keyed by providerId */
const kpiStore = new Map<string, any>();

/** Reports keyed by `${reportId}:${providerId}` */
const reportsStore = new Map<string, any>();

/** Reports list keyed by providerId */
const reportsListStore = new Map<string, any[]>();

/** Subscriptions keyed by `${subscriptionId}:${providerId}` */
const subscriptionsStore = new Map<string, any>();

/** Subscription list keyed by providerId */
const subscriptionsListStore = new Map<string, any[]>();

/** Analytics cache keyed by providerId */
const cacheStore = new Map<string, any>();

function resetDataStores() {
  revenueStore.clear();
  rejectionStore.clear();
  agingStore.clear();
  wcbStore.clear();
  aiCoachStore.clear();
  multiSiteStore.clear();
  kpiStore.clear();
  reportsStore.clear();
  reportsListStore.clear();
  subscriptionsStore.clear();
  subscriptionsListStore.clear();
  cacheStore.clear();

  // -- Physician 1 dashboard data --
  revenueStore.set(P1_USER_ID, {
    totalRevenue: '15000.00',
    claimCount: 42,
    pendingPipeline: '3200.00',
    monthlyTrend: [{ month: '2026-01', revenue: '15000.00' }],
    byBa: [{ baNumber: 'BA-001', revenue: '15000.00' }],
    topHscCodes: [{ code: '03.04A', count: 20, revenue: '8000.00' }],
    cacheStatus: 'realtime',
    period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
  });

  revenueStore.set(P2_USER_ID, {
    totalRevenue: '28000.00',
    claimCount: 95,
    pendingPipeline: '5100.00',
    monthlyTrend: [{ month: '2026-01', revenue: '28000.00' }],
    byBa: [{ baNumber: 'BA-002', revenue: '28000.00' }],
    topHscCodes: [{ code: '08.19A', count: 50, revenue: '20000.00' }],
    cacheStatus: 'realtime',
    period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
  });

  rejectionStore.set(P1_USER_ID, {
    rejectionRate: 5.2,
    totalRejected: 3,
    byExplanatoryCode: [{ code: 'E01', count: 2 }],
    byHscCode: [{ code: '03.04A', rate: 4.5, count: 1 }],
    resolutionFunnel: { total: 3, resolved: 1, pending: 2 },
  });

  rejectionStore.set(P2_USER_ID, {
    rejectionRate: 12.1,
    totalRejected: 15,
    byExplanatoryCode: [{ code: 'E02', count: 10 }],
    byHscCode: [{ code: '08.19A', rate: 11.0, count: 8 }],
    resolutionFunnel: { total: 15, resolved: 5, pending: 10 },
  });

  agingStore.set(P1_USER_ID, {
    brackets: [
      { label: '0-30 days', count: 5 },
      { label: '31-60 days', count: 2 },
      { label: '61-90 days', count: 0 },
      { label: '90+ days', count: 0 },
    ],
    approachingDeadline: 1,
    expiredClaims: 0,
    avgResolutionDays: 14,
  });

  agingStore.set(P2_USER_ID, {
    brackets: [
      { label: '0-30 days', count: 20 },
      { label: '31-60 days', count: 8 },
      { label: '61-90 days', count: 3 },
      { label: '90+ days', count: 1 },
    ],
    approachingDeadline: 4,
    expiredClaims: 1,
    avgResolutionDays: 28,
  });

  kpiStore.set(P1_USER_ID, {
    totalRevenue: { current: '15000.00', prior: '12000.00', delta: 25.0 },
    claimsSubmitted: { current: 42, prior: 38, delta: 10.5 },
    rejectionRate: { current: 5.2, prior: 6.0, delta: -13.3 },
    avgFeePerClaim: { current: '357.14', prior: '315.79', delta: 13.1 },
  });

  kpiStore.set(P2_USER_ID, {
    totalRevenue: { current: '28000.00', prior: '25000.00', delta: 12.0 },
    claimsSubmitted: { current: 95, prior: 80, delta: 18.75 },
    rejectionRate: { current: 12.1, prior: 10.5, delta: 15.2 },
    avgFeePerClaim: { current: '294.74', prior: '312.50', delta: -5.7 },
  });

  // -- Physician 1 reports --
  const now = new Date();
  const futureExpiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  reportsStore.set(`${P1_REPORT_ID}:${P1_USER_ID}`, {
    reportId: P1_REPORT_ID,
    providerId: P1_USER_ID,
    reportType: 'ACCOUNTANT_SUMMARY',
    format: 'CSV',
    status: 'ready',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '/secure/p1-report.csv',
    fileSizeBytes: 2048,
    downloadLinkExpiresAt: futureExpiry,
    downloaded: false,
    createdAt: now,
  });

  reportsListStore.set(P1_USER_ID, [
    reportsStore.get(`${P1_REPORT_ID}:${P1_USER_ID}`),
  ]);

  // -- Physician 2 reports --
  reportsStore.set(`${P2_REPORT_ID}:${P2_USER_ID}`, {
    reportId: P2_REPORT_ID,
    providerId: P2_USER_ID,
    reportType: 'MONTHLY_PERFORMANCE',
    format: 'PDF',
    status: 'ready',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '/secure/p2-report.pdf',
    fileSizeBytes: 4096,
    downloadLinkExpiresAt: futureExpiry,
    downloaded: false,
    createdAt: now,
  });

  reportsListStore.set(P2_USER_ID, [
    reportsStore.get(`${P2_REPORT_ID}:${P2_USER_ID}`),
  ]);

  // -- Physician 1 subscriptions --
  subscriptionsStore.set(`${P1_SUBSCRIPTION_ID}:${P1_USER_ID}`, {
    subscriptionId: P1_SUBSCRIPTION_ID,
    providerId: P1_USER_ID,
    reportType: 'WEEKLY_SUMMARY',
    frequency: 'WEEKLY',
    deliveryMethod: 'IN_APP',
    isActive: true,
    createdAt: now,
    updatedAt: now,
  });

  subscriptionsListStore.set(P1_USER_ID, [
    subscriptionsStore.get(`${P1_SUBSCRIPTION_ID}:${P1_USER_ID}`),
  ]);

  // -- Physician 2 subscriptions --
  subscriptionsStore.set(`${P2_SUBSCRIPTION_ID}:${P2_USER_ID}`, {
    subscriptionId: P2_SUBSCRIPTION_ID,
    providerId: P2_USER_ID,
    reportType: 'MONTHLY_PERFORMANCE',
    frequency: 'MONTHLY',
    deliveryMethod: 'EMAIL',
    isActive: true,
    createdAt: now,
    updatedAt: now,
  });

  subscriptionsListStore.set(P2_USER_ID, [
    subscriptionsStore.get(`${P2_SUBSCRIPTION_ID}:${P2_USER_ID}`),
  ]);

  // -- Analytics cache keyed by providerId --
  cacheStore.set(P1_USER_ID, {
    revenue_monthly: { value: '15000.00', computedAt: now },
  });

  cacheStore.set(P2_USER_ID, {
    revenue_monthly: { value: '28000.00', computedAt: now },
  });
}

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

function makeSession(id: string, userId: string, tokenHash: string): MockSession {
  const now = new Date();
  return {
    sessionId: id,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: now,
    lastActiveAt: now,
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
// Scoped handler deps — repositories that enforce physician scoping
// ---------------------------------------------------------------------------

function createScopedDashboardDeps(): DashboardRouteDeps {
  return {
    dashboardService: {
      getRevenueDashboard: vi.fn(async (providerId: string) => {
        return revenueStore.get(providerId) ?? {
          totalRevenue: '0.00', claimCount: 0, pendingPipeline: '0.00',
          monthlyTrend: [], byBa: [], topHscCodes: [],
          cacheStatus: 'realtime',
          period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
        };
      }),
      getRejectionDashboard: vi.fn(async (providerId: string) => {
        return rejectionStore.get(providerId) ?? {
          rejectionRate: 0, totalRejected: 0, byExplanatoryCode: [],
          byHscCode: [], resolutionFunnel: { total: 0, resolved: 0, pending: 0 },
        };
      }),
      getAgingDashboard: vi.fn(async (providerId: string) => {
        return agingStore.get(providerId) ?? {
          brackets: [], approachingDeadline: 0, expiredClaims: 0, avgResolutionDays: 0,
        };
      }),
      getWcbDashboard: vi.fn(async (providerId: string) => {
        return wcbStore.get(providerId) ?? null;
      }),
      getAiCoachDashboard: vi.fn(async (providerId: string) => {
        return aiCoachStore.get(providerId) ?? {
          acceptanceRate: 0, totalAccepted: 0, byCategory: [],
          topAcceptedRules: [], suppressedRules: [],
        };
      }),
      getMultiSiteDashboard: vi.fn(async (providerId: string) => {
        return multiSiteStore.get(providerId) ?? null;
      }),
      getKpis: vi.fn(async (providerId: string) => {
        return kpiStore.get(providerId) ?? {
          totalRevenue: { current: '0.00', prior: '0.00', delta: 0 },
          claimsSubmitted: { current: 0, prior: 0, delta: 0 },
          rejectionRate: { current: 0, prior: 0, delta: 0 },
          avgFeePerClaim: { current: '0.00', prior: '0.00', delta: 0 },
        };
      }),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createScopedReportDeps(): ReportRouteDeps {
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
      })),
      getById: vi.fn(async (reportId: string, providerId: string) => {
        const key = `${reportId}:${providerId}`;
        return reportsStore.get(key) ?? null;
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
        const key = `${reportId}:${providerId}`;
        const report = reportsStore.get(key);
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
        return {
          stream: { pipe: vi.fn() },
          contentType: 'text/csv',
          contentDisposition: `attachment; filename="report-${reportId}.csv"`,
          fileSizeBytes: report.fileSizeBytes,
        };
      }),
      isDownloadAvailable: vi.fn(async () => ({ available: true })),
    } as any,
    auditLog: vi.fn(async () => {}),
  };
}

function createScopedSubscriptionDeps(): SubscriptionRouteDeps {
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
      listByProvider: vi.fn(async (providerId: string) => {
        return subscriptionsListStore.get(providerId) ?? [];
      }),
      getById: vi.fn(async (subscriptionId: string, providerId: string) => {
        const key = `${subscriptionId}:${providerId}`;
        return subscriptionsStore.get(key) ?? null;
      }),
      update: vi.fn(async (subscriptionId: string, providerId: string, data: any) => {
        const key = `${subscriptionId}:${providerId}`;
        const sub = subscriptionsStore.get(key);
        if (!sub) return null;
        return { ...sub, ...data, updatedAt: new Date() };
      }),
      delete: vi.fn(async (subscriptionId: string, providerId: string) => {
        const key = `${subscriptionId}:${providerId}`;
        return subscriptionsStore.has(key);
      }),
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

  await testApp.register(dashboardRoutes, { deps: createScopedDashboardDeps() });
  await testApp.register(reportRoutes, { deps: createScopedReportDeps() });
  await testApp.register(subscriptionRoutes, { deps: createScopedSubscriptionDeps() });

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
// Seed auth identities
// ---------------------------------------------------------------------------

function seedIdentities() {
  sessions = [];
  users = [];

  // Physician 1
  users.push({
    userId: P1_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push(makeSession(P1_SESSION_ID, P1_USER_ID, P1_TOKEN_HASH));

  // Physician 2
  users.push({
    userId: P2_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push(makeSession(P2_SESSION_ID, P2_USER_ID, P2_TOKEN_HASH));

  // Delegate acting under Physician 1 context (full analytics permissions)
  users.push({
    userId: DELEGATE_P1_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_P1_USER_ID,
      physicianProviderId: P1_PROVIDER_ID,
      permissions: ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT', 'DATA_EXPORT'],
      linkageId: 'link-001',
    },
  });
  sessions.push(makeSession(DELEGATE_P1_SESSION_ID, DELEGATE_P1_USER_ID, DELEGATE_P1_TOKEN_HASH));

  // Delegate acting under Physician 2 context (full analytics permissions)
  users.push({
    userId: DELEGATE_P2_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_P2_USER_ID,
      physicianProviderId: P2_PROVIDER_ID,
      permissions: ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT', 'DATA_EXPORT'],
      linkageId: 'link-002',
    },
  });
  sessions.push(makeSession(DELEGATE_P2_SESSION_ID, DELEGATE_P2_USER_ID, DELEGATE_P2_TOKEN_HASH));

  // Delegate linked ONLY to Physician 1 — NOT linked to Physician 2
  users.push({
    userId: DELEGATE_P1_ONLY_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_P1_ONLY_USER_ID,
      physicianProviderId: P1_PROVIDER_ID,
      permissions: ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT'],
      linkageId: 'link-003',
    },
  });
  sessions.push(makeSession(DELEGATE_P1_ONLY_SESSION_ID, DELEGATE_P1_ONLY_USER_ID, DELEGATE_P1_ONLY_TOKEN_HASH));
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Analytics & Reporting Physician Tenant Isolation (Security)', () => {
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
  // Dashboard Isolation
  // =========================================================================

  describe('Dashboard isolation', () => {
    // -- Revenue dashboard --

    it('physician1 views revenue dashboard — sees ONLY their claims revenue', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue).toBe('15000.00');
      expect(body.data.claimCount).toBe(42);
      // Must NOT contain P2's data
      expect(body.data.totalRevenue).not.toBe('28000.00');
    });

    it('physician2 views revenue dashboard — sees ONLY their claims revenue', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue).toBe('28000.00');
      expect(body.data.claimCount).toBe(95);
      expect(body.data.totalRevenue).not.toBe('15000.00');
    });

    it('bidirectional revenue isolation — P1 and P2 get distinct data', async () => {
      const [res1, res2] = await Promise.all([
        injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH'),
        injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH'),
      ]);

      const data1 = JSON.parse(res1.body).data;
      const data2 = JSON.parse(res2.body).data;

      expect(data1.totalRevenue).not.toBe(data2.totalRevenue);
      expect(data1.claimCount).not.toBe(data2.claimCount);
      expect(data1.byBa[0]?.baNumber).not.toBe(data2.byBa[0]?.baNumber);
    });

    // -- Rejection dashboard --

    it('physician1 views rejection dashboard — sees ONLY their rejection data', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.rejectionRate).toBe(5.2);
      expect(body.data.totalRejected).toBe(3);
      expect(body.data.rejectionRate).not.toBe(12.1);
    });

    it('physician2 views rejection dashboard — sees ONLY their rejection data', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.rejectionRate).toBe(12.1);
      expect(body.data.totalRejected).toBe(15);
      expect(body.data.rejectionRate).not.toBe(5.2);
    });

    // -- Aging dashboard --

    it('physician1 views aging dashboard — sees ONLY their unresolved claims', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.approachingDeadline).toBe(1);
      expect(body.data.avgResolutionDays).toBe(14);
      expect(body.data.approachingDeadline).not.toBe(4);
    });

    it('physician2 views aging dashboard — sees ONLY their unresolved claims', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.approachingDeadline).toBe(4);
      expect(body.data.avgResolutionDays).toBe(28);
      expect(body.data.approachingDeadline).not.toBe(1);
    });

    // -- KPI dashboard --

    it('physician1 KPI values match physician1 data exclusively', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue.current).toBe('15000.00');
      expect(body.data.claimsSubmitted.current).toBe(42);
      expect(body.data.rejectionRate.current).toBe(5.2);
      // Must not contain P2's values
      expect(body.data.totalRevenue.current).not.toBe('28000.00');
      expect(body.data.claimsSubmitted.current).not.toBe(95);
    });

    it('physician2 KPI values match physician2 data exclusively', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue.current).toBe('28000.00');
      expect(body.data.claimsSubmitted.current).toBe(95);
      expect(body.data.rejectionRate.current).toBe(12.1);
      expect(body.data.totalRevenue.current).not.toBe('15000.00');
    });

    // -- WCB dashboard returns null (404) when no data —
    // Cross-physician: P1 cannot see P2's WCB config

    it('WCB dashboard returns null when physician has no WCB config — no cross-tenant leak', async () => {
      // Neither physician has WCB data seeded
      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/wcb?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/wcb?period=THIS_MONTH');

      expect(res1.statusCode).toBe(404);
      expect(res2.statusCode).toBe(404);
    });

    it('WCB dashboard scoped — P1 sees only their WCB data when available', async () => {
      wcbStore.set(P1_USER_ID, {
        byFormType: [{ type: 'C01', count: 5 }],
        timingTierDistribution: [{ tier: 'T1', count: 3 }],
        rejectionRate: 2.0,
      });

      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/wcb?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/wcb?period=THIS_MONTH');

      expect(res1.statusCode).toBe(200);
      expect(JSON.parse(res1.body).data.byFormType[0].type).toBe('C01');

      // P2 still gets 404 — cannot see P1's WCB data
      expect(res2.statusCode).toBe(404);
    });

    // -- AI Coach dashboard --

    it('AI coach dashboard scoped — P1 and P2 get distinct data', async () => {
      aiCoachStore.set(P1_USER_ID, { acceptanceRate: 0.75, totalAccepted: 20 });
      aiCoachStore.set(P2_USER_ID, { acceptanceRate: 0.45, totalAccepted: 8 });

      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/ai-coach?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/ai-coach?period=THIS_MONTH');

      const data1 = JSON.parse(res1.body).data;
      const data2 = JSON.parse(res2.body).data;

      expect(data1.acceptanceRate).toBe(0.75);
      expect(data2.acceptanceRate).toBe(0.45);
      expect(data1.acceptanceRate).not.toBe(data2.acceptanceRate);
    });

    // -- Multi-site dashboard --

    it('multi-site dashboard scoped — P1 and P2 see only their own locations', async () => {
      multiSiteStore.set(P1_USER_ID, {
        locations: [{ locationId: 'loc-p1', name: 'P1 Clinic', revenue: '10000.00' }],
      });
      multiSiteStore.set(P2_USER_ID, {
        locations: [{ locationId: 'loc-p2', name: 'P2 Clinic', revenue: '22000.00' }],
      });

      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/multi-site?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/multi-site?period=THIS_MONTH');

      const data1 = JSON.parse(res1.body).data;
      const data2 = JSON.parse(res2.body).data;

      expect(data1.locations[0].name).toBe('P1 Clinic');
      expect(data2.locations[0].name).toBe('P2 Clinic');
      expect(data1.locations[0].name).not.toBe(data2.locations[0].name);
    });

    // -- All 7 dashboards: no cross-physician data in any response body --

    it('no dashboard response body contains P2 identifiers when P1 requests', async () => {
      const endpoints = [
        '/api/v1/analytics/revenue?period=THIS_MONTH',
        '/api/v1/analytics/rejections?period=THIS_MONTH',
        '/api/v1/analytics/aging',
        '/api/v1/analytics/kpis?period=THIS_MONTH',
      ];

      for (const url of endpoints) {
        const res = await injectAs(P1_TOKEN, 'GET', url);
        const rawBody = res.body;

        expect(rawBody).not.toContain(P2_USER_ID);
        expect(rawBody).not.toContain(P2_PROVIDER_ID);
        expect(rawBody).not.toContain('28000.00');
        expect(rawBody).not.toContain('BA-002');
      }
    });
  });

  // =========================================================================
  // Report Isolation
  // =========================================================================

  describe('Report isolation', () => {
    it('physician1 generates accountant report — returns their own report_id', async () => {
      const res = await injectAs(P1_TOKEN, 'POST', '/api/v1/reports/accountant', {
        period_start: '2026-01-01',
        period_end: '2026-01-31',
        format: 'csv',
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBeDefined();
      expect(body.data.status).toBe('pending');
    });

    it('physician1 can retrieve their own report by ID', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBe(P1_REPORT_ID);
      expect(body.data.report_type).toBe('ACCOUNTANT_SUMMARY');
    });

    it('physician1 attempts GET /reports/:id with physician2 report_id — returns 404 (not 403)', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.data).toBeUndefined();
    });

    it('physician1 attempts GET /reports/:id/download with physician2 report_id — returns 404 (not 403)', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}/download`);

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.data).toBeUndefined();
    });

    it('physician2 cannot access physician1 report status', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician2 cannot download physician1 report', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}/download`);

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 report list contains ONLY physician1 reports', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      for (const report of body.data) {
        // Verify no P2 report IDs appear in P1's list
        expect(report.report_id).not.toBe(P2_REPORT_ID);
      }
    });

    it('physician2 report list contains ONLY physician2 reports', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      for (const report of body.data) {
        expect(report.report_id).not.toBe(P1_REPORT_ID);
      }
    });

    it('data portability export creates report scoped to requesting physician', async () => {
      const res = await injectAs(P1_TOKEN, 'POST', '/api/v1/reports/data-portability', {});

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBeDefined();
      // P2 cannot access this report
      const crossRes = await injectAs(
        P2_TOKEN,
        'GET',
        `/api/v1/reports/${body.data.report_id}`,
      );
      // The newly created report is keyed to P1, so P2 gets 404
      expect(crossRes.statusCode).toBe(404);
    });

    it('404 response for cross-physician report does not reveal report existence', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_REPORT_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('MONTHLY_PERFORMANCE');
      expect(rawBody).not.toContain('p2-report');
    });

    it('404 response for cross-physician download does not reveal file details', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}/download`);

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_REPORT_ID);
      expect(rawBody).not.toContain('p2-report');
      expect(rawBody).not.toContain('/secure/');
    });
  });

  // =========================================================================
  // Subscription Isolation
  // =========================================================================

  describe('Subscription isolation', () => {
    it('physician1 lists subscriptions — sees ONLY their own', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      for (const sub of body.data) {
        expect(sub.subscription_id).not.toBe(P2_SUBSCRIPTION_ID);
        expect(sub.provider_id).toBe(P1_USER_ID);
      }
    });

    it('physician2 lists subscriptions — sees ONLY their own', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      for (const sub of body.data) {
        expect(sub.subscription_id).not.toBe(P1_SUBSCRIPTION_ID);
        expect(sub.provider_id).toBe(P2_USER_ID);
      }
    });

    it('physician1 attempts PUT /report-subscriptions/:id with physician2 subscription_id — returns 404 (not 403)', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
        { frequency: 'DAILY' },
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.data).toBeUndefined();
    });

    it('physician1 attempts DELETE /report-subscriptions/:id with physician2 subscription_id — returns 404 (not 403)', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'DELETE',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician2 cannot update physician1 subscription', async () => {
      const res = await injectAs(
        P2_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${P1_SUBSCRIPTION_ID}`,
        { frequency: 'DAILY' },
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician2 cannot delete physician1 subscription', async () => {
      const res = await injectAs(
        P2_TOKEN,
        'DELETE',
        `/api/v1/report-subscriptions/${P1_SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('404 for cross-physician subscription does not leak subscription details', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
        { frequency: 'DAILY' },
      );

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_SUBSCRIPTION_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('MONTHLY_PERFORMANCE');
    });
  });

  // =========================================================================
  // Cache Isolation
  // =========================================================================

  describe('Cache isolation', () => {
    it('analytics cache entries for physician1 are never returned for physician2 dashboard queries', async () => {
      // Both physicians request revenue dashboard
      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      const data1 = JSON.parse(res1.body).data;
      const data2 = JSON.parse(res2.body).data;

      // Each physician receives their own cached data
      expect(data1.totalRevenue).toBe('15000.00');
      expect(data2.totalRevenue).toBe('28000.00');

      // Verify P1's cached value never appears in P2's response
      expect(res2.body).not.toContain('15000.00');
      // Verify P2's cached value never appears in P1's response
      expect(res1.body).not.toContain('28000.00');
    });

    it('KPI cache entries are physician-scoped — P1 deltas differ from P2', async () => {
      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');

      const kpi1 = JSON.parse(res1.body).data;
      const kpi2 = JSON.parse(res2.body).data;

      // Deltas are physician-specific computed values
      expect(kpi1.totalRevenue.delta).not.toBe(kpi2.totalRevenue.delta);
      expect(kpi1.claimsSubmitted.current).not.toBe(kpi2.claimsSubmitted.current);
    });

    it('rejection cache entries are physician-scoped', async () => {
      const res1 = await injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH');
      const res2 = await injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH');

      const data1 = JSON.parse(res1.body).data;
      const data2 = JSON.parse(res2.body).data;

      expect(data1.rejectionRate).not.toBe(data2.rejectionRate);
      expect(data1.totalRejected).not.toBe(data2.totalRejected);
    });
  });

  // =========================================================================
  // Delegate Cross-Physician Isolation
  // =========================================================================

  describe('Delegate cross-physician isolation', () => {
    it('delegate in physician1 context sees physician1 revenue dashboard', async () => {
      // Delegate context resolves to P1_PROVIDER_ID
      // Dashboard service is called with P1_PROVIDER_ID
      // Need to seed data keyed by P1_PROVIDER_ID for delegate resolution
      revenueStore.set(P1_PROVIDER_ID, {
        totalRevenue: '15000.00',
        claimCount: 42,
        pendingPipeline: '3200.00',
        monthlyTrend: [],
        byBa: [],
        topHscCodes: [],
        cacheStatus: 'realtime',
        period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
      });

      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue).toBe('15000.00');
    });

    it('delegate switches to physician2 context — sees physician2 data, NOT physician1', async () => {
      revenueStore.set(P2_PROVIDER_ID, {
        totalRevenue: '28000.00',
        claimCount: 95,
        pendingPipeline: '5100.00',
        monthlyTrend: [],
        byBa: [],
        topHscCodes: [],
        cacheStatus: 'realtime',
        period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
      });

      const res = await injectAs(DELEGATE_P2_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue).toBe('28000.00');
      expect(body.data.totalRevenue).not.toBe('15000.00');
    });

    it('delegate in P1 context sees only P1 subscriptions', async () => {
      // Need to seed using P1_PROVIDER_ID key for delegate resolution
      subscriptionsListStore.set(P1_PROVIDER_ID, [
        subscriptionsStore.get(`${P1_SUBSCRIPTION_ID}:${P1_USER_ID}`),
      ]);

      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const sub of body.data) {
        expect(sub.subscription_id).not.toBe(P2_SUBSCRIPTION_ID);
      }
    });

    it('delegate in P2 context sees only P2 subscriptions', async () => {
      subscriptionsListStore.set(P2_PROVIDER_ID, [
        subscriptionsStore.get(`${P2_SUBSCRIPTION_ID}:${P2_USER_ID}`),
      ]);

      const res = await injectAs(DELEGATE_P2_TOKEN, 'GET', '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const sub of body.data) {
        expect(sub.subscription_id).not.toBe(P1_SUBSCRIPTION_ID);
      }
    });

    it('delegate in P1 context sees P1 reports list', async () => {
      reportsListStore.set(P1_PROVIDER_ID, [
        reportsStore.get(`${P1_REPORT_ID}:${P1_USER_ID}`),
      ]);

      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', '/api/v1/reports');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const report of body.data) {
        expect(report.report_id).not.toBe(P2_REPORT_ID);
      }
    });

    it('delegate in P1 context can access P1 report by ID', async () => {
      reportsStore.set(`${P1_REPORT_ID}:${P1_PROVIDER_ID}`, {
        ...reportsStore.get(`${P1_REPORT_ID}:${P1_USER_ID}`),
      });

      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.report_id).toBe(P1_REPORT_ID);
    });

    it('delegate in P1 context CANNOT access P2 report by ID — returns 404', async () => {
      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}`);

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate NOT linked to P2 cannot access P2 analytics', async () => {
      // DELEGATE_P1_ONLY is only linked to P1, not P2
      // Their delegate context resolves to P1_PROVIDER_ID
      revenueStore.set(P1_PROVIDER_ID, {
        totalRevenue: '15000.00',
        claimCount: 42,
        pendingPipeline: '3200.00',
        monthlyTrend: [],
        byBa: [],
        topHscCodes: [],
        cacheStatus: 'realtime',
        period: { start: '2026-01-01', end: '2026-01-31', label: 'This Month' },
      });

      const res = await injectAs(
        DELEGATE_P1_ONLY_TOKEN,
        'GET',
        '/api/v1/analytics/revenue?period=THIS_MONTH',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Sees P1's data, not P2's
      expect(body.data.totalRevenue).toBe('15000.00');
      expect(body.data.totalRevenue).not.toBe('28000.00');
    });

    it('delegate in P1 context cannot update P2 subscription — returns 404', async () => {
      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
        { frequency: 'DAILY' },
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate in P1 context cannot delete P2 subscription — returns 404', async () => {
      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'DELETE',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate in P1 context cannot download P2 report — returns 404', async () => {
      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'GET',
        `/api/v1/reports/${P2_REPORT_ID}/download`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate KPI data is scoped to their physician context', async () => {
      kpiStore.set(P1_PROVIDER_ID, {
        totalRevenue: { current: '15000.00', prior: '12000.00', delta: 25.0 },
        claimsSubmitted: { current: 42, prior: 38, delta: 10.5 },
        rejectionRate: { current: 5.2, prior: 6.0, delta: -13.3 },
        avgFeePerClaim: { current: '357.14', prior: '315.79', delta: 13.1 },
      });

      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.totalRevenue.current).toBe('15000.00');
      expect(body.data.totalRevenue.current).not.toBe('28000.00');
    });
  });

  // =========================================================================
  // Cross-physician access always returns 404, NEVER 403
  // =========================================================================

  describe('Cross-physician access returns 404 (never 403)', () => {
    it('GET /reports/:id cross-physician returns 404 not 403', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /reports/:id/download cross-physician returns 404 not 403', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${P2_REPORT_ID}/download`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /report-subscriptions/:id cross-physician returns 404 not 403', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
        { frequency: 'DAILY' },
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /report-subscriptions/:id cross-physician returns 404 not 403', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'DELETE',
        `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`,
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('cross-physician 404 error bodies are generic — no resource details leaked', async () => {
      const crossEndpoints = [
        { method: 'GET' as const, url: `/api/v1/reports/${P2_REPORT_ID}` },
        { method: 'GET' as const, url: `/api/v1/reports/${P2_REPORT_ID}/download` },
        { method: 'PUT' as const, url: `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}`, payload: { frequency: 'DAILY' } },
        { method: 'DELETE' as const, url: `/api/v1/report-subscriptions/${P2_SUBSCRIPTION_ID}` },
      ];

      for (const ep of crossEndpoints) {
        const res = await injectAs(P1_TOKEN, ep.method, ep.url, ep.payload);
        expect(res.statusCode).toBe(404);
        const rawBody = res.body;

        // Must not contain any P2 identifiers
        expect(rawBody).not.toContain(P2_REPORT_ID);
        expect(rawBody).not.toContain(P2_SUBSCRIPTION_ID);
        expect(rawBody).not.toContain(P2_USER_ID);
        expect(rawBody).not.toContain(P2_PROVIDER_ID);
      }
    });
  });

  // =========================================================================
  // Non-existent resources return 404
  // =========================================================================

  describe('Non-existent resources return 404', () => {
    const NONEXISTENT_UUID = '00000000-ffff-ffff-ffff-ffffffffffff';

    it('GET /reports/:id with non-existent ID returns 404', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET /reports/:id/download with non-existent ID returns 404', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', `/api/v1/reports/${NONEXISTENT_UUID}/download`);
      expect(res.statusCode).toBe(404);
    });

    it('PUT /report-subscriptions/:id with non-existent ID returns 404', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${NONEXISTENT_UUID}`,
        { frequency: 'DAILY' },
      );
      expect(res.statusCode).toBe(404);
    });

    it('DELETE /report-subscriptions/:id with non-existent ID returns 404', async () => {
      const res = await injectAs(
        P1_TOKEN,
        'DELETE',
        `/api/v1/report-subscriptions/${NONEXISTENT_UUID}`,
      );
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Bidirectional Isolation Verification
  // =========================================================================

  describe('Bidirectional isolation verification', () => {
    it('P2 cannot access P1 report (reverse direction)', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot download P1 report (reverse direction)', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', `/api/v1/reports/${P1_REPORT_ID}/download`);
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot update P1 subscription (reverse direction)', async () => {
      const res = await injectAs(
        P2_TOKEN,
        'PUT',
        `/api/v1/report-subscriptions/${P1_SUBSCRIPTION_ID}`,
        { is_active: false },
      );
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot delete P1 subscription (reverse direction)', async () => {
      const res = await injectAs(
        P2_TOKEN,
        'DELETE',
        `/api/v1/report-subscriptions/${P1_SUBSCRIPTION_ID}`,
      );
      expect(res.statusCode).toBe(404);
    });

    it('bidirectional dashboard isolation — both directions verified simultaneously', async () => {
      const [p1Rev, p2Rev, p1Rej, p2Rej, p1Age, p2Age] = await Promise.all([
        injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH'),
        injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/revenue?period=THIS_MONTH'),
        injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH'),
        injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/rejections?period=THIS_MONTH'),
        injectAs(P1_TOKEN, 'GET', '/api/v1/analytics/aging'),
        injectAs(P2_TOKEN, 'GET', '/api/v1/analytics/aging'),
      ]);

      // Revenue isolation
      expect(JSON.parse(p1Rev.body).data.totalRevenue).toBe('15000.00');
      expect(JSON.parse(p2Rev.body).data.totalRevenue).toBe('28000.00');

      // Rejection isolation
      expect(JSON.parse(p1Rej.body).data.rejectionRate).toBe(5.2);
      expect(JSON.parse(p2Rej.body).data.rejectionRate).toBe(12.1);

      // Aging isolation
      expect(JSON.parse(p1Age.body).data.avgResolutionDays).toBe(14);
      expect(JSON.parse(p2Age.body).data.avgResolutionDays).toBe(28);
    });
  });

  // =========================================================================
  // Response body never leaks cross-tenant identifiers
  // =========================================================================

  describe('Response body never leaks cross-tenant identifiers', () => {
    it('P1 report list response contains no P2 identifiers', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/reports');
      const rawBody = res.body;

      expect(rawBody).not.toContain(P2_REPORT_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('P1 subscription list response contains no P2 identifiers', async () => {
      const res = await injectAs(P1_TOKEN, 'GET', '/api/v1/report-subscriptions');
      const rawBody = res.body;

      expect(rawBody).not.toContain(P2_SUBSCRIPTION_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('P2 report list response contains no P1 identifiers', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/reports');
      const rawBody = res.body;

      expect(rawBody).not.toContain(P1_REPORT_ID);
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
    });

    it('P2 subscription list response contains no P1 identifiers', async () => {
      const res = await injectAs(P2_TOKEN, 'GET', '/api/v1/report-subscriptions');
      const rawBody = res.body;

      expect(rawBody).not.toContain(P1_SUBSCRIPTION_ID);
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
    });
  });
});
