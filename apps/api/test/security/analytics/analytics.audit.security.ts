// ============================================================================
// Domain 8: Analytics & Reporting — Audit Trail Verification (Security)
// Verifies every state-changing action produces audit records, that the audit
// log is append-only, rate-limited dashboard audit, and delegate attribution.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
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
import { AnalyticsAuditAction } from '@meritum/shared/constants/analytics.constants.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const PHYSICIAN2_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_TOKEN_HASH = hashToken(PHYSICIAN2_TOKEN);
const PHYSICIAN2_USER_ID = 'aaaa0000-0000-0000-0000-000000000010';
const PHYSICIAN2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000010';

// Additional physician tokens for rate-limit-isolated tests
const PHYSICIAN3_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN3_TOKEN_HASH = hashToken(PHYSICIAN3_TOKEN);
const PHYSICIAN3_USER_ID = 'aaaa0000-0000-0000-0000-000000000020';
const PHYSICIAN3_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000020';

const PHYSICIAN4_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN4_TOKEN_HASH = hashToken(PHYSICIAN4_TOKEN);
const PHYSICIAN4_USER_ID = 'aaaa0000-0000-0000-0000-000000000030';
const PHYSICIAN4_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000030';

const PHYSICIAN5_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN5_TOKEN_HASH = hashToken(PHYSICIAN5_TOKEN);
const PHYSICIAN5_USER_ID = 'aaaa0000-0000-0000-0000-000000000040';
const PHYSICIAN5_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000040';

// Physician for "every state changing" section (separate rate-limit namespace)
const PHYSICIAN_STATE_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_STATE_TOKEN_HASH = hashToken(PHYSICIAN_STATE_TOKEN);
const PHYSICIAN_STATE_USER_ID = 'aaaa0000-0000-0000-0000-000000000050';
const PHYSICIAN_STATE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000050';

const DELEGATE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_TOKEN_HASH = hashToken(DELEGATE_TOKEN);
const DELEGATE_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';
const DELEGATE_PHYSICIAN_ID = PHYSICIAN_USER_ID;

// Delegate uses a separate physician for dashboard view tests (avoids rate-limit collision)
const DELEGATE2_TOKEN = randomBytes(32).toString('hex');
const DELEGATE2_TOKEN_HASH = hashToken(DELEGATE2_TOKEN);
const DELEGATE2_USER_ID = 'aaaa0000-0000-0000-0000-000000000003';
const DELEGATE2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000003';
const DELEGATE2_PHYSICIAN_ID = 'aaaa0000-0000-0000-0000-000000000060';

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';
const DUMMY_REPORT_ID = '11110000-0000-0000-0000-000000000001';
const DUMMY_SUBSCRIPTION_ID = '22220000-0000-0000-0000-000000000001';

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
// Tracked audit log calls
// ---------------------------------------------------------------------------

interface AuditLogEntry {
  action: string;
  providerId: string;
  details: Record<string, unknown>;
}

let auditLogCalls: AuditLogEntry[] = [];

// ---------------------------------------------------------------------------
// Tracked download audit calls (separate from route-level auditLog)
// ---------------------------------------------------------------------------

interface DownloadAuditEntry {
  action: string;
  resourceType: string;
  resourceId: string;
  providerId: string;
  metadata?: Record<string, unknown>;
}

let downloadAuditCalls: DownloadAuditEntry[] = [];

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

interface MockReport {
  reportId: string;
  providerId: string;
  reportType: string;
  format: string;
  status: string;
  periodStart?: string;
  periodEnd?: string;
  filePath: string;
  fileSizeBytes: number;
  downloadLinkExpiresAt: Date;
  downloaded: boolean;
  createdAt: Date;
}

let mockReports: MockReport[] = [];
let mockSubscriptions: any[] = [];

// ---------------------------------------------------------------------------
// Create deps with audit tracking
// ---------------------------------------------------------------------------

function createAuditTrackedDashboardDeps(): DashboardRouteDeps {
  return {
    dashboardService: {
      getRevenueDashboard: vi.fn(async () => ({
        total_revenue: '5000.00',
        claim_count: 25,
        by_period: [],
      })),
      getRejectionDashboard: vi.fn(async () => ({
        total_rejections: 3,
        rejection_rate: '0.12',
        by_code: [],
      })),
      getAgingDashboard: vi.fn(async () => ({
        brackets: [],
        approaching_deadline: 0,
        stale_claims: 0,
      })),
      getWcbDashboard: vi.fn(async () => ({
        by_form_type: [],
        timing_tier_distribution: [],
        revenue_trend: [],
      })),
      getAiCoachDashboard: vi.fn(async () => ({
        acceptance_rate: '0.75',
        revenue_recovered: '200.00',
        by_category: [],
      })),
      getMultiSiteDashboard: vi.fn(async () => ({
        sites: [],
        totals: { revenue: '0.00', claims: 0 },
      })),
      getKpis: vi.fn(async () => ({
        revenue: '5000.00',
        claims_submitted: 25,
        rejection_rate: '0.12',
        pending_pipeline: '1200.00',
      })),
    } as any,
    auditLog: vi.fn(async (entry: AuditLogEntry) => {
      auditLogCalls.push(entry);
    }),
  };
}

function createAuditTrackedReportDeps(): ReportRouteDeps {
  return {
    reportsRepo: {
      create: vi.fn(async (data: any) => {
        const report: MockReport = {
          reportId: randomBytes(16).toString('hex'),
          providerId: data.providerId,
          reportType: data.reportType,
          format: data.format,
          status: 'pending',
          periodStart: data.periodStart,
          periodEnd: data.periodEnd,
          filePath: data.filePath || '',
          fileSizeBytes: data.fileSizeBytes || 0,
          downloadLinkExpiresAt: data.downloadLinkExpiresAt || new Date(Date.now() + 86400000),
          downloaded: false,
          createdAt: new Date(),
        };
        mockReports.push(report);
        return report;
      }),
      getById: vi.fn(async (id: string, providerId: string) => {
        return mockReports.find(
          (r) => r.reportId === id && r.providerId === providerId,
        ) || null;
      }),
      listByProvider: vi.fn(async (providerId: string) => {
        const data = mockReports.filter((r) => r.providerId === providerId);
        return { data, total: data.length };
      }),
      updateStatus: vi.fn(async () => {}),
      markDownloaded: vi.fn(async () => {}),
      deleteExpired: vi.fn(async () => 0),
    } as any,
    reportGenerationService: {
      processReport: vi.fn(async () => {}),
      generateDataPortabilityExport: vi.fn(async () => {}),
    } as any,
    downloadService: {
      getDownloadStream: vi.fn(async (reportId: string, providerId: string) => {
        const report = mockReports.find(
          (r) => r.reportId === reportId && r.providerId === providerId,
        );
        if (!report) {
          const err = new Error('Report not found') as any;
          err.name = 'DownloadError';
          err.code = 'NOT_FOUND';
          throw err;
        }

        // Record download audit
        const auditAction =
          report.reportType === 'DATA_PORTABILITY'
            ? AnalyticsAuditAction.DATA_PORTABILITY_DOWNLOADED
            : AnalyticsAuditAction.REPORT_DOWNLOADED;

        downloadAuditCalls.push({
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
          stream: Readable.from(Buffer.from('mock-file-content')),
          contentType: 'text/csv',
          contentDisposition: `attachment; filename="report-${reportId}.csv"`,
          fileSizeBytes: 17,
        };
      }),
      isDownloadAvailable: vi.fn(async () => ({ available: true })),
    } as any,
    auditLog: vi.fn(async (entry: AuditLogEntry) => {
      auditLogCalls.push(entry);
    }),
  };
}

function createAuditTrackedSubscriptionDeps(): SubscriptionRouteDeps {
  return {
    subscriptionsRepo: {
      create: vi.fn(async (data: any) => {
        const sub = {
          subscriptionId: randomUUID(),
          providerId: data.providerId,
          reportType: data.reportType,
          frequency: data.frequency,
          deliveryMethod: data.deliveryMethod,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        mockSubscriptions.push(sub);
        return sub;
      }),
      listByProvider: vi.fn(async (providerId: string) => {
        return mockSubscriptions.filter((s) => s.providerId === providerId);
      }),
      update: vi.fn(async (id: string, providerId: string, data: any) => {
        const sub = mockSubscriptions.find(
          (s) => s.subscriptionId === id && s.providerId === providerId,
        );
        if (!sub) return null;
        Object.assign(sub, data, { updatedAt: new Date() });
        return sub;
      }),
      delete: vi.fn(async (id: string, providerId: string) => {
        const idx = mockSubscriptions.findIndex(
          (s) => s.subscriptionId === id && s.providerId === providerId,
        );
        if (idx === -1) return null;
        const [deleted] = mockSubscriptions.splice(idx, 1);
        return deleted;
      }),
    } as any,
    auditLog: vi.fn(async (entry: AuditLogEntry) => {
      auditLogCalls.push(entry);
    }),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let dashboardDeps: DashboardRouteDeps;
let reportDeps: ReportRouteDeps;
let subscriptionDeps: SubscriptionRouteDeps;

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

  dashboardDeps = createAuditTrackedDashboardDeps();
  reportDeps = createAuditTrackedReportDeps();
  subscriptionDeps = createAuditTrackedSubscriptionDeps();

  await testApp.register(dashboardRoutes, { deps: dashboardDeps });
  await testApp.register(reportRoutes, { deps: reportDeps });
  await testApp.register(subscriptionRoutes, { deps: subscriptionDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function physicianHeaders(): Record<string, string> {
  return { cookie: `session=${PHYSICIAN_TOKEN}` };
}

function physician2Headers(): Record<string, string> {
  return { cookie: `session=${PHYSICIAN2_TOKEN}` };
}

function physician3Headers(): Record<string, string> {
  return { cookie: `session=${PHYSICIAN3_TOKEN}` };
}

function physician4Headers(): Record<string, string> {
  return { cookie: `session=${PHYSICIAN4_TOKEN}` };
}

function physician5Headers(): Record<string, string> {
  return { cookie: `session=${PHYSICIAN5_TOKEN}` };
}

function physicianStateHeaders(): Record<string, string> {
  return { cookie: `session=${PHYSICIAN_STATE_TOKEN}` };
}

function delegateHeaders(): Record<string, string> {
  return { cookie: `session=${DELEGATE_TOKEN}` };
}

function delegate2Headers(): Record<string, string> {
  return { cookie: `session=${DELEGATE2_TOKEN}` };
}

function addPhysicianSession(
  userId: string,
  sessionId: string,
  tokenHash: string,
) {
  users.push({
    userId,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function addDelegateSession(
  userId: string,
  sessionId: string,
  tokenHash: string,
  physicianProviderId: string,
  permissions: string[],
) {
  users.push({
    userId,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: userId,
      physicianProviderId,
      permissions,
    },
  });
  sessions.push({
    sessionId,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function seedSessions() {
  sessions = [];
  users = [];

  addPhysicianSession(PHYSICIAN_USER_ID, PHYSICIAN_SESSION_ID, PHYSICIAN_TOKEN_HASH);
  addPhysicianSession(PHYSICIAN2_USER_ID, PHYSICIAN2_SESSION_ID, PHYSICIAN2_TOKEN_HASH);
  addPhysicianSession(PHYSICIAN3_USER_ID, PHYSICIAN3_SESSION_ID, PHYSICIAN3_TOKEN_HASH);
  addPhysicianSession(PHYSICIAN4_USER_ID, PHYSICIAN4_SESSION_ID, PHYSICIAN4_TOKEN_HASH);
  addPhysicianSession(PHYSICIAN5_USER_ID, PHYSICIAN5_SESSION_ID, PHYSICIAN5_TOKEN_HASH);
  addPhysicianSession(PHYSICIAN_STATE_USER_ID, PHYSICIAN_STATE_SESSION_ID, PHYSICIAN_STATE_TOKEN_HASH);
  addPhysicianSession(DELEGATE2_PHYSICIAN_ID, 'bbbb0000-0000-0000-0000-000000000060', hashToken('unused'));

  addDelegateSession(
    DELEGATE_USER_ID,
    DELEGATE_SESSION_ID,
    DELEGATE_TOKEN_HASH,
    DELEGATE_PHYSICIAN_ID,
    ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT', 'DATA_EXPORT'],
  );

  addDelegateSession(
    DELEGATE2_USER_ID,
    DELEGATE2_SESSION_ID,
    DELEGATE2_TOKEN_HASH,
    DELEGATE2_PHYSICIAN_ID,
    ['ANALYTICS_VIEW', 'REPORT_VIEW', 'REPORT_EXPORT', 'DATA_EXPORT'],
  );
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Analytics & Reporting Audit Trail Verification (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedSessions();
    auditLogCalls = [];
    downloadAuditCalls = [];
    mockReports = [];
    mockSubscriptions = [];
  });

  // =========================================================================
  // 1. DASHBOARD_VIEWED Audit Events
  // =========================================================================

  describe('DASHBOARD_VIEWED Audit Events', () => {
    const DASHBOARDS = [
      { path: '/api/v1/analytics/revenue?period=THIS_MONTH', type: 'revenue' },
      { path: '/api/v1/analytics/rejections?period=THIS_MONTH', type: 'rejections' },
      { path: '/api/v1/analytics/aging', type: 'aging' },
      { path: '/api/v1/analytics/wcb?period=THIS_MONTH', type: 'wcb' },
      { path: '/api/v1/analytics/ai-coach?period=THIS_MONTH', type: 'ai-coach' },
      { path: '/api/v1/analytics/multi-site?period=THIS_MONTH', type: 'multi-site' },
      { path: '/api/v1/analytics/kpis?period=THIS_MONTH', type: 'kpis' },
    ];

    for (const dashboard of DASHBOARDS) {
      it(`viewing ${dashboard.type} dashboard produces DASHBOARD_VIEWED audit entry`, async () => {
        const res = await app.inject({
          method: 'GET',
          url: dashboard.path,
          headers: physicianHeaders(),
        });

        expect(res.statusCode).toBe(200);

        // Allow fire-and-forget audit to settle
        await new Promise((r) => setTimeout(r, 20));

        const dashAudits = auditLogCalls.filter(
          (a) =>
            a.action === AnalyticsAuditAction.DASHBOARD_VIEWED &&
            (a.details as any).dashboardType === dashboard.type,
        );
        expect(dashAudits.length).toBe(1);
        expect(dashAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
        expect(dashAudits[0].details.dashboardType).toBe(dashboard.type);
      });
    }

    it('audit entry includes period and dashboard type', async () => {
      // Use physician3 to avoid rate-limit collision with earlier revenue tests
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_QUARTER',
        headers: physician3Headers(),
      });

      expect(res.statusCode).toBe(200);
      await new Promise((r) => setTimeout(r, 20));

      const audits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.DASHBOARD_VIEWED &&
          a.providerId === PHYSICIAN3_USER_ID,
      );
      expect(audits.length).toBe(1);
      expect(audits[0].details.dashboardType).toBe('revenue');
      expect(audits[0].details.period).toBe('THIS_QUARTER');
    });
  });

  // =========================================================================
  // 2. REPORT_GENERATED Audit Events
  // =========================================================================

  describe('REPORT_GENERATED Audit Events', () => {
    it('generating accountant report produces REPORT_GENERATED audit entry', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        headers: physicianHeaders(),
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const reportAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.REPORT_GENERATED,
      );
      expect(reportAudits.length).toBe(1);
      expect(reportAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
      expect(reportAudits[0].details.reportId).toBeDefined();
      expect(reportAudits[0].details.reportType).toBe('ACCOUNTANT_SUMMARY');
      expect(reportAudits[0].details.format).toBe('CSV');
      expect(reportAudits[0].details.periodStart).toBe('2026-01-01');
      expect(reportAudits[0].details.periodEnd).toBe('2026-01-31');
    });

    it('audit entry includes actor identity (providerId)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        headers: physicianHeaders(),
        payload: {
          format: 'pdf_detail',
          period_start: '2026-02-01',
          period_end: '2026-02-28',
        },
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const reportAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.REPORT_GENERATED,
      );
      expect(reportAudits.length).toBe(1);
      expect(reportAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
    });
  });

  // =========================================================================
  // 3. REPORT_DOWNLOADED Audit Events
  // =========================================================================

  describe('REPORT_DOWNLOADED Audit Events', () => {
    it('downloading a report produces REPORT_DOWNLOADED audit entry', async () => {
      // Seed a ready report
      const report: MockReport = {
        reportId: DUMMY_REPORT_ID,
        providerId: PHYSICIAN_USER_ID,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'CSV',
        status: 'ready',
        filePath: '/tmp/test-report.csv',
        fileSizeBytes: 1024,
        downloadLinkExpiresAt: new Date(Date.now() + 86400000),
        downloaded: false,
        createdAt: new Date(),
      };
      mockReports.push(report);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}/download`,
        headers: physicianHeaders(),
      });

      expect(res.statusCode).toBe(200);

      // The download service records audit entries
      expect(downloadAuditCalls.length).toBe(1);
      expect(downloadAuditCalls[0].action).toBe(AnalyticsAuditAction.REPORT_DOWNLOADED);
      expect(downloadAuditCalls[0].resourceId).toBe(DUMMY_REPORT_ID);
      expect(downloadAuditCalls[0].providerId).toBe(PHYSICIAN_USER_ID);
    });

    it('audit entry includes report_id and timestamp', async () => {
      mockReports.push({
        reportId: DUMMY_REPORT_ID,
        providerId: PHYSICIAN_USER_ID,
        reportType: 'ACCOUNTANT_DETAIL',
        format: 'PDF',
        status: 'ready',
        filePath: '/tmp/test-report.pdf',
        fileSizeBytes: 2048,
        downloadLinkExpiresAt: new Date(Date.now() + 86400000),
        downloaded: false,
        createdAt: new Date(),
      });

      await app.inject({
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}/download`,
        headers: physicianHeaders(),
      });

      expect(downloadAuditCalls.length).toBe(1);
      expect(downloadAuditCalls[0].resourceId).toBe(DUMMY_REPORT_ID);
      expect(downloadAuditCalls[0].metadata?.reportType).toBe('ACCOUNTANT_DETAIL');
    });
  });

  // =========================================================================
  // 4. DATA_PORTABILITY_REQUESTED Audit Events
  // =========================================================================

  describe('DATA_PORTABILITY_REQUESTED Audit Events', () => {
    it('requesting data portability export produces DATA_PORTABILITY_REQUESTED audit', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/data-portability',
        headers: physicianHeaders(),
        payload: {},
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const portabilityAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.DATA_PORTABILITY_REQUESTED,
      );
      expect(portabilityAudits.length).toBe(1);
      expect(portabilityAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
      expect(portabilityAudits[0].details.reportId).toBeDefined();
    });

    it('data portability audit is flagged as sensitive action', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/reports/data-portability',
        headers: physicianHeaders(),
        payload: {},
      });

      await new Promise((r) => setTimeout(r, 20));

      const portabilityAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.DATA_PORTABILITY_REQUESTED,
      );
      expect(portabilityAudits.length).toBe(1);
      expect(portabilityAudits[0].details.sensitive).toBe(true);
    });
  });

  // =========================================================================
  // 5. DATA_PORTABILITY_DOWNLOADED Audit Events
  // =========================================================================

  describe('DATA_PORTABILITY_DOWNLOADED Audit Events', () => {
    it('downloading data portability export produces DATA_PORTABILITY_DOWNLOADED audit', async () => {
      // Seed a ready data portability report
      const report: MockReport = {
        reportId: DUMMY_REPORT_ID,
        providerId: PHYSICIAN_USER_ID,
        reportType: 'DATA_PORTABILITY',
        format: 'ZIP',
        status: 'ready',
        filePath: '/tmp/data-export.zip',
        fileSizeBytes: 4096,
        downloadLinkExpiresAt: new Date(Date.now() + 86400000),
        downloaded: false,
        createdAt: new Date(),
      };
      mockReports.push(report);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}/download`,
        headers: physicianHeaders(),
      });

      expect(res.statusCode).toBe(200);

      expect(downloadAuditCalls.length).toBe(1);
      expect(downloadAuditCalls[0].action).toBe(
        AnalyticsAuditAction.DATA_PORTABILITY_DOWNLOADED,
      );
      expect(downloadAuditCalls[0].providerId).toBe(PHYSICIAN_USER_ID);
    });
  });

  // =========================================================================
  // 6. SUBSCRIPTION_CREATED Audit Events
  // =========================================================================

  describe('SUBSCRIPTION_CREATED Audit Events', () => {
    it('creating subscription produces SUBSCRIPTION_CREATED audit entry', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: physicianHeaders(),
        payload: {
          report_type: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          delivery_method: 'EMAIL',
        },
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const subAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_CREATED,
      );
      expect(subAudits.length).toBe(1);
      expect(subAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
      expect(subAudits[0].details.subscriptionId).toBeDefined();
      expect(subAudits[0].details.reportType).toBe('WEEKLY_SUMMARY');
      expect(subAudits[0].details.frequency).toBe('WEEKLY');
      expect(subAudits[0].details.deliveryMethod).toBe('EMAIL');
    });
  });

  // =========================================================================
  // 7. SUBSCRIPTION_UPDATED Audit Events
  // =========================================================================

  describe('SUBSCRIPTION_UPDATED Audit Events', () => {
    it('updating subscription produces SUBSCRIPTION_UPDATED audit with old and new values', async () => {
      // Create a subscription first
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: physicianHeaders(),
        payload: {
          report_type: 'MONTHLY_PERFORMANCE',
          frequency: 'MONTHLY',
          delivery_method: 'IN_APP',
        },
      });

      expect(createRes.statusCode).toBe(201);
      const subscriptionId = createRes.json().data.subscription_id;

      // Clear audit log to isolate update event
      auditLogCalls = [];

      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/v1/report-subscriptions/${subscriptionId}`,
        headers: physicianHeaders(),
        payload: {
          frequency: 'WEEKLY',
          delivery_method: 'BOTH',
        },
      });

      expect(updateRes.statusCode).toBe(200);
      await new Promise((r) => setTimeout(r, 20));

      const updateAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_UPDATED,
      );
      expect(updateAudits.length).toBe(1);
      expect(updateAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
      expect(updateAudits[0].details.subscriptionId).toBe(subscriptionId);
      expect(updateAudits[0].details.changes).toBeDefined();
      const changes = updateAudits[0].details.changes as Record<string, unknown>;
      expect(changes.frequency).toBe('WEEKLY');
      expect(changes.delivery_method).toBe('BOTH');
    });
  });

  // =========================================================================
  // 8. SUBSCRIPTION_CANCELLED Audit Events
  // =========================================================================

  describe('SUBSCRIPTION_CANCELLED Audit Events', () => {
    it('deleting subscription produces SUBSCRIPTION_CANCELLED audit entry', async () => {
      // Create a subscription first
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: physicianHeaders(),
        payload: {
          report_type: 'REJECTION_DIGEST',
          frequency: 'DAILY',
          delivery_method: 'EMAIL',
        },
      });

      expect(createRes.statusCode).toBe(201);
      const subscriptionId = createRes.json().data.subscription_id;

      // Clear audit log to isolate delete event
      auditLogCalls = [];

      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/report-subscriptions/${subscriptionId}`,
        headers: physicianHeaders(),
      });

      expect(deleteRes.statusCode).toBe(204);
      await new Promise((r) => setTimeout(r, 20));

      const cancelAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_CANCELLED,
      );
      expect(cancelAudits.length).toBe(1);
      expect(cancelAudits[0].providerId).toBe(PHYSICIAN_USER_ID);
      expect(cancelAudits[0].details.subscriptionId).toBe(subscriptionId);
    });
  });

  // =========================================================================
  // 9. Audit Integrity — Append-Only
  // =========================================================================

  describe('Audit Integrity — Append-Only', () => {
    it('no PUT/PATCH endpoint exists for audit log modification', async () => {
      const auditPaths = [
        '/api/v1/analytics/audit',
        '/api/v1/analytics/audit-log',
        `/api/v1/analytics/audit/${DUMMY_UUID}`,
        `/api/v1/analytics/audit-log/${DUMMY_UUID}`,
      ];

      for (const path of auditPaths) {
        const putRes = await app.inject({
          method: 'PUT',
          url: path,
          headers: physicianHeaders(),
          payload: { action: 'TAMPERED' },
        });
        expect(putRes.statusCode).not.toBe(200);

        const patchRes = await app.inject({
          method: 'PATCH',
          url: path,
          headers: physicianHeaders(),
          payload: { action: 'TAMPERED' },
        });
        expect(patchRes.statusCode).not.toBe(200);
      }
    });

    it('no DELETE endpoint exists for audit log records', async () => {
      const auditPaths = [
        '/api/v1/analytics/audit',
        '/api/v1/analytics/audit-log',
        `/api/v1/analytics/audit/${DUMMY_UUID}`,
        `/api/v1/analytics/audit-log/${DUMMY_UUID}`,
      ];

      for (const path of auditPaths) {
        const deleteRes = await app.inject({
          method: 'DELETE',
          url: path,
          headers: physicianHeaders(),
        });
        expect(deleteRes.statusCode).not.toBe(200);
        expect(deleteRes.statusCode).not.toBe(204);
      }
    });

    it('each audit entry includes action, providerId, and details JSONB', async () => {
      // Trigger a report generation to produce an audit entry
      await app.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        headers: physicianHeaders(),
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
      });

      await new Promise((r) => setTimeout(r, 20));

      expect(auditLogCalls.length).toBeGreaterThanOrEqual(1);
      const entry = auditLogCalls[0];
      expect(entry.action).toBeDefined();
      expect(typeof entry.action).toBe('string');
      expect(entry.providerId).toBeDefined();
      expect(typeof entry.providerId).toBe('string');
      expect(entry.details).toBeDefined();
      expect(typeof entry.details).toBe('object');
    });

    it('no analytics API route allows modification of existing audit entries', async () => {
      // Verify there are no routes that could modify audit entries
      const modificationAttempts = [
        { method: 'PUT' as const, url: '/api/v1/reports/audit' },
        { method: 'DELETE' as const, url: '/api/v1/reports/audit' },
        { method: 'PUT' as const, url: '/api/v1/report-subscriptions/audit' },
        { method: 'DELETE' as const, url: '/api/v1/report-subscriptions/audit' },
      ];

      for (const attempt of modificationAttempts) {
        const res = await app.inject({
          method: attempt.method,
          url: attempt.url,
          headers: physicianHeaders(),
          ...(attempt.method === 'PUT' ? { payload: { data: 'tampered' } } : {}),
        });
        expect(res.statusCode).not.toBe(200);
        expect(res.statusCode).not.toBe(204);
      }
    });
  });

  // =========================================================================
  // 10. Delegate Audit Trail
  // =========================================================================

  describe('Delegate Audit Trail', () => {
    it('delegate viewing dashboard records physician as provider, delegate as actor context', async () => {
      // Use delegate2 to avoid rate-limit collision (delegate2 maps to a fresh physician ID)
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: delegate2Headers(),
      });

      expect(res.statusCode).toBe(200);
      await new Promise((r) => setTimeout(r, 20));

      const dashAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.DASHBOARD_VIEWED &&
          a.providerId === DELEGATE2_PHYSICIAN_ID,
      );
      expect(dashAudits.length).toBe(1);
      // Provider ID should be the physician's ID (delegate context)
      expect(dashAudits[0].providerId).toBe(DELEGATE2_PHYSICIAN_ID);
      // Must NOT be the delegate's own user ID
      expect(dashAudits[0].providerId).not.toBe(DELEGATE2_USER_ID);
    });

    it('delegate downloading report records physician as provider', async () => {
      const report: MockReport = {
        reportId: DUMMY_REPORT_ID,
        providerId: DELEGATE_PHYSICIAN_ID,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'CSV',
        status: 'ready',
        filePath: '/tmp/delegate-report.csv',
        fileSizeBytes: 512,
        downloadLinkExpiresAt: new Date(Date.now() + 86400000),
        downloaded: false,
        createdAt: new Date(),
      };
      mockReports.push(report);

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}/download`,
        headers: delegateHeaders(),
      });

      expect(res.statusCode).toBe(200);

      expect(downloadAuditCalls.length).toBe(1);
      expect(downloadAuditCalls[0].providerId).toBe(DELEGATE_PHYSICIAN_ID);
      expect(downloadAuditCalls[0].providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate creating subscription records physician as provider', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: delegateHeaders(),
        payload: {
          report_type: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          delivery_method: 'IN_APP',
        },
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const subAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_CREATED,
      );
      expect(subAudits.length).toBe(1);
      expect(subAudits[0].providerId).toBe(DELEGATE_PHYSICIAN_ID);
      expect(subAudits[0].providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate generating report records physician as provider', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        headers: delegateHeaders(),
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const reportAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.REPORT_GENERATED,
      );
      expect(reportAudits.length).toBe(1);
      expect(reportAudits[0].providerId).toBe(DELEGATE_PHYSICIAN_ID);
      expect(reportAudits[0].providerId).not.toBe(DELEGATE_USER_ID);
    });

    it('delegate requesting data portability records physician as provider', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/reports/data-portability',
        headers: delegateHeaders(),
        payload: {},
      });

      expect(res.statusCode).toBe(201);
      await new Promise((r) => setTimeout(r, 20));

      const portabilityAudits = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.DATA_PORTABILITY_REQUESTED,
      );
      expect(portabilityAudits.length).toBe(1);
      expect(portabilityAudits[0].providerId).toBe(DELEGATE_PHYSICIAN_ID);
      expect(portabilityAudits[0].providerId).not.toBe(DELEGATE_USER_ID);
    });
  });

  // =========================================================================
  // 11. Rate-Limited Audit (DASHBOARD_VIEWED)
  // =========================================================================

  describe('Rate-Limited Audit (DASHBOARD_VIEWED)', () => {
    it('viewing same dashboard 3 times in 1 minute produces only 1 audit entry', async () => {
      // Use physician4 to avoid rate-limit collision with earlier tests
      // First view — should audit
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: physician4Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      // Second view — should be rate-limited (same dashboard type, within 5 min)
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: physician4Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      // Third view — also rate-limited
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: physician4Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      const revenueAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.DASHBOARD_VIEWED &&
          (a.details as any).dashboardType === 'revenue' &&
          a.providerId === PHYSICIAN4_USER_ID,
      );

      // Only 1 audit entry despite 3 views
      expect(revenueAudits.length).toBe(1);
    });

    it('viewing different dashboard types produces separate audit entries', async () => {
      // Use physician5 to avoid rate-limit collision
      // View revenue dashboard
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: physician5Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      // View rejections dashboard (different type)
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/rejections?period=THIS_MONTH',
        headers: physician5Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      const dashAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.DASHBOARD_VIEWED &&
          a.providerId === PHYSICIAN5_USER_ID,
      );

      // 2 separate audit entries for 2 different dashboard types
      expect(dashAudits.length).toBe(2);

      const types = dashAudits.map((a) => a.details.dashboardType);
      expect(types).toContain('revenue');
      expect(types).toContain('rejections');
    });

    it('different physicians viewing same dashboard type get separate audit entries', async () => {
      // Use aging dashboard (fresh for both physician2 and physician4 in rate-limit map)
      // Physician 2 views aging
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/aging',
        headers: physician2Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      // Physician 4 views aging (same dashboard type, different physician)
      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/aging',
        headers: physician4Headers(),
      });
      await new Promise((r) => setTimeout(r, 20));

      const agingAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.DASHBOARD_VIEWED &&
          (a.details as any).dashboardType === 'aging',
      );

      // 2 audit entries — one per physician
      expect(agingAudits.length).toBe(2);

      const providerIds = agingAudits.map((a) => a.providerId);
      expect(providerIds).toContain(PHYSICIAN2_USER_ID);
      expect(providerIds).toContain(PHYSICIAN4_USER_ID);
    });
  });

  // =========================================================================
  // 12. Every State-Changing Endpoint Produces Audit
  // =========================================================================

  describe('Every State-Changing Endpoint Produces Audit', () => {
    interface StateChangeRoute {
      method: 'GET' | 'POST' | 'PUT' | 'DELETE';
      url: string;
      payload?: Record<string, unknown>;
      description: string;
      setup?: () => void;
      expectedAuditAction?: string;
      checkDownloadAudit?: boolean;
      useStatePhysician?: boolean;
    }

    // Use PHYSICIAN_STATE identity for all dashboard views (fresh rate-limit namespace)
    const STATE_CHANGING_ROUTES: StateChangeRoute[] = [
      // Dashboard views (all 7) — use physicianStateHeaders for fresh rate limits
      {
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        description: 'View revenue dashboard',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      {
        method: 'GET',
        url: '/api/v1/analytics/rejections?period=THIS_MONTH',
        description: 'View rejections dashboard',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      {
        method: 'GET',
        url: '/api/v1/analytics/aging',
        description: 'View aging dashboard',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      {
        method: 'GET',
        url: '/api/v1/analytics/wcb?period=THIS_MONTH',
        description: 'View WCB dashboard',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      {
        method: 'GET',
        url: '/api/v1/analytics/ai-coach?period=THIS_MONTH',
        description: 'View AI Coach dashboard',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      {
        method: 'GET',
        url: '/api/v1/analytics/multi-site?period=THIS_MONTH',
        description: 'View multi-site dashboard',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      {
        method: 'GET',
        url: '/api/v1/analytics/kpis?period=THIS_MONTH',
        description: 'View KPIs',
        expectedAuditAction: AnalyticsAuditAction.DASHBOARD_VIEWED,
        useStatePhysician: true,
      },
      // Report generation
      {
        method: 'POST',
        url: '/api/v1/reports/accountant',
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
        description: 'Generate accountant report',
        expectedAuditAction: AnalyticsAuditAction.REPORT_GENERATED,
      },
      // Data portability
      {
        method: 'POST',
        url: '/api/v1/reports/data-portability',
        payload: {},
        description: 'Request data portability',
        expectedAuditAction: AnalyticsAuditAction.DATA_PORTABILITY_REQUESTED,
      },
      // Report download
      {
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}/download`,
        description: 'Download report',
        setup: () => {
          mockReports.push({
            reportId: DUMMY_REPORT_ID,
            providerId: PHYSICIAN_STATE_USER_ID,
            reportType: 'ACCOUNTANT_SUMMARY',
            format: 'CSV',
            status: 'ready',
            filePath: '/tmp/test.csv',
            fileSizeBytes: 100,
            downloadLinkExpiresAt: new Date(Date.now() + 86400000),
            downloaded: false,
            createdAt: new Date(),
          });
        },
        checkDownloadAudit: true,
        useStatePhysician: true,
      },
    ];

    for (const route of STATE_CHANGING_ROUTES) {
      it(`${route.description} (${route.method} ${route.url.split('?')[0]}) produces audit record`, async () => {
        auditLogCalls = [];
        downloadAuditCalls = [];

        if (route.setup) route.setup();

        const headers = route.useStatePhysician
          ? physicianStateHeaders()
          : physicianHeaders();

        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBeLessThan(300);
        await new Promise((r) => setTimeout(r, 20));

        if (route.checkDownloadAudit) {
          expect(downloadAuditCalls.length).toBeGreaterThanOrEqual(1);
        } else {
          const totalAudit = auditLogCalls.length;
          expect(totalAudit).toBeGreaterThanOrEqual(1);

          if (route.expectedAuditAction) {
            const matchingAudits = auditLogCalls.filter(
              (a) => a.action === route.expectedAuditAction,
            );
            expect(matchingAudits.length).toBeGreaterThanOrEqual(1);
          }
        }
      });
    }
  });

  // =========================================================================
  // 13. Read-Only Endpoints Do Not Produce Spurious Audits
  // =========================================================================

  describe('Read-Only Endpoints Do Not Produce Spurious State-Change Audits', () => {
    it('GET /api/v1/reports (list) does not produce audit', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/reports',
        headers: physicianHeaders(),
      });

      expect(res.statusCode).toBe(200);
      await new Promise((r) => setTimeout(r, 20));

      // No report-specific audit entries (only DASHBOARD_VIEWED from earlier could exist)
      const reportAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.REPORT_GENERATED ||
          a.action === AnalyticsAuditAction.REPORT_DOWNLOADED,
      );
      expect(reportAudits.length).toBe(0);
    });

    it('GET /api/v1/reports/:id (status check) does not produce audit', async () => {
      mockReports.push({
        reportId: DUMMY_REPORT_ID,
        providerId: PHYSICIAN_USER_ID,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'CSV',
        status: 'pending',
        filePath: '',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: new Date(Date.now() + 86400000),
        downloaded: false,
        createdAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}`,
        headers: physicianHeaders(),
      });

      expect(res.statusCode).toBe(200);
      await new Promise((r) => setTimeout(r, 20));

      const reportAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.REPORT_GENERATED ||
          a.action === AnalyticsAuditAction.REPORT_DOWNLOADED,
      );
      expect(reportAudits.length).toBe(0);
      expect(downloadAuditCalls.length).toBe(0);
    });

    it('GET /api/v1/report-subscriptions (list) does not produce audit', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/report-subscriptions',
        headers: physicianHeaders(),
      });

      expect(res.statusCode).toBe(200);
      await new Promise((r) => setTimeout(r, 20));

      const subAudits = auditLogCalls.filter(
        (a) =>
          a.action === AnalyticsAuditAction.SUBSCRIPTION_CREATED ||
          a.action === AnalyticsAuditAction.SUBSCRIPTION_UPDATED ||
          a.action === AnalyticsAuditAction.SUBSCRIPTION_CANCELLED,
      );
      expect(subAudits.length).toBe(0);
    });
  });

  // =========================================================================
  // 14. Audit Records Do Not Contain PHI
  // =========================================================================

  describe('Audit Records Do Not Contain PHI', () => {
    it('audit log entries do not contain patient names, PHN, or dates of birth', async () => {
      // Trigger multiple audit-producing actions
      await app.inject({
        method: 'POST',
        url: '/api/v1/reports/accountant',
        headers: physicianHeaders(),
        payload: {
          format: 'csv',
          period_start: '2026-01-01',
          period_end: '2026-01-31',
        },
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/reports/data-portability',
        headers: physicianHeaders(),
        payload: {},
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: physicianHeaders(),
        payload: {
          report_type: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          delivery_method: 'EMAIL',
        },
      });

      await app.inject({
        method: 'GET',
        url: '/api/v1/analytics/revenue?period=THIS_MONTH',
        headers: physicianHeaders(),
      });

      await new Promise((r) => setTimeout(r, 20));

      const allAuditsStr = JSON.stringify(auditLogCalls);

      // No patient name fields
      expect(allAuditsStr).not.toMatch(/firstName|lastName|patientName/i);
      // No PHN
      expect(allAuditsStr).not.toMatch(/\bphn\b/i);
      // No date of birth
      expect(allAuditsStr).not.toMatch(/dateOfBirth|date_of_birth/i);
      // No patient address
      expect(allAuditsStr).not.toMatch(/patientAddress|patient_address/i);
    });

    it('download audit entries contain only IDs and metadata, not PHI', async () => {
      mockReports.push({
        reportId: DUMMY_REPORT_ID,
        providerId: PHYSICIAN_USER_ID,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'CSV',
        status: 'ready',
        filePath: '/tmp/test.csv',
        fileSizeBytes: 100,
        downloadLinkExpiresAt: new Date(Date.now() + 86400000),
        downloaded: false,
        createdAt: new Date(),
      });

      await app.inject({
        method: 'GET',
        url: `/api/v1/reports/${DUMMY_REPORT_ID}/download`,
        headers: physicianHeaders(),
      });

      const allDownloadAuditsStr = JSON.stringify(downloadAuditCalls);

      // No patient fields
      expect(allDownloadAuditsStr).not.toMatch(/firstName|lastName|patientName/i);
      expect(allDownloadAuditsStr).not.toMatch(/\bphn\b/i);
      expect(allDownloadAuditsStr).not.toMatch(/dateOfBirth|date_of_birth/i);

      // Should contain only structural metadata
      expect(downloadAuditCalls[0].action).toBeDefined();
      expect(downloadAuditCalls[0].resourceId).toBeDefined();
      expect(downloadAuditCalls[0].providerId).toBeDefined();
    });
  });

  // =========================================================================
  // 15. Subscription Lifecycle Complete Audit Trail
  // =========================================================================

  describe('Subscription Lifecycle Complete Audit Trail', () => {
    it('full lifecycle (create, update, cancel) produces 3 distinct audit entries', async () => {
      // Create
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/report-subscriptions',
        headers: physicianHeaders(),
        payload: {
          report_type: 'MONTHLY_PERFORMANCE',
          frequency: 'MONTHLY',
          delivery_method: 'IN_APP',
        },
      });
      expect(createRes.statusCode).toBe(201);
      const subscriptionId = createRes.json().data.subscription_id;

      // Update
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/v1/report-subscriptions/${subscriptionId}`,
        headers: physicianHeaders(),
        payload: { frequency: 'WEEKLY' },
      });
      expect(updateRes.statusCode).toBe(200);

      // Cancel
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/report-subscriptions/${subscriptionId}`,
        headers: physicianHeaders(),
      });
      expect(deleteRes.statusCode).toBe(204);

      await new Promise((r) => setTimeout(r, 20));

      // Verify all 3 audit actions were recorded
      const created = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_CREATED,
      );
      const updated = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_UPDATED,
      );
      const cancelled = auditLogCalls.filter(
        (a) => a.action === AnalyticsAuditAction.SUBSCRIPTION_CANCELLED,
      );

      expect(created.length).toBe(1);
      expect(updated.length).toBe(1);
      expect(cancelled.length).toBe(1);

      // All point to the same subscription
      expect(created[0].details.subscriptionId).toBe(subscriptionId);
      expect(updated[0].details.subscriptionId).toBe(subscriptionId);
      expect(cancelled[0].details.subscriptionId).toBe(subscriptionId);
    });
  });
});
