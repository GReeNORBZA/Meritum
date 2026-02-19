// ============================================================================
// Domain 8: Analytics Dashboard — Integration Tests
// End-to-end tests for dashboard endpoints with mocked services that simulate
// realistic claim data (paid, rejected, adjusted, submitted across months).
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';

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
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  dashboardRoutes,
  type DashboardRouteDeps,
} from '../../../src/domains/analytics/routes/dashboard.routes.js';
import type {
  DashboardResponse,
  KpiCardsResponse,
} from '../../../src/domains/analytics/services/dashboard.service.js';
import type {
  RevenueMetrics,
  RejectionMetrics,
  AgingMetrics,
  WcbMetrics,
  AiCoachMetrics,
  MultiSiteMetrics,
  KpiMetrics,
} from '../../../src/domains/analytics/repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '10000000-0000-4000-8000-000000000001';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// ---------------------------------------------------------------------------
// Realistic metric fixtures — physician with known claim data
// ---------------------------------------------------------------------------

// Simulate a physician with:
// - 20 paid AHCIP claims totalling $3,200.00 in Feb 2026 (current month)
// - 5 rejected AHCIP claims
// - 3 adjusted AHCIP claims
// - 10 submitted WCB claims totalling $1,500.00
// - 15 paid AHCIP claims totalling $2,800.00 in Jan 2026 (prior month)
// - 2 BAs (BA001 and BA002)

function realisticRevenueMetrics(): RevenueMetrics {
  return {
    totalRevenue: '3200.00',
    totalSubmitted: '4700.00',
    claimCount: 20,
    monthlyTrend: [
      { month: '2026-01', revenue: '2800.00', count: 15 },
      { month: '2026-02', revenue: '3200.00', count: 20 },
    ],
    byBa: [
      { baNumber: 'BA001', revenue: '2000.00', count: 12 },
      { baNumber: 'BA002', revenue: '1200.00', count: 8 },
    ],
    topHscCodes: [
      { hscCode: '03.04A', revenue: '1500.00', count: 10 },
      { hscCode: '08.19A', revenue: '900.00', count: 5 },
    ],
    pendingPipeline: { value: '1500.00', count: 10 },
  };
}

function realisticRejectionMetrics(): RejectionMetrics {
  // Rejection rate = rejected / (assessed + rejected + adjusted)
  // = 5 / (20 + 5 + 3) = 5 / 28 ≈ 17.86%
  return {
    totalAssessed: 20,
    totalRejected: 5,
    totalAdjusted: 3,
    rejectionRate: '17.86',
    byExplanatoryCode: [
      { code: 'R01', count: 3 },
      { code: 'R02', count: 2 },
    ],
    byHscCode: [
      { hscCode: '03.04A', count: 2, rate: '20.00' },
      { hscCode: '08.19A', count: 3, rate: '60.00' },
    ],
    resolutionFunnel: {
      rejected: 5,
      resubmitted: 3,
      paidOnResubmission: 2,
      writtenOff: 1,
    },
  };
}

function realisticAgingMetrics(): AgingMetrics {
  return {
    brackets: [
      { label: '0-30 days', minDays: 0, maxDays: 30, count: 8, value: '1200.00' },
      { label: '31-60 days', minDays: 31, maxDays: 60, count: 5, value: '800.00' },
      { label: '61-90 days', minDays: 61, maxDays: 90, count: 3, value: '450.00' },
      { label: '90+ days', minDays: 91, maxDays: null, count: 2, value: '250.00' },
    ],
    approachingDeadline: {
      count: 1,
      claims: [{ claimId: 'claim-1', deadline: '2026-03-01', daysRemaining: 10 }],
    },
    expiredClaims: { count: 0 },
    avgResolutionDays: 22,
    staleClaims: { count: 1 },
  };
}

function realisticKpiMetrics(): KpiMetrics {
  return {
    totalRevenue: '3200.00',
    priorRevenue: '2800.00',
    revenueDelta: '14.29',
    claimsSubmitted: 30,
    priorClaimsSubmitted: 25,
    claimsDelta: '20.00',
    rejectionRate: '17.86',
    priorRejectionRate: '12.00',
    rejectionDelta: '48.83',
    avgFeePerClaim: '160.00',
    priorAvgFee: '186.67',
    avgFeeDelta: '-14.29',
    pendingPipeline: '1500.00',
    priorPendingPipeline: '1200.00',
    pipelineDelta: '25.00',
  };
}

function ahcipOnlyRevenueMetrics(): RevenueMetrics {
  return {
    totalRevenue: '3200.00',
    totalSubmitted: '3200.00',
    claimCount: 20,
    monthlyTrend: [
      { month: '2026-02', revenue: '3200.00', count: 20 },
    ],
    byBa: [
      { baNumber: 'BA001', revenue: '2000.00', count: 12 },
      { baNumber: 'BA002', revenue: '1200.00', count: 8 },
    ],
    topHscCodes: [
      { hscCode: '03.04A', revenue: '1500.00', count: 10 },
    ],
    pendingPipeline: { value: '0.00', count: 0 },
  };
}

function makeDashboardResponse<T>(data: T): DashboardResponse<T> {
  return {
    data,
    comparison: null,
    delta: null,
    period: {
      start: '2026-02-01',
      end: '2026-02-19',
      comparisonStart: '2026-01-01',
      comparisonEnd: '2026-01-19',
    },
    cacheStatus: 'realtime',
  };
}

function makeComparisonResponse<T>(
  data: T,
  comparison: T,
  delta: Record<string, string>,
): DashboardResponse<T> {
  return {
    data,
    comparison,
    delta,
    period: {
      start: '2026-02-01',
      end: '2026-02-19',
      comparisonStart: '2026-01-01',
      comparisonEnd: '2026-01-19',
    },
    cacheStatus: 'realtime',
  };
}

function makeKpiResponse(data: KpiMetrics): KpiCardsResponse {
  return {
    data,
    period: {
      start: '2026-02-01',
      end: '2026-02-19',
      comparisonStart: '2026-01-01',
      comparisonEnd: '2026-01-19',
    },
    cacheStatus: 'realtime',
  };
}

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
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(
  serviceMock: Record<string, any>,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(PHYSICIAN_ID, 'physician');
  await app.register(authPluginFp, { sessionDeps } as any);

  const auditLog = vi.fn().mockResolvedValue(undefined);

  const deps: DashboardRouteDeps = {
    dashboardService: serviceMock as any,
    auditLog,
  };

  await app.register(dashboardRoutes, { deps });
  await app.ready();

  return app;
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

describe('Analytics Dashboard — Integration Tests', () => {
  // -------------------------------------------------------------------------
  // GET /api/v1/analytics/revenue
  // -------------------------------------------------------------------------

  describe('GET /api/v1/analytics/revenue — KPI values', () => {
    it('returns revenue KPI values matching expected calculations', async () => {
      const metrics = realisticRevenueMetrics();
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(metrics),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const data = body.data.data;

      // Revenue KPI matches sum of assessed_fee for paid claims in period
      expect(data.totalRevenue).toBe('3200.00');
      expect(data.totalSubmitted).toBe('4700.00');
      expect(data.claimCount).toBe(20);

      // Monthly trend present
      expect(data.monthlyTrend).toHaveLength(2);
      expect(data.monthlyTrend[1].revenue).toBe('3200.00');

      // Pending pipeline
      expect(data.pendingPipeline.value).toBe('1500.00');
      expect(data.pendingPipeline.count).toBe(10);

      await app.close();
    });

    it('PCPCM dual-BA physician: revenue by BA correctly splits', async () => {
      const metrics = realisticRevenueMetrics();
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(metrics),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const byBa = body.data.data.byBa;

      // Verify BA split
      expect(byBa).toHaveLength(2);
      const ba001 = byBa.find((b: any) => b.baNumber === 'BA001');
      const ba002 = byBa.find((b: any) => b.baNumber === 'BA002');
      expect(ba001).toBeDefined();
      expect(ba002).toBeDefined();
      expect(ba001.revenue).toBe('2000.00');
      expect(ba002.revenue).toBe('1200.00');

      // Sum of BA revenue should equal total
      const baTotal = parseFloat(ba001.revenue) + parseFloat(ba002.revenue);
      expect(baTotal).toBe(parseFloat(metrics.totalRevenue));

      await app.close();
    });

    it('filters by claim_type=AHCIP returns only AHCIP claims', async () => {
      const ahcipMetrics = ahcipOnlyRevenueMetrics();
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(ahcipMetrics),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=THIS_MONTH&claim_type=AHCIP',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Service was called with AHCIP filter
      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
        expect.objectContaining({ claimType: 'AHCIP' }),
      );

      // Results reflect AHCIP-only data
      expect(body.data.data.totalRevenue).toBe('3200.00');
      expect(body.data.data.pendingPipeline.count).toBe(0);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // GET /api/v1/analytics/rejections
  // -------------------------------------------------------------------------

  describe('GET /api/v1/analytics/rejections — rejection rate formula', () => {
    it('rejection rate = rejected / (assessed + rejected + adjusted)', async () => {
      const metrics = realisticRejectionMetrics();
      const mockService = {
        getRejectionDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(metrics),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/rejections?period=THIS_MONTH',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const data = body.data.data;

      // Rejection rate formula: rejected / (assessed + rejected + adjusted)
      // = 5 / (20 + 5 + 3) = 5 / 28 ≈ 17.86%
      expect(data.rejectionRate).toBe('17.86');
      expect(data.totalAssessed).toBe(20);
      expect(data.totalRejected).toBe(5);
      expect(data.totalAdjusted).toBe(3);

      // Verify formula: not rejected / total_all_claims
      const denominatorCorrect = data.totalAssessed + data.totalRejected + data.totalAdjusted;
      const expectedRate = ((data.totalRejected / denominatorCorrect) * 100).toFixed(2);
      expect(data.rejectionRate).toBe(expectedRate);

      // Resolution funnel
      expect(data.resolutionFunnel.rejected).toBe(5);
      expect(data.resolutionFunnel.resubmitted).toBe(3);
      expect(data.resolutionFunnel.paidOnResubmission).toBe(2);
      expect(data.resolutionFunnel.writtenOff).toBe(1);

      await app.close();
    });

    it('breakdown by explanatory code present', async () => {
      const metrics = realisticRejectionMetrics();
      const mockService = {
        getRejectionDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(metrics),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/rejections?period=THIS_MONTH',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const byCode = body.data.data.byExplanatoryCode;

      expect(byCode).toHaveLength(2);
      const totalByCode = byCode.reduce((sum: number, c: any) => sum + c.count, 0);
      expect(totalByCode).toBe(5); // Matches totalRejected

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // GET /api/v1/analytics/aging
  // -------------------------------------------------------------------------

  describe('GET /api/v1/analytics/aging — bracket assignment', () => {
    it('verifies bracket assignment by days since DOS', async () => {
      const metrics = realisticAgingMetrics();
      const mockService = {
        getAgingDashboard: vi.fn().mockResolvedValue({
          data: metrics,
          cacheStatus: 'realtime',
        }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const brackets = body.data.data.brackets;

      // Verify 4 aging brackets
      expect(brackets).toHaveLength(4);

      // Bracket boundaries: 0-30, 31-60, 61-90, 90+
      expect(brackets[0].label).toBe('0-30 days');
      expect(brackets[0].minDays).toBe(0);
      expect(brackets[0].maxDays).toBe(30);
      expect(brackets[0].count).toBe(8);

      expect(brackets[1].label).toBe('31-60 days');
      expect(brackets[1].minDays).toBe(31);
      expect(brackets[1].maxDays).toBe(60);
      expect(brackets[1].count).toBe(5);

      expect(brackets[2].label).toBe('61-90 days');
      expect(brackets[2].minDays).toBe(61);
      expect(brackets[2].maxDays).toBe(90);
      expect(brackets[2].count).toBe(3);

      expect(brackets[3].label).toBe('90+ days');
      expect(brackets[3].minDays).toBe(91);
      expect(brackets[3].maxDays).toBeNull();
      expect(brackets[3].count).toBe(2);

      await app.close();
    });

    it('includes approaching deadline claims', async () => {
      const metrics = realisticAgingMetrics();
      const mockService = {
        getAgingDashboard: vi.fn().mockResolvedValue({
          data: metrics,
          cacheStatus: 'realtime',
        }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const approaching = body.data.data.approachingDeadline;

      expect(approaching.count).toBe(1);
      expect(approaching.claims).toHaveLength(1);
      expect(approaching.claims[0]).toHaveProperty('claimId');
      expect(approaching.claims[0]).toHaveProperty('daysRemaining');

      await app.close();
    });

    it('returns average resolution days', async () => {
      const metrics = realisticAgingMetrics();
      const mockService = {
        getAgingDashboard: vi.fn().mockResolvedValue({
          data: metrics,
          cacheStatus: 'realtime',
        }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.data.avgResolutionDays).toBe(22);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // GET /api/v1/analytics/kpis
  // -------------------------------------------------------------------------

  describe('GET /api/v1/analytics/kpis — all KPI card values', () => {
    it('returns all KPI card values in single response', async () => {
      const kpis = realisticKpiMetrics();
      const mockService = {
        getKpis: vi.fn().mockResolvedValue(makeKpiResponse(kpis)),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const data = body.data.data;

      // Revenue KPI
      expect(data.totalRevenue).toBe('3200.00');
      expect(data.priorRevenue).toBe('2800.00');
      expect(data.revenueDelta).toBe('14.29');

      // Claims submitted KPI
      expect(data.claimsSubmitted).toBe(30);
      expect(data.priorClaimsSubmitted).toBe(25);
      expect(data.claimsDelta).toBe('20.00');

      // Rejection rate KPI
      expect(data.rejectionRate).toBe('17.86');
      expect(data.priorRejectionRate).toBe('12.00');

      // Avg fee per claim KPI
      expect(data.avgFeePerClaim).toBe('160.00');
      expect(data.priorAvgFee).toBe('186.67');
      expect(data.avgFeeDelta).toBe('-14.29');

      // Pending pipeline KPI
      expect(data.pendingPipeline).toBe('1500.00');

      await app.close();
    });

    it('period comparison: THIS_MONTH delta values reflect prior month', async () => {
      const kpis = realisticKpiMetrics();
      const mockService = {
        getKpis: vi.fn().mockResolvedValue(makeKpiResponse(kpis)),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const data = body.data.data;

      // Revenue delta: (3200 - 2800) / |2800| * 100 = 14.29%
      expect(data.revenueDelta).toBe('14.29');

      // Claims delta: (30 - 25) / |25| * 100 = 20.00%
      expect(data.claimsDelta).toBe('20.00');

      // Pipeline delta: (1500 - 1200) / |1200| * 100 = 25.00%
      expect(data.pipelineDelta).toBe('25.00');

      // Period info present
      expect(body.data.period).toBeDefined();
      expect(body.data.period.start).toBe('2026-02-01');
      expect(body.data.period.comparisonStart).toBe('2026-01-01');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Revenue comparison with period
  // -------------------------------------------------------------------------

  describe('Period comparison — revenue dashboard', () => {
    it('THIS_MONTH returns delta values against prior month', async () => {
      const current = realisticRevenueMetrics();
      const prior: RevenueMetrics = {
        ...current,
        totalRevenue: '2800.00',
        claimCount: 15,
      };
      const delta = {
        totalRevenue: '14.29',
        claimCount: '33.33',
      };

      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeComparisonResponse(current, prior, delta),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Current period data
      expect(body.data.data.totalRevenue).toBe('3200.00');

      // Comparison data present
      expect(body.data.comparison).not.toBeNull();
      expect(body.data.comparison.totalRevenue).toBe('2800.00');

      // Delta values
      expect(body.data.delta).not.toBeNull();
      expect(body.data.delta.totalRevenue).toBe('14.29');

      // Period boundaries
      expect(body.data.period.start).toBeDefined();
      expect(body.data.period.comparisonStart).toBeDefined();

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Revenue filtered by claim_type=AHCIP
  // -------------------------------------------------------------------------

  describe('Filter: claim_type=AHCIP', () => {
    it('passes AHCIP filter to service and returns filtered data', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(ahcipOnlyRevenueMetrics()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=THIS_MONTH&claim_type=AHCIP',
      );

      expect(res.statusCode).toBe(200);

      // Verify the service was called with correct filter
      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
        expect.objectContaining({ claimType: 'AHCIP' }),
      );

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // PCPCM dual-BA revenue split
  // -------------------------------------------------------------------------

  describe('PCPCM dual-BA physician', () => {
    it('revenue by BA correctly splits across two BAs', async () => {
      const metrics: RevenueMetrics = {
        totalRevenue: '5000.00',
        totalSubmitted: '5000.00',
        claimCount: 30,
        monthlyTrend: [],
        byBa: [
          { baNumber: 'BA001', revenue: '3000.00', count: 18 },
          { baNumber: 'PCPCM-BA002', revenue: '2000.00', count: 12 },
        ],
        topHscCodes: [],
        pendingPipeline: { value: '0.00', count: 0 },
      };
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(metrics),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=THIS_MONTH',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const byBa = body.data.data.byBa;

      expect(byBa).toHaveLength(2);

      // Each BA has its own revenue correctly attributed
      const feeBa = byBa.find((b: any) => b.baNumber === 'BA001');
      const pcpcmBa = byBa.find((b: any) => b.baNumber === 'PCPCM-BA002');
      expect(feeBa).toBeDefined();
      expect(pcpcmBa).toBeDefined();
      expect(feeBa.revenue).toBe('3000.00');
      expect(pcpcmBa.revenue).toBe('2000.00');

      // Sum matches total
      const baSum = parseFloat(feeBa.revenue) + parseFloat(pcpcmBa.revenue);
      expect(baSum.toFixed(2)).toBe(metrics.totalRevenue);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Cache status field
  // -------------------------------------------------------------------------

  describe('Cache status', () => {
    it('includes cacheStatus in response', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(realisticRevenueMetrics()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.cacheStatus).toBe('realtime');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // All dashboard endpoints return 200 for authenticated physician
  // -------------------------------------------------------------------------

  describe('All dashboard endpoints accessible to authenticated physician', () => {
    let app: FastifyInstance;

    const fullService = {
      getRevenueDashboard: vi.fn().mockResolvedValue(
        makeDashboardResponse(realisticRevenueMetrics()),
      ),
      getRejectionDashboard: vi.fn().mockResolvedValue(
        makeDashboardResponse(realisticRejectionMetrics()),
      ),
      getAgingDashboard: vi.fn().mockResolvedValue({
        data: realisticAgingMetrics(),
        cacheStatus: 'realtime' as const,
      }),
      getWcbDashboard: vi.fn().mockResolvedValue(
        makeDashboardResponse({
          byFormType: [],
          timingTierDistribution: [],
          feeByTimingTier: [],
          revenueTrend: [],
          rejectionRate: '0.00',
          totalClaims: 0,
          totalRejected: 0,
        }),
      ),
      getAiCoachDashboard: vi.fn().mockResolvedValue(
        makeDashboardResponse({
          acceptanceRate: '0.00',
          totalGenerated: 0,
          totalAccepted: 0,
          totalDismissed: 0,
          revenueRecovered: '0.00',
          byCategory: [],
          topAcceptedRules: [],
          suppressedRules: [],
        }),
      ),
      getMultiSiteDashboard: vi.fn().mockResolvedValue(
        makeDashboardResponse({ locations: [] }),
      ),
      getKpis: vi.fn().mockResolvedValue(
        makeKpiResponse(realisticKpiMetrics()),
      ),
    };

    beforeAll(async () => {
      app = await buildTestApp(fullService);
    });

    afterAll(async () => {
      await app.close();
    });

    const endpoints = [
      '/api/v1/analytics/revenue?period=THIS_MONTH',
      '/api/v1/analytics/rejections?period=THIS_MONTH',
      '/api/v1/analytics/aging',
      '/api/v1/analytics/wcb?period=THIS_MONTH',
      '/api/v1/analytics/ai-coach?period=THIS_MONTH',
      '/api/v1/analytics/multi-site?period=THIS_MONTH',
      '/api/v1/analytics/kpis?period=THIS_MONTH',
    ];

    for (const endpoint of endpoints) {
      it(`GET ${endpoint} returns 200`, async () => {
        const res = await authedGet(app, endpoint);
        expect(res.statusCode).toBe(200);
      });
    }
  });
});
