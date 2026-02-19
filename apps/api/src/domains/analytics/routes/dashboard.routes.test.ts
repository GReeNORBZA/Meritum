// ============================================================================
// Domain 8: Dashboard Routes — Unit Tests
// Tests: route registration, Zod query validation, service method dispatch,
// provider scoping from auth context, audit rate limiting.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';

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
import { authPluginFp } from '../../../plugins/auth.plugin.js';
import { dashboardRoutes, type DashboardRouteDeps } from './dashboard.routes.js';
import { TimePeriod } from '@meritum/shared/constants/analytics.constants.js';
import type {
  DashboardResponse,
  KpiCardsResponse,
} from '../services/dashboard.service.js';
import type {
  RevenueMetrics,
  RejectionMetrics,
  AgingMetrics,
  WcbMetrics,
  AiCoachMetrics,
  MultiSiteMetrics,
  KpiMetrics,
} from '../repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000002';
const DELEGATE_PHYSICIAN_ID = '00000000-0000-4000-8000-000000000003';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// ---------------------------------------------------------------------------
// Mock metric fixtures
// ---------------------------------------------------------------------------

function emptyRevenue(): RevenueMetrics {
  return {
    totalRevenue: '0.00',
    totalSubmitted: '0.00',
    claimCount: 0,
    monthlyTrend: [],
    byBa: [],
    topHscCodes: [],
    pendingPipeline: { value: '0.00', count: 0 },
  };
}

function emptyRejection(): RejectionMetrics {
  return {
    totalAssessed: 0,
    totalRejected: 0,
    totalAdjusted: 0,
    rejectionRate: '0.00',
    byExplanatoryCode: [],
    byHscCode: [],
    resolutionFunnel: { rejected: 0, resubmitted: 0, paidOnResubmission: 0, writtenOff: 0 },
  };
}

function emptyAging(): AgingMetrics {
  return {
    brackets: [],
    approachingDeadline: { count: 0, claims: [] },
    expiredClaims: { count: 0 },
    avgResolutionDays: null,
    staleClaims: { count: 0 },
  };
}

function emptyWcb(): WcbMetrics {
  return {
    byFormType: [],
    timingTierDistribution: [],
    feeByTimingTier: [],
    revenueTrend: [],
    rejectionRate: '0.00',
    totalClaims: 0,
    totalRejected: 0,
  };
}

function emptyAiCoach(): AiCoachMetrics {
  return {
    acceptanceRate: '0.00',
    totalGenerated: 0,
    totalAccepted: 0,
    totalDismissed: 0,
    revenueRecovered: '0.00',
    byCategory: [],
    topAcceptedRules: [],
    suppressedRules: [],
  };
}

function emptyMultiSite(): MultiSiteMetrics {
  return { locations: [] };
}

function emptyKpis(): KpiMetrics {
  return {
    totalRevenue: '0.00',
    priorRevenue: '0.00',
    revenueDelta: '0.00',
    claimsSubmitted: 0,
    priorClaimsSubmitted: 0,
    claimsDelta: '0.00',
    rejectionRate: '0.00',
    priorRejectionRate: '0.00',
    rejectionDelta: '0.00',
    avgFeePerClaim: '0.00',
    priorAvgFee: '0.00',
    avgFeeDelta: '0.00',
    pendingPipeline: '0.00',
    priorPendingPipeline: '0.00',
    pipelineDelta: '0.00',
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

function makeSessionDeps(
  userId: string,
  role: string,
  delegateContext?: Record<string, unknown>,
) {
  const userObj: any = {
    userId,
    role,
    subscriptionStatus: 'ACTIVE',
  };
  if (delegateContext) {
    userObj.delegateContext = delegateContext;
  }

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
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(
  serviceMock: Record<string, any>,
  opts: {
    userId?: string;
    role?: string;
    delegateContext?: Record<string, unknown>;
  } = {},
): Promise<FastifyInstance> {
  const userId = opts.userId ?? PHYSICIAN_ID;
  const role = opts.role ?? 'physician';

  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(userId, role, opts.delegateContext);
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

function authedGet(app: FastifyInstance, url: string, token = SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Dashboard Routes', () => {
  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/revenue
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/revenue', () => {
    it('returns revenue dashboard with valid period', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyRevenue()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.data).toBeDefined();
      expect(mockService.getRevenueDashboard).toHaveBeenCalledOnce();
      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
        expect.any(Object),
      );

      await app.close();
    });

    it('rejects missing period param with 400', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue');

      expect(res.statusCode).toBe(400);
      expect(mockService.getRevenueDashboard).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects invalid period value with 400', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=INVALID');

      expect(res.statusCode).toBe(400);
      expect(mockService.getRevenueDashboard).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects CUSTOM_RANGE without dates with 400', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=CUSTOM_RANGE');

      expect(res.statusCode).toBe(400);
      expect(mockService.getRevenueDashboard).not.toHaveBeenCalled();

      await app.close();
    });

    it('accepts CUSTOM_RANGE with valid dates', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyRevenue()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2026-01-01&end_date=2026-01-31',
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          period: 'CUSTOM_RANGE',
          start_date: '2026-01-01',
          end_date: '2026-01-31',
        }),
        expect.any(Object),
      );

      await app.close();
    });

    it('passes optional filters to service', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyRevenue()),
        ),
      };
      const app = await buildTestApp(mockService);
      const locationId = '00000000-0000-4000-8000-000000000099';

      const res = await authedGet(
        app,
        `/api/v1/analytics/revenue?period=THIS_MONTH&claim_type=AHCIP&ba_number=BA001&location_id=${locationId}`,
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
        expect.objectContaining({
          claimType: 'AHCIP',
          baNumber: 'BA001',
          locationId,
        }),
      );

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH', 'invalid-token');

      expect(res.statusCode).toBe(401);
      expect(mockService.getRevenueDashboard).not.toHaveBeenCalled();

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/rejections
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/rejections', () => {
    it('returns rejection dashboard with valid period', async () => {
      const mockService = {
        getRejectionDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyRejection()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/rejections?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      expect(mockService.getRejectionDashboard).toHaveBeenCalledOnce();
      expect(mockService.getRejectionDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
        expect.any(Object),
      );

      await app.close();
    });

    it('rejects missing period with 400', async () => {
      const mockService = { getRejectionDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/rejections');
      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/aging
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/aging', () => {
    it('returns aging dashboard (no period required)', async () => {
      const mockService = {
        getAgingDashboard: vi.fn().mockResolvedValue({
          data: emptyAging(),
          cacheStatus: 'realtime',
        }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/aging');

      expect(res.statusCode).toBe(200);
      expect(mockService.getAgingDashboard).toHaveBeenCalledOnce();
      expect(mockService.getAgingDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.any(Object),
      );

      await app.close();
    });

    it('passes claim_type filter to service', async () => {
      const mockService = {
        getAgingDashboard: vi.fn().mockResolvedValue({
          data: emptyAging(),
          cacheStatus: 'realtime',
        }),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/aging?claim_type=WCB');

      expect(res.statusCode).toBe(200);
      expect(mockService.getAgingDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ claimType: 'WCB' }),
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/wcb
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/wcb', () => {
    it('returns WCB dashboard when physician has WCB config', async () => {
      const mockService = {
        getWcbDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyWcb()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/wcb?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      expect(mockService.getWcbDashboard).toHaveBeenCalledOnce();

      await app.close();
    });

    it('returns 404 when physician has no WCB config', async () => {
      const mockService = {
        getWcbDashboard: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/wcb?period=THIS_MONTH');

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('rejects missing period with 400', async () => {
      const mockService = { getWcbDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/wcb');
      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/ai-coach
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/ai-coach', () => {
    it('returns AI coach dashboard with valid period', async () => {
      const mockService = {
        getAiCoachDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyAiCoach()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/ai-coach?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      expect(mockService.getAiCoachDashboard).toHaveBeenCalledOnce();
      expect(mockService.getAiCoachDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
      );

      await app.close();
    });

    it('rejects invalid period with 400', async () => {
      const mockService = { getAiCoachDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/ai-coach?period=NOPE');
      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/multi-site
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/multi-site', () => {
    it('returns multi-site dashboard when physician has multiple locations', async () => {
      const mockService = {
        getMultiSiteDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyMultiSite()),
        ),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/multi-site?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      expect(mockService.getMultiSiteDashboard).toHaveBeenCalledOnce();

      await app.close();
    });

    it('returns 404 when physician has only one location', async () => {
      const mockService = {
        getMultiSiteDashboard: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/multi-site?period=THIS_MONTH');

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('rejects missing period with 400', async () => {
      const mockService = { getMultiSiteDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/multi-site');
      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/analytics/kpis
  // -----------------------------------------------------------------------

  describe('GET /api/v1/analytics/kpis', () => {
    it('returns KPI cards with valid period', async () => {
      const mockService = {
        getKpis: vi.fn().mockResolvedValue(makeKpiResponse(emptyKpis())),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/kpis?period=THIS_MONTH');

      expect(res.statusCode).toBe(200);
      expect(mockService.getKpis).toHaveBeenCalledOnce();
      expect(mockService.getKpis).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_MONTH' }),
        expect.any(Object),
      );

      await app.close();
    });

    it('rejects missing period with 400', async () => {
      const mockService = { getKpis: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/analytics/kpis');
      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('passes filters to service', async () => {
      const mockService = {
        getKpis: vi.fn().mockResolvedValue(makeKpiResponse(emptyKpis())),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/kpis?period=THIS_YEAR&claim_type=WCB&ba_number=BA999',
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.getKpis).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ period: 'THIS_YEAR' }),
        expect.objectContaining({ claimType: 'WCB', baNumber: 'BA999' }),
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Provider scoping — physician vs delegate
  // -----------------------------------------------------------------------

  describe('Provider scoping from session', () => {
    it('uses physician userId as providerId for physician role', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyRevenue()),
        ),
      };
      const app = await buildTestApp(mockService, {
        userId: PHYSICIAN_ID,
        role: 'physician',
      });

      await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.any(Object),
        expect.any(Object),
      );

      await app.close();
    });

    it('uses delegate physicianProviderId for delegate role', async () => {
      const mockService = {
        getRevenueDashboard: vi.fn().mockResolvedValue(
          makeDashboardResponse(emptyRevenue()),
        ),
      };
      const app = await buildTestApp(mockService, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['ANALYTICS_VIEW'],
          linkageId: 'link-1',
        },
      });

      await authedGet(app, '/api/v1/analytics/revenue?period=THIS_MONTH');

      expect(mockService.getRevenueDashboard).toHaveBeenCalledWith(
        DELEGATE_PHYSICIAN_ID,
        expect.any(Object),
        expect.any(Object),
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // All time period values accepted
  // -----------------------------------------------------------------------

  describe('all valid period values', () => {
    const periods = [
      'THIS_WEEK',
      'THIS_MONTH',
      'LAST_MONTH',
      'THIS_QUARTER',
      'THIS_YEAR',
      'TRAILING_12_MONTHS',
    ];

    for (const period of periods) {
      it(`accepts period=${period}`, async () => {
        const mockService = {
          getRevenueDashboard: vi.fn().mockResolvedValue(
            makeDashboardResponse(emptyRevenue()),
          ),
        };
        const app = await buildTestApp(mockService);

        const res = await authedGet(app, `/api/v1/analytics/revenue?period=${period}`);
        expect(res.statusCode).toBe(200);

        await app.close();
      });
    }
  });

  // -----------------------------------------------------------------------
  // Date range validation
  // -----------------------------------------------------------------------

  describe('date range validation', () => {
    it('rejects end_date before start_date', async () => {
      const mockService = { getRevenueDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2026-02-15&end_date=2026-01-01',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects date range exceeding 2 years', async () => {
      const mockService = { getRevenueDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=2022-01-01&end_date=2026-02-01',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects malformed date strings', async () => {
      const mockService = { getRevenueDashboard: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/analytics/revenue?period=CUSTOM_RANGE&start_date=not-a-date&end_date=2026-02-01',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });
});
