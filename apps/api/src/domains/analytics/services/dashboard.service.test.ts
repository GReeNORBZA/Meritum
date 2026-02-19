// ============================================================================
// Domain 8: Dashboard Service — Unit Tests
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  resolvePeriod,
  createDashboardService,
  type ResolvedPeriod,
} from './dashboard.service.js';
import { TimePeriod } from '@meritum/shared/constants/analytics.constants.js';
import type { PeriodParams } from '@meritum/shared/schemas/validation/analytics.validation.js';
import type { AnalyticsCacheRepository } from '../repos/analytics-cache.repo.js';
import type {
  DashboardQueryRepository,
  RevenueMetrics,
  RejectionMetrics,
  AgingMetrics,
  WcbMetrics,
  AiCoachMetrics,
  MultiSiteMetrics,
  KpiMetrics,
} from '../repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDate(dateStr: string): Date {
  // Parse as local date to avoid timezone issues
  const [y, m, d] = dateStr.split('-').map(Number);
  return new Date(y, m - 1, d);
}

function emptyRevenueMetrics(): RevenueMetrics {
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

function sampleRevenueMetrics(overrides?: Partial<RevenueMetrics>): RevenueMetrics {
  return {
    totalRevenue: '5000.00',
    totalSubmitted: '5500.00',
    claimCount: 50,
    monthlyTrend: [{ month: '2026-01', revenue: '5000.00', count: 50 }],
    byBa: [{ baNumber: 'BA001', revenue: '5000.00', count: 50 }],
    topHscCodes: [{ hscCode: '03.01A', revenue: '2000.00', count: 20 }],
    pendingPipeline: { value: '1500.00', count: 15 },
    ...overrides,
  };
}

function emptyRejectionMetrics(): RejectionMetrics {
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

function sampleRejectionMetrics(overrides?: Partial<RejectionMetrics>): RejectionMetrics {
  return {
    totalAssessed: 80,
    totalRejected: 10,
    totalAdjusted: 5,
    rejectionRate: '10.53',
    byExplanatoryCode: [{ code: 'E01', count: 5 }],
    byHscCode: [{ hscCode: '03.01A', count: 3, rate: '15.00' }],
    resolutionFunnel: { rejected: 10, resubmitted: 3, paidOnResubmission: 2, writtenOff: 1 },
    ...overrides,
  };
}

function emptyWcbMetrics(): WcbMetrics {
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

function sampleWcbMetrics(): WcbMetrics {
  return {
    byFormType: [{ formId: 'C-BI', count: 10, revenue: '3000.00' }],
    timingTierDistribution: [{ tier: 'within_72h', count: 5 }],
    feeByTimingTier: [{ tier: 'within_72h', totalFee: '1500.00', avgFee: '300.00', count: 5 }],
    revenueTrend: [{ month: '2026-01', revenue: '3000.00', count: 10 }],
    rejectionRate: '5.00',
    totalClaims: 20,
    totalRejected: 1,
  };
}

function emptyAiCoachMetrics(): AiCoachMetrics {
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

function sampleAiCoachMetrics(): AiCoachMetrics {
  return {
    acceptanceRate: '60.00',
    totalGenerated: 100,
    totalAccepted: 60,
    totalDismissed: 40,
    revenueRecovered: '2400.00',
    byCategory: [{ category: 'missing_modifier', generated: 50, accepted: 30, rate: '60.00', revenue: '1200.00' }],
    topAcceptedRules: [{ ruleId: 'rule-1', ruleName: 'Add Time Modifier', acceptedCount: 20, revenue: '800.00' }],
    suppressedRules: [],
  };
}

function emptyMultiSiteMetrics(): MultiSiteMetrics {
  return { locations: [] };
}

function sampleMultiSiteMetrics(): MultiSiteMetrics {
  return {
    locations: [
      { locationId: 'loc-1', locationName: 'Main Clinic', revenue: '4000.00', claimCount: 40, rejectionRate: '5.00', rrnpPremium: '1.15' },
      { locationId: 'loc-2', locationName: 'Rural Site', revenue: '1000.00', claimCount: 10, rejectionRate: '10.00', rrnpPremium: '1.25' },
    ],
  };
}

function sampleKpiMetrics(): KpiMetrics {
  return {
    totalRevenue: '5000.00',
    priorRevenue: '4000.00',
    revenueDelta: '25.00',
    claimsSubmitted: 50,
    priorClaimsSubmitted: 40,
    claimsDelta: '25.00',
    rejectionRate: '10.00',
    priorRejectionRate: '12.00',
    rejectionDelta: '-16.67',
    avgFeePerClaim: '100.00',
    priorAvgFee: '100.00',
    avgFeeDelta: '0.00',
    pendingPipeline: '1500.00',
    priorPendingPipeline: '1200.00',
    pipelineDelta: '25.00',
  };
}

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function createMockCacheRepo(): AnalyticsCacheRepository {
  return {
    getMetrics: vi.fn().mockResolvedValue([]),
    upsertMetric: vi.fn().mockResolvedValue({}),
    bulkUpsert: vi.fn().mockResolvedValue([]),
    getStaleEntries: vi.fn().mockResolvedValue([]),
    deleteExpiredEntries: vi.fn().mockResolvedValue(0),
  };
}

function createMockDashboardQueryRepo(): DashboardQueryRepository {
  return {
    computeRevenueMetrics: vi.fn().mockResolvedValue(emptyRevenueMetrics()),
    computeRejectionMetrics: vi.fn().mockResolvedValue(emptyRejectionMetrics()),
    computeAgingMetrics: vi.fn().mockResolvedValue({
      brackets: [],
      approachingDeadline: { count: 0, claims: [] },
      expiredClaims: { count: 0 },
      avgResolutionDays: null,
      staleClaims: { count: 0 },
    } satisfies AgingMetrics),
    computeWcbMetrics: vi.fn().mockResolvedValue(emptyWcbMetrics()),
    computeAiCoachMetrics: vi.fn().mockResolvedValue(emptyAiCoachMetrics()),
    computeMultiSiteMetrics: vi.fn().mockResolvedValue(emptyMultiSiteMetrics()),
    computeKpis: vi.fn().mockResolvedValue(sampleKpiMetrics()),
  };
}

const TEST_PROVIDER_ID = '00000000-0000-0000-0000-000000000001';

// ============================================================================
// Period Resolution Tests
// ============================================================================

describe('resolvePeriod', () => {
  // Fix "now" to Wednesday, 2026-02-18
  const now = makeDate('2026-02-18');

  describe('THIS_WEEK', () => {
    it('resolves Monday to today with prior week comparison', () => {
      const result = resolvePeriod({ period: TimePeriod.THIS_WEEK }, now);
      expect(result.periodStart).toBe('2026-02-16'); // Monday
      expect(result.periodEnd).toBe('2026-02-18'); // Wednesday (today)
      expect(result.comparisonStart).toBe('2026-02-09'); // Prior Monday
      expect(result.comparisonEnd).toBe('2026-02-11'); // Prior Wednesday
    });

    it('handles Monday as current day', () => {
      const monday = makeDate('2026-02-16');
      const result = resolvePeriod({ period: TimePeriod.THIS_WEEK }, monday);
      expect(result.periodStart).toBe('2026-02-16');
      expect(result.periodEnd).toBe('2026-02-16');
      expect(result.comparisonStart).toBe('2026-02-09');
      expect(result.comparisonEnd).toBe('2026-02-09');
    });

    it('handles Sunday', () => {
      const sunday = makeDate('2026-02-22');
      const result = resolvePeriod({ period: TimePeriod.THIS_WEEK }, sunday);
      expect(result.periodStart).toBe('2026-02-16'); // Monday of that week
      expect(result.periodEnd).toBe('2026-02-22');
      // Comparison: prior Mon to prior Sun (same 7-day span)
      expect(result.comparisonStart).toBe('2026-02-09');
      expect(result.comparisonEnd).toBe('2026-02-15');
    });
  });

  describe('THIS_MONTH', () => {
    it('resolves 1st to today with prior month comparison', () => {
      const result = resolvePeriod({ period: TimePeriod.THIS_MONTH }, now);
      expect(result.periodStart).toBe('2026-02-01');
      expect(result.periodEnd).toBe('2026-02-18');
      expect(result.comparisonStart).toBe('2026-01-01');
      expect(result.comparisonEnd).toBe('2026-01-18');
    });

    it('clamps comparison end when prior month is shorter', () => {
      // March 31 -> Feb only has 28 days (non-leap year 2027)
      const march31 = makeDate('2027-03-31');
      const result = resolvePeriod({ period: TimePeriod.THIS_MONTH }, march31);
      expect(result.periodStart).toBe('2027-03-01');
      expect(result.periodEnd).toBe('2027-03-31');
      expect(result.comparisonStart).toBe('2027-02-01');
      expect(result.comparisonEnd).toBe('2027-02-28'); // Clamped
    });
  });

  describe('LAST_MONTH', () => {
    it('resolves full prior month with month-before comparison', () => {
      const result = resolvePeriod({ period: TimePeriod.LAST_MONTH }, now);
      expect(result.periodStart).toBe('2026-01-01');
      expect(result.periodEnd).toBe('2026-01-31');
      expect(result.comparisonStart).toBe('2025-12-01');
      expect(result.comparisonEnd).toBe('2025-12-31');
    });

    it('handles January -> December cross-year', () => {
      const jan15 = makeDate('2026-01-15');
      const result = resolvePeriod({ period: TimePeriod.LAST_MONTH }, jan15);
      expect(result.periodStart).toBe('2025-12-01');
      expect(result.periodEnd).toBe('2025-12-31');
      expect(result.comparisonStart).toBe('2025-11-01');
      expect(result.comparisonEnd).toBe('2025-11-30');
    });
  });

  describe('THIS_QUARTER', () => {
    it('resolves quarter start to today with prior year same quarter', () => {
      const result = resolvePeriod({ period: TimePeriod.THIS_QUARTER }, now);
      expect(result.periodStart).toBe('2026-01-01'); // Q1 start
      expect(result.periodEnd).toBe('2026-02-18');
      expect(result.comparisonStart).toBe('2025-01-01');
      expect(result.comparisonEnd).toBe('2025-02-18');
    });

    it('resolves Q2 correctly', () => {
      const april15 = makeDate('2026-04-15');
      const result = resolvePeriod({ period: TimePeriod.THIS_QUARTER }, april15);
      expect(result.periodStart).toBe('2026-04-01');
      expect(result.periodEnd).toBe('2026-04-15');
      expect(result.comparisonStart).toBe('2025-04-01');
      expect(result.comparisonEnd).toBe('2025-04-15');
    });
  });

  describe('THIS_YEAR', () => {
    it('resolves Jan 1 to today with prior year comparison', () => {
      const result = resolvePeriod({ period: TimePeriod.THIS_YEAR }, now);
      expect(result.periodStart).toBe('2026-01-01');
      expect(result.periodEnd).toBe('2026-02-18');
      expect(result.comparisonStart).toBe('2025-01-01');
      expect(result.comparisonEnd).toBe('2025-02-18');
    });

    it('handles leap year day (Feb 29)', () => {
      // 2028 is a leap year
      const feb29 = makeDate('2028-02-29');
      const result = resolvePeriod({ period: TimePeriod.THIS_YEAR }, feb29);
      expect(result.periodStart).toBe('2028-01-01');
      expect(result.periodEnd).toBe('2028-02-29');
      expect(result.comparisonStart).toBe('2027-01-01');
      // 2027 is not a leap year, Feb 29 doesn't exist -> clamp to Feb 28
      expect(result.comparisonEnd).toBe('2027-02-28');
    });
  });

  describe('CUSTOM_RANGE', () => {
    it('uses provided dates with same-length prior period', () => {
      const result = resolvePeriod({
        period: TimePeriod.CUSTOM_RANGE,
        start_date: '2026-01-10',
        end_date: '2026-01-20',
      }, now);
      expect(result.periodStart).toBe('2026-01-10');
      expect(result.periodEnd).toBe('2026-01-20');
      // 10-day range -> comparison: Dec 31 - Jan 9 (10 days prior)
      expect(result.comparisonStart).toBe('2025-12-30');
      expect(result.comparisonEnd).toBe('2026-01-09');
    });

    it('handles single-day range', () => {
      const result = resolvePeriod({
        period: TimePeriod.CUSTOM_RANGE,
        start_date: '2026-02-15',
        end_date: '2026-02-15',
      }, now);
      expect(result.periodStart).toBe('2026-02-15');
      expect(result.periodEnd).toBe('2026-02-15');
      // 0-day range -> comparison: same day prior (Feb 14 single day)
      expect(result.comparisonStart).toBe('2026-02-14');
      expect(result.comparisonEnd).toBe('2026-02-14');
    });
  });

  describe('TRAILING_12_MONTHS', () => {
    it('resolves 12 months back with 12 months before that', () => {
      const result = resolvePeriod({ period: TimePeriod.TRAILING_12_MONTHS }, now);
      expect(result.periodStart).toBe('2025-02-19');
      expect(result.periodEnd).toBe('2026-02-18');
      expect(result.comparisonStart).toBe('2024-02-19');
      expect(result.comparisonEnd).toBe('2025-02-18');
    });
  });
});

// ============================================================================
// Dashboard Service Tests
// ============================================================================

describe('createDashboardService', () => {
  const now = makeDate('2026-02-18');
  let cacheRepo: AnalyticsCacheRepository;
  let dashboardQueryRepo: DashboardQueryRepository;
  let service: ReturnType<typeof createDashboardService>;

  beforeEach(() => {
    cacheRepo = createMockCacheRepo();
    dashboardQueryRepo = createMockDashboardQueryRepo();
    service = createDashboardService({
      cacheRepo,
      dashboardQueryRepo,
      hasWcbConfig: vi.fn().mockResolvedValue(true),
      hasMultipleLocations: vi.fn().mockResolvedValue(true),
      now: () => now,
    });
  });

  describe('getRevenueDashboard', () => {
    it('returns current and comparison data with deltas', async () => {
      const currentMetrics = sampleRevenueMetrics({ totalRevenue: '6000.00', claimCount: 60 });
      const priorMetrics = sampleRevenueMetrics({ totalRevenue: '4000.00', claimCount: 40 });

      vi.mocked(dashboardQueryRepo.computeRevenueMetrics)
        .mockResolvedValueOnce(currentMetrics)
        .mockResolvedValueOnce(priorMetrics);

      const result = await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.data).toEqual(currentMetrics);
      expect(result.comparison).toEqual(priorMetrics);
      expect(result.delta).toBeDefined();
      expect(result.delta!.totalRevenue).toBe('50.00'); // (6000-4000)/4000 * 100
      expect(result.delta!.claimCount).toBe('50.00'); // (60-40)/40 * 100
      expect(result.cacheStatus).toBe('realtime');
    });

    it('passes filters through to repo', async () => {
      await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
        { claimType: 'AHCIP', baNumber: 'BA001' },
      );

      expect(dashboardQueryRepo.computeRevenueMetrics).toHaveBeenCalledWith(
        TEST_PROVIDER_ID,
        '2026-02-01',
        '2026-02-18',
        { claimType: 'AHCIP', baNumber: 'BA001' },
      );
    });

    it('computes deltas with zero prior values', async () => {
      const currentMetrics = sampleRevenueMetrics({ totalRevenue: '1000.00', claimCount: 10 });

      vi.mocked(dashboardQueryRepo.computeRevenueMetrics)
        .mockResolvedValueOnce(currentMetrics)
        .mockResolvedValueOnce(emptyRevenueMetrics());

      const result = await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.delta!.totalRevenue).toBe('100.00'); // No prior -> 100%
      expect(result.delta!.claimCount).toBe('100.00');
    });

    it('computes deltas when both periods are zero', async () => {
      vi.mocked(dashboardQueryRepo.computeRevenueMetrics)
        .mockResolvedValueOnce(emptyRevenueMetrics())
        .mockResolvedValueOnce(emptyRevenueMetrics());

      const result = await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.delta!.totalRevenue).toBe('0.00');
      expect(result.delta!.claimCount).toBe('0.00');
    });

    it('includes resolved period dates in response', async () => {
      const result = await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.period.start).toBe('2026-02-01');
      expect(result.period.end).toBe('2026-02-18');
      expect(result.period.comparisonStart).toBe('2026-01-01');
      expect(result.period.comparisonEnd).toBe('2026-01-18');
    });
  });

  describe('getRejectionDashboard', () => {
    it('returns rejection metrics with comparison and deltas', async () => {
      const currentMetrics = sampleRejectionMetrics({ rejectionRate: '8.00', totalRejected: 8 });
      const priorMetrics = sampleRejectionMetrics({ rejectionRate: '12.00', totalRejected: 12 });

      vi.mocked(dashboardQueryRepo.computeRejectionMetrics)
        .mockResolvedValueOnce(currentMetrics)
        .mockResolvedValueOnce(priorMetrics);

      const result = await service.getRejectionDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.data).toEqual(currentMetrics);
      expect(result.comparison).toEqual(priorMetrics);
      // Rejection rate went down: (8-12)/12 * 100 = -33.33
      expect(result.delta!.rejectionRate).toBe('-33.33');
      expect(result.delta!.totalRejected).toBe('-33.33');
    });
  });

  describe('getAgingDashboard', () => {
    it('returns aging metrics always as realtime', async () => {
      const agingData: AgingMetrics = {
        brackets: [{ label: '0-30 days', minDays: 0, maxDays: 30, count: 5, value: '500.00' }],
        approachingDeadline: { count: 2, claims: [] },
        expiredClaims: { count: 1 },
        avgResolutionDays: 14,
        staleClaims: { count: 3 },
      };

      vi.mocked(dashboardQueryRepo.computeAgingMetrics).mockResolvedValue(agingData);

      const result = await service.getAgingDashboard(TEST_PROVIDER_ID);

      expect(result.data).toEqual(agingData);
      expect(result.cacheStatus).toBe('realtime');
    });

    it('passes filters to repo', async () => {
      await service.getAgingDashboard(TEST_PROVIDER_ID, { claimType: 'AHCIP' });

      expect(dashboardQueryRepo.computeAgingMetrics).toHaveBeenCalledWith(
        TEST_PROVIDER_ID,
        { claimType: 'AHCIP' },
      );
    });
  });

  describe('getWcbDashboard', () => {
    it('returns null for physicians without WCB config', async () => {
      const noWcbService = createDashboardService({
        cacheRepo,
        dashboardQueryRepo,
        hasWcbConfig: vi.fn().mockResolvedValue(false),
        hasMultipleLocations: vi.fn().mockResolvedValue(false),
        now: () => now,
      });

      const result = await noWcbService.getWcbDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result).toBeNull();
      expect(dashboardQueryRepo.computeWcbMetrics).not.toHaveBeenCalled();
    });

    it('returns WCB metrics with comparison for WCB physicians', async () => {
      const currentWcb = sampleWcbMetrics();
      const priorWcb = { ...sampleWcbMetrics(), totalClaims: 10, rejectionRate: '10.00' };

      vi.mocked(dashboardQueryRepo.computeWcbMetrics)
        .mockResolvedValueOnce(currentWcb)
        .mockResolvedValueOnce(priorWcb);

      const result = await service.getWcbDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result).not.toBeNull();
      expect(result!.data).toEqual(currentWcb);
      expect(result!.comparison).toEqual(priorWcb);
      expect(result!.delta!.totalClaims).toBe('100.00'); // 20 vs 10
    });
  });

  describe('getAiCoachDashboard', () => {
    it('returns AI Coach metrics with comparison and deltas', async () => {
      const currentAi = sampleAiCoachMetrics();
      const priorAi = { ...sampleAiCoachMetrics(), acceptanceRate: '50.00', totalAccepted: 50, revenueRecovered: '2000.00' };

      vi.mocked(dashboardQueryRepo.computeAiCoachMetrics)
        .mockResolvedValueOnce(currentAi)
        .mockResolvedValueOnce(priorAi);

      const result = await service.getAiCoachDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.data).toEqual(currentAi);
      expect(result.comparison).toEqual(priorAi);
      // acceptanceRate: (60-50)/50*100 = 20.00
      expect(result.delta!.acceptanceRate).toBe('20.00');
      // revenueRecovered: (2400-2000)/2000*100 = 20.00
      expect(result.delta!.revenueRecovered).toBe('20.00');
      // totalAccepted: (60-50)/50*100 = 20.00
      expect(result.delta!.totalAccepted).toBe('20.00');
    });
  });

  describe('getMultiSiteDashboard', () => {
    it('returns null for physicians with single location', async () => {
      const singleSiteService = createDashboardService({
        cacheRepo,
        dashboardQueryRepo,
        hasWcbConfig: vi.fn().mockResolvedValue(true),
        hasMultipleLocations: vi.fn().mockResolvedValue(false),
        now: () => now,
      });

      const result = await singleSiteService.getMultiSiteDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result).toBeNull();
      expect(dashboardQueryRepo.computeMultiSiteMetrics).not.toHaveBeenCalled();
    });

    it('returns multi-site metrics with comparison for multi-location physicians', async () => {
      const currentSites = sampleMultiSiteMetrics();
      const priorSites = { locations: [{ locationId: 'loc-1', locationName: 'Main Clinic', revenue: '3000.00', claimCount: 30, rejectionRate: '8.00', rrnpPremium: '1.15' }] };

      vi.mocked(dashboardQueryRepo.computeMultiSiteMetrics)
        .mockResolvedValueOnce(currentSites)
        .mockResolvedValueOnce(priorSites);

      const result = await service.getMultiSiteDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result).not.toBeNull();
      expect(result!.data).toEqual(currentSites);
      expect(result!.comparison).toEqual(priorSites);
      // Multi-site doesn't compute deltas (too complex with variable locations)
      expect(result!.delta).toBeNull();
    });

    it('passes locationIds filter through to repo', async () => {
      await service.getMultiSiteDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
        ['loc-1', 'loc-2'],
      );

      expect(dashboardQueryRepo.computeMultiSiteMetrics).toHaveBeenCalledWith(
        TEST_PROVIDER_ID,
        '2026-02-01',
        '2026-02-18',
        ['loc-1', 'loc-2'],
      );
    });
  });

  describe('getKpis', () => {
    it('returns KPI metrics with resolved period dates', async () => {
      const kpis = sampleKpiMetrics();
      vi.mocked(dashboardQueryRepo.computeKpis).mockResolvedValue(kpis);

      const result = await service.getKpis(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.data).toEqual(kpis);
      expect(result.period.start).toBe('2026-02-01');
      expect(result.period.end).toBe('2026-02-18');
      expect(result.cacheStatus).toBe('realtime');
    });

    it('passes resolved comparison dates to computeKpis', async () => {
      await service.getKpis(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
        { claimType: 'AHCIP' },
      );

      expect(dashboardQueryRepo.computeKpis).toHaveBeenCalledWith(
        TEST_PROVIDER_ID,
        '2026-02-01',
        '2026-02-18',
        '2026-01-01',
        '2026-01-18',
        { claimType: 'AHCIP' },
      );
    });
  });

  describe('delta calculation edge cases', () => {
    it('handles negative delta (decrease in revenue)', async () => {
      const currentMetrics = sampleRevenueMetrics({ totalRevenue: '3000.00', claimCount: 30 });
      const priorMetrics = sampleRevenueMetrics({ totalRevenue: '5000.00', claimCount: 50 });

      vi.mocked(dashboardQueryRepo.computeRevenueMetrics)
        .mockResolvedValueOnce(currentMetrics)
        .mockResolvedValueOnce(priorMetrics);

      const result = await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      expect(result.delta!.totalRevenue).toBe('-40.00'); // (3000-5000)/5000*100
      expect(result.delta!.claimCount).toBe('-40.00');
    });

    it('handles zero current with non-zero prior (complete dropoff)', async () => {
      const priorMetrics = sampleRevenueMetrics({ totalRevenue: '5000.00', claimCount: 50 });

      vi.mocked(dashboardQueryRepo.computeRevenueMetrics)
        .mockResolvedValueOnce(emptyRevenueMetrics())
        .mockResolvedValueOnce(priorMetrics);

      const result = await service.getRevenueDashboard(
        TEST_PROVIDER_ID,
        { period: TimePeriod.THIS_MONTH },
      );

      // (0 - 5000) / |5000| * 100 = -100.00
      expect(result.delta!.totalRevenue).toBe('-100.00');
    });
  });

  describe('provider scoping', () => {
    it('always passes providerId to dashboard query repo', async () => {
      await service.getRevenueDashboard(TEST_PROVIDER_ID, { period: TimePeriod.THIS_MONTH });

      const calls = vi.mocked(dashboardQueryRepo.computeRevenueMetrics).mock.calls;
      expect(calls).toHaveLength(2); // current + comparison
      expect(calls[0][0]).toBe(TEST_PROVIDER_ID);
      expect(calls[1][0]).toBe(TEST_PROVIDER_ID);
    });

    it('passes providerId to KPI repo calls', async () => {
      await service.getKpis(TEST_PROVIDER_ID, { period: TimePeriod.THIS_MONTH });

      expect(dashboardQueryRepo.computeKpis).toHaveBeenCalledWith(
        TEST_PROVIDER_ID,
        expect.any(String),
        expect.any(String),
        expect.any(String),
        expect.any(String),
        undefined,
      );
    });
  });
});
