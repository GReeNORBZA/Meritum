// ============================================================================
// Domain 8: Cache Refresh Service — Unit Tests
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createCacheRefreshService,
  type ClaimState,
} from './cache-refresh.service.js';
import { MetricKey } from '@meritum/shared/constants/analytics.constants.js';
import type { AnalyticsCacheRepository } from '../repos/analytics-cache.repo.js';
import type {
  DashboardQueryRepository,
  RevenueMetrics,
  RejectionMetrics,
  KpiMetrics,
  MultiSiteMetrics,
} from '../repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PROVIDER_1 = '00000000-0000-0000-0000-000000000001';
const PROVIDER_2 = '00000000-0000-0000-0000-000000000002';
const PROVIDER_3 = '00000000-0000-0000-0000-000000000003';

function makeDate(dateStr: string): Date {
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

function emptyKpiMetrics(): KpiMetrics {
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

function emptyMultiSiteMetrics(): MultiSiteMetrics {
  return { locations: [] };
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
    }),
    computeWcbMetrics: vi.fn().mockResolvedValue({
      byFormType: [],
      timingTierDistribution: [],
      feeByTimingTier: [],
      revenueTrend: [],
      rejectionRate: '0.00',
      totalClaims: 0,
      totalRejected: 0,
    }),
    computeAiCoachMetrics: vi.fn().mockResolvedValue({
      acceptanceRate: '0.00',
      totalGenerated: 0,
      totalAccepted: 0,
      totalDismissed: 0,
      revenueRecovered: '0.00',
      byCategory: [],
      topAcceptedRules: [],
      suppressedRules: [],
    }),
    computeMultiSiteMetrics: vi.fn().mockResolvedValue(emptyMultiSiteMetrics()),
    computeKpis: vi.fn().mockResolvedValue(emptyKpiMetrics()),
  };
}

// ============================================================================
// Tests
// ============================================================================

describe('CacheRefreshService', () => {
  const fixedNow = makeDate('2026-02-18');
  let cacheRepo: AnalyticsCacheRepository;
  let dashboardQueryRepo: DashboardQueryRepository;
  let getActiveProviderIds: ReturnType<typeof vi.fn>;
  let service: ReturnType<typeof createCacheRefreshService>;

  beforeEach(() => {
    cacheRepo = createMockCacheRepo();
    dashboardQueryRepo = createMockDashboardQueryRepo();
    getActiveProviderIds = vi.fn().mockResolvedValue([PROVIDER_1]);
    service = createCacheRefreshService({
      cacheRepo,
      dashboardQueryRepo,
      getActiveProviderIds,
      now: () => fixedNow,
    });
  });

  // ========================================================================
  // refreshAllProviders (nightly batch)
  // ========================================================================

  describe('refreshAllProviders', () => {
    it('populates cache for all active providers', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1, PROVIDER_2]);

      const result = await service.refreshAllProviders();

      expect(result.providersProcessed).toBe(2);
      expect(result.totalMetricsRefreshed).toBeGreaterThan(0);
      expect(result.errors).toHaveLength(0);

      // bulkUpsert should be called once per provider
      const bulkUpsertCalls = vi.mocked(cacheRepo.bulkUpsert).mock.calls;
      const providerIdsRefreshed = bulkUpsertCalls.map((call) => call[0]);
      expect(providerIdsRefreshed).toContain(PROVIDER_1);
      expect(providerIdsRefreshed).toContain(PROVIDER_2);
    });

    it('generates trailing 12 months of periods', async () => {
      const result = await service.refreshAllProviders();

      expect(result.totalMetricsRefreshed).toBeGreaterThan(0);

      // 14 metrics x 12 months = 168 entries per provider
      const bulkUpsertCalls = vi.mocked(cacheRepo.bulkUpsert).mock.calls;
      expect(bulkUpsertCalls).toHaveLength(1); // 1 provider
      const entries = bulkUpsertCalls[0][1];
      // Each period should have all 14 cacheable metrics
      expect(entries.length).toBe(14 * 12);
    });

    it('processes providers in batches to limit DB load', async () => {
      // Create 25 providers (should be 3 batches of 10, 10, 5)
      const providerIds = Array.from({ length: 25 }, (_, i) =>
        `00000000-0000-0000-0000-${String(i + 1).padStart(12, '0')}`,
      );
      getActiveProviderIds.mockResolvedValue(providerIds);

      const result = await service.refreshAllProviders();

      expect(result.providersProcessed).toBe(25);
      expect(vi.mocked(cacheRepo.bulkUpsert).mock.calls).toHaveLength(25);
    });

    it('continues processing when one provider fails', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1, PROVIDER_2, PROVIDER_3]);

      // Make the second provider's queries fail
      let callCount = 0;
      vi.mocked(dashboardQueryRepo.computeRevenueMetrics).mockImplementation(
        async (providerId: string) => {
          callCount++;
          if (providerId === PROVIDER_2) {
            throw new Error('DB connection timeout');
          }
          return emptyRevenueMetrics();
        },
      );

      const result = await service.refreshAllProviders();

      // All 3 providers are "processed" (errors are recorded, not thrown)
      expect(result.providersProcessed).toBe(3);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.providerId === PROVIDER_2)).toBe(true);
      // Provider 1 and 3 should contribute metrics
      expect(result.totalMetricsRefreshed).toBeGreaterThan(0);
    });

    it('handles empty provider list', async () => {
      getActiveProviderIds.mockResolvedValue([]);

      const result = await service.refreshAllProviders();

      expect(result.providersProcessed).toBe(0);
      expect(result.totalMetricsRefreshed).toBe(0);
      expect(result.errors).toHaveLength(0);
      expect(cacheRepo.bulkUpsert).not.toHaveBeenCalled();
    });

    it('never cross-contaminates cache entries between providers', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1, PROVIDER_2]);

      await service.refreshAllProviders();

      const bulkUpsertCalls = vi.mocked(cacheRepo.bulkUpsert).mock.calls;
      for (const call of bulkUpsertCalls) {
        const providerId = call[0];
        // bulkUpsert is always called with a single provider ID
        expect(typeof providerId).toBe('string');
        expect(providerId).toMatch(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        );
      }

      // Ensure provider IDs are never mixed in a single bulkUpsert call
      const p1Calls = bulkUpsertCalls.filter((c) => c[0] === PROVIDER_1);
      const p2Calls = bulkUpsertCalls.filter((c) => c[0] === PROVIDER_2);
      expect(p1Calls.length).toBeGreaterThan(0);
      expect(p2Calls.length).toBeGreaterThan(0);
    });
  });

  // ========================================================================
  // refreshProviderMetrics
  // ========================================================================

  describe('refreshProviderMetrics', () => {
    it('refreshes all metrics when metricKeys is omitted', async () => {
      const result = await service.refreshProviderMetrics(PROVIDER_1);

      expect(result.providerId).toBe(PROVIDER_1);
      expect(result.metricsRefreshed).toBe(14 * 12); // 14 metrics x 12 months
      expect(result.errors).toHaveLength(0);
      expect(cacheRepo.bulkUpsert).toHaveBeenCalledWith(
        PROVIDER_1,
        expect.any(Array),
      );
    });

    it('refreshes only specified metrics when metricKeys is provided', async () => {
      const result = await service.refreshProviderMetrics(PROVIDER_1, [
        MetricKey.REVENUE_MONTHLY,
        MetricKey.CLAIMS_PAID,
      ]);

      expect(result.metricsRefreshed).toBe(2 * 12); // 2 metrics x 12 months
      expect(result.errors).toHaveLength(0);

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const metricKeysUsed = [...new Set(entries.map((e) => e.metricKey))];
      expect(metricKeysUsed).toContain(MetricKey.REVENUE_MONTHLY);
      expect(metricKeysUsed).toContain(MetricKey.CLAIMS_PAID);
      expect(metricKeysUsed).not.toContain(MetricKey.REJECTION_RATE_MONTHLY);
    });

    it('stores computed values in cache entries', async () => {
      const revenueData = {
        ...emptyRevenueMetrics(),
        totalRevenue: '5000.00',
        monthlyTrend: [{ month: '2026-02', revenue: '5000.00', count: 50 }],
      };

      vi.mocked(dashboardQueryRepo.computeRevenueMetrics).mockResolvedValue(revenueData);

      await service.refreshProviderMetrics(PROVIDER_1, [MetricKey.REVENUE_MONTHLY]);

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const revenueEntries = entries.filter(
        (e) => e.metricKey === MetricKey.REVENUE_MONTHLY,
      );
      expect(revenueEntries.length).toBeGreaterThan(0);
      // Value should contain revenue data
      expect(revenueEntries[0].value).toEqual({
        totalRevenue: '5000.00',
        monthlyTrend: [{ month: '2026-02', revenue: '5000.00', count: 50 }],
      });
    });

    it('records errors for individual metric failures without stopping', async () => {
      vi.mocked(dashboardQueryRepo.computeRevenueMetrics).mockRejectedValue(
        new Error('Query timeout'),
      );

      const result = await service.refreshProviderMetrics(PROVIDER_1, [
        MetricKey.REVENUE_MONTHLY,
        MetricKey.CLAIMS_REJECTED,
      ]);

      // REVENUE_MONTHLY uses computeRevenueMetrics (fails)
      // CLAIMS_REJECTED uses computeRejectionMetrics (succeeds)
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.includes(MetricKey.REVENUE_MONTHLY))).toBe(true);
      // CLAIMS_REJECTED should still be cached
      expect(result.metricsRefreshed).toBeGreaterThan(0);
    });
  });

  // ========================================================================
  // handleClaimStateChange (incremental)
  // ========================================================================

  describe('handleClaimStateChange', () => {
    it('refreshes revenue metrics when claim is paid', async () => {
      const result = await service.handleClaimStateChange(
        PROVIDER_1,
        'AHCIP',
        'paid',
      );

      expect(result.providerId).toBe(PROVIDER_1);
      expect(result.metricsRefreshed).toBe(7); // paid maps to 7 metrics
      expect(result.errors).toHaveLength(0);

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const metricKeysRefreshed = entries.map((e) => e.metricKey);
      expect(metricKeysRefreshed).toContain(MetricKey.REVENUE_MONTHLY);
      expect(metricKeysRefreshed).toContain(MetricKey.CLAIMS_PAID);
      expect(metricKeysRefreshed).toContain(MetricKey.AVG_FEE_PER_CLAIM);
      expect(metricKeysRefreshed).toContain(MetricKey.REVENUE_BY_BA);
      expect(metricKeysRefreshed).toContain(MetricKey.REVENUE_BY_LOCATION);
      expect(metricKeysRefreshed).toContain(MetricKey.TOP_HSC_CODES);
      expect(metricKeysRefreshed).toContain(MetricKey.PENDING_PIPELINE);
    });

    it('refreshes rejection metrics when claim is rejected', async () => {
      const result = await service.handleClaimStateChange(
        PROVIDER_1,
        'AHCIP',
        'rejected',
      );

      expect(result.metricsRefreshed).toBe(4); // rejected maps to 4 metrics

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const metricKeysRefreshed = entries.map((e) => e.metricKey);
      expect(metricKeysRefreshed).toContain(MetricKey.REJECTION_RATE_MONTHLY);
      expect(metricKeysRefreshed).toContain(MetricKey.REJECTION_BY_CODE);
      expect(metricKeysRefreshed).toContain(MetricKey.REJECTION_BY_HSC);
      expect(metricKeysRefreshed).toContain(MetricKey.CLAIMS_REJECTED);
    });

    it('refreshes submission metrics when claim is submitted', async () => {
      const result = await service.handleClaimStateChange(
        PROVIDER_1,
        'AHCIP',
        'submitted',
      );

      expect(result.metricsRefreshed).toBe(2); // submitted maps to 2 metrics

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const metricKeysRefreshed = entries.map((e) => e.metricKey);
      expect(metricKeysRefreshed).toContain(MetricKey.CLAIMS_SUBMITTED);
      expect(metricKeysRefreshed).toContain(MetricKey.PENDING_PIPELINE);
    });

    it('refreshes adjustment metrics when claim is adjusted', async () => {
      const result = await service.handleClaimStateChange(
        PROVIDER_1,
        'WCB',
        'adjusted',
      );

      expect(result.metricsRefreshed).toBe(2); // adjusted maps to 2 metrics

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const metricKeysRefreshed = entries.map((e) => e.metricKey);
      expect(metricKeysRefreshed).toContain(MetricKey.CLAIMS_ADJUSTED);
      expect(metricKeysRefreshed).toContain(MetricKey.REJECTION_RESOLUTION_FUNNEL);
    });

    it('only refreshes the current month period', async () => {
      await service.handleClaimStateChange(PROVIDER_1, 'AHCIP', 'paid');

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      for (const entry of entries) {
        expect(entry.periodStart).toBe('2026-02-01');
        expect(entry.periodEnd).toBe('2026-02-18');
      }
    });

    it('does not refresh metrics unrelated to the state change', async () => {
      await service.handleClaimStateChange(PROVIDER_1, 'AHCIP', 'paid');

      const entries = vi.mocked(cacheRepo.bulkUpsert).mock.calls[0][1];
      const metricKeysRefreshed = entries.map((e) => e.metricKey);
      // paid should NOT trigger rejection-only metrics
      expect(metricKeysRefreshed).not.toContain(MetricKey.REJECTION_RATE_MONTHLY);
      expect(metricKeysRefreshed).not.toContain(MetricKey.REJECTION_BY_CODE);
      expect(metricKeysRefreshed).not.toContain(MetricKey.CLAIMS_ADJUSTED);
    });
  });

  // ========================================================================
  // isStale
  // ========================================================================

  describe('isStale', () => {
    it('returns true when stale entries exist', async () => {
      vi.mocked(cacheRepo.getStaleEntries).mockResolvedValue([
        {
          cacheId: 'cache-1',
          providerId: PROVIDER_1,
          metricKey: MetricKey.REVENUE_MONTHLY,
          periodStart: '2026-02-01',
          periodEnd: '2026-02-18',
          dimensions: null,
          value: {},
          computedAt: new Date('2026-02-18T00:00:00Z'),
        },
      ]);

      const result = await service.isStale(PROVIDER_1);

      expect(result).toBe(true);
      expect(cacheRepo.getStaleEntries).toHaveBeenCalledWith(PROVIDER_1, 60);
    });

    it('returns false when no stale entries exist', async () => {
      vi.mocked(cacheRepo.getStaleEntries).mockResolvedValue([]);

      const result = await service.isStale(PROVIDER_1);

      expect(result).toBe(false);
    });

    it('uses custom threshold when provided', async () => {
      vi.mocked(cacheRepo.getStaleEntries).mockResolvedValue([]);

      await service.isStale(PROVIDER_1, 30);

      expect(cacheRepo.getStaleEntries).toHaveBeenCalledWith(PROVIDER_1, 30);
    });

    it('uses default 60-minute threshold', async () => {
      await service.isStale(PROVIDER_1);

      expect(cacheRepo.getStaleEntries).toHaveBeenCalledWith(PROVIDER_1, 60);
    });
  });

  // ========================================================================
  // cleanupOldEntries
  // ========================================================================

  describe('cleanupOldEntries', () => {
    it('deletes entries older than 24 months', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1]);
      vi.mocked(cacheRepo.deleteExpiredEntries).mockResolvedValue(5);

      const result = await service.cleanupOldEntries();

      expect(result).toBe(5);
      expect(cacheRepo.deleteExpiredEntries).toHaveBeenCalledWith(
        PROVIDER_1,
        expect.any(Date),
      );

      // Verify the cutoff date is ~24 months ago
      const cutoffArg = vi.mocked(cacheRepo.deleteExpiredEntries).mock.calls[0][1] as Date;
      const expectedCutoff = new Date(fixedNow);
      expectedCutoff.setMonth(expectedCutoff.getMonth() - 24);
      expect(cutoffArg.getFullYear()).toBe(expectedCutoff.getFullYear());
      expect(cutoffArg.getMonth()).toBe(expectedCutoff.getMonth());
    });

    it('cleans up for all active providers', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1, PROVIDER_2]);
      vi.mocked(cacheRepo.deleteExpiredEntries)
        .mockResolvedValueOnce(3)
        .mockResolvedValueOnce(2);

      const result = await service.cleanupOldEntries();

      expect(result).toBe(5); // 3 + 2
      expect(cacheRepo.deleteExpiredEntries).toHaveBeenCalledTimes(2);
    });

    it('returns 0 when no entries to clean up', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1]);
      vi.mocked(cacheRepo.deleteExpiredEntries).mockResolvedValue(0);

      const result = await service.cleanupOldEntries();

      expect(result).toBe(0);
    });
  });

  // ========================================================================
  // Security: provider isolation
  // ========================================================================

  describe('provider isolation', () => {
    it('bulkUpsert always scoped to single provider', async () => {
      getActiveProviderIds.mockResolvedValue([PROVIDER_1, PROVIDER_2]);

      await service.refreshAllProviders();

      const calls = vi.mocked(cacheRepo.bulkUpsert).mock.calls;
      // Each call should have exactly one provider ID
      for (const call of calls) {
        expect(call[0]).toBeDefined();
        expect(typeof call[0]).toBe('string');
      }
      // No call should mix providers
      const p1Entries = calls.filter((c) => c[0] === PROVIDER_1);
      const p2Entries = calls.filter((c) => c[0] === PROVIDER_2);
      expect(p1Entries.length).toBeGreaterThan(0);
      expect(p2Entries.length).toBeGreaterThan(0);
    });

    it('dashboard query repo always called with correct provider', async () => {
      await service.handleClaimStateChange(PROVIDER_1, 'AHCIP', 'paid');

      const revenueCalls = vi.mocked(
        dashboardQueryRepo.computeRevenueMetrics,
      ).mock.calls;
      for (const call of revenueCalls) {
        expect(call[0]).toBe(PROVIDER_1);
      }
    });
  });
});
