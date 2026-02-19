// ============================================================================
// Domain 8: Cache Refresh Service
// Nightly batch, event-driven incremental, stale detection, cleanup.
// ============================================================================

import { MetricKey } from '@meritum/shared/constants/analytics.constants.js';
import type { AnalyticsCacheRepository } from '../repos/analytics-cache.repo.js';
import type { DashboardQueryRepository } from '../repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_STALE_THRESHOLD_MINUTES = 60;
const CACHE_RETENTION_MONTHS = 24;
const TRAILING_MONTHS = 12;
const PROVIDER_BATCH_SIZE = 10;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ClaimState = 'paid' | 'rejected' | 'submitted' | 'adjusted';

interface CacheRefreshDeps {
  cacheRepo: AnalyticsCacheRepository;
  dashboardQueryRepo: DashboardQueryRepository;
  getActiveProviderIds: () => Promise<string[]>;
  now?: () => Date;
}

export interface RefreshResult {
  providerId: string;
  metricsRefreshed: number;
  errors: string[];
}

export interface BatchRefreshResult {
  providersProcessed: number;
  totalMetricsRefreshed: number;
  errors: Array<{ providerId: string; error: string }>;
}

// ---------------------------------------------------------------------------
// Claim state -> affected metric keys mapping
// ---------------------------------------------------------------------------

const CLAIM_STATE_METRIC_MAP: Record<ClaimState, MetricKey[]> = {
  paid: [
    MetricKey.REVENUE_MONTHLY,
    MetricKey.CLAIMS_PAID,
    MetricKey.AVG_FEE_PER_CLAIM,
    MetricKey.REVENUE_BY_BA,
    MetricKey.REVENUE_BY_LOCATION,
    MetricKey.TOP_HSC_CODES,
    MetricKey.PENDING_PIPELINE,
  ],
  rejected: [
    MetricKey.REJECTION_RATE_MONTHLY,
    MetricKey.REJECTION_BY_CODE,
    MetricKey.REJECTION_BY_HSC,
    MetricKey.CLAIMS_REJECTED,
  ],
  submitted: [
    MetricKey.CLAIMS_SUBMITTED,
    MetricKey.PENDING_PIPELINE,
  ],
  adjusted: [
    MetricKey.CLAIMS_ADJUSTED,
    MetricKey.REJECTION_RESOLUTION_FUNNEL,
  ],
};

// All metric keys that can be cached
const ALL_CACHEABLE_METRICS: MetricKey[] = [
  MetricKey.REVENUE_MONTHLY,
  MetricKey.REVENUE_BY_BA,
  MetricKey.REVENUE_BY_LOCATION,
  MetricKey.TOP_HSC_CODES,
  MetricKey.CLAIMS_SUBMITTED,
  MetricKey.CLAIMS_PAID,
  MetricKey.CLAIMS_REJECTED,
  MetricKey.CLAIMS_ADJUSTED,
  MetricKey.REJECTION_RATE_MONTHLY,
  MetricKey.REJECTION_BY_CODE,
  MetricKey.REJECTION_BY_HSC,
  MetricKey.REJECTION_RESOLUTION_FUNNEL,
  MetricKey.PENDING_PIPELINE,
  MetricKey.AVG_FEE_PER_CLAIM,
];

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createCacheRefreshService(deps: CacheRefreshDeps) {
  const { cacheRepo, dashboardQueryRepo, getActiveProviderIds } = deps;
  const getNow = deps.now ?? (() => new Date());

  /**
   * Generate monthly period boundaries for trailing N months from a reference date.
   * Returns array of { periodStart, periodEnd } in YYYY-MM-DD format.
   */
  function generateMonthlyPeriods(
    referenceDate: Date,
    months: number,
  ): Array<{ periodStart: string; periodEnd: string }> {
    const periods: Array<{ periodStart: string; periodEnd: string }> = [];

    for (let i = 0; i < months; i++) {
      const year = referenceDate.getFullYear();
      const month = referenceDate.getMonth() - i;

      const start = new Date(year, month, 1);
      const end = new Date(year, month + 1, 0); // last day of month

      // Don't include future end dates - clamp to today
      const clampedEnd = end > referenceDate ? referenceDate : end;

      periods.push({
        periodStart: formatDate(start),
        periodEnd: formatDate(clampedEnd),
      });
    }

    return periods;
  }

  /**
   * Compute a single metric value for a provider and period.
   * Maps metric_key to the correct dashboard query repo method.
   */
  async function computeMetricValue(
    providerId: string,
    metricKey: MetricKey,
    periodStart: string,
    periodEnd: string,
  ): Promise<unknown> {
    switch (metricKey) {
      case MetricKey.REVENUE_MONTHLY: {
        const result = await dashboardQueryRepo.computeRevenueMetrics(
          providerId, periodStart, periodEnd,
        );
        return { totalRevenue: result.totalRevenue, monthlyTrend: result.monthlyTrend };
      }
      case MetricKey.REVENUE_BY_BA: {
        const result = await dashboardQueryRepo.computeRevenueMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.byBa;
      }
      case MetricKey.REVENUE_BY_LOCATION: {
        const result = await dashboardQueryRepo.computeMultiSiteMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.locations;
      }
      case MetricKey.TOP_HSC_CODES: {
        const result = await dashboardQueryRepo.computeRevenueMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.topHscCodes;
      }
      case MetricKey.CLAIMS_SUBMITTED: {
        const result = await dashboardQueryRepo.computeKpis(
          providerId, periodStart, periodEnd, periodStart, periodEnd,
        );
        return { count: result.claimsSubmitted };
      }
      case MetricKey.CLAIMS_PAID: {
        const result = await dashboardQueryRepo.computeRevenueMetrics(
          providerId, periodStart, periodEnd,
        );
        return { count: result.claimCount };
      }
      case MetricKey.CLAIMS_REJECTED: {
        const result = await dashboardQueryRepo.computeRejectionMetrics(
          providerId, periodStart, periodEnd,
        );
        return { count: result.totalRejected };
      }
      case MetricKey.CLAIMS_ADJUSTED: {
        const result = await dashboardQueryRepo.computeRejectionMetrics(
          providerId, periodStart, periodEnd,
        );
        return { count: result.totalAdjusted };
      }
      case MetricKey.REJECTION_RATE_MONTHLY: {
        const result = await dashboardQueryRepo.computeRejectionMetrics(
          providerId, periodStart, periodEnd,
        );
        return { rate: result.rejectionRate, totalRejected: result.totalRejected };
      }
      case MetricKey.REJECTION_BY_CODE: {
        const result = await dashboardQueryRepo.computeRejectionMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.byExplanatoryCode;
      }
      case MetricKey.REJECTION_BY_HSC: {
        const result = await dashboardQueryRepo.computeRejectionMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.byHscCode;
      }
      case MetricKey.REJECTION_RESOLUTION_FUNNEL: {
        const result = await dashboardQueryRepo.computeRejectionMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.resolutionFunnel;
      }
      case MetricKey.PENDING_PIPELINE: {
        const result = await dashboardQueryRepo.computeRevenueMetrics(
          providerId, periodStart, periodEnd,
        );
        return result.pendingPipeline;
      }
      case MetricKey.AVG_FEE_PER_CLAIM: {
        const result = await dashboardQueryRepo.computeKpis(
          providerId, periodStart, periodEnd, periodStart, periodEnd,
        );
        return { avgFee: result.avgFeePerClaim };
      }
      default:
        return null;
    }
  }

  return {
    /**
     * Nightly batch refresh: iterate all active providers, compute all
     * metric_keys for trailing 12 months, bulkUpsert into cache.
     * Processes providers in batches to limit DB load.
     */
    async refreshAllProviders(): Promise<BatchRefreshResult> {
      const providerIds = await getActiveProviderIds();
      const result: BatchRefreshResult = {
        providersProcessed: 0,
        totalMetricsRefreshed: 0,
        errors: [],
      };

      // Process in batches
      for (let i = 0; i < providerIds.length; i += PROVIDER_BATCH_SIZE) {
        const batch = providerIds.slice(i, i + PROVIDER_BATCH_SIZE);

        for (const providerId of batch) {
          try {
            const refreshResult = await this.refreshProviderMetrics(providerId);
            result.providersProcessed++;
            result.totalMetricsRefreshed += refreshResult.metricsRefreshed;
            if (refreshResult.errors.length > 0) {
              result.errors.push(
                ...refreshResult.errors.map((error) => ({ providerId, error })),
              );
            }
          } catch (error) {
            result.errors.push({
              providerId,
              error: error instanceof Error ? error.message : 'Unknown error',
            });
          }
        }
      }

      return result;
    },

    /**
     * Refresh specific (or all) metrics for a single provider.
     * Computes values for each monthly period in trailing 12 months,
     * then bulk-upserts into cache.
     */
    async refreshProviderMetrics(
      providerId: string,
      metricKeys?: MetricKey[],
    ): Promise<RefreshResult> {
      const keysToRefresh = metricKeys ?? ALL_CACHEABLE_METRICS;
      const periods = generateMonthlyPeriods(getNow(), TRAILING_MONTHS);

      const result: RefreshResult = {
        providerId,
        metricsRefreshed: 0,
        errors: [],
      };

      const entries: Array<{
        metricKey: string;
        periodStart: string;
        periodEnd: string;
        dimensions: Record<string, string> | null;
        value: unknown;
      }> = [];

      for (const period of periods) {
        for (const metricKey of keysToRefresh) {
          try {
            const value = await computeMetricValue(
              providerId,
              metricKey,
              period.periodStart,
              period.periodEnd,
            );

            entries.push({
              metricKey,
              periodStart: period.periodStart,
              periodEnd: period.periodEnd,
              dimensions: null,
              value,
            });
          } catch (error) {
            result.errors.push(
              `${metricKey}/${period.periodStart}: ${error instanceof Error ? error.message : 'Unknown error'}`,
            );
          }
        }
      }

      if (entries.length > 0) {
        await cacheRepo.bulkUpsert(providerId, entries);
        result.metricsRefreshed = entries.length;
      }

      return result;
    },

    /**
     * Handle a claim state change event. Maps the new state to affected
     * metric keys and triggers an incremental refresh for the current
     * month only (the most likely affected period).
     */
    async handleClaimStateChange(
      providerId: string,
      _claimType: string,
      newState: ClaimState,
    ): Promise<RefreshResult> {
      const affectedMetrics = CLAIM_STATE_METRIC_MAP[newState];

      if (!affectedMetrics || affectedMetrics.length === 0) {
        return {
          providerId,
          metricsRefreshed: 0,
          errors: [],
        };
      }

      // Refresh only the current month for affected metrics
      const now = getNow();
      const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const periodStart = formatDate(currentMonthStart);
      const periodEnd = formatDate(now);

      const result: RefreshResult = {
        providerId,
        metricsRefreshed: 0,
        errors: [],
      };

      const entries: Array<{
        metricKey: string;
        periodStart: string;
        periodEnd: string;
        dimensions: Record<string, string> | null;
        value: unknown;
      }> = [];

      for (const metricKey of affectedMetrics) {
        try {
          const value = await computeMetricValue(
            providerId,
            metricKey,
            periodStart,
            periodEnd,
          );

          entries.push({
            metricKey,
            periodStart,
            periodEnd,
            dimensions: null,
            value,
          });
        } catch (error) {
          result.errors.push(
            `${metricKey}: ${error instanceof Error ? error.message : 'Unknown error'}`,
          );
        }
      }

      if (entries.length > 0) {
        await cacheRepo.bulkUpsert(providerId, entries);
        result.metricsRefreshed = entries.length;
      }

      return result;
    },

    /**
     * Check if a provider's cache has any stale entries
     * (older than maxAgeMinutes, default 60).
     */
    async isStale(
      providerId: string,
      maxAgeMinutes: number = DEFAULT_STALE_THRESHOLD_MINUTES,
    ): Promise<boolean> {
      const staleEntries = await cacheRepo.getStaleEntries(
        providerId,
        maxAgeMinutes,
      );
      return staleEntries.length > 0;
    },

    /**
     * Delete cache entries for periods > 24 months old.
     * Hard deletes allowed — cache is not PHI source of truth.
     */
    async cleanupOldEntries(): Promise<number> {
      const providerIds = await getActiveProviderIds();
      const cutoff = new Date(getNow());
      cutoff.setMonth(cutoff.getMonth() - CACHE_RETENTION_MONTHS);

      let totalDeleted = 0;

      for (const providerId of providerIds) {
        const deleted = await cacheRepo.deleteExpiredEntries(
          providerId,
          cutoff,
        );
        totalDeleted += deleted;
      }

      return totalDeleted;
    },
  };
}

export type CacheRefreshService = ReturnType<typeof createCacheRefreshService>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(d: Date): string {
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}
