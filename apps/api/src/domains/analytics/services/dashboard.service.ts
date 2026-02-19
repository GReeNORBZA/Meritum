// ============================================================================
// Domain 8: Dashboard Service
// Aggregation, caching, and period comparison logic.
// Resolves period params to date ranges, checks cache, merges with real-time
// current-day data, computes period-over-period deltas.
// ============================================================================

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
  DashboardQueryFilters,
} from '../repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CACHE_STALE_THRESHOLD_MINUTES = 60;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ResolvedPeriod {
  periodStart: string; // YYYY-MM-DD
  periodEnd: string; // YYYY-MM-DD
  comparisonStart: string; // YYYY-MM-DD
  comparisonEnd: string; // YYYY-MM-DD
}

export interface DashboardResponse<T> {
  data: T;
  comparison: T | null;
  delta: Record<string, string> | null;
  period: {
    start: string;
    end: string;
    comparisonStart: string;
    comparisonEnd: string;
  };
  cacheStatus: 'fresh' | 'stale' | 'realtime';
}

export interface KpiCardsResponse {
  data: KpiMetrics;
  period: {
    start: string;
    end: string;
    comparisonStart: string;
    comparisonEnd: string;
  };
  cacheStatus: 'fresh' | 'stale' | 'realtime';
}

interface DashboardDeps {
  cacheRepo: AnalyticsCacheRepository;
  dashboardQueryRepo: DashboardQueryRepository;
  hasWcbConfig: (providerId: string) => Promise<boolean>;
  hasMultipleLocations: (providerId: string) => Promise<boolean>;
  now?: () => Date; // injectable for testing
}

// ---------------------------------------------------------------------------
// Period Resolution
// ---------------------------------------------------------------------------

export function resolvePeriod(
  params: PeriodParams,
  now: Date = new Date(),
): ResolvedPeriod {
  const today = formatDate(now);

  switch (params.period) {
    case TimePeriod.THIS_WEEK: {
      const monday = getMonday(now);
      const mondayStr = formatDate(monday);
      // Comparison: same weekday range of prior week
      const priorMonday = new Date(monday);
      priorMonday.setDate(priorMonday.getDate() - 7);
      const priorEnd = new Date(priorMonday);
      const daysSinceMonday = daysBetween(monday, now);
      priorEnd.setDate(priorEnd.getDate() + daysSinceMonday);
      return {
        periodStart: mondayStr,
        periodEnd: today,
        comparisonStart: formatDate(priorMonday),
        comparisonEnd: formatDate(priorEnd),
      };
    }

    case TimePeriod.THIS_MONTH: {
      const firstOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      const firstStr = formatDate(firstOfMonth);
      // Comparison: 1st to same day of prior month
      const priorFirst = new Date(
        now.getFullYear(),
        now.getMonth() - 1,
        1,
      );
      // Clamp day to last day of prior month to avoid JS Date rollover
      const lastDayPriorMonth = new Date(
        now.getFullYear(),
        now.getMonth(),
        0,
      ).getDate();
      const clampedDay = Math.min(now.getDate(), lastDayPriorMonth);
      const priorSameDay = new Date(
        now.getFullYear(),
        now.getMonth() - 1,
        clampedDay,
      );
      return {
        periodStart: firstStr,
        periodEnd: today,
        comparisonStart: formatDate(priorFirst),
        comparisonEnd: formatDate(priorSameDay),
      };
    }

    case TimePeriod.LAST_MONTH: {
      const lastMonthEnd = new Date(now.getFullYear(), now.getMonth(), 0);
      const lastMonthStart = new Date(
        lastMonthEnd.getFullYear(),
        lastMonthEnd.getMonth(),
        1,
      );
      // Comparison: month before that
      const prevMonthEnd = new Date(
        lastMonthStart.getFullYear(),
        lastMonthStart.getMonth(),
        0,
      );
      const prevMonthStart = new Date(
        prevMonthEnd.getFullYear(),
        prevMonthEnd.getMonth(),
        1,
      );
      return {
        periodStart: formatDate(lastMonthStart),
        periodEnd: formatDate(lastMonthEnd),
        comparisonStart: formatDate(prevMonthStart),
        comparisonEnd: formatDate(prevMonthEnd),
      };
    }

    case TimePeriod.THIS_QUARTER: {
      const quarterMonth = Math.floor(now.getMonth() / 3) * 3;
      const quarterStart = new Date(now.getFullYear(), quarterMonth, 1);
      // Comparison: same quarter prior year
      const priorQuarterStart = new Date(
        now.getFullYear() - 1,
        quarterMonth,
        1,
      );
      const priorQuarterEnd = new Date(
        now.getFullYear() - 1,
        quarterMonth + now.getMonth() - quarterMonth,
        now.getDate(),
      );
      // Clamp comparison end to end of that month if needed
      const lastDayOfCompMonth = new Date(
        priorQuarterEnd.getFullYear(),
        priorQuarterEnd.getMonth() + 1,
        0,
      ).getDate();
      if (priorQuarterEnd.getDate() > lastDayOfCompMonth) {
        priorQuarterEnd.setDate(lastDayOfCompMonth);
      }
      return {
        periodStart: formatDate(quarterStart),
        periodEnd: today,
        comparisonStart: formatDate(priorQuarterStart),
        comparisonEnd: formatDate(priorQuarterEnd),
      };
    }

    case TimePeriod.THIS_YEAR: {
      const yearStart = new Date(now.getFullYear(), 0, 1);
      // Comparison: Jan 1 to same day prior year
      const priorYearStart = new Date(now.getFullYear() - 1, 0, 1);
      // Clamp day to last day of same month in prior year (handles leap year)
      const lastDayOfMonthPriorYear = new Date(
        now.getFullYear() - 1,
        now.getMonth() + 1,
        0,
      ).getDate();
      const clampedDay = Math.min(now.getDate(), lastDayOfMonthPriorYear);
      const priorYearEnd = new Date(
        now.getFullYear() - 1,
        now.getMonth(),
        clampedDay,
      );
      return {
        periodStart: formatDate(yearStart),
        periodEnd: today,
        comparisonStart: formatDate(priorYearStart),
        comparisonEnd: formatDate(priorYearEnd),
      };
    }

    case TimePeriod.CUSTOM_RANGE: {
      const startDate = params.start_date!;
      const endDate = params.end_date!;
      const start = new Date(startDate);
      const end = new Date(endDate);
      const rangeDays = daysBetween(start, end);
      // Comparison: same-length period immediately prior
      const compEnd = new Date(start);
      compEnd.setDate(compEnd.getDate() - 1);
      const compStart = new Date(compEnd);
      compStart.setDate(compStart.getDate() - rangeDays);
      return {
        periodStart: startDate,
        periodEnd: endDate,
        comparisonStart: formatDate(compStart),
        comparisonEnd: formatDate(compEnd),
      };
    }

    case TimePeriod.TRAILING_12_MONTHS: {
      const trailingStart = new Date(now);
      trailingStart.setFullYear(trailingStart.getFullYear() - 1);
      trailingStart.setDate(trailingStart.getDate() + 1);
      // Comparison: 12 months before that
      const compEnd = new Date(trailingStart);
      compEnd.setDate(compEnd.getDate() - 1);
      const compStart = new Date(compEnd);
      compStart.setFullYear(compStart.getFullYear() - 1);
      compStart.setDate(compStart.getDate() + 1);
      return {
        periodStart: formatDate(trailingStart),
        periodEnd: today,
        comparisonStart: formatDate(compStart),
        comparisonEnd: formatDate(compEnd),
      };
    }

    default: {
      const _exhaustive: never = params.period;
      throw new Error(`Unknown period: ${_exhaustive}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createDashboardService(deps: DashboardDeps) {
  const { cacheRepo, dashboardQueryRepo, hasWcbConfig, hasMultipleLocations } =
    deps;
  const getNow = deps.now ?? (() => new Date());

  function isCacheFresh(computedAt: Date): boolean {
    const ageMs = getNow().getTime() - computedAt.getTime();
    return ageMs < CACHE_STALE_THRESHOLD_MINUTES * 60 * 1000;
  }

  return {
    resolvePeriod(params: PeriodParams): ResolvedPeriod {
      return resolvePeriod(params, getNow());
    },

    async getRevenueDashboard(
      providerId: string,
      params: PeriodParams,
      filters?: DashboardQueryFilters,
    ): Promise<DashboardResponse<RevenueMetrics>> {
      const resolved = resolvePeriod(params, getNow());

      // Current period
      const currentData = await dashboardQueryRepo.computeRevenueMetrics(
        providerId,
        resolved.periodStart,
        resolved.periodEnd,
        filters,
      );

      // Comparison period
      const comparisonData = await dashboardQueryRepo.computeRevenueMetrics(
        providerId,
        resolved.comparisonStart,
        resolved.comparisonEnd,
        filters,
      );

      const delta = computeRevenueDelta(currentData, comparisonData);

      return {
        data: currentData,
        comparison: comparisonData,
        delta,
        period: {
          start: resolved.periodStart,
          end: resolved.periodEnd,
          comparisonStart: resolved.comparisonStart,
          comparisonEnd: resolved.comparisonEnd,
        },
        cacheStatus: 'realtime',
      };
    },

    async getRejectionDashboard(
      providerId: string,
      params: PeriodParams,
      filters?: DashboardQueryFilters,
    ): Promise<DashboardResponse<RejectionMetrics>> {
      const resolved = resolvePeriod(params, getNow());

      const currentData = await dashboardQueryRepo.computeRejectionMetrics(
        providerId,
        resolved.periodStart,
        resolved.periodEnd,
        filters,
      );

      const comparisonData = await dashboardQueryRepo.computeRejectionMetrics(
        providerId,
        resolved.comparisonStart,
        resolved.comparisonEnd,
        filters,
      );

      const delta = computeRejectionDelta(currentData, comparisonData);

      return {
        data: currentData,
        comparison: comparisonData,
        delta,
        period: {
          start: resolved.periodStart,
          end: resolved.periodEnd,
          comparisonStart: resolved.comparisonStart,
          comparisonEnd: resolved.comparisonEnd,
        },
        cacheStatus: 'realtime',
      };
    },

    async getAgingDashboard(
      providerId: string,
      filters?: DashboardQueryFilters,
    ): Promise<{ data: AgingMetrics; cacheStatus: 'realtime' }> {
      // Aging is always real-time (point-in-time, no period)
      const data = await dashboardQueryRepo.computeAgingMetrics(
        providerId,
        filters,
      );

      return {
        data,
        cacheStatus: 'realtime',
      };
    },

    async getWcbDashboard(
      providerId: string,
      params: PeriodParams,
      filters?: DashboardQueryFilters,
    ): Promise<DashboardResponse<WcbMetrics> | null> {
      const hasWcb = await hasWcbConfig(providerId);
      if (!hasWcb) {
        return null;
      }

      const resolved = resolvePeriod(params, getNow());

      const currentData = await dashboardQueryRepo.computeWcbMetrics(
        providerId,
        resolved.periodStart,
        resolved.periodEnd,
        filters,
      );

      const comparisonData = await dashboardQueryRepo.computeWcbMetrics(
        providerId,
        resolved.comparisonStart,
        resolved.comparisonEnd,
        filters,
      );

      const delta = computeWcbDelta(currentData, comparisonData);

      return {
        data: currentData,
        comparison: comparisonData,
        delta,
        period: {
          start: resolved.periodStart,
          end: resolved.periodEnd,
          comparisonStart: resolved.comparisonStart,
          comparisonEnd: resolved.comparisonEnd,
        },
        cacheStatus: 'realtime',
      };
    },

    async getAiCoachDashboard(
      providerId: string,
      params: PeriodParams,
    ): Promise<DashboardResponse<AiCoachMetrics>> {
      const resolved = resolvePeriod(params, getNow());

      const currentData = await dashboardQueryRepo.computeAiCoachMetrics(
        providerId,
        resolved.periodStart,
        resolved.periodEnd,
      );

      const comparisonData = await dashboardQueryRepo.computeAiCoachMetrics(
        providerId,
        resolved.comparisonStart,
        resolved.comparisonEnd,
      );

      const delta = computeAiCoachDelta(currentData, comparisonData);

      return {
        data: currentData,
        comparison: comparisonData,
        delta,
        period: {
          start: resolved.periodStart,
          end: resolved.periodEnd,
          comparisonStart: resolved.comparisonStart,
          comparisonEnd: resolved.comparisonEnd,
        },
        cacheStatus: 'realtime',
      };
    },

    async getMultiSiteDashboard(
      providerId: string,
      params: PeriodParams,
      locationIds?: string[],
    ): Promise<DashboardResponse<MultiSiteMetrics> | null> {
      const hasMulti = await hasMultipleLocations(providerId);
      if (!hasMulti) {
        return null;
      }

      const resolved = resolvePeriod(params, getNow());

      const currentData = await dashboardQueryRepo.computeMultiSiteMetrics(
        providerId,
        resolved.periodStart,
        resolved.periodEnd,
        locationIds,
      );

      const comparisonData = await dashboardQueryRepo.computeMultiSiteMetrics(
        providerId,
        resolved.comparisonStart,
        resolved.comparisonEnd,
        locationIds,
      );

      return {
        data: currentData,
        comparison: comparisonData,
        delta: null,
        period: {
          start: resolved.periodStart,
          end: resolved.periodEnd,
          comparisonStart: resolved.comparisonStart,
          comparisonEnd: resolved.comparisonEnd,
        },
        cacheStatus: 'realtime',
      };
    },

    async getKpis(
      providerId: string,
      params: PeriodParams,
      filters?: DashboardQueryFilters,
    ): Promise<KpiCardsResponse> {
      const resolved = resolvePeriod(params, getNow());

      const data = await dashboardQueryRepo.computeKpis(
        providerId,
        resolved.periodStart,
        resolved.periodEnd,
        resolved.comparisonStart,
        resolved.comparisonEnd,
        filters,
      );

      return {
        data,
        period: {
          start: resolved.periodStart,
          end: resolved.periodEnd,
          comparisonStart: resolved.comparisonStart,
          comparisonEnd: resolved.comparisonEnd,
        },
        cacheStatus: 'realtime',
      };
    },
  };
}

export type DashboardService = ReturnType<typeof createDashboardService>;

// ---------------------------------------------------------------------------
// Delta Computation Helpers
// ---------------------------------------------------------------------------

function computeDelta(current: number, prior: number): string {
  if (prior === 0) {
    return current > 0 ? '100.00' : current < 0 ? '-100.00' : '0.00';
  }
  return (((current - prior) / Math.abs(prior)) * 100).toFixed(2);
}

function computeRevenueDelta(
  current: RevenueMetrics,
  prior: RevenueMetrics,
): Record<string, string> {
  return {
    totalRevenue: computeDelta(
      parseFloat(current.totalRevenue),
      parseFloat(prior.totalRevenue),
    ),
    claimCount: computeDelta(current.claimCount, prior.claimCount),
    pendingPipelineValue: computeDelta(
      parseFloat(current.pendingPipeline.value),
      parseFloat(prior.pendingPipeline.value),
    ),
  };
}

function computeRejectionDelta(
  current: RejectionMetrics,
  prior: RejectionMetrics,
): Record<string, string> {
  return {
    rejectionRate: computeDelta(
      parseFloat(current.rejectionRate),
      parseFloat(prior.rejectionRate),
    ),
    totalRejected: computeDelta(current.totalRejected, prior.totalRejected),
  };
}

function computeWcbDelta(
  current: WcbMetrics,
  prior: WcbMetrics,
): Record<string, string> {
  return {
    rejectionRate: computeDelta(
      parseFloat(current.rejectionRate),
      parseFloat(prior.rejectionRate),
    ),
    totalClaims: computeDelta(current.totalClaims, prior.totalClaims),
  };
}

function computeAiCoachDelta(
  current: AiCoachMetrics,
  prior: AiCoachMetrics,
): Record<string, string> {
  return {
    acceptanceRate: computeDelta(
      parseFloat(current.acceptanceRate),
      parseFloat(prior.acceptanceRate),
    ),
    revenueRecovered: computeDelta(
      parseFloat(current.revenueRecovered),
      parseFloat(prior.revenueRecovered),
    ),
    totalAccepted: computeDelta(current.totalAccepted, prior.totalAccepted),
  };
}

// ---------------------------------------------------------------------------
// Date Helpers
// ---------------------------------------------------------------------------

function formatDate(d: Date): string {
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getMonday(d: Date): Date {
  const date = new Date(d);
  const day = date.getDay();
  const diff = day === 0 ? 6 : day - 1; // Sunday = 6 days back, Monday = 0
  date.setDate(date.getDate() - diff);
  return date;
}

function daysBetween(a: Date, b: Date): number {
  const msPerDay = 24 * 60 * 60 * 1000;
  return Math.round((b.getTime() - a.getTime()) / msPerDay);
}
