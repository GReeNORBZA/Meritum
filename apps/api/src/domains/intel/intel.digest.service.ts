// ============================================================================
// Domain 7: Intelligence Engine — Periodic Summary Digest (MVPADD-001 §5.1.2)
// ============================================================================
//
// Scheduled job that aggregates suggestion events per provider for a billing
// period and produces a weekly digest summary. Emits INTEL_WEEKLY_DIGEST
// notification event for downstream delivery (email, in-app notification).

import { SuggestionEventType, SuggestionCategory, IntelAuditAction } from '@meritum/shared/constants/intelligence.constants.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DigestDeps {
  /** Get all suggestion events for a provider within a date range */
  getSuggestionEventsForPeriod: (
    providerId: string,
    startDate: Date,
    endDate: Date,
  ) => Promise<DigestEventRow[]>;

  /** List all active provider IDs */
  getActiveProviderIds: () => Promise<string[]>;

  /** Emit a notification event */
  emitNotification: (event: {
    type: string;
    providerId: string;
    payload: Record<string, unknown>;
  }) => Promise<void>;

  /** Audit log callback */
  auditLog?: (entry: {
    action: string;
    providerId: string;
    details: Record<string, unknown>;
  }) => Promise<void>;
}

export interface DigestEventRow {
  eventId: string;
  claimId: string;
  suggestionId: string;
  ruleId: string | null;
  providerId: string;
  eventType: string;
  tier: number;
  category: string;
  revenueImpact: string | null;
  createdAt: Date;
}

export interface CategoryBreakdown {
  category: string;
  generated: number;
  accepted: number;
  dismissed: number;
  revenueImpact: number;
}

export interface ProviderDigest {
  providerId: string;
  periodStart: string;
  periodEnd: string;
  totalGenerated: number;
  totalAccepted: number;
  totalDismissed: number;
  acceptanceRate: number;
  estimatedRevenueImpact: number;
  topCategories: CategoryBreakdown[];
}

// ---------------------------------------------------------------------------
// Digest Computation
// ---------------------------------------------------------------------------

/**
 * Compute a digest summary from raw suggestion events for a single provider.
 */
export function computeProviderDigest(
  providerId: string,
  events: DigestEventRow[],
  periodStart: Date,
  periodEnd: Date,
): ProviderDigest {
  let totalGenerated = 0;
  let totalAccepted = 0;
  let totalDismissed = 0;
  let estimatedRevenueImpact = 0;

  // Category-level aggregation
  const categoryMap = new Map<string, CategoryBreakdown>();

  for (const event of events) {
    const cat = event.category;
    if (!categoryMap.has(cat)) {
      categoryMap.set(cat, {
        category: cat,
        generated: 0,
        accepted: 0,
        dismissed: 0,
        revenueImpact: 0,
      });
    }
    const breakdown = categoryMap.get(cat)!;
    const impact = event.revenueImpact ? parseFloat(event.revenueImpact) : 0;

    switch (event.eventType) {
      case SuggestionEventType.GENERATED:
        totalGenerated++;
        breakdown.generated++;
        break;
      case SuggestionEventType.ACCEPTED:
        totalAccepted++;
        breakdown.accepted++;
        // Revenue impact is counted on acceptance
        if (!isNaN(impact)) {
          estimatedRevenueImpact += impact;
          breakdown.revenueImpact += impact;
        }
        break;
      case SuggestionEventType.DISMISSED:
        totalDismissed++;
        breakdown.dismissed++;
        break;
    }
  }

  // Top categories sorted by generated count descending, limit to 5
  const topCategories = [...categoryMap.values()]
    .sort((a, b) => b.generated - a.generated)
    .slice(0, 5);

  const acceptanceRate =
    totalGenerated > 0 ? totalAccepted / totalGenerated : 0;

  return {
    providerId,
    periodStart: periodStart.toISOString().split('T')[0],
    periodEnd: periodEnd.toISOString().split('T')[0],
    totalGenerated,
    totalAccepted,
    totalDismissed,
    acceptanceRate: Math.round(acceptanceRate * 10000) / 10000,
    estimatedRevenueImpact: Math.round(estimatedRevenueImpact * 100) / 100,
    topCategories,
  };
}

// ---------------------------------------------------------------------------
// Digest Job Runner
// ---------------------------------------------------------------------------

/**
 * Generate weekly digest for all active providers.
 *
 * Called by a scheduled job (cron). For each provider:
 * 1. Fetch suggestion events for the billing period.
 * 2. Compute digest summary.
 * 3. Emit INTEL_WEEKLY_DIGEST notification event.
 * 4. Log audit event.
 *
 * @param periodStart - Start of the digest period (inclusive).
 * @param periodEnd - End of the digest period (exclusive).
 * @returns Array of per-provider digest summaries.
 */
export async function generateWeeklyDigests(
  deps: DigestDeps,
  periodStart: Date,
  periodEnd: Date,
): Promise<ProviderDigest[]> {
  const providerIds = await deps.getActiveProviderIds();
  const digests: ProviderDigest[] = [];

  for (const providerId of providerIds) {
    const events = await deps.getSuggestionEventsForPeriod(
      providerId,
      periodStart,
      periodEnd,
    );

    // Skip providers with no activity
    if (events.length === 0) continue;

    const digest = computeProviderDigest(
      providerId,
      events,
      periodStart,
      periodEnd,
    );

    // Emit notification
    await deps.emitNotification({
      type: 'INTEL_WEEKLY_DIGEST',
      providerId,
      payload: {
        periodStart: digest.periodStart,
        periodEnd: digest.periodEnd,
        totalGenerated: digest.totalGenerated,
        totalAccepted: digest.totalAccepted,
        acceptanceRate: digest.acceptanceRate,
        estimatedRevenueImpact: digest.estimatedRevenueImpact,
        topCategories: digest.topCategories,
      },
    });

    // Audit
    if (deps.auditLog) {
      await deps.auditLog({
        action: IntelAuditAction.CLAIM_ANALYSED,
        providerId,
        details: {
          digestType: 'weekly',
          periodStart: digest.periodStart,
          periodEnd: digest.periodEnd,
          totalGenerated: digest.totalGenerated,
          totalAccepted: digest.totalAccepted,
          estimatedRevenueImpact: digest.estimatedRevenueImpact,
        },
      });
    }

    digests.push(digest);
  }

  return digests;
}

/**
 * Convenience: compute the default weekly period (last 7 days ending today).
 */
export function getDefaultWeeklyPeriod(): { start: Date; end: Date } {
  const end = new Date();
  end.setHours(0, 0, 0, 0);
  const start = new Date(end);
  start.setDate(start.getDate() - 7);
  return { start, end };
}
