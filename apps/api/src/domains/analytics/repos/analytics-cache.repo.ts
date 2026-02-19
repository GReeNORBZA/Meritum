import { eq, and, sql, inArray, lt } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  analyticsCache,
  type SelectAnalyticsCache,
} from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Analytics Cache Repository
// ---------------------------------------------------------------------------

export function createAnalyticsCacheRepository(db: NodePgDatabase) {
  return {
    /**
     * Fetch cached metrics for a provider.
     * Filter by metric_key IN metricKeys. Optionally filter by
     * dimensions JSONB containment (@>).
     * Scoped to provider_id — never returns another provider's data.
     */
    async getMetrics(
      providerId: string,
      metricKeys: string[],
      periodStart: string,
      periodEnd: string,
      dimensions?: Record<string, string>,
    ): Promise<SelectAnalyticsCache[]> {
      if (metricKeys.length === 0) {
        return [];
      }

      const conditions = [
        eq(analyticsCache.providerId, providerId),
        inArray(analyticsCache.metricKey, metricKeys),
        eq(analyticsCache.periodStart, periodStart),
        eq(analyticsCache.periodEnd, periodEnd),
      ];

      if (dimensions) {
        conditions.push(
          sql`${analyticsCache.dimensions} @> ${JSON.stringify(dimensions)}::jsonb`,
        );
      }

      const rows = await db
        .select()
        .from(analyticsCache)
        .where(and(...conditions));

      return rows;
    },

    /**
     * Insert or update a single cached metric.
     * Upsert target: (provider_id, metric_key, period_start, period_end, dimensions).
     * Updates computed_at to now() on conflict.
     * Scoped to provider_id.
     */
    async upsertMetric(
      providerId: string,
      metricKey: string,
      periodStart: string,
      periodEnd: string,
      dimensions: Record<string, string> | null,
      value: unknown,
    ): Promise<SelectAnalyticsCache> {
      const rows = await db
        .insert(analyticsCache)
        .values({
          providerId,
          metricKey,
          periodStart,
          periodEnd,
          dimensions,
          value,
          computedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: [
            analyticsCache.providerId,
            analyticsCache.metricKey,
            analyticsCache.periodStart,
            analyticsCache.periodEnd,
            analyticsCache.dimensions,
          ],
          set: {
            value,
            computedAt: new Date(),
          },
        })
        .returning();

      return rows[0];
    },

    /**
     * Batch upsert for nightly refresh.
     * All entries MUST belong to the same provider_id.
     * Uses Drizzle's onConflictDoUpdate. Updates computed_at on conflict.
     */
    async bulkUpsert(
      providerId: string,
      entries: Array<{
        metricKey: string;
        periodStart: string;
        periodEnd: string;
        dimensions: Record<string, string> | null;
        value: unknown;
      }>,
    ): Promise<SelectAnalyticsCache[]> {
      if (entries.length === 0) {
        return [];
      }

      const now = new Date();
      const values = entries.map((entry) => ({
        providerId,
        metricKey: entry.metricKey,
        periodStart: entry.periodStart,
        periodEnd: entry.periodEnd,
        dimensions: entry.dimensions,
        value: entry.value,
        computedAt: now,
      }));

      const rows = await db
        .insert(analyticsCache)
        .values(values)
        .onConflictDoUpdate({
          target: [
            analyticsCache.providerId,
            analyticsCache.metricKey,
            analyticsCache.periodStart,
            analyticsCache.periodEnd,
            analyticsCache.dimensions,
          ],
          set: {
            value: sql`excluded.value`,
            computedAt: sql`excluded.computed_at`,
          },
        })
        .returning();

      return rows;
    },

    /**
     * Return metrics where computed_at < now() - maxAgeMinutes.
     * Used to detect when cache needs refresh on dashboard open.
     * Scoped to provider_id.
     */
    async getStaleEntries(
      providerId: string,
      maxAgeMinutes: number,
    ): Promise<SelectAnalyticsCache[]> {
      const threshold = sql`NOW() - (${maxAgeMinutes} * INTERVAL '1 minute')`;

      const rows = await db
        .select()
        .from(analyticsCache)
        .where(
          and(
            eq(analyticsCache.providerId, providerId),
            lt(analyticsCache.computedAt, threshold),
          ),
        );

      return rows;
    },

    /**
     * Cleanup entries for periods no longer relevant (>24 months old).
     * Hard deletes allowed — analytics cache is not PHI source of truth.
     * Scoped to provider_id.
     */
    async deleteExpiredEntries(
      providerId: string,
      olderThan: Date,
    ): Promise<number> {
      const result = await db
        .delete(analyticsCache)
        .where(
          and(
            eq(analyticsCache.providerId, providerId),
            lt(analyticsCache.periodEnd, olderThan.toISOString().split('T')[0]),
          ),
        )
        .returning();

      return result.length;
    },
  };
}

export type AnalyticsCacheRepository = ReturnType<
  typeof createAnalyticsCacheRepository
>;
