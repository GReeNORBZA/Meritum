import { eq, and } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  reportSubscriptions,
  type InsertReportSubscription,
  type SelectReportSubscription,
} from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Report Subscriptions Repository
// ---------------------------------------------------------------------------

export function createReportSubscriptionsRepository(db: NodePgDatabase) {
  return {
    /**
     * Create a new report subscription.
     * Enforces unique (provider_id, report_type) — DB constraint handles duplicates.
     */
    async create(
      data: InsertReportSubscription,
    ): Promise<SelectReportSubscription> {
      const rows = await db
        .insert(reportSubscriptions)
        .values(data)
        .returning();

      return rows[0];
    },

    /**
     * Fetch subscription by ID scoped to provider.
     * Returns null if not found or wrong provider (404 pattern).
     */
    async getById(
      subscriptionId: string,
      providerId: string,
    ): Promise<SelectReportSubscription | null> {
      const rows = await db
        .select()
        .from(reportSubscriptions)
        .where(
          and(
            eq(reportSubscriptions.subscriptionId, subscriptionId),
            eq(reportSubscriptions.providerId, providerId),
          ),
        );

      return rows[0] ?? null;
    },

    /**
     * Update subscription fields (frequency, delivery_method, is_active).
     * Sets updated_at to now. Scoped to provider_id (404 pattern).
     */
    async update(
      subscriptionId: string,
      providerId: string,
      data: Partial<
        Pick<
          InsertReportSubscription,
          'frequency' | 'deliveryMethod' | 'isActive'
        >
      >,
    ): Promise<SelectReportSubscription | null> {
      const rows = await db
        .update(reportSubscriptions)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(reportSubscriptions.subscriptionId, subscriptionId),
            eq(reportSubscriptions.providerId, providerId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Hard delete a subscription. Returns true if deleted, false if not found.
     * Scoped to provider_id (404 pattern).
     */
    async delete(
      subscriptionId: string,
      providerId: string,
    ): Promise<boolean> {
      const rows = await db
        .delete(reportSubscriptions)
        .where(
          and(
            eq(reportSubscriptions.subscriptionId, subscriptionId),
            eq(reportSubscriptions.providerId, providerId),
          ),
        )
        .returning();

      return rows.length > 0;
    },

    /**
     * List all subscriptions (active + inactive) for a provider.
     * Scoped to provider_id.
     */
    async listByProvider(
      providerId: string,
    ): Promise<SelectReportSubscription[]> {
      return db
        .select()
        .from(reportSubscriptions)
        .where(eq(reportSubscriptions.providerId, providerId));
    },

    /**
     * Get all active subscriptions matching the given frequency.
     * Used by the system scheduler — returns minimal data needed for generation.
     * Not scoped to a single provider (system-level query).
     */
    async getDueSubscriptions(
      frequency: string,
    ): Promise<SelectReportSubscription[]> {
      return db
        .select()
        .from(reportSubscriptions)
        .where(
          and(
            eq(reportSubscriptions.isActive, true),
            eq(reportSubscriptions.frequency, frequency),
          ),
        );
    },
  };
}

export type ReportSubscriptionsRepository = ReturnType<
  typeof createReportSubscriptionsRepository
>;
