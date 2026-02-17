import { eq, and, lte, ne, sql, desc, asc, count, sum, max } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  subscriptions,
  paymentHistory,
  statusComponents,
  statusIncidents,
  incidentUpdates,
  type InsertSubscription,
  type SelectSubscription,
  type InsertPaymentHistory,
  type SelectPaymentHistory,
  type SelectStatusComponent,
  type SelectStatusIncident,
  type SelectIncidentUpdate,
} from '@meritum/shared/schemas/db/platform.schema.js';
import {
  DUNNING_SUSPENSION_DAY,
  DUNNING_CANCELLATION_DAY,
} from '@meritum/shared/constants/platform.constants.js';

// ---------------------------------------------------------------------------
// Subscription Repository
// ---------------------------------------------------------------------------

export function createSubscriptionRepository(db: NodePgDatabase) {
  return {
    async createSubscription(
      data: InsertSubscription,
    ): Promise<SelectSubscription> {
      const rows = await db
        .insert(subscriptions)
        .values(data)
        .returning();
      return rows[0];
    },

    async findSubscriptionByProviderId(
      providerId: string,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.providerId, providerId))
        .limit(1);
      return rows[0];
    },

    async findSubscriptionByStripeCustomerId(
      stripeCustomerId: string,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.stripeCustomerId, stripeCustomerId))
        .limit(1);
      return rows[0];
    },

    async findSubscriptionByStripeSubscriptionId(
      stripeSubscriptionId: string,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.stripeSubscriptionId, stripeSubscriptionId))
        .limit(1);
      return rows[0];
    },

    async updateSubscriptionStatus(
      subscriptionId: string,
      status: string,
      metadata?: {
        suspended_at?: Date | null;
        cancelled_at?: Date | null;
        deletion_scheduled_at?: Date | null;
      },
    ): Promise<SelectSubscription | undefined> {
      const setClauses: Record<string, unknown> = {
        status,
        updatedAt: new Date(),
      };
      if (metadata?.suspended_at !== undefined) {
        setClauses.suspendedAt = metadata.suspended_at;
      }
      if (metadata?.cancelled_at !== undefined) {
        setClauses.cancelledAt = metadata.cancelled_at;
      }
      if (metadata?.deletion_scheduled_at !== undefined) {
        setClauses.deletionScheduledAt = metadata.deletion_scheduled_at;
      }

      const rows = await db
        .update(subscriptions)
        .set(setClauses)
        .where(eq(subscriptions.subscriptionId, subscriptionId))
        .returning();
      return rows[0];
    },

    async updateSubscriptionPeriod(
      subscriptionId: string,
      periodStart: Date,
      periodEnd: Date,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .update(subscriptions)
        .set({
          currentPeriodStart: periodStart,
          currentPeriodEnd: periodEnd,
          updatedAt: new Date(),
        })
        .where(eq(subscriptions.subscriptionId, subscriptionId))
        .returning();
      return rows[0];
    },

    async updateSubscriptionPlan(
      subscriptionId: string,
      plan: string,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .update(subscriptions)
        .set({
          plan,
          updatedAt: new Date(),
        })
        .where(eq(subscriptions.subscriptionId, subscriptionId))
        .returning();
      return rows[0];
    },

    async incrementFailedPaymentCount(
      subscriptionId: string,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .update(subscriptions)
        .set({
          failedPaymentCount: sql`${subscriptions.failedPaymentCount} + 1`,
          updatedAt: new Date(),
        })
        .where(eq(subscriptions.subscriptionId, subscriptionId))
        .returning();
      return rows[0];
    },

    async resetFailedPaymentCount(
      subscriptionId: string,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .update(subscriptions)
        .set({
          failedPaymentCount: 0,
          updatedAt: new Date(),
        })
        .where(eq(subscriptions.subscriptionId, subscriptionId))
        .returning();
      return rows[0];
    },

    async findPastDueSubscriptions(): Promise<SelectSubscription[]> {
      return db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.status, 'PAST_DUE'));
    },

    async findSubscriptionsDueForSuspension(): Promise<SelectSubscription[]> {
      const suspensionCutoff = new Date(
        Date.now() - DUNNING_SUSPENSION_DAY * 24 * 60 * 60 * 1000,
      );
      return db
        .select()
        .from(subscriptions)
        .where(
          and(
            eq(subscriptions.status, 'PAST_DUE'),
            lte(subscriptions.updatedAt, suspensionCutoff),
          ),
        );
    },

    async findSubscriptionsDueForCancellation(): Promise<
      SelectSubscription[]
    > {
      // 30 total days from first failure = 16 days after suspension (at day 14)
      const cancellationGraceDays =
        DUNNING_CANCELLATION_DAY - DUNNING_SUSPENSION_DAY; // 16 days
      const cancellationCutoff = new Date(
        Date.now() - cancellationGraceDays * 24 * 60 * 60 * 1000,
      );
      return db
        .select()
        .from(subscriptions)
        .where(
          and(
            eq(subscriptions.status, 'SUSPENDED'),
            lte(subscriptions.suspendedAt, cancellationCutoff),
          ),
        );
    },

    async findSubscriptionsDueForDeletion(): Promise<SelectSubscription[]> {
      return db
        .select()
        .from(subscriptions)
        .where(
          and(
            eq(subscriptions.status, 'CANCELLED'),
            lte(subscriptions.deletionScheduledAt, new Date()),
          ),
        );
    },

    async countEarlyBirdSubscriptions(): Promise<number> {
      const rows = await db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.plan, 'EARLY_BIRD_MONTHLY'));
      return rows.length;
    },

    async findAllSubscriptions(filters: {
      status?: string;
      page: number;
      pageSize: number;
    }): Promise<{ data: SelectSubscription[]; total: number }> {
      const offset = (filters.page - 1) * filters.pageSize;

      const whereClause = filters.status
        ? eq(subscriptions.status, filters.status)
        : undefined;

      const [rows, countResult] = await Promise.all([
        whereClause
          ? db
              .select()
              .from(subscriptions)
              .where(whereClause)
              .orderBy(desc(subscriptions.createdAt))
              .limit(filters.pageSize)
              .offset(offset)
          : db
              .select()
              .from(subscriptions)
              .orderBy(desc(subscriptions.createdAt))
              .limit(filters.pageSize)
              .offset(offset),
        whereClause
          ? db
              .select({ count: count() })
              .from(subscriptions)
              .where(whereClause)
          : db.select({ count: count() }).from(subscriptions),
      ]);

      return {
        data: rows,
        total: countResult[0]?.count ?? 0,
      };
    },
  };
}

export type SubscriptionRepository = ReturnType<
  typeof createSubscriptionRepository
>;

// ---------------------------------------------------------------------------
// Payment History Repository
// ---------------------------------------------------------------------------

export function createPaymentRepository(db: NodePgDatabase) {
  return {
    async recordPayment(
      data: InsertPaymentHistory,
    ): Promise<SelectPaymentHistory> {
      const rows = await db
        .insert(paymentHistory)
        .values(data)
        .returning();
      return rows[0];
    },

    async findPaymentByStripeInvoiceId(
      stripeInvoiceId: string,
    ): Promise<SelectPaymentHistory | undefined> {
      const rows = await db
        .select()
        .from(paymentHistory)
        .where(eq(paymentHistory.stripeInvoiceId, stripeInvoiceId))
        .limit(1);
      return rows[0];
    },

    async listPaymentsForSubscription(
      subscriptionId: string,
      pagination: { page: number; pageSize: number },
    ): Promise<{ data: SelectPaymentHistory[]; total: number }> {
      const offset = (pagination.page - 1) * pagination.pageSize;

      const [rows, countResult] = await Promise.all([
        db
          .select()
          .from(paymentHistory)
          .where(eq(paymentHistory.subscriptionId, subscriptionId))
          .orderBy(desc(paymentHistory.createdAt))
          .limit(pagination.pageSize)
          .offset(offset),
        db
          .select({ count: count() })
          .from(paymentHistory)
          .where(eq(paymentHistory.subscriptionId, subscriptionId)),
      ]);

      return {
        data: rows,
        total: countResult[0]?.count ?? 0,
      };
    },

    async updatePaymentStatus(
      paymentId: string,
      status: string,
      paidAt?: Date,
    ): Promise<SelectPaymentHistory | undefined> {
      const setClauses: Record<string, unknown> = { status };
      if (paidAt !== undefined) {
        setClauses.paidAt = paidAt;
      }

      const rows = await db
        .update(paymentHistory)
        .set(setClauses)
        .where(eq(paymentHistory.paymentId, paymentId))
        .returning();
      return rows[0];
    },

    async getPaymentSummary(
      subscriptionId: string,
    ): Promise<{
      totalPaid: string;
      totalGst: string;
      paymentCount: number;
      lastPaymentDate: Date | null;
    }> {
      const rows = await db
        .select({
          totalPaid: sum(paymentHistory.totalCad),
          totalGst: sum(paymentHistory.gstAmount),
          paymentCount: count(),
          lastPaymentDate: max(paymentHistory.paidAt),
        })
        .from(paymentHistory)
        .where(
          and(
            eq(paymentHistory.subscriptionId, subscriptionId),
            eq(paymentHistory.status, 'PAID'),
          ),
        );

      const row = rows[0];
      return {
        totalPaid: row?.totalPaid ?? '0.00',
        totalGst: row?.totalGst ?? '0.00',
        paymentCount: row?.paymentCount ?? 0,
        lastPaymentDate: row?.lastPaymentDate ?? null,
      };
    },
  };
}

export type PaymentRepository = ReturnType<typeof createPaymentRepository>;

// ---------------------------------------------------------------------------
// Status Component Repository
// ---------------------------------------------------------------------------

export function createStatusComponentRepository(db: NodePgDatabase) {
  return {
    async listComponents(): Promise<SelectStatusComponent[]> {
      return db
        .select()
        .from(statusComponents)
        .orderBy(asc(statusComponents.sortOrder));
    },

    async updateComponentStatus(
      componentId: string,
      status: string,
    ): Promise<SelectStatusComponent | undefined> {
      const rows = await db
        .update(statusComponents)
        .set({
          status,
          updatedAt: new Date(),
        })
        .where(eq(statusComponents.componentId, componentId))
        .returning();
      return rows[0];
    },

    async seedComponents(
      components: Array<{ name: string; displayName: string; sortOrder: number }>,
    ): Promise<void> {
      for (const comp of components) {
        const existing = await db
          .select()
          .from(statusComponents)
          .where(eq(statusComponents.name, comp.name))
          .limit(1);

        if (existing.length === 0) {
          await db
            .insert(statusComponents)
            .values({
              name: comp.name,
              displayName: comp.displayName,
              sortOrder: comp.sortOrder,
              status: 'operational',
            });
        }
      }
    },
  };
}

export type StatusComponentRepository = ReturnType<
  typeof createStatusComponentRepository
>;

// ---------------------------------------------------------------------------
// Incident Repository
// ---------------------------------------------------------------------------

export function createIncidentRepository(db: NodePgDatabase) {
  return {
    async createIncident(data: {
      title: string;
      severity: string;
      affectedComponents: string[];
      initialMessage: string;
    }): Promise<SelectStatusIncident & { updates: SelectIncidentUpdate[] }> {
      const incidentRows = await db
        .insert(statusIncidents)
        .values({
          title: data.title,
          severity: data.severity,
          status: 'INVESTIGATING',
          affectedComponents: data.affectedComponents,
        })
        .returning();
      const incident = incidentRows[0];

      const updateRows = await db
        .insert(incidentUpdates)
        .values({
          incidentId: incident.incidentId,
          status: 'INVESTIGATING',
          message: data.initialMessage,
        })
        .returning();

      return { ...incident, updates: updateRows };
    },

    async updateIncident(
      incidentId: string,
      status: string,
      message: string,
    ): Promise<
      (SelectStatusIncident & { updates: SelectIncidentUpdate[] }) | undefined
    > {
      const setClauses: Record<string, unknown> = {
        status,
        updatedAt: new Date(),
      };
      if (status === 'RESOLVED') {
        setClauses.resolvedAt = new Date();
      }

      const incidentRows = await db
        .update(statusIncidents)
        .set(setClauses)
        .where(eq(statusIncidents.incidentId, incidentId))
        .returning();

      if (incidentRows.length === 0) return undefined;

      await db.insert(incidentUpdates).values({
        incidentId,
        status,
        message,
      });

      const updates = await db
        .select()
        .from(incidentUpdates)
        .where(eq(incidentUpdates.incidentId, incidentId))
        .orderBy(asc(incidentUpdates.createdAt));

      return { ...incidentRows[0], updates };
    },

    async listActiveIncidents(): Promise<
      Array<SelectStatusIncident & { updates: SelectIncidentUpdate[] }>
    > {
      const incidents = await db
        .select()
        .from(statusIncidents)
        .where(ne(statusIncidents.status, 'RESOLVED'))
        .orderBy(desc(statusIncidents.createdAt));

      const results: Array<
        SelectStatusIncident & { updates: SelectIncidentUpdate[] }
      > = [];
      for (const incident of incidents) {
        const updates = await db
          .select()
          .from(incidentUpdates)
          .where(eq(incidentUpdates.incidentId, incident.incidentId))
          .orderBy(asc(incidentUpdates.createdAt));
        results.push({ ...incident, updates });
      }
      return results;
    },

    async listIncidentHistory(pagination: {
      page: number;
      pageSize: number;
    }): Promise<{
      data: Array<SelectStatusIncident & { updates: SelectIncidentUpdate[] }>;
      total: number;
    }> {
      const offset = (pagination.page - 1) * pagination.pageSize;

      const [incidents, countResult] = await Promise.all([
        db
          .select()
          .from(statusIncidents)
          .orderBy(desc(statusIncidents.createdAt))
          .limit(pagination.pageSize)
          .offset(offset),
        db
          .select({ count: count() })
          .from(statusIncidents),
      ]);

      const results: Array<
        SelectStatusIncident & { updates: SelectIncidentUpdate[] }
      > = [];
      for (const incident of incidents) {
        const updates = await db
          .select()
          .from(incidentUpdates)
          .where(eq(incidentUpdates.incidentId, incident.incidentId))
          .orderBy(asc(incidentUpdates.createdAt));
        results.push({ ...incident, updates });
      }

      return {
        data: results,
        total: countResult[0]?.count ?? 0,
      };
    },

    async findIncidentById(
      incidentId: string,
    ): Promise<
      (SelectStatusIncident & { updates: SelectIncidentUpdate[] }) | undefined
    > {
      const rows = await db
        .select()
        .from(statusIncidents)
        .where(eq(statusIncidents.incidentId, incidentId))
        .limit(1);

      if (rows.length === 0) return undefined;

      const updates = await db
        .select()
        .from(incidentUpdates)
        .where(eq(incidentUpdates.incidentId, incidentId))
        .orderBy(asc(incidentUpdates.createdAt));

      return { ...rows[0], updates };
    },
  };
}

export type IncidentRepository = ReturnType<typeof createIncidentRepository>;
