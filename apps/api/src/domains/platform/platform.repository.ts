import { eq, and, lte, ne, sql, desc, asc, count, sum, max, isNotNull, isNull } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { createHash } from 'node:crypto';
import {
  subscriptions,
  paymentHistory,
  statusComponents,
  statusIncidents,
  incidentUpdates,
  practiceMemberships,
  imaAmendments,
  imaAmendmentResponses,
  breachRecords,
  breachAffectedCustodians,
  breachUpdates,
  dataDestructionTracking,
  type InsertSubscription,
  type SelectSubscription,
  type InsertPaymentHistory,
  type SelectPaymentHistory,
  type SelectStatusComponent,
  type SelectStatusIncident,
  type SelectIncidentUpdate,
  type SelectImaAmendment,
  type SelectImaAmendmentResponse,
  type SelectBreachRecord,
  type SelectBreachAffectedCustodian,
  type SelectBreachUpdate,
  type InsertDataDestructionTracking,
  type SelectDataDestructionTracking,
} from '@meritum/shared/schemas/db/platform.schema.js';
import {
  DUNNING_SUSPENSION_DAY,
  DUNNING_CANCELLATION_DAY,
  EARLY_BIRD_EXPIRY_WARNING_DAYS,
} from '@meritum/shared/constants/platform.constants.js';
import { ConflictError } from '../../lib/errors.js';

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
        .where(
          sql`${subscriptions.plan} IN ('EARLY_BIRD_MONTHLY', 'EARLY_BIRD_ANNUAL')`
        );
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

    /**
     * Generic subscription update — accepts partial fields to update.
     * Used by D17-010 to set earlyBirdLockedUntil after checkout completion.
     */
    async updateSubscription(
      subscriptionId: string,
      data: Partial<{
        earlyBirdLockedUntil: Date | null;
        earlyBirdExpiryNotified: boolean;
        plan: string;
        status: string;
        cancelledAt: Date | null;
      }>,
    ): Promise<SelectSubscription | undefined> {
      const rows = await db
        .update(subscriptions)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(eq(subscriptions.subscriptionId, subscriptionId))
        .returning();
      return rows[0];
    },

    /**
     * Check if a user has EVER had an early bird subscription, including cancelled ones.
     * This prevents re-signup at early bird rates after cancellation.
     * Spec reference: B2-3 — "Early bird rate does not survive cancellation."
     */
    async hasEverHadEarlyBird(userId: string): Promise<boolean> {
      const rows = await db
        .select()
        .from(subscriptions)
        .where(
          and(
            eq(subscriptions.providerId, userId),
            sql`${subscriptions.plan} IN ('EARLY_BIRD_MONTHLY', 'EARLY_BIRD_ANNUAL')`,
          ),
        )
        .limit(1);
      return rows.length > 0;
    },

    /**
     * Find active early bird subscriptions expiring within warningDays
     * that have NOT yet been notified.
     * Used by D17-012 Phase 1 — 30-day warning.
     */
    async findExpiringEarlyBirdSubscriptions(
      warningDays: number,
    ): Promise<SelectSubscription[]> {
      const warningCutoff = new Date(
        Date.now() + warningDays * 24 * 60 * 60 * 1000,
      );
      return db
        .select()
        .from(subscriptions)
        .where(
          and(
            sql`${subscriptions.plan} IN ('EARLY_BIRD_MONTHLY', 'EARLY_BIRD_ANNUAL')`,
            eq(subscriptions.status, 'ACTIVE'),
            isNotNull(subscriptions.earlyBirdLockedUntil),
            lte(subscriptions.earlyBirdLockedUntil, warningCutoff),
            eq(subscriptions.earlyBirdExpiryNotified, false),
          ),
        );
    },

    /**
     * Find active early bird subscriptions where the rate lock has expired.
     * Used by D17-012 Phase 2 — expiry transition.
     */
    async findExpiredEarlyBirdSubscriptions(): Promise<SelectSubscription[]> {
      return db
        .select()
        .from(subscriptions)
        .where(
          and(
            sql`${subscriptions.plan} IN ('EARLY_BIRD_MONTHLY', 'EARLY_BIRD_ANNUAL')`,
            eq(subscriptions.status, 'ACTIVE'),
            isNotNull(subscriptions.earlyBirdLockedUntil),
            lte(subscriptions.earlyBirdLockedUntil, new Date()),
          ),
        );
    },

    /**
     * Get the active practice membership for a user, or null if not in a practice.
     * Used by D17-012 to determine Path A vs Path B for expiry transition.
     */
    async getActivePracticeMembership(
      userId: string,
    ): Promise<{ membershipId: string; practiceId: string; billingMode: string; physicianUserId: string } | null> {
      const rows = await db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.physicianUserId, userId),
            eq(practiceMemberships.isActive, true),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Update billing_mode on a practice membership.
     * Used by D17-012 Path A to transition from INDIVIDUAL_EARLY_BIRD to PRACTICE_CONSOLIDATED.
     */
    async updatePracticeMembershipBillingMode(
      membershipId: string,
      billingMode: string,
    ): Promise<void> {
      await db
        .update(practiceMemberships)
        .set({ billingMode })
        .where(eq(practiceMemberships.membershipId, membershipId));
    },

    /**
     * Get all active practice members with billing_mode = 'INDIVIDUAL_EARLY_BIRD'.
     * Used by D17-014 for proactive transition notifications to practice admins.
     */
    async getEarlyBirdMembersInPractice(
      practiceId: string,
    ): Promise<Array<{
      physicianUserId: string;
      earlyBirdExpiryNotified: boolean;
    }>> {
      const members = await db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.isActive, true),
            eq(practiceMemberships.billingMode, 'INDIVIDUAL_EARLY_BIRD'),
          ),
        );

      // For each member, look up their subscription's earlyBirdExpiryNotified
      const results: Array<{
        physicianUserId: string;
        earlyBirdExpiryNotified: boolean;
      }> = [];

      for (const member of members) {
        const sub = await db
          .select()
          .from(subscriptions)
          .where(eq(subscriptions.providerId, member.physicianUserId))
          .limit(1);

        results.push({
          physicianUserId: member.physicianUserId,
          earlyBirdExpiryNotified: sub[0]?.earlyBirdExpiryNotified ?? false,
        });
      }

      return results;
    },

    /**
     * Find CANCELLED subscriptions whose deletionScheduledAt is within
     * the given number of days from now.
     * Used by IMA-012 export window reminders.
     */
    async findCancelledSubscriptionsInExportWindow(): Promise<SelectSubscription[]> {
      return db
        .select()
        .from(subscriptions)
        .where(
          and(
            eq(subscriptions.status, 'CANCELLED'),
            isNotNull(subscriptions.deletionScheduledAt),
          ),
        );
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

// ---------------------------------------------------------------------------
// Amendment Repository
// ---------------------------------------------------------------------------

export function createAmendmentRepository(db: NodePgDatabase) {
  return {
    async createAmendment(data: {
      amendmentType: string;
      title: string;
      description: string;
      documentText: string;
      effectiveDate: Date;
      createdBy: string;
    }): Promise<SelectImaAmendment> {
      const documentHash = createHash('sha256')
        .update(data.documentText)
        .digest('hex');

      const rows = await db
        .insert(imaAmendments)
        .values({
          amendmentType: data.amendmentType,
          title: data.title,
          description: data.description,
          documentHash,
          noticeDate: new Date(),
          effectiveDate: data.effectiveDate,
          createdBy: data.createdBy,
        })
        .returning();
      return rows[0];
    },

    async findAmendmentById(
      amendmentId: string,
    ): Promise<
      | (SelectImaAmendment & {
          responseCounts: { total: number; acknowledged: number; accepted: number; rejected: number };
        })
      | undefined
    > {
      const rows = await db
        .select()
        .from(imaAmendments)
        .where(eq(imaAmendments.amendmentId, amendmentId))
        .limit(1);

      if (rows.length === 0) return undefined;

      const responses = await db
        .select()
        .from(imaAmendmentResponses)
        .where(eq(imaAmendmentResponses.amendmentId, amendmentId));

      const responseCounts = {
        total: responses.length,
        acknowledged: responses.filter((r) => r.responseType === 'ACKNOWLEDGED').length,
        accepted: responses.filter((r) => r.responseType === 'ACCEPTED').length,
        rejected: responses.filter((r) => r.responseType === 'REJECTED').length,
      };

      return { ...rows[0], responseCounts };
    },

    async listAmendments(filters: {
      status?: string;
      page: number;
      pageSize: number;
    }): Promise<{ data: Array<SelectImaAmendment & { derivedStatus: string }>; total: number }> {
      const offset = (filters.page - 1) * filters.pageSize;
      const now = new Date();

      const allRows = await db
        .select()
        .from(imaAmendments)
        .orderBy(desc(imaAmendments.createdAt));

      const withStatus = allRows.map((row) => {
        let derivedStatus: string;
        if (now < row.effectiveDate) {
          derivedStatus = 'PENDING';
        } else {
          derivedStatus = 'ACTIVE';
        }
        return { ...row, derivedStatus };
      });

      const filtered = filters.status
        ? withStatus.filter((r) => r.derivedStatus === filters.status)
        : withStatus;

      return {
        data: filtered.slice(offset, offset + filters.pageSize),
        total: filtered.length,
      };
    },

    async findPendingAmendmentsForProvider(
      providerId: string,
    ): Promise<SelectImaAmendment[]> {
      const now = new Date();

      const amendments = await db
        .select()
        .from(imaAmendments)
        .where(lte(imaAmendments.effectiveDate, now));

      const responses = await db
        .select()
        .from(imaAmendmentResponses)
        .where(eq(imaAmendmentResponses.providerId, providerId));

      const respondedIds = new Set(responses.map((r) => r.amendmentId));

      return amendments.filter((a) => !respondedIds.has(a.amendmentId));
    },

    async createAmendmentResponse(data: {
      amendmentId: string;
      providerId: string;
      responseType: string;
      ipAddress: string;
      userAgent: string;
    }): Promise<SelectImaAmendmentResponse> {
      try {
        const rows = await db
          .insert(imaAmendmentResponses)
          .values({
            amendmentId: data.amendmentId,
            providerId: data.providerId,
            responseType: data.responseType,
            ipAddress: data.ipAddress,
            userAgent: data.userAgent,
          })
          .returning();
        return rows[0];
      } catch (err: any) {
        if (err.code === '23505') {
          throw new ConflictError(
            'Provider has already responded to this amendment',
          );
        }
        throw err;
      }
    },

    async getAmendmentResponse(
      amendmentId: string,
      providerId: string,
    ): Promise<SelectImaAmendmentResponse | undefined> {
      const rows = await db
        .select()
        .from(imaAmendmentResponses)
        .where(
          and(
            eq(imaAmendmentResponses.amendmentId, amendmentId),
            eq(imaAmendmentResponses.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async countUnrespondedAmendments(providerId: string): Promise<number> {
      const now = new Date();

      const amendments = await db
        .select()
        .from(imaAmendments)
        .where(lte(imaAmendments.effectiveDate, now));

      const responses = await db
        .select()
        .from(imaAmendmentResponses)
        .where(eq(imaAmendmentResponses.providerId, providerId));

      const respondedIds = new Set(responses.map((r) => r.amendmentId));

      return amendments.filter((a) => !respondedIds.has(a.amendmentId)).length;
    },
  };
}

export type AmendmentRepository = ReturnType<typeof createAmendmentRepository>;

// ---------------------------------------------------------------------------
// Breach Repository
// ---------------------------------------------------------------------------

export function createBreachRepository(db: NodePgDatabase) {
  return {
    async createBreachRecord(data: {
      breachDescription: string;
      breachDate: Date;
      awarenessDate: Date;
      hiDescription: string;
      includesIihi: boolean;
      affectedCount?: number;
      riskAssessment?: string;
      mitigationSteps?: string;
      contactName: string;
      contactEmail: string;
      createdBy: string;
    }): Promise<SelectBreachRecord> {
      // evidenceHoldUntil = awarenessDate + 12 months (server-computed)
      const evidenceHoldUntil = new Date(data.awarenessDate);
      evidenceHoldUntil.setMonth(evidenceHoldUntil.getMonth() + 12);

      const rows = await db
        .insert(breachRecords)
        .values({
          breachDescription: data.breachDescription,
          breachDate: data.breachDate,
          awarenessDate: data.awarenessDate,
          hiDescription: data.hiDescription,
          includesIihi: data.includesIihi,
          affectedCount: data.affectedCount,
          riskAssessment: data.riskAssessment,
          mitigationSteps: data.mitigationSteps,
          contactName: data.contactName,
          contactEmail: data.contactEmail,
          evidenceHoldUntil,
          createdBy: data.createdBy,
        })
        .returning();
      return rows[0];
    },

    async findBreachById(
      breachId: string,
    ): Promise<
      | (SelectBreachRecord & {
          affectedCustodianCount: number;
          updates: SelectBreachUpdate[];
        })
      | undefined
    > {
      const rows = await db
        .select()
        .from(breachRecords)
        .where(eq(breachRecords.breachId, breachId))
        .limit(1);

      if (rows.length === 0) return undefined;

      const [custodianCountResult, updates] = await Promise.all([
        db
          .select({ count: count() })
          .from(breachAffectedCustodians)
          .where(eq(breachAffectedCustodians.breachId, breachId)),
        db
          .select()
          .from(breachUpdates)
          .where(eq(breachUpdates.breachId, breachId))
          .orderBy(asc(breachUpdates.sentAt)),
      ]);

      return {
        ...rows[0],
        affectedCustodianCount: custodianCountResult[0]?.count ?? 0,
        updates,
      };
    },

    async listBreaches(filters: {
      status?: string;
      page: number;
      pageSize: number;
    }): Promise<{ data: SelectBreachRecord[]; total: number }> {
      const offset = (filters.page - 1) * filters.pageSize;

      const whereClause = filters.status
        ? eq(breachRecords.status, filters.status)
        : undefined;

      const [rows, countResult] = await Promise.all([
        whereClause
          ? db
              .select()
              .from(breachRecords)
              .where(whereClause)
              .orderBy(desc(breachRecords.createdAt))
              .limit(filters.pageSize)
              .offset(offset)
          : db
              .select()
              .from(breachRecords)
              .orderBy(desc(breachRecords.createdAt))
              .limit(filters.pageSize)
              .offset(offset),
        whereClause
          ? db
              .select({ count: count() })
              .from(breachRecords)
              .where(whereClause)
          : db.select({ count: count() }).from(breachRecords),
      ]);

      return {
        data: rows,
        total: countResult[0]?.count ?? 0,
      };
    },

    async updateBreachStatus(
      breachId: string,
      status: string,
      resolvedAt?: Date,
    ): Promise<SelectBreachRecord | undefined> {
      const setClauses: Record<string, unknown> = {
        status,
        updatedAt: new Date(),
      };
      if (status === 'RESOLVED') {
        setClauses.resolvedAt = resolvedAt ?? new Date();
      }

      const rows = await db
        .update(breachRecords)
        .set(setClauses)
        .where(eq(breachRecords.breachId, breachId))
        .returning();
      return rows[0];
    },

    async addAffectedCustodian(
      breachId: string,
      providerId: string,
    ): Promise<SelectBreachAffectedCustodian> {
      const rows = await db
        .insert(breachAffectedCustodians)
        .values({
          breachId,
          providerId,
        })
        .returning();
      return rows[0];
    },

    async markCustodianNotified(
      breachId: string,
      providerId: string,
      method: string,
    ): Promise<SelectBreachAffectedCustodian | undefined> {
      const rows = await db
        .update(breachAffectedCustodians)
        .set({
          initialNotifiedAt: new Date(),
          notificationMethod: method,
        })
        .where(
          and(
            eq(breachAffectedCustodians.breachId, breachId),
            eq(breachAffectedCustodians.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    async getUnnotifiedCustodians(
      breachId: string,
    ): Promise<SelectBreachAffectedCustodian[]> {
      return db
        .select()
        .from(breachAffectedCustodians)
        .where(
          and(
            eq(breachAffectedCustodians.breachId, breachId),
            isNull(breachAffectedCustodians.initialNotifiedAt),
          ),
        );
    },

    async createBreachUpdate(
      breachId: string,
      data: {
        updateType: string;
        content: string;
        createdBy: string;
      },
    ): Promise<SelectBreachUpdate> {
      const rows = await db
        .insert(breachUpdates)
        .values({
          breachId,
          updateType: data.updateType,
          content: data.content,
          createdBy: data.createdBy,
        })
        .returning();
      return rows[0];
    },

    async listBreachUpdates(breachId: string): Promise<SelectBreachUpdate[]> {
      return db
        .select()
        .from(breachUpdates)
        .where(eq(breachUpdates.breachId, breachId))
        .orderBy(asc(breachUpdates.sentAt));
    },

    async getOverdueBreaches(): Promise<SelectBreachRecord[]> {
      const seventyTwoHoursAgo = new Date(Date.now() - 72 * 60 * 60 * 1000);

      // Find breaches that are not resolved and awareness_date + 72h < now
      const breaches = await db
        .select()
        .from(breachRecords)
        .where(
          and(
            ne(breachRecords.status, 'RESOLVED'),
            lte(breachRecords.awarenessDate, seventyTwoHoursAgo),
          ),
        );

      // Filter to only those that have unnotified custodians
      const overdueBreaches: SelectBreachRecord[] = [];
      for (const breach of breaches) {
        const unnotified = await db
          .select({ count: count() })
          .from(breachAffectedCustodians)
          .where(
            and(
              eq(breachAffectedCustodians.breachId, breach.breachId),
              isNull(breachAffectedCustodians.initialNotifiedAt),
            ),
          );

        if ((unnotified[0]?.count ?? 0) > 0) {
          overdueBreaches.push(breach);
        }
      }

      return overdueBreaches;
    },
  };
}

export type BreachRepository = ReturnType<typeof createBreachRepository>;

// ---------------------------------------------------------------------------
// Data Destruction Tracking Repository (IMA-060)
// ---------------------------------------------------------------------------

export function createDestructionTrackingRepository(db: NodePgDatabase) {
  return {
    async createTrackingRecord(
      data: InsertDataDestructionTracking,
    ): Promise<SelectDataDestructionTracking> {
      const rows = await db
        .insert(dataDestructionTracking)
        .values(data)
        .returning();
      return rows[0];
    },

    async findByProviderId(
      providerId: string,
    ): Promise<SelectDataDestructionTracking | undefined> {
      const rows = await db
        .select()
        .from(dataDestructionTracking)
        .where(eq(dataDestructionTracking.providerId, providerId))
        .limit(1);
      return rows[0];
    },

    async updateActiveDeletedAt(
      providerId: string,
      activeDeletedAt: Date,
      backupPurgeDeadline: Date,
    ): Promise<SelectDataDestructionTracking | undefined> {
      const rows = await db
        .update(dataDestructionTracking)
        .set({ activeDeletedAt, backupPurgeDeadline })
        .where(eq(dataDestructionTracking.providerId, providerId))
        .returning();
      return rows[0];
    },

    async updateFilesDeletedAt(
      providerId: string,
      filesDeletedAt: Date,
    ): Promise<SelectDataDestructionTracking | undefined> {
      const rows = await db
        .update(dataDestructionTracking)
        .set({ filesDeletedAt })
        .where(eq(dataDestructionTracking.providerId, providerId))
        .returning();
      return rows[0];
    },

    async updateBackupPurgedAt(
      providerId: string,
      backupPurgedAt: Date,
    ): Promise<SelectDataDestructionTracking | undefined> {
      const rows = await db
        .update(dataDestructionTracking)
        .set({ backupPurgedAt })
        .where(eq(dataDestructionTracking.providerId, providerId))
        .returning();
      return rows[0];
    },

    async updateConfirmationSentAt(
      providerId: string,
      confirmationSentAt: Date,
    ): Promise<SelectDataDestructionTracking | undefined> {
      const rows = await db
        .update(dataDestructionTracking)
        .set({ confirmationSentAt })
        .where(eq(dataDestructionTracking.providerId, providerId))
        .returning();
      return rows[0];
    },

    async findPendingConfirmations(): Promise<SelectDataDestructionTracking[]> {
      return db
        .select()
        .from(dataDestructionTracking)
        .where(
          and(
            isNotNull(dataDestructionTracking.backupPurgedAt),
            isNull(dataDestructionTracking.confirmationSentAt),
          ),
        );
    },

    async findOverdueBackupPurges(): Promise<SelectDataDestructionTracking[]> {
      return db
        .select()
        .from(dataDestructionTracking)
        .where(
          and(
            isNull(dataDestructionTracking.backupPurgedAt),
            isNotNull(dataDestructionTracking.backupPurgeDeadline),
            lte(dataDestructionTracking.backupPurgeDeadline, new Date()),
          ),
        );
    },
  };
}

export type DestructionTrackingRepository = ReturnType<
  typeof createDestructionTrackingRepository
>;
