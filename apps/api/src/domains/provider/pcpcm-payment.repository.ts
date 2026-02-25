import { eq, and, lte, gte, count, desc, inArray, sql } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  pcpcmPayments,
  pcpcmEnrolments,
  type InsertPcpcmPayment,
  type SelectPcpcmPayment,
} from '@meritum/shared/schemas/db/provider.schema.js';

export function createPcpcmPaymentRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert a new PCPCM payment record.
     */
    async createPcpcmPayment(data: InsertPcpcmPayment): Promise<SelectPcpcmPayment> {
      const rows = await db
        .insert(pcpcmPayments)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a single payment by ID, always scoped by providerId for tenant isolation.
     */
    async findPcpcmPaymentById(
      paymentId: string,
      providerId: string,
    ): Promise<SelectPcpcmPayment | undefined> {
      const rows = await db
        .select()
        .from(pcpcmPayments)
        .where(
          and(
            eq(pcpcmPayments.paymentId, paymentId),
            eq(pcpcmPayments.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update a payment record, scoped by providerId for tenant isolation.
     */
    async updatePcpcmPayment(
      paymentId: string,
      providerId: string,
      data: Partial<InsertPcpcmPayment>,
    ): Promise<SelectPcpcmPayment | undefined> {
      const rows = await db
        .update(pcpcmPayments)
        .set(data)
        .where(
          and(
            eq(pcpcmPayments.paymentId, paymentId),
            eq(pcpcmPayments.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * List payments with pagination and optional filters (status, periodStart, periodEnd).
     * Always scoped by providerId.
     */
    async listPcpcmPaymentsForProvider(
      providerId: string,
      filters?: {
        status?: string;
        periodStart?: string;
        periodEnd?: string;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ data: SelectPcpcmPayment[]; total: number }> {
      const pageLimit = filters?.limit ?? 20;
      const pageOffset = filters?.offset ?? 0;

      const conditions: any[] = [eq(pcpcmPayments.providerId, providerId)];

      if (filters?.status) {
        conditions.push(eq(pcpcmPayments.status, filters.status));
      }
      if (filters?.periodStart) {
        conditions.push(gte(pcpcmPayments.paymentPeriodStart, filters.periodStart));
      }
      if (filters?.periodEnd) {
        conditions.push(lte(pcpcmPayments.paymentPeriodEnd, filters.periodEnd));
      }

      const whereClause = and(...conditions);

      const [rows, countResult] = await Promise.all([
        db
          .select()
          .from(pcpcmPayments)
          .where(whereClause)
          .orderBy(desc(pcpcmPayments.paymentPeriodEnd))
          .limit(pageLimit)
          .offset(pageOffset),
        db
          .select({ count: count() })
          .from(pcpcmPayments)
          .where(whereClause),
      ]);

      return {
        data: rows,
        total: countResult[0]?.count ?? 0,
      };
    },

    /**
     * Find unreconciled payments (status EXPECTED or RECEIVED) for a provider.
     */
    async findUnreconciledPayments(providerId: string): Promise<SelectPcpcmPayment[]> {
      return db
        .select()
        .from(pcpcmPayments)
        .where(
          and(
            eq(pcpcmPayments.providerId, providerId),
            inArray(pcpcmPayments.status, ['EXPECTED', 'RECEIVED']),
          ),
        )
        .orderBy(desc(pcpcmPayments.paymentPeriodEnd));
    },

    /**
     * Find payments within a specific date range for a provider.
     */
    async findPaymentsForPeriod(
      providerId: string,
      periodStart: string,
      periodEnd: string,
    ): Promise<SelectPcpcmPayment[]> {
      return db
        .select()
        .from(pcpcmPayments)
        .where(
          and(
            eq(pcpcmPayments.providerId, providerId),
            gte(pcpcmPayments.paymentPeriodStart, periodStart),
            lte(pcpcmPayments.paymentPeriodEnd, periodEnd),
          ),
        )
        .orderBy(desc(pcpcmPayments.paymentPeriodEnd));
    },

    /**
     * Update a payment's status with optional reconciledAt timestamp and notes.
     * Always scoped by providerId.
     */
    async updatePaymentStatus(
      paymentId: string,
      providerId: string,
      status: string,
      reconciledAt?: Date,
      notes?: string,
    ): Promise<SelectPcpcmPayment | undefined> {
      const setClauses: Record<string, unknown> = { status };
      if (reconciledAt !== undefined) {
        setClauses.reconciledAt = reconciledAt;
      }
      if (notes !== undefined) {
        setClauses.notes = notes;
      }

      const rows = await db
        .update(pcpcmPayments)
        .set(setClauses)
        .where(
          and(
            eq(pcpcmPayments.paymentId, paymentId),
            eq(pcpcmPayments.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Update the panel size on a PCPCM enrolment, scoped by providerId.
     */
    async updatePanelSizeOnEnrolment(
      enrolmentId: string,
      providerId: string,
      panelSize: number,
    ): Promise<void> {
      await db
        .update(pcpcmEnrolments)
        .set({ panelSize, updatedAt: new Date() })
        .where(
          and(
            eq(pcpcmEnrolments.enrolmentId, enrolmentId),
            eq(pcpcmEnrolments.providerId, providerId),
          ),
        );
    },

    /**
     * Find a PCPCM enrolment by ID, scoped by providerId for tenant isolation.
     */
    async findEnrolmentByIdAndProvider(
      enrolmentId: string,
      providerId: string,
    ): Promise<any | undefined> {
      const rows = await db
        .select()
        .from(pcpcmEnrolments)
        .where(
          and(
            eq(pcpcmEnrolments.enrolmentId, enrolmentId),
            eq(pcpcmEnrolments.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0];
    },
  };
}

export type PcpcmPaymentRepository = ReturnType<typeof createPcpcmPaymentRepository>;
