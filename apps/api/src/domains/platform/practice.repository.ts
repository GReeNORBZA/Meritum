import { eq, and, count } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  practices,
  practiceMemberships,
  type InsertPractice,
  type SelectPractice,
} from '@meritum/shared/schemas/db/platform.schema.js';

// ---------------------------------------------------------------------------
// Practice Repository
// ---------------------------------------------------------------------------

export function createPracticeRepository(db: NodePgDatabase) {
  return {
    async createPractice(data: InsertPractice): Promise<SelectPractice> {
      const rows = await db
        .insert(practices)
        .values(data)
        .returning();
      return rows[0];
    },

    async findPracticeById(
      practiceId: string,
    ): Promise<SelectPractice | null> {
      const rows = await db
        .select()
        .from(practices)
        .where(eq(practices.practiceId, practiceId))
        .limit(1);
      return rows[0] ?? null;
    },

    async findPracticeByAdminUserId(
      adminUserId: string,
    ): Promise<SelectPractice | null> {
      const rows = await db
        .select()
        .from(practices)
        .where(
          and(
            eq(practices.adminUserId, adminUserId),
            eq(practices.status, 'ACTIVE'),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    async updatePractice(
      practiceId: string,
      data: Partial<InsertPractice>,
    ): Promise<SelectPractice> {
      const rows = await db
        .update(practices)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(eq(practices.practiceId, practiceId))
        .returning();
      return rows[0];
    },

    async updatePracticeStatus(
      practiceId: string,
      status: string,
    ): Promise<void> {
      await db
        .update(practices)
        .set({
          status,
          updatedAt: new Date(),
        })
        .where(eq(practices.practiceId, practiceId));
    },

    async updatePracticeStripeIds(
      practiceId: string,
      stripeCustomerId: string,
      stripeSubscriptionId: string,
    ): Promise<void> {
      await db
        .update(practices)
        .set({
          stripeCustomerId,
          stripeSubscriptionId,
          updatedAt: new Date(),
        })
        .where(eq(practices.practiceId, practiceId));
    },

    async getActiveHeadcount(practiceId: string): Promise<number> {
      const rows = await db
        .select({ count: count() })
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.isActive, true),
          ),
        );
      return rows[0]?.count ?? 0;
    },

    async getConsolidatedSeatCount(practiceId: string): Promise<number> {
      const rows = await db
        .select({ count: count() })
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.isActive, true),
            eq(practiceMemberships.billingMode, 'PRACTICE_CONSOLIDATED'),
          ),
        );
      return rows[0]?.count ?? 0;
    },

    async findActivePractices(): Promise<SelectPractice[]> {
      return db
        .select()
        .from(practices)
        .where(eq(practices.status, 'ACTIVE'));
    },
  };
}

export type PracticeRepository = ReturnType<typeof createPracticeRepository>;
