import { eq, and, lte, count } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  practiceMemberships,
  type InsertPracticeMembership,
  type SelectPracticeMembership,
} from '@meritum/shared/schemas/db/platform.schema.js';

// ---------------------------------------------------------------------------
// Practice Membership Repository
// ---------------------------------------------------------------------------

export function createPracticeMembershipRepository(db: NodePgDatabase) {
  return {
    async createMembership(
      data: InsertPracticeMembership,
    ): Promise<SelectPracticeMembership> {
      const rows = await db
        .insert(practiceMemberships)
        .values(data)
        .returning();
      return rows[0];
    },

    async findActiveMembershipByPhysicianId(
      physicianUserId: string,
    ): Promise<SelectPracticeMembership | null> {
      const rows = await db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.physicianUserId, physicianUserId),
            eq(practiceMemberships.isActive, true),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    async findActiveMembershipsByPracticeId(
      practiceId: string,
    ): Promise<SelectPracticeMembership[]> {
      return db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.isActive, true),
          ),
        );
    },

    async findMembershipByPracticeAndPhysician(
      practiceId: string,
      physicianUserId: string,
    ): Promise<SelectPracticeMembership | null> {
      const rows = await db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.physicianUserId, physicianUserId),
            eq(practiceMemberships.isActive, true),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    async setRemovalScheduled(
      membershipId: string,
      removedAt: Date,
      removalEffectiveAt: Date,
    ): Promise<void> {
      await db
        .update(practiceMemberships)
        .set({
          removedAt,
          removalEffectiveAt,
        })
        .where(eq(practiceMemberships.membershipId, membershipId));
    },

    async deactivateMembership(membershipId: string): Promise<void> {
      await db
        .update(practiceMemberships)
        .set({ isActive: false })
        .where(eq(practiceMemberships.membershipId, membershipId));
    },

    async findPendingRemovals(
      cutoffDate: Date,
    ): Promise<SelectPracticeMembership[]> {
      return db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            lte(practiceMemberships.removalEffectiveAt, cutoffDate),
            eq(practiceMemberships.isActive, true),
          ),
        );
    },

    async deactivateAllMemberships(practiceId: string): Promise<void> {
      await db
        .update(practiceMemberships)
        .set({ isActive: false })
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.isActive, true),
          ),
        );
    },

    async updateBillingMode(
      membershipId: string,
      billingMode: string,
    ): Promise<void> {
      await db
        .update(practiceMemberships)
        .set({ billingMode })
        .where(eq(practiceMemberships.membershipId, membershipId));
    },

    async findMembershipsByBillingMode(
      practiceId: string,
      billingMode: string,
    ): Promise<SelectPracticeMembership[]> {
      return db
        .select()
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.billingMode, billingMode),
            eq(practiceMemberships.isActive, true),
          ),
        );
    },

    async countActiveMembersByBillingMode(
      practiceId: string,
      billingMode: string,
    ): Promise<number> {
      const rows = await db
        .select({ count: count() })
        .from(practiceMemberships)
        .where(
          and(
            eq(practiceMemberships.practiceId, practiceId),
            eq(practiceMemberships.billingMode, billingMode),
            eq(practiceMemberships.isActive, true),
          ),
        );
      return rows[0]?.count ?? 0;
    },
  };
}

export type PracticeMembershipRepository = ReturnType<
  typeof createPracticeMembershipRepository
>;
