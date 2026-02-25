import { eq, and, desc, count, inArray, sql } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  referralCodes,
  type SelectReferralCode,
  referralRedemptions,
  type SelectReferralRedemption,
} from '@meritum/shared/schemas/db/platform.schema.js';

// ---------------------------------------------------------------------------
// Referral Code Repository
// ---------------------------------------------------------------------------

export function createReferralCodeRepository(db: NodePgDatabase) {
  return {
    async createReferralCode(
      referrerUserId: string,
      code: string,
    ): Promise<SelectReferralCode> {
      const rows = await db
        .insert(referralCodes)
        .values({ referrerUserId, code })
        .returning();
      return rows[0];
    },

    async findReferralCodeByCode(
      code: string,
    ): Promise<SelectReferralCode | undefined> {
      const rows = await db
        .select()
        .from(referralCodes)
        .where(eq(referralCodes.code, code))
        .limit(1);
      return rows[0];
    },

    async findReferralCodeByUserId(
      userId: string,
    ): Promise<SelectReferralCode | undefined> {
      const rows = await db
        .select()
        .from(referralCodes)
        .where(
          and(
            eq(referralCodes.referrerUserId, userId),
            eq(referralCodes.isActive, true),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async deactivateReferralCode(
      referralCodeId: string,
    ): Promise<SelectReferralCode | undefined> {
      const rows = await db
        .update(referralCodes)
        .set({ isActive: false })
        .where(eq(referralCodes.referralCodeId, referralCodeId))
        .returning();
      return rows[0];
    },
  };
}

export type ReferralCodeRepository = ReturnType<
  typeof createReferralCodeRepository
>;

// ---------------------------------------------------------------------------
// Referral Redemption Repository
// ---------------------------------------------------------------------------

export function createReferralRedemptionRepository(db: NodePgDatabase) {
  return {
    async createRedemption(data: {
      referralCodeId: string;
      referrerUserId: string;
      referredUserId: string;
      anniversaryYear: number;
    }): Promise<SelectReferralRedemption> {
      const rows = await db
        .insert(referralRedemptions)
        .values({
          referralCodeId: data.referralCodeId,
          referrerUserId: data.referrerUserId,
          referredUserId: data.referredUserId,
          anniversaryYear: data.anniversaryYear,
          status: 'PENDING',
        })
        .returning();
      return rows[0];
    },

    async findPendingByReferredUser(
      referredUserId: string,
    ): Promise<SelectReferralRedemption | undefined> {
      const rows = await db
        .select()
        .from(referralRedemptions)
        .where(
          and(
            eq(referralRedemptions.referredUserId, referredUserId),
            eq(referralRedemptions.status, 'PENDING'),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async countQualifiedOrCreditedByReferrerAndYear(
      referrerUserId: string,
      anniversaryYear: number,
    ): Promise<number> {
      const rows = await db
        .select({ count: count() })
        .from(referralRedemptions)
        .where(
          and(
            eq(referralRedemptions.referrerUserId, referrerUserId),
            eq(referralRedemptions.anniversaryYear, anniversaryYear),
            inArray(referralRedemptions.status, ['QUALIFIED', 'CREDITED']),
          ),
        );
      return rows[0]?.count ?? 0;
    },

    async updateRedemptionStatus(
      redemptionId: string,
      data: Partial<{
        status: string;
        creditMonthValueCad: string;
        creditAppliedTo: string;
        creditAppliedAt: Date;
        qualifyingEventAt: Date;
      }>,
    ): Promise<SelectReferralRedemption | undefined> {
      const rows = await db
        .update(referralRedemptions)
        .set(data)
        .where(eq(referralRedemptions.redemptionId, redemptionId))
        .returning();
      return rows[0];
    },

    async findRedemptionsByReferrer(
      referrerUserId: string,
      filters?: { status?: string; anniversaryYear?: number },
    ): Promise<SelectReferralRedemption[]> {
      const conditions = [
        eq(referralRedemptions.referrerUserId, referrerUserId),
      ];

      if (filters?.status) {
        conditions.push(eq(referralRedemptions.status, filters.status));
      }
      if (filters?.anniversaryYear !== undefined) {
        conditions.push(
          eq(referralRedemptions.anniversaryYear, filters.anniversaryYear),
        );
      }

      return db
        .select()
        .from(referralRedemptions)
        .where(and(...conditions))
        .orderBy(desc(referralRedemptions.createdAt));
    },

    async findPendingRedemptions(): Promise<SelectReferralRedemption[]> {
      return db
        .select()
        .from(referralRedemptions)
        .where(eq(referralRedemptions.status, 'PENDING'));
    },

    async findQualifiedRedemptions(): Promise<SelectReferralRedemption[]> {
      return db
        .select()
        .from(referralRedemptions)
        .where(eq(referralRedemptions.status, 'QUALIFIED'));
    },

    async findRedemptionById(
      redemptionId: string,
    ): Promise<SelectReferralRedemption | undefined> {
      const rows = await db
        .select()
        .from(referralRedemptions)
        .where(eq(referralRedemptions.redemptionId, redemptionId))
        .limit(1);
      return rows[0];
    },
  };
}

export type ReferralRedemptionRepository = ReturnType<
  typeof createReferralRedemptionRepository
>;
