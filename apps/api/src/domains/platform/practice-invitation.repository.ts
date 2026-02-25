import { eq, and, lte, sql } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  practiceInvitations,
  type InsertPracticeInvitation,
  type SelectPracticeInvitation,
} from '@meritum/shared/schemas/db/platform.schema.js';

// ---------------------------------------------------------------------------
// Practice Invitation Repository
// ---------------------------------------------------------------------------

export function createPracticeInvitationRepository(db: NodePgDatabase) {
  return {
    async createInvitation(
      data: InsertPracticeInvitation,
    ): Promise<SelectPracticeInvitation> {
      const rows = await db
        .insert(practiceInvitations)
        .values(data)
        .returning();
      return rows[0];
    },

    async findInvitationByTokenHash(
      tokenHash: string,
    ): Promise<SelectPracticeInvitation | null> {
      const rows = await db
        .select()
        .from(practiceInvitations)
        .where(eq(practiceInvitations.tokenHash, tokenHash))
        .limit(1);
      return rows[0] ?? null;
    },

    async findPendingInvitationByEmail(
      email: string,
      practiceId: string,
    ): Promise<SelectPracticeInvitation | null> {
      const rows = await db
        .select()
        .from(practiceInvitations)
        .where(
          and(
            eq(practiceInvitations.invitedEmail, email.toLowerCase()),
            eq(practiceInvitations.practiceId, practiceId),
            eq(practiceInvitations.status, 'PENDING'),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    async findPendingInvitationsByPracticeId(
      practiceId: string,
    ): Promise<SelectPracticeInvitation[]> {
      return db
        .select()
        .from(practiceInvitations)
        .where(
          and(
            eq(practiceInvitations.practiceId, practiceId),
            eq(practiceInvitations.status, 'PENDING'),
          ),
        );
    },

    async updateInvitationStatus(
      invitationId: string,
      status: string,
    ): Promise<void> {
      await db
        .update(practiceInvitations)
        .set({ status })
        .where(eq(practiceInvitations.invitationId, invitationId));
    },

    async expireInvitations(cutoffDate: Date): Promise<number> {
      const result = await db
        .update(practiceInvitations)
        .set({ status: 'EXPIRED' })
        .where(
          and(
            eq(practiceInvitations.status, 'PENDING'),
            lte(practiceInvitations.expiresAt, cutoffDate),
          ),
        )
        .returning();
      return result.length;
    },

    async findInvitationsByEmail(
      email: string,
    ): Promise<SelectPracticeInvitation[]> {
      return db
        .select()
        .from(practiceInvitations)
        .where(eq(practiceInvitations.invitedEmail, email.toLowerCase()));
    },
  };
}

export type PracticeInvitationRepository = ReturnType<
  typeof createPracticeInvitationRepository
>;
