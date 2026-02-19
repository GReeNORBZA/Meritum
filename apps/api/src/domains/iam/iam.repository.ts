import { eq, and, lt, gt, gte, lte, ne, desc, sql } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  users,
  sessions,
  recoveryCodes,
  invitationTokens,
  delegateLinkages,
  auditLog,
  type InsertUser,
  type SelectUser,
  type SelectSession,
  type SelectRecoveryCode,
  type SelectInvitationToken,
  type SelectDelegateLinkage,
  type SelectAuditLog,
} from '@meritum/shared/schemas/db/iam.schema.js';
import { type SessionRevokeReason } from '@meritum/shared/constants/iam.constants.js';

/** Fields that updateUser must never modify — use dedicated functions instead. */
const PROTECTED_FIELDS = new Set<string>([
  'email',
  'passwordHash',
  'totpSecretEncrypted',
]);

type UpdateUserData = Partial<
  Pick<
    InsertUser,
    | 'fullName'
    | 'phone'
    | 'role'
    | 'emailVerified'
    | 'subscriptionStatus'
  >
>;

export function createUserRepository(db: NodePgDatabase) {
  return {
    async createUser(data: InsertUser): Promise<SelectUser> {
      const rows = await db
        .insert(users)
        .values({ ...data, email: data.email.toLowerCase() })
        .returning();
      return rows[0];
    },

    async findUserByEmail(email: string): Promise<SelectUser | undefined> {
      const rows = await db
        .select()
        .from(users)
        .where(and(eq(users.email, email.toLowerCase()), eq(users.isActive, true)))
        .limit(1);
      return rows[0];
    },

    async findUserById(userId: string): Promise<SelectUser | undefined> {
      const rows = await db
        .select()
        .from(users)
        .where(eq(users.userId, userId))
        .limit(1);
      return rows[0];
    },

    async updateUser(
      userId: string,
      data: UpdateUserData,
    ): Promise<SelectUser | undefined> {
      // Strip protected fields if they somehow sneak in
      const sanitised = { ...data } as Record<string, unknown>;
      for (const key of PROTECTED_FIELDS) {
        delete sanitised[key];
      }

      const rows = await db
        .update(users)
        .set({ ...sanitised, updatedAt: new Date() })
        .where(eq(users.userId, userId))
        .returning();
      return rows[0];
    },

    async incrementFailedLogin(userId: string): Promise<void> {
      // Atomically increment; lock after 10 failures (30-minute window)
      await db
        .update(users)
        .set({
          failedLoginCount: sql`${users.failedLoginCount} + 1`,
          lockedUntil: sql`CASE WHEN ${users.failedLoginCount} + 1 >= 10 THEN now() + interval '30 minutes' ELSE ${users.lockedUntil} END`,
          updatedAt: new Date(),
        })
        .where(eq(users.userId, userId));
    },

    async resetFailedLogin(userId: string): Promise<void> {
      await db
        .update(users)
        .set({
          failedLoginCount: 0,
          lockedUntil: null,
          updatedAt: new Date(),
        })
        .where(eq(users.userId, userId));
    },

    async isAccountLocked(userId: string): Promise<boolean> {
      const rows = await db
        .select({
          locked: sql<boolean>`${users.lockedUntil} > now()`,
        })
        .from(users)
        .where(eq(users.userId, userId))
        .limit(1);

      return rows[0]?.locked === true;
    },

    async setMfaSecret(
      userId: string,
      encryptedSecret: string,
    ): Promise<void> {
      await db
        .update(users)
        .set({
          totpSecretEncrypted: encryptedSecret,
          updatedAt: new Date(),
        })
        .where(eq(users.userId, userId));
    },

    async setMfaConfigured(userId: string): Promise<void> {
      await db
        .update(users)
        .set({
          mfaConfigured: true,
          updatedAt: new Date(),
        })
        .where(eq(users.userId, userId));
    },

    async deactivateUser(userId: string): Promise<void> {
      await db
        .update(users)
        .set({
          isActive: false,
          updatedAt: new Date(),
        })
        .where(eq(users.userId, userId));
    },
  };
}

export type IamRepository = ReturnType<typeof createUserRepository>;

// ---------------------------------------------------------------------------
// Session expiry constants
// ---------------------------------------------------------------------------

/** Absolute session lifetime: 24 hours from creation. */
const ABSOLUTE_EXPIRY_MS = 24 * 60 * 60 * 1000;
/** Idle session timeout: 60 minutes from last activity. */
const IDLE_EXPIRY_MS = 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Session Repository
// ---------------------------------------------------------------------------

interface CreateSessionData {
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
}

export interface SessionWithUser {
  session: SelectSession;
  user: Pick<SelectUser, 'userId' | 'role' | 'subscriptionStatus'>;
}

export function isSessionExpired(session: SelectSession): boolean {
  const now = Date.now();
  const createdAt = new Date(session.createdAt).getTime();
  const lastActiveAt = new Date(session.lastActiveAt).getTime();

  if (now - createdAt > ABSOLUTE_EXPIRY_MS) return true;
  if (now - lastActiveAt > IDLE_EXPIRY_MS) return true;
  return false;
}

export function createSessionRepository(db: NodePgDatabase) {
  return {
    async createSession(data: CreateSessionData): Promise<SelectSession> {
      const rows = await db
        .insert(sessions)
        .values(data)
        .returning();
      return rows[0];
    },

    async findSessionByTokenHash(
      tokenHash: string,
    ): Promise<SessionWithUser | undefined> {
      // Constant-time: comparison happens in the DB via WHERE clause.
      // We also filter revoked=false in the query to avoid returning revoked sessions.
      const rows = await db
        .select({
          session: sessions,
          user: {
            userId: users.userId,
            role: users.role,
            subscriptionStatus: users.subscriptionStatus,
          },
        })
        .from(sessions)
        .innerJoin(users, eq(sessions.userId, users.userId))
        .where(
          and(
            eq(sessions.tokenHash, tokenHash),
            eq(sessions.revoked, false),
          ),
        )
        .limit(1);

      if (rows.length === 0) return undefined;

      const row = rows[0];
      // Check expiry at the application level (cannot be done precisely in SQL
      // with Drizzle's type-safe builder for both absolute and idle checks).
      if (isSessionExpired(row.session)) return undefined;

      return row;
    },

    async refreshSession(sessionId: string): Promise<void> {
      await db
        .update(sessions)
        .set({ lastActiveAt: new Date() })
        .where(eq(sessions.sessionId, sessionId));
    },

    async revokeSession(
      sessionId: string,
      reason: SessionRevokeReason,
    ): Promise<void> {
      await db
        .update(sessions)
        .set({ revoked: true, revokedReason: reason })
        .where(eq(sessions.sessionId, sessionId));
    },

    async revokeAllUserSessions(
      userId: string,
      exceptSessionId: string | undefined,
      reason: SessionRevokeReason,
    ): Promise<void> {
      const conditions = [
        eq(sessions.userId, userId),
        eq(sessions.revoked, false),
      ];
      if (exceptSessionId) {
        conditions.push(ne(sessions.sessionId, exceptSessionId));
      }
      await db
        .update(sessions)
        .set({ revoked: true, revokedReason: reason })
        .where(and(...conditions));
    },

    async listActiveSessions(userId: string): Promise<SelectSession[]> {
      return db
        .select()
        .from(sessions)
        .where(
          and(
            eq(sessions.userId, userId),
            eq(sessions.revoked, false),
          ),
        );
    },

    isSessionExpired,

    async cleanupExpiredSessions(): Promise<void> {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      await db
        .delete(sessions)
        .where(
          and(
            eq(sessions.revoked, true),
            lt(sessions.createdAt, thirtyDaysAgo),
          ),
        );
    },
  };
}

export type SessionRepository = ReturnType<typeof createSessionRepository>;

// ---------------------------------------------------------------------------
// Recovery Code Repository
// ---------------------------------------------------------------------------

export function createRecoveryCodeRepository(db: NodePgDatabase) {
  return {
    async createRecoveryCodes(
      userId: string,
      codeHashes: string[],
    ): Promise<SelectRecoveryCode[]> {
      // Delete existing unused codes first — regeneration invalidates all previous codes
      await db
        .delete(recoveryCodes)
        .where(
          and(
            eq(recoveryCodes.userId, userId),
            eq(recoveryCodes.used, false),
          ),
        );

      const rows = await db
        .insert(recoveryCodes)
        .values(codeHashes.map((codeHash) => ({ userId, codeHash })))
        .returning();

      return rows;
    },

    async findUnusedRecoveryCodes(
      userId: string,
    ): Promise<SelectRecoveryCode[]> {
      return db
        .select()
        .from(recoveryCodes)
        .where(
          and(
            eq(recoveryCodes.userId, userId),
            eq(recoveryCodes.used, false),
          ),
        );
    },

    async markRecoveryCodeUsed(codeId: string): Promise<void> {
      await db
        .update(recoveryCodes)
        .set({ used: true })
        .where(eq(recoveryCodes.codeId, codeId));
    },

    async countRemainingCodes(userId: string): Promise<number> {
      const rows = await db
        .select()
        .from(recoveryCodes)
        .where(
          and(
            eq(recoveryCodes.userId, userId),
            eq(recoveryCodes.used, false),
          ),
        );
      return rows.length;
    },
  };
}

export type RecoveryCodeRepository = ReturnType<typeof createRecoveryCodeRepository>;

// ---------------------------------------------------------------------------
// Invitation Token Repository
// ---------------------------------------------------------------------------

interface CreateInvitationData {
  physicianUserId: string;
  delegateEmail: string;
  tokenHash: string;
  permissions: string[];
  expiresAt: Date;
}

export function createInvitationRepository(db: NodePgDatabase) {
  return {
    async createInvitation(
      data: CreateInvitationData,
    ): Promise<SelectInvitationToken> {
      const rows = await db
        .insert(invitationTokens)
        .values({
          physicianUserId: data.physicianUserId,
          delegateEmail: data.delegateEmail.toLowerCase(),
          tokenHash: data.tokenHash,
          permissions: data.permissions,
          expiresAt: data.expiresAt,
        })
        .returning();
      return rows[0];
    },

    async findInvitationByTokenHash(
      tokenHash: string,
    ): Promise<SelectInvitationToken | undefined> {
      const rows = await db
        .select()
        .from(invitationTokens)
        .where(
          and(
            eq(invitationTokens.tokenHash, tokenHash),
            eq(invitationTokens.accepted, false),
            gt(invitationTokens.expiresAt, new Date()),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async markInvitationAccepted(invitationId: string): Promise<void> {
      await db
        .update(invitationTokens)
        .set({ accepted: true })
        .where(eq(invitationTokens.invitationId, invitationId));
    },

    async listPendingInvitations(
      physicianUserId: string,
    ): Promise<SelectInvitationToken[]> {
      return db
        .select()
        .from(invitationTokens)
        .where(
          and(
            eq(invitationTokens.physicianUserId, physicianUserId),
            eq(invitationTokens.accepted, false),
            gt(invitationTokens.expiresAt, new Date()),
          ),
        );
    },
  };
}

export type InvitationRepository = ReturnType<typeof createInvitationRepository>;

// ---------------------------------------------------------------------------
// Delegate Linkage Repository
// ---------------------------------------------------------------------------

interface CreateDelegateLinkageData {
  physicianUserId: string;
  delegateUserId: string;
  permissions: string[];
  canApproveBatches: boolean;
}

export interface DelegateWithUserInfo {
  linkage: SelectDelegateLinkage;
  user: Pick<SelectUser, 'userId' | 'fullName' | 'email'>;
  lastLogin: Date | null;
}

export interface PhysicianForDelegate {
  linkage: SelectDelegateLinkage;
  physician: Pick<SelectUser, 'userId' | 'fullName' | 'email'>;
}

export function createDelegateLinkageRepository(db: NodePgDatabase) {
  return {
    async createDelegateLinkage(
      data: CreateDelegateLinkageData,
    ): Promise<SelectDelegateLinkage> {
      const rows = await db
        .insert(delegateLinkages)
        .values({
          physicianUserId: data.physicianUserId,
          delegateUserId: data.delegateUserId,
          permissions: data.permissions,
          canApproveBatches: data.canApproveBatches,
        })
        .returning();
      return rows[0];
    },

    async findLinkage(
      physicianUserId: string,
      delegateUserId: string,
    ): Promise<SelectDelegateLinkage | undefined> {
      const rows = await db
        .select()
        .from(delegateLinkages)
        .where(
          and(
            eq(delegateLinkages.physicianUserId, physicianUserId),
            eq(delegateLinkages.delegateUserId, delegateUserId),
            eq(delegateLinkages.isActive, true),
          ),
        )
        .limit(1);
      return rows[0];
    },

    async findLinkageById(
      linkageId: string,
    ): Promise<SelectDelegateLinkage | undefined> {
      const rows = await db
        .select()
        .from(delegateLinkages)
        .where(eq(delegateLinkages.linkageId, linkageId))
        .limit(1);
      return rows[0];
    },

    async listDelegatesForPhysician(
      physicianUserId: string,
    ): Promise<DelegateWithUserInfo[]> {
      const rows = await db
        .select({
          linkage: delegateLinkages,
          user: {
            userId: users.userId,
            fullName: users.fullName,
            email: users.email,
          },
        })
        .from(delegateLinkages)
        .innerJoin(users, eq(delegateLinkages.delegateUserId, users.userId))
        .where(
          and(
            eq(delegateLinkages.physicianUserId, physicianUserId),
            eq(delegateLinkages.isActive, true),
          ),
        );

      // Enrich with last login from sessions (most recent non-revoked session)
      const result: DelegateWithUserInfo[] = [];
      for (const row of rows) {
        const sessionRows = await db
          .select({ lastActiveAt: sessions.lastActiveAt })
          .from(sessions)
          .where(
            and(
              eq(sessions.userId, row.user.userId),
              eq(sessions.revoked, false),
            ),
          )
          .limit(1);

        result.push({
          linkage: row.linkage,
          user: row.user,
          lastLogin: sessionRows[0]?.lastActiveAt ?? null,
        });
      }

      return result;
    },

    async listPhysiciansForDelegate(
      delegateUserId: string,
    ): Promise<PhysicianForDelegate[]> {
      const rows = await db
        .select({
          linkage: delegateLinkages,
          physician: {
            userId: users.userId,
            fullName: users.fullName,
            email: users.email,
          },
        })
        .from(delegateLinkages)
        .innerJoin(users, eq(delegateLinkages.physicianUserId, users.userId))
        .where(
          and(
            eq(delegateLinkages.delegateUserId, delegateUserId),
            eq(delegateLinkages.isActive, true),
          ),
        );

      return rows;
    },

    async updateLinkagePermissions(
      linkageId: string,
      permissions: string[],
      canApproveBatches: boolean,
    ): Promise<SelectDelegateLinkage | undefined> {
      const rows = await db
        .update(delegateLinkages)
        .set({
          permissions,
          canApproveBatches,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(delegateLinkages.linkageId, linkageId),
            eq(delegateLinkages.isActive, true),
          ),
        )
        .returning();
      return rows[0];
    },

    async deactivateLinkage(
      linkageId: string,
    ): Promise<SelectDelegateLinkage | undefined> {
      const rows = await db
        .update(delegateLinkages)
        .set({
          isActive: false,
          updatedAt: new Date(),
        })
        .where(eq(delegateLinkages.linkageId, linkageId))
        .returning();
      return rows[0];
    },
  };
}

export type DelegateLinkageRepository = ReturnType<typeof createDelegateLinkageRepository>;

// ---------------------------------------------------------------------------
// Audit Log Repository (APPEND-ONLY — no update, no delete)
// ---------------------------------------------------------------------------

/** Sensitive keys that must never appear in the audit log detail field. */
const SANITISED_DETAIL_KEYS = new Set([
  'password',
  'passwordHash',
  'password_hash',
  'newPassword',
  'new_password',
  'currentPassword',
  'current_password',
  'token',
  'tokenHash',
  'token_hash',
  'totpSecret',
  'totp_secret',
  'totpSecretEncrypted',
  'totp_secret_encrypted',
  'sessionToken',
  'session_token',
  'mfa_session_token',
  'recovery_code',
  'codeHash',
  'code_hash',
]);

/** Recursively strip sensitive keys from a JSONB detail object. */
function sanitiseDetail(
  detail: Record<string, unknown> | null | undefined,
): Record<string, unknown> | null {
  if (!detail) return null;

  const sanitised: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(detail)) {
    if (SANITISED_DETAIL_KEYS.has(key)) {
      sanitised[key] = '[REDACTED]';
    } else if (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value)
    ) {
      sanitised[key] = sanitiseDetail(value as Record<string, unknown>);
    } else {
      sanitised[key] = value;
    }
  }
  return sanitised;
}

interface AppendAuditLogEntry {
  userId?: string | null;
  action: string;
  category: string;
  resourceType?: string | null;
  resourceId?: string | null;
  detail?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

interface AuditLogFilters {
  action?: string;
  category?: string;
  startDate?: string; // ISO 8601 date string
  endDate?: string;   // ISO 8601 date string
  page?: number;
  pageSize?: number;
}

export function createAuditLogRepository(db: NodePgDatabase) {
  return {
    /**
     * Append a single audit log entry. This is the ONLY write operation
     * on the audit_log table. No update, no delete.
     */
    async appendAuditLog(entry: AppendAuditLogEntry): Promise<SelectAuditLog> {
      const rows = await db
        .insert(auditLog)
        .values({
          userId: entry.userId ?? undefined,
          action: entry.action,
          category: entry.category,
          resourceType: entry.resourceType ?? undefined,
          resourceId: entry.resourceId ?? undefined,
          detail: sanitiseDetail(entry.detail),
          ipAddress: entry.ipAddress ?? undefined,
          userAgent: entry.userAgent ?? undefined,
        })
        .returning();
      return rows[0];
    },

    /**
     * Query audit log scoped to a specific user. Paginated, reverse
     * chronological order. Max 200 per page.
     */
    async queryAuditLog(
      userId: string,
      filters: AuditLogFilters = {},
    ): Promise<{ data: SelectAuditLog[]; total: number }> {
      const page = filters.page ?? 1;
      const pageSize = Math.min(filters.pageSize ?? 50, 200);
      const offset = (page - 1) * pageSize;

      const conditions = [eq(auditLog.userId, userId)];

      if (filters.action) {
        conditions.push(eq(auditLog.action, filters.action));
      }
      if (filters.category) {
        conditions.push(eq(auditLog.category, filters.category));
      }
      if (filters.startDate) {
        conditions.push(gte(auditLog.createdAt, new Date(filters.startDate)));
      }
      if (filters.endDate) {
        // endDate is inclusive: include the entire end day
        const endOfDay = new Date(filters.endDate);
        endOfDay.setUTCHours(23, 59, 59, 999);
        conditions.push(lte(auditLog.createdAt, endOfDay));
      }

      const data = await db
        .select()
        .from(auditLog)
        .where(and(...conditions))
        .orderBy(desc(auditLog.createdAt))
        .limit(pageSize)
        .offset(offset);

      // Count total matching entries for pagination
      const allMatching = await db
        .select()
        .from(auditLog)
        .where(and(...conditions));

      return { data, total: allMatching.length };
    },

    /**
     * Admin-only: query audit log across ALL users. The route guard
     * enforces admin role; the repository does not check it.
     */
    async querySystemAuditLog(
      filters: AuditLogFilters = {},
    ): Promise<{ data: SelectAuditLog[]; total: number }> {
      const page = filters.page ?? 1;
      const pageSize = Math.min(filters.pageSize ?? 50, 200);
      const offset = (page - 1) * pageSize;

      const conditions: ReturnType<typeof eq>[] = [];

      if (filters.action) {
        conditions.push(eq(auditLog.action, filters.action));
      }
      if (filters.category) {
        conditions.push(eq(auditLog.category, filters.category));
      }
      if (filters.startDate) {
        conditions.push(gte(auditLog.createdAt, new Date(filters.startDate)));
      }
      if (filters.endDate) {
        const endOfDay = new Date(filters.endDate);
        endOfDay.setUTCHours(23, 59, 59, 999);
        conditions.push(lte(auditLog.createdAt, endOfDay));
      }

      const whereClause =
        conditions.length > 0 ? and(...conditions) : undefined;

      const data = await db
        .select()
        .from(auditLog)
        .where(whereClause)
        .orderBy(desc(auditLog.createdAt))
        .limit(pageSize)
        .offset(offset);

      const allMatching = await db
        .select()
        .from(auditLog)
        .where(whereClause);

      return { data, total: allMatching.length };
    },

    /**
     * Export audit log for a specific user. Returns all matching entries
     * (no pagination limit). Date range is required by the caller (service layer).
     */
    async exportAuditLog(
      userId: string,
      filters: AuditLogFilters,
    ): Promise<SelectAuditLog[]> {
      if (!filters.startDate || !filters.endDate) {
        throw new Error('exportAuditLog requires both startDate and endDate');
      }

      const endOfDay = new Date(filters.endDate);
      endOfDay.setUTCHours(23, 59, 59, 999);

      const conditions = [
        eq(auditLog.userId, userId),
        gte(auditLog.createdAt, new Date(filters.startDate)),
        lte(auditLog.createdAt, endOfDay),
      ];

      if (filters.action) {
        conditions.push(eq(auditLog.action, filters.action));
      }
      if (filters.category) {
        conditions.push(eq(auditLog.category, filters.category));
      }

      return db
        .select()
        .from(auditLog)
        .where(and(...conditions))
        .orderBy(desc(auditLog.createdAt));
    },
  };
}

export type AuditLogRepository = ReturnType<typeof createAuditLogRepository>;
