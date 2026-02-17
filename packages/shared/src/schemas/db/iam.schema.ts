// ============================================================================
// Domain 1: Identity & Access Management — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  text,
  integer,
  timestamp,
  jsonb,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

// --- Users Table ---

export const users = pgTable(
  'users',
  {
    userId: uuid('user_id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).notNull(),
    passwordHash: varchar('password_hash', { length: 255 }).notNull(),
    fullName: varchar('full_name', { length: 200 }).notNull(),
    phone: varchar('phone', { length: 20 }),
    role: varchar('role', { length: 20 }).notNull().default('physician'),
    emailVerified: boolean('email_verified').notNull().default(false),
    mfaConfigured: boolean('mfa_configured').notNull().default(false),
    totpSecretEncrypted: text('totp_secret_encrypted'),
    subscriptionStatus: varchar('subscription_status', { length: 20 })
      .notNull()
      .default('trial'),
    failedLoginCount: integer('failed_login_count').notNull().default(0),
    lockedUntil: timestamp('locked_until', { withTimezone: true }),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('users_email_idx').on(table.email),
    index('users_role_is_active_idx').on(table.role, table.isActive),
    index('users_subscription_status_idx').on(table.subscriptionStatus),
  ],
);

// --- Recovery Codes Table ---

export const recoveryCodes = pgTable(
  'recovery_codes',
  {
    codeId: uuid('code_id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.userId),
    codeHash: varchar('code_hash', { length: 255 }).notNull(),
    used: boolean('used').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('recovery_codes_user_id_used_idx').on(table.userId, table.used),
  ],
);

// --- Sessions Table ---

export const sessions = pgTable(
  'sessions',
  {
    sessionId: uuid('session_id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.userId),
    tokenHash: varchar('token_hash', { length: 255 }).notNull(),
    ipAddress: varchar('ip_address', { length: 45 }).notNull(),
    userAgent: text('user_agent').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastActiveAt: timestamp('last_active_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    revoked: boolean('revoked').notNull().default(false),
    revokedReason: varchar('revoked_reason', { length: 30 }),
  },
  (table) => [
    uniqueIndex('sessions_token_hash_idx').on(table.tokenHash),
    index('sessions_user_id_revoked_idx').on(table.userId, table.revoked),
    index('sessions_last_active_at_idx').on(table.lastActiveAt),
  ],
);

// --- Invitation Tokens Table ---

export const invitationTokens = pgTable(
  'invitation_tokens',
  {
    invitationId: uuid('invitation_id').primaryKey().defaultRandom(),
    physicianUserId: uuid('physician_user_id')
      .notNull()
      .references(() => users.userId),
    delegateEmail: varchar('delegate_email', { length: 255 }).notNull(),
    tokenHash: varchar('token_hash', { length: 255 }).notNull(),
    permissions: jsonb('permissions').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    accepted: boolean('accepted').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('invitation_tokens_token_hash_idx').on(table.tokenHash),
    index('invitation_tokens_physician_accepted_idx').on(
      table.physicianUserId,
      table.accepted,
    ),
  ],
);

// --- Delegate Linkages Table ---

export const delegateLinkages = pgTable(
  'delegate_linkages',
  {
    linkageId: uuid('linkage_id').primaryKey().defaultRandom(),
    physicianUserId: uuid('physician_user_id')
      .notNull()
      .references(() => users.userId),
    delegateUserId: uuid('delegate_user_id')
      .notNull()
      .references(() => users.userId),
    permissions: jsonb('permissions').notNull().$type<string[]>(),
    canApproveBatches: boolean('can_approve_batches').notNull().default(false),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('delegate_linkages_physician_delegate_idx').on(
      table.physicianUserId,
      table.delegateUserId,
    ),
    index('delegate_linkages_delegate_is_active_idx').on(
      table.delegateUserId,
      table.isActive,
    ),
  ],
);

// --- Audit Log Table ---
// CRITICAL: Append-only. No UPDATE or DELETE operations. 7-year retention.

export const auditLog = pgTable(
  'audit_log',
  {
    logId: uuid('log_id').primaryKey().defaultRandom(),
    userId: uuid('user_id').references(() => users.userId),
    action: varchar('action', { length: 50 }).notNull(),
    category: varchar('category', { length: 20 }).notNull(),
    resourceType: varchar('resource_type', { length: 50 }),
    resourceId: uuid('resource_id'),
    detail: jsonb('detail').$type<Record<string, unknown>>(),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('audit_log_user_id_created_at_idx').on(table.userId, table.createdAt),
    index('audit_log_action_created_at_idx').on(table.action, table.createdAt),
    index('audit_log_resource_type_resource_id_created_at_idx').on(
      table.resourceType,
      table.resourceId,
      table.createdAt,
    ),
  ],
);

// --- Inferred Types ---

export type InsertUser = typeof users.$inferInsert;
export type SelectUser = typeof users.$inferSelect;

export type InsertRecoveryCode = typeof recoveryCodes.$inferInsert;
export type SelectRecoveryCode = typeof recoveryCodes.$inferSelect;

export type InsertSession = typeof sessions.$inferInsert;
export type SelectSession = typeof sessions.$inferSelect;

export type InsertInvitationToken = typeof invitationTokens.$inferInsert;
export type SelectInvitationToken = typeof invitationTokens.$inferSelect;

export type InsertDelegateLinkage = typeof delegateLinkages.$inferInsert;
export type SelectDelegateLinkage = typeof delegateLinkages.$inferSelect;

export type InsertAuditLog = typeof auditLog.$inferInsert;
export type SelectAuditLog = typeof auditLog.$inferSelect;
