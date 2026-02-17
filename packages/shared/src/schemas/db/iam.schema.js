"use strict";
// ============================================================================
// Domain 1: Identity & Access Management — Drizzle DB Schema
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditLog = exports.delegateLinkages = exports.invitationTokens = exports.sessions = exports.recoveryCodes = exports.users = void 0;
const pg_core_1 = require("drizzle-orm/pg-core");
// --- Users Table ---
exports.users = (0, pg_core_1.pgTable)('users', {
    userId: (0, pg_core_1.uuid)('user_id').primaryKey().defaultRandom(),
    email: (0, pg_core_1.varchar)('email', { length: 255 }).notNull(),
    passwordHash: (0, pg_core_1.varchar)('password_hash', { length: 255 }).notNull(),
    fullName: (0, pg_core_1.varchar)('full_name', { length: 200 }).notNull(),
    phone: (0, pg_core_1.varchar)('phone', { length: 20 }),
    role: (0, pg_core_1.varchar)('role', { length: 20 }).notNull().default('physician'),
    emailVerified: (0, pg_core_1.boolean)('email_verified').notNull().default(false),
    mfaConfigured: (0, pg_core_1.boolean)('mfa_configured').notNull().default(false),
    totpSecretEncrypted: (0, pg_core_1.text)('totp_secret_encrypted'),
    subscriptionStatus: (0, pg_core_1.varchar)('subscription_status', { length: 20 })
        .notNull()
        .default('trial'),
    failedLoginCount: (0, pg_core_1.integer)('failed_login_count').notNull().default(0),
    lockedUntil: (0, pg_core_1.timestamp)('locked_until', { withTimezone: true }),
    isActive: (0, pg_core_1.boolean)('is_active').notNull().default(true),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('users_email_idx').on(table.email),
    (0, pg_core_1.index)('users_role_is_active_idx').on(table.role, table.isActive),
    (0, pg_core_1.index)('users_subscription_status_idx').on(table.subscriptionStatus),
]);
// --- Recovery Codes Table ---
exports.recoveryCodes = (0, pg_core_1.pgTable)('recovery_codes', {
    codeId: (0, pg_core_1.uuid)('code_id').primaryKey().defaultRandom(),
    userId: (0, pg_core_1.uuid)('user_id')
        .notNull()
        .references(() => exports.users.userId),
    codeHash: (0, pg_core_1.varchar)('code_hash', { length: 255 }).notNull(),
    used: (0, pg_core_1.boolean)('used').notNull().default(false),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('recovery_codes_user_id_used_idx').on(table.userId, table.used),
]);
// --- Sessions Table ---
exports.sessions = (0, pg_core_1.pgTable)('sessions', {
    sessionId: (0, pg_core_1.uuid)('session_id').primaryKey().defaultRandom(),
    userId: (0, pg_core_1.uuid)('user_id')
        .notNull()
        .references(() => exports.users.userId),
    tokenHash: (0, pg_core_1.varchar)('token_hash', { length: 255 }).notNull(),
    ipAddress: (0, pg_core_1.varchar)('ip_address', { length: 45 }).notNull(),
    userAgent: (0, pg_core_1.text)('user_agent').notNull(),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
    lastActiveAt: (0, pg_core_1.timestamp)('last_active_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
    revoked: (0, pg_core_1.boolean)('revoked').notNull().default(false),
    revokedReason: (0, pg_core_1.varchar)('revoked_reason', { length: 30 }),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('sessions_token_hash_idx').on(table.tokenHash),
    (0, pg_core_1.index)('sessions_user_id_revoked_idx').on(table.userId, table.revoked),
    (0, pg_core_1.index)('sessions_last_active_at_idx').on(table.lastActiveAt),
]);
// --- Invitation Tokens Table ---
exports.invitationTokens = (0, pg_core_1.pgTable)('invitation_tokens', {
    invitationId: (0, pg_core_1.uuid)('invitation_id').primaryKey().defaultRandom(),
    physicianUserId: (0, pg_core_1.uuid)('physician_user_id')
        .notNull()
        .references(() => exports.users.userId),
    delegateEmail: (0, pg_core_1.varchar)('delegate_email', { length: 255 }).notNull(),
    tokenHash: (0, pg_core_1.varchar)('token_hash', { length: 255 }).notNull(),
    permissions: (0, pg_core_1.jsonb)('permissions').notNull(),
    expiresAt: (0, pg_core_1.timestamp)('expires_at', { withTimezone: true }).notNull(),
    accepted: (0, pg_core_1.boolean)('accepted').notNull().default(false),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('invitation_tokens_token_hash_idx').on(table.tokenHash),
    (0, pg_core_1.index)('invitation_tokens_physician_accepted_idx').on(table.physicianUserId, table.accepted),
]);
// --- Delegate Linkages Table ---
exports.delegateLinkages = (0, pg_core_1.pgTable)('delegate_linkages', {
    linkageId: (0, pg_core_1.uuid)('linkage_id').primaryKey().defaultRandom(),
    physicianUserId: (0, pg_core_1.uuid)('physician_user_id')
        .notNull()
        .references(() => exports.users.userId),
    delegateUserId: (0, pg_core_1.uuid)('delegate_user_id')
        .notNull()
        .references(() => exports.users.userId),
    permissions: (0, pg_core_1.jsonb)('permissions').notNull().$type(),
    canApproveBatches: (0, pg_core_1.boolean)('can_approve_batches').notNull().default(false),
    isActive: (0, pg_core_1.boolean)('is_active').notNull().default(true),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('delegate_linkages_physician_delegate_idx').on(table.physicianUserId, table.delegateUserId),
    (0, pg_core_1.index)('delegate_linkages_delegate_is_active_idx').on(table.delegateUserId, table.isActive),
]);
// --- Audit Log Table ---
// CRITICAL: Append-only. No UPDATE or DELETE operations. 7-year retention.
exports.auditLog = (0, pg_core_1.pgTable)('audit_log', {
    logId: (0, pg_core_1.uuid)('log_id').primaryKey().defaultRandom(),
    userId: (0, pg_core_1.uuid)('user_id').references(() => exports.users.userId),
    action: (0, pg_core_1.varchar)('action', { length: 50 }).notNull(),
    category: (0, pg_core_1.varchar)('category', { length: 20 }).notNull(),
    resourceType: (0, pg_core_1.varchar)('resource_type', { length: 50 }),
    resourceId: (0, pg_core_1.uuid)('resource_id'),
    detail: (0, pg_core_1.jsonb)('detail').$type(),
    ipAddress: (0, pg_core_1.varchar)('ip_address', { length: 45 }),
    userAgent: (0, pg_core_1.text)('user_agent'),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('audit_log_user_id_created_at_idx').on(table.userId, table.createdAt),
    (0, pg_core_1.index)('audit_log_action_created_at_idx').on(table.action, table.createdAt),
    (0, pg_core_1.index)('audit_log_resource_type_resource_id_created_at_idx').on(table.resourceType, table.resourceId, table.createdAt),
]);
//# sourceMappingURL=iam.schema.js.map