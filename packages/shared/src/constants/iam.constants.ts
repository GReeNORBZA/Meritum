// ============================================================================
// Domain 1: Identity & Access Management — Constants
// ============================================================================

// --- Roles ---

export const Role = {
  PHYSICIAN: 'PHYSICIAN',
  DELEGATE: 'DELEGATE',
  ADMIN: 'ADMIN',
} as const;

export type Role = (typeof Role)[keyof typeof Role];

// --- Permission Keys (24 total) ---

export const Permission = {
  CLAIM_CREATE: 'CLAIM_CREATE',
  CLAIM_VIEW: 'CLAIM_VIEW',
  CLAIM_EDIT: 'CLAIM_EDIT',
  CLAIM_DELETE: 'CLAIM_DELETE',
  CLAIM_SUBMIT: 'CLAIM_SUBMIT',

  BATCH_VIEW: 'BATCH_VIEW',
  BATCH_APPROVE: 'BATCH_APPROVE',

  PATIENT_CREATE: 'PATIENT_CREATE',
  PATIENT_VIEW: 'PATIENT_VIEW',
  PATIENT_EDIT: 'PATIENT_EDIT',
  PATIENT_IMPORT: 'PATIENT_IMPORT',

  REPORT_VIEW: 'REPORT_VIEW',
  REPORT_EXPORT: 'REPORT_EXPORT',

  ANALYTICS_VIEW: 'ANALYTICS_VIEW',

  PROVIDER_VIEW: 'PROVIDER_VIEW',
  PROVIDER_EDIT: 'PROVIDER_EDIT',

  DELEGATE_MANAGE: 'DELEGATE_MANAGE',

  SUBSCRIPTION_MANAGE: 'SUBSCRIPTION_MANAGE',

  SETTINGS_VIEW: 'SETTINGS_VIEW',
  SETTINGS_EDIT: 'SETTINGS_EDIT',

  DATA_EXPORT: 'DATA_EXPORT',

  AUDIT_VIEW: 'AUDIT_VIEW',

  AI_COACH_VIEW: 'AI_COACH_VIEW',
  AI_COACH_MANAGE: 'AI_COACH_MANAGE',

  // Admin-only
  ADMIN_PHI_ACCESS: 'ADMIN_PHI_ACCESS',
} as const;

export type Permission = (typeof Permission)[keyof typeof Permission];

// --- All standard permissions (the 24 physician permissions) ---

const STANDARD_PERMISSIONS: readonly Permission[] = [
  Permission.CLAIM_CREATE,
  Permission.CLAIM_VIEW,
  Permission.CLAIM_EDIT,
  Permission.CLAIM_DELETE,
  Permission.CLAIM_SUBMIT,
  Permission.BATCH_VIEW,
  Permission.BATCH_APPROVE,
  Permission.PATIENT_CREATE,
  Permission.PATIENT_VIEW,
  Permission.PATIENT_EDIT,
  Permission.PATIENT_IMPORT,
  Permission.REPORT_VIEW,
  Permission.REPORT_EXPORT,
  Permission.ANALYTICS_VIEW,
  Permission.PROVIDER_VIEW,
  Permission.PROVIDER_EDIT,
  Permission.DELEGATE_MANAGE,
  Permission.SUBSCRIPTION_MANAGE,
  Permission.SETTINGS_VIEW,
  Permission.SETTINGS_EDIT,
  Permission.DATA_EXPORT,
  Permission.AUDIT_VIEW,
  Permission.AI_COACH_VIEW,
  Permission.AI_COACH_MANAGE,
] as const;

// --- Default Permission Sets per Role ---

export const DefaultPermissions = {
  [Role.PHYSICIAN]: STANDARD_PERMISSIONS,

  [Role.DELEGATE]: [
    Permission.CLAIM_CREATE,
    Permission.CLAIM_VIEW,
    Permission.CLAIM_EDIT,
    Permission.CLAIM_DELETE,
    Permission.CLAIM_SUBMIT,
    Permission.BATCH_VIEW,
    Permission.BATCH_APPROVE,
    Permission.PATIENT_CREATE,
    Permission.PATIENT_VIEW,
    Permission.PATIENT_EDIT,
    Permission.PATIENT_IMPORT,
    Permission.REPORT_VIEW,
    Permission.REPORT_EXPORT,
    Permission.ANALYTICS_VIEW,
    Permission.PROVIDER_VIEW,
    Permission.PROVIDER_EDIT,
    Permission.SETTINGS_VIEW,
    Permission.SETTINGS_EDIT,
    Permission.AI_COACH_VIEW,
    Permission.AI_COACH_MANAGE,
  ] as readonly Permission[],

  [Role.ADMIN]: [
    ...STANDARD_PERMISSIONS,
    Permission.ADMIN_PHI_ACCESS,
  ] as readonly Permission[],
} as const satisfies Record<Role, readonly Permission[]>;

// --- Audit Action Identifiers (28 categories) ---

export const AuditAction = {
  // Auth events (13)
  AUTH_REGISTERED: 'auth.registered',
  AUTH_EMAIL_VERIFIED: 'auth.email_verified',
  AUTH_MFA_SETUP: 'auth.mfa_setup',
  AUTH_LOGIN_SUCCESS: 'auth.login_success',
  AUTH_LOGIN_FAILED: 'auth.login_failed',
  AUTH_LOGIN_MFA_SUCCESS: 'auth.login_mfa_success',
  AUTH_LOGIN_MFA_FAILED: 'auth.login_mfa_failed',
  AUTH_LOGIN_RECOVERY_USED: 'auth.login_recovery_used',
  AUTH_LOGOUT: 'auth.logout',
  AUTH_SESSION_REVOKED: 'auth.session_revoked',
  AUTH_SESSION_REVOKED_ALL: 'auth.session_revoked_all',
  AUTH_PASSWORD_RESET_REQUESTED: 'auth.password_reset_requested',
  AUTH_PASSWORD_RESET_COMPLETED: 'auth.password_reset_completed',

  // Delegate events (5)
  DELEGATE_INVITED: 'delegate.invited',
  DELEGATE_ACCEPTED: 'delegate.accepted',
  DELEGATE_PERMISSIONS_UPDATED: 'delegate.permissions_updated',
  DELEGATE_REVOKED: 'delegate.revoked',
  DELEGATE_CONTEXT_SWITCHED: 'delegate.context_switched',

  // Account events (7)
  ACCOUNT_UPDATED: 'account.updated',
  ACCOUNT_MFA_RECONFIGURED: 'account.mfa_reconfigured',
  ACCOUNT_RECOVERY_CODES_REGENERATED: 'account.recovery_codes_regenerated',
  ACCOUNT_DELETION_REQUESTED: 'account.deletion_requested',
  ACCOUNT_DELETION_EXECUTED: 'account.deletion_executed',
  ACCOUNT_SUSPENDED: 'account.suspended',
  ACCOUNT_REACTIVATED: 'account.reactivated',

  // Audit events (2)
  AUDIT_QUERIED: 'audit.queried',
  AUDIT_EXPORTED: 'audit.exported',

  // Admin events (1)
  ADMIN_MFA_RESET_ISSUED: 'admin.mfa_reset_issued',
} as const;

export type AuditAction = (typeof AuditAction)[keyof typeof AuditAction];

// --- Audit Action Categories ---

export const AuditCategory = {
  AUTH: 'auth',
  DELEGATE: 'delegate',
  ACCOUNT: 'account',
  AUDIT: 'audit',
  ADMIN: 'admin',
} as const;

export type AuditCategory = (typeof AuditCategory)[keyof typeof AuditCategory];

// --- Subscription Statuses ---

export const SubscriptionStatus = {
  TRIAL: 'TRIAL',
  ACTIVE: 'ACTIVE',
  PAST_DUE: 'PAST_DUE',
  SUSPENDED: 'SUSPENDED',
  CANCELLED: 'CANCELLED',
} as const;

export type SubscriptionStatus =
  (typeof SubscriptionStatus)[keyof typeof SubscriptionStatus];

// --- Session Revoke Reasons ---

export const SessionRevokeReason = {
  LOGOUT: 'logout',
  EXPIRED_IDLE: 'expired_idle',
  EXPIRED_ABSOLUTE: 'expired_absolute',
  REVOKED_REMOTE: 'revoked_remote',
  PASSWORD_RESET: 'password_reset',
  ACCOUNT_DELETED: 'account_deleted',
} as const;

export type SessionRevokeReason =
  (typeof SessionRevokeReason)[keyof typeof SessionRevokeReason];
