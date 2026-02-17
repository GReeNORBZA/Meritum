"use strict";
// ============================================================================
// Domain 1: Identity & Access Management — Constants
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionRevokeReason = exports.SubscriptionStatus = exports.AuditCategory = exports.AuditAction = exports.DefaultPermissions = exports.Permission = exports.Role = void 0;
// --- Roles ---
exports.Role = {
    PHYSICIAN: 'PHYSICIAN',
    DELEGATE: 'DELEGATE',
    ADMIN: 'ADMIN',
};
// --- Permission Keys (24 total) ---
exports.Permission = {
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
};
// --- All standard permissions (the 24 physician permissions) ---
const STANDARD_PERMISSIONS = [
    exports.Permission.CLAIM_CREATE,
    exports.Permission.CLAIM_VIEW,
    exports.Permission.CLAIM_EDIT,
    exports.Permission.CLAIM_DELETE,
    exports.Permission.CLAIM_SUBMIT,
    exports.Permission.BATCH_VIEW,
    exports.Permission.BATCH_APPROVE,
    exports.Permission.PATIENT_CREATE,
    exports.Permission.PATIENT_VIEW,
    exports.Permission.PATIENT_EDIT,
    exports.Permission.PATIENT_IMPORT,
    exports.Permission.REPORT_VIEW,
    exports.Permission.REPORT_EXPORT,
    exports.Permission.ANALYTICS_VIEW,
    exports.Permission.PROVIDER_VIEW,
    exports.Permission.PROVIDER_EDIT,
    exports.Permission.DELEGATE_MANAGE,
    exports.Permission.SUBSCRIPTION_MANAGE,
    exports.Permission.SETTINGS_VIEW,
    exports.Permission.SETTINGS_EDIT,
    exports.Permission.DATA_EXPORT,
    exports.Permission.AUDIT_VIEW,
    exports.Permission.AI_COACH_VIEW,
    exports.Permission.AI_COACH_MANAGE,
];
// --- Default Permission Sets per Role ---
exports.DefaultPermissions = {
    [exports.Role.PHYSICIAN]: STANDARD_PERMISSIONS,
    [exports.Role.DELEGATE]: [
        exports.Permission.CLAIM_CREATE,
        exports.Permission.CLAIM_VIEW,
        exports.Permission.CLAIM_EDIT,
        exports.Permission.CLAIM_DELETE,
        exports.Permission.CLAIM_SUBMIT,
        exports.Permission.BATCH_VIEW,
        exports.Permission.BATCH_APPROVE,
        exports.Permission.PATIENT_CREATE,
        exports.Permission.PATIENT_VIEW,
        exports.Permission.PATIENT_EDIT,
        exports.Permission.PATIENT_IMPORT,
        exports.Permission.REPORT_VIEW,
        exports.Permission.REPORT_EXPORT,
        exports.Permission.ANALYTICS_VIEW,
        exports.Permission.PROVIDER_VIEW,
        exports.Permission.PROVIDER_EDIT,
        exports.Permission.SETTINGS_VIEW,
        exports.Permission.SETTINGS_EDIT,
        exports.Permission.AI_COACH_VIEW,
        exports.Permission.AI_COACH_MANAGE,
    ],
    [exports.Role.ADMIN]: [
        ...STANDARD_PERMISSIONS,
        exports.Permission.ADMIN_PHI_ACCESS,
    ],
};
// --- Audit Action Identifiers (28 categories) ---
exports.AuditAction = {
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
};
// --- Audit Action Categories ---
exports.AuditCategory = {
    AUTH: 'auth',
    DELEGATE: 'delegate',
    ACCOUNT: 'account',
    AUDIT: 'audit',
    ADMIN: 'admin',
};
// --- Subscription Statuses ---
exports.SubscriptionStatus = {
    TRIAL: 'TRIAL',
    ACTIVE: 'ACTIVE',
    PAST_DUE: 'PAST_DUE',
    SUSPENDED: 'SUSPENDED',
    CANCELLED: 'CANCELLED',
};
// --- Session Revoke Reasons ---
exports.SessionRevokeReason = {
    LOGOUT: 'logout',
    EXPIRED_IDLE: 'expired_idle',
    EXPIRED_ABSOLUTE: 'expired_absolute',
    REVOKED_REMOTE: 'revoked_remote',
    PASSWORD_RESET: 'password_reset',
    ACCOUNT_DELETED: 'account_deleted',
};
//# sourceMappingURL=iam.constants.js.map