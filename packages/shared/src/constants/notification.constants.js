"use strict";
// ============================================================================
// Domain 9: Notification Service — Constants
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.NotificationAuditAction = exports.NOTIFICATION_RETENTION_ARCHIVE_DAYS = exports.NOTIFICATION_RETENTION_PRIMARY_DAYS = exports.EMAIL_MAX_RETRY_ATTEMPTS = exports.EMAIL_RETRY_SCHEDULE_MS = exports.EVENT_CATALOGUE = exports.EventCategory = exports.NotificationEventType = exports.EmailDeliveryStatus = exports.DigestMode = exports.NotificationChannel = exports.NotificationPriority = void 0;
// --- Notification Priority ---
exports.NotificationPriority = {
    URGENT: 'URGENT',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
};
// --- Notification Channel ---
exports.NotificationChannel = {
    IN_APP: 'IN_APP',
    EMAIL: 'EMAIL',
    PUSH: 'PUSH', // Phase 2 — included for forward compatibility
};
// --- Digest Mode ---
exports.DigestMode = {
    IMMEDIATE: 'IMMEDIATE',
    DAILY_DIGEST: 'DAILY_DIGEST',
    WEEKLY_DIGEST: 'WEEKLY_DIGEST',
};
// --- Email Delivery Status ---
exports.EmailDeliveryStatus = {
    QUEUED: 'QUEUED',
    SENT: 'SENT',
    DELIVERED: 'DELIVERED',
    BOUNCED: 'BOUNCED',
    FAILED: 'FAILED',
};
// --- Notification Event Types ---
exports.NotificationEventType = {
    // Claim Lifecycle (Domain 4) — 13 events
    CLAIM_VALIDATED: 'CLAIM_VALIDATED',
    CLAIM_FLAGGED: 'CLAIM_FLAGGED',
    DEADLINE_7_DAY: 'DEADLINE_7_DAY',
    DEADLINE_3_DAY: 'DEADLINE_3_DAY',
    DEADLINE_1_DAY: 'DEADLINE_1_DAY',
    DEADLINE_EXPIRED: 'DEADLINE_EXPIRED',
    BATCH_ASSEMBLED: 'BATCH_ASSEMBLED',
    BATCH_SUBMITTED: 'BATCH_SUBMITTED',
    BATCH_ERROR: 'BATCH_ERROR',
    CLAIM_ASSESSED: 'CLAIM_ASSESSED',
    CLAIM_REJECTED: 'CLAIM_REJECTED',
    CLAIM_PAID: 'CLAIM_PAID',
    DUPLICATE_DETECTED: 'DUPLICATE_DETECTED',
    // Intelligence Engine (Domain 7) — 3 events
    AI_SUGGESTION_READY: 'AI_SUGGESTION_READY',
    AI_HIGH_VALUE_SUGGESTION: 'AI_HIGH_VALUE_SUGGESTION',
    SOMB_CHANGE_IMPACT: 'SOMB_CHANGE_IMPACT',
    // Provider Management (Domain 5) — 5 events
    DELEGATE_INVITED: 'DELEGATE_INVITED',
    DELEGATE_ACCEPTED: 'DELEGATE_ACCEPTED',
    DELEGATE_REVOKED: 'DELEGATE_REVOKED',
    BA_STATUS_CHANGED: 'BA_STATUS_CHANGED',
    RRNP_RATE_CHANGED: 'RRNP_RATE_CHANGED',
    // Platform Operations (Domain 12) — 5 events
    PAYMENT_FAILED: 'PAYMENT_FAILED',
    PAYMENT_RECOVERED: 'PAYMENT_RECOVERED',
    ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED',
    ACCOUNT_REACTIVATED: 'ACCOUNT_REACTIVATED',
    MAINTENANCE_SCHEDULED: 'MAINTENANCE_SCHEDULED',
    // Analytics (Domain 8) — 2 events
    REPORT_READY: 'REPORT_READY',
    DATA_EXPORT_READY: 'DATA_EXPORT_READY',
};
// --- Event Category ---
exports.EventCategory = {
    CLAIM_LIFECYCLE: 'CLAIM_LIFECYCLE',
    INTELLIGENCE_ENGINE: 'INTELLIGENCE_ENGINE',
    PROVIDER_MANAGEMENT: 'PROVIDER_MANAGEMENT',
    PLATFORM_OPERATIONS: 'PLATFORM_OPERATIONS',
    ANALYTICS: 'ANALYTICS',
};
exports.EVENT_CATALOGUE = Object.freeze({
    // Claim Lifecycle (Domain 4) — 13 events
    [exports.NotificationEventType.CLAIM_VALIDATED]: {
        priority: exports.NotificationPriority.LOW,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.CLAIM_FLAGGED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.DEADLINE_7_DAY]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.DEADLINE_3_DAY]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.DEADLINE_1_DAY]: {
        priority: exports.NotificationPriority.URGENT,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.DEADLINE_EXPIRED]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.BATCH_ASSEMBLED]: {
        priority: exports.NotificationPriority.LOW,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.BATCH_SUBMITTED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.BATCH_ERROR]: {
        priority: exports.NotificationPriority.URGENT,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.CLAIM_ASSESSED]: {
        priority: exports.NotificationPriority.LOW,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.CLAIM_REJECTED]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.CLAIM_PAID]: {
        priority: exports.NotificationPriority.LOW,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    [exports.NotificationEventType.DUPLICATE_DETECTED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.CLAIM_LIFECYCLE,
    },
    // Intelligence Engine (Domain 7) — 3 events
    [exports.NotificationEventType.AI_SUGGESTION_READY]: {
        priority: exports.NotificationPriority.LOW,
        defaultInApp: true,
        defaultEmail: false,
        category: exports.EventCategory.INTELLIGENCE_ENGINE,
    },
    [exports.NotificationEventType.AI_HIGH_VALUE_SUGGESTION]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.INTELLIGENCE_ENGINE,
    },
    [exports.NotificationEventType.SOMB_CHANGE_IMPACT]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.INTELLIGENCE_ENGINE,
    },
    // Provider Management (Domain 5) — 5 events
    [exports.NotificationEventType.DELEGATE_INVITED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PROVIDER_MANAGEMENT,
    },
    [exports.NotificationEventType.DELEGATE_ACCEPTED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PROVIDER_MANAGEMENT,
    },
    [exports.NotificationEventType.DELEGATE_REVOKED]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PROVIDER_MANAGEMENT,
    },
    [exports.NotificationEventType.BA_STATUS_CHANGED]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PROVIDER_MANAGEMENT,
    },
    [exports.NotificationEventType.RRNP_RATE_CHANGED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PROVIDER_MANAGEMENT,
    },
    // Platform Operations (Domain 12) — 5 events
    [exports.NotificationEventType.PAYMENT_FAILED]: {
        priority: exports.NotificationPriority.URGENT,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PLATFORM_OPERATIONS,
    },
    [exports.NotificationEventType.PAYMENT_RECOVERED]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PLATFORM_OPERATIONS,
    },
    [exports.NotificationEventType.ACCOUNT_SUSPENDED]: {
        priority: exports.NotificationPriority.URGENT,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PLATFORM_OPERATIONS,
    },
    [exports.NotificationEventType.ACCOUNT_REACTIVATED]: {
        priority: exports.NotificationPriority.HIGH,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PLATFORM_OPERATIONS,
    },
    [exports.NotificationEventType.MAINTENANCE_SCHEDULED]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.PLATFORM_OPERATIONS,
    },
    // Analytics (Domain 8) — 2 events
    [exports.NotificationEventType.REPORT_READY]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.ANALYTICS,
    },
    [exports.NotificationEventType.DATA_EXPORT_READY]: {
        priority: exports.NotificationPriority.MEDIUM,
        defaultInApp: true,
        defaultEmail: true,
        category: exports.EventCategory.ANALYTICS,
    },
});
// --- Email Retry Schedule ---
// 4 attempts: immediate, +5min, +30min, +2hr
exports.EMAIL_RETRY_SCHEDULE_MS = Object.freeze([
    0,
    5 * 60 * 1000, // 5 minutes
    30 * 60 * 1000, // 30 minutes
    2 * 60 * 60 * 1000, // 2 hours
]);
exports.EMAIL_MAX_RETRY_ATTEMPTS = exports.EMAIL_RETRY_SCHEDULE_MS.length;
// --- Notification Retention ---
exports.NOTIFICATION_RETENTION_PRIMARY_DAYS = 90;
exports.NOTIFICATION_RETENTION_ARCHIVE_DAYS = 365;
// --- Notification Audit Actions ---
exports.NotificationAuditAction = {
    NOTIFICATION_CREATED: 'notification.created',
    NOTIFICATION_READ: 'notification.read',
    NOTIFICATION_READ_ALL: 'notification.read_all',
    NOTIFICATION_DISMISSED: 'notification.dismissed',
    NOTIFICATION_EMAIL_SENT: 'notification.email_sent',
    NOTIFICATION_EMAIL_BOUNCED: 'notification.email_bounced',
    NOTIFICATION_EMAIL_FAILED: 'notification.email_failed',
    NOTIFICATION_PREFERENCE_UPDATED: 'notification.preference_updated',
    NOTIFICATION_QUIET_HOURS_UPDATED: 'notification.quiet_hours_updated',
    NOTIFICATION_DIGEST_ASSEMBLED: 'notification.digest_assembled',
    NOTIFICATION_EVENT_EMITTED: 'notification.event_emitted',
};
//# sourceMappingURL=notification.constants.js.map