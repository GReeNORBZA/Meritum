export declare const NotificationPriority: {
    readonly URGENT: "URGENT";
    readonly HIGH: "HIGH";
    readonly MEDIUM: "MEDIUM";
    readonly LOW: "LOW";
};
export type NotificationPriority = (typeof NotificationPriority)[keyof typeof NotificationPriority];
export declare const NotificationChannel: {
    readonly IN_APP: "IN_APP";
    readonly EMAIL: "EMAIL";
    readonly PUSH: "PUSH";
};
export type NotificationChannel = (typeof NotificationChannel)[keyof typeof NotificationChannel];
export declare const DigestMode: {
    readonly IMMEDIATE: "IMMEDIATE";
    readonly DAILY_DIGEST: "DAILY_DIGEST";
    readonly WEEKLY_DIGEST: "WEEKLY_DIGEST";
};
export type DigestMode = (typeof DigestMode)[keyof typeof DigestMode];
export declare const EmailDeliveryStatus: {
    readonly QUEUED: "QUEUED";
    readonly SENT: "SENT";
    readonly DELIVERED: "DELIVERED";
    readonly BOUNCED: "BOUNCED";
    readonly FAILED: "FAILED";
};
export type EmailDeliveryStatus = (typeof EmailDeliveryStatus)[keyof typeof EmailDeliveryStatus];
export declare const NotificationEventType: {
    readonly CLAIM_VALIDATED: "CLAIM_VALIDATED";
    readonly CLAIM_FLAGGED: "CLAIM_FLAGGED";
    readonly DEADLINE_7_DAY: "DEADLINE_7_DAY";
    readonly DEADLINE_3_DAY: "DEADLINE_3_DAY";
    readonly DEADLINE_1_DAY: "DEADLINE_1_DAY";
    readonly DEADLINE_EXPIRED: "DEADLINE_EXPIRED";
    readonly BATCH_ASSEMBLED: "BATCH_ASSEMBLED";
    readonly BATCH_SUBMITTED: "BATCH_SUBMITTED";
    readonly BATCH_ERROR: "BATCH_ERROR";
    readonly CLAIM_ASSESSED: "CLAIM_ASSESSED";
    readonly CLAIM_REJECTED: "CLAIM_REJECTED";
    readonly CLAIM_PAID: "CLAIM_PAID";
    readonly DUPLICATE_DETECTED: "DUPLICATE_DETECTED";
    readonly AI_SUGGESTION_READY: "AI_SUGGESTION_READY";
    readonly AI_HIGH_VALUE_SUGGESTION: "AI_HIGH_VALUE_SUGGESTION";
    readonly SOMB_CHANGE_IMPACT: "SOMB_CHANGE_IMPACT";
    readonly DELEGATE_INVITED: "DELEGATE_INVITED";
    readonly DELEGATE_ACCEPTED: "DELEGATE_ACCEPTED";
    readonly DELEGATE_REVOKED: "DELEGATE_REVOKED";
    readonly BA_STATUS_CHANGED: "BA_STATUS_CHANGED";
    readonly RRNP_RATE_CHANGED: "RRNP_RATE_CHANGED";
    readonly PAYMENT_FAILED: "PAYMENT_FAILED";
    readonly PAYMENT_RECOVERED: "PAYMENT_RECOVERED";
    readonly ACCOUNT_SUSPENDED: "ACCOUNT_SUSPENDED";
    readonly ACCOUNT_REACTIVATED: "ACCOUNT_REACTIVATED";
    readonly MAINTENANCE_SCHEDULED: "MAINTENANCE_SCHEDULED";
    readonly REPORT_READY: "REPORT_READY";
    readonly DATA_EXPORT_READY: "DATA_EXPORT_READY";
};
export type NotificationEventType = (typeof NotificationEventType)[keyof typeof NotificationEventType];
export declare const EventCategory: {
    readonly CLAIM_LIFECYCLE: "CLAIM_LIFECYCLE";
    readonly INTELLIGENCE_ENGINE: "INTELLIGENCE_ENGINE";
    readonly PROVIDER_MANAGEMENT: "PROVIDER_MANAGEMENT";
    readonly PLATFORM_OPERATIONS: "PLATFORM_OPERATIONS";
    readonly ANALYTICS: "ANALYTICS";
};
export type EventCategory = (typeof EventCategory)[keyof typeof EventCategory];
interface EventCatalogueEntry {
    readonly priority: NotificationPriority;
    readonly defaultInApp: boolean;
    readonly defaultEmail: boolean;
    readonly category: EventCategory;
}
export declare const EVENT_CATALOGUE: Readonly<Record<NotificationEventType, EventCatalogueEntry>>;
export declare const EMAIL_RETRY_SCHEDULE_MS: readonly [0, number, number, number];
export declare const EMAIL_MAX_RETRY_ATTEMPTS: 4;
export declare const NOTIFICATION_RETENTION_PRIMARY_DAYS = 90;
export declare const NOTIFICATION_RETENTION_ARCHIVE_DAYS = 365;
export declare const NotificationAuditAction: {
    readonly NOTIFICATION_CREATED: "notification.created";
    readonly NOTIFICATION_READ: "notification.read";
    readonly NOTIFICATION_READ_ALL: "notification.read_all";
    readonly NOTIFICATION_DISMISSED: "notification.dismissed";
    readonly NOTIFICATION_EMAIL_SENT: "notification.email_sent";
    readonly NOTIFICATION_EMAIL_BOUNCED: "notification.email_bounced";
    readonly NOTIFICATION_EMAIL_FAILED: "notification.email_failed";
    readonly NOTIFICATION_PREFERENCE_UPDATED: "notification.preference_updated";
    readonly NOTIFICATION_QUIET_HOURS_UPDATED: "notification.quiet_hours_updated";
    readonly NOTIFICATION_DIGEST_ASSEMBLED: "notification.digest_assembled";
    readonly NOTIFICATION_EVENT_EMITTED: "notification.event_emitted";
};
export type NotificationAuditAction = (typeof NotificationAuditAction)[keyof typeof NotificationAuditAction];
export {};
//# sourceMappingURL=notification.constants.d.ts.map