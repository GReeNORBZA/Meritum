// ============================================================================
// Domain 9: Notification Service — Constants
// ============================================================================

// --- Notification Priority ---

export const NotificationPriority = {
  URGENT: 'URGENT',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
} as const;

export type NotificationPriority =
  (typeof NotificationPriority)[keyof typeof NotificationPriority];

// --- Notification Channel ---

export const NotificationChannel = {
  IN_APP: 'IN_APP',
  EMAIL: 'EMAIL',
  PUSH: 'PUSH', // Phase 2 — included for forward compatibility
} as const;

export type NotificationChannel =
  (typeof NotificationChannel)[keyof typeof NotificationChannel];

// --- Digest Mode ---

export const DigestMode = {
  IMMEDIATE: 'IMMEDIATE',
  DAILY_DIGEST: 'DAILY_DIGEST',
  WEEKLY_DIGEST: 'WEEKLY_DIGEST',
} as const;

export type DigestMode = (typeof DigestMode)[keyof typeof DigestMode];

// --- Email Delivery Status ---

export const EmailDeliveryStatus = {
  QUEUED: 'QUEUED',
  SENT: 'SENT',
  DELIVERED: 'DELIVERED',
  BOUNCED: 'BOUNCED',
  FAILED: 'FAILED',
} as const;

export type EmailDeliveryStatus =
  (typeof EmailDeliveryStatus)[keyof typeof EmailDeliveryStatus];

// --- Notification Event Types ---

export const NotificationEventType = {
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
} as const;

export type NotificationEventType =
  (typeof NotificationEventType)[keyof typeof NotificationEventType];

// --- Event Category ---

export const EventCategory = {
  CLAIM_LIFECYCLE: 'CLAIM_LIFECYCLE',
  INTELLIGENCE_ENGINE: 'INTELLIGENCE_ENGINE',
  PROVIDER_MANAGEMENT: 'PROVIDER_MANAGEMENT',
  PLATFORM_OPERATIONS: 'PLATFORM_OPERATIONS',
  ANALYTICS: 'ANALYTICS',
} as const;

export type EventCategory = (typeof EventCategory)[keyof typeof EventCategory];

// --- Event Catalogue ---

interface EventCatalogueEntry {
  readonly priority: NotificationPriority;
  readonly defaultInApp: boolean;
  readonly defaultEmail: boolean;
  readonly category: EventCategory;
}

export const EVENT_CATALOGUE: Readonly<
  Record<NotificationEventType, EventCatalogueEntry>
> = Object.freeze({
  // Claim Lifecycle (Domain 4) — 13 events
  [NotificationEventType.CLAIM_VALIDATED]: {
    priority: NotificationPriority.LOW,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.CLAIM_FLAGGED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.DEADLINE_7_DAY]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.DEADLINE_3_DAY]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.DEADLINE_1_DAY]: {
    priority: NotificationPriority.URGENT,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.DEADLINE_EXPIRED]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.BATCH_ASSEMBLED]: {
    priority: NotificationPriority.LOW,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.BATCH_SUBMITTED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.BATCH_ERROR]: {
    priority: NotificationPriority.URGENT,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.CLAIM_ASSESSED]: {
    priority: NotificationPriority.LOW,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.CLAIM_REJECTED]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.CLAIM_PAID]: {
    priority: NotificationPriority.LOW,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.CLAIM_LIFECYCLE,
  },
  [NotificationEventType.DUPLICATE_DETECTED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.CLAIM_LIFECYCLE,
  },

  // Intelligence Engine (Domain 7) — 3 events
  [NotificationEventType.AI_SUGGESTION_READY]: {
    priority: NotificationPriority.LOW,
    defaultInApp: true,
    defaultEmail: false,
    category: EventCategory.INTELLIGENCE_ENGINE,
  },
  [NotificationEventType.AI_HIGH_VALUE_SUGGESTION]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.INTELLIGENCE_ENGINE,
  },
  [NotificationEventType.SOMB_CHANGE_IMPACT]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.INTELLIGENCE_ENGINE,
  },

  // Provider Management (Domain 5) — 5 events
  [NotificationEventType.DELEGATE_INVITED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PROVIDER_MANAGEMENT,
  },
  [NotificationEventType.DELEGATE_ACCEPTED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PROVIDER_MANAGEMENT,
  },
  [NotificationEventType.DELEGATE_REVOKED]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PROVIDER_MANAGEMENT,
  },
  [NotificationEventType.BA_STATUS_CHANGED]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PROVIDER_MANAGEMENT,
  },
  [NotificationEventType.RRNP_RATE_CHANGED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PROVIDER_MANAGEMENT,
  },

  // Platform Operations (Domain 12) — 5 events
  [NotificationEventType.PAYMENT_FAILED]: {
    priority: NotificationPriority.URGENT,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PLATFORM_OPERATIONS,
  },
  [NotificationEventType.PAYMENT_RECOVERED]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PLATFORM_OPERATIONS,
  },
  [NotificationEventType.ACCOUNT_SUSPENDED]: {
    priority: NotificationPriority.URGENT,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PLATFORM_OPERATIONS,
  },
  [NotificationEventType.ACCOUNT_REACTIVATED]: {
    priority: NotificationPriority.HIGH,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PLATFORM_OPERATIONS,
  },
  [NotificationEventType.MAINTENANCE_SCHEDULED]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.PLATFORM_OPERATIONS,
  },

  // Analytics (Domain 8) — 2 events
  [NotificationEventType.REPORT_READY]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.ANALYTICS,
  },
  [NotificationEventType.DATA_EXPORT_READY]: {
    priority: NotificationPriority.MEDIUM,
    defaultInApp: true,
    defaultEmail: true,
    category: EventCategory.ANALYTICS,
  },
});

// --- Email Retry Schedule ---
// 4 attempts: immediate, +5min, +30min, +2hr

export const EMAIL_RETRY_SCHEDULE_MS = Object.freeze([
  0,
  5 * 60 * 1000,        // 5 minutes
  30 * 60 * 1000,       // 30 minutes
  2 * 60 * 60 * 1000,   // 2 hours
] as const);

export const EMAIL_MAX_RETRY_ATTEMPTS = EMAIL_RETRY_SCHEDULE_MS.length;

// --- Notification Retention ---

export const NOTIFICATION_RETENTION_PRIMARY_DAYS = 90;
export const NOTIFICATION_RETENTION_ARCHIVE_DAYS = 365;

// --- Notification Audit Actions ---

export const NotificationAuditAction = {
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
} as const;

export type NotificationAuditAction =
  (typeof NotificationAuditAction)[keyof typeof NotificationAuditAction];
