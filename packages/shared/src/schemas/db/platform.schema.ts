// ============================================================================
// Domain 12: Platform Operations — Drizzle DB Schema
// ============================================================================

import { sql } from 'drizzle-orm';
import {
  pgTable,
  uuid,
  varchar,
  boolean,
  integer,
  decimal,
  text,
  timestamp,
  jsonb,
  uniqueIndex,
  index,
} from 'drizzle-orm/pg-core';

import { users } from './iam.schema.js';
import { providers } from './provider.schema.js';

// --- Subscriptions Table ---
// One subscription per physician. No PHI stored here — billing metadata only.
// Stripe IDs are references only; no payment card data is stored in Meritum.

export const subscriptions = pgTable(
  'subscriptions',
  {
    subscriptionId: uuid('subscription_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => users.userId),
    stripeCustomerId: varchar('stripe_customer_id', { length: 50 }).notNull(),
    stripeSubscriptionId: varchar('stripe_subscription_id', {
      length: 50,
    }).notNull(),
    plan: varchar('plan', { length: 30 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('TRIAL'),
    currentPeriodStart: timestamp('current_period_start', {
      withTimezone: true,
    }).notNull(),
    currentPeriodEnd: timestamp('current_period_end', {
      withTimezone: true,
    }).notNull(),
    trialEnd: timestamp('trial_end', { withTimezone: true }),
    failedPaymentCount: integer('failed_payment_count').notNull().default(0),
    suspendedAt: timestamp('suspended_at', { withTimezone: true }),
    cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
    practiceId: uuid('practice_id').references(() => practices.practiceId),
    deletionScheduledAt: timestamp('deletion_scheduled_at', {
      withTimezone: true,
    }),
    // --- Early Bird Rate Lock (Batch 2: Pricing Lifecycle, spec B2-2) ---
    // Set to created_at + 12 months on early bird checkout completion.
    // Null for non-early-bird plans.
    earlyBirdLockedUntil: timestamp('early_bird_locked_until', {
      withTimezone: true,
    }),
    // Tracks whether the 30-day expiry warning notification has been sent.
    // Prevents duplicate notification sends in the scheduled job.
    earlyBirdExpiryNotified: boolean('early_bird_expiry_notified')
      .notNull()
      .default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('subscriptions_provider_id_idx').on(table.providerId),
    index('subscriptions_stripe_customer_id_idx').on(table.stripeCustomerId),
    index('subscriptions_stripe_subscription_id_idx').on(
      table.stripeSubscriptionId,
    ),
    index('subscriptions_status_idx').on(table.status),
    index('subscriptions_deletion_scheduled_at_idx').on(
      table.deletionScheduledAt,
    ),
    index('subscriptions_practice_id_idx').on(table.practiceId),
    index('subscriptions_early_bird_locked_until_idx').on(table.earlyBirdLockedUntil),
  ],
);

// --- Payment History Table ---
// Records every Stripe invoice outcome. No PHI — billing metadata only.
// GST is 5% of amount_cad; total_cad = amount_cad + gst_amount.

export const paymentHistory = pgTable(
  'payment_history',
  {
    paymentId: uuid('payment_id').primaryKey().defaultRandom(),
    subscriptionId: uuid('subscription_id')
      .notNull()
      .references(() => subscriptions.subscriptionId),
    stripeInvoiceId: varchar('stripe_invoice_id', { length: 50 }).notNull(),
    amountCad: decimal('amount_cad', { precision: 10, scale: 2 }).notNull(),
    gstAmount: decimal('gst_amount', { precision: 10, scale: 2 }).notNull(),
    totalCad: decimal('total_cad', { precision: 10, scale: 2 }).notNull(),
    status: varchar('status', { length: 20 }).notNull(),
    paidAt: timestamp('paid_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('payment_history_subscription_created_idx').on(
      table.subscriptionId,
      table.createdAt,
    ),
    index('payment_history_stripe_invoice_id_idx').on(table.stripeInvoiceId),
  ],
);

// --- Status Components Table ---
// Eight monitored platform components displayed on status.meritum.ca.

export const statusComponents = pgTable(
  'status_components',
  {
    componentId: uuid('component_id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 50 }).notNull(),
    displayName: varchar('display_name', { length: 100 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('operational'),
    description: text('description'),
    sortOrder: integer('sort_order').notNull().default(0),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [uniqueIndex('status_components_name_idx').on(table.name)],
);

// --- Status Incidents Table ---
// Tracks incidents affecting one or more components.

export const statusIncidents = pgTable(
  'status_incidents',
  {
    incidentId: uuid('incident_id').primaryKey().defaultRandom(),
    title: varchar('title', { length: 200 }).notNull(),
    status: varchar('status', { length: 20 }).notNull(),
    severity: varchar('severity', { length: 20 }).notNull(),
    affectedComponents: jsonb('affected_components').notNull(),
    resolvedAt: timestamp('resolved_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('status_incidents_status_created_idx').on(
      table.status,
      table.createdAt,
    ),
    index('status_incidents_created_at_idx').on(table.createdAt),
  ],
);

// --- Incident Updates Table ---
// Append-only timeline of updates for each incident.

export const incidentUpdates = pgTable(
  'incident_updates',
  {
    updateId: uuid('update_id').primaryKey().defaultRandom(),
    incidentId: uuid('incident_id')
      .notNull()
      .references(() => statusIncidents.incidentId),
    status: varchar('status', { length: 20 }).notNull(),
    message: text('message').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('incident_updates_incident_created_idx').on(
      table.incidentId,
      table.createdAt,
    ),
  ],
);

// --- Referral Codes Table ---
// Each physician gets a unique referral code at signup. Codes are active by default.
// Credit model: 1 month free per qualified referral, max 3 per anniversary year.

export const referralCodes = pgTable(
  'referral_codes',
  {
    referralCodeId: uuid('referral_code_id').primaryKey().defaultRandom(),
    referrerUserId: uuid('referrer_user_id')
      .notNull()
      .references(() => users.userId),
    code: varchar('code', { length: 20 }).notNull(),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('referral_codes_code_idx').on(table.code),
    index('referral_codes_referrer_user_id_idx').on(table.referrerUserId),
  ],
);

// --- Referral Redemptions Table ---
// Tracks the full lifecycle of a referral: PENDING → QUALIFIED → CREDITED (or EXPIRED).
// credit_month_value_cad = 1 month at referrer's rate at qualification time.
// Max 3 QUALIFIED/CREDITED per referrer per anniversary year.

export const referralRedemptions = pgTable(
  'referral_redemptions',
  {
    redemptionId: uuid('redemption_id').primaryKey().defaultRandom(),
    referralCodeId: uuid('referral_code_id')
      .notNull()
      .references(() => referralCodes.referralCodeId),
    referrerUserId: uuid('referrer_user_id')
      .notNull()
      .references(() => users.userId),
    referredUserId: uuid('referred_user_id')
      .notNull()
      .references(() => users.userId),
    status: varchar('status', { length: 20 }).notNull().default('PENDING'),
    creditMonthValueCad: decimal('credit_month_value_cad', {
      precision: 10,
      scale: 2,
    }),
    creditAppliedTo: varchar('credit_applied_to', { length: 20 }),
    creditAppliedAt: timestamp('credit_applied_at', { withTimezone: true }),
    qualifyingEventAt: timestamp('qualifying_event_at', { withTimezone: true }),
    anniversaryYear: integer('anniversary_year').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('referral_redemptions_referral_code_id_idx').on(table.referralCodeId),
    index('referral_redemptions_referred_user_id_idx').on(table.referredUserId),
    index('referral_redemptions_referrer_user_id_idx').on(table.referrerUserId),
    index('referral_redemptions_status_idx').on(table.status),
    index('referral_redemptions_referrer_anniversary_idx').on(
      table.referrerUserId,
      table.anniversaryYear,
    ),
  ],
);

// --- Practices Table ---
// Clinic-tier billing: groups multiple physicians under one Stripe subscription.
// No PHI stored — only practice name, admin reference, Stripe IDs, and billing metadata.

export const practices = pgTable(
  'practices',
  {
    practiceId: uuid('practice_id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 200 }).notNull(),
    adminUserId: uuid('admin_user_id')
      .notNull()
      .references(() => users.userId),
    stripeCustomerId: varchar('stripe_customer_id', { length: 50 }),
    stripeSubscriptionId: varchar('stripe_subscription_id', { length: 50 }),
    billingFrequency: varchar('billing_frequency', { length: 10 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('ACTIVE'),
    currentPeriodStart: timestamp('current_period_start', {
      withTimezone: true,
    }).notNull(),
    currentPeriodEnd: timestamp('current_period_end', {
      withTimezone: true,
    }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('practices_admin_user_id_idx').on(table.adminUserId),
    index('practices_stripe_customer_id_idx').on(table.stripeCustomerId),
    index('practices_status_idx').on(table.status),
  ],
);

// --- Practice Memberships Table ---
// Links physicians to practices. Tracks billing mode per member.
// billing_mode determines whether the physician is billed through the practice's
// consolidated Stripe subscription or retains their own individual early bird rate.

export const practiceMemberships = pgTable(
  'practice_memberships',
  {
    membershipId: uuid('membership_id').primaryKey().defaultRandom(),
    practiceId: uuid('practice_id')
      .notNull()
      .references(() => practices.practiceId),
    physicianUserId: uuid('physician_user_id')
      .notNull()
      .references(() => users.userId),
    billingMode: varchar('billing_mode', { length: 30 })
      .notNull()
      .default('PRACTICE_CONSOLIDATED'),
    joinedAt: timestamp('joined_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    removedAt: timestamp('removed_at', { withTimezone: true }),
    removalEffectiveAt: timestamp('removal_effective_at', {
      withTimezone: true,
    }),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('practice_memberships_practice_physician_active_idx')
      .on(table.practiceId, table.physicianUserId)
      .where(sql`${table.isActive} = true`),
    uniqueIndex('practice_memberships_physician_active_idx')
      .on(table.physicianUserId)
      .where(sql`${table.isActive} = true`),
    index('practice_memberships_practice_active_idx')
      .on(table.practiceId)
      .where(sql`${table.isActive} = true`),
  ],
);

// --- Practice Invitations Table ---
// Tracks invitations sent by practice admins to physicians.
// token_hash stores SHA-256 of the invitation token — raw token is NEVER stored.

export const practiceInvitations = pgTable(
  'practice_invitations',
  {
    invitationId: uuid('invitation_id').primaryKey().defaultRandom(),
    practiceId: uuid('practice_id')
      .notNull()
      .references(() => practices.practiceId),
    invitedEmail: varchar('invited_email', { length: 255 }).notNull(),
    invitedByUserId: uuid('invited_by_user_id')
      .notNull()
      .references(() => users.userId),
    status: varchar('status', { length: 20 }).notNull().default('PENDING'),
    tokenHash: varchar('token_hash', { length: 128 }).notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('practice_invitations_practice_id_idx').on(table.practiceId),
    index('practice_invitations_token_hash_idx').on(table.tokenHash),
    index('practice_invitations_invited_email_idx').on(table.invitedEmail),
    index('practice_invitations_status_idx').on(table.status),
  ],
);

// --- Inferred Types ---

export type InsertSubscription = typeof subscriptions.$inferInsert;
export type SelectSubscription = typeof subscriptions.$inferSelect;

export type InsertPaymentHistory = typeof paymentHistory.$inferInsert;
export type SelectPaymentHistory = typeof paymentHistory.$inferSelect;

export type InsertStatusComponent = typeof statusComponents.$inferInsert;
export type SelectStatusComponent = typeof statusComponents.$inferSelect;

export type InsertStatusIncident = typeof statusIncidents.$inferInsert;
export type SelectStatusIncident = typeof statusIncidents.$inferSelect;

export type InsertIncidentUpdate = typeof incidentUpdates.$inferInsert;
export type SelectIncidentUpdate = typeof incidentUpdates.$inferSelect;

export type InsertReferralCode = typeof referralCodes.$inferInsert;
export type SelectReferralCode = typeof referralCodes.$inferSelect;

export type InsertReferralRedemption = typeof referralRedemptions.$inferInsert;
export type SelectReferralRedemption = typeof referralRedemptions.$inferSelect;

export type InsertPractice = typeof practices.$inferInsert;
export type SelectPractice = typeof practices.$inferSelect;

export type InsertPracticeMembership = typeof practiceMemberships.$inferInsert;
export type SelectPracticeMembership = typeof practiceMemberships.$inferSelect;

export type InsertPracticeInvitation = typeof practiceInvitations.$inferInsert;
export type SelectPracticeInvitation = typeof practiceInvitations.$inferSelect;

// --- IMA Amendments Table ---
// Tracks amendments to the Independent Member Agreement.
// documentHash is SHA-256 of the amendment document text, computed server-side only.

export const imaAmendments = pgTable(
  'ima_amendments',
  {
    amendmentId: uuid('amendment_id').primaryKey().defaultRandom(),
    amendmentType: varchar('amendment_type', { length: 20 }).notNull(),
    title: text('title').notNull(),
    description: text('description').notNull(),
    documentHash: varchar('document_hash', { length: 64 }).notNull(),
    noticeDate: timestamp('notice_date', { withTimezone: true }).notNull(),
    effectiveDate: timestamp('effective_date', { withTimezone: true }).notNull(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('ima_amendments_type_idx').on(table.amendmentType),
    index('ima_amendments_effective_date_idx').on(table.effectiveDate),
  ],
);

// --- IMA Amendment Responses Table ---
// Records each physician's response to an amendment.
// ipAddress and userAgent are captured from the HTTP request, never from client-submitted data.
// Unique index on (amendmentId, providerId) prevents duplicate responses.

export const imaAmendmentResponses = pgTable(
  'ima_amendment_responses',
  {
    responseId: uuid('response_id').primaryKey().defaultRandom(),
    amendmentId: uuid('amendment_id')
      .notNull()
      .references(() => imaAmendments.amendmentId),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    responseType: varchar('response_type', { length: 20 }).notNull(),
    respondedAt: timestamp('responded_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    ipAddress: varchar('ip_address', { length: 45 }).notNull(),
    userAgent: varchar('user_agent', { length: 500 }).notNull(),
  },
  (table) => [
    index('ima_responses_amendment_idx').on(table.amendmentId),
    index('ima_responses_provider_idx').on(table.providerId),
    uniqueIndex('ima_responses_unique_idx').on(
      table.amendmentId,
      table.providerId,
    ),
  ],
);

export type InsertImaAmendment = typeof imaAmendments.$inferInsert;
export type SelectImaAmendment = typeof imaAmendments.$inferSelect;

export type InsertImaAmendmentResponse = typeof imaAmendmentResponses.$inferInsert;
export type SelectImaAmendmentResponse = typeof imaAmendmentResponses.$inferSelect;

// --- Breach Records Table ---
// Tracks privacy breach incidents under HIA s.8.1. awarenessDate starts the 72h
// notification clock. evidenceHoldUntil must be at least awarenessDate + 12 months.

export const breachRecords = pgTable(
  'breach_records',
  {
    breachId: uuid('breach_id').primaryKey().defaultRandom(),
    breachDescription: text('breach_description').notNull(),
    breachDate: timestamp('breach_date', { withTimezone: true }).notNull(),
    awarenessDate: timestamp('awareness_date', { withTimezone: true }).notNull(),
    hiDescription: text('hi_description').notNull(),
    includesIihi: boolean('includes_iihi').notNull(),
    affectedCount: integer('affected_count'),
    riskAssessment: text('risk_assessment'),
    mitigationSteps: text('mitigation_steps'),
    contactName: varchar('contact_name', { length: 200 }).notNull(),
    contactEmail: varchar('contact_email', { length: 100 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('INVESTIGATING'),
    evidenceHoldUntil: timestamp('evidence_hold_until', { withTimezone: true }),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    resolvedAt: timestamp('resolved_at', { withTimezone: true }),
  },
  (table) => [
    index('breach_records_status_idx').on(table.status),
    index('breach_records_awareness_date_idx').on(table.awarenessDate),
  ],
);

// --- Breach Affected Custodians Table ---
// Links breach records to affected physician custodians. Tracks initial notification.

export const breachAffectedCustodians = pgTable(
  'breach_affected_custodians',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    breachId: uuid('breach_id')
      .notNull()
      .references(() => breachRecords.breachId),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    initialNotifiedAt: timestamp('initial_notified_at', { withTimezone: true }),
    notificationMethod: varchar('notification_method', { length: 50 }),
  },
  (table) => [
    index('breach_affected_breach_idx').on(table.breachId),
    uniqueIndex('breach_affected_unique_idx').on(table.breachId, table.providerId),
  ],
);

// --- Breach Updates Table (append-only) ---
// Chronological record of INITIAL and SUPPLEMENTARY updates sent for a breach.
// No UPDATE or DELETE operations are permitted on this table.

export const breachUpdates = pgTable(
  'breach_updates',
  {
    updateId: uuid('update_id').primaryKey().defaultRandom(),
    breachId: uuid('breach_id')
      .notNull()
      .references(() => breachRecords.breachId),
    updateType: varchar('update_type', { length: 20 }).notNull(),
    content: text('content').notNull(),
    sentAt: timestamp('sent_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    index('breach_updates_breach_idx').on(table.breachId),
  ],
);

// --- Data Destruction Tracking Table ---
// One record per physician. Tracks the multi-phase data destruction process
// after account cancellation: active data deletion → file deletion → backup purge.

export const dataDestructionTracking = pgTable(
  'data_destruction_tracking',
  {
    trackingId: uuid('tracking_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .unique()
      .references(() => providers.providerId),
    lastKnownEmail: varchar('last_known_email', { length: 320 }),
    activeDeletedAt: timestamp('active_deleted_at', { withTimezone: true }),
    filesDeletedAt: timestamp('files_deleted_at', { withTimezone: true }),
    backupPurgeDeadline: timestamp('backup_purge_deadline', { withTimezone: true }),
    backupPurgedAt: timestamp('backup_purged_at', { withTimezone: true }),
    confirmationSentAt: timestamp('confirmation_sent_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('destruction_tracking_deadline_idx').on(table.backupPurgeDeadline),
  ],
);

export type InsertBreachRecord = typeof breachRecords.$inferInsert;
export type SelectBreachRecord = typeof breachRecords.$inferSelect;

export type InsertBreachAffectedCustodian = typeof breachAffectedCustodians.$inferInsert;
export type SelectBreachAffectedCustodian = typeof breachAffectedCustodians.$inferSelect;

export type InsertBreachUpdate = typeof breachUpdates.$inferInsert;
export type SelectBreachUpdate = typeof breachUpdates.$inferSelect;

export type InsertDataDestructionTracking = typeof dataDestructionTracking.$inferInsert;
export type SelectDataDestructionTracking = typeof dataDestructionTracking.$inferSelect;
