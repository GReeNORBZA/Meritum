// ============================================================================
// Domain 12: Platform Operations — Drizzle DB Schema
// ============================================================================

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
    deletionScheduledAt: timestamp('deletion_scheduled_at', {
      withTimezone: true,
    }),
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
// MVP accommodation: schema defined, not actively used. Referral program activates post-PMF.
// $50 credit per referral, max 10 per physician per year ($500/year cap).

export const referralCodes = pgTable(
  'referral_codes',
  {
    referralCodeId: uuid('referral_code_id').primaryKey().defaultRandom(),
    physicianUserId: uuid('physician_user_id')
      .notNull()
      .references(() => users.userId),
    code: varchar('code', { length: 20 }).notNull(),
    redemptionCount: integer('redemption_count').notNull().default(0),
    maxRedemptions: integer('max_redemptions').notNull().default(10),
    isActive: boolean('is_active').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('referral_codes_code_idx').on(table.code),
    index('referral_codes_physician_user_id_idx').on(table.physicianUserId),
  ],
);

// --- Referral Redemptions Table ---
// MVP accommodation: tracks which users redeemed a referral code.

export const referralRedemptions = pgTable(
  'referral_redemptions',
  {
    redemptionId: uuid('redemption_id').primaryKey().defaultRandom(),
    referralCodeId: uuid('referral_code_id')
      .notNull()
      .references(() => referralCodes.referralCodeId),
    referredUserId: uuid('referred_user_id')
      .notNull()
      .references(() => users.userId),
    creditAmountCad: decimal('credit_amount_cad', { precision: 10, scale: 2 })
      .notNull()
      .default('50.00'),
    creditApplied: boolean('credit_applied').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('referral_redemptions_referral_code_id_idx').on(table.referralCodeId),
    index('referral_redemptions_referred_user_id_idx').on(table.referredUserId),
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
