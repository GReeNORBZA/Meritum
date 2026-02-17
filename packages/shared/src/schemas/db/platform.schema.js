"use strict";
// ============================================================================
// Domain 12: Platform Operations — Drizzle DB Schema
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.referralRedemptions = exports.referralCodes = exports.incidentUpdates = exports.statusIncidents = exports.statusComponents = exports.paymentHistory = exports.subscriptions = void 0;
const pg_core_1 = require("drizzle-orm/pg-core");
const iam_schema_js_1 = require("./iam.schema.js");
// --- Subscriptions Table ---
// One subscription per physician. No PHI stored here — billing metadata only.
// Stripe IDs are references only; no payment card data is stored in Meritum.
exports.subscriptions = (0, pg_core_1.pgTable)('subscriptions', {
    subscriptionId: (0, pg_core_1.uuid)('subscription_id').primaryKey().defaultRandom(),
    providerId: (0, pg_core_1.uuid)('provider_id')
        .notNull()
        .references(() => iam_schema_js_1.users.userId),
    stripeCustomerId: (0, pg_core_1.varchar)('stripe_customer_id', { length: 50 }).notNull(),
    stripeSubscriptionId: (0, pg_core_1.varchar)('stripe_subscription_id', {
        length: 50,
    }).notNull(),
    plan: (0, pg_core_1.varchar)('plan', { length: 30 }).notNull(),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull().default('TRIAL'),
    currentPeriodStart: (0, pg_core_1.timestamp)('current_period_start', {
        withTimezone: true,
    }).notNull(),
    currentPeriodEnd: (0, pg_core_1.timestamp)('current_period_end', {
        withTimezone: true,
    }).notNull(),
    trialEnd: (0, pg_core_1.timestamp)('trial_end', { withTimezone: true }),
    failedPaymentCount: (0, pg_core_1.integer)('failed_payment_count').notNull().default(0),
    suspendedAt: (0, pg_core_1.timestamp)('suspended_at', { withTimezone: true }),
    cancelledAt: (0, pg_core_1.timestamp)('cancelled_at', { withTimezone: true }),
    deletionScheduledAt: (0, pg_core_1.timestamp)('deletion_scheduled_at', {
        withTimezone: true,
    }),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('subscriptions_provider_id_idx').on(table.providerId),
    (0, pg_core_1.index)('subscriptions_stripe_customer_id_idx').on(table.stripeCustomerId),
    (0, pg_core_1.index)('subscriptions_stripe_subscription_id_idx').on(table.stripeSubscriptionId),
    (0, pg_core_1.index)('subscriptions_status_idx').on(table.status),
    (0, pg_core_1.index)('subscriptions_deletion_scheduled_at_idx').on(table.deletionScheduledAt),
]);
// --- Payment History Table ---
// Records every Stripe invoice outcome. No PHI — billing metadata only.
// GST is 5% of amount_cad; total_cad = amount_cad + gst_amount.
exports.paymentHistory = (0, pg_core_1.pgTable)('payment_history', {
    paymentId: (0, pg_core_1.uuid)('payment_id').primaryKey().defaultRandom(),
    subscriptionId: (0, pg_core_1.uuid)('subscription_id')
        .notNull()
        .references(() => exports.subscriptions.subscriptionId),
    stripeInvoiceId: (0, pg_core_1.varchar)('stripe_invoice_id', { length: 50 }).notNull(),
    amountCad: (0, pg_core_1.decimal)('amount_cad', { precision: 10, scale: 2 }).notNull(),
    gstAmount: (0, pg_core_1.decimal)('gst_amount', { precision: 10, scale: 2 }).notNull(),
    totalCad: (0, pg_core_1.decimal)('total_cad', { precision: 10, scale: 2 }).notNull(),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull(),
    paidAt: (0, pg_core_1.timestamp)('paid_at', { withTimezone: true }),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('payment_history_subscription_created_idx').on(table.subscriptionId, table.createdAt),
    (0, pg_core_1.index)('payment_history_stripe_invoice_id_idx').on(table.stripeInvoiceId),
]);
// --- Status Components Table ---
// Eight monitored platform components displayed on status.meritum.ca.
exports.statusComponents = (0, pg_core_1.pgTable)('status_components', {
    componentId: (0, pg_core_1.uuid)('component_id').primaryKey().defaultRandom(),
    name: (0, pg_core_1.varchar)('name', { length: 50 }).notNull(),
    displayName: (0, pg_core_1.varchar)('display_name', { length: 100 }).notNull(),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull().default('operational'),
    description: (0, pg_core_1.text)('description'),
    sortOrder: (0, pg_core_1.integer)('sort_order').notNull().default(0),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [(0, pg_core_1.uniqueIndex)('status_components_name_idx').on(table.name)]);
// --- Status Incidents Table ---
// Tracks incidents affecting one or more components.
exports.statusIncidents = (0, pg_core_1.pgTable)('status_incidents', {
    incidentId: (0, pg_core_1.uuid)('incident_id').primaryKey().defaultRandom(),
    title: (0, pg_core_1.varchar)('title', { length: 200 }).notNull(),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull(),
    severity: (0, pg_core_1.varchar)('severity', { length: 20 }).notNull(),
    affectedComponents: (0, pg_core_1.jsonb)('affected_components').notNull(),
    resolvedAt: (0, pg_core_1.timestamp)('resolved_at', { withTimezone: true }),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('status_incidents_status_created_idx').on(table.status, table.createdAt),
    (0, pg_core_1.index)('status_incidents_created_at_idx').on(table.createdAt),
]);
// --- Incident Updates Table ---
// Append-only timeline of updates for each incident.
exports.incidentUpdates = (0, pg_core_1.pgTable)('incident_updates', {
    updateId: (0, pg_core_1.uuid)('update_id').primaryKey().defaultRandom(),
    incidentId: (0, pg_core_1.uuid)('incident_id')
        .notNull()
        .references(() => exports.statusIncidents.incidentId),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull(),
    message: (0, pg_core_1.text)('message').notNull(),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('incident_updates_incident_created_idx').on(table.incidentId, table.createdAt),
]);
// --- Referral Codes Table ---
// MVP accommodation: schema defined, not actively used. Referral program activates post-PMF.
// $50 credit per referral, max 10 per physician per year ($500/year cap).
exports.referralCodes = (0, pg_core_1.pgTable)('referral_codes', {
    referralCodeId: (0, pg_core_1.uuid)('referral_code_id').primaryKey().defaultRandom(),
    physicianUserId: (0, pg_core_1.uuid)('physician_user_id')
        .notNull()
        .references(() => iam_schema_js_1.users.userId),
    code: (0, pg_core_1.varchar)('code', { length: 20 }).notNull(),
    redemptionCount: (0, pg_core_1.integer)('redemption_count').notNull().default(0),
    maxRedemptions: (0, pg_core_1.integer)('max_redemptions').notNull().default(10),
    isActive: (0, pg_core_1.boolean)('is_active').notNull().default(false),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.uniqueIndex)('referral_codes_code_idx').on(table.code),
    (0, pg_core_1.index)('referral_codes_physician_user_id_idx').on(table.physicianUserId),
]);
// --- Referral Redemptions Table ---
// MVP accommodation: tracks which users redeemed a referral code.
exports.referralRedemptions = (0, pg_core_1.pgTable)('referral_redemptions', {
    redemptionId: (0, pg_core_1.uuid)('redemption_id').primaryKey().defaultRandom(),
    referralCodeId: (0, pg_core_1.uuid)('referral_code_id')
        .notNull()
        .references(() => exports.referralCodes.referralCodeId),
    referredUserId: (0, pg_core_1.uuid)('referred_user_id')
        .notNull()
        .references(() => iam_schema_js_1.users.userId),
    creditAmountCad: (0, pg_core_1.decimal)('credit_amount_cad', { precision: 10, scale: 2 })
        .notNull()
        .default('50.00'),
    creditApplied: (0, pg_core_1.boolean)('credit_applied').notNull().default(false),
    createdAt: (0, pg_core_1.timestamp)('created_at', { withTimezone: true })
        .notNull()
        .defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('referral_redemptions_referral_code_id_idx').on(table.referralCodeId),
    (0, pg_core_1.index)('referral_redemptions_referred_user_id_idx').on(table.referredUserId),
]);
//# sourceMappingURL=platform.schema.js.map