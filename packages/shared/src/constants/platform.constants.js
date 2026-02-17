"use strict";
// ============================================================================
// Domain 12: Platform Operations — Constants
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.DUNNING_CANCELLATION_DAY = exports.DUNNING_SUSPENSION_DAY = exports.DELETION_GRACE_PERIOD_DAYS = exports.EARLY_BIRD_CAP = exports.GST_RATE = exports.ComponentHealth = exports.StatusComponent = exports.IncidentStatus = exports.FeatureAccessMatrix = exports.Feature = exports.StripeWebhookEvent = exports.DunningStepConfig = exports.DunningStep = exports.PaymentStatus = exports.SubscriptionPlanPricing = exports.SubscriptionPlan = void 0;
const iam_constants_js_1 = require("./iam.constants.js");
// --- Subscription Plans ---
exports.SubscriptionPlan = {
    STANDARD_MONTHLY: 'STANDARD_MONTHLY',
    STANDARD_ANNUAL: 'STANDARD_ANNUAL',
    EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
};
// --- Subscription Plan Pricing (CAD, GST-exclusive) ---
exports.SubscriptionPlanPricing = {
    [exports.SubscriptionPlan.STANDARD_MONTHLY]: {
        plan: exports.SubscriptionPlan.STANDARD_MONTHLY,
        amount: '279.00',
        interval: 'month',
        label: 'Standard Monthly',
    },
    [exports.SubscriptionPlan.STANDARD_ANNUAL]: {
        plan: exports.SubscriptionPlan.STANDARD_ANNUAL,
        amount: '2790.00',
        interval: 'year',
        label: 'Standard Annual',
    },
    [exports.SubscriptionPlan.EARLY_BIRD_MONTHLY]: {
        plan: exports.SubscriptionPlan.EARLY_BIRD_MONTHLY,
        amount: '199.00',
        interval: 'month',
        label: 'Early Bird Monthly',
    },
};
// --- Payment Statuses ---
exports.PaymentStatus = {
    PAID: 'PAID',
    FAILED: 'FAILED',
    REFUNDED: 'REFUNDED',
};
// --- Dunning Steps (5 steps over 30 days) ---
exports.DunningStep = {
    STEP_1: 'STEP_1',
    STEP_2: 'STEP_2',
    STEP_3: 'STEP_3',
    STEP_4: 'STEP_4',
    STEP_5: 'STEP_5',
};
exports.DunningStepConfig = {
    [exports.DunningStep.STEP_1]: {
        step: exports.DunningStep.STEP_1,
        day: 0,
        action: 'payment_failed_notification',
        description: 'Payment failed notification, Stripe auto-retry in 3 days',
    },
    [exports.DunningStep.STEP_2]: {
        step: exports.DunningStep.STEP_2,
        day: 3,
        action: 'second_notification',
        description: 'Second notification if retry fails',
    },
    [exports.DunningStep.STEP_3]: {
        step: exports.DunningStep.STEP_3,
        day: 7,
        action: 'suspension_warning',
        description: 'Warning: suspension in 7 days',
    },
    [exports.DunningStep.STEP_4]: {
        step: exports.DunningStep.STEP_4,
        day: 14,
        action: 'account_suspended',
        description: 'Account SUSPENDED, submission blocked, read-only access',
    },
    [exports.DunningStep.STEP_5]: {
        step: exports.DunningStep.STEP_5,
        day: 30,
        action: 'subscription_cancelled',
        description: 'Subscription cancelled, 30-day deletion grace period',
    },
};
// --- Stripe Webhook Events (6 events) ---
exports.StripeWebhookEvent = {
    INVOICE_PAID: 'invoice.paid',
    INVOICE_PAYMENT_FAILED: 'invoice.payment_failed',
    INVOICE_CREATED: 'invoice.created',
    SUBSCRIPTION_UPDATED: 'customer.subscription.updated',
    SUBSCRIPTION_DELETED: 'customer.subscription.deleted',
    CHECKOUT_SESSION_COMPLETED: 'checkout.session.completed',
};
// --- Feature Access Matrix per Subscription Status ---
exports.Feature = {
    CLAIM_CREATE: 'claim_create',
    CLAIM_VIEW: 'claim_view',
    CLAIM_EDIT: 'claim_edit',
    BATCH_SUBMIT: 'batch_submit',
    PATIENT_CREATE: 'patient_create',
    PATIENT_VIEW: 'patient_view',
    PATIENT_EDIT: 'patient_edit',
    ANALYTICS_VIEW: 'analytics_view',
    REPORTS_VIEW: 'reports_view',
    REPORTS_EXPORT: 'reports_export',
    AI_COACH: 'ai_coach',
    SETTINGS_VIEW: 'settings_view',
    SETTINGS_EDIT: 'settings_edit',
    SETTINGS_PAYMENT: 'settings_payment',
    DATA_EXPORT: 'data_export',
    DELEGATE_MANAGE: 'delegate_manage',
    PROVIDER_EDIT: 'provider_edit',
};
const ALL_FEATURES = Object.values(exports.Feature);
exports.FeatureAccessMatrix = {
    [iam_constants_js_1.SubscriptionStatus.ACTIVE]: ALL_FEATURES,
    [iam_constants_js_1.SubscriptionStatus.TRIAL]: ALL_FEATURES,
    [iam_constants_js_1.SubscriptionStatus.PAST_DUE]: ALL_FEATURES,
    [iam_constants_js_1.SubscriptionStatus.SUSPENDED]: [
        exports.Feature.CLAIM_VIEW,
        exports.Feature.PATIENT_VIEW,
        exports.Feature.ANALYTICS_VIEW,
        exports.Feature.REPORTS_VIEW,
        exports.Feature.SETTINGS_VIEW,
        exports.Feature.SETTINGS_PAYMENT,
        exports.Feature.DATA_EXPORT,
    ],
    [iam_constants_js_1.SubscriptionStatus.CANCELLED]: [exports.Feature.DATA_EXPORT],
};
// --- Incident Statuses ---
exports.IncidentStatus = {
    INVESTIGATING: 'INVESTIGATING',
    IDENTIFIED: 'IDENTIFIED',
    MONITORING: 'MONITORING',
    RESOLVED: 'RESOLVED',
};
// --- Status Page Component Names (8 monitored components) ---
exports.StatusComponent = {
    WEB_APP: 'WEB_APP',
    API: 'API',
    HLINK_SUBMISSION: 'HLINK_SUBMISSION',
    WCB_SUBMISSION: 'WCB_SUBMISSION',
    AI_COACH: 'AI_COACH',
    EMAIL_DELIVERY: 'EMAIL_DELIVERY',
    DATABASE: 'DATABASE',
    PAYMENT_PROCESSING: 'PAYMENT_PROCESSING',
};
// --- Component Health Statuses ---
exports.ComponentHealth = {
    OPERATIONAL: 'OPERATIONAL',
    DEGRADED: 'DEGRADED',
    PARTIAL_OUTAGE: 'PARTIAL_OUTAGE',
    MAJOR_OUTAGE: 'MAJOR_OUTAGE',
    MAINTENANCE: 'MAINTENANCE',
};
// --- Platform Constants ---
exports.GST_RATE = 0.05;
exports.EARLY_BIRD_CAP = 100;
exports.DELETION_GRACE_PERIOD_DAYS = 30;
exports.DUNNING_SUSPENSION_DAY = 14;
exports.DUNNING_CANCELLATION_DAY = 30;
//# sourceMappingURL=platform.constants.js.map