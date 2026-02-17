// ============================================================================
// Domain 12: Platform Operations — Constants
// ============================================================================

import { SubscriptionStatus } from './iam.constants.js';

// --- Subscription Plans ---

export const SubscriptionPlan = {
  STANDARD_MONTHLY: 'STANDARD_MONTHLY',
  STANDARD_ANNUAL: 'STANDARD_ANNUAL',
  EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
} as const;

export type SubscriptionPlan =
  (typeof SubscriptionPlan)[keyof typeof SubscriptionPlan];

// --- Subscription Plan Pricing (CAD, GST-exclusive) ---

export const SubscriptionPlanPricing = {
  [SubscriptionPlan.STANDARD_MONTHLY]: {
    plan: SubscriptionPlan.STANDARD_MONTHLY,
    amount: '279.00',
    interval: 'month',
    label: 'Standard Monthly',
  },
  [SubscriptionPlan.STANDARD_ANNUAL]: {
    plan: SubscriptionPlan.STANDARD_ANNUAL,
    amount: '2790.00',
    interval: 'year',
    label: 'Standard Annual',
  },
  [SubscriptionPlan.EARLY_BIRD_MONTHLY]: {
    plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
    amount: '199.00',
    interval: 'month',
    label: 'Early Bird Monthly',
  },
} as const;

// --- Payment Statuses ---

export const PaymentStatus = {
  PAID: 'PAID',
  FAILED: 'FAILED',
  REFUNDED: 'REFUNDED',
} as const;

export type PaymentStatus = (typeof PaymentStatus)[keyof typeof PaymentStatus];

// --- Dunning Steps (5 steps over 30 days) ---

export const DunningStep = {
  STEP_1: 'STEP_1',
  STEP_2: 'STEP_2',
  STEP_3: 'STEP_3',
  STEP_4: 'STEP_4',
  STEP_5: 'STEP_5',
} as const;

export type DunningStep = (typeof DunningStep)[keyof typeof DunningStep];

export const DunningStepConfig = {
  [DunningStep.STEP_1]: {
    step: DunningStep.STEP_1,
    day: 0,
    action: 'payment_failed_notification',
    description: 'Payment failed notification, Stripe auto-retry in 3 days',
  },
  [DunningStep.STEP_2]: {
    step: DunningStep.STEP_2,
    day: 3,
    action: 'second_notification',
    description: 'Second notification if retry fails',
  },
  [DunningStep.STEP_3]: {
    step: DunningStep.STEP_3,
    day: 7,
    action: 'suspension_warning',
    description: 'Warning: suspension in 7 days',
  },
  [DunningStep.STEP_4]: {
    step: DunningStep.STEP_4,
    day: 14,
    action: 'account_suspended',
    description: 'Account SUSPENDED, submission blocked, read-only access',
  },
  [DunningStep.STEP_5]: {
    step: DunningStep.STEP_5,
    day: 30,
    action: 'subscription_cancelled',
    description: 'Subscription cancelled, 30-day deletion grace period',
  },
} as const;

// --- Stripe Webhook Events (6 events) ---

export const StripeWebhookEvent = {
  INVOICE_PAID: 'invoice.paid',
  INVOICE_PAYMENT_FAILED: 'invoice.payment_failed',
  INVOICE_CREATED: 'invoice.created',
  SUBSCRIPTION_UPDATED: 'customer.subscription.updated',
  SUBSCRIPTION_DELETED: 'customer.subscription.deleted',
  CHECKOUT_SESSION_COMPLETED: 'checkout.session.completed',
} as const;

export type StripeWebhookEvent =
  (typeof StripeWebhookEvent)[keyof typeof StripeWebhookEvent];

// --- Feature Access Matrix per Subscription Status ---

export const Feature = {
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
} as const;

export type Feature = (typeof Feature)[keyof typeof Feature];

const ALL_FEATURES: readonly Feature[] = Object.values(Feature);

export const FeatureAccessMatrix: Readonly<
  Record<string, readonly Feature[]>
> = {
  [SubscriptionStatus.ACTIVE]: ALL_FEATURES,
  [SubscriptionStatus.TRIAL]: ALL_FEATURES,
  [SubscriptionStatus.PAST_DUE]: ALL_FEATURES,
  [SubscriptionStatus.SUSPENDED]: [
    Feature.CLAIM_VIEW,
    Feature.PATIENT_VIEW,
    Feature.ANALYTICS_VIEW,
    Feature.REPORTS_VIEW,
    Feature.SETTINGS_VIEW,
    Feature.SETTINGS_PAYMENT,
    Feature.DATA_EXPORT,
  ],
  [SubscriptionStatus.CANCELLED]: [Feature.DATA_EXPORT],
} as const;

// --- Incident Statuses ---

export const IncidentStatus = {
  INVESTIGATING: 'INVESTIGATING',
  IDENTIFIED: 'IDENTIFIED',
  MONITORING: 'MONITORING',
  RESOLVED: 'RESOLVED',
} as const;

export type IncidentStatus =
  (typeof IncidentStatus)[keyof typeof IncidentStatus];

// --- Status Page Component Names (8 monitored components) ---

export const StatusComponent = {
  WEB_APP: 'WEB_APP',
  API: 'API',
  HLINK_SUBMISSION: 'HLINK_SUBMISSION',
  WCB_SUBMISSION: 'WCB_SUBMISSION',
  AI_COACH: 'AI_COACH',
  EMAIL_DELIVERY: 'EMAIL_DELIVERY',
  DATABASE: 'DATABASE',
  PAYMENT_PROCESSING: 'PAYMENT_PROCESSING',
} as const;

export type StatusComponent =
  (typeof StatusComponent)[keyof typeof StatusComponent];

// --- Component Health Statuses ---

export const ComponentHealth = {
  OPERATIONAL: 'OPERATIONAL',
  DEGRADED: 'DEGRADED',
  PARTIAL_OUTAGE: 'PARTIAL_OUTAGE',
  MAJOR_OUTAGE: 'MAJOR_OUTAGE',
  MAINTENANCE: 'MAINTENANCE',
} as const;

export type ComponentHealth =
  (typeof ComponentHealth)[keyof typeof ComponentHealth];

// --- Platform Constants ---

export const GST_RATE = 0.05;
export const EARLY_BIRD_CAP = 100;
export const DELETION_GRACE_PERIOD_DAYS = 30;
export const DUNNING_SUSPENSION_DAY = 14;
export const DUNNING_CANCELLATION_DAY = 30;
