// ============================================================================
// Domain 12: Platform Operations — Constants
// ============================================================================

import { SubscriptionStatus } from './iam.constants.js';

// --- Subscription Plans ---

export const SubscriptionPlan = {
  STANDARD_MONTHLY: 'STANDARD_MONTHLY',
  STANDARD_ANNUAL: 'STANDARD_ANNUAL',
  EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
  EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
  CLINIC_MONTHLY: 'CLINIC_MONTHLY',
  CLINIC_ANNUAL: 'CLINIC_ANNUAL',
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
    amount: '3181.00',
    interval: 'year',
    label: 'Standard Annual',
  },
  [SubscriptionPlan.EARLY_BIRD_MONTHLY]: {
    plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
    amount: '199.00',
    interval: 'month',
    label: 'Early Bird Monthly',
  },
  [SubscriptionPlan.EARLY_BIRD_ANNUAL]: {
    plan: SubscriptionPlan.EARLY_BIRD_ANNUAL,
    amount: '2388.00',
    interval: 'year',
    label: 'Early Bird Annual',
  },
  [SubscriptionPlan.CLINIC_MONTHLY]: {
    plan: SubscriptionPlan.CLINIC_MONTHLY,
    amount: '251.10',
    interval: 'month',
    label: 'Clinic Monthly',
  },
  [SubscriptionPlan.CLINIC_ANNUAL]: {
    plan: SubscriptionPlan.CLINIC_ANNUAL,
    amount: '2863.00',
    interval: 'year',
    label: 'Clinic Annual',
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
export const DELETION_GRACE_PERIOD_DAYS = 45;
export const BACKUP_PURGE_DEADLINE_DAYS = 90;
export const DUNNING_SUSPENSION_DAY = 14;
export const DUNNING_CANCELLATION_DAY = 30;

// --- Clinic/Practice Tier Constants ---

export const CLINIC_MINIMUM_PHYSICIANS = 5;
export const DISCOUNT_ANNUAL = 0.05;
export const DISCOUNT_CLINIC = 0.10;
export const DISCOUNT_CEILING = 0.15;

// --- Billing Mode ---

export const BillingMode = {
  PRACTICE_CONSOLIDATED: 'PRACTICE_CONSOLIDATED',
  INDIVIDUAL_EARLY_BIRD: 'INDIVIDUAL_EARLY_BIRD',
} as const;

export type BillingMode = (typeof BillingMode)[keyof typeof BillingMode];

// --- Practice Status ---

export const PracticeStatus = {
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  CANCELLED: 'CANCELLED',
} as const;

export type PracticeStatus = (typeof PracticeStatus)[keyof typeof PracticeStatus];

// --- Practice Invitation Status ---

export const PracticeInvitationStatus = {
  PENDING: 'PENDING',
  ACCEPTED: 'ACCEPTED',
  DECLINED: 'DECLINED',
  EXPIRED: 'EXPIRED',
} as const;

export type PracticeInvitationStatus =
  (typeof PracticeInvitationStatus)[keyof typeof PracticeInvitationStatus];

// --- Practice Invitation Expiry ---

export const PRACTICE_INVITATION_EXPIRY_DAYS = 7;

// --- Discount Framework (Batch 2: Pricing Lifecycle) ---

export const DISCOUNT_ANNUAL_PERCENT = 5;
export const DISCOUNT_CLINIC_PERCENT = 10;
export const DISCOUNT_CEILING_PERCENT = 15;

export const BASE_MONTHLY_RATE = 279;
export const EARLY_BIRD_MONTHLY_RATE = 199;
export const EARLY_BIRD_RATE_LOCK_MONTHS = 12;
export const EARLY_BIRD_EXPIRY_WARNING_DAYS = 30;

// Minimum effective rate: 85% of base rate ($237.15). No discount combination
// may produce a rate below this floor.
export const MINIMUM_RATE_FLOOR = BASE_MONTHLY_RATE * (1 - DISCOUNT_CEILING_PERCENT / 100);

// --- Referral Program (Batch 3: Referral Redesign) ---

export const ReferralRedemptionStatus = {
  PENDING: 'PENDING',
  QUALIFIED: 'QUALIFIED',
  CREDITED: 'CREDITED',
  EXPIRED: 'EXPIRED',
} as const;

export type ReferralRedemptionStatus =
  (typeof ReferralRedemptionStatus)[keyof typeof ReferralRedemptionStatus];

export const CreditApplicationTarget = {
  PRACTICE_INVOICE: 'PRACTICE_INVOICE',
  INDIVIDUAL_BANK: 'INDIVIDUAL_BANK',
} as const;

export type CreditApplicationTarget =
  (typeof CreditApplicationTarget)[keyof typeof CreditApplicationTarget];

export const REFERRAL_MAX_CREDITS_PER_YEAR = 3;
export const REFERRAL_CODE_LENGTH = 8;
export const REFERRAL_CREDIT_CHOICE_DEADLINE_DAYS = 7;

// --- Referral Credit Values ---
// Credit value = 1 month at referrer's current rate at time of qualification:
//   Early Bird:           $199.00
//   Standard Monthly:     $279.00
//   Standard Annual:      $265.08 (monthly equivalent: $3,181 / 12)
//   Clinic Monthly:       $251.10
//   Clinic Annual:        $238.58 (monthly equivalent: $2,863 / 12)
// Credit is calculated in checkReferralQualification(), not stored as a constant.

// --- Annual Cancellation Policy (B4-1) ---

export const ANNUAL_MINIMUM_COMMITMENT_MONTHS = 6;

export const ANNUAL_CANCELLATION_FORFEIT_MESSAGE =
  'Annual subscriptions require a 6-month minimum commitment. Your access continues until [period end date].';

export const CancellationPolicy = {
  /** Months 1-6: no refund, subscription continues until period end */
  FORFEIT_PERIOD: 'FORFEIT_PERIOD',
  /** Months 7-12: prorated refund for remaining months */
  PRORATED_REFUND: 'PRORATED_REFUND',
  /** Monthly subscriptions: cancel at period end, no refund logic needed */
  MONTHLY_CANCEL: 'MONTHLY_CANCEL',
} as const;

export type CancellationPolicy =
  (typeof CancellationPolicy)[keyof typeof CancellationPolicy];

/**
 * Calculate the prorated refund for an annual subscription cancellation.
 *
 * Formula: refund = (12 - months_used) * (annual_amount / 12)
 *
 * Returns null if months_used < ANNUAL_MINIMUM_COMMITMENT_MONTHS (no refund).
 * Returns 0 refund if months_used >= 12 (no remaining months).
 */
export function calculateAnnualRefund(
  annualAmount: number,
  monthsUsed: number,
): { refundAmount: number; monthsRemaining: number; monthlyRate: number } | null {
  if (monthsUsed < ANNUAL_MINIMUM_COMMITMENT_MONTHS) {
    return null; // Forfeit period — no refund
  }
  const monthlyRate = annualAmount / 12;
  const monthsRemaining = Math.max(0, 12 - monthsUsed);
  const refundAmount = parseFloat((monthsRemaining * monthlyRate).toFixed(2));
  return { refundAmount, monthsRemaining, monthlyRate };
}

/**
 * Determine the cancellation policy that applies based on the subscription plan
 * and months elapsed since current_period_start.
 */
export function determineCancellationPolicy(
  plan: string,
  monthsElapsed: number,
): CancellationPolicy {
  // Monthly plans: always MONTHLY_CANCEL
  if (plan.includes('MONTHLY')) {
    return CancellationPolicy.MONTHLY_CANCEL;
  }
  // Annual plans: check 6-month threshold
  if (monthsElapsed < ANNUAL_MINIMUM_COMMITMENT_MONTHS) {
    return CancellationPolicy.FORFEIT_PERIOD;
  }
  return CancellationPolicy.PRORATED_REFUND;
}

// --- IMA Amendment Types ---

export const ImaAmendmentType = {
  NON_MATERIAL: 'NON_MATERIAL',
  MATERIAL: 'MATERIAL',
} as const;

export type ImaAmendmentType =
  (typeof ImaAmendmentType)[keyof typeof ImaAmendmentType];

// --- IMA Amendment Response Types ---

export const ImaAmendmentResponseType = {
  ACKNOWLEDGED: 'ACKNOWLEDGED',
  ACCEPTED: 'ACCEPTED',
  REJECTED: 'REJECTED',
} as const;

export type ImaAmendmentResponseType =
  (typeof ImaAmendmentResponseType)[keyof typeof ImaAmendmentResponseType];

// --- Breach Status ---

export const BreachStatus = {
  INVESTIGATING: 'INVESTIGATING',
  NOTIFYING: 'NOTIFYING',
  MONITORING: 'MONITORING',
  RESOLVED: 'RESOLVED',
} as const;

export type BreachStatus = (typeof BreachStatus)[keyof typeof BreachStatus];

// --- Breach Update Type ---

export const BreachUpdateType = {
  INITIAL: 'INITIAL',
  SUPPLEMENTARY: 'SUPPLEMENTARY',
} as const;

export type BreachUpdateType =
  (typeof BreachUpdateType)[keyof typeof BreachUpdateType];

// --- Data Destruction Status ---

export const DestructionStatus = {
  PENDING: 'PENDING',
  ACTIVE_DELETED: 'ACTIVE_DELETED',
  FILES_DELETED: 'FILES_DELETED',
  BACKUP_PURGED: 'BACKUP_PURGED',
  CONFIRMED: 'CONFIRMED',
} as const;

export type DestructionStatus =
  (typeof DestructionStatus)[keyof typeof DestructionStatus];

// --- Platform Audit Actions (IMA) ---

export const PlatformAuditAction = {
  // IMA Amendment
  AMENDMENT_CREATED: 'amendment.created',
  AMENDMENT_ACKNOWLEDGED: 'amendment.acknowledged',
  AMENDMENT_ACCEPTED: 'amendment.accepted',
  AMENDMENT_REJECTED: 'amendment.rejected',

  // Breach
  BREACH_CREATED: 'breach.created',
  BREACH_NOTIFICATION_SENT: 'breach.notification_sent',
  BREACH_UPDATED: 'breach.updated',
  BREACH_RESOLVED: 'breach.resolved',
  BREACH_EVIDENCE_HOLD_SET: 'breach.evidence_hold_set',

  // Destruction
  DESTRUCTION_ACTIVE_DELETED: 'destruction.active_deleted',
  DESTRUCTION_FILES_DELETED: 'destruction.files_deleted',
  DESTRUCTION_BACKUP_PURGED: 'destruction.backup_purged',
  DESTRUCTION_CONFIRMED: 'destruction.confirmed',

  // Export
  EXPORT_FULL_HI_REQUESTED: 'export.full_hi_requested',
  EXPORT_FULL_HI_READY: 'export.full_hi_ready',
  EXPORT_PATIENT_ACCESS_REQUESTED: 'export.patient_access_requested',
  EXPORT_PATIENT_ACCESS_READY: 'export.patient_access_ready',

  // Patient correction
  PATIENT_CORRECTION_APPLIED: 'patient.correction_applied',
} as const;

export type PlatformAuditAction =
  (typeof PlatformAuditAction)[keyof typeof PlatformAuditAction];
