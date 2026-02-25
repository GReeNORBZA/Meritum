// ============================================================================
// Domain 12: Platform Operations — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  SubscriptionPlan,
  IncidentStatus,
  ComponentHealth,
} from '../constants/platform.constants.js';
import { SubscriptionStatus } from '../constants/iam.constants.js';

// --- Subscription: Checkout Session ---

export const createCheckoutSessionSchema = z.object({
  plan: z.enum([
    SubscriptionPlan.STANDARD_MONTHLY,
    SubscriptionPlan.STANDARD_ANNUAL,
    SubscriptionPlan.EARLY_BIRD_MONTHLY,
    SubscriptionPlan.EARLY_BIRD_ANNUAL,
    SubscriptionPlan.CLINIC_MONTHLY,
    SubscriptionPlan.CLINIC_ANNUAL,
  ]),
  success_url: z.string().url(),
  cancel_url: z.string().url(),
});

export type CreateCheckoutSession = z.infer<typeof createCheckoutSessionSchema>;

// --- Subscription: Customer Portal Session ---

export const createPortalSessionSchema = z.object({
  return_url: z.string().url(),
});

export type CreatePortalSession = z.infer<typeof createPortalSessionSchema>;

// --- Webhook: Stripe Signature Header ---

export const stripeWebhookHeaderSchema = z.object({
  'stripe-signature': z.string(),
});

export type StripeWebhookHeader = z.infer<typeof stripeWebhookHeaderSchema>;

// --- Status Page: Public Query (no required fields) ---

export const statusPageQuerySchema = z.object({});

export type StatusPageQuery = z.infer<typeof statusPageQuerySchema>;

// --- Status Page: Incident History Query ---

export const incidentHistoryQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
});

export type IncidentHistoryQuery = z.infer<typeof incidentHistoryQuerySchema>;

// --- Admin: Create Incident ---

const INCIDENT_SEVERITY = ['minor', 'major', 'critical'] as const;

export const createIncidentSchema = z.object({
  title: z.string().min(1).max(200),
  severity: z.enum(INCIDENT_SEVERITY),
  affected_components: z.array(z.string().uuid()).min(1),
  message: z.string().min(1),
});

export type CreateIncident = z.infer<typeof createIncidentSchema>;

// --- Admin: Update Incident ---

const INCIDENT_UPDATE_STATUS = [
  'investigating',
  'identified',
  'monitoring',
  'resolved',
] as const;

export const updateIncidentSchema = z.object({
  status: z.enum(INCIDENT_UPDATE_STATUS),
  message: z.string().min(1),
});

export type UpdateIncident = z.infer<typeof updateIncidentSchema>;

// --- Admin: Update Component Status ---

const COMPONENT_STATUS = [
  'operational',
  'degraded',
  'partial_outage',
  'major_outage',
  'maintenance',
] as const;

export const updateComponentStatusSchema = z.object({
  status: z.enum(COMPONENT_STATUS),
});

export type UpdateComponentStatus = z.infer<typeof updateComponentStatusSchema>;

// --- Admin: Subscription Query ---

const SUBSCRIPTION_STATUSES = [
  SubscriptionStatus.TRIAL,
  SubscriptionStatus.ACTIVE,
  SubscriptionStatus.PAST_DUE,
  SubscriptionStatus.SUSPENDED,
  SubscriptionStatus.CANCELLED,
] as const;

export const adminSubscriptionQuerySchema = z.object({
  status: z.enum(SUBSCRIPTION_STATUSES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(50),
});

export type AdminSubscriptionQuery = z.infer<typeof adminSubscriptionQuerySchema>;

// --- Practice Management: Create Practice ---

export const createPracticeSchema = z.object({
  name: z.string().min(1).max(200).trim(),
  billing_frequency: z.enum(['MONTHLY', 'ANNUAL']),
});

export type CreatePractice = z.infer<typeof createPracticeSchema>;

// --- Practice Management: Update Practice ---

export const updatePracticeSchema = z.object({
  name: z.string().min(1).max(200).trim().optional(),
  billing_frequency: z.enum(['MONTHLY', 'ANNUAL']).optional(),
});

export type UpdatePractice = z.infer<typeof updatePracticeSchema>;

// --- Practice Management: Invite Physician ---

export const invitePhysicianSchema = z.object({
  email: z.string().email().max(255).toLowerCase().trim(),
});

export type InvitePhysician = z.infer<typeof invitePhysicianSchema>;

// --- Practice Management: Accept Invitation (token param) ---

export const acceptInvitationParamsSchema = z.object({
  token: z.string().min(1).max(256),
});

export type AcceptInvitationParams = z.infer<typeof acceptInvitationParamsSchema>;

// --- Practice Management: Practice ID param ---

export const practiceIdParamsSchema = z.object({
  id: z.string().uuid(),
});

export type PracticeIdParams = z.infer<typeof practiceIdParamsSchema>;

// --- Practice Management: Seat Removal params ---

export const removeSeatParamsSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
});

export type RemoveSeatParams = z.infer<typeof removeSeatParamsSchema>;

// --- Practice Management: Seats Query ---

export const practiceSeatsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(50),
});

export type PracticeSeatsQuery = z.infer<typeof practiceSeatsQuerySchema>;

// --- Practice Management: Invoices Query ---

export const practiceInvoicesQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
});

export type PracticeInvoicesQuery = z.infer<typeof practiceInvoicesQuerySchema>;

// --- Referral Program: Validate Code (public endpoint) ---

export const validateReferralCodeSchema = z.object({
  code: z.string().length(8).regex(/^[A-Z0-9]{8}$/, 'Invalid referral code format'),
});

export type ValidateReferralCode = z.infer<typeof validateReferralCodeSchema>;

// --- Referral Program: Apply Credit ---

export const applyReferralCreditParamsSchema = z.object({
  redemptionId: z.string().uuid(),
});

export type ApplyReferralCreditParams = z.infer<typeof applyReferralCreditParamsSchema>;

export const applyReferralCreditBodySchema = z.object({
  target: z.enum(['PRACTICE_INVOICE', 'INDIVIDUAL_BANK']),
});

export type ApplyReferralCreditBody = z.infer<typeof applyReferralCreditBodySchema>;

// --- Referral Program: My Credits Query ---

export const referralCreditsQuerySchema = z.object({
  status: z.enum(['PENDING', 'QUALIFIED', 'CREDITED', 'EXPIRED']).optional(),
  anniversary_year: z.coerce.number().int().min(1).optional(),
});

export type ReferralCreditsQuery = z.infer<typeof referralCreditsQuerySchema>;
