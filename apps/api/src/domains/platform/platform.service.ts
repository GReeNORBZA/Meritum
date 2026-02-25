import {
  SubscriptionPlan,
  EARLY_BIRD_CAP,
  GST_RATE,
  DELETION_GRACE_PERIOD_DAYS,
  BACKUP_PURGE_DEADLINE_DAYS,
  PlatformAuditAction,
  PaymentStatus,
  StripeWebhookEvent,
  FeatureAccessMatrix,
  StatusComponent,
  ComponentHealth,
  IncidentStatus,
  EARLY_BIRD_RATE_LOCK_MONTHS,
  EARLY_BIRD_EXPIRY_WARNING_DAYS,
  BreachStatus,
  BreachUpdateType,
  type Feature,
} from '@meritum/shared/constants/platform.constants.js';
import { isEarlyBirdRate } from '@meritum/shared/utils/pricing.utils.js';
import { SubscriptionStatus } from '@meritum/shared/constants/iam.constants.js';
import { ConflictError, BusinessRuleError, NotFoundError, ValidationError, ForbiddenError } from '../../lib/errors.js';
import {
  type SubscriptionRepository,
  type PaymentRepository,
  type StatusComponentRepository,
  type IncidentRepository,
  type AmendmentRepository,
  type BreachRepository,
  type DestructionTrackingRepository,
} from './platform.repository.js';
import { type SpacesFileClient } from '../../lib/spaces.js';

// ---------------------------------------------------------------------------
// Stripe SDK interface (injected for testability)
// ---------------------------------------------------------------------------

export interface StripeClient {
  customers: {
    create(params: {
      email: string;
      name: string;
      metadata?: Record<string, string>;
    }): Promise<{ id: string }>;
    del(customerId: string): Promise<{ id: string; deleted: boolean }>;
  };
  checkout: {
    sessions: {
      create(params: {
        mode: 'subscription';
        customer: string;
        line_items: Array<{ price: string; quantity: number }>;
        subscription_data?: {
          default_tax_rates?: string[];
        };
        success_url: string;
        cancel_url: string;
        metadata?: Record<string, string>;
      }): Promise<{ url: string }>;
    };
  };
  billingPortal: {
    sessions: {
      create(params: {
        customer: string;
        return_url: string;
      }): Promise<{ url: string }>;
    };
  };
  taxRates: {
    create(params: {
      display_name: string;
      percentage: number;
      inclusive: boolean;
      country: string;
      state?: string;
      jurisdiction?: string;
      description?: string;
    }): Promise<{ id: string }>;
  };
  webhooks: {
    constructEvent(
      payload: string,
      signature: string,
      secret: string,
    ): StripeEvent;
  };
  invoiceItems: {
    create(params: {
      invoice: string;
      amount: number;
      currency: string;
      description: string;
      tax_rates?: string[];
    }): Promise<{ id: string }>;
  };
  subscriptions: {
    cancel(subscriptionId: string): Promise<{ id: string; status: string }>;
    update(subscriptionId: string, params: {
      items?: Array<{ id?: string; price?: string; quantity?: number }>;
      quantity?: number;
      proration_behavior?: string;
    }): Promise<{ id: string; status: string; items?: { data: Array<{ id: string; price: { id: string } }> } }>;
  };
}

// ---------------------------------------------------------------------------
// Stripe Event types (minimal typing for webhook processing)
// ---------------------------------------------------------------------------

export interface StripeEvent {
  id: string;
  type: string;
  data: {
    object: Record<string, any>;
  };
}

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

export interface UserRepo {
  findUserById(userId: string): Promise<{
    userId: string;
    email: string;
    fullName: string;
  } | undefined>;
  updateSubscriptionStatus(userId: string, status: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Data deletion interface (for PHI cleanup during account deletion)
// ---------------------------------------------------------------------------

export interface DataDeletionRepo {
  deleteClaimsByProviderId(providerId: string): Promise<number>;
  deletePatientsByProviderId(providerId: string): Promise<number>;
  deleteReportsByProviderId(providerId: string): Promise<number>;
  stripPiiFromAuditLogs(providerId: string): Promise<number>;
  anonymiseAiLearningData(providerId: string): Promise<number>;
  deactivateUser(userId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Audit logger interface (for recording dunning/lifecycle actions)
// ---------------------------------------------------------------------------

export interface AuditLogger {
  log(entry: {
    action: string;
    resourceType: string;
    resourceId: string;
    actorType: string;
    metadata?: Record<string, unknown>;
  }): Promise<void>;
}

// ---------------------------------------------------------------------------
// Active provider repo interface (for amendment notifications)
// ---------------------------------------------------------------------------

export interface ActiveProviderRepo {
  findActiveProviderIds(): Promise<string[]>;
}

export interface PlatformServiceDeps {
  subscriptionRepo: SubscriptionRepository;
  paymentRepo: PaymentRepository;
  statusComponentRepo: StatusComponentRepository;
  incidentRepo: IncidentRepository;
  amendmentRepo?: AmendmentRepository;
  activeProviderRepo?: ActiveProviderRepo;
  userRepo: UserRepo;
  stripe: StripeClient;
  config: {
    stripePriceStandardMonthly: string;
    stripePriceStandardAnnual: string;
    stripePriceEarlyBirdMonthly: string;
    stripePriceEarlyBirdAnnual: string;
    stripePriceClinicMonthly?: string;
    stripePriceClinicAnnual?: string;
    stripeWebhookSecret: string;
    gstTaxRateId?: string;
  };
  dataDeletionRepo?: DataDeletionRepo;
  breachRepo?: BreachRepository;
  auditLogger?: AuditLogger;
  destructionTrackingRepo?: DestructionTrackingRepository;
  spacesFileClient?: SpacesFileClient;
}

// ---------------------------------------------------------------------------
// Event emitter interface (for notification service integration)
// ---------------------------------------------------------------------------

export interface PlatformEventEmitter {
  emit(event: string, data: Record<string, unknown>): void;
}

// ---------------------------------------------------------------------------
// Plan → Price ID mapping
// ---------------------------------------------------------------------------

function getPriceId(plan: string, config: PlatformServiceDeps['config']): string {
  switch (plan) {
    case SubscriptionPlan.STANDARD_MONTHLY:
      return config.stripePriceStandardMonthly;
    case SubscriptionPlan.STANDARD_ANNUAL:
      return config.stripePriceStandardAnnual;
    case SubscriptionPlan.EARLY_BIRD_MONTHLY:
      return config.stripePriceEarlyBirdMonthly;
    case SubscriptionPlan.EARLY_BIRD_ANNUAL:
      return config.stripePriceEarlyBirdAnnual;
    case SubscriptionPlan.CLINIC_MONTHLY:
      return config.stripePriceClinicMonthly ?? config.stripePriceStandardMonthly;
    case SubscriptionPlan.CLINIC_ANNUAL:
      return config.stripePriceClinicAnnual ?? config.stripePriceStandardAnnual;
    default:
      throw new BusinessRuleError(`Invalid subscription plan: ${plan}`);
  }
}

// ---------------------------------------------------------------------------
// Service: Create Checkout Session
// ---------------------------------------------------------------------------

export interface CheckoutSessionResult {
  checkout_url: string;
}

/**
 * Create a Stripe Checkout session for subscription signup.
 *
 * 1. Verify no active subscription exists for this user.
 * 2. For EARLY_BIRD_MONTHLY: verify cap has not been reached.
 * 3. Create or retrieve Stripe Customer (name + email only — no PHI).
 * 4. Create Checkout session with correct Price ID and GST tax rate.
 * 5. Return the Checkout URL.
 */
export async function createCheckoutSession(
  deps: PlatformServiceDeps,
  userId: string,
  plan: string,
  successUrl: string,
  cancelUrl: string,
): Promise<CheckoutSessionResult> {
  // 1. Check for existing active subscription
  const existingSub = await deps.subscriptionRepo.findSubscriptionByProviderId(userId);
  if (existingSub) {
    const activeStatuses: string[] = [
      SubscriptionStatus.TRIAL,
      SubscriptionStatus.ACTIVE,
      SubscriptionStatus.PAST_DUE,
    ];
    if (activeStatuses.includes(existingSub.status)) {
      throw new ConflictError('User already has an active subscription');
    }
  }

  // 2a. Early bird re-signup prevention (spec B2-3)
  if (isEarlyBirdRate(plan)) {
    const hadEarlyBird = await deps.subscriptionRepo.hasEverHadEarlyBird(userId);
    if (hadEarlyBird) {
      throw new BusinessRuleError(
        'Early bird rate does not survive cancellation',
        { code: 'EARLY_BIRD_INELIGIBLE' },
      );
    }
  }

  // 2b. Early bird cap check
  if (plan === SubscriptionPlan.EARLY_BIRD_MONTHLY || plan === SubscriptionPlan.EARLY_BIRD_ANNUAL) {
    const earlyBirdCount = await deps.subscriptionRepo.countEarlyBirdSubscriptions();
    if (earlyBirdCount >= EARLY_BIRD_CAP) {
      throw new BusinessRuleError(
        'Early bird plan is sold out',
        { code: 'EARLY_BIRD_SOLD_OUT' },
      );
    }
  }

  // 3. Look up user to get email and name (no PHI beyond name/email)
  const user = await deps.userRepo.findUserById(userId);
  if (!user) {
    throw new NotFoundError('User');
  }

  // Create Stripe Customer
  const customer = await deps.stripe.customers.create({
    email: user.email,
    name: user.fullName,
    metadata: { meritum_user_id: userId },
  });

  // 4. Create Checkout Session
  const priceId = getPriceId(plan, deps.config);

  const sessionParams: Parameters<typeof deps.stripe.checkout.sessions.create>[0] = {
    mode: 'subscription',
    customer: customer.id,
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: successUrl,
    cancel_url: cancelUrl,
    metadata: { meritum_user_id: userId, plan },
  };

  // Add GST tax rate if configured
  if (deps.config.gstTaxRateId) {
    sessionParams.subscription_data = {
      default_tax_rates: [deps.config.gstTaxRateId],
    };
  }

  const session = await deps.stripe.checkout.sessions.create(sessionParams);

  // 5. Return checkout URL
  return { checkout_url: session.url };
}

// ---------------------------------------------------------------------------
// Service: Create Portal Session
// ---------------------------------------------------------------------------

export interface PortalSessionResult {
  portal_url: string;
}

/**
 * Create a Stripe Billing Portal session for an existing subscriber.
 *
 * 1. Find the user's subscription.
 * 2. Create a Billing Portal session with the Stripe Customer ID.
 * 3. Return the portal URL.
 */
export async function createPortalSession(
  deps: PlatformServiceDeps,
  userId: string,
  returnUrl: string,
): Promise<PortalSessionResult> {
  // 1. Find subscription for this user
  const subscription = await deps.subscriptionRepo.findSubscriptionByProviderId(userId);
  if (!subscription) {
    throw new NotFoundError('Subscription');
  }

  // 2. Create Billing Portal session
  const portalSession = await deps.stripe.billingPortal.sessions.create({
    customer: subscription.stripeCustomerId,
    return_url: returnUrl,
  });

  // 3. Return portal URL
  return { portal_url: portalSession.url };
}

// ---------------------------------------------------------------------------
// Service: Process Webhook Event
// ---------------------------------------------------------------------------

/**
 * Verify a Stripe webhook signature and dispatch to the appropriate handler.
 *
 * 1. Verify signature using STRIPE_WEBHOOK_SECRET. Reject if invalid.
 * 2. Parse event. Dispatch to handler by event type.
 */
export async function processWebhookEvent(
  deps: PlatformServiceDeps,
  rawBody: string,
  signature: string,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ received: boolean }> {
  if (!signature) {
    throw new ValidationError('Missing stripe-signature header');
  }

  let event: StripeEvent;
  try {
    event = deps.stripe.webhooks.constructEvent(
      rawBody,
      signature,
      deps.config.stripeWebhookSecret,
    );
  } catch {
    throw new ValidationError('Invalid webhook signature');
  }

  switch (event.type) {
    case StripeWebhookEvent.CHECKOUT_SESSION_COMPLETED:
      await handleCheckoutCompleted(deps, event, eventEmitter);
      break;
    case StripeWebhookEvent.INVOICE_PAID:
      await handleInvoicePaid(deps, event, eventEmitter);
      break;
    case StripeWebhookEvent.INVOICE_PAYMENT_FAILED:
      await handleInvoicePaymentFailed(deps, event, eventEmitter);
      break;
    case StripeWebhookEvent.INVOICE_CREATED:
      await handleInvoiceCreated(deps, event);
      break;
    case StripeWebhookEvent.SUBSCRIPTION_UPDATED:
      await handleSubscriptionUpdated(deps, event);
      break;
    case StripeWebhookEvent.SUBSCRIPTION_DELETED:
      await handleSubscriptionDeleted(deps, event, eventEmitter);
      break;
    default:
      // Unhandled event type — acknowledge receipt without processing
      break;
  }

  return { received: true };
}

// ---------------------------------------------------------------------------
// Handler: checkout.session.completed
// ---------------------------------------------------------------------------

/**
 * Link Stripe customer_id and subscription_id to Meritum user.
 * Create subscription record with status ACTIVE.
 * Record initial payment if applicable.
 * Emit SUBSCRIPTION_CREATED event.
 */
export async function handleCheckoutCompleted(
  deps: PlatformServiceDeps,
  event: StripeEvent,
  eventEmitter?: PlatformEventEmitter,
): Promise<void> {
  const session = event.data.object;
  const userId = session.metadata?.meritum_user_id;
  const plan = session.metadata?.plan;
  const stripeCustomerId = session.customer as string;
  const stripeSubscriptionId = session.subscription as string;

  if (!userId || !stripeCustomerId || !stripeSubscriptionId) {
    return; // Missing required metadata — can't process
  }

  // Idempotency: check if subscription already exists for this Stripe subscription
  const existing = await deps.subscriptionRepo.findSubscriptionByStripeSubscriptionId(
    stripeSubscriptionId,
  );
  if (existing) {
    return; // Already processed
  }

  const now = new Date();
  const periodEnd = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const effectivePlan = plan ?? SubscriptionPlan.STANDARD_MONTHLY;

  const createdSub = await deps.subscriptionRepo.createSubscription({
    providerId: userId,
    stripeCustomerId,
    stripeSubscriptionId,
    plan: effectivePlan,
    status: SubscriptionStatus.ACTIVE,
    currentPeriodStart: now,
    currentPeriodEnd: periodEnd,
  } as any);

  // D17-010: Set early bird rate lock if plan is early bird
  if (isEarlyBirdRate(effectivePlan)) {
    const lockedUntil = new Date(now);
    lockedUntil.setMonth(lockedUntil.getMonth() + EARLY_BIRD_RATE_LOCK_MONTHS);

    await deps.subscriptionRepo.updateSubscription(createdSub.subscriptionId, {
      earlyBirdLockedUntil: lockedUntil,
    });

    await deps.auditLogger?.log({
      action: 'EARLY_BIRD_RATE_LOCKED',
      resourceType: 'subscription',
      resourceId: createdSub.subscriptionId,
      actorType: 'system',
      metadata: {
        providerId: userId,
        plan: effectivePlan,
        lockedUntil: lockedUntil.toISOString(),
      },
    });
  }

  eventEmitter?.emit('SUBSCRIPTION_CREATED', {
    userId,
    plan: effectivePlan,
    stripeCustomerId,
    stripeSubscriptionId,
  });
}

// ---------------------------------------------------------------------------
// Handler: invoice.paid
// ---------------------------------------------------------------------------

/**
 * Record payment in payment_history (idempotent: check stripe_invoice_id).
 * Reset failed_payment_count. If status was PAST_DUE: update to ACTIVE.
 * Clear any dunning state. Emit PAYMENT_SUCCEEDED event.
 */
export async function handleInvoicePaid(
  deps: PlatformServiceDeps,
  event: StripeEvent,
  eventEmitter?: PlatformEventEmitter,
): Promise<void> {
  const invoice = event.data.object;
  const stripeInvoiceId = invoice.id as string;
  const stripeSubscriptionId = invoice.subscription as string;

  if (!stripeInvoiceId || !stripeSubscriptionId) {
    return;
  }

  // Idempotency: check if payment already recorded
  const existingPayment = await deps.paymentRepo.findPaymentByStripeInvoiceId(
    stripeInvoiceId,
  );
  if (existingPayment) {
    return; // Already processed
  }

  // Find subscription
  const subscription = await deps.subscriptionRepo.findSubscriptionByStripeSubscriptionId(
    stripeSubscriptionId,
  );
  if (!subscription) {
    return; // No matching subscription
  }

  // Extract amounts from invoice (Stripe amounts are in cents)
  const amountCents = (invoice.amount_paid ?? invoice.total ?? 0) as number;
  const taxCents = (invoice.tax ?? 0) as number;
  const subtotalCents = amountCents - taxCents;

  const amountCad = (subtotalCents / 100).toFixed(2);
  const gstAmount = (taxCents / 100).toFixed(2);
  const totalCad = (amountCents / 100).toFixed(2);

  // Record payment
  await deps.paymentRepo.recordPayment({
    subscriptionId: subscription.subscriptionId,
    stripeInvoiceId,
    amountCad,
    gstAmount,
    totalCad,
    status: PaymentStatus.PAID,
    paidAt: new Date(),
  } as any);

  // Reset failed payment count
  await deps.subscriptionRepo.resetFailedPaymentCount(
    subscription.subscriptionId,
  );

  // If PAST_DUE, transition back to ACTIVE and clear dunning state
  if (subscription.status === SubscriptionStatus.PAST_DUE) {
    await deps.subscriptionRepo.updateSubscriptionStatus(
      subscription.subscriptionId,
      SubscriptionStatus.ACTIVE,
      { suspended_at: null },
    );
  }

  eventEmitter?.emit('PAYMENT_SUCCEEDED', {
    subscriptionId: subscription.subscriptionId,
    stripeInvoiceId,
    amountCad: totalCad,
  });
}

// ---------------------------------------------------------------------------
// Handler: invoice.payment_failed
// ---------------------------------------------------------------------------

/**
 * Increment failed_payment_count. Record failed payment.
 * Emit PAYMENT_FAILED notification event.
 */
export async function handleInvoicePaymentFailed(
  deps: PlatformServiceDeps,
  event: StripeEvent,
  eventEmitter?: PlatformEventEmitter,
): Promise<void> {
  const invoice = event.data.object;
  const stripeInvoiceId = invoice.id as string;
  const stripeSubscriptionId = invoice.subscription as string;

  if (!stripeInvoiceId || !stripeSubscriptionId) {
    return;
  }

  // Find subscription
  const subscription = await deps.subscriptionRepo.findSubscriptionByStripeSubscriptionId(
    stripeSubscriptionId,
  );
  if (!subscription) {
    return;
  }

  // Idempotency: check if this failure was already recorded
  const existingPayment = await deps.paymentRepo.findPaymentByStripeInvoiceId(
    stripeInvoiceId,
  );
  if (existingPayment && existingPayment.status === PaymentStatus.FAILED) {
    return; // Already processed
  }

  // Extract amounts
  const amountCents = (invoice.amount_due ?? invoice.total ?? 0) as number;
  const taxCents = (invoice.tax ?? 0) as number;
  const subtotalCents = amountCents - taxCents;

  // Record failed payment
  await deps.paymentRepo.recordPayment({
    subscriptionId: subscription.subscriptionId,
    stripeInvoiceId,
    amountCad: (subtotalCents / 100).toFixed(2),
    gstAmount: (taxCents / 100).toFixed(2),
    totalCad: (amountCents / 100).toFixed(2),
    status: PaymentStatus.FAILED,
    paidAt: null,
  } as any);

  // Increment failed payment count
  await deps.subscriptionRepo.incrementFailedPaymentCount(
    subscription.subscriptionId,
  );

  // Update status to PAST_DUE if currently ACTIVE
  if (subscription.status === SubscriptionStatus.ACTIVE) {
    await deps.subscriptionRepo.updateSubscriptionStatus(
      subscription.subscriptionId,
      SubscriptionStatus.PAST_DUE,
    );
  }

  eventEmitter?.emit('PAYMENT_FAILED', {
    subscriptionId: subscription.subscriptionId,
    stripeInvoiceId,
    failedPaymentCount: (subscription.failedPaymentCount ?? 0) + 1,
  });
}

// ---------------------------------------------------------------------------
// Handler: invoice.created
// ---------------------------------------------------------------------------

/**
 * Verify GST line item present. If missing, add via Stripe API.
 */
export async function handleInvoiceCreated(
  deps: PlatformServiceDeps,
  event: StripeEvent,
): Promise<void> {
  const invoice = event.data.object;
  const invoiceId = invoice.id as string;

  if (!invoiceId) {
    return;
  }

  // Only process draft invoices that can be modified
  if (invoice.status !== 'draft') {
    return;
  }

  // Check if tax is already present
  const tax = (invoice.tax ?? 0) as number;
  if (tax > 0) {
    return; // GST already applied
  }

  // Calculate subtotal and add GST
  const subtotal = (invoice.subtotal ?? 0) as number;
  if (subtotal <= 0) {
    return;
  }

  const gstAmount = Math.round(subtotal * GST_RATE);

  // Add GST line item via Stripe API
  const createParams: Parameters<typeof deps.stripe.invoiceItems.create>[0] = {
    invoice: invoiceId,
    amount: gstAmount,
    currency: 'cad',
    description: 'GST (5%)',
  };

  if (deps.config.gstTaxRateId) {
    createParams.tax_rates = [deps.config.gstTaxRateId];
  }

  await deps.stripe.invoiceItems.create(createParams);
}

// ---------------------------------------------------------------------------
// Handler: customer.subscription.updated
// ---------------------------------------------------------------------------

/**
 * Sync status, plan, billing period from Stripe. Update local record.
 */
export async function handleSubscriptionUpdated(
  deps: PlatformServiceDeps,
  event: StripeEvent,
): Promise<void> {
  const stripeSubscription = event.data.object;
  const stripeSubscriptionId = stripeSubscription.id as string;

  if (!stripeSubscriptionId) {
    return;
  }

  const subscription = await deps.subscriptionRepo.findSubscriptionByStripeSubscriptionId(
    stripeSubscriptionId,
  );
  if (!subscription) {
    return;
  }

  // Map Stripe status to our status
  const stripeStatus = stripeSubscription.status as string;
  const statusMap: Record<string, string> = {
    active: SubscriptionStatus.ACTIVE,
    past_due: SubscriptionStatus.PAST_DUE,
    canceled: SubscriptionStatus.CANCELLED,
    trialing: SubscriptionStatus.TRIAL,
    unpaid: SubscriptionStatus.SUSPENDED,
  };

  const newStatus = statusMap[stripeStatus];
  if (newStatus && newStatus !== subscription.status) {
    await deps.subscriptionRepo.updateSubscriptionStatus(
      subscription.subscriptionId,
      newStatus,
    );
  }

  // Sync billing period
  const periodStart = stripeSubscription.current_period_start;
  const periodEnd = stripeSubscription.current_period_end;
  if (periodStart && periodEnd) {
    await deps.subscriptionRepo.updateSubscriptionPeriod(
      subscription.subscriptionId,
      new Date(periodStart * 1000),
      new Date(periodEnd * 1000),
    );
  }

  // Sync plan if changed (from price ID to plan mapping)
  const priceId = stripeSubscription.items?.data?.[0]?.price?.id;
  if (priceId) {
    const planMap: Record<string, string> = {
      [deps.config.stripePriceStandardMonthly]: SubscriptionPlan.STANDARD_MONTHLY,
      [deps.config.stripePriceStandardAnnual]: SubscriptionPlan.STANDARD_ANNUAL,
      [deps.config.stripePriceEarlyBirdMonthly]: SubscriptionPlan.EARLY_BIRD_MONTHLY,
      [deps.config.stripePriceEarlyBirdAnnual]: SubscriptionPlan.EARLY_BIRD_ANNUAL,
    };
    const newPlan = planMap[priceId];
    if (newPlan && newPlan !== subscription.plan) {
      await deps.subscriptionRepo.updateSubscriptionPlan(
        subscription.subscriptionId,
        newPlan,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Handler: customer.subscription.deleted
// ---------------------------------------------------------------------------

/**
 * Set status to CANCELLED. Set cancelled_at = now().
 * Set deletion_scheduled_at = now() + 30 days.
 * Emit SUBSCRIPTION_CANCELLED event.
 */
export async function handleSubscriptionDeleted(
  deps: PlatformServiceDeps,
  event: StripeEvent,
  eventEmitter?: PlatformEventEmitter,
): Promise<void> {
  const stripeSubscription = event.data.object;
  const stripeSubscriptionId = stripeSubscription.id as string;

  if (!stripeSubscriptionId) {
    return;
  }

  const subscription = await deps.subscriptionRepo.findSubscriptionByStripeSubscriptionId(
    stripeSubscriptionId,
  );
  if (!subscription) {
    return;
  }

  // Idempotency: skip if already cancelled
  if (subscription.status === SubscriptionStatus.CANCELLED) {
    return;
  }

  const now = new Date();
  const deletionScheduledAt = new Date(
    now.getTime() + DELETION_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
  );

  await deps.subscriptionRepo.updateSubscriptionStatus(
    subscription.subscriptionId,
    SubscriptionStatus.CANCELLED,
    {
      cancelled_at: now,
      deletion_scheduled_at: deletionScheduledAt,
    },
  );

  eventEmitter?.emit('SUBSCRIPTION_CANCELLED', {
    subscriptionId: subscription.subscriptionId,
    providerId: subscription.providerId,
    cancelledAt: now.toISOString(),
    deletionScheduledAt: deletionScheduledAt.toISOString(),
  });

  // IMA-012: Emit EXPORT_WINDOW_STARTED — physician now has 45 days to export data
  eventEmitter?.emit('EXPORT_WINDOW_STARTED', {
    subscriptionId: subscription.subscriptionId,
    providerId: subscription.providerId,
    deletionScheduledAt: deletionScheduledAt.toISOString(),
    exportWindowDays: DELETION_GRACE_PERIOD_DAYS,
  });
}

// ---------------------------------------------------------------------------
// Service: Run Dunning Check (daily scheduled job)
// ---------------------------------------------------------------------------

/**
 * Process the dunning sequence for PAST_DUE subscriptions.
 *
 * For each PAST_DUE subscription with failed_payment_count > 0:
 *   - Day 3: emit PAYMENT_RETRY_FAILED notification
 *   - Day 7: emit PAYMENT_SUSPENSION_WARNING notification
 *   - Day 14: suspend account → status SUSPENDED, set suspended_at,
 *             update user.subscription_status, emit ACCOUNT_SUSPENDED
 *
 * Idempotent: safe to run multiple times per day. Day 14 subscriptions
 * are found via findSubscriptionsDueForSuspension() which filters by
 * updatedAt <= (now - 14 days). Once suspended, they no longer match
 * the PAST_DUE query.
 */
export async function runDunningCheck(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ processed: number; suspended: number }> {
  const DAY_MS = 24 * 60 * 60 * 1000;
  let processed = 0;
  let suspended = 0;

  // --- Day 14: Suspend accounts ---
  const dueSuspension = await deps.subscriptionRepo.findSubscriptionsDueForSuspension();
  for (const sub of dueSuspension) {
    const now = new Date();

    await deps.subscriptionRepo.updateSubscriptionStatus(
      sub.subscriptionId,
      SubscriptionStatus.SUSPENDED,
      { suspended_at: now },
    );

    // Update user.subscription_status to 'suspended'
    await deps.userRepo.updateSubscriptionStatus(
      sub.providerId,
      SubscriptionStatus.SUSPENDED,
    );

    eventEmitter?.emit('ACCOUNT_SUSPENDED', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      suspendedAt: now.toISOString(),
    });

    await deps.auditLogger?.log({
      action: 'DUNNING_SUSPENSION',
      resourceType: 'subscription',
      resourceId: sub.subscriptionId,
      actorType: 'system',
      metadata: {
        providerId: sub.providerId,
        failedPaymentCount: sub.failedPaymentCount,
        step: 'DAY_14_SUSPEND',
      },
    });

    suspended++;
    processed++;
  }

  // --- Day 3 and Day 7 notifications ---
  // These are for PAST_DUE subs that are NOT yet due for suspension
  // (i.e., between 3-13 days past due)
  // We query all PAST_DUE subscriptions and check days since updatedAt
  const allPastDue = await deps.subscriptionRepo.findPastDueSubscriptions();
  const now = Date.now();

  for (const sub of allPastDue) {
    if (sub.failedPaymentCount <= 0) continue;

    const updatedTime = sub.updatedAt instanceof Date
      ? sub.updatedAt.getTime()
      : new Date(sub.updatedAt).getTime();
    const daysSinceUpdate = Math.floor((now - updatedTime) / DAY_MS);

    if (daysSinceUpdate >= 7 && daysSinceUpdate < 14) {
      eventEmitter?.emit('PAYMENT_SUSPENSION_WARNING', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        daysUntilSuspension: 14 - daysSinceUpdate,
      });

      await deps.auditLogger?.log({
        action: 'DUNNING_WARNING',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: { step: 'DAY_7_WARNING', daysSinceUpdate },
      });

      processed++;
    } else if (daysSinceUpdate >= 3 && daysSinceUpdate < 7) {
      eventEmitter?.emit('PAYMENT_RETRY_FAILED', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        failedPaymentCount: sub.failedPaymentCount,
      });

      await deps.auditLogger?.log({
        action: 'DUNNING_RETRY_NOTIFICATION',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: { step: 'DAY_3_RETRY_FAILED', daysSinceUpdate },
      });

      processed++;
    }
  }

  return { processed, suspended };
}

// ---------------------------------------------------------------------------
// Service: Run Cancellation Check (daily scheduled job)
// ---------------------------------------------------------------------------

/**
 * Cancel subscriptions that have been SUSPENDED for 16 days
 * (30 total days from first payment failure).
 *
 * 1. Find SUSPENDED subs where suspended_at + 16 days <= now().
 * 2. Cancel Stripe subscription via API.
 * 3. Update status to CANCELLED, set cancelled_at, deletion_scheduled_at.
 * 4. Emit SUBSCRIPTION_CANCELLED notification.
 *
 * Idempotent: once status becomes CANCELLED, the subscription no longer
 * matches the SUSPENDED query.
 */
export async function runCancellationCheck(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ cancelled: number }> {
  const dueCancellation = await deps.subscriptionRepo.findSubscriptionsDueForCancellation();
  let cancelled = 0;

  for (const sub of dueCancellation) {
    // Cancel the Stripe subscription
    await deps.stripe.subscriptions.cancel(sub.stripeSubscriptionId);

    const now = new Date();
    const deletionScheduledAt = new Date(
      now.getTime() + DELETION_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
    );

    await deps.subscriptionRepo.updateSubscriptionStatus(
      sub.subscriptionId,
      SubscriptionStatus.CANCELLED,
      {
        cancelled_at: now,
        deletion_scheduled_at: deletionScheduledAt,
      },
    );

    // Update user.subscription_status
    await deps.userRepo.updateSubscriptionStatus(
      sub.providerId,
      SubscriptionStatus.CANCELLED,
    );

    eventEmitter?.emit('SUBSCRIPTION_CANCELLED', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      cancelledAt: now.toISOString(),
      deletionScheduledAt: deletionScheduledAt.toISOString(),
    });

    // IMA-012: Emit EXPORT_WINDOW_STARTED — physician now has 45 days to export data
    eventEmitter?.emit('EXPORT_WINDOW_STARTED', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      deletionScheduledAt: deletionScheduledAt.toISOString(),
      exportWindowDays: DELETION_GRACE_PERIOD_DAYS,
    });

    await deps.auditLogger?.log({
      action: 'DUNNING_CANCELLATION',
      resourceType: 'subscription',
      resourceId: sub.subscriptionId,
      actorType: 'system',
      metadata: {
        providerId: sub.providerId,
        stripeSubscriptionId: sub.stripeSubscriptionId,
        deletionScheduledAt: deletionScheduledAt.toISOString(),
      },
    });

    cancelled++;
  }

  return { cancelled };
}

// ---------------------------------------------------------------------------
// Service: Run Deletion Check (daily scheduled job)
// ---------------------------------------------------------------------------

/**
 * Delete PHI data for CANCELLED subscriptions whose deletion_scheduled_at
 * has passed (30 days after cancellation).
 *
 * Deletion checklist (per FRD):
 *   - Claims, patients, provider profile: deleted
 *   - Audit logs: retained 10 years, PII stripped (provider_id hashed, PHN removed)
 *   - IMA records: retained 10 years (contractual evidence)
 *   - AI learning data: anonymised, retained for cohort aggregates
 *   - Stripe references: deleted (customer, payment methods, metadata)
 *
 * Idempotent: if dataDeletionRepo returns 0 rows for a subscription
 * that was already cleaned, no harm done. User account is deactivated
 * only once (deactivateUser is idempotent).
 */
export async function runDeletionCheck(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ deleted: number }> {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const dueDeletion = await deps.subscriptionRepo.findSubscriptionsDueForDeletion();
  let deleted = 0;

  for (const sub of dueDeletion) {
    const deletionRepo = deps.dataDeletionRepo;
    if (!deletionRepo) {
      continue; // Cannot process deletions without the deletion repository
    }

    // IMA-012: Emit EXPORT_WINDOW_CLOSED before triggering deletion
    eventEmitter?.emit('EXPORT_WINDOW_CLOSED', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      deletionScheduledAt: sub.deletionScheduledAt?.toISOString() ?? new Date().toISOString(),
    });

    // IMA-060: Look up user email BEFORE deactivation so we can store it
    const user = await deps.userRepo.findUserById(sub.providerId);
    const lastKnownEmail = user?.email ?? null;

    // 1. Delete PHI: claims, patients, reports
    await deletionRepo.deleteClaimsByProviderId(sub.providerId);
    await deletionRepo.deletePatientsByProviderId(sub.providerId);
    await deletionRepo.deleteReportsByProviderId(sub.providerId);

    // 2. Strip PII from audit logs (retain logs for 10 years per HIA)
    await deletionRepo.stripPiiFromAuditLogs(sub.providerId);

    // 3. Anonymise AI learning data (retain for cohort aggregates)
    await deletionRepo.anonymiseAiLearningData(sub.providerId);

    // 4. Delete Stripe customer data (payment methods, metadata)
    await deps.stripe.customers.del(sub.stripeCustomerId);

    // 5. Deactivate user account
    await deletionRepo.deactivateUser(sub.providerId);

    const now = new Date();

    // IMA-060: Create destruction tracking record (DB deletion complete)
    if (deps.destructionTrackingRepo) {
      const backupPurgeDeadline = new Date(
        now.getTime() + BACKUP_PURGE_DEADLINE_DAYS * DAY_MS,
      );

      await deps.destructionTrackingRepo.createTrackingRecord({
        providerId: sub.providerId,
        lastKnownEmail: lastKnownEmail,
        activeDeletedAt: now,
        backupPurgeDeadline,
      });

      await deps.auditLogger?.log({
        action: PlatformAuditAction.DESTRUCTION_ACTIVE_DELETED,
        resourceType: 'destruction_tracking',
        resourceId: sub.providerId,
        actorType: 'system',
        metadata: { subscriptionId: sub.subscriptionId },
      });
    }

    // IMA-060: Delete DO Spaces files scoped to this provider
    if (deps.spacesFileClient) {
      await deps.spacesFileClient.deleteProviderFiles(sub.providerId);

      if (deps.destructionTrackingRepo) {
        await deps.destructionTrackingRepo.updateFilesDeletedAt(
          sub.providerId,
          new Date(),
        );
      }

      await deps.auditLogger?.log({
        action: PlatformAuditAction.DESTRUCTION_FILES_DELETED,
        resourceType: 'destruction_tracking',
        resourceId: sub.providerId,
        actorType: 'system',
        metadata: { subscriptionId: sub.subscriptionId },
      });
    }

    eventEmitter?.emit('ACCOUNT_DATA_DELETED', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      deletedAt: now.toISOString(),
    });

    await deps.auditLogger?.log({
      action: 'ACCOUNT_DATA_DELETED',
      resourceType: 'subscription',
      resourceId: sub.subscriptionId,
      actorType: 'system',
      metadata: {
        providerId: sub.providerId,
        stripeCustomerId: sub.stripeCustomerId,
      },
    });

    deleted++;
  }

  return { deleted };
}

// ---------------------------------------------------------------------------
// Service: Run Export Window Reminders (daily scheduled job) — IMA-012
// ---------------------------------------------------------------------------

/**
 * Check CANCELLED subscriptions approaching data deletion and emit reminder
 * notifications at specific intervals:
 *   - 15 days remaining: EXPORT_WINDOW_REMINDER (HIGH priority)
 *   - 7 days remaining: EXPORT_WINDOW_CLOSING (URGENT priority)
 *   - 1 day remaining: EXPORT_WINDOW_CLOSING (URGENT priority, final warning)
 *
 * The export window is 45 days (DELETION_GRACE_PERIOD_DAYS).
 * Idempotent: safe to run multiple times per day. Notifications are emitted
 * based on the exact day remaining, so running twice on the same day will
 * produce duplicate events (the notification service should deduplicate).
 */
export async function runExportWindowReminders(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ reminded: number }> {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const cancelledSubs = await deps.subscriptionRepo.findCancelledSubscriptionsInExportWindow();
  let reminded = 0;
  const now = Date.now();

  for (const sub of cancelledSubs) {
    if (!sub.deletionScheduledAt) continue;

    const deletionTime = sub.deletionScheduledAt instanceof Date
      ? sub.deletionScheduledAt.getTime()
      : new Date(sub.deletionScheduledAt).getTime();

    const daysRemaining = Math.ceil((deletionTime - now) / DAY_MS);

    if (daysRemaining === 15) {
      eventEmitter?.emit('EXPORT_WINDOW_REMINDER', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        daysRemaining: 15,
        deletionScheduledAt: sub.deletionScheduledAt instanceof Date
          ? sub.deletionScheduledAt.toISOString()
          : new Date(sub.deletionScheduledAt).toISOString(),
      });

      await deps.auditLogger?.log({
        action: 'EXPORT_WINDOW_REMINDER',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: { providerId: sub.providerId, daysRemaining: 15 },
      });

      reminded++;
    } else if (daysRemaining === 7) {
      eventEmitter?.emit('EXPORT_WINDOW_CLOSING', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        daysRemaining: 7,
        deletionScheduledAt: sub.deletionScheduledAt instanceof Date
          ? sub.deletionScheduledAt.toISOString()
          : new Date(sub.deletionScheduledAt).toISOString(),
      });

      await deps.auditLogger?.log({
        action: 'EXPORT_WINDOW_CLOSING',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: { providerId: sub.providerId, daysRemaining: 7 },
      });

      reminded++;
    } else if (daysRemaining === 1) {
      eventEmitter?.emit('EXPORT_WINDOW_CLOSING', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        daysRemaining: 1,
        deletionScheduledAt: sub.deletionScheduledAt instanceof Date
          ? sub.deletionScheduledAt.toISOString()
          : new Date(sub.deletionScheduledAt).toISOString(),
      });

      await deps.auditLogger?.log({
        action: 'EXPORT_WINDOW_CLOSING_FINAL',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: { providerId: sub.providerId, daysRemaining: 1 },
      });

      reminded++;
    }
  }

  return { reminded };
}

// ---------------------------------------------------------------------------
// Service: Get Subscription Status (for middleware use)
// ---------------------------------------------------------------------------

export interface SubscriptionStatusResult {
  status: string;
  plan: string | null;
  features: readonly Feature[];
  subscription: {
    subscriptionId: string;
    currentPeriodEnd: Date;
    suspendedAt: Date | null;
    cancelledAt: Date | null;
    deletionScheduledAt: Date | null;
  } | null;
}

/**
 * Return the current subscription status and access level for a user.
 * Used by middleware to determine which features are available.
 */
export async function getSubscriptionStatus(
  deps: PlatformServiceDeps,
  userId: string,
): Promise<SubscriptionStatusResult> {
  const subscription = await deps.subscriptionRepo.findSubscriptionByProviderId(userId);

  if (!subscription) {
    return {
      status: SubscriptionStatus.CANCELLED,
      plan: null,
      features: FeatureAccessMatrix[SubscriptionStatus.CANCELLED] ?? [],
      subscription: null,
    };
  }

  const features = FeatureAccessMatrix[subscription.status] ?? [];

  return {
    status: subscription.status,
    plan: subscription.plan,
    features,
    subscription: {
      subscriptionId: subscription.subscriptionId,
      currentPeriodEnd: subscription.currentPeriodEnd,
      suspendedAt: subscription.suspendedAt ?? null,
      cancelledAt: subscription.cancelledAt ?? null,
      deletionScheduledAt: subscription.deletionScheduledAt ?? null,
    },
  };
}

// ---------------------------------------------------------------------------
// Service: Get Status Page (public — no auth required)
// ---------------------------------------------------------------------------

export interface StatusPageResult {
  components: Array<{
    componentId: string;
    name: string;
    displayName: string;
    status: string;
    description: string | null;
  }>;
  activeIncidents: Array<{
    incidentId: string;
    title: string;
    status: string;
    severity: string;
    affectedComponents: string[];
    createdAt: Date;
    updatedAt: Date;
    updates: Array<{
      updateId: string;
      status: string;
      message: string;
      createdAt: Date;
    }>;
  }>;
}

/**
 * Return all monitored components with their current status
 * and all active (non-resolved) incidents with their latest updates.
 * No authentication required — this is the public status page.
 */
export async function getStatusPage(
  deps: PlatformServiceDeps,
): Promise<StatusPageResult> {
  const [components, activeIncidents] = await Promise.all([
    deps.statusComponentRepo.listComponents(),
    deps.incidentRepo.listActiveIncidents(),
  ]);

  return {
    components: components.map((c) => ({
      componentId: c.componentId,
      name: c.name,
      displayName: c.displayName,
      status: c.status,
      description: c.description,
    })),
    activeIncidents: activeIncidents.map((i) => ({
      incidentId: i.incidentId,
      title: i.title,
      status: i.status,
      severity: i.severity,
      affectedComponents: i.affectedComponents as string[],
      createdAt: i.createdAt,
      updatedAt: i.updatedAt,
      updates: i.updates.map((u) => ({
        updateId: u.updateId,
        status: u.status,
        message: u.message,
        createdAt: u.createdAt,
      })),
    })),
  };
}

// ---------------------------------------------------------------------------
// Service: Get Incident History (public — no auth required)
// ---------------------------------------------------------------------------

export interface IncidentHistoryResult {
  data: StatusPageResult['activeIncidents'];
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
  };
}

/**
 * Return paginated incident history including resolved incidents.
 * No authentication required — this is the public status page.
 */
export async function getIncidentHistory(
  deps: PlatformServiceDeps,
  page: number,
  pageSize: number,
): Promise<IncidentHistoryResult> {
  const result = await deps.incidentRepo.listIncidentHistory({ page, pageSize });

  return {
    data: result.data.map((i) => ({
      incidentId: i.incidentId,
      title: i.title,
      status: i.status,
      severity: i.severity,
      affectedComponents: i.affectedComponents as string[],
      createdAt: i.createdAt,
      updatedAt: i.updatedAt,
      updates: i.updates.map((u) => ({
        updateId: u.updateId,
        status: u.status,
        message: u.message,
        createdAt: u.createdAt,
      })),
    })),
    pagination: {
      total: result.total,
      page,
      pageSize,
      hasMore: page * pageSize < result.total,
    },
  };
}

// ---------------------------------------------------------------------------
// Service: Create Incident (admin only)
// ---------------------------------------------------------------------------

export interface CreateIncidentInput {
  title: string;
  severity: string;
  affected_components: string[];
  message: string;
}

/**
 * Create a new incident, update affected component statuses,
 * and emit a MAINTENANCE_SCHEDULED notification.
 * Audit log: incident.created.
 */
export async function createIncident(
  deps: PlatformServiceDeps,
  adminUserId: string,
  data: CreateIncidentInput,
  eventEmitter?: PlatformEventEmitter,
): Promise<StatusPageResult['activeIncidents'][number]> {
  // Create the incident with initial update
  const incident = await deps.incidentRepo.createIncident({
    title: data.title,
    severity: data.severity,
    affectedComponents: data.affected_components,
    initialMessage: data.message,
  });

  // Update affected component statuses based on severity
  const componentStatus = data.severity === 'critical'
    ? ComponentHealth.MAJOR_OUTAGE
    : data.severity === 'major'
      ? ComponentHealth.PARTIAL_OUTAGE
      : ComponentHealth.DEGRADED;

  for (const componentId of data.affected_components) {
    await deps.statusComponentRepo.updateComponentStatus(componentId, componentStatus);
  }

  // Emit notification event
  eventEmitter?.emit('MAINTENANCE_SCHEDULED', {
    incidentId: incident.incidentId,
    title: data.title,
    severity: data.severity,
    affectedComponents: data.affected_components,
    message: data.message,
  });

  // Audit log
  await deps.auditLogger?.log({
    action: 'incident.created',
    resourceType: 'incident',
    resourceId: incident.incidentId,
    actorType: 'admin',
    metadata: {
      adminUserId,
      title: data.title,
      severity: data.severity,
      affectedComponents: data.affected_components,
    },
  });

  return {
    incidentId: incident.incidentId,
    title: incident.title,
    status: incident.status,
    severity: incident.severity,
    affectedComponents: incident.affectedComponents as string[],
    createdAt: incident.createdAt,
    updatedAt: incident.updatedAt,
    updates: incident.updates.map((u) => ({
      updateId: u.updateId,
      status: u.status,
      message: u.message,
      createdAt: u.createdAt,
    })),
  };
}

// ---------------------------------------------------------------------------
// Service: Update Incident (admin only)
// ---------------------------------------------------------------------------

/**
 * Post an update to an existing incident.
 * If resolving: set resolved_at, restore component statuses to operational.
 * Emit incident update notification.
 * Audit log: incident.updated.
 */
export async function updateIncident(
  deps: PlatformServiceDeps,
  adminUserId: string,
  incidentId: string,
  status: string,
  message: string,
  eventEmitter?: PlatformEventEmitter,
): Promise<StatusPageResult['activeIncidents'][number]> {
  const updated = await deps.incidentRepo.updateIncident(incidentId, status, message);

  if (!updated) {
    throw new NotFoundError('Incident');
  }

  // If resolving, restore affected components to operational
  if (status === IncidentStatus.RESOLVED) {
    const affectedComponents = updated.affectedComponents as string[];
    for (const componentId of affectedComponents) {
      await deps.statusComponentRepo.updateComponentStatus(
        componentId,
        ComponentHealth.OPERATIONAL,
      );
    }
  }

  // Emit notification event
  eventEmitter?.emit('INCIDENT_UPDATED', {
    incidentId,
    status,
    message,
    resolvedAt: updated.resolvedAt?.toISOString() ?? null,
  });

  // Audit log
  await deps.auditLogger?.log({
    action: 'incident.updated',
    resourceType: 'incident',
    resourceId: incidentId,
    actorType: 'admin',
    metadata: {
      adminUserId,
      newStatus: status,
      message,
    },
  });

  return {
    incidentId: updated.incidentId,
    title: updated.title,
    status: updated.status,
    severity: updated.severity,
    affectedComponents: updated.affectedComponents as string[],
    createdAt: updated.createdAt,
    updatedAt: updated.updatedAt,
    updates: updated.updates.map((u) => ({
      updateId: u.updateId,
      status: u.status,
      message: u.message,
      createdAt: u.createdAt,
    })),
  };
}

// ---------------------------------------------------------------------------
// Service: Update Component Status (admin only)
// ---------------------------------------------------------------------------

/**
 * Manual component status override.
 * Audit log: component.status_updated.
 */
export async function updateComponentStatus(
  deps: PlatformServiceDeps,
  adminUserId: string,
  componentId: string,
  status: string,
): Promise<{ componentId: string; name: string; displayName: string; status: string }> {
  const updated = await deps.statusComponentRepo.updateComponentStatus(componentId, status);

  if (!updated) {
    throw new NotFoundError('Component');
  }

  // Audit log
  await deps.auditLogger?.log({
    action: 'component.status_updated',
    resourceType: 'component',
    resourceId: componentId,
    actorType: 'admin',
    metadata: {
      adminUserId,
      newStatus: status,
    },
  });

  return {
    componentId: updated.componentId,
    name: updated.name,
    displayName: updated.displayName,
    status: updated.status,
  };
}

// ---------------------------------------------------------------------------
// Service: Check Early Bird Expiry (daily scheduled job) — D17-012, D17-014
// ---------------------------------------------------------------------------

/**
 * Scheduled job: check for early bird subscriptions approaching or past expiry.
 * Runs daily via cron.
 *
 * Two phases:
 * 1. Warning phase: early_bird_locked_until <= now() + 30 days AND early_bird_expiry_notified = false
 * 2. Transition phase: early_bird_locked_until <= now()
 *
 * Spec reference: B2-2 — Early Bird Rate Lock
 */
export async function checkEarlyBirdExpiry(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ warned: number; transitioned: number }> {
  let warned = 0;
  let transitioned = 0;

  // --- Phase 1: 30-day warning notifications ---
  const expiringSubs = await deps.subscriptionRepo.findExpiringEarlyBirdSubscriptions(
    EARLY_BIRD_EXPIRY_WARNING_DAYS,
  );

  for (const sub of expiringSubs) {
    // Emit warning to the physician
    eventEmitter?.emit('EARLY_BIRD_EXPIRING', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      earlyBirdLockedUntil: sub.earlyBirdLockedUntil?.toISOString(),
    });

    // Set notified flag
    await deps.subscriptionRepo.updateSubscription(sub.subscriptionId, {
      earlyBirdExpiryNotified: true,
    });

    // D17-014: Proactive practice admin notification
    const practiceMembership = await deps.subscriptionRepo.getActivePracticeMembership(
      sub.providerId,
    );
    if (practiceMembership) {
      const earlyBirdMembers = await deps.subscriptionRepo.getEarlyBirdMembersInPractice(
        practiceMembership.practiceId,
      );

      // Check if any OTHER member has already been notified about expiry
      const anyPreviouslyNotified = earlyBirdMembers.some(
        (m) =>
          m.physicianUserId !== sub.providerId &&
          m.earlyBirdExpiryNotified === true,
      );

      if (!anyPreviouslyNotified) {
        // This is the FIRST physician approaching expiry in this practice
        eventEmitter?.emit('PRACTICE_EARLY_BIRD_TRANSITION_STARTING', {
          practiceId: practiceMembership.practiceId,
          message:
            'A physician in your practice has an early bird rate expiring soon. Their billing will automatically transition to practice consolidated billing.',
        });
      }
    }

    warned++;
  }

  // --- Phase 2: Expiry transitions ---
  const expiredSubs = await deps.subscriptionRepo.findExpiredEarlyBirdSubscriptions();

  for (const sub of expiredSubs) {
    const membership = await deps.subscriptionRepo.getActivePracticeMembership(
      sub.providerId,
    );

    if (membership) {
      // PATH A: Physician is in a practice
      // 1. Cancel the individual early bird Stripe subscription
      await deps.stripe.subscriptions.cancel(sub.stripeSubscriptionId);

      // 2. Update subscription status to CANCELLED
      await deps.subscriptionRepo.updateSubscriptionStatus(
        sub.subscriptionId,
        SubscriptionStatus.CANCELLED,
        { cancelled_at: new Date() },
      );

      // 3. Transition practice membership billing_mode
      await deps.subscriptionRepo.updatePracticeMembershipBillingMode(
        membership.membershipId,
        'PRACTICE_CONSOLIDATED',
      );

      // 4. Emit notifications
      eventEmitter?.emit('EARLY_BIRD_EXPIRED', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        path: 'A',
        transitionedTo: 'PRACTICE_CONSOLIDATED',
      });

      eventEmitter?.emit('PRACTICE_MEMBER_TRANSITIONED', {
        practiceId: membership.practiceId,
        providerId: sub.providerId,
      });

      // 5. Audit log
      await deps.auditLogger?.log({
        action: 'EARLY_BIRD_EXPIRED_PATH_A',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: {
          providerId: sub.providerId,
          practiceId: membership.practiceId,
          membershipId: membership.membershipId,
          transitionedTo: 'PRACTICE_CONSOLIDATED',
        },
      });

      // D17-014: Check if all members are now post-early-bird
      const remainingEarlyBird = await deps.subscriptionRepo.getEarlyBirdMembersInPractice(
        membership.practiceId,
      );
      if (remainingEarlyBird.length === 0) {
        eventEmitter?.emit('PRACTICE_ALL_MEMBERS_POST_EARLY_BIRD', {
          practiceId: membership.practiceId,
          message:
            'All physicians in your practice have transitioned from early bird rates. Your practice is now fully on clinic tier consolidated billing.',
        });
      }
    } else {
      // PATH B: Physician is NOT in a practice
      // 1. Determine new plan
      const newPlan =
        sub.plan === SubscriptionPlan.EARLY_BIRD_MONTHLY
          ? SubscriptionPlan.STANDARD_MONTHLY
          : SubscriptionPlan.STANDARD_ANNUAL;

      // 2. Update Stripe subscription to new price
      const newPriceId = getPriceId(newPlan, deps.config);
      await deps.stripe.subscriptions.update(sub.stripeSubscriptionId, {
        items: [{ price: newPriceId }],
      });

      // 3. Update subscription record
      await deps.subscriptionRepo.updateSubscription(sub.subscriptionId, {
        plan: newPlan,
        earlyBirdLockedUntil: null,
      });

      // 4. Emit notification
      eventEmitter?.emit('EARLY_BIRD_EXPIRED', {
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        path: 'B',
        transitionedTo: newPlan,
      });

      // 5. Audit log
      await deps.auditLogger?.log({
        action: 'EARLY_BIRD_EXPIRED_PATH_B',
        resourceType: 'subscription',
        resourceId: sub.subscriptionId,
        actorType: 'system',
        metadata: {
          providerId: sub.providerId,
          previousPlan: sub.plan,
          newPlan,
        },
      });
    }

    transitioned++;
  }

  return { warned, transitioned };
}

// ---------------------------------------------------------------------------
// Service: Seed Status Components (idempotent)
// ---------------------------------------------------------------------------

const STATUS_COMPONENT_SEED = [
  { name: StatusComponent.WEB_APP, displayName: 'Web Application', sortOrder: 1 },
  { name: StatusComponent.API, displayName: 'API', sortOrder: 2 },
  { name: StatusComponent.HLINK_SUBMISSION, displayName: 'H-Link Submission', sortOrder: 3 },
  { name: StatusComponent.WCB_SUBMISSION, displayName: 'WCB Submission', sortOrder: 4 },
  { name: StatusComponent.AI_COACH, displayName: 'AI Coach', sortOrder: 5 },
  { name: StatusComponent.EMAIL_DELIVERY, displayName: 'Email Delivery', sortOrder: 6 },
  { name: StatusComponent.DATABASE, displayName: 'Database', sortOrder: 7 },
  { name: StatusComponent.PAYMENT_PROCESSING, displayName: 'Payment Processing', sortOrder: 8 },
];

/**
 * Idempotent seed of the 8 monitored status page components.
 * Safe to run multiple times — existing components will not be duplicated.
 */
export async function seedStatusComponents(
  deps: PlatformServiceDeps,
): Promise<void> {
  await deps.statusComponentRepo.seedComponents(STATUS_COMPONENT_SEED);
}

// ---------------------------------------------------------------------------
// Service: IMA Amendment — Create (admin only)
// ---------------------------------------------------------------------------

export interface CreateAmendmentInput {
  amendmentType: string;
  title: string;
  description: string;
  documentText: string;
  effectiveDate: Date;
}

export interface AmendmentAdminContext {
  userId: string;
  role: string;
}

/**
 * Create a new IMA amendment. Admin-only — enforced at service layer as
 * defense-in-depth (do not rely solely on route-level guards).
 *
 * 1. Verify caller has ADMIN role.
 * 2. Create amendment via repository.
 * 3. Emit IMA_AMENDMENT_NOTICE notification to all active physicians (fire-and-forget).
 * 4. Emit audit event amendment.created.
 */
export async function createAmendment(
  deps: PlatformServiceDeps,
  adminCtx: AmendmentAdminContext,
  data: CreateAmendmentInput,
  eventEmitter?: PlatformEventEmitter,
): Promise<ReturnType<NonNullable<PlatformServiceDeps['amendmentRepo']>['createAmendment']> extends Promise<infer T> ? T : never> {
  // 1. Admin-only check (defense-in-depth)
  if (adminCtx.role.toUpperCase() !== 'ADMIN') {
    throw new ForbiddenError('Only administrators can create amendments');
  }

  if (!deps.amendmentRepo) {
    throw new Error('Amendment repository not configured');
  }

  // 2. Create amendment record
  const amendment = await deps.amendmentRepo.createAmendment({
    amendmentType: data.amendmentType,
    title: data.title,
    description: data.description,
    documentText: data.documentText,
    effectiveDate: data.effectiveDate,
    createdBy: adminCtx.userId,
  });

  // 3. Fire-and-forget notification to all active physicians
  if (eventEmitter && deps.activeProviderRepo) {
    try {
      const providerIds = await deps.activeProviderRepo.findActiveProviderIds();
      eventEmitter.emit('IMA_AMENDMENT_NOTICE', {
        amendmentId: amendment.amendmentId,
        amendmentType: data.amendmentType,
        title: data.title,
        effectiveDate: data.effectiveDate.toISOString(),
        recipientProviderIds: providerIds,
      });
    } catch {
      // Notification delivery failures must not fail the transaction
    }
  }

  // 4. Audit event
  await deps.auditLogger?.log({
    action: 'amendment.created',
    resourceType: 'ima_amendment',
    resourceId: amendment.amendmentId,
    actorType: 'admin',
    metadata: {
      adminUserId: adminCtx.userId,
      amendmentType: data.amendmentType,
      title: data.title,
    },
  });

  return amendment;
}

// ---------------------------------------------------------------------------
// Service: IMA Amendment — Acknowledge (NON_MATERIAL)
// ---------------------------------------------------------------------------

export interface AmendmentPhysicianContext {
  userId: string;
  providerId: string;
  ipAddress: string;
  userAgent: string;
}

/**
 * Acknowledge a NON_MATERIAL amendment.
 * Creates a response record with type ACKNOWLEDGED.
 * Emits audit event amendment.acknowledged.
 */
export async function acknowledgeAmendment(
  deps: PlatformServiceDeps,
  ctx: AmendmentPhysicianContext,
  amendmentId: string,
  eventEmitter?: PlatformEventEmitter,
): Promise<void> {
  if (!deps.amendmentRepo) {
    throw new Error('Amendment repository not configured');
  }

  // Verify amendment exists
  const amendment = await deps.amendmentRepo.findAmendmentById(amendmentId);
  if (!amendment) {
    throw new NotFoundError('Amendment');
  }

  // Create ACKNOWLEDGED response
  await deps.amendmentRepo.createAmendmentResponse({
    amendmentId,
    providerId: ctx.providerId,
    responseType: 'ACKNOWLEDGED',
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  // Audit event
  await deps.auditLogger?.log({
    action: 'amendment.acknowledged',
    resourceType: 'ima_amendment',
    resourceId: amendmentId,
    actorType: 'physician',
    metadata: {
      userId: ctx.userId,
      providerId: ctx.providerId,
    },
  });
}

// ---------------------------------------------------------------------------
// Service: IMA Amendment — Respond (MATERIAL: ACCEPTED or REJECTED)
// ---------------------------------------------------------------------------

/**
 * Respond to a MATERIAL amendment with ACCEPTED or REJECTED.
 * Emits audit event amendment.accepted or amendment.rejected.
 */
export async function respondToAmendment(
  deps: PlatformServiceDeps,
  ctx: AmendmentPhysicianContext,
  amendmentId: string,
  responseType: 'ACCEPTED' | 'REJECTED',
  eventEmitter?: PlatformEventEmitter,
): Promise<void> {
  if (!deps.amendmentRepo) {
    throw new Error('Amendment repository not configured');
  }

  // Verify amendment exists
  const amendment = await deps.amendmentRepo.findAmendmentById(amendmentId);
  if (!amendment) {
    throw new NotFoundError('Amendment');
  }

  // Create response
  await deps.amendmentRepo.createAmendmentResponse({
    amendmentId,
    providerId: ctx.providerId,
    responseType,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  // Audit event
  const auditAction = responseType === 'ACCEPTED'
    ? 'amendment.accepted'
    : 'amendment.rejected';

  await deps.auditLogger?.log({
    action: auditAction,
    resourceType: 'ima_amendment',
    resourceId: amendmentId,
    actorType: 'physician',
    metadata: {
      userId: ctx.userId,
      providerId: ctx.providerId,
      responseType,
    },
  });
}

// ---------------------------------------------------------------------------
// Service: IMA Amendment — Get Blocking Amendments (gate middleware)
// ---------------------------------------------------------------------------

/**
 * Return NON_MATERIAL amendments past their effective_date that the provider
 * hasn't acknowledged. Used by gate middleware to block PHI access.
 *
 * MATERIAL amendments do NOT block — silence = existing terms continue
 * per IMA section 11.3.
 */
export async function getBlockingAmendments(
  deps: PlatformServiceDeps,
  providerId: string,
): Promise<Array<{ amendmentId: string; title: string; effectiveDate: Date }>> {
  if (!deps.amendmentRepo) {
    return [];
  }

  // Get all pending (unresponded, past effective date) amendments for this provider
  const pending = await deps.amendmentRepo.findPendingAmendmentsForProvider(providerId);

  // Filter to NON_MATERIAL only — MATERIAL amendments do not block
  return pending
    .filter((a) => a.amendmentType === 'NON_MATERIAL')
    .map((a) => ({
      amendmentId: a.amendmentId,
      title: a.title,
      effectiveDate: a.effectiveDate,
    }));
}

// ---------------------------------------------------------------------------
// Service: IMA Amendment — Run Reminders (scheduled job)
// ---------------------------------------------------------------------------

/**
 * Scheduled job: find MATERIAL amendments where the deadline is 30 days or
 * 7 days away, emit IMA_AMENDMENT_REMINDER to providers who haven't
 * responded yet.
 *
 * Idempotent: safe to run multiple times per day.
 */
export async function runAmendmentReminders(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ reminded: number }> {
  if (!deps.amendmentRepo || !deps.activeProviderRepo) {
    return { reminded: 0 };
  }

  const DAY_MS = 24 * 60 * 60 * 1000;
  const now = Date.now();
  let reminded = 0;

  // Get all amendments (we need to filter for MATERIAL type with upcoming effective_date)
  const allAmendments = await deps.amendmentRepo.listAmendments({
    page: 1,
    pageSize: 1000,
  });

  const activeProviderIds = await deps.activeProviderRepo.findActiveProviderIds();

  for (const amendment of allAmendments.data) {
    // Only MATERIAL amendments get reminders
    if (amendment.amendmentType !== 'MATERIAL') {
      continue;
    }

    const effectiveTime = amendment.effectiveDate instanceof Date
      ? amendment.effectiveDate.getTime()
      : new Date(amendment.effectiveDate).getTime();

    const daysUntilEffective = Math.ceil((effectiveTime - now) / DAY_MS);

    // Only send reminders at 30 days and 7 days
    if (daysUntilEffective !== 30 && daysUntilEffective !== 7) {
      continue;
    }

    // For each active provider, check if they've already responded
    for (const providerId of activeProviderIds) {
      const existingResponse = await deps.amendmentRepo.getAmendmentResponse(
        amendment.amendmentId,
        providerId,
      );

      if (!existingResponse) {
        eventEmitter?.emit('IMA_AMENDMENT_REMINDER', {
          amendmentId: amendment.amendmentId,
          providerId,
          title: amendment.title,
          daysUntilEffective,
          effectiveDate: amendment.effectiveDate instanceof Date
            ? amendment.effectiveDate.toISOString()
            : new Date(amendment.effectiveDate).toISOString(),
        });
        reminded++;
      }
    }
  }

  return { reminded };
}

// ---------------------------------------------------------------------------
// Service: Breach Notification — Create Breach (admin only)
// ---------------------------------------------------------------------------

export interface BreachAdminContext {
  userId: string;
  role: string;
}

export interface CreateBreachInput {
  breachDescription: string;
  breachDate: Date;
  awarenessDate: Date;
  hiDescription: string;
  includesIihi: boolean;
  affectedCount?: number;
  riskAssessment?: string;
  mitigationSteps?: string;
  contactName: string;
  contactEmail: string;
  affectedProviderIds: string[];
}

/**
 * Create a breach record and link all affected custodians.
 * Admin-only — enforced at service layer (defense-in-depth).
 */
export async function createBreach(
  deps: PlatformServiceDeps,
  adminCtx: BreachAdminContext,
  data: CreateBreachInput,
  eventEmitter?: PlatformEventEmitter,
) {
  if (adminCtx.role.toUpperCase() !== 'ADMIN') {
    throw new ForbiddenError('Only administrators can create breach records');
  }

  if (!deps.breachRepo) {
    throw new Error('Breach repository not configured');
  }

  const breach = await deps.breachRepo.createBreachRecord({
    breachDescription: data.breachDescription,
    breachDate: data.breachDate,
    awarenessDate: data.awarenessDate,
    hiDescription: data.hiDescription,
    includesIihi: data.includesIihi,
    affectedCount: data.affectedCount,
    riskAssessment: data.riskAssessment,
    mitigationSteps: data.mitigationSteps,
    contactName: data.contactName,
    contactEmail: data.contactEmail,
    createdBy: adminCtx.userId,
  });

  // Add all affected custodians
  for (const providerId of data.affectedProviderIds) {
    await deps.breachRepo.addAffectedCustodian(breach.breachId, providerId);
  }

  // Audit event
  await deps.auditLogger?.log({
    action: 'breach.created',
    resourceType: 'breach_record',
    resourceId: breach.breachId,
    actorType: 'admin',
    metadata: {
      adminUserId: adminCtx.userId,
      affectedProviderCount: data.affectedProviderIds.length,
    },
  });

  return breach;
}

// ---------------------------------------------------------------------------
// Service: Breach Notification — Send Initial Notifications
// ---------------------------------------------------------------------------

/**
 * Send BREACH_INITIAL_NOTIFICATION to all unnotified custodians.
 * Each custodian receives notification to both primary AND secondary email
 * (IMA section 11.7) via the notification service's dual-delivery mechanism.
 *
 * Creates an INITIAL breach_update record after sending.
 * Tracks the 72h deadline from awarenessDate.
 */
export async function sendBreachNotifications(
  deps: PlatformServiceDeps,
  adminCtx: BreachAdminContext,
  breachId: string,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ notified: number }> {
  if (adminCtx.role.toUpperCase() !== 'ADMIN') {
    throw new ForbiddenError('Only administrators can send breach notifications');
  }

  if (!deps.breachRepo) {
    throw new Error('Breach repository not configured');
  }

  const breach = await deps.breachRepo.findBreachById(breachId);
  if (!breach) {
    throw new NotFoundError('Breach record');
  }

  const unnotified = await deps.breachRepo.getUnnotifiedCustodians(breachId);

  let notifiedCount = 0;

  for (const custodian of unnotified) {
    // Emit BREACH_INITIAL_NOTIFICATION — dual-delivery sends to both
    // primary and secondary email automatically
    try {
      eventEmitter?.emit('BREACH_INITIAL_NOTIFICATION', {
        breachId,
        providerId: custodian.providerId,
        breachDescription: breach.breachDescription,
        contactName: breach.contactName,
        contactEmail: breach.contactEmail,
      });
    } catch {
      // Notification delivery failures must not halt the loop
    }

    await deps.breachRepo.markCustodianNotified(
      breachId,
      custodian.providerId,
      'EMAIL',
    );
    notifiedCount++;
  }

  // Create INITIAL breach update record
  if (notifiedCount > 0) {
    await deps.breachRepo.createBreachUpdate(breachId, {
      updateType: BreachUpdateType.INITIAL,
      content: `Initial breach notification sent to ${notifiedCount} custodian(s).`,
      createdBy: adminCtx.userId,
    });

    // Update breach status to NOTIFYING
    await deps.breachRepo.updateBreachStatus(breachId, BreachStatus.NOTIFYING);
  }

  // Audit event
  await deps.auditLogger?.log({
    action: 'breach.notification_sent',
    resourceType: 'breach_record',
    resourceId: breachId,
    actorType: 'admin',
    metadata: {
      adminUserId: adminCtx.userId,
      notifiedCount,
      awarenessDate: breach.awarenessDate instanceof Date
        ? breach.awarenessDate.toISOString()
        : String(breach.awarenessDate),
    },
  });

  return { notified: notifiedCount };
}

// ---------------------------------------------------------------------------
// Service: Breach Notification — Add Supplementary Update
// ---------------------------------------------------------------------------

/**
 * Add a SUPPLEMENTARY breach update and notify all affected custodians
 * (both primary and secondary email) via BREACH_UPDATE event.
 */
export async function addBreachUpdate(
  deps: PlatformServiceDeps,
  adminCtx: BreachAdminContext,
  breachId: string,
  content: string,
  eventEmitter?: PlatformEventEmitter,
) {
  if (adminCtx.role.toUpperCase() !== 'ADMIN') {
    throw new ForbiddenError('Only administrators can add breach updates');
  }

  if (!deps.breachRepo) {
    throw new Error('Breach repository not configured');
  }

  const breach = await deps.breachRepo.findBreachById(breachId);
  if (!breach) {
    throw new NotFoundError('Breach record');
  }

  const update = await deps.breachRepo.createBreachUpdate(breachId, {
    updateType: BreachUpdateType.SUPPLEMENTARY,
    content,
    createdBy: adminCtx.userId,
  });

  // Notify all affected custodians (not just unnotified — supplementary goes to all)
  // The notification service's dual-delivery mechanism handles secondary emails
  try {
    eventEmitter?.emit('BREACH_UPDATE', {
      breachId,
      updateId: update.updateId,
      content,
      contactName: breach.contactName,
      contactEmail: breach.contactEmail,
    });
  } catch {
    // Notification delivery failures must not fail the update
  }

  // Audit event
  await deps.auditLogger?.log({
    action: 'breach.updated',
    resourceType: 'breach_record',
    resourceId: breachId,
    actorType: 'admin',
    metadata: {
      adminUserId: adminCtx.userId,
      updateId: update.updateId,
      updateType: BreachUpdateType.SUPPLEMENTARY,
    },
  });

  return update;
}

// ---------------------------------------------------------------------------
// Service: Breach Notification — Resolve Breach
// ---------------------------------------------------------------------------

/**
 * Set breach status to RESOLVED with resolvedAt timestamp.
 */
export async function resolveBreach(
  deps: PlatformServiceDeps,
  adminCtx: BreachAdminContext,
  breachId: string,
  eventEmitter?: PlatformEventEmitter,
) {
  if (adminCtx.role.toUpperCase() !== 'ADMIN') {
    throw new ForbiddenError('Only administrators can resolve breach records');
  }

  if (!deps.breachRepo) {
    throw new Error('Breach repository not configured');
  }

  const breach = await deps.breachRepo.findBreachById(breachId);
  if (!breach) {
    throw new NotFoundError('Breach record');
  }

  if (breach.status === BreachStatus.RESOLVED) {
    throw new ConflictError('Breach is already resolved');
  }

  const resolved = await deps.breachRepo.updateBreachStatus(
    breachId,
    BreachStatus.RESOLVED,
    new Date(),
  );

  // Audit event
  await deps.auditLogger?.log({
    action: 'breach.resolved',
    resourceType: 'breach_record',
    resourceId: breachId,
    actorType: 'admin',
    metadata: {
      adminUserId: adminCtx.userId,
    },
  });

  return resolved;
}

// ---------------------------------------------------------------------------
// Service: Breach Notification — Check Deadlines (scheduled job)
// ---------------------------------------------------------------------------

/**
 * Scheduled job: find breaches where awarenessDate + 72h is approaching
 * and custodians are still unnotified. Returns overdue breaches for
 * admin alerting.
 */
export async function checkBreachDeadlines(
  deps: PlatformServiceDeps,
): Promise<{ overdueBreaches: Array<{ breachId: string; awarenessDate: Date | string }> }> {
  if (!deps.breachRepo) {
    throw new Error('Breach repository not configured');
  }

  const overdue = await deps.breachRepo.getOverdueBreaches();

  return {
    overdueBreaches: overdue.map((b) => ({
      breachId: b.breachId,
      awarenessDate: b.awarenessDate,
    })),
  };
}

// ---------------------------------------------------------------------------
// Service: Run Destruction Confirmation (daily scheduled job) — IMA-060
// ---------------------------------------------------------------------------

/**
 * Scheduled job: find destruction tracking records where backup has been purged
 * but confirmation email has not yet been sent. Sends DATA_DESTRUCTION_CONFIRMED
 * notification to the physician's last known email.
 *
 * Also detects overdue backup purges (deadline passed but not yet marked purged)
 * and alerts admin.
 */
export async function runDestructionConfirmation(
  deps: PlatformServiceDeps,
  eventEmitter?: PlatformEventEmitter,
): Promise<{ confirmed: number; overdueAlerts: number }> {
  if (!deps.destructionTrackingRepo) {
    return { confirmed: 0, overdueAlerts: 0 };
  }

  let confirmed = 0;
  let overdueAlerts = 0;

  // Phase 1: Send confirmation emails where backup has been purged
  const pendingConfirmations =
    await deps.destructionTrackingRepo.findPendingConfirmations();

  for (const record of pendingConfirmations) {
    if (record.lastKnownEmail) {
      eventEmitter?.emit('DATA_DESTRUCTION_CONFIRMED', {
        providerId: record.providerId,
        email: record.lastKnownEmail,
        activeDeletedAt: record.activeDeletedAt?.toISOString() ?? null,
        filesDeletedAt: record.filesDeletedAt?.toISOString() ?? null,
        backupPurgedAt: record.backupPurgedAt?.toISOString() ?? null,
      });
    }

    await deps.destructionTrackingRepo.updateConfirmationSentAt(
      record.providerId,
      new Date(),
    );

    await deps.auditLogger?.log({
      action: PlatformAuditAction.DESTRUCTION_CONFIRMED,
      resourceType: 'destruction_tracking',
      resourceId: record.providerId,
      actorType: 'system',
      metadata: {
        trackingId: record.trackingId,
        emailSent: !!record.lastKnownEmail,
      },
    });

    confirmed++;
  }

  // Phase 2: Alert admin about overdue backup purges
  const overdueRecords =
    await deps.destructionTrackingRepo.findOverdueBackupPurges();

  for (const record of overdueRecords) {
    eventEmitter?.emit('DESTRUCTION_BACKUP_OVERDUE', {
      providerId: record.providerId,
      backupPurgeDeadline: record.backupPurgeDeadline?.toISOString() ?? null,
    });

    overdueAlerts++;
  }

  return { confirmed, overdueAlerts };
}

// ---------------------------------------------------------------------------
// Service: Mark Backup Purged (admin action) — IMA-060
// ---------------------------------------------------------------------------

/**
 * Admin marks a provider's backups as purged after manual confirmation
 * that all backup copies have been destroyed.
 */
export async function markBackupPurged(
  deps: PlatformServiceDeps,
  adminCtx: { userId: string; role: string },
  providerId: string,
): Promise<{ backupPurgedAt: Date }> {
  if (adminCtx.role.toUpperCase() !== 'ADMIN') {
    throw new ForbiddenError('Only admin can mark backup purges');
  }

  if (!deps.destructionTrackingRepo) {
    throw new Error('Destruction tracking repository not configured');
  }

  const existing = await deps.destructionTrackingRepo.findByProviderId(providerId);
  if (!existing) {
    throw new NotFoundError('Destruction tracking record');
  }

  if (existing.backupPurgedAt) {
    throw new ConflictError('Backup already marked as purged');
  }

  const backupPurgedAt = new Date();
  await deps.destructionTrackingRepo.updateBackupPurgedAt(
    providerId,
    backupPurgedAt,
  );

  await deps.auditLogger?.log({
    action: PlatformAuditAction.DESTRUCTION_BACKUP_PURGED,
    resourceType: 'destruction_tracking',
    resourceId: providerId,
    actorType: 'admin',
    metadata: { adminUserId: adminCtx.userId },
  });

  return { backupPurgedAt };
}
