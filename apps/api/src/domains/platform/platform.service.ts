import {
  SubscriptionPlan,
  EARLY_BIRD_CAP,
  GST_RATE,
  DELETION_GRACE_PERIOD_DAYS,
  PaymentStatus,
  StripeWebhookEvent,
  FeatureAccessMatrix,
  StatusComponent,
  ComponentHealth,
  IncidentStatus,
  type Feature,
} from '@meritum/shared/constants/platform.constants.js';
import { SubscriptionStatus } from '@meritum/shared/constants/iam.constants.js';
import { ConflictError, BusinessRuleError, NotFoundError, ValidationError } from '../../lib/errors.js';
import {
  type SubscriptionRepository,
  type PaymentRepository,
  type StatusComponentRepository,
  type IncidentRepository,
} from './platform.repository.js';

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

export interface PlatformServiceDeps {
  subscriptionRepo: SubscriptionRepository;
  paymentRepo: PaymentRepository;
  statusComponentRepo: StatusComponentRepository;
  incidentRepo: IncidentRepository;
  userRepo: UserRepo;
  stripe: StripeClient;
  config: {
    stripePriceStandardMonthly: string;
    stripePriceStandardAnnual: string;
    stripePriceEarlyBirdMonthly: string;
    stripeWebhookSecret: string;
    gstTaxRateId?: string;
  };
  dataDeletionRepo?: DataDeletionRepo;
  auditLogger?: AuditLogger;
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

  // 2. Early bird cap check
  if (plan === SubscriptionPlan.EARLY_BIRD_MONTHLY) {
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

  await deps.subscriptionRepo.createSubscription({
    providerId: userId,
    stripeCustomerId,
    stripeSubscriptionId,
    plan: plan ?? SubscriptionPlan.STANDARD_MONTHLY,
    status: SubscriptionStatus.ACTIVE,
    currentPeriodStart: now,
    currentPeriodEnd: periodEnd,
  } as any);

  eventEmitter?.emit('SUBSCRIPTION_CREATED', {
    userId,
    plan: plan ?? SubscriptionPlan.STANDARD_MONTHLY,
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
  const dueDeletion = await deps.subscriptionRepo.findSubscriptionsDueForDeletion();
  let deleted = 0;

  for (const sub of dueDeletion) {
    const deletionRepo = deps.dataDeletionRepo;
    if (!deletionRepo) {
      continue; // Cannot process deletions without the deletion repository
    }

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

    eventEmitter?.emit('ACCOUNT_DATA_DELETED', {
      subscriptionId: sub.subscriptionId,
      providerId: sub.providerId,
      deletedAt: new Date().toISOString(),
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
