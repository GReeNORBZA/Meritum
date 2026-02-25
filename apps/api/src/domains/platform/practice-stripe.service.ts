import { GST_RATE } from '@meritum/shared/constants/platform.constants.js';
import type { PracticeStripeClient } from './practice.service.js';
import type { PracticeRepository } from './practice.repository.js';

// ---------------------------------------------------------------------------
// Dependency interface
// ---------------------------------------------------------------------------

export interface PracticeStripeServiceDeps {
  stripe: PracticeStripeClient;
  practiceRepo: PracticeRepository;
  env: {
    STRIPE_PRICE_CLINIC_MONTHLY: string;
    STRIPE_PRICE_CLINIC_ANNUAL: string;
  };
}

// ---------------------------------------------------------------------------
// createPracticeStripeSubscription
// ---------------------------------------------------------------------------

/**
 * Creates a Stripe customer + subscription for a practice.
 *
 * ZERO PHI sent to Stripe — only practice name and admin email.
 * Stripe quantity = consolidated seat count (PRACTICE_CONSOLIDATED only),
 * NOT total headcount.
 */
export async function createPracticeStripeSubscription(
  deps: PracticeStripeServiceDeps,
  practiceId: string,
  adminEmail: string,
  practiceName: string,
  billingFrequency: 'MONTHLY' | 'ANNUAL',
  consolidatedSeatCount: number,
): Promise<{ stripeCustomerId: string; stripeSubscriptionId: string }> {
  // 1. Create Stripe customer — ZERO PHI, only practice name + admin email
  const customer = await deps.stripe.customers.create({
    name: practiceName,
    email: adminEmail,
    metadata: { practice_id: practiceId },
  });

  // 2. Select the price ID based on billing frequency
  const priceId =
    billingFrequency === 'ANNUAL'
      ? deps.env.STRIPE_PRICE_CLINIC_ANNUAL
      : deps.env.STRIPE_PRICE_CLINIC_MONTHLY;

  // 3. Create Stripe subscription — quantity = consolidated seats only
  if (!deps.stripe.subscriptions?.create) {
    throw new Error('Stripe subscriptions.create is not available');
  }

  const subscription = await deps.stripe.subscriptions.create({
    customer: customer.id,
    items: [{ price: priceId, quantity: consolidatedSeatCount }],
    metadata: { practice_id: practiceId },
  });

  // 4. Persist Stripe IDs on the practice record
  await deps.practiceRepo.updatePracticeStripeIds(
    practiceId,
    customer.id,
    subscription.id,
  );

  return {
    stripeCustomerId: customer.id,
    stripeSubscriptionId: subscription.id,
  };
}

// ---------------------------------------------------------------------------
// updatePracticeStripeQuantity
// ---------------------------------------------------------------------------

/**
 * Updates the Stripe subscription quantity for a practice (prorated).
 *
 * Quantity = PRACTICE_CONSOLIDATED members only.
 */
export async function updatePracticeStripeQuantity(
  deps: PracticeStripeServiceDeps,
  practiceId: string,
  newQuantity: number,
): Promise<void> {
  const practice = await deps.practiceRepo.findPracticeById(practiceId);
  if (!practice) {
    throw new Error(`Practice not found: ${practiceId}`);
  }
  if (!practice.stripeSubscriptionId) {
    throw new Error(`Practice ${practiceId} has no Stripe subscription`);
  }
  if (!deps.stripe.subscriptions) {
    throw new Error('Stripe subscriptions API is not available');
  }

  await deps.stripe.subscriptions.update(practice.stripeSubscriptionId, {
    quantity: newQuantity,
    proration_behavior: 'create_prorations',
  });
}

// ---------------------------------------------------------------------------
// cancelPracticeStripeSubscription
// ---------------------------------------------------------------------------

/**
 * Cancels the Stripe subscription for a practice.
 */
export async function cancelPracticeStripeSubscription(
  deps: PracticeStripeServiceDeps,
  practiceId: string,
): Promise<void> {
  const practice = await deps.practiceRepo.findPracticeById(practiceId);
  if (!practice) {
    throw new Error(`Practice not found: ${practiceId}`);
  }
  if (!practice.stripeSubscriptionId) {
    throw new Error(`Practice ${practiceId} has no Stripe subscription`);
  }
  if (!deps.stripe.subscriptions) {
    throw new Error('Stripe subscriptions API is not available');
  }

  await deps.stripe.subscriptions.cancel(practice.stripeSubscriptionId);
}

// ---------------------------------------------------------------------------
// handlePracticeStripeWebhook
// ---------------------------------------------------------------------------

/**
 * Handles practice-specific Stripe webhook events.
 *
 * Distinguishes practice vs individual webhooks by checking
 * event.data.object.metadata.practice_id.
 *
 * Supported events:
 * - invoice.created  → Add GST (5% of subtotal) as a tax line
 * - invoice.paid     → Update practice status / record payment
 * - invoice.payment_failed → Flag practice for follow-up
 * - customer.subscription.deleted → Mark practice subscription cancelled
 */
export async function handlePracticeStripeWebhook(
  deps: PracticeStripeServiceDeps & { practiceRepo: PracticeRepository },
  event: { type: string; data: { object: any } },
): Promise<void> {
  const obj = event.data.object;
  const practiceId = obj.metadata?.practice_id;

  // Only handle practice-specific events
  if (!practiceId) {
    return;
  }

  switch (event.type) {
    case 'invoice.created': {
      // Add GST (5%) to the invoice subtotal
      const subtotal = obj.subtotal ?? 0;
      const gstAmount = Math.round(subtotal * GST_RATE);
      obj.tax = gstAmount;
      obj.total = subtotal + gstAmount;
      break;
    }

    case 'invoice.paid': {
      // Confirm the practice is active / payment succeeded
      const practice = await deps.practiceRepo.findPracticeById(practiceId);
      if (practice && practice.status !== 'ACTIVE') {
        await deps.practiceRepo.updatePracticeStatus(practiceId, 'ACTIVE');
      }
      break;
    }

    case 'invoice.payment_failed': {
      // Mark practice as past-due / suspended based on dunning
      const practice = await deps.practiceRepo.findPracticeById(practiceId);
      if (practice) {
        await deps.practiceRepo.updatePracticeStatus(practiceId, 'SUSPENDED');
      }
      break;
    }

    case 'customer.subscription.deleted': {
      // Stripe subscription was cancelled — update practice
      const practice = await deps.practiceRepo.findPracticeById(practiceId);
      if (practice) {
        await deps.practiceRepo.updatePracticeStatus(practiceId, 'CANCELLED');
      }
      break;
    }

    default:
      // Unknown event type for practice context — ignore
      break;
  }
}
